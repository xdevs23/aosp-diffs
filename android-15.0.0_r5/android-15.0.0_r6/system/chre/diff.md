```diff
diff --git a/Android.bp b/Android.bp
index 3498eeca..78a78cae 100644
--- a/Android.bp
+++ b/Android.bp
@@ -662,6 +662,7 @@ cc_library_static {
         "platform/linux/task_util/task.cc",
         "platform/linux/task_util/task_manager.cc",
         "platform/shared/pal_system_api.cc",
+        "util/duplicate_message_detector.cc",
         "util/dynamic_vector_base.cc",
     ],
     export_include_dirs: [
@@ -983,7 +984,6 @@ cc_defaults {
     cflags: [
         "-DCHRE_ASSERTIONS_ENABLED=true",
         "-DCHRE_AUDIO_SUPPORT_ENABLED",
-        "-DCHRE_BLE_READ_RSSI_SUPPORT_ENABLED",
         "-DCHRE_BLE_SUPPORT_ENABLED",
         "-DCHRE_FILENAME=__FILE__",
         "-DCHRE_FIRST_SUPPORTED_API_VERSION=CHRE_API_VERSION_1_1",
diff --git a/Android.mk b/Android.mk
deleted file mode 100644
index 476bc350..00000000
--- a/Android.mk
+++ /dev/null
@@ -1,152 +0,0 @@
-#
-# Copyright 2019 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-LOCAL_PATH := $(call my-dir)
-
-# Don't build the daemon for targets that don't contain a vendor image as
-# libsdsprpc and libadsprpc are provided by vendor code
-ifeq ($(BUILDING_VENDOR_IMAGE),true)
-
-ifeq ($(CHRE_DAEMON_ENABLED),true)
-
-include $(CLEAR_VARS)
-
-# CHRE AP-side daemon
-# NOTE: This can't be converted to a blueprint file until libsdsprpc /
-# libadsprpc is converted as blueprint targets can't depend on targets exposed
-# by makefiles
-LOCAL_MODULE := chre
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 SPDX-license-identifier-BSD
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-LOCAL_MODULE_OWNER := google
-LOCAL_MODULE_TAGS := optional
-LOCAL_VENDOR_MODULE := true
-LOCAL_INIT_RC := chre_daemon.rc
-
-LOCAL_CPP_EXTENSION := .cc
-LOCAL_CFLAGS += -Wall -Werror -Wextra
-LOCAL_CFLAGS += -DCHRE_DAEMON_METRIC_ENABLED
-
-LOCAL_TIDY_CHECKS := -google-runtime-int
-
-# Enable the LPMA feature for devices that support audio
-ifeq ($(CHRE_DAEMON_LPMA_ENABLED),true)
-LOCAL_CFLAGS += -DCHRE_DAEMON_LPMA_ENABLED
-endif
-
-ifeq ($(CHRE_DAEMON_LOAD_INTO_SENSORSPD),true)
-LOCAL_CFLAGS += -DCHRE_DAEMON_LOAD_INTO_SENSORSPD
-endif
-
-MSM_SRC_FILES := \
-    host/common/fbs_daemon_base.cc \
-    host/msm/daemon/fastrpc_daemon.cc \
-    host/msm/daemon/main.cc \
-    host/msm/daemon/generated/chre_slpi_stub.c
-
-MSM_INCLUDES := \
-    system/chre/host/msm/daemon
-
-LOCAL_SRC_FILES := \
-    host/common/daemon_base.cc \
-    host/common/config_util.cc \
-    host/common/file_stream.cc \
-    host/common/fragmented_load_transaction.cc \
-    host/common/host_protocol_host.cc \
-    host/common/log_message_parser.cc \
-    host/common/bt_snoop_log_parser.cc \
-    host/common/socket_server.cc \
-    host/common/st_hal_lpma_handler.cc \
-    platform/shared/host_protocol_common.cc
-
-LOCAL_C_INCLUDES := \
-    external/fastrpc/inc \
-    system/chre/external/flatbuffers/include \
-    system/chre/host/common/include \
-    system/chre/platform/shared/include \
-    system/chre/platform/slpi/include \
-    system/chre/util/include \
-    system/libbase/include \
-    system/core/libcutils/include \
-    system/logging/liblog/include \
-    system/core/libutils/include
-
-LOCAL_SHARED_LIBRARIES := \
-    libjsoncpp \
-    libutils \
-    libcutils \
-    liblog \
-    libhidlbase \
-    libbase \
-    android.hardware.soundtrigger@2.0 \
-    libpower \
-    libprotobuf-cpp-lite \
-    chremetrics-cpp \
-    chre_atoms_log \
-    android.frameworks.stats-V2-ndk \
-    libbinder_ndk \
-    server_configurable_flags
-
-LOCAL_STATIC_LIBRARIES := \
-    chre_flags_c_lib \
-    chre_metrics_reporter
-
-LOCAL_SRC_FILES += $(MSM_SRC_FILES)
-LOCAL_C_INCLUDES += $(MSM_INCLUDES)
-
-LOCAL_CPPFLAGS += -std=c++20
-LOCAL_CFLAGS += -Wno-sign-compare
-LOCAL_CFLAGS += -Wno-c++11-narrowing
-LOCAL_CFLAGS += -Wno-deprecated-volatile
-
-# Pigweed (PW)
-PW_DIR = external/pigweed
-PW_DIR_RELPATH = ../../$(PW_DIR)
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_assert/assert_compatibility_public_overrides
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_assert/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_base64/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_bytes/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_containers/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_log_tokenized/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_log/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_polyfill/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_polyfill/public_overrides
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_polyfill/standard_library_public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_preprocessor/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_result/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_span/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_status/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_string/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_tokenizer/public
-LOCAL_CFLAGS += -I$(PW_DIR)/pw_varint/public
-LOCAL_CFLAGS += -I$(PW_DIR)/third_party/fuchsia/repo/sdk/lib/stdcompat/include
-
-LOCAL_SRC_FILES += $(PW_DIR_RELPATH)/pw_tokenizer/decode.cc
-LOCAL_SRC_FILES += $(PW_DIR_RELPATH)/pw_tokenizer/detokenize.cc
-LOCAL_SRC_FILES += $(PW_DIR_RELPATH)/pw_varint/varint_c.c
-LOCAL_SRC_FILES += $(PW_DIR_RELPATH)/pw_varint/varint.cc
-
-ifeq ($(CHRE_DAEMON_USE_SDSPRPC),true)
-LOCAL_SHARED_LIBRARIES += libsdsprpc
-else
-LOCAL_SHARED_LIBRARIES += libadsprpc
-endif
-
-include $(BUILD_EXECUTABLE)
-
-endif   # CHRE_DAEMON_ENABLED
-endif   # BUILDING_VENDOR_IMAGE
diff --git a/Makefile b/Makefile
index 97790104..d8b072f6 100644
--- a/Makefile
+++ b/Makefile
@@ -98,7 +98,7 @@ endif
 # arbitrary epoch. This will roll over 16 bits after ~7 years, but patch version
 # is scoped to the API version, so we can adjust the offset when a new API
 # version is released.
-EPOCH=$(shell $(DATE_CMD) --date='2017-01-01' +%s)
+EPOCH=$(shell $(DATE_CMD) --date='2023-01-01' +%s)
 CHRE_PATCH_VERSION = $(shell echo $$(((`$(DATE_CMD) +%s` - $(EPOCH)) / (60 * 60))))
 endif
 
diff --git a/apps/audio_world/audio_world.cc b/apps/audio_world/audio_world.cc
index 686cdeca..83105256 100644
--- a/apps/audio_world/audio_world.cc
+++ b/apps/audio_world/audio_world.cc
@@ -16,6 +16,7 @@
 
 #include <cinttypes>
 #include <cmath>
+#include <cstddef>
 
 #include "chre/util/macros.h"
 #include "chre/util/nanoapp/audio.h"
@@ -44,7 +45,7 @@ bool gAudioRequested = false;
 uint32_t gAudioHandle;
 
 //! State for Kiss FFT and logging.
-uint8_t gKissFftBuffer[4096];
+alignas(std::max_align_t) uint8_t gKissFftBuffer[4096];
 kiss_fftr_cfg gKissFftConfig;
 kiss_fft_cpx gKissFftOutput[(kNumFrequencies / 2) + 1];
 Milliseconds gFirstAudioEventTimestamp = Milliseconds(0);
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/app_manager.cc b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/app_manager.cc
index 337cf605..e99c4eac 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/app_manager.cc
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/app_manager.cc
@@ -31,6 +31,7 @@
 #include "location/lbs/contexthub/nanoapps/proto/filter.nanopb.h"
 #include "third_party/contexthub/chre/util/include/chre/util/macros.h"
 #include "third_party/contexthub/chre/util/include/chre/util/nanoapp/log.h"
+#include "third_party/contexthub/chre/util/include/chre/util/time.h"
 
 #define LOG_TAG "[NEARBY][APP_MANAGER]"
 
@@ -42,7 +43,11 @@ using ::chre::Nanoseconds;
 
 AppManager::AppManager() {
   fp_filter_cache_time_nanosec_ = chreGetTime();
+  last_tracker_report_flush_time_nanosec_ = chreGetTime();
   tracker_storage_.SetCallback(this);
+  // Enable host awake and sleep state events to opportunistically flush the
+  // tracker reports to the host.
+  chreConfigureHostSleepStateEvents(true /* enable */);
 #ifdef NEARBY_PROFILE
   ashProfileInit(
       &profile_data_, "[NEARBY_MATCH_ADV_PERF]", 1000 /* print_interval_ms */,
@@ -113,6 +118,9 @@ void AppManager::HandleEvent(uint32_t sender_instance_id, uint16_t event_type,
         tracker_storage_.Refresh(tracker_filter_.GetBatchConfig());
       }
       break;
+    case CHRE_EVENT_HOST_AWAKE:
+      HandleHostAwakeEvent();
+      break;
     default:
       LOGD("Unknown event type: %" PRIu16, event_type);
   }
@@ -615,6 +623,20 @@ const char *AppManager::GetExtConfigNameFromTag(pb_size_t config_tag) {
   }
 }
 
+void AppManager::HandleHostAwakeEvent() {
+  // Send tracker reports to host when receive host awake event.
+  uint64_t current_time = chreGetTime();
+  uint64_t flush_threshold_nanosec =
+      tracker_filter_.GetBatchConfig().opportunistic_flush_threshold_time_ms *
+      chre::kOneMillisecondInNanoseconds;
+  if (current_time - last_tracker_report_flush_time_nanosec_ >=
+      flush_threshold_nanosec) {
+    LOGI("Flush tracker reports by host awake event.");
+    SendTrackerReportsToHost(tracker_storage_.GetBatchReports());
+    tracker_storage_.Clear();
+  }
+}
+
 void AppManager::OnTrackerStorageFullEvent() {
   SendTrackerStorageFullEventToHost();
 }
@@ -668,6 +690,7 @@ void AppManager::SendTrackerStorageFullEventToHost() {
 
 void AppManager::SendTrackerReportsToHost(
     chre::DynamicVector<TrackerReport> &tracker_reports) {
+  last_tracker_report_flush_time_nanosec_ = chreGetTime();
   uint16_t host_end_point = tracker_filter_.GetHostEndPoint();
   for (auto &tracker_report : tracker_reports) {
     size_t encoded_size;
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/app_manager.h b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/app_manager.h
index 379be9af..2d74be86 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/app_manager.h
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/app_manager.h
@@ -122,6 +122,9 @@ class AppManager : public TrackerStorageCallbackInterface {
   // BLE scan keep alive timer callback.
   void OnBleScanKeepAliveTimerCallback();
 
+  // Handles host awake event.
+  void HandleHostAwakeEvent();
+
   // Handles tracker filter config request from the host.
   bool HandleExtTrackerFilterConfig(
       const chreHostEndpointInfo &host_info,
@@ -188,6 +191,7 @@ class AppManager : public TrackerStorageCallbackInterface {
       screen_on_filter_extension_results_;
   uint64_t fp_filter_cache_time_nanosec_;
   uint64_t fp_filter_cache_expire_nanosec_ = kFpFilterResultExpireTimeNanoSec;
+  uint64_t last_tracker_report_flush_time_nanosec_;
 #ifdef NEARBY_PROFILE
   ashProfileData profile_data_;
 #endif
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/proto/nearby_extension.proto b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/proto/nearby_extension.proto
index 6ac8dfd2..873388a8 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/proto/nearby_extension.proto
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/proto/nearby_extension.proto
@@ -107,6 +107,14 @@ message ExtConfigRequest {
 
     // Timeout for tracker history to be considered lost.
     optional uint32 lost_timeout_ms = 7 [default = 60000];
+
+    // Time based threshold for opportunistic flush of tracker reports. When
+    // the nanoapp receives host awake event, it flueshes tracker reports if
+    // the epalsed time since the previous flush (by host or opportunistic)
+    // is equal to or greater than this threshold. The default value effectively
+    // disables the opportunistic flush.
+    optional uint32 opportunistic_flush_threshold_time_ms = 8
+        [default = 4294967295];
   }
 
   message FlushTrackerReports {}
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_filter.cc b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_filter.cc
index 91b2d52c..e072b7a9 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_filter.cc
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_filter.cc
@@ -58,6 +58,8 @@ void TrackerFilter::Update(
       filter_config.notify_threshold_tracker_count;
   batch_config_.max_history_count = filter_config.max_history_count;
   batch_config_.lost_timeout_ms = filter_config.lost_timeout_ms;
+  batch_config_.opportunistic_flush_threshold_time_ms =
+      filter_config.opportunistic_flush_threshold_time_ms;
 }
 
 void TrackerFilter::MatchAndSave(
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.cc b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.cc
index 91cff306..5f0d8053 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.cc
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.cc
@@ -18,8 +18,8 @@ namespace nearby {
 void TrackerStorage::Push(const chreBleAdvertisingReport &report,
                           const TrackerBatchConfig &config) {
   for (auto &tracker_report : tracker_reports_) {
-    if (IsEqualReport(tracker_report, report)) {
-      UpdateTrackerReport(tracker_report, config);
+    if (IsEqualAddress(tracker_report, report)) {
+      UpdateTrackerReport(tracker_report, config, report);
       return;
     }
   }
@@ -40,15 +40,22 @@ void TrackerStorage::Refresh(const TrackerBatchConfig &config) {
     if (back.state != TrackerState::kPresent) {
       continue;
     }
-    if (current_time_ms >= back.last_found_time_ms + config.lost_timeout_ms) {
+    if (current_time_ms >=
+        back.last_radio_discovery_time_ms + config.lost_timeout_ms) {
       back.state = TrackerState::kAbsent;
       back.lost_time_ms = current_time_ms;
     }
   }
 }
 
-void TrackerStorage::UpdateTrackerReport(TrackerReport &tracker_report,
-                                         const TrackerBatchConfig &config) {
+void TrackerStorage::UpdateTrackerReport(
+    TrackerReport &tracker_report, const TrackerBatchConfig &config,
+    const chreBleAdvertisingReport &report) {
+  LOGD_SENSITIVE_INFO(
+      "Received tracker report, tracker address: %02X:%02X:%02X:%02X:%02X:%02X",
+      tracker_report.header.address[0], tracker_report.header.address[1],
+      tracker_report.header.address[2], tracker_report.header.address[3],
+      tracker_report.header.address[4], tracker_report.header.address[5]);
   uint32_t current_time_ms = GetCurrentTimeMs();
   if (tracker_report.historian.empty() ||
       tracker_report.historian.back().state != TrackerState::kPresent) {
@@ -61,7 +68,12 @@ void TrackerStorage::UpdateTrackerReport(TrackerReport &tracker_report,
       tracker_report.historian.back().found_count++;
       tracker_report.historian.back().last_found_time_ms = current_time_ms;
     }
+    // Updates the last radio discovery time in the history without sampling.
+    tracker_report.historian.back().last_radio_discovery_time_ms =
+        current_time_ms;
   }
+  // Updates the advertising data if it is different from the previous one.
+  AddOrUpdateAdvertisingData(tracker_report, report);
   if (tracker_report.historian.size() > config.max_history_count) {
     LOGW(
         "Discarding old tracker history. Tracker history count %zu max history "
@@ -94,20 +106,8 @@ void TrackerStorage::AddTrackerReport(const chreBleAdvertisingReport &report,
   }
   // Creates a new key report and copies header.
   TrackerReport new_report;
-  new_report.header = report;
-  // Allocates advertise data and copy it as well.
-  uint16_t dataLength = report.dataLength;
-  if (dataLength > 0) {
-    chre::UniquePtr<uint8_t[]> data =
-        chre::MakeUniqueArray<uint8_t[]>(dataLength);
-    if (data == nullptr) {
-      LOGE("Memory allocation failed!");
-      return;
-    }
-    memcpy(data.get(), report.data, dataLength);
-    new_report.data = std::move(data);
-    new_report.header.data = new_report.data.get();
-  }
+  // Adds the advertising data to the new tracker report.
+  AddOrUpdateAdvertisingData(new_report, report);
   // For the new report, add a tracker history.
   new_report.historian.reserve(kDefaultTrackerHistorySize);
   new_report.historian.emplace_back(TrackerHistory(GetCurrentTimeMs()));
@@ -119,15 +119,42 @@ void TrackerStorage::AddTrackerReport(const chreBleAdvertisingReport &report,
        config.max_tracker_count);
 }
 
-bool TrackerStorage::IsEqualReport(
+void TrackerStorage::AddOrUpdateAdvertisingData(
+    TrackerReport &tracker_report, const chreBleAdvertisingReport &report) {
+  uint16_t dataLength = report.dataLength;
+  if (dataLength <= 0) {
+    LOGW("Empty advertising data found in advertising report");
+    return;
+  }
+  if (tracker_report.data == nullptr ||
+      tracker_report.header.dataLength != dataLength) {
+    tracker_report.header = report;
+    // Allocates advertise data and copy it as well.
+    chre::UniquePtr<uint8_t[]> data =
+        chre::MakeUniqueArray<uint8_t[]>(dataLength);
+    if (data == nullptr) {
+      LOGE("Memory allocation failed!");
+      return;
+    }
+    memcpy(data.get(), report.data, dataLength);
+    tracker_report.data = std::move(data);
+    tracker_report.header.data = tracker_report.data.get();
+  } else if (tracker_report.header.dataLength == dataLength &&
+             memcmp(tracker_report.data.get(), report.data,
+                    tracker_report.header.dataLength) != 0) {
+    tracker_report.header = report;
+    memcpy(tracker_report.data.get(), report.data,
+           tracker_report.header.dataLength);
+    tracker_report.header.data = tracker_report.data.get();
+  }
+}
+
+bool TrackerStorage::IsEqualAddress(
     const TrackerReport &tracker_report,
     const chreBleAdvertisingReport &report) const {
   return (tracker_report.header.addressType == report.addressType &&
           memcmp(tracker_report.header.address, report.address,
-                 CHRE_BLE_ADDRESS_LEN) == 0 &&
-          tracker_report.header.dataLength == report.dataLength &&
-          memcmp(tracker_report.data.get(), report.data,
-                 tracker_report.header.dataLength) == 0);
+                 CHRE_BLE_ADDRESS_LEN) == 0);
 }
 
 uint32_t TrackerStorage::GetCurrentTimeMs() const {
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.h b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.h
index 77246caf..73a03b21 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.h
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.h
@@ -32,6 +32,8 @@ struct TrackerBatchConfig {
   uint32_t max_history_count;
   // Timeout for tracker history to be considered lost.
   uint32_t lost_timeout_ms;
+  // Time based threshold for opportunistic flush of tracker reports.
+  uint32_t opportunistic_flush_threshold_time_ms;
 };
 
 enum class TrackerState {
@@ -45,6 +47,7 @@ struct TrackerHistory {
       : found_count(1),
         first_found_time_ms(current_time_ms),
         last_found_time_ms(current_time_ms),
+        last_radio_discovery_time_ms(current_time_ms),
         lost_time_ms(0),
         state(TrackerState::kPresent) {}
   // The number of times the tracker report was found at each sampling interval
@@ -56,6 +59,9 @@ struct TrackerHistory {
   // The most recent time when the tracker report was discovered for each
   // sampling period in the Present state.
   uint32_t last_found_time_ms;
+  // The most recent time when the tracker report was discovered by the LE
+  // radio, regardless of the sampling period or the tracker state.
+  uint32_t last_radio_discovery_time_ms;
   // The time at which the tracker report was lost. Only valid when the tracker
   // state is Absent.
   uint32_t lost_time_ms;
@@ -125,15 +131,30 @@ class TrackerStorage {
 
   // Updates tracker report in pushing advertisement.
   void UpdateTrackerReport(TrackerReport &tracker_report,
-                           const TrackerBatchConfig &config);
+                           const TrackerBatchConfig &config,
+                           const chreBleAdvertisingReport &report);
 
   // Adds a new tracker report to tracker storage.
   void AddTrackerReport(const chreBleAdvertisingReport &report,
                         const TrackerBatchConfig &config);
 
-  // Returns whether advertising report is same.
-  bool IsEqualReport(const TrackerReport &tracker_report,
-                     const chreBleAdvertisingReport &report) const;
+  // Adds or updates advertising data for tracker report.
+  // For a newly added tracker report, it will allocate memory for advertising
+  // data, and copy the advertising data from the advertising report.
+  // For an existing tracker report, it will check if the advertising data is
+  // different from the previous one. If the length is the same but the payload
+  // is different, it will update the tracker report by copying the advertising
+  // data from the advertising report. If the length is different, it will
+  // update the tracker report by re-allocating memory for advertising data, and
+  // copying the advertising data from the advertising report.
+  // If the advertising data is the same as the previous one, it will not do
+  // anything.
+  void AddOrUpdateAdvertisingData(TrackerReport &tracker_report,
+                                  const chreBleAdvertisingReport &report);
+
+  // Returns whether advertising address is same.
+  bool IsEqualAddress(const TrackerReport &tracker_report,
+                      const chreBleAdvertisingReport &report) const;
 
   // Returns current time in milliseconds.
   uint32_t GetCurrentTimeMs() const;
diff --git a/apps/test/chqts/src/general_test/basic_wifi_test.cc b/apps/test/chqts/src/general_test/basic_wifi_test.cc
index 540bd40f..0e9e0616 100644
--- a/apps/test/chqts/src/general_test/basic_wifi_test.cc
+++ b/apps/test/chqts/src/general_test/basic_wifi_test.cc
@@ -351,6 +351,13 @@ void BasicWifiTest::handleEvent(uint32_t /* senderInstanceId */,
       handleChreWifiAsyncEvent(static_cast<const chreAsyncResult *>(eventData));
       break;
     case CHRE_EVENT_WIFI_SCAN_RESULT: {
+      if (mScanMonitorEnabled && !mNextScanResultWasRequested) {
+        LOGI(
+            "Ignoring scan monitor scan result while waiting on requested scan"
+            " result");
+        break;
+      }
+
       if (!scanEventExpected()) {
         sendFatalFailureToHost("WiFi scan event received when not requested");
       }
@@ -422,15 +429,18 @@ void BasicWifiTest::handleChreWifiAsyncEvent(const chreAsyncResult *result) {
   LOGI("Received a wifi async event. request type: %" PRIu8
        " error code: %" PRIu8,
        result->requestType, result->errorCode);
-  if (result->requestType == CHRE_WIFI_REQUEST_TYPE_REQUEST_SCAN &&
-      !result->success && mNumScanRetriesRemaining > 0) {
-    LOGI("Wait for %" PRIu64 " seconds and try again",
-         kOnDemandScanTimeoutNs / chre::kOneSecondInNanoseconds);
-    mNumScanRetriesRemaining--;
-    mScanTimeoutTimerHandle = chreTimerSet(
-        /* duration= */ kOnDemandScanTimeoutNs, &mScanTimeoutTimerHandle,
-        /* oneShot= */ true);
-    return;
+  if (result->requestType == CHRE_WIFI_REQUEST_TYPE_REQUEST_SCAN) {
+    if (result->success) {
+      mNextScanResultWasRequested = true;
+    } else if (mNumScanRetriesRemaining > 0) {
+      LOGI("Wait for %" PRIu64 " seconds and try again",
+           kOnDemandScanTimeoutNs / chre::kOneSecondInNanoseconds);
+      mNumScanRetriesRemaining--;
+      mScanTimeoutTimerHandle = chreTimerSet(
+          /* duration= */ kOnDemandScanTimeoutNs, &mScanTimeoutTimerHandle,
+          /* oneShot= */ true);
+      return;
+    }
   }
   validateChreAsyncResult(result, mCurrentWifiRequest.value());
   processChreWifiAsyncResult(result);
@@ -451,11 +461,17 @@ void BasicWifiTest::processChreWifiAsyncResult(const chreAsyncResult *result) {
       break;
     case CHRE_WIFI_REQUEST_TYPE_CONFIGURE_SCAN_MONITOR:
       if (mCurrentWifiRequest->cookie == &kDisableScanMonitoringCookie) {
+        if (result->success) {
+          mScanMonitorEnabled = false;
+        }
         mTestSuccessMarker.markStageAndSuccessOnFinish(
             BASIC_WIFI_TEST_STAGE_SCAN_MONITOR);
         mStartTimestampNs = chreGetTime();
         startRangingAsyncTestStage();
       } else {
+        if (result->success) {
+          mScanMonitorEnabled = true;
+        }
         startScanAsyncTestStage();
       }
       break;
@@ -570,6 +586,7 @@ void BasicWifiTest::validateWifiScanEvent(const chreWifiScanEvent *eventData) {
 
   if (mWiFiScanResultRemaining == 0) {
     mNextExpectedIndex = 0;
+    mNextScanResultWasRequested = false;
     mTestSuccessMarker.markStageAndSuccessOnFinish(
         BASIC_WIFI_TEST_STAGE_SCAN_ASYNC);
     if (mWifiCapabilities & CHRE_WIFI_CAPABILITIES_SCAN_MONITORING) {
diff --git a/apps/test/chqts/src/general_test/basic_wifi_test.h b/apps/test/chqts/src/general_test/basic_wifi_test.h
index 181bfeef..4fe90f52 100644
--- a/apps/test/chqts/src/general_test/basic_wifi_test.h
+++ b/apps/test/chqts/src/general_test/basic_wifi_test.h
@@ -168,6 +168,12 @@ class BasicWifiTest : public Test {
   //! Start timestamp used to timing an event.
   uint64_t mStartTimestampNs = 0;
 
+  // Used to track if scan monitoring is currently enabled
+  bool mScanMonitorEnabled = false;
+
+  // Used to filter scan results unrelated to the test.
+  bool mNextScanResultWasRequested = false;
+
   //! Expected sequence number for an event within a series of events
   //! comprising a complete scan result.
   uint32_t mNextExpectedIndex = 0;
diff --git a/apps/test/common/chre_api_test/src/chre_api_test_manager.cc b/apps/test/common/chre_api_test/src/chre_api_test_manager.cc
index 63b7c081..7ddcd88b 100644
--- a/apps/test/common/chre_api_test/src/chre_api_test_manager.cc
+++ b/apps/test/common/chre_api_test/src/chre_api_test_manager.cc
@@ -24,6 +24,7 @@
 #include "chre/util/time.h"
 
 namespace {
+
 constexpr uint64_t kSyncFunctionTimeout = 2 * chre::kOneSecondInNanoseconds;
 
 /**
@@ -33,6 +34,8 @@ constexpr uint32_t kThreeAxisDataReadingsMaxCount = 10;
 constexpr uint32_t kChreBleAdvertisementReportMaxCount = 10;
 constexpr uint32_t kChreAudioDataEventMaxSampleBufferSize = 200;
 
+chre_rpc_GeneralEventsMessage gGeneralEventsMessage;
+
 /**
  * Closes the writer and invalidates the writer.
  *
@@ -86,6 +89,17 @@ void sendFailureAndFinishCloseWriter(
   message.status = false;
   sendFinishAndCloseWriter(writer, message);
 }
+
+template <>
+void sendFailureAndFinishCloseWriter<chre_rpc_GeneralEventsMessage>(
+    Optional<ChreApiTestService::ServerWriter<chre_rpc_GeneralEventsMessage>>
+        &writer) {
+  CHRE_ASSERT(writer.has_value());
+
+  std::memset(&gGeneralEventsMessage, 0, sizeof(gGeneralEventsMessage));
+  gGeneralEventsMessage.status = false;
+  sendFinishAndCloseWriter(writer, gGeneralEventsMessage);
+}
 }  // namespace
 
 // Start ChreApiTestService RPC generated functions
@@ -339,23 +353,25 @@ void ChreApiTestService::handleBleAsyncResult(const chreAsyncResult *result) {
 bool ChreApiTestService::handleChreAudioDataEvent(
     const chreAudioDataEvent *data) {
   // send the metadata
-  chre_rpc_GeneralEventsMessage metadataMessage;
-  metadataMessage.data.chreAudioDataMetadata.version = data->version;
-  metadataMessage.data.chreAudioDataMetadata.reserved =
+  std::memset(&gGeneralEventsMessage, 0, sizeof(gGeneralEventsMessage));
+  gGeneralEventsMessage.data.chreAudioDataMetadata.version = data->version;
+  gGeneralEventsMessage.data.chreAudioDataMetadata.reserved =
       0;  // Must be set to 0 always
-  metadataMessage.data.chreAudioDataMetadata.handle = data->handle;
-  metadataMessage.data.chreAudioDataMetadata.timestamp = data->timestamp;
-  metadataMessage.data.chreAudioDataMetadata.sampleRate = data->sampleRate;
-  metadataMessage.data.chreAudioDataMetadata.sampleCount = data->sampleCount;
-  metadataMessage.data.chreAudioDataMetadata.format = data->format;
-  metadataMessage.status = true;
-  metadataMessage.which_data =
+  gGeneralEventsMessage.data.chreAudioDataMetadata.handle = data->handle;
+  gGeneralEventsMessage.data.chreAudioDataMetadata.timestamp = data->timestamp;
+  gGeneralEventsMessage.data.chreAudioDataMetadata.sampleRate =
+      data->sampleRate;
+  gGeneralEventsMessage.data.chreAudioDataMetadata.sampleCount =
+      data->sampleCount;
+  gGeneralEventsMessage.data.chreAudioDataMetadata.format = data->format;
+  gGeneralEventsMessage.status = true;
+  gGeneralEventsMessage.which_data =
       chre_rpc_GeneralEventsMessage_chreAudioDataMetadata_tag;
-  sendPartialGeneralEventToHost(metadataMessage);
+  sendPartialGeneralEventToHost(gGeneralEventsMessage);
 
   // send the samples
-  chre_rpc_GeneralEventsMessage samplesMessage;
-  samplesMessage.status = false;
+  std::memset(&gGeneralEventsMessage, 0, sizeof(gGeneralEventsMessage));
+  gGeneralEventsMessage.status = false;
 
   uint32_t totalSamples = data->sampleCount;
   uint32_t maxSamplesPerMessage =
@@ -369,33 +385,34 @@ bool ChreApiTestService::handleChreAudioDataEvent(
   uint32_t numSamplesToSend = MIN(maxSamplesPerMessage, totalSamples);
   uint32_t sampleIdx = 0;
   for (int id = 0; numSamplesToSend > 0; id++) {
-    samplesMessage.data.chreAudioDataSamples.id = id;
+    gGeneralEventsMessage.data.chreAudioDataSamples.id = id;
 
     // assign data
     if (data->format == CHRE_AUDIO_DATA_FORMAT_8_BIT_U_LAW) {
-      samplesMessage.data.chreAudioDataSamples.samples.size = numSamplesToSend;
-      std::memcpy(samplesMessage.data.chreAudioDataSamples.samples.bytes,
+      gGeneralEventsMessage.data.chreAudioDataSamples.samples.size =
+          numSamplesToSend;
+      std::memcpy(gGeneralEventsMessage.data.chreAudioDataSamples.samples.bytes,
                   &data->samplesULaw8[sampleIdx], numSamplesToSend);
 
-      samplesMessage.status = true;
-      samplesMessage.which_data =
+      gGeneralEventsMessage.status = true;
+      gGeneralEventsMessage.which_data =
           chre_rpc_GeneralEventsMessage_chreAudioDataSamples_tag;
     } else if (data->format == CHRE_AUDIO_DATA_FORMAT_16_BIT_SIGNED_PCM) {
       // send double the bytes since each sample is 2B
-      samplesMessage.data.chreAudioDataSamples.samples.size =
+      gGeneralEventsMessage.data.chreAudioDataSamples.samples.size =
           numSamplesToSend * 2;
-      std::memcpy(samplesMessage.data.chreAudioDataSamples.samples.bytes,
+      std::memcpy(gGeneralEventsMessage.data.chreAudioDataSamples.samples.bytes,
                   &data->samplesS16[sampleIdx], numSamplesToSend * 2);
 
-      samplesMessage.status = true;
-      samplesMessage.which_data =
+      gGeneralEventsMessage.status = true;
+      gGeneralEventsMessage.which_data =
           chre_rpc_GeneralEventsMessage_chreAudioDataSamples_tag;
     } else {
       LOGE("Chre audio data event: format %" PRIu8 " unknown", data->format);
       return false;
     }
 
-    sendPartialGeneralEventToHost(samplesMessage);
+    sendPartialGeneralEventToHost(gGeneralEventsMessage);
 
     sampleIdx += numSamplesToSend;
     if (samplesRemainingAfterSend > maxSamplesPerMessage) {
@@ -461,38 +478,39 @@ void ChreApiTestService::handleGatheringEvent(uint16_t eventType,
   LOGD("Gather events Received matching event with type: %" PRIu16, eventType);
 
   bool messageSent = false;
-  chre_rpc_GeneralEventsMessage message;
-  message.status = false;
+  std::memset(&gGeneralEventsMessage, 0, sizeof(gGeneralEventsMessage));
+  gGeneralEventsMessage.status = false;
   switch (eventType) {
     case CHRE_EVENT_SENSOR_ACCELEROMETER_DATA: {
-      message.status = true;
-      message.which_data =
+      gGeneralEventsMessage.status = true;
+      gGeneralEventsMessage.which_data =
           chre_rpc_GeneralEventsMessage_chreSensorThreeAxisData_tag;
 
       const auto *data =
           static_cast<const struct chreSensorThreeAxisData *>(eventData);
-      message.data.chreSensorThreeAxisData.header.baseTimestamp =
+      gGeneralEventsMessage.data.chreSensorThreeAxisData.header.baseTimestamp =
           data->header.baseTimestamp;
-      message.data.chreSensorThreeAxisData.header.sensorHandle =
+      gGeneralEventsMessage.data.chreSensorThreeAxisData.header.sensorHandle =
           data->header.sensorHandle;
-      message.data.chreSensorThreeAxisData.header.readingCount =
+      gGeneralEventsMessage.data.chreSensorThreeAxisData.header.readingCount =
           data->header.readingCount;
-      message.data.chreSensorThreeAxisData.header.accuracy =
+      gGeneralEventsMessage.data.chreSensorThreeAxisData.header.accuracy =
           data->header.accuracy;
-      message.data.chreSensorThreeAxisData.header.reserved =
+      gGeneralEventsMessage.data.chreSensorThreeAxisData.header.reserved =
           data->header.reserved;
 
       uint32_t numReadings =
           MIN(data->header.readingCount, kThreeAxisDataReadingsMaxCount);
-      message.data.chreSensorThreeAxisData.readings_count = numReadings;
+      gGeneralEventsMessage.data.chreSensorThreeAxisData.readings_count =
+          numReadings;
       for (uint32_t i = 0; i < numReadings; ++i) {
-        message.data.chreSensorThreeAxisData.readings[i].timestampDelta =
-            data->readings[i].timestampDelta;
-        message.data.chreSensorThreeAxisData.readings[i].x =
+        gGeneralEventsMessage.data.chreSensorThreeAxisData.readings[i]
+            .timestampDelta = data->readings[i].timestampDelta;
+        gGeneralEventsMessage.data.chreSensorThreeAxisData.readings[i].x =
             data->readings[i].x;
-        message.data.chreSensorThreeAxisData.readings[i].y =
+        gGeneralEventsMessage.data.chreSensorThreeAxisData.readings[i].y =
             data->readings[i].y;
-        message.data.chreSensorThreeAxisData.readings[i].z =
+        gGeneralEventsMessage.data.chreSensorThreeAxisData.readings[i].z =
             data->readings[i].z;
       }
       break;
@@ -500,103 +518,109 @@ void ChreApiTestService::handleGatheringEvent(uint16_t eventType,
     case CHRE_EVENT_SENSOR_SAMPLING_CHANGE: {
       const auto *data =
           static_cast<const struct chreSensorSamplingStatusEvent *>(eventData);
-      message.data.chreSensorSamplingStatusEvent.sensorHandle =
+      gGeneralEventsMessage.data.chreSensorSamplingStatusEvent.sensorHandle =
           data->sensorHandle;
-      message.data.chreSensorSamplingStatusEvent.status.interval =
+      gGeneralEventsMessage.data.chreSensorSamplingStatusEvent.status.interval =
           data->status.interval;
-      message.data.chreSensorSamplingStatusEvent.status.latency =
+      gGeneralEventsMessage.data.chreSensorSamplingStatusEvent.status.latency =
           data->status.latency;
-      message.data.chreSensorSamplingStatusEvent.status.enabled =
+      gGeneralEventsMessage.data.chreSensorSamplingStatusEvent.status.enabled =
           data->status.enabled;
 
-      message.status = true;
-      message.which_data =
+      gGeneralEventsMessage.status = true;
+      gGeneralEventsMessage.which_data =
           chre_rpc_GeneralEventsMessage_chreSensorSamplingStatusEvent_tag;
       break;
     }
     case CHRE_EVENT_HOST_ENDPOINT_NOTIFICATION: {
       const auto *data =
           static_cast<const struct chreHostEndpointNotification *>(eventData);
-      message.data.chreHostEndpointNotification.hostEndpointId =
+      gGeneralEventsMessage.data.chreHostEndpointNotification.hostEndpointId =
           data->hostEndpointId;
-      message.data.chreHostEndpointNotification.notificationType =
+      gGeneralEventsMessage.data.chreHostEndpointNotification.notificationType =
           data->notificationType;
 
-      message.status = true;
-      message.which_data =
+      gGeneralEventsMessage.status = true;
+      gGeneralEventsMessage.which_data =
           chre_rpc_GeneralEventsMessage_chreHostEndpointNotification_tag;
       break;
     }
     case CHRE_EVENT_BLE_ADVERTISEMENT: {
       const auto *data =
           static_cast<const struct chreBleAdvertisementEvent *>(eventData);
-      message.data.chreBleAdvertisementEvent.reserved = data->reserved;
+      gGeneralEventsMessage.data.chreBleAdvertisementEvent.reserved =
+          data->reserved;
 
       uint32_t numReports =
           MIN(kChreBleAdvertisementReportMaxCount, data->numReports);
-      message.data.chreBleAdvertisementEvent.reports_count = numReports;
+      gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports_count =
+          numReports;
       for (uint32_t i = 0; i < numReports; ++i) {
-        message.data.chreBleAdvertisementEvent.reports[i].timestamp =
-            data->reports[i].timestamp;
-        message.data.chreBleAdvertisementEvent.reports[i]
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .timestamp = data->reports[i].timestamp;
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
             .eventTypeAndDataStatus = data->reports[i].eventTypeAndDataStatus;
-        message.data.chreBleAdvertisementEvent.reports[i].addressType =
-            data->reports[i].addressType;
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .addressType = data->reports[i].addressType;
 
-        message.data.chreBleAdvertisementEvent.reports[i].address.size =
-            CHRE_BLE_ADDRESS_LEN;
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .address.size = CHRE_BLE_ADDRESS_LEN;
         std::memcpy(
-            message.data.chreBleAdvertisementEvent.reports[i].address.bytes,
+            gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+                .address.bytes,
             data->reports[i].address, CHRE_BLE_ADDRESS_LEN);
 
-        message.data.chreBleAdvertisementEvent.reports[i].primaryPhy =
-            data->reports[i].primaryPhy;
-        message.data.chreBleAdvertisementEvent.reports[i].secondaryPhy =
-            data->reports[i].secondaryPhy;
-        message.data.chreBleAdvertisementEvent.reports[i].advertisingSid =
-            data->reports[i].advertisingSid;
-        message.data.chreBleAdvertisementEvent.reports[i].txPower =
-            data->reports[i].txPower;
-        message.data.chreBleAdvertisementEvent.reports[i]
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .primaryPhy = data->reports[i].primaryPhy;
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .secondaryPhy = data->reports[i].secondaryPhy;
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .advertisingSid = data->reports[i].advertisingSid;
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .txPower = data->reports[i].txPower;
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
             .periodicAdvertisingInterval =
             data->reports[i].periodicAdvertisingInterval;
-        message.data.chreBleAdvertisementEvent.reports[i].rssi =
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i].rssi =
             data->reports[i].rssi;
-        message.data.chreBleAdvertisementEvent.reports[i].directAddressType =
-            data->reports[i].directAddressType;
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .directAddressType = data->reports[i].directAddressType;
 
-        message.data.chreBleAdvertisementEvent.reports[i].directAddress.size =
-            CHRE_BLE_ADDRESS_LEN;
-        std::memcpy(message.data.chreBleAdvertisementEvent.reports[i]
-                        .directAddress.bytes,
-                    data->reports[i].directAddress, CHRE_BLE_ADDRESS_LEN);
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .directAddress.size = CHRE_BLE_ADDRESS_LEN;
+        std::memcpy(
+            gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+                .directAddress.bytes,
+            data->reports[i].directAddress, CHRE_BLE_ADDRESS_LEN);
 
-        message.data.chreBleAdvertisementEvent.reports[i].data.size =
-            data->reports[i].dataLength;
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .data.size = data->reports[i].dataLength;
         std::memcpy(
-            message.data.chreBleAdvertisementEvent.reports[i].data.bytes,
+            gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+                .data.bytes,
             data->reports[i].data, data->reports[i].dataLength);
 
-        message.data.chreBleAdvertisementEvent.reports[i].reserved =
-            data->reports[i].reserved;
+        gGeneralEventsMessage.data.chreBleAdvertisementEvent.reports[i]
+            .reserved = data->reports[i].reserved;
       }
 
-      message.status = true;
-      message.which_data =
+      gGeneralEventsMessage.status = true;
+      gGeneralEventsMessage.which_data =
           chre_rpc_GeneralEventsMessage_chreBleAdvertisementEvent_tag;
       break;
     }
     case CHRE_EVENT_AUDIO_SAMPLING_CHANGE: {
       const auto *data =
           static_cast<const struct chreAudioSourceStatusEvent *>(eventData);
-      message.data.chreAudioSourceStatusEvent.handle = data->handle;
-      message.data.chreAudioSourceStatusEvent.status.enabled =
+      gGeneralEventsMessage.data.chreAudioSourceStatusEvent.handle =
+          data->handle;
+      gGeneralEventsMessage.data.chreAudioSourceStatusEvent.status.enabled =
           data->status.enabled;
-      message.data.chreAudioSourceStatusEvent.status.suspended =
+      gGeneralEventsMessage.data.chreAudioSourceStatusEvent.status.suspended =
           data->status.suspended;
 
-      message.status = true;
-      message.which_data =
+      gGeneralEventsMessage.status = true;
+      gGeneralEventsMessage.which_data =
           chre_rpc_GeneralEventsMessage_chreAudioSourceStatusEvent_tag;
       break;
     }
@@ -616,13 +640,13 @@ void ChreApiTestService::handleGatheringEvent(uint16_t eventType,
     return;
   }
 
-  if (!message.status) {
+  if (!gGeneralEventsMessage.status) {
     LOGE("GatherEvents: unable to create message for event with type: %" PRIu16,
          eventType);
     return;
   }
 
-  sendGeneralEventToHost(message);
+  sendGeneralEventToHost(gGeneralEventsMessage);
 }
 
 void ChreApiTestService::handleTimerEvent(const void *cookie) {
diff --git a/apps/test/common/chre_reliable_message_test/inc/chre_reliable_message_test_manager.h b/apps/test/common/chre_reliable_message_test/inc/chre_reliable_message_test_manager.h
index b5f058e5..127ca6cc 100644
--- a/apps/test/common/chre_reliable_message_test/inc/chre_reliable_message_test_manager.h
+++ b/apps/test/common/chre_reliable_message_test/inc/chre_reliable_message_test_manager.h
@@ -81,6 +81,9 @@ class Manager {
 
   // If the test is running.
   bool mTestRunning = false;
+
+  // The timer handle for the test timeout.
+  uint32_t mTimerHandle = CHRE_TIMER_INVALID;
 };
 
 // The CHRE reliable message test manager singleton.
diff --git a/apps/test/common/chre_reliable_message_test/src/chre_reliable_message_test_manager.cc b/apps/test/common/chre_reliable_message_test/src/chre_reliable_message_test_manager.cc
index a340669a..1d65befd 100644
--- a/apps/test/common/chre_reliable_message_test/src/chre_reliable_message_test_manager.cc
+++ b/apps/test/common/chre_reliable_message_test/src/chre_reliable_message_test_manager.cc
@@ -25,6 +25,7 @@
 #include "chre/util/nanoapp/log.h"
 #include "chre/util/nested_data_ptr.h"
 #include "chre/util/optional.h"
+#include "chre/util/time.h"
 #include "chre_api/chre.h"
 #include "send_message.h"
 
@@ -63,11 +64,24 @@ void Manager::handleEvent(uint32_t senderInstanceId, uint16_t eventType,
       handleAsyncMessageStatus(result);
       break;
     }
+    case CHRE_EVENT_TIMER: {
+      mTimerHandle = CHRE_TIMER_INVALID;
+      completeTest(true);
+      break;
+    }
   }
 
-  if (mNumExpectedAsyncResults == 0 && mNumExpectedHostEchoMessages == 0 &&
+  if (mNumExpectedAsyncResults == 0 &&
+      mNumExpectedHostEchoMessages == 0 &&
       mNumExpectedFreeMessageCallbacks == 0) {
-    completeTest(true);
+    // Wait for 2s (twice reliable message timeout) to detect duplicates
+    constexpr Seconds kTimeoutForTestComplete(2);
+    mTimerHandle = chreTimerSet(kTimeoutForTestComplete.toRawNanoseconds(),
+                                /* cookie= */ nullptr, /* oneShot= */ true);
+    if (mTimerHandle == CHRE_TIMER_INVALID) {
+      LOGE("Failed to set the timer for test complete");
+      completeTest(false, "Failed to set the timer for test complete");
+    }
   }
 }
 
@@ -92,12 +106,18 @@ void Manager::completeTest(bool success, const char *message) {
 
   if (success) {
     LOGI("Test completed successfully");
-  } else {
+  } else if (message != nullptr) {
     LOGE("Test completed in error with message \"%s\"", message);
+  } else {
+    LOGE("Test completed in error");
   }
 
   mTestRunning = false;
-  chreHeapFree(mMessage);
+  if (mMessage != nullptr) {
+    chreHeapFree(mMessage);
+    mMessage = nullptr;
+  }
+
   sendTestResultWithMsgToHost(
       mHostEndpointId, chre_reliable_message_test_MessageType_TEST_RESULT,
       success, message, /* abortOnFailure= */ false);
diff --git a/apps/test/common/chre_settings_test/inc/chre_settings_test_manager.h b/apps/test/common/chre_settings_test/inc/chre_settings_test_manager.h
index 602b60d0..ece5b41a 100644
--- a/apps/test/common/chre_settings_test/inc/chre_settings_test_manager.h
+++ b/apps/test/common/chre_settings_test/inc/chre_settings_test_manager.h
@@ -111,6 +111,13 @@ class Manager {
    */
   void handleDataFromChre(uint16_t eventType, const void *eventData);
 
+  /**
+   * Requests the ranging wifi scan for the WIFI_RTT Feature.
+   *
+   * @return true if the request was accepted by CHRE
+   */
+  bool requestRangingForFeatureWifiRtt();
+
   /**
    * Starts a test for a given feature.
    *
@@ -159,7 +166,7 @@ class Manager {
   /*
    * @param data CHRE event data containing the cookie used to set the timer.
    */
-  void handleTimeout(const void *data);
+  void handleTimerEvent(const void *data);
 
   /**
    * Handles the BLE async result
@@ -188,6 +195,9 @@ class Manager {
   //! True if we have received a chreAudioSourceStatusEvent with suspended ==
   //! false.
   bool mAudioSamplingEnabled;
+
+  //! The number of retries available for requesting wifi scans before quitting
+  uint8_t mWifiRequestRetries;
 };
 
 // The settings test manager singleton.
diff --git a/apps/test/common/chre_settings_test/src/chre_settings_test_manager.cc b/apps/test/common/chre_settings_test/src/chre_settings_test_manager.cc
index 2ff7b5e7..85502cce 100644
--- a/apps/test/common/chre_settings_test/src/chre_settings_test_manager.cc
+++ b/apps/test/common/chre_settings_test/src/chre_settings_test_manager.cc
@@ -56,6 +56,10 @@ uint32_t gAudioDataTimerHandle = CHRE_TIMER_INVALID;
 constexpr uint32_t kAudioDataTimerCookie = 0xc001cafe;
 uint32_t gAudioStatusTimerHandle = CHRE_TIMER_INVALID;
 constexpr uint32_t kAudioStatusTimerCookie = 0xb01dcafe;
+uint32_t gRangingRequestRetryTimerHandle = CHRE_TIMER_INVALID;
+constexpr uint32_t kRangingRequestRetryTimerCookie = 0x600dcafe;
+
+constexpr uint8_t kMaxWifiRequestRetries = 3;
 
 bool getFeature(const chre_settings_test_TestCommand &command,
                 Manager::Feature *feature) {
@@ -285,7 +289,7 @@ void Manager::handleDataFromChre(uint16_t eventType, const void *eventData) {
         break;
 
       case CHRE_EVENT_TIMER:
-        handleTimeout(eventData);
+        handleTimerEvent(eventData);
         break;
 
       case CHRE_EVENT_WIFI_ASYNC_RESULT:
@@ -315,6 +319,12 @@ void Manager::handleDataFromChre(uint16_t eventType, const void *eventData) {
   }
 }
 
+bool Manager::requestRangingForFeatureWifiRtt() {
+  struct chreWifiRangingParams params = {
+      .targetListLen = 1, .targetList = &mCachedRangingTarget.value()};
+  return chreWifiRequestRangingAsync(&params, &kWifiRttCookie);
+}
+
 bool Manager::startTestForFeature(Feature feature) {
   bool success = true;
   switch (feature) {
@@ -326,9 +336,8 @@ bool Manager::startTestForFeature(Feature feature) {
       if (!mCachedRangingTarget.has_value()) {
         LOGE("No cached WiFi RTT ranging target");
       } else {
-        struct chreWifiRangingParams params = {
-            .targetListLen = 1, .targetList = &mCachedRangingTarget.value()};
-        success = chreWifiRequestRangingAsync(&params, &kWifiRttCookie);
+        mWifiRequestRetries = 0;
+        success = requestRangingForFeatureWifiRtt();
       }
       break;
     }
@@ -406,17 +415,46 @@ bool Manager::validateAsyncResult(const chreAsyncResult *result,
 
 void Manager::handleWifiAsyncResult(const chreAsyncResult *result) {
   bool success = false;
+  uint8_t feature = static_cast<uint8_t>(mTestSession->feature);
   switch (result->requestType) {
     case CHRE_WIFI_REQUEST_TYPE_REQUEST_SCAN: {
       if (mTestSession->feature == Feature::WIFI_RTT) {
-        // Ignore validating the scan async response since we only care about
-        // the actual scan event to initiate the RTT request. A failure to
-        // receive the scan response should cause a timeout at the host.
-        return;
+        if (result->errorCode == CHRE_ERROR_BUSY) {
+          if (mWifiRequestRetries >= kMaxWifiRequestRetries) {
+            // The request has failed repeatedly and we are no longer retrying
+            // Return success=false to the host rather than timeout.
+            LOGE("Reached max wifi request retries: test feature %" PRIu8
+                 ". Num retries=%" PRIu8,
+                 feature, kMaxWifiRequestRetries);
+            break;
+          }
+
+          // Retry on CHRE_ERROR_BUSY after a short delay
+          mWifiRequestRetries++;
+          uint64_t delay = kOneSecondInNanoseconds;
+          gRangingRequestRetryTimerHandle = chreTimerSet(
+              delay, &kRangingRequestRetryTimerCookie, /*oneShot=*/true);
+          LOGW(
+              "Request failed due to CHRE_ERROR_BUSY. Retrying after "
+              "delay=%" PRIu64 "ns, num_retries=%" PRIu8 "/%" PRIu8,
+              delay, mWifiRequestRetries, kMaxWifiRequestRetries);
+          return;
+        }
+
+        if (result->errorCode == CHRE_ERROR_NONE) {
+          // Ignore validating the scan async response since we only care about
+          // the actual scan event to initiate the RTT request.
+          return;
+        } else {
+          LOGE("Unexpected error in async result: test feature: %" PRIu8
+               " error: %" PRIu8,
+               feature, static_cast<uint8_t>(result->errorCode));
+          break;
+        }
       }
       if (mTestSession->feature != Feature::WIFI_SCANNING) {
         LOGE("Unexpected WiFi scan async result: test feature %" PRIu8,
-             static_cast<uint8_t>(mTestSession->feature));
+             feature);
       } else {
         success = validateAsyncResult(
             result, static_cast<const void *>(&kWifiScanningCookie));
@@ -426,7 +464,7 @@ void Manager::handleWifiAsyncResult(const chreAsyncResult *result) {
     case CHRE_WIFI_REQUEST_TYPE_RANGING: {
       if (mTestSession->feature != Feature::WIFI_RTT) {
         LOGE("Unexpected WiFi ranging async result: test feature %" PRIu8,
-             static_cast<uint8_t>(mTestSession->feature));
+             feature);
       } else {
         success = validateAsyncResult(
             result, static_cast<const void *>(&kWifiRttCookie));
@@ -627,9 +665,16 @@ void Manager::handleAudioDataEvent(const struct chreAudioDataEvent *event) {
   }
 }
 
-void Manager::handleTimeout(const void *eventData) {
+void Manager::handleTimerEvent(const void *eventData) {
   bool testSuccess = false;
   auto *cookie = static_cast<const uint32_t *>(eventData);
+
+  if (*cookie == kRangingRequestRetryTimerCookie) {
+    gRangingRequestRetryTimerHandle = CHRE_TIMER_INVALID;
+    requestRangingForFeatureWifiRtt();
+    return;
+  }
+
   // Ignore the audio status timer if the suspended status was received.
   if (*cookie == kAudioStatusTimerCookie && !mAudioSamplingEnabled) {
     gAudioStatusTimerHandle = CHRE_TIMER_INVALID;
diff --git a/build/variant/aosp_riscv55e03_tinysys.mk b/build/variant/aosp_riscv55e03_tinysys.mk
index 92d8a626..616ca543 100644
--- a/build/variant/aosp_riscv55e03_tinysys.mk
+++ b/build/variant/aosp_riscv55e03_tinysys.mk
@@ -7,9 +7,15 @@ include $(CHRE_PREFIX)/build/clean_build_template_args.mk
 TARGET_NAME = aosp_riscv55e03_tinysys
 ifneq ($(filter $(TARGET_NAME)% all, $(MAKECMDGOALS)),)
 
-ifeq ($(RISCV_TINYSYS_PREFIX),)
-$(error "The tinysys code directory needs to be exported as the RISCV_TINYSYS_PREFIX \
-         environment variable")
+ifneq ($(IS_NANOAPP_BUILD),)
+  # Inline functions of ctype.h for nanoapps
+  COMMON_CFLAGS += -DUSE_CHARSET_ASCII
+else
+  # only enforce RISCV_TINYSYS_PREFIX when building CHRE
+  ifeq ($(RISCV_TINYSYS_PREFIX),)
+  $(error "The tinysys code directory needs to be exported as the RISCV_TINYSYS_PREFIX \
+           environment variable")
+  endif
 endif
 
 TARGET_CFLAGS = $(TINYSYS_CFLAGS)
@@ -20,6 +26,12 @@ TARGET_SO_LATE_LIBS = $(AOSP_RISCV_TINYSYS_LATE_LIBS)
 TARGET_PLATFORM_ID = 0x476f6f676c003000
 
 # Macros #######################################################################
+TINYSYS_CFLAGS += $(FLATBUFFERS_CFLAGS)
+TINYSYS_CFLAGS += $(MBEDTLS_CFLAGS)
+
+TINYSYS_CFLAGS += -DCFG_DRAM_HEAP_SUPPORT
+TINYSYS_CFLAGS += -DCHRE_LOADER_ARCH=EM_RISCV
+TINYSYS_CFLAGS += -DCHRE_NANOAPP_LOAD_ALIGNMENT=4096
 
 TINYSYS_CFLAGS += -D__riscv
 TINYSYS_CFLAGS += -DMRV55
diff --git a/build/variant/aosp_riscv55e300_tinysys.mk b/build/variant/aosp_riscv55e300_tinysys.mk
index cbcfe16d..f8ffbf32 100644
--- a/build/variant/aosp_riscv55e300_tinysys.mk
+++ b/build/variant/aosp_riscv55e300_tinysys.mk
@@ -7,9 +7,15 @@ include $(CHRE_PREFIX)/build/clean_build_template_args.mk
 TARGET_NAME = aosp_riscv55e300_tinysys
 ifneq ($(filter $(TARGET_NAME)% all, $(MAKECMDGOALS)),)
 
-ifeq ($(RISCV_TINYSYS_PREFIX),)
-$(error "The tinysys code directory needs to be exported as the RISCV_TINYSYS_PREFIX \
-         environment variable")
+ifneq ($(IS_NANOAPP_BUILD),)
+  # Inline functions of ctype.h for nanoapps
+  COMMON_CFLAGS += -DUSE_CHARSET_ASCII
+else
+  # only enforce RISCV_TINYSYS_PREFIX when building CHRE
+  ifeq ($(RISCV_TINYSYS_PREFIX),)
+  $(error "The tinysys code directory needs to be exported as the RISCV_TINYSYS_PREFIX \
+           environment variable")
+  endif
 endif
 
 TARGET_CFLAGS = $(TINYSYS_CFLAGS)
@@ -21,6 +27,13 @@ TARGET_PLATFORM_ID = 0x476f6f676c003001
 
 # Macros #######################################################################
 
+TINYSYS_CFLAGS += $(FLATBUFFERS_CFLAGS)
+TINYSYS_CFLAGS += $(MBEDTLS_CFLAGS)
+
+TINYSYS_CFLAGS += -DCFG_DRAM_HEAP_SUPPORT
+TINYSYS_CFLAGS += -DCHRE_LOADER_ARCH=EM_RISCV
+TINYSYS_CFLAGS += -DCHRE_NANOAPP_LOAD_ALIGNMENT=4096
+
 TINYSYS_CFLAGS += -D__riscv
 TINYSYS_CFLAGS += -DMRV55
 TINYSYS_CFLAGS += -D_LIBCPP_HAS_NO_LONG_LONG
diff --git a/chpp/Android.bp b/chpp/Android.bp
index 588d2757..d969812e 100644
--- a/chpp/Android.bp
+++ b/chpp/Android.bp
@@ -24,6 +24,53 @@ package {
     default_applicable_licenses: ["system_chre_license"],
 }
 
+cc_defaults {
+    name: "chre_chpp_flags",
+    cflags: [
+        "-DCHPP_CHECKSUM_ENABLED",
+        "-DCHPP_DEBUG_ASSERT_ENABLED",
+        "-DCHPP_ENABLE_WORK_MONITOR",
+        "-DCHPP_EXPECTED_SERVICE_COUNT=3",
+        "-DCHPP_MAX_REGISTERED_CLIENTS=16",
+        "-DCHPP_MAX_REGISTERED_SERVICES=16",
+
+        "-DCHPP_CLIENT_ENABLED_DISCOVERY",
+        "-DCHPP_CLIENT_ENABLED_GNSS",
+        "-DCHPP_CLIENT_ENABLED_LOOPBACK",
+        "-DCHPP_CLIENT_ENABLED_TIMESYNC",
+        "-DCHPP_CLIENT_ENABLED_TRANSPORT_LOOPBACK",
+        "-DCHPP_CLIENT_ENABLED_WIFI",
+        "-DCHPP_CLIENT_ENABLED_WWAN",
+        "-DCHPP_SERVICE_ENABLED_GNSS",
+        "-DCHPP_SERVICE_ENABLED_TRANSPORT_LOOPBACK",
+        "-DCHPP_SERVICE_ENABLED_WIFI",
+        "-DCHPP_SERVICE_ENABLED_WWAN",
+
+        "-DCHPP_GNSS_DEFAULT_CAPABILITIES=0x7",
+        "-DCHPP_WIFI_DEFAULT_CAPABILITIES=0xf",
+        "-DCHPP_WWAN_DEFAULT_CAPABILITIES=0x1",
+    ],
+    visibility: ["//visibility:override"],
+}
+
+filegroup {
+    name: "chre_chpp_core_files",
+    srcs: [
+        "app.c",
+        "clients.c",
+        "platform/linux/memory.c",
+        "platform/linux/notifier.c",
+        "platform/pal_api.c",
+        "platform/shared/crc.c",
+        "services.c",
+        "services/discovery.c",
+        "services/loopback.c",
+        "services/nonhandle.c",
+        "services/timesync.c",
+        "transport.c",
+    ],
+}
+
 // Everything needed to run CHPP on Linux, except for the link layer.
 // Note that this is cc_defaults and not a lib because modules that inherit
 // these defaults may need to change compilation flags for sources here.
@@ -31,12 +78,6 @@ cc_defaults {
     name: "chre_chpp_core_without_link",
     vendor: true,
     cflags: [
-        "-DCHPP_CLIENT_ENABLED_TRANSPORT_LOOPBACK",
-        "-DCHPP_DEBUG_ASSERT_ENABLED",
-        "-DCHPP_ENABLE_WORK_MONITOR",
-        "-DCHPP_MAX_REGISTERED_CLIENTS=3",
-        "-DCHPP_MAX_REGISTERED_SERVICES=3",
-        "-DCHPP_SERVICE_ENABLED_TRANSPORT_LOOPBACK",
         // Required for pthread_setname_np()
         "-D_GNU_SOURCE",
         // clock_gettime() requires _POSIX_C_SOURCE >= 199309L
@@ -61,22 +102,7 @@ cc_defaults {
         "-std=c11",
     ],
     srcs: [
-        "app.c",
-        "clients.c",
-        "platform/linux/memory.c",
-        "platform/linux/notifier.c",
-        "platform/pal_api.c",
-        "platform/shared/crc.c",
-        "services.c",
-        "services/discovery.c",
-        "services/loopback.c",
-        "services/nonhandle.c",
-        "services/timesync.c",
-        "transport.c",
-    ],
-    export_include_dirs: [
-        "include",
-        "platform/linux/include",
+        ":chre_chpp_core_files",
     ],
     header_libs: [
         "chre_api",
@@ -90,25 +116,8 @@ cc_defaults {
     host_supported: true,
 }
 
-// Meant to be combined with chre_chpp_core_without_link to add in the full set
-// of optional clients and services.
-cc_defaults {
-    name: "chre_chpp_clients_and_services",
-    cflags: [
-        "-DCHPP_CLIENT_ENABLED_DISCOVERY",
-        "-DCHPP_CLIENT_ENABLED_GNSS",
-        "-DCHPP_CLIENT_ENABLED_LOOPBACK",
-        "-DCHPP_CLIENT_ENABLED_TIMESYNC",
-        "-DCHPP_CLIENT_ENABLED_WIFI",
-        "-DCHPP_CLIENT_ENABLED_WWAN",
-        "-DCHPP_SERVICE_ENABLED_GNSS",
-        "-DCHPP_SERVICE_ENABLED_WIFI",
-        "-DCHPP_SERVICE_ENABLED_WWAN",
-
-        "-DCHPP_GNSS_DEFAULT_CAPABILITIES=0x7",
-        "-DCHPP_WIFI_DEFAULT_CAPABILITIES=0xf",
-        "-DCHPP_WWAN_DEFAULT_CAPABILITIES=0x1",
-    ],
+filegroup {
+    name: "chre_chpp_clients_and_services_files",
     srcs: [
         "clients/discovery.c",
         "clients/gnss.c",
@@ -127,32 +136,47 @@ cc_defaults {
     ],
 }
 
+// Meant to be combined with chre_chpp_core_without_link to add in the full set
+// of optional clients and services.
+cc_defaults {
+    name: "chre_chpp_clients_and_services",
+    srcs: [
+        ":chre_chpp_clients_and_services_files",
+    ],
+}
+
+filegroup {
+    name: "chre_chpp_linux_files",
+    srcs: [
+        "platform/linux/link.c",
+    ],
+}
+
 cc_library_static {
     name: "chre_chpp_linux",
     defaults: [
         "chre_chpp_clients_and_services",
         "chre_chpp_core_without_link",
+        "chre_chpp_flags",
     ],
     srcs: [
-        "platform/linux/link.c",
+        ":chre_chpp_linux_files",
+    ],
+    export_include_dirs: [
+        "include",
+        "platform/linux/include",
     ],
 }
 
-cc_test_host {
-    name: "chre_chpp_linux_tests",
-    // TODO(b/232537107): Evaluate if isolated can be turned on
-    isolated: false,
-    cflags: [
-        "-DCHPP_CHECKSUM_ENABLED",
-        "-DCHPP_CLIENT_ENABLED_TRANSPORT_LOOPBACK",
-        "-DCHPP_ENABLE_WORK_MONITOR",
-        "-DCHPP_MAX_REGISTERED_CLIENTS=3",
-        "-DCHPP_MAX_REGISTERED_SERVICES=3",
-
-        "-DCHPP_GNSS_DEFAULT_CAPABILITIES=0x7",
-        "-DCHPP_WIFI_DEFAULT_CAPABILITIES=0xf",
-        "-DCHPP_WWAN_DEFAULT_CAPABILITIES=0x1",
+filegroup {
+    name: "chre_chpp_linux_tests_utility_files",
+    srcs: [
+        "test/transport_util.cpp",
     ],
+}
+
+filegroup {
+    name: "chre_chpp_linux_tests_files",
     srcs: [
         "test/app_discovery_test.cpp",
         "test/app_notification_test.cpp",
@@ -163,6 +187,19 @@ cc_test_host {
         "test/gnss_test.cpp",
         "test/transport_test.cpp",
     ],
+}
+
+cc_test_host {
+    name: "chre_chpp_linux_tests",
+    // TODO(b/232537107): Evaluate if isolated can be turned on
+    isolated: false,
+    defaults: [
+        "chre_chpp_flags",
+    ],
+    srcs: [
+        ":chre_chpp_linux_tests_files",
+        ":chre_chpp_linux_tests_utility_files",
+    ],
     static_libs: [
         "chre_chpp_linux",
         "chre_pal_linux",
diff --git a/chpp/app.c b/chpp/app.c
index 0ee7fb9a..55d6bc6a 100644
--- a/chpp/app.c
+++ b/chpp/app.c
@@ -36,6 +36,12 @@
 #include "chpp/macros.h"
 #include "chpp/notifier.h"
 #include "chpp/pal_api.h"
+#ifdef CHPP_CLIENT_ENABLED_VENDOR
+#include "chpp/platform/vendor_clients.h"
+#endif
+#ifdef CHPP_SERVICE_ENABLED_VENDOR
+#include "chpp/platform/vendor_services.h"
+#endif
 #include "chpp/services.h"
 #include "chpp/services/discovery.h"
 #include "chpp/services/loopback.h"
@@ -635,10 +641,16 @@ void chppAppInitWithClientServiceSet(
 
 #ifdef CHPP_SERVICE_ENABLED
   chppRegisterCommonServices(appContext);
+#ifdef CHPP_SERVICE_ENABLED_VENDOR
+  chppRegisterVendorServices(appContext);
+#endif
 #endif
 
 #ifdef CHPP_CLIENT_ENABLED
   chppRegisterCommonClients(appContext);
+#ifdef CHPP_CLIENT_ENABLED_VENDOR
+  chppRegisterVendorClients(appContext);
+#endif
   chppInitBasicClients(appContext);
 #endif
 }
@@ -650,10 +662,16 @@ void chppAppDeinit(struct ChppAppState *appContext) {
   chppDeinitMatchedClients(appContext);
   chppDeinitBasicClients(appContext);
   chppDeregisterCommonClients(appContext);
+#ifdef CHPP_CLIENT_ENABLED_VENDOR
+  chppDeregisterVendorClients(appContext);
+#endif
 #endif
 
 #ifdef CHPP_SERVICE_ENABLED
   chppDeregisterCommonServices(appContext);
+#ifdef CHPP_SERVICE_ENABLED_VENDOR
+  chppDeregisterVendorServices(appContext);
+#endif
 #endif
 
   chppPalSystemApiDeinit(appContext);
diff --git a/chpp/include/chpp/app.h b/chpp/include/chpp/app.h
index eda11fa5..907a07b4 100644
--- a/chpp/include/chpp/app.h
+++ b/chpp/include/chpp/app.h
@@ -478,6 +478,8 @@ struct ChppClientServiceSet {
   bool gnssClient : 1;
   bool wwanClient : 1;
   bool loopbackClient : 1;
+  bool vendorClients : 1;
+  bool vendorServices : 1;
 };
 
 struct ChppLoopbackClientState;
diff --git a/chpp/include/chpp/services.h b/chpp/include/chpp/services.h
index a89af3cb..a594af7b 100644
--- a/chpp/include/chpp/services.h
+++ b/chpp/include/chpp/services.h
@@ -33,7 +33,8 @@ extern "C" {
  ***********************************************/
 
 #if defined(CHPP_SERVICE_ENABLED_WWAN) || \
-    defined(CHPP_SERVICE_ENABLED_WIFI) || defined(CHPP_SERVICE_ENABLED_GNSS)
+    defined(CHPP_SERVICE_ENABLED_WIFI) || \
+    defined(CHPP_SERVICE_ENABLED_GNSS) || defined(CHPP_SERVICE_ENABLED_VENDOR)
 #define CHPP_SERVICE_ENABLED
 #endif
 
diff --git a/chpp/test/transport_test.cpp b/chpp/test/transport_test.cpp
index f1defb39..14c4776c 100644
--- a/chpp/test/transport_test.cpp
+++ b/chpp/test/transport_test.cpp
@@ -43,11 +43,9 @@
 #include "chpp/transport.h"
 #include "chre/pal/wwan.h"
 
-namespace {
+namespace chpp::test {
 
-// Preamble as separate bytes for testing
-constexpr uint8_t kChppPreamble0 = 0x68;
-constexpr uint8_t kChppPreamble1 = 0x43;
+namespace {
 
 // Max size of payload sent to chppRxDataCb (bytes)
 constexpr size_t kMaxChunkSize = 20000;
@@ -59,11 +57,13 @@ constexpr size_t kMaxPacketSize =
 constexpr int kChunkSizes[] = {0, 1, 2, 3, 4, 21, 100, 1000, 10001, 20000};
 
 // Number of services
-constexpr int kServiceCount = 3;
+constexpr int kServiceCount = CHPP_EXPECTED_SERVICE_COUNT;
 
 // State of the link layer.
 struct ChppLinuxLinkState gChppLinuxLinkContext;
 
+}  // namespace
+
 /*
  * Test suite for the CHPP Transport Layer
  */
@@ -100,255 +100,6 @@ class TransportTests : public testing::TestWithParam<int> {
   uint8_t mBuf[kMaxPacketSize] = {};
 };
 
-/**
- * Wait for chppTransportDoWork() to finish after it is notified by
- * chppEnqueueTxPacket to run.
- */
-void WaitForTransport(struct ChppTransportState *transportContext) {
-  // Start sending data out.
-  cycleSendThread();
-  // Wait for data to be received and processed.
-  std::this_thread::sleep_for(std::chrono::milliseconds(50));
-
-  // Should have reset loc and length for next packet / datagram
-  EXPECT_EQ(transportContext->rxStatus.locInDatagram, 0);
-  EXPECT_EQ(transportContext->rxDatagram.length, 0);
-}
-
-/**
- * Validates a ChppTestResponse. Since the error field within the
- * ChppAppHeader struct is optional (and not used for common services), this
- * function returns the error field to be checked if desired, depending on the
- * service.
- *
- * @param buf Buffer containing response.
- * @param ackSeq Ack sequence to be verified.
- * @param handle Handle number to be verified
- * @param transactionID Transaction ID to be verified.
- *
- * @return The error field within the ChppAppHeader struct that is used by some
- * but not all services.
- */
-uint8_t validateChppTestResponse(void *buf, uint8_t ackSeq, uint8_t handle,
-                                 uint8_t transactionID) {
-  struct ChppTestResponse *response = (ChppTestResponse *)buf;
-
-  // Check preamble
-  EXPECT_EQ(response->preamble0, kChppPreamble0);
-  EXPECT_EQ(response->preamble1, kChppPreamble1);
-
-  // Check response transport headers
-  EXPECT_EQ(response->transportHeader.packetCode, CHPP_TRANSPORT_ERROR_NONE);
-  EXPECT_EQ(response->transportHeader.ackSeq, ackSeq);
-
-  // Check response app headers
-  EXPECT_EQ(response->appHeader.handle, handle);
-  EXPECT_EQ(response->appHeader.type, CHPP_MESSAGE_TYPE_SERVICE_RESPONSE);
-  EXPECT_EQ(response->appHeader.transaction, transactionID);
-
-  // Return optional response error to be checked if desired
-  return response->appHeader.error;
-}
-
-/**
- * Aborts a packet and validates state.
- *
- * @param transportcontext Maintains status for each transport layer instance.
- */
-void endAndValidatePacket(struct ChppTransportState *transportContext) {
-  chppRxPacketCompleteCb(transportContext);
-  EXPECT_EQ(transportContext->rxStatus.state, CHPP_STATE_PREAMBLE);
-  EXPECT_EQ(transportContext->rxStatus.locInDatagram, 0);
-  EXPECT_EQ(transportContext->rxDatagram.length, 0);
-}
-
-/**
- * Adds a preamble to a certain location in a buffer, and increases the location
- * accordingly, to account for the length of the added preamble.
- *
- * @param buf Buffer.
- * @param location Location to add the preamble, which its value will be
- * increased accordingly.
- */
-void addPreambleToBuf(uint8_t *buf, size_t *location) {
-  buf[(*location)++] = kChppPreamble0;
-  buf[(*location)++] = kChppPreamble1;
-}
-
-/**
- * Adds a transport header (with default values) to a certain location in a
- * buffer, and increases the location accordingly, to account for the length of
- * the added transport header.
- *
- * @param buf Buffer.
- * @param location Location to add the transport header, which its value will be
- * increased accordingly.
- *
- * @return Pointer to the added transport header (e.g. to modify its fields).
- */
-ChppTransportHeader *addTransportHeaderToBuf(uint8_t *buf, size_t *location) {
-  size_t oldLoc = *location;
-
-  // Default values for initial, minimum size request packet
-  ChppTransportHeader transHeader = {};
-  transHeader.flags = CHPP_TRANSPORT_FLAG_FINISHED_DATAGRAM;
-  transHeader.packetCode = CHPP_TRANSPORT_ERROR_NONE;
-  transHeader.ackSeq = 1;
-  transHeader.seq = 0;
-  transHeader.length = sizeof(ChppAppHeader);
-  transHeader.reserved = 0;
-
-  memcpy(&buf[*location], &transHeader, sizeof(transHeader));
-  *location += sizeof(transHeader);
-
-  return (ChppTransportHeader *)&buf[oldLoc];
-}
-
-/**
- * Adds an app header (with default values) to a certain location in a buffer,
- * and increases the location accordingly, to account for the length of the
- * added app header.
- *
- * @param buf Buffer.
- * @param location Location to add the app header, which its value will be
- * increased accordingly.
- *
- * @return Pointer to the added app header (e.g. to modify its fields).
- */
-ChppAppHeader *addAppHeaderToBuf(uint8_t *buf, size_t *location) {
-  size_t oldLoc = *location;
-
-  // Default values - to be updated later as necessary
-  ChppAppHeader appHeader = {};
-  appHeader.handle = CHPP_HANDLE_NEGOTIATED_RANGE_START;
-  appHeader.type = CHPP_MESSAGE_TYPE_CLIENT_REQUEST;
-  appHeader.transaction = 0;
-  appHeader.error = CHPP_APP_ERROR_NONE;
-  appHeader.command = 0;
-
-  memcpy(&buf[*location], &appHeader, sizeof(appHeader));
-  *location += sizeof(appHeader);
-
-  return (ChppAppHeader *)&buf[oldLoc];
-}
-
-/**
- * Adds a transport footer to a certain location in a buffer, and increases the
- * location accordingly, to account for the length of the added preamble.
- *
- * @param buf Buffer.
- * @param location Location to add the footer. The value of location will be
- * increased accordingly.
- *
- */
-void addTransportFooterToBuf(uint8_t *buf, size_t *location) {
-  uint32_t *checksum = (uint32_t *)&buf[*location];
-
-  *checksum = chppCrc32(0, &buf[CHPP_PREAMBLE_LEN_BYTES],
-                        *location - CHPP_PREAMBLE_LEN_BYTES);
-
-  *location += sizeof(ChppTransportFooter);
-}
-
-/**
- * Opens a service and checks to make sure it was opened correctly.
- *
- * @param transportContext Transport layer context.
- * @param buf Buffer.
- * @param ackSeq Ack sequence of the packet to be sent out
- * @param seq Sequence number of the packet to be sent out.
- * @param handle Handle of the service to be opened.
- * @param transactionID Transaction ID for the open request.
- * @param command Open command.
- */
-void openService(ChppTransportState *transportContext, uint8_t *buf,
-                 uint8_t ackSeq, uint8_t seq, uint8_t handle,
-                 uint8_t transactionID, uint16_t command) {
-  size_t len = 0;
-
-  addPreambleToBuf(buf, &len);
-
-  ChppTransportHeader *transHeader = addTransportHeaderToBuf(buf, &len);
-  transHeader->ackSeq = ackSeq;
-  transHeader->seq = seq;
-
-  ChppAppHeader *appHeader = addAppHeaderToBuf(buf, &len);
-  appHeader->handle = handle;
-  appHeader->transaction = transactionID;
-  appHeader->command = command;
-
-  addTransportFooterToBuf(buf, &len);
-
-  // Send header + payload (if any) + footer
-  EXPECT_TRUE(chppRxDataCb(transportContext, buf, len));
-
-  // Check for correct state
-  uint8_t nextSeq = transHeader->seq + 1;
-  EXPECT_EQ(transportContext->rxStatus.expectedSeq, nextSeq);
-  EXPECT_EQ(transportContext->rxStatus.state, CHPP_STATE_PREAMBLE);
-
-  // Wait for response
-  WaitForTransport(transportContext);
-
-  // Validate common response fields
-  EXPECT_EQ(validateChppTestResponse(gChppLinuxLinkContext.buf, nextSeq, handle,
-                                     transactionID),
-            CHPP_APP_ERROR_NONE);
-
-  // Check response length
-  EXPECT_EQ(sizeof(ChppTestResponse), CHPP_PREAMBLE_LEN_BYTES +
-                                          sizeof(ChppTransportHeader) +
-                                          sizeof(ChppAppHeader));
-  EXPECT_EQ(transportContext->linkBufferSize,
-            sizeof(ChppTestResponse) + sizeof(ChppTransportFooter));
-}
-
-/**
- * Sends a command to a service and checks for errors.
- *
- * @param transportContext Transport layer context.
- * @param buf Buffer.
- * @param ackSeq Ack sequence of the packet to be sent out
- * @param seq Sequence number of the packet to be sent out.
- * @param handle Handle of the service to be opened.
- * @param transactionID Transaction ID for the open request.
- * @param command Command to be sent.
- */
-void sendCommandToService(ChppTransportState *transportContext, uint8_t *buf,
-                          uint8_t ackSeq, uint8_t seq, uint8_t handle,
-                          uint8_t transactionID, uint16_t command) {
-  size_t len = 0;
-
-  addPreambleToBuf(buf, &len);
-
-  ChppTransportHeader *transHeader = addTransportHeaderToBuf(buf, &len);
-  transHeader->ackSeq = ackSeq;
-  transHeader->seq = seq;
-
-  ChppAppHeader *appHeader = addAppHeaderToBuf(buf, &len);
-  appHeader->handle = handle;
-  appHeader->transaction = transactionID;
-  appHeader->command = command;
-
-  addTransportFooterToBuf(buf, &len);
-
-  // Send header + payload (if any) + footer
-  EXPECT_TRUE(chppRxDataCb(transportContext, buf, len));
-
-  // Check for correct state
-  uint8_t nextSeq = transHeader->seq + 1;
-  EXPECT_EQ(transportContext->rxStatus.expectedSeq, nextSeq);
-  EXPECT_EQ(transportContext->rxStatus.state, CHPP_STATE_PREAMBLE);
-
-  // Wait for response
-  WaitForTransport(transportContext);
-
-  // Validate common response fields
-  EXPECT_EQ(validateChppTestResponse(gChppLinuxLinkContext.buf, nextSeq, handle,
-                                     transactionID),
-            CHPP_APP_ERROR_NONE);
-}
-
 /**
  * A series of zeros shouldn't change state from CHPP_STATE_PREAMBLE
  */
@@ -838,14 +589,16 @@ TEST_F(TransportTests, WwanOpen) {
   uint8_t transactionID = 0;
   size_t len = 0;
 
+  EXPECT_EQ(findServiceHandle(&mAppContext, "WWAN", &handle), true);
+
   openService(&mTransportContext, mBuf, ackSeq++, seq++, handle,
-              transactionID++, CHPP_WWAN_OPEN);
+              transactionID++, CHPP_WWAN_OPEN, gChppLinuxLinkContext);
 
   addPreambleToBuf(mBuf, &len);
 
   uint16_t command = CHPP_WWAN_GET_CAPABILITIES;
   sendCommandToService(&mTransportContext, mBuf, ackSeq++, seq++, handle,
-                       transactionID++, command);
+                       transactionID++, command, gChppLinuxLinkContext);
 
   size_t responseLoc = sizeof(ChppTestResponse);
 
@@ -878,12 +631,14 @@ TEST_F(TransportTests, WifiOpen) {
   uint8_t handle = CHPP_HANDLE_NEGOTIATED_RANGE_START + 1;
   uint8_t transactionID = 0;
 
+  EXPECT_EQ(findServiceHandle(&mAppContext, "WiFi", &handle), true);
+
   openService(&mTransportContext, mBuf, ackSeq++, seq++, handle,
-              transactionID++, CHPP_WIFI_OPEN);
+              transactionID++, CHPP_WIFI_OPEN, gChppLinuxLinkContext);
 
   uint16_t command = CHPP_WIFI_GET_CAPABILITIES;
   sendCommandToService(&mTransportContext, mBuf, ackSeq++, seq++, handle,
-                       transactionID++, command);
+                       transactionID++, command, gChppLinuxLinkContext);
 
   size_t responseLoc = sizeof(ChppTestResponse);
 
@@ -921,14 +676,16 @@ TEST_F(TransportTests, GnssOpen) {
   uint8_t transactionID = 0;
   size_t len = 0;
 
+  EXPECT_EQ(findServiceHandle(&mAppContext, "GNSS", &handle), true);
+
   openService(&mTransportContext, mBuf, ackSeq++, seq++, handle,
-              transactionID++, CHPP_GNSS_OPEN);
+              transactionID++, CHPP_GNSS_OPEN, gChppLinuxLinkContext);
 
   addPreambleToBuf(mBuf, &len);
 
   uint16_t command = CHPP_GNSS_GET_CAPABILITIES;
   sendCommandToService(&mTransportContext, mBuf, ackSeq++, seq++, handle,
-                       transactionID++, command);
+                       transactionID++, command, gChppLinuxLinkContext);
 
   size_t responseLoc = sizeof(ChppTestResponse);
 
@@ -1096,7 +853,8 @@ void messageToInvalidHandle(ChppTransportState *transportContext,
 
   ChppAppHeader *appHeader = addAppHeaderToBuf(buf, &len);
   appHeader->handle =
-      CHPP_HANDLE_NEGOTIATED_RANGE_START + CHPP_MAX_REGISTERED_CLIENTS;
+      CHPP_HANDLE_NEGOTIATED_RANGE_START +
+      MAX(CHPP_MAX_REGISTERED_CLIENTS, CHPP_MAX_REGISTERED_SERVICES);
   appHeader->type = type;
   len = sizeof(struct ChppAppHeader);
 
@@ -1137,4 +895,5 @@ TEST_F(TransportTests, WorkMonitorInvoked) {
 
 INSTANTIATE_TEST_SUITE_P(TransportTestRange, TransportTests,
                          testing::ValuesIn(kChunkSizes));
-}  // namespace
+
+}  // namespace chpp::test
diff --git a/chpp/test/transport_test.h b/chpp/test/transport_test.h
index f9b502a8..ec7437ab 100644
--- a/chpp/test/transport_test.h
+++ b/chpp/test/transport_test.h
@@ -17,27 +17,12 @@
 #ifndef CHPP_TRANSPORT_TEST_H_
 #define CHPP_TRANSPORT_TEST_H_
 
-#include <stdbool.h>
-#include <stddef.h>
-#include <stdint.h>
-
-#include "chpp/app.h"
-#include "chpp/macros.h"
-#include "chpp/transport.h"
+#include "transport_util.h"
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
-CHPP_PACKED_START
-struct ChppTestResponse {
-  char preamble0;
-  char preamble1;
-  struct ChppTransportHeader transportHeader;
-  struct ChppAppHeader appHeader;
-} CHPP_PACKED_ATTR;
-CHPP_PACKED_END
-
 /************************************************
  *  Functions necessary for unit testing
  ***********************************************/
diff --git a/chpp/test/transport_util.cpp b/chpp/test/transport_util.cpp
new file mode 100644
index 00000000..ffa033a0
--- /dev/null
+++ b/chpp/test/transport_util.cpp
@@ -0,0 +1,319 @@
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
+#include "transport_util.h"
+
+#include <gtest/gtest.h>
+
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <string.h>
+#include <chrono>
+#include <thread>
+
+#include "chpp/app.h"
+#include "chpp/common/discovery.h"
+#include "chpp/common/gnss.h"
+#include "chpp/common/gnss_types.h"
+#include "chpp/common/standard_uuids.h"
+#include "chpp/common/wifi.h"
+#include "chpp/common/wifi_types.h"
+#include "chpp/common/wwan.h"
+#include "chpp/crc.h"
+#include "chpp/macros.h"
+#include "chpp/memory.h"
+#include "chpp/platform/platform_link.h"
+#include "chpp/platform/utils.h"
+#include "chpp/services/discovery.h"
+#include "chpp/services/loopback.h"
+#include "chpp/transport.h"
+#include "chre/pal/wwan.h"
+
+namespace chpp::test {
+
+/**
+ * Wait for chppTransportDoWork() to finish after it is notified by
+ * chppEnqueueTxPacket to run.
+ */
+void WaitForTransport(struct ChppTransportState *transportContext) {
+  // Start sending data out.
+  cycleSendThread();
+  // Wait for data to be received and processed.
+  std::this_thread::sleep_for(std::chrono::milliseconds(50));
+
+  // Should have reset loc and length for next packet / datagram
+  EXPECT_EQ(transportContext->rxStatus.locInDatagram, 0);
+  EXPECT_EQ(transportContext->rxDatagram.length, 0);
+}
+
+/**
+ * Validates a ChppTestResponse. Since the error field within the
+ * ChppAppHeader struct is optional (and not used for common services), this
+ * function returns the error field to be checked if desired, depending on the
+ * service.
+ *
+ * @param buf Buffer containing response.
+ * @param ackSeq Ack sequence to be verified.
+ * @param handle Handle number to be verified
+ * @param transactionID Transaction ID to be verified.
+ *
+ * @return The error field within the ChppAppHeader struct that is used by some
+ * but not all services.
+ */
+uint8_t validateChppTestResponse(void *buf, uint8_t ackSeq, uint8_t handle,
+                                 uint8_t transactionID) {
+  struct ChppTestResponse *response = (ChppTestResponse *)buf;
+
+  // Check preamble
+  EXPECT_EQ(response->preamble0, kChppPreamble0);
+  EXPECT_EQ(response->preamble1, kChppPreamble1);
+
+  // Check response transport headers
+  EXPECT_EQ(response->transportHeader.packetCode, CHPP_TRANSPORT_ERROR_NONE);
+  EXPECT_EQ(response->transportHeader.ackSeq, ackSeq);
+
+  // Check response app headers
+  EXPECT_EQ(response->appHeader.handle, handle);
+  EXPECT_EQ(response->appHeader.type, CHPP_MESSAGE_TYPE_SERVICE_RESPONSE);
+  EXPECT_EQ(response->appHeader.transaction, transactionID);
+
+  // Return optional response error to be checked if desired
+  return response->appHeader.error;
+}
+
+/**
+ * Aborts a packet and validates state.
+ *
+ * @param transportcontext Maintains status for each transport layer instance.
+ */
+void endAndValidatePacket(struct ChppTransportState *transportContext) {
+  chppRxPacketCompleteCb(transportContext);
+  EXPECT_EQ(transportContext->rxStatus.state, CHPP_STATE_PREAMBLE);
+  EXPECT_EQ(transportContext->rxStatus.locInDatagram, 0);
+  EXPECT_EQ(transportContext->rxDatagram.length, 0);
+}
+
+/**
+ * Adds a preamble to a certain location in a buffer, and increases the location
+ * accordingly, to account for the length of the added preamble.
+ *
+ * @param buf Buffer.
+ * @param location Location to add the preamble, which its value will be
+ * increased accordingly.
+ */
+void addPreambleToBuf(uint8_t *buf, size_t *location) {
+  buf[(*location)++] = kChppPreamble0;
+  buf[(*location)++] = kChppPreamble1;
+}
+
+/**
+ * Adds a transport header (with default values) to a certain location in a
+ * buffer, and increases the location accordingly, to account for the length of
+ * the added transport header.
+ *
+ * @param buf Buffer.
+ * @param location Location to add the transport header, which its value will be
+ * increased accordingly.
+ *
+ * @return Pointer to the added transport header (e.g. to modify its fields).
+ */
+ChppTransportHeader *addTransportHeaderToBuf(uint8_t *buf, size_t *location) {
+  size_t oldLoc = *location;
+
+  // Default values for initial, minimum size request packet
+  ChppTransportHeader transHeader = {};
+  transHeader.flags = CHPP_TRANSPORT_FLAG_FINISHED_DATAGRAM;
+  transHeader.packetCode = CHPP_TRANSPORT_ERROR_NONE;
+  transHeader.ackSeq = 1;
+  transHeader.seq = 0;
+  transHeader.length = sizeof(ChppAppHeader);
+  transHeader.reserved = 0;
+
+  memcpy(&buf[*location], &transHeader, sizeof(transHeader));
+  *location += sizeof(transHeader);
+
+  return (ChppTransportHeader *)&buf[oldLoc];
+}
+
+/**
+ * Adds an app header (with default values) to a certain location in a buffer,
+ * and increases the location accordingly, to account for the length of the
+ * added app header.
+ *
+ * @param buf Buffer.
+ * @param location Location to add the app header, which its value will be
+ * increased accordingly.
+ *
+ * @return Pointer to the added app header (e.g. to modify its fields).
+ */
+ChppAppHeader *addAppHeaderToBuf(uint8_t *buf, size_t *location) {
+  size_t oldLoc = *location;
+
+  // Default values - to be updated later as necessary
+  ChppAppHeader appHeader = {};
+  appHeader.handle = CHPP_HANDLE_NEGOTIATED_RANGE_START;
+  appHeader.type = CHPP_MESSAGE_TYPE_CLIENT_REQUEST;
+  appHeader.transaction = 0;
+  appHeader.error = CHPP_APP_ERROR_NONE;
+  appHeader.command = 0;
+
+  memcpy(&buf[*location], &appHeader, sizeof(appHeader));
+  *location += sizeof(appHeader);
+
+  return (ChppAppHeader *)&buf[oldLoc];
+}
+
+/**
+ * Adds a transport footer to a certain location in a buffer, and increases the
+ * location accordingly, to account for the length of the added preamble.
+ *
+ * @param buf Buffer.
+ * @param location Location to add the footer. The value of location will be
+ * increased accordingly.
+ *
+ */
+void addTransportFooterToBuf(uint8_t *buf, size_t *location) {
+  uint32_t *checksum = (uint32_t *)&buf[*location];
+
+  *checksum = chppCrc32(0, &buf[CHPP_PREAMBLE_LEN_BYTES],
+                        *location - CHPP_PREAMBLE_LEN_BYTES);
+
+  *location += sizeof(ChppTransportFooter);
+}
+
+/**
+ * Opens a service and checks to make sure it was opened correctly.
+ *
+ * @param transportContext Transport layer context.
+ * @param buf Buffer.
+ * @param ackSeq Ack sequence of the packet to be sent out
+ * @param seq Sequence number of the packet to be sent out.
+ * @param handle Handle of the service to be opened.
+ * @param transactionID Transaction ID for the open request.
+ * @param command Open command.
+ */
+void openService(ChppTransportState *transportContext, uint8_t *buf,
+                 uint8_t ackSeq, uint8_t seq, uint8_t handle,
+                 uint8_t transactionID, uint16_t command,
+                 struct ChppLinuxLinkState &chppLinuxLinkContext) {
+  size_t len = 0;
+
+  addPreambleToBuf(buf, &len);
+
+  ChppTransportHeader *transHeader = addTransportHeaderToBuf(buf, &len);
+  transHeader->ackSeq = ackSeq;
+  transHeader->seq = seq;
+
+  ChppAppHeader *appHeader = addAppHeaderToBuf(buf, &len);
+  appHeader->handle = handle;
+  appHeader->transaction = transactionID;
+  appHeader->command = command;
+
+  addTransportFooterToBuf(buf, &len);
+
+  // Send header + payload (if any) + footer
+  EXPECT_TRUE(chppRxDataCb(transportContext, buf, len));
+
+  // Check for correct state
+  uint8_t nextSeq = transHeader->seq + 1;
+  EXPECT_EQ(transportContext->rxStatus.expectedSeq, nextSeq);
+  EXPECT_EQ(transportContext->rxStatus.state, CHPP_STATE_PREAMBLE);
+
+  // Wait for response
+  WaitForTransport(transportContext);
+
+  // Validate common response fields
+  EXPECT_EQ(validateChppTestResponse(chppLinuxLinkContext.buf, nextSeq, handle,
+                                     transactionID),
+            CHPP_APP_ERROR_NONE);
+
+  // Check response length
+  EXPECT_EQ(sizeof(ChppTestResponse), CHPP_PREAMBLE_LEN_BYTES +
+                                          sizeof(ChppTransportHeader) +
+                                          sizeof(ChppAppHeader));
+  EXPECT_EQ(transportContext->linkBufferSize,
+            sizeof(ChppTestResponse) + sizeof(ChppTransportFooter));
+}
+
+/**
+ * Sends a command to a service and checks for errors.
+ *
+ * @param transportContext Transport layer context.
+ * @param buf Buffer.
+ * @param ackSeq Ack sequence of the packet to be sent out
+ * @param seq Sequence number of the packet to be sent out.
+ * @param handle Handle of the service to be opened.
+ * @param transactionID Transaction ID for the open request.
+ * @param command Command to be sent.
+ */
+void sendCommandToService(ChppTransportState *transportContext, uint8_t *buf,
+                          uint8_t ackSeq, uint8_t seq, uint8_t handle,
+                          uint8_t transactionID, uint16_t command,
+                          struct ChppLinuxLinkState &chppLinuxLinkContext) {
+  size_t len = 0;
+
+  addPreambleToBuf(buf, &len);
+
+  ChppTransportHeader *transHeader = addTransportHeaderToBuf(buf, &len);
+  transHeader->ackSeq = ackSeq;
+  transHeader->seq = seq;
+
+  ChppAppHeader *appHeader = addAppHeaderToBuf(buf, &len);
+  appHeader->handle = handle;
+  appHeader->transaction = transactionID;
+  appHeader->command = command;
+
+  addTransportFooterToBuf(buf, &len);
+
+  // Send header + payload (if any) + footer
+  EXPECT_TRUE(chppRxDataCb(transportContext, buf, len));
+
+  // Check for correct state
+  uint8_t nextSeq = transHeader->seq + 1;
+  EXPECT_EQ(transportContext->rxStatus.expectedSeq, nextSeq);
+  EXPECT_EQ(transportContext->rxStatus.state, CHPP_STATE_PREAMBLE);
+
+  // Wait for response
+  WaitForTransport(transportContext);
+
+  // Validate common response fields
+  EXPECT_EQ(validateChppTestResponse(chppLinuxLinkContext.buf, nextSeq, handle,
+                                     transactionID),
+            CHPP_APP_ERROR_NONE);
+}
+
+/**
+ * Find service handle by name.
+ *
+ * @param appContext App context.
+ * @param name Service name.
+ * @param handle Output service handle if found.
+ *
+ * @return True if service found, false otherwise.
+ */
+bool findServiceHandle(ChppAppState *appContext, const char *name,
+                       uint8_t *handle) {
+  for (uint8_t i = 0; i < appContext->registeredServiceCount; i++) {
+    if (0 == strcmp(appContext->registeredServices[i]->descriptor.name, name)) {
+      *handle = appContext->registeredServiceStates[i]->handle;
+      return true;
+    }
+  }
+  return false;
+}
+
+}  // namespace chpp::test
diff --git a/chpp/test/transport_util.h b/chpp/test/transport_util.h
new file mode 100644
index 00000000..17ebd069
--- /dev/null
+++ b/chpp/test/transport_util.h
@@ -0,0 +1,183 @@
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
+#ifndef CHPP_TRANSPORT_UTIL_H_
+#define CHPP_TRANSPORT_UTIL_H_
+
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+
+#include "chpp/app.h"
+#include "chpp/macros.h"
+#include "chpp/platform/platform_link.h"
+#include "chpp/transport.h"
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+CHPP_PACKED_START
+struct ChppTestResponse {
+  char preamble0;
+  char preamble1;
+  struct ChppTransportHeader transportHeader;
+  struct ChppAppHeader appHeader;
+} CHPP_PACKED_ATTR;
+CHPP_PACKED_END
+
+#ifdef __cplusplus
+}
+#endif
+
+namespace chpp::test {
+
+namespace {
+
+// Preamble as separate bytes for testing
+constexpr uint8_t kChppPreamble0 = 0x68;
+constexpr uint8_t kChppPreamble1 = 0x43;
+
+}  // namespace
+
+/************************************************
+ *  Helper functions available for other tests
+ ***********************************************/
+
+/**
+ * Wait for chppTransportDoWork() to finish after it is notified by
+ * chppEnqueueTxPacket to run.
+ */
+void WaitForTransport(struct ChppTransportState *transportContext);
+
+/**
+ * Validates a ChppTestResponse. Since the error field within the
+ * ChppAppHeader struct is optional (and not used for common services), this
+ * function returns the error field to be checked if desired, depending on the
+ * service.
+ *
+ * @param buf Buffer containing response.
+ * @param ackSeq Ack sequence to be verified.
+ * @param handle Handle number to be verified
+ * @param transactionID Transaction ID to be verified.
+ *
+ * @return The error field within the ChppAppHeader struct that is used by some
+ * but not all services.
+ */
+uint8_t validateChppTestResponse(void *buf, uint8_t ackSeq, uint8_t handle,
+                                 uint8_t transactionID);
+
+/**
+ * Aborts a packet and validates state.
+ *
+ * @param transportcontext Maintains status for each transport layer instance.
+ */
+void endAndValidatePacket(struct ChppTransportState *transportContext);
+
+/**
+ * Adds a preamble to a certain location in a buffer, and increases the location
+ * accordingly, to account for the length of the added preamble.
+ *
+ * @param buf Buffer.
+ * @param location Location to add the preamble, which its value will be
+ * increased accordingly.
+ */
+void addPreambleToBuf(uint8_t *buf, size_t *location);
+
+/**
+ * Adds a transport header (with default values) to a certain location in a
+ * buffer, and increases the location accordingly, to account for the length of
+ * the added transport header.
+ *
+ * @param buf Buffer.
+ * @param location Location to add the transport header, which its value will be
+ * increased accordingly.
+ *
+ * @return Pointer to the added transport header (e.g. to modify its fields).
+ */
+ChppTransportHeader *addTransportHeaderToBuf(uint8_t *buf, size_t *location);
+
+/**
+ * Adds an app header (with default values) to a certain location in a buffer,
+ * and increases the location accordingly, to account for the length of the
+ * added app header.
+ *
+ * @param buf Buffer.
+ * @param location Location to add the app header, which its value will be
+ * increased accordingly.
+ *
+ * @return Pointer to the added app header (e.g. to modify its fields).
+ */
+ChppAppHeader *addAppHeaderToBuf(uint8_t *buf, size_t *location);
+
+/**
+ * Adds a transport footer to a certain location in a buffer, and increases the
+ * location accordingly, to account for the length of the added preamble.
+ *
+ * @param buf Buffer.
+ * @param location Location to add the footer. The value of location will be
+ * increased accordingly.
+ *
+ */
+void addTransportFooterToBuf(uint8_t *buf, size_t *location);
+
+/**
+ * Opens a service and checks to make sure it was opened correctly.
+ *
+ * @param transportContext Transport layer context.
+ * @param buf Buffer.
+ * @param ackSeq Ack sequence of the packet to be sent out
+ * @param seq Sequence number of the packet to be sent out.
+ * @param handle Handle of the service to be opened.
+ * @param transactionID Transaction ID for the open request.
+ * @param command Open command.
+ */
+void openService(ChppTransportState *transportContext, uint8_t *buf,
+                 uint8_t ackSeq, uint8_t seq, uint8_t handle,
+                 uint8_t transactionID, uint16_t command,
+                 struct ChppLinuxLinkState &chppLinuxLinkContext);
+
+/**
+ * Sends a command to a service and checks for errors.
+ *
+ * @param transportContext Transport layer context.
+ * @param buf Buffer.
+ * @param ackSeq Ack sequence of the packet to be sent out
+ * @param seq Sequence number of the packet to be sent out.
+ * @param handle Handle of the service to be opened.
+ * @param transactionID Transaction ID for the open request.
+ * @param command Command to be sent.
+ */
+void sendCommandToService(ChppTransportState *transportContext, uint8_t *buf,
+                          uint8_t ackSeq, uint8_t seq, uint8_t handle,
+                          uint8_t transactionID, uint16_t command,
+                          struct ChppLinuxLinkState &chppLinuxLinkContext);
+
+/**
+ * Find service handle by name.
+ *
+ * @param appContext App context.
+ * @param name Service name.
+ * @param handle Output service handle if found.
+ *
+ * @return True if service found, false otherwise.
+ */
+bool findServiceHandle(ChppAppState *appContext, const char *name,
+                       uint8_t *handle);
+
+}  // namespace chpp::test
+
+#endif  // CHPP_TRANSPORT_UTIL_H_
diff --git a/chre_api/include/chre_api/chre/event.h b/chre_api/include/chre_api/chre/event.h
index 573c94be..d08b7d0b 100644
--- a/chre_api/include/chre_api/chre/event.h
+++ b/chre_api/include/chre_api/chre/event.h
@@ -822,9 +822,11 @@ bool chreSendMessageWithPermissions(void *message, size_t messageSize,
  *   then an async status is delivered to the nanoapp when the transmission
  *   completes either successfully or in error via the
  *   CHRE_EVENT_RELIABLE_MSG_ASYNC_RESULT event.
+ * - For any reliable messages pending completion at nanoapp unload:
+ *   - At least one delivery attempt will be made.
+ *   - The free callback will be invoked.
+ *   - The async result event will not be delivered.
  * - The error codes received are:
- *   - CHRE_ERROR_NANOAPP_STOPPING if the nanoapp was stopping during the
- *                                 request.
  *   - CHRE_ERROR_DESTINATION_NOT_FOUND if the destination was not found.
  *   - CHRE_ERROR if there was a permanent error.
  *   - CHRE_ERROR_TIMEOUT if there was no response from the recipient
diff --git a/chre_flags.aconfig b/chre_flags.aconfig
index 78fe2310..1fbb459b 100644
--- a/chre_flags.aconfig
+++ b/chre_flags.aconfig
@@ -2,103 +2,119 @@ package: "android.chre.flags"
 container: "system"
 
 flag {
-  name: "flag_log_nanoapp_load_metrics"
+  name: "context_hub_callback_uuid_enabled"
   namespace: "context_hub"
-  description: "This flag controls nanoapp load failure logging in the HAL and the addition of MetricsReporter"
-  bug: "298459533"
+  description: "Call IContextHubCallback.getUuid() to retrieve the UUID when this flag is on"
+  bug: "247124878"
 }
 
 flag {
-  name: "metrics_reporter_in_the_daemon"
+  name: "abort_if_no_context_hub_found"
   namespace: "context_hub"
-  description: "This flag controls the addition of MetricsReporter into the CHRE daemon"
-  bug: "298459533"
+  description: "Abort the HAL process if no context hub info found. For debug purpose only."
+  bug: "344642685"
 }
 
 flag {
-  name: "wait_for_preloaded_nanoapp_start"
+  name: "reconnect_host_endpoints_after_hal_restart"
   namespace: "context_hub"
-  description: "This flag controls the waiting-for-nanoapp-start behavior in the CHRE daemon"
-  bug: "298459533"
+  description: "Reconnect host endpoints of ContextHubService after Context Hub HAL restarts."
+  bug: "348253728"
 }
 
 flag {
-  name: "remove_ap_wakeup_metric_report_limit"
+  name: "reliable_message"
+  is_exported: true
   namespace: "context_hub"
-  description: "This flag controls removing a count limit on reporting the AP wakeup metric"
-  bug: "298459533"
+  description: "Enable the reliable message APIs"
+  bug: "314081414"
 }
 
 flag {
-  name: "context_hub_callback_uuid_enabled"
+  name: "reliable_message_implementation"
   namespace: "context_hub"
-  description: "Call IContextHubCallback.getUuid() to retrieve the UUID when this flag is on"
-  bug: "247124878"
+  description: "Enable support for reliable messages in CHRE"
+  bug: "314081414"
 }
 
 flag {
-  name: "abort_if_no_context_hub_found"
+  name: "reliable_message_duplicate_detection_service"
   namespace: "context_hub"
-  description: "Abort the HAL process if no context hub info found. For debug purpose only."
-  bug: "344642685"
+  description: "Enable duplicate detection for reliable messages in the Context Hub Service"
+  bug: "331795143"
 }
 
 flag {
-  name: "reduce_lock_holding_period"
+  name: "reliable_message_retry_support_service"
   namespace: "context_hub"
-  description: "A flag guarding the change of reducing lock holding period to avoid deadlock."
-  bug: "347392749"
+  description: "Enable retries for reliable messages in the Context Hub Service"
+  bug: "331795143"
 }
 
 flag {
-  name: "reconnect_host_endpoints_after_hal_restart"
+  name: "reliable_message_test_mode_behavior"
   namespace: "context_hub"
-  description: "Reconnect host endpoints of ContextHubService after Context Hub HAL restarts."
-  bug: "348253728"
+  description: "Enables test mode behaviors in the Context Hub Service for reliable messages"
+  bug: "333567339"
 }
 
 flag {
-  name: "bug_fix_reduce_lock_holding_period"
+  name: "bug_fix_hal_reliable_message_record"
   namespace: "context_hub"
-  description: "A flag guarding the fix of reducing lock holding period to avoid deadlock."
-  bug: "347392749"
+  description: "A flag guarding the fix of how the Context Hub HAL stores the reliable message records."
+  bug: "333567700"
   metadata {
     purpose: PURPOSE_BUGFIX
   }
 }
 
 flag {
-  name: "reliable_message"
-  is_exported: true
+  name: "fix_api_check"
   namespace: "context_hub"
-  description: "Enable the reliable message APIs"
-  bug: "314081414"
+  description: "Fixes API check errors in Context Hub classes"
+  bug: "340880058"
 }
 
 flag {
-  name: "reliable_message_implementation"
+  name: "refactor_hal_xport_agnostic"
   namespace: "context_hub"
-  description: "Enable support for reliable messages in CHRE"
-  bug: "314081414"
+  description: "Flag guarding refactor of ContextHub HAL to be transport agnostic"
+  bug: "360926711"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
 }
 
 flag {
-  name: "reliable_message_duplicate_detection_service"
+  name: "remove_old_context_hub_apis"
   namespace: "context_hub"
-  description: "Enable duplicate detection for reliable messages in the Context Hub Service"
-  bug: "331795143"
+  description: "Removes the implementation of the deprecated old ContextHub APIs"
+  bug: "359925548"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
 }
 
 flag {
-  name: "reliable_message_retry_support_service"
+  name: "unified_metrics_reporting_api"
   namespace: "context_hub"
-  description: "Enable retries for reliable messages in the Context Hub Service"
-  bug: "331795143"
+  description: "The API for unified metrics reporting in the Context Hub Service"
+  bug: "361804033"
 }
 
 flag {
-  name: "reliable_message_test_mode_behavior"
+  name: "unified_metrics_reporting_implementation"
   namespace: "context_hub"
-  description: "Enables test mode behaviors in the Context Hub Service for reliable messages"
-  bug: "333567339"
+  description: "The implementation for unified metrics reporting in the Context Hub Service"
+  bug: "361804033"
+}
+
+flag {
+  name: "reduce_locking_context_hub_transaction_manager"
+  namespace: "context_hub"
+  description: "Reduces locking in the ContextHubTransactionManager"
+  bug: "362299144"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
 }
diff --git a/core/ble_request_manager.cc b/core/ble_request_manager.cc
index 81cb18c7..ed93e3e6 100644
--- a/core/ble_request_manager.cc
+++ b/core/ble_request_manager.cc
@@ -121,7 +121,6 @@ uint32_t BleRequestManager::disableActiveScan(const Nanoapp *nanoapp) {
   return 1;
 }
 
-#ifdef CHRE_BLE_READ_RSSI_SUPPORT_ENABLED
 bool BleRequestManager::readRssiAsync(Nanoapp *nanoapp,
                                       uint16_t connectionHandle,
                                       const void *cookie) {
@@ -143,7 +142,6 @@ bool BleRequestManager::readRssiAsync(Nanoapp *nanoapp,
       BleReadRssiRequest{nanoapp->getInstanceId(), connectionHandle, cookie});
   return true;
 }
-#endif
 
 bool BleRequestManager::flushAsync(Nanoapp *nanoapp, const void *cookie) {
   CHRE_ASSERT(nanoapp);
@@ -404,7 +402,6 @@ void BleRequestManager::handleRequestStateResyncCallbackSync() {
   }
 }
 
-#ifdef CHRE_BLE_READ_RSSI_SUPPORT_ENABLED
 void BleRequestManager::handleReadRssi(uint8_t errorCode,
                                        uint16_t connectionHandle, int8_t rssi) {
   struct readRssiResponse {
@@ -490,7 +487,6 @@ uint8_t BleRequestManager::readRssi(uint16_t connectionHandle) {
     return CHRE_ERROR;
   }
 }
-#endif
 
 void BleRequestManager::handleFlushComplete(uint8_t errorCode) {
   if (mFlushRequestTimerHandle != CHRE_TIMER_INVALID) {
diff --git a/core/event_loop.cc b/core/event_loop.cc
index cfbcd81e..7c304c94 100644
--- a/core/event_loop.cc
+++ b/core/event_loop.cc
@@ -17,6 +17,7 @@
 #include "chre/core/event_loop.h"
 #include <cinttypes>
 #include <cstdint>
+#include <type_traits>
 
 #include "chre/core/event.h"
 #include "chre/core/event_loop_manager.h"
@@ -30,6 +31,7 @@
 #include "chre/util/system/debug_dump.h"
 #include "chre/util/system/event_callbacks.h"
 #include "chre/util/system/stats_container.h"
+#include "chre/util/throttle.h"
 #include "chre/util/time.h"
 #include "chre_api/chre/version.h"
 
@@ -82,16 +84,16 @@ bool populateNanoappInfo(const Nanoapp *app, struct chreNanoappInfo *info) {
 
 #ifndef CHRE_STATIC_EVENT_LOOP
 /**
- * @return true if a event is a low priority event.
+ * @return true if a event is a low priority event and is not from nanoapp.
  * Note: data and extraData are needed here to match the
  * matching function signature. Both are not used here, but
  * are used in other applications of
  * SegmentedQueue::removeMatchedFromBack.
  */
-bool isLowPriorityEvent(Event *event, void * /* data */,
-                        void * /* extraData */) {
+bool isNonNanoappLowPriorityEvent(Event *event, void * /* data */,
+                                  void * /* extraData */) {
   CHRE_ASSERT_NOT_NULL(event);
-  return event->isLowPriority;
+  return event->isLowPriority && event->senderInstanceId == kSystemInstanceId;
 }
 
 void deallocateFromMemoryPool(Event *event, void *memoryPool) {
@@ -237,7 +239,7 @@ bool EventLoop::unloadNanoapp(uint16_t instanceId,
         // there are no messages pending delivery to the host)
         EventLoopManagerSingleton::get()
             ->getHostCommsManager()
-            .flushNanoappMessagesAndTransactions(mNanoapps[i]->getAppId());
+            .flushNanoappMessages(*mNanoapps[i]);
 
         // Mark that this nanoapp is stopping early, so it can't send events or
         // messages during the nanoapp event queue flush
@@ -246,7 +248,7 @@ bool EventLoop::unloadNanoapp(uint16_t instanceId,
         if (nanoappStarted) {
           // Distribute all inbound events we have at this time - here we're
           // interested in handling any message free callbacks generated by
-          // flushInboundEventQueue()
+          // flushNanoappMessages()
           flushInboundEventQueue();
 
           // Post the unload event now (so we can reference the Nanoapp instance
@@ -272,7 +274,8 @@ bool EventLoop::unloadNanoapp(uint16_t instanceId,
   return unloaded;
 }
 
-bool EventLoop::removeLowPriorityEventsFromBack([[maybe_unused]] size_t removeNum) {
+bool EventLoop::removeNonNanoappLowPriorityEventsFromBack(
+    [[maybe_unused]] size_t removeNum) {
 #ifdef CHRE_STATIC_EVENT_LOOP
   return false;
 #else
@@ -280,10 +283,10 @@ bool EventLoop::removeLowPriorityEventsFromBack([[maybe_unused]] size_t removeNu
     return true;
   }
 
-  size_t numRemovedEvent =
-      mEvents.removeMatchedFromBack(isLowPriorityEvent, /* data= */ nullptr,
-                                    /* extraData= */ nullptr, removeNum,
-                                    deallocateFromMemoryPool, &mEventPool);
+  size_t numRemovedEvent = mEvents.removeMatchedFromBack(
+      isNonNanoappLowPriorityEvent, /* data= */ nullptr,
+      /* extraData= */ nullptr, removeNum, deallocateFromMemoryPool,
+      &mEventPool);
   if (numRemovedEvent == 0 || numRemovedEvent == SIZE_MAX) {
     LOGW("Cannot remove any low priority event");
   } else {
@@ -294,13 +297,15 @@ bool EventLoop::removeLowPriorityEventsFromBack([[maybe_unused]] size_t removeNu
 }
 
 bool EventLoop::hasNoSpaceForHighPriorityEvent() {
-  return mEventPool.full() &&
-         !removeLowPriorityEventsFromBack(targetLowPriorityEventRemove);
+  return mEventPool.full() && !removeNonNanoappLowPriorityEventsFromBack(
+                                  targetLowPriorityEventRemove);
 }
 
 bool EventLoop::deliverEventSync(uint16_t nanoappInstanceId,
                                  uint16_t eventType,
                                  void *eventData) {
+  CHRE_ASSERT(inEventLoopThread());
+
   Event event(eventType, eventData,
               /* freeCallback= */ nullptr,
               /* isLowPriority= */ false,
@@ -427,8 +432,6 @@ void EventLoop::logStateToBuffer(DebugDumpWrapper &debugDump) const {
                   mEventPoolUsage.getMax(), kMaxEventCount);
   debugDump.print("  Number of low priority events dropped: %" PRIu32 "\n",
                   mNumDroppedLowPriEvents);
-  debugDump.print("  Mean event pool usage: %" PRIu32 "/%zu\n",
-                  mEventPoolUsage.getMean(), kMaxEventCount);
 
   Nanoseconds timeSince =
       SystemTime::getMonotonicTime() - mTimeLastWakeupBucketCycled;
@@ -481,6 +484,29 @@ bool EventLoop::allocateAndPostEvent(uint16_t eventType, void *eventData,
 }
 
 void EventLoop::deliverNextEvent(const UniquePtr<Nanoapp> &app, Event *event) {
+  constexpr Seconds kLatencyThreshold = Seconds(1);
+  constexpr Seconds kThrottleInterval(1);
+  constexpr uint16_t kThrottleCount = 10;
+
+  // Handle time rollover. If Event ever changes the type used to store the
+  // received time, this will need to be updated.
+  uint32_t now = Event::getTimeMillis();
+  static_assert(
+      std::is_same<decltype(event->receivedTimeMillis), const uint16_t>::value);
+  if (now < event->receivedTimeMillis) {
+    now += UINT16_MAX + 1;
+  }
+  Milliseconds latency(now - event->receivedTimeMillis);
+
+  if (latency >= kLatencyThreshold) {
+    CHRE_THROTTLE(LOGW("Delayed event 0x%" PRIx16 " from instanceId %" PRIu16
+                       "->%" PRIu16 " took %" PRIu64 "ms to deliver",
+                       event->eventType, event->senderInstanceId,
+                       event->targetInstanceId, latency.getMilliseconds()),
+                  kThrottleInterval, kThrottleCount,
+                  SystemTime::getMonotonicTime());
+  }
+
   // TODO: cleaner way to set/clear this? RAII-style?
   mCurrentApp = app.get();
   app->processEvent(event);
diff --git a/core/gnss_manager.cc b/core/gnss_manager.cc
index 6ae57251..4fce1ef0 100644
--- a/core/gnss_manager.cc
+++ b/core/gnss_manager.cc
@@ -589,7 +589,11 @@ bool GnssSession::postAsyncResultEvent(uint16_t instanceId, bool success,
       event->reserved = 0;
       event->cookie = cookie;
 
-      mGnssErrorHistogram[errorCode]++;
+      if (errorCode < CHRE_ERROR_SIZE) {
+        mGnssErrorHistogram[errorCode]++;
+      } else {
+        LOGE("Undefined error in gnssAsyncResult: %" PRIu8, errorCode);
+      }
 
       EventLoopManagerSingleton::get()->getEventLoop().postEventOrDie(
           CHRE_EVENT_GNSS_ASYNC_RESULT, event, freeEventDataCallback,
diff --git a/core/host_comms_manager.cc b/core/host_comms_manager.cc
index 1bde7c69..b00a8c53 100644
--- a/core/host_comms_manager.cc
+++ b/core/host_comms_manager.cc
@@ -19,31 +19,29 @@
 #include <cinttypes>
 #include <cstdint>
 #include <type_traits>
+#include <utility>
 
+#include "chre/core/event_loop_common.h"
 #include "chre/core/event_loop_manager.h"
 #include "chre/platform/assert.h"
 #include "chre/platform/context.h"
 #include "chre/platform/host_link.h"
+#include "chre/platform/log.h"
+#include "chre/target_platform/log.h"
+#include "chre/util/duplicate_message_detector.h"
 #include "chre/util/macros.h"
 #include "chre/util/nested_data_ptr.h"
-#include "chre/util/system/event_callbacks.h"
+#include "chre/util/optional.h"
 #include "chre_api/chre.h"
 
 namespace chre {
 
 namespace {
 
-#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
-//! @see TransactionManager::DeferCancelCallback
-bool deferCancelCallback(uint32_t timerHandle) {
-  return EventLoopManagerSingleton::get()->cancelDelayedCallback(timerHandle);
-}
-#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
-
 /**
  * Checks if the message can be send from the nanoapp to the host.
  *
- * @see sendMessageToHostFromNanoapp for a description of the parameter.
+ * @see sendMessageToHostFromNanoapp for a description of the parameters.
  *
  * @return Whether the message can be send to the host.
  */
@@ -77,75 +75,111 @@ bool shouldAcceptMessageToHostFromNanoapp(Nanoapp *nanoapp, void *messageData,
 
 HostCommsManager::HostCommsManager()
 #ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
-    : mTransactionManager(sendMessageWithTransactionData,
-                          onMessageDeliveryStatus, deferCallback,
-                          deferCancelCallback, kReliableMessageRetryWaitTime,
-                          kReliableMessageTimeout, kReliableMessageNumRetries)
+    : mDuplicateMessageDetector(kReliableMessageDuplicateDetectorTimeout),
+      mTransactionManager(
+          *this,
+          EventLoopManagerSingleton::get()->getEventLoop().getTimerPool(),
+          kReliableMessageRetryWaitTime, kReliableMessageMaxAttempts)
 #endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
 {
 }
 
-bool HostCommsManager::completeTransaction(uint32_t transactionId,
-                                           uint8_t errorCode) {
+// TODO(b/346345637): rename this to align it with the message delivery status
+// terminology used elsewhere, and make it return void
+bool HostCommsManager::completeTransaction(
+    [[maybe_unused]] uint32_t transactionId,
+    [[maybe_unused]] uint8_t errorCode) {
 #ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
-  return mTransactionManager.completeTransaction(transactionId, errorCode);
+  auto callback = [](uint16_t /*type*/, void *data, void *extraData) {
+    uint32_t txnId = NestedDataPtr<uint32_t>(data);
+    uint8_t err = NestedDataPtr<uint8_t>(extraData);
+    EventLoopManagerSingleton::get()
+        ->getHostCommsManager()
+        .handleMessageDeliveryStatusSync(txnId, err);
+  };
+  EventLoopManagerSingleton::get()->deferCallback(
+      SystemCallbackType::ReliableMessageEvent,
+      NestedDataPtr<uint32_t>(transactionId), callback,
+      NestedDataPtr<uint8_t>(errorCode));
+  return true;
 #else
-  UNUSED_VAR(transactionId);
-  UNUSED_VAR(errorCode);
   return false;
 #endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
 }
 
-void HostCommsManager::flushNanoappMessagesAndTransactions(uint64_t appId) {
-  uint16_t nanoappInstanceId;
-  bool nanoappFound =
-      EventLoopManagerSingleton::get()
-          ->getEventLoop()
-          .findNanoappInstanceIdByAppId(appId, &nanoappInstanceId);
-  if (nanoappFound) {
-    flushNanoappTransactions(nanoappInstanceId);
-  } else {
-    LOGE("Could not find nanoapp 0x%016" PRIx64 " to flush transactions",
-         appId);
+void HostCommsManager::removeAllTransactionsFromNanoapp(
+    [[maybe_unused]] const Nanoapp &nanoapp) {
+#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+  struct FindContext {
+    decltype(mTransactionManager) &transactionManager;
+    const Nanoapp &nanoapp;
+  };
+
+  // Cancel any pending outbound reliable messages. We leverage find() here as
+  // a forEach() method by always returning false.
+  auto transactionRemover = [](HostMessage *msg, void *data) {
+    FindContext *ctx = static_cast<FindContext *>(data);
+
+    if (msg->isReliable && !msg->fromHost &&
+        msg->appId == ctx->nanoapp.getAppId() &&
+        !ctx->transactionManager.remove(msg->messageSequenceNumber)) {
+      LOGE("Couldn't find transaction %" PRIu32 " at flush",
+           msg->messageSequenceNumber);
+    }
+
+    return false;
+  };
+
+  FindContext context{mTransactionManager, nanoapp};
+  mMessagePool.find(transactionRemover, &context);
+#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+}
+
+void HostCommsManager::freeAllReliableMessagesFromNanoapp(
+    [[maybe_unused]] Nanoapp &nanoapp) {
+#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+  auto reliableMessageFromNanoappMatcher = [](HostMessage *msg, void *data) {
+    auto *napp = static_cast<const Nanoapp *>(data);
+    return (msg->isReliable && !msg->fromHost &&
+            msg->appId == napp->getAppId());
+  };
+  MessageToHost *message;
+  while ((message = mMessagePool.find(reliableMessageFromNanoappMatcher,
+                                      &nanoapp)) != nullptr) {
+    // We don't post message delivery status to the nanoapp, since it's being
+    // unloaded and we don't actually know the final message delivery status –
+    // simply free the memory
+    onMessageToHostCompleteInternal(message);
   }
+#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+}
+
+void HostCommsManager::flushNanoappMessages(Nanoapp &nanoapp) {
+  // First we remove all of the outgoing reliable message transactions from the
+  // transaction manager, which triggers sending any pending reliable messages
+  removeAllTransactionsFromNanoapp(nanoapp);
 
-  HostLink::flushMessagesSentByNanoapp(appId);
+  // This ensures that HostLink does not reference message memory (owned the
+  // nanoapp) anymore, i.e. onMessageToHostComplete() is called, which lets us
+  // free memory for any pending reliable messages
+  HostLink::flushMessagesSentByNanoapp(nanoapp.getAppId());
+  freeAllReliableMessagesFromNanoapp(nanoapp);
 }
 
+// TODO(b/346345637): rename this to better reflect its true meaning, which is
+// that HostLink doesn't reference the memory anymore
 void HostCommsManager::onMessageToHostComplete(const MessageToHost *message) {
   // We do not call onMessageToHostCompleteInternal for reliable messages
   // until the completion callback is called.
-  if (message == nullptr || message->isReliable) {
-    return;
+  if (message != nullptr && !message->isReliable) {
+    onMessageToHostCompleteInternal(message);
   }
-
-  onMessageToHostCompleteInternal(message);
 }
 
 void HostCommsManager::resetBlameForNanoappHostWakeup() {
   mIsNanoappBlamedForWakeup = false;
 }
 
-void HostCommsManager::sendDeferredMessageToNanoappFromHost(
-    MessageFromHost *craftedMessage) {
-  CHRE_ASSERT_LOG(craftedMessage != nullptr,
-                  "Deferred message from host is a NULL pointer");
-
-  if (!deliverNanoappMessageFromHost(craftedMessage)) {
-    LOGE("Dropping deferred message; destination app ID 0x%016" PRIx64
-         " still not found",
-         craftedMessage->appId);
-    if (craftedMessage->isReliable) {
-      sendMessageDeliveryStatus(craftedMessage->messageSequenceNumber,
-                                CHRE_ERROR_DESTINATION_NOT_FOUND);
-    }
-    mMessagePool.deallocate(craftedMessage);
-  } else {
-    LOGD("Deferred message to app ID 0x%016" PRIx64 " delivered",
-         craftedMessage->appId);
-  }
-}
-
 bool HostCommsManager::sendMessageToHostFromNanoapp(
     Nanoapp *nanoapp, void *messageData, size_t messageSize,
     uint32_t messageType, uint16_t hostEndpoint, uint32_t messagePermissions,
@@ -171,21 +205,14 @@ bool HostCommsManager::sendMessageToHostFromNanoapp(
   msgToHost->toHostData.appPermissions = nanoapp->getAppPermissions();
   msgToHost->toHostData.nanoappFreeFunction = freeCallback;
   msgToHost->isReliable = isReliable;
+  msgToHost->cookie = cookie;
+  msgToHost->fromHost = false;
 
-  bool success;
+  bool success = false;
   if (isReliable) {
 #ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
-    MessageTransactionData data = {
-        .messageSequenceNumberPtr = &msgToHost->messageSequenceNumber,
-        .messageSequenceNumber = static_cast<uint32_t>(-1),
-        .nanoappInstanceId = nanoapp->getInstanceId(),
-        .cookie = cookie,
-    };
-    success = mTransactionManager.startTransaction(
-        data, nanoapp->getInstanceId(), &msgToHost->messageSequenceNumber);
-#else
-    UNUSED_VAR(cookie);
-    success = false;
+    success = mTransactionManager.add(nanoapp->getInstanceId(),
+                                      &msgToHost->messageSequenceNumber);
 #endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
   } else {
     success = doSendMessageToHostFromNanoapp(nanoapp, msgToHost);
@@ -201,40 +228,38 @@ void HostCommsManager::sendMessageToNanoappFromHost(
     uint64_t appId, uint32_t messageType, uint16_t hostEndpoint,
     const void *messageData, size_t messageSize, bool isReliable,
     uint32_t messageSequenceNumber) {
-  if (hostEndpoint == kHostEndpointBroadcast) {
-    LOGE("Received invalid message from host from broadcast endpoint");
-  } else if (messageSize > ((UINT32_MAX))) {
-    // The current CHRE API uses uint32_t to represent the message size in
-    // struct chreMessageFromHostData. We don't expect to ever need to exceed
-    // this, but the check ensures we're on the up and up.
-    LOGE("Rejecting message of size %zu (too big)", messageSize);
-  } else {
-    MessageFromHost *craftedMessage = craftNanoappMessageFromHost(
-        appId, hostEndpoint, messageType, messageData,
-        static_cast<uint32_t>(messageSize), isReliable, messageSequenceNumber);
-    if (craftedMessage == nullptr) {
-      LOGE("Out of memory - rejecting message to app ID 0x%016" PRIx64
-           "(size %zu)",
-           appId, messageSize);
-      if (isReliable) {
-        sendMessageDeliveryStatus(messageSequenceNumber, CHRE_ERROR_NO_MEMORY);
-      }
-    } else if (!deliverNanoappMessageFromHost(craftedMessage)) {
-      LOGV("Deferring message; destination app ID 0x%016" PRIx64
-           " not found at this time",
-           appId);
-
-      auto callback = [](uint16_t /*type*/, void *data, void * /*extraData*/) {
-        EventLoopManagerSingleton::get()
-            ->getHostCommsManager()
-            .sendDeferredMessageToNanoappFromHost(
-                static_cast<MessageFromHost *>(data));
-      };
-      if (!EventLoopManagerSingleton::get()->deferCallback(
-              SystemCallbackType::DeferredMessageToNanoappFromHost,
-              craftedMessage, callback)) {
-        mMessagePool.deallocate(craftedMessage);
-      }
+  std::pair<chreError, MessageFromHost *> output =
+      validateAndCraftMessageFromHostToNanoapp(
+          appId, messageType, hostEndpoint, messageData, messageSize,
+          isReliable, messageSequenceNumber);
+  chreError error = output.first;
+  MessageFromHost *craftedMessage = output.second;
+
+  if (error == CHRE_ERROR_NONE) {
+    auto callback = [](uint16_t /*type*/, void *data, void* /* extraData */) {
+      MessageFromHost *craftedMessage = static_cast<MessageFromHost *>(data);
+      EventLoopManagerSingleton::get()
+          ->getHostCommsManager()
+          .deliverNanoappMessageFromHost(craftedMessage);
+    };
+
+    if (!EventLoopManagerSingleton::get()->deferCallback(
+            SystemCallbackType::DeferredMessageToNanoappFromHost,
+            craftedMessage, callback)) {
+      LOGE("Failed to defer callback to send message to nanoapp from host");
+      error = CHRE_ERROR_BUSY;
+    }
+  }
+
+  if (error != CHRE_ERROR_NONE) {
+#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+    if (isReliable) {
+      sendMessageDeliveryStatus(messageSequenceNumber, error);
+    }
+#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+
+    if (craftedMessage != nullptr) {
+      mMessagePool.deallocate(craftedMessage);
     }
   }
 }
@@ -249,8 +274,8 @@ MessageFromHost *HostCommsManager::craftNanoappMessageFromHost(
   } else if (!msgFromHost->message.copy_array(
                  static_cast<const uint8_t *>(messageData), messageSize)) {
     LOGE("Couldn't allocate %" PRIu32
-         " bytes for message data from host "
-         "(endpoint 0x%" PRIx16 " type %" PRIu32 ")",
+         " bytes for message data from host (endpoint 0x%" PRIx16
+         " type %" PRIu32 ")",
          messageSize, hostEndpoint, messageType);
     mMessagePool.deallocate(msgFromHost);
     msgFromHost = nullptr;
@@ -262,49 +287,87 @@ MessageFromHost *HostCommsManager::craftNanoappMessageFromHost(
     msgFromHost->fromHostData.hostEndpoint = hostEndpoint;
     msgFromHost->isReliable = isReliable;
     msgFromHost->messageSequenceNumber = messageSequenceNumber;
+    msgFromHost->fromHost = true;
   }
 
   return msgFromHost;
 }
 
-bool HostCommsManager::deferCallback(
-    TransactionManager<MessageTransactionData,
-                       kMaxOutstandingMessages>::DeferCallbackFunction func,
-    void *data, void *extraData, Nanoseconds delay, uint32_t *outTimerHandle) {
-  if (delay.toRawNanoseconds() == 0) {
-    CHRE_ASSERT(outTimerHandle == nullptr);
-    return EventLoopManagerSingleton::get()->deferCallback(
-        SystemCallbackType::ReliableMessageEvent, data, func, extraData);
-  }
+/**
+ * Checks if the message can be send to the nanoapp from the host. Crafts
+ * the message to the nanoapp.
+ *
+ * @see sendMessageToNanoappFromHost for a description of the parameters.
+ *
+ * @return the error code and the crafted message
+ */
+std::pair<chreError, MessageFromHost *>
+HostCommsManager::validateAndCraftMessageFromHostToNanoapp(
+    uint64_t appId, uint32_t messageType, uint16_t hostEndpoint,
+    const void *messageData, size_t messageSize, bool isReliable,
+    uint32_t messageSequenceNumber) {
+  chreError error = CHRE_ERROR_NONE;
+  MessageFromHost *craftedMessage = nullptr;
 
-  CHRE_ASSERT(outTimerHandle != nullptr);
-  *outTimerHandle = EventLoopManagerSingleton::get()->setDelayedCallback(
-      SystemCallbackType::ReliableMessageEvent, data, func, delay);
-  return true;
+  if (hostEndpoint == kHostEndpointBroadcast) {
+    LOGE("Received invalid message from host from broadcast endpoint");
+    error = CHRE_ERROR_INVALID_ARGUMENT;
+  } else if (messageSize > UINT32_MAX) {
+    // The current CHRE API uses uint32_t to represent the message size in
+    // struct chreMessageFromHostData. We don't expect to ever need to exceed
+    // this, but the check ensures we're on the up and up.
+    LOGE("Rejecting message of size %zu (too big)", messageSize);
+    error = CHRE_ERROR_INVALID_ARGUMENT;
+  } else {
+    craftedMessage = craftNanoappMessageFromHost(
+        appId, hostEndpoint, messageType, messageData,
+        static_cast<uint32_t>(messageSize), isReliable,
+        messageSequenceNumber);
+    if (craftedMessage == nullptr) {
+      LOGE("Out of memory - rejecting message to app ID 0x%016" PRIx64
+            "(size %zu)",
+            appId, messageSize);
+      error = CHRE_ERROR_NO_MEMORY;
+    }
+  }
+  return std::make_pair(error, craftedMessage);
 }
 
-bool HostCommsManager::deliverNanoappMessageFromHost(
+void HostCommsManager::deliverNanoappMessageFromHost(
     MessageFromHost *craftedMessage) {
-  const EventLoop &eventLoop = EventLoopManagerSingleton::get()->getEventLoop();
-  uint16_t targetInstanceId;
-  bool nanoappFound = false;
-
   CHRE_ASSERT_LOG(craftedMessage != nullptr,
                   "Cannot deliver NULL pointer nanoapp message from host");
 
-  if (eventLoop.findNanoappInstanceIdByAppId(craftedMessage->appId,
-                                             &targetInstanceId)) {
-    nanoappFound = true;
-    EventLoopManagerSingleton::get()->getEventLoop().postEventOrDie(
-        CHRE_EVENT_MESSAGE_FROM_HOST, &craftedMessage->fromHostData,
-        freeMessageFromHostCallback, targetInstanceId);
-    if (craftedMessage->isReliable) {
-      sendMessageDeliveryStatus(craftedMessage->messageSequenceNumber,
-                                CHRE_ERROR_NONE);
-    }
+  Optional<chreError> error;
+  uint16_t targetInstanceId;
+
+  bool foundNanoapp = EventLoopManagerSingleton::get()
+                          ->getEventLoop()
+                          .findNanoappInstanceIdByAppId(craftedMessage->appId,
+                                                        &targetInstanceId);
+  bool shouldDeliverMessage = !craftedMessage->isReliable ||
+                                shouldSendReliableMessageToNanoapp(
+                                    craftedMessage->messageSequenceNumber,
+                                    craftedMessage->fromHostData.hostEndpoint);
+  if (!foundNanoapp) {
+    error = CHRE_ERROR_DESTINATION_NOT_FOUND;
+  } else if (shouldDeliverMessage) {
+    EventLoopManagerSingleton::get()->getEventLoop().deliverEventSync(
+        targetInstanceId, CHRE_EVENT_MESSAGE_FROM_HOST,
+        &craftedMessage->fromHostData);
+    error = CHRE_ERROR_NONE;
   }
 
-  return nanoappFound;
+  if (craftedMessage->isReliable && error.has_value()) {
+    handleDuplicateAndSendMessageDeliveryStatus(
+        craftedMessage->messageSequenceNumber,
+        craftedMessage->fromHostData.hostEndpoint, error.value());
+  }
+  mMessagePool.deallocate(craftedMessage);
+
+#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+  mDuplicateMessageDetector.removeOldEntries();
+#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
 }
 
 bool HostCommsManager::doSendMessageToHostFromNanoapp(
@@ -331,121 +394,100 @@ bool HostCommsManager::doSendMessageToHostFromNanoapp(
   return true;
 }
 
-HostMessage *HostCommsManager::findMessageByMessageSequenceNumber(
+MessageToHost *HostCommsManager::findMessageToHostBySeq(
     uint32_t messageSequenceNumber) {
   return mMessagePool.find(
       [](HostMessage *inputMessage, void *data) {
         NestedDataPtr<uint32_t> targetMessageSequenceNumber(data);
-        return inputMessage->isReliable &&
+        return inputMessage->isReliable && !inputMessage->fromHost &&
                inputMessage->messageSequenceNumber ==
                    targetMessageSequenceNumber;
       },
       NestedDataPtr<uint32_t>(messageSequenceNumber));
 }
 
-size_t HostCommsManager::flushNanoappTransactions(uint16_t nanoappInstanceId) {
-#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
-  return mTransactionManager.flushTransactions(
-      [](const MessageTransactionData &data, void *callbackData) {
-        NestedDataPtr<uint16_t> innerNanoappInstanceId(callbackData);
-        if (innerNanoappInstanceId == data.nanoappInstanceId) {
-          HostMessage *message = EventLoopManagerSingleton::get()
-                                     ->getHostCommsManager()
-                                     .findMessageByMessageSequenceNumber(
-                                         data.messageSequenceNumber);
-          if (message != nullptr) {
-            EventLoopManagerSingleton::get()
-                ->getHostCommsManager()
-                .onMessageToHostCompleteInternal(message);
-          }
-          return true;
-        }
-        return false;
-      },
-      NestedDataPtr<uint16_t>(nanoappInstanceId));
-#else
-  UNUSED_VAR(nanoappInstanceId);
-  return 0;
-#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
-}
-
 void HostCommsManager::freeMessageToHost(MessageToHost *msgToHost) {
   if (msgToHost->toHostData.nanoappFreeFunction != nullptr) {
     EventLoopManagerSingleton::get()->getEventLoop().invokeMessageFreeFunction(
         msgToHost->appId, msgToHost->toHostData.nanoappFreeFunction,
         msgToHost->message.data(), msgToHost->message.size());
   }
+#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+  if (msgToHost->isReliable) {
+    mTransactionManager.remove(msgToHost->messageSequenceNumber);
+  }
+#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
   mMessagePool.deallocate(msgToHost);
 }
 
-void HostCommsManager::freeMessageFromHostCallback(uint16_t /*type*/,
-                                                   void *data) {
-  // We pass the chreMessageFromHostData structure to the nanoapp as the event's
-  // data pointer, but we need to return to the enclosing HostMessage pointer.
-  // As long as HostMessage is standard-layout, and fromHostData is the first
-  // field, we can convert between these two pointers via reinterpret_cast.
-  // These static assertions ensure this assumption is held.
-  static_assert(std::is_standard_layout<HostMessage>::value,
-                "HostMessage* is derived from HostMessage::fromHostData*, "
-                "therefore it must be standard layout");
-  static_assert(offsetof(MessageFromHost, fromHostData) == 0,
-                "fromHostData must be the first field in HostMessage");
-
-  auto *eventData = static_cast<chreMessageFromHostData *>(data);
-  auto *msgFromHost = reinterpret_cast<MessageFromHost *>(eventData);
-  auto &hostCommsMgr = EventLoopManagerSingleton::get()->getHostCommsManager();
-  hostCommsMgr.mMessagePool.deallocate(msgFromHost);
-}
-
-bool HostCommsManager::sendMessageWithTransactionData(
-    MessageTransactionData &data) {
-  // Set the message sequence number now that TransactionManager has set it.
-  // The message should still be available right now, but might not be later,
-  // so the pointer could be invalid at a later time.
-  data.messageSequenceNumber = *data.messageSequenceNumberPtr;
-
-  HostMessage *message =
-      EventLoopManagerSingleton::get()
-          ->getHostCommsManager()
-          .findMessageByMessageSequenceNumber(data.messageSequenceNumber);
+void HostCommsManager::onTransactionAttempt(uint32_t messageSequenceNumber,
+                                            uint16_t nanoappInstanceId) {
+  MessageToHost *message = findMessageToHostBySeq(messageSequenceNumber);
   Nanoapp *nanoapp =
       EventLoopManagerSingleton::get()->getEventLoop().findNanoappByInstanceId(
-          data.nanoappInstanceId);
-  return nanoapp != nullptr && message != nullptr &&
-         EventLoopManagerSingleton::get()
-             ->getHostCommsManager()
-             .doSendMessageToHostFromNanoapp(nanoapp, message);
-}
-
-bool HostCommsManager::onMessageDeliveryStatus(
-    const MessageTransactionData &data, uint8_t errorCode) {
-  chreAsyncResult *asyncResult = memoryAlloc<chreAsyncResult>();
-  if (asyncResult == nullptr) {
-    LOG_OOM();
-    return false;
+          nanoappInstanceId);
+  if (message == nullptr || nanoapp == nullptr) {
+    LOGE("Attempted to send reliable message %" PRIu32 " from nanoapp %" PRIu16
+         " but couldn't find:%s%s",
+         messageSequenceNumber, nanoappInstanceId,
+         (message == nullptr) ? " msg" : "",
+         (nanoapp == nullptr) ? " napp" : "");
+  } else {
+    bool success = doSendMessageToHostFromNanoapp(nanoapp, message);
+    LOGD("Attempted to send reliable message %" PRIu32 " from nanoapp %" PRIu16
+         " with success: %s",
+         messageSequenceNumber, nanoappInstanceId, success ? "true" : "false");
   }
+}
 
-  asyncResult->requestType = 0;
-  asyncResult->cookie = data.cookie;
-  asyncResult->errorCode = errorCode;
-  asyncResult->reserved = 0;
-  asyncResult->success = errorCode == CHRE_ERROR_NONE;
-
-  EventLoopManagerSingleton::get()->getEventLoop().postEventOrDie(
-      CHRE_EVENT_RELIABLE_MSG_ASYNC_RESULT, asyncResult, freeEventDataCallback,
-      data.nanoappInstanceId);
+void HostCommsManager::onTransactionFailure(uint32_t messageSequenceNumber,
+                                            uint16_t nanoappInstanceId) {
+  LOGE("Reliable message %" PRIu32 " from nanoapp %" PRIu16 " timed out",
+       messageSequenceNumber, nanoappInstanceId);
+  handleMessageDeliveryStatusSync(messageSequenceNumber, CHRE_ERROR_TIMEOUT);
+}
 
-  HostMessage *message =
-      EventLoopManagerSingleton::get()
-          ->getHostCommsManager()
-          .findMessageByMessageSequenceNumber(data.messageSequenceNumber);
-  if (message != nullptr) {
-    EventLoopManagerSingleton::get()
-        ->getHostCommsManager()
-        .onMessageToHostCompleteInternal(message);
+void HostCommsManager::handleDuplicateAndSendMessageDeliveryStatus(
+    [[maybe_unused]] uint32_t messageSequenceNumber,
+    [[maybe_unused]] uint16_t hostEndpoint,
+    [[maybe_unused]] chreError error) {
+#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+  bool success = mDuplicateMessageDetector.findAndSetError(
+      messageSequenceNumber, hostEndpoint, error);
+  if (!success) {
+    LOGW("Failed to set error for message with message sequence number: %"
+          PRIu32 " and host endpoint: 0x%" PRIx16,
+          messageSequenceNumber,
+          hostEndpoint);
   }
+  sendMessageDeliveryStatus(messageSequenceNumber, error);
+#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+}
 
-  return true;
+void HostCommsManager::handleMessageDeliveryStatusSync(
+    uint32_t messageSequenceNumber, uint8_t errorCode) {
+  EventLoop &eventLoop = EventLoopManagerSingleton::get()->getEventLoop();
+  uint16_t nanoappInstanceId;
+  MessageToHost *message = findMessageToHostBySeq(messageSequenceNumber);
+  if (message == nullptr) {
+    LOGW("Got message delivery status for unexpected seq %" PRIu32,
+         messageSequenceNumber);
+  } else if (!eventLoop.findNanoappInstanceIdByAppId(message->appId,
+                                                     &nanoappInstanceId)) {
+    // Expected if we unloaded the nanoapp while a message was in flight
+    LOGW("Got message delivery status seq %" PRIu32
+         " but couldn't find nanoapp 0x%" PRIx64,
+         messageSequenceNumber, message->appId);
+  } else {
+    chreAsyncResult asyncResult = {};
+    asyncResult.success = errorCode == CHRE_ERROR_NONE;
+    asyncResult.errorCode = errorCode;
+    asyncResult.cookie = message->cookie;
+
+    onMessageToHostCompleteInternal(message);
+    eventLoop.deliverEventSync(
+        nanoappInstanceId, CHRE_EVENT_RELIABLE_MSG_ASYNC_RESULT, &asyncResult);
+  }
 }
 
 void HostCommsManager::onMessageToHostCompleteInternal(
@@ -454,6 +496,10 @@ void HostCommsManager::onMessageToHostCompleteInternal(
   // the caller (HostLink) only gets a const pointer
   auto *msgToHost = const_cast<MessageToHost *>(message);
 
+  // TODO(b/346345637): add an assertion that HostLink does not own the memory,
+  // which is technically possible if a reliable message timed out before it
+  // was released
+
   // If there's no free callback, we can free the message right away as the
   // message pool is thread-safe; otherwise, we need to do it from within the
   // EventLoop context.
@@ -462,8 +508,7 @@ void HostCommsManager::onMessageToHostCompleteInternal(
   } else if (inEventLoopThread()) {
     // If we're already within the event loop context, it is safe to call the
     // free callback synchronously.
-    EventLoopManagerSingleton::get()->getHostCommsManager().freeMessageToHost(
-        msgToHost);
+    freeMessageToHost(msgToHost);
   } else {
     auto freeMsgCallback = [](uint16_t /*type*/, void *data,
                               void * /*extraData*/) {
@@ -474,10 +519,37 @@ void HostCommsManager::onMessageToHostCompleteInternal(
     if (!EventLoopManagerSingleton::get()->deferCallback(
             SystemCallbackType::MessageToHostComplete, msgToHost,
             freeMsgCallback)) {
-      EventLoopManagerSingleton::get()->getHostCommsManager().freeMessageToHost(
-          static_cast<MessageToHost *>(msgToHost));
+      freeMessageToHost(static_cast<MessageToHost *>(msgToHost));
+    }
+  }
+}
+
+bool HostCommsManager::shouldSendReliableMessageToNanoapp(
+    [[maybe_unused]] uint32_t messageSequenceNumber,
+    [[maybe_unused]] uint16_t hostEndpoint) {
+#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+  bool isDuplicate;
+  Optional<chreError> pastError = mDuplicateMessageDetector.findOrAdd(
+      messageSequenceNumber, hostEndpoint, &isDuplicate);
+
+  if (isDuplicate) {
+    bool isTransientFailure =
+        pastError.has_value() && (pastError.value() == CHRE_ERROR_BUSY ||
+                                  pastError.value() == CHRE_ERROR_TRANSIENT);
+    LOGW("Duplicate message with message sequence number: %" PRIu32
+         " and host endpoint: 0x%" PRIx16 " was detected. %s",
+         messageSequenceNumber, hostEndpoint,
+         isTransientFailure ? "Retrying." : "Not sending message to nanoapp.");
+    if (!isTransientFailure) {
+      if (pastError.has_value()) {
+        sendMessageDeliveryStatus(messageSequenceNumber, pastError.value());
+      }
+      return false;
     }
   }
+#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+
+  return true;
 }
 
 }  // namespace chre
diff --git a/core/include/chre/core/ble_request_manager.h b/core/include/chre/core/ble_request_manager.h
index d1e885f5..957b8ab1 100644
--- a/core/include/chre/core/ble_request_manager.h
+++ b/core/include/chre/core/ble_request_manager.h
@@ -87,7 +87,6 @@ class BleRequestManager : public NonCopyable {
    */
   bool stopScanAsync(Nanoapp *nanoapp, const void *cookie);
 
-#ifdef CHRE_BLE_READ_RSSI_SUPPORT_ENABLED
   /**
    * Requests to read the RSSI of a peer device on the given LE connection
    * handle.
@@ -115,7 +114,6 @@ class BleRequestManager : public NonCopyable {
    */
   bool readRssiAsync(Nanoapp *nanoapp, uint16_t connectionHandle,
                      const void *cookie);
-#endif
 
   /**
    * Initiates a flush operation where all batched advertisement events will be
@@ -178,7 +176,6 @@ class BleRequestManager : public NonCopyable {
    */
   void handleRequestStateResyncCallback();
 
-#ifdef CHRE_BLE_READ_RSSI_SUPPORT_ENABLED
   /**
    * Handles a readRssi response from the BLE PAL.
    *
@@ -189,7 +186,6 @@ class BleRequestManager : public NonCopyable {
    */
   void handleReadRssi(uint8_t errorCode, uint16_t connectionHandle,
                       int8_t rssi);
-#endif
 
   /**
    * Handler for the flush complete operation. Called when a flush operation is
@@ -278,7 +274,6 @@ class BleRequestManager : public NonCopyable {
   //! The timer handle for the flush operation. Used to track a flush timeout.
   TimerHandle mFlushRequestTimerHandle = CHRE_TIMER_INVALID;
 
-#ifdef CHRE_BLE_READ_RSSI_SUPPORT_ENABLED
   // A pending request from a nanoapp
   struct BleReadRssiRequest {
     uint16_t instanceId;
@@ -290,7 +285,6 @@ class BleRequestManager : public NonCopyable {
   // present) has been dispatched to the PAL, and subsequent entries are queued.
   static constexpr size_t kMaxPendingRssiRequests = 2;
   ArrayQueue<BleReadRssiRequest, kMaxPendingRssiRequests> mPendingRssiRequests;
-#endif
 
   // Struct to hold ble request data for logging
   struct BleRequestLog {
@@ -533,7 +527,6 @@ class BleRequestManager : public NonCopyable {
    */
   static bool isValidAdType(uint8_t adType);
 
-#ifdef CHRE_BLE_READ_RSSI_SUPPORT_ENABLED
   /**
    * Handles a readRssi response from the BLE PAL.
    * Runs in the context of the CHRE thread.
@@ -580,7 +573,6 @@ class BleRequestManager : public NonCopyable {
    * @return uint8_t the error code, with CHRE_ERROR_NONE indicating success
    */
   uint8_t readRssi(uint16_t connectionHandle);
-#endif
 
   /**
    * @return true if BLE setting is enabled.
diff --git a/core/include/chre/core/event.h b/core/include/chre/core/event.h
index 045dffe5..de64bc69 100644
--- a/core/include/chre/core/event.h
+++ b/core/include/chre/core/event.h
@@ -115,6 +115,9 @@ class Event : public NonCopyable {
     }
   }
 
+  //! @return Monotonic time reference for initializing receivedTimeMillis
+  static uint16_t getTimeMillis();
+
   const uint16_t eventType;
 
   //! This value can serve as a proxy for how fast CHRE is processing events
@@ -149,9 +152,6 @@ class Event : public NonCopyable {
 
  private:
   uint8_t mRefCount = 0;
-
-  //! @return Monotonic time reference for initializing receivedTimeMillis
-  static uint16_t getTimeMillis();
 };
 
 }  // namespace chre
diff --git a/core/include/chre/core/event_loop.h b/core/include/chre/core/event_loop.h
index 059281c5..fe7993a8 100644
--- a/core/include/chre/core/event_loop.h
+++ b/core/include/chre/core/event_loop.h
@@ -358,10 +358,6 @@ class EventLoop : public NonCopyable {
     return mEventPoolUsage.getMax();
   }
 
-  inline uint32_t getMeanEventQueueSize() const {
-    return mEventPoolUsage.getMean();
-  }
-
   inline uint32_t getNumEventsDropped() const {
     return mNumDroppedLowPriEvents;
   }
@@ -462,12 +458,12 @@ class EventLoop : public NonCopyable {
                             uint16_t targetInstanceId,
                             uint16_t targetGroupMask);
   /**
-   * Remove some low priority events from back of the queue.
+   * Remove some non nanoapp and low priority events from back of the queue.
    *
    * @param removeNum Number of low priority events to be removed.
    * @return False if cannot remove any low priority event.
    */
-  bool removeLowPriorityEventsFromBack(size_t removeNum);
+  bool removeNonNanoappLowPriorityEventsFromBack(size_t removeNum);
 
   /**
    * Determine if there are space for high priority event.
diff --git a/core/include/chre/core/event_loop_common.h b/core/include/chre/core/event_loop_common.h
index 6c3eb0c1..ca280d13 100644
--- a/core/include/chre/core/event_loop_common.h
+++ b/core/include/chre/core/event_loop_common.h
@@ -75,6 +75,7 @@ enum class SystemCallbackType : uint16_t {
   PulseResponse,
   ReliableMessageEvent,
   TimerPoolTimerExpired,
+  TransactionManagerTimeout,
 };
 
 //! Deferred/delayed callbacks use the event subsystem but are invariably sent
diff --git a/core/include/chre/core/host_comms_manager.h b/core/include/chre/core/host_comms_manager.h
index 83041fc5..a32a09a8 100644
--- a/core/include/chre/core/host_comms_manager.h
+++ b/core/include/chre/core/host_comms_manager.h
@@ -20,10 +20,12 @@
 #include <cstddef>
 #include <cstdint>
 
-#include "chre/core/event_loop.h"
+#include "chre/core/nanoapp.h"
+#include "chre/core/timer_pool.h"
 #include "chre/platform/atomic.h"
 #include "chre/platform/host_link.h"
 #include "chre/util/buffer.h"
+#include "chre/util/duplicate_message_detector.h"
 #include "chre/util/non_copyable.h"
 #include "chre/util/synchronized_memory_pool.h"
 #include "chre/util/time.h"
@@ -70,28 +72,34 @@ struct HostMessage : public NonCopyable {
       //! from the EventLoop where the nanoapp runs.
       chreMessageFreeFunction *nanoappFreeFunction;
 
-      //! Identifier for the host-side entity that should receive this message,
-      //! or that which sent it
+      //! Identifier for the host-side entity that should receive this message.
       uint16_t hostEndpoint;
 
-      //! true if this message results in the host transitioning from suspend
+      //! true if this message resulted in the host transitioning from suspend
       //! to awake.
       bool wokeHost;
     } toHostData;
   };
 
+  //! Distinguishes whether this is a message from the host or to the host,
+  //! which dictates whether fromHostData or toHostData are used.
+  bool fromHost;
+
   //! Whether the message is reliable.
   //! Reliable messages are acknowledge by sending with a status containing
   //! the transaction ID.
   bool isReliable;
 
-  //! Source/destination nanoapp ID
-  uint64_t appId;
-
   //! Used to report reliable message status back to the sender.
   uint32_t messageSequenceNumber;
 
-  //! Application-defined message data
+  //! Opaque nanoapp-supplied cookie associated with reliable messages.
+  const void *cookie;
+
+  //! Source/destination nanoapp ID.
+  uint64_t appId;
+
+  //! Application-defined message data.
   Buffer<uint8_t> message;
 };
 
@@ -105,7 +113,7 @@ typedef HostMessage MessageToHost;
  * Singleton) to the platform-specific HostLinkBase functionality for use by
  * platform-specific code.
  */
-class HostCommsManager : public HostLink {
+class HostCommsManager : public HostLink, private TransactionManagerCallback {
  public:
   HostCommsManager();
 
@@ -126,14 +134,15 @@ class HostCommsManager : public HostLink {
    * pending delivery to the host. At the point that this function is called, it
    * is guaranteed that no new messages will be generated from this nanoapp.
    *
-   * This function also flushes any outstanding reliable message transactions
-   * for the associated nanoapp.
+   * This function also flushes any outstanding reliable message transactions,
+   * by ensuring at least one attempt to send to the host is made, and not
+   * providing a message delivery status event to the nanoapp.
    *
    * This function must impose strict ordering constraints, such that after it
    * returns, it is guaranteed that HostCommsManager::onMessageToHostComplete
    * will not be invoked for the app with the given ID.
    */
-  void flushNanoappMessagesAndTransactions(uint64_t appId);
+  void flushNanoappMessages(Nanoapp &nanoapp);
 
   /**
    * Invoked by the HostLink platform layer when it is done with a message to
@@ -152,20 +161,6 @@ class HostCommsManager : public HostLink {
    */
   void resetBlameForNanoappHostWakeup();
 
-  /**
-   * This function is used by sendMessageToNanoappFromHost() for sending
-   * deferred messages. Messages are deferred when the destination nanoapp is
-   * not yet loaded.
-   *
-   * By the time this function is called through deferCallback, nanoapp load
-   * requests in the queue will have been processed and therefore all nanoapps
-   * are expected to be ready.
-   *
-   * @param craftedMessage Deferred message from host to be delivered to the
-   * destination nanoapp
-   */
-  void sendDeferredMessageToNanoappFromHost(MessageFromHost *craftedMessage);
-
   /**
    * Formulates a MessageToHost using the supplied message contents and
    * passes it to HostLink for transmission to the host.
@@ -228,27 +223,45 @@ class HostCommsManager : public HostLink {
                                     uint32_t messageSequenceNumber);
 
  private:
-  //! The data passed to the transaction manager for use with reliable messages.
-  struct MessageTransactionData {
-    uint32_t *messageSequenceNumberPtr;
-    uint32_t messageSequenceNumber;
-    uint16_t nanoappInstanceId;
-    const void *cookie;
-  };
-
-  //! The maximum number of retries for a reliable message.
-  static constexpr uint16_t kReliableMessageNumRetries = 3;
+  //! How many times we'll try sending a reliable message before giving up.
+  static constexpr uint16_t kReliableMessageMaxAttempts = 4;
 
-  //! The retry wait time for reliable messages.
+  //! How long we'll wait after sending a reliable message which doesn't receive
+  //! an ACK before trying again.
   static constexpr Milliseconds kReliableMessageRetryWaitTime =
       Milliseconds(250);
 
-  //! The timeout to receive an acknowledgment for a reliable message.
-  static constexpr Seconds kReliableMessageTimeout = Seconds(1);
+  //! How long we'll wait before timing out a reliable message.
+  static constexpr Nanoseconds kReliableMessageTimeout =
+      kReliableMessageRetryWaitTime * kReliableMessageMaxAttempts;
+
+  //! How long we'll wait before removing a duplicate message record from the
+  //! duplicate message detector.
+  static constexpr Nanoseconds kReliableMessageDuplicateDetectorTimeout =
+      kReliableMessageTimeout * 3;
 
   //! The maximum number of messages we can have outstanding at any given time.
   static constexpr size_t kMaxOutstandingMessages = 32;
 
+  //! Ensures that we do not blame more than once per host wakeup. This is
+  //! checked before calling host blame to make sure it is set once. The power
+  //! control managers then reset back to false on host suspend.
+  AtomicBool mIsNanoappBlamedForWakeup{false};
+
+  //! Memory pool used to allocate message metadata (but not the contents of the
+  //! messages themselves). Must be synchronized as the same HostCommsManager
+  //! handles communications for all EventLoops, and also to support freeing
+  //! messages directly in onMessageToHostComplete.
+  SynchronizedMemoryPool<HostMessage, kMaxOutstandingMessages> mMessagePool;
+
+#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+  //! The duplicate message detector for reliable messages.
+  DuplicateMessageDetector mDuplicateMessageDetector;
+
+  //! The transaction manager for reliable messages.
+  TransactionManager<kMaxOutstandingMessages, TimerPool> mTransactionManager;
+#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+
   /**
    * Allocates and populates the event structure used to notify a nanoapp of an
    * incoming message from the host.
@@ -265,27 +278,33 @@ class HostCommsManager : public HostLink {
       const void *messageData, uint32_t messageSize, bool isReliable,
       uint32_t messageSequenceNumber);
 
-  //! @see TransactionManager::DeferCallback
-  static bool deferCallback(
-      TransactionManager<MessageTransactionData,
-                         kMaxOutstandingMessages>::DeferCallbackFunction func,
-      void *data, void *extraData, Nanoseconds delay, uint32_t *outTimerHandle);
+  /**
+   * Checks if the message could be sent to the nanoapp from the host. Crafts
+   * the message to the nanoapp.
+   *
+   * @see sendMessageToNanoappFromHost for a description of the parameters.
+   *
+   * @return the error code and the crafted message. The message is dynamically
+   *         allocated and must be freed by the caller.
+   */
+  std::pair<chreError, MessageFromHost *>
+  validateAndCraftMessageFromHostToNanoapp(uint64_t appId, uint32_t messageType,
+                                           uint16_t hostEndpoint,
+                                           const void *messageData,
+                                           size_t messageSize, bool isReliable,
+                                           uint32_t messageSequenceNumber);
 
   /**
    * Posts a crafted event, craftedMessage, to a nanoapp for processing, and
    * deallocates it afterwards.
    *
-   * Used to implement sendMessageToNanoappFromHost() and
-   * sendDeferredMessageToNanoappFromHost(). They allocate and populated the
-   * event using craftNanoappMessageFromHost().
-   *
-   * @param craftedMessage Message from host to be delivered to the destination
-   * nanoapp
+   * Used to implement sendMessageToNanoappFromHost(). It allocates and
+   * populates the event using craftNanoappMessageFromHost().
    *
-   * @return true if the message was delivered to the event queue (i.e.
-   *         destination app ID exists in the system)
+   * @param craftedMessage Message from host to be delivered to the
+   * destination nanoapp
    */
-  bool deliverNanoappMessageFromHost(MessageFromHost *craftedMessage);
+  void deliverNanoappMessageFromHost(MessageFromHost *craftedMessage);
 
   /**
    * Sends a message to the host from a nanoapp. This method also
@@ -302,26 +321,13 @@ class HostCommsManager : public HostLink {
                                       MessageToHost *msgToHost);
 
   /**
-   * Find the message associated with the message sequence number if it exists.
-   * Returns nullptr other wise.
+   * Find the message to the host associated with the message sequence number,
+   * if it exists. Returns nullptr otherwise.
    *
    * @param messageSequenceNumber The message sequence number.
    * @return The message or nullptr if not found.
    */
-  HostMessage *findMessageByMessageSequenceNumber(
-      uint32_t messageSequenceNumber);
-
-  /**
-   * Flushes all the pending reliable message transactions for a nanoapp.
-   *
-   * The completion callback is not called. However,
-   * onMessageToHostCompleteInternal is called for every message removed.
-   *
-   * @param nanoappInstanceId The nanoapp instance ID which
-   * transactions will be flushed.
-   * @return The number of flushed transactions.
-   */
-  size_t flushNanoappTransactions(uint16_t nanoappInstanceId);
+  MessageToHost *findMessageToHostBySeq(uint32_t messageSequenceNumber);
 
   /**
    * Releases memory associated with a message to the host, including invoking
@@ -333,24 +339,35 @@ class HostCommsManager : public HostLink {
   void freeMessageToHost(MessageToHost *msgToHost);
 
   /**
-   * Event free callback used to release memory allocated to deliver a message
-   * to a nanoapp from the host.
-   *
-   * @param type Event type
-   * @param data Event data
+   * Callback used to send a reliable message.
+   * @see TransactionManagerCallback
    */
-  static void freeMessageFromHostCallback(uint16_t type, void *data);
+  void onTransactionAttempt(uint32_t messageSequenceNumber,
+                            uint16_t nanoappInstanceId) final;
 
   /**
-   * Callback used to send a reliable message.
+   * Callback invoked when a transaction has timed out after the maximum
+   * number of retries.
+   * @see TransactionManagerCallback
+   */
+  void onTransactionFailure(uint32_t messageSequenceNumber,
+                            uint16_t nanoappInstanceId) final;
+
+  /**
+   * Handles a duplicate message from the host by setting the error in the
+   * duplicate message detector and sends a message delivery status to the
+   * nanoapp.
    *
-   * @param data The message transaction data.
-   * @return Whether the message was sent successfully.
+   * @param messageSequenceNumber The message sequence number.
+   * @param hostEndpoint The host endpoint.
+   * @param error The error from sending the message to the nanoapp.
    */
-  static bool sendMessageWithTransactionData(MessageTransactionData &data);
+  void handleDuplicateAndSendMessageDeliveryStatus(
+      uint32_t messageSequenceNumber, uint16_t hostEndpoint, chreError error);
 
   /**
-   * Called when a reliable message transaction status is reported by the host.
+   * Called when a reliable message transaction status is reported by the
+   * host.
    *
    * The status is delivered to the nanoapp that sent the message by posting a
    * CHRE_EVENT_RELIABLE_MSG_ASYNC_STATUS event.
@@ -360,8 +377,8 @@ class HostCommsManager : public HostLink {
    * @return Whether the event was posted successfully.
    *
    */
-  static bool onMessageDeliveryStatus(const MessageTransactionData &data,
-                                      uint8_t errorCode);
+  void handleMessageDeliveryStatusSync(uint32_t messageSequenceNumber,
+                                       uint8_t errorCode);
 
   /**
    * Invoked by onMessageToHostComplete for a non-reliable message
@@ -370,26 +387,37 @@ class HostCommsManager : public HostLink {
    *
    * This function is thread-safe.
    *
-   * @param message A message pointer previously given to HostLink::sendMessage
+   * @param message A message pointer previously given to
+   * HostLink::sendMessage
    */
   void onMessageToHostCompleteInternal(const MessageToHost *msgToHost);
 
-  //! Ensures that we do not blame more than once per host wakeup. This is
-  //! checked before calling host blame to make sure it is set once. The power
-  //! control managers then reset back to false on host suspend.
-  AtomicBool mIsNanoappBlamedForWakeup{false};
+  /**
+   * Calls TransactionManager::remove for all pending reliable messages sent
+   * by this nanoapp, normally used as part of nanoapp unload flow.
+   */
+  void removeAllTransactionsFromNanoapp(const Nanoapp &nanoapp);
 
-  //! Memory pool used to allocate message metadata (but not the contents of the
-  //! messages themselves). Must be synchronized as the same HostCommsManager
-  //! handles communications for all EventLoops, and also to support freeing
-  //! messages directly in onMessageToHostComplete.
-  SynchronizedMemoryPool<HostMessage, kMaxOutstandingMessages> mMessagePool;
+  /**
+   * Releases memory for all pending reliable messages sent by this nanoapp.
+   * The data must have already been flushed through HostLink, and the
+   * transactions must have already been cleaned up.
+   */
+  void freeAllReliableMessagesFromNanoapp(Nanoapp &nanoapp);
 
-#ifdef CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
-  //! The transaction manager for reliable messages.
-  TransactionManager<MessageTransactionData, kMaxOutstandingMessages>
-      mTransactionManager;
-#endif  // CHRE_RELIABLE_MESSAGE_SUPPORT_ENABLED
+  /**
+   * Returns whether to send the reliable message to the nanoapp. This
+   * function returns true, indicating to the caller to send the message, when
+   * the message is not a duplicate or when the duplicate message was sent
+   * previously with a transient error. When this function returns false, the
+   * error is sent to the host using sendMessageDeliveryStatus.
+   *
+   * @param messageSequenceNumber The message sequence number.
+   * @param hostEndpoint The host endpoint.
+   * @return Whether to send the message to the nanoapp.
+   */
+  bool shouldSendReliableMessageToNanoapp(uint32_t messageSequenceNumber,
+                                          uint16_t hostEndpoint);
 };
 
 }  // namespace chre
diff --git a/core/include/chre/core/wifi_request_manager.h b/core/include/chre/core/wifi_request_manager.h
index 576b1d81..b5e27089 100644
--- a/core/include/chre/core/wifi_request_manager.h
+++ b/core/include/chre/core/wifi_request_manager.h
@@ -176,7 +176,7 @@ class WifiRequestManager : public NonCopyable {
    * Wifi scan.
    *
    * @param pending The result of the request was successful and the results
-   *        be sent via the handleScanEvent method.
+   *        will be sent via the handleScanEvent method.
    * @param errorCode an error code that is used to indicate success or what
    *        type of error has occurred. See the chreError enum in the CHRE API
    *        for additional details.
@@ -617,8 +617,8 @@ class WifiRequestManager : public NonCopyable {
    * thread. This method is intended to be invoked on the CHRE event loop
    * thread.
    *
-   * @param enabled true if the result of the operation was an enabled scan
-   *        monitor.
+   * @param pending The result of the request was successful and the results
+   *        will be sent via the handleScanEvent method.
    * @param errorCode an error code that is provided to indicate success or what
    *        type of error has occurred. See the chreError enum in the CHRE API
    *        for additional details.
@@ -912,6 +912,12 @@ class WifiRequestManager : public NonCopyable {
    * has responded in the expected time window.
    */
   TimerHandle setScanRequestTimer();
+
+  /**
+   * Clears the system timer tracking timeout of the scan request. Should be
+   * called after scan response and all pending data have been delivered.
+   */
+  void cancelScanRequestTimer();
 };
 
 }  // namespace chre
diff --git a/core/include/chre/core/wwan_request_manager.h b/core/include/chre/core/wwan_request_manager.h
index 5d35a181..1c1e278d 100644
--- a/core/include/chre/core/wwan_request_manager.h
+++ b/core/include/chre/core/wwan_request_manager.h
@@ -19,6 +19,7 @@
 
 #include <cstdint>
 
+#include "chre/core/api_manager_common.h"
 #include "chre/core/nanoapp.h"
 #include "chre/platform/platform_wwan.h"
 #include "chre/util/non_copyable.h"
@@ -88,6 +89,10 @@ class WwanRequestManager : public NonCopyable {
   //! is set.
   const void *mCellInfoRequestingNanoappCookie;
 
+  //! ErrorCode Histogram for collected errors, the index of this array
+  //! corresponds to the type of the errorcode
+  uint32_t mCellInfoErrorHistogram[CHRE_ERROR_SIZE] = {0};
+
   /**
    * Handles the result of a request for cell info. See handleCellInfoResult
    * which may be called from any thread. This thread is intended to be invoked
diff --git a/core/nanoapp.cc b/core/nanoapp.cc
index 774ae9c1..f16dbae2 100644
--- a/core/nanoapp.cc
+++ b/core/nanoapp.cc
@@ -200,17 +200,15 @@ void Nanoapp::logStateToBuffer(DebugDumpWrapper &debugDump) const {
 void Nanoapp::logMemAndComputeHeader(DebugDumpWrapper &debugDump) const {
   // Print table header
   // Nanoapp column sized to accommodate largest known name
-  debugDump.print("\n%10sNanoapp%9s| Mem Alloc (Bytes) |%7sEvent Time (Ms)\n",
+  debugDump.print("\n%10sNanoapp%9s| Mem Alloc (Bytes) |%2sEvent Time (Ms)\n",
                   "", "", "");
-  debugDump.print("%26s| Current |     Max |    Mean |     Max |   Total\n",
-                  "");
+  debugDump.print("%26s| Current |     Max |     Max |   Total\n", "");
 }
 
 void Nanoapp::logMemAndComputeEntry(DebugDumpWrapper &debugDump) const {
   debugDump.print("%25s |", getAppName());
   debugDump.print(" %7zu |", getTotalAllocatedBytes());
   debugDump.print(" %7zu |", getPeakAllocatedBytes());
-  debugDump.print(" %7" PRIu64 " |", mEventProcessTime.getMean());
   debugDump.print(" %7" PRIu64 " |", mEventProcessTime.getMax());
   debugDump.print(" %7" PRIu64 "\n", mEventProcessTimeSinceBoot);
 }
diff --git a/core/telemetry_manager.cc b/core/telemetry_manager.cc
index 6772cb5a..6bc32a72 100644
--- a/core/telemetry_manager.cc
+++ b/core/telemetry_manager.cc
@@ -85,8 +85,7 @@ void sendPalOpenFailedMetric(_android_chre_metrics_ChrePalType pal) {
                    &result);
 }
 
-void sendEventLoopStats(uint32_t maxQueueSize, uint32_t meanQueueSize,
-                        uint32_t numDroppedEvents) {
+void sendEventLoopStats(uint32_t maxQueueSize, uint32_t numDroppedEvents) {
   _android_chre_metrics_ChreEventQueueSnapshotReported result =
       CHREATOMS_GET(ChreEventQueueSnapshotReported_init_default);
   result.has_snapshot_chre_get_time_ms = true;
@@ -95,8 +94,6 @@ void sendEventLoopStats(uint32_t maxQueueSize, uint32_t meanQueueSize,
       kOneMillisecondInNanoseconds;
   result.has_max_event_queue_size = true;
   result.max_event_queue_size = maxQueueSize;
-  result.has_mean_event_queue_size = true;
-  result.mean_event_queue_size = meanQueueSize;
   result.has_num_dropped_events = true;
   result.num_dropped_events = numDroppedEvents;
 
@@ -154,7 +151,6 @@ void TelemetryManager::onPalOpenFailure(PalType type) {
 void TelemetryManager::collectSystemMetrics() {
   EventLoop &eventLoop = EventLoopManagerSingleton::get()->getEventLoop();
   sendEventLoopStats(eventLoop.getMaxEventQueueSize(),
-                     eventLoop.getMeanEventQueueSize(),
                      eventLoop.getNumEventsDropped());
 
   scheduleMetricTimer();
diff --git a/core/timer_pool.cc b/core/timer_pool.cc
index 23d1833d..36d032e5 100644
--- a/core/timer_pool.cc
+++ b/core/timer_pool.cc
@@ -25,8 +25,14 @@
 #include "chre/util/lock_guard.h"
 #include "chre/util/nested_data_ptr.h"
 
+#include <cstdint>
+
 namespace chre {
 
+namespace {
+constexpr uint64_t kTimerAlreadyFiredExpiration = UINT64_MAX;
+}  // anonymous namespace
+
 TimerPool::TimerPool() {
   if (!mSystemTimer.init()) {
     FATAL_ERROR("Failed to initialize a system timer for the TimerPool");
@@ -276,11 +282,14 @@ bool TimerPool::handleExpiredTimersAndScheduleNextLocked() {
 
       rescheduleAndRemoveExpiredTimersLocked(currentTimerRequest);
     } else {
-      // Update the system timer to reflect the duration until the closest
-      // expiry (mTimerRequests is sorted by expiry, so we just do this for
-      // the first timer found which has not expired yet)
-      Nanoseconds duration = currentTimerRequest.expirationTime - currentTime;
-      mSystemTimer.set(handleSystemTimerCallback, this, duration);
+      if (currentTimerRequest.expirationTime.toRawNanoseconds() <
+          kTimerAlreadyFiredExpiration) {
+        // Update the system timer to reflect the duration until the closest
+        // expiry (mTimerRequests is sorted by expiry, so we just do this for
+        // the first timer found which has not expired yet)
+        Nanoseconds duration = currentTimerRequest.expirationTime - currentTime;
+        mSystemTimer.set(handleSystemTimerCallback, this, duration);
+      }
       break;
     }
   }
@@ -294,9 +303,9 @@ void TimerPool::rescheduleAndRemoveExpiredTimersLocked(
     popTimerRequestLocked();
   } else {
     TimerRequest copyRequest = request;
-    copyRequest.expirationTime = request.isOneShot
-        ? Nanoseconds(UINT64_MAX)
-        : request.expirationTime + request.duration;
+    copyRequest.expirationTime =
+        request.isOneShot ? Nanoseconds(kTimerAlreadyFiredExpiration)
+                          : request.expirationTime + request.duration;
     popTimerRequestLocked();
     CHRE_ASSERT(insertTimerRequestLocked(copyRequest));
   }
diff --git a/core/wifi_request_manager.cc b/core/wifi_request_manager.cc
index eb9a5531..8aa4649a 100644
--- a/core/wifi_request_manager.cc
+++ b/core/wifi_request_manager.cc
@@ -332,6 +332,14 @@ TimerHandle WifiRequestManager::setScanRequestTimer() {
       Nanoseconds(CHRE_WIFI_SCAN_RESULT_TIMEOUT_NS));
 }
 
+void WifiRequestManager::cancelScanRequestTimer() {
+  if (mScanRequestTimeoutHandle != CHRE_TIMER_INVALID) {
+    EventLoopManagerSingleton::get()->cancelDelayedCallback(
+        mScanRequestTimeoutHandle);
+    mScanRequestTimeoutHandle = CHRE_TIMER_INVALID;
+  }
+}
+
 bool WifiRequestManager::nanoappHasPendingScanRequest(
     uint16_t instanceId) const {
   for (const auto &scanRequest : mPendingScanRequests) {
@@ -698,7 +706,8 @@ void WifiRequestManager::logStateToBuffer(DebugDumpWrapper &debugDump) const {
     debugDump.print("  ts=%" PRIu64 " nappId=%" PRIu16 " scanType=%" PRIu8
                     " maxScanAge(ms)=%" PRIu64 "\n",
                     log.timestamp.toRawNanoseconds(), log.instanceId,
-                    log.scanType, log.maxScanAgeMs.getMilliseconds());
+                    static_cast<uint8_t>(log.scanType),
+                    log.maxScanAgeMs.getMilliseconds());
   }
 
   debugDump.print(" Last scan event @ %" PRIu64 " ms\n",
@@ -849,7 +858,11 @@ bool WifiRequestManager::postScanMonitorAsyncResultEvent(
       event->reserved = 0;
       event->cookie = cookie;
 
-      mScanMonitorErrorHistogram[errorCode]++;
+      if (errorCode < CHRE_ERROR_SIZE) {
+        mScanMonitorErrorHistogram[errorCode]++;
+      } else {
+        LOGE("Undefined error in ScanMonitorAsyncResult: %" PRIu8, errorCode);
+      }
 
       EventLoopManagerSingleton::get()->getEventLoop().postEventOrDie(
           CHRE_EVENT_WIFI_ASYNC_RESULT, event, freeEventDataCallback,
@@ -887,7 +900,11 @@ bool WifiRequestManager::postScanRequestAsyncResultEvent(
     event->reserved = 0;
     event->cookie = cookie;
 
-    mActiveScanErrorHistogram[errorCode]++;
+    if (errorCode < CHRE_ERROR_SIZE) {
+      mActiveScanErrorHistogram[errorCode]++;
+    } else {
+      LOGE("Undefined error in ScanRequestAsyncResult: %" PRIu8, errorCode);
+    }
 
     EventLoopManagerSingleton::get()->getEventLoop().postEventOrDie(
         CHRE_EVENT_WIFI_ASYNC_RESULT, event, freeEventDataCallback,
@@ -972,12 +989,6 @@ void WifiRequestManager::handleScanResponseSync(bool pending,
     LOGE("handleScanResponseSync called with no outstanding request");
   }
 
-  if (mScanRequestTimeoutHandle != CHRE_TIMER_INVALID) {
-    EventLoopManagerSingleton::get()->cancelDelayedCallback(
-        mScanRequestTimeoutHandle);
-    mScanRequestTimeoutHandle = CHRE_TIMER_INVALID;
-  }
-
   // TODO: raise this to CHRE_ASSERT_LOG
   if (!pending && errorCode == CHRE_ERROR_NONE) {
     LOGE("Invalid wifi scan response");
@@ -1012,6 +1023,7 @@ void WifiRequestManager::handleScanResponseSync(bool pending,
       // If the scan results are not pending, pop the first event since it's no
       // longer waiting for anything. Otherwise, wait for the results to be
       // delivered and then pop the first request.
+      cancelScanRequestTimer();
       mPendingScanRequests.pop();
       dispatchQueuedScanRequests(true /* postAsyncResult */);
     }
@@ -1162,6 +1174,7 @@ void WifiRequestManager::handleFreeWifiScanEvent(chreWifiScanEvent *scanEvent) {
     if (mScanEventResultCountAccumulator >= scanEvent->resultTotal) {
       mScanEventResultCountAccumulator = 0;
       mScanRequestResultsArePending = false;
+      cancelScanRequestTimer();
     }
 
     if (!mScanRequestResultsArePending && !mPendingScanRequests.empty()) {
diff --git a/core/wwan_request_manager.cc b/core/wwan_request_manager.cc
index 1bf51f64..9fbbc92e 100644
--- a/core/wwan_request_manager.cc
+++ b/core/wwan_request_manager.cc
@@ -66,6 +66,14 @@ void WwanRequestManager::handleCellInfoResultSync(
     chreWwanCellInfoResult *result) {
   if (mCellInfoRequestingNanoappInstanceId.has_value()) {
     result->cookie = mCellInfoRequestingNanoappCookie;
+
+    uint8_t errorCode = result->errorCode;
+    if (errorCode < CHRE_ERROR_SIZE) {
+      mCellInfoErrorHistogram[errorCode]++;
+    } else {
+      LOGE("Undefined error in cellInfoResult: %" PRIu8, errorCode);
+    }
+
     EventLoopManagerSingleton::get()->getEventLoop().postEventOrDie(
         CHRE_EVENT_WWAN_CELL_INFO_RESULT, result, freeCellInfoResultCallback,
         mCellInfoRequestingNanoappInstanceId.value());
@@ -80,6 +88,11 @@ void WwanRequestManager::logStateToBuffer(DebugDumpWrapper &debugDump) const {
     debugDump.print(" WWAN request pending nanoappId=%" PRIu16 "\n",
                     mCellInfoRequestingNanoappInstanceId.value());
   }
+
+  debugDump.print(" API error distribution (error-code indexed):\n");
+  debugDump.print("   Cell Scan:\n");
+  debugDump.logErrorHistogram(mCellInfoErrorHistogram,
+                              ARRAY_SIZE(mCellInfoErrorHistogram));
 }
 
 void WwanRequestManager::handleFreeCellInfoResult(
diff --git a/external/flatbuffers/README.md b/external/flatbuffers/README.md
index 09cc0f4e..7fdfad1e 100644
--- a/external/flatbuffers/README.md
+++ b/external/flatbuffers/README.md
@@ -1,3 +1,5 @@
+# flatbuffers
+
 This folder contains a modified version of the FlatBuffers implementation header
 file (flatbuffers.h) which customizes it for running in the CHRE environment.
 When upgrading to a newer FlatBuffers release, be sure to manually merge the
@@ -7,3 +9,28 @@ The FlatBuffers IDL compiler (flatc) can be used without modification, but must
 match the version of the Flatbuffers library used here.
 
 The FlatBuffers project is hosted at https://github.com/google/flatbuffers/
+
+## Current version
+
+The version currently supported is [v1.12.0](https://github.com/google/flatbuffers/releases/tag/v1.12.0).
+
+### Building flatc
+
+Official build instructions: https://flatbuffers.dev/flatbuffers_guide_building.html
+
+Instructions updated May 29, 2024.
+
+```shell
+mkdir /tmp/flatbuffer-v1.12.0
+cd /tmp/flatbuffer-v1.12.0
+wget https://github.com/google/flatbuffers/archive/refs/tags/v1.12.0.tar.gz -O flatbuffers-1.12.0.tar.gz
+tar -xzvf flatbuffers-1.12.0.tar.gz
+cd flatbuffers-1.12.0
+cmake .
+make flatc
+```
+
+Adding flatc to your PATH
+```shell
+export PATH=$PATH:/tmp/flatbuffer-v1.12.0/flatbuffers-1.12.0
+```
diff --git a/host/common/config_util.cc b/host/common/config_util.cc
index e39083f5..fa6e9852 100644
--- a/host/common/config_util.cc
+++ b/host/common/config_util.cc
@@ -17,12 +17,35 @@
 #include "chre_host/config_util.h"
 #include "chre_host/log.h"
 
+#include <dirent.h>
 #include <json/json.h>
+#include <filesystem>
 #include <fstream>
+#include <regex>
 
 namespace android {
 namespace chre {
 
+bool findAllNanoappsInFolder(const std::string &path,
+                             std::vector<std::string> &outNanoapps) {
+  DIR *dir = opendir(path.c_str());
+  if (dir == nullptr) {
+    LOGE("Failed to open nanoapp folder %s", path.c_str());
+    return false;
+  }
+  std::regex regex("(\\w+)\\.napp_header");
+  std::cmatch match;
+  for (struct dirent *entry; (entry = readdir(dir)) != nullptr;) {
+    if (!std::regex_match(entry->d_name, match, regex)) {
+      continue;
+    }
+    LOGD("Found nanoapp: %s", match[1]);
+    outNanoapps.push_back(match[1]);
+  }
+  closedir(dir);
+  return true;
+}
+
 bool getPreloadedNanoappsFromConfigFile(const std::string &configFilePath,
                                         std::string &outDirectory,
                                         std::vector<std::string> &outNanoapps) {
@@ -31,8 +54,15 @@ bool getPreloadedNanoappsFromConfigFile(const std::string &configFilePath,
   Json::CharReaderBuilder builder;
   Json::Value config;
   if (!configFileStream) {
-    LOGE("Failed to open config file '%s'", configFilePath.c_str());
-    return false;
+    // TODO(b/350102369) to deprecate preloaded_nanoapps.json
+    // During the transition, fall back to the old behavior if the json
+    // file exists. But if the json file does not exist, do the new behavior
+    // to load all nanoapps in /vendor/etc/chre or where ever the location.
+    LOGI("Failed to open config file '%s' load all nanoapps in folder ",
+         configFilePath.c_str());
+    std::filesystem::path path(configFilePath);
+    outDirectory = path.parent_path().string();
+    return findAllNanoappsInFolder(outDirectory, outNanoapps);
   } else if (!Json::parseFromStream(builder, configFileStream, &config,
                                     /* errs = */ nullptr)) {
     LOGE("Failed to parse nanoapp config file");
diff --git a/host/common/daemon_base.cc b/host/common/daemon_base.cc
index b7681cbb..839a1a75 100644
--- a/host/common/daemon_base.cc
+++ b/host/common/daemon_base.cc
@@ -14,9 +14,6 @@
  * limitations under the License.
  */
 
-// TODO(b/298459533): metrics_reporter_in_the_daemon ramp up -> remove old
-// code
-
 #include <signal.h>
 #include <cstdlib>
 #include <fstream>
@@ -48,7 +45,6 @@ using ::aidl::android::frameworks::stats::VendorAtomValue;
 using ::android::chre::Atoms::CHRE_EVENT_QUEUE_SNAPSHOT_REPORTED;
 using ::android::chre::Atoms::CHRE_PAL_OPEN_FAILED;
 using ::android::chre::Atoms::ChrePalOpenFailed;
-using ::android::chre::flags::metrics_reporter_in_the_daemon;
 #endif  // CHRE_DAEMON_METRIC_ENABLED
 
 namespace {
@@ -169,23 +165,12 @@ void ChreDaemonBase::handleMetricLog(const ::chre::fbs::MetricLogT *metricMsg) {
       if (!metric.ParseFromArray(encodedMetric.data(), encodedMetric.size())) {
         LOGE("Failed to parse metric data");
       } else {
-        if (metrics_reporter_in_the_daemon()) {
-          ChrePalOpenFailed::ChrePalType pal =
-              static_cast<ChrePalOpenFailed::ChrePalType>(metric.pal());
-          ChrePalOpenFailed::Type type =
-              static_cast<ChrePalOpenFailed::Type>(metric.type());
-          if (!mMetricsReporter.logPalOpenFailed(pal, type)) {
-            LOGE("Could not log the PAL open failed metric");
-          }
-        } else {
-          std::vector<VendorAtomValue> values(2);
-          values[0].set<VendorAtomValue::intValue>(metric.pal());
-          values[1].set<VendorAtomValue::intValue>(metric.type());
-          const VendorAtom atom{
-              .atomId = Atoms::CHRE_PAL_OPEN_FAILED,
-              .values{std::move(values)},
-          };
-          reportMetric(atom);
+        ChrePalOpenFailed::ChrePalType pal =
+            static_cast<ChrePalOpenFailed::ChrePalType>(metric.pal());
+        ChrePalOpenFailed::Type type =
+            static_cast<ChrePalOpenFailed::Type>(metric.type());
+        if (!mMetricsReporter.logPalOpenFailed(pal, type)) {
+          LOGE("Could not log the PAL open failed metric");
         }
       }
       break;
@@ -194,36 +179,11 @@ void ChreDaemonBase::handleMetricLog(const ::chre::fbs::MetricLogT *metricMsg) {
       metrics::ChreEventQueueSnapshotReported metric;
       if (!metric.ParseFromArray(encodedMetric.data(), encodedMetric.size())) {
         LOGE("Failed to parse metric data");
-      } else {
-        if (metrics_reporter_in_the_daemon()) {
-          if (!mMetricsReporter.logEventQueueSnapshotReported(
-                  metric.snapshot_chre_get_time_ms(),
-                  metric.max_event_queue_size(), metric.mean_event_queue_size(),
-                  metric.num_dropped_events())) {
-            LOGE("Could not log the event queue snapshot metric");
-          }
-        } else {
-          std::vector<VendorAtomValue> values(6);
-          values[0].set<VendorAtomValue::intValue>(
-              metric.snapshot_chre_get_time_ms());
-          values[1].set<VendorAtomValue::intValue>(
-              metric.max_event_queue_size());
-          values[2].set<VendorAtomValue::intValue>(
-              metric.mean_event_queue_size());
-          values[3].set<VendorAtomValue::intValue>(metric.num_dropped_events());
-          // Last two values are not currently populated and will be implemented
-          // later. To avoid confusion of the interpretation, we use UINT32_MAX
-          // as a placeholder value.
-          values[4].set<VendorAtomValue::intValue>(
-              UINT32_MAX);  // max_queue_delay_us
-          values[5].set<VendorAtomValue::intValue>(
-              UINT32_MAX);  // mean_queue_delay_us
-          const VendorAtom atom{
-              .atomId = Atoms::CHRE_EVENT_QUEUE_SNAPSHOT_REPORTED,
-              .values{std::move(values)},
-          };
-          reportMetric(atom);
-        }
+      } else if (!mMetricsReporter.logEventQueueSnapshotReported(
+              metric.snapshot_chre_get_time_ms(),
+              metric.max_event_queue_size(), metric.mean_event_queue_size(),
+              metric.num_dropped_events())) {
+        LOGE("Could not log the event queue snapshot metric");
       }
       break;
     }
diff --git a/host/common/fbs_daemon_base.cc b/host/common/fbs_daemon_base.cc
index ee45ccc8..8fc8abd2 100644
--- a/host/common/fbs_daemon_base.cc
+++ b/host/common/fbs_daemon_base.cc
@@ -14,9 +14,6 @@
  * limitations under the License.
  */
 
-// TODO(b/298459533): metrics_reporter_in_the_daemon ramp up -> remove old
-// code
-
 #include <cstdlib>
 #include <fstream>
 
@@ -45,7 +42,6 @@ using ::aidl::android::frameworks::stats::IStats;
 using ::aidl::android::frameworks::stats::VendorAtom;
 using ::aidl::android::frameworks::stats::VendorAtomValue;
 using ::android::chre::Atoms::ChreHalNanoappLoadFailed;
-using ::android::chre::flags::metrics_reporter_in_the_daemon;
 #endif  // CHRE_DAEMON_METRIC_ENABLED
 
 bool FbsDaemonBase::sendNanoappLoad(uint64_t appId, uint32_t appVersion,
@@ -181,26 +177,11 @@ void FbsDaemonBase::handleDaemonMessage(const uint8_t *message) {
              mPreloadedNanoappPendingTransactions.front().transactionId);
 
 #ifdef CHRE_DAEMON_METRIC_ENABLED
-        if (metrics_reporter_in_the_daemon()) {
-          if (!mMetricsReporter.logNanoappLoadFailed(
-                  mPreloadedNanoappPendingTransactions.front().nanoappId,
-                  ChreHalNanoappLoadFailed::TYPE_PRELOADED,
-                  ChreHalNanoappLoadFailed::REASON_ERROR_GENERIC)) {
-            LOGE("Could not log the nanoapp load failed metric");
-          }
-        } else {
-          std::vector<VendorAtomValue> values(3);
-          values[0].set<VendorAtomValue::longValue>(
-              mPreloadedNanoappPendingTransactions.front().nanoappId);
-          values[1].set<VendorAtomValue::intValue>(
-              Atoms::ChreHalNanoappLoadFailed::TYPE_PRELOADED);
-          values[2].set<VendorAtomValue::intValue>(
-              Atoms::ChreHalNanoappLoadFailed::REASON_ERROR_GENERIC);
-          const VendorAtom atom{
-              .atomId = Atoms::CHRE_HAL_NANOAPP_LOAD_FAILED,
-              .values{std::move(values)},
-          };
-          reportMetric(atom);
+        if (!mMetricsReporter.logNanoappLoadFailed(
+                mPreloadedNanoappPendingTransactions.front().nanoappId,
+                ChreHalNanoappLoadFailed::TYPE_PRELOADED,
+                ChreHalNanoappLoadFailed::REASON_ERROR_GENERIC)) {
+          LOGE("Could not log the nanoapp load failed metric");
         }
 #endif  // CHRE_DAEMON_METRIC_ENABLED
       }
diff --git a/host/common/hal_client.cc b/host/common/hal_client.cc
index 9b4086e2..e25e6f58 100644
--- a/host/common/hal_client.cc
+++ b/host/common/hal_client.cc
@@ -46,10 +46,6 @@ bool HalClient::isServiceAvailable() {
   return GetBoolProperty(kHalEnabledProperty, /* default_value= */ false);
 }
 
-bool HalClient::reduceLockHolding() {
-  return flags::bug_fix_reduce_lock_holding_period();
-}
-
 std::unique_ptr<HalClient> HalClient::create(
     const std::shared_ptr<IContextHubCallback> &callback,
     int32_t contextHubId) {
@@ -126,6 +122,7 @@ HalError HalClient::initConnection() {
     mContextHub = nullptr;
     return HalError::CALLBACK_REGISTRATION_FAILED;
   }
+  mIsHalConnected = true;
   LOGI("%s is successfully (re)connected to CHRE HAL", mClientName.c_str());
   return HalError::SUCCESS;
 }
@@ -136,6 +133,7 @@ void HalClient::onHalDisconnected(void *cookie) {
   {
     std::lock_guard<std::shared_mutex> lockGuard(halClient->mConnectionLock);
     halClient->mContextHub = nullptr;
+    halClient->mIsHalConnected = false;
   }
   LOGW("%s is disconnected from CHRE HAL. Reconnecting...",
        halClient->mClientName.c_str());
diff --git a/host/common/include/chre_host/daemon_base.h b/host/common/include/chre_host/daemon_base.h
index 453a8665..6490ad9d 100644
--- a/host/common/include/chre_host/daemon_base.h
+++ b/host/common/include/chre_host/daemon_base.h
@@ -25,9 +25,6 @@
  * implement.
  */
 
-// TODO(b/298459533): metrics_reporter_in_the_daemon ramp up -> remove old
-// code
-
 #include <atomic>
 #include <csignal>
 #include <cstdint>
diff --git a/host/common/include/chre_host/hal_client.h b/host/common/include/chre_host/hal_client.h
index ac77f08a..45ce4468 100644
--- a/host/common/include/chre_host/hal_client.h
+++ b/host/common/include/chre_host/hal_client.h
@@ -109,12 +109,9 @@ class HalClient {
    */
   static bool isServiceAvailable();
 
-  /** A bug fix flag guarding the lock holding reduction change. */
-  static bool reduceLockHolding();
-
   /** Returns true if this HalClient instance is connected to the HAL. */
   bool isConnected() {
-    return mContextHub != nullptr;
+    return mIsHalConnected;
   }
 
   /** Connects to CHRE HAL synchronously. */
@@ -281,6 +278,7 @@ class HalClient {
   // The lock guarding the init connection flow.
   std::shared_mutex mConnectionLock;
   std::shared_ptr<IContextHub> mContextHub;
+  std::atomic_bool mIsHalConnected = false;
 
   // Handler of the binder disconnection event with HAL.
   ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
diff --git a/host/common/include/chre_host/log_message_parser.h b/host/common/include/chre_host/log_message_parser.h
index b131f612..2b4546e6 100644
--- a/host/common/include/chre_host/log_message_parser.h
+++ b/host/common/include/chre_host/log_message_parser.h
@@ -20,12 +20,14 @@
 #include <endian.h>
 #include <cinttypes>
 #include <memory>
+#include <mutex>
 #include <optional>
 #include "chre/util/time.h"
 #include "chre_host/bt_snoop_log_parser.h"
 #include "chre_host/generated/host_messages_generated.h"
 #include "chre_host/nanoapp_load_listener.h"
 
+#include <android-base/thread_annotations.h>
 #include <android/log.h>
 
 #include "pw_tokenizer/detokenize.h"
@@ -94,7 +96,8 @@ class LogMessageParser : public INanoappLoadListener {
    * @param removeBinary Remove the nanoapp binary associated with the app ID if
    * true.
    */
-  void removeNanoappDetokenizerAndBinary(uint64_t appId);
+  void removeNanoappDetokenizerAndBinary(uint64_t appId)
+      EXCLUDES(mNanoappMutex);
 
   /**
    * Reset all nanoapp log detokenizers.
@@ -176,14 +179,19 @@ class LogMessageParser : public INanoappLoadListener {
   };
 
   //! Maps nanoapp instance IDs to the corresponding app ID and pigweed
-  //! detokenizer.
+  //! detokenizer. Guarded by mNanoappMutex.
   std::unordered_map<uint16_t /*instanceId*/, NanoappDetokenizer>
-      mNanoappDetokenizers;
+      mNanoappDetokenizers GUARDED_BY(mNanoappMutex);
 
   //! This is used to find the binary associated with a nanoapp with its app ID.
+  //! Guarded by mNanoappMutex.
   std::unordered_map<uint64_t /*appId*/,
                      std::shared_ptr<const std::vector<uint8_t>>>
-      mNanoappAppIdToBinary;
+      mNanoappAppIdToBinary GUARDED_BY(mNanoappMutex);
+
+  //! The mutex used to guard operations of mNanoappAppIdtoBinary and
+  //! mNanoappDetokenizers.
+  std::mutex mNanoappMutex;
 
   static android_LogPriority chreLogLevelToAndroidLogPriority(uint8_t level);
 
@@ -297,13 +305,27 @@ class LogMessageParser : public INanoappLoadListener {
   bool checkTokenDatabaseOverflow(uint32_t databaseOffset, size_t databaseSize,
                                   size_t binarySize);
 
-  /*
+  /**
    * Helper function that returns the log type of a log message.
    */
   LogType extractLogType(const LogMessageV2 *message) {
     return static_cast<LogType>((message->metadata & kLogTypeMask) >>
                                 kLogTypeBitOffset);
   }
+
+  /**
+   * Helper function that returns the nanoapp binary from its appId.
+   */
+  std::shared_ptr<const std::vector<uint8_t>> fetchNanoappBinary(uint64_t appId)
+      EXCLUDES(mNanoappMutex);
+
+  /**
+   * Helper function that registers a nanoapp detokenizer with its appID and
+   * instanceID.
+   */
+  void registerDetokenizer(uint64_t appId, uint16_t instanceId,
+                           pw::Result<Detokenizer> nanoappDetokenizer)
+      EXCLUDES(mNanoappMutex);
 };
 
 }  // namespace chre
diff --git a/host/common/log_message_parser.cc b/host/common/log_message_parser.cc
index 86fb55cf..2499123d 100644
--- a/host/common/log_message_parser.cc
+++ b/host/common/log_message_parser.cc
@@ -195,6 +195,7 @@ LogMessageParser::parseAndEmitTokenizedLogMessageAndGetSize(
 std::optional<size_t>
 LogMessageParser::parseAndEmitNanoappTokenizedLogMessageAndGetSize(
     const LogMessageV2 *message, size_t maxLogMessageLen) {
+  std::lock_guard<std::mutex> lock(mNanoappMutex);
   auto *tokenizedLog =
       reinterpret_cast<const NanoappTokenizedLog *>(message->logMessage);
   auto detokenizerIter = mNanoappDetokenizers.find(tokenizedLog->instanceId);
@@ -307,49 +308,67 @@ void LogMessageParser::addNanoappDetokenizer(uint64_t appId,
                                              uint16_t instanceId,
                                              uint64_t databaseOffset,
                                              size_t databaseSize) {
-  auto appBinaryIter = mNanoappAppIdToBinary.find(appId);
-  if (appBinaryIter == mNanoappAppIdToBinary.end()) {
+  std::shared_ptr<const std::vector<uint8_t>> appBinary =
+      fetchNanoappBinary(appId);
+  if (!appBinary) {
     LOGE(
         "Binary not in cache, can't extract log token database for app ID "
         "0x%016" PRIx64,
         appId);
-  } else if (databaseSize == kInvalidTokenDatabaseSize) {
-    // Remove and free the nanoapp binary.
-    mNanoappAppIdToBinary.erase(appId);
-  } else if (checkTokenDatabaseOverflow(databaseOffset, databaseSize,
-                                        appBinaryIter->second->size())) {
-    LOGE(
-        "Token database fails memory bounds check for nanoapp with app ID "
-        "0x%016" PRIx64 ". Token database offset received: %" PRIu32
-        "; size received: %zu; Size of the appBinary: %zu.",
-        appId, databaseOffset, databaseSize, appBinaryIter->second->size());
   } else {
-    const uint8_t *tokenDatabaseBinaryStart =
-        appBinaryIter->second->data() + kImageHeaderSize + databaseOffset;
-
-    pw::span<const uint8_t> tokenEntries(tokenDatabaseBinaryStart,
-                                         databaseSize);
-    pw::Result<Detokenizer> nanoappDetokenizer =
-        pw::tokenizer::Detokenizer::FromElfSection(tokenEntries);
-
-    // Clear out any stale detokenizer instance and clean up memory.
-    appBinaryIter->second.reset();
     removeNanoappDetokenizerAndBinary(appId);
-
-    if (nanoappDetokenizer.ok()) {
-      NanoappDetokenizer detokenizer;
-      detokenizer.appId = appId;
-      detokenizer.detokenizer =
-          std::make_unique<Detokenizer>(std::move(*nanoappDetokenizer));
-      mNanoappDetokenizers[instanceId] = std::move(detokenizer);
-    } else {
-      LOGE("Unable to parse log detokenizer for app with ID: 0x%016" PRIx64,
-           appId);
+    if (databaseSize != kInvalidTokenDatabaseSize) {
+      if (checkTokenDatabaseOverflow(databaseOffset, databaseSize,
+                                     appBinary->size())) {
+        LOGE(
+            "Token database fails memory bounds check for nanoapp with app ID "
+            "0x%016" PRIx64 ". Token database offset received: %" PRIu32
+            "; size received: %zu; Size of the appBinary: %zu.",
+            appId, databaseOffset, databaseSize, appBinary->size());
+      } else {
+        const uint8_t *tokenDatabaseBinaryStart =
+            appBinary->data() + kImageHeaderSize + databaseOffset;
+
+        pw::span<const uint8_t> tokenEntries(tokenDatabaseBinaryStart,
+                                             databaseSize);
+        pw::Result<Detokenizer> nanoappDetokenizer =
+            pw::tokenizer::Detokenizer::FromElfSection(tokenEntries);
+
+        registerDetokenizer(appId, instanceId, std::move(nanoappDetokenizer));
+      }
     }
   }
 }
 
+void LogMessageParser::registerDetokenizer(
+    uint64_t appId, uint16_t instanceId,
+    pw::Result<Detokenizer> nanoappDetokenizer) {
+  std::lock_guard<std::mutex> lock(mNanoappMutex);
+
+  if (nanoappDetokenizer.ok()) {
+    NanoappDetokenizer detokenizer;
+    detokenizer.appId = appId;
+    detokenizer.detokenizer =
+        std::make_unique<Detokenizer>(std::move(*nanoappDetokenizer));
+    mNanoappDetokenizers[instanceId] = std::move(detokenizer);
+  } else {
+    LOGE("Unable to parse log detokenizer for app with ID: 0x%016" PRIx64,
+         appId);
+  }
+}
+
+std::shared_ptr<const std::vector<uint8_t>>
+LogMessageParser::fetchNanoappBinary(uint64_t appId) {
+  std::lock_guard<std::mutex> lock(mNanoappMutex);
+  auto appBinaryIter = mNanoappAppIdToBinary.find(appId);
+  if (appBinaryIter != mNanoappAppIdToBinary.end()) {
+    return appBinaryIter->second;
+  }
+  return nullptr;
+}
+
 void LogMessageParser::removeNanoappDetokenizerAndBinary(uint64_t appId) {
+  std::lock_guard<std::mutex> lock(mNanoappMutex);
   for (const auto &item : mNanoappDetokenizers) {
     if (item.second.appId == appId) {
       mNanoappDetokenizers.erase(item.first);
@@ -359,12 +378,14 @@ void LogMessageParser::removeNanoappDetokenizerAndBinary(uint64_t appId) {
 }
 
 void LogMessageParser::resetNanoappDetokenizerState() {
+  std::lock_guard<std::mutex> lock(mNanoappMutex);
   mNanoappDetokenizers.clear();
   mNanoappAppIdToBinary.clear();
 }
 
 void LogMessageParser::onNanoappLoadStarted(
     uint64_t appId, std::shared_ptr<const std::vector<uint8_t>> nanoappBinary) {
+  std::lock_guard<std::mutex> lock(mNanoappMutex);
   mNanoappAppIdToBinary[appId] = nanoappBinary;
 }
 
diff --git a/host/common/test/power_test/chre_power_test_client.cc b/host/common/test/power_test/chre_power_test_client.cc
index 1251e998..c68130a7 100644
--- a/host/common/test/power_test/chre_power_test_client.cc
+++ b/host/common/test/power_test/chre_power_test_client.cc
@@ -481,6 +481,7 @@ inline uint64_t getId(std::vector<string> &args) {
 const string searchPath(const string &name) {
   const string kAdspPath = "vendor/dsp/adsp/" + name;
   const string kSdspPath = "vendor/dsp/sdsp/" + name;
+  const string kEtcTestPath = "vendor/etc/chre/test/" + name;
   const string kEtcPath = "vendor/etc/chre/" + name;
 
   struct stat buf;
@@ -488,6 +489,8 @@ const string searchPath(const string &name) {
     return kAdspPath;
   } else if (stat(kSdspPath.c_str(), &buf) == 0) {
     return kSdspPath;
+  } else if (stat(kEtcTestPath.c_str(), &buf) == 0) {
+    return kEtcTestPath;
   } else {
     return kEtcPath;
   }
diff --git a/host/hal_generic/common/hal_chre_socket_connection.cc b/host/hal_generic/common/hal_chre_socket_connection.cc
index 432a36ef..4d6b7b7c 100644
--- a/host/hal_generic/common/hal_chre_socket_connection.cc
+++ b/host/hal_generic/common/hal_chre_socket_connection.cc
@@ -14,9 +14,6 @@
  * limitations under the License.
  */
 
-// TODO(b/298459533): remove_ap_wakeup_metric_report_limit ramp up -> remove old
-// code
-
 #define LOG_TAG "ContextHubHal"
 #define LOG_NDEBUG 1
 
@@ -25,13 +22,6 @@
 #include <log/log.h>
 
 #ifdef CHRE_HAL_SOCKET_METRICS_ENABLED
-// TODO(b/298459533): Remove these when the flag_log_nanoapp_load_metrics flag
-// is cleaned up
-#include <aidl/android/frameworks/stats/IStats.h>
-#include <android/binder_manager.h>
-#include <android_chre_flags.h>
-// TODO(b/298459533): Remove end
-
 #include <chre_atoms_log.h>
 #include <utils/SystemClock.h>
 #endif  // CHRE_HAL_SOCKET_METRICS_ENABLED
@@ -48,17 +38,6 @@ using ::android::chre::HostProtocolHost;
 using ::flatbuffers::FlatBufferBuilder;
 
 #ifdef CHRE_HAL_SOCKET_METRICS_ENABLED
-// TODO(b/298459533): Remove these when the flag_log_nanoapp_load_metrics flag
-// is cleaned up
-using ::aidl::android::frameworks::stats::IStats;
-using ::aidl::android::frameworks::stats::VendorAtom;
-using ::aidl::android::frameworks::stats::VendorAtomValue;
-using ::android::chre::Atoms::CHRE_AP_WAKE_UP_OCCURRED;
-using ::android::chre::Atoms::CHRE_HAL_NANOAPP_LOAD_FAILED;
-using ::android::chre::flags::flag_log_nanoapp_load_metrics;
-using ::android::chre::flags::remove_ap_wakeup_metric_report_limit;
-// TODO(b/298459533): Remove end
-
 using ::android::chre::MetricsReporter;
 using ::android::chre::Atoms::ChreHalNanoappLoadFailed;
 #endif  // CHRE_HAL_SOCKET_METRICS_ENABLED
@@ -198,13 +177,7 @@ bool HalChreSocketConnection::isLoadTransactionPending() {
 
 HalChreSocketConnection::SocketCallbacks::SocketCallbacks(
     HalChreSocketConnection &parent, IChreSocketCallback *callback)
-    : mParent(parent), mCallback(callback) {
-#ifdef CHRE_HAL_SOCKET_METRICS_ENABLED
-  if (!remove_ap_wakeup_metric_report_limit()) {
-    mLastClearedTimestamp = elapsedRealtime();
-  }
-#endif  // CHRE_HAL_SOCKET_METRICS_ENABLED
-}
+    : mParent(parent), mCallback(callback) {}
 
 void HalChreSocketConnection::SocketCallbacks::onMessageReceived(
     const void *data, size_t length) {
@@ -235,37 +208,10 @@ void HalChreSocketConnection::SocketCallbacks::handleNanoappMessage(
 #ifdef CHRE_HAL_SOCKET_METRICS_ENABLED
   if (message.woke_host) {
     // check and update the 24hour timer
-    std::lock_guard<std::mutex> lock(mNanoappWokeApCountMutex);
     long nanoappId = message.app_id;
 
-    if (!remove_ap_wakeup_metric_report_limit()) {
-      long timeElapsed = elapsedRealtime() - mLastClearedTimestamp;
-      if (timeElapsed > kOneDayinMillis) {
-        mNanoappWokeUpCount = 0;
-        mLastClearedTimestamp = elapsedRealtime();
-      }
-
-      mNanoappWokeUpCount++;
-    }
-
-    if (remove_ap_wakeup_metric_report_limit() ||
-        mNanoappWokeUpCount < kMaxDailyReportedApWakeUp) {
-      if (flag_log_nanoapp_load_metrics()) {
-        if (!mParent.mMetricsReporter.logApWakeupOccurred(nanoappId)) {
-          ALOGE("Could not log AP Wakeup metric");
-        }
-      } else {
-        // create and report the vendor atom
-        std::vector<VendorAtomValue> values(1);
-        values[0].set<VendorAtomValue::longValue>(nanoappId);
-
-        const VendorAtom atom{
-            .atomId = CHRE_AP_WAKE_UP_OCCURRED,
-            .values{std::move(values)},
-        };
-
-        mParent.reportMetric(atom);
-      }
+    if (!mParent.mMetricsReporter.logApWakeupOccurred(nanoappId)) {
+      ALOGE("Could not log AP Wakeup metric");
     }
   }
 #endif  // CHRE_HAL_SOCKET_METRICS_ENABLED
@@ -326,13 +272,11 @@ void HalChreSocketConnection::SocketCallbacks::handleLoadNanoappResponse(
 
 #ifdef CHRE_HAL_SOCKET_METRICS_ENABLED
         if (!success) {
-          if (flag_log_nanoapp_load_metrics()) {
-            if (!mParent.mMetricsReporter.logNanoappLoadFailed(
-                    transaction.getNanoappId(),
-                    ChreHalNanoappLoadFailed::TYPE_DYNAMIC,
-                    ChreHalNanoappLoadFailed::REASON_ERROR_GENERIC)) {
-              ALOGE("Could not log the nanoapp load failed metric");
-            }
+          if (!mParent.mMetricsReporter.logNanoappLoadFailed(
+                  transaction.getNanoappId(),
+                  ChreHalNanoappLoadFailed::TYPE_DYNAMIC,
+                  ChreHalNanoappLoadFailed::REASON_ERROR_GENERIC)) {
+            ALOGE("Could not log the nanoapp load failed metric");
           }
         }
 #endif  // CHRE_HAL_SOCKET_METRICS_ENABLED
@@ -390,26 +334,10 @@ bool HalChreSocketConnection::sendFragmentedLoadNanoAppRequest(
           request.fragmentId);
 
 #ifdef CHRE_HAL_SOCKET_METRICS_ENABLED
-    if (flag_log_nanoapp_load_metrics()) {
-      if (!mMetricsReporter.logNanoappLoadFailed(
-              request.appId, ChreHalNanoappLoadFailed::TYPE_DYNAMIC,
-              ChreHalNanoappLoadFailed::REASON_CONNECTION_ERROR)) {
-        ALOGE("Could not log the nanoapp load failed metric");
-      }
-    } else {
-      // create and report the vendor atom
-      std::vector<VendorAtomValue> values(3);
-      values[0].set<VendorAtomValue::longValue>(request.appId);
-      values[1].set<VendorAtomValue::intValue>(
-          ChreHalNanoappLoadFailed::TYPE_DYNAMIC);
-      values[2].set<VendorAtomValue::intValue>(
-          ChreHalNanoappLoadFailed::REASON_ERROR_GENERIC);
-
-      const VendorAtom atom{
-          .atomId = CHRE_HAL_NANOAPP_LOAD_FAILED,
-          .values{std::move(values)},
-      };
-      reportMetric(atom);
+    if (!mMetricsReporter.logNanoappLoadFailed(
+            request.appId, ChreHalNanoappLoadFailed::TYPE_DYNAMIC,
+            ChreHalNanoappLoadFailed::REASON_CONNECTION_ERROR)) {
+      ALOGE("Could not log the nanoapp load failed metric");
     }
 #endif  // CHRE_HAL_SOCKET_METRICS_ENABLED
 
@@ -421,32 +349,6 @@ bool HalChreSocketConnection::sendFragmentedLoadNanoAppRequest(
   return success;
 }
 
-#ifdef CHRE_HAL_SOCKET_METRICS_ENABLED
-// TODO(b/298459533): Remove this the flag_log_nanoapp_load_metrics flag is
-// cleaned up
-void HalChreSocketConnection::reportMetric(const VendorAtom atom) {
-  const std::string statsServiceName =
-      std::string(IStats::descriptor).append("/default");
-  if (!AServiceManager_isDeclared(statsServiceName.c_str())) {
-    ALOGE("Stats service is not declared.");
-    return;
-  }
-
-  std::shared_ptr<IStats> stats_client = IStats::fromBinder(ndk::SpAIBinder(
-      AServiceManager_waitForService(statsServiceName.c_str())));
-  if (stats_client == nullptr) {
-    ALOGE("Failed to get IStats service");
-    return;
-  }
-
-  const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(atom);
-  if (!ret.isOk()) {
-    ALOGE("Failed to report vendor atom");
-  }
-}
-// TODO(b/298459533): Remove end
-#endif  // CHRE_HAL_SOCKET_METRICS_ENABLED
-
 }  // namespace implementation
 }  // namespace common
 }  // namespace contexthub
diff --git a/host/hal_generic/common/hal_chre_socket_connection.h b/host/hal_generic/common/hal_chre_socket_connection.h
index 417638c6..5a3be438 100644
--- a/host/hal_generic/common/hal_chre_socket_connection.h
+++ b/host/hal_generic/common/hal_chre_socket_connection.h
@@ -160,14 +160,6 @@ class HalChreSocketConnection {
     HalChreSocketConnection &mParent;
     IChreSocketCallback *mCallback = nullptr;
     bool mHaveConnected = false;
-
-#ifdef CHRE_HAL_SOCKET_METRICS_ENABLED
-    long mLastClearedTimestamp = 0;
-    static constexpr uint32_t kOneDayinMillis = 24 * 60 * 60 * 1000;
-    static constexpr uint16_t kMaxDailyReportedApWakeUp = 200;
-    uint16_t mNanoappWokeUpCount = 0;
-    std::mutex mNanoappWokeApCountMutex;
-#endif  // CHRE_HAL_SOCKET_METRICS_ENABLED
   };
 
   sp<SocketCallbacks> mSocketCallbacks;
@@ -211,18 +203,6 @@ class HalChreSocketConnection {
    */
   bool sendFragmentedLoadNanoAppRequest(
       chre::FragmentedLoadTransaction &transaction);
-
-#ifdef CHRE_HAL_SOCKET_METRICS_ENABLED
-  // TODO(b/298459533): Remove this when the flag_log_nanoapp_load_metrics flag
-  // is cleaned up
-  /**
-   * Create and report CHRE vendor atom and send it to stats_client
-   *
-   * @param atom the vendor atom to be reported
-   */
-  void reportMetric(const aidl::android::frameworks::stats::VendorAtom atom);
-#endif  // CHRE_HAL_SOCKET_METRICS_ENABLED
-  // TODO(b/298459533): Remove end
 };
 
 }  // namespace implementation
diff --git a/host/hal_generic/common/hal_client_manager.cc b/host/hal_generic/common/hal_client_manager.cc
index d281503a..ec75fdc4 100644
--- a/host/hal_generic/common/hal_client_manager.cc
+++ b/host/hal_generic/common/hal_client_manager.cc
@@ -435,15 +435,15 @@ void HalClientManager::sendMessageForAllCallbacks(
   }
 }
 
-const std::unordered_set<HostEndpointId>
-    *HalClientManager::getAllConnectedEndpoints(pid_t pid) {
+std::optional<std::unordered_set<HostEndpointId>>
+HalClientManager::getAllConnectedEndpoints(pid_t pid) {
   const std::lock_guard<std::mutex> lock(mLock);
   const Client *client = getClientByProcessId(pid);
   if (client == nullptr) {
     LOGE("Unknown HAL client with pid %d", pid);
-    return nullptr;
+    return {};
   }
-  return &(client->endpointIds);
+  return client->endpointIds;
 }
 
 bool HalClientManager::mutateEndpointIdFromHostIfNeeded(
@@ -544,9 +544,6 @@ std::optional<int64_t> HalClientManager::resetPendingUnloadTransaction(
   if (isPendingTransactionMatched(clientId, transactionId,
                                   mPendingUnloadTransaction)) {
     int64_t nanoappId = mPendingUnloadTransaction->nanoappId;
-    LOGI("Clears out the pending unload transaction for nanoapp 0x%" PRIx64
-         ": client id %" PRIu16 ", transaction id %" PRIu32,
-         nanoappId, clientId, transactionId);
     mPendingUnloadTransaction.reset();
     return nanoappId;
   }
diff --git a/host/hal_generic/common/hal_client_manager.h b/host/hal_generic/common/hal_client_manager.h
index 1a2fefce..0073da2c 100644
--- a/host/hal_generic/common/hal_client_manager.h
+++ b/host/hal_generic/common/hal_client_manager.h
@@ -24,6 +24,7 @@
 
 #include <sys/types.h>
 #include <cstddef>
+#include <optional>
 #include <unordered_map>
 #include <unordered_set>
 #include <utility>
@@ -307,10 +308,11 @@ class HalClientManager {
   /**
    * Gets all the connected endpoints for the client identified by the @p pid.
    *
-   * @return the pointer to the endpoint id set if the client is identifiable,
-   * otherwise nullptr.
+   * @return copy of the endpoint id set if the client is identifiable,
+   * otherwise empty optional.
    */
-  const std::unordered_set<HostEndpointId> *getAllConnectedEndpoints(pid_t pid);
+  std::optional<std::unordered_set<HostEndpointId>> getAllConnectedEndpoints(
+      pid_t pid);
 
   /** Sends a message to every connected endpoints. */
   void sendMessageForAllCallbacks(
diff --git a/host/hal_generic/common/multi_client_context_hub_base.cc b/host/hal_generic/common/multi_client_context_hub_base.cc
index 400107e5..8eb92eb6 100644
--- a/host/hal_generic/common/multi_client_context_hub_base.cc
+++ b/host/hal_generic/common/multi_client_context_hub_base.cc
@@ -29,6 +29,7 @@
 
 #include <android_chre_flags.h>
 #include <system/chre/core/chre_metrics.pb.h>
+#include <chrono>
 
 namespace android::hardware::contexthub::common::implementation {
 
@@ -37,6 +38,7 @@ using ::android::chre::FragmentedLoadTransaction;
 using ::android::chre::getStringFromByteVector;
 using ::android::chre::Atoms::ChreHalNanoappLoadFailed;
 using ::android::chre::flags::abort_if_no_context_hub_found;
+using ::android::chre::flags::bug_fix_hal_reliable_message_record;
 using ::android::chre::flags::reliable_message_implementation;
 using ::ndk::ScopedAStatus;
 namespace fbs = ::chre::fbs;
@@ -133,6 +135,7 @@ ErrorCode toErrorCode(uint32_t chreErrorCode) {
   switch (chreErrorCode) {
     case CHRE_ERROR_NONE:
       return ErrorCode::OK;
+    case CHRE_ERROR_BUSY: // fallthrough
     case CHRE_ERROR_TRANSIENT:
       return ErrorCode::TRANSIENT_ERROR;
     case CHRE_ERROR:
@@ -200,7 +203,7 @@ ScopedAStatus MultiClientContextHubBase::loadNanoapp(
   if (!isValidContextHubId(contextHubId)) {
     return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
   }
-  LOGI("Loading nanoapp 0x%" PRIx64, appBinary.nanoappId);
+  LOGD("Loading nanoapp 0x%" PRIx64, appBinary.nanoappId);
   uint32_t targetApiVersion = (appBinary.targetChreApiMajorVersion << 24) |
                               (appBinary.targetChreApiMinorVersion << 16);
   auto nanoappBuffer =
@@ -260,7 +263,7 @@ ScopedAStatus MultiClientContextHubBase::unloadNanoapp(int32_t contextHubId,
                                                            appId)) {
     return fromResult(false);
   }
-  LOGI("Unloading nanoapp 0x%" PRIx64, appId);
+  LOGD("Unloading nanoapp 0x%" PRIx64, appId);
   HalClientId clientId = mHalClientManager->getClientId(pid);
   flatbuffers::FlatBufferBuilder builder(64);
   HostProtocolHost::encodeUnloadNanoappRequest(
@@ -270,6 +273,9 @@ ScopedAStatus MultiClientContextHubBase::unloadNanoapp(int32_t contextHubId,
 
   bool result = mConnection->sendMessage(builder);
   if (!result) {
+    LOGE("Failed to send an unload request for nanoapp 0x%" PRIx64
+         " transaction %" PRIi32,
+         appId, transactionId);
     mHalClientManager->resetPendingUnloadTransaction(clientId, transactionId);
   }
   return fromResult(result);
@@ -411,7 +417,25 @@ ScopedAStatus MultiClientContextHubBase::sendMessageToHub(
   }
 
   if (reliable_message_implementation() && message.isReliable) {
-    mReliableMessageMap.insert({message.messageSequenceNumber, hostEndpointId});
+    if (bug_fix_hal_reliable_message_record()) {
+      std::lock_guard<std::mutex> lock(mReliableMessageMutex);
+      auto iter = std::find_if(
+          mReliableMessageQueue.begin(), mReliableMessageQueue.end(),
+          [&message](const ReliableMessageRecord &record) {
+            return record.messageSequenceNumber == message.messageSequenceNumber;
+          });
+      if (iter == mReliableMessageQueue.end()) {
+        mReliableMessageQueue.push_back(ReliableMessageRecord{
+            .timestamp = std::chrono::steady_clock::now(),
+            .messageSequenceNumber = message.messageSequenceNumber,
+            .hostEndpointId = hostEndpointId});
+        std::push_heap(mReliableMessageQueue.begin(), mReliableMessageQueue.end(),
+                      std::greater<ReliableMessageRecord>());
+      }
+      cleanupReliableMessageQueueLocked();
+    } else {
+      mReliableMessageMap.insert({message.messageSequenceNumber, hostEndpointId});
+    }
   }
 
   flatbuffers::FlatBufferBuilder builder(1024);
@@ -546,7 +570,7 @@ bool MultiClientContextHubBase::enableTestMode() {
   // Unload each nanoapp.
   // mTestModeNanoapps tracks nanoapps that are actually unloaded. Removing an
   // element from std::vector is O(n) but such a removal should rarely happen.
-  LOGI("Trying to unload %" PRIu64 " nanoapps to enable test mode",
+  LOGD("Trying to unload %" PRIu64 " nanoapps to enable test mode",
        mTestModeNanoapps->size());
   for (auto iter = mTestModeNanoapps->begin();
        iter != mTestModeNanoapps->end();) {
@@ -577,7 +601,7 @@ bool MultiClientContextHubBase::enableTestMode() {
     mEventLogger.logNanoappUnload(appId, success);
   }
 
-  LOGI("%" PRIu64 " nanoapps are unloaded to enable test mode",
+  LOGD("%" PRIu64 " nanoapps are unloaded to enable test mode",
        mTestModeNanoapps->size());
   mIsTestModeEnabled = true;
   mTestModeNanoapps.emplace();
@@ -591,7 +615,7 @@ void MultiClientContextHubBase::disableTestMode() {
   }
   int numOfNanoappsLoaded =
       mPreloadedNanoappLoader->loadPreloadedNanoapps(mTestModeSystemNanoapps);
-  LOGI("%d nanoapps are reloaded to recover from test mode",
+  LOGD("%d nanoapps are reloaded to recover from test mode",
        numOfNanoappsLoaded);
   mIsTestModeEnabled = false;
 }
@@ -714,6 +738,7 @@ void MultiClientContextHubBase::onDebugDumpComplete(
 
 void MultiClientContextHubBase::onNanoappListResponse(
     const fbs::NanoappListResponseT &response, HalClientId clientId) {
+  LOGD("Received a nanoapp list response for client %" PRIu16, clientId);
   {
     std::unique_lock<std::mutex> lock(mTestModeMutex);
     if (!mTestModeNanoapps.has_value()) {
@@ -843,6 +868,10 @@ void MultiClientContextHubBase::onNanoappUnloadResponse(
     mEventLogger.logNanoappUnload(*nanoappId, response.success);
     if (auto callback = mHalClientManager->getCallback(clientId);
         callback != nullptr) {
+      LOGD("Unload transaction %" PRIu32 " for nanoapp 0x%" PRIx64
+           " client id %" PRIu16 " is finished: %s",
+           response.transaction_id, *nanoappId, clientId,
+           response.success ? "success" : "failure");
       callback->handleTransactionResult(response.transaction_id,
                                         /* in_success= */ response.success);
     }
@@ -869,7 +898,15 @@ void MultiClientContextHubBase::onNanoappMessage(
     outMessage.messageSequenceNumber = 0;
   }
 
-  auto messageContentPerms =
+  std::string messageSeq = "reliable message seq=" +
+                           std::to_string(outMessage.messageSequenceNumber);
+  LOGD("Received a nanoapp message from 0x%" PRIx64 " endpoint 0x%" PRIx16
+       ": Type 0x%" PRIx32 " size %zu %s",
+       outMessage.nanoappId, outMessage.hostEndPoint, outMessage.messageType,
+       outMessage.messageBody.size(),
+       outMessage.isReliable ? messageSeq.c_str() : "");
+
+  std::vector<std::string> messageContentPerms =
       chreToAndroidPermissions(message.message_permissions);
   // broadcast message is sent to every connected endpoint
   if (message.host_endpoint == CHRE_HOST_ENDPOINT_BROADCAST) {
@@ -894,18 +931,41 @@ void MultiClientContextHubBase::onMessageDeliveryStatus(
     return;
   }
 
-  auto hostEndpointIdIter =
-      mReliableMessageMap.find(status.message_sequence_number);
-  if (hostEndpointIdIter == mReliableMessageMap.end()) {
-    LOGE(
-        "Unable to get the host endpoint ID for message sequence "
-        "number: %" PRIu32,
-        status.message_sequence_number);
-    return;
+  HostEndpointId hostEndpointId;
+  if (bug_fix_hal_reliable_message_record()) {
+    {
+      std::lock_guard<std::mutex> lock(mReliableMessageMutex);
+      auto iter = std::find_if(
+          mReliableMessageQueue.begin(), mReliableMessageQueue.end(),
+          [&status](const ReliableMessageRecord &record) {
+            return record.messageSequenceNumber == status.message_sequence_number;
+          });
+      if (iter == mReliableMessageQueue.end()) {
+        LOGE(
+            "Unable to get the host endpoint ID for message "
+            "sequence number: %" PRIu32,
+            status.message_sequence_number);
+        return;
+      }
+
+      hostEndpointId = iter->hostEndpointId;
+      cleanupReliableMessageQueueLocked();
+    }
+  } else {
+    auto hostEndpointIdIter =
+        mReliableMessageMap.find(status.message_sequence_number);
+    if (hostEndpointIdIter == mReliableMessageMap.end()) {
+      LOGE(
+          "Unable to get the host endpoint ID for message sequence "
+          "number: %" PRIu32,
+          status.message_sequence_number);
+      return;
+    }
+
+    hostEndpointId = hostEndpointIdIter->second;
+    mReliableMessageMap.erase(hostEndpointIdIter);
   }
 
-  HostEndpointId hostEndpointId = hostEndpointIdIter->second;
-  mReliableMessageMap.erase(hostEndpointIdIter);
   std::shared_ptr<IContextHubCallback> callback =
       mHalClientManager->getCallbackForEndpoint(hostEndpointId);
   if (callback == nullptr) {
@@ -930,7 +990,7 @@ void MultiClientContextHubBase::handleClientDeath(pid_t clientPid) {
   LOGI("Process %d is dead. Cleaning up.", clientPid);
   if (auto endpoints = mHalClientManager->getAllConnectedEndpoints(clientPid)) {
     for (auto endpointId : *endpoints) {
-      LOGI("Sending message to remove endpoint 0x%" PRIx16, endpointId);
+      LOGD("Sending message to remove endpoint 0x%" PRIx16, endpointId);
       if (!mHalClientManager->mutateEndpointIdFromHostIfNeeded(clientPid,
                                                                endpointId)) {
         continue;
@@ -1058,4 +1118,14 @@ void MultiClientContextHubBase::onMetricLog(
   // Reached here only if an error has occurred for a known metric id.
   LOGE("Failed to parse metric data with id %" PRIu32, metricMessage.id);
 }
+
+void MultiClientContextHubBase::cleanupReliableMessageQueueLocked() {
+  while (!mReliableMessageQueue.empty() &&
+         mReliableMessageQueue.front().isExpired()) {
+    std::pop_heap(mReliableMessageQueue.begin(), mReliableMessageQueue.end(),
+                  std::greater<ReliableMessageRecord>());
+    mReliableMessageQueue.pop_back();
+  }
+}
+
 }  // namespace android::hardware::contexthub::common::implementation
diff --git a/host/hal_generic/common/multi_client_context_hub_base.h b/host/hal_generic/common/multi_client_context_hub_base.h
index 29185bb2..c596089e 100644
--- a/host/hal_generic/common/multi_client_context_hub_base.h
+++ b/host/hal_generic/common/multi_client_context_hub_base.h
@@ -31,6 +31,12 @@
 #include "hal_client_id.h"
 #include "hal_client_manager.h"
 
+#include <chrono>
+#include <deque>
+#include <mutex>
+#include <optional>
+#include <unordered_map>
+
 namespace android::hardware::contexthub::common::implementation {
 
 using namespace aidl::android::hardware::contexthub;
@@ -95,6 +101,10 @@ class MultiClientContextHubBase
   void writeToDebugFile(const char *str) override;
 
  protected:
+  // The timeout for a reliable message.
+  constexpr static std::chrono::nanoseconds kReliableMessageTimeout =
+      std::chrono::seconds(1);
+
   // The data needed by the death client to clear states of a client.
   struct HalDeathRecipientCookie {
     MultiClientContextHubBase *hal;
@@ -105,6 +115,22 @@ class MultiClientContextHubBase
     }
   };
 
+  // Contains information about a reliable message that has been received.
+  struct ReliableMessageRecord {
+    std::chrono::time_point<std::chrono::steady_clock> timestamp;
+    int32_t messageSequenceNumber;
+    HostEndpointId hostEndpointId;
+
+    bool isExpired() const {
+      return timestamp + kReliableMessageTimeout <
+             std::chrono::steady_clock::now();
+    }
+
+    bool operator>(const ReliableMessageRecord &other) const {
+      return timestamp > other.timestamp;
+    }
+  };
+
   void tryTimeSync(size_t numOfRetries, useconds_t retryDelayUs) {
     if (mConnection->isTimeSyncNeeded()) {
       TimeSyncer::sendTimeSyncWithRetry(mConnection.get(), numOfRetries,
@@ -156,6 +182,12 @@ class MultiClientContextHubBase
            mSettingEnabled[setting];
   }
 
+  /**
+   * Removes messages from the reliable message queue that have been received
+   * by the host more than kReliableMessageTimeout ago.
+   */
+  void cleanupReliableMessageQueueLocked();
+
   HalClientManager::DeadClientUnlinker mDeadClientUnlinker;
 
   // HAL is the unique owner of the communication channel to CHRE.
@@ -207,6 +239,10 @@ class MultiClientContextHubBase
   std::unique_ptr<MetricsReporter> mMetricsReporter;
 
   // Used to map message sequence number to host endpoint ID
+  std::mutex mReliableMessageMutex;
+  std::deque<ReliableMessageRecord> mReliableMessageQueue;
+
+  // TODO(b/333567700): Remove when cleaning up the bug_fix_hal_reliable_message_record flag
   std::unordered_map<int32_t, HostEndpointId> mReliableMessageMap;
 };
 }  // namespace android::hardware::contexthub::common::implementation
diff --git a/host/test/hal_generic/common/hal_client_manager_test.cc b/host/test/hal_generic/common/hal_client_manager_test.cc
index c79fd184..e40e249d 100644
--- a/host/test/hal_generic/common/hal_client_manager_test.cc
+++ b/host/test/hal_generic/common/hal_client_manager_test.cc
@@ -18,6 +18,7 @@
 #include <chrono>
 #include <cstdlib>
 #include <fstream>
+#include <optional>
 #include <thread>
 
 #include <json/json.h>
@@ -44,7 +45,9 @@ using ndk::ScopedAStatus;
 
 using ::testing::_;
 using ::testing::ByMove;
+using ::testing::Eq;
 using ::testing::IsEmpty;
+using ::testing::Optional;
 using ::testing::Return;
 using ::testing::SizeIs;
 using ::testing::UnorderedElementsAre;
@@ -402,6 +405,8 @@ TEST_F(HalClientManagerTest, EndpointRegistry) {
   std::shared_ptr<ContextHubCallbackForTest> vendorCallback =
       ContextHubCallbackForTest::make<ContextHubCallbackForTest>(kVendorUuid);
 
+  EXPECT_THAT(halClientManager->getAllConnectedEndpoints(kSystemServerPid),
+              Eq(std::nullopt));
   halClientManager->registerCallback(kSystemServerPid, systemCallback,
                                      /* deathRecipientCookie= */ nullptr);
   halClientManager->registerCallback(kVendorPid, vendorCallback,
@@ -409,14 +414,23 @@ TEST_F(HalClientManagerTest, EndpointRegistry) {
 
   std::vector<HalClient> clients = halClientManager->getClients();
   EXPECT_THAT(clients, SizeIs(2));
-  // only system server can register endpoint ids > 63.
+  EXPECT_THAT(halClientManager->getAllConnectedEndpoints(kSystemServerPid),
+              Optional(IsEmpty()));
+  EXPECT_THAT(halClientManager->getAllConnectedEndpoints(kVendorPid),
+              Optional(IsEmpty()));
 
+  // only system server can register endpoint ids > 63.
   EXPECT_TRUE(halClientManager->registerEndpointId(kSystemServerPid,
                                                    /* endpointId= */ 64));
+  EXPECT_THAT(halClientManager->getAllConnectedEndpoints(kSystemServerPid),
+              Optional(UnorderedElementsAre(64)));
+
   EXPECT_TRUE(halClientManager->registerEndpointId(kVendorPid,
                                                    /*endpointId= */ 63));
   EXPECT_FALSE(halClientManager->registerEndpointId(kVendorPid,
                                                     /* endpointId= */ 64));
+  EXPECT_THAT(halClientManager->getAllConnectedEndpoints(kVendorPid),
+              Optional(UnorderedElementsAre(63)));
 }
 
 TEST_F(HalClientManagerTest, EndpointIdMutationForVendorClient) {
diff --git a/host/test/hal_generic/common/hal_client_test.cc b/host/test/hal_generic/common/hal_client_test.cc
index 3dddeee1..ed3fb6f7 100644
--- a/host/test/hal_generic/common/hal_client_test.cc
+++ b/host/test/hal_generic/common/hal_client_test.cc
@@ -52,6 +52,7 @@ class HalClientForTest : public HalClient {
                        ndk::SharedRefBase::make<IContextHubCallbackDefault>())
       : HalClient(callback) {
     mContextHub = contextHub;
+    mIsHalConnected = contextHub != nullptr;
     for (const HostEndpointId &endpointId : connectedEndpoints) {
       mConnectedEndpoints[endpointId] = {.hostEndpointId = endpointId};
     }
diff --git a/host/tinysys/hal/Android.bp b/host/tinysys/hal/Android.bp
index 9aced71f..dc7e51d4 100644
--- a/host/tinysys/hal/Android.bp
+++ b/host/tinysys/hal/Android.bp
@@ -15,14 +15,16 @@
 
 package {
     default_team: "trendy_team_context_hub",
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "system_chre_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
     default_applicable_licenses: ["system_chre_license"],
 }
 
+// The rc and xml files are removed from the definition of
+// android.hardware.contexthub-service.tinysys to accommodate the various
+// needs of tinysys platform setup scenarios. These files can be installed
+// back by adding items below:
+//
+//   init_rc: ["android.hardware.contexthub-service.tinysys.rc"],
+//   vintf_fragments: ["android.hardware.contexthub-service.tinysys.xml"],
 cc_binary {
     name: "android.hardware.contexthub-service.tinysys",
     cpp_std: "c++20",
@@ -43,7 +45,6 @@ cc_binary {
         "system/chre/platform/shared/include/",
         "system/chre/util/include/",
     ],
-    init_rc: ["android.hardware.contexthub-service.tinysys.rc"],
     cflags: [
         "-DCHRE_HOST_DEFAULT_FRAGMENT_SIZE=2048",
         "-DCHRE_IS_HOST_BUILD",
@@ -59,6 +60,7 @@ cc_binary {
         "android.media.soundtrigger.types-V1-ndk",
         "chre_atoms_log",
         "chremetrics-cpp",
+        "libaconfig_storage_read_api_cc",
         "libbase",
         "libbinder_ndk",
         "libcutils",
@@ -68,7 +70,6 @@ cc_binary {
         "libprotobuf-cpp-lite",
         "libutils",
         "server_configurable_flags",
-        "libaconfig_storage_read_api_cc",
     ],
     header_libs: [
         "chre_api",
@@ -83,5 +84,4 @@ cc_binary {
         "pw_span",
         "pw_varint",
     ],
-    vintf_fragments: ["android.hardware.contexthub-service.tinysys.xml"],
 }
diff --git a/java/test/ble_concurrency/src/com/google/android/chre/test/bleconcurrency/ContextHubBleConcurrencyTestExecutor.java b/java/test/ble_concurrency/src/com/google/android/chre/test/bleconcurrency/ContextHubBleConcurrencyTestExecutor.java
index cd1db4d9..10187ba3 100644
--- a/java/test/ble_concurrency/src/com/google/android/chre/test/bleconcurrency/ContextHubBleConcurrencyTestExecutor.java
+++ b/java/test/ble_concurrency/src/com/google/android/chre/test/bleconcurrency/ContextHubBleConcurrencyTestExecutor.java
@@ -46,7 +46,7 @@ public class ContextHubBleConcurrencyTestExecutor extends ContextHubBleTestExecu
      */
     private void testHostScanFirst() throws Exception {
         startBleScanOnHost();
-        chreBleStartScanSync(getDefaultScanFilter());
+        chreBleStartScanSync(getServiceDataScanFilterChre());
         Thread.sleep(1000);
         chreBleStopScanSync();
         stopBleScanOnHost();
@@ -56,7 +56,7 @@ public class ContextHubBleConcurrencyTestExecutor extends ContextHubBleTestExecu
      * Tests with CHRE starting scanning first.
      */
     private void testChreScanFirst() throws Exception {
-        chreBleStartScanSync(getDefaultScanFilter());
+        chreBleStartScanSync(getServiceDataScanFilterChre());
         startBleScanOnHost();
         Thread.sleep(1000);
         stopBleScanOnHost();
diff --git a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubBleTestExecutor.java b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubBleTestExecutor.java
index cdb0e98d..e8d30777 100644
--- a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubBleTestExecutor.java
+++ b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubBleTestExecutor.java
@@ -86,6 +86,11 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
      */
     public static final int CHRE_BLE_AD_TYPE_SERVICE_DATA_WITH_UUID_16 = 0x16;
 
+    /**
+     * The advertisement type for manufacturer data.
+     */
+    public static final int CHRE_BLE_AD_TYPE_MANUFACTURER_DATA = 0xFF;
+
     /**
      * The BLE advertisement event ID.
      */
@@ -97,6 +102,11 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
     public static final int CHRE_BLE_CAPABILITIES_SCAN = 1 << 0;
     public static final int CHRE_BLE_FILTER_CAPABILITIES_SERVICE_DATA = 1 << 7;
 
+    /**
+     * CHRE BLE test manufacturer ID.
+     */
+    private static final int CHRE_BLE_TEST_MANUFACTURER_ID = 0xEEEE;
+
     private BluetoothAdapter mBluetoothAdapter = null;
     private BluetoothLeAdvertiser mBluetoothLeAdvertiser = null;
     private BluetoothLeScanner mBluetoothLeScanner = null;
@@ -216,11 +226,30 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
         return builder.build();
     }
 
+    /**
+     * Generates a BLE scan filter that filters only for the CHRE test manufacturer ID.
+     */
+    public static ChreApiTest.ChreBleScanFilter getManufacturerDataScanFilterChre() {
+        ChreApiTest.ChreBleScanFilter.Builder builder =
+                ChreApiTest.ChreBleScanFilter.newBuilder()
+                        .setRssiThreshold(RSSI_THRESHOLD);
+        ChreApiTest.ChreBleGenericFilter manufacturerFilter =
+                ChreApiTest.ChreBleGenericFilter.newBuilder()
+                        .setType(CHRE_BLE_AD_TYPE_MANUFACTURER_DATA)
+                        .setLength(2)
+                        .setData(ByteString.copyFrom(HexFormat.of().parseHex("EEEE")))
+                        .setMask(ByteString.copyFrom(HexFormat.of().parseHex("FFFF")))
+                        .build();
+        builder = builder.addScanFilters(manufacturerFilter);
+
+        return builder.build();
+    }
+
     /**
      * Generates a BLE scan filter that filters only for the known Google beacons:
      * Google Eddystone and Nearby Fastpair.
      */
-    public static ChreApiTest.ChreBleScanFilter getDefaultScanFilter() {
+    public static ChreApiTest.ChreBleScanFilter getServiceDataScanFilterChre() {
         return getDefaultScanFilter(true /* useEddystone */, true /* useNearbyFastpair */);
     }
 
@@ -236,7 +265,7 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
      * Google Eddystone and Nearby Fastpair. We specify the filter data in (little-endian) LE
      * here as the CHRE code will take BE input and transform it to LE.
      */
-    public static List<ScanFilter> getDefaultScanFilterHost() {
+    public static List<ScanFilter> getServiceDataScanFilterHost() {
         assertThat(CHRE_BLE_AD_TYPE_SERVICE_DATA_WITH_UUID_16)
                 .isEqualTo(ScanRecord.DATA_TYPE_SERVICE_DATA_16_BIT);
 
@@ -256,6 +285,24 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
         return ImmutableList.of(scanFilter, scanFilter2);
     }
 
+    /**
+     * Generates a BLE scan filter that filters only for the known CHRE test specific
+     * manufacturer ID.
+     */
+    public static List<ScanFilter> getManufacturerDataScanFilterHost() {
+        assertThat(CHRE_BLE_AD_TYPE_MANUFACTURER_DATA)
+                .isEqualTo(ScanRecord.DATA_TYPE_MANUFACTURER_SPECIFIC_DATA);
+
+        ScanFilter scanFilter = new ScanFilter.Builder()
+                .setAdvertisingDataTypeWithData(
+                        ScanRecord.DATA_TYPE_MANUFACTURER_SPECIFIC_DATA,
+                        ByteString.copyFrom(HexFormat.of().parseHex("EEEE")).toByteArray(),
+                        ByteString.copyFrom(HexFormat.of().parseHex("FFFF")).toByteArray())
+                .build();
+
+        return ImmutableList.of(scanFilter);
+    }
+
     /**
      * Starts a BLE scan and asserts it was started successfully in a synchronous manner.
      * This waits for the event to be received and returns the status in the event.
@@ -337,7 +384,7 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
                 .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                 .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                 .build();
-        mBluetoothLeScanner.startScan(getDefaultScanFilterHost(),
+        mBluetoothLeScanner.startScan(getServiceDataScanFilterHost(),
                 scanSettings, mScanCallback);
     }
 
@@ -356,7 +403,7 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
             return;
         }
 
-        AdvertisingSetParameters parameters = (new AdvertisingSetParameters.Builder())
+        AdvertisingSetParameters parameters = new AdvertisingSetParameters.Builder()
                 .setLegacyMode(true)
                 .setConnectable(false)
                 .setInterval(AdvertisingSetParameters.INTERVAL_HIGH)
@@ -370,15 +417,44 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
                 .build();
 
         mBluetoothLeAdvertiser.startAdvertisingSet(parameters, data,
-                null, null, null, mAdvertisingSetCallback);
+                /* ownAddress= */ null, /* periodicParameters= */ null,
+                /* periodicData= */ null, mAdvertisingSetCallback);
+        mAdvertisingStartLatch.await();
+        assertThat(mIsAdvertising.get()).isTrue();
+    }
+
+    /**
+     * Starts broadcasting the CHRE test manufacturer Data from the AP.
+     */
+    public void startBleAdvertisingManufacturer() throws InterruptedException {
+        if (mIsAdvertising.get()) {
+            return;
+        }
+
+        AdvertisingSetParameters parameters = new AdvertisingSetParameters.Builder()
+                .setLegacyMode(true)
+                .setConnectable(false)
+                .setInterval(AdvertisingSetParameters.INTERVAL_HIGH)
+                .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_HIGH)
+                .build();
+
+        AdvertiseData data = new AdvertiseData.Builder()
+                .addManufacturerData(CHRE_BLE_TEST_MANUFACTURER_ID, new byte[] {0})
+                .setIncludeDeviceName(false)
+                .setIncludeTxPowerLevel(true)
+                .build();
+
+        mBluetoothLeAdvertiser.startAdvertisingSet(parameters, data,
+                /* ownAddress= */ null, /* periodicParameters= */ null,
+                /* periodicData= */ null, mAdvertisingSetCallback);
         mAdvertisingStartLatch.await();
         assertThat(mIsAdvertising.get()).isTrue();
     }
 
     /**
-     * Stops advertising Google Eddystone from the AP.
+     * Stops advertising data from the AP.
      */
-    public void stopBleAdvertisingGoogleEddystone() throws InterruptedException {
+    public void stopBleAdvertising() throws InterruptedException {
         if (!mIsAdvertising.get()) {
             return;
         }
diff --git a/java/test/chqts/src/com/google/android/chre/test/chqts/multidevice/ContextHubMultiDeviceBleBeaconTestExecutor.java b/java/test/chqts/src/com/google/android/chre/test/chqts/multidevice/ContextHubMultiDeviceBleBeaconTestExecutor.java
index 19f04915..c1ada3d2 100644
--- a/java/test/chqts/src/com/google/android/chre/test/chqts/multidevice/ContextHubMultiDeviceBleBeaconTestExecutor.java
+++ b/java/test/chqts/src/com/google/android/chre/test/chqts/multidevice/ContextHubMultiDeviceBleBeaconTestExecutor.java
@@ -34,6 +34,12 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
 
     private static final long TIMEOUT_IN_NS = TIMEOUT_IN_S * 1000000000L;
 
+    /**
+     * The minimum offset in bytes of a BLE advertisement report which includes the length
+     * and type of the report.
+     */
+    private static final int BLE_ADVERTISEMENT_DATA_HEADER_OFFSET = 2;
+
     public ContextHubMultiDeviceBleBeaconTestExecutor(NanoAppBinary nanoapp) {
         super(nanoapp);
     }
@@ -45,19 +51,45 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
      * there is at least one advertisement, otherwise it returns false.
      */
     public boolean gatherAndVerifyChreBleAdvertisementsForGoogleEddystone() throws Exception {
-        Future<List<ChreApiTest.GeneralEventsMessage>> eventsFuture =
-                new ChreApiTestUtil().gatherEvents(
-                        mRpcClients.get(0),
-                        Arrays.asList(CHRE_EVENT_BLE_ADVERTISEMENT),
-                        NUM_EVENTS_TO_GATHER,
-                        TIMEOUT_IN_NS);
+        List<ChreApiTest.GeneralEventsMessage> events = gatherChreBleEvents();
+        if (events == null) {
+            return false;
+        }
 
-        List<ChreApiTest.GeneralEventsMessage> events = eventsFuture.get();
+        for (ChreApiTest.GeneralEventsMessage event: events) {
+            if (!event.hasChreBleAdvertisementEvent()) {
+                continue;
+            }
+
+            ChreApiTest.ChreBleAdvertisementEvent bleAdvertisementEvent =
+                    event.getChreBleAdvertisementEvent();
+            for (int i = 0; i < bleAdvertisementEvent.getReportsCount(); ++i) {
+                ChreApiTest.ChreBleAdvertisingReport report = bleAdvertisementEvent.getReports(i);
+                byte[] data = report.getData().toByteArray();
+                if (data == null || data.length < BLE_ADVERTISEMENT_DATA_HEADER_OFFSET) {
+                    continue;
+                }
+
+                if (searchForGoogleEddystoneAdvertisement(data)) {
+                    return true;
+                }
+            }
+        }
+        return false;
+    }
+
+    /**
+     * Gathers BLE advertisement events from the nanoapp for TIMEOUT_IN_NS or up to
+     * NUM_EVENTS_TO_GATHER events. This function returns true if all
+     * chreBleAdvertisingReport's contain advertisments with CHRE test manufacturer ID and
+     * there is at least one advertisement, otherwise it returns false.
+     */
+    public boolean gatherAndVerifyChreBleAdvertisementsWithManufacturerData() throws Exception {
+        List<ChreApiTest.GeneralEventsMessage> events = gatherChreBleEvents();
         if (events == null) {
             return false;
         }
 
-        boolean foundGoogleEddystoneBleAdvertisement = false;
         for (ChreApiTest.GeneralEventsMessage event: events) {
             if (!event.hasChreBleAdvertisementEvent()) {
                 continue;
@@ -68,17 +100,30 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
             for (int i = 0; i < bleAdvertisementEvent.getReportsCount(); ++i) {
                 ChreApiTest.ChreBleAdvertisingReport report = bleAdvertisementEvent.getReports(i);
                 byte[] data = report.getData().toByteArray();
-                if (data == null || data.length < 2) {
+                if (data == null || data.length < BLE_ADVERTISEMENT_DATA_HEADER_OFFSET) {
                     continue;
                 }
 
-                if (!searchForGoogleEddystoneAdvertisement(data)) {
-                    return false;
+                if (searchForManufacturerAdvertisement(data)) {
+                    return true;
                 }
-                foundGoogleEddystoneBleAdvertisement = true;
             }
         }
-        return foundGoogleEddystoneBleAdvertisement;
+        return false;
+    }
+
+    /**
+     * Gathers CHRE BLE advertisement events.
+     */
+    private List<ChreApiTest.GeneralEventsMessage> gatherChreBleEvents() throws Exception {
+        Future<List<ChreApiTest.GeneralEventsMessage>> eventsFuture =
+                new ChreApiTestUtil().gatherEvents(
+                        mRpcClients.get(0),
+                        Arrays.asList(CHRE_EVENT_BLE_ADVERTISEMENT),
+                        NUM_EVENTS_TO_GATHER,
+                        TIMEOUT_IN_NS);
+        List<ChreApiTest.GeneralEventsMessage> events = eventsFuture.get();
+        return events;
     }
 
     /**
@@ -89,6 +134,13 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
     }
 
     /**
+     * Starts a BLE scan with test manufacturer data.
+     */
+    public void chreBleStartScanSyncWithManufacturerData() throws Exception {
+        chreBleStartScanSync(getManufacturerDataScanFilterChre());
+    }
+
+     /**
      * Returns true if the data contains an advertisement for Google Eddystone,
      * otherwise returns false.
      */
@@ -105,4 +157,23 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
         }
         return false;
     }
+
+    /**
+     * Returns true if the data contains an advertisement for CHRE test manufacturer data,
+     * otherwise returns false.
+     */
+    private boolean searchForManufacturerAdvertisement(byte[] data) {
+        if (data.length < 2) {
+            return false;
+        }
+
+        for (int j = 0; j < data.length - 1; ++j) {
+            if (Byte.compare(data[j], (byte) 0xEE) == 0
+                    && Byte.compare(data[j + 1], (byte) 0xEE) == 0) {
+                return true;
+            }
+        }
+
+        return false;
+    }
 }
diff --git a/java/test/cross_validation/src/com/google/android/chre/test/crossvalidator/ChreCrossValidatorSensor.java b/java/test/cross_validation/src/com/google/android/chre/test/crossvalidator/ChreCrossValidatorSensor.java
index f6a43214..cc62d5d7 100644
--- a/java/test/cross_validation/src/com/google/android/chre/test/crossvalidator/ChreCrossValidatorSensor.java
+++ b/java/test/cross_validation/src/com/google/android/chre/test/crossvalidator/ChreCrossValidatorSensor.java
@@ -144,9 +144,10 @@ public class ChreCrossValidatorSensor
             }
         }
 
-        Assume.assumeTrue(String.format("Sensor could not be instantiated for sensor type %d.",
-                apSensorType),
-                mSensorList.size() > 0);
+        Assume.assumeTrue(
+            String.format("Sensor could not be instantiated for sensor type %d, " +
+                              "skipping this test", apSensorType),
+            mSensorList.size() > 0);
     }
 
     @Override
diff --git a/java/test/settings/Android.bp b/java/test/settings/Android.bp
index 96aa6f0c..a21e82d3 100644
--- a/java/test/settings/Android.bp
+++ b/java/test/settings/Android.bp
@@ -28,6 +28,7 @@ java_library {
     srcs: ["src/**/*.java"],
 
     static_libs: [
+        "androidx.test.espresso.intents",
         "androidx.test.rules",
         "chre-test-utils",
         "chre_settings_test_java_proto",
diff --git a/java/test/settings/src/com/google/android/chre/test/setting/ContextHubBleSettingsTestExecutor.java b/java/test/settings/src/com/google/android/chre/test/setting/ContextHubBleSettingsTestExecutor.java
index e91785dd..694d4c8d 100644
--- a/java/test/settings/src/com/google/android/chre/test/setting/ContextHubBleSettingsTestExecutor.java
+++ b/java/test/settings/src/com/google/android/chre/test/setting/ContextHubBleSettingsTestExecutor.java
@@ -16,6 +16,16 @@
 
 package com.google.android.chre.test.setting;
 
+import static androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra;
+
+import static com.google.common.truth.Truth.assertThat;
+import static com.google.common.truth.Truth.assertWithMessage;
+
+import static org.mockito.Mockito.any;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.timeout;
+import static org.mockito.Mockito.verify;
+
 import android.app.Instrumentation;
 import android.bluetooth.BluetoothAdapter;
 import android.bluetooth.BluetoothManager;
@@ -25,160 +35,171 @@ import android.content.Intent;
 import android.content.IntentFilter;
 import android.hardware.location.NanoAppBinary;
 import android.util.Log;
+import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.google.android.chre.nanoapp.proto.ChreSettingsTest;
 import com.google.android.utils.chre.SettingsUtil;
 
-import org.junit.Assert;
-
-import java.util.concurrent.CountDownLatch;
-import java.util.concurrent.TimeUnit;
+import org.hamcrest.Matcher;
+import org.hamcrest.core.AllOf;
+import org.mockito.hamcrest.MockitoHamcrest;
 
-/**
- * A test to check for behavior when Bluetooth settings are changed.
- */
+/** A test to check for behavior when Bluetooth settings are changed. */
 public class ContextHubBleSettingsTestExecutor {
     private static final String TAG = "ContextHubBleSettingsTestExecutor";
-    private final ContextHubSettingsTestExecutor mExecutor;
 
-    private final Instrumentation mInstrumentation =
-            androidx.test.platform.app.InstrumentationRegistry.getInstrumentation();
+    private final Context mContext =
+            InstrumentationRegistry.getInstrumentation().getTargetContext();
 
-    private final Context mContext = mInstrumentation.getTargetContext();
+    private final BluetoothAdapter mAdapter;
+
+    private final ContextHubSettingsTestExecutor mExecutor;
 
     private final SettingsUtil mSettingsUtil;
 
     private boolean mInitialBluetoothEnabled;
-
+    private boolean mInitialScanningEnabled;
     private boolean mInitialAirplaneMode;
 
-    private boolean mInitialBluetoothScanningEnabled;
-
-    public static class BluetoothUpdateListener {
-        public BluetoothUpdateListener(int state) {
-            mExpectedState = state;
-        }
-
-        // Expected state of the BT Adapter
-        private final int mExpectedState;
-
-        public CountDownLatch mBluetoothLatch = new CountDownLatch(1);
-
-        public BroadcastReceiver mBluetoothUpdateReceiver = new BroadcastReceiver() {
-            @Override
-            public void onReceive(Context context, Intent intent) {
-                if (BluetoothAdapter.ACTION_STATE_CHANGED.equals(intent.getAction())
-                        || BluetoothAdapter.ACTION_BLE_STATE_CHANGED.equals(
-                                intent.getAction())) {
-                    if (mExpectedState == intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1)) {
-                        mBluetoothLatch.countDown();
-                    }
-                }
-            }
-        };
-    }
-
     public ContextHubBleSettingsTestExecutor(NanoAppBinary binary) {
+        mAdapter = mContext.getSystemService(BluetoothManager.class).getAdapter();
         mExecutor = new ContextHubSettingsTestExecutor(binary);
         mSettingsUtil = new SettingsUtil(mContext);
     }
 
-    /**
-     * Should be called in a @Before method.
-     */
+    /** Should be called in a @Before method. */
     public void setUp() throws InterruptedException {
         mInitialBluetoothEnabled = mSettingsUtil.isBluetoothEnabled();
-        mInitialBluetoothScanningEnabled = mSettingsUtil.isBluetoothScanningAlwaysEnabled();
+        mInitialScanningEnabled = mSettingsUtil.isBluetoothScanningAlwaysEnabled();
         mInitialAirplaneMode = mSettingsUtil.isAirplaneModeOn();
-        Log.d(TAG, "isBluetoothEnabled=" + mInitialBluetoothEnabled
-                    + "; isBluetoothScanningEnabled=" + mInitialBluetoothScanningEnabled
-                    + "; isAirplaneModeOn=" + mInitialAirplaneMode);
+        Log.d(
+                TAG,
+                ("isBluetoothEnabled=" + mInitialBluetoothEnabled)
+                        + (" isBluetoothScanningEnabled=" + mInitialScanningEnabled)
+                        + (" isAirplaneModeOn=" + mInitialAirplaneMode));
         mSettingsUtil.setAirplaneMode(false /* enable */);
         mExecutor.init();
     }
 
     public void runBleScanningTest() throws InterruptedException {
-        runBleScanningTest(false /* enableBluetooth */, false /* enableBluetoothScanning */);
-        runBleScanningTest(true /* enableBluetooth */, false /* enableBluetoothScanning */);
-        runBleScanningTest(false /* enableBluetooth */, true /* enableBluetoothScanning */);
-        runBleScanningTest(true /* enableBluetooth */, true /* enableBluetoothScanning */);
+        runBleScanningTest(false /* enableBluetooth */, false /* enableScanning */);
+        runBleScanningTest(true /* enableBluetooth */, false /* enableScanning */);
+        runBleScanningTest(false /* enableBluetooth */, true /* enableScanning */);
+        runBleScanningTest(true /* enableBluetooth */, true /* enableScanning */);
     }
 
-    /**
-     * Should be called in an @After method.
-     */
+    /** Should be called in an @After method. */
     public void tearDown() throws InterruptedException {
+        Log.d(TAG, "tearDown");
         mExecutor.deinit();
         mSettingsUtil.setBluetooth(mInitialBluetoothEnabled);
-        mSettingsUtil.setBluetoothScanningSettings(mInitialBluetoothScanningEnabled);
+        mSettingsUtil.setBluetoothScanningSettings(mInitialScanningEnabled);
         mSettingsUtil.setAirplaneMode(mInitialAirplaneMode);
     }
 
-    /**
-     * Sets the BLE scanning settings on the device.
-     * @param enable                    true to enable Bluetooth settings, false to disable it.
-     * @param enableBluetoothScanning   if true, enable BLE scanning; false, otherwise
-     */
-    private void setBluetoothSettings(boolean enable, boolean enableBluetoothScanning) {
-        // Check if already in the desired state
-        if ((enable == mSettingsUtil.isBluetoothEnabled())
-                 && (enableBluetoothScanning == mSettingsUtil.isBluetoothScanningAlwaysEnabled())) {
-            return;
-        }
+    @SafeVarargs
+    private void verifyIntentReceived(BroadcastReceiver receiver, Matcher<Intent>... matchers) {
+        verify(receiver, timeout(10_000))
+                .onReceive(any(Context.class), MockitoHamcrest.argThat(AllOf.allOf(matchers)));
+    }
 
-        int state = BluetoothAdapter.STATE_OFF;
-        if (enable) {
-            state = BluetoothAdapter.STATE_ON;
-        } else if (enableBluetoothScanning) {
-            state = BluetoothAdapter.STATE_BLE_ON;
+    private int getBluetoothState() {
+        if (mAdapter.getState() == BluetoothAdapter.STATE_ON) {
+            return BluetoothAdapter.STATE_ON;
+        } else if (mAdapter.isLeEnabled()) {
+            return BluetoothAdapter.STATE_BLE_ON;
+        } else {
+            return BluetoothAdapter.STATE_OFF;
         }
+    }
 
-        BluetoothUpdateListener bluetoothUpdateListener = new BluetoothUpdateListener(state);
-        IntentFilter filter = new IntentFilter();
-        filter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED);
-        filter.addAction(BluetoothAdapter.ACTION_BLE_STATE_CHANGED);
-        mContext.registerReceiver(bluetoothUpdateListener.mBluetoothUpdateReceiver, filter);
-
-        mSettingsUtil.setBluetooth(enable);
-        mSettingsUtil.setBluetoothScanningSettings(enableBluetoothScanning);
-        if (!enable && enableBluetoothScanning) {
-            BluetoothManager bluetoothManager = mContext.getSystemService(BluetoothManager.class);
-            Assert.assertTrue(bluetoothManager != null);
-            BluetoothAdapter bluetoothAdapter = bluetoothManager.getAdapter();
-            Assert.assertTrue(bluetoothAdapter != null);
-            Assert.assertTrue(bluetoothAdapter.enableBLE());
-        }
+    /** return true if a state change occurred */
+    private void setBluetoothMode(int wantedState) {
+        BroadcastReceiver receiver = mock(BroadcastReceiver.class);
+        mContext.registerReceiver(
+                receiver, new IntentFilter(BluetoothAdapter.ACTION_BLE_STATE_CHANGED));
         try {
-            boolean success = bluetoothUpdateListener.mBluetoothLatch.await(10, TimeUnit.SECONDS);
-            Assert.assertTrue("Timeout waiting for signal: bluetooth update listener", success);
-            Assert.assertTrue(enable == mSettingsUtil.isBluetoothEnabled());
-            Assert.assertTrue(enableBluetoothScanning
-                    == mSettingsUtil.isBluetoothScanningAlwaysEnabled());
+            if (wantedState == getBluetoothState()) {
+                Log.d(TAG, "Bluetooth already in " + BluetoothAdapter.nameForState(wantedState));
+                return;
+            }
 
-            // Wait a few seconds to ensure setting is propagated to CHRE path
-            Thread.sleep(2000);
-        } catch (InterruptedException e) {
-            Assert.fail(e.getMessage());
+            switch (wantedState) {
+                case BluetoothAdapter.STATE_ON -> {
+                    mSettingsUtil.setBluetooth(true);
+                }
+                case BluetoothAdapter.STATE_BLE_ON -> {
+                    if (!mAdapter.isBleScanAlwaysAvailable()) {
+                        try {
+                            // Wait to ensure settings is propagated to Bluetooth
+                            Thread.sleep(1000);
+                        } catch (InterruptedException e) {
+                            assertWithMessage(e.getMessage()).fail();
+                        }
+                    }
+                    // staying in BLE_ON is not possible without the scan setting
+                    assertThat(mAdapter.isBleScanAlwaysAvailable()).isTrue();
+                    // When Bluetooth is ON, calling enableBLE will not do anything on its own. We
+                    // also need to disable the classic Bluetooth
+                    assertThat(mAdapter.enableBLE()).isTrue();
+                    mSettingsUtil.setBluetooth(false);
+                }
+                case BluetoothAdapter.STATE_OFF -> {
+                    mSettingsUtil.setBluetooth(false);
+                }
+            }
+
+            verifyIntentReceived(receiver, hasExtra(BluetoothAdapter.EXTRA_STATE, wantedState));
+        } finally {
+            mContext.unregisterReceiver(receiver);
+        }
+    }
+
+    void setScanningMode(boolean enableScanning) {
+        if (enableScanning == mSettingsUtil.isBluetoothScanningAlwaysEnabled()) {
+            Log.d(TAG, "Scanning is already in the expected mode: " + enableScanning);
+            return;
         }
 
-        mContext.unregisterReceiver(bluetoothUpdateListener.mBluetoothUpdateReceiver);
+        Log.d(TAG, "Setting scanning into: " + enableScanning);
+        mSettingsUtil.setBluetoothScanningSettings(enableScanning);
     }
 
     /**
      * Helper function to run the test
      *
-     * @param enableBluetooth         if bluetooth is enabled
-     * @param enableBluetoothScanning if bluetooth scanning is always enabled
+     * @param enableBluetooth if bluetooth is enabled
+     * @param enableScanning if bluetooth scanning is always enabled
      */
-    private void runBleScanningTest(boolean enableBluetooth,
-            boolean enableBluetoothScanning) throws InterruptedException {
-        setBluetoothSettings(enableBluetooth, enableBluetoothScanning);
-
-        boolean enableFeature = enableBluetooth || enableBluetoothScanning;
-        ChreSettingsTest.TestCommand.State state = enableFeature
-                ? ChreSettingsTest.TestCommand.State.ENABLED
-                : ChreSettingsTest.TestCommand.State.DISABLED;
-        mExecutor.startTestAssertSuccess(
-                ChreSettingsTest.TestCommand.Feature.BLE_SCANNING, state);
+    private void runBleScanningTest(boolean enableBluetooth, boolean enableScanning)
+            throws InterruptedException {
+        Log.d(TAG, "runTest: Bluetooth=" + enableBluetooth + " Scanning=" + enableScanning);
+        setScanningMode(enableScanning);
+
+        if (enableBluetooth) {
+            setBluetoothMode(BluetoothAdapter.STATE_ON);
+        } else if (enableScanning) {
+            // If scanning just get toggle ON, it may take times to propagate and to allow BLE_ON…
+            setBluetoothMode(BluetoothAdapter.STATE_BLE_ON);
+        } else {
+            setBluetoothMode(BluetoothAdapter.STATE_OFF);
+        }
+
+        try {
+            // Wait to ensure settings are propagated to CHRE path
+            Thread.sleep(2000);
+        } catch (InterruptedException e) {
+            assertWithMessage(e.getMessage()).fail();
+        }
+
+        assertThat(mSettingsUtil.isBluetoothEnabled()).isEqualTo(enableBluetooth);
+        assertThat(mSettingsUtil.isBluetoothScanningAlwaysEnabled()).isEqualTo(enableScanning);
+
+        boolean enableFeature = enableBluetooth || enableScanning;
+        ChreSettingsTest.TestCommand.State state =
+                enableFeature
+                        ? ChreSettingsTest.TestCommand.State.ENABLED
+                        : ChreSettingsTest.TestCommand.State.DISABLED;
+        mExecutor.startTestAssertSuccess(ChreSettingsTest.TestCommand.Feature.BLE_SCANNING, state);
     }
 }
diff --git a/pal/util/tests/wifi_scan_cache_test.cc b/pal/util/tests/wifi_scan_cache_test.cc
index 19a6be3e..997e567a 100644
--- a/pal/util/tests/wifi_scan_cache_test.cc
+++ b/pal/util/tests/wifi_scan_cache_test.cc
@@ -50,9 +50,12 @@ const chrePalWifiCallbacks gChreWifiPalCallbacks = {
     .scanEventCallback = chreWifiScanEventCallback,
 };
 
+using InputVec = std::vector<chreWifiScanResult>;
+using ResultVec = chre::FixedSizeVector<chreWifiScanResult,
+                                        CHRE_PAL_WIFI_SCAN_CACHE_CAPACITY>;
+
 chre::Optional<WifiScanResponse> gWifiScanResponse;
-chre::FixedSizeVector<chreWifiScanResult, CHRE_PAL_WIFI_SCAN_CACHE_CAPACITY>
-    gWifiScanResultList;
+ResultVec gWifiScanResultList;
 chre::Optional<chreWifiScanEvent> gExpectedWifiScanEvent;
 bool gWifiScanEventCompleted;
 
@@ -142,19 +145,17 @@ void beginDefaultWifiCache(const uint32_t *scannedFreqList,
       gExpectedWifiScanEvent->radioChainPref, activeScanResult);
 }
 
-void cacheDefaultWifiCacheTest(size_t numEvents,
-                               const uint32_t *scannedFreqList,
-                               uint16_t scannedFreqListLen,
-                               bool activeScanResult = true,
-                               bool scanMonitoringEnabled = false) {
+void resultSpecifiedWifiCacheTest(size_t numEvents, InputVec &inputResults,
+                                  ResultVec &expectedResults,
+                                  const uint32_t *scannedFreqList,
+                                  uint16_t scannedFreqListLen,
+                                  bool activeScanResult = true,
+                                  bool scanMonitoringEnabled = false) {
   gWifiScanEventCompleted = false;
   beginDefaultWifiCache(scannedFreqList, scannedFreqListLen, activeScanResult);
 
-  chreWifiScanResult result = {};
   for (size_t i = 0; i < numEvents; i++) {
-    result.rssi = static_cast<int8_t>(i);
-    memcpy(result.bssid, &i, sizeof(i));
-    chreWifiScanCacheScanEventAdd(&result);
+    chreWifiScanCacheScanEventAdd(&inputResults[i]);
   }
 
   chreWifiScanCacheScanEventEnd(CHRE_ERROR_NONE);
@@ -177,13 +178,48 @@ void cacheDefaultWifiCacheTest(size_t numEvents,
   ASSERT_EQ(gWifiScanResultList.size(), numEventsExpected);
   for (size_t i = 0; i < gWifiScanResultList.size(); i++) {
     // ageMs is not known apriori
-    result.ageMs = gWifiScanResultList[i].ageMs;
+    expectedResults[i].ageMs = gWifiScanResultList[i].ageMs;
+    EXPECT_EQ(memcmp(&gWifiScanResultList[i], &expectedResults[i],
+                     sizeof(chreWifiScanResult)),
+              0);
+  }
+}
+
+void cacheDefaultWifiCacheTest(size_t numEvents,
+                               const uint32_t *scannedFreqList,
+                               uint16_t scannedFreqListLen,
+                               bool activeScanResult = true,
+                               bool scanMonitoringEnabled = false) {
+  InputVec inputResults;
+  ResultVec expectedResults;
+
+  // Generate a default set of input and expected results if not specified
+  chreWifiScanResult result = {};
+  for (uint64_t i = 0; i < numEvents; i++) {
     result.rssi = static_cast<int8_t>(i);
-    memcpy(result.bssid, &i, sizeof(i));
-    EXPECT_EQ(
-        memcmp(&gWifiScanResultList[i], &result, sizeof(chreWifiScanResult)),
-        0);
+    memcpy(result.bssid, &i, sizeof(result.bssid));
+    inputResults.push_back(result);
+
+    if (!expectedResults.full()) {
+      expectedResults.push_back(result);
+    } else {
+      int8_t minRssi = result.rssi;
+      int minIdx = -1;
+      for (uint64_t idx = 0; idx < expectedResults.size(); idx++) {
+        if (expectedResults[idx].rssi < minRssi) {
+          minRssi = expectedResults[idx].rssi;
+          minIdx = idx;
+        }
+      }
+      if (minIdx != -1) {
+        expectedResults[minIdx] = result;
+      }
+    }
   }
+
+  resultSpecifiedWifiCacheTest(numEvents, inputResults, expectedResults,
+                               scannedFreqList, scannedFreqListLen,
+                               activeScanResult, scanMonitoringEnabled);
 }
 
 void testCacheDispatch(size_t numEvents, uint32_t maxScanAgeMs,
@@ -236,10 +272,63 @@ TEST_F(WifiScanCacheTests, MultiWifiResultTest) {
 
 TEST_F(WifiScanCacheTests, WifiResultOverflowTest) {
   cacheDefaultWifiCacheTest(
-      CHRE_PAL_WIFI_SCAN_CACHE_CAPACITY + 1 /* numEvents */,
+      CHRE_PAL_WIFI_SCAN_CACHE_CAPACITY + 42 /* numEvents */,
       nullptr /* scannedFreqList */, 0 /* scannedFreqListLen */);
 }
 
+TEST_F(WifiScanCacheTests, WeakestRssiNotAddedToFullCacheTest) {
+  size_t numEvents = CHRE_PAL_WIFI_SCAN_CACHE_CAPACITY + 1;
+  InputVec inputResults;
+  ResultVec expectedResults;
+
+  chreWifiScanResult result = {};
+  result.rssi = -20;
+  uint64_t i;
+  for (i = 0; i < CHRE_PAL_WIFI_SCAN_CACHE_CAPACITY; i++) {
+    memcpy(result.bssid, &i, sizeof(result.bssid));
+    inputResults.push_back(result);
+    expectedResults.push_back(result);
+  }
+
+  result.rssi = -21;
+  memcpy(result.bssid, &i, sizeof(result.bssid));
+  inputResults.push_back(result);
+
+  resultSpecifiedWifiCacheTest(numEvents, inputResults, expectedResults,
+                               nullptr /* scannedFreqList */,
+                               0 /* scannedFreqListLen */);
+}
+
+TEST_F(WifiScanCacheTests, WeakestRssiReplacedAtEndOfFullCacheTest) {
+  size_t numEvents = CHRE_PAL_WIFI_SCAN_CACHE_CAPACITY + 1;
+  InputVec inputResults;
+  ResultVec expectedResults;
+
+  chreWifiScanResult result = {};
+  result.rssi = -20;
+  uint64_t i;
+  for (i = 0; i < CHRE_PAL_WIFI_SCAN_CACHE_CAPACITY - 1; i++) {
+    memcpy(result.bssid, &i, sizeof(result.bssid));
+    inputResults.push_back(result);
+    expectedResults.push_back(result);
+  }
+
+  result.rssi = -21;
+  memcpy(result.bssid, &i, sizeof(result.bssid));
+  i++;
+  inputResults.push_back(result);
+
+  result.rssi = -19;
+  memcpy(result.bssid, &i, sizeof(result.bssid));
+  i++;
+  inputResults.push_back(result);
+  expectedResults.push_back(result);
+
+  resultSpecifiedWifiCacheTest(numEvents, inputResults, expectedResults,
+                               nullptr /* scannedFreqList */,
+                               0 /* scannedFreqListLen */);
+}
+
 TEST_F(WifiScanCacheTests, EmptyWifiResultTest) {
   cacheDefaultWifiCacheTest(0 /* numEvents */, nullptr /* scannedFreqList */,
                             0 /* scannedFreqListLen */);
@@ -331,19 +420,19 @@ TEST_F(WifiScanCacheTests, DuplicateScanResultTest) {
   chreWifiScanResult result = {};
   result.rssi = -98;
   result.primaryChannel = 5270;
-  const char *dummySsid = "Test ssid";
-  memcpy(result.ssid, dummySsid, strlen(dummySsid));
-  result.ssidLen = strlen(dummySsid);
-  const char *dummyBssid = "12:34:56:78:9a:bc";
-  memcpy(result.bssid, dummyBssid, strlen(dummyBssid));
+  std::string sampleSsid = "Test ssid";
+  memcpy(result.ssid, sampleSsid.c_str(), sampleSsid.length());
+  result.ssidLen = sampleSsid.length();
+  std::string sampleBssid = "12:34:56:78:9a:bc";
+  memcpy(result.bssid, sampleBssid.c_str(), sampleBssid.length());
   chreWifiScanResult result2 = {};
   result2.rssi = -98;
   result2.primaryChannel = 5270;
-  const char *dummySsid2 = "Test ssid 2";
-  memcpy(result2.ssid, dummySsid2, strlen(dummySsid2));
-  result2.ssidLen = strlen(dummySsid2);
-  const char *dummyBssid2 = "34:56:78:9a:bc:de";
-  memcpy(result2.bssid, dummyBssid2, strlen(dummyBssid2));
+  std::string sampleSsid2 = "Test ssid 2";
+  memcpy(result2.ssid, sampleSsid2.c_str(), sampleSsid2.length());
+  result2.ssidLen = sampleSsid2.length();
+  std::string sampleBssid2 = "34:56:78:9a:bc:de";
+  memcpy(result2.bssid, sampleBssid2.c_str(), sampleBssid2.length());
 
   chreWifiScanCacheScanEventAdd(&result);
   chreWifiScanCacheScanEventAdd(&result2);
diff --git a/pal/util/wifi_scan_cache.c b/pal/util/wifi_scan_cache.c
index 8ccfef5c..44f23374 100644
--- a/pal/util/wifi_scan_cache.c
+++ b/pal/util/wifi_scan_cache.c
@@ -165,6 +165,24 @@ static bool isWifiScanResultInCache(const struct chreWifiScanResult *result,
   return false;
 }
 
+static bool isLowerRssiScanResultInCache(
+    const struct chreWifiScanResult *result, size_t *index) {
+  int8_t lowestRssi = result->rssi;
+  bool foundWeakerResult = false;
+  for (uint8_t i = 0; i < gWifiCacheState.event.resultTotal; i++) {
+    const struct chreWifiScanResult *cacheResult =
+        &gWifiCacheState.resultList[i];
+    // Filter based on RSSI to determine weakest result in cache.
+    if (cacheResult->rssi < lowestRssi) {
+      lowestRssi = cacheResult->rssi;
+      *index = i;
+      foundWeakerResult = true;
+    }
+  }
+
+  return foundWeakerResult;
+}
+
 /************************************************
  *  Public functions
  ***********************************************/
@@ -233,29 +251,32 @@ bool chreWifiScanCacheScanEventBegin(enum chreWifiScanType scanType,
 void chreWifiScanCacheScanEventAdd(const struct chreWifiScanResult *result) {
   if (!gWifiCacheState.started) {
     gSystemApi->log(CHRE_LOG_ERROR, "Cannot add to cache before starting it");
-  } else {
-    size_t index;
-    bool exists = isWifiScanResultInCache(result, &index);
-    if (!exists && gWifiCacheState.event.resultTotal >=
-                       CHRE_PAL_WIFI_SCAN_CACHE_CAPACITY) {
-      // TODO(b/174510884): Filter based on e.g. RSSI if full
+    return;
+  }
+
+  size_t index;
+  if (!isWifiScanResultInCache(result, &index)) {
+    if (gWifiCacheState.event.resultTotal >=
+        CHRE_PAL_WIFI_SCAN_CACHE_CAPACITY) {
       gWifiCacheState.numWifiScanResultsDropped++;
-    } else {
-      if (!exists) {
-        // Only add a new entry if the result was not already cached.
-        index = gWifiCacheState.event.resultTotal;
-        gWifiCacheState.event.resultTotal++;
+      // Determine weakest result in cache to replace with the new result.
+      if (!isLowerRssiScanResultInCache(result, &index)) {
+        return;
       }
-
-      memcpy(&gWifiCacheState.resultList[index], result,
-             sizeof(const struct chreWifiScanResult));
-
-      // ageMs will be properly populated in chreWifiScanCacheScanEventEnd
-      gWifiCacheState.resultList[index].ageMs =
-          (uint32_t)gSystemApi->getCurrentTime() /
-          (uint32_t)kOneMillisecondInNanoseconds;
+    } else {
+      // Result was not already cached, add new entry to the end of the cache
+      index = gWifiCacheState.event.resultTotal;
+      gWifiCacheState.event.resultTotal++;
     }
   }
+
+  memcpy(&gWifiCacheState.resultList[index], result,
+         sizeof(const struct chreWifiScanResult));
+
+  // ageMs will be properly populated in chreWifiScanCacheScanEventEnd
+  gWifiCacheState.resultList[index].ageMs =
+      (uint32_t)gSystemApi->getCurrentTime() /
+      (uint32_t)kOneMillisecondInNanoseconds;
 }
 
 void chreWifiScanCacheScanEventEnd(enum chreError errorCode) {
diff --git a/platform/freertos/include/chre/target_platform/mutex_base_impl.h b/platform/freertos/include/chre/target_platform/mutex_base_impl.h
index a983f5e3..07ddf0c1 100644
--- a/platform/freertos/include/chre/target_platform/mutex_base_impl.h
+++ b/platform/freertos/include/chre/target_platform/mutex_base_impl.h
@@ -44,7 +44,7 @@ inline bool Mutex::try_lock() {
   TickType_t doNotBlock = static_cast<TickType_t>(0);
   BaseType_t rv = xSemaphoreTake(mSemaphoreHandle, doNotBlock);
 
-  return (rv == pdTRUE) ? true : false;
+  return rv == pdTRUE;
 }
 
 inline void Mutex::unlock() {
diff --git a/platform/freertos/init.cc b/platform/freertos/init.cc
index 16c5db5c..065b3aa8 100644
--- a/platform/freertos/init.cc
+++ b/platform/freertos/init.cc
@@ -103,18 +103,9 @@ const char *getChreFlushTaskName();
 #endif
 
 BaseType_t init() {
-  BaseType_t rc = pdPASS;
-
-  DramVoteClientSingleton::init();
-
-  rc = initLogger();
-
-  if (rc == pdPASS) {
-    rc = xTaskCreate(chreThreadEntry, getChreTaskName(),
-                     kChreTaskStackDepthWords, nullptr /* args */,
-                     kChreTaskPriority, &gChreTaskHandle);
-  }
-
+  BaseType_t rc =
+      xTaskCreate(chreThreadEntry, getChreTaskName(), kChreTaskStackDepthWords,
+                  nullptr /* args */, kChreTaskPriority, &gChreTaskHandle);
   CHRE_ASSERT(rc == pdPASS);
 
 #ifdef CHRE_ENABLE_CHPP
diff --git a/platform/include/chre/platform/host_link.h b/platform/include/chre/platform/host_link.h
index 451470f1..0d5b7b4d 100644
--- a/platform/include/chre/platform/host_link.h
+++ b/platform/include/chre/platform/host_link.h
@@ -41,12 +41,16 @@ class HostLink : public HostLinkBase, public NonCopyable {
  public:
   /**
    * Flush (or purge) any messages sent by the given app ID that are currently
-   * pending delivery to the host. At the point that this function is called, it
-   * is guaranteed that no new messages will be generated from this nanoapp.
+   * pending delivery to the host. Note that this doesn't need to guarantee that
+   * messages have arrived on the host side, only that the memory associated
+   * with them is no longer referenced by HostLink, i.e.
+   * HostCommsManager::onMessageToHostComplete() has been invoked. This function
+   * must impose strict ordering constraints, such that after it returns, it is
+   * guaranteed that HostCommsManager::onMessageToHostComplete will not be
+   * invoked for the app with the given ID.
    *
-   * This function must impose strict ordering constraints, such that after it
-   * returns, it is guaranteed that HostCommsManager::onMessageToHostComplete
-   * will not be invoked for the app with the given ID.
+   * At the point that this function is called, it is guaranteed that no new
+   * messages will be generated from this nanoapp.
    */
   void flushMessagesSentByNanoapp(uint64_t appId);
 
diff --git a/platform/include/chre/platform/memory.h b/platform/include/chre/platform/memory.h
index a7048b02..df5bb67a 100644
--- a/platform/include/chre/platform/memory.h
+++ b/platform/include/chre/platform/memory.h
@@ -18,6 +18,7 @@
 #define CHRE_PLATFORM_MEMORY_H_
 
 #include <cstddef>
+#include <cstdint>
 
 namespace chre {
 
@@ -33,10 +34,18 @@ void *memoryAlloc(size_t size);
  *
  * This implementation is optional and is not typically needed.
  */
-
 template <typename T>
 T *memoryAlignedAlloc();
 
+/**
+ * A platform abstraction for aligned memory allocation for an array. The
+ * semantics are the same as aligned_malloc.
+ *
+ * This implementation is optional and is not typically needed.
+ */
+template <typename T>
+T *memoryAlignedAllocArray(size_t count);
+
 /**
  * A platform abstraction for memory free. The semantics are the same as free.
  */
diff --git a/platform/include/chre/platform/notifier.h b/platform/include/chre/platform/notifier.h
new file mode 100644
index 00000000..0e1fd3a3
--- /dev/null
+++ b/platform/include/chre/platform/notifier.h
@@ -0,0 +1,104 @@
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
+#ifndef CHRE_PLATFORM_NOTIFIER_H_
+#define CHRE_PLATFORM_NOTIFIER_H_
+
+#include "chre/platform/thread_handle.h"
+#include "chre/target_platform/notifier_base.h"
+#include "chre/util/non_copyable.h"
+
+namespace chre {
+
+/**
+ * Provides the ability to notify a fixed thread/task. A thread must be bound to
+ * the instance, after which any thread (including itself) may notify it via
+ * Notify(). The target thread receives notifications through the Wait() which
+ * returns immediately if there are pending notifications or otherwise blocks.
+ * Pending notifications are cleared before the target thread returns from
+ * Wait().
+ *
+ * An example control flow between two threads:
+ * [Event]  [T1]          [T2]      [Description]
+ * 1.       Bind()        ...       T1 binds itself to the notifier
+ * 2.       ...           Notify()  T2 notifies.
+ * 3.       ...           Notify()  T2 notifies again before T1 calls Wait().
+ * 2.       Wait()        ...       T1 waits for notifications. Returns
+ *                                  immediately.
+ * 3.       Wait()        ...       T1 waits again. The previous Wait() cleared
+ *                                  both pending notifications so it blocks.
+ * 4.       <blocked>     Notify()  T2 notifies. T1 is scheduled again.
+ * 5.       ...           Notify()  T2 notifies.
+ * 6.       Clear()       ...       T1 clears pending notifications.
+ * 7.       Wait()        ...       T1 waits for notifications. Blocks as all
+ *                                  pending notifications were cleared.
+ *
+ * NotifierBase is subclassed to allow platforms to inject the storage for their
+ * implementation.
+ */
+class Notifier : public NotifierBase, public NonCopyable {
+ public:
+  /**
+   * Allows the platform to perform any necessary initialization.
+   */
+  Notifier();
+
+  /**
+   * Allows the platform to perform any necessary de-initialization.
+   */
+  ~Notifier();
+
+  /**
+   * Binds a thread to this instance.
+   *
+   * By default, binds the instance to the current thread.
+   *
+   * This is not thread-safe w.r.t. Wait() and Notify(). It must be called
+   * before either Wait() or Notify() are called.
+   */
+  void Bind(ThreadHandle threadHandle = ThreadHandle::GetCurrent());
+
+  /**
+   * Blocks the caller until/unless notified.
+   *
+   * Clears any pending notifications before returning. The user must be
+   * prepared for spurious wake-ups.
+   *
+   * Must be called by the last thread bound to this instance.
+   */
+  void Wait();
+
+  /**
+   * Sets notification state, and if necessary, wakes the thread in Wait().
+   *
+   * Depending on the platform it may be valid to invoke this from an interrupt
+   * context.
+   */
+  void Notify();
+
+  /**
+   * Clears any pending notifications.
+   *
+   * Must be called from the last thread bound to this instance.
+   */
+  void Clear();
+};
+
+}  // namespace chre
+
+#include "chre/target_platform/notifier_impl.h"
+
+#endif  // CHRE_PLATFORM_NOTIFIER_H_
diff --git a/platform/include/chre/platform/thread_handle.h b/platform/include/chre/platform/thread_handle.h
new file mode 100644
index 00000000..563c514c
--- /dev/null
+++ b/platform/include/chre/platform/thread_handle.h
@@ -0,0 +1,92 @@
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
+#ifndef CHRE_PLATFORM_THREAD_HANDLE_H_
+#define CHRE_PLATFORM_THREAD_HANDLE_H_
+
+#include "chre/target_platform/thread_handle_base.h"
+
+namespace chre {
+
+/**
+ * Wrapper around a platform-specific thread handle.
+ *
+ * The user can get a ThreadHandle representing the current thread or convert
+ * to/from a platform-specific representation. ThreadHandles can be compared for
+ * equality. ThreadHandles are copyable, though the exact behavior is platform
+ * specific.
+ *
+ * ThreadHandleBase is subclassed to allow platforms to inject the storage for
+ * their implementation.
+ */
+class ThreadHandle : public ThreadHandleBase {
+ public:
+  using ThreadHandleBase::NativeHandle;
+
+  /**
+   * Returns the ThreadHandle for the current thread/task.
+   */
+  static ThreadHandle GetCurrent() {
+    return ThreadHandle();
+  }
+
+  /**
+   * Creates a ThreadHandle from a platform-specific id.
+   */
+  explicit ThreadHandle(NativeHandle nativeHandle);
+
+  /**
+   * ThreadHandle is copyable and movable.
+   */
+  ThreadHandle(const ThreadHandle &other);
+  ThreadHandle(ThreadHandle &&other);
+  ThreadHandle &operator=(const ThreadHandle &other);
+  ThreadHandle &operator=(ThreadHandle &&other);
+
+  /**
+   * Allows the platform to perform any necessary de-initialization.
+   */
+  ~ThreadHandle();
+
+  /**
+   * Returns the platform-specific id.
+   */
+  NativeHandle GetNative() const;
+
+  /**
+   * Compares with another ThreadHandle for equality.
+   */
+  bool operator==(const ThreadHandle &other) const;
+
+  /**
+   * Compares with another ThreadHandle for inequality.
+   */
+  bool operator!=(const ThreadHandle &other) const {
+    return !(*this == other);
+  }
+
+ protected:
+  /**
+   * Allows the platform to perform any necessary initialization.
+   */
+  ThreadHandle();
+};
+
+}  // namespace chre
+
+#include "chre/target_platform/thread_handle_impl.h"
+
+#endif  // CHRE_PLATFORM_THREAD_HANDLE_H_
diff --git a/platform/linux/include/chre/platform/linux/pal_wifi.h b/platform/linux/include/chre/platform/linux/pal_wifi.h
index ff3bee46..b2ab83ce 100644
--- a/platform/linux/include/chre/platform/linux/pal_wifi.h
+++ b/platform/linux/include/chre/platform/linux/pal_wifi.h
@@ -40,10 +40,10 @@ bool chrePalWifiIsScanMonitoringActive();
  * to CHRE.
  *
  * @param requestType select one request type to modify its behavior.
- * @param seconds delayed response time.
+ * @param milliseconds delayed response time.
  */
 void chrePalWifiDelayResponse(PalWifiAsyncRequestTypes requestType,
-                              std::chrono::seconds seconds);
+                              std::chrono::milliseconds milliseconds);
 
 /**
  * Sets if PAL should send back async request result for each async request.
diff --git a/platform/linux/include/chre/target_platform/memory_impl.h b/platform/linux/include/chre/target_platform/memory_impl.h
index 608bbc5d..825ecf47 100644
--- a/platform/linux/include/chre/target_platform/memory_impl.h
+++ b/platform/linux/include/chre/target_platform/memory_impl.h
@@ -32,6 +32,16 @@ inline T *memoryAlignedAlloc() {
   return static_cast<T *>(ptr);
 }
 
+template <typename T>
+inline T *memoryAlignedAllocArray(size_t count) {
+  void *ptr;
+  int result = posix_memalign(&ptr, alignof(T), sizeof(T) * count);
+  if (result != 0) {
+    ptr = nullptr;
+  }
+  return static_cast<T *>(ptr);
+}
+
 }  // namespace chre
 
 #endif  // CHRE_PLATFORM_LINUX_MEMORY_IMPL_H_
diff --git a/platform/linux/include/chre/target_platform/notifier_base.h b/platform/linux/include/chre/target_platform/notifier_base.h
new file mode 100644
index 00000000..4ab4c347
--- /dev/null
+++ b/platform/linux/include/chre/target_platform/notifier_base.h
@@ -0,0 +1,50 @@
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
+#ifndef CHRE_PLATFORM_LINUX_NOTIFIER_BASE_H_
+#define CHRE_PLATFORM_LINUX_NOTIFIER_BASE_H_
+
+#include <pthread.h>
+
+#include <condition_variable>
+#include <mutex>
+#include <optional>
+
+namespace chre {
+
+/**
+ * Storage for Linux implementation of a direct task notifier.
+ */
+class NotifierBase {
+ protected:
+  static constexpr uint32_t kWaitFlag = 0x80000000;
+
+  //! The task this Notifier instance is bound to.
+  std::optional<pthread_t> mTarget;
+
+  //! Mutex protecting the notified state.
+  std::mutex mLock;
+
+  //! Condition variable used to notify the waiting task.
+  std::condition_variable mCondVar;
+
+  //! Whether the Notifier has been notified.
+  bool mNotified = false;
+};
+
+}  // namespace chre
+
+#endif  // CHRE_PLATFORM_LINUX_NOTIFIER_BASE_H_
diff --git a/platform/linux/include/chre/target_platform/notifier_impl.h b/platform/linux/include/chre/target_platform/notifier_impl.h
new file mode 100644
index 00000000..bde122c8
--- /dev/null
+++ b/platform/linux/include/chre/target_platform/notifier_impl.h
@@ -0,0 +1,70 @@
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
+#ifndef CHRE_PLATFORM_LINUX_NOTIFIER_IMPL_H_
+#define CHRE_PLATFORM_LINUX_NOTIFIER_IMPL_H_
+
+#include <pthread.h>
+
+#include <cinttypes>
+#include <mutex>
+
+#include "chre/platform/assert.h"
+#include "chre/platform/log.h"
+#include "chre/platform/notifier.h"
+#include "chre/platform/thread_handle.h"
+
+namespace chre {
+
+inline Notifier::Notifier() = default;
+inline Notifier::~Notifier() = default;
+
+inline void Notifier::Bind(ThreadHandle threadHandle) {
+  mTarget = threadHandle.GetNative();
+}
+
+inline void Notifier::Wait() {
+  CHRE_ASSERT_LOG(mTarget, "Notifier is not bound.");
+  CHRE_ASSERT_LOG(pthread_equal(pthread_self(), *mTarget),
+                  "Wrong thread calling Notifier::Wait(). Expected %" PRIu64
+                  ", got %" PRIu64,
+                  *mTarget, pthread_self());
+  std::unique_lock lock(mLock);
+  mCondVar.wait(lock, [this] { return mNotified; });
+  mNotified = false;
+}
+
+inline void Notifier::Notify() {
+  {
+    std::lock_guard lock(mLock);
+    mNotified = true;
+  }
+  mCondVar.notify_one();
+}
+
+inline void Notifier::Clear() {
+  CHRE_ASSERT_LOG(mTarget, "Notifier is not bound.");
+  CHRE_ASSERT_LOG(pthread_equal(pthread_self(), *mTarget),
+                  "Wrong thread calling Notifier::Wait(). Expected %" PRIu64
+                  ", got %" PRIu64,
+                  *mTarget, pthread_self());
+  std::lock_guard lock(mLock);
+  mNotified = false;
+}
+
+}  // namespace chre
+
+#endif  // CHRE_PLATFORM_LINUX_NOTIFIER_IMPL_H_
diff --git a/platform/linux/include/chre/target_platform/system_timer_base.h b/platform/linux/include/chre/target_platform/system_timer_base.h
index d7be591e..1d52dc2f 100644
--- a/platform/linux/include/chre/target_platform/system_timer_base.h
+++ b/platform/linux/include/chre/target_platform/system_timer_base.h
@@ -20,6 +20,7 @@
 #include <signal.h>
 #include <time.h>
 #include <cinttypes>
+#include <mutex>
 
 namespace chre {
 
@@ -29,6 +30,9 @@ namespace chre {
  */
 class SystemTimerBase {
  protected:
+  //! The mutex to protect the callback and data.
+  std::mutex mMutex;
+
   //! The timer id that is generated during the initialization phase.
   timer_t mTimerId;
 
diff --git a/platform/linux/include/chre/target_platform/thread_handle_base.h b/platform/linux/include/chre/target_platform/thread_handle_base.h
new file mode 100644
index 00000000..5ae4da5b
--- /dev/null
+++ b/platform/linux/include/chre/target_platform/thread_handle_base.h
@@ -0,0 +1,36 @@
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
+#ifndef CHRE_PLATFORM_LINUX_THREAD_HANDLE_BASE_H_
+#define CHRE_PLATFORM_LINUX_THREAD_HANDLE_BASE_H_
+
+#include <pthread.h>
+
+namespace chre {
+
+/**
+ * Storage for the Linux implementation of a thread handle.
+ */
+class ThreadHandleBase {
+ protected:
+  using NativeHandle = pthread_t;
+
+  NativeHandle mHandle;
+};
+
+}  // namespace chre
+
+#endif  // CHRE_PLATFORM_LINUX_THREAD_HANDLE_BASE_H_
diff --git a/platform/linux/include/chre/target_platform/thread_handle_impl.h b/platform/linux/include/chre/target_platform/thread_handle_impl.h
new file mode 100644
index 00000000..ca261a12
--- /dev/null
+++ b/platform/linux/include/chre/target_platform/thread_handle_impl.h
@@ -0,0 +1,49 @@
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
+#ifndef CHRE_PLATFORM_LINUX_THREAD_HANDLE_IMPL_H_
+#define CHRE_PLATFORM_LINUX_THREAD_HANDLE_IMPL_H_
+
+#include "chre/platform/thread_handle.h"
+
+#include <pthread.h>
+
+namespace chre {
+
+inline ThreadHandle::ThreadHandle(ThreadHandle::NativeHandle nativeHandle) {
+  mHandle = nativeHandle;
+}
+
+inline ThreadHandle::ThreadHandle(const ThreadHandle &other) = default;
+inline ThreadHandle::ThreadHandle(ThreadHandle &&other) = default;
+inline ThreadHandle &ThreadHandle::operator=(const ThreadHandle &other) =
+    default;
+inline ThreadHandle &ThreadHandle::operator=(ThreadHandle &&other) = default;
+inline ThreadHandle::~ThreadHandle() = default;
+
+inline ThreadHandle::NativeHandle ThreadHandle::GetNative() const {
+  return mHandle;
+}
+
+inline bool ThreadHandle::operator==(const ThreadHandle &other) const {
+  return pthread_equal(mHandle, other.mHandle);
+}
+
+inline ThreadHandle::ThreadHandle() : ThreadHandle(pthread_self()) {}
+
+}  // namespace chre
+
+#endif  // CHRE_PLATFORM_LINUX_THREAD_HANDLE_IMPL_H_
diff --git a/platform/linux/pal_wifi.cc b/platform/linux/pal_wifi.cc
index 7013b893..ae0fcf6f 100644
--- a/platform/linux/pal_wifi.cc
+++ b/platform/linux/pal_wifi.cc
@@ -273,9 +273,10 @@ bool chrePalWifiIsScanMonitoringActive() {
 }
 
 void chrePalWifiDelayResponse(PalWifiAsyncRequestTypes requestType,
-                              std::chrono::seconds seconds) {
+                              std::chrono::milliseconds milliseconds) {
   gAsyncRequestDelayResponseTime[chre::asBaseType(requestType)] =
-      std::chrono::duration_cast<std::chrono::nanoseconds>(seconds);
+      std::chrono::duration_cast<std::chrono::nanoseconds>(milliseconds);
+  ;
 }
 
 const struct chrePalWifiApi *chrePalWifiGetApi(uint32_t requestedApiVersion) {
diff --git a/platform/linux/system_timer.cc b/platform/linux/system_timer.cc
index 12be939c..caa0474b 100644
--- a/platform/linux/system_timer.cc
+++ b/platform/linux/system_timer.cc
@@ -16,19 +16,24 @@
 
 #include "chre/platform/system_timer.h"
 
-#include "chre/platform/log.h"
-#include "chre/util/time.h"
-
 #include <errno.h>
 #include <signal.h>
 #include <string.h>
+
 #include <cinttypes>
+#include <mutex>
+#include <unordered_set>
+
+#include "chre/platform/log.h"
+#include "chre/util/time.h"
 
 namespace chre {
 
 namespace {
 
 constexpr uint64_t kOneSecondInNanoseconds = 1000000000;
+std::unordered_set<SystemTimer *> gActiveTimerInstances;
+std::mutex gGlobalTimerMutex;
 
 void NanosecondsToTimespec(uint64_t ns, struct timespec *ts) {
   ts->tv_sec = ns / kOneSecondInNanoseconds;
@@ -39,12 +44,21 @@ void NanosecondsToTimespec(uint64_t ns, struct timespec *ts) {
 
 void SystemTimerBase::systemTimerNotifyCallback(union sigval cookie) {
   SystemTimer *sysTimer = static_cast<SystemTimer *>(cookie.sival_ptr);
-  sysTimer->mCallback(sysTimer->mData);
+  std::lock_guard<std::mutex> globalLock(gGlobalTimerMutex);
+  if (gActiveTimerInstances.find(sysTimer) != gActiveTimerInstances.end()) {
+    std::lock_guard<std::mutex> lock(sysTimer->mMutex);
+    sysTimer->mCallback(sysTimer->mData);
+  }
 }
 
-SystemTimer::SystemTimer() {}
+SystemTimer::SystemTimer() {
+  std::lock_guard<std::mutex> globalLock(gGlobalTimerMutex);
+  gActiveTimerInstances.insert(this);
+}
 
 SystemTimer::~SystemTimer() {
+  std::lock_guard<std::mutex> globalLock(gGlobalTimerMutex);
+  gActiveTimerInstances.erase(this);
   if (mInitialized) {
     int ret = timer_delete(mTimerId);
     if (ret != 0) {
@@ -77,28 +91,30 @@ bool SystemTimer::init() {
 
 bool SystemTimer::set(SystemTimerCallback *callback, void *data,
                       Nanoseconds delay) {
+  if (!mInitialized) {
+    return false;
+  }
+
   // 0 has a special meaning in POSIX, i.e. cancel the timer. In our API, a
   // value of 0 just means fire right away.
   if (delay.toRawNanoseconds() == 0) {
     delay = Nanoseconds(1);
   }
 
-  if (mInitialized) {
+  {
+    std::lock_guard<std::mutex> lock(mMutex);
     mCallback = callback;
     mData = data;
-    return setInternal(delay.toRawNanoseconds());
-  } else {
-    return false;
   }
+  return setInternal(delay.toRawNanoseconds());
 }
 
 bool SystemTimer::cancel() {
   if (mInitialized) {
     // Setting delay to 0 disarms the timer.
     return setInternal(0);
-  } else {
-    return false;
   }
+  return false;
 }
 
 bool SystemTimer::isActive() {
@@ -119,7 +135,6 @@ bool SystemTimer::isActive() {
 bool SystemTimerBase::setInternal(uint64_t delayNs) {
   constexpr int kFlags = 0;
   struct itimerspec spec = {};
-  bool success = false;
 
   NanosecondsToTimespec(delayNs, &spec.it_value);
   NanosecondsToTimespec(0, &spec.it_interval);
@@ -127,11 +142,9 @@ bool SystemTimerBase::setInternal(uint64_t delayNs) {
   int ret = timer_settime(mTimerId, kFlags, &spec, nullptr);
   if (ret != 0) {
     LOGE("Couldn't set timer: %s", strerror(errno));
-  } else {
-    success = true;
+    return false;
   }
-
-  return success;
+  return true;
 }
 
 }  // namespace chre
diff --git a/platform/platform.mk b/platform/platform.mk
index 21fc3064..8e16753f 100644
--- a/platform/platform.mk
+++ b/platform/platform.mk
@@ -182,7 +182,6 @@ endif
 
 SLPI_QSH_SRCS += platform/slpi/see/island_vote_client.cc
 SLPI_QSH_SRCS += platform/slpi/see/power_control_manager.cc
-SLPI_QSH_SRCS += platform/slpi/qsh/qsh_proto_shim.cc
 
 ifeq ($(CHRE_USE_BUFFERED_LOGGING), true)
 SLPI_QSH_SRCS += platform/shared/log_buffer.cc
@@ -527,9 +526,3 @@ TINYSYS_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/nanoapp/include
 TINYSYS_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/include/chre/platform/shared/libc
 TINYSYS_CFLAGS += -I$(CHRE_PREFIX)/platform/tinysys/include
 
-TINYSYS_CFLAGS += $(FLATBUFFERS_CFLAGS)
-TINYSYS_CFLAGS += $(MBEDTLS_CFLAGS)
-
-TINYSYS_CFLAGS += -DCFG_DRAM_HEAP_SUPPORT
-TINYSYS_CFLAGS += -DCHRE_LOADER_ARCH=EM_RISCV
-TINYSYS_CFLAGS += -DCHRE_NANOAPP_LOAD_ALIGNMENT=4096
diff --git a/platform/shared/aligned_alloc_unsupported/include/chre/target_platform/memory_impl.h b/platform/shared/aligned_alloc_unsupported/include/chre/target_platform/memory_impl.h
index b749b95c..7bd62ba9 100644
--- a/platform/shared/aligned_alloc_unsupported/include/chre/target_platform/memory_impl.h
+++ b/platform/shared/aligned_alloc_unsupported/include/chre/target_platform/memory_impl.h
@@ -30,6 +30,13 @@ inline T *memoryAlignedAlloc() {
   return nullptr;
 }
 
+template <typename T>
+inline T *memoryAlignedAllocArray([[maybe_unused]] size_t count) {
+  static_assert(AlwaysFalse<T>::value,
+                "memoryAlignedAlloc is unsupported on this platform");
+  return nullptr;
+}
+
 }  // namespace chre
 
 #endif  // CHRE_SHARED_ALIGNED_ALLOC_UNSUPPORTED_MEMORY_IMPL_H_
diff --git a/platform/shared/chre_api_ble.cc b/platform/shared/chre_api_ble.cc
index 1f630174..ea403876 100644
--- a/platform/shared/chre_api_ble.cc
+++ b/platform/shared/chre_api_ble.cc
@@ -107,7 +107,7 @@ DLL_EXPORT bool chreBleStopScanAsync() {
 
 DLL_EXPORT bool chreBleReadRssiAsync(uint16_t connectionHandle,
                                      const void *cookie) {
-#ifdef CHRE_BLE_READ_RSSI_SUPPORT_ENABLED
+#ifdef CHRE_BLE_SUPPORT_ENABLED
   chre::Nanoapp *nanoapp = EventLoopManager::validateChreApiCall(__func__);
   return nanoapp->permitPermissionUse(NanoappPermissions::CHRE_PERMS_BLE) &&
          EventLoopManagerSingleton::get()->getBleRequestManager().readRssiAsync(
@@ -116,7 +116,7 @@ DLL_EXPORT bool chreBleReadRssiAsync(uint16_t connectionHandle,
   UNUSED_VAR(connectionHandle);
   UNUSED_VAR(cookie);
   return false;
-#endif  // CHRE_BLE_READ_RSSI_SUPPORT_ENABLED
+#endif  // CHRE_BLE_SUPPORT_ENABLED
 }
 
 DLL_EXPORT bool chreBleGetScanStatus(struct chreBleScanStatus *status) {
diff --git a/platform/shared/platform_ble.cc b/platform/shared/platform_ble.cc
index 9d0bf90c..54e5f1ee 100644
--- a/platform/shared/platform_ble.cc
+++ b/platform/shared/platform_ble.cc
@@ -139,14 +139,8 @@ bool PlatformBle::readRssiAsync(uint16_t connectionHandle) {
 
 void PlatformBleBase::readRssiCallback(uint8_t errorCode,
                                        uint16_t connectionHandle, int8_t rssi) {
-#ifdef CHRE_BLE_READ_RSSI_SUPPORT_ENABLED
   EventLoopManagerSingleton::get()->getBleRequestManager().handleReadRssi(
       errorCode, connectionHandle, rssi);
-#else
-  UNUSED_VAR(errorCode);
-  UNUSED_VAR(connectionHandle);
-  UNUSED_VAR(rssi);
-#endif
 }
 
 bool PlatformBle::flushAsync() {
diff --git a/platform/slpi/init.cc b/platform/slpi/init.cc
index 6aef26b2..db57fba0 100644
--- a/platform/slpi/init.cc
+++ b/platform/slpi/init.cc
@@ -40,10 +40,6 @@ extern "C" {
 #include "chre/platform/slpi/see/island_vote_client.h"
 #endif
 
-#ifdef CHRE_QSH_ENABLED
-#include "chre/platform/slpi/qsh/qsh_proto_shim.h"
-#endif
-
 #ifdef CHRE_USE_BUFFERED_LOGGING
 #include "chre/platform/shared/log_buffer_manager.h"
 #endif
@@ -118,20 +114,12 @@ uint8_t gSecondaryLogBufferData[CHRE_LOG_BUFFER_DATA_SIZE];
  * @param data Argument passed to qurt_thread_create()
  */
 void chreThreadEntry(void * /*data*/) {
-#ifdef CHRE_QSH_ENABLED
-  chre::openQsh();
-#endif  // CHRE_QSH_ENABLED
-
   EventLoopManagerSingleton::get()->lateInit();
   chre::loadStaticNanoapps();
   EventLoopManagerSingleton::get()->getEventLoop().run();
 
   chre::deinit();
 
-#ifdef CHRE_QSH_ENABLED
-  chre::closeQsh();
-#endif  // CHRE_QSH_ENABLED
-
 #if defined(CHRE_SLPI_SEE) && !defined(IMPORT_CHRE_UTILS)
   chre::IslandVoteClientSingleton::deinit();
 #endif
diff --git a/platform/slpi/qsh/qsh_proto_shim.cc b/platform/slpi/qsh/qsh_proto_shim.cc
deleted file mode 100644
index e56282d7..00000000
--- a/platform/slpi/qsh/qsh_proto_shim.cc
+++ /dev/null
@@ -1,141 +0,0 @@
-/*
- * Copyright (C) 2016 The Android Open Source Project
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
-#include <dlfcn.h>
-#include <cstdint>
-
-extern "C" {
-
-#include "qsh_na_api.h"
-
-}  // extern "C"
-
-#include "chre/core/event_loop_manager.h"
-#include "chre/core/nanoapp.h"
-#include "chre/platform/assert.h"
-#include "chre/platform/log.h"
-#include "chre/platform/memory.h"
-#include "chre/platform/slpi/qsh/qsh_proto_shim.h"
-#include "chre/sensor.h"
-#include "chre/util/macros.h"
-#include "chre/util/system/event_callbacks.h"
-
-namespace chre {
-namespace {
-
-//! Function pointer to store QSH's version of chreSensorFlushAsync
-decltype(chreSensorFlushAsync) *gFlushFuncPtr = nullptr;
-
-/*
- * Used by QSH to obtain the currently running nanoapp instance ID when nanoapps
- * invoke CHRE APIs implemented by its shim.
- */
-bool getCurrentNanoappInstanceId(uint32_t *nanoappInstId) {
-  CHRE_ASSERT(nanoappInstId != nullptr);
-  if (nanoappInstId == nullptr) {
-    return false;
-  }
-
-  bool success = false;
-  Nanoapp *currentNanoapp =
-      EventLoopManagerSingleton::get()->getEventLoop().getCurrentNanoapp();
-  if (currentNanoapp == nullptr) {
-    LOGE("No nanoapp currently executing");
-  } else {
-    *nanoappInstId = currentNanoapp->getInstanceId();
-    success = true;
-  }
-  return success;
-}
-
-/*
- * Used by QSH to post events to the CHRE event loop. The caller continues to
- * own the event pointer after returning so a copy must be made of the data.
- */
-bool postEventFromQsh(uint16_t eventType, void *event, uint32_t eventLen,
-                      uint32_t nanoappInstId) {
-  // Default success to true if the event is empty since an empty event can
-  // still be sent to CHRE.
-  bool success = false;
-  void *eventCopy = nullptr;
-  if (eventLen == 0) {
-    CHRE_ASSERT(event == nullptr);
-    if (event != nullptr) {
-      LOGE("Event len 0 with non-null event data");
-    } else {
-      success = true;
-    }
-  } else {
-    CHRE_ASSERT(event != nullptr);
-    if (event != nullptr) {
-      eventCopy = memoryAlloc(eventLen);
-      if (eventCopy == nullptr) {
-        LOG_OOM();
-      } else {
-        memcpy(eventCopy, event, eventLen);
-        success = true;
-      }
-    }
-  }
-
-  if (success) {
-    EventLoopManagerSingleton::get()->getEventLoop().postEventOrDie(
-        eventType, eventCopy, freeEventDataCallback,
-        static_cast<uint16_t>(nanoappInstId));
-  }
-  return success;
-}
-
-const qsh_na_api_callbacks gQshCallbacks = {
-    getCurrentNanoappInstanceId, /* get_current_nanoapp_inst_id */
-    postEventFromQsh,            /* post_event */
-};
-
-}  // anonymous namespace
-
-void openQsh() {
-  if (!qsh_na_open(&gQshCallbacks)) {
-    LOGE("QSH failed to open");
-  } else {
-    LOGI("QSH opened");
-    gFlushFuncPtr = reinterpret_cast<decltype(gFlushFuncPtr)>(
-        dlsym(RTLD_NEXT, STRINGIFY(chreSensorFlushAsync)));
-    if (gFlushFuncPtr == nullptr) {
-      LOGE("Flush function not found!");
-    }
-  }
-}
-
-void closeQsh() {
-  qsh_na_close();
-}
-
-}  // namespace chre
-
-// Define the delete operator so that SLPI doesn't have to expose this symbol
-// since CHRE will never call it directly
-void operator delete(void *ptr) noexcept {
-  free(ptr);
-}
-
-// Export the chreSensorFlushAsync symbol from CHRE and then used the previously
-// looked up symbol to WAR loader issue where nanoapps can't see QSH symbols.
-DLL_EXPORT extern "C" bool chreSensorFlushAsync(uint32_t sensorHandle,
-                                                const void *cookie) {
-  return (chre::gFlushFuncPtr != nullptr)
-             ? chre::gFlushFuncPtr(sensorHandle, cookie)
-             : false;
-}
\ No newline at end of file
diff --git a/platform/tinysys/host_link.cc b/platform/tinysys/host_link.cc
index bc708b10..a393da9a 100644
--- a/platform/tinysys/host_link.cc
+++ b/platform/tinysys/host_link.cc
@@ -627,6 +627,11 @@ DRAM_REGION_FUNCTION bool HostLinkBase::send(uint8_t *data, size_t dataLen) {
 
 DRAM_REGION_FUNCTION void HostLinkBase::sendTimeSyncRequest() {}
 
+DRAM_REGION_FUNCTION void HostLinkBase::sendNanConfiguration(
+    bool /* enabled */) {
+  LOGE("%s is unsupported", __func__);
+}
+
 DRAM_REGION_FUNCTION void HostLinkBase::sendLogMessageV2(
     const uint8_t *logMessage, size_t logMessageSize, uint32_t numLogsDropped) {
   LOGV("%s: size %zu", __func__, logMessageSize);
@@ -834,7 +839,7 @@ DRAM_REGION_FUNCTION void HostLink::flushMessagesSentByNanoapp(
 
 DRAM_REGION_FUNCTION void HostMessageHandlers::handleTimeSyncMessage(
     int64_t offset) {
-  LOGE("%s unsupported.", __func__);
+  LOGE("%s is unsupported", __func__);
 }
 
 DRAM_REGION_FUNCTION void HostMessageHandlers::handleDebugDumpRequest(
@@ -868,7 +873,7 @@ DRAM_REGION_FUNCTION void HostMessageHandlers::handleSelfTestRequest(
 
 DRAM_REGION_FUNCTION void HostMessageHandlers::handleNanConfigurationUpdate(
     bool /* enabled */) {
-  LOGE("%s NAN unsupported.", __func__);
+  LOGE("%s is unsupported", __func__);
 }
 
 DRAM_REGION_FUNCTION void sendAudioRequest() {
diff --git a/platform/tinysys/include/chre/target_platform/host_link_base.h b/platform/tinysys/include/chre/target_platform/host_link_base.h
index e148cd2d..09d1b20c 100644
--- a/platform/tinysys/include/chre/target_platform/host_link_base.h
+++ b/platform/tinysys/include/chre/target_platform/host_link_base.h
@@ -105,6 +105,14 @@ class HostLinkBase {
                         size_t /*logMessageSize*/,
                         uint32_t /*num_logs_dropped*/);
 
+  /**
+   * Enqueues a NAN configuration request to be sent to the host.
+   *
+   * @param enable Requests that NAN be enabled or disabled based on the
+   *        boolean's value.
+   */
+  void sendNanConfiguration(bool enable);
+
  private:
   AtomicBool mInitialized = false;
 };
diff --git a/platform/zephyr/CMakeLists.txt b/platform/zephyr/CMakeLists.txt
index a4a3908e..b011f15c 100644
--- a/platform/zephyr/CMakeLists.txt
+++ b/platform/zephyr/CMakeLists.txt
@@ -54,6 +54,7 @@ if(CONFIG_CHRE)
       "${CHRE_DIR}/platform/shared/version.cc"
       "${CHRE_DIR}/platform/shared/system_time.cc"
       "${CHRE_DIR}/util/buffer_base.cc"
+      "${CHRE_DIR}/util/duplicate_message_detector.cc"
       "${CHRE_DIR}/util/dynamic_vector_base.cc"
       "${CHRE_DIR}/util/hash.cc"
   )
diff --git a/platform/zephyr/linker_chre.ld b/platform/zephyr/linker_chre.ld
index 1c46e835..8b879432 100644
--- a/platform/zephyr/linker_chre.ld
+++ b/platform/zephyr/linker_chre.ld
@@ -17,5 +17,4 @@
 SECTION_DATA_PROLOGUE(_CHRE_SECTION,,)
 {
 	KEEP(*(".unstable_id"));
-} GROUP_DATA_LINK_IN(RAMABLE_REGION, ROMABLE_REGION)
-
+} GROUP_ROM_LINK_IN(RAMABLE_REGION, ROMABLE_REGION)
diff --git a/test/simulation/delay_event_test.cc b/test/simulation/delay_event_test.cc
new file mode 100644
index 00000000..196f8f9d
--- /dev/null
+++ b/test/simulation/delay_event_test.cc
@@ -0,0 +1,95 @@
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
+#include <cstdint>
+#include <mutex>
+
+#include "chre/platform/linux/system_time.h"
+
+#include "gtest/gtest.h"
+#include "inc/test_util.h"
+#include "test_base.h"
+#include "test_event.h"
+#include "test_event_queue.h"
+#include "test_util.h"
+
+using ::chre::platform_linux::overrideMonotonicTime;
+using ::chre::platform_linux::SystemTimeOverride;
+
+namespace chre {
+namespace {
+
+CREATE_CHRE_TEST_EVENT(DELAY_EVENT, 0);
+
+constexpr Seconds kDelayEventInterval(2);
+std::mutex gMutex;
+
+class DelayEventNanoapp : public TestNanoapp {
+ public:
+  bool start() override {
+    return true;
+  }
+
+  void handleEvent(uint32_t, uint16_t eventType,
+                   const void *eventData) override {
+    switch (eventType) {
+      case CHRE_EVENT_TEST_EVENT: {
+        auto event = static_cast<const TestEvent *>(eventData);
+        switch (event->type) {
+          case DELAY_EVENT: {
+            std::lock_guard<std::mutex> lock(gMutex);
+
+            if (!hasSeenDelayEvent) {
+              overrideMonotonicTime(SystemTime::getMonotonicTime() +
+                                    kDelayEventInterval);
+              hasSeenDelayEvent = true;
+            }
+            TestEventQueueSingleton::get()->pushEvent(DELAY_EVENT);
+            break;
+          }
+        }
+      }
+    }
+  }
+
+ private:
+  bool hasSeenDelayEvent = false;
+};
+
+TEST_F(TestBase, DelayedEventIsFlagged) {
+  constexpr uint32_t kDelayEventCount = 3;
+  SystemTimeOverride override(0);
+  uint64_t appId = loadNanoapp(MakeUnique<DelayEventNanoapp>());
+
+  testing::internal::CaptureStdout();
+  {
+    std::lock_guard<std::mutex> lock(gMutex);
+    for (uint32_t i = 0; i < kDelayEventCount; ++i) {
+      overrideMonotonicTime(SystemTime::getMonotonicTime() + Nanoseconds(1));
+      sendEventToNanoapp(appId, DELAY_EVENT);
+    }
+  }
+
+  for (uint32_t i = 0; i < kDelayEventCount; ++i) {
+    waitForEvent(DELAY_EVENT);
+  }
+
+  std::string output = testing::internal::GetCapturedStdout();
+  EXPECT_NE(output.find("Delayed event"), std::string::npos);
+}
+
+}  // namespace
+}  // namespace chre
\ No newline at end of file
diff --git a/test/simulation/inc/test_base.h b/test/simulation/inc/test_base.h
index 95ac29c7..6638cd64 100644
--- a/test/simulation/inc/test_base.h
+++ b/test/simulation/inc/test_base.h
@@ -23,17 +23,36 @@
 
 #include "chre/core/event_loop_manager.h"
 #include "chre/core/nanoapp.h"
+#include "chre/platform/system_time.h"
 #include "chre/platform/system_timer.h"
 #include "chre/util/time.h"
 #include "test_event_queue.h"
 
 namespace chre {
 
+// TODO(b/346903946): remove these extra debug logs once issue resolved
+#define CHRE_TEST_DEBUG(fmt, ...)                                        \
+  do {                                                                   \
+    fprintf(stderr, "%" PRIu64 "ns %s: " fmt "\n",                       \
+            SystemTime::getMonotonicTime().toRawNanoseconds(), __func__, \
+            ##__VA_ARGS__);                                              \
+    fprintf(stdout, "%" PRIu64 "ns %s: " fmt "\n",                       \
+            SystemTime::getMonotonicTime().toRawNanoseconds(), __func__, \
+            ##__VA_ARGS__);                                              \
+  } while (0)
+
 /*
  * A base class for all CHRE simulated tests.
  */
 class TestBase : public testing::Test {
  protected:
+  TestBase() {
+    CHRE_TEST_DEBUG("Constructed %p", this);
+  }
+  ~TestBase() {
+    CHRE_TEST_DEBUG("Destroying %p", this);
+  }
+
   void SetUp() override;
   void TearDown() override;
 
@@ -94,6 +113,17 @@ class TestBase : public testing::Test {
     return nanoapp;
   }
 
+  class MemberInitLogger {
+   public:
+    MemberInitLogger() {
+      CHRE_TEST_DEBUG("Construction start");
+    }
+    ~MemberInitLogger() {
+      CHRE_TEST_DEBUG("Destruction finished");
+    }
+  };
+
+  MemberInitLogger mInitLogger;
   std::thread mChreThread;
   SystemTimer mSystemTimer;
 };
diff --git a/test/simulation/wifi_scan_test.cc b/test/simulation/wifi_scan_test.cc
index 70bfa7c9..1940e075 100644
--- a/test/simulation/wifi_scan_test.cc
+++ b/test/simulation/wifi_scan_test.cc
@@ -32,6 +32,7 @@
 
 namespace chre {
 namespace {
+using namespace std::chrono_literals;
 
 CREATE_CHRE_TEST_EVENT(SCAN_REQUEST, 20);
 
@@ -49,13 +50,13 @@ class WifiScanRequestQueueTestBase : public TestBase {
     TestBase::SetUp();
     // Add delay to make sure the requests are queued.
     chrePalWifiDelayResponse(PalWifiAsyncRequestTypes::SCAN,
-                             std::chrono::seconds(1));
+                             /* milliseconds= */ 100ms);
   }
 
   void TearDown() {
     TestBase::TearDown();
     chrePalWifiDelayResponse(PalWifiAsyncRequestTypes::SCAN,
-                             std::chrono::seconds(0));
+                             /* milliseconds= */ 0ms);
   }
 };
 
diff --git a/tools/get_padded_memsize.sh b/tools/get_padded_memsize.sh
new file mode 100755
index 00000000..6a10066b
--- /dev/null
+++ b/tools/get_padded_memsize.sh
@@ -0,0 +1,76 @@
+#!/bin/bash
+
+#
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+#
+
+# Usage
+# ./get_padded_memsize.sh <TINYSYS/SLPI/QSH> <obj_name>
+
+# Quit if any command produces an error.
+set -e
+
+# Parse variables
+PLATFORM=$1
+PLATFORM_NOT_CORRECT_STR="You must specify the platform being analyzed. Should be TINYSYS, QSH, or SLPI"
+: ${PLATFORM:?$PLATFORM_NOT_CORRECT_STR}
+if [ "$PLATFORM" != "TINYSYS" ] && [ "$PLATFORM" != "SLPI" ] && [ "$PLATFORM" != "QSH" ]; then
+  echo $PLATFORM_NOT_CORRECT_STR
+  exit 1
+fi
+
+OBJ=$2
+: ${OBJ:?"You must specify the .so to size."}
+
+# Setup required paths and obtain segments
+if [ "$PLATFORM" == "TINYSYS" ]; then
+  : ${RISCV_TOOLCHAIN_PATH}:?"Set RISCV_TOOLCHAIN_PATH, e.g. prebuilts/clang/md32rv/linux-x86"
+  READELF_PATH="$RISCV_TOOLCHAIN_PATH/bin/llvm-readelf"
+elif [ "$PLATFORM" == "SLPI" ] || [ "$PLATFORM" == "QSH" ]; then
+  : ${HEXAGON_TOOLS_PREFIX:?"Set HEXAGON_TOOLS_PREFIX, e.g. export HEXAGON_TOOLS_PREFIX=\$HOME/Qualcomm/HEXAGON_Tools/8.1.04"}
+  READELF_PATH="$HEXAGON_TOOLS_PREFIX/Tools/bin/hexagon-readelf"
+else
+  READELF_PATH="readelf"
+fi
+
+SEGMENTS="$($READELF_PATH -l $OBJ | grep LOAD)"
+
+# Save current IFS to restore later.
+CURR_IFS=$IFS
+
+printf "\n$OBJ\n"
+TOTAL=0
+IFS=$'\n'
+for LINE in $SEGMENTS; do
+  # Headers: Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
+  IFS=" " HEADERS=(${LINE})
+  LEN=${#HEADERS[@]}
+
+  MEMSIZE=$(( HEADERS[5] ))
+  # Flg can have a space in it, 'R E', for example.
+  ALIGN=$(( HEADERS[LEN - 1] ))
+  # Rounded up to the next integral multiple of Align.
+  QUOTIENT=$(( (MEMSIZE + ALIGN - 1) / ALIGN ))
+  PADDED=$(( ALIGN * QUOTIENT ))
+  PADDING=$(( PADDED - MEMSIZE ))
+
+  printf '  MemSize:0x%x Align:0x%x Padded:0x%x Padding:%d\n' $MEMSIZE $ALIGN $PADDED $PADDING
+  TOTAL=$(( TOTAL + PADDED ))
+done
+
+IFS=$CURR_IFS
+printf 'Total Padded MemSize: 0x%x (%d)\n' $TOTAL $TOTAL
+
diff --git a/util/duplicate_message_detector.cc b/util/duplicate_message_detector.cc
new file mode 100644
index 00000000..dd1e3784
--- /dev/null
+++ b/util/duplicate_message_detector.cc
@@ -0,0 +1,102 @@
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
+#include "chre/util/duplicate_message_detector.h"
+
+#include "chre/platform/system_time.h"
+
+#include <cstdint>
+
+namespace chre {
+
+Optional<chreError> DuplicateMessageDetector::findOrAdd(
+    uint32_t messageSequenceNumber, uint16_t hostEndpoint,
+    bool *outIsDuplicate) {
+  DuplicateMessageDetector::ReliableMessageRecord *record =
+      findLocked(messageSequenceNumber, hostEndpoint);
+  if (outIsDuplicate != nullptr) {
+    *outIsDuplicate = record != nullptr;
+  }
+
+  if (record == nullptr) {
+    record = addLocked(messageSequenceNumber, hostEndpoint);
+    if (record == nullptr) {
+      LOG_OOM();
+      if (outIsDuplicate != nullptr) {
+        *outIsDuplicate = true;
+      }
+      return CHRE_ERROR_NO_MEMORY;
+    }
+  }
+  return record->error;
+}
+
+bool DuplicateMessageDetector::findAndSetError(uint32_t messageSequenceNumber,
+                                               uint16_t hostEndpoint,
+                                               chreError error) {
+  DuplicateMessageDetector::ReliableMessageRecord *record =
+      findLocked(messageSequenceNumber, hostEndpoint);
+  if (record == nullptr) {
+    return false;
+  }
+
+  record->error = error;
+  return true;
+}
+
+void DuplicateMessageDetector::removeOldEntries() {
+  Nanoseconds now = SystemTime::getMonotonicTime();
+  while (!mReliableMessageRecordQueue.empty()) {
+    ReliableMessageRecord &record = mReliableMessageRecordQueue.top();
+    if (record.timestamp + kTimeout <= now) {
+      mReliableMessageRecordQueue.pop();
+    } else {
+      break;
+    }
+  }
+}
+
+DuplicateMessageDetector::ReliableMessageRecord*
+    DuplicateMessageDetector::addLocked(
+        uint32_t messageSequenceNumber,
+        uint16_t hostEndpoint) {
+  bool success = mReliableMessageRecordQueue.push(
+      ReliableMessageRecord{
+          .timestamp = SystemTime::getMonotonicTime(),
+          .messageSequenceNumber = messageSequenceNumber,
+          .hostEndpoint = hostEndpoint,
+          .error = Optional<chreError>()});
+  return success
+      ? findLocked(messageSequenceNumber, hostEndpoint, /* reverse= */ true)
+      : nullptr;
+}
+
+DuplicateMessageDetector::ReliableMessageRecord*
+  DuplicateMessageDetector::findLocked(uint32_t messageSequenceNumber,
+                                       uint16_t hostEndpoint,
+                                       bool reverse) {
+  for (size_t i = 0; i < mReliableMessageRecordQueue.size(); ++i) {
+    size_t index = reverse ? mReliableMessageRecordQueue.size() - i - 1 : i;
+    ReliableMessageRecord &record = mReliableMessageRecordQueue[index];
+    if (record.messageSequenceNumber == messageSequenceNumber &&
+        record.hostEndpoint == hostEndpoint) {
+      return &record;
+    }
+  }
+  return nullptr;
+}
+
+}  // namespace chre
diff --git a/util/include/chre/util/array_queue.h b/util/include/chre/util/array_queue.h
index f19700f7..2be174e9 100644
--- a/util/include/chre/util/array_queue.h
+++ b/util/include/chre/util/array_queue.h
@@ -428,6 +428,6 @@ class ArrayQueueIterator {
 
 }  // namespace chre
 
-#include "chre/util/array_queue_impl.h"
+#include "chre/util/array_queue_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_ARRAY_QUEUE_H_
diff --git a/util/include/chre/util/array_queue_impl.h b/util/include/chre/util/array_queue_impl.h
index 58179c80..aa466b75 100644
--- a/util/include/chre/util/array_queue_impl.h
+++ b/util/include/chre/util/array_queue_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_ARRAY_QUEUE_IMPL_H_
 #define CHRE_UTIL_ARRAY_QUEUE_IMPL_H_
 
+// IWYU pragma: private
 #include <new>
 #include <utility>
 
diff --git a/util/include/chre/util/buffer.h b/util/include/chre/util/buffer.h
index af3101b4..5a2dce71 100644
--- a/util/include/chre/util/buffer.h
+++ b/util/include/chre/util/buffer.h
@@ -67,7 +67,7 @@ class Buffer : private BufferBase {
    * this object will not attempt to free the memory itself.
    *
    * @param buffer A pointer to a pre-allocated array.
-   * @param size The number of elements in the array.
+   * @param size The number of elements in the array. Maximum supported is 2^31.
    */
   void wrap(ElementType *buffer, size_t size) {
     BufferBase::wrap(buffer, size);
@@ -83,7 +83,7 @@ class Buffer : private BufferBase {
    * returned.
    *
    * @param buffer A pointer to an array to copy.
-   * @param size The number of elements in the array.
+   * @param size The number of elements in the array. Maximum supported is 2^31.
    * @return true if capacity was reserved to fit the supplied buffer and the
    *         supplied buffer was copied into the internal buffer of this object,
    *         or if the supplied input is empty, false otherwise.
diff --git a/util/include/chre/util/buffer_base.h b/util/include/chre/util/buffer_base.h
index a9db3153..8846238d 100644
--- a/util/include/chre/util/buffer_base.h
+++ b/util/include/chre/util/buffer_base.h
@@ -25,6 +25,8 @@ namespace chre {
 
 class BufferBase : public NonCopyable {
  protected:
+  BufferBase() : mBuffer(nullptr), mSize(0), mBufferRequiresFree(false) {}
+
   /**
    * Cleans up for the buffer. If the buffer is currently owned by this object,
    * it is released.
@@ -32,13 +34,13 @@ class BufferBase : public NonCopyable {
   ~BufferBase();
 
   //! The buffer to manage.
-  void *mBuffer = nullptr;
+  void *mBuffer;
 
   //! The number of elements in the buffer.
-  size_t mSize = 0;
+  size_t mSize : 31;
 
   //! Set to true when mBuffer needs to be released by the destructor.
-  bool mBufferRequiresFree = false;
+  bool mBufferRequiresFree : 1;
 
   /**
    * @see Buffer::wrap.
diff --git a/util/include/chre/util/conditional_lock_guard.h b/util/include/chre/util/conditional_lock_guard.h
index 2304a528..8430e908 100644
--- a/util/include/chre/util/conditional_lock_guard.h
+++ b/util/include/chre/util/conditional_lock_guard.h
@@ -45,6 +45,6 @@ class ConditionalLockGuard : public NonCopyable {
 
 }  // namespace chre
 
-#include "chre/util/conditional_lock_guard_impl.h"
+#include "chre/util/conditional_lock_guard_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_CONDITIONAL_LOCK_GUARD_H_
diff --git a/util/include/chre/util/conditional_lock_guard_impl.h b/util/include/chre/util/conditional_lock_guard_impl.h
index 3debd5a1..ab1abe8a 100644
--- a/util/include/chre/util/conditional_lock_guard_impl.h
+++ b/util/include/chre/util/conditional_lock_guard_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_CONDITIONAL_LOCK_GUARD_IMPL_H_
 #define CHRE_UTIL_CONDITIONAL_LOCK_GUARD_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/util/conditional_lock_guard.h"
 
 namespace chre {
diff --git a/util/include/chre/util/container_support.h b/util/include/chre/util/container_support.h
index 93ff8e00..546c00bf 100644
--- a/util/include/chre/util/container_support.h
+++ b/util/include/chre/util/container_support.h
@@ -47,11 +47,19 @@ inline void *memoryAlloc(size_t size) {
   return chreHeapAlloc(static_cast<uint32_t>(size));
 }
 
+/**
+ * Returns memory of suitable alignment to hold an array of the given object
+ * type, which may exceed alignment of std::max_align_t and therefore cannot
+ * use memoryAlloc().
+ *
+ * @param count the number of elements to allocate.
+ * @return a pointer to allocated memory or nullptr if allocation failed.
+ */
 template <typename T>
-inline T *memoryAlignedAlloc() {
+inline T *memoryAlignedAllocArray([[maybe_unused]] size_t count) {
 #ifdef CHRE_STANDALONE_POSIX_ALIGNED_ALLOC
   void *ptr;
-  int result = posix_memalign(&ptr, alignof(T), sizeof(T));
+  int result = posix_memalign(&ptr, alignof(T), sizeof(T) * count);
   if (result != 0) {
     ptr = nullptr;
   }
@@ -63,6 +71,18 @@ inline T *memoryAlignedAlloc() {
 #endif  // CHRE_STANDALONE_POSIX_ALIGNED_ALLOC
 }
 
+/**
+ * Returns memory of suitable alignment to hold a given object of the
+ * type T, which may exceed alignment of std::max_align_t and therefore cannot
+ * use memoryAlloc().
+ *
+ * @return a pointer to allocated memory or nullptr if allocation failed.
+ */
+template <typename T>
+inline T *memoryAlignedAlloc() {
+  return memoryAlignedAllocArray<T>(/* count= */ 1);
+}
+
 /**
  * Provides the memoryFree function that is normally provided by the CHRE
  * runtime. It maps into chreHeapFree.
@@ -81,20 +101,53 @@ inline void memoryFree(void *pointer) {
 
 namespace chre {
 
+/**
+ * Provides the memoryAlloc function that is normally provided by the CHRE
+ * runtime. It maps into malloc.
+ *
+ * @param size the size of the allocation to make.
+ * @return a pointer to allocated memory or nullptr if allocation failed.
+ */
 inline void *memoryAlloc(size_t size) {
   return malloc(size);
 }
 
+/**
+ * Returns memory of suitable alignment to hold an array of the given object
+ * type, which may exceed alignment of std::max_align_t and therefore cannot
+ * use memoryAlloc().
+ *
+ * @param count the number of elements to allocate.
+ * @return a pointer to allocated memory or nullptr if allocation failed.
+ */
 template <typename T>
-inline T *memoryAlignedAlloc() {
+inline T *memoryAlignedAllocArray(size_t count) {
   void *ptr;
-  int result = posix_memalign(&ptr, alignof(T), sizeof(T));
+  int result = posix_memalign(&ptr, alignof(T), sizeof(T) * count);
   if (result != 0) {
     ptr = nullptr;
   }
   return static_cast<T *>(ptr);
 }
 
+/**
+ * Returns memory of suitable alignment to hold a given object of the
+ * type T, which may exceed alignment of std::max_align_t and therefore cannot
+ * use memoryAlloc().
+ *
+ * @return a pointer to allocated memory or nullptr if allocation failed.
+ */
+template <typename T>
+inline T *memoryAlignedAlloc() {
+  return memoryAlignedAllocArray<T>(/* count= */1);
+}
+
+/**
+ * Provides the memoryFree function that is normally provided by the CHRE
+ * runtime. It maps into free.
+ *
+ * @param pointer the allocation to release.
+ */
 inline void memoryFree(void *pointer) {
   free(pointer);
 }
diff --git a/util/include/chre/util/duplicate_message_detector.h b/util/include/chre/util/duplicate_message_detector.h
new file mode 100644
index 00000000..176f3d2e
--- /dev/null
+++ b/util/include/chre/util/duplicate_message_detector.h
@@ -0,0 +1,111 @@
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
+#ifndef CHRE_UTIL_DUPLICATE_MESSAGE_DETECTOR_H_
+#define CHRE_UTIL_DUPLICATE_MESSAGE_DETECTOR_H_
+
+#include "chre/util/non_copyable.h"
+#include "chre/util/optional.h"
+#include "chre/util/priority_queue.h"
+#include "chre/util/time.h"
+#include "chre_api/chre.h"
+
+#include <functional>
+
+namespace chre {
+
+/**
+ * This class is used to detect duplicate reliable messages. It keeps a record
+ * of all reliable messages that have been sent from the host. If a message with
+ * the same message sequence number and host endpoint is sent again, it is
+ * considered a duplicate. This class is not thread-safe.
+ *
+ * A typical usage of this class would be as follows:
+ *
+ * Call findOrAdd() to add a new message to the detector. If the message is a
+ * duplicate, the detector will return the error code previously recorded.
+ * If the message is not a duplicate, the detector will return an empty
+ * Optional.
+ *
+ * Call findAndSetError() to set the error code for a message that has already
+ * been added to the detector.
+ *
+ * Call removeOldEntries() to remove any messages that have been in the detector
+ * for longer than the timeout specified in the constructor.
+ */
+class DuplicateMessageDetector : public NonCopyable {
+ public:
+  struct ReliableMessageRecord {
+    Nanoseconds timestamp;
+    uint32_t messageSequenceNumber;
+    uint16_t hostEndpoint;
+    Optional<chreError> error;
+
+    inline bool operator>(const ReliableMessageRecord &rhs) const {
+      return timestamp > rhs.timestamp;
+    }
+  };
+
+  DuplicateMessageDetector() = delete;
+  DuplicateMessageDetector(Nanoseconds timeout):
+      kTimeout(timeout) {}
+  ~DuplicateMessageDetector() = default;
+
+  //! Finds the message with the given message sequence number and host
+  //! endpoint. If the message is not found, a new message is added to the
+  //! detector. Returns the error code previously recorded for the message, or
+  //! an empty Optional if the message is not a duplicate. If outIsDuplicate is
+  //! not nullptr, it will be set to true if the message is a duplicate (was
+  //! found), or false otherwise.
+  Optional<chreError> findOrAdd(uint32_t messageSequenceNumber,
+                                uint16_t hostEndpoint,
+                                bool *outIsDuplicate = nullptr);
+
+  //! Sets the error code for a message that has already been added to the
+  //! detector. Returns true if the message was found and the error code was
+  //! set, or false if the message was not found.
+  bool findAndSetError(uint32_t messageSequenceNumber, uint16_t hostEndpoint,
+                       chreError error);
+
+  //! Removes any messages that have been in the detector for longer than the
+  //! timeout specified in the constructor.
+  void removeOldEntries();
+
+ private:
+  //! The timeout specified in the constructor. This should be the reliable
+  //! message timeout.
+  Nanoseconds kTimeout;
+
+  //! The queue of reliable message records.
+  PriorityQueue<ReliableMessageRecord, std::greater<ReliableMessageRecord>>
+      mReliableMessageRecordQueue;
+
+  //! Adds a new message to the detector. Returns the message record, or nullptr
+  //! if the message could not be added. Not thread safe.
+  ReliableMessageRecord *addLocked(uint32_t messageSequenceNumber,
+                                   uint16_t hostEndpoint);
+
+  //! Finds the message with the given message sequence number and host
+  //! endpoint, else returns nullptr. Not thread safe. If reverse is true,
+  //! this function searches from the end of the queue.
+  ReliableMessageRecord *findLocked(uint32_t messageSequenceNumber,
+                                    uint16_t hostEndpoint,
+                                    bool reverse = false);
+};
+
+}  // namespace chre
+
+#endif  // CHRE_UTIL_DUPLICATE_MESSAGE_DETECTOR_H_
diff --git a/util/include/chre/util/dynamic_vector.h b/util/include/chre/util/dynamic_vector.h
index a5d669ef..680a0231 100644
--- a/util/include/chre/util/dynamic_vector.h
+++ b/util/include/chre/util/dynamic_vector.h
@@ -369,6 +369,6 @@ class DynamicVector : private DynamicVectorBase {
 
 }  // namespace chre
 
-#include "chre/util/dynamic_vector_impl.h"
+#include "chre/util/dynamic_vector_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_DYNAMIC_VECTOR_H_
diff --git a/util/include/chre/util/dynamic_vector_impl.h b/util/include/chre/util/dynamic_vector_impl.h
index 4ce6e7df..219de998 100644
--- a/util/include/chre/util/dynamic_vector_impl.h
+++ b/util/include/chre/util/dynamic_vector_impl.h
@@ -17,8 +17,10 @@
 #ifndef CHRE_UTIL_DYNAMIC_VECTOR_IMPL_H_
 #define CHRE_UTIL_DYNAMIC_VECTOR_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/util/dynamic_vector.h"
 
+#include <cstddef>
 #include <memory>
 #include <new>
 #include <utility>
@@ -105,6 +107,10 @@ bool DynamicVector<ElementType>::push_back(const ElementType &element) {
 template <typename ElementType>
 bool DynamicVector<ElementType>::doPushBack(const ElementType &element,
                                             std::true_type) {
+  if constexpr (alignof(ElementType) > alignof(std::max_align_t)) {
+    // This type requires aligned allocation, so use the non-trivial doPushBack.
+    return doPushBack(element, std::false_type());
+  }
   return DynamicVectorBase::doPushBack(static_cast<const void *>(&element),
                                        sizeof(ElementType));
 }
@@ -132,7 +138,7 @@ bool DynamicVector<ElementType>::push_back(ElementType &&element) {
 
 template <typename ElementType>
 template <typename... Args>
-bool DynamicVector<ElementType>::emplace_back(Args &&... args) {
+bool DynamicVector<ElementType>::emplace_back(Args &&...args) {
   bool spaceAvailable = prepareForPush();
   if (spaceAvailable) {
     new (&data()[mSize++]) ElementType(std::forward<Args>(args)...);
@@ -178,6 +184,10 @@ bool DynamicVector<ElementType>::reserve(size_type newCapacity) {
 template <typename ElementType>
 bool DynamicVector<ElementType>::doReserve(size_type newCapacity,
                                            std::true_type) {
+  if constexpr (alignof(ElementType) > alignof(std::max_align_t)) {
+    // This type requires aligned allocation, so use the non-trivial reserve.
+    return doReserve(newCapacity, std::false_type());
+  }
   return DynamicVectorBase::doReserve(newCapacity, sizeof(ElementType));
 }
 
@@ -186,8 +196,14 @@ bool DynamicVector<ElementType>::doReserve(size_type newCapacity,
                                            std::false_type) {
   bool success = (newCapacity <= mCapacity);
   if (!success) {
-    ElementType *newData = static_cast<ElementType *>(
-        memoryAlloc(newCapacity * sizeof(ElementType)));
+    ElementType *newData;
+    if constexpr (alignof(ElementType) > alignof(std::max_align_t)) {
+      newData = memoryAlignedAllocArray<ElementType>(newCapacity);
+    } else {
+      newData = static_cast<ElementType *>(
+          memoryAlloc(newCapacity * sizeof(ElementType)));
+    }
+
     if (newData != nullptr) {
       if (data() != nullptr) {
         uninitializedMoveOrCopy(data(), mSize, newData);
@@ -347,6 +363,11 @@ bool DynamicVector<ElementType>::prepareForPush() {
 
 template <typename ElementType>
 bool DynamicVector<ElementType>::doPrepareForPush(std::true_type) {
+  if constexpr (alignof(ElementType) > alignof(std::max_align_t)) {
+    // This type requires aligned allocation, so use the non-trivial
+    // doPrepareForPush.
+    return doPrepareForPush(std::false_type());
+  }
   return DynamicVectorBase::doPrepareForPush(sizeof(ElementType));
 }
 
diff --git a/util/include/chre/util/fixed_size_blocking_queue.h b/util/include/chre/util/fixed_size_blocking_queue.h
index 71634972..58277fe6 100644
--- a/util/include/chre/util/fixed_size_blocking_queue.h
+++ b/util/include/chre/util/fixed_size_blocking_queue.h
@@ -120,6 +120,6 @@ class FixedSizeBlockingQueue
 
 }  // namespace chre
 
-#include "chre/util/fixed_size_blocking_queue_impl.h"
+#include "chre/util/fixed_size_blocking_queue_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_FIXED_SIZE_BLOCKING_QUEUE_H_
diff --git a/util/include/chre/util/fixed_size_blocking_queue_impl.h b/util/include/chre/util/fixed_size_blocking_queue_impl.h
index ec161c07..43911df8 100644
--- a/util/include/chre/util/fixed_size_blocking_queue_impl.h
+++ b/util/include/chre/util/fixed_size_blocking_queue_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_FIXED_SIZE_BLOCKING_QUEUE_IMPL_H_
 #define CHRE_UTIL_FIXED_SIZE_BLOCKING_QUEUE_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/util/fixed_size_blocking_queue.h"
 #include "chre/util/lock_guard.h"
 
diff --git a/util/include/chre/util/fixed_size_vector.h b/util/include/chre/util/fixed_size_vector.h
index 9f9d6cd4..91658e13 100644
--- a/util/include/chre/util/fixed_size_vector.h
+++ b/util/include/chre/util/fixed_size_vector.h
@@ -211,6 +211,6 @@ class FixedSizeVector : public NonCopyable {
 
 }  // namespace chre
 
-#include "chre/util/fixed_size_vector_impl.h"
+#include "chre/util/fixed_size_vector_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_FIXED_SIZE_VECTOR_H_
diff --git a/util/include/chre/util/fixed_size_vector_impl.h b/util/include/chre/util/fixed_size_vector_impl.h
index 0c3853d7..d6d4112b 100644
--- a/util/include/chre/util/fixed_size_vector_impl.h
+++ b/util/include/chre/util/fixed_size_vector_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_FIXED_SIZE_VECTOR_IMPL_H_
 #define CHRE_UTIL_FIXED_SIZE_VECTOR_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/util/fixed_size_vector.h"
 
 #include <new>
diff --git a/util/include/chre/util/fragmentation_manager.h b/util/include/chre/util/fragmentation_manager.h
new file mode 100644
index 00000000..02e26eff
--- /dev/null
+++ b/util/include/chre/util/fragmentation_manager.h
@@ -0,0 +1,113 @@
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
+#ifndef CHRE_UTIL_FRAGMENTATION_MANAGER
+#define CHRE_UTIL_FRAGMENTATION_MANAGER
+#include <stddef.h>
+#include <type_traits>
+#include "chre/util/optional.h"
+namespace chre {
+
+/**
+ * Structure representing a fragment of continuous data.
+ *
+ * @tparam ObjectType the type of the data.
+ *
+ * @param data pointer to the start of the data.
+ * @param size number of count of the data.
+ */
+template <typename ObjectType>
+struct Fragment {
+  ObjectType *data;
+  size_t size;
+  Fragment(ObjectType *data_, size_t size_) : data(data_), size(size_) {}
+};
+
+/**
+ * A data structure designed to partition continuous sequences of data into
+ * manageable fragments.
+ *
+ * This class is particularly useful when dealing with large datasets, allowing
+ * for efficient processing. Each fragment represents a contiguous subset of the
+ * original data, with the size of each fragment determined by the
+ * @c fragmentSize parameter besides the last fragment. The last fragment might
+ * have less data then @c fragmentSize if there is no enough data left.
+ * It is also the creator's responsibility to make sure that the data is alive
+ * during the usage of FragmentationManager since FragmentationManager does not
+ * keep a copy of the data.
+ *
+ * @tparam ObjectType The specific type of data element (object) to be stored
+ * within this structure.
+ * @tparam fragmentSize The number of @c ObjectType elements that constitute a
+ * single fragment.
+ */
+template <typename ObjectType, size_t fragmentSize>
+class FragmentationManager {
+ public:
+  /**
+   * Initializes the fragmentation manager, partitioning a continuous block of
+   * data into fragments.
+   *
+   * @param dataSource A raw pointer to pointing to the beginning of the
+   * continuous data block to be fragmented.
+   * @param dataSize The total number of bytes in the dataSource.
+   *
+   * @return false if dataSource is initialized with a nullptr; otherwise true.
+   */
+  bool init(ObjectType *dataSource, size_t dataSize);
+
+  /**
+   * Deinitializes the fragmentation manager.
+   */
+  void deinit();
+
+  /**
+   * Retrieves the next available data fragment.
+   *
+   * @return a @c Fragment with @c data pointing to the address of the
+   * fragment's data; @c size with the size of the fragment. If there is no more
+   * fragments, return an empty optional.
+   */
+  Optional<Fragment<ObjectType>> getNextFragment();
+
+  /**
+   * @return the number of fragments that have been emitted so far.
+   */
+  size_t getEmittedFragmentedCount() {
+    return mEmittedFragment;
+  }
+  /**
+   * @return True if all fragments have been emitted.
+
+   */
+  bool hasNoMoreFragment() {
+    return mEmittedFragment * fragmentSize >= mDataSize;
+  }
+
+ private:
+  // A pointer to the beginning of the continuous block of data being
+  // fragmented.
+  ObjectType *mData;
+  // The number of bytes in the 'mData' block.
+  size_t mDataSize;
+  // The number of fragments that have been emitted.
+  size_t mEmittedFragment;
+};
+}  // namespace chre
+
+#include "chre/util/fragmentation_manager_impl.h"  // IWYU pragma: export
+
+#endif  // CHRE_UTIL_FRAGMENTATION_MANAGER
diff --git a/util/include/chre/util/fragmentation_manager_impl.h b/util/include/chre/util/fragmentation_manager_impl.h
new file mode 100644
index 00000000..bc6a25dc
--- /dev/null
+++ b/util/include/chre/util/fragmentation_manager_impl.h
@@ -0,0 +1,63 @@
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
+#ifndef CHRE_UTIL_FRAGMENTATION_MANAGER_IMPL
+#define CHRE_UTIL_FRAGMENTATION_MANAGER_IMPL
+
+// IWYU pragma: private
+#include "chre/util/fragmentation_manager.h"
+#include "chre/util/optional.h"
+
+namespace chre {
+
+template <typename ObjectType, size_t fragmentSize>
+bool FragmentationManager<ObjectType, fragmentSize>::init(
+    ObjectType *dataSource, size_t dataSize) {
+  if (dataSource == nullptr) {
+    return false;
+  }
+  mData = dataSource;
+  mDataSize = dataSize;
+  mEmittedFragment = 0;
+  return true;
+}
+
+template <typename ObjectType, size_t fragmentSize>
+void FragmentationManager<ObjectType, fragmentSize>::deinit() {
+  mData = nullptr;
+  mDataSize = 0;
+  mEmittedFragment = 0;
+}
+
+template <typename ObjectType, size_t fragmentSize>
+Optional<Fragment<ObjectType>>
+FragmentationManager<ObjectType, fragmentSize>::getNextFragment() {
+  if (hasNoMoreFragment()) {
+    return Optional<Fragment<ObjectType>>();
+  }
+  size_t currentFragmentSize = fragmentSize;
+  // Special case to calculate the size of the last fragment.
+  if ((mEmittedFragment + 1) * fragmentSize > mDataSize) {
+    currentFragmentSize = mDataSize % fragmentSize;
+  }
+  Fragment<ObjectType> fragment(mData + mEmittedFragment * fragmentSize,
+                                currentFragmentSize);
+  ++mEmittedFragment;
+  return fragment;
+}
+
+}  // namespace chre
+#endif  // CHRE_UTIL_FRAGMENTATION_MANAGER_IMPL
diff --git a/util/include/chre/util/heap_impl.h b/util/include/chre/util/heap_impl.h
index 2cca4451..3f875e9c 100644
--- a/util/include/chre/util/heap_impl.h
+++ b/util/include/chre/util/heap_impl.h
@@ -14,10 +14,10 @@
  * limitations under the License.
  */
 
-// IWYU pragma: private, include "heap.h"
 #ifndef CHRE_UTIL_HEAP_IMPL_H_
 #define CHRE_UTIL_HEAP_IMPL_H_
 
+// IWYU pragma: private
 #include <utility>
 
 #include "chre/util/container_support.h"
diff --git a/util/include/chre/util/intrusive_list.h b/util/include/chre/util/intrusive_list.h
index 77709f20..4a394d16 100644
--- a/util/include/chre/util/intrusive_list.h
+++ b/util/include/chre/util/intrusive_list.h
@@ -60,6 +60,15 @@ struct ListNode {
   ~ListNode() {
     CHRE_ASSERT(node.prev == nullptr && node.next == nullptr);
   }
+
+  /**
+   * Checks if this list node is linked in a list.
+   *
+   * @return true if the list node is part of a list.
+   */
+  bool isLinked() const {
+    return node.prev != nullptr && node.next != nullptr;
+  }
 };
 
 /**
@@ -239,6 +248,6 @@ class IntrusiveList : private intrusive_list_internal::IntrusiveListBase {
 
 }  // namespace chre
 
-#include "chre/util/intrusive_list_impl.h"
+#include "chre/util/intrusive_list_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_INTRUSIVE_LIST_H_
diff --git a/util/include/chre/util/intrusive_list_impl.h b/util/include/chre/util/intrusive_list_impl.h
index 61ee095b..cce121df 100644
--- a/util/include/chre/util/intrusive_list_impl.h
+++ b/util/include/chre/util/intrusive_list_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_INTRUSIVE_LIST_IMPL_H_
 #define CHRE_UTIL_INTRUSIVE_LIST_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/util/intrusive_list.h"
 
 #include "chre/util/container_support.h"
diff --git a/util/include/chre/util/lock_guard.h b/util/include/chre/util/lock_guard.h
index 46763796..7f51e0df 100644
--- a/util/include/chre/util/lock_guard.h
+++ b/util/include/chre/util/lock_guard.h
@@ -46,6 +46,6 @@ class LockGuard : public NonCopyable {
 
 }  // namespace chre
 
-#include "chre/util/lock_guard_impl.h"
+#include "chre/util/lock_guard_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_LOCK_GUARD_H_
diff --git a/util/include/chre/util/lock_guard_impl.h b/util/include/chre/util/lock_guard_impl.h
index 218bb88b..7656ac05 100644
--- a/util/include/chre/util/lock_guard_impl.h
+++ b/util/include/chre/util/lock_guard_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_LOCK_GUARD_IMPL_H_
 #define CHRE_UTIL_LOCK_GUARD_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/util/lock_guard.h"
 
 namespace chre {
diff --git a/util/include/chre/util/memory.h b/util/include/chre/util/memory.h
index 7082b33b..a420a08c 100644
--- a/util/include/chre/util/memory.h
+++ b/util/include/chre/util/memory.h
@@ -78,6 +78,6 @@ void memoryFreeAndDestroy(T *element);
 
 }  // namespace chre
 
-#include "chre/util/memory_impl.h"
+#include "chre/util/memory_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_MEMORY_H
diff --git a/util/include/chre/util/memory_impl.h b/util/include/chre/util/memory_impl.h
index 85c97fcb..96f08ca1 100644
--- a/util/include/chre/util/memory_impl.h
+++ b/util/include/chre/util/memory_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_MEMORY_IMPL_H_
 #define CHRE_UTIL_MEMORY_IMPL_H_
 
+// IWYU pragma: private
 #include <cstring>
 #include <new>
 #include <type_traits>
diff --git a/util/include/chre/util/memory_pool.h b/util/include/chre/util/memory_pool.h
index 802fc036..4d4f4a5f 100644
--- a/util/include/chre/util/memory_pool.h
+++ b/util/include/chre/util/memory_pool.h
@@ -191,6 +191,6 @@ class MemoryPool : public NonCopyable {
 
 }  // namespace chre
 
-#include "chre/util/memory_pool_impl.h"
+#include "chre/util/memory_pool_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_MEMORY_POOL_H_
diff --git a/util/include/chre/util/memory_pool_impl.h b/util/include/chre/util/memory_pool_impl.h
index b126a3d0..12531965 100644
--- a/util/include/chre/util/memory_pool_impl.h
+++ b/util/include/chre/util/memory_pool_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_MEMORY_POOL_IMPL_H_
 #define CHRE_UTIL_MEMORY_POOL_IMPL_H_
 
+// IWYU pragma: private
 #include <cinttypes>
 #include <type_traits>
 #include <utility>
diff --git a/util/include/chre/util/optional.h b/util/include/chre/util/optional.h
index 4437b73e..d3fc0923 100644
--- a/util/include/chre/util/optional.h
+++ b/util/include/chre/util/optional.h
@@ -180,6 +180,6 @@ class Optional {
 
 }  // namespace chre
 
-#include "chre/util/optional_impl.h"
+#include "chre/util/optional_impl.h"  // IWYU pragma: export
 
 #endif  // UTIL_CHRE_OPTIONAL_H_
diff --git a/util/include/chre/util/optional_impl.h b/util/include/chre/util/optional_impl.h
index cc9834d8..86bb478a 100644
--- a/util/include/chre/util/optional_impl.h
+++ b/util/include/chre/util/optional_impl.h
@@ -17,6 +17,7 @@
 #ifndef UTIL_CHRE_OPTIONAL_IMPL_H_
 #define UTIL_CHRE_OPTIONAL_IMPL_H_
 
+// IWYU pragma: private
 #include <new>
 #include <utility>
 
diff --git a/util/include/chre/util/pigweed/rpc_client.h b/util/include/chre/util/pigweed/rpc_client.h
index 4920b648..44b05ff0 100644
--- a/util/include/chre/util/pigweed/rpc_client.h
+++ b/util/include/chre/util/pigweed/rpc_client.h
@@ -128,7 +128,9 @@ Optional<T> RpcClient::get() {
 
     mChannelId = chreGetInstanceId();
     mChannelOutput.setServer(info.instanceId);
-    mRpcClient.OpenChannel(mChannelId, mChannelOutput);
+    if (!mRpcClient.OpenChannel(mChannelId, mChannelOutput).ok()) {
+      return Optional<T>();
+    }
   }
 
   chreConfigureNanoappInfoEvents(true);
@@ -137,4 +139,4 @@ Optional<T> RpcClient::get() {
 
 }  // namespace chre
 
-#endif  // CHRE_UTIL_PIGWEED_RPC_SERVER_H_
\ No newline at end of file
+#endif  // CHRE_UTIL_PIGWEED_RPC_SERVER_H_
diff --git a/util/include/chre/util/priority_queue.h b/util/include/chre/util/priority_queue.h
index bec1fbb5..d4e0b5b6 100644
--- a/util/include/chre/util/priority_queue.h
+++ b/util/include/chre/util/priority_queue.h
@@ -181,6 +181,6 @@ class PriorityQueue : public NonCopyable {
 
 }  // namespace chre
 
-#include "chre/util/priority_queue_impl.h"
+#include "chre/util/priority_queue_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_PRIORITY_QUEUE_H_
diff --git a/util/include/chre/util/priority_queue_impl.h b/util/include/chre/util/priority_queue_impl.h
index 5bce243b..f92df8fb 100644
--- a/util/include/chre/util/priority_queue_impl.h
+++ b/util/include/chre/util/priority_queue_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_PRIORITY_QUEUE_IMPL_H_
 #define CHRE_UTIL_PRIORITY_QUEUE_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/util/priority_queue.h"
 
 #include <utility>
diff --git a/util/include/chre/util/scope_timer.h b/util/include/chre/util/scope_timer.h
index 1aa9bd3e..7fd6dbec 100644
--- a/util/include/chre/util/scope_timer.h
+++ b/util/include/chre/util/scope_timer.h
@@ -50,6 +50,6 @@ class ScopeTimer : public NonCopyable {
 
 }  // namespace chre
 
-#include "chre/util/scope_timer_impl.h"
+#include "chre/util/scope_timer_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_SCOPE_TIMER_H_
diff --git a/util/include/chre/util/scope_timer_impl.h b/util/include/chre/util/scope_timer_impl.h
index 94cf4376..fa2eaae3 100644
--- a/util/include/chre/util/scope_timer_impl.h
+++ b/util/include/chre/util/scope_timer_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_SCOPE_TIMER_IMPL_H_
 #define CHRE_UTIL_SCOPE_TIMER_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/platform/system_time.h"
 
 namespace chre {
diff --git a/util/include/chre/util/segmented_queue.h b/util/include/chre/util/segmented_queue.h
index d809df25..127e3a6f 100644
--- a/util/include/chre/util/segmented_queue.h
+++ b/util/include/chre/util/segmented_queue.h
@@ -423,6 +423,6 @@ class SegmentedQueue : public NonCopyable {
 
 }  // namespace chre
 
-#include "chre/util/segmented_queue_impl.h"
+#include "chre/util/segmented_queue_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_SEGMENTED_QUEUE_H_
diff --git a/util/include/chre/util/segmented_queue_impl.h b/util/include/chre/util/segmented_queue_impl.h
index 623cac64..604be687 100644
--- a/util/include/chre/util/segmented_queue_impl.h
+++ b/util/include/chre/util/segmented_queue_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_SEGMENTED_QUEUE_IMPL_H
 #define CHRE_UTIL_SEGMENTED_QUEUE_IMPL_H
 
+// IWYU pragma: private
 #include <algorithm>
 #include <type_traits>
 #include <utility>
diff --git a/util/include/chre/util/singleton.h b/util/include/chre/util/singleton.h
index 965f5f4e..5c7c2863 100644
--- a/util/include/chre/util/singleton.h
+++ b/util/include/chre/util/singleton.h
@@ -90,6 +90,6 @@ class Singleton : public NonCopyable {
 
 }  // namespace chre
 
-#include "chre/util/singleton_impl.h"
+#include "chre/util/singleton_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_SINGLETON_H_
diff --git a/util/include/chre/util/singleton_impl.h b/util/include/chre/util/singleton_impl.h
index b38c724e..6b962c65 100644
--- a/util/include/chre/util/singleton_impl.h
+++ b/util/include/chre/util/singleton_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_SINGLETON_IMPL_H_
 #define CHRE_UTIL_SINGLETON_IMPL_H_
 
+// IWYU pragma: private
 #include <new>
 #include <utility>
 
diff --git a/util/include/chre/util/synchronized_expandable_memory_pool.h b/util/include/chre/util/synchronized_expandable_memory_pool.h
index 2fbe030c..72c8c623 100644
--- a/util/include/chre/util/synchronized_expandable_memory_pool.h
+++ b/util/include/chre/util/synchronized_expandable_memory_pool.h
@@ -124,6 +124,6 @@ class SynchronizedExpandableMemoryPool : public NonCopyable {
 
 }  // namespace chre
 
-#include "chre/util/synchronized_expandable_memory_pool_impl.h"
+#include "chre/util/synchronized_expandable_memory_pool_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_SYNCHRONIZED_EXPANDABLE_MEMORY_POOL_H_
diff --git a/util/include/chre/util/synchronized_expandable_memory_pool_impl.h b/util/include/chre/util/synchronized_expandable_memory_pool_impl.h
index 8e20913f..31b9007f 100644
--- a/util/include/chre/util/synchronized_expandable_memory_pool_impl.h
+++ b/util/include/chre/util/synchronized_expandable_memory_pool_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_SYNCHRONIZED_EXPANDABLE_MEMORY_POOL_IMPL_H_
 #define CHRE_UTIL_SYNCHRONIZED_EXPANDABLE_MEMORY_POOL_IMPL_H_
 
+// IWYU pragma: private
 #include <algorithm>
 
 #include "chre/util/lock_guard.h"
diff --git a/util/include/chre/util/synchronized_memory_pool.h b/util/include/chre/util/synchronized_memory_pool.h
index 34af8474..7e5294d1 100644
--- a/util/include/chre/util/synchronized_memory_pool.h
+++ b/util/include/chre/util/synchronized_memory_pool.h
@@ -94,6 +94,6 @@ class SynchronizedMemoryPool : public NonCopyable {
 
 }  // namespace chre
 
-#include "chre/util/synchronized_memory_pool_impl.h"
+#include "chre/util/synchronized_memory_pool_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_SYNCHRONIZED_MEMORY_POOL_H_
diff --git a/util/include/chre/util/synchronized_memory_pool_impl.h b/util/include/chre/util/synchronized_memory_pool_impl.h
index c3f29bdc..6856500d 100644
--- a/util/include/chre/util/synchronized_memory_pool_impl.h
+++ b/util/include/chre/util/synchronized_memory_pool_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_SYNCHRONIZED_MEMORY_POOL_IMPL_H_
 #define CHRE_UTIL_SYNCHRONIZED_MEMORY_POOL_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/util/lock_guard.h"
 #include "chre/util/synchronized_memory_pool.h"
 
diff --git a/util/include/chre/util/system/stats_container.h b/util/include/chre/util/system/stats_container.h
index 4a5e4041..c7e979c6 100644
--- a/util/include/chre/util/system/stats_container.h
+++ b/util/include/chre/util/system/stats_container.h
@@ -17,7 +17,6 @@
 #ifndef CHRE_UTIL_SYSTEM_STATS_CONTAINER_H_
 #define CHRE_UTIL_SYSTEM_STATS_CONTAINER_H_
 
-#include <cinttypes>
 #include <type_traits>
 
 #include "chre/util/macros.h"
@@ -36,40 +35,18 @@ class StatsContainer {
  public:
   /**
    * @brief Construct a new Stats Container object
-   *
-   * @param averageWindow_ how many data stored before prioritizing new data,
-   * it should not be bigger than the default value to prevent rounding to 0
    */
-  StatsContainer(uint32_t averageWindow_ = 512)
-      : mAverageWindow(averageWindow_) {}
+  StatsContainer() {}
 
   /**
-   * Add a new value to the metric collection and update mean/max value
-   * Mean calculated in rolling bases to prevent overflow by accumulating too
-   * much data.
+   * Add a new value to the metric collection and update max value
    *
-   * Before mCount reaches mAverageWindow, it calculates the normal average
-   * After mCount reaches mAverageWindow, weighted average is used to prioritize
-   * recent data where the new value always contributes 1/mAverageWindow amount
-   * to the average
    * @param value a T instance
    */
   void addValue(T value) {
-    if (mCount < mAverageWindow) {
-      ++mCount;
-    }
-    mMean = (mCount - 1) * (mMean / mCount) + value / mCount;
     mMax = MAX(value, mMax);
   }
 
-  /**
-   * @return the average value calculated by the description of the
-   * addValue method
-   */
-  T getMean() const {
-    return mMean;
-  }
-
   /**
    * @return the max value
    */
@@ -77,20 +54,7 @@ class StatsContainer {
     return mMax;
   }
 
-  /**
-   * @return the average window
-   */
-  uint32_t getAverageWindow() const {
-    return mAverageWindow;
-  }
-
  private:
-  //! Mean of the collections of this stats
-  T mMean = 0;
-  //! Number of collections of this stats
-  uint32_t mCount = 0;
-  //! The Window that the container will not do weighted average
-  uint32_t mAverageWindow;
   //! Max of stats
   T mMax = 0;
 };
diff --git a/util/include/chre/util/throttle.h b/util/include/chre/util/throttle.h
new file mode 100644
index 00000000..5026afbe
--- /dev/null
+++ b/util/include/chre/util/throttle.h
@@ -0,0 +1,49 @@
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
+#ifndef CHRE_UTIL_THROTTLE_H_
+#define CHRE_UTIL_THROTTLE_H_
+
+#include "chre/util/optional.h"
+
+using ::chre::Optional;
+
+/**
+ * Throttles an action to a given interval and maximum number of times.
+ * The action will be called at most maxCount in every interval.
+ *
+ * @param action The action to throttle
+ * @param interval The interval between actions
+ * @param maxCount The maximum number of times to call the action
+ * @param getTime A function to get the current time
+ */
+#define CHRE_THROTTLE(action, interval, maxCount, getTime) \
+  do {                                                     \
+    static uint32_t _count = 0;                            \
+    static Optional<Nanoseconds> _lastCallTime;            \
+    Nanoseconds _now = getTime;                            \
+    if (!_lastCallTime.has_value() ||                      \
+        _now - _lastCallTime.value() >= interval) {        \
+      _count = 0;                                          \
+      _lastCallTime = _now;                                \
+    }                                                      \
+    if (++_count > maxCount) {                             \
+      break;                                               \
+    }                                                      \
+    action;                                                \
+  } while (0)
+
+#endif  // CHRE_UTIL_THROTTLE_H_
diff --git a/util/include/chre/util/time.h b/util/include/chre/util/time.h
index faef7dcf..3a4c6188 100644
--- a/util/include/chre/util/time.h
+++ b/util/include/chre/util/time.h
@@ -308,6 +308,6 @@ constexpr bool operator>(const Nanoseconds &nanos_a,
 
 }  // namespace chre
 
-#include "chre/util/time_impl.h"
+#include "chre/util/time_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_TIME_H_
diff --git a/util/include/chre/util/time_impl.h b/util/include/chre/util/time_impl.h
index 5fe5712c..653e7c0f 100644
--- a/util/include/chre/util/time_impl.h
+++ b/util/include/chre/util/time_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_TIME_IMPL_H_
 #define CHRE_UTIL_TIME_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/util/time.h"
 
 namespace chre {
diff --git a/util/include/chre/util/transaction_manager.h b/util/include/chre/util/transaction_manager.h
index 1e1211f6..7fd4b0eb 100644
--- a/util/include/chre/util/transaction_manager.h
+++ b/util/include/chre/util/transaction_manager.h
@@ -18,9 +18,7 @@
 #define CHRE_UTIL_TRANSACTION_MANAGER_H_
 
 #include <cstdint>
-#include <type_traits>
 
-#include "chre/platform/mutex.h"
 #include "chre/util/array_queue.h"
 #include "chre/util/non_copyable.h"
 #include "chre/util/optional.h"
@@ -28,304 +26,206 @@
 
 namespace chre {
 
+class TransactionManagerCallback {
+ public:
+  virtual ~TransactionManagerCallback() = default;
+
+  //! Initiate or retry an operation associated with the given transaction ID
+  virtual void onTransactionAttempt(uint32_t transactionId,
+                                    uint16_t groupId) = 0;
+
+  //! Invoked when a transaction fails to complete after the max attempt limit
+  virtual void onTransactionFailure(uint32_t transactionId,
+                                    uint16_t groupId) = 0;
+};
+
 /**
- * TransactionManager tracks pending transactions.
+ * TransactionManager helps track operations which should be retried if not
+ * completed within a set amount of time.
  *
- * Transactions are long running operations identified by an ID.
- * The TransactionManager makes sure that the transactions will complete only
- * once after a call to completeTransaction or after the optional timeout
- * expires whichever comes first. A transaction will be retried by calling
- * the start callback after no complete call has been made before the retry
- * wait time.
+ * Transactions are long running operations identified by an ID. Further,
+ * transactions can be grouped to ensure that only one transaction within a
+ * group is outstanding at a time.
  *
- * Typical usage:
- * 1. Start a transaction. Get the ID back.
- * 2. TransactionManager will run start callback with the data.
- * 3. If the start callback fails or if the transaction is not completed,
- *    TransactionManager will call the start callback again after the retry
- *    wait time.
- * 4. Call completeTransaction with the ID.
- * 5. TransactionManager will call the complete callback with the data.
+ * This class is not thread-safe, so the caller must ensure all its methods are
+ * invoked on the same thread that TimerPool callbacks are invoked on.
  *
- * If completeTransaction is not called before the timeout, the transaction
- * will be completed with a CHRE_ERROR_TIMEOUT.
+ * Usage summary:
+ *  - Call add() to initiate the transaction and assign an ID
+ *    - TransactionManager will invoke the onTransactionAttempt() callback,
+ *      either synchronously and immediately, or after any previous transactions
+ *      in the same group have completed
+ *  - Call remove() when the transaction's operation completes or is canceled
+ *    - If not called within the timeout, TransactionManager will call
+ *      onTransactionAttempt() again
+ *    - If the operation times out after the specified maximum number of
+ *      attempts, TransactionManager will call onTransactionFailure() and
+ *      remove the transaction (note that this is the only circumstance under
+ *      which onTransactionFailure() is called)
  *
- * Ensure the thread processing the deferred callbacks is completed before the
- * destruction of the TransactionManager.
- *
- * @param TransactionData The data passed to the start and complete callbacks.
- * @param kMaxTransactions The maximum number of pending transactions.
+ * @param kMaxTransactions The maximum number of pending transactions
+ * (statically allocated)
+ * @param TimerPoolType A chre::TimerPool-like class, which supports methods
+ * with the same signature and semantics as TimerPool::setSystemTimer() and
+ * TimerPool::cancelSystemTimer()
  */
-template <typename TransactionData, size_t kMaxTransactions>
+template <size_t kMaxTransactions, class TimerPoolType>
 class TransactionManager : public NonCopyable {
  public:
   /**
-   * Type of the callback called on transaction completion. This callback is
-   * called in the defer callback thread.
-   *
-   * This callback cannot call any of the TransactionManager methods.
-   *
-   * @param data The data for the transaction.
-   * @param errorCode The error code passed to completeTransaction.
-   * @return whether the callback succeeded.
-   */
-  using CompleteCallback = typename std::conditional<
-      std::is_pointer<TransactionData>::value ||
-          std::is_fundamental<TransactionData>::value,
-      bool (*)(TransactionData data, uint8_t errorCode),
-      bool (*)(const TransactionData &data, uint8_t errorCode)>::type;
-
-  /**
-   * Type of the callback called to start the transaction. This is the action
-   * that will be repeated on a retry of the transaction. This callback is
-   * called in the defer callback thread.
-   *
-   * This callback cannot call any of the TransactionManager methods.
-   *
-   * @param data The data for the transaction.
-   * @return whether the callback succeeded.
-   */
-  using StartCallback =
-      typename std::conditional<std::is_pointer<TransactionData>::value ||
-                                    std::is_fundamental<TransactionData>::value,
-                                bool (*)(TransactionData data),
-                                bool (*)(TransactionData &data)>::type;
-
-  /**
-   * The type of function used to defer a callback. See DeferCallback.
-   *
-   * @param type The type passed from the DeferCallback.
-   * @param data The data passed from the DeferCallback.
-   * @param extraData The extra data passed from the DeferCallback.
-   */
-  using DeferCallbackFunction = void (*)(uint16_t type, void *data,
-                                         void *extraData);
-
-  /**
-   * Type of the callback used to defer the call of func with data and extraData
-   * after waiting for delay. extraData is ignored if delay > 0 ns.
-   *
-   * This callback cannot call any of the TransactionManager methods.
-   *
-   * @param func The function to call when the callback is executed.
-   * @param data The data to pass to the function.
-   * @param extraData The extra data to pass to the function.
-   * @param delay The nanoseconds delay to wait before calling the function.
-   * @param outTimerHandle The output timer handle if delay > 0 ns.
-   * @return whether the callback succeeded.
-   */
-  using DeferCallback = bool (*)(DeferCallbackFunction func, void *data,
-                                 void *extraData, Nanoseconds delay,
-                                 uint32_t *outTimerHandle);
-
-  /**
-   * Type of the callback used to cancel a defer call made using the
-   * DeferCallback.
-   *
-   * This callback cannot call any of the TransactionManager methods.
-   *
-   * @param timerHandle the timer handle returned using the DeferCallback.
-   * @return whether the callback was successfully cancelled.
+   * @param cb Callback
+   * @param timerPool TimerPool-like object to use for retry timers
+   * @param timeout How long to wait for remove() to be called after
+   *        onTransactionAttempt() before trying again or failing
+   * @param maxAttempts Maximum number of times to try the transaction before
+   *        giving up
    */
-  using DeferCancelCallback = bool (*)(uint32_t timerHandle);
-
-  /**
-   * The callback used to determine which elements to remove
-   * during a flush.
-   *
-   * This callback cannot call any of the TransactionManager methods.
-   */
-  using FlushCallback = typename std::conditional<
-      std::is_pointer<TransactionData>::value ||
-          std::is_fundamental<TransactionData>::value,
-      bool (*)(TransactionData data, void *callbackData),
-      bool (*)(const TransactionData &data, void *callbackData)>::type;
-
-  /**
-   * The function called when the transaction processing timer is fired.
-   * @see DeferCallbackFunction() for parameter information.
-   */
-  static void onTimerFired(uint16_t /* type */, void *data,
-                           void * /* extraData */) {
-    auto transactionManagerPtr = static_cast<TransactionManager *>(data);
-    if (transactionManagerPtr == nullptr) {
-      LOGE("Could not get transaction manager to process transactions");
-      return;
-    }
-
-    transactionManagerPtr->mTimerHandle = CHRE_TIMER_INVALID;
-    transactionManagerPtr->processTransactions();
-  }
-
-  TransactionManager() = delete;
-
-  TransactionManager(StartCallback startCallback,
-                     CompleteCallback completeCallback,
-                     DeferCallback deferCallback,
-                     DeferCancelCallback deferCancelCallback,
-                     Nanoseconds retryWaitTime, Nanoseconds timeout,
-                     uint16_t maxNumRetries = 3)
-      : kStartCallback(startCallback),
-        kCompleteCallback(completeCallback),
-        kDeferCallback(deferCallback),
-        kDeferCancelCallback(deferCancelCallback),
-        kRetryWaitTime(retryWaitTime),
-        kTimeout(timeout),
-        kMaxNumRetries(maxNumRetries) {
-    CHRE_ASSERT(startCallback != nullptr);
-    CHRE_ASSERT(completeCallback != nullptr);
-    CHRE_ASSERT(deferCallback != nullptr);
-    CHRE_ASSERT(deferCancelCallback != nullptr);
-    CHRE_ASSERT(retryWaitTime.toRawNanoseconds() > 0);
-    CHRE_ASSERT(timeout.toRawNanoseconds() == 0 ||
-                timeout.toRawNanoseconds() > retryWaitTime.toRawNanoseconds());
+  TransactionManager(TransactionManagerCallback &cb, TimerPoolType &timerPool,
+                     Nanoseconds timeout, uint8_t maxAttempts = 3)
+      : kTimeout(timeout),
+        kMaxAttempts(maxAttempts),
+        mTimerPool(timerPool),
+        mCb(cb) {
+    CHRE_ASSERT(timeout.toRawNanoseconds() > 0);
   }
 
   /**
-   * Completes a transaction.
-   *
-   * The callback registered when starting the transaction is called with the
-   * errorCode if the error is not CHRE_ERROR_TRANSIENT. If the error is
-   * CHRE_ERROR_TRANSIENT, this function marks the transaction as ready
-   * to retry and processes transactions.
-   *
-   * This function is safe to call in any thread.
-   *
-   * Note that the callback will be called at most once on the first call to
-   * this method. For example if the transaction timed out before an explicit
-   * call to completeTransaction, the callback is only invoked for the timeout.
-   *
-   * @param transactionId ID of the transaction to complete.
-   * @param errorCode Error code to pass to the callback.
-   * @return Whether the transaction was completed successfully.
+   * This destructor only guarantees that no transaction callbacks will be
+   * invoked after it returns – it does not invoke any callbacks on its own.
+   * Users of this class should typically ensure that all pending transactions
+   * are cleaned up (i.e. removed) prior to destroying this object.
    */
-  bool completeTransaction(uint32_t transactionId, uint8_t errorCode);
+  ~TransactionManager();
 
   /**
-   * Flushes all the pending transactions that match the FlushCallback.
-   *
-   * This function is safe to call in any thread.
+   * Initiate a transaction, assigning it a globally unique transactionId and
+   * invoking the onTransactionAttempt() callback from within this function if
+   * it is the only pending transaction in the groupId.
    *
-   * The completion callback is not called.
+   * This must not be called from within a callback method, like
+   * onTransactionFailed().
    *
-   * @param flushCallback The function that determines which transactions will
-   * be flushed (upon return true).
-   * @param data The data to be passed to the flush callback.
-   * @return The number of flushed transactions.
+   * @param groupId ID used to serialize groups of transactions
+   * @param[out] transactionId Assigned ID, set prior to calling
+   *         onTransactionAttempt()
+   * @return false if kMaxTransactions are pending, true otherwise
    */
-  size_t flushTransactions(FlushCallback flushCallback, void *data);
+  bool add(uint16_t groupId, uint32_t *transactionId);
 
   /**
-   * Starts a transaction. This function will mark the transaction as ready to
-   * execute the StartCallback and processes transactions. The StartCallback
-   * will be called only when there are no other pending transactions for the
-   * unique cookie.
+   * Complete a transaction, by removing it from the active set of transactions.
    *
-   * The transaction will complete with a CHRE_ERROR_TIMEOUT if
-   * completeTransaction has not been called before the timeout. The timeout
-   * is calculated from the time the StartCallback is called.
+   * After this returns, it is guaranteed that callbacks will not be invoked for
+   * this transaction ID. If another transaction is pending with the same group
+   * ID as this one, onTransactionAttempt() is invoked for it from within this
+   * function.
    *
-   * This function is safe to call in any thread.
+   * This should be called on successful completion or cancelation of a
+   * transaction, but is automatically handled when a transaction fails due to
+   * timeout.
    *
-   * @param data The transaction data and callbacks used to run the transaction.
-   * @param cookie The cookie used to ensure only one transaction will be
-   *        started and pending for a given cookie.
-   * @param id A pointer to the transaction ID that will be populated when
-   *        startTransaction succeed. It must not be null.
-   * @return Whether the transaction was started successfully.
+   * This must not be called from within a callback method, like
+   * onTransactionAttempt().
+   *
+   * @param transactionId
+   * @return true if the transactionId was found and removed from the queue
    */
-  bool startTransaction(const TransactionData &data, uint16_t cookie,
-                        uint32_t *id);
+  bool remove(uint32_t transactionId);
 
  private:
   //! Stores transaction-related data.
   struct Transaction {
+    Transaction(uint32_t id_, uint16_t groupId_) : id(id_), groupId(groupId_) {}
+
     uint32_t id;
-    TransactionData data;
-    Nanoseconds nextRetryTime;
-    Nanoseconds timeoutTime;
-    uint16_t cookie;
-    uint16_t numCompletedStartCalls;
-    Optional<uint8_t> errorCode;
+    uint16_t groupId;
+
+    //! Counts up by 1 on each attempt, 0 when pending first attempt
+    uint8_t attemptCount = 0;
+
+    //! Absolute time when the next retry should be attempted or the transaction
+    //! should be considered failed. Defaults to max so it's never the next
+    //! timeout if something else is active.
+    Nanoseconds timeout = Nanoseconds(UINT64_MAX);
   };
 
-  /**
-   * Defers processing transactions in the defer callback thread.
-   */
-  void deferProcessTransactions();
+  //! RAII helper to set a boolean to true and restore to false at end of scope
+  class ScopedFlag {
+   public:
+    ScopedFlag(bool &flag) : mFlag(flag) {
+      mFlag = true;
+    }
+    ~ScopedFlag() {
+      mFlag = false;
+    }
 
-  /**
-   * Calls the complete callback for a transaction if needed. Also updates the
-   * transaction state. Assumes the caller holds the mutex.
-   *
-   * @param transaction The transaction.
-   */
-  void doCompleteTransactionLocked(Transaction &transaction);
+   private:
+    bool &mFlag;
+  };
 
-  /**
-   * Calls the start callback for a transaction if needed. Also updates the
-   * transaction state. Assumes the caller holds the mutex.
-   *
-   * @param transaction The transaction.
-   * @param i The index of the transaction in mTransactions.
-   * @param now The current time.
-   */
-  void doStartTransactionLocked(Transaction &transaction, size_t i,
-                                Nanoseconds now);
+  const Nanoseconds kTimeout;
+  const uint8_t kMaxAttempts;
 
-  /**
-   * Generates a pseudo random ID for a transaction in the range of
-   * [0, 2^30 - 1].
-   * @return The generated ID.
-   */
-  uint32_t generatePseudoRandomId();
+  TimerPoolType &mTimerPool;
+  TransactionManagerCallback &mCb;
 
-  /**
-   * Processes transactions. This function will call the start callback and
-   * complete callback where appropriate and keep track of which transactions
-   * need to be retried next. This function is called in the defer callback
-   * thread and will defer a call to itself at the next time needed to processes
-   * the next transaction.
-   */
-  void processTransactions();
+  //! Delayed assignment to start at a pseudo-random value
+  Optional<uint32_t> mNextTransactionId;
+
+  //! Helps catch misuse, e.g. trying to remove a transaction from a callback
+  bool mInCallback = false;
 
-  //! The start callback.
-  const StartCallback kStartCallback;
+  //! Handle of timer that expires, or CHRE_TIMER_INVALID if none
+  uint32_t mTimerHandle = CHRE_TIMER_INVALID;
 
-  //! The complete callback.
-  const CompleteCallback kCompleteCallback;
+  //! Set of active transactions
+  ArrayQueue<Transaction, kMaxTransactions> mTransactions;
 
-  //! The defer callback.
-  const DeferCallback kDeferCallback;
+  //! Callback given to mTimerPool, invoked when the next expiring transaction
+  //! has timed out
+  static void onTimerExpired(uint16_t /*type*/, void *data,
+                             void * /*extraData*/) {
+    auto *obj =
+        static_cast<TransactionManager<kMaxTransactions, TimerPoolType> *>(
+            data);
+    obj->handleTimerExpiry();
+  }
 
-  //! The defer cancel callback.
-  const DeferCancelCallback kDeferCancelCallback;
+  //! @return a pseudorandom ID for a transaction in the range of [0, 2^30 - 1]
+  uint32_t generatePseudoRandomId();
 
-  //! The retry wait time.
-  const Nanoseconds kRetryWaitTime;
+  //! If the last added transaction is the only one in its group, start it;
+  //! otherwise do nothing
+  void maybeStartLastTransaction();
 
-  //! The timeout for a transaction.
-  const Nanoseconds kTimeout;
+  //! If there's a pending transaction in this group, start the next one;
+  //! otherwise do nothing
+  void startNextTransactionInGroup(uint16_t groupId);
 
-  //! The maximum number of retries for a transaction.
-  const uint16_t kMaxNumRetries;
+  //! Update the transaction state and invoke the attempt callback, but doesn't
+  //! set the timer
+  void startTransaction(Transaction &transaction);
 
-  //! The mutex protecting mTransactions and mTimerHandle.
-  Mutex mMutex;
+  //! Updates the timer to the proper state for mTransactions
+  void updateTimer();
 
-  //! The next ID for use when creating a transaction.
-  Optional<uint32_t> mNextTransactionId;
+  //! Sets the timer to expire after a delay
+  void setTimer(Nanoseconds delay);
 
-  //! The timer handle for the timer tracking execution of processTransactions.
-  //! Can only be modified in the defer callback thread.
-  uint32_t mTimerHandle = CHRE_TIMER_INVALID;
+  //! Sets the timer to expire at the given time, or effectively immediately if
+  //! expiry is in the past
+  void setTimerAbsolute(Nanoseconds expiry);
 
-  //! The list of transactions.
-  ArrayQueue<Transaction, kMaxTransactions> mTransactions;
+  //! Processes any timed out transactions and reset the timer as needed
+  void handleTimerExpiry();
+
+  //! Invokes the failure callback and starts the next transaction in the group,
+  //! but does not remove the transaction (it should already be removed)
+  void handleTransactionFailure(Transaction &transaction);
 };
 
 }  // namespace chre
 
-#include "chre/util/transaction_manager_impl.h"
+#include "chre/util/transaction_manager_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_TRANSACTION_MANAGER_H_
diff --git a/util/include/chre/util/transaction_manager_impl.h b/util/include/chre/util/transaction_manager_impl.h
index d3e4db26..3aa51084 100644
--- a/util/include/chre/util/transaction_manager_impl.h
+++ b/util/include/chre/util/transaction_manager_impl.h
@@ -17,186 +17,76 @@
 #ifndef CHRE_UTIL_TRANSACTION_MANAGER_IMPL_H_
 #define CHRE_UTIL_TRANSACTION_MANAGER_IMPL_H_
 
-#include <algorithm>
-#include <inttypes.h>
+// IWYU pragma: private
+#include "chre/util/transaction_manager.h"
 
+#include "chre/core/event_loop_common.h"
 #include "chre/platform/system_time.h"
 #include "chre/util/hash.h"
-#include "chre/util/lock_guard.h"
-#include "chre/util/transaction_manager.h"
-#include "chre_api/chre.h"
 
 namespace chre {
 
-using ::chre::Nanoseconds;
-using ::chre::Seconds;
-
-template <typename TransactionData, size_t kMaxTransactions>
-bool TransactionManager<TransactionData, kMaxTransactions>::completeTransaction(
-    uint32_t transactionId, uint8_t errorCode) {
-  bool success = false;
-
-  {
-    LockGuard<Mutex> lock(mMutex);
-    for (size_t i = 0; i < mTransactions.size(); ++i) {
-      Transaction &transaction = mTransactions[i];
-      if (transaction.id == transactionId) {
-        if (errorCode == CHRE_ERROR_TRANSIENT) {
-          transaction.nextRetryTime = Nanoseconds(0);
-        } else {
-          transaction.errorCode = errorCode;
-        }
-        success = true;
-        break;
-      }
-    }
-  }
-
-  if (success) {
-    deferProcessTransactions();
-  } else {
-    LOGE("Unable to complete transaction with ID: %" PRIu32, transactionId);
-  }
-  return success;
-}
-
-template <typename TransactionData, size_t kMaxTransactions>
-size_t TransactionManager<TransactionData, kMaxTransactions>::flushTransactions(
-    FlushCallback callback, void *data) {
-  if (callback == nullptr) {
-    return 0;
-  }
-
-  deferProcessTransactions();
-
-  LockGuard<Mutex> lock(mMutex);
-  size_t numFlushed = 0;
-  for (size_t i = 0; i < mTransactions.size();) {
-    if (callback(mTransactions[i].data, data)) {
-      mTransactions.remove(i);
-      ++numFlushed;
-    } else {
-      ++i;
-    }
+template <size_t kMaxTransactions, class TimerPoolType>
+TransactionManager<kMaxTransactions, TimerPoolType>::~TransactionManager() {
+  if (mTimerHandle != CHRE_TIMER_INVALID) {
+    LOGI("At least one pending transaction at destruction");
+    mTimerPool.cancelSystemTimer(mTimerHandle);
   }
-  return numFlushed;
 }
 
-template <typename TransactionData, size_t kMaxTransactions>
-bool TransactionManager<TransactionData, kMaxTransactions>::startTransaction(
-    const TransactionData &data, uint16_t cookie, uint32_t *id) {
+template <size_t kMaxTransactions, class TimerPoolType>
+bool TransactionManager<kMaxTransactions, TimerPoolType>::add(uint16_t groupId,
+                                                              uint32_t *id) {
   CHRE_ASSERT(id != nullptr);
+  CHRE_ASSERT(!mInCallback);
 
-  {
-    LockGuard<Mutex> lock(mMutex);
-    if (mTransactions.full()) {
-      LOGE("The transaction queue is full");
-      return false;
-    }
-
-    if (!mNextTransactionId.has_value()) {
-      mNextTransactionId = generatePseudoRandomId();
-    }
-    uint32_t transactionId = (mNextTransactionId.value())++;
-    *id = transactionId;
-
-    Transaction transaction{
-        .id = transactionId,
-        .data = data,
-        .nextRetryTime = Nanoseconds(0),
-        .timeoutTime = Nanoseconds(0),
-        .cookie = cookie,
-        .numCompletedStartCalls = 0,
-        .errorCode = Optional<uint8_t>(),
-    };
-
-    mTransactions.push(transaction);
+  if (mTransactions.full()) {
+    LOGE("Can't add new transaction: storage is full");
+    return false;
   }
 
-  deferProcessTransactions();
-  return true;
-}
-
-template <typename TransactionData, size_t kMaxTransactions>
-void TransactionManager<TransactionData,
-                        kMaxTransactions>::deferProcessTransactions() {
-  bool success = kDeferCallback(
-      [](uint16_t /* type */, void *data, void * /* extraData */) {
-        auto transactionManagerPtr = static_cast<TransactionManager *>(data);
-        if (transactionManagerPtr == nullptr) {
-          LOGE("Could not get transaction manager to process transactions");
-          return;
-        }
-
-        transactionManagerPtr->processTransactions();
-      },
-      this,
-      /* extraData= */ nullptr,
-      /* delay= */ Nanoseconds(0),
-      /* outTimerHandle= */ nullptr);
-
-  if (!success) {
-    LOGE("Could not defer callback to process transactions");
+  if (!mNextTransactionId.has_value()) {
+    mNextTransactionId = generatePseudoRandomId();
   }
-}
+  *id = (mNextTransactionId.value())++;
+  mTransactions.emplace(*id, groupId);
 
-template <typename TransactionData, size_t kMaxTransactions>
-void TransactionManager<TransactionData, kMaxTransactions>::
-    doCompleteTransactionLocked(Transaction &transaction) {
-  uint8_t errorCode = CHRE_ERROR_TIMEOUT;
-  if (transaction.errorCode.has_value()) {
-    errorCode = *transaction.errorCode;
-  }
-
-  bool success = kCompleteCallback(transaction.data, errorCode);
-  if (success) {
-    LOGI("Transaction %" PRIu32 " completed with error code: %" PRIu8,
-         transaction.id, errorCode);
-  } else {
-    LOGE("Could not complete transaction %" PRIu32, transaction.id);
+  maybeStartLastTransaction();
+  if (mTransactions.size() == 1) {
+    setTimerAbsolute(mTransactions.back().timeout);
   }
+  return true;
 }
 
-template <typename TransactionData, size_t kMaxTransactions>
-void TransactionManager<TransactionData, kMaxTransactions>::
-    doStartTransactionLocked(Transaction &transaction, size_t i,
-                             Nanoseconds now) {
-  // Ensure only one pending transaction per unique cookie.
-  bool canStart = true;
-  for (size_t j = 0; j < mTransactions.size(); ++j) {
-    if (i != j && mTransactions[j].cookie == transaction.cookie &&
-        mTransactions[j].numCompletedStartCalls > 0) {
-      canStart = false;
-      break;
-    }
-  }
-  if (!canStart) {
-    return;
-  }
-
-  if (transaction.timeoutTime.toRawNanoseconds() != 0) {
-    transaction.timeoutTime = now + kTimeout;
-  }
+template <size_t kMaxTransactions, class TimerPoolType>
+bool TransactionManager<kMaxTransactions, TimerPoolType>::remove(
+    uint32_t transactionId) {
+  CHRE_ASSERT(!mInCallback);
+  for (size_t i = 0; i < mTransactions.size(); ++i) {
+    Transaction &transaction = mTransactions[i];
+    if (transaction.id == transactionId) {
+      uint16_t groupId = transaction.groupId;
+      bool transactionWasStarted = transaction.attemptCount > 0;
+      mTransactions.remove(i);
 
-  bool success = kStartCallback(transaction.data);
-  if (success) {
-    LOGI("Transaction %" PRIu32 " started", transaction.id);
-  } else {
-    LOGE("Could not start transaction %" PRIu32, transaction.id);
+      if (transactionWasStarted) {
+        startNextTransactionInGroup(groupId);
+        updateTimer();
+      }
+      return true;
+    }
   }
-
-  ++transaction.numCompletedStartCalls;
-  transaction.nextRetryTime = now + kRetryWaitTime;
+  return false;
 }
 
-template <typename TransactionData, size_t kMaxTransactions>
-uint32_t TransactionManager<TransactionData,
-                        kMaxTransactions>::generatePseudoRandomId() {
+template <size_t kMaxTransactions, class TimerPoolType>
+uint32_t
+TransactionManager<kMaxTransactions, TimerPoolType>::generatePseudoRandomId() {
   uint64_t data =
       SystemTime::getMonotonicTime().toRawNanoseconds() +
       static_cast<uint64_t>(SystemTime::getEstimatedHostTimeOffset());
-  uint32_t hash = fnv1a32Hash(reinterpret_cast<const uint8_t*>(&data),
-                              sizeof(uint64_t));
+  uint32_t hash =
+      fnv1a32Hash(reinterpret_cast<const uint8_t *>(&data), sizeof(data));
 
   // We mix the top 2 bits back into the middle of the hash to provide a value
   // that leaves a gap of at least ~1 billion sequence numbers before
@@ -208,64 +98,134 @@ uint32_t TransactionManager<TransactionData,
   return hash & ~kMask;
 }
 
-template <typename TransactionData, size_t kMaxTransactions>
-void TransactionManager<TransactionData,
-                        kMaxTransactions>::processTransactions() {
-  if (mTimerHandle != CHRE_TIMER_INVALID) {
-    CHRE_ASSERT(kDeferCancelCallback(mTimerHandle));
-    mTimerHandle = CHRE_TIMER_INVALID;
+template <size_t kMaxTransactions, class TimerPoolType>
+void TransactionManager<kMaxTransactions,
+                        TimerPoolType>::maybeStartLastTransaction() {
+  Transaction &lastTransaction = mTransactions.back();
+
+  for (const Transaction &transaction : mTransactions) {
+    if (transaction.groupId == lastTransaction.groupId &&
+        transaction.id != lastTransaction.id) {
+      // Have at least one pending request for this group, so this transaction
+      // will only be started via removeTransaction()
+      return;
+    }
   }
 
-  Nanoseconds now = SystemTime::getMonotonicTime();
-  Nanoseconds nextExecutionTime(UINT64_MAX);
+  startTransaction(lastTransaction);
+}
 
-  {
-    LockGuard<Mutex> lock(mMutex);
-    if (mTransactions.empty()) {
+template <size_t kMaxTransactions, class TimerPoolType>
+void TransactionManager<kMaxTransactions, TimerPoolType>::
+    startNextTransactionInGroup(uint16_t groupId) {
+  for (Transaction &transaction : mTransactions) {
+    if (transaction.groupId == groupId) {
+      startTransaction(transaction);
       return;
     }
+  }
+}
 
-    // If a transaction is completed, it will be removed from the queue.
-    // The loop continues processing in this case as there may be another
-    // transaction that is ready to start with the same cookie that was
-    // blocked from starting by the completed transaction.
-    bool continueProcessing;
-    do {
-      continueProcessing = false;
-      for (size_t i = 0; i < mTransactions.size();) {
-        Transaction &transaction = mTransactions[i];
-        if ((transaction.timeoutTime.toRawNanoseconds() != 0 &&
-             transaction.timeoutTime <= now) ||
-            (transaction.nextRetryTime <= now &&
-             transaction.numCompletedStartCalls > kMaxNumRetries) ||
-            transaction.errorCode.has_value()) {
-          doCompleteTransactionLocked(transaction);
-          mTransactions.remove(i);
-          continueProcessing = true;
-        } else {
-          if (transaction.nextRetryTime <= now) {
-            doStartTransactionLocked(transaction, i, now);
-          }
+template <size_t kMaxTransactions, class TimerPoolType>
+void TransactionManager<kMaxTransactions, TimerPoolType>::startTransaction(
+    Transaction &transaction) {
+  CHRE_ASSERT(transaction.attemptCount == 0);
+  transaction.attemptCount = 1;
+  transaction.timeout = SystemTime::getMonotonicTime() + kTimeout;
+  {
+    ScopedFlag f(mInCallback);
+    mCb.onTransactionAttempt(transaction.id, transaction.groupId);
+  }
+}
 
-          nextExecutionTime =
-              std::min(nextExecutionTime, transaction.nextRetryTime);
-          if (transaction.timeoutTime.toRawNanoseconds() != 0) {
-            nextExecutionTime =
-                std::min(nextExecutionTime, transaction.timeoutTime);
-          }
-          ++i;
+template <size_t kMaxTransactions, class TimerPoolType>
+void TransactionManager<kMaxTransactions, TimerPoolType>::updateTimer() {
+  mTimerPool.cancelSystemTimer(mTimerHandle);
+  if (mTransactions.empty()) {
+    mTimerHandle = CHRE_TIMER_INVALID;
+  } else {
+    Nanoseconds nextTimeout(UINT64_MAX);
+    for (const Transaction &transaction : mTransactions) {
+      if (transaction.timeout < nextTimeout) {
+        nextTimeout = transaction.timeout;
+      }
+    }
+    // If we hit this assert, we only have transactions that haven't been
+    // started yet
+    CHRE_ASSERT(nextTimeout.toRawNanoseconds() != UINT64_MAX);
+    setTimerAbsolute(nextTimeout);
+  }
+}
+
+template <size_t kMaxTransactions, class TimerPoolType>
+void TransactionManager<kMaxTransactions, TimerPoolType>::setTimer(
+    Nanoseconds duration) {
+  mTimerHandle = mTimerPool.setSystemTimer(
+      duration, onTimerExpired, SystemCallbackType::TransactionManagerTimeout,
+      /*data=*/this);
+}
+
+template <size_t kMaxTransactions, class TimerPoolType>
+void TransactionManager<kMaxTransactions, TimerPoolType>::setTimerAbsolute(
+    Nanoseconds expiry) {
+  constexpr Nanoseconds kMinDelay(100);
+  Nanoseconds now = SystemTime::getMonotonicTime();
+  Nanoseconds delay = (expiry > now) ? expiry - now : kMinDelay;
+  setTimer(delay);
+}
+
+template <size_t kMaxTransactions, class TimerPoolType>
+void TransactionManager<kMaxTransactions, TimerPoolType>::handleTimerExpiry() {
+  mTimerHandle = CHRE_TIMER_INVALID;
+  if (mTransactions.empty()) {
+    LOGW("Got timer callback with no pending transactions");
+    return;
+  }
+
+  // - If a transaction has reached its timeout, try again
+  // - If a transaction has timed out for the final time, fail it
+  //   - If another transaction in the same group is pending, start it
+  // - Keep track of the transaction with the shortest timeout, use that to
+  //   update the timer
+  Nanoseconds now = SystemTime::getMonotonicTime();
+  Nanoseconds nextTimeout(UINT64_MAX);
+  for (size_t i = 0; i < mTransactions.size(); /* ++i at end of scope */) {
+    Transaction &transaction = mTransactions[i];
+    if (transaction.timeout <= now) {
+      if (++transaction.attemptCount > kMaxAttempts) {
+        Transaction transactionCopy = transaction;
+        mTransactions.remove(i);  // Invalidates transaction reference
+        handleTransactionFailure(transactionCopy);
+        // Since mTransactions is FIFO, any pending transactions in this group
+        // will appear after this one, so we don't need to restart the loop
+        continue;
+      } else {
+        transaction.timeout = now + kTimeout;
+        {
+          ScopedFlag f(mInCallback);
+          mCb.onTransactionAttempt(transaction.id, transaction.groupId);
         }
       }
-    } while (continueProcessing);
+    }
+    if (transaction.timeout < nextTimeout) {
+      nextTimeout = transaction.timeout;
+    }
+    ++i;
   }
 
-  Nanoseconds waitTime = nextExecutionTime - SystemTime::getMonotonicTime();
-  if (waitTime.toRawNanoseconds() > 0) {
-    kDeferCallback(
-        TransactionManager<TransactionData, kMaxTransactions>::onTimerFired,
-        /* data= */ this, /* extraData= */ nullptr, waitTime, &mTimerHandle);
-    CHRE_ASSERT(mTimerHandle != CHRE_TIMER_INVALID);
+  if (!mTransactions.empty()) {
+    setTimerAbsolute(nextTimeout);
+  }
+}
+
+template <size_t kMaxTransactions, class TimerPoolType>
+void TransactionManager<kMaxTransactions, TimerPoolType>::
+    handleTransactionFailure(Transaction &transaction) {
+  {
+    ScopedFlag f(mInCallback);
+    mCb.onTransactionFailure(transaction.id, transaction.groupId);
   }
+  startNextTransactionInGroup(transaction.groupId);
 }
 
 }  // namespace chre
diff --git a/util/include/chre/util/unique_ptr.h b/util/include/chre/util/unique_ptr.h
index e0d47622..3b56087a 100644
--- a/util/include/chre/util/unique_ptr.h
+++ b/util/include/chre/util/unique_ptr.h
@@ -231,6 +231,6 @@ UniquePtr<ObjectType> MakeUniqueZeroFill();
 
 }  // namespace chre
 
-#include "chre/util/unique_ptr_impl.h"
+#include "chre/util/unique_ptr_impl.h"  // IWYU pragma: export
 
 #endif  // CHRE_UTIL_UNIQUE_PTR_H_
diff --git a/util/include/chre/util/unique_ptr_impl.h b/util/include/chre/util/unique_ptr_impl.h
index ff4802e4..4e41284f 100644
--- a/util/include/chre/util/unique_ptr_impl.h
+++ b/util/include/chre/util/unique_ptr_impl.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_UTIL_UNIQUE_PTR_IMPL_H_
 #define CHRE_UTIL_UNIQUE_PTR_IMPL_H_
 
+// IWYU pragma: private
 #include "chre/util/unique_ptr.h"
 
 #include <string.h>
diff --git a/util/pigweed/rpc_client.cc b/util/pigweed/rpc_client.cc
index 6cf84626..5fb39ac6 100644
--- a/util/pigweed/rpc_client.cc
+++ b/util/pigweed/rpc_client.cc
@@ -97,9 +97,9 @@ void RpcClient::handleNanoappStopped(const void *eventData) {
   }
 
   if (info->instanceId == mChannelId) {
-    mRpcClient.CloseChannel(mChannelId);
+    mRpcClient.CloseChannel(mChannelId).IgnoreError();
     mChannelId = 0;
   }
 }
 
-}  // namespace chre
\ No newline at end of file
+}  // namespace chre
diff --git a/util/pigweed/rpc_server.cc b/util/pigweed/rpc_server.cc
index 0bf7d671..42be93b5 100644
--- a/util/pigweed/rpc_server.cc
+++ b/util/pigweed/rpc_server.cc
@@ -22,6 +22,7 @@
 #include "chre/util/nanoapp/log.h"
 #include "chre/util/pigweed/rpc_helper.h"
 #include "chre_api/chre.h"
+#include "pw_status/status.h"
 
 #ifndef LOG_TAG
 #define LOG_TAG "[RpcServer]"
@@ -121,10 +122,13 @@ bool RpcServer::handleMessageFromHost(const void *eventData) {
   }
 
   mHostOutput.setHostEndpoint(hostMessage->hostEndpoint);
-  mServer.OpenChannel(result.value(), mHostOutput);
-
-  pw::Status status = mServer.ProcessPacket(packet);
+  pw::Status status = mServer.OpenChannel(result.value(), mHostOutput);
+  if (status != pw::OkStatus() && status != pw::Status::AlreadyExists()) {
+    LOGE("Failed to open channel");
+    return false;
+  }
 
+  status = mServer.ProcessPacket(packet);
   if (status != pw::OkStatus()) {
     LOGE("Failed to process the packet");
     return false;
@@ -153,11 +157,14 @@ bool RpcServer::handleMessageFromNanoapp(uint32_t senderInstanceId,
   chreConfigureNanoappInfoEvents(true);
 
   mNanoappOutput.setClient(senderInstanceId);
-  mServer.OpenChannel(result.value(), mNanoappOutput);
-
-  pw::Status success = mServer.ProcessPacket(packet);
+  pw::Status status = mServer.OpenChannel(result.value(), mNanoappOutput);
+  if (status != pw::OkStatus() && status != pw::Status::AlreadyExists()) {
+    LOGE("Failed to open channel");
+    return false;
+  }
 
-  if (success != pw::OkStatus()) {
+  status = mServer.ProcessPacket(packet);
+  if (status != pw::OkStatus()) {
     LOGE("Failed to process the packet");
     return false;
   }
@@ -176,8 +183,10 @@ void RpcServer::handleHostClientNotification(const void *eventData) {
   if (notif->notificationType == HOST_ENDPOINT_NOTIFICATION_TYPE_DISCONNECT) {
     size_t hostIndex = mConnectedHosts.find(notif->hostEndpointId);
     if (hostIndex != mConnectedHosts.size()) {
-      mServer.CloseChannel(kChannelIdHostClient |
-                           static_cast<uint32_t>(notif->hostEndpointId));
+      mServer
+          .CloseChannel(kChannelIdHostClient |
+                        static_cast<uint32_t>(notif->hostEndpointId))
+          .IgnoreError();
       mConnectedHosts.erase(hostIndex);
     }
   }
@@ -188,8 +197,8 @@ void RpcServer::handleNanoappStopped(const void *eventData) {
 
   if (info->instanceId > kRpcNanoappMaxId) {
     LOGE("Invalid nanoapp Id 0x%08" PRIx32, info->instanceId);
-  } else {
-    mServer.CloseChannel(info->instanceId);
+  } else if (!mServer.CloseChannel(info->instanceId).ok()) {
+    LOGE("Failed to close channel for nanoapp 0x%08" PRIx32, info->instanceId);
   }
 }
 
@@ -197,4 +206,4 @@ pw::Status RpcServer::closeChannel(uint32_t id) {
   return mServer.CloseChannel(id);
 }
 
-}  // namespace chre
\ No newline at end of file
+}  // namespace chre
diff --git a/util/tests/duplicate_message_detector_test.cc b/util/tests/duplicate_message_detector_test.cc
new file mode 100644
index 00000000..50a83f11
--- /dev/null
+++ b/util/tests/duplicate_message_detector_test.cc
@@ -0,0 +1,101 @@
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
+#include "chre_api/chre.h"
+#include "gtest/gtest.h"
+
+#include "chre/platform/linux/system_time.h"
+#include "chre/util/duplicate_message_detector.h"
+
+using chre::platform_linux::SystemTimeOverride;
+
+namespace chre {
+
+constexpr Nanoseconds kTimeout = Nanoseconds(100);
+constexpr uint32_t kNumMessages = 100;
+
+TEST(DuplicateMessageDetectorTest, AddMessageCanBeFound) {
+  DuplicateMessageDetector duplicateMessageDetector(kTimeout);
+  uint32_t messageSequenceNumber = 1;
+  uint16_t hostEndpoint = 2;
+
+  EXPECT_FALSE(duplicateMessageDetector.findOrAdd(messageSequenceNumber,
+                                                  hostEndpoint).has_value());
+}
+
+TEST(DuplicateMessageDetectorTest, AddMultipleCanBeFound) {
+  DuplicateMessageDetector duplicateMessageDetector(kTimeout);
+  for (size_t i = 0; i < kNumMessages; ++i) {
+    EXPECT_FALSE(duplicateMessageDetector.findOrAdd(i, i).has_value());
+  }
+}
+
+TEST(DuplicateMessageDetectorTest, RemoveOldEntries) {
+  DuplicateMessageDetector duplicateMessageDetector(kTimeout);
+
+  for (size_t i = 0; i < kNumMessages; ++i) {
+    SystemTimeOverride override(i);
+    EXPECT_FALSE(duplicateMessageDetector.findOrAdd(i, kNumMessages - i)
+                 .has_value());
+  }
+
+  SystemTimeOverride override(kTimeout * 10);
+  duplicateMessageDetector.removeOldEntries();
+
+  for (size_t i = 0; i < kNumMessages; ++i) {
+    EXPECT_FALSE(duplicateMessageDetector.findAndSetError(i,
+                                                          kNumMessages - i,
+                                                          CHRE_ERROR_NONE));
+  }
+}
+
+TEST(DuplicateMessageDetectorTest, RemoveOldEntriesDoesNotRemoveRecentEntries) {
+  DuplicateMessageDetector duplicateMessageDetector(kTimeout);
+
+  for (size_t i = 0; i < kNumMessages; ++i) {
+    SystemTimeOverride override(i);
+    EXPECT_FALSE(duplicateMessageDetector.findOrAdd(i, i).has_value());
+  }
+
+  {
+    constexpr uint32_t kNumMessagesToRemove = kNumMessages / 2;
+    SystemTimeOverride override(kNumMessagesToRemove +
+                                kTimeout.toRawNanoseconds());
+    duplicateMessageDetector.removeOldEntries();
+
+    for (size_t i = 0; i <= kNumMessagesToRemove; ++i) {
+      EXPECT_FALSE(duplicateMessageDetector.findAndSetError(i, i,
+                                                            CHRE_ERROR_NONE));
+    }
+    for (size_t i = kNumMessagesToRemove + 1; i < kNumMessages; ++i) {
+      bool isDuplicate = false;
+      EXPECT_FALSE(
+          duplicateMessageDetector.findOrAdd(i, i, &isDuplicate).has_value());
+      EXPECT_TRUE(isDuplicate);
+      EXPECT_TRUE(duplicateMessageDetector.findAndSetError(i, i,
+                                                           CHRE_ERROR_NONE));
+
+      isDuplicate = false;
+      Optional<chreError> error =
+          duplicateMessageDetector.findOrAdd(i, i, &isDuplicate);
+      EXPECT_TRUE(error.has_value());
+      EXPECT_EQ(error.value(), CHRE_ERROR_NONE);
+      EXPECT_TRUE(isDuplicate);
+    }
+  }
+}
+
+}  // namespace chre
diff --git a/util/tests/dynamic_vector_test.cc b/util/tests/dynamic_vector_test.cc
index f72befdd..e69bd4cb 100644
--- a/util/tests/dynamic_vector_test.cc
+++ b/util/tests/dynamic_vector_test.cc
@@ -779,3 +779,54 @@ TEST(DynamicVector, Resize) {
   EXPECT_EQ(vector.size(), 99);
   EXPECT_EQ(vector.capacity(), 99);
 }
+
+/**
+ * A test class that exceeds the default max alignment and is not trivial.
+ */
+struct alignas(64) ExceedsMaxAlignNotTrivial {
+  ExceedsMaxAlignNotTrivial() {
+    value = 1000;
+  }
+
+  int value;
+};
+
+/**
+ * A test class that exceeds the default max alignment and is trivial.
+ */
+struct alignas(64) ExceedsMaxAlignIsTrivial {
+  int value;
+};
+
+static_assert(alignof(ExceedsMaxAlignNotTrivial) > alignof(std::max_align_t));
+static_assert(!std::is_trivial<ExceedsMaxAlignNotTrivial>::value);
+static_assert(alignof(ExceedsMaxAlignIsTrivial) > alignof(std::max_align_t));
+static_assert(std::is_trivial<ExceedsMaxAlignIsTrivial>::value);
+
+TEST(DynamicVector, AlignedAllocExceedsMaxAlignNotTrivial) {
+  for (size_t i = 0; i < 10; ++i) {
+    chre::DynamicVector<ExceedsMaxAlignNotTrivial> vector;
+    for (size_t j = 0; j < i; ++j) {
+      ExceedsMaxAlignNotTrivial exceedsMaxAlignNotTrivial;
+      EXPECT_TRUE(vector.push_back(exceedsMaxAlignNotTrivial));
+      EXPECT_NE(vector.data(), nullptr);
+      EXPECT_EQ(reinterpret_cast<uint64_t>(vector.data()) %
+                    alignof(ExceedsMaxAlignNotTrivial),
+                0);
+    }
+  }
+}
+
+TEST(DynamicVector, AlignedAllocExceedsMaxAlignIsTrivial) {
+  for (size_t i = 0; i < 10; ++i) {
+    chre::DynamicVector<ExceedsMaxAlignIsTrivial> vector;
+    for (size_t j = 0; j < i; ++j) {
+      ExceedsMaxAlignIsTrivial exceedsMaxAlignIsTrivial;
+      EXPECT_TRUE(vector.push_back(exceedsMaxAlignIsTrivial));
+      EXPECT_NE(vector.data(), nullptr);
+      EXPECT_EQ(reinterpret_cast<uint64_t>(vector.data()) %
+                    alignof(ExceedsMaxAlignIsTrivial),
+                0);
+    }
+  }
+}
diff --git a/util/tests/fragmentation_manager_test.cc b/util/tests/fragmentation_manager_test.cc
new file mode 100644
index 00000000..04d349f2
--- /dev/null
+++ b/util/tests/fragmentation_manager_test.cc
@@ -0,0 +1,185 @@
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
+#include "chre/util/fragmentation_manager.h"
+#include <stdio.h>
+#include <type_traits>
+#include "chre/util/memory.h"
+#include "gtest/gtest.h"
+
+namespace chre::test {
+
+TEST(FragmentationTest, CanRetrieveByteDataTest) {
+  constexpr size_t dataSize = 9;
+  constexpr size_t fragmentSize = 3;
+  uint8_t testData[dataSize];
+  Optional<Fragment<uint8_t>> fragment;
+  FragmentationManager<uint8_t, fragmentSize> testManager;
+
+  for (size_t i = 0; i < dataSize; i++) {
+    testData[i] = i;
+  }
+  testManager.init(testData, dataSize);
+  for (size_t iteration = 0; iteration < dataSize / fragmentSize; ++iteration) {
+    std::cout << iteration << std::endl;
+    fragment = testManager.getNextFragment();
+    EXPECT_TRUE(fragment.has_value());
+    EXPECT_EQ(fragment.value().size, fragmentSize);
+    for (size_t j = 0; j < fragmentSize; j++) {
+      EXPECT_EQ(fragment.value().data[j], j + iteration * fragmentSize);
+    }
+  }
+
+  fragment = testManager.getNextFragment();
+  EXPECT_FALSE(fragment.has_value());
+
+  testManager.deinit();
+}
+
+TEST(FragmentationTest, CanRetrieveLongDataTest) {
+  constexpr size_t dataSize = 10;
+  constexpr size_t fragmentSize = 3;
+  uint32_t testData[dataSize];
+  Optional<Fragment<uint32_t>> fragment;
+  FragmentationManager<uint32_t, fragmentSize> testManager;
+
+  for (size_t i = 0; i < dataSize; i++) {
+    testData[i] = i;
+  }
+  testManager.init(testData, dataSize);
+  for (size_t iteration = 0; iteration < dataSize / fragmentSize; ++iteration) {
+    fragment = testManager.getNextFragment();
+    EXPECT_TRUE(fragment.has_value());
+    EXPECT_EQ(fragment.value().size, fragmentSize);
+    for (size_t j = 0; j < fragmentSize; j++) {
+      EXPECT_EQ(fragment.value().data[j], j + iteration * fragmentSize);
+    }
+  }
+
+  // Special case for the last element.
+  fragment = testManager.getNextFragment();
+  EXPECT_TRUE(fragment.has_value());
+  EXPECT_EQ(fragment.value().size, 1);
+  EXPECT_EQ(fragment.value().data[0], testData[dataSize - 1]);
+
+  fragment = testManager.getNextFragment();
+  EXPECT_FALSE(fragment.has_value());
+
+  testManager.deinit();
+}
+
+TEST(FragmentationTest, FailWhenInitializingWithNullptr) {
+  constexpr size_t dataSize = 10;
+  constexpr size_t fragmentSize = 3;
+  FragmentationManager<uint64_t, fragmentSize> testManager;
+  EXPECT_FALSE(testManager.init(nullptr, dataSize));
+}
+
+TEST(FragmentationTest, CanRetrieveLongComplexDataTest) {
+  struct Foo {
+    uint8_t byteData;
+    uint32_t longData;
+    uint64_t doubleData;
+  };
+
+  constexpr size_t dataSize = 10;
+  constexpr size_t fragmentSize = 3;
+  Foo testData[dataSize];
+  Optional<Fragment<Foo>> fragment;
+  FragmentationManager<Foo, fragmentSize> testManager;
+
+  for (size_t i = 0; i < dataSize; i++) {
+    testData[i].byteData = i;
+    testData[i].longData = static_cast<uint64_t>(i) << 16 | i;
+    testData[i].doubleData = static_cast<uint64_t>(i) << 32 | i;
+  }
+
+  EXPECT_TRUE(testManager.init(testData, dataSize));
+  for (size_t iteration = 0; iteration < dataSize / fragmentSize; ++iteration) {
+    fragment = testManager.getNextFragment();
+    EXPECT_TRUE(fragment.has_value());
+    EXPECT_EQ(fragment.value().size, fragmentSize);
+    for (size_t j = 0; j < fragmentSize; j++) {
+      uint8_t arrayIndex = j + iteration * fragmentSize;
+      EXPECT_EQ(
+          memcmp(&fragment.value().data[j], &testData[arrayIndex], sizeof(Foo)),
+          0);
+    }
+    EXPECT_EQ(fragment.value().data, &testData[iteration * fragmentSize]);
+  }
+
+  // Special case for the last element.
+  fragment = testManager.getNextFragment();
+  EXPECT_TRUE(fragment.has_value());
+  EXPECT_EQ(fragment.value().size, 1);
+  EXPECT_EQ(
+      memcmp(&fragment.value().data[0], &testData[dataSize - 1], sizeof(Foo)),
+      0);
+
+  fragment = testManager.getNextFragment();
+  EXPECT_FALSE(fragment.has_value());
+
+  testManager.deinit();
+}
+
+TEST(FragmentationTest, CanReuseAfterDeinitInitTest) {
+  constexpr size_t dataSize = 10;
+  constexpr size_t fragmentSize = 3;
+  uint32_t testData[dataSize];
+  for (size_t i = 0; i < dataSize; i++) {
+    testData[i] = i;
+  }
+
+  constexpr size_t realDataSize = 13;
+  uint32_t realTestData[realDataSize];
+  for (size_t i = 0; i < realDataSize; i++) {
+    realTestData[i] = UINT32_MAX - i;
+  }
+
+  Optional<Fragment<uint32_t>> fragment;
+  FragmentationManager<uint32_t, fragmentSize> testManager;
+
+  testManager.init(testData, dataSize);
+  for (size_t iteration = 0; iteration < dataSize / fragmentSize; ++iteration) {
+    testManager.getNextFragment();
+  }
+  testManager.deinit();
+
+  testManager.init(realTestData, realDataSize);
+  for (size_t iteration = 0; iteration < realDataSize / fragmentSize;
+       ++iteration) {
+    fragment = testManager.getNextFragment();
+    EXPECT_TRUE(fragment.has_value());
+    EXPECT_EQ(fragment.value().size, fragmentSize);
+    for (size_t j = 0; j < fragmentSize; j++) {
+      EXPECT_EQ(fragment.value().data[j],
+                realTestData[iteration * fragmentSize + j]);
+    }
+  }
+
+  // Special case for the last element.
+  fragment = testManager.getNextFragment();
+  EXPECT_TRUE(fragment.has_value());
+  EXPECT_EQ(fragment.value().size, 1);
+  EXPECT_EQ(fragment.value().data[0], realTestData[realDataSize - 1]);
+
+  fragment = testManager.getNextFragment();
+  EXPECT_FALSE(fragment.has_value());
+
+  testManager.deinit();
+}
+
+}  // namespace chre::test
diff --git a/util/tests/intrusive_list_test.cc b/util/tests/intrusive_list_test.cc
index 98129050..655954da 100644
--- a/util/tests/intrusive_list_test.cc
+++ b/util/tests/intrusive_list_test.cc
@@ -138,3 +138,15 @@ TEST(IntrusiveList, LinkFront) {
   EXPECT_EQ(nodeB.node.next, &nodeA.node);
   EXPECT_EQ(nodeA.node.prev, &nodeB.node);
 }
+
+TEST(IntrusiveList, IsLinked) {
+  ListNode<int> node(0);
+  EXPECT_EQ(node.isLinked(), false);
+
+  IntrusiveList<int> list;
+  list.link_front(&node);
+  EXPECT_EQ(node.isLinked(), true);
+
+  list.unlink_front();
+  EXPECT_EQ(node.isLinked(), false);
+}
diff --git a/util/tests/stats_container_test.cc b/util/tests/stats_container_test.cc
index d3fba3c3..deea2b68 100644
--- a/util/tests/stats_container_test.cc
+++ b/util/tests/stats_container_test.cc
@@ -17,65 +17,18 @@
 #include "chre/util/system/stats_container.h"
 #include "gtest/gtest.h"
 
-TEST(StatsContainer, MeanBasicTest) {
+TEST(StatsContainer, MaxBasicTest) {
   chre::StatsContainer<uint8_t> testContainer;
 
-  ASSERT_EQ(testContainer.getMean(), 0);
+  ASSERT_EQ(testContainer.getMax(), 0);
 
-  testContainer.addValue(10);
   testContainer.addValue(20);
-  ASSERT_EQ(testContainer.getMean(), 15);
-
-  testContainer.addValue(40);
-  ASSERT_EQ(testContainer.getMean(), (10 + 20 + 40) / 3);
-}
-
-TEST(StatsContainer, UINTMeanOverflowTest) {
-  chre::StatsContainer<uint8_t> testContainer;
-
-  testContainer.addValue(200);
-  testContainer.addValue(100);
-  ASSERT_EQ(testContainer.getMean(), 150);
-}
-
-TEST(StatsContainer, AddSmallerValueThanMeanCheck) {
-  chre::StatsContainer<uint16_t> testContainer;
-
   testContainer.addValue(10);
-  testContainer.addValue(20);
-  testContainer.addValue(30);
-  ASSERT_EQ(testContainer.getMean(), 20);
-
-  testContainer.addValue(4);
-  ASSERT_EQ(testContainer.getMean(), 16);
-}
-
-TEST(StatsContainer, AddBiggerValueThanMeanCheck) {
-  chre::StatsContainer<uint16_t> testContainer;
-
-  testContainer.addValue(10);
-  testContainer.addValue(20);
-  testContainer.addValue(30);
-  ASSERT_EQ(testContainer.getMean(), 20);
+  ASSERT_EQ(testContainer.getMax(), 20);
 
   testContainer.addValue(40);
-  ASSERT_EQ(testContainer.getMean(), 25);
-}
-
-TEST(StatsContainer, OverAverageWindowCheck) {
-  uint64_t maxCount = 3;
-  chre::StatsContainer<uint16_t> testContainer(maxCount);
+  ASSERT_EQ(testContainer.getMax(), 40);
 
-  testContainer.addValue(10);
-  testContainer.addValue(20);
   testContainer.addValue(30);
-  ASSERT_EQ(testContainer.getMean(), 20);
-
-  testContainer.addValue(40);
-
-  /**
-   * Only check if StatsContainer still works after have more element than its
-   * averageWindow. Does not check the correctness of the estimated value
-   */
-  ASSERT_GT(testContainer.getMean(), 20);
-}
\ No newline at end of file
+  ASSERT_EQ(testContainer.getMax(), 40);
+}
diff --git a/util/tests/throttle_test.cc b/util/tests/throttle_test.cc
new file mode 100644
index 00000000..e32e8897
--- /dev/null
+++ b/util/tests/throttle_test.cc
@@ -0,0 +1,63 @@
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
+#include <cmath>
+#include <cstdint>
+
+#include "gtest/gtest.h"
+
+#include "chre/platform/linux/system_time.h"
+#include "chre/platform/system_time.h"
+#include "chre/util/throttle.h"
+#include "chre/util/time.h"
+
+using ::chre::Milliseconds;
+using ::chre::Nanoseconds;
+using ::chre::Seconds;
+using ::chre::SystemTime;
+using ::chre::platform_linux::SystemTimeOverride;
+
+TEST(Throttle, ThrottlesActionLessThanOneInterval) {
+  uint32_t count = 0;
+  constexpr uint32_t kMaxCount = 10;
+  constexpr uint64_t kCallCount = 1000;
+  constexpr Seconds kInterval(1);
+  static_assert(kCallCount < kInterval.toRawNanoseconds());
+
+  for (uint64_t i = 0; i < kCallCount; ++i) {
+    SystemTimeOverride override(i);
+    CHRE_THROTTLE(++count, kInterval, kMaxCount,
+                  SystemTime::getMonotonicTime());
+  }
+
+  EXPECT_EQ(count, kMaxCount);
+}
+
+TEST(Throttle, ThrottlesActionMoreThanOneInterval) {
+  uint32_t count = 0;
+  constexpr uint32_t kMaxCount = 10;
+  constexpr uint64_t kCallCount = 1000;
+  constexpr Nanoseconds kInterval(100);
+  static_assert(kCallCount > kInterval.toRawNanoseconds());
+
+  for (uint64_t i = 0; i < kCallCount; ++i) {
+    SystemTimeOverride override(i);
+    CHRE_THROTTLE(++count, kInterval, kMaxCount,
+                  SystemTime::getMonotonicTime());
+  }
+
+  EXPECT_EQ(count, (kCallCount / kInterval.toRawNanoseconds()) * kMaxCount);
+}
diff --git a/util/tests/transaction_manager_test.cc b/util/tests/transaction_manager_test.cc
index a743d363..0c70b2f4 100644
--- a/util/tests/transaction_manager_test.cc
+++ b/util/tests/transaction_manager_test.cc
@@ -14,490 +14,338 @@
  * limitations under the License.
  */
 
-#include <chrono>
-#include <condition_variable>
-#include <cstdint>
+#include "chre/util/transaction_manager.h"
+
+#include <algorithm>
 #include <map>
-#include <mutex>
-#include <optional>
 
-#include "chre/platform/linux/task_util/task_manager.h"
-#include "chre/util/nested_data_ptr.h"
-#include "chre/util/time.h"
-#include "chre/util/transaction_manager.h"
+#include "chre/core/event_loop_common.h"
+#include "chre/core/timer_pool.h"
+#include "chre/platform/linux/system_time.h"
 
+#include "gmock/gmock.h"
 #include "gtest/gtest.h"
 
+using chre::platform_linux::SystemTimeOverride;
+using testing::_;
+using testing::Return;
+
 namespace chre {
 namespace {
 
-constexpr uint16_t kMaxNumRetries = 3;
 constexpr size_t kMaxTransactions = 32;
-constexpr Milliseconds kRetryWaitTime = Milliseconds(10);
-constexpr Milliseconds kTransactionTimeout = Milliseconds(100);
-constexpr std::chrono::milliseconds kWaitTimeout =
-    std::chrono::milliseconds(500);
-
-class TransactionManagerTest;
-
-struct TransactionData {
-  TransactionManagerTest *test;
-  bool *transactionStarted;
-  uint32_t *numTimesTransactionStarted;
-  uint32_t data;
-};
+constexpr Nanoseconds kTimeout = Milliseconds(10);
+constexpr uint16_t kMaxAttempts = 3;
 
-struct TransactionCompleted {
-  TransactionData data;
-  uint8_t errorCode;
-};
+}  // anonymous namespace
 
-class TransactionManagerTest : public testing::Test {
- protected:
-  bool transactionStartCallback(TransactionData &data, bool doFaultyStart) {
-    bool faultyStartSuccess = true;
-    {
-      std::lock_guard<std::mutex> lock(mMutex);
-
-      if (data.transactionStarted != nullptr) {
-        *data.transactionStarted = true;
-      }
-
-      if (data.numTimesTransactionStarted != nullptr) {
-        ++(*data.numTimesTransactionStarted);
-        faultyStartSuccess = *data.numTimesTransactionStarted > 1;
-      }
-    }
+class MockTimerPool {
+ public:
+  MOCK_METHOD(TimerHandle, setSystemTimer,
+              (Nanoseconds, SystemEventCallbackFunction, SystemCallbackType,
+               void *));
+  MOCK_METHOD(bool, cancelSystemTimer, (TimerHandle));
+};
 
-    bool success = !doFaultyStart || faultyStartSuccess;
-    if (success) {
-      mCondVar.notify_all();
-    }
-    return success;
+class FakeTimerPool {
+ public:
+  TimerHandle setSystemTimer(Nanoseconds duration,
+                             SystemEventCallbackFunction *callback,
+                             SystemCallbackType /*callbackType*/, void *data) {
+    Timer timer = {
+        .expiry = SystemTime::getMonotonicTime() + duration,
+        .callback = callback,
+        .data = data,
+    };
+    TimerHandle handle = mNextHandle++;
+    mTimers[handle] = timer;
+    return handle;
+  }
+  bool cancelSystemTimer(TimerHandle handle) {
+    return mTimers.erase(handle) == 1;
   }
 
-  bool transactionCallback(const TransactionData &data, uint8_t errorCode) {
-    {
-      std::lock_guard<std::mutex> lock(mMutex);
-
-      EXPECT_FALSE(mTransactionCallbackCalled);
-      mTransactionCallbackCalled = true;
-      mTransactionCompleted.data = data;
-      mTransactionCompleted.errorCode = errorCode;
+  //! Advance the time to the next expiring timer and invoke its callback
+  //! @return false if no timers exist
+  bool invokeNextTimer(SystemTimeOverride &time,
+                       Nanoseconds additionalDelay = Nanoseconds(0)) {
+    auto it = std::min_element(mTimers.begin(), mTimers.end(),
+                               [](const auto &a, const auto &b) {
+                                 return a.second.expiry < b.second.expiry;
+                               });
+    if (it == mTimers.end()) {
+      return false;
     }
-
-    mCondVar.notify_all();
+    Timer timer = it->second;
+    mTimers.erase(it);
+    time.update(timer.expiry + additionalDelay);
+    timer.callback(/*type=*/0, timer.data, /*extraData=*/nullptr);
     return true;
   }
 
-  static bool deferCallback(
-      TransactionManager<TransactionData,
-                         kMaxTransactions>::DeferCallbackFunction func,
-      void *data, void *extraData, Nanoseconds delay,
-      uint32_t *outTimerHandle) {
-    if (func == nullptr) {
-      return false;
-    }
+  struct Timer {
+    Nanoseconds expiry;
+    SystemEventCallbackFunction *callback;
+    void *data;
+  };
 
-    const TransactionManagerTest *test = nullptr;
-    {
-      std::lock_guard<std::mutex> lock(sMapMutex);
-      auto iter = sMap.find(getTestName());
-      if (iter == sMap.end()) {
-        if (outTimerHandle != nullptr) {
-          *outTimerHandle = 0xDEADBEEF;
-        }
-        return true;  // Test is ending - no need to defer callback
-      }
-      test = iter->second;
-    }
-
-    std::optional<uint32_t> taskId = test->getTaskManager()->addTask(
-        [func, data, extraData]() { func(/* type= */ 0, data, extraData); },
-        std::chrono::nanoseconds(delay.toRawNanoseconds()),
-        /* isOneShot= */ true);
+  TimerHandle mNextHandle = 1;
+  std::map<TimerHandle, Timer> mTimers;
+};
 
-    if (!taskId.has_value()) {
-      return false;
-    }
+class MockTransactionManagerCallback : public TransactionManagerCallback {
+ public:
+  MOCK_METHOD(void, onTransactionAttempt, (uint32_t, uint16_t), (override));
+  MOCK_METHOD(void, onTransactionFailure, (uint32_t, uint16_t), (override));
+};
 
-    if (outTimerHandle != nullptr) {
-      *outTimerHandle = *taskId;
-    }
-    return true;
+class FakeTransactionManagerCallback : public TransactionManagerCallback {
+ public:
+  void onTransactionAttempt(uint32_t transactionId,
+                            uint16_t /*groupId*/) override {
+    mTries.push_back(transactionId);
+  }
+  void onTransactionFailure(uint32_t transactionId,
+                            uint16_t /*groupId*/) override {
+    mFailures.push_back(transactionId);
   }
 
-  static bool deferCancelCallback(uint32_t timerHandle) {
-    const TransactionManagerTest *test = nullptr;
-    {
-      std::lock_guard<std::mutex> lock(sMapMutex);
-      auto iter = sMap.find(getTestName());
-      if (iter == sMap.end()) {
-        return true;  // Test is ending - no need to cancel defer callback
-      }
-      test = iter->second;
-    }
+  std::vector<uint32_t> mTries;
+  std::vector<uint32_t> mFailures;
+};
 
-    return test->getTaskManager()->cancelTask(timerHandle);
-  }
+using TxnMgr = TransactionManager<kMaxTransactions, MockTimerPool>;
+using TxnMgrF = TransactionManager<kMaxTransactions, FakeTimerPool>;
 
-  static std::string getTestName() {
-    std::string testName;
-    auto instance = testing::UnitTest::GetInstance();
-    if (instance != nullptr) {
-      auto testInfo = instance->current_test_info();
-      if (testInfo != nullptr) {
-        testName = testInfo->name();
-      }
-    }
-    return testName;
+class TransactionManagerTest : public testing::Test {
+ public:
+ protected:
+  TxnMgr defaultTxnMgr() {
+    return TxnMgr(mFakeCb, mTimerPool, kTimeout, kMaxAttempts);
   }
 
-  TaskManager *getTaskManager() const {
-    EXPECT_NE(mTaskManager.get(), nullptr);
-    return mTaskManager.get();
+  TxnMgrF defaultTxnMgrF() {
+    return TxnMgrF(mFakeCb, mFakeTimerPool, kTimeout, kMaxAttempts);
   }
 
-  std::unique_ptr<TransactionManager<TransactionData, kMaxTransactions>>
-  getTransactionManager(bool doFaultyStart,
-                        uint16_t maxNumRetries = kMaxNumRetries) const {
-    return std::make_unique<TransactionManager<TransactionData, kMaxTransactions>>(
-        doFaultyStart
-            ? [](TransactionData &data) {
-              return data.test != nullptr &&
-                  data.test->transactionStartCallback(data,
-                      /* doFaultyStart= */ true);
-            }
-            : [](TransactionData &data) {
-              return data.test != nullptr &&
-                  data.test->transactionStartCallback(data,
-                      /* doFaultyStart= */ false);
-            },
-        [](const TransactionData &data, uint8_t errorCode) {
-          return data.test != nullptr &&
-              data.test->transactionCallback(data, errorCode);
-        },
-        TransactionManagerTest::deferCallback,
-        TransactionManagerTest::deferCancelCallback,
-        kRetryWaitTime,
-        kTransactionTimeout,
-        maxNumRetries);
-  }
+  static constexpr uint32_t kTimerId = 1;
 
-  void SetUp() override {
-    {
-      std::lock_guard<std::mutex> lock(sMapMutex);
-      std::string testName = getTestName();
-      ASSERT_FALSE(testName.empty());
-      sMap.insert_or_assign(testName, this);
-    }
+  MockTimerPool mTimerPool;
+  FakeTimerPool mFakeTimerPool;
+  FakeTransactionManagerCallback mFakeCb;
+  MockTransactionManagerCallback mMockCb;
+  SystemTimeOverride mTime = SystemTimeOverride(0);
+};
 
-    mTransactionManager = getTransactionManager(/* doFaultyStart= */ false);
-    mFaultyStartTransactionManager =
-        getTransactionManager(/* doFaultyStart= */ true);
-    mZeroRetriesTransactionManager =
-        getTransactionManager(/* doFaultyStart= */ false,
-                              /* maxNumRetries= */ 0);
+TEST_F(TransactionManagerTest, StartSingleTransaction) {
+  TxnMgr tm = defaultTxnMgr();
 
-    mTaskManager = std::make_unique<TaskManager>();
-  }
+  EXPECT_CALL(mTimerPool, setSystemTimer(kTimeout, _, _, _))
+      .Times(1)
+      .WillOnce(Return(kTimerId));
 
-  void TearDown() override {
-    {
-      std::lock_guard<std::mutex> lock(sMapMutex);
-      std::string testName = getTestName();
-      ASSERT_FALSE(testName.empty());
-      sMap.erase(testName);
-    }
+  uint32_t id;
+  EXPECT_TRUE(tm.add(/*groupId=*/0, &id));
 
-    mTaskManager->flushAndStop();
-    mTaskManager.reset();
-    mZeroRetriesTransactionManager.reset();
-    mFaultyStartTransactionManager.reset();
-    mTransactionManager.reset();
-  }
+  ASSERT_EQ(mFakeCb.mTries.size(), 1);
+  EXPECT_EQ(mFakeCb.mTries[0], id);
+  EXPECT_EQ(mFakeCb.mFailures.size(), 0);
+}
 
-  static std::mutex sMapMutex;
-  static std::map<std::string, const TransactionManagerTest *> sMap;
-
-  std::mutex mMutex;
-  std::condition_variable mCondVar;
-  bool mTransactionCallbackCalled = false;
-  std::unique_ptr<TaskManager> mTaskManager = nullptr;
-  TransactionCompleted mTransactionCompleted;
-
-  std::unique_ptr<TransactionManager<TransactionData, kMaxTransactions>>
-      mTransactionManager = nullptr;
-  std::unique_ptr<TransactionManager<TransactionData, kMaxTransactions>>
-      mFaultyStartTransactionManager = nullptr;
-  std::unique_ptr<TransactionManager<TransactionData, kMaxTransactions>>
-      mZeroRetriesTransactionManager = nullptr;
-};
-std::mutex TransactionManagerTest::sMapMutex;
-std::map<std::string, const TransactionManagerTest *>
-    TransactionManagerTest::sMap;
-
-TEST_F(TransactionManagerTest, TransactionShouldComplete) {
-  std::unique_lock<std::mutex> lock(mMutex);
-
-  bool transactionStarted1 = false;
-  bool transactionStarted2 = false;
-  uint32_t transactionId1;
-  uint32_t transactionId2;
-  EXPECT_TRUE(mTransactionManager->startTransaction(
-      {
-          .test = this,
-          .transactionStarted = &transactionStarted1,
-          .numTimesTransactionStarted = nullptr,
-          .data = 1,
-      },
-      /* cookie= */ 1, &transactionId1));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [&transactionStarted1]() { return transactionStarted1; });
-  EXPECT_TRUE(transactionStarted1);
-
-  EXPECT_TRUE(mTransactionManager->startTransaction(
-      {
-          .test = this,
-          .transactionStarted = &transactionStarted2,
-          .numTimesTransactionStarted = nullptr,
-          .data = 2,
-      },
-      /* cookie= */ 2, &transactionId2));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [&transactionStarted2]() { return transactionStarted2; });
-  EXPECT_TRUE(transactionStarted2);
-
-  mTransactionCallbackCalled = false;
-  EXPECT_TRUE(mTransactionManager->completeTransaction(
-      transactionId2, CHRE_ERROR_INVALID_ARGUMENT));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [this]() { return mTransactionCallbackCalled; });
-  EXPECT_TRUE(mTransactionCallbackCalled);
-  EXPECT_EQ(mTransactionCompleted.data.data, 2);
-  EXPECT_EQ(mTransactionCompleted.errorCode, CHRE_ERROR_INVALID_ARGUMENT);
-
-  mTransactionCallbackCalled = false;
-  EXPECT_TRUE(mTransactionManager->completeTransaction(transactionId1,
-                                                       CHRE_ERROR_NONE));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [this]() { return mTransactionCallbackCalled; });
-  EXPECT_TRUE(mTransactionCallbackCalled);
-  EXPECT_EQ(mTransactionCompleted.data.data, 1);
-  EXPECT_EQ(mTransactionCompleted.errorCode, CHRE_ERROR_NONE);
+TEST_F(TransactionManagerTest, RemoveSingleTransaction) {
+  TxnMgr tm = defaultTxnMgr();
+
+  EXPECT_CALL(mTimerPool, setSystemTimer(_, _, _, _))
+      .Times(1)
+      .WillOnce(Return(kTimerId));
+
+  uint32_t id;
+  ASSERT_TRUE(tm.add(/*groupId=*/0, &id));
+
+  EXPECT_CALL(mTimerPool, cancelSystemTimer(kTimerId))
+      .Times(1)
+      .WillOnce(Return(true));
+
+  EXPECT_TRUE(tm.remove(id));
+  EXPECT_EQ(mFakeCb.mTries.size(), 1);
+  EXPECT_EQ(mFakeCb.mFailures.size(), 0);
 }
 
-TEST_F(TransactionManagerTest, TransactionShouldCompleteOnlyOnce) {
-  std::unique_lock<std::mutex> lock(mMutex);
-
-  uint32_t transactionId;
-  bool transactionStarted = false;
-  EXPECT_TRUE(mTransactionManager->startTransaction(
-      {
-          .test = this,
-          .transactionStarted = &transactionStarted,
-          .numTimesTransactionStarted = nullptr,
-          .data = 1,
-      },
-      /* cookie= */ 1, &transactionId));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [&transactionStarted]() { return transactionStarted; });
-  EXPECT_TRUE(transactionStarted);
-
-  mTransactionCallbackCalled = false;
-  EXPECT_TRUE(mTransactionManager->completeTransaction(
-      transactionId, CHRE_ERROR_INVALID_ARGUMENT));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [this]() { return mTransactionCallbackCalled; });
-  EXPECT_TRUE(mTransactionCallbackCalled);
-
-  mTransactionCallbackCalled = false;
-  EXPECT_FALSE(mTransactionManager->completeTransaction(
-      transactionId, CHRE_ERROR_INVALID_ARGUMENT));
-  EXPECT_FALSE(mTransactionCallbackCalled);
+TEST_F(TransactionManagerTest, SingleTransactionSuccessOnRetry) {
+  TxnMgrF tm = defaultTxnMgrF();
+
+  uint32_t id;
+  ASSERT_TRUE(tm.add(0, &id));
+  EXPECT_TRUE(mFakeTimerPool.invokeNextTimer(mTime));
+  EXPECT_EQ(mFakeCb.mTries.size(), 2);
+
+  EXPECT_TRUE(tm.remove(id));
+  ASSERT_EQ(mFakeCb.mTries.size(), 2);
+  EXPECT_EQ(mFakeCb.mTries[0], id);
+  EXPECT_EQ(mFakeCb.mTries[1], id);
+  EXPECT_EQ(mFakeCb.mFailures.size(), 0);
+  EXPECT_FALSE(mFakeTimerPool.invokeNextTimer(mTime));
+}
+
+TEST_F(TransactionManagerTest, SingleTransactionTimeout) {
+  TxnMgrF tm = defaultTxnMgrF();
+
+  uint32_t id;
+  ASSERT_TRUE(tm.add(0, &id));
+  size_t count = 0;
+  while (mFakeTimerPool.invokeNextTimer(mTime) && count++ < kMaxAttempts * 2);
+  EXPECT_EQ(count, kMaxAttempts);
+  EXPECT_EQ(std::count(mFakeCb.mTries.begin(), mFakeCb.mTries.end(), id),
+            kMaxAttempts);
+  ASSERT_EQ(mFakeCb.mFailures.size(), 1);
+  EXPECT_EQ(mFakeCb.mFailures[0], id);
+
+  // The transaction should actually be gone
+  EXPECT_FALSE(tm.remove(id));
+  EXPECT_FALSE(mFakeTimerPool.invokeNextTimer(mTime));
+}
+
+TEST_F(TransactionManagerTest, TwoTransactionsDifferentGroups) {
+  TxnMgrF tm = defaultTxnMgrF();
+
+  uint32_t id1;
+  uint32_t id2;
+  EXPECT_TRUE(tm.add(/*groupId=*/0, &id1));
+  EXPECT_TRUE(tm.add(/*groupId=*/1, &id2));
+
+  // Both should start
+  ASSERT_EQ(mFakeCb.mTries.size(), 2);
+  EXPECT_EQ(mFakeCb.mTries[0], id1);
+  EXPECT_EQ(mFakeCb.mTries[1], id2);
+  EXPECT_EQ(mFakeCb.mFailures.size(), 0);
 }
 
-TEST_F(TransactionManagerTest, TransactionShouldTimeout) {
-  std::unique_lock<std::mutex> lock(mMutex);
-
-  uint32_t numTimesTransactionStarted = 0;
-  uint32_t transactionId;
-  mTransactionCallbackCalled = false;
-  EXPECT_TRUE(mTransactionManager->startTransaction(
-      {
-          .test = this,
-          .transactionStarted = nullptr,
-          .numTimesTransactionStarted = &numTimesTransactionStarted,
-          .data = 456,
-      },
-      /* cookie= */ 1, &transactionId));
-
-  mTransactionCallbackCalled = false;
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [this]() { return mTransactionCallbackCalled; });
-  EXPECT_TRUE(mTransactionCallbackCalled);
-  EXPECT_EQ(mTransactionCompleted.data.data, 456);
-  EXPECT_EQ(mTransactionCompleted.errorCode, CHRE_ERROR_TIMEOUT);
-  EXPECT_EQ(numTimesTransactionStarted, kMaxNumRetries + 1);
+TEST_F(TransactionManagerTest, TwoTransactionsSameGroup) {
+  TxnMgrF tm = defaultTxnMgrF();
+
+  uint32_t id1;
+  uint32_t id2;
+  EXPECT_TRUE(tm.add(/*groupId=*/0, &id1));
+  EXPECT_TRUE(tm.add(/*groupId=*/0, &id2));
+
+  // Only the first should start
+  ASSERT_EQ(mFakeCb.mTries.size(), 1);
+  EXPECT_EQ(mFakeCb.mTries[0], id1);
+
+  // Second starts after the first finishes
+  EXPECT_TRUE(tm.remove(id1));
+  ASSERT_EQ(mFakeCb.mTries.size(), 2);
+  EXPECT_EQ(mFakeCb.mTries[1], id2);
+
+  // Second completes with no funny business
+  EXPECT_TRUE(tm.remove(id2));
+  EXPECT_EQ(mFakeCb.mTries.size(), 2);
+  EXPECT_EQ(mFakeCb.mFailures.size(), 0);
+  EXPECT_FALSE(mFakeTimerPool.invokeNextTimer(mTime));
 }
 
-TEST_F(TransactionManagerTest,
-       TransactionShouldRetryWhenTransactCallbackFails) {
-  std::unique_lock<std::mutex> lock(mMutex);
-
-  uint32_t numTimesTransactionStarted = 0;
-  const NestedDataPtr<uint32_t> kData(456);
-  uint32_t transactionId;
-  mTransactionCallbackCalled = false;
-  EXPECT_TRUE(mFaultyStartTransactionManager->startTransaction(
-      {
-          .test = this,
-          .transactionStarted = nullptr,
-          .numTimesTransactionStarted = &numTimesTransactionStarted,
-          .data = kData,
-      },
-      /* cookie= */ 1, &transactionId));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [&numTimesTransactionStarted]() {
-    return numTimesTransactionStarted >= 2;
-  });
-  EXPECT_GE(numTimesTransactionStarted, 2);
-
-  mTransactionCallbackCalled = false;
-  EXPECT_TRUE(mFaultyStartTransactionManager->completeTransaction(
-      transactionId, CHRE_ERROR_NONE));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [this]() { return mTransactionCallbackCalled; });
-  EXPECT_TRUE(mTransactionCallbackCalled);
-  EXPECT_EQ(mTransactionCompleted.data.data, 456);
-  EXPECT_EQ(mTransactionCompleted.errorCode, CHRE_ERROR_NONE);
+TEST_F(TransactionManagerTest, TwoTransactionsSameGroupTimeout) {
+  TxnMgrF tm = defaultTxnMgrF();
+
+  uint32_t id1;
+  uint32_t id2;
+  EXPECT_TRUE(tm.add(/*groupId=*/0, &id1));
+  EXPECT_TRUE(tm.add(/*groupId=*/0, &id2));
+
+  // Time out the first transaction, which should kick off the second
+  for (size_t i = 0; i < kMaxAttempts; i++) {
+    EXPECT_TRUE(mFakeTimerPool.invokeNextTimer(mTime));
+  }
+  ASSERT_EQ(mFakeCb.mTries.size(), kMaxAttempts + 1);
+  EXPECT_EQ(std::count(mFakeCb.mTries.begin(), mFakeCb.mTries.end(), id1),
+            kMaxAttempts);
+  EXPECT_EQ(mFakeCb.mTries.back(), id2);
+
+  // Retry + time out behavior for second works the same as the first
+  for (size_t i = 0; i < kMaxAttempts; i++) {
+    EXPECT_TRUE(mFakeTimerPool.invokeNextTimer(mTime));
+  }
+  ASSERT_EQ(mFakeCb.mTries.size(), kMaxAttempts * 2);
+  EXPECT_EQ(std::count(mFakeCb.mTries.begin(), mFakeCb.mTries.end(), id2),
+            kMaxAttempts);
+  ASSERT_EQ(mFakeCb.mFailures.size(), 2);
+  EXPECT_EQ(mFakeCb.mFailures[0], id1);
+  EXPECT_EQ(mFakeCb.mFailures[1], id2);
+  EXPECT_FALSE(mFakeTimerPool.invokeNextTimer(mTime));
 }
 
-TEST_F(TransactionManagerTest, TransactionShouldTimeoutWithNoRetries) {
-  std::unique_lock<std::mutex> lock(mMutex);
-
-  uint32_t numTimesTransactionStarted = 0;
-  uint32_t transactionId;
-  mTransactionCallbackCalled = false;
-  EXPECT_TRUE(mZeroRetriesTransactionManager->startTransaction(
-      {
-          .test = this,
-          .transactionStarted = nullptr,
-          .numTimesTransactionStarted = &numTimesTransactionStarted,
-          .data = 456,
-      },
-      /* cookie= */ 1, &transactionId));
-
-  mTransactionCallbackCalled = false;
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [this]() { return mTransactionCallbackCalled; });
-  EXPECT_TRUE(mTransactionCallbackCalled);
-  EXPECT_EQ(mTransactionCompleted.data.data, 456);
-  EXPECT_EQ(mTransactionCompleted.errorCode, CHRE_ERROR_TIMEOUT);
-  EXPECT_EQ(numTimesTransactionStarted, 1);  // No retries - only called once
+TEST_F(TransactionManagerTest, TwoTransactionsSameGroupRemoveReverseOrder) {
+  TxnMgrF tm = defaultTxnMgrF();
+
+  uint32_t id1;
+  uint32_t id2;
+  EXPECT_TRUE(tm.add(/*groupId=*/0, &id1));
+  EXPECT_TRUE(tm.add(/*groupId=*/0, &id2));
+
+  // Only the first should start
+  ASSERT_EQ(mFakeCb.mTries.size(), 1);
+  EXPECT_EQ(mFakeCb.mTries[0], id1);
+
+  // Remove second one first
+  EXPECT_TRUE(tm.remove(id2));
+
+  // Finish the first one
+  EXPECT_TRUE(tm.remove(id1));
+  ASSERT_EQ(mFakeCb.mTries.size(), 1);
+  EXPECT_EQ(mFakeCb.mTries[0], id1);
+  EXPECT_EQ(mFakeCb.mFailures.size(), 0);
+  EXPECT_FALSE(mFakeTimerPool.invokeNextTimer(mTime));
 }
 
-TEST_F(TransactionManagerTest, FlushedTransactionShouldNotComplete) {
-  std::unique_lock<std::mutex> lock(mMutex);
-
-  bool transactionStarted1 = false;
-  bool transactionStarted2 = false;
-  uint32_t transactionId1;
-  uint32_t transactionId2;
-  EXPECT_TRUE(mTransactionManager->startTransaction(
-      {
-          .test = this,
-          .transactionStarted = &transactionStarted1,
-          .numTimesTransactionStarted = nullptr,
-          .data = 1,
-      },
-      /* cookie= */ 1, &transactionId1));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [&transactionStarted1]() { return transactionStarted1; });
-  EXPECT_TRUE(transactionStarted1);
-
-  EXPECT_TRUE(mTransactionManager->startTransaction(
-      {
-          .test = this,
-          .transactionStarted = &transactionStarted2,
-          .numTimesTransactionStarted = nullptr,
-          .data = 2,
-      },
-      /* cookie= */ 2, &transactionId2));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [&transactionStarted2]() { return transactionStarted2; });
-  EXPECT_TRUE(transactionStarted2);
-
-  EXPECT_EQ(mTransactionManager->flushTransactions(
-                [](const TransactionData &data, void *callbackData) {
-                  NestedDataPtr<uint32_t> magicNum(callbackData);
-                  return magicNum == 456 && data.data == 2;
-                },
-                NestedDataPtr<uint32_t>(456)),
-            1);
-
-  EXPECT_FALSE(mTransactionManager->completeTransaction(
-      transactionId2, CHRE_ERROR_INVALID_ARGUMENT));
-
-  mTransactionCallbackCalled = false;
-  EXPECT_TRUE(mTransactionManager->completeTransaction(transactionId1,
-                                                       CHRE_ERROR_NONE));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [this]() { return mTransactionCallbackCalled; });
-  EXPECT_TRUE(mTransactionCallbackCalled);
-  EXPECT_EQ(mTransactionCompleted.data.data, 1);
-  EXPECT_EQ(mTransactionCompleted.errorCode, CHRE_ERROR_NONE);
+TEST_F(TransactionManagerTest, MultipleTimeouts) {
+  TxnMgrF tm = defaultTxnMgrF();
+
+  // Timeout both in a single callback
+  uint32_t ids[2];
+  EXPECT_TRUE(tm.add(/*groupId=*/0, &ids[0]));
+  mTime.update(kTimeout.toRawNanoseconds() / 2);
+  EXPECT_TRUE(tm.add(/*groupId=*/1, &ids[1]));
+  EXPECT_TRUE(mFakeTimerPool.invokeNextTimer(mTime, kTimeout));
+  EXPECT_EQ(mFakeCb.mTries.size(), 4);
+
+  // Since both retries were dispatched at the same time, they should time out
+  // again together
+  EXPECT_TRUE(mFakeTimerPool.invokeNextTimer(mTime, kTimeout));
+  EXPECT_EQ(mFakeCb.mTries.size(), 6);
+
+  // If changing the max # of attempts, modify the below code too so it triggers
+  // failure
+  static_assert(kMaxAttempts == 3);
+  EXPECT_TRUE(mFakeTimerPool.invokeNextTimer(mTime, kTimeout));
+  EXPECT_EQ(mFakeCb.mTries.size(), 6);
+  for (size_t i = 0; i < mFakeCb.mTries.size(); i++) {
+    EXPECT_EQ(mFakeCb.mTries[i], ids[i % 2]);
+  }
+  ASSERT_EQ(mFakeCb.mFailures.size(), 2);
+  EXPECT_EQ(mFakeCb.mFailures[0], ids[0]);
+  EXPECT_EQ(mFakeCb.mFailures[1], ids[1]);
+  EXPECT_FALSE(mFakeTimerPool.invokeNextTimer(mTime));
 }
 
-TEST_F(TransactionManagerTest, TransactionShouldWaitSameCookie) {
-  std::unique_lock<std::mutex> lock(mMutex);
-
-  bool transactionStarted1 = false;
-  bool transactionStarted2 = false;
-  uint32_t transactionId1;
-  uint32_t transactionId2;
-  EXPECT_TRUE(mTransactionManager->startTransaction(
-      {
-          .test = this,
-          .transactionStarted = &transactionStarted1,
-          .numTimesTransactionStarted = nullptr,
-          .data = 1,
-      },
-      /* cookie= */ 0xCAFE, &transactionId1));
-  EXPECT_TRUE(mTransactionManager->startTransaction(
-      {
-          .test = this,
-          .transactionStarted = &transactionStarted2,
-          .numTimesTransactionStarted = nullptr,
-          .data = 2,
-      },
-      /* cookie= */ 0xCAFE, &transactionId2));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [&transactionStarted1]() { return transactionStarted1; });
-  EXPECT_TRUE(transactionStarted1);
-  EXPECT_FALSE(transactionStarted2);
-
-  mTransactionCallbackCalled = false;
-  EXPECT_TRUE(mTransactionManager->completeTransaction(
-      transactionId1, CHRE_ERROR_INVALID_ARGUMENT));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [this, &transactionStarted2]() {
-                      return mTransactionCallbackCalled && transactionStarted2;
-                    });
-  EXPECT_TRUE(mTransactionCallbackCalled);
-  EXPECT_EQ(mTransactionCompleted.data.data, 1);
-  EXPECT_EQ(mTransactionCompleted.errorCode, CHRE_ERROR_INVALID_ARGUMENT);
-  EXPECT_TRUE(transactionStarted2);
-
-  mTransactionCallbackCalled = false;
-  EXPECT_TRUE(mTransactionManager->completeTransaction(transactionId2,
-                                                       CHRE_ERROR_NONE));
-  mCondVar.wait_for(lock, kWaitTimeout,
-                    [this]() { return mTransactionCallbackCalled; });
-  EXPECT_TRUE(mTransactionCallbackCalled);
-  EXPECT_EQ(mTransactionCompleted.data.data, 2);
-  EXPECT_EQ(mTransactionCompleted.errorCode, CHRE_ERROR_NONE);
+TEST_F(TransactionManagerTest, CallbackUsesCorrectGroupId) {
+  TxnMgrF tm(mMockCb, mFakeTimerPool, kTimeout, /*maxAttempts=*/1);
+
+  EXPECT_CALL(mMockCb, onTransactionAttempt(_, 1)).Times(1);
+  EXPECT_CALL(mMockCb, onTransactionAttempt(_, 2)).Times(1);
+  EXPECT_CALL(mMockCb, onTransactionAttempt(_, 3)).Times(1);
+
+  uint32_t id;
+  tm.add(1, &id);
+  tm.add(2, &id);
+  tm.add(3, &id);
+
+  EXPECT_CALL(mMockCb, onTransactionFailure(_, 1)).Times(1);
+  EXPECT_CALL(mMockCb, onTransactionFailure(_, 2)).Times(1);
+  EXPECT_CALL(mMockCb, onTransactionFailure(_, 3)).Times(1);
+
+  mFakeTimerPool.invokeNextTimer(mTime);
+  mFakeTimerPool.invokeNextTimer(mTime);
+  mFakeTimerPool.invokeNextTimer(mTime);
 }
 
-}  // namespace
 }  // namespace chre
diff --git a/util/util.mk b/util/util.mk
index 8cb8413c..b03bd26f 100644
--- a/util/util.mk
+++ b/util/util.mk
@@ -10,6 +10,7 @@ COMMON_CFLAGS += -I$(CHRE_PREFIX)/util/include
 # Common Source Files ##########################################################
 
 COMMON_SRCS += $(CHRE_PREFIX)/util/buffer_base.cc
+COMMON_SRCS += $(CHRE_PREFIX)/util/duplicate_message_detector.cc
 COMMON_SRCS += $(CHRE_PREFIX)/util/dynamic_vector_base.cc
 COMMON_SRCS += $(CHRE_PREFIX)/util/hash.cc
 COMMON_SRCS += $(CHRE_PREFIX)/util/intrusive_list_base.cc
@@ -31,7 +32,9 @@ GOOGLETEST_SRCS += $(CHRE_PREFIX)/util/tests/blocking_queue_test.cc
 GOOGLETEST_SRCS += $(CHRE_PREFIX)/util/tests/buffer_test.cc
 GOOGLETEST_SRCS += $(CHRE_PREFIX)/util/tests/copyable_fixed_size_vector_test.cc
 GOOGLETEST_SRCS += $(CHRE_PREFIX)/util/tests/debug_dump_test.cc
+GOOGLETEST_SRCS += $(CHRE_PREFIX)/util/tests/duplicate_message_detector_test.cc
 GOOGLETEST_SRCS += $(CHRE_PREFIX)/util/tests/dynamic_vector_test.cc
+GOOGLETEST_SRCS += $(CHRE_PREFIX)/util/tests/fragmentation_manager_test.cc
 GOOGLETEST_SRCS += $(CHRE_PREFIX)/util/tests/fixed_size_vector_test.cc
 GOOGLETEST_SRCS += $(CHRE_PREFIX)/util/tests/heap_test.cc
 GOOGLETEST_SRCS += $(CHRE_PREFIX)/util/tests/intrusive_list_test.cc
diff --git a/variant/tinysys/variant.mk b/variant/tinysys/variant.mk
index c5690b40..58493051 100644
--- a/variant/tinysys/variant.mk
+++ b/variant/tinysys/variant.mk
@@ -1,3 +1,8 @@
+#
+# Google Reference CHRE framework build customization for tinysys platforms.
+#
+# Build customization of nanoapps can be found in aosp_riscv*_tinysys.mk.
+#
 
 ifeq ($(ANDROID_BUILD_TOP),)
 $(error "You should supply an ANDROID_BUILD_TOP environment variable \
@@ -68,7 +73,7 @@ TINYSYS_CFLAGS += -DCHRE_MAX_EVENT_BLOCKS=4
 CHRE_AUDIO_SUPPORT_ENABLED = true
 CHRE_GNSS_SUPPORT_ENABLED = true
 CHRE_SENSORS_SUPPORT_ENABLED = true
-CHRE_WIFI_SUPPORT_ENABLED = false
+CHRE_WIFI_SUPPORT_ENABLED = true
 CHRE_WWAN_SUPPORT_ENABLED = false
 CHRE_BLE_SUPPORT_ENABLED = true
 
```

