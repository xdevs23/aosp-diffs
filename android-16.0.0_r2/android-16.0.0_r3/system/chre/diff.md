```diff
diff --git a/Android.bp b/Android.bp
index 1e0cfda0..af9b575e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -50,6 +50,7 @@ filegroup {
         "host/common/log_message_parser.cc",
         "host/common/preloaded_nanoapp_loader.cc",
         "host/common/time_syncer.cc",
+        "host/hal_generic/common/error_util.cc",
         "host/hal_generic/common/hal_client_manager.cc",
         "host/hal_generic/common/multi_client_context_hub_base.cc",
         "host/hal_generic/common/permissions_util.cc",
@@ -93,8 +94,8 @@ cc_defaults {
         "system/chre/host/common/include/",
         "system/chre/host/hal_generic/aidl/",
         "system/chre/host/hal_generic/common/",
-        "system/chre/platform/shared/include/",
         "system/chre/platform/shared/fbs/include",
+        "system/chre/platform/shared/include/",
         "system/chre/util/include/",
     ],
     header_libs: [
@@ -137,8 +138,8 @@ cc_library_static {
     ],
     export_include_dirs: [
         "host/common/include",
-        "platform/shared/include",
         "platform/shared/fbs/include",
+        "platform/shared/include",
         "util/include",
     ],
     srcs: [
@@ -155,7 +156,7 @@ cc_library_static {
     header_libs: ["chre_flatbuffers"],
     export_header_lib_headers: ["chre_flatbuffers"],
     shared_libs: [
-        "android.hardware.contexthub-V3-ndk",
+        "android.hardware.contexthub-V4-ndk",
         "libaconfig_storage_read_api_cc",
         "libbase",
         "libbinder_ndk",
@@ -303,8 +304,8 @@ cc_binary {
     name: "chre_power_test_client",
     vendor: true,
     local_include_dirs: [
-        "apps/power_test/common/include",
         "apps/power_test/common/generated/include",
+        "apps/power_test/common/include",
         "chre_api/include/chre_api",
         "util/include",
     ],
@@ -328,38 +329,6 @@ filegroup {
     srcs: ["host/common/st_hal_lpma_handler.cc"],
 }
 
-cc_binary {
-    name: "chre_aidl_hal_client",
-    vendor: true,
-    cpp_std: "c++20",
-    local_include_dirs: [
-        "chre_api/include",
-        "host/common/include",
-    ],
-    srcs: [
-        "host/common/chre_aidl_hal_client.cc",
-        "host/common/file_stream.cc",
-        "host/common/log.cc",
-    ],
-    shared_libs: [
-        "android.hardware.contexthub-V3-ndk",
-        "libbase",
-        "libbinder_ndk",
-        "libjsoncpp",
-        "liblog",
-        "libutils",
-    ],
-    static_libs: [
-        "chre_client",
-    ],
-    cflags: [
-        "-DLOG_TAG=\"CHRE.HAL.CLIENT\"",
-        "-Wall",
-        "-Werror",
-        "-fexceptions",
-    ],
-}
-
 cc_test {
     name: "audio_stress_test",
     vendor: true,
@@ -585,7 +554,7 @@ cc_library_static {
 }
 
 cc_test_host {
-    name: "hal_unit_tests",
+    name: "chre_hal_unit_tests",
     vendor: true,
     srcs: [
         "host/common/fragmented_load_transaction.cc",
@@ -600,8 +569,8 @@ cc_test_host {
         "host/hal_generic/common/",
         "platform/android/include",
         "platform/include",
-        "platform/shared/include/",
         "platform/shared/fbs/include",
+        "platform/shared/include/",
         "util/include/",
     ],
     static_libs: [
@@ -610,6 +579,7 @@ cc_test_host {
         "chre_host_common",
         "event_logger",
         "libgmock",
+        "pw_base64",
         "pw_detokenizer",
     ],
     shared_libs: [
@@ -745,8 +715,8 @@ cc_library_static {
     export_include_dirs: [
         "platform/include",
         "platform/linux/include",
-        "platform/shared/include",
         "platform/shared/fbs/include",
+        "platform/shared/include",
         "util/include",
     ],
     header_libs: [
@@ -789,8 +759,8 @@ cc_test_host {
         "pal/util/include",
         "platform/include",
         "platform/linux/include",
-        "platform/shared/include",
         "platform/shared/fbs/include",
+        "platform/shared/include",
         "platform/shared/pw_trace/include",
         "util/include",
     ],
@@ -962,6 +932,7 @@ cc_test_host {
     ],
     local_include_dirs: [
         "platform/shared",
+        "platform/shared/nanoapp_memory_guard_no_op/include",
         "platform/shared/public_platform_ble_pal",
         "platform/shared/public_platform_debug_dump_manager",
         "platform/shared/public_platform_gnss_pal",
@@ -1080,8 +1051,9 @@ cc_library_static {
         "platform/include",
         "platform/linux/include",
         "platform/shared/audio_pal/include",
-        "platform/shared/include",
         "platform/shared/fbs/include",
+        "platform/shared/include",
+        "platform/shared/nanoapp_memory_guard_no_op/include",
         "platform/shared/public_platform_ble_pal",
         "platform/shared/public_platform_debug_dump_manager",
         "platform/shared/public_platform_gnss_pal",
@@ -1138,6 +1110,8 @@ cc_defaults {
         "-DGTEST",
         "-Wextra-semi",
         "-Wvla-extension",
+        "-Wall",
+        "-Werror",
     ],
 }
 
@@ -1150,8 +1124,8 @@ cc_defaults {
     local_include_dirs: [
         "external/flatbuffers/include",
         "host/common/include",
-        "platform/shared/include",
         "platform/shared/fbs/include",
+        "platform/shared/include",
         "util/include",
     ],
     srcs: [
@@ -1213,6 +1187,7 @@ cc_binary {
         "host/exynos/main.cc",
     ],
     static_libs: [
+        "pw_base64",
         "pw_detokenizer",
         "pw_polyfill",
         "pw_span",
@@ -1240,6 +1215,20 @@ java_library_static {
     sdk_version: "current",
 }
 
+java_library_static {
+    name: "endpoint_echo_test_proto_java_lite",
+    host_supported: true,
+    proto: {
+        type: "lite",
+        include_dirs: ["external/protobuf/src"],
+    },
+    srcs: [
+        ":libprotobuf-internal-protos",
+        "apps/test/common/endpoint_echo_test/rpc/endpoint_echo_test.proto",
+    ],
+    sdk_version: "current",
+}
+
 cc_library_static {
     name: "chre_host_util",
     vendor_available: true,
@@ -1249,9 +1238,11 @@ cc_library_static {
     ],
     srcs: [
         "host/common/file_stream.cc",
+        "host/common/time_util.cc",
     ],
     shared_libs: [
         "liblog",
+        "libutils",
     ],
     cflags: [
         "-Wall",
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/crypto/aes.c b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/crypto/aes.c
index 25c0e6fc..630fa3e4 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/crypto/aes.c
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/crypto/aes.c
@@ -251,7 +251,7 @@ void aesEncr(struct AesContext *ctx, const uint32_t *src, uint32_t *dst) {
 int aesCtrInit(struct AesCtrContext *ctx, const void *k, const void *iv,
                enum AesKeyType key_type) {
   const uint32_t *p_k;
-  uint32_t aligned_k[AES_BLOCK_WORDS];
+  uint32_t aligned_k[AES_KEY_MAX_WORDS];
 
   if (AES_128_KEY_TYPE == key_type) {
     ctx->aes.aes_key_words = AES_128_KEY_WORDS;
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/hw_filter.cc b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/hw_filter.cc
index f3742094..760285c6 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/hw_filter.cc
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/hw_filter.cc
@@ -9,42 +9,50 @@
 
 namespace nearby {
 
+bool HwFilter::Match(const chreBleGenericFilter &hardware_filter,
+                     const chreBleAdvertisingReport &report) {
+  // Scans through data and parses each advertisement structure.
+  for (int i = 0; i < report.dataLength;) {
+    // First byte has the advertisement data length including type and data.
+    uint8_t ad_type_data_length = report.data[i];
+    // Early termination with zero length advertisement.
+    if (ad_type_data_length == 0) break;
+    // Terminates when advertisement length passes over the end of data
+    // buffer.
+    if (ad_type_data_length >= report.dataLength - i) break;
+    // Second byte has advertisement data type.
+    ++i;
+    // Moves to the next data structure if advertisement data length is less
+    // than filter length regardless of data mask or advertisement data
+    // type is different from filter type.
+    if (ad_type_data_length - 1 >= hardware_filter.len &&
+        report.data[i] == hardware_filter.type) {
+      // Assumes advertisement data structure is matched.
+      bool matched = true;
+      // Data should match through data filter mask within filter length.
+      for (int j = 0; j < hardware_filter.len; ++j) {
+        if ((report.data[i + 1 + j] & hardware_filter.dataMask[j]) !=
+            (hardware_filter.data[j] & hardware_filter.dataMask[j])) {
+          matched = false;
+          break;
+        }
+      }
+      if (matched) {
+        return true;
+      }
+    }
+    // Moves to next advertisement structure.
+    i += ad_type_data_length;
+  }
+  return false;
+}
+
 bool HwFilter::Match(
     const chre::DynamicVector<chreBleGenericFilter> &hardware_filters,
     const chreBleAdvertisingReport &report) {
-  for (const auto filter : hardware_filters) {
-    // Scans through data and parses each advertisement structure.
-    for (int i = 0; i < report.dataLength;) {
-      // First byte has the advertisement data length including type and data.
-      uint8_t ad_type_data_length = report.data[i];
-      // Early termination with zero length advertisement.
-      if (ad_type_data_length == 0) break;
-      // Terminates when advertisement length passes over the end of data
-      // buffer.
-      if (ad_type_data_length >= report.dataLength - i) break;
-      // Second byte has advertisement data type.
-      ++i;
-      // Moves to the next data structure if advertisement data length is less
-      // than filter length regardless of data mask or advertisement data
-      // type is different from filter type.
-      if (ad_type_data_length - 1 >= filter.len &&
-          report.data[i] == filter.type) {
-        // Assumes advertisement data structure is matched.
-        bool matched = true;
-        // Data should match through data filter mask within filter length.
-        for (int j = 0; j < filter.len; ++j) {
-          if ((report.data[i + 1 + j] & filter.dataMask[j]) !=
-              (filter.data[j] & filter.dataMask[j])) {
-            matched = false;
-            break;
-          }
-        }
-        if (matched) {
-          return true;
-        }
-      }
-      // Moves to next advertisement structure.
-      i += ad_type_data_length;
+  for (const auto hardware_filter : hardware_filters) {
+    if (Match(hardware_filter, report)) {
+      return true;
     }
   }
   return false;
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/hw_filter.h b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/hw_filter.h
index d26f834f..0aa58fd9 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/hw_filter.h
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/hw_filter.h
@@ -9,7 +9,13 @@ namespace nearby {
 
 class HwFilter {
  public:
-  // Matches BLE advertisement with hardware filter and returns the result.
+  // Matches BLE advertisement with a single hardware filter and returns the
+  // result.
+  static bool Match(const chreBleGenericFilter &hardware_filter,
+                    const chreBleAdvertisingReport &report);
+
+  // Matches BLE advertisement with multiple hardware filters and returns the
+  // result.
   static bool Match(
       const chre::DynamicVector<chreBleGenericFilter> &hardware_filters,
       const chreBleAdvertisingReport &report);
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_filter.cc b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_filter.cc
index cfd1e3c9..e7876063 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_filter.cc
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_filter.cc
@@ -1,6 +1,7 @@
 #include "location/lbs/contexthub/nanoapps/nearby/tracker_filter.h"
 
 #include <inttypes.h>
+
 #include <cstddef>
 #include <cstdint>
 #include <cstring>
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.cc b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.cc
index 5f0d8053..6a9200e4 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.cc
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.cc
@@ -7,6 +7,7 @@
 #include <utility>
 
 #include "chre_api/chre.h"
+#include "location/lbs/contexthub/nanoapps/nearby/hw_filter.h"
 #include "third_party/contexthub/chre/util/include/chre/util/nanoapp/log.h"
 #include "third_party/contexthub/chre/util/include/chre/util/time.h"
 #include "third_party/contexthub/chre/util/include/chre/util/unique_ptr.h"
@@ -14,6 +15,24 @@
 #define LOG_TAG "[NEARBY][TRACKER_STORAGE]"
 
 namespace nearby {
+namespace {
+constexpr chreBleGenericFilter kDultTagGenericFilter = {
+    .type = CHRE_BLE_AD_TYPE_SERVICE_DATA_WITH_UUID_16_LE,
+    .len = 2,
+    .data = {0xb2, 0xfc},
+    .dataMask = {0xff, 0xff},
+};
+
+inline bool IsDultTagAdvertisingData(const uint8_t *data, uint16_t length) {
+  if (data == nullptr) {
+    return false;
+  }
+  chreBleAdvertisingReport report = {};
+  report.dataLength = length;
+  report.data = data;
+  return HwFilter::Match(kDultTagGenericFilter, report);
+}
+}  // namespace
 
 void TrackerStorage::Push(const chreBleAdvertisingReport &report,
                           const TrackerBatchConfig &config) {
@@ -126,9 +145,17 @@ void TrackerStorage::AddOrUpdateAdvertisingData(
     LOGW("Empty advertising data found in advertising report");
     return;
   }
+  // If the advertising data is the same as the previous one or exempt from
+  // updating advertising data, it will not do anything.
+  if (tracker_report.data != nullptr &&
+      ((tracker_report.header.dataLength == dataLength &&
+        memcmp(tracker_report.data.get(), report.data,
+               tracker_report.header.dataLength) == 0) ||
+       IsExemptFromUpdateAdvertisingData(tracker_report, report))) {
+    return;
+  }
   if (tracker_report.data == nullptr ||
       tracker_report.header.dataLength != dataLength) {
-    tracker_report.header = report;
     // Allocates advertise data and copy it as well.
     chre::UniquePtr<uint8_t[]> data =
         chre::MakeUniqueArray<uint8_t[]>(dataLength);
@@ -136,17 +163,26 @@ void TrackerStorage::AddOrUpdateAdvertisingData(
       LOGE("Memory allocation failed!");
       return;
     }
-    memcpy(data.get(), report.data, dataLength);
     tracker_report.data = std::move(data);
-    tracker_report.header.data = tracker_report.data.get();
-  } else if (tracker_report.header.dataLength == dataLength &&
-             memcmp(tracker_report.data.get(), report.data,
-                    tracker_report.header.dataLength) != 0) {
-    tracker_report.header = report;
-    memcpy(tracker_report.data.get(), report.data,
-           tracker_report.header.dataLength);
-    tracker_report.header.data = tracker_report.data.get();
   }
+  tracker_report.header = report;
+  memcpy(tracker_report.data.get(), report.data,
+         tracker_report.header.dataLength);
+  tracker_report.header.data = tracker_report.data.get();
+}
+
+bool TrackerStorage::IsExemptFromUpdateAdvertisingData(
+    const TrackerReport &tracker_report,
+    const chreBleAdvertisingReport &report) {
+  // For some tag devices, which alternate between legacy and DULT advertising
+  // formats using the same mac address, we want to prioritize and retain the
+  // DULT advertising data. If the existing tracker report contains DULT
+  // advertising data and the new report doesn't, we keep the existing DULT
+  // advertising data and ignore the new report by returning true so that
+  // exempting from updating advertising data.
+  return IsDultTagAdvertisingData(tracker_report.data.get(),
+                                  tracker_report.header.dataLength) &&
+         !IsDultTagAdvertisingData(report.data, report.dataLength);
 }
 
 bool TrackerStorage::IsEqualAddress(
diff --git a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.h b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.h
index 75eb1039..a4590b31 100644
--- a/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.h
+++ b/apps/nearby/location/lbs/contexthub/nanoapps/nearby/tracker_storage.h
@@ -152,6 +152,12 @@ class TrackerStorage {
   void AddOrUpdateAdvertisingData(TrackerReport &tracker_report,
                                   const chreBleAdvertisingReport &report);
 
+  // Returns whether the tracker report is exempt from updating advertising
+  // data.
+  bool IsExemptFromUpdateAdvertisingData(
+      const TrackerReport &tracker_report,
+      const chreBleAdvertisingReport &report);
+
   // Returns whether advertising address is same.
   bool IsEqualAddress(const TrackerReport &tracker_report,
                       const chreBleAdvertisingReport &report) const;
diff --git a/apps/nearby/third_party/contexthub/chre/util/include/chre/util/optional.h b/apps/nearby/third_party/contexthub/chre/util/include/chre/util/optional.h
index 24394cc8..de11d6c1 100644
--- a/apps/nearby/third_party/contexthub/chre/util/include/chre/util/optional.h
+++ b/apps/nearby/third_party/contexthub/chre/util/include/chre/util/optional.h
@@ -21,6 +21,31 @@
 
 namespace chre {
 
+/**
+ * A tag dispatch type to indicate an empty Optional state, similar to
+ * std::nullopt_t.
+ *
+ * This type is used in constructors and assignment operators of Optional
+ * to explicitly create or assign an empty (disengaged) state.
+ */
+struct nullopt_t {
+  // The constructor is explicit to prevent conversions from arbitrary integer
+  // types (like 0 or NULL/nullptr).
+  constexpr explicit nullopt_t(int /*dummy*/) {}
+};
+
+/**
+ * nullopt definition used to indicate an empty Optional, allows easier porting
+ * from std::optional and std::nullopt.
+ *
+ * This can be used to construct or assign an empty Optional.
+ * For example:
+ * chre::Optional<int> o = chre::nullopt;
+ * o = chre::nullopt;
+ * return chree::nullopt;
+ */
+inline constexpr nullopt_t nullopt{/*dummy*/ 0};
+
 /**
  * This container keeps track of an optional object. The container is similar to
  * std::optional introduced in C++17.
@@ -38,6 +63,11 @@ class Optional {
    */
   constexpr Optional() : mObject() {}
 
+  /**
+   * Constructs an optional object with no initial value (from chre::nullopt).
+   */
+  constexpr Optional(nullopt_t) noexcept : mObject() {}
+
   /**
    * Default copy constructor.
    *
diff --git a/apps/test/chqts/src/general_test/basic_sensor_test_base.cc b/apps/test/chqts/src/general_test/basic_sensor_test_base.cc
index 127fb99b..9d02b256 100644
--- a/apps/test/chqts/src/general_test/basic_sensor_test_base.cc
+++ b/apps/test/chqts/src/general_test/basic_sensor_test_base.cc
@@ -206,6 +206,8 @@ void BasicSensorTestBase::startTest() {
   }
 
   if (!found) {
+    LOGI("Skip the test as no sensor found. index=%" PRIu8 ", type=%" PRIu8,
+         mCurrentSensorIndex, mSensorType);
     sendStringToHost(MessageType::kSkipped,
                      "No default sensor found for optional sensor.");
     return;
@@ -325,7 +327,11 @@ void BasicSensorTestBase::finishTest() {
   LOGI("Final sampling status interval=%" PRIu64 " latency=%" PRIu64
        " enabled %d",
        status.interval, status.latency, status.enabled);
-  if (!mExternalSamplingStatusChange) {
+  if (mExternalSamplingStatusChange) {
+    LOGI(
+        "Interval and/or latency have been changed by others. Skip the "
+        "verification of chreSensorSamplingStatus");
+  } else {
     // No one else changed this, so it should be what we had before.
     if (status.enabled != mOriginalStatus.enabled) {
       EXPECT_FAIL_RETURN("SensorInfo.enabled not back to original");
@@ -411,8 +417,7 @@ void BasicSensorTestBase::verifyEventHeader(const chreSensorDataHeader *header,
            kEventLoopSlack);
       EXPECT_FAIL_RETURN("SensorDataHeader is in the past");
     }
-    if ((mState == State::kFinished) &&
-        (header->baseTimestamp > mDoneTimestamp)) {
+    if (mState == State::kFinished && header->baseTimestamp > mDoneTimestamp) {
       EXPECT_FAIL_RETURN("SensorDataHeader is from after DONE");
     }
     *timeToUpdate = header->baseTimestamp;
@@ -470,9 +475,10 @@ void BasicSensorTestBase::handleSamplingChangeEvent(
        eventData->status.interval, eventData->status.latency,
        eventData->status.enabled);
   if (mPrevSensorHandle.has_value() &&
-      (mPrevSensorHandle.value() == eventData->sensorHandle)) {
+      mPrevSensorHandle.value() == eventData->sensorHandle) {
     // We can get a "DONE" event from the previous sensor for multi-sensor
     // devices, so we ignore these events.
+    LOGI("Ignore the 'Done' event from previous sensor");
     return;
   }
 
@@ -492,8 +498,8 @@ void BasicSensorTestBase::handleSamplingChangeEvent(
       LOGW("SamplingChangeEvent disabled the sensor.");
     }
 
-    if ((mNewStatus.interval != eventData->status.interval) ||
-        (mNewStatus.latency != eventData->status.latency)) {
+    if (mNewStatus.interval != eventData->status.interval ||
+        mNewStatus.latency != eventData->status.latency) {
       // This is from someone other than us.  Let's note that so we know
       // our consistency checks are invalid.
       mExternalSamplingStatusChange = true;
@@ -503,7 +509,7 @@ void BasicSensorTestBase::handleSamplingChangeEvent(
 
 void BasicSensorTestBase::handleSensorDataEvent(uint16_t eventType,
                                                 const void *eventData) {
-  if ((mState == State::kPreStart) || (mState == State::kPreConfigure)) {
+  if (mState == State::kPreStart || mState == State::kPreConfigure) {
     EXPECT_FAIL_RETURN("SensorDataEvent sent too early.");
   }
   // Note, if mState is kFinished, we could be getting batched data which
@@ -517,11 +523,13 @@ void BasicSensorTestBase::handleSensorDataEvent(uint16_t eventType,
   // Send to the sensor itself for any additional checks of actual data.
   confirmDataIsSane(eventData);
   if (mState == State::kExpectingInitialDataEvent) {
+    LOGI("Received the initial data event");
     mState = State::kExpectingLastDataEvent;
   } else if (mState == State::kExpectingLastDataEvent) {
+    LOGI("Received the last data event");
     finishTest();
   } else if (mState != State::kFinished) {
-    uint32_t value = static_cast<uint32_t>(mState);
+    auto value = static_cast<uint32_t>(mState);
     sendInternalFailureToHost("Illegal mState in handleSensorDataEvent:",
                               &value);
   }
@@ -538,7 +546,7 @@ void BasicSensorTestBase::handleEvent(uint32_t senderInstanceId,
       CHRE_EVENT_SENSOR_DATA_EVENT_BASE + getSensorType();
 
   if (senderInstanceId == mInstanceId) {
-    if ((eventType == kStartEvent) && (mState == State::kPreStart)) {
+    if (eventType == kStartEvent && mState == State::kPreStart) {
       startTest();
     }
   } else if (senderInstanceId != CHRE_INSTANCE_ID) {
diff --git a/apps/test/chqts/src/general_test/basic_sensor_test_base.h b/apps/test/chqts/src/general_test/basic_sensor_test_base.h
index 9443f5f3..fc3ff0ac 100644
--- a/apps/test/chqts/src/general_test/basic_sensor_test_base.h
+++ b/apps/test/chqts/src/general_test/basic_sensor_test_base.h
@@ -83,7 +83,7 @@ class BasicSensorTestBase : public Test {
   virtual void confirmDataIsSane(const void *eventData) = 0;
 
  private:
-  enum State {
+  enum class State {
     kPreStart,
     kPreConfigure,
     kExpectingInitialDataEvent,
diff --git a/apps/test/chqts/src/general_test/basic_sensor_tests.cc b/apps/test/chqts/src/general_test/basic_sensor_tests.cc
index 6ca57819..e60c2b3f 100644
--- a/apps/test/chqts/src/general_test/basic_sensor_tests.cc
+++ b/apps/test/chqts/src/general_test/basic_sensor_tests.cc
@@ -15,12 +15,19 @@
  */
 
 #include <general_test/basic_sensor_tests.h>
+#include "chre/util/nanoapp/log.h"
 
 #include <shared/macros.h>
 #include <shared/send_message.h>
 
+#include <cinttypes>
+
 #include "chre/util/macros.h"
 
+#ifndef LOG_TAG
+#define LOG_TAG "[BasicSensorTest]"
+#endif
+
 namespace general_test {
 
 static void checkFloat(float value, float extremeLow, float extremeHigh) {
@@ -44,6 +51,8 @@ static void checkTimestampDelta(uint32_t delta, size_t index) {
 static void verifyThreeAxisData(const void *eventData, float extremeLow,
                                 float extremeHigh) {
   auto data = static_cast<const chreSensorThreeAxisData *>(eventData);
+  LOGI("3-axis data event: timestamp=%" PRIu64 ", handle=%" PRIu32,
+       data->header.baseTimestamp, data->header.sensorHandle);
   for (size_t i = 0; i < data->header.readingCount; i++) {
     checkTimestampDelta(data->readings[i].timestampDelta, i);
     for (size_t j = 0; j < 3; j++) {
diff --git a/apps/test/common/endpoint_echo_test/Makefile b/apps/test/common/endpoint_echo_test/Makefile
new file mode 100644
index 00000000..a9bde556
--- /dev/null
+++ b/apps/test/common/endpoint_echo_test/Makefile
@@ -0,0 +1,23 @@
+#
+# Endpoint Echo Test Nanoapp Makefile
+#
+
+# Makefile Includes ############################################################
+
+include endpoint_echo_test.mk
+
+# Nanoapp Configuration ########################################################
+
+NANOAPP_NAME = endpoint_echo_test
+NANOAPP_ID = 0x476f6f6754000012
+NANOAPP_NAME_STRING = \"Endpoint\ Echo\ Test\"
+NANOAPP_VERSION = 0x00000001
+
+# Compiler Flags ###############################################################
+
+# Defines
+COMMON_CFLAGS += -DLOG_TAG=\"[EndpointEchoTest]\"
+
+# Makefile Includes ############################################################
+
+include $(CHRE_PREFIX)/build/nanoapp/app.mk
diff --git a/apps/test/common/endpoint_echo_test/endpoint_echo_test.mk b/apps/test/common/endpoint_echo_test/endpoint_echo_test.mk
new file mode 100644
index 00000000..c1a62e86
--- /dev/null
+++ b/apps/test/common/endpoint_echo_test/endpoint_echo_test.mk
@@ -0,0 +1,40 @@
+#
+# Endpoint Echo Test Nanoapp Makefile
+#
+# Environment Checks ###########################################################
+ifeq ($(CHRE_PREFIX),)
+  ifneq ($(ANDROID_BUILD_TOP),)
+    CHRE_PREFIX = $(ANDROID_BUILD_TOP)/system/chre
+  else
+    $(error "You must run 'lunch' to setup ANDROID_BUILD_TOP, or explicitly \
+    define the CHRE_PREFIX environment variable to point to the CHRE root \
+    directory.")
+  endif
+endif
+
+# Nanoapp Configuration ########################################################
+
+NANOAPP_PATH = $(CHRE_PREFIX)/apps/test/common/endpoint_echo_test
+
+# Source Code ##################################################################
+
+COMMON_SRCS += $(NANOAPP_PATH)/src/endpoint_echo_test_manager.cc
+COMMON_SRCS += $(NANOAPP_PATH)/src/endpoint_echo_test.cc
+
+# Utilities ####################################################################
+
+# Compiler Flags ###############################################################
+
+# Defines
+COMMON_CFLAGS += -DNANOAPP_MINIMUM_LOG_LEVEL=CHRE_LOG_LEVEL_DEBUG
+COMMON_CFLAGS += -DCHRE_ASSERTIONS_ENABLED
+
+# Includes
+COMMON_CFLAGS += -I$(NANOAPP_PATH)/inc
+
+# Permission declarations ######################################################
+
+# PW RPC protos ################################################################
+
+PW_RPC_SRCS = $(NANOAPP_PATH)/rpc/endpoint_echo_test.proto
+PW_RPC_SRCS += $(ANDROID_BUILD_TOP)/external/protobuf/src/google/protobuf/empty.proto
diff --git a/apps/test/common/endpoint_echo_test/inc/endpoint_echo_test_manager.h b/apps/test/common/endpoint_echo_test/inc/endpoint_echo_test_manager.h
new file mode 100644
index 00000000..8e7c251f
--- /dev/null
+++ b/apps/test/common/endpoint_echo_test/inc/endpoint_echo_test_manager.h
@@ -0,0 +1,168 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef ENDPOINT_ECHO_TEST_MANAGER_H_
+#define ENDPOINT_ECHO_TEST_MANAGER_H_
+
+#include <cinttypes>
+#include <cstdint>
+
+#include "chre/util/optional.h"
+#include "chre/util/pigweed/rpc_server.h"
+#include "chre/util/singleton.h"
+#include "chre/util/time.h"
+#include "chre_api/chre.h"
+#include "endpoint_echo_test.rpc.pb.h"
+
+class EndpointEchoTestService final
+    : public chre::rpc::pw_rpc::nanopb::EndpointEchoTestService::Service<
+          EndpointEchoTestService> {
+ public:
+  void RunNanoappToHostTest(const google_protobuf_Empty &request,
+                            ServerWriter<chre_rpc_ReturnStatus> &writer);
+};
+
+/**
+ * Handles requests for the Endpoint Echo Test nanoapp.
+ */
+class EndpointEchoTestManager {
+ public:
+  /**
+   * Allows the manager to do any init necessary as part of nanoappStart.
+   */
+  bool start();
+
+  /**
+   * Allows the manager to do any cleanup necessary as part of nanoappEnd.
+   */
+  void end();
+
+  /**
+   * Handle a CHRE event.
+   *
+   * @param senderInstanceId    the instand ID that sent the event.
+   * @param eventType           the type of the event.
+   * @param eventData           the data for the event.
+   */
+  void handleEvent(uint32_t senderInstanceId, uint16_t eventType,
+                   const void *eventData);
+
+  /**
+   * Sets the permission for the next server message.
+   *
+   * @params permission Bitmasked CHRE_MESSAGE_PERMISSION_.
+   */
+  void setPermissionForNextMessage(uint32_t permission);
+
+  /**
+   * Starts the nanoapp-initiated part of the test.
+   * @param writer The writer to use to send the test status.
+   */
+  void startTest(
+      EndpointEchoTestService::ServerWriter<chre_rpc_ReturnStatus> &&writer);
+
+ private:
+  /** The service descriptor for the echo service. */
+  constexpr static char kTestEchoServiceDescriptor[] =
+      "android.hardware.contexthub.test.EchoService";
+
+  /** The echo test service used for endpoint messaging. */
+  constexpr static chreMsgServiceInfo kTestEchoService = {
+      .majorVersion = 1,
+      .minorVersion = 0,
+      .serviceDescriptor = kTestEchoServiceDescriptor,
+      .serviceFormat = chreMsgEndpointServiceFormat::
+          CHRE_MSG_ENDPOINT_SERVICE_FORMAT_CUSTOM};
+
+  /** The timeout for the test. */
+  constexpr static chre::Nanoseconds kTestTimeout =
+      chre::Nanoseconds(5 * chre::kOneSecondInNanoseconds);
+
+  /** The phases of the test. */
+  enum class TestPhase {
+    kOpenSession,
+    kSendMessage,
+    kCloseSession,
+  };
+
+  /**
+   * Handle a CHRE event for the nanoapp -> host -> nanoapp test path.
+   *
+   * @param senderInstanceId    the instand ID that sent the event.
+   * @param eventType           the type of the event.
+   * @param eventData           the data for the event.
+   * @return                    true if the event was handled, false otherwise.
+   */
+  bool handleEventNanoappToHostTest(uint32_t senderInstanceId,
+                                    uint16_t eventType, const void *eventData);
+
+  /**
+   * Handle a CHRE event for the host -> nanoapp -> host test path.
+   *
+   * @param senderInstanceId    the instand ID that sent the event.
+   * @param eventType           the type of the event.
+   * @param eventData           the data for the event.
+   * @return                    true if the event was handled, false otherwise.
+   */
+  bool handleEventHostToNanoappTest(uint32_t senderInstanceId,
+                                    uint16_t eventType, const void *eventData);
+
+  /** Runs the nanoapp-initiated part of the test. */
+  void runNanoappToHostTest(TestPhase phase);
+
+  /**
+   * Sends the test status to the host.
+   * @param success Whether the test passed.
+   * @param errorMessage The error message if the test failed.
+   */
+  void sendTestStatus(bool success, const char *errorMessage);
+
+  /** Sends a test pass status to the host. */
+  void passTest();
+
+  /** Sends a test fail status to the host. */
+  void failTest(const char *errorMessage);
+
+  /** pw_rpc service used to process the RPCs. */
+  EndpointEchoTestService mEndpointEchoTestService;
+
+  /** RPC server. */
+  chre::RpcServer mServer;
+
+  /** The open session for the echo service. */
+  chre::Optional<chreMsgSessionInfo> mOpenSession;
+
+  /** The timer handle for the test. */
+  uint32_t mTimerHandle = CHRE_TIMER_INVALID;
+
+  /** The writer to use to send the test status. */
+  chre::Optional<EndpointEchoTestService::ServerWriter<chre_rpc_ReturnStatus>>
+      mWriter;
+
+  /** Whether the nanoapp-initiated part of the test is in progress. */
+  bool mNanoappToHostTestInProgress = false;
+
+  /** The session ID for the echo service. */
+  uint16_t mSessionId = CHRE_MSG_SESSION_ID_INVALID;
+
+  /** The message to send for the test. */
+  uint8_t mMessageBuffer[10];
+};
+
+typedef chre::Singleton<EndpointEchoTestManager>
+    EndpointEchoTestManagerSingleton;
+
+#endif  // ENDPOINT_ECHO_TEST_MANAGER_H_
diff --git a/apps/test/common/endpoint_echo_test/rpc/endpoint_echo_test.proto b/apps/test/common/endpoint_echo_test/rpc/endpoint_echo_test.proto
new file mode 100644
index 00000000..7bae87af
--- /dev/null
+++ b/apps/test/common/endpoint_echo_test/rpc/endpoint_echo_test.proto
@@ -0,0 +1,25 @@
+syntax = "proto3";
+
+package chre.rpc;
+
+import "google/protobuf/empty.proto";
+
+option java_package = "dev.chre.rpc.proto";
+
+// RPC for the endpoint echo test
+service EndpointEchoTestService {
+  // Run the nanoapp-to-host test
+  rpc RunNanoappToHostTest(google.protobuf.Empty)
+      returns (stream ReturnStatus) {}
+}
+
+// Received in response to IsTestSupported
+message Status {
+  bool status = 1;
+}
+
+// Received in response to a test pass or fail
+message ReturnStatus {
+  bool status = 1;
+  string error_message = 2;
+}
diff --git a/apps/test/common/endpoint_echo_test/src/endpoint_echo_test.cc b/apps/test/common/endpoint_echo_test/src/endpoint_echo_test.cc
new file mode 100644
index 00000000..fab8fed8
--- /dev/null
+++ b/apps/test/common/endpoint_echo_test/src/endpoint_echo_test.cc
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include <cinttypes>
+
+#include "chre_api/chre.h"
+#include "endpoint_echo_test_manager.h"
+
+namespace chre {
+
+extern "C" void nanoappHandleEvent(uint32_t senderInstanceId,
+                                   uint16_t eventType, const void *eventData) {
+  EndpointEchoTestManagerSingleton::get()->handleEvent(senderInstanceId,
+                                                       eventType, eventData);
+}
+
+extern "C" bool nanoappStart(void) {
+  EndpointEchoTestManagerSingleton::init();
+  return EndpointEchoTestManagerSingleton::get()->start();
+}
+
+extern "C" void nanoappEnd(void) {
+  EndpointEchoTestManagerSingleton::get()->end();
+  EndpointEchoTestManagerSingleton::deinit();
+}
+
+}  // namespace chre
diff --git a/apps/test/common/endpoint_echo_test/src/endpoint_echo_test_manager.cc b/apps/test/common/endpoint_echo_test/src/endpoint_echo_test_manager.cc
new file mode 100644
index 00000000..25a7280a
--- /dev/null
+++ b/apps/test/common/endpoint_echo_test/src/endpoint_echo_test_manager.cc
@@ -0,0 +1,311 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "endpoint_echo_test_manager.h"
+
+#include "chre/util/nanoapp/log.h"
+#include "chre_api/chre.h"
+
+#include "pb.h"
+#include "pb_encode.h"
+
+#include <cstring>
+
+void EndpointEchoTestService::RunNanoappToHostTest(
+    const google_protobuf_Empty & /* request */,
+    EndpointEchoTestService::ServerWriter<chre_rpc_ReturnStatus> &writer) {
+  EndpointEchoTestManagerSingleton::get()->startTest(std::move(writer));
+}
+
+bool EndpointEchoTestManager::start() {
+  bool endpointSupported = (chreGetCapabilities() &
+                            CHRE_CAPABILITIES_GENERIC_ENDPOINT_MESSAGES) != 0;
+  if (endpointSupported) {
+    chre::RpcServer::Service service = {.service = mEndpointEchoTestService,
+                                        .id = 0xb157d6b46418c40b,
+                                        .version = 0x01000000};
+    if (!mServer.registerServices(1, &service)) {
+      LOGE("Error while registering the service");
+      return false;
+    }
+
+    if (!chreMsgPublishServices(&kTestEchoService, /* numServices= */ 1)) {
+      LOGE("Failed to publish test echo service");
+      return false;
+    }
+  }
+  return true;
+}
+
+void EndpointEchoTestManager::end() {
+  mServer.close();
+}
+
+void EndpointEchoTestManager::handleEvent(uint32_t senderInstanceId,
+                                          uint16_t eventType,
+                                          const void *eventData) {
+  if (!mServer.handleEvent(senderInstanceId, eventType, eventData)) {
+    LOGE("An RPC error occurred");
+  }
+
+  // Handle the nanoapp-initiated part of the test first. This is done before
+  // the host-initiated part of the test as during the host-initiated part of
+  // the test, the nanoapp acts as a simple echo service with no control
+  // information.
+  if (handleEventNanoappToHostTest(senderInstanceId, eventType, eventData)) {
+    return;
+  }
+
+  if (handleEventHostToNanoappTest(senderInstanceId, eventType, eventData)) {
+    return;
+  }
+
+  LOGE("Unexpected event type %" PRIu16, eventType);
+}
+
+void EndpointEchoTestManager::setPermissionForNextMessage(uint32_t permission) {
+  mServer.setPermissionForNextMessage(permission);
+}
+
+void EndpointEchoTestManager::startTest(
+    EndpointEchoTestService::ServerWriter<chre_rpc_ReturnStatus> &&writer) {
+  LOGD("Started nanoapp-initiated message test");
+
+  mNanoappToHostTestInProgress = true;
+  mWriter = std::move(writer);
+  mTimerHandle =
+      chreTimerSet(kTestTimeout.toRawNanoseconds(), /* cookie= */ nullptr,
+                   /* oneShot= */ true);
+  if (mTimerHandle == CHRE_TIMER_INVALID) {
+    failTest("Failed to set test timeout timer");
+    return;
+  }
+
+  runNanoappToHostTest(TestPhase::kOpenSession);
+}
+
+bool EndpointEchoTestManager::handleEventNanoappToHostTest(
+    uint32_t /* senderInstanceId */, uint16_t eventType,
+    const void *eventData) {
+  if (!mNanoappToHostTestInProgress) {
+    // Only handle these events if we are in the nanoapp-initiated part of the
+    // test. Otherwise, we should allow the other handlers a chance to handle
+    // the event.
+    return false;
+  }
+
+  switch (eventType) {
+    case CHRE_EVENT_MSG_SESSION_OPENED: {
+      auto *info = static_cast<const chreMsgSessionInfo *>(eventData);
+      if (info->hubId != CHRE_MSG_HUB_ID_ANDROID ||
+          std::strcmp(info->serviceDescriptor, kTestEchoServiceDescriptor) !=
+              0) {
+        failTest("Received session opened event for invalid session");
+      } else {
+        mSessionId = info->sessionId;
+        if (mSessionId == CHRE_MSG_SESSION_ID_INVALID) {
+          failTest(
+              "Received a corrupted session opened event with an invalid "
+              "session ID");
+        } else {
+          runNanoappToHostTest(TestPhase::kSendMessage);
+        }
+      }
+      return true;
+    }
+    case CHRE_EVENT_MSG_SESSION_CLOSED: {
+      if (mSessionId == CHRE_MSG_SESSION_ID_INVALID) {
+        failTest("Session open rejected by the host");
+      } else {
+        auto *info = static_cast<const chreMsgSessionInfo *>(eventData);
+        if (info->sessionId != mSessionId) {
+          failTest("Received session closed event for invalid session");
+        } else {
+          mSessionId = CHRE_MSG_SESSION_ID_INVALID;
+          passTest();
+        }
+      }
+      return true;
+    }
+    case CHRE_EVENT_MSG_FROM_ENDPOINT: {
+      auto *msg =
+          static_cast<const chreMsgMessageFromEndpointData *>(eventData);
+      if (msg->sessionId != mSessionId) {
+        failTest("Received message from invalid session ID");
+        return true;
+      }
+      if (msg->messageSize != sizeof(mMessageBuffer)) {
+        failTest("Received message with invalid size");
+        return true;
+      }
+
+      auto *message = static_cast<const uint8_t *>(msg->message);
+      for (uint8_t i = 0; i < sizeof(mMessageBuffer); ++i) {
+        if (message[i] != mMessageBuffer[i]) {
+          failTest("Received message with invalid payload");
+          return true;
+        }
+      }
+
+      runNanoappToHostTest(TestPhase::kCloseSession);
+      return true;
+    }
+    case CHRE_EVENT_TIMER: {
+      if (mTimerHandle == CHRE_TIMER_INVALID) {
+        LOGE("Received timer event when no timer is set");
+      } else {
+        mTimerHandle = CHRE_TIMER_INVALID;
+        failTest("Test timed out");
+      }
+      return true;
+    }
+  }
+  return false;
+}
+
+bool EndpointEchoTestManager::handleEventHostToNanoappTest(
+    uint32_t /* senderInstanceId */, uint16_t eventType,
+    const void *eventData) {
+  switch (eventType) {
+    case CHRE_EVENT_MSG_FROM_ENDPOINT: {
+      auto *msg =
+          static_cast<const chreMsgMessageFromEndpointData *>(eventData);
+      if (!mOpenSession.has_value()) {
+        LOGE("Received message when no session opened");
+      } else if (mOpenSession->sessionId != msg->sessionId) {
+        LOGE("Message from invalid session ID: expected %" PRIu16
+             " received %" PRIu16,
+             mOpenSession->sessionId, msg->sessionId);
+      } else {
+        uint8_t *messageBuffer =
+            static_cast<uint8_t *>(chreHeapAlloc(msg->messageSize));
+        if (msg->messageSize != 0 && messageBuffer == nullptr) {
+          LOGE("Failed to allocate memory for message buffer");
+        } else {
+          std::memcpy(static_cast<void *>(messageBuffer),
+                      const_cast<void *>(msg->message), msg->messageSize);
+          bool success = chreMsgSend(
+              messageBuffer, msg->messageSize, msg->messageType, msg->sessionId,
+              msg->messagePermissions,
+              [](void *message, size_t /* size */) { chreHeapFree(message); });
+          if (!success) {
+            LOGE("Echo service failed to echo message");
+          }
+        }
+      }
+      return true;
+    }
+    case CHRE_EVENT_MSG_SESSION_OPENED: {
+      [[fallthrough]];
+    }
+    case CHRE_EVENT_MSG_SESSION_CLOSED: {
+      bool open = (eventType == CHRE_EVENT_MSG_SESSION_OPENED);
+      auto *info = static_cast<const chreMsgSessionInfo *>(eventData);
+      LOGD("Session %s (id=%" PRIu16 "): hub ID 0x%" PRIx64
+           ", endpoint ID 0x%" PRIx64,
+           open ? "opened" : "closed", info->sessionId, info->hubId,
+           info->endpointId);
+      if (open) {
+        mOpenSession = *info;
+      } else {
+        mOpenSession.reset();
+      }
+      return true;
+    }
+  }
+  return false;
+}
+
+void EndpointEchoTestManager::runNanoappToHostTest(TestPhase phase) {
+  switch (phase) {
+    case TestPhase::kOpenSession: {
+      bool success = chreMsgSessionOpenAsync(CHRE_MSG_HUB_ID_ANDROID,
+                                             CHRE_MSG_ENDPOINT_ID_ANY,
+                                             kTestEchoServiceDescriptor);
+      if (!success) {
+        failTest("Failed to open session");
+      }
+      break;
+    }
+    case TestPhase::kSendMessage: {
+      for (uint8_t i = 0; i < sizeof(mMessageBuffer); ++i) {
+        mMessageBuffer[i] = i;
+      }
+
+      bool success = chreMsgSend(
+          static_cast<void *>(mMessageBuffer), sizeof(mMessageBuffer),
+          /* messageType= */ 0, mSessionId, CHRE_MESSAGE_PERMISSION_NONE,
+          [](void *, size_t) {});
+      if (!success) {
+        failTest("Failed to send message");
+      }
+      break;
+    }
+    case TestPhase::kCloseSession: {
+      bool success = chreMsgSessionCloseAsync(mSessionId);
+      if (!success) {
+        failTest("Failed to close session");
+      }
+      break;
+    }
+    default:
+      failTest("Invalid test part");
+  }
+}
+
+void EndpointEchoTestManager::sendTestStatus(bool success,
+                                             const char *errorMessage) {
+  if (!mWriter.has_value()) {
+    LOGE("No writer available to send test status");
+    return;
+  }
+
+  if (mTimerHandle != CHRE_TIMER_INVALID) {
+    chreTimerCancel(mTimerHandle);
+    mTimerHandle = CHRE_TIMER_INVALID;
+  }
+
+  chre_rpc_ReturnStatus status = chre_rpc_ReturnStatus_init_default;
+  status.status = success;
+
+  status.error_message.funcs.encode =
+      [](pb_ostream_t *stream, const pb_field_t *field, void *const *arg) {
+        const char *errorMessage = static_cast<const char *>(*arg);
+        return pb_encode_tag_for_field(stream, field) &&
+               pb_encode_string(stream,
+                                reinterpret_cast<const uint8_t *>(errorMessage),
+                                strlen(errorMessage));
+      };
+  status.error_message.arg = const_cast<char *>(errorMessage);
+
+  setPermissionForNextMessage(CHRE_MESSAGE_PERMISSION_NONE);
+  CHRE_ASSERT(mWriter->Write(status).ok());
+  setPermissionForNextMessage(CHRE_MESSAGE_PERMISSION_NONE);
+  mWriter->Finish();
+  mWriter.reset();
+
+  mNanoappToHostTestInProgress = false;
+
+  LOGD("Finished nanoapp-initiated message test");
+}
+
+void EndpointEchoTestManager::passTest() {
+  sendTestStatus(/* success= */ true, /* errorMessage= */ "");
+}
+
+void EndpointEchoTestManager::failTest(const char *errorMessage) {
+  sendTestStatus(/* success= */ false, errorMessage);
+}
\ No newline at end of file
diff --git a/apps/test/common/shared/inc/send_message.h b/apps/test/common/shared/inc/send_message.h
index 49c84ad5..dd40d678 100644
--- a/apps/test/common/shared/inc/send_message.h
+++ b/apps/test/common/shared/inc/send_message.h
@@ -35,7 +35,7 @@ chre_test_common_TestResult makeTestResultProtoMessage(
  * uses the free callback specified in chre/util/nanoapp/callbacks.h
  */
 void sendTestResultToHost(uint16_t hostEndpointId, uint32_t messageType,
-                          bool success, bool abortOnFailure = true);
+                          bool success, bool abortOnFailure = false);
 
 /**
  * Sends a test result to the host using the chre_test_common.TestResult
@@ -52,7 +52,7 @@ void sendTestResultToHost(uint16_t hostEndpointId, uint32_t messageType,
  */
 void sendTestResultWithMsgToHost(uint16_t hostEndpointId, uint32_t messageType,
                                  bool success, const char *errMessage,
-                                 bool abortOnFailure = true);
+                                 bool abortOnFailure = false);
 
 /**
  * Sends a message to the host with an empty payload.
diff --git a/build/aidl.mk b/build/aidl.mk
new file mode 100644
index 00000000..bf5b10b2
--- /dev/null
+++ b/build/aidl.mk
@@ -0,0 +1,49 @@
+#
+# Nanoapp/CHRE AIDL Makefile
+#
+# Include this file to generate source files for .aidl interfaces. The following
+# variables must be defined:
+# - AIDL_GEN_SRCS:  The list of .aidl interface files
+# - AIDL_ROOT:      The root directory of the interface
+#
+# Note that the .aidl interface must be defined in $AIDL_ROOT/<package>/<source>.aidl.
+# For example, if an IHello interface is defined under the package hello.world, then
+# the file must exist in $AIDL_ROOT/hello/world/IHello.aidl.
+#
+# The generated source files and includes are automatically added to COMMON_SRCS and
+# COMMON_CFLAGS, respectively.
+
+# Environment Checks ###############################################################
+
+ifeq ($(ANDROID_BUILD_TOP),)
+$(error "You must run lunch, or specify an explicit ANDROID_BUILD_TOP environment \
+         variable")
+endif
+
+# Setup ############################################################################
+
+# Currently supports the cpp language. Other languages may be added as needed.
+AIDL_LANGUAGE := cpp
+
+AIDL_GEN_PATH := $(OUT)/aidl_gen
+
+AIDL_GEN_SRCS += $(patsubst %.aidl, \
+                     $(AIDL_GEN_PATH)/%.cpp, \
+                     $(AIDL_SRCS))
+
+ifneq ($(AIDL_GEN_SRCS),)
+COMMON_CFLAGS += -I$(AIDL_GEN_PATH)/$(AIDL_ROOT)
+COMMON_SRCS += $(AIDL_GEN_SRCS)
+endif
+
+ifeq ($(AIDL_TOOL),)
+AIDL_TOOL := $(ANDROID_BUILD_TOP)/prebuilts/build-tools/linux-x86/bin/aidl
+endif
+
+# Build ############################################################################
+
+$(AIDL_GEN_PATH)/%.cpp: %.aidl $(AIDL_TOOL)
+	@echo "[AIDL] $<"
+	$(V)mkdir -p $(AIDL_GEN_PATH)/$(AIDL_ROOT)
+	$(AIDL_TOOL) --lang=$(AIDL_LANGUAGE) --structured $(abspath $<) \
+		-I $(AIDL_ROOT) -h $(AIDL_GEN_PATH)/$(AIDL_ROOT) -o $(AIDL_GEN_PATH)/$(AIDL_ROOT)
\ No newline at end of file
diff --git a/build/build_template.mk b/build/build_template.mk
index 441e6896..c002bfd4 100644
--- a/build/build_template.mk
+++ b/build/build_template.mk
@@ -23,29 +23,40 @@
 # (for instance, it can be used to override common flags in COMMON_CFLAGS).
 #
 # Argument List:
-#     $1  - TARGET_NAME          - The name of the target being built.
-#     $2  - TARGET_CFLAGS        - The compiler flags to use for this target.
-#     $3  - TARGET_CC            - The C/C++ compiler for the target variant.
-#     $4  - TARGET_SO_LDFLAGS    - The linker flags to use for this target.
-#     $5  - TARGET_LD            - The linker for the target variant.
-#     $6  - TARGET_ARFLAGS       - The archival flags to use for this target.
-#     $7  - TARGET_AR            - The archival tool for the targer variant.
-#     $8  - TARGET_VARIANT_SRCS  - Source files specific to this variant.
-#     $9  - TARGET_BUILD_BIN     - Build a binary. Typically this means that the
-#                                  source files provided include an entry point.
-#     $10 - TARGET_BIN_LDFLAGS   - Linker flags that are passed to the linker
-#                                  when building an executable binary.
-#     $11 - TARGET_SO_EARLY_LIBS - Link against a set of libraries when building
-#                                  a shared object or binary. These are placed
-#                                  before the objects produced by this build.
-#     $12 - TARGET_SO_LATE_LIBS  - Link against a set of libraries when building
-#                                  a shared object or binary. These are placed
-#                                  after the objects produced by this build.
-#     $13 - TARGET_PLATFORM_ID   - The ID of the platform that this nanoapp
-#                                  build targets.
-#     $14 - TARGET_ACONFIGFLAGS  - The list of aconfig flag value files specific
-#                                  to this build target
-#     $15 - TARGET_ADDITIONAL_LD - Additional linker for this target variant.
+#     $1  - TARGET_NAME            - The name of the target being built.
+#     $2  - TARGET_CFLAGS          - The compiler flags to use for this target.
+#     $3  - TARGET_CC              - The C/C++ compiler for the target variant.
+#     $4  - TARGET_SO_LDFLAGS      - The linker flags to use for this target.
+#     $5  - TARGET_LD              - The linker for the target variant.
+#     $6  - TARGET_ARFLAGS         - The archival flags to use for this target.
+#     $7  - TARGET_AR              - The archival tool for the targer variant.
+#     $8  - TARGET_VARIANT_SRCS    - Source files specific to this variant.
+#     $9  - TARGET_BUILD_BIN       - Build a binary. Typically this means that
+#                                    the source files provided include an entry
+#                                    point.
+#     $10 - TARGET_BIN_LDFLAGS     - Linker flags that are passed to the linker
+#                                    when building an executable binary.
+#     $11 - TARGET_SO_EARLY_LIBS   - Link against a set of libraries when
+#                                    building a shared object or binary. These
+#                                    are placed before the objects produced by
+#                                    this build.
+#     $12 - TARGET_SO_LATE_LIBS    - Link against a set of libraries when
+#                                    building a shared object or binary. These
+#                                    are placed after the objects produced by
+#                                    this build.
+#     $13 - TARGET_PLATFORM_ID     - The ID of the platform that this nanoapp
+#                                    build targets.
+#     $14 - TARGET_ACONFIGFLAGS    - The list of aconfig flag value files
+#                                    specific to this build target
+#     $15 - TARGET_ADDITIONAL_LD   - Additional linker for this target variant.
+#     $16 - TARGET_VARIANT_HP_SRCS - High power source files specific to this
+#                                    variant. The sections of the .o files
+#                                    generated from these sources are all
+#                                    prepended with the .high_power prefix so
+#                                    they can be put into a different memory
+#                                    region based on target-specific linker
+#                                    script. As of now, only cc source files
+#                                    are supported.
 #
 ################################################################################
 
@@ -63,6 +74,14 @@ $(1)_CPP_SRCS = $$(filter %.cpp, $(COMMON_SRCS) $(8))
 $(1)_C_SRCS = $$(filter %.c, $(COMMON_SRCS) $(8))
 $(1)_S_SRCS = $$(filter %.S, $(COMMON_SRCS) $(8))
 
+$(1)_HP_CC_SRCS = $$(filter %.cc, $(16))
+
+# If there are duplicate files in TARGET_VARIANT_HP_SRCS and COMMON_SRCS,
+# remove the duplicates from COMMON_SRCS and only include them as part of the
+# TARGET_VARIANT_HP_SRCS. This enables platforms to move common sources to high
+# power regions of memory.
+$(1)_CC_SRCS := $$(filter-out $$($(1)_HP_CC_SRCS), $$($(1)_CC_SRCS))
+
 # Object files.
 $(1)_OBJS_DIR = $(1)_objs
 $(1)_CC_OBJS = $$(patsubst %.cc, $(OUT)/$$($(1)_OBJS_DIR)/%.o, \
@@ -73,6 +92,8 @@ $(1)_C_OBJS = $$(patsubst %.c, $(OUT)/$$($(1)_OBJS_DIR)/%.o, \
                           $$($(1)_C_SRCS))
 $(1)_S_OBJS = $$(patsubst %.S, $(OUT)/$$($(1)_OBJS_DIR)/%.o, \
                           $$($(1)_S_SRCS))
+$(1)_HP_CC_OBJS = $$(patsubst %.cc, $(OUT)/$$($(1)_OBJS_DIR)/%.o, \
+                           $$($(1)_HP_CC_SRCS))
 
 # Automatic dependency resolution Makefiles.
 $(1)_CC_DEPS = $$(patsubst %.cc, $(OUT)/$$($(1)_OBJS_DIR)/%.d, \
@@ -83,12 +104,15 @@ $(1)_C_DEPS = $$(patsubst %.c, $(OUT)/$$($(1)_OBJS_DIR)/%.d, \
                           $$($(1)_C_SRCS))
 $(1)_S_DEPS = $$(patsubst %.S, $(OUT)/$$($(1)_OBJS_DIR)/%.d, \
                           $$($(1)_S_SRCS))
+$(1)_HP_CC_DEPS = $$(patsubst %.cc, $(OUT)/$$($(1)_OBJS_DIR)/%.d, \
+                           $$($(1)_HP_CC_SRCS))
 
 # Add object file directories.
 $(1)_DIRS = $$(sort $$(dir $$($(1)_CC_OBJS) \
                            $$($(1)_CPP_OBJS) \
                            $$($(1)_C_OBJS) \
-                           $$($(1)_S_OBJS)))
+                           $$($(1)_S_OBJS) \
+                           $$($(1)_HP_CC_OBJS)))
 
 # Outputs ######################################################################
 
@@ -214,6 +238,12 @@ $$($(1)_CC_OBJS): $(OUT)/$$($(1)_OBJS_DIR)/%.o: %.cc $(MAKEFILE_LIST)
 	$(V)$(3) $(COMMON_CXX_CFLAGS) -DCHRE_FILENAME=\"$$(notdir $$<)\" $(2) -c \
 		$$< -o $$@
 
+$$($(1)_HP_CC_OBJS): $(OUT)/$$($(1)_OBJS_DIR)/%.o: %.cc $(MAKEFILE_LIST)
+	@echo " [CC] $$<"
+	$(V)$(3) $(COMMON_CXX_CFLAGS) -DCHRE_FILENAME=\"$$(notdir $$<)\" $(2) -c \
+		$$< -o $$@
+	$(V)$(OBJCOPY) $$@ --prefix-alloc-sections .high_power
+
 $$($(1)_C_OBJS): $(OUT)/$$($(1)_OBJS_DIR)/%.o: %.c $(MAKEFILE_LIST)
 	@echo " [C] $$<"
 	$(V)$(3) $(COMMON_C_CFLAGS) -DCHRE_FILENAME=\"$$(notdir $$<)\" $(2) -c $$< \
@@ -231,7 +261,7 @@ $(1)_ARFLAGS = $(COMMON_ARFLAGS) \
     $(6)
 
 $$($(1)_AR): $$($(1)_CC_OBJS) $$($(1)_CPP_OBJS) $$($(1)_C_OBJS) \
-              $$($(1)_S_OBJS) | $$(OUT)/$(1) $$($(1)_DIRS)
+              $$($(1)_S_OBJS) $$($(1)_HP_CC_OBJS) | $$(OUT)/$(1) $$($(1)_DIRS)
 	@echo " [AR] $$@"
 	$(V)$(7) $$($(1)_ARFLAGS) $$@ $$(filter %.o, $$^)
 
@@ -279,16 +309,17 @@ flagging_library_$(1):
 
 # Link #########################################################################
 
-$$($(1)_SO): $$($(1)_CC_DEPS) \
-              $$($(1)_CPP_DEPS) $$($(1)_C_DEPS) $$($(1)_S_DEPS) \
+$$($(1)_SO): $$($(1)_CC_DEPS) $$($(1)_CPP_DEPS) \
+              $$($(1)_C_DEPS) $$($(1)_S_DEPS) $$($(1)_HP_CC_DEPS) \
               $$($(1)_CC_OBJS) $$($(1)_CPP_OBJS) $$($(1)_C_OBJS) \
-              $$($(1)_S_OBJS) $(RUST_DEPENDENCIES) | $$(OUT)/$(1) $$($(1)_DIRS)
+              $$($(1)_S_OBJS) $$($(1)_HP_CC_OBJS) $(RUST_DEPENDENCIES) \
+              | $$(OUT)/$(1) $$($(1)_DIRS)
 	$(5) $(4) -o $$@ $(11) $$(filter %.o, $$^) $(12) $(15)
 
-$$($(1)_BIN): $$($(1)_CC_DEPS) \
-               $$($(1)_CPP_DEPS) $$($(1)_C_DEPS) $$($(1)_S_DEPS) \
+$$($(1)_BIN): $$($(1)_CC_DEPS) $$($(1)_CPP_DEPS) \
+               $$($(1)_C_DEPS) $$($(1)_S_DEPS) $$($(1)_HP_CC_DEPS) \
                $$($(1)_CC_OBJS) $$($(1)_CPP_OBJS) $$($(1)_C_OBJS) \
-               $$($(1)_S_OBJS) | $$(OUT)/$(1) $$($(1)_DIRS)
+               $$($(1)_S_OBJS) $$($(1)_HP_CC_OBJS) | $$(OUT)/$(1) $$($(1)_DIRS)
 	$(V)$(3) -o $$@ $(11) $$(filter %.o, $$^) $(12) $(10)
 
 # Output Directories ###########################################################
@@ -321,6 +352,11 @@ $$($(1)_S_DEPS): $(OUT)/$$($(1)_OBJS_DIR)/%.d: %.S
 	$(V)$(3) $(DEP_CFLAGS) \
 		-DCHRE_FILENAME=\"$$(notdir $$<)\" $(2) $$< -o $$@
 
+$$($(1)_HP_CC_DEPS): $(OUT)/$$($(1)_OBJS_DIR)/%.d: %.cc
+	$(V)mkdir -p $$(dir $$@)
+	$(V)$(3) $(DEP_CFLAGS) $(COMMON_CXX_CFLAGS) \
+		-DCHRE_FILENAME=\"$$(notdir $$<)\" $(2) $$< -o $$@
+
 # Include generated dependency files if they are in the requested build target.
 # This avoids dependency generation from occuring for a debug target when a
 # non-debug target is requested.
@@ -329,6 +365,7 @@ ifneq ($(filter $(1) all, $(MAKECMDGOALS)),)
 -include $$(patsubst %.o, %.d, $$($(1)_CPP_DEPS))
 -include $$(patsubst %.o, %.d, $$($(1)_C_DEPS))
 -include $$(patsubst %.o, %.d, $$($(1)_S_DEPS))
+-include $$(patsubst %.o, %.d, $$($(1)_HP_CC_DEPS))
 endif
 
 endef
@@ -356,7 +393,8 @@ $(eval $(call BUILD_TEMPLATE,$(TARGET_NAME), \
                              $(TARGET_SO_LATE_LIBS), \
                              $(TARGET_PLATFORM_ID), \
                              $(TARGET_ACONFIGFLAGS), \
-                             $(TARGET_ADDITIONAL_LD)))
+                             $(TARGET_ADDITIONAL_LD), \
+                             $(TARGET_VARIANT_HP_SRCS)))
 
 # Debug Template Invocation ####################################################
 
@@ -376,4 +414,5 @@ $(eval $(call BUILD_TEMPLATE,$(TARGET_NAME)_debug, \
                              $(TARGET_SO_LATE_LIBS), \
                              $(TARGET_PLATFORM_ID), \
                              $(TARGET_ACONFIGFLAGS), \
-                             $(TARGET_ADDITIONAL_LD)))
+                             $(TARGET_ADDITIONAL_LD), \
+                             $(TARGET_VARIANT_HP_SRCS)))
diff --git a/build/variant/aosp_riscv_tinysys_common.mk b/build/variant/aosp_riscv_tinysys_common.mk
index 136f2a48..1950a1d4 100644
--- a/build/variant/aosp_riscv_tinysys_common.mk
+++ b/build/variant/aosp_riscv_tinysys_common.mk
@@ -65,6 +65,11 @@ ifneq ($(filter $(TARGET_NAME)% all, $(MAKECMDGOALS)),)
   TINYSYS_CFLAGS += -DCFG_STATIC_ALLOCATE
   TINYSYS_CFLAGS += -DconfigSUPPORT_STATIC_ALLOCATION=1
 
+  # Disable atomic operations in Pigweed as they are not supported on this platform.
+  # This will eventually be deprecated by the Pigweed team when they move to
+  # portable atomics with pw_atomic.
+  TINYSYS_CFLAGS += -DPW_ALLOCATOR_HAS_ATOMICS=0
+
   # Compiling flags ##############################################################
 
   TINYSYS_CFLAGS += $(FLATBUFFERS_CFLAGS)
diff --git a/chpp/clients/gnss.c b/chpp/clients/gnss.c
index 6f02dc05..e6a4d99d 100644
--- a/chpp/clients/gnss.c
+++ b/chpp/clients/gnss.c
@@ -120,6 +120,11 @@ static const struct ChppClient kGnssClientConfig = {
     .minLength = sizeof(struct ChppAppHeader),
 };
 
+static const struct chrePalGnssCallbacks *getPalCallbacks(void) {
+  gSystemApi->forceDramAccess();
+  return gCallbacks;
+}
+
 /************************************************
  *  Prototypes
  ***********************************************/
@@ -197,7 +202,7 @@ static enum ChppAppErrorCode chppDispatchGnssResponse(void *clientContext,
         chppClientProcessOpenResponse(&gnssClientContext->client, buf, len);
         if (rxHeader->error == CHPP_APP_ERROR_NONE &&
             gnssClientContext->requestStateResyncPending) {
-          gCallbacks->requestStateResync();
+          getPalCallbacks()->requestStateResync();
           gnssClientContext->requestStateResyncPending = false;
         }
         break;
@@ -422,7 +427,7 @@ static void chppGnssControlLocationSessionResult(
 
   if (len < sizeof(struct ChppGnssControlLocationSessionResponse)) {
     // Short response length indicates an error
-    gCallbacks->locationStatusChangeCallback(
+    getPalCallbacks()->locationStatusChangeCallback(
         false, chppAppShortResponseErrorHandler(buf, len, "ControlLocation"));
 
   } else {
@@ -434,8 +439,8 @@ static void chppGnssControlLocationSessionResult(
         "errorCode=%" PRIu8,
         result->enabled, result->errorCode);
 
-    gCallbacks->locationStatusChangeCallback(result->enabled,
-                                             result->errorCode);
+    getPalCallbacks()->locationStatusChangeCallback(result->enabled,
+                                                    result->errorCode);
   }
 }
 
@@ -455,7 +460,7 @@ static void chppGnssControlMeasurementSessionResult(
 
   if (len < sizeof(struct ChppGnssControlMeasurementSessionResponse)) {
     // Short response length indicates an error
-    gCallbacks->measurementStatusChangeCallback(
+    getPalCallbacks()->measurementStatusChangeCallback(
         false, chppAppShortResponseErrorHandler(buf, len, "Measurement"));
 
   } else {
@@ -467,8 +472,8 @@ static void chppGnssControlMeasurementSessionResult(
         "errorCode=%" PRIu8,
         result->enabled, result->errorCode);
 
-    gCallbacks->measurementStatusChangeCallback(result->enabled,
-                                                result->errorCode);
+    getPalCallbacks()->measurementStatusChangeCallback(result->enabled,
+                                                       result->errorCode);
   }
 }
 
@@ -517,7 +522,7 @@ static void chppGnssStateResyncNotification(
     // when the open has succeeded.
     clientContext->requestStateResyncPending = true;
   } else {
-    gCallbacks->requestStateResync();
+    getPalCallbacks()->requestStateResync();
     clientContext->requestStateResyncPending = false;
   }
 }
@@ -546,7 +551,7 @@ static void chppGnssLocationResultNotification(
   if (chre == NULL) {
     CHPP_LOGE("Location result conversion failed: len=%" PRIuSIZE, len);
   } else {
-    gCallbacks->locationEventCallback(chre);
+    getPalCallbacks()->locationEventCallback(chre);
   }
 }
 
@@ -575,7 +580,7 @@ static void chppGnssMeasurementResultNotification(
   if (chre == NULL) {
     CHPP_LOGE("Measurement result conversion failed len=%" PRIuSIZE, len);
   } else {
-    gCallbacks->measurementEventCallback(chre);
+    getPalCallbacks()->measurementEventCallback(chre);
   }
 }
 
diff --git a/chpp/clients/loopback.c b/chpp/clients/loopback.c
index d8d8b991..c1f78de8 100644
--- a/chpp/clients/loopback.c
+++ b/chpp/clients/loopback.c
@@ -26,6 +26,7 @@
 #include "chpp/clients/discovery.h"
 #include "chpp/log.h"
 #include "chpp/memory.h"
+#include "chpp/time.h"
 #include "chpp/transport.h"
 
 /************************************************
@@ -44,6 +45,7 @@ struct ChppLoopbackClientState {
   struct ChppEndpointState client;                  // CHPP client state
   struct ChppOutgoingRequestState runLoopbackTest;  // Loopback test state
 
+  uint64_t lastLoopbackTestTimeNs;           // Last loopback test time
   struct ChppLoopbackTestResult testResult;  // Last test result
   const uint8_t *loopbackData;               // Pointer to loopback data
 };
@@ -95,9 +97,12 @@ bool chppDispatchLoopbackServiceResponse(struct ChppAppState *appState,
   CHPP_NOT_NULL(state);
   CHPP_NOT_NULL(state->loopbackData);
 
-  CHPP_ASSERT(chppTimestampIncomingResponse(
+  if (!(chppTimestampIncomingResponse(
       state->client.appContext, &state->runLoopbackTest,
-      (const struct ChppAppHeader *)response));
+      (const struct ChppAppHeader *)response))) {
+    CHPP_LOGE("Invalid loopback response - dropping");
+    return false;
+  }
 
   struct ChppLoopbackTestResult *result = &state->testResult;
 
@@ -170,6 +175,7 @@ static bool chppRunLoopbackTestInternal(struct ChppAppState *appState,
                                         const uint8_t *buf, size_t len,
                                         bool sync,
                                         struct ChppLoopbackTestResult *out) {
+  const uint64_t kTimeoutNs = 5 * CHPP_NSEC_PER_SEC;
   CHPP_NOT_NULL(out);
   bool success = false;
   CHPP_LOGD("Loopback client TX len=%" PRIuSIZE,
@@ -187,10 +193,16 @@ static bool chppRunLoopbackTestInternal(struct ChppAppState *appState,
     chppMutexLock(&state->client.syncResponse.mutex);
     struct ChppLoopbackTestResult *result = &state->testResult;
 
-    if (result->error == CHPP_APP_ERROR_BLOCKED) {
+    uint64_t nowNs = chppGetCurrentTimeNs();
+    if (result->error == CHPP_APP_ERROR_BLOCKED &&
+        nowNs < state->lastLoopbackTestTimeNs + kTimeoutNs) {
       CHPP_DEBUG_ASSERT_LOG(false, "Another loopback in progress");
       out->error = CHPP_APP_ERROR_BLOCKED;
     } else {
+      if (result->error == CHPP_APP_ERROR_BLOCKED) {
+        CHPP_LOGW("Previous loopback (%" PRIu64 " ms ago) timed out",
+                  (nowNs - state->lastLoopbackTestTimeNs) / CHPP_NSEC_PER_MSEC);
+      }
       memset(result, 0, sizeof(struct ChppLoopbackTestResult));
       result->error = CHPP_APP_ERROR_BLOCKED;
       result->requestLen = len + CHPP_LOOPBACK_HEADER_LEN;
@@ -204,20 +216,24 @@ static bool chppRunLoopbackTestInternal(struct ChppAppState *appState,
       } else {
         state->loopbackData = buf;
         memcpy(&loopbackRequest[CHPP_LOOPBACK_HEADER_LEN], buf, len);
+        state->lastLoopbackTestTimeNs = nowNs;
 
         chppMutexUnlock(&state->client.syncResponse.mutex);
         if (sync) {
           if (!chppClientSendTimestampedRequestAndWaitTimeout(
                   &state->client, &state->runLoopbackTest, loopbackRequest,
-                  result->requestLen, 5 * CHPP_NSEC_PER_SEC)) {
+                  result->requestLen, kTimeoutNs)) {
             result->error = CHPP_APP_ERROR_UNSPECIFIED;
           } else {
             success = true;
           }
         } else {
+          // We use infinite timeout here since timeouts for predefined clients
+          // are not well-supported by CHPP today. Timeout for this case is
+          // handled opportunistically using lastLoopbackTestTimeNs check above.
           if (!chppClientSendTimestampedRequestOrFail(
                   &state->client, &state->runLoopbackTest, loopbackRequest,
-                  result->requestLen, 5 * CHPP_NSEC_PER_SEC)) {
+                  result->requestLen, CHPP_REQUEST_TIMEOUT_INFINITE)) {
             result->error = CHPP_APP_ERROR_UNSPECIFIED;
           } else {
             success = true;
diff --git a/chpp/clients/timesync.c b/chpp/clients/timesync.c
index 3026f216..9f2588df 100644
--- a/chpp/clients/timesync.c
+++ b/chpp/clients/timesync.c
@@ -23,14 +23,13 @@
 
 #include "chpp/app.h"
 #include "chpp/clients.h"
+#include "chpp/clients/discovery.h"
 #include "chpp/common/timesync.h"
 #include "chpp/log.h"
 #include "chpp/memory.h"
 #include "chpp/time.h"
 #include "chpp/transport.h"
 
-#include "chpp/clients/discovery.h"
-
 /************************************************
  *  Private Definitions
  ***********************************************/
@@ -42,8 +41,9 @@
 struct ChppTimesyncClientState {
   struct ChppEndpointState client;                // CHPP client state
   struct ChppOutgoingRequestState measureOffset;  // Request response state
-
   struct ChppTimesyncResult timesyncResult;  // Result of measureOffset
+  uint64_t lastMeasurementTimeNs;  // The last time a timesync was started
+  bool isOffsetClipping;  // If the offset was clipped on previous check
 };
 
 /************************************************
@@ -77,7 +77,7 @@ void chppTimesyncClientDeinit(struct ChppAppState *appState) {
 }
 
 void chppTimesyncClientReset(struct ChppAppState *appState) {
-  CHPP_LOGD("Timesync client reset");
+  CHPP_LOGI("Timesync client reset");
   CHPP_DEBUG_NOT_NULL(appState);
   struct ChppTimesyncClientState *state = appState->timesyncClientContext;
   CHPP_NOT_NULL(state);
@@ -86,6 +86,7 @@ void chppTimesyncClientReset(struct ChppAppState *appState) {
   state->timesyncResult.offsetNs = 0;
   state->timesyncResult.rttNs = 0;
   state->timesyncResult.measurementTimeNs = 0;
+  state->lastMeasurementTimeNs = 0;
 }
 
 bool chppDispatchTimesyncServiceResponse(struct ChppAppState *appState,
@@ -118,40 +119,68 @@ bool chppDispatchTimesyncServiceResponse(struct ChppAppState *appState,
                                   (int64_t)CHPP_CLIENT_TIMESYNC_MAX_CHANGE_NS);
       clippedOffsetChangeNs = MAX(clippedOffsetChangeNs,
                                   -(int64_t)CHPP_CLIENT_TIMESYNC_MAX_CHANGE_NS);
+    } else {
+      CHPP_LOGI("First timesync offset=%" PRId64 "ms at t=%" PRIu64,
+                offsetNs / (int64_t)CHPP_NSEC_PER_MSEC,
+                state->measureOffset.responseTimeNs / CHPP_NSEC_PER_MSEC);
     }
 
+    bool clippingStatusChanged = false;
     state->timesyncResult.offsetNs += clippedOffsetChangeNs;
 
     if (offsetChangeNs != clippedOffsetChangeNs) {
+      if (!state->isOffsetClipping) {
+        CHPP_LOGI("Timesync offset newly required clipping");
+        state->isOffsetClipping = true;
+        clippingStatusChanged = true;
+      }
       CHPP_LOGW("Drift=%" PRId64 " clipped to %" PRId64 " at t=%" PRIu64,
                 offsetChangeNs / (int64_t)CHPP_NSEC_PER_MSEC,
                 clippedOffsetChangeNs / (int64_t)CHPP_NSEC_PER_MSEC,
                 state->measureOffset.responseTimeNs / CHPP_NSEC_PER_MSEC);
     } else {
+      if (state->isOffsetClipping) {
+        CHPP_LOGI("Timesync offset no longer requires clipping");
+        state->isOffsetClipping = false;
+        clippingStatusChanged = true;
+      }
       state->timesyncResult.measurementTimeNs =
           state->measureOffset.responseTimeNs;
     }
 
     state->timesyncResult.error = CHPP_APP_ERROR_NONE;
 
-    CHPP_LOGD("Timesync RTT=%" PRIu64 " correction=%" PRId64 " offset=%" PRId64
-              " t=%" PRIu64,
-              state->timesyncResult.rttNs / CHPP_NSEC_PER_MSEC,
-              clippedOffsetChangeNs / (int64_t)CHPP_NSEC_PER_MSEC,
-              offsetNs / (int64_t)CHPP_NSEC_PER_MSEC,
-              state->timesyncResult.measurementTimeNs / CHPP_NSEC_PER_MSEC);
+    if (clippingStatusChanged) {
+      CHPP_LOGI("Timesync RTT=%" PRIu64 " correction=%" PRId64
+                " offset=%" PRId64 " t=%" PRIu64,
+                state->timesyncResult.rttNs / CHPP_NSEC_PER_MSEC,
+                clippedOffsetChangeNs / (int64_t)CHPP_NSEC_PER_MSEC,
+                offsetNs / (int64_t)CHPP_NSEC_PER_MSEC,
+                state->timesyncResult.measurementTimeNs / CHPP_NSEC_PER_MSEC);
+    }
   }
 
   return true;
 }
 
 bool chppTimesyncMeasureOffset(struct ChppAppState *appState) {
+  const uint64_t kTimeoutNs = 5 * CHPP_NSEC_PER_SEC;
   bool result = false;
   CHPP_LOGD("Measuring timesync t=%" PRIu64,
             chppGetCurrentTimeNs() / CHPP_NSEC_PER_MSEC);
   CHPP_DEBUG_NOT_NULL(appState);
   struct ChppTimesyncClientState *state = appState->timesyncClientContext;
   CHPP_NOT_NULL(state);
+  uint64_t nowNs = chppGetCurrentTimeNs();
+  if (state->timesyncResult.error == CHPP_APP_ERROR_BUSY) {
+    if (nowNs < state->lastMeasurementTimeNs + kTimeoutNs) {
+      CHPP_LOGE("Rejecting timesync request: in progress");
+      return false;
+    } else {
+      CHPP_LOGW("Last timesync (%" PRIu64 " ms ago) timed out",
+                (nowNs - state->lastMeasurementTimeNs) / CHPP_NSEC_PER_MSEC);
+    }
+  }
 
   state->timesyncResult.error =
       CHPP_APP_ERROR_BUSY;  // A measurement is in progress
@@ -164,12 +193,16 @@ bool chppTimesyncMeasureOffset(struct ChppAppState *appState) {
     state->timesyncResult.error = CHPP_APP_ERROR_OOM;
     CHPP_LOG_OOM();
 
+  // We use an infinite timeout here because timeouts are not well-supported for
+  // predefined clients in CHPP today. An opportunistic timeout will be used
+  // using the lastMeasurementTimeNs check above.
   } else if (!chppClientSendTimestampedRequestOrFail(
                  &state->client, &state->measureOffset, request, requestLen,
                  CHPP_REQUEST_TIMEOUT_INFINITE)) {
     state->timesyncResult.error = CHPP_APP_ERROR_UNSPECIFIED;
 
   } else {
+    state->lastMeasurementTimeNs = nowNs;
     result = true;
   }
 
diff --git a/chpp/clients/wifi.c b/chpp/clients/wifi.c
index e4c78876..b0b87175 100644
--- a/chpp/clients/wifi.c
+++ b/chpp/clients/wifi.c
@@ -140,6 +140,11 @@ static const struct ChppClient kWifiClientConfig = {
     .minLength = sizeof(struct ChppAppHeader),
 };
 
+static const struct chrePalWifiCallbacks *getPalCallbacks(void) {
+  gSystemApi->forceDramAccess();
+  return gCallbacks;
+}
+
 /************************************************
  *  Prototypes
  ***********************************************/
@@ -526,7 +531,7 @@ static void chppWifiConfigureScanMonitorResult(
     // Short response length indicates an error
     uint8_t error = chppAppShortResponseErrorHandler(buf, len, "ScanMonitor");
     if (!gWifiClientContext.scanMonitorSilenceCallback) {
-      gCallbacks->scanMonitorStatusChangeCallback(false, error);
+      getPalCallbacks()->scanMonitorStatusChangeCallback(false, error);
     }
   } else {
     struct ChppWifiConfigureScanMonitorAsyncResponseParameters *result =
@@ -543,8 +548,8 @@ static void chppWifiConfigureScanMonitorResult(
       // calls to scanMonitorStatusChangeCallback must not be made, and it
       // should only be invoked as the direct result of an earlier call to
       // configureScanMonitor.
-      gCallbacks->scanMonitorStatusChangeCallback(result->enabled,
-                                                  result->errorCode);
+      getPalCallbacks()->scanMonitorStatusChangeCallback(result->enabled,
+                                                         result->errorCode);
     }  // Else, the WiFi subsystem has been reset and we are required to
        // silently reenable the scan monitor.
 
@@ -567,13 +572,15 @@ static void chppWifiRequestScanResult(struct ChppWifiClientState *clientContext,
 
   if (len < sizeof(struct ChppWifiRequestScanResponse)) {
     // Short response length indicates an error
-    gCallbacks->scanResponseCallback(
+    getPalCallbacks()->scanResponseCallback(
         false, chppAppShortResponseErrorHandler(buf, len, "ScanRequest"));
 
   } else {
     struct ChppWifiRequestScanResponseParameters *result =
         &((struct ChppWifiRequestScanResponse *)buf)->params;
     CHPP_LOGI("Scan request success=%d at service", result->pending);
+    clientContext->scanTimeoutPending = false;
+    chppAppCancelTimerTimeout(&gWifiClientContext.client);
     if (result->pending) {
       if (!chppAppRequestTimerTimeout(&clientContext->client,
                                       CHRE_NSEC_PER_SEC)) {
@@ -582,7 +589,7 @@ static void chppWifiRequestScanResult(struct ChppWifiClientState *clientContext,
         clientContext->scanTimeoutPending = true;
       }
     }
-    gCallbacks->scanResponseCallback(result->pending, result->errorCode);
+    getPalCallbacks()->scanResponseCallback(result->pending, result->errorCode);
   }
 }
 
@@ -603,8 +610,8 @@ static void chppWifiRequestRangingResult(
   struct ChppAppHeader *rxHeader = (struct ChppAppHeader *)buf;
 
   if (rxHeader->error != CHPP_APP_ERROR_NONE) {
-    gCallbacks->rangingEventCallback(chppAppErrorToChreError(rxHeader->error),
-                                     NULL);
+    getPalCallbacks()->rangingEventCallback(
+        chppAppErrorToChreError(rxHeader->error), NULL);
 
   } else {
     CHPP_LOGD("Ranging request accepted at service");
@@ -625,7 +632,7 @@ static void chppWifiRequestNanSubscribeResult(uint8_t *buf, size_t len) {
   struct ChppAppHeader *rxHeader = (struct ChppAppHeader *)buf;
 
   if (rxHeader->error != CHPP_APP_ERROR_NONE) {
-    gCallbacks->nanServiceIdentifierCallback(
+    getPalCallbacks()->nanServiceIdentifierCallback(
         chppAppErrorToChreError(rxHeader->error), 0 /* subscriptionId */);
 
   } else {
@@ -647,7 +654,7 @@ static void chppWifiNanSubscriptionCanceledResult(uint8_t *buf, size_t len) {
   struct ChppAppHeader *rxHeader = (struct ChppAppHeader *)buf;
 
   if (rxHeader->error != CHPP_APP_ERROR_NONE) {
-    gCallbacks->nanSubscriptionCanceledCallback(
+    getPalCallbacks()->nanSubscriptionCanceledCallback(
         chppAppErrorToChreError(rxHeader->error), 0 /* subscriptionId */);
 
   } else {
@@ -702,7 +709,7 @@ static void chppWifiScanEventNotification(
       clientContext->scanTimeoutPending = false;
     }
 
-    gCallbacks->scanEventCallback(chre);
+    getPalCallbacks()->scanEventCallback(chre);
   }
 }
 
@@ -760,7 +767,7 @@ static void chppWifiRangingEventNotification(
     CHPP_LOGE("Ranging event conversion failed len=%" PRIuSIZE, len);
   }
 
-  gCallbacks->rangingEventCallback(error, chre);
+  getPalCallbacks()->rangingEventCallback(error, chre);
 }
 
 /**
@@ -785,7 +792,7 @@ static void chppWifiDiscoveryEventNotification(uint8_t *buf, size_t len) {
   if (event == NULL) {
     CHPP_LOGE("Discovery event CHPP -> CHRE conversion failed");
   } else {
-    gCallbacks->nanServiceDiscoveryCallback(event);
+    getPalCallbacks()->nanServiceDiscoveryCallback(event);
   }
 }
 
@@ -809,7 +816,7 @@ static void chppWifiNanServiceLostEventNotification(uint8_t *buf, size_t len) {
   if (event == NULL) {
     CHPP_LOGE("Session lost event CHPP -> CHRE conversion failed");
   } else {
-    gCallbacks->nanServiceLostCallback(event->id, event->peerId);
+    getPalCallbacks()->nanServiceLostCallback(event->id, event->peerId);
   }
 }
 
@@ -834,7 +841,7 @@ static void chppWifiNanServiceTerminatedEventNotification(uint8_t *buf,
   if (event == NULL) {
     CHPP_LOGE("Session terminated event CHPP -> CHRE conversion failed");
   } else {
-    gCallbacks->nanServiceTerminatedCallback(event->reason, event->id);
+    getPalCallbacks()->nanServiceTerminatedCallback(event->reason, event->id);
   }
 }
 
@@ -858,7 +865,7 @@ static void chppWifiRequestNanSubscribeNotification(uint8_t *buf, size_t len) {
     errorCode = id->errorCode;
     subscriptionId = id->subscriptionId;
   }
-  gCallbacks->nanServiceIdentifierCallback(errorCode, subscriptionId);
+  getPalCallbacks()->nanServiceIdentifierCallback(errorCode, subscriptionId);
 }
 
 /**
@@ -881,7 +888,7 @@ static void chppWifiNanSubscriptionCanceledNotification(uint8_t *buf,
     errorCode = chppNotif->errorCode;
     subscriptionId = chppNotif->subscriptionId;
   }
-  gCallbacks->nanSubscriptionCanceledCallback(errorCode, subscriptionId);
+  getPalCallbacks()->nanSubscriptionCanceledCallback(errorCode, subscriptionId);
 }
 
 /**
@@ -1042,6 +1049,16 @@ static bool chppWifiClientRequestScan(const struct chreWifiScanParams *params) {
         &gWifiClientContext.client,
         &gWifiClientContext.outReqStates[CHPP_WIFI_REQUEST_SCAN_ASYNC], request,
         requestLen, CHPP_WIFI_SCAN_RESULT_TIMEOUT_NS);
+    gWifiClientContext.scanTimeoutPending = false;
+    chppAppCancelTimerTimeout(&gWifiClientContext.client);
+    if (result) {
+      if (!chppAppRequestTimerTimeout(&gWifiClientContext.client,
+                                      10 * CHRE_NSEC_PER_SEC)) {
+        CHPP_LOGE("Failed to schedule scan timeout");
+      } else {
+        gWifiClientContext.scanTimeoutPending = true;
+      }
+    }
   }
 
   return result;
diff --git a/chpp/clients/wwan.c b/chpp/clients/wwan.c
index 2beffe34..3e64f6c1 100644
--- a/chpp/clients/wwan.c
+++ b/chpp/clients/wwan.c
@@ -120,6 +120,11 @@ static const struct ChppClient kWwanClientConfig = {
     .minLength = sizeof(struct ChppAppHeader),
 };
 
+static const struct chrePalWwanCallbacks *getPalCallbacks(void) {
+  gSystemApi->forceDramAccess();
+  return gCallbacks;
+}
+
 /************************************************
  *  Prototypes
  ***********************************************/
@@ -385,7 +390,7 @@ static void chppWwanGetCellInfoAsyncResult(
   }
 
   if (chre != NULL) {
-    gCallbacks->cellInfoResultCallback(chre);
+    getPalCallbacks()->cellInfoResultCallback(chre);
   }
 }
 
diff --git a/chre_api/include/chre_api/chre/msg.h b/chre_api/include/chre_api/chre/msg.h
index f02fd400..ab58b62f 100644
--- a/chre_api/include/chre_api/chre/msg.h
+++ b/chre_api/include/chre_api/chre/msg.h
@@ -620,7 +620,7 @@ bool chreMsgSessionCloseAsync(uint16_t sessionId);
  * @param messagePermissions Bitmask of permissions that must be held to receive
  *     this message, and will be attributed to the recipient. Primarily relevant
  *     when the destination endpoint is an Android application. Refer to
- *     CHRE_MESSAGE_PERMISSIONS.
+ *     CHRE_MESSAGE_PERMISSION_* values.
  * @param freeCallback Invoked when the system no longer needs the memory
  *     holding the message. Note that this does not necessarily mean that the
  *     message has been delivered. If message is non-NULL, this must be
diff --git a/chre_api/include/chre_api/chre/version.h b/chre_api/include/chre_api/chre/version.h
index 467bb85e..757ba03d 100644
--- a/chre_api/include/chre_api/chre/version.h
+++ b/chre_api/include/chre_api/chre/version.h
@@ -179,6 +179,16 @@ extern "C" {
  */
 #define CHRE_API_VERSION_1_11 UINT32_C(0x010b0000)
 
+/**
+ * Value for version 1.12 of the Context Hub Runtime Environment API interface.
+ *
+ * @note This version of the CHRE API has not been finalized yet, and is
+ * currently considered a preview that is subject to change.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_12 UINT32_C(0x010c0000)
+
 /**
  * Major and Minor Version of this Context Hub Runtime Environment API.
  *
@@ -196,7 +206,7 @@ extern "C" {
  * Note that version numbers can always be numerically compared with
  * expected results, so 1.0.0 < 1.0.4 < 1.1.0 < 2.0.300 < 3.5.0.
  */
-#define CHRE_API_VERSION CHRE_API_VERSION_1_11
+#define CHRE_API_VERSION CHRE_API_VERSION_1_12
 
 /**
  * Utility macro to extract only the API major version of a composite CHRE
diff --git a/chre_api/legacy/v1_11/chre.h b/chre_api/legacy/v1_11/chre.h
new file mode 100644
index 00000000..c67e52ad
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre.h
@@ -0,0 +1,202 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+#ifndef _CHRE_H_
+#define _CHRE_H_
+
+/**
+ * @file
+ * This header file includes all the headers which combine to fully define the
+ * interface for the Context Hub Runtime Environment (CHRE).  This interface is
+ * of interest to both implementers of CHREs and authors of nanoapps.  The API
+ * documentation attempts to address concerns of both.
+ *
+ * See individual header files for API details, and general comments below
+ * for overall platform information.
+ */
+
+#include <chre/audio.h>
+#include <chre/ble.h>
+#include <chre/common.h>
+#include <chre/event.h>
+#include <chre/gnss.h>
+#include <chre/msg.h>
+#include <chre/nanoapp.h>
+#include <chre/re.h>
+#include <chre/sensor.h>
+#include <chre/toolchain.h>
+#include <chre/user_settings.h>
+#include <chre/version.h>
+#include <chre/wifi.h>
+#include <chre/wwan.h>
+
+/**
+ * @mainpage
+ * CHRE is the Context Hub Runtime Environment.  CHRE is used in Android to run
+ * contextual applications, called nanoapps, in a low-power processing domain
+ * other than the applications processor that runs Android itself.  The CHRE
+ * API, documented herein, is the common interface exposed to nanoapps for any
+ * compatible CHRE implementation.  The CHRE API provides the ability for
+ * creating nanoapps that are code-compatible across different CHRE
+ * implementations and underlying platforms. Refer to the following sections for
+ * a discussion on some important details of CHRE that aren't explicitly exposed
+ * in the API itself.
+ *
+ * @section entry_points Entry points
+ *
+ * The following entry points are used to bind a nanoapp to the CHRE system, and
+ * all three must be implemented by any nanoapp (see chre/nanoapp.h):
+ * - nanoappStart: initialization
+ * - nanoappHandleEvent: hook for event-driven processing
+ * - nanoappEnd: graceful teardown
+ *
+ * The CHRE implementation must also ensure that it performs these functions
+ * prior to invoking nanoappStart, or after nanoappEnd returns:
+ * - bss section zeroed out (prior to nanoappStart)
+ * - static variables initialized (prior to nanoappStart)
+ * - global C++ constructors called (prior to nanoappStart)
+ * - global C++ destructors called (after nanoappEnd)
+ *
+ * @section threading Threading model
+ *
+ * A CHRE implementation is free to choose among many different
+ * threading models, including a single-threaded system or a multi-threaded
+ * system with preemption.  The current platform definition is agnostic to this
+ * underlying choice.  However, the CHRE implementation must ensure that time
+ * spent executing within a nanoapp does not significantly degrade or otherwise
+ * interfere with other functions of the system in which CHRE is implemented,
+ * especially latency-sensitive tasks such as sensor event delivery to the AP.
+ * In other words, it must ensure that these functions can either occur in
+ * parallel or preempt a nanoapp's execution.  The current version of the API
+ * does not specify whether the implementation allows for CPU sharing between
+ * nanoapps on a more granular level than the handling of individual events [1].
+ * In any case, event ordering from the perspective of an individual nanoapp
+ * must be FIFO, but the CHRE implementation may choose to violate total
+ * ordering of events across all nanoapps to achieve more fair resource sharing,
+ * but this is not required.
+ *
+ * This version of the CHRE API does require that all nanoapps are treated as
+ * non-reentrant, meaning that only one instance of program flow can be inside
+ * an individual nanoapp at any given time.  That is, any of the functions of
+ * the nanoapp, including the entry points and all other callbacks, cannot be
+ * invoked if a previous invocation to the same or any other function in the
+ * nanoapp has not completed yet.
+ *
+ * For example, if a nanoapp is currently in nanoappHandleEvent(), the CHRE is
+ * not allowed to call nanoappHandleEvent() again, or to call a memory freeing
+ * callback.  Similarly, if a nanoapp is currently in a memory freeing
+ * callback, the CHRE is not allowed to call nanoappHandleEvent(), or invoke
+ * another memory freeing callback.
+ *
+ * There are two exceptions to this rule: If an invocation of chreSendEvent()
+ * fails (returns 'false'), it is allowed to immediately invoke the memory
+ * freeing callback passed into that function.  This is a rare case, and one
+ * where otherwise a CHRE implementation is likely to leak memory. Similarly,
+ * chreSendMessageToHost() is allowed to invoke the memory freeing callback
+ * directly, whether it returns 'true' or 'false'.  This is because the CHRE
+ * implementation may copy the message data to its own buffer, and therefore
+ * wouldn't need the nanoapp-supplied buffer after chreSendMessageToHost()
+ * returns.
+ *
+ * For a nanoapp author, this means no thought needs to be given to
+ * synchronization issues with global objects, as they will, by definition,
+ * only be accessed by a single thread at once.
+ *
+ * [1]: Note to CHRE implementers: A future version of the CHRE platform may
+ * require multi-threading with preemption.  This is mentioned as a heads up,
+ * and to allow implementors deciding between implementation approaches to
+ * make the most informed choice.
+ *
+ * @section timing Timing
+ *
+ * Nanoapps should expect to be running on a highly constrained system, with
+ * little memory and little CPU.  Any single nanoapp should expect to
+ * be one of several nanoapps on the system, which also share the CPU with the
+ * CHRE and possibly other services as well.
+ *
+ * Thus, a nanoapp needs to be efficient in its memory and CPU usage.
+ * Also, as noted in the Threading Model section, a CHRE implementation may
+ * be single threaded.  As a result, all methods invoked in a nanoapp
+ * (like nanoappStart, nanoappHandleEvent, memory free callbacks, etc.)
+ * must run "quickly".  "Quickly" is difficult to define, as there is a
+ * diversity of Context Hub hardware.  Nanoapp authors are strongly recommended
+ * to limit their application to consuming no more than 1 second of CPU time
+ * prior to returning control to the CHRE implementation.  A CHRE implementation
+ * may consider a nanoapp as unresponsive if it spends more time than this to
+ * process a single event, and take corrective action.
+ *
+ * A nanoapp may have the need to occasionally perform a large block of
+ * calculations that exceeds the 1 second guidance.  The recommended approach in
+ * this case is to split up the large block of calculations into smaller
+ * batches.  In one call into the nanoapp, the nanoapp can perform the first
+ * batch, and then set a timer or send an event (chreSendEvent()) to itself
+ * indicating which batch should be done next. This will allow the nanoapp to
+ * perform the entire calculation over time, without monopolizing system
+ * resources.
+ *
+ * @section floats Floating point support
+ *
+ * The C type 'float' is used in this API, and thus a CHRE implementation
+ * is required to support 'float's.
+ *
+ * Support of the C types 'double' and 'long double' is optional for a
+ * CHRE implementation.  Note that if a CHRE decides to support them, unlike
+ * 'float' support, there is no requirement that this support is particularly
+ * efficient.  So nanoapp authors should be aware this may be inefficient.
+ *
+ * If a CHRE implementation chooses not to support 'double' or
+ * 'long double', then the build toolchain setup provided needs to set
+ * the preprocessor define CHRE_NO_DOUBLE_SUPPORT.
+ *
+ * @section compat CHRE and Nanoapp compatibility
+ *
+ * CHRE implementations must make affordances to maintain binary compatibility
+ * across minor revisions of the API version (e.g. v1.1 to v1.2).  This applies
+ * to both running a nanoapp compiled for a newer version of the API on a CHRE
+ * implementation built against an older version (backwards compatibility), and
+ * vice versa (forwards compatibility).  API changes that are acceptable in
+ * minor version changes that may require special measures to ensure binary
+ * compatibility include: addition of new functions; addition of arguments to
+ * existing functions when the default value used for nanoapps compiled against
+ * the old version is well-defined and does not affect existing functionality;
+ * and addition of fields to existing structures, even when this induces a
+ * binary layout change (this should be made rare via judicious use of reserved
+ * fields).  API changes that must only occur alongside a major version change
+ * and are therefore not compatible include: removal of any function, argument,
+ * field in a data structure, or mandatory functional behavior that a nanoapp
+ * may depend on; any change in the interpretation of an existing data structure
+ * field that alters the way it was defined previously (changing the units of a
+ * field would fall under this, but appropriating a previously reserved field
+ * for some new functionality would not); and any change in functionality or
+ * expected behavior that conflicts with the previous definition.
+ *
+ * Note that the CHRE API only specifies the software interface between a
+ * nanoapp and the CHRE system - the binary interface (ABI) between nanoapp and
+ * CHRE is necessarily implementation-dependent.  Therefore, the recommended
+ * approach to accomplish binary compatibility is to build a Nanoapp Support
+ * Library (NSL) that is specific to the CHRE implementation into the nanoapp
+ * binary, and use it to handle ABI details in a way that ensures compatibility.
+ * In addition, to accomplish forwards compatibility, the CHRE implementation is
+ * expected to recognize the CHRE API version that a nanoapp is targeting and
+ * engage compatibility behaviors where necessary.
+ *
+ * By definition, major API version changes (e.g. v1.1 to v2.0) break
+ * compatibility.  Therefore, a CHRE implementation must not attempt to load a
+ * nanoapp that is targeting a newer major API version.
+ */
+
+#endif  /* _CHRE_H_ */
+
diff --git a/chre_api/legacy/v1_11/chre/audio.h b/chre_api/legacy/v1_11/chre/audio.h
new file mode 100644
index 00000000..085329ec
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/audio.h
@@ -0,0 +1,432 @@
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_AUDIO_H_
+#define _CHRE_AUDIO_H_
+
+/**
+ * @file
+ * The API for requesting audio in the Context Hub Runtime Environment.
+ *
+ * This includes the definition of audio data structures and the ability to
+ * request audio streams.
+ */
+
+#include <chre/event.h>
+
+#include <stdint.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * The current compatibility version of the chreAudioDataEvent structure.
+ */
+#define CHRE_AUDIO_DATA_EVENT_VERSION  UINT8_C(1)
+
+/**
+ * Produce an event ID in the block of IDs reserved for audio
+ * @param offset Index into audio event ID block; valid range [0,15]
+ */
+#define CHRE_AUDIO_EVENT_ID(offset)  (CHRE_EVENT_AUDIO_FIRST_EVENT + (offset))
+
+/**
+ * nanoappHandleEvent argument: struct chreAudioSourceStatusEvent
+ *
+ * Indicates a change in the format and/or rate of audio data provided to a
+ * nanoapp.
+ */
+#define CHRE_EVENT_AUDIO_SAMPLING_CHANGE  CHRE_AUDIO_EVENT_ID(0)
+
+/**
+ * nanoappHandleEvent argument: struct chreAudioDataEvent
+ *
+ * Provides a buffer of audio data to a nanoapp.
+ */
+#define CHRE_EVENT_AUDIO_DATA  CHRE_AUDIO_EVENT_ID(1)
+
+/**
+ * The maximum size of the name of an audio source including the
+ * null-terminator.
+ */
+#define CHRE_AUDIO_SOURCE_NAME_MAX_SIZE  (40)
+
+/**
+ * Helper values for sample rates.
+ *
+ * @defgroup CHRE_AUDIO_SAMPLE_RATES
+ * @{
+ */
+
+//! 16kHz Audio Sample Data
+#define CHRE_AUDIO_SAMPLE_RATE_16KHZ  (16000)
+
+/** @} */
+
+/**
+ * Formats for audio that can be provided to a nanoapp.
+ */
+enum chreAudioDataFormat {
+  /**
+   * Unsigned, 8-bit u-Law encoded data as specified by ITU-T G.711.
+   */
+  CHRE_AUDIO_DATA_FORMAT_8_BIT_U_LAW = 0,
+
+  /**
+   * Signed, 16-bit linear PCM data. Endianness must be native to the local
+   * processor.
+   */
+  CHRE_AUDIO_DATA_FORMAT_16_BIT_SIGNED_PCM = 1,
+};
+
+/**
+ * A description of an audio source available to a nanoapp.
+ *
+ * This provides a description of an audio source with a name and a
+ * description of the format of the provided audio data.
+ */
+struct chreAudioSource {
+  /**
+   * A human readable name for this audio source. This is a C-style,
+   * null-terminated string. The length must be less than or equal to
+   * CHRE_AUDIO_SOURCE_NAME_MAX_SIZE bytes (including the null-terminator) and
+   * is expected to describe the source of the audio in US English. All
+   * characters must be printable (i.e.: isprint would return true for all
+   * characters in the name for the EN-US locale). The typical use of this field
+   * is for a nanoapp to log the name of the audio source that it is using.
+   *
+   * Example: "Camcorder Microphone"
+   */
+  const char *name;
+
+  /**
+   * The sampling rate in hertz of this mode. This value is rounded to the
+   * nearest integer. Typical values might include 16000, 44100 and 44800.
+   *
+   * If the requested audio source is preempted by another feature of the system
+   * (e.g. hotword), a gap may occur in received audio data. This is indicated
+   * to the client by posting a CHRE_EVENT_AUDIO_SAMPLING_CHANGE event. The
+   * nanoapp will then receive another CHRE_EVENT_AUDIO_SAMPLING_CHANGE event
+   * once the audio source is available again.
+   */
+  uint32_t sampleRate;
+
+  /**
+   * The minimum amount of time that this audio source can be buffered, in
+   * nanoseconds. Audio data is delivered to nanoapps in buffers. This specifies
+   * the minimum amount of data that can be delivered to a nanoapp without
+   * losing data. A request for a buffer that is smaller than this will fail.
+   */
+  uint64_t minBufferDuration;
+
+  /**
+   * The maximum amount of time that this audio source can be buffered, in
+   * nanoseconds. Audio data is delivered to nanoapps in buffers. This specifies
+   * the maximum amount of data that can be stored by the system in one event
+   * without losing data. A request for a buffer that is larger than this will
+   * fail.
+   */
+  uint64_t maxBufferDuration;
+
+  /**
+   * The format for data provided to the nanoapp. This will be assigned to one
+   * of the enum chreAudioDataFormat values.
+   */
+  uint8_t format;
+};
+
+/**
+ * The current status of an audio source.
+ */
+struct chreAudioSourceStatus {
+  /**
+   * Set to true if the audio source is currently enabled by this nanoapp. If
+   * this struct is provided by a CHRE_EVENT_AUDIO_SAMPLING_CHANGE event, it
+   * must necessarily be set to true because sampling change events are only
+   * sent for sources which this nanoapp has actively subscribed to. If this
+   * struct is obtained from the chreAudioGetStatus API, it may be set to true
+   * or false depending on if audio is currently enabled.
+   */
+  bool enabled;
+
+  /**
+   * Set to true if the audio source is currently suspended and no audio data
+   * will be received from this source.
+   */
+  bool suspended;
+};
+
+/**
+ * The nanoappHandleEvent argument for CHRE_EVENT_AUDIO_SAMPLING_CHANGE.
+ */
+struct chreAudioSourceStatusEvent {
+  /**
+   * The audio source which has completed a status change.
+   */
+  uint32_t handle;
+
+  /**
+   * The status of this audio source.
+   */
+  struct chreAudioSourceStatus status;
+};
+
+/**
+ * The nanoappHandleEvent argument for CHRE_EVENT_AUDIO_DATA.
+ *
+ * One example of the sequence of events for a nanoapp to receive audio data is:
+ *
+ * 1. CHRE_EVENT_AUDIO_SAMPLING_CHANGE - Indicates that audio data is not
+ *                                       suspended.
+ * 2. CHRE_EVENT_AUDIO_DATA - One buffer of audio samples. Potentially repeated.
+ * 3. CHRE_EVENT_AUDIO_SAMPLING_CHANGE - Indicates that audio data has suspended
+ *                                       which indicates a gap in the audio.
+ * 4. CHRE_EVENT_AUDIO_SAMPLING_CHANGE - Indicates that audio data has resumed
+ *                                       and that audio data may be delivered
+ *                                       again if enough samples are buffered.
+ * 5. CHRE_EVENT_AUDIO_DATA - One buffer of audio samples. Potentially repeated.
+ *                            The nanoapp must tolerate a gap in the timestamps.
+ *
+ * This process repeats for as long as an active request is made for an audio
+ * source. A CHRE_EVENT_AUDIO_SAMPLING_CHANGE does not guarantee that the next
+ * event will be a CHRE_EVENT_AUDIO_DATA event when suspended is set to false.
+ * It may happen that the audio source is suspended before a complete buffer can
+ * be captured. This will cause another CHRE_EVENT_AUDIO_SAMPLING_CHANGE event
+ * to be dispatched with suspended set to true before a buffer is delivered.
+ *
+ * Audio events must be delivered to a nanoapp in order.
+ */
+struct chreAudioDataEvent {
+  /**
+   * Indicates the version of the structure, for compatibility purposes. Clients
+   * do not normally need to worry about this field; the CHRE implementation
+   * guarantees that the client only receives the structure version it expects.
+   */
+  uint8_t version;
+
+  /**
+   * Additional bytes reserved for future use; must be set to 0.
+   */
+  uint8_t reserved[3];
+
+  /**
+   * The handle for which this audio data originated from.
+   */
+  uint32_t handle;
+
+  /**
+   * The base timestamp for this buffer of audio data, from the same time base
+   * as chreGetTime() (in nanoseconds). The audio API does not provide
+   * timestamps for each audio sample. This timestamp corresponds to the first
+   * sample of the buffer. Even though the value is expressed in nanoseconds,
+   * there is an expectation that the sample clock may drift and nanosecond
+   * level accuracy may not be possible. The goal is to be as accurate as
+   * possible within reasonable limitations of a given system.
+   */
+  uint64_t timestamp;
+
+  /**
+   * The sample rate for this buffer of data in hertz, rounded to the nearest
+   * integer. Fractional sampling rates are not supported. Typical values might
+   * include 16000, 44100 and 48000.
+   */
+  uint32_t sampleRate;
+
+  /**
+   * The number of samples provided with this buffer.
+   */
+  uint32_t sampleCount;
+
+  /**
+   * The format of this audio data. This enumeration and union of pointers below
+   * form a tagged struct. The consumer of this API must use this enum to
+   * determine which samples pointer below to dereference. This will be assigned
+   * to one of the enum chreAudioDataFormat values.
+   */
+  uint8_t format;
+
+  /**
+   * A union of pointers to various formats of sample data. These correspond to
+   * the valid chreAudioDataFormat values.
+   */
+  union {
+    const uint8_t *samplesULaw8;
+    const int16_t *samplesS16;
+  };
+};
+
+/**
+ * Retrieves information about an audio source supported by the current CHRE
+ * implementation. The source returned by the runtime must not change for the
+ * entire lifecycle of the Nanoapp and hot-pluggable audio sources are not
+ * supported.
+ *
+ * A simple example of iterating all available audio sources is provided here:
+ *
+ * struct chreAudioSource audioSource;
+ * for (uint32_t i = 0; chreAudioGetSource(i, &audioSource); i++) {
+ *     chreLog(CHRE_LOG_INFO, "Found audio source: %s", audioSource.name);
+ * }
+ *
+ * Handles provided to this API must be a stable value for the entire duration
+ * of a nanoapp. Handles for all audio sources must be zero-indexed and
+ * contiguous. The following are examples of handles that could be provided to
+ * this API:
+ *
+ *   Valid: 0
+ *   Valid: 0, 1, 2, 3
+ * Invalid: 1, 2, 3
+ * Invalid: 0, 2
+ *
+ * @param handle The handle for an audio source to obtain details for. The
+ *     range of acceptable handles must be zero-indexed and contiguous.
+ * @param audioSource A struct to populate with details of the audio source.
+ * @return true if the query was successful, false if the provided handle is
+ *     invalid or the supplied audioSource is NULL.
+ *
+ * @since v1.2
+ */
+bool chreAudioGetSource(uint32_t handle, struct chreAudioSource *audioSource);
+
+/**
+ * Nanoapps must define CHRE_NANOAPP_USES_AUDIO somewhere in their build
+ * system (e.g. Makefile) if the nanoapp needs to use the following audio APIs.
+ * In addition to allowing access to these APIs, defining this macro will also
+ * ensure CHRE enforces that all host clients this nanoapp talks to have the
+ * required Android permissions needed to listen to audio data by adding
+ * metadata to the nanoapp.
+ */
+#if defined(CHRE_NANOAPP_USES_AUDIO) || !defined(CHRE_IS_NANOAPP_BUILD)
+
+/**
+ * Configures delivery of audio data to the current nanoapp. Note that this may
+ * not fully disable the audio source if it is used by other clients in the
+ * system but it will halt data delivery to the nanoapp.
+ *
+ * The bufferDuration and deliveryInterval parameters as described below are
+ * used together to determine both how much and how often to deliver data to a
+ * nanoapp, respectively. A nanoapp will always be provided the requested
+ * amount of data at the requested interval, even if another nanoapp in CHRE
+ * requests larger/more frequent buffers or smaller/less frequent buffers.
+ * These two buffering parameters allow describing the duty cycle of captured
+ * audio data. If a nanoapp wishes to receive all available audio data, it will
+ * specify a bufferDuration and deliveryInterval that are equal. A 50% duty
+ * cycle would be achieved by specifying a deliveryInterval that is double the
+ * value of the bufferDuration provided. These parameters allow the audio
+ * subsystem to operate at less than 100% duty cycle and permits use of
+ * incomplete audio data without periodic reconfiguration of the source.
+ *
+ * Two examples are illustrated below:
+ *
+ * Target duty cycle: 50%
+ * bufferDuration:    2
+ * deliveryInterval:  4
+ *
+ * Time       0   1   2   3   4   5   6   7
+ * Batch                  A               B
+ * Sample    --  --  a1  a2  --  --  b1  b2
+ * Duration          [    ]          [    ]
+ * Interval  [            ]  [            ]
+ *
+ *
+ * Target duty cycle: 100%
+ * bufferDuration:    4
+ * deliveryInterval:  4
+ *
+ * Time       0   1   2   3   4   5   6   7
+ * Batch                  A               B
+ * Sample    a1  a2  a3  a4  b1  b2  b3  b4
+ * Duration  [            ]  [            ]
+ * Interval  [            ]  [            ]
+ *
+ *
+ * This is expected to reduce power overall.
+ *
+ * The first audio buffer supplied to the nanoapp may contain data captured
+ * prior to the request. This could happen if the microphone was already enabled
+ * and reading into a buffer prior to the nanoapp requesting audio data for
+ * itself. The nanoapp must tolerate this.
+ *
+ * It is important to note that multiple logical audio sources (e.g. different
+ * sample rate, format, etc.) may map to one physical audio source. It is
+ * possible for a nanoapp to request audio data from more than one logical
+ * source at a time. Audio data may be suspended for either the current or other
+ * requests. The CHRE_EVENT_AUDIO_SAMPLING_CHANGE will be posted to all clients
+ * if such a change occurs. It is also possible for the request to succeed and
+ * all audio sources are serviced simultaneously. This is implementation defined
+ * but at least one audio source must function correctly if it is advertised,
+ * under normal conditions (e.g. not required for some other system function,
+ * such as hotword).
+ *
+ * @param handle The handle for this audio source. The handle for the desired
+ *     audio source can be determined using chreAudioGetSource().
+ * @param enable true if enabling the source, false otherwise. When passed as
+ *     false, the bufferDuration and deliveryInterval parameters are ignored.
+ * @param bufferDuration The amount of time to capture audio samples from this
+ *     audio source, in nanoseconds per delivery interval. This value must be
+ *     in the range of minBufferDuration/maxBufferDuration for this source or
+ *     the request will fail. The number of samples captured per buffer will be
+ *     derived from the sample rate of the source and the requested duration and
+ *     rounded down to the nearest sample boundary.
+ * @param deliveryInterval Desired time between each CHRE_EVENT_AUDIO_DATA
+ *     event. This allows specifying the complete duty cycle of a request
+ *     for audio data, in nanoseconds. This value must be greater than or equal
+ *     to bufferDuration or the request will fail due to an invalid
+ *     configuration.
+ * @return true if the configuration was successful, false if invalid parameters
+ *     were provided (non-existent handle, invalid buffering configuration).
+ *
+ * @since v1.2
+ * @note Requires audio permission
+ */
+bool chreAudioConfigureSource(uint32_t handle, bool enable,
+                              uint64_t bufferDuration,
+                              uint64_t deliveryInterval);
+
+/**
+ * Gets the current chreAudioSourceStatus struct for a given audio handle.
+ *
+ * @param handle The handle for the audio source to query. The provided handle
+ *     is obtained from a chreAudioSource which is requested from the
+ *     chreAudioGetSource API.
+ * @param status The current status of the supplied audio source.
+ * @return true if the provided handle is valid and the status was obtained
+ *     successfully, false if the handle was invalid or status is NULL.
+ *
+ * @since v1.2
+ * @note Requires audio permission
+ */
+bool chreAudioGetStatus(uint32_t handle, struct chreAudioSourceStatus *status);
+
+#else  /* defined(CHRE_NANOAPP_USES_AUDIO) || !defined(CHRE_IS_NANOAPP_BUILD) */
+#define CHRE_AUDIO_PERM_ERROR_STRING \
+    "CHRE_NANOAPP_USES_AUDIO must be defined when building this nanoapp in " \
+    "order to refer to "
+#define chreAudioConfigureSource(...) \
+    CHRE_BUILD_ERROR(CHRE_AUDIO_PERM_ERROR_STRING "chreAudioConfigureSource")
+#define chreAudioGetStatus(...) \
+    CHRE_BUILD_ERROR(CHRE_AUDIO_PERM_ERROR_STRING "chreAudioGetStatus")
+#endif  /* defined(CHRE_NANOAPP_USES_AUDIO) || !defined(CHRE_IS_NANOAPP_BUILD) */
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* _CHRE_AUDIO_H_ */
diff --git a/chre_api/legacy/v1_11/chre/ble.h b/chre_api/legacy/v1_11/chre/ble.h
new file mode 100644
index 00000000..06a88ec8
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/ble.h
@@ -0,0 +1,1163 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef CHRE_BLE_H_
+#define CHRE_BLE_H_
+
+/**
+ * @file
+ * CHRE BLE (Bluetooth Low Energy, Bluetooth LE) API.
+ * The CHRE BLE API currently supports BLE scanning features.
+ *
+ * The features in the CHRE BLE API are a subset and adaptation of Android
+ * capabilities as described in the Android BLE API and HCI requirements.
+ * ref:
+ * https://developer.android.com/guide/topics/connectivity/bluetooth/ble-overview
+ * ref: https://source.android.com/devices/bluetooth/hci_requirements
+ *
+ * All byte arrays in the CHRE BLE API follow the byte order used OTA unless
+ * specified otherwise, and multi-byte types, for example uint16_t, follow the
+ * processor's native byte order. One notable exception is addresses. Address
+ * fields in both scan filters and advertising reports must be in big endian
+ * byte order to match the Android Bluetooth API (ref:
+ * https://developer.android.com/reference/android/bluetooth/BluetoothAdapter#getRemoteDevice(byte[])).
+ */
+
+#include <chre/common.h>
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <string.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * The set of flags returned by chreBleGetCapabilities().
+ *
+ * @defgroup CHRE_BLE_CAPABILITIES
+ * @{
+ */
+//! No BLE APIs are supported
+#define CHRE_BLE_CAPABILITIES_NONE (UINT32_C(0))
+
+//! CHRE supports BLE scanning
+#define CHRE_BLE_CAPABILITIES_SCAN (UINT32_C(1) << 0)
+
+//! CHRE BLE supports batching of scan results, either through Android-specific
+//! HCI (OCF: 0x156), or by the CHRE framework, internally.
+//! @since v1.7 Platforms with this capability must also support flushing scan
+//! results during a batched scan.
+#define CHRE_BLE_CAPABILITIES_SCAN_RESULT_BATCHING (UINT32_C(1) << 1)
+
+//! CHRE BLE scan supports best-effort hardware filtering. If filtering is
+//! available, chreBleGetFilterCapabilities() returns a bitmap indicating the
+//! specific filtering capabilities that are supported.
+//! To differentiate best-effort vs. no filtering, the following requirement
+//! must be met for this flag:
+//! If only one nanoapp is requesting BLE scans and there are no BLE scans from
+//! the AP, only filtered results will be provided to the nanoapp.
+#define CHRE_BLE_CAPABILITIES_SCAN_FILTER_BEST_EFFORT (UINT32_C(1) << 2)
+
+//! CHRE BLE supports reading the RSSI of a specified LE-ACL connection handle.
+#define CHRE_BLE_CAPABILITIES_READ_RSSI (UINT32_C(1) << 3)
+
+//! CHRE supports offloading a Bluetooth connection socket for bidirectional
+//! data transfer over a Connection-Oriented Channel (COC).
+#define CHRE_BLE_CAPABILITIES_LE_COC_SOCKET UINT32_C (UINT32_C(1) << 4)
+/** @} */
+
+/**
+ * The set of flags returned by chreBleGetFilterCapabilities().
+ *
+ * The representative bit for each filtering capability is based on the sub-OCF
+ * of the Android filtering HCI vendor-specific command (LE_APCF_Command, OCF:
+ * 0x0157) for that particular filtering capability, as found in
+ * https://source.android.com/devices/bluetooth/hci_requirements
+ *
+ * For example, the Service Data filter has a sub-command of 0x7; hence
+ * the filtering capability is indicated by (1 << 0x7).
+ *
+ * @defgroup CHRE_BLE_FILTER_CAPABILITIES
+ * @{
+ */
+//! No CHRE BLE filters are supported
+#define CHRE_BLE_FILTER_CAPABILITIES_NONE (UINT32_C(0))
+
+//! CHRE BLE supports RSSI filters
+#define CHRE_BLE_FILTER_CAPABILITIES_RSSI (UINT32_C(1) << 1)
+
+//! CHRE BLE supports Broadcaster Address filters (Corresponding HCI OCF:
+//! 0x0157, Sub-command: 0x02)
+//! @since v1.9
+#define CHRE_BLE_FILTER_CAPABILITIES_BROADCASTER_ADDRESS (UINT32_C(1) << 2)
+
+//! CHRE BLE supports Manufacturer Data filters (Corresponding HCI OCF: 0x0157,
+//! Sub-command: 0x06)
+//! @since v1.8
+#define CHRE_BLE_FILTER_CAPABILITIES_MANUFACTURER_DATA (UINT32_C(1) << 6)
+
+//! CHRE BLE supports Service Data filters (Corresponding HCI OCF: 0x0157,
+//! Sub-command: 0x07)
+#define CHRE_BLE_FILTER_CAPABILITIES_SERVICE_DATA (UINT32_C(1) << 7)
+/** @} */
+
+/**
+ * Produce an event ID in the block of IDs reserved for BLE.
+ *
+ * Valid input range is [0, 15]. Do not add new events with ID > 15
+ * (see chre/event.h)
+ *
+ * @param offset Index into BLE event ID block; valid range is [0, 15].
+ *
+ * @defgroup CHRE_BLE_EVENT_ID
+ * @{
+ */
+#define CHRE_BLE_EVENT_ID(offset) (CHRE_EVENT_BLE_FIRST_EVENT + (offset))
+
+/**
+ * nanoappHandleEvent argument: struct chreAsyncResult
+ *
+ * Communicates the asynchronous result of a request to the BLE API. The
+ * requestType field in {@link #chreAsyncResult} is set to a value from enum
+ * chreBleRequestType.
+ *
+ * This is used for results of async config operations which need to
+ * interop with lower level code (potentially in a different thread) or send an
+ * HCI command to the FW and wait on the response.
+ */
+#define CHRE_EVENT_BLE_ASYNC_RESULT CHRE_BLE_EVENT_ID(0)
+
+/**
+ * nanoappHandleEvent argument: struct chreBleAdvertisementEvent
+ *
+ * Provides results of a BLE scan.
+ */
+#define CHRE_EVENT_BLE_ADVERTISEMENT CHRE_BLE_EVENT_ID(1)
+
+/**
+ * nanoappHandleEvent argument: struct chreAsyncResult
+ *
+ * Indicates that a flush request made via chreBleFlushAsync() is complete, and
+ * all batched advertisements resulting from the flush have been delivered via
+ * preceding CHRE_EVENT_BLE_ADVERTISEMENT events.
+ *
+ * @since v1.7
+ */
+#define CHRE_EVENT_BLE_FLUSH_COMPLETE CHRE_BLE_EVENT_ID(2)
+
+/**
+ * nanoappHandleEvent argument: struct chreBleReadRssiEvent
+ *
+ * Provides the RSSI of an LE ACL connection following a call to
+ * chreBleReadRssiAsync().
+ *
+ * @since v1.8
+ */
+#define CHRE_EVENT_BLE_RSSI_READ CHRE_BLE_EVENT_ID(3)
+
+/**
+ * nanoappHandleEvent argument: struct chreBatchCompleteEvent
+ *
+ * This event is generated if the platform enabled batching, and when all
+ * events in a single batch has been delivered (for example, batching
+ * CHRE_EVENT_BLE_ADVERTISEMENT events if the platform has
+ * CHRE_BLE_CAPABILITIES_SCAN_RESULT_BATCHING enabled, and a non-zero
+ * reportDelayMs in chreBleStartScanAsync() was accepted).
+ *
+ * If the nanoapp receives a CHRE_EVENT_BLE_SCAN_STATUS_CHANGE with a non-zero
+ * reportDelayMs and enabled set to true, then this event must be generated.
+ *
+ * @since v1.8
+ */
+#define CHRE_EVENT_BLE_BATCH_COMPLETE CHRE_BLE_EVENT_ID(4)
+
+/**
+ * nanoappHandleEvent argument: struct chreBleScanStatus
+ *
+ * This event is generated when the values in chreBleScanStatus changes.
+ *
+ * @since v1.8
+ */
+#define CHRE_EVENT_BLE_SCAN_STATUS_CHANGE CHRE_BLE_EVENT_ID(5)
+
+/**
+ * nanoappHandleEvent argument: struct chreBleSocketConnectionEvent
+ *
+ * This event is sent to a nanoapp when ownership of a connected BLE socket is
+ * being transferred to the nanoapp. If the nanoapp does not call
+ * chreBleSocketAccept() while handling this event, then the transfer is
+ * aborted.
+ *
+ * @see chreBleSocketAccept()
+ * @since v1.11
+ */
+#define CHRE_EVENT_BLE_SOCKET_CONNECTION CHRE_BLE_EVENT_ID(6)
+
+/**
+ * nanoappHandleEvent argument: struct chreBleSocketDisconnectionEvent
+ *
+ * This event is sent to a nanoapp when a socket it previously accepted via
+ * chreBleSocketAccept() can no longer be used by the nanoapp.
+ *
+ * @since v1.11
+ */
+#define CHRE_EVENT_BLE_SOCKET_DISCONNECTION CHRE_BLE_EVENT_ID(7)
+
+/**
+ * nanoappHandleEvent argument: struct chreBleSocketPacketEvent
+ *
+ * This event is sent when a packet is received over a socket owned by the
+ * nanoapp.
+ *
+ * @since v1.11
+ */
+#define CHRE_EVENT_BLE_SOCKET_PACKET CHRE_BLE_EVENT_ID(8)
+
+/**
+ * nanoappHandleEvent argument: NULL
+ *
+ * This event is sent when a socket is ready to accept packets after
+ * encountering CHRE_BLE_SOCKET_SEND_STATUS_QUEUE_FULL.
+ *
+ * @see chreBleSocketSend()
+ * @since v1.11
+ */
+#define CHRE_EVENT_BLE_SOCKET_SEND_AVAILABLE CHRE_BLE_EVENT_ID(9)
+
+// NOTE: Do not add new events with ID > 15
+/** @} */
+
+/**
+ * Maximum BLE (legacy) advertisement payload data length, in bytes
+ * This is calculated by subtracting 2 (type + len) from 31 (max payload).
+ */
+#define CHRE_BLE_DATA_LEN_MAX (29)
+
+/**
+ * BLE device address length, in bytes.
+ */
+#define CHRE_BLE_ADDRESS_LEN (6)
+
+/**
+ * RSSI value (int8_t) indicating no RSSI threshold.
+ */
+#define CHRE_BLE_RSSI_THRESHOLD_NONE (-128)
+
+/**
+ * RSSI value (int8_t) indicating no RSSI value available.
+ */
+#define CHRE_BLE_RSSI_NONE (127)
+
+/**
+ * Tx power value (int8_t) indicating no Tx power value available.
+ */
+#define CHRE_BLE_TX_POWER_NONE (127)
+
+/**
+ * Indicates ADI field was not provided in advertisement.
+ */
+#define CHRE_BLE_ADI_NONE (0xFF)
+
+/**
+ * The CHRE BLE advertising event type is based on the BT Core Spec v5.2,
+ * Vol 4, Part E, Section 7.7.65.13, LE Extended Advertising Report event,
+ * Event_Type.
+ *
+ * Note: helper functions are provided to avoid bugs, e.g. a nanoapp doing
+ * (eventTypeAndDataStatus == ADV_IND) instead of properly masking off reserved
+ * and irrelevant bits.
+ *
+ * @defgroup CHRE_BLE_EVENT
+ * @{
+ */
+// Extended event types
+#define CHRE_BLE_EVENT_MASK_TYPE (0x1f)
+#define CHRE_BLE_EVENT_TYPE_FLAG_CONNECTABLE (1 << 0)
+#define CHRE_BLE_EVENT_TYPE_FLAG_SCANNABLE (1 << 1)
+#define CHRE_BLE_EVENT_TYPE_FLAG_DIRECTED (1 << 2)
+#define CHRE_BLE_EVENT_TYPE_FLAG_SCAN_RSP (1 << 3)
+#define CHRE_BLE_EVENT_TYPE_FLAG_LEGACY (1 << 4)
+
+// Data status
+#define CHRE_BLE_EVENT_MASK_DATA_STATUS (0x3 << 5)
+#define CHRE_BLE_EVENT_DATA_STATUS_COMPLETE (0x0 << 5)
+#define CHRE_BLE_EVENT_DATA_STATUS_MORE_DATA_PENDING (0x1 << 5)
+#define CHRE_BLE_EVENT_DATA_STATUS_DATA_TRUNCATED (0x2 << 5)
+
+// Legacy event types
+#define CHRE_BLE_EVENT_TYPE_LEGACY_ADV_IND                                  \
+  (CHRE_BLE_EVENT_TYPE_FLAG_LEGACY | CHRE_BLE_EVENT_TYPE_FLAG_CONNECTABLE | \
+   CHRE_BLE_EVENT_TYPE_FLAG_SCANNABLE)
+#define CHRE_BLE_EVENT_TYPE_LEGACY_DIRECT_IND \
+  (CHRE_BLE_EVENT_TYPE_FLAG_LEGACY | CHRE_BLE_EVENT_TYPE_FLAG_CONNECTABLE)
+#define CHRE_BLE_EVENT_TYPE_LEGACY_ADV_SCAN_IND \
+  (CHRE_BLE_EVENT_TYPE_FLAG_LEGACY | CHRE_BLE_EVENT_TYPE_FLAG_SCANNABLE)
+#define CHRE_BLE_EVENT_TYPE_LEGACY_ADV_NONCONN_IND \
+  (CHRE_BLE_EVENT_TYPE_FLAG_LEGACY)
+#define CHRE_BLE_EVENT_TYPE_LEGACY_SCAN_RESP_ADV_IND \
+  (CHRE_BLE_EVENT_TYPE_FLAG_SCAN_RSP | CHRE_BLE_EVENT_TYPE_LEGACY_ADV_IND)
+#define CHRE_BLE_EVENT_TYPE_LEGACY_SCAN_RESP_ADV_SCAN_IND \
+  (CHRE_BLE_EVENT_TYPE_FLAG_SCAN_RSP | CHRE_BLE_EVENT_TYPE_LEGACY_ADV_SCAN_IND)
+/** @} */
+
+/**
+ * The maximum amount of time allowed to elapse between the call to
+ * chreBleFlushAsync() and when CHRE_EVENT_BLE_FLUSH_COMPLETE is delivered to
+ * the nanoapp on a successful flush.
+ */
+#define CHRE_BLE_FLUSH_COMPLETE_TIMEOUT_NS (5 * CHRE_NSEC_PER_SEC)
+
+/**
+ * Indicates a type of request made in this API. Used to populate the resultType
+ * field of struct chreAsyncResult sent with CHRE_EVENT_BLE_ASYNC_RESULT.
+ */
+enum chreBleRequestType {
+  CHRE_BLE_REQUEST_TYPE_START_SCAN = 1,
+  CHRE_BLE_REQUEST_TYPE_STOP_SCAN = 2,
+  CHRE_BLE_REQUEST_TYPE_FLUSH = 3,      //!< @since v1.7
+  CHRE_BLE_REQUEST_TYPE_READ_RSSI = 4,  //!< @since v1.8
+};
+
+/**
+ * CHRE BLE scan modes identify functional scan levels without specifying or
+ * guaranteeing particular scan parameters (e.g. duty cycle, interval, radio
+ * chain).
+ *
+ * The actual scan parameters may be platform dependent and may change without
+ * notice in real time based on contextual cues, etc.
+ *
+ * Scan modes should be selected based on use cases as described.
+ */
+enum chreBleScanMode {
+  //! A background scan level for always-running ambient applications.
+  //! A representative duty cycle may be between 3 - 10 % (tentative, and
+  //! with no guarantees).
+  CHRE_BLE_SCAN_MODE_BACKGROUND = 1,
+
+  //! A foreground scan level to be used for short periods.
+  //! A representative duty cycle may be between 10 - 20 % (tentative, and
+  //! with no guarantees).
+  CHRE_BLE_SCAN_MODE_FOREGROUND = 2,
+
+  //! A very high duty cycle scan level to be used for very short durations.
+  //! A representative duty cycle may be between 50 - 100 % (tentative, and
+  //! with no guarantees).
+  CHRE_BLE_SCAN_MODE_AGGRESSIVE = 3,
+};
+
+/**
+ * Selected AD Types are available among those defined in the Bluetooth spec.
+ * Assigned Numbers, Generic Access Profile.
+ * ref: https://www.bluetooth.com/specifications/assigned-numbers/
+ */
+enum chreBleAdType {
+  //! Service Data with 16-bit UUID
+  //! @since v1.8 CHRE_BLE_AD_TYPE_SERVICE_DATA_WITH_UUID_16 was renamed
+  //! CHRE_BLE_AD_TYPE_SERVICE_DATA_WITH_UUID_16_LE to reflect that nanoapps
+  //! compiled against v1.8+ should use OTA format for service data filters.
+  CHRE_BLE_AD_TYPE_SERVICE_DATA_WITH_UUID_16_LE = 0x16,
+
+  //! Manufacturer Specific Data
+  //! @since v1.8
+  CHRE_BLE_AD_TYPE_MANUFACTURER_DATA = 0xff,
+};
+
+/**
+ * Generic filters are used to filter for the presence of AD structures in the
+ * data field of LE Extended Advertising Report events (ref: BT Core Spec v5.3,
+ * Vol 3, Part E, Section 11).
+ *
+ * The CHRE generic filter structure represents a generic filter on an AD Type
+ * as defined in the Bluetooth spec Assigned Numbers, Generic Access Profile
+ * (ref: https://www.bluetooth.com/specifications/assigned-numbers/). This
+ * generic structure is used by the Android HCI Advertising Packet Content
+ * Filter (APCF) AD Type sub-command 0x09 (ref:
+ * https://source.android.com/docs/core/connect/bluetooth/hci_requirements#le_apcf_command-ad_type_sub_cmd).
+ *
+ * The filter is matched when an advertisement event contains an AD structure in
+ * its data field that matches the following criteria:
+ *   AdStructure.type == type
+ *   AdStructure.data & dataMask == data & dataMask
+ *
+ * The maximum data length is limited to the maximum possible legacy
+ * advertisement payload data length (29 bytes). The data and dataMask must be
+ * in OTA format. For each zero bit of the dataMask, the corresponding
+ * data bit must also be zero.
+ *
+ * Note that the CHRE implementation may not support every kind of filter that
+ * can be represented by this structure. Use chreBleGetFilterCapabilities() to
+ * discover supported filtering capabilities at runtime.
+ *
+ * Example 1: To filter on a 16 bit service data UUID of 0xFE2C, the following
+ * settings would be used:
+ *   type = CHRE_BLE_AD_TYPE_SERVICE_DATA_WITH_UUID_16_LE
+ *   len = 2
+ *   data = {0x2C, 0xFE}
+ *   dataMask = {0xFF, 0xFF}
+ *
+ * Example 2: To filter for manufacturer data of 0x12, 0x34 from Google (0x00E0),
+ * the following settings would be used:
+ *   type = CHRE_BLE_AD_TYPE_MANUFACTURER_DATA
+ *   len = 4
+ *   data = {0xE0, 0x00, 0x12, 0x34}
+ *   dataMask = {0xFF, 0xFF, 0xFF, 0xFF}
+ *
+ * Refer to "Supplement to the Bluetooth Core Specification for details (v9,
+ * Part A, Section 1.4)" for details regarding the manufacturer data format.
+ */
+struct chreBleGenericFilter {
+  //! Acceptable values among enum chreBleAdType
+  uint8_t type;
+
+  /**
+   * Length of data and dataMask. AD payloads shorter than this length will not
+   * be matched by the filter. Length must be greater than 0.
+   */
+  uint8_t len;
+
+  //! Used in combination with dataMask to filter an advertisement
+  uint8_t data[CHRE_BLE_DATA_LEN_MAX];
+
+  //! Used in combination with data to filter an advertisement
+  uint8_t dataMask[CHRE_BLE_DATA_LEN_MAX];
+};
+
+/**
+ * Broadcaster address filters are used to filter by the address field of the LE
+ * Extended Advertising Report event which is defined in the BT Core Spec v5.3,
+ * Vol 4, Part E, Section 7.7.65.13.
+ *
+ * The CHRE broadcaster address filter structure is modeled after the
+ * Advertising Packet Content Filter (APCF) HCI broadcaster address sub-command
+ * 0x02 (ref:
+ * https://source.android.com/docs/core/connect/bluetooth/hci_requirements#le_apcf_command-broadcast_address_sub_cmd).
+ * However, it differs from this HCI command in two major ways:
+ *
+ * 1) The CHRE broadcaster address filter does not filter by address type at
+ *    this time. If a nanoapp wants to filter for a particular address type, it
+ *    must check the addressType field of the chreBleAdvertisingReport.
+ *
+ * 2) The broadcasterAddress must be in big endian byte order to match the
+ *    format of the Android Bluetooth API (ref:
+ *    https://developer.android.com/reference/android/bluetooth/BluetoothAdapter#getRemoteDevice(byte[])).
+ *    This is intended to allow easier integration between nanoapp and Host
+ *    code.
+ *
+ * The filter is matched when an advertisement even meets the following
+ * criteria:
+ *   broadcasterAddress == chreBleAdvertisingReport.address.
+ *
+ * Example: To filter on the address (01:02:03:AB:CD:EF), the following
+ * settings would be used:
+ *   broadcasterAddress = {0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF}
+ *
+ * @since v1.9
+ */
+struct chreBleBroadcasterAddressFilter {
+  //! 6-byte Broadcaster address
+  uint8_t broadcasterAddress[CHRE_BLE_ADDRESS_LEN];
+};
+
+/**
+ * CHRE Bluetooth LE scan filters.
+ *
+ * @see chreBleScanFilterV1_9 for further details.
+ *
+ * @deprecated as of v1.9 due to the addition of the
+ * chreBleBroadcasterAddressFilter. New code should use chreBleScanFilterV1_9
+ * instead of this struct. This struct will be removed in a future version.
+ */
+struct chreBleScanFilter {
+  //! RSSI threshold filter (Corresponding HCI OCF: 0x0157, Sub: 0x01), where
+  //! advertisements with RSSI values below this threshold may be disregarded.
+  //! An rssiThreshold value of CHRE_BLE_RSSI_THRESHOLD_NONE indicates no RSSI
+  //! filtering.
+  int8_t rssiThreshold;
+
+  //! Number of generic scan filters provided in the scanFilters array.
+  //! A scanFilterCount value of 0 indicates no generic scan filters.
+  uint8_t scanFilterCount;
+
+  //! Pointer to an array of scan filters. If the array contains more than one
+  //! entry, advertisements matching any of the entries will be returned
+  //! (functional OR).
+  const struct chreBleGenericFilter *scanFilters;
+};
+
+/**
+ * CHRE Bluetooth LE scan filters are based on a combination of an RSSI
+ * threshold, generic filters, and broadcaster address filters.
+ *
+ * When multiple filters are specified, rssiThreshold is combined with the other
+ * filters via functional AND, and the other filters are all combined as
+ * functional OR. In other words, an advertisement matches the filter if:
+ *   rssi >= rssiThreshold
+ *   AND (matchAny(genericFilters) OR matchAny(broadcasterAddressFilters))
+ *
+ * CHRE-provided filters are implemented in a best-effort manner, depending on
+ * HW capabilities of the system and available resources. Therefore, provided
+ * scan results may be a superset of the specified filters. Nanoapps should try
+ * to take advantage of CHRE scan filters as much as possible, but must design
+ * their logic as to not depend on CHRE filtering.
+ *
+ * The syntax of CHRE scan filter definition is modeled after a combination of
+ * multiple Android HCI Advertising Packet Content Filter (APCF) sub commands
+ * including the RSSI threshold from the set filtering parameters sub command
+ * (ref:
+ * https://source.android.com/docs/core/connect/bluetooth/hci_requirements#le_apcf_command-set_filtering_parameters_sub_cmd).
+ * @see chreBleGenericFilter and chreBleBroadcasterAddressFilter for details
+ * about other APCF sub commands referenced.
+ *
+ * @since v1.9
+ */
+struct chreBleScanFilterV1_9 {
+  //! RSSI threshold filter (Corresponding HCI OCF: 0x0157, Sub: 0x01), where
+  //! advertisements with RSSI values below this threshold may be disregarded.
+  //! An rssiThreshold value of CHRE_BLE_RSSI_THRESHOLD_NONE indicates no RSSI
+  //! filtering.
+  int8_t rssiThreshold;
+
+  //! Number of generic filters provided in the scanFilters array. A
+  //! genericFilterCount value of 0 indicates no generic filters.
+  uint8_t genericFilterCount;
+
+  //! Pointer to an array of generic filters. If the array contains more than
+  //! one entry, advertisements matching any of the entries will be returned
+  //! (functional OR). This is expected to be null if genericFilterCount is 0.
+  const struct chreBleGenericFilter *genericFilters;
+
+  //! Number of broadcaster address filters provided in the
+  //! broadcasterAddressFilters array. A broadcasterAddressFilterCount value
+  //! of 0 indicates no broadcaster address filters.
+  uint8_t broadcasterAddressFilterCount;
+
+  //! Pointer to an array of broadcaster address filters. If the array contains
+  //! more than one entry, advertisements matching any of the entries will be
+  //! returned (functional OR). This is expected to be null if
+  //! broadcasterAddressFilterCount is 0.
+  const struct chreBleBroadcasterAddressFilter *broadcasterAddressFilters;
+};
+
+/**
+ * CHRE BLE advertising address type is based on the BT Core Spec v5.2, Vol 4,
+ * Part E, Section 7.7.65.13, LE Extended Advertising Report event,
+ * Address_Type.
+ */
+enum chreBleAddressType {
+  //! Public device address.
+  CHRE_BLE_ADDRESS_TYPE_PUBLIC = 0x00,
+
+  //! Random device address.
+  CHRE_BLE_ADDRESS_TYPE_RANDOM = 0x01,
+
+  //! Public identity address (corresponds to resolved private address).
+  CHRE_BLE_ADDRESS_TYPE_PUBLIC_IDENTITY = 0x02,
+
+  //! Random (static) Identity Address (corresponds to resolved private
+  //! address)
+  CHRE_BLE_ADDRESS_TYPE_RANDOM_IDENTITY = 0x03,
+
+  //! No address provided (anonymous advertisement).
+  CHRE_BLE_ADDRESS_TYPE_NONE = 0xff,
+};
+
+/**
+ * CHRE BLE physical (PHY) channel encoding type, if supported, is based on the
+ * BT Core Spec v5.2, Vol 4, Part E, Section 7.7.65.13, LE Extended Advertising
+ * Report event, entries Primary_PHY and Secondary_PHY.
+ */
+enum chreBlePhyType {
+  //! No packets on this PHY (only on the secondary channel), or feature not
+  //! supported.
+  CHRE_BLE_PHY_NONE = 0x00,
+
+  //! LE 1 MBPS PHY encoding.
+  CHRE_BLE_PHY_1M = 0x01,
+
+  //! LE 2 MBPS PHY encoding (only on the secondary channel).
+  CHRE_BLE_PHY_2M = 0x02,
+
+  //! LE long-range coded PHY encoding.
+  CHRE_BLE_PHY_CODED = 0x03,
+};
+
+/**
+ * The CHRE BLE Advertising Report event is based on the BT Core Spec v5.2,
+ * Vol 4, Part E, Section 7.7.65.13, LE Extended Advertising Report event, with
+ * the following differences:
+ *
+ * 1) A CHRE timestamp field, which can be useful if CHRE is batching results.
+ * 2) Reordering of the rssi and periodicAdvertisingInterval fields for memory
+ *    alignment (prevent padding).
+ * 3) Addition of four reserved bytes to reclaim padding.
+ * 4) The address fields are formatted in big endian byte order to match the
+ *    order specified for BluetoothDevices in the Android Bluetooth API (ref:
+ *    https://developer.android.com/reference/android/bluetooth/BluetoothAdapter#getRemoteDevice(byte[])).
+ */
+struct chreBleAdvertisingReport {
+  //! The base timestamp, in nanoseconds, in the same time base as chreGetTime()
+  uint64_t timestamp;
+
+  //! @see CHRE_BLE_EVENT
+  uint8_t eventTypeAndDataStatus;
+
+  //! Advertising address type as defined in enum chreBleAddressType
+  uint8_t addressType;
+
+  //! Advertising device address. Formatted in big endian byte order.
+  uint8_t address[CHRE_BLE_ADDRESS_LEN];
+
+  //! Advertiser PHY on primary advertising physical channel, if supported, as
+  //! defined in enum chreBlePhyType.
+  uint8_t primaryPhy;
+
+  //! Advertiser PHY on secondary advertising physical channel, if supported, as
+  //! defined in enum chreBlePhyType.
+  uint8_t secondaryPhy;
+
+  //! Value of the Advertising SID subfield in the ADI field of the PDU among
+  //! the range of [0, 0x0f].
+  //! CHRE_BLE_ADI_NONE indicates no ADI field was provided.
+  //! Other values are reserved.
+  uint8_t advertisingSid;
+
+  //! Transmit (Tx) power in dBm. Typical values are [-127, 20].
+  //! CHRE_BLE_TX_POWER_NONE indicates Tx power not available.
+  int8_t txPower;
+
+  //! Interval of the periodic advertising in 1.25 ms intervals, i.e.
+  //! time = periodicAdvertisingInterval * 1.25 ms
+  //! 0 means no periodic advertising. Minimum value is otherwise 6 (7.5 ms).
+  uint16_t periodicAdvertisingInterval;
+
+  //! RSSI in dBm. Typical values are [-127, 20].
+  //! CHRE_BLE_RSSI_NONE indicates RSSI is not available.
+  int8_t rssi;
+
+  //! Direct address type (i.e. only accept connection requests from a known
+  //! peer device) as defined in enum chreBleAddressType.
+  uint8_t directAddressType;
+
+  //! Direct address (i.e. only accept connection requests from a known peer
+  //! device). Formatted in big endian byte order.
+  uint8_t directAddress[CHRE_BLE_ADDRESS_LEN];
+
+  //! Length of data field. Acceptable range is [0, 62] for legacy and
+  //! [0, 255] for extended advertisements.
+  uint16_t dataLength;
+
+  //! dataLength bytes of data, or null if dataLength is 0. This represents
+  //! the ADV_IND payload, optionally concatenated with SCAN_RSP, as indicated
+  //! by eventTypeAndDataStatus.
+  const uint8_t *data;
+
+  //! Reserved for future use; set to 0
+  uint32_t reserved;
+};
+
+/**
+ * A CHRE BLE Advertising Event can contain any number of CHRE BLE Advertising
+ * Reports (i.e. advertisements).
+ */
+struct chreBleAdvertisementEvent {
+  //! Reserved for future use; set to 0
+  uint16_t reserved;
+
+  //! Number of advertising reports in this event
+  uint16_t numReports;
+
+  //! Array of length numReports
+  const struct chreBleAdvertisingReport *reports;
+};
+
+/**
+ * The RSSI read on a particular LE connection handle, based on the parameters
+ * in BT Core Spec v5.3, Vol 4, Part E, Section 7.5.4, Read RSSI command
+ */
+struct chreBleReadRssiEvent {
+  //! Structure which contains the cookie associated with the original request,
+  //! along with an error code that indicates request success or failure.
+  struct chreAsyncResult result;
+
+  //! The handle upon which CHRE attempted to read RSSI.
+  uint16_t connectionHandle;
+
+  //! The RSSI of the last packet received on this connection, if valid
+  //! (-127 to 20)
+  int8_t rssi;
+};
+
+/**
+ * Describes the current status of the BLE request in the platform.
+ *
+ * @since v1.8
+ */
+struct chreBleScanStatus {
+  //! The currently configured report delay in the scan configuration.
+  //! If enabled is false, this value does not have meaning.
+  uint32_t reportDelayMs;
+
+  //! True if the BLE scan is currently enabled. This can be set to false
+  //! if BLE scan was temporarily disabled (e.g. BT subsystem is down,
+  //! or due to user settings).
+  bool enabled;
+
+  //! Reserved for future use - set to zero.
+  uint8_t reserved[3];
+};
+
+/**
+ * Data associated with CHRE_EVENT_BLE_SOCKET_CONNECTION.
+ *
+ * @since v1.11
+ */
+struct chreBleSocketConnectionEvent {
+  //! Unique identifier for this socket connection. This ID in CHRE matches the
+  //! ID used on the host side. It is valid only while the socket is connected.
+  uint64_t socketId;
+
+  //! Descriptive socket name provided by the host app that initiated the socket
+  //! offload request. This is not guaranteed to be unique across the system,
+  //! but can help the offload app understand the purpose of the socket when it
+  //! receives a socket connection event. This pointer is only valid for the
+  //! duration of the event.
+  const char *socketName;
+
+  //! When sending a packet to the socket via chreBleSocketSend(), the length
+  //! must not exceed this value.
+  uint16_t maxTxPacketLength;
+
+  //! When the nanoapp receives packets from the socket via the
+  //! chreBleSocketPacketEvent, the length will not exceed this value.
+  uint16_t maxRxPacketLength;
+};
+
+/**
+ * Data associated with CHRE_EVENT_BLE_SOCKET_DISCONNECTION.
+ *
+ * @since v1.11
+ */
+struct chreBleSocketDisconnectionEvent {
+  //! Identifier for the disconnected socket. Once a socket is disconnected, the
+  //! same socket ID will not be reconnected. To resume communication, a new
+  //! socket must be created and transferred to the nanoapp.
+  //! @see chreBleSocketConnectionEvent.socketId
+  uint64_t socketId;
+};
+
+/**
+ * Incoming socket data, sent with CHRE_EVENT_BLE_SOCKET_PACKET.
+ *
+ * @since v1.11
+ */
+struct chreBleSocketPacketEvent {
+  //! @see chreBleSocketConnectionEvent.socketId
+  uint64_t socketId;
+
+  //! Length of data in bytes. The length will not exceed the maxRxPacketLength
+  //! provided in the CHRE event CHRE_EVENT_BLE_SOCKET_CONNECTION.
+  uint16_t length;
+
+  //! Packet payload that is length bytes.
+  const uint8_t *data;
+};
+
+/**
+ * Result code used with chreBleSocketSend().
+ *
+ * @since v1.11
+ */
+enum chreBleSocketSendStatus {
+  //! The packet has successfully been sent to the platform layer.
+  CHRE_BLE_SOCKET_SEND_STATUS_SUCCESS = 1,
+
+  //! The packet will not be sent.
+  CHRE_BLE_SOCKET_SEND_STATUS_FAILURE = 2,
+
+  //! The packet cannot be sent at this time because too many packets are in
+  //! flight. The nanoapp will be notified via a
+  //! CHRE_EVENT_BLE_SOCKET_SEND_AVAILABLE event when the socket is available to
+  //! send the packet.
+  CHRE_BLE_SOCKET_SEND_STATUS_QUEUE_FULL = 3,
+};
+
+/**
+ * Callback which frees the packet sent via chreBleSocketSend().
+ *
+ * This callback is (optionally) provided to the chreBleSocketSend() function as
+ * a means for freeing the packet. When this callback is invoked, the packet is
+ * no longer needed and can be released. Note that this in no way assures that
+ * said packet was sent to the offload socket, simply that this memory is no
+ * longer needed.
+ *
+ * @param data The data argument from chreBleSocketSend().
+ * @param length The length argument from chreBleSocketSend().
+ *
+ * @see chreBleSocketSend()
+ *
+ * @since v1.11
+ */
+typedef void(chreBleSocketPacketFreeFunction)(void *data, uint16_t length);
+
+/**
+ * Retrieves a set of flags indicating the BLE features supported by the
+ * current CHRE implementation. The value returned by this function must be
+ * consistent for the entire duration of the nanoapp's execution.
+ *
+ * The client must allow for more flags to be set in this response than it knows
+ * about, for example if the implementation supports a newer version of the API
+ * than the client was compiled against.
+ *
+ * @return A bitmask with zero or more CHRE_BLE_CAPABILITIES_* flags set. @see
+ *         CHRE_BLE_CAPABILITIES
+ *
+ * @since v1.6
+ */
+uint32_t chreBleGetCapabilities(void);
+
+/**
+ * Retrieves a set of flags indicating the BLE filtering features supported by
+ * the current CHRE implementation. The value returned by this function must be
+ * consistent for the entire duration of the nanoapp's execution.
+ *
+ * The client must allow for more flags to be set in this response than it knows
+ * about, for example if the implementation supports a newer version of the API
+ * than the client was compiled against.
+ *
+ * @return A bitmask with zero or more CHRE_BLE_FILTER_CAPABILITIES_* flags set.
+ *         @see CHRE_BLE_FILTER_CAPABILITIES
+ *
+ * @since v1.6
+ */
+uint32_t chreBleGetFilterCapabilities(void);
+
+/**
+ * Helper function to extract event type from eventTypeAndDataStatus as defined
+ * in the BT Core Spec v5.2, Vol 4, Part E, Section 7.7.65.13, LE Extended
+ * Advertising Report event, entry Event_Type.
+ *
+ * @see CHRE_BLE_EVENT
+ *
+ * @param eventTypeAndDataStatus Combined event type and data status
+ *
+ * @return The event type portion of eventTypeAndDataStatus
+ */
+static inline uint8_t chreBleGetEventType(uint8_t eventTypeAndDataStatus) {
+  return (eventTypeAndDataStatus & CHRE_BLE_EVENT_MASK_TYPE);
+}
+
+/**
+ * Helper function to extract data status from eventTypeAndDataStatus as defined
+ * in the BT Core Spec v5.2, Vol 4, Part E, Section 7.7.65.13, LE Extended
+ * Advertising Report event, entry Event_Type.
+ *
+ * @see CHRE_BLE_EVENT
+ *
+ * @param eventTypeAndDataStatus Combined event type and data status
+ *
+ * @return The data status portion of eventTypeAndDataStatus
+ */
+static inline uint8_t chreBleGetDataStatus(uint8_t eventTypeAndDataStatus) {
+  return (eventTypeAndDataStatus & CHRE_BLE_EVENT_MASK_DATA_STATUS);
+}
+
+/**
+ * Helper function to to combine an event type with a data status to create
+ * eventTypeAndDataStatus as defined in the BT Core Spec v5.2, Vol 4, Part E,
+ * Section 7.7.65.13, LE Extended Advertising Report event, entry Event_Type.
+ *
+ * @see CHRE_BLE_EVENT
+ *
+ * @param eventType Event type
+ * @param dataStatus Data status
+ *
+ * @return A combined eventTypeAndDataStatus
+ */
+static inline uint8_t chreBleGetEventTypeAndDataStatus(uint8_t eventType,
+                                                       uint8_t dataStatus) {
+  return ((eventType & CHRE_BLE_EVENT_MASK_TYPE) |
+          (dataStatus & CHRE_BLE_EVENT_MASK_DATA_STATUS));
+}
+
+/**
+ * Nanoapps must define CHRE_NANOAPP_USES_BLE somewhere in their build
+ * system (e.g. Makefile) if the nanoapp needs to use the following BLE APIs.
+ * In addition to allowing access to these APIs, defining this macro will also
+ * ensure CHRE enforces that all host clients this nanoapp talks to have the
+ * required Android permissions needed to access BLE functionality by adding
+ * metadata to the nanoapp.
+ */
+#if defined(CHRE_NANOAPP_USES_BLE) || !defined(CHRE_IS_NANOAPP_BUILD)
+
+/**
+ * Start Bluetooth LE (BLE) scanning on CHRE.
+ *
+ * @see chreBleStartScanAsyncV1_9 for further details.
+ *
+ * @deprecated as of v1.9 due to the addition of the chreBleScanFilterV1_9
+ * struct and a cookie parameter. New code should use
+ * chreBleStartScanAsyncV1_9() instead of this function. This function will be
+ * removed in a future version.
+ */
+bool chreBleStartScanAsync(enum chreBleScanMode mode, uint32_t reportDelayMs,
+                           const struct chreBleScanFilter *filter);
+
+/**
+ * Start Bluetooth LE (BLE) scanning on CHRE.
+ *
+ * The result of the operation will be delivered asynchronously via the CHRE
+ * event CHRE_EVENT_BLE_ASYNC_RESULT.
+ *
+ * The scan results will be delivered asynchronously via the CHRE event
+ * CHRE_EVENT_BLE_ADVERTISEMENT.
+ *
+ * If CHRE_USER_SETTING_BLE_AVAILABLE is disabled, CHRE is expected to return an
+ * async result with error CHRE_ERROR_FUNCTION_DISABLED. If this setting is
+ * enabled, the Bluetooth subsystem may still be powered down in the scenario
+ * where the main Bluetooth toggle is disabled, but the Bluetooth scanning
+ * setting is enabled, and there is no request for BLE to be enabled at the
+ * Android level. In this scenario, CHRE will return an async result with error
+ * CHRE_ERROR_FUNCTION_DISABLED.
+ *
+ * To ensure that Bluetooth remains powered on in this settings configuration so
+ * that a nanoapp can scan, the nanoapp's Android host entity should use the
+ * BluetoothAdapter.enableBLE() API to register this request with the Android
+ * Bluetooth stack.
+ *
+ * If chreBleStartScanAsync() is called while a previous scan has been started,
+ * the previous scan will be stopped first and replaced with the new scan.
+ *
+ * Note that some corresponding Android parameters are missing from the CHRE
+ * API, where the following default or typical parameters are used:
+ * Callback type: CALLBACK_TYPE_ALL_MATCHES
+ * Result type: SCAN_RESULT_TYPE_FULL
+ * Match mode: MATCH_MODE_AGGRESSIVE
+ * Number of matches per filter: MATCH_NUM_MAX_ADVERTISEMENT
+ * Legacy-only: false
+ * PHY type: PHY_LE_ALL_SUPPORTED
+ *
+ * A CHRE_EVENT_BLE_SCAN_STATUS_CHANGE will be generated if the values in
+ * chreBleScanStatus changes as a result of this call.
+ *
+ * @param mode Scanning mode selected among enum chreBleScanMode
+ * @param reportDelayMs Maximum requested batching delay in ms. 0 indicates no
+ *                      batching. Note that the system may deliver results
+ *                      before the maximum specified delay is reached.
+ * @param filter Pointer to the requested best-effort filter configuration as
+ *               defined by struct chreBleScanFilter. The ownership of filter
+ *               and its nested elements remains with the caller, and the caller
+ *               may release it as soon as chreBleStartScanAsync() returns.
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *               sent as a response to this request.
+ *
+ * @return True to indicate that the request was accepted. False otherwise.
+ *
+ * @since v1.9
+ */
+bool chreBleStartScanAsyncV1_9(enum chreBleScanMode mode,
+                               uint32_t reportDelayMs,
+                               const struct chreBleScanFilterV1_9 *filter,
+                               const void *cookie);
+
+/**
+ * Stops a CHRE BLE scan.
+ *
+ * @see chreBleStopScanAsyncV1_9 for further details.
+ *
+ * @deprecated as of v1.9 due to the addition of the cookie parameter. New code
+ * should use chreBleStopScanAsyncV1_9() instead of this function. This function
+ * will be removed in a future version.
+ */
+bool chreBleStopScanAsync(void);
+
+/**
+ * Stops a CHRE BLE scan.
+ *
+ * The result of the operation will be delivered asynchronously via the CHRE
+ * event CHRE_EVENT_BLE_ASYNC_RESULT.
+ *
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *               sent as a response to this request.
+ *
+ * @return True to indicate that the request was accepted. False otherwise.
+ *
+ * @since v1.9
+ */
+bool chreBleStopScanAsyncV1_9(const void *cookie);
+
+/**
+ * Requests to immediately deliver batched scan results. The nanoapp must
+ * have an active BLE scan request. If a request is accepted, it will be treated
+ * as though the reportDelayMs has expired for a batched scan. Upon accepting
+ * the request, CHRE works to immediately deliver scan results currently kept in
+ * batching memory, if any, via regular CHRE_EVENT_BLE_ADVERTISEMENT events,
+ * followed by a CHRE_EVENT_BLE_FLUSH_COMPLETE event.
+ *
+ * If the underlying system fails to complete the flush operation within
+ * CHRE_BLE_FLUSH_COMPLETE_TIMEOUT_NS, CHRE will send a
+ * CHRE_EVENT_BLE_FLUSH_COMPLETE event with CHRE_ERROR_TIMEOUT.
+ *
+ * If multiple flush requests are made prior to flush completion, then the
+ * requesting nanoapp will receive all batched samples existing at the time of
+ * the latest flush request. In this case, the number of
+ * CHRE_EVENT_BLE_FLUSH_COMPLETE events received must equal the number of flush
+ * requests made.
+ *
+ * If chreBleStopScanAsync() is called while a flush operation is in progress,
+ * it is unspecified whether the flush operation will complete successfully or
+ * return an error, such as CHRE_ERROR_FUNCTION_DISABLED, but in any case,
+ * CHRE_EVENT_BLE_FLUSH_COMPLETE must still be delivered. The same applies if
+ * the Bluetooth user setting is disabled during a flush operation.
+ *
+ * If called while running on a CHRE API version below v1.7, this function
+ * returns false and has no effect.
+ *
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *               sent as a response to this request.
+ *
+ * @return True to indicate the request was accepted. False otherwise.
+ *
+ * @since v1.7
+ */
+bool chreBleFlushAsync(const void *cookie);
+
+/**
+ * Requests to read the RSSI of a peer device on the given LE connection
+ * handle.
+ *
+ * If the request is accepted, the response will be delivered in a
+ * CHRE_EVENT_BLE_RSSI_READ event with the same cookie.
+ *
+ * The request may be rejected if resources are not available to service the
+ * request (such as if too many outstanding requests already exist). If so, the
+ * client may retry later.
+ *
+ * Note that the connectionHandle is valid only while the connection remains
+ * active. If a peer device disconnects then reconnects, the handle may change.
+ * BluetoothDevice#getConnectionHandle() can be used from the Android framework
+ * to get the latest handle upon reconnection.
+ *
+ * @param connectionHandle
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *               embedded in the response to this request.
+ * @return True if the request has been accepted and dispatched to the
+ *         controller. False otherwise.
+ *
+ * @since v1.8
+ *
+ */
+bool chreBleReadRssiAsync(uint16_t connectionHandle, const void *cookie);
+
+/**
+ * Retrieves the current state of the BLE scan on the platform.
+ *
+ * @param status A non-null pointer to where the scan status will be
+ *               populated.
+ *
+ * @return True if the status was obtained successfully.
+ *
+ * @since v1.8
+ */
+bool chreBleGetScanStatus(struct chreBleScanStatus *status);
+
+/**
+ * Accepts transfer of ownership of a connected socket and subscribes to
+ * CHRE_EVENT_BLE_SOCKET_PACKET events for this socket. This API is only
+ * valid to call while handling the CHRE_EVENT_BLE_SOCKET_CONNECTION event.
+ *
+ * @param socketId ID passed in chreBleSocketConnectionEvent.socketId
+ * @return True if CHRE confirms that socket ownership has been transferred.
+ *
+ * @since v1.11
+ */
+bool chreBleSocketAccept(uint64_t socketId);
+
+/**
+ * Sends a packet to the socket with the corresponding socketId. This API can
+ * only be used after the nanoapp has received a
+ * CHRE_EVENT_BLE_SOCKET_CONNECTION event indicating the offloaded socket is
+ * connected and has accepted ownership of the socket by calling
+ * chreBleSocketAccept().
+ *
+ * NOTE: freeCallback WILL NOT be invoked if the return status is
+ * CHRE_BLE_SOCKET_SEND_STATUS_QUEUE_FULL.
+ *
+ * @param socketId @see chreBleSocketConnectionEvent.socketId
+ * @param data Packet to be sent to the socket that is length bytes. After this
+ *     API is called, ownership of this memory passes to CHRE and the nanoapp
+ *     must ensure that the packet remains valid and unmodified until the
+ *     freeCallback is invoked.
+  * @param length Length of packet to be sent to the socket in bytes. Cannot
+ *     exceed the maxTxPacketLength provided in the CHRE event
+ *     CHRE_EVENT_BLE_SOCKET_CONNECTION.
+ * @param freeCallback Callback invoked to indicate that the packet data buffer
+ *     is not needed by CHRE anymore. Note that invocation of this function does
+ *     not mean that the packet has been delivered, only that memory can be
+ *     released. This is guaranteed to be invoked if this function returns
+ *     CHRE_BLE_SOCKET_SEND_STATUS_SUCCESS or
+ *     CHRE_BLE_SOCKET_SEND_STATUS_FAILURE, but WILL NOT be invoked for
+ *     CHRE_BLE_SOCKET_SEND_STATUS_QUEUE_FULL. This may be invoked
+ *     synchronously, so nanoapp developers should not call chreBleSocketSend()
+ *     from within the callback to avoid potential infinite recursion.
+ * @return A value from enum chreBleSocketSendStatus.
+ *
+ * @since v1.11
+ */
+int32_t chreBleSocketSend(uint64_t socketId, const void *data, uint16_t length,
+                          chreBleSocketPacketFreeFunction *freeCallback);
+
+/**
+ * Definitions for handling unsupported CHRE BLE scenarios.
+ */
+#else  // defined(CHRE_NANOAPP_USES_BLE) || !defined(CHRE_IS_NANOAPP_BUILD)
+
+#define CHRE_BLE_PERM_ERROR_STRING                                       \
+  "CHRE_NANOAPP_USES_BLE must be defined when building this nanoapp in " \
+  "order to refer to "
+
+#define chreBleStartScanAsync(...) \
+  CHRE_BUILD_ERROR(CHRE_BLE_PERM_ERROR_STRING "chreBleStartScanAsync")
+
+#define chreBleStopScanAsync(...) \
+  CHRE_BUILD_ERROR(CHRE_BLE_PERM_ERROR_STRING "chreBleStopScanAsync")
+
+#define chreBleFlushAsync(...) \
+  CHRE_BUILD_ERROR(CHRE_BLE_PERM_ERROR_STRING "chreBleFlushAsync")
+
+#define chreBleReadRssiAsync(...) \
+  CHRE_BUILD_ERROR(CHRE_BLE_PERM_ERROR_STRING "chreBleReadRssiAsync")
+
+#define chreBleGetScanStatus(...) \
+  CHRE_BUILD_ERROR(CHRE_BLE_PERM_ERROR_STRING "chreBleGetScanStatus")
+
+#define chreBleSocketAccept(...) \
+  CHRE_BUILD_ERROR(CHRE_BLE_PERM_ERROR_STRING "chreBleSocketAccept")
+
+#define chreBleSocketSend(...) \
+  CHRE_BUILD_ERROR(CHRE_BLE_PERM_ERROR_STRING "chreBleSocketSend")
+
+#endif  // defined(CHRE_NANOAPP_USES_BLE) || !defined(CHRE_IS_NANOAPP_BUILD)
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif /* CHRE_BLE_H_ */
diff --git a/chre_api/legacy/v1_11/chre/common.h b/chre_api/legacy/v1_11/chre/common.h
new file mode 100644
index 00000000..61214fcf
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/common.h
@@ -0,0 +1,208 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_COMMON_H_
+#define _CHRE_COMMON_H_
+
+/**
+ * @file
+ * Definitions shared across multiple CHRE header files
+ */
+
+#include <stdbool.h>
+#include <stdint.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * Mask of the 5 most significant bytes in a 64-bit nanoapp or CHRE platform
+ * identifier, which represents the vendor ID portion of the ID.
+ */
+#define CHRE_VENDOR_ID_MASK  UINT64_C(0xFFFFFFFFFF000000)
+
+/**
+ * Vendor ID "Googl".  Used in nanoapp IDs and CHRE platform IDs developed and
+ * released by Google.
+ */
+#define CHRE_VENDOR_ID_GOOGLE  UINT64_C(0x476F6F676C000000)
+
+/**
+ * Vendor ID "GoogT".  Used for nanoapp IDs associated with testing done by
+ * Google.
+ */
+#define CHRE_VENDOR_ID_GOOGLE_TEST  UINT64_C(0x476F6F6754000000)
+
+/**
+ * Helper macro to mask off all bytes other than the vendor ID (most significant
+ * 5 bytes) in 64-bit nanoapp and CHRE platform identifiers.
+ *
+ * @see chreGetNanoappInfo()
+ * @see chreGetPlatformId()
+ */
+#define CHRE_EXTRACT_VENDOR_ID(id)  ((id) & CHRE_VENDOR_ID_MASK)
+
+/**
+ * Number of nanoseconds in one second, represented as an unsigned 64-bit
+ * integer
+ */
+#define CHRE_NSEC_PER_SEC  UINT64_C(1000000000)
+
+/**
+ * General timeout for asynchronous API requests. Unless specified otherwise, a
+ * function call that returns data asynchronously via an event, such as
+ * CHRE_EVENT_ASYNC_GNSS_RESULT, must do so within this amount of time.
+ */
+#define CHRE_ASYNC_RESULT_TIMEOUT_NS  (5 * CHRE_NSEC_PER_SEC)
+
+/**
+ * A generic listing of error codes for use in {@link #chreAsyncResult} and
+ * elsewhere. In general, module-specific error codes may be added to this enum,
+ * but effort should be made to come up with a generic name that still captures
+ * the meaning of the error.
+ */
+// LINT.IfChange
+enum chreError {
+    //! No error occurred
+    CHRE_ERROR_NONE = 0,
+
+    //! An unspecified failure occurred
+    CHRE_ERROR = 1,
+
+    //! One or more supplied arguments are invalid
+    CHRE_ERROR_INVALID_ARGUMENT = 2,
+
+    //! Unable to satisfy request because the system is busy
+    CHRE_ERROR_BUSY = 3,
+
+    //! Unable to allocate memory
+    CHRE_ERROR_NO_MEMORY = 4,
+
+    //! The requested feature is not supported
+    CHRE_ERROR_NOT_SUPPORTED = 5,
+
+    //! A timeout occurred while processing the request
+    CHRE_ERROR_TIMEOUT = 6,
+
+    //! The relevant capability is disabled, for example due to a user
+    //! configuration that takes precedence over this request
+    CHRE_ERROR_FUNCTION_DISABLED = 7,
+
+    //! The request was rejected due to internal rate limiting of the requested
+    //! functionality - the client may try its request again after waiting an
+    //! unspecified amount of time
+    CHRE_ERROR_REJECTED_RATE_LIMIT = 8,
+
+    //! The requested functionality is not currently accessible from the CHRE,
+    //! because another client, such as the main applications processor, is
+    //! currently controlling it.
+    CHRE_ERROR_FUNCTION_RESTRICTED_TO_OTHER_MASTER = 9,
+    CHRE_ERROR_FUNCTION_RESTRICTED_TO_OTHER_CLIENT = 9,
+
+    //! This request is no longer valid. It may have been replaced by a newer
+    //! request before taking effect.
+    //! @since v1.6
+    CHRE_ERROR_OBSOLETE_REQUEST = 10,
+
+    //! A transient error occurred. The request can be retried.
+    //! @since v1.10
+    CHRE_ERROR_TRANSIENT = 11,
+
+    //! Unable to satisfy request because of missing permissions.
+    //! @since v1.10
+    CHRE_ERROR_PERMISSION_DENIED = 12,
+
+    //! Unable to satisfy request because the destination is not found.
+    //! @since v1.10
+    CHRE_ERROR_DESTINATION_NOT_FOUND = 13,
+
+    //!< Do not exceed this value when adding new error codes
+    CHRE_ERROR_LAST = UINT8_MAX,
+};
+// LINT.ThenChange(../../../../util/include/chre/util/system/chre_error_util.h)
+
+/**
+ * Generic data structure to indicate the result of an asynchronous operation.
+ *
+ * @note
+ * The general model followed by CHRE for asynchronous operations is that a
+ * request function returns a boolean value that indicates whether the request
+ * was accepted for further processing. The actual result of the operation is
+ * provided in a subsequent event sent with an event type that is defined in the
+ * specific API. Typically, a "cookie" parameter is supplied to allow the client
+ * to tie the response to a specific request, or pass data through, etc. The
+ * response is expected to be delivered within CHRE_ASYNC_RESULT_TIMEOUT_NS if
+ * not specified otherwise.
+ *
+ * The CHRE implementation must allow for multiple asynchronous requests to be
+ * outstanding at a given time, under reasonable resource constraints. Further,
+ * requests must be processed in the same order as supplied by the client of the
+ * API in order to maintain causality. Using GNSS as an example, if a client
+ * calls chreGnssLocationSessionStartAsync() and then immediately calls
+ * chreGnssLocationSessionStopAsync(), the final result must be that the
+ * location session is stopped. Whether requests always complete in the
+ * order that they are given is implementation-defined. For example, if a client
+ * calls chreGnssLocationSessionStart() and then immediately calls
+ * chreGnssMeasurementSessionStart(), it is possible for the
+ * CHRE_EVENT_GNSS_RESULT associated with the measurement session to be
+ * delivered before the one for the location session.
+ */
+struct chreAsyncResult {
+    //! Indicates the request associated with this result. The interpretation of
+    //! values in this field is dependent upon the event type provided when this
+    //! result was delivered.
+    uint8_t requestType;
+
+    //! Set to true if the request was successfully processed
+    bool success;
+
+    //! If the request failed (success is false), this is set to a value from
+    //! enum chreError (other than CHRE_ERROR_NONE), which may provide
+    //! additional information about the nature of the failure.
+    //! @see #chreError
+    uint8_t errorCode;
+
+    //! Reserved for future use, set to 0
+    uint8_t reserved;
+
+    //! Set to the cookie parameter given to the request function tied to this
+    //! result
+    const void *cookie;
+};
+
+/**
+ * A structure to store an event describing the end of batched events.
+ *
+ * @since v1.8
+ */
+struct chreBatchCompleteEvent {
+    //! Indicates the type of event (of type CHRE_EVENT_TYPE_*) that was
+    //! batched.
+    uint16_t eventType;
+
+    //! Reserved for future use, set to 0
+    uint8_t reserved[2];
+};
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif /* _CHRE_COMMON_H_ */
diff --git a/chre_api/legacy/v1_11/chre/event.h b/chre_api/legacy/v1_11/chre/event.h
new file mode 100644
index 00000000..e9cc30ac
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/event.h
@@ -0,0 +1,1065 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_EVENT_H_
+#define _CHRE_EVENT_H_
+
+/**
+ * @file
+ * Context Hub Runtime Environment API dealing with events and messages.
+ */
+
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <stdlib.h>
+
+#include <chre/common.h>
+#include <chre/toolchain.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * The CHRE implementation is required to provide the following preprocessor
+ * defines via the build system.
+ *
+ * CHRE_MESSAGE_TO_HOST_MAX_SIZE: The maximum size, in bytes, allowed for
+ *     a message sent to chreSendMessageToHostEndpoint().  This must be at least
+ *     CHRE_MESSAGE_TO_HOST_MINIMUM_MAX_SIZE. If the system supports a larger
+ *     maximum size, it will be defined as the return value of
+ *     chreGetMessageToHostMaxSize().
+ */
+#ifndef CHRE_MESSAGE_TO_HOST_MAX_SIZE
+#error CHRE_MESSAGE_TO_HOST_MAX_SIZE must be defined by the CHRE implementation
+#endif
+
+/**
+ * The minimum size, in bytes, any CHRE implementation will use for
+ * CHRE_MESSAGE_TO_HOST_MAX_SIZE is set to 1000 for v1.5+ CHRE implementations,
+ * and 128 for v1.0-v1.4 implementations (previously kept in
+ * CHRE_MESSAGE_TO_HOST_MINIMUM_MAX_SIZE, which has been removed).
+ *
+ * All CHRE implementations supporting v1.5+ must support the raised limit of
+ * 1000 bytes, however a nanoapp compiled against v1.5 cannot assume this
+ * limit if there is a possibility their binary will run on a v1.4 or earlier
+ * implementation that had a lower limit. To allow for nanoapp compilation in
+ * these situations, CHRE_MESSAGE_TO_HOST_MAX_SIZE must be set to the minimum
+ * value the nanoapp may encounter, and CHRE_NANOAPP_SUPPORTS_PRE_V1_5 can be
+ * defined to skip the compile-time check.
+ */
+#if (!defined(CHRE_NANOAPP_SUPPORTS_PRE_V1_5) && \
+     CHRE_MESSAGE_TO_HOST_MAX_SIZE < 1000) ||    \
+    (defined(CHRE_NANOAPP_SUPPORTS_PRE_V1_5) &&  \
+     CHRE_MESSAGE_TO_HOST_MAX_SIZE < 128)
+#error CHRE_MESSAGE_TO_HOST_MAX_SIZE is too small.
+#endif
+
+/**
+ * CHRE_MESSAGE_TO_HOST_MAX_SIZE must be less than or equal to 4096. If the system
+ * supports a larger maximum size, it will be defined as the return value of
+ * chreGetMessageToHostMaxSize().
+ */
+#if CHRE_MESSAGE_TO_HOST_MAX_SIZE > 4096
+#error CHRE_MESSAGE_TO_HOST_MAX_SIZE must be <= 4096
+#endif
+
+/**
+ * The lowest numerical value legal for a user-defined event.
+ *
+ * The system reserves all event values from 0 to 0x7FFF, inclusive.
+ * User events may use any value in the range 0x8000 to 0xFFFF, inclusive.
+ *
+ * Note that the same event values might be used by different nanoapps
+ * for different meanings.  This is not a concern, as these values only
+ * have meaning when paired with the originating nanoapp.
+ */
+#define CHRE_EVENT_FIRST_USER_VALUE  UINT16_C(0x8000)
+
+/**
+ * nanoappHandleEvent argument: struct chreMessageFromHostData
+ *
+ * The format of the 'message' part of this structure is left undefined,
+ * and it's up to the nanoapp and host to have an established protocol
+ * beforehand.
+ */
+#define CHRE_EVENT_MESSAGE_FROM_HOST  UINT16_C(0x0001)
+
+/**
+ * nanoappHandleEvent argument: 'cookie' given to chreTimerSet() method.
+ *
+ * Indicates that a timer has elapsed, in accordance with how chreTimerSet() was
+ * invoked.
+ */
+#define CHRE_EVENT_TIMER  UINT16_C(0x0002)
+
+/**
+ * nanoappHandleEvent argument: struct chreNanoappInfo
+ *
+ * Indicates that a nanoapp has successfully started (its nanoappStart()
+ * function has been called, and it returned true) and is able to receive events
+ * sent via chreSendEvent().  Note that this event is not sent for nanoapps that
+ * were started prior to the current nanoapp - use chreGetNanoappInfo() to
+ * determine if another nanoapp is already running.
+ *
+ * @see chreConfigureNanoappInfoEvents
+ * @since v1.1
+ */
+#define CHRE_EVENT_NANOAPP_STARTED  UINT16_C(0x0003)
+
+/**
+ * nanoappHandleEvent argument: struct chreNanoappInfo
+ *
+ * Indicates that a nanoapp has stopped executing and is no longer able to
+ * receive events sent via chreSendEvent().  Any events sent prior to receiving
+ * this event are not guaranteed to have been delivered.
+ *
+ * @see chreConfigureNanoappInfoEvents
+ * @since v1.1
+ */
+#define CHRE_EVENT_NANOAPP_STOPPED  UINT16_C(0x0004)
+
+/**
+ * nanoappHandleEvent argument: NULL
+ *
+ * Indicates that CHRE has observed the host wake from low-power sleep state.
+ *
+ * @see chreConfigureHostSleepStateEvents
+ * @since v1.2
+ */
+#define CHRE_EVENT_HOST_AWAKE  UINT16_C(0x0005)
+
+/**
+ * nanoappHandleEvent argument: NULL
+ *
+ * Indicates that CHRE has observed the host enter low-power sleep state.
+ *
+ * @see chreConfigureHostSleepStateEvents
+ * @since v1.2
+ */
+#define CHRE_EVENT_HOST_ASLEEP  UINT16_C(0x0006)
+
+/**
+ * nanoappHandleEvent argument: NULL
+ *
+ * Indicates that CHRE is collecting debug dumps. Nanoapps can call
+ * chreDebugDumpLog() to log their debug data while handling this event.
+ *
+ * @see chreConfigureDebugDumpEvent
+ * @see chreDebugDumpLog
+ * @since v1.4
+ */
+#define CHRE_EVENT_DEBUG_DUMP  UINT16_C(0x0007)
+
+/**
+ * nanoappHandleEvent argument: struct chreHostEndpointNotification
+ *
+ * Notifications event regarding a host endpoint.
+ *
+ * @see chreConfigureHostEndpointNotifications
+ * @since v1.6
+ */
+#define CHRE_EVENT_HOST_ENDPOINT_NOTIFICATION UINT16_C(0x0008)
+
+/**
+ * Indicates a RPC request from a nanoapp.
+ *
+ * @since v1.9
+ */
+#define CHRE_EVENT_RPC_REQUEST UINT16_C(0x00009)
+
+/**
+ * Indicates a RPC response from a nanoapp.
+ *
+ * @since v1.9
+ */
+#define CHRE_EVENT_RPC_RESPONSE UINT16_C(0x0000A)
+
+/**
+ * nanoappHandleEvent argument: struct chreAsyncResult
+ *
+ * Async status for reliable messages. The resultType field
+ * will be populated with a value of 0.
+ *
+ * @see chreSendReliableMessageAsync
+ * @since v1.10
+ */
+#define CHRE_EVENT_RELIABLE_MSG_ASYNC_RESULT UINT16_C(0x000B)
+
+/**
+ * First possible value for CHRE_EVENT_SENSOR events.
+ *
+ * This allows us to separately define our CHRE_EVENT_SENSOR_* events in
+ * chre/sensor.h, without fear of collision with other event values.
+ */
+#define CHRE_EVENT_SENSOR_FIRST_EVENT  UINT16_C(0x0100)
+
+/**
+ * Last possible value for CHRE_EVENT_SENSOR events.
+ *
+ * This allows us to separately define our CHRE_EVENT_SENSOR_* events in
+ * chre/sensor.h, without fear of collision with other event values.
+ */
+#define CHRE_EVENT_SENSOR_LAST_EVENT  UINT16_C(0x02FF)
+
+/**
+ * First event in the block reserved for GNSS. These events are defined in
+ * chre/gnss.h.
+ */
+#define CHRE_EVENT_GNSS_FIRST_EVENT  UINT16_C(0x0300)
+#define CHRE_EVENT_GNSS_LAST_EVENT   UINT16_C(0x030F)
+
+/**
+ * First event in the block reserved for WiFi. These events are defined in
+ * chre/wifi.h.
+ */
+#define CHRE_EVENT_WIFI_FIRST_EVENT  UINT16_C(0x0310)
+#define CHRE_EVENT_WIFI_LAST_EVENT   UINT16_C(0x031F)
+
+/**
+ * First event in the block reserved for WWAN. These events are defined in
+ * chre/wwan.h.
+ */
+#define CHRE_EVENT_WWAN_FIRST_EVENT  UINT16_C(0x0320)
+#define CHRE_EVENT_WWAN_LAST_EVENT   UINT16_C(0x032F)
+
+/**
+ * First event in the block reserved for audio. These events are defined in
+ * chre/audio.h.
+ */
+#define CHRE_EVENT_AUDIO_FIRST_EVENT UINT16_C(0x0330)
+#define CHRE_EVENT_AUDIO_LAST_EVENT  UINT16_C(0x033F)
+
+/**
+ * First event in the block reserved for settings changed notifications.
+ * These events are defined in chre/user_settings.h
+ *
+ * @since v1.5
+ */
+#define CHRE_EVENT_SETTING_CHANGED_FIRST_EVENT UINT16_C(0x340)
+#define CHRE_EVENT_SETTING_CHANGED_LAST_EVENT  UINT16_C(0x34F)
+
+/**
+ * First event in the block reserved for Bluetooth LE. These events are defined
+ * in chre/ble.h.
+ */
+#define CHRE_EVENT_BLE_FIRST_EVENT UINT16_C(0x0350)
+#define CHRE_EVENT_BLE_LAST_EVENT  UINT16_C(0x035F)
+
+/**
+ * First event in the block reserved for session-based messaging. These events
+ * are defined in chre/msg.h.
+ */
+#define CHRE_EVENT_MSG_FIRST_EVENT UINT16_C(0x0360)
+#define CHRE_EVENT_MSG_LAST_EVENT UINT16_C(0x036F)
+
+/**
+ * First in the extended range of values dedicated for internal CHRE
+ * implementation usage.
+ *
+ * This range is semantically the same as the internal event range defined
+ * below, but has been extended to allow for more implementation-specific events
+ * to be used.
+ *
+ * @since v1.1
+ */
+#define CHRE_EVENT_INTERNAL_EXTENDED_FIRST_EVENT  UINT16_C(0x7000)
+
+/**
+ * First in a range of values dedicated for internal CHRE implementation usage.
+ *
+ * If a CHRE wishes to use events internally, any values within this range
+ * are assured not to be taken by future CHRE API additions.
+ */
+#define CHRE_EVENT_INTERNAL_FIRST_EVENT  UINT16_C(0x7E00)
+
+/**
+ * Last in a range of values dedicated for internal CHRE implementation usage.
+ *
+ * If a CHRE wishes to use events internally, any values within this range
+ * are assured not to be taken by future CHRE API additions.
+ */
+#define CHRE_EVENT_INTERNAL_LAST_EVENT  UINT16_C(0x7FFF)
+
+/**
+ * A special value for the hostEndpoint argument in
+ * chreSendMessageToHostEndpoint() that indicates that the message should be
+ * delivered to all host endpoints.  This value will not be used in the
+ * hostEndpoint field of struct chreMessageFromHostData supplied with
+ * CHRE_EVENT_MESSAGE_FROM_HOST.
+ *
+ * @since v1.1
+ */
+#define CHRE_HOST_ENDPOINT_BROADCAST  UINT16_C(0xFFFF)
+
+/**
+ * A special value for hostEndpoint in struct chreMessageFromHostData that
+ * indicates that a host endpoint is unknown or otherwise unspecified.  This
+ * value may be received in CHRE_EVENT_MESSAGE_FROM_HOST, but it is not valid to
+ * provide it to chreSendMessageToHostEndpoint().
+ *
+ * @since v1.1
+ */
+#define CHRE_HOST_ENDPOINT_UNSPECIFIED  UINT16_C(0xFFFE)
+
+/**
+ * Bitmask values that can be given as input to the messagePermissions parameter
+ * of chreSendMessageWithPermissions(). These values are typically used by
+ * nanoapps when they used data from the corresponding CHRE APIs to produce the
+ * message contents being sent and is used to attribute permissions usage on
+ * the Android side. See chreSendMessageWithPermissions() for more details on
+ * how these values are used when sending a message.
+ *
+ * Values in the range
+ * [CHRE_MESSAGE_PERMISSION_VENDOR_START, CHRE_MESSAGE_PERMISSION_VENDOR_END]
+ * are reserved for vendors to use when adding support for permission-gated APIs
+ * in their implementations.
+ *
+ * On the Android side, CHRE permissions are mapped as follows:
+ * - CHRE_MESSAGE_PERMISSION_AUDIO: android.permission.RECORD_AUDIO
+ * - CHRE_MESSAGE_PERMISSION_GNSS, CHRE_MESSAGE_PERMISSION_WIFI, and
+ *   CHRE_MESSAGE_PERMISSION_WWAN: android.permission.ACCESS_FINE_LOCATION, and
+ *   android.permissions.ACCESS_BACKGROUND_LOCATION
+ *
+ * @since v1.5
+ *
+ * @defgroup CHRE_MESSAGE_PERMISSION
+ * @{
+ */
+
+#define CHRE_MESSAGE_PERMISSION_NONE UINT32_C(0)
+#define CHRE_MESSAGE_PERMISSION_AUDIO UINT32_C(1)
+#define CHRE_MESSAGE_PERMISSION_GNSS (UINT32_C(1) << 1)
+#define CHRE_MESSAGE_PERMISSION_WIFI (UINT32_C(1) << 2)
+#define CHRE_MESSAGE_PERMISSION_WWAN (UINT32_C(1) << 3)
+#define CHRE_MESSAGE_PERMISSION_BLE (UINT32_C(1) << 4)
+#define CHRE_MESSAGE_PERMISSION_VENDOR_START (UINT32_C(1) << 24)
+#define CHRE_MESSAGE_PERMISSION_VENDOR_END (UINT32_C(1) << 31)
+
+/** @} */
+
+/**
+ * Reserved message type for RPC messages.
+ *
+ * @see chreSendMessageWithPermissions
+ *
+ * @since v1.9
+ */
+#define CHRE_MESSAGE_TYPE_RPC UINT32_C(0x7FFFFFF5)
+
+/**
+ * @see chrePublishRpcServices
+ *
+ * @since v1.8
+ */
+#define CHRE_MINIMUM_RPC_SERVICE_LIMIT UINT8_C(4)
+
+/**
+ * Data provided with CHRE_EVENT_MESSAGE_FROM_HOST.
+ */
+struct chreMessageFromHostData {
+    /**
+     * Message type supplied by the host.
+     *
+     * @note In CHRE API v1.0, support for forwarding this field from the host
+     * was not strictly required, and some implementations did not support it.
+     * However, its support is mandatory as of v1.1.
+     */
+    union {
+        /**
+         * The preferred name to use when referencing this field.
+         *
+         * @since v1.1
+         */
+        uint32_t messageType;
+
+        /**
+         * @deprecated This is the name for the messageType field used in v1.0.
+         * Left to allow code to compile against both v1.0 and v1.1 of the API
+         * definition without needing to use #ifdefs. This will be removed in a
+         * future API update - use messageType instead.
+         */
+        uint32_t reservedMessageType;
+    };
+
+    /**
+     * The size, in bytes of the following 'message'.
+     *
+     * This can be 0.
+     */
+    uint32_t messageSize;
+
+    /**
+     * The message from the host.
+     *
+     * These contents are of a format that the host and nanoapp must have
+     * established beforehand.
+     *
+     * This data is 'messageSize' bytes in length.  Note that if 'messageSize'
+     * is 0, this might be NULL.
+     */
+    const void *message;
+
+    /**
+     * An identifier for the host-side entity that sent this message.  Unless
+     * this is set to CHRE_HOST_ENDPOINT_UNSPECIFIED, it can be used in
+     * chreSendMessageToHostEndpoint() to send a directed reply that will only
+     * be received by the given entity on the host.  Endpoint identifiers are
+     * opaque values assigned at runtime, so they cannot be assumed to always
+     * describe a specific entity across restarts.
+     *
+     * If running on a CHRE API v1.0 implementation, this field will always be
+     * set to CHRE_HOST_ENDPOINT_UNSPECIFIED.
+     *
+     * @since v1.1
+     */
+    uint16_t hostEndpoint;
+};
+
+/**
+ * Provides metadata for a nanoapp in the system.
+ */
+struct chreNanoappInfo {
+    /**
+     * Nanoapp identifier. The convention for populating this value is to set
+     * the most significant 5 bytes to a value that uniquely identifies the
+     * vendor, and the lower 3 bytes identify the nanoapp.
+     */
+    uint64_t appId;
+
+    /**
+     * Nanoapp version.  The semantics of this field are defined by the nanoapp,
+     * however nanoapps are recommended to follow the same scheme used for the
+     * CHRE version exposed in chreGetVersion().  That is, the most significant
+     * byte represents the major version, the next byte the minor version, and
+     * the lower two bytes the patch version.
+     */
+    uint32_t version;
+
+    /**
+     * The instance ID of this nanoapp, which can be used in chreSendEvent() to
+     * address an event specifically to this nanoapp.  This identifier is
+     * guaranteed to be unique among all nanoapps in the system.
+     *
+     * As of CHRE API v1.6, instance ID is guaranteed to never be greater than
+     * UINT16_MAX. This allows for the instance ID be packed with other data
+     * inside a 32-bit integer (useful for RPC routing).
+     */
+    uint32_t instanceId;
+
+    /**
+     * Reserved for future use.
+     * Always set to 0.
+     */
+    uint8_t reserved[3];
+
+    /**
+     * The number of RPC services exposed by this nanoapp.
+     * The service details are available in the rpcServices array.
+     * Must always be set to 0 when running on a CHRE implementation prior to
+     * v1.8
+     *
+     * @since v1.8
+     */
+    uint8_t rpcServiceCount;
+
+    /**
+     * Array of RPC services published by this nanoapp.
+     * Services are published via chrePublishRpcServices.
+     * The array contains rpcServiceCount entries.
+     *
+     * The pointer is only valid when rpcServiceCount is greater than 0.
+     *
+     * @since v1.8
+     */
+    const struct chreNanoappRpcService *rpcServices;
+};
+
+/**
+ * The types of notification events that can be included in struct
+ * chreHostEndpointNotification.
+ *
+ * @defgroup HOST_ENDPOINT_NOTIFICATION_TYPE
+ * @{
+ */
+#define HOST_ENDPOINT_NOTIFICATION_TYPE_DISCONNECT UINT8_C(0)
+/** @} */
+
+/**
+ * Data provided in CHRE_EVENT_HOST_ENDPOINT_NOTIFICATION.
+ */
+struct chreHostEndpointNotification {
+    /**
+     * The ID of the host endpoint that this notification is for.
+     */
+    uint16_t hostEndpointId;
+
+    /**
+     * The type of notification this event represents, which should be
+     * one of the HOST_ENDPOINT_NOTIFICATION_TYPE_* values.
+     */
+    uint8_t notificationType;
+
+    /**
+     * Reserved for future use, must be zero.
+     */
+    uint8_t reserved;
+};
+
+//! The maximum length of a host endpoint's name.
+#define CHRE_MAX_ENDPOINT_NAME_LEN (51)
+
+//! The maximum length of a host endpoint's tag.
+#define CHRE_MAX_ENDPOINT_TAG_LEN (51)
+
+/**
+ * The type of host endpoint that can be used in the hostEndpointType field
+ * of chreHostEndpointInfo.
+ *
+ * @since v1.6
+ *
+ * @defgroup CHRE_HOST_ENDPOINT_TYPE_
+ * @{
+ */
+
+//! The host endpoint is part of the Android system framework.
+#define CHRE_HOST_ENDPOINT_TYPE_FRAMEWORK UINT8_C(0x00)
+
+//! The host endpoint is an Android app.
+#define CHRE_HOST_ENDPOINT_TYPE_APP UINT8_C(0x01)
+
+//! The host endpoint is an Android native program.
+#define CHRE_HOST_ENDPOINT_TYPE_NATIVE UINT8_C(0x02)
+
+//! Values in the range [CHRE_HOST_ENDPOINT_TYPE_VENDOR_START,
+//! CHRE_HOST_ENDPOINT_TYPE_VENDOR_END] can be a custom defined host endpoint
+//! type for platform-specific vendor use.
+#define CHRE_HOST_ENDPOINT_TYPE_VENDOR_START UINT8_C(0x80)
+#define CHRE_HOST_ENDPOINT_TYPE_VENDOR_END UINT8_C(0xFF)
+
+/** @} */
+
+/**
+ * Provides metadata for a host endpoint.
+ *
+ * @since v1.6
+ */
+struct chreHostEndpointInfo {
+    //! The endpoint ID of this host.
+    uint16_t hostEndpointId;
+
+    //! The type of host endpoint, which must be set to one of the
+    //! CHRE_HOST_ENDPOINT_TYPE_* values or a value in the vendor-reserved
+    //! range.
+    uint8_t hostEndpointType;
+
+    //! Flag indicating if the packageName/endpointName field is valid.
+    uint8_t isNameValid : 1;
+
+    //! Flag indicating if the attributionTag/endpointTag field is valid.
+    uint8_t isTagValid : 1;
+
+    //! A union of null-terminated host name strings.
+    union {
+        //! The Android package name associated with this host, valid if the
+        //! hostEndpointType is CHRE_HOST_ENDPOINT_TYPE_APP or
+        //! CHRE_HOST_ENDPOINT_TYPE_FRAMEWORK. Refer to the Android documentation
+        //! for the package attribute in the app manifest.
+        char packageName[CHRE_MAX_ENDPOINT_NAME_LEN];
+
+        //! A generic endpoint name that can be used for endpoints that
+        //! may not have a package name.
+        char endpointName[CHRE_MAX_ENDPOINT_NAME_LEN];
+    };
+
+    //! A union of null-terminated host tag strings for further identification.
+    union {
+        //! The attribution tag associated with this host that is used to audit
+        //! access to data, which can be valid if the hostEndpointType is
+        //! CHRE_HOST_ENDPOINT_TYPE_APP. Refer to the Android documentation
+        //! regarding data audit using attribution tags.
+        char attributionTag[CHRE_MAX_ENDPOINT_TAG_LEN];
+
+        //! A generic endpoint tag that can be used for endpoints that
+        //! may not have an attribution tag.
+        char endpointTag[CHRE_MAX_ENDPOINT_TAG_LEN];
+    };
+};
+
+/**
+ * An RPC service exposed by a nanoapp.
+ *
+ * The implementation of the RPC interface is not defined by the HAL, and is written
+ * at the messaging endpoint layers (Android app and/or CHRE nanoapp). NanoappRpcService
+ * contains the informational metadata to be consumed by the RPC interface layer.
+ */
+struct chreNanoappRpcService {
+    /**
+     * The unique 64-bit ID of an RPC service exposed by a nanoapp. Note that
+     * the uniqueness is only required within the nanoapp's domain (i.e. the
+     * combination of the nanoapp ID and service id must be unique).
+     */
+    uint64_t id;
+
+    /**
+     * The software version of this service, which follows the sematic
+     * versioning scheme (see semver.org). It follows the format
+     * major.minor.patch, where major and minor versions take up one byte
+     * each, and the patch version takes up the final 2 bytes.
+     */
+    uint32_t version;
+};
+
+/**
+ * Callback which frees data associated with an event.
+ *
+ * This callback is (optionally) provided to the chreSendEvent() method as
+ * a means for freeing the event data and performing any other cleanup
+ * necessary when the event is completed.  When this callback is invoked,
+ * 'eventData' is no longer needed and can be released.
+ *
+ * @param eventType  The 'eventType' argument from chreSendEvent().
+ * @param eventData  The 'eventData' argument from chreSendEvent().
+ *
+ * @see chreSendEvent
+ */
+typedef void (chreEventCompleteFunction)(uint16_t eventType, void *eventData);
+
+/**
+ * Callback which frees a message.
+ *
+ * This callback is (optionally) provided to the chreSendMessageToHostEndpoint()
+ * method as a means for freeing the message.  When this callback is invoked,
+ * 'message' is no longer needed and can be released.  Note that this in
+ * no way assures that said message did or did not make it to the host, simply
+ * that this memory is no longer needed.
+ *
+ * @param message  The 'message' argument from chreSendMessageToHostEndpoint().
+ * @param messageSize  The 'messageSize' argument from
+ *     chreSendMessageToHostEndpoint().
+ *
+ * @see chreSendMessageToHostEndpoint
+ */
+typedef void (chreMessageFreeFunction)(void *message, size_t messageSize);
+
+
+/**
+ * Enqueue an event to be sent to another nanoapp.
+ *
+ * @param eventType  This is a user-defined event type, of at least the
+ *     value CHRE_EVENT_FIRST_USER_VALUE.  It is illegal to attempt to use any
+ *     of the CHRE_EVENT_* values reserved for the CHRE.
+ * @param eventData  A pointer value that will be understood by the receiving
+ *     app.  Note that NULL is perfectly acceptable.  It also is not required
+ *     that this be a valid pointer, although if this nanoapp is intended to
+ *     work on arbitrary CHRE implementations, then the size of a
+ *     pointer cannot be assumed to be a certain size.  Note that the caller
+ *     no longer owns this memory after the call.
+ * @param freeCallback  A pointer to a callback function.  After the lifetime
+ *     of 'eventData' is over (either through successful delivery or the event
+ *     being dropped), this callback will be invoked.  This argument is allowed
+ *     to be NULL, in which case no callback will be invoked.
+ * @param targetInstanceId  The ID of the instance we're delivering this event
+ *     to.  Note that this is allowed to be our own instance.  The instance ID
+ *     of a nanoapp can be retrieved by using chreGetNanoappInfoByInstanceId().
+ * @return true if the event was enqueued, false otherwise.  Note that even
+ *     if this method returns 'false', the 'freeCallback' will be invoked,
+ *     if non-NULL.  Note in the 'false' case, the 'freeCallback' may be
+ *     invoked directly from within chreSendEvent(), so it's necessary
+ *     for nanoapp authors to avoid possible recursion with this.
+ *
+ * @see chreEventDataFreeFunction
+ */
+bool chreSendEvent(uint16_t eventType, void *eventData,
+                   chreEventCompleteFunction *freeCallback,
+                   uint32_t targetInstanceId);
+
+/**
+ * Send a message to the host, using the broadcast endpoint
+ * CHRE_HOST_ENDPOINT_BROADCAST.  Refer to chreSendMessageToHostEndpoint() for
+ * further details.
+ *
+ * @see chreSendMessageToHostEndpoint
+ *
+ * @deprecated New code should use chreSendMessageToHostEndpoint() instead of
+ * this function.  A future update to the API may cause references to this
+ * function to produce a compiler warning.
+ */
+bool chreSendMessageToHost(void *message, uint32_t messageSize,
+                           uint32_t messageType,
+                           chreMessageFreeFunction *freeCallback)
+    CHRE_DEPRECATED("Use chreSendMessageToHostEndpoint instead");
+
+/**
+ * Send a message to the host, using CHRE_MESSAGE_PERMISSION_NONE for the
+ * associated message permissions. This method must only be used if no data
+ * provided by CHRE's audio, GNSS, WiFi, and WWAN APIs was used to produce the
+ * contents of the message being sent. Refer to chreSendMessageWithPermissions()
+ * for further details.
+ *
+ * @see chreSendMessageWithPermissions
+ *
+ * @since v1.1
+ */
+bool chreSendMessageToHostEndpoint(void *message, size_t messageSize,
+                                   uint32_t messageType, uint16_t hostEndpoint,
+                                   chreMessageFreeFunction *freeCallback);
+
+/**
+ * Send a message to the host, waking it up if it is currently asleep.
+ *
+ * This message is by definition arbitrarily defined.  Since we're not
+ * just a passing a pointer to memory around the system, but need to copy
+ * this into various buffers to send it to the host, the CHRE
+ * implementation cannot be asked to support an arbitrarily large message
+ * size.  As a result, we have the CHRE implementation define
+ * CHRE_MESSAGE_TO_HOST_MAX_SIZE.
+ *
+ * CHRE_MESSAGE_TO_HOST_MAX_SIZE is not given a value by the Platform API.  The
+ * Platform API does define CHRE_MESSAGE_TO_HOST_MINIMUM_MAX_SIZE, and requires
+ * that CHRE_MESSAGE_TO_HOST_MAX_SIZE is at least that value.
+ *
+ * As a result, if your message sizes are all less than
+ * CHRE_MESSAGE_TO_HOST_MINIMUM_MAX_SIZE, then you have no concerns on any
+ * CHRE implementation.  If your message sizes are larger, you'll need to
+ * come up with a strategy for splitting your message across several calls
+ * to this method.  As long as that strategy works for
+ * CHRE_MESSAGE_TO_HOST_MINIMUM_MAX_SIZE, it will work across all CHRE
+ * implementations (although on some implementations less calls to this
+ * method may be necessary).
+ *
+ * When sending a message to the host, the ContextHub service will enforce
+ * the host client has been granted Android-level permissions corresponding to
+ * the ones the nanoapp declares it uses through CHRE_NANOAPP_USES_AUDIO, etc.
+ * In addition to this, the permissions bitmask provided as input to this method
+ * results in the Android framework using app-ops to verify and log access upon
+ * message delivery to an application. This is primarily useful for ensuring
+ * accurate attribution for messages generated using permission-controlled data.
+ * The bitmask declared by the nanoapp for this message must be a
+ * subset of the permissions it declared it would use at build time or the
+ * message will be rejected.
+ *
+ * Nanoapps must use this method if the data they are sending contains or was
+ * derived from any data sampled through CHRE's audio, GNSS, WiFi, or WWAN APIs.
+ * Additionally, if vendors add APIs to expose data that would be guarded by a
+ * permission in Android, vendors must support declaring a message permission
+ * through this method.
+ *
+ * @param message  Pointer to a block of memory to send to the host.
+ *     NULL is acceptable only if messageSize is 0.  If non-NULL, this
+ *     must be a legitimate pointer (that is, unlike chreSendEvent(), a small
+ *     integral value cannot be cast to a pointer for this).  Note that the
+ *     caller no longer owns this memory after the call.
+ * @param messageSize  The size, in bytes, of the given message. If this exceeds
+ *     CHRE_MESSAGE_TO_HOST_MAX_SIZE, the message will be rejected.
+ * @param messageType  Message type sent to the app on the host.
+ *     NOTE: In CHRE API v1.0, support for forwarding this field to the host was
+ *     not strictly required, and some implementations did not support it.
+ *     However, its support is mandatory as of v1.1.
+ *     NOTE: The value CHRE_MESSAGE_TYPE_RPC is reserved for usage by RPC
+ *     libraries and normally should not be directly used by nanoapps.
+ * @param hostEndpoint  An identifier for the intended recipient of the message,
+ *     or CHRE_HOST_ENDPOINT_BROADCAST if all registered endpoints on the host
+ *     should receive the message.  Endpoint identifiers are assigned on the
+ *     host side, and nanoapps may learn of the host endpoint ID of an intended
+ *     recipient via an initial message sent by the host.  This parameter is
+ *     always treated as CHRE_HOST_ENDPOINT_BROADCAST if running on a CHRE API
+ *     v1.0 implementation. CHRE_HOST_ENDPOINT_BROADCAST isn't allowed to be
+ *     specified if anything other than CHRE_MESSAGE_PERMISSION_NONE is given
+ *     as messagePermissions since doing so would potentially attribute
+ *     permissions usage to host clients that don't intend to consume the data.
+ * @param messagePermissions Bitmasked CHRE_MESSAGE_PERMISSION_ values that will
+ *     be converted to corresponding Android-level permissions and attributed
+ *     the host endpoint upon consumption of the message.
+ * @param freeCallback  A pointer to a callback function.  After the lifetime
+ *     of 'message' is over (which does not assure that 'message' made it to
+ *     the host, just that the transport layer no longer needs this memory),
+ *     this callback will be invoked.  This argument is allowed
+ *     to be NULL, in which case no callback will be invoked.
+ * @return true if the message was accepted for transmission, false otherwise.
+ *     Note that even if this method returns 'false', the 'freeCallback' will
+ *     be invoked, if non-NULL.  In either case, the 'freeCallback' may be
+ *     invoked directly from within chreSendMessageToHostEndpoint(), so it's
+ *     necessary for nanoapp authors to avoid possible recursion with this.
+ *
+ * @see chreMessageFreeFunction
+ *
+ * @since v1.5
+ */
+bool chreSendMessageWithPermissions(void *message, size_t messageSize,
+                                    uint32_t messageType, uint16_t hostEndpoint,
+                                    uint32_t messagePermissions,
+                                    chreMessageFreeFunction *freeCallback);
+
+/**
+ * Send a reliable message to the host.
+ *
+ * A reliable message is similar to a message sent by
+ * chreSendMessageWithPermissions() with the difference that the host
+ * acknowledges the message by sending a status back to the nanoapp, and the
+ * CHRE implementation takes care of retries to help mitigate transient
+ * failures. The final result of attempting to deliver the message is given
+ * via a CHRE_EVENT_RELIABLE_MSG_ASYNC_RESULT event. The maximum time until the
+ * nanoapp will receive the result is CHRE_ASYNC_RESULT_TIMEOUT_NS.
+ *
+ * The free callback is invoked before the async status is delivered to the
+ * nanoapp via the CHRE_EVENT_RELIABLE_MSG_ASYNC_RESULT event and does not
+ * indicate successful delivery of the message.
+ *
+ * The API is similar to chreSendMessageWithPermissions() with a few
+ * differences:
+ * - chreSendReliableMessageAsync() takes an extra cookie that is part of the
+ *   async result
+ * - When the message is accepted for transmission (the function returns true)
+ *   then an async status is delivered to the nanoapp when the transmission
+ *   completes either successfully or in error via the
+ *   CHRE_EVENT_RELIABLE_MSG_ASYNC_RESULT event.
+ * - For any reliable messages pending completion at nanoapp unload:
+ *   - At least one delivery attempt will be made.
+ *   - The free callback will be invoked.
+ *   - The async result event will not be delivered.
+ * - The error codes received are:
+ *   - CHRE_ERROR_DESTINATION_NOT_FOUND if the destination was not found.
+ *   - CHRE_ERROR if there was a permanent error.
+ *   - CHRE_ERROR_TIMEOUT if there was no response from the recipient
+ *                        (a timeout).
+ *
+ * This is an optional feature, and this function will always return
+ * false if CHRE_CAPABILITIES_RELIABLE_MESSAGES is not indicated by
+ * chreGetCapabilities().
+ *
+ * @see chreSendMessageWithPermissions
+ *
+ * @since v1.10
+ */
+bool chreSendReliableMessageAsync(void *message, size_t messageSize,
+                                  uint32_t messageType, uint16_t hostEndpoint,
+                                  uint32_t messagePermissions,
+                                  chreMessageFreeFunction *freeCallback,
+                                  const void *cookie);
+
+/**
+ * Queries for information about a nanoapp running in the system.
+ *
+ * In the current API, appId is required to be unique, i.e. there cannot be two
+ * nanoapps running concurrently with the same appId.  If this restriction is
+ * removed in a future API version and multiple instances of the same appId are
+ * present, this function must always return the first app to start.
+ *
+ * @param appId Identifier for the nanoapp that the caller is requesting
+ *     information about.
+ * @param info Output parameter.  If this function returns true, this structure
+ *     will be populated with details of the specified nanoapp.
+ * @return true if a nanoapp with the given ID is currently running, and the
+ *     supplied info parameter was populated with its information.
+ *
+ * @since v1.1
+ */
+bool chreGetNanoappInfoByAppId(uint64_t appId, struct chreNanoappInfo *info);
+
+/**
+ * Queries for information about a nanoapp running in the system, using the
+ * runtime unique identifier.  This method can be used to get information about
+ * the sender of an event.
+ *
+ * @param instanceId
+ * @param info Output parameter.  If this function returns true, this structure
+ *     will be populated with details of the specified nanoapp.
+ * @return true if a nanoapp with the given instance ID is currently running,
+ *     and the supplied info parameter was populated with its information.
+ *
+ * @since v1.1
+ */
+bool chreGetNanoappInfoByInstanceId(uint32_t instanceId,
+                                    struct chreNanoappInfo *info);
+
+/**
+ * Configures whether this nanoapp will be notified when other nanoapps in the
+ * system start and stop, via CHRE_EVENT_NANOAPP_STARTED and
+ * CHRE_EVENT_NANOAPP_STOPPED.  These events are disabled by default, and if a
+ * nanoapp is not interested in interacting with other nanoapps, then it does
+ * not need to register for them.  However, if inter-nanoapp communication is
+ * desired, nanoapps are recommended to call this function from nanoappStart().
+ *
+ * If running on a CHRE platform that only supports v1.0 of the CHRE API, this
+ * function has no effect.
+ *
+ * @param enable true to enable these events, false to disable
+ *
+ * @see CHRE_EVENT_NANOAPP_STARTED
+ * @see CHRE_EVENT_NANOAPP_STOPPED
+ *
+ * @since v1.1
+ */
+void chreConfigureNanoappInfoEvents(bool enable);
+
+/**
+ * Configures whether this nanoapp will be notified when the host (applications
+ * processor) transitions between wake and sleep, via CHRE_EVENT_HOST_AWAKE and
+ * CHRE_EVENT_HOST_ASLEEP.  As chreSendMessageToHostEndpoint() wakes the host if
+ * it is asleep, these events can be used to opportunistically send data to the
+ * host only when it wakes up for some other reason.  Note that this event is
+ * not instantaneous - there is an inherent delay in CHRE observing power state
+ * changes of the host processor, which may be significant depending on the
+ * implementation, especially in the wake to sleep direction.  Therefore,
+ * nanoapps are not guaranteed that messages sent to the host between AWAKE and
+ * ASLEEP events will not trigger a host wakeup.  However, implementations must
+ * ensure that the nominal wake-up notification latency is strictly less than
+ * the minimum wake-sleep time of the host processor.  Implementations are also
+ * encouraged to minimize this and related latencies where possible, to avoid
+ * unnecessary host wake-ups.
+ *
+ * These events are only sent on transitions, so the initial state will not be
+ * sent to the nanoapp as an event - use chreIsHostAwake().
+ *
+ * @param enable true to enable these events, false to disable
+ *
+ * @see CHRE_EVENT_HOST_AWAKE
+ * @see CHRE_EVENT_HOST_ASLEEP
+ *
+ * @since v1.2
+ */
+void chreConfigureHostSleepStateEvents(bool enable);
+
+/**
+ * Retrieves the current sleep/wake state of the host (applications processor).
+ * Note that, as with the CHRE_EVENT_HOST_AWAKE and CHRE_EVENT_HOST_ASLEEP
+ * events, there is no guarantee that CHRE's view of the host processor's sleep
+ * state is instantaneous, and it may also change between querying the state and
+ * performing a host-waking action like sending a message to the host.
+ *
+ * @return true if by CHRE's own estimation the host is currently awake,
+ *     false otherwise
+ *
+ * @since v1.2
+ */
+bool chreIsHostAwake(void);
+
+/**
+ * Configures whether this nanoapp will be notified when CHRE is collecting
+ * debug dumps, via CHRE_EVENT_DEBUG_DUMP. This event is disabled by default,
+ * and if a nanoapp is not interested in logging its debug data, then it does
+ * not need to register for it.
+ *
+ * @param enable true to enable receipt of this event, false to disable.
+ *
+ * @see CHRE_EVENT_DEBUG_DUMP
+ * @see chreDebugDumpLog
+ *
+ * @since v1.4
+ */
+void chreConfigureDebugDumpEvent(bool enable);
+
+/**
+ * Configures whether this nanoapp will receive updates regarding a host
+ * endpoint that is connected with the Context Hub.
+ *
+ * If this API succeeds, the nanoapp will receive disconnection notifications,
+ * via the CHRE_EVENT_HOST_ENDPOINT_NOTIFICATION event with an eventData of type
+ * chreHostEndpointNotification with its notificationType set to
+ * HOST_ENDPOINT_NOTIFICATION_TYPE_DISCONNECT, which can be invoked if the host
+ * has disconnected from the Context Hub either explicitly or implicitly (e.g.
+ * crashes). Nanoapps can use this notifications to clean up any resources
+ * associated with this host endpoint.
+ *
+ * @param hostEndpointId The host endpoint ID to configure notifications for.
+ * @param enable true to enable notifications.
+ *
+ * @return true on success
+ *
+ * @see chreMessageFromHostData
+ * @see chreHostEndpointNotification
+ * @see CHRE_EVENT_HOST_ENDPOINT_NOTIFICATION
+ *
+ * @since v1.6
+ */
+bool chreConfigureHostEndpointNotifications(uint16_t hostEndpointId,
+                                            bool enable);
+
+/**
+ * Publishes RPC services from this nanoapp.
+ *
+ * When this API is invoked, the list of RPC services will be provided to
+ * host applications interacting with the nanoapp.
+ *
+ * This function must be invoked from nanoappStart(), to guarantee stable output
+ * of the list of RPC services supported by the nanoapp.
+ *
+ * Although nanoapps are recommended to only call this API once with all
+ * services it intends to publish, if it is called multiple times, each
+ * call will append to the list of published services.
+ *
+ * Starting in CHRE API v1.8, the implementation must allow for a nanoapp to
+ * publish at least CHRE_MINIMUM_RPC_SERVICE_LIMIT services and at most
+ * UINT8_MAX services. If calling this function would result in exceeding
+ * the limit, the services must not be published and it must return false.
+ *
+ * @param services A non-null pointer to the list of RPC services to publish.
+ * @param numServices The number of services to publish, i.e. the length of the
+ *   services array.
+ *
+ * @return true if the publishing is successful.
+ *
+ * @since v1.6
+ *
+ * @deprecated Use chreMsgPublishServices() instead. If this function is
+ * called with CHRE API version v1.11 or above, it will convert each
+ * struct chreNanoappRpcService to a struct chreMsgEndpointServiceInfo and
+ * call chreMsgPublishServices() instead. The conversion will be mapped as
+ * follows:
+ *   - majorVersion = chreNanoappRpcService.version
+ *   - minorVersion = 0
+ *   - serviceDescriptor = FORMAT_STRING(
+ *     "chre.nanoapp_0x%016" PRIX64 ".service_0x%016" PRIX64, nanoapp_id,
+ *     service_id)
+ *   - serviceFormat = CHRE_ENDPOINT_SERVICE_FORMAT_PW_RPC_PROTOBUF
+ */
+bool chrePublishRpcServices(struct chreNanoappRpcService *services,
+                            size_t numServices);
+
+/**
+ * Retrieves metadata for a given host endpoint ID.
+ *
+ * This API will provide metadata regarding an endpoint associated with a
+ * host endpoint ID. The nanoapp should use this API to determine more
+ * information about a host endpoint that has sent a message to the nanoapp,
+ * after receiving a chreMessageFromHostData (which includes the endpoint ID).
+ *
+ * If the given host endpoint ID is not associated with a valid host (or if the
+ * client has disconnected from the Android or CHRE framework, i.e. no longer
+ * able to send messages to CHRE), this method will return false and info will
+ * not be populated.
+ *
+ * @param hostEndpointId The endpoint ID of the host to get info for.
+ * @param info The non-null pointer to where the metadata will be stored.
+ *
+ * @return true if info has been successfully populated.
+ *
+ * @since v1.6
+ */
+bool chreGetHostEndpointInfo(uint16_t hostEndpointId,
+                             struct chreHostEndpointInfo *info);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* _CHRE_EVENT_H_ */
+
diff --git a/chre_api/legacy/v1_11/chre/gnss.h b/chre_api/legacy/v1_11/chre/gnss.h
new file mode 100644
index 00000000..74e8649d
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/gnss.h
@@ -0,0 +1,675 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_GNSS_H_
+#define _CHRE_GNSS_H_
+
+/**
+ * @file
+ * Global Navigation Satellite System (GNSS) API.
+ *
+ * These structures and definitions are based on the Android N GPS HAL.
+ * Refer to that header file (located at this path as of the time of this
+ * comment: hardware/libhardware/include/hardware/gps.h) and associated
+ * documentation for further details and explanations for these fields.
+ * References in comments like "(ref: GnssAccumulatedDeltaRangeState)" map to
+ * the relevant element in the GPS HAL where additional information can be
+ * found.
+ *
+ * In general, the parts of this API that are taken from the GPS HAL follow the
+ * naming conventions established in that interface rather than the CHRE API
+ * conventions, in order to avoid confusion and enable code re-use where
+ * applicable.
+ */
+
+
+#include <stdbool.h>
+#include <stdint.h>
+
+#include <chre/common.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * The set of flags that may be returned by chreGnssGetCapabilities()
+ * @defgroup CHRE_GNSS_CAPABILITIES
+ * @{
+ */
+
+//! A lack of flags indicates that GNSS is not supported in this CHRE
+#define CHRE_GNSS_CAPABILITIES_NONE          (UINT32_C(0))
+
+//! GNSS position fixes are supported via chreGnssLocationSessionStartAsync()
+#define CHRE_GNSS_CAPABILITIES_LOCATION      (UINT32_C(1) << 0)
+
+//! GNSS raw measurements are supported via
+//! chreGnssMeasurementSessionStartAsync()
+#define CHRE_GNSS_CAPABILITIES_MEASUREMENTS  (UINT32_C(1) << 1)
+
+//! Location fixes supplied from chreGnssConfigurePassiveLocationListener()
+//! are tapped in at the GNSS engine level, so they include additional fixes
+//! such as those requested by the AP, and not just those requested by other
+//! nanoapps within CHRE (which is the case when this flag is not set)
+#define CHRE_GNSS_CAPABILITIES_GNSS_ENGINE_BASED_PASSIVE_LISTENER \
+                                             (UINT32_C(1) << 2)
+
+//! GNSS data from remote sources is supported via
+//! chreGnssLocationSessionStartAsyncV1_11() and
+//! chreGnssMeasurementSessionStartAsyncV1_11()
+//! @since v1.11
+#define CHRE_GNSS_CAPABILITIES_REMOTE_SOURCE (UINT32_C(1) << 3)
+
+/** @} */
+
+/**
+ * The current version of struct chreGnssDataEvent associated with this API
+ */
+#define CHRE_GNSS_DATA_EVENT_VERSION  UINT8_C(0)
+
+/**
+ * The maximum time the CHRE implementation is allowed to elapse before sending
+ * an event with the result of an asynchronous request, unless specified
+ * otherwise
+ */
+#define CHRE_GNSS_ASYNC_RESULT_TIMEOUT_NS  (5 * CHRE_NSEC_PER_SEC)
+
+/**
+ * Produce an event ID in the block of IDs reserved for GNSS
+ * @param offset  Index into GNSS event ID block; valid range [0,15]
+ */
+#define CHRE_GNSS_EVENT_ID(offset)  (CHRE_EVENT_GNSS_FIRST_EVENT + (offset))
+
+/**
+ * nanoappHandleEvent argument: struct chreAsyncResult
+ *
+ * Communicates the asynchronous result of a request to the GNSS API, such as
+ * starting a location session via chreGnssLocationSessionStartAsync(). The
+ * requestType field in chreAsyncResult is set to a value from enum
+ * chreGnssRequestType.
+ */
+#define CHRE_EVENT_GNSS_ASYNC_RESULT  CHRE_GNSS_EVENT_ID(0)
+
+/**
+ * nanoappHandleEvent argument: struct chreGnssLocationEvent
+ *
+ * Represents a location fix provided by the GNSS subsystem.
+ */
+#define CHRE_EVENT_GNSS_LOCATION      CHRE_GNSS_EVENT_ID(1)
+
+/**
+ * nanoappHandleEvent argument: struct chreGnssDataEvent
+ *
+ * Represents a set of GNSS measurements with associated clock data.
+ */
+#define CHRE_EVENT_GNSS_DATA          CHRE_GNSS_EVENT_ID(2)
+
+// NOTE: Do not add new events with ID > 15; only values 0-15 are reserved
+// (see chre/event.h)
+
+// Flags indicating the Accumulated Delta Range's states
+// (ref: GnssAccumulatedDeltaRangeState)
+#define CHRE_GNSS_ADR_STATE_UNKNOWN     (UINT16_C(0))
+#define CHRE_GNSS_ADR_STATE_VALID       (UINT16_C(1) << 0)
+#define CHRE_GNSS_ADR_STATE_RESET       (UINT16_C(1) << 1)
+#define CHRE_GNSS_ADR_STATE_CYCLE_SLIP  (UINT16_C(1) << 2)
+
+// Flags to indicate what fields in chreGnssClock are valid (ref: GnssClockFlags)
+#define CHRE_GNSS_CLOCK_HAS_LEAP_SECOND        (UINT16_C(1) << 0)
+#define CHRE_GNSS_CLOCK_HAS_TIME_UNCERTAINTY   (UINT16_C(1) << 1)
+#define CHRE_GNSS_CLOCK_HAS_FULL_BIAS          (UINT16_C(1) << 2)
+#define CHRE_GNSS_CLOCK_HAS_BIAS               (UINT16_C(1) << 3)
+#define CHRE_GNSS_CLOCK_HAS_BIAS_UNCERTAINTY   (UINT16_C(1) << 4)
+#define CHRE_GNSS_CLOCK_HAS_DRIFT              (UINT16_C(1) << 5)
+#define CHRE_GNSS_CLOCK_HAS_DRIFT_UNCERTAINTY  (UINT16_C(1) << 6)
+
+// Flags to indicate which values are valid in a GpsLocation
+// (ref: GpsLocationFlags)
+#define CHRE_GPS_LOCATION_HAS_LAT_LONG           (UINT16_C(1) << 0)
+#define CHRE_GPS_LOCATION_HAS_ALTITUDE           (UINT16_C(1) << 1)
+#define CHRE_GPS_LOCATION_HAS_SPEED              (UINT16_C(1) << 2)
+#define CHRE_GPS_LOCATION_HAS_BEARING            (UINT16_C(1) << 3)
+#define CHRE_GPS_LOCATION_HAS_ACCURACY           (UINT16_C(1) << 4)
+
+//! @since v1.3
+#define CHRE_GPS_LOCATION_HAS_ALTITUDE_ACCURACY  (UINT16_C(1) << 5)
+//! @since v1.3
+#define CHRE_GPS_LOCATION_HAS_SPEED_ACCURACY     (UINT16_C(1) << 6)
+//! @since v1.3
+#define CHRE_GPS_LOCATION_HAS_BEARING_ACCURACY   (UINT16_C(1) << 7)
+
+/**
+ * The maximum number of instances of struct chreGnssMeasurement that may be
+ * included in a single struct chreGnssDataEvent.
+ *
+ * The value of this struct was increased from 64 to 128 in CHRE v1.5. For
+ * nanoapps targeting CHRE v1.4 or lower, the measurement_count will be capped
+ * at 64.
+ */
+#define CHRE_GNSS_MAX_MEASUREMENT  UINT8_C(128)
+#define CHRE_GNSS_MAX_MEASUREMENT_PRE_1_5  UINT8_C(64)
+
+// Flags indicating the GNSS measurement state (ref: GnssMeasurementState)
+#define CHRE_GNSS_MEASUREMENT_STATE_UNKNOWN                (UINT16_C(0))
+#define CHRE_GNSS_MEASUREMENT_STATE_CODE_LOCK              (UINT16_C(1) << 0)
+#define CHRE_GNSS_MEASUREMENT_STATE_BIT_SYNC               (UINT16_C(1) << 1)
+#define CHRE_GNSS_MEASUREMENT_STATE_SUBFRAME_SYNC          (UINT16_C(1) << 2)
+#define CHRE_GNSS_MEASUREMENT_STATE_TOW_DECODED            (UINT16_C(1) << 3)
+#define CHRE_GNSS_MEASUREMENT_STATE_MSEC_AMBIGUOUS         (UINT16_C(1) << 4)
+#define CHRE_GNSS_MEASUREMENT_STATE_SYMBOL_SYNC            (UINT16_C(1) << 5)
+#define CHRE_GNSS_MEASUREMENT_STATE_GLO_STRING_SYNC        (UINT16_C(1) << 6)
+#define CHRE_GNSS_MEASUREMENT_STATE_GLO_TOD_DECODED        (UINT16_C(1) << 7)
+#define CHRE_GNSS_MEASUREMENT_STATE_BDS_D2_BIT_SYNC        (UINT16_C(1) << 8)
+#define CHRE_GNSS_MEASUREMENT_STATE_BDS_D2_SUBFRAME_SYNC   (UINT16_C(1) << 9)
+#define CHRE_GNSS_MEASUREMENT_STATE_GAL_E1BC_CODE_LOCK     (UINT16_C(1) << 10)
+#define CHRE_GNSS_MEASUREMENT_STATE_GAL_E1C_2ND_CODE_LOCK  (UINT16_C(1) << 11)
+#define CHRE_GNSS_MEASUREMENT_STATE_GAL_E1B_PAGE_SYNC      (UINT16_C(1) << 12)
+#define CHRE_GNSS_MEASUREMENT_STATE_SBAS_SYNC              (UINT16_C(1) << 13)
+
+#define CHRE_GNSS_MEASUREMENT_CARRIER_FREQUENCY_UNKNOWN    0.f
+
+/**
+ * Indicates a type of request made in this API. Used to populate the resultType
+ * field of struct chreAsyncResult sent with CHRE_EVENT_GNSS_ASYNC_RESULT.
+ */
+enum chreGnssRequestType {
+    CHRE_GNSS_REQUEST_TYPE_LOCATION_SESSION_START    = 1,
+    CHRE_GNSS_REQUEST_TYPE_LOCATION_SESSION_STOP     = 2,
+    CHRE_GNSS_REQUEST_TYPE_MEASUREMENT_SESSION_START = 3,
+    CHRE_GNSS_REQUEST_TYPE_MEASUREMENT_SESSION_STOP  = 4,
+};
+
+/**
+ * Constellation type associated with an SV
+ */
+enum chreGnssConstellationType {
+    CHRE_GNSS_CONSTELLATION_UNKNOWN = 0,
+    CHRE_GNSS_CONSTELLATION_GPS     = 1,
+    CHRE_GNSS_CONSTELLATION_SBAS    = 2,
+    CHRE_GNSS_CONSTELLATION_GLONASS = 3,
+    CHRE_GNSS_CONSTELLATION_QZSS    = 4,
+    CHRE_GNSS_CONSTELLATION_BEIDOU  = 5,
+    CHRE_GNSS_CONSTELLATION_GALILEO = 6,
+};
+
+/**
+ * Enumeration of available values for the chreGnssMeasurement multipath indicator
+ */
+enum chreGnssMultipathIndicator {
+    //! The indicator is not available or unknown
+    CHRE_GNSS_MULTIPATH_INDICATOR_UNKNOWN     = 0,
+    //! The measurement is indicated to be affected by multipath
+    CHRE_GNSS_MULTIPATH_INDICATOR_PRESENT     = 1,
+    //! The measurement is indicated to be not affected by multipath
+    CHRE_GNSS_MULTIPATH_INDICATOR_NOT_PRESENT = 2,
+};
+
+/**
+ * Enumeration of available values for the GNSS source type associated with
+ * a location fix, measurement data, a location session or a measurement
+ * session
+ */
+enum chreGnssSource {
+  //! In the request context, indicates that there is no preference for a
+  //! particular GNSS engine, so if there are multiple, allow the system to
+  //! decide which one is used (the selected engine may change over the course
+  //! of a session).
+  //! In the result context, indicates that the GNSS engine used was not
+  //! explicitly reported.
+  CHRE_GNSS_SOURCE_UNSPECIFIED = 0,
+  //! References the GNSS system local to this device
+  CHRE_GNSS_SOURCE_LOCAL = 1,
+  //! References a GNSS system on a remote device
+  CHRE_GNSS_SOURCE_REMOTE = 2,
+};
+
+/**
+ * Represents an estimate of the GNSS clock time (see the Android GPS HAL for
+ * more detailed information)
+ */
+struct chreGnssClock {
+    //! The GNSS receiver hardware clock value in nanoseconds, including
+    //! uncertainty
+    int64_t time_ns;
+
+    //! The difference between hardware clock inside GNSS receiver and the
+    //! estimated GNSS time in nanoseconds; contains bias uncertainty
+    int64_t full_bias_ns;
+
+    //! Sub-nanosecond bias, adds to full_bias_ns
+    float bias_ns;
+
+    //! The clock's drift in nanoseconds per second
+    float drift_nsps;
+
+    //! 1-sigma uncertainty associated with the clock's bias in nanoseconds
+    float bias_uncertainty_ns;
+
+    //! 1-sigma uncertainty associated with the clock's drift in nanoseconds
+    //! per second
+    float drift_uncertainty_nsps;
+
+    //! While this number stays the same, timeNs should flow continuously
+    uint32_t hw_clock_discontinuity_count;
+
+    //! A set of flags indicating the validity of the fields in this data
+    //! structure (see GNSS_CLOCK_HAS_*)
+    uint16_t flags;
+
+    //! Reserved for future use; set to 0
+    uint8_t reserved[2];
+};
+
+/**
+ * Represents a GNSS measurement; contains raw and computed information (see the
+ * Android GPS HAL for more detailed information)
+ */
+struct chreGnssMeasurement {
+    //! Hardware time offset from time_ns for this measurement, in nanoseconds
+    int64_t time_offset_ns;
+
+    //! Accumulated delta range since the last channel reset in micro-meters
+    int64_t accumulated_delta_range_um;
+
+    //! Received GNSS satellite time at the time of measurement, in nanoseconds
+    int64_t received_sv_time_in_ns;
+
+    //! 1-sigma uncertainty of received GNSS satellite time, in nanoseconds
+    int64_t received_sv_time_uncertainty_in_ns;
+
+    //! Pseudorange rate at the timestamp in meters per second (uncorrected)
+    float pseudorange_rate_mps;
+
+    //! 1-sigma uncertainty of pseudorange rate in meters per second
+    float pseudorange_rate_uncertainty_mps;
+
+    //! 1-sigma uncertainty of the accumulated delta range in meters
+    float accumulated_delta_range_uncertainty_m;
+
+    //! Carrier-to-noise density in dB-Hz, in the range of [0, 63]
+    float c_n0_dbhz;
+
+    //! Signal to noise ratio (dB), power above observed noise at correlators
+    float snr_db;
+
+    //! Satellite sync state flags (GNSS_MEASUREMENT_STATE_*) - sets modulus for
+    //! received_sv_time_in_ns
+    uint16_t state;
+
+    //! Set of ADR state flags (GNSS_ADR_STATE_*)
+    uint16_t accumulated_delta_range_state;
+
+    //! Satellite vehicle ID number
+    int16_t svid;
+
+    //! Constellation of the given satellite vehicle
+    //! @see #chreGnssConstellationType
+    uint8_t constellation;
+
+    //! @see #chreGnssMultipathIndicator
+    uint8_t multipath_indicator;
+
+    //! Carrier frequency of the signal tracked in Hz.
+    //! For example, it can be the GPS central frequency for L1 = 1575.45 MHz,
+    //! or L2 = 1227.60 MHz, L5 = 1176.45 MHz, various GLO channels, etc.
+    //!
+    //! Set to CHRE_GNSS_MEASUREMENT_CARRIER_FREQUENCY_UNKNOWN if not reported.
+    //!
+    //! For an L1, L5 receiver tracking a satellite on L1 and L5 at the same
+    //! time, two chreGnssMeasurement structs must be reported for this same
+    //! satellite, in one of the measurement structs, all the values related to
+    //! L1 must be filled, and in the other all of the values related to L5
+    //! must be filled.
+    //! @since v1.4
+    float carrier_frequency_hz;
+};
+
+/**
+ * Data structure sent with events associated with CHRE_EVENT_GNSS_DATA, enabled
+ * via chreGnssMeasurementSessionStartAsync()
+ */
+struct chreGnssDataEvent {
+    //! Indicates the version of the structure, for compatibility purposes.
+    //! Clients do not normally need to worry about this field; the CHRE
+    //! implementation guarantees that it only sends the client the structure
+    //! version it expects.
+    uint8_t version;
+
+    //! Number of chreGnssMeasurement entries included in this event. Must be in
+    //! the range [0, CHRE_GNSS_MAX_MEASUREMENT]
+    uint8_t measurement_count;
+
+    //! The source of the GNSS data
+    //! @see #chreGnssSource
+    //! @since v1.11
+    uint8_t gnss_source;
+
+    //! Reserved for future use; set to 0
+    uint8_t reserved[5];
+
+    struct chreGnssClock clock;
+
+    //! Pointer to an array containing measurement_count measurements
+    const struct chreGnssMeasurement *measurements;
+};
+
+/**
+ * Data structure sent with events of type CHRE_EVENT_GNSS_LOCATION, enabled via
+ * chreGnssLocationSessionStartAsync(). This is modeled after GpsLocation in the
+ * GPS HAL, but does not use the double data type.
+ */
+struct chreGnssLocationEvent {
+    //! UTC timestamp for location fix in milliseconds since January 1, 1970
+    uint64_t timestamp;
+
+    //! Fixed point latitude, degrees times 10^7 (roughly centimeter resolution)
+    int32_t latitude_deg_e7;
+
+    //! Fixed point longitude, degrees times 10^7 (roughly centimeter
+    //! resolution)
+    int32_t longitude_deg_e7;
+
+    //! Altitude in meters above the WGS 84 reference ellipsoid
+    float altitude;
+
+    //! Horizontal speed in meters per second
+    float speed;
+
+    //! Clockwise angle between north and current heading, in degrees; range
+    //! [0, 360)
+    float bearing;
+
+    //! Expected horizontal accuracy in meters such that a circle with a radius
+    //! of length 'accuracy' from the latitude and longitude has a 68%
+    //! probability of including the true location.
+    float accuracy;
+
+    //! A set of flags indicating which fields in this structure are valid.
+    //! If any fields are not available, the flag must not be set and the field
+    //! must be initialized to 0.
+    //! @see #GpsLocationFlags
+    uint16_t flags;
+
+    //! The source of the GNSS data
+    //! @see #chreGnssSource
+    //! @since v1.11
+    uint8_t gnss_source;
+
+    //! Reserved for future use; set to 0
+    //! @since v1.3
+    uint8_t reserved[1];
+
+    //! Expected vertical accuracy in meters such that a range of
+    //! 2 * altitude_accuracy centered around altitude has a 68% probability of
+    //! including the true altitude.
+    //! @since v1.3
+    float altitude_accuracy;
+
+    //! Expected speed accuracy in meters per second such that a range of
+    //! 2 * speed_accuracy centered around speed has a 68% probability of
+    //! including the true speed.
+    //! @since v1.3
+    float speed_accuracy;
+
+    //! Expected bearing accuracy in degrees such that a range of
+    //! 2 * bearing_accuracy centered around bearing has a 68% probability of
+    //! including the true bearing.
+    //! @since v1.3
+    float bearing_accuracy;
+};
+
+
+/**
+ * Retrieves a set of flags indicating the GNSS features supported by the
+ * current CHRE implementation. The value returned by this function must be
+ * consistent for the entire duration of the Nanoapp's execution.
+ *
+ * The client must allow for more flags to be set in this response than it knows
+ * about, for example if the implementation supports a newer version of the API
+ * than the client was compiled against.
+ *
+ * @return A bitmask with zero or more CHRE_GNSS_CAPABILITIES_* flags set
+ *
+ * @since v1.1
+ */
+uint32_t chreGnssGetCapabilities(void);
+
+/**
+ * Nanoapps must define CHRE_NANOAPP_USES_GNSS somewhere in their build
+ * system (e.g. Makefile) if the nanoapp needs to use the following GNSS APIs.
+ * In addition to allowing access to these APIs, defining this macro will also
+ * ensure CHRE enforces that all host clients this nanoapp talks to have the
+ * required Android permissions needed to listen to GNSS data by adding metadata
+ * to the nanoapp.
+ */
+#if defined(CHRE_NANOAPP_USES_GNSS) || !defined(CHRE_IS_NANOAPP_BUILD)
+
+/**
+ * Initiates a GNSS positioning session, or changes the requested interval of an
+ * existing session.
+ *
+ * @see chreGnssLocationSessionStartAsyncV1_11 for further details. This
+ * function behaves the same as calling that function with
+ * CHRE_GNSS_SOURCE_UNSPECIFIED.
+ */
+bool chreGnssLocationSessionStartAsync(uint32_t minIntervalMs,
+                                       uint32_t minTimeToNextFixMs,
+                                       const void *cookie);
+
+/**
+ * Initiates a GNSS positioning session, or changes the requested interval of an
+ * existing session. If starting or modifying the session was successful, then
+ * the GNSS engine will work on determining the device's position.
+ *
+ * This result of this request is delivered asynchronously via an event of type
+ * CHRE_EVENT_GNSS_ASYNC_RESULT. Refer to the note in {@link #chreAsyncResult}
+ * for more details. If the "Location" setting is disabled at the Android level,
+ * the CHRE implementation is expected to return a result with
+ * CHRE_ERROR_FUNCTION_DISABLED.
+ *
+ * If chreGnssGetCapabilities() does not include
+ * CHRE_GNSS_CAPABILITIES_REMOTE_SOURCE, calling this function with
+ * CHRE_GNSS_SOURCE_REMOTE will return false. Calling this function with
+ * CHRE_GNSS_SOURCE_LOCAL or CHRE_GNSS_SOURCE_UNSPECIFIED will elicit the same
+ * behavior as chreGnssLocationSessionStartAsync(), including when run on CHRE
+ * versions prior to v1.11.
+ *
+ * @param minIntervalMs The desired minimum interval between location fixes
+ *        delivered to the client via CHRE_EVENT_GNSS_LOCATION, in milliseconds.
+ *        The requesting client must allow for fixes to be delivered at shorter
+ *        or longer interval than requested. For example, adverse RF conditions
+ *        may result in fixes arriving at a longer interval, etc.
+ * @param minTimeToNextFixMs The desired minimum time to the next location fix.
+ *        If this is 0, the GNSS engine should start working on the next fix
+ *        immediately. If greater than 0, the GNSS engine should not spend
+ *        measurable power to produce a location fix until this amount of time
+ *        has elapsed.
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *        sent in relation to this request.
+ * @param source The source of the GNSS data to request.
+ *
+ * @return true if the request was accepted for processing, false otherwise
+ *
+ * @since v1.11
+ * @note Requires GNSS permission
+ */
+bool chreGnssLocationSessionStartAsyncV1_11(uint32_t minIntervalMs,
+                                            uint32_t minTimeToNextFixMs,
+                                            const void *cookie,
+                                            enum chreGnssSource source);
+
+/**
+ * Terminates an existing GNSS positioning session. If no positioning session
+ * is active at the time of this request, it is treated as if an active session
+ * was successfully ended.
+ *
+ * This result of this request is delivered asynchronously via an event of type
+ * CHRE_EVENT_GNSS_ASYNC_RESULT. Refer to the note in {@link #chreAsyncResult}
+ * for more details.
+ *
+ * After CHRE_EVENT_GNSS_ASYNC_RESULT is delivered to the client, no more
+ * CHRE_EVENT_GNSS_LOCATION events will be delievered until a new location
+ * session is started.
+ *
+ * If chreGnssGetCapabilities() returns a value that does not have the
+ * CHRE_GNSS_CAPABILITIES_LOCATION flag set, then this method will return false.
+ *
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *        sent in relation to this request.
+ *
+ * @return true if the request was accepted for processing, false otherwise
+ *
+ * @since v1.1
+ * @note Requires GNSS permission
+ */
+bool chreGnssLocationSessionStopAsync(const void *cookie);
+
+/**
+ * Initiates a request to receive raw GNSS measurements.
+ *
+ * @see chreGnssMeasurementSessionStartAsyncV1_11 for further details. This
+ * function behaves the same as calling that function with
+ * CHRE_GNSS_SOURCE_UNSPECIFIED.
+ */
+bool chreGnssMeasurementSessionStartAsync(uint32_t minIntervalMs,
+                                          const void *cookie);
+
+/**
+ * Initiates a request to receive raw GNSS measurements. A GNSS measurement
+ * session can exist independently of location sessions. In other words, a
+ * Nanoapp is able to receive measurements at its requested interval both with
+ * and without an active location session.
+ *
+ * This result of this request is delivered asynchronously via an event of type
+ * CHRE_EVENT_GNSS_ASYNC_RESULT. Refer to the note in {@link #chreAsyncResult}
+ * for more details. If the "Location" setting is disabled at the Android level,
+ * the CHRE implementation is expected to return a result with
+ * CHRE_ERROR_FUNCTION_DISABLED.
+ *
+ * If chreGnssGetCapabilities() does not include
+ * CHRE_GNSS_CAPABILITIES_REMOTE_SOURCE, calling this function with
+ * CHRE_GNSS_SOURCE_REMOTE will return false. Calling this function with
+ * CHRE_GNSS_SOURCE_LOCAL or CHRE_GNSS_SOURCE_UNSPECIFIED will elicit the same
+ * behavior as chreGnssMeasurementSessionStartAsync(), including when run on
+ * CHRE versions prior to v1.11.
+ *
+ * @param minIntervalMs The desired minimum interval between measurement reports
+ *        delivered via CHRE_EVENT_GNSS_DATA. When requested at 1000ms or
+ *        faster, and GNSS measurements are tracked, device should report
+ *        measurements as fast as requested, and shall report no slower than
+ *        once every 1000ms, on average.
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *        sent in relation to this request.
+ * @param source The source of the GNSS data to request.
+ *
+ * @return true if the request was accepted for processing, false otherwise
+ *
+ * @since v1.11
+ * @note Requires GNSS permission
+ */
+bool chreGnssMeasurementSessionStartAsyncV1_11(uint32_t minIntervalMs,
+                                               const void *cookie,
+                                               enum chreGnssSource source);
+
+/**
+ * Terminates an existing raw GNSS measurement session. If no measurement
+ * session is active at the time of this request, it is treated as if an active
+ * session was successfully ended.
+ *
+ * This result of this request is delivered asynchronously via an event of type
+ * CHRE_EVENT_GNSS_ASYNC_RESULT. Refer to the note in {@link #chreAsyncResult}
+ * for more details.
+ *
+ * If chreGnssGetCapabilities() returns a value that does not have the
+ * CHRE_GNSS_CAPABILITIES_MEASUREMENTS flag set, then this method will return
+ * false.
+ *
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *        sent in relation to this request.
+ *
+ * @return true if the request was accepted for processing, false otherwise
+ *
+ * @since v1.1
+ * @note Requires GNSS permission
+ */
+bool chreGnssMeasurementSessionStopAsync(const void *cookie);
+
+/**
+ * Controls whether this nanoapp will passively receive GNSS-based location
+ * fixes produced as a result of location sessions initiated by other entities.
+ * This function allows a nanoapp to opportunistically receive location fixes
+ * via CHRE_EVENT_GNSS_LOCATION events without imposing additional power cost,
+ * though with no guarantees as to when or how often those events will arrive.
+ * There will be no duplication of events if a passive location listener and
+ * location session are enabled in parallel.
+ *
+ * Enabling passive location listening is not required to receive events for an
+ * active location session started via chreGnssLocationSessionStartAsync(). This
+ * setting is independent of the active location session, so modifying one does
+ * not have an effect on the other.
+ *
+ * If chreGnssGetCapabilities() returns a value that does not have the
+ * CHRE_GNSS_CAPABILITIES_LOCATION flag set or the value returned by
+ * chreGetApiVersion() is less than CHRE_API_VERSION_1_2, then this method will
+ * return false.
+ *
+ * If chreGnssGetCapabilities() includes
+ * CHRE_GNSS_CAPABILITIES_GNSS_ENGINE_BASED_PASSIVE_LISTENER, the passive
+ * registration is recorded at the GNSS engine level, so events include fixes
+ * requested by the applications processor and potentially other non-CHRE
+ * clients. If this flag is not set, then only fixes requested by other nanoapps
+ * within CHRE are provided.
+ *
+ * @param enable true to receive opportunistic location fixes, false to disable
+ *
+ * @return true if the configuration was processed successfully, false on error
+ *     or if this feature is not supported
+ *
+ * @since v1.2
+ * @note Requires GNSS permission
+ */
+bool chreGnssConfigurePassiveLocationListener(bool enable);
+
+#else  /* defined(CHRE_NANOAPP_USES_GNSS) || !defined(CHRE_IS_NANOAPP_BUILD) */
+#define CHRE_GNSS_PERM_ERROR_STRING \
+    "CHRE_NANOAPP_USES_GNSS must be defined when building this nanoapp in " \
+    "order to refer to "
+#define chreGnssLocationSessionStartAsync(...) \
+    CHRE_BUILD_ERROR(CHRE_GNSS_PERM_ERROR_STRING \
+                     "chreGnssLocationSessionStartAsync")
+#define chreGnssLocationSessionStopAsync(...) \
+    CHRE_BUILD_ERROR(CHRE_GNSS_PERM_ERROR_STRING \
+                     "chreGnssLocationSessionStopAsync")
+#define chreGnssMeasurementSessionStartAsync(...) \
+    CHRE_BUILD_ERROR(CHRE_GNSS_PERM_ERROR_STRING \
+                     "chreGnssMeasurementSessionStartAsync")
+#define chreGnssMeasurementSessionStopAsync(...) \
+    CHRE_BUILD_ERROR(CHRE_GNSS_PERM_ERROR_STRING \
+                     "chreGnssMeasurementSessionStopAsync")
+#define chreGnssConfigurePassiveLocationListener(...) \
+    CHRE_BUILD_ERROR(CHRE_GNSS_PERM_ERROR_STRING \
+                     "chreGnssConfigurePassiveLocationListener")
+#endif  /* defined(CHRE_NANOAPP_USES_GNSS) || !defined(CHRE_IS_NANOAPP_BUILD) */
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* _CHRE_GNSS_H_ */
diff --git a/chre_api/legacy/v1_11/chre/msg.h b/chre_api/legacy/v1_11/chre/msg.h
new file mode 100644
index 00000000..ab58b62f
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/msg.h
@@ -0,0 +1,644 @@
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_MSG_H_
+#define _CHRE_MSG_H_
+
+/**
+ * @file
+ * Context Hub Runtime Environment API for session-based messaging with generic
+ * endpoints.
+ *
+ * Key concepts:
+ * - **Endpoint**: an entity in the system that can send and receive messages.
+ *   Example endpoints include nanoapps, other offload components outside of
+ *   CHRE, privileged Android applications or Android system components
+ *   (registered via the ContextHubManager.registerEndpoint() API), vendor
+ *   processes (e.g. HALs) registered with the Context Hub HAL, etc.
+ * - **Message**: a datagram sent over a session.
+ * - **Session**: an active connection between two endpoints, optionally scoped
+ *   to a specific service. All messages must be sent over an established
+ *   session. A session will be automatically closed if sending a message fails
+ *   or the remote endpoint otherwise disconnects.
+ * - **Service**: a defined interface and wire format associated with some
+ *   functionality. Endpoints can choose to not register any services, for
+ *   example in cases where the endpoint only functions as a client, or if its
+ *   interface is implied and internal (e.g. a nanoapp that is tightly coupled
+ *   with its host-side code). Endpoints may also register 1 or more services,
+ *   and multiple endpoints may register the same service. This enables
+ *   abstraction between the interface/functionality and the entity/endpoint
+ *   that implements it.
+ *
+ * This API provides a single interface for nanoapps to communicate with other
+ * parts of the system, regardless of location.  Nanoapps should use these APIs
+ * rather than chreSendEvent(), chreSendMessageToHostEndpoint(), and related
+ * APIs if they do not need to support Android versions prior to Android 16 nor
+ * CHRE APIs older than v1.11.
+ *
+ * The general order of API usage as a client (session initiator) is:
+ *
+ * 1. The nanoapp should know the target service and/or endpoint ID it wants to
+ *    interact with, and optionally the target hub ID, and provide this to
+ *    chreMsgConfigureEndpointReadyEvents() or
+ *    chreMsgConfigureServiceReadyEvents().
+ * 2. The nanoapp will receive an event when a suitable endpoint is found. The
+ *    nanoapp then calls chreMsgSessionOpenAsync() to initiate communication.
+ * 3. Once the session is established, the nanoapp receives a
+ *    CHRE_EVENT_MSG_SESSION_OPENED event. If a failure occurred or the target
+ *    endpoint did not accept the session, a CHRE_EVENT_MSG_SESSION_CLOSED event
+ *    will be provided instead.
+ * 4. Assuming the session was opened successfully, the nanoapp can now send
+ *    messages over the session using chreMsgSend() and will receive messages
+ *    via CHRE_EVENT_MSG_FROM_ENDPOINT.
+ * 5. The session may be left open indefinitely, or closed by either endpoint,
+ *    or by the system on error or if one endpoint crashes/disconnects. If the
+ *    target endpoint crashes and then recovers, a new ready event will be
+ *    generated and communication can resume at step 2.
+ *
+ * As a server (session responder), the high-level flow is:
+ *
+ * 1. (Optional) Register one or more services via chreMsgPublishServices().
+ * 2. The nanoapp receives CHRE_EVENT_MSG_SESSION_OPENED when another endpoint
+ *    initiates a session. The session can either be used immediately, or the
+ *    nanoapp can use chreMsgSessionCloseAsync() to reject the session.
+ * 3. Once a session is established, it functions the same regardless of which
+ *    endpoint initiated the session.
+ *
+ * @since v1.11
+ */
+
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <stdlib.h>
+
+#include <chre/common.h>
+#include <chre/event.h>
+#include <chre/toolchain.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * The type of endpoint.
+ * Backing type: uint32_t.
+ */
+enum chreMsgEndpointType {
+  CHRE_MSG_ENDPOINT_TYPE_INVALID = 0,
+  CHRE_MSG_ENDPOINT_TYPE_HOST_FRAMEWORK = 1,
+  CHRE_MSG_ENDPOINT_TYPE_HOST_APP = 2,
+  CHRE_MSG_ENDPOINT_TYPE_HOST_NATIVE = 3,
+  CHRE_MSG_ENDPOINT_TYPE_NANOAPP = 4,
+  CHRE_MSG_ENDPOINT_TYPE_GENERIC = 5,
+};
+
+/**
+ * The service RPC format.
+ * Backing type: uint32_t.
+ */
+enum chreMsgEndpointServiceFormat {
+  CHRE_MSG_ENDPOINT_SERVICE_FORMAT_INVALID = 0,
+  CHRE_MSG_ENDPOINT_SERVICE_FORMAT_CUSTOM = 1,
+  CHRE_MSG_ENDPOINT_SERVICE_FORMAT_AIDL = 2,
+  CHRE_MSG_ENDPOINT_SERVICE_FORMAT_PW_RPC_PROTOBUF = 3,
+};
+
+/**
+ * The reason for a session closure event or an endpoint notification
+ * event.
+ * Backing type: uint8_t.
+ */
+enum chreMsgEndpointReason {
+  CHRE_MSG_ENDPOINT_REASON_UNSPECIFIED = 0,
+  CHRE_MSG_ENDPOINT_REASON_OUT_OF_MEMORY = 1,
+  CHRE_MSG_ENDPOINT_REASON_TIMEOUT = 2,
+  CHRE_MSG_ENDPOINT_REASON_OPEN_ENDPOINT_SESSION_REQUEST_REJECTED = 3,
+  CHRE_MSG_ENDPOINT_REASON_CLOSE_ENDPOINT_SESSION_REQUESTED = 4,
+  CHRE_MSG_ENDPOINT_REASON_ENDPOINT_INVALID = 5,
+  CHRE_MSG_ENDPOINT_REASON_ENDPOINT_GONE = 6,
+  CHRE_MSG_ENDPOINT_REASON_ENDPOINT_CRASHED = 7,
+  CHRE_MSG_ENDPOINT_REASON_HUB_RESET = 8,
+  CHRE_MSG_ENDPOINT_REASON_PERMISSION_DENIED = 9,
+};
+
+/**
+ * The message hub ID reserved for the Android framework (Context Hub Service).
+ */
+#define CHRE_MSG_HUB_ID_ANDROID UINT64_C(0x416E64726F696400)
+
+#define CHRE_MSG_HUB_ID_INVALID UINT64_C(0)
+#define CHRE_MSG_HUB_ID_RESERVED UINT64_C(-1)
+#define CHRE_MSG_ENDPOINT_ID_INVALID UINT64_C(0)
+#define CHRE_MSG_ENDPOINT_ID_RESERVED UINT64_C(-1)
+#define CHRE_MSG_SESSION_ID_INVALID UINT16_MAX
+
+/**
+ * Wildcard hub ID for use with chreMsgConfigureEndpointReadyEvents() and
+ * chreMsgConfigureServiceReadyEvents().
+ */
+#define CHRE_MSG_HUB_ID_ANY CHRE_MSG_HUB_ID_INVALID
+
+/**
+ * Wildcard endpoint ID for use with chreMsgConfigureEndpointReadyEvents() and
+ * chreMsgSessionOpenAsync().
+ */
+#define CHRE_MSG_ENDPOINT_ID_ANY CHRE_MSG_ENDPOINT_ID_INVALID
+
+/**
+ * The maximum length of an endpoint's name.
+ */
+#define CHRE_MSG_MAX_NAME_LEN (51)
+
+/**
+ * The maximum length of a service descriptor (including null terminator).
+ */
+#define CHRE_MSG_MAX_SERVICE_DESCRIPTOR_LEN (128)
+
+/**
+ * @see chreMsgPublishServices
+ */
+#define CHRE_MSG_MINIMUM_SERVICE_LIMIT UINT8_C(4)
+
+/**
+ * Produce an event ID in the block of IDs reserved for session-based messaging.
+ *
+ * Valid input range is [0, 15]. Do not add new events with ID > 15
+ * (see chre/event.h)
+ *
+ * @param offset Index into MSG event ID block; valid range is [0, 15].
+ *
+ * @defgroup CHRE_MSG_EVENT_ID
+ * @{
+ */
+#define CHRE_MSG_EVENT_ID(offset) (CHRE_EVENT_MSG_FIRST_EVENT + (offset))
+
+/**
+ * nanoappHandleEvent argument: struct chreMsgMessageFromEndpointData
+ *
+ * The format of the 'message' part of this structure is left undefined,
+ * and it's up to the nanoapp and endpoint to have an established protocol
+ * beforehand.
+ *
+ * On receiving the first message from an endpoint, the nanoapp can assume
+ * a session with the sessionId has been created and can be used to send
+ * messages to the endpoint. The nanoapp will receive a
+ * CHRE_EVENT_MSG_SESSION_CLOSED event when the session is closed.
+ *
+ * @since v1.11
+ */
+#define CHRE_EVENT_MSG_FROM_ENDPOINT CHRE_MSG_EVENT_ID(0)
+
+/**
+ * nanoappHandleEvent argument: struct chreMsgSessionInfo
+ *
+ * Indicates that a session with an endpoint has been opened.
+ *
+ * @since v1.11
+ */
+#define CHRE_EVENT_MSG_SESSION_OPENED CHRE_MSG_EVENT_ID(1)
+
+/**
+ * nanoappHandleEvent argument: struct chreMsgSessionInfo
+ *
+ * Indicates that a session with an endpoint has been closed.
+ *
+ * @since v1.11
+ */
+#define CHRE_EVENT_MSG_SESSION_CLOSED CHRE_MSG_EVENT_ID(2)
+
+/**
+ * nanoappHandleEvent argument: struct chreMsgEndpointReadyEvent
+ *
+ * Notifications event regarding a generic endpoint.
+ *
+ * @see chreConfigureEndpointNotifications
+ * @since v1.11
+ */
+#define CHRE_EVENT_MSG_ENDPOINT_READY CHRE_MSG_EVENT_ID(3)
+
+/**
+ * nanoappHandleEvent argument: struct chreMsgServiceReadyEvent
+ *
+ * Notifications event regarding a generic endpoint with a service.
+ *
+ * @see chreConfigureEndpointServiceNotifications
+ * @since v1.11
+ */
+#define CHRE_EVENT_MSG_SERVICE_READY CHRE_MSG_EVENT_ID(4)
+
+// NOTE: Do not add new events with ID > 15
+/** @} */
+
+/**
+ * Provides metadata for an endpoint.
+ */
+struct chreMsgEndpointInfo {
+  /**
+   * The message hub ID and endpoint ID of the endpoint.
+   */
+  uint64_t hubId;
+  uint64_t endpointId;
+
+  /**
+   * The type of the endpoint. One of chreMsgEndpointType enum values.
+   */
+  uint32_t type;
+
+  /**
+   * The version of the endpoint.
+   */
+  uint32_t version;
+
+  /**
+   * The required permissions of the endpoint, a bitmask of
+   * CHRE_MESSAGE_PERMISSION_* values.
+   */
+  uint32_t requiredPermissions;
+
+  /**
+   * The maximum size of a message that can be sent to the endpoint.
+   *
+   * For endpoints on CHRE_MSG_HUB_ID_ANDROID, this is the same as
+   * chreGetMessageToHostMaxSize().
+   */
+  uint32_t maxMessageSize;
+
+  /**
+   * The name of the endpoint, an ASCII null-terminated string. This name is
+   * specified by the endpoint when it is registered by its message hub.
+   */
+  char name[CHRE_MSG_MAX_NAME_LEN];
+};
+
+/**
+ * Provides metadata for an endpoint service.
+ */
+struct chreMsgServiceInfo {
+  /**
+   * The major version of the service.
+   */
+  uint32_t majorVersion;
+
+  /**
+   * The minor version of the service.
+   */
+  uint32_t minorVersion;
+
+  /**
+   * The descriptor of the service, an ASCII null-terminated string. This must
+   * be valid for the lifetime of the nanoapp.
+   */
+  const char *serviceDescriptor;
+
+  /**
+   * The format of the service. One of chreMsgEndpointServiceFormat enum values.
+   */
+  uint32_t serviceFormat;
+};
+
+/**
+ * Data provided with CHRE_EVENT_MSG_SESSION_OPENED,
+ * CHRE_EVENT_MSG_SESSION_CLOSED or chreGetSessionInfo().
+ */
+struct chreMsgSessionInfo {
+  /**
+   * The message hub ID and endpoint ID of the other party in the session.
+   */
+  uint64_t hubId;
+  uint64_t endpointId;
+
+  /**
+   * The descriptor of the service, an ASCII null-terminated string. This
+   * will be an empty string if the session was not opened with a service.
+   */
+  char serviceDescriptor[CHRE_MSG_MAX_SERVICE_DESCRIPTOR_LEN];
+
+  /**
+   * The ID of the session.
+   */
+  uint16_t sessionId;
+
+  /**
+   * The reason for the event. Used for sessions closure. For all other uses,
+   * this value will be CHRE_MSG_ENDPOINT_REASON_UNSPECIFIED. One of
+   * chreMsgEndpointReason enum values.
+   */
+  uint8_t reason;
+};
+
+/**
+ * Data provided with CHRE_EVENT_MSG_FROM_ENDPOINT.
+ */
+struct chreMsgMessageFromEndpointData {
+  /**
+   * Message type supplied by the endpoint.
+   */
+  uint32_t messageType;
+
+  /**
+   * Message permissions supplied by the endpoint. The format is specified by
+   * the CHRE_MESSAGE_PERMISSION_* values if the endpoint is a nanoapp, else
+   * it is specified by the endpoint. These permissions are enforced by CHRE.
+   * A nanoapp without the required permissions will not receive the message.
+   */
+  uint32_t messagePermissions;
+
+  /**
+   * The message from the endpoint.
+   *
+   * These contents are of a format that the endpoint and nanoapp must have
+   * established beforehand.
+   *
+   * This data is 'messageSize' bytes in length.  Note that if 'messageSize'
+   * is 0, this might contain NULL.
+   */
+  const void *message;
+
+  /**
+   * The size, in bytes of the following 'message'.
+   *
+   * This can be 0.
+   */
+  size_t messageSize;
+
+  /**
+   * The session ID of the message. A session is the active connection between
+   * two endpoints. The receiving nanoapp or endpoint initiated the session
+   * before sending this message. If the nanoapp has not yet received a
+   * message with this session ID, it can assume the session was created by
+   * the nanoapp or other endpoint. The nanoapp may send messages to the other
+   * endpoint with this session ID.
+   */
+  uint16_t sessionId;
+};
+
+/**
+ * Data provided in CHRE_EVENT_MSG_ENDPOINT_READY.
+ */
+struct chreMsgEndpointReadyEvent {
+  /**
+   * The message hub ID and endpoint ID of the endpoint.
+   */
+  uint64_t hubId;
+  uint64_t endpointId;
+};
+
+/**
+ * Data provided in CHRE_EVENT_MSG_SERVICE_READY.
+ */
+struct chreMsgServiceReadyEvent {
+  /**
+   * The message hub ID and endpoint ID of the endpoint.
+   */
+  uint64_t hubId;
+  uint64_t endpointId;
+
+  /**
+   * The descriptor of the service, an ASCII null-terminated string.
+   */
+  char serviceDescriptor[CHRE_MSG_MAX_SERVICE_DESCRIPTOR_LEN];
+};
+
+/**
+ * Retrieves metadata for a given endpoint.
+ *
+ * If the given message hub ID and endpoint ID are not associated with a valid
+ * endpoint, this method will return false and info will not be populated.
+ *
+ * @param hubId The message hub ID of the endpoint for which to get info.
+ * @param endpointId The endpoint ID of the endpoint for which to get info.
+ * @param info The non-null pointer to where the metadata will be stored.
+ *
+ * @return true if info has been successfully populated.
+ *
+ * @since v1.11
+ */
+bool chreMsgGetEndpointInfo(uint64_t hubId, uint64_t endpointId,
+                            struct chreMsgEndpointInfo *info);
+
+/**
+ * Configures whether this nanoapp will receive updates regarding an endpoint
+ * that is connected with a message hub and a specific service.  The hubId can
+ * be CHRE_MSG_HUB_ID_ANY to configure notifications for matching endpoints that
+ * are connected with any message hub. The endpoint ID can be
+ * CHRE_MSG_ENDPOINT_ID_ANY to configure notifications for all endpoints that
+ * match the given hub.
+ *
+ * If this API succeeds, the nanoapp will receive endpoint notifications via
+ * CHRE_EVENT_MSG_ENDPOINT_READY with chreMsgEndpointReadyEvent.
+ *
+ * If one or more endpoints matching the filter are already ready when this
+ * function is called, CHRE_EVENT_MSG_ENDPOINT_READY will be immediately
+ * posted to this nanoapp.
+ *
+ * @param hubId The message hub ID of the endpoint for which to configure
+ *     notifications for all endpoints that are connected with any message hub.
+ * @param endpointId The endpoint ID of the endpoint for which to configure
+ *     notifications.
+ * @param enable true to enable notifications.
+ *
+ * @return true on success
+ *
+ * @since v1.11
+ */
+bool chreMsgConfigureEndpointReadyEvents(uint64_t hubId, uint64_t endpointId,
+                                         bool enable);
+
+/**
+ * Configures whether this nanoapp will receive updates regarding all endpoints
+ * that are connected with the message hub that provide the specified service.
+ *
+ * If this API succeeds, the nanoapp will receive endpoint notifications via
+ * CHRE_EVENT_MSG_SERVICE_READY with chreMsgServiceReadyEvent.
+ *
+ * If one or more endpoints matching the filter are already ready when this
+ * function is called, CHRE_EVENT_MSG_SERVICE_READY will be immediately posted
+ * to this nanoapp.
+ *
+ * @param hubId The message hub ID of the endpoint for which to configure
+ *     notifications for all endpoints that are connected with any message hub.
+ * @param serviceDescriptor The descriptor of the service associated with the
+ *     endpoint for which to configure notifications, a null-terminated ASCII
+ *     string. If not NULL, the underlying memory must outlive the notifications
+ *     configuration. If NULL, this will return false.
+ * @param enable true to enable notifications.
+ *
+ * @return true on success
+ *
+ * @see chreMsgConfigureEndpointReadyEvents
+ * @since v1.11
+ */
+bool chreMsgConfigureServiceReadyEvents(uint64_t hubId,
+                                        const char *serviceDescriptor,
+                                        bool enable);
+
+/**
+ * Retrieves metadata for a currently active session ID.
+ *
+ * If the given session ID is not associated with a valid session or if the
+ * caller nanoapp is not a participant in the session, this method will return
+ * false and info will not be populated.
+ *
+ * @param sessionId The session ID of the session for which to get info.
+ * @param info The non-null pointer to where the metadata will be stored.
+ *
+ * @return true if info has been successfully populated.
+ *
+ * @since v1.11
+ */
+bool chreMsgSessionGetInfo(uint16_t sessionId, struct chreMsgSessionInfo *info);
+
+/**
+ * Publishes services exposed by this nanoapp, which will be included with the
+ * endpoint metadata visible to other endpoints in the system.
+ *
+ * This function must be invoked from nanoappStart(), which ensures stable
+ * output of the list of services supported by the nanoapp. Calls made outside
+ * of nanoappStart() will have no effect.
+ *
+ * Although nanoapps are recommended to only call this API once with all
+ * services it intends to publish, if called multiple times, each call will
+ * append to the list of published services.
+ *
+ * The implementation must allow for a nanoapp to publish at least
+ * CHRE_MSG_MINIMUM_SERVICE_LIMIT services and at most UINT8_MAX services. If
+ * calling this function would result in exceeding the limit, the services must
+ * not be published and it must return false.
+ *
+ * @param services A non-null pointer to the list of services to publish.
+ * @param numServices The number of services to publish, i.e. the length of the
+ *     services array.
+ *
+ * @return true if the publishing is successful.
+ *
+ * @since v1.11
+ */
+bool chreMsgPublishServices(const struct chreMsgServiceInfo *services,
+                            size_t numServices);
+
+/**
+ * Opens a session with an endpoint.
+ *
+ * If this function returns true, the result of session initiation will be
+ * provided by a CHRE_EVENT_MSG_SESSION_OPENED or CHRE_EVENT_MSG_SESSION_CLOSED
+ * event containing the same hub ID, endpoint ID, and service descriptor
+ * parameters. Nanoapps may only open one session for each unique combination of
+ * parameters.
+ *
+ * @param hubId The message hub ID of the endpoint. Can be CHRE_MSG_HUB_ID_ANY
+ *     to open a session with the default endpoint.
+ * @param endpointId The endpoint ID of the endpoint. Can be
+ *     CHRE_MSG_ENDPOINT_ID_ANY to open a session with a specified service. The
+ *     service cannot be NULL in this case.
+ * @param serviceDescriptor The descriptor of the service associated with the
+ *     endpoint with which to open the session, a null-terminated ASCII string.
+ *     Can be NULL. The underlying memory must remain valid at least until the
+ *     session is closed - for example, it should be a pointer to a static const
+ *     variable hard-coded in the nanoapp.
+ *     NOTE: as event data supplied to nanoapps does not live beyond the
+ *     nanoappHandleEvent() invocation, it is NOT valid to use the serviceData
+ *     array provided inside chreMsgServiceReadyEvent here.
+ *
+ * @return true if the request was successfully dispatched, or false if a
+ *     synchronous error occurred, in which case no subsequent event will be
+ *     sent.
+ *
+ * @since v1.11
+ */
+bool chreMsgSessionOpenAsync(uint64_t hubId, uint64_t endpointId,
+                             const char *serviceDescriptor);
+
+/**
+ * Closes a session with an endpoint.
+ *
+ * If the given session ID is not associated with a valid session or if the
+ * calling nanoapp is not a participant in the session, this method will return
+ * false.
+ *
+ * The nanoapp will receive a CHRE_EVENT_MSG_SESSION_CLOSED event when the
+ * session teardown is complete. The session is immediately unavailable for
+ * sending. It is unspecified whether any in-flight messages sent by the
+ * other endpoint will be received prior to CHRE_EVENT_MSG_SESSION_CLOSED, but
+ * once this event is delivered, no further data will be received.
+ *
+ * @param sessionId ID of the session to close.
+ *
+ * @return true if the session closure process was initiated.
+ *
+ * @since v1.11
+ */
+bool chreMsgSessionCloseAsync(uint16_t sessionId);
+
+/**
+ * Send a message to an endpoint over an active session.
+ *
+ * This is similar to the stateless host message APIs, such as
+ * chreSendMessageWithPermissions(), but it supports sending data to an
+ * arbitrary endpoint, which could be a host app, another nanoapp, or something
+ * else.
+ *
+ * Messages are guaranteed to be delivered in the order they were sent. If an
+ * error occurs while attempting to deliver the message, the session will be
+ * closed by the system with a suitable reason provided in the data sent with
+ * CHRE_EVENT_MSG_SESSION_CLOSED. While this covers most scenarios, no explicit
+ * end-to-end acknowledgement is provided, and any internal timeouts and/or
+ * retries are implementation-dependent. Similar to chreMsgSessionCloseAsync(),
+ * if the session is closed by the other endpoint or system, it is unspecified
+ * whether any in-flight messages were delivered. The option to send reliable
+ * messages over a socket is planned for a future release. In the meantime, if
+ * full reliability is desired for host communication, use
+ * chreSendReliableMessageAsync().
+ *
+ * @param message Pointer to a block of memory to send to the other endpoint in
+ *     this session. NULL is acceptable only if messageSize is 0. This function
+ *     transfers ownership of the provided memory to the system, so the data
+ *     must stay valid and unmodified until freeCallback is invoked.
+ * @param messageSize The size, in bytes, of the given message. Maximum allowed
+ *     size for the destination endpoint is provided in chreMsgEndpointInfo.
+ * @param messageType An opaque value passed along with the message payload,
+ *     using an application/service-defined scheme.
+ * @param sessionId The session over which to send this message, which also
+ *     implicitly identifies the destination service (if used), endpoint, and
+ *     hub. Provided in chreMsgSessionInfo.
+ * @param messagePermissions Bitmask of permissions that must be held to receive
+ *     this message, and will be attributed to the recipient. Primarily relevant
+ *     when the destination endpoint is an Android application. Refer to
+ *     CHRE_MESSAGE_PERMISSION_* values.
+ * @param freeCallback Invoked when the system no longer needs the memory
+ *     holding the message. Note that this does not necessarily mean that the
+ *     message has been delivered. If message is non-NULL, this must be
+ *     non-NULL, and if message is NULL, this must be NULL.
+ *
+ * @return true if the message was accepted for transmission, false otherwise.
+ *     Note that even if this method returns false, the freeCallback will be
+ *     invoked, if non-NULL. In either case, the freeCallback may be invoked
+ *     synchronously, so it must not call chreMsgSend() to avoid recursion.
+ *
+ * @since v1.11
+ */
+bool chreMsgSend(void *message, size_t messageSize, uint32_t messageType,
+                 uint16_t sessionId, uint32_t messagePermissions,
+                 chreMessageFreeFunction *freeCallback);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif /* _CHRE_MSG_H_ */
diff --git a/chre_api/legacy/v1_11/chre/nanoapp.h b/chre_api/legacy/v1_11/chre/nanoapp.h
new file mode 100644
index 00000000..3a1c3628
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/nanoapp.h
@@ -0,0 +1,96 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_NANOAPP_H_
+#define _CHRE_NANOAPP_H_
+
+/**
+ * @file
+ * Methods in the Context Hub Runtime Environment which must be implemented
+ * by the nanoapp.
+ */
+
+#include <stdbool.h>
+#include <stdint.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * Method invoked by the CHRE when loading the nanoapp.
+ *
+ * Every CHRE method is legal to call from this method.
+ *
+ * @return  'true' if the nanoapp successfully started.  'false' if the nanoapp
+ *     failed to properly initialize itself (for example, could not obtain
+ *     sufficient memory from the heap).  If this method returns 'false', the
+ *     nanoapp will be unloaded by the CHRE (and nanoappEnd will
+ *     _not_ be invoked in that case).
+ * @see nanoappEnd
+ */
+bool nanoappStart(void);
+
+/**
+ * Method invoked by the CHRE when there is an event for this nanoapp.
+ *
+ * Every CHRE method is legal to call from this method.
+ *
+ * @param senderInstanceId  The Instance ID for the source of this event.
+ *     Note that this may be CHRE_INSTANCE_ID, indicating that the event
+ *     was generated by the CHRE.
+ * @param eventType  The event type.  This might be one of the CHRE_EVENT_*
+ *     types defined in this API.  But it might also be a user-defined event.
+ * @param eventData  The associated data, if any, for this specific type of
+ *     event.  From the nanoapp's perspective, this eventData's lifetime ends
+ *     when this method returns, and thus any data the nanoapp wishes to
+ *     retain must be copied.  Note that interpretation of event data is
+ *     given by the event type, and for some events may not be a valid
+ *     pointer.  See documentation of the specific CHRE_EVENT_* types for how to
+ *     interpret this data for those.  Note that for user events, you will
+ *     need to establish what this data means.
+ */
+void nanoappHandleEvent(uint32_t senderInstanceId, uint16_t eventType,
+                        const void *eventData);
+
+/**
+ * Method invoked by the CHRE when unloading the nanoapp.
+ *
+ * It is not valid to attempt to send events or messages, or to invoke functions
+ * which will generate events to this app, within the nanoapp implementation of
+ * this function.  That means it is illegal for the nanoapp invoke any of the
+ * following:
+ *
+ * - chreSendEvent()
+ * - chreSendMessageToHost()
+ * - chreSensorConfigure()
+ * - chreSensorConfigureModeOnly()
+ * - chreTimerSet()
+ * - etc.
+ *
+ * @see nanoappStart
+ */
+void nanoappEnd(void);
+
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* _CHRE_NANOAPP_H_ */
diff --git a/chre_api/legacy/v1_11/chre/re.h b/chre_api/legacy/v1_11/chre/re.h
new file mode 100644
index 00000000..3987b013
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/re.h
@@ -0,0 +1,496 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_RE_H_
+#define _CHRE_RE_H_
+
+/**
+ * @file
+ * Some of the core Runtime Environment utilities of the Context Hub
+ * Runtime Environment.
+ *
+ * This includes functions for memory allocation, logging, and timers.
+ */
+
+#include <stdarg.h>
+#include <stdbool.h>
+#include <stdint.h>
+#include <stdlib.h>
+
+#include <chre/toolchain.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * The instance ID for the CHRE.
+ *
+ * This ID is used to identify events generated by the CHRE (as
+ * opposed to events generated by another nanoapp).
+ */
+#define CHRE_INSTANCE_ID  UINT32_C(0)
+
+/**
+ * A timer ID representing an invalid timer.
+ *
+ * This valid is returned by chreTimerSet() if a timer cannot be
+ * started.
+ */
+#define CHRE_TIMER_INVALID  UINT32_C(-1)
+
+
+/**
+ * The maximum size, in characters including null terminator, guaranteed for
+ * logging debug data with one call of chreDebugDumpLog() without getting
+ * truncated.
+ *
+ * @see chreDebugDumpLog
+ * @since v1.4
+ */
+#define CHRE_DEBUG_DUMP_MINIMUM_MAX_SIZE 1000
+
+/**
+ * The set of flags that may be returned by chreGetCapabilities()
+ * @defgroup CHRE_CAPABILITIES
+ * @{
+ */
+
+//! None of the optional capabilities are supported
+#define CHRE_CAPABILITIES_NONE                          (UINT32_C(0))
+
+//! Support for reliable messages.
+//! @see chreSendReliableMessageAsync
+#define CHRE_CAPABILITIES_RELIABLE_MESSAGES             (UINT32_C(1) << 0)
+
+//! Support for generic endpoint messaging.
+//! @see chreMsgSend
+#define CHRE_CAPABILITIES_GENERIC_ENDPOINT_MESSAGES     (UINT32_C(1) << 1)
+
+/** @} */
+
+/**
+ * Logging levels used to indicate severity level of logging messages.
+ *
+ * CHRE_LOG_ERROR: Something fatal has happened, i.e. something that will have
+ *     user-visible consequences and won't be recoverable without explicitly
+ *     deleting some data, uninstalling applications, wiping the data
+ *     partitions or reflashing the entire phone (or worse).
+ * CHRE_LOG_WARN: Something that will have user-visible consequences but is
+ *     likely to be recoverable without data loss by performing some explicit
+ *     action, ranging from waiting or restarting an app all the way to
+ *     re-downloading a new version of an application or rebooting the device.
+ * CHRE_LOG_INFO: Something interesting to most people happened, i.e. when a
+ *     situation is detected that is likely to have widespread impact, though
+ *     isn't necessarily an error.
+ * CHRE_LOG_DEBUG: Used to further note what is happening on the device that
+ *     could be relevant to investigate and debug unexpected behaviors. You
+ *     should log only what is needed to gather enough information about what
+ *     is going on about your component.
+ *
+ * There is currently no API to turn on/off logging by level, but we anticipate
+ * adding such in future releases.
+ *
+ * @see chreLog
+ */
+enum chreLogLevel {
+    CHRE_LOG_ERROR,
+    CHRE_LOG_WARN,
+    CHRE_LOG_INFO,
+    CHRE_LOG_DEBUG
+};
+
+/**
+ * Retrieves a set of flags indicating the CHRE optional features supported by
+ * the current implementation. The value returned by this function must be
+ * consistent for the entire duration of the nanoapp's execution.
+ *
+ * The client must allow for more flags to be set in this response than it knows
+ * about, for example if the implementation supports a newer version of the API
+ * than the client was compiled against.
+ *
+ * @return A bitmask with zero or more CHRE_CAPABILITIES_* flags set.
+ *
+ * @since v1.10
+ */
+uint32_t chreGetCapabilities(void);
+
+/**
+ * Returns the maximum size in bytes of a message sent to the host.
+ * This function will always return a value greater than or equal to
+ * CHRE_MESSAGE_TO_HOST_MAX_SIZE. If the capability
+ * CHRE_CAPABILITIES_RELIABLE_MESSAGES is enabled, this function will
+ * return a value greater than or equal to 32000.
+ *
+ * On v1.9 or earlier platforms, this will always return CHRE_MESSAGE_TO_HOST_MAX_SIZE.
+ *
+ * @return The maximum message size in bytes.
+ *
+ * @since v1.10
+ */
+uint32_t chreGetMessageToHostMaxSize(void);
+
+/**
+ * Get the application ID.
+ *
+ * The application ID is set by the loader of the nanoapp.  This is not
+ * assured to be unique among all nanoapps running in the system.
+ *
+ * @return The application ID.
+ */
+uint64_t chreGetAppId(void);
+
+/**
+ * Get the instance ID.
+ *
+ * The instance ID is the CHRE handle to this nanoapp.  This is assured
+ * to be unique among all nanoapps running in the system, and to be
+ * different from the CHRE_INSTANCE_ID.  This is the ID used to communicate
+ * between nanoapps.
+ *
+ * @return The instance ID
+ */
+uint32_t chreGetInstanceId(void);
+
+/**
+ * A method for logging information about the system.
+ *
+ * The chreLog logging activity alone must not cause host wake-ups. For
+ * example, logs could be buffered in internal memory when the host is asleep,
+ * and delivered when appropriate (e.g. the host wakes up). If done this way,
+ * the internal buffer is recommended to be large enough (at least a few KB), so
+ * that multiple messages can be buffered. When these logs are sent to the host,
+ * they are strongly recommended to be made visible under the tag 'CHRE' in
+ * logcat - a future version of the CHRE API may make this a hard requirement.
+ *
+ * A log entry can have a variety of levels (@see LogLevel).  This function
+ * allows a variable number of arguments, in a printf-style format.
+ *
+ * A nanoapp needs to be able to rely upon consistent printf format
+ * recognition across any platform, and thus we establish formats which
+ * are required to be handled by every CHRE implementation.  Some of the
+ * integral formats may seem obscure, but this API heavily uses types like
+ * uint32_t and uint16_t.  The platform independent macros for those printf
+ * formats, like PRId32 or PRIx16, end up using some of these "obscure"
+ * formats on some platforms, and thus are required.
+ *
+ * For the initial N release, our emphasis is on correctly getting information
+ * into the log, and minimizing the requirements for CHRE implementations
+ * beyond that.  We're not as concerned about how the information is visually
+ * displayed.  As a result, there are a number of format sub-specifiers which
+ * are "OPTIONAL" for the N implementation.  "OPTIONAL" in this context means
+ * that a CHRE implementation is allowed to essentially ignore the specifier,
+ * but it must understand the specifier enough in order to properly skip it.
+ *
+ * For a nanoapp author, an OPTIONAL format means you might not get exactly
+ * what you want on every CHRE implementation, but you will always get
+ * something valid.
+ *
+ * To be clearer, here's an example with the OPTIONAL 0-padding for integers
+ * for different hypothetical CHRE implementations.
+ * Compliant, chose to implement OPTIONAL format:
+ *   chreLog(level, "%04x", 20) ==> "0014"
+ * Compliant, chose not to implement OPTIONAL format:
+ *   chreLog(level, "%04x", 20) ==> "14"
+ * Non-compliant, discarded format because the '0' was assumed to be incorrect:
+ *   chreLog(level, "%04x", 20) ==> ""
+ *
+ * Note that some of the OPTIONAL specifiers will probably become
+ * required in future APIs.
+ *
+ * We also have NOT_SUPPORTED specifiers.  Nanoapp authors should not use any
+ * NOT_SUPPORTED specifiers, as unexpected things could happen on any given
+ * CHRE implementation.  A CHRE implementation is allowed to support this
+ * (for example, when using shared code which already supports this), but
+ * nanoapp authors need to avoid these.
+ *
+ * Unless specifically noted as OPTIONAL or NOT_SUPPORTED, format
+ * (sub-)specifiers listed below are required.
+ *
+ * While all CHRE implementations must support chreLog(), some platform
+ * implementations may support enhanced logging functionality only possible
+ * through a macro. This improved functionality is supported through
+ * platform-specific customization of the log macros provided in
+ * chre/util/nanoapp/log.h. All nanoapps are recommended to use these log
+ * macros where possible, as they will fall back to chreLog() as needed.
+ *
+ * OPTIONAL format sub-specifiers:
+ * - '-' (left-justify within the given field width)
+ * - '+' (precede the result with a '+' sign if it is positive)
+ * - ' ' (precede the result with a blank space if no sign is going to be
+ *        output)
+ * - '#' (For 'o', 'x' or 'X', precede output with "0", "0x" or "0X",
+ *        respectively.  For floating point, unconditionally output a decimal
+ *        point.)
+ * - '0' (left pad the number with zeroes instead of spaces when <width>
+ *        needs padding)
+ * - <width> (A number representing the minimum number of characters to be
+ *            output, left-padding with blank spaces if needed to meet the
+ *            minimum)
+ * - '.'<precision> (A number which has different meaning depending on context.)
+ *    - Integer context: Minimum number of digits to output, padding with
+ *          leading zeros if needed to meet the minimum.
+ *    - 'f' context: Number of digits to output after the decimal
+ *          point (to the right of it).
+ *    - 's' context: Maximum number of characters to output.
+ *
+ * Integral format specifiers:
+ * - 'd' (signed)
+ * - 'u' (unsigned)
+ * - 'o' (octal)
+ * - 'x' (hexadecimal, lower case)
+ * - 'X' (hexadecimal, upper case)
+ *
+ * Integral format sub-specifiers (as prefixes to an above integral format):
+ * - 'hh' (char)
+ * - 'h' (short)
+ * - 'l' (long)
+ * - 'll' (long long)
+ * - 'z' (size_t)
+ * - 't' (ptrdiff_t)
+ *
+ * Other format specifiers:
+ * - 'f' (floating point)
+ * - 'c' (character)
+ * - 's' (character string, terminated by '\0')
+ * - 'p' (pointer)
+ * - '%' (escaping the percent sign (i.e. "%%" becomes "%"))
+ *
+ * NOT_SUPPORTED specifiers:
+ * - 'n' (output nothing, but fill in a given pointer with the number
+ *        of characters written so far)
+ * - '*' (indicates that the width/precision value comes from one of the
+ *        arguments to the function)
+ * - 'e', 'E' (scientific notation output)
+ * - 'g', 'G' (Shortest floating point representation)
+ *
+ * @param level  The severity level for this message.
+ * @param formatStr  Either the entirety of the message, or a printf-style
+ *     format string of the format documented above.
+ * @param ...  A variable number of arguments necessary for the given
+ *     'formatStr' (there may be no additional arguments for some 'formatStr's).
+ */
+CHRE_PRINTF_ATTR(2, 3)
+void chreLog(enum chreLogLevel level, const char *formatStr, ...);
+
+/**
+ * Get the system time.
+ *
+ * This returns a time in nanoseconds in reference to some arbitrary
+ * time in the past.  This method is only useful for determining timing
+ * between events on the system, and is not useful for determining
+ * any sort of absolute time.
+ *
+ * This value must always increase (and must never roll over).  This
+ * value has no meaning across CHRE reboots.
+ *
+ * @return The system time, in nanoseconds.
+ */
+uint64_t chreGetTime(void);
+
+/**
+ * Retrieves CHRE's current estimated offset between the local CHRE clock
+ * exposed in chreGetTime(), and the host-side clock exposed in the Android API
+ * SystemClock.elapsedRealtimeNanos().  This offset is formed as host time minus
+ * CHRE time, so that it can be added to the value returned by chreGetTime() to
+ * determine the current estimate of the host time.
+ *
+ * A call to this function must not require waking up the host and should return
+ * quickly.
+ *
+ * This function must always return a valid value from the earliest point that
+ * it can be called by a nanoapp.  In other words, it is not valid to return
+ * some fixed/invalid value while waiting for the initial offset estimate to be
+ * determined - this initial offset must be ready before nanoapps are started.
+ *
+ * @return An estimate of the offset between CHRE's time returned in
+ *     chreGetTime() and the time on the host given in the Android API
+ *     SystemClock.elapsedRealtimeNanos(), accurate to within +/- 10
+ *     milliseconds, such that adding this offset to chreGetTime() produces the
+ *     estimated current time on the host.  This value may change over time to
+ *     account for drift, etc., so multiple calls to this API may produce
+ *     different results.
+ *
+ * @since v1.1
+ */
+int64_t chreGetEstimatedHostTimeOffset(void);
+
+/**
+ * Convenience function to retrieve CHRE's estimate of the current time on the
+ * host, corresponding to the Android API SystemClock.elapsedRealtimeNanos().
+ *
+ * @return An estimate of the current time on the host, accurate to within
+ *     +/- 10 milliseconds.  This estimate is *not* guaranteed to be
+ *     monotonically increasing, and may move backwards as a result of receiving
+ *     new information from the host.
+ *
+ * @since v1.1
+ */
+static inline uint64_t chreGetEstimatedHostTime(void) {
+    int64_t offset = chreGetEstimatedHostTimeOffset();
+    uint64_t time = chreGetTime();
+
+    // Just casting time to int64_t and adding the (potentially negative) offset
+    // should be OK under most conditions, but this way avoids issues if
+    // time >= 2^63, which is technically allowed since we don't specify a start
+    // value for chreGetTime(), though one would assume 0 is roughly boot time.
+    if (offset >= 0) {
+        time += (uint64_t) offset;
+    } else {
+        // Assuming chreGetEstimatedHostTimeOffset() is implemented properly,
+        // this will never underflow, because offset = hostTime - chreTime,
+        // and both times are monotonically increasing (e.g. when determining
+        // the offset, if hostTime is 0 and chreTime is 100 we'll have
+        // offset = -100, but chreGetTime() will always return >= 100 after that
+        // point).
+        time -= (uint64_t) (offset * -1);
+    }
+
+    return time;
+}
+
+/**
+ * Set a timer.
+ *
+ * When the timer fires, nanoappHandleEvent will be invoked with
+ * CHRE_EVENT_TIMER and with the given 'cookie'.
+ *
+ * A CHRE implementation is required to provide at least 32
+ * timers.  However, there's no assurance there will be any available
+ * for any given nanoapp (if it's loaded late, etc).
+ *
+ * @param duration  Time, in nanoseconds, before the timer fires.
+ * @param cookie  Argument that will be sent to nanoappHandleEvent upon the
+ *     timer firing.  This is allowed to be NULL and does not need to be
+ *     a valid pointer (assuming the nanoappHandleEvent code is expecting such).
+ * @param oneShot  If true, the timer will just fire once.  If false, the
+ *     timer will continue to refire every 'duration', until this timer is
+ *     canceled (@see chreTimerCancel).
+ *
+ * @return  The timer ID.  If the system is unable to set a timer
+ *     (no more available timers, etc.) then CHRE_TIMER_INVALID will
+ *     be returned.
+ *
+ * @see nanoappHandleEvent
+ */
+uint32_t chreTimerSet(uint64_t duration, const void *cookie, bool oneShot);
+
+/**
+ * Cancel a timer.
+ *
+ * After this method returns, the CHRE assures there will be no more
+ * events sent from this timer, and any enqueued events from this timer
+ * will need to be evicted from the queue by the CHRE.
+ *
+ * @param timerId  A timer ID obtained by this nanoapp via chreTimerSet().
+ * @return true if the timer was cancelled, false otherwise.  We may
+ *     fail to cancel the timer if it's a one shot which (just) fired,
+ *     or if the given timer ID is not owned by the calling app.
+ */
+bool chreTimerCancel(uint32_t timerId);
+
+/**
+ * Terminate this nanoapp.
+ *
+ * This takes effect immediately.
+ *
+ * The CHRE will no longer execute this nanoapp.  The CHRE will not invoke
+ * nanoappEnd(), nor will it call any memory free callbacks in the nanoapp.
+ *
+ * The CHRE will unload/evict this nanoapp's code.
+ *
+ * @param abortCode  A value indicating the reason for aborting.  (Note that
+ *    in this version of the API, there is no way for anyone to access this
+ *    code, but future APIs may expose it.)
+ * @return Never.  This method does not return, as the CHRE stops nanoapp
+ *    execution immediately.
+ */
+void chreAbort(uint32_t abortCode) CHRE_NO_RETURN;
+
+/**
+ * Allocate a given number of bytes from the system heap.
+ *
+ * The nanoapp is required to free this memory via chreHeapFree() prior to
+ * the nanoapp ending.
+ *
+ * While the CHRE implementation is required to free up heap resources of
+ * a nanoapp when unloading it, future requirements and tests focused on
+ * nanoapps themselves may check for memory leaks, and will require nanoapps
+ * to properly manage their heap resources.
+ *
+ * @param bytes  The number of bytes requested.
+ * @return  A pointer to 'bytes' contiguous bytes of heap memory, or NULL
+ *     if the allocation could not be performed.  This pointer must be suitably
+ *     aligned for any kind of variable.
+ *
+ * @see chreHeapFree.
+ */
+CHRE_MALLOC_ATTR
+void *chreHeapAlloc(uint32_t bytes);
+
+/**
+ * Free a heap allocation.
+ *
+ * This allocation must be from a value returned from a chreHeapAlloc() call
+ * made by this nanoapp.  In other words, it is illegal to free memory
+ * allocated by another nanoapp (or the CHRE).
+ *
+ * @param ptr  'ptr' is required to be a value returned from chreHeapAlloc().
+ *     Note that since chreHeapAlloc can return NULL, CHRE
+ *     implementations must safely handle 'ptr' being NULL.
+ *
+ * @see chreHeapAlloc.
+ */
+void chreHeapFree(void *ptr);
+
+/**
+ * Logs the nanoapp's debug data into debug dumps.
+ *
+ * A debug dump is a string representation of information that can be used to
+ * diagnose and debug issues. While chreLog() is useful for logging events as
+ * they happen, the debug dump is a complementary function typically used to
+ * output a snapshot of a nanoapp's state, history, vital statistics, etc. The
+ * CHRE framework is required to pass this information to the debug method in
+ * the Context Hub HAL, where it can be captured in Android bugreports, etc.
+ *
+ * This function must only be called while handling CHRE_EVENT_DEBUG_DUMP,
+ * otherwise it will have no effect. A nanoapp can call this function multiple
+ * times while handling the event. If the resulting formatted string from a
+ * single call to this function is longer than CHRE_DEBUG_DUMP_MINIMUM_MAX_SIZE
+ * characters, it may get truncated.
+ *
+ * @param formatStr A printf-style format string of the format documented in
+ *     chreLog().
+ * @param ... A variable number of arguments necessary for the given 'formatStr'
+ *     (there may be no additional arguments for some 'formatStr's).
+ *
+ * @see chreConfigureDebugDumpEvent
+ * @see chreLog
+ *
+ * @since v1.4
+ */
+CHRE_PRINTF_ATTR(1, 2)
+void chreDebugDumpLog(const char *formatStr, ...);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* _CHRE_RE_H_ */
+
diff --git a/chre_api/legacy/v1_11/chre/sensor.h b/chre_api/legacy/v1_11/chre/sensor.h
new file mode 100644
index 00000000..551803e4
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/sensor.h
@@ -0,0 +1,1132 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_SENSOR_H_
+#define _CHRE_SENSOR_H_
+
+/**
+ * @file
+ * API dealing with sensor interaction in the Context Hub Runtime
+ * Environment.
+ *
+ * This includes the definition of our sensor types and the ability to
+ * configure them for receiving events.
+ */
+
+#include <stdbool.h>
+#include <stdint.h>
+
+#include <chre/common.h>
+#include <chre/event.h>
+#include <chre/sensor_types.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+
+/**
+ * Base value for all of the data events for sensors.
+ *
+ * The value for a data event FOO is
+ * CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_FOO
+ *
+ * This allows for easy mapping, and also explains why there are gaps
+ * in our values since we don't have all possible sensor types assigned.
+ */
+#define CHRE_EVENT_SENSOR_DATA_EVENT_BASE  CHRE_EVENT_SENSOR_FIRST_EVENT
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data can be interpreted using the 'x', 'y', and 'z' fields within
+ * 'readings', or by the 3D array 'v' (v[0] == x; v[1] == y; v[2] == z).
+ *
+ * All values are in SI units (m/s^2) and measure the acceleration applied to
+ * the device.
+ */
+#define CHRE_EVENT_SENSOR_ACCELEROMETER_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_ACCELEROMETER)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorOccurrenceData
+ *
+ * Since this is a one-shot sensor, after this event is delivered to the
+ * nanoapp, the sensor automatically goes into DONE mode.  Sensors of this
+ * type must be configured with a ONE_SHOT mode.
+ */
+#define CHRE_EVENT_SENSOR_INSTANT_MOTION_DETECT_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_INSTANT_MOTION_DETECT)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorOccurrenceData
+ *
+ * Since this is a one-shot sensor, after this event is delivered to the
+ * nanoapp, the sensor automatically goes into DONE mode.  Sensors of this
+ * type must be configured with a ONE_SHOT mode.
+ */
+#define CHRE_EVENT_SENSOR_STATIONARY_DETECT_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_STATIONARY_DETECT)
+
+/**
+ * nanoappHandleEvent argument: struct struct chreSensorOccurrenceData
+ *
+ * Since this is a one-shot sensor, after this event is delivered to the
+ * nanoapp, the sensor automatically goes into DONE mode.  Sensors of this
+ * type must be configured with a ONE_SHOT mode.
+ */
+#define CHRE_EVENT_SENSOR_SIGNIFICANT_MOTION_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_SIGNIFICANT_MOTION)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data can be interpreted using the 'x', 'y', and 'z' fields within
+ * 'readings', or by the 3D array 'v' (v[0] == x; v[1] == y; v[2] == z).
+ *
+ * All values are in radians/second and measure the rate of rotation
+ * around the X, Y and Z axis.
+ */
+#define CHRE_EVENT_SENSOR_GYROSCOPE_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_GYROSCOPE)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data can be interpreted using the 'x', 'y', and 'z' fields within
+ * 'readings', or by the 3D array 'v' (v[0] == x; v[1] == y; v[2] == z).
+ *
+ * All values are in micro-Tesla (uT) and measure the geomagnetic
+ * field in the X, Y and Z axis.
+ */
+#define CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_GEOMAGNETIC_FIELD)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorFloatData
+ *
+ * The data can be interpreted using the 'pressure' field within 'readings'.
+ * This value is in hectopascals (hPa).
+ */
+#define CHRE_EVENT_SENSOR_PRESSURE_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_PRESSURE)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorFloatData
+ *
+ * The data can be interpreted using the 'light' field within 'readings'.
+ * This value is in SI lux units.
+ */
+#define CHRE_EVENT_SENSOR_LIGHT_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_LIGHT)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorByteData
+ *
+ * The data is interpreted from the following fields in 'readings':
+ * o 'isNear': If set to 1, we are nearby (on the order of centimeters);
+ *       if set to 0, we are far. The meaning of near/far in this field must be
+ *       consistent with the Android definition.
+ * o 'invalid': If set to 1, this is not a valid reading of this data.
+ *       As of CHRE API v1.2, this field is deprecated and must always be set to
+ *       0.  If an invalid reading is generated by the sensor hardware, it must
+ *       be dropped and not delivered to any nanoapp.
+ *
+ * In prior versions of the CHRE API, there can be an invalid event generated
+ * upon configuring this sensor.  Thus, the 'invalid' field must be checked on
+ * the first event before interpreting 'isNear'.
+ */
+#define CHRE_EVENT_SENSOR_PROXIMITY_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_PROXIMITY)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorOccurrenceData
+ *
+ * This data is generated every time a step is taken by the user.
+ *
+ * This is backed by the same algorithm that feeds Android's
+ * SENSOR_TYPE_STEP_DETECTOR, and therefore sacrifices some accuracy to target
+ * an update latency of under 2 seconds.
+ *
+ * @since v1.3
+ */
+#define CHRE_EVENT_SENSOR_STEP_DETECT_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_STEP_DETECT)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorUint64Data
+ *
+ * The value of the data is the cumulative number of steps taken by the user
+ * since the last reboot while the sensor is active. This data is generated
+ * every time a step is taken by the user.
+ *
+ * This is backed by the same algorithm that feeds Android's
+ * SENSOR_TYPE_STEP_COUNTER, and therefore targets high accuracy with under
+ * 10 seconds of update latency.
+ *
+ * @since v1.5
+ */
+#define CHRE_EVENT_SENSOR_STEP_COUNTER_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_STEP_COUNTER)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorFloatData
+ *
+ * The value of the data is the measured hinge angle between 0 and 360 degrees
+ * inclusive.
+ *
+ * This is backed by the same algorithm that feeds Android's
+ * SENSOR_TYPE_HINGE_ANGLE.
+ *
+ * @since v1.5
+ */
+#define CHRE_EVENT_SENSOR_HINGE_ANGLE_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_HINGE_ANGLE)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data can be interpreted using the 'x', 'y', and 'z' fields within
+ * 'readings', or by the 3D array 'v' (v[0] == x; v[1] == y; v[2] == z).
+ *
+ * All values are in SI units (m/s^2) and measure the acceleration applied to
+ * the device.
+ */
+#define CHRE_EVENT_SENSOR_UNCALIBRATED_ACCELEROMETER_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_UNCALIBRATED_ACCELEROMETER)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data can be interpreted using the 'x', 'y', and 'z' fields within
+ * 'readings', or by the 3D array 'v' (v[0] == x; v[1] == y; v[2] == z).
+ *
+ * All values are in radians/second and measure the rate of rotation
+ * around the X, Y and Z axis.
+ */
+#define CHRE_EVENT_SENSOR_UNCALIBRATED_GYROSCOPE_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_UNCALIBRATED_GYROSCOPE)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data can be interpreted using the 'x', 'y', and 'z' fields within
+ * 'readings', or by the 3D array 'v' (v[0] == x; v[1] == y; v[2] == z).
+ *
+ * All values are in micro-Tesla (uT) and measure the geomagnetic
+ * field in the X, Y and Z axis.
+ */
+#define CHRE_EVENT_SENSOR_UNCALIBRATED_GEOMAGNETIC_FIELD_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_UNCALIBRATED_GEOMAGNETIC_FIELD)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorFloatData
+ *
+ * The data can be interpreted using the 'temperature' field within 'readings'.
+ * This value is in degrees Celsius.
+ */
+#define CHRE_EVENT_SENSOR_ACCELEROMETER_TEMPERATURE_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_ACCELEROMETER_TEMPERATURE)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorFloatData
+ *
+ * The data can be interpreted using the 'temperature' field within 'readings'.
+ * This value is in degrees Celsius.
+ */
+#define CHRE_EVENT_SENSOR_GYROSCOPE_TEMPERATURE_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_GYROSCOPE_TEMPERATURE)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorFloatData
+ *
+ * The data can be interpreted using the 'temperature' field within 'readings'.
+ * This value is in degrees Celsius.
+ */
+#define CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_TEMPERATURE_DATA \
+    (CHRE_EVENT_SENSOR_DATA_EVENT_BASE + CHRE_SENSOR_TYPE_GEOMAGNETIC_FIELD_TEMPERATURE)
+
+/**
+ * First value for sensor events which are not data from the sensor.
+ *
+ * Unlike the data event values, these other event values don't have any
+ * mapping to sensor types.
+ */
+#define CHRE_EVENT_SENSOR_OTHER_EVENTS_BASE \
+    (CHRE_EVENT_SENSOR_FIRST_EVENT + 0x0100)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorSamplingStatusEvent
+ *
+ * Indicates that the interval and/or the latency which this sensor is
+ * sampling at has changed.
+ */
+#define CHRE_EVENT_SENSOR_SAMPLING_CHANGE \
+    (CHRE_EVENT_SENSOR_OTHER_EVENTS_BASE + 0)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data can be interpreted using the 'x_bias', 'y_bias', and 'z_bias'
+ * field within 'readings', or by the 3D array 'bias' (bias[0] == x_bias;
+ * bias[1] == y_bias; bias[2] == z_bias). Bias is subtracted from uncalibrated
+ * data to generate calibrated data.
+ *
+ * All values are in radians/second and measure the rate of rotation
+ * around the X, Y and Z axis.
+ *
+ * If bias delivery is supported, this event is generated by default when
+ * chreSensorConfigure is called to enable for the sensor of type
+ * CHRE_SENSOR_TYPE_GYROSCOPE, or if bias delivery is explicitly enabled
+ * through chreSensorConfigureBiasEvents() for the sensor.
+ */
+#define CHRE_EVENT_SENSOR_GYROSCOPE_BIAS_INFO \
+    (CHRE_EVENT_SENSOR_OTHER_EVENTS_BASE + 1)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data can be interpreted using the 'x_bias', 'y_bias', and 'z_bias'
+ * field within 'readings', or by the 3D array 'bias' (bias[0] == x_bias;
+ * bias[1] == y_bias; bias[2] == z_bias). Bias is subtracted from uncalibrated
+ * data to generate calibrated data.
+ *
+ * All values are in micro-Tesla (uT) and measure the geomagnetic
+ * field in the X, Y and Z axis.
+ *
+ * If bias delivery is supported, this event is generated by default when
+ * chreSensorConfigure is called to enable for the sensor of type
+ * CHRE_SENSOR_TYPE_GEOMAGNETIC_FIELD, or if bias delivery is explicitly enabled
+ * through chreSensorConfigureBiasEvents() for the sensor.
+ */
+#define CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_BIAS_INFO \
+    (CHRE_EVENT_SENSOR_OTHER_EVENTS_BASE + 2)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data can be interpreted using the 'x_bias', 'y_bias', and 'z_bias'
+ * field within 'readings', or by the 3D array 'bias' (bias[0] == x_bias;
+ * bias[1] == y_bias; bias[2] == z_bias). Bias is subtracted from uncalibrated
+ * data to generate calibrated data.
+ *
+ * All values are in SI units (m/s^2) and measure the acceleration applied to
+ * the device.
+ *
+ * If bias delivery is supported, this event is generated by default when
+ * chreSensorConfigure is called to enable for the sensor of type
+ * CHRE_SENSOR_TYPE_ACCELEROMETER, or if bias delivery is explicitly enabled
+ * through chreSensorConfigureBiasEvents() for the sensor.
+ *
+ * @since v1.3
+ */
+#define CHRE_EVENT_SENSOR_ACCELEROMETER_BIAS_INFO \
+    (CHRE_EVENT_SENSOR_OTHER_EVENTS_BASE + 3)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorFlushCompleteEvent
+ *
+ * An event indicating that a flush request made by chreSensorFlushAsync has
+ * completed.
+ *
+ * @see chreSensorFlushAsync
+ *
+ * @since v1.3
+ */
+#define CHRE_EVENT_SENSOR_FLUSH_COMPLETE \
+    (CHRE_EVENT_SENSOR_OTHER_EVENTS_BASE + 4)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data of this event is the same as that of
+ * CHRE_EVENT_SENSOR_GYROSCOPE_BIAS_INFO, except the sensorHandle field of
+ * chreSensorDataHeader contains the handle of the sensor of type
+ * CHRE_SENSOR_TYPE_UNCALIBRATED_GYROSCOPE.
+ *
+ * This event is only generated if the bias reporting is explicitly enabled
+ * for a nanoapp through chreSensorConfigureBiasEvents() for the sensor of type
+ * CHRE_SENSOR_TYPE_UNCALIBRATED_GYROSCOPE.
+ *
+ * @see CHRE_EVENT_SENSOR_GYROSCOPE_BIAS_INFO
+ *
+ * @since v1.3
+ */
+#define CHRE_EVENT_SENSOR_UNCALIBRATED_GYROSCOPE_BIAS_INFO \
+    (CHRE_EVENT_SENSOR_OTHER_EVENTS_BASE + 5)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data of this event is the same as that of
+ * CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_BIAS_INFO, except the sensorHandle field
+ * of chreSensorDataHeader contains the handle of the sensor of type
+ * CHRE_SENSOR_TYPE_UNCALIBRATED_GEOMAGNETIC_FIELD.
+ *
+ * This event is only generated if the bias reporting is explicitly enabled
+ * for a nanoapp through chreSensorConfigureBiasEvents() for the sensor of type
+ * CHRE_SENSOR_TYPE_UNCALIBRATED_GEOMAGNETIC_FIELD.
+ *
+ * @see CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_BIAS_INFO
+ *
+ * @since v1.3
+ */
+#define CHRE_EVENT_SENSOR_UNCALIBRATED_GEOMAGNETIC_FIELD_BIAS_INFO \
+    (CHRE_EVENT_SENSOR_OTHER_EVENTS_BASE + 6)
+
+/**
+ * nanoappHandleEvent argument: struct chreSensorThreeAxisData
+ *
+ * The data of this event is the same as that of
+ * CHRE_EVENT_SENSOR_ACCELEROMETER_BIAS_INFO, except the sensorHandle field
+ * of chreSensorDataHeader contains the handle of the sensor of type
+ * CHRE_SENSOR_TYPE_UNCALIBRATED_ACCELEROMETER.
+ *
+ * This event is only generated if the bias reporting is explicitly enabled
+ * for a nanoapp through chreSensorConfigureBiasEvents for the sensor of type
+ * CHRE_SENSOR_TYPE_UNCALIBRATED_ACCELEROMETER.
+ *
+ * @see CHRE_EVENT_SENSOR_ACCELEROMETER_BIAS_INFO
+ *
+ * @since v1.3
+ */
+#define CHRE_EVENT_SENSOR_UNCALIBRATED_ACCELEROMETER_BIAS_INFO \
+    (CHRE_EVENT_SENSOR_OTHER_EVENTS_BASE + 7)
+
+#if CHRE_EVENT_SENSOR_UNCALIBRATED_ACCELEROMETER_BIAS_INFO > \
+    CHRE_EVENT_SENSOR_LAST_EVENT
+#error Too many sensor events.
+#endif
+
+/**
+ * Value indicating we want the smallest possible latency for a sensor.
+ *
+ * This literally translates to 0 nanoseconds for the chreSensorConfigure()
+ * argument.  While we won't get exactly 0 nanoseconds, the CHRE will
+ * queue up this event As Soon As Possible.
+ */
+#define CHRE_SENSOR_LATENCY_ASAP  UINT64_C(0)
+
+/**
+ * Special value indicating non-importance, or non-applicability of the sampling
+ * interval.
+ *
+ * @see chreSensorConfigure
+ * @see chreSensorSamplingStatus
+ */
+#define CHRE_SENSOR_INTERVAL_DEFAULT  UINT64_C(-1)
+
+/**
+ * Special value indicating non-importance of the latency.
+ *
+ * @see chreSensorConfigure
+ * @see chreSensorSamplingStatus
+ */
+#define CHRE_SENSOR_LATENCY_DEFAULT  UINT64_C(-1)
+
+/**
+ * A sensor index value indicating that it is the default sensor.
+ *
+ * @see chreSensorFind
+ */
+#define CHRE_SENSOR_INDEX_DEFAULT  UINT8_C(0)
+
+/**
+ * Special value indicating non-importance of the batch interval.
+ *
+ * @see chreSensorConfigureWithBatchInterval
+ */
+#define CHRE_SENSOR_BATCH_INTERVAL_DEFAULT  UINT64_C(-1)
+
+// This is used to define elements of enum chreSensorConfigureMode.
+#define CHRE_SENSOR_CONFIGURE_RAW_POWER_ON           (1 << 0)
+
+// This is used to define elements of enum chreSensorConfigureMode.
+#define CHRE_SENSOR_CONFIGURE_RAW_REPORT_CONTINUOUS  (1 << 1)
+
+// This is used to define elements of enum chreSensorConfigureMode.
+#define CHRE_SENSOR_CONFIGURE_RAW_REPORT_ONE_SHOT    (2 << 1)
+
+/**
+ * The maximum amount of time allowed to elapse between the call to
+ * chreSensorFlushAsync() and when CHRE_EVENT_SENSOR_FLUSH_COMPLETE is delivered
+ * to the nanoapp on a successful flush.
+ */
+#define CHRE_SENSOR_FLUSH_COMPLETE_TIMEOUT_NS  (5 * CHRE_NSEC_PER_SEC)
+
+/**
+ * Modes we can configure a sensor to use.
+ *
+ * Our mode will affect not only how/if we receive events, but
+ * also whether or not the sensor will be powered on our behalf.
+ *
+ * @see chreSensorConfigure
+ */
+enum chreSensorConfigureMode {
+    /**
+     * Get events from the sensor.
+     *
+     * Power: Turn on if not already on.
+     * Reporting: Continuous.  Send each new event as it comes (subject to
+     *     batching and latency).
+     */
+    CHRE_SENSOR_CONFIGURE_MODE_CONTINUOUS =
+        (CHRE_SENSOR_CONFIGURE_RAW_POWER_ON |
+         CHRE_SENSOR_CONFIGURE_RAW_REPORT_CONTINUOUS),
+
+    /**
+     * Get a single event from the sensor and then become DONE.
+     *
+     * Once the event is sent, the sensor automatically
+     * changes to CHRE_SENSOR_CONFIGURE_MODE_DONE mode.
+     *
+     * Power: Turn on if not already on.
+     * Reporting: One shot.  Send the next event and then be DONE.
+     */
+    CHRE_SENSOR_CONFIGURE_MODE_ONE_SHOT =
+        (CHRE_SENSOR_CONFIGURE_RAW_POWER_ON |
+         CHRE_SENSOR_CONFIGURE_RAW_REPORT_ONE_SHOT),
+
+    /**
+     * Get events from a sensor that are generated for any client in the system.
+     *
+     * This is considered passive because the sensor will not be powered on for
+     * the sake of our nanoapp.  If and only if another client in the system has
+     * requested this sensor power on will we get events.
+     *
+     * This can be useful for something which is interested in seeing data, but
+     * not interested enough to be responsible for powering on the sensor.
+     *
+     * Power: Do not power the sensor on our behalf.
+     * Reporting: Continuous.  Send each event as it comes.
+     */
+    CHRE_SENSOR_CONFIGURE_MODE_PASSIVE_CONTINUOUS =
+        CHRE_SENSOR_CONFIGURE_RAW_REPORT_CONTINUOUS,
+
+    /**
+     * Get a single event from a sensor that is generated for any client in the
+     * system.
+     *
+     * See CHRE_SENSOR_CONFIGURE_MODE_PASSIVE_CONTINUOUS for more details on
+     * what the "passive" means.
+     *
+     * Power: Do not power the sensor on our behalf.
+     * Reporting: One shot.  Send only the next event and then be DONE.
+     */
+    CHRE_SENSOR_CONFIGURE_MODE_PASSIVE_ONE_SHOT =
+        CHRE_SENSOR_CONFIGURE_RAW_REPORT_ONE_SHOT,
+
+    /**
+     * Indicate we are done using this sensor and no longer interested in it.
+     *
+     * See chreSensorConfigure for more details on expressing interest or
+     * lack of interest in a sensor.
+     *
+     * Power: Do not power the sensor on our behalf.
+     * Reporting: None.
+     */
+    CHRE_SENSOR_CONFIGURE_MODE_DONE = 0,
+};
+
+/**
+ * A structure containing information about a Sensor.
+ *
+ * See documentation of individual fields below.
+ */
+struct chreSensorInfo {
+    /**
+     * The name of the sensor.
+     *
+     * A text name, useful for logging/debugging, describing the Sensor.  This
+     * is not assured to be unique (i.e. there could be multiple sensors with
+     * the name "Temperature").
+     *
+     * CHRE implementations may not set this as NULL.  An empty
+     * string, while discouraged, is legal.
+     */
+    const char *sensorName;
+
+    /**
+     * One of the CHRE_SENSOR_TYPE_* defines above.
+     */
+    uint8_t sensorType;
+
+    /**
+     * Flag indicating if this sensor is on-change.
+     *
+     * An on-change sensor only generates events when underlying state
+     * changes.  This has the same meaning as on-change does in the Android
+     * Sensors HAL.  See sensors.h for much more details.
+     *
+     * A value of 1 indicates this is on-change.  0 indicates this is not
+     * on-change.
+     */
+    uint8_t isOnChange          : 1;
+
+    /**
+     * Flag indicating if this sensor is one-shot.
+     *
+     * A one-shot sensor only triggers a single event, and then automatically
+     * disables itself.
+     *
+     * A value of 1 indicates this is one-shot.  0 indicates this is not
+     * on-change.
+     */
+    uint8_t isOneShot           : 1;
+
+    /**
+     * Flag indicating if this sensor supports reporting bias info events.
+     *
+     * This field will be set to 0 when running on CHRE API versions prior to
+     * v1.3, but must be ignored (i.e. does not mean bias info event is not
+     * supported).
+     *
+     * @see chreSensorConfigureBiasEvents
+     *
+     * @since v1.3
+     */
+    uint8_t reportsBiasEvents   : 1;
+
+    /**
+     * Flag indicating if this sensor supports passive mode requests.
+     *
+     * This field will be set to 0 when running on CHRE API versions prior to
+     * v1.4, and must be ignored (i.e. does not mean passive mode requests are
+     * not supported).
+     *
+     * @see chreSensorConfigure
+     *
+     * @since v1.4
+     */
+    uint8_t supportsPassiveMode : 1;
+
+    uint8_t unusedFlags         : 4;
+
+    /**
+     * The minimum sampling interval supported by this sensor, in nanoseconds.
+     *
+     * Requests to chreSensorConfigure with a lower interval than this will
+     * fail.  If the sampling interval is not applicable to this sensor, this
+     * will be set to CHRE_SENSOR_INTERVAL_DEFAULT.
+     *
+     * This field will be set to 0 when running on CHRE API versions prior to
+     * v1.1, indicating that the minimum interval is not known.
+     *
+     * @since v1.1
+     */
+    uint64_t minInterval;
+
+    /**
+     * Uniquely identifies the sensor for a given type. A value of 0 indicates
+     * that this is the "default" sensor, which is returned by
+     * chreSensorFindDefault().
+     *
+     * The sensor index of a given type must be stable across boots (i.e. must
+     * not change), and a different sensor of the same type must have different
+     * sensor index values, and the set of sensorIndex values for a given sensor
+     * type must be continuguous.
+     *
+     * @since v1.5
+     */
+    uint8_t sensorIndex;
+};
+
+/**
+ * The status of a sensor's sampling configuration.
+ */
+struct chreSensorSamplingStatus {
+    /**
+     * The interval, in nanoseconds, at which sensor data is being sampled at.
+     * This should be used by nanoapps to determine the rate at which samples
+     * will be generated and not to indicate what the sensor is truly sampling
+     * at since resampling may occur to limit incoming data.
+     *
+     * If this is CHRE_SENSOR_INTERVAL_DEFAULT, then a sampling interval
+     * isn't meaningful for this sensor.
+     *
+     * Note that if 'enabled' is false, this value is not meaningful.
+     */
+    uint64_t interval;
+
+    /**
+     * The latency, in nanoseconds, at which the sensor is now reporting.
+     *
+     * If this is CHRE_SENSOR_LATENCY_DEFAULT, then a latency
+     * isn't meaningful for this sensor.
+     *
+     * The effective batch interval can be derived from this value by
+     * adding the current sampling interval.
+     *
+     * Note that if 'enabled' is false, this value is not meaningful.
+     */
+    uint64_t latency;
+
+    /**
+     * True if the sensor is actively powered and sampling; false otherwise.
+     */
+    bool enabled;
+};
+
+/**
+ * The nanoappHandleEvent argument for CHRE_EVENT_SENSOR_SAMPLING_CHANGE.
+ *
+ * Note that only at least one of 'interval' or 'latency' must be
+ * different than it was prior to this event.  Thus, one of these
+ * fields may be (but doesn't need to be) the same as before.
+ */
+struct chreSensorSamplingStatusEvent {
+    /**
+     * The handle of the sensor which has experienced a change in sampling.
+     */
+    uint32_t sensorHandle;
+
+    /**
+     * The new sampling status.
+     *
+     * At least one of the field in this struct will be different from
+     * the previous sampling status event.
+     */
+    struct chreSensorSamplingStatus status;
+};
+
+/**
+ * The nanoappHandleEvent argument for CHRE_EVENT_SENSOR_FLUSH_COMPLETE.
+ *
+ * @see chreSensorFlushAsync
+ *
+ * @since v1.3
+ */
+struct chreSensorFlushCompleteEvent {
+    /**
+     * The handle of the sensor which a flush was completed.
+     */
+    uint32_t sensorHandle;
+
+    /**
+     * Populated with a value from enum {@link #chreError}, indicating whether
+     * the flush failed, and if so, provides the cause of the failure.
+     */
+    uint8_t errorCode;
+
+    /**
+     * Reserved for future use. Set to 0.
+     */
+    uint8_t reserved[3];
+
+    /**
+     * Set to the cookie parameter given to chreSensorFlushAsync.
+     */
+    const void *cookie;
+};
+
+/**
+ * Find the default sensor for a given sensor type.
+ *
+ * @param sensorType One of the CHRE_SENSOR_TYPE_* constants.
+ * @param handle  If a sensor is found, then the memory will be filled with
+ *     the value for the sensor's handle.  This argument must be non-NULL.
+ * @return true if a sensor was found, false otherwise.
+ */
+bool chreSensorFindDefault(uint8_t sensorType, uint32_t *handle);
+
+/**
+ * Finds a sensor of a given index and sensor type.
+ *
+ * For CHRE implementations that support multiple sensors of the same sensor
+ * type, this method can be used to get the non-default sensor(s). The default
+ * sensor, as defined in the chreSensorFindDefault(), will be returned if
+ * a sensor index of zero is specified.
+ *
+ * A simple example of iterating all available sensors of a given type is
+ * provided here:
+ *
+ * uint32_t handle;
+ * for (uint8_t i = 0; chreSensorFind(sensorType, i, &handle); i++) {
+ *   chreLog(CHRE_LOG_INFO,
+ *           "Found sensor index %" PRIu8 ", which has handle %" PRIu32,
+ *           i, handle);
+ * }
+ *
+ * If this method is invoked for CHRE versions prior to v1.5, invocations with
+ * sensorIndex value of 0 will be equivalent to using chreSensorFindDefault, and
+ * if sensorIndex is non-zero will return false.
+ *
+ * In cases where multiple sensors are supported in both the Android sensors
+ * framework and CHRE, the sensorName of the chreSensorInfo struct for a given
+ * sensor instance must match exactly with that of the
+ * android.hardware.Sensor#getName() return value. This can be used to match a
+ * sensor instance between the Android and CHRE sensors APIs.
+ *
+ * @param sensorType One of the CHRE_SENSOR_TYPE_* constants.
+ * @param sensorIndex The index of the desired sensor.
+ * @param handle  If a sensor is found, then the memory will be filled with
+ *     the value for the sensor's handle.  This argument must be non-NULL.
+ * @return true if a sensor was found, false otherwise.
+ *
+ * @since v1.5
+ */
+bool chreSensorFind(uint8_t sensorType, uint8_t sensorIndex, uint32_t *handle);
+
+/**
+ * Get the chreSensorInfo struct for a given sensor.
+ *
+ * @param sensorHandle  The sensor handle, as obtained from
+ *     chreSensorFindDefault() or passed to nanoappHandleEvent().
+ * @param info  If the sensor is valid, then this memory will be filled with
+ *     the SensorInfo contents for this sensor.  This argument must be
+ *     non-NULL.
+ * @return true if the senor handle is valid and 'info' was filled in;
+ *     false otherwise.
+ */
+bool chreGetSensorInfo(uint32_t sensorHandle, struct chreSensorInfo *info);
+
+/**
+ * Get the chreSensorSamplingStatus struct for a given sensor.
+ *
+ * Note that this may be different from what was requested in
+ * chreSensorConfigure(), for multiple reasons.  It's possible that the sensor
+ * does not exactly support the interval requested in chreSensorConfigure(), so
+ * a faster one was chosen.
+ *
+ * It's also possible that there is another user of this sensor who has
+ * requested a faster interval and/or lower latency.  This latter scenario
+ * should be noted, because it means the sensor rate can change due to no
+ * interaction from this nanoapp.  Note that the
+ * CHRE_EVENT_SENSOR_SAMPLING_CHANGE event will trigger in this case, so it's
+ * not necessary to poll for such a change.
+ *
+ * This function must return a valid status if the provided sensor is being
+ * actively sampled by a nanoapp and a CHRE_EVENT_SENSOR_SAMPLING_CHANGE has
+ * been delivered indicating their request has taken effect. It is not required
+ * to return a valid status if no nanoapp is actively sampling the sensor.
+ *
+ * @param sensorHandle  The sensor handle, as obtained from
+ *     chreSensorFindDefault() or passed to nanoappHandleEvent().
+ * @param status  If the sensor is actively enabled by a nanoapp, then this
+ *     memory must be filled with the sampling status contents for this sensor.
+ *     This argument must be non-NULL.
+ * @return true if the sensor handle is valid and 'status' was filled in;
+ *     false otherwise.
+ */
+bool chreGetSensorSamplingStatus(uint32_t sensorHandle,
+                                 struct chreSensorSamplingStatus *status);
+
+/**
+ * Configures a given sensor at a specific interval and latency and mode.
+ *
+ * If this sensor's chreSensorInfo has isOneShot set to 1,
+ * then the mode must be one of the ONE_SHOT modes, or this method will fail.
+ *
+ * The CHRE wants to power as few sensors as possible, in keeping with its
+ * low power design.  As such, it only turns on sensors when there are clients
+ * actively interested in that sensor data, and turns off sensors as soon as
+ * there are no clients interested in them.  Calling this method generally
+ * indicates an interest, and using CHRE_SENSOR_CONFIGURE_MODE_DONE shows
+ * when we are no longer interested.
+ *
+ * Thus, each initial Configure of a sensor (per nanoapp) needs to eventually
+ * have a DONE call made, either directly or on its behalf.  Subsequent calls
+ * to a Configure method within the same nanoapp, when there has been no DONE
+ * in between, still only require a single DONE call.
+ *
+ * For example, the following is valid usage:
+ * <code>
+ *   chreSensorConfigure(myHandle, mode, interval0, latency0);
+ *   [...]
+ *   chreSensorConfigure(myHandle, mode, interval1, latency0);
+ *   [...]
+ *   chreSensorConfigure(myHandle, mode, interval1, latency1);
+ *   [...]
+ *   chreSensorConfigureModeOnly(myHandle, CHRE_SENSOR_CONFIGURE_MODE_DONE);
+ * </code>
+ *
+ * The first call to Configure is the one which creates the requirement
+ * to eventually call with DONE.  The subsequent calls are just changing the
+ * interval/latency.  They have not changed the fact that this nanoapp is
+ * still interested in output from the sensor 'myHandle'.  Thus, only one
+ * single call for DONE is needed.
+ *
+ * There is a special case.  One-shot sensors, sensors which
+ * just trigger a single event and never trigger again, implicitly go into
+ * DONE mode after that single event triggers.  Thus, the
+ * following are legitimate usages:
+ * <code>
+ *   chreSensorConfigure(myHandle, MODE_ONE_SHOT, interval, latency);
+ *   [...]
+ *   [myHandle triggers an event]
+ *   [no need to configure to DONE].
+ * </code>
+ *
+ * And:
+ * <code>
+ *   chreSensorConfigure(myHandle, MODE_ONE_SHOT, interval, latency);
+ *   [...]
+ *   chreSensorConfigureModeOnly(myHandle, MODE_DONE);
+ *   [we cancelled myHandle before it ever triggered an event]
+ * </code>
+ *
+ * Note that while PASSIVE modes, by definition, don't express an interest in
+ * powering the sensor, DONE is still necessary to silence the event reporting.
+ * Starting with CHRE API v1.4, for sensors that do not support passive mode, a
+ * request with mode set to CHRE_SENSOR_CONFIGURE_MODE_PASSIVE_CONTINUOUS or
+ * CHRE_SENSOR_CONFIGURE_MODE_PASSIVE_ONE_SHOT will be rejected. CHRE API
+ * versions 1.3 and older implicitly assume that passive mode is supported
+ * across all sensors, however this is not necessarily the case. Clients can
+ * call chreSensorInfo to identify whether a sensor supports passive mode.
+ *
+ * When a calibrated sensor (e.g. CHRE_SENSOR_TYPE_ACCELEROMETER) is
+ * successfully enabled through this method and if bias delivery is supported,
+ * by default CHRE will start delivering bias events for the sensor
+ * (e.g. CHRE_EVENT_SENSOR_ACCELEROMETER_BIAS_INFO) to the nanoapp. If the
+ * nanoapp does not wish to receive these events, they can be disabled through
+ * chreSensorConfigureBiasEvents after enabling the sensor.
+ *
+ * @param sensorHandle  The handle to the sensor, as obtained from
+ *     chreSensorFindDefault().
+ * @param mode  The mode to use.  See descriptions within the
+ *     chreSensorConfigureMode enum.
+ * @param interval  The interval, in nanoseconds, at which we want events from
+ *     the sensor.  On success, the sensor will be set to 'interval', or a value
+ *     less than 'interval'.  There is a special value
+ *     CHRE_SENSOR_INTERVAL_DEFAULT, in which we don't express a preference for
+ *     the interval, and allow the sensor to choose what it wants.  Note that
+ *     due to batching, we may receive events less frequently than
+ *     'interval'.
+ * @param latency  The maximum latency, in nanoseconds, allowed before the
+ *     CHRE begins delivery of an event.  This will control how many events
+ *     can be queued by the sensor before requiring a delivery event.
+ *     Latency is defined as the "timestamp when event is queued by the CHRE"
+ *     minus "timestamp of oldest unsent data reading".
+ *     There is a special value CHRE_SENSOR_LATENCY_DEFAULT, in which we don't
+ *     express a preference for the latency, and allow the sensor to choose what
+ *     it wants.
+ *     Note that there is no assurance of how long it will take an event to
+ *     get through a CHRE's queueing system, and thus there is no ability to
+ *     request a minimum time from the occurrence of a phenomenon to when the
+ *     nanoapp receives the information.  The current CHRE API has no
+ *     real-time elements, although future versions may introduce some to
+ *     help with this issue.
+ * @return true if the configuration succeeded, false otherwise.
+ *
+ * @see chreSensorConfigureMode
+ * @see chreSensorFindDefault
+ * @see chreSensorInfo
+ * @see chreSensorConfigureBiasEvents
+ */
+bool chreSensorConfigure(uint32_t sensorHandle,
+                         enum chreSensorConfigureMode mode,
+                         uint64_t interval, uint64_t latency);
+
+/**
+ * Short cut for chreSensorConfigure where we only want to configure the mode
+ * and do not care about interval/latency.
+ *
+ * @see chreSensorConfigure
+ */
+static inline bool chreSensorConfigureModeOnly(
+        uint32_t sensorHandle, enum chreSensorConfigureMode mode) {
+    return chreSensorConfigure(sensorHandle,
+                               mode,
+                               CHRE_SENSOR_INTERVAL_DEFAULT,
+                               CHRE_SENSOR_LATENCY_DEFAULT);
+}
+
+/**
+ * Convenience function that wraps chreSensorConfigure but enables batching to
+ * be controlled by specifying the desired maximum batch interval rather
+ * than maximum sample latency.  Users may find the batch interval to be a more
+ * intuitive method of expressing the desired batching behavior.
+ *
+ * Batch interval is different from latency as the batch interval time is
+ * counted starting when the prior event containing a batch of sensor samples is
+ * delivered, while latency starts counting when the first sample is deferred to
+ * start collecting a batch.  In other words, latency ignores the time between
+ * the last sample in a batch to the first sample of the next batch, while it's
+ * included in the batch interval, as illustrated below.
+ *
+ *  Time      0   1   2   3   4   5   6   7   8
+ *  Batch             A           B           C
+ *  Sample   a1  a2  a3  b1  b2  b3  c1  c2  c3
+ *  Latency  [        ]  [        ]  [        ]
+ *  BatchInt          |           |           |
+ *
+ * In the diagram, the effective sample interval is 1 time unit, latency is 2
+ * time units, and batch interval is 3 time units.
+ *
+ * @param sensorHandle See chreSensorConfigure#sensorHandle
+ * @param mode See chreSensorConfigure#mode
+ * @param sampleInterval See chreSensorConfigure#interval, but note that
+ *     CHRE_SENSOR_INTERVAL_DEFAULT is not a supported input to this method.
+ * @param batchInterval The desired maximum interval, in nanoseconds, between
+ *     CHRE enqueuing each batch of sensor samples.
+ * @return Same as chreSensorConfigure
+ *
+ * @see chreSensorConfigure
+ *
+ * @since v1.1
+ */
+static inline bool chreSensorConfigureWithBatchInterval(
+        uint32_t sensorHandle, enum chreSensorConfigureMode mode,
+        uint64_t sampleInterval, uint64_t batchInterval) {
+    bool result = false;
+
+    if (sampleInterval != CHRE_SENSOR_INTERVAL_DEFAULT) {
+        uint64_t latency;
+        if (batchInterval == CHRE_SENSOR_BATCH_INTERVAL_DEFAULT) {
+            latency = CHRE_SENSOR_LATENCY_DEFAULT;
+        } else if (batchInterval > sampleInterval) {
+            latency = batchInterval - sampleInterval;
+        } else {
+            latency = CHRE_SENSOR_LATENCY_ASAP;
+        }
+        result = chreSensorConfigure(sensorHandle, mode, sampleInterval,
+                                     latency);
+    }
+
+    return result;
+}
+
+/**
+ * Configures the reception of bias events for a specific sensor.
+ *
+ * If bias event delivery is supported for a sensor, the sensor's chreSensorInfo
+ * has reportsBiasEvents set to 1. If supported, it must be supported for both
+ * calibrated and uncalibrated versions of the sensor. If supported, CHRE must
+ * provide bias events to the nanoapp by default when chreSensorConfigure is
+ * called to enable the calibrated version of the sensor (for backwards
+ * compatibility reasons, as this is the defined behavior for CHRE API v1.0).
+ * When configuring uncalibrated sensors, nanoapps must explicitly configure an
+ * enable request through this method to receive bias events. If bias event
+ * delivery is not supported for the sensor, this method will return false and
+ * no bias events will be generated.
+ *
+ * To enable bias event delivery (enable=true), the nanoapp must be registered
+ * to the sensor through chreSensorConfigure, and bias events will only be
+ * generated when the sensor is powered on. To disable the bias event delivery,
+ * this method can be invoked with enable=false.
+ *
+ * If an enable configuration is successful, the calling nanoapp will receive
+ * bias info events, e.g. CHRE_EVENT_SENSOR_ACCELEROMETER_BIAS_INFO, when the
+ * bias status changes (or first becomes available). Calibrated data
+ * (e.g. CHRE_SENSOR_TYPE_ACCELEROMETER) is generated by subracting bias from
+ * uncalibrated data (e.g. CHRE_SENSOR_TYPE_UNCALIBRATED_ACCELEROMETER).
+ * Calibrated sensor events are generated by applying the most recent bias
+ * available (i.e. timestamp of calibrated data are greater than or equal to the
+ * timestamp of the bias data that has been applied to it). The configuration of
+ * bias event delivery persists until the sensor is unregistered by the nanoapp
+ * through chreSensorConfigure or modified through this method.
+ *
+ * To get an initial bias before new bias events, the nanoapp should get the
+ * bias synchronously after this method is invoked, e.g.:
+ *
+ * if (chreSensorConfigure(handle, ...)) {
+ *   chreSensorConfigureBiasEvents(handle, true);
+ *   chreSensorGetThreeAxisBias(handle, &bias);
+ * }
+ *
+ * Note that chreSensorGetThreeAxisBias() should be called after
+ * chreSensorConfigureBiasEvents() to ensure that no bias events are lost.
+ *
+ * If called while running on a CHRE API version below v1.3, this function
+ * returns false and has no effect. The default behavior regarding bias events
+ * is unchanged, meaning that the implementation may still send bias events
+ * when a calibrated sensor is registered (if supported), and will not send bias
+ * events when an uncalibrated sensor is registered.
+ *
+ * @param sensorHandle The handle to the sensor, as obtained from
+ *     chreSensorFindDefault().
+ * @param enable true to receive bias events, false otherwise
+ *
+ * @return true if the configuration succeeded, false otherwise
+ *
+ * @since v1.3
+ */
+bool chreSensorConfigureBiasEvents(uint32_t sensorHandle, bool enable);
+
+/**
+ * Synchronously provides the most recent bias info available for a sensor. The
+ * bias will only be provided for a sensor that supports bias event delivery
+ * using the chreSensorThreeAxisData type. If the bias is not yet available
+ * (but is supported), this method will store data with a bias of 0 and the
+ * accuracy field in chreSensorDataHeader set to CHRE_SENSOR_ACCURACY_UNKNOWN.
+ *
+ * If called while running on a CHRE API version below v1.3, this function
+ * returns false.
+ *
+ * @param sensorHandle The handle to the sensor, as obtained from
+ *     chreSensorFindDefault().
+ * @param bias A pointer to where the bias will be stored.
+ *
+ * @return true if the bias was successfully stored, false if sensorHandle was
+ *     invalid or the sensor does not support three axis bias delivery
+ *
+ * @since v1.3
+ *
+ * @see chreSensorConfigureBiasEvents
+ */
+bool chreSensorGetThreeAxisBias(uint32_t sensorHandle,
+                                struct chreSensorThreeAxisData *bias);
+
+/**
+ * Makes a request to flush all samples stored for batching. The nanoapp must be
+ * registered to the sensor through chreSensorConfigure, and the sensor must be
+ * powered on. If the request is accepted, all batched samples of the sensor
+ * are sent to nanoapps registered to the sensor. During a flush, it is treated
+ * as though the latency as given in chreSensorConfigure has expired. When all
+ * batched samples have been flushed (or the flush fails), the nanoapp will
+ * receive a unicast CHRE_EVENT_SENSOR_FLUSH_COMPLETE event. The time to deliver
+ * this event must not exceed CHRE_SENSOR_FLUSH_COMPLETE_TIMEOUT_NS after this
+ * method is invoked. If there are no samples in the batch buffer (either in
+ * hardware FIFO or software), then this method will return true and a
+ * CHRE_EVENT_SENSOR_FLUSH_COMPLETE event is delivered immediately.
+ *
+ * If a flush request is invalid (e.g. the sensor refers to a one-shot sensor,
+ * or the sensor was not enabled), and this API will return false and no
+ * CHRE_EVENT_SENSOR_FLUSH_COMPLETE event will be delivered.
+ *
+ * If multiple flush requests are made for a sensor prior to flush completion,
+ * then the requesting nanoapp will receive all batched samples existing at the
+ * time of the latest flush request. In this case, the number of
+ * CHRE_EVENT_SENSOR_FLUSH_COMPLETE events received must equal the number of
+ * flush requests made.
+ *
+ * If a sensor request is disabled after a flush request is made through this
+ * method but before the flush operation is completed, the nanoapp will receive
+ * a CHRE_EVENT_SENSOR_FLUSH_COMPLETE with the error code
+ * CHRE_ERROR_FUNCTION_DISABLED for any pending flush requests.
+ *
+ * Starting with CHRE API v1.3, implementations must support this capability
+ * across all exposed sensor types.
+ *
+ * @param sensorHandle  The handle to the sensor, as obtained from
+ *     chreSensorFindDefault().
+ * @param cookie  An opaque value that will be included in the
+ *     chreSensorFlushCompleteEvent sent in relation to this request.
+ *
+ * @return true if the request was accepted for processing, false otherwise
+ *
+ * @since v1.3
+ */
+bool chreSensorFlushAsync(uint32_t sensorHandle, const void *cookie);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* _CHRE_SENSOR_H_ */
diff --git a/chre_api/legacy/v1_11/chre/sensor_types.h b/chre_api/legacy/v1_11/chre/sensor_types.h
new file mode 100644
index 00000000..6b46a227
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/sensor_types.h
@@ -0,0 +1,483 @@
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_SENSOR_TYPES_H_
+#define _CHRE_SENSOR_TYPES_H_
+
+/**
+ * @file
+ * Standalone definition of sensor types, and the data structures of the sample
+ * events they emit.
+ */
+
+#include <stdint.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * @file
+ * The CHRE_SENSOR_TYPE_* defines are the sensor types supported.
+ *
+ * Unless otherwise noted, each of these sensor types is based off of a
+ * corresponding sensor type in the Android API's sensors.h interface.
+ * For a given CHRE_SENSOR_TYPE_FOO, it corresponds to the SENSOR_TYPE_FOO in
+ * hardware/libhardware/include/hardware/sensors.h of the Android code base.
+ *
+ * Unless otherwise noted below, a CHRE_SENSOR_TYPE_FOO should be assumed
+ * to work the same as the Android SENSOR_TYPE_FOO, as documented in the
+ * sensors.h documentation and as detailed within the Android Compatibility
+ * Definition Document.
+ *
+ * Note that every sensor will generate CHRE_EVENT_SENSOR_SAMPLING_CHANGE
+ * events, so it is not listed with each individual sensor.
+ */
+
+/**
+ * Start value for all of the vendor-defined private sensors.
+ *
+ * @since v1.2
+ */
+#define CHRE_SENSOR_TYPE_VENDOR_START  UINT8_C(0xC0)
+
+/**
+ * Accelerometer.
+ *
+ * Generates: CHRE_EVENT_SENSOR_ACCELEROMETER_DATA and
+ *     optionally CHRE_EVENT_SENSOR_ACCELEROMETER_BIAS_INFO
+ *
+ * Note that the ACCELEROMETER_DATA is always the fully calibrated data,
+ * including factory calibration and runtime calibration if available.
+ *
+ * @see chreConfigureSensorBiasEvents
+ */
+#define CHRE_SENSOR_TYPE_ACCELEROMETER  UINT8_C(0x01)
+
+/**
+ * Instantaneous motion detection.
+ *
+ * Generates: CHRE_EVENT_SENSOR_INSTANT_MOTION_DETECT_DATA
+ *
+ * This is a one-shot sensor.
+ *
+ * This does not have a direct analogy within sensors.h.  This is similar
+ * to SENSOR_TYPE_MOTION_DETECT, but this triggers instantly upon any
+ * motion, instead of waiting for a period of continuous motion.
+ */
+#define CHRE_SENSOR_TYPE_INSTANT_MOTION_DETECT  UINT8_C(0x02)
+
+/**
+ * Stationary detection.
+ *
+ * Generates: CHRE_EVENT_SENSOR_STATIONARY_DETECT_DATA
+ *
+ * This is a one-shot sensor.
+ */
+#define CHRE_SENSOR_TYPE_STATIONARY_DETECT  UINT8_C(0x03)
+
+/**
+ * Gyroscope.
+ *
+ * Generates: CHRE_EVENT_SENSOR_GYROSCOPE_DATA and
+ *     optionally CHRE_EVENT_SENSOR_GYROSCOPE_BIAS_INFO
+ *
+ * Note that the GYROSCOPE_DATA is always the fully calibrated data, including
+ * factory calibration and runtime calibration if available.
+ *
+ * @see chreConfigureSensorBiasEvents
+ */
+#define CHRE_SENSOR_TYPE_GYROSCOPE  UINT8_C(0x06)
+
+/**
+ * Uncalibrated gyroscope.
+ *
+ * Generates: CHRE_EVENT_SENSOR_UNCALIBRATED_GYROSCOPE_DATA
+ *
+ * Note that the UNCALIBRATED_GYROSCOPE_DATA must be factory calibrated data,
+ * but not runtime calibrated.
+ */
+#define CHRE_SENSOR_TYPE_UNCALIBRATED_GYROSCOPE  UINT8_C(0x07)
+
+/**
+ * Magnetometer.
+ *
+ * Generates: CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_DATA and
+ *     optionally CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_BIAS_INFO
+ *
+ * Note that the GEOMAGNETIC_FIELD_DATA is always the fully calibrated data,
+ * including factory calibration and runtime calibration if available.
+ *
+ * @see chreConfigureSensorBiasEvents
+ */
+#define CHRE_SENSOR_TYPE_GEOMAGNETIC_FIELD  UINT8_C(0x08)
+
+/**
+ * Uncalibrated magnetometer.
+ *
+ * Generates: CHRE_EVENT_SENSOR_UNCALIBRATED_GEOMAGNETIC_FIELD_DATA
+ *
+ * Note that the UNCALIBRATED_GEOMAGNETIC_FIELD_DATA must be factory calibrated
+ * data, but not runtime calibrated.
+ */
+#define CHRE_SENSOR_TYPE_UNCALIBRATED_GEOMAGNETIC_FIELD  UINT8_C(0x09)
+
+/**
+ * Barometric pressure sensor.
+ *
+ * Generates: CHRE_EVENT_SENSOR_PRESSURE_DATA
+ */
+#define CHRE_SENSOR_TYPE_PRESSURE  UINT8_C(0x0A)
+
+/**
+ * Ambient light sensor.
+ *
+ * Generates: CHRE_EVENT_SENSOR_LIGHT_DATA
+ *
+ * This is an on-change sensor.
+ */
+#define CHRE_SENSOR_TYPE_LIGHT  UINT8_C(0x0C)
+
+/**
+ * Proximity detection.
+ *
+ * Generates: CHRE_EVENT_SENSOR_PROXIMITY_DATA
+ *
+ * This is an on-change sensor.
+ */
+#define CHRE_SENSOR_TYPE_PROXIMITY  UINT8_C(0x0D)
+
+/**
+ * Step detection.
+ *
+ * Generates: CHRE_EVENT_SENSOR_STEP_DETECT_DATA
+ *
+ * @since v1.3
+ */
+#define CHRE_SENSOR_TYPE_STEP_DETECT  UINT8_C(0x17)
+
+/**
+ * Step counter.
+ *
+ * Generates: CHRE_EVENT_SENSOR_STEP_COUNTER_DATA
+ *
+ * This is an on-change sensor. Note that the data returned by this sensor must
+ * match the value that can be obtained via the Android sensors framework at the
+ * same point in time. This means, if CHRE reboots from the rest of the system,
+ * the counter must not reset to 0.
+ *
+ * @since v1.5
+ */
+#define CHRE_SENSOR_TYPE_STEP_COUNTER UINT8_C(0x18)
+
+/**
+ * Significant motion detection.
+ *
+ * Generates: CHRE_EVENT_SENSOR_SIGNIFICANT_MOTION_DATA
+ *
+ * This is a one-shot sensor.
+ *
+ * @since v1.10
+ */
+#define CHRE_SENSOR_TYPE_SIGNIFICANT_MOTION  UINT8_C(0x1C)
+
+/**
+ * Hinge angle sensor.
+ *
+ * Generates: CHRE_EVENT_SENSOR_HINGE_ANGLE_DATA
+ *
+ * This is an on-change sensor.
+ *
+ * A sensor of this type measures the angle, in degrees, between two
+ * integral parts of the device. Movement of a hinge measured by this sensor
+ * type is expected to alter the ways in which the user may interact with
+ * the device, for example by unfolding or revealing a display.
+ *
+ * @since v1.5
+ */
+#define CHRE_SENSOR_TYPE_HINGE_ANGLE UINT8_C(0x24)
+
+/**
+ * Uncalibrated accelerometer.
+ *
+ * Generates: CHRE_EVENT_SENSOR_UNCALIBRATED_ACCELEROMETER_DATA
+ *
+ * Note that the UNCALIBRATED_ACCELEROMETER_DATA must be factory calibrated
+ * data, but not runtime calibrated.
+ */
+#define CHRE_SENSOR_TYPE_UNCALIBRATED_ACCELEROMETER  UINT8_C(0x37)
+
+/**
+ * Accelerometer temperature.
+ *
+ * Generates: CHRE_EVENT_SENSOR_ACCELEROMETER_TEMPERATURE_DATA
+ */
+#define CHRE_SENSOR_TYPE_ACCELEROMETER_TEMPERATURE  UINT8_C(0x38)
+
+/**
+ * Gyroscope temperature.
+ *
+ * Generates: CHRE_EVENT_SENSOR_GYROSCOPE_TEMPERATURE_DATA
+ */
+#define CHRE_SENSOR_TYPE_GYROSCOPE_TEMPERATURE  UINT8_C(0x39)
+
+/**
+ * Magnetometer temperature.
+ *
+ * Generates: CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_TEMPERATURE_DATA
+ */
+#define CHRE_SENSOR_TYPE_GEOMAGNETIC_FIELD_TEMPERATURE  UINT8_C(0x3A)
+
+#if CHRE_SENSOR_TYPE_GEOMAGNETIC_FIELD_TEMPERATURE >= CHRE_SENSOR_TYPE_VENDOR_START
+#error Too many sensor types
+#endif
+
+/**
+ * Values that can be stored in the accuracy field of chreSensorDataHeader.
+ * If CHRE_SENSOR_ACCURACY_UNKNOWN is returned, then the driver did not provide
+ * accuracy information with the data. Values in the range
+ * [CHRE_SENSOR_ACCURACY_VENDOR_START, CHRE_SENSOR_ACCURACY_VENDOR_END] are
+ * reserved for vendor-specific values for vendor sensor types, and are not used
+ * by CHRE for standard sensor types.
+ *
+ * Otherwise, the values have the same meaning as defined in the Android
+ * Sensors definition:
+ * https://developer.android.com/reference/android/hardware/SensorManager
+ *
+ * @since v1.3
+ *
+ * @defgroup CHRE_SENSOR_ACCURACY
+ * @{
+ */
+
+#define CHRE_SENSOR_ACCURACY_UNKNOWN       UINT8_C(0x00)
+#define CHRE_SENSOR_ACCURACY_UNRELIABLE    UINT8_C(0x01)
+#define CHRE_SENSOR_ACCURACY_LOW           UINT8_C(0x02)
+#define CHRE_SENSOR_ACCURACY_MEDIUM        UINT8_C(0x03)
+#define CHRE_SENSOR_ACCURACY_HIGH          UINT8_C(0x04)
+#define CHRE_SENSOR_ACCURACY_VENDOR_START  UINT8_C(0xC0)
+#define CHRE_SENSOR_ACCURACY_VENDOR_END    UINT8_MAX
+
+/** @} */
+
+/**
+ * Header used in every structure containing batchable data from a sensor.
+ *
+ * The typical structure for sensor data looks like:
+ *
+ *   struct chreSensorTypeData {
+ *       struct chreSensorDataHeader header;
+ *       struct chreSensorTypeSampleData {
+ *           uint32_t timestampDelta;
+ *           union {
+ *               <type> value;
+ *               <type> interpretation0;
+ *               <type> interpretation1;
+ *           };
+ *       } readings[1];
+ *   };
+ *
+ * Despite 'readings' being declared as an array of 1 element,
+ * an instance of the struct will actually have 'readings' as
+ * an array of header.readingCount elements (which may be 1).
+ * The 'timestampDelta' is in relation to the previous 'readings' (or
+ * the baseTimestamp for readings[0].  So,
+ * Timestamp for readings[0] == header.baseTimestamp +
+ *     readings[0].timestampDelta.
+ * Timestamp for readings[1] == timestamp for readings[0] +
+ *     readings[1].timestampDelta.
+ * And thus, in order to determine the timestamp for readings[N], it's
+ * necessary to process through all of the N-1 readings.  The advantage,
+ * though, is that our entire readings can span an arbitrary length of time,
+ * just as long as any two consecutive readings differ by no more than
+ * 4.295 seconds (timestampDelta, like all time in the CHRE, is in
+ * nanoseconds).
+ *
+ * If a sensor has batched readings where two consecutive readings differ by
+ * more than 4.295 seconds, the CHRE will split them across multiple
+ * instances of the struct, and send multiple events.
+ *
+ * The value from the sensor is typically expressed in a union,
+ * allowing a generic access to the data ('value'), along with
+ * differently named access giving a more natural interpretation
+ * of the data for the specific sensor types which use this
+ * structure.  This allows, for example, barometer code to
+ * reference readings[N].pressure, and an ambient light sensor
+ * to reference readings[N].light, while both use the same
+ * structure.
+ */
+struct chreSensorDataHeader {
+    /**
+     * The base timestamp, in nanoseconds; must be in the same time base as
+     * chreGetTime().
+     */
+    uint64_t baseTimestamp;
+
+    /**
+     * The handle of the sensor producing this event.
+     */
+    uint32_t sensorHandle;
+
+    /**
+     * The number elements in the 'readings' array.
+     *
+     * This must be at least 1.
+     */
+    uint16_t readingCount;
+
+    /**
+     * The accuracy of the sensor data.
+     *
+     * @ref CHRE_SENSOR_ACCURACY
+     *
+     * @since v1.3
+     */
+    uint8_t accuracy;
+
+    /**
+     * Reserved bytes.
+     *
+     * This must be 0.
+     */
+    uint8_t reserved;
+};
+
+/**
+ * Data for a sensor which reports on three axes.
+ *
+ * This is used by CHRE_EVENT_SENSOR_ACCELEROMETER_DATA,
+ * CHRE_EVENT_SENSOR_ACCELEROMETER_BIAS_INFO,
+ * CHRE_EVENT_SENSOR_UNCALIBRATED_ACCELEROMETER_DATA,
+ * CHRE_EVENT_SENSOR_GYROSCOPE_DATA,
+ * CHRE_EVENT_SENSOR_GYROSCOPE_BIAS_INFO,
+ * CHRE_EVENT_SENSOR_UNCALIBRATED_GYROSCOPE_DATA,
+ * CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_DATA,
+ * CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_BIAS_INFO, and
+ * CHRE_EVENT_SENSOR_UNCALIBRATED_GEOMAGNETIC_FIELD_DATA.
+ */
+struct chreSensorThreeAxisData {
+    /**
+     * @see chreSensorDataHeader
+     */
+    struct chreSensorDataHeader header;
+    struct chreSensorThreeAxisSampleData {
+        /**
+         * @see chreSensorDataHeader
+         */
+        uint32_t timestampDelta;
+        union {
+            float values[3];
+            float v[3];
+            struct {
+                float x;
+                float y;
+                float z;
+            };
+            float bias[3];
+            struct {
+                float x_bias;
+                float y_bias;
+                float z_bias;
+            };
+        };
+    } readings[1];
+};
+
+/**
+ * Data from a sensor where we only care about a event occurring.
+ *
+ * This is a bit unusual in that our readings have no data in addition
+ * to the timestamp.  But since we only care about the occurrence, we
+ * don't need to know anything else.
+ *
+ * Used by: CHRE_EVENT_SENSOR_INSTANT_MOTION_DETECT_DATA,
+ *     CHRE_EVENT_SENSOR_STATIONARY_DETECT_DATA,
+ *     CHRE_EVENT_SENSOR_STEP_DETECT_DATA, and
+ *     CHRE_EVENT_SENSOR_SIGNIFICANT_MOTION_DATA.
+ */
+struct chreSensorOccurrenceData {
+    struct chreSensorDataHeader header;
+    struct chreSensorOccurrenceSampleData {
+        uint32_t timestampDelta;
+        // This space intentionally left blank.
+        // Only the timestamp is meaningful here, there
+        // is no additional data.
+    } readings[1];
+};
+
+/**
+ * This is used by CHRE_EVENT_SENSOR_LIGHT_DATA,
+ * CHRE_EVENT_SENSOR_PRESSURE_DATA,
+ * CHRE_EVENT_SENSOR_ACCELEROMETER_TEMPERATURE_DATA,
+ * CHRE_EVENT_SENSOR_GYROSCOPE_TEMPERATURE_DATA,
+ * CHRE_EVENT_SENSOR_GEOMAGNETIC_FIELD_TEMPERATURE_DATA, and
+ * CHRE_EVENT_SENSOR_HINGE_ANGLE_DATA.
+ */
+struct chreSensorFloatData {
+    struct chreSensorDataHeader header;
+    struct chreSensorFloatSampleData {
+        uint32_t timestampDelta;
+        union {
+            float value;
+            float light;        //!< Unit: lux
+            float pressure;     //!< Unit: hectopascals (hPa)
+            float temperature;  //!< Unit: degrees Celsius
+            float angle;        //!< Unit: angular degrees
+        };
+    } readings[1];
+};
+
+/**
+ * CHRE_EVENT_SENSOR_PROXIMITY_DATA.
+ */
+struct chreSensorByteData {
+    struct chreSensorDataHeader header;
+    struct chreSensorByteSampleData {
+        uint32_t timestampDelta;
+        union {
+            uint8_t value;
+            struct {
+                uint8_t isNear : 1;
+                //! @deprecated As of v1.2, this field is deprecated and must
+                //! always be set to 0
+                uint8_t invalid : 1;
+                uint8_t padding0 : 6;
+            };
+        };
+    } readings[1];
+};
+
+/**
+ * Data for a sensor which reports a single uint64 value.
+ *
+ * This is used by CHRE_EVENT_SENSOR_STEP_COUNTER_DATA.
+ */
+struct chreSensorUint64Data {
+    struct chreSensorDataHeader header;
+    struct chreSensorUint64SampleData {
+        uint32_t timestampDelta;
+        uint64_t value;
+    } readings[1];
+};
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* _CHRE_SENSOR_TYPES_H_ */
diff --git a/chre_api/legacy/v1_11/chre/toolchain.h b/chre_api/legacy/v1_11/chre/toolchain.h
new file mode 100644
index 00000000..7c93bb16
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/toolchain.h
@@ -0,0 +1,87 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef CHRE_TOOLCHAIN_H_
+#define CHRE_TOOLCHAIN_H_
+
+/**
+ * @file
+ * Compiler/build toolchain-specific macros used by the CHRE API
+ */
+
+#if defined(__GNUC__) || defined(__clang__)
+// For GCC and clang
+
+#define CHRE_DEPRECATED(message) \
+  __attribute__((deprecated(message)))
+
+// Indicates that the function does not return (i.e. abort).
+#define CHRE_NO_RETURN __attribute__((noreturn))
+
+// Enable printf-style compiler warnings for mismatched format string and args
+#define CHRE_PRINTF_ATTR(formatPos, argStart) \
+  __attribute__((format(printf, formatPos, argStart)))
+
+#define CHRE_BUILD_ERROR(message) CHRE_DO_PRAGMA(GCC error message)
+#define CHRE_DO_PRAGMA(message) _Pragma(#message)
+
+// Marks a function as malloc-like, for optimizations with the return pointer
+#define CHRE_MALLOC_ATTR __attribute__((__malloc__))
+
+#elif defined(__ICCARM__) || defined(__CC_ARM)
+// For IAR ARM and Keil MDK-ARM compilers
+
+#define CHRE_PRINTF_ATTR(formatPos, argStart)
+
+#define CHRE_DEPRECATED(message)
+
+#define CHRE_NO_RETURN
+
+#define CHRE_MALLOC_ATTR
+
+#elif defined(_MSC_VER)
+// For Microsoft Visual Studio
+
+#define CHRE_PRINTF_ATTR(formatPos, argStart)
+
+#define CHRE_DEPRECATED(message)
+
+#define CHRE_NO_RETURN
+
+#define CHRE_MALLOC_ATTR
+
+#else  // if !defined(__GNUC__) && !defined(__clang__)
+
+#error Need to add support for new compiler
+
+#endif
+
+// For platforms that don't support error pragmas, utilize the best method of
+// showing an error depending on the platform support.
+#ifndef CHRE_BUILD_ERROR
+#ifdef __cplusplus  // C++17 or greater assumed
+#define CHRE_BUILD_ERROR(message) static_assert(0, message)
+#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
+#define CHRE_BUILD_ERROR(message) _Static_assert(0, message)
+#else
+#define CHRE_BUILD_ERROR(message) char buildError[-1] = message
+#endif
+#endif
+
+#endif  // CHRE_TOOLCHAIN_H_
diff --git a/chre_api/legacy/v1_11/chre/user_settings.h b/chre_api/legacy/v1_11/chre/user_settings.h
new file mode 100644
index 00000000..a13290d8
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/user_settings.h
@@ -0,0 +1,148 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_USER_SETTINGS_H_
+#define _CHRE_USER_SETTINGS_H_
+
+/**
+ * @file
+ * The API for requesting notifications on changes in the settings of the
+ * active user. If the device is set up with one or more secondary users
+ * (see https://source.android.com/devices/tech/admin/multi-user), the user
+ * settings in CHRE reflect that of the currently active user.
+ */
+
+#include <stdbool.h>
+#include <stdint.h>
+
+#include <chre/event.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * The user settings that nanoapps can request notifications for on a status
+ * change.
+ *
+ * NOTE: The WIFI available setting indicates the overall availability
+ * of WIFI related functionality. For example, if wifi is disabled for
+ * connectivity but enabled for location, the WIFI available setting is
+ * enabled.
+ *
+ * NOTE: The BLE available setting is the logical OR of the main Bluetooth
+ * setting and the Bluetooth scanning setting found under Location settings.
+ * Note that this indicates whether the user is allowing Bluetooth to be used,
+ * however the system may still fully power down the BLE chip in some scenarios
+ * if no request for it exists on the Android host side. See the
+ * chreBleStartScanAsync() API documentation for more information.
+ *
+ * @defgroup CHRE_USER_SETTINGS
+ * @{
+ */
+#define CHRE_USER_SETTING_LOCATION             UINT8_C(0)
+#define CHRE_USER_SETTING_WIFI_AVAILABLE       UINT8_C(1)
+#define CHRE_USER_SETTING_AIRPLANE_MODE        UINT8_C(2)
+#define CHRE_USER_SETTING_MICROPHONE           UINT8_C(3)
+#define CHRE_USER_SETTING_BLE_AVAILABLE        UINT8_C(4)
+
+/** @} */
+
+/**
+ * Produce an event ID in the block of IDs reserved for settings notifications.
+ *
+ * @param offset Index into the event ID block, valid in the range [0,15]
+ */
+#define CHRE_SETTING_EVENT_ID(offset) (CHRE_EVENT_SETTING_CHANGED_FIRST_EVENT + (offset))
+
+/**
+ * nanoappHandleEvent argument: struct chreUserSettingChangedEvent
+ *
+ * Notify nanoapps of a change in the associated setting. Nanoapps must first
+ * register (via chreUserSettingConfigureEvents) for events before they are
+ * sent out.
+ */
+#define CHRE_EVENT_SETTING_CHANGED_LOCATION         CHRE_SETTING_EVENT_ID(0)
+#define CHRE_EVENT_SETTING_CHANGED_WIFI_AVAILABLE   CHRE_SETTING_EVENT_ID(1)
+#define CHRE_EVENT_SETTING_CHANGED_AIRPLANE_MODE    CHRE_SETTING_EVENT_ID(2)
+#define CHRE_EVENT_SETTING_CHANGED_MICROPHONE       CHRE_SETTING_EVENT_ID(3)
+#define CHRE_EVENT_SETTING_CHANGED_BLE_AVAILABLE    CHRE_SETTING_EVENT_ID(4)
+
+#if CHRE_EVENT_SETTING_CHANGED_BLE_AVAILABLE > CHRE_EVENT_SETTING_CHANGED_LAST_EVENT
+#error Too many setting changed events.
+#endif
+
+/**
+ * Indicates the current state of a setting.
+ * The setting state is 'unknown' only in the following scenarios:
+ *  - CHRE hasn't received the initial state yet on a restart.
+ *  - The nanoapp is running on CHRE v1.4 or older
+ *  - Nanoapp provided in invalid setting ID to chreUserSettingGetStatus.
+ */
+enum chreUserSettingState {
+  CHRE_USER_SETTING_STATE_UNKNOWN = -1,
+  CHRE_USER_SETTING_STATE_DISABLED = 0,
+  CHRE_USER_SETTING_STATE_ENABLED = 1
+};
+
+/**
+ * The nanoappHandleEvent argument for CHRE settings changed notifications.
+ */
+struct chreUserSettingChangedEvent {
+  //! Indicates the setting whose state has changed.
+  uint8_t setting;
+
+  //! A value that corresponds to a member in enum chreUserSettingState,
+  // indicating the latest value of the setting.
+  int8_t settingState;
+};
+
+/**
+ * Get the current state of a given setting.
+ *
+ * @param setting The setting to get the current status of.
+ *
+ * @return The current state of the requested setting. The state is returned
+ * as an int8_t to be consistent with the associated event data, but is
+ * guaranteed to be a valid enum chreUserSettingState member.
+ *
+ * @since v1.5
+ */
+int8_t chreUserSettingGetState(uint8_t setting);
+
+/**
+ * Register or deregister for a notification on a status change for a given
+ * setting. Note that registration does not produce an event with the initial
+ * (or current) state, though nanoapps can use chreUserSettingGetState() for
+ * this purpose.
+ *
+ * @param setting The setting on whose change a notification is desired.
+ * @param enable The nanoapp is registered to receive notifications on a
+ * change in the user settings if this parameter is true, otherwise the
+ * nanoapp receives no further notifications for this setting.
+ *
+ * @since v1.5
+ */
+void chreUserSettingConfigureEvents(uint8_t setting, bool enable);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* _CHRE_USER_SETTINGS_H_ */
diff --git a/chre_api/legacy/v1_11/chre/version.h b/chre_api/legacy/v1_11/chre/version.h
new file mode 100644
index 00000000..467bb85e
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/version.h
@@ -0,0 +1,294 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_VERSION_H_
+#define _CHRE_VERSION_H_
+
+/**
+ * @file
+ * Definitions and methods for the versioning of the Context Hub Runtime
+ * Environment.
+ *
+ * The CHRE API versioning pertains to all header files in the CHRE API.
+ */
+
+#include <stdint.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * Value for version 0.1 of the Context Hub Runtime Environment API interface.
+ *
+ * This is a legacy version of the CHRE API. Version 1.0 is considered the first
+ * official CHRE API version.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_0_1 UINT32_C(0x00010000)
+
+/**
+ * Value for version 1.0 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API shipped with the Android Nougat release.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_0 UINT32_C(0x01000000)
+
+/**
+ * Value for version 1.1 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API shipped with the Android O release. It adds
+ * initial support for new GNSS, WiFi, and WWAN modules.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_1 UINT32_C(0x01010000)
+
+/**
+ * Value for version 1.2 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API shipped with the Android P release. It adds
+ * initial support for the new audio module.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_2 UINT32_C(0x01020000)
+
+/**
+ * Value for version 1.3 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API shipped with the Android Q release. It adds
+ * support for GNSS location altitude/speed/bearing accuracy. It also adds step
+ * detect as a standard CHRE sensor and supports bias event delivery and sensor
+ * data flushing.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_3 UINT32_C(0x01030000)
+
+/**
+ * Value for version 1.4 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API shipped with the Android R release. It adds
+ * support for collecting debug dump information from nanoapps, receiving L5
+ * GNSS measurements, determining if a sensor supports passive requests,
+ * receiving 5G cell info, and deprecates chreSendMessageToHost.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_4 UINT32_C(0x01040000)
+
+/**
+ * Value for version 1.5 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API shipped with the Android S release. It adds
+ * support for multiple sensors of the same type, permissions for sensitive CHRE
+ * APIs / data usage, ability to receive user settings updates, step counter and
+ * hinge angle sensors, improved WiFi scan preferences to support power
+ * optimization, new WiFi security types, increased the lower bound for the
+ * maximum CHRE to host message size, and increased GNSS measurements in
+ * chreGnssDataEvent.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_5 UINT32_C(0x01050000)
+
+/**
+ * Value for version 1.6 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API is shipped with the Android T release. It adds
+ * support for BLE scanning, subscribing to the WiFi NAN discovery engine,
+ * subscribing to host endpoint notifications, requesting metadata for a host
+ * endpoint ID, nanoapps publishing RPC services they support, and limits the
+ * nanoapp instance ID size to INT16_MAX.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_6 UINT32_C(0x01060000)
+
+/**
+ * Value for version 1.7 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API is shipped with a post-launch update to the
+ * Android T release. It adds the BLE flush API.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_7 UINT32_C(0x01070000)
+
+/**
+ * Value for version 1.8 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API is shipped with the Android U release. It adds
+ * support for filtering by manufacturer data in BLE scans, reading the RSSI
+ * value of a BLE connection, allowing the nanoapp to check BLE scan status,
+ * allowing the nanoapp to specify which RPC services it supports, and
+ * delivering batch complete events for batched BLE scans.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_8 UINT32_C(0x01080000)
+
+/**
+ * Value for version 1.9 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API is shipped with a post-launch update to the
+ * Android U release. It adds the BLE Broadcaster Address filter.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_9 UINT32_C(0x01090000)
+
+/**
+ * Value for version 1.10 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API is shipped with Android V. It adds support for
+ * reliable messaging.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_10 UINT32_C(0x010a0000)
+
+/**
+ * Value for version 1.11 of the Context Hub Runtime Environment API interface.
+ *
+ * This version of the CHRE API is shipped with Android 16. It adds support for
+ * for session-based generic endpoint messaging (msg.h), BLE socket offload,
+ * remote source GNSS, and explicit WWAN cell neighbor capability indication.
+ *
+ * @see CHRE_API_VERSION
+ */
+#define CHRE_API_VERSION_1_11 UINT32_C(0x010b0000)
+
+/**
+ * Major and Minor Version of this Context Hub Runtime Environment API.
+ *
+ * The major version changes when there is an incompatible API change.
+ *
+ * The minor version changes when there is an addition in functionality
+ * in a backwards-compatible manner.
+ *
+ * We define the version number as an unsigned 32-bit value.  The most
+ * significant byte is the Major Version.  The second-most significant byte
+ * is the Minor Version.  The two least significant bytes are the Patch
+ * Version.  The Patch Version is not defined by this header API, but
+ * is provided by a specific CHRE implementation (see chreGetVersion()).
+ *
+ * Note that version numbers can always be numerically compared with
+ * expected results, so 1.0.0 < 1.0.4 < 1.1.0 < 2.0.300 < 3.5.0.
+ */
+#define CHRE_API_VERSION CHRE_API_VERSION_1_11
+
+/**
+ * Utility macro to extract only the API major version of a composite CHRE
+ * version.
+ *
+ * @param version A uint32_t version, e.g. the value returned by
+ *     chreGetApiVersion()
+ *
+ * @return The API major version in the least significant byte, e.g. 0x01
+ */
+#define CHRE_EXTRACT_MAJOR_VERSION(version) \
+  (uint32_t)(((version) & UINT32_C(0xFF000000)) >> 24)
+
+/**
+ * Utility macro to extract only the API minor version of a composite CHRE
+ * version.
+ *
+ * @param version A uint32_t version, e.g. the CHRE_API_VERSION constant
+ *
+ * @return The API minor version in the least significant byte, e.g. 0x01
+ */
+#define CHRE_EXTRACT_MINOR_VERSION(version) \
+  (uint32_t)(((version) & UINT32_C(0x00FF0000)) >> 16)
+
+/**
+ * Utility macro to extract only the API minor version of a composite CHRE
+ * version.
+ *
+ * @param version A complete uint32_t version, e.g. the value returned by
+ *     chreGetVersion()
+ *
+ * @return The implementation patch version in the least significant two bytes,
+ *     e.g. 0x0123, with all other bytes set to 0
+ */
+#define CHRE_EXTRACT_PATCH_VERSION(version) (uint32_t)((version) & UINT32_C(0xFFFF))
+
+/**
+ * Get the API version the CHRE implementation was compiled against.
+ *
+ * This is not necessarily the CHRE_API_VERSION in the header the nanoapp was
+ * built against, and indeed may not have even appeared in the context_hub_os.h
+ * header which this nanoapp was built against.
+ *
+ * By definition, this will have the two least significant bytes set to 0,
+ * and only contain the major and minor version number.
+ *
+ * @return The API version.
+ */
+uint32_t chreGetApiVersion(void);
+
+/**
+ * Get the version of this CHRE implementation.
+ *
+ * By definition, ((chreGetApiVersion() & UINT32_C(0xFFFF0000)) ==
+ *                 (chreGetVersion()    & UINT32_C(0xFFFF0000))).
+ *
+ * The Patch Version, in the lower two bytes, only have meaning in context
+ * of this specific platform ID.  It is increased by the platform every time
+ * a backwards-compatible bug fix is released.
+ *
+ * @return The version.
+ *
+ * @see chreGetPlatformId()
+ */
+uint32_t chreGetVersion(void);
+
+/**
+ * Get the Platform ID of this CHRE.
+ *
+ * The most significant five bytes are the vendor ID as set out by the
+ * NANOAPP_VENDOR convention in the original context hub HAL header file
+ * (context_hub.h), also used by nanoapp IDs.
+ *
+ * The least significant three bytes are set by the vendor, but must be
+ * unique for each different CHRE implementation/hardware that the vendor
+ * supplies.
+ *
+ * The idea is that in the case of known bugs in the field, a new nanoapp could
+ * be shipped with a workaround that would use this value, and chreGetVersion(),
+ * to have code that can conditionally work around the bug on a buggy version.
+ * Thus, we require this uniqueness to allow such a setup to work.
+ *
+ * This platform ID is also the message hub ID for CHRE.
+ *
+ * @return The platform ID.
+ *
+ * @see CHRE_EXTRACT_VENDOR_ID
+ */
+uint64_t chreGetPlatformId(void);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif /* _CHRE_VERSION_H_ */
diff --git a/chre_api/legacy/v1_11/chre/wifi.h b/chre_api/legacy/v1_11/chre/wifi.h
new file mode 100644
index 00000000..e02f419f
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/wifi.h
@@ -0,0 +1,1321 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_WIFI_H_
+#define _CHRE_WIFI_H_
+
+/**
+ * @file
+ * WiFi (IEEE 802.11) API, currently covering scanning features useful for
+ * determining location and offloading certain connectivity scans.
+ *
+ * In this file, specification references use the following shorthand:
+ *
+ *    Shorthand | Full specification name
+ *   ---------- | ------------------------
+ *     "802.11" | IEEE Std 802.11-2007
+ *     "HT"     | IEEE Std 802.11n-2009
+ *     "VHT"    | IEEE Std 802.11ac-2013
+ *     "WiFi 6" | IEEE Std 802.11ax draft
+ *     "NAN"    | Wi-Fi Neighbor Awareness Networking (NAN) Technical
+ *                Specification (v3.2)
+ *
+ * In the current version of CHRE API, the 6GHz band introduced in WiFi 6 is
+ * not supported. A scan request from CHRE should not result in scanning 6GHz
+ * channels. In particular, if a 6GHz channel is specified in scanning or
+ * ranging request parameter, CHRE should return an error code of
+ * CHRE_ERROR_NOT_SUPPORTED. Additionally, CHRE implementations must not include
+ * observations of access points on 6GHz channels in scan results, especially
+ * those produced due to scan monitoring.
+ */
+
+#include "common.h"
+#include <chre/common.h>
+
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <string.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * The set of flags returned by chreWifiGetCapabilities().
+ * @defgroup CHRE_WIFI_CAPABILITIES
+ * @{
+ */
+
+//! No WiFi APIs are supported
+#define CHRE_WIFI_CAPABILITIES_NONE              (UINT32_C(0))
+
+//! Listening to scan results is supported, as enabled via
+//! chreWifiConfigureScanMonitorAsync()
+#define CHRE_WIFI_CAPABILITIES_SCAN_MONITORING   (UINT32_C(1) << 0)
+
+//! Requesting WiFi scans on-demand is supported via chreWifiRequestScanAsync()
+#define CHRE_WIFI_CAPABILITIES_ON_DEMAND_SCAN    (UINT32_C(1) << 1)
+
+//! Specifying the radio chain preference in on-demand scan requests, and
+//! reporting it in scan events is supported
+//! @since v1.2
+#define CHRE_WIFI_CAPABILITIES_RADIO_CHAIN_PREF  (UINT32_C(1) << 2)
+
+//! Requesting RTT ranging is supported via chreWifiRequestRangingAsync()
+//! @since v1.2
+#define CHRE_WIFI_CAPABILITIES_RTT_RANGING       (UINT32_C(1) << 3)
+
+//! Specifies if WiFi NAN service subscription is supported. If a platform
+//! supports subscriptions, then it must also support RTT ranging for NAN
+//! services via chreWifiNanRequestRangingAsync()
+//! @since v1.6
+#define CHRE_WIFI_CAPABILITIES_NAN_SUB           (UINT32_C(1) << 4)
+
+/** @} */
+
+/**
+ * Produce an event ID in the block of IDs reserved for WiFi
+ * @param offset  Index into WiFi event ID block; valid range [0,15]
+ */
+#define CHRE_WIFI_EVENT_ID(offset)  (CHRE_EVENT_WIFI_FIRST_EVENT + (offset))
+
+/**
+ * nanoappHandleEvent argument: struct chreAsyncResult
+ *
+ * Communicates the asynchronous result of a request to the WiFi API. The
+ * requestType field in {@link #chreAsyncResult} is set to a value from enum
+ * chreWifiRequestType.
+ */
+#define CHRE_EVENT_WIFI_ASYNC_RESULT  CHRE_WIFI_EVENT_ID(0)
+
+/**
+ * nanoappHandleEvent argument: struct chreWifiScanEvent
+ *
+ * Provides results of a WiFi scan.
+ */
+#define CHRE_EVENT_WIFI_SCAN_RESULT  CHRE_WIFI_EVENT_ID(1)
+
+/**
+ * nanoappHandleEvent argument: struct chreWifiRangingEvent
+ *
+ * Provides results of an RTT ranging request.
+ */
+#define CHRE_EVENT_WIFI_RANGING_RESULT  CHRE_WIFI_EVENT_ID(2)
+
+/**
+ * nanoappHandleEvent argument: struct chreWifiNanIdentifierEvent
+ *
+ * Lets the client know if the NAN engine was able to successfully assign
+ * an identifier to the subscribe call. The 'cookie' field in the event
+ * argument struct can be used to track which subscribe request this identifier
+ * maps to.
+ */
+#define CHRE_EVENT_WIFI_NAN_IDENTIFIER_RESULT   CHRE_WIFI_EVENT_ID(3)
+
+/**
+ * nanoappHandleEvent argument: struct chreWifiNanDiscoveryEvent
+ *
+ * Event that is sent whenever a NAN service matches the criteria specified
+ * in a subscription request.
+ */
+#define CHRE_EVENT_WIFI_NAN_DISCOVERY_RESULT  CHRE_WIFI_EVENT_ID(4)
+
+/**
+ * nanoappHandleEvent argument: struct chreWifiNanSessionLostEvent
+ *
+ * Informs the client that a discovered service is no longer available or
+ * visible.
+ * The ID of the service on the client that was communicating with the extinct
+ * service is indicated by the event argument.
+ */
+#define CHRE_EVENT_WIFI_NAN_SESSION_LOST  CHRE_WIFI_EVENT_ID(5)
+
+/**
+ * nanoappHandleEvent argument: struct chreWifiNanSessionTerminatedEvent
+ *
+ * Signals the end of a NAN subscription session. The termination can be due to
+ * the user turning the WiFi off, or other platform reasons like not being able
+ * to support NAN concurrency with the host. The terminated event will have a
+ * reason code appropriately populated to denote why the event was sent.
+ */
+#define CHRE_EVENT_WIFI_NAN_SESSION_TERMINATED  CHRE_WIFI_EVENT_ID(6)
+
+// NOTE: Do not add new events with ID > 15; only values 0-15 are reserved
+// (see chre/event.h)
+
+/**
+ * The maximum amount of time that is allowed to elapse between a call to
+ * chreWifiRequestScanAsync() that returns true, and the associated
+ * CHRE_EVENT_WIFI_ASYNC_RESULT used to indicate whether the scan completed
+ * successfully or not.
+ */
+#define CHRE_WIFI_SCAN_RESULT_TIMEOUT_NS  (30 * CHRE_NSEC_PER_SEC)
+
+/**
+ * The maximum amount of time that is allowed to elapse between a call to
+ * chreWifiRequestRangingAsync() that returns true, and the associated
+ * CHRE_EVENT_WIFI_RANGING_RESULT used to indicate whether the ranging operation
+ * completed successfully or not.
+ */
+#define CHRE_WIFI_RANGING_RESULT_TIMEOUT_NS  (30 * CHRE_NSEC_PER_SEC)
+
+/**
+ * The current compatibility version of the chreWifiScanEvent structure,
+ * including nested structures.
+ */
+#define CHRE_WIFI_SCAN_EVENT_VERSION  UINT8_C(1)
+
+/**
+ * The current compatibility version of the chreWifiRangingEvent structure,
+ * including nested structures.
+ */
+#define CHRE_WIFI_RANGING_EVENT_VERSION  UINT8_C(0)
+
+/**
+ * Maximum number of frequencies that can be explicitly specified when
+ * requesting a scan
+ * @see #chreWifiScanParams
+ */
+#define CHRE_WIFI_FREQUENCY_LIST_MAX_LEN  (20)
+
+/**
+ * Maximum number of SSIDs that can be explicitly specified when requesting a
+ * scan
+ * @see #chreWifiScanParams
+ */
+#define CHRE_WIFI_SSID_LIST_MAX_LEN  (20)
+
+/**
+ * The maximum number of devices that can be specified in a single RTT ranging
+ * request.
+ * @see #chreWifiRangingParams
+ */
+#define CHRE_WIFI_RANGING_LIST_MAX_LEN  (10)
+
+/**
+ * The maximum number of octets in an SSID (see 802.11 7.3.2.1)
+ */
+#define CHRE_WIFI_SSID_MAX_LEN  (32)
+
+/**
+ * The number of octets in a BSSID (see 802.11 7.1.3.3.3)
+ */
+#define CHRE_WIFI_BSSID_LEN  (6)
+
+/**
+ * Set of flags which can either indicate a frequency band. Specified as a bit
+ * mask to allow for combinations in future API versions.
+ * @defgroup CHRE_WIFI_BAND_MASK
+ * @{
+ */
+
+#define CHRE_WIFI_BAND_MASK_2_4_GHZ  (UINT8_C(1) << 0)  //!< 2.4 GHz
+#define CHRE_WIFI_BAND_MASK_5_GHZ    (UINT8_C(1) << 1)  //!< 5 GHz
+
+/** @} */
+
+/**
+ * Characteristics of a scanned device given in struct chreWifiScanResult.flags
+ * @defgroup CHRE_WIFI_SCAN_RESULT_FLAGS
+ * @{
+ */
+
+#define CHRE_WIFI_SCAN_RESULT_FLAGS_NONE                       UINT8_C(0)
+
+//! Element ID 61 (HT Operation) is present (see HT 7.3.2)
+#define CHRE_WIFI_SCAN_RESULT_FLAGS_HT_OPS_PRESENT             (UINT8_C(1) << 0)
+
+//! Element ID 192 (VHT Operation) is present (see VHT 8.4.2)
+#define CHRE_WIFI_SCAN_RESULT_FLAGS_VHT_OPS_PRESENT            (UINT8_C(1) << 1)
+
+//! Element ID 127 (Extended Capabilities) is present, and bit 70 (Fine Timing
+//! Measurement Responder) is set to 1 (see IEEE Std 802.11-2016 9.4.2.27)
+#define CHRE_WIFI_SCAN_RESULT_FLAGS_IS_FTM_RESPONDER           (UINT8_C(1) << 2)
+
+//! Retained for backwards compatibility
+//! @see CHRE_WIFI_SCAN_RESULT_FLAGS_IS_FTM_RESPONDER
+#define CHRE_WIFI_SCAN_RESULT_FLAGS_IS_80211MC_RTT_RESPONDER \
+    CHRE_WIFI_SCAN_RESULT_FLAGS_IS_FTM_RESPONDER
+
+//! HT Operation element indicates that a secondary channel is present
+//! (see HT 7.3.2.57)
+#define CHRE_WIFI_SCAN_RESULT_FLAGS_HAS_SECONDARY_CHANNEL_OFFSET \
+                                                               (UINT8_C(1) << 3)
+
+//! HT Operation element indicates that the secondary channel is below the
+//! primary channel (see HT 7.3.2.57)
+#define CHRE_WIFI_SCAN_RESULT_FLAGS_SECONDARY_CHANNEL_OFFSET_IS_BELOW  \
+                                                               (UINT8_C(1) << 4)
+
+/** @} */
+
+/**
+ * Identifies the authentication methods supported by an AP. Note that not every
+ * combination of flags may be possible. Based on WIFI_PNO_AUTH_CODE_* from
+ * hardware/libhardware_legacy/include/hardware_legacy/gscan.h in Android.
+ * @defgroup CHRE_WIFI_SECURITY_MODE_FLAGS
+ * @{
+ */
+
+#define CHRE_WIFI_SECURITY_MODE_UNKNOWN  (UINT8_C(0))
+//! @deprecated since v1.10. Use CHRE_WIFI_SECURITY_MODE_UNKNOWN instead.
+#define CHRE_WIFI_SECURITY_MODE_UNKONWN  CHRE_WIFI_SECURITY_MODE_UNKNOWN
+
+#define CHRE_WIFI_SECURITY_MODE_OPEN (UINT8_C(1) << 0)  //!< No auth/security
+#define CHRE_WIFI_SECURITY_MODE_WEP  (UINT8_C(1) << 1)
+#define CHRE_WIFI_SECURITY_MODE_PSK  (UINT8_C(1) << 2)  //!< WPA-PSK or WPA2-PSK
+#define CHRE_WIFI_SECURITY_MODE_EAP  (UINT8_C(1) << 3)  //!< WPA-EAP or WPA2-EAP
+
+//! @since v1.5
+#define CHRE_WIFI_SECURITY_MODE_SAE  (UINT8_C(1) << 4)
+
+//! @since v1.5
+#define CHRE_WIFI_SECURITY_MODE_EAP_SUITE_B  (UINT8_C(1) << 5)
+
+//! @since v1.5
+#define CHRE_WIFI_SECURITY_MODE_OWE  (UINT8_C(1) << 6)
+
+/** @} */
+
+/**
+ * Identifies which radio chain was used to discover an AP. The underlying
+ * hardware does not necessarily support more than one radio chain.
+ * @defgroup CHRE_WIFI_RADIO_CHAIN_FLAGS
+ * @{
+ */
+
+#define CHRE_WIFI_RADIO_CHAIN_UNKNOWN  (UINT8_C(0))
+#define CHRE_WIFI_RADIO_CHAIN_0        (UINT8_C(1) << 0)
+#define CHRE_WIFI_RADIO_CHAIN_1        (UINT8_C(1) << 1)
+
+/** @} */
+
+//! Special value indicating that an LCI uncertainty fields is not provided
+//! Ref: RFC 6225
+#define CHRE_WIFI_LCI_UNCERTAINTY_UNKNOWN  UINT8_C(0)
+
+/**
+ * Defines the flags that may be returned in
+ * {@link #chreWifiRangingResult.flags}. Undefined bits are reserved for future
+ * use and must be ignored by nanoapps.
+ * @defgroup CHRE_WIFI_RTT_RESULT_FLAGS
+ * @{
+ */
+
+//! If set, the nested chreWifiLci structure is populated; otherwise it is
+//! invalid and must be ignored
+#define CHRE_WIFI_RTT_RESULT_HAS_LCI  (UINT8_C(1) << 0)
+
+/** @} */
+
+/**
+ * Identifies a WiFi frequency band
+ */
+enum chreWifiBand {
+    CHRE_WIFI_BAND_2_4_GHZ = CHRE_WIFI_BAND_MASK_2_4_GHZ,
+    CHRE_WIFI_BAND_5_GHZ   = CHRE_WIFI_BAND_MASK_5_GHZ,
+};
+
+/**
+ * Indicates the BSS operating channel width determined from the VHT and/or HT
+ * Operation elements. Refer to VHT 8.4.2.161 and HT 7.3.2.57.
+ */
+enum chreWifiChannelWidth {
+    CHRE_WIFI_CHANNEL_WIDTH_20_MHZ         = 0,
+    CHRE_WIFI_CHANNEL_WIDTH_40_MHZ         = 1,
+    CHRE_WIFI_CHANNEL_WIDTH_80_MHZ         = 2,
+    CHRE_WIFI_CHANNEL_WIDTH_160_MHZ        = 3,
+    CHRE_WIFI_CHANNEL_WIDTH_80_PLUS_80_MHZ = 4,
+};
+
+/**
+ * Indicates the type of scan requested or performed
+ */
+enum chreWifiScanType {
+    //! Perform a purely active scan using probe requests. Do not scan channels
+    //! restricted to use via Dynamic Frequency Selection (DFS) only.
+    CHRE_WIFI_SCAN_TYPE_ACTIVE = 0,
+
+    //! Perform an active scan on unrestricted channels, and also perform a
+    //! passive scan on channels that are restricted to use via Dynamic
+    //! Frequency Selection (DFS), e.g. the U-NII bands 5250-5350MHz and
+    //! 5470-5725MHz in the USA as mandated by FCC regulation.
+    CHRE_WIFI_SCAN_TYPE_ACTIVE_PLUS_PASSIVE_DFS = 1,
+
+    //! Perform a passive scan, only listening for beacons.
+    CHRE_WIFI_SCAN_TYPE_PASSIVE = 2,
+
+    //! Client has no preference for a particular scan type.
+    //! Only valid in a {@link #chreWifiScanParams}.
+    //!
+    //! On a v1.4 or earlier platform, this will fall back to
+    //! CHRE_WIFI_SCAN_TYPE_ACTIVE if {@link #chreWifiScanParams.channelSet} is
+    //! set to CHRE_WIFI_CHANNEL_SET_NON_DFS, and to
+    //! CHRE_WIFI_SCAN_TYPE_ACTIVE_PLUS_PASSIVE_DFS otherwise.
+    //!
+    //! If CHRE_WIFI_CAPABILITIES_RADIO_CHAIN_PREF is supported, a v1.5 or
+    //! later platform shall perform a type of scan optimized for {@link
+    //! #chreWifiScanParams.radioChainPref}.
+    //!
+    //! Clients are strongly encouraged to set this value in {@link
+    //! #chreWifiScanParams.scanType} and instead express their preferences
+    //! through {@link #chreWifiRadioChainPref} and {@link #chreWifiChannelSet}
+    //! so the platform can best optimize power and performance.
+    //!
+    //! @since v1.5
+    CHRE_WIFI_SCAN_TYPE_NO_PREFERENCE = 3,
+};
+
+/**
+ * Indicates whether RTT ranging with a specific device succeeded
+ */
+enum chreWifiRangingStatus {
+    //! Ranging completed successfully
+    CHRE_WIFI_RANGING_STATUS_SUCCESS = 0,
+
+    //! Ranging failed due to an unspecified error
+    CHRE_WIFI_RANGING_STATUS_ERROR   = 1,
+};
+
+/**
+ * Possible values for {@link #chreWifiLci.altitudeType}. Ref: RFC 6225 2.4
+ */
+enum chreWifiLciAltitudeType {
+    CHRE_WIFI_LCI_ALTITUDE_TYPE_UNKNOWN = 0,
+    CHRE_WIFI_LCI_ALTITUDE_TYPE_METERS  = 1,
+    CHRE_WIFI_LCI_ALTITUDE_TYPE_FLOORS  = 2,
+};
+
+/**
+ * Indicates a type of request made in this API. Used to populate the resultType
+ * field of struct chreAsyncResult sent with CHRE_EVENT_WIFI_ASYNC_RESULT.
+ */
+enum chreWifiRequestType {
+    CHRE_WIFI_REQUEST_TYPE_CONFIGURE_SCAN_MONITOR = 1,
+    CHRE_WIFI_REQUEST_TYPE_REQUEST_SCAN           = 2,
+    CHRE_WIFI_REQUEST_TYPE_RANGING                = 3,
+    CHRE_WIFI_REQUEST_TYPE_NAN_SUBSCRIBE          = 4,
+};
+
+/**
+ * Allows a nanoapp to express its preference for how multiple available
+ * radio chains should be used when performing an on-demand scan. This is only a
+ * preference from the nanoapp and is not guaranteed to be honored by the WiFi
+ * firmware.
+ */
+enum chreWifiRadioChainPref {
+    //! No preference for radio chain usage
+    CHRE_WIFI_RADIO_CHAIN_PREF_DEFAULT = 0,
+
+    //! In a scan result, indicates that the radio chain preference used for the
+    //! scan is not known
+    CHRE_WIFI_RADIO_CHAIN_PREF_UNKNOWN = CHRE_WIFI_RADIO_CHAIN_PREF_DEFAULT,
+
+    //! Prefer to use available radio chains in a way that minimizes time to
+    //! complete the scan
+    CHRE_WIFI_RADIO_CHAIN_PREF_LOW_LATENCY = 1,
+
+    //! Prefer to use available radio chains in a way that minimizes total power
+    //! consumed for the scan
+    CHRE_WIFI_RADIO_CHAIN_PREF_LOW_POWER = 2,
+
+    //! Prefer to use available radio chains in a way that maximizes accuracy of
+    //! the scan result, e.g. RSSI measurements
+    CHRE_WIFI_RADIO_CHAIN_PREF_HIGH_ACCURACY = 3,
+};
+
+/**
+ * WiFi NAN subscription type.
+ */
+enum chreWifiNanSubscribeType {
+    //! In the active mode, explicit transmission of a subscribe message is
+    //! requested, and publish messages are processed.
+    CHRE_WIFI_NAN_SUBSCRIBE_TYPE_ACTIVE = 0,
+
+    //! In the passive mode, no transmission of a subscribe message is
+    //! requested, but received publish messages are checked for matches.
+    CHRE_WIFI_NAN_SUBSCRIBE_TYPE_PASSIVE = 1,
+};
+
+/**
+ * Indicates the reason for a subscribe session termination.
+ */
+enum chreWifiNanTerminatedReason {
+    CHRE_WIFI_NAN_TERMINATED_BY_USER_REQUEST = 0,
+    CHRE_WIFI_NAN_TERMINATED_BY_TIMEOUT = 1,
+    CHRE_WIFI_NAN_TERMINATED_BY_FAILURE = 2,
+};
+
+/**
+ * SSID with an explicit length field, used when an array of SSIDs is supplied.
+ */
+struct chreWifiSsidListItem {
+    //! Number of valid bytes in ssid. Valid range [0, CHRE_WIFI_SSID_MAX_LEN]
+    uint8_t ssidLen;
+
+    //! Service Set Identifier (SSID)
+    uint8_t ssid[CHRE_WIFI_SSID_MAX_LEN];
+};
+
+/**
+ * Indicates the set of channels to be scanned.
+ *
+ * @since v1.5
+ */
+enum chreWifiChannelSet {
+    //! The set of channels that allows active scan using probe request.
+    CHRE_WIFI_CHANNEL_SET_NON_DFS = 0,
+
+    //! The set of all channels supported.
+    CHRE_WIFI_CHANNEL_SET_ALL = 1,
+};
+
+/**
+ * Data structure passed to chreWifiRequestScanAsync
+ */
+struct chreWifiScanParams {
+    //! Set to a value from @ref enum chreWifiScanType
+    uint8_t scanType;
+
+    //! Indicates whether the client is willing to tolerate receiving cached
+    //! results of a previous scan, and if so, the maximum age of the scan that
+    //! the client will accept. "Age" in this case is defined as the elapsed
+    //! time between when the most recent scan was completed and the request is
+    //! received, in milliseconds. If set to 0, no cached results may be
+    //! provided, and all scan results must come from a "fresh" WiFi scan, i.e.
+    //! one that completes strictly after this request is received. If more than
+    //! one scan is cached and meets this age threshold, only the newest scan is
+    //! provided.
+    uint32_t maxScanAgeMs;
+
+    //! If set to 0, scan all frequencies. Otherwise, this indicates the number
+    //! of frequencies to scan, as specified in the frequencyList array. Valid
+    //! range [0, CHRE_WIFI_FREQUENCY_LIST_MAX_LEN].
+    uint16_t frequencyListLen;
+
+    //! Pointer to an array of frequencies to scan, given as channel center
+    //! frequencies in MHz. This field may be NULL if frequencyListLen is 0.
+    const uint32_t *frequencyList;
+
+    //! If set to 0, do not restrict scan to any SSIDs. Otherwise, this
+    //! indicates the number of SSIDs in the ssidList array to be used for
+    //! directed probe requests. Not applicable and ignore when scanType is
+    //! CHRE_WIFI_SCAN_TYPE_PASSIVE.
+    uint8_t ssidListLen;
+
+    //! Pointer to an array of SSIDs to use for directed probe requests. May be
+    //! NULL if ssidListLen is 0.
+    const struct chreWifiSsidListItem *ssidList;
+
+    //! Set to a value from enum chreWifiRadioChainPref to specify the desired
+    //! trade-off between power consumption, accuracy, etc. If
+    //! chreWifiGetCapabilities() does not have the applicable bit set, this
+    //! parameter is ignored.
+    //! @since v1.2
+    uint8_t radioChainPref;
+
+    //! Set to a value from enum chreWifiChannelSet to specify the set of
+    //! channels to be scanned. This field is considered by the platform only
+    //! if scanType is CHRE_WIFI_SCAN_TYPE_NO_PREFERENCE and frequencyListLen
+    //! is equal to zero.
+    //!
+    //! @since v1.5
+    uint8_t channelSet;
+};
+
+/**
+ * Provides information about a single access point (AP) detected in a scan.
+ */
+struct chreWifiScanResult {
+    //! Number of milliseconds prior to referenceTime in the enclosing
+    //! chreWifiScanEvent struct when the probe response or beacon frame that
+    //! was used to populate this structure was received.
+    uint32_t ageMs;
+
+    //! Capability Information field sent by the AP (see 802.11 7.3.1.4). This
+    //! field must reflect native byte order and bit ordering, such that
+    //! (capabilityInfo & 1) gives the bit for the ESS subfield.
+    uint16_t capabilityInfo;
+
+    //! Number of valid bytes in ssid. Valid range [0, CHRE_WIFI_SSID_MAX_LEN]
+    uint8_t ssidLen;
+
+    //! Service Set Identifier (SSID), a series of 0 to 32 octets identifying
+    //! the access point. Note that this is commonly a human-readable ASCII
+    //! string, but this is not the required encoding per the standard.
+    uint8_t ssid[CHRE_WIFI_SSID_MAX_LEN];
+
+    //! Basic Service Set Identifier (BSSID), represented in big-endian byte
+    //! order, such that the first octet of the OUI is accessed in byte index 0.
+    uint8_t bssid[CHRE_WIFI_BSSID_LEN];
+
+    //! A set of flags from CHRE_WIFI_SCAN_RESULT_FLAGS_*
+    uint8_t flags;
+
+    //! RSSI (Received Signal Strength Indicator), in dBm. Typically negative.
+    //! If multiple radio chains were used to scan this AP, this is a "best
+    //! available" measure that may be a composite of measurements taken across
+    //! the radio chains.
+    int8_t  rssi;
+
+    //! Operating band, set to a value from enum chreWifiBand
+    uint8_t band;
+
+    /**
+     * Indicates the center frequency of the primary 20MHz channel, given in
+     * MHz. This value is derived from the channel number via the formula:
+     *
+     *     primaryChannel (MHz) = CSF + 5 * primaryChannelNumber
+     *
+     * Where CSF is the channel starting frequency (in MHz) given by the
+     * operating class/band (i.e. 2407 or 5000), and primaryChannelNumber is the
+     * channel number in the range [1, 200].
+     *
+     * Refer to VHT 22.3.14.
+     */
+    uint32_t primaryChannel;
+
+    /**
+     * If the channel width is 20 MHz, this field is not relevant and set to 0.
+     * If the channel width is 40, 80, or 160 MHz, then this denotes the channel
+     * center frequency (in MHz). If the channel is 80+80 MHz, then this denotes
+     * the center frequency of segment 0, which contains the primary channel.
+     * This value is derived from the frequency index using the same formula as
+     * for primaryChannel.
+     *
+     * Refer to VHT 8.4.2.161, and VHT 22.3.14.
+     *
+     * @see #primaryChannel
+     */
+    uint32_t centerFreqPrimary;
+
+    /**
+     * If the channel width is 80+80MHz, then this denotes the center frequency
+     * of segment 1, which does not contain the primary channel. Otherwise, this
+     * field is not relevant and set to 0.
+     *
+     * @see #centerFreqPrimary
+     */
+    uint32_t centerFreqSecondary;
+
+    //! @see #chreWifiChannelWidth
+    uint8_t channelWidth;
+
+    //! Flags from CHRE_WIFI_SECURITY_MODE_* indicating supported authentication
+    //! and associated security modes
+    //! @see CHRE_WIFI_SECURITY_MODE_FLAGS
+    uint8_t securityMode;
+
+    //! Identifies the radio chain(s) used to discover this AP
+    //! @see CHRE_WIFI_RADIO_CHAIN_FLAGS
+    //! @since v1.2
+    uint8_t radioChain;
+
+    //! If the CHRE_WIFI_RADIO_CHAIN_0 bit is set in radioChain, gives the RSSI
+    //! measured on radio chain 0 in dBm; otherwise invalid and set to 0. This
+    //! field, along with its relative rssiChain1, can be used to determine RSSI
+    //! measurements from each radio chain when multiple chains were used to
+    //! discover this AP.
+    //! @see #radioChain
+    //! @since v1.2
+    int8_t rssiChain0;
+    int8_t rssiChain1;  //!< @see #rssiChain0
+
+    //! Reserved; set to 0
+    uint8_t reserved[7];
+};
+
+/**
+ * Data structure sent with events of type CHRE_EVENT_WIFI_SCAN_RESULT.
+ */
+struct chreWifiScanEvent {
+    //! Indicates the version of the structure, for compatibility purposes.
+    //! Clients do not normally need to worry about this field; the CHRE
+    //! implementation guarantees that the client only receives the structure
+    //! version it expects.
+    uint8_t version;
+
+    //! The number of entries in the results array in this event. The CHRE
+    //! implementation may split scan results across multiple events for memory
+    //! concerns, etc.
+    uint8_t resultCount;
+
+    //! The total number of results returned by the scan. Allows an event
+    //! consumer to identify when it has received all events associated with a
+    //! scan.
+    uint8_t resultTotal;
+
+    //! Sequence number for this event within the series of events comprising a
+    //! complete scan result. Scan events are delivered strictly in order, i.e.
+    //! this is monotonically increasing for the results of a single scan. Valid
+    //! range [0, <number of events for scan> - 1]. The number of events for a
+    //! scan is typically given by
+    //! ceil(resultTotal / <max results per event supported by platform>).
+    uint8_t eventIndex;
+
+    //! A value from enum chreWifiScanType indicating the type of scan performed
+    uint8_t scanType;
+
+    //! If a directed scan was performed to a limited set of SSIDs, then this
+    //! identifies the number of unique SSIDs included in the probe requests.
+    //! Otherwise, this is set to 0, indicating that the scan was not limited by
+    //! SSID. Note that if this is non-zero, the list of SSIDs used is not
+    //! included in the scan event.
+    uint8_t ssidSetSize;
+
+    //! If 0, indicates that all frequencies applicable for the scanType were
+    //! scanned. Otherwise, indicates the number of frequencies scanned, as
+    //! specified in scannedFreqList.
+    uint16_t scannedFreqListLen;
+
+    //! Timestamp when the scan was completed, from the same time base as
+    //! chreGetTime() (in nanoseconds)
+    uint64_t referenceTime;
+
+    //! Pointer to an array containing scannedFreqListLen values comprising the
+    //! set of frequencies that were scanned. Frequencies are specified as
+    //! channel center frequencies in MHz. May be NULL if scannedFreqListLen is
+    //! 0.
+    const uint32_t *scannedFreqList;
+
+    //! Pointer to an array containing resultCount entries. May be NULL if
+    //! resultCount is 0.
+    const struct chreWifiScanResult *results;
+
+    //! Set to a value from enum chreWifiRadioChainPref indicating the radio
+    //! chain preference used for the scan. If the applicable bit is not set in
+    //! chreWifiGetCapabilities(), this will always be set to
+    //! CHRE_WIFI_RADIO_CHAIN_PREF_UNKNOWN.
+    //! @since v1.2
+    uint8_t radioChainPref;
+};
+
+/**
+ * Identifies a device to perform RTT ranging against. These values are normally
+ * populated based on the contents of a scan result.
+ * @see #chreWifiScanResult
+ * @see chreWifiRangingTargetFromScanResult()
+ */
+struct chreWifiRangingTarget {
+    //! Device MAC address, specified in the same byte order as
+    //! {@link #chreWifiScanResult.bssid}
+    uint8_t macAddress[CHRE_WIFI_BSSID_LEN];
+
+    //! Center frequency of the primary 20MHz channel, in MHz
+    //! @see #chreWifiScanResult.primaryChannel
+    uint32_t primaryChannel;
+
+    //! Channel center frequency, in MHz, or 0 if not relevant
+    //! @see #chreWifiScanResult.centerFreqPrimary
+    uint32_t centerFreqPrimary;
+
+    //! Channel center frequency of segment 1 if channel width is 80+80MHz,
+    //! otherwise 0
+    //! @see #chreWifiScanResult.centerFreqSecondary
+    uint32_t centerFreqSecondary;
+
+    //! @see #chreWifiChannelWidth
+    uint8_t channelWidth;
+
+    //! Reserved for future use and ignored by CHRE
+    uint8_t reserved[3];
+};
+
+/**
+ * Parameters for an RTT ("Fine Timing Measurement" in terms of 802.11-2016)
+ * ranging request, supplied to chreWifiRequestRangingAsync().
+ */
+struct chreWifiRangingParams {
+    //! Number of devices to perform ranging against and the length of
+    //! targetList, in range [1, CHRE_WIFI_RANGING_LIST_MAX_LEN].
+    uint8_t targetListLen;
+
+    //! Array of macAddressListLen MAC addresses (e.g. BSSIDs) with which to
+    //! attempt RTT ranging.
+    const struct chreWifiRangingTarget *targetList;
+};
+
+/**
+ * Provides the result of RTT ranging with a single device.
+ */
+struct chreWifiRangingResult {
+    //! Time when the ranging operation on this device was performed, in the
+    //! same time base as chreGetTime() (in nanoseconds)
+    uint64_t timestamp;
+
+    //! MAC address of the device for which ranging was requested
+    uint8_t macAddress[CHRE_WIFI_BSSID_LEN];
+
+    //! Gives the result of ranging to this device. If not set to
+    //! CHRE_WIFI_RANGING_STATUS_SUCCESS, the ranging attempt to this device
+    //! failed, and other fields in this structure may be invalid.
+    //! @see #chreWifiRangingStatus
+    uint8_t status;
+
+    //! The mean RSSI measured during the RTT burst, in dBm. Typically negative.
+    //! If status is not CHRE_WIFI_RANGING_STATUS_SUCCESS, will be set to 0.
+    int8_t rssi;
+
+    //! Estimated distance to the device with the given BSSID, in millimeters.
+    //! Generally the mean of multiple measurements performed in a single burst.
+    //! If status is not CHRE_WIFI_RANGING_STATUS_SUCCESS, will be set to 0.
+    uint32_t distance;
+
+    //! Standard deviation of estimated distance across multiple measurements
+    //! performed in a single RTT burst, in millimeters. If status is not
+    //! CHRE_WIFI_RANGING_STATUS_SUCCESS, will be set to 0.
+    uint32_t distanceStdDev;
+
+    //! Location Configuration Information (LCI) information optionally returned
+    //! during the ranging procedure. Only valid if {@link #flags} has the
+    //! CHRE_WIFI_RTT_RESULT_HAS_LCI bit set. Refer to IEEE 802.11-2016
+    //! 9.4.2.22.10, 11.24.6.7, and RFC 6225 (July 2011) for more information.
+    //! Coordinates are to be interpreted according to the WGS84 datum.
+    struct chreWifiLci {
+        //! Latitude in degrees as 2's complement fixed-point with 25 fractional
+        //! bits, i.e. degrees * 2^25. Ref: RFC 6225 2.3
+        int64_t latitude;
+
+        //! Longitude, same format as {@link #latitude}
+        int64_t longitude;
+
+        //! Altitude represented as a 2's complement fixed-point value with 8
+        //! fractional bits. Interpretation depends on {@link #altitudeType}. If
+        //! UNKNOWN, this field must be ignored. If *METERS, distance relative
+        //! to the zero point in the vertical datum. If *FLOORS, a floor value
+        //! relative to the ground floor, potentially fractional, e.g. to
+        //! indicate mezzanine levels. Ref: RFC 6225 2.4
+        int32_t altitude;
+
+        //! Maximum extent of latitude uncertainty in degrees, decoded via this
+        //! formula: 2 ^ (8 - x) where "x" is the encoded value passed in this
+        //! field. Unknown if set to CHRE_WIFI_LCI_UNCERTAINTY_UNKNOWN.
+        //! Ref: RFC 6225 2.3.2
+        uint8_t latitudeUncertainty;
+
+        //! @see #latitudeUncertainty
+        uint8_t longitudeUncertainty;
+
+        //! Defines how to interpret altitude, set to a value from enum
+        //! chreWifiLciAltitudeType
+        uint8_t altitudeType;
+
+        //! Uncertainty in altitude, decoded via this formula: 2 ^ (21 - x)
+        //! where "x" is the encoded value passed in this field. Unknown if set
+        //! to CHRE_WIFI_LCI_UNCERTAINTY_UNKNOWN. Only applies when altitudeType
+        //! is CHRE_WIFI_LCI_ALTITUDE_TYPE_METERS. Ref: RFC 6225 2.4.5
+        uint8_t altitudeUncertainty;
+    } lci;
+
+    //! Refer to CHRE_WIFI_RTT_RESULT_FLAGS
+    uint8_t flags;
+
+    //! Reserved; set to 0
+    uint8_t reserved[7];
+};
+
+/**
+ * Data structure sent with events of type CHRE_EVENT_WIFI_RANGING_RESULT.
+ */
+struct chreWifiRangingEvent {
+    //! Indicates the version of the structure, for compatibility purposes.
+    //! Clients do not normally need to worry about this field; the CHRE
+    //! implementation guarantees that the client only receives the structure
+    //! version it expects.
+    uint8_t version;
+
+    //! The number of ranging results included in the results array; matches the
+    //! number of MAC addresses specified in the request
+    uint8_t resultCount;
+
+    //! Reserved; set to 0
+    uint8_t reserved[2];
+
+    //! Pointer to an array containing resultCount entries
+    const struct chreWifiRangingResult *results;
+};
+
+/**
+ * Indicates the WiFi NAN capabilities of the device. Must contain non-zero
+ * values if WiFi NAN is supported.
+ */
+struct chreWifiNanCapabilities {
+    //! Maximum length of the match filter arrays (applies to both tx and rx
+    //! match filters).
+    uint32_t maxMatchFilterLength;
+
+    //! Maximum length of the service specific information byte array.
+    uint32_t maxServiceSpecificInfoLength;
+
+    //! Maximum length of the service name. Includes the NULL terminator.
+    uint8_t maxServiceNameLength;
+
+    //! Reserved for future use.
+    uint8_t reserved[3];
+};
+
+/**
+ * Data structure sent with events of type
+ * CHRE_EVENT_WIFI_NAN_IDENTIFIER_RESULT
+ */
+struct chreWifiNanIdentifierEvent {
+    //! A unique ID assigned by the NAN engine for the subscribe request
+    //! associated with the cookie encapsulated in the async result below. The
+    //! ID is set to 0 if there was a request failure in which case the async
+    //! result below contains the appropriate error code indicating the failure
+    //! reason.
+    uint32_t id;
+
+    //! Structure which contains the cookie associated with the publish/
+    //! subscribe request, along with an error code that indicates request
+    //! success or failure.
+    struct chreAsyncResult result;
+};
+
+/**
+ * Indicates the desired configuration for a WiFi NAN ranging request.
+ */
+struct chreWifiNanRangingParams {
+    //! MAC address of the NAN device for which range is to be determined.
+    uint8_t macAddress[CHRE_WIFI_BSSID_LEN];
+};
+
+/**
+ * Configuration parameters specific to the Subscribe Function (Spec 4.1.1.1)
+ */
+struct chreWifiNanSubscribeConfig {
+    //! Indicates the subscribe type, set to a value from @ref
+    //! chreWifiNanSubscribeType.
+    uint8_t subscribeType;
+
+    //! UTF-8 name string that identifies the service/application. Must be NULL
+    //! terminated. Note that the string length cannot be greater than the
+    //! maximum length specified by @ref chreWifiNanCapabilities. No
+    //! restriction is placed on the string case, since the service name
+    //! matching is expected to be case insensitive.
+    const char *service;
+
+    //! An array of bytes (and the associated array length) of service-specific
+    //! information. Note that the array length must be less than the
+    //! maxServiceSpecificInfoLength parameter obtained from the NAN
+    //! capabilities (@see struct chreWifiNanCapabilities).
+    const uint8_t *serviceSpecificInfo;
+    uint32_t serviceSpecificInfoSize;
+
+    //! Ordered sequence of {length | value} pairs that specify match criteria
+    //! beyond the service name. 'length' uses 1 byte, and its value indicates
+    //! the number of bytes of the match criteria that follow. The length of
+    //! the match filter array should not exceed the maximum match filter
+    //! length obtained from @ref chreWifiNanGetCapabilities. When a service
+    //! publish message discovery frame containing the Service ID being
+    //! subscribed to is received, the matching is done as follows:
+    //! Each {length | value} pair in the kth position (1 <= k <= #length-value
+    //! pairs) is compared against the kth {length | value} pair in the
+    //! matching filter field of the publish message.
+    //! - For a kth position {length | value} pair in the rx match filter with
+    //!   a length of 0, a match is declared regardless of the tx match filter
+    //!   contents.
+    //! - For a kth position {length | value} pair in the rx match with a non-
+    //!   zero length, there must be an exact match with the kth position pair
+    //!    in the match filter field of the received service descriptor for a
+    //!    match to be found.
+    //! Please refer to Appendix H of the NAN spec for examples on matching.
+    //! The match filter length should not exceed the maxMatchFilterLength
+    //! obtained from @ref chreWifiNanCapabilities.
+    const uint8_t *matchFilter;
+    uint32_t matchFilterLength;
+};
+
+/**
+ * Data structure sent with events of type
+ * CHRE_EVENT_WIFI_NAN_DISCOVERY_RESULT.
+ */
+struct chreWifiNanDiscoveryEvent {
+    //! Identifier of the subscribe function instance that requested a
+    //! discovery.
+    uint32_t subscribeId;
+
+    //! Identifier of the publisher on the remote NAN device.
+    uint32_t publishId;
+
+    //! NAN interface address of the publisher
+    uint8_t publisherAddress[CHRE_WIFI_BSSID_LEN];
+
+    //! An array of bytes (and the associated array length) of service-specific
+    //! information. Note that the array length must be less than the
+    //! maxServiceSpecificInfoLength parameter obtained from the NAN
+    //! capabilities (@see struct chreWifiNanCapabilities).
+    const uint8_t *serviceSpecificInfo;
+    uint32_t serviceSpecificInfoSize;
+};
+
+/**
+ * Data structure sent with events of type CHRE_EVENT_WIFI_NAN_SESSION_LOST.
+ */
+struct chreWifiNanSessionLostEvent {
+    //! The original ID (returned by the NAN discovery engine) of the subscriber
+    //! instance.
+    uint32_t id;
+
+    //! The ID of the previously discovered publisher on a peer NAN device that
+    //! is no longer connected.
+    uint32_t peerId;
+};
+
+/**
+ * Data structure sent with events of type
+ * CHRE_EVENT_WIFI_NAN_SESSION_TERMINATED.
+ */
+struct chreWifiNanSessionTerminatedEvent {
+    //! The original ID (returned by the NAN discovery engine) of the subscriber
+    //! instance that was terminated.
+    uint32_t id;
+
+    //! A value that maps to one of the termination reasons in @ref enum
+    //! chreWifiNanTerminatedReason.
+    uint8_t reason;
+
+    //! Reserved for future use.
+    uint8_t reserved[3];
+};
+
+/**
+ * Retrieves a set of flags indicating the WiFi features supported by the
+ * current CHRE implementation. The value returned by this function must be
+ * consistent for the entire duration of the Nanoapp's execution.
+ *
+ * The client must allow for more flags to be set in this response than it knows
+ * about, for example if the implementation supports a newer version of the API
+ * than the client was compiled against.
+ *
+ * @return A bitmask with zero or more CHRE_WIFI_CAPABILITIES_* flags set
+ *
+ * @since v1.1
+ */
+uint32_t chreWifiGetCapabilities(void);
+
+/**
+ * Retrieves device-specific WiFi NAN capabilities, and populates them in
+ * the @ref chreWifiNanCapabilities structure.
+ *
+ * @param capabilities Structure into which the WiFi NAN capabilities of
+ *        the device are populated into. Must not be NULL.
+ * @return true if WiFi NAN is supported, false otherwise.
+ *
+ * @since v1.6
+ */
+bool chreWifiNanGetCapabilities(struct chreWifiNanCapabilities *capabilities);
+
+/**
+ * Nanoapps must define CHRE_NANOAPP_USES_WIFI somewhere in their build
+ * system (e.g. Makefile) if the nanoapp needs to use the following WiFi APIs.
+ * In addition to allowing access to these APIs, defining this macro will also
+ * ensure CHRE enforces that all host clients this nanoapp talks to have the
+ * required Android permissions needed to listen to WiFi data by adding metadata
+ * to the nanoapp.
+ */
+#if defined(CHRE_NANOAPP_USES_WIFI) || !defined(CHRE_IS_NANOAPP_BUILD)
+
+/**
+ * Manages a client's request to receive the results of WiFi scans performed for
+ * other purposes, for example scans done to maintain connectivity and scans
+ * requested by other clients. The presence of this request has no effect on the
+ * frequency or configuration of the WiFi scans performed - it is purely a
+ * registration by the client to receive the results of scans that would
+ * otherwise occur normally. This should include all available scan results,
+ * including those that are not normally sent to the applications processor,
+ * such as Preferred Network Offload (PNO) scans. Scan results provided because
+ * of this registration must not contain cached results - they are always
+ * expected to contain the fresh results from a recent scan.
+ *
+ * An active scan monitor subscription must persist across temporary conditions
+ * under which no WiFi scans will be performed, for example if WiFi is
+ * completely disabled via user-controlled settings, or if the WiFi system
+ * restarts independently of CHRE. Likewise, a request to enable a scan monitor
+ * subscription must succeed under normal conditions, even in circumstances
+ * where no WiFi scans will be performed. In these cases, the scan monitor
+ * implementation must produce scan results once the temporary condition is
+ * cleared, for example after WiFi is enabled by the user.
+ *
+ * These scan results are delivered to the Nanoapp's handle event callback using
+ * CHRE_EVENT_WIFI_SCAN_RESULT.
+ *
+ * An active scan monitor subscription is not necessary to receive the results
+ * of an on-demand scan request sent via chreWifiRequestScanAsync(), and it does
+ * not result in duplicate delivery of scan results generated from
+ * chreWifiRequestScanAsync().
+ *
+ * If no monitor subscription is active at the time of a request with
+ * enable=false, it is treated as if an active subscription was successfully
+ * ended.
+ *
+ * The result of this request is delivered asynchronously via an event of type
+ * CHRE_EVENT_WIFI_ASYNC_RESULT. Refer to the note in {@link #chreAsyncResult}
+ * for more details.
+ *
+ * @param enable Set to true to enable monitoring scan results, false to
+ *        disable
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *        sent in relation to this request.
+ * @return true if the request was accepted for processing, false otherwise
+ *
+ * @since v1.1
+ * @note Requires WiFi permission
+ */
+bool chreWifiConfigureScanMonitorAsync(bool enable, const void *cookie);
+
+/**
+ * Sends an on-demand request for WiFi scan results. This may trigger a new
+ * scan, or be entirely serviced from cache, depending on the maxScanAgeMs
+ * parameter.
+ *
+ * This resulting status of this request is delivered asynchronously via an
+ * event of type CHRE_EVENT_WIFI_ASYNC_RESULT. The result must be delivered
+ * within CHRE_WIFI_SCAN_RESULT_TIMEOUT_NS of the this request. Refer to the
+ * note in {@link #chreAsyncResult} for more details.
+ *
+ * A successful result provided in CHRE_EVENT_WIFI_ASYNC_RESULT indicates that
+ * the scan results are ready to be delivered in a subsequent event (or events,
+ * which arrive consecutively without any other scan results in between)
+ * of type CHRE_EVENT_WIFI_SCAN_RESULT.
+ *
+ * WiFi scanning must be disabled if both "WiFi scanning" and "WiFi" settings
+ * are disabled at the Android level. In this case, the CHRE implementation is
+ * expected to return a result with CHRE_ERROR_FUNCTION_DISABLED.
+ *
+ * It is not valid for a client to request a new scan while a result is pending
+ * based on a previous scan request from the same client. In this situation, the
+ * CHRE implementation is expected to return a result with CHRE_ERROR_BUSY.
+ * However, if a scan is currently pending or in progress due to a request from
+ * another client, whether within the CHRE or otherwise, the implementation must
+ * not fail the request for this reason. If the pending scan satisfies the
+ * client's request parameters, then the implementation should use its results
+ * to satisfy the request rather than scheduling a new scan.
+ *
+ * @param params A set of parameters for the scan request. Must not be NULL.
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *        sent in relation to this request.
+ * @return true if the request was accepted for processing, false otherwise
+ *
+ * @since v1.1
+ * @note Requires WiFi permission
+ */
+bool chreWifiRequestScanAsync(const struct chreWifiScanParams *params,
+                              const void *cookie);
+
+/**
+ * Convenience function which calls chreWifiRequestScanAsync() with a default
+ * set of scan parameters.
+ *
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *        sent in relation to this request.
+ * @return true if the request was accepted for processing, false otherwise
+ *
+ * @since v1.1
+ * @note Requires WiFi permission
+ */
+static inline bool chreWifiRequestScanAsyncDefault(const void *cookie) {
+    static const struct chreWifiScanParams params = {
+        /*.scanType=*/         CHRE_WIFI_SCAN_TYPE_NO_PREFERENCE,
+        /*.maxScanAgeMs=*/     5000,  // 5 seconds
+        /*.frequencyListLen=*/ 0,
+        /*.frequencyList=*/    NULL,
+        /*.ssidListLen=*/      0,
+        /*.ssidList=*/         NULL,
+        /*.radioChainPref=*/   CHRE_WIFI_RADIO_CHAIN_PREF_DEFAULT,
+        /*.channelSet=*/       CHRE_WIFI_CHANNEL_SET_NON_DFS
+    };
+    return chreWifiRequestScanAsync(&params, cookie);
+}
+
+/**
+ * Issues a request to initiate distance measurements using round-trip time
+ * (RTT), aka Fine Timing Measurement (FTM), to one or more devices identified
+ * by MAC address. Within CHRE, MACs are typically the BSSIDs of scanned APs
+ * that have the CHRE_WIFI_SCAN_RESULT_FLAGS_IS_FTM_RESPONDER flag set.
+ *
+ * This resulting status of this request is delivered asynchronously via an
+ * event of type CHRE_EVENT_WIFI_ASYNC_RESULT. The result must be delivered
+ * within CHRE_WIFI_RANGING_RESULT_TIMEOUT_NS of the this request. Refer to the
+ * note in {@link #chreAsyncResult} for more details.
+ *
+ * WiFi RTT ranging must be disabled if any of the following is true:
+ * - Both "WiFi" and "WiFi Scanning" settings are disabled at the Android level.
+ * - The "Location" setting is disabled at the Android level.
+ * In this case, the CHRE implementation is expected to return a result with
+ * CHRE_ERROR_FUNCTION_DISABLED.
+ *
+ * A successful result provided in CHRE_EVENT_WIFI_ASYNC_RESULT indicates that
+ * the results of ranging will be delivered in a subsequent event of type
+ * CHRE_EVENT_WIFI_RANGING_RESULT. Note that the CHRE_EVENT_WIFI_ASYNC_RESULT
+ * gives an overall status - for example, it is used to indicate failure if the
+ * entire ranging request was rejected because WiFi is disabled. However, it is
+ * valid for this event to indicate success, but RTT ranging to fail for all
+ * requested devices - for example, they may be out of range. Therefore, it is
+ * also necessary to check the status field in {@link #chreWifiRangingResult}.
+ *
+ * @param params Structure containing the parameters of the scan request,
+ *        including the list of devices to attempt ranging.
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *        sent in relation to this request.
+ * @return true if the request was accepted for processing, false otherwise
+ *
+ * @since v1.2
+ * @note Requires WiFi permission
+ */
+bool chreWifiRequestRangingAsync(const struct chreWifiRangingParams *params,
+                                 const void *cookie);
+
+/**
+ * Helper function to populate an instance of struct chreWifiRangingTarget with
+ * the contents of a scan result provided in struct chreWifiScanResult.
+ * Populates other parameters that are not directly derived from the scan result
+ * with default values.
+ *
+ * @param scanResult The scan result to parse as input
+ * @param rangingTarget The RTT ranging target to populate as output
+ *
+ * @note Requires WiFi permission
+ */
+static inline void chreWifiRangingTargetFromScanResult(
+        const struct chreWifiScanResult *scanResult,
+        struct chreWifiRangingTarget *rangingTarget) {
+    memcpy(rangingTarget->macAddress, scanResult->bssid,
+           sizeof(rangingTarget->macAddress));
+    rangingTarget->primaryChannel      = scanResult->primaryChannel;
+    rangingTarget->centerFreqPrimary   = scanResult->centerFreqPrimary;
+    rangingTarget->centerFreqSecondary = scanResult->centerFreqSecondary;
+    rangingTarget->channelWidth        = scanResult->channelWidth;
+
+    // Note that this is not strictly necessary (CHRE can see which API version
+    // the nanoapp was built against, so it knows to ignore these fields), but
+    // we do it here to keep things nice and tidy
+    memset(rangingTarget->reserved, 0, sizeof(rangingTarget->reserved));
+}
+
+/**
+ * Subscribe to a NAN service.
+ *
+ * Sends a subscription request to the NAN discovery engine with the
+ * specified configuration parameters. If successful, a unique non-zero
+ * subscription ID associated with this instance of the subscription
+ * request is assigned by the NAN discovery engine. The subscription request
+ * is active until explicitly canceled, or if the connection was interrupted.
+ *
+ * Note that CHRE forwards any discovery events that it receives to the
+ * subscribe function instance, and does no duplicate filtering. If
+ * multiple events of the same discovery are undesirable, it is up to the
+ * platform NAN discovery engine implementation to implement redundancy
+ * detection mechanisms.
+ *
+ * If WiFi is turned off by the user at the Android level, an existing
+ * subscribe session is canceled, and a CHRE_EVENT_WIFI_ASYNC_RESULT event is
+ * event is sent to the subscriber. Nanoapps are expected to register for user
+ * settings notifications (@see chreUserSettingConfigureEvents), and
+ * re-establish a subscribe session on a WiFi re-enabled settings changed
+ * notification.
+ *
+ * @param config Service subscription configuration
+ * @param cookie A value that the nanoapp uses to track this particular
+ *        subscription request.
+ * @return true if NAN is enabled and a subscription request was successfully
+ *         made to the NAN engine. The actual result of the service discovery
+ *         is sent via a CHRE_EVENT_WIFI_NAN_DISCOVERY_RESULT event.
+ *
+ * @since v1.6
+ * @note Requires WiFi permission
+ */
+bool chreWifiNanSubscribe(struct chreWifiNanSubscribeConfig *config,
+                          const void *cookie);
+
+/**
+ * Cancel a subscribe function instance.
+ *
+ * @param subscriptionId The ID that was originally assigned to this instance
+ *        of the subscribe function.
+ * @return true if NAN is enabled, the subscribe ID  was found and the instance
+ *         successfully canceled.
+ *
+ * @since v1.6
+ * @note Requires WiFi permission
+ */
+bool chreWifiNanSubscribeCancel(uint32_t subscriptionID);
+
+/**
+ * Request RTT ranging from a peer NAN device.
+ *
+ * Nanoapps can use this API to explicitly request measurement reports from
+ * the peer device. Note that both end points have to support ranging for a
+ * successful request. The MAC address of the peer NAN device for which ranging
+ * is desired may be obtained either from a NAN service discovery or from an
+ * out-of-band source (HAL service, BLE, etc.).
+ *
+ * If WiFi is turned off by the user at the Android level, an existing
+ * ranging session is canceled, and a CHRE_EVENT_WIFI_ASYNC_RESULT event is
+ * sent to the subscriber. Nanoapps are expected to register for user settings
+ * notifications (@see chreUserSettingConfigureEvents), and perform another
+ * ranging request on a WiFi re-enabled settings changed notification.
+ *
+ * A successful result provided in CHRE_EVENT_WIFI_ASYNC_RESULT indicates that
+ * the results of ranging will be delivered in a subsequent event of type
+ * CHRE_EVENT_WIFI_RANGING_RESULT.
+ *
+ * @param params Structure containing the parameters of the ranging request,
+ *        including the MAC address of the peer NAN device to attempt ranging.
+ * @param cookie An opaque value that will be included in the chreAsyncResult
+ *        sent in relation to this request.
+ * @return true if the request was accepted for processing, false otherwise.
+ * @since v1.6
+ * @note Requires WiFi permission
+ */
+bool chreWifiNanRequestRangingAsync(const struct chreWifiNanRangingParams *params,
+                                    const void *cookie);
+
+#else  /* defined(CHRE_NANOAPP_USES_WIFI) || !defined(CHRE_IS_NANOAPP_BUILD) */
+#define CHRE_WIFI_PERM_ERROR_STRING \
+    "CHRE_NANOAPP_USES_WIFI must be defined when building this nanoapp in " \
+    "order to refer to "
+#define chreWifiConfigureScanMonitorAsync(...) \
+    CHRE_BUILD_ERROR(CHRE_WIFI_PERM_ERROR_STRING \
+                     "chreWifiConfigureScanMonitorAsync")
+#define chreWifiRequestScanAsync(...) \
+    CHRE_BUILD_ERROR(CHRE_WIFI_PERM_ERROR_STRING \
+                     "chreWifiRequestScanAsync")
+#define chreWifiRequestScanAsyncDefault(...) \
+    CHRE_BUILD_ERROR(CHRE_WIFI_PERM_ERROR_STRING \
+                     "chreWifiRequestScanAsyncDefault")
+#define chreWifiRequestRangingAsync(...) \
+    CHRE_BUILD_ERROR(CHRE_WIFI_PERM_ERROR_STRING "chreWifiRequestRangingAsync")
+#define chreWifiRangingTargetFromScanResult(...) \
+    CHRE_BUILD_ERROR(CHRE_WIFI_PERM_ERROR_STRING \
+                     "chreWifiRangingTargetFromScanResult")
+#define chreWifiNanSubscribe(...) \
+    CHRE_BUILD_ERROR(CHRE_WIFI_PERM_ERROR_STRING "chreWifiNanSubscribe")
+#define chreWifiNanSubscribeCancel(...) \
+    CHRE_BUILD_ERROR(CHRE_WIFI_PERM_ERROR_STRING "chreWifiNanSubscribeCancel")
+#define chreWifiNanRequestRangingAsync(...) \
+    CHRE_BUILD_ERROR(CHRE_WIFI_PERM_ERROR_STRING "chreWifiNanRequestRangingAsync")
+#endif  /* defined(CHRE_NANOAPP_USES_WIFI) || !defined(CHRE_IS_NANOAPP_BUILD) */
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* _CHRE_WIFI_H_ */
diff --git a/chre_api/legacy/v1_11/chre/wwan.h b/chre_api/legacy/v1_11/chre/wwan.h
new file mode 100644
index 00000000..80cbf3d3
--- /dev/null
+++ b/chre_api/legacy/v1_11/chre/wwan.h
@@ -0,0 +1,600 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+// IWYU pragma: private, include "chre_api/chre.h"
+// IWYU pragma: friend chre/.*\.h
+
+#ifndef _CHRE_WWAN_H_
+#define _CHRE_WWAN_H_
+
+/**
+ * @file
+ * Wireless Wide Area Network (WWAN, i.e. mobile/cellular network) API relevant
+ * for querying cell tower identity and associated information that can be
+ * useful in determining location.
+ *
+ * Based on Android N RIL definitions (located at this path as of the time of
+ * this comment: hardware/ril/include/telephony/ril.h), version 12. Updated
+ * based on Android radio HAL definition (hardware/interfaces/radio) for more
+ * recent Android builds. Refer to those files and associated documentation for
+ * further details.
+ *
+ * In general, the parts of this API that are taken from the RIL follow the
+ * field naming conventions established in that interface rather than the CHRE
+ * API conventions, in order to avoid confusion and enable code re-use where
+ * applicable. Note that structure names include the chreWwan* prefix rather
+ * than RIL_*, but field names are the same. If necessary to enable code
+ * sharing, it is recommended to create typedefs that map from the CHRE
+ * structures to the associated RIL type names, for example "typedef struct
+ * chreWwanCellIdentityGsm RIL_CellIdentityGsm_v12", etc.
+ */
+
+#include <chre/common.h>
+
+#include <stdbool.h>
+#include <stdint.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * The set of flags returned by chreWwanGetCapabilities().
+ * @defgroup CHRE_WWAN_CAPABILITIES
+ * @{
+ */
+
+//! No WWAN APIs are supported
+#define CHRE_WWAN_CAPABILITIES_NONE       (UINT32_C(0))
+
+//! Current cell information can be queried via chreWwanGetCellInfoAsync()
+#define CHRE_WWAN_GET_CELL_INFO           (UINT32_C(1) << 0)
+
+//! The chreWwanCellInfoResult from chreWwanGetCellInfoAsync() will include
+//! all available chreWwanCellInfo as entries in cells, not just a single
+//! primary result.
+//! @since v1.11 - Neighbor support in prior versions of the API is unspecified.
+#define CHRE_WWAN_GET_CELL_NEIGHBOR_INFO  (UINT32_C(1) << 1)
+
+/** @} */
+
+/**
+ * Produce an event ID in the block of IDs reserved for WWAN
+ * @param offset  Index into WWAN event ID block; valid range [0,15]
+ */
+#define CHRE_WWAN_EVENT_ID(offset)  (CHRE_EVENT_WWAN_FIRST_EVENT + (offset))
+
+/**
+ * nanoappHandleEvent argument: struct chreWwanCellInfoResult
+ *
+ * Provides the result of an asynchronous request for cell info sent via
+ * chreWwanGetCellInfoAsync().
+ */
+#define CHRE_EVENT_WWAN_CELL_INFO_RESULT  CHRE_WWAN_EVENT_ID(0)
+
+// NOTE: Do not add new events with ID > 15; only values 0-15 are reserved
+// (see chre/event.h)
+
+/**
+ * The current version of struct chreWwanCellInfoResult associated with this
+ * API definition.
+ */
+#define CHRE_WWAN_CELL_INFO_RESULT_VERSION  UINT8_C(1)
+
+//! Reference: RIL_CellIdentityGsm_v12
+struct chreWwanCellIdentityGsm {
+    //! 3-digit Mobile Country Code, 0..999, INT32_MAX if unknown
+    int32_t mcc;
+
+    //! 2 or 3-digit Mobile Network Code, 0..999, INT32_MAX if unknown
+    int32_t mnc;
+
+    //! 16-bit Location Area Code, 0..65535, INT32_MAX if unknown
+    int32_t lac;
+
+    //! 16-bit GSM Cell Identity described in TS 27.007, 0..65535,
+    //! INT32_MAX if unknown
+    int32_t cid;
+
+    //! 16-bit GSM Absolute RF channel number, INT32_MAX if unknown
+    int32_t arfcn;
+
+    //! 6-bit Base Station Identity Code, UINT8_MAX if unknown
+    uint8_t bsic;
+
+    //! Reserved for future use; must be set to 0
+    uint8_t reserved[3];
+};
+
+//! Reference: RIL_CellIdentityWcdma_v12
+struct chreWwanCellIdentityWcdma {
+    //! 3-digit Mobile Country Code, 0..999, INT32_MAX if unknown
+    int32_t mcc;
+
+    //! 2 or 3-digit Mobile Network Code, 0..999, INT32_MAX if unknown
+    int32_t mnc;
+
+    //! 16-bit Location Area Code, 0..65535, INT32_MAX if unknown
+    int32_t lac;
+
+    //! 28-bit UMTS Cell Identity described in TS 25.331, 0..268435455,
+    //! INT32_MAX if unknown
+    int32_t cid;
+
+    //! 9-bit UMTS Primary Scrambling Code described in TS 25.331, 0..511,
+    //! INT32_MAX if unknown
+    int32_t psc;
+
+    //! 16-bit UMTS Absolute RF Channel Number, INT32_MAX if unknown
+    int32_t uarfcn;
+};
+
+//! Reference: RIL_CellIdentityCdma
+struct chreWwanCellIdentityCdma {
+    //! Network Id 0..65535, INT32_MAX if unknown
+    int32_t networkId;
+
+    //! CDMA System Id 0..32767, INT32_MAX if unknown
+    int32_t systemId;
+
+    //! Base Station Id 0..65535, INT32_MAX if unknown
+    int32_t basestationId;
+
+    //! Longitude is a decimal number as specified in 3GPP2 C.S0005-A v6.0.
+    //! It is represented in units of 0.25 seconds and ranges from -2592000
+    //! to 2592000, both values inclusive (corresponding to a range of -180
+    //! to +180 degrees). INT32_MAX if unknown
+    int32_t longitude;
+
+    //! Latitude is a decimal number as specified in 3GPP2 C.S0005-A v6.0.
+    //! It is represented in units of 0.25 seconds and ranges from -1296000
+    //! to 1296000, both values inclusive (corresponding to a range of -90
+    //! to +90 degrees). INT32_MAX if unknown
+    int32_t latitude;
+};
+
+//! Reference: RIL_CellIdentityLte_v12
+struct chreWwanCellIdentityLte {
+    //! 3-digit Mobile Country Code, 0..999, INT32_MAX if unknown
+    int32_t mcc;
+
+    //! 2 or 3-digit Mobile Network Code, 0..999, INT32_MAX if unknown
+    int32_t mnc;
+
+    //! 28-bit Cell Identity described in TS ???, INT32_MAX if unknown
+    int32_t ci;
+
+    //! physical cell id 0..503, INT32_MAX if unknown
+    int32_t pci;
+
+    //! 16-bit tracking area code, INT32_MAX if unknown
+    int32_t tac;
+
+    //! 18-bit LTE Absolute RF Channel Number, INT32_MAX if unknown
+    int32_t earfcn;
+};
+
+//! Reference: RIL_CellIdentityTdscdma
+struct chreWwanCellIdentityTdscdma {
+    //! 3-digit Mobile Country Code, 0..999, INT32_MAX if unknown
+    int32_t mcc;
+
+    //! 2 or 3-digit Mobile Network Code, 0..999, INT32_MAX if unknown
+    int32_t mnc;
+
+    //! 16-bit Location Area Code, 0..65535, INT32_MAX if unknown
+    int32_t lac;
+
+    //! 28-bit UMTS Cell Identity described in TS 25.331, 0..268435455,
+    //! INT32_MAX if unknown
+    int32_t cid;
+
+    //! 8-bit Cell Parameters ID described in TS 25.331, 0..127, INT32_MAX if
+    //! unknown
+    int32_t cpid;
+};
+
+//! Reference: android.hardware.radio@1.4 CellIdentityNr
+//! @since v1.4
+struct chreWwanCellIdentityNr {
+    //! 3-digit Mobile Country Code, in range [0, 999]. This value must be valid
+    //! for registered or camped cells. INT32_MAX means invalid/unreported.
+    int32_t mcc;
+
+    //! 2 or 3-digit Mobile Network Code, in range [0, 999]. This value must be
+    //! valid for registered or camped cells. INT32_MAX means
+    //! invalid/unreported.
+    int32_t mnc;
+
+    //! NR Cell Identity in range [0, 68719476735] (36 bits), which
+    //! unambiguously identifies a cell within a public land mobile network
+    //! (PLMN). This value must be valid for registered or camped cells.
+    //! Reference: TS 38.413 section 9.3.1.7.
+    //!
+    //! Note: for backward compatibility reasons, the nominally int64_t nci is
+    //! split into two uint32_t values, with nci0 being the least significant 4
+    //! bytes. If chreWwanUnpackNrNci returns INT64_MAX, it means nci is
+    //! invalid/unreported.
+    //!
+    //! Users are recommended to use the helper accessor chreWwanUnpackNrNci to
+    //! access the nci field.
+    //!
+    //! @see chreWwanUnpackNrNci
+    uint32_t nci0;
+    uint32_t nci1;
+
+    //! Physical cell id in range [0, 1007]. This value must be valid.
+    //! Reference: TS 38.331 section 6.3.2.
+    int32_t pci;
+
+    //! 24-bit tracking area code in range [0, 16777215]. INT32_MAX means
+    //! invalid/unreported.
+    //! Reference: TS 38.413 section 9.3.3.10 and TS 29.571 section 5.4.2.
+    int32_t tac;
+
+    //! NR Absolute Radio Frequency Channel Number, in range [0, 3279165]. This
+    //! value must be valid.
+    //! Reference: TS 38.101-1 section 5.4.2.1 and TS 38.101-2 section 5.4.2.1.
+    int32_t nrarfcn;
+};
+
+//! Reference: RIL_GSM_SignalStrength_v12
+struct chreWwanSignalStrengthGsm {
+    //! Valid values are (0-31, 99) as defined in TS 27.007 8.5
+    //! INT32_MAX means invalid/unreported.
+    int32_t signalStrength;
+
+    //! bit error rate (0-7, 99) as defined in TS 27.007 8.5
+    //! INT32_MAX means invalid/unreported.
+    int32_t bitErrorRate;
+
+    //! Timing Advance in bit periods. 1 bit period = 48.13 us.
+    //! INT32_MAX means invalid/unreported.
+    int32_t timingAdvance;
+};
+
+//! Reference: RIL_SignalStrengthWcdma
+struct chreWwanSignalStrengthWcdma {
+    //! Valid values are (0-31, 99) as defined in TS 27.007 8.5
+    //! INT32_MAX means invalid/unreported.
+    int32_t signalStrength;
+
+    //! bit error rate (0-7, 99) as defined in TS 27.007 8.5
+    //! INT32_MAX means invalid/unreported.
+    int32_t bitErrorRate;
+};
+
+//! Reference: RIL_CDMA_SignalStrength
+struct chreWwanSignalStrengthCdma {
+    //! Valid values are positive integers.  This value is the actual RSSI value
+    //! multiplied by -1.  Example: If the actual RSSI is -75, then this
+    //! response value will be 75.
+    //! INT32_MAX means invalid/unreported.
+    int32_t dbm;
+
+    //! Valid values are positive integers.  This value is the actual Ec/Io
+    //! multiplied by -10.  Example: If the actual Ec/Io is -12.5 dB, then this
+    //! response value will be 125.
+    //! INT32_MAX means invalid/unreported.
+    int32_t ecio;
+};
+
+//! Reference: RIL_EVDO_SignalStrength
+struct chreWwanSignalStrengthEvdo {
+    //! Valid values are positive integers.  This value is the actual RSSI value
+    //! multiplied by -1.  Example: If the actual RSSI is -75, then this
+    //! response value will be 75.
+    //! INT32_MAX means invalid/unreported.
+    int32_t dbm;
+
+    //! Valid values are positive integers.  This value is the actual Ec/Io
+    //! multiplied by -10.  Example: If the actual Ec/Io is -12.5 dB, then this
+    //! response value will be 125.
+    //! INT32_MAX means invalid/unreported.
+    int32_t ecio;
+
+    //! Valid values are 0-8.  8 is the highest signal to noise ratio.
+    //! INT32_MAX means invalid/unreported.
+    int32_t signalNoiseRatio;
+};
+
+//! Reference: RIL_LTE_SignalStrength_v8
+struct chreWwanSignalStrengthLte {
+    //! Valid values are (0-31, 99) as defined in TS 27.007 8.5
+    int32_t signalStrength;
+
+    //! The current Reference Signal Receive Power in dBm multiplied by -1.
+    //! Range: 44 to 140 dBm
+    //! INT32_MAX means invalid/unreported.
+    //! Reference: 3GPP TS 36.133 9.1.4
+    int32_t rsrp;
+
+    //! The current Reference Signal Receive Quality in dB multiplied by -1.
+    //! Range: 3 to 20 dB.
+    //! INT32_MAX means invalid/unreported.
+    //! Reference: 3GPP TS 36.133 9.1.7
+    int32_t rsrq;
+
+    //! The current reference signal signal-to-noise ratio in 0.1 dB units.
+    //! Range: -200 to +300 (-200 = -20.0 dB, +300 = 30dB).
+    //! INT32_MAX means invalid/unreported.
+    //! Reference: 3GPP TS 36.101 8.1.1
+    int32_t rssnr;
+
+    //! The current Channel Quality Indicator.
+    //! Range: 0 to 15.
+    //! INT32_MAX means invalid/unreported.
+    //! Reference: 3GPP TS 36.101 9.2, 9.3, A.4
+    int32_t cqi;
+
+    //! timing advance in micro seconds for a one way trip from cell to device.
+    //! Approximate distance can be calculated using 300m/us * timingAdvance.
+    //! Range: 0 to 0x7FFFFFFE
+    //! INT32_MAX means invalid/unreported.
+    //! Reference: 3GPP 36.321 section 6.1.3.5
+    //! also: http://www.cellular-planningoptimization.com/2010/02/timing-advance-with-calculation.html
+    int32_t timingAdvance;
+};
+
+//! Reference: RIL_TD_SCDMA_SignalStrength
+struct chreWwanSignalStrengthTdscdma {
+    //! The Received Signal Code Power in dBm multiplied by -1.
+    //! Range : 25 to 120
+    //! INT32_MAX means invalid/unreported.
+    //! Reference: 3GPP TS 25.123, section 9.1.1.1
+    int32_t rscp;
+};
+
+//! Reference: android.hardware.radio@1.4 NrSignalStrength
+//! @since v1.4
+struct chreWwanSignalStrengthNr {
+    //! SS (second synchronization) reference signal received power in dBm
+    //! multiplied by -1.
+    //! Range [44, 140], INT32_MAX means invalid/unreported.
+    //! Reference: TS 38.215 section 5.1.1 and TS 38.133 section 10.1.6.
+    int32_t ssRsrp;
+
+    //! SS reference signal received quality in 0.5 dB units.
+    //! Range [-86, 41] with -86 = -43.0 dB and 41 = 20.5 dB.
+    //! INT32_MAX means invalid/unreported.
+    //! Reference: TS 38.215 section 5.1.3 and TS 38.133 section 10.1.11.1.
+    int32_t ssRsrq;
+
+    //! SS signal-to-noise and interference ratio in 0.5 dB units.
+    //! Range [-46, 81] with -46 = -23.0 dB and 81 = 40.5 dB.
+    //! INT32_MAX means invalid/unreported.
+    //! Reference: TS 38.215 section 5.1.5 and TS 38.133 section 10.1.16.1.
+    int32_t ssSinr;
+
+    //! CSI reference signal received power in dBm multiplied by -1.
+    //! Range [44, 140], INT32_MAX means invalid/unreported.
+    //! Reference: TS 38.215 section 5.1.2 and TS 38.133 section 10.1.6.
+    int32_t csiRsrp;
+
+    //! CSI reference signal received quality in 0.5 dB units.
+    //! Range [-86, 41] with -86 = -43.0 dB and 41 = 20.5 dB.
+    //! INT32_MAX means invalid/unreported.
+    //! Reference: TS 38.215 section 5.1.4 and TS 38.133 section 10.1.11.1.
+    int32_t csiRsrq;
+
+    //! CSI signal-to-noise and interference ratio in 0.5 dB units.
+    //! Range [-46, 81] with -46 = -23.0 dB and 81 = 40.5 dB.
+    //! INT32_MAX means invalid/unreported.
+    //! Reference: TS 38.215 section 5.1.6 and TS 38.133 section 10.1.16.1.
+    int32_t csiSinr;
+};
+
+//! Reference: RIL_CellInfoGsm_v12
+struct chreWwanCellInfoGsm {
+    struct chreWwanCellIdentityGsm    cellIdentityGsm;
+    struct chreWwanSignalStrengthGsm  signalStrengthGsm;
+};
+
+//! Reference: RIL_CellInfoWcdma_v12
+struct chreWwanCellInfoWcdma {
+    struct chreWwanCellIdentityWcdma    cellIdentityWcdma;
+    struct chreWwanSignalStrengthWcdma  signalStrengthWcdma;
+};
+
+//! Reference: RIL_CellInfoCdma
+struct chreWwanCellInfoCdma {
+    struct chreWwanCellIdentityCdma    cellIdentityCdma;
+    struct chreWwanSignalStrengthCdma  signalStrengthCdma;
+    struct chreWwanSignalStrengthEvdo  signalStrengthEvdo;
+};
+
+//! Reference: RIL_CellInfoLte_v12
+struct chreWwanCellInfoLte {
+    struct chreWwanCellIdentityLte    cellIdentityLte;
+    struct chreWwanSignalStrengthLte  signalStrengthLte;
+};
+
+//! Reference: RIL_CellInfoTdscdma
+struct chreWwanCellInfoTdscdma {
+    struct chreWwanCellIdentityTdscdma    cellIdentityTdscdma;
+    struct chreWwanSignalStrengthTdscdma  signalStrengthTdscdma;
+};
+
+//! Reference: android.hardware.radio@1.4 CellInfoNr
+//! @since v1.4
+struct chreWwanCellInfoNr {
+    struct chreWwanCellIdentityNr    cellIdentityNr;
+    struct chreWwanSignalStrengthNr  signalStrengthNr;
+};
+
+//! Reference: RIL_CellInfoType
+//! All other values are reserved and should be ignored by nanoapps.
+enum chreWwanCellInfoType {
+    CHRE_WWAN_CELL_INFO_TYPE_GSM      = 1,
+    CHRE_WWAN_CELL_INFO_TYPE_CDMA     = 2,
+    CHRE_WWAN_CELL_INFO_TYPE_LTE      = 3,
+    CHRE_WWAN_CELL_INFO_TYPE_WCDMA    = 4,
+    CHRE_WWAN_CELL_INFO_TYPE_TD_SCDMA = 5,
+    CHRE_WWAN_CELL_INFO_TYPE_NR       = 6,  //! @since v1.4
+};
+
+//! Reference: RIL_TimeStampType
+enum chreWwanCellTimeStampType {
+    CHRE_WWAN_CELL_TIMESTAMP_TYPE_UNKNOWN  = 0,
+    CHRE_WWAN_CELL_TIMESTAMP_TYPE_ANTENNA  = 1,
+    CHRE_WWAN_CELL_TIMESTAMP_TYPE_MODEM    = 2,
+    CHRE_WWAN_CELL_TIMESTAMP_TYPE_OEM_RIL  = 3,
+    CHRE_WWAN_CELL_TIMESTAMP_TYPE_JAVA_RIL = 4,
+};
+
+//! Reference: RIL_CellInfo_v12
+struct chreWwanCellInfo {
+    //! Timestamp in nanoseconds; must be in the same time base as chreGetTime()
+    uint64_t timeStamp;
+
+    //! A value from enum {@link #CellInfoType} indicating the radio access
+    //! technology of the cell, and which field in union CellInfo can be used
+    //! to retrieve additional information
+    uint8_t cellInfoType;
+
+    //! A value from enum {@link #CellTimeStampType} that identifies the source
+    //! of the value in timeStamp. This is typically set to
+    //! CHRE_WWAN_CELL_TIMESTAMP_TYPE_OEM_RIL, and indicates the time given by
+    //! chreGetTime() that an intermediate module received the data from the
+    //! modem and forwarded it to the requesting CHRE client.
+    uint8_t timeStampType;
+
+    //! !0 if this cell is registered, 0 if not registered
+    uint8_t registered;
+
+    //! Reserved for future use; must be set to 0
+    uint8_t reserved;
+
+    //! The value in cellInfoType indicates which field in this union is valid
+    union chreWwanCellInfoPerRat {
+        struct chreWwanCellInfoGsm     gsm;
+        struct chreWwanCellInfoCdma    cdma;
+        struct chreWwanCellInfoLte     lte;
+        struct chreWwanCellInfoWcdma   wcdma;
+        struct chreWwanCellInfoTdscdma tdscdma;
+        struct chreWwanCellInfoNr      nr;  //! @since v1.4
+    } CellInfo;
+};
+
+/**
+ * Data structure provided with events of type CHRE_EVENT_WWAN_CELL_INFO_RESULT.
+ */
+struct chreWwanCellInfoResult {
+    //! Indicates the version of the structure, for compatibility purposes.
+    //! Clients do not normally need to worry about this field; the CHRE
+    //! implementation guarantees that the client only receives the structure
+    //! version it expects.
+    uint8_t version;
+
+    //! Populated with a value from enum {@link #chreError}, indicating whether
+    //! the request failed, and if so, provides the cause of the failure
+    uint8_t errorCode;
+
+    //! The number of valid entries in cells[]
+    uint8_t cellInfoCount;
+
+    //! Reserved for future use; must be set to 0
+    uint8_t reserved;
+
+    //! Set to the cookie parameter given to chreWwanGetCellInfoAsync()
+    const void *cookie;
+
+    //! Pointer to an array of cellInfoCount elements containing information
+    //! about serving and neighbor cells
+    const struct chreWwanCellInfo *cells;
+};
+
+
+/**
+ * Retrieves a set of flags indicating the WWAN features supported by the
+ * current CHRE implementation. The value returned by this function must be
+ * consistent for the entire duration of the Nanoapp's execution.
+ *
+ * The client must allow for more flags to be set in this response than it knows
+ * about, for example if the implementation supports a newer version of the API
+ * than the client was compiled against.
+ *
+ * @return A bitmask with zero or more CHRE_WWAN_CAPABILITIES_* flags set
+ *
+ * @since v1.1
+ */
+uint32_t chreWwanGetCapabilities(void);
+
+/**
+ * Nanoapps must define CHRE_NANOAPP_USES_WWAN somewhere in their build
+ * system (e.g. Makefile) if the nanoapp needs to use the following WWAN APIs.
+ * In addition to allowing access to these APIs, defining this macro will also
+ * ensure CHRE enforces that all host clients this nanoapp talks to have the
+ * required Android permissions needed to listen to WWAN data by adding metadata
+ * to the nanoapp.
+ */
+#if defined(CHRE_NANOAPP_USES_WWAN) || !defined(CHRE_IS_NANOAPP_BUILD)
+
+/**
+ * Query information about the current serving cell and its neighbors. This does
+ * not perform a network scan, but should return state from the current network
+ * registration data stored in the cellular modem. This is effectively the same
+ * as a request for RIL_REQUEST_GET_CELL_INFO_LIST in the RIL.
+ *
+ * The requested cellular information is returned asynchronously via
+ * CHRE_EVENT_WWAN_CELL_INFO_RESULT. The implementation must send this event,
+ * either with successful data or an error status, within
+ * CHRE_ASYNC_RESULT_TIMEOUT_NS.
+ *
+ * If the airplane mode setting is enabled at the Android level, the CHRE
+ * implementation is expected to return a successful asynchronous result with an
+ * empty cell info list.
+ *
+ * @param cookie An opaque value that will be included in the
+ *               chreWwanCellInfoResult sent in relation to this request.
+ *
+ * @return true if the request was accepted for processing, false otherwise
+ *
+ * @since v1.1
+ * @note Requires WWAN permission
+ */
+bool chreWwanGetCellInfoAsync(const void *cookie);
+
+/**
+ * Helper accessor for nci in the chreWwanCellIdentityNr struct.
+ *
+ * @return nci or INT64_MAX if invalid/unreported.
+ *
+ * @see chreWwanCellIdentityNr
+ *
+ * @since v1.4
+ * @note Requires WWAN permission
+ */
+static inline int64_t chreWwanUnpackNrNci(
+    const struct chreWwanCellIdentityNr *nrCellId) {
+  return (int64_t) (((uint64_t) nrCellId->nci1 << 32) | nrCellId->nci0);
+}
+
+#else  /* defined(CHRE_NANOAPP_USES_WWAN) || !defined(CHRE_IS_NANOAPP_BUILD) */
+#define CHRE_WWAN_PERM_ERROR_STRING \
+    "CHRE_NANOAPP_USES_WWAN must be defined when building this nanoapp in " \
+    "order to refer to "
+#define chreWwanGetCellInfoAsync(...) \
+    CHRE_BUILD_ERROR(CHRE_WWAN_PERM_ERROR_STRING "chreWwanGetCellInfoAsync")
+#define chreWwanUnpackNrNci(...) \
+    CHRE_BUILD_ERROR(CHRE_WWAN_PERM_ERROR_STRING "chreWwanUnpackNrNci")
+#endif  /* defined(CHRE_NANOAPP_USES_WWAN) || !defined(CHRE_IS_NANOAPP_BUILD) */
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* _CHRE_WWAN_H_ */
diff --git a/chre_flags.aconfig b/chre_flags.aconfig
index 3707a8d0..851badc3 100644
--- a/chre_flags.aconfig
+++ b/chre_flags.aconfig
@@ -22,27 +22,6 @@ flag {
   bug: "344642685"
 }
 
-flag {
-  name: "reconnect_host_endpoints_after_hal_restart"
-  namespace: "context_hub"
-  description: "Reconnect host endpoints of ContextHubService after Context Hub HAL restarts."
-  bug: "348253728"
-}
-
-flag {
-  name: "reliable_message_duplicate_detection_service"
-  namespace: "context_hub"
-  description: "Enable duplicate detection for reliable messages in the Context Hub Service"
-  bug: "331795143"
-}
-
-flag {
-  name: "reliable_message_retry_support_service"
-  namespace: "context_hub"
-  description: "Enable retries for reliable messages in the Context Hub Service"
-  bug: "331795143"
-}
-
 flag {
   name: "reliable_message_test_mode_behavior"
   namespace: "context_hub"
@@ -50,33 +29,6 @@ flag {
   bug: "333567339"
 }
 
-flag {
-  name: "bug_fix_hal_reliable_message_record"
-  namespace: "context_hub"
-  description: "A flag guarding the fix of how the Context Hub HAL stores the reliable message records."
-  bug: "333567700"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
-flag {
-  name: "fix_api_check"
-  namespace: "context_hub"
-  description: "Fixes API check errors in Context Hub classes"
-  bug: "340880058"
-}
-
-flag {
-  name: "refactor_hal_xport_agnostic"
-  namespace: "context_hub"
-  description: "Flag guarding refactor of ContextHub HAL to be transport agnostic"
-  bug: "360926711"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
 flag {
   name: "remove_old_context_hub_apis"
   namespace: "context_hub"
@@ -87,16 +39,6 @@ flag {
   }
 }
 
-flag {
-  name: "reduce_locking_context_hub_transaction_manager"
-  namespace: "context_hub"
-  description: "Reduces locking in the ContextHubTransactionManager"
-  bug: "362299144"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
 flag {
   name: "offload_api"
   namespace: "context_hub"
@@ -112,16 +54,6 @@ flag {
   bug: "361573382"
 }
 
-flag {
-  name: "efw_xport_rewind_on_error"
-  namespace: "context_hub"
-  description: "Flag guarding the AOC-dependent behavior to rewind to the last good message"
-  bug: "371057943"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
 flag {
   name: "efw_xport_in_context_hub"
   namespace: "context_hub"
@@ -150,8 +82,11 @@ flag {
 }
 
 flag {
-  name: "bt_socket_hal_supported"
+  name: "gnss_hal_use_endpoint_messaging"
   namespace: "context_hub"
-  description: "Flag guarding whether a working implementation of the BT socket HAL is supported in the ContextHub HAL process or a stub version"
-  bug: "380946927"
+  description: "Flag guarding the use of endpoint messaging for the GNSS HAL"
+  bug: "407810084"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
 }
diff --git a/core/debug_dump_manager.cc b/core/debug_dump_manager.cc
index 49826447..d9011528 100644
--- a/core/debug_dump_manager.cc
+++ b/core/debug_dump_manager.cc
@@ -20,6 +20,7 @@
 
 #include "chre/core/event_loop_manager.h"
 #include "chre/core/settings.h"
+#include "chre/platform/system_time.h"
 
 namespace chre {
 
@@ -71,6 +72,8 @@ void DebugDumpManager::appendNanoappLog(const Nanoapp &nanoapp,
 
 void DebugDumpManager::collectFrameworkDebugDumps() {
   auto *eventLoopManager = EventLoopManagerSingleton::get();
+  mDebugDump.print("CHRE debug dump started @ ts=%" PRIu64 "\n",
+                   SystemTime::getMonotonicTime().toRawNanoseconds());
   eventLoopManager->getMemoryManager().logStateToBuffer(mDebugDump);
   eventLoopManager->getEventLoop().logStateToBuffer(mDebugDump);
 #ifdef CHRE_SENSORS_SUPPORT_ENABLED
diff --git a/core/event_loop.cc b/core/event_loop.cc
index d51ff81c..f08c865d 100644
--- a/core/event_loop.cc
+++ b/core/event_loop.cc
@@ -105,10 +105,6 @@ bool isNonNanoappLowPriorityEvent(Event *event, void * /* data */,
   CHRE_ASSERT_NOT_NULL(event);
   return event->isLowPriority && event->senderInstanceId == kSystemInstanceId;
 }
-
-void deallocateFromMemoryPool(Event *event, void *memoryPool) {
-  static_cast<DynamicMemoryPool *>(memoryPool)->deallocate(event);
-}
 #endif
 
 }  // anonymous namespace
@@ -144,12 +140,12 @@ void EventLoop::invokeMessageFreeFunction(uint64_t appId,
   Nanoapp *nanoapp = lookupAppByAppId(appId);
   if (nanoapp == nullptr) {
     LOGE("Couldn't find app 0x%016" PRIx64 " for message free callback", appId);
-  } else {
-    auto prevCurrentApp = mCurrentApp;
-    mCurrentApp = nanoapp;
-    freeFunction(message, messageSize);
-    mCurrentApp = prevCurrentApp;
+    return;
   }
+  auto prevCurrentApp = mCurrentApp;
+  mCurrentApp = nanoapp;
+  mCurrentApp->invokeMessageFreeCallback(freeFunction, message, messageSize);
+  mCurrentApp = prevCurrentApp;
 }
 
 void EventLoop::run() {
@@ -300,16 +296,21 @@ bool EventLoop::removeNonNanoappLowPriorityEventsFromBack(
     return true;
   }
 
-  size_t numRemovedEvent = mEvents.removeMatchedFromBack(
+  auto freeEventCallback = [](Event *event, void *data) {
+    EventLoop *eventLoop = static_cast<EventLoop *>(data);
+    eventLoop->freeEvent(event);
+  };
+  size_t numRemovedEvents = mEvents.removeMatchedFromBack(
       isNonNanoappLowPriorityEvent, /* data= */ nullptr,
-      /* extraData= */ nullptr, removeNum, deallocateFromMemoryPool,
-      &mEventPool);
-  if (numRemovedEvent == 0 || numRemovedEvent == SIZE_MAX) {
+      /* extraData= */ nullptr, removeNum, freeEventCallback,
+      /* extraDataForFreeFunction= */ this);
+  if (numRemovedEvents == 0 || numRemovedEvents == SIZE_MAX) {
     LOGW("Cannot remove any low priority event");
   } else {
-    mNumDroppedLowPriEvents += numRemovedEvent;
+    mNumDroppedLowPriEvents += numRemovedEvents;
+    LOGW("Dropped %zu low priority events", numRemovedEvents);
   }
-  return numRemovedEvent > 0;
+  return numRemovedEvents > 0;
 #endif
 }
 
@@ -632,13 +633,25 @@ void EventLoop::flushInboundEventQueue() {
 }
 
 void EventLoop::freeEvent(Event *event) {
-  if (event->hasFreeCallback()) {
-    // TODO: find a better way to set the context to the creator of the event
-    mCurrentApp = lookupAppByInstanceId(event->senderInstanceId);
-    event->invokeFreeCallback();
-    mCurrentApp = nullptr;
+  if (event->targetInstanceId == kSystemInstanceId) {
+    event->invokeSystemEventCallback();
+  } else if (event->freeCallback != nullptr) {
+    if (event->senderInstanceId == kSystemInstanceId) {
+      event->invokeEventFreeCallback();
+    } else {
+      mCurrentApp = lookupAppByInstanceId(event->senderInstanceId);
+      if (mCurrentApp != nullptr) {
+        mCurrentApp->invokeEventFreeCallback(
+            event->freeCallback, event->eventType, event->eventData);
+      } else {
+        LOGE("No app found (senderIId=%" PRIu16 ", targetIId=%" PRIu16
+             ", type=0x%" PRIx16 ") for free event callback",
+             event->senderInstanceId, event->targetInstanceId,
+             event->eventType);
+      }
+      mCurrentApp = nullptr;
+    }
   }
-
   mEventPool.deallocate(event);
 }
 
@@ -758,6 +771,7 @@ void EventLoop::unloadNanoappAtIndex(size_t index, bool nanoappStarted) {
 }
 
 void EventLoop::setCycleWakeupBucketsTimer() {
+#ifndef CHRE_IS_SIMULATOR_BUILD
   if (mCycleWakeupBucketsHandle != CHRE_TIMER_INVALID) {
     EventLoopManagerSingleton::get()->cancelDelayedCallback(
         mCycleWakeupBucketsHandle);
@@ -772,6 +786,7 @@ void EventLoop::setCycleWakeupBucketsTimer() {
       EventLoopManagerSingleton::get()->setDelayedCallback(
           SystemCallbackType::CycleNanoappWakeupBucket, nullptr /*data*/,
           callback, kIntervalWakeupBucket);
+#endif  // CHRE_IS_SIMULATOR_BUILD
 }
 
 void EventLoop::handleNanoappWakeupBuckets() {
diff --git a/core/host_message_hub_manager.cc b/core/host_message_hub_manager.cc
index 48fbed7d..e41b6850 100644
--- a/core/host_message_hub_manager.cc
+++ b/core/host_message_hub_manager.cc
@@ -16,6 +16,7 @@
 
 #include "chre/core/host_message_hub_manager.h"
 #include "chre/target_platform/log.h"
+#include "chre_api/chre.h"
 
 #ifdef CHRE_MESSAGE_ROUTER_SUPPORT_ENABLED
 
@@ -186,7 +187,9 @@ void HostMessageHubManager::closeSession(MessageHubId hubId,
 
 void HostMessageHubManager::sendMessage(MessageHubId hubId, SessionId sessionId,
                                         pw::span<const std::byte> data,
-                                        uint32_t type, uint32_t permissions) {
+                                        uint32_t type, uint32_t permissions,
+                                        bool isReliable,
+                                        uint32_t sequenceNumber) {
   LockGuard<Mutex> lock(mHubsLock);
   for (auto &hub : mHubs) {
     if (hub->getMessageHub().getId() != hubId) continue;
@@ -201,8 +204,18 @@ void HostMessageHubManager::sendMessage(MessageHubId hubId, SessionId sessionId,
 
     // Note: We are assuming here that no host hubs will create sessions with
     // themselves as it is not allowed by the HAL API.
-    hub->getMessageHub().sendMessage(std::move(dataCopy), type, permissions,
-                                     sessionId);
+    bool status = hub->getMessageHub().sendMessage(std::move(dataCopy), type,
+                                                   permissions, sessionId);
+    if (!status) {
+      LOGE("Failed to send message on session with ID: 0x%" PRIx16, sessionId);
+    }
+
+    if (isReliable) {
+      // TODO(b/406803626): Add proper support for reliable messages and
+      // duplicate detection.
+      mCb->onMessageDeliveryStatus(hubId, sessionId, sequenceNumber,
+                                   status ? CHRE_ERROR_NONE : CHRE_ERROR);
+    }
     return;
   }
   LOGE("No host hub 0x%" PRIx64 " for send message", hubId);
diff --git a/core/include/chre/core/event.h b/core/include/chre/core/event.h
index 0136a1ba..5b8b8166 100644
--- a/core/include/chre/core/event.h
+++ b/core/include/chre/core/event.h
@@ -93,25 +93,22 @@ class Event : public NonCopyable {
     return (mRefCount == 0);
   }
 
-  //! @return true if this event has an associated callback which needs to be
-  //! called prior to deallocating the event
-  bool hasFreeCallback() {
-    return (targetInstanceId == kSystemInstanceId || freeCallback != nullptr);
+  /**
+   * Invoke the callback sent from and targeting the system.
+   *
+   * targetInstanceId must be kSystemInstanceId in this case.
+   */
+  void invokeSystemEventCallback() const {
+    systemEventCallback(eventType, eventData, extraData);
   }
 
   /**
-   * Invoke the callback associated with this event with the applicable function
-   * signature (passing extraData if this is a system event).
+   * Invoke the free callback for a system-generated event targeting a nanoapp.
    *
-   * The caller MUST confirm that hasFreeCallback() is true before calling this
-   * method.
+   * This function is only to be used for system-generated events.
    */
-  void invokeFreeCallback() {
-    if (targetInstanceId == kSystemInstanceId) {
-      systemEventCallback(eventType, eventData, extraData);
-    } else {
-      freeCallback(eventType, eventData);
-    }
+  void invokeEventFreeCallback() const {
+    freeCallback(eventType, eventData);
   }
 
   //! @return Monotonic time reference for initializing receivedTimeMillis
diff --git a/core/include/chre/core/event_loop.h b/core/include/chre/core/event_loop.h
index 723c44f8..249ddced 100644
--- a/core/include/chre/core/event_loop.h
+++ b/core/include/chre/core/event_loop.h
@@ -194,6 +194,10 @@ class EventLoop : public NonCopyable {
    * @param targetInstanceId The instance ID of the destination of this event
    * @param targetGroupMask Mask used to limit the recipients that are
    *        registered to receive this event
+   *
+   * @return True if the event was delivered to any nanoapps, otherwise false
+   *
+   * @see distributeEventCommon
    */
   bool distributeEventSync(uint16_t eventType, void *eventData,
                            uint16_t targetInstanceId = kBroadcastInstanceId,
@@ -541,7 +545,7 @@ class EventLoop : public NonCopyable {
 
   /**
    * Shared functionality to distributeEvent and distributeEventSync. Should
-   * only be called by those functions. Hnadles event distribution and logging
+   * only be called by those functions. Handles event distribution and logging
    * without any pre- or post-processing.
    *
    * @param event The Event to distribute to Nanoapps
diff --git a/core/include/chre/core/event_loop_manager.h b/core/include/chre/core/event_loop_manager.h
index 2d5e523c..a1740acd 100644
--- a/core/include/chre/core/event_loop_manager.h
+++ b/core/include/chre/core/event_loop_manager.h
@@ -225,8 +225,25 @@ class EventLoopManager : public NonCopyable {
   }
 
 #ifdef CHRE_BLE_SOCKET_SUPPORT_ENABLED
+  /**
+   * Sets the BLE socket manager. This method must be called once and should be
+   * called prior to executing any nanoapps.
+   */
+  void setBleSocketManager(BleSocketManager &bleSocketManager) {
+    CHRE_ASSERT(mBleSocketManager == nullptr);
+    mBleSocketManager = &bleSocketManager;
+  }
+
+  /**
+   * @return A reference to the BLE socket manager. This allows interacting
+   *         with the BLE socket subsystem and manages requests from various
+   *         nanoapps.
+   *
+   * NOTE: Must call setBleSocketManager before using this function.
+   */
   BleSocketManager &getBleSocketManager() {
-    return mBleSocketManager;
+    CHRE_ASSERT(mBleSocketManager != nullptr);
+    return *mBleSocketManager;
   }
 #endif  // CHRE_BLE_SOCKET_SUPPORT_ENABLED
 
@@ -366,7 +383,7 @@ class EventLoopManager : public NonCopyable {
 #ifdef CHRE_BLE_SOCKET_SUPPORT_ENABLED
   //! The BLE socket manager tracks offloaded sockets and handles sending
   //! packets between nanoapps and offloaded sockets.
-  BleSocketManager mBleSocketManager;
+  BleSocketManager *mBleSocketManager = nullptr;
 #endif  // CHRE_BLE_SOCKET_SUPPORT_ENABLED
 
 #endif  // CHRE_BLE_SUPPORT_ENABLED
diff --git a/core/include/chre/core/host_message_hub_manager.h b/core/include/chre/core/host_message_hub_manager.h
index b78208a6..4dce2d29 100644
--- a/core/include/chre/core/host_message_hub_manager.h
+++ b/core/include/chre/core/host_message_hub_manager.h
@@ -119,6 +119,21 @@ class HostMessageHubManager : public NonCopyable {
                                    message::SessionId session,
                                    pw::UniquePtr<std::byte[]> &&data,
                                    uint32_t type, uint32_t permissions) = 0;
+
+    /**
+     * Sends a notification that a message has been delivered to the host.
+     *
+     * Invoked within MessageHubCallback::onMessageDeliveryStatus().
+     *
+     * @param hub The destination hub id
+     * @param session The session id
+     * @param messageSequenceNumber The sequence number of the message
+     * @param errorCode The error code of the delivery status
+     */
+    virtual bool onMessageDeliveryStatus(message::MessageHubId hub,
+                                         message::SessionId session,
+                                         uint32_t messageSequenceNumber,
+                                         uint8_t errorCode) = 0;
     /**
      * Sends a request to open a session with a host endpoint
      *
@@ -249,10 +264,13 @@ class HostMessageHubManager : public NonCopyable {
    * @param data Message data
    * @param type Message type
    * @param permissions Message permissions
+   * @param isReliable Whether the message is reliable
+   * @param sequenceNumber The sequence number of the message
    */
   void sendMessage(message::MessageHubId hubId, message::SessionId sessionId,
                    pw::span<const std::byte> data, uint32_t type,
-                   uint32_t permissions);
+                   uint32_t permissions, bool isReliable = false,
+                   uint32_t sequenceNumber = 0);
 
  private:
   /**
diff --git a/core/include/chre/core/wifi_request_manager.h b/core/include/chre/core/wifi_request_manager.h
index 2709011d..3ce61ae6 100644
--- a/core/include/chre/core/wifi_request_manager.h
+++ b/core/include/chre/core/wifi_request_manager.h
@@ -295,6 +295,8 @@ class WifiRequestManager : public NonCopyable {
  private:
   struct PendingRequestBase {
     uint16_t nanoappInstanceId;  //!< ID of the Nanoapp issuing this request
+    // TODO(b/415309376): Set dispatched=true for all pending request types
+    bool dispatched = false;     //!< true if the request was sent to the PAL
     const void *cookie;          //!< User data supplied by the nanoapp
 
     PendingRequestBase() = default;
@@ -426,9 +428,12 @@ class WifiRequestManager : public NonCopyable {
   ArrayQueue<PendingScanMonitorRequest, kMaxScanMonitorStateTransitions>
       mPendingScanMonitorRequests;
 
-  //! The queue of scan request. Only one asynchronous scan monitor state
-  //! transition can be in flight at one time. Any further requests are queued
-  //! here.
+  //! The queue of scan requests. Only one scan can be in flight at a time,
+  //! and any further requests are queued here. This allows serialization of
+  //! requests to the platform layer to help simplify their implementation.
+  //! Nanoapps are limited to one request at a time to save power and limit
+  //! strain on the queue. For these reasons, we have taken special care to
+  //! allow a nanoapp receiving its final scan event to request a new scan.
   ArrayQueue<PendingScanRequest, kMaxPendingScanRequest> mPendingScanRequests;
 
   //! The list of nanoapps who have enabled scan monitoring. This list is
@@ -445,6 +450,7 @@ class WifiRequestManager : public NonCopyable {
   DynamicVector<NanoappNanSubscriptions> mNanoappSubscriptions;
 
   //! This is set to true if the results of an active scan request are pending.
+  //! While true, prevents additional scan requests from being dispatched.
   bool mScanRequestResultsArePending = false;
 
   //! Accumulates the number of scan event results to determine when the last
@@ -610,24 +616,42 @@ class WifiRequestManager : public NonCopyable {
                                        uint8_t errorCode, const void *cookie);
 
   /**
-   * Calls through to postScanRequestAsyncResultEvent but invokes the
-   * FATAL_ERROR macro if the event is not posted successfully. This is used in
-   * asynchronous contexts where a nanoapp could be stuck waiting for a response
-   * but CHRE failed to enqueue one. For parameter details,
-   * @see postScanRequestAsyncResultEvent
+   * Synchronously distributes an event to a nanoapp indicating the result of a
+   * request for an active wifi scan.
+   *
+   * @param nanoappInstanceId The nanoapp instance ID to direct the event to.
+   * @param success If the request for a wifi resource was successful.
+   * @param errorCode The error code when success is set to false.
+   * @param cookie The cookie to be provided to the nanoapp. This is
+   *        round-tripped from the nanoapp to provide context.
+   *
+   * @return true if the event was successfully delivered.
    */
-  void postScanRequestAsyncResultEventFatal(uint16_t nanoappInstanceId,
+  bool distributeScanRequestAsyncResultSync(uint16_t nanoappInstanceId,
                                             bool success, uint8_t errorCode,
                                             const void *cookie);
 
   /**
-   * Posts a broadcast event containing the results of a wifi scan. Failure to
-   * post this event is a FATAL_ERROR. This is unrecoverable as the nanoapp will
-   * be stuck waiting for wifi scan results but there may be a gap.
+   * Determines if the current WifiScanEvent was requested by a nanoapp that is
+   * not registered to receive broadcast events of CHRE_EVENT_WIFI_SCAN_RESULT.
+   *
+   * For use in conjunction with distributeScanEventSync so that the nanoapp can
+   * be temporarily registered for broadcast delievery of the event.
+   *
+   * @return A pointer to the nanoapp which needs to be temporarily registered,
+   *         if any. Otherwise nullptr.
+   */
+  Nanoapp *getUnregisteredNanoappRequestingScan() const;
+
+  /**
+   * Synchronously distributes a chreWifiScanEvent to the requesting nanoapp as
+   * well as any nanoapps registered for broadcast. This allows for pre- and
+   * post-processing of the event to neatly manage broadcast registrations.
+   * This method must be invoked on the CHRE event loop thread.
    *
    * @param event the wifi scan event.
    */
-  void postScanEventFatal(chreWifiScanEvent *event);
+  void distributeScanEventSync(chreWifiScanEvent *event);
 
   /**
    * Posts an event to a nanoapp indicating the async result of a NAN operation.
@@ -753,12 +777,12 @@ class WifiRequestManager : public NonCopyable {
 
   /**
    * Issues the pending scan requests to the platform in queued order until one
-   * dispatched successfully or the queue is empty.
+   * dispatched successfully or the queue is empty. An async response will
+   * always be provided.
    *
-   * @param postAsyncResult if a dispatch failure should post a async result.
    * @return true if successfully dispatched one request.
    */
-  bool dispatchQueuedScanRequests(bool postAsyncResult);
+  bool dispatchQueuedScanRequests();
 
   /**
    * Issues the next pending ranging request to the platform.
@@ -789,22 +813,12 @@ class WifiRequestManager : public NonCopyable {
                               struct chreWifiRangingEvent *event);
 
   /**
-   * Handles the releasing of a WiFi scan event and unsubscribes a nanoapp who
-   * has made an active request for a wifi scan from WiFi scan events in the
-   * future (if it has not subscribed to passive events).
-   *
-   * @param scanEvent The scan event to release.
-   */
-  void handleFreeWifiScanEvent(chreWifiScanEvent *scanEvent);
-
-  /**
-   * Releases a wifi event (scan, ranging, NAN discovery) after nanoapps have
+   * Releases a wifi event (ranging, NAN discovery) after nanoapps have
    * consumed it.
    *
    * @param eventType the type of event being freed.
    * @param eventData a pointer to the scan event to release.
    */
-  static void freeWifiScanEventCallback(uint16_t eventType, void *eventData);
   static void freeWifiRangingEventCallback(uint16_t eventType, void *eventData);
   static void freeNanDiscoveryEventCallback(uint16_t eventType,
                                             void *eventData);
diff --git a/core/nanoapp.cc b/core/nanoapp.cc
index 427d8c16..0d9be724 100644
--- a/core/nanoapp.cc
+++ b/core/nanoapp.cc
@@ -200,13 +200,13 @@ void Nanoapp::logStateToBuffer(DebugDumpWrapper &debugDump) const {
 void Nanoapp::logMemAndComputeHeader(DebugDumpWrapper &debugDump) const {
   // Print table header
   // Nanoapp column sized to accommodate largest known name
-  debugDump.print("\n%10sNanoapp%9s| Mem Alloc (Bytes) |%2sEvent Time (Ms)\n",
+  debugDump.print("\n%14sNanoapp%12s| Mem Alloc (Bytes) |%2sEvent Time (Ms)\n",
                   "", "", "");
-  debugDump.print("%26s| Current |     Max |     Max |   Total\n", "");
+  debugDump.print("%33s| Current |     Max |     Max |   Total\n", "");
 }
 
 void Nanoapp::logMemAndComputeEntry(DebugDumpWrapper &debugDump) const {
-  debugDump.print("%25s |", getAppName());
+  debugDump.print("%32s |", getAppName());
   debugDump.print(" %7zu |", getTotalAllocatedBytes());
   debugDump.print(" %7zu |", getPeakAllocatedBytes());
   debugDump.print(" %7" PRIu64 " |", mEventProcessTime.getMax());
@@ -260,7 +260,7 @@ void Nanoapp::logMessageHistoryHeader(DebugDumpWrapper &debugDump) const {
                 "Update of nanoapp debug dump column widths requrired");
 
   // Print table header
-  debugDump.print("\n%26s|", " Nanoapp ");
+  debugDump.print("\n%33s|", " Nanoapp ");
   debugDump.print("%11s|", " Total w/u ");
   // Wakeup Histogram = 2 + (4 * kMaxSizeWakeupBuckets);
   debugDump.print("%22s|", " Wakeup Histogram ");
@@ -271,7 +271,7 @@ void Nanoapp::logMessageHistoryHeader(DebugDumpWrapper &debugDump) const {
   // Event Time Histogram (ms) = 2 + (7 * kMaxSizeWakeupBuckets);
   debugDump.print("%37s", " Event Time Histogram (ms) ");
 
-  debugDump.print("\n%26s|%11s|", "", "");
+  debugDump.print("\n%33s|%11s|", "", "");
   for (int32_t i = kMaxSizeWakeupBuckets - 1; i >= 0; --i) {
     debugDump.print(" %3s", bucketTags[i]);
   }
@@ -287,7 +287,7 @@ void Nanoapp::logMessageHistoryHeader(DebugDumpWrapper &debugDump) const {
 }
 
 void Nanoapp::logMessageHistoryEntry(DebugDumpWrapper &debugDump) const {
-  debugDump.print("%25s |", getAppName());
+  debugDump.print("%32s |", getAppName());
 
   // Print wakeupCount and histogram
   debugDump.print(" %9" PRIu32 " | ", mNumWakeupsSinceBoot);
diff --git a/core/sensor_request_manager.cc b/core/sensor_request_manager.cc
index 566e1a8a..5a3df2d5 100644
--- a/core/sensor_request_manager.cc
+++ b/core/sensor_request_manager.cc
@@ -514,14 +514,13 @@ void SensorRequestManager::handleSamplingStatusUpdate(
       EventLoopManagerSingleton::get()->getSensorRequestManager().getSensor(
           sensorHandle);
   if (sensor == nullptr || sensor->isOneShot()) {
+    // We don't log a warning for one-shot sensors because they are expected to
+    // receive a sampling status update when they are enabled.
     if (sensor == nullptr) {
       LOGW(
           "Received a sampling status update for non existing sensorHandle "
           "%" PRIu32,
           sensorHandle);
-    } else {
-      LOGW("Received a sampling status update for one shot sensor %s",
-           sensor->getSensorName());
     }
     releaseSamplingStatusUpdate(status);
   } else {
diff --git a/core/wifi_request_manager.cc b/core/wifi_request_manager.cc
index e1277f5e..24924be1 100644
--- a/core/wifi_request_manager.cc
+++ b/core/wifi_request_manager.cc
@@ -183,7 +183,7 @@ void WifiRequestManager::dispatchQueuedConfigureScanMonitorRequests() {
 
 void WifiRequestManager::handleConfigureScanMonitorTimeout() {
   if (mPendingScanMonitorRequests.empty()) {
-    LOGE("Configure Scan Monitor timer timedout with no pending request.");
+    LOGE("Configure Scan Monitor timer timed out with no pending request.");
   } else {
     EventLoopManagerSingleton::get()->getSystemHealthMonitor().onFailure(
         HealthCheckId::WifiConfigureScanMonitorTimeout);
@@ -322,7 +322,7 @@ bool WifiRequestManager::sendRangingRequest(PendingRangingRequest &request) {
 
 void WifiRequestManager::handleRangingRequestTimeout() {
   if (mPendingRangingRequests.empty()) {
-    LOGE("Request ranging timer timedout with no pending request.");
+    LOGE("Request ranging timer timed out with no pending request.");
   } else {
     EventLoopManagerSingleton::get()->getSystemHealthMonitor().onFailure(
         HealthCheckId::WifiRequestRangingTimeout);
@@ -386,7 +386,7 @@ bool WifiRequestManager::requestRanging(RangingType rangingType,
 void WifiRequestManager::handleScanRequestTimeout() {
   mScanRequestTimeoutHandle = CHRE_TIMER_INVALID;
   if (mPendingScanRequests.empty()) {
-    LOGE("Scan Request timer timedout with no pending request.");
+    LOGE("Scan Request timer timed out with no pending request.");
   } else {
     EventLoopManagerSingleton::get()->getSystemHealthMonitor().onFailure(
         HealthCheckId::WifiScanResponseTimeout);
@@ -394,7 +394,7 @@ void WifiRequestManager::handleScanRequestTimeout() {
     // scan request.
     resetScanEventResultCountAccumulator();
     mPendingScanRequests.pop();
-    dispatchQueuedScanRequests(true /* postAsyncResult */);
+    dispatchQueuedScanRequests();
   }
 }
 
@@ -459,11 +459,12 @@ bool WifiRequestManager::requestScan(Nanoapp *nanoapp,
     success = true;
     handleScanResponse(false /* pending */, CHRE_ERROR_FUNCTION_DISABLED);
   } else {
-    if (mPendingScanRequests.size() == 1) {
-      success = dispatchQueuedScanRequests(false /* postAsyncResult */);
-    } else {
-      success = true;
+    // If this is the only request, and we can serve it now, attempt to do so
+    if (mPendingScanRequests.size() == 1 && !mScanRequestResultsArePending) {
+      dispatchQueuedScanRequests();
     }
+
+    success = true;
   }
 
   return success;
@@ -536,7 +537,7 @@ void WifiRequestManager::handleScanEvent(struct chreWifiScanEvent *event) {
     auto *scanEvent = static_cast<struct chreWifiScanEvent *>(data);
     EventLoopManagerSingleton::get()
         ->getWifiRequestManager()
-        .postScanEventFatal(scanEvent);
+        .distributeScanEventSync(scanEvent);
   };
 
   EventLoopManagerSingleton::get()->deferCallback(
@@ -965,34 +966,36 @@ bool WifiRequestManager::postScanMonitorAsyncResultEvent(
     const void *cookie) {
   // Allocate and post an event to the nanoapp requesting wifi.
   bool eventPosted = false;
+  // Reserve the memory for the AsyncResult first so that if we run out of
+  // memory during updateNanoappScanMonitoringList we can still post the event.
+  chreAsyncResult *event = memoryAlloc<chreAsyncResult>();
   // If we failed to enable, don't add the nanoapp to the list, but always
   // remove it if it was trying to disable. This keeps us from getting stuck in
   // a state where we think the scan monitor is enabled (because the list is
   // non-empty) when we actually aren't sure (e.g. the scan monitor disablement
   // may have been handled but delivering the result ran into an error).
-  if ((!success && enable) ||
-      updateNanoappScanMonitoringList(enable, nanoappInstanceId)) {
-    chreAsyncResult *event = memoryAlloc<chreAsyncResult>();
-    if (event == nullptr) {
-      LOG_OOM();
-    } else {
-      event->requestType = CHRE_WIFI_REQUEST_TYPE_CONFIGURE_SCAN_MONITOR;
-      event->success = success;
-      event->errorCode = errorCode;
-      event->reserved = 0;
-      event->cookie = cookie;
-
-      if (errorCode < CHRE_ERROR_SIZE) {
-        mScanMonitorErrorHistogram[errorCode]++;
-      } else {
-        LOGE("Undefined error in ScanMonitorAsyncResult: %" PRIu8, errorCode);
-      }
+  if (event == nullptr) {
+    LOG_OOM();
+  } else if ((!success && enable) ||
+             updateNanoappScanMonitoringList(enable, nanoappInstanceId)) {
+    event->requestType = CHRE_WIFI_REQUEST_TYPE_CONFIGURE_SCAN_MONITOR;
+    event->success = success;
+    event->errorCode = errorCode;
+    event->reserved = 0;
+    event->cookie = cookie;
 
-      EventLoopManagerSingleton::get()->getEventLoop().postEventOrDie(
-          CHRE_EVENT_WIFI_ASYNC_RESULT, event, freeEventDataCallback,
-          nanoappInstanceId);
-      eventPosted = true;
+    if (errorCode < CHRE_ERROR_SIZE) {
+      mScanMonitorErrorHistogram[errorCode]++;
+    } else {
+      LOGE("Undefined error in ScanMonitorAsyncResult: %" PRIu8, errorCode);
     }
+
+    EventLoopManagerSingleton::get()->getEventLoop().postEventOrDie(
+        CHRE_EVENT_WIFI_ASYNC_RESULT, event, freeEventDataCallback,
+        nanoappInstanceId);
+    eventPosted = true;
+  } else {
+    memoryFree(event);
   }
 
   return eventPosted;
@@ -1007,6 +1010,20 @@ void WifiRequestManager::postScanMonitorAsyncResultEventFatal(
   }
 }
 
+Nanoapp *WifiRequestManager::getUnregisteredNanoappRequestingScan() const {
+  if (mScanRequestResultsArePending) {
+    uint16_t requesterId = mPendingScanRequests.front().nanoappInstanceId;
+    if (!nanoappHasScanMonitorRequest(requesterId)) {
+      Nanoapp *nanoapp = EventLoopManagerSingleton::get()
+                             ->getEventLoop()
+                             .findNanoappByInstanceId(requesterId);
+      return nanoapp;
+    }
+  }
+
+  return nullptr;
+}
+
 bool WifiRequestManager::postScanRequestAsyncResultEvent(
     uint16_t nanoappInstanceId, bool success, uint8_t errorCode,
     const void *cookie) {
@@ -1039,18 +1056,72 @@ bool WifiRequestManager::postScanRequestAsyncResultEvent(
   return eventPosted;
 }
 
-void WifiRequestManager::postScanRequestAsyncResultEventFatal(
+bool WifiRequestManager::distributeScanRequestAsyncResultSync(
     uint16_t nanoappInstanceId, bool success, uint8_t errorCode,
     const void *cookie) {
-  if (!postScanRequestAsyncResultEvent(nanoappInstanceId, success, errorCode,
-                                       cookie)) {
-    FATAL_ERROR("Failed to send WiFi scan request async result event");
+  bool eventPosted = false;
+  chreAsyncResult event;
+
+  event.requestType = CHRE_WIFI_REQUEST_TYPE_REQUEST_SCAN;
+  event.success = success;
+  event.errorCode = errorCode;
+  event.reserved = 0;
+  event.cookie = cookie;
+
+  if (errorCode < CHRE_ERROR_SIZE) {
+    mActiveScanErrorHistogram[errorCode]++;
+  } else {
+    LOGE("Undefined error in ScanRequestAsyncResult: %" PRIu8, errorCode);
   }
+
+  eventPosted =
+      EventLoopManagerSingleton::get()->getEventLoop().distributeEventSync(
+          CHRE_EVENT_WIFI_ASYNC_RESULT, &event, nanoappInstanceId);
+
+  return eventPosted;
 }
 
-void WifiRequestManager::postScanEventFatal(chreWifiScanEvent *event) {
-  EventLoopManagerSingleton::get()->getEventLoop().postEventOrDie(
-      CHRE_EVENT_WIFI_SCAN_RESULT, event, freeWifiScanEventCallback);
+void WifiRequestManager::distributeScanEventSync(chreWifiScanEvent *event) {
+  // Register requesting nanoapp for broadcast if it isn't already
+  Nanoapp *tempRegisterNanoapp = getUnregisteredNanoappRequestingScan();
+  if (tempRegisterNanoapp != nullptr) {
+    tempRegisterNanoapp->registerForBroadcastEvent(CHRE_EVENT_WIFI_SCAN_RESULT);
+  }
+
+  bool resultsComplete = false;
+  if (mScanRequestResultsArePending) {
+    mScanEventResultCountAccumulator += event->resultCount;
+    if (mScanEventResultCountAccumulator >= event->resultTotal) {
+      // Nanoapps may only have one pending scan request at a time, tracked by
+      // mPendingScanRequests. Pop this scan request now to allow the nanoapp to
+      // request a new scan when it receives the last wifi scan result event.
+      mScanEventResultCountAccumulator = 0;
+      cancelScanRequestTimer();
+      if (!mPendingScanRequests.empty()) {
+        mPendingScanRequests.pop();
+      }
+      resultsComplete = true;
+    }
+  }
+
+  EventLoopManagerSingleton::get()->getEventLoop().distributeEventSync(
+      CHRE_EVENT_WIFI_SCAN_RESULT, event, kBroadcastInstanceId);
+  if (tempRegisterNanoapp != nullptr) {
+    tempRegisterNanoapp->unregisterForBroadcastEvent(
+        CHRE_EVENT_WIFI_SCAN_RESULT);
+  }
+
+  // Clear after event distribution to block new requests from being dispatched
+  // before this request is completed.
+  if (resultsComplete) {
+    mScanRequestResultsArePending = false;
+  }
+
+  addDebugLog(DebugLogEntry::forScanEvent(*event));
+  mPlatformWifi.releaseScanEvent(event);
+  if (!mScanRequestResultsArePending) {
+    dispatchQueuedScanRequests();
+  }
 }
 
 void WifiRequestManager::handleScanMonitorStateChangeSync(bool enabled,
@@ -1125,30 +1196,24 @@ void WifiRequestManager::handleScanResponseSync(bool pending,
            errorCode);
     }
     PendingScanRequest &currentScanRequest = mPendingScanRequests.front();
-    postScanRequestAsyncResultEventFatal(currentScanRequest.nanoappInstanceId,
-                                         success, errorCode,
-                                         currentScanRequest.cookie);
 
     // Set a flag to indicate that results may be pending.
     mScanRequestResultsArePending = pending;
 
-    if (pending) {
-      Nanoapp *nanoapp =
-          EventLoopManagerSingleton::get()
-              ->getEventLoop()
-              .findNanoappByInstanceId(currentScanRequest.nanoappInstanceId);
-      if (nanoapp == nullptr) {
-        LOGW("Received WiFi scan response for unknown nanoapp");
-      } else {
-        nanoapp->registerForBroadcastEvent(CHRE_EVENT_WIFI_SCAN_RESULT);
-      }
-    } else {
+    // The scan events are delivered synchronously, so the async result must
+    // also be delivered synchronously. If not, the async result may be
+    // delivered after the event results.
+    distributeScanRequestAsyncResultSync(currentScanRequest.nanoappInstanceId,
+                                         success, errorCode,
+                                         currentScanRequest.cookie);
+
+    if (!pending) {
       // If the scan results are not pending, pop the first event since it's no
       // longer waiting for anything. Otherwise, wait for the results to be
       // delivered and then pop the first request.
       cancelScanRequestTimer();
       mPendingScanRequests.pop();
-      dispatchQueuedScanRequests(true /* postAsyncResult */);
+      dispatchQueuedScanRequests();
     }
   }
 }
@@ -1235,10 +1300,11 @@ void WifiRequestManager::dispatchQueuedNanSubscribeRequestWithRetry() {
     ;
 }
 
-bool WifiRequestManager::dispatchQueuedScanRequests(bool postAsyncResult) {
-  while (!mPendingScanRequests.empty()) {
+bool WifiRequestManager::dispatchQueuedScanRequests() {
+  while (!mPendingScanRequests.empty() &&
+         !mPendingScanRequests.front().dispatched) {
     uint8_t asyncError = CHRE_ERROR_NONE;
-    const PendingScanRequest &currentScanRequest = mPendingScanRequests.front();
+    PendingScanRequest &currentScanRequest = mPendingScanRequests.front();
 
     if (!EventLoopManagerSingleton::get()
              ->getSettingManager()
@@ -1253,18 +1319,15 @@ bool WifiRequestManager::dispatchQueuedScanRequests(bool postAsyncResult) {
       if (!syncResult) {
         asyncError = CHRE_ERROR;
       } else {
+        currentScanRequest.dispatched = true;
         mScanRequestTimeoutHandle = setScanRequestTimer();
         return true;
       }
     }
 
-    if (postAsyncResult) {
-      postScanRequestAsyncResultEvent(currentScanRequest.nanoappInstanceId,
-                                      false /*success*/, asyncError,
-                                      currentScanRequest.cookie);
-    } else {
-      LOGE("Wifi scan request failed");
-    }
+    postScanRequestAsyncResultEvent(currentScanRequest.nanoappInstanceId,
+                                    false /*success*/, asyncError,
+                                    currentScanRequest.cookie);
     mPendingScanRequests.pop();
   }
   return false;
@@ -1296,44 +1359,6 @@ void WifiRequestManager::handleRangingEventSync(
     ;
 }
 
-void WifiRequestManager::handleFreeWifiScanEvent(chreWifiScanEvent *scanEvent) {
-  addDebugLog(DebugLogEntry::forScanEvent(*scanEvent));
-  if (mScanRequestResultsArePending) {
-    // Reset the event distribution logic once an entire scan event has been
-    // received and processed by the nanoapp requesting the scan event.
-    mScanEventResultCountAccumulator += scanEvent->resultCount;
-    if (mScanEventResultCountAccumulator >= scanEvent->resultTotal) {
-      resetScanEventResultCountAccumulator();
-      cancelScanRequestTimer();
-    }
-
-    if (!mScanRequestResultsArePending && !mPendingScanRequests.empty()) {
-      uint16_t pendingNanoappInstanceId =
-          mPendingScanRequests.front().nanoappInstanceId;
-      Nanoapp *nanoapp = EventLoopManagerSingleton::get()
-                             ->getEventLoop()
-                             .findNanoappByInstanceId(pendingNanoappInstanceId);
-      if (nanoapp == nullptr) {
-        LOGW("Attempted to unsubscribe unknown nanoapp from WiFi scan events");
-      } else if (!nanoappHasScanMonitorRequest(pendingNanoappInstanceId)) {
-        nanoapp->unregisterForBroadcastEvent(CHRE_EVENT_WIFI_SCAN_RESULT);
-      }
-      mPendingScanRequests.pop();
-      dispatchQueuedScanRequests(true /* postAsyncResult */);
-    }
-  }
-
-  mPlatformWifi.releaseScanEvent(scanEvent);
-}
-
-void WifiRequestManager::freeWifiScanEventCallback(uint16_t /* eventType */,
-                                                   void *eventData) {
-  auto *scanEvent = static_cast<struct chreWifiScanEvent *>(eventData);
-  EventLoopManagerSingleton::get()
-      ->getWifiRequestManager()
-      .handleFreeWifiScanEvent(scanEvent);
-}
-
 void WifiRequestManager::freeWifiRangingEventCallback(uint16_t /* eventType */,
                                                       void *eventData) {
   auto *event = static_cast<struct chreWifiRangingEvent *>(eventData);
diff --git a/host/common/chre_aidl_hal_client.cc b/host/common/chre_aidl_hal_client.cc
deleted file mode 100644
index 2b3b93b9..00000000
--- a/host/common/chre_aidl_hal_client.cc
+++ /dev/null
@@ -1,881 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
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
-#include <aidl/android/hardware/contexthub/BnContextHubCallback.h>
-#include <aidl/android/hardware/contexthub/IContextHub.h>
-#include <aidl/android/hardware/contexthub/NanoappBinary.h>
-#include <android/binder_manager.h>
-#include <android/binder_process.h>
-#include <dirent.h>
-#include <utils/String16.h>
-
-#include <cctype>
-#include <filesystem>
-#include <fstream>
-#include <future>
-#include <map>
-#include <regex>
-#include <stdexcept>
-#include <string>
-#include <unordered_set>
-#include <vector>
-
-#include "chre_api/chre/version.h"
-#include "chre_host/file_stream.h"
-#include "chre_host/hal_client.h"
-#include "chre_host/log.h"
-#include "chre_host/napp_header.h"
-
-using ::aidl::android::hardware::contexthub::AsyncEventType;
-using ::aidl::android::hardware::contexthub::BnContextHubCallback;
-using ::aidl::android::hardware::contexthub::ContextHubInfo;
-using ::aidl::android::hardware::contexthub::ContextHubMessage;
-using ::aidl::android::hardware::contexthub::HostEndpointInfo;
-using ::aidl::android::hardware::contexthub::IContextHub;
-using ::aidl::android::hardware::contexthub::MessageDeliveryStatus;
-using ::aidl::android::hardware::contexthub::NanoappBinary;
-using ::aidl::android::hardware::contexthub::NanoappInfo;
-using ::aidl::android::hardware::contexthub::NanSessionRequest;
-using ::aidl::android::hardware::contexthub::Setting;
-using ::android::chre::HalClient;
-using ::android::chre::NanoAppBinaryHeader;
-using ::android::chre::readFileContents;
-using ::android::internal::ToString;
-using ::ndk::ScopedAStatus;
-
-namespace {
-// A default id 0 is used for every command requiring a context hub id. When
-// this is not the case the id number should be one of the arguments of the
-// commands.
-constexpr uint32_t kContextHubId = 0;
-constexpr int32_t kLoadTransactionId = 1;
-constexpr int32_t kUnloadTransactionId = 2;
-
-// Though IContextHub.aidl says loading operation is capped at 30s to finish,
-// multiclient HAL can terminate a load/unload transaction after 5s to avoid
-// blocking other load/unload transactions.
-constexpr auto kTimeOutThresholdInSec = std::chrono::seconds(5);
-
-// 34a3a27e-9b83-4098-b564-e83b0c28d4bb
-constexpr std::array<uint8_t, 16> kUuid = {0x34, 0xa3, 0xa2, 0x7e, 0x9b, 0x83,
-                                           0x40, 0x98, 0xb5, 0x64, 0xe8, 0x3b,
-                                           0x0c, 0x28, 0xd4, 0xbb};
-
-// Locations should be searched in the sequence defined below:
-const char *kPredefinedNanoappPaths[] = {
-    "/vendor/etc/chre/",
-    "/vendor/dsp/adsp/",
-    "/vendor/dsp/sdsp/",
-    "/vendor/lib/rfsa/adsp/",
-};
-
-const std::string kClientName{"ChreAidlHalClient"};
-
-inline void throwError(const std::string &message) {
-  throw std::system_error{std::error_code(), message};
-}
-
-bool isValidHexNumber(const std::string &number) {
-  if (number.empty() ||
-      (number.substr(0, 2) != "0x" && number.substr(0, 2) != "0X")) {
-    return false;
-  }
-  for (int i = 2; i < number.size(); i++) {
-    if (!isxdigit(number[i])) {
-      throwError("Hex app id " + number + " contains invalid character.");
-    }
-  }
-  return number.size() > 2;
-}
-
-uint16_t verifyAndConvertEndpointHexId(const std::string &number) {
-  // host endpoint id must be a 16-bits long hex number.
-  if (isValidHexNumber(number)) {
-    int convertedNumber = std::stoi(number, /* idx= */ nullptr, /* base= */ 16);
-    if (convertedNumber < std::numeric_limits<uint16_t>::max()) {
-      return static_cast<uint16_t>(convertedNumber);
-    }
-  }
-  throwError("host endpoint id must be a 16-bits long hex number.");
-  return 0;  // code never reached.
-}
-
-bool isValidNanoappHexId(const std::string &number) {
-  if (!isValidHexNumber(number)) {
-    return false;
-  }
-  // Once the input has the hex prefix, an exception will be thrown if it is
-  // malformed because it shouldn't be treated as an app name anymore.
-  if (number.size() > 18) {
-    throwError("Hex app id must has a length of [3, 18] including the prefix.");
-  }
-  return true;
-}
-
-std::string parseAppVersion(uint32_t version) {
-  std::ostringstream stringStream;
-  stringStream << std::hex << "0x" << version << std::dec << " (v"
-               << CHRE_EXTRACT_MAJOR_VERSION(version) << "."
-               << CHRE_EXTRACT_MINOR_VERSION(version) << "."
-               << CHRE_EXTRACT_PATCH_VERSION(version) << ")";
-  return stringStream.str();
-}
-
-std::string parseTransactionId(int32_t transactionId) {
-  switch (transactionId) {
-    case kLoadTransactionId:
-      return "Loading";
-    case kUnloadTransactionId:
-      return "Unloading";
-    default:
-      return "Unknown";
-  }
-}
-
-class ContextHubCallback : public BnContextHubCallback {
- public:
-  ScopedAStatus handleNanoappInfo(
-      const std::vector<NanoappInfo> &appInfo) override {
-    std::cout << appInfo.size() << " nanoapps loaded" << std::endl;
-    for (const NanoappInfo &app : appInfo) {
-      std::cout << "appId: 0x" << std::hex << app.nanoappId << std::dec << " {"
-                << "\n\tappVersion: " << parseAppVersion(app.nanoappVersion)
-                << "\n\tenabled: " << (app.enabled ? "true" : "false")
-                << "\n\tpermissions: " << ToString(app.permissions)
-                << "\n\trpcServices: " << ToString(app.rpcServices) << "\n}"
-                << std::endl;
-    }
-    resetPromise();
-    return ScopedAStatus::ok();
-  }
-
-  ScopedAStatus handleContextHubMessage(
-      const ContextHubMessage &message,
-      const std::vector<std::string> & /*msgContentPerms*/) override {
-    std::cout << "Received a message!" << std::endl
-              << "   From: 0x" << std::hex << message.nanoappId << std::endl
-              << "     To: 0x" << static_cast<int>(message.hostEndPoint)
-              << std::endl
-              << "   Body: (type " << message.messageType << " size "
-              << message.messageBody.size() << ") 0x";
-    for (const uint8_t &data : message.messageBody) {
-      std::cout << std::hex << static_cast<uint16_t>(data);
-    }
-    std::cout << std::endl << std::endl;
-    resetPromise();
-    return ScopedAStatus::ok();
-  }
-
-  ScopedAStatus handleContextHubAsyncEvent(AsyncEventType event) override {
-    std::cout << "Received async event " << toString(event) << std::endl;
-    resetPromise();
-    return ScopedAStatus::ok();
-  }
-
-  // Called after loading/unloading a nanoapp.
-  ScopedAStatus handleTransactionResult(int32_t transactionId,
-                                        bool success) override {
-    std::cout << parseTransactionId(transactionId) << " transaction is "
-              << (success ? "successful" : "failed") << std::endl;
-    resetPromise();
-    return ScopedAStatus::ok();
-  }
-
-  ScopedAStatus handleNanSessionRequest(
-      const NanSessionRequest & /* request */) override {
-    resetPromise();
-    return ScopedAStatus::ok();
-  }
-
-  ScopedAStatus handleMessageDeliveryStatus(
-      char16_t /* hostEndPointId */,
-      const MessageDeliveryStatus & /* messageDeliveryStatus */) override {
-    resetPromise();
-    return ScopedAStatus::ok();
-  }
-
-  ScopedAStatus getUuid(std::array<uint8_t, 16> *out_uuid) override {
-    *out_uuid = kUuid;
-    return ScopedAStatus::ok();
-  }
-
-  ScopedAStatus getName(std::string *out_name) override {
-    *out_name = kClientName;
-    return ScopedAStatus::ok();
-  }
-
-  void resetPromise() {
-    promise.set_value();
-    promise = std::promise<void>{};
-  }
-
-  // TODO(b/247124878):
-  // This promise is shared among all the HAL callbacks to simplify the
-  // implementation. This is based on the assumption that every command should
-  // get a response before timeout and the first callback triggered is for the
-  // response.
-  //
-  // In very rare cases, however, the assumption doesn't hold:
-  //  - multiple callbacks are triggered by a command and come back out of order
-  //  - one command is timed out and the user typed in another command then the
-  //  first callback for the first command is triggered
-  // Once we have a chance we should consider refactor this design to let each
-  // callback use their specific promises.
-  std::promise<void> promise;
-};
-
-std::shared_ptr<IContextHub> gContextHub = nullptr;
-std::shared_ptr<ContextHubCallback> gCallback = nullptr;
-
-void registerHostCallback() {
-  if (gCallback != nullptr) {
-    gCallback.reset();
-  }
-  gCallback = ContextHubCallback::make<ContextHubCallback>();
-  if (!gContextHub->registerCallback(kContextHubId, gCallback).isOk()) {
-    throwError("Failed to register the callback");
-  }
-}
-
-/** Initializes gContextHub and register gCallback. */
-std::shared_ptr<IContextHub> getContextHub() {
-  if (gContextHub == nullptr) {
-    auto aidlServiceName = std::string() + IContextHub::descriptor + "/default";
-    ndk::SpAIBinder binder(
-        AServiceManager_waitForService(aidlServiceName.c_str()));
-    if (binder.get() == nullptr) {
-      throwError("Could not find Context Hub HAL");
-    }
-    gContextHub = IContextHub::fromBinder(binder);
-  }
-  if (gCallback == nullptr) {
-    registerHostCallback();
-  }
-  return gContextHub;
-}
-
-void printNanoappHeader(const NanoAppBinaryHeader &header) {
-  std::cout << " {"
-            << "\n\tappId: 0x" << std::hex << header.appId << std::dec
-            << "\n\tappVersion: " << parseAppVersion(header.appVersion)
-            << "\n\tflags: " << header.flags << "\n\ttarget CHRE API version: "
-            << static_cast<int>(header.targetChreApiMajorVersion) << "."
-            << static_cast<int>(header.targetChreApiMinorVersion) << "\n}"
-            << std::endl;
-}
-
-std::unique_ptr<NanoAppBinaryHeader> findHeaderByName(
-    const std::string &appName, const std::string &binaryPath) {
-  DIR *dir = opendir(binaryPath.c_str());
-  if (dir == nullptr) {
-    return nullptr;
-  }
-  std::regex regex(appName + ".napp_header");
-  std::cmatch match;
-
-  std::unique_ptr<NanoAppBinaryHeader> result = nullptr;
-  for (struct dirent *entry; (entry = readdir(dir)) != nullptr;) {
-    if (!std::regex_match(entry->d_name, match, regex)) {
-      continue;
-    }
-    std::ifstream input(std::string(binaryPath) + "/" + entry->d_name,
-                        std::ios::binary);
-    result = std::make_unique<NanoAppBinaryHeader>();
-    input.read(reinterpret_cast<char *>(result.get()),
-               sizeof(NanoAppBinaryHeader));
-    break;
-  }
-  closedir(dir);
-  return result;
-}
-
-void readNanoappHeaders(std::map<std::string, NanoAppBinaryHeader> &nanoapps,
-                        const std::string &binaryPath) {
-  DIR *dir = opendir(binaryPath.c_str());
-  if (dir == nullptr) {
-    return;
-  }
-  std::regex regex("(\\w+)\\.napp_header");
-  std::cmatch match;
-  for (struct dirent *entry; (entry = readdir(dir)) != nullptr;) {
-    if (!std::regex_match(entry->d_name, match, regex)) {
-      continue;
-    }
-    std::ifstream input(std::string(binaryPath) + "/" + entry->d_name,
-                        std::ios::binary);
-    input.read(reinterpret_cast<char *>(&nanoapps[match[1]]),
-               sizeof(NanoAppBinaryHeader));
-  }
-  closedir(dir);
-}
-
-void verifyStatus(const std::string &operation, const ScopedAStatus &status) {
-  if (!status.isOk()) {
-    gCallback->resetPromise();
-    throwError(operation + " fails with abnormal status " +
-               ToString(status.getMessage()) + " error code " +
-               ToString(status.getServiceSpecificError()));
-  }
-}
-
-void verifyStatusAndSignal(const std::string &operation,
-                           const ScopedAStatus &status,
-                           const std::future<void> &future_signal) {
-  verifyStatus(operation, status);
-  std::future_status future_status =
-      future_signal.wait_for(kTimeOutThresholdInSec);
-  if (future_status != std::future_status::ready) {
-    gCallback->resetPromise();
-    throwError(operation + " doesn't finish within " +
-               ToString(kTimeOutThresholdInSec.count()) + " seconds");
-  }
-}
-
-/** Finds the .napp_header file associated to the nanoapp.
- *
- * This function guarantees to return a non-null {@link NanoAppBinaryHeader}
- * pointer. In case a .napp_header file cannot be found an exception will be
- * raised.
- *
- * @param pathAndName name of the nanoapp that might be prefixed with it path.
- * It will be normalized to the format of <absolute-path><name>.so at the end.
- * For example, "abc" will be changed to "/path/to/abc.so".
- * @return a unique pointer to the {@link NanoAppBinaryHeader} found
- */
-std::unique_ptr<NanoAppBinaryHeader> findHeaderAndNormalizePath(
-    std::string &pathAndName) {
-  // To match the file pattern of [path]<name>[.so]
-  std::regex pathNameRegex("(.*?)(\\w+)(\\.so)?");
-  std::smatch smatch;
-  if (!std::regex_match(pathAndName, smatch, pathNameRegex)) {
-    throwError("Invalid nanoapp: " + pathAndName);
-  }
-  std::string fullPath = smatch[1];
-  std::string appName = smatch[2];
-  // absolute path is provided:
-  if (!fullPath.empty() && fullPath[0] == '/') {
-    auto result = findHeaderByName(appName, fullPath);
-    if (result == nullptr) {
-      throwError("Unable to find the nanoapp header for " + pathAndName);
-    }
-    pathAndName = fullPath + appName + ".so";
-    return result;
-  }
-  // relative path is searched form predefined locations:
-  for (const std::string &predefinedPath : kPredefinedNanoappPaths) {
-    auto result = findHeaderByName(appName, predefinedPath);
-    if (result == nullptr) {
-      continue;
-    }
-    pathAndName = predefinedPath + appName + ".so";
-    return result;
-  }
-  throwError("Unable to find the nanoapp header for " + pathAndName);
-  return nullptr;
-}
-
-int64_t getNanoappIdFrom(std::string &appIdOrName) {
-  int64_t appId;
-  if (isValidNanoappHexId(appIdOrName)) {
-    appId = std::stoll(appIdOrName, nullptr, 16);
-  } else {
-    // Treat the appIdOrName as the app name and try again
-    appId =
-        static_cast<int64_t>(findHeaderAndNormalizePath(appIdOrName)->appId);
-  }
-  return appId;
-}
-
-void getAllContextHubs() {
-  std::vector<ContextHubInfo> hubs{};
-  getContextHub()->getContextHubs(&hubs);
-  if (hubs.empty()) {
-    std::cerr << "Failed to get any context hub." << std::endl;
-    return;
-  }
-  for (const auto &hub : hubs) {
-    std::cout << "Context Hub " << hub.id << ": " << std::endl
-              << "  Name: " << hub.name << std::endl
-              << "  Vendor: " << hub.vendor << std::endl
-              << "  Max support message length (bytes): "
-              << hub.maxSupportedMessageLengthBytes << std::endl
-              << "  Version: " << static_cast<uint32_t>(hub.chreApiMajorVersion)
-              << "." << static_cast<uint32_t>(hub.chreApiMinorVersion)
-              << std::endl
-              << "  Chre platform id: 0x" << std::hex << hub.chrePlatformId
-              << std::endl;
-  }
-}
-
-void loadNanoapp(std::string &pathAndName) {
-  auto header = findHeaderAndNormalizePath(pathAndName);
-  std::vector<uint8_t> soBuffer{};
-  if (!readFileContents(pathAndName.c_str(), soBuffer)) {
-    throwError("Failed to open the content of " + pathAndName);
-  }
-  NanoappBinary binary;
-  binary.nanoappId = static_cast<int64_t>(header->appId);
-  binary.customBinary = soBuffer;
-  binary.flags = static_cast<int32_t>(header->flags);
-  binary.targetChreApiMajorVersion =
-      static_cast<int8_t>(header->targetChreApiMajorVersion);
-  binary.targetChreApiMinorVersion =
-      static_cast<int8_t>(header->targetChreApiMinorVersion);
-  binary.nanoappVersion = static_cast<int32_t>(header->appVersion);
-
-  auto status =
-      getContextHub()->loadNanoapp(kContextHubId, binary, kLoadTransactionId);
-  verifyStatusAndSignal(/* operation= */ "loading nanoapp " + pathAndName,
-                        status, gCallback->promise.get_future());
-}
-
-void unloadNanoapp(std::string &appIdOrName) {
-  auto appId = getNanoappIdFrom(appIdOrName);
-  auto status = getContextHub()->unloadNanoapp(kContextHubId, appId,
-                                               kUnloadTransactionId);
-  verifyStatusAndSignal(/* operation= */ "unloading nanoapp " + appIdOrName,
-                        status, gCallback->promise.get_future());
-}
-
-void queryNanoapps() {
-  auto status = getContextHub()->queryNanoapps(kContextHubId);
-  verifyStatusAndSignal(/* operation= */ "querying nanoapps", status,
-                        gCallback->promise.get_future());
-}
-
-HostEndpointInfo createHostEndpointInfo(const std::string &hexEndpointId) {
-  uint16_t hostEndpointId = verifyAndConvertEndpointHexId(hexEndpointId);
-  return {
-      .hostEndpointId = hostEndpointId,
-      .type = HostEndpointInfo::Type::NATIVE,
-      .packageName = "chre_aidl_hal_client",
-      .attributionTag{},
-  };
-}
-
-void onEndpointConnected(const std::string &hexEndpointId) {
-  auto contextHub = getContextHub();
-  HostEndpointInfo info = createHostEndpointInfo(hexEndpointId);
-  // connect the endpoint to HAL
-  verifyStatus(/* operation= */ "connect endpoint",
-               contextHub->onHostEndpointConnected(info));
-  std::cout << "Connected." << std::endl;
-}
-
-void onEndpointDisconnected(const std::string &hexEndpointId) {
-  auto contextHub = getContextHub();
-  uint16_t hostEndpointId = verifyAndConvertEndpointHexId(hexEndpointId);
-  // disconnect the endpoint from HAL
-  verifyStatus(/* operation= */ "disconnect endpoint",
-               contextHub->onHostEndpointDisconnected(hostEndpointId));
-  std::cout << "Disconnected." << std::endl;
-}
-
-ContextHubMessage createContextHubMessage(const std::string &hexHostEndpointId,
-                                          std::string &appIdOrName,
-                                          const std::string &hexPayload) {
-  if (!isValidHexNumber(hexPayload)) {
-    throwError("Invalid hex payload.");
-  }
-  auto appId = getNanoappIdFrom(appIdOrName);
-  uint16_t hostEndpointId = verifyAndConvertEndpointHexId(hexHostEndpointId);
-  ContextHubMessage contextHubMessage = {
-      .nanoappId = appId,
-      .hostEndPoint = hostEndpointId,
-      .messageBody = {},
-      .permissions = {},
-  };
-  // populate the payload
-  for (int i = 2; i < hexPayload.size(); i += 2) {
-    contextHubMessage.messageBody.push_back(
-        std::stoi(hexPayload.substr(i, 2), /* idx= */ nullptr, /* base= */ 16));
-  }
-  return contextHubMessage;
-}
-
-/** Sends a hexPayload from hexHostEndpointId to appIdOrName. */
-void sendMessageToNanoapp(const std::string &hexHostEndpointId,
-                          std::string &appIdOrName,
-                          const std::string &hexPayload) {
-  ContextHubMessage contextHubMessage =
-      createContextHubMessage(hexHostEndpointId, appIdOrName, hexPayload);
-  // send the message
-  auto contextHub = getContextHub();
-  auto status = contextHub->sendMessageToHub(kContextHubId, contextHubMessage);
-  verifyStatusAndSignal(/* operation= */ "sending a message to " + appIdOrName,
-                        status, gCallback->promise.get_future());
-}
-
-void changeSetting(const std::string &setting, bool enabled) {
-  auto contextHub = getContextHub();
-  int settingType = std::stoi(setting);
-  if (settingType < 1 || settingType > 7) {
-    throwError("setting type must be within [1, 7].");
-  }
-  ScopedAStatus status =
-      contextHub->onSettingChanged(static_cast<Setting>(settingType), enabled);
-  std::cout << "onSettingChanged is called to "
-            << (enabled ? "enable" : "disable") << " setting type "
-            << settingType << std::endl;
-  verifyStatus("change setting", status);
-}
-
-void enableTestModeOnContextHub() {
-  auto status = getContextHub()->setTestMode(/* enable= */ true);
-  verifyStatus(/* operation= */ "enabling test mode", status);
-  std::cout << "Test mode is enabled" << std::endl;
-}
-
-void disableTestModeOnContextHub() {
-  auto status = getContextHub()->setTestMode(/* enable= */false);
-  verifyStatus(/* operation= */ "disabling test mode", status);
-  std::cout << "Test mode is disabled" << std::endl;
-}
-
-void getAllPreloadedNanoappIds() {
-  std::vector<int64_t> appIds{};
-  verifyStatus("get preloaded nanoapp ids",
-               getContextHub()->getPreloadedNanoappIds(kContextHubId, &appIds));
-  for (const auto &appId : appIds) {
-    std::cout << "0x" << std::hex << appId << std::endl;
-  }
-}
-
-// Please keep Command in alphabetical order
-enum Command {
-  connect,
-  connectEndpoint,
-  disableSetting,
-  disableTestMode,
-  disconnectEndpoint,
-  enableSetting,
-  enableTestMode,
-  getContextHubs,
-  getPreloadedNanoappIds,
-  list,
-  load,
-  query,
-  registerCallback,
-  sendMessage,
-  unload,
-  unsupported
-};
-
-struct CommandInfo {
-  Command cmd;
-  u_int8_t numOfArgs;  // including cmd;
-  std::string argsFormat;
-  std::string usage;
-};
-
-const std::map<std::string, CommandInfo> kAllCommands{
-    {"connect",
-     {.cmd = connect,
-      .numOfArgs = 1,
-      .argsFormat = "",
-      .usage = "connect to HAL using hal_client library and keep the session "
-               "alive while user can execute other commands. Use 'exit' to "
-               "quit the session."}},
-    {"connectEndpoint",
-     {.cmd = connectEndpoint,
-      .numOfArgs = 2,
-      .argsFormat = "<HEX_ENDPOINT_ID>",
-      .usage =
-          "associate an endpoint with the current client and notify HAL."}},
-    {"disableSetting",
-     {.cmd = disableSetting,
-      .numOfArgs = 2,
-      .argsFormat = "<SETTING>",
-      .usage = "disable a setting identified by a number defined in "
-               "android/hardware/contexthub/Setting.aidl."}},
-    {"disableTestMode",
-     {.cmd = disableTestMode,
-      .numOfArgs = 1,
-      .argsFormat = "",
-      .usage = "disable test mode."}},
-    {"disconnectEndpoint",
-     {.cmd = disconnectEndpoint,
-      .numOfArgs = 2,
-      .argsFormat = "<HEX_ENDPOINT_ID>",
-      .usage = "remove an endpoint with the current client and notify HAL."}},
-    {"enableSetting",
-     {.cmd = enableSetting,
-      .numOfArgs = 2,
-      .argsFormat = "<SETTING>",
-      .usage = "enable a setting identified by a number defined in "
-               "android/hardware/contexthub/Setting.aidl."}},
-    {"enableTestMode",
-     {.cmd = enableTestMode,
-      .numOfArgs = 1,
-      .argsFormat = "",
-      .usage = "enable test mode."}},
-    {"getContextHubs",
-     {.cmd = getContextHubs,
-      .numOfArgs = 1,
-      .argsFormat = "",
-      .usage = "get all the context hubs."}},
-    {"getPreloadedNanoappIds",
-     {.cmd = getPreloadedNanoappIds,
-      .numOfArgs = 1,
-      .argsFormat = "",
-      .usage = "get a list of ids for the preloaded nanoapps."}},
-    {"list",
-     {.cmd = list,
-      .numOfArgs = 2,
-      .argsFormat = "</PATH/TO/NANOAPPS>",
-      .usage = "list all the nanoapps' header info in the path."}},
-    {"load",
-     {.cmd = load,
-      .numOfArgs = 2,
-      .argsFormat = "<APP_NAME | /PATH/TO/APP_NAME>",
-      .usage = "load the nanoapp specified by the name. If an absolute path is "
-               "not provided the default locations are searched."}},
-    {"query",
-     {.cmd = query,
-      .numOfArgs = 1,
-      .argsFormat = "",
-      .usage = "show all loaded nanoapps (system apps excluded)."}},
-    {"registerCallback",
-     {.cmd = registerCallback,
-      .numOfArgs = 1,
-      .argsFormat = "",
-      .usage = "register a callback for the current client."}},
-    {"sendMessage",
-     {.cmd = sendMessage,
-      .numOfArgs = 4,
-      .argsFormat = "<HEX_ENDPOINT_ID> <HEX_NANOAPP_ID | APP_NAME | "
-                    "/PATH/TO/APP_NAME> <HEX_PAYLOAD>",
-      .usage = "send a payload to a nanoapp. If an absolute path is not "
-               "provided the default locations are searched."}},
-    {"unload",
-     {.cmd = unload,
-      .numOfArgs = 2,
-      .argsFormat = "<HEX_NANOAPP_ID | APP_NAME | /PATH/TO/APP_NAME>",
-      .usage = "unload the nanoapp specified by either the nanoapp id or the "
-               "app name. If an absolute path is not provided the default "
-               "locations are searched."}},
-};
-
-void fillSupportedCommandMap(
-    const std::unordered_set<std::string> &supportedCommands,
-    std::map<std::string, CommandInfo> &supportedCommandMap) {
-  std::copy_if(kAllCommands.begin(), kAllCommands.end(),
-               std::inserter(supportedCommandMap, supportedCommandMap.begin()),
-               [&](auto const &kv_pair) {
-                 return supportedCommands.find(kv_pair.first) !=
-                        supportedCommands.end();
-               });
-}
-
-void printUsage(const std::map<std::string, CommandInfo> &supportedCommands) {
-  constexpr uint32_t kCommandLength = 40;
-  std::cout << std::left << "Usage: COMMAND [ARGUMENTS]" << std::endl;
-  for (auto const &kv_pair : supportedCommands) {
-    std::string cmdLine = kv_pair.first + " " + kv_pair.second.argsFormat;
-    std::cout << std::setw(kCommandLength) << cmdLine;
-    if (cmdLine.size() > kCommandLength) {
-      std::cout << std::endl << std::string(kCommandLength, ' ');
-    }
-    std::cout << " - " + kv_pair.second.usage << std::endl;
-  }
-  std::cout << std::endl;
-}
-
-Command parseCommand(
-    const std::vector<std::string> &cmdLine,
-    const std::map<std::string, CommandInfo> &supportedCommandMap) {
-  if (cmdLine.empty() ||
-      supportedCommandMap.find(cmdLine[0]) == supportedCommandMap.end()) {
-    return unsupported;
-  }
-  auto cmdInfo = supportedCommandMap.at(cmdLine[0]);
-  return cmdLine.size() == cmdInfo.numOfArgs ? cmdInfo.cmd : unsupported;
-}
-
-void executeCommand(std::vector<std::string> cmdLine) {
-  switch (parseCommand(cmdLine, kAllCommands)) {
-    case connectEndpoint: {
-      onEndpointConnected(cmdLine[1]);
-      break;
-    }
-    case disableSetting: {
-      changeSetting(cmdLine[1], false);
-      break;
-    }
-    case disableTestMode: {
-      disableTestModeOnContextHub();
-      break;
-    }
-    case disconnectEndpoint: {
-      onEndpointDisconnected(cmdLine[1]);
-      break;
-    }
-    case enableSetting: {
-      changeSetting(cmdLine[1], true);
-      break;
-    }
-    case enableTestMode: {
-      enableTestModeOnContextHub();
-      break;
-    }
-    case getContextHubs: {
-      getAllContextHubs();
-      break;
-    }
-    case getPreloadedNanoappIds: {
-      getAllPreloadedNanoappIds();
-      break;
-    }
-    case list: {
-      std::map<std::string, NanoAppBinaryHeader> nanoapps{};
-      readNanoappHeaders(nanoapps, cmdLine[1]);
-      for (const auto &entity : nanoapps) {
-        std::cout << entity.first;
-        printNanoappHeader(entity.second);
-      }
-      break;
-    }
-    case load: {
-      loadNanoapp(cmdLine[1]);
-      break;
-    }
-    case query: {
-      queryNanoapps();
-      break;
-    }
-    case registerCallback: {
-      registerHostCallback();
-      break;
-    }
-    case sendMessage: {
-      sendMessageToNanoapp(cmdLine[1], cmdLine[2], cmdLine[3]);
-      break;
-    }
-    case unload: {
-      unloadNanoapp(cmdLine[1]);
-      break;
-    }
-    default:
-      printUsage(kAllCommands);
-  }
-}
-
-std::vector<std::string> getCommandLine() {
-  std::string input;
-  std::cout << "> ";
-  std::getline(std::cin, input);
-  input.push_back('\n');
-  std::vector<std::string> result{};
-  for (int begin = 0, end = 0; end < input.size();) {
-    if (isspace(input[begin])) {
-      end = begin = begin + 1;
-      continue;
-    }
-    if (!isspace(input[end])) {
-      end += 1;
-      continue;
-    }
-    result.push_back(input.substr(begin, end - begin));
-    begin = end;
-  }
-  return result;
-}
-
-void connectToHal() {
-  if (gCallback == nullptr) {
-    gCallback = ContextHubCallback::make<ContextHubCallback>();
-  }
-  std::unique_ptr<HalClient> halClient = HalClient::create(gCallback);
-  if (halClient == nullptr || !halClient->connect()) {
-    LOGE("Failed to init the connection to HAL.");
-    return;
-  }
-  std::unordered_set<std::string> supportedCommands = {
-      "connectEndpoint", "disconnectEndpoint", "query", "sendMessage"};
-  std::map<std::string, CommandInfo> supportedCommandMap{};
-  fillSupportedCommandMap(supportedCommands, supportedCommandMap);
-
-  while (true) {
-    auto cmdLine = getCommandLine();
-    if (cmdLine.empty()) {
-      continue;
-    }
-    if (cmdLine.size() == 1 && cmdLine[0] == "exit") {
-      break;
-    }
-    try {
-      switch (parseCommand(cmdLine, supportedCommandMap)) {
-        case connectEndpoint: {
-          HostEndpointInfo info =
-              createHostEndpointInfo(/* hexEndpointId= */ cmdLine[1]);
-          verifyStatus(/* operation= */ "connect endpoint",
-                       halClient->connectEndpoint(info));
-          break;
-        }
-
-        case query: {
-          verifyStatusAndSignal(/* operation= */ "querying nanoapps",
-                                halClient->queryNanoapps(),
-                                gCallback->promise.get_future());
-          break;
-        }
-
-        case disconnectEndpoint: {
-          uint16_t hostEndpointId =
-              verifyAndConvertEndpointHexId(/* number= */ cmdLine[1]);
-          verifyStatus(/* operation= */ "disconnect endpoint",
-                       halClient->disconnectEndpoint(hostEndpointId));
-          break;
-        }
-        case sendMessage: {
-          ContextHubMessage message = createContextHubMessage(
-              /* hexHostEndpointId= */ cmdLine[1],
-              /* appIdOrName= */ cmdLine[2], /* hexPayload= */ cmdLine[3]);
-          verifyStatusAndSignal(
-              /* operation= */ "sending a message to " + cmdLine[2],
-              halClient->sendMessage(message), gCallback->promise.get_future());
-          break;
-        }
-        default:
-          printUsage(supportedCommandMap);
-      }
-    } catch (std::system_error &e) {
-      std::cerr << e.what() << std::endl;
-    }
-  }
-}
-}  // anonymous namespace
-
-int main(int argc, char *argv[]) {
-  // Start binder thread pool to enable callbacks.
-  ABinderProcess_startThreadPool();
-
-  std::vector<std::string> cmdLine{};
-  for (int i = 1; i < argc; i++) {
-    cmdLine.emplace_back(argv[i]);
-  }
-  try {
-    if (cmdLine.size() == 1 && cmdLine[0] == "connect") {
-      connectToHal();
-      return 0;
-    }
-    executeCommand(cmdLine);
-  } catch (std::system_error &e) {
-    std::cerr << e.what() << std::endl;
-    return -1;
-  }
-  return 0;
-}
diff --git a/host/common/hal_client.cc b/host/common/hal_client.cc
index e25e6f58..90416425 100644
--- a/host/common/hal_client.cc
+++ b/host/common/hal_client.cc
@@ -22,30 +22,22 @@
 #include "chre_host/log.h"
 
 #include <android-base/properties.h>
-#include <android_chre_flags.h>
+#include <android/binder_manager.h>
 #include <utils/SystemClock.h>
-
-#include <cinttypes>
 #include <thread>
 
 namespace android::chre {
 
-using ::aidl::android::hardware::contexthub::IContextHub;
-using ::aidl::android::hardware::contexthub::IContextHubCallback;
-using ::android::base::GetBoolProperty;
-using ::ndk::ScopedAStatus;
+using aidl::android::hardware::contexthub::IContextHub;
+using aidl::android::hardware::contexthub::IContextHubCallback;
+using base::GetBoolProperty;
+using ndk::ScopedAStatus;
 
 namespace {
-constexpr char kHalEnabledProperty[]{"vendor.chre.multiclient_hal.enabled"};
-
 // Multiclient HAL needs getUuid() added since V3 to identify each client.
 constexpr int kMinHalInterfaceVersion = 3;
 }  // namespace
 
-bool HalClient::isServiceAvailable() {
-  return GetBoolProperty(kHalEnabledProperty, /* default_value= */ false);
-}
-
 std::unique_ptr<HalClient> HalClient::create(
     const std::shared_ptr<IContextHubCallback> &callback,
     int32_t contextHubId) {
@@ -54,22 +46,16 @@ std::unique_ptr<HalClient> HalClient::create(
     return nullptr;
   }
 
-  if (!isServiceAvailable()) {
-    LOGE("CHRE Multiclient HAL is not enabled on this device");
-    return nullptr;
-  }
-
-  if (callback->version < kMinHalInterfaceVersion) {
+  if (IContextHubCallback::version < kMinHalInterfaceVersion) {
     LOGE("Callback interface version is %" PRIi32 ". It must be >= %" PRIi32,
          callback->version, kMinHalInterfaceVersion);
     return nullptr;
   }
-
   return std::unique_ptr<HalClient>(new HalClient(callback, contextHubId));
 }
 
 HalError HalClient::initConnection() {
-  std::lock_guard<std::shared_mutex> lockGuard{mConnectionLock};
+  std::lock_guard lockGuard{mConnectionLock};
 
   if (mContextHub != nullptr) {
     LOGW("%s is already connected to CHRE HAL", mClientName.c_str());
@@ -128,10 +114,10 @@ HalError HalClient::initConnection() {
 }
 
 void HalClient::onHalDisconnected(void *cookie) {
-  int64_t startTime = ::android::elapsedRealtime();
+  int64_t startTime = elapsedRealtime();
   auto *halClient = static_cast<HalClient *>(cookie);
   {
-    std::lock_guard<std::shared_mutex> lockGuard(halClient->mConnectionLock);
+    std::lock_guard lockGuard(halClient->mConnectionLock);
     halClient->mContextHub = nullptr;
     halClient->mIsHalConnected = false;
   }
@@ -139,13 +125,14 @@ void HalClient::onHalDisconnected(void *cookie) {
        halClient->mClientName.c_str());
 
   HalError result = halClient->initConnection();
-  uint64_t duration = ::android::elapsedRealtime() - startTime;
+  uint64_t duration = elapsedRealtime() - startTime;
   if (result != HalError::SUCCESS) {
     LOGE("Failed to fully reconnect to CHRE HAL after %" PRIu64
          "ms, HalErrorCode: %" PRIi32,
          duration, result);
     return;
   }
+
   tryReconnectEndpoints(halClient);
   LOGI("%s is reconnected to CHRE HAL after %" PRIu64 "ms",
        halClient->mClientName.c_str(), duration);
@@ -232,7 +219,7 @@ void HalClient::tryReconnectEndpoints(HalClient *halClient) {
 }
 
 HalClient::~HalClient() {
-  std::lock_guard<std::mutex> lock(mBackgroundConnectionFuturesLock);
+  std::lock_guard lock(mBackgroundConnectionFuturesLock);
   for (const auto &future : mBackgroundConnectionFutures) {
     // Calling std::thread.join() has chance to hang if the background thread
     // being joined is still waiting for connecting to the service. Therefore
diff --git a/host/common/include/chre_host/hal_client.h b/host/common/include/chre_host/hal_client.h
index 45ce4468..7dd438ee 100644
--- a/host/common/include/chre_host/hal_client.h
+++ b/host/common/include/chre_host/hal_client.h
@@ -17,9 +17,7 @@
 #ifndef CHRE_HOST_HAL_CLIENT_H_
 #define CHRE_HOST_HAL_CLIENT_H_
 
-#include <cinttypes>
 #include <future>
-#include <memory>
 #include <shared_mutex>
 #include <thread>
 #include <unordered_map>
@@ -31,27 +29,32 @@
 #include <aidl/android/hardware/contexthub/IContextHub.h>
 #include <aidl/android/hardware/contexthub/IContextHubCallback.h>
 #include <aidl/android/hardware/contexthub/NanoappBinary.h>
-#include <android/binder_manager.h>
 #include <android/binder_process.h>
 
 #include "hal_error.h"
 
 namespace android::chre {
 
-using ::aidl::android::hardware::contexthub::AsyncEventType;
-using ::aidl::android::hardware::contexthub::BnContextHubCallback;
-using ::aidl::android::hardware::contexthub::ContextHubInfo;
-using ::aidl::android::hardware::contexthub::ContextHubMessage;
-using ::aidl::android::hardware::contexthub::HostEndpointInfo;
-using ::aidl::android::hardware::contexthub::IContextHub;
-using ::aidl::android::hardware::contexthub::IContextHubCallback;
-using ::aidl::android::hardware::contexthub::IContextHubDefault;
-using ::aidl::android::hardware::contexthub::MessageDeliveryStatus;
-using ::aidl::android::hardware::contexthub::NanoappBinary;
-using ::aidl::android::hardware::contexthub::NanoappInfo;
-using ::aidl::android::hardware::contexthub::NanSessionRequest;
-using ::aidl::android::hardware::contexthub::Setting;
-using ::ndk::ScopedAStatus;
+using aidl::android::hardware::contexthub::AsyncEventType;
+using aidl::android::hardware::contexthub::BnContextHubCallback;
+using aidl::android::hardware::contexthub::ContextHubInfo;
+using aidl::android::hardware::contexthub::ContextHubMessage;
+using aidl::android::hardware::contexthub::EndpointId;
+using aidl::android::hardware::contexthub::EndpointInfo;
+using aidl::android::hardware::contexthub::HostEndpointInfo;
+using aidl::android::hardware::contexthub::HubInfo;
+using aidl::android::hardware::contexthub::IContextHub;
+using aidl::android::hardware::contexthub::IContextHubCallback;
+using aidl::android::hardware::contexthub::IContextHubDefault;
+using aidl::android::hardware::contexthub::IEndpointCallback;
+using aidl::android::hardware::contexthub::IEndpointCommunication;
+using aidl::android::hardware::contexthub::MessageDeliveryStatus;
+using aidl::android::hardware::contexthub::NanoappBinary;
+using aidl::android::hardware::contexthub::NanoappInfo;
+using aidl::android::hardware::contexthub::NanSessionRequest;
+using aidl::android::hardware::contexthub::Service;
+using aidl::android::hardware::contexthub::Setting;
+using ndk::ScopedAStatus;
 
 /**
  * A class connecting to CHRE Multiclient HAL via binder and taking care of
@@ -86,6 +89,65 @@ class HalClient {
     virtual ~BackgroundConnectionCallback() = default;
   };
 
+  /**
+   * A builder class to facilitate the creation of EndpointInfo objects.
+   *
+   * This class provides a fluent interface for constructing an EndpointInfo
+   * object step-by-step. It simplifies the process by setting default values
+   * for optional fields and allowing method chaining.
+   *
+   * Usage:
+   * 1. Construct an EndpointInfoBuilder with the mandatory EndpointId and
+   * name. Please refer to EndpointId.aidl for details about endpoint ids.
+   *    - The `hubId` within the EndpointId is expected to be statically
+   *      defined and globally unique, identifying a specific session-based
+   *      messaging hub.
+   *    - The `endpointId` within the EndpointId is expected to be statically
+   *      defined and unique *within the scope of its hub*, identifying a
+   *      specific endpoint (e.g., a nanoapp, a specific host client, etc.).
+   * 2. Optionally call setter methods like `setVersion()`, `setTag()`, etc., to
+   * configure the optional details. These methods return a reference to the
+   * builder, allowing chaining.
+   * 3. Call `build()` to obtain the final, configured EndpointInfo object.
+   */
+  class EndpointInfoBuilder {
+   public:
+    EndpointInfoBuilder(const EndpointId &id, const std::string &name) {
+      mEndpointInfo.id = id;
+      mEndpointInfo.name = name;
+      mEndpointInfo.type = EndpointInfo::EndpointType::NATIVE;
+      mEndpointInfo.version = 0;
+      mEndpointInfo.tag = std::nullopt;
+    }
+
+    EndpointInfoBuilder &setVersion(const int32_t &version) {
+      mEndpointInfo.version = version;
+      return *this;
+    }
+
+    EndpointInfoBuilder &setTag(const std::string &tag) {
+      mEndpointInfo.tag = tag;
+      return *this;
+    }
+
+    EndpointInfoBuilder &addRequiredPermission(const std::string &permission) {
+      mEndpointInfo.requiredPermissions.push_back(permission);
+      return *this;
+    }
+
+    EndpointInfoBuilder &addService(const Service &service) {
+      mEndpointInfo.services.push_back(service);
+      return *this;
+    }
+
+    [[nodiscard]] EndpointInfo build() const {
+      return mEndpointInfo;
+    }
+
+   private:
+    EndpointInfo mEndpointInfo;
+  };
+
   ~HalClient();
 
   /**
@@ -100,15 +162,6 @@ class HalClient {
       const std::shared_ptr<IContextHubCallback> &callback,
       int32_t contextHubId = kDefaultContextHubId);
 
-  /**
-   * Returns true if the multiclient HAL is available.
-   *
-   * <p>Multicleint HAL may not be available on a device that has CHRE enabled.
-   * In this situation, clients are expected to still use SocketClient to
-   * communicate with CHRE.
-   */
-  static bool isServiceAvailable();
-
   /** Returns true if this HalClient instance is connected to the HAL. */
   bool isConnected() {
     return mIsHalConnected;
@@ -121,7 +174,7 @@ class HalClient {
 
   /** Connects to CHRE HAL in background. */
   void connectInBackground(BackgroundConnectionCallback &callback) {
-    std::lock_guard<std::mutex> lock(mBackgroundConnectionFuturesLock);
+    std::lock_guard lock(mBackgroundConnectionFuturesLock);
     // Policy std::launch::async is required to avoid lazy evaluation which can
     // postpone the execution until get() of the future returned by std::async
     // is called.
@@ -146,6 +199,35 @@ class HalClient {
   /** Disconnects a host endpoint from CHRE. */
   ScopedAStatus disconnectEndpoint(char16_t hostEndpointId);
 
+  /** Registers a new hub for endpoint communication. */
+  ScopedAStatus registerEndpointHub(
+      const std::shared_ptr<IEndpointCallback> &callback,
+      const HubInfo &hubInfo,
+      std::shared_ptr<IEndpointCommunication> *communication) {
+    return callIfConnected(
+        [&](const std::shared_ptr<IContextHub> &contextHubHal) {
+          return contextHubHal->registerEndpointHub(callback, hubInfo,
+                                                    communication);
+        });
+  }
+
+  /** Lists all the hubs, including the Context Hub and generic hubs. */
+  ScopedAStatus getHubs(std::vector<HubInfo> *hubs) {
+    return callIfConnected(
+        [&](const std::shared_ptr<IContextHub> &contextHubHal) {
+          return contextHubHal->getHubs(hubs);
+        });
+  }
+
+  /** Lists all the endpoints, including the Context Hub nanoapps and generic
+   * endpoints. */
+  ScopedAStatus getEndpoints(std::vector<EndpointInfo> *endpoints) {
+    return callIfConnected(
+        [&](const std::shared_ptr<IContextHub> &contextHubHal) {
+          return contextHubHal->getEndpoints(endpoints);
+        });
+  }
+
  protected:
   class HalClientCallback : public BnContextHubCallback {
    public:
@@ -236,7 +318,7 @@ class HalClient {
       // Make a copy of mContextHub so that even if HAL is disconnected and
       // mContextHub is set to null the copy is kept as non-null to avoid crash.
       // Still guard the copy by a shared lock to avoid torn writes.
-      std::shared_lock<std::shared_mutex> sharedLock(mConnectionLock);
+      std::shared_lock sharedLock(mConnectionLock);
       hub = mContextHub;
     }
     if (hub == nullptr) {
@@ -246,18 +328,18 @@ class HalClient {
   }
 
   bool isEndpointConnected(HostEndpointId hostEndpointId) {
-    std::shared_lock<std::shared_mutex> sharedLock(mConnectedEndpointsLock);
+    std::shared_lock sharedLock(mConnectedEndpointsLock);
     return mConnectedEndpoints.find(hostEndpointId) !=
            mConnectedEndpoints.end();
   }
 
   void insertConnectedEndpoint(const HostEndpointInfo &hostEndpointInfo) {
-    std::lock_guard<std::shared_mutex> lockGuard(mConnectedEndpointsLock);
+    std::lock_guard lockGuard(mConnectedEndpointsLock);
     mConnectedEndpoints[hostEndpointInfo.hostEndpointId] = hostEndpointInfo;
   }
 
   void removeConnectedEndpoint(HostEndpointId hostEndpointId) {
-    std::lock_guard<std::shared_mutex> lockGuard(mConnectedEndpointsLock);
+    std::lock_guard lockGuard(mConnectedEndpointsLock);
     mConnectedEndpoints.erase(hostEndpointId);
   }
 
diff --git a/host/common/include/chre_host/time_util.h b/host/common/include/chre_host/time_util.h
new file mode 100644
index 00000000..d777e1c8
--- /dev/null
+++ b/host/common/include/chre_host/time_util.h
@@ -0,0 +1,63 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+#pragma once
+
+#include <chrono>
+#include <string>
+
+#include <utils/SystemClock.h>
+
+namespace android::chre {
+
+/**
+ * Converts a CHRE timestamp to one comparable with elapsedRealtimeNano().
+ *
+ * @param chreTime CHRE timestamp in ns
+ * @param estimatedHostOffset Estimated offset from host time in ns
+ * @return Estimated host timestamp
+ */
+constexpr uint64_t estimatedHostRealtimeNs(uint64_t chreTime,
+                                           uint64_t estimatedHostOffset) {
+  return chreTime + estimatedHostOffset;
+}
+
+/**
+ * Generates a nice representation of the given system time.
+ *
+ * @param time The time to stringify, default is now
+ * @return time formatted as mm-dd HH:MM:SS.xxx
+ */
+std::string getWallclockTime(std::chrono::time_point<std::chrono::system_clock>
+                                 time = std::chrono::system_clock::now());
+
+/**
+ * Converts elapsedRealtimeNano() to wallclock time and formats it.
+ *
+ * @param realtime Output of elapsedRealtimeNano() or comparable timestamp
+ * @param now Reference point for converting realtime. Optionally allows passing
+ * in the current time.
+ * @param nowRealtime Used to compute the duration since realtime. Optionally
+ * allows passing in the current time.
+ * @param realtime formatted as mm-dd HH:MM:SS.xxx
+ */
+std::string realtimeNsToWallclockTime(
+    uint64_t realtime,
+    std::chrono::time_point<std::chrono::system_clock> now =
+        std::chrono::system_clock::now(),
+    uint64_t nowRealtime = elapsedRealtimeNano());
+
+}  // namespace android::chre
diff --git a/host/common/socket_client.cc b/host/common/socket_client.cc
index 2e301d5e..226986be 100644
--- a/host/common/socket_client.cc
+++ b/host/common/socket_client.cc
@@ -213,12 +213,12 @@ bool SocketClient::receiveThreadRunning() const {
 
 bool SocketClient::reconnect() {
   constexpr auto kMinDelay = std::chrono::duration<int32_t, std::milli>(250);
-  constexpr auto kMaxDelay = std::chrono::minutes(5);
+  constexpr auto kMaxDelay = std::chrono::seconds(4);
   // Try reconnecting at initial delay this many times before backing off
   constexpr unsigned int kExponentialBackoffDelay =
       std::chrono::seconds(10) / kMinDelay;
-  // Give up after this many tries (~2.5 hours)
-  constexpr unsigned int kRetryLimit = kExponentialBackoffDelay + 40;
+  // Give up after this many tries (a little under 3 hours)
+  constexpr unsigned int kRetryLimit = 2500;
   auto delay = kMinDelay;
   unsigned int retryCount = 0;
 
diff --git a/host/common/time_util.cc b/host/common/time_util.cc
new file mode 100644
index 00000000..ab50ba47
--- /dev/null
+++ b/host/common/time_util.cc
@@ -0,0 +1,55 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+#include "chre_host/time_util.h"
+
+#include <chrono>
+#include <cinttypes>
+#include <cstdio>
+#include <ctime>
+#include <string>
+
+namespace android::chre {
+
+std::string getWallclockTime(
+    std::chrono::time_point<std::chrono::system_clock> time) {
+  auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
+      time.time_since_epoch());
+
+  constexpr int kBufferSize = 20;  // mm-dd HH:MM:SS.xxx
+  char buffer[kBufferSize]{};
+  time_t cTime = std::chrono::system_clock::to_time_t(time);
+  std::strftime(buffer, kBufferSize, "%m-%d %H:%M:%S.", std::localtime(&cTime));
+  // The offset 15 is right after the `.` printed by strftime(). The size 4 is
+  // the 3 digits of the durationMs followed by a null terminator.
+  std::snprintf(buffer + 15, /* size= */ 4, "%03" PRIu16,
+                static_cast<uint16_t>(durationMs.count() % 1000));
+  return {buffer};
+}
+
+std::string realtimeNsToWallclockTime(
+    uint64_t realtime, std::chrono::time_point<std::chrono::system_clock> now,
+    uint64_t nowRealtime) {
+  if (nowRealtime < realtime) {
+    return "<Error - Could not compute wallclock time>";
+  }
+  auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
+      std::chrono::nanoseconds{nowRealtime - realtime});
+  auto hostTime = now - diff;
+  return getWallclockTime(hostTime);
+}
+
+}  // namespace android::chre
diff --git a/host/hal_generic/Android.bp b/host/hal_generic/Android.bp
index 35e265a9..8107a136 100644
--- a/host/hal_generic/Android.bp
+++ b/host/hal_generic/Android.bp
@@ -43,6 +43,7 @@ filegroup {
         "aidl/generic_context_hub_aidl.cc",
         "common/bluetooth_socket_fbs_hal.cc",
         "common/hal_chre_socket_connection.cc",
+        "common/error_util.cc",
         "common/permissions_util.cc",
     ],
 }
diff --git a/host/hal_generic/common/bluetooth_socket_fbs_hal.cc b/host/hal_generic/common/bluetooth_socket_fbs_hal.cc
index e791253e..0962658e 100644
--- a/host/hal_generic/common/bluetooth_socket_fbs_hal.cc
+++ b/host/hal_generic/common/bluetooth_socket_fbs_hal.cc
@@ -18,6 +18,9 @@
 
 #include <cstdint>
 #include <future>
+#include <memory>
+#include <mutex>
+#include <string>
 
 #include "chre/platform/shared/host_protocol_common.h"
 #include "chre_host/generated/host_messages_generated.h"
@@ -38,15 +41,7 @@ ScopedAStatus BluetoothSocketFbsHal::registerCallback(
 
 ScopedAStatus BluetoothSocketFbsHal::getSocketCapabilities(
     SocketCapabilities *result) {
-  std::future<SocketCapabilities> future = mCapabilitiesPromise.get_future();
-
-  flatbuffers::FlatBufferBuilder builder(64);
-  auto socketCapabilitiesRequest =
-      ::chre::fbs::CreateBtSocketCapabilitiesRequest(builder);
-  ::chre::HostProtocolCommon::finalize(
-      builder, ::chre::fbs::ChreMessage::BtSocketCapabilitiesRequest,
-      socketCapabilitiesRequest.Union());
-
+  LOGI("Received getSocketCapabilities request");
   if (!mOffloadLinkAvailable) {
     LOGE("BT Socket Offload Link not available");
     return ScopedAStatus::fromServiceSpecificErrorWithMessage(
@@ -54,16 +49,14 @@ ScopedAStatus BluetoothSocketFbsHal::getSocketCapabilities(
         "BT offload link not available");
   }
 
-  if (!mOffloadLink->sendMessageToOffloadStack(builder.GetBufferPointer(),
-                                               builder.GetSize())) {
-    LOGE("Failed to send BT socket capabilities request message");
+  std::future<SocketCapabilities> future = sendSocketCapabilitiesRequest();
+  if (!future.valid()) {
+    LOGE("BT socket capabilities future is not valid");
     return ScopedAStatus::fromServiceSpecificErrorWithMessage(
         static_cast<int32_t>(STATUS_UNKNOWN_ERROR),
-        "Failed to send BT socket message");
+        "BT socket capabilities future is not valid");
   }
-
-  std::future_status status = future.wait_for(std::chrono::seconds(5));
-  if (status != std::future_status::ready) {
+  if (future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
     LOGE("BT Socket capabilities request timed out");
     return ScopedAStatus::fromServiceSpecificErrorWithMessage(
         static_cast<int32_t>(STATUS_UNKNOWN_ERROR),
@@ -74,6 +67,25 @@ ScopedAStatus BluetoothSocketFbsHal::getSocketCapabilities(
   return ScopedAStatus::ok();
 }
 
+std::future<SocketCapabilities>
+BluetoothSocketFbsHal::sendSocketCapabilitiesRequest() {
+  std::lock_guard lock(mMutex);
+  flatbuffers::FlatBufferBuilder builder(64);
+  auto socketCapabilitiesRequest =
+      ::chre::fbs::CreateBtSocketCapabilitiesRequest(builder);
+  ::chre::HostProtocolCommon::finalize(
+      builder, ::chre::fbs::ChreMessage::BtSocketCapabilitiesRequest,
+      socketCapabilitiesRequest.Union());
+  if (!mOffloadLink->sendMessageToOffloadStack(builder.GetBufferPointer(),
+                                               builder.GetSize())) {
+    LOGE("Failed to send BT socket capabilities request message");
+    return std::future<SocketCapabilities>();
+  }
+
+  mCapabilitiesPromise = std::make_optional<std::promise<SocketCapabilities>>();
+  return mCapabilitiesPromise->get_future();
+}
+
 ScopedAStatus BluetoothSocketFbsHal::opened(const SocketContext &context) {
   LOGD("Host opened BT offload socket ID=%" PRIu64, context.socketId);
   if (!mOffloadLinkAvailable) {
@@ -204,6 +216,11 @@ void BluetoothSocketFbsHal::handleBtSocketClose(
 void BluetoothSocketFbsHal::handleBtSocketCapabilitiesResponse(
     const ::chre::fbs::BtSocketCapabilitiesResponseT &response) {
   LOGD("Got BT Socket capabilities response");
+  std::lock_guard lock(mMutex);
+  if (!mCapabilitiesPromise.has_value()) {
+    LOGE("Received BT Socket capabilities response with no pending request");
+    return;
+  }
   SocketCapabilities capabilities = {
       .leCocCapabilities =
           {
@@ -218,7 +235,8 @@ void BluetoothSocketFbsHal::handleBtSocketCapabilitiesResponse(
               .maxFrameSize = response.rfcommCapabilities->maxFrameSize,
           },
   };
-  mCapabilitiesPromise.set_value(capabilities);
+  mCapabilitiesPromise->set_value(capabilities);
+  mCapabilitiesPromise = std::nullopt;
 }
 
 void BluetoothSocketFbsHal::sendOpenedCompleteMessage(int64_t socketId,
diff --git a/host/hal_generic/common/bluetooth_socket_fbs_hal.h b/host/hal_generic/common/bluetooth_socket_fbs_hal.h
index cb1866d1..6bfee63d 100644
--- a/host/hal_generic/common/bluetooth_socket_fbs_hal.h
+++ b/host/hal_generic/common/bluetooth_socket_fbs_hal.h
@@ -19,6 +19,9 @@
 #include <atomic>
 #include <cstdint>
 #include <future>
+#include <mutex>
+#include <optional>
+#include <string>
 
 #include "aidl/android/hardware/bluetooth/socket/BnBluetoothSocket.h"
 #include "bluetooth_socket_offload_link.h"
@@ -69,7 +72,11 @@ class BluetoothSocketFbsHal : public BnBluetoothSocket,
 
   // A promise that is set when getSocketCapabilities is called and is fulfilled
   // when a response is received from the offload stack.
-  std::promise<SocketCapabilities> mCapabilitiesPromise;
+  std::optional<std::promise<SocketCapabilities>> mCapabilitiesPromise =
+      std::nullopt;
+
+  // A mutex to guard the mCapabilitiesPromise.
+  std::mutex mMutex;
 
   void sendOpenedCompleteMessage(int64_t socketId, Status status,
                                  std::string reason);
@@ -81,6 +88,10 @@ class BluetoothSocketFbsHal : public BnBluetoothSocket,
 
   void handleBtSocketCapabilitiesResponse(
       const ::chre::fbs::BtSocketCapabilitiesResponseT &response);
+
+  // Sends a socket capabilities request to the offload stack and returns a
+  // future that is fulfilled with the capabilities response.
+  std::future<SocketCapabilities> sendSocketCapabilitiesRequest();
 };
 
 }  // namespace aidl::android::hardware::bluetooth::socket::impl
diff --git a/host/hal_generic/common/context_hub_v4_impl.cc b/host/hal_generic/common/context_hub_v4_impl.cc
index 16c01da7..a3528748 100644
--- a/host/hal_generic/common/context_hub_v4_impl.cc
+++ b/host/hal_generic/common/context_hub_v4_impl.cc
@@ -43,8 +43,9 @@ void ContextHubV4Impl::init() {
   // is used both to initialize the CHRE-side host hub proxies and to request
   // embedded hub state.
   HostProtocolHostV4::encodeGetMessageHubsAndEndpointsRequest(builder);
-  if (!mSendMessageFn(builder))
+  if (!mSendMessageFn(builder)) {
     LOGE("Failed to initialize CHRE host hub proxies");
+  }
   mManager.forEachHostHub([this](HostHub &hub) {
     flatbuffers::FlatBufferBuilder builder;
     HostProtocolHostV4::encodeRegisterMessageHub(builder, hub.info());
@@ -304,12 +305,14 @@ ScopedAStatus HostHubInterface::endpointSessionOpenComplete(int32_t sessionId) {
 
 ScopedAStatus HostHubInterface::unregister() {
   std::lock_guard lock(mHostHubOpLock);  // See header documentation.
-  if (auto status = mHub->unregister(); !status.ok())
+  if (auto status = mHub->unregister(); !status.ok()) {
     return fromPwStatus(status);
+  }
   flatbuffers::FlatBufferBuilder builder;
   HostProtocolHostV4::encodeUnregisterMessageHub(builder, mHub->id());
-  if (!mSendMessageFn(builder))
+  if (!mSendMessageFn(builder)) {
     LOGE("Failed to send UnregisterMessageHub for hub 0x%" PRIx64, mHub->id());
+  }
   return ScopedAStatus::ok();
 }
 
@@ -354,10 +357,11 @@ bool ContextHubV4Impl::handleMessageFromChre(
     case ChreMessage::EndpointReady:
       onEndpointReady(*message.AsEndpointReady());
       break;
-    default:
+    default: {
       LOGW("Got unexpected message type %" PRIu8,
            static_cast<uint8_t>(message.type));
       return false;
+    }
   }
   return true;
 }
@@ -499,7 +503,9 @@ void ContextHubV4Impl::onEndpointSessionMessage(
     return;
   }
   auto status = hub->handleMessage(sessionId, message);
-  if (status.ok()) return;
+  if (status.ok()) {
+    return;
+  }
   handleSessionFailure(hub, sessionId, status);
 }
 
@@ -516,7 +522,9 @@ void ContextHubV4Impl::onEndpointSessionMessageDeliveryStatus(
     return;
   }
   auto status = hub->handleMessageDeliveryStatus(sessionId, deliveryStatus);
-  if (status.ok()) return;
+  if (status.ok()) {
+    return;
+  }
   handleSessionFailure(hub, sessionId, status);
 }
 
@@ -524,7 +532,9 @@ void ContextHubV4Impl::unlinkDeadHostHub(
     std::function<pw::Result<int64_t>()> unlinkFn) {
   std::lock_guard lock(mHostHubOpLock);  // See header documentation.
   auto statusOrHubId = unlinkFn();
-  if (!statusOrHubId.ok()) return;
+  if (!statusOrHubId.ok()) {
+    return;
+  }
   flatbuffers::FlatBufferBuilder builder;
   HostProtocolHostV4::encodeUnregisterMessageHub(builder, *statusOrHubId);
   if (!mSendMessageFn(builder)) {
@@ -546,4 +556,4 @@ void ContextHubV4Impl::handleSessionFailure(const std::shared_ptr<HostHub> &hub,
   hub->closeSession(session, Reason::UNSPECIFIED).IgnoreError();
 }
 
-}  // namespace android::hardware::contexthub::common::implementation
+}  // namespace android::hardware::contexthub::common::implementation
\ No newline at end of file
diff --git a/host/hal_generic/common/error_util.cc b/host/hal_generic/common/error_util.cc
new file mode 100644
index 00000000..aea680f6
--- /dev/null
+++ b/host/hal_generic/common/error_util.cc
@@ -0,0 +1,60 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "error_util.h"
+
+#include "chre_api/chre.h"
+
+using ::aidl::android::hardware::contexthub::ErrorCode;
+
+namespace android::hardware::contexthub::common::implementation {
+
+uint8_t toChreErrorCode(ErrorCode errorCode) {
+  switch (errorCode) {
+    case ErrorCode::OK:
+      return CHRE_ERROR_NONE;
+    case ErrorCode::TRANSIENT_ERROR:
+      return CHRE_ERROR_TRANSIENT;
+    case ErrorCode::PERMANENT_ERROR:
+      return CHRE_ERROR;
+    case ErrorCode::PERMISSION_DENIED:
+      return CHRE_ERROR_PERMISSION_DENIED;
+    case ErrorCode::DESTINATION_NOT_FOUND:
+      return CHRE_ERROR_DESTINATION_NOT_FOUND;
+  }
+
+  return CHRE_ERROR;
+}
+
+ErrorCode toErrorCode(uint32_t chreErrorCode) {
+  switch (chreErrorCode) {
+    case CHRE_ERROR_NONE:
+      return ErrorCode::OK;
+    case CHRE_ERROR_BUSY:  // fallthrough
+    case CHRE_ERROR_TRANSIENT:
+      return ErrorCode::TRANSIENT_ERROR;
+    case CHRE_ERROR:
+      return ErrorCode::PERMANENT_ERROR;
+    case CHRE_ERROR_PERMISSION_DENIED:
+      return ErrorCode::PERMISSION_DENIED;
+    case CHRE_ERROR_DESTINATION_NOT_FOUND:
+      return ErrorCode::DESTINATION_NOT_FOUND;
+  }
+
+  return aidl::android::hardware::contexthub::ErrorCode::PERMANENT_ERROR;
+}
+
+}  // namespace android::hardware::contexthub::common::implementation
diff --git a/host/hal_generic/common/error_util.h b/host/hal_generic/common/error_util.h
new file mode 100644
index 00000000..2a14dc2a
--- /dev/null
+++ b/host/hal_generic/common/error_util.h
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef ANDROID_HARDWARE_CONTEXTHUB_COMMON_ERROR_UTIL_H
+#define ANDROID_HARDWARE_CONTEXTHUB_COMMON_ERROR_UTIL_H
+
+#include "aidl/android/hardware/contexthub/ErrorCode.h"
+
+namespace android::hardware::contexthub::common::implementation {
+
+//! Converts the AIDL ErrorCode to the CHRE error code.
+uint8_t toChreErrorCode(
+    aidl::android::hardware::contexthub::ErrorCode errorCode);
+
+//! Converts the CHRE error code to the AIDL ErrorCode.
+aidl::android::hardware::contexthub::ErrorCode toErrorCode(
+    uint32_t chreErrorCode);
+
+}  // namespace android::hardware::contexthub::common::implementation
+
+#endif  // ANDROID_HARDWARE_CONTEXTHUB_COMMON_ERROR_UTIL_H
diff --git a/host/hal_generic/common/host_protocol_host_v4.cc b/host/hal_generic/common/host_protocol_host_v4.cc
index c3137150..f62ab3a2 100644
--- a/host/hal_generic/common/host_protocol_host_v4.cc
+++ b/host/hal_generic/common/host_protocol_host_v4.cc
@@ -18,6 +18,7 @@
 
 #include <chre_host/host_protocol_host.h>
 
+#include "error_util.h"
 #include "permissions_util.h"
 
 namespace android::hardware::contexthub::common::implementation {
@@ -137,8 +138,7 @@ void HostProtocolHostV4::encodeEndpointSessionMessageDeliveryStatus(
     FlatBufferBuilder &builder, int64_t hostHubId, uint16_t sessionId,
     const AidlMessageDeliveryStatus &status) {
   auto fbsStatus = ::chre::fbs::CreateMessageDeliveryStatus(
-      builder, status.messageSequenceNumber,
-      static_cast<int8_t>(status.errorCode));
+      builder, status.messageSequenceNumber, toChreErrorCode(status.errorCode));
   auto msg = ::chre::fbs::CreateEndpointSessionMessageDeliveryStatus(
       builder, hostHubId, sessionId, fbsStatus);
   finalize(builder, ChreMessage::EndpointSessionMessageDeliveryStatus,
@@ -245,7 +245,7 @@ void HostProtocolHostV4::decodeEndpointSessionMessageDeliveryStatus(
   sessionId = msg.session_id;
   status = {.messageSequenceNumber =
                 static_cast<int32_t>(msg.status->message_sequence_number),
-            .errorCode = static_cast<AidlErrorCode>(msg.status->error_code)};
+            .errorCode = toErrorCode(msg.status->error_code)};
 }
 
 Offset<MessageHub> HostProtocolHostV4::aidlToFbsMessageHub(
diff --git a/host/hal_generic/common/message_hub_manager.cc b/host/hal_generic/common/message_hub_manager.cc
index 6b289f83..d984e2d9 100644
--- a/host/hal_generic/common/message_hub_manager.cc
+++ b/host/hal_generic/common/message_hub_manager.cc
@@ -67,10 +67,12 @@ pw::Status HostHub::addEndpoint(const EndpointInfo &info) {
     return pw::Status::PermissionDenied();
   }
   int64_t id = info.id.id;
-  if (auto it = mIdToEndpoint.find(id); it != mIdToEndpoint.end()) {
-    LOGE("Endpoint %" PRId64 " already exists in hub %" PRId64, id,
-         kInfo.hubId);
-    return pw::Status::AlreadyExists();
+  for (const auto &[existId, existInfo] : mIdToEndpoint) {
+    if (id == existId || (!info.name.empty() && info.name == existInfo.name)) {
+      LOGE("Endpoint %" PRId64 " (%s) already exists in hub %" PRId64, id,
+           info.name.c_str(), kInfo.hubId);
+      return pw::Status::AlreadyExists();
+    }
   }
   mIdToEndpoint.insert({id, info});
   return pw::OkStatus();
@@ -83,9 +85,13 @@ pw::Result<std::vector<uint16_t>> HostHub::removeEndpoint(
   if (auto it = mIdToEndpoint.find(id.id); it != mIdToEndpoint.end()) {
     std::vector<uint16_t> sessions;
     for (const auto &[sessionId, session] : mIdToSession) {
-      if (session.mHostEndpoint == id) sessions.push_back(sessionId);
+      if (session.mHostEndpoint == id) {
+        sessions.push_back(sessionId);
+      }
+    }
+    for (auto sessionId : sessions) {
+      mIdToSession.erase(sessionId);
     }
-    for (auto sessionId : sessions) mIdToSession.erase(sessionId);
     mIdToEndpoint.erase(it);
     return sessions;
   }
@@ -188,7 +194,9 @@ pw::Status HostHub::closeSession(uint16_t id, std::optional<Reason> reason) {
     return pw::Status::NotFound();
   }
   mIdToSession.erase(it);
-  if (reason) mCallback->onCloseEndpointSession(id, *reason);
+  if (reason) {
+    mCallback->onCloseEndpointSession(id, *reason);
+  }
   return pw::OkStatus();
 }
 
@@ -212,7 +220,9 @@ pw::Status HostHub::ackSession(uint16_t id, bool hostAcked) {
     }
     session->mPendingDestination = false;
     // Notify the initiator that the session has been opened.
-    if (isHostSession) mCallback->onEndpointSessionOpenComplete(id);
+    if (isHostSession) {
+      mCallback->onEndpointSessionOpenComplete(id);
+    }
   } else if (session->mPendingMessageRouter) {
     if (hostAcked) {
       LOGE("Message router must ack session %" PRIu16, id);
@@ -257,8 +267,9 @@ pw::Status HostHub::unregister() {
 std::vector<EndpointInfo> HostHub::getEndpoints() const {
   std::vector<EndpointInfo> endpoints;
   std::lock_guard lock(mManager.mLock);
-  for (const auto &[id, endpoint] : mIdToEndpoint)
+  for (const auto &[id, endpoint] : mIdToEndpoint) {
     endpoints.push_back(endpoint);
+  }
   return endpoints;
 }
 
@@ -277,7 +288,8 @@ pw::Status HostHub::checkValidLocked() {
           " which was not successfully registered.",
           kInfo.hubId);
     return pw::Status::FailedPrecondition();
-  } else if (mUnlinked) {
+  }
+  if (mUnlinked) {
     ALOGW("Hub %" PRId64 " went down mid-operation", kInfo.hubId);
     return pw::Status::Aborted();
   }
@@ -293,10 +305,13 @@ pw::Status HostHub::endpointExistsLocked(
     return pw::Status::InvalidArgument();
   }
   if (auto it = mIdToEndpoint.find(id.id); it != mIdToEndpoint.end()) {
-    if (!serviceDescriptor) return pw::OkStatus();
+    if (!serviceDescriptor) {
+      return pw::OkStatus();
+    }
     for (const auto &service : it->second.services) {
-      if (service.serviceDescriptor == *serviceDescriptor)
+      if (service.serviceDescriptor == *serviceDescriptor) {
         return pw::OkStatus();
+      }
     }
     LOGW("Endpoint (%" PRId64 ", %" PRId64 ") doesn't have service %s",
          id.hubId, id.id, serviceDescriptor->c_str());
@@ -306,15 +321,18 @@ pw::Status HostHub::endpointExistsLocked(
 
 bool HostHub::sessionIdInRangeLocked(uint16_t id) {
   for (auto range : mSessionIdRanges) {
-    if (id >= range.first && id <= range.second) return true;
+    if (id >= range.first && id <= range.second) {
+      return true;
+    }
   }
   return false;
 }
 
 pw::Status HostHub::checkSessionOpenLocked(uint16_t id) {
   PW_TRY_ASSIGN(Session * session, getSessionLocked(id));
-  if (!session->mPendingDestination && !session->mPendingMessageRouter)
+  if (!session->mPendingDestination && !session->mPendingMessageRouter) {
     return pw::OkStatus();
+  }
   LOGE("Session %" PRIu16 " is pending", id);
   return pw::Status::FailedPrecondition();
 }
@@ -339,9 +357,13 @@ pw::Result<std::shared_ptr<HostHub>> MessageHubManager::createHostHub(
     return pw::Status::PermissionDenied();
   }
   std::lock_guard lock(mLock);
-  if (mIdToHostHub.count(info.hubId)) return pw::Status::AlreadyExists();
+  if (mIdToHostHub.count(info.hubId)) {
+    return pw::Status::AlreadyExists();
+  }
   std::shared_ptr<HostHub> hub(new HostHub(*this, std::move(callback), info));
-  if (!hub->mCallback) return pw::Status::Internal();
+  if (!hub->mCallback) {
+    return pw::Status::Internal();
+  }
   mIdToHostHub.insert({info.hubId, hub});
   LOGI("Registered host hub %" PRId64, info.hubId);
   return hub;
@@ -349,8 +371,9 @@ pw::Result<std::shared_ptr<HostHub>> MessageHubManager::createHostHub(
 
 std::shared_ptr<HostHub> MessageHubManager::getHostHub(int64_t id) {
   std::lock_guard lock(mLock);
-  if (auto it = mIdToHostHub.find(id); it != mIdToHostHub.end())
+  if (auto it = mIdToHostHub.find(id); it != mIdToHostHub.end()) {
     return it->second;
+  }
   return {};
 }
 
@@ -358,9 +381,13 @@ void MessageHubManager::forEachHostHub(std::function<void(HostHub &hub)> fn) {
   std::list<std::shared_ptr<HostHub>> hubs;
   {
     std::lock_guard lock(mLock);
-    for (auto &[id, hub] : mIdToHostHub) hubs.push_back(hub);
+    for (auto &[id, hub] : mIdToHostHub) {
+      hubs.push_back(hub);
+    }
+  }
+  for (auto &hub : hubs) {
+    fn(*hub);
   }
-  for (auto &hub : hubs) fn(*hub);
 }
 
 void MessageHubManager::initEmbeddedState() {
@@ -376,16 +403,20 @@ void MessageHubManager::clearEmbeddedState() {
   // Clear embedded hub state, caching the list of now removed endpoints.
   std::vector<EndpointId> endpoints;
   for (const auto &[hubId, hub] : mIdToEmbeddedHub) {
-    for (const auto &[endpointId, endpoint] : hub.idToEndpoint)
-      if (endpoint.second) endpoints.push_back(endpoint.first.id);
+    for (const auto &[endpointId, endpoint] : hub.idToEndpoint) {
+      if (endpoint.second) {
+        endpoints.push_back(endpoint.first.id);
+      }
+    }
   }
   mIdToEmbeddedHub.clear();
 
   // For each host hub, close all sessions and send all removed endpoints.
   for (const auto &[hubId, hub] : mIdToHostHub) {
     ::android::base::ScopedLockAssertion lockAssertion(hub->mManager.mLock);
-    for (const auto &[sessionId, session] : hub->mIdToSession)
+    for (const auto &[sessionId, session] : hub->mIdToSession) {
       hub->mCallback->onCloseEndpointSession(sessionId, Reason::HUB_RESET);
+    }
     hub->mCallback->onEndpointStopped(endpoints, Reason::HUB_RESET);
   }
 }
@@ -396,7 +427,9 @@ void MessageHubManager::addEmbeddedHub(const HubInfo &hub) {
     LOGW("Skipping embedded hub registration before initEmbeddedState()");
     return;
   }
-  if (mIdToEmbeddedHub.count(hub.hubId)) return;
+  if (mIdToEmbeddedHub.count(hub.hubId)) {
+    return;
+  }
   mIdToEmbeddedHub[hub.hubId].info = hub;
 }
 
@@ -406,9 +439,14 @@ void MessageHubManager::removeEmbeddedHub(int64_t id) {
   // Get the list of endpoints being removed and remove the hub.
   std::vector<EndpointId> endpoints;
   auto it = mIdToEmbeddedHub.find(id);
-  if (it == mIdToEmbeddedHub.end()) return;
-  for (const auto &[endpointId, info] : it->second.idToEndpoint)
-    if (info.second) endpoints.push_back(info.first.id);
+  if (it == mIdToEmbeddedHub.end()) {
+    return;
+  }
+  for (const auto &[endpointId, info] : it->second.idToEndpoint) {
+    if (info.second) {
+      endpoints.push_back(info.first.id);
+    }
+  }
   mIdToEmbeddedHub.erase(it);
 
   // For each host hub, determine which sessions if any are now closed and send
@@ -422,7 +460,9 @@ void MessageHubManager::removeEmbeddedHub(int64_t id) {
         closedSessions.push_back(sessionId);
       }
     }
-    for (auto session : closedSessions) hub->mIdToSession.erase(session);
+    for (auto session : closedSessions) {
+      hub->mIdToSession.erase(session);
+    }
     hub->mCallback->onEndpointStopped(endpoints, Reason::HUB_RESET);
   }
 }
@@ -430,7 +470,9 @@ void MessageHubManager::removeEmbeddedHub(int64_t id) {
 std::vector<HubInfo> MessageHubManager::getEmbeddedHubs() const {
   std::lock_guard lock(mLock);
   std::vector<HubInfo> hubs;
-  for (const auto &[id, hub] : mIdToEmbeddedHub) hubs.push_back(hub.info);
+  for (const auto &[id, hub] : mIdToEmbeddedHub) {
+    hubs.push_back(hub.info);
+  }
   return hubs;
 }
 
@@ -451,7 +493,9 @@ void MessageHubManager::addEmbeddedEndpointService(const EndpointId &endpoint,
     return;
   }
   auto statusOrEndpoint = lookupEmbeddedEndpointLocked(endpoint);
-  if (!statusOrEndpoint.ok()) return;
+  if (!statusOrEndpoint.ok()) {
+    return;
+  }
   if ((*statusOrEndpoint)->second) {
     LOGE("Adding service to embedded endpoint after ready");
     return;
@@ -466,7 +510,9 @@ void MessageHubManager::setEmbeddedEndpointReady(const EndpointId &id) {
     return;
   }
   auto statusOrEndpoint = lookupEmbeddedEndpointLocked(id);
-  if (!statusOrEndpoint.ok() || (*statusOrEndpoint)->second) return;
+  if (!statusOrEndpoint.ok() || (*statusOrEndpoint)->second) {
+    return;
+  }
   (*statusOrEndpoint)->second = true;
   for (auto &[hostHubId, hub] : mIdToHostHub) {
     ::android::base::ScopedLockAssertion lockAssertion(hub->mManager.mLock);
@@ -478,8 +524,11 @@ std::vector<EndpointInfo> MessageHubManager::getEmbeddedEndpoints() const {
   std::lock_guard lock(mLock);
   std::vector<EndpointInfo> endpoints;
   for (const auto &[id, hub] : mIdToEmbeddedHub) {
-    for (const auto &[endptId, endptInfo] : hub.idToEndpoint)
-      if (endptInfo.second) endpoints.push_back(endptInfo.first);
+    for (const auto &[endptId, endptInfo] : hub.idToEndpoint) {
+      if (endptInfo.second) {
+        endpoints.push_back(endptInfo.first);
+      }
+    }
   }
   return endpoints;
 }
@@ -487,8 +536,12 @@ std::vector<EndpointInfo> MessageHubManager::getEmbeddedEndpoints() const {
 void MessageHubManager::removeEmbeddedEndpoint(const EndpointId &id) {
   std::lock_guard lock(mLock);
   auto hubIt = mIdToEmbeddedHub.find(id.hubId);
-  if (hubIt == mIdToEmbeddedHub.end()) return;
-  if (!hubIt->second.idToEndpoint.erase(id.id)) return;
+  if (hubIt == mIdToEmbeddedHub.end()) {
+    return;
+  }
+  if (!hubIt->second.idToEndpoint.erase(id.id)) {
+    return;
+  }
 
   // For each host hub, determine which sessions if any are now closed and send
   // notifications as appropriate. Also send the removed endpoint notification.
@@ -502,7 +555,9 @@ void MessageHubManager::removeEmbeddedEndpoint(const EndpointId &id) {
         closedSessions.push_back(sessionId);
       }
     }
-    for (auto session : closedSessions) hub->mIdToSession.erase(session);
+    for (auto session : closedSessions) {
+      hub->mIdToSession.erase(session);
+    }
     hub->mCallback->onEndpointStopped({id}, Reason::ENDPOINT_GONE);
   }
 }
@@ -569,9 +624,13 @@ pw::Status MessageHubManager::embeddedEndpointExistsLocked(
          id.hubId, id.id);
     return pw::Status::NotFound();
   }
-  if (!serviceDescriptor) return pw::OkStatus();
+  if (!serviceDescriptor) {
+    return pw::OkStatus();
+  }
   for (const auto &service : endpoint->first.services) {
-    if (service.serviceDescriptor == *serviceDescriptor) return pw::OkStatus();
+    if (service.serviceDescriptor == *serviceDescriptor) {
+      return pw::OkStatus();
+    }
   }
   LOGW("Endpoint (%" PRId64 ", %" PRId64 ") doesn't have service %s", id.hubId,
        id.id, serviceDescriptor->c_str());
@@ -583,7 +642,9 @@ MessageHubManager::lookupEmbeddedEndpointLocked(const EndpointId &id) {
   auto hubIt = mIdToEmbeddedHub.find(id.hubId);
   if (hubIt != mIdToEmbeddedHub.end()) {
     auto it = hubIt->second.idToEndpoint.find(id.id);
-    if (it != hubIt->second.idToEndpoint.end()) return &(it->second);
+    if (it != hubIt->second.idToEndpoint.end()) {
+      return &(it->second);
+    }
   }
   LOGW("Could not find remote endpoint (%" PRId64 ", %" PRId64 ")", id.hubId,
        id.id);
diff --git a/host/hal_generic/common/multi_client_context_hub_base.cc b/host/hal_generic/common/multi_client_context_hub_base.cc
index 1255195e..ddfef8fc 100644
--- a/host/hal_generic/common/multi_client_context_hub_base.cc
+++ b/host/hal_generic/common/multi_client_context_hub_base.cc
@@ -25,6 +25,7 @@
 #include "chre_host/fragmented_load_transaction.h"
 #include "chre_host/hal_error.h"
 #include "chre_host/host_protocol_host.h"
+#include "error_util.h"
 #include "hal_client_id.h"
 #include "permissions_util.h"
 
@@ -34,13 +35,12 @@
 
 namespace android::hardware::contexthub::common::implementation {
 
-using ::android::base::WriteStringToFd;
-using ::android::chre::FragmentedLoadTransaction;
-using ::android::chre::getStringFromByteVector;
-using ::android::chre::Atoms::ChreHalNanoappLoadFailed;
-using ::android::chre::flags::abort_if_no_context_hub_found;
-using ::android::chre::flags::bug_fix_hal_reliable_message_record;
-using ::ndk::ScopedAStatus;
+using Atoms::ChreHalNanoappLoadFailed;
+using base::WriteStringToFd;
+using chre::FragmentedLoadTransaction;
+using chre::getStringFromByteVector;
+using flags::abort_if_no_context_hub_found;
+using ndk::ScopedAStatus;
 namespace fbs = ::chre::fbs;
 
 namespace {
@@ -49,7 +49,7 @@ constexpr uint32_t kDefaultHubId = 0;
 // timeout for calling getContextHubs(), which is synchronous
 constexpr auto kHubInfoQueryTimeout = std::chrono::seconds(5);
 // timeout for enable/disable test mode, which is synchronous
-constexpr std::chrono::duration ktestModeTimeOut = std::chrono::seconds(5);
+constexpr std::chrono::duration kTestModeTimeout = std::chrono::seconds(5);
 
 // The transaction id for synchronously load/unload a nanoapp in test mode.
 constexpr int32_t kTestModeTransactionId{static_cast<int32_t>(0x80000000)};
@@ -88,7 +88,7 @@ bool getFbsSetting(const Setting &setting, fbs::Setting *fbsSetting) {
   return foundSetting;
 }
 
-chre::fbs::SettingState toFbsSettingState(bool enabled) {
+fbs::SettingState toFbsSettingState(bool enabled) {
   return enabled ? chre::fbs::SettingState::ENABLED
                  : chre::fbs::SettingState::DISABLED;
 }
@@ -114,41 +114,6 @@ inline ScopedAStatus fromResult(bool result) {
                 : fromServiceError(HalError::OPERATION_FAILED);
 }
 
-uint8_t toChreErrorCode(ErrorCode errorCode) {
-  switch (errorCode) {
-    case ErrorCode::OK:
-      return CHRE_ERROR_NONE;
-    case ErrorCode::TRANSIENT_ERROR:
-      return CHRE_ERROR_TRANSIENT;
-    case ErrorCode::PERMANENT_ERROR:
-      return CHRE_ERROR;
-    case ErrorCode::PERMISSION_DENIED:
-      return CHRE_ERROR_PERMISSION_DENIED;
-    case ErrorCode::DESTINATION_NOT_FOUND:
-      return CHRE_ERROR_DESTINATION_NOT_FOUND;
-  }
-
-  return CHRE_ERROR;
-}
-
-ErrorCode toErrorCode(uint32_t chreErrorCode) {
-  switch (chreErrorCode) {
-    case CHRE_ERROR_NONE:
-      return ErrorCode::OK;
-    case CHRE_ERROR_BUSY: // fallthrough
-    case CHRE_ERROR_TRANSIENT:
-      return ErrorCode::TRANSIENT_ERROR;
-    case CHRE_ERROR:
-      return ErrorCode::PERMANENT_ERROR;
-    case CHRE_ERROR_PERMISSION_DENIED:
-      return ErrorCode::PERMISSION_DENIED;
-    case CHRE_ERROR_DESTINATION_NOT_FOUND:
-      return ErrorCode::DESTINATION_NOT_FOUND;
-  }
-
-  return ErrorCode::PERMANENT_ERROR;
-}
-
 }  // anonymous namespace
 
 MultiClientContextHubBase::MultiClientContextHubBase() {
@@ -435,25 +400,21 @@ ScopedAStatus MultiClientContextHubBase::sendMessageToHub(
   }
 
   if (message.isReliable) {
-    if (bug_fix_hal_reliable_message_record()) {
-      std::lock_guard<std::mutex> lock(mReliableMessageMutex);
-      auto iter = std::find_if(
-          mReliableMessageQueue.begin(), mReliableMessageQueue.end(),
-          [&message](const ReliableMessageRecord &record) {
-            return record.messageSequenceNumber == message.messageSequenceNumber;
-          });
-      if (iter == mReliableMessageQueue.end()) {
-        mReliableMessageQueue.push_back(ReliableMessageRecord{
-            .timestamp = std::chrono::steady_clock::now(),
-            .messageSequenceNumber = message.messageSequenceNumber,
-            .hostEndpointId = hostEndpointId});
-        std::push_heap(mReliableMessageQueue.begin(), mReliableMessageQueue.end(),
-                      std::greater<ReliableMessageRecord>());
-      }
-      cleanupReliableMessageQueueLocked();
-    } else {
-      mReliableMessageMap.insert({message.messageSequenceNumber, hostEndpointId});
+    std::lock_guard<std::mutex> lock(mReliableMessageMutex);
+    auto iter = std::find_if(
+        mReliableMessageQueue.begin(), mReliableMessageQueue.end(),
+        [&message](const ReliableMessageRecord &record) {
+          return record.messageSequenceNumber == message.messageSequenceNumber;
+        });
+    if (iter == mReliableMessageQueue.end()) {
+      mReliableMessageQueue.push_back(ReliableMessageRecord{
+          .timestamp = std::chrono::steady_clock::now(),
+          .messageSequenceNumber = message.messageSequenceNumber,
+          .hostEndpointId = hostEndpointId});
+      std::push_heap(mReliableMessageQueue.begin(), mReliableMessageQueue.end(),
+                     std::greater<ReliableMessageRecord>());
     }
+    cleanupReliableMessageQueueLocked();
   }
 
   flatbuffers::FlatBufferBuilder builder(1024);
@@ -571,21 +532,26 @@ ScopedAStatus MultiClientContextHubBase::sendMessageDeliveryStatusToHub(
 }
 
 ScopedAStatus MultiClientContextHubBase::getHubs(std::vector<HubInfo> *hubs) {
-  if (mV4Impl) return mV4Impl->getHubs(hubs);
+  if (mV4Impl) {
+    return mV4Impl->getHubs(hubs);
+  }
   return ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
 }
 
 ScopedAStatus MultiClientContextHubBase::getEndpoints(
     std::vector<EndpointInfo> *endpoints) {
-  if (mV4Impl) return mV4Impl->getEndpoints(endpoints);
+  if (mV4Impl) {
+    return mV4Impl->getEndpoints(endpoints);
+  }
   return ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
 }
 
 ScopedAStatus MultiClientContextHubBase::registerEndpointHub(
     const std::shared_ptr<IEndpointCallback> &callback, const HubInfo &hubInfo,
     std::shared_ptr<IEndpointCommunication> *hubInterface) {
-  if (mV4Impl)
+  if (mV4Impl) {
     return mV4Impl->registerEndpointHub(callback, hubInfo, hubInterface);
+  }
   return ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
 }
 
@@ -598,13 +564,13 @@ bool MultiClientContextHubBase::enableTestModeLocked(
     LOGE("Failed to get a list of loaded nanoapps to enable test mode");
     return false;
   }
-  if (!mEnableTestModeCv.wait_for(lock, ktestModeTimeOut, [&]() {
+  if (!mEnableTestModeCv.wait_for(lock, kTestModeTimeout, [&]() {
         return mTestModeNanoapps.has_value() &&
                mTestModeSystemNanoapps.has_value();
       })) {
     LOGE("Failed to get a list of loaded nanoapps within %" PRIu64
          " seconds to enable test mode",
-         ktestModeTimeOut.count());
+         kTestModeTimeout.count());
     return false;
   }
 
@@ -628,7 +594,7 @@ bool MultiClientContextHubBase::enableTestModeLocked(
 
     // Wait for the unloading result.
     mTestModeSyncUnloadResult.reset();
-    mEnableTestModeCv.wait_for(lock, ktestModeTimeOut, [&]() {
+    mEnableTestModeCv.wait_for(lock, kTestModeTimeout, [&]() {
       return mTestModeSyncUnloadResult.has_value();
     });
     bool success =
@@ -1005,38 +971,24 @@ void MultiClientContextHubBase::onNanoappMessage(
 void MultiClientContextHubBase::onMessageDeliveryStatus(
     const ::chre::fbs::MessageDeliveryStatusT &status) {
   HostEndpointId hostEndpointId;
-  if (bug_fix_hal_reliable_message_record()) {
-    {
-      std::lock_guard<std::mutex> lock(mReliableMessageMutex);
-      auto iter = std::find_if(
-          mReliableMessageQueue.begin(), mReliableMessageQueue.end(),
-          [&status](const ReliableMessageRecord &record) {
-            return record.messageSequenceNumber == status.message_sequence_number;
-          });
-      if (iter == mReliableMessageQueue.end()) {
-        LOGE(
-            "Unable to get the host endpoint ID for message "
-            "sequence number: %" PRIu32,
-            status.message_sequence_number);
-        return;
-      }
 
-      hostEndpointId = iter->hostEndpointId;
-      cleanupReliableMessageQueueLocked();
-    }
-  } else {
-    auto hostEndpointIdIter =
-        mReliableMessageMap.find(status.message_sequence_number);
-    if (hostEndpointIdIter == mReliableMessageMap.end()) {
+  {
+    std::lock_guard<std::mutex> lock(mReliableMessageMutex);
+    auto iter = std::find_if(
+        mReliableMessageQueue.begin(), mReliableMessageQueue.end(),
+        [&status](const ReliableMessageRecord &record) {
+          return record.messageSequenceNumber == status.message_sequence_number;
+        });
+    if (iter == mReliableMessageQueue.end()) {
       LOGE(
-          "Unable to get the host endpoint ID for message sequence "
-          "number: %" PRIu32,
+          "Unable to get the host endpoint ID for message "
+          "sequence number: %" PRIu32,
           status.message_sequence_number);
       return;
     }
 
-    hostEndpointId = hostEndpointIdIter->second;
-    mReliableMessageMap.erase(hostEndpointIdIter);
+    hostEndpointId = iter->hostEndpointId;
+    cleanupReliableMessageQueueLocked();
   }
 
   std::shared_ptr<IContextHubCallback> callback =
@@ -1078,15 +1030,19 @@ void MultiClientContextHubBase::handleClientDeath(pid_t clientPid) {
 
 void MultiClientContextHubBase::onChreDisconnected() {
   mIsChreReady = false;
-  LOGW("HAL APIs will be failed because CHRE is disconnected");
-  if (mV4Impl) mV4Impl->onChreDisconnected();
+  LOGW("HAL APIs will fail because CHRE is disconnected");
+  if (mV4Impl) {
+    mV4Impl->onChreDisconnected();
+  }
 }
 
 void MultiClientContextHubBase::onChreRestarted() {
   mIsWifiAvailable.reset();
   mEventLogger.logContextHubRestart();
   mHalClientManager->handleChreRestart();
-  if (mV4Impl) mV4Impl->onChreRestarted();
+  if (mV4Impl) {
+    mV4Impl->onChreRestarted();
+  }
 
   // Unblock APIs BEFORE informing the clients that CHRE has restarted so that
   // any API call triggered by handleContextHubAsyncEvent() can come through.
diff --git a/host/test/hal_generic/common/hal_client_test.cc b/host/test/hal_generic/common/hal_client_test.cc
index ed3fb6f7..c4d3387f 100644
--- a/host/test/hal_generic/common/hal_client_test.cc
+++ b/host/test/hal_generic/common/hal_client_test.cc
@@ -14,7 +14,6 @@
  * limitations under the License.
  */
 #include "chre_host/hal_client.h"
-#include "chre_host/hal_error.h"
 
 #include <unordered_set>
 
@@ -26,20 +25,21 @@
 namespace android::chre {
 
 namespace {
-using ::aidl::android::hardware::contexthub::ContextHubMessage;
-using ::aidl::android::hardware::contexthub::HostEndpointInfo;
-using ::aidl::android::hardware::contexthub::IContextHub;
-using ::aidl::android::hardware::contexthub::IContextHubCallbackDefault;
-using ::aidl::android::hardware::contexthub::IContextHubDefault;
-
-using ::ndk::ScopedAStatus;
-
-using ::testing::_;
-using ::testing::ByMove;
-using ::testing::Field;
-using ::testing::IsEmpty;
-using ::testing::Return;
-using ::testing::UnorderedElementsAre;
+using aidl::android::hardware::contexthub::ContextHubMessage;
+using aidl::android::hardware::contexthub::HostEndpointInfo;
+using aidl::android::hardware::contexthub::IContextHub;
+using aidl::android::hardware::contexthub::IContextHubCallbackDefault;
+using aidl::android::hardware::contexthub::IContextHubDefault;
+
+using ndk::ScopedAStatus;
+
+using testing::_;
+using testing::ByMove;
+using testing::ElementsAre;
+using testing::Field;
+using testing::IsEmpty;
+using testing::Return;
+using testing::UnorderedElementsAre;
 
 using HostEndpointId = char16_t;
 constexpr HostEndpointId kEndpointId = 0x10;
@@ -220,4 +220,99 @@ TEST(HalClientTest, IsConnected) {
 
   EXPECT_THAT(halClient->isConnected(), true);
 }
+
+/** =================== Tests for EndpointInfoBuilder =================== */
+
+TEST(HalClientTest, EndpointInfoBuilderBasic) {
+  auto endpointId = EndpointId{.id = 1, .hubId = 0xabcdef00};
+  EndpointInfo info =
+      HalClient::EndpointInfoBuilder(endpointId, "my endpoint id").build();
+  EXPECT_EQ(info.id, endpointId);
+  EXPECT_EQ(info.name, "my endpoint id");
+  EXPECT_EQ(info.type, EndpointInfo::EndpointType::NATIVE);
+  EXPECT_EQ(info.version, 0);
+  EXPECT_EQ(info.tag, std::nullopt);
+  EXPECT_THAT(info.requiredPermissions, IsEmpty());
+  EXPECT_THAT(info.services, IsEmpty());
+}
+
+TEST(HalClientTest, EndpointInfoBuilderSetVersion) {
+  auto endpointId = EndpointId{.id = 1, .hubId = 0xabcdef00};
+  int32_t version = 5;
+  EndpointInfo info =
+      HalClient::EndpointInfoBuilder(endpointId, "versioned endpoint")
+          .setVersion(version)
+          .build();
+  EXPECT_EQ(info.id, endpointId);
+  EXPECT_EQ(info.name, "versioned endpoint");
+  EXPECT_EQ(info.version, version);
+}
+
+TEST(HalClientTest, EndpointInfoBuilderSetTag) {
+  auto endpointId = EndpointId{.id = 1, .hubId = 0xabcdef00};
+  std::string tag = "my_special_tag";
+  EndpointInfo info =
+      HalClient::EndpointInfoBuilder(endpointId, "tagged endpoint")
+          .setTag(tag)
+          .build();
+  EXPECT_EQ(info.id, endpointId);
+  EXPECT_EQ(info.name, "tagged endpoint");
+  EXPECT_EQ(info.tag.value(), tag);
+}
+
+TEST(HalClientTest, EndpointInfoBuilderAddPermission) {
+  auto endpointId = EndpointId{.id = 1, .hubId = 0xabcdef00};
+  std::string perm1 = "android.permission.LOCATION";
+  std::string perm2 = "android.permission.WIFI";
+  EndpointInfo info =
+      HalClient::EndpointInfoBuilder(endpointId, "secure endpoint")
+          .addRequiredPermission(perm1)
+          .addRequiredPermission(perm2)
+          .build();
+  EXPECT_EQ(info.id, endpointId);
+  EXPECT_EQ(info.name, "secure endpoint");
+  EXPECT_THAT(info.requiredPermissions, ElementsAre(perm1, perm2));
+}
+
+TEST(HalClientTest, EndpointInfoBuilderAddService) {
+  auto endpointId = EndpointId{.id = 1, .hubId = 0xabcdef00};
+  Service service1 = {.serviceDescriptor = "svc1"};
+  Service service2 = {.serviceDescriptor = "svc2"};
+  EndpointInfo info =
+      HalClient::EndpointInfoBuilder(endpointId, "service endpoint")
+          .addService(service1)
+          .addService(service2)
+          .build();
+  EXPECT_EQ(info.id, endpointId);
+  EXPECT_EQ(info.name, "service endpoint");
+  EXPECT_THAT(info.services,
+              ElementsAre(Field(&Service::serviceDescriptor, "svc1"),
+                          Field(&Service::serviceDescriptor, "svc2")));
+}
+
+TEST(HalClientTest, EndpointInfoBuilderAllFields) {
+  auto endpointId = EndpointId{.id = 1, .hubId = 0xabcdef00};
+  int32_t version = 3;
+  std::string tag = "full_tag";
+  std::string perm1 = "android.permission.BLUETOOTH";
+  Service service1 = {.serviceDescriptor = "svc1", .majorVersion = 1};
+
+  EndpointInfo info =
+      HalClient::EndpointInfoBuilder(endpointId, "full endpoint")
+          .setVersion(version)
+          .setTag(tag)
+          .addRequiredPermission(perm1)
+          .addService(service1)
+          .build();
+
+  EXPECT_EQ(info.id, endpointId);
+  EXPECT_EQ(info.name, "full endpoint");
+  EXPECT_EQ(info.type, EndpointInfo::EndpointType::NATIVE);  // Still default
+  EXPECT_EQ(info.version, version);
+  EXPECT_EQ(info.tag.value(), tag);
+  EXPECT_THAT(info.requiredPermissions, ElementsAre(perm1));
+  EXPECT_THAT(info.services,
+              ElementsAre(Field(&Service::serviceDescriptor, "svc1")));
+  EXPECT_THAT(info.services, ElementsAre(Field(&Service::majorVersion, 1)));
+}
 }  // namespace android::chre
diff --git a/host/test/hal_generic/common/message_hub_manager_test.cc b/host/test/hal_generic/common/message_hub_manager_test.cc
index 15e29390..6b8d23d8 100644
--- a/host/test/hal_generic/common/message_hub_manager_test.cc
+++ b/host/test/hal_generic/common/message_hub_manager_test.cc
@@ -113,7 +113,7 @@ const HubInfo kHub1Info{.hubId = kHub1Id};
 const HubInfo kHub2Info{.hubId = kHub2Id};
 const Service kTestService{.serviceDescriptor = kTestServiceDescriptor};
 const EndpointInfo kEndpoint1_1Info{
-    .id = {.id = kEndpoint1Id, .hubId = kHub1Id}};
+    .id = {.id = kEndpoint1Id, .hubId = kHub1Id}, .name = "endpoint1_1"};
 const EndpointInfo kEndpoint1_2Info{
     .id = {.id = kEndpoint2Id, .hubId = kHub1Id}, .services = {kTestService}};
 const EndpointInfo kEndpoint2_1Info{
@@ -371,14 +371,26 @@ TEST_F(MessageHubManagerTest, AddAndRemoveHostEndpoint) {
   EXPECT_THAT(mHostHub->getEndpoints(), IsEmpty());
 }
 
-TEST_F(MessageHubManagerTest, AddDuplicateEndpoint) {
+TEST_F(MessageHubManagerTest, AddDuplicateEndpointId) {
   mHostHubCb = SharedRefBase::make<MockEndpointCallback>();
   mHostHub = *mManager->createHostHub(mHostHubCb, kHub1Info, 0, 0);
   ASSERT_TRUE(mHostHub->addEndpoint(kEndpoint1_1Info).ok());
+  EndpointInfo duplicate = kEndpoint1_1Info;
+  duplicate.name = "notEndpoint1_1";
+  EXPECT_EQ(mHostHub->addEndpoint(duplicate), pw::Status::AlreadyExists());
   EXPECT_EQ(mHostHub->addEndpoint(kEndpoint1_1Info),
             pw::Status::AlreadyExists());
 }
 
+TEST_F(MessageHubManagerTest, AddDuplicateEndpointName) {
+  mHostHubCb = SharedRefBase::make<MockEndpointCallback>();
+  mHostHub = *mManager->createHostHub(mHostHubCb, kHub1Info, 0, 0);
+  ASSERT_TRUE(mHostHub->addEndpoint(kEndpoint1_1Info).ok());
+  EndpointInfo duplicate = kEndpoint1_1Info;
+  duplicate.id.id++;
+  EXPECT_EQ(mHostHub->addEndpoint(duplicate), pw::Status::AlreadyExists());
+}
+
 TEST_F(MessageHubManagerTest, RemoveNonexistentEndpoint) {
   mHostHubCb = SharedRefBase::make<MockEndpointCallback>();
   mHostHub = *mManager->createHostHub(mHostHubCb, kHub1Info, 0, 0);
diff --git a/host/tinysys/hal/Android.bp b/host/tinysys/hal/Android.bp
index ba1e970d..5dd383d2 100644
--- a/host/tinysys/hal/Android.bp
+++ b/host/tinysys/hal/Android.bp
@@ -48,6 +48,7 @@ cc_binary {
         "libpower",
     ],
     static_libs: [
+        "pw_base64",
         "pw_detokenizer",
         "pw_polyfill",
         "pw_span",
diff --git a/host/tinysys/hal/tinysys_chre_connection.cc b/host/tinysys/hal/tinysys_chre_connection.cc
index 777596f5..dcac2433 100644
--- a/host/tinysys/hal/tinysys_chre_connection.cc
+++ b/host/tinysys/hal/tinysys_chre_connection.cc
@@ -66,6 +66,8 @@ unsigned getRequestCode(ChreState chreState) {
       assert(false);
   }
 }
+
+constexpr std::chrono::milliseconds kMessageHandlingTimeThreshold{1000};
 }  // namespace
 
 bool TinysysChreConnection::init() {
@@ -82,8 +84,10 @@ bool TinysysChreConnection::init() {
   }
   // launch the tasks
   mMessageListener = std::thread(messageListenerTask, this);
+  mMessageHandler = std::thread(messageHandlerTask, this);
   mMessageSender = std::thread(messageSenderTask, this);
   mStateListener = std::thread(chreStateMonitorTask, this);
+
   mLpmaHandler.init();
   return true;
 }
@@ -107,12 +111,22 @@ bool TinysysChreConnection::init() {
              payloadSize, errno);
         continue;
       }
-      handleMessageFromChre(chreConnection, chreConnection->mPayload.get(),
-                            payloadSize);
+      chreConnection->mReceivingQueue.emplace(chreConnection->mPayload.get(),
+                                              payloadSize);
     }
   }
 }
 
+void TinysysChreConnection::messageHandlerTask(
+    TinysysChreConnection *chreConnection) {
+  while (true) {
+    chreConnection->mReceivingQueue.waitForMessage();
+    MessageFromChre &message = chreConnection->mReceivingQueue.front();
+    handleMessageFromChre(chreConnection, message.buffer.get(), message.size);
+    chreConnection->mReceivingQueue.pop();
+  }
+}
+
 [[noreturn]] void TinysysChreConnection::chreStateMonitorTask(
     TinysysChreConnection *chreConnection) {
   int chreFd = chreConnection->getChreFileDescriptor();
@@ -138,7 +152,7 @@ bool TinysysChreConnection::init() {
           /* timeoutMs= */ std::chrono::milliseconds(10000));
       LOGW("SCP restarted! CHRE recover time: %" PRIu64 "ms.",
            ::android::elapsedRealtime() - startTime);
-      chreConnection->getCallback()->onChreRestarted();
+      chreConnection->mCallback->onChreRestarted();
     }
     chreCurrentState = chreNextState;
   }
@@ -149,14 +163,14 @@ bool TinysysChreConnection::init() {
   LOGI("Message sender task is launched.");
   int chreFd = chreConnection->getChreFileDescriptor();
   while (true) {
-    chreConnection->mQueue.waitForMessage();
-    ChreConnectionMessage &message = chreConnection->mQueue.front();
+    chreConnection->mSendingQueue.waitForMessage();
+    MessageToChre &message = chreConnection->mSendingQueue.front();
     auto size =
         TEMP_FAILURE_RETRY(write(chreFd, &message, message.getMessageSize()));
     if (size < 0) {
       LOGE("Failed to write to chre file descriptor. errno=%d\n", errno);
     }
-    chreConnection->mQueue.pop();
+    chreConnection->mSendingQueue.pop();
   }
 }
 
@@ -165,7 +179,7 @@ bool TinysysChreConnection::sendMessage(void *data, size_t length) {
     LOGE("length %zu is not within the accepted range.", length);
     return false;
   }
-  return mQueue.emplace(data, length);
+  return mSendingQueue.emplace(data, length);
 }
 
 void TinysysChreConnection::handleMessageFromChre(
@@ -173,6 +187,7 @@ void TinysysChreConnection::handleMessageFromChre(
     size_t messageLen) {
   // TODO(b/267188769): Move the wake lock acquisition/release to RAII
   // pattern.
+  int64_t startTime = ::android::elapsedRealtime();
   bool isWakelockAcquired =
       acquire_wake_lock(PARTIAL_WAKE_LOCK, kWakeLock) == 0;
   if (!isWakelockAcquired) {
@@ -185,18 +200,18 @@ void TinysysChreConnection::handleMessageFromChre(
   if (!HostProtocolHost::extractHostClientIdAndType(
           messageBuffer, messageLen, &hostClientId, &messageType)) {
     LOGW("Failed to extract host client ID from message - sending broadcast");
-    hostClientId = ::chre::kHostClientIdUnspecified;
+    hostClientId = chre::kHostClientIdUnspecified;
   }
   LOGV("Received a message (type: %hhu, len: %zu) from CHRE for client %d",
        messageType, messageLen, hostClientId);
 
   switch (messageType) {
     case fbs::ChreMessage::LowPowerMicAccessRequest: {
-      chreConnection->getLpmaHandler()->enable(/* enabled= */ true);
+      chreConnection->mLpmaHandler.enable(/* enabled= */ true);
       break;
     }
     case fbs::ChreMessage::LowPowerMicAccessRelease: {
-      chreConnection->getLpmaHandler()->enable(/* enabled= */ false);
+      chreConnection->mLpmaHandler.enable(/* enabled= */ false);
       break;
     }
     case fbs::ChreMessage::PulseResponse: {
@@ -211,8 +226,8 @@ void TinysysChreConnection::handleMessageFromChre(
       break;
     }
     default: {
-      chreConnection->getCallback()->handleMessageFromChre(messageBuffer,
-                                                           messageLen);
+      chreConnection->mCallback->handleMessageFromChre(messageBuffer,
+                                                       messageLen);
       break;
     }
   }
@@ -223,5 +238,11 @@ void TinysysChreConnection::handleMessageFromChre(
       LOGV("The wake lock is released after handling a message.");
     }
   }
+  int64_t durationMs = ::android::elapsedRealtime() - startTime;
+  if (durationMs > kMessageHandlingTimeThreshold.count()) {
+    LOGW("It takes %" PRIu64 "ms to handle a message with ClientId=%" PRIu16
+         " Type=%" PRIu8,
+         durationMs, hostClientId, static_cast<uint8_t>(messageType));
+  }
 }
 }  // namespace aidl::android::hardware::contexthub
diff --git a/host/tinysys/hal/tinysys_chre_connection.h b/host/tinysys/hal/tinysys_chre_connection.h
index 5c771b49..89da12eb 100644
--- a/host/tinysys/hal/tinysys_chre_connection.h
+++ b/host/tinysys/hal/tinysys_chre_connection.h
@@ -19,7 +19,6 @@
 
 #include "chre_connection.h"
 #include "chre_connection_callback.h"
-#include "chre_host/fragmented_load_transaction.h"
 #include "chre_host/host_protocol_host.h"
 #include "chre_host/log.h"
 #include "chre_host/log_message_parser.h"
@@ -31,7 +30,7 @@
 #include <queue>
 #include <thread>
 
-using ::android::chre::StHalLpmaHandler;
+using android::chre::StHalLpmaHandler;
 
 namespace aidl::android::hardware::contexthub {
 
@@ -42,10 +41,10 @@ using ::android::chre::HostProtocolHost;
 // TODO(b/267188769): We should add comments explaining how IPI works.
 class TinysysChreConnection : public ChreConnection {
  public:
-  TinysysChreConnection(ChreConnectionCallback *callback)
+  explicit TinysysChreConnection(ChreConnectionCallback *callback)
       : mCallback(callback), mLpmaHandler(/* allowed= */ true) {
     mPayload = std::make_unique<uint8_t[]>(kMaxReceivingPayloadBytes);
-  };
+  }
 
   ~TinysysChreConnection() override {
     // TODO(b/264308286): Need a decent way to terminate the listener thread.
@@ -53,6 +52,9 @@ class TinysysChreConnection : public ChreConnection {
     if (mMessageListener.joinable()) {
       mMessageListener.join();
     }
+    if (mMessageHandler.joinable()) {
+      mMessageHandler.join();
+    }
     if (mMessageSender.joinable()) {
       mMessageSender.join();
     }
@@ -73,7 +75,7 @@ class TinysysChreConnection : public ChreConnection {
     flatbuffers::FlatBufferBuilder builder(48);
     HostProtocolHost::encodePulseRequest(builder);
 
-    std::unique_lock<std::mutex> lock(mChrePulseMutex);
+    std::unique_lock lock(mChrePulseMutex);
     // reset mIsChreRecovered before sending a PulseRequest message
     mIsChreBackOnline = false;
     sendMessage(builder.GetBufferPointer(), builder.GetSize());
@@ -84,20 +86,12 @@ class TinysysChreConnection : public ChreConnection {
 
   void notifyChreBackOnline() {
     {
-      std::unique_lock<std::mutex> lock(mChrePulseMutex);
+      std::unique_lock lock(mChrePulseMutex);
       mIsChreBackOnline = true;
     }
     mChrePulseCondition.notify_all();
   }
 
-  inline ChreConnectionCallback *getCallback() {
-    return mCallback;
-  }
-
-  inline StHalLpmaHandler *getLpmaHandler() {
-    return &mLpmaHandler;
-  }
-
  private:
   // The wakelock used to keep device awake while handleUsfMsgAsync() is being
   // called.
@@ -115,36 +109,48 @@ class TinysysChreConnection : public ChreConnection {
   // The path to CHRE file descriptor
   static constexpr char kChreFileDescriptorPath[] = "/dev/scp_chre_manager";
 
-  // Max queue size for sending messages to CHRE
-  static constexpr size_t kMaxSynchronousMessageQueueSize = 64;
-
   // Wrapper for a message sent to CHRE
-  struct ChreConnectionMessage {
+  struct MessageToChre {
     // This magic number is the SCP_CHRE_MAGIC constant defined by kernel
     // scp_chre_manager service. The value is embedded in the payload as a
     // security check for proper use of the device node.
     uint32_t magic = 0x67728269;
     uint32_t payloadSize = 0;
-    uint8_t payload[kMaxSendingPayloadBytes];
+    uint8_t payload[kMaxSendingPayloadBytes]{};
 
-    ChreConnectionMessage(void *data, size_t length) {
+    MessageToChre(void *data, size_t length) {
       assert(length <= kMaxSendingPayloadBytes);
       memcpy(payload, data, length);
       payloadSize = static_cast<uint32_t>(length);
     }
 
-    uint32_t getMessageSize() {
+    [[nodiscard]] uint32_t getMessageSize() const {
       return sizeof(magic) + sizeof(payloadSize) + payloadSize;
     }
   };
 
+  // Wrapper for a message from CHRE
+  struct MessageFromChre {
+    std::unique_ptr<uint8_t[]> buffer;
+    size_t size;
+
+    MessageFromChre(void *data, ssize_t length) {
+      buffer = std::make_unique<uint8_t[]>(length);
+      memcpy(buffer.get(), data, length);
+      size = length;
+    }
+  };
+
   // A queue suitable for multiple producers and a single consumer.
+  template <typename ElementType>
   class SynchronousMessageQueue {
    public:
+    explicit SynchronousMessageQueue(size_t capacity) : mCapacity(capacity) {}
+
     bool emplace(void *data, size_t length) {
-      std::unique_lock<std::mutex> lock(mMutex);
-      if (mQueue.size() >= kMaxSynchronousMessageQueueSize) {
-        LOGE("Message queue from HAL to CHRE is full!");
+      std::unique_lock lock(mMutex);
+      if (mQueue.size() >= mCapacity) {
+        LOGE("Message queue is full!");
         return false;
       }
       mQueue.emplace(data, length);
@@ -153,30 +159,39 @@ class TinysysChreConnection : public ChreConnection {
     }
 
     void pop() {
-      std::unique_lock<std::mutex> lock(mMutex);
+      std::unique_lock lock(mMutex);
       mQueue.pop();
     }
 
-    ChreConnectionMessage &front() {
-      std::unique_lock<std::mutex> lock(mMutex);
+    ElementType &front() {
+      std::unique_lock lock(mMutex);
       return mQueue.front();
     }
 
     void waitForMessage() {
-      std::unique_lock<std::mutex> lock(mMutex);
-      mCv.wait(lock, [&]() { return !mQueue.empty(); });
+      std::unique_lock lock(mMutex);
+      mCv.wait(lock, [&] { return !mQueue.empty(); });
+    }
+
+    size_t size() {
+      return mQueue.size();
     }
 
    private:
+    const size_t mCapacity;
     std::mutex mMutex;
     std::condition_variable mCv;
-    std::queue<ChreConnectionMessage> mQueue;
+    std::queue<ElementType> mQueue;
   };
 
   // The task receiving message from CHRE
   [[noreturn]] static void messageListenerTask(
       TinysysChreConnection *chreConnection);
 
+  // The task handling message from CHRE
+  [[noreturn]] static void messageHandlerTask(
+      TinysysChreConnection *chreConnection);
+
   // The task sending message to CHRE
   [[noreturn]] static void messageSenderTask(
       TinysysChreConnection *chreConnection);
@@ -185,18 +200,20 @@ class TinysysChreConnection : public ChreConnection {
   [[noreturn]] static void chreStateMonitorTask(
       TinysysChreConnection *chreConnection);
 
-  [[nodiscard]] inline int getChreFileDescriptor() const {
+  [[nodiscard]] int getChreFileDescriptor() const {
     return mChreFileDescriptor;
   }
 
   // The file descriptor for communication with CHRE
-  int mChreFileDescriptor;
+  int mChreFileDescriptor = 0;
 
   // The calback function that should be implemented by HAL
   ChreConnectionCallback *mCallback;
 
   // the message listener thread that receives messages from CHRE
   std::thread mMessageListener;
+  // the message handling thread that handles messages from CHRE
+  std::thread mMessageHandler;
   // the message sender thread that sends messages to CHRE
   std::thread mMessageSender;
   // the status listener thread that hosts chreStateMonitorTask
@@ -208,8 +225,10 @@ class TinysysChreConnection : public ChreConnection {
   // The LPMA handler to talk to the ST HAL
   StHalLpmaHandler mLpmaHandler;
 
-  // For messages sent to CHRE
-  SynchronousMessageQueue mQueue;
+  // Queues for sending to and receiving messages from CHRE, with heuristic
+  // capacity size.
+  SynchronousMessageQueue<MessageToChre> mSendingQueue{/* capacity= */ 64};
+  SynchronousMessageQueue<MessageFromChre> mReceivingQueue{/* capacity= */ 256};
 
   // Mutex and CV are used to get PulseResponse from CHRE synchronously.
   std::mutex mChrePulseMutex;
diff --git a/host/tools/Android.bp b/host/tools/Android.bp
new file mode 100644
index 00000000..54f29224
--- /dev/null
+++ b/host/tools/Android.bp
@@ -0,0 +1,51 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package {
+    default_team: "trendy_team_context_hub",
+    default_applicable_licenses: ["system_chre_license"],
+}
+
+cc_binary {
+    name: "chre_aidl_hal_client",
+    vendor: true,
+    cpp_std: "c++20",
+    header_libs: [
+        "chre_api",
+    ],
+    srcs: [
+        "chre_aidl_hal_client/*.cc",
+    ],
+    shared_libs: [
+        "android.hardware.contexthub-V4-ndk",
+        "libbase",
+        "libbinder_ndk",
+        "libjsoncpp",
+        "liblog",
+        "libutils",
+    ],
+    static_libs: [
+        "chre_client",
+        "chre_host_common",
+        "chre_host_util",
+    ],
+    cflags: [
+        "-DLOG_TAG=\"CHRE.HAL.CLIENT\"",
+        "-Wall",
+        "-Werror",
+        "-fexceptions",
+    ],
+}
diff --git a/host/tools/chre_aidl_hal_client/command_handlers.cc b/host/tools/chre_aidl_hal_client/command_handlers.cc
new file mode 100644
index 00000000..f5b92186
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/command_handlers.cc
@@ -0,0 +1,410 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "command_handlers.h"
+#include "context_hub_callback.h"
+#include "nanoapp_helper.h"
+#include "utils.h"
+
+#include <aidl/android/hardware/contexthub/BnContextHubCallback.h>
+#include <aidl/android/hardware/contexthub/IContextHub.h>
+#include <aidl/android/hardware/contexthub/NanoappBinary.h>
+#include <android/binder_manager.h>
+#include <android/binder_process.h>
+
+#include <future>
+#include <stdexcept>
+#include <string>
+#include <vector>
+
+#include "chre_host/file_stream.h"
+#include "chre_host/hal_client.h"
+#include "chre_host/log.h"
+#include "chre_host/napp_header.h"
+#include "endpoint_callback.h"
+
+namespace android::chre::chre_aidl_hal_client {
+
+using chre::HalClient;
+using chre::NanoAppBinaryHeader;
+using chre::readFileContents;
+
+using aidl::android::hardware::contexthub::AsyncEventType;
+using aidl::android::hardware::contexthub::BnContextHubCallback;
+using aidl::android::hardware::contexthub::ContextHubInfo;
+using aidl::android::hardware::contexthub::ContextHubMessage;
+using aidl::android::hardware::contexthub::HostEndpointInfo;
+using aidl::android::hardware::contexthub::IContextHub;
+using aidl::android::hardware::contexthub::MessageDeliveryStatus;
+using aidl::android::hardware::contexthub::NanoappBinary;
+using aidl::android::hardware::contexthub::NanoappInfo;
+using aidl::android::hardware::contexthub::NanSessionRequest;
+using aidl::android::hardware::contexthub::Setting;
+using internal::ToString;
+using ndk::ScopedAStatus;
+
+std::shared_ptr<IContextHub> gContextHub = nullptr;
+std::shared_ptr<ContextHubCallback> gCallback = nullptr;
+
+// Session based messaging related variables.
+std::shared_ptr<IEndpointCallback> gEndpointCallback = nullptr;
+std::shared_ptr<IEndpointCommunication> gCommunication = nullptr;
+
+void registerHostCallback() {
+  if (gCallback != nullptr) {
+    gCallback.reset();
+  }
+  gCallback = ContextHubCallback::make<ContextHubCallback>();
+  if (!gContextHub->registerCallback(kContextHubId, gCallback).isOk()) {
+    throwError("Failed to register the callback");
+  }
+}
+
+/** Initializes gContextHub and register gCallback. */
+std::shared_ptr<IContextHub> getContextHub() {
+  if (gContextHub == nullptr) {
+    const auto aidlServiceName =
+        std::string() + IContextHub::descriptor + "/default";
+    ndk::SpAIBinder binder(
+        AServiceManager_waitForService(aidlServiceName.c_str()));
+    if (binder.get() == nullptr) {
+      throwError("Could not find Context Hub HAL");
+    }
+    gContextHub = IContextHub::fromBinder(binder);
+  }
+  if (gCallback == nullptr) {
+    registerHostCallback();
+  }
+  return gContextHub;
+}
+
+void verifyStatus(const std::string &operation, const ScopedAStatus &status) {
+  if (!status.isOk()) {
+    gCallback->resetPromise();
+    throwError(operation + " fails with abnormal status " +
+               ToString(status.getMessage()) + " error code " +
+               ToString(status.getServiceSpecificError()));
+  }
+}
+
+void verifyStatusAndSignal(const std::string &operation,
+                           const ScopedAStatus &status,
+                           const std::future<void> &future_signal) {
+  verifyStatus(operation, status);
+  std::future_status future_status =
+      future_signal.wait_for(kTimeOutThresholdInSec);
+  if (future_status != std::future_status::ready) {
+    gCallback->resetPromise();
+    throwError(operation + " doesn't finish within " +
+               ToString(kTimeOutThresholdInSec.count()) + " seconds");
+  }
+}
+
+void getAllHubs() {
+  std::vector<HubInfo> hubs{};
+  if (const auto status = getContextHub()->getHubs(&hubs); !status.isOk()) {
+    std::cerr << "Failed to get hubs: " << status.getMessage() << std::endl;
+    return;
+  }
+  if (hubs.empty()) {
+    std::cerr << "No hubs found" << std::endl;
+    return;
+  }
+  for (const auto &[hubId, hubDetails] : hubs) {
+    std::cout << "Hub id: 0x" << std::hex << hubId << " "
+              << hubDetails.toString() << std::endl;
+  }
+}
+
+void getAllEndpoints() {
+  std::vector<EndpointInfo> endpoints{};
+  if (const auto status = getContextHub()->getEndpoints(&endpoints);
+      !status.isOk()) {
+    std::cerr << "Failed to get endpoints: " << status.getMessage()
+              << std::endl;
+    return;
+  }
+  EndpointHelper::printEndpoints(endpoints);
+}
+
+void getAllContextHubs() {
+  std::vector<ContextHubInfo> hubs{};
+  getContextHub()->getContextHubs(&hubs);
+  if (hubs.empty()) {
+    std::cerr << "Failed to get any context hub." << std::endl;
+    return;
+  }
+  for (const auto &hub : hubs) {
+    std::cout << "Context Hub " << hub.id << ": " << std::endl
+              << "  Name: " << hub.name << std::endl
+              << "  Vendor: " << hub.vendor << std::endl
+              << "  Max support message length (bytes): "
+              << hub.maxSupportedMessageLengthBytes << std::endl
+              << "  Version: " << static_cast<uint32_t>(hub.chreApiMajorVersion)
+              << "." << static_cast<uint32_t>(hub.chreApiMinorVersion)
+              << std::endl
+              << "  Chre platform id: 0x" << std::hex << hub.chrePlatformId
+              << std::endl;
+  }
+}
+
+void loadNanoapp(std::string &pathAndName) {
+  std::unique_ptr<NanoAppBinaryHeader> header =
+      NanoappHelper::findHeaderAndNormalizePath(pathAndName);
+  std::vector<uint8_t> soBuffer{};
+  if (!readFileContents(pathAndName.c_str(), soBuffer)) {
+    throwError("Failed to open the content of " + pathAndName);
+  }
+  NanoappBinary binary;
+  binary.nanoappId = static_cast<int64_t>(header->appId);
+  binary.customBinary = soBuffer;
+  binary.flags = static_cast<int32_t>(header->flags);
+  binary.targetChreApiMajorVersion =
+      static_cast<int8_t>(header->targetChreApiMajorVersion);
+  binary.targetChreApiMinorVersion =
+      static_cast<int8_t>(header->targetChreApiMinorVersion);
+  binary.nanoappVersion = static_cast<int32_t>(header->appVersion);
+
+  auto status =
+      getContextHub()->loadNanoapp(kContextHubId, binary, kLoadTransactionId);
+  verifyStatusAndSignal(/* operation= */ "loading nanoapp " + pathAndName,
+                        status, gCallback->promise.get_future());
+}
+
+void unloadNanoapp(std::string &appIdOrName) {
+  auto appId = NanoappHelper::getNanoappIdFrom(appIdOrName);
+  auto status = getContextHub()->unloadNanoapp(kContextHubId, appId,
+                                               kUnloadTransactionId);
+  verifyStatusAndSignal(/* operation= */ "unloading nanoapp " + appIdOrName,
+                        status, gCallback->promise.get_future());
+}
+
+void queryNanoapps() {
+  auto status = getContextHub()->queryNanoapps(kContextHubId);
+  verifyStatusAndSignal(/* operation= */ "querying nanoapps", status,
+                        gCallback->promise.get_future());
+}
+
+HostEndpointInfo createHostEndpointInfo(const std::string &hexEndpointId) {
+  char16_t hostEndpointId = verifyAndConvertEndpointHexId(hexEndpointId);
+  return {
+      .hostEndpointId = hostEndpointId,
+      .type = HostEndpointInfo::Type::NATIVE,
+      .packageName = "chre_aidl_hal_client",
+      .attributionTag{},
+  };
+}
+
+void onEndpointConnected(const std::string &hexEndpointId) {
+  auto contextHub = getContextHub();
+  HostEndpointInfo info = createHostEndpointInfo(hexEndpointId);
+  // connect the endpoint to HAL
+  verifyStatus(/* operation= */ "connect endpoint",
+               contextHub->onHostEndpointConnected(info));
+  std::cout << "Connected." << std::endl;
+}
+
+void onEndpointDisconnected(const std::string &hexEndpointId) {
+  auto contextHub = getContextHub();
+  uint16_t hostEndpointId = verifyAndConvertEndpointHexId(hexEndpointId);
+  // disconnect the endpoint from HAL
+  verifyStatus(/* operation= */ "disconnect endpoint",
+               contextHub->onHostEndpointDisconnected(hostEndpointId));
+  std::cout << "Disconnected." << std::endl;
+}
+
+ContextHubMessage createContextHubMessage(const std::string &hexHostEndpointId,
+                                          std::string &appIdOrName,
+                                          const std::string &hexPayload) {
+  if (!isValidHexNumber(hexPayload)) {
+    throwError("Invalid hex payload.");
+  }
+  int64_t appId = NanoappHelper::getNanoappIdFrom(appIdOrName);
+  char16_t hostEndpointId = verifyAndConvertEndpointHexId(hexHostEndpointId);
+  ContextHubMessage contextHubMessage = {
+      .nanoappId = appId,
+      .hostEndPoint = hostEndpointId,
+      .messageBody = {},
+      .permissions = {},
+  };
+  // populate the payload
+  for (int i = 2; i < hexPayload.size(); i += 2) {
+    contextHubMessage.messageBody.push_back(
+        std::stoi(hexPayload.substr(i, 2), /* idx= */ nullptr, /* base= */ 16));
+  }
+  return contextHubMessage;
+}
+
+/** Sends a hexPayload from hexHostEndpointId to appIdOrName. */
+void sendMessageToNanoapp(const std::string &hexHostEndpointId,
+                          std::string &appIdOrName,
+                          const std::string &hexPayload) {
+  ContextHubMessage contextHubMessage =
+      createContextHubMessage(hexHostEndpointId, appIdOrName, hexPayload);
+  // send the message
+  auto contextHub = getContextHub();
+  auto status = contextHub->sendMessageToHub(kContextHubId, contextHubMessage);
+  verifyStatusAndSignal(/* operation= */ "sending a message to " + appIdOrName,
+                        status, gCallback->promise.get_future());
+}
+
+void changeSetting(const std::string &setting, bool enabled) {
+  auto contextHub = getContextHub();
+  int settingType = std::stoi(setting);
+  if (settingType < 1 || settingType > 7) {
+    throwError("setting type must be within [1, 7].");
+  }
+  ScopedAStatus status =
+      contextHub->onSettingChanged(static_cast<Setting>(settingType), enabled);
+  std::cout << "onSettingChanged is called to "
+            << (enabled ? "enable" : "disable") << " setting type "
+            << settingType << std::endl;
+  verifyStatus("change setting", status);
+}
+
+void enableTestModeOnContextHub() {
+  auto status = getContextHub()->setTestMode(/* in_enable= */ true);
+  verifyStatus(/* operation= */ "enabling test mode", status);
+  std::cout << "Test mode is enabled" << std::endl;
+}
+
+void disableTestModeOnContextHub() {
+  auto status = getContextHub()->setTestMode(/* in_enable= */ false);
+  verifyStatus(/* operation= */ "disabling test mode", status);
+  std::cout << "Test mode is disabled" << std::endl;
+}
+
+void getAllPreloadedNanoappIds() {
+  std::vector<int64_t> appIds{};
+  verifyStatus("get preloaded nanoapp ids",
+               getContextHub()->getPreloadedNanoappIds(kContextHubId, &appIds));
+  for (const auto &appId : appIds) {
+    std::cout << "0x" << std::hex << appId << std::endl;
+  }
+}
+
+void executeHalClientCommand(HalClient *halClient,
+                             const std::vector<std::string> &cmdLine) {
+  if (auto func = CommandHelper::parseCommand(cmdLine, kHalClientCommands)) {
+    try {
+      func(halClient, cmdLine);
+    } catch (std::system_error &e) {
+      std::cerr << e.what() << std::endl;
+    }
+  } else {
+    CommandHelper::printUsage(kHalClientCommands);
+  }
+}
+
+void connectToHal() {
+  if (gCallback == nullptr) {
+    gCallback = ContextHubCallback::make<ContextHubCallback>();
+  }
+  std::unique_ptr<HalClient> halClient = HalClient::create(gCallback);
+  if (halClient == nullptr || !halClient->connect()) {
+    LOGE("Failed to init the connection to HAL.");
+    return;
+  }
+
+  while (true) {
+    auto cmdLine = CommandHelper::getCommandLine();
+    if (cmdLine.empty()) {
+      continue;
+    }
+    executeHalClientCommand(halClient.get(), cmdLine);
+  }
+}
+
+void halClientConnectEndpoint(HalClient *halClient,
+                              const std::string &hexEndpointId) {
+  HostEndpointInfo info = createHostEndpointInfo(hexEndpointId);
+  verifyStatus(/* operation= */ "connect endpoint",
+               halClient->connectEndpoint(info));
+}
+
+void halClientDisconnectEndpoint(HalClient *halClient,
+                                 const std::string &hexEndpointId) {
+  uint16_t hostEndpointId = verifyAndConvertEndpointHexId(hexEndpointId);
+  verifyStatus(/* operation= */ "disconnect endpoint",
+               halClient->disconnectEndpoint(hostEndpointId));
+}
+
+void halClientGetEndpoints(HalClient *halClient) {
+  std::vector<EndpointInfo> endpoints{};
+  verifyStatus(/* operation= */ "get session-based endpoints",
+               halClient->getEndpoints(&endpoints));
+  EndpointHelper::printEndpoints(endpoints);
+}
+
+void halClientGetHubs(HalClient *halClient) {
+  std::vector<HubInfo> hubs{};
+  verifyStatus(/*operation= */ "Get session-based hubs",
+               halClient->getHubs(&hubs));
+  if (hubs.empty()) {
+    std::cerr << "No hubs found" << std::endl;
+    return;
+  }
+  for (const auto &[hubId, hubDetails] : hubs) {
+    std::cout << "Hub id: 0x" << std::hex << hubId << " "
+              << hubDetails.toString() << std::endl;
+  }
+}
+
+void halClientQuery(HalClient *halClient) {
+  verifyStatusAndSignal(/* operation= */ "querying nanoapps",
+                        halClient->queryNanoapps(),
+                        gCallback->promise.get_future());
+}
+
+void halClientSendMessage(HalClient *halClient,
+                          const std::vector<std::string> &cmdLine) {
+  std::string appIdOrName = cmdLine[2];
+  ContextHubMessage message = createContextHubMessage(
+      /* hexHostEndpointId= */ cmdLine[1], appIdOrName,
+      /* hexPayload= */ cmdLine[3]);
+  verifyStatusAndSignal(
+      /* operation= */ "sending a message to " + cmdLine[2],
+      halClient->sendMessage(message), gCallback->promise.get_future());
+}
+
+void halClientRegisterHub(HalClient *halClient) {
+  gEndpointCallback = EndpointCallback::make<EndpointCallback>();
+  verifyStatus(/* operation= */ "register an endpoint hub",
+               halClient->registerEndpointHub(gEndpointCallback, kHubInfo,
+                                              &gCommunication));
+}
+
+std::vector<std::string> CommandHelper::getCommandLine() {
+  std::string input;
+  std::cout << "> ";
+  std::getline(std::cin, input);
+  input.push_back('\n');
+  std::vector<std::string> result{};
+  for (int begin = 0, end = 0; end < input.size();) {
+    if (isspace(input[begin])) {
+      end = begin = begin + 1;
+      continue;
+    }
+    if (!isspace(input[end])) {
+      end += 1;
+      continue;
+    }
+    result.push_back(input.substr(begin, end - begin));
+    begin = end;
+  }
+  return result;
+}
+}  // namespace android::chre::chre_aidl_hal_client
\ No newline at end of file
diff --git a/host/tools/chre_aidl_hal_client/command_handlers.h b/host/tools/chre_aidl_hal_client/command_handlers.h
new file mode 100644
index 00000000..e98bc576
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/command_handlers.h
@@ -0,0 +1,424 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef ANDROID_CHRE_AIDL_HAL_CLIENT_COMMANDS_H
+#define ANDROID_CHRE_AIDL_HAL_CLIENT_COMMANDS_H
+
+#include "nanoapp_helper.h"
+
+#include <sys/types.h>
+#include <functional>
+#include <iostream>
+#include <string>
+#include <vector>
+
+#include "chre_host/hal_client.h"
+
+namespace android::chre::chre_aidl_hal_client {
+
+/** Handlers that run directly after connecting to HAL. */
+void onEndpointConnected(const std::string &hexEndpointId);
+void changeSetting(const std::string &setting, bool enabled);
+void disableTestModeOnContextHub();
+void onEndpointDisconnected(const std::string &hexEndpointId);
+void enableTestModeOnContextHub();
+void getAllEndpoints();
+void getAllContextHubs();
+void getAllHubs();
+void getAllPreloadedNanoappIds();
+void loadNanoapp(std::string &pathAndName);
+void queryNanoapps();
+void registerHostCallback();
+void sendMessageToNanoapp(const std::string &hexHostEndpointId,
+                          std::string &appIdOrName,
+                          const std::string &hexPayload);
+void unloadNanoapp(std::string &appIdOrName);
+
+/** The handler that connects to HAL using hal_client library. */
+void connectToHal();
+
+/** Handlers for commands that can only be run after connecting to HAL. */
+void halClientConnectEndpoint(HalClient *halClient,
+                              const std::string &hexEndpointId);
+void halClientDisconnectEndpoint(HalClient *halClient,
+                                 const std::string &hexEndpointId);
+void halClientGetEndpoints(HalClient *halClient);
+void halClientGetHubs(HalClient *halClient);
+void halClientQuery(HalClient *halClient);
+void halClientRegisterHub(HalClient *halClient);
+void halClientSendMessage(HalClient *halClient,
+                          const std::vector<std::string> &cmdLine);
+
+using DirectCommandFunction =
+    std::function<void(const std::vector<std::string> &)>;
+using HalClientCommandFunction =
+    std::function<void(HalClient *halClient, const std::vector<std::string> &)>;
+
+/** Holds metadata associated with a specific command. */
+template <typename FuncType>
+struct CommandInfo {
+  /** The command string. */
+  std::string cmd;
+
+  /**
+   * Number of arguments expected *after* the command name.
+   * For example, if the command is "load <app_name>", numOfArgs is 1.
+   * If the command is "query", numOfArgs is 0.
+   */
+  u_int8_t numOfArgs;
+
+  /**
+   * A string describing the expected arguments format (e.g.,
+   * "<HEX_ENDPOINT_ID>"). Empty if no arguments are expected.
+   */
+  std::string argsFormat;
+
+  /** A brief description of what the command does. */
+  std::string usage;
+
+  /** The function to execute for this command. */
+  FuncType func;
+};
+
+/**
+ * The commands that can be run directly by chre_aidl_hal_client.
+ *
+ * <p>Please keep Command in alphabetical order.
+ */
+const std::vector<CommandInfo<DirectCommandFunction>> kAllDirectCommands{
+    {.cmd = "connect",
+     .numOfArgs = 0,
+     .argsFormat = "",
+     .usage = "connect to HAL using hal_client library and keep the session "
+              "alive while user can execute other commands. Use 'exit' to "
+              "quit the session.",
+     .func =
+         [](const std::vector<std::string> & /*cmdLine*/) { connectToHal(); }},
+
+    {.cmd = "connectEndpoint",
+     .numOfArgs = 1,
+     .argsFormat = "<HEX_ENDPOINT_ID>",
+     .usage = "associate an endpoint with the current client and notify HAL.",
+     .func =
+         [](const std::vector<std::string> &cmdLine) {
+           onEndpointConnected(cmdLine[1]);
+         }},
+
+    {.cmd = "disableSetting",
+     .numOfArgs = 1,
+     .argsFormat = "<SETTING>",
+     .usage = "disable a setting identified by a number defined in "
+              "android/hardware/contexthub/Setting.aidl.",
+     .func =
+         [](const std::vector<std::string> &cmdLine) {
+           changeSetting(cmdLine[1], /* enabled= */ false);
+         }},
+
+    {.cmd = "disableTestMode",
+     .numOfArgs = 0,
+     .argsFormat = "",
+     .usage = "disable test mode.",
+     .func =
+         [](const std::vector<std::string> & /*cmdLine*/) {
+           disableTestModeOnContextHub();
+         }},
+
+    {.cmd = "disconnectEndpoint",
+     .numOfArgs = 1,
+     .argsFormat = "<HEX_ENDPOINT_ID>",
+     .usage = "remove an endpoint with the current client and notify HAL.",
+     .func =
+         [](const std::vector<std::string> &cmdLine) {
+           onEndpointDisconnected(cmdLine[1]);
+         }},
+
+    {.cmd = "enableSetting",
+     .numOfArgs = 1,
+     .argsFormat = "<SETTING>",
+     .usage = "enable a setting identified by a number defined in "
+              "android/hardware/contexthub/Setting.aidl.",
+     .func =
+         [](const std::vector<std::string> &cmdLine) {
+           changeSetting(cmdLine[1], true);
+         }},
+
+    {.cmd = "enableTestMode",
+     .numOfArgs = 0,
+     .argsFormat = "",
+     .usage = "enable test mode.",
+     .func =
+         [](const std::vector<std::string> & /*cmdLine*/) {
+           enableTestModeOnContextHub();
+         }},
+
+    {.cmd = "getEndpoints",
+     .numOfArgs = 0,
+     .argsFormat = "",
+     .usage = "get all the endpoints used for session-based messaging.",
+     .func =
+         [](const std::vector<std::string> & /*cmdLine*/) {
+           getAllEndpoints();
+         }},
+
+    {.cmd = "getContextHubs",
+     .numOfArgs = 0,
+     .argsFormat = "",
+     .usage = "get all the context hubs.",
+     .func =
+         [](const std::vector<std::string> & /*cmdLine*/) {
+           getAllContextHubs();
+         }},
+
+    {.cmd = "getHubs",
+     .numOfArgs = 0,
+     .argsFormat = "",
+     .usage = "get all the hubs for session-based messaging.",
+     .func =
+         [](const std::vector<std::string> & /*cmdLine*/) { getAllHubs(); }},
+
+    {.cmd = "getPreloadedNanoappIds",
+     .numOfArgs = 0,
+     .argsFormat = "",
+     .usage = "get a list of ids for the preloaded nanoapps.",
+     .func =
+         [](const std::vector<std::string> & /*cmdLine*/) {
+           getAllPreloadedNanoappIds();
+         }},
+
+    {.cmd = "list",
+     .numOfArgs = 1,
+     .argsFormat = "</PATH/TO/NANOAPPS>",
+     .usage = "list all the nanoapps' header info in the path.",
+     .func =
+         [](const std::vector<std::string> &cmdLine) {
+           NanoappHelper::listNanoappsInPath(cmdLine[1]);
+         }},
+
+    {.cmd = "load",
+     .numOfArgs = 1,
+     .argsFormat = "<APP_NAME | /PATH/TO/APP_NAME>",
+     .usage = "load the nanoapp specified by the name. If an absolute path is "
+              "not provided the default locations are searched.",
+     // Need a mutable copy for findHeaderAndNormalizePath
+     .func =
+         [](const std::vector<std::string> &cmdLine) {
+           auto appName = cmdLine[1];
+           loadNanoapp(appName);
+         }},
+
+    {.cmd = "query",
+     .numOfArgs = 0,
+     .argsFormat = "",
+     .usage = "show all loaded nanoapps (system apps excluded).",
+     .func =
+         [](const std::vector<std::string> & /*cmdLine*/) { queryNanoapps(); }},
+
+    {.cmd = "registerCallback",
+     .numOfArgs = 0,
+     .argsFormat = "",
+     .usage = "register a callback for the current client.",
+     .func =
+         [](const std::vector<std::string> & /*cmdLine*/) {
+           registerHostCallback();
+         }},
+
+    {.cmd = "sendMessage",
+     .numOfArgs = 3,
+     .argsFormat = "<HEX_ENDPOINT_ID> <HEX_NANOAPP_ID | APP_NAME | "
+                   "/PATH/TO/APP_NAME> <HEX_PAYLOAD>",
+     .usage = "send a payload to a nanoapp. If an absolute path is not "
+              "provided the default locations are searched.",
+     // Need a mutable copy for getNanoappIdFrom potentially
+     .func =
+         [](const std::vector<std::string> &cmdLine) {
+           auto appIdOrName = cmdLine[2];
+           sendMessageToNanoapp(cmdLine[1], appIdOrName, cmdLine[3]);
+         }},
+
+    {.cmd = "unload",
+     .numOfArgs = 1,
+     .argsFormat = "<HEX_NANOAPP_ID | APP_NAME | /PATH/TO/APP_NAME>",
+     .usage = "unload the nanoapp specified by either the nanoapp id or the "
+              "app name. If an absolute path is not provided the default "
+              "locations are searched.",
+     // Need a mutable copy for getNanoappIdFrom potentially
+     .func =
+         [](const std::vector<std::string> &cmdLine) {
+           auto appIdOrName = cmdLine[1];
+           unloadNanoapp(appIdOrName);
+         }},
+};
+
+/**
+ * The commands that can only be run after connecting to HAL via HalClient,
+ * which is what {@code connect} command does.
+ *
+ * Please keep Command in alphabetical order.
+ */
+const std::vector<CommandInfo<HalClientCommandFunction>> kHalClientCommands{
+    {
+        .cmd = "connectEndpoint",
+        .numOfArgs = 1,
+        .argsFormat = "<HEX_ENDPOINT_ID>",
+        .usage =
+            "associate an endpoint with the current client and notify HAL.",
+        .func =
+            [](HalClient *halClient, const std::vector<std::string> &cmdLine) {
+              halClientConnectEndpoint(halClient, cmdLine[1]);
+            },
+    },
+
+    {
+        .cmd = "disconnectEndpoint",
+        .numOfArgs = 1,
+        .argsFormat = "<HEX_ENDPOINT_ID>",
+        .usage = "remove an endpoint with the current client and notify HAL.",
+        .func =
+            [](HalClient *halClient, const std::vector<std::string> &cmdLine) {
+              halClientDisconnectEndpoint(halClient, cmdLine[1]);
+            },
+    },
+
+    {
+        .cmd = "exit",
+        .numOfArgs = 0,
+        .argsFormat = "",
+        .usage = "Quit the connection mode.",
+        .func = [](HalClient * /*halClient*/,
+                   const std::vector<std::string> & /*cmdLine*/) { exit(0); },
+    },
+
+    {
+        .cmd = "getHubs",
+        .numOfArgs = 0,
+        .argsFormat = "",
+        .usage = "get all the hubs for session-based messaging.",
+        .func =
+            [](HalClient *halClient,
+               const std::vector<std::string> & /*cmdLine*/) {
+              halClientGetHubs(halClient);
+            },
+    },
+
+    {
+        .cmd = "getEndpoints",
+        .numOfArgs = 0,
+        .argsFormat = "",
+        .usage = "get all the endpoints used for session-based messaging.",
+        .func =
+            [](HalClient *halClient,
+               const std::vector<std::string> & /*cmdLine*/) {
+              halClientGetEndpoints(halClient);
+            },
+    },
+
+    {
+        .cmd = "query",
+        .numOfArgs = 0,
+        .argsFormat = "",
+        .usage = "show all loaded nanoapps (system apps excluded).",
+        .func =
+            [](HalClient *halClient,
+               const std::vector<std::string> & /*cmdLine*/) {
+              halClientQuery(halClient);
+            },
+    },
+
+    {
+        .cmd = "registerHub",
+        .numOfArgs = 0,
+        .argsFormat = "",
+        .usage = "register a hub using id and name.",
+        .func =
+            [](HalClient *halClient,
+               const std::vector<std::string> & /*cmdLine*/) {
+              halClientRegisterHub(halClient);
+            },
+    },
+
+    {
+        .cmd = "sendMessage",
+        .numOfArgs = 3,
+        .argsFormat = "<HEX_ENDPOINT_ID> <HEX_NANOAPP_ID | APP_NAME | "
+                      "/PATH/TO/APP_NAME> <HEX_PAYLOAD>",
+        .usage = "send a payload to a nanoapp. If an absolute path is not "
+                 "provided the default locations are searched.",
+        .func =
+            [](HalClient *halClient, const std::vector<std::string> &cmdLine) {
+              halClientSendMessage(halClient, cmdLine);
+            },
+    },
+};
+
+/**
+ * Helper class to manage command definitions and potentially parsing/usage
+ * logic.
+ */
+class CommandHelper {
+ public:
+  CommandHelper() = delete;
+
+  /**
+   * Parses the command line input and finds the matching handler function.
+   *
+   * Checks the command name and the number of arguments.
+   *
+   * @param cmdLine The command line arguments as a vector of strings.
+   * @param supportedCommands A vector of supported CommandInfo structs.
+   * @return A CommandFunction that matches the command name and arguments.
+   */
+  template <typename FuncType>
+  static FuncType parseCommand(
+      const std::vector<std::string> &cmdLine,
+      const std::vector<CommandInfo<FuncType>> &supportedCommands) {
+    auto cmdInfoItor =
+        std::ranges::find_if(supportedCommands.begin(), supportedCommands.end(),
+                             [&](const CommandInfo<FuncType> &cmdInfo) {
+                               return cmdInfo.cmd == cmdLine[0] &&
+                                      cmdInfo.numOfArgs == cmdLine.size() - 1;
+                             });
+    return cmdInfoItor != supportedCommands.end() ? cmdInfoItor->func : nullptr;
+  }
+
+  /** Prints the usage instructions for the supported commands. */
+  template <typename FuncType>
+  static void printUsage(
+      const std::vector<CommandInfo<FuncType>> &supportedCommands) {
+    std::cout << std::left << "Usage: COMMAND [ARGUMENTS]" << std::endl;
+    for (auto const &command : supportedCommands) {
+      std::string cmdLine = command.cmd + " " + command.argsFormat;
+      std::cout << std::setw(kCommandLength) << cmdLine;
+      if (cmdLine.size() > kCommandLength) {
+        std::cout << std::endl << std::string(kCommandLength, ' ');
+      }
+      std::cout << " - " + command.usage << std::endl;
+    }
+    std::cout << std::endl;
+  }
+
+  /**
+   * Reads a line from standard input and parses it into command line arguments.
+   *
+   * @return A vector of strings representing the parsed command line arguments.
+   */
+  static std::vector<std::string> getCommandLine();
+
+ private:
+  static constexpr uint32_t kCommandLength = 40;
+};
+
+}  // namespace android::chre::chre_aidl_hal_client
+#endif  // ANDROID_CHRE_AIDL_HAL_CLIENT_COMMANDS_H
\ No newline at end of file
diff --git a/host/tools/chre_aidl_hal_client/context_hub_callback.cc b/host/tools/chre_aidl_hal_client/context_hub_callback.cc
new file mode 100644
index 00000000..f8061bc6
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/context_hub_callback.cc
@@ -0,0 +1,120 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "context_hub_callback.h"
+#include "chre_api/chre/version.h"
+
+namespace android::chre::chre_aidl_hal_client {
+namespace {
+
+using internal::ToString;
+
+// 34a3a27e-9b83-4098-b564-e83b0c28d4bb
+constexpr std::array<uint8_t, 16> kUuid = {0x34, 0xa3, 0xa2, 0x7e, 0x9b, 0x83,
+                                           0x40, 0x98, 0xb5, 0x64, 0xe8, 0x3b,
+                                           0x0c, 0x28, 0xd4, 0xbb};
+
+const std::string kClientName{"ChreAidlHalClient"};
+
+std::string parseTransactionId(int32_t transactionId) {
+  switch (transactionId) {
+    case kLoadTransactionId:
+      return "Loading";
+    case kUnloadTransactionId:
+      return "Unloading";
+    default:
+      return "Unknown";
+  }
+}
+}  // namespace
+
+ScopedAStatus ContextHubCallback::handleNanoappInfo(
+    const std::vector<NanoappInfo> &appInfo) {
+  std::cout << appInfo.size() << " nanoapps loaded" << std::endl;
+  for (const NanoappInfo &app : appInfo) {
+    std::cout << "appId: 0x" << std::hex << app.nanoappId << std::dec << " {"
+              << "\n\tappVersion: "
+              << NanoappHelper::parseAppVersion(app.nanoappVersion)
+              << "\n\tenabled: " << (app.enabled ? "true" : "false")
+              << "\n\tpermissions: " << ToString(app.permissions)
+              << "\n\trpcServices: " << ToString(app.rpcServices) << "\n}"
+              << std::endl;
+  }
+  resetPromise();
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus ContextHubCallback::handleContextHubMessage(
+    const ContextHubMessage &message,
+    const std::vector<std::string> & /*msgContentPerms*/) {
+  std::cout << "Received a message!" << std::endl
+            << "   From: 0x" << std::hex << message.nanoappId << std::endl
+            << "     To: 0x" << static_cast<int>(message.hostEndPoint)
+            << std::endl
+            << "   Body: (type " << message.messageType << " size "
+            << message.messageBody.size() << ") 0x";
+  for (const uint8_t &data : message.messageBody) {
+    std::cout << std::hex << static_cast<uint16_t>(data);
+  }
+  std::cout << std::endl << std::endl;
+  resetPromise();
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus ContextHubCallback::handleContextHubAsyncEvent(
+    AsyncEventType event) {
+  std::cout << "Received async event " << toString(event) << std::endl;
+  resetPromise();
+  return ScopedAStatus::ok();
+}
+
+// Called after loading/unloading a nanoapp.
+ScopedAStatus ContextHubCallback::handleTransactionResult(int32_t transactionId,
+                                                          bool success) {
+  std::cout << parseTransactionId(transactionId) << " transaction is "
+            << (success ? "successful" : "failed") << std::endl;
+  resetPromise();
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus ContextHubCallback::handleNanSessionRequest(
+    const NanSessionRequest & /* request */) {
+  resetPromise();
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus ContextHubCallback::handleMessageDeliveryStatus(
+    char16_t /* hostEndPointId */,
+    const MessageDeliveryStatus & /* messageDeliveryStatus */) {
+  resetPromise();
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus ContextHubCallback::getUuid(std::array<uint8_t, 16> *out_uuid) {
+  *out_uuid = kUuid;
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus ContextHubCallback::getName(std::string *out_name) {
+  *out_name = kClientName;
+  return ScopedAStatus::ok();
+}
+
+void ContextHubCallback::resetPromise() {
+  promise.set_value();
+  promise = std::promise<void>{};
+}
+}  // namespace android::chre::chre_aidl_hal_client
diff --git a/host/tools/chre_aidl_hal_client/context_hub_callback.h b/host/tools/chre_aidl_hal_client/context_hub_callback.h
new file mode 100644
index 00000000..6146d6df
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/context_hub_callback.h
@@ -0,0 +1,141 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef ANDROID_CHRE_AIDL_HAL_CLIENT_CONTEXT_HUB_CALLBACK_H
+#define ANDROID_CHRE_AIDL_HAL_CLIENT_CONTEXT_HUB_CALLBACK_H
+
+#include <aidl/android/hardware/contexthub/BnContextHubCallback.h>
+#include <aidl/android/hardware/contexthub/IContextHub.h>
+#include <future>
+
+#include "nanoapp_helper.h"
+
+namespace android::chre::chre_aidl_hal_client {
+
+using aidl::android::hardware::contexthub::AsyncEventType;
+using aidl::android::hardware::contexthub::BnContextHubCallback;
+using aidl::android::hardware::contexthub::ContextHubInfo;
+using aidl::android::hardware::contexthub::ContextHubMessage;
+using aidl::android::hardware::contexthub::HostEndpointInfo;
+using aidl::android::hardware::contexthub::IContextHub;
+using aidl::android::hardware::contexthub::MessageDeliveryStatus;
+using aidl::android::hardware::contexthub::NanoappBinary;
+using aidl::android::hardware::contexthub::NanoappInfo;
+using aidl::android::hardware::contexthub::NanSessionRequest;
+using aidl::android::hardware::contexthub::Setting;
+using ndk::ScopedAStatus;
+
+/** Default Context Hub ID used for commands when not specified otherwise. */
+constexpr uint32_t kContextHubId = 0;
+
+/** Transaction ID used for nanoapp load operations. */
+constexpr int32_t kLoadTransactionId = 1;
+
+/** Transaction ID used for nanoapp unload operations. */
+constexpr int32_t kUnloadTransactionId = 2;
+
+/**
+ * Timeout threshold for HAL operations like load/unload.
+ *
+ * Although the AIDL definition specifies a 30s cap, the multiclient HAL
+ * might enforce a shorter timeout (e.g., 5s) to prevent blocking other clients.
+ */
+constexpr auto kTimeOutThresholdInSec = std::chrono::seconds(5);
+
+/**
+ * Implements the IContextHubCallback AIDL interface to receive asynchronous
+ * responses and events from the Context Hub HAL.
+ *
+ * This class handles callbacks related to nanoapp information, messages,
+ * transaction results, and other events. It uses a std::promise to signal
+ * the main thread when a callback is received.
+ */
+class ContextHubCallback final : public BnContextHubCallback {
+ public:
+  /**
+   * See IContextHubCallback.aidl#handleNanoappInfo.
+   */
+  ScopedAStatus handleNanoappInfo(
+      const std::vector<NanoappInfo> &appInfo) override;
+
+  /**
+   * See IContextHubCallback.aidl#handleContextHubMessage.
+   */
+  ScopedAStatus handleContextHubMessage(
+      const ContextHubMessage &message,
+      const std::vector<std::string> & /*msgContentPerms*/) override;
+
+  /**
+   * See IContextHubCallback.aidl#handleContextHubAsyncEvent.
+   */
+  ScopedAStatus handleContextHubAsyncEvent(AsyncEventType event) override;
+
+  /**
+   * See IContextHubCallback.aidl#handleTransactionResult.
+   */
+  ScopedAStatus handleTransactionResult(int32_t transactionId,
+                                        bool success) override;
+
+  /**
+   * See IContextHubCallback.aidl#handleNanSessionRequest.
+   */
+  ScopedAStatus handleNanSessionRequest(
+      const NanSessionRequest & /* request */) override;
+
+  /**
+   * See IContextHubCallback.aidl#handleMessageDeliveryStatus.
+   */
+  ScopedAStatus handleMessageDeliveryStatus(
+      char16_t /* hostEndPointId */,
+      const MessageDeliveryStatus & /* messageDeliveryStatus */) override;
+
+  /**
+   * See IContextHubCallback.aidl#getUuid.
+   */
+  ScopedAStatus getUuid(std::array<uint8_t, 16> *out_uuid) override;
+
+  /**
+   * See IContextHubCallback.aidl#getName.
+   */
+  ScopedAStatus getName(std::string *out_name) override;
+
+  /**
+   * Resets the internal promise, allowing the main thread to wait for the next
+   * callback.
+   */
+  void resetPromise();
+
+  /**
+   * A promise used to signal the main thread when a callback is received.
+   *
+   * TODO(b/247124878):
+   * This promise is shared among all the HAL callbacks to simplify the
+   * implementation. This is based on the assumption that every command should
+   * get a response before timeout and the first callback triggered is for the
+   * response.
+   *
+   * In very rare cases, however, the assumption doesn't hold:
+   *  - multiple callbacks are triggered by a command and come back out of order
+   *  - one command is timed out and the user typed in another command then the
+   *  first callback for the first command is triggered
+   * Once we have a chance we should consider refactor this design to let each
+   * callback use their specific promises.
+   */
+  std::promise<void> promise;
+};
+}  // namespace android::chre::chre_aidl_hal_client
+
+#endif  // ANDROID_CHRE_AIDL_HAL_CLIENT_CONTEXT_HUB_CALLBACK_H
\ No newline at end of file
diff --git a/host/tools/chre_aidl_hal_client/endpoint_callback.cc b/host/tools/chre_aidl_hal_client/endpoint_callback.cc
new file mode 100644
index 00000000..4cfeccd1
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/endpoint_callback.cc
@@ -0,0 +1,136 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "endpoint_callback.h"
+#include <iostream>
+
+#include "nanoapp_helper.h"
+
+namespace android::chre::chre_aidl_hal_client {
+
+ScopedAStatus EndpointCallback::onEndpointStarted(
+    const std::vector<EndpointInfo> &in_endpointInfos) {
+  std::cout << "EndpointCallback::onEndpointStarted called with "
+            << in_endpointInfos.size() << " endpoints." << std::endl;
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus EndpointCallback::onEndpointStopped(
+    const std::vector<EndpointId> &in_endpointIds, Reason in_reason) {
+  std::cout << "EndpointCallback::onEndpointStopped called for "
+            << in_endpointIds.size() << " endpoints. Reason: "
+            << aidl::android::hardware::contexthub::toString(in_reason)
+            << std::endl;
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus EndpointCallback::onMessageReceived(int32_t in_sessionId,
+                                                  const Message &in_msg) {
+  std::cout << "EndpointCallback::onMessageReceived called for session "
+            << in_sessionId << " seqNum=" << in_msg.sequenceNumber << std::endl;
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus EndpointCallback::onMessageDeliveryStatusReceived(
+    int32_t in_sessionId, const MessageDeliveryStatus &in_msgStatus) {
+  std::cout << "EndpointCallback::onMessageDeliveryStatusReceived called for "
+               "session "
+            << in_sessionId << ". Seq=" << in_msgStatus.messageSequenceNumber
+            << " errorCode="
+            << aidl::android::hardware::contexthub::toString(
+                   in_msgStatus.errorCode)
+            << std::endl;  // Use toString for enum
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus EndpointCallback::onEndpointSessionOpenRequest(
+    int32_t in_sessionId, const EndpointId &in_destination,
+    const EndpointId &in_initiator,
+    const std::optional<std::string> &in_serviceDescriptor) {
+  std::cout << "EndpointCallback::onEndpointSessionOpenRequest called for "
+               "session "
+            << in_sessionId << " from " << in_initiator.toString() << " to "
+            << in_destination.toString();
+  if (in_serviceDescriptor.has_value()) {
+    std::cout << " with service descriptor: " << in_serviceDescriptor.value();
+  }
+  std::cout << std::endl;
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus EndpointCallback::onCloseEndpointSession(int32_t in_sessionId,
+                                                       Reason in_reason) {
+  std::cout << "EndpointCallback::onCloseEndpointSession called for session "
+            << in_sessionId << ". Reason: "
+            << aidl::android::hardware::contexthub::toString(in_reason)
+            << std::endl;  // Use toString for enum
+  return ScopedAStatus::ok();
+}
+
+ScopedAStatus EndpointCallback::onEndpointSessionOpenComplete(
+    int32_t in_sessionId) {
+  std::cout
+      << "EndpointCallback::onEndpointSessionOpenComplete called for session "
+      << in_sessionId << std::endl;
+  return ScopedAStatus::ok();
+}
+
+void EndpointHelper::printEndpoints(std::vector<EndpointInfo> &endpoints) {
+  if (endpoints.empty()) {
+    std::cout << "No endpoints found" << std::endl;
+    return;
+  }
+  std::cout << "Found " << endpoints.size() << " endpoint(s):" << std::endl;
+  for (const auto &[endpoint, type, name, version, tag, requiredPermissions,
+                    services] : endpoints) {
+    const std::string versionString =
+        type == EndpointInfo::EndpointType::NANOAPP
+            ? NanoappHelper::parseAppVersion(version)
+            : std::to_string(version);
+    std::cout << "----------------------------------------" << std::endl;
+    std::cout << "  Hub ID:      0x" << std::hex << endpoint.hubId << std::endl;
+    std::cout << "  Endpoint ID: 0x" << std::hex << endpoint.id << std::dec
+              << std::endl;
+    std::cout << "  Name:        " << name << std::endl;
+    std::cout << "  Type:        " << toString(type) << std::endl;
+    std::cout << "  Version:     " << versionString << std::endl;
+    std::cout << "  Tag:         " << (tag.has_value() ? tag.value() : "<none>")
+              << std::endl;
+
+    std::cout << "  Permissions: ";
+    if (requiredPermissions.empty()) {
+      std::cout << "<none>" << std::endl;
+    } else {
+      std::cout << std::endl;
+      for (const auto &perm : requiredPermissions) {
+        std::cout << "    - " << perm << std::endl;
+      }
+    }
+
+    std::cout << "  Services:    ";
+    if (services.empty()) {
+      std::cout << "<none>" << std::endl;
+    } else {
+      std::cout << std::endl;
+      for (const auto &service : services) {
+        std::cout << "    - " << service.toString() << std::endl;
+      }
+    }
+  }
+  std::cout << "----------------------------------------" << std::endl;
+}
+
+}  // namespace android::chre::chre_aidl_hal_client
\ No newline at end of file
diff --git a/host/tools/chre_aidl_hal_client/endpoint_callback.h b/host/tools/chre_aidl_hal_client/endpoint_callback.h
new file mode 100644
index 00000000..f5be198f
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/endpoint_callback.h
@@ -0,0 +1,101 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef ANDROID_CHRE_AIDL_HAL_CLIENT_SESSION_BASED_MESSAGING_H
+#define ANDROID_CHRE_AIDL_HAL_CLIENT_SESSION_BASED_MESSAGING_H
+
+#include <vector>
+
+#include <aidl/android/hardware/contexthub/BnContextHubCallback.h>
+#include <aidl/android/hardware/contexthub/BnEndpointCallback.h>
+#include <aidl/android/hardware/contexthub/ContextHubMessage.h>
+#include <aidl/android/hardware/contexthub/HostEndpointInfo.h>
+#include <aidl/android/hardware/contexthub/IContextHub.h>
+#include <aidl/android/hardware/contexthub/IContextHubCallback.h>
+#include <aidl/android/hardware/contexthub/NanoappBinary.h>
+#include <android/binder_process.h>
+
+namespace android::chre::chre_aidl_hal_client {
+
+using aidl::android::hardware::contexthub::AsyncEventType;
+using aidl::android::hardware::contexthub::BnContextHubCallback;
+using aidl::android::hardware::contexthub::BnEndpointCallback;
+using aidl::android::hardware::contexthub::ContextHubInfo;
+using aidl::android::hardware::contexthub::ContextHubMessage;
+using aidl::android::hardware::contexthub::EndpointId;
+using aidl::android::hardware::contexthub::EndpointInfo;
+using aidl::android::hardware::contexthub::HostEndpointInfo;
+using aidl::android::hardware::contexthub::HubInfo;
+using aidl::android::hardware::contexthub::IContextHub;
+using aidl::android::hardware::contexthub::IContextHubCallback;
+using aidl::android::hardware::contexthub::IContextHubDefault;
+using aidl::android::hardware::contexthub::IEndpointCallback;
+using aidl::android::hardware::contexthub::IEndpointCallbackDefault;
+using aidl::android::hardware::contexthub::IEndpointCommunication;
+using aidl::android::hardware::contexthub::Message;
+using aidl::android::hardware::contexthub::MessageDeliveryStatus;
+using aidl::android::hardware::contexthub::NanoappBinary;
+using aidl::android::hardware::contexthub::NanoappInfo;
+using aidl::android::hardware::contexthub::NanSessionRequest;
+using aidl::android::hardware::contexthub::Reason;
+using aidl::android::hardware::contexthub::Service;
+using aidl::android::hardware::contexthub::Setting;
+using aidl::android::hardware::contexthub::VendorHubInfo;
+using ndk::ScopedAStatus;
+
+const VendorHubInfo kVendorHubInfo = {
+    .name = "chre_aidl_hal_client_hub",
+    .version = 1,
+};
+
+const HubInfo kHubInfo = {
+    .hubId = 0xbeefbeef,
+    .hubDetails = kVendorHubInfo,
+};
+
+class EndpointCallback : public BnEndpointCallback {
+ public:
+  ScopedAStatus onEndpointStarted(
+      const std::vector<EndpointInfo> &in_endpointInfos) override;
+
+  ScopedAStatus onEndpointStopped(const std::vector<EndpointId> &in_endpointIds,
+                                  Reason in_reason) override;
+
+  ScopedAStatus onMessageReceived(int32_t in_sessionId,
+                                  const Message &in_msg) override;
+
+  ScopedAStatus onMessageDeliveryStatusReceived(
+      int32_t in_sessionId, const MessageDeliveryStatus &in_msgStatus) override;
+
+  ScopedAStatus onEndpointSessionOpenRequest(
+      int32_t in_sessionId, const EndpointId &in_destination,
+      const EndpointId &in_initiator,
+      const std::optional<std::string> &in_serviceDescriptor) override;
+
+  ScopedAStatus onCloseEndpointSession(int32_t in_sessionId,
+                                       Reason in_reason) override;
+
+  ScopedAStatus onEndpointSessionOpenComplete(int32_t in_sessionId) override;
+};
+
+class EndpointHelper {
+ public:
+  static void printEndpoints(std::vector<EndpointInfo> &endpoints);
+};
+
+}  // namespace android::chre::chre_aidl_hal_client
+
+#endif  // ANDROID_CHRE_AIDL_HAL_CLIENT_SESSION_BASED_MESSAGING_H
\ No newline at end of file
diff --git a/host/tools/chre_aidl_hal_client/main.cc b/host/tools/chre_aidl_hal_client/main.cc
new file mode 100644
index 00000000..c28ad02e
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/main.cc
@@ -0,0 +1,54 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "command_handlers.h"
+
+#include <android/binder_process.h>
+
+#include <stdexcept>
+#include <string>
+#include <vector>
+
+#include "chre_host/hal_client.h"
+
+using namespace android::chre::chre_aidl_hal_client;
+
+void executeCommand(const std::vector<std::string> &cmdLine) {
+  if (auto func = CommandHelper::parseCommand<DirectCommandFunction>(
+          cmdLine, kAllDirectCommands)) {
+    func(cmdLine);
+  } else {
+    CommandHelper::printUsage<DirectCommandFunction>(kAllDirectCommands);
+  }
+}
+
+int main(int argc, char *argv[]) {
+  using namespace android::chre::chre_aidl_hal_client;
+  // Start binder thread pool to enable callbacks.
+  ABinderProcess_startThreadPool();
+
+  std::vector<std::string> cmdLine{};
+  for (int i = 1; i < argc; i++) {
+    cmdLine.emplace_back(argv[i]);
+  }
+  try {
+    executeCommand(cmdLine);
+  } catch (std::system_error &e) {
+    std::cerr << e.what() << std::endl;
+    return -1;
+  }
+  return 0;
+}
\ No newline at end of file
diff --git a/host/tools/chre_aidl_hal_client/nanoapp_helper.cc b/host/tools/chre_aidl_hal_client/nanoapp_helper.cc
new file mode 100644
index 00000000..1abdf287
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/nanoapp_helper.cc
@@ -0,0 +1,191 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "nanoapp_helper.h"
+#include "utils.h"
+
+#include <dirent.h>
+#include <fstream>
+#include <future>
+#include <iostream>
+#include <regex>
+#include <string>
+
+#include "chre_api/chre/version.h"
+
+namespace android::chre::chre_aidl_hal_client {
+
+namespace {
+// Locations should be searched in the sequence defined below:
+const char *kPredefinedNanoappPaths[] = {
+    "/vendor/etc/chre/",
+    "/vendor/dsp/adsp/",
+    "/vendor/dsp/sdsp/",
+    "/vendor/lib/rfsa/adsp/",
+};
+}  // namespace
+
+std::string NanoappHelper::parseAppVersion(uint32_t version) {
+  std::ostringstream stringStream;
+  stringStream << std::hex << "0x" << version << std::dec << " (v"
+               << CHRE_EXTRACT_MAJOR_VERSION(version) << "."
+               << CHRE_EXTRACT_MINOR_VERSION(version) << "."
+               << CHRE_EXTRACT_PATCH_VERSION(version) << ")";
+  return stringStream.str();
+}
+
+bool NanoappHelper::isValidNanoappHexId(const std::string &number) {
+  if (!isValidHexNumber(number)) {
+    return false;
+  }
+  // Once the input has the hex prefix, an exception will be thrown if it is
+  // malformed because it shouldn't be treated as an app name anymore.
+  if (number.size() > 18) {
+    throwError(
+        "Hex app id must have a length of [3, 18] including the prefix.");
+  }
+  return true;
+}
+
+void NanoappHelper::printNanoappHeader(const NanoAppBinaryHeader &header) {
+  std::cout << " {"
+            << "\n\tappId: 0x" << std::hex << header.appId << std::dec
+            << "\n\tappVersion: "
+            << NanoappHelper::parseAppVersion(header.appVersion)
+            << "\n\tflags: " << header.flags << "\n\ttarget CHRE API version: "
+            << static_cast<int>(header.targetChreApiMajorVersion) << "."
+            << static_cast<int>(header.targetChreApiMinorVersion) << "\n}"
+            << std::endl;
+}
+
+std::unique_ptr<NanoAppBinaryHeader> NanoappHelper::findHeaderByName(
+    const std::string &appName, const std::string &binaryPath) {
+  DIR *dir = opendir(binaryPath.c_str());
+  if (dir == nullptr) {
+    return nullptr;
+  }
+  std::regex regex(appName + ".napp_header");
+  std::cmatch match;
+
+  std::unique_ptr<NanoAppBinaryHeader> result = nullptr;
+  for (dirent *entry; (entry = readdir(dir)) != nullptr;) {
+    if (!std::regex_match(entry->d_name, match, regex)) {
+      continue;
+    }
+    std::ifstream input(std::string(binaryPath) + "/" + entry->d_name,
+                        std::ios::binary);
+    result = std::make_unique<NanoAppBinaryHeader>();
+    input.read(reinterpret_cast<char *>(result.get()),
+               sizeof(NanoAppBinaryHeader));
+    break;
+  }
+  closedir(dir);
+  return result;
+}
+
+void NanoappHelper::readNanoappHeaders(
+    std::map<std::string, NanoAppBinaryHeader> &nanoapps,
+    const std::string &binaryPath) {
+  DIR *dir = opendir(binaryPath.c_str());
+  if (dir == nullptr) {
+    return;
+  }
+  std::regex regex("(\\w+)\\.napp_header");
+  std::cmatch match;
+  for (struct dirent *entry; (entry = readdir(dir)) != nullptr;) {
+    if (!std::regex_match(entry->d_name, match, regex)) {
+      continue;
+    }
+    std::ifstream input(std::string(binaryPath) + "/" + entry->d_name,
+                        std::ios::binary);
+    input.read(reinterpret_cast<char *>(&nanoapps[match[1]]),
+               sizeof(NanoAppBinaryHeader));
+  }
+  closedir(dir);
+}
+
+/**
+ * Finds the .napp_header file associated to the nanoapp.
+ *
+ * This function guarantees to return a non-null {@link NanoAppBinaryHeader}
+ * pointer. In case a .napp_header file cannot be found an exception will be
+ * raised.
+ *
+ * @param pathAndName name of the nanoapp that might be prefixed with it path.
+ * It will be normalized to the format of <absolute-path><name>.so at the end.
+ * For example, "abc" will be changed to "/path/to/abc.so".
+ *
+ * @return a unique pointer to the {@link NanoAppBinaryHeader} found
+ */
+std::unique_ptr<NanoAppBinaryHeader> NanoappHelper::findHeaderAndNormalizePath(
+    std::string &pathAndName) {
+  // To match the file pattern of [path]<name>[.so]
+  std::regex pathNameRegex("(.*?)(\\w+)(\\.so)?");
+  std::smatch smatch;
+  if (!std::regex_match(pathAndName, smatch, pathNameRegex)) {
+    throwError("Invalid nanoapp: " + pathAndName);
+  }
+  std::string fullPath = smatch[1];
+  std::string appName = smatch[2];
+  // absolute path is provided:
+  if (!fullPath.empty() && fullPath[0] == '/') {
+    auto result = findHeaderByName(appName, fullPath);
+    if (result == nullptr) {
+      throwError("Unable to find the nanoapp header for " + pathAndName);
+    }
+    pathAndName = fullPath + appName + ".so";
+    return result;
+  }
+  // relative path is searched form predefined locations:
+  for (const std::string &predefinedPath : kPredefinedNanoappPaths) {
+    auto result = findHeaderByName(appName, predefinedPath);
+    if (result == nullptr) {
+      continue;
+    }
+    pathAndName = predefinedPath + appName + ".so";
+    return result;
+  }
+  throwError("Unable to find the nanoapp header for " + pathAndName);
+  return nullptr;
+}
+
+int64_t NanoappHelper::getNanoappIdFrom(std::string &appIdOrName) {
+  int64_t appId;
+  if (NanoappHelper::isValidNanoappHexId(appIdOrName)) {
+    appId = std::stoll(appIdOrName, nullptr, 16);
+  } else {
+    // Treat the appIdOrName as the app name and try again
+    appId =
+        static_cast<int64_t>(findHeaderAndNormalizePath(appIdOrName)->appId);
+  }
+  return appId;
+}
+
+void NanoappHelper::listNanoappsInPath(const std::string &path) {
+  std::map<std::string, NanoAppBinaryHeader> nanoapps{};
+  NanoappHelper::readNanoappHeaders(nanoapps, path);
+  if (nanoapps.empty()) {
+    std::cout << "No nanoapp headers found in " << path << std::endl;
+    return;
+  }
+  std::cout << "Nanoapps found in " << path << ":" << std::endl;
+  for (const auto &[appName, appHeader] : nanoapps) {
+    std::cout << appName;
+    NanoappHelper::printNanoappHeader(appHeader);
+  }
+}
+
+}  // namespace android::chre::chre_aidl_hal_client
\ No newline at end of file
diff --git a/host/tools/chre_aidl_hal_client/nanoapp_helper.h b/host/tools/chre_aidl_hal_client/nanoapp_helper.h
new file mode 100644
index 00000000..16bc0bf9
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/nanoapp_helper.h
@@ -0,0 +1,155 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef ANDROID_CHRE_AIDL_HAL_CLIENT_NANOAPP_HELPER_H
+#define ANDROID_CHRE_AIDL_HAL_CLIENT_NANOAPP_HELPER_H
+
+#include <fstream>
+#include <map>
+#include <string>
+
+#include "chre_host/napp_header.h"
+
+namespace android::chre::chre_aidl_hal_client {
+
+/**
+ * Provides static utility functions for handling nanoapps.
+ *
+ * This class offers functionalities like parsing versions, validating IDs,
+ * finding and reading nanoapp headers, and resolving nanoapp IDs from names or
+ * hex strings.
+ */
+class NanoappHelper {
+ public:
+  /**
+   * Parses a raw nanoapp version number into a human-readable string.
+   *
+   * Formats the version as "0x<hex_version> (v<major>.<minor>.<patch>)".
+   *
+   * @param version The raw 32-bit version number.
+   * @return A string representation of the version.
+   */
+  static std::string parseAppVersion(uint32_t version);
+
+  /**
+   * Checks if a string represents a valid 64-bit hexadecimal nanoapp ID.
+   *
+   * A valid hex ID must start with "0x" or "0X", be followed by 1 to 16
+   * hexadecimal digits (0-9, a-f, A-F), resulting in a total length between 3
+   * and 18 characters. Throws an error if the format is invalid after the
+   * prefix or if the length constraint is violated.
+   *
+   * @param number The string to validate.
+   * @return true if the string is a valid hex nanoapp ID format, false
+   * otherwise.
+   * @throws std::system_error if the format is invalid after the prefix or if
+   * the length constraint is violated.
+   */
+  static bool isValidNanoappHexId(const std::string &number);
+
+  /**
+   * Prints the details of a NanoAppBinaryHeader to standard output.
+   *
+   * @param header The nanoapp header structure to print.
+   */
+  static void printNanoappHeader(const NanoAppBinaryHeader &header);
+
+  /**
+   * Finds and reads a nanoapp header file by name within a specific directory.
+   *
+   * Searches for a file named "<appName>.napp_header" in the given
+   * `binaryPath`.
+   *
+   * @param appName The base name of the nanoapp (without path or extension).
+   * @param binaryPath The directory path to search within.
+   * @return A unique pointer to the read NanoAppBinaryHeader if found,
+   * otherwise nullptr.
+   */
+  static std::unique_ptr<NanoAppBinaryHeader> findHeaderByName(
+      const std::string &appName, const std::string &binaryPath);
+
+  /**
+   * Reads all nanoapp header files from a specified directory.
+   *
+   * Scans the directory for files matching "*.napp_header", reads them, and
+   * populates the provided map. The map keys will be the nanoapp names
+   * extracted from the filenames.
+   *
+   * @param nanoapps A map to populate with nanoapp names and their
+   * corresponding headers.
+   * @param binaryPath The directory path to scan for header files.
+   */
+  static void readNanoappHeaders(
+      std::map<std::string, NanoAppBinaryHeader> &nanoapps,
+      const std::string &binaryPath);
+
+  /**
+   * Finds the .napp_header file associated with a nanoapp and normalizes its
+   * path.
+   *
+   * Parses the input `pathAndName` to extract the path and name. If an
+   * absolute path is given, it searches there. Otherwise, it searches
+   * predefined system paths. If found, it updates `pathAndName` to the full,
+   * normalized path (e.g., "/path/to/app.so") and returns the header.
+   *
+   * This function guarantees to return a non-null {@link NanoAppBinaryHeader}
+   * pointer if successful.
+   *
+   * @param pathAndName Input string potentially containing path and name (e.g.,
+   * "my_app", "/vendor/etc/chre/my_app.so"). This string reference will be
+   * modified to the normalized absolute path ending in ".so" if the header is
+   * found.
+   * @return A unique pointer to the {@link NanoAppBinaryHeader} found.
+   * @throws std::system_error if the input format is invalid or the header
+   * file cannot be found.
+   */
+  static std::unique_ptr<NanoAppBinaryHeader> findHeaderAndNormalizePath(
+      std::string &pathAndName);
+
+  /**
+   * Gets the 64-bit nanoapp ID from a string, which can be a hex ID or a
+   * name/path.
+   *
+   * If the input string is identified as a valid hex nanoapp ID (using
+   * `isValidNanoappHexId`), it's converted directly. Otherwise, the string is
+   * treated as a nanoapp name (potentially with a path), and its header is
+   * located using `findHeaderAndNormalizePath` to retrieve the ID. The input
+   * string `appIdOrName` might be modified by
+   * `findHeaderAndNormalizePath` if it's treated as a name.
+   *
+   * @param appIdOrName A string containing either the hex ID ("0x...") or the
+   * nanoapp name/path. This string reference might be modified.
+   * @return The 64-bit nanoapp ID.
+   * @throws std::system_error if the input is neither a valid hex ID nor a
+   * resolvable nanoapp name.
+   */
+  static int64_t getNanoappIdFrom(std::string &appIdOrName);
+
+  /**
+   * Reads all nanoapp headers from the specified path and prints their details.
+   *
+   * Scans the given directory for files ending in ".napp_header", reads each
+   * header, and prints the extracted nanoapp name along with its header
+   * information (using `printNanoappHeader`) to standard output. If no headers
+   * are found, it prints a message indicating that.
+   *
+   * @param path The directory path to scan for nanoapp header files.
+   */
+  static void listNanoappsInPath(const std::string &path);
+};
+}  // namespace android::chre::chre_aidl_hal_client
+
+#endif  // ANDROID_CHRE_AIDL_HAL_CLIENT_NANOAPP_HELPER_H
\ No newline at end of file
diff --git a/host/tools/chre_aidl_hal_client/utils.cc b/host/tools/chre_aidl_hal_client/utils.cc
new file mode 100644
index 00000000..91a49fb4
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/utils.cc
@@ -0,0 +1,51 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "utils.h"
+#include <filesystem>
+#include <fstream>
+#include <stdexcept>
+#include <string>
+
+#include "chre_api/chre/version.h"
+namespace android::chre::chre_aidl_hal_client {
+
+bool isValidHexNumber(const std::string &number) {
+  if (number.empty() ||
+      (number.substr(0, 2) != "0x" && number.substr(0, 2) != "0X")) {
+    return false;
+  }
+  for (int i = 2; i < number.size(); i++) {
+    if (!isxdigit(number[i])) {
+      throwError("Hex app id " + number + " contains invalid character.");
+    }
+  }
+  return number.size() > 2;
+}
+
+char16_t verifyAndConvertEndpointHexId(const std::string &number) {
+  // host endpoint id must be a 16-bits long hex number.
+  if (isValidHexNumber(number)) {
+    const char16_t convertedNumber =
+        std::stoi(number, /* idx= */ nullptr, /* base= */ 16);
+    if (convertedNumber < std::numeric_limits<uint16_t>::max()) {
+      return convertedNumber;
+    }
+  }
+  throwError("host endpoint id must be a 16-bits long hex number.");
+  return 0;  // code never reached.
+}
+}  // namespace android::chre::chre_aidl_hal_client
\ No newline at end of file
diff --git a/host/tools/chre_aidl_hal_client/utils.h b/host/tools/chre_aidl_hal_client/utils.h
new file mode 100644
index 00000000..9923b607
--- /dev/null
+++ b/host/tools/chre_aidl_hal_client/utils.h
@@ -0,0 +1,60 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef ANDROID_CHRE_AIDL_HAL_CLIENT_UTILS_H
+#define ANDROID_CHRE_AIDL_HAL_CLIENT_UTILS_H
+
+#include <string>
+#include <system_error>
+
+namespace android::chre::chre_aidl_hal_client {
+
+/**
+ * Throws a std::system_error with the provided message.
+ *
+ * @param message The error message to include in the exception.
+ */
+inline void throwError(const std::string &message) {
+  throw std::system_error{std::error_code(), message};
+}
+
+/**
+ * Checks if a string represents a valid hexadecimal number.
+ *
+ * A valid hex number must start with "0x" or "0X" and be followed by one or
+ * more hexadecimal digits (0-9, a-f, A-F).
+ * Throws an error if an invalid character is found after the prefix.
+ *
+ * @param number The string to validate.
+ * @return true if the string is a valid non-empty hex number, false otherwise.
+ */
+bool isValidHexNumber(const std::string &number);
+
+/**
+ * Verifies if a string represents a valid 16-bit hexadecimal number and
+ * converts it.
+ *
+ * Throws an error if the input string is not a valid hex number or if the
+ * converted value is outside the range of a 16-bit unsigned integer.
+ *
+ * @param number The string containing the hex number (e.g., "0x1234").
+ * @return The converted char16_t value.
+ * @throws std::system_error if the input is invalid.
+ */
+char16_t verifyAndConvertEndpointHexId(const std::string &number);
+}  // namespace android::chre::chre_aidl_hal_client
+
+#endif  // ANDROID_CHRE_AIDL_HAL_CLIENT_UTILS_H
\ No newline at end of file
diff --git a/java/test/audio_concurrency/src/com/google/android/chre/test/audioconcurrency/ContextHubAudioConcurrencyTestExecutor.java b/java/test/audio_concurrency/src/com/google/android/chre/test/audioconcurrency/ContextHubAudioConcurrencyTestExecutor.java
index b2aae5ec..73d5711b 100644
--- a/java/test/audio_concurrency/src/com/google/android/chre/test/audioconcurrency/ContextHubAudioConcurrencyTestExecutor.java
+++ b/java/test/audio_concurrency/src/com/google/android/chre/test/audioconcurrency/ContextHubAudioConcurrencyTestExecutor.java
@@ -65,7 +65,7 @@ public class ContextHubAudioConcurrencyTestExecutor extends ContextHubClientCall
 
     private CountDownLatch mCountDownLatch;
 
-    private boolean mInitialized = false;
+    private boolean mInitAttempted = false;
 
     private boolean mVerifyAudioGaps = false;
 
@@ -133,11 +133,11 @@ public class ContextHubAudioConcurrencyTestExecutor extends ContextHubClientCall
      * Should be invoked before run() is invoked to set up the test, e.g. in a @Before method.
      */
     public void init() {
-        Assert.assertFalse("init() must not be invoked when already initialized", mInitialized);
+        Assert.assertFalse("init() must not be invoked when already initialized", mInitAttempted);
+        mInitAttempted = true;
         ChreTestUtil.loadNanoAppAssertSuccess(mContextHubManager, mContextHubInfo, mNanoAppBinary);
 
         mVerifyAudioGaps = shouldVerifyAudioGaps();
-        mInitialized = true;
     }
 
     /**
@@ -177,12 +177,11 @@ public class ContextHubAudioConcurrencyTestExecutor extends ContextHubClientCall
      * Cleans up the test, should be invoked in e.g. @After method.
      */
     public void deinit() {
-        Assert.assertTrue("deinit() must be invoked after init()", mInitialized);
+        Assert.assertTrue("deinit() must be invoked after init()", mInitAttempted);
+        mInitAttempted = false;
 
         ChreTestUtil.unloadNanoAppAssertSuccess(mContextHubManager, mContextHubInfo, mNanoAppId);
         mContextHubClient.close();
-
-        mInitialized = false;
     }
 
     /**
diff --git a/java/test/ble_concurrency/src/com/google/android/chre/test/bleconcurrency/ContextHubBleConcurrencyTestExecutor.java b/java/test/ble_concurrency/src/com/google/android/chre/test/bleconcurrency/ContextHubBleConcurrencyTestExecutor.java
index c071aef9..7456cb98 100644
--- a/java/test/ble_concurrency/src/com/google/android/chre/test/bleconcurrency/ContextHubBleConcurrencyTestExecutor.java
+++ b/java/test/ble_concurrency/src/com/google/android/chre/test/bleconcurrency/ContextHubBleConcurrencyTestExecutor.java
@@ -45,8 +45,8 @@ public class ContextHubBleConcurrencyTestExecutor extends ContextHubBleTestExecu
      * Tests with the host starting scanning first.
      */
     private void testHostScanFirst() throws Exception {
-        startBleScanOnHost();
-        chreBleStartScanSync(getServiceDataScanFilterChre());
+        startBleScanOnHost(getGoogleServiceDataScanFilterHost());
+        chreBleStartScanSync(getGoogleServiceDataScanFilterChre());
         Thread.sleep(1000);
         chreBleStopScanSync();
         stopBleScanOnHost();
@@ -56,8 +56,8 @@ public class ContextHubBleConcurrencyTestExecutor extends ContextHubBleTestExecu
      * Tests with CHRE starting scanning first.
      */
     private void testChreScanFirst() throws Exception {
-        chreBleStartScanSync(getServiceDataScanFilterChre());
-        startBleScanOnHost();
+        chreBleStartScanSync(getGoogleServiceDataScanFilterChre());
+        startBleScanOnHost(getGoogleServiceDataScanFilterHost());
         Thread.sleep(1000);
         stopBleScanOnHost();
         chreBleStopScanSync();
diff --git a/java/test/chqts/Android.bp b/java/test/chqts/Android.bp
index fd285356..ff6a4d9c 100644
--- a/java/test/chqts/Android.bp
+++ b/java/test/chqts/Android.bp
@@ -34,6 +34,7 @@ java_library {
         "chre_pigweed_utils",
         "chre_reliable_message_test_java_proto",
         "chre_test_common_java_proto",
+        "endpoint_echo_test_proto_java_lite",
         "guava",
         "pw_rpc_java_client",
         "truth",
diff --git a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubBleTestExecutor.java b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubBleTestExecutor.java
index afaa0bd8..da5b606f 100644
--- a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubBleTestExecutor.java
+++ b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubBleTestExecutor.java
@@ -33,6 +33,7 @@ import android.bluetooth.le.ScanResult;
 import android.bluetooth.le.ScanSettings;
 import android.hardware.location.NanoAppBinary;
 import android.os.ParcelUuid;
+import android.util.Log;
 
 import com.google.android.utils.chre.ChreApiTestUtil;
 import com.google.common.collect.ImmutableList;
@@ -40,6 +41,8 @@ import com.google.protobuf.ByteString;
 
 import org.junit.Assert;
 
+import java.util.ArrayList;
+import java.util.Collections;
 import java.util.HexFormat;
 import java.util.List;
 import java.util.UUID;
@@ -71,6 +74,11 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
      */
     public static final UUID EDDYSTONE_UUID = to128BitUuid((short) 0xFEAA);
 
+    /**
+     * The ID for the service data beacon for multi-device test.
+     */
+    public static final UUID CHRE_TEST_SERVICE_DATA_UUID = to128BitUuid((short) 0xABCD);
+
     /**
      * The delay to report results in milliseconds.
      */
@@ -105,7 +113,8 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
     /**
      * CHRE BLE test manufacturer ID.
      */
-    private static final int CHRE_BLE_TEST_MANUFACTURER_ID = 0xEEEE;
+    public static final int CHRE_BLE_TEST_MANUFACTURER_ID = 0xEEEE;
+
 
     private BluetoothAdapter mBluetoothAdapter = null;
     private BluetoothLeAdvertiser mBluetoothLeAdvertiser = null;
@@ -126,6 +135,11 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
      */
     private AtomicBoolean mIsAdvertising = new AtomicBoolean();
 
+    /**
+     * List to store BLE scan received by host.
+     */
+    public final List<ScanResult> mScanResults = Collections.synchronizedList(new ArrayList<>());
+
     /**
      * Callback for BLE scans.
      */
@@ -142,7 +156,13 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
 
         @Override
         public void onScanResult(int callbackType, ScanResult result) {
-            // do nothing
+            if (result == null) {
+                Log.w(TAG, "Received null scan result.");
+                return;
+            }
+            synchronized (mScanResults) {
+                mScanResults.add(result);
+            }
         }
     };
 
@@ -194,9 +214,10 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
      *
      * @param useEddystone          if true, filter for Google Eddystone.
      * @param useNearbyFastpair     if true, filter for Nearby Fastpair.
+     * @param useChreTestServiceData if true, filter for Test Service Data.
      */
     public static ChreApiTest.ChreBleScanFilter getDefaultScanFilter(boolean useEddystone,
-            boolean useNearbyFastpair) {
+            boolean useNearbyFastpair, boolean useChreTestServiceData) {
         ChreApiTest.ChreBleScanFilter.Builder builder =
                 ChreApiTest.ChreBleScanFilter.newBuilder()
                         .setRssiThreshold(RSSI_THRESHOLD);
@@ -223,6 +244,17 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
             builder = builder.addScanFilters(nearbyFastpairFilter);
         }
 
+        if (useChreTestServiceData) {
+            ChreApiTest.ChreBleGenericFilter eddystoneFilter =
+                    ChreApiTest.ChreBleGenericFilter.newBuilder()
+                            .setType(CHRE_BLE_AD_TYPE_SERVICE_DATA_WITH_UUID_16)
+                            .setLength(2)
+                            .setData(ByteString.copyFrom(HexFormat.of().parseHex("CDAB")))
+                            .setMask(ByteString.copyFrom(HexFormat.of().parseHex("FFFF")))
+                            .build();
+            builder = builder.addScanFilters(eddystoneFilter);
+        }
+
         return builder.build();
     }
 
@@ -249,15 +281,17 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
      * Generates a BLE scan filter that filters only for the known Google beacons:
      * Google Eddystone and Nearby Fastpair.
      */
-    public static ChreApiTest.ChreBleScanFilter getServiceDataScanFilterChre() {
-        return getDefaultScanFilter(true /* useEddystone */, true /* useNearbyFastpair */);
+    public static ChreApiTest.ChreBleScanFilter getGoogleServiceDataScanFilterChre() {
+        return getDefaultScanFilter(true /* useEddystone */, true /* useNearbyFastpair */,
+                    false /* useChreTestServiceData */);
     }
 
     /**
-     * Generates a BLE scan filter that filters only for Google Eddystone.
+     * Generates a BLE scan filter that filters for a test service data UUID.
      */
-    public static ChreApiTest.ChreBleScanFilter getGoogleEddystoneScanFilter() {
-        return getDefaultScanFilter(true /* useEddystone */, false /* useNearbyFastpair */);
+    public static ChreApiTest.ChreBleScanFilter getTestServiceDataFilterChre() {
+        return getDefaultScanFilter(false /* useEddystone */, false /* useNearbyFastpair */,
+                    true /* useChreTestServiceData */);
     }
 
     /**
@@ -265,7 +299,7 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
      * Google Eddystone and Nearby Fastpair. We specify the filter data in (little-endian) LE
      * here as the CHRE code will take BE input and transform it to LE.
      */
-    public static List<ScanFilter> getServiceDataScanFilterHost() {
+    public static List<ScanFilter> getGoogleServiceDataScanFilterHost() {
         assertThat(CHRE_BLE_AD_TYPE_SERVICE_DATA_WITH_UUID_16)
                 .isEqualTo(ScanRecord.DATA_TYPE_SERVICE_DATA_16_BIT);
 
@@ -285,6 +319,25 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
         return ImmutableList.of(scanFilter, scanFilter2);
     }
 
+    /**
+     * Generates a BLE scan filter for a Test Service Data UUID.
+     * We specify the filter data in (little-endian) LE
+     * here as the CHRE code will take BE input and transform it to LE.
+     */
+    public static List<ScanFilter> getTestServiceDataScanFilterHost() {
+        assertThat(CHRE_BLE_AD_TYPE_SERVICE_DATA_WITH_UUID_16)
+                .isEqualTo(ScanRecord.DATA_TYPE_SERVICE_DATA_16_BIT);
+
+        ScanFilter scanFilter = new ScanFilter.Builder()
+                .setAdvertisingDataTypeWithData(
+                        ScanRecord.DATA_TYPE_SERVICE_DATA_16_BIT,
+                        ByteString.copyFrom(HexFormat.of().parseHex("CDAB")).toByteArray(),
+                        ByteString.copyFrom(HexFormat.of().parseHex("FFFF")).toByteArray())
+                .build();
+
+        return ImmutableList.of(scanFilter);
+    }
+
     /**
      * Generates a BLE scan filter that filters only for the known CHRE test specific
      * manufacturer ID.
@@ -377,14 +430,17 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
     }
 
     /**
-     * Starts a BLE scan on the host side with known Google beacon filters.
+     * Starts a BLE scan on the host side with the given scan filters.
      */
-    public void startBleScanOnHost() {
+    public void startBleScanOnHost(List<ScanFilter> scanFilter) throws Exception {
+        if (scanFilter == null) {
+            throw new IllegalAccessException("Scan filters must not be empty or null");
+        }
         ScanSettings scanSettings = new ScanSettings.Builder()
                 .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                 .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                 .build();
-        mBluetoothLeScanner.startScan(getServiceDataScanFilterHost(),
+        mBluetoothLeScanner.startScan(scanFilter,
                 scanSettings, mScanCallback);
     }
 
@@ -423,6 +479,34 @@ public class ContextHubBleTestExecutor extends ContextHubChreApiTestExecutor {
         assertThat(mIsAdvertising.get()).isTrue();
     }
 
+    /**
+     * Starts broadcasting the CHRE test Service Data beacon from the AP.
+     */
+    public void startBleAdvertisingTestServiceData() throws InterruptedException {
+        if (mIsAdvertising.get()) {
+            return;
+        }
+
+        AdvertisingSetParameters parameters = new AdvertisingSetParameters.Builder()
+                .setLegacyMode(true)
+                .setConnectable(false)
+                .setInterval(AdvertisingSetParameters.INTERVAL_LOW)
+                .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_MEDIUM)
+                .build();
+
+        AdvertiseData data = new AdvertiseData.Builder()
+                .addServiceData(new ParcelUuid(CHRE_TEST_SERVICE_DATA_UUID), new byte[] {0})
+                .setIncludeDeviceName(false)
+                .setIncludeTxPowerLevel(true)
+                .build();
+
+        mBluetoothLeAdvertiser.startAdvertisingSet(parameters, data,
+                /* ownAddress= */ null, /* periodicParameters= */ null,
+                /* periodicData= */ null, mAdvertisingSetCallback);
+        mAdvertisingStartLatch.await();
+        assertThat(mIsAdvertising.get()).isTrue();
+    }
+
     /**
      * Starts broadcasting the CHRE test manufacturer Data from the AP.
      */
diff --git a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubChreApiTestExecutor.java b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubChreApiTestExecutor.java
index b3c23366..81198268 100644
--- a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubChreApiTestExecutor.java
+++ b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubChreApiTestExecutor.java
@@ -25,7 +25,7 @@ import android.hardware.location.NanoAppBinary;
 
 import androidx.test.InstrumentationRegistry;
 
-import com.google.android.chre.utils.pigweed.ChreRpcClient;
+import com.google.android.utils.chre.pigweed.ChreRpcClient;
 import com.google.android.utils.chre.ChreApiTestUtil;
 import com.google.android.utils.chre.ChreTestUtil;
 
diff --git a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubEstimatedHostTimeTestExecutor.java b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubEstimatedHostTimeTestExecutor.java
index a657c954..a5ebf2a6 100644
--- a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubEstimatedHostTimeTestExecutor.java
+++ b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubEstimatedHostTimeTestExecutor.java
@@ -15,77 +15,79 @@
  */
 package com.google.android.chre.test.chqts;
 
+import static com.google.common.truth.Truth.assertThat;
+import static com.google.common.truth.Truth.assertWithMessage;
+
 import android.hardware.location.ContextHubInfo;
 import android.hardware.location.ContextHubManager;
 import android.hardware.location.NanoAppBinary;
 import android.os.SystemClock;
+import android.util.Log;
 
 import java.nio.ByteBuffer;
 import java.nio.ByteOrder;
+import java.util.ArrayList;
+import java.util.Collections;
+import java.util.List;
 
 /**
- * Verify estimated host time from nanoapp.
- *
- * Protocol:
- * host to app: ESTIMATED_HOST_TIME, no data
- * app to host: CONTINUE
- * host to app: CONTINUE, 64-bit time
- * app to host: SUCCESS
+ * Verify estimated host time from nanoapp is relatively accurate.
  *
+ * <p> The test is initiated from the nanoapp side which sends a message to the host. Starting from
+ * there host sends an empty message to the nanoapp and wait for the response.
+ * Once the response is received the time that CHRE received the message is calculated as
+ * message_received_time = message_sent_time + RTT/2. Then message_received_time is used to
+ * calculate a delta with the chreGetEstimatedHostTime(). This process is repeated to get a min
+ * value.
  */
 public class ContextHubEstimatedHostTimeTestExecutor extends ContextHubGeneralTestExecutor {
-    private static final long MAX_ALLOWED_TIME_DELTA_NS = 10000000;     // 10 ms.
-    private static final int NUM_RTT_SAMPLES = 5;
+    private static final int MAX_ALLOWED_NIN_DELTA_NS = 10_000_000;     // 10 ms.
+    private static final int NUM_OF_SAMPLES = 5;
     private long mMsgSendTimestampNs = 0;
-    private long mSmallestDelta = Long.MAX_VALUE;
-    private int mSamplesReceived = 0;
+    private static final String TAG = "EstimatedHostTimeTest";
+    private final List<Long> mDeltas;
+    private final long mNanoappId;
 
     public ContextHubEstimatedHostTimeTestExecutor(ContextHubManager manager, ContextHubInfo info,
             NanoAppBinary binary) {
         super(manager, info, new GeneralTestNanoApp(binary,
                 ContextHubTestConstants.TestNames.ESTIMATED_HOST_TIME));
+        mNanoappId = binary.getNanoAppId();
+        mDeltas = new ArrayList<>();
     }
 
     @Override
     protected void handleMessageFromNanoApp(long nanoAppId,
             ContextHubTestConstants.MessageType type, byte[] data) {
-        if (type != ContextHubTestConstants.MessageType.CONTINUE) {
-            fail("Unexpected message type " + type);
-        } else {
-            if (data.length != 0 && mMsgSendTimestampNs != 0) {
-                long currentTimestampNs = SystemClock.elapsedRealtimeNanos();
-                long chreTimestampNs = ByteBuffer.wrap(data)
-                        .order(ByteOrder.LITTLE_ENDIAN)
-                        .getLong();
+        assertThat(type).isEqualTo(ContextHubTestConstants.MessageType.CONTINUE);
 
-                // Identify the closest CHRE timestamp to the midpoint of RTT.
-                // This needs to be done across multiple rounds since RTT may not
-                // be evenly distributed in a single round
-                long middleTimestamp = (currentTimestampNs - mMsgSendTimestampNs) / 2
-                                       + mMsgSendTimestampNs;
-                long deltaNs = java.lang.Math.abs(chreTimestampNs - middleTimestamp);
+        if (mMsgSendTimestampNs != 0) {
+            assertThat(data.length).isGreaterThan(0);
+            long currentTimestampNs = SystemClock.elapsedRealtimeNanos();
+            long chreTimestampNs = ByteBuffer.wrap(data)
+                    .order(ByteOrder.LITTLE_ENDIAN)
+                    .getLong();
 
-                mSmallestDelta = java.lang.Math.min(mSmallestDelta, deltaNs);
-                mSamplesReceived += 1;
+            long middleTimestamp = (currentTimestampNs - mMsgSendTimestampNs) / 2
+                    + mMsgSendTimestampNs;
+            mDeltas.add(Math.abs(chreTimestampNs - middleTimestamp));
 
-                if (mSamplesReceived == NUM_RTT_SAMPLES) {
-                    if (mSmallestDelta < MAX_ALLOWED_TIME_DELTA_NS) {
-                        pass();
-                    } else {
-                        fail("Inconsistent CHRE/AP timestamps- Current TS: "
-                                + currentTimestampNs + " CHRE TS: " + chreTimestampNs
-                                + " start TS: " + mMsgSendTimestampNs + " Smallest Delta: "
-                                + mSmallestDelta);
-                    }
-                }
+            if (mDeltas.size() == NUM_OF_SAMPLES) {
+                Log.d(TAG, "Deltas (ns): " + mDeltas);
+                assertWithMessage(String.format(
+                        "The min delta between estimated host time and host real"
+                                + " time is larger than %d ms. abs of deltas: %s",
+                        MAX_ALLOWED_NIN_DELTA_NS, mDeltas)).that(Collections.min(mDeltas)).isAtMost(
+                        MAX_ALLOWED_NIN_DELTA_NS);
+                pass();
             }
+        }
 
-            if (mSamplesReceived < NUM_RTT_SAMPLES) {
-                mMsgSendTimestampNs = SystemClock.elapsedRealtimeNanos();
-                sendMessageToNanoAppOrFail(nanoAppId,
-                        ContextHubTestConstants.MessageType.CONTINUE.asInt(),
-                        new byte[0] /* data */);
-            }
+        if (mDeltas.size() < NUM_OF_SAMPLES) {
+            mMsgSendTimestampNs = SystemClock.elapsedRealtimeNanos();
+            sendMessageToNanoAppOrFail(mNanoappId,
+                    ContextHubTestConstants.MessageType.CONTINUE.asInt(), /* data= */
+                    new byte[0]);
         }
     }
 }
diff --git a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubInfoByIdTestExecutor.java b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubInfoByIdTestExecutor.java
index 47dca4d1..60bff985 100644
--- a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubInfoByIdTestExecutor.java
+++ b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubInfoByIdTestExecutor.java
@@ -15,6 +15,8 @@
  */
 package com.google.android.chre.test.chqts;
 
+import static com.google.common.truth.Truth.assertThat;
+
 import android.hardware.location.ContextHubInfo;
 import android.hardware.location.ContextHubManager;
 import android.hardware.location.NanoAppBinary;
@@ -25,16 +27,16 @@ import java.nio.ByteBuffer;
 import java.nio.ByteOrder;
 
 /**
- * Verify NanoApp info by appId/instanceId
+ * A test executor to verify that the nanoapp version can be queried by App ID or Instance ID.
  *
- * Protocol:
- * Host to App: mTestName, no data
- * App to Host: CONTINUE, no data
- * Host to App: CONTINUE, 32-bit app version
- * App to Host: SUCCESS, no data
+ * <p>This test verifies that the nanoapp version retrieved by the host-side API matches the
+ * nanoapp version retrieved by the nanoapp via CHRE APIs. The test nanoapp sends a message to
+ * this executor, which then retrieves the nanoapp version using the host-side API and sends it
+ * back to the nanoapp. The nanoapp then compares this version with the one it retrieved via CHRE
+ * APIs and verifies that they match.
  */
+
 public class ContextHubInfoByIdTestExecutor extends ContextHubGeneralTestExecutor {
-    private boolean mFirstMessage = true;
 
     public ContextHubInfoByIdTestExecutor(ContextHubManager manager, ContextHubInfo info,
             NanoAppBinary binary, ContextHubTestConstants.TestNames testName) {
@@ -44,10 +46,7 @@ public class ContextHubInfoByIdTestExecutor extends ContextHubGeneralTestExecuto
     @Override
     protected void handleMessageFromNanoApp(long nanoAppId,
             ContextHubTestConstants.MessageType type, byte[] data) {
-        if (type != ContextHubTestConstants.MessageType.CONTINUE) {
-            fail("Unexpected message type " + type);
-            return;
-        }
+        assertThat(type).isEqualTo(ContextHubTestConstants.MessageType.CONTINUE);
 
         int version =
                 ChreTestUtil.getNanoAppVersion(getContextHubManager(), getContextHubInfo(),
diff --git a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubNanoAppRequirementsTestExecutor.java b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubNanoAppRequirementsTestExecutor.java
index 5a590d4a..1866af56 100644
--- a/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubNanoAppRequirementsTestExecutor.java
+++ b/java/test/chqts/src/com/google/android/chre/test/chqts/ContextHubNanoAppRequirementsTestExecutor.java
@@ -26,6 +26,7 @@ import java.util.ArrayList;
 import java.util.List;
 
 import dev.chre.rpc.proto.ChreApiTest;
+
 public class ContextHubNanoAppRequirementsTestExecutor extends ContextHubChreApiTestExecutor {
     private final List<Long> mPreloadedNanoappIds;
 
@@ -48,19 +49,14 @@ public class ContextHubNanoAppRequirementsTestExecutor extends ContextHubChreApi
     private static final int MAX_AUDIO_SOURCES_TO_TRY = 10;
 
     /**
-     * Formats for audio that can be provided to a nanoapp. See enum chreAudioDataFormat in the
-     * CHRE API.
+     * Formats for audio that can be provided to a nanoapp. See enum chreAudioDataFormat in the CHRE
+     * API.
      */
     public enum ChreAudioDataFormat {
-        /**
-         * Unsigned, 8-bit u-Law encoded data as specified by ITU-T G.711.
-         */
+        /** Unsigned, 8-bit u-Law encoded data as specified by ITU-T G.711. */
         CHRE_AUDIO_DATA_FORMAT_8_BIT_U_LAW(0),
 
-        /**
-         * Signed, 16-bit linear PCM data. Endianness must be native to the local
-         * processor.
-         */
+        /** Signed, 16-bit linear PCM data. Endianness must be native to the local processor. */
         CHRE_AUDIO_DATA_FORMAT_16_BIT_SIGNED_PCM(1);
 
         private final int mId;
@@ -72,7 +68,7 @@ public class ContextHubNanoAppRequirementsTestExecutor extends ContextHubChreApi
         /**
          * Returns the ID.
          *
-         * @return int      the ID
+         * @return int the ID
          */
         public int getId() {
             return mId;
@@ -82,39 +78,31 @@ public class ContextHubNanoAppRequirementsTestExecutor extends ContextHubChreApi
     public ContextHubNanoAppRequirementsTestExecutor(NanoAppBinary nanoapp) {
         super(nanoapp);
         mPreloadedNanoappIds = new ArrayList<Long>();
-        for (long nanoappId: mContextHubManager.getPreloadedNanoAppIds(mContextHub)) {
+        for (long nanoappId : mContextHubManager.getPreloadedNanoAppIds(mContextHub)) {
             mPreloadedNanoappIds.add(nanoappId);
         }
     }
 
-    /**
-     * Tests for specific sensors for activity.
-     */
+    /** Tests for specific sensors for activity. */
     public void assertActivitySensors() throws Exception {
         findDefaultSensorAndAssertItExists(CHRE_SENSOR_TYPE_INSTANT_MOTION_DETECT);
         int accelerometerHandle =
                 findDefaultSensorAndAssertItExists(CHRE_SENSOR_TYPE_ACCELEROMETER);
-        getSensorInfoAndVerifyInterval(accelerometerHandle,
-                CHRE_SENSOR_ACCELEROMETER_INTERVAL_NS);
+        getSensorInfoAndVerifyInterval(accelerometerHandle, CHRE_SENSOR_ACCELEROMETER_INTERVAL_NS);
     }
 
-    /**
-     * Tests for specific sensors for movement.
-     */
+    /** Tests for specific sensors for movement. */
     public void assertMovementSensors() throws Exception {
         findDefaultSensorAndAssertItExists(CHRE_SENSOR_TYPE_ACCELEROMETER);
-        int gyroscopeHandle =
-                findDefaultSensorAndAssertItExists(CHRE_SENSOR_TYPE_GYROSCOPE);
-        getSensorInfoAndVerifyInterval(gyroscopeHandle,
-                CHRE_SENSOR_GYROSCOPE_INTERVAL_NS);
+        int gyroscopeHandle = findDefaultSensorAndAssertItExists(CHRE_SENSOR_TYPE_GYROSCOPE);
+        getSensorInfoAndVerifyInterval(gyroscopeHandle, CHRE_SENSOR_GYROSCOPE_INTERVAL_NS);
 
-        findAudioSourceAndAssertItExists(CHRE_AUDIO_MIN_BUFFER_SIZE_NS,
+        findAudioSourceAndAssertItExists(
+                CHRE_AUDIO_MIN_BUFFER_SIZE_NS,
                 ChreAudioDataFormat.CHRE_AUDIO_DATA_FORMAT_16_BIT_SIGNED_PCM);
     }
 
-    /**
-     * Tests for specific BLE capabilities.
-     */
+    /** Tests for specific BLE capabilities. */
     public void assertBleSensors() throws Exception {
         // TODO(b/262043286): Enable this once BLE is available
         /*
@@ -124,9 +112,7 @@ public class ContextHubNanoAppRequirementsTestExecutor extends ContextHubChreApi
         */
     }
 
-    /**
-     * Returns true if the nanoappId represents a preloaded nanoapp; false otherwise.
-     */
+    /** Returns true if the nanoappId represents a preloaded nanoapp; false otherwise. */
     public boolean isNanoappPreloaded(long nanoappId) {
         return mPreloadedNanoappIds.contains(nanoappId);
     }
@@ -134,61 +120,65 @@ public class ContextHubNanoAppRequirementsTestExecutor extends ContextHubChreApi
     /**
      * Finds the default sensor for the given type and asserts that it exists.
      *
-     * @param sensorType        the type of the sensor (constant)
-     *
-     * @return                  the handle of the sensor
+     * @param sensorType the type of the sensor (constant)
+     * @return the handle of the sensor
      */
     public int findDefaultSensorAndAssertItExists(int sensorType) throws Exception {
-        ChreApiTest.ChreSensorFindDefaultInput input = ChreApiTest.ChreSensorFindDefaultInput
-                .newBuilder().setSensorType(sensorType).build();
+        ChreApiTest.ChreSensorFindDefaultInput input =
+                ChreApiTest.ChreSensorFindDefaultInput.newBuilder()
+                        .setSensorType(sensorType)
+                        .build();
         ChreApiTest.ChreSensorFindDefaultOutput response =
-                ChreApiTestUtil.callUnaryRpcMethodSync(getRpcClient(),
-                        "chre.rpc.ChreApiTestService.ChreSensorFindDefault", input);
-        Assert.assertTrue("Did not find sensor with type: " + sensorType,
-                response.getFoundSensor());
+                ChreApiTestUtil.callUnaryRpcMethodSync(
+                        getRpcClient(), "chre.rpc.ChreApiTestService.ChreSensorFindDefault", input);
+        Assert.assertTrue(
+                "Did not find sensor with type: " + sensorType, response.getFoundSensor());
         return response.getSensorHandle();
     }
 
     /**
-     * Gets the sensor samping status and verifies the minimum interval from chreGetSensorInfo
-     * is less than or equal to the expected interval -> the sensor is at least as fast at sampling
-     * as is required.
+     * Gets the sensor samping status and verifies the minimum interval from chreGetSensorInfo is
+     * less than or equal to the expected interval -> the sensor is at least as fast at sampling as
+     * is required.
      *
-     * @param sensorHandle          the handle to the sensor
-     * @param expectedInterval      the true sampling interval
+     * @param sensorHandle the handle to the sensor
+     * @param expectedInterval the true sampling interval
      */
     public void getSensorInfoAndVerifyInterval(int sensorHandle, long expectedInterval)
             throws Exception {
         ChreApiTest.ChreHandleInput input =
-                ChreApiTest.ChreHandleInput.newBuilder()
-                .setHandle(sensorHandle).build();
+                ChreApiTest.ChreHandleInput.newBuilder().setHandle(sensorHandle).build();
         ChreApiTest.ChreGetSensorInfoOutput response =
-                ChreApiTestUtil.callUnaryRpcMethodSync(getRpcClient(),
-                        "chre.rpc.ChreApiTestService.ChreGetSensorInfo", input);
-        Assert.assertTrue("Failed to get sensor info for sensor with handle: " + sensorHandle,
+                ChreApiTestUtil.callUnaryRpcMethodSync(
+                        getRpcClient(), "chre.rpc.ChreApiTestService.ChreGetSensorInfo", input);
+        Assert.assertTrue(
+                "Failed to get sensor info for sensor with handle: " + sensorHandle,
                 response.getStatus());
-        Assert.assertTrue("The sensor with handle: " + sensorHandle
-                + " does not sample at a fast enough rate.",
+        Assert.assertTrue(
+                "The sensor with handle: "
+                        + sensorHandle
+                        + " does not sample at a fast enough rate.",
                 response.getMinInterval() <= expectedInterval);
     }
 
     /**
-     * Iterates through possible audio sources to find a source that has a minimum buffer
-     * size in ns of expectedMinBufferSizeNs and a format of format.
+     * Iterates through possible audio sources to find a source that has a minimum buffer size in ns
+     * of expectedMinBufferSizeNs and a format of format.
      *
-     * @param expectedMinBufferSizeInNs         the minimum buffer size in nanoseconds (ns)
-     * @param format                            the audio format enum
+     * @param expectedMinBufferSizeInNs the minimum buffer size in nanoseconds (ns)
+     * @param format the audio format enum
      */
-    public void findAudioSourceAndAssertItExists(long expectedMinBufferSizeNs,
-            ChreAudioDataFormat format) throws Exception {
+    public void findAudioSourceAndAssertItExists(
+            long expectedMinBufferSizeNs, ChreAudioDataFormat format) throws Exception {
         boolean foundAcceptableAudioSource = false;
         for (int i = 0; i < MAX_AUDIO_SOURCES_TO_TRY; ++i) {
             ChreApiTest.ChreHandleInput input =
-                    ChreApiTest.ChreHandleInput.newBuilder()
-                    .setHandle(i).build();
+                    ChreApiTest.ChreHandleInput.newBuilder().setHandle(i).build();
             ChreApiTest.ChreAudioGetSourceOutput response =
-                    ChreApiTestUtil.callUnaryRpcMethodSync(getRpcClient(),
-                            "chre.rpc.ChreApiTestService.ChreAudioGetSource", input);
+                    ChreApiTestUtil.callUnaryRpcMethodSync(
+                            getRpcClient(),
+                            "chre.rpc.ChreApiTestService.ChreAudioGetSource",
+                            input);
             if (response.getStatus()
                     && response.getMinBufferDuration() >= expectedMinBufferSizeNs
                     && response.getFormat() == format.getId()) {
@@ -196,9 +186,12 @@ public class ContextHubNanoAppRequirementsTestExecutor extends ContextHubChreApi
                 break;
             }
         }
-        Assert.assertTrue("Did not find an acceptable audio source with a minimum buffer "
-                + "size of " + expectedMinBufferSizeNs
-                + " ns and format: " + format.name(),
+        Assert.assertTrue(
+                "Did not find an acceptable audio source with a minimum buffer "
+                        + "size of "
+                        + expectedMinBufferSizeNs
+                        + " ns and format: "
+                        + format.name(),
                 foundAcceptableAudioSource);
     }
 
diff --git a/java/test/chqts/src/com/google/android/chre/test/chqts/multidevice/ContextHubMultiDeviceBleBeaconTestExecutor.java b/java/test/chqts/src/com/google/android/chre/test/chqts/multidevice/ContextHubMultiDeviceBleBeaconTestExecutor.java
index 2826a550..497a7db0 100644
--- a/java/test/chqts/src/com/google/android/chre/test/chqts/multidevice/ContextHubMultiDeviceBleBeaconTestExecutor.java
+++ b/java/test/chqts/src/com/google/android/chre/test/chqts/multidevice/ContextHubMultiDeviceBleBeaconTestExecutor.java
@@ -16,11 +16,17 @@
 
 package com.google.android.chre.test.chqts.multidevice;
 
+import android.bluetooth.le.ScanRecord;
+import android.bluetooth.le.ScanResult;
 import android.hardware.location.NanoAppBinary;
+import android.os.ParcelUuid;
+import android.util.Log;
 
 import com.google.android.chre.test.chqts.ContextHubBleTestExecutor;
 import com.google.android.utils.chre.ChreApiTestUtil;
+import com.google.protobuf.ByteString;
 
+import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 import java.util.concurrent.Future;
@@ -28,12 +34,16 @@ import java.util.concurrent.Future;
 import dev.chre.rpc.proto.ChreApiTest;
 
 public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTestExecutor {
+    private static final String TAG = "ContextHubMultiDeviceBleBeaconTestExecutor";
+
     private static final int NUM_EVENTS_TO_GATHER_PER_CYCLE = 1000;
 
     private static final long TIMEOUT_IN_S = 1;
 
     private static final long TIMEOUT_IN_NS = TIMEOUT_IN_S * 1000000000L;
 
+    private static final long TIMEOUT_IN_MS = 1000;
+
     private static final int NUM_EVENT_CYCLES_TO_GATHER = 5;
 
     /**
@@ -50,10 +60,13 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
      * Gathers BLE advertisement events from the nanoapp for NUM_EVENT_CYCLES_TO_GATHER
      * cycles, and for each cycle gathers for TIMEOUT_IN_NS or up to
      * NUM_EVENTS_TO_GATHER_PER_CYCLE events. This function returns true if all
-     * chreBleAdvertisingReport's contain advertisments for Google Eddystone and
+     * chreBleAdvertisingReport's contain advertisements for Service Data and
      * there is at least one advertisement, otherwise it returns false.
      */
-    public boolean gatherAndVerifyChreBleAdvertisementsForGoogleEddystone() throws Exception {
+    public List<ChreApiTest.ChreBleAdvertisingReport>
+                gatherAndVerifyChreBleAdvertisementsForServiceData() throws Exception {
+        List<ChreApiTest.ChreBleAdvertisingReport> reports = new ArrayList<>();
+
         for (int i = 0; i < NUM_EVENT_CYCLES_TO_GATHER; i++) {
             List<ChreApiTest.GeneralEventsMessage> events = gatherChreBleEvents();
             if (events == null) {
@@ -75,23 +88,25 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
                         continue;
                     }
 
-                    if (searchForGoogleEddystoneAdvertisement(data)) {
-                        return true;
+                    if (searchForServiceDataAdvertisement(data)) {
+                        reports.add(report);
                     }
                 }
             }
         }
-        return false;
+        return reports;
     }
 
     /**
      * Gathers BLE advertisement events from the nanoapp for NUM_EVENT_CYCLES_TO_GATHER
      * cycles, and for each cycle gathers for TIMEOUT_IN_NS or up to
      * NUM_EVENTS_TO_GATHER_PER_CYCLE events. This function returns true if all
-     * chreBleAdvertisingReport's contain advertisments with CHRE test manufacturer ID and
+     * chreBleAdvertisingReport's contain advertisements with CHRE test manufacturer ID and
      * there is at least one advertisement, otherwise it returns false.
      */
-    public boolean gatherAndVerifyChreBleAdvertisementsWithManufacturerData() throws Exception {
+    public List<ChreApiTest.ChreBleAdvertisingReport>
+                gatherAndVerifyChreBleAdvertisementsWithManufacturerData() throws Exception {
+        List<ChreApiTest.ChreBleAdvertisingReport> reports = new ArrayList<>();
         for (int i = 0; i < NUM_EVENT_CYCLES_TO_GATHER; i++) {
             List<ChreApiTest.GeneralEventsMessage> events = gatherChreBleEvents();
             if (events == null) {
@@ -114,12 +129,12 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
                     }
 
                     if (searchForManufacturerAdvertisement(data)) {
-                        return true;
+                        reports.add(report);
                     }
                 }
             }
         }
-        return false;
+        return reports;
     }
 
     /**
@@ -137,10 +152,96 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
     }
 
     /**
-     * Starts a BLE scan with the Google Eddystone filter.
+     * Gathers BLE advertisement events received from the Android scan which match
+     * the CHRE test Service Data UUID.
      */
-    public void chreBleStartScanSyncWithGoogleEddystoneFilter() throws Exception {
-        chreBleStartScanSync(getGoogleEddystoneScanFilter());
+    public List<ScanResult>
+                gatherAndVerifyAndroidBleAdvertisementsForServiceData() throws Exception {
+        List<ScanResult> scanResultsList = new ArrayList<>();
+        for (int i = 0; i < NUM_EVENT_CYCLES_TO_GATHER; i++) {
+            List<ScanResult> scanResults =
+                        gatherAndroidBleEvents(NUM_EVENT_CYCLES_TO_GATHER, TIMEOUT_IN_MS);
+
+            for (ScanResult result : scanResults) {
+                ScanRecord record = result.getScanRecord();
+                if (record == null) {
+                    Log.w(TAG, "ScanRecord was null, skipping result: " + result.toString());
+                    continue;
+                }
+                byte [] serviceData =
+                        record.getServiceData(new ParcelUuid(CHRE_TEST_SERVICE_DATA_UUID));
+                if (serviceData != null) {
+                    scanResultsList.add(result);
+                }
+            }
+        }
+        return scanResultsList;
+    }
+
+    /**
+     * Gathers BLE advertisement events received from the Android scan
+     * which match the CHRE test Manufacturer Data ID.
+     */
+    public List<ScanResult>
+                gatherAndVerifyAndroidBleAdvertisementsWithManufacturerData() throws Exception {
+        List<ScanResult> scanResultsList = new ArrayList<>();
+        for (int i = 0; i < NUM_EVENT_CYCLES_TO_GATHER; i++) {
+
+            List<ScanResult> events =
+                            gatherAndroidBleEvents(NUM_EVENT_CYCLES_TO_GATHER, TIMEOUT_IN_MS);
+
+            for (ScanResult result : events) {
+                ScanRecord record = result.getScanRecord();
+                if (record == null) {
+                    continue;
+                }
+                if (record.getManufacturerSpecificData(CHRE_BLE_TEST_MANUFACTURER_ID) != null) {
+                    scanResultsList.add(result);
+                }
+            }
+        }
+        return scanResultsList;
+    }
+
+    /**
+     * Gathers Android BLE advertisement events.
+     */
+    private List<ScanResult> gatherAndroidBleEvents(int maxEvents,
+                                                 long timeoutMillis) throws Exception {
+        List<ScanResult> gathered = new ArrayList<>();
+        long startTime = System.currentTimeMillis();
+
+        synchronized (mScanResults) {
+            Long nowTime = System.currentTimeMillis();
+            while ((nowTime - startTime) < timeoutMillis
+                                                                && gathered.size() < maxEvents) {
+
+                while (!mScanResults.isEmpty() && gathered.size() < maxEvents) {
+                    ScanResult result = mScanResults.remove(0);
+                    gathered.add(result);
+                }
+                if (gathered.size() >= maxEvents) {
+                    break;
+                }
+
+                long timeLeft = timeoutMillis - (nowTime - startTime);
+                if (timeLeft > 0) {
+                    try {
+                        mScanResults.wait(timeLeft);
+                    } catch (InterruptedException e) {
+                        Log.e(TAG, "Wait interrupted" + e.getMessage());
+                    }
+                }
+            }
+        }
+        return gathered;
+    }
+
+    /**
+     * Starts a BLE scan with the Service Data filter.
+     */
+    public void chreBleStartScanSyncWithServiceDataFilter() throws Exception {
+        chreBleStartScanSync(getTestServiceDataFilterChre());
     }
 
     /**
@@ -151,17 +252,32 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
     }
 
      /**
-     * Returns true if the data contains an advertisement for Google Eddystone,
+     *  Starts an Android BLE scan with Service Data filter.
+     */
+    public void androidBleStartScanSyncWithServiceDataFilter() throws Exception {
+        startBleScanOnHost(getTestServiceDataScanFilterHost());
+    }
+
+
+     /**
+     *  Starts an Android BLE scan with Google Manufacturer filter.
+     */
+    public void androidBleStartScanSyncWithManufacturerData() throws Exception {
+        startBleScanOnHost(getManufacturerDataScanFilterHost());
+    }
+
+     /**
+     * Returns true if the data contains an advertisement for Service Data,
      * otherwise returns false.
      */
-    private boolean searchForGoogleEddystoneAdvertisement(byte[] data) {
+    private boolean searchForServiceDataAdvertisement(byte[] data) {
         if (data.length < 2) {
             return false;
         }
 
         for (int j = 0; j < data.length - 1; ++j) {
-            if (Byte.compare(data[j], (byte) 0xAA) == 0
-                    && Byte.compare(data[j + 1], (byte) 0xFE) == 0) {
+            if (Byte.compare(data[j], (byte) 0xCD) == 0
+                    && Byte.compare(data[j + 1], (byte) 0xAB) == 0) {
                 return true;
             }
         }
@@ -186,4 +302,88 @@ public class ContextHubMultiDeviceBleBeaconTestExecutor extends ContextHubBleTes
 
         return false;
     }
+
+    /**
+     * Compares Android and CHRE advertisment
+     */
+    private boolean verifyBleAdvertisementsMatch(List<ScanResult> androidResults,
+                List<ChreApiTest.ChreBleAdvertisingReport> chreReports) throws Exception {
+
+        if (androidResults.isEmpty() || chreReports.isEmpty()) {
+            Log.e(TAG, "Advertisment was not received "
+                        + "androidResult.size()= " + androidResults.size()
+                        + "chreResult.size()= " + chreReports.size());
+            return false;
+        }
+
+        int minSize = Math.min(androidResults.size(), chreReports.size());
+        for (int i = 0; i < minSize; i++) {
+            ScanResult androidResult = androidResults.get(i);
+            ChreApiTest.ChreBleAdvertisingReport chreReport = chreReports.get(i);
+
+            String androidMac = androidResult.getDevice().getAddress();
+            String chreMac = formatMacAddress(chreReport.getAddress());
+
+            if (!androidMac.equalsIgnoreCase(chreMac)) {
+                Log.e(TAG, "Mac address mismatch at index " + i
+                            + " Android Mac= " + androidMac
+                            + " CHRE Mac= " + chreMac);
+                return false;
+            }
+            int androidTxPower = androidResult.getScanRecord().getTxPowerLevel();
+            int chreTxPower = chreReport.getTxPower();
+
+            if (androidTxPower != chreTxPower) {
+                Log.e(TAG, "Error power at index: " + i);
+                return false;
+            }
+        }
+
+        return true;
+    }
+
+    /**
+     * Formats the address byte code
+     */
+    private static String formatMacAddress(ByteString macBytes) {
+        byte[] macArray = macBytes.toByteArray();
+        StringBuilder macBuilder = new StringBuilder();
+        for (int i = 0; i < macArray.length; i++) {
+            macBuilder.append(String.format("%02X", macArray[i]));
+            if (i != macArray.length - 1) {
+                macBuilder.append(":");
+            }
+        }
+        return macBuilder.toString();
+    }
+
+    /**
+     * Starts Android/CHRE BLE event verification for Service Data
+     */
+    public boolean verifyAndroidAndChreServiceDataEventsMatch()
+                                                        throws Exception {
+
+        List<ScanResult> androidResults =
+                    gatherAndVerifyAndroidBleAdvertisementsForServiceData();
+        List<ChreApiTest.ChreBleAdvertisingReport> chreResults =
+                    gatherAndVerifyChreBleAdvertisementsForServiceData();
+
+        return verifyBleAdvertisementsMatch(androidResults, chreResults);
+
+    }
+
+    /**
+     * Starts Android/CHRE BLE event verification for Manufacturer Data
+     */
+    public boolean verifyAndroidAndChreManufacturerDataEventsMatch()
+                                                        throws Exception {
+
+        List<ScanResult> androidResults =
+                    gatherAndVerifyAndroidBleAdvertisementsWithManufacturerData();
+        List<ChreApiTest.ChreBleAdvertisingReport> chreResults =
+                    gatherAndVerifyChreBleAdvertisementsWithManufacturerData();
+
+        return verifyBleAdvertisementsMatch(androidResults, chreResults);
+
+    }
 }
diff --git a/java/test/cross_validation/src/com/google/android/chre/test/crossvalidator/ChreCrossValidatorWwan.java b/java/test/cross_validation/src/com/google/android/chre/test/crossvalidator/ChreCrossValidatorWwan.java
index 4b9472bf..f6c02357 100644
--- a/java/test/cross_validation/src/com/google/android/chre/test/crossvalidator/ChreCrossValidatorWwan.java
+++ b/java/test/cross_validation/src/com/google/android/chre/test/crossvalidator/ChreCrossValidatorWwan.java
@@ -197,8 +197,10 @@ public class ChreCrossValidatorWwan extends ChreCrossValidatorBase implements Ex
         Assert.assertNotNull("Timed out for cell info for AP", result);
 
         if (result.getErrorCode() != 0 || result.getErrorDetail() != null) {
-            Log.e(TAG, "AP requestCellInfoUpdate failed with detail="
-                    + result.getErrorDetail().getMessage());
+            Log.e(
+                    TAG,
+                    "AP requestCellInfoUpdate failed with detail="
+                            + result.getErrorDetail().getMessage());
             Assert.fail("AP requestCellInfoUpdate failed with errorCode=" + result.getErrorCode());
         }
 
@@ -528,6 +530,13 @@ public class ChreCrossValidatorWwan extends ChreCrossValidatorBase implements Ex
         return false;
     }
 
+    boolean compareMxc(int chreMxc, String apMxcStr) {
+        if (apMxcStr == null) {
+            return chreMxc == Integer.MAX_VALUE;
+        }
+        return chreMxc == Integer.parseInt(apMxcStr);
+    }
+
     boolean compareCellIdentityNr(
             ChreCrossValidationWwan.WwanCellInfo chreCellInfoNr, CellInfoNr apCellInfoNr) {
 
@@ -562,10 +571,6 @@ public class ChreCrossValidatorWwan extends ChreCrossValidatorBase implements Ex
                 chreCellInfoLte.getLte().getCellIdentity();
 
         if (chreCellInfoLte.getIsRegistered() != apCellInfoLte.isRegistered()
-                || chreCellIdentityLte.getMcc()
-                        != parseCellIdentityString(apCellIdentityLte.getMccString())
-                || chreCellIdentityLte.getMnc()
-                        != parseCellIdentityString(apCellIdentityLte.getMncString())
                 || chreCellIdentityLte.getCi() != apCellIdentityLte.getCi()
                 || chreCellIdentityLte.getPci() != apCellIdentityLte.getPci()
                 || chreCellIdentityLte.getTac() != apCellIdentityLte.getTac()
@@ -573,6 +578,12 @@ public class ChreCrossValidatorWwan extends ChreCrossValidatorBase implements Ex
             return false;
         }
 
+        // Mcc and Mnc will be null strings if they are invalid. Handle this case specially.
+        if (!compareMxc(chreCellIdentityLte.getMcc(), apCellIdentityLte.getMccString())
+                || !compareMxc(chreCellIdentityLte.getMnc(), apCellIdentityLte.getMncString())) {
+            return false;
+        }
+
         return true;
     }
 
@@ -582,10 +593,6 @@ public class ChreCrossValidatorWwan extends ChreCrossValidatorBase implements Ex
         ChreCrossValidationWwan.CellIdentityGsm chreCellIdentityGsm =
                 chreCellInfoGsm.getGsm().getCellIdentity();
         if (chreCellInfoGsm.getIsRegistered() != apCellInfoGsm.isRegistered()
-                || chreCellIdentityGsm.getMcc()
-                        != parseCellIdentityString(apCellIdentityGsm.getMccString())
-                || chreCellIdentityGsm.getMnc()
-                        != parseCellIdentityString(apCellIdentityGsm.getMncString())
                 || chreCellIdentityGsm.getLac() != apCellIdentityGsm.getLac()
                 || chreCellIdentityGsm.getCid() != apCellIdentityGsm.getCid()
                 || chreCellIdentityGsm.getArfcn() != apCellIdentityGsm.getArfcn()
@@ -593,6 +600,12 @@ public class ChreCrossValidatorWwan extends ChreCrossValidatorBase implements Ex
             return false;
         }
 
+        // Mcc and Mnc will be null strings if they are invalid. Handle this case specially.
+        if (!compareMxc(chreCellIdentityGsm.getMcc(), apCellIdentityGsm.getMccString())
+                || !compareMxc(chreCellIdentityGsm.getMnc(), apCellIdentityGsm.getMncString())) {
+            return false;
+        }
+
         return true;
     }
 
@@ -603,10 +616,6 @@ public class ChreCrossValidatorWwan extends ChreCrossValidatorBase implements Ex
         ChreCrossValidationWwan.CellIdentityWcdma chreCellIdentityWcdma =
                 chreCellInfoWcdma.getWcdma().getCellIdentity();
         if (chreCellInfoWcdma.getIsRegistered() != apCellInfoWcdma.isRegistered()
-                || chreCellIdentityWcdma.getMcc()
-                        != parseCellIdentityString(apCellIdentityWcdma.getMccString())
-                || chreCellIdentityWcdma.getMnc()
-                        != parseCellIdentityString(apCellIdentityWcdma.getMncString())
                 || chreCellIdentityWcdma.getLac() != apCellIdentityWcdma.getLac()
                 || chreCellIdentityWcdma.getCid() != apCellIdentityWcdma.getCid()
                 || chreCellIdentityWcdma.getPsc() != apCellIdentityWcdma.getPsc()
@@ -614,6 +623,13 @@ public class ChreCrossValidatorWwan extends ChreCrossValidatorBase implements Ex
             return false;
         }
 
+        // Mcc and Mnc will be null strings if they are invalid. Handle this case specially.
+        if (!compareMxc(chreCellIdentityWcdma.getMcc(), apCellIdentityWcdma.getMccString())
+                || !compareMxc(
+                        chreCellIdentityWcdma.getMnc(), apCellIdentityWcdma.getMncString())) {
+            return false;
+        }
+
         return true;
     }
 
@@ -702,7 +718,7 @@ public class ChreCrossValidatorWwan extends ChreCrossValidatorBase implements Ex
         public Throwable getErrorDetail() {
             return mDetail;
         }
-    };
+    }
 
     void requestCellInfoRefresh() {
         CellInfoCallback callback =
diff --git a/java/test/endpoint/Android.bp b/java/test/endpoint/Android.bp
index b35f55e1..5945568b 100644
--- a/java/test/endpoint/Android.bp
+++ b/java/test/endpoint/Android.bp
@@ -29,7 +29,10 @@ java_library {
 
     static_libs: [
         "androidx.test.rules",
+        "chre_pigweed_utils",
         "chre-test-utils",
+        "endpoint_echo_test_proto_java_lite",
+        "pw_rpc_java_client",
     ],
 
     sdk_version: "test_current",
diff --git a/java/test/endpoint/src/com/google/android/chre/test/endpoint/ContextHubEchoEndpointExecutor.java b/java/test/endpoint/src/com/google/android/chre/test/endpoint/ContextHubEndpointEchoExecutor.java
similarity index 79%
rename from java/test/endpoint/src/com/google/android/chre/test/endpoint/ContextHubEchoEndpointExecutor.java
rename to java/test/endpoint/src/com/google/android/chre/test/endpoint/ContextHubEndpointEchoExecutor.java
index 102d1107..3d42214d 100644
--- a/java/test/endpoint/src/com/google/android/chre/test/endpoint/ContextHubEchoEndpointExecutor.java
+++ b/java/test/endpoint/src/com/google/android/chre/test/endpoint/ContextHubEndpointEchoExecutor.java
@@ -38,7 +38,12 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.test.InstrumentationRegistry;
 
+import com.google.android.utils.chre.pigweed.ChreRpcClient;
+import com.google.android.utils.chre.ChreApiTestUtil;
 import com.google.android.utils.chre.ChreTestUtil;
+import com.google.protobuf.ByteString;
+import com.google.protobuf.Empty;
+import com.google.protobuf.MessageLite;
 
 import org.junit.Assert;
 import org.junit.Assume;
@@ -55,13 +60,20 @@ import java.util.concurrent.ScheduledThreadPoolExecutor;
 import java.util.concurrent.TimeUnit;
 import java.util.function.Consumer;
 
+import dev.chre.rpc.proto.EndpointEchoTest;
+import dev.pigweed.pw_rpc.Call.ServerStreamingFuture;
+import dev.pigweed.pw_rpc.Call.UnaryFuture;
+import dev.pigweed.pw_rpc.MethodClient;
+import dev.pigweed.pw_rpc.Service;
+import dev.pigweed.pw_rpc.UnaryResult;
+
 /**
  * A test to validate endpoint connection and messaging with an service on the device. The device
  * tested in this class is expected to register a test echo service, which must behave as a loopback
  * service which echoes back a message sent to it with identical payload.
  */
-public class ContextHubEchoEndpointExecutor {
-    private static final String TAG = "ContextHubEchoEndpointExecutor";
+public class ContextHubEndpointEchoExecutor {
+    private static final String TAG = "ContextHubEndpointEchoExecutor";
 
     /** The service descriptor for an echo service. */
     private static final String ECHO_SERVICE_DESCRIPTOR =
@@ -79,20 +91,17 @@ public class ContextHubEchoEndpointExecutor {
     @Nullable private final ContextHubInfo mContextHubInfo;
 
     /** The nanoapp binary which publishes a test echo service */
-    @Nullable private final NanoAppBinary mEchoServiceNanoappBinary;
+    @Nullable private final NanoAppBinary mEchoNanoappBinary;
 
     /** The ID of the above nanoapp */
-    private static final long ECHO_SERVICE_NANOAPP_ID = 0x476f6f6754fffffbL;
-
-    /** The nanoapp binary which connects to a host-side test echo service */
-    @Nullable private final NanoAppBinary mEchoClientNanoappBinary;
-
-    /** The ID of the above nanoapp */
-    private static final long ECHO_CLIENT_NANOAPP_ID = 0x476f6f6754000012L;
+    private static final long ECHO_SERVICE_NANOAPP_ID = 0x476f6f6754000012L;
 
     /** A local hub endpoint currently registered with the service. */
     private HubEndpoint mRegisteredEndpoint = null;
 
+    /** Whether the echo service nanoapp is loaded */
+    private boolean mIsEchoNanoappLoaded = false;
+
     static class TestLifecycleCallback implements HubEndpointLifecycleCallback {
         TestLifecycleCallback() {
             this(/* acceptSession= */ false);
@@ -189,35 +198,42 @@ public class ContextHubEchoEndpointExecutor {
             return mEndpointStoppedQueue.poll(TIMEOUT_DISCOVERY_SECONDS, TimeUnit.SECONDS);
         }
 
+        public void clear() {
+            mEndpointStartedQueue.clear();
+            mEndpointStoppedQueue.clear();
+        }
+
         private BlockingQueue<List<HubDiscoveryInfo>> mEndpointStartedQueue =
                 new ArrayBlockingQueue<>(1);
         private BlockingQueue<Pair<List<HubDiscoveryInfo>, Integer>> mEndpointStoppedQueue =
                 new ArrayBlockingQueue<>(1);
     }
 
-    public ContextHubEchoEndpointExecutor(ContextHubManager manager) {
-        this(
-                manager,
-                /* info= */ null,
-                /* echoServiceNanoappBinary= */ null,
-                /* echoClientNanoappBinary= */ null);
+    static class TestEchoMessageCallback implements HubEndpointMessageCallback {
+        @Override
+        public void onMessageReceived(HubEndpointSession session, HubMessage message) {
+            Log.d(TAG, "onMessageReceived: session=" + session + ", message=" + message);
+            session.sendMessage(message);
+        }
     }
 
-    public ContextHubEchoEndpointExecutor(
-            ContextHubManager manager,
-            ContextHubInfo info,
-            NanoAppBinary echoServiceNanoappBinary,
-            NanoAppBinary echoClientNanoappBinary) {
-        if (echoServiceNanoappBinary != null) {
-            Assert.assertEquals(echoServiceNanoappBinary.getNanoAppId(), ECHO_SERVICE_NANOAPP_ID);
-        }
-        if (echoClientNanoappBinary != null) {
-            Assert.assertEquals(echoServiceNanoappBinary.getNanoAppId(), ECHO_CLIENT_NANOAPP_ID);
+    public ContextHubEndpointEchoExecutor(ContextHubManager manager) {
+        this(manager, /* info= */ null, /* EchoNanoappBinary= */ null);
+    }
+
+    public ContextHubEndpointEchoExecutor(
+            ContextHubManager manager, ContextHubInfo info, NanoAppBinary EchoNanoappBinary) {
+        if (EchoNanoappBinary != null) {
+            Assert.assertEquals(EchoNanoappBinary.getNanoAppId(), ECHO_SERVICE_NANOAPP_ID);
         }
         mContextHubManager = manager;
         mContextHubInfo = info;
-        mEchoServiceNanoappBinary = echoServiceNanoappBinary;
-        mEchoClientNanoappBinary = echoClientNanoappBinary;
+        mEchoNanoappBinary = EchoNanoappBinary;
+        mIsEchoNanoappLoaded = false;
+    }
+
+    public void init() {
+        loadEchoNanoapp();
     }
 
     /** Deinitialization code that should be called in e.g. @After. */
@@ -225,16 +241,7 @@ public class ContextHubEchoEndpointExecutor {
         if (mRegisteredEndpoint != null) {
             unregisterRegisteredEndpointNoThrow();
         }
-        if (mContextHubInfo != null && mEchoServiceNanoappBinary != null) {
-            List<NanoAppState> stateList =
-                    ChreTestUtil.queryNanoAppsAssertSuccess(mContextHubManager, mContextHubInfo);
-            for (NanoAppState state : stateList) {
-                if (state.getNanoAppId() == ECHO_SERVICE_NANOAPP_ID) {
-                    ChreTestUtil.unloadNanoAppAssertSuccess(
-                            mContextHubManager, mContextHubInfo, state.getNanoAppId());
-                }
-            }
-        }
+        unloadEchoNanoapp();
     }
 
     /**
@@ -244,9 +251,12 @@ public class ContextHubEchoEndpointExecutor {
      * @return The list of hub discovery info which contains the echo service.
      */
     public List<HubDiscoveryInfo> getEchoServiceList() {
+        loadEchoNanoapp();
+
         List<HubDiscoveryInfo> infoList = new ArrayList<>();
         checkApiSupport(
                 (manager) -> infoList.addAll(manager.findEndpoints(ECHO_SERVICE_DESCRIPTOR)));
+        Assert.assertNotEquals(infoList.size(), 0);
         for (HubDiscoveryInfo info : infoList) {
             printHubDiscoveryInfo(info);
             HubEndpointInfo endpointInfo = info.getHubEndpointInfo();
@@ -347,9 +357,9 @@ public class ContextHubEchoEndpointExecutor {
 
             final int messageType = 1234;
             HubMessage message =
-                    new HubMessage.Builder(
-                            messageType,
-                            new byte[] {1, 2, 3, 4, 5}).setResponseRequired(true).build();
+                    new HubMessage.Builder(messageType, new byte[] {1, 2, 3, 4, 5})
+                            .setResponseRequired(true)
+                            .build();
             ContextHubTransaction<Void> txn = session.sendMessage(message);
             Assert.assertNotNull(txn);
             ContextHubTransaction.Response<Void> txnResponse =
@@ -387,6 +397,10 @@ public class ContextHubEchoEndpointExecutor {
      * @param executor An optional executor to invoke callbacks on.
      */
     private void doTestEndpointDiscovery(@Nullable Executor executor) throws Exception {
+        // Unload before registering the callback to ensure that the endpoint is not already
+        // registered.
+        unloadEchoNanoapp();
+
         TestDiscoveryCallback callback = new TestDiscoveryCallback();
         if (executor != null) {
             checkApiSupport(
@@ -399,6 +413,7 @@ public class ContextHubEchoEndpointExecutor {
                             manager.registerEndpointDiscoveryCallback(
                                     callback, ECHO_SERVICE_DESCRIPTOR));
         }
+        callback.clear();
 
         checkDynamicEndpointDiscovery(callback);
         checkApiSupport((manager) -> manager.unregisterEndpointDiscoveryCallback(callback));
@@ -420,6 +435,10 @@ public class ContextHubEchoEndpointExecutor {
      * @param executor An optional executor to invoke callbacks on.
      */
     private void doTestEndpointIdDiscovery(@Nullable Executor executor) throws Exception {
+        // Unload before registering the callback to ensure that the endpoint is not already
+        // registered.
+        unloadEchoNanoapp();
+
         TestDiscoveryCallback callback = new TestDiscoveryCallback();
         if (executor != null) {
             checkApiSupport(
@@ -432,6 +451,7 @@ public class ContextHubEchoEndpointExecutor {
                             manager.registerEndpointDiscoveryCallback(
                                     callback, ECHO_SERVICE_NANOAPP_ID));
         }
+        callback.clear();
 
         checkDynamicEndpointDiscovery(callback);
         checkApiSupport((manager) -> manager.unregisterEndpointDiscoveryCallback(callback));
@@ -442,64 +462,34 @@ public class ContextHubEchoEndpointExecutor {
      *
      * <p>For CHRE-capable devices, we will also confirm that a connection can be started from the
      * embedded client and echo works as intended. The echo client nanoapp is expected to open a
-     * session with the host-side service when the nanoapp is loaded, and sends a message to echo
-     * back to the nanoapp once the session is opened.
+     * session with the host-side service when the RPC starts, and sends a message to echo back to
+     * the nanoapp once the session is opened.
      */
     public void testApplicationEchoService() throws Exception {
-        Collection<HubServiceInfo> serviceList = new ArrayList<>();
-        HubServiceInfo.Builder builder =
-                new HubServiceInfo.Builder(
-                        ECHO_SERVICE_DESCRIPTOR,
-                        HubServiceInfo.FORMAT_CUSTOM,
-                        ECHO_SERVICE_MAJOR_VERSION,
-                        ECHO_SERVICE_MINOR_VERSION);
-        HubServiceInfo info = builder.build();
-        Assert.assertNotNull(info);
-        serviceList.add(info);
-
         TestLifecycleCallback callback = new TestLifecycleCallback(/* acceptSession= */ true);
-        TestMessageCallback messageCallback = new TestMessageCallback();
+        TestEchoMessageCallback messageCallback = new TestEchoMessageCallback();
         mRegisteredEndpoint =
                 registerDefaultEndpoint(
-                        callback, messageCallback, /* executor= */ null, serviceList);
+                        callback, messageCallback, /* executor= */ null, createEchoServiceInfo());
 
-        // TODO(b/385765805): Enable when ready
-        boolean isDynamicLoadingSupported = false;
-        if (isDynamicLoadingSupported
-                && mContextHubInfo != null
-                && mEchoClientNanoappBinary != null) {
-            ChreTestUtil.loadNanoAppAssertSuccess(
-                    mContextHubManager, mContextHubInfo, mEchoClientNanoappBinary);
-            HubEndpointSessionResult result = callback.waitForOpenSessionRequest();
-            Assert.assertNotNull(result);
-            Assert.assertTrue(result.isAccepted());
-            HubEndpointSession session = callback.waitForEndpointSession();
-            Assert.assertNotNull(session);
-            Log.d(TAG, "Session open: " + session);
+        if (mContextHubInfo == null || mEchoNanoappBinary == null) {
+            return; // skip rest of the test
+        }
 
-            HubMessage message = messageCallback.waitForMessage();
-            Assert.assertNotNull(message);
-            HubMessage outMessage =
-                    new HubMessage.Builder(message.getMessageType(), message.getMessageBody())
-                            .setResponseRequired(true)
-                            .build();
-            ContextHubTransaction<Void> txn = session.sendMessage(outMessage);
-            Assert.assertNotNull(txn);
-            ContextHubTransaction.Response<Void> txnResponse =
-                    txn.waitForResponse(TIMEOUT_MESSAGE_SECONDS, TimeUnit.SECONDS);
-            Assert.assertNotNull(txnResponse);
-            Assert.assertEquals(txnResponse.getResult(), ContextHubTransaction.RESULT_SUCCESS);
+        loadEchoNanoapp();
 
-            ChreTestUtil.unloadNanoAppAssertSuccess(
-                    mContextHubManager, mContextHubInfo, mEchoClientNanoappBinary.getNanoAppId());
-            Pair<HubEndpointSession, Integer> closeResult = callback.waitForCloseSession();
-            Assert.assertNotNull(closeResult);
-            Assert.assertNotNull(closeResult.first);
-            Log.d(TAG, "Session closed: " + closeResult.first);
-            Assert.assertEquals(session, closeResult.first);
-            Assert.assertNotNull(closeResult.second);
-            Assert.assertEquals(closeResult.second.intValue(), HubEndpoint.REASON_ENDPOINT_STOPPED);
-        }
+        ChreRpcClient rpcClient = getRpcClientForEchoNanoapp();
+        ChreApiTestUtil util = new ChreApiTestUtil();
+
+        List<EndpointEchoTest.ReturnStatus> responses =
+                util.callServerStreamingRpcMethodSync(
+                        rpcClient,
+                        "chre.rpc.EndpointEchoTestService.RunNanoappToHostTest",
+                        Empty.getDefaultInstance());
+        Assert.assertNotNull(responses);
+        Assert.assertEquals(responses.size(), 1);
+        EndpointEchoTest.ReturnStatus status = responses.get(0);
+        Assert.assertTrue(status.getErrorMessage(), status.getStatus());
 
         unregisterRegisteredEndpoint();
     }
@@ -602,31 +592,26 @@ public class ContextHubEchoEndpointExecutor {
     }
 
     private void checkDynamicEndpointDiscovery(TestDiscoveryCallback callback) throws Exception {
-        // TODO(b/385765805): Enable when ready
-        boolean isDynamicLoadingSupported = false;
-        if (isDynamicLoadingSupported
-                && mContextHubInfo != null
-                && mEchoServiceNanoappBinary != null) {
-            ChreTestUtil.loadNanoAppAssertSuccess(
-                    mContextHubManager, mContextHubInfo, mEchoServiceNanoappBinary);
-            List<HubDiscoveryInfo> discoveryList = callback.waitForStarted();
-            Assert.assertNotNull(discoveryList);
-            Assert.assertNotEquals(discoveryList.size(), 0);
-            Assert.assertTrue(checkNanoappInDiscoveryList(discoveryList));
-
-            ChreTestUtil.unloadNanoAppAssertSuccess(
-                    mContextHubManager, mContextHubInfo, mEchoServiceNanoappBinary.getNanoAppId());
-            Pair<List<HubDiscoveryInfo>, Integer> discoveryListAndReason =
-                    callback.waitForStopped();
-            Assert.assertNotNull(discoveryListAndReason);
-            discoveryList = discoveryListAndReason.first;
-            Assert.assertNotNull(discoveryList);
-            Assert.assertNotEquals(discoveryList.size(), 0);
-            Assert.assertTrue(checkNanoappInDiscoveryList(discoveryList));
-            Integer reason = discoveryListAndReason.second;
-            Assert.assertNotNull(reason);
-            Assert.assertEquals(reason.intValue(), HubEndpoint.REASON_ENDPOINT_STOPPED);
+        if (mContextHubInfo == null || mEchoNanoappBinary == null) {
+            return;
         }
+
+        loadEchoNanoapp();
+        List<HubDiscoveryInfo> discoveryList = callback.waitForStarted();
+        Assert.assertNotNull(discoveryList);
+        Assert.assertNotEquals(discoveryList.size(), 0);
+        Assert.assertTrue(checkNanoappInDiscoveryList(discoveryList));
+
+        unloadEchoNanoapp();
+        Pair<List<HubDiscoveryInfo>, Integer> discoveryListAndReason = callback.waitForStopped();
+        Assert.assertNotNull(discoveryListAndReason);
+        discoveryList = discoveryListAndReason.first;
+        Assert.assertNotNull(discoveryList);
+        Assert.assertNotEquals(discoveryList.size(), 0);
+        Assert.assertTrue(checkNanoappInDiscoveryList(discoveryList));
+        Integer reason = discoveryListAndReason.second;
+        Assert.assertNotNull(reason);
+        Assert.assertEquals(reason.intValue(), HubEndpoint.REASON_ENDPOINT_STOPPED);
     }
 
     private boolean checkNanoappInDiscoveryList(List<HubDiscoveryInfo> discoveryList) {
@@ -642,4 +627,52 @@ public class ContextHubEchoEndpointExecutor {
         }
         return false;
     }
+
+    private Collection<HubServiceInfo> createEchoServiceInfo() {
+        Collection<HubServiceInfo> serviceList = new ArrayList<>();
+        HubServiceInfo.Builder builder =
+                new HubServiceInfo.Builder(
+                        ECHO_SERVICE_DESCRIPTOR,
+                        HubServiceInfo.FORMAT_CUSTOM,
+                        ECHO_SERVICE_MAJOR_VERSION,
+                        ECHO_SERVICE_MINOR_VERSION);
+        HubServiceInfo info = builder.build();
+        Assert.assertNotNull(info);
+        serviceList.add(info);
+        return serviceList;
+    }
+
+    /** Loads the echo service nanoapp if it is not already loaded. */
+    private void loadEchoNanoapp() {
+        if (!mIsEchoNanoappLoaded && mContextHubInfo != null && mEchoNanoappBinary != null) {
+            ChreTestUtil.loadNanoAppAssertSuccess(
+                    mContextHubManager, mContextHubInfo, mEchoNanoappBinary);
+            mIsEchoNanoappLoaded = true;
+        }
+    }
+
+    /** Unloads the echo service nanoapp if it is already loaded. */
+    private void unloadEchoNanoapp() {
+        if (mIsEchoNanoappLoaded && mContextHubInfo != null && mEchoNanoappBinary != null) {
+            ChreTestUtil.unloadNanoAppAssertSuccess(
+                    mContextHubManager, mContextHubInfo, mEchoNanoappBinary.getNanoAppId());
+            mIsEchoNanoappLoaded = false;
+        }
+    }
+
+    private ChreRpcClient getRpcClientForEchoNanoapp() {
+        Service endpointEchoTestRpcService =
+                new Service(
+                        "chre.rpc.EndpointEchoTestService",
+                        Service.serverStreamingMethod(
+                                "RunNanoappToHostTest",
+                                Empty.parser(),
+                                EndpointEchoTest.ReturnStatus.parser()));
+        return new ChreRpcClient(
+                mContextHubManager,
+                mContextHubInfo,
+                mEchoNanoappBinary.getNanoAppId(),
+                List.of(endpointEchoTestRpcService),
+                /* callback= */ null);
+    }
 }
diff --git a/java/test/rpc_service/src/com/google/android/chre/test/rpc_service/ContextHubRpcServiceTestExecutor.java b/java/test/rpc_service/src/com/google/android/chre/test/rpc_service/ContextHubRpcServiceTestExecutor.java
index ce19f6a6..e0db9b81 100644
--- a/java/test/rpc_service/src/com/google/android/chre/test/rpc_service/ContextHubRpcServiceTestExecutor.java
+++ b/java/test/rpc_service/src/com/google/android/chre/test/rpc_service/ContextHubRpcServiceTestExecutor.java
@@ -30,7 +30,7 @@ import android.hardware.location.ContextHubManager;
 import android.hardware.location.NanoAppBinary;
 import android.hardware.location.NanoAppState;
 
-import com.google.android.chre.utils.pigweed.ChreRpcClient;
+import com.google.android.utils.chre.pigweed.ChreRpcClient;
 import com.google.android.utils.chre.ChreTestUtil;
 
 import org.junit.Assert;
diff --git a/java/test/utils/src/com/google/android/utils/chre/ChreApiTestUtil.java b/java/test/utils/src/com/google/android/utils/chre/ChreApiTestUtil.java
index c01b0209..d6d02851 100644
--- a/java/test/utils/src/com/google/android/utils/chre/ChreApiTestUtil.java
+++ b/java/test/utils/src/com/google/android/utils/chre/ChreApiTestUtil.java
@@ -20,7 +20,7 @@ import android.content.Context;
 
 import androidx.annotation.NonNull;
 
-import com.google.android.chre.utils.pigweed.ChreRpcClient;
+import com.google.android.utils.chre.pigweed.ChreRpcClient;
 import com.google.common.io.ByteSink;
 import com.google.common.io.Files;
 import com.google.protobuf.ByteString;
diff --git a/java/test/utils/src/com/google/android/utils/chre/ChreTestUtil.java b/java/test/utils/src/com/google/android/utils/chre/ChreTestUtil.java
index d05dc5b6..b9b2e50f 100644
--- a/java/test/utils/src/com/google/android/utils/chre/ChreTestUtil.java
+++ b/java/test/utils/src/com/google/android/utils/chre/ChreTestUtil.java
@@ -130,6 +130,17 @@ public class ChreTestUtil {
      */
     public static boolean unloadNanoApp(
             ContextHubManager manager, ContextHubInfo info, long nanoAppId) {
+        List<NanoAppState> nanoApps = queryNanoAppsAssertSuccess(manager, info);
+        boolean isLoaded = false;
+        for (NanoAppState state : nanoApps) {
+            if (state.getNanoAppId() == nanoAppId) {
+                isLoaded = true;
+                break;
+            }
+        }
+        if (!isLoaded) {
+            return true;
+        }
         ContextHubTransaction<Void> txn = manager.unloadNanoApp(info, nanoAppId);
         ContextHubTransaction.Response<Void> resp = null;
         try {
diff --git a/java/test/utils/src/com/google/android/utils/chre/ContextHubHostTestUtil.java b/java/test/utils/src/com/google/android/utils/chre/ContextHubHostTestUtil.java
index ba1b8a00..991e736f 100644
--- a/java/test/utils/src/com/google/android/utils/chre/ContextHubHostTestUtil.java
+++ b/java/test/utils/src/com/google/android/utils/chre/ContextHubHostTestUtil.java
@@ -15,6 +15,10 @@
  */
 package com.google.android.utils.chre;
 
+import static com.google.common.truth.Truth.assertWithMessage;
+
+import static org.junit.Assume.assumeTrue;
+
 import android.content.Context;
 import android.content.pm.PackageManager;
 import android.hardware.location.ContextHubInfo;
@@ -28,7 +32,6 @@ import androidx.test.InstrumentationRegistry;
 import com.android.compatibility.common.util.DynamicConfigDeviceSide;
 
 import org.junit.Assert;
-import org.junit.Assume;
 import org.xmlpull.v1.XmlPullParserException;
 
 import java.io.File;
@@ -48,7 +51,7 @@ public class ContextHubHostTestUtil {
      * The names of the dynamic configs corresponding to each test suite.
      */
     public static final String[] DEVICE_DYNAMIC_CONFIG_NAMES =
-            new String[] {"GtsGmscoreHostTestCases", "GtsLocationContextMultiDeviceTestCases"};
+            new String[]{"GtsGmscoreHostTestCases", "GtsLocationContextMultiDeviceTestCases"};
 
     public static String multiDeviceExternalNanoappPath = null;
 
@@ -92,14 +95,14 @@ public class ContextHubHostTestUtil {
     /**
      * Waits on a CountDownLatch or assert if it timed out or was interrupted.
      *
-     * @param latch                       the CountDownLatch
-     * @param timeout                     the timeout duration
-     * @param unit                        the timeout unit
-     * @param timeoutErrorMessage         the message to display on timeout assert
+     * @param latch               the CountDownLatch
+     * @param timeout             the timeout duration
+     * @param unit                the timeout unit
+     * @param timeoutErrorMessage the message to display on timeout assert
      */
     public static void awaitCountDownLatchAssertOnFailure(
             CountDownLatch latch, long timeout, TimeUnit unit, String timeoutErrorMessage)
-                    throws InterruptedException {
+            throws InterruptedException {
         boolean result = latch.await(timeout, unit);
         Assert.assertTrue(timeoutErrorMessage, result);
     }
@@ -130,8 +133,8 @@ public class ContextHubHostTestUtil {
     /**
      * Read the nanoapp to an InputStream object.
      *
-     * @param context   the Context to find the asset resources
-     * @param fullName  the fullName of the nanoapp
+     * @param context  the Context to find the asset resources
+     * @param fullName the fullName of the nanoapp
      * @return the InputStream of the nanoapp
      */
     public static InputStream getNanoAppInputStream(Context context, String fullName) {
@@ -142,7 +145,7 @@ public class ContextHubHostTestUtil {
                     new FileInputStream(new File(fullName));
         } catch (IOException e) {
             Assert.fail("Could not find asset " + fullName + ": "
-                        + e.toString());
+                    + e.toString());
         }
         return inputStream;
     }
@@ -216,6 +219,28 @@ public class ContextHubHostTestUtil {
         return false;
     }
 
+    /**
+     * Determines if the device under test should run the aoc v2 asset directory.
+     *
+     * @return true if the device is in the aoc v2 device list.
+     */
+    private static boolean deviceInAocV2List() {
+        DynamicConfigDeviceSide deviceDynamicConfig = getDynamicConfig();
+        List<String> configValues = deviceDynamicConfig.getValues("chre_aoc_v2_list");
+        Assert.assertTrue("Could not find aoc v2 device list from dynamic config",
+                configValues != null);
+
+        String deviceName = Build.DEVICE;
+        for (String element : configValues) {
+            String[] delimited = element.split(",");
+            if (delimited.length != 0 && delimited[0].equals(deviceName)) {
+                return true;
+            }
+        }
+
+        return false;
+    }
+
     /**
      * Returns the path of the nanoapps for a CHRE implementation using the platform ID.
      *
@@ -240,6 +265,9 @@ public class ContextHubHostTestUtil {
             String[] delimited = element.split(",");
             if (delimited.length == 2 && delimited[0].equals(platformIdHexString)) {
                 path = delimited[1];
+                if (path.equals("CHRE_on_AOCGoogle") && deviceInAocV2List()) {
+                    path = "CHRE_on_AOCv2Google";
+                }
                 break;
             }
         }
@@ -284,11 +312,11 @@ public class ContextHubHostTestUtil {
 
     /**
      * @return the device side dynamic config for GtsGmscoreHostTestCases or
-     *         GtsLocationContextMultiDeviceTestCases
+     * GtsLocationContextMultiDeviceTestCases
      */
     private static DynamicConfigDeviceSide getDynamicConfig() {
         DynamicConfigDeviceSide deviceDynamicConfig = null;
-        for (String deviceDynamicConfigName: DEVICE_DYNAMIC_CONFIG_NAMES) {
+        for (String deviceDynamicConfigName : DEVICE_DYNAMIC_CONFIG_NAMES) {
             try {
                 deviceDynamicConfig = new DynamicConfigDeviceSide(deviceDynamicConfigName);
             } catch (XmlPullParserException e) {
@@ -326,37 +354,14 @@ public class ContextHubHostTestUtil {
      * @param manager The ContextHubManager on this app.
      */
     public static void checkDeviceShouldRunTest(Context context, ContextHubManager manager) {
-        boolean supportsContextHub;
-        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
-            supportsContextHub =
-                    context.getPackageManager().hasSystemFeature(
+        assumeTrue("Device is in the denylist, skipping test", !deviceInDenylist());
+        boolean supportsContextHub =
+                context.getPackageManager().hasSystemFeature(
                         PackageManager.FEATURE_CONTEXT_HUB);
-            Assert.assertTrue("ContextHubManager must be null if feature is not supported.",
-                    supportsContextHub || manager == null);
-        } else {
-            supportsContextHub = (manager != null);
-        }
-        Assume.assumeTrue("Device does not support Context Hub, skipping test", supportsContextHub);
-
-        int numContextHubs;
-        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
-            numContextHubs = manager.getContextHubs().size();
-        } else {
-            int[] handles = manager.getContextHubHandles();
-            Assert.assertNotNull(handles);
-            numContextHubs = handles.length;
-        }
-
-        // Only use allowlist logic on builds that do not require the Context Hub feature flag.
-        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
-            // Use allowlist on platforms that reports no Context Hubs to prevent false positive
-            // failures on devices that do not actually support CHRE.
-            Assume.assumeTrue(
-                    "Device not in allowlist and does not have Context Hub, skipping test",
-                    numContextHubs != 0 || deviceInAllowlist());
-        }
-
+        assumeTrue("Device does not support Context Hub, skipping test", supportsContextHub);
+        assertWithMessage("ContextHubManager must not be null if the feature is supported").that(
+                manager).isNotNull();
         // Use a denylist on platforms that should not run CHQTS.
-        Assume.assumeTrue("Device is in denylist, skipping test", !deviceInDenylist());
+
     }
 }
diff --git a/java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreCallbackHandler.java b/java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreCallbackHandler.java
similarity index 86%
rename from java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreCallbackHandler.java
rename to java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreCallbackHandler.java
index 291ebf7d..51116758 100644
--- a/java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreCallbackHandler.java
+++ b/java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreCallbackHandler.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.android.chre.utils.pigweed;
+package com.google.android.utils.chre.pigweed;
 
 import static android.hardware.location.ContextHubManager.AUTHORIZATION_DENIED;
 import static android.hardware.location.ContextHubManager.AUTHORIZATION_GRANTED;
@@ -39,8 +39,8 @@ public class ChreCallbackHandler extends ContextHubClientCallback {
 
     /**
      * @param nanoappId ID of the RPC Server nanoapp
-     * @param callback  The callbacks receiving messages and life-cycle events from nanoapps,
-     *                  nullable.
+     * @param callback The callbacks receiving messages and life-cycle events from nanoapps,
+     *     nullable.
      */
     public ChreCallbackHandler(long nanoappId, ContextHubClientCallback callback) {
         mNanoappId = nanoappId;
@@ -50,7 +50,7 @@ public class ChreCallbackHandler extends ContextHubClientCallback {
     /**
      * Completes the initialization.
      *
-     * @param rpcClient     The Pigweed RPC client, non null
+     * @param rpcClient The Pigweed RPC client, non null
      * @param channelOutput The ChannelOutput used by Pigweed, non null
      */
     public void lateInit(Client rpcClient, ChreChannelOutput channelOutput) {
@@ -58,9 +58,7 @@ public class ChreCallbackHandler extends ContextHubClientCallback {
         mChannelOutput = Objects.requireNonNull(channelOutput);
     }
 
-    /**
-     * This method passes the message to pigweed RPC for decoding.
-     */
+    /** This method passes the message to pigweed RPC for decoding. */
     @Override
     public void onMessageFromNanoApp(ContextHubClient client, NanoAppMessage message) {
         if (mRpcClient != null && message.getNanoAppId() == mNanoappId) {
@@ -71,9 +69,7 @@ public class ChreCallbackHandler extends ContextHubClientCallback {
         }
     }
 
-    /**
-     * This method ensures all outstanding RPCs are canceled.
-     */
+    /** This method ensures all outstanding RPCs are canceled. */
     @Override
     public void onHubReset(ContextHubClient client) {
         closeChannel();
@@ -82,9 +78,7 @@ public class ChreCallbackHandler extends ContextHubClientCallback {
         }
     }
 
-    /**
-     * This method ensures all outstanding RPCs are canceled.
-     */
+    /** This method ensures all outstanding RPCs are canceled. */
     @Override
     public void onNanoAppAborted(ContextHubClient client, long nanoappId, int abortCode) {
         if (nanoappId == mNanoappId) {
@@ -102,9 +96,7 @@ public class ChreCallbackHandler extends ContextHubClientCallback {
         }
     }
 
-    /**
-     * This method ensures all outstanding RPCs are canceled.
-     */
+    /** This method ensures all outstanding RPCs are canceled. */
     @Override
     public void onNanoAppUnloaded(ContextHubClient client, long nanoappId) {
         if (nanoappId == mNanoappId) {
@@ -122,9 +114,7 @@ public class ChreCallbackHandler extends ContextHubClientCallback {
         }
     }
 
-    /**
-     * This method ensures all outstanding RPCs are canceled.
-     */
+    /** This method ensures all outstanding RPCs are canceled. */
     @Override
     public void onNanoAppDisabled(ContextHubClient client, long nanoappId) {
         if (nanoappId == mNanoappId) {
@@ -140,8 +130,8 @@ public class ChreCallbackHandler extends ContextHubClientCallback {
      * will fail until the client becomes authorized again.
      */
     @Override
-    public void onClientAuthorizationChanged(ContextHubClient client, long nanoappId,
-            int authorization) {
+    public void onClientAuthorizationChanged(
+            ContextHubClient client, long nanoappId, int authorization) {
         if (mChannelOutput != null && nanoappId == mNanoappId) {
             if (authorization == AUTHORIZATION_DENIED) {
                 mChannelOutput.setAuthDenied(true /* denied */);
diff --git a/java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreChannelOutput.java b/java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreChannelOutput.java
similarity index 84%
rename from java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreChannelOutput.java
rename to java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreChannelOutput.java
index 1e79693b..34716305 100644
--- a/java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreChannelOutput.java
+++ b/java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreChannelOutput.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.android.chre.utils.pigweed;
+package com.google.android.utils.chre.pigweed;
 
 import android.hardware.location.ContextHubClient;
 import android.hardware.location.ContextHubTransaction;
@@ -29,9 +29,7 @@ import dev.pigweed.pw_rpc.ChannelOutputException;
  * of Pigweed RPC to make it more friendly to use with CHRE APIs.
  */
 public class ChreChannelOutput implements Channel.Output {
-    /**
-     * Message type to use for RPC messages.
-     */
+    /** Message type to use for RPC messages. */
     public static final int CHRE_MESSAGE_TYPE_RPC = 0x7FFFFFF5;
 
     // 1 denotes that a host endpoint is the client that created the channel.
@@ -48,13 +46,11 @@ public class ChreChannelOutput implements Channel.Output {
         mNanoappId = nanoappId;
     }
 
-    /**
-     * This method MUST NOT be called directly from users of this class.
-     */
+    /** This method MUST NOT be called directly from users of this class. */
     @Override
     public void send(byte[] packet) throws ChannelOutputException {
-        NanoAppMessage message = NanoAppMessage.createMessageToNanoApp(mNanoappId,
-                CHRE_MESSAGE_TYPE_RPC, packet);
+        NanoAppMessage message =
+                NanoAppMessage.createMessageToNanoApp(mNanoappId, CHRE_MESSAGE_TYPE_RPC, packet);
         if (mAuthDenied.get()
                 || ContextHubTransaction.RESULT_SUCCESS != mClient.sendMessageToNanoApp(message)) {
             throw new ChannelOutputException();
@@ -62,16 +58,16 @@ public class ChreChannelOutput implements Channel.Output {
     }
 
     /**
-     * @return Channel ID to use for all Channels that use this output to send
-     * messages to a nanoapp.
+     * @return Channel ID to use for all Channels that use this output to send messages to a
+     *     nanoapp.
      */
     public int getChannelId() {
         return (CHANNEL_ID_HOST_CLIENT | mClient.getId());
     }
 
     /**
-     * Used to indicate whether the particular nanoapp cannot be communicated
-     * with any more (e.g. due to permissions loss).
+     * Used to indicate whether the particular nanoapp cannot be communicated with any more (e.g.
+     * due to permissions loss).
      */
     void setAuthDenied(boolean denied) {
         mAuthDenied.set(denied);
diff --git a/java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreIntentHandler.java b/java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreIntentHandler.java
similarity index 89%
rename from java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreIntentHandler.java
rename to java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreIntentHandler.java
index 91cdcf28..c8a06577 100644
--- a/java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreIntentHandler.java
+++ b/java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreIntentHandler.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.android.chre.utils.pigweed;
+package com.google.android.utils.chre.pigweed;
 
 import static android.hardware.location.ContextHubManager.AUTHORIZATION_DENIED;
 import static android.hardware.location.ContextHubManager.AUTHORIZATION_GRANTED;
@@ -27,22 +27,20 @@ import java.util.Objects;
 
 import dev.pigweed.pw_rpc.Client;
 
-/**
- * Handles RPC events in CHRE intent.
- */
+/** Handles RPC events in CHRE intent. */
 public class ChreIntentHandler {
     private static final String TAG = "ChreIntentHandler";
 
     /**
      * Handles CHRE intents.
      *
-     * @param intent        the intent, non null
-     * @param nanoappId     ID of the RPC Server nanoapp
-     * @param rpcClient     The Pigweed RPC client, non null
+     * @param intent the intent, non null
+     * @param nanoappId ID of the RPC Server nanoapp
+     * @param rpcClient The Pigweed RPC client, non null
      * @param channelOutput The ChannelOutput used by Pigweed, non null
      */
-    public static void handle(Intent intent, long nanoappId, Client rpcClient,
-            ChreChannelOutput channelOutput) {
+    public static void handle(
+            Intent intent, long nanoappId, Client rpcClient, ChreChannelOutput channelOutput) {
         Objects.requireNonNull(intent);
         Objects.requireNonNull(rpcClient);
         Objects.requireNonNull(channelOutput);
diff --git a/java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreRpcClient.java b/java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreRpcClient.java
similarity index 72%
rename from java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreRpcClient.java
rename to java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreRpcClient.java
index 205482ee..f5e62d2a 100644
--- a/java/utils/pigweed/src/com/google/android/chre/utils/pigweed/ChreRpcClient.java
+++ b/java/utils/pigweed/src/com/google/android/utils/chre/pigweed/ChreRpcClient.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.android.chre.utils.pigweed;
+package com.google.android.utils.chre.pigweed;
 
 import android.content.Intent;
 import android.hardware.location.ContextHubClient;
@@ -34,7 +34,7 @@ import dev.pigweed.pw_rpc.Service;
 /**
  * Pigweed RPC Client Helper.
  *
- * See https://g3doc.corp.google.com/location/lbs/contexthub/g3doc/nanoapps/pw_rpc_host.md
+ * <p>See https://g3doc.corp.google.com/location/lbs/contexthub/g3doc/nanoapps/pw_rpc_host.md
  */
 public class ChreRpcClient {
 
@@ -52,17 +52,20 @@ public class ChreRpcClient {
     /**
      * Creates a ContextHubClient and initializes the helper.
      *
-     * Use this constructor for persistent clients using callbacks.
+     * <p>Use this constructor for persistent clients using callbacks.
      *
-     * @param manager         The context manager used to create a client, non null
-     * @param info            Context hub info, non null
+     * @param manager The context manager used to create a client, non null
+     * @param info Context hub info, non null
      * @param serverNanoappId The ID of the RPC server nanoapp
-     * @param services        The list of services provided by the server, non null
-     * @param callback        The callbacks receiving messages and life-cycle events from nanoapps,
-     *                        nullable
+     * @param services The list of services provided by the server, non null
+     * @param callback The callbacks receiving messages and life-cycle events from nanoapps,
+     *     nullable
      */
-    public ChreRpcClient(ContextHubManager manager, ContextHubInfo info,
-            long serverNanoappId, List<Service> services,
+    public ChreRpcClient(
+            ContextHubManager manager,
+            ContextHubInfo info,
+            long serverNanoappId,
+            List<Service> services,
             ContextHubClientCallback callback) {
         Objects.requireNonNull(manager);
         Objects.requireNonNull(info);
@@ -79,16 +82,16 @@ public class ChreRpcClient {
     /**
      * Initializes the helper
      *
-     * Use this constructor for non-persistent clients using intents.
+     * <p>Use this constructor for non-persistent clients using intents.
      *
-     * handleIntent() must be called with any CHRE intent received by the BroadcastReceiver.
+     * <p>handleIntent() must be called with any CHRE intent received by the BroadcastReceiver.
      *
      * @param contextHubClient The context hub client providing the RPC server nanoapp, non null
-     * @param serverNanoappId  The ID of the RPC server nanoapp
-     * @param services         The list of services provided by the server, non null
+     * @param serverNanoappId The ID of the RPC server nanoapp
+     * @param services The list of services provided by the server, non null
      */
-    public ChreRpcClient(ContextHubClient contextHubClient, long serverNanoappId,
-            List<Service> services) {
+    public ChreRpcClient(
+            ContextHubClient contextHubClient, long serverNanoappId, List<Service> services) {
         mContextHubClient = Objects.requireNonNull(contextHubClient);
         Objects.requireNonNull(services);
         mServerNanoappId = serverNanoappId;
@@ -100,14 +103,14 @@ public class ChreRpcClient {
     /**
      * Returns whether the state matches the server nanoapp and the service is provided.
      *
-     * @param state           A nanoapp state
+     * @param state A nanoapp state
      * @param serverNanoappId The ID of the RPC server nanoapp
-     * @param serviceId       ID of the service
-     * @param serviceVersion  Version of the service
+     * @param serviceId ID of the service
+     * @param serviceVersion Version of the service
      * @return the state matches the server nanoapp and the service is provided
      */
-    public static boolean hasService(NanoAppState state, long serverNanoappId, long serviceId,
-            int serviceVersion) {
+    public static boolean hasService(
+            NanoAppState state, long serverNanoappId, long serviceId, int serviceVersion) {
         if (state.getNanoAppId() != serverNanoappId) {
             return false;
         }
@@ -130,16 +133,12 @@ public class ChreRpcClient {
         ChreIntentHandler.handle(intent, mServerNanoappId, mRpcClient, mChannelOutput);
     }
 
-    /**
-     * Returns the context hub client.
-     */
+    /** Returns the context hub client. */
     public ContextHubClient getContextHubClient() {
         return mContextHubClient;
     }
 
-    /**
-     * Shorthand for closing the underlying ContextHubClient.
-     */
+    /** Shorthand for closing the underlying ContextHubClient. */
     public void close() {
         mContextHubClient.close();
     }
@@ -147,7 +146,7 @@ public class ChreRpcClient {
     /**
      * Returns a MethodClient.
      *
-     * Use the client to invoke the service.
+     * <p>Use the client to invoke the service.
      *
      * @param methodName the method name as "package.Service.Method" or "package.Service/Method"
      * @return The MethodClient instance
diff --git a/pal/include/chre/pal/system.h b/pal/include/chre/pal/system.h
index 20570047..7ae7a7b0 100644
--- a/pal/include/chre/pal/system.h
+++ b/pal/include/chre/pal/system.h
@@ -101,6 +101,11 @@ struct chrePalSystemApi {
    * @see chreHeapFree
    */
   void (*memoryFree)(void *pointer);
+
+  /**
+   * Ensures the PAL can access DRAM memory.
+   */
+  void (*forceDramAccess)(void);
 };
 
 #ifdef __cplusplus
diff --git a/platform/arm/nanoapp_loader.cc b/platform/arm/nanoapp_loader.cc
index 2eaa9d10..571eb67b 100644
--- a/platform/arm/nanoapp_loader.cc
+++ b/platform/arm/nanoapp_loader.cc
@@ -42,8 +42,8 @@ bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
       for (i = 0; i < nRelocs; ++i) {
         ElfRel *curr = &reloc[i];
         int relocType = ELFW_R_TYPE(curr->r_info);
-        ElfAddr *addr = reinterpret_cast<ElfAddr *>(mMapping + curr->r_offset);
-
+        ElfAddr *addr =
+            reinterpret_cast<ElfAddr *>(mMapping.getPhyAddrOf(curr->r_offset));
         switch (relocType) {
           case R_ARM_RELATIVE:
             LOGV("Resolving ARM_RELATIVE at offset %lx",
@@ -51,7 +51,8 @@ bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
             // TODO(b/155512914): When we move to DRAM allocations, we need to
             // check if the above address is in a Read-Only section of memory,
             // and give it temporary write permission if that is the case.
-            *addr += reinterpret_cast<uintptr_t>(mMapping);
+            mMapping.replace(curr->r_offset, reinterpret_cast<ElfAddr>(
+                                                 mMapping.getPhyAddrOf(*addr)));
             break;
 
           case R_ARM_ABS32: {
@@ -61,7 +62,7 @@ bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
             auto *dynamicSymbolTable =
                 reinterpret_cast<ElfSym *>(mDynamicSymbolTablePtr);
             ElfSym *sym = &dynamicSymbolTable[posInSymbolTable];
-            *addr = reinterpret_cast<uintptr_t>(mMapping + sym->st_value);
+            *addr = mMapping.getPhyAddrOf(sym->st_value);
             break;
           }
 
@@ -116,7 +117,7 @@ bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
 bool NanoappLoader::resolveGot() {
   ElfAddr *addr;
   ElfRel *reloc = reinterpret_cast<ElfRel *>(
-      mMapping + getDynEntry(getDynamicHeader(), DT_JMPREL));
+      mMapping.getPhyAddrOf(getDynEntry(getDynamicHeader(), DT_JMPREL)));
   size_t relocSize = getDynEntry(getDynamicHeader(), DT_PLTRELSZ);
   size_t nRelocs = relocSize / sizeof(ElfRel);
   LOGV("Resolving GOT with %zu relocations", nRelocs);
@@ -131,7 +132,8 @@ bool NanoappLoader::resolveGot() {
       case R_ARM_JUMP_SLOT: {
         LOGV("Resolving ARM_JUMP_SLOT at offset %lx",
              static_cast<long unsigned int>(curr->r_offset));
-        addr = reinterpret_cast<ElfAddr *>(mMapping + curr->r_offset);
+        addr =
+            reinterpret_cast<ElfAddr *>(mMapping.getPhyAddrOf(curr->r_offset));
         size_t posInSymbolTable = ELFW_R_SYM(curr->r_info);
         void *resolved = resolveData(posInSymbolTable);
         if (resolved == nullptr) {
diff --git a/platform/embos/memory.cc b/platform/embos/memory.cc
index c8c060e8..12032039 100644
--- a/platform/embos/memory.cc
+++ b/platform/embos/memory.cc
@@ -63,4 +63,8 @@ void memoryFreeDram(void *pointer) {
   OS_free(pointer);
 }
 
+void palSystemApiForceDramAccess() {
+  // No-op
+}
+
 }  // namespace chre
diff --git a/platform/exynos/platform_nanoapp.cc b/platform/exynos/platform_nanoapp.cc
index 6962716f..1bed4396 100644
--- a/platform/exynos/platform_nanoapp.cc
+++ b/platform/exynos/platform_nanoapp.cc
@@ -109,6 +109,18 @@ const char *PlatformNanoapp::getAppName() const {
   return (mAppInfo != nullptr) ? mAppInfo->name : "Unknown";
 }
 
+void PlatformNanoapp::invokeEventFreeCallback(
+    chreEventCompleteFunction *function, const uint16_t eventType,
+    void *const eventData) const {
+  function(eventType, eventData);
+}
+
+void PlatformNanoapp::invokeMessageFreeCallback(
+    chreMessageFreeFunction *function, void *message,
+    const size_t messageSize) const {
+  function(message, messageSize);
+}
+
 bool PlatformNanoappBase::isLoaded() const {
   return (mIsStatic ||
           (mAppBinary != nullptr && mBytesLoaded == mAppBinaryLen) ||
diff --git a/platform/freertos/CMakeLists.txt b/platform/freertos/CMakeLists.txt
index ab464ee1..02f0239c 100644
--- a/platform/freertos/CMakeLists.txt
+++ b/platform/freertos/CMakeLists.txt
@@ -7,6 +7,7 @@ pw_add_library(chre.platform.freertos.platform_nanoapp STATIC
     public_platform_nanoapp
   PUBLIC_DEPS
     chre.platform.shared.memory
+    chre.platform.shared.nanoapp_memory_guard_no_op
     chre.platform.shared.nanoapp_support_lib_dso
   SOURCES
     platform_nanoapp.cc
diff --git a/platform/freertos/init.cc b/platform/freertos/init.cc
index 065b3aa8..c7841b5f 100644
--- a/platform/freertos/init.cc
+++ b/platform/freertos/init.cc
@@ -18,7 +18,12 @@
 
 #ifdef CHRE_ENABLE_CHPP
 #include "chpp/platform/chpp_init.h"
-#endif
+#endif  // CHRE_ENABLE_CHPP
+
+#ifdef CHRE_BLE_SOCKET_SUPPORT_ENABLED
+#include "chre/core/ble_socket_manager.h"
+#endif  // CHRE_BLE_SOCKET_SUPPORT_ENABLED
+
 #include "chre/core/event_loop_manager.h"
 #include "chre/core/static_nanoapps.h"
 #include "chre/platform/shared/dram_vote_client.h"
@@ -27,7 +32,7 @@
 #ifdef CHRE_USE_BUFFERED_LOGGING
 #include "chre/platform/shared/log_buffer_manager.h"
 #include "chre/target_platform/macros.h"
-#endif
+#endif  // CHRE_USE_BUFFERED_LOGGING
 
 #include "task.h"
 
@@ -40,29 +45,34 @@ constexpr UBaseType_t kChreTaskPriority =
     tskIDLE_PRIORITY + CHRE_FREERTOS_TASK_PRIORITY;
 #else
 constexpr UBaseType_t kChreTaskPriority = tskIDLE_PRIORITY + 1;
-#endif
+#endif  // CHRE_FREERTOS_TASK_PRIORITY
 
 #ifdef CHRE_FREERTOS_STACK_DEPTH_IN_WORDS
 constexpr configSTACK_DEPTH_TYPE kChreTaskStackDepthWords =
     CHRE_FREERTOS_STACK_DEPTH_IN_WORDS;
 #else
 constexpr configSTACK_DEPTH_TYPE kChreTaskStackDepthWords = 0x800;
-#endif
+#endif  // CHRE_FREERTOS_STACK_DEPTH_IN_WORDS
 
 TaskHandle_t gChreTaskHandle;
 
-#ifdef CHRE_USE_BUFFERED_LOGGING
+#ifndef CHRE_HIGH_POWER_BSS_ATTRIBUTE
+#define CHRE_HIGH_POWER_BSS_ATTRIBUTE
+#endif  // CHRE_HIGH_POWER_BSS_ATTRIBUTE
 
+#ifdef CHRE_USE_BUFFERED_LOGGING
 TaskHandle_t gChreFlushTaskHandle;
 
-#ifdef CHRE_HIGH_POWER_TEXT_ATTRIBUTE
-CHRE_HIGH_POWER_TEXT_ATTRIBUTE
-#endif
+CHRE_HIGH_POWER_BSS_ATTRIBUTE
 uint8_t gSecondaryLogBufferData[CHRE_LOG_BUFFER_DATA_SIZE];
 
 uint8_t gPrimaryLogBufferData[CHRE_LOG_BUFFER_DATA_SIZE];
+#endif  // CHRE_USE_BUFFERED_LOGGING
 
-#endif
+#ifdef CHRE_BLE_SOCKET_SUPPORT_ENABLED
+CHRE_HIGH_POWER_BSS_ATTRIBUTE
+BleSocketManager gBleSocketManager;
+#endif  // CHRE_BLE_SOCKET_SUPPORT_ENABLED
 
 // This function is intended to be the task action function for FreeRTOS.
 // It Initializes CHRE, runs the event loop, and only exits if it receives
@@ -74,6 +84,11 @@ void chreThreadEntry(void *context) {
 
   chre::init();
   chre::EventLoopManagerSingleton::get()->lateInit();
+#ifdef CHRE_BLE_SOCKET_SUPPORT_ENABLED
+  forceDramAccess();
+  chre::EventLoopManagerSingleton::get()->setBleSocketManager(
+      gBleSocketManager);
+#endif  // CHRE_BLE_SOCKET_SUPPORT_ENABLED
   chre::loadStaticNanoapps();
 
   chre::EventLoopManagerSingleton::get()->getEventLoop().run();
@@ -94,13 +109,13 @@ void chreFlushLogsToHostThreadEntry(void *context) {
   // Never exits
   chre::LogBufferManagerSingleton::get()->startSendLogsToHostLoop();
 }
-#endif
+#endif  // CHRE_USE_BUFFERED_LOGGING
 
 }  // namespace
 
 #ifdef CHRE_USE_BUFFERED_LOGGING
 const char *getChreFlushTaskName();
-#endif
+#endif  // CHRE_USE_BUFFERED_LOGGING
 
 BaseType_t init() {
   BaseType_t rc =
@@ -110,7 +125,7 @@ BaseType_t init() {
 
 #ifdef CHRE_ENABLE_CHPP
   chpp::init();
-#endif
+#endif  // CHRE_ENABLE_CHPP
 
   return rc;
 }
@@ -127,7 +142,7 @@ BaseType_t initLogger() {
                      kChreTaskStackDepthWords, nullptr /* args */,
                      kChreTaskPriority, &gChreFlushTaskHandle);
   }
-#endif
+#endif  // CHRE_USE_BUFFERED_LOGGING
   return rc;
 }
 
@@ -140,7 +155,7 @@ void deinit() {
 
 #ifdef CHRE_ENABLE_CHPP
   chpp::deinit();
-#endif
+#endif  // CHRE_ENABLE_CHPP
 }
 
 const char *getChreTaskName() {
@@ -153,7 +168,7 @@ const char *getChreFlushTaskName() {
   static constexpr char kChreFlushTaskName[] = "CHRELogs";
   return kChreFlushTaskName;
 }
-#endif
+#endif  // CHRE_USE_BUFFERED_LOGGING
 
 }  // namespace freertos
 
diff --git a/platform/freertos/memory.cc b/platform/freertos/memory.cc
index ada67024..e3aea2a8 100644
--- a/platform/freertos/memory.cc
+++ b/platform/freertos/memory.cc
@@ -37,4 +37,8 @@ void palSystemApiMemoryFree(void *pointer) {
   free(pointer);
 }
 
+void palSystemApiForceDramAccess() {
+  // No-op
+}
+
 }  // namespace chre
diff --git a/platform/freertos/platform_nanoapp.cc b/platform/freertos/platform_nanoapp.cc
index a3d908b1..ace103ac 100644
--- a/platform/freertos/platform_nanoapp.cc
+++ b/platform/freertos/platform_nanoapp.cc
@@ -25,6 +25,7 @@
 #include "chre/platform/shared/authentication.h"
 #include "chre/platform/shared/nanoapp_dso_util.h"
 #include "chre/platform/shared/nanoapp_loader.h"
+#include "chre/platform/shared/nanoapp_memory_guard.h"
 #include "chre/util/macros.h"
 #include "chre/util/system/napp_header_utils.h"
 #include "chre/util/system/napp_permissions.h"
@@ -61,6 +62,7 @@ bool PlatformNanoapp::start() {
   } else if (mAppInfo == nullptr) {
     LOGE("Null app info!");
   } else {
+    NanoappMemoryGuard guard(*this);
     success = mAppInfo->entryPoints.start();
   }
 
@@ -70,12 +72,18 @@ bool PlatformNanoapp::start() {
 void PlatformNanoapp::handleEvent(uint32_t senderInstanceId, uint16_t eventType,
                                   const void *eventData) {
   enableDramAccessIfRequired();
-  mAppInfo->entryPoints.handleEvent(senderInstanceId, eventType, eventData);
+  {
+    NanoappMemoryGuard guard(*this);
+    mAppInfo->entryPoints.handleEvent(senderInstanceId, eventType, eventData);
+  }
 }
 
 void PlatformNanoapp::end() {
   enableDramAccessIfRequired();
-  mAppInfo->entryPoints.end();
+  {
+    NanoappMemoryGuard guard(*this);
+    mAppInfo->entryPoints.end();
+  }
   closeNanoapp();
 }
 
@@ -129,6 +137,20 @@ void PlatformNanoapp::logStateToBuffer(DebugDumpWrapper &debugDump) const {
   }
 }
 
+void PlatformNanoapp::invokeEventFreeCallback(
+    chreEventCompleteFunction *function, const uint16_t eventType,
+    void *const eventData) const {
+  const NanoappMemoryGuard guard(*this);
+  function(eventType, eventData);
+}
+
+void PlatformNanoapp::invokeMessageFreeCallback(
+    chreMessageFreeFunction *function, void *message,
+    const size_t messageSize) const {
+  const NanoappMemoryGuard guard(*this);
+  function(message, messageSize);
+}
+
 const char *PlatformNanoappBase::getAppVersionString(size_t *length) const {
   const char *versionString = kDefaultAppVersionString;
   *length = kDefaultAppVersionStringSize;
diff --git a/platform/freertos/public_platform_nanoapp/chre/target_platform/platform_nanoapp_base.h b/platform/freertos/public_platform_nanoapp/chre/target_platform/platform_nanoapp_base.h
index b75364d8..d204cbe5 100644
--- a/platform/freertos/public_platform_nanoapp/chre/target_platform/platform_nanoapp_base.h
+++ b/platform/freertos/public_platform_nanoapp/chre/target_platform/platform_nanoapp_base.h
@@ -87,6 +87,14 @@ class PlatformNanoappBase {
    */
   bool copyNanoappFragment(const void *buffer, size_t bufferSize);
 
+  bool isStatic() const {
+    return mIsStatic;
+  }
+
+  void *getDsoHandle() const {
+    return mDsoHandle;
+  }
+
  protected:
   //! The app ID we received in the metadata alongside the nanoapp binary. This
   //! is also included in (and checked against) mAppInfo.
diff --git a/platform/include/chre/platform/platform_nanoapp.h b/platform/include/chre/platform/platform_nanoapp.h
index 7d9e7360..4592124f 100644
--- a/platform/include/chre/platform/platform_nanoapp.h
+++ b/platform/include/chre/platform/platform_nanoapp.h
@@ -20,6 +20,7 @@
 #include <cstddef>
 #include <cstdint>
 
+#include "chre/core/event.h"
 #include "chre/target_platform/platform_nanoapp_base.h"
 #include "chre/util/non_copyable.h"
 #include "chre/util/system/debug_dump.h"
@@ -120,6 +121,37 @@ class PlatformNanoapp : public PlatformNanoappBase, public NonCopyable {
    */
   void logStateToBuffer(DebugDumpWrapper &debugDump) const;
 
+  /**
+   * Invokes the `chreEventCompleteFunction` for an event that was originally
+   * sent by this nanoapp.
+   *
+   * @param function A non-null pointer to the event completion callback
+   *        function originally provided by this nanoapp when it sent the event.
+   * @param eventType The type of the event being freed.
+   * @param eventData The data associated with the event being freed.
+   *
+   * @see chreEventCompleteFunction
+   * @see NanoappMemoryGuard
+   */
+  void invokeEventFreeCallback(chreEventCompleteFunction *function,
+                               uint16_t eventType, void *eventData) const;
+
+  /**
+   * Invokes the freeing callback provided by a nanoapp for a message sent to
+   * the host.
+   *
+   * @param function The callback function pointer provided by the
+   * nanoapp.
+   * @param message The message data pointer originally passed to
+   *        chreSendMessageToHostEndpoint() or similar.
+   * @param messageSize The size of the message data.
+   *
+   * @see chreMessageFreeFunction
+   * @see HostCommsManager::freeMessageToHost
+   */
+  void invokeMessageFreeCallback(chreMessageFreeFunction *function,
+                                 void *message, size_t messageSize) const;
+
  protected:
   /**
    * PlatformNanoapp's constructor is protected, as it must only exist within
diff --git a/platform/linux/include/chre/target_platform/log.h b/platform/linux/include/chre/target_platform/log.h
index fa1a9440..627e662c 100644
--- a/platform/linux/include/chre/target_platform/log.h
+++ b/platform/linux/include/chre/target_platform/log.h
@@ -17,29 +17,46 @@
 #ifndef CHRE_PLATFORM_LINUX_LOG_H_
 #define CHRE_PLATFORM_LINUX_LOG_H_
 
+#include "chre/platform/system_time.h"
 #include "chre_api/chre/re.h"
 
 #ifndef __FILENAME__
 #define __FILENAME__ __FILE__
 #endif
 
+#include <cinttypes>
+
 #ifdef GTEST
 // When using GoogleTest, just output to stdout since tests are single-threaded.
 // GoogleTest complains about multiple threads if the PlatformLogSingleton is
 // used.
 #include <stdio.h>
 
-#define CHRE_LINUX_LOG(logLevel, levelStr, color, fmt, ...)               \
-  printf("\e[" color "m%s %s:%d\t" fmt "\e[0m\n", levelStr, __FILENAME__, \
-         __LINE__, ##__VA_ARGS__)
+#define CHRE_LINUX_LOG(logLevel, levelStr, color, fmt, ...)                \
+  do {                                                                     \
+    uint64_t timeMs =                                                      \
+        chre::SystemTime::getMonotonicTime().toRawNanoseconds() / 1000000; \
+    uint64_t secondsPart = timeMs / 1000;                                  \
+    uint64_t millisPart = timeMs % 1000;                                   \
+    printf("\e[" color "m%s %s:%d\t@ %" PRIu64 ".03%" PRIu64 ": " fmt      \
+           "\e[0m\n",                                                      \
+           levelStr, __FILENAME__, __LINE__, secondsPart, millisPart,      \
+           ##__VA_ARGS__);                                                 \
+  } while (0);
 #else
 #include "chre/platform/linux/platform_log.h"
 
-#define CHRE_LINUX_LOG(logLevel, levelStr, color, fmt, ...)        \
-  if (::chre::PlatformLogSingleton::isInitialized()) {             \
-    ::chre::PlatformLogSingleton::get()->log(                      \
-        logLevel, "\e[" color "m%s %s:%d\t" fmt "\e[0m", levelStr, \
-        __FILENAME__, __LINE__, ##__VA_ARGS__);                    \
+#define CHRE_LINUX_LOG(logLevel, levelStr, color, fmt, ...)                 \
+  if (::chre::PlatformLogSingleton::isInitialized()) {                      \
+    uint64_t timeMs =                                                       \
+        chre::SystemTime::getMonotonicTime().toRawNanoseconds() / 1000000;  \
+    uint64_t secondsPart = timeMs / 1000;                                   \
+    uint64_t millisPart = timeMs % 1000;                                    \
+    ::chre::PlatformLogSingleton::get()->log(                               \
+        logLevel,                                                           \
+        "\e[" color "m%s %s:%d\t@ %" PRIu64 ".03%" PRIu64 ": " fmt "\e[0m", \
+        levelStr, __FILENAME__, __LINE__, secondsPart, millisPart,          \
+        ##__VA_ARGS__);                                                     \
   }
 #endif
 
diff --git a/platform/linux/memory.cc b/platform/linux/memory.cc
index 4db8c2d1..2ef6cac9 100644
--- a/platform/linux/memory.cc
+++ b/platform/linux/memory.cc
@@ -38,4 +38,8 @@ void palSystemApiMemoryFree(void *pointer) {
 
 void forceDramAccess() {}
 
+void palSystemApiForceDramAccess() {
+  forceDramAccess();
+}
+
 }  // namespace chre
diff --git a/platform/linux/platform_nanoapp.cc b/platform/linux/platform_nanoapp.cc
index 1a4fb17d..4f7e8684 100644
--- a/platform/linux/platform_nanoapp.cc
+++ b/platform/linux/platform_nanoapp.cc
@@ -80,6 +80,18 @@ bool PlatformNanoapp::isSystemNanoapp() const {
 void PlatformNanoapp::logStateToBuffer(
     DebugDumpWrapper & /* debugDump */) const {}
 
+void PlatformNanoapp::invokeEventFreeCallback(
+    chreEventCompleteFunction *function, const uint16_t eventType,
+    void *const eventData) const {
+  function(eventType, eventData);
+}
+
+void PlatformNanoapp::invokeMessageFreeCallback(
+    chreMessageFreeFunction *function, void *message,
+    const size_t messageSize) const {
+  function(message, messageSize);
+}
+
 void PlatformNanoappBase::loadFromFile(const std::string &filename) {
   CHRE_ASSERT(!isLoaded());
   mFilename = filename;
diff --git a/platform/platform.mk b/platform/platform.mk
index e66e3bba..55dc8dab 100644
--- a/platform/platform.mk
+++ b/platform/platform.mk
@@ -29,6 +29,7 @@ SLPI_CFLAGS += -I$(SLPI_PREFIX)/platform/rtld/inc
 
 SLPI_CFLAGS += -Iplatform/shared/aligned_alloc_unsupported/include
 SLPI_CFLAGS += -Iplatform/shared/include
+SLPI_CFLAGS += -Iplatform/shared/nanoapp_memory_guard_no_op/include
 SLPI_CFLAGS += -Iplatform/shared/fbs/include
 SLPI_CFLAGS += -Iplatform/slpi/include
 
@@ -196,6 +197,7 @@ endif
 # Simulator-specific Compiler Flags ############################################
 
 SIM_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/include
+SIM_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/nanoapp_memory_guard_no_op/include
 SIM_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/public_platform_ble_pal
 SIM_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/public_platform_debug_dump_manager
 SIM_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/public_platform_gnss_pal
@@ -351,6 +353,7 @@ GOOGLETEST_CFLAGS += $(FLATBUFFERS_CFLAGS)
 
 # The order here is important so that the googletest target prefers shared,
 # linux and then SLPI.
+GOOGLETEST_CFLAGS += -Iplatform/shared/fbs/include
 GOOGLETEST_CFLAGS += -Iplatform/shared/include
 GOOGLETEST_CFLAGS += -Iplatform/shared/public_platform_ble_pal
 GOOGLETEST_CFLAGS += -Iplatform/shared/public_platform_debug_dump_manager
@@ -380,6 +383,7 @@ endif
 EMBOS_CFLAGS += -I$(CHRE_PREFIX)/platform/embos/include
 EMBOS_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/aligned_alloc_unsupported/include
 EMBOS_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/include
+EMBOS_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/nanoapp_memory_guard_no_op/include
 EMBOS_CFLAGS += $(FLATBUFFERS_CFLAGS)
 
 # The IAR flavor of EmbOS's RTOS.h includes an intrinsics.h header for
@@ -420,8 +424,9 @@ EMBOS_SRCS += $(CHRE_PREFIX)/platform/shared/nanoapp_loader.cc
 
 # Exynos specific compiler flags
 EXYNOS_CFLAGS += -I$(CHRE_PREFIX)/platform/exynos/include
-EXYNOS_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/fbs/include
 EXYNOS_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/audio_pal/include
+EXYNOS_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/fbs/include
+EXYNOS_CFLAGS += -I$(CHRE_PREFIX)/platform/shared/nanoapp_memory_guard_no_op/include
 
 EXYNOS_SRCS += $(CHRE_PREFIX)/platform/exynos/chre_api_re.cc
 EXYNOS_SRCS += $(CHRE_PREFIX)/platform/shared/host_link.cc
@@ -465,6 +470,7 @@ TINYSYS_SRCS += $(CHRE_PREFIX)/platform/tinysys/host_cpu_update.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/tinysys/host_link.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/tinysys/log_buffer_manager.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/tinysys/memory.cc
+TINYSYS_SRCS += $(CHRE_PREFIX)/platform/tinysys/nanoapp_memory_guard.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/tinysys/platform_cache_management.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/tinysys/platform_pal.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/tinysys/stdlib_wrapper.cc
@@ -500,6 +506,7 @@ TINYSYS_SRCS += $(CHRE_PREFIX)/platform/shared/host_protocol_chre.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/shared/host_protocol_common.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/shared/log_buffer.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/shared/log_buffer_manager.cc
+TINYSYS_SRCS += $(CHRE_PREFIX)/platform/shared/log_common.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/shared/memory_manager.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/shared/nanoapp_abort.cc
 TINYSYS_SRCS += $(CHRE_PREFIX)/platform/shared/nanoapp_load_manager.cc
diff --git a/platform/riscv/nanoapp_loader.cc b/platform/riscv/nanoapp_loader.cc
index d1253e07..e59f54b7 100644
--- a/platform/riscv/nanoapp_loader.cc
+++ b/platform/riscv/nanoapp_loader.cc
@@ -19,7 +19,6 @@
 namespace chre {
 
 bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
-  bool success = false;
   if (dyn == nullptr) {
     return false;
   }
@@ -28,7 +27,7 @@ bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
     case DT_RELA: {
       if (getDynEntry(dyn, tag) == 0) {
         LOGE("RISC-V Elf binaries must have DT_RELA dynamic entry");
-        break;
+        return false;
       }
 
       // The value of the RELA entry in dynamic table is the sh_addr field
@@ -36,7 +35,7 @@ bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
       // which is usually the same, but on occasions can be different.
       SectionHeader *dynamicRelaTablePtr = getSectionHeader(".rela.dyn");
       CHRE_ASSERT(dynamicRelaTablePtr != nullptr);
-      ElfRela *reloc =
+      auto *reloc =
           reinterpret_cast<ElfRela *>(mBinary + dynamicRelaTablePtr->sh_offset);
       size_t relocSize = dynamicRelaTablePtr->sh_size;
       size_t nRelocs = relocSize / sizeof(ElfRela);
@@ -45,7 +44,6 @@ bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
       for (size_t i = 0; i < nRelocs; ++i) {
         ElfRela *curr = &reloc[i];
         int relocType = ELFW_R_TYPE(curr->r_info);
-        ElfAddr *addr = reinterpret_cast<ElfAddr *>(mMapping + curr->r_offset);
 
         switch (relocType) {
           case R_RISCV_RELATIVE:
@@ -54,7 +52,8 @@ bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
             // TODO(b/155512914): When we move to DRAM allocations, we need to
             // check if the above address is in a Read-Only section of memory,
             // and give it temporary write permission if that is the case.
-            *addr = reinterpret_cast<uintptr_t>(mMapping + curr->r_addend);
+            mMapping.replace(curr->r_offset,
+                             mMapping.getPhyAddrOf(curr->r_addend));
             break;
 
           case R_RISCV_32: {
@@ -64,7 +63,8 @@ bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
             auto *dynamicSymbolTable =
                 reinterpret_cast<ElfSym *>(mDynamicSymbolTablePtr);
             ElfSym *sym = &dynamicSymbolTable[posInSymbolTable];
-            *addr = reinterpret_cast<uintptr_t>(mMapping + sym->st_value);
+            mMapping.replace(curr->r_offset,
+                             mMapping.getPhyAddrOf(sym->st_value));
             break;
           }
 
@@ -73,24 +73,25 @@ bool NanoappLoader::relocateTable(DynamicHeader *dyn, int tag) {
             break;
         }
       }
-      success = true;
-      break;
+      return true;
     }
     case DT_REL:
       // Not required for RISC-V
-      success = true;
-      break;
-    default:
+      return true;
+    default: {
       LOGE("Unsupported table tag %d", tag);
+      return false;
+    }
   }
-
-  return success;
 }
 
 bool NanoappLoader::resolveGot() {
-  ElfAddr *addr;
-  ElfRela *reloc = reinterpret_cast<ElfRela *>(
-      mMapping + getDynEntry(getDynamicHeader(), DT_JMPREL));
+  auto *reloc = reinterpret_cast<ElfRela *>(
+      mMapping.getPhyAddrOf(getDynEntry(getDynamicHeader(), DT_JMPREL)));
+  if (reloc == nullptr) {
+    LOGE("Unable to find the JMPREL relocation section");
+    return false;
+  }
   size_t relocSize = getDynEntry(getDynamicHeader(), DT_PLTRELSZ);
   size_t nRelocs = relocSize / sizeof(ElfRela);
   LOGV("Resolving GOT with %zu relocations", nRelocs);
@@ -105,7 +106,6 @@ bool NanoappLoader::resolveGot() {
       case R_RISCV_JUMP_SLOT: {
         LOGV("Resolving RISCV_JUMP_SLOT at offset %lx, %d",
              static_cast<long unsigned int>(curr->r_offset), curr->r_addend);
-        addr = reinterpret_cast<ElfAddr *>(mMapping + curr->r_offset);
         size_t posInSymbolTable = ELFW_R_SYM(curr->r_info);
         void *resolved = resolveData(posInSymbolTable);
         if (resolved == nullptr) {
@@ -113,7 +113,8 @@ bool NanoappLoader::resolveGot() {
                curr->r_offset);
           success = false;
         }
-        *addr = reinterpret_cast<ElfAddr>(resolved) + curr->r_addend;
+        mMapping.replace(curr->r_offset,
+                         reinterpret_cast<ElfAddr>(resolved) + curr->r_addend);
         break;
       }
 
diff --git a/platform/shared/CMakeLists.txt b/platform/shared/CMakeLists.txt
index eb85ebcd..bb5a12d1 100644
--- a/platform/shared/CMakeLists.txt
+++ b/platform/shared/CMakeLists.txt
@@ -18,6 +18,8 @@ pw_add_facade(chre.platform.shared.bt_snoop_log INTERFACE
     include/chre/platform/shared/bt_snoop_log.h
   PUBLIC_INCLUDES
     include
+  PUBLIC_DEPS
+    chre.platform.shared.log_common
 )
 
 # Implements chre_api/chre/audio.h's:
@@ -380,6 +382,20 @@ pw_add_library(chre.platform.shared.log_buffer STATIC
     chre.util
 )
 
+pw_add_library(chre.platform.shared.log_common STATIC
+  HEADERS
+    include/chre/platform/shared/log_common.h
+  PUBLIC_INCLUDES
+    include
+  PUBLIC_DEPS
+    chre.platform.shared.log_buffer_manager
+  SOURCES
+    log_common.cc
+  PRIVATE_DEPS
+    pw_log_tokenized.config
+    pw_tokenizer
+)
+
 # This requires the backend to provide an implementation for:
 # - void LogBufferManager::preSecondaryBufferUse() const
 pw_add_facade(chre.platform.shared.log_buffer_manager STATIC
@@ -517,6 +533,14 @@ pw_add_library(chre.platform.shared.nanoapp_tokenized_log STATIC
     pw_tokenizer
 )
 
+# Note that this is only for building purpose. In the future it can be changed to a facade if needed
+pw_add_library(chre.platform.shared.nanoapp_memory_guard_no_op INTERFACE
+  HEADERS
+    nanoapp_memory_guard_no_op/include/chre/target_platform/nanoapp_memory_guard_base.h
+  PUBLIC_INCLUDES
+    nanoapp_memory_guard_no_op/include
+)
+
 pw_add_library(chre.platform.shared.pal_audio_stub STATIC
   SOURCES
     pal_audio_stub.cc
diff --git a/platform/shared/host_protocol_chre.cc b/platform/shared/host_protocol_chre.cc
index c0831b77..74b42db7 100644
--- a/platform/shared/host_protocol_chre.cc
+++ b/platform/shared/host_protocol_chre.cc
@@ -391,7 +391,9 @@ bool HostProtocolChre::decodeMessageFromHost(const void *message,
             reinterpret_cast<const std::byte *>(msg->data()->data()),
             msg->data()->size()};
         getHostHubManager().sendMessage(msg->host_hub_id(), msg->session_id(),
-                                        data, msg->type(), msg->permissions());
+                                        data, msg->type(), msg->permissions(),
+                                        (msg->flags() & 0x1) != 0,
+                                        msg->sequence_number());
         break;
       }
 
@@ -762,4 +764,15 @@ void HostProtocolChre::encodeEndpointSessionMessage(
   finalize(builder, fbs::ChreMessage::EndpointSessionMessage, msg.Union());
 }
 
+void HostProtocolChre::encodeEndpointSessionMessageDeliveryStatus(
+    ChreFlatBufferBuilder &builder, message::MessageHubId hub,
+    message::SessionId session, uint32_t messageId, uint8_t status) {
+  auto messageDeliveryStatus =
+      fbs::CreateMessageDeliveryStatus(builder, messageId, status);
+  auto msg = fbs::CreateEndpointSessionMessageDeliveryStatus(
+      builder, hub, session, messageDeliveryStatus);
+  finalize(builder, fbs::ChreMessage::EndpointSessionMessageDeliveryStatus,
+           msg.Union());
+}
+
 }  // namespace chre
diff --git a/platform/shared/include/chre/platform/shared/host_protocol_chre.h b/platform/shared/include/chre/platform/shared/host_protocol_chre.h
index 14130f01..b77c89d9 100644
--- a/platform/shared/include/chre/platform/shared/host_protocol_chre.h
+++ b/platform/shared/include/chre/platform/shared/host_protocol_chre.h
@@ -497,6 +497,19 @@ class HostProtocolChre : public HostProtocolCommon {
                                            message::SessionId session,
                                            pw::UniquePtr<std::byte[]> &&data,
                                            uint32_t type, uint32_t permissions);
+
+  /**
+   * Encodes a message delivery status notification.
+   *
+   * @param builder Builder which assembles and stores the message.
+   * @param hub Id of the destination host hub.
+   * @param session Id of the session.
+   * @param messageId The message sequence number.
+   * @param status The delivery status.
+   */
+  static void encodeEndpointSessionMessageDeliveryStatus(
+      ChreFlatBufferBuilder &builder, message::MessageHubId hub,
+      message::SessionId session, uint32_t messageId, uint8_t status);
 };
 
 }  // namespace chre
diff --git a/platform/shared/include/chre/platform/shared/log_common.h b/platform/shared/include/chre/platform/shared/log_common.h
new file mode 100644
index 00000000..bbbd9bcb
--- /dev/null
+++ b/platform/shared/include/chre/platform/shared/log_common.h
@@ -0,0 +1,67 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef CHRE_PLATFORM_SHARED_LOG_COMMON_H_
+#define CHRE_PLATFORM_SHARED_LOG_COMMON_H_
+
+#include "chre_api/chre/re.h"
+
+#ifdef CHRE_TOKENIZED_LOGGING_ENABLED
+#include "pw_tokenizer/tokenize.h"
+#endif  // CHRE_TOKENIZED_LOGGING_ENABLED
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * Log via the CHRE LogBufferManagerSingleton vaLog method.
+ *
+ * @param level The log level.
+ * @param format The format string.
+ * @param ... The arguments to print into the final log.
+ */
+void chrePlatformLogToBuffer(enum chreLogLevel level, const char *format, ...);
+
+/**
+ * Store a log as pure bytes. The message may be an encoded or tokenized
+ * log. The decoding pattern for this message is up to the receiver.
+ *
+ * @param level Logging level.
+ * @param msg a byte buffer containing the encoded log message.
+ * @param msgSize size of the encoded log message buffer.
+ */
+void chrePlatformEncodedLogToBuffer(enum chreLogLevel level, const uint8_t *msg,
+                                    size_t msgSize);
+
+#ifdef CHRE_TOKENIZED_LOGGING_ENABLED
+/**
+ * Handles encoding and processing of a tokenized log message.
+ *
+ * @param level Logging level.
+ * @param token Encoded tokenized message.
+ * @param types Specifies the argument types.
+ * @param ... The arguments to print into the final log.
+ */
+void EncodeTokenizedMessage(uint32_t level, pw_tokenizer_Token token,
+                            pw_tokenizer_ArgTypes types, ...);
+#endif  // CHRE_TOKENIZED_LOGGING_ENABLED
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  // CHRE_PLATFORM_SHARED_LOG_COMMON_H_
diff --git a/platform/shared/include/chre/platform/shared/nanoapp_loader.h b/platform/shared/include/chre/platform/shared/nanoapp_loader.h
index 407e05ae..83a66ab9 100644
--- a/platform/shared/include/chre/platform/shared/nanoapp_loader.h
+++ b/platform/shared/include/chre/platform/shared/nanoapp_loader.h
@@ -21,7 +21,7 @@
 #include <cstdlib>
 
 #include "chre/platform/shared/loader_util.h"
-
+#include "chre/platform/shared/memory.h"
 #include "chre/util/dynamic_vector.h"
 #include "chre/util/optional.h"
 
@@ -69,6 +69,38 @@ struct AtExitCallback {
  */
 class NanoappLoader {
  public:
+  using DynamicHeader = ElfW(Dyn);
+  using ElfAddr = ElfW(Addr);
+  using ElfHeader = ElfW(Ehdr);
+  using ElfRel = ElfW(Rel);  // Relocation table entry,
+  // in section of type SHT_REL
+  using ElfRela = ElfW(Rela);
+  using ElfSym = ElfW(Sym);
+  using ElfWord = ElfW(Word);
+  using ElfOff = ElfW(Off);
+  using ProgramHeader = ElfW(Phdr);
+  using SectionHeader = ElfW(Shdr);
+
+  /**
+   * A struct representing a loadable segment in the ELF binary.
+   */
+  struct LoadableSegment {
+    /** The physical address of the segment mapped into the memory. */
+    ElfAddr pAddr;
+
+    /** The memory size of the segment. */
+    ElfWord memSize;
+
+    /**
+     * The permissions of the segment, a bitwise combination of read (4), write
+     * (2), and execute (1).
+     */
+    ElfWord permission;
+
+    LoadableSegment(ElfAddr pAddr, ElfWord size, ElfWord permission)
+        : pAddr(pAddr), memSize(size), permission(permission) {};
+  };
+
   NanoappLoader() = delete;
 
   /**
@@ -146,7 +178,99 @@ class NanoappLoader {
    */
   void getTokenDatabaseSectionInfo(uint32_t *offset, size_t *size);
 
+  const DynamicVector<LoadableSegment> &getLoadableSegments() {
+    return mMapping.getLoadableSegments();
+  }
+
  private:
+  /**
+   * A class that handles the allocation, mapping, and management of memory
+   * segments for a nanoapp.
+   */
+  class MemoryMapping {
+   public:
+    MemoryMapping() = default;
+
+    ~MemoryMapping() {
+      LOGV("Freeing nanoapp memory mapping for size: %zu", mMemorySpan);
+      if (mIsInTcm) {
+        nanoappBinaryFree(mAddr);
+      } else {
+        nanoappBinaryDramFree(mAddr);
+      }
+    }
+
+    /**
+     * Gets the physical address corresponding to a virtual address.
+     *
+     * @param vAddr The virtual address to translate.
+     * @return The corresponding physical address, or 0 if the virtual address
+     * is not found.
+     */
+    [[nodiscard]] ElfAddr getPhyAddrOf(ElfAddr vAddr) const {
+      return reinterpret_cast<ElfAddr>(mAddr) - mStartingVa + vAddr;
+    }
+
+    /**
+     * Replaces the value at a given virtual address.
+     *
+     * @param vAddr The virtual address to modify.
+     * @param value The new value to write.
+     */
+    void replace(ElfAddr vAddr, ElfAddr value) const {
+      auto phyAddr = reinterpret_cast<ElfAddr *>(getPhyAddrOf(vAddr));
+      *phyAddr = value;
+    }
+
+    /** Gets a const reference to the vector of loadable segments. */
+    const DynamicVector<LoadableSegment> &getLoadableSegments() {
+      return mSegments;
+    }
+
+    /**
+     * Returns true if the virtual address is within the valid range, false
+     * otherwise.
+     */
+    [[nodiscard]] bool isValidVa(ElfAddr vAddr) const {
+      return vAddr >= mStartingVa && vAddr < mStartingVa + mMemorySpan;
+    }
+
+    /**
+     * Constructs the memory mapping from program headers.
+     *
+     * Allocates memory and copies loadable segments from the ELF binary.
+     *
+     * @param first Pointer to the first program header.
+     * @param last Pointer to the last program header.
+     * @param isInTcm True if the binary should be mapped into TCM, false
+     *     otherwise.
+     * @param binary Pointer to the start of the ELF binary.
+     * @return True on success, false otherwise.
+     */
+    bool construct(const ProgramHeader *first, const ProgramHeader *last,
+                   bool isInTcm, uint8_t *binary);
+
+    /** Wipes the system caches for the mapped memory. */
+    void wipeCache() const;
+
+   private:
+    /** Vector of loadable segments. */
+    DynamicVector<LoadableSegment> mSegments{};
+
+    /** Pointer to the allocated memory. */
+    uint8_t *mAddr = nullptr;
+
+    /** The virtual address of the first loadable segment's starting page
+     * boundary. */
+    ElfAddr mStartingVa = 0;
+
+    /** The total memory span of the mapped memory. */
+    size_t mMemorySpan = 0;
+
+    /** True if the binary is mapped into TCM, false otherwise. */
+    bool mIsInTcm = false;
+  };
+
   explicit NanoappLoader(void *elfInput, bool mapIntoTcm) {
     mBinary = static_cast<uint8_t *>(elfInput);
     mIsTcmBinary = mapIntoTcm;
@@ -169,52 +293,46 @@ class NanoappLoader {
    */
   void close();
 
-  using DynamicHeader = ElfW(Dyn);
-  using ElfAddr = ElfW(Addr);
-  using ElfHeader = ElfW(Ehdr);
-  using ElfRel = ElfW(Rel);  // Relocation table entry,
-                             // in section of type SHT_REL
-  using ElfRela = ElfW(Rela);
-  using ElfSym = ElfW(Sym);
-  using ElfWord = ElfW(Word);
-  using ProgramHeader = ElfW(Phdr);
-  using SectionHeader = ElfW(Shdr);
-
-  //! Name of various segments in the ELF that need to be looked up
+  /** Name of various segments in the ELF that need to be looked up. */
   static constexpr const char *kDynsymTableName = ".dynsym";
   static constexpr const char *kDynstrTableName = ".dynstr";
   static constexpr const char *kInitArrayName = ".init_array";
   static constexpr const char *kFiniArrayName = ".fini_array";
   static constexpr const char *kTokenTableName = ".pw_tokenizer.entries";
 
-  //! Pointer to the table of all the section names.
+  /** Pointer to the table of all the section names. */
   char *mSectionNamesPtr = nullptr;
-  //! Pointer to the table of dynamic symbol names for defined symbols.
+
+  /** Pointer to the table of dynamic symbol names for defined symbols. */
   char *mDynamicStringTablePtr = nullptr;
-  //! Pointer to the table of dynamic symbol information for defined symbols.
+
+  /** Pointer to the table of dynamic symbol information for defined symbols. */
   uint8_t *mDynamicSymbolTablePtr = nullptr;
-  //! Pointer to the array of section header entries.
+
+  /** Pointer to the array of section header entries. */
   SectionHeader *mSectionHeadersPtr = nullptr;
-  //! Number of SectionHeaders pointed to by mSectionHeadersPtr.
+
+  /** Number of SectionHeaders pointed to by mSectionHeadersPtr. */
   size_t mNumSectionHeaders = 0;
-  //! Size of the data pointed to by mDynamicSymbolTablePtr.
+
+  /** Size of the data pointed to by mDynamicSymbolTablePtr. */
   size_t mDynamicSymbolTableSize = 0;
 
-  //! The ELF that is being mapped into the system. This pointer will be invalid
-  //! after open returns.
+  /** The ELF that is being mapped into the system which will be invalid after
+   * open returns. */
   uint8_t *mBinary = nullptr;
-  //! The starting location of the memory that has been mapped into the system.
-  uint8_t *mMapping = nullptr;
-  //! The span of memory that has been mapped into the system.
-  size_t mMemorySpan = 0;
-  //! The difference between where the first load segment was mapped into
-  //! virtual memory and what the virtual load offset was of that segment.
-  ElfAddr mLoadBias = 0;
-  //! Dynamic vector containing functions that should be invoked prior to
-  //! unloading this nanoapp. Note that functions are stored in the order they
-  //! were added and should be called in reverse.
-  DynamicVector<struct AtExitCallback> mAtexitFunctions;
-  //! Whether this loader instance is managing a TCM nanoapp binary.
+
+  /** Loadable segments that are mapped into the memory. */
+  MemoryMapping mMapping;
+
+  /**
+   * Dynamic vector containing functions that should be invoked prior to
+   * unloading this nanoapp. Note that functions are stored in the order they
+   * were added and should be called in reverse.
+   */
+  DynamicVector<AtExitCallback> mAtexitFunctions;
+
+  /** Whether this loader instance is managing a TCM nanoapp binary. */
   bool mIsTcmBinary = false;
 
   /**
@@ -327,15 +445,6 @@ class NanoappLoader {
    */
   void freeAllocatedData();
 
-  /**
-   * Ensures the BSS section is properly mapped into memory. If there is a
-   * difference between the size of the BSS section in the ELF binary and the
-   * size it needs to be in memory, the rest of the section is zeroed out.
-   *
-   * @param header The ProgramHeader of the BSS section that is being mapped in.
-   */
-  void mapBss(const ProgramHeader *header);
-
   /**
    * Resolves the address of an undefined symbol located at the given position
    * in the symbol table. This symbol must be defined and exposed by the given
diff --git a/platform/shared/include/chre/platform/shared/nanoapp_memory_guard.h b/platform/shared/include/chre/platform/shared/nanoapp_memory_guard.h
new file mode 100644
index 00000000..d90e6c5b
--- /dev/null
+++ b/platform/shared/include/chre/platform/shared/nanoapp_memory_guard.h
@@ -0,0 +1,81 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+/**
+ * @file
+ * Defines the NanoappMemoryGuard class, an RAII helper for managing nanoapp
+ * memory permissions.
+ *
+ * This class provides an interface for the platform-specific implementation
+ * provided by NanoappMemoryGuardBase. This abstraction allows for
+ * PlatformNanoapp code to be shared across devices with different MPU/MMU
+ * characteristics.
+ *
+ * If hardware-based memory protection of nanoapp code is not intrinsically
+ * provided by the system, or there is a desire to provide stricter protection
+ * (for example, making a nanoapp's memory inaccessible unless it is currently
+ * running via the expected call flow), then the platform implementer should
+ * provide an implementation of NanoappMemoryGuardBase accessible via the
+ * chre/target_platform/nanoapp_memory_guard_base.h include path which enables
+ * and disables access to the nanoapp's memory.
+ *
+ * If no additional protection is needed, the include path for the no-op base
+ * class implementation (found in
+ * platform/shared/nanoapp_memory_guard_no_op/include/...) should be used by
+ * adding it to the platform's build includes.
+ */
+
+#ifndef CHRE_PLATFORM_NANOAPP_MEMORY_GUARD_H_
+#define CHRE_PLATFORM_NANOAPP_MEMORY_GUARD_H_
+
+#include "chre/platform/platform_nanoapp.h"
+#include "chre/platform/shared/nanoapp_loader.h"
+#include "chre/target_platform/nanoapp_memory_guard_base.h"
+
+namespace chre {
+
+/**
+ * @brief An RAII helper class to manage nanoapp memory permissions.
+ *
+ * Instantiating this class grants memory permissions for the associated
+ * nanoapp (via the base class constructor). When the instance goes out of
+ * scope, its destructor ensures that the permissions are revoked (via the base
+ * class destructor).
+ */
+class NanoappMemoryGuard : public NanoappMemoryGuardBase {
+ public:
+  /**
+   * Constructs the guard and grants memory permissions for the given nanoapp.
+   *
+   * @param nanoapp The nanoapp instance for which to manage memory permissions.
+   */
+  explicit NanoappMemoryGuard(const PlatformNanoapp &nanoapp)
+      : NanoappMemoryGuardBase(nanoapp) {}
+
+  /**
+   * Constructs the guard and grants memory permissions based on the permission
+   * settings in the loadable segments.
+   *
+   * @param loadableSegments The loadable segments of the nanoapp binary
+   * @param numSegments The number of loadable segments
+   */
+  NanoappMemoryGuard(const NanoappLoader::LoadableSegment *loadableSegments,
+                     size_t numSegments)
+      : NanoappMemoryGuardBase(loadableSegments, numSegments) {}
+};
+}  // namespace chre
+
+#endif  // CHRE_PLATFORM_NANOAPP_MEMORY_GUARD_H_
\ No newline at end of file
diff --git a/platform/shared/include/chre/platform/shared/pal_system_api.h b/platform/shared/include/chre/platform/shared/pal_system_api.h
index 0413d835..b3807f3a 100644
--- a/platform/shared/include/chre/platform/shared/pal_system_api.h
+++ b/platform/shared/include/chre/platform/shared/pal_system_api.h
@@ -32,6 +32,12 @@ void *palSystemApiMemoryAlloc(size_t size);
  */
 void palSystemApiMemoryFree(void *pointer);
 
+/**
+ * DRAM access coming from the PAL. This function needs to be implemented by the
+ * platform and is not provided by the shared code.
+ */
+void palSystemApiForceDramAccess();
+
 //! Provides a global instance of the PAL system API for all PAL subsystems to
 //! leverage.
 extern const chrePalSystemApi gChrePalSystemApi;
diff --git a/platform/shared/log_buffer_manager.cc b/platform/shared/log_buffer_manager.cc
index 0a0bf902..2dbfb491 100644
--- a/platform/shared/log_buffer_manager.cc
+++ b/platform/shared/log_buffer_manager.cc
@@ -22,52 +22,6 @@
 #include "chre/platform/shared/fbs/host_messages_generated.h"
 #include "chre/util/lock_guard.h"
 
-#ifdef CHRE_TOKENIZED_LOGGING_ENABLED
-#include "chre/platform/log.h"
-#include "pw_log_tokenized/config.h"
-#include "pw_tokenizer/encode_args.h"
-#include "pw_tokenizer/tokenize.h"
-#endif  // CHRE_TOKENIZED_LOGGING_ENABLED
-
-void chrePlatformLogToBuffer(chreLogLevel chreLogLevel, const char *format,
-                             ...) {
-  va_list args;
-  va_start(args, format);
-  if (chre::LogBufferManagerSingleton::isInitialized()) {
-    chre::LogBufferManagerSingleton::get()->logVa(chreLogLevel, format, args);
-  }
-  va_end(args);
-}
-
-void chrePlatformEncodedLogToBuffer(chreLogLevel level, const uint8_t *msg,
-                                    size_t msgSize) {
-  if (chre::LogBufferManagerSingleton::isInitialized()) {
-    chre::LogBufferManagerSingleton::get()->logEncoded(level, msg, msgSize);
-  }
-}
-
-void chrePlatformBtSnoopLog(BtSnoopDirection direction, const uint8_t *buffer,
-                            size_t size) {
-  chre::LogBufferManagerSingleton::get()->logBtSnoop(direction, buffer, size);
-}
-
-#ifdef CHRE_TOKENIZED_LOGGING_ENABLED
-// The callback function that must be defined to handle an encoded
-// tokenizer message.
-void EncodeTokenizedMessage(uint32_t level, pw_tokenizer_Token token,
-                            pw_tokenizer_ArgTypes types, ...) {
-  va_list args;
-  va_start(args, types);
-  pw::tokenizer::EncodedMessage<pw::log_tokenized::kEncodingBufferSizeBytes>
-      encodedMessage(token, types, args);
-  va_end(args);
-
-  chrePlatformEncodedLogToBuffer(static_cast<chreLogLevel>(level),
-                                 encodedMessage.data_as_uint8(),
-                                 encodedMessage.size());
-}
-#endif  // CHRE_TOKENIZED_LOGGING_ENABLED
-
 namespace chre {
 
 using LogType = fbs::LogType;
diff --git a/platform/shared/log_common.cc b/platform/shared/log_common.cc
new file mode 100644
index 00000000..094ab782
--- /dev/null
+++ b/platform/shared/log_common.cc
@@ -0,0 +1,64 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "chre/platform/shared/log_common.h"
+
+#include "chre/platform/shared/log_buffer_manager.h"
+
+#ifdef CHRE_TOKENIZED_LOGGING_ENABLED
+#include "pw_log_tokenized/config.h"
+#include "pw_tokenizer/encode_args.h"
+#include "pw_tokenizer/tokenize.h"
+#endif  // CHRE_TOKENIZED_LOGGING_ENABLED
+
+void chrePlatformLogToBuffer(chreLogLevel chreLogLevel, const char *format,
+                             ...) {
+  va_list args;
+  va_start(args, format);
+  if (chre::LogBufferManagerSingleton::isInitialized()) {
+    chre::LogBufferManagerSingleton::get()->logVa(chreLogLevel, format, args);
+  }
+  va_end(args);
+}
+
+void chrePlatformEncodedLogToBuffer(chreLogLevel level, const uint8_t *msg,
+                                    size_t msgSize) {
+  if (chre::LogBufferManagerSingleton::isInitialized()) {
+    chre::LogBufferManagerSingleton::get()->logEncoded(level, msg, msgSize);
+  }
+}
+
+void chrePlatformBtSnoopLog(BtSnoopDirection direction, const uint8_t *buffer,
+                            size_t size) {
+  chre::LogBufferManagerSingleton::get()->logBtSnoop(direction, buffer, size);
+}
+
+#ifdef CHRE_TOKENIZED_LOGGING_ENABLED
+// The callback function that must be defined to handle an encoded
+// tokenizer message.
+void EncodeTokenizedMessage(uint32_t level, pw_tokenizer_Token token,
+                            pw_tokenizer_ArgTypes types, ...) {
+  va_list args;
+  va_start(args, types);
+  pw::tokenizer::EncodedMessage<pw::log_tokenized::kEncodingBufferSizeBytes>
+      encodedMessage(token, types, args);
+  va_end(args);
+
+  chrePlatformEncodedLogToBuffer(static_cast<chreLogLevel>(level),
+                                 encodedMessage.data_as_uint8(),
+                                 encodedMessage.size());
+}
+#endif  // CHRE_TOKENIZED_LOGGING_ENABLED
diff --git a/platform/shared/nanoapp_loader.cc b/platform/shared/nanoapp_loader.cc
index a827e4fb..955e515d 100644
--- a/platform/shared/nanoapp_loader.cc
+++ b/platform/shared/nanoapp_loader.cc
@@ -27,6 +27,7 @@
 #include "chre/platform/shared/debug_dump.h"
 #include "chre/platform/shared/memory.h"
 #include "chre/platform/shared/nanoapp/tokenized_log.h"
+#include "chre/platform/shared/nanoapp_memory_guard.h"
 #include "chre/platform/shared/platform_cache_management.h"
 #include "chre/util/dynamic_vector.h"
 #include "chre/util/macros.h"
@@ -42,7 +43,6 @@
 namespace chre {
 namespace {
 
-using ElfHeader = ElfW(Ehdr);
 using ProgramHeader = ElfW(Phdr);
 
 struct ExportedData {
@@ -300,6 +300,66 @@ CHRE_DEPRECATED_EPILOGUE
 
 }  // namespace
 
+bool NanoappLoader::MemoryMapping::construct(const ProgramHeader *first,
+                                             const ProgramHeader *last,
+                                             bool isInTcm, uint8_t *binary) {
+  ElfAddr alignment = first->p_align;
+  mStartingVa = roundDownToAlign(first->p_vaddr, alignment);
+  mMemorySpan = last->p_vaddr + last->p_memsz - mStartingVa;
+  mIsInTcm = isInTcm;
+
+  // Allocate memory.
+  if (isInTcm) {
+    mAddr = static_cast<uint8_t *>(nanoappBinaryAlloc(mMemorySpan, alignment));
+  } else {
+    mAddr =
+        static_cast<uint8_t *>(nanoappBinaryDramAlloc(mMemorySpan, alignment));
+  }
+  if (mAddr == nullptr) {
+    LOGE("Failed to allocate memory for nanoapp of size %zu", mMemorySpan);
+    return false;
+  }
+
+  // Map the segments.
+  for (const ProgramHeader *ph = first; ph <= last; ++ph) {
+    if (ph->p_type == PT_LOAD) {
+      ElfAddr startPage = getPhyAddrOf(ph->p_vaddr);
+      mSegments.emplace_back(/* pAddr= */ startPage, /* memSize= */ ph->p_memsz,
+                             /* permission= */ ph->p_flags);
+
+      // Copy the content.
+      memcpy(reinterpret_cast<void *>(startPage), binary + ph->p_offset,
+             ph->p_filesz);
+      // If the memory size of this segment exceeds the file size fill the gap
+      // with zeros.
+      if (ph->p_memsz > ph->p_filesz) {
+        memset(reinterpret_cast<void *>(startPage + ph->p_filesz), 0,
+               ph->p_memsz - ph->p_filesz);
+      }
+
+      LOGV("vAddr: 0x%" PRIx64 ", pAddr: 0x%" PRIx64 ", memSize: 0x%" PRIx32
+           ", permission: 0x%" PRIx32,
+           static_cast<uint64_t>(ph->p_vaddr),
+           static_cast<uint64_t>(mSegments.back().pAddr),
+           mSegments.back().memSize, mSegments.back().permission);
+    } else {
+      LOGE("Non-loadable segment found between loadable segments");
+      return false;
+    }
+  }
+
+  LOGD("Totally %zu loadable Segments. Starting vAddr: 0x%" PRIx64
+       ", memory span: %zu, binary base addr: %p",
+       mSegments.size(), static_cast<uint64_t>(mStartingVa), mMemorySpan,
+       mAddr);
+
+  return true;
+}
+
+void NanoappLoader::MemoryMapping::wipeCache() const {
+  wipeSystemCaches(reinterpret_cast<uintptr_t>(mAddr), mMemorySpan);
+}
+
 NanoappLoader *NanoappLoader::create(void *elfInput, bool mapIntoTcm) {
   if (elfInput == nullptr) {
     LOGE("Elf header must not be null");
@@ -365,7 +425,7 @@ bool NanoappLoader::open() {
   } else {
     // Wipe caches before calling init array to ensure initializers are not in
     // the data cache.
-    wipeSystemCaches(reinterpret_cast<uintptr_t>(mMapping), mMemorySpan);
+    mMapping.wipeCache();
     if (!callInitArray()) {
       LOGE("Failed to perform static init");
     } else {
@@ -377,8 +437,12 @@ bool NanoappLoader::open() {
 }
 
 void NanoappLoader::close() {
-  callAtexitFunctions();
-  callTerminatorArray();
+  {
+    NanoappMemoryGuard guard(mMapping.getLoadableSegments().data(),
+                             mMapping.getLoadableSegments().size());
+    callAtexitFunctions();
+    callTerminatorArray();
+  }
   freeAllocatedData();
 }
 
@@ -403,21 +467,6 @@ void NanoappLoader::registerAtexitFunction(struct AtExitCallback &cb) {
   }
 }
 
-void NanoappLoader::mapBss(const ProgramHeader *hdr) {
-  // if the memory size of this segment exceeds the file size zero fill the
-  // difference.
-  LOGV("Program Hdr mem sz: %u file size: %u", hdr->p_memsz, hdr->p_filesz);
-  if (hdr->p_memsz > hdr->p_filesz) {
-    ElfAddr endOfFile = hdr->p_vaddr + hdr->p_filesz + mLoadBias;
-    ElfAddr endOfMem = hdr->p_vaddr + hdr->p_memsz + mLoadBias;
-    if (endOfMem > endOfFile) {
-      auto deltaMem = endOfMem - endOfFile;
-      LOGV("Zeroing out %u from page %x", deltaMem, endOfFile);
-      memset(reinterpret_cast<void *>(endOfFile), 0, deltaMem);
-    }
-  }
-}
-
 bool NanoappLoader::callInitArray() {
   bool success = true;
   // Sets global variable used by atexit in case it's invoked as part of
@@ -427,16 +476,20 @@ bool NanoappLoader::callInitArray() {
   // TODO(b/151847750): ELF can have other sections like .init, .preinit, .fini
   // etc. Be sure to look for those if they end up being something that should
   // be supported for nanoapps.
+  NanoappMemoryGuard guard(mMapping.getLoadableSegments().data(),
+                           mMapping.getLoadableSegments().size());
   for (size_t i = 0; i < mNumSectionHeaders; ++i) {
     const char *name = getSectionHeaderName(mSectionHeadersPtr[i].sh_name);
     if (strncmp(name, kInitArrayName, strlen(kInitArrayName)) == 0) {
-      LOGV("Invoking init function");
-      uintptr_t initArray =
-          static_cast<uintptr_t>(mLoadBias + mSectionHeadersPtr[i].sh_addr);
+      LOGV("Parsing %zu init functions",
+           static_cast<size_t>(mSectionHeadersPtr[i].sh_size) /
+               sizeof(uintptr_t));
+      auto initArray = mMapping.getPhyAddrOf(mSectionHeadersPtr[i].sh_addr);
       uintptr_t offset = 0;
       while (offset < mSectionHeadersPtr[i].sh_size) {
-        ElfAddr *funcPtr = reinterpret_cast<ElfAddr *>(initArray + offset);
-        uintptr_t initFunction = static_cast<uintptr_t>(*funcPtr);
+        auto *funcPtr = reinterpret_cast<ElfAddr *>(initArray + offset);
+        auto initFunction = static_cast<uintptr_t>(*funcPtr);
+        LOGV("Invoking init function at 0x%p", funcPtr);
         ((void (*)())initFunction)();
         offset += sizeof(initFunction);
         if (gStaticInitFailure) {
@@ -460,11 +513,6 @@ uintptr_t NanoappLoader::roundDownToAlign(uintptr_t virtualAddr,
 }
 
 void NanoappLoader::freeAllocatedData() {
-  if (mIsTcmBinary) {
-    nanoappBinaryFree(mMapping);
-  } else {
-    nanoappBinaryDramFree(mMapping);
-  }
   memoryFreeDram(mSectionHeadersPtr);
   memoryFreeDram(mSectionNamesPtr);
   mDynamicSymbolTablePtr = nullptr;
@@ -608,76 +656,27 @@ bool NanoappLoader::createMappings() {
   while (first->p_type != PT_LOAD && first <= last) {
     ++first;
   }
-
-  bool success = false;
   if (first->p_type != PT_LOAD) {
     LOGE("Unable to find any load segments in the binary");
-  } else {
-    // Verify that the first load segment has a program header
-    // first byte of a valid load segment can't be greater than the
-    // program header offset
-    bool valid =
-        (first->p_offset < getElfHeader()->e_phoff) &&
-        (first->p_filesz >= (getElfHeader()->e_phoff +
-                             (numProgramHeaders * sizeof(ProgramHeader))));
-    if (!valid) {
-      LOGE("Load segment program header validation failed");
-    } else {
-      // Get the last load segment
-      while (last > first && last->p_type != PT_LOAD) --last;
-
-      size_t alignment = first->p_align;
-      size_t memorySpan = last->p_vaddr + last->p_memsz - first->p_vaddr;
-      LOGV("Nanoapp image Memory Span: %zu", memorySpan);
-
-      if (mIsTcmBinary) {
-        mMapping =
-            static_cast<uint8_t *>(nanoappBinaryAlloc(memorySpan, alignment));
-      } else {
-        mMapping = static_cast<uint8_t *>(
-            nanoappBinaryDramAlloc(memorySpan, alignment));
-      }
-
-      if (mMapping == nullptr) {
-        LOG_OOM();
-      } else {
-        LOGV("Starting location of mappings %p", mMapping);
-        mMemorySpan = memorySpan;
-
-        // Calculate the load bias using the first load segment.
-        uintptr_t adjustedFirstLoadSegAddr =
-            roundDownToAlign(first->p_vaddr, alignment);
-        mLoadBias =
-            reinterpret_cast<uintptr_t>(mMapping) - adjustedFirstLoadSegAddr;
-        LOGV("Load bias is %lu", static_cast<long unsigned int>(mLoadBias));
-
-        success = true;
-      }
-    }
+    return false;
   }
 
-  if (success) {
-    // Map the remaining segments
-    for (const ProgramHeader *ph = first; ph <= last; ++ph) {
-      if (ph->p_type == PT_LOAD) {
-        ElfAddr segStart = ph->p_vaddr + mLoadBias;
-        void *startPage = reinterpret_cast<void *>(segStart);
-        void *binaryStartPage = mBinary + ph->p_offset;
-        size_t segmentLen = ph->p_filesz;
-
-        LOGV("Mapping start page %p from %p with length %zu", startPage,
-             binaryStartPage, segmentLen);
-        memcpy(startPage, binaryStartPage, segmentLen);
-        mapBss(ph);
-      } else {
-        LOGE("Non-load segment found between load segments");
-        success = false;
-        break;
-      }
-    }
+  // Verify that the first load segment has a program header
+  // first byte of a valid load segment can't be greater than the
+  // program header offset
+  bool valid =
+      (first->p_offset < getElfHeader()->e_phoff) &&
+      (first->p_filesz >=
+       (getElfHeader()->e_phoff + (numProgramHeaders * sizeof(ProgramHeader))));
+  if (!valid) {
+    LOGE("Load segment program header validation failed");
+    return false;
   }
 
-  return success;
+  // Get the last load segment
+  while (last > first && last->p_type != PT_LOAD) --last;
+
+  return mMapping.construct(first, last, mIsTcmBinary, mBinary);
 }
 
 NanoappLoader::ElfSym *NanoappLoader::getDynamicSymbol(
@@ -700,25 +699,25 @@ void *NanoappLoader::getSymbolTarget(const ElfSym *symbol) {
   if (symbol == nullptr || symbol->st_shndx == SHN_UNDEF) {
     return nullptr;
   }
-  return mMapping + symbol->st_value;
+  return reinterpret_cast<void *>(mMapping.getPhyAddrOf(symbol->st_value));
 }
 
 void *NanoappLoader::resolveData(size_t posInSymbolTable) {
   const ElfSym *symbol = getDynamicSymbol(posInSymbolTable);
   const char *dataName = getDataName(symbol);
-  void *target = nullptr;
-
-  if (dataName != nullptr) {
-    LOGV("Resolving %s", dataName);
-    target = findExportedSymbol(dataName);
-    if (target == nullptr) {
-      target = getSymbolTarget(symbol);
-    }
-    if (target == nullptr) {
-      LOGE("Unable to find %s", dataName);
-    }
+  if (dataName == nullptr) {
+    LOGV("Resolving %s failed", dataName);
+    return nullptr;
+  }
+  void *target = findExportedSymbol(dataName);
+  if (target == nullptr) {
+    target = getSymbolTarget(symbol);
+  }
+  if (target == nullptr) {
+    LOGE("Unable to find symbol %s", dataName);
+  } else {
+    LOGV("Symbol %s is found at 0x%p", dataName, target);
   }
-
   return target;
 }
 
@@ -793,12 +792,14 @@ void NanoappLoader::callTerminatorArray() {
   for (size_t i = 0; i < mNumSectionHeaders; ++i) {
     const char *name = getSectionHeaderName(mSectionHeadersPtr[i].sh_name);
     if (strncmp(name, kFiniArrayName, strlen(kFiniArrayName)) == 0) {
-      uintptr_t finiArray =
-          static_cast<uintptr_t>(mLoadBias + mSectionHeadersPtr[i].sh_addr);
+      LOGV("Parsing %zu fini_array functions",
+           static_cast<size_t>(mSectionHeadersPtr[i].sh_size));
+      auto finiArray = mMapping.getPhyAddrOf(mSectionHeadersPtr[i].sh_addr);
       uintptr_t offset = 0;
       while (offset < mSectionHeadersPtr[i].sh_size) {
-        ElfAddr *funcPtr = reinterpret_cast<ElfAddr *>(finiArray + offset);
-        uintptr_t finiFunction = static_cast<uintptr_t>(*funcPtr);
+        auto *funcPtr = reinterpret_cast<ElfAddr *>(finiArray + offset);
+        auto finiFunction = static_cast<uintptr_t>(*funcPtr);
+        LOGV("Invoking fini function at 0x%p", funcPtr);
         ((void (*)())finiFunction)();
         offset += sizeof(finiFunction);
       }
diff --git a/platform/shared/nanoapp_memory_guard_no_op/include/chre/target_platform/nanoapp_memory_guard_base.h b/platform/shared/nanoapp_memory_guard_no_op/include/chre/target_platform/nanoapp_memory_guard_base.h
new file mode 100644
index 00000000..c0b7ce3d
--- /dev/null
+++ b/platform/shared/nanoapp_memory_guard_no_op/include/chre/target_platform/nanoapp_memory_guard_base.h
@@ -0,0 +1,35 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef CHRE_PLATFORM_NANOAPP_MEMORY_GUARD_BASE_H_
+#define CHRE_PLATFORM_NANOAPP_MEMORY_GUARD_BASE_H_
+
+#include "chre/platform/platform_nanoapp.h"
+#include "chre/platform/shared/nanoapp_loader.h"
+#include "chre/util/non_copyable.h"
+
+namespace chre {
+
+class NanoappMemoryGuardBase : public NonCopyable {
+ public:
+  explicit NanoappMemoryGuardBase(const PlatformNanoapp & /*nanoapp*/) {}
+  NanoappMemoryGuardBase(
+      const NanoappLoader::LoadableSegment * /*loadable_segment*/,
+      size_t /*size*/) {}
+  ~NanoappMemoryGuardBase() = default;
+};
+}  // namespace chre
+#endif  // CHRE_PLATFORM_NANOAPP_MEMORY_GUARD_BASE_H_
\ No newline at end of file
diff --git a/platform/shared/pal_system_api.cc b/platform/shared/pal_system_api.cc
index bd805024..1980ec51 100644
--- a/platform/shared/pal_system_api.cc
+++ b/platform/shared/pal_system_api.cc
@@ -66,6 +66,7 @@ const chrePalSystemApi gChrePalSystemApi = {
     palSystemApiLog,                     /* log */
     palSystemApiMemoryAlloc,             /* memoryAlloc */
     palSystemApiMemoryFree,              /* memoryFree */
+    palSystemApiForceDramAccess,         /* forceDramAccess */
 };
 
 }  // namespace chre
diff --git a/platform/slpi/memory.cc b/platform/slpi/memory.cc
index 8ac624d1..b583df31 100644
--- a/platform/slpi/memory.cc
+++ b/platform/slpi/memory.cc
@@ -95,4 +95,8 @@ void palSystemApiMemoryFree(void *pointer) {
   free(pointer);
 }
 
+void palSystemApiForceDramAccess() {
+  // No-op
+}
+
 }  // namespace chre
diff --git a/platform/slpi/platform_nanoapp.cc b/platform/slpi/platform_nanoapp.cc
index 979debeb..ebfc85b0 100644
--- a/platform/slpi/platform_nanoapp.cc
+++ b/platform/slpi/platform_nanoapp.cc
@@ -69,6 +69,18 @@ void PlatformNanoapp::end() {
   closeNanoapp();
 }
 
+void PlatformNanoapp::invokeEventFreeCallback(
+    chreEventCompleteFunction *function, const uint16_t eventType,
+    void *const eventData) const {
+  function(eventType, eventData);
+}
+
+void PlatformNanoapp::invokeMessageFreeCallback(
+    chreMessageFreeFunction *function, void *message,
+    const size_t messageSize) const {
+  function(message, messageSize);
+}
+
 bool PlatformNanoappBase::setAppInfo(uint64_t appId, uint32_t appVersion,
                                      const char *appFilename,
                                      uint32_t targetApiVersion) {
diff --git a/platform/tinysys/host_link.cc b/platform/tinysys/host_link.cc
index 68b80cc1..7645cfdb 100644
--- a/platform/tinysys/host_link.cc
+++ b/platform/tinysys/host_link.cc
@@ -25,8 +25,6 @@
 #include "chre/platform/shared/host_protocol_chre.h"
 #include "chre/platform/shared/log_buffer_manager.h"
 #include "chre/platform/shared/nanoapp_load_manager.h"
-#include "chre/platform/system_time.h"
-#include "chre/platform/system_timer.h"
 #include "chre/util/flatbuffers/helpers.h"
 #include "chre/util/nested_data_ptr.h"
 #include "chre_api/chre.h"
@@ -123,7 +121,6 @@ struct NanoappListData {
 };
 
 enum class PendingMessageType {
-  Shutdown,
   NanoappMessageToHost,
   HubInfoResponse,
   NanoappListResponse,
@@ -131,34 +128,32 @@ enum class PendingMessageType {
   UnloadNanoappResponse,
   DebugDumpData,
   DebugDumpResponse,
-  TimeSyncRequest,
   LowPowerMicAccessRequest,
   LowPowerMicAccessRelease,
   EncodedLogMessage,
-  SelfTestResponse,
-  MetricLog,
-  NanConfigurationRequest,
-  PulseRequest,
   PulseResponse,
   NanoappTokenDatabaseInfo,
   MessageDeliveryStatus,
 };
 
 struct PendingMessage {
-  PendingMessage(PendingMessageType msgType, uint16_t hostClientId) {
-    type = msgType;
-    data.hostClientId = hostClientId;
+  static PendingMessage createFromHostClientId(const uint16_t hostClientId) {
+    PendingMessage msg(PendingMessageType::HubInfoResponse);
+    msg.hostClientId = hostClientId;
+    return msg;
   }
 
-  PendingMessage(PendingMessageType msgType,
-                 const HostMessage *msgToHost = nullptr) {
-    type = msgType;
-    data.msgToHost = msgToHost;
+  static PendingMessage createFromMessageToHost(const HostMessage *msgToHost) {
+    PendingMessage msg(PendingMessageType::NanoappMessageToHost);
+    msg.msgToHost = msgToHost;
+    return msg;
   }
 
-  PendingMessage(PendingMessageType msgType, ChreFlatBufferBuilder *builder) {
-    type = msgType;
-    data.builder = builder;
+  static PendingMessage createFromFlatBufferBuilder(
+      const PendingMessageType msgType, ChreFlatBufferBuilder *builder) {
+    PendingMessage msg(msgType);
+    msg.builder = builder;
+    return msg;
   }
 
   PendingMessageType type;
@@ -166,7 +161,14 @@ struct PendingMessage {
     const HostMessage *msgToHost;
     uint16_t hostClientId;
     ChreFlatBufferBuilder *builder;
-  } data;
+  };
+
+ private:
+  explicit PendingMessage(const PendingMessageType msgType) : type(msgType) {
+    msgToHost = nullptr;
+    builder = nullptr;
+    hostClientId = 0;
+  }
 };
 
 constexpr size_t kOutboundQueueSize = 100;
@@ -195,8 +197,6 @@ DRAM_REGION_FUNCTION bool generateMessageFromBuilder(
 
 DRAM_REGION_FUNCTION bool generateMessageToHost(const HostMessage *message) {
   LOGV("%s: message size %zu", __func__, message->message.size());
-  // TODO(b/285219398): ideally we'd construct our flatbuffer directly in the
-  // host-supplied buffer
   constexpr size_t kFixedReserveSize = 88;
   ChreFlatBufferBuilder builder(message->message.size() + kFixedReserveSize);
   HostProtocolChre::encodeNanoappMessage(
@@ -221,9 +221,9 @@ DRAM_REGION_FUNCTION int generateHubInfoResponse(uint16_t hostClientId) {
       "Clang " STRINGIFY(__clang_major__) "." STRINGIFY(
           __clang_minor__) "." STRINGIFY(__clang_patchlevel__);
   constexpr uint32_t kLegacyPlatformVersion = 0;
-  constexpr uint32_t kLegacyToolchainVersion =
-      ((__clang_major__ & 0xFF) << 24) | ((__clang_minor__ & 0xFF) << 16) |
-      (__clang_patchlevel__ & 0xFFFF);
+  constexpr uint32_t kLegacyToolchainVersion = (__clang_major__ & 0xFF) << 24 |
+                                               (__clang_minor__ & 0xFF) << 16 |
+                                               (__clang_patchlevel__ & 0xFFFF);
   constexpr float kPeakMips = 350;
   constexpr float kStoppedPower = 0;
   constexpr float kSleepPower = 1;
@@ -247,14 +247,14 @@ DRAM_REGION_FUNCTION bool dequeueMessage(PendingMessage pendingMsg) {
   bool result = false;
   switch (pendingMsg.type) {
     case PendingMessageType::NanoappMessageToHost:
-      result = generateMessageToHost(pendingMsg.data.msgToHost);
+      result = generateMessageToHost(pendingMsg.msgToHost);
       break;
 
     case PendingMessageType::HubInfoResponse:
-      result = generateHubInfoResponse(pendingMsg.data.hostClientId);
+      result = generateHubInfoResponse(pendingMsg.hostClientId);
       break;
     default:
-      result = generateMessageFromBuilder(pendingMsg.data.builder);
+      result = generateMessageFromBuilder(pendingMsg.builder);
       break;
   }
   return result;
@@ -268,8 +268,8 @@ DRAM_REGION_FUNCTION bool dequeueMessage(PendingMessage pendingMsg) {
  *
  * @return true if the message was successfully added to the queue.
  */
-DRAM_REGION_FUNCTION bool enqueueMessage(PendingMessage pendingMsg) {
-  return gOutboundQueue.push(pendingMsg);
+DRAM_REGION_FUNCTION bool enqueueMessage(const PendingMessage message) {
+  return gOutboundQueue.push(message);
 }
 
 /**
@@ -288,7 +288,7 @@ DRAM_REGION_FUNCTION bool enqueueMessage(PendingMessage pendingMsg) {
  */
 DRAM_REGION_FUNCTION bool buildAndEnqueueMessage(
     PendingMessageType msgType, size_t initialBufferSize,
-    MessageBuilderFunction *msgBuilder, void *cookie) {
+    MessageBuilderFunction *buildMsgFunc, void *cookie) {
   LOGV("%s: message type %d, size %zu", __func__, msgType, initialBufferSize);
   bool pushed = false;
 
@@ -297,9 +297,10 @@ DRAM_REGION_FUNCTION bool buildAndEnqueueMessage(
     LOGE("Couldn't allocate memory for message type %d",
          static_cast<int>(msgType));
   } else {
-    msgBuilder(*builder, cookie);
+    buildMsgFunc(*builder, cookie);
 
-    if (!enqueueMessage(PendingMessage(msgType, builder.get()))) {
+    if (!enqueueMessage(PendingMessage::createFromFlatBufferBuilder(
+            msgType, builder.get()))) {
       LOGE("Couldn't push message type %d to outbound queue",
            static_cast<int>(msgType));
     } else {
@@ -361,8 +362,8 @@ DRAM_REGION_FUNCTION void handleUnloadNanoappCallback(uint16_t /*type*/,
   HostProtocolChre::encodeUnloadNanoappResponse(*builder, cbData->hostClientId,
                                                 cbData->transactionId, success);
 
-  if (!enqueueMessage(PendingMessage(PendingMessageType::UnloadNanoappResponse,
-                                     builder.get()))) {
+  if (!enqueueMessage(PendingMessage::createFromFlatBufferBuilder(
+          PendingMessageType::UnloadNanoappResponse, builder.get()))) {
     LOGE("Failed to send unload response to host: %x transactionID: 0x%x",
          cbData->hostClientId, cbData->transactionId);
   } else {
@@ -388,10 +389,11 @@ DRAM_REGION_FUNCTION void sendDebugDumpData(uint16_t hostClientId,
   };
 
   constexpr size_t kFixedSizePortion = 52;
-  DebugDumpMessageData data;
-  data.hostClientId = hostClientId;
-  data.debugStr = debugStr;
-  data.debugStrSize = debugStrSize;
+  DebugDumpMessageData data{
+      .hostClientId = hostClientId,
+      .debugStr = debugStr,
+      .debugStrSize = debugStrSize,
+  };
   buildAndEnqueueMessage(PendingMessageType::DebugDumpData,
                          kFixedSizePortion + debugStrSize, msgBuilder, &data);
 }
@@ -412,10 +414,11 @@ DRAM_REGION_FUNCTION void sendDebugDumpResponse(uint16_t hostClientId,
   };
 
   constexpr size_t kInitialSize = 52;
-  DebugDumpResponseData data;
-  data.hostClientId = hostClientId;
-  data.success = success;
-  data.dataCount = dataCount;
+  DebugDumpResponseData data{
+      .hostClientId = hostClientId,
+      .success = success,
+      .dataCount = dataCount,
+  };
   buildAndEnqueueMessage(PendingMessageType::DebugDumpResponse, kInitialSize,
                          msgBuilder, &data);
 }
@@ -436,14 +439,9 @@ DRAM_REGION_FUNCTION void sendDebugDumpResultToHost(uint16_t hostClientId,
 }
 
 DRAM_REGION_FUNCTION HostLinkBase::HostLinkBase() {
-  LOGV("HostLinkBase::%s", __func__);
   initializeIpi();
 }
 
-DRAM_REGION_FUNCTION HostLinkBase::~HostLinkBase() {
-  LOGV("HostLinkBase::%s", __func__);
-}
-
 DRAM_REGION_FUNCTION void HostLinkBase::vChreReceiveTask(void *pvParameters) {
   int i = 0;
   int ret = 0;
@@ -451,26 +449,41 @@ DRAM_REGION_FUNCTION void HostLinkBase::vChreReceiveTask(void *pvParameters) {
   LOGV("%s", __func__);
   while (true) {
     LOGV("%s calling ipi_recv_reply(), Cnt=%d", __func__, i++);
-    ret = ipi_recv_reply(IPI_IN_C_HOST_SCP_CHRE, (void *)&gChreIpiAckToHost[0],
-                         1);
+    ret = ipi_recv_reply(IPI_IN_C_HOST_SCP_CHRE, gChreIpiAckToHost, 1);
     if (ret != IPI_ACTION_DONE)
       LOGE("%s ipi_recv_reply() ret = %d", __func__, ret);
     LOGV("%s reply_end", __func__);
   }
 }
 
+DRAM_REGION_FUNCTION void HostLinkBase::waitIfHostLinkIsNotInitialized() {
+  if (mInitialized) {
+    return;
+  }
+
+  LockGuard lock(mInitMutex);
+  while (!mInitialized) {
+    mInitCv.wait(mInitMutex);
+  }
+
+  LOGD("%zu messaged queued while waiting for host link to get ready",
+       gOutboundQueue.size());
+}
+
 DRAM_REGION_FUNCTION void HostLinkBase::vChreSendTask(void *pvParameters) {
+  auto hostLink = static_cast<HostLinkBase *>(pvParameters);
   while (true) {
-    auto msg = gOutboundQueue.pop();
+    hostLink->waitIfHostLinkIsNotInitialized();
+    const auto msg = gOutboundQueue.pop();
     dequeueMessage(msg);
   }
 }
 
-DRAM_REGION_FUNCTION void HostLinkBase::chreIpiHandler(unsigned int id,
+DRAM_REGION_FUNCTION void HostLinkBase::chreIpiHandler(unsigned int /*id*/,
                                                        void *prdata, void *data,
-                                                       unsigned int len) {
+                                                       unsigned int /*len*/) {
   /* receive magic and cmd */
-  struct ScpChreIpiMsg msg = *(struct ScpChreIpiMsg *)data;
+  ScpChreIpiMsg msg = *static_cast<struct ScpChreIpiMsg *>(data);
 
   // check the magic number and payload size need to be copy(if need) */
   LOGD("%s: Received a message from AP. Size=%u", __func__, msg.size);
@@ -511,8 +524,7 @@ DRAM_REGION_FUNCTION void HostLinkBase::chreIpiHandler(unsigned int id,
 #else  // SCP_CHRE_USE_DMA
 
   dvfs_enable_DRAM_resource(CHRE_MEM_ID);
-  memcpy(static_cast<void *>(gChreRecvBuffer),
-         reinterpret_cast<void *>(srcAddr), msg.size);
+  memcpy(gChreRecvBuffer, reinterpret_cast<void *>(srcAddr), msg.size);
   dvfs_disable_DRAM_resource(CHRE_MEM_ID);
 
 #endif  // SCP_CHRE_USE_DMA
@@ -525,7 +537,7 @@ DRAM_REGION_FUNCTION void HostLinkBase::chreIpiHandler(unsigned int id,
   gChreIpiAckToHost[1] = msg.size;
 }
 
-DRAM_REGION_FUNCTION void HostLinkBase::initializeIpi(void) {
+DRAM_REGION_FUNCTION void HostLinkBase::initializeIpi() {
   bool success = false;
   int ret;
   constexpr size_t kBackgroundTaskStackSize = 1024;
@@ -537,29 +549,35 @@ DRAM_REGION_FUNCTION void HostLinkBase::initializeIpi(void) {
 #endif
 
   // prepared share memory information and register the callback functions
-  if (!(ret = scp_get_reserve_mem_by_id(SCP_CHRE_FROM_MEM_ID,
-                                        &gChreSubregionRecvAddr,
-                                        &gChreSubregionRecvSize))) {
+  if (!scp_get_reserve_mem_by_id(SCP_CHRE_FROM_MEM_ID, &gChreSubregionRecvAddr,
+                                 &gChreSubregionRecvSize)) {
     LOGE("%s: get SCP_CHRE_FROM_MEM_ID memory fail", __func__);
-  } else if (!(ret = scp_get_reserve_mem_by_id(SCP_CHRE_TO_MEM_ID,
-                                               &gChreSubregionSendAddr,
-                                               &gChreSubregionSendSize))) {
+  } else if (!scp_get_reserve_mem_by_id(SCP_CHRE_TO_MEM_ID,
+                                        &gChreSubregionSendAddr,
+                                        &gChreSubregionSendSize)) {
     LOGE("%s: get SCP_CHRE_TO_MEM_ID memory fail", __func__);
   } else if (pdPASS != xTaskCreate(vChreReceiveTask, "CHRE_RECEIVE",
-                                   kBackgroundTaskStackSize, (void *)0,
-                                   kBackgroundTaskPriority, NULL)) {
+                                   kBackgroundTaskStackSize,
+                                   /* pvParameters= */ nullptr,
+                                   kBackgroundTaskPriority,
+                                   /* pxCreatedTask= */ nullptr)) {
     LOGE("%s failed to create ipi receiver task", __func__);
-  } else if (pdPASS != xTaskCreate(vChreSendTask, "CHRE_SEND",
-                                   kBackgroundTaskStackSize, (void *)0,
-                                   kBackgroundTaskPriority, NULL)) {
+  } else if (pdPASS !=
+             xTaskCreate(vChreSendTask, "CHRE_SEND", kBackgroundTaskStackSize,
+                         /* pvParameters= */ this, kBackgroundTaskPriority,
+                         /* pxCreatedTask= */ nullptr)) {
     LOGE("%s failed to create ipi outbound message queue task", __func__);
   } else if (IPI_ACTION_DONE !=
-             (ret = ipi_register(IPI_IN_C_HOST_SCP_CHRE, (void *)chreIpiHandler,
-                                 (void *)this, (void *)&gChreIpiRecvData[0]))) {
+             (ret = ipi_register(
+                  /* ipi_id= */ IPI_IN_C_HOST_SCP_CHRE,
+                  /* cb= */ reinterpret_cast<void *>(chreIpiHandler),
+                  /* prData= */ this, /* msg= */ &gChreIpiRecvData[0]))) {
     LOGE("ipi_register IPI_IN_C_HOST_SCP_CHRE failed, %d", ret);
   } else if (IPI_ACTION_DONE !=
-             (ret = ipi_register(IPI_OUT_C_SCP_HOST_CHRE, NULL, (void *)this,
-                                 (void *)&gChreIpiAckFromHost[0]))) {
+             (ret = ipi_register(/* ipi_id= */ IPI_OUT_C_SCP_HOST_CHRE,
+                                 /* cb= */ nullptr,
+                                 /* prdata= */ this,
+                                 /* msg= */ &gChreIpiAckFromHost[0]))) {
     LOGE("ipi_register IPI_OUT_C_SCP_HOST_CHRE failed, %d", ret);
   } else {
     success = true;
@@ -571,16 +589,16 @@ DRAM_REGION_FUNCTION void HostLinkBase::initializeIpi(void) {
 }
 
 DRAM_REGION_FUNCTION void HostLinkBase::receive(HostLinkBase *instance,
-                                                void *message, int messageLen) {
-  LOGV("%s: message len %d", __func__, messageLen);
-
-  // TODO(b/277128368): A crude way to initially determine daemon's up - set
-  // a flag on the first message received. This is temporary until a better
-  // way to do this is available.
-  instance->setInitialized(true);
+                                                void *message,
+                                                size_t messageLen) {
+  LOGV("%s: message len %zu", __func__, messageLen);
+  if (!instance->mInitialized) {
+    instance->mInitialized = true;
+    instance->mInitCv.notify_one();
+  }
 
   if (!HostProtocolChre::decodeMessageFromHost(message, messageLen)) {
-    LOGE("Failed to decode msg %p of len %u", message, messageLen);
+    LOGE("Failed to decode msg %p of len %zu", message, messageLen);
   }
 }
 
@@ -592,7 +610,7 @@ DRAM_REGION_FUNCTION bool HostLinkBase::send(uint8_t *data, size_t dataLen) {
 #define HOST_LINK_IPI_RESPONSE_TIMEOUT_MS 100
 #endif
   LOGV("HostLinkBase::%s: %zu, %p", __func__, dataLen, data);
-  struct ScpChreIpiMsg msg;
+  ScpChreIpiMsg msg{};
   msg.magic = SCP_CHRE_MAGIC;
   msg.size = dataLen;
 
@@ -672,7 +690,8 @@ DRAM_REGION_FUNCTION void HostLinkBase::sendNanConfiguration(
 }
 
 DRAM_REGION_FUNCTION void HostLinkBase::sendLogMessageV2(
-    const uint8_t *logMessage, size_t logMessageSize, uint32_t numLogsDropped) {
+    const uint8_t *logMessage, const size_t logMessageSize,
+    uint32_t numLogsDropped) const {
   LOGV("%s: size %zu", __func__, logMessageSize);
   struct LogMessageData {
     const uint8_t *logMsg;
@@ -683,19 +702,16 @@ DRAM_REGION_FUNCTION void HostLinkBase::sendLogMessageV2(
   LogMessageData logMessageData{logMessage, logMessageSize, numLogsDropped};
 
   auto msgBuilder = [](ChreFlatBufferBuilder &builder, void *cookie) {
-    const auto *data = static_cast<const LogMessageData *>(cookie);
+    const auto data = static_cast<const LogMessageData *>(cookie);
     HostProtocolChre::encodeLogMessagesV2(
         builder, data->logMsg, data->logMsgSize, data->numLogsDropped);
   };
 
   constexpr size_t kInitialSize = 128;
-  bool result = false;
-  if (isInitialized()) {
-    result = buildAndEnqueueMessage(
-        PendingMessageType::EncodedLogMessage,
-        kInitialSize + logMessageSize + sizeof(numLogsDropped), msgBuilder,
-        &logMessageData);
-  }
+  bool result = buildAndEnqueueMessage(
+      PendingMessageType::EncodedLogMessage,
+      kInitialSize + logMessageSize + sizeof(numLogsDropped), msgBuilder,
+      &logMessageData);
 
 #ifdef CHRE_USE_BUFFERED_LOGGING
   if (LogBufferManagerSingleton::isInitialized()) {
@@ -708,15 +724,7 @@ DRAM_REGION_FUNCTION void HostLinkBase::sendLogMessageV2(
 
 DRAM_REGION_FUNCTION bool HostLink::sendMessage(HostMessage const *message) {
   LOGV("HostLink::%s size(%zu)", __func__, message->message.size());
-  bool success = false;
-
-  if (isInitialized()) {
-    success = enqueueMessage(
-        PendingMessage(PendingMessageType::NanoappMessageToHost, message));
-  } else {
-    LOGW("Dropping outbound message: host link not initialized yet");
-  }
-  return success;
+  return enqueueMessage(PendingMessage::createFromMessageToHost(message));
 }
 
 DRAM_REGION_FUNCTION bool HostLink::sendMessageDeliveryStatus(
@@ -736,10 +744,6 @@ DRAM_REGION_FUNCTION bool HostLink::sendMessageDeliveryStatus(
                                 /* initialBufferSize= */ 64, msgBuilder, &args);
 }
 
-// TODO(b/285219398): HostMessageHandlers member function implementations are
-// expected to be (mostly) identical for any platform that uses flatbuffers
-// to encode messages - refactor the host link to merge the multiple copies
-// we currently have.
 DRAM_REGION_FUNCTION void HostMessageHandlers::handleNanoappMessage(
     uint64_t appId, uint32_t messageType, uint16_t hostEndpoint,
     const void *messageData, size_t messageDataLen, bool isReliable,
@@ -762,8 +766,7 @@ DRAM_REGION_FUNCTION void HostMessageHandlers::handleMessageDeliveryStatus(
 DRAM_REGION_FUNCTION void HostMessageHandlers::handleHubInfoRequest(
     uint16_t hostClientId) {
   LOGV("%s: host client id %d", __func__, hostClientId);
-  enqueueMessage(
-      PendingMessage(PendingMessageType::HubInfoResponse, hostClientId));
+  enqueueMessage(PendingMessage::createFromHostClientId(hostClientId));
 }
 
 DRAM_REGION_FUNCTION void HostMessageHandlers::handleNanoappListRequest(
@@ -877,7 +880,7 @@ DRAM_REGION_FUNCTION void HostLinkBase::sendNanoappTokenDatabaseInfo(
   } args{appId, tokenDatabaseOffset, tokenDatabaseSize};
 
   auto msgBuilder = [](ChreFlatBufferBuilder &builder, void *cookie) {
-    DatabaseInfoArgs *args = static_cast<DatabaseInfoArgs *>(cookie);
+    auto *args = static_cast<DatabaseInfoArgs *>(cookie);
     uint16_t instanceId;
     EventLoopManagerSingleton::get()
         ->getEventLoop()
@@ -897,7 +900,7 @@ DRAM_REGION_FUNCTION void HostLink::flushMessagesSentByNanoapp(
 }
 
 DRAM_REGION_FUNCTION void HostMessageHandlers::handleTimeSyncMessage(
-    int64_t offset) {
+    int64_t /*offset*/) {
   LOGE("%s is unsupported", __func__);
 }
 
@@ -915,7 +918,6 @@ DRAM_REGION_FUNCTION void HostMessageHandlers::handleDebugDumpRequest(
 
 DRAM_REGION_FUNCTION void HostMessageHandlers::handleSettingChangeMessage(
     fbs::Setting setting, fbs::SettingState state) {
-  // TODO(b/285219398): Refactor handleSettingChangeMessage to shared code
   Setting chreSetting;
   bool chreSettingEnabled;
   if (HostProtocolChre::getSettingFromFbs(setting, &chreSetting) &&
diff --git a/platform/tinysys/include/chre/extensions/platform/symbol_list.h b/platform/tinysys/include/chre/extensions/platform/symbol_list.h
new file mode 100644
index 00000000..47e22176
--- /dev/null
+++ b/platform/tinysys/include/chre/extensions/platform/symbol_list.h
@@ -0,0 +1,31 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+ *
+ */
+
+#ifndef CHRE_EXTENSIONS_PLATFORM_SYMBOL_LIST_H_
+#define CHRE_EXTENSIONS_PLATFORM_SYMBOL_LIST_H_
+
+#include "chre/platform/shared/loader_util.h"
+
+namespace chre {
+
+const ExportedData kVendorExportedData[] = {
+    ADD_EXPORTED_C_SYMBOL(_Sinx),
+};
+
+}  // namespace chre
+
+#endif  // CHRE_EXTENSIONS_PLATFORM_SYMBOL_LIST_H_
\ No newline at end of file
diff --git a/platform/tinysys/include/chre/target_platform/host_link_base.h b/platform/tinysys/include/chre/target_platform/host_link_base.h
index 09d1b20c..d7e9ec77 100644
--- a/platform/tinysys/include/chre/target_platform/host_link_base.h
+++ b/platform/tinysys/include/chre/target_platform/host_link_base.h
@@ -17,13 +17,11 @@
 #ifndef CHRE_PLATFORM_TINYSYS_HOST_LINK_BASE_H_
 #define CHRE_PLATFORM_TINYSYS_HOST_LINK_BASE_H_
 
-#include <cinttypes>
 #include <cstddef>
 
 #include "chre/platform/atomic.h"
-#include "chre/platform/mutex.h"
+#include "chre/platform/condition_variable.h"
 #include "chre/platform/shared/host_protocol_chre.h"
-#include "chre/util/lock_guard.h"
 
 namespace chre {
 
@@ -40,24 +38,21 @@ void sendDebugDumpResultToHost(uint16_t hostClientId, const char *debugStr,
 class HostLinkBase {
  public:
   HostLinkBase();
-  ~HostLinkBase();
-
   static void vChreReceiveTask(void * /*pvParameters*/);
   static void vChreSendTask(void * /*pvParameters*/);
   static void chreIpiHandler(unsigned int /*id*/, void * /*prdata*/,
                              void * /*data*/, unsigned int /*len*/);
-  void initializeIpi(void);
+  void initializeIpi();
 
   /**
    * Implements the IPC message receive handler.
    *
-   * @param cookie An opaque pointer that was provided to the IPC driver during
-   *        callback registration.
+   * @param instance An opaque pointer that was provided to the IPC driver
+   * during callback registration.
    * @param message The host message sent to CHRE.
    * @param messageLen The host message length in bytes.
    */
-  static void receive(HostLinkBase * /*instance*/, void * /*message*/,
-                      int /*messageLen*/);
+  static void receive(HostLinkBase *instance, void *message, size_t messageLen);
   /**
    * Send a message to the host.
    *
@@ -65,7 +60,7 @@ class HostLinkBase {
    * @param dataLen Size of the message payload in bytes.
    * @return true if the operation succeeds, false otherwise.
    */
-  static bool send(uint8_t * /*data*/, size_t /*dataLen*/);
+  static bool send(uint8_t *data, size_t dataLen);
 
   /**
    * Enqueues a nanoapp token database info message to be sent to the host if a
@@ -81,14 +76,6 @@ class HostLinkBase {
                                            uint32_t tokenDatabaseOffset,
                                            size_t tokenDatabaseSize);
 
-  void setInitialized(bool initialized) {
-    mInitialized = initialized;
-  }
-
-  bool isInitialized() const {
-    return mInitialized;
-  }
-
   /**
    * Sends a request to the host for a time sync message.
    */
@@ -101,9 +88,8 @@ class HostLinkBase {
    * @param logMessageSize length of the log message buffer
    * @param numLogsDropped the number of logs dropped since CHRE started
    */
-  void sendLogMessageV2(const uint8_t * /*logMessage*/,
-                        size_t /*logMessageSize*/,
-                        uint32_t /*num_logs_dropped*/);
+  void sendLogMessageV2(const uint8_t *logMessage, size_t logMessageSize,
+                        uint32_t numLogsDropped) const;
 
   /**
    * Enqueues a NAN configuration request to be sent to the host.
@@ -113,7 +99,11 @@ class HostLinkBase {
    */
   void sendNanConfiguration(bool enable);
 
+  void waitIfHostLinkIsNotInitialized();
+
  private:
+  Mutex mInitMutex;
+  ConditionVariable mInitCv;
   AtomicBool mInitialized = false;
 };
 
diff --git a/platform/tinysys/include/chre/target_platform/log.h b/platform/tinysys/include/chre/target_platform/log.h
index 83403790..b3d17e90 100644
--- a/platform/tinysys/include/chre/target_platform/log.h
+++ b/platform/tinysys/include/chre/target_platform/log.h
@@ -17,6 +17,7 @@
 #ifndef CHRE_PLATFORM_TINYSYS_LOG_H_
 #define CHRE_PLATFORM_TINYSYS_LOG_H_
 
+#include "chre/platform/shared/log_common.h"
 #include "chre_api/chre.h"
 
 #ifdef __cplusplus
@@ -31,17 +32,6 @@ extern "C" {
 
 #ifdef CHRE_USE_BUFFERED_LOGGING
 
-/**
- * Log via the LogBufferManagerSingleton vaLog method.
- *
- * Defined in system/chre/platform/shared/log_buffer_manager.cc
- *
- * @param level The log level.
- * @param format The format string.
- * @param ... The arguments to print into the final log.
- */
-void chrePlatformLogToBuffer(enum chreLogLevel level, const char *format, ...);
-
 // Print logs to host logcat
 #define CHRE_BUFFER_LOG(level, fmt, arg...)     \
   do {                                          \
diff --git a/platform/tinysys/include/chre/target_platform/nanoapp_memory_guard_base.h b/platform/tinysys/include/chre/target_platform/nanoapp_memory_guard_base.h
new file mode 100644
index 00000000..2973a679
--- /dev/null
+++ b/platform/tinysys/include/chre/target_platform/nanoapp_memory_guard_base.h
@@ -0,0 +1,50 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef CHRE_PLATFORM_NANOAPP_MEMORY_GUARD_BASE_H_
+#define CHRE_PLATFORM_NANOAPP_MEMORY_GUARD_BASE_H_
+
+#include "chre/platform/platform_nanoapp.h"
+#include "chre/platform/shared/nanoapp_loader.h"
+#include "chre/util/non_copyable.h"
+
+namespace chre {
+
+/** Base class for platform-specific nanoapp memory protection. */
+class NanoappMemoryGuardBase : public NonCopyable {
+ public:
+  explicit NanoappMemoryGuardBase(const PlatformNanoapp &nanoapp);
+
+  NanoappMemoryGuardBase(const NanoappLoader::LoadableSegment *loadableSegments,
+                         size_t numSegments);
+
+  virtual ~NanoappMemoryGuardBase();
+
+ private:
+  /**
+   * Applies permissions to the nanoapp's memory segments based on the
+   * permission settings in NanoappLoader::LoadableSegment.
+   */
+  void grantMemoryPermissions() const;
+
+  /** Removes the permissions applied to the nanoapp's memory segments. */
+  void revokeMemoryPermissions() const;
+
+  const NanoappLoader::LoadableSegment *mLoadableSegments = nullptr;
+  size_t mNumSegments = 0;
+};
+}  // namespace chre
+#endif  // CHRE_PLATFORM_NANOAPP_MEMORY_GUARD_BASE_H_
\ No newline at end of file
diff --git a/platform/tinysys/memory.cc b/platform/tinysys/memory.cc
index 0c117536..4258da58 100644
--- a/platform/tinysys/memory.cc
+++ b/platform/tinysys/memory.cc
@@ -112,4 +112,9 @@ void memoryFree(void *pointer) {
     vPortFree(pointer);
   }
 }
+
+void palSystemApiForceDramAccess() {
+  forceDramAccess();
+}
+
 }  // namespace chre
diff --git a/platform/tinysys/nanoapp_memory_guard.cc b/platform/tinysys/nanoapp_memory_guard.cc
new file mode 100644
index 00000000..881595b6
--- /dev/null
+++ b/platform/tinysys/nanoapp_memory_guard.cc
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "chre/platform/shared/nanoapp_memory_guard.h"
+#include "chre/platform/platform_nanoapp.h"
+
+namespace chre {
+NanoappMemoryGuardBase::NanoappMemoryGuardBase(const PlatformNanoapp &nanoapp) {
+  if (nanoapp.isStatic()) {
+    return;
+  }
+
+  auto *loader = static_cast<NanoappLoader *>(nanoapp.getDsoHandle());
+  mLoadableSegments = loader->getLoadableSegments().data();
+  mNumSegments = loader->getLoadableSegments().size();
+  grantMemoryPermissions();
+}
+
+NanoappMemoryGuardBase::NanoappMemoryGuardBase(
+    const NanoappLoader::LoadableSegment *loadableSegments,
+    const size_t numSegments)
+    : mLoadableSegments(loadableSegments), mNumSegments(numSegments) {
+  grantMemoryPermissions();
+}
+
+NanoappMemoryGuardBase::~NanoappMemoryGuardBase() {
+  revokeMemoryPermissions();
+}
+
+void NanoappMemoryGuardBase::grantMemoryPermissions() const {
+  if (mLoadableSegments == nullptr || mNumSegments == 0) {
+    return;
+  }
+  // TODO(b/394483221) - grant permissions based on mLoadableSegments.
+}
+
+void NanoappMemoryGuardBase::revokeMemoryPermissions() const {
+  if (mLoadableSegments == nullptr || mNumSegments == 0) {
+    return;
+  }
+  // TODO(b/394483221) - revoke permissions.
+}
+}  // namespace chre
\ No newline at end of file
diff --git a/platform/zephyr/platform_nanoapp.cc b/platform/zephyr/platform_nanoapp.cc
index fc03516e..7cf49d60 100644
--- a/platform/zephyr/platform_nanoapp.cc
+++ b/platform/zephyr/platform_nanoapp.cc
@@ -57,6 +57,18 @@ bool PlatformNanoapp::isSystemNanoapp() const {
   return (mAppInfo != nullptr && mAppInfo->isSystemNanoapp);
 }
 
+void PlatformNanoapp::invokeEventFreeCallback(
+    chreEventCompleteFunction *function, const uint16_t eventType,
+    void *const eventData) const {
+  function(eventType, eventData);
+}
+
+void PlatformNanoapp::invokeMessageFreeCallback(
+    chreMessageFreeFunction *function, void *message,
+    const size_t messageSize) const {
+  function(message, messageSize);
+}
+
 bool PlatformNanoappBase::isLoaded() const {
   return mIsStatic;
 }
diff --git a/test/simulation/host_message_hub_test.cc b/test/simulation/host_message_hub_test.cc
index 079f6c79..903ef3d4 100644
--- a/test/simulation/host_message_hub_test.cc
+++ b/test/simulation/host_message_hub_test.cc
@@ -74,6 +74,8 @@ class MockHostCallback : public HostMessageHubManager::HostCallback {
               (MessageHubId, SessionId, pw::UniquePtr<std::byte[]> &&, uint32_t,
                uint32_t),
               (override));
+  MOCK_METHOD(bool, onMessageDeliveryStatus,
+              (MessageHubId, SessionId, uint32_t, uint8_t), (override));
   MOCK_METHOD(void, onSessionOpenRequest, (const Session &), (override));
   MOCK_METHOD(void, onSessionOpened, (MessageHubId, SessionId), (override));
   MOCK_METHOD(void, onSessionClosed, (MessageHubId, SessionId, Reason),
diff --git a/test/simulation/wifi_scan_test.cc b/test/simulation/wifi_scan_test.cc
index bf4aecf1..cd3d8c0a 100644
--- a/test/simulation/wifi_scan_test.cc
+++ b/test/simulation/wifi_scan_test.cc
@@ -153,6 +153,96 @@ TEST_F(WifiScanTest, WifiScanBasicSettingTest) {
   unloadNanoapp(appId);
 }
 
+TEST_F(WifiScanRequestQueueTestBase, WifiScanRequestDuringResultTest) {
+  // Test that a nanoapp can request a scan during the result of a previous
+  // scan request.
+
+  // 1. Make nanoapp request scan
+  // 2. Have nanoapp programmed to re-request scan during result (only one time)
+  // 3. Make sure that the second request is accepted
+
+  class WifiScanTestRequestDuringResultNanoapp : public TestNanoapp {
+   public:
+    explicit WifiScanTestRequestDuringResultNanoapp(uint64_t id)
+        : TestNanoapp(TestNanoappInfo{
+              .id = id, .perms = NanoappPermissions::CHRE_PERMS_WIFI}) {}
+
+    void handleEvent(uint32_t, uint16_t eventType,
+                     const void *eventData) override {
+      switch (eventType) {
+        case CHRE_EVENT_WIFI_ASYNC_RESULT: {
+          auto *event = static_cast<const chreAsyncResult *>(eventData);
+          LOGI("got async result success= %d", event->success);
+          TestEventQueueSingleton::get()->pushEvent(
+              CHRE_EVENT_WIFI_ASYNC_RESULT,
+              WifiAsyncData{
+                  .cookie = static_cast<const uint32_t *>(event->cookie),
+                  .errorCode = static_cast<chreError>(event->errorCode)});
+          break;
+        }
+
+        case CHRE_EVENT_WIFI_SCAN_RESULT: {
+          TestEventQueueSingleton::get()->pushEvent(
+              CHRE_EVENT_WIFI_SCAN_RESULT);
+
+          // If this is the first time we receive a scan result, we should
+          // request another scan immediately.
+          if (mScanRequestCount == 1) {
+            mScanRequestCount++;
+            bool success = chreWifiRequestScanAsyncDefault(&mSentCookie);
+            LOGI("requested second scan with success= %d", success);
+            TestEventQueueSingleton::get()->pushEvent(SCAN_REQUEST, success);
+          }
+
+          break;
+        }
+
+        case CHRE_EVENT_TEST_EVENT: {
+          auto event = static_cast<const TestEvent *>(eventData);
+          bool success = false;
+          switch (event->type) {
+            case SCAN_REQUEST:
+              mSentCookie = *static_cast<uint32_t *>(event->data);
+              mScanRequestCount++;
+              success = chreWifiRequestScanAsyncDefault(&(mSentCookie));
+              LOGI("requested scan with success= %d", success);
+              TestEventQueueSingleton::get()->pushEvent(SCAN_REQUEST, success);
+              break;
+          }
+        }
+      }
+    }
+
+   protected:
+    uint32_t mSentCookie;
+    uint32_t mScanRequestCount = 0;
+    WifiAsyncData mReceivedAsyncResult;
+  };
+
+  uint64_t appOneId = loadNanoapp(
+      MakeUnique<WifiScanTestRequestDuringResultNanoapp>(kAppOneId));
+
+  EventLoopManagerSingleton::get()->getSettingManager().postSettingChange(
+      Setting::WIFI_AVAILABLE, true /* enabled */);
+
+  constexpr uint32_t appOneRequestCookie = 0x1010;
+  bool success;
+  WifiAsyncData wifiAsyncData;
+
+  // Request the first scan, which will trigger the second as well
+  sendEventToNanoapp(appOneId, SCAN_REQUEST, appOneRequestCookie);
+  for (int i = 0; i < 2; ++i) {
+    waitForEvent(SCAN_REQUEST, &success);
+    EXPECT_TRUE(success);
+    waitForEvent(CHRE_EVENT_WIFI_ASYNC_RESULT, &wifiAsyncData);
+    EXPECT_EQ(wifiAsyncData.errorCode, CHRE_ERROR_NONE);
+    EXPECT_EQ(*wifiAsyncData.cookie, appOneRequestCookie);
+    waitForEvent(CHRE_EVENT_WIFI_SCAN_RESULT);
+  }
+
+  unloadNanoapp(appOneId);
+}
+
 TEST_F(WifiScanRequestQueueTestBase, WifiQueuedScanSettingChangeTest) {
   CREATE_CHRE_TEST_EVENT(CONCURRENT_NANOAPP_RECEIVED_EXPECTED_ASYNC_EVENT_COUNT,
                          1);
@@ -433,4 +523,4 @@ TEST_F(WifiScanRequestQueueTestBase, WifiScanActiveScanFromDistinctNanoapps) {
 }
 
 }  // namespace
-}  // namespace chre
\ No newline at end of file
+}  // namespace chre
diff --git a/test/simulation/wifi_timeout_test.cc b/test/simulation/wifi_timeout_test.cc
index 1e9d4766..36229dfc 100644
--- a/test/simulation/wifi_timeout_test.cc
+++ b/test/simulation/wifi_timeout_test.cc
@@ -127,7 +127,7 @@ TEST_F(WifiTimeoutTest, WifiScanRequestTimeoutTest) {
 
   waitForEvent(REQUEST_TIMED_OUT);
 
-  // Make sure that we can still request scan after a timedout
+  // Make sure that we can still request scan after a timed out
   // request.
   constexpr uint32_t successCookie = 0x0101;
   chrePalWifiEnableResponse(PalWifiAsyncRequestTypes::SCAN,
@@ -238,7 +238,7 @@ TEST_F(WifiTimeoutTest, WifiCanDispatchQueuedRequestAfterOneTimeout) {
 
   waitForEvent(REQUEST_TIMED_OUT);
 
-  // Make sure that we can still request scan for both nanoapps after a timedout
+  // Make sure that we can still request scan for both nanoapps after a timed out
   // request.
   constexpr uint32_t successCookie = 0x0101;
   chrePalWifiEnableResponse(PalWifiAsyncRequestTypes::SCAN,
@@ -336,7 +336,7 @@ TEST_F(WifiTimeoutTest, WifiScanMonitorTimeoutTest) {
 
   waitForEvent(REQUEST_TIMED_OUT);
 
-  // Make sure that we can still request to change scan monitor after a timedout
+  // Make sure that we can still request to change scan monitor after a timed out
   // request.
   MonitoringRequest enableRequest{.enable = true, .cookie = 0x1010};
   chrePalWifiEnableResponse(PalWifiAsyncRequestTypes::SCAN_MONITORING, true);
@@ -453,7 +453,7 @@ TEST_F(WifiTimeoutTest, WifiRequestRangingTimeoutTest) {
 
   waitForEvent(REQUEST_TIMED_OUT);
 
-  // Make sure that we can still request ranging after a timedout request
+  // Make sure that we can still request ranging after a timed out request
   uint32_t successCookie = 0x0101;
   chrePalWifiEnableResponse(PalWifiAsyncRequestTypes::RANGING, true);
   sendEventToNanoapp(appId, RANGING_REQUEST, successCookie);
diff --git a/tools/todo_checker.py b/tools/todo_checker.py
index e2a3f47e..4984b1fa 100755
--- a/tools/todo_checker.py
+++ b/tools/todo_checker.py
@@ -96,7 +96,7 @@ def grep_for_todos(bug_id : str) -> int:
                                             encoding='UTF-8')
 
   grep_base_cmd = 'grep -nri '
-  grep_file_filters = '--include \*.h --include \*.cc --include \*.cpp --include \*.c '
+  grep_file_filters = r'--include \*.h --include \*.cc --include \*.cpp --include \*.c '
   grep_shell_cmd = grep_base_cmd + grep_file_filters + bug_id + repo_path
   try:
     grep_result = subprocess.check_output(grep_shell_cmd, shell=True,
diff --git a/util/include/chre/util/optional.h b/util/include/chre/util/optional.h
index 24394cc8..de11d6c1 100644
--- a/util/include/chre/util/optional.h
+++ b/util/include/chre/util/optional.h
@@ -21,6 +21,31 @@
 
 namespace chre {
 
+/**
+ * A tag dispatch type to indicate an empty Optional state, similar to
+ * std::nullopt_t.
+ *
+ * This type is used in constructors and assignment operators of Optional
+ * to explicitly create or assign an empty (disengaged) state.
+ */
+struct nullopt_t {
+  // The constructor is explicit to prevent conversions from arbitrary integer
+  // types (like 0 or NULL/nullptr).
+  constexpr explicit nullopt_t(int /*dummy*/) {}
+};
+
+/**
+ * nullopt definition used to indicate an empty Optional, allows easier porting
+ * from std::optional and std::nullopt.
+ *
+ * This can be used to construct or assign an empty Optional.
+ * For example:
+ * chre::Optional<int> o = chre::nullopt;
+ * o = chre::nullopt;
+ * return chree::nullopt;
+ */
+inline constexpr nullopt_t nullopt{/*dummy*/ 0};
+
 /**
  * This container keeps track of an optional object. The container is similar to
  * std::optional introduced in C++17.
@@ -38,6 +63,11 @@ class Optional {
    */
   constexpr Optional() : mObject() {}
 
+  /**
+   * Constructs an optional object with no initial value (from chre::nullopt).
+   */
+  constexpr Optional(nullopt_t) noexcept : mObject() {}
+
   /**
    * Default copy constructor.
    *
diff --git a/util/include/chre/util/segmented_queue.h b/util/include/chre/util/segmented_queue.h
index 38f660f5..4bfb5976 100644
--- a/util/include/chre/util/segmented_queue.h
+++ b/util/include/chre/util/segmented_queue.h
@@ -14,8 +14,7 @@
  * limitations under the License.
  */
 
-#ifndef CHRE_UTIL_SEGMENTED_QUEUE_H_
-#define CHRE_UTIL_SEGMENTED_QUEUE_H_
+#pragma once
 
 #include <type_traits>
 #include <utility>
@@ -83,7 +82,7 @@ class SegmentedQueue : public NonCopyable {
    * @return true: Return true if the segmented queue cannot accept new element.
    */
   bool full() const {
-    return mSize == kMaxBlockCount * kBlockSize;
+    return mSize == maxBlockCount() * kBlockSize;
   }
 
   /**
@@ -223,9 +222,11 @@ class SegmentedQueue : public NonCopyable {
                                void *extraDataForFreeFunction = nullptr);
 
  private:
+  size_t maxBlockCount() const { return mRawStoragePtrs.capacity(); }
+
   /**
    * Push a new block to the end of storage to add storage space.
-   * The total block count after push cannot exceed kMaxBlockCount.
+   * The total block count after push cannot exceed maxBlockCount().
    *
    * @return true: Return true if a new block can be added.
    */
@@ -233,7 +234,7 @@ class SegmentedQueue : public NonCopyable {
 
   /**
    * Insert one block to the underlying storage.
-   * The total block count after push cannot exceed kMaxBlockCount.
+   * The total block count after push cannot exceed maxBlockCount().
    *
    * @param blockIndex: The index to insert a block at.
    * @return true: Return true if a new block can be added.
@@ -400,15 +401,13 @@ class SegmentedQueue : public NonCopyable {
   //! The data storage of this segmented queue.
   DynamicVector<UniquePtr<Block>> mRawStoragePtrs;
 
+  //! Non-owning list of blocks that we allocated in the constructor and
+  //! therefore shouldn't deallocate in resetEmptyQueue().
+  DynamicVector<Block *> mStaticBlocks;
+
   //! Records how many items are in this queue.
   size_t mSize = 0;
 
-  //! The maximum block count this queue can hold.
-  const size_t kMaxBlockCount;
-
-  //! How many blocks allocated in constructor.
-  const size_t kStaticBlockCount;
-
   //! The offset of the first element of the queue starting from the start of
   //! the DynamicVector.
   size_t mHead = 0;
@@ -416,13 +415,10 @@ class SegmentedQueue : public NonCopyable {
   // TODO(b/258828257): Modify initialization logic to make it work when
   // kStaticBlockCount = 0
   //! The offset of the last element of the queue starting from the start of the
-  //! DynamicVector. Initialize it to the end of container for a easier
-  //! implementation of push_back().
-  size_t mTail = kBlockSize * kStaticBlockCount - 1;
+  //! DynamicVector
+  size_t mTail;
 };
 
 }  // namespace chre
 
 #include "chre/util/segmented_queue_impl.h"  // IWYU pragma: export
-
-#endif  // CHRE_UTIL_SEGMENTED_QUEUE_H_
diff --git a/util/include/chre/util/segmented_queue_impl.h b/util/include/chre/util/segmented_queue_impl.h
index 604be687..eafe7996 100644
--- a/util/include/chre/util/segmented_queue_impl.h
+++ b/util/include/chre/util/segmented_queue_impl.h
@@ -14,8 +14,7 @@
  * limitations under the License.
  */
 
-#ifndef CHRE_UTIL_SEGMENTED_QUEUE_IMPL_H
-#define CHRE_UTIL_SEGMENTED_QUEUE_IMPL_H
+#pragma once
 
 // IWYU pragma: private
 #include <algorithm>
@@ -31,13 +30,15 @@ namespace chre {
 template <typename ElementType, size_t kBlockSize>
 SegmentedQueue<ElementType, kBlockSize>::SegmentedQueue(size_t maxBlockCount,
                                                         size_t staticBlockCount)
-    : kMaxBlockCount(maxBlockCount), kStaticBlockCount(staticBlockCount) {
-  CHRE_ASSERT(kMaxBlockCount >= kStaticBlockCount);
-  CHRE_ASSERT(kStaticBlockCount > 0);
-  CHRE_ASSERT(kMaxBlockCount * kBlockSize < SIZE_MAX);
-  mRawStoragePtrs.reserve(kMaxBlockCount);
-  for (size_t i = 0; i < kStaticBlockCount; i++) {
+    : mTail(kBlockSize * staticBlockCount - 1) {
+  CHRE_ASSERT(maxBlockCount >= staticBlockCount);
+  CHRE_ASSERT(staticBlockCount > 0);
+  CHRE_ASSERT(maxBlockCount * kBlockSize < SIZE_MAX);
+  mRawStoragePtrs.reserve(maxBlockCount);
+  mStaticBlocks.reserve(staticBlockCount);
+  for (size_t i = 0; i < staticBlockCount; i++) {
     pushOneBlock();
+    mStaticBlocks.push_back(mRawStoragePtrs.back().get());
   }
 }
 
@@ -300,7 +301,7 @@ bool SegmentedQueue<ElementType, kBlockSize>::insertBlock(size_t blockIndex) {
   // Supporting inserting at any index since we started this data structure as
   // std::deque and would like to support push_front() in the future. This
   // function should not be needed once b/258771255 is implemented.
-  CHRE_ASSERT(mRawStoragePtrs.size() != kMaxBlockCount);
+  CHRE_ASSERT(mRawStoragePtrs.size() != mRawStoragePtrs.capacity());
   bool success = false;
 
   Block *newBlockPtr = static_cast<Block *>(memoryAlloc(sizeof(Block)));
@@ -470,13 +471,23 @@ template <typename ElementType, size_t kBlockSize>
 void SegmentedQueue<ElementType, kBlockSize>::resetEmptyQueue() {
   CHRE_ASSERT(empty());
 
-  while (mRawStoragePtrs.size() != kStaticBlockCount) {
-    mRawStoragePtrs.pop_back();
+  // Remove all blocks other than static
+  for (size_t i = 0; i < mRawStoragePtrs.size(); ++i) {
+    bool isStatic = false;
+    for (size_t j = 0; j < mStaticBlocks.size(); ++j) {
+      if (mRawStoragePtrs[i].get() == mStaticBlocks[j]) {
+        isStatic = true;
+        break;
+      }
+    }
+    if (!isStatic) {
+      mRawStoragePtrs.erase(i);
+      i--;
+    }
   }
+
   mHead = 0;
   mTail = capacity() - 1;
 }
 
 }  // namespace chre
-
-#endif  // CHRE_UTIL_SEGMENTED_QUEUE_IMPL_H
\ No newline at end of file
diff --git a/util/tests/optional_test.cc b/util/tests/optional_test.cc
index ba647a04..84043f2d 100644
--- a/util/tests/optional_test.cc
+++ b/util/tests/optional_test.cc
@@ -54,6 +54,11 @@ TEST(Optional, NoValueByDefault) {
   EXPECT_FALSE(myInt.has_value());
 }
 
+TEST(Optional, NoValueByDefaultNullopt) {
+  Optional<int> myInt = chre::nullopt;
+  EXPECT_FALSE(myInt.has_value());
+}
+
 TEST(Optional, NonDefaultValueByDefault) {
   Optional<int> myInt(0x1337);
   EXPECT_TRUE(myInt.has_value());
@@ -119,6 +124,12 @@ TEST(Optional, OptionalCopyAssignAndRead) {
   EXPECT_EQ(*myCopiedInt, 0x1337);
 }
 
+TEST(Optional, OptionalCopyAssignNullopt) {
+  Optional<int> myInt(0x1337);
+  myInt = chre::nullopt;
+  EXPECT_FALSE(myInt.has_value());
+}
+
 static constexpr int kInvalidValue = -1;
 
 class MovableButNonCopyable : public chre::NonCopyable {
diff --git a/util/tests/segmented_queue_test.cc b/util/tests/segmented_queue_test.cc
index a3c731ac..5e3872f3 100644
--- a/util/tests/segmented_queue_test.cc
+++ b/util/tests/segmented_queue_test.cc
@@ -299,6 +299,52 @@ TEST(SegmentedQueue, MiddleBlockTest) {
   }
 }
 
+TEST(SegmentedQueue, KeepStaticBlocks) {
+  // This test confirms that even if a block is inserted in the middle of the
+  // block list and then the queue is emptied, the static blocks will be kept.
+  // To force the queue to allocate a new block between the two static blocks,
+  // we follow a process outlined below, where A and B are static blocks, H is
+  // head, T is tail, x is a populated slot, and - is an empty slot:
+  //  1. A[ H x x ] B[ x x T ]
+  //  2. A[ - - - ] B[ H x T ]
+  //  3. A[ x x T ] B[ H x x ]
+  //  4. A[ x x x ] C[ T - - ] B[ H x x ]
+  constexpr uint8_t blockSize = 3;
+  constexpr uint8_t maxBlockCount = 3;
+  constexpr uint8_t staticBlockCount = 2;
+  SegmentedQueue<int, blockSize> segmentedQueue(maxBlockCount,
+                                                staticBlockCount);
+  // 1. Fill static blocks
+  for (uint32_t i = 0; i < blockSize * staticBlockCount; i++) {
+    EXPECT_TRUE(segmentedQueue.push_back(i));
+  }
+  EXPECT_EQ(segmentedQueue.size(), segmentedQueue.capacity());
+  int *firstBlock = &segmentedQueue[0];
+  int *secondBlock = &segmentedQueue[blockSize];
+  // 2. Empty first block
+  for (uint32_t i = 0; i < blockSize; i++) {
+    segmentedQueue.pop_front();
+  }
+  // 3. Fill first block (it now holds the tail)
+  for (uint32_t i = 0; i < blockSize; i++) {
+    EXPECT_TRUE(segmentedQueue.push_back(i + blockSize * staticBlockCount));
+  }
+  EXPECT_EQ(&segmentedQueue[blockSize], firstBlock);
+  // 4. Push again to trigger allocation of a new block in the middle
+  EXPECT_TRUE(segmentedQueue.push_back(blockSize * staticBlockCount + 1));
+  // 5. Empty the queue to deallocate the dynamic block
+  for (uint32_t i = 0; i < blockSize * staticBlockCount + 1; i++) {
+    segmentedQueue.pop_front();
+  }
+  EXPECT_TRUE(segmentedQueue.empty());
+  // 6. Confirm that the original static blocks are the ones that remain
+  for (int i = 0; i < blockSize + 1; i++) {
+    segmentedQueue.push_back(i);
+  }
+  EXPECT_EQ(&segmentedQueue[0], firstBlock);
+  EXPECT_EQ(&segmentedQueue[blockSize], secondBlock);
+}
+
 TEST(SegmentedQueue, RemoveMatchesEnoughItem) {
   constexpr uint8_t blockSize = 3;
   constexpr uint8_t maxBlockCount = 2;
diff --git a/variant/tinysys/variant.mk b/variant/tinysys/variant.mk
index ccb2db52..cc409f83 100644
--- a/variant/tinysys/variant.mk
+++ b/variant/tinysys/variant.mk
@@ -19,7 +19,7 @@ VARIANT_PREFIX = $(ANDROID_BUILD_TOP)/system/chre/variant
 COMMIT_HASH_COMMAND = git describe --always --long --dirty
 COMMIT_HASH = $(shell $(COMMIT_HASH_COMMAND))
 
-COMMON_CFLAGS += -DCHRE_VERSION_STRING="\"chre=tinysys@$(COMMIT_HASH)\""
+COMMON_CFLAGS += -DCHRE_VERSION_STRING='"chre=tinysys@$(COMMIT_HASH)"'
 
 # Platform-specific Settings ###################################################
 
@@ -55,10 +55,12 @@ TINYSYS_CFLAGS += -I$(RISCV_TINYSYS_PREFIX)/scp/project/RV55_A/common/platform/i
 
 # Common Compiler Flags ########################################################
 
-# Supply a symbol to indicate that the build variant supplies the static
-# nanoapp list.
+# Supply a symbol to indicate that the build variant supplies the static nanoapp list.
 COMMON_CFLAGS += -DCHRE_VARIANT_SUPPLIES_STATIC_NANOAPP_LIST
 
+# Support for tinysys specific exported symbols
+COMMON_CFLAGS += -DCHREX_SYMBOL_EXTENSIONS
+
 # Enable nanoapp authentication by default
 TINYSYS_CFLAGS += -DCHRE_NAPP_AUTHENTICATION_ENABLED
 
```

