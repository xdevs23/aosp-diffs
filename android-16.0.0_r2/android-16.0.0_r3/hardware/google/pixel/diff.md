```diff
diff --git a/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk b/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk
deleted file mode 100644
index 46bf5d14..00000000
--- a/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += hardware/google/pixel-sepolicy/connectivity_thermal_power_manager
-
-$(call soong_config_set,connectivity_thermal_power_manager_config,use_alcedo_modem,$(USES_ALCEDO_MODEM))
-ifeq ($(USES_ALCEDO_MODEM),true)
-PRODUCT_PACKAGES += ConnectivityThermalPowerManagerNextgen
-PRODUCT_PACKAGES_DEBUG += mipc_util
-endif
diff --git a/pixelstats/Android.bp b/pixelstats/Android.bp
index 87590f83..232b7508 100644
--- a/pixelstats/Android.bp
+++ b/pixelstats/Android.bp
@@ -159,7 +159,6 @@ cc_library {
         "BatteryFGReporter.cpp",
         "BatteryFwUpdateReporter.cpp",
         "BatteryTTFReporter.cpp",
-        "BrownoutDetectedReporter.cpp",
         "ChargeStatsReporter.cpp",
         "DisplayStatsReporter.cpp",
         "DropDetect.cpp",
diff --git a/pixelstats/BatteryEEPROMReporter.cpp b/pixelstats/BatteryEEPROMReporter.cpp
index 0167d615..2493b94b 100644
--- a/pixelstats/BatteryEEPROMReporter.cpp
+++ b/pixelstats/BatteryEEPROMReporter.cpp
@@ -62,6 +62,26 @@ bool BatteryEEPROMReporter::ReadFileToInt(const std::string &path, int32_t *val)
     return true;
 }
 
+bool BatteryEEPROMReporter::checkCycleCountRollback() {
+    const std::string cycle_count_path(BATTERY_CYCLE_COUNT_PATH);
+    int cycle_count;
+
+    if (ReadFileToInt(cycle_count_path.c_str(), &cycle_count) && cycle_count > 0) {
+        if (last_cycle_count == 0) {
+            last_cycle_count = cycle_count;
+            return false;
+        }
+
+        if (cycle_count < last_cycle_count) {
+            ALOGD("Cycle count rollback from %d to %d", last_cycle_count, cycle_count);
+            last_cycle_count = cycle_count;
+            return true;
+        }
+    }
+
+    return false;
+}
+
 std::string BatteryEEPROMReporter::checkPaths(const std::vector<std::string>& paths) {
     if (paths.empty()) {
         return ""; // Or throw an exception if appropriate
@@ -81,14 +101,13 @@ void BatteryEEPROMReporter::checkAndReport(const std::shared_ptr<IStats> &stats_
     std::string file_contents;
     std::string history_each;
     std::string cycle_count;
-
     const std::string cycle_count_path(BATTERY_CYCLE_COUNT_PATH);
     int sparse_index_count = 0;
-
     const int kSecondsPerMonth = 60 * 60 * 24 * 30;
     int64_t now = getTimeSecs();
 
-    if ((report_time_ != 0) && (now - report_time_ < kSecondsPerMonth)) {
+    if (!checkCycleCountRollback() && (report_time_ != 0) &&
+        (now - report_time_ < kSecondsPerMonth)) {
         ALOGD("Not upload time. now: %" PRId64 ", pre: %" PRId64, now, report_time_);
         return;
     }
@@ -348,9 +367,6 @@ void BatteryEEPROMReporter::checkAndReportFGModelLoading(const std::shared_ptr<I
     int num;
     const char *data;
 
-    if (path.empty())
-        return;
-
     /* not found */
     if (path.empty())
         return;
@@ -389,14 +405,17 @@ void BatteryEEPROMReporter::checkAndReportFGLearning(const std::shared_ptr<IStat
 
     clock_gettime(CLOCK_MONOTONIC, &boot_time);
 
-    readLogbuffer(path, kNumFGLearningFieldsV3, params.checksum, format, last_lh_check_, events);
+    readLogbuffer(path, kNumFGLearningFieldsV4, params.checksum, format, last_lh_check_, events);
+    if (events.size() == 0)
+        readLogbuffer(path, kNumFGLearningFieldsV3, params.checksum, format, last_lh_check_, events);
     if (events.size() == 0)
         readLogbuffer(path, kNumFGLearningFieldsV2, params.checksum, format, last_lh_check_, events);
 
     for (int event_idx = 0; event_idx < events.size(); event_idx++) {
         std::vector<uint32_t> &event = events[event_idx];
         if (event.size() == kNumFGLearningFieldsV2 ||
-            event.size() == kNumFGLearningFieldsV3) {
+            event.size() == kNumFGLearningFieldsV3 ||
+            event.size() == kNumFGLearningFieldsV4) {
             params.full_cap = event[0];                /* fcnom */
             params.esr = event[1];                     /* dpacc */
             params.rslow = event[2];                   /* dqacc */
@@ -413,8 +432,14 @@ void BatteryEEPROMReporter::checkAndReportFGLearning(const std::shared_ptr<IStat
             params.cycle_cnt = event[13];              /* vfocf */
             params.rcomp0 = event[14];                 /* rcomp0 */
             params.tempco = event[15];                 /* tempco */
-            if (event.size() == kNumFGLearningFieldsV3)
+            if (event.size() >= kNumFGLearningFieldsV3)
                 params.soh = event[16];                /* unix time */
+            if (event.size() == kNumFGLearningFieldsV4) {
+                params.cutoff_soc = event[17];         /* cotrim */
+                params.cc_soc = event[18];             /* coff */
+                params.batt_temp = event[19];          /* lock_1 */
+                params.timer_h = event[20];            /* lock_2 */
+            }
         } else {
             ALOGE("Not support %zu fields for FG learning event", event.size());
             continue;
@@ -424,12 +449,11 @@ void BatteryEEPROMReporter::checkAndReportFGLearning(const std::shared_ptr<IStat
     last_lh_check_ = (unsigned int)boot_time.tv_sec;
 }
 
-void BatteryEEPROMReporter::checkAndReportValidation(const std::shared_ptr<IStats> &stats_client,
+void BatteryEEPROMReporter::checkAndReportHistValid(const std::shared_ptr<IStats> &stats_client,
                                                      const std::vector<std::string> &paths) {
     struct BatteryEEPROMPipeline params = {.checksum = EvtHistoryValidation};
     std::string path = checkPaths(paths);
     struct timespec boot_time;
-    auto format = FormatIgnoreAddr;
     std::vector<std::vector<uint32_t>> events;
 
     if (path.empty())
@@ -437,7 +461,12 @@ void BatteryEEPROMReporter::checkAndReportValidation(const std::shared_ptr<IStat
 
     clock_gettime(CLOCK_MONOTONIC, &boot_time);
 
-    readLogbuffer(path, kNumValidationFields, params.checksum, format, last_hv_check_, events);
+    readLogbuffer(path, kNumValidationFieldsV2, params.checksum, FormatOnlyVal, last_hv_check_,
+                  events);
+    if (events.size() == 0)
+        readLogbuffer(path, kNumValidationFields, params.checksum, FormatIgnoreAddr,
+                      last_hv_check_, events);
+
     for (int event_idx = 0; event_idx < events.size(); event_idx++) {
         std::vector<uint32_t> &event = events[event_idx];
         if (event.size() == kNumValidationFields) {
@@ -446,10 +475,18 @@ void BatteryEEPROMReporter::checkAndReportValidation(const std::shared_ptr<IStat
             params.rslow = event[2];    /* last cycle count */
             params.full_rep = event[3]; /* estimate cycle count after recovery */
             reportEvent(stats_client, params);
-            /* force report history metrics if it was recovered */
-            if (last_hv_check_ != 0) {
-                report_time_ = 0;
-            }
+        } else if (event.size() == kNumValidationFieldsV2) {
+            params.cycle_cnt = event[0];/* log type */
+            params.full_cap = event[1]; /* first empty entry */
+            params.esr = event[2];      /* first misplaced entry */
+            params.rslow = event[3];    /* first migrated entry */
+            params.batt_temp = event[4];/* last migrated entry */
+            params.cutoff_soc = event[5];/* last cycle count */
+            params.cc_soc = event[6];   /* current cycle count */
+            params.sys_soc = event[7];  /* eeprom cycle count */
+            params.msoc = event[8];     /* result */
+            params.soh = event[9];      /* unix time */
+            reportEvent(stats_client, params);
         } else {
             ALOGE("Not support %zu fields for History Validation event", event.size());
         }
diff --git a/pixelstats/BrownoutDetectedReporter.cpp b/pixelstats/BrownoutDetectedReporter.cpp
deleted file mode 100644
index b2d38ed8..00000000
--- a/pixelstats/BrownoutDetectedReporter.cpp
+++ /dev/null
@@ -1,594 +0,0 @@
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
-#define LOG_TAG "pixelstats: BrownoutDetected"
-
-#include <aidl/android/frameworks/stats/IStats.h>
-#include <android-base/file.h>
-#include <android-base/parseint.h>
-#include <android-base/properties.h>
-#include <android-base/stringprintf.h>
-#include <android-base/strings.h>
-#include <android/binder_manager.h>
-#include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
-#include <pixelstats/BrownoutDetectedReporter.h>
-#include <time.h>
-#include <utils/Log.h>
-
-#include <map>
-#include <regex>
-
-namespace android {
-namespace hardware {
-namespace google {
-namespace pixel {
-
-using aidl::android::frameworks::stats::IStats;
-using aidl::android::frameworks::stats::VendorAtom;
-using aidl::android::frameworks::stats::VendorAtomValue;
-using android::base::ReadFileToString;
-using android::hardware::google::pixel::PixelAtoms::BrownoutDetected;
-
-#define READING_IDX 2
-#define KEY_IDX 0
-#define DEFAULT_BATTERY_TEMP 9999999
-#define DEFAULT_BATTERY_SOC 100
-#define DEFAULT_BATTERY_VOLT 5000000
-#define ONE_SECOND_IN_US 1000000
-
-const std::regex kTimestampPattern("^\\S+\\s[0-9]+:[0-9]+:[0-9]+\\S+$");
-const std::regex kIrqPattern("^(\\S+)\\striggered\\sat\\s\\S+$");
-const std::regex kOdpmPattern("^CH\\d+\\[(\\S+)\\],\\s(\\d+)$");
-const std::regex kDvfsPattern("^([A-Z1-9]+):(\\d+)$");
-const std::regex kFgPattern("^(voltage_now):(\\d+)$");
-const std::regex kBatteryTempPattern("^(battery):(\\d+)$");
-const std::regex kBatteryCyclePattern("^(battery_cycle):(\\d+)$");
-const std::regex kBatterySocPattern("^(soc):(\\d+)$");
-const std::regex kAlreadyUpdatedPattern("^(LASTMEAL_UPDATED)$");
-
-const std::map<std::string, int> kBrownoutReason = {{"uvlo,pmic,if", BrownoutDetected::UVLO_IF},
-                                                    {"ocp,pmic,if", BrownoutDetected::OCP_IF},
-                                                    {"ocp2,pmic,if", BrownoutDetected::OCP2_IF},
-                                                    {"uvlo,pmic,main", BrownoutDetected::UVLO_MAIN},
-                                                    {"uvlo,pmic,sub", BrownoutDetected::UVLO_SUB},
-                                                    {"ocp,buck1m", BrownoutDetected::OCP_B1M},
-                                                    {"ocp,buck2m", BrownoutDetected::OCP_B2M},
-                                                    {"ocp,buck3m", BrownoutDetected::OCP_B3M},
-                                                    {"ocp,buck4m", BrownoutDetected::OCP_B4M},
-                                                    {"ocp,buck5m", BrownoutDetected::OCP_B5M},
-                                                    {"ocp,buck6m", BrownoutDetected::OCP_B6M},
-                                                    {"ocp,buck7m", BrownoutDetected::OCP_B7M},
-                                                    {"ocp,buck8m", BrownoutDetected::OCP_B8M},
-                                                    {"ocp,buck9m", BrownoutDetected::OCP_B9M},
-                                                    {"ocp,buck10m", BrownoutDetected::OCP_B10M},
-                                                    {"ocp,buck1s", BrownoutDetected::OCP_B1S},
-                                                    {"ocp,buck2s", BrownoutDetected::OCP_B2S},
-                                                    {"ocp,buck3s", BrownoutDetected::OCP_B3S},
-                                                    {"ocp,buck4s", BrownoutDetected::OCP_B4S},
-                                                    {"ocp,buck5s", BrownoutDetected::OCP_B5S},
-                                                    {"ocp,buck6s", BrownoutDetected::OCP_B6S},
-                                                    {"ocp,buck7s", BrownoutDetected::OCP_B7S},
-                                                    {"ocp,buck8s", BrownoutDetected::OCP_B8S},
-                                                    {"ocp,buck9s", BrownoutDetected::OCP_B9S},
-                                                    {"ocp,buck10s", BrownoutDetected::OCP_B10S},
-                                                    {"ocp,buckas", BrownoutDetected::OCP_BAS},
-                                                    {"ocp,buckbs", BrownoutDetected::OCP_BBS},
-                                                    {"ocp,buckcs", BrownoutDetected::OCP_BCS},
-                                                    {"ocp,buckds", BrownoutDetected::OCP_BDS}};
-
-bool BrownoutDetectedReporter::updateIfFound(std::string line, std::regex pattern,
-                                             int *current_value, Update flag) {
-    bool found = false;
-    std::smatch pattern_match;
-    if (std::regex_match(line, pattern_match, pattern)) {
-        if (pattern_match.size() < (READING_IDX + 1)) {
-            return found;
-        }
-        found = true;
-        int reading = std::stoi(pattern_match[READING_IDX].str());
-        if (flag == kUpdateMax) {
-            if (*current_value < reading) {
-                *current_value = reading;
-            }
-        } else {
-            if (*current_value > reading) {
-                *current_value = reading;
-            }
-        }
-    }
-    return found;
-}
-
-void BrownoutDetectedReporter::setAtomFieldValue(std::vector<VendorAtomValue> &values, int offset,
-                                                 int content) {
-    if (offset - kVendorAtomOffset < values.size()) {
-        ALOGW("VendorAtomValue size is smaller than offset");
-        values[offset - kVendorAtomOffset].set<VendorAtomValue::intValue>(content);
-    }
-}
-
-void BrownoutDetectedReporter::uploadData(const std::shared_ptr<IStats> &stats_client,
-                                          const struct BrownoutDetectedInfo max_value) {
-    // Load values array
-    VendorAtomValue tmp;
-    std::vector<VendorAtomValue> values(90);
-    setAtomFieldValue(values, BrownoutDetected::kTriggeredIrqFieldNumber, max_value.triggered_irq_);
-    setAtomFieldValue(values, BrownoutDetected::kTriggeredTimestampFieldNumber,
-                      max_value.triggered_timestamp_);
-    setAtomFieldValue(values, BrownoutDetected::kBatteryTempFieldNumber, max_value.battery_temp_);
-    setAtomFieldValue(values, BrownoutDetected::kBatterySocFieldNumber,
-                      100 - max_value.battery_soc_);
-    setAtomFieldValue(values, BrownoutDetected::kBatteryCycleFieldNumber, max_value.battery_cycle_);
-    setAtomFieldValue(values, BrownoutDetected::kVoltageNowFieldNumber, max_value.voltage_now_);
-
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel01FieldNumber,
-                      max_value.odpm_value_[0]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel02FieldNumber,
-                      max_value.odpm_value_[1]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel03FieldNumber,
-                      max_value.odpm_value_[2]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel04FieldNumber,
-                      max_value.odpm_value_[3]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel05FieldNumber,
-                      max_value.odpm_value_[4]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel06FieldNumber,
-                      max_value.odpm_value_[5]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel07FieldNumber,
-                      max_value.odpm_value_[6]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel08FieldNumber,
-                      max_value.odpm_value_[7]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel09FieldNumber,
-                      max_value.odpm_value_[8]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel10FieldNumber,
-                      max_value.odpm_value_[9]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel11FieldNumber,
-                      max_value.odpm_value_[10]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel12FieldNumber,
-                      max_value.odpm_value_[11]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel13FieldNumber,
-                      max_value.odpm_value_[12]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel14FieldNumber,
-                      max_value.odpm_value_[13]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel15FieldNumber,
-                      max_value.odpm_value_[14]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel16FieldNumber,
-                      max_value.odpm_value_[15]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel17FieldNumber,
-                      max_value.odpm_value_[16]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel18FieldNumber,
-                      max_value.odpm_value_[17]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel19FieldNumber,
-                      max_value.odpm_value_[18]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel20FieldNumber,
-                      max_value.odpm_value_[19]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel21FieldNumber,
-                      max_value.odpm_value_[20]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel22FieldNumber,
-                      max_value.odpm_value_[21]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel23FieldNumber,
-                      max_value.odpm_value_[22]);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel24FieldNumber,
-                      max_value.odpm_value_[23]);
-
-    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel1FieldNumber, max_value.dvfs_value_[0]);
-    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel2FieldNumber, max_value.dvfs_value_[1]);
-    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel3FieldNumber, max_value.dvfs_value_[2]);
-    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel4FieldNumber, max_value.dvfs_value_[3]);
-    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel5FieldNumber, max_value.dvfs_value_[4]);
-    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel6FieldNumber, max_value.dvfs_value_[5]);
-    setAtomFieldValue(values, BrownoutDetected::kBrownoutReasonFieldNumber,
-                      max_value.brownout_reason_);
-
-    setAtomFieldValue(values, BrownoutDetected::kMaxCurrentFieldNumber, max_value.max_curr_);
-    setAtomFieldValue(values, BrownoutDetected::kEvtCntUvlo1FieldNumber, max_value.evt_cnt_uvlo1_);
-    setAtomFieldValue(values, BrownoutDetected::kEvtCntUvlo2FieldNumber, max_value.evt_cnt_uvlo2_);
-    setAtomFieldValue(values, BrownoutDetected::kEvtCntOilo1FieldNumber, max_value.evt_cnt_oilo1_);
-    setAtomFieldValue(values, BrownoutDetected::kEvtCntOilo2FieldNumber, max_value.evt_cnt_oilo2_);
-    setAtomFieldValue(values, BrownoutDetected::kVimonVbattFieldNumber, max_value.vimon_vbatt_);
-    setAtomFieldValue(values, BrownoutDetected::kVimonIbattFieldNumber, max_value.vimon_ibatt_);
-
-    setAtomFieldValue(values, BrownoutDetected::kMitigationMethod0FieldNumber,
-                      max_value.mitigation_method_0_);
-    setAtomFieldValue(values, BrownoutDetected::kMitigationMethod0CountFieldNumber,
-                      max_value.mitigation_method_0_count_);
-    setAtomFieldValue(values, BrownoutDetected::kMitigationMethod0TimeUsFieldNumber,
-                      max_value.mitigation_method_0_time_us_);
-
-    setAtomFieldValue(values, BrownoutDetected::kPreOcpCpu1BckupFieldNumber,
-                      max_value.pre_ocp_cpu1_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kPreOcpCpu2BckupFieldNumber,
-                      max_value.pre_ocp_cpu2_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kPreOcpTpuBckupFieldNumber,
-                      max_value.pre_ocp_tpu_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kPreOcpGpuBckupFieldNumber,
-                      max_value.pre_ocp_gpu_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kPreUvloHitCntMFieldNumber,
-                      max_value.pre_uvlo_hit_cnt_m_);
-    setAtomFieldValue(values, BrownoutDetected::kPreUvloHitCntSFieldNumber,
-                      max_value.pre_uvlo_hit_cnt_s_);
-    setAtomFieldValue(values, BrownoutDetected::kPreUvloDurFieldNumber, max_value.uvlo_dur_);
-
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat0SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_0_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat1SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_1_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat2SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_2_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat3SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_3_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat4SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_4_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat5SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_5_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat6SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_6_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat7SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_7_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat8SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_8_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat9SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_9_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat10SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_10_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat11SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_11_sys_evt_main_bckup_);
-
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat0SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_0_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat1SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_1_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat2SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_2_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat3SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_3_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat4SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_4_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat5SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_5_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat6SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_6_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat7SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_7_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat8SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_8_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat9SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_9_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat10SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_10_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat11SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_11_sys_evt_sub_bckup_);
-
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt0SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_ext_0_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt1SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_ext_1_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt2SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_ext_2_sys_evt_main_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt3SysEvtMainBckupFieldNumber,
-                      max_value.odpm_irq_stat_ext_3_sys_evt_main_bckup_);
-
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt0SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_ext_0_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt1SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_ext_1_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt2SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_ext_2_sys_evt_sub_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt3SysEvtSubBckupFieldNumber,
-                      max_value.odpm_irq_stat_ext_3_sys_evt_sub_bckup_);
-
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatGpuBckupFieldNumber,
-                      max_value.odpm_irq_stat_gpu_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatTpuBckupFieldNumber,
-                      max_value.odpm_irq_stat_tpu_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatCpu1BckupFieldNumber,
-                      max_value.odpm_irq_stat_cpu1_bckup_);
-    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatCpu2BckupFieldNumber,
-                      max_value.odpm_irq_stat_cpu2_bckup_);
-
-    // Send vendor atom to IStats HAL
-    VendorAtom event = {.reverseDomainName = "",
-                        .atomId = PixelAtoms::Atom::kBrownoutDetected,
-                        .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report ChargeStats to Stats service");
-}
-
-long BrownoutDetectedReporter::parseTimestamp(std::string timestamp) {
-    struct tm triggeredTimestamp = {};
-    std::string timestampFormat = "%Y-%m-%d %H:%M:%S";
-    if (strptime(timestamp.substr(0, 19).c_str(), timestampFormat.c_str(), &triggeredTimestamp)) {
-        auto logFileTime = std::chrono::system_clock::from_time_t(mktime(&triggeredTimestamp));
-        return logFileTime.time_since_epoch().count() / ONE_SECOND_IN_US;
-    }
-    return 0;
-}
-
-int BrownoutDetectedReporter::brownoutReasonCheck(const std::string &brownoutReasonProp) {
-    std::string reason = android::base::GetProperty(brownoutReasonProp.c_str(), "");
-    if (reason.empty()) {
-        // Brownout not found
-        return -1;
-    }
-    auto key = kBrownoutReason.find(reason);
-    if (key == kBrownoutReason.end()) {
-        return -1;
-    }
-    return key->second;
-}
-
-int parseIRQ(const std::string &element) {
-    int idx = atoi(element.c_str());
-    if (idx == SMPL_WARN) {
-        return BrownoutDetected::SMPL_WARN;
-    } else if (idx == UVLO1) {
-        return BrownoutDetected::UVLO1;
-    } else if (idx == UVLO2) {
-        return BrownoutDetected::UVLO2;
-    } else if (idx == BATOILO) {
-        return BrownoutDetected::BATOILO;
-    } else if (idx == BATOILO2) {
-        return BrownoutDetected::BATOILO2;
-    }
-    return -1;
-}
-
-void BrownoutDetectedReporter::logBrownoutCsv(const std::shared_ptr<IStats> &stats_client,
-                                              const std::string &CsvFilePath,
-                                              const std::string &brownoutReasonProp) {
-    std::string csvFile;
-    if (!android::base::ReadFileToString(CsvFilePath, &csvFile)) {
-        return;
-    }
-    std::istringstream content(csvFile);
-    std::string line;
-    struct BrownoutDetectedInfo max_value = {};
-    max_value.voltage_now_ = DEFAULT_BATTERY_VOLT;
-    max_value.battery_soc_ = DEFAULT_BATTERY_SOC;
-    max_value.battery_temp_ = DEFAULT_BATTERY_TEMP;
-    std::smatch pattern_match;
-    max_value.brownout_reason_ = brownoutReasonCheck(brownoutReasonProp);
-    if (max_value.brownout_reason_ < 0) {
-        return;
-    }
-    bool isAlreadyUpdated = false;
-    std::vector<std::vector<std::string>> rows;
-    int row_num = 0;
-    while (std::getline(content, line)) {
-        if (std::regex_match(line, pattern_match, kAlreadyUpdatedPattern)) {
-            isAlreadyUpdated = true;
-            break;
-        }
-        row_num++;
-        if (row_num == 1) {
-            continue;
-        }
-        std::vector<std::string> row;
-        std::stringstream ss(line);
-        std::string field;
-        while (getline(ss, field, ',')) {
-            row.push_back(field);
-        }
-
-        max_value.triggered_timestamp_ = parseTimestamp(row[TIMESTAMP_IDX].c_str());
-        max_value.triggered_irq_ = parseIRQ(row[IRQ_IDX]);
-        max_value.battery_soc_ = atoi(row[SOC_IDX].c_str());
-        max_value.battery_temp_ = atoi(row[TEMP_IDX].c_str());
-        max_value.battery_cycle_ = atoi(row[CYCLE_IDX].c_str());
-        max_value.voltage_now_ = atoi(row[VOLTAGE_IDX].c_str());
-        for (int i = 0; i < DVFS_MAX_IDX; i++) {
-            max_value.dvfs_value_[i] = atoi(row[i + DVFS_CHANNEL_0].c_str());
-        }
-        for (int i = 0; i < ODPM_MAX_IDX; i++) {
-            max_value.odpm_value_[i] = atoi(row[i + ODPM_CHANNEL_0].c_str());
-        }
-        if (row.size() > MITIGATION_METHOD_0_TIME) {
-            max_value.mitigation_method_0_ = atoi(row[MITIGATION_METHOD_0].c_str());
-            max_value.mitigation_method_0_count_ = atoi(row[MITIGATION_METHOD_0_COUNT].c_str());
-            max_value.mitigation_method_0_time_us_ = atoi(row[MITIGATION_METHOD_0_TIME].c_str());
-        }
-        if (row.size() > MAX_CURR) {
-            max_value.evt_cnt_oilo1_ = atoi(row[EVT_CNT_IDX_OILO1].c_str());
-            max_value.evt_cnt_oilo2_ = atoi(row[EVT_CNT_IDX_OILO2].c_str());
-            max_value.evt_cnt_uvlo1_ = atoi(row[EVT_CNT_IDX_UVLO1].c_str());
-            max_value.evt_cnt_uvlo2_ = atoi(row[EVT_CNT_IDX_UVLO2].c_str());
-            max_value.max_curr_ = atoi(row[MAX_CURR].c_str());
-        }
-        if (row.size() > IDX_VIMON_I) {
-            max_value.vimon_vbatt_ = atoi(row[IDX_VIMON_V].c_str());
-            max_value.vimon_ibatt_ = atoi(row[IDX_VIMON_I].c_str());
-        }
-        if (row.size() > UVLO_DUR_IDX) {
-            max_value.pre_ocp_cpu1_bckup_ = atoi(row[PRE_OCP_CPU1_BCKUP_IDX].c_str());
-            max_value.pre_ocp_cpu2_bckup_ = atoi(row[PRE_OCP_CPU2_BCKUP_IDX].c_str());
-            max_value.pre_ocp_tpu_bckup_ = atoi(row[PRE_OCP_TPU_BCKUP_IDX].c_str());
-            max_value.pre_ocp_gpu_bckup_ = atoi(row[PRE_OCP_GPU_BCKUP_IDX].c_str());
-            max_value.pre_uvlo_hit_cnt_m_ = atoi(row[PRE_UVLO_HIT_CNT_M_IDX].c_str());
-            max_value.pre_uvlo_hit_cnt_s_ = atoi(row[PRE_UVLO_HIT_CNT_S_IDX].c_str());
-            max_value.uvlo_dur_ = atoi(row[UVLO_DUR_IDX].c_str());
-        }
-        if (row.size() > ODPM_IRQ_STAT_CPU2_BCKUP_IDX) {
-            max_value.pre_ocp_cpu1_bckup_ = atoi(row[PRE_OCP_CPU1_BCKUP_IDX].c_str());
-            max_value.pre_ocp_cpu2_bckup_ = atoi(row[PRE_OCP_CPU2_BCKUP_IDX].c_str());
-
-            max_value.odpm_irq_stat_0_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_0_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_1_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_1_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_2_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_2_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_3_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_3_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_4_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_4_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_5_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_5_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_6_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_6_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_7_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_7_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_8_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_8_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_9_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_9_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_10_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_10_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_11_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_11_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-
-            max_value.odpm_irq_stat_0_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_0_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_1_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_1_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_2_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_2_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_3_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_3_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_4_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_4_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_5_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_5_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_6_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_6_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_7_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_7_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_8_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_8_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_9_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_9_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_10_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_10_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_11_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_11_SYS_EVT_SUB_BCKUP_IDX].c_str());
-
-            max_value.odpm_irq_stat_ext_0_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_EXT_0_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_ext_1_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_EXT_1_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_ext_2_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_EXT_2_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_ext_3_sys_evt_main_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_EXT_3_SYS_EVT_MAIN_BCKUP_IDX].c_str());
-
-            max_value.odpm_irq_stat_ext_0_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_EXT_0_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_ext_1_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_EXT_1_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_ext_2_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_EXT_2_SYS_EVT_SUB_BCKUP_IDX].c_str());
-            max_value.odpm_irq_stat_ext_3_sys_evt_sub_bckup_ =
-                    atoi(row[ODPM_IRQ_STAT_EXT_3_SYS_EVT_SUB_BCKUP_IDX].c_str());
-        }
-    }
-    if (!isAlreadyUpdated && max_value.battery_temp_ != DEFAULT_BATTERY_TEMP) {
-        std::string file_content = "LASTMEAL_UPDATED\n" + csvFile;
-        android::base::WriteStringToFile(file_content, CsvFilePath);
-        uploadData(stats_client, max_value);
-    }
-}
-
-void BrownoutDetectedReporter::logBrownout(const std::shared_ptr<IStats> &stats_client,
-                                           const std::string &logFilePath,
-                                           const std::string &brownoutReasonProp) {
-    std::string logFile;
-    if (!android::base::ReadFileToString(logFilePath, &logFile)) {
-        return;
-    }
-    std::istringstream content(logFile);
-    std::string line;
-    struct BrownoutDetectedInfo max_value = {};
-    max_value.voltage_now_ = DEFAULT_BATTERY_VOLT;
-    max_value.battery_soc_ = DEFAULT_BATTERY_SOC;
-    max_value.battery_temp_ = DEFAULT_BATTERY_TEMP;
-    std::smatch pattern_match;
-    int odpm_index = 0, dvfs_index = 0;
-    max_value.brownout_reason_ = brownoutReasonCheck(brownoutReasonProp);
-    if (max_value.brownout_reason_ < 0) {
-        return;
-    }
-    bool isAlreadyUpdated = false;
-    while (std::getline(content, line)) {
-        if (std::regex_match(line, pattern_match, kAlreadyUpdatedPattern)) {
-            isAlreadyUpdated = true;
-            break;
-        }
-        if (std::regex_match(line, pattern_match, kIrqPattern)) {
-            if (pattern_match.size() < (KEY_IDX + 1)) {
-                return;
-            }
-            std::ssub_match irq = pattern_match[KEY_IDX];
-            if (irq.str().find("batoilo") != std::string::npos) {
-                max_value.triggered_irq_ = BrownoutDetected::BATOILO;
-                continue;
-            }
-            if (irq.str().find("vdroop1") != std::string::npos) {
-                max_value.triggered_irq_ = BrownoutDetected::UVLO1;
-                continue;
-            }
-            if (irq.str().find("vdroop2") != std::string::npos) {
-                max_value.triggered_irq_ = BrownoutDetected::UVLO2;
-                continue;
-            }
-            if (irq.str().find("smpl_gm") != std::string::npos) {
-                max_value.triggered_irq_ = BrownoutDetected::SMPL_WARN;
-                continue;
-            }
-            continue;
-        }
-        if (std::regex_match(line, pattern_match, kTimestampPattern)) {
-            max_value.triggered_timestamp_ = parseTimestamp(line.c_str());
-            continue;
-        }
-        if (updateIfFound(line, kBatterySocPattern, &max_value.battery_soc_, kUpdateMin)) {
-            continue;
-        }
-        if (updateIfFound(line, kBatteryTempPattern, &max_value.battery_temp_, kUpdateMin)) {
-            continue;
-        }
-        if (updateIfFound(line, kBatteryCyclePattern, &max_value.battery_cycle_, kUpdateMax)) {
-            continue;
-        }
-        if (updateIfFound(line, kFgPattern, &max_value.voltage_now_, kUpdateMin)) {
-            continue;
-        }
-        if (updateIfFound(line, kDvfsPattern, &max_value.dvfs_value_[dvfs_index], kUpdateMax)) {
-            dvfs_index++;
-            // Discarding previous value and update with new DVFS value
-            if (dvfs_index == DVFS_MAX_IDX) {
-                dvfs_index = 0;
-            }
-            continue;
-        }
-        if (updateIfFound(line, kOdpmPattern, &max_value.odpm_value_[odpm_index], kUpdateMax)) {
-            odpm_index++;
-            // Discarding previous value and update with new ODPM value
-            if (odpm_index == ODPM_MAX_IDX) {
-                odpm_index = 0;
-            }
-            continue;
-        }
-    }
-    if (!isAlreadyUpdated && max_value.battery_temp_ != DEFAULT_BATTERY_TEMP) {
-        std::string file_content = "LASTMEAL_UPDATED\n" + logFile;
-        android::base::WriteStringToFile(file_content, logFilePath);
-        uploadData(stats_client, max_value);
-    }
-}
-
-}  // namespace pixel
-}  // namespace google
-}  // namespace hardware
-}  // namespace android
diff --git a/pixelstats/ChargeStatsReporter.cpp b/pixelstats/ChargeStatsReporter.cpp
index db6a6e85..2dacf8c0 100644
--- a/pixelstats/ChargeStatsReporter.cpp
+++ b/pixelstats/ChargeStatsReporter.cpp
@@ -40,7 +40,7 @@ using android::hardware::google::pixel::PixelAtoms::ChargeStats;
 using android::hardware::google::pixel::PixelAtoms::VoltageTierStats;
 
 #define DURATION_FILTER_SECS 15
-#define CHG_STATS_FMT "%d,%d,%d, %d,%d,%d,%d %d %d,%d, %d,%d"
+#define CHG_STATS_FMT "%d,%d,%d, %d,%d,%d,%d %d %d,%d, %d,%d,%d,%d"
 #define WLC_ASTATS_FMT "A:%d,%d,%d,%d"
 #define WLC_DSTATS_FMT "D:%x,%x,%x,%x,%x, %x,%x"
 
@@ -54,7 +54,7 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
                                             const std::string line, const std::string wline_at,
                                             const std::string wline_ac,
                                             const std::string pca_line) {
-    int charge_stats_fields[] = {
+    const int charge_stats_fields[] = {
             ChargeStats::kAdapterTypeFieldNumber,
             ChargeStats::kAdapterVoltageFieldNumber,
             ChargeStats::kAdapterAmperageFieldNumber,
@@ -75,40 +75,47 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
             ChargeStats::kAacrAlgoFieldNumber,
             ChargeStats::kAacpVersionFieldNumber,
             ChargeStats::kAaccFieldNumber,
+            ChargeStats::kAafvFieldNumber,
+            ChargeStats::kMaxChargeVoltageFieldNumber,
     };
     const int32_t chg_fields_size = std::size(charge_stats_fields);
-    static_assert(chg_fields_size == 20, "Unexpected charge stats fields size");
+    static_assert(chg_fields_size == 22, "Unexpected charge stats fields size");
     const int32_t wlc_fields_size = 7;
     std::vector<VendorAtomValue> values(chg_fields_size);
     VendorAtomValue val;
     int32_t i = 0, tmp[chg_fields_size] = {0};
     int32_t pca_ac[2] = {0}, pca_rs[5] = {0}, stats_size;
+    int32_t wlc_at[4] = {0};
     std::string pdo_line, file_contents;
     std::istringstream ss;
 
     ALOGD("processing %s", line.c_str());
 
     stats_size = sscanf(line.c_str(), CHG_STATS_FMT, &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4],
-                        &tmp[5], &tmp[6], &tmp[7], &tmp[8], &tmp[9], &tmp[18], &tmp[19]);
+                        &tmp[5], &tmp[6], &tmp[7], &tmp[8], &tmp[9], &tmp[18], &tmp[19], &tmp[20],
+                        &tmp[21]);
     if (stats_size != kNumChgStatsFormat00Fields && stats_size != kNumChgStatsFormat01Fields &&
-        stats_size != kNumChgStatsFormat02Fields && stats_size != kNumChgStatsFormat03Fields) {
+        stats_size != kNumChgStatsFormat02Fields && stats_size != kNumChgStatsFormat03Fields &&
+        stats_size != kNumChgStatsFormat04Fields) {
         ALOGE("Couldn't process %s (stats_size: %d)", line.c_str(), stats_size);
         return;
     }
 
     if (!wline_at.empty()) {
-        int32_t type = 0, soc = 0, voltage = 0, current = 0;
         ALOGD("wlc: processing %s", wline_at.c_str());
-        if (sscanf(wline_at.c_str(), WLC_ASTATS_FMT, &type, &soc, &voltage, &current) != 4) {
+        if (sscanf(wline_at.c_str(), WLC_ASTATS_FMT, &wlc_at[0], &wlc_at[1], &wlc_at[2],
+                   &wlc_at[3]) != 4) {
             ALOGE("Couldn't process %s", wline_at.c_str());
         } else {
-            tmp[0] = wireless_charge_stats_.TranslateSysModeToAtomValue(type);
-            tmp[1] = voltage;
-            tmp[2] = current;
+            tmp[0] = wireless_charge_stats_.TranslateSysModeToAtomValue(wlc_at[0]);
+            tmp[1] = wlc_at[2];
+            tmp[2] = wlc_at[3];
             ALOGD("wlc: processing %s", wline_ac.c_str());
             if (sscanf(wline_ac.c_str(), WLC_DSTATS_FMT, &tmp[10], &tmp[11], &tmp[12],
                        &tmp[13], &tmp[14], &tmp[15], &tmp[16]) != 7)
                 ALOGE("Couldn't process %s", wline_ac.c_str());
+            else
+                goto report_stats;
         }
     }
 
@@ -118,17 +125,14 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
                    &pca_rs[1], &pca_rs[2], &pca_rs[3], &pca_rs[4]) != 7) {
             ALOGE("Couldn't process %s", pca_line.c_str());
         } else {
+            tmp[0] = PixelAtoms::ChargeStats::ADAPTER_TYPE_USB_PD_PPS;
+            tmp[10] = pca_ac[0];
+            tmp[11] = pca_ac[1];
             tmp[12] = pca_rs[2];
             tmp[13] = pca_rs[3];
             tmp[14] = pca_rs[4];
+            tmp[15] = pca_rs[0];
             tmp[16] = pca_rs[1];
-            if (wline_at.empty()) {
-                /* force adapter type to PPS when pca log is available, but not wlc */
-                tmp[0] = PixelAtoms::ChargeStats::ADAPTER_TYPE_USB_PD_PPS;
-                tmp[10] = pca_ac[0];
-                tmp[11] = pca_ac[1];
-                tmp[15] = pca_rs[0];
-            }
         }
     }
 
@@ -152,6 +156,7 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
         ss >> tmp[17];
     }
 
+report_stats:
     for (i = 0; i < chg_fields_size; i++) {
         val.set<VendorAtomValue::intValue>(tmp[i]);
         values[charge_stats_fields[i] - kVendorAtomOffset] = val;
diff --git a/pixelstats/JsonConfigUtils.cpp b/pixelstats/JsonConfigUtils.cpp
index 223b949a..7e4f7969 100644
--- a/pixelstats/JsonConfigUtils.cpp
+++ b/pixelstats/JsonConfigUtils.cpp
@@ -24,11 +24,22 @@ namespace hardware {
 namespace google {
 namespace pixel {
 
+// Helper function to read int vectors from JSON
+std::vector<int> readIntVectorFromJson(const Json::Value &jsonArr) {
+    std::vector<int> vec;
+    if (jsonArr.isArray()) {  // Check if jsonArr is an array
+        for (Json::Value::ArrayIndex i = 0; i < jsonArr.size(); ++i) {
+            vec.push_back(jsonArr[i].asInt());
+        }
+    }
+    return vec;
+}
+
 // Helper function to read string vectors from JSON
 std::vector<std::string> readStringVectorFromJson(const Json::Value &jsonArr) {
     std::vector<std::string> vec;
     if (jsonArr.isArray()) { // Check if jsonArr is an array
-        for (unsigned int i = 0; i < jsonArr.size(); ++i) {
+        for (Json::Value::ArrayIndex i = 0; i < jsonArr.size(); ++i) {
             vec.push_back(jsonArr[i].asString());
         }
     }
@@ -40,7 +51,7 @@ std::vector<std::pair<std::string, std::string>>
 readStringPairVectorFromJson(const Json::Value &jsonArr) {
     std::vector<std::pair<std::string, std::string>> vec;
     if (jsonArr.isArray()) { // Check if jsonArr is an array
-        for (unsigned int i = 0; i < jsonArr.size(); ++i) {
+        for (Json::Value::ArrayIndex i = 0; i < jsonArr.size(); ++i) {
             const Json::Value& innerArr = jsonArr[i];
             if (innerArr.isArray() && innerArr.size() == 2) { // Check if inner array is valid
                 vec.push_back({innerArr[0].asString(), innerArr[1].asString()});
diff --git a/pixelstats/SysfsCollector.cpp b/pixelstats/SysfsCollector.cpp
index f5685162..dd81a81d 100644
--- a/pixelstats/SysfsCollector.cpp
+++ b/pixelstats/SysfsCollector.cpp
@@ -69,7 +69,7 @@ using android::hardware::google::pixel::PixelAtoms::PartitionsUsedSpaceReported;
 using android::hardware::google::pixel::PixelAtoms::PcieLinkStatsReported;
 using android::hardware::google::pixel::PixelAtoms::StorageUfsHealth;
 using android::hardware::google::pixel::PixelAtoms::StorageUfsResetCount;
-using android::hardware::google::pixel::PixelAtoms::ThermalDfsStats;
+using android::hardware::google::pixel::PixelAtoms::StorageUfsErrorCountReported;
 using android::hardware::google::pixel::PixelAtoms::VendorAudioAdaptedInfoStatsReported;
 using android::hardware::google::pixel::PixelAtoms::VendorAudioBtMediaStatsReported;
 using android::hardware::google::pixel::PixelAtoms::VendorAudioHardwareStatsReported;
@@ -89,9 +89,10 @@ using android::hardware::google::pixel::PixelAtoms::VendorTempResidencyStats;
 using android::hardware::google::pixel::PixelAtoms::WaterEventReported;
 using android::hardware::google::pixel::PixelAtoms::ZramBdStat;
 using android::hardware::google::pixel::PixelAtoms::ZramMmStat;
+using android::hardware::google::pixel::PixelAtoms::UfsStorageTypeReported;
 
-SysfsCollector::SysfsCollector(const Json::Value& configData)
-    : configData(configData) {}
+SysfsCollector::SysfsCollector(const Json::Value &configData)
+    : configData(configData), thermal_stats_reporter_(configData) {}
 
 bool SysfsCollector::ReadFileToInt(const std::string &path, int *val) {
     return ReadFileToInt(path.c_str(), val);
@@ -164,9 +165,9 @@ void SysfsCollector::logBatteryChargeCycles(const std::shared_ptr<IStats> &stats
 void SysfsCollector::logBatteryEEPROM(const std::shared_ptr<IStats> &stats_client) {
     std::string EEPROMPath = getCStringOrDefault(configData, "EEPROMPath");
     std::vector<std::string> GMSRPath = readStringVectorFromJson(configData["GMSRPath"]);
-    std::string maxfgHistoryPath = getCStringOrDefault(configData, "MaxfgHistoryPath");
     std::vector<std::string> FGModelLoadingPath = readStringVectorFromJson(configData["FGModelLoadingPath"]);
     std::vector<std::string> FGLogBufferPath = readStringVectorFromJson(configData["FGLogBufferPath"]);
+    std::string maxfgHistoryPath = "/dev/maxfg_history";
 
     if (EEPROMPath.empty()) {
         ALOGV("Battery EEPROM path not specified in JSON");
@@ -178,20 +179,7 @@ void SysfsCollector::logBatteryEEPROM(const std::shared_ptr<IStats> &stats_clien
     battery_EEPROM_reporter_.checkAndReportMaxfgHistory(stats_client, maxfgHistoryPath);
     battery_EEPROM_reporter_.checkAndReportFGModelLoading(stats_client, FGModelLoadingPath);
     battery_EEPROM_reporter_.checkAndReportFGLearning(stats_client, FGLogBufferPath);
-}
-
-/**
- * Log battery history validation
- */
-void SysfsCollector::logBatteryHistoryValidation() {
-    const std::shared_ptr<IStats> stats_client = getStatsService();
-    if (!stats_client) {
-        ALOGE("Unable to get AIDL Stats service");
-        return;
-    }
-
-    std::vector<std::string> FGLogBufferPath = readStringVectorFromJson(configData["FGLogBufferPath"]);
-    battery_EEPROM_reporter_.checkAndReportValidation(stats_client, FGLogBufferPath);
+    battery_EEPROM_reporter_.checkAndReportHistValid(stats_client, FGLogBufferPath);
 }
 
 /**
@@ -456,9 +444,13 @@ void SysfsCollector::logHDCPStats(const std::shared_ptr<IStats> &stats_client) {
 }
 
 void SysfsCollector::logThermalStats(const std::shared_ptr<IStats> &stats_client) {
+    //**************** Legacy dfs stats monitoring. ************************//
     std::vector<std::string> thermalStatsPaths =
         readStringVectorFromJson(configData["ThermalStatsPaths"]);
-    thermal_stats_reporter_.logThermalStats(stats_client, thermalStatsPaths);
+    thermal_stats_reporter_.logThermalDfsStats(stats_client, thermalStatsPaths);
+
+    //************** Tj trip count monitoring. ***********************//
+    thermal_stats_reporter_.logTjTripCountStats(stats_client);
 }
 
 void SysfsCollector::logDisplayPortDSCStats(const std::shared_ptr<IStats> &stats_client) {
@@ -595,37 +587,111 @@ void SysfsCollector::logUFSLifetime(const std::shared_ptr<IStats> &stats_client)
     }
 }
 
-void SysfsCollector::logUFSErrorStats(const std::shared_ptr<IStats> &stats_client) {
-    int value, host_reset_count = 0;
+void SysfsCollector::logUFSErrorsCount(const std::shared_ptr<IStats> &stats_client) {
+    std::string bootDevice = android::base::GetProperty("ro.boot.bootdevice", "");
+    if (bootDevice.empty()) {
+        ALOGW("ro.boot.bootdevice property is empty.");
+        return;
+    }
+
+    std::string baseUfsPath = "/sys/devices/platform/" + bootDevice + "/err_stats/";
+
+    static constexpr std::array<std::string_view, 13> errorNodes = {
+        "auto_hibern8_err_count",
+        "dev_reset_count",
+        "dl_err_count",
+        "dme_err_count",
+        "fatal_err_count",
+        "host_reset_count",
+        "link_startup_err_count",
+        "nl_err_count",
+        "pa_err_count",
+        "resume_err_count",
+        "suspend_err_count",
+        "task_abort_count",
+        "tl_err_count"
+    };
 
-    std::vector<std::string> UFSErrStatsPath = readStringVectorFromJson(configData["UFSErrStatsPath"]);
+    std::vector<VendorAtomValue> values(errorNodes.size());
+    std::vector<int32_t> counts(errorNodes.size());
 
-    if (UFSErrStatsPath.empty() || strlen(UFSErrStatsPath.front().c_str()) == 0) {
-        ALOGV("UFS host reset count path not specified in JSON");
-        return;
-    }
+    for (size_t errorTypeIndex = 0; errorTypeIndex < errorNodes.size(); ++errorTypeIndex) {
+        std::string fullPath = baseUfsPath + std::string(errorNodes[errorTypeIndex]); // Convert string_view to string.
 
-    for (int i = 0; i < UFSErrStatsPath.size(); i++) {
-        if (!ReadFileToInt(UFSErrStatsPath[i], &value)) {
-            ALOGE("Unable to read host reset count");
-            return;
+        if (!ReadFileToInt(fullPath, &counts[errorTypeIndex])) {
+            ALOGE("Unable to read ufs error (%s): %s",
+                  std::string(errorNodes[errorTypeIndex]).c_str(), fullPath.c_str());
+            counts[errorTypeIndex] = 0;
         }
-        host_reset_count += value;
     }
 
+    // Load values array
+    values[StorageUfsErrorCountReported::kAutoHibern8ErrCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[0]); // auto_hibern8_err_count
+    values[StorageUfsErrorCountReported::kDevResetCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[1]); // dev_reset_count
+    values[StorageUfsErrorCountReported::kDlErrCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[2]); // dl_err_count
+    values[StorageUfsErrorCountReported::kDmeErrCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[3]); // dme_err_count
+    values[StorageUfsErrorCountReported::kFatalErrCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[4]); // fatal_err_count
+    values[StorageUfsErrorCountReported::kHostResetCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[5]); // host_reset_count
+    values[StorageUfsErrorCountReported::kLinkStartupErrCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[6]); // link_startup_err_count
+    values[StorageUfsErrorCountReported::kNlErrCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[7]); // nl_err_count
+    values[StorageUfsErrorCountReported::kPaErrCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[8]); // pa_err_count
+    values[StorageUfsErrorCountReported::kResumeErrCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[9]); // resume_err_count
+    values[StorageUfsErrorCountReported::kSuspendErrCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[10]); // suspend_err_count
+    values[StorageUfsErrorCountReported::kTaskAbortCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[11]); // task_abort_count
+    values[StorageUfsErrorCountReported::kTlErrCountFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(counts[12]); // tl_err_count
+
+    // Send vendor atom to IStats HAL
+    VendorAtom event = {.reverseDomainName = PixelAtoms::ReverseDomainNames().pixel(),
+                        .atomId = PixelAtoms::Atom::kStorageUfsErrorCountReported,
+                        .values = std::move(values)};
+
+    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
+    if (!ret.isOk()) {
+        ALOGE("Unable to report StorageUfsErrorCountReported to Stats service");
+    }
+}
+
+void SysfsCollector::logUfsStorageType() {
+    const std::shared_ptr<IStats> stats_client = getStatsService();
+    if (!stats_client) {
+        ALOGE("Unable to get AIDL Stats service");
+        return;
+    }
+    int ufs_type = 0;
+    bool zufs_provisioned = android::base::GetBoolProperty(
+        "ro.vendor.product.ufs_type_zufs", false);
+    ALOGD("Property ro.vendor.product.ufs_type_zufs: %s", zufs_provisioned ? "true" : "false");
+
+    if (zufs_provisioned)
+        ufs_type = UfsStorageTypeReported::ZUFS;
+    else
+        ufs_type = UfsStorageTypeReported::CONVENTIONAL;
+
     // Load values array
     std::vector<VendorAtomValue> values(1);
-    VendorAtomValue tmp;
-    tmp.set<VendorAtomValue::intValue>(host_reset_count);
-    values[StorageUfsResetCount::kHostResetCountFieldNumber - kVendorAtomOffset] = tmp;
+    values[UfsStorageTypeReported::kUfsTypeFieldNumber - kVendorAtomOffset] =
+        VendorAtomValue::make<VendorAtomValue::intValue>(ufs_type);
 
     // Send vendor atom to IStats HAL
-    VendorAtom event = {.reverseDomainName = "",
-                        .atomId = PixelAtoms::Atom::kUfsResetCount,
+    VendorAtom event = {.reverseDomainName = PixelAtoms::ReverseDomainNames().pixel(),
+                        .atomId = PixelAtoms::Atom::kUfsStorageTypeReported,
                         .values = std::move(values)};
     const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
     if (!ret.isOk()) {
-        ALOGE("Unable to report UFS host reset count to Stats service");
+        ALOGE("Unable to report UfsStorageTypeReported to Stats service");
     }
 }
 
@@ -941,6 +1007,13 @@ void SysfsCollector::logF2fsSmartIdleMaintEnabled(const std::shared_ptr<IStats>
 }
 
 void SysfsCollector::logDmVerityPartitionReadAmount(const std::shared_ptr<IStats> &stats_client) {
+    // Check if DmVerityPartitionReadAmount is false in the configuration.
+    std::string dmVerityValue = getCStringOrDefault(configData, "DmVerityPartitionReadAmount");
+    if (dmVerityValue == "false") {
+        ALOGV("DmVerityPartitionReadAmount is false, skipping.");
+        return; // Return directly if the flag is false.
+    }
+
     //  Array of partition names corresponding to the DmPartition enum.
     static constexpr std::array<std::string_view, 4>
         partitionNames = {"system", "system_ext", "product", "vendor"};
@@ -954,8 +1027,6 @@ void SysfsCollector::logDmVerityPartitionReadAmount(const std::shared_ptr<IStats
 
     size_t partitionIndex = 0;
     for (const auto& partitionName : partitionNames) {
-        ++partitionIndex;
-
         // Construct the partition name with slot suffix
         std::string fullPartitionName = std::string(partitionName) + slotSuffix;
 
@@ -1020,6 +1091,7 @@ void SysfsCollector::logDmVerityPartitionReadAmount(const std::shared_ptr<IStats
         if (!ret.isOk()) {
             ALOGE("Unable to report DmVerityPartitionReadAmountReported to Stats service");
         }
+        ++partitionIndex;
     }
     return;
 }
@@ -2252,7 +2324,6 @@ void SysfsCollector::logPerDay() {
     logBatteryEEPROM(stats_client);
     logBatteryHealth(stats_client);
     logBatteryTTF(stats_client);
-    logBatteryHistoryValidation();
     logBlockStatsReported(stats_client);
     logCodec1Failed(stats_client);
     logCodecFailed(stats_client);
@@ -2271,7 +2342,7 @@ void SysfsCollector::logPerDay() {
     logSpeakerImpedance(stats_client);
     logSpeechDspStat(stats_client);
     logUFSLifetime(stats_client);
-    logUFSErrorStats(stats_client);
+    logUFSErrorsCount(stats_client);
     logSpeakerHealthStats(stats_client);
     mm_metrics_reporter_.logCmaStatus(stats_client);
     mm_metrics_reporter_.logPixelMmMetricsPerDay(stats_client);
@@ -2296,23 +2367,6 @@ void SysfsCollector::aggregatePer5Min() {
     mm_metrics_reporter_.aggregatePixelMmMetricsPer5Min();
 }
 
-void SysfsCollector::logBrownout() {
-    const std::shared_ptr<IStats> stats_client = getStatsService();
-    if (!stats_client) {
-        ALOGE("Unable to get AIDL Stats service");
-        return;
-    }
-    std::string brownoutCsvPath = getCStringOrDefault(configData, "BrownoutCsvPath");
-    std::string brownoutLogPath = getCStringOrDefault(configData, "BrownoutLogPath");
-    std::string brownoutReasonProp = getCStringOrDefault(configData, "BrownoutReasonProp");
-    if (brownoutCsvPath.empty())
-        brownout_detected_reporter_.logBrownoutCsv(stats_client, brownoutCsvPath.c_str(),
-                                                   brownoutReasonProp);
-    else if (brownoutLogPath.empty())
-        brownout_detected_reporter_.logBrownout(stats_client, brownoutLogPath.c_str(),
-                                                brownoutReasonProp);
-}
-
 void SysfsCollector::logWater() {
     const std::shared_ptr<IStats> stats_client = getStatsService();
     if (!stats_client) {
@@ -2325,7 +2379,7 @@ void SysfsCollector::logWater() {
 }
 
 void SysfsCollector::logOnce() {
-    logBrownout();
+    logUfsStorageType();
     logWater();
 }
 
diff --git a/pixelstats/TempResidencyReporter.cpp b/pixelstats/TempResidencyReporter.cpp
index 254d9ee9..139d4a3a 100644
--- a/pixelstats/TempResidencyReporter.cpp
+++ b/pixelstats/TempResidencyReporter.cpp
@@ -38,7 +38,6 @@ using aidl::android::frameworks::stats::VendorAtom;
 using aidl::android::frameworks::stats::VendorAtomValue;
 using android::base::ReadFileToString;
 using android::base::WriteStringToFile;
-using android::hardware::google::pixel::PixelAtoms::ThermalDfsStats;
 
 bool updateOffsetAndCheckBound(int *offset, const int &bytes_read, const int &data_len) {
     *offset += bytes_read;
diff --git a/pixelstats/ThermalStatsReporter.cpp b/pixelstats/ThermalStatsReporter.cpp
index d0e7db41..2afad7be 100644
--- a/pixelstats/ThermalStatsReporter.cpp
+++ b/pixelstats/ThermalStatsReporter.cpp
@@ -23,6 +23,7 @@
 #include <android-base/strings.h>
 #include <android/binder_manager.h>
 #include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
+#include <pixelstats/JsonConfigUtils.h>
 #include <pixelstats/ThermalStatsReporter.h>
 #include <utils/Log.h>
 
@@ -37,11 +38,131 @@ using aidl::android::frameworks::stats::IStats;
 using aidl::android::frameworks::stats::VendorAtom;
 using aidl::android::frameworks::stats::VendorAtomValue;
 using android::base::ReadFileToString;
+using android::base::WriteStringToFile;
 using android::hardware::google::pixel::PixelAtoms::ThermalDfsStats;
 
-ThermalStatsReporter::ThermalStatsReporter() {}
+namespace {
 
-bool ThermalStatsReporter::readDfsCount(const std::string &path, int64_t *val) {
+enum class ThermalStatsErrorCode : int32_t {
+    ERR_OK = 0,
+    ERR_READ_FAIL = -1,
+    ERR_RESET_FAIL = -2,
+    ERR_INVALID_DATA = -3
+};
+
+/**
+ * Calculates the stat value to report and the next previous value.
+ *
+ * Handles logic based on read/reset success, current vs previous values as:
+ * 1) Read = ERR
+ *  - Value to report = ERR_READ_FAIL
+ *  - Updated prev value = Prev (continue with previous value)
+ * 2) Read = OK AND Reset = ERR
+ *  a) Current = 0
+ *    - Value to report = ERR_RESET_FAIL (for better debuggability)
+ *    - Updated prev value = Current
+ *  b) Current >= Prev
+ *    - Value to report = Current - Prev
+ *    - Updated prev value = Current
+ *  c) Current < Prev
+ *    - Value to report = ERR_INVALID_DATA
+ *    - Updated prev value = 0
+ * 3) Read = OK AND Reset = OK
+ *  a) Current >= Prev
+ *    - Value to report = Current - Prev
+ *    - Updated prev value = 0
+ *  b) Current < Prev
+ *    - Value to report = ERR_INVALID_DATA
+ *    - Updated prev value = 0
+ *
+ * @param current_value: The value just read from the source.
+ * @param previous_value: The value stored from the previous reporting cycle.
+ * @param read_status: Status of the read operation.
+ * @param reset_status: Status of the reset operation.
+ * @return std::pair<int64_t, int64_t> Pair containing:
+ *    first:  The value to report (can be a count or an error code).
+ *    second: The updated previous value to store for the next cycle.
+ */
+std::pair<int64_t, int64_t> calculateReportValueAndNewPrev(int64_t current_value,
+                                                           int64_t previous_value,
+                                                           ThermalStatsErrorCode read_status,
+                                                           ThermalStatsErrorCode reset_status) {
+    int64_t value_to_report;
+    int64_t updated_prev_value;
+    if (read_status != ThermalStatsErrorCode::ERR_OK) {
+        value_to_report = static_cast<int64_t>(read_status);
+        updated_prev_value = previous_value;
+    } else if (reset_status != ThermalStatsErrorCode::ERR_OK) {
+        if (current_value == 0) {
+            value_to_report = static_cast<int64_t>(ThermalStatsErrorCode::ERR_RESET_FAIL);
+            updated_prev_value = current_value;
+        } else {
+            if (current_value >= previous_value) {
+                value_to_report = current_value - previous_value;
+                updated_prev_value = current_value;
+            } else {
+                value_to_report = static_cast<int64_t>(ThermalStatsErrorCode::ERR_INVALID_DATA);
+                updated_prev_value = 0;
+            }
+        }
+    } else {
+        if (current_value >= previous_value) {
+            value_to_report = current_value - previous_value;
+        } else {
+            value_to_report = static_cast<int64_t>(ThermalStatsErrorCode::ERR_INVALID_DATA);
+        }
+        updated_prev_value = 0;
+    }
+    return {value_to_report, updated_prev_value};
+}
+
+}  // namespace
+
+ThermalStatsReporter::ThermalStatsReporter(const Json::Value &configData) {
+    parseThermalTjTripCounterConfig(configData);
+}
+
+void ThermalStatsReporter::parseThermalTjTripCounterConfig(const Json::Value &configData) {
+    if (!configData.isMember("ThermalTjTripCounterConfig")) {
+        ALOGI("No thermal Tj trip counter config found.");
+        return;
+    }
+
+    Json::Value tjTripCountConfig = configData["ThermalTjTripCounterConfig"];
+    for (Json::Value::ArrayIndex i = 0; i < tjTripCountConfig.size(); i++) {
+        std::string name = tjTripCountConfig[i]["Name"].asString();
+        if (name.empty() || !kThermalZoneStrToEnum.count(name)) {
+            ALOGE("Thermal Tj trip counter config [%d] with invalid sensor %s", i, name.c_str());
+        }
+        std::vector<int> trip_numbers = readIntVectorFromJson(tjTripCountConfig[i]["TripNumbers"]);
+        for (size_t trip_idx = 0; trip_idx < trip_numbers.size(); trip_idx++) {
+            if (trip_numbers[trip_idx] < 0 || trip_numbers[trip_idx] >= kMaxTripNumber) {
+                ALOGE("Thermal Tj trip counter config [%d], trip at idx %zu has invalid trip "
+                      "number "
+                      "%d",
+                      i, trip_idx, trip_numbers[trip_idx]);
+                continue;
+            }
+        }
+        std::string read_path = getCStringOrDefault(tjTripCountConfig[i], "ReadPath");
+        std::string reset_path = getCStringOrDefault(tjTripCountConfig[i], "ResetPath");
+        if (read_path.empty() || reset_path.empty()) {
+            ALOGE("Thermal Tj trip counter config [%d] for sensor %s has invalid read: %s or "
+                  "reset: %s "
+                  "path",
+                  i, name.c_str(), read_path.c_str(), reset_path.c_str());
+            continue;
+        }
+        tz_trip_count_config_[kThermalZoneStrToEnum.at(name)] = {
+                .trip_numbers = trip_numbers,
+                .prev_trip_counts = std::vector<int64_t>(kMaxTripNumber, 0),
+                .read_path = read_path,
+                .reset_path = reset_path,
+        };
+    }
+}
+
+bool ThermalStatsReporter::readAllTripCount(const std::string &path, std::vector<int64_t> *trips) {
     std::string file_contents;
 
     if (path.empty()) {
@@ -52,26 +173,30 @@ bool ThermalStatsReporter::readDfsCount(const std::string &path, int64_t *val) {
     if (!ReadFileToString(path.c_str(), &file_contents)) {
         ALOGE("Unable to read %s - %s", path.c_str(), strerror(errno));
         return false;
-    } else {
-        int64_t trips[8];
-
-        if (sscanf(file_contents.c_str(),
-                   "%" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64
-                   " %" SCNd64 " %" SCNd64,
-                   &trips[0], &trips[1], &trips[2], &trips[3], &trips[4], &trips[5], &trips[6],
-                   &trips[7]) < 8) {
-            ALOGE("Unable to parse trip_counters %s from file %s", file_contents.c_str(),
-                  path.c_str());
-            return false;
-        }
+    }
 
-        /* Trip#6 corresponds to DFS count */
-        *val = trips[6];
+    trips->resize(kMaxTripNumber, 0);
+    if (sscanf(file_contents.c_str(),
+               "%" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64
+               " %" SCNd64,
+               &(*trips)[0], &(*trips)[1], &(*trips)[2], &(*trips)[3], &(*trips)[4], &(*trips)[5],
+               &(*trips)[6], &(*trips)[7]) < kMaxTripNumber) {
+        ALOGE("Unable to parse trip_counters %s from file %s", file_contents.c_str(), path.c_str());
+        return false;
     }
 
     return true;
 }
 
+bool ThermalStatsReporter::readDfsCount(const std::string &path, int64_t *val) {
+    std::vector<int64_t> trips;
+    if (!readAllTripCount(path, &trips)) {
+        return false;
+    }
+    *val = trips[6];
+    return true;
+}
+
 bool ThermalStatsReporter::captureThermalDfsStats(
         const std::vector<std::string> &thermal_stats_paths, struct ThermalDfsCounts *pcur_data) {
     bool report_stats = false;
@@ -179,9 +304,66 @@ void ThermalStatsReporter::logThermalDfsStats(const std::shared_ptr<IStats> &sta
         ALOGE("Unable to report thermal DFS stats to Stats service");
 }
 
-void ThermalStatsReporter::logThermalStats(const std::shared_ptr<IStats> &stats_client,
-                                           const std::vector<std::string> &thermal_stats_paths) {
-    logThermalDfsStats(stats_client, thermal_stats_paths);
+void ThermalStatsReporter::logTjTripCountStats(const std::shared_ptr<IStats> &stats_client) {
+    if (tz_trip_count_config_.empty())
+        return;
+
+    for (auto &[tz, trip_count_config] : tz_trip_count_config_) {
+        ThermalStatsErrorCode read_status, reset_status;
+        std::vector<int64_t> trips;
+
+        if (readAllTripCount(trip_count_config.read_path, &trips)) {
+            read_status = ThermalStatsErrorCode::ERR_OK;
+            if (WriteStringToFile(std::to_string(0), trip_count_config.reset_path)) {
+                reset_status = ThermalStatsErrorCode::ERR_OK;
+            } else {
+                ALOGE("Failed to write to file %s", trip_count_config.reset_path.c_str());
+                reset_status = ThermalStatsErrorCode::ERR_RESET_FAIL;
+            }
+        } else {
+            ALOGE("Unable to read trip count from %s", trip_count_config.read_path.c_str());
+            // Resize needed before assigning error codes. Value is meaningless.
+            trips.resize(kMaxTripNumber, 0);
+            read_status = ThermalStatsErrorCode::ERR_READ_FAIL;
+            // Reset fails if read fails
+            reset_status = ThermalStatsErrorCode::ERR_READ_FAIL;
+        }
+
+        for (const auto &trip_number : trip_count_config.trip_numbers) {
+            int64_t &prev_trip_count_ref = trip_count_config.prev_trip_counts[trip_number];
+
+            auto [trip_count_to_report, updated_prev_value] = calculateReportValueAndNewPrev(
+                    trips[trip_number], prev_trip_count_ref, read_status, reset_status);
+
+            // Update the stored previous value
+            prev_trip_count_ref = updated_prev_value;
+
+            // Skip reporting if the calculated count is 0 (and not an error code)
+            if (trip_count_to_report == 0) {
+                ALOGD("Skipping logging Tj trip count for tz: %d, trip: %d with count: 0", tz,
+                      trip_number);
+                continue;
+            }
+
+            std::vector<VendorAtomValue> values(3);
+            values[0].set<VendorAtomValue::intValue>(tz);
+            values[1].set<VendorAtomValue::intValue>(trip_number);
+            // Clamp the value to INT32_MAX before reporting
+            values[2].set<VendorAtomValue::intValue>(
+                    static_cast<int32_t>(std::min<int64_t>(trip_count_to_report, INT32_MAX)));
+
+            VendorAtom event = {.reverseDomainName = "",
+                                .atomId = PixelAtoms::Atom::kThermalTjTripCountReported,
+                                .values = std::move(values)};
+            ALOGI("Reported thermal Tj trip count metrics for tz: %d, trip: %d, count: %" PRId64,
+                  tz, trip_number, trip_count_to_report);
+
+            const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
+            if (!ret.isOk()) {
+                ALOGE("Unable to report thermal Tj trip count stats to Stats service");
+            }
+        }
+    }
 }
 
 }  // namespace pixel
diff --git a/pixelstats/include/pixelstats/BatteryEEPROMReporter.h b/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
index d84bf3b6..33e2194a 100644
--- a/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
+++ b/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
@@ -44,7 +44,7 @@ class BatteryEEPROMReporter {
                                   const std::vector<std::string> &paths);
     void checkAndReportFGModelLoading(const std::shared_ptr<IStats> &stats_client,
                                       const std::vector<std::string> &paths);
-    void checkAndReportValidation(const std::shared_ptr<IStats> &stats_client,
+    void checkAndReportHistValid(const std::shared_ptr<IStats> &stats_client,
                                   const std::vector<std::string> &paths);
 
   private:
@@ -53,10 +53,14 @@ class BatteryEEPROMReporter {
     const int kNumFGLearningFieldsV2 = 16;
     /* with additional unix time field */
     const int kNumFGLearningFieldsV3 = 17;
+    /* with COTRIM/COFF/LOCK fields */
+    const int kNumFGLearningFieldsV4 = 21;
     unsigned int last_lh_check_ = 0;
     /* The number of elements for history validation event */
     const int kNumValidationFields = 4;
+    const int kNumValidationFieldsV2 = 10;
     unsigned int last_hv_check_ = 0;
+    int last_cycle_count = 0;
 
     /* P21+ history format */
     struct BatteryEEPROMPipelineRawFormat {
@@ -108,7 +112,8 @@ class BatteryEEPROMReporter {
     void reportEvent(const std::shared_ptr<IStats> &stats_client,
                      const struct BatteryEEPROMPipeline &hist);
     bool ReadFileToInt(const std::string &path, int32_t *val);
-    std::string checkPaths(const std::vector<std::string>& paths);
+    bool checkCycleCountRollback();
+    std::string checkPaths(const std::vector<std::string> &paths);
 
     const int kNum77759GMSRFields = 11;
     const int kNum77779GMSRFields = 9;
diff --git a/pixelstats/include/pixelstats/BrownoutDetectedReporter.h b/pixelstats/include/pixelstats/BrownoutDetectedReporter.h
deleted file mode 100644
index 5e801eec..00000000
--- a/pixelstats/include/pixelstats/BrownoutDetectedReporter.h
+++ /dev/null
@@ -1,225 +0,0 @@
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
-#ifndef HARDWARE_GOOGLE_PIXEL_PIXELSTATS_BROWNOUTDETECTEDREPORTER_H
-#define HARDWARE_GOOGLE_PIXEL_PIXELSTATS_BROWNOUTDETECTEDREPORTER_H
-
-#include <aidl/android/frameworks/stats/IStats.h>
-#include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
-
-#include <map>
-#include <regex>
-#include <string>
-
-namespace android {
-namespace hardware {
-namespace google {
-namespace pixel {
-
-using aidl::android::frameworks::stats::IStats;
-using aidl::android::frameworks::stats::VendorAtomValue;
-
-#define ODPM_MAX_IDX 24
-#define DVFS_MAX_IDX 6
-
-/*
- * CsvIdx dictates the indexing of how data aligns with lastmeal.csv.
- * lastmeal.csv is generated by battery_mitigation upon brownout detection.
- * The new data added here are the additional data captured by
- * battery_mitigation during the generation of lastmeal.csv.
- * filed b/335498252 to make this portion be passed from gs-common.
- */
-enum CsvIdx {
-    TIMESTAMP_IDX,
-    IRQ_IDX,
-    SOC_IDX,
-    TEMP_IDX,
-    CYCLE_IDX,
-    VOLTAGE_IDX,
-    CURRENT_IDX,
-    DVFS_CHANNEL_0 = 7,
-    ODPM_CHANNEL_0 = DVFS_CHANNEL_0 + DVFS_MAX_IDX,      /* 13 */
-    MITIGATION_METHOD_0 = ODPM_CHANNEL_0 + ODPM_MAX_IDX, /* 37 */
-    MITIGATION_METHOD_0_COUNT,
-    MITIGATION_METHOD_0_TIME,
-    EVT_CNT_IDX_OILO1,
-    EVT_CNT_IDX_OILO2,
-    EVT_CNT_IDX_UVLO1,
-    EVT_CNT_IDX_UVLO2,
-    MAX_CURR,
-    IDX_VIMON_V,
-    IDX_VIMON_I,
-    PRE_OCP_CPU1_BCKUP_IDX,
-    PRE_OCP_CPU2_BCKUP_IDX,
-    PRE_OCP_TPU_BCKUP_IDX,
-    PRE_OCP_GPU_BCKUP_IDX,
-    PRE_UVLO_HIT_CNT_M_IDX,
-    PRE_UVLO_HIT_CNT_S_IDX,
-    UVLO_DUR_IDX,
-    ODPM_IRQ_STAT_0_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_1_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_2_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_3_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_4_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_5_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_6_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_7_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_8_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_9_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_10_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_11_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_0_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_1_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_2_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_3_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_4_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_5_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_6_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_7_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_8_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_9_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_10_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_11_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_EXT_0_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_EXT_1_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_EXT_2_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_EXT_3_SYS_EVT_MAIN_BCKUP_IDX,
-    ODPM_IRQ_STAT_EXT_0_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_EXT_1_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_EXT_2_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_EXT_3_SYS_EVT_SUB_BCKUP_IDX,
-    ODPM_IRQ_STAT_GPU_BCKUP_IDX,
-    ODPM_IRQ_STAT_TPU_BCKUP_IDX,
-    ODPM_IRQ_STAT_CPU1_BCKUP_IDX,
-    ODPM_IRQ_STAT_CPU2_BCKUP_IDX,
-};
-
-enum Irq {
-    SMPL_WARN,
-    OCP_WARN_CPUCL1,
-    OCP_WARN_CPUCL2,
-    SOFT_OCP_WARN_CPUCL1,
-    SOFT_OCP_WARN_CPUCL2,
-    OCP_WARN_TPU,
-    SOFT_OCP_WARN_TPU,
-    OCP_WARN_GPU,
-    SOFT_OCP_WARN_GPU,
-    PMIC_SOC,
-    UVLO1,
-    UVLO2,
-    BATOILO,
-    BATOILO2,
-    PMIC_120C,
-    PMIC_140C,
-    PMIC_OVERHEAT,
-};
-
-enum Update { kUpdateMax, kUpdateMin };
-
-/**
- * A class to upload Pixel Brownout metrics
- */
-class BrownoutDetectedReporter {
-  public:
-    void logBrownout(const std::shared_ptr<IStats> &stats_client, const std::string &logFilePath,
-                     const std::string &brownoutReasonProp);
-    void logBrownoutCsv(const std::shared_ptr<IStats> &stats_client, const std::string &logFilePath,
-                        const std::string &brownoutReasonProp);
-    int brownoutReasonCheck(const std::string &brownoutReasonProp);
-
-  private:
-    struct BrownoutDetectedInfo {
-        int triggered_irq_;
-        long triggered_timestamp_;
-        int battery_temp_;
-        int battery_cycle_;
-        int battery_soc_;
-        int voltage_now_;
-        int odpm_value_[ODPM_MAX_IDX];
-        int dvfs_value_[DVFS_MAX_IDX];
-        int brownout_reason_;
-        int mitigation_method_0_;
-        int mitigation_method_0_count_;
-        unsigned long long mitigation_method_0_time_us_;
-        int max_curr_;
-        int evt_cnt_uvlo1_;
-        int evt_cnt_uvlo2_;
-        int evt_cnt_oilo1_;
-        int evt_cnt_oilo2_;
-        int vimon_vbatt_;
-        int vimon_ibatt_;
-        int pre_ocp_cpu1_bckup_;
-        int pre_ocp_cpu2_bckup_;
-        int pre_ocp_tpu_bckup_;
-        int pre_ocp_gpu_bckup_;
-        int pre_uvlo_hit_cnt_m_;
-        int pre_uvlo_hit_cnt_s_;
-        int uvlo_dur_;
-        int odpm_irq_stat_0_sys_evt_main_bckup_;
-        int odpm_irq_stat_1_sys_evt_main_bckup_;
-        int odpm_irq_stat_2_sys_evt_main_bckup_;
-        int odpm_irq_stat_3_sys_evt_main_bckup_;
-        int odpm_irq_stat_4_sys_evt_main_bckup_;
-        int odpm_irq_stat_5_sys_evt_main_bckup_;
-        int odpm_irq_stat_6_sys_evt_main_bckup_;
-        int odpm_irq_stat_7_sys_evt_main_bckup_;
-        int odpm_irq_stat_8_sys_evt_main_bckup_;
-        int odpm_irq_stat_9_sys_evt_main_bckup_;
-        int odpm_irq_stat_10_sys_evt_main_bckup_;
-        int odpm_irq_stat_11_sys_evt_main_bckup_;
-        int odpm_irq_stat_0_sys_evt_sub_bckup_;
-        int odpm_irq_stat_1_sys_evt_sub_bckup_;
-        int odpm_irq_stat_2_sys_evt_sub_bckup_;
-        int odpm_irq_stat_3_sys_evt_sub_bckup_;
-        int odpm_irq_stat_4_sys_evt_sub_bckup_;
-        int odpm_irq_stat_5_sys_evt_sub_bckup_;
-        int odpm_irq_stat_6_sys_evt_sub_bckup_;
-        int odpm_irq_stat_7_sys_evt_sub_bckup_;
-        int odpm_irq_stat_8_sys_evt_sub_bckup_;
-        int odpm_irq_stat_9_sys_evt_sub_bckup_;
-        int odpm_irq_stat_10_sys_evt_sub_bckup_;
-        int odpm_irq_stat_11_sys_evt_sub_bckup_;
-        int odpm_irq_stat_ext_0_sys_evt_main_bckup_;
-        int odpm_irq_stat_ext_1_sys_evt_main_bckup_;
-        int odpm_irq_stat_ext_2_sys_evt_main_bckup_;
-        int odpm_irq_stat_ext_3_sys_evt_main_bckup_;
-        int odpm_irq_stat_ext_0_sys_evt_sub_bckup_;
-        int odpm_irq_stat_ext_1_sys_evt_sub_bckup_;
-        int odpm_irq_stat_ext_2_sys_evt_sub_bckup_;
-        int odpm_irq_stat_ext_3_sys_evt_sub_bckup_;
-        int odpm_irq_stat_gpu_bckup_;
-        int odpm_irq_stat_tpu_bckup_;
-        int odpm_irq_stat_cpu1_bckup_;
-        int odpm_irq_stat_cpu2_bckup_;
-    };
-
-    void setAtomFieldValue(std::vector<VendorAtomValue> &values, int offset, int content);
-    long parseTimestamp(std::string timestamp);
-    bool updateIfFound(std::string line, std::regex pattern, int *current_value, Update flag);
-    void uploadData(const std::shared_ptr<IStats> &stats_client,
-                    const struct BrownoutDetectedInfo max_value);
-    // Proto messages are 1-indexed and VendorAtom field numbers start at 2, so
-    // store everything in the values array at the index of the field number
-    // -2.
-    const int kVendorAtomOffset = 2;
-};
-
-}  // namespace pixel
-}  // namespace google
-}  // namespace hardware
-}  // namespace android
-
-#endif  // HARDWARE_GOOGLE_PIXEL_PIXELSTATS_BROWNOUTDETECTEDREPORTER_H
diff --git a/pixelstats/include/pixelstats/ChargeStatsReporter.h b/pixelstats/include/pixelstats/ChargeStatsReporter.h
index e787474d..f32ae93b 100644
--- a/pixelstats/include/pixelstats/ChargeStatsReporter.h
+++ b/pixelstats/include/pixelstats/ChargeStatsReporter.h
@@ -61,6 +61,8 @@ class ChargeStatsReporter {
     const int kNumChgStatsFormat02Fields = 10;  // "%d,%d,%d, %d,%d,%d,%d %d %d,%d" AACR + CSI
     const int kNumChgStatsFormat03Fields =
             12;  // "%d,%d,%d, %d,%d,%d,%d %d %d,%d, %d,%d" AACR + CSI + AACP
+    const int kNumChgStatsFormat04Fields =
+            14;  // "%d,%d,%d, %d,%d,%d,%d %d %d,%d, %d,%d,%d,%d" AACR + CSI + AACP + AAFV
 
     const std::string kThermalChargeMetricsPath =
             "/sys/devices/platform/google,charger/thermal_stats";
diff --git a/pixelstats/include/pixelstats/JsonConfigUtils.h b/pixelstats/include/pixelstats/JsonConfigUtils.h
index d3fcf2e9..d3bd80e8 100644
--- a/pixelstats/include/pixelstats/JsonConfigUtils.h
+++ b/pixelstats/include/pixelstats/JsonConfigUtils.h
@@ -26,6 +26,7 @@ namespace hardware {
 namespace google {
 namespace pixel {
 
+std::vector<int> readIntVectorFromJson(const Json::Value &jsonArr);
 std::vector<std::string> readStringVectorFromJson(const Json::Value &jsonArr);
 std::vector<std::pair<std::string, std::string>> readStringPairVectorFromJson(const Json::Value &jsonArr);
 std::string getCStringOrDefault(const Json::Value configData, const std::string& key);
diff --git a/pixelstats/include/pixelstats/SysfsCollector.h b/pixelstats/include/pixelstats/SysfsCollector.h
index 8b712a5b..2e07f86c 100644
--- a/pixelstats/include/pixelstats/SysfsCollector.h
+++ b/pixelstats/include/pixelstats/SysfsCollector.h
@@ -24,7 +24,6 @@
 #include "BatteryEEPROMReporter.h"
 #include "BatteryHealthReporter.h"
 #include "BatteryTTFReporter.h"
-#include "BrownoutDetectedReporter.h"
 #include "DisplayStatsReporter.h"
 #include "MitigationDurationReporter.h"
 #include "MitigationStatsReporter.h"
@@ -52,7 +51,6 @@ class SysfsCollector {
     bool ReadFileToInt(const char *path, int *val);
     void aggregatePer5Min();
     void logOnce();
-    void logBrownout();
     void logWater();
     void logPerDay();
     void logPerHour();
@@ -68,7 +66,7 @@ class SysfsCollector {
     void logSpeechDspStat(const std::shared_ptr<IStats> &stats_client);
     void logBatteryCapacity(const std::shared_ptr<IStats> &stats_client);
     void logUFSLifetime(const std::shared_ptr<IStats> &stats_client);
-    void logUFSErrorStats(const std::shared_ptr<IStats> &stats_client);
+    void logUFSErrorsCount(const std::shared_ptr<IStats> &stats_client);
     void logF2fsStats(const std::shared_ptr<IStats> &stats_client);
     void logF2fsAtomicWriteInfo(const std::shared_ptr<IStats> &stats_client);
     void logF2fsCompressionInfo(const std::shared_ptr<IStats> &stats_client);
@@ -106,12 +104,12 @@ class SysfsCollector {
     void logBatteryGMSR(const std::shared_ptr<IStats> &stats_client);
     void logDmVerityPartitionReadAmount(const std::shared_ptr<IStats> &stats_client);
     void logBatteryHistoryValidation();
+    void logUfsStorageType();
 
     BatteryEEPROMReporter battery_EEPROM_reporter_;
     MmMetricsReporter mm_metrics_reporter_;
     MitigationStatsReporter mitigation_stats_reporter_;
     MitigationDurationReporter mitigation_duration_reporter_;
-    BrownoutDetectedReporter brownout_detected_reporter_;
     ThermalStatsReporter thermal_stats_reporter_;
     DisplayStatsReporter display_stats_reporter_;
     BatteryHealthReporter battery_health_reporter_;
diff --git a/pixelstats/include/pixelstats/ThermalStatsReporter.h b/pixelstats/include/pixelstats/ThermalStatsReporter.h
index 57f246eb..c08c2497 100644
--- a/pixelstats/include/pixelstats/ThermalStatsReporter.h
+++ b/pixelstats/include/pixelstats/ThermalStatsReporter.h
@@ -19,6 +19,7 @@
 
 #include <aidl/android/frameworks/stats/IStats.h>
 #include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
+#include <json/reader.h>
 
 #include <string>
 
@@ -35,9 +36,10 @@ using aidl::android::frameworks::stats::VendorAtomValue;
  */
 class ThermalStatsReporter {
   public:
-    ThermalStatsReporter();
-    void logThermalStats(const std::shared_ptr<IStats> &stats_client,
-                         const std::vector<std::string> &thermal_stats_paths);
+    ThermalStatsReporter(const Json::Value &configData);
+    void logThermalDfsStats(const std::shared_ptr<IStats> &stats_client,
+                            const std::vector<std::string> &thermal_stats_paths);
+    void logTjTripCountStats(const std::shared_ptr<IStats> &stats_client);
 
   private:
     struct ThermalDfsCounts {
@@ -49,18 +51,35 @@ class ThermalStatsReporter {
         int64_t aur_count;
     };
 
+    struct TripCountConfig {
+        std::vector<int> trip_numbers;
+        std::vector<int64_t> prev_trip_counts;
+        std::string read_path;
+        std::string reset_path;
+    };
+
     // Proto messages are 1-indexed and VendorAtom field numbers start at 2, so
     // store everything in the values array at the index of the field number
     // -2.
     const int kVendorAtomOffset = 2;
     const int kNumOfThermalDfsStats = 6;
+    const int kMaxTripNumber = 8;
+    const std::unordered_map<std::string, PixelAtoms::TjThermalZone> kThermalZoneStrToEnum{
+            {"BIG", PixelAtoms::BIG}, {"BIG_MID", PixelAtoms::BIG_MID},
+            {"MID", PixelAtoms::MID}, {"LITTLE", PixelAtoms::LITTLE},
+            {"GPU", PixelAtoms::GPU}, {"TPU", PixelAtoms::TPU},
+            {"AUR", PixelAtoms::AUR}, {"ISP", PixelAtoms::ISP},
+            {"MEM", PixelAtoms::MEM}, {"AOC", PixelAtoms::AOC}};
+
     struct ThermalDfsCounts prev_data;
+    // Map of Tj thermal zone to the trip count config.
+    std::unordered_map<PixelAtoms::TjThermalZone, TripCountConfig> tz_trip_count_config_;
 
-    void logThermalDfsStats(const std::shared_ptr<IStats> &stats_client,
-                            const std::vector<std::string> &thermal_stats_paths);
     bool captureThermalDfsStats(const std::vector<std::string> &thermal_stats_paths,
                                 struct ThermalDfsCounts *cur_data);
     bool readDfsCount(const std::string &path, int64_t *val);
+    bool readAllTripCount(const std::string &path, std::vector<int64_t> *vals);
+    void parseThermalTjTripCounterConfig(const Json::Value &configData);
 };
 
 }  // namespace pixel
diff --git a/pixelstats/pixelatoms.proto b/pixelstats/pixelatoms.proto
index b3f2e448..2cdd9ed1 100644
--- a/pixelstats/pixelatoms.proto
+++ b/pixelstats/pixelatoms.proto
@@ -97,7 +97,7 @@ message Atom {
       VendorLongIRQStatsReported vendor_long_irq_stats_reported = 105043;
       VendorResumeLatencyStats vendor_resume_latency_stats = 105044;
       VendorTempResidencyStats vendor_temp_residency_stats = 105045;
-      BrownoutDetected brownout_detected = 105046;
+      BrownoutDetected brownout_detected = 105046 [(android.os.statsd.module) = "pixelbcl"];
       PcieLinkStatsReported pcie_link_stats = 105047;
       VendorSensorCoolingDeviceStats vendor_sensor_cooling_device_stats = 105048;
 
@@ -129,7 +129,6 @@ message Atom {
       BatteryTimeToFullStatsReported battery_time_to_full_stats_reported = 105074;
       VendorAudioDirectUsbAccessUsageStats vendor_audio_direct_usb_access_usage_stats = 105075 [(android.os.statsd.module) = "pixelaudio"];
       VendorAudioUsbConfigStats vendor_audio_usb_config_stats = 105076 [(android.os.statsd.module) = "pixelaudio"];
-      GpuFrequencyTimeInStatePerUidReported gpu_frequency_time_in_state_per_uid_reported = 105077;
       GpuFrozenAppsMemoryPerUid gpu_frozen_apps_memory_per_uid = 105078;
       RepairModeEntered repair_mode_entered = 105079;
       RepairModeExited repair_mode_exited = 105080;
@@ -147,8 +146,12 @@ message Atom {
       BatteryFirmwareUpdateReported battery_firmware_update_reported = 105092;
       PowerFifoDump power_fifo_dump = 105093 [(android.os.statsd.module) = "pixelpower"];
       GnssTtffReported gnss_ttff_reported = 105094 [(android.os.statsd.module) = "pixelgnss"];
+      StorageUfsErrorCountReported storage_ufs_error_count_reported = 105095;
+      UfsStorageTypeReported ufs_storage_type_reported = 105096;
+      ThermalTjTripCountReported thermal_tj_trip_count_reported = 105097;
     }
     // AOSP atom ID range ends at 109999
+    reserved 105077; // moved GpuFrequencyTimeInStatePerUidReported
     reserved 109997; // reserved for VtsVendorAtomJavaTest test atom
     reserved 109998; // reserved for VtsVendorAtomJavaTest test atom
     reserved 109999; // reserved for VtsVendorAtomJavaTest test atom
@@ -251,6 +254,8 @@ message ChargeStats {
     optional int32 aacr_algo = 19;
     optional int32 aacp_version = 20;
     optional int32 aacc = 21;
+    optional int32 aafv = 22;
+    optional int32 max_charge_voltage = 23;
 }
 
 /* A message containing stats from each charge voltage tier. */
@@ -1859,6 +1864,22 @@ message BrownoutDetected {
     optional int32 odpm_irq_stat_cpu1_bckup = 90;
     // odpm irq stat cpu2 at brownout
     optional int32 odpm_irq_stat_cpu2_bckup = 91;
+    // triggered ODPM Reading: Channel 25
+    optional int32 odpm_channel25 = 92;
+    // triggered ODPM Reading: Channel 26
+    optional int32 odpm_channel26 = 93;
+    // triggered ODPM Reading: Channel 27
+    optional int32 odpm_channel27 = 94;
+    // triggered ODPM Reading: Channel 28
+    optional int32 odpm_channel28 = 95;
+    // triggered ODPM Reading: Channel 29
+    optional int32 odpm_channel29 = 96;
+    // triggered ODPM Reading: Channel 30
+    optional int32 odpm_channel30 = 97;
+    // triggered ODPM Reading: Channel 31
+    optional int32 odpm_channel31 = 98;
+    // triggered ODPM Reading: Channel 32
+    optional int32 odpm_channel32 = 99;
 }
 
 /*
@@ -2393,6 +2414,7 @@ message PixelImpulseUsageReported {
       TAG_SKIN_TEMPERATURE = 2;
       TAG_BUSINESS_SCOPE = 3;
       TAG_NON_BUSINESS_SCOPE = 4;
+      TAG_RESTART_DELAY = 5;
   }
   /* Tag for debugging purpose */
   optional Tag tag = 5;
@@ -2776,87 +2798,6 @@ message VendorAudioUsbConfigStats {
   optional int32 duration_second = 7;
 };
 
-/*
- * Per-app GPU DVFS time-in-state data, for each GPU frequency.
- * Logging is capped at 15 apps/uids max, per 6 hours.
- * Logged from:
- *   hardware/google/pixel/pixelstats/
- *
- * See: b/341045478, b/340834608
- *
- * Estimated Logging Rate:
- * Peak: 15 times in 6 hours | Avg: 15 times in 6 hours
- */
-message GpuFrequencyTimeInStatePerUidReported {
-  /* Vendor reverse domain name (expecting "com.google.pixel"). */
-  optional string reverse_domain_name = 1;
-
-  /* App UID. */
-  optional int32 uid = 2 [(android.os.statsd.is_uid) = true];
-
-  /*
-   * Time passed, since the previous push of this atom for this uid, in
-   * milliseconds.
-   */
-  optional int32 reporting_duration_ms = 3;
-
-  /*
-   * Report up to 15 different frequencies, and how much time was spent in each
-   * frequency, by this app/uid since the previous push of this atom.
-   * Frequencies are given in KHz, and time is given in milliseconds since the
-   * previous push of this atom.
-   * Each individual device will always report the same frequency in the same
-   * field (for the aggregation in the metric(s) to work). If a frequency had 0
-   * time spent in it (since the previous atom push) for an app/uid - both
-   * frequency and duration fields for that frequency will not be set (to save
-   * space).
-   */
-  optional int32 frequency_1_khz = 4;
-  optional int32 time_1_millis = 5;
-
-  optional int32 frequency_2_khz = 6;
-  optional int32 time_2_millis = 7;
-
-  optional int32 frequency_3_khz = 8;
-  optional int32 time_3_millis = 9;
-
-  optional int32 frequency_4_khz = 10;
-  optional int32 time_4_millis = 11;
-
-  optional int32 frequency_5_khz = 12;
-  optional int32 time_5_millis = 13;
-
-  optional int32 frequency_6_khz = 14;
-  optional int32 time_6_millis = 15;
-
-  optional int32 frequency_7_khz = 16;
-  optional int32 time_7_millis = 17;
-
-  optional int32 frequency_8_khz = 18;
-  optional int32 time_8_millis = 19;
-
-  optional int32 frequency_9_khz = 20;
-  optional int32 time_9_millis = 21;
-
-  optional int32 frequency_10_khz = 22;
-  optional int32 time_10_millis = 23;
-
-  optional int32 frequency_11_khz = 24;
-  optional int32 time_11_millis = 25;
-
-  optional int32 frequency_12_khz = 26;
-  optional int32 time_12_millis = 27;
-
-  optional int32 frequency_13_khz = 28;
-  optional int32 time_13_millis = 29;
-
-  optional int32 frequency_14_khz = 30;
-  optional int32 time_14_millis = 31;
-
-  optional int32 frequency_15_khz = 32;
-  optional int32 time_15_millis = 33;
-}
-
 /* GPU memory allocation information for frozen apps */
 message GpuFrozenAppsMemoryPerUid {
   /* Vendor reverse domain name (expecting "com.google.pixel"). */
@@ -3233,7 +3174,7 @@ message MediaPlaybackUsageStatsReported {
   optional float volume = 10;
 
   /* Average power in milliwatts. -1 if unavailable. */
-  optional float average_power = 11;
+  optional float average_power = 11 [deprecated = true];
 
   /* Sample rate used in the media playback. */
   optional int32 sample_rate = 12;
@@ -3266,6 +3207,12 @@ message MediaPlaybackUsageStatsReported {
 
   /* Offload Encoding used in the media playback. */
   optional OffloadEncoding offload_encoding = 16;
+
+  /* Powers in milliwatts for each speaker. There are at most 4 speakers. */
+  repeated float milliwatt_powers = 17;
+
+  /* Active duration in second for each speaker. There are at most 4 speakers. */
+  repeated int32 speaker_active_duration_second = 18;
 }
 
 /*
@@ -3557,3 +3504,101 @@ message GnssTtffReported {
   optional bool almanac_used = 21;
   optional bool ephemeris_used = 22;
 }
+
+/*
+ * Collects and reports counts of various UFS error types.
+ * Logged from:
+ *   hardware/google/pixel/pixelstats/SysfsCollector.cpp
+ *
+ * Estimated Logging Rate:
+ * Peak: 1 times in 24 hours | Avg: 1 times per device per day
+ */
+message StorageUfsErrorCountReported {
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+
+  /* Number of auto_hibern8_err_count read from the ufs err_stats */
+  optional int32 auto_hibern8_err_count = 2;
+  /* Number of dev_reset_count read from the ufs err_stats */
+  optional int32 dev_reset_count = 3;
+  /* Number of dl_err_count read from the ufs err_stats */
+  optional int32 dl_err_count = 4;
+  /* Number of dme_err_count read from the ufs err_stats */
+  optional int32 dme_err_count = 5;
+  /* Number of fatal_err_count read from the ufs err_stats */
+  optional int32 fatal_err_count = 6;
+  /* Number of host_reset_count read from the ufs err_stats */
+  optional int32 host_reset_count = 7;
+  /* Number of link_startup_err_count read from the ufs err_stats */
+  optional int32 link_startup_err_count = 8;
+  /* Number of nl_err_count read from the ufs err_stats */
+  optional int32 nl_err_count = 9;
+  /* Number of pa_err_count read from the ufs err_stats */
+  optional int32 pa_err_count = 10;
+  /* Number of resume_err_count read from the ufs err_stats */
+  optional int32 resume_err_count = 11;
+  /* Number of suspend_err_count read from the ufs err_stats */
+  optional int32 suspend_err_count = 12;
+  /* Number of task_abort_count read from the ufs err_stats */
+  optional int32 task_abort_count = 13;
+  /* Number of tl_err_count read from the ufs err_stats */
+  optional int32 tl_err_count = 14;
+}
+
+/*
+ * Collects and reports UFS storage type, ZUFS or legacy.
+ * Logged from:
+ *   hardware/google/pixel/pixelstats/SysfsCollector.cpp
+ *
+ * Estimated Logging Rate:
+ * Peak: 1 times in 24 hours | Avg: 1 times per device per day
+ */
+message UfsStorageTypeReported {
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+
+  enum UfsType {
+    UNKNOWN = 0;
+    CONVENTIONAL = 1;
+    ZUFS = 2;
+  }
+
+  /* ZUFS type is provisioned */
+  optional UfsType ufs_type = 2;
+}
+
+enum TjThermalZone {
+  UNKNOWN_TZ = 0;
+  BIG = 1;
+  BIG_MID = 2;
+  MID = 3;
+  LITTLE = 4;
+  GPU = 5;
+  TPU = 6;
+  AUR = 7;
+  ISP = 8;
+  MEM = 9;
+  AOC = 10;
+}
+
+/*
+ * A message containing the number of times a thermal trip occurred for a
+ * particular trip number on a particular thermal zone.
+ *
+ * Conditions: We generate the atom only when the thermal zone trip is triggered
+ * for that trip number.
+ *
+ * Logged per thermal zone for configured trip number once per day.
+ *
+ * Logged from: hardware/google/pixel/pixelstats/SysfsCollector.cpp
+ */
+message ThermalTjTripCountReported {
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+  /* The tj thermal zone on which the trip occurred. */
+  optional TjThermalZone thermal_zone = 2;
+  /* The trip number for the thermal zone on which the trip occurred. */
+  optional int32 trip_number = 3;
+  /* The number of times the trip occurred. */
+  optional int32 trip_count = 4;
+}
diff --git a/power-libperfmgr/Android.bp b/power-libperfmgr/Android.bp
index bd4ccc7e..f8f89c00 100644
--- a/power-libperfmgr/Android.bp
+++ b/power-libperfmgr/Android.bp
@@ -68,12 +68,15 @@ cc_test {
         "aidl/GpuCapacityNode.cpp",
         "aidl/PowerHintSession.cpp",
         "aidl/PowerSessionManager.cpp",
+        "aidl/SessionMetrics.cpp",
         "aidl/SessionRecords.cpp",
         "aidl/SessionChannel.cpp",
         "aidl/SessionTaskMap.cpp",
         "aidl/SessionValueEntry.cpp",
         "aidl/TaskRampupMultNode.cpp",
         "aidl/UClampVoter.cpp",
+        "aidl/utils/TgidTypeChecker.cpp",
+        "aidl/utils/ThermalStateListener.cpp",
     ],
     cpp_std: "gnu++20",
     static_libs: [
@@ -83,6 +86,8 @@ cc_test {
         "android.hardware.common.fmq-V1-ndk",
     ],
     shared_libs: [
+        "android.hardware.thermal@2.0",
+        "android.hardware.thermal-V1-ndk",
         "liblog",
         "libbase",
         "libcutils",
@@ -145,12 +150,14 @@ cc_binary {
         "aidl/PowerSessionManager.cpp",
         "aidl/SupportManager.cpp",
         "aidl/UClampVoter.cpp",
+        "aidl/SessionMetrics.cpp",
         "aidl/SessionRecords.cpp",
         "aidl/SessionChannel.cpp",
         "aidl/SessionTaskMap.cpp",
         "aidl/SessionValueEntry.cpp",
         "aidl/TaskRampupMultNode.cpp",
         "aidl/utils/ThermalStateListener.cpp",
+        "aidl/utils/TgidTypeChecker.cpp",
     ],
     cpp_std: "gnu++20",
 }
diff --git a/power-libperfmgr/OWNERS b/power-libperfmgr/OWNERS
index 44e8882f..ec96eb48 100644
--- a/power-libperfmgr/OWNERS
+++ b/power-libperfmgr/OWNERS
@@ -1,4 +1,5 @@
-wvw@google.com
 jenhaochen@google.com
 jimmyshiu@google.com
 guibing@google.com
+jagdishsb@google.com
+mattbuckley@google.com
\ No newline at end of file
diff --git a/power-libperfmgr/aidl/AdpfTypes.h b/power-libperfmgr/aidl/AdpfTypes.h
index 2a5bf424..f5658bc5 100644
--- a/power-libperfmgr/aidl/AdpfTypes.h
+++ b/power-libperfmgr/aidl/AdpfTypes.h
@@ -127,7 +127,9 @@ constexpr const char *AdpfVoteTypeToStr(AdpfVoteType voteType) {
 enum class ProcessTag : int32_t {
     DEFAULT = 0,
     // System UI related processes, e.g. sysui, nexuslauncher.
-    SYSTEM_UI
+    SYSTEM_UI,
+    // Chrome related processes, e.g. com.android.chrome, com.android.chrome:privileged_processX
+    CHROME
 };
 
 constexpr const char *toString(ProcessTag procTag) {
@@ -136,6 +138,8 @@ constexpr const char *toString(ProcessTag procTag) {
             return "DEFAULT";
         case ProcessTag::SYSTEM_UI:
             return "SYSTEM_UI";
+        case ProcessTag::CHROME:
+            return "CHROME";
         default:
             return "INVALID_PROC_TAG";
     }
diff --git a/power-libperfmgr/aidl/MetricUploader.cpp b/power-libperfmgr/aidl/MetricUploader.cpp
index bb6e05ec..7d157513 100644
--- a/power-libperfmgr/aidl/MetricUploader.cpp
+++ b/power-libperfmgr/aidl/MetricUploader.cpp
@@ -79,7 +79,7 @@ bool MetricUploader::reportAtom(const int32_t &atomId, std::vector<VendorAtomVal
     return true;
 }
 
-bool MetricUploader::uploadMetrics(const SessionJankStatsWithThermal &sessMetrics) {
+bool MetricUploader::uploadMetrics(const SessionMetrics &sessMetrics) {
     // TODO(guibing): Store the sessMetrics into the format of the metric atom
     // and then call "reportAtom" to upload them.
     std::string sessMetricDescriptor = std::string(toString(sessMetrics.scenarioType)) + "-" +
diff --git a/power-libperfmgr/aidl/MetricUploader.h b/power-libperfmgr/aidl/MetricUploader.h
index 137cd213..8ce6646f 100644
--- a/power-libperfmgr/aidl/MetricUploader.h
+++ b/power-libperfmgr/aidl/MetricUploader.h
@@ -40,7 +40,7 @@ class MetricUploader {
     MetricUploader &operator=(MetricUploader &&) = delete;
 
     bool init();
-    bool uploadMetrics(const SessionJankStatsWithThermal &sessMetrics);
+    bool uploadMetrics(const SessionMetrics &sessMetrics);
 
     // Singleton
     static MetricUploader *getInstance() {
diff --git a/power-libperfmgr/aidl/PowerHintSession.cpp b/power-libperfmgr/aidl/PowerHintSession.cpp
index 95a666c4..09e9e06a 100644
--- a/power-libperfmgr/aidl/PowerHintSession.cpp
+++ b/power-libperfmgr/aidl/PowerHintSession.cpp
@@ -34,6 +34,7 @@
 #include "GpuCalculationHelpers.h"
 #include "tests/mocks/MockHintManager.h"
 #include "tests/mocks/MockPowerSessionManager.h"
+#include "utils/TgidTypeChecker.h"
 
 namespace aidl {
 namespace google {
@@ -58,9 +59,9 @@ static inline int64_t ns_to_100us(int64_t ns) {
     return ns / 100000;
 }
 
-static const char systemSessionCheckPath[] = "/proc/vendor_sched/is_tgid_system_ui";
-static const bool systemSessionCheckNodeExist = access(systemSessionCheckPath, W_OK) == 0;
 static constexpr int32_t kTargetDurationChangeThreshold = 30;  // Percentage change threshold
+static const char kHINTNAME_APP_FIRST_FRAME[] = "PER_ADPF_SESSION_FIRST_FRAME";
+static const char kHINTNAME_SYS_FIRST_FRAME[] = "ALL_ADPF_SESSIONS_FIRST_FRAME";
 
 }  // namespace
 
@@ -143,30 +144,6 @@ int64_t PowerHintSession<HintManagerT, PowerSessionManagerT>::convertWorkDuratio
     return output;
 }
 
-template <class HintManagerT, class PowerSessionManagerT>
-ProcessTag PowerHintSession<HintManagerT, PowerSessionManagerT>::getProcessTag(int32_t tgid) {
-    if (!systemSessionCheckNodeExist) {
-        ALOGD("Vendor system session checking node doesn't exist");
-        return ProcessTag::DEFAULT;
-    }
-
-    int flags = O_WRONLY | O_TRUNC | O_CLOEXEC;
-    ::android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(systemSessionCheckPath, flags)));
-    if (fd == -1) {
-        ALOGW("Can't open system session checking node %s", systemSessionCheckPath);
-        return ProcessTag::DEFAULT;
-    }
-    // The file-write return status is true if the task belongs to systemUI or Launcher. Other task
-    // or invalid tgid will return a false value.
-    auto stat = ::android::base::WriteStringToFd(std::to_string(tgid), fd);
-    ALOGD("System session checking result: %d - %d", tgid, stat);
-    if (stat) {
-        return ProcessTag::SYSTEM_UI;
-    } else {
-        return ProcessTag::DEFAULT;
-    }
-}
-
 template <class HintManagerT, class PowerSessionManagerT>
 PowerHintSession<HintManagerT, PowerSessionManagerT>::PowerHintSession(
         int32_t tgid, int32_t uid, const std::vector<int32_t> &threadIds, int64_t durationNs,
@@ -174,7 +151,9 @@ PowerHintSession<HintManagerT, PowerSessionManagerT>::PowerHintSession(
     : mPSManager(PowerSessionManagerT::getInstance()),
       mSessionId(++sSessionIDCounter),
       mSessTag(tag),
-      mProcTag(getProcessTag(tgid)),
+      mProcTag(TgidTypeChecker::getInstance()->isValid()
+                       ? TgidTypeChecker::getInstance()->getProcessTag(tgid)
+                       : ProcessTag::DEFAULT),
       mIdString(StringPrintf("%" PRId32 "-%" PRId32 "-%" PRId64 "-%s-%" PRId32, tgid, uid,
                              mSessionId, toString(tag).c_str(), static_cast<int32_t>(mProcTag))),
       mDescriptor(std::make_shared<AppHintDesc>(mSessionId, tgid, uid, threadIds, tag, mProcTag,
@@ -183,6 +162,9 @@ PowerHintSession<HintManagerT, PowerSessionManagerT>::PowerHintSession(
       mAdpfProfile(mProcTag != ProcessTag::DEFAULT
                            ? HintManager::GetInstance()->GetAdpfProfile(toString(mProcTag))
                            : HintManager::GetInstance()->GetAdpfProfile(toString(mSessTag))),
+      mEnableMetricCollection(
+              mProcTag != ProcessTag::SYSTEM_UI &&
+              HintManager::GetInstance()->GetOtherConfigs().enableMetricCollection.value_or(false)),
       mOnAdpfUpdate(
               [this](const std::shared_ptr<AdpfConfig> config) { this->setAdpfProfile(config); }),
       mSessionRecords(getAdpfProfile()->mHeuristicBoostOn.has_value() &&
@@ -202,7 +184,8 @@ PowerHintSession<HintManagerT, PowerSessionManagerT>::PowerHintSession(
     }
 
     mLastUpdatedTime = std::chrono::steady_clock::now();
-    mPSManager->addPowerSession(mIdString, mDescriptor, mAppDescriptorTrace, threadIds);
+    mPSManager->addPowerSession(mIdString, mDescriptor, mAppDescriptorTrace,
+                                mEnableMetricCollection, threadIds);
     // init boost
     auto adpfConfig = getAdpfProfile();
     mPSManager->voteSet(
@@ -247,12 +230,23 @@ void PowerHintSession<HintManagerT, PowerSessionManagerT>::updatePidControlVaria
 }
 
 template <class HintManagerT, class PowerSessionManagerT>
-void PowerHintSession<HintManagerT, PowerSessionManagerT>::tryToSendPowerHint(std::string hint) {
+bool PowerHintSession<HintManagerT, PowerSessionManagerT>::hintSupported(
+        const std::string &hint) const {
     if (!mSupportedHints[hint].has_value()) {
         mSupportedHints[hint] = HintManagerT::GetInstance()->IsHintSupported(hint);
     }
-    if (mSupportedHints[hint].value()) {
-        HintManagerT::GetInstance()->DoHint(hint);
+    return mSupportedHints[hint].value();
+}
+
+template <class HintManagerT, class PowerSessionManagerT>
+void PowerHintSession<HintManagerT, PowerSessionManagerT>::tryToSendPowerHint(
+        std::string hint, std::optional<std::chrono::milliseconds> duration) {
+    if (hintSupported(hint)) {
+        if (duration) {
+            HintManagerT::GetInstance()->DoHint(hint, *duration);
+        } else {
+            HintManagerT::GetInstance()->DoHint(hint);
+        }
     }
 }
 
@@ -474,16 +468,17 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::reportA
 
     bool hboostEnabled =
             adpfConfig->mHeuristicBoostOn.has_value() && adpfConfig->mHeuristicBoostOn.value();
-    bool heurRampupEnabled =
-            adpfConfig->mHeuristicRampup.has_value() && adpfConfig->mHeuristicRampup.value();
+    bool heurRampupEnabled = adpfConfig->mHeuristicRampup.has_value() &&
+                             adpfConfig->mHeuristicRampup.value() && mProcTag != ProcessTag::CHROME;
 
     if (hboostEnabled) {
-        FrameBuckets newFramesInBuckets;
+        FrameTimingMetrics newFrameMetrics;
         mSessionRecords->addReportedDurations(
-                actualDurations, mDescriptor->targetNs.count(), newFramesInBuckets,
+                actualDurations, mDescriptor->targetNs.count(), newFrameMetrics,
                 mSessTag == SessionTag::SURFACEFLINGER && mPSManager->getGameModeEnableState());
         mPSManager->updateHboostStatistics(mSessionId, mJankyLevel, actualDurations.size());
-        mPSManager->updateFrameBuckets(mSessionId, newFramesInBuckets);
+        mPSManager->updateFrameMetrics(mSessionId, newFrameMetrics);
+        mPSManager->updateCollectedSessionMetrics(mSessionId);
         updateHeuristicBoost();
         if (heurRampupEnabled && mPSManager->hasValidTaskRampupMultNode()) {
             mPSManager->updateRampupBoostMode(mSessionId, mJankyLevel,
@@ -562,6 +557,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::reportA
 template <class HintManagerT, class PowerSessionManagerT>
 ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::sendHint(
         SessionHint hint) {
+    std::string hint_name = toString(hint);
     {
         std::scoped_lock lock{mPowerHintSessionLock};
         if (mSessionClosed) {
@@ -585,6 +581,13 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::sendHin
                 updatePidControlVariable(adpfConfig->mUclampMinLow);
                 break;
             case SessionHint::CPU_LOAD_RESET:
+                if (isTimeout() && hintSupported(kHINTNAME_APP_FIRST_FRAME)) {
+                    hint_name = kHINTNAME_APP_FIRST_FRAME;
+                    if (hintSupported(kHINTNAME_SYS_FIRST_FRAME) &&
+                        mPSManager->areAllSessionsTimeout()) {
+                        hint_name = kHINTNAME_SYS_FIRST_FRAME;
+                    }
+                }
                 updatePidControlVariable(
                         std::max(adpfConfig->mUclampMinInit,
                                  static_cast<uint32_t>(mDescriptor->pidControlVariable)),
@@ -630,7 +633,16 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::sendHin
     }
     // Don't hold a lock (mPowerHintSession) while DoHint will try to take another
     // lock(NodeLooperThread).
-    tryToSendPowerHint(toString(hint));
+    tryToSendPowerHint(hint_name, {});
+
+    // TODO(kevindubois): b/411417175 Remove this hint in favor of capacity voting around
+    // GPU_LOAD_UP after all pixel devices support this node.
+    if (hint == SessionHint::GPU_LOAD_UP &&
+        (mSessTag == SessionTag::SURFACEFLINGER ||
+         (mSessTag == SessionTag::SYSUI || mProcTag == ProcessTag::SYSTEM_UI))) {
+        tryToSendPowerHint("EXPENSIVE_RENDERING", 175ms);
+    }
+
     return ndk::ScopedAStatus::ok();
 }
 
diff --git a/power-libperfmgr/aidl/PowerHintSession.h b/power-libperfmgr/aidl/PowerHintSession.h
index c243f719..a2fa7693 100644
--- a/power-libperfmgr/aidl/PowerHintSession.h
+++ b/power-libperfmgr/aidl/PowerHintSession.h
@@ -78,7 +78,10 @@ class PowerHintSession : public BnPowerHintSession, public Immobile {
     bool isTimeout() REQUIRES(mPowerHintSessionLock);
     // Is hint session for a user application
     bool isAppSession() REQUIRES(mPowerHintSessionLock);
-    void tryToSendPowerHint(std::string hint);
+    // Try to send the named hint, optionally, with a override duration. If no duration is set,
+    // the hint's default duration applies.
+    bool hintSupported(const std::string &hint) const;
+    void tryToSendPowerHint(std::string hint, std::optional<std::chrono::milliseconds> duration);
     void updatePidControlVariable(int pidControlVariable, bool updateVote = true)
             REQUIRES(mPowerHintSessionLock);
     int64_t convertWorkDurationToBoostByPid(const std::vector<WorkDuration> &actualDurations)
@@ -89,7 +92,6 @@ class PowerHintSession : public BnPowerHintSession, public Immobile {
     void updateHeuristicBoost() REQUIRES(mPowerHintSessionLock);
     void resetSessionHeuristicStates() REQUIRES(mPowerHintSessionLock);
     const std::shared_ptr<AdpfConfig> getAdpfProfile() const;
-    ProcessTag getProcessTag(int32_t tgid);
     ndk::ScopedAStatus setModeLocked(SessionMode mode, bool enabled)
             REQUIRES(mPowerHintSessionLock);
 
@@ -108,10 +110,11 @@ class PowerHintSession : public BnPowerHintSession, public Immobile {
     time_point<steady_clock> mLastUpdatedTime GUARDED_BY(mPowerHintSessionLock);
     bool mSessionClosed GUARDED_BY(mPowerHintSessionLock) = false;
     // Are cpu load change related hints are supported
-    std::unordered_map<std::string, std::optional<bool>> mSupportedHints;
+    std::unordered_map<std::string, std::optional<bool>> mutable mSupportedHints;
     // Use the value of the last enum in enum_range +1 as array size
     std::array<bool, enum_size<SessionMode>()> mModes GUARDED_BY(mPowerHintSessionLock){};
     std::shared_ptr<AdpfConfig> mAdpfProfile;
+    const bool mEnableMetricCollection;
     std::function<void(const std::shared_ptr<AdpfConfig>)> mOnAdpfUpdate;
     std::unique_ptr<SessionRecords> mSessionRecords GUARDED_BY(mPowerHintSessionLock) = nullptr;
     bool mHeuristicBoostActive GUARDED_BY(mPowerHintSessionLock){false};
diff --git a/power-libperfmgr/aidl/PowerSessionManager.cpp b/power-libperfmgr/aidl/PowerSessionManager.cpp
index fd17a906..dd07feb6 100644
--- a/power-libperfmgr/aidl/PowerSessionManager.cpp
+++ b/power-libperfmgr/aidl/PowerSessionManager.cpp
@@ -30,6 +30,7 @@
 #include "AppDescriptorTrace.h"
 #include "AppHintDesc.h"
 #include "tests/mocks/MockHintManager.h"
+#include "utils/ThermalStateListener.h"
 
 namespace aidl {
 namespace google {
@@ -40,6 +41,9 @@ namespace pixel {
 
 constexpr char kGameModeName[] = "GAME";
 constexpr int32_t kBGRampupVal = 1;
+// The frame number threshold to decide whether upload a metric session.
+// It's intended to avoid uploading the metric session with just few frames.
+static constexpr int32_t kNumOfFramesThreshold = 20;
 
 namespace {
 /* there is no glibc or bionic wrapper */
@@ -98,7 +102,7 @@ bool PowerSessionManager<HintManagerT>::getGameModeEnableState() {
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::addPowerSession(
         const std::string &idString, const std::shared_ptr<AppHintDesc> &sessionDescriptor,
-        const std::shared_ptr<AppDescriptorTrace> &sessionTrace,
+        const std::shared_ptr<AppDescriptorTrace> &sessionTrace, const bool enableMetricCollection,
         const std::vector<int32_t> &threadIds) {
     if (!sessionDescriptor) {
         ALOGE("sessionDescriptor is null. PowerSessionManager failed to add power session: %s",
@@ -121,6 +125,18 @@ void PowerSessionManager<HintManagerT>::addPowerSession(
             static_cast<std::underlying_type_t<AdpfVoteType>>(AdpfVoteType::CPU_VOTE_DEFAULT),
             CpuVote(false, timeNow, sessionDescriptor->targetNs, kUclampMin, kUclampMax));
 
+    if (enableMetricCollection) {
+        SessionMetrics sessMetr;
+        sessMetr.uid = sessionDescriptor->uid;
+        sessMetr.metricStartTime = std::chrono::system_clock::now();
+        sessMetr.thermalThrotStat = ThermalStateListener::getInstance()->getThermalThrotSev();
+        if (sessionDescriptor->tag == SessionTag::SURFACEFLINGER) {
+            sessMetr.frameTimelineType = FrameTimelineType::SURFACEFLINGER;
+            sessMetr.scenarioType = mGameModeEnabled ? ScenarioType::GAME : ScenarioType::DEFAULT;
+        }
+        sve.sessFrameMetrics = sessMetr;
+    }
+
     bool addedRes = false;
     {
         std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
@@ -148,6 +164,18 @@ void PowerSessionManager<HintManagerT>::removePowerSession(int64_t sessionId) {
         // Wait till end to remove session because it needs to be around for apply U clamp
         // to work above since applying the uclamp needs a valid session id
         std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
+
+        // collect the session metric before close the session
+        auto sessValPtr = mSessionTaskMap.findSession(sessionId);
+        if (sessValPtr->sessFrameMetrics) {
+            sessValPtr->sessFrameMetrics.value().metricEndTime = std::chrono::system_clock::now();
+            sessValPtr->sessFrameMetrics.value().metricSessionCompleted = true;
+            if (sessValPtr->sessFrameMetrics.value().totalFrameNumber >= kNumOfFramesThreshold &&
+                mCollectedSessionMetrics.size() < kMaxNumOfCachedSessionMetrics) {
+                mCollectedSessionMetrics.push_back(sessValPtr->sessFrameMetrics.value());
+            }
+        }
+
         mSessionTaskMap.replace(sessionId, {}, &addedThreads, &removedThreads);
         mSessionTaskMap.remove(sessionId);
     }
@@ -189,7 +217,7 @@ void PowerSessionManager<HintManagerT>::setThreadsFromPowerSession(
 }
 
 template <class HintManagerT>
-std::optional<bool> PowerSessionManager<HintManagerT>::isAnyAppSessionActive() {
+bool PowerSessionManager<HintManagerT>::isAnyAppSessionActive() {
     bool isAnyAppSessionActive = false;
     {
         std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
@@ -199,6 +227,16 @@ std::optional<bool> PowerSessionManager<HintManagerT>::isAnyAppSessionActive() {
     return isAnyAppSessionActive;
 }
 
+template <class HintManagerT>
+bool PowerSessionManager<HintManagerT>::areAllSessionsTimeout() {
+    bool areAllTimeout = false;
+    {
+        std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
+        areAllTimeout = mSessionTaskMap.areAllSessionsTimeout(std::chrono::steady_clock::now());
+    }
+    return areAllTimeout;
+}
+
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::dumpToFd(int fd) {
     std::ostringstream dump_buf;
@@ -224,6 +262,20 @@ void PowerSessionManager<HintManagerT>::dumpToFd(int fd) {
                 dump_buf << "]\n";
             });
     dump_buf << "========== End PowerSessionManager ADPF list ==========\n";
+
+    dump_buf << "========== Begin power session metrics list ==========\n";
+    dump_buf << "--- Ongoing sessions' metrics ---\n";
+    mSessionTaskMap.forEachSessionValTasks(
+            [&](auto /* sessionId */, const auto &sessionVal, const auto & /* tasks */) {
+                if (sessionVal.sessFrameMetrics) {
+                    sessionVal.sessFrameMetrics.value().dump(dump_buf);
+                }
+            });
+    dump_buf << "\n--- Cached sessions' metrics ---\n";
+    for (const auto &met : mCollectedSessionMetrics) {
+        met.dump(dump_buf);
+    }
+    dump_buf << "========== End power session metrics list ==========\n";
     if (!::android::base::WriteStringToFd(dump_buf.str(), fd)) {
         ALOGE("Failed to dump one of session list to fd:%d", fd);
     }
@@ -250,6 +302,19 @@ void PowerSessionManager<HintManagerT>::pause(int64_t sessionId) {
             // default low value when session gets paused.
             voteRampupBoostLocked(sessionId, false, kBGRampupVal, kBGRampupVal);
         }
+
+        // collect the session metric
+        if (sessValPtr->sessFrameMetrics) {
+            sessValPtr->sessFrameMetrics.value().metricEndTime = std::chrono::system_clock::now();
+            sessValPtr->sessFrameMetrics.value().metricSessionCompleted = true;
+            if (sessValPtr->sessFrameMetrics.value().totalFrameNumber >= kNumOfFramesThreshold &&
+                mCollectedSessionMetrics.size() < kMaxNumOfCachedSessionMetrics) {
+                mCollectedSessionMetrics.push_back(sessValPtr->sessFrameMetrics.value());
+            }
+            sessValPtr->sessFrameMetrics.value().resetMetric(
+                    ThermalStateListener::getInstance()->getThermalThrotSev(),
+                    mGameModeEnabled ? ScenarioType::GAME : ScenarioType::DEFAULT);
+        }
     }
     applyCpuAndGpuVotes(sessionId, std::chrono::steady_clock::now());
 }
@@ -269,6 +334,11 @@ void PowerSessionManager<HintManagerT>::resume(int64_t sessionId) {
             return;
         }
         sessValPtr->isActive = true;
+        if (sessValPtr->sessFrameMetrics) {
+            sessValPtr->sessFrameMetrics.value().resetMetric(
+                    ThermalStateListener::getInstance()->getThermalThrotSev(),
+                    mGameModeEnabled ? ScenarioType::GAME : ScenarioType::DEFAULT);
+        }
     }
     applyCpuAndGpuVotes(sessionId, std::chrono::steady_clock::now());
 }
@@ -572,15 +642,29 @@ void PowerSessionManager<HintManagerT>::clear() {
 }
 
 template <class HintManagerT>
-void PowerSessionManager<HintManagerT>::updateFrameBuckets(int64_t sessionId,
-                                                           const FrameBuckets &lastReportedFrames) {
+void PowerSessionManager<HintManagerT>::updateFrameMetrics(
+        int64_t sessionId, const FrameTimingMetrics &lastReportedFrames) {
     std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
     auto sessValPtr = mSessionTaskMap.findSession(sessionId);
     if (nullptr == sessValPtr) {
         return;
     }
 
-    sessValPtr->sessFrameBuckets.addUpNewFrames(lastReportedFrames);
+    sessValPtr->sessFrameBuckets.addUpNewFrames(lastReportedFrames.framesInBuckets);
+    if (sessValPtr->sessFrameMetrics) {
+        switch (sessValPtr->sessFrameMetrics.value().scenarioType) {
+            case ScenarioType::GAME:
+                sessValPtr->sessFrameMetrics.value().addNewFrames(
+                        lastReportedFrames.gameFrameMetrics);
+                break;
+            case ScenarioType::DEFAULT:
+                sessValPtr->sessFrameMetrics.value().addNewFrames(
+                        lastReportedFrames.framesInBuckets);
+                break;
+            default:
+                ALOGW("Unknown scenarioType during updateFrameMetrics.");
+        }
+    }
 }
 
 template <class HintManagerT>
@@ -707,6 +791,41 @@ void PowerSessionManager<HintManagerT>::updateRampupBoostMode(int64_t sessionId,
     }
 }
 
+template <class HintManagerT>
+bool PowerSessionManager<HintManagerT>::updateCollectedSessionMetrics(int64_t sessionId) {
+    std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
+    auto sessValPtr = mSessionTaskMap.findSession(sessionId);
+    if (nullptr == sessValPtr || !sessValPtr->sessFrameMetrics) {
+        return false;
+    }
+
+    bool needNewMetricSession = false;
+    auto newScenarioType = mGameModeEnabled ? ScenarioType::GAME : ScenarioType::DEFAULT;
+    if (sessValPtr->tag == SessionTag::SURFACEFLINGER) {
+        if (sessValPtr->sessFrameMetrics.value().scenarioType != newScenarioType) {
+            needNewMetricSession = true;
+        }
+    }
+
+    auto newThermalThrotSev = ThermalStateListener::getInstance()->getThermalThrotSev();
+    if (sessValPtr->sessFrameMetrics.value().thermalThrotStat != newThermalThrotSev) {
+        needNewMetricSession = true;
+    }
+
+    if (needNewMetricSession) {
+        sessValPtr->sessFrameMetrics.value().metricEndTime = std::chrono::system_clock::now();
+        sessValPtr->sessFrameMetrics.value().metricSessionCompleted = true;
+        if (sessValPtr->sessFrameMetrics.value().totalFrameNumber >= kNumOfFramesThreshold &&
+            mCollectedSessionMetrics.size() < kMaxNumOfCachedSessionMetrics) {
+            mCollectedSessionMetrics.push_back(sessValPtr->sessFrameMetrics.value());
+        }
+        sessValPtr->sessFrameMetrics.value().resetMetric(newThermalThrotSev, newScenarioType);
+        return true;
+    }
+
+    return false;
+}
+
 template class PowerSessionManager<>;
 template class PowerSessionManager<testing::NiceMock<mock::pixel::MockHintManager>>;
 
diff --git a/power-libperfmgr/aidl/PowerSessionManager.h b/power-libperfmgr/aidl/PowerSessionManager.h
index cc86feeb..7010e3db 100644
--- a/power-libperfmgr/aidl/PowerSessionManager.h
+++ b/power-libperfmgr/aidl/PowerSessionManager.h
@@ -26,6 +26,7 @@
 #include "AppHintDesc.h"
 #include "BackgroundWorker.h"
 #include "GpuCapacityNode.h"
+#include "SessionMetrics.h"
 #include "SessionTaskMap.h"
 #include "TaskRampupMultNode.h"
 
@@ -49,7 +50,7 @@ class PowerSessionManager : public Immobile {
     void addPowerSession(const std::string &idString,
                          const std::shared_ptr<AppHintDesc> &sessionDescriptor,
                          const std::shared_ptr<AppDescriptorTrace> &sessionTrace,
-                         const std::vector<int32_t> &threadIds);
+                         const bool enableMetricCollection, const std::vector<int32_t> &threadIds);
     void removePowerSession(int64_t sessionId);
     // Replace current threads in session with threadIds
     void setThreadsFromPowerSession(int64_t sessionId, const std::vector<int32_t> &threadIds);
@@ -76,7 +77,7 @@ class PowerSessionManager : public Immobile {
 
     void updateHboostStatistics(int64_t sessionId, SessionJankyLevel jankyLevel,
                                 int32_t numOfFrames);
-    void updateFrameBuckets(int64_t sessionId, const FrameBuckets &lastReportedFrames);
+    void updateFrameMetrics(int64_t sessionId, const FrameTimingMetrics &lastReportedFrames);
     bool hasValidTaskRampupMultNode();
     void updateRampupBoostMode(int64_t sessionId, SessionJankyLevel jankyLevel,
                                int32_t defaultRampupVal, int32_t highRampupVal);
@@ -95,9 +96,11 @@ class PowerSessionManager : public Immobile {
     void clear();
     std::shared_ptr<void> getSession(int64_t sessionId);
     bool getGameModeEnableState();
+    bool updateCollectedSessionMetrics(int64_t sessionId);
+    bool areAllSessionsTimeout();
 
   private:
-    std::optional<bool> isAnyAppSessionActive();
+    bool isAnyAppSessionActive();
     const std::string kDisableBoostHintName;
 
     // Rewrite specific
@@ -133,7 +136,10 @@ class PowerSessionManager : public Immobile {
         : mPriorityQueueWorkerPool(new PriorityQueueWorkerPool(1, "adpf_handler")),
           mEventSessionTimeoutWorker([&](auto e) { handleEvent(e); }, mPriorityQueueWorkerPool),
           mGpuCapacityNode(createGpuCapacityNode()),
-          mTaskRampupMultNode(TaskRampupMultNode::getInstance()) {}
+          mTaskRampupMultNode(TaskRampupMultNode::getInstance()),
+          kMaxNumOfCachedSessionMetrics(HintManagerT::GetInstance()
+                                                ->GetOtherConfigs()
+                                                .maxNumOfCachedSessionMetrics.value_or(100)) {}
     PowerSessionManager(PowerSessionManager const &) = delete;
     PowerSessionManager &operator=(PowerSessionManager const &) = delete;
 
@@ -144,6 +150,9 @@ class PowerSessionManager : public Immobile {
 
     std::atomic<bool> mGameModeEnabled{false};
     std::shared_ptr<TaskRampupMultNode> mTaskRampupMultNode;
+
+    std::vector<SessionMetrics> mCollectedSessionMetrics GUARDED_BY(mSessionTaskMapMutex);
+    const int32_t kMaxNumOfCachedSessionMetrics;
 };
 
 }  // namespace pixel
diff --git a/power-libperfmgr/aidl/SessionMetrics.cpp b/power-libperfmgr/aidl/SessionMetrics.cpp
new file mode 100644
index 00000000..58cc0a0c
--- /dev/null
+++ b/power-libperfmgr/aidl/SessionMetrics.cpp
@@ -0,0 +1,145 @@
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
+#define LOG_TAG "powerhal-libperfmgr"
+
+#include "SessionMetrics.h"
+
+#include <android-base/logging.h>
+
+namespace aidl {
+namespace google {
+namespace hardware {
+namespace power {
+namespace impl {
+namespace pixel {
+
+static constexpr int32_t TIME_BUCKETS_SIZE = 100;
+
+void SessionMetrics::resetMetric(ThrottlingSeverity newThermalState, ScenarioType newScenario) {
+    scenarioType = newScenario;
+    thermalThrotStat = newThermalState;
+    metricSessionCompleted = false;
+    totalFrameNumber = 0;
+    metricStartTime = std::chrono::system_clock::now();
+    appFrameMetrics = std::nullopt;
+    gameFrameMetrics = std::nullopt;
+}
+
+void SessionMetrics::addNewFrames(const GameFrameMetrics &newFrameMetrics) {
+    if (!gameFrameMetrics) {
+        GameFrameMetrics newGameMetrics;
+        newGameMetrics.frameTimingMs.resize(TIME_BUCKETS_SIZE, 0);
+        newGameMetrics.frameTimingDeltaMs.resize(TIME_BUCKETS_SIZE, 0);
+        gameFrameMetrics = newGameMetrics;
+    }
+
+    gameFrameMetrics.value().totalFrameTimeMs += newFrameMetrics.totalFrameTimeMs;
+    gameFrameMetrics.value().numOfFrames += newFrameMetrics.numOfFrames;
+    totalFrameNumber += newFrameMetrics.numOfFrames;
+
+    for (const auto &frameDur : newFrameMetrics.frameTimingMs) {
+        if (frameDur >= TIME_BUCKETS_SIZE) {
+            gameFrameMetrics.value().frameTimingMs[TIME_BUCKETS_SIZE - 1]++;
+            // Because we're going to use the total time to compute the total average
+            // FPS, limiting the maximum value of the outlier's frame duration here.
+            // Deducting the parts that's over the maximum value "TIME_BUCKETS_SIZE"
+            // which has been added above.
+            gameFrameMetrics.value().totalFrameTimeMs -= frameDur - TIME_BUCKETS_SIZE;
+        } else if (frameDur >= 0) {
+            gameFrameMetrics.value().frameTimingMs[frameDur]++;
+        }
+    }
+
+    for (const auto &frameDurDelta : newFrameMetrics.frameTimingDeltaMs) {
+        if (frameDurDelta >= TIME_BUCKETS_SIZE) {
+            gameFrameMetrics.value().frameTimingDeltaMs[TIME_BUCKETS_SIZE - 1]++;
+        } else if (frameDurDelta >= 0) {
+            gameFrameMetrics.value().frameTimingDeltaMs[frameDurDelta]++;
+        }
+    }
+}
+
+void SessionMetrics::addNewFrames(const FrameBuckets &newFrameMetrics) {
+    if (!appFrameMetrics) {
+        appFrameMetrics = newFrameMetrics;
+        totalFrameNumber += newFrameMetrics.totalNumOfFrames;
+        return;
+    }
+
+    appFrameMetrics.value().addUpNewFrames(newFrameMetrics);
+    totalFrameNumber += newFrameMetrics.totalNumOfFrames;
+}
+
+std::ostream &SessionMetrics::dump(std::ostream &os) const {
+    os << "Session uid: " << std::to_string(uid.value_or(-1)) << ", ";
+    os << "Scenario: " << toString(scenarioType) << ", ";
+    os << "FrameTimelineType: " << toString(frameTimelineType) << ", ";
+    os << "Thermal throttling status: " << ::android::internal::ToString(thermalThrotStat) << "\n";
+
+    std::time_t startTime = std::chrono::system_clock::to_time_t(metricStartTime);
+    os << "    Start time: " << std::ctime(&startTime);
+
+    if (metricSessionCompleted) {
+        std::time_t endTime = std::chrono::system_clock::to_time_t(metricEndTime);
+        os << "    End time: " << std::ctime(&endTime);
+    }
+
+    if (appFrameMetrics) {
+        os << "    ";
+        os << appFrameMetrics.value().toString();
+        os << "\n";
+    }
+
+    if (gameFrameMetrics) {
+        os << "    frameTimingHistogram: [";
+        bool notEmpty = false;
+        for (int i = 0; i < TIME_BUCKETS_SIZE; i++) {
+            if (gameFrameMetrics.value().frameTimingMs[i] > 0) {
+                if (notEmpty)
+                    os << ", ";
+                os << i << ":" << gameFrameMetrics.value().frameTimingMs[i];
+                notEmpty = true;
+            }
+        }
+        os << "]\n";
+        os << "    frameTimingDeltaHistogram: [";
+        notEmpty = false;
+        for (int i = 0; i < TIME_BUCKETS_SIZE; i++) {
+            if (gameFrameMetrics.value().frameTimingDeltaMs[i] > 0) {
+                if (notEmpty)
+                    os << ", ";
+                os << i << ":" << gameFrameMetrics.value().frameTimingDeltaMs[i];
+                notEmpty = true;
+            }
+        }
+        os << "]\n";
+        auto avgFPS = gameFrameMetrics.value().totalFrameTimeMs > 0
+                              ? gameFrameMetrics.value().numOfFrames * 1000.0 /
+                                        gameFrameMetrics.value().totalFrameTimeMs
+                              : -1;
+        os << "    Average FPS: " << avgFPS << "\n";
+        os << "    Total number of frames: " << gameFrameMetrics.value().numOfFrames << "\n";
+    }
+    return os;
+}
+
+}  // namespace pixel
+}  // namespace impl
+}  // namespace power
+}  // namespace hardware
+}  // namespace google
+}  // namespace aidl
diff --git a/power-libperfmgr/aidl/SessionMetrics.h b/power-libperfmgr/aidl/SessionMetrics.h
index ad13b4ef..9e172e24 100644
--- a/power-libperfmgr/aidl/SessionMetrics.h
+++ b/power-libperfmgr/aidl/SessionMetrics.h
@@ -16,6 +16,12 @@
 
 #pragma once
 
+#include <aidl/android/hardware/thermal/IThermal.h>
+
+#include <chrono>
+#include <ctime>
+#include <iostream>
+
 namespace aidl {
 namespace google {
 namespace hardware {
@@ -23,10 +29,12 @@ namespace power {
 namespace impl {
 namespace pixel {
 
+using ::aidl::android::hardware::thermal::ThrottlingSeverity;
+
 /**
- * Put jank frames into buckets. The "jank" evaluation is reusing the session records jank
- * evaluation logic while here only counts the frames over 17ms. Though the current jank
- * evaluation is not exactly right for every frame at the moment, it can still provide a
+ * Put non-game "APP" jank frames into buckets. The "jank" evaluation is reusing the session
+ * records jank evaluation logic while here only counts the frames over 17ms. Though the current
+ * jank evaluation is not exactly right for every frame at the moment, it can still provide a
  * a good sense of session's jank status. When we have more precise timeline from platform side
  * the jank evaluation logic could be updated.
  */
@@ -80,6 +88,23 @@ struct FrameBuckets {
     }
 };
 
+struct GameFrameMetrics {
+    // Histogram for frame time distribution for computing FPS distribution
+    std::vector<uint32_t> frameTimingMs;
+    // Histogram for frame time deltas for identifying jitters distribution
+    std::vector<uint32_t> frameTimingDeltaMs;
+    // Total time of all frames to compute the total average FPS
+    uint64_t totalFrameTimeMs{0};
+    uint32_t numOfFrames{0};
+};
+
+struct FrameTimingMetrics {
+    // Non-game APP jank frames in buckets
+    FrameBuckets framesInBuckets;
+    // Game frame timing info.
+    GameFrameMetrics gameFrameMetrics;
+};
+
 enum class ScenarioType : int32_t { DEFAULT = 0, GAME };
 
 constexpr const char *toString(ScenarioType scenType) {
@@ -106,11 +131,35 @@ constexpr const char *toString(FrameTimelineType timelineType) {
     }
 }
 
-struct SessionJankStatsWithThermal {
+/**
+ * Session's frame statistics that be used to construct the Pixel perf atoms and be uploaded
+ * to the server.
+ */
+struct SessionMetrics {
+  public:
+    // App uid when available
     std::optional<int32_t> uid;
-    ScenarioType scenarioType;
-    FrameTimelineType frameTimelineType;
-    // TODO(guibing) add more detailed definition of the jank metrics.
+    // Device scenario when collecting the metric, e.g. Game/Android Auto
+    ScenarioType scenarioType{ScenarioType::DEFAULT};
+    // Source of the frame timeline. Mostly of them comes from app itself,
+    // while game metric session currently uses the SF's frame timeline.
+    FrameTimelineType frameTimelineType{FrameTimelineType::APP};
+    // Metric session start and end time
+    std::chrono::time_point<std::chrono::system_clock> metricStartTime;
+    std::chrono::time_point<std::chrono::system_clock> metricEndTime;
+    bool metricSessionCompleted{false};
+    // Thermal throttling status
+    ThrottlingSeverity thermalThrotStat{ThrottlingSeverity::NONE};
+    uint32_t totalFrameNumber{0};
+    // Performance metrics for game and non-game APP.
+    std::optional<FrameBuckets> appFrameMetrics;
+    std::optional<GameFrameMetrics> gameFrameMetrics;
+
+    void addNewFrames(const GameFrameMetrics &newFrameMetrics);
+    void addNewFrames(const FrameBuckets &newFrameMetrics);
+    void resetMetric(ThrottlingSeverity newThermalState,
+                     ScenarioType newScenario = ScenarioType::DEFAULT);
+    std::ostream &dump(std::ostream &os) const;
 };
 
 }  // namespace pixel
diff --git a/power-libperfmgr/aidl/SessionRecords.cpp b/power-libperfmgr/aidl/SessionRecords.cpp
index f1664969..596c70d5 100644
--- a/power-libperfmgr/aidl/SessionRecords.cpp
+++ b/power-libperfmgr/aidl/SessionRecords.cpp
@@ -36,8 +36,8 @@ SessionRecords::SessionRecords(const int32_t maxNumOfRecords, const double jankC
 
 void SessionRecords::addReportedDurations(const std::vector<WorkDuration> &actualDurationsNs,
                                           int64_t targetDurationNs,
-                                          FrameBuckets &newFramesInBuckets,
-                                          bool computeFPSJitters) {
+                                          FrameTimingMetrics &newFrameMetrics,
+                                          bool computeGameMetrics) {
     for (auto &duration : actualDurationsNs) {
         int32_t totalDurationUs = duration.durationNanos / 1000;
 
@@ -67,6 +67,7 @@ void SessionRecords::addReportedDurations(const std::vector<WorkDuration> &actua
             }
         }
 
+        mPreLastRecordIndex = mLatestRecordIndex;
         mLatestRecordIndex = (mLatestRecordIndex + 1) % kMaxNumOfRecords;
 
         // Track start delay
@@ -81,7 +82,7 @@ void SessionRecords::addReportedDurations(const std::vector<WorkDuration> &actua
         // A frame is evaluated as FPS jitter if its startInterval is not less
         // than previous three frames' average startIntervals.
         bool FPSJitter = false;
-        if (computeFPSJitters) {
+        if (computeGameMetrics) {
             if (mAddedFramesForFPSCheck < kTotalFramesForFPSCheck) {
                 if (startIntervalUs > 0) {
                     mLatestStartIntervalSumUs += startIntervalUs;
@@ -111,10 +112,17 @@ void SessionRecords::addReportedDurations(const std::vector<WorkDuration> &actua
         if (cycleMissed) {
             mNumOfMissedCycles++;
         }
-        updateFrameBuckets(totalDurationUs, cycleMissed, newFramesInBuckets);
+        updateFrameBuckets(totalDurationUs, cycleMissed, newFrameMetrics.framesInBuckets);
+        if (computeGameMetrics) {
+            /**
+             * Currently SF frame intervals under "game mode" are used to track the game's FPS.
+             * If the Android platform can pass the timestamps of Game's major layers, that would
+             * be more precise in the long term.
+             */
+            updateGameMetrics(startIntervalUs, newFrameMetrics.gameFrameMetrics);
+        }
 
-        // Pop out the indexes that their related values are not greater than the
-        // latest one.
+        // Pop out the indexes that their related values are not greater than the latest one.
         while (!mRecordsIndQueue.empty() &&
                (mRecords[mRecordsIndQueue.back()].totalDurationUs <= totalDurationUs)) {
             mRecordsIndQueue.pop_back();
@@ -202,6 +210,21 @@ void SessionRecords::updateFrameBuckets(int32_t frameDurationUs, bool isJankFram
     }
 }
 
+void SessionRecords::updateGameMetrics(int32_t frameIntervalUs, GameFrameMetrics &gameMetrics) {
+    if (frameIntervalUs <= 0) {
+        return;
+    }
+    auto frameIntervalMs = frameIntervalUs / 1000;
+    gameMetrics.frameTimingMs.push_back(frameIntervalMs);
+
+    if (mNumOfFrames > 2) {
+        gameMetrics.frameTimingDeltaMs.push_back(
+                std::abs(frameIntervalUs - mRecords[mPreLastRecordIndex].startIntervalUs) / 1000);
+    }
+    gameMetrics.totalFrameTimeMs += frameIntervalMs;
+    gameMetrics.numOfFrames++;
+}
+
 }  // namespace pixel
 }  // namespace impl
 }  // namespace power
diff --git a/power-libperfmgr/aidl/SessionRecords.h b/power-libperfmgr/aidl/SessionRecords.h
index 5b1fb746..0f2a49a0 100644
--- a/power-libperfmgr/aidl/SessionRecords.h
+++ b/power-libperfmgr/aidl/SessionRecords.h
@@ -46,15 +46,15 @@ class SessionRecords {
     ~SessionRecords() = default;
 
     void addReportedDurations(const std::vector<WorkDuration> &actualDurationsNs,
-                              int64_t targetDurationNs, FrameBuckets &newFramesInBuckets,
-                              bool computeFPSJitters = false);
+                              int64_t targetDurationNs, FrameTimingMetrics &newFrameMetrics,
+                              bool computeGameMetrics = false);
     std::optional<int32_t> getMaxDuration();
     std::optional<int32_t> getAvgDuration();
     int32_t getNumOfRecords();
     int32_t getNumOfMissedCycles();
     bool isLowFrameRate(int32_t fpsLowRateThreshold);
     void resetRecords();
-    // It will only return valid value when the computeFPSJitters is enabled while
+    // It will only return valid value when the computeGameMetrics is enabled while
     // calling addReportedDurations. It's mainly for game mode FPS monitoring.
     int32_t getLatestFPS() const;
     int32_t getNumOfFPSJitters() const;
@@ -62,6 +62,7 @@ class SessionRecords {
   private:
     void updateFrameBuckets(int32_t frameDurationUs, bool isJankFrame,
                             FrameBuckets &framesInBuckets);
+    void updateGameMetrics(int32_t frameIntervalUs, GameFrameMetrics &gameMetrics);
 
     const int32_t kMaxNumOfRecords;
     const double kJankCheckTimeFactor;
@@ -72,6 +73,7 @@ class SessionRecords {
     int32_t mAvgDurationUs{0};
     int64_t mLastStartTimeNs{0};
     int32_t mLatestRecordIndex{-1};
+    int32_t mPreLastRecordIndex{-1};
     int32_t mNumOfMissedCycles{0};
     int32_t mNumOfFrames{0};
     int64_t mSumOfDurationsUs{0};
diff --git a/power-libperfmgr/aidl/SessionTaskMap.cpp b/power-libperfmgr/aidl/SessionTaskMap.cpp
index 95001dce..db4f12c3 100644
--- a/power-libperfmgr/aidl/SessionTaskMap.cpp
+++ b/power-libperfmgr/aidl/SessionTaskMap.cpp
@@ -150,6 +150,15 @@ bool SessionTaskMap::isAnyAppSessionActive(std::chrono::steady_clock::time_point
     return false;
 }
 
+bool SessionTaskMap::areAllSessionsTimeout(std::chrono::steady_clock::time_point timePoint) const {
+    for (auto &sessionVal : mSessions) {
+        if (!sessionVal.second.val->votes->allTimedOut(timePoint)) {
+            return false;
+        }
+    }
+    return true;
+}
+
 bool SessionTaskMap::remove(int64_t sessionId) {
     auto sessItr = mSessions.find(sessionId);
     if (sessItr == mSessions.end()) {
diff --git a/power-libperfmgr/aidl/SessionTaskMap.h b/power-libperfmgr/aidl/SessionTaskMap.h
index 087a5c2b..a26e76b8 100644
--- a/power-libperfmgr/aidl/SessionTaskMap.h
+++ b/power-libperfmgr/aidl/SessionTaskMap.h
@@ -71,6 +71,9 @@ class SessionTaskMap {
     // Return true if any app session is active, false otherwise
     bool isAnyAppSessionActive(std::chrono::steady_clock::time_point timePoint) const;
 
+    // Return true if all sessions are timeout, false otherwise
+    bool areAllSessionsTimeout(std::chrono::steady_clock::time_point timePoint) const;
+
     // Remove a session based on session id
     bool remove(int64_t sessionId);
 
diff --git a/power-libperfmgr/aidl/SessionValueEntry.cpp b/power-libperfmgr/aidl/SessionValueEntry.cpp
index 4e2649f9..611c792b 100644
--- a/power-libperfmgr/aidl/SessionValueEntry.cpp
+++ b/power-libperfmgr/aidl/SessionValueEntry.cpp
@@ -37,6 +37,7 @@ std::ostream &SessionValueEntry::dump(std::ostream &os) const {
         os << ", votes nullptr";
     }
     os << ", " << isActive;
+    os << ", " << votes->allTimedOut(timeNow);
     auto totalFrames = hBoostModeDist.lightModeFrames + hBoostModeDist.moderateModeFrames +
                        hBoostModeDist.severeModeFrames;
     os << ", HBoost:"
diff --git a/power-libperfmgr/aidl/SessionValueEntry.h b/power-libperfmgr/aidl/SessionValueEntry.h
index 1c449088..2fbeadea 100644
--- a/power-libperfmgr/aidl/SessionValueEntry.h
+++ b/power-libperfmgr/aidl/SessionValueEntry.h
@@ -58,6 +58,7 @@ struct SessionValueEntry {
     bool isPowerEfficient{false};
     HeurBoostStatistics hBoostModeDist;
     bool rampupBoostActive{false};
+    std::optional<SessionMetrics> sessFrameMetrics;
 
     // Write info about power session to ostream for logging and debugging
     std::ostream &dump(std::ostream &os) const;
diff --git a/power-libperfmgr/aidl/service.cpp b/power-libperfmgr/aidl/service.cpp
index 4fe410eb..b0b50fc1 100644
--- a/power-libperfmgr/aidl/service.cpp
+++ b/power-libperfmgr/aidl/service.cpp
@@ -21,6 +21,7 @@
 #include <android/binder_ibinder_platform.h>
 #include <android/binder_manager.h>
 #include <android/binder_process.h>
+#include <processgroup/processgroup.h>
 #include <perfmgr/HintManager.h>
 
 #include <thread>
@@ -28,7 +29,6 @@
 #include "MetricUploader.h"
 #include "Power.h"
 #include "PowerExt.h"
-#include "PowerSessionManager.h"
 #include "disp-power/DisplayLowPower.h"
 #include "utils/ThermalStateListener.h"
 
@@ -52,6 +52,11 @@ int main() {
 
     std::shared_ptr<DisplayLowPower> dlpw = std::make_shared<DisplayLowPower>();
 
+    // set task profile "PreferIdle" to lower scheduling latency.
+    if (!SetTaskProfiles(0, {"PreferIdleSet"})) {
+        LOG(WARNING) << "Device does not support 'PreferIdleSet' task profile.";
+    }
+
     // single thread
     ABinderProcess_setThreadPoolMaxThreadCount(0);
 
diff --git a/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp b/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp
index a976a494..cb8d53cf 100644
--- a/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp
+++ b/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp
@@ -16,6 +16,7 @@
 
 #include <aidl/android/hardware/power/SessionTag.h>
 #include <android-base/file.h>
+#include <android-base/parseint.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 #include <sys/syscall.h>
@@ -167,11 +168,16 @@ class PowerHintSessionTest : public ::testing::Test {
             thread_vendor_attrs.push_back(attr);
         }
 
-        const int32_t tag_word_pos = 10;  // The adpf attribute position in dump log.
+        const int32_t tag_word_pos = 9;  // The user QOS attributes position in dump log.
         if (thread_vendor_attrs.size() < tag_word_pos + 1) {
             return false;
         }
-        *isActive = thread_vendor_attrs[tag_word_pos] == "1";
+        const int32_t adpf_bit_pos = 4;  // ADPF bit position in the user QOS variable.
+        int32_t vendor_qos_val;
+        if (!::android::base::ParseInt(thread_vendor_attrs[tag_word_pos], &vendor_qos_val)) {
+            return false;
+        }
+        *isActive = vendor_qos_val & (0x1 << adpf_bit_pos);
         return true;
     }
 };
@@ -364,6 +370,65 @@ TEST_F(PowerHintSessionMockedTest, updateSessionJankState) {
               mHintSession->updateSessionJankState(SessionJankyLevel::LIGHT, 9, 5.0, false));
 }
 
+using TestingPowerHintSessionHintMocked =
+        PowerHintSession<testing::NiceMock<mock::pixel::MockHintManager>,
+                         PowerSessionManager<testing::NiceMock<mock::pixel::MockHintManager>>>;
+
+enum class HintSendRequirement { SEND_HINT, DONT_SEND_HINT };
+struct SessionGPULoadUpHintParam {
+    SessionTag tag;
+    HintSendRequirement shouldSendHint;
+};
+
+static inline NiceMock<mock::pixel::MockHintManager> *primeHintManager(
+        std::shared_ptr<::android::perfmgr::AdpfConfig> const &config) {
+    auto mockHintManager = NiceMock<mock::pixel::MockHintManager>::GetInstance();
+    ON_CALL(*mockHintManager, GetAdpfProfile()).WillByDefault(Return(config));
+    ON_CALL(*mockHintManager, IsHintSupported("EXPENSIVE_RENDERING")).WillByDefault(Return(true));
+    return mockHintManager;
+}
+
+struct PowerHintSessionGpuLoadUpTest : TestWithParam<SessionGPULoadUpHintParam> {
+    PowerHintSessionGpuLoadUpTest() noexcept
+        : mTestConfig(std::make_shared<::android::perfmgr::AdpfConfig>(makeMockConfig())),
+          mMockHintManager(primeHintManager(mTestConfig)),
+          mHintSession(ndk::SharedRefBase::make<TestingPowerHintSessionHintMocked>(
+                  mTgid, mUid, std::vector<int>{mTid}, 1, GetParam().tag)) {}
+
+    ~PowerHintSessionGpuLoadUpTest() noexcept {
+        Mock::VerifyAndClearExpectations(mMockHintManager);
+    }
+
+  protected:
+    std::shared_ptr<::android::perfmgr::AdpfConfig> const mTestConfig;
+    NiceMock<mock::pixel::MockHintManager> *mMockHintManager;
+    std::shared_ptr<TestingPowerHintSessionHintMocked> mHintSession;
+
+    static constexpr int mTgid = 10000;
+    static constexpr int mUid = 1001;
+    static constexpr int mTid = 10000;
+};
+
+TEST_P(PowerHintSessionGpuLoadUpTest, sessionGPULoadUpHint) {
+    if (GetParam().shouldSendHint == HintSendRequirement::DONT_SEND_HINT) {
+        EXPECT_CALL(*mMockHintManager, DoHint(_)).Times(0);
+        EXPECT_CALL(*mMockHintManager, DoHint(_, _)).Times(0);
+    } else {
+        EXPECT_CALL(*mMockHintManager, DoHint("EXPENSIVE_RENDERING", Gt(1ms)))
+                .Times(1)
+                .WillOnce(Return(true));
+    }
+    EXPECT_TRUE(mHintSession->sendHint(SessionHint::GPU_LOAD_UP).isOk());
+}
+
+INSTANTIATE_TEST_SUITE_P(
+        GpuLoadUpTest, PowerHintSessionGpuLoadUpTest,
+        testing::Values(
+                SessionGPULoadUpHintParam{SessionTag::OTHER, HintSendRequirement::DONT_SEND_HINT},
+                SessionGPULoadUpHintParam{SessionTag::SYSUI, HintSendRequirement::SEND_HINT},
+                SessionGPULoadUpHintParam{SessionTag::SURFACEFLINGER,
+                                          HintSendRequirement::SEND_HINT}));
+
 }  // namespace pixel
 }  // namespace impl
 }  // namespace power
diff --git a/power-libperfmgr/aidl/tests/SessionRecordsTest.cpp b/power-libperfmgr/aidl/tests/SessionRecordsTest.cpp
index 4c7666e9..b9885570 100644
--- a/power-libperfmgr/aidl/tests/SessionRecordsTest.cpp
+++ b/power-libperfmgr/aidl/tests/SessionRecordsTest.cpp
@@ -67,7 +67,7 @@ TEST_F(SessionRecordsTest, NoRecords) {
 }
 
 TEST_F(SessionRecordsTest, addReportedDurations) {
-    FrameBuckets buckets;
+    FrameTimingMetrics buckets;
     mRecords->addReportedDurations(fakeWorkDurations({3, 4, 3, 2}), MS_TO_NS(3), buckets);
     ASSERT_EQ(4, mRecords->getNumOfRecords());
     ASSERT_EQ(MS_TO_US(4), mRecords->getMaxDuration().value());
@@ -91,7 +91,7 @@ TEST_F(SessionRecordsTest, addReportedDurations) {
 }
 
 TEST_F(SessionRecordsTest, checkLowFrameRate) {
-    FrameBuckets buckets;
+    FrameTimingMetrics buckets;
     ASSERT_FALSE(mRecords->isLowFrameRate(25));
     mRecords->addReportedDurations(fakeWorkDurations({{0, 8}, {10, 9}, {20, 8}, {30, 8}}),
                                    MS_TO_NS(10), buckets);
@@ -112,7 +112,7 @@ TEST_F(SessionRecordsTest, checkLowFrameRate) {
 }
 
 TEST_F(SessionRecordsTest, switchTargetDuration) {
-    FrameBuckets buckets;
+    FrameTimingMetrics buckets;
     ASSERT_FALSE(mRecords->isLowFrameRate(25));
     mRecords->addReportedDurations(fakeWorkDurations({{0, 8}, {10, 9}, {20, 19}, {40, 8}}),
                                    MS_TO_NS(10), buckets);
@@ -138,7 +138,7 @@ TEST_F(SessionRecordsTest, switchTargetDuration) {
 }
 
 TEST_F(SessionRecordsTest, checkFPSJitters) {
-    FrameBuckets buckets;
+    FrameTimingMetrics buckets;
     ASSERT_EQ(0, mRecords->getNumOfFPSJitters());
     mRecords->addReportedDurations(fakeWorkDurations({{0, 8}, {10, 9}, {20, 8}, {30, 8}}),
                                    MS_TO_NS(10), buckets, true);
@@ -171,33 +171,94 @@ TEST_F(SessionRecordsTest, checkFPSJitters) {
 }
 
 TEST_F(SessionRecordsTest, updateFrameBuckets) {
-    FrameBuckets buckets;
+    FrameTimingMetrics timingInfo;
 
     mRecords->addReportedDurations(fakeWorkDurations({10, 11, 16, 17, 26, 40}), MS_TO_NS(10),
-                                   buckets);
-    ASSERT_EQ(6, buckets.totalNumOfFrames);
-    ASSERT_EQ(1, buckets.numOfFrames17to25ms);
-    ASSERT_EQ(1, buckets.numOfFrames25to34ms);
-    ASSERT_EQ(1, buckets.numOfFrames34to67ms);
-    ASSERT_EQ(0, buckets.numOfFrames67to100ms);
-    ASSERT_EQ(0, buckets.numOfFramesOver100ms);
-
-    mRecords->addReportedDurations(fakeWorkDurations({80, 100}), MS_TO_NS(10), buckets);
-    ASSERT_EQ(8, buckets.totalNumOfFrames);
-    ASSERT_EQ(1, buckets.numOfFrames17to25ms);
-    ASSERT_EQ(1, buckets.numOfFrames25to34ms);
-    ASSERT_EQ(1, buckets.numOfFrames34to67ms);
-    ASSERT_EQ(1, buckets.numOfFrames67to100ms);
-    ASSERT_EQ(1, buckets.numOfFramesOver100ms);
+                                   timingInfo);
+    ASSERT_EQ(6, timingInfo.framesInBuckets.totalNumOfFrames);
+    ASSERT_EQ(1, timingInfo.framesInBuckets.numOfFrames17to25ms);
+    ASSERT_EQ(1, timingInfo.framesInBuckets.numOfFrames25to34ms);
+    ASSERT_EQ(1, timingInfo.framesInBuckets.numOfFrames34to67ms);
+    ASSERT_EQ(0, timingInfo.framesInBuckets.numOfFrames67to100ms);
+    ASSERT_EQ(0, timingInfo.framesInBuckets.numOfFramesOver100ms);
+
+    mRecords->addReportedDurations(fakeWorkDurations({80, 100}), MS_TO_NS(10), timingInfo);
+    ASSERT_EQ(8, timingInfo.framesInBuckets.totalNumOfFrames);
+    ASSERT_EQ(1, timingInfo.framesInBuckets.numOfFrames17to25ms);
+    ASSERT_EQ(1, timingInfo.framesInBuckets.numOfFrames25to34ms);
+    ASSERT_EQ(1, timingInfo.framesInBuckets.numOfFrames34to67ms);
+    ASSERT_EQ(1, timingInfo.framesInBuckets.numOfFrames67to100ms);
+    ASSERT_EQ(1, timingInfo.framesInBuckets.numOfFramesOver100ms);
 
     FrameBuckets newBuckets{2, 1, 1, 1, 1, 0};
-    buckets.addUpNewFrames(newBuckets);
-    ASSERT_EQ(10, buckets.totalNumOfFrames);
-    ASSERT_EQ(2, buckets.numOfFrames17to25ms);
-    ASSERT_EQ(2, buckets.numOfFrames25to34ms);
-    ASSERT_EQ(2, buckets.numOfFrames34to67ms);
-    ASSERT_EQ(2, buckets.numOfFrames67to100ms);
-    ASSERT_EQ(1, buckets.numOfFramesOver100ms);
+    timingInfo.framesInBuckets.addUpNewFrames(newBuckets);
+    ASSERT_EQ(10, timingInfo.framesInBuckets.totalNumOfFrames);
+    ASSERT_EQ(2, timingInfo.framesInBuckets.numOfFrames17to25ms);
+    ASSERT_EQ(2, timingInfo.framesInBuckets.numOfFrames25to34ms);
+    ASSERT_EQ(2, timingInfo.framesInBuckets.numOfFrames34to67ms);
+    ASSERT_EQ(2, timingInfo.framesInBuckets.numOfFrames67to100ms);
+    ASSERT_EQ(1, timingInfo.framesInBuckets.numOfFramesOver100ms);
+
+    SessionMetrics sessMetric;
+    sessMetric.addNewFrames(timingInfo.framesInBuckets);
+    ASSERT_EQ(10, sessMetric.appFrameMetrics.value().totalNumOfFrames);
+    ASSERT_EQ(10, sessMetric.totalFrameNumber);
+    ASSERT_EQ(2, sessMetric.appFrameMetrics.value().numOfFrames17to25ms);
+    ASSERT_EQ(2, sessMetric.appFrameMetrics.value().numOfFrames25to34ms);
+    ASSERT_EQ(2, sessMetric.appFrameMetrics.value().numOfFrames34to67ms);
+    ASSERT_EQ(2, sessMetric.appFrameMetrics.value().numOfFrames67to100ms);
+    ASSERT_EQ(1, sessMetric.appFrameMetrics.value().numOfFramesOver100ms);
+}
+
+TEST_F(SessionRecordsTest, updateGameMetrics) {
+    FrameTimingMetrics frameMetrics;
+    mRecords->addReportedDurations(fakeWorkDurations({{8, 8}, {19, 9}, {28, 8}, {38, 8}}),
+                                   MS_TO_NS(10), frameMetrics, true);
+    std::vector<uint32_t> expectedFrameMs = {10, 10, 10};
+    std::vector<uint32_t> expectedDeltaMs = {0, 0};
+    ASSERT_EQ(expectedDeltaMs, frameMetrics.gameFrameMetrics.frameTimingDeltaMs);
+    ASSERT_EQ(expectedFrameMs, frameMetrics.gameFrameMetrics.frameTimingMs);
+    ASSERT_EQ(30, frameMetrics.gameFrameMetrics.totalFrameTimeMs);
+    ASSERT_EQ(3, frameMetrics.gameFrameMetrics.numOfFrames);
+
+    mRecords->addReportedDurations(fakeWorkDurations({{158, 118}, {169, 9}}), MS_TO_NS(10),
+                                   frameMetrics, true);
+    expectedFrameMs = {10, 10, 10, 10, 120};
+    expectedDeltaMs = {0, 0, 0, 110};
+    ASSERT_EQ(expectedDeltaMs, frameMetrics.gameFrameMetrics.frameTimingDeltaMs);
+    ASSERT_EQ(expectedFrameMs, frameMetrics.gameFrameMetrics.frameTimingMs);
+    ASSERT_EQ(160, frameMetrics.gameFrameMetrics.totalFrameTimeMs);
+    ASSERT_EQ(5, frameMetrics.gameFrameMetrics.numOfFrames);
+
+    mRecords->addReportedDurations(fakeWorkDurations({{179, 9}, {189, 9}}), MS_TO_NS(10),
+                                   frameMetrics, false);
+    expectedFrameMs = {10, 10, 10, 10, 120};
+    expectedDeltaMs = {0, 0, 0, 110};
+    ASSERT_EQ(expectedDeltaMs, frameMetrics.gameFrameMetrics.frameTimingDeltaMs);
+    ASSERT_EQ(expectedFrameMs, frameMetrics.gameFrameMetrics.frameTimingMs);
+    ASSERT_EQ(160, frameMetrics.gameFrameMetrics.totalFrameTimeMs);
+    ASSERT_EQ(5, frameMetrics.gameFrameMetrics.numOfFrames);
+
+    SessionMetrics sessMetric;
+    sessMetric.addNewFrames(frameMetrics.gameFrameMetrics);
+    auto lastIndex = sessMetric.gameFrameMetrics.value().frameTimingMs.size() - 1;
+    ASSERT_EQ(4, sessMetric.gameFrameMetrics.value().frameTimingMs[10]);
+    ASSERT_EQ(1, sessMetric.gameFrameMetrics.value().frameTimingMs[lastIndex]);
+    ASSERT_EQ(3, sessMetric.gameFrameMetrics.value().frameTimingDeltaMs[0]);
+    ASSERT_EQ(1, sessMetric.gameFrameMetrics.value().frameTimingDeltaMs[lastIndex]);
+    // Each frame's duration is capped to the metric bucket size, which is 100 (ms).
+    ASSERT_EQ(140, sessMetric.gameFrameMetrics.value().totalFrameTimeMs);
+    ASSERT_EQ(5, sessMetric.gameFrameMetrics.value().numOfFrames);
+
+    GameFrameMetrics newFrames{{10, 1000}, {5, 990}, 1010, 2};
+    sessMetric.addNewFrames(newFrames);
+    ASSERT_EQ(5, sessMetric.gameFrameMetrics.value().frameTimingMs[10]);
+    ASSERT_EQ(2, sessMetric.gameFrameMetrics.value().frameTimingMs[lastIndex]);
+    ASSERT_EQ(3, sessMetric.gameFrameMetrics.value().frameTimingDeltaMs[0]);
+    ASSERT_EQ(1, sessMetric.gameFrameMetrics.value().frameTimingDeltaMs[5]);
+    ASSERT_EQ(2, sessMetric.gameFrameMetrics.value().frameTimingDeltaMs[lastIndex]);
+    ASSERT_EQ(250, sessMetric.gameFrameMetrics.value().totalFrameTimeMs);
+    ASSERT_EQ(7, sessMetric.gameFrameMetrics.value().numOfFrames);
 }
 
 }  // namespace pixel
diff --git a/power-libperfmgr/aidl/tests/mocks/MockHintManager.h b/power-libperfmgr/aidl/tests/mocks/MockHintManager.h
index 0427c547..3d9c17ac 100644
--- a/power-libperfmgr/aidl/tests/mocks/MockHintManager.h
+++ b/power-libperfmgr/aidl/tests/mocks/MockHintManager.h
@@ -45,6 +45,7 @@ class MockHintManager {
     MOCK_METHOD(bool, SetAdpfProfileFromDoHint, (const std::string &profile_name), ());
     MOCK_METHOD(std::shared_ptr<::android::perfmgr::AdpfConfig>, GetAdpfProfileFromDoHint, (),
                 (const));
+    MOCK_METHOD(::android::perfmgr::OtherConfigs, GetOtherConfigs, (), (const));
 
     static testing::NiceMock<MockHintManager> *GetInstance() {
         static testing::NiceMock<MockHintManager> instance{};
diff --git a/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h b/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
index 7b19c1ec..b5c7e7b4 100644
--- a/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
+++ b/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
@@ -37,7 +37,7 @@ class MockPowerSessionManager {
                 (const std::string &idString,
                  const std::shared_ptr<impl::pixel::AppHintDesc> &sessionDescriptor,
                  const std::shared_ptr<impl::pixel::AppDescriptorTrace> &sessionTrace,
-                 const std::vector<int32_t> &threadIds),
+                 const bool enableMetricCollection, const std::vector<int32_t> &threadIds),
                 ());
     MOCK_METHOD(void, removePowerSession, (int64_t sessionId), ());
     MOCK_METHOD(void, setThreadsFromPowerSession,
@@ -73,12 +73,14 @@ class MockPowerSessionManager {
                 ());
     MOCK_METHOD(bool, getGameModeEnableState, (), ());
     MOCK_METHOD(bool, hasValidTaskRampupMultNode, (), ());
-    MOCK_METHOD(void, updateFrameBuckets,
-                (int64_t sessionId, const impl::pixel::FrameBuckets &lastReportedFrames), ());
+    MOCK_METHOD(void, updateFrameMetrics,
+                (int64_t sessionId, const impl::pixel::FrameTimingMetrics &lastReportedFrames), ());
     MOCK_METHOD(void, updateRampupBoostMode,
                 (int64_t sessionId, impl::pixel::SessionJankyLevel jankyLevel,
                  int32_t defaultRampupVal, int32_t highRampupVal),
                 ());
+    MOCK_METHOD(void, updateCollectedSessionMetrics, (int64_t sessionId), ());
+    MOCK_METHOD(bool, areAllSessionsTimeout, (), ());
 
     static testing::NiceMock<MockPowerSessionManager> *getInstance() {
         static testing::NiceMock<MockPowerSessionManager> instance{};
diff --git a/power-libperfmgr/aidl/utils/TgidTypeChecker.cpp b/power-libperfmgr/aidl/utils/TgidTypeChecker.cpp
new file mode 100644
index 00000000..0ec77776
--- /dev/null
+++ b/power-libperfmgr/aidl/utils/TgidTypeChecker.cpp
@@ -0,0 +1,82 @@
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
+#define LOG_TAG "powerhal-libperfmgr"
+#include "TgidTypeChecker.h"
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+
+namespace aidl {
+namespace google {
+namespace hardware {
+namespace power {
+namespace impl {
+namespace pixel {
+
+static constexpr char typeCheckNodePath[] = "/proc/vendor_sched/check_tgid_type";
+
+TgidTypeChecker::TgidTypeChecker() {
+    if (access(typeCheckNodePath, W_OK) != 0) {
+        mTypeCheckerFd = -1;
+        LOG(WARNING) << "Can't find vendor node: " << typeCheckNodePath;
+        return;
+    }
+
+    int flags = O_WRONLY | O_TRUNC | O_CLOEXEC;
+    mTypeCheckerFd = TEMP_FAILURE_RETRY(open(typeCheckNodePath, flags));
+    if (mTypeCheckerFd < 0) {
+        LOG(ERROR) << "Failed to open the node: " << mTypeCheckerFd;
+    }
+}
+
+TgidTypeChecker::~TgidTypeChecker() {
+    if (mTypeCheckerFd >= 0) {
+        ::close(mTypeCheckerFd);
+    }
+}
+
+ProcessTag TgidTypeChecker::getProcessTag(int32_t tgid) {
+    std::lock_guard lock(mMutex);
+    if (mTypeCheckerFd < 0) {
+        LOG(WARNING) << "Invalid tigd type checker, skipping the check";
+        return ProcessTag::DEFAULT;
+    }
+
+    auto val = std::to_string(tgid);
+    int ret = TEMP_FAILURE_RETRY(write(mTypeCheckerFd, val.c_str(), val.length()));
+
+    switch (ret) {
+        case 1:
+            return ProcessTag::SYSTEM_UI;
+        case 2:
+            return ProcessTag::CHROME;
+        default:
+            return ProcessTag::DEFAULT;
+    }
+    return ProcessTag::DEFAULT;
+}
+
+bool TgidTypeChecker::isValid() const {
+    return mTypeCheckerFd >= 0;
+}
+
+}  // namespace pixel
+}  // namespace impl
+}  // namespace power
+}  // namespace hardware
+}  // namespace google
+}  // namespace aidl
diff --git a/power-libperfmgr/aidl/utils/TgidTypeChecker.h b/power-libperfmgr/aidl/utils/TgidTypeChecker.h
new file mode 100644
index 00000000..cfdacb73
--- /dev/null
+++ b/power-libperfmgr/aidl/utils/TgidTypeChecker.h
@@ -0,0 +1,61 @@
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
+#pragma once
+
+#include <fcntl.h>
+#include <unistd.h>
+
+#include <cstdint>
+#include <mutex>
+
+#include "../AdpfTypes.h"
+
+namespace aidl {
+namespace google {
+namespace hardware {
+namespace power {
+namespace impl {
+namespace pixel {
+
+class TgidTypeChecker {
+  public:
+    static std::shared_ptr<TgidTypeChecker> getInstance() {
+        static std::shared_ptr<TgidTypeChecker> instance(new TgidTypeChecker());
+        return instance;
+    }
+
+    ProcessTag getProcessTag(int32_t tgid);
+    bool isValid() const;
+
+    ~TgidTypeChecker();
+
+  private:
+    // singleton
+    TgidTypeChecker();
+    TgidTypeChecker(TgidTypeChecker const &) = delete;
+    TgidTypeChecker &operator=(TgidTypeChecker const &) = delete;
+
+    std::mutex mMutex;
+    int mTypeCheckerFd = -1;
+};
+
+}  // namespace pixel
+}  // namespace impl
+}  // namespace power
+}  // namespace hardware
+}  // namespace google
+}  // namespace aidl
diff --git a/power-libperfmgr/libperfmgr/Android.bp b/power-libperfmgr/libperfmgr/Android.bp
index 7059320e..b27e8ee0 100644
--- a/power-libperfmgr/libperfmgr/Android.bp
+++ b/power-libperfmgr/libperfmgr/Android.bp
@@ -24,6 +24,7 @@ cc_defaults {
     shared_libs: [
         "libbase",
         "libcutils",
+        "libprocessgroup",
         "libutils",
     ],
     static_libs: [
@@ -60,6 +61,7 @@ cc_library {
         "HintManager.cc",
         "AdpfConfig.cc",
         "EventNode.cc",
+        "JobQueueManager.cc",
     ],
 }
 
@@ -77,6 +79,7 @@ cc_test {
         "tests/NodeLooperThreadTest.cc",
         "tests/HintManagerTest.cc",
         "tests/EventNodeTest.cc",
+        "tests/JobQueueManagerTest.cc",
     ],
     test_suites: [
         "device-tests",
diff --git a/power-libperfmgr/libperfmgr/EventNode.cc b/power-libperfmgr/libperfmgr/EventNode.cc
index 2a2d2e39..3635e9e2 100644
--- a/power-libperfmgr/libperfmgr/EventNode.cc
+++ b/power-libperfmgr/libperfmgr/EventNode.cc
@@ -30,11 +30,11 @@ namespace android {
 namespace perfmgr {
 
 EventNode::EventNode(
-        std::string name, std::string node_path, std::vector<RequestGroup> req_sorted,
+        std::string name, std::vector<std::string> node_paths, std::vector<RequestGroup> req_sorted,
         std::size_t default_val_index, bool reset_on_init,
-        std::function<void(const std::string &, const std::string &, const std::string &)>
+        std::function<void(const std::string &, const std::vector<std::string> &, const std::string &)>
                 update_callback)
-    : Node(std::move(name), std::move(node_path), std::move(req_sorted), default_val_index,
+    : Node(std::move(name), std::move(node_paths), std::move(req_sorted), default_val_index,
            reset_on_init),
       update_callback_(update_callback) {}
 
@@ -59,7 +59,7 @@ std::chrono::milliseconds EventNode::Update(bool) {
                     GetName() + ":" + req_value + ":" + std::to_string(expire_time.count());
             ATRACE_BEGIN(tag.c_str());
         }
-        update_callback_(name_, node_path_, req_value);
+        update_callback_(name_, node_paths_, req_value);
         current_val_index_ = value_index;
         reset_on_init_ = false;
         if (ATRACE_ENABLED()) {
@@ -71,13 +71,12 @@ std::chrono::milliseconds EventNode::Update(bool) {
 
 void EventNode::DumpToFd(int fd) const {
     const std::string &node_value = req_sorted_[current_val_index_].GetRequestValue();
-    std::string buf(android::base::StringPrintf(
-            "Node Name\t"
-            "Event Path\t"
-            "Current Index\t"
-            "Current Value\n"
-            "%s\t%s\t%zu\t%s\n",
-            name_.c_str(), node_path_.c_str(), current_val_index_, node_value.c_str()));
+    std::string buf("Node Name\tEvent Path\tCurrent Index\tCurrent Value\n");
+
+    for (const auto &path : node_paths_) {
+        buf += android::base::StringPrintf("%s\t%s\t%zu\t%s\n", name_.c_str(), path.c_str(), current_val_index_, node_value.c_str());
+    }
+
     if (!android::base::WriteStringToFd(buf, fd)) {
         LOG(ERROR) << "Failed to dump fd: " << fd;
     }
diff --git a/power-libperfmgr/libperfmgr/FileNode.cc b/power-libperfmgr/libperfmgr/FileNode.cc
index 8ccacbcf..01ef9f3f 100644
--- a/power-libperfmgr/libperfmgr/FileNode.cc
+++ b/power-libperfmgr/libperfmgr/FileNode.cc
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 
+#include <cerrno>
 #define ATRACE_TAG (ATRACE_TAG_POWER | ATRACE_TAG_HAL)
 #define LOG_TAG "libperfmgr"
 
@@ -30,19 +31,21 @@
 namespace android {
 namespace perfmgr {
 
-FileNode::FileNode(std::string name, std::string node_path, std::vector<RequestGroup> req_sorted,
-                   std::size_t default_val_index, bool reset_on_init, bool truncate, bool hold_fd,
-                   bool write_only)
-    : Node(std::move(name), std::move(node_path), std::move(req_sorted), default_val_index,
+FileNode::FileNode(std::string name, std::vector<std::string> node_paths,
+                   std::vector<RequestGroup> req_sorted, std::size_t default_val_index,
+                   bool reset_on_init, bool truncate, bool allow_failure, bool hold_fd, bool write_only)
+    : Node(std::move(name), std::move(node_paths), std::move(req_sorted), default_val_index,
            reset_on_init),
       hold_fd_(hold_fd),
       truncate_(truncate),
       write_only_(write_only),
-      warn_timeout_(android::base::GetBoolProperty("ro.debuggable", false) ? 5ms : 50ms) {}
+      warn_timeout_(android::base::GetBoolProperty("ro.debuggable", false) ? 5ms : 50ms),
+      allow_failure_(allow_failure) {}
 
 std::chrono::milliseconds FileNode::Update(bool log_error) {
     std::size_t value_index = default_val_index_;
     std::chrono::milliseconds expire_time = std::chrono::milliseconds::max();
+    bool successfullyUpdated = true;
 
     // Find the highest outstanding request's expire time
     for (std::size_t i = 0; i < req_sorted_.size(); i++) {
@@ -56,54 +59,72 @@ std::chrono::milliseconds FileNode::Update(bool log_error) {
     if (value_index != current_val_index_ || reset_on_init_) {
         const std::string& req_value =
             req_sorted_[value_index].GetRequestValue();
+
         if (ATRACE_ENABLED()) {
             ATRACE_INT(("N:" + GetName()).c_str(), value_index);
             const std::string tag =
                     GetName() + ":" + req_value + ":" + std::to_string(expire_time.count());
             ATRACE_BEGIN(tag.c_str());
         }
-        android::base::Timer t;
+
         int flags = O_WRONLY | O_CLOEXEC;
+
         if (GetTruncate()) {
             flags |= O_TRUNC;
         }
-        fd_.reset(TEMP_FAILURE_RETRY(open(node_path_.c_str(), flags)));
 
-        if (fd_ == -1 || !android::base::WriteStringToFd(req_value, fd_)) {
-            if (log_error) {
-                LOG(WARNING) << "Failed to write to node: " << node_path_
-                             << " with value: " << req_value << ", fd: " << fd_;
-            }
-            // Retry in 500ms or sooner
-            expire_time = std::min(expire_time, std::chrono::milliseconds(500));
-        } else {
-            // For regular file system, we need fsync
-            fsync(fd_);
-            // Some dev node requires file to remain open during the entire hint
-            // duration e.g. /dev/cpu_dma_latency, so fd_ is intentionally kept
-            // open during any requested value other than default one. If
-            // request a default value, node will write the value and then
-            // release the fd.
-            if ((!hold_fd_) || value_index == default_val_index_) {
-                fd_.reset();
-            }
-            auto duration = t.duration();
-            if (duration > warn_timeout_) {
-                LOG(WARNING) << "Slow writing to file: '" << node_path_
-                             << "' with value: '" << req_value
-                             << "' took: " << duration.count() << " ms";
+        for (const auto &path : node_paths_) {
+            android::base::Timer t;
+
+            fd_.reset(TEMP_FAILURE_RETRY(open(path.c_str(), flags)));
+
+            if (fd_ == -1 || !android::base::WriteStringToFd(req_value, fd_)) {
+                if (!allow_failure_ || fd_ != -1 || errno != ENOENT) {
+                    if (log_error) {
+                        LOG(WARNING) << "Failed to write to node: " << path
+                                    << " with value: " << req_value << ", fd: " << fd_;
+                    }
+                    // Retry in 500ms or sooner
+                    expire_time = std::min(expire_time, std::chrono::milliseconds(500));
+                    successfullyUpdated = false;
+                }
+            } else {
+                // For regular file system, we need fsync
+                fsync(fd_);
+                // Some dev node requires file to remain open during the entire hint
+                // duration e.g. /dev/cpu_dma_latency, so fd_ is intentionally kept
+                // open during any requested value other than default one. If
+                // request a default value, node will write the value and then
+                // release the fd.
+                if ((!hold_fd_) || value_index == default_val_index_) {
+                    fd_.reset();
+                }
+                auto duration = t.duration();
+                if (duration > warn_timeout_) {
+                    LOG(WARNING) << "Slow writing to file: '" << path << "' with value: '"
+                                << req_value << "' took: " << duration.count() << " ms";
+                }
             }
+        }
+
+        if (successfullyUpdated){
             // Update current index only when succeed
             current_val_index_ = value_index;
             reset_on_init_ = false;
         }
+
         if (ATRACE_ENABLED()) {
             ATRACE_END();
         }
     }
+
     return expire_time;
 }
 
+bool FileNode::GetAllowFailure() const {
+    return allow_failure_;
+}
+
 bool FileNode::GetHoldFd() const {
     return hold_fd_;
 }
@@ -113,24 +134,22 @@ bool FileNode::GetTruncate() const {
 }
 
 void FileNode::DumpToFd(int fd) const {
-    std::string node_value;
-    if (!write_only_ && !android::base::ReadFileToString(node_path_, &node_value)) {
-        LOG(ERROR) << "Failed to read node path: " << node_path_;
+    std::string buf("Node Name\tNode Path\tCurrent Index\tCurrent Value\tHold FD\tTruncate\n");
+
+    for (const auto &path : node_paths_) {
+        std::string node_value;
+        if (!write_only_ && !android::base::ReadFileToString(path, &node_value)) {
+            LOG(ERROR) << "Failed to read node path: " << path;
+        }
+        node_value = android::base::Trim(node_value);
+        buf += android::base::StringPrintf("%s\t%s\t%zu\t%s\t%d\t%d\n", name_.c_str(), path.c_str(),
+                                           current_val_index_, node_value.c_str(), hold_fd_, truncate_);
     }
-    node_value = android::base::Trim(node_value);
-    std::string buf(
-            android::base::StringPrintf("Node Name\t"
-                                        "Node Path\t"
-                                        "Current Index\t"
-                                        "Current Value\t"
-                                        "Hold FD\t"
-                                        "Truncate\n"
-                                        "%s\t%s\t%zu\t%s\t%d\t%d\n",
-                                        name_.c_str(), node_path_.c_str(), current_val_index_,
-                                        node_value.c_str(), hold_fd_, truncate_));
+
     if (!android::base::WriteStringToFd(buf, fd)) {
         LOG(ERROR) << "Failed to dump fd: " << fd;
     }
+
     for (std::size_t i = 0; i < req_sorted_.size(); i++) {
         req_sorted_[i].DumpToFd(
             fd, android::base::StringPrintf("\t\tReq%zu:\t", i));
diff --git a/power-libperfmgr/libperfmgr/HintManager.cc b/power-libperfmgr/libperfmgr/HintManager.cc
index e22087ea..0a388cd6 100644
--- a/power-libperfmgr/libperfmgr/HintManager.cc
+++ b/power-libperfmgr/libperfmgr/HintManager.cc
@@ -303,9 +303,32 @@ void HintManager::DumpToFd(int fd) {
             LOG(ERROR) << "Failed to dump fd: " << fd;
         }
     }
+
+    DumpOtherConfigs(fd);
     fsync(fd);
 }
 
+void HintManager::DumpOtherConfigs(int fd) {
+    std::ostringstream dumpBuf;
+    dumpBuf << "========== Other configurations begin ==========\n";
+    if (other_configs_.GPUSysfsPath) {
+        dumpBuf << "GPUSysfsPath: " << other_configs_.GPUSysfsPath.value() << "\n";
+    }
+    if (other_configs_.enableMetricCollection) {
+        dumpBuf << "EnableMetricCollection: " << other_configs_.enableMetricCollection.value()
+                << "\n";
+    }
+    if (other_configs_.maxNumOfCachedSessionMetrics) {
+        dumpBuf << "MaxNumOfCachedSessionMetrics: "
+                << other_configs_.maxNumOfCachedSessionMetrics.value() << "\n";
+    }
+    dumpBuf << "========== Other configurations end ==========\n";
+
+    if (!android::base::WriteStringToFd(dumpBuf.str(), fd)) {
+        LOG(ERROR) << "Failed to dump fd: " << fd;
+    }
+}
+
 bool HintManager::Start() {
     return nm_->Start();
 }
@@ -336,20 +359,42 @@ HintManager *HintManager::GetInstance() {
     return sInstance.get();
 }
 
-static std::optional<std::string> ParseGpuSysfsNode(const std::string &json_doc) {
+OtherConfigs HintManager::ParseOtherConfigs(const std::string &json_doc) {
+    OtherConfigs otherConf;
     Json::Value root;
     Json::CharReaderBuilder builder;
     std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
     std::string errorMessage;
     if (!reader->parse(&*json_doc.begin(), &*json_doc.end(), &root, &errorMessage)) {
         LOG(ERROR) << "Failed to parse JSON config: " << errorMessage;
-        return {};
+        return otherConf;
+    }
+
+    // TODO(guibing@): Remove this part after all the powerhint configurations moved its position
+    // under "OtherConfigs". Keep it now for compatibility with existing powerhint json files.
+    if (!root["GpuSysfsPath"].empty() && root["GpuSysfsPath"].isString()) {
+        otherConf.GPUSysfsPath = root["GpuSysfsPath"].asString();
+    }
+
+    if (root["OtherConfigs"].empty()) {
+        return otherConf;
     }
 
-    if (root["GpuSysfsPath"].empty() || !root["GpuSysfsPath"].isString()) {
-        return {};
+    // Parse other configurations
+    Json::Value extraOtherConf = root["OtherConfigs"];
+    if (!extraOtherConf["EnableMetricCollection"].empty() &&
+        extraOtherConf["EnableMetricCollection"].isBool()) {
+        otherConf.enableMetricCollection = extraOtherConf["EnableMetricCollection"].asBool();
     }
-    return {root["GpuSysfsPath"].asString()};
+    if (!extraOtherConf["MaxNumOfCachedSessionMetrics"].empty() &&
+        extraOtherConf["MaxNumOfCachedSessionMetrics"].isUInt()) {
+        otherConf.maxNumOfCachedSessionMetrics =
+                extraOtherConf["MaxNumOfCachedSessionMetrics"].asUInt();
+    }
+    if (!extraOtherConf["GpuSysfsPath"].empty() && extraOtherConf["GpuSysfsPath"].isString()) {
+        otherConf.GPUSysfsPath = extraOtherConf["GpuSysfsPath"].asString();
+    }
+    return otherConf;
 }
 
 HintManager *HintManager::GetFromJSON(const std::string &config_path, bool start) {
@@ -377,23 +422,26 @@ HintManager *HintManager::GetFromJSON(const std::string &config_path, bool start
     LOG(VERBOSE) << "Parse ADPF Hint Event Table from all nodes.";
     for (std::size_t i = 0; i < nodes.size(); ++i) {
         const std::string &node_name = nodes[i]->GetName();
-        const std::string &node_path = nodes[i]->GetPath();
-        if (node_path.starts_with(kAdpfEventNodePath)) {
-            std::string tag = node_path.substr(strlen(kAdpfEventNodePath));
-            std::size_t index = nodes[i]->GetDefaultIndex();
-            std::string profile_name = nodes[i]->GetValues()[index];
-            for (std::size_t j = 0; j < adpfs.size(); ++j) {
-                if (adpfs[j]->mName == profile_name) {
-                    tag_adpfs[tag] = adpfs[j];
-                    LOG(INFO) << "[" << tag << ":" << node_name << "] set to '" << profile_name
-                              << "'";
-                    break;
+        const std::vector<std::string> &node_paths = nodes[i]->GetPaths();
+
+        for (auto &path: node_paths){
+            if (path.starts_with(kAdpfEventNodePath)) {
+                std::string tag = path.substr(strlen(kAdpfEventNodePath));
+                std::size_t index = nodes[i]->GetDefaultIndex();
+                std::string profile_name = nodes[i]->GetValues()[index];
+                for (std::size_t j = 0; j < adpfs.size(); ++j) {
+                    if (adpfs[j]->mName == profile_name) {
+                        tag_adpfs[tag] = adpfs[j];
+                        LOG(INFO) << "[" << tag << ":" << node_name << "] set to '" << profile_name
+                                << "'";
+                        break;
+                    }
+                }
+                if (!tag_adpfs[tag]) {
+                    tag_adpfs[tag] = adpfs[0];
+                    LOG(INFO) << "[" << tag << ":" << node_name << "] fallback to '" << adpfs[0]->mName
+                            << "'";
                 }
-            }
-            if (!tag_adpfs[tag]) {
-                tag_adpfs[tag] = adpfs[0];
-                LOG(INFO) << "[" << tag << ":" << node_name << "] fallback to '" << adpfs[0]->mName
-                          << "'";
             }
         }
     }
@@ -403,11 +451,11 @@ HintManager *HintManager::GetFromJSON(const std::string &config_path, bool start
         return nullptr;
     }
 
-    auto const gpu_sysfs_node = ParseGpuSysfsNode(json_doc);
+    auto const other_configs = ParseOtherConfigs(json_doc);
 
     sp<NodeLooperThread> nm = new NodeLooperThread(std::move(nodes));
     sInstance =
-            std::make_unique<HintManager>(std::move(nm), actions, adpfs, tag_adpfs, gpu_sysfs_node);
+            std::make_unique<HintManager>(std::move(nm), actions, adpfs, tag_adpfs, other_configs);
 
     if (!HintManager::InitHintStatus(sInstance)) {
         LOG(ERROR) << "Failed to initialize hint status";
@@ -456,20 +504,46 @@ std::vector<std::unique_ptr<Node>> HintManager::ParseNodes(const std::string &js
             return nodes_parsed;
         }
 
+        std::vector<std::string> paths_parsed;
         std::string path = nodes[i]["Path"].asString();
-        LOG(VERBOSE) << "Node[" << i << "]'s Path: " << path;
-        if (path.empty()) {
+
+        if (!path.empty()) {
+            LOG(WARNING) << "In node" << name << " old node path format detected.";
+            auto result = nodes_path_parsed.insert(path);
+            if (!result.second) {
+                LOG(ERROR) << "Duplicate Node[" << i << "]'s Paths";
+                nodes_parsed.clear();
+                return nodes_parsed;
+            }
+            paths_parsed.push_back(path);
+        }
+
+        Json::Value paths = nodes[i]["Paths"];
+
+        if (paths.empty()) {
             LOG(ERROR) << "Failed to read "
-                       << "Node[" << i << "]'s Path";
-            nodes_parsed.clear();
-            return nodes_parsed;
+                       << "Node[" << i << "]'s Paths";
+            if (paths_parsed.empty()) {
+                nodes_parsed.clear();
+                return nodes_parsed;
+            }
         }
 
-        result = nodes_path_parsed.insert(path);
-        if (!result.second) {
-            LOG(ERROR) << "Duplicate Node[" << i << "]'s Path";
-            nodes_parsed.clear();
-            return nodes_parsed;
+        for (Json::Value::ArrayIndex j = 0; j < paths.size(); ++j) {
+            path = paths[j].asString();
+            if (path.empty()) {
+                LOG(ERROR) << "Failed to read "
+                           << "Node[" << i << "]'s Paths";
+                nodes_parsed.clear();
+                return nodes_parsed;
+            }
+            auto result = nodes_path_parsed.insert(path);
+            if (!result.second) {
+                LOG(ERROR) << "Duplicate Node[" << i << "]'s Paths";
+                nodes_parsed.clear();
+                return nodes_parsed;
+            }
+            paths_parsed.push_back(path);
         }
 
         bool is_event_node = false;
@@ -551,13 +625,13 @@ std::vector<std::unique_ptr<Node>> HintManager::ParseNodes(const std::string &js
                      << reset << std::noboolalpha;
 
         if (is_event_node) {
-            auto update_callback = [](const std::string &name, const std::string &path,
+            auto update_callback = [](const std::string &name, const std::vector<std::string> &path,
                                       const std::string &val) {
                 HintManager::GetInstance()->OnNodeUpdate(name, path, val);
             };
             nodes_parsed.emplace_back(std::make_unique<EventNode>(
-                    name, path, values_parsed, static_cast<std::size_t>(default_index), reset,
-                    update_callback));
+                    name, paths_parsed, values_parsed, static_cast<std::size_t>(default_index),
+                    reset, update_callback));
         } else if (is_file) {
             bool truncate = android::base::GetBoolProperty(kPowerHalTruncateProp, true);
             if (nodes[i]["Truncate"].empty() || !nodes[i]["Truncate"].isBool()) {
@@ -588,12 +662,23 @@ std::vector<std::unique_ptr<Node>> HintManager::ParseNodes(const std::string &js
             LOG(VERBOSE) << "Node[" << i << "]'s WriteOnly: " << std::boolalpha
                          << write_only << std::noboolalpha;
 
+            bool allow_failure = false;
+            if (nodes[i]["AllowFailure"].empty() || !nodes[i]["AllowFailure"].isBool()) {
+                LOG(INFO) << "Failed to read Node[" << i
+                        << "]'s AllowFailure, set to 'false'";
+            } else {
+                allow_failure = nodes[i]["AllowFailure"].asBool();
+            }
+            LOG(VERBOSE) << "Node[" << i << "]'s AllowFailure: " << std::boolalpha
+                         << allow_failure << std::noboolalpha;
+
             nodes_parsed.emplace_back(std::make_unique<FileNode>(
-                    name, path, values_parsed, static_cast<std::size_t>(default_index), reset,
-                    truncate, hold_fd, write_only));
+                    name, paths_parsed, values_parsed, static_cast<std::size_t>(default_index),
+                    reset, truncate, allow_failure, hold_fd, write_only));
         } else {
-            nodes_parsed.emplace_back(std::make_unique<PropertyNode>(
-                    name, path, values_parsed, static_cast<std::size_t>(default_index), reset));
+            nodes_parsed.emplace_back(
+                    std::make_unique<PropertyNode>(name, paths_parsed, values_parsed,
+                                                   static_cast<std::size_t>(default_index), reset));
         }
     }
     LOG(INFO) << nodes_parsed.size() << " Nodes parsed successfully";
@@ -1003,19 +1088,21 @@ bool HintManager::IsAdpfProfileSupported(const std::string &profile_name) const
 }
 
 void HintManager::OnNodeUpdate(const std::string &name,
-                               __attribute__((unused)) const std::string &path,
+                               __attribute__((unused)) const std::vector<std::string> &paths,
                                const std::string &value) {
     // Check if the node is to update ADPF.
-    if (path.starts_with(kAdpfEventNodePath)) {
-        std::string tag = path.substr(strlen(kAdpfEventNodePath));
-        bool updated = SetAdpfProfile(tag, value);
-        if (!updated) {
-            LOG(DEBUG) << "OnNodeUpdate:[" << name << "] failed to update '" << value << "'";
-            return;
-        }
-        auto &callback_list = tag_update_callback_list_[tag];
-        for (const auto &callback : callback_list) {
-            (*callback)(tag_profile_map_[tag]);
+    for (const auto &path : paths) {
+        if (path.starts_with(kAdpfEventNodePath)) {
+            std::string tag = path.substr(strlen(kAdpfEventNodePath));
+            bool updated = SetAdpfProfile(tag, value);
+            if (!updated) {
+                LOG(DEBUG) << "OnNodeUpdate:[" << name << "] failed to update '" << value << "'";
+                return;
+            }
+            auto &callback_list = tag_update_callback_list_[tag];
+            for (const auto &callback : callback_list) {
+                (*callback)(tag_profile_map_[tag]);
+            }
         }
     }
 }
@@ -1040,7 +1127,11 @@ void HintManager::UnregisterAdpfUpdateEvent(const std::string &tag,
 }
 
 std::optional<std::string> HintManager::gpu_sysfs_config_path() const {
-    return gpu_sysfs_config_path_;
+    return other_configs_.GPUSysfsPath;
+}
+
+OtherConfigs HintManager::GetOtherConfigs() const {
+    return other_configs_;
 }
 
 }  // namespace perfmgr
diff --git a/power-libperfmgr/libperfmgr/JobQueueManager.cc b/power-libperfmgr/libperfmgr/JobQueueManager.cc
new file mode 100644
index 00000000..6525af21
--- /dev/null
+++ b/power-libperfmgr/libperfmgr/JobQueueManager.cc
@@ -0,0 +1,135 @@
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
+#define ATRACE_TAG (ATRACE_TAG_POWER | ATRACE_TAG_HAL)
+#define LOG_TAG "libperfmgr"
+
+#include "perfmgr/JobQueueManager.h"
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/stringprintf.h>
+#include <utils/Trace.h>
+
+#include "perfmgr/NodeLooperThread.h"
+
+namespace android {
+namespace perfmgr {
+
+JobQueueManager::JobQueueManager(size_t poolSize) : mPoolSize(poolSize) {
+    for (size_t i = 0; i < mPoolSize; ++i) {
+        Job *job = new Job();
+        mJobPool.push_back(job);  // Add to the pool
+    }
+}
+
+void JobQueueManager::enqueueRequest(Job *job) {
+    ::android::AutoMutex _l(mQueueMutex);
+    // This is a priority_queue(automatically sort the jobs by schedule_time)
+    mJobQueue.push(job);
+}
+
+Job *JobQueueManager::dequeueRequest() {
+    ::android::AutoMutex _l(mQueueMutex);
+    if (mJobQueue.empty()) {
+        return nullptr;
+    }
+    Job *job = mJobQueue.top();
+    mJobQueue.pop();
+    return job;
+}
+
+Job *JobQueueManager::getFreeJob() {
+    ::android::AutoMutex _l(mQueueMutex);
+    if (mJobPool.empty()) {
+        // If pool is empty, allocate a new job on the heap.
+        // This can happen if the pool size is not sufficient, or
+        // if a job is not returned to the pool correctly.
+        std::string warning = "PowerHAL:JobPoolEmpty[queue:" + std::to_string(mJobQueue.size()) +
+                              ",pool: " + std::to_string(mPoolSize) +
+                              ",limit:" + std::to_string(mPoolSize) + "]";
+        LOG(WARNING) << warning;
+        ATRACE_NAME(warning.c_str());
+        return new Job();
+    }
+    Job *job = mJobPool.front();
+    mJobPool.pop_front();
+    return job;
+}
+
+void JobQueueManager::returnJob(Job *job) {
+    ::android::AutoMutex _l(mQueueMutex);
+    job->reset();  // Reset the job's content
+    mJobPool.push_back(job);
+}
+
+size_t JobQueueManager::getSize() {
+    ::android::AutoMutex _l(mQueueMutex);
+    return mJobQueue.size();
+}
+
+void JobQueueManager::DumpToFd(int fd) {
+    ::android::AutoMutex _l(mQueueMutex);
+
+    std::string buf = android::base::StringPrintf(
+            "Job Queue Dump:\n"
+            "-------------------\n"
+            "Queue Size: %zu\n"
+            "Pool Size: %zu\n"
+            "-------------------\n",
+            mJobQueue.size(), mJobPool.size());
+    if (!android::base::WriteStringToFd(buf, fd)) {
+        LOG(ERROR) << "Failed to dump queue info to fd: " << fd;
+    }
+
+    // Dump Job Queue
+    if (!mJobQueue.empty()) {
+        buf = "Job Queue:\n";
+        if (!android::base::WriteStringToFd(buf, fd)) {
+            LOG(ERROR) << "Failed to write queue header to fd: " << fd;
+        }
+
+        // Directly dump jobs from mJobQueue and re-push them.
+        std::priority_queue<Job *, std::vector<Job *>, JobComparator> tempQueue;
+        for (auto it = mJobQueue.size(); it > 0; --it) {
+            Job *job = mJobQueue.top();
+            mJobQueue.pop();
+            buf = android::base::StringPrintf(
+                    "  Hint Type: %s, Schedule Time: %lld, Is Cancel: %d\n", job->hint_type.c_str(),
+                    job->schedule_time.time_since_epoch().count(), job->is_cancel);
+            if (!android::base::WriteStringToFd(buf, fd)) {
+                LOG(ERROR) << "Failed to dump job info to fd: " << fd;
+            }
+            tempQueue.push(job);
+        }
+
+        // Restore mJobQueue
+        while (!tempQueue.empty()) {
+            mJobQueue.push(tempQueue.top());
+            tempQueue.pop();
+        }
+    }
+}
+
+void Job::reset() {
+    actions.clear();
+    hint_type.clear();
+    schedule_time = std::chrono::steady_clock::now();
+    is_cancel = false;
+}
+
+}  // namespace perfmgr
+}  // namespace android
diff --git a/power-libperfmgr/libperfmgr/Node.cc b/power-libperfmgr/libperfmgr/Node.cc
index eb180e65..0e2ec4ab 100644
--- a/power-libperfmgr/libperfmgr/Node.cc
+++ b/power-libperfmgr/libperfmgr/Node.cc
@@ -26,11 +26,10 @@
 namespace android {
 namespace perfmgr {
 
-Node::Node(std::string name, std::string node_path,
-           std::vector<RequestGroup> req_sorted, std::size_t default_val_index,
-           bool reset_on_init)
+Node::Node(std::string name, std::vector<std::string> node_paths,
+           std::vector<RequestGroup> req_sorted, std::size_t default_val_index, bool reset_on_init)
     : name_(std::move(name)),
-      node_path_(std::move(node_path)),
+      node_paths_(std::move(node_paths)),
       req_sorted_(std::move(req_sorted)),
       default_val_index_(default_val_index),
       reset_on_init_(reset_on_init),
@@ -61,8 +60,8 @@ const std::string& Node::GetName() const {
     return name_;
 }
 
-const std::string& Node::GetPath() const {
-    return node_path_;
+const std::vector<std::string> &Node::GetPaths() const {
+    return node_paths_;
 }
 
 bool Node::GetValueIndex(const std::string& value, std::size_t* index) const {
diff --git a/power-libperfmgr/libperfmgr/NodeLooperThread.cc b/power-libperfmgr/libperfmgr/NodeLooperThread.cc
index d38501d5..fd1c0fae 100644
--- a/power-libperfmgr/libperfmgr/NodeLooperThread.cc
+++ b/power-libperfmgr/libperfmgr/NodeLooperThread.cc
@@ -10,7 +10,7 @@
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specic language governing permissions and
+ * See the License for the specific language governing permissions and
  * limitations under the License.
  */
 
@@ -22,11 +22,20 @@
 #include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/properties.h>
+#include <processgroup/processgroup.h>
 #include <utils/Trace.h>
 
 namespace android {
 namespace perfmgr {
 
+status_t NodeLooperThread::readyToRun() {
+    // set task profile "PreferIdle" to lower scheduling latency.
+    if (!SetTaskProfiles(0, {"PreferIdleSet"})) {
+        LOG(WARNING) << "Device does not support 'PreferIdleSet' task profile.";
+    }
+    return NO_ERROR;
+}
+
 bool NodeLooperThread::Request(const std::vector<NodeAction>& actions,
                                const std::string& hint_type) {
     if (::android::Thread::exitPending()) {
@@ -37,38 +46,22 @@ bool NodeLooperThread::Request(const std::vector<NodeAction>& actions,
         LOG(WARNING) << "NodeLooperThread is not running, request " << hint_type;
     }
 
-    bool ret = true;
-    ::android::AutoMutex _l(lock_);
+    Job *job = jobmgr_.getFreeJob();
+    job->is_cancel = false;
+    job->hint_type = hint_type;
+    job->schedule_time = std::chrono::steady_clock::now();
+    ATRACE_BEGIN(("enq:+" + hint_type).c_str());
     for (const auto& a : actions) {
-        if (!a.enable_property.empty() &&
-            !android::base::GetBoolProperty(a.enable_property, true)) {
-            // Disabled action based on its control property
-            continue;
-        }
-        if (a.node_index >= nodes_.size()) {
-            LOG(ERROR) << "Node index out of bound: " << a.node_index
-                       << " ,size: " << nodes_.size();
-            ret = false;
-        } else {
-            // End time set to steady time point max
-            ReqTime end_time = ReqTime::max();
-            // Timeout is non-zero
-            if (a.timeout_ms != std::chrono::milliseconds::zero()) {
-                auto now = std::chrono::steady_clock::now();
-                // Overflow protection in case timeout_ms is too big to overflow
-                // time point which is unsigned integer
-                if (std::chrono::duration_cast<std::chrono::milliseconds>(
-                        ReqTime::max() - now) > a.timeout_ms) {
-                    end_time = now + a.timeout_ms;
-                }
-            }
-            ret = nodes_[a.node_index]->AddRequest(a.value_index, hint_type,
-                                                   end_time) &&
-                  ret;
-        }
+        std::string act_name = nodes_[a.node_index]->GetName();
+        ATRACE_BEGIN(act_name.c_str());
+        job->actions.push_back(a);
+        ATRACE_END();
     }
+    jobmgr_.enqueueRequest(job);
+    LOG(VERBOSE) << "JobQueue[+].size:" << jobmgr_.getSize();
+    ATRACE_END();
     wake_cond_.signal();
-    return ret;
+    return true;
 }
 
 bool NodeLooperThread::Cancel(const std::vector<NodeAction>& actions,
@@ -81,19 +74,21 @@ bool NodeLooperThread::Cancel(const std::vector<NodeAction>& actions,
         LOG(WARNING) << "NodeLooperThread is not running, cancel " << hint_type;
     }
 
-    bool ret = true;
-    ::android::AutoMutex _l(lock_);
+    Job *job = jobmgr_.getFreeJob();
+    job->is_cancel = true;
+    job->hint_type = hint_type;
+    job->schedule_time = std::chrono::steady_clock::now();
+    ATRACE_BEGIN(("enq:-" + hint_type).c_str());
     for (const auto& a : actions) {
-        if (a.node_index >= nodes_.size()) {
-            LOG(ERROR) << "Node index out of bound: " << a.node_index
-                       << " ,size: " << nodes_.size();
-            ret = false;
-        } else {
-            nodes_[a.node_index]->RemoveRequest(hint_type);
-        }
+        std::string act_name = nodes_[a.node_index]->GetName();
+        ATRACE_BEGIN(act_name.c_str());
+        job->actions.push_back(a);
+        ATRACE_END();
     }
+    jobmgr_.enqueueRequest(job);
+    ATRACE_END();
     wake_cond_.signal();
-    return ret;
+    return true;
 }
 
 void NodeLooperThread::DumpToFd(int fd) {
@@ -101,15 +96,64 @@ void NodeLooperThread::DumpToFd(int fd) {
     for (auto& n : nodes_) {
         n->DumpToFd(fd);
     }
+    jobmgr_.DumpToFd(fd);
 }
 
 bool NodeLooperThread::threadLoop() {
+    Job *job = jobmgr_.dequeueRequest();
     ::android::AutoMutex _l(lock_);
-    std::chrono::milliseconds timeout_ms = kMaxUpdatePeriod;
+
+    if (job != nullptr) {
+        ATRACE_BEGIN(("deq:" + job->hint_type + (job->is_cancel ? ":-" : ":+")).c_str());
+        for (const auto &a : job->actions) {
+            std::string node_name = nodes_[a.node_index]->GetName();
+            if (!a.enable_property.empty() &&
+                !android::base::GetBoolProperty(a.enable_property, true)) {
+                ATRACE_BEGIN((node_name + ":prop:disabled").c_str());
+                // Disabled action based on its control property
+                ATRACE_END();
+                continue;
+            }
+            if (a.node_index >= nodes_.size()) {
+                LOG(ERROR) << "Node index out of bound: " << a.node_index
+                           << " ,size: " << nodes_.size();
+                ATRACE_NAME((node_name + ":out-of-bound").c_str());
+                continue;
+            } else if (job->is_cancel) {
+                ATRACE_BEGIN((node_name + ":disable").c_str());
+                nodes_[a.node_index]->RemoveRequest(job->hint_type);
+                ATRACE_END();
+            } else {
+                ATRACE_BEGIN((node_name + ":enable").c_str());
+                // End time set to steady time point max
+                ReqTime end_time = ReqTime::max();
+                // Timeout is non-zero
+                if (a.timeout_ms != std::chrono::milliseconds::zero()) {
+                    auto now = job->schedule_time;  // std::chrono::steady_clock::now();
+                    // Overflow protection in case timeout_ms is too big to
+                    // overflow time point which is unsigned integer
+                    if (std::chrono::duration_cast<std::chrono::milliseconds>(ReqTime::max() -
+                                                                              now) > a.timeout_ms) {
+                        end_time = now + a.timeout_ms;
+                    }
+                }
+                bool ok = nodes_[a.node_index]->AddRequest(a.value_index, job->hint_type, end_time);
+                if (!ok) {
+                    LOG(ERROR) << "Node.AddRequest err: Node[" << node_name << "][" << a.value_index
+                               << "]";
+                }
+                ATRACE_END();
+            }
+        }
+        ATRACE_END();
+        jobmgr_.returnJob(job);
+        LOG(VERBOSE) << "JobQueue[-].size:" << jobmgr_.getSize();
+    }
 
     // Update 2 passes: some node may have dependency in other node
     // e.g. update cpufreq min to VAL while cpufreq max still set to
     // a value lower than VAL, is expected to fail in first pass
+    std::chrono::milliseconds timeout_ms = kMaxUpdatePeriod;
     ATRACE_BEGIN("update_nodes");
     for (auto& n : nodes_) {
         n->Update(false);
@@ -127,6 +171,11 @@ bool NodeLooperThread::threadLoop() {
     LOG(VERBOSE) << "NodeLooperThread will wait for " << sleep_timeout_ns
                  << "ns";
     ATRACE_BEGIN("wait");
+    if (jobmgr_.getSize()) {
+        LOG(VERBOSE) << "JobQueue not empty, size:" << jobmgr_.getSize()
+                     << ". Alter sleep_timeout_ns to 0";
+        sleep_timeout_ns = 0;
+    }
     wake_cond_.waitRelative(lock_, sleep_timeout_ns);
     ATRACE_END();
     return true;
diff --git a/power-libperfmgr/libperfmgr/PropertyNode.cc b/power-libperfmgr/libperfmgr/PropertyNode.cc
index cb4d2ca7..3cd59df0 100644
--- a/power-libperfmgr/libperfmgr/PropertyNode.cc
+++ b/power-libperfmgr/libperfmgr/PropertyNode.cc
@@ -29,11 +29,11 @@
 namespace android {
 namespace perfmgr {
 
-PropertyNode::PropertyNode(std::string name, std::string node_path,
-                           std::vector<RequestGroup> req_sorted,
-                           std::size_t default_val_index, bool reset_on_init)
-    : Node(std::move(name), std::move(node_path), std::move(req_sorted),
-           default_val_index, reset_on_init) {}
+PropertyNode::PropertyNode(std::string name, std::vector<std::string> node_paths,
+                           std::vector<RequestGroup> req_sorted, std::size_t default_val_index,
+                           bool reset_on_init)
+    : Node(std::move(name), std::move(node_paths), std::move(req_sorted), default_val_index,
+           reset_on_init) {}
 
 std::chrono::milliseconds PropertyNode::Update(bool) {
     std::size_t value_index = default_val_index_;
@@ -51,20 +51,25 @@ std::chrono::milliseconds PropertyNode::Update(bool) {
     if (value_index != current_val_index_ || reset_on_init_) {
         const std::string& req_value =
             req_sorted_[value_index].GetRequestValue();
+
         if (ATRACE_ENABLED()) {
             ATRACE_INT(("N:" + GetName()).c_str(), value_index);
             const std::string tag =
                     GetName() + ":" + req_value + ":" + std::to_string(expire_time.count());
             ATRACE_BEGIN(tag.c_str());
         }
-        if (!android::base::SetProperty(node_path_, req_value)) {
-            LOG(WARNING) << "Failed to set property to : " << node_path_
-                         << " with value: " << req_value;
-        } else {
-            // Update current index only when succeed
-            current_val_index_ = value_index;
-            reset_on_init_ = false;
+
+        for (const auto &path : node_paths_) {
+            if (!android::base::SetProperty(path, req_value)) {
+                LOG(WARNING) << "Failed to set property to : " << path
+                            << " with value: " << req_value;
+            } else {
+                // Update current index only when succeed
+                current_val_index_ = value_index;
+                reset_on_init_ = false;
+            }
         }
+
         if (ATRACE_ENABLED()) {
             ATRACE_END();
         }
@@ -73,14 +78,13 @@ std::chrono::milliseconds PropertyNode::Update(bool) {
 }
 
 void PropertyNode::DumpToFd(int fd) const {
-    std::string node_value = android::base::GetProperty(node_path_, "");
-    std::string buf(android::base::StringPrintf(
-            "Node Name\t"
-            "Property Name\t"
-            "Current Index\t"
-            "Current Value\n"
-            "%s\t%s\t%zu\t%s\n",
-            name_.c_str(), node_path_.c_str(), current_val_index_, node_value.c_str()));
+    std::string buf("Node Name\tProperty Name\tCurrent Index\tCurrent Value\n");
+
+    for (const auto &path : node_paths_) {
+        std::string node_value = android::base::GetProperty(path, "");
+        buf += android::base::StringPrintf("%s\t%s\t%zu\t%s\n", name_.c_str(), path.c_str(), current_val_index_, node_value.c_str());
+    }
+
     if (!android::base::WriteStringToFd(buf, fd)) {
         LOG(ERROR) << "Failed to dump fd: " << fd;
     }
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/EventNode.h b/power-libperfmgr/libperfmgr/include/perfmgr/EventNode.h
index f1b97f15..ba03dc53 100644
--- a/power-libperfmgr/libperfmgr/include/perfmgr/EventNode.h
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/EventNode.h
@@ -29,9 +29,11 @@ namespace perfmgr {
 // EventNode represents to handle events by callback function.
 class EventNode : public Node {
   public:
-    EventNode(std::string name, std::string node_path, std::vector<RequestGroup> req_sorted,
-              std::size_t default_val_index, bool reset_on_init,
-              std::function<void(const std::string &, const std::string &, const std::string &)>
+    EventNode(std::string name, std::vector<std::string> node_paths,
+              std::vector<RequestGroup> req_sorted, std::size_t default_val_index,
+              bool reset_on_init,
+              std::function<void(const std::string &, const std::vector<std::string> &,
+                                 const std::string &)>
                       update_callback);
 
     std::chrono::milliseconds Update(bool log_error) override;
@@ -40,7 +42,7 @@ class EventNode : public Node {
   private:
     EventNode(const Node &other) = delete;
     EventNode &operator=(Node const &) = delete;
-    const std::function<void(const std::string &name, const std::string &path,
+    const std::function<void(const std::string &name, const std::vector<std::string> &paths,
                              const std::string &value)>
             update_callback_;
 };
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/FileNode.h b/power-libperfmgr/libperfmgr/include/perfmgr/FileNode.h
index bb8a2a79..9d1f87ee 100644
--- a/power-libperfmgr/libperfmgr/include/perfmgr/FileNode.h
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/FileNode.h
@@ -31,12 +31,13 @@ namespace perfmgr {
 // FileNode represents file
 class FileNode : public Node {
   public:
-    FileNode(std::string name, std::string node_path, std::vector<RequestGroup> req_sorted,
-             std::size_t default_val_index, bool reset_on_init, bool truncate,
-             bool hold_fd = false, bool write_only = false);
+    FileNode(std::string name, std::vector<std::string> node_paths,
+             std::vector<RequestGroup> req_sorted, std::size_t default_val_index,
+             bool reset_on_init, bool truncate, bool allow_failure, bool hold_fd = false, bool write_only = false);
 
     std::chrono::milliseconds Update(bool log_error) override;
 
+    bool GetAllowFailure() const;
     bool GetHoldFd() const;
     bool GetTruncate() const;
 
@@ -52,6 +53,7 @@ class FileNode : public Node {
     const bool write_only_;
     const std::chrono::milliseconds warn_timeout_;
     android::base::unique_fd fd_;
+    bool allow_failure_;
 };
 
 }  // namespace perfmgr
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/HintManager.h b/power-libperfmgr/libperfmgr/include/perfmgr/HintManager.h
index 303818a8..26ca34f9 100644
--- a/power-libperfmgr/libperfmgr/include/perfmgr/HintManager.h
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/HintManager.h
@@ -82,6 +82,12 @@ struct Hint {
     std::shared_ptr<HintStatus> status GUARDED_BY(hint_lock);
 };
 
+struct OtherConfigs {
+    std::optional<std::string> GPUSysfsPath;
+    std::optional<bool> enableMetricCollection;
+    std::optional<uint32_t> maxNumOfCachedSessionMetrics;
+};
+
 // HintManager is the external interface of the library to be used by PowerHAL
 // to do power hints with sysfs nodes. HintManager maintains a representation of
 // the actions that are parsed from the configuration file as a mapping from a
@@ -91,13 +97,13 @@ class HintManager {
     HintManager(sp<NodeLooperThread> nm, const std::unordered_map<std::string, Hint> &actions,
                 const std::vector<std::shared_ptr<AdpfConfig>> &adpfs,
                 const std::unordered_map<std::string, std::shared_ptr<AdpfConfig>> &tag_adpfs,
-                std::optional<std::string> gpu_sysfs_config_path)
+                const OtherConfigs &other_configs)
         : nm_(std::move(nm)),
           actions_(actions),
           adpfs_(adpfs),
           tag_profile_map_(tag_adpfs),
           adpf_index_(0),
-          gpu_sysfs_config_path_(gpu_sysfs_config_path) {}
+          other_configs_(other_configs) {}
     ~HintManager() {
         if (nm_.get() != nullptr) nm_->Stop();
     }
@@ -140,6 +146,9 @@ class HintManager {
     // get current ADPF.
     std::shared_ptr<AdpfConfig> GetAdpfProfile(const std::string &node_name = "OTHER") const;
 
+    // get other configurations
+    OtherConfigs GetOtherConfigs() const;
+
     // Check if ADPF is supported.
     bool IsAdpfSupported() const;
 
@@ -169,6 +178,7 @@ class HintManager {
     static std::unordered_map<std::string, Hint> ParseActions(
             const std::string &json_doc, const std::vector<std::unique_ptr<Node>> &nodes);
     static std::vector<std::shared_ptr<AdpfConfig>> ParseAdpfConfigs(const std::string &json_doc);
+    static OtherConfigs ParseOtherConfigs(const std::string &json_doc);
     static bool InitHintStatus(const std::unique_ptr<HintManager> &hm);
 
     static void Reload(bool start);
@@ -184,20 +194,24 @@ class HintManager {
     void DoHintAction(const std::string &hint_type);
     // Helper function to take hint actions when EndHint
     void EndHintAction(const std::string &hint_type);
+    // Dump the "OtherConfigs" parts in the parsed configuration file.
+    void DumpOtherConfigs(int fd);
+
     sp<NodeLooperThread> nm_;
     std::unordered_map<std::string, Hint> actions_;
     std::vector<std::shared_ptr<AdpfConfig>> adpfs_;
     // TODO(jimmyshiu@): Need to be removed once all powerhint.json up-to-date.
     std::unordered_map<std::string, std::shared_ptr<AdpfConfig>> tag_profile_map_;
     uint32_t adpf_index_;
-    std::optional<std::string> gpu_sysfs_config_path_;
 
     static std::unique_ptr<HintManager> sInstance;
 
     // Hint Update Callback
-    void OnNodeUpdate(const std::string &name, const std::string &path, const std::string &value);
+    void OnNodeUpdate(const std::string &name, const std::vector<std::string> &paths, const std::string &value);
     // set ADPF config by hint name.
     std::unordered_map<std::string, std::vector<AdpfCallback *>> tag_update_callback_list_;
+    // Other configurations
+    OtherConfigs other_configs_;
 };
 
 }  // namespace perfmgr
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/JobQueueManager.h b/power-libperfmgr/libperfmgr/include/perfmgr/JobQueueManager.h
new file mode 100644
index 00000000..7d551c98
--- /dev/null
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/JobQueueManager.h
@@ -0,0 +1,84 @@
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
+#ifndef ANDROID_LIBPERFMGR_JOBQUEUEMANAGER_H_
+#define ANDROID_LIBPERFMGR_JOBQUEUEMANAGER_H_
+
+#include <utils/Mutex.h>
+
+#include <chrono>
+#include <cstddef>
+#include <deque>
+#include <functional>
+#include <queue>
+#include <vector>
+
+namespace android {
+namespace perfmgr {
+
+/* Default pool size for JobQueueManager
+ *
+ * Observed from the log of CM4 on 2025 March, the queue size reaches ~45 during
+ * bootup while the NodeLooperThread is not running. Therefore, set the pool
+ * size to 64.
+ */
+const size_t DEFAULT_POOL_SIZE = 64;
+
+struct NodeAction;  // Forward declaration
+
+struct Job {
+    std::vector<NodeAction> actions;  // Replace with your action type
+    std::string hint_type;            // Replace with your hint type
+    std::chrono::time_point<std::chrono::steady_clock> schedule_time;
+    bool is_cancel;  // True if this is a cancel request
+    void reset();
+};
+
+// Custom comparator for priority_queue (earlier schedule_time has higher priority)
+struct JobComparator {
+    bool operator()(const Job *a, const Job *b) const {
+        return a->schedule_time > b->schedule_time;  // Earlier time means higher priority
+    }
+};
+
+class JobQueueManager {
+  public:
+    JobQueueManager(size_t poolSize = DEFAULT_POOL_SIZE);  // Constructor with pool size
+
+    // Add a job to the queue
+    void enqueueRequest(Job *job);
+
+    // Get the next job from the queue
+    Job *dequeueRequest();
+    Job *getFreeJob();
+    void returnJob(Job *job);
+    size_t getSize();
+
+    // Dump messages to fd
+    void DumpToFd(int fd);
+
+  private:
+    // Job will be auto sorted by JobComparator in priority_queue
+    std::priority_queue<Job *, std::vector<Job *>, JobComparator> mJobQueue;
+    ::android::Mutex mQueueMutex;  // Mutex to protect the queue
+    std::deque<Job *> mJobPool;    // Use deque for efficient push/pop from both ends
+    size_t mPoolSize;
+};
+
+}  // namespace perfmgr
+}  // namespace android
+
+#endif  // ANDROID_LIBPERFMGR_JOBQUEUEMANAGER_H_
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/Node.h b/power-libperfmgr/libperfmgr/include/perfmgr/Node.h
index e0db0777..bf646ade 100644
--- a/power-libperfmgr/libperfmgr/include/perfmgr/Node.h
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/Node.h
@@ -62,7 +62,7 @@ class Node {
     virtual std::chrono::milliseconds Update(bool log_error) = 0;
 
     const std::string& GetName() const;
-    const std::string& GetPath() const;
+    const std::vector<std::string> &GetPaths() const;
     std::vector<std::string> GetValues() const;
     std::size_t GetDefaultIndex() const;
     bool GetResetOnInit() const;
@@ -70,14 +70,13 @@ class Node {
     virtual void DumpToFd(int fd) const = 0;
 
   protected:
-    Node(std::string name, std::string node_path,
-         std::vector<RequestGroup> req_sorted, std::size_t default_val_index,
-         bool reset_on_init);
+    Node(std::string name, std::vector<std::string> node_paths,
+         std::vector<RequestGroup> req_sorted, std::size_t default_val_index, bool reset_on_init);
     Node(const Node& other) = delete;
     Node& operator=(Node const&) = delete;
 
     const std::string name_;
-    const std::string node_path_;
+    const std::vector<std::string> node_paths_;
     // request vector, one entry per possible value, sorted by priority.
     std::vector<RequestGroup> req_sorted_;
     const std::size_t default_val_index_;
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/NodeLooperThread.h b/power-libperfmgr/libperfmgr/include/perfmgr/NodeLooperThread.h
index 67cb36f3..a77f0b4a 100644
--- a/power-libperfmgr/libperfmgr/include/perfmgr/NodeLooperThread.h
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/NodeLooperThread.h
@@ -10,7 +10,7 @@
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specic language governing permissions and
+ * See the License for the specific language governing permissions and
  * limitations under the License.
  */
 
@@ -25,6 +25,7 @@
 #include <utility>
 #include <vector>
 
+#include "perfmgr/JobQueueManager.h"
 #include "perfmgr/Node.h"
 
 namespace android {
@@ -84,6 +85,8 @@ class NodeLooperThread : public ::android::Thread {
   private:
     NodeLooperThread(NodeLooperThread const&) = delete;
     NodeLooperThread &operator=(NodeLooperThread const &) = delete;
+
+    status_t readyToRun() override;
     bool threadLoop() override;
 
     static constexpr auto kMaxUpdatePeriod = std::chrono::milliseconds::max();
@@ -98,6 +101,9 @@ class NodeLooperThread : public ::android::Thread {
 
     // lock to protect nodes_
     ::android::Mutex lock_;
+
+    // Job queue for threadloop to process
+    JobQueueManager jobmgr_;
 };
 
 }  // namespace perfmgr
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/PropertyNode.h b/power-libperfmgr/libperfmgr/include/perfmgr/PropertyNode.h
index feaf85fa..22bf9260 100644
--- a/power-libperfmgr/libperfmgr/include/perfmgr/PropertyNode.h
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/PropertyNode.h
@@ -29,9 +29,9 @@ namespace perfmgr {
 // PropertyNode represents managed system properties
 class PropertyNode : public Node {
   public:
-    PropertyNode(std::string name, std::string node_path,
-                 std::vector<RequestGroup> req_sorted,
-                 std::size_t default_val_index, bool reset_on_init);
+    PropertyNode(std::string name, std::vector<std::string> node_paths,
+                 std::vector<RequestGroup> req_sorted, std::size_t default_val_index,
+                 bool reset_on_init);
 
     std::chrono::milliseconds Update(bool log_error) override;
 
diff --git a/power-libperfmgr/libperfmgr/tests/EventNodeTest.cc b/power-libperfmgr/libperfmgr/tests/EventNodeTest.cc
index 62ca90f6..92478619 100644
--- a/power-libperfmgr/libperfmgr/tests/EventNodeTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/EventNodeTest.cc
@@ -17,10 +17,11 @@
 #include <android-base/file.h>
 #include <android-base/stringprintf.h>
 #include <gtest/gtest.h>
+#include <gmock/gmock.h>
 
-#include <algorithm>
 #include <thread>
 
+#include "gmock/gmock.h"
 #include "perfmgr/EventNode.h"
 
 namespace android {
@@ -34,9 +35,9 @@ constexpr auto kSLEEP_TOLERANCE_MS = 2ms;
 // Test init with no default value
 TEST(EventNodeTest, NoInitDefaultTest) {
     std::string node_val = "uninitialize";
-    auto update_callback = [&node_val](const std::string &, const std::string &,
+    auto update_callback = [&node_val](const std::string &, const std::vector<std::string> &,
                                        const std::string &val) { node_val = val; };
-    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 1, false,
+    EventNode t("EventName", {"<Event>:Node"}, {{"value0"}, {"value1"}, {"value2"}}, 1, false,
                 update_callback);
     t.Update(false);
     EXPECT_EQ(node_val, "uninitialize");
@@ -45,13 +46,13 @@ TEST(EventNodeTest, NoInitDefaultTest) {
 // Test init with default value
 TEST(EventNodeTest, InitDefaultTest) {
     std::string node_val = "uninitialize";
-    auto update_callback = [&node_val](const std::string &, const std::string &,
+    auto update_callback = [&node_val](const std::string &, const std::vector<std::string> &,
                                        const std::string &val) { node_val = val; };
-    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 1, true,
+    EventNode t("EventName", {"<Event>:Node"}, {{"value0"}, {"value1"}, {"value2"}}, 1, true,
                 update_callback);
     t.Update(false);
     EXPECT_EQ(node_val, "value1");
-    EventNode t2("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 0, true,
+    EventNode t2("EventName", {"<Event>:Node"}, {{"value0"}, {"value1"}, {"value2"}}, 0, true,
                  update_callback);
     t2.Update(false);
     EXPECT_EQ(node_val, "value0");
@@ -60,9 +61,9 @@ TEST(EventNodeTest, InitDefaultTest) {
 // Test DumpToFd
 TEST(EventNodeTest, DumpToFdTest) {
     std::string node_val = "uninitialize";
-    auto update_callback = [&node_val](const std::string &, const std::string &,
+    auto update_callback = [&node_val](const std::string &, const std::vector<std::string> &,
                                        const std::string &val) { node_val = val; };
-    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 1, true,
+    EventNode t("EventName", {"<Event>:Node"}, {{"value0"}, {"value1"}, {"value2"}}, 1, true,
                 update_callback);
     t.Update(false);
     t.Update(false);
@@ -84,9 +85,9 @@ TEST(EventNodeTest, DumpToFdTest) {
 // Test GetValueIndex
 TEST(EventNodeTest, GetValueIndexTest) {
     std::string node_val = "uninitialize";
-    auto update_callback = [&node_val](const std::string &, const std::string &,
+    auto update_callback = [&node_val](const std::string &, const std::vector<std::string> &,
                                        const std::string &val) { node_val = val; };
-    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 1, false,
+    EventNode t("EventName", {"<Event>:Node"}, {{"value0"}, {"value1"}, {"value2"}}, 1, false,
                 update_callback);
     std::size_t index = 0;
     EXPECT_TRUE(t.GetValueIndex("value2", &index));
@@ -99,9 +100,9 @@ TEST(EventNodeTest, GetValueIndexTest) {
 // Test GetValues
 TEST(EventNodeTest, GetValuesTest) {
     std::string node_val = "uninitialize";
-    auto update_callback = [&node_val](const std::string &, const std::string &,
+    auto update_callback = [&node_val](const std::string &, const std::vector<std::string> &,
                                        const std::string &val) { node_val = val; };
-    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 1, false,
+    EventNode t("EventName", {"<Event>:Node"}, {{"value0"}, {"value1"}, {"value2"}}, 1, false,
                 update_callback);
     std::vector values = t.GetValues();
     EXPECT_EQ(3u, values.size());
@@ -113,13 +114,13 @@ TEST(EventNodeTest, GetValuesTest) {
 // Test get more properties
 TEST(EventNodeTest, GetPropertiesTest) {
     std::string node_val = "uninitialize";
-    auto update_callback = [&node_val](const std::string &, const std::string &,
+    auto update_callback = [&node_val](const std::string &, const std::vector<std::string> &,
                                        const std::string &val) { node_val = val; };
     std::string test_name = "TESTREQ_1";
     std::string test_path = "TEST_PATH";
-    EventNode t(test_name, test_path, {}, 0, false, update_callback);
+    EventNode t(test_name, {test_path}, {}, 0, false, update_callback);
     EXPECT_EQ(test_name, t.GetName());
-    EXPECT_EQ(test_path, t.GetPath());
+    EXPECT_THAT(t.GetPaths(), testing::ElementsAre(test_path));
     EXPECT_EQ(0u, t.GetValues().size());
     EXPECT_EQ(0u, t.GetDefaultIndex());
     EXPECT_FALSE(t.GetResetOnInit());
@@ -128,9 +129,9 @@ TEST(EventNodeTest, GetPropertiesTest) {
 // Test add request
 TEST(EventNodeTest, AddRequestTest) {
     std::string node_val = "uninitialize";
-    auto update_callback = [&node_val](const std::string &, const std::string &,
+    auto update_callback = [&node_val](const std::string &, const std::vector<std::string> &,
                                        const std::string &val) { node_val = val; };
-    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {""}}, 2, true,
+    EventNode t("EventName", {"<Event>:Node"}, {{"value0"}, {"value1"}, {""}}, 2, true,
                 update_callback);
     auto start = std::chrono::steady_clock::now();
     EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
@@ -158,9 +159,9 @@ TEST(EventNodeTest, AddRequestTest) {
 // Test remove request
 TEST(EventNodeTest, RemoveRequestTest) {
     std::string node_val = "uninitialize";
-    auto update_callback = [&node_val](const std::string &, const std::string &,
+    auto update_callback = [&node_val](const std::string &, const std::vector<std::string> &,
                                        const std::string &val) { node_val = val; };
-    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 2, true,
+    EventNode t("EventName", {"<Event>:Node"}, {{"value0"}, {"value1"}, {"value2"}}, 2, true,
                 update_callback);
     auto start = std::chrono::steady_clock::now();
     EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
@@ -188,9 +189,9 @@ TEST(EventNodeTest, RemoveRequestTest) {
 // Test add request
 TEST(EventNodeTest, AddRequestTestOverride) {
     std::string node_val = "uninitialize";
-    auto update_callback = [&node_val](const std::string &, const std::string &,
+    auto update_callback = [&node_val](const std::string &, const std::vector<std::string> &,
                                        const std::string &val) { node_val = val; };
-    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 2, true,
+    EventNode t("EventName", {"<Event>:Node"}, {{"value0"}, {"value1"}, {"value2"}}, 2, true,
                 update_callback);
     auto start = std::chrono::steady_clock::now();
     EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
diff --git a/power-libperfmgr/libperfmgr/tests/FileNodeTest.cc b/power-libperfmgr/libperfmgr/tests/FileNodeTest.cc
index c3f269bb..4ef7a63f 100644
--- a/power-libperfmgr/libperfmgr/tests/FileNodeTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/FileNodeTest.cc
@@ -17,8 +17,8 @@
 #include <android-base/file.h>
 #include <android-base/stringprintf.h>
 #include <gtest/gtest.h>
+#include <gmock/gmock.h>
 
-#include <algorithm>
 #include <thread>
 
 #include "perfmgr/FileNode.h"
@@ -41,7 +41,7 @@ static inline void _VerifyPathValue(const std::string& path,
 // Test init with no default value
 TEST(FileNodeTest, NoInitDefaultTest) {
     TemporaryFile tf;
-    FileNode t("t", tf.path, {{"value0"}, {"value1"}, {"value2"}}, 1, false, false);
+    FileNode t("t", {tf.path}, {{"value0"}, {"value1"}, {"value2"}}, 1, false, false, false);
     t.Update(false);
     _VerifyPathValue(tf.path, "");
 }
@@ -49,11 +49,11 @@ TEST(FileNodeTest, NoInitDefaultTest) {
 // Test init with default value
 TEST(FileNodeTest, InitDefaultTest) {
     TemporaryFile tf;
-    FileNode t("t", tf.path, {{"value0"}, {"value1"}, {"value2"}}, 1, true, true);
+    FileNode t("t", {tf.path}, {{"value0"}, {"value1"}, {"value2"}}, 1, true, true, false);
     t.Update(false);
     _VerifyPathValue(tf.path, "value1");
     TemporaryFile tf2;
-    FileNode t2("t2", tf2.path, {{"value0"}, {"value1"}, {"value2"}}, 0, true, true);
+    FileNode t2("t2", {tf2.path}, {{"value0"}, {"value1"}, {"value2"}}, 0, true, true, false);
     t2.Update(false);
     _VerifyPathValue(tf2.path, "value0");
 }
@@ -61,8 +61,8 @@ TEST(FileNodeTest, InitDefaultTest) {
 // Test DumpToFd
 TEST(FileNodeTest, DumpToFdTest) {
     TemporaryFile tf;
-    FileNode t("test_dump", tf.path, {{"value0"}, {"value1"}, {"value2"}}, 1,
-               true, true);
+    FileNode t("test_dump", {tf.path}, {{"value0"}, {"value1"}, {"value2"}}, 1,
+               true, true, false);
     t.Update(false);
     TemporaryFile dumptf;
     t.DumpToFd(dumptf.fd);
@@ -82,7 +82,7 @@ TEST(FileNodeTest, DumpToFdTest) {
 // Test GetValueIndex
 TEST(FileNodeTest, GetValueIndexTest) {
     TemporaryFile tf;
-    FileNode t("t", tf.path, {{"value0"}, {"value1"}, {"value2"}}, 1, false, false);
+    FileNode t("t", {tf.path}, {{"value0"}, {"value1"}, {"value2"}}, 1, false, false, false);
     std::size_t index = 0;
     EXPECT_TRUE(t.GetValueIndex("value2", &index));
     EXPECT_EQ(2u, index);
@@ -94,21 +94,19 @@ TEST(FileNodeTest, GetValueIndexTest) {
 // Test GetValues
 TEST(FileNodeTest, GetValuesTest) {
     TemporaryFile tf;
-    FileNode t("t", tf.path, {{"value0"}, {"value1"}, {"value2"}}, 1, false, false);
+    FileNode t("t", {tf.path}, {{"value0"}, {"value1"}, {"value2"}}, 1, false, false, false);
     std::vector values = t.GetValues();
     EXPECT_EQ(3u, values.size());
-    EXPECT_EQ("value0", values[0]);
-    EXPECT_EQ("value1", values[1]);
-    EXPECT_EQ("value2", values[2]);
+    EXPECT_THAT(values, testing::ElementsAre("value0", "value1", "value2"));
 }
 
 // Test get more properties
 TEST(FileNodeTest, GetPropertiesTest) {
     std::string test_name = "TESTREQ_1";
     std::string test_path = "TEST_PATH";
-    FileNode t(test_name, test_path, {}, 0, false, false, true);
+    FileNode t(test_name, {test_path}, {}, 0, false, true, false, true);
     EXPECT_EQ(test_name, t.GetName());
-    EXPECT_EQ(test_path, t.GetPath());
+    EXPECT_THAT(t.GetPaths(), testing::ElementsAre(test_path));
     EXPECT_EQ(0u, t.GetValues().size());
     EXPECT_EQ(0u, t.GetDefaultIndex());
     EXPECT_FALSE(t.GetResetOnInit());
@@ -117,8 +115,8 @@ TEST(FileNodeTest, GetPropertiesTest) {
 
 // Test add request fail and retry
 TEST(FileNodeTest, AddRequestTestFail) {
-    FileNode t("t", "/sys/android/nonexist_node_test",
-               {{"value0"}, {"value1"}, {"value2"}}, 2, true, true);
+    FileNode t("t", {"/sys/android/nonexist_node_test"},
+               {{"value0"}, {"value1"}, {"value2"}}, 2, true, true, false);
     auto start = std::chrono::steady_clock::now();
     EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 200ms));
     std::chrono::milliseconds expire_time = t.Update(true);
@@ -136,7 +134,7 @@ TEST(FileNodeTest, AddRequestTestFail) {
 // Test add request
 TEST(FileNodeTest, AddRequestTest) {
     TemporaryFile tf;
-    FileNode t("t", tf.path, {{"value0"}, {"value1"}, {"value2"}}, 2, true, true);
+    FileNode t("t", {tf.path}, {{"value0"}, {"value1"}, {"value2"}}, 2, true, true, false);
     auto start = std::chrono::steady_clock::now();
     EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
     std::chrono::milliseconds expire_time = t.Update(true);
@@ -166,7 +164,7 @@ TEST(FileNodeTest, AddRequestTest) {
 // Test remove request
 TEST(FileNodeTest, RemoveRequestTest) {
     TemporaryFile tf;
-    FileNode t("t", tf.path, {{"value0"}, {"value1"}, {"value2"}}, 2, true, true);
+    FileNode t("t", {tf.path}, {{"value0"}, {"value1"}, {"value2"}}, 2, true, false, true);
     auto start = std::chrono::steady_clock::now();
     EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
     std::chrono::milliseconds expire_time = t.Update(true);
@@ -196,8 +194,8 @@ TEST(FileNodeTest, RemoveRequestTest) {
 // Test add request with holding fd
 TEST(FileNodeTest, AddRequestTestHoldFdOverride) {
     TemporaryFile tf;
-    FileNode t("t", tf.path, {{"value0"}, {"value1"}, {"value2"}}, 2, true,
-               true, true);
+    FileNode t("t", {tf.path}, {{"value0"}, {"value1"}, {"value2"}}, 2, true,
+               true, false, true, true);
     EXPECT_TRUE(t.GetHoldFd());
     auto start = std::chrono::steady_clock::now();
     EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
@@ -237,5 +235,22 @@ TEST(FileNodeTest, AddRequestTestHoldFdOverride) {
     EXPECT_EQ(std::chrono::milliseconds::max(), expire_time);
 }
 
+TEST(FileNodeTest, AllowFailureTest) {
+    FileNode t("t", {"/sys/android/nonexist_node_test"},
+               {{"value0"}, {"value1"}, {"value2"}}, 2, true, true, true);
+    auto start = std::chrono::steady_clock::now();
+    EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 200ms));
+    std::chrono::milliseconds expire_time = t.Update(true);
+    // Add request @ value1
+    EXPECT_NEAR(std::chrono::milliseconds(200).count(), expire_time.count(),
+                kTIMING_TOLERANCE_MS);
+    // Add request @ value0 higher prio than value1
+    EXPECT_TRUE(t.AddRequest(0, "LAUNCH", start + 2000ms));
+    expire_time = t.Update(true);
+    // Retry in 2000 ms
+    EXPECT_NEAR(std::chrono::milliseconds(2000).count(), expire_time.count(),
+                kTIMING_TOLERANCE_MS);
+}
+
 }  // namespace perfmgr
 }  // namespace android
diff --git a/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc b/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc
index b413f977..68377bfc 100644
--- a/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc
@@ -55,17 +55,18 @@ constexpr char kJSON_RAW[] = R"(
         },
         {
             "Name": "CPUCluster1MinFreq",
-            "Path": "/sys/devices/system/cpu/cpu4/cpufreq/scaling_min_freq",
+            "Paths": ["/sys/devices/system/cpu/cpu4/cpufreq/scaling_min_freq"],
             "Values": [
                 "1512000",
                 "1134000",
                 "384000"
             ],
-            "HoldFd": true
+            "HoldFd": true,
+            "AllowFailure": true
         },
         {
             "Name": "ModeProperty",
-            "Path": "vendor.pwhal.mode",
+            "Paths": ["vendor.pwhal.mode"],
             "Values": [
                 "HIGH",
                 "LOW",
@@ -75,7 +76,7 @@ constexpr char kJSON_RAW[] = R"(
         },
         {
             "Name": "TestEnableProperty",
-            "Path": "vendor.pwhal.enable.test",
+            "Paths": ["vendor.pwhal.enable.test"],
             "Values": [
                 "0",
                 "1"
@@ -157,7 +158,7 @@ constexpr char kJSON_ADPF[] = R"(
     "Nodes": [
         {
             "Name": "OTHER",
-            "Path": "<AdpfConfig>:OTHER",
+            "Paths": ["<AdpfConfig>:OTHER"],
             "Values": [
                 "ADPF_DEFAULT"
             ],
@@ -165,7 +166,7 @@ constexpr char kJSON_ADPF[] = R"(
         },
         {
             "Name": "SURFACEFLINGER",
-            "Path": "<AdpfConfig>:SURFACEFLINGER",
+            "Paths": ["<AdpfConfig>:SURFACEFLINGER"],
             "Values": [
                 "ADPF_DEFAULT",
                 "ADPF_SF"
@@ -289,7 +290,11 @@ constexpr char kJSON_ADPF[] = R"(
             "MaxRecordsNum": 50
         }
     ],
-    "GpuSysfsPath" : "/sys/devices/platform/123.abc"
+    "GpuSysfsPath" : "/sys/devices/platform/123.abc",
+    "OtherConfigs": {
+        "EnableMetricCollection": true,
+        "MaxNumOfCachedSessionMetrics": 100
+    }
 }
 )";
 
@@ -297,7 +302,7 @@ class HintManagerTest : public ::testing::Test, public HintManager {
   protected:
     HintManagerTest()
         : HintManager(nullptr, std::unordered_map<std::string, Hint>{},
-                      std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, {}) {
+                      std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, other_configs_) {
         android::base::SetMinimumLogSeverity(android::base::VERBOSE);
         prop_ = "vendor.pwhal.mode";
     }
@@ -306,16 +311,16 @@ class HintManagerTest : public ::testing::Test, public HintManager {
         // Set up 3 dummy nodes
         std::unique_ptr<TemporaryFile> tf = std::make_unique<TemporaryFile>();
         nodes_.emplace_back(new FileNode(
-            "n0", tf->path, {{"n0_value0"}, {"n0_value1"}, {"n0_value2"}}, 2,
-            false, false));
+            "n0", {tf->path}, {{"n0_value0"}, {"n0_value1"}, {"n0_value2"}}, 2,
+            false, false, false));
         files_.emplace_back(std::move(tf));
         tf = std::make_unique<TemporaryFile>();
         nodes_.emplace_back(new FileNode(
-            "n1", tf->path, {{"n1_value0"}, {"n1_value1"}, {"n1_value2"}}, 2,
-            true, true));
+            "n1", {tf->path}, {{"n1_value0"}, {"n1_value1"}, {"n1_value2"}}, 2,
+            true, true, false, true));
         files_.emplace_back(std::move(tf));
         nodes_.emplace_back(new PropertyNode(
-            "n2", prop_, {{"n2_value0"}, {"n2_value1"}, {"n2_value2"}}, 2,
+            "n2", {prop_}, {{"n2_value0"}, {"n2_value1"}, {"n2_value2"}}, 2,
             true));
         nm_ = new NodeLooperThread(std::move(nodes_));
         // Set up dummy actions
@@ -361,31 +366,33 @@ class HintManagerTest : public ::testing::Test, public HintManager {
     std::string json_doc_;
     std::string prop_;
     std::unordered_map<std::string, std::shared_ptr<AdpfConfig>> tag_adpfs_;
+    OtherConfigs other_configs_;
 };
 
-static inline void _VerifyPropertyValue(const std::string& path,
-                                        const std::string& value) {
-    std::string s = android::base::GetProperty(path, "");
-    EXPECT_EQ(value, s);
-}
+#define VERIFY_PROPERTY_VALUE(path, expected_value)           \
+    {                                                         \
+        std::string s = android::base::GetProperty(path, ""); \
+        EXPECT_EQ(expected_value, s);                         \
+    }
 
-static inline void _VerifyPathValue(const std::string& path,
-                                    const std::string& value) {
-    std::string s;
-    EXPECT_TRUE(android::base::ReadFileToString(path, &s)) << strerror(errno);
-    EXPECT_EQ(value, s);
-}
+#define VERIFY_PATH_VALUE(path, expected_value)                                    \
+    {                                                                              \
+        std::string s;                                                             \
+        EXPECT_TRUE(android::base::ReadFileToString(path, &s)) << strerror(errno); \
+        EXPECT_EQ(expected_value, s);                                              \
+    }
 
-static inline void _VerifyStats(const HintStats &stats, uint32_t count, uint64_t duration_min,
-                                uint64_t duration_max) {
-    EXPECT_EQ(stats.count, count);
-    EXPECT_GE(stats.duration_ms, duration_min);
-    EXPECT_LT(stats.duration_ms, duration_max);
-}
+#define VERIFY_STATS(stats, expected_count, expected_duration_min, expected_duration_max) \
+    {                                                                                     \
+        EXPECT_EQ(stats.count, expected_count);                                           \
+        EXPECT_GE(stats.duration_ms, expected_duration_min);                              \
+        EXPECT_LT(stats.duration_ms, expected_duration_max);                              \
+    }
 
 // Test GetHints
 TEST_F(HintManagerTest, GetHintsTest) {
-    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, {});
+    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_,
+                   other_configs_);
     EXPECT_TRUE(hm.Start());
     std::vector<std::string> hints = hm.GetHints();
     EXPECT_TRUE(hm.IsRunning());
@@ -396,9 +403,8 @@ TEST_F(HintManagerTest, GetHintsTest) {
 
 // Test GetHintStats
 TEST_F(HintManagerTest, GetHintStatsTest) {
-    auto hm =
-            std::make_unique<HintManager>(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(),
-                                          tag_adpfs_, std::optional<std::string>{});
+    auto hm = std::make_unique<HintManager>(
+            nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, other_configs_);
     EXPECT_TRUE(InitHintStatus(hm));
     EXPECT_TRUE(hm->Start());
     HintStats launch_stats(hm->GetHintStats("LAUNCH"));
@@ -411,18 +417,20 @@ TEST_F(HintManagerTest, GetHintStatsTest) {
 
 // Test initialization of default values
 TEST_F(HintManagerTest, HintInitDefaultTest) {
-    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, {});
+    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_,
+                   other_configs_);
     EXPECT_TRUE(hm.Start());
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
     EXPECT_TRUE(hm.IsRunning());
-    _VerifyPathValue(files_[0]->path, "");
-    _VerifyPathValue(files_[1]->path, "n1_value2");
-    _VerifyPropertyValue(prop_, "n2_value2");
+    VERIFY_PATH_VALUE(files_[0]->path, "");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value2");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value2");
 }
 
 // Test IsHintSupported
 TEST_F(HintManagerTest, HintSupportedTest) {
-    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, {});
+    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_,
+                   other_configs_);
     EXPECT_TRUE(hm.IsHintSupported("INTERACTION"));
     EXPECT_TRUE(hm.IsHintSupported("LAUNCH"));
     EXPECT_FALSE(hm.IsHintSupported("NO_SUCH_HINT"));
@@ -430,97 +438,95 @@ TEST_F(HintManagerTest, HintSupportedTest) {
 
 // Test hint/cancel/expire with dummy actions
 TEST_F(HintManagerTest, HintTest) {
-    auto hm =
-            std::make_unique<HintManager>(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(),
-                                          tag_adpfs_, std::optional<std::string>{});
+    auto hm = std::make_unique<HintManager>(
+            nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, other_configs_);
     EXPECT_TRUE(InitHintStatus(hm));
     EXPECT_TRUE(hm->Start());
     EXPECT_TRUE(hm->IsRunning());
     EXPECT_TRUE(hm->DoHint("INTERACTION"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0]->path, "n0_value1");
-    _VerifyPathValue(files_[1]->path, "n1_value1");
-    _VerifyPropertyValue(prop_, "n2_value1");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value1");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value1");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value1");
     // this won't change the expire time of INTERACTION hint
     EXPECT_TRUE(hm->DoHint("INTERACTION", 200ms));
     // now place new hint
     EXPECT_TRUE(hm->DoHint("LAUNCH"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0]->path, "n0_value0");
-    _VerifyPathValue(files_[1]->path, "n1_value0");
-    _VerifyPropertyValue(prop_, "n2_value0");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value0");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value0");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value0");
     EXPECT_TRUE(hm->DoHint("LAUNCH", 500ms));
     // "LAUNCH" node1 not expired
     std::this_thread::sleep_for(400ms);
-    _VerifyPathValue(files_[0]->path, "n0_value0");
-    _VerifyPathValue(files_[1]->path, "n1_value0");
-    _VerifyPropertyValue(prop_, "n2_value0");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value0");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value0");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value0");
     // "LAUNCH" node1 expired
     std::this_thread::sleep_for(100ms + kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0]->path, "n0_value0");
-    _VerifyPathValue(files_[1]->path, "n1_value1");
-    _VerifyPropertyValue(prop_, "n2_value1");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value0");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value1");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value1");
     EXPECT_TRUE(hm->EndHint("LAUNCH"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
     // "LAUNCH" canceled
-    _VerifyPathValue(files_[0]->path, "n0_value1");
-    _VerifyPathValue(files_[1]->path, "n1_value1");
-    _VerifyPropertyValue(prop_, "n2_value1");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value1");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value1");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value1");
     std::this_thread::sleep_for(200ms);
     // "INTERACTION" node0 expired
-    _VerifyPathValue(files_[0]->path, "n0_value2");
-    _VerifyPathValue(files_[1]->path, "n1_value1");
-    _VerifyPropertyValue(prop_, "n2_value2");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value2");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value1");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value2");
     EXPECT_TRUE(hm->EndHint("INTERACTION"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
     // "INTERACTION" canceled
-    _VerifyPathValue(files_[0]->path, "n0_value2");
-    _VerifyPathValue(files_[1]->path, "n1_value2");
-    _VerifyPropertyValue(prop_, "n2_value2");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value2");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value2");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value2");
 }
 
 // Test collecting stats with simple actions
 TEST_F(HintManagerTest, HintStatsTest) {
-    auto hm =
-            std::make_unique<HintManager>(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(),
-                                          tag_adpfs_, std::optional<std::string>{});
+    auto hm = std::make_unique<HintManager>(
+            nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, other_configs_);
     EXPECT_TRUE(InitHintStatus(hm));
     EXPECT_TRUE(hm->Start());
     EXPECT_TRUE(hm->IsRunning());
     EXPECT_TRUE(hm->DoHint("INTERACTION"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0]->path, "n0_value1");
-    _VerifyPathValue(files_[1]->path, "n1_value1");
-    _VerifyPropertyValue(prop_, "n2_value1");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value1");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value1");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value1");
     // now place "LAUNCH" hint with timeout of 500ms
     EXPECT_TRUE(hm->DoHint("LAUNCH", 500ms));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0]->path, "n0_value0");
-    _VerifyPathValue(files_[1]->path, "n1_value0");
-    _VerifyPropertyValue(prop_, "n2_value0");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value0");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value0");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value0");
     // "LAUNCH" expired
     std::this_thread::sleep_for(500ms + kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0]->path, "n0_value1");
-    _VerifyPathValue(files_[1]->path, "n1_value1");
-    _VerifyPropertyValue(prop_, "n2_value1");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value1");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value1");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value1");
     HintStats launch_stats(hm->GetHintStats("LAUNCH"));
     // Since duration is recorded at the next DoHint,
     // duration should be 0.
-    _VerifyStats(launch_stats, 1, 0, 100);
+    VERIFY_STATS(launch_stats, 1, 0, 100);
     std::this_thread::sleep_for(100ms + kSLEEP_TOLERANCE_MS);
     EXPECT_TRUE(hm->EndHint("INTERACTION"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
     // "INTERACTION" canceled
-    _VerifyPathValue(files_[0]->path, "n0_value2");
-    _VerifyPathValue(files_[1]->path, "n1_value2");
-    _VerifyPropertyValue(prop_, "n2_value2");
+    VERIFY_PATH_VALUE(files_[0]->path, "n0_value2");
+    VERIFY_PATH_VALUE(files_[1]->path, "n1_value2");
+    VERIFY_PROPERTY_VALUE(prop_, "n2_value2");
     HintStats interaction_stats(hm->GetHintStats("INTERACTION"));
-    _VerifyStats(interaction_stats, 1, 800, 900);
+    VERIFY_STATS(interaction_stats, 1, 800, 900);
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
     // Second LAUNCH hint sent to get the first duration recorded.
     EXPECT_TRUE(hm->DoHint("LAUNCH"));
     launch_stats = hm->GetHintStats("LAUNCH");
-    _VerifyStats(launch_stats, 2, 500, 600);
+    VERIFY_STATS(launch_stats, 2, 500, 600);
 }
 
 // Test parsing nodes
@@ -529,8 +535,8 @@ TEST_F(HintManagerTest, ParseNodesTest) {
     EXPECT_EQ(4u, nodes.size());
     EXPECT_EQ("CPUCluster0MinFreq", nodes[0]->GetName());
     EXPECT_EQ("CPUCluster1MinFreq", nodes[1]->GetName());
-    EXPECT_EQ(files_[0 + 2]->path, nodes[0]->GetPath());
-    EXPECT_EQ(files_[1 + 2]->path, nodes[1]->GetPath());
+    EXPECT_THAT(nodes[0]->GetPaths(), testing::ElementsAre(files_[0 + 2]->path));
+    EXPECT_THAT(nodes[1]->GetPaths(), testing::ElementsAre(files_[1 + 2]->path));
     EXPECT_EQ("1512000", nodes[0]->GetValues()[0]);
     EXPECT_EQ("1134000", nodes[0]->GetValues()[1]);
     EXPECT_EQ("384000", nodes[0]->GetValues()[2]);
@@ -544,8 +550,10 @@ TEST_F(HintManagerTest, ParseNodesTest) {
     // no dynamic_cast intentionally in Android
     EXPECT_FALSE(reinterpret_cast<FileNode*>(nodes[0].get())->GetHoldFd());
     EXPECT_TRUE(reinterpret_cast<FileNode*>(nodes[1].get())->GetHoldFd());
+    EXPECT_FALSE(reinterpret_cast<FileNode*>(nodes[0].get())->GetAllowFailure());
+    EXPECT_TRUE(reinterpret_cast<FileNode*>(nodes[1].get())->GetAllowFailure());
     EXPECT_EQ("ModeProperty", nodes[2]->GetName());
-    EXPECT_EQ(prop_, nodes[2]->GetPath());
+    EXPECT_THAT(nodes[2]->GetPaths(), testing::ElementsAre(prop_));
     EXPECT_EQ("HIGH", nodes[2]->GetValues()[0]);
     EXPECT_EQ("LOW", nodes[2]->GetValues()[1]);
     EXPECT_EQ("NONE", nodes[2]->GetValues()[2]);
@@ -615,8 +623,8 @@ TEST_F(HintManagerTest, ParsePropertyNodesEmptyValueTest) {
     EXPECT_EQ(4u, nodes.size());
     EXPECT_EQ("CPUCluster0MinFreq", nodes[0]->GetName());
     EXPECT_EQ("CPUCluster1MinFreq", nodes[1]->GetName());
-    EXPECT_EQ(files_[0 + 2]->path, nodes[0]->GetPath());
-    EXPECT_EQ(files_[1 + 2]->path, nodes[1]->GetPath());
+    EXPECT_THAT(nodes[0]->GetPaths(), testing::ElementsAre(files_[0 + 2]->path));
+    EXPECT_THAT(nodes[1]->GetPaths(), testing::ElementsAre(files_[1 + 2]->path));
     EXPECT_EQ("1512000", nodes[0]->GetValues()[0]);
     EXPECT_EQ("1134000", nodes[0]->GetValues()[1]);
     EXPECT_EQ("384000", nodes[0]->GetValues()[2]);
@@ -630,8 +638,10 @@ TEST_F(HintManagerTest, ParsePropertyNodesEmptyValueTest) {
     // no dynamic_cast intentionally in Android
     EXPECT_FALSE(reinterpret_cast<FileNode*>(nodes[0].get())->GetHoldFd());
     EXPECT_TRUE(reinterpret_cast<FileNode*>(nodes[1].get())->GetHoldFd());
+    EXPECT_FALSE(reinterpret_cast<FileNode*>(nodes[0].get())->GetAllowFailure());
+    EXPECT_TRUE(reinterpret_cast<FileNode*>(nodes[1].get())->GetAllowFailure());
     EXPECT_EQ("ModeProperty", nodes[2]->GetName());
-    EXPECT_EQ(prop_, nodes[2]->GetPath());
+    EXPECT_THAT(nodes[2]->GetPaths(), testing::ElementsAre(prop_));
     EXPECT_EQ("HIGH", nodes[2]->GetValues()[0]);
     EXPECT_EQ("", nodes[2]->GetValues()[1]);
     EXPECT_EQ("NONE", nodes[2]->GetValues()[2]);
@@ -755,51 +765,51 @@ TEST_F(HintManagerTest, GetFromJSONTest) {
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
     EXPECT_TRUE(hm->IsRunning());
     // Initial default value on Node0
-    _VerifyPathValue(files_[0 + 2]->path, "384000");
-    _VerifyPathValue(files_[1 + 2]->path, "");
-    _VerifyPropertyValue(prop_, "");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "384000");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "");
+    VERIFY_PROPERTY_VALUE(prop_, "");
     // Do INTERACTION
     EXPECT_TRUE(hm->DoHint("INTERACTION"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0 + 2]->path, "384000");
-    _VerifyPathValue(files_[1 + 2]->path, "1134000");
-    _VerifyPropertyValue(prop_, "LOW");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "384000");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "1134000");
+    VERIFY_PROPERTY_VALUE(prop_, "LOW");
     // Do LAUNCH
-    _VerifyPropertyValue("vendor.pwhal.enable.test", "1");
+    VERIFY_PROPERTY_VALUE("vendor.pwhal.enable.test", "1");
     EXPECT_TRUE(hm->DoHint("LAUNCH"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0 + 2]->path, "1134000");
-    _VerifyPathValue(files_[1 + 2]->path, "1512000");
-    _VerifyPropertyValue(prop_, "HIGH");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "1134000");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "1512000");
+    VERIFY_PROPERTY_VALUE(prop_, "HIGH");
     std::this_thread::sleep_for(500ms);
     // "LAUNCH" node0 expired
-    _VerifyPathValue(files_[0 + 2]->path, "384000");
-    _VerifyPathValue(files_[1 + 2]->path, "1512000");
-    _VerifyPropertyValue(prop_, "LOW");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "384000");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "1512000");
+    VERIFY_PROPERTY_VALUE(prop_, "LOW");
     EXPECT_TRUE(hm->EndHint("LAUNCH"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
     // "LAUNCH" canceled
-    _VerifyPathValue(files_[0 + 2]->path, "384000");
-    _VerifyPathValue(files_[1 + 2]->path, "1134000");
-    _VerifyPropertyValue(prop_, "LOW");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "384000");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "1134000");
+    VERIFY_PROPERTY_VALUE(prop_, "LOW");
     std::this_thread::sleep_for(300ms);
     // "INTERACTION" node1 expired
-    _VerifyPathValue(files_[0 + 2]->path, "384000");
-    _VerifyPathValue(files_[1 + 2]->path, "384000");
-    _VerifyPropertyValue(prop_, "NONE");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "384000");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "384000");
+    VERIFY_PROPERTY_VALUE(prop_, "NONE");
 
     // Disable action[2] of LAUNCH
     EXPECT_TRUE(hm->EndHint("LAUNCH"));
-    _VerifyPropertyValue("vendor.pwhal.enable.test", "1");
+    VERIFY_PROPERTY_VALUE("vendor.pwhal.enable.test", "1");
     EXPECT_TRUE(hm->DoHint("DISABLE_LAUNCH_ACT2"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPropertyValue("vendor.pwhal.enable.test", "0");
+    VERIFY_PROPERTY_VALUE("vendor.pwhal.enable.test", "0");
     EXPECT_TRUE(hm->DoHint("LAUNCH"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0 + 2]->path, "1134000");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "1134000");
     // action[2] have no effect.
-    _VerifyPathValue(files_[1 + 2]->path, "384000");
-    _VerifyPropertyValue(prop_, "HIGH");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "384000");
+    VERIFY_PROPERTY_VALUE(prop_, "HIGH");
     EXPECT_TRUE(hm->EndHint("LAUNCH"));
     EXPECT_TRUE(hm->EndHint("DISABLE_LAUNCH_ACT2"));
 
@@ -807,31 +817,31 @@ TEST_F(HintManagerTest, GetFromJSONTest) {
     EXPECT_TRUE(hm->DoHint("MASK_LAUNCH_MODE"));
     EXPECT_FALSE(hm->DoHint("LAUNCH"));  // should fail
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0 + 2]->path, "384000");
-    _VerifyPathValue(files_[1 + 2]->path, "384000");
-    _VerifyPropertyValue(prop_, "NONE");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "384000");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "384000");
+    VERIFY_PROPERTY_VALUE(prop_, "NONE");
 
     // UnMask LAUNCH and do LAUNCH
     EXPECT_TRUE(hm->EndHint("MASK_LAUNCH_MODE"));
     EXPECT_TRUE(hm->DoHint("LAUNCH"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0 + 2]->path, "1134000");
-    _VerifyPathValue(files_[1 + 2]->path, "1512000");
-    _VerifyPropertyValue(prop_, "HIGH");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "1134000");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "1512000");
+    VERIFY_PROPERTY_VALUE(prop_, "HIGH");
     // END_LAUNCH_MODE should deactivate LAUNCH
     EXPECT_TRUE(hm->DoHint("END_LAUNCH_MODE"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0 + 2]->path, "384000");
-    _VerifyPathValue(files_[1 + 2]->path, "384000");
-    _VerifyPropertyValue(prop_, "NONE");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "384000");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "384000");
+    VERIFY_PROPERTY_VALUE(prop_, "NONE");
     EXPECT_TRUE(hm->EndHint("END_LAUNCH_MODE"));
 
     // DO_LAUNCH_MODE should activate LAUNCH
     EXPECT_TRUE(hm->DoHint("DO_LAUNCH_MODE"));
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
-    _VerifyPathValue(files_[0 + 2]->path, "1134000");
-    _VerifyPathValue(files_[1 + 2]->path, "1512000");
-    _VerifyPropertyValue(prop_, "HIGH");
+    VERIFY_PATH_VALUE(files_[0 + 2]->path, "1134000");
+    VERIFY_PATH_VALUE(files_[1 + 2]->path, "1512000");
+    VERIFY_PROPERTY_VALUE(prop_, "HIGH");
 
     // Mask LAUNCH
     EXPECT_TRUE(hm->DoHint("MASK_LAUNCH_MODE"));
@@ -1135,5 +1145,28 @@ TEST_F(HintManagerTest, GpuConfigSupport) {
     EXPECT_EQ(profile->mGpuCapacityLoadUpHeadroom, 0);
 }
 
+TEST_F(HintManagerTest, OtherConfigs) {
+    // With other configurations
+    TemporaryFile json_file;
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
+    HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
+    ASSERT_TRUE(hm);
+
+    auto other_configs = hm->GetOtherConfigs();
+    EXPECT_EQ(other_configs.GPUSysfsPath, "/sys/devices/platform/123.abc");
+    EXPECT_TRUE(other_configs.enableMetricCollection);
+    EXPECT_EQ(other_configs.maxNumOfCachedSessionMetrics, 100);
+
+    // Without other configurations
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_RAW, json_file.path)) << strerror(errno);
+    hm = HintManager::GetFromJSON(json_file.path, false);
+    ASSERT_TRUE(hm);
+
+    other_configs = hm->GetOtherConfigs();
+    EXPECT_EQ(other_configs.GPUSysfsPath, std::nullopt);
+    EXPECT_EQ(other_configs.enableMetricCollection, std::nullopt);
+    EXPECT_EQ(other_configs.maxNumOfCachedSessionMetrics, std::nullopt);
+}
+
 }  // namespace perfmgr
 }  // namespace android
diff --git a/power-libperfmgr/libperfmgr/tests/JobQueueManagerTest.cc b/power-libperfmgr/libperfmgr/tests/JobQueueManagerTest.cc
new file mode 100644
index 00000000..476cb2ef
--- /dev/null
+++ b/power-libperfmgr/libperfmgr/tests/JobQueueManagerTest.cc
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
+#include "gtest/gtest.h"
+#include "perfmgr/JobQueueManager.h"
+#include "perfmgr/NodeLooperThread.h"
+
+namespace android {
+namespace perfmgr {
+
+const size_t OVER_POOL_SIZE = DEFAULT_POOL_SIZE + 4;
+
+// Helper function to create a Job for testing
+Job *createJob(const std::string &hint_type, int schedule_time, bool is_cancel = false) {
+    Job *job = new Job();
+    job->hint_type = hint_type;
+    job->schedule_time =
+            std::chrono::time_point<std::chrono::steady_clock>(std::chrono::seconds(schedule_time));
+    job->is_cancel = is_cancel;
+    return job;
+}
+
+// Test fixture class
+class JobQueueManagerTest : public ::testing::Test {
+  protected:
+    JobQueueManager jobMgr_;
+    void TearDown() override {
+        // Clean up any jobs that might be left in the queue
+        Job *job;
+        while ((job = jobMgr_.dequeueRequest()) != nullptr) {
+            delete job;
+        }
+    }
+};
+
+TEST_F(JobQueueManagerTest, TestEnqueueAndDequeue) {
+    Job *job1 = createJob("type1", 2);
+    Job *job2 = createJob("type2", 1);
+
+    jobMgr_.enqueueRequest(job1);
+    jobMgr_.enqueueRequest(job2);
+
+    Job *dequeuedJob1 = jobMgr_.dequeueRequest();
+    Job *dequeuedJob2 = jobMgr_.dequeueRequest();
+
+    ASSERT_NE(dequeuedJob1, nullptr);
+    ASSERT_NE(dequeuedJob2, nullptr);
+
+    // Verify that the jobs are dequeued in the correct order (based on schedule time)
+    ASSERT_EQ(dequeuedJob1->hint_type, "type2");
+    ASSERT_EQ(dequeuedJob2->hint_type, "type1");
+
+    delete dequeuedJob1;
+    delete dequeuedJob2;
+}
+
+TEST_F(JobQueueManagerTest, TestEmptyQueue) {
+    Job *dequeuedJob = jobMgr_.dequeueRequest();
+    ASSERT_EQ(dequeuedJob, nullptr);
+}
+
+TEST_F(JobQueueManagerTest, TestPoolAllocation) {
+    // Enqueue more jobs than the default pool size to force pool expansion.
+    for (int i = 0; i < OVER_POOL_SIZE; ++i) {
+        Job *job = createJob("test", i);
+        jobMgr_.enqueueRequest(job);
+    }
+
+    // Dequeue all of them to ensure the pool is reused
+    for (int i = 0; i < OVER_POOL_SIZE; ++i) {
+        Job *job = jobMgr_.dequeueRequest();
+        ASSERT_NE(job, nullptr);
+        delete job;
+    }
+
+    // Check if the queue is empty
+    Job *dequeuedJob = jobMgr_.dequeueRequest();
+    ASSERT_EQ(dequeuedJob, nullptr);
+}
+
+TEST_F(JobQueueManagerTest, TestJobReset) {
+    Job *job = createJob("test", 1);
+    jobMgr_.enqueueRequest(job);
+    Job *dequeuedJob = jobMgr_.dequeueRequest();
+    ASSERT_NE(dequeuedJob, nullptr);
+    ASSERT_EQ(dequeuedJob->hint_type, "test");
+    jobMgr_.returnJob(dequeuedJob);  // Return the job to the pool
+
+    // Now, enqueue another job
+    Job *job2 = createJob("new_test", 2);
+    jobMgr_.enqueueRequest(job2);
+    Job *dequeuedJob2 = jobMgr_.dequeueRequest();
+    ASSERT_NE(dequeuedJob2, nullptr);
+    ASSERT_EQ(dequeuedJob2->hint_type, "new_test");
+    jobMgr_.returnJob(dequeuedJob2);
+}
+
+TEST_F(JobQueueManagerTest, TestGetFreeJobAndReturnJob) {
+    // Get a free job
+    Job *job = jobMgr_.getFreeJob();
+    ASSERT_NE(job, nullptr);
+
+    // Set some data in the job
+    job->hint_type = "test_type";
+    job->schedule_time = std::chrono::steady_clock::now();
+    job->is_cancel = true;
+
+    // Return the job
+    jobMgr_.returnJob(job);
+
+    // Test the pool size, we allocate more than the pool size to verify it works.
+    // Also, verify all jobs are reset.
+    for (int i = 0; i < OVER_POOL_SIZE; i++) {
+        Job *job3 = jobMgr_.getFreeJob();
+        ASSERT_NE(job3, nullptr);
+        ASSERT_EQ(job3->hint_type, "");
+        ASSERT_EQ(job3->is_cancel, false);
+        jobMgr_.returnJob(job3);
+    }
+}
+
+}  // namespace perfmgr
+}  // namespace android
diff --git a/power-libperfmgr/libperfmgr/tests/NodeLooperThreadTest.cc b/power-libperfmgr/libperfmgr/tests/NodeLooperThreadTest.cc
index 8deccd4a..8b6280e9 100644
--- a/power-libperfmgr/libperfmgr/tests/NodeLooperThreadTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/NodeLooperThreadTest.cc
@@ -35,13 +35,13 @@ class NodeLooperThreadTest : public ::testing::Test {
     virtual void SetUp() {
         std::unique_ptr<TemporaryFile> tf = std::make_unique<TemporaryFile>();
         nodes_.emplace_back(new FileNode(
-            "n0", tf->path, {{"n0_value0"}, {"n0_value1"}, {"n0_value2"}}, 2,
-            false, false));
+            "n0", {tf->path}, {{"n0_value0"}, {"n0_value1"}, {"n0_value2"}}, 2,
+            false, false, false));
         files_.emplace_back(std::move(tf));
         tf = std::make_unique<TemporaryFile>();
         nodes_.emplace_back(new FileNode(
-            "n1", tf->path, {{"n1_value0"}, {"n1_value1"}, {"n1_value2"}}, 2,
-            true, true));
+            "n1", {tf->path}, {{"n1_value0"}, {"n1_value1"}, {"n1_value2"}}, 2,
+            true, true, false));
         files_.emplace_back(std::move(tf));
     }
 
diff --git a/power-libperfmgr/libperfmgr/tests/PropertyNodeTest.cc b/power-libperfmgr/libperfmgr/tests/PropertyNodeTest.cc
index 5dd88a10..ad6187b2 100644
--- a/power-libperfmgr/libperfmgr/tests/PropertyNodeTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/PropertyNodeTest.cc
@@ -18,8 +18,8 @@
 #include <android-base/properties.h>
 #include <android-base/stringprintf.h>
 #include <gtest/gtest.h>
+#include <gmock/gmock.h>
 
-#include <algorithm>
 #include <thread>
 
 #include "perfmgr/PropertyNode.h"
@@ -47,7 +47,7 @@ static inline const std::string _InitProperty(const std::string& path) {
 // Test init with no default value
 TEST(PropertyNodeTest, NoInitDefaultTest) {
     std::string key = _InitProperty("test.libperfmgr.key");
-    PropertyNode t("t", key, {{"value0"}, {"value1"}, {"value2"}}, 1, false);
+    PropertyNode t("t", {key}, {{"value0"}, {"value1"}, {"value2"}}, 1, false);
     t.Update(false);
     _VerifyPropertyValue(key, "");
 }
@@ -55,11 +55,11 @@ TEST(PropertyNodeTest, NoInitDefaultTest) {
 // Test init with default value
 TEST(PropertyNodeTest, InitDefaultTest) {
     std::string key = _InitProperty("test.libperfmgr.key");
-    PropertyNode t("t", key, {{"value0"}, {"value1"}, {"value2"}}, 1, true);
+    PropertyNode t("t", {key}, {{"value0"}, {"value1"}, {"value2"}}, 1, true);
     t.Update(false);
     _VerifyPropertyValue(key, "value1");
     std::string key2 = _InitProperty("test.libperfmgr.key2");
-    PropertyNode t2("t2", key2, {{"value0"}, {"value1"}, {"value2"}}, 0, true);
+    PropertyNode t2("t2", {key2}, {{"value0"}, {"value1"}, {"value2"}}, 0, true);
     t2.Update(false);
     _VerifyPropertyValue(key2, "value0");
 }
@@ -67,7 +67,7 @@ TEST(PropertyNodeTest, InitDefaultTest) {
 // Test DumpToFd
 TEST(PropertyNodeTest, DumpToFdTest) {
     std::string key = _InitProperty("test.libperfmgr.key");
-    PropertyNode t("test_dump", key, {{"value0"}, {"value1"}, {"value2"}}, 1,
+    PropertyNode t("test_dump", {key}, {{"value0"}, {"value1"}, {"value2"}}, 1,
                    true);
     t.Update(false);
     TemporaryFile dumptf;
@@ -89,7 +89,7 @@ TEST(PropertyNodeTest, DumpToFdTest) {
 // Test GetValueIndex
 TEST(PropertyNodeTest, GetValueIndexTest) {
     std::string key = _InitProperty("test.libperfmgr.key");
-    PropertyNode t("t", key, {{"value0"}, {"value1"}, {"value2"}}, 1, false);
+    PropertyNode t("t", {key}, {{"value0"}, {"value1"}, {"value2"}}, 1, false);
     std::size_t index = 0;
     EXPECT_TRUE(t.GetValueIndex("value2", &index));
     EXPECT_EQ(2u, index);
@@ -101,7 +101,7 @@ TEST(PropertyNodeTest, GetValueIndexTest) {
 // Test GetValues
 TEST(PropertyNodeTest, GetValuesTest) {
     std::string key = _InitProperty("test.libperfmgr.key");
-    PropertyNode t("t", key, {{"value0"}, {"value1"}, {"value2"}}, 1, false);
+    PropertyNode t("t", {key}, {{"value0"}, {"value1"}, {"value2"}}, 1, false);
     std::vector values = t.GetValues();
     EXPECT_EQ(3u, values.size());
     EXPECT_EQ("value0", values[0]);
@@ -113,9 +113,9 @@ TEST(PropertyNodeTest, GetValuesTest) {
 TEST(PropertyNodeTest, GetPropertiesTest) {
     std::string test_name = "TESTREQ_1";
     std::string test_path = "TEST_PATH";
-    PropertyNode t(test_name, test_path, {}, 0, false);
+    PropertyNode t(test_name, {test_path}, {}, 0, false);
     EXPECT_EQ(test_name, t.GetName());
-    EXPECT_EQ(test_path, t.GetPath());
+    EXPECT_THAT(t.GetPaths(), testing::ElementsAre(test_path));
     EXPECT_EQ(0u, t.GetValues().size());
     EXPECT_EQ(0u, t.GetDefaultIndex());
     EXPECT_FALSE(t.GetResetOnInit());
@@ -124,7 +124,7 @@ TEST(PropertyNodeTest, GetPropertiesTest) {
 // Test add request
 TEST(PropertyNodeTest, AddRequestTest) {
     std::string key = _InitProperty("test.libperfmgr.key");
-    PropertyNode t("t", key, {{"value0"}, {"value1"}, {""}}, 2, true);
+    PropertyNode t("t", {key}, {{"value0"}, {"value1"}, {""}}, 2, true);
     auto start = std::chrono::steady_clock::now();
     EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
     std::chrono::milliseconds expire_time = t.Update(true);
@@ -154,7 +154,7 @@ TEST(PropertyNodeTest, AddRequestTest) {
 // Test remove request
 TEST(PropertyNodeTest, RemoveRequestTest) {
     std::string key = _InitProperty("test.libperfmgr.key");
-    PropertyNode t("t", key, {{"value0"}, {"value1"}, {"value2"}}, 2, true);
+    PropertyNode t("t", {key}, {{"value0"}, {"value1"}, {"value2"}}, 2, true);
     auto start = std::chrono::steady_clock::now();
     EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
     std::chrono::milliseconds expire_time = t.Update(true);
@@ -184,7 +184,7 @@ TEST(PropertyNodeTest, RemoveRequestTest) {
 // Test add request
 TEST(PropertyNodeTest, AddRequestTestOverride) {
     std::string key = _InitProperty("test.libperfmgr.key");
-    PropertyNode t("t", key, {{"value0"}, {"value1"}, {"value2"}}, 2, true);
+    PropertyNode t("t", {key}, {{"value0"}, {"value1"}, {"value2"}}, 2, true);
     auto start = std::chrono::steady_clock::now();
     EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
     std::chrono::milliseconds expire_time = t.Update(true);
diff --git a/powerstats/Android.bp b/powerstats/Android.bp
index 2b0ffa1f..ea4c99f9 100644
--- a/powerstats/Android.bp
+++ b/powerstats/Android.bp
@@ -66,16 +66,17 @@ filegroup {
     srcs: ["android.hardware.power.stats-service.pixel.rc"],
 }
 
-filegroup {
+vintf_fragment {
     name: "pixel_powerstats_xml",
-    srcs: ["android.hardware.power.stats-service.pixel.xml"],
+    src: "android.hardware.power.stats-service.pixel.xml",
+    vendor: true,
 }
 
 cc_defaults {
     name: "powerstats_pixel_binary_defaults",
     defaults: ["powerstats_pixel_defaults"],
     init_rc: [":pixel_powerstats_rc"],
-    vintf_fragments: [":pixel_powerstats_xml"],
+    vintf_fragment_modules: ["pixel_powerstats_xml"],
     relative_install_path: "hw",
     proprietary: true,
     shared_libs: [
diff --git a/powerstats/PowerStatsAidl.cpp b/powerstats/PowerStatsAidl.cpp
index bd7ba36b..cbebfa79 100644
--- a/powerstats/PowerStatsAidl.cpp
+++ b/powerstats/PowerStatsAidl.cpp
@@ -136,11 +136,27 @@ ndk::ScopedAStatus PowerStats::getEnergyConsumed(const std::vector<int32_t> &in_
         return ndk::ScopedAStatus::ok();
     }
 
+    // Refresh all reading once only, to prevent refresh multiple times and
+    // putting pressure on the odpm reading in the kernel and PMIC
+    std::vector<EnergyMeasurement> energyData;
+    readEnergyMeter({}, &energyData);
+
+    return getEnergyConsumed(in_energyConsumerIds, energyData, _aidl_return);
+}
+
+ndk::ScopedAStatus PowerStats::getEnergyConsumed(
+        const std::vector<int32_t> &in_energyConsumerIds,
+        const std::vector<EnergyMeasurement> &in_energyMeasurement,
+        std::vector<EnergyConsumerResult> *_aidl_return) {
+    if (mEnergyConsumers.empty()) {
+        return ndk::ScopedAStatus::ok();
+    }
+
     // If in_powerEntityIds is empty then return data for all supported energy consumers
     if (in_energyConsumerIds.empty()) {
         std::vector<int32_t> v(mEnergyConsumerInfos.size());
         std::iota(std::begin(v), std::end(v), 0);
-        return getEnergyConsumed(v, _aidl_return);
+        return getEnergyConsumed(v, in_energyMeasurement, _aidl_return);
     }
 
     for (const auto id : in_energyConsumerIds) {
@@ -149,7 +165,7 @@ ndk::ScopedAStatus PowerStats::getEnergyConsumed(const std::vector<int32_t> &in_
             return ndk::ScopedAStatus(AStatus_fromExceptionCode(EX_ILLEGAL_ARGUMENT));
         }
 
-        auto resopt = mEnergyConsumers[id]->getEnergyConsumed();
+        auto resopt = mEnergyConsumers[id]->getEnergyConsumed(in_energyMeasurement);
         if (resopt) {
             EnergyConsumerResult res = resopt.value();
             res.id = id;
@@ -220,7 +236,8 @@ void PowerStats::getChannelNames(std::unordered_map<int32_t, std::string> *chann
     }
 }
 
-void PowerStats::dumpEnergyMeter(std::ostringstream &oss, bool delta) {
+void PowerStats::dumpEnergyMeter(std::ostringstream &oss, bool delta,
+                                 const std::vector<EnergyMeasurement> &energyData) {
     const char *headerFormat = "  %32s   %18s\n";
     const char *dataFormat = "  %32s   %14.2f mWs\n";
     const char *headerFormatDelta = "  %32s   %18s (%14s)\n";
@@ -231,9 +248,6 @@ void PowerStats::dumpEnergyMeter(std::ostringstream &oss, bool delta) {
 
     oss << "\n============= PowerStats HAL 2.0 energy meter ==============\n";
 
-    std::vector<EnergyMeasurement> energyData;
-    readEnergyMeter({}, &energyData);
-
     if (delta) {
         static std::vector<EnergyMeasurement> prevEnergyData;
         ::android::base::boot_clock::time_point curTime = ::android::base::boot_clock::now();
@@ -373,11 +387,12 @@ void PowerStats::dumpStateResidency(std::ostringstream &oss, bool delta) {
     oss << "========== End of PowerStats HAL 2.0 state residencies ==========\n";
 }
 
-void PowerStats::dumpEnergyConsumer(std::ostringstream &oss, bool delta) {
+void PowerStats::dumpEnergyConsumer(std::ostringstream &oss, bool delta,
+                                    const std::vector<EnergyMeasurement> &energyData) {
     (void)delta;
 
     std::vector<EnergyConsumerResult> results;
-    getEnergyConsumed({}, &results);
+    getEnergyConsumed({}, energyData, &results);
 
     oss << "\n============= PowerStats HAL 2.0 energy consumers ==============\n";
 
@@ -401,11 +416,16 @@ binder_status_t PowerStats::dump(int fd, const char **args, uint32_t numArgs) {
     // Generate debug output for state residency
     dumpStateResidency(oss, delta);
 
+    // Refresh all reading once only, to prevent refresh multiple times and
+    // putting pressure on the odpm reading in the kernel and PMIC
+    std::vector<EnergyMeasurement> energyData;
+    readEnergyMeter({}, &energyData);
+
     // Generate debug output for energy consumer
-    dumpEnergyConsumer(oss, delta);
+    dumpEnergyConsumer(oss, delta, energyData);
 
     // Generate debug output energy meter
-    dumpEnergyMeter(oss, delta);
+    dumpEnergyMeter(oss, delta, energyData);
 
     ::android::base::WriteStringToFd(oss.str(), fd);
     fsync(fd);
diff --git a/powerstats/dataproviders/PowerStatsEnergyConsumer.cpp b/powerstats/dataproviders/PowerStatsEnergyConsumer.cpp
index 0b641659..38db9353 100644
--- a/powerstats/dataproviders/PowerStatsEnergyConsumer.cpp
+++ b/powerstats/dataproviders/PowerStatsEnergyConsumer.cpp
@@ -81,7 +81,7 @@ bool PowerStatsEnergyConsumer::addEnergyMeter(std::set<std::string> channelNames
 
     for (const auto &c : channels) {
         if (channelNames.count(c.name)) {
-            mChannelIds.push_back(c.id);
+            mChannelIds.insert(c.id);
         }
     }
 
@@ -144,18 +144,21 @@ bool PowerStatsEnergyConsumer::addAttribution(std::unordered_map<int32_t, std::s
     return (mCoefficients.size() == stateCoeffs.size());
 }
 
-std::optional<EnergyConsumerResult> PowerStatsEnergyConsumer::getEnergyConsumed() {
+std::optional<EnergyConsumerResult> PowerStatsEnergyConsumer::getEnergyConsumed(
+        const std::vector<EnergyMeasurement> &energyData) {
     int64_t totalEnergyUWs = 0;
     int64_t timestampMs = 0;
 
     if (!mChannelIds.empty()) {
-        std::vector<EnergyMeasurement> measurements;
-        if (mPowerStats->readEnergyMeter(mChannelIds, &measurements).isOk()) {
-            for (const auto &m : measurements) {
-                totalEnergyUWs += m.energyUWs;
-                timestampMs = m.timestampMs;
+        int found = 0;
+        for (const auto &e : energyData) {
+            if (mChannelIds.count(e.id)) {
+                totalEnergyUWs += e.energyUWs;
+                timestampMs = e.timestampMs;
+                found++;
             }
-        } else {
+        }
+        if (found != mChannelIds.size()) {
             LOG(ERROR) << "Failed to read energy meter";
             return {};
         }
diff --git a/powerstats/include/PowerStatsAidl.h b/powerstats/include/PowerStatsAidl.h
index c9910651..cc1b8a06 100644
--- a/powerstats/include/PowerStatsAidl.h
+++ b/powerstats/include/PowerStatsAidl.h
@@ -43,7 +43,8 @@ class PowerStats : public BnPowerStats {
       public:
         virtual ~IEnergyConsumer() = default;
         virtual std::pair<EnergyConsumerType, std::string> getInfo() = 0;
-        virtual std::optional<EnergyConsumerResult> getEnergyConsumed() = 0;
+        virtual std::optional<EnergyConsumerResult> getEnergyConsumed(
+                const std::vector<EnergyMeasurement> &energyData) = 0;
         virtual std::string getConsumerName() = 0;
     };
 
@@ -85,8 +86,13 @@ class PowerStats : public BnPowerStats {
                                  const std::vector<StateResidencyResult> &results);
     void dumpStateResidencyOneShot(std::ostringstream &oss,
                                    const std::vector<StateResidencyResult> &results);
-    void dumpEnergyConsumer(std::ostringstream &oss, bool delta);
-    void dumpEnergyMeter(std::ostringstream &oss, bool delta);
+    void dumpEnergyConsumer(std::ostringstream &oss, bool delta,
+                            const std::vector<EnergyMeasurement> &energyData);
+    void dumpEnergyMeter(std::ostringstream &oss, bool delta,
+                         const std::vector<EnergyMeasurement> &energyData);
+    ndk::ScopedAStatus getEnergyConsumed(const std::vector<int32_t> &in_energyConsumerIds,
+                                         const std::vector<EnergyMeasurement> &in_energyMeasurement,
+                                         std::vector<EnergyConsumerResult> *_aidl_return);
 
     std::vector<std::unique_ptr<IStateResidencyDataProvider>> mStateResidencyDataProviders;
     std::vector<PowerEntity> mPowerEntityInfos;
diff --git a/powerstats/include/dataproviders/PowerStatsEnergyConsumer.h b/powerstats/include/dataproviders/PowerStatsEnergyConsumer.h
index a37520b6..05a3171e 100644
--- a/powerstats/include/dataproviders/PowerStatsEnergyConsumer.h
+++ b/powerstats/include/dataproviders/PowerStatsEnergyConsumer.h
@@ -17,12 +17,13 @@
 #pragma once
 
 #include <PowerStatsAidl.h>
-#include "PowerStatsEnergyAttribution.h"
-
 #include <utils/RefBase.h>
 
 #include <map>
 #include <set>
+#include <unordered_set>
+
+#include "PowerStatsEnergyAttribution.h"
 
 namespace aidl {
 namespace android {
@@ -64,7 +65,8 @@ class PowerStatsEnergyConsumer : public PowerStats::IEnergyConsumer {
 
     std::pair<EnergyConsumerType, std::string> getInfo() override { return {kType, kName}; }
 
-    std::optional<EnergyConsumerResult> getEnergyConsumed() override;
+    std::optional<EnergyConsumerResult> getEnergyConsumed(
+            const std::vector<EnergyMeasurement> &energyData) override;
 
     std::string getConsumerName() override;
 
@@ -79,7 +81,7 @@ class PowerStatsEnergyConsumer : public PowerStats::IEnergyConsumer {
     const EnergyConsumerType kType;
     const std::string kName;
     std::shared_ptr<PowerStats> mPowerStats;
-    std::vector<int32_t> mChannelIds;
+    std::unordered_set<int32_t> mChannelIds;
     int32_t mPowerEntityId;
     bool mWithAttribution;
     std::unordered_map<int32_t, std::string> mAttrInfoPath;
diff --git a/thermal/Android.bp b/thermal/Android.bp
index cc088b22..ad686d6c 100644
--- a/thermal/Android.bp
+++ b/thermal/Android.bp
@@ -20,7 +20,7 @@ cc_binary {
     ],
     vendor: true,
     relative_install_path: "hw",
-    vintf_fragments: [
+    vintf_fragment_modules: [
         "android.hardware.thermal-service.pixel.xml",
     ],
     init_rc: [
@@ -65,6 +65,12 @@ cc_binary {
     ],
 }
 
+vintf_fragment {
+    name: "android.hardware.thermal-service.pixel.xml",
+    src: "android.hardware.thermal-service.pixel.xml",
+    vendor: true,
+}
+
 cc_test {
     name: "libthermaltest",
     vendor: true,
diff --git a/thermal/Thermal.cpp b/thermal/Thermal.cpp
index dac1c1f4..39e668c7 100644
--- a/thermal/Thermal.cpp
+++ b/thermal/Thermal.cpp
@@ -719,13 +719,22 @@ void Thermal::dumpThermalData(int fd, const char **args, uint32_t numArgs) {
                     boot_clock::time_point::min()) {
                     continue;
                 }
+                std::stringstream count_threshold_counted_log;
+                if (sensor_status_pair.second.count_threshold_counted.size()) {
+                    count_threshold_counted_log << std::boolalpha;
+                    count_threshold_counted_log << " CountThresholdCounted: [";
+                    for (bool state : sensor_status_pair.second.count_threshold_counted) {
+                        count_threshold_counted_log << state << " ";
+                    }
+                    count_threshold_counted_log << "]";
+                }
                 dump_buf << " Name: " << sensor_status_pair.first
                          << " CachedValue: " << sensor_status_pair.second.thermal_cached.temp
                          << " TimeToCache: "
                          << std::chrono::duration_cast<std::chrono::milliseconds>(
                                     now - sensor_status_pair.second.thermal_cached.timestamp)
                                     .count()
-                         << "ms" << std::endl;
+                         << "ms" << count_threshold_counted_log.str() << std::endl;
             }
         }
         {
diff --git a/thermal/tests/thermal_config_field_names.txt b/thermal/tests/thermal_config_field_names.txt
index a2a31d17..8a87d158 100644
--- a/thermal/tests/thermal_config_field_names.txt
+++ b/thermal/tests/thermal_config_field_names.txt
@@ -10,6 +10,9 @@ Combination
 CombinationType
 Configs
 CoolingDevices
+CountThresholdHysteresis
+ExcludedPowerInfo
+ExcludedPowerRailsLog
 Formula
 Hidden
 HotHysteresis
@@ -17,27 +20,41 @@ HotThreshold
 I_Cutoff
 I_Default
 I_Max
+I_Trend
 Include
 K_D
 K_I
+K_Io
+K_Iu
 K_Po
 K_Pu
 LimitInfo
 LoggingName
+LogInfo
+LogIntervalMs
 MaxAllocPower
 MaxReleaseStep
 MaxThrottleStep
 MinAllocPower
+MinPollingCount
+MinStuckDuration
 ModelPath
 Monitor
 Multiplier
 Name
 Offset
+OffsetThresholds
+OffsetValues
 Outlier
 OutputLabelCount
 PassiveDelay
+PowerSampleCount
 PIDInfo
 PollingDelay
+PowerRail
+PowerRails
+PowerSampleDelay
+PowerWeight
 PredictionDuration
 PreviousSampleCount
 RecordWithDefaultThreshold
@@ -48,14 +65,21 @@ SendPowerHint
 Sensors
 S_Power
 Stats
+Stuck
+StepRatio
 SupportPrediction
 SupportUnderSampling
+TempPath
+TempPathType
 TempRange
+TempStuck
+ThermalSampleCount
 Thresholds
 TimeResolution
 TriggerSensor
 TripPointIgnorable
 Type
 Version
+VirtualRails
 VirtualSensor
-VrThreshold
\ No newline at end of file
+VrThreshold
diff --git a/thermal/thermal-helper.cpp b/thermal/thermal-helper.cpp
index 43792a59..50c2c431 100644
--- a/thermal/thermal-helper.cpp
+++ b/thermal/thermal-helper.cpp
@@ -24,11 +24,8 @@
 #include <android-base/strings.h>
 #include <utils/Trace.h>
 
-#include <filesystem>
-#include <iterator>
 #include <set>
 #include <sstream>
-#include <thread>
 #include <vector>
 
 namespace aidl {
@@ -97,23 +94,28 @@ std::unordered_map<std::string, std::string> parseThermalPathMap(std::string_vie
 
 std::unordered_map<std::string, std::string> parsePowerCapPathMap(void) {
     std::unordered_map<std::string, std::string> path_map;
-    std::error_code ec;
-
-    if (!std::filesystem::exists(kPowerCapRoot, ec)) {
-        LOG(INFO) << "powercap root " << kPowerCapRoot << " does not exist, ec " << ec.message();
+    std::unique_ptr<DIR, int (*)(DIR *)> dir(opendir(kPowerCapRoot.data()), closedir);
+    if (!dir) {
         return path_map;
     }
 
-    for (const auto &entry : std::filesystem::directory_iterator(kPowerCapRoot)) {
-        std::string path = ::android::base::StringPrintf("%s/%s", entry.path().c_str(),
-                                                         kPowerCapNameFile.data());
+    while (struct dirent *dp = readdir(dir.get())) {
+        if (dp->d_type != DT_LNK) {
+            continue;
+        }
+
+        std::string path = ::android::base::StringPrintf("%s/%s/%s", kPowerCapRoot.data(),
+                                                         dp->d_name, kPowerCapNameFile.data());
+
         std::string name;
-        if (::android::base::ReadFileToString(path, &name)) {
-            path_map.emplace(::android::base::Trim(name), entry.path());
-        } else {
-            PLOG(ERROR) << "Failed to read from " << path << ", errno " << errno;
+        if (!::android::base::ReadFileToString(path, &name)) {
+            continue;
         }
+
+        path_map.emplace(::android::base::Trim(name),
+                         ::android::base::StringPrintf("%s/%s", kPowerCapRoot.data(), dp->d_name));
     }
+
     return path_map;
 }
 
@@ -194,6 +196,9 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
         ret = false;
     }
 
+    ParseThermalLogInfo(config, &log_status_);
+    log_status_.prev_log_time = boot_clock::now();
+
     auto cdev_map = parseThermalPathMap(kCoolingDevicePrefix.data());
     auto powercap_map = parsePowerCapPathMap();
 
@@ -238,16 +243,30 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
     }
 
     for (auto &[sensor_name, sensor_info] : sensor_info_map_) {
+        std::vector<bool> count_threshold_counted;
+
+        if (sensor_info.virtual_sensor_info != nullptr &&
+            sensor_info.virtual_sensor_info->formula == FormulaOption::COUNT_THRESHOLD) {
+            count_threshold_counted.resize(sensor_info.virtual_sensor_info->coefficients.size());
+            std::fill(count_threshold_counted.begin(), count_threshold_counted.end(), false);
+        }
+
         sensor_status_map_[sensor_name] = {
                 .severity = ThrottlingSeverity::NONE,
                 .prev_hot_severity = ThrottlingSeverity::NONE,
                 .prev_cold_severity = ThrottlingSeverity::NONE,
                 .last_update_time = boot_clock::time_point::min(),
                 .thermal_cached = {NAN, boot_clock::time_point::min()},
+                .count_threshold_counted = count_threshold_counted,
                 .pending_notification = false,
                 .override_status = {nullptr, false, false},
         };
 
+        for (int i = 0; i < sensor_info.thermal_sample_count; i++) {
+            sensor_status_map_[sensor_name].thermal_history.push(
+                    {NAN, boot_clock::time_point::min()});
+        }
+
         if (sensor_info.throttling_info != nullptr) {
             if (!thermal_throttling_.registerThermalThrottling(
                         sensor_name, sensor_info.throttling_info, cooling_device_info_map_)) {
@@ -587,7 +606,7 @@ SensorReadStatus ThermalHelperImpl::readTemperature(std::string_view sensor_name
     const auto &sensor_info = sensor_info_map_.at(sensor_name.data());
     out->type = sensor_info.type;
     out->name = sensor_name.data();
-    out->value = temp * sensor_info.multiplier;
+    out->value = TEMP_CONVERSION(temp, sensor_info);
 
     std::pair<ThrottlingSeverity, ThrottlingSeverity> status =
             std::make_pair(ThrottlingSeverity::NONE, ThrottlingSeverity::NONE);
@@ -800,20 +819,27 @@ bool ThermalHelperImpl::initializeSensorMap(
         if (sensor_info_pair.second.virtual_sensor_info != nullptr) {
             continue;
         }
-        if (!path_map.count(sensor_name.data())) {
-            LOG(ERROR) << "Could not find " << sensor_name << " in sysfs";
-            return false;
-        }
 
-        std::string path;
-        if (sensor_info_pair.second.temp_path.empty()) {
-            path = ::android::base::StringPrintf("%s/%s", path_map.at(sensor_name.data()).c_str(),
-                                                 kSensorTempSuffix.data());
-        } else {
-            path = sensor_info_pair.second.temp_path;
-        }
+        auto path = sensor_info_pair.second.temp_path;
+        const auto &path_type = sensor_info_pair.second.temp_path_type;
+        // If of SYSFS path type, ensure the sensor name is in the path map.
+        if (path_type == TempPathType::SYSFS) {
+            if (!path_map.contains(sensor_name.data())) {
+                LOG(ERROR) << "Could not find " << sensor_name << " in sysfs";
+                return false;
+            }
 
-        if (!thermal_sensors_.addThermalFile(sensor_name, path)) {
+            if (path.empty()) {
+                path = ::android::base::StringPrintf(
+                        "%s/%s", path_map.at(sensor_name.data()).c_str(), kSensorTempSuffix.data());
+            }
+        } else if (path_type == TempPathType::DEVICE_PROPERTY) {
+            if (path.empty()) {
+                LOG(ERROR) << "Empty device property path for sensor: " << sensor_name;
+                return false;
+            }
+        }
+        if (!thermal_sensors_.addThermalFile(sensor_name, path, path_type)) {
             LOG(ERROR) << "Could not add " << sensor_name << "to sensors map";
             return false;
         }
@@ -1152,7 +1178,7 @@ ThrottlingSeverity ThermalHelperImpl::getSeverityReference(std::string_view sens
     for (size_t i = 0; i < severity_ref_sensors.size(); i++) {
         Temperature temp;
         if (readTemperature(severity_ref_sensors[i], &temp, false) != SensorReadStatus::OKAY) {
-            return ThrottlingSeverity::NONE;
+            continue;
         }
         LOG(VERBOSE) << sensor_name << "'s severity reference " << severity_ref_sensors[i]
                      << " reading:" << toString(temp.throttlingStatus);
@@ -1391,6 +1417,25 @@ bool ThermalHelperImpl::readTemperaturePredictions(std::string_view sensor_name,
     return true;
 }
 
+// return thermal rising trend per min
+float ThermalHelperImpl::getThermalRising(const SensorStatus &sensor_status,
+                                          const ThermalSample &curr_sample) {
+    static constexpr int kMsecPerMin = 60000;
+    if (sensor_status.thermal_history.size() == 0) {
+        return NAN;
+    }
+    const auto last_sample = sensor_status.thermal_history.front();
+    if (std::isnan(last_sample.temp) || curr_sample.timestamp <= last_sample.timestamp) {
+        return NAN;
+    }
+
+    return (curr_sample.temp - last_sample.temp) /
+           std::chrono::duration_cast<std::chrono::milliseconds>(curr_sample.timestamp -
+                                                                 last_sample.timestamp)
+                   .count() *
+           kMsecPerMin;
+}
+
 constexpr int kTranTimeoutParam = 2;
 
 SensorReadStatus ThermalHelperImpl::readThermalSensor(
@@ -1398,7 +1443,6 @@ SensorReadStatus ThermalHelperImpl::readThermalSensor(
         std::map<std::string, float> *sensor_log_map) {
     std::string file_reading;
     boot_clock::time_point now = boot_clock::now();
-
     ATRACE_NAME(StringPrintf("ThermalHelper::readThermalSensor - %s", sensor_name.data()).c_str());
     if (!(sensor_info_map_.count(sensor_name.data()) &&
           sensor_status_map_.count(sensor_name.data()))) {
@@ -1441,6 +1485,7 @@ SensorReadStatus ThermalHelperImpl::readThermalSensor(
         *temp = std::atof(::android::base::Trim(file_reading).c_str());
     } else {
         const auto &linked_sensors_size = sensor_info.virtual_sensor_info->linked_sensors.size();
+        std::vector<bool> count_threshold_counted(linked_sensors_size, false);
         std::vector<float> sensor_readings(linked_sensors_size, NAN);
 
         // Calculate temperature of each of the linked sensor
@@ -1490,9 +1535,27 @@ SensorReadStatus ThermalHelperImpl::readThermalSensor(
                 }
                 switch (sensor_info.virtual_sensor_info->formula) {
                     case FormulaOption::COUNT_THRESHOLD:
-                        if ((coefficient < 0 && sensor_readings[i] < -coefficient) ||
-                            (coefficient >= 0 && sensor_readings[i] >= coefficient))
-                            temp_val += 1;
+                        if (coefficient < 0) {
+                            if (sensor_status.count_threshold_counted[i]) {
+                                coefficient +=
+                                        sensor_info.virtual_sensor_info->count_threshold_hyst[i];
+                            }
+
+                            if (sensor_readings[i] < -coefficient) {
+                                temp_val += 1;
+                                count_threshold_counted[i] = true;
+                            }
+                        } else {
+                            if (sensor_status.count_threshold_counted[i]) {
+                                coefficient -=
+                                        sensor_info.virtual_sensor_info->count_threshold_hyst[i];
+                            }
+
+                            if (sensor_readings[i] >= coefficient) {
+                                temp_val += 1;
+                                count_threshold_counted[i] = true;
+                            }
+                        }
                         break;
                     case FormulaOption::WEIGHTED_AVG:
                         temp_val += sensor_readings[i] * coefficient;
@@ -1515,6 +1578,10 @@ SensorReadStatus ThermalHelperImpl::readThermalSensor(
                 }
             }
             *temp = (temp_val + sensor_info.virtual_sensor_info->offset);
+            if (sensor_info.virtual_sensor_info->formula == FormulaOption::COUNT_THRESHOLD) {
+                std::unique_lock<std::shared_mutex> _lock(sensor_status_map_mutex_);
+                sensor_status.count_threshold_counted = count_threshold_counted;
+            }
         }
     }
 
@@ -1532,7 +1599,9 @@ SensorReadStatus ThermalHelperImpl::readThermalSensor(
         sensor_status.thermal_cached.temp = *temp;
         sensor_status.thermal_cached.timestamp = now;
     }
-    auto real_temp = (*temp) * sensor_info.multiplier;
+
+    auto real_temp = TEMP_CONVERSION(*temp, sensor_info);
+
     thermal_stats_helper_.updateSensorTempStatsByThreshold(sensor_name, real_temp);
     return SensorReadStatus::OKAY;
 }
@@ -1704,11 +1773,25 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
                 }
             }
 
+            float dt_per_min = NAN;
+            if (sensor_info.thermal_sample_count) {
+                std::unique_lock<std::shared_mutex> _lock(sensor_status_map_mutex_);
+                ThermalSample curr_sample = {temp.value, now};
+                dt_per_min = getThermalRising(sensor_status, curr_sample);
+                if (sensor_status.thermal_history.size()) {
+                    sensor_status.thermal_history.pop();
+                    sensor_status.thermal_history.push(curr_sample);
+                } else {
+                    LOG(ERROR) << "Sensor " << name_status_pair.first
+                               << ": thermal_history size should not be zero";
+                }
+            }
+
             // update thermal throttling request
             thermal_throttling_.thermalThrottlingUpdate(
                     temp, sensor_info, sensor_status.severity, time_elapsed_ms,
                     power_files_.GetPowerStatusMap(), cooling_device_info_map_, max_throttling,
-                    sensor_predictions);
+                    sensor_predictions, dt_per_min);
         }
 
         thermal_throttling_.computeCoolingDevicesRequest(
@@ -1744,10 +1827,13 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
         LOG(ERROR) << "Failed to report " << count_failed_reporting << " thermal stats";
     }
 
-    const auto since_last_power_log_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
-            now - power_files_.GetPrevPowerLogTime());
-    if ((since_last_power_log_ms >= kPowerLogIntervalMs) || (shutdown_severity_reached)) {
-        power_files_.logPowerStatus(now);
+    const auto since_last_log_ms =
+            std::chrono::duration_cast<std::chrono::milliseconds>(now - log_status_.prev_log_time);
+
+    if (since_last_log_ms >= log_status_.log_interval_ms || (shutdown_severity_reached)) {
+        power_files_.logPowerStatus(log_status_.excluded_power_set);
+        thermal_throttling_.logCoolingDeviceStatus(cooling_device_info_map_);
+        log_status_.prev_log_time = now;
     }
 
     return min_sleep_ms;
diff --git a/thermal/thermal-helper.h b/thermal/thermal-helper.h
index d81f3a61..043f9960 100644
--- a/thermal/thermal-helper.h
+++ b/thermal/thermal-helper.h
@@ -48,6 +48,13 @@ using ::android::sp;
 
 using NotificationCallback = std::function<void(const Temperature &t)>;
 
+#define INVALID_TEMPERATURE_KERNEL -274000
+#define UNDEFINED_TEMPERATURE -FLT_MAX
+
+#define TEMP_CONVERSION(temp_val, sensor_info)                          \
+    (((temp_val) == INVALID_TEMPERATURE_KERNEL) ? UNDEFINED_TEMPERATURE \
+                                                : ((temp_val) * sensor_info.multiplier))
+
 // Get thermal_zone type
 bool getThermalZoneTypeById(int tz_id, std::string *);
 
@@ -73,6 +80,8 @@ struct SensorStatus {
     ThrottlingSeverity prev_cold_severity;
     boot_clock::time_point last_update_time;
     ThermalSample thermal_cached;
+    std::vector<bool> count_threshold_counted;
+    std::queue<ThermalSample> thermal_history;
     bool pending_notification;
     OverrideStatus override_status;
 };
@@ -230,6 +239,7 @@ class ThermalHelperImpl : public ThermalHelper {
     size_t getPredictionMaxWindowMs(std::string_view sensor_name);
     float readPredictionAfterTimeMs(std::string_view sensor_name, const size_t time_ms);
     bool readTemperaturePredictions(std::string_view sensor_name, std::vector<float> *predictions);
+    float getThermalRising(const SensorStatus &sensor_status, const ThermalSample &curr_sample);
     void updateCoolingDevices(const std::vector<std::string> &cooling_devices_to_update);
     // Check the max throttling for binded cooling device
     void maxCoolingRequestCheck(
@@ -238,6 +248,7 @@ class ThermalHelperImpl : public ThermalHelper {
     ThrottlingSeverity getSeverityReference(std::string_view sensor_name);
 
     sp<ThermalWatcher> thermal_watcher_;
+    LogStatus log_status_;
     PowerFiles power_files_;
     ThermalFiles thermal_sensors_;
     ThermalFiles cooling_devices_;
diff --git a/thermal/utils/power_files.cpp b/thermal/utils/power_files.cpp
index 32a6e700..fd7765d3 100644
--- a/thermal/utils/power_files.cpp
+++ b/thermal/utils/power_files.cpp
@@ -144,8 +144,7 @@ bool PowerFiles::registerPowerRailsToWatch(
         LOG(INFO) << "Successfully to register power rail " << power_rail_info_pair.first;
     }
 
-    power_status_log_ = {.prev_log_time = boot_clock::now(),
-                         .prev_energy_info_map = energy_info_map_};
+    prev_energy_info_map_ = energy_info_map_;
     return true;
 }
 
@@ -374,19 +373,17 @@ void PowerFiles::powerSamplingSwitch(std::string_view power_rail, const bool ena
     }
 }
 
-void PowerFiles::logPowerStatus(const boot_clock::time_point &now) {
+void PowerFiles::logPowerStatus(const std::unordered_set<std::string> &excluded_power_set) {
     // calculate energy and print
     uint8_t power_rail_log_cnt = 0;
     uint64_t max_duration = 0;
     float tot_power = 0.0;
     std::string out;
-    for (const auto &energy_info_pair : energy_info_map_) {
-        const auto &rail = energy_info_pair.first;
-        if (!power_status_log_.prev_energy_info_map.count(rail)) {
+    for (const auto &[rail, curr_sample] : energy_info_map_) {
+        if (!prev_energy_info_map_.contains(rail)) {
             continue;
         }
-        const auto &last_sample = power_status_log_.prev_energy_info_map.at(rail);
-        const auto &curr_sample = energy_info_pair.second;
+        const auto &last_sample = prev_energy_info_map_.at(rail);
         float avg_power = NAN;
         if (calculateAvgPower(rail, last_sample, curr_sample, &avg_power) &&
             !std::isnan(avg_power)) {
@@ -398,9 +395,11 @@ void PowerFiles::logPowerStatus(const boot_clock::time_point &now) {
                 out.append("Power rails ");
             }
             out.append(StringPrintf("[%s: %0.2f mW] ", rail.c_str(), avg_power));
-            power_rail_log_cnt++;
-            tot_power += avg_power;
-            max_duration = std::max(max_duration, curr_sample.duration - last_sample.duration);
+            if (!excluded_power_set.contains(rail)) {
+                power_rail_log_cnt++;
+                tot_power += avg_power;
+                max_duration = std::max(max_duration, curr_sample.duration - last_sample.duration);
+            }
         }
     }
 
@@ -409,7 +408,7 @@ void PowerFiles::logPowerStatus(const boot_clock::time_point &now) {
                                   max_duration);
         LOG(INFO) << out;
     }
-    power_status_log_ = {.prev_log_time = now, .prev_energy_info_map = energy_info_map_};
+    prev_energy_info_map_ = energy_info_map_;
 }
 
 }  // namespace implementation
diff --git a/thermal/utils/power_files.h b/thermal/utils/power_files.h
index 8a2bcd42..54394d8d 100644
--- a/thermal/utils/power_files.h
+++ b/thermal/utils/power_files.h
@@ -48,12 +48,6 @@ struct PowerStatus {
     bool enabled;
 };
 
-struct PowerStatusLog {
-    boot_clock::time_point prev_log_time;
-    // energy sample at last logging
-    std::unordered_map<std::string, PowerSample> prev_energy_info_map;
-};
-
 // A helper class for monitoring power rails.
 class PowerFiles {
   public:
@@ -68,13 +62,9 @@ class PowerFiles {
     // Update the power data from ODPM sysfs
     bool refreshPowerStatus(void);
     // Log the power data for the duration
-    void logPowerStatus(const boot_clock::time_point &now);
+    void logPowerStatus(const std::unordered_set<std::string> &excluded_power_set);
     // OnOff the power calculation
     void powerSamplingSwitch(std::string_view power_rail, const bool enabled);
-    // Get previous power log time_point
-    const boot_clock::time_point &GetPrevPowerLogTime() const {
-        return power_status_log_.prev_log_time;
-    }
     // Get power status map
     const std::unordered_map<std::string, PowerStatus> &GetPowerStatusMap() const {
         std::shared_lock<std::shared_mutex> _lock(power_status_map_mutex_);
@@ -103,7 +93,8 @@ class PowerFiles {
     std::unordered_map<std::string, PowerRailInfo> power_rail_info_map_;
     // The set to store the energy source paths
     std::unordered_set<std::string> energy_path_set_;
-    PowerStatusLog power_status_log_;
+    // energy sample at last logging
+    std::unordered_map<std::string, PowerSample> prev_energy_info_map_;
 };
 
 }  // namespace implementation
diff --git a/thermal/utils/thermal_files.cpp b/thermal/utils/thermal_files.cpp
index c42fa1c3..ccf255cf 100644
--- a/thermal/utils/thermal_files.cpp
+++ b/thermal/utils/thermal_files.cpp
@@ -20,11 +20,11 @@
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include <android-base/properties.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <utils/Trace.h>
 
-#include <algorithm>
 #include <string_view>
 
 namespace aidl {
@@ -35,36 +35,55 @@ namespace implementation {
 
 using ::android::base::StringPrintf;
 
-std::string ThermalFiles::getThermalFilePath(std::string_view thermal_name) const {
+constexpr std::string_view kDefaultFileValue("0");
+
+PathInfo ThermalFiles::getThermalFilePath(std::string_view thermal_name) const {
     auto sensor_itr = thermal_name_to_path_map_.find(thermal_name.data());
     if (sensor_itr == thermal_name_to_path_map_.end()) {
-        return "";
+        return PathInfo();
     }
     return sensor_itr->second;
 }
 
-bool ThermalFiles::addThermalFile(std::string_view thermal_name, std::string_view path) {
-    return thermal_name_to_path_map_.emplace(thermal_name, path).second;
+bool ThermalFiles::addThermalFile(std::string_view thermal_name, std::string_view path,
+                                  TempPathType temp_path_type) {
+    return thermal_name_to_path_map_
+            .emplace(thermal_name,
+                     PathInfo{
+                             .path = std::string(path),
+                             .temp_path_type = temp_path_type,
+                     })
+            .second;
 }
 
 bool ThermalFiles::readThermalFile(std::string_view thermal_name, std::string *data) const {
     std::string sensor_reading;
-    std::string file_path = getThermalFilePath(std::string_view(thermal_name));
+    const auto path_info = getThermalFilePath(thermal_name);
     *data = "";
 
     ATRACE_NAME(StringPrintf("ThermalFiles::readThermalFile - %s", thermal_name.data()).c_str());
-    if (file_path.empty()) {
+    if (path_info.path.empty()) {
         PLOG(WARNING) << "Failed to find " << thermal_name << "'s path";
         return false;
     }
 
-    if (!::android::base::ReadFileToString(file_path, &sensor_reading)) {
-        PLOG(WARNING) << "Failed to read sensor: " << thermal_name;
-        return false;
-    }
-
-    if (sensor_reading.size() <= 1) {
-        LOG(ERROR) << thermal_name << "'s return size:" << sensor_reading.size() << " is invalid";
+    if (path_info.temp_path_type == TempPathType::SYSFS) {
+        if (!::android::base::ReadFileToString(path_info.path, &sensor_reading)) {
+            PLOG(WARNING) << "Failed to read sensor: " << thermal_name;
+            return false;
+        }
+
+        if (sensor_reading.size() <= 1) {
+            LOG(ERROR) << thermal_name << "'s return size:" << sensor_reading.size()
+                       << " is invalid";
+            return false;
+        }
+    } else if (path_info.temp_path_type == TempPathType::DEVICE_PROPERTY) {
+        sensor_reading = ::android::base::GetProperty(path_info.path, kDefaultFileValue.data());
+    } else {
+        LOG(ERROR) << "Unsupported temp path type: "
+                   << static_cast<std::underlying_type<TempPathType>::type>(
+                              path_info.temp_path_type);
         return false;
     }
 
@@ -74,11 +93,11 @@ bool ThermalFiles::readThermalFile(std::string_view thermal_name, std::string *d
 }
 
 bool ThermalFiles::writeCdevFile(std::string_view cdev_name, std::string_view data) {
-    std::string file_path =
+    const auto path_info =
             getThermalFilePath(::android::base::StringPrintf("%s_%s", cdev_name.data(), "w"));
 
     ATRACE_NAME(StringPrintf("ThermalFiles::writeCdevFile - %s", cdev_name.data()).c_str());
-    if (!::android::base::WriteStringToFile(data.data(), file_path)) {
+    if (!::android::base::WriteStringToFile(data.data(), path_info.path)) {
         PLOG(WARNING) << "Failed to write cdev: " << cdev_name << " to " << data.data();
         return false;
     }
diff --git a/thermal/utils/thermal_files.h b/thermal/utils/thermal_files.h
index 4b837809..400eceeb 100644
--- a/thermal/utils/thermal_files.h
+++ b/thermal/utils/thermal_files.h
@@ -19,12 +19,19 @@
 #include <string>
 #include <unordered_map>
 
+#include "thermal_info.h"
+
 namespace aidl {
 namespace android {
 namespace hardware {
 namespace thermal {
 namespace implementation {
 
+struct PathInfo {
+    std::string path = "";
+    TempPathType temp_path_type = TempPathType::SYSFS;
+};
+
 class ThermalFiles {
   public:
     ThermalFiles() = default;
@@ -32,9 +39,10 @@ class ThermalFiles {
     ThermalFiles(const ThermalFiles &) = delete;
     void operator=(const ThermalFiles &) = delete;
 
-    std::string getThermalFilePath(std::string_view thermal_name) const;
+    PathInfo getThermalFilePath(std::string_view thermal_name) const;
     // Returns true if add was successful, false otherwise.
-    bool addThermalFile(std::string_view thermal_name, std::string_view path);
+    bool addThermalFile(std::string_view thermal_name, std::string_view path,
+                        TempPathType temp_path_type = TempPathType::SYSFS);
     // If thermal_name is not found in the thermal names to path map, this will set
     // data to empty and return false. If the thermal_name is found and its content
     // is read, this function will fill in data accordingly then return true.
@@ -43,7 +51,7 @@ class ThermalFiles {
     size_t getNumThermalFiles() const { return thermal_name_to_path_map_.size(); }
 
   private:
-    std::unordered_map<std::string, std::string> thermal_name_to_path_map_;
+    std::unordered_map<std::string, PathInfo> thermal_name_to_path_map_;
 };
 
 }  // namespace implementation
diff --git a/thermal/utils/thermal_info.cpp b/thermal/utils/thermal_info.cpp
index 87ba0fdf..a363e710 100644
--- a/thermal/utils/thermal_info.cpp
+++ b/thermal/utils/thermal_info.cpp
@@ -57,7 +57,7 @@ float getFloatFromValue(const Json::Value &value) {
 
 int getIntFromValue(const Json::Value &value) {
     if (value.isString()) {
-        return (value.asString() == "max") ? std::numeric_limits<int>::max()
+        return (value.asString() == "MAX") ? std::numeric_limits<int>::max()
                                            : std::stoul(value.asString());
     } else {
         return value.asInt();
@@ -276,6 +276,15 @@ bool ParseThermalConfig(std::string_view config_path, Json::Value *config,
                                    "RecordWithThreshold");
             }
         }
+        if (!sub_config["LogInfo"].empty()) {
+            if ((*config)["LogInfo"].empty()) {
+                (*config)["LogInfo"] = sub_config["LogInfo"];
+            } else {
+                MergeConfigEntries(&(*config)["LogInfo"], &sub_config["LogInfo"],
+                                   "ExcludedPowerRailsLog");
+                MergeConfigEntries(&(*config)["LogInfo"], &sub_config["LogInfo"], "LogIntervalMs");
+            }
+        }
     }
 
     return true;
@@ -337,6 +346,7 @@ bool ParseVirtualSensorInfo(const std::string_view name, const Json::Value &sens
     std::vector<SensorFusionType> linked_sensors_type;
     std::vector<std::string> trigger_sensors;
     std::vector<std::string> coefficients;
+    std::vector<float> count_threshold_hyst;
     std::vector<SensorFusionType> coefficients_type;
     FormulaOption formula = FormulaOption::COUNT_THRESHOLD;
     std::string vt_estimator_model_file;
@@ -423,6 +433,24 @@ bool ParseVirtualSensorInfo(const std::string_view name, const Json::Value &sens
         return false;
     }
 
+    values = sensor["CountThresholdHysteresis"];
+    if (!values.size()) {
+        count_threshold_hyst.reserve(linked_sensors.size());
+        for (size_t j = 0; j < linked_sensors.size(); ++j) {
+            count_threshold_hyst.emplace_back(0.0);
+        }
+    } else if (values.size() != linked_sensors.size()) {
+        LOG(ERROR) << "Sensor[" << name << "] has invalid CountThresholdHysteresis size";
+        return false;
+    } else if (values.size() && formula == FormulaOption::COUNT_THRESHOLD) {
+        count_threshold_hyst.reserve(values.size());
+        for (Json::Value::ArrayIndex j = 0; j < values.size(); ++j) {
+            count_threshold_hyst.emplace_back(values[j].asFloat());
+            LOG(INFO) << "Sensor[" << name << "]'s CountThresholdHysteresis[" << j
+                      << "]: " << count_threshold_hyst[j];
+        }
+    }
+
     values = sensor["CoefficientType"];
     if (!values.size()) {
         coefficients_type.reserve(linked_sensors.size());
@@ -608,10 +636,10 @@ bool ParseVirtualSensorInfo(const std::string_view name, const Json::Value &sens
                   << "] with input samples: " << linked_sensors.size();
     }
 
-    virtual_sensor_info->reset(
-            new VirtualSensorInfo{linked_sensors, linked_sensors_type, coefficients,
-                                  coefficients_type, offset, trigger_sensors, formula,
-                                  vt_estimator_model_file, std::move(vt_estimator), backup_sensor});
+    virtual_sensor_info->reset(new VirtualSensorInfo{
+            linked_sensors, linked_sensors_type, coefficients, coefficients_type,
+            count_threshold_hyst, offset, trigger_sensors, formula, vt_estimator_model_file,
+            std::move(vt_estimator), backup_sensor});
     return true;
 }
 
@@ -972,6 +1000,8 @@ bool ParseSensorThrottlingInfo(
     s_power.fill(NAN);
     std::array<float, kThrottlingSeverityCount> i_cutoff;
     i_cutoff.fill(NAN);
+
+    float i_trend = NAN;
     float i_default = 0.0;
     float i_default_pct = NAN;
     int tran_cycle = 0;
@@ -1070,6 +1100,11 @@ bool ParseSensorThrottlingInfo(
             return false;
         }
 
+        if (!sensor["PIDInfo"]["I_Trend"].empty()) {
+            i_trend = getFloatFromValue(sensor["PIDInfo"]["I_Trend"]);
+            LOG(INFO) << "Sensor[" << name << "]'s I_Trend: " << i_trend;
+        }
+
         if (!sensor["PIDInfo"]["I_Default"].empty()) {
             i_default = getFloatFromValue(sensor["PIDInfo"]["I_Default"]);
             LOG(INFO) << "Sensor[" << name << "]'s I_Default: " << i_default;
@@ -1173,10 +1208,10 @@ bool ParseSensorThrottlingInfo(
         }
         excluded_power_info_map[power_rail] = power_weight;
     }
-    throttling_info->reset(new ThrottlingInfo{k_po, k_pu, k_io, k_iu, k_d, i_max, max_alloc_power,
-                                              min_alloc_power, s_power, i_cutoff, i_default,
-                                              i_default_pct, tran_cycle, excluded_power_info_map,
-                                              binded_cdev_info_map, profile_map});
+    throttling_info->reset(
+            new ThrottlingInfo{k_po, k_pu, k_io, k_iu, k_d, i_max, max_alloc_power, min_alloc_power,
+                               s_power, i_cutoff, i_trend, i_default, i_default_pct, tran_cycle,
+                               excluded_power_info_map, binded_cdev_info_map, profile_map});
     *support_throttling = support_pid | support_hard_limit;
     return true;
 }
@@ -1451,6 +1486,24 @@ bool ParseSensorInfo(const Json::Value &config,
             }
         }
 
+        TempPathType temp_path_type = TempPathType::SYSFS;
+        if (sensors[i]["TempPathType"].empty()) {
+            LOG(INFO) << "Sensor[" << name << "]'s TempPathType is empty, default to SYSFS.";
+        } else {
+            const auto &temp_path_type_str = sensors[i]["TempPathType"].asString();
+            if (temp_path_type_str == "SYSFS") {
+                temp_path_type = TempPathType::SYSFS;
+            } else if (temp_path_type_str == "DEVICE_PROPERTY") {
+                temp_path_type = TempPathType::DEVICE_PROPERTY;
+            } else {
+                LOG(ERROR) << "Sensor[" << name
+                           << "]'s TempPathType is invalid: " << temp_path_type_str;
+                sensors_parsed->clear();
+                return false;
+            }
+            LOG(INFO) << "Sensor[" << name << "]'s TempPathType: " << temp_path_type_str;
+        }
+
         std::string temp_path;
         if (!sensors[i]["TempPath"].empty()) {
             temp_path = sensors[i]["TempPath"].asString();
@@ -1557,12 +1610,19 @@ bool ParseSensorInfo(const Json::Value &config,
         bool is_watch = (send_cb | send_powerhint | support_throttling);
         LOG(INFO) << "Sensor[" << name << "]'s is_watch: " << std::boolalpha << is_watch;
 
+        int thermal_sample_count = 0;
+        if (!sensors[i]["ThermalSampleCount"].empty()) {
+            thermal_sample_count = std::max(0, getIntFromValue(sensors[i]["ThermalSampleCount"]));
+        }
+        LOG(INFO) << "Sensor[" << name << "]'s ThermalSampleCount: " << thermal_sample_count;
+
         (*sensors_parsed)[name] = {
                 .type = sensor_type,
                 .hot_thresholds = hot_thresholds,
                 .cold_thresholds = cold_thresholds,
                 .hot_hysteresis = hot_hysteresis,
                 .cold_hysteresis = cold_hysteresis,
+                .temp_path_type = temp_path_type,
                 .temp_path = temp_path,
                 .severity_reference = severity_reference,
                 .vr_threshold = vr_threshold,
@@ -1580,6 +1640,7 @@ bool ParseSensorInfo(const Json::Value &config,
                 .virtual_sensor_info = std::move(virtual_sensor_info),
                 .throttling_info = std::move(throttling_info),
                 .predictor_info = std::move(predictor_info),
+                .thermal_sample_count = thermal_sample_count,
         };
 
         ++total_parsed;
@@ -1677,6 +1738,37 @@ bool ParseCoolingDevice(const Json::Value &config,
     return true;
 }
 
+void ParseThermalLogInfo(const Json::Value &config, LogStatus *log_status) {
+    Json::Value log_info = config["LogInfo"];
+
+    if (log_info.empty()) {
+        LOG(VERBOSE) << "Empty loginfo";
+        return;
+    }
+
+    LOG(VERBOSE) << "Parse LogInfo Config";
+    Json::Value values;
+    if (!log_info["ExcludedPowerRailsLog"].empty()) {
+        values = log_info["ExcludedPowerRailsLog"];
+        for (Json::Value::ArrayIndex i = 0; i < values.size(); ++i) {
+            (*log_status).excluded_power_set.insert(values[i].asString());
+            LOG(INFO) << "ExcludedPowerRailsLog[" << i << "]'s Name: " << values[i].asString();
+        }
+    } else {
+        LOG(VERBOSE) << "Total Power rail exclude list is empty, use all power rails.";
+    }
+
+    if (!log_info["LogIntervalMs"].empty()) {
+        const auto value = getIntFromValue(log_info["LogIntervalMs"]);
+        if (value > 0) {
+            (*log_status).log_interval_ms = std::chrono::milliseconds(value);
+        }
+    }
+    LOG(INFO) << "Thermal log interval: " << (*log_status).log_interval_ms;
+
+    return;
+}
+
 bool ParsePowerRailInfo(
         const Json::Value &config,
         std::unordered_map<std::string, PowerRailInfo> *power_rails_parsed,
diff --git a/thermal/utils/thermal_info.h b/thermal/utils/thermal_info.h
index 6a6d5689..f48df4d8 100644
--- a/thermal/utils/thermal_info.h
+++ b/thermal/utils/thermal_info.h
@@ -40,10 +40,10 @@ constexpr size_t kThrottlingSeverityCount =
                       ::ndk::enum_range<ThrottlingSeverity>().end());
 using ThrottlingArray = std::array<float, static_cast<size_t>(kThrottlingSeverityCount)>;
 using CdevArray = std::array<int, static_cast<size_t>(kThrottlingSeverityCount)>;
+using ::android::base::boot_clock;
 constexpr std::chrono::milliseconds kMinPollIntervalMs = std::chrono::milliseconds(2000);
+constexpr std::chrono::milliseconds kLogIntervalMs = std::chrono::milliseconds(60000);
 constexpr std::chrono::milliseconds kUeventPollTimeoutMs = std::chrono::milliseconds(300000);
-// TODO(b/292044404): Add debug config to make them easily configurable
-constexpr std::chrono::milliseconds kPowerLogIntervalMs = std::chrono::milliseconds(60000);
 constexpr int kMaxPowerLogPerLine = 6;
 // Max number of time_in_state buckets is 20 in atoms
 // VendorSensorCoolingDeviceStats, VendorTempResidencyStats
@@ -144,7 +144,7 @@ struct VirtualSensorInfo {
     std::vector<SensorFusionType> linked_sensors_type;
     std::vector<std::string> coefficients;
     std::vector<SensorFusionType> coefficients_type;
-
+    std::vector<float> count_threshold_hyst;
     float offset;
     std::vector<std::string> trigger_sensors;
     FormulaOption formula;
@@ -212,6 +212,9 @@ struct ThrottlingInfo {
     ThrottlingArray min_alloc_power;
     ThrottlingArray s_power;
     ThrottlingArray i_cutoff;
+    // Increase power budget by I only when thermal rising per min is equal or lower than
+    // i_trend
+    float i_trend;
     float i_default;
     float i_default_pct;
     int tran_cycle;
@@ -220,12 +223,19 @@ struct ThrottlingInfo {
     ProfileMap profile_map;
 };
 
+// Type of temp path to read the sensor data.
+enum class TempPathType : uint32_t {
+    SYSFS = 0,        // Default, read from sysfs
+    DEVICE_PROPERTY,  // Read from device property
+};
+
 struct SensorInfo {
     TemperatureType type;
     ThrottlingArray hot_thresholds;
     ThrottlingArray cold_thresholds;
     ThrottlingArray hot_hysteresis;
     ThrottlingArray cold_hysteresis;
+    TempPathType temp_path_type;
     std::string temp_path;
     std::vector<std::string> severity_reference;
     float vr_threshold;
@@ -245,6 +255,7 @@ struct SensorInfo {
     std::unique_ptr<VirtualSensorInfo> virtual_sensor_info;
     std::shared_ptr<ThrottlingInfo> throttling_info;
     std::unique_ptr<PredictorInfo> predictor_info;
+    int thermal_sample_count;
 };
 
 struct CdevInfo {
@@ -263,6 +274,12 @@ struct PowerRailInfo {
     std::unique_ptr<VirtualPowerRailInfo> virtual_power_rail_info;
 };
 
+struct LogStatus {
+    std::unordered_set<std::string> excluded_power_set;
+    std::chrono::milliseconds log_interval_ms = kLogIntervalMs;
+    boot_clock::time_point prev_log_time;
+};
+
 bool LoadThermalConfig(std::string_view config_path, Json::Value *config);
 bool ParseThermalConfig(std::string_view config_path, Json::Value *config,
                         std::unordered_set<std::string> *loaded_config_paths);
@@ -284,6 +301,8 @@ bool ParseCoolingDeviceStatsConfig(
         const Json::Value &config,
         const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map_,
         StatsInfo<int> *cooling_device_request_info_parsed);
+
+void ParseThermalLogInfo(const Json::Value &config, LogStatus *log_status);
 }  // namespace implementation
 }  // namespace thermal
 }  // namespace hardware
diff --git a/thermal/utils/thermal_throttling.cpp b/thermal/utils/thermal_throttling.cpp
index 79b6aea2..a0b428dc 100644
--- a/thermal/utils/thermal_throttling.cpp
+++ b/thermal/utils/thermal_throttling.cpp
@@ -189,7 +189,7 @@ float ThermalThrottling::updatePowerBudget(
         std::chrono::milliseconds time_elapsed_ms, ThrottlingSeverity curr_severity,
         const bool max_throttling,
         const std::unordered_map<std::string, PowerStatus> &power_status_map,
-        const std::vector<float> &sensor_predictions) {
+        const std::vector<float> &sensor_predictions, const float dt_per_min) {
     float p = 0, d = 0;
     float power_budget = std::numeric_limits<float>::max();
     bool target_changed = false;
@@ -269,7 +269,10 @@ float ThermalThrottling::updatePowerBudget(
                    throttling_status.prev_power_budget <
                            sensor_info.throttling_info->max_alloc_power[target_state] &&
                    !is_fully_release) {
-            throttling_status.i_budget += err * sensor_info.throttling_info->k_iu[target_state];
+            if (std::isnan(sensor_info.throttling_info->i_trend) ||
+                (!std::isnan(dt_per_min) && (dt_per_min <= sensor_info.throttling_info->i_trend))) {
+                throttling_status.i_budget += err * sensor_info.throttling_info->k_iu[target_state];
+            }
         }
     }
 
@@ -331,7 +334,7 @@ float ThermalThrottling::updatePowerBudget(
     LOG(INFO) << temp.name << " power_budget=" << power_budget << " err=" << err
               << " s_power=" << sensor_info.throttling_info->s_power[target_state]
               << " time_elapsed_ms=" << time_elapsed_ms.count() << " p=" << p
-              << " i=" << throttling_status.i_budget << " d=" << d
+              << " i=" << throttling_status.i_budget << " d=" << d << " dt_per_min=" << dt_per_min
               << " compensation=" << compensation << " budget transient=" << budget_transient
               << " control target=" << target_state << " excluded power budget=" << excludepower
               << log_buf;
@@ -353,6 +356,7 @@ float ThermalThrottling::updatePowerBudget(
                static_cast<int>(err / sensor_info.multiplier));
     ATRACE_INT((sensor_name + std::string("-p")).c_str(), static_cast<int>(p));
     ATRACE_INT((sensor_name + std::string("-d")).c_str(), static_cast<int>(d));
+    ATRACE_INT((sensor_name + std::string("-dt_per_min")).c_str(), static_cast<int>(dt_per_min));
     ATRACE_INT((sensor_name + std::string("-predict_compensation")).c_str(),
                static_cast<int>(compensation));
     ATRACE_INT((sensor_name + std::string("-excluded_power_budget")).c_str(),
@@ -401,7 +405,8 @@ bool ThermalThrottling::allocatePowerToCdev(
         const ThrottlingSeverity curr_severity, const std::chrono::milliseconds time_elapsed_ms,
         const std::unordered_map<std::string, PowerStatus> &power_status_map,
         const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map,
-        const bool max_throttling, const std::vector<float> &sensor_predictions) {
+        const bool max_throttling, const std::vector<float> &sensor_predictions,
+        const float dt_per_min) {
     float total_weight = 0;
     float last_updated_avg_power = NAN;
     float allocated_power = 0;
@@ -413,9 +418,9 @@ bool ThermalThrottling::allocatePowerToCdev(
     std::string log_buf;
 
     std::unique_lock<std::shared_mutex> _lock(thermal_throttling_status_map_mutex_);
-    auto total_power_budget =
-            updatePowerBudget(temp, sensor_info, cooling_device_info_map, time_elapsed_ms,
-                              curr_severity, max_throttling, power_status_map, sensor_predictions);
+    auto total_power_budget = updatePowerBudget(temp, sensor_info, cooling_device_info_map,
+                                                time_elapsed_ms, curr_severity, max_throttling,
+                                                power_status_map, sensor_predictions, dt_per_min);
     const auto &profile = thermal_throttling_status_map_[temp.name].profile;
 
     // Go through binded cdev, compute total cdev weight
@@ -769,7 +774,8 @@ void ThermalThrottling::thermalThrottlingUpdate(
         const ThrottlingSeverity curr_severity, const std::chrono::milliseconds time_elapsed_ms,
         const std::unordered_map<std::string, PowerStatus> &power_status_map,
         const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map,
-        const bool max_throttling, const std::vector<float> &sensor_predictions) {
+        const bool max_throttling, const std::vector<float> &sensor_predictions,
+        const float dt_per_min) {
     if (!thermal_throttling_status_map_.count(temp.name)) {
         return;
     }
@@ -781,7 +787,7 @@ void ThermalThrottling::thermalThrottlingUpdate(
     if (thermal_throttling_status_map_[temp.name].pid_power_budget_map.size()) {
         if (!allocatePowerToCdev(temp, sensor_info, curr_severity, time_elapsed_ms,
                                  power_status_map, cooling_device_info_map, max_throttling,
-                                 sensor_predictions)) {
+                                 sensor_predictions, dt_per_min)) {
             LOG(ERROR) << "Sensor " << temp.name << " PID request cdev failed";
             // Clear the CDEV request if the power budget is failed to be allocated
             for (auto &pid_cdev_request_pair :
@@ -912,6 +918,26 @@ bool ThermalThrottling::getCdevMaxRequest(std::string_view cdev_name, int *max_s
     return true;
 }
 
+void ThermalThrottling::logCoolingDeviceStatus(
+        const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map) {
+    int max_state = 0;
+    std::ostringstream cdev_log;
+    for (const auto &[cdev_name, cdev_info] : cooling_device_info_map) {
+        if (getCdevMaxRequest(cdev_name, &max_state)) {
+            ATRACE_INT((cdev_name + std::string("-state")).c_str(), max_state);
+            if (!cdev_info.apply_powercap) {
+                cdev_log << cdev_name << " state:" << max_state << " ";
+            } else {
+                const auto budget = static_cast<int>(
+                        std::lround(cdev_info.state2power[max_state] / cdev_info.multiplier));
+                cdev_log << cdev_name << " state:" << max_state << ",budget:" << budget << " ";
+                ATRACE_INT((cdev_name + std::string("-budget")).c_str(), budget);
+            }
+        }
+    }
+    LOG(INFO) << "CDEV log " << cdev_log.str();
+}
+
 }  // namespace implementation
 }  // namespace thermal
 }  // namespace hardware
diff --git a/thermal/utils/thermal_throttling.h b/thermal/utils/thermal_throttling.h
index 0d012209..c5732fc5 100644
--- a/thermal/utils/thermal_throttling.h
+++ b/thermal/utils/thermal_throttling.h
@@ -82,7 +82,8 @@ class ThermalThrottling {
             const std::unordered_map<std::string, PowerStatus> &power_status_map,
             const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map,
             const bool max_throttling = false,
-            const std::vector<float> &sensor_predictions = std::vector<float>{});
+            const std::vector<float> &sensor_predictions = std::vector<float>{},
+            const float dt_per_min = NAN);
 
     // Compute the throttling target from all the sensors' request
     void computeCoolingDevicesRequest(std::string_view sensor_name, const SensorInfo &sensor_info,
@@ -91,6 +92,9 @@ class ThermalThrottling {
                                       ThermalStatsHelper *thermal_stats_helper);
     // Get the aggregated (from all sensor) max request for a cooling device
     bool getCdevMaxRequest(std::string_view cdev_name, int *max_state);
+    // Print cooling device status
+    void logCoolingDeviceStatus(
+            const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map);
 
   private:
     // Check if the thermal throttling profile need to be switched
@@ -102,7 +106,8 @@ class ThermalThrottling {
             std::chrono::milliseconds time_elapsed_ms, ThrottlingSeverity curr_severity,
             const bool max_throttling,
             const std::unordered_map<std::string, PowerStatus> &power_status_map,
-            const std::vector<float> &sensor_predictions = std::vector<float>{});
+            const std::vector<float> &sensor_predictions = std::vector<float>{},
+            const float dt_per_min = NAN);
 
     // PID algo - return the power number from excluded power rail list
     float computeExcludedPower(const SensorInfo &sensor_info,
@@ -116,7 +121,8 @@ class ThermalThrottling {
             const ThrottlingSeverity curr_severity, const std::chrono::milliseconds time_elapsed_ms,
             const std::unordered_map<std::string, PowerStatus> &power_status_map,
             const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map,
-            const bool max_throttling, const std::vector<float> &sensor_predictions);
+            const bool max_throttling, const std::vector<float> &sensor_predictions,
+            const float dt_per_min = NAN);
     // PID algo - map the target throttling state according to the power budget
     void updateCdevRequestByPower(
             std::string sensor_name,
```

