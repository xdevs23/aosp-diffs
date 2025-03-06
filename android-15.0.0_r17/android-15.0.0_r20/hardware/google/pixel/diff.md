```diff
diff --git a/.gitignore b/.gitignore
new file mode 100644
index 00000000..600d2d33
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1 @@
+.vscode
\ No newline at end of file
diff --git a/atrace/atrace_categories.txt b/atrace/atrace_categories.txt
index 7167c5be..479d76de 100644
--- a/atrace/atrace_categories.txt
+++ b/atrace/atrace_categories.txt
@@ -44,6 +44,8 @@ sched
  systrace/0
 freq
  msm_bus/bus_rules_matches
+cpm
+ cpm_trace/param_set_value_cpm
 thermal_tj
  lmh/lmh_dcvs_freq
  thermal_exynos/thermal_cpu_pressure
diff --git a/common/pixel-common-device.mk b/common/pixel-common-device.mk
index 7d9173b6..947caa1e 100644
--- a/common/pixel-common-device.mk
+++ b/common/pixel-common-device.mk
@@ -44,12 +44,19 @@ PRODUCT_COPY_FILES += \
 endif
 
 # Preopt SystemUI
+ifneq ($(RELEASE_SYSTEMUI_USE_SPEED_PROFILE), true)
 PRODUCT_DEXPREOPT_SPEED_APPS += SystemUIGoogle  # For internal
 PRODUCT_DEXPREOPT_SPEED_APPS += SystemUI        # For AOSP
+endif
 
-# Compile SystemUI on device with `speed`.
+# Set on-device compilation mode for SystemUI.
+ifeq ($(RELEASE_SYSTEMUI_USE_SPEED_PROFILE), true)
+PRODUCT_PROPERTY_OVERRIDES += \
+    dalvik.vm.systemuicompilerfilter=speed-profile
+else
 PRODUCT_PROPERTY_OVERRIDES += \
     dalvik.vm.systemuicompilerfilter=speed
+endif
 
 # Virtual fingerprint HAL
 PRODUCT_PACKAGES += com.android.hardware.biometrics.fingerprint.virtual
diff --git a/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk b/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk
index d64a1456..9f6c95e7 100644
--- a/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk
+++ b/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk
@@ -1,3 +1,9 @@
 SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += hardware/google/pixel-sepolicy/connectivity_thermal_power_manager
 
+$(call soong_config_set,connectivity_thermal_power_manager_config,use_alcedo_modem,$(USES_ALCEDO_MODEM))
+ifeq ($(USES_ALCEDO_MODEM),true)
+PRODUCT_PACKAGES += ConnectivityThermalPowerManagerNextgen
+PRODUCT_PACKAGES_DEBUG += mipc_util
+else
 PRODUCT_PACKAGES += ConnectivityThermalPowerManager
+endif
diff --git a/health/Android.bp b/health/Android.bp
index 3b67e1ec..74171e00 100644
--- a/health/Android.bp
+++ b/health/Android.bp
@@ -16,7 +16,7 @@ cc_library {
         "DeviceHealth.cpp",
         "HealthHelper.cpp",
         "LowBatteryShutdownMetrics.cpp",
-        "StatsHelper.cpp"
+        "StatsHelper.cpp",
     ],
 
     cflags: [
@@ -35,13 +35,13 @@ cc_library {
 
     export_shared_lib_headers: [
         "android.frameworks.stats-V1-ndk",
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
         "libpixelatoms_defs",
     ],
 
     shared_libs: [
         "android.frameworks.stats-V1-ndk",
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
         "libbase",
         "libbinder_ndk",
         "libcutils",
diff --git a/misc_writer/include/misc_writer/misc_writer.h b/misc_writer/include/misc_writer/misc_writer.h
index d04a2ce4..46554b33 100644
--- a/misc_writer/include/misc_writer/misc_writer.h
+++ b/misc_writer/include/misc_writer/misc_writer.h
@@ -48,6 +48,8 @@ enum class MiscWriterActions : int32_t {
   kSetDisplayMode,
   kClearDisplayMode,
   kWriteEagleEyePatterns,
+  kSetDisableFaceauthEval,
+  kClearDisableFaceauthEval,
 
   kUnset = -1,
 };
@@ -73,7 +75,7 @@ class MiscWriter {
         char user_preferred_resolution[32];
         char sota_csku[8];
         char sota_csku_signature[96];
-        char eagleEye[2000];
+        char eagleEye[32];
         char skipUnbootableCheck[32];
     } __attribute__((__packed__)) bootloader_message_vendor_t;
 
@@ -109,6 +111,7 @@ class MiscWriter {
     static constexpr char kTimeMinRtc[] = "timeminrtc=";
     static constexpr uint32_t kFaceauthEvalValOffsetInVendorSpace =
             offsetof(bootloader_message_vendor_t, faceauth_eval);
+    static constexpr char kDisableFaceauthEvalFlag[] = "disable-faceauth-eval";
     static constexpr uint32_t kSotaScheduleShipmodeOffsetInVendorSpace =
             offsetof(bootloader_message_vendor_t, sota_schedule_shipmode);
     static constexpr uint32_t kDstTransitionOffsetInVendorSpace =
diff --git a/misc_writer/misc_writer.cpp b/misc_writer/misc_writer.cpp
index 7b025f29..16876e99 100644
--- a/misc_writer/misc_writer.cpp
+++ b/misc_writer/misc_writer.cpp
@@ -129,6 +129,14 @@ bool MiscWriter::PerformAction(std::optional<size_t> override_offset) {
         content = stringdata_;
         content.resize(sizeof(bootloader_message_vendor_t::eagleEye), 0);
         break;
+    case MiscWriterActions::kSetDisableFaceauthEval:
+    case MiscWriterActions::kClearDisableFaceauthEval:
+        offset = override_offset.value_or(kFaceauthEvalValOffsetInVendorSpace);
+        content = (action_ == MiscWriterActions::kSetDisableFaceauthEval)
+                          ? kDisableFaceauthEvalFlag
+                          : std::string(32, 0);
+        content.resize(32, 0);
+        break;
     case MiscWriterActions::kUnset:
       LOG(ERROR) << "The misc writer action must be set";
       return false;
diff --git a/misc_writer/misc_writer_main.cpp b/misc_writer/misc_writer_main.cpp
index 47649ac9..e52b4dc6 100644
--- a/misc_writer/misc_writer_main.cpp
+++ b/misc_writer/misc_writer_main.cpp
@@ -58,7 +58,8 @@ static int Usage(std::string_view name) {
   std::cerr << "  --set-display-mode <mode>     Write the display mode at boot\n";
   std::cerr << "  --clear-display-mode          Clear the display mode at boot\n";
   std::cerr << "  --set-trending-issue-pattern <string within 2000 byte> Write a regex string";
-  std::cerr << "  --read-trending-issue-pattern Read eagleEye misc portion";
+  std::cerr << "  --set-disable-faceauth-eval   Write disable-faceauth-eval flag\n";
+  std::cerr << "  --clear-disable-faceauth-eval Clear disable-faceauth-eval flag\n";
   std::cerr << "Writes the given hex string to the specified offset in vendor space in /misc "
                "partition.\nDefault offset is used for each action unless "
                "--override-vendor-space-offset is specified.\n";
@@ -87,8 +88,9 @@ int main(int argc, char** argv) {
     { "set-dstoffset", required_argument, nullptr, 0 },
     { "set-display-mode", required_argument, nullptr, 0 },
     { "clear-display-mode", no_argument, nullptr, 0 },
+    { "set-disable-faceauth-eval", no_argument, nullptr, 0 },
+    { "clear-disable-faceauth-eval", no_argument, nullptr, 0 },
     { "set-trending-issue-pattern", required_argument, nullptr, 0 },
-    { "read-trending-issue-pattern", no_argument, nullptr, 0 },
     { nullptr, 0, nullptr, 0 },
   };
 
@@ -102,6 +104,8 @@ int main(int argc, char** argv) {
     { "clear-wrist-orientation", MiscWriterActions::kClearWristOrientationFlag },
     { "set-sota-config", MiscWriterActions::kSetSotaConfig },
     { "clear-display-mode", MiscWriterActions::kClearDisplayMode },
+    { "set-disable-faceauth-eval", MiscWriterActions::kSetDisableFaceauthEval },
+    { "clear-disable-faceauth-eval", MiscWriterActions::kClearDisableFaceauthEval },
   };
 
   std::unique_ptr<MiscWriter> misc_writer;
@@ -236,10 +240,6 @@ int main(int argc, char** argv) {
       misc_writer = std::make_unique<MiscWriter>(iter->second);
     } else if (option_name == "set-dsttransition"s) {
       long long int dst_transition = strtoll(optarg, NULL, 10);
-      if (0 == dst_transition) {
-        LOG(ERROR) << "Failed to parse the dst transition:" << optarg;
-        return Usage(argv[0]);
-      }
       if (misc_writer) {
         LOG(ERROR) << "Misc writer action has already been set";
         return Usage(argv[0]);
@@ -266,18 +266,11 @@ int main(int argc, char** argv) {
       if (misc_writer) {
         LOG(ERROR) << "Misc writer action has already been set";
         return Usage(argv[0]);
-      } else if (sizeof(argv[2]) >= 2000) {
-        std::cerr << "String is too large, we only take strings smaller than 2000, but you provide " << sizeof(argv[2]);
+      } else if (sizeof(argv[2]) >= 32) {
+        std::cerr << "String is too large, we only take strings smaller than 32, but you provide " << sizeof(argv[2]);
         return Usage(argv[0]);
       }
       misc_writer = std::make_unique<MiscWriter>(MiscWriterActions::kWriteEagleEyePatterns, argv[2]);
-    } else if (option_name == "read-trending-issue-pattern"s) {
-      if (misc_writer) {
-        LOG(ERROR) << "Misc writer action has already been set";
-        return Usage(argv[0]);
-      }
-      std::cerr << "function is not yet implemented";
-      return EXIT_SUCCESS;
     } else {
       LOG(FATAL) << "Unreachable path, option_name: " << option_name;
     }
diff --git a/pixelstats/Android.bp b/pixelstats/Android.bp
index 6f3cdf31..29fdc323 100644
--- a/pixelstats/Android.bp
+++ b/pixelstats/Android.bp
@@ -171,6 +171,7 @@ cc_library {
         "ThermalStatsReporter.cpp",
         "TempResidencyReporter.cpp",
         "UeventListener.cpp",
+        "WaterEventReporter.cpp",
         "WirelessChargeStats.cpp",
     ],
     cflags: [
diff --git a/pixelstats/BatteryEEPROMReporter.cpp b/pixelstats/BatteryEEPROMReporter.cpp
index 4f73b6d1..cce74488 100644
--- a/pixelstats/BatteryEEPROMReporter.cpp
+++ b/pixelstats/BatteryEEPROMReporter.cpp
@@ -15,6 +15,7 @@
  */
 
 #define LOG_TAG "pixelstats: BatteryEEPROM"
+#define BATTERY_CYCLE_COUNT_PATH "/sys/class/power_supply/battery/cycle_count"
 
 #include <log/log.h>
 #include <time.h>
@@ -23,6 +24,8 @@
 #include <cmath>
 
 #include <android-base/file.h>
+#include <android-base/parseint.h>
+#include <android-base/strings.h>
 #include <pixelstats/BatteryEEPROMReporter.h>
 #include <pixelstats/StatsHelper.h>
 #include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
@@ -37,12 +40,28 @@ using aidl::android::frameworks::stats::VendorAtomValue;
 using android::base::ReadFileToString;
 using android::hardware::google::pixel::PixelAtoms::BatteryEEPROM;
 
-#define LINESIZE 71
-#define LINESIZE_V2 31
+#define LINESIZE 31
 #define LINESIZE_MAX17201_HIST 80
 
 BatteryEEPROMReporter::BatteryEEPROMReporter() {}
 
+bool BatteryEEPROMReporter::ReadFileToInt(const std::string &path, int16_t *val) {
+    std::string file_contents;
+
+    if (!ReadFileToString(path.c_str(), &file_contents)) {
+        ALOGI("Unable to read %s - %s", path.c_str(), strerror(errno));
+        return false;
+    }
+
+    file_contents = android::base::Trim(file_contents);
+    if (!android::base::ParseInt(file_contents, val)) {
+        ALOGI("Unable to convert %s to int - %s", path.c_str(), strerror(errno));
+        return false;
+    }
+
+    return true;
+}
+
 void BatteryEEPROMReporter::setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset,
                                               int content) {
     std::vector<VendorAtomValue> &val = *values;
@@ -55,6 +74,10 @@ void BatteryEEPROMReporter::checkAndReport(const std::shared_ptr<IStats> &stats_
                                            const std::string &path) {
     std::string file_contents;
     std::string history_each;
+    std::string cycle_count;
+
+    const std::string cycle_count_path(BATTERY_CYCLE_COUNT_PATH);
+    int sparse_index_count = 0;
 
     const int kSecondsPerMonth = 60 * 60 * 24 * 30;
     int64_t now = getTimeSecs();
@@ -69,102 +92,97 @@ void BatteryEEPROMReporter::checkAndReport(const std::shared_ptr<IStats> &stats_
         return;
     }
 
-    int16_t i, num;
-    struct BatteryHistory hist;
     const int kHistTotalLen = file_contents.size();
-
-    ALOGD("kHistTotalLen=%d\n", kHistTotalLen);
-
-    if (kHistTotalLen >= (LINESIZE_V2 * BATT_HIST_NUM_MAX_V2)) {
-        struct BatteryHistoryExtend histv2;
-        for (i = 0; i < BATT_HIST_NUM_MAX_V2; i++) {
-            size_t history_offset = i * LINESIZE_V2;
-            if (history_offset > file_contents.size())
-                break;
-            history_each = file_contents.substr(history_offset, LINESIZE_V2);
-            unsigned int data[4];
-
-            /* Format transfer: go/gsx01-eeprom */
-            num = sscanf(history_each.c_str(), "%4" SCNx16 "%4" SCNx16 "%x %x %x %x",
-                        &histv2.tempco, &histv2.rcomp0, &data[0], &data[1], &data[2], &data[3]);
-
-            if (histv2.tempco == 0xFFFF && histv2.rcomp0 == 0xFFFF)
-                continue;
-
-            /* Extract each data */
-            uint64_t tmp = (int64_t)data[3] << 48 |
-                           (int64_t)data[2] << 32 |
-                           (int64_t)data[1] << 16 |
-                           data[0];
-
-            /* ignore this data if unreasonable */
-            if (tmp <= 0)
-                continue;
-
-            /* data format/unit in go/gsx01-eeprom#heading=h.finy98ign34p */
-            histv2.timer_h = tmp & 0xFF;
-            histv2.fullcapnom = (tmp >>= 8) & 0x3FF;
-            histv2.fullcaprep = (tmp >>= 10) & 0x3FF;
-            histv2.mixsoc = (tmp >>= 10) & 0x3F;
-            histv2.vfsoc = (tmp >>= 6) & 0x3F;
-            histv2.maxvolt = (tmp >>= 6) & 0xF;
-            histv2.minvolt = (tmp >>= 4) & 0xF;
-            histv2.maxtemp = (tmp >>= 4) & 0xF;
-            histv2.mintemp = (tmp >>= 4) & 0xF;
-            histv2.maxchgcurr = (tmp >>= 4) & 0xF;
-            histv2.maxdischgcurr = (tmp >>= 4) & 0xF;
-
-            /* Mapping to original format to collect data */
-            /* go/pixel-battery-eeprom-atom#heading=h.dcawdjiz2ls6 */
-            hist.tempco = histv2.tempco;
-            hist.rcomp0 = histv2.rcomp0;
-            hist.timer_h = (uint8_t)histv2.timer_h * 5;
-            hist.max_temp = (int8_t)histv2.maxtemp * 3 + 22;
-            hist.min_temp = (int8_t)histv2.mintemp * 3 - 20;
-            hist.min_ibatt = (int16_t)histv2.maxchgcurr * 500 * (-1);
-            hist.max_ibatt = (int16_t)histv2.maxdischgcurr * 500;
-            hist.min_vbatt = (uint16_t)histv2.minvolt * 10 + 2500;
-            hist.max_vbatt = (uint16_t)histv2.maxvolt * 20 + 4200;
-            hist.batt_soc = (uint8_t)histv2.vfsoc * 2;
-            hist.msoc = (uint8_t)histv2.mixsoc * 2;
-            hist.full_cap = (int16_t)histv2.fullcaprep * 125 / 1000;
-            hist.full_rep = (int16_t)histv2.fullcapnom * 125 / 1000;
-            hist.cycle_cnt = (i + 1) * 10;
-
-            reportEvent(stats_client, hist);
-            report_time_ = getTimeSecs();
+    const int kHistTotalNum = kHistTotalLen / LINESIZE;
+    ALOGD("kHistTotalLen=%d, kHistTotalNum=%d\n", kHistTotalLen, kHistTotalNum);
+
+    /* TODO: wait for pa/2875004 merge
+    if (ReadFileToString(cycle_count_path.c_str(), &cycle_count)) {
+        int cnt;
+
+        cycle_count = android::base::Trim(cycle_count);
+        if (android::base::ParseInt(cycle_count, &cnt)) {
+            cnt /= 10;
+            if (cnt > kHistTotalNum)
+                sparse_index_count = cnt % kHistTotalNum;
         }
-        return;
+
+        ALOGD("sparse_index_count %d cnt: %d cycle_count %s\n", sparse_index_count, cnt,
+              cycle_count.c_str());
     }
+    */
 
-    for (i = 0; i < (LINESIZE * BATT_HIST_NUM_MAX); i = i + LINESIZE) {
-        if (i + LINESIZE > kHistTotalLen)
+    struct BatteryHistoryRawFormat hist_raw;
+    struct BatteryHistory hist;
+    int16_t i;
+
+    ReadFileToInt(kBatteryPairingPath, &hist.battery_pairing);
+
+    for (i = 0; i < kHistTotalNum; i++) {
+        size_t history_offset = i * LINESIZE;
+        if (history_offset + LINESIZE > kHistTotalLen)
             break;
-        history_each = file_contents.substr(i, LINESIZE);
-        num = sscanf(history_each.c_str(),
-                   "%4" SCNx16 "%4" SCNx16 "%4" SCNx16 "%4" SCNx16
-                   "%2" SCNx8 "%2" SCNx8 " %2" SCNx8 "%2" SCNx8
-                   "%2" SCNx8 "%2" SCNx8 " %2" SCNx8 "%2" SCNx8
-                   "%2" SCNx8 "%2" SCNx8 " %4" SCNx16 "%4" SCNx16
-                   "%4" SCNx16 "%4" SCNx16 "%4" SCNx16,
-                   &hist.cycle_cnt, &hist.full_cap, &hist.esr,
-                   &hist.rslow, &hist.batt_temp, &hist.soh,
-                   &hist.cc_soc, &hist.cutoff_soc, &hist.msoc,
-                   &hist.sys_soc, &hist.reserve, &hist.batt_soc,
-                   &hist.min_temp, &hist.max_temp,  &hist.max_vbatt,
-                   &hist.min_vbatt, &hist.max_ibatt, &hist.min_ibatt,
-                   &hist.checksum);
-
-        if (num != kNumBatteryHistoryFields) {
-            ALOGE("Couldn't process %s", history_each.c_str());
+        history_each = file_contents.substr(history_offset, LINESIZE);
+        unsigned int data[4];
+
+        /* Format transfer: go/gsx01-eeprom */
+        int16_t num = sscanf(history_each.c_str(), "%4" SCNx16 "%4" SCNx16 "%x %x %x %x",
+                      &hist_raw.tempco, &hist_raw.rcomp0, &data[0], &data[1], &data[2], &data[3]);
+        if (num <= 0)
             continue;
-        }
 
-        if (checkLogEvent(hist)) {
-            reportEvent(stats_client, hist);
-            report_time_ = getTimeSecs();
-        }
+        if (hist_raw.tempco == 0xFFFF && hist_raw.rcomp0 == 0xFFFF)
+            continue;
+
+        /* Extract each data */
+        uint64_t tmp = (int64_t)data[3] << 48 |
+                       (int64_t)data[2] << 32 |
+                       (int64_t)data[1] << 16 |
+                       data[0];
+
+        /* ignore this data if unreasonable */
+        if (tmp <= 0)
+            continue;
+
+        /* data format/unit in go/gsx01-eeprom#heading=h.finy98ign34p */
+        hist_raw.timer_h = tmp & 0xFF;
+        hist_raw.fullcapnom = (tmp >>= 8) & 0x3FF;
+        hist_raw.fullcaprep = (tmp >>= 10) & 0x3FF;
+        hist_raw.mixsoc = (tmp >>= 10) & 0x3F;
+        hist_raw.vfsoc = (tmp >>= 6) & 0x3F;
+        hist_raw.maxvolt = (tmp >>= 6) & 0xF;
+        hist_raw.minvolt = (tmp >>= 4) & 0xF;
+        hist_raw.maxtemp = (tmp >>= 4) & 0xF;
+        hist_raw.mintemp = (tmp >>= 4) & 0xF;
+        hist_raw.maxchgcurr = (tmp >>= 4) & 0xF;
+        hist_raw.maxdischgcurr = (tmp >>= 4) & 0xF;
+
+        /* Mapping to original format to collect data */
+        /* go/pixel-battery-eeprom-atom#heading=h.dcawdjiz2ls6 */
+        hist.tempco = hist_raw.tempco;
+        hist.rcomp0 = hist_raw.rcomp0;
+        hist.timer_h = (uint8_t)hist_raw.timer_h * 5;
+        hist.max_temp = (int8_t)hist_raw.maxtemp * 3 + 22;
+        hist.min_temp = (int8_t)hist_raw.mintemp * 3 - 20;
+        hist.min_ibatt = (int16_t)hist_raw.maxchgcurr * 500 * (-1);
+        hist.max_ibatt = (int16_t)hist_raw.maxdischgcurr * 500;
+        hist.min_vbatt = (uint16_t)hist_raw.minvolt * 10 + 2500;
+        hist.max_vbatt = (uint16_t)hist_raw.maxvolt * 20 + 4200;
+        hist.batt_soc = (uint8_t)hist_raw.vfsoc * 2;
+        hist.msoc = (uint8_t)hist_raw.mixsoc * 2;
+        hist.full_cap = (int16_t)hist_raw.fullcaprep * 125 / 1000;
+        hist.full_rep = (int16_t)hist_raw.fullcapnom * 125 / 1000;
+
+        /* i < sparse_index_count: 20 40 60 80  */
+        if (i < sparse_index_count)
+            hist.cycle_cnt = (i + 1) * 20;
+        else
+            hist.cycle_cnt = (i + sparse_index_count + 1) * 10;
+
+        reportEvent(stats_client, hist);
+        report_time_ = getTimeSecs();
     }
+    return;
 }
 
 int64_t BatteryEEPROMReporter::getTimeSecs(void) {
@@ -208,17 +226,18 @@ void BatteryEEPROMReporter::reportEvent(const std::shared_ptr<IStats> &stats_cli
             BatteryEEPROM::kMaxIbattFieldNumber,  BatteryEEPROM::kMinIbattFieldNumber,
             BatteryEEPROM::kChecksumFieldNumber,  BatteryEEPROM::kTempcoFieldNumber,
             BatteryEEPROM::kRcomp0FieldNumber,    BatteryEEPROM::kTimerHFieldNumber,
-            BatteryEEPROM::kFullRepFieldNumber};
+            BatteryEEPROM::kFullRepFieldNumber,   BatteryEEPROM::kBatteryPairingFieldNumber};
 
     ALOGD("reportEvent: cycle_cnt:%d, full_cap:%d, esr:%d, rslow:%d, soh:%d, "
           "batt_temp:%d, cutoff_soc:%d, cc_soc:%d, sys_soc:%d, msoc:%d, "
           "batt_soc:%d, reserve:%d, max_temp:%d, min_temp:%d, max_vbatt:%d, "
           "min_vbatt:%d, max_ibatt:%d, min_ibatt:%d, checksum:%#x, full_rep:%d, "
-          "tempco:%#x, rcomp0:%#x, timer_h:%d",
+          "tempco:%#x, rcomp0:%#x, timer_h:%d, batt_pair:%d",
           hist.cycle_cnt, hist.full_cap, hist.esr, hist.rslow, hist.soh, hist.batt_temp,
           hist.cutoff_soc, hist.cc_soc, hist.sys_soc, hist.msoc, hist.batt_soc, hist.reserve,
           hist.max_temp, hist.min_temp, hist.max_vbatt, hist.min_vbatt, hist.max_ibatt,
-          hist.min_ibatt, hist.checksum, hist.full_rep, hist.tempco, hist.rcomp0, hist.timer_h);
+          hist.min_ibatt, hist.checksum, hist.full_rep, hist.tempco, hist.rcomp0, hist.timer_h,
+          hist.battery_pairing);
 
     std::vector<VendorAtomValue> values(eeprom_history_fields.size());
     VendorAtomValue val;
@@ -269,6 +288,8 @@ void BatteryEEPROMReporter::reportEvent(const std::shared_ptr<IStats> &stats_cli
     values[BatteryEEPROM::kTimerHFieldNumber - kVendorAtomOffset] = val;
     val.set<VendorAtomValue::intValue>(hist.full_rep);
     values[BatteryEEPROM::kFullRepFieldNumber - kVendorAtomOffset] = val;
+    val.set<VendorAtomValue::intValue>(hist.battery_pairing);
+    values[BatteryEEPROM::kBatteryPairingFieldNumber - kVendorAtomOffset] = val;
 
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kBatteryEeprom,
@@ -438,7 +459,7 @@ void BatteryEEPROMReporter::checkAndReportFGModelLoading(const std::shared_ptr<I
                                     .checksum = EvtModelLoading, };
     std::string file_contents;
     std::string path;
-    int num, pos = 0;
+    int num;
     const char *data;
 
     if (paths.empty())
@@ -462,15 +483,12 @@ void BatteryEEPROMReporter::checkAndReportFGModelLoading(const std::shared_ptr<I
 
     data = file_contents.c_str();
 
-    num = sscanf(&data[pos],  "ModelNextUpdate: %" SCNu16 "\n"
-                 "%*x:%*x\n%*x:%*x\n%*x:%*x\n%*x:%*x\n%*x:%*x\n%n",
-                 &params.rslow, &pos);
-    if (num != 1) {
+    num = sscanf(data, "ModelNextUpdate: %" SCNu16 "%*[0-9a-f: \n]ATT: %" SCNu16 " FAIL: %" SCNu16,
+                 &params.rslow, &params.full_cap, &params.esr);
+    if (num != 3) {
         ALOGE("Couldn't process ModelLoading History. num=%d\n", num);
         return;
-    }
-
-    sscanf(&data[pos],  "ATT: %" SCNu16 " FAIL: %" SCNu16, &params.full_cap, &params.esr);
+     }
 
     /* don't need to report when attempts counter is zero */
     if (params.full_cap == 0)
@@ -566,11 +584,15 @@ void BatteryEEPROMReporter::checkAndReportValidation(const std::shared_ptr<IStat
     for (int event_idx = 0; event_idx < events.size(); event_idx++) {
         std::vector<uint32_t> &event = events[event_idx];
         if (event.size() == kNumValidationFields) {
-            params.full_cap = event[0]; /* fcnom */
-            params.esr = event[1];      /* dpacc */
-            params.rslow = event[2];    /* dqacc */
-            params.full_rep = event[3]; /* fcrep */
+            params.full_cap = event[0]; /* first empty entry */
+            params.esr = event[1];      /* num of entries need to be recovered or fix result */
+            params.rslow = event[2];    /* last cycle count */
+            params.full_rep = event[3]; /* estimate cycle count after recovery */
             reportEventInt32(stats_client, params);
+            /* force report history metrics if it was recovered */
+            if (last_hv_check_ != 0) {
+                report_time_ = 0;
+            }
         } else {
             ALOGE("Not support %zu fields for History Validation event", event.size());
         }
diff --git a/pixelstats/BrownoutDetectedReporter.cpp b/pixelstats/BrownoutDetectedReporter.cpp
index e256939e..afdf16d5 100644
--- a/pixelstats/BrownoutDetectedReporter.cpp
+++ b/pixelstats/BrownoutDetectedReporter.cpp
@@ -112,11 +112,11 @@ bool BrownoutDetectedReporter::updateIfFound(std::string line, std::regex patter
     return found;
 }
 
-void BrownoutDetectedReporter::setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset,
+void BrownoutDetectedReporter::setAtomFieldValue(std::vector<VendorAtomValue> &values, int offset,
                                                  int content) {
-    std::vector<VendorAtomValue> &val = *values;
-    if (offset - kVendorAtomOffset < val.size()) {
-        val[offset - kVendorAtomOffset].set<VendorAtomValue::intValue>(content);
+    if (offset - kVendorAtomOffset < values.size()) {
+        ALOGW("VendorAtomValue size is smaller than offset");
+        values[offset - kVendorAtomOffset].set<VendorAtomValue::intValue>(content);
     }
 }
 
@@ -124,97 +124,180 @@ void BrownoutDetectedReporter::uploadData(const std::shared_ptr<IStats> &stats_c
                                           const struct BrownoutDetectedInfo max_value) {
     // Load values array
     VendorAtomValue tmp;
-    std::vector<VendorAtomValue> values(47);
-    setAtomFieldValue(&values, BrownoutDetected::kTriggeredIrqFieldNumber,
-                      max_value.triggered_irq_);
-    setAtomFieldValue(&values, BrownoutDetected::kTriggeredTimestampFieldNumber,
+    std::vector<VendorAtomValue> values(90);
+    setAtomFieldValue(values, BrownoutDetected::kTriggeredIrqFieldNumber, max_value.triggered_irq_);
+    setAtomFieldValue(values, BrownoutDetected::kTriggeredTimestampFieldNumber,
                       max_value.triggered_timestamp_);
-    setAtomFieldValue(&values, BrownoutDetected::kBatteryTempFieldNumber, max_value.battery_temp_);
-    setAtomFieldValue(&values, BrownoutDetected::kBatterySocFieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kBatteryTempFieldNumber, max_value.battery_temp_);
+    setAtomFieldValue(values, BrownoutDetected::kBatterySocFieldNumber,
                       100 - max_value.battery_soc_);
-    setAtomFieldValue(&values, BrownoutDetected::kBatteryCycleFieldNumber,
-                      max_value.battery_cycle_);
-    setAtomFieldValue(&values, BrownoutDetected::kVoltageNowFieldNumber, max_value.voltage_now_);
+    setAtomFieldValue(values, BrownoutDetected::kBatteryCycleFieldNumber, max_value.battery_cycle_);
+    setAtomFieldValue(values, BrownoutDetected::kVoltageNowFieldNumber, max_value.voltage_now_);
 
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel01FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel01FieldNumber,
                       max_value.odpm_value_[0]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel02FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel02FieldNumber,
                       max_value.odpm_value_[1]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel03FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel03FieldNumber,
                       max_value.odpm_value_[2]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel04FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel04FieldNumber,
                       max_value.odpm_value_[3]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel05FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel05FieldNumber,
                       max_value.odpm_value_[4]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel06FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel06FieldNumber,
                       max_value.odpm_value_[5]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel07FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel07FieldNumber,
                       max_value.odpm_value_[6]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel08FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel08FieldNumber,
                       max_value.odpm_value_[7]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel09FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel09FieldNumber,
                       max_value.odpm_value_[8]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel10FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel10FieldNumber,
                       max_value.odpm_value_[9]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel11FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel11FieldNumber,
                       max_value.odpm_value_[10]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel12FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel12FieldNumber,
                       max_value.odpm_value_[11]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel13FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel13FieldNumber,
                       max_value.odpm_value_[12]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel14FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel14FieldNumber,
                       max_value.odpm_value_[13]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel15FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel15FieldNumber,
                       max_value.odpm_value_[14]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel16FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel16FieldNumber,
                       max_value.odpm_value_[15]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel17FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel17FieldNumber,
                       max_value.odpm_value_[16]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel18FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel18FieldNumber,
                       max_value.odpm_value_[17]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel19FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel19FieldNumber,
                       max_value.odpm_value_[18]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel20FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel20FieldNumber,
                       max_value.odpm_value_[19]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel21FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel21FieldNumber,
                       max_value.odpm_value_[20]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel22FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel22FieldNumber,
                       max_value.odpm_value_[21]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel23FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel23FieldNumber,
                       max_value.odpm_value_[22]);
-    setAtomFieldValue(&values, BrownoutDetected::kOdpmChannel24FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kOdpmChannel24FieldNumber,
                       max_value.odpm_value_[23]);
 
-    setAtomFieldValue(&values, BrownoutDetected::kDvfsChannel1FieldNumber,
-                      max_value.dvfs_value_[0]);
-    setAtomFieldValue(&values, BrownoutDetected::kDvfsChannel2FieldNumber,
-                      max_value.dvfs_value_[1]);
-    setAtomFieldValue(&values, BrownoutDetected::kDvfsChannel3FieldNumber,
-                      max_value.dvfs_value_[2]);
-    setAtomFieldValue(&values, BrownoutDetected::kDvfsChannel4FieldNumber,
-                      max_value.dvfs_value_[3]);
-    setAtomFieldValue(&values, BrownoutDetected::kDvfsChannel5FieldNumber,
-                      max_value.dvfs_value_[4]);
-    setAtomFieldValue(&values, BrownoutDetected::kDvfsChannel6FieldNumber,
-                      max_value.dvfs_value_[5]);
-    setAtomFieldValue(&values, BrownoutDetected::kBrownoutReasonFieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel1FieldNumber, max_value.dvfs_value_[0]);
+    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel2FieldNumber, max_value.dvfs_value_[1]);
+    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel3FieldNumber, max_value.dvfs_value_[2]);
+    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel4FieldNumber, max_value.dvfs_value_[3]);
+    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel5FieldNumber, max_value.dvfs_value_[4]);
+    setAtomFieldValue(values, BrownoutDetected::kDvfsChannel6FieldNumber, max_value.dvfs_value_[5]);
+    setAtomFieldValue(values, BrownoutDetected::kBrownoutReasonFieldNumber,
                       max_value.brownout_reason_);
 
-    setAtomFieldValue(&values, BrownoutDetected::kMaxCurrentFieldNumber, max_value.max_curr_);
-    setAtomFieldValue(&values, BrownoutDetected::kEvtCntUvlo1FieldNumber, max_value.evt_cnt_uvlo1_);
-    setAtomFieldValue(&values, BrownoutDetected::kEvtCntUvlo2FieldNumber, max_value.evt_cnt_uvlo2_);
-    setAtomFieldValue(&values, BrownoutDetected::kEvtCntOilo1FieldNumber, max_value.evt_cnt_oilo1_);
-    setAtomFieldValue(&values, BrownoutDetected::kEvtCntOilo2FieldNumber, max_value.evt_cnt_oilo2_);
-    setAtomFieldValue(&values, BrownoutDetected::kVimonVbattFieldNumber, max_value.vimon_vbatt_);
-    setAtomFieldValue(&values, BrownoutDetected::kVimonIbattFieldNumber, max_value.vimon_ibatt_);
+    setAtomFieldValue(values, BrownoutDetected::kMaxCurrentFieldNumber, max_value.max_curr_);
+    setAtomFieldValue(values, BrownoutDetected::kEvtCntUvlo1FieldNumber, max_value.evt_cnt_uvlo1_);
+    setAtomFieldValue(values, BrownoutDetected::kEvtCntUvlo2FieldNumber, max_value.evt_cnt_uvlo2_);
+    setAtomFieldValue(values, BrownoutDetected::kEvtCntOilo1FieldNumber, max_value.evt_cnt_oilo1_);
+    setAtomFieldValue(values, BrownoutDetected::kEvtCntOilo2FieldNumber, max_value.evt_cnt_oilo2_);
+    setAtomFieldValue(values, BrownoutDetected::kVimonVbattFieldNumber, max_value.vimon_vbatt_);
+    setAtomFieldValue(values, BrownoutDetected::kVimonIbattFieldNumber, max_value.vimon_ibatt_);
 
-    setAtomFieldValue(&values, BrownoutDetected::kMitigationMethod0FieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kMitigationMethod0FieldNumber,
                       max_value.mitigation_method_0_);
-    setAtomFieldValue(&values, BrownoutDetected::kMitigationMethod0CountFieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kMitigationMethod0CountFieldNumber,
                       max_value.mitigation_method_0_count_);
-    setAtomFieldValue(&values, BrownoutDetected::kMitigationMethod0TimeUsFieldNumber,
+    setAtomFieldValue(values, BrownoutDetected::kMitigationMethod0TimeUsFieldNumber,
                       max_value.mitigation_method_0_time_us_);
 
+    setAtomFieldValue(values, BrownoutDetected::kPreOcpCpu1BckupFieldNumber,
+                      max_value.pre_ocp_cpu1_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kPreOcpCpu2BckupFieldNumber,
+                      max_value.pre_ocp_cpu2_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kPreOcpTpuBckupFieldNumber,
+                      max_value.pre_ocp_tpu_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kPreOcpGpuBckupFieldNumber,
+                      max_value.pre_ocp_gpu_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kPreUvloHitCntMFieldNumber,
+                      max_value.pre_uvlo_hit_cnt_m_);
+    setAtomFieldValue(values, BrownoutDetected::kPreUvloHitCntSFieldNumber,
+                      max_value.pre_uvlo_hit_cnt_s_);
+    setAtomFieldValue(values, BrownoutDetected::kPreUvloDurFieldNumber, max_value.uvlo_dur_);
+
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat0SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_0_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat1SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_1_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat2SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_2_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat3SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_3_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat4SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_4_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat5SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_5_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat6SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_6_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat7SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_7_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat8SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_8_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat9SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_9_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat10SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_10_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat11SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_11_sys_evt_main_bckup_);
+
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat0SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_0_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat1SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_1_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat2SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_2_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat3SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_3_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat4SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_4_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat5SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_5_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat6SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_6_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat7SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_7_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat8SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_8_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat9SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_9_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat10SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_10_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStat11SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_11_sys_evt_sub_bckup_);
+
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt0SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_ext_0_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt1SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_ext_1_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt2SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_ext_2_sys_evt_main_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt3SysEvtMainBckupFieldNumber,
+                      max_value.odpm_irq_stat_ext_3_sys_evt_main_bckup_);
+
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt0SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_ext_0_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt1SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_ext_1_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt2SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_ext_2_sys_evt_sub_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatExt3SysEvtSubBckupFieldNumber,
+                      max_value.odpm_irq_stat_ext_3_sys_evt_sub_bckup_);
+
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatGpuBckupFieldNumber,
+                      max_value.odpm_irq_stat_gpu_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatTpuBckupFieldNumber,
+                      max_value.odpm_irq_stat_tpu_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatCpu1BckupFieldNumber,
+                      max_value.odpm_irq_stat_cpu1_bckup_);
+    setAtomFieldValue(values, BrownoutDetected::kOdpmIrqStatCpu2BckupFieldNumber,
+                      max_value.odpm_irq_stat_cpu2_bckup_);
+
     // Send vendor atom to IStats HAL
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kBrownoutDetected,
@@ -323,6 +406,87 @@ void BrownoutDetectedReporter::logBrownoutCsv(const std::shared_ptr<IStats> &sta
             max_value.vimon_vbatt_ = atoi(row[IDX_VIMON_V].c_str());
             max_value.vimon_ibatt_ = atoi(row[IDX_VIMON_I].c_str());
         }
+        if (row.size() > UVLO_DUR_IDX) {
+            max_value.pre_ocp_cpu1_bckup_ = atoi(row[PRE_OCP_CPU1_BCKUP_IDX].c_str());
+            max_value.pre_ocp_cpu2_bckup_ = atoi(row[PRE_OCP_CPU2_BCKUP_IDX].c_str());
+            max_value.pre_ocp_tpu_bckup_ = atoi(row[PRE_OCP_TPU_BCKUP_IDX].c_str());
+            max_value.pre_ocp_gpu_bckup_ = atoi(row[PRE_OCP_GPU_BCKUP_IDX].c_str());
+            max_value.pre_uvlo_hit_cnt_m_ = atoi(row[PRE_UVLO_HIT_CNT_M_IDX].c_str());
+            max_value.pre_uvlo_hit_cnt_s_ = atoi(row[PRE_UVLO_HIT_CNT_S_IDX].c_str());
+            max_value.uvlo_dur_ = atoi(row[UVLO_DUR_IDX].c_str());
+        }
+        if (row.size() > ODPM_IRQ_STAT_CPU2_BCKUP_IDX) {
+            max_value.pre_ocp_cpu1_bckup_ = atoi(row[PRE_OCP_CPU1_BCKUP_IDX].c_str());
+            max_value.pre_ocp_cpu2_bckup_ = atoi(row[PRE_OCP_CPU2_BCKUP_IDX].c_str());
+
+            max_value.odpm_irq_stat_0_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_0_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_1_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_1_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_2_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_2_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_3_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_3_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_4_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_4_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_5_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_5_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_6_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_6_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_7_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_7_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_8_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_8_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_9_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_9_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_10_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_10_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_11_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_11_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+
+            max_value.odpm_irq_stat_0_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_0_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_1_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_1_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_2_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_2_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_3_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_3_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_4_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_4_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_5_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_5_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_6_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_6_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_7_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_7_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_8_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_8_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_9_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_9_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_10_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_10_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_11_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_11_SYS_EVT_SUB_BCKUP_IDX].c_str());
+
+            max_value.odpm_irq_stat_ext_0_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_EXT_0_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_ext_1_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_EXT_1_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_ext_2_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_EXT_2_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_ext_3_sys_evt_main_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_EXT_3_SYS_EVT_MAIN_BCKUP_IDX].c_str());
+
+            max_value.odpm_irq_stat_ext_0_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_EXT_0_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_ext_1_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_EXT_1_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_ext_2_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_EXT_2_SYS_EVT_SUB_BCKUP_IDX].c_str());
+            max_value.odpm_irq_stat_ext_3_sys_evt_sub_bckup_ =
+                    atoi(row[ODPM_IRQ_STAT_EXT_3_SYS_EVT_SUB_BCKUP_IDX].c_str());
+        }
     }
     if (!isAlreadyUpdated && max_value.battery_temp_ != DEFAULT_BATTERY_TEMP) {
         std::string file_content = "LASTMEAL_UPDATED\n" + csvFile;
diff --git a/pixelstats/ChargeStatsReporter.cpp b/pixelstats/ChargeStatsReporter.cpp
index 081583fe..6da2c97c 100644
--- a/pixelstats/ChargeStatsReporter.cpp
+++ b/pixelstats/ChargeStatsReporter.cpp
@@ -40,9 +40,7 @@ using android::hardware::google::pixel::PixelAtoms::ChargeStats;
 using android::hardware::google::pixel::PixelAtoms::VoltageTierStats;
 
 #define DURATION_FILTER_SECS 15
-#define CHG_STATS_FMT0 "%d,%d,%d, %d,%d,%d,%d"
-#define CHG_STATS_FMT1 "%d,%d,%d, %d,%d,%d,%d %d" /* AACR */
-#define CHG_STATS_FMT2 "%d,%d,%d, %d,%d,%d,%d %d %d,%d" /* AACR + CSI */
+#define CHG_STATS_FMT "%d,%d,%d, %d,%d,%d,%d %d %d,%d, %d,%d"
 
 ChargeStatsReporter::ChargeStatsReporter() {}
 
@@ -72,34 +70,27 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
             ChargeStats::kAdapterCapabilities4FieldNumber,
             ChargeStats::kReceiverState0FieldNumber,
             ChargeStats::kReceiverState1FieldNumber,
+            ChargeStats::kAacrAlgoFieldNumber,
+            ChargeStats::kAacpVersionFieldNumber,
+            ChargeStats::kAaccFieldNumber,
     };
     const int32_t chg_fields_size = std::size(charge_stats_fields);
-    static_assert(chg_fields_size == 17, "Unexpected charge stats fields size");
+    static_assert(chg_fields_size == 20, "Unexpected charge stats fields size");
     const int32_t wlc_fields_size = 7;
     std::vector<VendorAtomValue> values(chg_fields_size);
     VendorAtomValue val;
-    int32_t i = 0, tmp[chg_fields_size] = {0}, fields_size = (chg_fields_size - wlc_fields_size);
-    int32_t pca_ac[2] = {0}, pca_rs[5] = {0};
+    int32_t i = 0, tmp[chg_fields_size] = {0};
+    int32_t pca_ac[2] = {0}, pca_rs[5] = {0}, stats_size;
     std::string pdo_line, file_contents;
     std::istringstream ss;
 
     ALOGD("processing %s", line.c_str());
-    if (sscanf(line.c_str(), CHG_STATS_FMT2, &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5],
-               &tmp[6], &tmp[7], &tmp[8], &tmp[9]) == 10) {
-        /*
-         * Charging Speed Indicator (CSI) the sum of the reasons that limit the charging speed in
-         * this charging session.
-         */
-    } else if (sscanf(line.c_str(), CHG_STATS_FMT1, &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4],
-               &tmp[5], &tmp[6], &tmp[7]) == 8) {
-        /*
-         * Age Adjusted Charge Rate (AACR) logs an additional battery capacity in order to determine
-         * the charge curve needed to minimize battery cycle life degradation, while also minimizing
-         * impact to the user.
-         */
-    } else if (sscanf(line.c_str(), CHG_STATS_FMT0, &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4],
-                      &tmp[5], &tmp[6]) != 7) {
-        ALOGE("Couldn't process %s", line.c_str());
+
+    stats_size = sscanf(line.c_str(), CHG_STATS_FMT, &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4],
+                        &tmp[5], &tmp[6], &tmp[7], &tmp[8], &tmp[9], &tmp[18], &tmp[19]);
+    if (stats_size != kNumChgStatsFormat00Fields && stats_size != kNumChgStatsFormat01Fields &&
+        stats_size != kNumChgStatsFormat02Fields && stats_size != kNumChgStatsFormat03Fields) {
+        ALOGE("Couldn't process %s (stats_size: %d)", line.c_str(), stats_size);
         return;
     }
 
@@ -114,8 +105,6 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
             if (sscanf(wline_ac.c_str(), "D:%x,%x,%x,%x,%x, %x,%x", &tmp[10], &tmp[11], &tmp[12],
                        &tmp[13], &tmp[14], &tmp[15], &tmp[16]) != 7)
                 ALOGE("Couldn't process %s", wline_ac.c_str());
-            else
-                fields_size = chg_fields_size; /* include wlc stats */
         }
     }
 
@@ -125,7 +114,6 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
                    &pca_rs[1], &pca_rs[2], &pca_rs[3], &pca_rs[4]) != 7) {
             ALOGE("Couldn't process %s", pca_line.c_str());
         } else {
-            fields_size = chg_fields_size; /* include pca stats */
             tmp[12] = pca_rs[2];
             tmp[13] = pca_rs[3];
             tmp[14] = pca_rs[4];
@@ -143,8 +131,8 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
     if (ReadFileToString(kGChargerMetricsPath.c_str(), &file_contents)) {
         ss.str(file_contents);
         while (std::getline(ss, pdo_line)) {
-            if (sscanf(pdo_line.c_str(), "D:%x,%x,%x,%x,%x,%x,%x", &pca_ac[0], &pca_ac[1], &pca_rs[0],
-                   &pca_rs[1], &pca_rs[2], &pca_rs[3], &pca_rs[4]) != 7) {
+            if (sscanf(pdo_line.c_str(), "D:%x,%x,%x,%x,%x,%x,%x", &pca_ac[0], &pca_ac[1],
+                       &pca_rs[0], &pca_rs[1], &pca_rs[2], &pca_rs[3], &pca_rs[4]) != 7) {
                 continue;
             } else {
                 ALOGD("processed %s, apdo:%d, pdo:%d", pdo_line.c_str(), pca_ac[1], pca_rs[4]);
@@ -155,7 +143,12 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
         }
     }
 
-    for (i = 0; i < fields_size; i++) {
+    if (ReadFileToString(kGAacrAlgoPath.c_str(), &file_contents)) {
+        ss.str(file_contents);
+        ss >> tmp[17];
+    }
+
+    for (i = 0; i < chg_fields_size; i++) {
         val.set<VendorAtomValue::intValue>(tmp[i]);
         values[charge_stats_fields[i] - kVendorAtomOffset] = val;
     }
diff --git a/pixelstats/SysfsCollector.cpp b/pixelstats/SysfsCollector.cpp
index 0d570110..a79dda0d 100644
--- a/pixelstats/SysfsCollector.cpp
+++ b/pixelstats/SysfsCollector.cpp
@@ -32,6 +32,7 @@
 #include <sys/vfs.h>
 #include <cinttypes>
 #include <string>
+#include <filesystem>
 
 #ifndef ARRAY_SIZE
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
@@ -54,6 +55,7 @@ using android::hardware::google::pixel::PixelAtoms::DisplayPanelErrorStats;
 using android::hardware::google::pixel::PixelAtoms::DisplayPortDSCSupportCountStatsReported;
 using android::hardware::google::pixel::PixelAtoms::DisplayPortErrorStats;
 using android::hardware::google::pixel::PixelAtoms::DisplayPortMaxResolutionCountStatsReported;
+using android::hardware::google::pixel::PixelAtoms::DmVerityPartitionReadAmountReported;
 using android::hardware::google::pixel::PixelAtoms::F2fsAtomicWriteInfo;
 using android::hardware::google::pixel::PixelAtoms::F2fsCompressionInfo;
 using android::hardware::google::pixel::PixelAtoms::F2fsGcSegmentInfo;
@@ -81,6 +83,7 @@ using android::hardware::google::pixel::PixelAtoms::VendorSpeakerImpedance;
 using android::hardware::google::pixel::PixelAtoms::VendorSpeakerStatsReported;
 using android::hardware::google::pixel::PixelAtoms::VendorSpeechDspStat;
 using android::hardware::google::pixel::PixelAtoms::VendorTempResidencyStats;
+using android::hardware::google::pixel::PixelAtoms::WaterEventReported;
 using android::hardware::google::pixel::PixelAtoms::ZramBdStat;
 using android::hardware::google::pixel::PixelAtoms::ZramMmStat;
 
@@ -142,7 +145,8 @@ SysfsCollector::SysfsCollector(const struct SysfsPaths &sysfs_paths)
       kMaxfgHistoryPath("/dev/maxfg_history"),
       kFGModelLoadingPath(sysfs_paths.FGModelLoadingPath),
       kFGLogBufferPath(sysfs_paths.FGLogBufferPath),
-      kSpeakerVersionPath(sysfs_paths.SpeakerVersionPath) {}
+      kSpeakerVersionPath(sysfs_paths.SpeakerVersionPath),
+      kWaterEventPath(sysfs_paths.WaterEventPath){}
 
 bool SysfsCollector::ReadFileToInt(const std::string &path, int *val) {
     return ReadFileToInt(path.c_str(), val);
@@ -926,6 +930,90 @@ void SysfsCollector::logF2fsSmartIdleMaintEnabled(const std::shared_ptr<IStats>
     }
 }
 
+void SysfsCollector::logDmVerityPartitionReadAmount(const std::shared_ptr<IStats> &stats_client) {
+    //  Array of partition names corresponding to the DmPartition enum.
+    static constexpr std::array<std::string_view, 4>
+        partitionNames = {"system", "system_ext", "product", "vendor"};
+
+    // These index comes from kernel Document
+    // Documentation/ABI/stable/sysfs-block
+    constexpr int READ_SEC_IDX = 2;
+
+    // Get the slot suffix from system property
+    std::string slotSuffix = android::base::GetProperty("ro.boot.slot_suffix", "");
+
+    size_t partitionIndex = 0;
+    for (const auto& partitionName : partitionNames) {
+        ++partitionIndex;
+
+        // Construct the partition name with slot suffix
+        std::string fullPartitionName = std::string(partitionName) + slotSuffix;
+
+        // Construct the path using std::string
+        std::string relativePathStr = "/dev/block/mapper/" + fullPartitionName;
+
+        // Create the std::filesystem::path from the string
+        std::filesystem::path relativePath(relativePathStr);
+        std::error_code ec;
+        std::filesystem::path absolutePath = std::filesystem::canonical(relativePath, ec);
+
+        if (ec) {
+          ALOGE("Failed to get canonical path for %s: %s",
+            fullPartitionName.c_str(),
+            ec.message().c_str());
+          continue;
+        }
+
+        // If canonical path is found, extract the filename (e.g., "dm-0")
+        std::string dmDeviceName = absolutePath.filename();
+        dmDeviceName = android::base::Trim(dmDeviceName);
+
+        // Directly process the dmDeviceName here
+        std::string statPath = "/sys/block/" + dmDeviceName + "/stat";
+        std::string statContent;
+        if (!android::base::ReadFileToString(statPath, &statContent)) {
+            ALOGE("Failed to read symbolic link: %s", statPath.c_str());
+            continue; // Skip to the next partitionName
+        }
+
+        std::vector<std::string> statFields;
+        std::istringstream iss(statContent);
+        std::string field;
+        while (iss >> field) {
+            statFields.push_back(field);
+        }
+        if (statFields.size() < 3) {
+            ALOGE("Invalid block statistics format: %s", statPath.c_str());
+            continue; // Skip to the next partitionName
+        }
+
+        int64_t readSectors;
+        if (!android::base::ParseInt(statFields[READ_SEC_IDX], &readSectors)) {
+            // Handle the error, e.g., log an error message, set a default value, etc.
+            ALOGE("Failed to parse read sectors value: %s", statFields[READ_SEC_IDX].c_str());
+            readSectors = -1; // Or another appropriate default/error value
+        }
+        std::vector<VendorAtomValue> values(2);
+        // Use partitionIndex for kDmPartitionFieldNumber
+        values[DmVerityPartitionReadAmountReported::kDmPartitionFieldNumber - kVendorAtomOffset] =
+            VendorAtomValue::make<VendorAtomValue::intValue>(static_cast<int32_t>(partitionIndex));
+
+        // Use converted readSectors for kReadSectorsFieldNumber
+        values[DmVerityPartitionReadAmountReported::kReadSectorsFieldNumber - kVendorAtomOffset] =
+            VendorAtomValue::make<VendorAtomValue::longValue>(readSectors);
+
+        // Send vendor atom to IStats HAL
+        VendorAtom event = {.reverseDomainName = PixelAtoms::ReverseDomainNames().pixel(),
+                            .atomId = PixelAtoms::Atom::kDmVerityPartitionReadAmountReported,
+                            .values = std::move(values)};
+        const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
+        if (!ret.isOk()) {
+            ALOGE("Unable to report DmVerityPartitionReadAmountReported to Stats service");
+        }
+    }
+    return;
+}
+
 void SysfsCollector::logBlockStatsReported(const std::shared_ptr<IStats> &stats_client) {
     std::string sdaPath = "/sys/block/sda/stat";
     std::string file_contents;
@@ -2135,6 +2223,7 @@ void SysfsCollector::logPerDay() {
     logDisplayPortStats(stats_client);
     logDisplayPortDSCStats(stats_client);
     logDisplayPortMaxResolutionStats(stats_client);
+    logDmVerityPartitionReadAmount(stats_client);
     logHDCPStats(stats_client);
     logF2fsStats(stats_client);
     logF2fsAtomicWriteInfo(stats_client);
@@ -2184,8 +2273,22 @@ void SysfsCollector::logBrownout() {
                                                 kBrownoutReasonProp);
 }
 
+void SysfsCollector::logWater() {
+    const std::shared_ptr<IStats> stats_client = getStatsService();
+    if (!stats_client) {
+        ALOGE("Unable to get AIDL Stats service");
+        return;
+    }
+    if (kWaterEventPath == nullptr || strlen(kWaterEventPath) == 0)
+        return;
+    PixelAtoms::WaterEventReported::EventPoint event_point =
+            PixelAtoms::WaterEventReported::EventPoint::WaterEventReported_EventPoint_BOOT;
+    water_event_reporter_.logEvent(stats_client, event_point, kWaterEventPath);
+}
+
 void SysfsCollector::logOnce() {
     logBrownout();
+    logWater();
 }
 
 void SysfsCollector::logPerHour() {
diff --git a/pixelstats/UeventListener.cpp b/pixelstats/UeventListener.cpp
index 86002599..ddbfa7ed 100644
--- a/pixelstats/UeventListener.cpp
+++ b/pixelstats/UeventListener.cpp
@@ -72,6 +72,7 @@ using android::hardware::google::pixel::PixelAtoms::PdVidPid;
 using android::hardware::google::pixel::PixelAtoms::ThermalSensorAbnormalityDetected;
 using android::hardware::google::pixel::PixelAtoms::VendorHardwareFailed;
 using android::hardware::google::pixel::PixelAtoms::VendorUsbPortOverheat;
+using android::hardware::google::pixel::PixelAtoms::WaterEventReported;
 
 constexpr int32_t UEVENT_MSG_LEN = 2048;  // it's 2048 in all other users.
 constexpr int32_t PRODUCT_TYPE_OFFSET = 23;
@@ -395,6 +396,15 @@ void UeventListener::ReportThermalAbnormalEvent(const std::shared_ptr<IStats> &s
         ALOGE("Unable to report Thermal Abnormal event.");
 }
 
+void UeventListener::ReportWaterEvent(const std::shared_ptr<IStats> &stats_client,
+                                      const char *driver, const char *devpath)
+{
+    if (!stats_client || !driver || !devpath || !water_event_reporter_.ueventDriverMatch(driver))
+        return;
+
+    water_event_reporter_.logUevent(stats_client, devpath);
+}
+
 bool UeventListener::ProcessUevent() {
     char msg[UEVENT_MSG_LEN + 2];
     char *cp;
@@ -491,6 +501,7 @@ bool UeventListener::ProcessUevent() {
         ReportThermalAbnormalEvent(stats_client, devpath, thermal_abnormal_event_type,
                                    thermal_abnormal_event_info);
         ReportFGMetricsEvent(stats_client, driver);
+        ReportWaterEvent(stats_client, driver, devpath);
     }
 
     if (log_fd_ > 0) {
diff --git a/pixelstats/WaterEventReporter.cpp b/pixelstats/WaterEventReporter.cpp
new file mode 100644
index 00000000..d6fab923
--- /dev/null
+++ b/pixelstats/WaterEventReporter.cpp
@@ -0,0 +1,198 @@
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
+#define LOG_TAG "pixelstats: WaterEvent"
+
+#include <aidl/android/frameworks/stats/IStats.h>
+#include <android-base/file.h>
+#include <android-base/properties.h>
+#include <android-base/stringprintf.h>
+#include <android-base/strings.h>
+#include <android/binder_manager.h>
+#include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
+#include <pixelstats/WaterEventReporter.h>
+#include <utils/Log.h>
+
+#include <cinttypes>
+
+
+namespace android {
+namespace hardware {
+namespace google {
+namespace pixel {
+
+using aidl::android::frameworks::stats::IStats;
+using aidl::android::frameworks::stats::VendorAtom;
+using aidl::android::frameworks::stats::VendorAtomValue;
+using android::base::ReadFileToString;
+
+static const char * const WATER_EVENT_DRIVER_STR = "DRIVER=h2omg";
+
+WaterEventReporter::WaterEventReporter() {};
+
+static bool fileExists(const std::string &path) {
+    struct stat sb;
+
+    return stat(path.c_str(), &sb) == 0;
+}
+
+static bool readFileToInt(const char *const path, int *val) {
+    std::string file_contents;
+
+    if (!ReadFileToString(path, &file_contents)) {
+        ALOGE("Unable to read %s - %s", path, strerror(errno));
+        return false;
+    } else if (sscanf(file_contents.c_str(), "%d", val) != 1) {
+        ALOGE("Unable to convert %s to int - %s", path, strerror(errno));
+        return false;
+    }
+    return true;
+}
+
+static inline bool readFileToInt(const std::string &path, int *val) {
+    return readFileToInt(path.c_str(), val);
+}
+
+void WaterEventReporter::logEvent(const std::shared_ptr<IStats> &stats_client,
+                                  PixelAtoms::WaterEventReported::EventPoint event_point,
+                                  const std::string_view sysfs_root)
+{
+   const std::string sysfs_path(sysfs_root);
+   static int count = 0;
+
+    if (!fileExists(sysfs_path)) {
+        ALOGE("WaterEvent path is not valid %s", sysfs_path.c_str());
+        return;
+    }
+
+    std::vector<VendorAtomValue> values(kNumOfWaterEventAtoms, 0);
+
+    // Is this during boot or as a result of an event
+    values[PixelAtoms::WaterEventReported::kCollectionEventFieldNumber - kVendorAtomOffset] = event_point;
+
+    // Most important, what is the state of the fuse
+    std::string fuse_state_str;
+    if (ReadFileToString(sysfs_path + "/fuse/status", &fuse_state_str)) {
+        if (!fuse_state_str.compare(0, 4, "open")) {
+            values[PixelAtoms::WaterEventReported::kFuseStateFieldNumber - kVendorAtomOffset] =
+                    PixelAtoms::WaterEventReported::FuseState::WaterEventReported_FuseState_BLOWN;
+        } else if (!fuse_state_str.compare(0, 5, "short")) {
+            values[PixelAtoms::WaterEventReported::kFuseStateFieldNumber - kVendorAtomOffset] =
+                    PixelAtoms::WaterEventReported::FuseState::WaterEventReported_FuseState_INTACT;
+        } else {
+             values[PixelAtoms::WaterEventReported::kFuseStateFieldNumber - kVendorAtomOffset] =
+                     PixelAtoms::WaterEventReported::FuseState::WaterEventReported_FuseState_FUSE_STATE_UNKNOWN;
+        }
+    }
+
+    // Is the fuse enabled
+    int fuse_enable;
+    if (readFileToInt(sysfs_path + "/fuse/enable", &fuse_enable))
+        values[PixelAtoms::WaterEventReported::kFuseEnabledFieldNumber - kVendorAtomOffset] =
+                fuse_enable ? PixelAtoms::WaterEventReported::CircuitState::WaterEventReported_CircuitState_CIRCUIT_ENABLED :
+                              PixelAtoms::WaterEventReported::CircuitState::WaterEventReported_CircuitState_CIRCUIT_DISABLED;
+
+    // Is system fault enabled
+    int fault_enable;
+    if (readFileToInt(sysfs_path + "/fault/enable", &fault_enable))
+        values[PixelAtoms::WaterEventReported::kFaultEnabledFieldNumber - kVendorAtomOffset] =
+                fault_enable ? PixelAtoms::WaterEventReported::CircuitState::WaterEventReported_CircuitState_CIRCUIT_ENABLED :
+                              PixelAtoms::WaterEventReported::CircuitState::WaterEventReported_CircuitState_CIRCUIT_DISABLED;
+
+    std::tuple<std::string, int, int> sensors[] = {
+        {"reference", PixelAtoms::WaterEventReported::kReferenceStateFieldNumber, PixelAtoms::WaterEventReported::kReferenceThresholdFieldNumber},
+        {"sensor0", PixelAtoms::WaterEventReported::kSensor0StateFieldNumber, PixelAtoms::WaterEventReported::kSensor0ThresholdFieldNumber},
+        {"sensor1", PixelAtoms::WaterEventReported::kSensor1StateFieldNumber, PixelAtoms::WaterEventReported::kSensor1ThresholdFieldNumber},
+        {"sensor2", PixelAtoms::WaterEventReported::kSensor1StateFieldNumber, PixelAtoms::WaterEventReported::kSensor1ThresholdFieldNumber}
+    };
+
+    //   Get the sensor states (including reference) from either the boot_value (if this is during
+    //   startup), or the latched_value if this is the result of a uevent
+    for (auto e : sensors) {
+        std::string sensor_path = std::get<0>(e);
+        int sensor_state_field_number = std::get<1>(e);
+        int threshold_field_number = std::get<2>(e);
+
+        std::string sensor_state_path = sysfs_path + "/" + sensor_path;
+        sensor_state_path += (event_point == PixelAtoms::WaterEventReported::EventPoint::WaterEventReported_EventPoint_BOOT) ? "/boot_value" : "/latched_value";
+
+        std::string sensor_state_str;
+        if (!ReadFileToString(sensor_state_path, &sensor_state_str)) {
+            continue;
+        }
+
+        if (!sensor_state_str.compare(0, 3, "dry")) {
+             values[sensor_state_field_number - kVendorAtomOffset] =
+                     PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_DRY;
+        } else if (sensor_state_str.compare(0, 3, "wet")) {
+             values[sensor_state_field_number- kVendorAtomOffset] =
+                PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_WET;
+        } else if (!sensor_state_str.compare(0, 3, "invl")) {
+            values[sensor_state_field_number - kVendorAtomOffset] =
+                PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_INVALID;
+        } else if (!sensor_state_str.compare(0, 3, "dis")) {
+                values[sensor_state_field_number - kVendorAtomOffset] =
+                        PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_DISABLED;
+        } else {
+                values[sensor_state_field_number - kVendorAtomOffset] =
+                    PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_SENSOR_STATE_UNKNOWN;
+            continue;
+        }
+
+        // report the threshold
+        std::string threshold_path = sysfs_path + "/" + sensor_path + "/threshold";
+        int sensor_threshold;
+        if (readFileToInt(threshold_path, &sensor_threshold)) {
+            values[PixelAtoms::WaterEventReported::kReferenceThresholdFieldNumber - kVendorAtomOffset] = sensor_threshold;
+        }
+    }
+
+    VendorAtom event = {.reverseDomainName = "",
+                        .atomId = PixelAtoms::Atom::kWaterEventReported,
+                        .values = std::move(values)};
+    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
+    if (!ret.isOk())
+        ALOGE("Unable to report Water event.");
+}
+
+void WaterEventReporter::logUevent(const std::shared_ptr<IStats> &stats_client,
+                                   const std::string_view uevent_devpath)
+{
+    ALOGI("Reporting Water event");
+    std::string dpath(uevent_devpath);
+
+    std::vector<std::string> value = android::base::Split(dpath, "=");
+    if (value.size() != 2) {
+        ALOGE("Error report Water event split failed");
+        return;
+    }
+
+    std::string sysfs_path("/sys");
+    sysfs_path += value[1];
+
+    PixelAtoms::WaterEventReported::EventPoint event_point =
+        PixelAtoms::WaterEventReported::EventPoint::WaterEventReported_EventPoint_IRQ;
+    logEvent(stats_client, event_point, sysfs_path);
+}
+
+bool WaterEventReporter::ueventDriverMatch(const char * const driver) {
+    return !strncmp(driver, WATER_EVENT_DRIVER_STR, strlen(WATER_EVENT_DRIVER_STR));
+}
+
+}  // namespace pixel
+}  // namespace google
+}  // namespace hardware
+}  // namespace android
diff --git a/pixelstats/include/pixelstats/BatteryEEPROMReporter.h b/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
index 6dc1c629..5d127720 100644
--- a/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
+++ b/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
@@ -30,15 +30,6 @@ namespace pixel {
 using aidl::android::frameworks::stats::IStats;
 using aidl::android::frameworks::stats::VendorAtomValue;
 
-// The storage for save whole history is 928 byte
-// each history contains 19 items with total size 28 byte
-// hence the history number is 928/28~33
-#define BATT_HIST_NUM_MAX 33
-
-// New history layout total size is 924 or 900 byte
-// each history data size is 12 bytes: 900/12=75
-#define BATT_HIST_NUM_MAX_V2 75
-
 /**
  * A class to upload battery EEPROM metrics
  */
@@ -118,9 +109,9 @@ class BatteryEEPROMReporter {
         uint8_t timer_h;
          /* The full capacity of the battery learning at the end of every charge cycle */
         uint16_t full_rep;
+        /* The battery pairing state */
+        int16_t battery_pairing;
     };
-    /* The number of elements in struct BatteryHistory for P20 series */
-    const int kNumBatteryHistoryFields = 19;
     /* The number of elements for relaxation event */
     const int kNumFGLearningFieldsV2 = 16;
     /* with additional unix time field */
@@ -131,7 +122,7 @@ class BatteryEEPROMReporter {
     unsigned int last_hv_check_ = 0;
 
     /* P21+ history format */
-    struct BatteryHistoryExtend {
+    struct BatteryHistoryRawFormat {
         uint16_t tempco;
         uint16_t rcomp0;
         uint8_t timer_h;
@@ -182,10 +173,13 @@ class BatteryEEPROMReporter {
     void reportEventInt32(const std::shared_ptr<IStats> &stats_client,
                      const struct BatteryHistoryInt32 &hist);
     void setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset, int content);
+    bool ReadFileToInt(const std::string &path, int16_t *val);
 
     const int kNum77759GMSRFields = 11;
     const int kNum77779GMSRFields = 9;
     const int kNum17201HISTFields = 16;
+
+    const std::string kBatteryPairingPath = "/sys/class/power_supply/battery/pairing_state";
 };
 
 }  // namespace pixel
diff --git a/pixelstats/include/pixelstats/BrownoutDetectedReporter.h b/pixelstats/include/pixelstats/BrownoutDetectedReporter.h
index 4e811b49..5e801eec 100644
--- a/pixelstats/include/pixelstats/BrownoutDetectedReporter.h
+++ b/pixelstats/include/pixelstats/BrownoutDetectedReporter.h
@@ -62,6 +62,49 @@ enum CsvIdx {
     MAX_CURR,
     IDX_VIMON_V,
     IDX_VIMON_I,
+    PRE_OCP_CPU1_BCKUP_IDX,
+    PRE_OCP_CPU2_BCKUP_IDX,
+    PRE_OCP_TPU_BCKUP_IDX,
+    PRE_OCP_GPU_BCKUP_IDX,
+    PRE_UVLO_HIT_CNT_M_IDX,
+    PRE_UVLO_HIT_CNT_S_IDX,
+    UVLO_DUR_IDX,
+    ODPM_IRQ_STAT_0_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_1_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_2_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_3_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_4_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_5_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_6_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_7_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_8_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_9_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_10_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_11_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_0_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_1_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_2_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_3_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_4_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_5_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_6_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_7_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_8_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_9_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_10_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_11_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_EXT_0_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_EXT_1_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_EXT_2_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_EXT_3_SYS_EVT_MAIN_BCKUP_IDX,
+    ODPM_IRQ_STAT_EXT_0_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_EXT_1_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_EXT_2_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_EXT_3_SYS_EVT_SUB_BCKUP_IDX,
+    ODPM_IRQ_STAT_GPU_BCKUP_IDX,
+    ODPM_IRQ_STAT_TPU_BCKUP_IDX,
+    ODPM_IRQ_STAT_CPU1_BCKUP_IDX,
+    ODPM_IRQ_STAT_CPU2_BCKUP_IDX,
 };
 
 enum Irq {
@@ -118,9 +161,52 @@ class BrownoutDetectedReporter {
         int evt_cnt_oilo2_;
         int vimon_vbatt_;
         int vimon_ibatt_;
+        int pre_ocp_cpu1_bckup_;
+        int pre_ocp_cpu2_bckup_;
+        int pre_ocp_tpu_bckup_;
+        int pre_ocp_gpu_bckup_;
+        int pre_uvlo_hit_cnt_m_;
+        int pre_uvlo_hit_cnt_s_;
+        int uvlo_dur_;
+        int odpm_irq_stat_0_sys_evt_main_bckup_;
+        int odpm_irq_stat_1_sys_evt_main_bckup_;
+        int odpm_irq_stat_2_sys_evt_main_bckup_;
+        int odpm_irq_stat_3_sys_evt_main_bckup_;
+        int odpm_irq_stat_4_sys_evt_main_bckup_;
+        int odpm_irq_stat_5_sys_evt_main_bckup_;
+        int odpm_irq_stat_6_sys_evt_main_bckup_;
+        int odpm_irq_stat_7_sys_evt_main_bckup_;
+        int odpm_irq_stat_8_sys_evt_main_bckup_;
+        int odpm_irq_stat_9_sys_evt_main_bckup_;
+        int odpm_irq_stat_10_sys_evt_main_bckup_;
+        int odpm_irq_stat_11_sys_evt_main_bckup_;
+        int odpm_irq_stat_0_sys_evt_sub_bckup_;
+        int odpm_irq_stat_1_sys_evt_sub_bckup_;
+        int odpm_irq_stat_2_sys_evt_sub_bckup_;
+        int odpm_irq_stat_3_sys_evt_sub_bckup_;
+        int odpm_irq_stat_4_sys_evt_sub_bckup_;
+        int odpm_irq_stat_5_sys_evt_sub_bckup_;
+        int odpm_irq_stat_6_sys_evt_sub_bckup_;
+        int odpm_irq_stat_7_sys_evt_sub_bckup_;
+        int odpm_irq_stat_8_sys_evt_sub_bckup_;
+        int odpm_irq_stat_9_sys_evt_sub_bckup_;
+        int odpm_irq_stat_10_sys_evt_sub_bckup_;
+        int odpm_irq_stat_11_sys_evt_sub_bckup_;
+        int odpm_irq_stat_ext_0_sys_evt_main_bckup_;
+        int odpm_irq_stat_ext_1_sys_evt_main_bckup_;
+        int odpm_irq_stat_ext_2_sys_evt_main_bckup_;
+        int odpm_irq_stat_ext_3_sys_evt_main_bckup_;
+        int odpm_irq_stat_ext_0_sys_evt_sub_bckup_;
+        int odpm_irq_stat_ext_1_sys_evt_sub_bckup_;
+        int odpm_irq_stat_ext_2_sys_evt_sub_bckup_;
+        int odpm_irq_stat_ext_3_sys_evt_sub_bckup_;
+        int odpm_irq_stat_gpu_bckup_;
+        int odpm_irq_stat_tpu_bckup_;
+        int odpm_irq_stat_cpu1_bckup_;
+        int odpm_irq_stat_cpu2_bckup_;
     };
 
-    void setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset, int content);
+    void setAtomFieldValue(std::vector<VendorAtomValue> &values, int offset, int content);
     long parseTimestamp(std::string timestamp);
     bool updateIfFound(std::string line, std::regex pattern, int *current_value, Update flag);
     void uploadData(const std::shared_ptr<IStats> &stats_client,
diff --git a/pixelstats/include/pixelstats/ChargeStatsReporter.h b/pixelstats/include/pixelstats/ChargeStatsReporter.h
index 69b6eb9c..e787474d 100644
--- a/pixelstats/include/pixelstats/ChargeStatsReporter.h
+++ b/pixelstats/include/pixelstats/ChargeStatsReporter.h
@@ -56,12 +56,20 @@ class ChargeStatsReporter {
     // -2.
     const int kVendorAtomOffset = 2;
 
+    const int kNumChgStatsFormat00Fields = 7;   // "%d,%d,%d, %d,%d,%d,%d"
+    const int kNumChgStatsFormat01Fields = 8;   // "%d,%d,%d, %d,%d,%d,%d %d" AACR
+    const int kNumChgStatsFormat02Fields = 10;  // "%d,%d,%d, %d,%d,%d,%d %d %d,%d" AACR + CSI
+    const int kNumChgStatsFormat03Fields =
+            12;  // "%d,%d,%d, %d,%d,%d,%d %d %d,%d, %d,%d" AACR + CSI + AACP
+
     const std::string kThermalChargeMetricsPath =
             "/sys/devices/platform/google,charger/thermal_stats";
 
     const std::string kGChargerMetricsPath = "/sys/devices/platform/google,charger/charge_stats";
 
     const std::string kGDualBattMetricsPath = "/sys/class/power_supply/dualbatt/dbatt_stats";
+
+    const std::string kGAacrAlgoPath = "/sys/class/power_supply/battery/aacr_algo";
 };
 
 }  // namespace pixel
diff --git a/pixelstats/include/pixelstats/SysfsCollector.h b/pixelstats/include/pixelstats/SysfsCollector.h
index 15d50ddf..908dab23 100644
--- a/pixelstats/include/pixelstats/SysfsCollector.h
+++ b/pixelstats/include/pixelstats/SysfsCollector.h
@@ -30,6 +30,7 @@
 #include "MmMetricsReporter.h"
 #include "TempResidencyReporter.h"
 #include "ThermalStatsReporter.h"
+#include "WaterEventReporter.h"
 
 namespace android {
 namespace hardware {
@@ -100,6 +101,7 @@ class SysfsCollector {
         const std::vector<std::string> FGModelLoadingPath;
         const std::vector<std::string> FGLogBufferPath;
         const char *const SpeakerVersionPath;
+        const char *const WaterEventPath;
     };
 
     SysfsCollector(const struct SysfsPaths &paths);
@@ -111,6 +113,7 @@ class SysfsCollector {
     void aggregatePer5Min();
     void logOnce();
     void logBrownout();
+    void logWater();
     void logPerDay();
     void logPerHour();
 
@@ -161,6 +164,7 @@ class SysfsCollector {
     void logOffloadEffectsStats(const std::shared_ptr<IStats> &stats_client);
     void logBluetoothAudioUsage(const std::shared_ptr<IStats> &stats_client);
     void logBatteryGMSR(const std::shared_ptr<IStats> &stats_client);
+    void logDmVerityPartitionReadAmount(const std::shared_ptr<IStats> &stats_client);
     void logBatteryHistoryValidation();
 
     const char *const kSlowioReadCntPath;
@@ -221,6 +225,7 @@ class SysfsCollector {
     const std::vector<std::string> kFGModelLoadingPath;
     const std::vector<std::string> kFGLogBufferPath;
     const char *const kSpeakerVersionPath;
+    const char *const kWaterEventPath;
 
     BatteryEEPROMReporter battery_EEPROM_reporter_;
     MmMetricsReporter mm_metrics_reporter_;
@@ -232,6 +237,7 @@ class SysfsCollector {
     BatteryHealthReporter battery_health_reporter_;
     BatteryTTFReporter battery_time_to_full_reporter_;
     TempResidencyReporter temp_residency_reporter_;
+    WaterEventReporter water_event_reporter_;
     // Proto messages are 1-indexed and VendorAtom field numbers start at 2, so
     // store everything in the values array at the index of the field number    // -2.
     const int kVendorAtomOffset = 2;
diff --git a/pixelstats/include/pixelstats/UeventListener.h b/pixelstats/include/pixelstats/UeventListener.h
index a9e87cb5..125db874 100644
--- a/pixelstats/include/pixelstats/UeventListener.h
+++ b/pixelstats/include/pixelstats/UeventListener.h
@@ -22,6 +22,8 @@
 #include <pixelstats/BatteryCapacityReporter.h>
 #include <pixelstats/ChargeStatsReporter.h>
 #include <pixelstats/BatteryFGReporter.h>
+#include <pixelstats/WaterEventReporter.h>
+
 
 namespace android {
 namespace hardware {
@@ -98,6 +100,8 @@ class UeventListener {
                                     const char *devpath, const char *thermal_abnormal_event_type,
                                     const char *thermal_abnormal_event_info);
     void ReportFGMetricsEvent(const std::shared_ptr<IStats> &stats_client, const char *driver);
+    void ReportWaterEvent(const std::shared_ptr<IStats> &stats_client,
+                          const char *driver, const char *devpath);
 
     const std::string kAudioUevent;
     const std::string kBatterySSOCPath;
@@ -195,6 +199,7 @@ class UeventListener {
     BatteryCapacityReporter battery_capacity_reporter_;
     ChargeStatsReporter charge_stats_reporter_;
     BatteryFGReporter battery_fg_reporter_;
+    WaterEventReporter water_event_reporter_;
 
     // Proto messages are 1-indexed and VendorAtom field numbers start at 2, so
     // store everything in the values array at the index of the field number
diff --git a/pixelstats/include/pixelstats/WaterEventReporter.h b/pixelstats/include/pixelstats/WaterEventReporter.h
new file mode 100644
index 00000000..def9715f
--- /dev/null
+++ b/pixelstats/include/pixelstats/WaterEventReporter.h
@@ -0,0 +1,57 @@
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
+#ifndef HARDWARE_GOOGLE_PIXEL_PIXELSTATS_WATEREVENTREPORTER_H
+#define HARDWARE_GOOGLE_PIXEL_PIXELSTATS_WATEREVENTREPORTER_H
+
+#include <aidl/android/frameworks/stats/IStats.h>
+#include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
+
+#include <string>
+
+namespace android {
+namespace hardware {
+namespace google {
+namespace pixel {
+
+using aidl::android::frameworks::stats::IStats;
+
+/**
+ * A class to upload Pixel Water Event metrics
+ */
+class WaterEventReporter {
+  public:
+    WaterEventReporter();
+    void logEvent(const std::shared_ptr<IStats> &stats_client,
+                  PixelAtoms::WaterEventReported::EventPoint event_point,
+                  const std::string_view sysfs_root);
+    void logUevent(const std::shared_ptr<IStats> &stats_client,
+                  const std::string_view uevent_devpath);
+    bool ueventDriverMatch(const char * const driver);
+  private:
+    // Proto messages are 1-indexed and VendorAtom field numbers start at 2, so
+    // store everything in the values array at the index of the field number
+    // -2.
+    const int kVendorAtomOffset = 2;
+    const int kNumOfWaterEventAtoms = 13;
+};
+
+}  // namespace pixel
+}  // namespace google
+}  // namespace hardware
+}  // namespace android
+
+#endif  // HARDWARE_GOOGLE_PIXEL_PIXELSTATS_WATEREVENTREPORTER_H
diff --git a/pixelstats/pixelatoms.proto b/pixelstats/pixelatoms.proto
index eb30e5d0..d277645a 100644
--- a/pixelstats/pixelatoms.proto
+++ b/pixelstats/pixelatoms.proto
@@ -139,6 +139,10 @@ message Atom {
       VendorAudioDspRecordUsageStatsReported vendor_audio_dsp_record_usage_stats_reported = 105085 [(android.os.statsd.module) = "pixelaudio"];
       VendorAudioUsbConnectionState vendor_audio_usb_connection_state = 105086 [(android.os.statsd.module) = "pixelaudio"];
       VendorAudioSpeakerPowerStatsReported vendor_audio_speaker_power_stats_reported = 105087 [(android.os.statsd.module) = "pixelaudio"];
+      DmVerityPartitionReadAmountReported dm_verity_partition_read_amount_reported = 105088;
+      WaterEventReported water_event_reported = 105089;
+      MediaPlaybackUsageStatsReported media_playback_usage_stats_reported = 105090 [(android.os.statsd.module) = "pixelaudio"];
+      CallUsageStatsReported call_usage_stats_reported = 105091 [(android.os.statsd.module) = "pixelaudio"];
     }
     // AOSP atom ID range ends at 109999
     reserved 109997; // reserved for VtsVendorAtomJavaTest test atom
@@ -237,6 +241,10 @@ message ChargeStats {
     /* Charging Speed Indicator(CSI) status and type */
     optional int32 csi_aggregate_status = 17;
     optional int32 csi_aggregate_type = 18;
+
+    optional int32 aacr_algo = 19;
+    optional int32 aacp_version = 20;
+    optional int32 aacc = 21;
 }
 
 /* A message containing stats from each charge voltage tier. */
@@ -483,6 +491,18 @@ message BatteryEEPROM {
     optional int32 timer_h = 23;
     /* The full capacity of the battery learning at the end of every charge cycle */
     optional int32 full_rep = 24;
+
+    enum BattPairingEvent {
+      WRITE_ERROR = -4;
+      READ_ERROR = -3;
+      MISMATCH = -2;
+      DISABLED = -1;
+      ENABLED = 0;
+      PAIRED = 1;
+      RESET = 2;
+    };
+
+    optional BattPairingEvent battery_pairing = 25;
 }
 
 /* A message containing an exceptional event from citadel. */
@@ -1708,6 +1728,92 @@ message BrownoutDetected {
     optional int32 mitigation_method_0_count = 47;
     // Mitigation Method 0 Entry Time
     optional int64 mitigation_method_0_time_us = 48;
+    // pre ocp cpu1 backup at brownout
+    optional int32 pre_ocp_cpu1_bckup = 49;
+    // pre ocp cpu2 backup at brownout
+    optional int32 pre_ocp_cpu2_bckup = 50;
+    // pre ocp tpu backup at brownout
+    optional int32 pre_ocp_tpu_bckup = 51;
+    // pre ocp gpu backup at brownout
+    optional int32 pre_ocp_gpu_bckup = 52;
+    // pre uvlo hit count for m pmic at brownout
+    optional int32 pre_uvlo_hit_cnt_m = 53;
+    // pre uvlo hit count for s pmic at brownout
+    optional int32 pre_uvlo_hit_cnt_s = 54;
+    // pre uvlo assertion duration at brownout
+    optional int32 pre_uvlo_dur = 55;
+    // odpm irq stat 0 main at brownout
+    optional int32 odpm_irq_stat_0_sys_evt_main_bckup = 56;
+    // odpm irq stat 1 main at brownout
+    optional int32 odpm_irq_stat_1_sys_evt_main_bckup = 57;
+    // odpm irq stat 2 main at brownout
+    optional int32 odpm_irq_stat_2_sys_evt_main_bckup = 58;
+    // odpm irq stat 3 main at brownout
+    optional int32 odpm_irq_stat_3_sys_evt_main_bckup = 59;
+    // odpm irq stat 4 main at brownout
+    optional int32 odpm_irq_stat_4_sys_evt_main_bckup = 60;
+    // odpm irq stat 5 main at brownout
+    optional int32 odpm_irq_stat_5_sys_evt_main_bckup = 61;
+    // odpm irq stat 6 main at brownout
+    optional int32 odpm_irq_stat_6_sys_evt_main_bckup = 62;
+    // odpm irq stat 7 main at brownout
+    optional int32 odpm_irq_stat_7_sys_evt_main_bckup = 63;
+    // odpm irq stat 8 main at brownout
+    optional int32 odpm_irq_stat_8_sys_evt_main_bckup = 64;
+    // odpm irq stat 9 main at brownout
+    optional int32 odpm_irq_stat_9_sys_evt_main_bckup = 65;
+    // odpm irq stat 10 main at brownout
+    optional int32 odpm_irq_stat_10_sys_evt_main_bckup = 66;
+    // odpm irq stat 11 main at brownout
+    optional int32 odpm_irq_stat_11_sys_evt_main_bckup = 67;
+    // odpm irq stat 0 sub at brownout
+    optional int32 odpm_irq_stat_0_sys_evt_sub_bckup = 68;
+    // odpm irq stat 1 sub at brownout
+    optional int32 odpm_irq_stat_1_sys_evt_sub_bckup = 69;
+    // odpm irq stat 2 sub at brownout
+    optional int32 odpm_irq_stat_2_sys_evt_sub_bckup = 70;
+    // odpm irq stat 3 sub at brownout
+    optional int32 odpm_irq_stat_3_sys_evt_sub_bckup = 71;
+    // odpm irq stat 4 sub at brownout
+    optional int32 odpm_irq_stat_4_sys_evt_sub_bckup = 72;
+    // odpm irq stat 5 sub at brownout
+    optional int32 odpm_irq_stat_5_sys_evt_sub_bckup = 73;
+    // odpm irq stat 6 sub at brownout
+    optional int32 odpm_irq_stat_6_sys_evt_sub_bckup = 74;
+    // odpm irq stat 7 sub at brownout
+    optional int32 odpm_irq_stat_7_sys_evt_sub_bckup = 75;
+    // odpm irq stat 8 sub at brownout
+    optional int32 odpm_irq_stat_8_sys_evt_sub_bckup = 76;
+    // odpm irq stat 9 sub at brownout
+    optional int32 odpm_irq_stat_9_sys_evt_sub_bckup = 77;
+    // odpm irq stat 10 sub at brownout
+    optional int32 odpm_irq_stat_10_sys_evt_sub_bckup = 78;
+    // odpm irq stat 11 sub at brownout
+    optional int32 odpm_irq_stat_11_sys_evt_sub_bckup = 79;
+    // odpm irq stat ext 0 main at brownout
+    optional int32 odpm_irq_stat_ext_0_sys_evt_main_bckup = 80;
+    // odpm irq stat ext 1 main at brownout
+    optional int32 odpm_irq_stat_ext_1_sys_evt_main_bckup = 81;
+    // odpm irq stat ext 2 main at brownout
+    optional int32 odpm_irq_stat_ext_2_sys_evt_main_bckup = 82;
+    // odpm irq stat ext 3 main at brownout
+    optional int32 odpm_irq_stat_ext_3_sys_evt_main_bckup = 83;
+    // odpm irq stat ext 0 sub at brownout
+    optional int32 odpm_irq_stat_ext_0_sys_evt_sub_bckup = 84;
+    // odpm irq stat ext 1 sub at brownout
+    optional int32 odpm_irq_stat_ext_1_sys_evt_sub_bckup = 85;
+    // odpm irq stat ext 2 sub at brownout
+    optional int32 odpm_irq_stat_ext_2_sys_evt_sub_bckup = 86;
+    // odpm irq stat ext 3 sub at brownout
+    optional int32 odpm_irq_stat_ext_3_sys_evt_sub_bckup = 87;
+    // odpm irq stat gpu at brownout
+    optional int32 odpm_irq_stat_gpu_bckup = 88;
+    // odpm irq stat tpu at brownout
+    optional int32 odpm_irq_stat_tpu_bckup = 89;
+    // odpm irq stat cpu1 at brownout
+    optional int32 odpm_irq_stat_cpu1_bckup = 90;
+    // odpm irq stat cpu2 at brownout
+    optional int32 odpm_irq_stat_cpu2_bckup = 91;
 }
 
 /*
@@ -2757,6 +2863,128 @@ message DisplayPortMaxResolutionCountStatsReported{
   optional int32 max_res_7680_4320 = 12;
 }
 
+/* Audio Device Interface. */
+enum AudioDeviceInterface {
+  UNKNOWN_DEVICE_INTERFACE = 0;
+
+  // Built-in speakers
+  SPEAKER = 1;
+  SPEAKER_EARPIECE = 2;
+  SPEAKER_SAFE = 3;
+
+  // Built-in microphones
+  MICROPHONES = 4;
+  BACK_MICROPHONES = 5;
+  // internal used microphones
+  ULTRASOUND_MICROPHONES = 6;
+  SOUND_TRIGGER_MICROPHONES = 7;
+
+  // BT SCO
+  BLUETOOTH_SCO_DEFAULT = 8;
+  BLUETOOTH_SCO_HEADSET = 9;
+  BLUETOOTH_SCO_CAR_KIT = 10;
+  BLUETOOTH_SCO_HEADSET_MICROPHONES = 11;
+
+  // BT A2DP
+  BLUETOOTH_A2DP_DEVICE = 12;
+  BLUETOOTH_A2DP_SPEAKER = 13;
+  BLUETOOTH_A2DP_HEADPHONE = 14;
+
+  // BT low energy (BLE)
+  BLUETOOTH_LOW_ENERGY_SPEAKER = 15;
+  BLUETOOTH_LOW_ENERGY_HEADSET = 16;
+  BLUETOOTH_LOW_ENERGY_BROADCAST = 17;
+  BLUETOOTH_LOW_ENERGY_HEADSET_MICROPHONES = 18;
+
+  // USB
+  USB_DEVICE = 19;
+  USB_HEADSET = 20;
+  USB_DOCK = 21;
+  USB_DEVICE_MICROPHONES = 22;
+  USB_HEADSET_MICROPHONES = 23;
+  USB_DOCK_MICROPHONES = 24;
+
+  // HDMI
+  HDMI_DEVICE = 25;
+
+  // Telephony
+  TELEPHONY_TX = 26;
+  TELEPHONY_RX = 27;
+  IN_CALL_CAPTURE_SOURCE0 = 28;
+  IN_CALL_CAPTURE_SOURCE1 = 29;
+  IN_CALL_CAPTURE_SOURCE2 = 30;
+
+  // Null sink and source
+  NULL_SOURCE = 31;
+  NULL_SINK = 32;
+
+  // Echo reference
+  ECHO_REFERENCE_DEVICE_INTERFACE = 33;
+}
+
+/* Audio Use Case. */
+enum AudioUseCase {
+  UNKNOWN_VENDOR_AUDIO_USECASE = 0;
+  // playback use cases
+  PRIMARY_PLAYBACK = 1;
+  RAW_PLAYBACK = 2;
+  DEEP_BUFFER_PLAYBACK = 3;
+  COMPRESS_OFFLOAD_PLAYBACK = 4;
+  MMAP_PLAYBACK = 5;
+  HIFI_PLAYBACK = 6;
+  VOIP_PLAYBACK = 7;
+  TELEPHONY_PLAYBACK = 8;
+  IN_CALL_PLAYBACK = 9;
+  SPATIALIZER_PLAYBACK = 10;
+  ULTRASOUND_PLAYBACK = 11;
+  HAPTIC_PLAYBACK = 12;
+  SPATIALIZER_OFFLOAD_PLAYBACK = 13;
+  // capture use cases
+  PRIMARY_CAPTURE = 14;
+  FAST_CAPTURE = 15;
+  HIFI_CAPTURE = 16;
+  MMAP_CAPTURE = 17;
+  VOIP_CAPTURE = 18;
+  VOIP_GSENET_CAPTURE = 19;
+  ULTRASOUND_CAPTURE = 20;
+  TELEPHONY_CAPTURE = 21;
+  IN_CALL_CAPTURE = 22;
+  SOUND_TRIGGER_CAPTURE = 23;
+  SOUND_TRIGGER_TAP_CAPTURE = 24;
+  HOTWORD_LOOKBACK_CAPTURE = 25;
+  ECHO_REFERENCE_CAPTURE = 26;
+
+  // voice call use case
+  VOICE_CALL_DOWNLINK = 27;
+  VOICE_CALL_UPLINK = 28;
+}
+
+/* Audio source with the original enum value. */
+enum AudioSource {
+  DEFAULT = 0;
+  MIC = 1;
+  VOICE_UPLINK = 2;
+  VOICE_DOWNLINK = 3;
+  VOICE_CALL = 4;
+  CAMCORDER = 5;
+  VOICE_RECOGNITION = 6;
+  VOICE_COMMUNICATION = 7;
+  REMOTE_SUBMIX = 8;
+  UNPROCESSED = 9;
+  VOICE_PERFORMANCE = 10;
+  ECHO_REFERENCE = 1997;
+  FM_TUNER = 1998;
+  HOTWORD = 1999;
+  ULTRASOUND = 2000;
+}
+
+enum AudioScreenFoldingState {
+  UNKNOWN_FOLDING_STATE = 0;
+  CLAMSHELL = 1;
+  CLOSED = 2;
+  OPEN = 3;
+}
+
 /*
  * A message containing recording usage event.
  * Logged from:
@@ -2792,121 +3020,6 @@ message VendorAudioDspRecordUsageStatsReported {
     CUSTOM_IN_PCM5 = 19;
   }
 
-  /* Audio Device Interface. */
-  enum AudioDeviceInterface {
-    UNKNOWN_DEVICE_INTERFACE = 0;
-
-    // Built-in speakers
-    SPEAKER = 1;
-    SPEAKER_EARPIECE = 2;
-    SPEAKER_SAFE = 3;
-
-    // Built-in microphones
-    MICROPHONES = 4;
-    BACK_MICROPHONES = 5;
-    // internal used microphones
-    ULTRASOUND_MICROPHONES = 6;
-    SOUND_TRIGGER_MICROPHONES = 7;
-
-    // BT SCO
-    BLUETOOTH_SCO_DEFAULT = 8;
-    BLUETOOTH_SCO_HEADSET = 9;
-    BLUETOOTH_SCO_CAR_KIT = 10;
-    BLUETOOTH_SCO_HEADSET_MICROPHONES = 11;
-
-    // BT A2DP
-    BLUETOOTH_A2DP_DEVICE = 12;
-    BLUETOOTH_A2DP_SPEAKER = 13;
-    BLUETOOTH_A2DP_HEADPHONE = 14;
-
-    // BT low energy (BLE)
-    BLUETOOTH_LOW_ENERGY_SPEAKER = 15;
-    BLUETOOTH_LOW_ENERGY_HEADSET = 16;
-    BLUETOOTH_LOW_ENERGY_BROADCAST = 17;
-    BLUETOOTH_LOW_ENERGY_HEADSET_MICROPHONES = 18;
-
-    // USB
-    USB_DEVICE = 19;
-    USB_HEADSET = 20;
-    USB_DOCK = 21;
-    USB_DEVICE_MICROPHONES = 22;
-    USB_HEADSET_MICROPHONES = 23;
-    USB_DOCK_MICROPHONES = 24;
-
-    // HDMI
-    HDMI_DEVICE = 25;
-
-    // Telephony
-    TELEPHONY_TX = 26;
-    TELEPHONY_RX = 27;
-    IN_CALL_CAPTURE_SOURCE0 = 28;
-    IN_CALL_CAPTURE_SOURCE1 = 29;
-    IN_CALL_CAPTURE_SOURCE2 = 30;
-
-    // Null sink and source
-    NULL_SOURCE = 31;
-    NULL_SINK = 32;
-
-    // Echo reference
-    ECHO_REFERENCE_DEVICE_INTERFACE = 33;
-  }
-
-  /* Audio Use Case. */
-  enum UseCase {
-    UNKNOWN_VENDOR_AUDIO_USECASE = 0;
-    // playback use cases
-    PRIMARY_PLAYBACK = 1;
-    RAW_PLAYBACK = 2;
-    DEEP_BUFFER_PLAYBACK = 3;
-    COMPRESS_OFFLOAD_PLAYBACK = 4;
-    MMAP_PLAYBACK = 5;
-    HIFI_PLAYBACK = 6;
-    VOIP_PLAYBACK = 7;
-    TELEPHONY_PLAYBACK = 8;
-    IN_CALL_PLAYBACK = 9;
-    SPATIALIZER_PLAYBACK = 10;
-    ULTRASOUND_PLAYBACK = 11;
-    HAPTIC_PLAYBACK = 12;
-    SPATIALIZER_OFFLOAD_PLAYBACK = 13;
-    // capture use cases
-    PRIMARY_CAPTURE = 14;
-    FAST_CAPTURE = 15;
-    HIFI_CAPTURE = 16;
-    MMAP_CAPTURE = 17;
-    VOIP_CAPTURE = 18;
-    VOIP_GSENET_CAPTURE = 19;
-    ULTRASOUND_CAPTURE = 20;
-    TELEPHONY_CAPTURE = 21;
-    IN_CALL_CAPTURE = 22;
-    SOUND_TRIGGER_CAPTURE = 23;
-    SOUND_TRIGGER_TAP_CAPTURE = 24;
-    HOTWORD_LOOKBACK_CAPTURE = 25;
-    ECHO_REFERENCE_CAPTURE = 26;
-
-    // voice call use case
-    VOICE_CALL_DOWNLINK = 27;
-    VOICE_CALL_UPLINK = 28;
-  }
-
-  /* Audio source with the original enum value. */
-  enum AudioSource {
-    DEFAULT = 0;
-    MIC = 1;
-    VOICE_UPLINK = 2;
-    VOICE_DOWNLINK = 3;
-    VOICE_CALL = 4;
-    CAMCORDER = 5;
-    VOICE_RECOGNITION = 6;
-    VOICE_COMMUNICATION = 7;
-    REMOTE_SUBMIX = 8;
-    UNPROCESSED = 9;
-    VOICE_PERFORMANCE = 10;
-    ECHO_REFERENCE = 1997;
-    FM_TUNER = 1998;
-    HOTWORD = 1999;
-    ULTRASOUND = 2000;
-  };
-
   enum CameraType {
     UNKNOWN_CAMERA_TYPE = 0;
     FRONT_CAMERA = 1;
@@ -2925,7 +3038,7 @@ message VendorAudioDspRecordUsageStatsReported {
   optional AudioDeviceInterface audio_device_interface = 5;
 
   /* Usecase used */
-  optional UseCase vendor_audio_use_case = 6;
+  optional AudioUseCase vendor_audio_use_case = 6;
 
   /* Camera Type */
   optional CameraType camera_type = 7;
@@ -2937,8 +3050,104 @@ message VendorAudioDspRecordUsageStatsReported {
    * changes mid-recording, new atom will be uploaded but this value will be false.
    */
   optional bool is_beginning_of_recording = 9;
+
+  /* Folding state of the phone */
+  optional AudioScreenFoldingState audio_screen_folding_state = 10;
+
+  /* Device screen is on or off */
+  optional bool is_screen_on = 11;
 };
 
+/*
+ * Logs the audio media playback usage stats.
+ * Logged from:
+ *   vendor/google/whitechapel/audio/hal/aidl/audio/metric/suez_data_adapter/statsd_suez_data_adapter.cc
+ *
+ * Estimated Logging Rate: Any time during audia media playback that screen_orientation / audio device / use case changes.
+ * It will be aggregated in a count and value metric to keep the resource usage low.
+ */
+message MediaPlaybackUsageStatsReported {
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+
+  /* Device interface used */
+  optional AudioDeviceInterface interface = 2;
+
+  /* AudioSource used */
+  optional AudioSource audio_source = 3;
+
+  /* Usecase used */
+  optional AudioUseCase audio_use_case = 4;
+
+    /* Screen orientation used. */
+  optional int32 screen_orientation = 5;
+
+  /* True if this atom represent the end of playback. If usecase/interfaces/orientation
+   * changes mid-playback, new atom will be uploaded but this value will be false.
+   */
+  optional bool is_end_of_playback = 6;
+
+    /* Duration in second */
+  optional int32 duration_second = 7;
+
+  /* Folding state of the phone */
+  optional AudioScreenFoldingState audio_screen_folding_state = 8;
+
+  /* Device screen is on or off */
+  optional bool is_screen_on = 9;
+
+  /* Volume of the playback */
+  optional float volume = 10;
+
+  /* Average power in milliwatts. -1 if unavailable. */
+  optional float average_power = 11;
+}
+
+/*
+ * Logs the call usage information stats.
+ * Logged from:
+ *   vendor/google/whitechapel/audio/hal/aidl/audio/metric/suez_data_adapter/statsd_suez_data_adapter.cc
+ *
+ * Estimated Logging Rate: Every 24 hours round to nearest 5 minutes
+ */
+message CallUsageStatsReported {
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+
+  /* Device interface used */
+  optional AudioDeviceInterface downlink_interface = 2;
+
+  /* AudioSource used */
+  optional AudioSource downlink_audio_source = 3;
+
+  /* Usecase used */
+  optional AudioUseCase downlink_audio_use_case = 4;
+
+  /* Device interface used */
+  optional AudioDeviceInterface uplink_interface = 5;
+
+  /* AudioSource used */
+  optional AudioSource uplink_audio_source = 6;
+
+  /* Usecase used */
+  optional AudioUseCase uplink_audio_use_case = 7;
+
+  /* Number of call in the past 24 hours */
+  optional int32 call_count = 8;
+
+  /* Duration in second (value is round to 5 minutes) */
+  optional int32 duration_second = 9;
+
+  /* Current volume for the downlink playback */
+  optional float volume = 10;
+
+  /* Average power in milliwatts. -1 if unavailable. */
+  optional float average_power = 11;
+
+  /* background noise level from 1 (lowest) to 12 (highest). */
+  optional float noise_level = 12;
+}
+
 /*
  * A message containing USB audio connection error event.
  * Logged from:
@@ -2991,3 +3200,88 @@ message VendorAudioSpeakerPowerStatsReported {
   /* Duration in second that speaker is using the average power. i-th value represent i-th speaker. There are at most 4 speakers. */
   repeated int32 duration_second = 3;
 }
+
+/*
+ * A message containing how many sectors read from
+ * the dm verity protected partitions
+ */
+message DmVerityPartitionReadAmountReported {
+  enum DmPartition {
+    SYSTEM = 0;
+    SYSTEM_EXT = 1;
+    PRODUCT = 2;
+    VENDOR = 3;
+    ODM = 4;
+    UNKNOWN = 5;
+  }
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+  /* Identifies the dm-verity protected partition accessed. */
+  optional DmPartition dm_partition = 2;
+  /* Number of sectors read from the dm-verity protected partition. */
+  optional int64 read_sectors = 3;
+}
+
+/*
+ * Event showing the state of the sensor when a Water Intrusion Event occurs
+ */
+message WaterEventReported {
+  enum FuseState {
+    FUSE_STATE_UNKNOWN = 0;
+    INTACT = 1; /* fuse has not blown */
+    BLOWN = 2;   /* fuse has blown */
+  }
+  enum EventPoint {
+    EVENT_POINT_UNKNOWN = 0;
+    BOOT = 1;
+    IRQ = 2;
+  }
+  enum SensorState {
+    SENSOR_STATE_UNKNOWN = 0;
+    WET = 1;
+    DRY = 2;
+    INVALID = 3;
+    DISABLED = 4;
+  }
+
+  enum CircuitState {
+    CIRCUIT_ENABLED_UNKNOWN = 0;
+    CIRCUIT_ENABLED = 1;
+    CIRCUIT_DISABLED = 2;
+  }
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+  /*
+   * Event details
+   */
+  /* The lifecycle point at which event was collected */
+  optional EventPoint collection_event = 13;
+
+  /* state of the intrusion detection fuse */
+  optional FuseState fuse_state = 2;
+  /* Was the fuse enabled */
+  optional CircuitState fuse_enabled = 3;
+
+  /* The state of the reference sensor. */
+  optional SensorState reference_state = 4;
+  /* The threshold of the reference in mV. */
+  optional int32 reference_threshold = 8;
+
+  /* The state of sensor 0. */
+  optional SensorState sensor0_state = 5;
+  /* The threshold of sensor 0 in mV. */
+  repeated int32 sensor0_threshold = 9;
+
+  /* The state of sensor 1. */
+  optional SensorState sensor1_state = 6;
+  /* The threshold of sensor1 in mv. */
+  repeated int32 sensor1_threshold = 10;
+
+   /* The state of sensor 2. */
+  optional SensorState sensor2_state = 7;
+  /* The threshold of the sensor 2 in mv. */
+  repeated int32 sensor2_threshold = 11;
+
+  /* Was system fault enabled */
+  optional CircuitState fault_enabled = 12;
+}
diff --git a/power-libperfmgr/Android.bp b/power-libperfmgr/Android.bp
index ff9a707c..c29d9d60 100644
--- a/power-libperfmgr/Android.bp
+++ b/power-libperfmgr/Android.bp
@@ -59,12 +59,17 @@ cc_test {
         "aidl/tests/SessionTaskMapTest.cpp",
         "aidl/tests/TestHelper.cpp",
         "aidl/tests/UClampVoterTest.cpp",
+        "aidl/tests/ChannelGroupTest.cpp",
+        "aidl/tests/ChannelManagerTest.cpp",
         "aidl/BackgroundWorker.cpp",
+        "aidl/ChannelGroup.cpp",
+        "aidl/ChannelManager.cpp",
         "aidl/GpuCalculationHelpers.cpp",
         "aidl/GpuCapacityNode.cpp",
         "aidl/PowerHintSession.cpp",
         "aidl/PowerSessionManager.cpp",
         "aidl/SessionRecords.cpp",
+        "aidl/SessionChannel.cpp",
         "aidl/SessionTaskMap.cpp",
         "aidl/SessionValueEntry.cpp",
         "aidl/UClampVoter.cpp",
@@ -88,7 +93,10 @@ cc_test {
         "pixel-power-ext-V1-ndk",
         "libfmq",
     ],
-    test_suites: ["device-tests"],
+    test_suites: [
+        "device-tests",
+        "device-pixel-tests",
+    ],
 }
 
 cc_binary {
@@ -120,6 +128,8 @@ cc_binary {
     ],
     srcs: [
         "aidl/BackgroundWorker.cpp",
+        "aidl/ChannelGroup.cpp",
+        "aidl/ChannelManager.cpp",
         "aidl/GpuCalculationHelpers.cpp",
         "aidl/GpuCapacityNode.cpp",
         "aidl/service.cpp",
@@ -127,8 +137,10 @@ cc_binary {
         "aidl/PowerExt.cpp",
         "aidl/PowerHintSession.cpp",
         "aidl/PowerSessionManager.cpp",
+        "aidl/SupportManager.cpp",
         "aidl/UClampVoter.cpp",
         "aidl/SessionRecords.cpp",
+        "aidl/SessionChannel.cpp",
         "aidl/SessionTaskMap.cpp",
         "aidl/SessionValueEntry.cpp",
     ],
diff --git a/power-libperfmgr/TEST_MAPPING b/power-libperfmgr/TEST_MAPPING
new file mode 100644
index 00000000..56b8cf8c
--- /dev/null
+++ b/power-libperfmgr/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "postsubmit": [
+    {
+      "name": "libadpf_test"
+    }
+  ]
+}
\ No newline at end of file
diff --git a/power-libperfmgr/aidl/AdpfTypes.h b/power-libperfmgr/aidl/AdpfTypes.h
index 4db48948..2a5bf424 100644
--- a/power-libperfmgr/aidl/AdpfTypes.h
+++ b/power-libperfmgr/aidl/AdpfTypes.h
@@ -24,6 +24,7 @@
 #include <aidl/android/hardware/power/Mode.h>
 #include <aidl/android/hardware/power/SessionConfig.h>
 #include <aidl/android/hardware/power/SessionTag.h>
+#include <aidl/android/hardware/power/SupportInfo.h>
 #include <aidl/android/hardware/power/WorkDuration.h>
 #include <android-base/thread_annotations.h>
 #include <fmq/AidlMessageQueue.h>
@@ -35,6 +36,26 @@ namespace aidl::google::hardware::power::impl::pixel {
 
 using namespace android::hardware::power;
 
+template <class T>
+constexpr size_t enum_size() {
+    return static_cast<size_t>(*(ndk::enum_range<T>().end() - 1)) + 1;
+}
+
+template <class E>
+bool supportFromBitset(int64_t &supportInt, E type) {
+    return (supportInt >> static_cast<int>(type)) % 2;
+}
+
+using ::android::AidlMessageQueue;
+using ::android::hardware::EventFlag;
+using android::hardware::common::fmq::MQDescriptor;
+using android::hardware::common::fmq::SynchronizedReadWrite;
+
+using ChannelQueueDesc = MQDescriptor<ChannelMessage, SynchronizedReadWrite>;
+using ChannelQueue = AidlMessageQueue<ChannelMessage, SynchronizedReadWrite>;
+using FlagQueueDesc = MQDescriptor<int8_t, SynchronizedReadWrite>;
+using FlagQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;
+
 using ::android::AidlMessageQueue;
 using ::android::hardware::EventFlag;
 using android::hardware::common::fmq::MQDescriptor;
@@ -103,6 +124,23 @@ constexpr const char *AdpfVoteTypeToStr(AdpfVoteType voteType) {
     }
 }
 
+enum class ProcessTag : int32_t {
+    DEFAULT = 0,
+    // System UI related processes, e.g. sysui, nexuslauncher.
+    SYSTEM_UI
+};
+
+constexpr const char *toString(ProcessTag procTag) {
+    switch (procTag) {
+        case ProcessTag::DEFAULT:
+            return "DEFAULT";
+        case ProcessTag::SYSTEM_UI:
+            return "SYSTEM_UI";
+        default:
+            return "INVALID_PROC_TAG";
+    }
+}
+
 class Immobile {
   public:
     Immobile() {}
@@ -112,7 +150,28 @@ class Immobile {
     Immobile &operator=(Immobile &) = delete;
 };
 
-constexpr int kUclampMin{0};
-constexpr int kUclampMax{1024};
+constexpr int kUclampMin = 0;
+constexpr int kUclampMax = 1024;
+
+// For this FMQ, the first 2 bytes are write bytes, and the last 2 are
+// read bytes. There are 32 bits total per flag, and this is split between read
+// and write, allowing for 16 channels total. The first read bit corresponds to
+// the same buffer as the first write bit, so bit 0 (write) and bit 16 (read)
+// correspond to the same buffer, bit 1 (write) and bit 17 (read) are the same buffer,
+// all the way to bit 15 (write) and bit 31 (read). These read/write masks allow for
+// selectively picking only the read or write bits in a flag integer.
+
+constexpr uint32_t kWriteBits = 0x0000ffff;
+constexpr uint32_t kReadBits = 0xffff0000;
+
+// ADPF FMQ configuration is dictated by the vendor, and the size of the queue is decided
+// by the HAL and passed to the framework. 32 is a reasonable upper bound, as it can handle
+// even 2 different sessions reporting all of their cached durations at the same time into one
+// buffer. If the buffer ever runs out of space, the client will just use a binder instead,
+// so there is not a real risk of data loss.
+constexpr size_t kFMQQueueSize = 32;
+
+// The maximum number of channels that can be assigned to a ChannelGroup
+constexpr size_t kMaxChannels = 16;
 
 }  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/AppDescriptorTrace.h b/power-libperfmgr/aidl/AppDescriptorTrace.h
index d9af140b..96b7060a 100644
--- a/power-libperfmgr/aidl/AppDescriptorTrace.h
+++ b/power-libperfmgr/aidl/AppDescriptorTrace.h
@@ -30,11 +30,6 @@ namespace power {
 namespace impl {
 namespace pixel {
 
-template <class T>
-constexpr size_t enum_size() {
-    return static_cast<size_t>(*(ndk::enum_range<T>().end() - 1)) + 1;
-}
-
 // The App Hint Descriptor struct manages information necessary
 // to calculate the next uclamp min value from the PID function
 // and is separate so that it can be used as a pointer for
@@ -85,6 +80,8 @@ struct AppDescriptorTrace {
         trace_cpu_duration = StringPrintf("adpf.%s-%s", idString.c_str(), "cpu_duration");
         trace_gpu_duration = StringPrintf("adpf.%s-%s", idString.c_str(), "gpu_duration");
         trace_gpu_capacity = StringPrintf("adpf.%s-%s", idString.c_str(), "gpu_capacity");
+        trace_game_mode_fps = "adpf.sf.gameModeFPS";
+        trace_game_mode_fps_jitters = "adpf.sf.gameModeFPSJitters";
     }
 
     // Trace values
@@ -119,6 +116,8 @@ struct AppDescriptorTrace {
     std::string trace_cpu_duration;
     std::string trace_gpu_duration;
     std::string trace_gpu_capacity;
+    std::string trace_game_mode_fps;
+    std::string trace_game_mode_fps_jitters;
 };
 
 }  // namespace pixel
diff --git a/power-libperfmgr/aidl/ChannelGroup.cpp b/power-libperfmgr/aidl/ChannelGroup.cpp
new file mode 100644
index 00000000..e033ea3f
--- /dev/null
+++ b/power-libperfmgr/aidl/ChannelGroup.cpp
@@ -0,0 +1,218 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#define ATRACE_TAG (ATRACE_TAG_POWER | ATRACE_TAG_HAL)
+
+#include "ChannelGroup.h"
+
+#include <gmock/gmock.h>
+#include <processgroup/processgroup.h>
+#include <sys/resource.h>
+#include <utils/SystemClock.h>
+#include <utils/Trace.h>
+
+#include <algorithm>
+#include <mutex>
+
+#include "AdpfTypes.h"
+#include "ChannelManager.h"
+#include "log/log_main.h"
+#include "tests/mocks/MockPowerHintSession.h"
+#include "tests/mocks/MockPowerSessionManager.h"
+
+namespace aidl::google::hardware::power::impl::pixel {
+using Tag = ChannelMessage::ChannelMessageContents::Tag;
+
+template <class PowerSessionManagerT, class PowerHintSessionT>
+ChannelGroup<PowerSessionManagerT, PowerHintSessionT>::ChannelGroup(int32_t id)
+    : mGroupId(id),
+      mFlagQueue(std::make_shared<FlagQueue>(1, true)),
+      mGroupThread(std::thread(&ChannelGroup::runChannelGroup, this)) {}
+
+template <class PowerSessionManagerT, class PowerHintSessionT>
+ChannelGroup<PowerSessionManagerT, PowerHintSessionT>::~ChannelGroup() {
+    mDestructing = true;
+
+    EventFlag *flag;
+    EventFlag::createEventFlag(mFlagQueue->getEventFlagWord(), &flag);
+    // Wake up the handler. 0xffffffff wakes on every bit in the flag,
+    // to ensure the wake-up will be handled regardless of other configuration settings,
+    // and even if some of these bits are already set.
+    flag->wake(0xffffffff);
+
+    mGroupThread.join();
+}
+
+template <class PowerSessionManagerT, class PowerHintSessionT>
+int32_t ChannelGroup<PowerSessionManagerT, PowerHintSessionT>::getChannelCount() const {
+    return mLiveChannels;
+}
+
+template <class PowerSessionManagerT, class PowerHintSessionT>
+bool ChannelGroup<PowerSessionManagerT, PowerHintSessionT>::removeChannel(int32_t slot) {
+    std::scoped_lock lock(mGroupMutex);
+    if (!mChannels[slot]) {
+        return false;
+    }
+    mChannels[slot] = nullptr;
+    --mLiveChannels;
+    return true;
+}
+
+template <class PowerSessionManagerT, class PowerHintSessionT>
+std::shared_ptr<SessionChannel>
+ChannelGroup<PowerSessionManagerT, PowerHintSessionT>::createChannel(int32_t tgid, int32_t uid) {
+    std::scoped_lock lock(mGroupMutex);
+    ALOGV("Creating channel for tgid: %" PRId32 " uid: %" PRId32, tgid, uid);
+    int slot = 0;
+    for (slot = 0; slot < kMaxChannels; ++slot) {
+        if (!mChannels[slot]) {
+            break;
+        }
+    }
+    LOG_ALWAYS_FATAL_IF(slot == kMaxChannels, "Failed to create channel!");
+    ++mLiveChannels;
+    ChannelManager<SessionChannel>::ChannelMapValue channelId{
+            {.groupId = static_cast<int32_t>(mGroupId), .offset = slot}};
+    mChannels[slot] = std::make_shared<SessionChannel>(tgid, uid, channelId, slot);
+    ALOGV("Channel created on group: %" PRId32 " slot: %" PRId32, mGroupId, slot);
+    return mChannels[slot];
+}
+
+template <class PowerSessionManagerT, class PowerHintSessionT>
+std::shared_ptr<SessionChannel> ChannelGroup<PowerSessionManagerT, PowerHintSessionT>::getChannel(
+        int32_t slot) {
+    std::scoped_lock lock(mGroupMutex);
+    LOG_ALWAYS_FATAL_IF(!mChannels[slot], "Requesting a dead channel!");
+    return mChannels[slot];
+}
+
+template <class PowerSessionManagerT, class PowerHintSessionT>
+void ChannelGroup<PowerSessionManagerT, PowerHintSessionT>::getFlagDesc(
+        std::optional<FlagQueueDesc> *_return_desc) const {
+    *_return_desc = std::make_optional(mFlagQueue->dupeDesc());
+}
+
+template <class PowerSessionManagerT, class PowerHintSessionT>
+void ChannelGroup<PowerSessionManagerT, PowerHintSessionT>::runChannelGroup() {
+    EventFlag *flag;
+    {
+        std::scoped_lock lock(mGroupMutex);
+        EventFlag::createEventFlag(mFlagQueue->getEventFlagWord(), &flag);
+    }
+
+    setpriority(PRIO_PROCESS, getpid(), -20);
+
+    uint32_t flagState = 0;
+    static std::set<uid_t> blocklist = {};
+    std::vector<ChannelMessage> messages;
+    std::vector<android::hardware::power::WorkDuration> durations;
+    durations.reserve(kFMQQueueSize);
+    messages.reserve(kFMQQueueSize);
+
+    while (!mDestructing) {
+        messages.clear();
+        flag->wait(kWriteBits, &flagState, 0, true);
+        int64_t now = ::android::uptimeNanos();
+        if (mDestructing) {
+            return;
+        }
+        {
+            std::scoped_lock lock(mGroupMutex);
+            // Get the rightmost nonzero bit, corresponding to the next active channel
+            for (int channelNum = std::countr_zero(flagState);
+                 channelNum < kMaxChannels && !mDestructing;
+                 channelNum = std::countr_zero(flagState)) {
+                // Drop the lowest set write bit
+                flagState &= (flagState - 1);
+                auto &channel = mChannels[channelNum];
+                if (!channel || !channel->isValid()) {
+                    continue;
+                }
+                if (blocklist.contains(channel->getUid())) {
+                    continue;
+                }
+                int toRead = channel->getQueue()->availableToRead();
+                if (toRead <= 0) {
+                    continue;
+                }
+                messages.resize(toRead);
+                if (!channel->getQueue()->read(messages.data(), toRead)) {
+                    // stop messing with your buffer >:(
+                    blocklist.insert(channel->getUid());
+                    continue;
+                }
+                flag->wake(mChannels[channelNum]->getReadBitmask());
+                for (int messageIndex = 0; messageIndex < messages.size() && !mDestructing;
+                     ++messageIndex) {
+                    ChannelMessage &message = messages[messageIndex];
+                    auto sessionPtr = std::static_pointer_cast<PowerHintSessionT>(
+                            PowerSessionManagerT::getInstance()->getSession(message.sessionID));
+                    if (!sessionPtr) {
+                        continue;
+                    }
+                    switch (message.data.getTag()) {
+                        case Tag::hint: {
+                            sessionPtr->sendHint(message.data.get<Tag::hint>());
+                            break;
+                        }
+                        case Tag::targetDuration: {
+                            sessionPtr->updateTargetWorkDuration(
+                                    message.data.get<Tag::targetDuration>());
+                            break;
+                        }
+                        case Tag::workDuration: {
+                            durations.clear();
+                            for (; !mDestructing && messageIndex < messages.size() &&
+                                   messages[messageIndex].data.getTag() == Tag::workDuration &&
+                                   messages[messageIndex].sessionID == message.sessionID;
+                                 ++messageIndex) {
+                                ChannelMessage &currentMessage = messages[messageIndex];
+                                auto &durationData = currentMessage.data.get<Tag::workDuration>();
+                                durations.emplace_back(WorkDuration{
+                                        .timeStampNanos = currentMessage.timeStampNanos,
+                                        .durationNanos = durationData.durationNanos,
+                                        .cpuDurationNanos = durationData.cpuDurationNanos,
+                                        .gpuDurationNanos = durationData.gpuDurationNanos,
+                                        .workPeriodStartTimestampNanos =
+                                                durationData.workPeriodStartTimestampNanos});
+                            }
+                            sessionPtr->reportActualWorkDuration(durations);
+                            break;
+                        }
+                        case Tag::mode: {
+                            auto mode = message.data.get<Tag::mode>();
+                            sessionPtr->setMode(mode.modeInt, mode.enabled);
+                            break;
+                        }
+                        default: {
+                            ALOGE("Invalid data tag sent: %s",
+                                  std::to_string(static_cast<int>(message.data.getTag())).c_str());
+                            break;
+                        }
+                    }
+                }
+            }
+        }
+    }
+}
+
+template class ChannelGroup<>;
+template class ChannelGroup<testing::NiceMock<mock::pixel::MockPowerSessionManager>,
+                            testing::NiceMock<mock::pixel::MockPowerHintSession>>;
+
+}  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/ChannelGroup.h b/power-libperfmgr/aidl/ChannelGroup.h
new file mode 100644
index 00000000..598b1172
--- /dev/null
+++ b/power-libperfmgr/aidl/ChannelGroup.h
@@ -0,0 +1,73 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+// Keeps track of groups of channels that all use the same EventFlag
+
+#pragma once
+
+#include <android-base/thread_annotations.h>
+
+#include <array>
+#include <mutex>
+#include <optional>
+#include <thread>
+
+#include "AdpfTypes.h"
+#include "PowerHintSession.h"
+#include "PowerSessionManager.h"
+#include "SessionChannel.h"
+
+namespace aidl::google::hardware::power::impl::pixel {
+// This manages a group of FMQ channels that are watched by a single thread. This class manages the
+// channels, the thread that waits on their callbacks, and the mutex for that thread.
+//
+// We have the channels guarded by a lock in this class and the channel count guarded by
+// the manager, because adding/removing is only done by the manager while locked.
+// Thus, only the manager lock is required to count the group size when figuring out where
+// to insert a new channel.
+template <class PowerSessionManagerT = PowerSessionManager<>,
+          class PowerHintSessionT = PowerHintSession<>>
+class ChannelGroup : public Immobile {
+  public:
+    ~ChannelGroup();
+    ChannelGroup(int32_t id);
+    bool removeChannel(int32_t slot) EXCLUDES(mGroupMutex);
+    int32_t getChannelCount() const;
+    // Returns the channel ID
+    std::shared_ptr<SessionChannel> createChannel(int32_t tgid, int32_t uid) EXCLUDES(mGroupMutex);
+    std::shared_ptr<SessionChannel> getChannel(int32_t slot) EXCLUDES(mGroupMutex);
+    void getFlagDesc(std::optional<FlagQueueDesc> *_return_desc) const;
+
+  private:
+    void runChannelGroup() EXCLUDES(mGroupMutex);
+
+    // Guard the number of channels with the global lock, so we only need one
+    // lock in order to figure out where to insert new sessions, instead of getting
+    // a lock for each channelgroup.
+    int32_t mLiveChannels = 0;
+    const int32_t mGroupId;
+
+    // Tracks whether the group is currently being destructed, used to kill the helper thread
+    bool mDestructing = false;
+    // Used to guard items internal to the FMQ thread
+    std::mutex mGroupMutex;
+    std::array<std::shared_ptr<SessionChannel>, kMaxChannels> mChannels GUARDED_BY(mGroupMutex){};
+    const std::shared_ptr<FlagQueue> mFlagQueue;
+
+    std::thread mGroupThread;
+};
+
+}  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/ChannelManager.cpp b/power-libperfmgr/aidl/ChannelManager.cpp
new file mode 100644
index 00000000..4851c984
--- /dev/null
+++ b/power-libperfmgr/aidl/ChannelManager.cpp
@@ -0,0 +1,129 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#define ATRACE_TAG (ATRACE_TAG_POWER | ATRACE_TAG_HAL)
+
+#include "ChannelManager.h"
+
+#include <inttypes.h>
+
+#include "tests/mocks/MockChannelGroup.h"
+#include "tests/mocks/MockPowerHintSession.h"
+#include "tests/mocks/MockPowerSessionManager.h"
+
+namespace aidl::google::hardware::power::impl::pixel {
+
+template <class ChannelGroupT>
+bool ChannelManager<ChannelGroupT>::closeChannel(int32_t tgid, int32_t uid) {
+    std::scoped_lock lock{mChannelManagerMutex};
+    ChannelMapKey key{.tgid = tgid, .uid = uid};
+    auto channelIter = mChannelMap.find(key);
+    if (channelIter == mChannelMap.end()) {
+        return false;
+    }
+    ChannelMapValue value{.value = channelIter->second};
+    auto groupIter = mChannelGroups.find(value.groupId);
+    if (groupIter == mChannelGroups.end()) {
+        return false;
+    }
+
+    if (!groupIter->second.removeChannel(value.offset)) {
+        return false;
+    }
+
+    // Ensure the group is cleaned up if we remove the last channel
+    if (groupIter->second.getChannelCount() == 0) {
+        mChannelGroups.erase(groupIter);
+    }
+    mChannelMap.erase(channelIter);
+    return true;
+}
+
+template <class ChannelGroupT>
+std::shared_ptr<SessionChannel> ChannelManager<ChannelGroupT>::getOrCreateChannel(int32_t tgid,
+                                                                                  int32_t uid) {
+    ChannelMapKey key{.tgid = tgid, .uid = uid};
+    auto channelIter = mChannelMap.find(key);
+    if (channelIter != mChannelMap.end()) {
+        ChannelMapValue value{.value = channelIter->second};
+        return mChannelGroups.at(value.groupId).getChannel(value.offset);
+    }
+    // If channel does not exist, we need to create it
+    int32_t groupId = -1;
+    for (auto &&group : mChannelGroups) {
+        if (group.second.getChannelCount() < kMaxChannels) {
+            groupId = group.first;
+            break;
+        }
+    }
+    // No group was found, we need to make a new one
+    if (groupId == -1) {
+        groupId = mChannelGroups.empty() ? 0 : mChannelGroups.rbegin()->first + 1;
+        mChannelGroups.emplace(std::piecewise_construct, std::forward_as_tuple(groupId),
+                               std::forward_as_tuple(groupId));
+    }
+
+    std::shared_ptr<SessionChannel> channel = mChannelGroups.at(groupId).createChannel(tgid, uid);
+    mChannelMap[key] = channel->getId();
+
+    return channel;
+}
+
+template <class ChannelGroupT>
+bool ChannelManager<ChannelGroupT>::getChannelConfig(int32_t tgid, int32_t uid,
+                                                     ChannelConfig *config) {
+    std::scoped_lock lock{mChannelManagerMutex};
+    std::shared_ptr<SessionChannel> channel = getOrCreateChannel(tgid, uid);
+    if (!channel || !channel->isValid()) {
+        return false;
+    }
+    mChannelGroups.at(ChannelMapValue{.value = channel->getId()}.groupId)
+            .getFlagDesc(&config->eventFlagDescriptor);
+    channel->getDesc(&config->channelDescriptor);
+    config->readFlagBitmask = channel->getReadBitmask();
+    config->writeFlagBitmask = channel->getWriteBitmask();
+    return true;
+}
+
+template <class ChannelGroupT>
+int ChannelManager<ChannelGroupT>::getGroupCount() {
+    std::scoped_lock lock{mChannelManagerMutex};
+    return mChannelGroups.size();
+}
+
+template <class ChannelGroupT>
+int ChannelManager<ChannelGroupT>::getChannelCount() {
+    std::scoped_lock lock{mChannelManagerMutex};
+    int out = 0;
+    for (auto &&group : mChannelGroups) {
+        out += group.second.getChannelCount();
+    }
+    return out;
+}
+
+template <class ChannelGroupT>
+ChannelManager<ChannelGroupT> *ChannelManager<ChannelGroupT>::getInstance() {
+    static ChannelManager instance{};
+    return &instance;
+}
+
+template class ChannelManager<>;
+template class ChannelManager<testing::NiceMock<mock::pixel::MockChannelGroup>>;
+template class ChannelManager<ChannelGroup<testing::NiceMock<mock::pixel::MockPowerSessionManager>,
+                                           testing::NiceMock<mock::pixel::MockPowerHintSession>>>;
+
+}  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/ChannelManager.h b/power-libperfmgr/aidl/ChannelManager.h
new file mode 100644
index 00000000..7656d10d
--- /dev/null
+++ b/power-libperfmgr/aidl/ChannelManager.h
@@ -0,0 +1,69 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include <map>
+#include <unordered_map>
+
+#include "AdpfTypes.h"
+#include "ChannelGroup.h"
+#include "SessionChannel.h"
+
+namespace aidl::google::hardware::power::impl::pixel {
+
+template <class ChannelGroupT = ChannelGroup<>>
+class ChannelManager : public Immobile {
+  public:
+    ~ChannelManager() = default;
+    bool closeChannel(int32_t tgid, int32_t uid);
+    bool getChannelConfig(int32_t tgid, int32_t uid, ChannelConfig *config);
+    int getGroupCount();
+    int getChannelCount();
+    // The instance of this class is actually owned by the PowerSessionManager singleton
+    // This is mostly to reduce the number of singletons and make it simpler to mock
+    static ChannelManager *getInstance();
+
+    union ChannelMapKey {
+        struct {
+            int32_t tgid;
+            int32_t uid;
+        };
+        int64_t key;
+        operator int64_t() { return key; }
+    };
+
+    union ChannelMapValue {
+        struct {
+            int32_t groupId;
+            int32_t offset;
+        };
+        int64_t value;
+        operator int64_t() { return value; }
+    };
+
+  private:
+    std::mutex mChannelManagerMutex;
+
+    std::map<int32_t, ChannelGroupT> mChannelGroups GUARDED_BY(mChannelManagerMutex);
+    std::shared_ptr<SessionChannel> getOrCreateChannel(int32_t tgid, int32_t uid)
+            REQUIRES(mChannelManagerMutex);
+
+    // Used to look up where channels actually are in this data structure, and guarantee uniqueness
+    std::unordered_map<int64_t, int64_t> mChannelMap GUARDED_BY(mChannelManagerMutex);
+};
+
+}  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/Power.cpp b/power-libperfmgr/aidl/Power.cpp
index 6ede0fb2..50ec5439 100644
--- a/power-libperfmgr/aidl/Power.cpp
+++ b/power-libperfmgr/aidl/Power.cpp
@@ -21,19 +21,21 @@
 #include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/properties.h>
-#include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <fmq/AidlMessageQueue.h>
 #include <fmq/EventFlag.h>
 #include <perfmgr/HintManager.h>
 #include <utils/Log.h>
 
-#include <mutex>
+#include <cstdint>
+#include <memory>
 #include <optional>
 
 #include "AdpfTypes.h"
+#include "ChannelManager.h"
 #include "PowerHintSession.h"
 #include "PowerSessionManager.h"
+#include "SupportManager.h"
 #include "disp-power/DisplayLowPower.h"
 
 namespace aidl {
@@ -88,6 +90,8 @@ Power::Power(std::shared_ptr<DisplayLowPower> dlpw)
 
     auto status = this->getInterfaceVersion(&mServiceVersion);
     LOG(INFO) << "PowerHAL InterfaceVersion:" << mServiceVersion << " isOK: " << status.isOk();
+
+    mSupportInfo = SupportManager::makeSupportInfo();
 }
 
 ndk::ScopedAStatus Power::setMode(Mode type, bool enabled) {
@@ -140,15 +144,6 @@ ndk::ScopedAStatus Power::setMode(Mode type, bool enabled) {
                 mVRModeOn = false;
             }
             break;
-        case Mode::AUTOMOTIVE_PROJECTION:
-            mDisplayLowPower->SetAAMode(enabled);
-            if (enabled) {
-                HintManager::GetInstance()->DoHint("AUTOMOTIVE_PROJECTION");
-            } else {
-                HintManager::GetInstance()->EndHint("AUTOMOTIVE_PROJECTION");
-                HintManager::GetInstance()->EndHint("DISPLAY_IDLE_AA");
-            }
-            break;
         case Mode::LAUNCH:
             if (mVRModeOn || mSustainedPerfModeOn) {
                 break;
@@ -191,36 +186,8 @@ ndk::ScopedAStatus Power::setMode(Mode type, bool enabled) {
 }
 
 ndk::ScopedAStatus Power::isModeSupported(Mode type, bool *_aidl_return) {
-    switch (mServiceVersion) {
-        case 5:
-            if (static_cast<int32_t>(type) <= static_cast<int32_t>(Mode::AUTOMOTIVE_PROJECTION))
-                break;
-            [[fallthrough]];
-        case 4:
-            [[fallthrough]];
-        case 3:
-            if (static_cast<int32_t>(type) <= static_cast<int32_t>(Mode::GAME_LOADING))
-                break;
-            [[fallthrough]];
-        case 2:
-            [[fallthrough]];
-        case 1:
-            if (static_cast<int32_t>(type) <= static_cast<int32_t>(Mode::CAMERA_STREAMING_HIGH))
-                break;
-            [[fallthrough]];
-        default:
-            *_aidl_return = false;
-            return ndk::ScopedAStatus::ok();
-    }
-    bool supported = HintManager::GetInstance()->IsHintSupported(toString(type));
-    // LOW_POWER handled insides PowerHAL specifically
-    if (type == Mode::LOW_POWER) {
-        supported = true;
-    }
-    if (!supported && HintManager::GetInstance()->IsAdpfProfileSupported(toString(type))) {
-        supported = true;
-    }
-    LOG(INFO) << "Power mode " << toString(type) << " isModeSupported: " << supported;
+    bool supported = supportFromBitset(mSupportInfo.modes, type);
+    LOG(INFO) << "Power Mode " << toString(type) << " isModeSupported: " << supported;
     *_aidl_return = supported;
     return ndk::ScopedAStatus::ok();
 }
@@ -263,28 +230,8 @@ ndk::ScopedAStatus Power::setBoost(Boost type, int32_t durationMs) {
 }
 
 ndk::ScopedAStatus Power::isBoostSupported(Boost type, bool *_aidl_return) {
-    switch (mServiceVersion) {
-        case 5:
-            [[fallthrough]];
-        case 4:
-            [[fallthrough]];
-        case 3:
-            [[fallthrough]];
-        case 2:
-            [[fallthrough]];
-        case 1:
-            if (static_cast<int32_t>(type) <= static_cast<int32_t>(Boost::CAMERA_SHOT))
-                break;
-            [[fallthrough]];
-        default:
-            *_aidl_return = false;
-            return ndk::ScopedAStatus::ok();
-    }
-    bool supported = HintManager::GetInstance()->IsHintSupported(toString(type));
-    if (!supported && HintManager::GetInstance()->IsAdpfProfileSupported(toString(type))) {
-        supported = true;
-    }
-    LOG(INFO) << "Power boost " << toString(type) << " isBoostSupported: " << supported;
+    bool supported = supportFromBitset(mSupportInfo.boosts, type);
+    LOG(INFO) << "Power oost " << toString(type) << " isBoostSupported: " << supported;
     *_aidl_return = supported;
     return ndk::ScopedAStatus::ok();
 }
@@ -310,6 +257,14 @@ binder_status_t Power::dump(int fd, const char **, uint32_t) {
     return STATUS_OK;
 }
 
+ndk::ScopedAStatus Power::getCpuHeadroom(const CpuHeadroomParams &_, CpuHeadroomResult *) {
+    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
+}
+
+ndk::ScopedAStatus Power::getGpuHeadroom(const GpuHeadroomParams &_, GpuHeadroomResult *) {
+    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
+}
+
 ndk::ScopedAStatus Power::createHintSession(int32_t tgid, int32_t uid,
                                             const std::vector<int32_t> &threadIds,
                                             int64_t durationNanos,
@@ -352,23 +307,32 @@ ndk::ScopedAStatus Power::createHintSessionWithConfig(
     return ndk::ScopedAStatus::ok();
 }
 
-ndk::ScopedAStatus Power::getSessionChannel(int32_t, int32_t, ChannelConfig *_aidl_return) {
-    static AidlMessageQueue<ChannelMessage, SynchronizedReadWrite> stubQueue{20, true};
-    static std::thread stubThread([&] {
-        ChannelMessage data;
-        // This loop will only run while there is data waiting
-        // to be processed, and blocks on a futex all other times
-        while (stubQueue.readBlocking(&data, 1, 0)) {
-        }
-    });
-    _aidl_return->channelDescriptor = stubQueue.dupeDesc();
-    _aidl_return->readFlagBitmask = 0x01;
-    _aidl_return->writeFlagBitmask = 0x02;
-    _aidl_return->eventFlagDescriptor = std::nullopt;
+ndk::ScopedAStatus Power::getSessionChannel(int32_t tgid, int32_t uid,
+                                            ChannelConfig *_aidl_return) {
+    if (ChannelManager<>::getInstance()->getChannelConfig(tgid, uid, _aidl_return)) {
+        return ndk::ScopedAStatus::ok();
+    }
+    return ndk::ScopedAStatus::fromStatus(EX_ILLEGAL_STATE);
+}
+
+ndk::ScopedAStatus Power::closeSessionChannel(int32_t tgid, int32_t uid) {
+    ChannelManager<>::getInstance()->closeChannel(tgid, uid);
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus Power::getSupportInfo(SupportInfo *_aidl_return) {
+    // Copy the support object into the binder
+    *_aidl_return = mSupportInfo;
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus Power::sendCompositionData(const std::vector<CompositionData> &) {
+    LOG(INFO) << "Composition data received!";
     return ndk::ScopedAStatus::ok();
 }
 
-ndk::ScopedAStatus Power::closeSessionChannel(int32_t, int32_t) {
+ndk::ScopedAStatus Power::sendCompositionUpdate(const CompositionUpdate &) {
+    LOG(INFO) << "Composition update received!";
     return ndk::ScopedAStatus::ok();
 }
 
diff --git a/power-libperfmgr/aidl/Power.h b/power-libperfmgr/aidl/Power.h
index 05bff652..80a857ff 100644
--- a/power-libperfmgr/aidl/Power.h
+++ b/power-libperfmgr/aidl/Power.h
@@ -40,6 +40,10 @@ class Power : public ::aidl::android::hardware::power::BnPower {
     ndk::ScopedAStatus isModeSupported(Mode type, bool *_aidl_return) override;
     ndk::ScopedAStatus setBoost(Boost type, int32_t durationMs) override;
     ndk::ScopedAStatus isBoostSupported(Boost type, bool *_aidl_return) override;
+    ndk::ScopedAStatus getCpuHeadroom(const CpuHeadroomParams &in_params,
+                                      CpuHeadroomResult *_aidl_return) override;
+    ndk::ScopedAStatus getGpuHeadroom(const GpuHeadroomParams &in_params,
+                                      GpuHeadroomResult *_aidl_return) override;
     ndk::ScopedAStatus createHintSession(int32_t tgid, int32_t uid,
                                          const std::vector<int32_t> &threadIds,
                                          int64_t durationNanos,
@@ -52,14 +56,19 @@ class Power : public ::aidl::android::hardware::power::BnPower {
     ndk::ScopedAStatus getSessionChannel(int32_t tgid, int32_t uid,
                                          ChannelConfig *_aidl_return) override;
     ndk::ScopedAStatus closeSessionChannel(int32_t tgid, int32_t uid) override;
+    ndk::ScopedAStatus getSupportInfo(SupportInfo *_aidl_return);
     binder_status_t dump(int fd, const char **args, uint32_t numArgs) override;
+    ndk::ScopedAStatus sendCompositionData(const std::vector<CompositionData> &in_data) override;
+    ndk::ScopedAStatus sendCompositionUpdate(const CompositionUpdate &in_update) override;
 
   private:
+    void initSupportStatus();
     std::shared_ptr<DisplayLowPower> mDisplayLowPower;
     std::unique_ptr<InteractionHandler> mInteractionHandler;
     std::atomic<bool> mVRModeOn;
     std::atomic<bool> mSustainedPerfModeOn;
     int32_t mServiceVersion;
+    SupportInfo mSupportInfo;
 };
 
 }  // namespace pixel
diff --git a/power-libperfmgr/aidl/PowerExt.cpp b/power-libperfmgr/aidl/PowerExt.cpp
index fce358f6..045772f5 100644
--- a/power-libperfmgr/aidl/PowerExt.cpp
+++ b/power-libperfmgr/aidl/PowerExt.cpp
@@ -51,14 +51,6 @@ ndk::ScopedAStatus PowerExt::setMode(const std::string &mode, bool enabled) {
         PowerSessionManager<>::getInstance()->updateHintMode(mode, enabled);
     }
 
-    if (mode == "DISPLAY_IDLE" && mDisplayLowPower->IsAAModeOn()) {
-        if (enabled) {
-            HintManager::GetInstance()->DoHint("DISPLAY_IDLE_AA");
-        } else {
-            HintManager::GetInstance()->EndHint("DISPLAY_IDLE_AA");
-        }
-    }
-
     return ndk::ScopedAStatus::ok();
 }
 
diff --git a/power-libperfmgr/aidl/PowerHintSession.cpp b/power-libperfmgr/aidl/PowerHintSession.cpp
index e6f07317..ef9c7f03 100644
--- a/power-libperfmgr/aidl/PowerHintSession.cpp
+++ b/power-libperfmgr/aidl/PowerHintSession.cpp
@@ -19,6 +19,7 @@
 
 #include "PowerHintSession.h"
 
+#include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/parsedouble.h>
 #include <android-base/properties.h>
@@ -57,6 +58,10 @@ static inline int64_t ns_to_100us(int64_t ns) {
     return ns / 100000;
 }
 
+static const char systemSessionCheckPath[] = "/proc/vendor_sched/is_tgid_system_ui";
+static const bool systemSessionCheckNodeExist = access(systemSessionCheckPath, W_OK) == 0;
+static constexpr int32_t kTargetDurationChangeThreshold = 30;  // Percentage change threshold
+
 }  // namespace
 
 template <class HintManagerT, class PowerSessionManagerT>
@@ -138,19 +143,46 @@ int64_t PowerHintSession<HintManagerT, PowerSessionManagerT>::convertWorkDuratio
     return output;
 }
 
+template <class HintManagerT, class PowerSessionManagerT>
+ProcessTag PowerHintSession<HintManagerT, PowerSessionManagerT>::getProcessTag(int32_t tgid) {
+    if (!systemSessionCheckNodeExist) {
+        ALOGD("Vendor system session checking node doesn't exist");
+        return ProcessTag::DEFAULT;
+    }
+
+    int flags = O_WRONLY | O_TRUNC | O_CLOEXEC;
+    ::android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(systemSessionCheckPath, flags)));
+    if (fd == -1) {
+        ALOGW("Can't open system session checking node %s", systemSessionCheckPath);
+        return ProcessTag::DEFAULT;
+    }
+    // The file-write return status is true if the task belongs to systemUI or Launcher. Other task
+    // or invalid tgid will return a false value.
+    auto stat = ::android::base::WriteStringToFd(std::to_string(tgid), fd);
+    ALOGD("System session checking result: %d - %d", tgid, stat);
+    if (stat) {
+        return ProcessTag::SYSTEM_UI;
+    } else {
+        return ProcessTag::DEFAULT;
+    }
+}
+
 template <class HintManagerT, class PowerSessionManagerT>
 PowerHintSession<HintManagerT, PowerSessionManagerT>::PowerHintSession(
         int32_t tgid, int32_t uid, const std::vector<int32_t> &threadIds, int64_t durationNs,
         SessionTag tag)
     : mPSManager(PowerSessionManagerT::getInstance()),
       mSessionId(++sSessionIDCounter),
-      mIdString(StringPrintf("%" PRId32 "-%" PRId32 "-%" PRId64 "-%s", tgid, uid, mSessionId,
-                             toString(tag).c_str())),
+      mSessTag(tag),
+      mProcTag(getProcessTag(tgid)),
+      mIdString(StringPrintf("%" PRId32 "-%" PRId32 "-%" PRId64 "-%s-%" PRId32, tgid, uid,
+                             mSessionId, toString(tag).c_str(), static_cast<int32_t>(mProcTag))),
       mDescriptor(std::make_shared<AppHintDesc>(mSessionId, tgid, uid, threadIds, tag,
                                                 std::chrono::nanoseconds(durationNs))),
       mAppDescriptorTrace(std::make_shared<AppDescriptorTrace>(mIdString)),
-      mTag(tag),
-      mAdpfProfile(HintManager::GetInstance()->GetAdpfProfile(toString(mTag))),
+      mAdpfProfile(mProcTag != ProcessTag::DEFAULT
+                           ? HintManager::GetInstance()->GetAdpfProfile(toString(mProcTag))
+                           : HintManager::GetInstance()->GetAdpfProfile(toString(mSessTag))),
       mOnAdpfUpdate(
               [this](const std::shared_ptr<AdpfConfig> config) { this->setAdpfProfile(config); }),
       mSessionRecords(getAdpfProfile()->mHeuristicBoostOn.has_value() &&
@@ -162,10 +194,15 @@ PowerHintSession<HintManagerT, PowerSessionManagerT>::PowerHintSession(
     ATRACE_CALL();
     ATRACE_INT(mAppDescriptorTrace->trace_target.c_str(), mDescriptor->targetNs.count());
     ATRACE_INT(mAppDescriptorTrace->trace_active.c_str(), mDescriptor->is_active.load());
-    HintManager::GetInstance()->RegisterAdpfUpdateEvent(toString(mTag), &mOnAdpfUpdate);
+
+    if (mProcTag != ProcessTag::DEFAULT) {
+        HintManager::GetInstance()->RegisterAdpfUpdateEvent(toString(mProcTag), &mOnAdpfUpdate);
+    } else {
+        HintManager::GetInstance()->RegisterAdpfUpdateEvent(toString(mSessTag), &mOnAdpfUpdate);
+    }
 
     mLastUpdatedTime = std::chrono::steady_clock::now();
-    mPSManager->addPowerSession(mIdString, mDescriptor, mAppDescriptorTrace, threadIds);
+    mPSManager->addPowerSession(mIdString, mDescriptor, mAppDescriptorTrace, threadIds, mProcTag);
     // init boost
     auto adpfConfig = getAdpfProfile();
     mPSManager->voteSet(
@@ -238,7 +275,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::pause()
     if (!mDescriptor->is_active.load())
         return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
     // Reset to default uclamp value.
-    mPSManager->setThreadsFromPowerSession(mSessionId, {});
+    mPSManager->setThreadsFromPowerSession(mSessionId, {}, mProcTag);
     mDescriptor->is_active.store(false);
     mPSManager->pause(mSessionId);
     ATRACE_INT(mAppDescriptorTrace->trace_active.c_str(), false);
@@ -256,7 +293,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::resume(
     if (mDescriptor->is_active.load()) {
         return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
     }
-    mPSManager->setThreadsFromPowerSession(mSessionId, mDescriptor->thread_ids);
+    mPSManager->setThreadsFromPowerSession(mSessionId, mDescriptor->thread_ids, mProcTag);
     mDescriptor->is_active.store(true);
     // resume boost
     mPSManager->resume(mSessionId);
@@ -273,9 +310,14 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::close()
     }
     mSessionClosed = true;
     // Remove the session from PowerSessionManager first to avoid racing.
-    mPSManager->removePowerSession(mSessionId);
+    mPSManager->removePowerSession(mSessionId, mProcTag);
     mDescriptor->is_active.store(false);
-    HintManager::GetInstance()->UnregisterAdpfUpdateEvent(toString(mTag), &mOnAdpfUpdate);
+
+    if (mProcTag != ProcessTag::DEFAULT) {
+        HintManager::GetInstance()->UnregisterAdpfUpdateEvent(toString(mProcTag), &mOnAdpfUpdate);
+    } else {
+        HintManager::GetInstance()->UnregisterAdpfUpdateEvent(toString(mSessTag), &mOnAdpfUpdate);
+    }
     ATRACE_INT(mAppDescriptorTrace->trace_min.c_str(), 0);
     return ndk::ScopedAStatus::ok();
 }
@@ -294,6 +336,18 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::updateT
     }
     targetDurationNanos = targetDurationNanos * getAdpfProfile()->mTargetTimeFactor;
 
+    // Reset session records and heuristic boost states when the percentage change of target
+    // duration is over the threshold.
+    if (targetDurationNanos != mDescriptor->targetNs.count() &&
+        getAdpfProfile()->mHeuristicBoostOn.has_value() &&
+        getAdpfProfile()->mHeuristicBoostOn.value()) {
+        auto lastTargetNs = mDescriptor->targetNs.count();
+        if (abs(targetDurationNanos - lastTargetNs) >
+            lastTargetNs / 100 * kTargetDurationChangeThreshold) {
+            resetSessionHeuristicStates();
+        }
+    }
+
     mDescriptor->targetNs = std::chrono::nanoseconds(targetDurationNanos);
     mPSManager->updateTargetWorkDuration(mSessionId, AdpfVoteType::CPU_VOTE_DEFAULT,
                                          mDescriptor->targetNs);
@@ -302,6 +356,19 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::updateT
     return ndk::ScopedAStatus::ok();
 }
 
+template <class HintManagerT, class PowerSessionManagerT>
+void PowerHintSession<HintManagerT, PowerSessionManagerT>::resetSessionHeuristicStates() {
+    mSessionRecords->resetRecords();
+    mJankyLevel = SessionJankyLevel::LIGHT;
+    mJankyFrameNum = 0;
+    ATRACE_INT(mAppDescriptorTrace->trace_hboost_janky_level.c_str(),
+               static_cast<int32_t>(mJankyLevel));
+    ATRACE_INT(mAppDescriptorTrace->trace_missed_cycles.c_str(), mJankyFrameNum);
+    ATRACE_INT(mAppDescriptorTrace->trace_avg_duration.c_str(), 0);
+    ATRACE_INT(mAppDescriptorTrace->trace_max_duration.c_str(), 0);
+    ATRACE_INT(mAppDescriptorTrace->trace_low_frame_rate.c_str(), false);
+}
+
 template <class HintManagerT, class PowerSessionManagerT>
 SessionJankyLevel PowerHintSession<HintManagerT, PowerSessionManagerT>::updateSessionJankState(
         SessionJankyLevel oldState, int32_t numOfJankFrames, double durationVariance,
@@ -333,21 +400,14 @@ template <class HintManagerT, class PowerSessionManagerT>
 void PowerHintSession<HintManagerT, PowerSessionManagerT>::updateHeuristicBoost() {
     auto maxDurationUs = mSessionRecords->getMaxDuration();  // micro seconds
     auto avgDurationUs = mSessionRecords->getAvgDuration();  // micro seconds
-    auto numOfReportedDurations = mSessionRecords->getNumOfRecords();
     auto numOfJankFrames = mSessionRecords->getNumOfMissedCycles();
 
-    if (!maxDurationUs.has_value() || !avgDurationUs.has_value()) {
-        // No history data stored
+    if (!maxDurationUs.has_value() || !avgDurationUs.has_value() || avgDurationUs.value() <= 0) {
+        // No history data stored or invalid average duration.
         return;
     }
 
-    double maxToAvgRatio;
-    if (numOfReportedDurations <= 0) {
-        maxToAvgRatio = maxDurationUs.value() * 1.0 / (mDescriptor->targetNs.count() / 1000);
-    } else {
-        maxToAvgRatio = maxDurationUs.value() / avgDurationUs.value();
-    }
-
+    auto maxToAvgRatio = maxDurationUs.value() * 1.0 / avgDurationUs.value();
     auto isLowFPS =
             mSessionRecords->isLowFrameRate(getAdpfProfile()->mLowFrameRateThreshold.value());
 
@@ -360,6 +420,12 @@ void PowerHintSession<HintManagerT, PowerSessionManagerT>::updateHeuristicBoost(
     ATRACE_INT(mAppDescriptorTrace->trace_avg_duration.c_str(), avgDurationUs.value());
     ATRACE_INT(mAppDescriptorTrace->trace_max_duration.c_str(), maxDurationUs.value());
     ATRACE_INT(mAppDescriptorTrace->trace_low_frame_rate.c_str(), isLowFPS);
+    if (mSessTag == SessionTag::SURFACEFLINGER) {
+        ATRACE_INT(mAppDescriptorTrace->trace_game_mode_fps.c_str(),
+                   mSessionRecords->getLatestFPS());
+        ATRACE_INT(mAppDescriptorTrace->trace_game_mode_fps_jitters.c_str(),
+                   mSessionRecords->getNumOfFPSJitters());
+    }
 }
 
 template <class HintManagerT, class PowerSessionManagerT>
@@ -413,8 +479,12 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::reportA
             adpfConfig->mHeuristicBoostOn.has_value() && adpfConfig->mHeuristicBoostOn.value();
 
     if (hboostEnabled) {
-        mSessionRecords->addReportedDurations(actualDurations, mDescriptor->targetNs.count());
+        FrameBuckets newFramesInBuckets;
+        mSessionRecords->addReportedDurations(
+                actualDurations, mDescriptor->targetNs.count(), newFramesInBuckets,
+                mSessTag == SessionTag::SURFACEFLINGER && mPSManager->getGameModeEnableState());
         mPSManager->updateHboostStatistics(mSessionId, mJankyLevel, actualDurations.size());
+        mPSManager->updateFrameBuckets(mSessionId, newFramesInBuckets);
         updateHeuristicBoost();
     }
 
@@ -529,7 +599,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::sendHin
                                                                adpfConfig->mStaleTimeFactor / 2.0));
                 break;
             case SessionHint::POWER_EFFICIENCY:
-                setMode(SessionMode::POWER_EFFICIENCY, true);
+                setModeLocked(SessionMode::POWER_EFFICIENCY, true);
                 break;
             case SessionHint::GPU_LOAD_UP:
                 mPSManager->voteSet(mSessionId, AdpfVoteType::GPU_LOAD_UP,
@@ -542,6 +612,12 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::sendHin
             case SessionHint::GPU_LOAD_RESET:
                 // TODO(kevindubois): add impl
                 break;
+            case SessionHint::CPU_LOAD_SPIKE:
+                // TODO(mattbuckley): add impl
+                break;
+            case SessionHint::GPU_LOAD_SPIKE:
+                // TODO(kevindubois): add impl
+                break;
             default:
                 ALOGE("Error: hint is invalid");
                 return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
@@ -558,6 +634,12 @@ template <class HintManagerT, class PowerSessionManagerT>
 ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::setMode(SessionMode mode,
                                                                                  bool enabled) {
     std::scoped_lock lock{mPowerHintSessionLock};
+    return setModeLocked(mode, enabled);
+}
+
+template <class HintManagerT, class PowerSessionManagerT>
+ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::setModeLocked(
+        SessionMode mode, bool enabled) {
     if (mSessionClosed) {
         ALOGE("Error: session is dead");
         return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
@@ -591,7 +673,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::setThre
         return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
     }
     mDescriptor->thread_ids = threadIds;
-    mPSManager->setThreadsFromPowerSession(mSessionId, threadIds);
+    mPSManager->setThreadsFromPowerSession(mSessionId, threadIds, mProcTag);
     // init boost
     updatePidControlVariable(getAdpfProfile()->mUclampMinInit);
     return ndk::ScopedAStatus::ok();
@@ -606,14 +688,16 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::getSess
 
 template <class HintManagerT, class PowerSessionManagerT>
 SessionTag PowerHintSession<HintManagerT, PowerSessionManagerT>::getSessionTag() const {
-    return mTag;
+    return mSessTag;
 }
 
 template <class HintManagerT, class PowerSessionManagerT>
 const std::shared_ptr<AdpfConfig>
 PowerHintSession<HintManagerT, PowerSessionManagerT>::getAdpfProfile() const {
     if (!mAdpfProfile) {
-        return HintManager::GetInstance()->GetAdpfProfile(toString(mTag));
+        return mProcTag == ProcessTag::DEFAULT
+                       ? HintManager::GetInstance()->GetAdpfProfile(toString(mSessTag))
+                       : HintManager::GetInstance()->GetAdpfProfile(toString(mProcTag));
     }
     return mAdpfProfile;
 }
diff --git a/power-libperfmgr/aidl/PowerHintSession.h b/power-libperfmgr/aidl/PowerHintSession.h
index da73c132..c243f719 100644
--- a/power-libperfmgr/aidl/PowerHintSession.h
+++ b/power-libperfmgr/aidl/PowerHintSession.h
@@ -87,11 +87,19 @@ class PowerHintSession : public BnPowerHintSession, public Immobile {
                                              double durationVariance, bool isLowFPS)
             REQUIRES(mPowerHintSessionLock);
     void updateHeuristicBoost() REQUIRES(mPowerHintSessionLock);
+    void resetSessionHeuristicStates() REQUIRES(mPowerHintSessionLock);
     const std::shared_ptr<AdpfConfig> getAdpfProfile() const;
+    ProcessTag getProcessTag(int32_t tgid);
+    ndk::ScopedAStatus setModeLocked(SessionMode mode, bool enabled)
+            REQUIRES(mPowerHintSessionLock);
 
     // Data
     PowerSessionManagerT *mPSManager;
     const int64_t mSessionId = 0;
+    // Tag labeling what kind of session this is
+    const SessionTag mSessTag;
+    // Pixel process tag for more granular session control.
+    const ProcessTag mProcTag{ProcessTag::DEFAULT};
     const std::string mIdString;
     std::shared_ptr<AppHintDesc> mDescriptor GUARDED_BY(mPowerHintSessionLock);
 
@@ -103,8 +111,6 @@ class PowerHintSession : public BnPowerHintSession, public Immobile {
     std::unordered_map<std::string, std::optional<bool>> mSupportedHints;
     // Use the value of the last enum in enum_range +1 as array size
     std::array<bool, enum_size<SessionMode>()> mModes GUARDED_BY(mPowerHintSessionLock){};
-    // Tag labeling what kind of session this is
-    const SessionTag mTag;
     std::shared_ptr<AdpfConfig> mAdpfProfile;
     std::function<void(const std::shared_ptr<AdpfConfig>)> mOnAdpfUpdate;
     std::unique_ptr<SessionRecords> mSessionRecords GUARDED_BY(mPowerHintSessionLock) = nullptr;
diff --git a/power-libperfmgr/aidl/PowerSessionManager.cpp b/power-libperfmgr/aidl/PowerSessionManager.cpp
index 2ee4565f..3547db30 100644
--- a/power-libperfmgr/aidl/PowerSessionManager.cpp
+++ b/power-libperfmgr/aidl/PowerSessionManager.cpp
@@ -27,7 +27,6 @@
 #include <sys/syscall.h>
 #include <utils/Trace.h>
 
-#include "AdpfTypes.h"
 #include "AppDescriptorTrace.h"
 #include "AppHintDesc.h"
 #include "tests/mocks/MockHintManager.h"
@@ -40,6 +39,7 @@ namespace impl {
 namespace pixel {
 
 using ::android::perfmgr::HintManager;
+constexpr char kGameModeName[] = "GAME";
 
 namespace {
 /* there is no glibc or bionic wrapper */
@@ -77,20 +77,29 @@ static int set_uclamp(int tid, UclampRange range) {
 }
 }  // namespace
 
-// TODO(jimmyshiu@): Deprecated. Remove once all powerhint.json up-to-date.
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::updateHintMode(const std::string &mode, bool enabled) {
     ALOGD("%s %s:%b", __func__, mode.c_str(), enabled);
+    if (mode.compare(kGameModeName) == 0) {
+        mGameModeEnabled = enabled;
+    }
+
+    // TODO(jimmyshiu@): Deprecated. Remove once all powerhint.json up-to-date.
     if (enabled && HintManager::GetInstance()->GetAdpfProfileFromDoHint()) {
         HintManager::GetInstance()->SetAdpfProfileFromDoHint(mode);
     }
 }
 
+template <class HintManagerT>
+bool PowerSessionManager<HintManagerT>::getGameModeEnableState() {
+    return mGameModeEnabled;
+}
+
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::addPowerSession(
         const std::string &idString, const std::shared_ptr<AppHintDesc> &sessionDescriptor,
         const std::shared_ptr<AppDescriptorTrace> &sessionTrace,
-        const std::vector<int32_t> &threadIds) {
+        const std::vector<int32_t> &threadIds, const ProcessTag procTag) {
     if (!sessionDescriptor) {
         ALOGE("sessionDescriptor is null. PowerSessionManager failed to add power session: %s",
               idString.c_str());
@@ -119,11 +128,12 @@ void PowerSessionManager<HintManagerT>::addPowerSession(
         ALOGE("sessionTaskMap failed to add power session: %" PRId64, sessionDescriptor->sessionId);
     }
 
-    setThreadsFromPowerSession(sessionDescriptor->sessionId, threadIds);
+    setThreadsFromPowerSession(sessionDescriptor->sessionId, threadIds, procTag);
 }
 
 template <class HintManagerT>
-void PowerSessionManager<HintManagerT>::removePowerSession(int64_t sessionId) {
+void PowerSessionManager<HintManagerT>::removePowerSession(int64_t sessionId,
+                                                           const ProcessTag procTag) {
     // To remove a session we also need to undo the effects the session
     // has on currently enabled votes which means setting vote to inactive
     // and then forceing a uclamp update to occur
@@ -140,9 +150,19 @@ void PowerSessionManager<HintManagerT>::removePowerSession(int64_t sessionId) {
         mSessionTaskMap.remove(sessionId);
     }
 
-    for (auto tid : removedThreads) {
-        if (!SetTaskProfiles(tid, {"NoResetUclampGrp"})) {
-            ALOGE("Failed to set NoResetUclampGrp task profile for tid:%d", tid);
+    if (procTag == ProcessTag::SYSTEM_UI) {
+        for (auto tid : removedThreads) {
+            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_EXTREME_CLEAR"})) {
+                ALOGE("Failed to set SCHED_QOS_SENSITIVE_EXTREME_CLEAR task profile for tid:%d",
+                      tid);
+            }
+        }
+    } else {
+        for (auto tid : removedThreads) {
+            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_STANDARD_CLEAR"})) {
+                ALOGE("Failed to set SCHED_QOS_SENSITIVE_STANDARD_CLEAR task profile for tid:%d",
+                      tid);
+            }
         }
     }
 
@@ -151,7 +171,7 @@ void PowerSessionManager<HintManagerT>::removePowerSession(int64_t sessionId) {
 
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::setThreadsFromPowerSession(
-        int64_t sessionId, const std::vector<int32_t> &threadIds) {
+        int64_t sessionId, const std::vector<int32_t> &threadIds, const ProcessTag procTag) {
     std::vector<pid_t> addedThreads;
     std::vector<pid_t> removedThreads;
     forceSessionActive(sessionId, false);
@@ -159,14 +179,33 @@ void PowerSessionManager<HintManagerT>::setThreadsFromPowerSession(
         std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
         mSessionTaskMap.replace(sessionId, threadIds, &addedThreads, &removedThreads);
     }
-    for (auto tid : addedThreads) {
-        if (!SetTaskProfiles(tid, {"ResetUclampGrp"})) {
-            ALOGE("Failed to set ResetUclampGrp task profile for tid:%d", tid);
+    if (procTag == ProcessTag::SYSTEM_UI) {
+        for (auto tid : addedThreads) {
+            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_EXTREME_SET"})) {
+                ALOGE("Failed to set SCHED_QOS_SENSITIVE_EXTREME_SET task profile for tid:%d", tid);
+            }
+        }
+    } else {
+        for (auto tid : addedThreads) {
+            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_STANDARD_SET"})) {
+                ALOGE("Failed to set SCHED_QOS_SENSITIVE_STANDARD_SET task profile for tid:%d",
+                      tid);
+            }
         }
     }
-    for (auto tid : removedThreads) {
-        if (!SetTaskProfiles(tid, {"NoResetUclampGrp"})) {
-            ALOGE("Failed to set NoResetUclampGrp task profile for tid:%d", tid);
+    if (procTag == ProcessTag::SYSTEM_UI) {
+        for (auto tid : removedThreads) {
+            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_EXTREME_CLEAR"})) {
+                ALOGE("Failed to set SCHED_QOS_SENSITIVE_EXTREME_CLEAR task profile for tid:%d",
+                      tid);
+            }
+        }
+    } else {
+        for (auto tid : removedThreads) {
+            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_STANDARD_CLEAR"})) {
+                ALOGE("Failed to set SCHED_QOS_SENSITIVE_STANDARD_CLEAR task profile for tid:%d",
+                      tid);
+            }
         }
     }
     forceSessionActive(sessionId, true);
@@ -380,17 +419,17 @@ void PowerSessionManager<HintManagerT>::disableBoosts(int64_t sessionId) {
 
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::enableSystemTopAppBoost() {
-    if (HintManager::GetInstance()->IsHintSupported(kDisableBoostHintName)) {
+    if (HintManagerT::GetInstance()->IsHintSupported(kDisableBoostHintName)) {
         ALOGV("PowerSessionManager::enableSystemTopAppBoost!!");
-        HintManager::GetInstance()->EndHint(kDisableBoostHintName);
+        HintManagerT::GetInstance()->EndHint(kDisableBoostHintName);
     }
 }
 
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::disableSystemTopAppBoost() {
-    if (HintManager::GetInstance()->IsHintSupported(kDisableBoostHintName)) {
+    if (HintManagerT::GetInstance()->IsHintSupported(kDisableBoostHintName)) {
         ALOGV("PowerSessionManager::disableSystemTopAppBoost!!");
-        HintManager::GetInstance()->DoHint(kDisableBoostHintName);
+        HintManagerT::GetInstance()->DoHint(kDisableBoostHintName);
     }
 }
 
@@ -448,7 +487,7 @@ void PowerSessionManager<HintManagerT>::handleEvent(const EventSessionTimeout &e
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::applyUclampLocked(
         int64_t sessionId, std::chrono::steady_clock::time_point timePoint) {
-    auto config = HintManager::GetInstance()->GetAdpfProfile();
+    auto config = HintManagerT::GetInstance()->GetAdpfProfile();
     {
         // TODO(kevindubois) un-indent this in followup patch to reduce churn.
         auto sessValPtr = mSessionTaskMap.findSession(sessionId);
@@ -492,7 +531,7 @@ void PowerSessionManager<HintManagerT>::applyGpuVotesLocked(
         return;
     }
 
-    auto const gpuVotingOn = HintManager::GetInstance()->GetAdpfProfile()->mGpuBoostOn;
+    auto const gpuVotingOn = HintManagerT::GetInstance()->GetAdpfProfile()->mGpuBoostOn;
     if (mGpuCapacityNode && gpuVotingOn) {
         auto const capacity = mSessionTaskMap.getSessionsGpuCapacity(timePoint);
         (*mGpuCapacityNode)->set_gpu_capacity(capacity);
@@ -582,6 +621,18 @@ void PowerSessionManager<HintManagerT>::clear() {
     mSessionMap.clear();
 }
 
+template <class HintManagerT>
+void PowerSessionManager<HintManagerT>::updateFrameBuckets(int64_t sessionId,
+                                                           const FrameBuckets &lastReportedFrames) {
+    std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
+    auto sessValPtr = mSessionTaskMap.findSession(sessionId);
+    if (nullptr == sessValPtr) {
+        return;
+    }
+
+    sessValPtr->sessFrameBuckets.addUpNewFrames(lastReportedFrames);
+}
+
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::updateHboostStatistics(int64_t sessionId,
                                                                SessionJankyLevel jankyLevel,
diff --git a/power-libperfmgr/aidl/PowerSessionManager.h b/power-libperfmgr/aidl/PowerSessionManager.h
index e71ed2e5..e0d1352a 100644
--- a/power-libperfmgr/aidl/PowerSessionManager.h
+++ b/power-libperfmgr/aidl/PowerSessionManager.h
@@ -23,6 +23,7 @@
 #include <mutex>
 #include <optional>
 
+#include "AdpfTypes.h"
 #include "AppHintDesc.h"
 #include "BackgroundWorker.h"
 #include "GpuCapacityNode.h"
@@ -50,10 +51,11 @@ class PowerSessionManager : public Immobile {
     void addPowerSession(const std::string &idString,
                          const std::shared_ptr<AppHintDesc> &sessionDescriptor,
                          const std::shared_ptr<AppDescriptorTrace> &sessionTrace,
-                         const std::vector<int32_t> &threadIds);
-    void removePowerSession(int64_t sessionId);
+                         const std::vector<int32_t> &threadIds, const ProcessTag procTag);
+    void removePowerSession(int64_t sessionId, const ProcessTag procTag);
     // Replace current threads in session with threadIds
-    void setThreadsFromPowerSession(int64_t sessionId, const std::vector<int32_t> &threadIds);
+    void setThreadsFromPowerSession(int64_t sessionId, const std::vector<int32_t> &threadIds,
+                                    const ProcessTag procTag);
     // Pause and resume power hint session
     void pause(int64_t sessionId);
     void resume(int64_t sessionId);
@@ -79,6 +81,8 @@ class PowerSessionManager : public Immobile {
     void updateHboostStatistics(int64_t sessionId, SessionJankyLevel jankyLevel,
                                 int32_t numOfFrames);
 
+    void updateFrameBuckets(int64_t sessionId, const FrameBuckets &lastReportedFrames);
+
     // Singleton
     static PowerSessionManager *getInstance() {
         static PowerSessionManager instance{};
@@ -92,6 +96,7 @@ class PowerSessionManager : public Immobile {
     // Only for testing
     void clear();
     std::shared_ptr<void> getSession(int64_t sessionId);
+    bool getGameModeEnableState();
 
   private:
     std::optional<bool> isAnyAppSessionActive();
@@ -137,7 +142,9 @@ class PowerSessionManager : public Immobile {
     std::optional<std::unique_ptr<GpuCapacityNode>> const mGpuCapacityNode;
 
     std::mutex mSessionMapMutex;
-    std::map<int, std::weak_ptr<void>> mSessionMap GUARDED_BY(mSessionMapMutex);
+    std::unordered_map<int, std::weak_ptr<void>> mSessionMap GUARDED_BY(mSessionMapMutex);
+
+    std::atomic<bool> mGameModeEnabled{false};
 };
 
 }  // namespace pixel
diff --git a/power-libperfmgr/aidl/SessionChannel.cpp b/power-libperfmgr/aidl/SessionChannel.cpp
new file mode 100644
index 00000000..d324cf5c
--- /dev/null
+++ b/power-libperfmgr/aidl/SessionChannel.cpp
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
+#include "SessionChannel.h"
+
+#include "AdpfTypes.h"
+
+namespace aidl::google::hardware::power::impl::pixel {
+
+SessionChannel::SessionChannel(int32_t tgid, int32_t uid, int64_t id, int32_t offset)
+    : mTgid(tgid),
+      mUid(uid),
+      mId(id),
+      mReadMask(1u << (offset + 16)),
+      mWriteMask(1u << offset),
+      mChannelQueue(kFMQQueueSize, true) {}
+
+void SessionChannel::getDesc(ChannelQueueDesc *_return_desc) {
+    *_return_desc = mChannelQueue.dupeDesc();
+}
+
+bool SessionChannel::isValid() const {
+    return mChannelQueue.isValid();
+}
+
+ChannelQueue *SessionChannel::getQueue() {
+    return &mChannelQueue;
+}
+
+int32_t SessionChannel::getTgid() const {
+    return mTgid;
+}
+
+int32_t SessionChannel::getUid() const {
+    return mUid;
+}
+
+int64_t SessionChannel::getId() const {
+    return mId;
+}
+
+uint32_t SessionChannel::getReadBitmask() const {
+    return mReadMask;
+}
+
+uint32_t SessionChannel::getWriteBitmask() const {
+    return mWriteMask;
+}
+
+}  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/SessionChannel.h b/power-libperfmgr/aidl/SessionChannel.h
new file mode 100644
index 00000000..4af73338
--- /dev/null
+++ b/power-libperfmgr/aidl/SessionChannel.h
@@ -0,0 +1,54 @@
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
+#pragma once
+
+#include <cstdint>
+
+#include "AdpfTypes.h"
+
+namespace aidl::google::hardware::power::impl::pixel {
+
+class SessionChannel {
+  public:
+    SessionChannel(int32_t tgid, int32_t uid, int64_t id, int32_t offset);
+    void getDesc(ChannelQueueDesc *_return_desc);
+    bool isValid() const;
+    ChannelQueue *getQueue();
+    int32_t getTgid() const;
+    int32_t getUid() const;
+    int64_t getId() const;
+    // write is the lowest 16 bits, read is the upper 16 bits
+    uint32_t getWriteBitmask() const;
+    uint32_t getReadBitmask() const;
+
+  private:
+    int32_t mTgid = -1;
+    int32_t mUid = -1;
+    // An ID starting from 0 increasing sequentially, representing
+    // location in the session array. If a channel dies, it isn't removed
+    // but killed, so that the order remains the same for everyone. It will
+    // be replaced when new sessions come along. The first 15 sessions
+    // all get unique sets of bits to communicate with their client,
+    // and 16+ have to share the last slot. It's worth considering making
+    // another thread if we go beyond 16.
+    const int64_t mId = -1;
+    const uint32_t mReadMask = 0;
+    const uint32_t mWriteMask = 0;
+    ChannelQueue mChannelQueue;
+};
+
+}  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/SessionMetrics.h b/power-libperfmgr/aidl/SessionMetrics.h
new file mode 100644
index 00000000..6ae600f0
--- /dev/null
+++ b/power-libperfmgr/aidl/SessionMetrics.h
@@ -0,0 +1,88 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+namespace aidl {
+namespace google {
+namespace hardware {
+namespace power {
+namespace impl {
+namespace pixel {
+
+/**
+ * Put jank frames into buckets. The "jank" evaluation is reusing the session records jank
+ * evaluation logic while here only counts the frames over 17ms. Though the current jank
+ * evaluation is not exactly right for every frame at the moment, it can still provide a
+ * a good sense of session's jank status. When we have more precise timeline from platform side
+ * the jank evaluation logic could be updated.
+ */
+struct FrameBuckets {
+  public:
+    int64_t totalNumOfFrames{0};      // This includes jank frames and normal frames.
+    int64_t numOfFrames17to25ms{0};   // Jank frames over 1 120Hz Vsync interval(8.333ms)
+    int64_t numOfFrames25to34ms{0};   // Jank frames over 2 120Hz Vsync interval(16.667ms)
+    int64_t numOfFrames34to67ms{0};   // Jank frames over 3 to 6 120Hz Vsync intervals.
+    int64_t numOfFrames67to100ms{0};  // Jank frames between 10 Hz and 15 Hz
+    int64_t numOfFramesOver100ms{0};  // Jank frames below 10 Hz.
+
+    std::string toString() const {
+        std::stringstream ss;
+        ss << "JankFramesInBuckets: ";
+        if (totalNumOfFrames <= 0) {
+            ss << "0%-0%-0%-0%-0%-0";
+            return ss.str();
+        }
+
+        ss << (numOfFrames17to25ms * 10000 / totalNumOfFrames / 100.0) << "%";
+        if (numOfFrames17to25ms > 0) {
+            ss << "(" << numOfFrames17to25ms << ")";
+        }
+
+        appendSingleBucketStr(numOfFrames25to34ms, totalNumOfFrames, ss);
+        appendSingleBucketStr(numOfFrames34to67ms, totalNumOfFrames, ss);
+        appendSingleBucketStr(numOfFrames67to100ms, totalNumOfFrames, ss);
+        appendSingleBucketStr(numOfFramesOver100ms, totalNumOfFrames, ss);
+
+        ss << "-" << totalNumOfFrames;
+        return ss.str();
+    }
+
+    void addUpNewFrames(const FrameBuckets &newFrames) {
+        totalNumOfFrames += newFrames.totalNumOfFrames;
+        numOfFrames17to25ms += newFrames.numOfFrames17to25ms;
+        numOfFrames25to34ms += newFrames.numOfFrames25to34ms;
+        numOfFrames34to67ms += newFrames.numOfFrames34to67ms;
+        numOfFrames67to100ms += newFrames.numOfFrames67to100ms;
+        numOfFramesOver100ms += newFrames.numOfFramesOver100ms;
+    }
+
+  private:
+    void appendSingleBucketStr(int64_t singleBucketFrames, int64_t totalFrames,
+                               std::stringstream &ss) const {
+        ss << "-" << (singleBucketFrames * 10000 / totalFrames / 100.0) << "%";
+        if (singleBucketFrames > 0) {
+            ss << "(" << singleBucketFrames << ")";
+        }
+    }
+};
+
+}  // namespace pixel
+}  // namespace impl
+}  // namespace power
+}  // namespace hardware
+}  // namespace google
+}  // namespace aidl
diff --git a/power-libperfmgr/aidl/SessionRecords.cpp b/power-libperfmgr/aidl/SessionRecords.cpp
index 7f09a994..f1664969 100644
--- a/power-libperfmgr/aidl/SessionRecords.cpp
+++ b/power-libperfmgr/aidl/SessionRecords.cpp
@@ -27,13 +27,17 @@ namespace power {
 namespace impl {
 namespace pixel {
 
+static constexpr int32_t kTotalFramesForFPSCheck = 3;
+
 SessionRecords::SessionRecords(const int32_t maxNumOfRecords, const double jankCheckTimeFactor)
     : kMaxNumOfRecords(maxNumOfRecords), kJankCheckTimeFactor(jankCheckTimeFactor) {
     mRecords.resize(maxNumOfRecords);
 }
 
 void SessionRecords::addReportedDurations(const std::vector<WorkDuration> &actualDurationsNs,
-                                          int64_t targetDurationNs) {
+                                          int64_t targetDurationNs,
+                                          FrameBuckets &newFramesInBuckets,
+                                          bool computeFPSJitters) {
     for (auto &duration : actualDurationsNs) {
         int32_t totalDurationUs = duration.durationNanos / 1000;
 
@@ -48,6 +52,12 @@ void SessionRecords::addReportedDurations(const std::vector<WorkDuration> &actua
                     LOG(ERROR) << "Invalid number of missed cycles: " << mNumOfMissedCycles;
                 }
             }
+            if (mRecords[indexOfRecordToRemove].isFPSJitter) {
+                mNumOfFrameFPSJitters--;
+                if (mNumOfFrameFPSJitters < 0) {
+                    LOG(ERROR) << "Invalid number of FPS jitter frames: " << mNumOfFrameFPSJitters;
+                }
+            }
             mNumOfFrames--;
 
             // If the record to be removed is the max duration, pop it out of the
@@ -67,12 +77,41 @@ void SessionRecords::addReportedDurations(const std::vector<WorkDuration> &actua
         }
         mLastStartTimeNs = startTimeNs;
 
+        // Track the number of frame FPS jitters.
+        // A frame is evaluated as FPS jitter if its startInterval is not less
+        // than previous three frames' average startIntervals.
+        bool FPSJitter = false;
+        if (computeFPSJitters) {
+            if (mAddedFramesForFPSCheck < kTotalFramesForFPSCheck) {
+                if (startIntervalUs > 0) {
+                    mLatestStartIntervalSumUs += startIntervalUs;
+                    mAddedFramesForFPSCheck++;
+                }
+            } else {
+                if (startIntervalUs > (1.4 * mLatestStartIntervalSumUs / kTotalFramesForFPSCheck)) {
+                    FPSJitter = true;
+                    mNumOfFrameFPSJitters++;
+                }
+                int32_t oldRecordIndex = mLatestRecordIndex - kTotalFramesForFPSCheck;
+                if (oldRecordIndex < 0) {
+                    oldRecordIndex += kMaxNumOfRecords;
+                }
+                mLatestStartIntervalSumUs +=
+                        startIntervalUs - mRecords[oldRecordIndex].startIntervalUs;
+            }
+        } else {
+            mLatestStartIntervalSumUs = 0;
+            mAddedFramesForFPSCheck = 0;
+        }
+
         bool cycleMissed = totalDurationUs > (targetDurationNs / 1000) * kJankCheckTimeFactor;
-        mRecords[mLatestRecordIndex] = CycleRecord{startIntervalUs, totalDurationUs, cycleMissed};
+        mRecords[mLatestRecordIndex] =
+                CycleRecord{startIntervalUs, totalDurationUs, cycleMissed, FPSJitter};
         mNumOfFrames++;
         if (cycleMissed) {
             mNumOfMissedCycles++;
         }
+        updateFrameBuckets(totalDurationUs, cycleMissed, newFramesInBuckets);
 
         // Pop out the indexes that their related values are not greater than the
         // latest one.
@@ -125,6 +164,44 @@ bool SessionRecords::isLowFrameRate(int32_t fpsLowRateThreshold) {
     return false;
 }
 
+void SessionRecords::resetRecords() {
+    mAvgDurationUs = 0;
+    mLastStartTimeNs = 0;
+    mLatestRecordIndex = -1;
+    mNumOfMissedCycles = 0;
+    mNumOfFrames = 0;
+    mSumOfDurationsUs = 0;
+    mRecordsIndQueue.clear();
+}
+
+int32_t SessionRecords::getLatestFPS() const {
+    return 1000000 * kTotalFramesForFPSCheck / mLatestStartIntervalSumUs;
+}
+
+int32_t SessionRecords::getNumOfFPSJitters() const {
+    return mNumOfFrameFPSJitters;
+}
+
+void SessionRecords::updateFrameBuckets(int32_t frameDurationUs, bool isJankFrame,
+                                        FrameBuckets &framesInBuckets) {
+    framesInBuckets.totalNumOfFrames++;
+    if (!isJankFrame || frameDurationUs < 17000) {
+        return;
+    }
+
+    if (frameDurationUs < 25000) {
+        framesInBuckets.numOfFrames17to25ms++;
+    } else if (frameDurationUs < 34000) {
+        framesInBuckets.numOfFrames25to34ms++;
+    } else if (frameDurationUs < 67000) {
+        framesInBuckets.numOfFrames34to67ms++;
+    } else if (frameDurationUs < 100000) {
+        framesInBuckets.numOfFrames67to100ms++;
+    } else if (frameDurationUs >= 100000) {
+        framesInBuckets.numOfFramesOver100ms++;
+    }
+}
+
 }  // namespace pixel
 }  // namespace impl
 }  // namespace power
diff --git a/power-libperfmgr/aidl/SessionRecords.h b/power-libperfmgr/aidl/SessionRecords.h
index df5c81a1..5b1fb746 100644
--- a/power-libperfmgr/aidl/SessionRecords.h
+++ b/power-libperfmgr/aidl/SessionRecords.h
@@ -22,6 +22,8 @@
 #include <optional>
 #include <vector>
 
+#include "SessionMetrics.h"
+
 namespace aidl {
 namespace google {
 namespace hardware {
@@ -30,13 +32,13 @@ namespace impl {
 namespace pixel {
 
 using aidl::android::hardware::power::WorkDuration;
-
 class SessionRecords {
   public:
     struct CycleRecord {
         int32_t startIntervalUs{0};
         int32_t totalDurationUs{0};
         bool isMissedCycle{false};
+        bool isFPSJitter{false};
     };
 
   public:
@@ -44,14 +46,23 @@ class SessionRecords {
     ~SessionRecords() = default;
 
     void addReportedDurations(const std::vector<WorkDuration> &actualDurationsNs,
-                              int64_t targetDurationNs);
+                              int64_t targetDurationNs, FrameBuckets &newFramesInBuckets,
+                              bool computeFPSJitters = false);
     std::optional<int32_t> getMaxDuration();
     std::optional<int32_t> getAvgDuration();
     int32_t getNumOfRecords();
     int32_t getNumOfMissedCycles();
     bool isLowFrameRate(int32_t fpsLowRateThreshold);
+    void resetRecords();
+    // It will only return valid value when the computeFPSJitters is enabled while
+    // calling addReportedDurations. It's mainly for game mode FPS monitoring.
+    int32_t getLatestFPS() const;
+    int32_t getNumOfFPSJitters() const;
 
   private:
+    void updateFrameBuckets(int32_t frameDurationUs, bool isJankFrame,
+                            FrameBuckets &framesInBuckets);
+
     const int32_t kMaxNumOfRecords;
     const double kJankCheckTimeFactor;
     std::vector<CycleRecord> mRecords;
@@ -64,6 +75,12 @@ class SessionRecords {
     int32_t mNumOfMissedCycles{0};
     int32_t mNumOfFrames{0};
     int64_t mSumOfDurationsUs{0};
+
+    // Compute the sum of start interval for the last few frames.
+    // It can be beneficial for computing the FPS jitters.
+    int32_t mLatestStartIntervalSumUs{0};
+    int32_t mNumOfFrameFPSJitters{0};
+    int32_t mAddedFramesForFPSCheck{0};
 };
 
 }  // namespace pixel
diff --git a/power-libperfmgr/aidl/SessionValueEntry.cpp b/power-libperfmgr/aidl/SessionValueEntry.cpp
index cff5bf67..30b1ee0b 100644
--- a/power-libperfmgr/aidl/SessionValueEntry.cpp
+++ b/power-libperfmgr/aidl/SessionValueEntry.cpp
@@ -46,7 +46,7 @@ std::ostream &SessionValueEntry::dump(std::ostream &os) const {
        << "%-"
        << (totalFrames <= 0 ? 0 : (hBoostModeDist.severeModeFrames * 10000 / totalFrames / 100.0))
        << "%-" << totalFrames << ", ";
-
+    os << sessFrameBuckets.toString() << ", ";
     return os;
 }
 
diff --git a/power-libperfmgr/aidl/SessionValueEntry.h b/power-libperfmgr/aidl/SessionValueEntry.h
index 3ccade81..90392aaa 100644
--- a/power-libperfmgr/aidl/SessionValueEntry.h
+++ b/power-libperfmgr/aidl/SessionValueEntry.h
@@ -19,6 +19,7 @@
 #include <ostream>
 
 #include "AppDescriptorTrace.h"
+#include "SessionRecords.h"
 #include "UClampVoter.h"
 
 namespace aidl {
@@ -50,6 +51,7 @@ struct SessionValueEntry {
     std::chrono::steady_clock::time_point lastUpdatedTime;
     std::shared_ptr<Votes> votes;
     std::shared_ptr<AppDescriptorTrace> sessionTrace;
+    FrameBuckets sessFrameBuckets;
     bool isPowerEfficient{false};
     HeurBoostStatistics hBoostModeDist;
 
diff --git a/power-libperfmgr/aidl/SupportManager.cpp b/power-libperfmgr/aidl/SupportManager.cpp
new file mode 100644
index 00000000..85caf499
--- /dev/null
+++ b/power-libperfmgr/aidl/SupportManager.cpp
@@ -0,0 +1,234 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include "SupportManager.h"
+
+#include <perfmgr/HintManager.h>
+
+#include <bitset>
+#include <map>
+#include <type_traits>
+
+#include "AdpfTypes.h"
+
+namespace aidl::google::hardware::power::impl::pixel {
+using ::android::perfmgr::HintManager;
+
+template <class E>
+using SupportList = std::initializer_list<std::pair<const E, int32_t>>;
+
+#define ASSERT_CAPACITY(Enum, list)                                               \
+    static_assert(list.size() >= enum_size<Enum>(),                               \
+                  "Enum " #Enum " is missing entries in SupportManager.");        \
+    static_assert(std::is_same<const Enum, decltype(list.begin()->first)>::value, \
+                  "Mismatched types on " #list);
+
+// clang-format off
+constexpr SupportList<Mode> kModeEarliestVersion {
+  {Mode::DOUBLE_TAP_TO_WAKE, 1},
+  {Mode::LOW_POWER, 1},
+  {Mode::SUSTAINED_PERFORMANCE, 1},
+  {Mode::FIXED_PERFORMANCE, 1},
+  {Mode::VR, 1},
+  {Mode::LAUNCH, 1},
+  {Mode::EXPENSIVE_RENDERING, 1},
+  {Mode::INTERACTIVE, 1},
+  {Mode::DEVICE_IDLE, 1},
+  {Mode::DISPLAY_INACTIVE, 1},
+  {Mode::AUDIO_STREAMING_LOW_LATENCY, 1},
+  {Mode::CAMERA_STREAMING_SECURE, 1},
+  {Mode::CAMERA_STREAMING_LOW, 1},
+  {Mode::CAMERA_STREAMING_MID, 1},
+  {Mode::CAMERA_STREAMING_HIGH, 1},
+  {Mode::GAME, 3},
+  {Mode::GAME_LOADING, 3},
+  {Mode::DISPLAY_CHANGE, 5},
+  {Mode::AUTOMOTIVE_PROJECTION, 5},
+};
+
+constexpr SupportList<Boost> kBoostEarliestVersion = {
+  {Boost::INTERACTION, 1},
+  {Boost::DISPLAY_UPDATE_IMMINENT, 1},
+  {Boost::ML_ACC, 1},
+  {Boost::AUDIO_LAUNCH, 1},
+  {Boost::CAMERA_LAUNCH, 1},
+  {Boost::CAMERA_SHOT, 1},
+};
+
+constexpr SupportList<SessionHint> kSessionHintEarliestVersion = {
+  {SessionHint::CPU_LOAD_UP, 4},
+  {SessionHint::CPU_LOAD_DOWN, 4},
+  {SessionHint::CPU_LOAD_RESET, 4},
+  {SessionHint::CPU_LOAD_RESUME, 4},
+  {SessionHint::POWER_EFFICIENCY, 4},
+  {SessionHint::GPU_LOAD_UP, 5},
+  {SessionHint::GPU_LOAD_DOWN, 5},
+  {SessionHint::GPU_LOAD_RESET, 5},
+  {SessionHint::CPU_LOAD_SPIKE, 6},
+  {SessionHint::GPU_LOAD_SPIKE, 6},
+};
+
+constexpr SupportList<SessionMode> kSessionModeEarliestVersion = {
+  {SessionMode::POWER_EFFICIENCY, 5},
+  {SessionMode::GRAPHICS_PIPELINE, 6},
+  {SessionMode::AUTO_CPU, 6},
+  {SessionMode::AUTO_GPU, 6},
+};
+
+constexpr SupportList<SessionTag> kSessionTagEarliestVersion {
+  {SessionTag::OTHER, 5},
+  {SessionTag::SURFACEFLINGER, 5},
+  {SessionTag::HWUI, 5},
+  {SessionTag::GAME, 5},
+  {SessionTag::APP, 5},
+  {SessionTag::SYSUI, 6},
+};
+// clang-format on
+
+// Make it so that this refuses to build if you add enums but don't define them here
+ASSERT_CAPACITY(Mode, kModeEarliestVersion);
+ASSERT_CAPACITY(Boost, kBoostEarliestVersion);
+ASSERT_CAPACITY(SessionHint, kSessionHintEarliestVersion);
+ASSERT_CAPACITY(SessionMode, kSessionModeEarliestVersion);
+ASSERT_CAPACITY(SessionTag, kSessionTagEarliestVersion);
+
+std::map<Mode, int32_t> kModeEarliestVersionMap = kModeEarliestVersion;
+std::map<Boost, int32_t> kBoostEarliestVersionMap = kBoostEarliestVersion;
+std::map<SessionHint, int32_t> kSessionHintEarliestVersionMap = kSessionHintEarliestVersion;
+std::map<SessionMode, int32_t> kSessionModeEarliestVersionMap = kSessionModeEarliestVersion;
+std::map<SessionTag, int32_t> kSessionTagEarliestVersionMap = kSessionTagEarliestVersion;
+
+SupportInfo SupportManager::makeSupportInfo() {
+    SupportInfo out;
+    out.usesSessions = HintManager::GetInstance()->IsAdpfSupported();
+
+    // Assume all are unsupported
+    std::bitset<64> modeBits(0);
+    std::bitset<64> boostBits(0);
+    std::bitset<64> sessionHintBits(0);
+    std::bitset<64> sessionModeBits(0);
+    std::bitset<64> sessionTagBits(0);
+
+    for (auto &&mode : ndk::enum_range<Mode>()) {
+        modeBits[static_cast<int>(mode)] = modeSupported(mode);
+    }
+    for (auto &&boost : ndk::enum_range<Boost>()) {
+        boostBits[static_cast<int>(boost)] = boostSupported(boost);
+    }
+
+    out.modes = static_cast<int64_t>(modeBits.to_ullong());
+    out.boosts = static_cast<int64_t>(boostBits.to_ullong());
+
+    // Don't check session-specific items if they aren't supported
+    if (!out.usesSessions) {
+        return out;
+    }
+
+    for (auto &&sessionHint : ndk::enum_range<SessionHint>()) {
+        sessionHintBits[static_cast<int>(sessionHint)] = sessionHintSupported(sessionHint);
+    }
+    for (auto &&sessionMode : ndk::enum_range<SessionMode>()) {
+        sessionModeBits[static_cast<int>(sessionMode)] = sessionModeSupported(sessionMode);
+    }
+    for (auto &&sessionTag : ndk::enum_range<SessionTag>()) {
+        sessionTagBits[static_cast<int>(sessionTag)] = sessionTagSupported(sessionTag);
+    }
+
+    out.sessionHints = static_cast<int64_t>(sessionHintBits.to_ullong());
+    out.sessionModes = static_cast<int64_t>(sessionModeBits.to_ullong());
+    out.sessionTags = static_cast<int64_t>(sessionTagBits.to_ullong());
+
+    out.compositionData = {
+            .isSupported = false,
+            .disableGpuFences = false,
+            .maxBatchSize = 1,
+            .alwaysBatch = false,
+    };
+    out.headroom = {
+        .isCpuSupported = false,
+        .isGpuSupported = false,
+        .cpuMinIntervalMillis = 0,
+        .gpuMinIntervalMillis = 0,
+    };
+
+    return out;
+}
+
+bool SupportManager::modeSupported(Mode type) {
+    auto it = kModeEarliestVersionMap.find(type);
+    if (it == kModeEarliestVersionMap.end() || IPower::version < it->second) {
+        return false;
+    }
+    bool supported = HintManager::GetInstance()->IsHintSupported(toString(type));
+    // LOW_POWER handled insides PowerHAL specifically
+    if (type == Mode::LOW_POWER) {
+        return true;
+    }
+    if (!supported && HintManager::GetInstance()->IsAdpfProfileSupported(toString(type))) {
+        return true;
+    }
+    return supported;
+}
+
+bool SupportManager::boostSupported(Boost type) {
+    auto it = kBoostEarliestVersionMap.find(type);
+    if (it == kBoostEarliestVersionMap.end() || IPower::version < it->second) {
+        return false;
+    }
+    bool supported = HintManager::GetInstance()->IsHintSupported(toString(type));
+    if (!supported && HintManager::GetInstance()->IsAdpfProfileSupported(toString(type))) {
+        return true;
+    }
+    return supported;
+}
+
+bool SupportManager::sessionHintSupported(SessionHint type) {
+    auto it = kSessionHintEarliestVersionMap.find(type);
+    if (it == kSessionHintEarliestVersionMap.end() || IPower::version < it->second) {
+        return false;
+    }
+    switch (type) {
+        case SessionHint::POWER_EFFICIENCY:
+            return false;
+        default:
+            return true;
+    }
+}
+
+bool SupportManager::sessionModeSupported(SessionMode type) {
+    auto it = kSessionModeEarliestVersionMap.find(type);
+    if (it == kSessionModeEarliestVersionMap.end() || IPower::version < it->second) {
+        return false;
+    }
+    switch (type) {
+        case SessionMode::POWER_EFFICIENCY:
+            return false;
+        case SessionMode::GRAPHICS_PIPELINE:
+            return false;
+        default:
+            return true;
+    }
+}
+
+bool SupportManager::sessionTagSupported(SessionTag type) {
+    auto it = kSessionTagEarliestVersionMap.find(type);
+    if (it == kSessionTagEarliestVersionMap.end() || IPower::version < it->second) {
+        return false;
+    }
+    return true;
+}
+
+}  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/vibrator/drv2624/tests/utils.h b/power-libperfmgr/aidl/SupportManager.h
similarity index 50%
rename from vibrator/drv2624/tests/utils.h
rename to power-libperfmgr/aidl/SupportManager.h
index 766ac5cc..c89bba21 100644
--- a/vibrator/drv2624/tests/utils.h
+++ b/power-libperfmgr/aidl/SupportManager.h
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2019 The Android Open Source Project
+ * Copyright 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,15 +13,24 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-#ifndef ANDROID_HARDWARE_VIBRATOR_TEST_UTILS_H
-#define ANDROID_HARDWARE_VIBRATOR_TEST_UTILS_H
 
-#include <cmath>
+#pragma once
 
-#include "types.h"
+#include "AdpfTypes.h"
 
-static inline int32_t amplitudeToRtpInput(EffectAmplitude amplitude) {
-    return std::round(amplitude * 127);
-}
+namespace aidl::google::hardware::power::impl::pixel {
 
-#endif  // ANDROID_HARDWARE_VIBRATOR_TEST_UTILS_H
+class SupportManager {
+  public:
+    static SupportInfo makeSupportInfo();
+
+  private:
+    static bool getAdfpSupported();
+    static bool modeSupported(Mode);
+    static bool boostSupported(Boost);
+    static bool sessionModeSupported(SessionMode);
+    static bool sessionHintSupported(SessionHint);
+    static bool sessionTagSupported(SessionTag);
+};
+
+}  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/android.hardware.power-service.pixel.xml b/power-libperfmgr/aidl/android.hardware.power-service.pixel.xml
index 418fb83d..1bb73f30 100644
--- a/power-libperfmgr/aidl/android.hardware.power-service.pixel.xml
+++ b/power-libperfmgr/aidl/android.hardware.power-service.pixel.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.power</name>
-        <version>5</version>
+        <version>6</version>
         <fqname>IPower/default</fqname>
     </hal>
 </manifest>
diff --git a/power-libperfmgr/aidl/tests/ChannelGroupTest.cpp b/power-libperfmgr/aidl/tests/ChannelGroupTest.cpp
new file mode 100644
index 00000000..170f0373
--- /dev/null
+++ b/power-libperfmgr/aidl/tests/ChannelGroupTest.cpp
@@ -0,0 +1,264 @@
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
+#include <aidl/android/hardware/power/BnPower.h>
+#include <fmq/AidlMessageQueue.h>
+#include <fmq/EventFlag.h>
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+#include <future>
+
+#include "aidl/AdpfTypes.h"
+#include "aidl/ChannelGroup.h"
+#include "aidl/ChannelManager.h"
+#include "aidl/android/hardware/power/ChannelMessage.h"
+#include "aidl/android/hardware/power/WorkDurationFixedV1.h"
+#include "android/binder_auto_utils.h"
+#include "gmock/gmock.h"
+#include "mocks/MockPowerHintSession.h"
+#include "mocks/MockPowerSessionManager.h"
+
+namespace aidl::google::hardware::power::impl::pixel {
+
+using namespace std::chrono_literals;
+using namespace testing;
+using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
+using ::android::AidlMessageQueue;
+using ::android::hardware::EventFlag;
+using android::hardware::power::ChannelMessage;
+
+using SessionMessageQueue = AidlMessageQueue<ChannelMessage, SynchronizedReadWrite>;
+using FlagMessageQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;
+
+constexpr int kChannelId = 1;
+
+class ChannelGroupTest : public Test {
+  public:
+    virtual void SetUp() {
+        mManager = NiceMock<mock::pixel::MockPowerSessionManager>::getInstance();
+        Mock::VerifyAndClear(mManager);
+    }
+
+  protected:
+    NiceMock<mock::pixel::MockPowerSessionManager> *mManager;
+    ChannelGroup<NiceMock<mock::pixel::MockPowerSessionManager>,
+                 NiceMock<mock::pixel::MockPowerHintSession>>
+            mChannelGroup{1};
+};
+
+class FMQTest : public ChannelGroupTest {
+  public:
+    void SetUp() override {
+        ChannelGroupTest::SetUp();
+        std::optional<FlagQueueDesc> flagDesc;
+        mChannelGroup.getFlagDesc(&flagDesc);
+        mBackendChannel = mChannelGroup.createChannel(mTestTgid, mTestUid);
+        ChannelQueueDesc channelDesc;
+        mBackendChannel->getDesc(&channelDesc);
+        mChannel = std::make_shared<SessionMessageQueue>(channelDesc, true);
+        mReadFlag = mBackendChannel->getReadBitmask();
+        mWriteFlag = mBackendChannel->getWriteBitmask();
+        ASSERT_TRUE(mChannel->isValid());
+
+        if (flagDesc.has_value()) {
+            mFlagChannel = std::make_shared<FlagMessageQueue>(*flagDesc, true);
+            ASSERT_EQ(EventFlag::createEventFlag(mFlagChannel->getEventFlagWord(), &mEventFlag),
+                      ::android::OK);
+        } else {
+            ASSERT_EQ(EventFlag::createEventFlag(mChannel->getEventFlagWord(), &mEventFlag),
+                      ::android::OK);
+        }
+
+        ASSERT_NE(mEventFlag, nullptr);
+
+        mMockPowerHintSession = std::make_shared<NiceMock<mock::pixel::MockPowerHintSession>>();
+        ON_CALL(*mMockPowerHintSession, getSessionConfig)
+                .WillByDefault(DoAll(SetArgPointee<0>(SessionConfig{.id = mSessionId}),
+                                     Return(ByMove(ndk::ScopedAStatus::ok()))));
+
+        ON_CALL(*mManager, getSession(Eq(mSessionId))).WillByDefault(Return(mMockPowerHintSession));
+    }
+    void TearDown() {}
+
+  protected:
+    int mTestTgid = 123;
+    int mTestUid = 234;
+    int mSessionId = 4;
+    uint32_t mReadFlag;
+    uint32_t mWriteFlag;
+    std::shared_ptr<IPowerHintSession> mSession;
+    std::shared_ptr<SessionMessageQueue> mChannel;
+    std::shared_ptr<FlagMessageQueue> mFlagChannel;
+    std::shared_ptr<SessionChannel> mBackendChannel;
+    ::android::hardware::EventFlag *mEventFlag;
+    // SessionConfig mSessionConfig{.id=mSessionId};
+    std::shared_ptr<NiceMock<mock::pixel::MockPowerHintSession>> mMockPowerHintSession;
+};
+
+bool WorkDurationsAreSame(WorkDuration a, WorkDuration b) {
+    return a.timeStampNanos == b.timeStampNanos && a.cpuDurationNanos,
+           b.cpuDurationNanos && a.gpuDurationNanos == b.gpuDurationNanos &&
+                   a.workPeriodStartTimestampNanos == b.workPeriodStartTimestampNanos &&
+                   a.durationNanos == b.durationNanos;
+}
+
+TEST_F(ChannelGroupTest, testCreateAndDestroyChannelGroup) {}
+
+TEST_F(ChannelGroupTest, testCreateChannel) {
+    int tgid = 234;
+    int uid = 123;
+    int count1 = mChannelGroup.getChannelCount();
+    auto out = mChannelGroup.createChannel(tgid, uid);
+
+    EXPECT_EQ(mChannelGroup.getChannelCount(), count1 + 1);
+    EXPECT_EQ(out->getUid(), uid);
+    EXPECT_EQ(out->getTgid(), tgid);
+}
+
+TEST_F(ChannelGroupTest, testGetChannel) {
+    int tgid = 234;
+    int uid = 123;
+    int count1 = mChannelGroup.getChannelCount();
+    auto out1 = mChannelGroup.createChannel(tgid, uid);
+    auto out2 = mChannelGroup.getChannel(
+            ChannelManager<>::ChannelMapValue{.value = out1->getId()}.offset);
+
+    EXPECT_EQ(mChannelGroup.getChannelCount(), count1 + 1);
+    EXPECT_EQ(out1->getId(), out2->getId());
+    EXPECT_EQ(out1->getTgid(), out2->getTgid());
+    EXPECT_EQ(out1->getId(), out2->getId());
+}
+
+TEST_F(ChannelGroupTest, testRemoveChannel) {
+    int tgid = 234;
+    int uid = 123;
+    int count1 = mChannelGroup.getChannelCount();
+    auto out1 = mChannelGroup.createChannel(tgid, uid);
+
+    EXPECT_EQ(mChannelGroup.getChannelCount(), count1 + 1);
+
+    mChannelGroup.removeChannel(ChannelManager<>::ChannelMapValue{.value = out1->getId()}.offset);
+
+    EXPECT_EQ(mChannelGroup.getChannelCount(), count1);
+}
+
+TEST_F(ChannelGroupTest, testGetFlagDesc) {
+    std::optional<FlagQueueDesc> desc;
+    mChannelGroup.getFlagDesc(&desc);
+
+    EXPECT_EQ(desc.has_value(), true);
+}
+
+TEST_F(FMQTest, testSendingHint) {
+    std::promise<SessionHint> sentHint;
+    EXPECT_CALL(*mMockPowerHintSession, sendHint).Times(1).WillOnce([&](SessionHint hint) {
+        sentHint.set_value(hint);
+        return ndk::ScopedAStatus::ok();
+    });
+
+    ChannelMessage in{.timeStampNanos = 1L,
+                      .sessionID = mSessionId,
+                      .data = ChannelMessage::ChannelMessageContents::make<
+                              ChannelMessage::ChannelMessageContents::Tag::hint>(
+                              SessionHint::GPU_LOAD_RESET)};
+    mChannel->writeBlocking(&in, 1, mReadFlag, mWriteFlag, 0, mEventFlag);
+
+    auto future = sentHint.get_future();
+    auto status = future.wait_for(1s);
+    EXPECT_EQ(status, std::future_status::ready);
+    SessionHint out = future.get();
+
+    EXPECT_EQ(out, SessionHint::GPU_LOAD_RESET);
+}
+
+ChannelMessage fromWorkDuration(WorkDuration in, int32_t sessionId) {
+    return ChannelMessage{
+            .timeStampNanos = in.timeStampNanos,
+            .sessionID = sessionId,
+            .data = ChannelMessage::ChannelMessageContents::make<
+                    ChannelMessage::ChannelMessageContents::Tag::workDuration>(WorkDurationFixedV1{
+                    .durationNanos = in.durationNanos,
+                    .workPeriodStartTimestampNanos = in.workPeriodStartTimestampNanos,
+                    .cpuDurationNanos = in.cpuDurationNanos,
+                    .gpuDurationNanos = in.gpuDurationNanos})};
+}
+
+TEST_F(FMQTest, testSendingReportActualMessage) {
+    std::promise<WorkDuration> reportedDuration;
+    EXPECT_CALL(*mMockPowerHintSession, reportActualWorkDuration)
+            .Times(1)
+            .WillOnce([&](const std::vector<WorkDuration> &actualDurations) {
+                reportedDuration.set_value(actualDurations[0]);
+                return ndk::ScopedAStatus::ok();
+            });
+
+    WorkDuration expected{.timeStampNanos = 1L,
+                          .durationNanos = 5L,
+                          .workPeriodStartTimestampNanos = 3L,
+                          .cpuDurationNanos = 4L,
+                          .gpuDurationNanos = 5L};
+
+    ChannelMessage in = fromWorkDuration(expected, mSessionId);
+
+    mChannel->writeBlocking(&in, 1, mReadFlag, mWriteFlag, 0, mEventFlag);
+
+    auto future = reportedDuration.get_future();
+    auto status = future.wait_for(1s);
+    EXPECT_EQ(status, std::future_status::ready);
+    WorkDuration out = future.get();
+
+    EXPECT_EQ(WorkDurationsAreSame(expected, out), true);
+}
+
+TEST_F(FMQTest, testSendingManyReportActualMessages) {
+    std::promise<std::vector<WorkDuration>> reportedDurations;
+    EXPECT_CALL(*mMockPowerHintSession, reportActualWorkDuration)
+            .Times(1)
+            .WillOnce([&](const std::vector<WorkDuration> &actualDurations) {
+                reportedDurations.set_value(actualDurations);
+                return ndk::ScopedAStatus::ok();
+            });
+
+    WorkDuration expectedBase{.timeStampNanos = 10L,
+                              .durationNanos = 50L,
+                              .workPeriodStartTimestampNanos = 30L,
+                              .cpuDurationNanos = 40L,
+                              .gpuDurationNanos = 50L};
+
+    std::vector<WorkDuration> in;
+    std::vector<ChannelMessage> messagesIn;
+    for (int i = 0; i < 20; i++) {
+        in.emplace_back(expectedBase.timeStampNanos + i, expectedBase.durationNanos + i,
+                        expectedBase.workPeriodStartTimestampNanos + i,
+                        expectedBase.cpuDurationNanos + i, expectedBase.gpuDurationNanos + i);
+        messagesIn.emplace_back(fromWorkDuration(in[i], mSessionId));
+    }
+
+    mChannel->writeBlocking(messagesIn.data(), 20, mReadFlag, mWriteFlag, 0, mEventFlag);
+
+    auto future = reportedDurations.get_future();
+    auto status = future.wait_for(1s);
+    EXPECT_EQ(status, std::future_status::ready);
+    std::vector<WorkDuration> out = future.get();
+    EXPECT_EQ(out.size(), 20);
+
+    for (int i = 0; i < 20; i++) {
+        EXPECT_EQ(WorkDurationsAreSame(in[i], out[i]), true);
+    }
+}
+
+}  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/tests/ChannelManagerTest.cpp b/power-libperfmgr/aidl/tests/ChannelManagerTest.cpp
new file mode 100644
index 00000000..273a861f
--- /dev/null
+++ b/power-libperfmgr/aidl/tests/ChannelManagerTest.cpp
@@ -0,0 +1,117 @@
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
+#include <aidl/android/hardware/power/BnPower.h>
+#include <fmq/AidlMessageQueue.h>
+#include <fmq/EventFlag.h>
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+#include "aidl/ChannelManager.h"
+#include "mocks/MockPowerHintSession.h"
+#include "mocks/MockPowerSessionManager.h"
+
+namespace aidl::google::hardware::power::impl::pixel {
+
+using namespace std::chrono_literals;
+using namespace testing;
+using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
+using ::android::AidlMessageQueue;
+using android::hardware::power::ChannelMessage;
+
+using SessionMessageQueue = AidlMessageQueue<ChannelMessage, SynchronizedReadWrite>;
+using FlagMessageQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;
+
+class ChannelManagerTest : public Test {
+  public:
+    virtual void SetUp() {
+        mChannelManager = ChannelManager<
+                ChannelGroup<testing::NiceMock<mock::pixel::MockPowerSessionManager>,
+                             testing::NiceMock<mock::pixel::MockPowerHintSession>>>::getInstance();
+    }
+
+  protected:
+    ChannelManager<ChannelGroup<testing::NiceMock<mock::pixel::MockPowerSessionManager>,
+                                testing::NiceMock<mock::pixel::MockPowerHintSession>>>
+            *mChannelManager;
+};
+
+TEST_F(ChannelManagerTest, testGetChannelConfig) {
+    int kUid = 3000;
+    int kTgid = 4000;
+    ChannelConfig config;
+    auto out = mChannelManager->getChannelConfig(kUid, kTgid, &config);
+    ASSERT_EQ(out, true);
+}
+
+TEST_F(ChannelManagerTest, testCloseChannel) {
+    int kUid = 3000;
+    int kTgid = 4000;
+    ChannelConfig config;
+    mChannelManager->getChannelConfig(kUid, kTgid, &config);
+    bool success = mChannelManager->closeChannel(kUid, kTgid);
+    ASSERT_EQ(success, true);
+}
+
+TEST_F(ChannelManagerTest, testManyChannelsSpawnMoreGroups) {
+    int kUid = 3000;
+    int kTgid = 4000;
+    int kChannelsToSpawn = 40;
+    ChannelConfig config;
+    // Spawn first one separately to make sure the group is created
+    mChannelManager->getChannelConfig(kUid, kTgid, &config);
+    ASSERT_EQ(mChannelManager->getChannelCount(), 1);
+    ASSERT_EQ(mChannelManager->getGroupCount(), 1);
+    for (int i = 1; i < kChannelsToSpawn; ++i) {
+        mChannelManager->getChannelConfig(kUid + i, kTgid + i, &config);
+    }
+    ASSERT_GT(mChannelManager->getGroupCount(), 1);
+    ASSERT_EQ(mChannelManager->getChannelCount(), kChannelsToSpawn);
+}
+
+TEST_F(ChannelManagerTest, testNewChannelsReplaceOldChannels) {
+    int kUid = 3000;
+    int kTgid = 4000;
+    int kChannelsToSpawn = 40;
+    ChannelConfig config;
+    // Spawn first one separately to make sure the group isn't destroyed later
+    mChannelManager->getChannelConfig(kUid, kTgid, &config);
+    for (int i = 1; i < kChannelsToSpawn; ++i) {
+        mChannelManager->getChannelConfig(kUid + i, kTgid + i, &config);
+        mChannelManager->closeChannel(kUid + i, kTgid + i);
+    }
+    ASSERT_EQ(mChannelManager->getGroupCount(), 1);
+    ASSERT_EQ(mChannelManager->getChannelCount(), 1);
+}
+
+TEST_F(ChannelManagerTest, testGroupsCloseOnLastChannelDies) {
+    int kUid = 3000;
+    int kTgid = 4000;
+    int kChannelsToSpawn = 40;
+    ChannelConfig config;
+    for (int i = 0; i < kChannelsToSpawn; ++i) {
+        mChannelManager->getChannelConfig(kUid + i, kTgid + i, &config);
+    }
+    ASSERT_GT(mChannelManager->getGroupCount(), 0);
+    ASSERT_EQ(mChannelManager->getChannelCount(), 40);
+    for (int i = 0; i < kChannelsToSpawn; ++i) {
+        mChannelManager->closeChannel(kUid + i, kTgid + i);
+    }
+    ASSERT_EQ(mChannelManager->getGroupCount(), 0);
+    ASSERT_EQ(mChannelManager->getChannelCount(), 0);
+}
+
+}  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp b/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp
index 8e32ad98..a976a494 100644
--- a/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp
+++ b/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp
@@ -21,6 +21,7 @@
 #include <sys/syscall.h>
 
 #include <chrono>
+#include <iostream>
 #include <mutex>
 #include <thread>
 #include <unordered_map>
@@ -158,19 +159,19 @@ class PowerHintSessionTest : public ::testing::Test {
 
         // Extract our sched dump entry.
         std::string threadEntry = schedDump.substr(pid_position, entry_end_position - pid_position);
-        if (threadEntry.size() < 3) {
-            std::cerr << "Error: sched dump entry invalid." << std::endl;
-            return false;
-        }
 
-        // We do reverse array access since the first entries have variable length.
-        char powerSessionActiveFlag = threadEntry[threadEntry.size() - 3];
-        if (powerSessionActiveFlag == '1') {
-            *isActive = true;
+        std::istringstream thread_dump_info(threadEntry);
+        std::vector<std::string> thread_vendor_attrs;
+        std::string attr;
+        while (thread_dump_info >> attr) {
+            thread_vendor_attrs.push_back(attr);
         }
 
-        // At this point, we have found a valid entry with SessionAllowed == bool, so we return
-        // success status.
+        const int32_t tag_word_pos = 10;  // The adpf attribute position in dump log.
+        if (thread_vendor_attrs.size() < tag_word_pos + 1) {
+            return false;
+        }
+        *isActive = thread_vendor_attrs[tag_word_pos] == "1";
         return true;
     }
 };
diff --git a/power-libperfmgr/aidl/tests/SessionRecordsTest.cpp b/power-libperfmgr/aidl/tests/SessionRecordsTest.cpp
index 49f6c64e..4c7666e9 100644
--- a/power-libperfmgr/aidl/tests/SessionRecordsTest.cpp
+++ b/power-libperfmgr/aidl/tests/SessionRecordsTest.cpp
@@ -67,21 +67,23 @@ TEST_F(SessionRecordsTest, NoRecords) {
 }
 
 TEST_F(SessionRecordsTest, addReportedDurations) {
-    mRecords->addReportedDurations(fakeWorkDurations({3, 4, 3, 2}), MS_TO_NS(3));
+    FrameBuckets buckets;
+    mRecords->addReportedDurations(fakeWorkDurations({3, 4, 3, 2}), MS_TO_NS(3), buckets);
     ASSERT_EQ(4, mRecords->getNumOfRecords());
     ASSERT_EQ(MS_TO_US(4), mRecords->getMaxDuration().value());
     ASSERT_EQ(MS_TO_US(3), mRecords->getAvgDuration().value());
     ASSERT_EQ(0, mRecords->getNumOfMissedCycles());
 
     // Push more records to override part of the old ones in the ring buffer
-    mRecords->addReportedDurations(fakeWorkDurations({2, 1, 2}), MS_TO_NS(3));
+    mRecords->addReportedDurations(fakeWorkDurations({2, 1, 2}), MS_TO_NS(3), buckets);
     ASSERT_EQ(5, mRecords->getNumOfRecords());
     ASSERT_EQ(MS_TO_US(3), mRecords->getMaxDuration().value());
     ASSERT_EQ(MS_TO_US(2), mRecords->getAvgDuration().value());
     ASSERT_EQ(0, mRecords->getNumOfMissedCycles());
 
     // More records to override the ring buffer more rounds
-    mRecords->addReportedDurations(fakeWorkDurations({10, 2, 9, 8, 4, 5, 7, 6}), MS_TO_NS(3));
+    mRecords->addReportedDurations(fakeWorkDurations({10, 2, 9, 8, 4, 5, 7, 6}), MS_TO_NS(3),
+                                   buckets);
     ASSERT_EQ(5, mRecords->getNumOfRecords());
     ASSERT_EQ(MS_TO_US(8), mRecords->getMaxDuration().value());
     ASSERT_EQ(MS_TO_US(6), mRecords->getAvgDuration().value());
@@ -89,25 +91,115 @@ TEST_F(SessionRecordsTest, addReportedDurations) {
 }
 
 TEST_F(SessionRecordsTest, checkLowFrameRate) {
+    FrameBuckets buckets;
     ASSERT_FALSE(mRecords->isLowFrameRate(25));
     mRecords->addReportedDurations(fakeWorkDurations({{0, 8}, {10, 9}, {20, 8}, {30, 8}}),
-                                   MS_TO_NS(10));
+                                   MS_TO_NS(10), buckets);
     ASSERT_EQ(4, mRecords->getNumOfRecords());
     ASSERT_FALSE(mRecords->isLowFrameRate(25));
 
-    mRecords->addReportedDurations(fakeWorkDurations({{130, 8}, {230, 9}}), MS_TO_NS(10));
+    mRecords->addReportedDurations(fakeWorkDurations({{130, 8}, {230, 9}}), MS_TO_NS(10), buckets);
     ASSERT_EQ(5, mRecords->getNumOfRecords());
     ASSERT_FALSE(mRecords->isLowFrameRate(25));
 
-    mRecords->addReportedDurations(fakeWorkDurations({{330, 8}, {430, 9}}), MS_TO_NS(10));
+    mRecords->addReportedDurations(fakeWorkDurations({{330, 8}, {430, 9}}), MS_TO_NS(10), buckets);
     ASSERT_EQ(5, mRecords->getNumOfRecords());
     ASSERT_TRUE(mRecords->isLowFrameRate(25));
 
-    mRecords->addReportedDurations(fakeWorkDurations({{440, 8}, {450, 9}}), MS_TO_NS(10));
+    mRecords->addReportedDurations(fakeWorkDurations({{440, 8}, {450, 9}}), MS_TO_NS(10), buckets);
     ASSERT_EQ(5, mRecords->getNumOfRecords());
     ASSERT_FALSE(mRecords->isLowFrameRate(25));
 }
 
+TEST_F(SessionRecordsTest, switchTargetDuration) {
+    FrameBuckets buckets;
+    ASSERT_FALSE(mRecords->isLowFrameRate(25));
+    mRecords->addReportedDurations(fakeWorkDurations({{0, 8}, {10, 9}, {20, 19}, {40, 8}}),
+                                   MS_TO_NS(10), buckets);
+    ASSERT_EQ(4, mRecords->getNumOfRecords());
+    ASSERT_EQ(MS_TO_US(19), mRecords->getMaxDuration().value());
+    ASSERT_EQ(MS_TO_US(11), mRecords->getAvgDuration().value());
+    ASSERT_EQ(1, mRecords->getNumOfMissedCycles());
+
+    // Change the target duration. It will reset all the old record states.
+    mRecords->resetRecords();
+    ASSERT_EQ(0, mRecords->getNumOfRecords());
+    ASSERT_FALSE(mRecords->getMaxDuration().has_value());
+    ASSERT_FALSE(mRecords->getAvgDuration().has_value());
+    ASSERT_EQ(0, mRecords->getNumOfMissedCycles());
+    ASSERT_FALSE(mRecords->isLowFrameRate(25));
+
+    mRecords->addReportedDurations(fakeWorkDurations({{50, 14}, {70, 16}}), MS_TO_NS(20), buckets);
+    ASSERT_EQ(2, mRecords->getNumOfRecords());
+    ASSERT_EQ(MS_TO_US(16), mRecords->getMaxDuration().value());
+    ASSERT_EQ(MS_TO_US(15), mRecords->getAvgDuration().value());
+    ASSERT_EQ(0, mRecords->getNumOfMissedCycles());
+    ASSERT_FALSE(mRecords->isLowFrameRate(25));
+}
+
+TEST_F(SessionRecordsTest, checkFPSJitters) {
+    FrameBuckets buckets;
+    ASSERT_EQ(0, mRecords->getNumOfFPSJitters());
+    mRecords->addReportedDurations(fakeWorkDurations({{0, 8}, {10, 9}, {20, 8}, {30, 8}}),
+                                   MS_TO_NS(10), buckets, true);
+    ASSERT_EQ(0, mRecords->getNumOfFPSJitters());
+    ASSERT_EQ(100, mRecords->getLatestFPS());
+
+    mRecords->addReportedDurations(fakeWorkDurations({{40, 22}, {80, 8}}), MS_TO_NS(10), buckets,
+                                   true);
+    ASSERT_EQ(1, mRecords->getNumOfFPSJitters());
+    ASSERT_EQ(50, mRecords->getLatestFPS());
+    mRecords->addReportedDurations(fakeWorkDurations({{90, 8}, {100, 8}, {110, 7}}), MS_TO_NS(10),
+                                   buckets, true);
+    ASSERT_EQ(1, mRecords->getNumOfFPSJitters());
+
+    // Push more records to override part of the old ones in the ring buffer
+    mRecords->addReportedDurations(fakeWorkDurations({{120, 22}, {150, 8}}), MS_TO_NS(10), buckets,
+                                   true);
+    ASSERT_EQ(1, mRecords->getNumOfFPSJitters());
+
+    // Cancel the new FPS Jitter evaluation for the new records report.
+    mRecords->addReportedDurations(fakeWorkDurations({{160, 8}, {170, 8}}), MS_TO_NS(10), buckets);
+    ASSERT_EQ(1, mRecords->getNumOfFPSJitters());
+    ASSERT_EQ(0, mRecords->getLatestFPS());
+
+    // All the old FPS Jitters stored in the records buffer got overrode by new records.
+    mRecords->addReportedDurations(fakeWorkDurations({{190, 8}, {230, 8}, {300, 8}}), MS_TO_NS(10),
+                                   buckets);
+    ASSERT_EQ(0, mRecords->getNumOfFPSJitters());
+    ASSERT_EQ(0, mRecords->getLatestFPS());
+}
+
+TEST_F(SessionRecordsTest, updateFrameBuckets) {
+    FrameBuckets buckets;
+
+    mRecords->addReportedDurations(fakeWorkDurations({10, 11, 16, 17, 26, 40}), MS_TO_NS(10),
+                                   buckets);
+    ASSERT_EQ(6, buckets.totalNumOfFrames);
+    ASSERT_EQ(1, buckets.numOfFrames17to25ms);
+    ASSERT_EQ(1, buckets.numOfFrames25to34ms);
+    ASSERT_EQ(1, buckets.numOfFrames34to67ms);
+    ASSERT_EQ(0, buckets.numOfFrames67to100ms);
+    ASSERT_EQ(0, buckets.numOfFramesOver100ms);
+
+    mRecords->addReportedDurations(fakeWorkDurations({80, 100}), MS_TO_NS(10), buckets);
+    ASSERT_EQ(8, buckets.totalNumOfFrames);
+    ASSERT_EQ(1, buckets.numOfFrames17to25ms);
+    ASSERT_EQ(1, buckets.numOfFrames25to34ms);
+    ASSERT_EQ(1, buckets.numOfFrames34to67ms);
+    ASSERT_EQ(1, buckets.numOfFrames67to100ms);
+    ASSERT_EQ(1, buckets.numOfFramesOver100ms);
+
+    FrameBuckets newBuckets{2, 1, 1, 1, 1, 0};
+    buckets.addUpNewFrames(newBuckets);
+    ASSERT_EQ(10, buckets.totalNumOfFrames);
+    ASSERT_EQ(2, buckets.numOfFrames17to25ms);
+    ASSERT_EQ(2, buckets.numOfFrames25to34ms);
+    ASSERT_EQ(2, buckets.numOfFrames34to67ms);
+    ASSERT_EQ(2, buckets.numOfFrames67to100ms);
+    ASSERT_EQ(1, buckets.numOfFramesOver100ms);
+}
+
 }  // namespace pixel
 }  // namespace impl
 }  // namespace power
diff --git a/power-libperfmgr/aidl/tests/mocks/MockChannelGroup.h b/power-libperfmgr/aidl/tests/mocks/MockChannelGroup.h
new file mode 100644
index 00000000..3c9d9b27
--- /dev/null
+++ b/power-libperfmgr/aidl/tests/mocks/MockChannelGroup.h
@@ -0,0 +1,39 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include <aidl/AdpfTypes.h>
+#include <aidl/SessionChannel.h>
+#include <gmock/gmock.h>
+
+namespace aidl::google::hardware::power::mock::pixel {
+
+class MockChannelGroup {
+  public:
+    ~MockChannelGroup() = default;
+    MockChannelGroup(size_t) {}
+
+    MOCK_METHOD(bool, removeChannel, (size_t channelId));
+    MOCK_METHOD(size_t, getChannelCount, (), (const));
+    MOCK_METHOD(std::shared_ptr<impl::pixel::SessionChannel>, createChannel,
+                (int32_t tgid, int32_t uid));
+    MOCK_METHOD(std::shared_ptr<impl::pixel::SessionChannel>, getChannel, (size_t channelId));
+    MOCK_METHOD(void, getFlagDesc, (std::optional<impl::pixel::FlagQueueDesc> * _return_desc),
+                (const));
+};
+
+}  // namespace aidl::google::hardware::power::mock::pixel
diff --git a/power-libperfmgr/aidl/tests/mocks/MockHintManager.h b/power-libperfmgr/aidl/tests/mocks/MockHintManager.h
index 3c6a2c4b..0427c547 100644
--- a/power-libperfmgr/aidl/tests/mocks/MockHintManager.h
+++ b/power-libperfmgr/aidl/tests/mocks/MockHintManager.h
@@ -42,6 +42,9 @@ class MockHintManager {
                 (const));
     MOCK_METHOD(void, DumpToFd, (int fd), ());
     MOCK_METHOD(bool, Start, (), ());
+    MOCK_METHOD(bool, SetAdpfProfileFromDoHint, (const std::string &profile_name), ());
+    MOCK_METHOD(std::shared_ptr<::android::perfmgr::AdpfConfig>, GetAdpfProfileFromDoHint, (),
+                (const));
 
     static testing::NiceMock<MockHintManager> *GetInstance() {
         static testing::NiceMock<MockHintManager> instance{};
diff --git a/power-libperfmgr/aidl/tests/mocks/MockPowerHintSession.h b/power-libperfmgr/aidl/tests/mocks/MockPowerHintSession.h
index 7c070e8d..f6492f19 100644
--- a/power-libperfmgr/aidl/tests/mocks/MockPowerHintSession.h
+++ b/power-libperfmgr/aidl/tests/mocks/MockPowerHintSession.h
@@ -44,19 +44,6 @@ class MockPowerHintSession {
     MOCK_METHOD(bool, isModeSet, (android::hardware::power::SessionMode mode), (const));
     MOCK_METHOD(void, dumpToStream, (std::ostream & stream));
     MOCK_METHOD(android::hardware::power::SessionTag, getSessionTag, (), (const));
-
-    class MockSessionTracker {
-      public:
-        MOCK_METHOD(void, registerSession,
-                    (std::shared_ptr<MockPowerHintSession> & session, int64_t sessionId));
-        MOCK_METHOD(void, unregisterSession, (int64_t sessionId));
-        MOCK_METHOD(std::shared_ptr<MockPowerHintSession>, getSession, (int64_t sessionId));
-    };
-
-    static testing::NiceMock<MockSessionTracker> *getTracker() {
-        static testing::NiceMock<MockSessionTracker> instance{};
-        return &instance;
-    }
 };
 
 }  // namespace aidl::google::hardware::power::mock::pixel
diff --git a/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h b/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
index 30926118..5b0bf545 100644
--- a/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
+++ b/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
@@ -20,6 +20,7 @@
 #include <aidl/AppDescriptorTrace.h>
 #include <aidl/AppHintDesc.h>
 #include <aidl/PhysicalQuantityTypes.h>
+#include <aidl/SessionMetrics.h>
 #include <gmock/gmock.h>
 
 namespace aidl::google::hardware::power::mock::pixel {
@@ -36,11 +37,14 @@ class MockPowerSessionManager {
                 (const std::string &idString,
                  const std::shared_ptr<impl::pixel::AppHintDesc> &sessionDescriptor,
                  const std::shared_ptr<impl::pixel::AppDescriptorTrace> &sessionTrace,
-                 const std::vector<int32_t> &threadIds),
+                 const std::vector<int32_t> &threadIds, const impl::pixel::ProcessTag procTag),
                 ());
-    MOCK_METHOD(void, removePowerSession, (int64_t sessionId), ());
+    MOCK_METHOD(void, removePowerSession,
+                (int64_t sessionId, const impl::pixel::ProcessTag procTag), ());
     MOCK_METHOD(void, setThreadsFromPowerSession,
-                (int64_t sessionId, const std::vector<int32_t> &threadIds), ());
+                (int64_t sessionId, const std::vector<int32_t> &threadIds,
+                 const impl::pixel::ProcessTag procTag),
+                ());
     MOCK_METHOD(void, pause, (int64_t sessionId), ());
     MOCK_METHOD(void, resume, (int64_t sessionId), ());
     MOCK_METHOD(void, updateUniversalBoostMode, (), ());
@@ -71,6 +75,9 @@ class MockPowerSessionManager {
     MOCK_METHOD(void, updateHboostStatistics,
                 (int64_t sessionId, impl::pixel::SessionJankyLevel jankyLevel, int32_t numOfFrames),
                 ());
+    MOCK_METHOD(bool, getGameModeEnableState, (), ());
+    MOCK_METHOD(void, updateFrameBuckets,
+                (int64_t sessionId, const impl::pixel::FrameBuckets &lastReportedFrames), ());
 
     static testing::NiceMock<MockPowerSessionManager> *getInstance() {
         static testing::NiceMock<MockPowerSessionManager> instance{};
diff --git a/power-libperfmgr/disp-power/DisplayLowPower.cpp b/power-libperfmgr/disp-power/DisplayLowPower.cpp
index 81744be0..f2da5746 100644
--- a/power-libperfmgr/disp-power/DisplayLowPower.cpp
+++ b/power-libperfmgr/disp-power/DisplayLowPower.cpp
@@ -31,7 +31,7 @@ namespace power {
 namespace impl {
 namespace pixel {
 
-DisplayLowPower::DisplayLowPower() : mFossStatus(false), mAAModeOn(false) {}
+DisplayLowPower::DisplayLowPower() : mFossStatus(false) {}
 
 void DisplayLowPower::Init() {
     ConnectPpsDaemon();
@@ -79,13 +79,6 @@ void DisplayLowPower::SetFoss(bool enable) {
     }
 }
 
-void DisplayLowPower::SetAAMode(bool enable) {
-    mAAModeOn = enable;
-}
-bool DisplayLowPower::IsAAModeOn() {
-  return mAAModeOn;
-}
-
 }  // namespace pixel
 }  // namespace impl
 }  // namespace power
diff --git a/power-libperfmgr/disp-power/DisplayLowPower.h b/power-libperfmgr/disp-power/DisplayLowPower.h
index 64a7dcfe..53eb6c99 100644
--- a/power-libperfmgr/disp-power/DisplayLowPower.h
+++ b/power-libperfmgr/disp-power/DisplayLowPower.h
@@ -33,8 +33,6 @@ class DisplayLowPower {
     ~DisplayLowPower() {}
     void Init();
     void SetDisplayLowPower(bool enable);
-    void SetAAMode(bool enable);
-    bool IsAAModeOn();
 
   private:
     void ConnectPpsDaemon();
@@ -43,7 +41,6 @@ class DisplayLowPower {
 
     ::android::base::unique_fd mPpsSocket;
     bool mFossStatus;
-    std::atomic<bool> mAAModeOn;
 };
 
 }  // namespace pixel
diff --git a/power-libperfmgr/libperfmgr/Android.bp b/power-libperfmgr/libperfmgr/Android.bp
index fe6b6951..7059320e 100644
--- a/power-libperfmgr/libperfmgr/Android.bp
+++ b/power-libperfmgr/libperfmgr/Android.bp
@@ -60,13 +60,16 @@ cc_library {
         "HintManager.cc",
         "AdpfConfig.cc",
         "EventNode.cc",
-    ]
+    ],
 }
 
 cc_test {
     name: "libperfmgr_test",
     defaults: ["libperfmgr_defaults"],
-    static_libs: ["libperfmgr", "libgmock" ],
+    static_libs: [
+        "libperfmgr",
+        "libgmock",
+    ],
     srcs: [
         "tests/RequestGroupTest.cc",
         "tests/FileNodeTest.cc",
@@ -75,7 +78,10 @@ cc_test {
         "tests/HintManagerTest.cc",
         "tests/EventNodeTest.cc",
     ],
-    test_suites: ["device-tests"],
+    test_suites: [
+        "device-tests",
+        "device-pixel-tests",
+    ],
     require_root: true,
 }
 
@@ -85,5 +91,5 @@ cc_binary {
     static_libs: ["libperfmgr"],
     srcs: [
         "tools/ConfigVerifier.cc",
-    ]
+    ],
 }
diff --git a/power-libperfmgr/libperfmgr/HintManager.cc b/power-libperfmgr/libperfmgr/HintManager.cc
index bc12cd94..1b20e718 100644
--- a/power-libperfmgr/libperfmgr/HintManager.cc
+++ b/power-libperfmgr/libperfmgr/HintManager.cc
@@ -268,14 +268,27 @@ void HintManager::DumpToFd(int fd) {
         LOG(ERROR) << "Failed to dump fd: " << fd;
     }
 
-    // Dump current ADPF profile
+    // Dump current ADPF profiles
     if (IsAdpfSupported()) {
         header = "========== ADPF Tag Profile begin ==========\n";
         if (!android::base::WriteStringToFd(header, fd)) {
             LOG(ERROR) << "Failed to dump fd: " << fd;
         }
-        // TODO(jimmyshiu@/guibing@): Update it when fully switched to the tag based adpf profiles.
+
+        header = "---- Default non-tagged adpf profile ----\n";
+        if (!android::base::WriteStringToFd(header, fd)) {
+            LOG(ERROR) << "Failed to dump fd: " << fd;
+        }
         GetAdpfProfileFromDoHint()->dumpToFd(fd);
+
+        for (const auto &tag_profile : tag_profile_map_) {
+            header = StringPrintf("---- Tagged ADPF Profile: %s ----\n", tag_profile.first.c_str());
+            if (!android::base::WriteStringToFd(header, fd)) {
+                LOG(ERROR) << "Failed to dump fd: " << fd;
+            }
+            tag_profile.second->dumpToFd(fd);
+        }
+
         footer = "========== ADPF Tag Profile end ==========\n";
         if (!android::base::WriteStringToFd(footer, fd)) {
             LOG(ERROR) << "Failed to dump fd: " << fd;
diff --git a/power-libperfmgr/libperfmgr/TEST_MAPPING b/power-libperfmgr/libperfmgr/TEST_MAPPING
new file mode 100644
index 00000000..5e910d1c
--- /dev/null
+++ b/power-libperfmgr/libperfmgr/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "postsubmit": [
+    {
+      "name": "libperfmgr_test"
+    }
+  ]
+}
\ No newline at end of file
diff --git a/power-libperfmgr/tests/powerhint_config_field_names.txt b/power-libperfmgr/tests/powerhint_config_field_names.txt
new file mode 100644
index 00000000..2a3b3606
--- /dev/null
+++ b/power-libperfmgr/tests/powerhint_config_field_names.txt
@@ -0,0 +1,51 @@
+Actions
+AdpfConfig
+DefaultIndex
+Duration
+GpuBoost
+GpuCapacityBoostMax
+GpuSysfsPath
+HBoostModerateJankThreshold
+HBoostOffMaxAvgDurRatio
+HBoostSevereJankPidPu
+HBoostSevereJankThreshold
+HBoostUclampMinCeilingRange
+HBoostUclampMinFloorRange
+HeuristicBoost_On
+JankCheckTimeFactor
+LowFrameRateThreshold
+MaxRecordsNum
+Name
+Name
+Node
+Nodes
+Path
+PID_Do
+PID_Du
+PID_I
+PID_I_High
+PID_I_Init
+PID_I_Low
+PID_On
+PID_Po
+PID_Pu
+PowerHint
+ReportingRateLimitNs
+ResetOnInit
+SamplingWindow_D
+SamplingWindow_I
+SamplingWindow_P
+StaleTimeFactor
+TargetTimeFactor
+Type
+UclampMax_EfficientBase
+UclampMax_EfficientOffset
+UclampMin_High
+UclampMin_Init
+UclampMin_LoadReset
+UclampMin_LoadUp
+UclampMin_Low
+UclampMin_On
+Value
+Values
+WriteOnly
diff --git a/preupload_hooks/pixel_json_checker/OWNERS b/preupload_hooks/pixel_json_checker/OWNERS
new file mode 100644
index 00000000..d4a3b948
--- /dev/null
+++ b/preupload_hooks/pixel_json_checker/OWNERS
@@ -0,0 +1,7 @@
+wvw@google.com
+paillon@google.com
+jenhaochen@google.com
+liumartin@google.com
+sayanna@google.com
+kamewang@google.com
+jinpengsong@google.com
\ No newline at end of file
diff --git a/preupload_hooks/pixel_json_checker/gitlint/LICENSE b/preupload_hooks/pixel_json_checker/gitlint/LICENSE
new file mode 100644
index 00000000..d6456956
--- /dev/null
+++ b/preupload_hooks/pixel_json_checker/gitlint/LICENSE
@@ -0,0 +1,202 @@
+
+                                 Apache License
+                           Version 2.0, January 2004
+                        http://www.apache.org/licenses/
+
+   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
+
+   1. Definitions.
+
+      "License" shall mean the terms and conditions for use, reproduction,
+      and distribution as defined by Sections 1 through 9 of this document.
+
+      "Licensor" shall mean the copyright owner or entity authorized by
+      the copyright owner that is granting the License.
+
+      "Legal Entity" shall mean the union of the acting entity and all
+      other entities that control, are controlled by, or are under common
+      control with that entity. For the purposes of this definition,
+      "control" means (i) the power, direct or indirect, to cause the
+      direction or management of such entity, whether by contract or
+      otherwise, or (ii) ownership of fifty percent (50%) or more of the
+      outstanding shares, or (iii) beneficial ownership of such entity.
+
+      "You" (or "Your") shall mean an individual or Legal Entity
+      exercising permissions granted by this License.
+
+      "Source" form shall mean the preferred form for making modifications,
+      including but not limited to software source code, documentation
+      source, and configuration files.
+
+      "Object" form shall mean any form resulting from mechanical
+      transformation or translation of a Source form, including but
+      not limited to compiled object code, generated documentation,
+      and conversions to other media types.
+
+      "Work" shall mean the work of authorship, whether in Source or
+      Object form, made available under the License, as indicated by a
+      copyright notice that is included in or attached to the work
+      (an example is provided in the Appendix below).
+
+      "Derivative Works" shall mean any work, whether in Source or Object
+      form, that is based on (or derived from) the Work and for which the
+      editorial revisions, annotations, elaborations, or other modifications
+      represent, as a whole, an original work of authorship. For the purposes
+      of this License, Derivative Works shall not include works that remain
+      separable from, or merely link (or bind by name) to the interfaces of,
+      the Work and Derivative Works thereof.
+
+      "Contribution" shall mean any work of authorship, including
+      the original version of the Work and any modifications or additions
+      to that Work or Derivative Works thereof, that is intentionally
+      submitted to Licensor for inclusion in the Work by the copyright owner
+      or by an individual or Legal Entity authorized to submit on behalf of
+      the copyright owner. For the purposes of this definition, "submitted"
+      means any form of electronic, verbal, or written communication sent
+      to the Licensor or its representatives, including but not limited to
+      communication on electronic mailing lists, source code control systems,
+      and issue tracking systems that are managed by, or on behalf of, the
+      Licensor for the purpose of discussing and improving the Work, but
+      excluding communication that is conspicuously marked or otherwise
+      designated in writing by the copyright owner as "Not a Contribution."
+
+      "Contributor" shall mean Licensor and any individual or Legal Entity
+      on behalf of whom a Contribution has been received by Licensor and
+      subsequently incorporated within the Work.
+
+   2. Grant of Copyright License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      copyright license to reproduce, prepare Derivative Works of,
+      publicly display, publicly perform, sublicense, and distribute the
+      Work and such Derivative Works in Source or Object form.
+
+   3. Grant of Patent License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      (except as stated in this section) patent license to make, have made,
+      use, offer to sell, sell, import, and otherwise transfer the Work,
+      where such license applies only to those patent claims licensable
+      by such Contributor that are necessarily infringed by their
+      Contribution(s) alone or by combination of their Contribution(s)
+      with the Work to which such Contribution(s) was submitted. If You
+      institute patent litigation against any entity (including a
+      cross-claim or counterclaim in a lawsuit) alleging that the Work
+      or a Contribution incorporated within the Work constitutes direct
+      or contributory patent infringement, then any patent licenses
+      granted to You under this License for that Work shall terminate
+      as of the date such litigation is filed.
+
+   4. Redistribution. You may reproduce and distribute copies of the
+      Work or Derivative Works thereof in any medium, with or without
+      modifications, and in Source or Object form, provided that You
+      meet the following conditions:
+
+      (a) You must give any other recipients of the Work or
+          Derivative Works a copy of this License; and
+
+      (b) You must cause any modified files to carry prominent notices
+          stating that You changed the files; and
+
+      (c) You must retain, in the Source form of any Derivative Works
+          that You distribute, all copyright, patent, trademark, and
+          attribution notices from the Source form of the Work,
+          excluding those notices that do not pertain to any part of
+          the Derivative Works; and
+
+      (d) If the Work includes a "NOTICE" text file as part of its
+          distribution, then any Derivative Works that You distribute must
+          include a readable copy of the attribution notices contained
+          within such NOTICE file, excluding those notices that do not
+          pertain to any part of the Derivative Works, in at least one
+          of the following places: within a NOTICE text file distributed
+          as part of the Derivative Works; within the Source form or
+          documentation, if provided along with the Derivative Works; or,
+          within a display generated by the Derivative Works, if and
+          wherever such third-party notices normally appear. The contents
+          of the NOTICE file are for informational purposes only and
+          do not modify the License. You may add Your own attribution
+          notices within Derivative Works that You distribute, alongside
+          or as an addendum to the NOTICE text from the Work, provided
+          that such additional attribution notices cannot be construed
+          as modifying the License.
+
+      You may add Your own copyright statement to Your modifications and
+      may provide additional or different license terms and conditions
+      for use, reproduction, or distribution of Your modifications, or
+      for any such Derivative Works as a whole, provided Your use,
+      reproduction, and distribution of the Work otherwise complies with
+      the conditions stated in this License.
+
+   5. Submission of Contributions. Unless You explicitly state otherwise,
+      any Contribution intentionally submitted for inclusion in the Work
+      by You to the Licensor shall be under the terms and conditions of
+      this License, without any additional terms or conditions.
+      Notwithstanding the above, nothing herein shall supersede or modify
+      the terms of any separate license agreement you may have executed
+      with Licensor regarding such Contributions.
+
+   6. Trademarks. This License does not grant permission to use the trade
+      names, trademarks, service marks, or product names of the Licensor,
+      except as required for reasonable and customary use in describing the
+      origin of the Work and reproducing the content of the NOTICE file.
+
+   7. Disclaimer of Warranty. Unless required by applicable law or
+      agreed to in writing, Licensor provides the Work (and each
+      Contributor provides its Contributions) on an "AS IS" BASIS,
+      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
+      implied, including, without limitation, any warranties or conditions
+      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
+      PARTICULAR PURPOSE. You are solely responsible for determining the
+      appropriateness of using or redistributing the Work and assume any
+      risks associated with Your exercise of permissions under this License.
+
+   8. Limitation of Liability. In no event and under no legal theory,
+      whether in tort (including negligence), contract, or otherwise,
+      unless required by applicable law (such as deliberate and grossly
+      negligent acts) or agreed to in writing, shall any Contributor be
+      liable to You for damages, including any direct, indirect, special,
+      incidental, or consequential damages of any character arising as a
+      result of this License or out of the use or inability to use the
+      Work (including but not limited to damages for loss of goodwill,
+      work stoppage, computer failure or malfunction, or any and all
+      other commercial damages or losses), even if such Contributor
+      has been advised of the possibility of such damages.
+
+   9. Accepting Warranty or Additional Liability. While redistributing
+      the Work or Derivative Works thereof, You may choose to offer,
+      and charge a fee for, acceptance of support, warranty, indemnity,
+      or other liability obligations and/or rights consistent with this
+      License. However, in accepting such obligations, You may act only
+      on Your own behalf and on Your sole responsibility, not on behalf
+      of any other Contributor, and only if You agree to indemnify,
+      defend, and hold each Contributor harmless for any liability
+      incurred by, or claims asserted against, such Contributor by reason
+      of your accepting any such warranty or additional liability.
+
+   END OF TERMS AND CONDITIONS
+
+   APPENDIX: How to apply the Apache License to your work.
+
+      To apply the Apache License to your work, attach the following
+      boilerplate notice, with the fields enclosed by brackets "[]"
+      replaced with your own identifying information. (Don't include
+      the brackets!)  The text should be enclosed in the appropriate
+      comment syntax for the file format. We also recommend that a
+      file or class name and description of purpose be included on the
+      same "printed page" as the copyright notice for easier
+      identification within third-party archives.
+
+   Copyright [yyyy] [name of copyright owner]
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+   you may not use this file except in compliance with the License.
+   You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+   Unless required by applicable law or agreed to in writing, software
+   distributed under the License is distributed on an "AS IS" BASIS,
+   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+   See the License for the specific language governing permissions and
+   limitations under the License.
diff --git a/preupload_hooks/pixel_json_checker/gitlint/__init__.py b/preupload_hooks/pixel_json_checker/gitlint/__init__.py
new file mode 100644
index 00000000..b3b48ddc
--- /dev/null
+++ b/preupload_hooks/pixel_json_checker/gitlint/__init__.py
@@ -0,0 +1 @@
+# Empty placeholder file to make gitlint importable from thermal_config_checker.py
diff --git a/preupload_hooks/pixel_json_checker/gitlint/git.py b/preupload_hooks/pixel_json_checker/gitlint/git.py
new file mode 100644
index 00000000..9d1591aa
--- /dev/null
+++ b/preupload_hooks/pixel_json_checker/gitlint/git.py
@@ -0,0 +1,136 @@
+# Copyright 2013-2014 Sebastian Kreft
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
+"""Functions to get information from git."""
+
+import os.path
+import subprocess
+
+import gitlint.utils as utils
+
+
+def repository_root():
+    """Returns the root of the repository as an absolute path."""
+    try:
+        root = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'],
+                                       stderr=subprocess.STDOUT).strip()
+        # Convert to unicode first
+        return root.decode('utf-8')
+    except subprocess.CalledProcessError:
+        return None
+
+
+def last_commit():
+    """Returns the SHA1 of the last commit."""
+    try:
+        root = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
+                                       stderr=subprocess.STDOUT).strip()
+        # Convert to unicode first
+        return root.decode('utf-8')
+    except subprocess.CalledProcessError:
+        return None
+
+
+def _remove_filename_quotes(filename):
+    """Removes the quotes from a filename returned by git status."""
+    if filename.startswith('"') and filename.endswith('"'):
+        return filename[1:-1]
+
+    return filename
+
+
+def modified_files(root, tracked_only=False, commit=None):
+    """Returns a list of files that has been modified since the last commit.
+
+    Args:
+      root: the root of the repository, it has to be an absolute path.
+      tracked_only: exclude untracked files when True.
+      commit: SHA1 of the commit. If None, it will get the modified files in the
+        working copy.
+
+    Returns: a dictionary with the modified files as keys, and additional
+      information as value. In this case it adds the status returned by
+      git status.
+    """
+    assert os.path.isabs(root), "Root has to be absolute, got: %s" % root
+
+    if commit:
+        return _modified_files_with_commit(root, commit)
+
+    # Convert to unicode and split
+    status_lines = subprocess.check_output([
+        'git', 'status', '--porcelain', '--untracked-files=all',
+        '--ignore-submodules=all']).decode('utf-8').split(os.linesep)
+
+    modes = ['M ', ' M', 'A ', 'AM', 'MM']
+    if not tracked_only:
+        modes.append(r'\?\?')
+    modes_str = '|'.join(modes)
+
+    modified_file_status = utils.filter_lines(
+        status_lines,
+        r'(?P<mode>%s) (?P<filename>.+)' % modes_str,
+        groups=('filename', 'mode'))
+
+    return dict((os.path.join(root, _remove_filename_quotes(filename)), mode)
+                for filename, mode in modified_file_status)
+
+
+def _modified_files_with_commit(root, commit):
+    # Convert to unicode and split
+    status_lines = subprocess.check_output(
+        ['git', 'diff-tree', '-r', '--root', '--no-commit-id', '--name-status',
+         commit]).decode('utf-8').split(os.linesep)
+
+    modified_file_status = utils.filter_lines(
+        status_lines,
+        r'(?P<mode>A|M)\s(?P<filename>.+)',
+        groups=('filename', 'mode'))
+
+    # We need to add a space to the mode, so to be compatible with the output
+    # generated by modified files.
+    return dict((os.path.join(root, _remove_filename_quotes(filename)),
+                 mode + ' ') for filename, mode in modified_file_status)
+
+
+def modified_lines(filename, extra_data, commit=None):
+    """Returns the lines that have been modified for this file.
+
+    Args:
+      filename: the file to check.
+      extra_data: is the extra_data returned by modified_files. Additionally, a
+        value of None means that the file was not modified.
+      commit: the complete sha1 (40 chars) of the commit.
+
+    Returns: a list of lines that were modified, or None in case all lines are
+      new.
+    """
+    if extra_data is None:
+        return []
+    if extra_data not in ('M ', ' M', 'MM'):
+        return None
+
+    if commit is None:
+        commit = '0' * 40
+    commit = commit.encode('utf-8')
+
+    # Split as bytes, as the output may have some non unicode characters.
+    blame_lines = subprocess.check_output(
+        ['git', 'blame', (commit + b'^!'), '--porcelain', '--', filename]).split(
+            os.linesep.encode('utf-8'))
+    modified_line_numbers = utils.filter_lines(
+        blame_lines,
+        commit + br' (?P<line>\d+) (\d+)',
+        groups=('line',))
+
+    return list(map(int, modified_line_numbers))
diff --git a/preupload_hooks/pixel_json_checker/gitlint/utils.py b/preupload_hooks/pixel_json_checker/gitlint/utils.py
new file mode 100644
index 00000000..c9e28ea8
--- /dev/null
+++ b/preupload_hooks/pixel_json_checker/gitlint/utils.py
@@ -0,0 +1,114 @@
+# Copyright 2013-2014 Sebastian Kreft
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
+"""Common function used across modules."""
+
+import io
+import os
+import re
+
+
+def filter_lines(lines, filter_regex, groups=None):
+    """Filters out the lines not matching the pattern.
+
+    Args:
+      lines: list[string]: lines to filter.
+      pattern: string: regular expression to filter out lines.
+
+    Returns: list[string]: the list of filtered lines.
+    """
+    pattern = re.compile(filter_regex)
+    for line in lines:
+        match = pattern.search(line)
+        if match:
+            if groups is None:
+                yield line
+            elif len(groups) == 1:
+                yield match.group(groups[0])
+            else:
+                matched_groups = match.groupdict()
+                yield tuple(matched_groups.get(group) for group in groups)
+
+
+# TODO(skreft): add test
+def which(program):
+    """Returns a list of paths where the program is found."""
+    if (os.path.isabs(program) and os.path.isfile(program) and
+            os.access(program, os.X_OK)):
+        return [program]
+
+    candidates = []
+    locations = os.environ.get("PATH").split(os.pathsep)
+    for location in locations:
+        candidate = os.path.join(location, program)
+        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
+            candidates.append(candidate)
+    return candidates
+
+
+def programs_not_in_path(programs):
+    """Returns all the programs that are not found in the PATH."""
+    return [program for program in programs if not which(program)]
+
+
+def _open_for_write(filename):
+    """Opens filename for writing, creating the directories if needed."""
+    dirname = os.path.dirname(filename)
+    if not os.path.exists(dirname):
+        os.makedirs(dirname)
+
+    return io.open(filename, 'w')
+
+
+def _get_cache_filename(name, filename):
+    """Returns the cache location for filename and linter name."""
+    filename = os.path.abspath(filename)[1:]
+    home_folder = os.path.expanduser('~')
+    base_cache_dir = os.path.join(home_folder, '.git-lint', 'cache')
+
+    return os.path.join(base_cache_dir, name, filename)
+
+
+def get_output_from_cache(name, filename):
+    """Returns the output from the cache if still valid.
+
+    It checks that the cache file is defined and that its modification time is
+    after the modification time of the original file.
+
+    Args:
+      name: string: name of the linter.
+      filename: string: path of the filename for which we are retrieving the
+        output.
+
+    Returns: a string with the output, if it is still valid, or None otherwise.
+    """
+    cache_filename = _get_cache_filename(name, filename)
+    if (os.path.exists(cache_filename) and
+            os.path.getmtime(filename) < os.path.getmtime(cache_filename)):
+        with io.open(cache_filename) as f:
+            return f.read()
+
+    return None
+
+
+def save_output_in_cache(name, filename, output):
+    """Saves output in the cache location.
+
+    Args:
+      name: string: name of the linter.
+      filename: string: path of the filename for which we are saving the output.
+      output: string: full output (not yet filetered) of the lint command.
+    """
+    cache_filename = _get_cache_filename(name, filename)
+    with _open_for_write(cache_filename) as f:
+        f.write(output)
diff --git a/preupload_hooks/pixel_json_checker/pixel_config_checker.py b/preupload_hooks/pixel_json_checker/pixel_config_checker.py
new file mode 100644
index 00000000..e4773e2e
--- /dev/null
+++ b/preupload_hooks/pixel_json_checker/pixel_config_checker.py
@@ -0,0 +1,101 @@
+#!/usr/bin/env python3
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
+
+"""This is a general JSON Config checker that checks string values.
+"""
+
+import json
+import os
+import subprocess
+import sys
+
+class PixelJSONFieldNameChecker(object):
+  """A object for common JSON configuration checking.
+
+    Takes a json_files = dict(file_path, JSON Object) and
+    field_names_path (list of strings) and checks every field name
+    against the list.
+
+    Typical usage example:
+
+    foo = PixelFieldNameChecker(files, vocabulary_path)
+    success, error = foo.check_json_spelling()
+  """
+  valid_field_names = None
+  json_files = None
+  commit_sha = None
+
+  def __init__(self, json_files, field_names_path):
+    self.valid_field_names = self.load_field_names_from_txt(field_names_path)
+    self.json_files = json_files
+
+  def load_field_names_from_txt(self, file_path):
+   """ Function to load a list of new line separated field names
+   from a file at file_path.
+
+   input:
+    file_path: path to lexicon
+
+   output: Set of strings.
+   """
+   field_names = set()
+   with open(file_path, 'r') as f:
+     for line in f:
+       name = line.strip()
+       if name:
+         field_names.add(name)
+   return field_names
+
+  def _check_json_field_names(self, data):
+    """ Recursive function that traverses the json object
+      checking every field and string value.
+
+    input:
+      data: JSON object
+
+    output:
+      Tuple of Success and name if unknown.
+    """
+    if isinstance(data, dict):
+      for key, value in data.items():
+        if key not in self.valid_field_names:
+          return False, key
+        ok, name = self._check_json_field_names(value)
+        if not ok:
+          return False, name
+
+    if isinstance(data, list):
+      for item in data:
+        ok, name = self._check_json_field_names(item)
+        if not ok:
+          return False, name
+
+    return True, None
+
+  def check_json_field_names(self):
+    """ Entry function to check strings and field names if known.
+
+    output:
+      Tuple of Success and error message.
+    """
+    for file_path, json_object in self.json_files.items():
+      success, message = self._check_json_field_names(json_object)
+      if not success:
+        return False, "File " + file_path +": Unknown string: " + message
+
+    return True, ""
diff --git a/preupload_hooks/pixel_json_checker/powerhint_config_checker.py b/preupload_hooks/pixel_json_checker/powerhint_config_checker.py
new file mode 100755
index 00000000..e2a08d3f
--- /dev/null
+++ b/preupload_hooks/pixel_json_checker/powerhint_config_checker.py
@@ -0,0 +1,110 @@
+#!/usr/bin/env python3
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
+
+"""This program validates pixel powerhint configuration strings
+against a predefined list of fields.
+"""
+
+from __future__ import print_function
+
+import argparse
+import errno
+import json
+import os
+import shutil
+import subprocess
+import sys
+import gitlint.git as git
+
+from pixel_config_checker import PixelJSONFieldNameChecker
+
+def get_powerhint_modified_files(commit):
+  """Getter for finding which powerhint json files were modified
+    in the commit.
+
+    Args: Commit sha
+
+    Returns:
+        modified_files: List of powerhint config files modified if any.
+  """
+  root = git.repository_root()
+  modified_files = git.modified_files(root, True, commit)
+  modified_files = {f: modified_files[f] for f
+                    in modified_files if f.endswith('.json') and 'powerhint' in f}
+
+  return modified_files
+
+def main(args=None):
+  """Main function for checking powerhint configs.
+
+    Args:
+      commit: The change commit's SHA.
+      field_names: The path to known field names.
+
+    Returns:
+      Exits with error if unsuccessful.
+  """
+
+  # Mapping of form (json path, json object)
+  json_files = dict()
+
+  # Load arguments provided from repo hooks.
+  parser = argparse.ArgumentParser()
+  parser.add_argument('--commit', '-c')
+  parser.add_argument('--field_names', '-l')
+  args = parser.parse_args()
+  if not args.commit:
+    return "Invalid commit provided"
+
+  if not args.field_names:
+    return "No field names path provided"
+
+  if not git.repository_root():
+    return "Not inside a git repository"
+
+  # Gets modified and added json files in current commit.
+  powerhint_check_file_paths = get_powerhint_modified_files(args.commit)
+  if not list(powerhint_check_file_paths.keys()):
+      return 0
+
+  # Populate and validate (json path, json object) maps to test.
+  for file_name in powerhint_check_file_paths.keys():
+    rel_path = os.path.relpath(file_name)
+    content = subprocess.check_output(
+        ["git", "show", args.commit + ":" + rel_path])
+    try:
+        json_file = json.loads(content)
+        json_files[rel_path] = json_file
+    except ValueError as e:
+      return "Malformed JSON file " + rel_path + " with message "+ str(e)
+
+  # Instantiates the common config checker and runs tests on config.
+  checker = PixelJSONFieldNameChecker(json_files, args.field_names)
+  success, message = checker.check_json_field_names()
+  if not success:
+    return "powerhint JSON field name check error: " + message
+
+if __name__ == '__main__':
+  ret = main()
+  if ret:
+    print(ret)
+    print("----------------------------------------------------")
+    print("| !! Please see go/pixel-perf-thermal-preupload !! |")
+    print("----------------------------------------------------")
+    sys.exit(1)
+
diff --git a/preupload_hooks/pixel_json_checker/thermal_config_checker.py b/preupload_hooks/pixel_json_checker/thermal_config_checker.py
new file mode 100755
index 00000000..caac9b65
--- /dev/null
+++ b/preupload_hooks/pixel_json_checker/thermal_config_checker.py
@@ -0,0 +1,110 @@
+#!/usr/bin/env python3
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
+
+"""This program validates pixel thermal configuration strings
+against a predefined list of fields.
+"""
+
+from __future__ import print_function
+
+import argparse
+import errno
+import json
+import os
+import shutil
+import subprocess
+import sys
+import gitlint.git as git
+
+from pixel_config_checker import PixelJSONFieldNameChecker
+
+def get_thermal_modified_files(commit):
+  """Getter for finding which thermal json files were modified
+    in the commit.
+
+    Args: Commit sha
+
+    Returns:
+        modified_files: List of thermal config files modified if any.
+  """
+  root = git.repository_root()
+  modified_files = git.modified_files(root, True, commit)
+  modified_files = {f: modified_files[f] for f
+                    in modified_files if f.endswith('.json') and 'thermal' in f}
+
+  return modified_files
+
+def main(args=None):
+  """Main function for checking thermal configs.
+
+    Args:
+      commit: The change commit's SHA.
+      field_names: The path to known field names.
+
+    Returns:
+      Exits with error if unsuccessful.
+  """
+
+  # Mapping of form (json path, json object)
+  json_files = dict()
+
+  # Load arguments provided from repo hooks.
+  parser = argparse.ArgumentParser()
+  parser.add_argument('--commit', '-c')
+  parser.add_argument('--field_names', '-l')
+  args = parser.parse_args()
+  if not args.commit:
+    return "Invalid commit provided"
+
+  if not args.field_names:
+    return "No field names path provided"
+
+  if not git.repository_root():
+    return "Not inside a git repository"
+
+  # Gets modified and added json files in current commit.
+  thermal_check_file_paths = get_thermal_modified_files(args.commit)
+  if not list(thermal_check_file_paths.keys()):
+      return 0
+
+  # Populate and validate (json path, json object) maps to test.
+  for file_name in thermal_check_file_paths.keys():
+    rel_path = os.path.relpath(file_name)
+    content = subprocess.check_output(
+        ["git", "show", args.commit + ":" + rel_path])
+    try:
+        json_file = json.loads(content)
+        json_files[rel_path] = json_file
+    except ValueError as e:
+      return "Malformed JSON file " + rel_path + " with message "+ str(e)
+
+  # Instantiates the common config checker and runs tests on config.
+  checker = PixelJSONFieldNameChecker(json_files, args.field_names)
+  success, message = checker.check_json_field_names()
+  if not success:
+    return "Thermal JSON field name check error: " + message
+
+if __name__ == '__main__':
+  ret = main()
+  if ret:
+    print(ret)
+    print("----------------------------------------------------")
+    print("| !! Please see go/pixel-perf-thermal-preupload !! |")
+    print("----------------------------------------------------")
+    sys.exit(1)
+
diff --git a/recovery/Android.bp b/recovery/Android.bp
index 0adc6c37..cd3526b2 100644
--- a/recovery/Android.bp
+++ b/recovery/Android.bp
@@ -49,6 +49,5 @@ cc_library_static {
     shared_libs: [
         "libbase",
         "librecovery_ui",
-        "libboot_control_client",
     ],
 }
diff --git a/recovery/recovery_watch_ui.cpp b/recovery/recovery_watch_ui.cpp
index b6e72752..2fe0a465 100644
--- a/recovery/recovery_watch_ui.cpp
+++ b/recovery/recovery_watch_ui.cpp
@@ -14,14 +14,7 @@
  * limitations under the License.
  */
 
-#include <BootControlClient.h>
-#include <android-base/endian.h>
-#include <android-base/logging.h>
-#include <android-base/strings.h>
 #include <dlfcn.h>
-#include <misc_writer/misc_writer.h>
-#include <recovery_ui/device.h>
-#include <recovery_ui/wear_ui.h>
 #include <stdint.h>
 #include <string.h>
 
@@ -29,6 +22,13 @@
 #include <string_view>
 #include <vector>
 
+#include <android-base/endian.h>
+#include <android-base/logging.h>
+#include <android-base/strings.h>
+#include <misc_writer/misc_writer.h>
+#include <recovery_ui/device.h>
+#include <recovery_ui/wear_ui.h>
+
 namespace android {
 namespace hardware {
 namespace google {
@@ -67,24 +67,6 @@ class PixelWatchDevice : public ::Device {
   public:
     explicit PixelWatchDevice(::WearRecoveryUI* const ui) : ::Device(ui) {}
 
-    bool PreWipeData() override {
-        uint32_t currentSlot = 0;
-        const auto module = android::hal::BootControlClient::WaitForService();
-        if (module == nullptr) {
-            LOG(ERROR) << "Error getting bootctrl module, slot attributes not reset";
-        } else {
-            // Reset current slot attributes
-            currentSlot = module->GetCurrentSlot();
-            LOG(INFO) << "Slot attributes reset for slot " << currentSlot;
-            const auto result = module->SetActiveBootSlot(currentSlot);
-            if (!result.IsOk()) {
-                LOG(ERROR) << "Unable to call SetActiveBootSlot for slot " << currentSlot;
-            }
-        }
-
-        // Loogging errors is sufficient, we don't want to block Wipe Data on this.
-        return true;
-    }
     /** Hook to wipe user data not stored in /data */
     bool PostWipeData() override {
         // Try to do everything but report a failure if anything wasn't successful
diff --git a/thermal/Android.bp b/thermal/Android.bp
index d621f61a..cc088b22 100644
--- a/thermal/Android.bp
+++ b/thermal/Android.bp
@@ -14,6 +14,7 @@ cc_binary {
         "utils/power_files.cpp",
         "utils/powerhal_helper.cpp",
         "utils/thermal_stats_helper.cpp",
+        "utils/thermal_predictions_helper.cpp",
         "utils/thermal_watcher.cpp",
         "virtualtemp_estimator/virtualtemp_estimator.cpp",
     ],
@@ -34,7 +35,7 @@ cc_binary {
         "libbinder_ndk",
         "android.frameworks.stats-V2-ndk",
         "android.hardware.power-V1-ndk",
-        "android.hardware.thermal-V2-ndk",
+        "android.hardware.thermal-V3-ndk",
         "pixel-power-ext-V1-ndk",
         "pixelatoms-cpp",
     ],
@@ -77,6 +78,7 @@ cc_test {
         "utils/power_files.cpp",
         "utils/powerhal_helper.cpp",
         "utils/thermal_stats_helper.cpp",
+        "utils/thermal_predictions_helper.cpp",
         "utils/thermal_watcher.cpp",
         "tests/mock_thermal_helper.cpp",
         "tests/thermal_looper_test.cpp",
@@ -92,7 +94,7 @@ cc_test {
         "libbinder_ndk",
         "android.frameworks.stats-V2-ndk",
         "android.hardware.power-V1-ndk",
-        "android.hardware.thermal-V2-ndk",
+        "android.hardware.thermal-V3-ndk",
         "pixel-power-ext-V1-ndk",
         "pixelatoms-cpp",
     ],
@@ -122,13 +124,12 @@ sh_binary {
     ],
 }
 
-
 cc_binary {
     name: "virtualtemp_estimator_test",
     srcs: [
         "virtualtemp_estimator/virtualtemp_estimator.cpp",
-        "virtualtemp_estimator/virtualtemp_estimator_test.cpp"
-        ],
+        "virtualtemp_estimator/virtualtemp_estimator_test.cpp",
+    ],
     shared_libs: [
         "libbase",
         "libc",
@@ -137,7 +138,8 @@ cc_binary {
         "libbinder",
         "libhidlbase",
         "libutils",
-        "libjsoncpp",],
+        "libjsoncpp",
+    ],
     vendor: true,
     cflags: [
         "-Wall",
diff --git a/thermal/Thermal.cpp b/thermal/Thermal.cpp
index ef977b27..dac1c1f4 100644
--- a/thermal/Thermal.cpp
+++ b/thermal/Thermal.cpp
@@ -307,6 +307,10 @@ ndk::ScopedAStatus Thermal::unregisterCoolingDeviceChangedCallback(
     return ndk::ScopedAStatus::ok();
 }
 
+ndk::ScopedAStatus Thermal::forecastSkinTemperature(int32_t, float *) {
+    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
+}
+
 void Thermal::dumpVirtualSensorInfo(std::ostringstream *dump_buf) {
     *dump_buf << "getVirtualSensorInfo:" << std::endl;
     const auto &map = thermal_helper_->GetSensorInfoMap();
diff --git a/thermal/Thermal.h b/thermal/Thermal.h
index 024fc59c..ae7c8bc6 100644
--- a/thermal/Thermal.h
+++ b/thermal/Thermal.h
@@ -78,6 +78,8 @@ class Thermal : public BnThermal {
             CoolingType type) override;
     ndk::ScopedAStatus unregisterCoolingDeviceChangedCallback(
             const std::shared_ptr<ICoolingDeviceChangedCallback> &callback) override;
+    ndk::ScopedAStatus forecastSkinTemperature(int32_t forecastSeconds,
+                                               float *_aidl_return) override;
 
     binder_status_t dump(int fd, const char **args, uint32_t numArgs) override;
 
diff --git a/thermal/android.hardware.thermal-service.pixel.xml b/thermal/android.hardware.thermal-service.pixel.xml
index 08dc68ca..148ddbfc 100644
--- a/thermal/android.hardware.thermal-service.pixel.xml
+++ b/thermal/android.hardware.thermal-service.pixel.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.thermal</name>
-        <version>2</version>
+        <version>3</version>
         <fqname>IThermal/default</fqname>
     </hal>
 </manifest>
diff --git a/thermal/tests/mock_thermal_helper.h b/thermal/tests/mock_thermal_helper.h
index 9ba6e7f3..91972c4f 100644
--- a/thermal/tests/mock_thermal_helper.h
+++ b/thermal/tests/mock_thermal_helper.h
@@ -38,7 +38,7 @@ class MockThermalHelper : public ThermalHelper {
     MOCK_METHOD(bool, emulSeverity, (std::string_view, const int, const bool), (override));
     MOCK_METHOD(bool, emulClear, (std::string_view), (override));
     MOCK_METHOD(bool, isInitializedOk, (), (const, override));
-    MOCK_METHOD(bool, readTemperature, (std::string_view, Temperature *out, const bool),
+    MOCK_METHOD(SensorReadStatus, readTemperature, (std::string_view, Temperature *out, const bool),
                 (override));
     MOCK_METHOD(bool, readTemperatureThreshold, (std::string_view, TemperatureThreshold *),
                 (const, override));
diff --git a/thermal/tests/pixel_config_checker.py b/thermal/tests/pixel_config_checker.py
new file mode 100644
index 00000000..525621e8
--- /dev/null
+++ b/thermal/tests/pixel_config_checker.py
@@ -0,0 +1,101 @@
+#!/usr/bin/env python3
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
+
+"""This is a general Json Config checker that checks string values
+against a predefined vocabulary list.
+"""
+
+import json
+import os
+import subprocess
+import sys
+
+class PixelConfigLexiconChecker(object):
+  """A object for common JSON configuration checking.
+
+    Takes a json_files = dict(file_path, JSON Object) and
+    lexicon_path (list of words) and checks every field name and
+    string value against the list of words.
+
+    Typical usage example:
+
+    foo = PixelConfigLexiconChecker(files, vocabulary_path)
+    success, error = foo.check_json_spelling()
+  """
+  valid_words = None
+  json_files = None
+  commit_sha = None
+
+  def __init__(self, json_files, lexicon_path):
+    self.valid_words = self.load_words_from_txt(lexicon_path)
+    self.json_files = json_files
+
+  def load_words_from_txt(self, file_path):
+   """ Function to load list of words from file
+
+   input:
+    file_path: path to lexicon
+
+   output: Set of words.
+   """
+   words = set()
+   with open(file_path, 'r') as f:
+     for line in f:
+       word = line.strip()
+       if word:
+         words.add(word)
+   return words
+
+  def _check_json_spelling(self, data):
+    """ Recursive function that traverses the json object
+      checking every field and string value.
+
+    input:
+      data: JSON object
+
+    output:
+      Tuple of Success and word if unknown.
+    """
+    if isinstance(data, dict):
+      for key, value in data.items():
+        if key not in self.valid_words:
+          return False, key
+        ok, word = self._check_json_spelling(value)
+        if not ok:
+          return False, word
+
+    if isinstance(data, list):
+      for item in data:
+        ok, word = self._check_json_spelling(item)
+        if not ok:
+          return False, word
+
+    return True, None
+
+  def check_json_spelling(self):
+    """ Entry function to check strings and field names if known.
+
+    output:
+      Tuple of Success and error message.
+    """
+    for file_path, json_object in self.json_files.items():
+      success, message = self._check_json_spelling(json_object)
+      if not success:
+        return False, "File " + file_path +": Unknown string: " + message
+
+    return True, ""
diff --git a/thermal/tests/thermal_config_field_names.txt b/thermal/tests/thermal_config_field_names.txt
new file mode 100644
index 00000000..9c2820ed
--- /dev/null
+++ b/thermal/tests/thermal_config_field_names.txt
@@ -0,0 +1,46 @@
+BackupSensor
+BindedCdevInfo
+CdevCeiling
+CdevRequest
+CdevWeightForPID
+Coefficient
+CoefficientType
+Combination
+CoolingDevices
+Formula
+Hidden
+HotHysteresis
+HotThreshold
+I_Cutoff
+I_Default
+I_Max
+Include
+K_D
+K_I
+K_Po
+K_Pu
+LimitInfo
+MaxAllocPower
+MaxReleaseStep
+MaxThrottleStep
+MinAllocPower
+ModelPath
+Multiplier
+Name
+Offset
+OutputLabelCount
+PassiveDelay
+PIDInfo
+PollingDelay
+PreviousSampleCount
+SendCallback
+SendPowerHint
+Sensors
+S_Power
+SupportUnderSampling
+TimeResolution
+TriggerSensor
+Type
+Version
+VirtualSensor
+VrThreshold
\ No newline at end of file
diff --git a/thermal/tests/thermal_looper_test.cpp b/thermal/tests/thermal_looper_test.cpp
index 65f13d13..9c9bda6d 100644
--- a/thermal/tests/thermal_looper_test.cpp
+++ b/thermal/tests/thermal_looper_test.cpp
@@ -41,6 +41,11 @@ class TestCallback : public BnThermalChangedCallback {
         return ndk::ScopedAStatus::ok();
     }
 
+    ndk::ScopedAStatus notifyThresholdChanged(const TemperatureThreshold &) override {
+        // no impl for threshold change
+        return ndk::ScopedAStatus::ok();
+    }
+
     std::vector<Temperature> getTemperatures() {
         std::lock_guard<std::mutex> lock_guard(mMutex);
         return mTemperatures;
diff --git a/thermal/thermal-helper.cpp b/thermal/thermal-helper.cpp
index a7f878c6..68f06488 100644
--- a/thermal/thermal-helper.cpp
+++ b/thermal/thermal-helper.cpp
@@ -189,6 +189,11 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
         ret = false;
     }
 
+    if (!thermal_predictions_helper_.initializePredictionSensors(sensor_info_map_)) {
+        LOG(ERROR) << "Failed to initialize prediction sensors";
+        ret = false;
+    }
+
     if (ret) {
         if (!thermal_stats_helper_.initializeStats(config, sensor_info_map_,
                                                    cooling_device_info_map_, this)) {
@@ -289,7 +294,8 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
             }
         }
         // Check predictor info config
-        if (name_status_pair.second.predictor_info != nullptr) {
+        if ((name_status_pair.second.predictor_info != nullptr) &&
+            name_status_pair.second.predictor_info->support_pid_compensation) {
             std::string predict_sensor_name = name_status_pair.second.predictor_info->sensor;
             if (!(sensor_info_map_.count(predict_sensor_name))) {
                 LOG(ERROR) << name_status_pair.first << "'s predictor " << predict_sensor_name
@@ -307,31 +313,29 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
                 break;
             }
 
-            if (name_status_pair.second.predictor_info->support_pid_compensation) {
-                std::vector<float> output_template;
-                size_t prediction_weight_count =
-                        name_status_pair.second.predictor_info->prediction_weights.size();
-                // read predictor out to get the size of output vector
-                ::thermal::vtestimator::VtEstimatorStatus predict_check =
-                        predictor_sensor_info.virtual_sensor_info->vt_estimator->GetAllPredictions(
-                                &output_template);
-
-                if (predict_check != ::thermal::vtestimator::kVtEstimatorOk) {
-                    LOG(ERROR) << "Failed to get output size of " << name_status_pair.first
-                               << "'s predictor " << predict_sensor_name
-                               << " GetAllPredictions ret: " << ret << ")";
-                    ret = false;
-                    break;
-                }
+            std::vector<float> output_template;
+            size_t prediction_weight_count =
+                    name_status_pair.second.predictor_info->prediction_weights.size();
+            // read predictor out to get the size of output vector
+            ::thermal::vtestimator::VtEstimatorStatus predict_check =
+                    predictor_sensor_info.virtual_sensor_info->vt_estimator->GetAllPredictions(
+                            &output_template);
+
+            if (predict_check != ::thermal::vtestimator::kVtEstimatorOk) {
+                LOG(ERROR) << "Failed to get output size of " << name_status_pair.first
+                           << "'s predictor " << predict_sensor_name
+                           << " GetAllPredictions ret: " << ret << ")";
+                ret = false;
+                break;
+            }
 
-                if (prediction_weight_count != output_template.size()) {
-                    LOG(ERROR) << "Sensor [" << name_status_pair.first << "]: "
-                               << "prediction weights size (" << prediction_weight_count
-                               << ") doesn't match predictor [" << predict_sensor_name
-                               << "]'s output size (" << output_template.size() << ")";
-                    ret = false;
-                    break;
-                }
+            if (prediction_weight_count != output_template.size()) {
+                LOG(ERROR) << "Sensor [" << name_status_pair.first
+                           << "]: " << "prediction weights size (" << prediction_weight_count
+                           << ") doesn't match predictor [" << predict_sensor_name
+                           << "]'s output size (" << output_template.size() << ")";
+                ret = false;
+                break;
             }
         }
     }
@@ -517,23 +521,29 @@ bool ThermalHelperImpl::readCoolingDevice(std::string_view cooling_device,
     return true;
 }
 
-bool ThermalHelperImpl::readTemperature(std::string_view sensor_name, Temperature *out,
-                                        const bool force_no_cache) {
+SensorReadStatus ThermalHelperImpl::readTemperature(std::string_view sensor_name, Temperature *out,
+                                                    const bool force_no_cache) {
     // Return fail if the thermal sensor cannot be read.
     float temp = NAN;
     std::map<std::string, float> sensor_log_map;
     auto &sensor_status = sensor_status_map_.at(sensor_name.data());
 
-    if (!readThermalSensor(sensor_name, &temp, force_no_cache, &sensor_log_map)) {
+    const auto ret = readThermalSensor(sensor_name, &temp, force_no_cache, &sensor_log_map);
+    if (ret == SensorReadStatus::ERROR) {
         LOG(ERROR) << "Failed to read thermal sensor " << sensor_name.data();
         thermal_stats_helper_.reportThermalAbnormality(
                 ThermalSensorAbnormalityDetected::TEMP_READ_FAIL, sensor_name, std::nullopt);
-        return false;
+        return SensorReadStatus::ERROR;
+    }
+
+    if (ret == SensorReadStatus::UNDER_COLLECTING) {
+        LOG(INFO) << "Thermal sensor " << sensor_name.data() << " is under collecting";
+        return SensorReadStatus::UNDER_COLLECTING;
     }
 
     if (std::isnan(temp)) {
         LOG(INFO) << "Sensor " << sensor_name.data() << " temperature is nan.";
-        return false;
+        return SensorReadStatus::ERROR;
     }
     const auto severity_reference = getSeverityReference(sensor_name.data());
 
@@ -547,7 +557,7 @@ bool ThermalHelperImpl::readTemperature(std::string_view sensor_name, Temperatur
 
     // Only update status if the thermal sensor is being monitored
     if (!sensor_info.is_watch) {
-        return true;
+        return SensorReadStatus::OKAY;
     }
     ThrottlingSeverity prev_hot_severity, prev_cold_severity;
     {
@@ -599,7 +609,7 @@ bool ThermalHelperImpl::readTemperature(std::string_view sensor_name, Temperatur
     ATRACE_INT((sensor_name.data() + std::string("-severity")).c_str(),
                static_cast<int>(out->throttlingStatus));
 
-    return true;
+    return SensorReadStatus::OKAY;
 }
 
 bool ThermalHelperImpl::readTemperatureThreshold(std::string_view sensor_name,
@@ -832,7 +842,6 @@ bool ThermalHelperImpl::initializeCoolingDevices(
                            << cooling_device_info_pair.second.state2power.size()
                            << ", number should be " << cooling_device_info_pair.second.max_state + 1
                            << " (max_state + 1)";
-                return false;
             }
         }
 
@@ -951,9 +960,11 @@ bool ThermalHelperImpl::fillCurrentTemperatures(bool filterType, bool filterCall
         if (filterCallback && !name_info_pair.second.send_cb) {
             continue;
         }
-        if (readTemperature(name_info_pair.first, &temp, false)) {
+
+        const auto status = readTemperature(name_info_pair.first, &temp, false);
+        if (status == SensorReadStatus::OKAY) {
             ret.emplace_back(std::move(temp));
-        } else {
+        } else if (status == SensorReadStatus::ERROR) {
             LOG(ERROR) << __func__
                        << ": error reading temperature for sensor: " << name_info_pair.first;
         }
@@ -1016,7 +1027,7 @@ ThrottlingSeverity ThermalHelperImpl::getSeverityReference(std::string_view sens
     }
 
     Temperature temp;
-    if (!readTemperature(severity_reference, &temp, false)) {
+    if (readTemperature(severity_reference, &temp, false) != SensorReadStatus::OKAY) {
         return ThrottlingSeverity::NONE;
     }
     LOG(VERBOSE) << sensor_name << "'s severity reference " << severity_reference
@@ -1029,8 +1040,8 @@ bool ThermalHelperImpl::readDataByType(std::string_view sensor_data, float *read
                                        std::map<std::string, float> *sensor_log_map) {
     switch (type) {
         case SensorFusionType::SENSOR:
-            if (!readThermalSensor(sensor_data.data(), reading_value, force_no_cache,
-                                   sensor_log_map)) {
+            if (readThermalSensor(sensor_data.data(), reading_value, force_no_cache,
+                                  sensor_log_map) == SensorReadStatus::ERROR) {
                 LOG(ERROR) << "Failed to get " << sensor_data.data() << " data";
                 return false;
             }
@@ -1106,6 +1117,9 @@ bool ThermalHelperImpl::runVirtualTempEstimator(std::string_view sensor_name,
             sensor_info.virtual_sensor_info->vt_estimator->Estimate(model_inputs, &model_outputs);
 
     if (ret == ::thermal::vtestimator::kVtEstimatorOk) {
+        if (sensor_info.predictor_info && sensor_info.predictor_info->supports_predictions) {
+            thermal_predictions_helper_.updateSensor(sensor_name, model_outputs);
+        }
         *outputs = model_outputs;
         return true;
     } else if (ret == ::thermal::vtestimator::kVtEstimatorLowConfidence ||
@@ -1251,16 +1265,16 @@ bool ThermalHelperImpl::readTemperaturePredictions(std::string_view sensor_name,
 
 constexpr int kTranTimeoutParam = 2;
 
-bool ThermalHelperImpl::readThermalSensor(std::string_view sensor_name, float *temp,
-                                          const bool force_no_cache,
-                                          std::map<std::string, float> *sensor_log_map) {
+SensorReadStatus ThermalHelperImpl::readThermalSensor(
+        std::string_view sensor_name, float *temp, const bool force_no_cache,
+        std::map<std::string, float> *sensor_log_map) {
     std::string file_reading;
     boot_clock::time_point now = boot_clock::now();
 
     ATRACE_NAME(StringPrintf("ThermalHelper::readThermalSensor - %s", sensor_name.data()).c_str());
     if (!(sensor_info_map_.count(sensor_name.data()) &&
           sensor_status_map_.count(sensor_name.data()))) {
-        return false;
+        return SensorReadStatus::ERROR;
     }
 
     const auto &sensor_info = sensor_info_map_.at(sensor_name.data());
@@ -1271,7 +1285,7 @@ bool ThermalHelperImpl::readThermalSensor(std::string_view sensor_name, float *t
         if (sensor_status.override_status.emul_temp != nullptr) {
             *temp = sensor_status.override_status.emul_temp->temp;
             (*sensor_log_map)[sensor_name.data()] = *temp;
-            return true;
+            return SensorReadStatus::OKAY;
         }
     }
 
@@ -1286,7 +1300,7 @@ bool ThermalHelperImpl::readThermalSensor(std::string_view sensor_name, float *t
         *temp = sensor_status.thermal_cached.temp;
         (*sensor_log_map)[sensor_name.data()] = *temp;
         ATRACE_INT((sensor_name.data() + std::string("-cached")).c_str(), static_cast<int>(*temp));
-        return true;
+        return SensorReadStatus::OKAY;
     }
 
     // Reading thermal sensor according to it's composition
@@ -1294,7 +1308,7 @@ bool ThermalHelperImpl::readThermalSensor(std::string_view sensor_name, float *t
         if (!thermal_sensors_.readThermalFile(sensor_name.data(), &file_reading) ||
             file_reading.empty()) {
             LOG(ERROR) << "failed to read sensor: " << sensor_name;
-            return false;
+            return SensorReadStatus::ERROR;
         }
         *temp = std::stof(::android::base::Trim(file_reading));
     } else {
@@ -1309,21 +1323,26 @@ bool ThermalHelperImpl::readThermalSensor(std::string_view sensor_name, float *t
                                 force_no_cache, sensor_log_map)) {
                 LOG(ERROR) << "Failed to read " << sensor_name.data() << "'s linked sensor "
                            << sensor_info.virtual_sensor_info->linked_sensors[i];
-                return false;
+                return SensorReadStatus::ERROR;
             }
             if (std::isnan(sensor_readings[i])) {
                 LOG(INFO) << sensor_name << " data is under collecting";
-                return true;
+                return SensorReadStatus::UNDER_COLLECTING;
             }
         }
 
-        if ((sensor_info.virtual_sensor_info->formula == FormulaOption::USE_ML_MODEL) ||
-            (sensor_info.virtual_sensor_info->formula == FormulaOption::USE_LINEAR_MODEL)) {
+        if (sensor_info.virtual_sensor_info->formula == FormulaOption::PREVIOUSLY_PREDICTED) {
+            const auto ret = thermal_predictions_helper_.readSensor(sensor_name, temp);
+            if (ret != SensorReadStatus::OKAY) {
+                return ret;
+            }
+        } else if ((sensor_info.virtual_sensor_info->formula == FormulaOption::USE_ML_MODEL) ||
+                   (sensor_info.virtual_sensor_info->formula == FormulaOption::USE_LINEAR_MODEL)) {
             std::vector<float> vt_estimator_out;
             if (!runVirtualTempEstimator(sensor_name, sensor_log_map, force_no_cache,
                                          &vt_estimator_out)) {
                 LOG(ERROR) << "Failed running VirtualEstimator for " << sensor_name;
-                return false;
+                return SensorReadStatus::ERROR;
             }
             *temp = vt_estimator_out[0];
         } else {
@@ -1335,11 +1354,11 @@ bool ThermalHelperImpl::readThermalSensor(std::string_view sensor_name, float *t
                                     force_no_cache, sensor_log_map)) {
                     LOG(ERROR) << "Failed to read " << sensor_name.data() << "'s coefficient "
                                << sensor_info.virtual_sensor_info->coefficients[i];
-                    return false;
+                    return SensorReadStatus::ERROR;
                 }
                 if (std::isnan(coefficient)) {
                     LOG(INFO) << sensor_name << " data is under collecting";
-                    return true;
+                    return SensorReadStatus::UNDER_COLLECTING;
                 }
                 switch (sensor_info.virtual_sensor_info->formula) {
                     case FormulaOption::COUNT_THRESHOLD:
@@ -1364,7 +1383,7 @@ bool ThermalHelperImpl::readThermalSensor(std::string_view sensor_name, float *t
                         break;
                     default:
                         LOG(ERROR) << "Unknown formula type for sensor " << sensor_name.data();
-                        return false;
+                        return SensorReadStatus::ERROR;
                 }
             }
             *temp = (temp_val + sensor_info.virtual_sensor_info->offset);
@@ -1387,7 +1406,7 @@ bool ThermalHelperImpl::readThermalSensor(std::string_view sensor_name, float *t
     }
     auto real_temp = (*temp) * sensor_info.multiplier;
     thermal_stats_helper_.updateSensorTempStatsByThreshold(sensor_name, real_temp);
-    return true;
+    return SensorReadStatus::OKAY;
 }
 
 // This is called in the different thread context and will update sensor_status
@@ -1503,12 +1522,19 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
         }
 
         std::pair<ThrottlingSeverity, ThrottlingSeverity> throttling_status;
-        if (!readTemperature(name_status_pair.first, &temp, force_no_cache)) {
+        const auto ret = readTemperature(name_status_pair.first, &temp, force_no_cache);
+        if (ret == SensorReadStatus::ERROR) {
             LOG(ERROR) << __func__
                        << ": error reading temperature for sensor: " << name_status_pair.first;
             continue;
         }
 
+        if (ret == SensorReadStatus::UNDER_COLLECTING) {
+            LOG(INFO) << __func__
+                      << ": data under collecting for sensor: " << name_status_pair.first;
+            continue;
+        }
+
         {
             std::unique_lock<std::shared_mutex> _lock(sensor_status_map_mutex_);
             if (sensor_status.pending_notification) {
diff --git a/thermal/thermal-helper.h b/thermal/thermal-helper.h
index bd64505f..8665d524 100644
--- a/thermal/thermal-helper.h
+++ b/thermal/thermal-helper.h
@@ -33,6 +33,7 @@
 #include "utils/powerhal_helper.h"
 #include "utils/thermal_files.h"
 #include "utils/thermal_info.h"
+#include "utils/thermal_predictions_helper.h"
 #include "utils/thermal_stats_helper.h"
 #include "utils/thermal_throttling.h"
 #include "utils/thermal_watcher.h"
@@ -91,8 +92,8 @@ class ThermalHelper {
                               const bool max_throttling) = 0;
     virtual bool emulClear(std::string_view target_sensor) = 0;
     virtual bool isInitializedOk() const = 0;
-    virtual bool readTemperature(std::string_view sensor_name, Temperature *out,
-                                 const bool force_sysfs = false) = 0;
+    virtual SensorReadStatus readTemperature(std::string_view sensor_name, Temperature *out,
+                                             const bool force_sysfs = false) = 0;
     virtual bool readTemperatureThreshold(std::string_view sensor_name,
                                           TemperatureThreshold *out) const = 0;
     virtual bool readCoolingDevice(std::string_view cooling_device, CoolingDevice *out) const = 0;
@@ -140,8 +141,8 @@ class ThermalHelperImpl : public ThermalHelper {
     bool isInitializedOk() const override { return is_initialized_; }
 
     // Read the temperature of a single sensor.
-    bool readTemperature(std::string_view sensor_name, Temperature *out,
-                         const bool force_sysfs = false) override;
+    SensorReadStatus readTemperature(std::string_view sensor_name, Temperature *out,
+                                     const bool force_sysfs = false) override;
 
     bool readTemperatureThreshold(std::string_view sensor_name,
                                   TemperatureThreshold *out) const override;
@@ -213,8 +214,9 @@ class ThermalHelperImpl : public ThermalHelper {
     bool readDataByType(std::string_view sensor_data, float *reading_value,
                         const SensorFusionType type, const bool force_no_cache,
                         std::map<std::string, float> *sensor_log_map);
-    bool readThermalSensor(std::string_view sensor_name, float *temp, const bool force_sysfs,
-                           std::map<std::string, float> *sensor_log_map);
+    SensorReadStatus readThermalSensor(std::string_view sensor_name, float *temp,
+                                       const bool force_sysfs,
+                                       std::map<std::string, float> *sensor_log_map);
     bool runVirtualTempEstimator(std::string_view sensor_name,
                                  std::map<std::string, float> *sensor_log_map,
                                  const bool force_no_cache, std::vector<float> *outputs);
@@ -241,6 +243,7 @@ class ThermalHelperImpl : public ThermalHelper {
             supported_powerhint_map_;
     PowerHalService power_hal_service_;
     ThermalStatsHelper thermal_stats_helper_;
+    ThermalPredictionsHelper thermal_predictions_helper_;
     mutable std::shared_mutex sensor_status_map_mutex_;
     std::unordered_map<std::string, SensorStatus> sensor_status_map_;
 };
diff --git a/thermal/utils/thermal_info.cpp b/thermal/utils/thermal_info.cpp
index 92ba07af..f4dd713f 100644
--- a/thermal/utils/thermal_info.cpp
+++ b/thermal/utils/thermal_info.cpp
@@ -358,8 +358,11 @@ bool ParseVirtualSensorInfo(const std::string_view name, const Json::Value &sens
         formula = FormulaOption::USE_ML_MODEL;
     } else if (sensor["Formula"].asString().compare("USE_LINEAR_MODEL") == 0) {
         formula = FormulaOption::USE_LINEAR_MODEL;
+    } else if (sensor["Formula"].asString().compare("PREVIOUSLY_PREDICTED") == 0) {
+        formula = FormulaOption::PREVIOUSLY_PREDICTED;
     } else {
-        LOG(ERROR) << "Sensor[" << name << "]'s Formula is invalid";
+        LOG(ERROR) << "Sensor[" << name << "]'s Formula: " << sensor["Formula"].asString()
+                   << " is invalid";
         return false;
     }
 
@@ -399,12 +402,14 @@ bool ParseVirtualSensorInfo(const std::string_view name, const Json::Value &sens
             coefficients.emplace_back(values[j].asString());
             LOG(INFO) << "Sensor[" << name << "]'s coefficient[" << j << "]: " << coefficients[j];
         }
-    } else if ((formula != FormulaOption::USE_ML_MODEL)) {
+    } else if ((formula != FormulaOption::USE_ML_MODEL) &&
+               (formula != FormulaOption::PREVIOUSLY_PREDICTED)) {
         LOG(ERROR) << "Sensor[" << name << "] has no Coefficient setting";
         return false;
     }
     if ((linked_sensors.size() != coefficients.size()) &&
-        (formula != FormulaOption::USE_ML_MODEL) && (formula != FormulaOption::USE_LINEAR_MODEL)) {
+        (formula != FormulaOption::USE_ML_MODEL) && (formula != FormulaOption::USE_LINEAR_MODEL) &&
+        (formula != FormulaOption::PREVIOUSLY_PREDICTED)) {
         LOG(ERROR) << "Sensor[" << name << "] has invalid Coefficient size";
         return false;
     }
@@ -604,47 +609,88 @@ bool ParseVirtualSensorInfo(const std::string_view name, const Json::Value &sens
 bool ParsePredictorInfo(const std::string_view name, const Json::Value &sensor,
                         std::unique_ptr<PredictorInfo> *predictor_info) {
     Json::Value predictor = sensor["PredictorInfo"];
-    if (predictor.empty()) {
-        return true;
-    }
-
-    LOG(INFO) << "Start to parse Sensor[" << name << "]'s PredictorInfo";
-    if (predictor["Sensor"].empty()) {
-        LOG(ERROR) << "Failed to parse Sensor [" << name << "]'s PredictorInfo";
-        return false;
-    }
-
     std::string predict_sensor;
     bool support_pid_compensation = false;
     std::vector<float> prediction_weights;
     ThrottlingArray k_p_compensate;
-    predict_sensor = predictor["Sensor"].asString();
-    LOG(INFO) << "Sensor [" << name << "]'s predictor name is " << predict_sensor;
-    // parse pid compensation configuration
-    if ((!predictor["PredictionWeight"].empty()) && (!predictor["KPCompensate"].empty())) {
-        support_pid_compensation = true;
-        if (!predictor["PredictionWeight"].size()) {
-            LOG(ERROR) << "Failed to parse PredictionWeight";
+
+    bool supports_predictions = false;
+    int prediction_sample_interval = 0;
+    int num_prediction_samples = 0;
+    int prediction_duration = 0;
+    bool set_predictor_info = false;
+
+    if (!predictor.empty()) {
+        set_predictor_info = true;
+        LOG(INFO) << "Start to parse Sensor[" << name << "]'s PredictorInfo";
+        if (predictor["Sensor"].empty()) {
+            LOG(ERROR) << "Failed to parse Sensor [" << name << "]'s PredictorInfo";
             return false;
         }
-        prediction_weights.reserve(predictor["PredictionWeight"].size());
-        for (Json::Value::ArrayIndex i = 0; i < predictor["PredictionWeight"].size(); ++i) {
-            float weight = predictor["PredictionWeight"][i].asFloat();
-            if (std::isnan(weight)) {
-                LOG(ERROR) << "Unexpected NAN prediction weight for sensor [" << name << "]";
+
+        predict_sensor = predictor["Sensor"].asString();
+        LOG(INFO) << "Sensor [" << name << "]'s predictor name is " << predict_sensor;
+        // parse pid compensation configuration
+        if ((!predictor["PredictionWeight"].empty()) && (!predictor["KPCompensate"].empty())) {
+            support_pid_compensation = true;
+            if (!predictor["PredictionWeight"].size()) {
+                LOG(ERROR) << "Failed to parse PredictionWeight";
+                return false;
+            }
+            prediction_weights.reserve(predictor["PredictionWeight"].size());
+            for (Json::Value::ArrayIndex i = 0; i < predictor["PredictionWeight"].size(); ++i) {
+                float weight = predictor["PredictionWeight"][i].asFloat();
+                if (std::isnan(weight)) {
+                    LOG(ERROR) << "Unexpected NAN prediction weight for sensor [" << name << "]";
+                }
+                prediction_weights.emplace_back(weight);
+                LOG(INFO) << "Sensor[" << name << "]'s prediction weights [" << i
+                          << "]: " << weight;
+            }
+            if (!getFloatFromJsonValues(predictor["KPCompensate"], &k_p_compensate, false, false)) {
+                LOG(ERROR) << "Failed to parse KPCompensate";
+                return false;
             }
-            prediction_weights.emplace_back(weight);
-            LOG(INFO) << "Sensor[" << name << "]'s prediction weights [" << i << "]: " << weight;
         }
-        if (!getFloatFromJsonValues(predictor["KPCompensate"], &k_p_compensate, false, false)) {
-            LOG(ERROR) << "Failed to parse KPCompensate";
+    }
+
+    if (sensor["SupportPrediction"].asBool()) {
+        set_predictor_info = true;
+        supports_predictions = true;
+        LOG(INFO) << "Sensor[" << name << "] supports predictions.";
+
+        if (sensor["SampleDuration"].empty()) {
+            LOG(ERROR) << "SampleDuration is empty for predictor sensor: " << name;
             return false;
         }
+
+        if (sensor["OutputLabelCount"].empty()) {
+            LOG(ERROR) << "OutputLabelCount is empty for predictor sensor: " << name;
+            return false;
+        }
+
+        prediction_sample_interval = sensor["SampleDuration"].asInt();
+        num_prediction_samples = sensor["OutputLabelCount"].asInt();
     }
 
-    LOG(INFO) << "Successfully created PredictorInfo for Sensor[" << name << "]";
-    predictor_info->reset(new PredictorInfo{predict_sensor, support_pid_compensation,
-                                            prediction_weights, k_p_compensate});
+    if (sensor["Formula"].asString().compare("PREVIOUSLY_PREDICTED") == 0) {
+        set_predictor_info = true;
+        if (sensor["PredictionDuration"].empty()) {
+            LOG(ERROR) << "Sensor[" << name
+                       << "] is a PREVIOUSLY_PREDICTED sensor and has no PredictionDuration";
+            return false;
+        }
+
+        prediction_duration = sensor["PredictionDuration"].asInt();
+    }
+
+    if (set_predictor_info) {
+        LOG(INFO) << "Successfully created PredictorInfo for Sensor[" << name << "]";
+        predictor_info->reset(new PredictorInfo{predict_sensor, support_pid_compensation,
+                                                prediction_weights, k_p_compensate,
+                                                supports_predictions, prediction_sample_interval,
+                                                num_prediction_samples, prediction_duration});
+    }
 
     return true;
 }
diff --git a/thermal/utils/thermal_info.h b/thermal/utils/thermal_info.h
index dc1f6cb9..c5b39dc8 100644
--- a/thermal/utils/thermal_info.h
+++ b/thermal/utils/thermal_info.h
@@ -56,7 +56,8 @@ enum class FormulaOption : uint32_t {
     MAXIMUM,
     MINIMUM,
     USE_ML_MODEL,
-    USE_LINEAR_MODEL
+    USE_LINEAR_MODEL,
+    PREVIOUSLY_PREDICTED
 };
 
 template <typename T>
@@ -130,6 +131,12 @@ enum class SensorFusionType : uint32_t {
     CDEV,
 };
 
+enum class SensorReadStatus : uint32_t {
+    OKAY = 0,
+    UNDER_COLLECTING,
+    ERROR,
+};
+
 std::ostream &operator<<(std::ostream &os, const SensorFusionType &sensor_fusion_type);
 
 struct VirtualSensorInfo {
@@ -151,6 +158,11 @@ struct PredictorInfo {
     bool support_pid_compensation;
     std::vector<float> prediction_weights;
     ThrottlingArray k_p_compensate;
+
+    bool supports_predictions;       // Does this sensor support predictions
+    int prediction_sample_interval;  // Interval between each predicted sample
+    int num_prediction_samples;      // How many samples are predicted for each iteration
+    int prediction_duration;         // Prediction duration for a PREDICTED sensor
 };
 
 struct VirtualPowerRailInfo {
diff --git a/thermal/utils/thermal_predictions_helper.cpp b/thermal/utils/thermal_predictions_helper.cpp
new file mode 100644
index 00000000..ba856a96
--- /dev/null
+++ b/thermal/utils/thermal_predictions_helper.cpp
@@ -0,0 +1,215 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+#include "thermal_predictions_helper.h"
+
+#include <android-base/logging.h>
+#include <android/binder_manager.h>
+
+#include <algorithm>
+#include <numeric>
+#include <string_view>
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace thermal {
+namespace implementation {
+
+bool ThermalPredictionsHelper::registerPredictorSensor(std::string_view sensor_name,
+                                                       int sample_duration, int num_out_samples) {
+    if (sample_duration <= 0 || num_out_samples <= 0) {
+        LOG(ERROR) << "Invalid sample_duration: " << sample_duration
+                   << " or num_out_samples: " << num_out_samples << " for sensor: " << sensor_name;
+        return false;
+    }
+
+    if (predictor_sensors_.count(sensor_name.data())) {
+        LOG(ERROR) << "sensor_name " << sensor_name << " is already registered as predictor";
+        return false;
+    }
+
+    predictor_sensors_[sensor_name.data()] = PredictorSensorInfo(
+            {std::string(sensor_name), sample_duration, num_out_samples,
+             std::vector<PredictionSample>(num_out_samples, PredictionSample(num_out_samples)), 0});
+    return true;
+}
+
+bool ThermalPredictionsHelper::registerPredictedSensor(std::string_view sensor_name,
+                                                       std::string_view linked_sensor,
+                                                       int duration) {
+    if (duration < 0) {
+        LOG(ERROR) << "Invalid duration: " << duration << " for sensor: " << sensor_name;
+        return false;
+    }
+
+    if (predicted_sensors_.count(sensor_name.data())) {
+        LOG(ERROR) << "sensor_name " << sensor_name << " is already registered as predicted sensor";
+        return false;
+    }
+
+    if (predictor_sensors_.count(linked_sensor.data()) == 0) {
+        LOG(ERROR) << "linked_sensor_name " << linked_sensor << " is not registered as predictor";
+        return false;
+    }
+
+    PredictorSensorInfo &predictor_sensor_info = predictor_sensors_[linked_sensor.data()];
+    const int max_prediction_duration =
+            (predictor_sensor_info.num_out_samples - 1) * predictor_sensor_info.sample_duration;
+
+    if (duration > max_prediction_duration) {
+        LOG(ERROR) << "Predicted sensor " << sensor_name
+                   << " duration is greater than max prediction duration of predictor "
+                   << linked_sensor << " which is " << max_prediction_duration;
+        return false;
+    }
+
+    // round up to nearest lower index
+    const int prediction_index = duration / predictor_sensor_info.sample_duration;
+    if (duration % predictor_sensor_info.sample_duration != 0) {
+        LOG(INFO) << "Predicted sensor " << sensor_name << " duration " << duration
+                  << " is not a multiple of " << linked_sensor << " sample duration "
+                  << predictor_sensor_info.sample_duration << " and hence updated to "
+                  << prediction_index * predictor_sensor_info.sample_duration;
+    }
+
+    predicted_sensors_[sensor_name.data()] = PredictedSensorInfo(
+            {std::string(sensor_name), std::string(linked_sensor), duration, prediction_index});
+    return true;
+}
+
+bool ThermalPredictionsHelper::updateSensor(std::string_view sensor_name,
+                                            std::vector<float> &values) {
+    std::unique_lock<std::shared_mutex> _lock(sensor_predictions_mutex_);
+    const auto sensor_itr = predictor_sensors_.find(sensor_name.data());
+    if (sensor_itr == predictor_sensors_.end()) {
+        LOG(ERROR) << "sensor_name " << sensor_name << " is not registered as predictor";
+        return false;
+    }
+
+    PredictorSensorInfo &predictor_sensor_info = predictor_sensors_[sensor_name.data()];
+    if (values.size() != static_cast<size_t>(predictor_sensor_info.num_out_samples)) {
+        LOG(ERROR) << "Invalid number of values: " << values.size()
+                   << " for sensor: " << sensor_name
+                   << ", expected: " << predictor_sensor_info.num_out_samples;
+        return false;
+    }
+
+    predictor_sensor_info.samples[predictor_sensor_info.cur_index].timestamp = boot_clock::now();
+    predictor_sensor_info.samples[predictor_sensor_info.cur_index].values = values;
+    predictor_sensor_info.cur_index++;
+    predictor_sensor_info.cur_index %= predictor_sensor_info.num_out_samples;
+
+    return true;
+}
+
+SensorReadStatus ThermalPredictionsHelper::readSensor(std::string_view sensor_name, float *temp) {
+    std::shared_lock<std::shared_mutex> _lock(sensor_predictions_mutex_);
+    const auto sensor_itr = predicted_sensors_.find(sensor_name.data());
+    if (sensor_itr == predicted_sensors_.end()) {
+        LOG(ERROR) << "sensor_name " << sensor_name << " is not registered as predicted sensor";
+        return SensorReadStatus::ERROR;
+    }
+
+    PredictedSensorInfo &predicted_sensor_info = predicted_sensors_[sensor_name.data()];
+    const int prediction_index = predicted_sensor_info.prediction_index;
+
+    const auto linked_sensor_itr = predictor_sensors_.find(predicted_sensor_info.linked_sensor);
+    if (linked_sensor_itr == predictor_sensors_.end()) {
+        LOG(ERROR) << "linked_sensor_name " << predicted_sensor_info.linked_sensor
+                   << " is not registered as predictor for sensor" << sensor_name;
+        return SensorReadStatus::ERROR;
+    }
+
+    PredictorSensorInfo predictor_sensor_info = linked_sensor_itr->second;
+    boot_clock::time_point now = boot_clock::now();
+    const auto min_time_elapsed_ms = predicted_sensor_info.duration - kToleranceIntervalMs;
+    const auto max_time_elapsed_ms = predicted_sensor_info.duration + kToleranceIntervalMs;
+    int loop_count = 0;
+    do {
+        int index = predictor_sensor_info.cur_index - loop_count - 1;
+        if (index < 0) {
+            index += predictor_sensor_info.num_out_samples;
+        }
+
+        const auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
+                now - predictor_sensor_info.samples[index].timestamp);
+        if (time_elapsed.count() <= max_time_elapsed_ms &&
+            time_elapsed.count() >= min_time_elapsed_ms) {
+            *temp = predictor_sensor_info.samples[index].values[prediction_index];
+            return SensorReadStatus::OKAY;
+        }
+
+        loop_count++;
+    } while (loop_count < predictor_sensor_info.num_out_samples);
+
+    LOG(INFO) << "sensor_name: " << sensor_name << " no valid prediction samples found";
+    return SensorReadStatus::UNDER_COLLECTING;
+}
+
+bool ThermalPredictionsHelper::initializePredictionSensors(
+        const std::unordered_map<std::string, SensorInfo> &sensor_info_map) {
+    std::unique_lock<std::shared_mutex> _lock(sensor_predictions_mutex_);
+
+    for (auto it = sensor_info_map.begin(); it != sensor_info_map.end(); ++it) {
+        const std::string_view sensor_name = it->first;
+        const SensorInfo &sensor_info = it->second;
+
+        if (!sensor_info.predictor_info || !sensor_info.virtual_sensor_info ||
+            (!sensor_info.predictor_info->supports_predictions)) {
+            continue;
+        }
+
+        if (!registerPredictorSensor(sensor_name,
+                                     sensor_info.predictor_info->prediction_sample_interval,
+                                     sensor_info.predictor_info->num_prediction_samples)) {
+            LOG(ERROR) << "Failed to register predictor sensor: " << sensor_name;
+            return false;
+        }
+    }
+
+    for (auto it = sensor_info_map.begin(); it != sensor_info_map.end(); ++it) {
+        const std::string_view sensor_name = it->first;
+        const SensorInfo &sensor_info = it->second;
+
+        if (!sensor_info.predictor_info || !sensor_info.virtual_sensor_info ||
+            (sensor_info.virtual_sensor_info->formula != FormulaOption::PREVIOUSLY_PREDICTED)) {
+            continue;
+        }
+
+        if (sensor_info.virtual_sensor_info->linked_sensors.size() != 1) {
+            LOG(ERROR) << "Invalid number of linked sensors: "
+                       << sensor_info.virtual_sensor_info->linked_sensors.size()
+                       << " for sensor: " << sensor_name;
+            return false;
+        }
+
+        if (!registerPredictedSensor(sensor_name,
+                                     sensor_info.virtual_sensor_info->linked_sensors[0],
+                                     sensor_info.predictor_info->prediction_duration)) {
+            LOG(ERROR) << "Failed to register predicted sensor: " << sensor_name;
+            return false;
+        }
+    }
+
+    return true;
+}
+
+}  // namespace implementation
+}  // namespace thermal
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/thermal/utils/thermal_predictions_helper.h b/thermal/utils/thermal_predictions_helper.h
new file mode 100644
index 00000000..532ebe87
--- /dev/null
+++ b/thermal/utils/thermal_predictions_helper.h
@@ -0,0 +1,91 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+#include <aidl/android/hardware/thermal/Temperature.h>
+#include <android-base/chrono_utils.h>
+
+#include <chrono>
+#include <shared_mutex>
+#include <string_view>
+#include <unordered_map>
+#include <vector>
+
+#include "thermal_info.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace thermal {
+namespace implementation {
+
+using ::android::base::boot_clock;
+constexpr int kToleranceIntervalMs = 1000;
+
+struct PredictionSample {
+    PredictionSample(int num_out_samples) {
+        timestamp = boot_clock::time_point::min();
+        values = std::vector<float>(num_out_samples, NAN);
+    }
+    boot_clock::time_point timestamp;
+    std::vector<float> values;
+};
+
+struct PredictorSensorInfo {
+    std::string sensor_name;
+    int sample_duration;
+    int num_out_samples;
+    std::vector<PredictionSample> samples;
+    int cur_index;
+};
+
+struct PredictedSensorInfo {
+    std::string sensor_name;
+    std::string linked_sensor;
+    int duration;
+    int prediction_index;
+};
+
+class ThermalPredictionsHelper {
+  public:
+    ThermalPredictionsHelper() = default;
+    ~ThermalPredictionsHelper() = default;
+    // Disallow copy and assign
+    ThermalPredictionsHelper(const ThermalPredictionsHelper &) = delete;
+    void operator=(const ThermalPredictionsHelper &) = delete;
+
+    bool initializePredictionSensors(
+            const std::unordered_map<std::string, SensorInfo> &sensor_info_map);
+    bool updateSensor(std::string_view sensor_name, std::vector<float> &values);
+    SensorReadStatus readSensor(std::string_view sensor_name, float *temp);
+
+  private:
+    std::unordered_map<std::string, PredictorSensorInfo> predictor_sensors_;
+    std::unordered_map<std::string, PredictedSensorInfo> predicted_sensors_;
+    mutable std::shared_mutex sensor_predictions_mutex_;
+
+    bool registerPredictedSensor(std::string_view sensor_name, std::string_view linked_sensor,
+                                 int duration);
+    bool registerPredictorSensor(std::string_view sensor_name, int sample_duration,
+                                 int num_out_samples);
+};
+
+}  // namespace implementation
+}  // namespace thermal
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/thermal/utils/thermal_throttling.cpp b/thermal/utils/thermal_throttling.cpp
index 1e011ec3..b7fc634e 100644
--- a/thermal/utils/thermal_throttling.cpp
+++ b/thermal/utils/thermal_throttling.cpp
@@ -191,14 +191,33 @@ float ThermalThrottling::updatePowerBudget(
     float p = 0, d = 0;
     float power_budget = std::numeric_limits<float>::max();
     bool target_changed = false;
+    bool is_fully_throttle = true;
+    bool is_fully_release = true;
     float budget_transient = 0.0;
     auto &throttling_status = thermal_throttling_status_map_.at(temp.name);
+    const auto &profile = throttling_status.profile;
     std::string sensor_name = temp.name;
 
     if (curr_severity == ThrottlingSeverity::NONE) {
         return power_budget;
     }
 
+    // Go through the binded cdev, check current throttle status
+    for (const auto &binded_cdev_info_pair :
+         ((sensor_info.throttling_info->profile_map.empty() ||
+           !sensor_info.throttling_info->profile_map.contains(profile))
+                  ? sensor_info.throttling_info->binded_cdev_info_map
+                  : sensor_info.throttling_info->profile_map.at(profile))) {
+        if (throttling_status.pid_cdev_request_map.at(binded_cdev_info_pair.first) >
+            binded_cdev_info_pair.second.limit_info[static_cast<size_t>(curr_severity)]) {
+            is_fully_release = false;
+        }
+        if (throttling_status.pid_cdev_request_map.at(binded_cdev_info_pair.first) <
+            binded_cdev_info_pair.second.cdev_ceiling[static_cast<size_t>(curr_severity)]) {
+            is_fully_throttle = false;
+        }
+    }
+
     const auto target_state = getTargetStateOfPID(sensor_info, curr_severity);
     if (throttling_status.prev_target != static_cast<size_t>(ThrottlingSeverity::NONE) &&
         target_state != throttling_status.prev_target &&
@@ -216,9 +235,11 @@ float ThermalThrottling::updatePowerBudget(
         return sensor_info.throttling_info->min_alloc_power[target_state];
     }
 
+    // Calculate P budget
     p = err * (err < 0 ? sensor_info.throttling_info->k_po[target_state]
                        : sensor_info.throttling_info->k_pu[target_state]);
 
+    // Calculate I budget
     if (std::isnan(throttling_status.i_budget)) {
         if (std::isnan(sensor_info.throttling_info->i_default_pct)) {
             throttling_status.i_budget = sensor_info.throttling_info->i_default;
@@ -237,15 +258,16 @@ float ThermalThrottling::updatePowerBudget(
     }
 
     if (err < sensor_info.throttling_info->i_cutoff[target_state]) {
-        if (!(throttling_status.prev_power_budget <=
-                      sensor_info.throttling_info->min_alloc_power[target_state] &&
-              err < 0) &&
-            !(throttling_status.prev_power_budget >=
-                      sensor_info.throttling_info->max_alloc_power[target_state] &&
-              err > 0)) {
-            throttling_status.i_budget +=
-                    err * (err < 0 ? sensor_info.throttling_info->k_io[target_state]
-                                   : sensor_info.throttling_info->k_iu[target_state]);
+        if (err < 0 &&
+            throttling_status.prev_power_budget >
+                    sensor_info.throttling_info->min_alloc_power[target_state] &&
+            !is_fully_throttle) {
+            throttling_status.i_budget += err * sensor_info.throttling_info->k_io[target_state];
+        } else if (err > 0 &&
+                   throttling_status.prev_power_budget <
+                           sensor_info.throttling_info->max_alloc_power[target_state] &&
+                   !is_fully_release) {
+            throttling_status.i_budget += err * sensor_info.throttling_info->k_iu[target_state];
         }
     }
 
@@ -254,6 +276,7 @@ float ThermalThrottling::updatePowerBudget(
                                      (throttling_status.i_budget > 0 ? 1 : -1);
     }
 
+    // Calculate D budget
     if (!std::isnan(throttling_status.prev_err) &&
         time_elapsed_ms != std::chrono::milliseconds::zero()) {
         d = sensor_info.throttling_info->k_d[target_state] * (err - throttling_status.prev_err) /
@@ -392,7 +415,7 @@ bool ThermalThrottling::allocatePowerToCdev(
         }
     }
 
-    // Compute total cdev weight
+    // Go through binded cdev, compute total cdev weight
     for (const auto &binded_cdev_info_pair :
          (sensor_info.throttling_info->profile_map.count(profile)
                   ? sensor_info.throttling_info->profile_map.at(profile)
diff --git a/vibrator/Android.bp b/vibrator/Android.bp
deleted file mode 100644
index a06ec3d4..00000000
--- a/vibrator/Android.bp
+++ /dev/null
@@ -1,67 +0,0 @@
-//
-// Copyright (C) 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_defaults {
-    name: "PixelVibratorDefaults",
-    relative_install_path: "hw",
-    static_libs: [
-        "PixelVibratorCommon",
-    ],
-    shared_libs: [
-        "libbase",
-        "libbinder_ndk",
-        "libcutils",
-        "libhardware",
-        "liblog",
-        "libutils",
-    ],
-    tidy: true,
-    tidy_checks: [
-        "-*",
-        "clang-analyzer-*",
-        "google-*",
-        "cert*",
-        "misc*",
-        "performance*",
-        "-google-readability*",
-        "-misc-const-correctness",
-        "-misc-non-private-member-variables-in-classes",
-    ],
-    tidy_flags: [
-        "-header-filter=hardware/google/pixel/vibrator*",
-    ],
-}
-
-cc_defaults {
-    name: "PixelVibratorBinaryDefaults",
-    defaults: ["PixelVibratorDefaults"],
-    shared_libs: [
-        "android.hardware.vibrator-V2-ndk",
-    ],
-}
-
-cc_defaults {
-    name: "PixelVibratorTestDefaults",
-    defaults: ["PixelVibratorDefaults"],
-    static_libs: [
-        "android.hardware.vibrator-V2-ndk",
-    ],
-    test_suites: ["device-tests"],
-    require_root: true,
-}
diff --git a/vibrator/OWNERS b/vibrator/OWNERS
deleted file mode 100644
index 859c7e07..00000000
--- a/vibrator/OWNERS
+++ /dev/null
@@ -1,4 +0,0 @@
-chrispaulo@google.com
-michaelwr@google.com
-nathankulczak@google.com
-taikuo@google.com
diff --git a/vibrator/common/Android.bp b/vibrator/common/Android.bp
deleted file mode 100644
index 3dd55bf9..00000000
--- a/vibrator/common/Android.bp
+++ /dev/null
@@ -1,228 +0,0 @@
-//
-// Copyright (C) 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-soong_config_module_type {
-    name: "haptics_feature_cc_defaults",
-    module_type: "cc_defaults",
-    config_namespace: "haptics",
-    variables: [
-        "actuator_model",
-        "adaptive_haptics_feature",
-    ],
-    properties: ["cflags"],
-}
-
-soong_config_string_variable {
-    name: "actuator_model",
-    values: [
-        "luxshare_ict_081545",
-        "luxshare_ict_lt_xlra1906d",
-        "legacy_zlra_actuator",
-    ],
-}
-
-soong_config_string_variable {
-    name: "adaptive_haptics_feature",
-    values: [
-        "adaptive_haptics_v1",
-    ],
-}
-
-haptics_feature_cc_defaults {
-    name: "haptics_feature_defaults",
-    soong_config_variables: {
-        actuator_model: {
-            luxshare_ict_081545: {
-                cflags: [
-                    "-DLUXSHARE_ICT_081545",
-                ],
-            },
-            luxshare_ict_lt_xlra1906d: {
-                cflags: [
-                    "-DLUXSHARE_ICT_LT_XLRA1906D",
-                ],
-            },
-            legacy_zlra_actuator: {
-                cflags: [
-                    "-DLEGACY_ZLRA_ACTUATOR",
-                ],
-            },
-            conditions_default: {
-                cflags: [
-                    "-DUNSPECIFIED_ACTUATOR",
-                ],
-            },
-        },
-        adaptive_haptics_feature: {
-            adaptive_haptics_v1: {
-                cflags: [
-                    "-DADAPTIVE_HAPTICS_V1",
-                ],
-            },
-            conditions_default: {
-                cflags: [
-                    "-DDISABLE_ADAPTIVE_HAPTICS_FEATURE",
-                ],
-            },
-        },
-    },
-}
-
-cc_library {
-    name: "libvibecapo_proto",
-    vendor_available: true,
-    owner: "google",
-    defaults: [
-        "VibratorHalCs40l26BinaryDefaults",
-    ],
-    srcs: [
-        "proto/capo.proto",
-    ],
-    export_include_dirs: [
-        "proto",
-    ],
-    proto: {
-        type: "lite",
-        export_proto_headers: true,
-    },
-}
-
-cc_library {
-    name: "VibratorCapo",
-    defaults: [
-        "PixelVibratorBinaryDefaults",
-        "haptics_feature_defaults",
-    ],
-    srcs: [
-        "CapoDetector.cpp",
-    ],
-    shared_libs: [
-        "libcutils",
-        "libprotobuf-cpp-lite",
-    ],
-    static_libs: [
-        "chre_client",
-        "libvibecapo_proto",
-    ],
-    export_include_dirs: [
-        "proto",
-        ".",
-    ],
-    export_static_lib_headers: [
-        "libvibecapo_proto",
-    ],
-    vendor_available: true,
-}
-
-cc_defaults {
-    name: "VibratorCapoDefaults",
-    static_libs: [
-        "chre_client",
-        "libvibecapo_proto",
-        "VibratorCapo",
-    ],
-    shared_libs: [
-        "libprotobuf-cpp-lite",
-    ],
-}
-
-cc_library {
-    name: "PixelVibratorCommon",
-    srcs: [
-        "HardwareBase.cpp",
-    ],
-    shared_libs: [
-        "libbase",
-        "libcutils",
-        "liblog",
-        "libutils",
-    ],
-    cflags: [
-        "-DATRACE_TAG=(ATRACE_TAG_VIBRATOR | ATRACE_TAG_HAL)",
-        "-DLOG_TAG=\"VibratorCommon\"",
-    ],
-    export_include_dirs: ["."],
-    vendor_available: true,
-}
-
-cc_library {
-    name: "PixelVibratorStats",
-    vendor: true,
-    srcs: ["StatsBase.cpp"],
-    cflags: [
-        "-Werror",
-        "-Wall",
-        "-Wextra",
-        "-DATRACE_TAG=(ATRACE_TAG_VIBRATOR | ATRACE_TAG_HAL)",
-        "-DLOG_TAG=\"VibratorStats\"",
-    ],
-    static_libs: [
-        "libvibrator_atoms",
-    ],
-    shared_libs: [
-        "android.frameworks.stats-V2-ndk",
-        "libbase",
-        "libcutils",
-        "libbinder_ndk",
-        "liblog",
-        "libutils",
-    ],
-}
-
-genrule {
-    name: "vibrator_atoms.h",
-    tools: ["stats-log-api-gen"],
-    cmd: "$(location stats-log-api-gen) --header $(out)" +
-        " --module vibrator" +
-        " --namespace android,hardware,google,pixel,VibratorAtoms" +
-        " --vendor-proto hardware/google/pixel/pixelstats/pixelatoms.proto",
-    out: [
-        "vibrator_atoms.h",
-    ],
-    srcs: [
-        ":pixelatoms_proto",
-    ],
-}
-
-genrule {
-    name: "vibrator_atoms.cpp",
-    tools: ["stats-log-api-gen"],
-    cmd: "$(location stats-log-api-gen) --cpp $(out)" +
-        " --module vibrator" +
-        " --importHeader vibrator_atoms.h" +
-        " --namespace android,hardware,google,pixel,VibratorAtoms" +
-        " --vendor-proto hardware/google/pixel/pixelstats/pixelatoms.proto",
-    out: [
-        "vibrator_atoms.cpp",
-    ],
-    srcs: [
-        ":pixelatoms_proto",
-    ],
-}
-
-cc_library_static {
-    name: "libvibrator_atoms",
-    vendor: true,
-    generated_sources: ["vibrator_atoms.cpp"],
-    generated_headers: ["vibrator_atoms.h"],
-    export_generated_headers: ["vibrator_atoms.h"],
-    shared_libs: [
-        "android.frameworks.stats-V2-ndk",
-    ],
-}
diff --git a/vibrator/common/CapoDetector.cpp b/vibrator/common/CapoDetector.cpp
deleted file mode 100644
index a8f3ff2b..00000000
--- a/vibrator/common/CapoDetector.cpp
+++ /dev/null
@@ -1,233 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-#include "CapoDetector.h"
-
-#include <google/protobuf/io/coded_stream.h>
-#include <google/protobuf/io/zero_copy_stream_impl.h>
-#include <google/protobuf/message.h>
-#include <log/log.h>
-
-#ifdef LOG_TAG
-#undef LOG_TAG
-#define LOG_TAG "CapoDetector"
-#endif
-
-namespace android {
-namespace chre {
-
-/**
- * Called when initializing connection with CHRE socket.
- */
-sp<CapoDetector> CapoDetector::start() {
-    sp<CapoDetector> listener = new CapoDetector();
-    if (!listener->connectInBackground(kChreSocketName, listener)) {
-        ALOGE("Couldn't connect to CHRE socket");
-        return nullptr;
-    }
-    ALOGI("%s connect to CHRE socket.", __func__);
-
-    return listener;
-}
-
-/**
- * Called when the socket is successfully (re-)connected.
- * Reset the position and try to send NanoappList request.
- */
-void CapoDetector::onConnected() {
-    flatbuffers::FlatBufferBuilder builder;
-
-    // Reset the last position type.
-    last_position_type_ = capo::PositionType::UNKNOWN;
-
-    HostProtocolHost::encodeNanoappListRequest(builder);
-    if (!sendMessage(builder.GetBufferPointer(), builder.GetSize())) {
-        ALOGE("Failed to send NanoappList request");
-        // We don't return nullptr here so that we don't change the behavior
-    }
-}
-
-/**
- * Called when we have failed to (re-)connect the socket after many attempts
- * and are giving up.
- */
-void CapoDetector::onConnectionAborted() {
-    ALOGE("%s, Capo Aborting Connection!", __func__);
-}
-
-/**
- * Invoked when the socket is disconnected, and this connection loss was not
- * the result of an explicit call to disconnect().
- * Reset the position while disconnecting.
- */
-
-void CapoDetector::onDisconnected() {
-    last_position_type_ = capo::PositionType::UNKNOWN;
-}
-
-/**
- * Decode unix socket msgs to CHRE messages, and call the appropriate
- * callback depending on the CHRE message.
- */
-void CapoDetector::onMessageReceived(const void *data, size_t length) {
-    if (!HostProtocolHost::decodeMessageFromChre(data, length, *this)) {
-        ALOGE("Failed to decode message");
-    }
-}
-
-/**
- * Listen for messages from capo nanoapp and handle the message.
- */
-void CapoDetector::handleNanoappMessage(const fbs::NanoappMessageT &message) {
-    ALOGI("%s, Id %" PRIu64 ", type %d, size %d", __func__, message.app_id, message.message_type,
-          static_cast<int>(message.message.size()));
-    // Exclude the message with unmatched nanoapp id.
-    if (message.app_id != kCapoNanoappId)
-        return;
-
-    // Handle the message with message_type.
-    switch (message.message_type) {
-        case capo::MessageType::ACK_NOTIFICATION: {
-            capo::AckNotification gd;
-            gd.set_notification_type(static_cast<capo::NotificationType>(message.message[1]));
-            ALOGD("%s, get notification event from capo nanoapp, type %d", __func__,
-                  gd.notification_type());
-            break;
-        }
-        case capo::MessageType::POSITION_DETECTED: {
-            uint8_t position;
-            uint32_t time;
-            {
-                std::lock_guard<std::mutex> lock(mCapoMutex);
-                capo::PositionDetected gd;
-                time = getCurrentTimeInMs();
-                gd.set_position_type(static_cast<capo::PositionType>(message.message[1]));
-                ALOGD("CapoDetector: [%u] get position event from capo nanoapp, from %d to %d",
-                      time, last_position_type_, gd.position_type());
-
-                // Record the last moment we were in FACE_UP state
-                if (last_position_type_ == capo::PositionType::ON_TABLE_FACE_UP ||
-                    gd.position_type() == capo::PositionType::ON_TABLE_FACE_UP) {
-                    mLastFaceUpEvent = time;
-                }
-                last_position_type_ = gd.position_type();
-                position = last_position_type_;
-            }
-            // Callback to function while getting carried position event.
-            if (callback_func_ != nullptr) {
-                ALOGD("%s, sent position type %d to callback function", __func__,
-                      last_position_type_);
-                callback_func_(last_position_type_);
-            }
-            break;
-        }
-        default:
-            ALOGE("%s, get invalid message, type: %" PRIu32 ", from capo nanoapp.", __func__,
-                  message.message_type);
-            break;
-    }
-}
-
-/**
- * Handle the response of a NanoappList request.
- * Ensure that capo nanoapp is running.
- */
-void CapoDetector::handleNanoappListResponse(const fbs::NanoappListResponseT &response) {
-    for (const std::unique_ptr<fbs::NanoappListEntryT> &nanoapp : response.nanoapps) {
-        if (nanoapp->app_id == kCapoNanoappId) {
-            if (nanoapp->enabled)
-                enable();
-            else
-                ALOGE("Capo nanoapp not enabled");
-            return;
-        }
-    }
-    ALOGE("Capo nanoapp not found");
-}
-
-/**
- * Send enabling message to the nanoapp.
- */
-void CapoDetector::enable() {
-    // Create CHRE message with serialized message
-    flatbuffers::FlatBufferBuilder builder, config_builder, force_builder;
-
-    auto config_data = std::make_unique<capo::ConfigureDetector_ConfigData>();
-    auto msg = std::make_unique<capo::ConfigureDetector>();
-
-    config_data->set_still_time_threshold_nanosecond(
-            mCapoDetectorMDParameters.still_time_threshold_ns);
-    config_data->set_window_width_nanosecond(mCapoDetectorMDParameters.window_width_ns);
-    config_data->set_motion_confidence_threshold(
-            mCapoDetectorMDParameters.motion_confidence_threshold);
-    config_data->set_still_confidence_threshold(
-            mCapoDetectorMDParameters.still_confidence_threshold);
-    config_data->set_var_threshold(mCapoDetectorMDParameters.var_threshold);
-    config_data->set_var_threshold_delta(mCapoDetectorMDParameters.var_threshold_delta);
-
-    msg->set_allocated_config_data(config_data.release());
-
-    auto pb_size = msg->ByteSizeLong();
-    auto pb_data = std::make_unique<uint8_t[]>(pb_size);
-
-    if (!msg->SerializeToArray(pb_data.get(), pb_size)) {
-        ALOGE("Failed to serialize message.");
-    }
-
-    ALOGI("Configuring CapoDetector");
-    // Configure the detector from host-side
-    ::android::chre::HostProtocolHost::encodeNanoappMessage(
-            config_builder, getNanoppAppId(), capo::MessageType::CONFIGURE_DETECTOR,
-            getHostEndPoint(), pb_data.get(), pb_size);
-    ALOGI("Sending capo config message to Nanoapp, %" PRIu32 " bytes", config_builder.GetSize());
-    if (!sendMessage(config_builder.GetBufferPointer(), config_builder.GetSize())) {
-        ALOGE("Failed to send config event for capo nanoapp");
-    }
-
-    ALOGI("Enabling CapoDetector");
-    ::android::chre::HostProtocolHost::encodeNanoappMessage(
-            builder, getNanoppAppId(), capo::MessageType::ENABLE_DETECTOR, getHostEndPoint(),
-            /*messageData*/ nullptr, /*messageDataLenbuffer*/ 0);
-    ALOGI("Sending enable message to Nanoapp, %" PRIu32 " bytes", builder.GetSize());
-    if (!sendMessage(builder.GetBufferPointer(), builder.GetSize())) {
-        ALOGE("Failed to send enable event for capo nanoapp");
-    }
-
-    ALOGI("Forcing CapoDetector to update state");
-    // Force an updated state upon connection
-    ::android::chre::HostProtocolHost::encodeNanoappMessage(
-            force_builder, getNanoppAppId(), capo::MessageType::FORCE_UPDATE, getHostEndPoint(),
-            /*messageData*/ nullptr, /*messageDataLenbuffer*/ 0);
-    ALOGI("Sending force-update message to Nanoapp, %" PRIu32 " bytes", force_builder.GetSize());
-    if (!sendMessage(force_builder.GetBufferPointer(), force_builder.GetSize())) {
-        ALOGE("Failed to send force-update event for capo nanoapp");
-    }
-}
-
-/**
- * Method for gathering the position and time tuple simultaneously to avoid any
- * concurrency issues.
- */
-void CapoDetector::getCarriedPositionInfo(uint8_t *position, uint32_t *time) {
-    std::lock_guard<std::mutex> lock(mCapoMutex);
-    if (position)
-        *position = last_position_type_;
-    if (time)
-        *time = mLastFaceUpEvent;
-}
-
-}  // namespace chre
-}  // namespace android
diff --git a/vibrator/common/CapoDetector.h b/vibrator/common/CapoDetector.h
deleted file mode 100644
index f8cdc6fa..00000000
--- a/vibrator/common/CapoDetector.h
+++ /dev/null
@@ -1,118 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-#include <chre_host/host_protocol_host.h>
-#include <chre_host/socket_client.h>
-
-#include <chrono>
-
-#include "proto/capo.pb.h"
-
-using android::sp;
-using android::chre::HostProtocolHost;
-using android::chre::IChreMessageHandlers;
-using android::chre::SocketClient;
-
-// following convention of CHRE code.
-namespace fbs = ::chre::fbs;
-
-namespace android {
-namespace chre {
-
-#define NS_FROM_MS(x) ((x)*1000000)
-
-struct CapoMDParams {
-    uint64_t still_time_threshold_ns;
-    uint32_t window_width_ns;
-    float motion_confidence_threshold;
-    float still_confidence_threshold;
-    float var_threshold;
-    float var_threshold_delta;
-};
-
-class CapoDetector : public android::chre::SocketClient::ICallbacks,
-                     public android::chre::IChreMessageHandlers,
-                     public android::chre::SocketClient {
-  public:
-    // Typedef declaration for callback function.
-    typedef std::function<void(uint8_t)> cb_fn_t;
-
-    // Called when initializing connection with CHRE socket.
-    static android::sp<CapoDetector> start();
-    // Common getTime function to share
-    static uint32_t getCurrentTimeInMs() {
-        return std::chrono::duration_cast<std::chrono::milliseconds>(
-                       std::chrono::system_clock::now().time_since_epoch())
-                .count();
-    }
-    // Called when the socket is successfully (re-)connected.
-    // Reset the position and try to send NanoappList request.
-    void onConnected() override;
-    // Called when we have failed to (re-)connect the socket after many attempts
-    // and are giving up.
-    void onConnectionAborted() override;
-    // Invoked when the socket is disconnected, and this connection loss
-    // was not the result of an explicit call to disconnect().
-    // Reset the position while disconnecting.
-    void onDisconnected() override;
-    // Decode unix socket msgs to CHRE messages, and call the appropriate
-    // callback depending on the CHRE message.
-    void onMessageReceived(const void *data, size_t length) override;
-    // Listen for messages from capo nanoapp and handle the message.
-    void handleNanoappMessage(const ::chre::fbs::NanoappMessageT &message) override;
-    // Handle the response of a NanoappList request.
-    // Ensure that capo nanoapp is running.
-    void handleNanoappListResponse(const ::chre::fbs::NanoappListResponseT &response) override;
-    // Send enabling message to the nanoapp.
-    void enable();
-    // Get last carried position type and time simultaneously.
-    void getCarriedPositionInfo(uint8_t *position, uint32_t *time);
-    // Get last carried position type.
-    uint8_t getCarriedPosition() { return last_position_type_; }
-    // Get the host endpoint.
-    uint16_t getHostEndPoint() { return kHostEndpoint; }
-    // Get the capo nanoapp ID.
-    uint64_t getNanoppAppId() { return kCapoNanoappId; }
-    // Set up callback_func_ if needed.
-    void setCallback(cb_fn_t cb) { callback_func_ = cb; }
-
-  private:
-    // Nanoapp ID of capo, ref: go/nanoapp-id-tracker.
-    static constexpr uint64_t kCapoNanoappId = 0x476f6f676c001020ULL;
-    // String of socket name for connecting chre.
-    static constexpr char kChreSocketName[] = "chre";
-    // The host endpoint we use when sending message.
-    // Set with 0x9020 based on 0x8000 AND capo_app_id(1020).
-    // Ref: go/host-endpoint-id-tracker.
-    static constexpr uint16_t kHostEndpoint = 0x9020;
-    // Using for hal layer callback function.
-    cb_fn_t callback_func_ = nullptr;
-    // Last carried position received from the nano app
-    capo::PositionType last_position_type_ = capo::PositionType::UNKNOWN;
-    // Last face up event
-    uint32_t mLastFaceUpEvent = 0;
-    // Mutex for time + position tuple
-    std::mutex mCapoMutex;
-    // Motion detector parameters for host-driven capo config
-    const struct CapoMDParams mCapoDetectorMDParameters {
-        .still_time_threshold_ns = NS_FROM_MS(500), .window_width_ns = NS_FROM_MS(100),
-        .motion_confidence_threshold = 0.98f, .still_confidence_threshold = 0.99f,
-        .var_threshold = 0.0125f, .var_threshold_delta = 0.0125f,
-    };
-};
-
-}  // namespace chre
-}  // namespace android
diff --git a/vibrator/common/HardwareBase.cpp b/vibrator/common/HardwareBase.cpp
deleted file mode 100644
index fb15523a..00000000
--- a/vibrator/common/HardwareBase.cpp
+++ /dev/null
@@ -1,132 +0,0 @@
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
-#include "HardwareBase.h"
-
-#include <cutils/properties.h>
-#include <log/log.h>
-
-#include <fstream>
-#include <sstream>
-
-#include "utils.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-HwApiBase::HwApiBase() {
-    mPathPrefix = std::getenv("HWAPI_PATH_PREFIX") ?: "";
-    if (mPathPrefix.empty() && (std::getenv("INPUT_EVENT_NAME") == NULL)) {
-        ALOGE("Failed to get HWAPI path prefix!");
-    }
-}
-
-void HwApiBase::saveName(const std::string &name, const std::ios *stream) {
-    mNames[stream] = name;
-}
-
-void HwApiBase::debug(int fd) {
-    dprintf(fd, "Kernel:\n");
-
-    for (auto &entry : utils::pathsFromEnv("HWAPI_DEBUG_PATHS", mPathPrefix)) {
-        auto &path = entry.first;
-        auto &stream = entry.second;
-        std::string line;
-
-        dprintf(fd, "  %s:\n", path.c_str());
-        while (std::getline(stream, line)) {
-            dprintf(fd, "    %s\n", line.c_str());
-        }
-    }
-
-    mRecordsMutex.lock();
-    dprintf(fd, "  Records:\n");
-    for (auto &r : mRecords) {
-        if (r == nullptr) {
-            continue;
-        }
-        dprintf(fd, "    %s\n", r->toString(mNames).c_str());
-    }
-    mRecordsMutex.unlock();
-}
-
-HwCalBase::HwCalBase() {
-    std::ifstream calfile;
-    auto propertyPrefix = std::getenv("PROPERTY_PREFIX");
-
-    if (propertyPrefix != NULL) {
-        mPropertyPrefix = std::string(propertyPrefix);
-    } else {
-        ALOGE("Failed get property prefix!");
-    }
-
-    utils::fileFromEnv("CALIBRATION_FILEPATH", &calfile);
-
-    for (std::string line; std::getline(calfile, line);) {
-        if (line.empty() || line[0] == '#') {
-            continue;
-        }
-        std::istringstream is_line(line);
-        std::string key, value;
-        if (std::getline(is_line, key, ':') && std::getline(is_line, value)) {
-            mCalData[utils::trim(key)] = utils::trim(value);
-        }
-    }
-}
-
-void HwCalBase::debug(int fd) {
-    std::ifstream stream;
-    std::string path;
-    std::string line;
-    struct context {
-        HwCalBase *obj;
-        int fd;
-    } context{this, fd};
-
-    dprintf(fd, "Properties:\n");
-
-    property_list(
-            [](const char *key, const char *value, void *cookie) {
-                struct context *context = static_cast<struct context *>(cookie);
-                HwCalBase *obj = context->obj;
-                int fd = context->fd;
-                const std::string expect{obj->mPropertyPrefix};
-                const std::string actual{key, std::min(strlen(key), expect.size())};
-                if (actual == expect) {
-                    dprintf(fd, "  %s:\n", key);
-                    dprintf(fd, "    %s\n", value);
-                }
-            },
-            &context);
-
-    dprintf(fd, "\n");
-
-    dprintf(fd, "Persist:\n");
-
-    utils::fileFromEnv("CALIBRATION_FILEPATH", &stream, &path);
-
-    dprintf(fd, "  %s:\n", path.c_str());
-    while (std::getline(stream, line)) {
-        dprintf(fd, "    %s\n", line.c_str());
-    }
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/common/HardwareBase.h b/vibrator/common/HardwareBase.h
deleted file mode 100644
index d038c198..00000000
--- a/vibrator/common/HardwareBase.h
+++ /dev/null
@@ -1,251 +0,0 @@
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
-#pragma once
-
-#include <android-base/stringprintf.h>
-#include <android-base/unique_fd.h>
-#include <log/log.h>
-#include <sys/epoll.h>
-#include <utils/Trace.h>
-
-#include <chrono>
-#include <list>
-#include <map>
-#include <sstream>
-#include <string>
-#include <type_traits>
-
-#include "utils.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::android::base::StringPrintf;
-using ::android::base::unique_fd;
-
-class HwApiBase {
-  private:
-    using NamesMap = std::map<const std::ios *, std::string>;
-
-    class RecordInterface {
-      public:
-        virtual std::string toString(const NamesMap &names) = 0;
-        virtual ~RecordInterface() {}
-    };
-    template <typename T>
-    class Record : public RecordInterface {
-      public:
-        Record(const char *func, const T &value, const std::ios *stream)
-            : mFunc(func),
-              mValue(value),
-              mStream(stream),
-              mTp(std::chrono::system_clock::system_clock::now()) {}
-        std::string toString(const NamesMap &names) override;
-
-      private:
-        const char *mFunc;
-        const T mValue;
-        const std::ios *mStream;
-        const std::chrono::system_clock::time_point mTp;
-    };
-    using Records = std::list<std::unique_ptr<RecordInterface>>;
-
-    static constexpr uint32_t RECORDS_SIZE = 2048;
-
-  public:
-    HwApiBase();
-    void debug(int fd);
-
-  protected:
-    void updatePathPrefix(const std::string &prefix) {
-        ALOGI("Update HWAPI path prefix to %s", prefix.c_str());
-        mPathPrefix = prefix;
-    }
-    void saveName(const std::string &name, const std::ios *stream);
-    template <typename T>
-    void open(const std::string &name, T *stream);
-    template <typename T>
-    bool has(const T &stream);
-    template <typename T>
-    bool get(T *value, std::istream *stream);
-    template <typename T>
-    bool set(const T &value, std::ostream *stream);
-    template <typename T>
-    bool poll(const T &value, std::istream *stream, const int32_t timeout = -1);
-    template <typename T>
-    void record(const char *func, const T &value, const std::ios *stream);
-
-  private:
-    std::string mPathPrefix;
-    NamesMap mNames;
-    Records mRecords{RECORDS_SIZE};
-    std::mutex mRecordsMutex;
-    std::mutex mIoMutex;
-};
-
-#define HWAPI_RECORD(args...) HwApiBase::record(__FUNCTION__, ##args)
-
-template <typename T>
-void HwApiBase::open(const std::string &name, T *stream) {
-    saveName(name, stream);
-    utils::openNoCreate(mPathPrefix + name, stream);
-}
-
-template <typename T>
-bool HwApiBase::has(const T &stream) {
-    if constexpr (std::is_same<T, std::fstream>::value || std::is_same<T, std::ofstream>::value ||
-                  std::is_same<T, std::ifstream>::value)
-        return stream.is_open() && !stream.fail();
-
-    ALOGE("File stream is not of the correct type");
-    return false;
-}
-
-template <typename T>
-bool HwApiBase::get(T *value, std::istream *stream) {
-    ATRACE_NAME("HwApi::get");
-    std::scoped_lock ioLock{mIoMutex};
-    bool ret;
-    stream->seekg(0);
-    *stream >> *value;
-    if (!(ret = !!*stream)) {
-        ALOGE("Failed to read %s (%d): %s", mNames[stream].c_str(), errno, strerror(errno));
-    }
-    stream->clear();
-    HWAPI_RECORD(*value, stream);
-    return ret;
-}
-
-template <typename T>
-bool HwApiBase::set(const T &value, std::ostream *stream) {
-    ATRACE_NAME("HwApi::set");
-    using utils::operator<<;
-    std::scoped_lock ioLock{mIoMutex};
-    bool ret;
-    *stream << value << std::endl;
-    if (!(ret = !!*stream)) {
-        ALOGE("Failed to write %s (%d): %s", mNames[stream].c_str(), errno, strerror(errno));
-        stream->clear();
-    }
-    HWAPI_RECORD(value, stream);
-    return ret;
-}
-
-template <typename T>
-bool HwApiBase::poll(const T &value, std::istream *stream, const int32_t timeoutMs) {
-    ATRACE_NAME(StringPrintf("HwApi::poll %s==%s", mNames[stream].c_str(),
-                             std::to_string(value).c_str())
-                        .c_str());
-    auto path = mPathPrefix + mNames[stream];
-    unique_fd fileFd{::open(path.c_str(), O_RDONLY)};
-    unique_fd epollFd{epoll_create(1)};
-    epoll_event event = {
-            .events = EPOLLPRI | EPOLLET,
-    };
-    T actual;
-    bool ret;
-    int epollRet;
-
-    if (timeoutMs < -1) {
-        ALOGE("Invalid polling timeout!");
-        return false;
-    }
-
-    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fileFd, &event)) {
-        ALOGE("Failed to poll %s (%d): %s", mNames[stream].c_str(), errno, strerror(errno));
-        return false;
-    }
-
-    while ((ret = get(&actual, stream)) && (actual != value)) {
-        epollRet = epoll_wait(epollFd, &event, 1, timeoutMs);
-        if (epollRet <= 0) {
-            ALOGE("Polling error or timeout! (%d)", epollRet);
-            return false;
-        }
-    }
-
-    HWAPI_RECORD(value, stream);
-    return ret;
-}
-
-template <typename T>
-void HwApiBase::record(const char *func, const T &value, const std::ios *stream) {
-    std::lock_guard<std::mutex> lock(mRecordsMutex);
-    mRecords.emplace_back(std::make_unique<Record<T>>(func, value, stream));
-    mRecords.pop_front();
-}
-
-template <typename T>
-std::string HwApiBase::Record<T>::toString(const NamesMap &names) {
-    using utils::operator<<;
-    std::stringstream ret;
-    auto lTp = std::chrono::system_clock::to_time_t(mTp);
-    struct tm buf;
-    auto lTime = localtime_r(&lTp, &buf);
-
-    ret << std::put_time(lTime, "%Y-%m-%d %H:%M:%S.") << std::setfill('0') << std::setw(3)
-        << (std::chrono::duration_cast<std::chrono::milliseconds>(mTp.time_since_epoch()) % 1000)
-                    .count()
-        << "    " << mFunc << " '" << names.at(mStream) << "' = '" << mValue << "'";
-    return ret.str();
-}
-
-class HwCalBase {
-  public:
-    HwCalBase();
-    void debug(int fd);
-
-  protected:
-    template <typename T>
-    bool getProperty(const char *key, T *value, const T defval);
-    template <typename T>
-    bool getPersist(const char *key, T *value);
-
-  private:
-    std::string mPropertyPrefix;
-    std::map<std::string, std::string> mCalData;
-};
-
-template <typename T>
-bool HwCalBase::getProperty(const char *key, T *outval, const T defval) {
-    ATRACE_NAME("HwCal::getProperty");
-    *outval = utils::getProperty(mPropertyPrefix + key, defval);
-    return true;
-}
-
-template <typename T>
-bool HwCalBase::getPersist(const char *key, T *value) {
-    ATRACE_NAME("HwCal::getPersist");
-    auto it = mCalData.find(key);
-    if (it == mCalData.end()) {
-        ALOGE("Missing %s config!", key);
-        return false;
-    }
-    std::stringstream stream{it->second};
-    utils::unpack(stream, value);
-    if (!stream || !stream.eof()) {
-        ALOGE("Invalid %s config!", key);
-        return false;
-    }
-    return true;
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/common/StatsBase.cpp b/vibrator/common/StatsBase.cpp
deleted file mode 100644
index 9160d81a..00000000
--- a/vibrator/common/StatsBase.cpp
+++ /dev/null
@@ -1,258 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#include "StatsBase.h"
-
-#include <aidl/android/frameworks/stats/IStats.h>
-#include <android/binder_manager.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-#include <vibrator_atoms.h>
-
-#include <chrono>
-#include <sstream>
-
-using ::aidl::android::frameworks::stats::IStats;
-using ::aidl::android::frameworks::stats::VendorAtom;
-
-namespace VibratorAtoms = ::android::hardware::google::pixel::VibratorAtoms;
-
-using VibratorAtoms::createVendorAtom;
-
-#ifndef ARRAY_SIZE
-#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
-#endif
-
-#ifdef TRACE_STATS
-static const char *kAtomLookup[] = {"HAPTICS_PLAYCOUNTS", "HAPTICS_LATENCIES", "HAPTICS_ERRORS",
-                                    "INVALID"};
-
-const char *atomToString(uint32_t atomId) {
-    switch (atomId) {
-        case VibratorAtoms::VIBRATOR_PLAYCOUNT_REPORTED:
-            return kAtomLookup[0];
-            break;
-        case VibratorAtoms::VIBRATOR_LATENCY_REPORTED:
-            return kAtomLookup[1];
-            break;
-        case VibratorAtoms::VIBRATOR_ERRORS_REPORTED:
-            return kAtomLookup[2];
-            break;
-        default:
-            return kAtomLookup[ARRAY_SIZE(kAtomLookup) - 1];
-            break;
-    }
-}
-
-#define STATS_TRACE(...)   \
-    ATRACE_NAME(__func__); \
-    ALOGD(__VA_ARGS__)
-#else
-#define STATS_TRACE(...) ATRACE_NAME(__func__)
-#define atomToString(x)
-#endif
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-#ifdef FAST_LOG
-static constexpr auto UPLOAD_INTERVAL = std::chrono::minutes(1);
-#else
-static constexpr auto UPLOAD_INTERVAL = std::chrono::hours(24);
-#endif
-
-static void reportVendorAtom(const std::shared_ptr<IStats> &statsClient, const VendorAtom &atom) {
-    STATS_TRACE("   reportVendorAtom(statsClient, atom: %s)", atomToString(atom.atomId));
-    const ndk::ScopedAStatus status = statsClient->reportVendorAtom(atom);
-    if (status.isOk()) {
-        ALOGI("Vendor atom [id = %d] reported.", atom.atomId);
-    } else {
-        ALOGE("Failed to report atom [id = %d].", atom.atomId);
-    }
-}
-
-static std::string dumpData(const std::vector<int32_t> &data) {
-    std::stringstream stream;
-    for (auto datum : data) {
-        stream << " " << datum;
-    }
-    return stream.str();
-}
-
-StatsBase::StatsBase(const std::string &instance)
-    : mReporterThread([this]() { runReporterThread(); }),
-      kStatsInstanceName(std::string() + IStats::descriptor + "/" + instance) {}
-
-StatsBase::~StatsBase() {}
-
-void StatsBase::debug(int fd) {
-    STATS_TRACE("debug(fd: %d)", fd);
-
-    dprintf(fd, "Stats:\n");
-    {
-        std::scoped_lock<std::mutex> lock(mDataAccess);
-        dprintf(fd, "  Waveform Counts:%s\n", dumpData(mWaveformCounts).c_str());
-        dprintf(fd, "  Duration Counts:%s\n", dumpData(mDurationCounts).c_str());
-        dprintf(fd, "  Min Latencies:%s\n", dumpData(mMinLatencies).c_str());
-        dprintf(fd, "  Max Latencies:%s\n", dumpData(mMaxLatencies).c_str());
-        dprintf(fd, "  Latency Totals:%s\n", dumpData(mLatencyTotals).c_str());
-        dprintf(fd, "  Latency Counts:%s\n", dumpData(mLatencyCounts).c_str());
-        dprintf(fd, "  Error Counts: %s\n", dumpData(mErrorCounts).c_str());
-    }
-}
-
-void StatsBase::reportVendorAtomAsync(const VendorAtom &atom) {
-    STATS_TRACE("reportVendorAtomAsync(atom: %s)", atomToString(atom.atomId));
-    std::scoped_lock<std::mutex> lock(mAtomQueueAccess);
-    mAtomQueue.push_back(atom);
-    mAtomQueueUpdated.notify_all();
-}
-
-void StatsBase::uploadDiagnostics() {
-    STATS_TRACE("uploadDiagnostics()");
-    uploadPlaycountAtoms();
-    uploadLatencyAtoms();
-    uploadErrorAtoms();
-}
-
-std::shared_ptr<IStats> StatsBase::waitForStatsService() const {
-    STATS_TRACE("waitForStatsService()");
-    if (!AServiceManager_isDeclared(kStatsInstanceName.c_str())) {
-        ALOGE("IStats service '%s' is not registered.", kStatsInstanceName.c_str());
-        return nullptr;
-    }
-
-    ALOGI("Waiting for IStats service '%s' to come up.", kStatsInstanceName.c_str());
-    std::shared_ptr<IStats> client = IStats::fromBinder(
-            ndk::SpAIBinder(AServiceManager_waitForService(kStatsInstanceName.c_str())));
-    if (!client) {
-        ALOGE("Failed to get IStats service '%s'.", kStatsInstanceName.c_str());
-        return nullptr;
-    }
-    ALOGI("IStats service online.");
-    return client;
-}
-
-void StatsBase::runReporterThread() {
-    STATS_TRACE("runReporterThread()");
-    using clock = std::chrono::steady_clock;
-    auto nextUpload = clock::now() + UPLOAD_INTERVAL;
-    auto status = std::cv_status::no_timeout;
-
-    while (!mTerminateReporterThread) {
-        drainAtomQueue();
-        {
-            std::unique_lock<std::mutex> lock(mAtomQueueAccess);
-            if (!mAtomQueue.empty())
-                continue;
-            status = mAtomQueueUpdated.wait_until(lock, nextUpload);
-        }
-
-        if (status == std::cv_status::timeout) {
-            nextUpload = clock::now() + UPLOAD_INTERVAL;
-            uploadDiagnostics();
-        }
-    }
-}
-
-void StatsBase::drainAtomQueue() {
-    STATS_TRACE("drainAtomQueue()");
-    std::vector<VendorAtom> tempQueue;
-    {
-        std::unique_lock<std::mutex> lock(mAtomQueueAccess);
-        std::swap(mAtomQueue, tempQueue);
-    }
-
-    std::shared_ptr<IStats> client = waitForStatsService();
-    if (!client) {
-        ALOGE("Failed to get IStats service. Atoms are dropped.");
-        return;
-    }
-
-    for (const VendorAtom &atom : tempQueue) {
-        reportVendorAtom(client, atom);
-    }
-}
-
-void StatsBase::uploadPlaycountAtoms() {
-    STATS_TRACE("uploadPlaycountAtoms()");
-    VendorAtom playcountAtom = vibratorPlaycountAtom();
-    reportVendorAtomAsync(playcountAtom);
-    clearData(&mWaveformCounts);
-    clearData(&mDurationCounts);
-}
-
-void StatsBase::uploadLatencyAtoms() {
-    STATS_TRACE("uploadLatencyAtoms()");
-    VendorAtom latencyAtom = vibratorLatencyAtom();
-    reportVendorAtomAsync(latencyAtom);
-    clearData(&mMinLatencies);
-    clearData(&mMaxLatencies);
-    clearData(&mLatencyTotals);
-    clearData(&mLatencyCounts);
-}
-
-void StatsBase::uploadErrorAtoms() {
-    STATS_TRACE("uploadErrorAtoms()");
-    VendorAtom errorAtom = vibratorErrorAtom();
-    reportVendorAtomAsync(errorAtom);
-    clearData(&mErrorCounts);
-}
-
-void StatsBase::clearData(std::vector<int32_t> *data) {
-    STATS_TRACE("clearData(data)");
-    if (data) {
-        std::scoped_lock<std::mutex> lock(mDataAccess);
-        std::fill((*data).begin(), (*data).end(), 0);
-    }
-}
-
-VendorAtom StatsBase::vibratorPlaycountAtom() {
-    STATS_TRACE("vibratorPlaycountAtom()");
-    std::scoped_lock<std::mutex> lock(mDataAccess);
-    return createVendorAtom(VibratorAtoms::VIBRATOR_PLAYCOUNT_REPORTED, "", mWaveformCounts,
-                            mDurationCounts);
-}
-
-VendorAtom StatsBase::vibratorLatencyAtom() {
-    STATS_TRACE("vibratorLatencyAtom()");
-    std::vector<int32_t> avgLatencies;
-
-    std::scoped_lock<std::mutex> lock(mDataAccess);
-    for (uint32_t i = 0; i < mLatencyCounts.size(); i++) {
-        int32_t avg = 0;
-        if (mLatencyCounts[0] > 0) {
-            avg = mLatencyTotals[i] / mLatencyCounts[i];
-        }
-        avgLatencies.push_back(avg);
-    }
-
-    return createVendorAtom(VibratorAtoms::VIBRATOR_LATENCY_REPORTED, "", mMinLatencies,
-                            mMaxLatencies, avgLatencies);
-}
-
-VendorAtom StatsBase::vibratorErrorAtom() {
-    STATS_TRACE("vibratorErrorAtom()");
-    std::scoped_lock<std::mutex> lock(mDataAccess);
-    return createVendorAtom(VibratorAtoms::VIBRATOR_ERRORS_REPORTED, "", mErrorCounts);
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/common/StatsBase.h b/vibrator/common/StatsBase.h
deleted file mode 100644
index 2b0d9867..00000000
--- a/vibrator/common/StatsBase.h
+++ /dev/null
@@ -1,95 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#pragma once
-
-#include <utils/SystemClock.h>
-
-#include <cinttypes>
-#include <mutex>
-#include <thread>
-#include <vector>
-
-/* Forward declaration to speed-up build and avoid build errors. Clients of this
- * library force to use C++11 std, when AIDL auto-generated code uses features
- * from more recent C++ version. */
-namespace aidl {
-namespace android {
-namespace frameworks {
-namespace stats {
-
-class VendorAtom;
-class IStats;
-
-}  // namespace stats
-}  // namespace frameworks
-}  // namespace android
-}  // namespace aidl
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-class StatsBase {
-  public:
-    using VendorAtom = ::aidl::android::frameworks::stats::VendorAtom;
-    using IStats = ::aidl::android::frameworks::stats::IStats;
-
-    StatsBase(const std::string &instance);
-    ~StatsBase();
-
-    void debug(int fd);
-
-  protected:
-    std::vector<int32_t> mWaveformCounts;
-    std::vector<int32_t> mDurationCounts;
-    std::vector<int32_t> mMinLatencies;
-    std::vector<int32_t> mMaxLatencies;
-    std::vector<int32_t> mLatencyTotals;
-    std::vector<int32_t> mLatencyCounts;
-    std::vector<int32_t> mErrorCounts;
-    std::mutex mDataAccess;
-
-  private:
-    void runReporterThread();
-    void reportVendorAtomAsync(const VendorAtom &atom);
-    void uploadDiagnostics();
-    std::shared_ptr<IStats> waitForStatsService() const;
-    void drainAtomQueue();
-
-    void uploadPlaycountAtoms();
-    void uploadLatencyAtoms();
-    void uploadErrorAtoms();
-
-    void clearData(std::vector<int32_t> *data);
-
-    VendorAtom vibratorPlaycountAtom();
-    VendorAtom vibratorLatencyAtom();
-    VendorAtom vibratorErrorAtom();
-
-    std::thread mReporterThread;
-    std::vector<VendorAtom> mAtomQueue;
-    std::mutex mAtomQueueAccess;
-    std::condition_variable mAtomQueueUpdated;
-    bool mTerminateReporterThread = false;
-
-    const std::string kStatsInstanceName;
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/common/proto/capo.proto b/vibrator/common/proto/capo.proto
deleted file mode 100644
index 2b1939cc..00000000
--- a/vibrator/common/proto/capo.proto
+++ /dev/null
@@ -1,164 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-syntax = "proto3";
-
-package capo;
-
-// The message types used in capo nanoapp. Some of them are H2C
-// (Host-To-CHRE) and others are C2H (CHRE-To-Host). One message type must be
-// either H2C or C2H. Each message type can choose to have payload or not.
-enum MessageType {
-  // Explicitly prevents 0 from being used as a valid message type.
-  // Doing so protects from obscure bugs caused by default-initialized values.
-  INVALID = 0;
-
-  // Detector configuration related message start from 100.
-  // Signal for host to acknowledge the notification.
-  // It contains AckNotification payload.
-  ACK_NOTIFICATION = 100;
-
-  // Signal to enable the carried position detector for device. No payload.
-  ENABLE_DETECTOR = 101;
-
-  // Signal to disable the carried position detector for device. No payload.
-  DISABLE_DETECTOR = 102;
-
-  // Signal to request most recent carried position detector state. No payload.
-  REQUEST_UPDATE = 103;
-
-  // Signal to force carried position detector to refresh state. No payload.
-  FORCE_UPDATE = 104;
-
-  // Configure the detector with desired parameters. ConfigureDetector payload.
-  CONFIGURE_DETECTOR = 105;
-
-  // Position Detection related message start from 200.
-  // Signal while carried position of device detected.
-  // It contains PositionDetected payload.
-  POSITION_DETECTED = 200;
-}
-
-// Notification Type.
-enum NotificationType {
-  // Explicitly prevents 0 from being used as a valid notification type.
-  // Doing so protects from obscure bugs caused by default-initialized values.
-  INVALID_NOTIFICATION = 0;
-
-  // Notification of enabling the carried position detector for device.
-  ENABLE_NOTIFICATION = 1;
-
-  // Notification of disabling the carried position detector for device.
-  DISABLE_NOTIFICATION = 2;
-
-  // Notification of request update from the carried position detector.
-  REQUEST_UPDATE_NOTIFICATION = 3;
-
-  // Notification of force update from the carried position detector.
-  FORCE_UPDATE_NOTIFICATION = 4;
-
-  // Notification of configure message.
-  CONFIGURE_NOTIFICATION = 5;
-}
-
-// This message type used for host to acknowledge the notification.
-message AckNotification {
-  // Sent a notification type for host to acknowledge.
-  NotificationType notification_type = 1;
-}
-
-// Position type.
-enum PositionType {
-  // Explicitly prevents 0 from being used as a valid carried position type.
-  // Doing so protects from obscure bugs caused by default-initialized values.
-  UNKNOWN = 0;
-
-  // Carried position while device is in motion.
-  IN_MOTION = 1;
-
-  // Carried position while device is on table and faces up.
-  ON_TABLE_FACE_UP = 2;
-
-  // Carried position while device is on table and faces down.
-  ON_TABLE_FACE_DOWN = 3;
-
-  // Carried position while device is stationary in unknown orientation.
-  STATIONARY_UNKNOWN = 4;
-}
-
-// This message type used to notify host a position was a detected.
-message PositionDetected {
-  // Sent a position type that is defined in PositionTypes.
-  PositionType position_type = 1;
-}
-
-// Predefined configurations for detector.
-enum ConfigPresetType {
-  // Explicitly prevents 0 from being used as a valid type.
-  // Doing so protects from obscure bugs caused by default-initialized values.
-  CONFIG_PRESET_UNSPECIFIED = 0;
-
-  // Default preset.
-  CONFIG_PRESET_DEFAULT = 1;
-
-  // Preset for sticky-stationary behavior.
-  CONFIG_PRESET_STICKY_STATIONARY = 2;
-}
-
-message ConfigureDetector {
-  // Ref: cs/location/lbs/contexthub/nanoapps/motiondetector/motion_detector.h
-  message ConfigData {
-    // These algo parameters are exposed to enable tuning via server flags.
-    // The amount of time that the algorithm's computed stillness confidence
-    // must exceed still_confidence_threshold before entering the stationary
-    // state. Increasing this value will make the algorithm take longer to
-    // transition from the in motion state to the stationary state.
-    uint64 still_time_threshold_nanosecond = 1;
-
-    // The amount of time in which the variance should be averaged. Increasing
-    // this value will effectively smooth the input data, making the algorithm
-    // less likely to transition between states.
-    uint32 window_width_nanosecond = 2;
-
-    // The required confidence that the device is in motion before entering the
-    // motion state. Valid range is [0.0, 1.0], where 1.0 indicates that the
-    // algorithm must be 100% certain that the device is moving before entering
-    // the motion state. If the Instant Motion sensor is triggered, this value
-    // is ignored and the algorithm is immediately transitioned into the in
-    // motion state.
-    float motion_confidence_threshold = 3;
-
-    // The required confidence that the device is stationary before entering the
-    // stationary state. Valid range is [0.0, 1.0], where 1.0 indicates that the
-    // algorithm must be 100% certain that the device is stationary before
-    // entering the stationary state.
-    float still_confidence_threshold = 4;
-
-    // The variance threshold for the StillnessDetector algorithm. Increasing
-    // this value causes the algorithm to be less likely to detect motion.
-    float var_threshold = 5;
-
-    // The variance threshold delta for the StillnessDetector algorithm about
-    // which the stationary confidence is calculated. Valid range is
-    // [0.0, var_threshold].
-    float var_threshold_delta = 6;
-  }
-
-  oneof type {
-    ConfigPresetType preset_type = 1;
-    ConfigData config_data = 2;
-  }
-}
diff --git a/vibrator/common/utils.h b/vibrator/common/utils.h
deleted file mode 100644
index b5005a6f..00000000
--- a/vibrator/common/utils.h
+++ /dev/null
@@ -1,188 +0,0 @@
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
-#pragma once
-
-#include <android-base/macros.h>
-#include <android-base/parsedouble.h>
-#include <android-base/properties.h>
-#include <log/log.h>
-
-#include <fstream>
-#include <map>
-#include <sstream>
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-namespace utils {
-
-template <typename T>
-class Is_Iterable {
-  private:
-    template <typename U>
-    static std::true_type test(typename U::iterator *u);
-
-    template <typename U>
-    static std::false_type test(U *u);
-
-  public:
-    static const bool value = decltype(test<T>(0))::value;
-};
-
-template <typename T, bool B>
-using Enable_If_Iterable = std::enable_if_t<Is_Iterable<T>::value == B>;
-
-template <typename T, typename U = void>
-using Enable_If_Signed = std::enable_if_t<std::is_signed_v<T>, U>;
-
-template <typename T, typename U = void>
-using Enable_If_Unsigned = std::enable_if_t<std::is_unsigned_v<T>, U>;
-
-// override for default behavior of printing as a character
-inline std::ostream &operator<<(std::ostream &stream, const int8_t value) {
-    return stream << +value;
-}
-// override for default behavior of printing as a character
-inline std::ostream &operator<<(std::ostream &stream, const uint8_t value) {
-    return stream << +value;
-}
-
-template <typename T>
-inline auto toUnderlying(const T value) {
-    return static_cast<std::underlying_type_t<T>>(value);
-}
-
-template <typename T>
-inline Enable_If_Iterable<T, true> unpack(std::istream &stream, T *value) {
-    for (auto &entry : *value) {
-        stream >> entry;
-    }
-}
-
-template <typename T>
-inline Enable_If_Iterable<T, false> unpack(std::istream &stream, T *value) {
-    stream >> *value;
-}
-
-template <>
-inline void unpack<std::string>(std::istream &stream, std::string *value) {
-    *value = std::string(std::istreambuf_iterator(stream), {});
-    stream.setstate(std::istream::eofbit);
-}
-
-template <typename T>
-inline Enable_If_Signed<T, T> getProperty(const std::string &key, const T def) {
-    if (std::is_floating_point_v<T>) {
-        float result;
-        std::string value = ::android::base::GetProperty(key, "");
-        if (!value.empty() && ::android::base::ParseFloat(value, &result)) {
-            return result;
-        }
-        return def;
-    } else {
-        return ::android::base::GetIntProperty(key, def);
-    }
-}
-
-template <typename T>
-inline Enable_If_Unsigned<T, T> getProperty(const std::string &key, const T def) {
-    return ::android::base::GetUintProperty(key, def);
-}
-
-template <typename T, size_t N>
-inline std::array<T, N> getProperty(const std::string &key, const std::array<T, N> &def) {
-    std::string value = ::android::base::GetProperty(key, "");
-    if (!value.empty()) {
-        std::array<T, N> result{0};
-        std::stringstream stream{value};
-        utils::unpack(stream, &result);
-        if (stream && stream.eof())
-            return result;
-    }
-    return def;
-}
-
-template <>
-inline bool getProperty<bool>(const std::string &key, const bool def) {
-    return ::android::base::GetBoolProperty(key, def);
-}
-
-template <typename T>
-static void openNoCreate(const std::string &file, T *outStream) {
-    if (!std::filesystem::exists(file)) {
-        ALOGE("File does not exist: %s", file.c_str());
-        return;
-    }
-
-    outStream->open(file);
-    if (!*outStream) {
-        ALOGE("Failed to open %s (%d): %s", file.c_str(), errno, strerror(errno));
-    }
-}
-
-template <typename T>
-static void fileFromEnv(const char *env, T *outStream, std::string *outName = nullptr) {
-    auto file = std::getenv(env);
-
-    if (file == nullptr) {
-        ALOGE("Failed get env %s", env);
-        return;
-    }
-
-    if (outName != nullptr) {
-        *outName = std::string(file);
-    }
-
-    openNoCreate(file, outStream);
-}
-
-static ATTRIBUTE_UNUSED auto pathsFromEnv(const char *env, const std::string &prefix = "") {
-    std::map<std::string, std::ifstream> ret;
-    auto value = std::getenv(env);
-
-    if (value == nullptr) {
-        return ret;
-    }
-
-    std::istringstream paths{value};
-    std::string path;
-
-    while (paths >> path) {
-        ret[path].open(prefix + path);
-    }
-
-    return ret;
-}
-
-static ATTRIBUTE_UNUSED std::string trim(const std::string &str,
-                                         const std::string &whitespace = " \t") {
-    const auto str_begin = str.find_first_not_of(whitespace);
-    if (str_begin == std::string::npos) {
-        return "";
-    }
-
-    const auto str_end = str.find_last_not_of(whitespace);
-    const auto str_range = str_end - str_begin + 1;
-
-    return str.substr(str_begin, str_range);
-}
-
-}  // namespace utils
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l25/Android.bp b/vibrator/cs40l25/Android.bp
deleted file mode 100644
index 7c4fe7e8..00000000
--- a/vibrator/cs40l25/Android.bp
+++ /dev/null
@@ -1,97 +0,0 @@
-//
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_defaults {
-    name: "android.hardware.vibrator-defaults.cs40l25",
-    cflags: [
-        "-DATRACE_TAG=(ATRACE_TAG_VIBRATOR | ATRACE_TAG_HAL)",
-        "-DLOG_TAG=\"Vibrator\"",
-    ],
-    shared_libs: [
-        "libbinder",
-    ],
-}
-
-cc_defaults {
-    name: "VibratorHalCs40l25BinaryDefaults",
-    defaults: [
-        "PixelVibratorBinaryDefaults",
-        "android.hardware.vibrator-defaults.cs40l25",
-    ],
-    include_dirs: [
-        "external/tinyalsa/include",
-    ],
-    shared_libs: [
-        "libcutils",
-        "libtinyalsa",
-    ],
-}
-
-cc_defaults {
-    name: "VibratorHalCs40l25TestDefaults",
-    defaults: [
-        "PixelVibratorTestDefaults",
-        "android.hardware.vibrator-defaults.cs40l25",
-    ],
-    static_libs: [
-        "android.hardware.vibrator-impl.cs40l25",
-        "libtinyalsa",
-    ],
-}
-
-cc_library {
-    name: "android.hardware.vibrator-impl.cs40l25",
-    defaults: [
-        "VibratorHalCs40l25BinaryDefaults",
-        "haptics_feature_defaults",
-    ],
-    srcs: ["Vibrator.cpp"],
-    export_include_dirs: ["."],
-    vendor_available: true,
-    visibility: [":__subpackages__"],
-}
-
-cc_binary {
-    name: "android.hardware.vibrator-service.cs40l25",
-    defaults: ["VibratorHalCs40l25BinaryDefaults"],
-    init_rc: ["android.hardware.vibrator-service.cs40l25.rc"],
-    vintf_fragments: ["android.hardware.vibrator-service.cs40l25.xml"],
-    srcs: ["service.cpp"],
-    shared_libs: [
-        "android.hardware.vibrator-impl.cs40l25",
-        "PixelVibratorStats",
-    ],
-    proprietary: true,
-}
-
-cc_binary {
-    name: "android.hardware.vibrator-service.cs40l25-dual",
-    defaults: ["VibratorHalCs40l25BinaryDefaults"],
-    init_rc: ["android.hardware.vibrator-service.cs40l25-dual.rc"],
-    vintf_fragments: ["android.hardware.vibrator-service.cs40l25-dual.xml"],
-    srcs: ["service.cpp"],
-    shared_libs: [
-        "android.hardware.vibrator-impl.cs40l25",
-        "PixelVibratorStats",
-    ],
-    cflags: [
-        "-DVIBRATOR_NAME=\"dual\"",
-    ],
-    proprietary: true,
-}
diff --git a/vibrator/cs40l25/Hardware.h b/vibrator/cs40l25/Hardware.h
deleted file mode 100644
index 7f06141b..00000000
--- a/vibrator/cs40l25/Hardware.h
+++ /dev/null
@@ -1,209 +0,0 @@
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
-#pragma once
-
-#include "HardwareBase.h"
-#include "Vibrator.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-class HwApi : public Vibrator::HwApi, private HwApiBase {
-  public:
-    HwApi() {
-        open("device/f0_stored", &mF0);
-        open("device/f0_offset", &mF0Offset);
-        open("device/redc_stored", &mRedc);
-        open("device/q_stored", &mQ);
-        open("activate", &mActivate);
-        open("duration", &mDuration);
-        open("state", &mState);
-        open("device/cp_trigger_duration", &mEffectDuration);
-        open("device/cp_trigger_index", &mEffectIndex);
-        open("device/cp_trigger_queue", &mEffectQueue);
-        open("device/cp_dig_scale", &mEffectScale);
-        open("device/dig_scale", &mGlobalScale);
-        open("device/asp_enable", &mAspEnable);
-        open("device/gpio1_fall_index", &mGpioFallIndex);
-        open("device/gpio1_fall_dig_scale", &mGpioFallScale);
-        open("device/gpio1_rise_index", &mGpioRiseIndex);
-        open("device/gpio1_rise_dig_scale", &mGpioRiseScale);
-        open("device/vibe_state", &mVibeState);
-        open("device/num_waves", &mEffectCount);
-        open("device/clab_enable", &mClabEnable);
-        open("device/available_pwle_segments", &mAvailablePwleSegments);
-        open("device/pwle", &mPwle);
-        open("device/pwle_ramp_down", &mPwleRampDown);
-    }
-
-    bool setF0(uint32_t value) override { return set(value, &mF0); }
-    bool setF0Offset(uint32_t value) override { return set(value, &mF0Offset); }
-    bool setRedc(uint32_t value) override { return set(value, &mRedc); }
-    bool setQ(uint32_t value) override { return set(value, &mQ); }
-    bool setActivate(bool value) override { return set(value, &mActivate); }
-    bool setDuration(uint32_t value) override { return set(value, &mDuration); }
-    bool getEffectCount(uint32_t *value) override { return get(value, &mEffectCount); }
-    bool getEffectDuration(uint32_t *value) override { return get(value, &mEffectDuration); }
-    bool setEffectIndex(uint32_t value) override { return set(value, &mEffectIndex); }
-    bool setEffectQueue(std::string value) override { return set(value, &mEffectQueue); }
-    bool hasEffectScale() override { return has(mEffectScale); }
-    bool setEffectScale(uint32_t value) override { return set(value, &mEffectScale); }
-    bool setGlobalScale(uint32_t value) override { return set(value, &mGlobalScale); }
-    bool setState(bool value) override { return set(value, &mState); }
-    bool hasAspEnable() override { return has(mAspEnable); }
-    bool getAspEnable(bool *value) override { return get(value, &mAspEnable); }
-    bool setAspEnable(bool value) override { return set(value, &mAspEnable); }
-    bool setGpioFallIndex(uint32_t value) override { return set(value, &mGpioFallIndex); }
-    bool setGpioFallScale(uint32_t value) override { return set(value, &mGpioFallScale); }
-    bool setGpioRiseIndex(uint32_t value) override { return set(value, &mGpioRiseIndex); }
-    bool setGpioRiseScale(uint32_t value) override { return set(value, &mGpioRiseScale); }
-    bool pollVibeState(uint32_t value, int32_t timeoutMs) override {
-        return poll(value, &mVibeState, timeoutMs);
-    }
-    bool setClabEnable(bool value) override { return set(value, &mClabEnable); }
-    bool getAvailablePwleSegments(uint32_t *value) override {
-        return get(value, &mAvailablePwleSegments);
-    }
-    bool hasPwle() override { return has(mPwle); }
-    bool setPwle(std::string value) override { return set(value, &mPwle); }
-    bool setPwleRampDown(uint32_t value) override { return set(value, &mPwleRampDown); }
-    void debug(int fd) override { HwApiBase::debug(fd); }
-
-  private:
-    std::ofstream mF0;
-    std::ofstream mF0Offset;
-    std::ofstream mRedc;
-    std::ofstream mQ;
-    std::ofstream mActivate;
-    std::ofstream mDuration;
-    std::ifstream mEffectCount;
-    std::ifstream mEffectDuration;
-    std::ofstream mEffectIndex;
-    std::ofstream mEffectQueue;
-    std::ofstream mEffectScale;
-    std::ofstream mGlobalScale;
-    std::ofstream mState;
-    std::fstream mAspEnable;
-    std::ofstream mGpioFallIndex;
-    std::ofstream mGpioFallScale;
-    std::ofstream mGpioRiseIndex;
-    std::ofstream mGpioRiseScale;
-    std::ifstream mVibeState;
-    std::ofstream mClabEnable;
-    std::ifstream mAvailablePwleSegments;
-    std::ofstream mPwle;
-    std::ofstream mPwleRampDown;
-};
-
-class HwCal : public Vibrator::HwCal, private HwCalBase {
-  private:
-    static constexpr char VERSION[] = "version";
-    static constexpr char F0_CONFIG[] = "f0_measured";
-    static constexpr char REDC_CONFIG[] = "redc_measured";
-    static constexpr char Q_CONFIG[] = "q_measured";
-    static constexpr char Q_INDEX[] = "q_index";
-    static constexpr char VOLTAGES_CONFIG[] = "v_levels";
-    static constexpr char TICK_VOLTAGES_CONFIG[] = "v_tick";
-    static constexpr char CLICK_VOLTAGES_CONFIG[] = "v_click";
-    static constexpr char LONG_VOLTAGES_CONFIG[] = "v_long";
-
-    static constexpr uint32_t Q_FLOAT_TO_FIXED = 1 << 16;
-    static constexpr float Q_INDEX_TO_FLOAT = 1.5f;
-    static constexpr uint32_t Q_INDEX_TO_FIXED = Q_INDEX_TO_FLOAT * Q_FLOAT_TO_FIXED;
-    static constexpr uint32_t Q_INDEX_OFFSET = 2.0f * Q_FLOAT_TO_FIXED;
-
-    static constexpr uint32_t VERSION_DEFAULT = 1;
-    static constexpr int32_t DEFAULT_FREQUENCY_SHIFT = 0;
-    static constexpr float DEFAULT_DEVICE_MASS = 0.21;
-    static constexpr float DEFAULT_LOC_COEFF = 0.5;
-    static constexpr uint32_t Q_DEFAULT = 15.5 * Q_FLOAT_TO_FIXED;
-    static constexpr std::array<uint32_t, 6> V_LEVELS_DEFAULT = {60, 70, 80, 90, 100, 76};
-    static constexpr std::array<uint32_t, 2> V_TICK_DEFAULT = {10, 70};
-    static constexpr std::array<uint32_t, 2> V_CTICK_DEFAULT = {10, 70};
-    static constexpr std::array<uint32_t, 2> V_LONG_DEFAULT = {10, 70};
-
-  public:
-    HwCal() {}
-
-    bool getVersion(uint32_t *value) override {
-        if (getPersist(VERSION, value)) {
-            return true;
-        }
-        *value = VERSION_DEFAULT;
-        return true;
-    }
-    bool getLongFrequencyShift(int32_t *value) override {
-        return getProperty("long.frequency.shift", value, DEFAULT_FREQUENCY_SHIFT);
-    }
-    bool getDeviceMass(float *value) override {
-        return getProperty("device.mass", value, DEFAULT_DEVICE_MASS);
-    }
-    bool getLocCoeff(float *value) override {
-        return getProperty("loc.coeff", value, DEFAULT_LOC_COEFF);
-    }
-    bool getF0(uint32_t *value) override { return getPersist(F0_CONFIG, value); }
-    bool getRedc(uint32_t *value) override { return getPersist(REDC_CONFIG, value); }
-    bool getQ(uint32_t *value) override {
-        if (getPersist(Q_CONFIG, value)) {
-            return true;
-        }
-        if (getPersist(Q_INDEX, value)) {
-            *value = *value * Q_INDEX_TO_FIXED + Q_INDEX_OFFSET;
-            return true;
-        }
-        *value = Q_DEFAULT;
-        return true;
-    }
-    bool getVolLevels(std::array<uint32_t, 6> *value) override {
-        if (getPersist(VOLTAGES_CONFIG, value)) {
-            return true;
-        }
-        *value = V_LEVELS_DEFAULT;
-        return true;
-    }
-    bool getTickVolLevels(std::array<uint32_t, 2> *value) override {
-        if (getPersist(TICK_VOLTAGES_CONFIG, value)) {
-            return true;
-        }
-        *value = V_TICK_DEFAULT;
-        return true;
-    }
-    bool getClickVolLevels(std::array<uint32_t, 2> *value) override {
-        if (getPersist(CLICK_VOLTAGES_CONFIG, value)) {
-            return true;
-        }
-        *value = V_CTICK_DEFAULT;
-        return true;
-    }
-    bool getLongVolLevels(std::array<uint32_t, 2> *value) override {
-        if (getPersist(LONG_VOLTAGES_CONFIG, value)) {
-            return true;
-        }
-        *value = V_LONG_DEFAULT;
-        return true;
-    }
-    bool isChirpEnabled() override {
-        return utils::getProperty("persist.vendor.vibrator.hal.chirp.enabled", false);
-    }
-    void debug(int fd) override { HwCalBase::debug(fd); }
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l25/Stats.h b/vibrator/cs40l25/Stats.h
deleted file mode 100644
index f6a7a347..00000000
--- a/vibrator/cs40l25/Stats.h
+++ /dev/null
@@ -1,292 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#pragma once
-
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include <algorithm>
-#include <chrono>
-#include <mutex>
-
-#include "StatsBase.h"
-#include "Vibrator.h"
-
-constexpr int32_t DURATION_BUCKET_WIDTH = 50;
-constexpr int32_t DURATION_50MS_BUCKET_COUNT = 20;
-constexpr int32_t DURATION_BUCKET_COUNT = DURATION_50MS_BUCKET_COUNT + 1;
-constexpr uint32_t MAX_TIME_MS = UINT16_MAX;
-
-#ifndef ARRAY_SIZE
-#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
-#endif
-
-#ifdef HAPTIC_TRACE
-static const char *kWaveformLookup[] = {"WAVEFORM_LONG_VIBRATION_EFFECT",
-                                        "WAVEFORM_RESERVED_1",
-                                        "WAVEFORM_CLICK",
-                                        "WAVEFORM_SHORT_VIBRATION_EFFECT",
-                                        "WAVEFORM_THUD",
-                                        "WAVEFORM_SPIN",
-                                        "WAVEFORM_QUICK_RISE",
-                                        "WAVEFORM_SLOW_RISE",
-                                        "WAVEFORM_QUICK_FALL",
-                                        "WAVEFORM_LIGHT_TICK",
-                                        "WAVEFORM_LOW_TICK",
-                                        "WAVEFORM_RESERVED_MFG_1",
-                                        "WAVEFORM_RESERVED_MFG_2",
-                                        "WAVEFORM_RESERVED_MFG_3",
-                                        "WAVEFORM_COMPOSE",
-                                        "WAVEFORM_PWLE",
-                                        "INVALID"};
-static const char *kLatencyLookup[] = {"kWaveformEffectLatency", "kPrebakedEffectLatency",
-                                       "kCompositionEffectLatency", "kPwleEffectLatency",
-                                       "INVALID"};
-static const char *kErrorLookup[] = {"kInitError",
-                                     "kHwApiError",
-                                     "kHwCalError",
-                                     "kComposeFailError",
-                                     "kAlsaFailError",
-                                     "kAsyncFailError",
-                                     "kBadTimeoutError",
-                                     "kBadAmplitudeError",
-                                     "kBadEffectError",
-                                     "kBadEffectStrengthError",
-                                     "kBadPrimitiveError",
-                                     "kBadCompositeError",
-                                     "kPwleConstructionFailError",
-                                     "kUnsupportedOpError",
-                                     "INVALID"};
-
-const char *waveformToString(uint16_t index) {
-    return kWaveformLookup[(index < ARRAY_SIZE(kWaveformLookup)) ? index
-                                                                 : ARRAY_SIZE(kWaveformLookup) - 1];
-}
-
-const char *latencyToString(uint16_t index) {
-    return kLatencyLookup[(index < ARRAY_SIZE(kLatencyLookup)) ? index
-                                                               : ARRAY_SIZE(kLatencyLookup) - 1];
-}
-
-const char *errorToString(uint16_t index) {
-    return kErrorLookup[(index < ARRAY_SIZE(kErrorLookup)) ? index : ARRAY_SIZE(kErrorLookup) - 1];
-}
-
-#define STATS_TRACE(...)   \
-    ATRACE_NAME(__func__); \
-    ALOGD(__VA_ARGS__)
-#else
-#define STATS_TRACE(...) ATRACE_NAME(__func__)
-#define waveformToString(x)
-#define latencyToString(x)
-#define errorToString(x)
-#endif
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-enum EffectLatency : uint16_t {
-    kWaveformEffectLatency = 0,
-    kPrebakedEffectLatency,
-    kCompositionEffectLatency,
-    kPwleEffectLatency,
-
-    kEffectLatencyCount
-};
-
-enum VibratorError : uint16_t {
-    kInitError = 0,
-    kHwApiError,
-    kHwCalError,
-    kComposeFailError,
-    kAlsaFailError,
-    kAsyncFailError,
-    kBadTimeoutError,
-    kBadAmplitudeError,
-    kBadEffectError,
-    kBadEffectStrengthError,
-    kBadPrimitiveError,
-    kBadCompositeError,
-    kPwleConstructionFailError,
-    kUnsupportedOpError,
-
-    kVibratorErrorCount
-};
-
-class StatsApi : public Vibrator::StatsApi, private StatsBase {
-  private:
-    static constexpr uint32_t BASE_CONTINUOUS_EFFECT_OFFSET = 32768;
-    enum WaveformIndex : uint16_t {
-        /* Physical waveform */
-        WAVEFORM_LONG_VIBRATION_EFFECT_INDEX = 0,
-        WAVEFORM_RESERVED_INDEX_1 = 1,
-        WAVEFORM_CLICK_INDEX = 2,
-        WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX = 3,
-        WAVEFORM_THUD_INDEX = 4,
-        WAVEFORM_SPIN_INDEX = 5,
-        WAVEFORM_QUICK_RISE_INDEX = 6,
-        WAVEFORM_SLOW_RISE_INDEX = 7,
-        WAVEFORM_QUICK_FALL_INDEX = 8,
-        WAVEFORM_LIGHT_TICK_INDEX = 9,
-        WAVEFORM_LOW_TICK_INDEX = 10,
-        WAVEFORM_RESERVED_MFG_1,
-        WAVEFORM_RESERVED_MFG_2,
-        WAVEFORM_RESERVED_MFG_3,
-        WAVEFORM_MAX_PHYSICAL_INDEX,
-        /* OWT waveform */
-        WAVEFORM_COMPOSE = WAVEFORM_MAX_PHYSICAL_INDEX,
-        WAVEFORM_PWLE,
-        /*
-         * Refer to <linux/input.h>, the WAVEFORM_MAX_INDEX must not exceed 96.
-         * #define FF_GAIN          0x60  // 96 in decimal
-         * #define FF_MAX_EFFECTS   FF_GAIN
-         */
-        WAVEFORM_MAX_INDEX,
-    };
-
-  public:
-    StatsApi()
-        : StatsBase(std::string(std::getenv("STATS_INSTANCE"))),
-          mCurrentLatencyIndex(kEffectLatencyCount) {
-        mWaveformCounts = std::vector<int32_t>(WAVEFORM_MAX_INDEX, 0);
-        mDurationCounts = std::vector<int32_t>(DURATION_BUCKET_COUNT, 0);
-        mMinLatencies = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mMaxLatencies = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mLatencyTotals = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mLatencyCounts = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mErrorCounts = std::vector<int32_t>(kVibratorErrorCount, 0);
-    }
-
-    bool logPrimitive(uint16_t effectIndex) override {
-        STATS_TRACE("logPrimitive(effectIndex: %s)", waveformToString(effectIndex));
-
-        if (effectIndex >= WAVEFORM_MAX_PHYSICAL_INDEX ||
-            effectIndex == WAVEFORM_LONG_VIBRATION_EFFECT_INDEX ||
-            effectIndex == WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX) {
-            ALOGE("Invalid waveform index for logging primitive: %d", effectIndex);
-            return false;
-        }
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            mWaveformCounts[effectIndex]++;
-        }
-
-        return true;
-    }
-
-    bool logWaveform(uint16_t effectIndex, int32_t duration) override {
-        STATS_TRACE("logWaveform(effectIndex: %s, duration: %d)", waveformToString(effectIndex),
-                    duration);
-
-        if (effectIndex != WAVEFORM_LONG_VIBRATION_EFFECT_INDEX &&
-            effectIndex != WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX + BASE_CONTINUOUS_EFFECT_OFFSET) {
-            ALOGE("Invalid waveform index for logging waveform: %d", effectIndex);
-            return false;
-        } else if (effectIndex ==
-                   WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX + BASE_CONTINUOUS_EFFECT_OFFSET) {
-            effectIndex = WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX;
-        }
-
-        if (duration > MAX_TIME_MS || duration < 0) {
-            ALOGE("Invalid waveform duration for logging waveform: %d", duration);
-            return false;
-        }
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            mWaveformCounts[effectIndex]++;
-            if (duration < DURATION_BUCKET_WIDTH * DURATION_50MS_BUCKET_COUNT) {
-                mDurationCounts[duration / DURATION_BUCKET_WIDTH]++;
-            } else {
-                mDurationCounts[DURATION_50MS_BUCKET_COUNT]++;
-            }
-        }
-
-        return true;
-    }
-
-    bool logError(uint16_t errorIndex) override {
-        STATS_TRACE("logError(errorIndex: %s)", errorToString(errorIndex));
-
-        if (errorIndex >= kVibratorErrorCount) {
-            ALOGE("Invalid index for logging error: %d", errorIndex);
-            return false;
-        }
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            mErrorCounts[errorIndex]++;
-        }
-
-        return true;
-    }
-
-    bool logLatencyStart(uint16_t latencyIndex) override {
-        STATS_TRACE("logLatencyStart(latencyIndex: %s)", latencyToString(latencyIndex));
-
-        if (latencyIndex >= kEffectLatencyCount) {
-            ALOGE("Invalid index for measuring latency: %d", latencyIndex);
-            return false;
-        }
-
-        mCurrentLatencyStart = std::chrono::steady_clock::now();
-        mCurrentLatencyIndex = latencyIndex;
-
-        return true;
-    }
-
-    bool logLatencyEnd() override {
-        STATS_TRACE("logLatencyEnd()");
-
-        if (mCurrentLatencyIndex >= kEffectLatencyCount) {
-            return false;
-        }
-
-        int32_t latency = (std::chrono::duration_cast<std::chrono::milliseconds>(
-                                   std::chrono::steady_clock::now() - mCurrentLatencyStart))
-                                  .count();
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            if (latency < mMinLatencies[mCurrentLatencyIndex] ||
-                mMinLatencies[mCurrentLatencyIndex] == 0) {
-                mMinLatencies[mCurrentLatencyIndex] = latency;
-            }
-            if (latency > mMaxLatencies[mCurrentLatencyIndex]) {
-                mMaxLatencies[mCurrentLatencyIndex] = latency;
-            }
-            mLatencyTotals[mCurrentLatencyIndex] += latency;
-            mLatencyCounts[mCurrentLatencyIndex]++;
-        }
-
-        mCurrentLatencyIndex = kEffectLatencyCount;
-        return true;
-    }
-
-    void debug(int fd) override { StatsBase::debug(fd); }
-
-  private:
-    uint16_t mCurrentLatencyIndex;
-    std::chrono::time_point<std::chrono::steady_clock> mCurrentLatencyStart;
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l25/TEST_MAPPING b/vibrator/cs40l25/TEST_MAPPING
deleted file mode 100644
index c684d707..00000000
--- a/vibrator/cs40l25/TEST_MAPPING
+++ /dev/null
@@ -1,20 +0,0 @@
-{
-  "presubmit": [
-    {
-      "name": "VibratorHalCs40l25TestSuite",
-      "keywords": [
-        "nextgen"
-      ]
-    }
-  ],
-  "postsubmit": [
-    {
-      "name": "VibratorHalCs40l25Benchmark"
-    }
-  ],
-  "pts-experimental": [
-    {
-      "name": "VibratorHalCs40l25TestSuite"
-    }
-  ]
-}
diff --git a/vibrator/cs40l25/Vibrator.cpp b/vibrator/cs40l25/Vibrator.cpp
deleted file mode 100644
index e786048f..00000000
--- a/vibrator/cs40l25/Vibrator.cpp
+++ /dev/null
@@ -1,1498 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-#include "Vibrator.h"
-
-#include <android-base/properties.h>
-#include <hardware/hardware.h>
-#include <hardware/vibrator.h>
-#include <log/log.h>
-#include <stdio.h>
-#include <utils/Trace.h>
-
-#include <cinttypes>
-#include <cmath>
-#include <fstream>
-#include <iostream>
-#include <map>
-#include <sstream>
-
-#include "Stats.h"
-#include "utils.h"
-
-#ifndef ARRAY_SIZE
-#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
-#endif
-
-#define PROC_SND_PCM "/proc/asound/pcm"
-#define HAPTIC_PCM_DEVICE_SYMBOL "haptic nohost playback"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-#ifdef HAPTIC_TRACE
-#define HAPTICS_TRACE(...) ALOGD(__VA_ARGS__)
-#else
-#define HAPTICS_TRACE(...)
-#endif
-
-static constexpr uint32_t BASE_CONTINUOUS_EFFECT_OFFSET = 32768;
-
-static constexpr uint32_t WAVEFORM_EFFECT_0_20_LEVEL = 0;
-static constexpr uint32_t WAVEFORM_EFFECT_1_00_LEVEL = 4;
-static constexpr uint32_t WAVEFORM_EFFECT_LEVEL_MINIMUM = 4;
-
-static constexpr uint32_t WAVEFORM_DOUBLE_CLICK_SILENCE_MS = 100;
-
-static constexpr uint32_t WAVEFORM_LONG_VIBRATION_EFFECT_INDEX = 0;
-static constexpr uint32_t WAVEFORM_LONG_VIBRATION_THRESHOLD_MS = 50;
-static constexpr uint32_t WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX = 3 + BASE_CONTINUOUS_EFFECT_OFFSET;
-
-static constexpr uint32_t WAVEFORM_CLICK_INDEX = 2;
-static constexpr uint32_t WAVEFORM_THUD_INDEX = 4;
-static constexpr uint32_t WAVEFORM_SPIN_INDEX = 5;
-static constexpr uint32_t WAVEFORM_QUICK_RISE_INDEX = 6;
-static constexpr uint32_t WAVEFORM_SLOW_RISE_INDEX = 7;
-static constexpr uint32_t WAVEFORM_QUICK_FALL_INDEX = 8;
-static constexpr uint32_t WAVEFORM_LIGHT_TICK_INDEX = 9;
-static constexpr uint32_t WAVEFORM_LOW_TICK_INDEX = 10;
-
-static constexpr uint32_t WAVEFORM_UNSAVED_TRIGGER_QUEUE_INDEX = 65529;
-static constexpr uint32_t WAVEFORM_TRIGGER_QUEUE_INDEX = 65534;
-static constexpr uint32_t VOLTAGE_GLOBAL_SCALE_LEVEL = 5;
-static constexpr uint8_t VOLTAGE_SCALE_MAX = 100;
-
-static constexpr int8_t MAX_COLD_START_LATENCY_MS = 6;  // I2C Transaction + DSP Return-From-Standby
-static constexpr int8_t MAX_PAUSE_TIMING_ERROR_MS = 1;  // ALERT Irq Handling
-static constexpr uint32_t MAX_TIME_MS = UINT32_MAX;
-
-static constexpr float AMP_ATTENUATE_STEP_SIZE = 0.125f;
-static constexpr float EFFECT_FREQUENCY_KHZ = 48.0f;
-
-static constexpr auto ASYNC_COMPLETION_TIMEOUT = std::chrono::milliseconds(100);
-static constexpr auto POLLING_TIMEOUT = 20;
-
-static constexpr int32_t COMPOSE_DELAY_MAX_MS = 10000;
-static constexpr int32_t COMPOSE_SIZE_MAX = 127;
-static constexpr int32_t COMPOSE_PWLE_SIZE_LIMIT = 82;
-static constexpr int32_t CS40L2X_PWLE_LENGTH_MAX = 4094;
-
-// Measured resonant frequency, f0_measured, is represented by Q10.14 fixed
-// point format on cs40l2x devices. The expression to calculate f0 is:
-//   f0 = f0_measured / 2^Q14_BIT_SHIFT
-// See the LRA Calibration Support documentation for more details.
-static constexpr int32_t Q14_BIT_SHIFT = 14;
-
-// Measured Q factor, q_measured, is represented by Q8.16 fixed
-// point format on cs40l2x devices. The expression to calculate q is:
-//   q = q_measured / 2^Q16_BIT_SHIFT
-// See the LRA Calibration Support documentation for more details.
-static constexpr int32_t Q16_BIT_SHIFT = 16;
-
-// Measured ReDC, redc_measured, is represented by Q7.17 fixed
-// point format on cs40l2x devices. The expression to calculate redc is:
-//   redc = redc_measured * 5.857 / 2^Q17_BIT_SHIFT
-// See the LRA Calibration Support documentation for more details.
-static constexpr int32_t Q17_BIT_SHIFT = 17;
-
-static constexpr int32_t COMPOSE_PWLE_PRIMITIVE_DURATION_MAX_MS = 999;
-static constexpr float PWLE_LEVEL_MIN = 0.0f;
-static constexpr float PWLE_LEVEL_MAX = 1.0f;
-static constexpr float CS40L2X_PWLE_LEVEL_MAX = 0.99f;
-static constexpr float PWLE_FREQUENCY_RESOLUTION_HZ = 1.0f;
-static constexpr float PWLE_FREQUENCY_MIN_HZ = 30.0f;
-static constexpr float RESONANT_FREQUENCY_DEFAULT = 145.0f;
-static constexpr float PWLE_FREQUENCY_MAX_HZ = 300.0f;
-static constexpr float PWLE_BW_MAP_SIZE =
-    1 + ((PWLE_FREQUENCY_MAX_HZ - PWLE_FREQUENCY_MIN_HZ) / PWLE_FREQUENCY_RESOLUTION_HZ);
-static constexpr float RAMP_DOWN_CONSTANT = 1048.576f;
-static constexpr float RAMP_DOWN_TIME_MS = 0.0f;
-
-static struct pcm_config haptic_nohost_config = {
-    .channels = 1,
-    .rate = 48000,
-    .period_size = 80,
-    .period_count = 2,
-    .format = PCM_FORMAT_S16_LE,
-};
-
-static uint8_t amplitudeToScale(float amplitude, float maximum) {
-    return std::round((-20 * std::log10(amplitude / static_cast<float>(maximum))) /
-                      (AMP_ATTENUATE_STEP_SIZE));
-}
-
-// Discrete points of frequency:max_level pairs as recommended by the document
-#if defined(LUXSHARE_ICT_081545)
-static std::map<float, float> discretePwleMaxLevels = {{120.0, 0.4},  {130.0, 0.31}, {140.0, 0.14},
-                                                       {145.0, 0.09}, {150.0, 0.15}, {160.0, 0.35},
-                                                       {170.0, 0.4}};
-// Discrete points of frequency:max_level pairs as recommended by the document
-#elif defined(LUXSHARE_ICT_LT_XLRA1906D)
-static std::map<float, float> discretePwleMaxLevels = {{145.0, 0.38}, {150.0, 0.35}, {160.0, 0.35},
-                                                       {170.0, 0.15}, {180.0, 0.35}, {190.0, 0.35},
-                                                       {200.0, 0.38}};
-#else
-static std::map<float, float> discretePwleMaxLevels = {};
-#endif
-
-// Initialize all limits to 0.4 according to the document Max. Allowable Chirp Levels
-#if defined(LUXSHARE_ICT_081545)
-std::vector<float> pwleMaxLevelLimitMap(PWLE_BW_MAP_SIZE, 0.4);
-// Initialize all limits to 0.38 according to the document Max. Allowable Chirp Levels
-#elif defined(LUXSHARE_ICT_LT_XLRA1906D)
-std::vector<float> pwleMaxLevelLimitMap(PWLE_BW_MAP_SIZE, 0.38);
-#else
-std::vector<float> pwleMaxLevelLimitMap(PWLE_BW_MAP_SIZE, 1.0);
-#endif
-
-void Vibrator::createPwleMaxLevelLimitMap() {
-    HAPTICS_TRACE("createPwleMaxLevelLimitMap()");
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_FREQUENCY_CONTROL) {
-        std::map<float, float>::iterator itr0, itr1;
-
-        if (discretePwleMaxLevels.empty()) {
-            return;
-        }
-        if (discretePwleMaxLevels.size() == 1) {
-            itr0 = discretePwleMaxLevels.begin();
-            float pwleMaxLevelLimitMapIdx =
-                    (itr0->first - PWLE_FREQUENCY_MIN_HZ) / PWLE_FREQUENCY_RESOLUTION_HZ;
-            pwleMaxLevelLimitMap[pwleMaxLevelLimitMapIdx] = itr0->second;
-            return;
-        }
-
-        itr0 = discretePwleMaxLevels.begin();
-        itr1 = std::next(itr0, 1);
-
-        while (itr1 != discretePwleMaxLevels.end()) {
-            float x0 = itr0->first;
-            float y0 = itr0->second;
-            float x1 = itr1->first;
-            float y1 = itr1->second;
-            float pwleMaxLevelLimitMapIdx =
-                    (itr0->first - PWLE_FREQUENCY_MIN_HZ) / PWLE_FREQUENCY_RESOLUTION_HZ;
-
-            // FixLater: avoid floating point loop counters
-            // NOLINTBEGIN(clang-analyzer-security.FloatLoopCounter,cert-flp30-c)
-            for (float xp = x0; xp < (x1 + PWLE_FREQUENCY_RESOLUTION_HZ);
-                 xp += PWLE_FREQUENCY_RESOLUTION_HZ) {
-                // NOLINTEND(clang-analyzer-security.FloatLoopCounter,cert-flp30-c)
-                float yp = y0 + ((y1 - y0) / (x1 - x0)) * (xp - x0);
-
-                pwleMaxLevelLimitMap[pwleMaxLevelLimitMapIdx++] = yp;
-            }
-
-            itr0++;
-            itr1++;
-        }
-    }
-}
-
-enum class AlwaysOnId : uint32_t {
-    GPIO_RISE,
-    GPIO_FALL,
-};
-
-Vibrator::Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal,
-                   std::unique_ptr<StatsApi> statsapi)
-    : mHwApi(std::move(hwapi)),
-      mHwCal(std::move(hwcal)),
-      mStatsApi(std::move(statsapi)),
-      mAsyncHandle(std::async([] {})) {
-    int32_t longFreqencyShift;
-    uint32_t calVer;
-    uint32_t caldata;
-    uint32_t effectCount;
-
-    if (!mHwApi->setState(true)) {
-        mStatsApi->logError(kHwApiError);
-        ALOGE("Failed to set state (%d): %s", errno, strerror(errno));
-    }
-
-    if (mHwCal->getF0(&caldata)) {
-        mHwApi->setF0(caldata);
-        mResonantFrequency = static_cast<float>(caldata) / (1 << Q14_BIT_SHIFT);
-    } else {
-        mStatsApi->logError(kHwApiError);
-        ALOGE("Failed to get resonant frequency (%d): %s, using default resonant HZ: %f", errno,
-              strerror(errno), RESONANT_FREQUENCY_DEFAULT);
-        mResonantFrequency = RESONANT_FREQUENCY_DEFAULT;
-    }
-    if (mHwCal->getRedc(&caldata)) {
-        mHwApi->setRedc(caldata);
-        mRedc = caldata;
-    }
-    if (mHwCal->getQ(&caldata)) {
-        mHwApi->setQ(caldata);
-    }
-
-    mHwCal->getLongFrequencyShift(&longFreqencyShift);
-    if (longFreqencyShift > 0) {
-        mF0Offset = longFreqencyShift * std::pow(2, 14);
-    } else if (longFreqencyShift < 0) {
-        mF0Offset = std::pow(2, 24) - std::abs(longFreqencyShift) * std::pow(2, 14);
-    } else {
-        mF0Offset = 0;
-    }
-
-    mHwCal->getVersion(&calVer);
-    if (calVer == 1) {
-        std::array<uint32_t, 6> volLevels;
-        mHwCal->getVolLevels(&volLevels);
-        /*
-         * Given voltage levels for two intensities, assuming a linear function,
-         * solve for 'f(0)' in 'v = f(i) = a + b * i' (i.e 'v0 - (v1 - v0) / ((i1 - i0) / i0)').
-         */
-        mClickEffectVol[0] = std::max(std::lround(volLevels[WAVEFORM_EFFECT_0_20_LEVEL] -
-                                             (volLevels[WAVEFORM_EFFECT_1_00_LEVEL] -
-                                              volLevels[WAVEFORM_EFFECT_0_20_LEVEL]) /
-                                                     4.0f),
-                                 static_cast<long>(WAVEFORM_EFFECT_LEVEL_MINIMUM));
-        mClickEffectVol[1] = volLevels[WAVEFORM_EFFECT_1_00_LEVEL];
-        mTickEffectVol = mClickEffectVol;
-        mLongEffectVol[0] = 0;
-        mLongEffectVol[1] = volLevels[VOLTAGE_GLOBAL_SCALE_LEVEL];
-    } else {
-        mHwCal->getTickVolLevels(&mTickEffectVol);
-        mHwCal->getClickVolLevels(&mClickEffectVol);
-        mHwCal->getLongVolLevels(&mLongEffectVol);
-    }
-    HAPTICS_TRACE("Vibrator(hwapi, hwcal:%u)", calVer);
-
-    mHwApi->getEffectCount(&effectCount);
-    mEffectDurations.resize(effectCount);
-
-    mIsPrimitiveDelayEnabled =
-            utils::getProperty("ro.vendor.vibrator.hal.cs40L25.primitive_delays.enabled", false);
-
-    mDelayEffectDurations.resize(effectCount);
-    if (mIsPrimitiveDelayEnabled) {
-        mDelayEffectDurations = {
-                25, 45, 45, 20, 20, 20, 20, 20,
-        }; /* delays for each effect based on measurements */
-    } else {
-        mDelayEffectDurations = {
-                0, 0, 0, 0, 0, 0, 0, 0,
-        }; /* no delay if property not set */
-    }
-
-    for (size_t effectIndex = 0; effectIndex < effectCount; effectIndex++) {
-        mHwApi->setEffectIndex(effectIndex);
-        uint32_t effectDuration;
-        if (mHwApi->getEffectDuration(&effectDuration)) {
-            mEffectDurations[effectIndex] = std::ceil(effectDuration / EFFECT_FREQUENCY_KHZ);
-        }
-    }
-
-    mHwApi->setClabEnable(true);
-
-    if (!(getPwleCompositionSizeMax(&mCompositionSizeMax).isOk())) {
-        mStatsApi->logError(kInitError);
-        ALOGE("Failed to get pwle composition size max, using default size: %d",
-              COMPOSE_PWLE_SIZE_LIMIT);
-        mCompositionSizeMax = COMPOSE_PWLE_SIZE_LIMIT;
-    }
-
-    mIsChirpEnabled = mHwCal->isChirpEnabled();
-    createPwleMaxLevelLimitMap();
-    mGenerateBandwidthAmplitudeMapDone = false;
-    mBandwidthAmplitudeMap = generateBandwidthAmplitudeMap();
-    mIsUnderExternalControl = false;
-    setPwleRampDown();
-}
-
-ndk::ScopedAStatus Vibrator::getCapabilities(int32_t *_aidl_return) {
-    HAPTICS_TRACE("getCapabilities(_aidl_return)");
-    ATRACE_NAME("Vibrator::getCapabilities");
-    int32_t ret = IVibrator::CAP_ON_CALLBACK | IVibrator::CAP_PERFORM_CALLBACK |
-                  IVibrator::CAP_COMPOSE_EFFECTS | IVibrator::CAP_ALWAYS_ON_CONTROL |
-                  IVibrator::CAP_GET_RESONANT_FREQUENCY | IVibrator::CAP_GET_Q_FACTOR;
-    if (mHwApi->hasEffectScale()) {
-        ret |= IVibrator::CAP_AMPLITUDE_CONTROL;
-    }
-    if (mHwApi->hasAspEnable() || hasHapticAlsaDevice()) {
-        ret |= IVibrator::CAP_EXTERNAL_CONTROL;
-    }
-    if (mHwApi->hasPwle() && mIsChirpEnabled) {
-        ret |= IVibrator::CAP_FREQUENCY_CONTROL | IVibrator::CAP_COMPOSE_PWLE_EFFECTS;
-    }
-    *_aidl_return = ret;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::off() {
-    HAPTICS_TRACE("off()");
-    ATRACE_NAME("Vibrator::off");
-    ALOGD("off");
-    setGlobalAmplitude(false);
-    mHwApi->setF0Offset(0);
-    if (!mHwApi->setActivate(0)) {
-        mStatsApi->logError(kHwApiError);
-        ALOGE("Failed to turn vibrator off (%d): %s", errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-    mActiveId = -1;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::on(int32_t timeoutMs,
-                                const std::shared_ptr<IVibratorCallback> &callback) {
-    HAPTICS_TRACE("on(timeoutMs:%u, callback)", timeoutMs);
-    ATRACE_NAME("Vibrator::on");
-    ALOGD("on");
-    mStatsApi->logLatencyStart(kWaveformEffectLatency);
-    const uint32_t index = timeoutMs < WAVEFORM_LONG_VIBRATION_THRESHOLD_MS
-                                   ? WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX
-                                   : WAVEFORM_LONG_VIBRATION_EFFECT_INDEX;
-    mStatsApi->logWaveform(index, timeoutMs);
-    if (MAX_COLD_START_LATENCY_MS <= UINT32_MAX - timeoutMs) {
-        timeoutMs += MAX_COLD_START_LATENCY_MS;
-    }
-    setGlobalAmplitude(true);
-    mHwApi->setF0Offset(mF0Offset);
-    return on(timeoutMs, index, callback);
-}
-
-ndk::ScopedAStatus Vibrator::perform(Effect effect, EffectStrength strength,
-                                     const std::shared_ptr<IVibratorCallback> &callback,
-                                     int32_t *_aidl_return) {
-    HAPTICS_TRACE("perform(effect:%s, strength:%s, callback, _aidl_return)",
-                  toString(effect).c_str(), toString(strength).c_str());
-    ATRACE_NAME("Vibrator::perform");
-    ALOGD("perform");
-
-    mStatsApi->logLatencyStart(kPrebakedEffectLatency);
-
-    return performEffect(effect, strength, callback, _aidl_return);
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedEffects(std::vector<Effect> *_aidl_return) {
-    HAPTICS_TRACE("getSupportedEffects(_aidl_return)");
-    *_aidl_return = {Effect::TEXTURE_TICK, Effect::TICK, Effect::CLICK, Effect::HEAVY_CLICK,
-                     Effect::DOUBLE_CLICK};
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::setAmplitude(float amplitude) {
-    HAPTICS_TRACE("setAmplitude(amplitude:%f)", amplitude);
-    ATRACE_NAME("Vibrator::setAmplitude");
-    if (amplitude <= 0.0f || amplitude > 1.0f) {
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-
-    if (!isUnderExternalControl()) {
-        return setEffectAmplitude(amplitude, 1.0);
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::setExternalControl(bool enabled) {
-    HAPTICS_TRACE("setExternalControl(enabled:%u)", enabled);
-    ATRACE_NAME("Vibrator::setExternalControl");
-    setGlobalAmplitude(enabled);
-
-    if (isUnderExternalControl() == enabled) {
-        if (enabled) {
-            ALOGE("Restart the external process.");
-            if (mHasHapticAlsaDevice) {
-                if (!enableHapticPcmAmp(&mHapticPcm, !enabled, mCard, mDevice)) {
-                    mStatsApi->logError(kAlsaFailError);
-                    ALOGE("Failed to %s haptic pcm device: %d", (enabled ? "enable" : "disable"),
-                          mDevice);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-                }
-            }
-            if (mHwApi->hasAspEnable()) {
-                if (!mHwApi->setAspEnable(!enabled)) {
-                    mStatsApi->logError(kHwApiError);
-                    ALOGE("Failed to set external control (%d): %s", errno, strerror(errno));
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-                }
-            }
-        } else {
-            ALOGE("The external control is already disabled.");
-            return ndk::ScopedAStatus::ok();
-        }
-    }
-    if (mHasHapticAlsaDevice) {
-        if (!enableHapticPcmAmp(&mHapticPcm, enabled, mCard, mDevice)) {
-            mStatsApi->logError(kAlsaFailError);
-            ALOGE("Failed to %s haptic pcm device: %d", (enabled ? "enable" : "disable"), mDevice);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-        }
-    }
-    if (mHwApi->hasAspEnable()) {
-        if (!mHwApi->setAspEnable(enabled)) {
-            mStatsApi->logError(kHwApiError);
-            ALOGE("Failed to set external control (%d): %s", errno, strerror(errno));
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-        }
-    }
-
-    mIsUnderExternalControl = enabled;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getCompositionDelayMax(int32_t *maxDelayMs) {
-    HAPTICS_TRACE("getCompositionDelayMax(maxDelayMs)");
-    ATRACE_NAME("Vibrator::getCompositionDelayMax");
-    *maxDelayMs = COMPOSE_DELAY_MAX_MS;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getCompositionSizeMax(int32_t *maxSize) {
-    HAPTICS_TRACE("getCompositionSizeMax(maxSize)");
-    ATRACE_NAME("Vibrator::getCompositionSizeMax");
-    *maxSize = COMPOSE_SIZE_MAX;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedPrimitives(std::vector<CompositePrimitive> *supported) {
-    HAPTICS_TRACE("getSupportedPrimitives(supported)");
-    *supported = {
-            CompositePrimitive::NOOP,       CompositePrimitive::CLICK,
-            CompositePrimitive::THUD,       CompositePrimitive::SPIN,
-            CompositePrimitive::QUICK_RISE, CompositePrimitive::SLOW_RISE,
-            CompositePrimitive::QUICK_FALL, CompositePrimitive::LIGHT_TICK,
-            CompositePrimitive::LOW_TICK,
-    };
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getPrimitiveDuration(CompositePrimitive primitive,
-                                                  int32_t *durationMs) {
-    HAPTICS_TRACE("getPrimitiveDuration(primitive:%s, durationMs)", toString(primitive).c_str());
-    ndk::ScopedAStatus status;
-    uint32_t effectIndex;
-
-    if (primitive != CompositePrimitive::NOOP) {
-        status = getPrimitiveDetails(primitive, &effectIndex);
-        if (!status.isOk()) {
-            return status;
-        }
-
-        *durationMs = mEffectDurations[effectIndex];
-    } else {
-        *durationMs = 0;
-    }
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::compose(const std::vector<CompositeEffect> &composite,
-                                     const std::shared_ptr<IVibratorCallback> &callback) {
-    HAPTICS_TRACE("compose(composite, callback)");
-    ATRACE_NAME("Vibrator::compose");
-    ALOGD("compose");
-    std::ostringstream effectBuilder;
-    std::string effectQueue;
-
-    mStatsApi->logLatencyStart(kCompositionEffectLatency);
-
-    if (composite.size() > COMPOSE_SIZE_MAX) {
-        mStatsApi->logError(kBadCompositeError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-    const std::scoped_lock<std::mutex> lock(mTotalDurationMutex);
-
-    // Reset the mTotalDuration
-    mTotalDuration = 0;
-    for (auto &e : composite) {
-        if (e.scale < 0.0f || e.scale > 1.0f) {
-            mStatsApi->logError(kBadCompositeError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-        }
-
-        if (e.delayMs) {
-            if (e.delayMs > COMPOSE_DELAY_MAX_MS) {
-                mStatsApi->logError(kBadCompositeError);
-                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-            }
-            effectBuilder << e.delayMs << ",";
-            mTotalDuration += e.delayMs;
-        }
-        if (e.primitive != CompositePrimitive::NOOP) {
-            ndk::ScopedAStatus status;
-            uint32_t effectIndex;
-
-            status = getPrimitiveDetails(e.primitive, &effectIndex);
-            mStatsApi->logPrimitive(effectIndex);
-            if (!status.isOk()) {
-                mStatsApi->logError(kBadCompositeError);
-                return status;
-            }
-
-            effectBuilder << effectIndex << "." << intensityToVolLevel(e.scale, effectIndex) << ",";
-            mTotalDuration += mEffectDurations[effectIndex];
-
-            mTotalDuration += mDelayEffectDurations[effectIndex];
-        }
-    }
-
-    if (effectBuilder.tellp() == 0) {
-        mStatsApi->logError(kComposeFailError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-
-    effectBuilder << 0;
-
-    effectQueue = effectBuilder.str();
-
-    return performEffect(0 /*ignored*/, 0 /*ignored*/, &effectQueue, callback);
-}
-
-ndk::ScopedAStatus Vibrator::on(uint32_t timeoutMs, uint32_t effectIndex,
-                                const std::shared_ptr<IVibratorCallback> &callback) {
-    HAPTICS_TRACE("on(timeoutMs:%u, effectIndex:%u, callback)", timeoutMs, effectIndex);
-    if (isUnderExternalControl()) {
-        setExternalControl(false);
-        ALOGE("Device is under external control mode. Force to disable it to prevent chip hang "
-              "problem.");
-    }
-    if (mAsyncHandle.wait_for(ASYNC_COMPLETION_TIMEOUT) != std::future_status::ready) {
-        mStatsApi->logError(kAsyncFailError);
-        ALOGE("Previous vibration pending: prev: %d, curr: %d", mActiveId, effectIndex);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    ALOGD("on");
-    mHwApi->setEffectIndex(effectIndex);
-    mHwApi->setDuration(timeoutMs);
-    mStatsApi->logLatencyEnd();
-    mHwApi->setActivate(1);
-    // Using the mToalDuration for composed effect.
-    // For composed effect, we set the UINT32_MAX to the duration sysfs node,
-    // but it not a practical way to use it to monitor the total duration time.
-    if (timeoutMs != UINT32_MAX) {
-        const std::scoped_lock<std::mutex> lock(mTotalDurationMutex);
-        mTotalDuration = timeoutMs;
-    }
-
-    mActiveId = effectIndex;
-
-    mAsyncHandle = std::async(&Vibrator::waitForComplete, this, callback);
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::setEffectAmplitude(float amplitude, float maximum) {
-    HAPTICS_TRACE("setEffectAmplitude(amplitude:%f, maximum:%f)", amplitude, maximum);
-    int32_t scale = amplitudeToScale(amplitude, maximum);
-
-    if (!mHwApi->setEffectScale(scale)) {
-        mStatsApi->logError(kHwApiError);
-        ALOGE("Failed to set effect amplitude (%d): %s", errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::setGlobalAmplitude(bool set) {
-    HAPTICS_TRACE("setGlobalAmplitude(set:%u)", set);
-    uint8_t amplitude = set ? mLongEffectVol[1] : VOLTAGE_SCALE_MAX;
-    int32_t scale = amplitudeToScale(amplitude, VOLTAGE_SCALE_MAX);
-
-    if (!mHwApi->setGlobalScale(scale)) {
-        mStatsApi->logError(kHwApiError);
-        ALOGE("Failed to set global amplitude (%d): %s", errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedAlwaysOnEffects(std::vector<Effect> *_aidl_return) {
-    HAPTICS_TRACE("getSupportedAlwaysOnEffects(_aidl_return)");
-    *_aidl_return = {Effect::TEXTURE_TICK, Effect::TICK, Effect::CLICK, Effect::HEAVY_CLICK};
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::alwaysOnEnable(int32_t id, Effect effect, EffectStrength strength) {
-    HAPTICS_TRACE("alwaysOnEnable(id:%d, effect:%s, strength:%s)", id, toString(effect).c_str(),
-                  toString(strength).c_str());
-    ndk::ScopedAStatus status;
-    uint32_t effectIndex;
-    uint32_t timeMs;
-    uint32_t volLevel;
-    uint32_t scale;
-
-    status = getSimpleDetails(effect, strength, &effectIndex, &timeMs, &volLevel);
-    if (!status.isOk()) {
-        return status;
-    }
-
-    scale = amplitudeToScale(volLevel, VOLTAGE_SCALE_MAX);
-
-    switch (static_cast<AlwaysOnId>(id)) {
-        case AlwaysOnId::GPIO_RISE:
-            mHwApi->setGpioRiseIndex(effectIndex);
-            mHwApi->setGpioRiseScale(scale);
-            return ndk::ScopedAStatus::ok();
-        case AlwaysOnId::GPIO_FALL:
-            mHwApi->setGpioFallIndex(effectIndex);
-            mHwApi->setGpioFallScale(scale);
-            return ndk::ScopedAStatus::ok();
-    }
-
-    mStatsApi->logError(kUnsupportedOpError);
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::alwaysOnDisable(int32_t id) {
-    HAPTICS_TRACE("alwaysOnDisable(id: %d)", id);
-    switch (static_cast<AlwaysOnId>(id)) {
-        case AlwaysOnId::GPIO_RISE:
-            mHwApi->setGpioRiseIndex(0);
-            return ndk::ScopedAStatus::ok();
-        case AlwaysOnId::GPIO_FALL:
-            mHwApi->setGpioFallIndex(0);
-            return ndk::ScopedAStatus::ok();
-    }
-
-    mStatsApi->logError(kUnsupportedOpError);
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getResonantFrequency(float *resonantFreqHz) {
-    HAPTICS_TRACE("getResonantFrequency(resonantFreqHz)");
-    *resonantFreqHz = mResonantFrequency;
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getQFactor(float *qFactor) {
-    HAPTICS_TRACE("getQFactor(qFactor)");
-    uint32_t caldata;
-    if (!mHwCal->getQ(&caldata)) {
-        mStatsApi->logError(kHwCalError);
-        ALOGE("Failed to get q factor (%d): %s", errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-    *qFactor = static_cast<float>(caldata) / (1 << Q16_BIT_SHIFT);
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getFrequencyResolution(float *freqResolutionHz) {
-    HAPTICS_TRACE("getFrequencyResolution(freqResolutionHz)");
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_FREQUENCY_CONTROL) {
-        *freqResolutionHz = PWLE_FREQUENCY_RESOLUTION_HZ;
-        return ndk::ScopedAStatus::ok();
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::getFrequencyMinimum(float *freqMinimumHz) {
-    HAPTICS_TRACE("getFrequencyMinimum(freqMinimumHz)");
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_FREQUENCY_CONTROL) {
-        *freqMinimumHz = PWLE_FREQUENCY_MIN_HZ;
-        return ndk::ScopedAStatus::ok();
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-static float redcToFloat(uint32_t redcMeasured) {
-    HAPTICS_TRACE("redcToFloat(redcMeasured: %u)", redcMeasured);
-    return redcMeasured * 5.857 / (1 << Q17_BIT_SHIFT);
-}
-
-std::vector<float> Vibrator::generateBandwidthAmplitudeMap() {
-    HAPTICS_TRACE("generateBandwidthAmplitudeMap()");
-    // Use constant Q Factor of 10 from HW's suggestion
-    const float qFactor = 10.0f;
-    const float blSys = 1.1f;
-    const float gravity = 9.81f;
-    const float maxVoltage = 12.3f;
-    float deviceMass = 0, locCoeff = 0;
-
-    mHwCal->getDeviceMass(&deviceMass);
-    mHwCal->getLocCoeff(&locCoeff);
-    if (!deviceMass || !locCoeff) {
-        mStatsApi->logError(kInitError);
-        ALOGE("Failed to get Device Mass: %f and Loc Coeff: %f", deviceMass, locCoeff);
-        return std::vector<float>();
-    }
-
-    // Resistance value need to be retrieved from calibration file
-    if (!mRedc) {
-        mStatsApi->logError(kInitError);
-        ALOGE("Failed to get redc");
-        return std::vector<float>();
-    }
-    const float rSys = redcToFloat(mRedc);
-
-    std::vector<float> bandwidthAmplitudeMap(PWLE_BW_MAP_SIZE, 1.0);
-
-    const float wnSys = mResonantFrequency * 2 * M_PI;
-
-    float frequencyHz = PWLE_FREQUENCY_MIN_HZ;
-    float frequencyRadians = 0.0f;
-    float vLevel = 0.4f;
-    float vSys = (mLongEffectVol[1] / 100.0) * maxVoltage * vLevel;
-    float maxAsys = 0;
-
-    for (int i = 0; i < PWLE_BW_MAP_SIZE; i++) {
-        frequencyRadians = frequencyHz * 2 * M_PI;
-        vLevel = pwleMaxLevelLimitMap[i];
-        vSys = (mLongEffectVol[1] / 100.0) * maxVoltage * vLevel;
-
-        float var1 = pow((pow(wnSys, 2) - pow(frequencyRadians, 2)), 2);
-        float var2 = pow((wnSys * frequencyRadians / qFactor), 2);
-
-        float psysAbs = sqrt(var1 + var2);
-        // The equation and all related details: b/170919640#comment5
-        float amplitudeSys = (vSys * blSys * locCoeff / rSys / deviceMass) *
-                             pow(frequencyRadians, 2) / psysAbs / gravity;
-        // Record the maximum acceleration for the next for loop
-        if (amplitudeSys > maxAsys)
-            maxAsys = amplitudeSys;
-
-        bandwidthAmplitudeMap[i] = amplitudeSys;
-        frequencyHz += PWLE_FREQUENCY_RESOLUTION_HZ;
-    }
-    // Scaled the map between 0.00 and 1.00
-    if (maxAsys > 0) {
-        for (int j = 0; j < PWLE_BW_MAP_SIZE; j++) {
-            bandwidthAmplitudeMap[j] = std::floor((bandwidthAmplitudeMap[j] / maxAsys) * 100) / 100;
-        }
-        mGenerateBandwidthAmplitudeMapDone = true;
-    } else {
-        return std::vector<float>();
-    }
-
-    return bandwidthAmplitudeMap;
-}
-
-ndk::ScopedAStatus Vibrator::getBandwidthAmplitudeMap(std::vector<float> *_aidl_return) {
-    HAPTICS_TRACE("getBandwidthAmplitudeMap(_aidl_return)");
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_FREQUENCY_CONTROL) {
-        if (!mGenerateBandwidthAmplitudeMapDone) {
-            mBandwidthAmplitudeMap = generateBandwidthAmplitudeMap();
-        }
-        *_aidl_return = mBandwidthAmplitudeMap;
-        return (!mBandwidthAmplitudeMap.empty())
-                       ? ndk::ScopedAStatus::ok()
-                       : ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::getPwlePrimitiveDurationMax(int32_t *durationMs) {
-    HAPTICS_TRACE("getPwlePrimitiveDurationMax(durationMs)");
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_COMPOSE_PWLE_EFFECTS) {
-        *durationMs = COMPOSE_PWLE_PRIMITIVE_DURATION_MAX_MS;
-        return ndk::ScopedAStatus::ok();
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::getPwleCompositionSizeMax(int32_t *maxSize) {
-    HAPTICS_TRACE("getPwleCompositionSizeMax(maxSize)");
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_COMPOSE_PWLE_EFFECTS) {
-        uint32_t segments;
-        if (!mHwApi->getAvailablePwleSegments(&segments)) {
-            mStatsApi->logError(kHwApiError);
-            ALOGE("Failed to get availablePwleSegments (%d): %s", errno, strerror(errno));
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-        }
-        *maxSize = (segments > COMPOSE_PWLE_SIZE_LIMIT) ? COMPOSE_PWLE_SIZE_LIMIT : segments;
-        mCompositionSizeMax = *maxSize;
-        return ndk::ScopedAStatus::ok();
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedBraking(std::vector<Braking> *supported) {
-    HAPTICS_TRACE("getSupportedBraking(supported)");
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_COMPOSE_PWLE_EFFECTS) {
-        *supported = {
-            Braking::NONE,
-            Braking::CLAB,
-        };
-        return ndk::ScopedAStatus::ok();
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::setPwle(const std::string &pwleQueue) {
-    HAPTICS_TRACE("setPwle(pwleQueue:%s)", pwleQueue.c_str());
-    if (!mHwApi->setPwle(pwleQueue)) {
-        mStatsApi->logError(kHwApiError);
-        ALOGE("Failed to write \"%s\" to pwle (%d): %s", pwleQueue.c_str(), errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    return ndk::ScopedAStatus::ok();
-}
-
-static void incrementIndex(int *index) {
-    *index += 1;
-}
-
-static void constructActiveDefaults(std::ostringstream &pwleBuilder, const int &segmentIdx) {
-    HAPTICS_TRACE("constructActiveDefaults(pwleBuilder, segmentIdx:%d)", segmentIdx);
-    pwleBuilder << ",C" << segmentIdx << ":1";
-    pwleBuilder << ",B" << segmentIdx << ":0";
-    pwleBuilder << ",AR" << segmentIdx << ":0";
-    pwleBuilder << ",V" << segmentIdx << ":0";
-}
-
-static void constructActiveSegment(std::ostringstream &pwleBuilder, const int &segmentIdx,
-                                   int duration, float amplitude, float frequency) {
-    HAPTICS_TRACE(
-            "constructActiveSegment(pwleBuilder, segmentIdx:%d, duration:%d, amplitude:%f, "
-            "frequency:%f)",
-            segmentIdx, duration, amplitude, frequency);
-    pwleBuilder << ",T" << segmentIdx << ":" << duration;
-    pwleBuilder << ",L" << segmentIdx << ":" << std::setprecision(1) << amplitude;
-    pwleBuilder << ",F" << segmentIdx << ":" << std::lroundf(frequency);
-    constructActiveDefaults(pwleBuilder, segmentIdx);
-}
-
-static void constructBrakingSegment(std::ostringstream &pwleBuilder, const int &segmentIdx,
-                                    int duration, Braking brakingType, float frequency) {
-    HAPTICS_TRACE(
-            "constructActiveSegment(pwleBuilder, segmentIdx:%d, duration:%d, brakingType:%s, "
-            "frequency:%f)",
-            segmentIdx, duration, toString(brakingType).c_str(), frequency);
-    pwleBuilder << ",T" << segmentIdx << ":" << duration;
-    pwleBuilder << ",L" << segmentIdx << ":" << 0;
-    pwleBuilder << ",F" << segmentIdx << ":" << std::lroundf(frequency);
-    pwleBuilder << ",C" << segmentIdx << ":0";
-    pwleBuilder << ",B" << segmentIdx << ":"
-                << static_cast<std::underlying_type<Braking>::type>(brakingType);
-    pwleBuilder << ",AR" << segmentIdx << ":0";
-    pwleBuilder << ",V" << segmentIdx << ":0";
-}
-
-ndk::ScopedAStatus Vibrator::composePwle(const std::vector<PrimitivePwle> &composite,
-                                         const std::shared_ptr<IVibratorCallback> &callback) {
-    HAPTICS_TRACE("composePwle(composite, callback)");
-    ATRACE_NAME("Vibrator::composePwle");
-    std::ostringstream pwleBuilder;
-    std::string pwleQueue;
-
-    mStatsApi->logLatencyStart(kPwleEffectLatency);
-
-    if (!mIsChirpEnabled) {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    if (composite.size() <= 0 || composite.size() > mCompositionSizeMax) {
-        mStatsApi->logError(kBadCompositeError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-
-    float prevEndAmplitude = 0;
-    float prevEndFrequency = mResonantFrequency;
-
-    int segmentIdx = 0;
-    uint32_t totalDuration = 0;
-
-    pwleBuilder << "S:0,WF:4,RP:0,WT:0";
-
-    for (auto &e : composite) {
-        switch (e.getTag()) {
-            case PrimitivePwle::active: {
-                auto active = e.get<PrimitivePwle::active>();
-                if (active.duration < 0 ||
-                    active.duration > COMPOSE_PWLE_PRIMITIVE_DURATION_MAX_MS) {
-                    mStatsApi->logError(kBadCompositeError);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-                if (active.startAmplitude < PWLE_LEVEL_MIN ||
-                    active.startAmplitude > PWLE_LEVEL_MAX ||
-                    active.endAmplitude < PWLE_LEVEL_MIN || active.endAmplitude > PWLE_LEVEL_MAX) {
-                    mStatsApi->logError(kBadCompositeError);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-                if (active.startAmplitude > CS40L2X_PWLE_LEVEL_MAX) {
-                    active.startAmplitude = CS40L2X_PWLE_LEVEL_MAX;
-                }
-                if (active.endAmplitude > CS40L2X_PWLE_LEVEL_MAX) {
-                    active.endAmplitude = CS40L2X_PWLE_LEVEL_MAX;
-                }
-
-                if (active.startFrequency < PWLE_FREQUENCY_MIN_HZ ||
-                    active.startFrequency > PWLE_FREQUENCY_MAX_HZ ||
-                    active.endFrequency < PWLE_FREQUENCY_MIN_HZ ||
-                    active.endFrequency > PWLE_FREQUENCY_MAX_HZ) {
-                    mStatsApi->logError(kBadCompositeError);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-
-                // clip to the hard limit on input level from pwleMaxLevelLimitMap
-                float maxLevelLimit =
-                    pwleMaxLevelLimitMap[active.startFrequency / PWLE_FREQUENCY_RESOLUTION_HZ - 1];
-                if (active.startAmplitude > maxLevelLimit) {
-                    active.startAmplitude = maxLevelLimit;
-                }
-                maxLevelLimit =
-                    pwleMaxLevelLimitMap[active.endFrequency / PWLE_FREQUENCY_RESOLUTION_HZ - 1];
-                if (active.endAmplitude > maxLevelLimit) {
-                    active.endAmplitude = maxLevelLimit;
-                }
-
-                if (!((active.startAmplitude == prevEndAmplitude) &&
-                      (active.startFrequency == prevEndFrequency))) {
-                    constructActiveSegment(pwleBuilder, segmentIdx, 0, active.startAmplitude,
-                                           active.startFrequency);
-                    incrementIndex(&segmentIdx);
-                }
-
-                constructActiveSegment(pwleBuilder, segmentIdx, active.duration,
-                                       active.endAmplitude, active.endFrequency);
-                incrementIndex(&segmentIdx);
-
-                prevEndAmplitude = active.endAmplitude;
-                prevEndFrequency = active.endFrequency;
-                totalDuration += active.duration;
-                break;
-            }
-            case PrimitivePwle::braking: {
-                auto braking = e.get<PrimitivePwle::braking>();
-                if (braking.braking > Braking::CLAB) {
-                    mStatsApi->logError(kBadPrimitiveError);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-                if (braking.duration > COMPOSE_PWLE_PRIMITIVE_DURATION_MAX_MS) {
-                    mStatsApi->logError(kBadPrimitiveError);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-
-                constructBrakingSegment(pwleBuilder, segmentIdx, braking.duration, braking.braking,
-                                        prevEndFrequency);
-                incrementIndex(&segmentIdx);
-
-                prevEndAmplitude = 0;
-                totalDuration += braking.duration;
-                break;
-            }
-        }
-    }
-
-    pwleQueue = pwleBuilder.str();
-    ALOGD("composePwle queue: (%s)", pwleQueue.c_str());
-
-    if (pwleQueue.size() > CS40L2X_PWLE_LENGTH_MAX) {
-        ALOGE("PWLE string too large(%u)", static_cast<uint32_t>(pwleQueue.size()));
-        mStatsApi->logError(kPwleConstructionFailError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    } else {
-        ALOGD("PWLE string : %u", static_cast<uint32_t>(pwleQueue.size()));
-        ndk::ScopedAStatus status = setPwle(pwleQueue);
-        if (!status.isOk()) {
-            mStatsApi->logError(kPwleConstructionFailError);
-            ALOGE("Failed to write pwle queue");
-            return status;
-        }
-    }
-    setEffectAmplitude(VOLTAGE_SCALE_MAX, VOLTAGE_SCALE_MAX);
-    mHwApi->setEffectIndex(WAVEFORM_UNSAVED_TRIGGER_QUEUE_INDEX);
-
-    totalDuration += MAX_COLD_START_LATENCY_MS;
-    mHwApi->setDuration(totalDuration);
-    {
-        const std::scoped_lock<std::mutex> lock(mTotalDurationMutex);
-        mTotalDuration = totalDuration;
-    }
-
-    mStatsApi->logLatencyEnd();
-    mHwApi->setActivate(1);
-
-    mAsyncHandle = std::async(&Vibrator::waitForComplete, this, callback);
-
-    return ndk::ScopedAStatus::ok();
-}
-
-bool Vibrator::isUnderExternalControl() {
-    HAPTICS_TRACE("isUnderExternalControl()");
-    return mIsUnderExternalControl;
-}
-
-binder_status_t Vibrator::dump(int fd, const char **args, uint32_t numArgs) {
-    HAPTICS_TRACE("dump(fd:%d, args, numArgs:%u)", fd, numArgs);
-    if (fd < 0) {
-        ALOGE("Called debug() with invalid fd.");
-        return STATUS_OK;
-    }
-
-    (void)args;
-    (void)numArgs;
-
-    dprintf(fd, "AIDL:\n");
-
-    dprintf(fd, "  F0 Offset: %" PRIu32 "\n", mF0Offset);
-
-    dprintf(fd, "  Voltage Levels:\n");
-    dprintf(fd, "    Tick Effect Min: %" PRIu32 " Max: %" PRIu32 "\n",
-            mTickEffectVol[0], mTickEffectVol[1]);
-    dprintf(fd, "    Click Effect Min: %" PRIu32 " Max: %" PRIu32 "\n",
-            mClickEffectVol[0], mClickEffectVol[1]);
-    dprintf(fd, "    Long Effect Min: %" PRIu32 " Max: %" PRIu32 "\n",
-            mLongEffectVol[0], mLongEffectVol[1]);
-
-    dprintf(fd, "  Effect Durations:");
-    for (auto d : mEffectDurations) {
-        dprintf(fd, " %" PRIu32, d);
-    }
-    dprintf(fd, "\n");
-
-    dprintf(fd, "\n");
-
-    mHwApi->debug(fd);
-
-    dprintf(fd, "\n");
-
-    mHwCal->debug(fd);
-
-    dprintf(fd, "\n");
-
-    mStatsApi->debug(fd);
-
-    fsync(fd);
-    return STATUS_OK;
-}
-
-ndk::ScopedAStatus Vibrator::getSimpleDetails(Effect effect, EffectStrength strength,
-                                              uint32_t *outEffectIndex, uint32_t *outTimeMs,
-                                              uint32_t *outVolLevel) {
-    HAPTICS_TRACE(
-            "getSimpleDetails(effect:%s, strength:%s, outEffectIndex, outTimeMs"
-            ", outVolLevel)",
-            toString(effect).c_str(), toString(strength).c_str());
-    uint32_t effectIndex;
-    uint32_t timeMs;
-    float intensity;
-    uint32_t volLevel;
-
-    switch (strength) {
-        case EffectStrength::LIGHT:
-            intensity = 0.5f;
-            break;
-        case EffectStrength::MEDIUM:
-            intensity = 0.7f;
-            break;
-        case EffectStrength::STRONG:
-            intensity = 1.0f;
-            break;
-        default:
-            mStatsApi->logError(kUnsupportedOpError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    switch (effect) {
-        case Effect::TEXTURE_TICK:
-            effectIndex = WAVEFORM_LIGHT_TICK_INDEX;
-            intensity *= 0.5f;
-            break;
-        case Effect::TICK:
-            effectIndex = WAVEFORM_CLICK_INDEX;
-            intensity *= 0.5f;
-            break;
-        case Effect::CLICK:
-            effectIndex = WAVEFORM_CLICK_INDEX;
-            intensity *= 0.7f;
-            break;
-        case Effect::HEAVY_CLICK:
-            effectIndex = WAVEFORM_CLICK_INDEX;
-            intensity *= 1.0f;
-            break;
-        default:
-            mStatsApi->logError(kUnsupportedOpError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    volLevel = intensityToVolLevel(intensity, effectIndex);
-    timeMs = mEffectDurations[effectIndex] + MAX_COLD_START_LATENCY_MS;
-    {
-        const std::scoped_lock<std::mutex> lock(mTotalDurationMutex);
-        mTotalDuration = timeMs;
-    }
-
-    *outEffectIndex = effectIndex;
-    *outTimeMs = timeMs;
-    *outVolLevel = volLevel;
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getCompoundDetails(Effect effect, EffectStrength strength,
-                                                uint32_t *outTimeMs, uint32_t * /*outVolLevel*/,
-                                                std::string *outEffectQueue) {
-    HAPTICS_TRACE(
-            "getCompoundDetails(effect:%s, strength:%s, outTimeMs, outVolLevel, outEffectQueue)",
-            toString(effect).c_str(), toString(strength).c_str());
-    ndk::ScopedAStatus status;
-    uint32_t timeMs;
-    std::ostringstream effectBuilder;
-    uint32_t thisEffectIndex;
-    uint32_t thisTimeMs;
-    uint32_t thisVolLevel;
-
-    switch (effect) {
-        case Effect::DOUBLE_CLICK:
-            timeMs = 0;
-
-            status = getSimpleDetails(Effect::CLICK, strength, &thisEffectIndex, &thisTimeMs,
-                                      &thisVolLevel);
-            if (!status.isOk()) {
-                return status;
-            }
-            effectBuilder << thisEffectIndex << "." << thisVolLevel;
-            timeMs += thisTimeMs;
-
-            effectBuilder << ",";
-
-            effectBuilder << WAVEFORM_DOUBLE_CLICK_SILENCE_MS;
-            timeMs += WAVEFORM_DOUBLE_CLICK_SILENCE_MS + MAX_PAUSE_TIMING_ERROR_MS;
-
-            effectBuilder << ",";
-
-            status = getSimpleDetails(Effect::HEAVY_CLICK, strength, &thisEffectIndex, &thisTimeMs,
-                                      &thisVolLevel);
-            if (!status.isOk()) {
-                return status;
-            }
-            effectBuilder << thisEffectIndex << "." << thisVolLevel;
-            timeMs += thisTimeMs;
-            {
-                const std::scoped_lock<std::mutex> lock(mTotalDurationMutex);
-                mTotalDuration = timeMs;
-            }
-
-            break;
-        default:
-            mStatsApi->logError(kUnsupportedOpError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    *outTimeMs = timeMs;
-    *outEffectQueue = effectBuilder.str();
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getPrimitiveDetails(CompositePrimitive primitive,
-                                                 uint32_t *outEffectIndex) {
-    HAPTICS_TRACE("getPrimitiveDetails(primitive:%s, outEffectIndex)", toString(primitive).c_str());
-    uint32_t effectIndex;
-
-    switch (primitive) {
-        case CompositePrimitive::NOOP:
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-        case CompositePrimitive::CLICK:
-            effectIndex = WAVEFORM_CLICK_INDEX;
-            break;
-        case CompositePrimitive::THUD:
-            effectIndex = WAVEFORM_THUD_INDEX;
-            break;
-        case CompositePrimitive::SPIN:
-            effectIndex = WAVEFORM_SPIN_INDEX;
-            break;
-        case CompositePrimitive::QUICK_RISE:
-            effectIndex = WAVEFORM_QUICK_RISE_INDEX;
-            break;
-        case CompositePrimitive::SLOW_RISE:
-            effectIndex = WAVEFORM_SLOW_RISE_INDEX;
-            break;
-        case CompositePrimitive::QUICK_FALL:
-            effectIndex = WAVEFORM_QUICK_FALL_INDEX;
-            break;
-        case CompositePrimitive::LIGHT_TICK:
-            effectIndex = WAVEFORM_LIGHT_TICK_INDEX;
-            break;
-        case CompositePrimitive::LOW_TICK:
-            effectIndex = WAVEFORM_LOW_TICK_INDEX;
-            break;
-        default:
-            mStatsApi->logError(kUnsupportedOpError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    *outEffectIndex = effectIndex;
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::setEffectQueue(const std::string &effectQueue) {
-    HAPTICS_TRACE("setEffectQueue(effectQueue:%s)", effectQueue.c_str());
-    if (!mHwApi->setEffectQueue(effectQueue)) {
-        ALOGE("Failed to write \"%s\" to effect queue (%d): %s", effectQueue.c_str(), errno,
-              strerror(errno));
-        mStatsApi->logError(kHwApiError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::performEffect(Effect effect, EffectStrength strength,
-                                           const std::shared_ptr<IVibratorCallback> &callback,
-                                           int32_t *outTimeMs) {
-    HAPTICS_TRACE("performEffect(effect:%s, strength:%s, callback, outTimeMs)",
-                  toString(effect).c_str(), toString(strength).c_str());
-    ndk::ScopedAStatus status;
-    uint32_t effectIndex;
-    uint32_t timeMs = 0;
-    uint32_t volLevel;
-    std::string effectQueue;
-
-    switch (effect) {
-        case Effect::TEXTURE_TICK:
-            // fall-through
-        case Effect::TICK:
-            // fall-through
-        case Effect::CLICK:
-            // fall-through
-        case Effect::HEAVY_CLICK:
-            status = getSimpleDetails(effect, strength, &effectIndex, &timeMs, &volLevel);
-            break;
-        case Effect::DOUBLE_CLICK:
-            status = getCompoundDetails(effect, strength, &timeMs, &volLevel, &effectQueue);
-            break;
-        default:
-            mStatsApi->logError(kUnsupportedOpError);
-            status = ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-            break;
-    }
-    if (!status.isOk()) {
-        goto exit;
-    }
-
-    status = performEffect(effectIndex, volLevel, &effectQueue, callback);
-
-exit:
-
-    *outTimeMs = timeMs;
-    return status;
-}
-
-ndk::ScopedAStatus Vibrator::performEffect(uint32_t effectIndex, uint32_t volLevel,
-                                           const std::string *effectQueue,
-                                           const std::shared_ptr<IVibratorCallback> &callback) {
-    HAPTICS_TRACE("performEffect(effectIndex:%u, volLevel:%u, effectQueue:%s, callback)",
-                  effectIndex, volLevel, effectQueue->c_str());
-    if (effectQueue && !effectQueue->empty()) {
-        ndk::ScopedAStatus status = setEffectQueue(*effectQueue);
-        if (!status.isOk()) {
-            return status;
-        }
-        setEffectAmplitude(VOLTAGE_SCALE_MAX, VOLTAGE_SCALE_MAX);
-        effectIndex = WAVEFORM_TRIGGER_QUEUE_INDEX;
-    } else {
-        setEffectAmplitude(volLevel, VOLTAGE_SCALE_MAX);
-    }
-
-    return on(MAX_TIME_MS, effectIndex, callback);
-}
-
-void Vibrator::waitForComplete(std::shared_ptr<IVibratorCallback> &&callback) {
-    HAPTICS_TRACE("waitForComplete(callback)");
-    ALOGD("waitForComplete");
-    uint32_t duration;
-    {
-        const std::scoped_lock<std::mutex> lock(mTotalDurationMutex);
-        duration = ((mTotalDuration + POLLING_TIMEOUT) < UINT32_MAX)
-                           ? mTotalDuration + POLLING_TIMEOUT
-                           : UINT32_MAX;
-    }
-    if (!mHwApi->pollVibeState(false, duration)) {
-        ALOGE("Timeout(%u)! Fail to poll STOP state", duration);
-    } else {
-        ALOGD("waitForComplete: Get STOP! Set active to 0.");
-    }
-    mHwApi->setActivate(false);
-
-    if (callback) {
-        auto ret = callback->onComplete();
-        if (!ret.isOk()) {
-            mStatsApi->logError(kAsyncFailError);
-            ALOGE("Failed completion callback: %d", ret.getExceptionCode());
-        }
-    }
-}
-
-uint32_t Vibrator::intensityToVolLevel(float intensity, uint32_t effectIndex) {
-    HAPTICS_TRACE("intensityToVolLevel(intensity:%f, effectIndex:%u)", intensity, effectIndex);
-    uint32_t volLevel;
-    auto calc = [](float intst, std::array<uint32_t, 2> v) -> uint32_t {
-                return std::lround(intst * (v[1] - v[0])) + v[0]; };
-
-    switch (effectIndex) {
-        case WAVEFORM_LIGHT_TICK_INDEX:
-            volLevel = calc(intensity, mTickEffectVol);
-            break;
-        case WAVEFORM_QUICK_RISE_INDEX:
-            // fall-through
-        case WAVEFORM_QUICK_FALL_INDEX:
-            volLevel = calc(intensity, mLongEffectVol);
-            break;
-        case WAVEFORM_CLICK_INDEX:
-            // fall-through
-        case WAVEFORM_THUD_INDEX:
-            // fall-through
-        case WAVEFORM_SPIN_INDEX:
-            // fall-through
-        case WAVEFORM_SLOW_RISE_INDEX:
-            // fall-through
-        default:
-            volLevel = calc(intensity, mClickEffectVol);
-            break;
-    }
-
-    return volLevel;
-}
-
-bool Vibrator::findHapticAlsaDevice(int *card, int *device) {
-    HAPTICS_TRACE("findHapticAlsaDevice(card, device)");
-    std::string line;
-    std::ifstream myfile(PROC_SND_PCM);
-    if (myfile.is_open()) {
-        while (getline(myfile, line)) {
-            if (line.find(HAPTIC_PCM_DEVICE_SYMBOL) != std::string::npos) {
-                std::stringstream ss(line);
-                std::string currentToken;
-                std::getline(ss, currentToken, ':');
-                sscanf(currentToken.c_str(), "%d-%d", card, device);
-                return true;
-            }
-        }
-        myfile.close();
-    } else {
-        mStatsApi->logError(kAlsaFailError);
-        ALOGE("Failed to read file: %s", PROC_SND_PCM);
-    }
-    return false;
-}
-
-bool Vibrator::hasHapticAlsaDevice() {
-    HAPTICS_TRACE("hasHapticAlsaDevice()");
-    // We need to call findHapticAlsaDevice once only. Calling in the
-    // constructor is too early in the boot process and the pcm file contents
-    // are empty. Hence we make the call here once only right before we need to.
-    static bool configHapticAlsaDeviceDone = false;
-    if (!configHapticAlsaDeviceDone) {
-        if (findHapticAlsaDevice(&mCard, &mDevice)) {
-            mHasHapticAlsaDevice = true;
-            configHapticAlsaDeviceDone = true;
-        } else {
-            mStatsApi->logError(kAlsaFailError);
-            ALOGE("Haptic ALSA device not supported");
-        }
-    }
-    return mHasHapticAlsaDevice;
-}
-
-bool Vibrator::enableHapticPcmAmp(struct pcm **haptic_pcm, bool enable, int card, int device) {
-    HAPTICS_TRACE("enableHapticPcmAmp(pcm, enable:%u, card:%d, device:%d)", enable, card, device);
-    int ret = 0;
-
-    if (enable) {
-        *haptic_pcm = pcm_open(card, device, PCM_OUT, &haptic_nohost_config);
-        if (!pcm_is_ready(*haptic_pcm)) {
-            ALOGE("cannot open pcm_out driver: %s", pcm_get_error(*haptic_pcm));
-            goto fail;
-        }
-
-        ret = pcm_prepare(*haptic_pcm);
-        if (ret < 0) {
-            ALOGE("cannot prepare haptic_pcm: %s", pcm_get_error(*haptic_pcm));
-            goto fail;
-        }
-
-        ret = pcm_start(*haptic_pcm);
-        if (ret < 0) {
-            ALOGE("cannot start haptic_pcm: %s", pcm_get_error(*haptic_pcm));
-            goto fail;
-        }
-
-        return true;
-    } else {
-        if (*haptic_pcm) {
-            pcm_close(*haptic_pcm);
-            *haptic_pcm = NULL;
-        }
-        return true;
-    }
-
-fail:
-    pcm_close(*haptic_pcm);
-    *haptic_pcm = NULL;
-    return false;
-}
-
-void Vibrator::setPwleRampDown() {
-    HAPTICS_TRACE("setPwleRampDown()");
-    // The formula for calculating the ramp down coefficient to be written into
-    // pwle_ramp_down is as follows:
-    //    Crd = 1048.576 / Trd
-    // where Trd is the desired ramp down time in seconds
-    // pwle_ramp_down accepts only 24 bit integers values
-
-    if (RAMP_DOWN_TIME_MS != 0.0) {
-        const float seconds = RAMP_DOWN_TIME_MS / 1000;
-        const auto ramp_down_coefficient = static_cast<uint32_t>(RAMP_DOWN_CONSTANT / seconds);
-        if (!mHwApi->setPwleRampDown(ramp_down_coefficient)) {
-            mStatsApi->logError(kHwApiError);
-            ALOGE("Failed to write \"%d\" to pwle_ramp_down (%d): %s", ramp_down_coefficient, errno,
-                  strerror(errno));
-        }
-    } else {
-        // Turn off the low level PWLE Ramp Down feature
-        if (!mHwApi->setPwleRampDown(0)) {
-            mStatsApi->logError(kHwApiError);
-            ALOGE("Failed to write 0 to pwle_ramp_down (%d): %s", errno, strerror(errno));
-        }
-    }
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l25/Vibrator.h b/vibrator/cs40l25/Vibrator.h
deleted file mode 100644
index e462cce2..00000000
--- a/vibrator/cs40l25/Vibrator.h
+++ /dev/null
@@ -1,264 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-#pragma once
-
-#include <aidl/android/hardware/vibrator/BnVibrator.h>
-#include <tinyalsa/asoundlib.h>
-
-#include <array>
-#include <fstream>
-#include <future>
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-class Vibrator : public BnVibrator {
-  public:
-    // APIs for interfacing with the kernel driver.
-    class HwApi {
-      public:
-        virtual ~HwApi() = default;
-        // Stores the LRA resonant frequency to be used for PWLE playback
-        // and click compensation.
-        virtual bool setF0(uint32_t value) = 0;
-        // Stores the frequency offset for long vibrations.
-        virtual bool setF0Offset(uint32_t value) = 0;
-        // Stores the LRA series resistance to be used for click
-        // compensation.
-        virtual bool setRedc(uint32_t value) = 0;
-        // Stores the LRA Q factor to be used for Q-dependent waveform
-        // selection.
-        virtual bool setQ(uint32_t value) = 0;
-        // Activates/deactivates the vibrator for durations specified by
-        // setDuration().
-        virtual bool setActivate(bool value) = 0;
-        // Specifies the vibration duration in milliseconds.
-        virtual bool setDuration(uint32_t value) = 0;
-        // Reports the number of effect waveforms loaded in firmware.
-        virtual bool getEffectCount(uint32_t *value) = 0;
-        // Reports the duration of the waveform selected by
-        // setEffectIndex(), measured in 48-kHz periods.
-        virtual bool getEffectDuration(uint32_t *value) = 0;
-        // Selects the waveform associated with vibration calls from
-        // the Android vibrator HAL.
-        virtual bool setEffectIndex(uint32_t value) = 0;
-        // Specifies an array of waveforms, delays, and repetition markers to
-        // generate complex waveforms.
-        virtual bool setEffectQueue(std::string value) = 0;
-        // Reports whether setEffectScale() is supported.
-        virtual bool hasEffectScale() = 0;
-        // Indicates the number of 0.125-dB steps of attenuation to apply to
-        // waveforms triggered in response to vibration calls from the
-        // Android vibrator HAL.
-        virtual bool setEffectScale(uint32_t value) = 0;
-        // Indicates the number of 0.125-dB steps of attenuation to apply to
-        // any output waveform (additive to all other set*Scale()
-        // controls).
-        virtual bool setGlobalScale(uint32_t value) = 0;
-        // Specifies the active state of the vibrator
-        // (true = enabled, false = disabled).
-        virtual bool setState(bool value) = 0;
-        // Reports whether getAspEnable()/setAspEnable() is supported.
-        virtual bool hasAspEnable() = 0;
-        // Enables/disables ASP playback.
-        virtual bool getAspEnable(bool *value) = 0;
-        // Reports enabled/disabled state of ASP playback.
-        virtual bool setAspEnable(bool value) = 0;
-        // Selects the waveform associated with a GPIO1 falling edge.
-        virtual bool setGpioFallIndex(uint32_t value) = 0;
-        // Indicates the number of 0.125-dB steps of attenuation to apply to
-        // waveforms triggered in response to a GPIO1 falling edge.
-        virtual bool setGpioFallScale(uint32_t value) = 0;
-        // Selects the waveform associated with a GPIO1 rising edge.
-        virtual bool setGpioRiseIndex(uint32_t value) = 0;
-        // Indicates the number of 0.125-dB steps of attenuation to apply to
-        // waveforms triggered in response to a GPIO1 rising edge.
-        virtual bool setGpioRiseScale(uint32_t value) = 0;
-        // Blocks until timeout or vibrator reaches desired state
-        // (true = enabled, false = disabled).
-        virtual bool pollVibeState(uint32_t value, int32_t timeoutMs = -1) = 0;
-        // Enables/disables closed-loop active braking.
-        virtual bool setClabEnable(bool value) = 0;
-        // Reports the number of available PWLE segments.
-        virtual bool getAvailablePwleSegments(uint32_t *value) = 0;
-        // Reports whether piecewise-linear envelope for waveforms is supported.
-        virtual bool hasPwle() = 0;
-        // Specifies piecewise-linear specifications to generate complex
-        // waveforms.
-        virtual bool setPwle(std::string value) = 0;
-        // Specifies the coefficient required for a ramp down when a waveform
-        // ends
-        virtual bool setPwleRampDown(uint32_t value) = 0;
-        // Emit diagnostic information to the given file.
-        virtual void debug(int fd) = 0;
-    };
-
-    // APIs for obtaining calibration/configuration data from persistent memory.
-    class HwCal {
-      public:
-        virtual ~HwCal() = default;
-        // Obtain the calibration version
-        virtual bool getVersion(uint32_t *value) = 0;
-        // Obtains the LRA resonant frequency to be used for PWLE playback
-        // and click compensation.
-        virtual bool getF0(uint32_t *value) = 0;
-        // Obtains the LRA series resistance to be used for click
-        // compensation.
-        virtual bool getRedc(uint32_t *value) = 0;
-        // Obtains the LRA Q factor to be used for Q-dependent waveform
-        // selection.
-        virtual bool getQ(uint32_t *value) = 0;
-        // Obtains frequency shift for long vibrations.
-        virtual bool getLongFrequencyShift(int32_t *value) = 0;
-        // Obtains device mass for calculating the bandwidth amplitude map
-        virtual bool getDeviceMass(float *value) = 0;
-        // Obtains loc coeff for calculating the bandwidth amplitude map
-        virtual bool getLocCoeff(float *value) = 0;
-        // Obtains the discreet voltage levels to be applied for the various
-        // waveforms, in units of 1%.
-        virtual bool getVolLevels(std::array<uint32_t, 6> *value) = 0;
-        // Obtains the v0/v1(min/max) voltage levels to be applied for
-        // tick/click/long in units of 1%.
-        virtual bool getTickVolLevels(std::array<uint32_t, 2> *value) = 0;
-        virtual bool getClickVolLevels(std::array<uint32_t, 2> *value) = 0;
-        virtual bool getLongVolLevels(std::array<uint32_t, 2> *value) = 0;
-        // Checks if the chirp feature is enabled.
-        virtual bool isChirpEnabled() = 0;
-        // Emit diagnostic information to the given file.
-        virtual void debug(int fd) = 0;
-    };
-
-    // APIs for logging data to statistics backend
-    class StatsApi {
-      public:
-        virtual ~StatsApi() = default;
-        // Increment count for effect
-        virtual bool logPrimitive(uint16_t effectIndex) = 0;
-        // Increment count for long/short waveform and duration bucket
-        virtual bool logWaveform(uint16_t effectIndex, int32_t duration) = 0;
-        // Increment count for error
-        virtual bool logError(uint16_t errorIndex) = 0;
-        // Start new latency measurement
-        virtual bool logLatencyStart(uint16_t latencyIndex) = 0;
-        // Finish latency measurement and update latency statistics with result
-        virtual bool logLatencyEnd() = 0;
-        // Emit diagnostic information to the given file.
-        virtual void debug(int fd) = 0;
-    };
-
-  public:
-    Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal,
-             std::unique_ptr<StatsApi> statsapi);
-
-    ndk::ScopedAStatus getCapabilities(int32_t *_aidl_return) override;
-    ndk::ScopedAStatus off() override;
-    ndk::ScopedAStatus on(int32_t timeoutMs,
-                          const std::shared_ptr<IVibratorCallback> &callback) override;
-    ndk::ScopedAStatus perform(Effect effect, EffectStrength strength,
-                               const std::shared_ptr<IVibratorCallback> &callback,
-                               int32_t *_aidl_return) override;
-    ndk::ScopedAStatus getSupportedEffects(std::vector<Effect> *_aidl_return) override;
-    ndk::ScopedAStatus setAmplitude(float amplitude) override;
-    ndk::ScopedAStatus setExternalControl(bool enabled) override;
-    ndk::ScopedAStatus getCompositionDelayMax(int32_t *maxDelayMs);
-    ndk::ScopedAStatus getCompositionSizeMax(int32_t *maxSize);
-    ndk::ScopedAStatus getSupportedPrimitives(std::vector<CompositePrimitive> *supported) override;
-    ndk::ScopedAStatus getPrimitiveDuration(CompositePrimitive primitive,
-                                            int32_t *durationMs) override;
-    ndk::ScopedAStatus compose(const std::vector<CompositeEffect> &composite,
-                               const std::shared_ptr<IVibratorCallback> &callback) override;
-    ndk::ScopedAStatus getSupportedAlwaysOnEffects(std::vector<Effect> *_aidl_return) override;
-    ndk::ScopedAStatus alwaysOnEnable(int32_t id, Effect effect, EffectStrength strength) override;
-    ndk::ScopedAStatus alwaysOnDisable(int32_t id) override;
-    ndk::ScopedAStatus getResonantFrequency(float *resonantFreqHz) override;
-    ndk::ScopedAStatus getQFactor(float *qFactor) override;
-    ndk::ScopedAStatus getFrequencyResolution(float *freqResolutionHz) override;
-    ndk::ScopedAStatus getFrequencyMinimum(float *freqMinimumHz) override;
-    ndk::ScopedAStatus getBandwidthAmplitudeMap(std::vector<float> *_aidl_return) override;
-    ndk::ScopedAStatus getPwlePrimitiveDurationMax(int32_t *durationMs) override;
-    ndk::ScopedAStatus getPwleCompositionSizeMax(int32_t *maxSize) override;
-    ndk::ScopedAStatus getSupportedBraking(std::vector<Braking> *supported) override;
-    ndk::ScopedAStatus composePwle(const std::vector<PrimitivePwle> &composite,
-                                   const std::shared_ptr<IVibratorCallback> &callback) override;
-
-    binder_status_t dump(int fd, const char **args, uint32_t numArgs) override;
-
-  private:
-    ndk::ScopedAStatus on(uint32_t timeoutMs, uint32_t effectIndex,
-                          const std::shared_ptr<IVibratorCallback> &callback);
-    // set 'amplitude' based on an arbitrary scale determined by 'maximum'
-    ndk::ScopedAStatus setEffectAmplitude(float amplitude, float maximum);
-    ndk::ScopedAStatus setGlobalAmplitude(bool set);
-    // 'simple' effects are those precompiled and loaded into the controller
-    ndk::ScopedAStatus getSimpleDetails(Effect effect, EffectStrength strength,
-                                        uint32_t *outEffectIndex, uint32_t *outTimeMs,
-                                        uint32_t *outVolLevel);
-    // 'compound' effects are those composed by stringing multiple 'simple' effects
-    ndk::ScopedAStatus getCompoundDetails(Effect effect, EffectStrength strength,
-                                          uint32_t *outTimeMs, uint32_t *outVolLevel,
-                                          std::string *outEffectQueue);
-    ndk::ScopedAStatus getPrimitiveDetails(CompositePrimitive primitive, uint32_t *outEffectIndex);
-    ndk::ScopedAStatus setEffectQueue(const std::string &effectQueue);
-    ndk::ScopedAStatus performEffect(Effect effect, EffectStrength strength,
-                                     const std::shared_ptr<IVibratorCallback> &callback,
-                                     int32_t *outTimeMs);
-    ndk::ScopedAStatus performEffect(uint32_t effectIndex, uint32_t volLevel,
-                                     const std::string *effectQueue,
-                                     const std::shared_ptr<IVibratorCallback> &callback);
-    ndk::ScopedAStatus setPwle(const std::string &pwleQueue);
-    bool isUnderExternalControl();
-    void waitForComplete(std::shared_ptr<IVibratorCallback> &&callback);
-    uint32_t intensityToVolLevel(float intensity, uint32_t effectIndex);
-    bool findHapticAlsaDevice(int *card, int *device);
-    bool hasHapticAlsaDevice();
-    bool enableHapticPcmAmp(struct pcm **haptic_pcm, bool enable, int card, int device);
-    void createPwleMaxLevelLimitMap();
-    void setPwleRampDown();
-    std::vector<float> generateBandwidthAmplitudeMap();
-
-    std::unique_ptr<HwApi> mHwApi;
-    std::unique_ptr<HwCal> mHwCal;
-    std::unique_ptr<StatsApi> mStatsApi;
-    uint32_t mF0Offset;
-    std::array<uint32_t, 2> mTickEffectVol;
-    std::array<uint32_t, 2> mClickEffectVol;
-    std::array<uint32_t, 2> mLongEffectVol;
-    std::vector<uint32_t> mEffectDurations;
-    std::vector<uint32_t> mDelayEffectDurations;
-    std::future<void> mAsyncHandle;
-    int32_t mCompositionSizeMax;
-    struct pcm *mHapticPcm;
-    int mCard;
-    int mDevice;
-    bool mHasHapticAlsaDevice;
-    bool mIsPrimitiveDelayEnabled;
-    bool mIsUnderExternalControl;
-    float mResonantFrequency;
-    uint32_t mRedc{0};
-    int8_t mActiveId{-1};
-    bool mIsChirpEnabled;
-    std::vector<float> mBandwidthAmplitudeMap;
-    bool mGenerateBandwidthAmplitudeMapDone;
-    uint32_t mTotalDuration{0};
-    std::mutex mTotalDurationMutex;
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25-dual.rc b/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25-dual.rc
deleted file mode 100644
index f9ed341c..00000000
--- a/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25-dual.rc
+++ /dev/null
@@ -1,78 +0,0 @@
-on boot
-    wait /sys/class/leds/vibrator_1/device
-
-    mkdir /mnt/vendor/persist/haptics 0770 system system
-    chmod 770 /mnt/vendor/persist/haptics
-    chmod 440 /mnt/vendor/persist/haptics/cs40l25a_dual.cal
-    chown system system /mnt/vendor/persist/haptics
-    chown system system /mnt/vendor/persist/haptics/cs40l25a_dual.cal
-
-    chown system system /sys/class/leds/vibrator_1/activate
-    chown system system /sys/class/leds/vibrator_1/brightness
-    chown system system /sys/class/leds/vibrator_1/duration
-    chown system system /sys/class/leds/vibrator_1/state
-
-    chown system system /sys/class/leds/vibrator_1/device/asp_enable
-    chown system system /sys/class/leds/vibrator_1/device/available_pwle_segments
-    chown system system /sys/class/leds/vibrator_1/device/clab_enable
-    chown system system /sys/class/leds/vibrator_1/device/comp_enable
-    chown system system /sys/class/leds/vibrator_1/device/cp_dig_scale
-    chown system system /sys/class/leds/vibrator_1/device/cp_trigger_duration
-    chown system system /sys/class/leds/vibrator_1/device/cp_trigger_index
-    chown system system /sys/class/leds/vibrator_1/device/cp_trigger_q_sub
-    chown system system /sys/class/leds/vibrator_1/device/cp_trigger_queue
-    chown system system /sys/class/leds/vibrator_1/device/dig_scale
-    chown system system /sys/class/leds/vibrator_1/device/exc_enable
-    chown system system /sys/class/leds/vibrator_1/device/f0_stored
-    chown system system /sys/class/leds/vibrator_1/device/f0_offset
-    chown system system /sys/class/leds/vibrator_1/device/fw_rev
-    chown system system /sys/class/leds/vibrator_1/device/gpio1_enable
-    chown system system /sys/class/leds/vibrator_1/device/gpio1_fall_dig_scale
-    chown system system /sys/class/leds/vibrator_1/device/gpio1_fall_index
-    chown system system /sys/class/leds/vibrator_1/device/gpio1_rise_dig_scale
-    chown system system /sys/class/leds/vibrator_1/device/gpio1_rise_index
-    chown system system /sys/class/leds/vibrator_1/device/gpio_event
-    chown system system /sys/class/leds/vibrator_1/device/gpio_trigger
-    chown system system /sys/class/leds/vibrator_1/device/heartbeat
-    chown system system /sys/class/leds/vibrator_1/device/hw_reset
-    chown system system /sys/class/leds/vibrator_1/device/num_waves
-    chown system system /sys/class/leds/vibrator_1/device/pwle
-    chown system system /sys/class/leds/vibrator_1/device/q_stored
-    chown system system /sys/class/leds/vibrator_1/device/redc_comp_enable
-    chown system system /sys/class/leds/vibrator_1/device/redc_stored
-    chown system system /sys/class/leds/vibrator_1/device/standby_timeout
-    chown system system /sys/class/leds/vibrator_1/device/vbatt_max
-    chown system system /sys/class/leds/vibrator_1/device/vbatt_min
-    chown system system /sys/class/leds/vibrator_1/device/vibe_state
-
-    enable vendor.vibrator.cs40l25-dual
-
-service vendor.vibrator.cs40l25-dual /vendor/bin/hw/android.hardware.vibrator-service.cs40l25-dual
-    class hal
-    user system
-    group system
-
-    setenv PROPERTY_PREFIX ro.vendor.vibrator.hal.
-    setenv CALIBRATION_FILEPATH /mnt/vendor/persist/haptics/cs40l25a_dual.cal
-
-    setenv HWAPI_PATH_PREFIX /sys/class/leds/vibrator_1/
-    setenv HWAPI_DEBUG_PATHS "
-        device/asp_enable
-        device/available_pwle_segments
-	device/clab_enable
-        device/f0_stored
-	device/f0_offset
-        device/fw_rev
-        device/gpio1_fall_dig_scale
-        device/gpio1_fall_index
-        device/gpio1_rise_dig_scale
-        device/gpio1_rise_index
-        device/heartbeat
-        device/num_waves
-        device/pwle
-        device/q_stored
-        device/redc_stored
-        state
-        "
-
-    disabled
diff --git a/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25-dual.xml b/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25-dual.xml
deleted file mode 100644
index 1bd3e7e8..00000000
--- a/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25-dual.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<manifest version="1.0" type="device">
-    <hal format="aidl">
-        <name>android.hardware.vibrator</name>
-        <version>2</version>
-        <fqname>IVibrator/dual</fqname>
-    </hal>
-</manifest>
diff --git a/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25.rc b/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25.rc
deleted file mode 100644
index 101cae87..00000000
--- a/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25.rc
+++ /dev/null
@@ -1,80 +0,0 @@
-on property:vendor.all.modules.ready=1
-    wait /sys/class/leds/vibrator/device
-
-    mkdir /mnt/vendor/persist/haptics 0770 system system
-    chmod 770 /mnt/vendor/persist/haptics
-    chmod 440 /mnt/vendor/persist/haptics/cs40l25a.cal
-    chown system system /mnt/vendor/persist/haptics
-    chown system system /mnt/vendor/persist/haptics/cs40l25a.cal
-
-    chown system system /sys/class/leds/vibrator/activate
-    chown system system /sys/class/leds/vibrator/brightness
-    chown system system /sys/class/leds/vibrator/duration
-    chown system system /sys/class/leds/vibrator/state
-
-    chown system system /sys/class/leds/vibrator/device/asp_enable
-    chown system system /sys/class/leds/vibrator/device/available_pwle_segments
-    chown system system /sys/class/leds/vibrator/device/clab_enable
-    chown system system /sys/class/leds/vibrator/device/comp_enable
-    chown system system /sys/class/leds/vibrator/device/cp_dig_scale
-    chown system system /sys/class/leds/vibrator/device/cp_trigger_duration
-    chown system system /sys/class/leds/vibrator/device/cp_trigger_index
-    chown system system /sys/class/leds/vibrator/device/cp_trigger_q_sub
-    chown system system /sys/class/leds/vibrator/device/cp_trigger_queue
-    chown system system /sys/class/leds/vibrator/device/dig_scale
-    chown system system /sys/class/leds/vibrator/device/exc_enable
-    chown system system /sys/class/leds/vibrator/device/f0_stored
-    chown system system /sys/class/leds/vibrator/device/f0_offset
-    chown system system /sys/class/leds/vibrator/device/fw_rev
-    chown system system /sys/class/leds/vibrator/device/gpio1_fall_dig_scale
-    chown system system /sys/class/leds/vibrator/device/gpio1_fall_index
-    chown system system /sys/class/leds/vibrator/device/gpio1_rise_dig_scale
-    chown system system /sys/class/leds/vibrator/device/gpio1_rise_index
-    chown system system /sys/class/leds/vibrator/device/heartbeat
-    chown system system /sys/class/leds/vibrator/device/hw_reset
-    chown system system /sys/class/leds/vibrator/device/num_waves
-    chown system system /sys/class/leds/vibrator/device/pwle
-    chown system system /sys/class/leds/vibrator/device/pwle_ramp_down
-    chown system system /sys/class/leds/vibrator/device/q_stored
-    chown system system /sys/class/leds/vibrator/device/redc_comp_enable
-    chown system system /sys/class/leds/vibrator/device/redc_stored
-    chown system system /sys/class/leds/vibrator/device/standby_timeout
-    chown system system /sys/class/leds/vibrator/device/vbatt_max
-    chown system system /sys/class/leds/vibrator/device/vbatt_min
-    chown system system /sys/class/leds/vibrator/device/vibe_state
-
-    enable vendor.vibrator.cs40l25
-
-service vendor.vibrator.cs40l25 /vendor/bin/hw/android.hardware.vibrator-service.cs40l25
-    class hal
-    user system
-    group system
-
-    setenv PROPERTY_PREFIX ro.vendor.vibrator.hal.
-    setenv CALIBRATION_FILEPATH /mnt/vendor/persist/haptics/cs40l25a.cal
-
-    setenv HWAPI_PATH_PREFIX /sys/class/leds/vibrator/
-    setenv HWAPI_DEBUG_PATHS "
-        device/asp_enable
-        device/available_pwle_segments
-        device/clab_enable
-        device/f0_stored
-        device/f0_offset
-        device/fw_rev
-        device/gpio1_fall_dig_scale
-        device/gpio1_fall_index
-        device/gpio1_rise_dig_scale
-        device/gpio1_rise_index
-        device/heartbeat
-        device/num_waves
-        device/pwle
-        device/pwle_ramp_down
-        device/q_stored
-        device/redc_stored
-        device/vibe_state
-        state
-        "
-
-    setenv STATS_INSTANCE default
-
-    disabled
diff --git a/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25.xml b/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25.xml
deleted file mode 100644
index 4db8f8c5..00000000
--- a/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<manifest version="1.0" type="device">
-    <hal format="aidl">
-        <name>android.hardware.vibrator</name>
-        <version>2</version>
-        <fqname>IVibrator/default</fqname>
-    </hal>
-</manifest>
diff --git a/vibrator/cs40l25/bench/Android.bp b/vibrator/cs40l25/bench/Android.bp
deleted file mode 100644
index 0f802fb4..00000000
--- a/vibrator/cs40l25/bench/Android.bp
+++ /dev/null
@@ -1,33 +0,0 @@
-//
-// Copyright (C) 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_benchmark {
-    name: "VibratorHalCs40l25Benchmark",
-    defaults: ["VibratorHalCs40l25TestDefaults"],
-    srcs: [
-        "benchmark.cpp",
-    ],
-    shared_libs: [
-        "libbase",
-    ],
-    // TODO(b/135767253): Remove when fixed.
-    test_suites: ["device-tests"],
-    // TODO(b/142024316): Remove when fixed.
-    require_root: true,
-}
diff --git a/vibrator/cs40l25/bench/Stats.h b/vibrator/cs40l25/bench/Stats.h
deleted file mode 100644
index 81f62348..00000000
--- a/vibrator/cs40l25/bench/Stats.h
+++ /dev/null
@@ -1,220 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#pragma once
-
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include <algorithm>
-#include <chrono>
-#include <mutex>
-
-#include "Vibrator.h"
-
-constexpr int32_t DURATION_BUCKET_WIDTH = 50;
-constexpr int32_t DURATION_50MS_BUCKET_COUNT = 20;
-constexpr int32_t DURATION_BUCKET_COUNT = DURATION_50MS_BUCKET_COUNT + 1;
-constexpr uint32_t MAX_TIME_MS = UINT16_MAX;
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-enum EffectLatency : uint16_t {
-    kPrebakedEffectLatency = 0,
-    kCompositionEffectLatency,
-    kPwleEffectLatency,
-
-    kEffectLatencyCount
-};
-
-enum VibratorError : uint16_t {
-    kInitError = 0,
-    kHwApiError,
-    kHwCalError,
-    kComposeFailError,
-    kAlsaFailError,
-    kAsyncFailError,
-    kBadTimeoutError,
-    kBadAmplitudeError,
-    kBadEffectError,
-    kBadEffectStrengthError,
-    kBadPrimitiveError,
-    kBadCompositeError,
-    kPwleConstructionFailError,
-    kUnsupportedOpError,
-
-    kVibratorErrorCount
-};
-
-class StatsApi : public Vibrator::StatsApi {
-  private:
-    static constexpr uint32_t BASE_CONTINUOUS_EFFECT_OFFSET = 32768;
-    enum WaveformIndex : uint16_t {
-        /* Physical waveform */
-        WAVEFORM_LONG_VIBRATION_EFFECT_INDEX = 0,
-        WAVEFORM_RESERVED_INDEX_1 = 1,
-        WAVEFORM_CLICK_INDEX = 2,
-        WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX = 3,
-        WAVEFORM_THUD_INDEX = 4,
-        WAVEFORM_SPIN_INDEX = 5,
-        WAVEFORM_QUICK_RISE_INDEX = 6,
-        WAVEFORM_SLOW_RISE_INDEX = 7,
-        WAVEFORM_QUICK_FALL_INDEX = 8,
-        WAVEFORM_LIGHT_TICK_INDEX = 9,
-        WAVEFORM_LOW_TICK_INDEX = 10,
-        WAVEFORM_RESERVED_MFG_1,
-        WAVEFORM_RESERVED_MFG_2,
-        WAVEFORM_RESERVED_MFG_3,
-        WAVEFORM_MAX_PHYSICAL_INDEX,
-        /* OWT waveform */
-        WAVEFORM_COMPOSE = WAVEFORM_MAX_PHYSICAL_INDEX,
-        WAVEFORM_PWLE,
-        /*
-         * Refer to <linux/input.h>, the WAVEFORM_MAX_INDEX must not exceed 96.
-         * #define FF_GAIN          0x60  // 96 in decimal
-         * #define FF_MAX_EFFECTS   FF_GAIN
-         */
-        WAVEFORM_MAX_INDEX,
-    };
-
-  public:
-    StatsApi() {
-        mWaveformCounts = std::vector<int32_t>(WAVEFORM_MAX_INDEX, 0);
-        mDurationCounts = std::vector<int32_t>(DURATION_BUCKET_COUNT, 0);
-        mMinLatencies = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mMaxLatencies = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mLatencyTotals = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mLatencyCounts = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mErrorCounts = std::vector<int32_t>(kVibratorErrorCount, 0);
-    }
-
-    bool logPrimitive(uint16_t effectIndex) override {
-        if (effectIndex >= WAVEFORM_MAX_PHYSICAL_INDEX ||
-            effectIndex == WAVEFORM_LONG_VIBRATION_EFFECT_INDEX ||
-            effectIndex == WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX) {
-            ALOGE("Invalid waveform index for logging primitive: %d", effectIndex);
-            return false;
-        }
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            mWaveformCounts[effectIndex]++;
-        }
-
-        return true;
-    }
-
-    bool logWaveform(uint16_t effectIndex, int32_t duration) override {
-        if (effectIndex != WAVEFORM_LONG_VIBRATION_EFFECT_INDEX &&
-            effectIndex != WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX + BASE_CONTINUOUS_EFFECT_OFFSET) {
-            ALOGE("Invalid waveform index for logging waveform: %d", effectIndex);
-            return false;
-        } else if (effectIndex ==
-                   WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX + BASE_CONTINUOUS_EFFECT_OFFSET) {
-            effectIndex = WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX;
-        }
-
-        if (duration > MAX_TIME_MS || duration < 0) {
-            ALOGE("Invalid waveform duration for logging waveform: %d", duration);
-            return false;
-        }
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            mWaveformCounts[effectIndex]++;
-            if (duration < DURATION_BUCKET_WIDTH * DURATION_50MS_BUCKET_COUNT) {
-                mDurationCounts[duration / DURATION_BUCKET_WIDTH]++;
-            } else {
-                mDurationCounts[DURATION_50MS_BUCKET_COUNT]++;
-            }
-        }
-
-        return true;
-    }
-
-    bool logError(uint16_t errorIndex) override {
-        if (errorIndex >= kVibratorErrorCount) {
-            ALOGE("Invalid index for logging error: %d", errorIndex);
-            return false;
-        }
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            mErrorCounts[errorIndex]++;
-        }
-
-        return true;
-    }
-
-    bool logLatencyStart(uint16_t latencyIndex) override {
-        if (latencyIndex >= kEffectLatencyCount) {
-            ALOGE("Invalid index for measuring latency: %d", latencyIndex);
-            return false;
-        }
-
-        mCurrentLatencyStart = std::chrono::steady_clock::now();
-        mCurrentLatencyIndex = latencyIndex;
-
-        return true;
-    }
-
-    bool logLatencyEnd() override {
-        if (mCurrentLatencyIndex >= kEffectLatencyCount) {
-            return false;
-        }
-
-        int32_t latency = (std::chrono::duration_cast<std::chrono::milliseconds>(
-                                   std::chrono::steady_clock::now() - mCurrentLatencyStart))
-                                  .count();
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            if (latency < mMinLatencies[mCurrentLatencyIndex] ||
-                mMinLatencies[mCurrentLatencyIndex] == 0) {
-                mMinLatencies[mCurrentLatencyIndex] = latency;
-            }
-            if (latency > mMaxLatencies[mCurrentLatencyIndex]) {
-                mMinLatencies[mCurrentLatencyIndex] = latency;
-            }
-            mLatencyTotals[mCurrentLatencyIndex] += latency;
-            mLatencyCounts[mCurrentLatencyIndex]++;
-        }
-
-        mCurrentLatencyIndex = kEffectLatencyCount;
-        return true;
-    }
-
-    void debug(int fd) override { (void)fd; }
-
-  private:
-    uint16_t mCurrentLatencyIndex;
-    std::chrono::time_point<std::chrono::steady_clock> mCurrentLatencyStart;
-    std::vector<int32_t> mWaveformCounts;
-    std::vector<int32_t> mDurationCounts;
-    std::vector<int32_t> mMinLatencies;
-    std::vector<int32_t> mMaxLatencies;
-    std::vector<int32_t> mLatencyTotals;
-    std::vector<int32_t> mLatencyCounts;
-    std::vector<int32_t> mErrorCounts;
-    std::mutex mDataAccess;
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l25/bench/benchmark.cpp b/vibrator/cs40l25/bench/benchmark.cpp
deleted file mode 100644
index f447315c..00000000
--- a/vibrator/cs40l25/bench/benchmark.cpp
+++ /dev/null
@@ -1,167 +0,0 @@
-/* * Copyright (C) 2019 The Android Open Source Project *
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
-#include "benchmark/benchmark.h"
-
-#include <android-base/file.h>
-#include <cutils/fs.h>
-
-#include "Hardware.h"
-#include "Stats.h"
-#include "Vibrator.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-class VibratorBench : public benchmark::Fixture {
-  private:
-    static constexpr const char *FILE_NAMES[]{
-            "device/f0_stored",
-            "device/redc_stored",
-            "device/q_stored",
-            "activate",
-            "duration",
-            "state",
-            "device/cp_trigger_duration",
-            "device/cp_trigger_index",
-            "device/cp_trigger_queue",
-            "device/cp_dig_scale",
-            "device/dig_scale",
-            "device/asp_enable",
-            "device/gpio1_fall_index",
-            "device/gpio1_fall_dig_scale",
-            "device/gpio1_rise_index",
-            "device/gpio1_rise_dig_scale",
-            "device/vibe_state",
-            "device/num_waves",
-    };
-
-  public:
-    void SetUp(::benchmark::State & /*state*/) override {
-        auto prefix = std::filesystem::path(mFilesDir.path) / "";
-        const std::map<const std::string, const std::string> content{
-                {"duration", std::to_string((uint32_t)std::rand() ?: 1)},
-                {"device/asp_enable", std::to_string(0)},
-                {"device/cp_trigger_duration", std::to_string(0)},
-                {"device/num_waves", std::to_string(10)},
-                {"device/vibe_state", std::to_string(0)},
-        };
-
-        setenv("HWAPI_PATH_PREFIX", prefix.c_str(), true);
-
-        for (auto n : FILE_NAMES) {
-            const auto it = content.find(n);
-            const auto name = std::filesystem::path(n);
-            const auto path = std::filesystem::path(mFilesDir.path) / name;
-
-            fs_mkdirs(path.c_str(), S_IRWXU);
-
-            if (it != content.end()) {
-                std::ofstream{path} << it->second << std::endl;
-            } else {
-                symlink("/dev/null", path.c_str());
-            }
-        }
-
-        mVibrator = ndk::SharedRefBase::make<Vibrator>(
-                std::make_unique<HwApi>(), std::make_unique<HwCal>(), std::make_unique<StatsApi>());
-    }
-
-    static void DefaultArgs(benchmark::internal::Benchmark *b) { b->Unit(benchmark::kMicrosecond); }
-
-    static void SupportedEffectArgs(benchmark::internal::Benchmark *b) {
-        b->ArgNames({"Effect", "Strength"});
-        for (Effect effect : ndk::enum_range<Effect>()) {
-            for (EffectStrength strength : ndk::enum_range<EffectStrength>()) {
-                b->Args({static_cast<long>(effect), static_cast<long>(strength)});
-            }
-        }
-    }
-
-  protected:
-    TemporaryDir mFilesDir;
-    std::shared_ptr<IVibrator> mVibrator;
-};
-
-#define BENCHMARK_WRAPPER(fixt, test, code) \
-    BENCHMARK_DEFINE_F(fixt, test)          \
-    /* NOLINTNEXTLINE */                    \
-    (benchmark::State & state){code} BENCHMARK_REGISTER_F(fixt, test)->Apply(fixt::DefaultArgs)
-
-BENCHMARK_WRAPPER(VibratorBench, on, {
-    uint32_t duration = std::rand() ?: 1;
-
-    for (auto _ : state) {
-        mVibrator->on(duration, nullptr);
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, off, {
-    for (auto _ : state) {
-        mVibrator->off();
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, setAmplitude, {
-    uint8_t amplitude = std::rand() ?: 1;
-
-    for (auto _ : state) {
-        mVibrator->setAmplitude(amplitude);
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, setExternalControl_enable, {
-    for (auto _ : state) {
-        mVibrator->setExternalControl(true);
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, setExternalControl_disable, {
-    for (auto _ : state) {
-        mVibrator->setExternalControl(false);
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, getCapabilities, {
-    int32_t capabilities;
-
-    for (auto _ : state) {
-        mVibrator->getCapabilities(&capabilities);
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, perform, {
-    Effect effect = Effect(state.range(0));
-    EffectStrength strength = EffectStrength(state.range(1));
-    int32_t lengthMs;
-
-    ndk::ScopedAStatus status = mVibrator->perform(effect, strength, nullptr, &lengthMs);
-
-    if (!status.isOk()) {
-        return;
-    }
-
-    for (auto _ : state) {
-        mVibrator->perform(effect, strength, nullptr, &lengthMs);
-    }
-})->Apply(VibratorBench::SupportedEffectArgs);
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
-
-BENCHMARK_MAIN();
diff --git a/vibrator/cs40l25/device-stereo.mk b/vibrator/cs40l25/device-stereo.mk
deleted file mode 100644
index 8a030974..00000000
--- a/vibrator/cs40l25/device-stereo.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-PRODUCT_PACKAGES += \
-    android.hardware.vibrator-service.cs40l25 \
-    android.hardware.vibrator-service.cs40l25-dual \
-
-BOARD_SEPOLICY_DIRS += \
-    hardware/google/pixel-sepolicy/vibrator/cs40l25 \
diff --git a/vibrator/cs40l25/device.mk b/vibrator/cs40l25/device.mk
deleted file mode 100644
index 61b95d5b..00000000
--- a/vibrator/cs40l25/device.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-PRODUCT_PACKAGES += \
-    android.hardware.vibrator-service.cs40l25 \
-
-BOARD_SEPOLICY_DIRS += \
-    hardware/google/pixel-sepolicy/vibrator/common \
-    hardware/google/pixel-sepolicy/vibrator/cs40l25 \
diff --git a/vibrator/cs40l25/fuzzer/Android.bp b/vibrator/cs40l25/fuzzer/Android.bp
deleted file mode 100644
index 5d990c61..00000000
--- a/vibrator/cs40l25/fuzzer/Android.bp
+++ /dev/null
@@ -1,38 +0,0 @@
-//
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_team: "trendy_team_pixel_system_sw_touch_haptic",
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_fuzz {
-    name: "VibratorHalCs40l25Fuzzer",
-    relative_install_path: "",
-    defaults: [
-        "VibratorHalCs40l25BinaryDefaults",
-        "service_fuzzer_defaults",
-    ],
-    srcs: [
-        "fuzzer-vibrator.cpp",
-    ],
-    shared_libs: [
-        "android.hardware.vibrator-impl.cs40l25",
-    ],
-    fuzz_config: {
-        triage_assignee: "pixel-haptics-triage@google.com",
-        componentid: 716924,
-    },
-}
diff --git a/vibrator/cs40l25/fuzzer/fuzzer-vibrator.cpp b/vibrator/cs40l25/fuzzer/fuzzer-vibrator.cpp
deleted file mode 100644
index 7fad1370..00000000
--- a/vibrator/cs40l25/fuzzer/fuzzer-vibrator.cpp
+++ /dev/null
@@ -1,55 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#include <fuzzbinder/libbinder_ndk_driver.h>
-#include <fuzzer/FuzzedDataProvider.h>
-
-#include "Hardware.h"
-#include "Vibrator.h"
-
-using ::aidl::android::hardware::vibrator::HwApi;
-using ::aidl::android::hardware::vibrator::HwCal;
-using ::aidl::android::hardware::vibrator::Vibrator;
-using android::fuzzService;
-using ndk::SharedRefBase;
-
-// No stats collection.
-class FakeStatsApi : public Vibrator::StatsApi {
-  public:
-    FakeStatsApi() = default;
-    ~FakeStatsApi() = default;
-
-    bool logPrimitive(uint16_t) override { return true; }
-
-    bool logWaveform(uint16_t, int32_t) override { return true; }
-
-    bool logError(uint16_t) override { return true; }
-
-    bool logLatencyStart(uint16_t) override { return true; }
-
-    bool logLatencyEnd() { return true; }
-
-    void debug(int32_t) override {}
-};
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
-    auto vibService = ndk::SharedRefBase::make<Vibrator>(
-            std::make_unique<HwApi>(), std::make_unique<HwCal>(), std::make_unique<FakeStatsApi>());
-
-    fuzzService(vibService->asBinder().get(), FuzzedDataProvider(data, size));
-
-    return 0;
-}
diff --git a/vibrator/cs40l25/service.cpp b/vibrator/cs40l25/service.cpp
deleted file mode 100644
index 81e2edef..00000000
--- a/vibrator/cs40l25/service.cpp
+++ /dev/null
@@ -1,57 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-#include <android/binder_manager.h>
-#include <android/binder_process.h>
-#include <binder/IServiceManager.h>
-#include <binder/ProcessState.h>
-#include <log/log.h>
-
-#include "Hardware.h"
-#include "Stats.h"
-#include "Vibrator.h"
-
-using ::aidl::android::hardware::vibrator::HwApi;
-using ::aidl::android::hardware::vibrator::HwCal;
-using ::aidl::android::hardware::vibrator::StatsApi;
-using ::aidl::android::hardware::vibrator::Vibrator;
-using ::android::defaultServiceManager;
-using ::android::ProcessState;
-using ::android::sp;
-using ::android::String16;
-
-#if !defined(VIBRATOR_NAME)
-#define VIBRATOR_NAME "default"
-#endif
-
-int main() {
-    auto svc = ndk::SharedRefBase::make<Vibrator>(
-            std::make_unique<HwApi>(), std::make_unique<HwCal>(), std::make_unique<StatsApi>());
-    const auto svcName = std::string() + svc->descriptor + "/" + VIBRATOR_NAME;
-
-    ProcessState::initWithDriver("/dev/vndbinder");
-
-    auto svcBinder = svc->asBinder();
-    binder_status_t status = AServiceManager_addService(svcBinder.get(), svcName.c_str());
-    LOG_ALWAYS_FATAL_IF(status != STATUS_OK);
-
-    ProcessState::self()->setThreadPoolMaxThreadCount(1);
-    ProcessState::self()->startThreadPool();
-
-    ABinderProcess_setThreadPoolMaxThreadCount(0);
-    ABinderProcess_joinThreadPool();
-
-    return EXIT_FAILURE;  // should not reach
-}
diff --git a/vibrator/cs40l25/tests/Android.bp b/vibrator/cs40l25/tests/Android.bp
deleted file mode 100644
index 4bff5ddc..00000000
--- a/vibrator/cs40l25/tests/Android.bp
+++ /dev/null
@@ -1,34 +0,0 @@
-//
-// Copyright (C) 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_test {
-    name: "VibratorHalCs40l25TestSuite",
-    defaults: ["VibratorHalCs40l25TestDefaults"],
-    srcs: [
-        "test-hwapi.cpp",
-        "test-hwcal.cpp",
-        "test-vibrator.cpp",
-    ],
-    static_libs: [
-        "libgmock",
-    ],
-    shared_libs: [
-        "libbase",
-    ],
-}
diff --git a/vibrator/cs40l25/tests/mocks.h b/vibrator/cs40l25/tests/mocks.h
deleted file mode 100644
index 3cd46fc4..00000000
--- a/vibrator/cs40l25/tests/mocks.h
+++ /dev/null
@@ -1,96 +0,0 @@
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
-#ifndef ANDROID_HARDWARE_VIBRATOR_TEST_MOCKS_H
-#define ANDROID_HARDWARE_VIBRATOR_TEST_MOCKS_H
-
-#include <aidl/android/hardware/vibrator/BnVibratorCallback.h>
-
-#include "Vibrator.h"
-
-class MockApi : public ::aidl::android::hardware::vibrator::Vibrator::HwApi {
-  public:
-    MOCK_METHOD0(destructor, void());
-    MOCK_METHOD1(setF0, bool(uint32_t value));
-    MOCK_METHOD1(setF0Offset, bool(uint32_t value));
-    MOCK_METHOD1(setRedc, bool(uint32_t value));
-    MOCK_METHOD1(setQ, bool(uint32_t value));
-    MOCK_METHOD1(setActivate, bool(bool value));
-    MOCK_METHOD1(setDuration, bool(uint32_t value));
-    MOCK_METHOD1(getEffectCount, bool(uint32_t *value));
-    MOCK_METHOD1(getEffectDuration, bool(uint32_t *value));
-    MOCK_METHOD1(setEffectIndex, bool(uint32_t value));
-    MOCK_METHOD1(setEffectQueue, bool(std::string value));
-    MOCK_METHOD0(hasEffectScale, bool());
-    MOCK_METHOD1(setEffectScale, bool(uint32_t value));
-    MOCK_METHOD1(setGlobalScale, bool(uint32_t value));
-    MOCK_METHOD1(setState, bool(bool value));
-    MOCK_METHOD0(hasAspEnable, bool());
-    MOCK_METHOD1(getAspEnable, bool(bool *value));
-    MOCK_METHOD1(setAspEnable, bool(bool value));
-    MOCK_METHOD1(setGpioFallIndex, bool(uint32_t value));
-    MOCK_METHOD1(setGpioFallScale, bool(uint32_t value));
-    MOCK_METHOD1(setGpioRiseIndex, bool(uint32_t value));
-    MOCK_METHOD1(setGpioRiseScale, bool(uint32_t value));
-    MOCK_METHOD2(pollVibeState, bool(uint32_t value, int32_t timeoutMs));
-    MOCK_METHOD1(setClabEnable, bool(bool value));
-    MOCK_METHOD1(getAvailablePwleSegments, bool(uint32_t *value));
-    MOCK_METHOD0(hasPwle, bool());
-    MOCK_METHOD1(setPwle, bool(std::string value));
-    MOCK_METHOD1(setPwleRampDown, bool(uint32_t value));
-    MOCK_METHOD1(debug, void(int fd));
-
-    ~MockApi() override { destructor(); };
-};
-
-class MockCal : public ::aidl::android::hardware::vibrator::Vibrator::HwCal {
-  public:
-    MOCK_METHOD0(destructor, void());
-    MOCK_METHOD1(getVersion, bool(uint32_t *value));
-    MOCK_METHOD1(getF0, bool(uint32_t *value));
-    MOCK_METHOD1(getRedc, bool(uint32_t *value));
-    MOCK_METHOD1(getQ, bool(uint32_t *value));
-    MOCK_METHOD1(getLongFrequencyShift, bool(int32_t *value));
-    MOCK_METHOD1(getVolLevels, bool(std::array<uint32_t, 6> *value));
-    MOCK_METHOD1(getTickVolLevels, bool(std::array<uint32_t, 2> *value));
-    MOCK_METHOD1(getClickVolLevels, bool(std::array<uint32_t, 2> *value));
-    MOCK_METHOD1(getLongVolLevels, bool(std::array<uint32_t, 2> *value));
-    MOCK_METHOD0(isChirpEnabled, bool());
-    MOCK_METHOD1(getDeviceMass, bool(float *value));
-    MOCK_METHOD1(getLocCoeff, bool(float *value));
-    MOCK_METHOD1(debug, void(int fd));
-
-    ~MockCal() override { destructor(); };
-};
-
-class MockStats : public ::aidl::android::hardware::vibrator::Vibrator::StatsApi {
-  public:
-    MOCK_METHOD0(destructor, void());
-    MOCK_METHOD1(logPrimitive, bool(uint16_t effectIndex));
-    MOCK_METHOD2(logWaveform, bool(uint16_t effectIndex, int32_t duration));
-    MOCK_METHOD1(logError, bool(uint16_t errorIndex));
-    MOCK_METHOD1(logLatencyStart, bool(uint16_t latencyIndex));
-    MOCK_METHOD0(logLatencyEnd, bool());
-    MOCK_METHOD1(debug, void(int fd));
-
-    ~MockStats() override { destructor(); };
-};
-
-class MockVibratorCallback : public aidl::android::hardware::vibrator::BnVibratorCallback {
-  public:
-    MOCK_METHOD(ndk::ScopedAStatus, onComplete, ());
-};
-
-#endif  // ANDROID_HARDWARE_VIBRATOR_TEST_MOCKS_H
diff --git a/vibrator/cs40l25/tests/test-hwapi.cpp b/vibrator/cs40l25/tests/test-hwapi.cpp
deleted file mode 100644
index a339207b..00000000
--- a/vibrator/cs40l25/tests/test-hwapi.cpp
+++ /dev/null
@@ -1,361 +0,0 @@
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
-#include <android-base/file.h>
-#include <cutils/fs.h>
-#include <gtest/gtest.h>
-
-#include <cstdlib>
-#include <fstream>
-
-#include "Hardware.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::testing::Test;
-using ::testing::TestParamInfo;
-using ::testing::ValuesIn;
-using ::testing::WithParamInterface;
-
-class HwApiTest : public Test {
-  private:
-    static constexpr const char *FILE_NAMES[]{
-            "device/f0_stored",
-            "device/redc_stored",
-            "device/q_stored",
-            "activate",
-            "duration",
-            "state",
-            "device/cp_trigger_duration",
-            "device/cp_trigger_index",
-            "device/cp_trigger_queue",
-            "device/cp_dig_scale",
-            "device/dig_scale",
-            "device/asp_enable",
-            "device/gpio1_fall_index",
-            "device/gpio1_fall_dig_scale",
-            "device/gpio1_rise_index",
-            "device/gpio1_rise_dig_scale",
-            "device/num_waves",
-            "device/available_pwle_segments",
-            "device/pwle",
-            "device/pwle_ramp_down",
-    };
-
-  public:
-    void SetUp() override {
-        std::string prefix;
-        for (auto n : FILE_NAMES) {
-            auto name = std::filesystem::path(n);
-            auto path = std::filesystem::path(mFilesDir.path) / name;
-            fs_mkdirs(path.c_str(), S_IRWXU);
-            std::ofstream touch{path};
-            mFileMap[name] = path;
-        }
-        prefix = std::filesystem::path(mFilesDir.path) / "";
-        setenv("HWAPI_PATH_PREFIX", prefix.c_str(), true);
-        mHwApi = std::make_unique<HwApi>();
-
-        for (auto n : FILE_NAMES) {
-            auto name = std::filesystem::path(n);
-            auto path = std::filesystem::path(mEmptyDir.path) / name;
-        }
-        prefix = std::filesystem::path(mEmptyDir.path) / "";
-        setenv("HWAPI_PATH_PREFIX", prefix.c_str(), true);
-        mNoApi = std::make_unique<HwApi>();
-    }
-
-    void TearDown() override { verifyContents(); }
-
-    static auto ParamNameFixup(std::string str) {
-        std::replace(str.begin(), str.end(), '/', '_');
-        return str;
-    }
-
-  protected:
-    // Set expected file content for a test.
-    template <typename T>
-    void expectContent(const std::string &name, const T &value) {
-        mExpectedContent[name] << value << std::endl;
-    }
-
-    // Set actual file content for an input test.
-    template <typename T>
-    void updateContent(const std::string &name, const T &value) {
-        std::ofstream(mFileMap[name]) << value << std::endl;
-    }
-
-    template <typename T>
-    void expectAndUpdateContent(const std::string &name, const T &value) {
-        expectContent(name, value);
-        updateContent(name, value);
-    }
-
-    // Compare all file contents against expected contents.
-    void verifyContents() {
-        for (auto &a : mFileMap) {
-            std::ifstream file{a.second};
-            std::string expect = mExpectedContent[a.first].str();
-            std::string actual = std::string(std::istreambuf_iterator<char>(file),
-                                             std::istreambuf_iterator<char>());
-            EXPECT_EQ(expect, actual) << a.first;
-        }
-    }
-
-  protected:
-    std::unique_ptr<Vibrator::HwApi> mHwApi;
-    std::unique_ptr<Vibrator::HwApi> mNoApi;
-    std::map<std::string, std::string> mFileMap;
-    TemporaryDir mFilesDir;
-    TemporaryDir mEmptyDir;
-    std::map<std::string, std::stringstream> mExpectedContent;
-};
-
-template <typename T>
-class HwApiTypedTest : public HwApiTest,
-                       public WithParamInterface<std::tuple<std::string, std::function<T>>> {
-  public:
-    static auto PrintParam(const TestParamInfo<typename HwApiTypedTest::ParamType> &info) {
-        return ParamNameFixup(std::get<0>(info.param));
-    }
-    static auto MakeParam(std::string name, std::function<T> func) {
-        return std::make_tuple(name, func);
-    }
-};
-
-using HasTest = HwApiTypedTest<bool(Vibrator::HwApi &)>;
-
-TEST_P(HasTest, success_returnsTrue) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-
-    EXPECT_TRUE(func(*mHwApi));
-}
-
-TEST_P(HasTest, success_returnsFalse) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-
-    EXPECT_FALSE(func(*mNoApi));
-}
-
-INSTANTIATE_TEST_CASE_P(
-        HwApiTests, HasTest,
-        ValuesIn({
-                HasTest::MakeParam("device/cp_dig_scale", &Vibrator::HwApi::hasEffectScale),
-                HasTest::MakeParam("device/asp_enable", &Vibrator::HwApi::hasAspEnable),
-                HasTest::MakeParam("device/pwle", &Vibrator::HwApi::hasPwle),
-        }),
-        HasTest::PrintParam);
-
-using GetBoolTest = HwApiTypedTest<bool(Vibrator::HwApi &, bool *)>;
-
-TEST_P(GetBoolTest, success_returnsTrue) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    bool expect = true;
-    bool actual = !expect;
-
-    expectAndUpdateContent(name, "1");
-
-    EXPECT_TRUE(func(*mHwApi, &actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_P(GetBoolTest, success_returnsFalse) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    bool expect = false;
-    bool actual = !expect;
-
-    expectAndUpdateContent(name, "0");
-
-    EXPECT_TRUE(func(*mHwApi, &actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_P(GetBoolTest, failure) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-    bool value;
-
-    EXPECT_FALSE(func(*mNoApi, &value));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, GetBoolTest,
-                        ValuesIn({
-                                GetBoolTest::MakeParam("device/asp_enable",
-                                                       &Vibrator::HwApi::getAspEnable),
-                        }),
-                        GetBoolTest::PrintParam);
-
-using GetUint32Test = HwApiTypedTest<bool(Vibrator::HwApi &, uint32_t *)>;
-
-TEST_P(GetUint32Test, success) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    expectAndUpdateContent(name, expect);
-
-    EXPECT_TRUE(func(*mHwApi, &actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_P(GetUint32Test, failure) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-    uint32_t value;
-
-    EXPECT_FALSE(func(*mNoApi, &value));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, GetUint32Test,
-                        ValuesIn({
-                                GetUint32Test::MakeParam("device/num_waves",
-                                                         &Vibrator::HwApi::getEffectCount),
-                                GetUint32Test::MakeParam("device/cp_trigger_duration",
-                                                         &Vibrator::HwApi::getEffectDuration),
-                                GetUint32Test::MakeParam("device/available_pwle_segments",
-                                                         &Vibrator::HwApi::getAvailablePwleSegments),
-                        }),
-                        GetUint32Test::PrintParam);
-
-using SetBoolTest = HwApiTypedTest<bool(Vibrator::HwApi &, bool)>;
-
-TEST_P(SetBoolTest, success_returnsTrue) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-
-    expectContent(name, "1");
-
-    EXPECT_TRUE(func(*mHwApi, true));
-}
-
-TEST_P(SetBoolTest, success_returnsFalse) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-
-    expectContent(name, "0");
-
-    EXPECT_TRUE(func(*mHwApi, false));
-}
-
-TEST_P(SetBoolTest, failure) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-
-    EXPECT_FALSE(func(*mNoApi, true));
-    EXPECT_FALSE(func(*mNoApi, false));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, SetBoolTest,
-                        ValuesIn({
-                                SetBoolTest::MakeParam("activate", &Vibrator::HwApi::setActivate),
-                                SetBoolTest::MakeParam("state", &Vibrator::HwApi::setState),
-                                SetBoolTest::MakeParam("device/asp_enable",
-                                                       &Vibrator::HwApi::setAspEnable),
-                        }),
-                        SetBoolTest::PrintParam);
-
-using SetUint32Test = HwApiTypedTest<bool(Vibrator::HwApi &, uint32_t)>;
-
-TEST_P(SetUint32Test, success) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    uint32_t value = std::rand();
-
-    expectContent(name, value);
-
-    EXPECT_TRUE(func(*mHwApi, value));
-}
-
-TEST_P(SetUint32Test, failure) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-    uint32_t value = std::rand();
-
-    EXPECT_FALSE(func(*mNoApi, value));
-}
-
-INSTANTIATE_TEST_CASE_P(
-        HwApiTests, SetUint32Test,
-        ValuesIn({
-                SetUint32Test::MakeParam("device/f0_stored", &Vibrator::HwApi::setF0),
-                SetUint32Test::MakeParam("device/redc_stored", &Vibrator::HwApi::setRedc),
-                SetUint32Test::MakeParam("device/q_stored", &Vibrator::HwApi::setQ),
-                SetUint32Test::MakeParam("duration", &Vibrator::HwApi::setDuration),
-                SetUint32Test::MakeParam("device/cp_trigger_index",
-                                         &Vibrator::HwApi::setEffectIndex),
-                SetUint32Test::MakeParam("device/cp_dig_scale", &Vibrator::HwApi::setEffectScale),
-                SetUint32Test::MakeParam("device/dig_scale", &Vibrator::HwApi::setGlobalScale),
-                SetUint32Test::MakeParam("device/gpio1_fall_index",
-                                         &Vibrator::HwApi::setGpioFallIndex),
-                SetUint32Test::MakeParam("device/gpio1_fall_dig_scale",
-                                         &Vibrator::HwApi::setGpioFallScale),
-                SetUint32Test::MakeParam("device/gpio1_rise_index",
-                                         &Vibrator::HwApi::setGpioRiseIndex),
-                SetUint32Test::MakeParam("device/gpio1_rise_dig_scale",
-                                         &Vibrator::HwApi::setGpioRiseScale),
-                SetUint32Test::MakeParam("device/pwle_ramp_down",
-                                         &Vibrator::HwApi::setPwleRampDown),
-        }),
-        SetUint32Test::PrintParam);
-
-using SetStringTest = HwApiTypedTest<bool(Vibrator::HwApi &, std::string)>;
-
-TEST_P(SetStringTest, success) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    std::string value = TemporaryFile().path;
-
-    expectContent(name, value);
-
-    EXPECT_TRUE(func(*mHwApi, value));
-}
-
-TEST_P(SetStringTest, failure) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-    std::string value = TemporaryFile().path;
-
-    EXPECT_FALSE(func(*mNoApi, value));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, SetStringTest,
-                        ValuesIn({
-                                SetStringTest::MakeParam("device/cp_trigger_queue",
-                                                         &Vibrator::HwApi::setEffectQueue),
-                                SetStringTest::MakeParam("device/pwle",
-                                                         &Vibrator::HwApi::setPwle),
-                        }),
-                        SetStringTest::PrintParam);
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l25/tests/test-hwcal.cpp b/vibrator/cs40l25/tests/test-hwcal.cpp
deleted file mode 100644
index c9b71864..00000000
--- a/vibrator/cs40l25/tests/test-hwcal.cpp
+++ /dev/null
@@ -1,299 +0,0 @@
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
-#include <android-base/file.h>
-#include <gtest/gtest.h>
-
-#include <fstream>
-
-#include "Hardware.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::testing::Test;
-
-class HwCalTest : public Test {
-  protected:
-    static constexpr uint32_t Q_DEFAULT = 15.5f * (1 << 16);
-    static constexpr std::array<uint32_t, 6> V_DEFAULT = {60, 70, 80, 90, 100, 76};
-
-  public:
-    void SetUp() override { setenv("CALIBRATION_FILEPATH", mCalFile.path, true); }
-
-  private:
-    static void pack(std::ostream &stream, const uint32_t &value, std::string lpad,
-                     std::string rpad) {
-        stream << lpad << value << rpad;
-    }
-
-    template <typename T, typename std::array<T, 0>::size_type N>
-    static void pack(std::ostream &stream, const std::array<T, N> &value, std::string lpad,
-                     std::string rpad) {
-        for (auto &entry : value) {
-            pack(stream, entry, lpad, rpad);
-        }
-    }
-
-  protected:
-    void createHwCal() { mHwCal = std::make_unique<HwCal>(); }
-
-    template <typename T>
-    void write(const std::string key, const T &value, std::string lpad = " ",
-               std::string rpad = "") {
-        std::ofstream calfile{mCalFile.path, std::ios_base::app};
-        calfile << key << ":";
-        pack(calfile, value, lpad, rpad);
-        calfile << std::endl;
-    }
-
-    void unlink() { ::unlink(mCalFile.path); }
-
-  protected:
-    std::unique_ptr<Vibrator::HwCal> mHwCal;
-    TemporaryFile mCalFile;
-};
-
-TEST_F(HwCalTest, f0_measured) {
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    write("f0_measured", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getF0(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, f0_missing) {
-    uint32_t actual;
-
-    createHwCal();
-
-    EXPECT_FALSE(mHwCal->getF0(&actual));
-}
-
-TEST_F(HwCalTest, redc_measured) {
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    write("redc_measured", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getRedc(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, redc_missing) {
-    uint32_t actual;
-
-    createHwCal();
-
-    EXPECT_FALSE(mHwCal->getRedc(&actual));
-}
-
-TEST_F(HwCalTest, q_measured) {
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    write("q_measured", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getQ(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, q_index) {
-    uint8_t value = std::rand();
-    uint32_t expect = value * 1.5f * (1 << 16) + 2.0f * (1 << 16);
-    uint32_t actual = ~expect;
-
-    write("q_index", value);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getQ(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, q_missing) {
-    uint32_t expect = Q_DEFAULT;
-    uint32_t actual = ~expect;
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getQ(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, q_nofile) {
-    uint32_t expect = Q_DEFAULT;
-    uint32_t actual = ~expect;
-
-    write("q_measured", actual);
-    unlink();
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getQ(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, v_levels) {
-    std::array<uint32_t, 6> expect;
-    std::array<uint32_t, 6> actual;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) {
-        e = std::rand();
-        return ~e;
-    });
-
-    write("v_levels", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, v_missing) {
-    std::array<uint32_t, 6> expect = V_DEFAULT;
-    std::array<uint32_t, 6> actual;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) { return ~e; });
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, v_short) {
-    std::array<uint32_t, 6> expect = V_DEFAULT;
-    std::array<uint32_t, 6> actual;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) { return ~e; });
-
-    write("v_levels", std::array<uint32_t, expect.size() - 1>());
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, v_long) {
-    std::array<uint32_t, 6> expect = V_DEFAULT;
-    std::array<uint32_t, 6> actual;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) { return ~e; });
-
-    write("v_levels", std::array<uint32_t, expect.size() + 1>());
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, v_nofile) {
-    std::array<uint32_t, 6> expect = V_DEFAULT;
-    std::array<uint32_t, 6> actual;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) { return ~e; });
-
-    write("v_levels", actual);
-    unlink();
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, multiple) {
-    uint32_t f0Expect = std::rand();
-    uint32_t f0Actual = ~f0Expect;
-    uint32_t redcExpect = std::rand();
-    uint32_t redcActual = ~redcExpect;
-    uint32_t qExpect = std::rand();
-    uint32_t qActual = ~qExpect;
-    std::array<uint32_t, 6> volExpect;
-    std::array<uint32_t, 6> volActual;
-
-    std::transform(volExpect.begin(), volExpect.end(), volActual.begin(), [](uint32_t &e) {
-        e = std::rand();
-        return ~e;
-    });
-
-    write("f0_measured", f0Expect);
-    write("redc_measured", redcExpect);
-    write("q_measured", qExpect);
-    write("v_levels", volExpect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getF0(&f0Actual));
-    EXPECT_EQ(f0Expect, f0Actual);
-    EXPECT_TRUE(mHwCal->getRedc(&redcActual));
-    EXPECT_EQ(redcExpect, redcActual);
-    EXPECT_TRUE(mHwCal->getQ(&qActual));
-    EXPECT_EQ(qExpect, qActual);
-    EXPECT_TRUE(mHwCal->getVolLevels(&volActual));
-    EXPECT_EQ(volExpect, volActual);
-}
-
-TEST_F(HwCalTest, trimming) {
-    uint32_t f0Expect = std::rand();
-    uint32_t f0Actual = ~f0Expect;
-    uint32_t redcExpect = std::rand();
-    uint32_t redcActual = ~redcExpect;
-    uint32_t qExpect = std::rand();
-    uint32_t qActual = ~qExpect;
-    std::array<uint32_t, 6> volExpect;
-    std::array<uint32_t, 6> volActual;
-
-    std::transform(volExpect.begin(), volExpect.end(), volActual.begin(), [](uint32_t &e) {
-        e = std::rand();
-        return ~e;
-    });
-
-    write("f0_measured", f0Expect, " \t", "\t ");
-    write("redc_measured", redcExpect, " \t", "\t ");
-    write("q_measured", qExpect, " \t", "\t ");
-    write("v_levels", volExpect, " \t", "\t ");
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getF0(&f0Actual));
-    EXPECT_EQ(f0Expect, f0Actual);
-    EXPECT_TRUE(mHwCal->getRedc(&redcActual));
-    EXPECT_EQ(redcExpect, redcActual);
-    EXPECT_TRUE(mHwCal->getQ(&qActual));
-    EXPECT_EQ(qExpect, qActual);
-    EXPECT_TRUE(mHwCal->getVolLevels(&volActual));
-    EXPECT_EQ(volExpect, volActual);
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l25/tests/test-vibrator.cpp b/vibrator/cs40l25/tests/test-vibrator.cpp
deleted file mode 100644
index 16ac69d1..00000000
--- a/vibrator/cs40l25/tests/test-vibrator.cpp
+++ /dev/null
@@ -1,738 +0,0 @@
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
-#include <aidl/android/hardware/vibrator/BnVibratorCallback.h>
-#include <android-base/logging.h>
-#include <gmock/gmock.h>
-#include <gtest/gtest.h>
-
-#include <future>
-
-#include "Stats.h"
-#include "Vibrator.h"
-#include "mocks.h"
-#include "types.h"
-#include "utils.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::testing::_;
-using ::testing::AnyNumber;
-using ::testing::Assign;
-using ::testing::AtLeast;
-using ::testing::AtMost;
-using ::testing::Combine;
-using ::testing::DoAll;
-using ::testing::DoDefault;
-using ::testing::Exactly;
-using ::testing::Expectation;
-using ::testing::ExpectationSet;
-using ::testing::Ge;
-using ::testing::Mock;
-using ::testing::MockFunction;
-using ::testing::Range;
-using ::testing::Return;
-using ::testing::Sequence;
-using ::testing::SetArgPointee;
-using ::testing::Test;
-using ::testing::TestParamInfo;
-using ::testing::ValuesIn;
-using ::testing::WithParamInterface;
-
-// Forward Declarations
-
-static EffectQueue Queue(const QueueEffect &effect);
-static EffectQueue Queue(const QueueDelay &delay);
-template <typename T, typename U, typename... Args>
-static EffectQueue Queue(const T &first, const U &second, Args... rest);
-
-static EffectLevel Level(float intensity);
-static EffectScale Scale(float intensity);
-
-// Constants With Arbitrary Values
-
-static constexpr uint32_t CAL_VERSION = 1;
-static constexpr std::array<EffectLevel, 6> V_LEVELS{40, 50, 60, 70, 80, 90};
-static constexpr std::array<EffectDuration, 10> EFFECT_DURATIONS{0,   0,   11,  0,   300,
-                                                                 132, 150, 500, 101, 5};
-
-// Constants With Prescribed Values
-
-static const std::map<Effect, EffectIndex> EFFECT_INDEX{
-        {Effect::CLICK, 2},
-        {Effect::TICK, 2},
-        {Effect::HEAVY_CLICK, 2},
-        {Effect::TEXTURE_TICK, 9},
-};
-
-static constexpr EffectIndex QUEUE_INDEX{65534};
-
-static const EffectScale ON_GLOBAL_SCALE{levelToScale(V_LEVELS[5])};
-static const EffectIndex ON_EFFECT_INDEX{0};
-static constexpr uint32_t WAVEFORM_DOUBLE_CLICK_SILENCE_MS = 100;
-static constexpr int8_t MAX_COLD_START_LATENCY_MS = 6;  // I2C Transaction + DSP Return-From-Standby
-static constexpr int8_t MAX_PAUSE_TIMING_ERROR_MS = 1;  // ALERT Irq Handling
-static constexpr auto POLLING_TIMEOUT = 20;
-
-static const std::map<EffectTuple, EffectScale> EFFECT_SCALE{
-        {{Effect::CLICK, EffectStrength::LIGHT}, Scale(0.7f * 0.5f)},
-        {{Effect::CLICK, EffectStrength::MEDIUM}, Scale(0.7f * 0.7f)},
-        {{Effect::CLICK, EffectStrength::STRONG}, Scale(0.7f * 1.0f)},
-        {{Effect::TICK, EffectStrength::LIGHT}, Scale(0.5f * 0.5f)},
-        {{Effect::TICK, EffectStrength::MEDIUM}, Scale(0.5f * 0.7f)},
-        {{Effect::TICK, EffectStrength::STRONG}, Scale(0.5f * 1.0f)},
-        {{Effect::HEAVY_CLICK, EffectStrength::LIGHT}, Scale(1.0f * 0.5f)},
-        {{Effect::HEAVY_CLICK, EffectStrength::MEDIUM}, Scale(1.0f * 0.7f)},
-        {{Effect::HEAVY_CLICK, EffectStrength::STRONG}, Scale(1.0f * 1.0f)},
-        {{Effect::TEXTURE_TICK, EffectStrength::LIGHT}, Scale(0.5f * 0.5f)},
-        {{Effect::TEXTURE_TICK, EffectStrength::MEDIUM}, Scale(0.5f * 0.7f)},
-        {{Effect::TEXTURE_TICK, EffectStrength::STRONG}, Scale(0.5f * 1.0f)},
-};
-
-static const std::map<EffectTuple, EffectQueue> EFFECT_QUEUE{
-        {{Effect::DOUBLE_CLICK, EffectStrength::LIGHT},
-         Queue(QueueEffect{EFFECT_INDEX.at(Effect::CLICK), Level(0.7f * 0.5f)},
-               WAVEFORM_DOUBLE_CLICK_SILENCE_MS,
-               QueueEffect{EFFECT_INDEX.at(Effect::CLICK), Level(1.0f * 0.5f)})},
-        {{Effect::DOUBLE_CLICK, EffectStrength::MEDIUM},
-         Queue(QueueEffect{EFFECT_INDEX.at(Effect::CLICK), Level(0.7f * 0.7f)},
-               WAVEFORM_DOUBLE_CLICK_SILENCE_MS,
-               QueueEffect{EFFECT_INDEX.at(Effect::CLICK), Level(1.0f * 0.7f)})},
-        {{Effect::DOUBLE_CLICK, EffectStrength::STRONG},
-         Queue(QueueEffect{EFFECT_INDEX.at(Effect::CLICK), Level(0.7f * 1.0f)},
-               WAVEFORM_DOUBLE_CLICK_SILENCE_MS,
-               QueueEffect{EFFECT_INDEX.at(Effect::CLICK), Level(1.0f * 1.0f)})},
-};
-
-EffectQueue Queue(const QueueEffect &effect) {
-    auto index = std::get<0>(effect);
-    auto level = std::get<1>(effect);
-    auto string = std::to_string(index) + "." + std::to_string(level);
-    auto duration = EFFECT_DURATIONS[index];
-    return {string, duration};
-}
-
-EffectQueue Queue(const QueueDelay &delay) {
-    auto string = std::to_string(delay);
-    return {string, delay};
-}
-
-template <typename T, typename U, typename... Args>
-EffectQueue Queue(const T &first, const U &second, Args... rest) {
-    auto head = Queue(first);
-    auto tail = Queue(second, rest...);
-    auto string = std::get<0>(head) + "," + std::get<0>(tail);
-    auto duration = std::get<1>(head) + std::get<1>(tail);
-    return {string, duration};
-}
-
-static EffectLevel Level(float intensity) {
-    auto vMin = std::max(V_LEVELS[0] - (V_LEVELS[4] - V_LEVELS[0]) / 4.0f, 4.0f);
-    auto vMax = V_LEVELS[4];
-    return std::lround(intensity * (vMax - vMin)) + vMin;
-}
-
-static EffectScale Scale(float intensity) {
-    return levelToScale(Level(intensity));
-}
-
-class VibratorTest : public Test {
-  public:
-    void SetUp() override {
-        std::unique_ptr<MockApi> mockapi;
-        std::unique_ptr<MockCal> mockcal;
-        std::unique_ptr<MockStats> mockstats;
-
-        createMock(&mockapi, &mockcal, &mockstats);
-        createVibrator(std::move(mockapi), std::move(mockcal), std::move(mockstats));
-    }
-
-    void TearDown() override { deleteVibrator(); }
-
-  protected:
-    void createMock(std::unique_ptr<MockApi> *mockapi, std::unique_ptr<MockCal> *mockcal,
-                    std::unique_ptr<MockStats> *mockstats) {
-        *mockapi = std::make_unique<MockApi>();
-        *mockcal = std::make_unique<MockCal>();
-        *mockstats = std::make_unique<MockStats>();
-
-        mMockApi = mockapi->get();
-        mMockCal = mockcal->get();
-        mMockStats = mockstats->get();
-
-        ON_CALL(*mMockApi, destructor()).WillByDefault(Assign(&mMockApi, nullptr));
-
-        ON_CALL(*mMockApi, getEffectCount(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(EFFECT_DURATIONS.size()), Return(true)));
-
-        ON_CALL(*mMockApi, setEffectIndex(_))
-                .WillByDefault(Invoke(this, &VibratorTest::setEffectIndex));
-
-        ON_CALL(*mMockApi, getEffectDuration(_))
-                .WillByDefault(Invoke(this, &VibratorTest::getEffectDuration));
-
-        ON_CALL(*mMockCal, destructor()).WillByDefault(Assign(&mMockCal, nullptr));
-
-        ON_CALL(*mMockCal, getVersion(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(CAL_VERSION), Return(true)));
-
-        ON_CALL(*mMockCal, getVolLevels(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(V_LEVELS), Return(true)));
-
-        relaxMock(false);
-    }
-
-    void createVibrator(std::unique_ptr<MockApi> mockapi, std::unique_ptr<MockCal> mockcal,
-                        std::unique_ptr<MockStats> mockstats, bool relaxed = true) {
-        if (relaxed) {
-            relaxMock(true);
-        }
-        mVibrator = ndk::SharedRefBase::make<Vibrator>(std::move(mockapi), std::move(mockcal),
-                                                       std::move(mockstats));
-        if (relaxed) {
-            relaxMock(false);
-        }
-    }
-
-    void deleteVibrator(bool relaxed = true) {
-        if (relaxed) {
-            relaxMock(true);
-        }
-        mVibrator.reset();
-    }
-
-    bool setEffectIndex(EffectIndex index) {
-        mEffectIndex = index;
-        return true;
-    }
-
-    bool getEffectDuration(EffectDuration *duration) {
-        if (mEffectIndex < EFFECT_DURATIONS.size()) {
-            *duration = msToCycles(EFFECT_DURATIONS[mEffectIndex]);
-            return true;
-        } else {
-            return false;
-        }
-    }
-
-  private:
-    void relaxMock(bool relax) {
-        auto times = relax ? AnyNumber() : Exactly(0);
-
-        Mock::VerifyAndClearExpectations(mMockApi);
-        Mock::VerifyAndClearExpectations(mMockCal);
-        Mock::VerifyAndClearExpectations(mMockStats);
-
-        EXPECT_CALL(*mMockApi, destructor()).Times(times);
-        EXPECT_CALL(*mMockApi, setF0(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setRedc(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setQ(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setActivate(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setDuration(_)).Times(times);
-        EXPECT_CALL(*mMockApi, getEffectCount(_)).Times(times);
-        EXPECT_CALL(*mMockApi, getEffectDuration(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setEffectIndex(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setEffectQueue(_)).Times(times);
-        EXPECT_CALL(*mMockApi, hasEffectScale()).Times(times);
-        EXPECT_CALL(*mMockApi, setEffectScale(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setGlobalScale(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setState(_)).Times(times);
-        EXPECT_CALL(*mMockApi, hasAspEnable()).Times(times);
-        EXPECT_CALL(*mMockApi, getAspEnable(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setAspEnable(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setGpioFallIndex(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setGpioFallScale(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setGpioRiseIndex(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setGpioRiseScale(_)).Times(times);
-        EXPECT_CALL(*mMockApi, debug(_)).Times(times);
-
-        EXPECT_CALL(*mMockCal, destructor()).Times(times);
-        EXPECT_CALL(*mMockCal, getF0(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getRedc(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getQ(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getVolLevels(_)).Times(times);
-        EXPECT_CALL(*mMockCal, debug(_)).Times(times);
-
-        ON_CALL(*mMockStats, destructor()).WillByDefault(Assign(&mMockStats, nullptr));
-        ON_CALL(*mMockStats, logPrimitive(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockStats, logWaveform(_, _)).WillByDefault(Return(true));
-        ON_CALL(*mMockStats, logLatencyStart(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockStats, logLatencyEnd()).WillByDefault(Return(true));
-    }
-
-  protected:
-    MockApi *mMockApi;
-    MockCal *mMockCal;
-    MockStats *mMockStats;
-    std::shared_ptr<IVibrator> mVibrator;
-    uint32_t mEffectIndex;
-};
-
-TEST_F(VibratorTest, Constructor) {
-    std::unique_ptr<MockApi> mockapi;
-    std::unique_ptr<MockCal> mockcal;
-    std::unique_ptr<MockStats> mockstats;
-    uint32_t f0Val = std::rand();
-    uint32_t redcVal = std::rand();
-    uint32_t qVal = std::rand();
-    uint32_t calVer;
-    Expectation volGet;
-    Sequence f0Seq, redcSeq, qSeq, volSeq, durSeq;
-
-    EXPECT_CALL(*mMockApi, destructor()).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockCal, destructor()).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockStats, destructor()).WillOnce(DoDefault());
-
-    deleteVibrator(false);
-
-    createMock(&mockapi, &mockcal, &mockstats);
-
-    EXPECT_CALL(*mMockCal, getF0(_))
-            .InSequence(f0Seq)
-            .WillOnce(DoAll(SetArgPointee<0>(f0Val), Return(true)));
-    EXPECT_CALL(*mMockApi, setF0(f0Val)).InSequence(f0Seq).WillOnce(Return(true));
-
-    EXPECT_CALL(*mMockCal, getRedc(_))
-            .InSequence(redcSeq)
-            .WillOnce(DoAll(SetArgPointee<0>(redcVal), Return(true)));
-    EXPECT_CALL(*mMockApi, setRedc(redcVal)).InSequence(redcSeq).WillOnce(Return(true));
-
-    EXPECT_CALL(*mMockCal, getQ(_))
-            .InSequence(qSeq)
-            .WillOnce(DoAll(SetArgPointee<0>(qVal), Return(true)));
-    EXPECT_CALL(*mMockApi, setQ(qVal)).InSequence(qSeq).WillOnce(Return(true));
-    if (mMockCal->getVersion(&calVer) == 1) {
-        volGet = EXPECT_CALL(*mMockCal, getVolLevels(_)).WillOnce(DoDefault());
-    } else {
-        volGet = EXPECT_CALL(*mMockCal, getTickVolLevels(_)).WillOnce(DoDefault());
-        volGet = EXPECT_CALL(*mMockCal, getClickVolLevels(_)).WillOnce(DoDefault());
-        volGet = EXPECT_CALL(*mMockCal, getLongVolLevels(_)).WillOnce(DoDefault());
-    }
-
-    EXPECT_CALL(*mMockApi, setState(true)).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, getEffectCount(_)).InSequence(durSeq).WillOnce(DoDefault());
-
-    for (auto &d : EFFECT_DURATIONS) {
-        EXPECT_CALL(*mMockApi, setEffectIndex(&d - &EFFECT_DURATIONS[0]))
-                .InSequence(durSeq)
-                .WillOnce(DoDefault());
-        EXPECT_CALL(*mMockApi, getEffectDuration(_)).InSequence(durSeq).WillOnce(DoDefault());
-    }
-
-    EXPECT_CALL(*mMockApi, hasEffectScale()).WillRepeatedly(Return(true));
-    EXPECT_CALL(*mMockApi, hasAspEnable()).WillRepeatedly(Return(true));
-
-    createVibrator(std::move(mockapi), std::move(mockcal), std::move(mockstats), false);
-}
-
-TEST_F(VibratorTest, on) {
-    Sequence s1, s2, s3;
-    uint16_t duration = std::rand() + 1;
-
-    EXPECT_CALL(*mMockStats, logLatencyStart(kWaveformEffectLatency))
-            .InSequence(s1, s2, s3)
-            .WillOnce(DoDefault());
-    EXPECT_CALL(*mMockStats, logWaveform(_, _)).InSequence(s1).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockApi, setGlobalScale(ON_GLOBAL_SCALE)).InSequence(s1).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setEffectIndex(ON_EFFECT_INDEX)).InSequence(s2).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockApi, setDuration(Ge(duration))).InSequence(s3).WillOnce(Return(true));
-    EXPECT_CALL(*mMockStats, logLatencyEnd()).InSequence(s1, s2, s3).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockApi, setActivate(true)).InSequence(s1, s2, s3).WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->on(duration, nullptr).isOk());
-}
-
-TEST_F(VibratorTest, off) {
-    EXPECT_CALL(*mMockApi, setActivate(false)).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setGlobalScale(0)).WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->off().isOk());
-}
-
-TEST_F(VibratorTest, supportsAmplitudeControl_supported) {
-    EXPECT_CALL(*mMockApi, hasEffectScale()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, hasAspEnable()).WillOnce(Return(true));
-
-    int32_t capabilities;
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_GT(capabilities & IVibrator::CAP_AMPLITUDE_CONTROL, 0);
-}
-
-TEST_F(VibratorTest, supportsAmplitudeControl_unsupported1) {
-    EXPECT_CALL(*mMockApi, hasEffectScale()).WillOnce(Return(false));
-    EXPECT_CALL(*mMockApi, hasAspEnable()).WillOnce(Return(true));
-
-    int32_t capabilities;
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_EQ(capabilities & IVibrator::CAP_AMPLITUDE_CONTROL, 0);
-}
-
-TEST_F(VibratorTest, supportsAmplitudeControl_unsupported2) {
-    EXPECT_CALL(*mMockApi, hasEffectScale()).WillOnce(Return(false));
-    EXPECT_CALL(*mMockApi, hasAspEnable()).WillOnce(Return(false));
-
-    int32_t capabilities;
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_EQ(capabilities & IVibrator::CAP_AMPLITUDE_CONTROL, 0);
-}
-
-TEST_F(VibratorTest, supportsExternalAmplitudeControl_unsupported) {
-    EXPECT_CALL(*mMockApi, hasEffectScale()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, hasAspEnable()).WillOnce(Return(true));
-
-    int32_t capabilities;
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_EQ(capabilities & IVibrator::CAP_EXTERNAL_AMPLITUDE_CONTROL, 0);
-}
-
-TEST_F(VibratorTest, setAmplitude_supported) {
-    Sequence s;
-    EffectAmplitude amplitude = static_cast<float>(std::rand()) / RAND_MAX ?: 1.0f;
-    // The default mIsUnderExternalControl is false, no need to turn off the External Control
-
-    EXPECT_CALL(*mMockApi, setEffectScale(amplitudeToScale(amplitude)))
-            .InSequence(s)
-            .WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->setAmplitude(amplitude).isOk());
-}
-
-TEST_F(VibratorTest, setAmplitude_unsupported) {
-    // Turn on the External Control and make mIsUnderExternalControl true
-    Sequence s;
-
-    EXPECT_CALL(*mMockApi, hasAspEnable()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setGlobalScale(ON_GLOBAL_SCALE)).InSequence(s).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setAspEnable(true)).InSequence(s).WillOnce(Return(true));
-    EXPECT_TRUE(mVibrator->setExternalControl(true).isOk());
-
-    EXPECT_EQ(EX_UNSUPPORTED_OPERATION, mVibrator->setAmplitude(1).getExceptionCode());
-}
-
-TEST_F(VibratorTest, supportsExternalControl_supported) {
-    EXPECT_CALL(*mMockApi, hasEffectScale()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, hasAspEnable()).WillOnce(Return(true));
-
-    int32_t capabilities;
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_GT(capabilities & IVibrator::CAP_EXTERNAL_CONTROL, 0);
-}
-
-TEST_F(VibratorTest, supportsExternalControl_unsupported) {
-    EXPECT_CALL(*mMockApi, hasEffectScale()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, hasAspEnable()).WillOnce(Return(false));
-
-    int32_t capabilities;
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_EQ(capabilities & IVibrator::CAP_EXTERNAL_CONTROL, 0);
-}
-
-TEST_F(VibratorTest, setExternalControl_enable) {
-    Sequence s;
-
-    EXPECT_CALL(*mMockApi, hasAspEnable()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setGlobalScale(ON_GLOBAL_SCALE)).InSequence(s).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setAspEnable(true)).InSequence(s).WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->setExternalControl(true).isOk());
-}
-
-TEST_F(VibratorTest, setExternalControl_disable) {
-    Sequence s;
-
-    EXPECT_CALL(*mMockApi, hasAspEnable()).WillRepeatedly(Return(true));
-    // The default mIsUnderExternalControl is false, so it needs to turn on the External Control
-    // to make mIsUnderExternalControl become true.
-    EXPECT_CALL(*mMockApi, setGlobalScale(ON_GLOBAL_SCALE)).InSequence(s).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setAspEnable(true)).InSequence(s).WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->setExternalControl(true).isOk());
-
-    EXPECT_CALL(*mMockApi, setAspEnable(false)).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setGlobalScale(0)).WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->setExternalControl(false).isOk());
-}
-
-class EffectsTest : public VibratorTest, public WithParamInterface<EffectTuple> {
-  public:
-    static auto PrintParam(const TestParamInfo<ParamType> &info) {
-        auto param = info.param;
-        auto effect = std::get<0>(param);
-        auto strength = std::get<1>(param);
-        return toString(effect) + "_" + toString(strength);
-    }
-};
-
-TEST_P(EffectsTest, perform) {
-    auto param = GetParam();
-    auto effect = std::get<0>(param);
-    auto strength = std::get<1>(param);
-    auto scale = EFFECT_SCALE.find(param);
-    auto queue = EFFECT_QUEUE.find(param);
-    EffectDuration duration;
-    auto callback = ndk::SharedRefBase::make<MockVibratorCallback>();
-    std::promise<void> promise;
-    std::future<void> future{promise.get_future()};
-    auto complete = [&promise] {
-        promise.set_value();
-        return ndk::ScopedAStatus::ok();
-    };
-
-    ExpectationSet eSetup;
-    Expectation eActivate, ePollStop;
-
-    eSetup +=
-            EXPECT_CALL(*mMockStats, logLatencyStart(kPrebakedEffectLatency)).WillOnce(DoDefault());
-
-    if (scale != EFFECT_SCALE.end()) {
-        EffectIndex index = EFFECT_INDEX.at(effect);
-        duration = EFFECT_DURATIONS[index] + MAX_COLD_START_LATENCY_MS;
-
-        eSetup += EXPECT_CALL(*mMockApi, setEffectIndex(index)).WillOnce(DoDefault());
-        eSetup += EXPECT_CALL(*mMockApi, setEffectScale(scale->second)).WillOnce(Return(true));
-    } else if (queue != EFFECT_QUEUE.end()) {
-        duration = std::get<1>(queue->second) + MAX_COLD_START_LATENCY_MS * 2 +
-                   MAX_PAUSE_TIMING_ERROR_MS;
-
-        eSetup += EXPECT_CALL(*mMockApi, setEffectIndex(QUEUE_INDEX)).WillOnce(DoDefault());
-        eSetup += EXPECT_CALL(*mMockApi, setEffectQueue(std::get<0>(queue->second)))
-                          .WillOnce(Return(true));
-        eSetup += EXPECT_CALL(*mMockApi, setEffectScale(0)).WillOnce(Return(true));
-    } else {
-        duration = 0;
-    }
-
-    if (duration) {
-        eSetup += EXPECT_CALL(*mMockApi, setDuration(Ge(duration))).WillOnce(Return(true));
-        eSetup += EXPECT_CALL(*mMockStats, logLatencyEnd()).WillOnce(DoDefault());
-        eActivate = EXPECT_CALL(*mMockApi, setActivate(true)).After(eSetup).WillOnce(Return(true));
-        ePollStop = EXPECT_CALL(*mMockApi, pollVibeState(false, duration + POLLING_TIMEOUT))
-                            .After(eActivate)
-                            .WillOnce(DoDefault());
-
-        EXPECT_CALL(*mMockApi, setActivate(false)).After(ePollStop).WillOnce(Return(true));
-        EXPECT_CALL(*callback, onComplete()).After(ePollStop).WillOnce(complete);
-    }
-
-    int32_t lengthMs;
-    ndk::ScopedAStatus status = mVibrator->perform(effect, strength, callback, &lengthMs);
-    if (status.isOk()) {
-        EXPECT_LE(duration, lengthMs);
-    } else {
-        EXPECT_EQ(EX_UNSUPPORTED_OPERATION, status.getExceptionCode());
-        EXPECT_EQ(0, lengthMs);
-    }
-
-    if (duration) {
-        EXPECT_EQ(future.wait_for(std::chrono::milliseconds(100)), std::future_status::ready);
-    }
-}
-
-TEST_P(EffectsTest, alwaysOnEnable) {
-    auto param = GetParam();
-    auto effect = std::get<0>(param);
-    auto strength = std::get<1>(param);
-    auto scale = EFFECT_SCALE.find(param);
-    bool supported = (scale != EFFECT_SCALE.end());
-
-    if (supported) {
-        EXPECT_CALL(*mMockApi, setGpioRiseIndex(EFFECT_INDEX.at(effect))).WillOnce(Return(true));
-        EXPECT_CALL(*mMockApi, setGpioRiseScale(scale->second)).WillOnce(Return(true));
-    }
-
-    ndk::ScopedAStatus status = mVibrator->alwaysOnEnable(0, effect, strength);
-    if (supported) {
-        EXPECT_EQ(EX_NONE, status.getExceptionCode());
-    } else {
-        EXPECT_EQ(EX_UNSUPPORTED_OPERATION, status.getExceptionCode());
-    }
-}
-
-const std::vector<Effect> kEffects{ndk::enum_range<Effect>().begin(),
-                                   ndk::enum_range<Effect>().end()};
-const std::vector<EffectStrength> kEffectStrengths{ndk::enum_range<EffectStrength>().begin(),
-                                                   ndk::enum_range<EffectStrength>().end()};
-
-INSTANTIATE_TEST_CASE_P(VibratorTests, EffectsTest,
-                        Combine(ValuesIn(kEffects.begin(), kEffects.end()),
-                                ValuesIn(kEffectStrengths.begin(), kEffectStrengths.end())),
-                        EffectsTest::PrintParam);
-
-struct PrimitiveParam {
-    CompositePrimitive primitive;
-    EffectIndex index;
-};
-
-class PrimitiveTest : public VibratorTest, public WithParamInterface<PrimitiveParam> {
-  public:
-    static auto PrintParam(const TestParamInfo<ParamType> &info) {
-        return toString(info.param.primitive);
-    }
-};
-
-const std::vector<PrimitiveParam> kPrimitiveParams = {
-        {CompositePrimitive::NOOP, 0},       {CompositePrimitive::CLICK, 2},
-        {CompositePrimitive::THUD, 4},       {CompositePrimitive::SPIN, 5},
-        {CompositePrimitive::QUICK_RISE, 6}, {CompositePrimitive::SLOW_RISE, 7},
-        {CompositePrimitive::QUICK_FALL, 8},
-};
-
-TEST_P(PrimitiveTest, getPrimitiveDuration) {
-    auto param = GetParam();
-    auto primitive = param.primitive;
-    auto index = param.index;
-    int32_t duration;
-
-    EXPECT_EQ(EX_NONE, mVibrator->getPrimitiveDuration(primitive, &duration).getExceptionCode());
-    EXPECT_EQ(EFFECT_DURATIONS[index], duration);
-}
-
-INSTANTIATE_TEST_CASE_P(VibratorTests, PrimitiveTest,
-                        ValuesIn(kPrimitiveParams.begin(), kPrimitiveParams.end()),
-                        PrimitiveTest::PrintParam);
-
-struct ComposeParam {
-    std::string name;
-    std::vector<CompositeEffect> composite;
-    EffectQueue queue;
-};
-
-class ComposeTest : public VibratorTest, public WithParamInterface<ComposeParam> {
-  public:
-    static auto PrintParam(const TestParamInfo<ParamType> &info) { return info.param.name; }
-};
-
-TEST_P(ComposeTest, compose) {
-    auto param = GetParam();
-    auto composite = param.composite;
-    auto queue = std::get<0>(param.queue);
-    auto duration = std::get<1>(param.queue);
-    ExpectationSet eSetup;
-    Expectation eActivate, ePollStop;
-    auto callback = ndk::SharedRefBase::make<MockVibratorCallback>();
-    std::promise<void> promise;
-    std::future<void> future{promise.get_future()};
-    auto complete = [&promise] {
-        promise.set_value();
-        return ndk::ScopedAStatus::ok();
-    };
-
-    eSetup += EXPECT_CALL(*mMockStats, logLatencyStart(kCompositionEffectLatency))
-                      .WillOnce(DoDefault());
-    for (auto &primitive : composite) {
-        eSetup += EXPECT_CALL(*mMockStats, logPrimitive(_)).After(eSetup).WillOnce(DoDefault());
-    }
-    eSetup += EXPECT_CALL(*mMockApi, setEffectIndex(QUEUE_INDEX)).WillOnce(DoDefault());
-    eSetup += EXPECT_CALL(*mMockApi, setEffectQueue(queue)).WillOnce(Return(true));
-    eSetup += EXPECT_CALL(*mMockApi, setEffectScale(0)).WillOnce(Return(true));
-    eSetup += EXPECT_CALL(*mMockApi, setDuration(UINT32_MAX)).WillOnce(Return(true));
-    eSetup += EXPECT_CALL(*mMockStats, logLatencyEnd()).WillOnce(DoDefault());
-    eActivate = EXPECT_CALL(*mMockApi, setActivate(true)).After(eSetup).WillOnce(Return(true));
-    ePollStop = EXPECT_CALL(*mMockApi, pollVibeState(false, duration + POLLING_TIMEOUT))
-                        .After(eActivate)
-                        .WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setActivate(false)).After(ePollStop).WillOnce(Return(true));
-    EXPECT_CALL(*callback, onComplete()).After(ePollStop).WillOnce(complete);
-
-    EXPECT_EQ(EX_NONE, mVibrator->compose(composite, callback).getExceptionCode());
-
-    EXPECT_EQ(future.wait_for(std::chrono::milliseconds(100)), std::future_status::ready);
-}
-
-const std::vector<ComposeParam> kComposeParams = {
-        {"click", {{0, CompositePrimitive::CLICK, 1.0f}}, Queue(QueueEffect(2, Level(1.0f)), 0)},
-        {"thud", {{1, CompositePrimitive::THUD, 0.8f}}, Queue(1, QueueEffect(4, Level(0.8f)), 0)},
-        {"spin", {{2, CompositePrimitive::SPIN, 0.6f}}, Queue(2, QueueEffect(5, Level(0.6f)), 0)},
-        {"quick_rise",
-         {{3, CompositePrimitive::QUICK_RISE, 0.4f}},
-         Queue(3, QueueEffect(6, 0.4f * V_LEVELS[5]), 0)},
-        {"slow_rise",
-         {{4, CompositePrimitive::SLOW_RISE, 0.0f}},
-         Queue(4, QueueEffect(7, Level(0.0f)), 0)},
-        {"quick_fall",
-         {{5, CompositePrimitive::QUICK_FALL, 1.0f}},
-         Queue(5, QueueEffect(8, 1.0f * V_LEVELS[5]), 0)},
-        {"pop",
-         {{6, CompositePrimitive::SLOW_RISE, 1.0f}, {50, CompositePrimitive::THUD, 1.0f}},
-         Queue(6, QueueEffect(7, Level(1.0f)), 50, QueueEffect(4, Level(1.0f)), 0)},
-        {"snap",
-         {{7, CompositePrimitive::QUICK_RISE, 1.0f}, {0, CompositePrimitive::QUICK_FALL, 1.0f}},
-         Queue(7, QueueEffect(6, 1.0f * V_LEVELS[5]), QueueEffect(8, 1.0f * V_LEVELS[5]), 0)},
-};
-
-INSTANTIATE_TEST_CASE_P(VibratorTests, ComposeTest,
-                        ValuesIn(kComposeParams.begin(), kComposeParams.end()),
-                        ComposeTest::PrintParam);
-
-class AlwaysOnTest : public VibratorTest, public WithParamInterface<int32_t> {
-  public:
-    static auto PrintParam(const TestParamInfo<ParamType> &info) {
-        return std::to_string(info.param);
-    }
-};
-
-TEST_P(AlwaysOnTest, alwaysOnEnable) {
-    auto param = GetParam();
-    auto scale = EFFECT_SCALE.begin();
-
-    std::advance(scale, std::rand() % EFFECT_SCALE.size());
-
-    auto effect = std::get<0>(scale->first);
-    auto strength = std::get<1>(scale->first);
-
-    switch (param) {
-        case 0:
-            EXPECT_CALL(*mMockApi, setGpioRiseIndex(EFFECT_INDEX.at(effect)))
-                    .WillOnce(Return(true));
-            EXPECT_CALL(*mMockApi, setGpioRiseScale(scale->second)).WillOnce(Return(true));
-            break;
-        case 1:
-            EXPECT_CALL(*mMockApi, setGpioFallIndex(EFFECT_INDEX.at(effect)))
-                    .WillOnce(Return(true));
-            EXPECT_CALL(*mMockApi, setGpioFallScale(scale->second)).WillOnce(Return(true));
-            break;
-    }
-
-    ndk::ScopedAStatus status = mVibrator->alwaysOnEnable(param, effect, strength);
-    EXPECT_EQ(EX_NONE, status.getExceptionCode());
-}
-
-TEST_P(AlwaysOnTest, alwaysOnDisable) {
-    auto param = GetParam();
-
-    switch (param) {
-        case 0:
-            EXPECT_CALL(*mMockApi, setGpioRiseIndex(0)).WillOnce(Return(true));
-            break;
-        case 1:
-            EXPECT_CALL(*mMockApi, setGpioFallIndex(0)).WillOnce(Return(true));
-            break;
-    }
-
-    ndk::ScopedAStatus status = mVibrator->alwaysOnDisable(param);
-    EXPECT_EQ(EX_NONE, status.getExceptionCode());
-}
-
-INSTANTIATE_TEST_CASE_P(VibratorTests, AlwaysOnTest, Range(0, 1), AlwaysOnTest::PrintParam);
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l25/tests/types.h b/vibrator/cs40l25/tests/types.h
deleted file mode 100644
index c8d379da..00000000
--- a/vibrator/cs40l25/tests/types.h
+++ /dev/null
@@ -1,33 +0,0 @@
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
-#ifndef ANDROID_HARDWARE_VIBRATOR_TEST_TYPES_H
-#define ANDROID_HARDWARE_VIBRATOR_TEST_TYPES_H
-
-#include <aidl/android/hardware/vibrator/IVibrator.h>
-
-using EffectIndex = uint16_t;
-using EffectLevel = uint32_t;
-using EffectAmplitude = float;
-using EffectScale = uint16_t;
-using EffectDuration = uint32_t;
-using EffectQueue = std::tuple<std::string, EffectDuration>;
-using EffectTuple = std::tuple<::aidl::android::hardware::vibrator::Effect,
-                               ::aidl::android::hardware::vibrator::EffectStrength>;
-
-using QueueEffect = std::tuple<EffectIndex, EffectLevel>;
-using QueueDelay = uint32_t;
-
-#endif  // ANDROID_HARDWARE_VIBRATOR_TEST_TYPES_H
diff --git a/vibrator/cs40l25/tests/utils.h b/vibrator/cs40l25/tests/utils.h
deleted file mode 100644
index 6cc87afb..00000000
--- a/vibrator/cs40l25/tests/utils.h
+++ /dev/null
@@ -1,39 +0,0 @@
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
-#ifndef ANDROID_HARDWARE_VIBRATOR_TEST_UTILS_H
-#define ANDROID_HARDWARE_VIBRATOR_TEST_UTILS_H
-
-#include <cmath>
-
-#include "types.h"
-
-static inline EffectScale toScale(float target, float maximum) {
-    return std::round((-20 * std::log10(target / static_cast<float>(maximum))) / 0.125f);
-}
-
-static inline EffectScale levelToScale(EffectLevel level) {
-    return toScale(level, 100);
-}
-
-static inline EffectScale amplitudeToScale(EffectAmplitude amplitude) {
-    return toScale(amplitude, 1.0f);
-}
-
-static inline uint32_t msToCycles(EffectDuration ms) {
-    return ms * 48;
-}
-
-#endif  // ANDROID_HARDWARE_VIBRATOR_TEST_UTILS_H
diff --git a/vibrator/cs40l26/Android.bp b/vibrator/cs40l26/Android.bp
deleted file mode 100644
index be1840c6..00000000
--- a/vibrator/cs40l26/Android.bp
+++ /dev/null
@@ -1,149 +0,0 @@
-//
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_defaults {
-    name: "android.hardware.vibrator-defaults.cs40l26",
-    cflags: [
-        "-DATRACE_TAG=(ATRACE_TAG_VIBRATOR | ATRACE_TAG_HAL)",
-        "-DLOG_TAG=\"Vibrator\"",
-    ],
-}
-
-cc_defaults {
-    name: "VibratorHalCs40l26BinaryDefaults",
-    defaults: [
-        "PixelVibratorBinaryDefaults",
-        "android.hardware.vibrator-defaults.cs40l26",
-    ],
-    include_dirs: [
-        "external/tinyalsa/include",
-    ],
-    shared_libs: [
-        "libcutils",
-        "libtinyalsa",
-        "libbase",
-        "libutils",
-    ],
-}
-
-cc_defaults {
-    name: "VibratorHalCs40l26TestDefaults",
-    defaults: [
-        "PixelVibratorTestDefaults",
-        "VibratorCapoDefaults",
-        "android.hardware.vibrator-defaults.cs40l26",
-    ],
-    static_libs: [
-        "libtinyalsa",
-        "android.hardware.vibrator-impl.cs40l26",
-    ],
-}
-
-cc_library {
-    name: "android.hardware.vibrator-impl.cs40l26",
-    defaults: [
-        "VibratorHalCs40l26BinaryDefaults",
-        "VibratorCapoDefaults",
-        "haptics_feature_defaults",
-    ],
-    srcs: [
-        "Vibrator.cpp",
-        "DspMemChunk.cpp",
-    ],
-    shared_libs: [
-        "PixelVibratorFlagsL26",
-    ],
-    export_include_dirs: [
-        ".",
-    ],
-    vendor_available: true,
-    visibility: [":__subpackages__"],
-}
-
-cc_binary {
-    name: "android.hardware.vibrator-service.cs40l26",
-    defaults: [
-        "VibratorHalCs40l26BinaryDefaults",
-        "VibratorCapoDefaults",
-    ],
-    init_rc: ["android.hardware.vibrator-service.cs40l26.rc"],
-    vintf_fragments: ["android.hardware.vibrator-service.cs40l26.xml"],
-    srcs: ["service.cpp"],
-    shared_libs: [
-        "android.hardware.vibrator-impl.cs40l26",
-        "PixelVibratorStats",
-    ],
-    proprietary: true,
-}
-
-cc_binary {
-    name: "android.hardware.vibrator-service.cs40l26-dual",
-    defaults: [
-        "VibratorHalCs40l26BinaryDefaults",
-        "VibratorCapoDefaults",
-    ],
-    init_rc: ["android.hardware.vibrator-service.cs40l26-dual.rc"],
-    vintf_fragments: ["android.hardware.vibrator-service.cs40l26-dual.xml"],
-    srcs: ["service.cpp"],
-    shared_libs: [
-        "android.hardware.vibrator-impl.cs40l26",
-        "PixelVibratorStats",
-    ],
-    cflags: ["-DVIBRATOR_NAME=\"dual\""],
-    proprietary: true,
-}
-
-aconfig_declarations {
-    name: "VibratorFlagsL26",
-    package: "vendor.vibrator.hal.flags",
-    container: "vendor",
-    exportable: true,
-    srcs: ["VibratorFlags.aconfig"],
-}
-
-cc_aconfig_library {
-    name: "PixelVibratorFlagsL26",
-    aconfig_declarations: "VibratorFlagsL26",
-    vendor_available: true,
-}
-
-java_aconfig_library {
-    name: "PixelVibratorFlagsL26_java",
-    aconfig_declarations: "VibratorFlagsL26",
-    mode: "exported",
-    visibility: ["//vendor:__subpackages__"],
-}
-
-filegroup {
-    name: "haptics_srcs",
-    srcs: [
-        "service.cpp",
-        "Vibrator.cpp",
-    ],
-}
-
-filegroup {
-    name: "android.hardware.vibrator-service.cs40l26.xml",
-    srcs: ["android.hardware.vibrator-service.cs40l26.xml"],
-}
-
-filegroup {
-    name: "android.hardware.vibrator-service.cs40l26.rc",
-    srcs: ["android.hardware.vibrator-service.cs40l26.rc"],
-}
diff --git a/vibrator/cs40l26/DspMemChunk.cpp b/vibrator/cs40l26/DspMemChunk.cpp
deleted file mode 100644
index 8d460653..00000000
--- a/vibrator/cs40l26/DspMemChunk.cpp
+++ /dev/null
@@ -1,316 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#include "DspMemChunk.h"
-
-#include <linux/version.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include <cmath>
-
-#include "Trace.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-#ifdef VIBRATOR_TRACE
-/* Function Trace */
-#define VFTRACE(...)                                                             \
-    ATRACE_NAME(StringPrintf("Vibrator::%s", __func__).c_str());                 \
-    auto f_trace_ = std::make_unique<FunctionTrace>("Vibrator", __func__);       \
-    __VA_OPT__(f_trace_->addParameter(PREPEND_EACH_ARG_WITH_NAME(__VA_ARGS__))); \
-    f_trace_->save()
-/* Effect Trace */
-#define VETRACE(i, s, d, ch)                                    \
-    auto e_trace_ = std::make_unique<EffectTrace>(i, s, d, ch); \
-    e_trace_->save()
-#else
-#define VFTRACE(...) ATRACE_NAME(StringPrintf("Vibrator::%s", __func__).c_str())
-#define VETRACE(...)
-#endif
-
-enum WaveformIndex : uint16_t {
-    /* Physical waveform */
-    WAVEFORM_LONG_VIBRATION_EFFECT_INDEX = 0,
-    WAVEFORM_RESERVED_INDEX_1 = 1,
-    WAVEFORM_CLICK_INDEX = 2,
-    WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX = 3,
-    WAVEFORM_THUD_INDEX = 4,
-    WAVEFORM_SPIN_INDEX = 5,
-    WAVEFORM_QUICK_RISE_INDEX = 6,
-    WAVEFORM_SLOW_RISE_INDEX = 7,
-    WAVEFORM_QUICK_FALL_INDEX = 8,
-    WAVEFORM_LIGHT_TICK_INDEX = 9,
-    WAVEFORM_LOW_TICK_INDEX = 10,
-    WAVEFORM_RESERVED_MFG_1,
-    WAVEFORM_RESERVED_MFG_2,
-    WAVEFORM_RESERVED_MFG_3,
-    WAVEFORM_MAX_PHYSICAL_INDEX,
-    /* OWT waveform */
-    WAVEFORM_COMPOSE = WAVEFORM_MAX_PHYSICAL_INDEX,
-    WAVEFORM_PWLE,
-    /*
-     * Refer to <linux/input.h>, the WAVEFORM_MAX_INDEX must not exceed 96.
-     * #define FF_GAIN      0x60  // 96 in decimal
-     * #define FF_MAX_EFFECTS   FF_GAIN
-     */
-    WAVEFORM_MAX_INDEX,
-};
-
-DspMemChunk::DspMemChunk(uint8_t type, size_t size) : head(new uint8_t[size]{0x00}) {
-    VFTRACE(type, size);
-    waveformType = type;
-    _current = head.get();
-    _max = _current + size;
-
-    if (waveformType == WAVEFORM_COMPOSE) {
-        write(8, 0); /* Padding */
-        write(8, 0); /* nsections placeholder */
-        write(8, 0); /* repeat */
-    } else if (waveformType == WAVEFORM_PWLE) {
-#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
-        write(16, (PWLE_FTR_BUZZ_BIT | PWLE_FTR_DVL_BIT)
-                          << PWLE_HEADER_FTR_SHIFT); /* Feature flag */
-        write(8, PWLE_WT_TYPE);                      /* type12 */
-        write(24, PWLE_HEADER_WORD_COUNT);           /* Header word count */
-        write(24, 0);                                /* Body word count placeholder */
-#endif
-        write(24, 0); /* Waveform length placeholder */
-        write(8, 0);  /* Repeat */
-        write(12, 0); /* Wait time between repeats */
-        write(8, 0);  /* nsections placeholder */
-    } else {
-        ALOGE("%s: Invalid type: %u", __func__, waveformType);
-    }
-}
-
-int DspMemChunk::write(int nbits, uint32_t val) {
-    VFTRACE(nbits, val);
-    int nwrite;
-
-    nwrite = min(24 - _cachebits, nbits);
-    _cache <<= nwrite;
-    _cache |= val >> (nbits - nwrite);
-    _cachebits += nwrite;
-    nbits -= nwrite;
-
-    if (_cachebits == 24) {
-        if (isEnd())
-            return -ENOSPC;
-
-        _cache &= 0xFFFFFF;
-        for (size_t i = 0; i < sizeof(_cache); i++, _cache <<= 8)
-            *_current++ = (_cache & 0xFF000000) >> 24;
-
-        bytes += sizeof(_cache);
-        _cachebits = 0;
-    }
-
-    if (nbits)
-        return write(nbits, val);
-
-    return 0;
-}
-
-int DspMemChunk::fToU16(float input, uint16_t *output, float scale, float min, float max) {
-    VFTRACE(input, output, scale, min, max);
-    if (input < min || input > max)
-        return -ERANGE;
-
-    *output = roundf(input * scale);
-    return 0;
-}
-
-void DspMemChunk::constructPwleSegment(uint16_t delay, uint16_t amplitude, uint16_t frequency,
-                                       uint8_t flags, uint32_t vbemfTarget) {
-    VFTRACE(delay, amplitude, frequency, flags, vbemfTarget);
-    write(16, delay);
-    write(12, amplitude);
-    write(12, frequency);
-    /* feature flags to control the chirp, CLAB braking, back EMF amplitude regulation */
-    write(8, (flags | 1) << 4);
-    if (flags & PWLE_AMP_REG_BIT) {
-        write(24, vbemfTarget); /* target back EMF voltage */
-    }
-}
-
-int DspMemChunk::flush() {
-    VFTRACE();
-    if (!_cachebits)
-        return 0;
-
-    return write(24 - _cachebits, 0);
-}
-
-int DspMemChunk::constructComposeSegment(uint32_t effectVolLevel, uint32_t effectIndex,
-                                         uint8_t repeat, uint8_t flags, uint16_t nextEffectDelay) {
-    VFTRACE(effectVolLevel, effectIndex, repeat, flags, nextEffectDelay);
-    if (waveformType != WAVEFORM_COMPOSE) {
-        ALOGE("%s: Invalid type: %d", __func__, waveformType);
-        return -EDOM;
-    }
-    if (effectVolLevel > 100 || effectIndex > WAVEFORM_MAX_PHYSICAL_INDEX) {
-        ALOGE("%s: Invalid argument: %u, %u", __func__, effectVolLevel, effectIndex);
-        return -EINVAL;
-    }
-    write(8, effectVolLevel);   /* amplitude */
-    write(8, effectIndex);      /* index */
-    write(8, repeat);           /* repeat */
-    write(8, flags);            /* flags */
-    write(16, nextEffectDelay); /* delay */
-    return 0;
-}
-
-int DspMemChunk::constructActiveSegment(int duration, float amplitude, float frequency,
-                                        bool chirp) {
-    VFTRACE(duration, amplitude, frequency, chirp);
-    uint16_t delay = 0;
-    uint16_t amp = 0;
-    uint16_t freq = 0;
-    uint8_t flags = 0x0;
-    if (waveformType != WAVEFORM_PWLE) {
-        ALOGE("%s: Invalid type: %d", __func__, waveformType);
-        return -EDOM;
-    }
-    if ((fToU16(duration, &delay, 4, 0.0f, COMPOSE_PWLE_PRIMITIVE_DURATION_MAX_MS) < 0) ||
-        (fToU16(amplitude, &amp, 2048, CS40L26_PWLE_LEVEL_MIN, CS40L26_PWLE_LEVEL_MAX) < 0) ||
-        (fToU16(frequency, &freq, 4, PWLE_FREQUENCY_MIN_HZ, PWLE_FREQUENCY_MAX_HZ) < 0)) {
-        ALOGE("%s: Invalid argument: %d, %f, %f", __func__, duration, amplitude, frequency);
-        return -ERANGE;
-    }
-    if (chirp) {
-        flags |= PWLE_CHIRP_BIT;
-    }
-    constructPwleSegment(delay, amp, freq, flags, 0 /*ignored*/);
-    return 0;
-}
-
-int DspMemChunk::constructBrakingSegment(int duration, Braking brakingType) {
-    VFTRACE(duration, brakingType);
-    uint16_t delay = 0;
-    uint16_t freq = 0;
-    uint8_t flags = 0x00;
-    if (waveformType != WAVEFORM_PWLE) {
-        ALOGE("%s: Invalid type: %d", __func__, waveformType);
-        return -EDOM;
-    }
-    if (fToU16(duration, &delay, 4, 0.0f, COMPOSE_PWLE_PRIMITIVE_DURATION_MAX_MS) < 0) {
-        ALOGE("%s: Invalid argument: %d", __func__, duration);
-        return -ERANGE;
-    }
-    fToU16(PWLE_FREQUENCY_MIN_HZ, &freq, 4, PWLE_FREQUENCY_MIN_HZ, PWLE_FREQUENCY_MAX_HZ);
-    if (static_cast<std::underlying_type<Braking>::type>(brakingType)) {
-        flags |= PWLE_BRAKE_BIT;
-    }
-
-    constructPwleSegment(delay, 0 /*ignored*/, freq, flags, 0 /*ignored*/);
-    return 0;
-}
-
-int DspMemChunk::updateWLength(uint32_t totalDuration) {
-    VFTRACE(totalDuration);
-    uint8_t *f = front();
-    if (f == nullptr) {
-        ALOGE("%s: head does not exist!", __func__);
-        return -ENOMEM;
-    }
-    if (waveformType != WAVEFORM_PWLE) {
-        ALOGE("%s: Invalid type: %d", __func__, waveformType);
-        return -EDOM;
-    }
-    if (totalDuration > 0x7FFFF) {
-        ALOGE("%s: Invalid argument: %u", __func__, totalDuration);
-        return -EINVAL;
-    }
-#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
-    f += PWLE_HEADER_WORD_COUNT * PWLE_WORD_SIZE;
-#endif
-    totalDuration *= 8;            /* Unit: 0.125 ms (since wlength played @ 8kHz). */
-    totalDuration |= WT_LEN_CALCD; /* Bit 23 is for WT_LEN_CALCD; Bit 22 is for WT_INDEFINITE. */
-    *(f + 0) = (totalDuration >> 24) & 0xFF;
-    *(f + 1) = (totalDuration >> 16) & 0xFF;
-    *(f + 2) = (totalDuration >> 8) & 0xFF;
-    *(f + 3) = totalDuration & 0xFF;
-    return 0;
-}
-
-int DspMemChunk::updateNSection(int segmentIdx) {
-    VFTRACE(segmentIdx);
-    uint8_t *f = front();
-    if (f == nullptr) {
-        ALOGE("%s: head does not exist!", __func__);
-        return -ENOMEM;
-    }
-
-    if (waveformType == WAVEFORM_COMPOSE) {
-        if (segmentIdx > COMPOSE_SIZE_MAX + 1 /*1st effect may have a delay*/) {
-            ALOGE("%s: Invalid argument: %d", __func__, segmentIdx);
-            return -EINVAL;
-        }
-        *(f + 2) = (0xFF & segmentIdx);
-    } else if (waveformType == WAVEFORM_PWLE) {
-        if (segmentIdx > COMPOSE_PWLE_SIZE_MAX_DEFAULT) {
-            ALOGE("%s: Invalid argument: %d", __func__, segmentIdx);
-            return -EINVAL;
-        }
-#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
-        f += PWLE_HEADER_WORD_COUNT * PWLE_WORD_SIZE;
-#endif
-        *(f + 7) |= (0xF0 & segmentIdx) >> 4; /* Bit 4 to 7 */
-        *(f + 9) |= (0x0F & segmentIdx) << 4; /* Bit 3 to 0 */
-    } else {
-        ALOGE("%s: Invalid type: %d", __func__, waveformType);
-        return -EDOM;
-    }
-
-    return 0;
-}
-
-int DspMemChunk::updateWCount(int segmentCount) {
-    uint8_t *f = front();
-
-    if (segmentCount > COMPOSE_SIZE_MAX + 1 /*1st effect may have a delay*/) {
-        ALOGE("%s: Invalid argument: %d", __func__, segmentCount);
-        return -EINVAL;
-    }
-    if (f == nullptr) {
-        ALOGE("%s: head does not exist!", __func__);
-        return -ENOMEM;
-    }
-    if (waveformType != WAVEFORM_PWLE) {
-        ALOGE("%s: Invalid type: %d", __func__, waveformType);
-        return -EDOM;
-    }
-
-#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
-    f += PWLE_HEADER_WORD_COUNT * PWLE_WORD_SIZE;
-#endif
-    uint32_t dataSize = segmentCount * PWLE_SEGMENT_WORD_COUNT + PWLE_HEADER_WORD_COUNT;
-    *(f + 0) = (dataSize >> 24) & 0xFF;
-    *(f + 1) = (dataSize >> 16) & 0xFF;
-    *(f + 2) = (dataSize >> 8) & 0xFF;
-    *(f + 3) = dataSize & 0xFF;
-
-    return 0;
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/DspMemChunk.h b/vibrator/cs40l26/DspMemChunk.h
deleted file mode 100644
index 1bc15f49..00000000
--- a/vibrator/cs40l26/DspMemChunk.h
+++ /dev/null
@@ -1,108 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#pragma once
-
-#include <aidl/android/hardware/vibrator/BnVibrator.h>
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-constexpr int32_t COMPOSE_PWLE_PRIMITIVE_DURATION_MAX_MS = 16383;
-
-constexpr uint32_t WT_LEN_CALCD = 0x00800000;
-constexpr uint8_t PWLE_CHIRP_BIT = 0x8;  // Dynamic/frequency and voltage
-constexpr uint8_t PWLE_BRAKE_BIT = 0x4;
-constexpr uint8_t PWLE_AMP_REG_BIT = 0x2;
-
-static constexpr uint8_t PWLE_WT_TYPE = 12;
-static constexpr uint8_t PWLE_HEADER_WORD_COUNT = 3;
-static constexpr uint8_t PWLE_HEADER_FTR_SHIFT = 8;
-static constexpr uint8_t PWLE_SVC_METADATA_WORD_COUNT = 3;
-static constexpr uint32_t PWLE_SVC_METADATA_TERMINATOR = 0xFFFFFF;
-static constexpr uint8_t PWLE_SEGMENT_WORD_COUNT = 2;
-static constexpr uint8_t PWLE_HEADER_WCOUNT_WORD_OFFSET = 2;
-static constexpr uint8_t PWLE_WORD_SIZE = sizeof(uint32_t);
-
-static constexpr uint8_t PWLE_SVC_NO_BRAKING = -1;
-static constexpr uint8_t PWLE_SVC_CAT_BRAKING = 0;
-static constexpr uint8_t PWLE_SVC_OPEN_BRAKING = 1;
-static constexpr uint8_t PWLE_SVC_CLOSED_BRAKING = 2;
-static constexpr uint8_t PWLE_SVC_MIXED_BRAKING = 3;
-
-static constexpr uint32_t PWLE_SVC_MAX_BRAKING_TIME_MS = 1000;
-
-static constexpr uint8_t PWLE_FTR_BUZZ_BIT = 0x80;
-static constexpr uint8_t PWLE_FTR_CLICK_BIT = 0x00;
-static constexpr uint8_t PWLE_FTR_DYNAMIC_F0_BIT = 0x10;
-static constexpr uint8_t PWLE_FTR_SVC_METADATA_BIT = 0x04;
-static constexpr uint8_t PWLE_FTR_DVL_BIT = 0x02;
-static constexpr uint8_t PWLE_FTR_LF0T_BIT = 0x01;
-
-constexpr float CS40L26_PWLE_LEVEL_MIN = -1.0;
-constexpr float CS40L26_PWLE_LEVEL_MAX = 0.9995118;
-
-constexpr float PWLE_FREQUENCY_MIN_HZ = 30.0f;
-constexpr float PWLE_FREQUENCY_MAX_HZ = 300.0f;
-
-/* nsections is 8 bits. Need to preserve 1 section for the first delay before the first effect. */
-static constexpr int32_t COMPOSE_SIZE_MAX = 254;
-static constexpr int32_t COMPOSE_PWLE_SIZE_MAX_DEFAULT = 127;
-
-class DspMemChunk {
-  public:
-    DspMemChunk(uint8_t type, size_t size);
-
-    uint8_t *front() const { return head.get(); }
-    uint8_t type() const { return waveformType; }
-    size_t size() const { return bytes; }
-
-    int flush();
-
-    int constructComposeSegment(uint32_t effectVolLevel, uint32_t effectIndex, uint8_t repeat,
-                                uint8_t flags, uint16_t nextEffectDelay);
-    int constructActiveSegment(int duration, float amplitude, float frequency, bool chirp);
-    int constructBrakingSegment(int duration, Braking brakingType);
-
-    int updateWLength(uint32_t totalDuration);
-    int updateNSection(int segmentIdx);
-    int updateWCount(int segmentCount);
-
-  private:
-    std::unique_ptr<uint8_t[]> head;
-    size_t bytes = 0;
-    uint8_t waveformType;
-    uint8_t *_current;
-    const uint8_t *_max;
-    uint32_t _cache = 0;
-    int _cachebits = 0;
-
-    bool isEnd() const { return _current == _max; }
-    int min(int x, int y) { return x < y ? x : y; }
-
-    int write(int nbits, uint32_t val);
-
-    int fToU16(float input, uint16_t *output, float scale, float min, float max);
-
-    void constructPwleSegment(uint16_t delay, uint16_t amplitude, uint16_t frequency, uint8_t flags,
-                              uint32_t vbemfTarget = 0);
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/Hardware.h b/vibrator/cs40l26/Hardware.h
deleted file mode 100644
index 58225c2c..00000000
--- a/vibrator/cs40l26/Hardware.h
+++ /dev/null
@@ -1,555 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#pragma once
-
-#include <glob.h>
-
-#include <algorithm>
-
-#include "HardwareBase.h"
-#include "Vibrator.h"
-
-#define PROC_SND_PCM "/proc/asound/pcm"
-#define HAPTIC_PCM_DEVICE_SYMBOL "haptic nohost playback"
-
-static struct pcm_config haptic_nohost_config = {
-        .channels = 1,
-        .rate = 48000,
-        .period_size = 80,
-        .period_count = 2,
-        .format = PCM_FORMAT_S16_LE,
-};
-
-enum WaveformIndex : uint16_t {
-    /* Physical waveform */
-    WAVEFORM_LONG_VIBRATION_EFFECT_INDEX = 0,
-    WAVEFORM_RESERVED_INDEX_1 = 1,
-    WAVEFORM_CLICK_INDEX = 2,
-    WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX = 3,
-    WAVEFORM_THUD_INDEX = 4,
-    WAVEFORM_SPIN_INDEX = 5,
-    WAVEFORM_QUICK_RISE_INDEX = 6,
-    WAVEFORM_SLOW_RISE_INDEX = 7,
-    WAVEFORM_QUICK_FALL_INDEX = 8,
-    WAVEFORM_LIGHT_TICK_INDEX = 9,
-    WAVEFORM_LOW_TICK_INDEX = 10,
-    WAVEFORM_RESERVED_MFG_1,
-    WAVEFORM_RESERVED_MFG_2,
-    WAVEFORM_RESERVED_MFG_3,
-    WAVEFORM_MAX_PHYSICAL_INDEX,
-    /* OWT waveform */
-    WAVEFORM_COMPOSE = WAVEFORM_MAX_PHYSICAL_INDEX,
-    WAVEFORM_PWLE,
-    /*
-     * Refer to <linux/input.h>, the WAVEFORM_MAX_INDEX must not exceed 96.
-     * #define FF_GAIN          0x60  // 96 in decimal
-     * #define FF_MAX_EFFECTS   FF_GAIN
-     */
-    WAVEFORM_MAX_INDEX,
-};
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-class HwApi : public Vibrator::HwApi, private HwApiBase {
-  public:
-    HwApi() {
-        HwApi::initFF();
-        open("calibration/f0_stored", &mF0);
-        open("default/f0_offset", &mF0Offset);
-        open("calibration/redc_stored", &mRedc);
-        open("calibration/q_stored", &mQ);
-        open("default/vibe_state", &mVibeState);
-        open("default/num_waves", &mEffectCount);
-        open("default/braking_time_bank", &mEffectBrakingTimeBank);
-        open("default/braking_time_index", &mEffectBrakingTimeIndex);
-        open("default/braking_time_ms", &mEffectBrakingTimeMs);
-        open("default/owt_free_space", &mOwtFreeSpace);
-        open("default/f0_comp_enable", &mF0CompEnable);
-        open("default/redc_comp_enable", &mRedcCompEnable);
-        open("default/delay_before_stop_playback_us", &mMinOnOffInterval);
-    }
-
-    bool setF0(std::string value) override { return set(value, &mF0); }
-    bool setF0Offset(uint32_t value) override { return set(value, &mF0Offset); }
-    bool setRedc(std::string value) override { return set(value, &mRedc); }
-    bool setQ(std::string value) override { return set(value, &mQ); }
-    bool getEffectCount(uint32_t *value) override { return get(value, &mEffectCount); }
-    bool hasEffectBrakingTimeBank() override { return has(mEffectBrakingTimeBank); }
-    bool setEffectBrakingTimeBank(uint32_t value) override {
-        return set(value, &mEffectBrakingTimeBank);
-    }
-    bool setEffectBrakingTimeIndex(uint32_t value) override {
-        return set(value, &mEffectBrakingTimeIndex);
-    }
-    bool getEffectBrakingTimeMs(uint32_t *value) override {
-        return get(value, &mEffectBrakingTimeMs);
-    }
-    bool pollVibeState(uint32_t value, int32_t timeoutMs) override {
-        return poll(value, &mVibeState, timeoutMs);
-    }
-    bool hasOwtFreeSpace() override { return has(mOwtFreeSpace); }
-    bool getOwtFreeSpace(uint32_t *value) override { return get(value, &mOwtFreeSpace); }
-    bool setF0CompEnable(bool value) override { return set(value, &mF0CompEnable); }
-    bool setRedcCompEnable(bool value) override { return set(value, &mRedcCompEnable); }
-    bool setMinOnOffInterval(uint32_t value) override { return set(value, &mMinOnOffInterval); }
-    uint32_t getContextScale() override {
-        return utils::getProperty("persist.vendor.vibrator.hal.context.scale", 100);
-    }
-    bool getContextEnable() override {
-        return utils::getProperty("persist.vendor.vibrator.hal.context.enable", false);
-    }
-    uint32_t getContextSettlingTime() override {
-        return utils::getProperty("persist.vendor.vibrator.hal.context.settlingtime", 3000);
-    }
-    uint32_t getContextCooldownTime() override {
-        return utils::getProperty("persist.vendor.vibrator.hal.context.cooldowntime", 1000);
-    }
-    bool getContextFadeEnable() override {
-        return utils::getProperty("persist.vendor.vibrator.hal.context.fade", false);
-    }
-
-    // TODO(b/234338136): Need to add the force feedback HW API test cases
-    bool initFF() override {
-        ATRACE_NAME(__func__);
-        const std::string INPUT_EVENT_NAME = std::getenv("INPUT_EVENT_NAME") ?: "";
-        if (INPUT_EVENT_NAME.find("cs40l26") == std::string::npos) {
-            ALOGE("Invalid input name: %s", INPUT_EVENT_NAME.c_str());
-            return false;
-        }
-
-        glob_t g = {};
-        const std::string INPUT_EVENT_PATH = "/dev/input/event*";
-        int fd = -1, ret;
-        uint32_t val = 0;
-        char str[256] = {0x00};
-        // Scan /dev/input/event* to get the correct input device path for FF effects manipulation.
-        // Then constructs the /sys/class/input/event*/../../../ for driver attributes accessing
-        // across different platforms and different kernels.
-        for (uint8_t retry = 1; retry < 11 && !mInputFd.ok(); retry++) {
-            ret = glob(INPUT_EVENT_PATH.c_str(), 0, nullptr, &g);
-            if (ret) {
-                ALOGE("Failed to get input event paths (%d): %s", errno, strerror(errno));
-            } else {
-                for (size_t i = 0; i < g.gl_pathc; i++) {
-                    fd = TEMP_FAILURE_RETRY(::open(g.gl_pathv[i], O_RDWR));
-                    if (fd < 0) {
-                        continue;
-                    }
-                    // Determine the input device path:
-                    // 1. Check if EV_FF is flagged in event bits.
-                    // 2. Match device name(s) with this CS40L26 HAL instance.
-                    if (ioctl(fd, EVIOCGBIT(0, sizeof(val)), &val) > 0 && (val & (1 << EV_FF)) &&
-                        ioctl(fd, EVIOCGNAME(sizeof(str)), &str) > 0 &&
-                        strcmp(str, INPUT_EVENT_NAME.c_str()) == 0) {
-                        // Get fd ready for input event ioctl().
-                        mInputFd.reset(fd);  // mInputFd.ok() becomes true.
-                        ALOGI("Control %s through %s", INPUT_EVENT_NAME.c_str(), g.gl_pathv[i]);
-
-                        std::string path = g.gl_pathv[i];
-                        // Get fstream ready for input event write().
-                        saveName(path, &mInputIoStream);
-                        mInputIoStream.open(
-                                path, std::fstream::out | std::fstream::in | std::fstream::binary);
-                        if (!mInputIoStream) {
-                            ALOGE("Failed to open %s (%d): %s", path.c_str(), errno,
-                                  strerror(errno));
-                        }
-
-                        // Construct the sysfs device path.
-                        path = "/sys/class/input/" +
-                               path.substr(path.find("event"), std::string::npos) + "/../../../";
-                        updatePathPrefix(path);
-                        break;
-                    }
-                    close(fd);
-                    memset(str, 0x00, sizeof(str));
-                    val = 0;
-                }
-            }
-
-            if (!mInputFd.ok()) {
-                sleep(1);
-                ALOGW("Retry #%d to search in %zu input devices...", retry, g.gl_pathc);
-            }
-        }
-        globfree(&g);
-
-        if (!mInputFd.ok()) {
-            ALOGE("Failed to get an input event with name %s", INPUT_EVENT_NAME.c_str());
-            return false;
-        }
-
-        return true;
-    }
-    bool setFFGain(uint16_t value) override {
-        ATRACE_NAME(StringPrintf("%s %d%%", __func__, value).c_str());
-        struct input_event gain = {
-                .type = EV_FF,
-                .code = FF_GAIN,
-                .value = value,
-        };
-        if (value > 100) {
-            ALOGE("Invalid gain");
-            return false;
-        }
-        mInputIoStream.write((const char *)&gain, sizeof(gain));
-        mInputIoStream.flush();
-        if (mInputIoStream.fail()) {
-            ALOGE("setFFGain fail");
-            return false;
-        }
-        HWAPI_RECORD(StringPrintf("%d%%", value), &mInputIoStream);
-        return true;
-    }
-    bool setFFEffect(struct ff_effect *effect, uint16_t timeoutMs) override {
-        ATRACE_NAME(StringPrintf("%s %dms", __func__, timeoutMs).c_str());
-        if (effect == nullptr) {
-            ALOGE("Invalid ff_effect");
-            return false;
-        }
-        if (ioctl(mInputFd, EVIOCSFF, effect) < 0) {
-            ALOGE("setFFEffect fail");
-            return false;
-        }
-        HWAPI_RECORD(StringPrintf("#%d: %dms", (*effect).id, timeoutMs), &mInputIoStream);
-        return true;
-    }
-    bool setFFPlay(int8_t index, bool value) override {
-        ATRACE_NAME(StringPrintf("%s index:%d %s", __func__, index, value ? "on" : "off").c_str());
-        struct input_event play = {
-                .type = EV_FF,
-                .code = static_cast<uint16_t>(index),
-                .value = value,
-        };
-        mInputIoStream.write((const char *)&play, sizeof(play));
-        mInputIoStream.flush();
-        if (mInputIoStream.fail()) {
-            ALOGE("setFFPlay fail");
-            return false;
-        }
-        HWAPI_RECORD(StringPrintf("#%d: %b", index, value), &mInputIoStream);
-        return true;
-    }
-    bool getHapticAlsaDevice(int *card, int *device) override {
-        ATRACE_NAME(__func__);
-        std::string line;
-        std::ifstream myfile(PROC_SND_PCM);
-        if (myfile.is_open()) {
-            while (getline(myfile, line)) {
-                if (line.find(HAPTIC_PCM_DEVICE_SYMBOL) != std::string::npos) {
-                    std::stringstream ss(line);
-                    std::string currentToken;
-                    std::getline(ss, currentToken, ':');
-                    sscanf(currentToken.c_str(), "%d-%d", card, device);
-                    saveName(StringPrintf("/dev/snd/pcmC%uD%up", *card, *device), &mPcmStream);
-                    return true;
-                }
-            }
-            myfile.close();
-        } else {
-            ALOGE("Failed to read file: %s", PROC_SND_PCM);
-        }
-        return false;
-    }
-    bool setHapticPcmAmp(struct pcm **haptic_pcm, bool enable, int card, int device) override {
-        ATRACE_NAME(StringPrintf("%s %s", __func__, enable ? "enable" : "disable").c_str());
-        int ret = 0;
-
-        if (enable) {
-            *haptic_pcm = pcm_open(card, device, PCM_OUT, &haptic_nohost_config);
-            if (!pcm_is_ready(*haptic_pcm)) {
-                ALOGE("cannot open pcm_out driver: %s", pcm_get_error(*haptic_pcm));
-                goto fail;
-            }
-            HWAPI_RECORD(std::string("pcm_open"), &mPcmStream);
-
-            ret = pcm_prepare(*haptic_pcm);
-            if (ret < 0) {
-                ALOGE("cannot prepare haptic_pcm: %s", pcm_get_error(*haptic_pcm));
-                goto fail;
-            }
-            HWAPI_RECORD(std::string("pcm_prepare"), &mPcmStream);
-
-            ret = pcm_start(*haptic_pcm);
-            if (ret < 0) {
-                ALOGE("cannot start haptic_pcm: %s", pcm_get_error(*haptic_pcm));
-                goto fail;
-            }
-            HWAPI_RECORD(std::string("pcm_start"), &mPcmStream);
-
-            return true;
-        } else {
-            if (*haptic_pcm) {
-                pcm_close(*haptic_pcm);
-                HWAPI_RECORD(std::string("pcm_close"), &mPcmStream);
-                *haptic_pcm = NULL;
-            }
-            return true;
-        }
-
-    fail:
-        pcm_close(*haptic_pcm);
-        HWAPI_RECORD(std::string("pcm_close"), &mPcmStream);
-        *haptic_pcm = NULL;
-        return false;
-    }
-    bool isPassthroughI2sHapticSupported() override {
-        return utils::getProperty("ro.vendor.vibrator.hal.passthrough_i2s_supported", false);
-    }
-    bool uploadOwtEffect(const uint8_t *owtData, const uint32_t numBytes, struct ff_effect *effect,
-                         uint32_t *outEffectIndex, int *status) override {
-        ATRACE_NAME(__func__);
-        if (owtData == nullptr || effect == nullptr || outEffectIndex == nullptr) {
-            ALOGE("Invalid argument owtData, ff_effect or outEffectIndex");
-            *status = EX_NULL_POINTER;
-            return false;
-        }
-        if (status == nullptr) {
-            ALOGE("Invalid argument status");
-            return false;
-        }
-
-        (*effect).u.periodic.custom_len = numBytes / sizeof(uint16_t);
-        memcpy((*effect).u.periodic.custom_data, owtData, numBytes);
-
-        if ((*effect).id != -1) {
-            ALOGE("(*effect).id != -1");
-        }
-
-        /* Create a new OWT waveform to update the PWLE or composite effect. */
-        (*effect).id = -1;
-        if (ioctl(mInputFd, EVIOCSFF, effect) < 0) {
-            ALOGE("Failed to upload effect %d (%d): %s", *outEffectIndex, errno, strerror(errno));
-            *status = EX_ILLEGAL_STATE;
-            return false;
-        }
-
-        if ((*effect).id >= FF_MAX_EFFECTS || (*effect).id < 0) {
-            ALOGE("Invalid waveform index after upload OWT effect: %d", (*effect).id);
-            *status = EX_ILLEGAL_ARGUMENT;
-            return false;
-        }
-        *outEffectIndex = (*effect).id;
-        *status = 0;
-        HWAPI_RECORD(StringPrintf("#%d: %dB", *outEffectIndex, numBytes), &mInputIoStream);
-        return true;
-    }
-    bool eraseOwtEffect(int8_t effectIndex, std::vector<ff_effect> *effect) override {
-        ATRACE_NAME(__func__);
-        uint32_t effectCountBefore, effectCountAfter, i, successFlush = 0;
-
-        if (effectIndex < WAVEFORM_MAX_PHYSICAL_INDEX) {
-            ALOGE("Invalid waveform index for OWT erase: %d", effectIndex);
-            return false;
-        }
-        if (effect == nullptr || (*effect).empty()) {
-            ALOGE("Invalid argument effect");
-            return false;
-        }
-
-        if (effectIndex < WAVEFORM_MAX_INDEX) {
-            /* Normal situation. Only erase the effect which we just played. */
-            if (ioctl(mInputFd, EVIOCRMFF, effectIndex) < 0) {
-                ALOGE("Failed to erase effect %d (%d): %s", effectIndex, errno, strerror(errno));
-            }
-            for (i = WAVEFORM_MAX_PHYSICAL_INDEX; i < WAVEFORM_MAX_INDEX; i++) {
-                if ((*effect)[i].id == effectIndex) {
-                    (*effect)[i].id = -1;
-                    break;
-                }
-            }
-            HWAPI_RECORD(StringPrintf("#%d", effectIndex), &mInputIoStream);
-        } else {
-            /* Flush all non-prestored effects of ff-core and driver. */
-            getEffectCount(&effectCountBefore);
-            for (i = WAVEFORM_MAX_PHYSICAL_INDEX; i < FF_MAX_EFFECTS; i++) {
-                if (ioctl(mInputFd, EVIOCRMFF, i) >= 0) {
-                    successFlush++;
-                    HWAPI_RECORD(StringPrintf("#%d", i), &mInputIoStream);
-                }
-            }
-            getEffectCount(&effectCountAfter);
-            ALOGW("Flushed effects: ff: %d; driver: %d -> %d; success: %d", effectIndex,
-                  effectCountBefore, effectCountAfter, successFlush);
-            /* Reset all OWT effect index of HAL. */
-            for (i = WAVEFORM_MAX_PHYSICAL_INDEX; i < WAVEFORM_MAX_INDEX; i++) {
-                (*effect)[i].id = -1;
-            }
-        }
-        return true;
-    }
-    bool isDbcSupported() override {
-        ATRACE_NAME(__func__);
-        return utils::getProperty("ro.vendor.vibrator.hal.dbc.enable", false);
-    }
-
-    bool enableDbc() override {
-        ATRACE_NAME(__func__);
-        if (isDbcSupported()) {
-            open("dbc/dbc_env_rel_coef", &mDbcEnvRelCoef);
-            open("dbc/dbc_rise_headroom", &mDbcRiseHeadroom);
-            open("dbc/dbc_fall_headroom", &mDbcFallHeadroom);
-            open("dbc/dbc_tx_lvl_thresh_fs", &mDbcTxLvlThreshFs);
-            open("dbc/dbc_tx_lvl_hold_off_ms", &mDbcTxLvlHoldOffMs);
-            open("default/pm_active_timeout_ms", &mPmActiveTimeoutMs);
-            open("dbc/dbc_enable", &mDbcEnable);
-
-            // Set values from config. Default if not found.
-            set(utils::getProperty("ro.vendor.vibrator.hal.dbc.envrelcoef", kDbcDefaultEnvRelCoef),
-                &mDbcEnvRelCoef);
-            set(utils::getProperty("ro.vendor.vibrator.hal.dbc.riseheadroom",
-                                   kDbcDefaultRiseHeadroom),
-                &mDbcRiseHeadroom);
-            set(utils::getProperty("ro.vendor.vibrator.hal.dbc.fallheadroom",
-                                   kDbcDefaultFallHeadroom),
-                &mDbcFallHeadroom);
-            set(utils::getProperty("ro.vendor.vibrator.hal.dbc.txlvlthreshfs",
-                                   kDbcDefaultTxLvlThreshFs),
-                &mDbcTxLvlThreshFs);
-            set(utils::getProperty("ro.vendor.vibrator.hal.dbc.txlvlholdoffms",
-                                   kDbcDefaultTxLvlHoldOffMs),
-                &mDbcTxLvlHoldOffMs);
-            set(utils::getProperty("ro.vendor.vibrator.hal.pm.activetimeout",
-                                   kDefaultPmActiveTimeoutMs),
-                &mPmActiveTimeoutMs);
-            set(kDbcEnable, &mDbcEnable);
-            return true;
-        }
-        return false;
-    }
-
-    void debug(int fd) override { HwApiBase::debug(fd); }
-
-  private:
-    static constexpr uint32_t kDbcDefaultEnvRelCoef = 8353728;
-    static constexpr uint32_t kDbcDefaultRiseHeadroom = 1909602;
-    static constexpr uint32_t kDbcDefaultFallHeadroom = 1909602;
-    static constexpr uint32_t kDbcDefaultTxLvlThreshFs = 2516583;
-    static constexpr uint32_t kDbcDefaultTxLvlHoldOffMs = 0;
-    static constexpr uint32_t kDefaultPmActiveTimeoutMs = 5;
-    static constexpr uint32_t kDbcEnable = 1;
-
-    std::ofstream mF0;
-    std::ofstream mF0Offset;
-    std::ofstream mRedc;
-    std::ofstream mQ;
-    std::ifstream mEffectCount;
-    std::ofstream mEffectBrakingTimeBank;
-    std::ofstream mEffectBrakingTimeIndex;
-    std::ifstream mEffectBrakingTimeMs;
-    std::ifstream mVibeState;
-    std::ifstream mOwtFreeSpace;
-    std::ofstream mF0CompEnable;
-    std::ofstream mRedcCompEnable;
-    std::ofstream mMinOnOffInterval;
-    std::ofstream mInputIoStream;
-    std::ofstream mPcmStream;
-    ::android::base::unique_fd mInputFd;
-
-    // DBC Parameters
-    std::ofstream mDbcEnvRelCoef;
-    std::ofstream mDbcRiseHeadroom;
-    std::ofstream mDbcFallHeadroom;
-    std::ofstream mDbcTxLvlThreshFs;
-    std::ofstream mDbcTxLvlHoldOffMs;
-    std::ofstream mDbcEnable;
-    std::ofstream mPmActiveTimeoutMs;
-};
-
-class HwCal : public Vibrator::HwCal, private HwCalBase {
-  private:
-    static constexpr char VERSION[] = "version";
-    static constexpr char F0_CONFIG[] = "f0_measured";
-    static constexpr char REDC_CONFIG[] = "redc_measured";
-    static constexpr char Q_CONFIG[] = "q_measured";
-    static constexpr char TICK_VOLTAGES_CONFIG[] = "v_tick";
-    static constexpr char CLICK_VOLTAGES_CONFIG[] = "v_click";
-    static constexpr char LONG_VOLTAGES_CONFIG[] = "v_long";
-
-    static constexpr uint32_t VERSION_DEFAULT = 2;
-    static constexpr int32_t DEFAULT_FREQUENCY_SHIFT = 0;
-    static constexpr float DEFAULT_DEVICE_MASS = 0.21;
-    static constexpr float DEFAULT_LOC_COEFF = 2.5;
-    static constexpr std::array<uint32_t, 2> V_TICK_DEFAULT = {5, 95};
-    static constexpr std::array<uint32_t, 2> V_CLICK_DEFAULT = {5, 95};
-    static constexpr std::array<uint32_t, 2> V_LONG_DEFAULT = {5, 95};
-
-  public:
-    HwCal() {}
-
-    bool getVersion(uint32_t *value) override {
-        if (getPersist(VERSION, value)) {
-            return true;
-        }
-        *value = VERSION_DEFAULT;
-        return true;
-    }
-    bool getLongFrequencyShift(int32_t *value) override {
-        return getProperty("long.frequency.shift", value, DEFAULT_FREQUENCY_SHIFT);
-    }
-    bool getDeviceMass(float *value) override {
-        return getProperty("device.mass", value, DEFAULT_DEVICE_MASS);
-    }
-    bool getLocCoeff(float *value) override {
-        return getProperty("loc.coeff", value, DEFAULT_LOC_COEFF);
-    }
-    bool getF0(std::string *value) override { return getPersist(F0_CONFIG, value); }
-    bool getRedc(std::string *value) override { return getPersist(REDC_CONFIG, value); }
-    bool getQ(std::string *value) override { return getPersist(Q_CONFIG, value); }
-    bool getTickVolLevels(std::array<uint32_t, 2> *value) override {
-        if (getPersist(TICK_VOLTAGES_CONFIG, value)) {
-            return true;
-        }
-        return getProperty(TICK_VOLTAGES_CONFIG, value, V_TICK_DEFAULT);
-    }
-    bool getClickVolLevels(std::array<uint32_t, 2> *value) override {
-        if (getPersist(CLICK_VOLTAGES_CONFIG, value)) {
-            return true;
-        }
-        return getProperty(CLICK_VOLTAGES_CONFIG, value, V_CLICK_DEFAULT);
-    }
-    bool getLongVolLevels(std::array<uint32_t, 2> *value) override {
-        if (getPersist(LONG_VOLTAGES_CONFIG, value)) {
-            return true;
-        }
-        return getProperty(LONG_VOLTAGES_CONFIG, value, V_LONG_DEFAULT);
-    }
-    bool isChirpEnabled() override {
-        return utils::getProperty("persist.vendor.vibrator.hal.chirp.enabled", false);
-    }
-    bool getSupportedPrimitives(uint32_t *value) override {
-        return getProperty("supported_primitives", value, (uint32_t)0);
-    }
-    bool isF0CompEnabled() override {
-        bool value;
-        getProperty("f0.comp.enabled", &value, true);
-        return value;
-    }
-    bool isRedcCompEnabled() override {
-        bool value;
-        getProperty("redc.comp.enabled", &value, false);
-        return value;
-    }
-    void debug(int fd) override { HwCalBase::debug(fd); }
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/Stats.h b/vibrator/cs40l26/Stats.h
deleted file mode 100644
index 39480061..00000000
--- a/vibrator/cs40l26/Stats.h
+++ /dev/null
@@ -1,260 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#pragma once
-
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include <algorithm>
-#include <chrono>
-#include <mutex>
-
-#include "Hardware.h"
-#include "StatsBase.h"
-#include "Vibrator.h"
-
-constexpr int32_t DURATION_BUCKET_WIDTH = 50;
-constexpr int32_t DURATION_50MS_BUCKET_COUNT = 20;
-constexpr int32_t DURATION_BUCKET_COUNT = DURATION_50MS_BUCKET_COUNT + 1;
-constexpr uint32_t MAX_TIME_MS = UINT16_MAX;
-
-#ifndef ARRAY_SIZE
-#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
-#endif
-
-#ifdef HAPTIC_TRACE
-static const char *kWaveformLookup[] = {"WAVEFORM_LONG_VIBRATION_EFFECT",
-                                        "WAVEFORM_RESERVED_1",
-                                        "WAVEFORM_CLICK",
-                                        "WAVEFORM_SHORT_VIBRATION_EFFECT",
-                                        "WAVEFORM_THUD",
-                                        "WAVEFORM_SPIN",
-                                        "WAVEFORM_QUICK_RISE",
-                                        "WAVEFORM_SLOW_RISE",
-                                        "WAVEFORM_QUICK_FALL",
-                                        "WAVEFORM_LIGHT_TICK",
-                                        "WAVEFORM_LOW_TICK",
-                                        "WAVEFORM_RESERVED_MFG_1",
-                                        "WAVEFORM_RESERVED_MFG_2",
-                                        "WAVEFORM_RESERVED_MFG_3",
-                                        "WAVEFORM_COMPOSE",
-                                        "WAVEFORM_PWLE",
-                                        "INVALID"};
-static const char *kLatencyLookup[] = {"kWaveformEffectLatency", "kPrebakedEffectLatency",
-                                       "kCompositionEffectLatency", "kPwleEffectLatency",
-                                       "INVALID"};
-static const char *kErrorLookup[] = {"kInitError",
-                                     "kHwApiError",
-                                     "kHwCalError",
-                                     "kComposeFailError",
-                                     "kAlsaFailError",
-                                     "kAsyncFailError",
-                                     "kBadTimeoutError",
-                                     "kBadAmplitudeError",
-                                     "kBadEffectError",
-                                     "kBadEffectStrengthError",
-                                     "kBadPrimitiveError",
-                                     "kBadCompositeError",
-                                     "kPwleConstructionFailError",
-                                     "kUnsupportedOpError",
-                                     "INVALID"};
-
-const char *waveformToString(uint16_t index) {
-    return kWaveformLookup[(index < ARRAY_SIZE(kWaveformLookup)) ? index
-                                                                 : ARRAY_SIZE(kWaveformLookup) - 1];
-}
-
-const char *latencyToString(uint16_t index) {
-    return kLatencyLookup[(index < ARRAY_SIZE(kLatencyLookup)) ? index
-                                                               : ARRAY_SIZE(kLatencyLookup) - 1];
-}
-
-const char *errorToString(uint16_t index) {
-    return kErrorLookup[(index < ARRAY_SIZE(kErrorLookup)) ? index : ARRAY_SIZE(kErrorLookup) - 1];
-}
-
-#define STATS_TRACE(...)   \
-    ATRACE_NAME(__func__); \
-    ALOGD(__VA_ARGS__)
-#else
-#define STATS_TRACE(...) ATRACE_NAME(__func__)
-#define waveformToString(x)
-#define latencyToString(x)
-#define errorToString(x)
-#endif
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-enum EffectLatency : uint16_t {
-    kWaveformEffectLatency = 0,
-    kPrebakedEffectLatency,
-    kCompositionEffectLatency,
-    kPwleEffectLatency,
-
-    kEffectLatencyCount
-};
-
-enum VibratorError : uint16_t {
-    kInitError = 0,
-    kHwApiError,
-    kHwCalError,
-    kComposeFailError,
-    kAlsaFailError,
-    kAsyncFailError,
-    kBadTimeoutError,
-    kBadAmplitudeError,
-    kBadEffectError,
-    kBadEffectStrengthError,
-    kBadPrimitiveError,
-    kBadCompositeError,
-    kPwleConstructionFailError,
-    kUnsupportedOpError,
-
-    kVibratorErrorCount
-};
-
-class StatsApi : public Vibrator::StatsApi, private StatsBase {
-  public:
-    StatsApi()
-        : StatsBase(std::string(std::getenv("STATS_INSTANCE"))),
-          mCurrentLatencyIndex(kEffectLatencyCount) {
-        mWaveformCounts = std::vector<int32_t>(WAVEFORM_MAX_INDEX, 0);
-        mDurationCounts = std::vector<int32_t>(DURATION_BUCKET_COUNT, 0);
-        mMinLatencies = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mMaxLatencies = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mLatencyTotals = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mLatencyCounts = std::vector<int32_t>(kEffectLatencyCount, 0);
-        mErrorCounts = std::vector<int32_t>(kVibratorErrorCount, 0);
-    }
-
-    bool logPrimitive(uint16_t effectIndex) override {
-        STATS_TRACE("logPrimitive(effectIndex: %s)", waveformToString(effectIndex));
-
-        if (effectIndex >= WAVEFORM_MAX_PHYSICAL_INDEX ||
-            effectIndex == WAVEFORM_LONG_VIBRATION_EFFECT_INDEX ||
-            effectIndex == WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX) {
-            ALOGE("Invalid waveform index for logging primitive: %d", effectIndex);
-            return false;
-        }
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            mWaveformCounts[effectIndex]++;
-        }
-
-        return true;
-    }
-
-    bool logWaveform(uint16_t effectIndex, int32_t duration) override {
-        STATS_TRACE("logWaveform(effectIndex: %s, duration: %d)", waveformToString(effectIndex),
-                    duration);
-
-        if (effectIndex != WAVEFORM_LONG_VIBRATION_EFFECT_INDEX &&
-            effectIndex != WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX) {
-            ALOGE("Invalid waveform index for logging waveform: %d", effectIndex);
-            return false;
-        }
-
-        if (duration > MAX_TIME_MS || duration < 0) {
-            ALOGE("Invalid waveform duration for logging waveform: %d", duration);
-            return false;
-        }
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            mWaveformCounts[effectIndex]++;
-            if (duration < DURATION_BUCKET_WIDTH * DURATION_50MS_BUCKET_COUNT) {
-                mDurationCounts[duration / DURATION_BUCKET_WIDTH]++;
-            } else {
-                mDurationCounts[DURATION_50MS_BUCKET_COUNT]++;
-            }
-        }
-
-        return true;
-    }
-
-    bool logError(uint16_t errorIndex) override {
-        STATS_TRACE("logError(errorIndex: %s)", errorToString(errorIndex));
-
-        if (errorIndex >= kVibratorErrorCount) {
-            ALOGE("Invalid index for logging error: %d", errorIndex);
-            return false;
-        }
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            mErrorCounts[errorIndex]++;
-        }
-
-        return true;
-    }
-
-    bool logLatencyStart(uint16_t latencyIndex) override {
-        STATS_TRACE("logLatencyStart(latencyIndex: %s)", latencyToString(latencyIndex));
-
-        if (latencyIndex >= kEffectLatencyCount) {
-            ALOGE("Invalid index for measuring latency: %d", latencyIndex);
-            return false;
-        }
-
-        mCurrentLatencyStart = std::chrono::steady_clock::now();
-        mCurrentLatencyIndex = latencyIndex;
-
-        return true;
-    }
-
-    bool logLatencyEnd() override {
-        STATS_TRACE("logLatencyEnd()");
-
-        if (mCurrentLatencyIndex >= kEffectLatencyCount) {
-            return false;
-        }
-
-        int32_t latency = (std::chrono::duration_cast<std::chrono::milliseconds>(
-                                   std::chrono::steady_clock::now() - mCurrentLatencyStart))
-                                  .count();
-
-        {
-            std::scoped_lock<std::mutex> lock(mDataAccess);
-            if (latency < mMinLatencies[mCurrentLatencyIndex] ||
-                mMinLatencies[mCurrentLatencyIndex] == 0) {
-                mMinLatencies[mCurrentLatencyIndex] = latency;
-            }
-            if (latency > mMaxLatencies[mCurrentLatencyIndex]) {
-                mMaxLatencies[mCurrentLatencyIndex] = latency;
-            }
-            mLatencyTotals[mCurrentLatencyIndex] += latency;
-            mLatencyCounts[mCurrentLatencyIndex]++;
-        }
-
-        mCurrentLatencyIndex = kEffectLatencyCount;
-        return true;
-    }
-
-    void debug(int fd) override { StatsBase::debug(fd); }
-
-  private:
-    uint16_t mCurrentLatencyIndex;
-    std::chrono::time_point<std::chrono::steady_clock> mCurrentLatencyStart;
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/TEST_MAPPING b/vibrator/cs40l26/TEST_MAPPING
deleted file mode 100644
index 1d8ff7ac..00000000
--- a/vibrator/cs40l26/TEST_MAPPING
+++ /dev/null
@@ -1,10 +0,0 @@
-{
-  "presubmit": [
-    {
-      "name": "VibratorHalCs40l26TestSuite",
-      "keywords": [
-        "nextgen"
-      ]
-    }
-  ]
-}
diff --git a/vibrator/cs40l26/Trace.cpp b/vibrator/cs40l26/Trace.cpp
deleted file mode 100644
index 10b54534..00000000
--- a/vibrator/cs40l26/Trace.cpp
+++ /dev/null
@@ -1,256 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#include "Trace.h"
-
-#include <aidl/android/hardware/vibrator/BnVibrator.h>
-#include <log/log.h>
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-enum WaveformIndex : uint16_t {
-    /* Physical waveform */
-    WAVEFORM_LONG_VIBRATION_EFFECT_INDEX = 0,
-    WAVEFORM_RESERVED_INDEX_1 = 1,
-    WAVEFORM_CLICK_INDEX = 2,
-    WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX = 3,
-    WAVEFORM_THUD_INDEX = 4,
-    WAVEFORM_SPIN_INDEX = 5,
-    WAVEFORM_QUICK_RISE_INDEX = 6,
-    WAVEFORM_SLOW_RISE_INDEX = 7,
-    WAVEFORM_QUICK_FALL_INDEX = 8,
-    WAVEFORM_LIGHT_TICK_INDEX = 9,
-    WAVEFORM_LOW_TICK_INDEX = 10,
-    WAVEFORM_RESERVED_MFG_1,
-    WAVEFORM_RESERVED_MFG_2,
-    WAVEFORM_RESERVED_MFG_3,
-    WAVEFORM_MAX_PHYSICAL_INDEX,
-    /* OWT waveform */
-    WAVEFORM_COMPOSE = WAVEFORM_MAX_PHYSICAL_INDEX,
-    WAVEFORM_PWLE,
-    /*
-     * Refer to <linux/input.h>, the WAVEFORM_MAX_INDEX must not exceed 96.
-     * #define FF_GAIN          0x60  // 96 in decimal
-     * #define FF_MAX_EFFECTS   FF_GAIN
-     */
-    WAVEFORM_MAX_INDEX,
-};
-
-/* Support printing */
-
-std::ostream &operator<<(std::ostream &out, std::shared_ptr<IVibratorCallback> arg) {
-    return out << arg->descriptor << "()";
-}
-
-std::ostream &operator<<(std::ostream &out, const ff_effect *arg) {
-    if (arg == nullptr) {
-        return out;
-    }
-
-    return out << StringPrintf("%p", arg).c_str();
-}
-
-std::ostream &operator<<(std::ostream &out, const ff_effect &arg) {
-    out << "(";
-    out << "FF_PERIODIC, " << arg.id << ", " << arg.replay.length << "ms, "
-        << arg.u.periodic.custom_len << " bytes";
-    out << ")";
-    return out;
-}
-
-std::ostream &operator<<(std::ostream &out, const CompositePrimitive &arg) {
-    return out << toString(arg).c_str();
-}
-
-std::ostream &operator<<(std::ostream &out, const Braking &arg) {
-    return out << toString(arg).c_str();
-}
-
-std::ostream &operator<<(std::ostream &out, const PrimitivePwle &arg) {
-    out << "(";
-    switch (arg.getTag()) {
-        case PrimitivePwle::active: {
-            auto active = arg.get<PrimitivePwle::active>();
-            out << std::fixed << std::setprecision(2) << active.startAmplitude << ", "
-                << active.startFrequency << "Hz, " << active.endAmplitude << ", "
-                << active.endFrequency << "Hz, " << active.duration << "ms";
-            break;
-        }
-        case PrimitivePwle::braking: {
-            out << "Deprecated!";
-            break;
-        }
-    }
-    out << ")";
-    return out;
-}
-
-std::ostream &operator<<(std::ostream &out, const CompositeEffect &arg) {
-    out << "(" << arg.delayMs << "ms, " << toString(arg.primitive) << ", " << arg.scale << ")";
-    return out;
-}
-
-std::ostream &operator<<(std::ostream &out, const DspMemChunk *arg) {
-    if (arg == nullptr) {
-        return out << "NULL";
-    }
-
-    out << "(";
-    if (arg->type() == 14) {
-        out << "WAVEFORM_COMPOSE, ";
-    } else if (arg->type() == 15) {
-        out << "WAVEFORM_PWLE, ";
-    }
-    out << arg->size() << " bytes";
-    out << ")";
-    return out;
-}
-
-std::ostream &operator<<(std::ostream &out, Effect arg) {
-    return out << toString(arg).c_str();
-}
-
-std::ostream &operator<<(std::ostream &out, EffectStrength arg) {
-    return out << toString(arg).c_str();
-}
-
-/* Trace Interface */
-
-int Trace::mDepth = -1;
-std::vector<std::string> Trace::mTrace = {};
-std::vector<std::vector<std::string>> Trace::mPreviousTraces = {};
-
-void Trace::debug(int fd) {
-    std::vector<std::string> tTrace;
-    std::swap(mTrace, tTrace);
-
-    std::vector<std::vector<std::string>> tPreviousTraces;
-    std::swap(mPreviousTraces, tPreviousTraces);
-
-    dprintf(fd, "\nCurrent Trace:\n");
-    for (auto line : tTrace) {
-        dprintf(fd, "%s\n", line.c_str());
-    }
-
-    if (tPreviousTraces.size() > 0) {
-        for (auto i = tPreviousTraces.size(); i--;) {
-            dprintf(fd, "\nPrevious Trace #%zu:\n", i);
-            for (auto line : tPreviousTraces[i]) {
-                dprintf(fd, "%s\n", line.c_str());
-            }
-        }
-    }
-}
-
-/* FunctionTrace Interface */
-
-FunctionTrace::FunctionTrace(const char *funcName) : mClassName(""), mFuncName(funcName) {
-    Trace::enter();
-}
-
-FunctionTrace::FunctionTrace(const char *className, const char *funcName)
-    : mClassName(className), mFuncName(funcName) {
-    Trace::enter();
-}
-
-FunctionTrace::~FunctionTrace() {
-    Trace::exit();
-}
-
-void FunctionTrace::save() {
-    std::stringstream fmt;
-    int d = Trace::depth();
-    for (int i = 0; i < d; i++) {
-        fmt << "   ";
-    }
-
-    if (mClassName != "") {
-        fmt << mClassName << "::";
-    }
-    fmt << mFuncName << "(";
-
-    for (auto param : mParameters) {
-        fmt << param;
-        if (param != mParameters.back()) {
-            fmt << ", ";
-        }
-    }
-
-    fmt << ")";
-
-    std::string fmtOut = fmt.str();
-    ALOGI("%s", fmtOut.c_str());
-    Trace::push(fmtOut);
-}
-
-/* Effect Trace Implementation */
-
-EffectTrace::EffectTrace(uint16_t index, float scale, int32_t duration, const DspMemChunk *ch) {
-    std::stringstream fmt;
-    fmt << "Effect(";
-    switch (index) {
-        case WAVEFORM_LONG_VIBRATION_EFFECT_INDEX:
-            fmt << "LONG_VIBRATION, " << scale << ", " << duration << ")";
-            break;
-        case WAVEFORM_CLICK_INDEX:
-            fmt << "CLICK, " << scale << ")";
-            break;
-        case WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX:
-            fmt << "SHORT_VIBRATION, " << scale << ", " << duration << ")";
-            break;
-        case WAVEFORM_THUD_INDEX:
-        case WAVEFORM_SPIN_INDEX:
-        case WAVEFORM_QUICK_RISE_INDEX:
-        case WAVEFORM_SLOW_RISE_INDEX:
-        case WAVEFORM_QUICK_FALL_INDEX:
-            break;
-        case WAVEFORM_LIGHT_TICK_INDEX:
-            fmt << "LIGHT_TICK, " << scale << ")";
-            break;
-        case WAVEFORM_LOW_TICK_INDEX:
-            break;
-        case WAVEFORM_COMPOSE:
-            fmt << "COMPOSITE, " << ch->size() << " bytes)";
-            break;
-        case WAVEFORM_PWLE:
-            fmt << "PWLE, " << ch->size() << " bytes)";
-            break;
-        default:
-            break;
-    }
-    mDescription = fmt.str();
-}
-
-void EffectTrace::save() {
-    std::stringstream fmt;
-    for (int i = 0; i < depth(); i++) {
-        fmt << "   ";
-    }
-    fmt << mDescription;
-
-    std::string fmtOut = fmt.str();
-    ALOGI("%s", fmtOut.c_str());
-    Trace::push(fmtOut);
-    Trace::save();
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/Trace.h b/vibrator/cs40l26/Trace.h
deleted file mode 100644
index 4b49126d..00000000
--- a/vibrator/cs40l26/Trace.h
+++ /dev/null
@@ -1,231 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#pragma once
-
-#include <aidl/android/hardware/vibrator/BnVibrator.h>
-#include <aidl/android/hardware/vibrator/BnVibratorCallback.h>
-#include <android-base/stringprintf.h>
-#include <hardware/hardware.h>
-#include <hardware/vibrator.h>
-#include <linux/input.h>
-
-#include <iomanip>
-#include <iostream>
-#include <sstream>
-#include <string>
-#include <typeinfo>
-#include <vector>
-
-#include "DspMemChunk.h"
-
-/* Macros to expand argument (x) into pair("x", x) for nicer tracing logs
- * Easily extendible past 7 elements
- */
-#define WITH_NAME(a) std::make_pair(#a, a)
-
-#define VA_NUM_ARGS(...) VA_NUM_ARGS_IMPL(__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1)
-#define VA_NUM_ARGS_IMPL(_1, _2, _3, _4, _5, _6, _7, N, ...) N
-
-#define CONCAT_IMPL(x, y) x##y
-#define MACRO_CONCAT(x, y) CONCAT_IMPL(x, y)
-
-#define PREPEND_EACH_ARG_WITH_NAME_1(a) WITH_NAME(a)
-#define PREPEND_EACH_ARG_WITH_NAME_2(a, ...) WITH_NAME(a), PREPEND_EACH_ARG_WITH_NAME_1(__VA_ARGS__)
-#define PREPEND_EACH_ARG_WITH_NAME_3(a, ...) WITH_NAME(a), PREPEND_EACH_ARG_WITH_NAME_2(__VA_ARGS__)
-#define PREPEND_EACH_ARG_WITH_NAME_4(a, ...) WITH_NAME(a), PREPEND_EACH_ARG_WITH_NAME_3(__VA_ARGS__)
-#define PREPEND_EACH_ARG_WITH_NAME_5(a, ...) WITH_NAME(a), PREPEND_EACH_ARG_WITH_NAME_4(__VA_ARGS__)
-#define PREPEND_EACH_ARG_WITH_NAME_6(a, ...) WITH_NAME(a), PREPEND_EACH_ARG_WITH_NAME_5(__VA_ARGS__)
-#define PREPEND_EACH_ARG_WITH_NAME_7(a, ...) WITH_NAME(a), PREPEND_EACH_ARG_WITH_NAME_6(__VA_ARGS__)
-#define PREPEND_EACH_ARG_WITH_NAME(...) \
-    MACRO_CONCAT(PREPEND_EACH_ARG_WITH_NAME_, VA_NUM_ARGS(__VA_ARGS__))(__VA_ARGS__)
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::android::base::StringPrintf;
-
-/* Supported typenames */
-
-// Fallback to typeid
-template <typename T>
-struct TypeName {
-    static const char *Get() { return "<unknown>"; }
-};
-
-// Helper Macro
-#define SUPPORT_TYPENAME(T)        \
-    template <>                    \
-    struct TypeName<T> {           \
-        static const char *Get() { \
-            return #T;             \
-        }                          \
-    }
-
-SUPPORT_TYPENAME(bool);
-
-SUPPORT_TYPENAME(int8_t);
-SUPPORT_TYPENAME(int16_t);
-SUPPORT_TYPENAME(int32_t);
-SUPPORT_TYPENAME(uint8_t);
-SUPPORT_TYPENAME(uint16_t);
-SUPPORT_TYPENAME(uint32_t);
-
-SUPPORT_TYPENAME(int8_t *);
-SUPPORT_TYPENAME(int16_t *);
-SUPPORT_TYPENAME(int32_t *);
-SUPPORT_TYPENAME(uint8_t *);
-SUPPORT_TYPENAME(uint16_t *);
-SUPPORT_TYPENAME(uint32_t *);
-
-SUPPORT_TYPENAME(const int16_t *);
-SUPPORT_TYPENAME(const int32_t *);
-SUPPORT_TYPENAME(const uint16_t *);
-SUPPORT_TYPENAME(const uint32_t *);
-
-SUPPORT_TYPENAME(float);
-SUPPORT_TYPENAME(float *);
-SUPPORT_TYPENAME(const float *);
-
-SUPPORT_TYPENAME(std::string);
-SUPPORT_TYPENAME(const std::string &);
-SUPPORT_TYPENAME(const char **);
-
-SUPPORT_TYPENAME(std::vector<ff_effect> *);
-SUPPORT_TYPENAME(const ff_effect *);
-SUPPORT_TYPENAME(ff_effect);
-SUPPORT_TYPENAME(ff_effect *);
-
-SUPPORT_TYPENAME(Effect);
-SUPPORT_TYPENAME(EffectStrength);
-SUPPORT_TYPENAME(std::vector<Effect> *);
-
-SUPPORT_TYPENAME(const std::vector<PrimitivePwle> &);
-SUPPORT_TYPENAME(const std::vector<PrimitivePwle>);
-SUPPORT_TYPENAME(std::vector<PrimitivePwle> &);
-SUPPORT_TYPENAME(std::vector<PrimitivePwle>);
-
-SUPPORT_TYPENAME(const std::shared_ptr<IVibratorCallback> &&);
-SUPPORT_TYPENAME(const std::shared_ptr<IVibratorCallback> &);
-SUPPORT_TYPENAME(const std::shared_ptr<IVibratorCallback>);
-SUPPORT_TYPENAME(std::shared_ptr<IVibratorCallback> &&);
-SUPPORT_TYPENAME(std::shared_ptr<IVibratorCallback> &);
-SUPPORT_TYPENAME(std::shared_ptr<IVibratorCallback>);
-
-SUPPORT_TYPENAME(std::vector<CompositePrimitive> *);
-SUPPORT_TYPENAME(CompositePrimitive);
-
-SUPPORT_TYPENAME(const std::vector<CompositeEffect> &);
-SUPPORT_TYPENAME(const std::vector<CompositeEffect>);
-SUPPORT_TYPENAME(std::vector<CompositeEffect> &);
-SUPPORT_TYPENAME(std::vector<CompositeEffect>);
-
-SUPPORT_TYPENAME(std::vector<Braking> *);
-SUPPORT_TYPENAME(struct pcm **);
-SUPPORT_TYPENAME(const DspMemChunk *);
-SUPPORT_TYPENAME(DspMemChunk *);
-
-/* Support printing */
-
-template <typename T>
-std::ostream &operator<<(std::ostream &out, const std::vector<T> &arg) {
-    out << "{";
-    for (size_t i = 0; i < arg.size(); i++) {
-        out << arg[i];
-        if (i != arg.size() - 1) {
-            out << ", ";
-        }
-    }
-    out << "}";
-    return out;
-}
-
-std::ostream &operator<<(std::ostream &out, const std::shared_ptr<IVibratorCallback> arg);
-std::ostream &operator<<(std::ostream &out, const ff_effect *arg);
-std::ostream &operator<<(std::ostream &out, const ff_effect &arg);
-std::ostream &operator<<(std::ostream &out, const CompositePrimitive &arg);
-std::ostream &operator<<(std::ostream &out, const Braking &arg);
-std::ostream &operator<<(std::ostream &out, const PrimitivePwle &arg);
-std::ostream &operator<<(std::ostream &out, const CompositeEffect &arg);
-std::ostream &operator<<(std::ostream &out, const DspMemChunk *arg);
-std::ostream &operator<<(std::ostream &out, Effect arg);
-std::ostream &operator<<(std::ostream &out, EffectStrength arg);
-
-/* Tracing classes */
-
-class Trace {
-  public:
-    static void debug(int fd);
-    static int depth() { return mDepth; }
-    static void enter() { mDepth++; }
-    static void exit() { mDepth--; }
-    static void push(const std::string &t) { mTrace.push_back(t); }
-    static void pop() { mTrace.pop_back(); }
-    static void save() {
-        std::vector<std::string> temp;
-        std::swap(mTrace, temp);
-        mPreviousTraces.push_back(std::move(temp));
-    }
-
-  private:
-    static int mDepth;
-    static std::vector<std::string> mTrace;
-    static std::vector<std::vector<std::string>> mPreviousTraces;
-};
-
-class FunctionTrace : public Trace {
-  public:
-    FunctionTrace(const char *funcName);
-    FunctionTrace(const char *className, const char *funcName);
-    ~FunctionTrace();
-
-    template <typename T>
-    void addParameter(std::pair<const char *, T> t) {
-        std::stringstream fmt;
-        fmt << TypeName<T>::Get() << " " << t.first << ":" << t.second;
-        mParameters.push_back(fmt.str());
-    }
-
-    template <typename T, typename... Ts>
-    void addParameter(std::pair<const char *, T> t, Ts... ts) {
-        addParameter(t);
-        addParameter(ts...);
-    }
-
-    void addParameter() { return; }
-
-    void save();
-
-  private:
-    std::string mClassName;
-    std::string mFuncName;
-    std::vector<std::string> mParameters;
-};
-
-class EffectTrace : public Trace {
-  public:
-    EffectTrace(uint16_t index, float scale, int32_t duration, const DspMemChunk *ch);
-    void save();
-
-  private:
-    std::string mDescription;
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/Vibrator.cpp b/vibrator/cs40l26/Vibrator.cpp
deleted file mode 100644
index 81cc5fd7..00000000
--- a/vibrator/cs40l26/Vibrator.cpp
+++ /dev/null
@@ -1,1735 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#include "Vibrator.h"
-
-#include <android-base/properties.h>
-#include <hardware/hardware.h>
-#include <hardware/vibrator.h>
-#include <linux/version.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-#include <vendor_vibrator_hal_flags.h>
-
-#include <chrono>
-#include <cinttypes>
-#include <cmath>
-#include <fstream>
-#include <iostream>
-#include <limits>
-#include <map>
-#include <memory>
-#include <optional>
-#include <sstream>
-#include <string_view>
-
-#include "DspMemChunk.h"
-#include "Stats.h"
-#include "Trace.h"
-
-#ifndef ARRAY_SIZE
-#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
-#endif
-
-namespace vibrator_aconfig_flags = vendor::vibrator::hal::flags;
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-#ifdef VIBRATOR_TRACE
-/* Function Trace */
-#define VFTRACE(...)                                                             \
-    ATRACE_NAME(StringPrintf("Vibrator::%s", __func__).c_str());                 \
-    auto f_trace_ = std::make_unique<FunctionTrace>("Vibrator", __func__);       \
-    __VA_OPT__(f_trace_->addParameter(PREPEND_EACH_ARG_WITH_NAME(__VA_ARGS__))); \
-    f_trace_->save()
-/* Effect Trace */
-#define VETRACE(i, s, d, ch)                                    \
-    auto e_trace_ = std::make_unique<EffectTrace>(i, s, d, ch); \
-    e_trace_->save()
-#else
-#define VFTRACE(...) ATRACE_NAME(StringPrintf("Vibrator::%s", __func__).c_str())
-#define VETRACE(...)
-#endif
-
-static constexpr uint16_t FF_CUSTOM_DATA_LEN_MAX_COMP = 2044;  // (COMPOSE_SIZE_MAX + 1) * 8 + 4
-static constexpr uint16_t FF_CUSTOM_DATA_LEN_MAX_PWLE = 2302;
-
-static constexpr uint32_t WAVEFORM_DOUBLE_CLICK_SILENCE_MS = 100;
-
-static constexpr uint32_t WAVEFORM_LONG_VIBRATION_THRESHOLD_MS = 50;
-
-static constexpr uint8_t VOLTAGE_SCALE_MAX = 100;
-
-static constexpr int8_t MAX_COLD_START_LATENCY_MS = 6;  // I2C Transaction + DSP Return-From-Standby
-static constexpr uint32_t MIN_ON_OFF_INTERVAL_US = 8500;  // SVC initialization time
-static constexpr int8_t MAX_PAUSE_TIMING_ERROR_MS = 1;    // ALERT Irq Handling
-static constexpr uint32_t MAX_TIME_MS = UINT16_MAX;
-
-static constexpr auto ASYNC_COMPLETION_TIMEOUT = std::chrono::milliseconds(100);
-static constexpr auto POLLING_TIMEOUT = 50;  // POLLING_TIMEOUT < ASYNC_COMPLETION_TIMEOUT
-static constexpr int32_t COMPOSE_DELAY_MAX_MS = 10000;
-
-static constexpr float PWLE_LEVEL_MIN = 0.0;
-static constexpr float PWLE_LEVEL_MAX = 1.0;
-static constexpr float PWLE_FREQUENCY_RESOLUTION_HZ = 1.00;
-static constexpr float RESONANT_FREQUENCY_DEFAULT = 145.0f;
-static constexpr float PWLE_BW_MAP_SIZE =
-        1 + ((PWLE_FREQUENCY_MAX_HZ - PWLE_FREQUENCY_MIN_HZ) / PWLE_FREQUENCY_RESOLUTION_HZ);
-
-enum WaveformBankID : uint8_t {
-    RAM_WVFRM_BANK,
-    ROM_WVFRM_BANK,
-    OWT_WVFRM_BANK,
-};
-
-enum WaveformIndex : uint16_t {
-    /* Physical waveform */
-    WAVEFORM_LONG_VIBRATION_EFFECT_INDEX = 0,
-    WAVEFORM_RESERVED_INDEX_1 = 1,
-    WAVEFORM_CLICK_INDEX = 2,
-    WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX = 3,
-    WAVEFORM_THUD_INDEX = 4,
-    WAVEFORM_SPIN_INDEX = 5,
-    WAVEFORM_QUICK_RISE_INDEX = 6,
-    WAVEFORM_SLOW_RISE_INDEX = 7,
-    WAVEFORM_QUICK_FALL_INDEX = 8,
-    WAVEFORM_LIGHT_TICK_INDEX = 9,
-    WAVEFORM_LOW_TICK_INDEX = 10,
-    WAVEFORM_RESERVED_MFG_1,
-    WAVEFORM_RESERVED_MFG_2,
-    WAVEFORM_RESERVED_MFG_3,
-    WAVEFORM_MAX_PHYSICAL_INDEX,
-    /* OWT waveform */
-    WAVEFORM_COMPOSE = WAVEFORM_MAX_PHYSICAL_INDEX,
-    WAVEFORM_PWLE,
-    /*
-     * Refer to <linux/input.h>, the WAVEFORM_MAX_INDEX must not exceed 96.
-     * #define FF_GAIN      0x60  // 96 in decimal
-     * #define FF_MAX_EFFECTS   FF_GAIN
-     */
-    WAVEFORM_MAX_INDEX,
-};
-
-std::vector<CompositePrimitive> defaultSupportedPrimitives = {
-        ndk::enum_range<CompositePrimitive>().begin(), ndk::enum_range<CompositePrimitive>().end()};
-
-enum vibe_state {
-    VIBE_STATE_STOPPED = 0,
-    VIBE_STATE_HAPTIC,
-    VIBE_STATE_ASP,
-};
-
-std::mutex mActiveId_mutex;  // protects mActiveId
-
-// Discrete points of frequency:max_level pairs around resonant(145Hz default) frequency
-// Initialize the actuator LUXSHARE_ICT_081545 limits to 0.447 and others 1.0
-#if defined(LUXSHARE_ICT_081545)
-static std::map<float, float> discretePwleMaxLevels = {
-        {120.0, 0.447}, {130.0, 0.346}, {140.0, 0.156}, {145.0, 0.1},
-        {150.0, 0.167}, {160.0, 0.391}, {170.0, 0.447}};
-std::vector<float> pwleMaxLevelLimitMap(PWLE_BW_MAP_SIZE, 0.447);
-#else
-static std::map<float, float> discretePwleMaxLevels = {};
-std::vector<float> pwleMaxLevelLimitMap(PWLE_BW_MAP_SIZE, 1.0);
-#endif
-
-enum class QValueFormat {
-    FORMAT_7_16,  // Q
-    FORMAT_8_15,  // Redc
-    FORMAT_9_14   // F0
-};
-
-static float qValueToFloat(std::string_view qValueInHex, QValueFormat qValueFormat, bool isSigned) {
-    uint32_t intBits = 0;
-    uint32_t fracBits = 0;
-    switch (qValueFormat) {
-        case QValueFormat::FORMAT_7_16:
-            intBits = 7;
-            fracBits = 16;
-            break;
-        case QValueFormat::FORMAT_8_15:
-            intBits = 8;
-            fracBits = 15;
-            break;
-        case QValueFormat::FORMAT_9_14:
-            intBits = 9;
-            fracBits = 14;
-            break;
-        default:
-            ALOGE("Q Format enum not implemented");
-            return std::numeric_limits<float>::quiet_NaN();
-    }
-
-    uint32_t totalBits = intBits + fracBits + (isSigned ? 1 : 0);
-
-    int valInt = 0;
-    std::stringstream ss;
-    ss << std::hex << qValueInHex;
-    ss >> valInt;
-
-    if (ss.fail() || !ss.eof()) {
-        ALOGE("Invalid hex format: %s", qValueInHex.data());
-        return std::numeric_limits<float>::quiet_NaN();
-    }
-
-    // Handle sign extension if necessary
-    if (isSigned && (valInt & (1 << (totalBits - 1)))) {
-        valInt -= 1 << totalBits;
-    }
-
-    return static_cast<float>(valInt) / (1 << fracBits);
-}
-
-Vibrator::Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal,
-                   std::unique_ptr<StatsApi> statsapi)
-    : mHwApi(std::move(hwapi)),
-      mHwCal(std::move(hwcal)),
-      mStatsApi(std::move(statsapi)),
-      mAsyncHandle(std::async([] {})) {
-    int32_t longFrequencyShift;
-    std::string caldata{8, '0'};
-    uint32_t calVer;
-    const std::string INPUT_EVENT_NAME = std::getenv("INPUT_EVENT_NAME") ?: "";
-
-    mFfEffects.resize(WAVEFORM_MAX_INDEX);
-    mEffectDurations.resize(WAVEFORM_MAX_INDEX);
-    mEffectBrakingDurations.resize(WAVEFORM_MAX_INDEX);
-    mEffectDurations = {
-#if defined(UNSPECIFIED_ACTUATOR)
-            /* For Z-LRA actuators */
-            1000, 100, 25, 1000, 247, 166, 150, 500, 100, 6, 17, 1000, 13, 5,
-#elif defined(LEGACY_ZLRA_ACTUATOR)
-            1000, 100, 25, 1000, 150, 100, 150, 500, 100, 6, 25, 1000, 13, 5,
-#else
-            1000, 100, 9, 1000, 300, 133, 150, 500, 100, 5, 12, 1000, 13, 5,
-#endif
-    }; /* 11+3 waveforms. The duration must < UINT16_MAX */
-    mEffectCustomData.reserve(WAVEFORM_MAX_INDEX);
-
-    uint8_t effectIndex;
-    uint16_t numBytes = 0;
-    for (effectIndex = 0; effectIndex < WAVEFORM_MAX_INDEX; effectIndex++) {
-        if (effectIndex < WAVEFORM_MAX_PHYSICAL_INDEX) {
-            /* Initialize physical waveforms. */
-            mEffectCustomData.push_back({RAM_WVFRM_BANK, effectIndex});
-            mFfEffects[effectIndex] = {
-                    .type = FF_PERIODIC,
-                    .id = -1,
-                    // Length == 0 to allow firmware control of the duration
-                    .replay.length = 0,
-                    .u.periodic.waveform = FF_CUSTOM,
-                    .u.periodic.custom_data = mEffectCustomData[effectIndex].data(),
-                    .u.periodic.custom_len =
-                            static_cast<uint32_t>(mEffectCustomData[effectIndex].size()),
-            };
-            // Bypass the waveform update due to different input name
-            if (INPUT_EVENT_NAME.find("cs40l26") != std::string::npos) {
-                // Let the firmware control the playback duration to avoid
-                // cutting any effect that is played short
-                if (!mHwApi->setFFEffect(&mFfEffects[effectIndex], mEffectDurations[effectIndex])) {
-                    mStatsApi->logError(kHwApiError);
-                    ALOGE("Failed upload effect %d (%d): %s", effectIndex, errno, strerror(errno));
-                }
-            }
-            if (mFfEffects[effectIndex].id != effectIndex) {
-                ALOGW("Unexpected effect index: %d -> %d", effectIndex, mFfEffects[effectIndex].id);
-            }
-
-            if (mHwApi->hasEffectBrakingTimeBank()) {
-                mHwApi->setEffectBrakingTimeIndex(effectIndex);
-                mHwApi->getEffectBrakingTimeMs(&mEffectBrakingDurations[effectIndex]);
-            }
-        } else {
-            /* Initiate placeholders for OWT effects. */
-            numBytes = effectIndex == WAVEFORM_COMPOSE ? FF_CUSTOM_DATA_LEN_MAX_COMP
-                                                       : FF_CUSTOM_DATA_LEN_MAX_PWLE;
-            std::vector<int16_t> tempVec(numBytes, 0);
-            mEffectCustomData.push_back(std::move(tempVec));
-            mFfEffects[effectIndex] = {
-                    .type = FF_PERIODIC,
-                    .id = -1,
-                    .replay.length = 0,
-                    .u.periodic.waveform = FF_CUSTOM,
-                    .u.periodic.custom_data = mEffectCustomData[effectIndex].data(),
-                    .u.periodic.custom_len = 0,
-            };
-        }
-    }
-
-    if (mHwCal->getF0(&caldata)) {
-        mHwApi->setF0(caldata);
-        mResonantFrequency = qValueToFloat(caldata, QValueFormat::FORMAT_9_14, false);
-    } else {
-        mStatsApi->logError(kHwCalError);
-        ALOGE("Failed to get resonant frequency (%d): %s, using default resonant HZ: %f", errno,
-              strerror(errno), RESONANT_FREQUENCY_DEFAULT);
-        mResonantFrequency = RESONANT_FREQUENCY_DEFAULT;
-    }
-    if (mHwCal->getRedc(&caldata)) {
-        mHwApi->setRedc(caldata);
-        mRedc = qValueToFloat(caldata, QValueFormat::FORMAT_8_15, false);
-    }
-    if (mHwCal->getQ(&caldata)) {
-        mHwApi->setQ(caldata);
-    }
-
-    mHwCal->getLongFrequencyShift(&longFrequencyShift);
-    if (longFrequencyShift > 0) {
-        mF0Offset = longFrequencyShift * std::pow(2, 14);
-    } else if (longFrequencyShift < 0) {
-        mF0Offset = std::pow(2, 24) - std::abs(longFrequencyShift) * std::pow(2, 14);
-    } else {
-        mF0Offset = 0;
-    }
-
-    mHwCal->getVersion(&calVer);
-    if (calVer == 2) {
-        mHwCal->getTickVolLevels(&mTickEffectVol);
-        mHwCal->getClickVolLevels(&mClickEffectVol);
-        mHwCal->getLongVolLevels(&mLongEffectVol);
-    } else {
-        ALOGD("Unsupported calibration version: %u!", calVer);
-    }
-
-    mHwApi->setF0CompEnable(mHwCal->isF0CompEnabled());
-    mHwApi->setRedcCompEnable(mHwCal->isRedcCompEnabled());
-
-    mHasPassthroughHapticDevice = mHwApi->isPassthroughI2sHapticSupported();
-
-    mIsUnderExternalControl = false;
-
-    mIsChirpEnabled = mHwCal->isChirpEnabled();
-
-    mHwCal->getSupportedPrimitives(&mSupportedPrimitivesBits);
-    if (mSupportedPrimitivesBits > 0) {
-        for (auto e : defaultSupportedPrimitives) {
-            if (mSupportedPrimitivesBits & (1 << uint32_t(e))) {
-                mSupportedPrimitives.emplace_back(e);
-            }
-        }
-    } else {
-        for (auto e : defaultSupportedPrimitives) {
-            mSupportedPrimitivesBits |= (1 << uint32_t(e));
-        }
-        mSupportedPrimitives = defaultSupportedPrimitives;
-    }
-
-    mHwApi->setMinOnOffInterval(MIN_ON_OFF_INTERVAL_US);
-
-    createPwleMaxLevelLimitMap();
-    createBandwidthAmplitudeMap();
-
-    // We need to do this until it's supported through WISCE
-    mHwApi->enableDbc();
-
-#ifdef ADAPTIVE_HAPTICS_V1
-    updateContext();
-#endif /*ADAPTIVE_HAPTICS_V1*/
-}
-
-ndk::ScopedAStatus Vibrator::getCapabilities(int32_t *_aidl_return) {
-    VFTRACE(_aidl_return);
-
-    int32_t ret = IVibrator::CAP_ON_CALLBACK | IVibrator::CAP_PERFORM_CALLBACK |
-                  IVibrator::CAP_AMPLITUDE_CONTROL | IVibrator::CAP_GET_RESONANT_FREQUENCY |
-                  IVibrator::CAP_GET_Q_FACTOR;
-    if (mHasPassthroughHapticDevice || hasHapticAlsaDevice()) {
-        ret |= IVibrator::CAP_EXTERNAL_CONTROL;
-    } else {
-        mStatsApi->logError(kAlsaFailError);
-        ALOGE("No haptics ALSA device");
-    }
-    if (mHwApi->hasOwtFreeSpace()) {
-        ret |= IVibrator::CAP_COMPOSE_EFFECTS;
-        if (mIsChirpEnabled) {
-            ret |= IVibrator::CAP_FREQUENCY_CONTROL | IVibrator::CAP_COMPOSE_PWLE_EFFECTS;
-        }
-    }
-    *_aidl_return = ret;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::off() {
-    VFTRACE();
-    bool ret{true};
-    const std::scoped_lock<std::mutex> lock(mActiveId_mutex);
-
-    const auto startTime = std::chrono::system_clock::now();
-    const auto endTime = startTime + std::chrono::milliseconds(POLLING_TIMEOUT);
-    auto now = startTime;
-    while (halState == ISSUED && now <= endTime) {
-        std::this_thread::sleep_for(std::chrono::milliseconds(1));
-        now = std::chrono::system_clock::now();
-    }
-    if (halState == ISSUED && now > endTime) {
-        ALOGE("Timeout waiting for the actuator activation! (%d ms)", POLLING_TIMEOUT);
-    } else if (halState == PLAYING) {
-        ALOGD("Took %lld ms to wait for the actuator activation.",
-              std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count());
-    }
-
-    if (mActiveId >= 0) {
-        /* Stop the active effect. */
-        if (!mHwApi->setFFPlay(mActiveId, false)) {
-            mStatsApi->logError(kHwApiError);
-            ALOGE("Failed to stop effect %d (%d): %s", mActiveId, errno, strerror(errno));
-            ret = false;
-        }
-        halState = STOPPED;
-
-        if ((mActiveId >= WAVEFORM_MAX_PHYSICAL_INDEX) &&
-            (!mHwApi->eraseOwtEffect(mActiveId, &mFfEffects))) {
-            mStatsApi->logError(kHwApiError);
-            ALOGE("Failed to clean up the composed effect %d", mActiveId);
-            ret = false;
-        }
-    } else {
-        ALOGV("Vibrator is already off");
-    }
-
-    mActiveId = -1;
-    if (mF0Offset) {
-        mHwApi->setF0Offset(0);
-    }
-    halState = RESTORED;
-
-    if (ret) {
-        return ndk::ScopedAStatus::ok();
-    } else {
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::on(int32_t timeoutMs,
-                                const std::shared_ptr<IVibratorCallback> &callback) {
-    VFTRACE(timeoutMs, callback);
-
-    mStatsApi->logLatencyStart(kWaveformEffectLatency);
-    if (timeoutMs > MAX_TIME_MS) {
-        mStatsApi->logError(kBadTimeoutError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-    const uint16_t index = (timeoutMs < WAVEFORM_LONG_VIBRATION_THRESHOLD_MS)
-                                   ? WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX
-                                   : WAVEFORM_LONG_VIBRATION_EFFECT_INDEX;
-    if (MAX_COLD_START_LATENCY_MS <= MAX_TIME_MS - timeoutMs) {
-        timeoutMs += MAX_COLD_START_LATENCY_MS;
-    }
-    if (mF0Offset) {
-        mHwApi->setF0Offset(mF0Offset);
-    }
-
-    mStatsApi->logWaveform(index, timeoutMs);
-    return on(timeoutMs, index, nullptr /*ignored*/, callback);
-}
-
-ndk::ScopedAStatus Vibrator::perform(Effect effect, EffectStrength strength,
-                                     const std::shared_ptr<IVibratorCallback> &callback,
-                                     int32_t *_aidl_return) {
-    VFTRACE(effect, strength, callback, _aidl_return);
-
-    mStatsApi->logLatencyStart(kPrebakedEffectLatency);
-
-    return performEffect(effect, strength, callback, _aidl_return);
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedEffects(std::vector<Effect> *_aidl_return) {
-    VFTRACE(_aidl_return);
-    *_aidl_return = {Effect::TEXTURE_TICK, Effect::TICK, Effect::CLICK, Effect::HEAVY_CLICK,
-                     Effect::DOUBLE_CLICK};
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::setAmplitude(float amplitude) {
-    VFTRACE(amplitude);
-    if (amplitude <= 0.0f || amplitude > 1.0f) {
-        mStatsApi->logError(kBadAmplitudeError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-
-    if (!isUnderExternalControl()) {
-        mGlobalAmplitude = amplitude;
-        auto volLevel = intensityToVolLevel(mGlobalAmplitude, WAVEFORM_LONG_VIBRATION_EFFECT_INDEX);
-        return setEffectAmplitude(volLevel, VOLTAGE_SCALE_MAX, true);
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::setExternalControl(bool enabled) {
-    VFTRACE(enabled);
-    if (enabled) {
-        setEffectAmplitude(VOLTAGE_SCALE_MAX, VOLTAGE_SCALE_MAX, enabled);
-    }
-
-    if (!mHasPassthroughHapticDevice) {
-        if (mHasHapticAlsaDevice || mConfigHapticAlsaDeviceDone ||
-            hasHapticAlsaDevice()) {
-            if (!mHwApi->setHapticPcmAmp(&mHapticPcm, enabled, mCard,
-                                         mDevice)) {
-                mStatsApi->logError(kHwApiError);
-                ALOGE("Failed to %s haptic pcm device: %d",
-                      (enabled ? "enable" : "disable"), mDevice);
-                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-            }
-        } else {
-            mStatsApi->logError(kAlsaFailError);
-            ALOGE("No haptics ALSA device");
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-        }
-    }
-
-    mIsUnderExternalControl = enabled;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getCompositionDelayMax(int32_t *maxDelayMs) {
-    VFTRACE(maxDelayMs);
-    *maxDelayMs = COMPOSE_DELAY_MAX_MS;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getCompositionSizeMax(int32_t *maxSize) {
-    VFTRACE(maxSize);
-    *maxSize = COMPOSE_SIZE_MAX;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedPrimitives(std::vector<CompositePrimitive> *supported) {
-    VFTRACE(supported);
-    *supported = mSupportedPrimitives;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getPrimitiveDuration(CompositePrimitive primitive,
-                                                  int32_t *durationMs) {
-    VFTRACE(primitive, durationMs);
-    ndk::ScopedAStatus status;
-    uint32_t effectIndex;
-    if (primitive != CompositePrimitive::NOOP) {
-        status = getPrimitiveDetails(primitive, &effectIndex);
-        if (!status.isOk()) {
-            return status;
-        }
-
-        *durationMs = mEffectDurations[effectIndex] + mEffectBrakingDurations[effectIndex];
-    } else {
-        *durationMs = 0;
-    }
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::compose(const std::vector<CompositeEffect> &composite,
-                                     const std::shared_ptr<IVibratorCallback> &callback) {
-    VFTRACE(composite, callback);
-    uint16_t size;
-    uint16_t nextEffectDelay;
-
-    mStatsApi->logLatencyStart(kCompositionEffectLatency);
-
-    if (composite.size() > COMPOSE_SIZE_MAX || composite.empty()) {
-        ALOGE("%s: Invalid size", __func__);
-        mStatsApi->logError(kBadCompositeError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-
-    /* Check if there is a wait before the first effect. */
-    nextEffectDelay = composite.front().delayMs;
-    if (nextEffectDelay > COMPOSE_DELAY_MAX_MS || nextEffectDelay < 0) {
-        ALOGE("%s: Invalid delay %u", __func__, nextEffectDelay);
-        mStatsApi->logError(kBadCompositeError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    } else if (nextEffectDelay > 0) {
-        size = composite.size() + 1;
-    } else {
-        size = composite.size();
-    }
-
-    DspMemChunk ch(WAVEFORM_COMPOSE, FF_CUSTOM_DATA_LEN_MAX_COMP);
-    const uint8_t header_count = ch.size();
-
-    /* Insert 1 section for a wait before the first effect. */
-    if (nextEffectDelay) {
-        ch.constructComposeSegment(0 /*amplitude*/, 0 /*index*/, 0 /*repeat*/, 0 /*flags*/,
-                                   nextEffectDelay /*delay*/);
-    }
-
-    for (uint32_t i_curr = 0, i_next = 1; i_curr < composite.size(); i_curr++, i_next++) {
-        auto &e_curr = composite[i_curr];
-        uint32_t effectIndex = 0;
-        uint32_t effectVolLevel = 0;
-        if (e_curr.scale < 0.0f || e_curr.scale > 1.0f) {
-            ALOGE("%s: #%u: Invalid scale %f", __func__, i_curr, e_curr.scale);
-            mStatsApi->logError(kBadCompositeError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-        }
-
-        if (e_curr.primitive != CompositePrimitive::NOOP) {
-            ndk::ScopedAStatus status;
-            status = getPrimitiveDetails(e_curr.primitive, &effectIndex);
-            if (!status.isOk()) {
-                return status;
-            }
-            effectVolLevel = intensityToVolLevel(e_curr.scale, effectIndex);
-        }
-
-        /* Fetch the next composite effect delay and fill into the current section */
-        nextEffectDelay = 0;
-        if (i_next < composite.size()) {
-            auto &e_next = composite[i_next];
-            int32_t delay = e_next.delayMs;
-
-            if (delay > COMPOSE_DELAY_MAX_MS || delay < 0) {
-                ALOGE("%s: #%u: Invalid delay %d", __func__, i_next, delay);
-                mStatsApi->logError(kBadCompositeError);
-                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-            }
-            nextEffectDelay = delay;
-        }
-
-        if (effectIndex == 0 && nextEffectDelay == 0) {
-            ALOGE("%s: #%u: Invalid results", __func__, i_curr);
-            mStatsApi->logError(kBadCompositeError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-        }
-
-        nextEffectDelay += mEffectBrakingDurations[effectIndex];
-
-        mStatsApi->logPrimitive(effectIndex);
-        ch.constructComposeSegment(effectVolLevel, effectIndex, 0 /*repeat*/, 0 /*flags*/,
-                                   nextEffectDelay /*delay*/);
-    }
-
-    ch.flush();
-    if (ch.updateNSection(size) < 0) {
-        mStatsApi->logError(kComposeFailError);
-        ALOGE("%s: Failed to update the section count", __func__);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-    if (header_count == ch.size()) {
-        ALOGE("%s: Failed to append effects", __func__);
-        mStatsApi->logError(kComposeFailError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    } else {
-        // Composition duration should be 0 to allow firmware to play the whole effect
-        mFfEffects[WAVEFORM_COMPOSE].replay.length = 0;
-        return performEffect(WAVEFORM_MAX_INDEX /*ignored*/, VOLTAGE_SCALE_MAX /*ignored*/, &ch,
-                             callback);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::on(uint32_t timeoutMs, uint32_t effectIndex, const DspMemChunk *ch,
-                                const std::shared_ptr<IVibratorCallback> &callback) {
-    VFTRACE(timeoutMs, effectIndex, ch, callback);
-    ndk::ScopedAStatus status = ndk::ScopedAStatus::ok();
-
-    if (effectIndex >= FF_MAX_EFFECTS) {
-        mStatsApi->logError(kBadEffectError);
-        ALOGE("Invalid waveform index %d", effectIndex);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-    if (mAsyncHandle.wait_for(ASYNC_COMPLETION_TIMEOUT) != std::future_status::ready) {
-        mStatsApi->logError(kAsyncFailError);
-        ALOGE("Previous vibration pending: prev: %d, curr: %d", mActiveId, effectIndex);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    if (ch) {
-        /* Upload OWT effect. */
-        if (ch->front() == nullptr) {
-            mStatsApi->logError(kBadCompositeError);
-            ALOGE("Invalid OWT bank");
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-        }
-
-        if (ch->type() != WAVEFORM_PWLE && ch->type() != WAVEFORM_COMPOSE) {
-            mStatsApi->logError(kBadCompositeError);
-            ALOGE("Invalid OWT type");
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-        }
-        effectIndex = ch->type();
-
-        uint32_t freeBytes;
-        mHwApi->getOwtFreeSpace(&freeBytes);
-        if (ch->size() > freeBytes) {
-            mStatsApi->logError(kBadCompositeError);
-            ALOGE("Invalid OWT length: Effect %d: %zu > %d!", effectIndex, ch->size(), freeBytes);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-        }
-        int errorStatus;
-        if (!mHwApi->uploadOwtEffect(ch->front(), ch->size(), &mFfEffects[effectIndex],
-                                     &effectIndex, &errorStatus)) {
-            mStatsApi->logError(kHwApiError);
-            ALOGE("Invalid uploadOwtEffect");
-            return ndk::ScopedAStatus::fromExceptionCode(errorStatus);
-        }
-
-    } else if (effectIndex == WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX ||
-               effectIndex == WAVEFORM_LONG_VIBRATION_EFFECT_INDEX) {
-        /* Update duration for long/short vibration. */
-        // We can pass in the timeout for long/short vibration effects
-        mFfEffects[effectIndex].replay.length = static_cast<uint16_t>(timeoutMs);
-        if (!mHwApi->setFFEffect(&mFfEffects[effectIndex], static_cast<uint16_t>(timeoutMs))) {
-            mStatsApi->logError(kHwApiError);
-            ALOGE("Failed to edit effect %d (%d): %s", effectIndex, errno, strerror(errno));
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-        }
-    }
-
-    const std::scoped_lock<std::mutex> lock(mActiveId_mutex);
-    mActiveId = effectIndex;
-    /* Play the event now. */
-    VETRACE(effectIndex, mGlobalAmplitude, timeoutMs, ch);
-    mStatsApi->logLatencyEnd();
-    if (!mHwApi->setFFPlay(effectIndex, true)) {
-        mStatsApi->logError(kHwApiError);
-        ALOGE("Failed to play effect %d (%d): %s", effectIndex, errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-    halState = ISSUED;
-
-    mAsyncHandle = std::async(&Vibrator::waitForComplete, this, callback);
-    return ndk::ScopedAStatus::ok();
-}
-
-uint16_t Vibrator::amplitudeToScale(float amplitude, float maximum, bool scalable) {
-    VFTRACE(amplitude, maximum, scalable);
-    float ratio = 100; /* Unit: % */
-
-    if (maximum != 0)
-        ratio = amplitude / maximum * 100;
-
-    if (maximum == 0 || ratio > 100)
-        ratio = 100;
-
-#ifdef ADAPTIVE_HAPTICS_V1
-    if (scalable && mContextEnable && mContextListener) {
-        uint32_t now = CapoDetector::getCurrentTimeInMs();
-        uint32_t last_played = mLastEffectPlayedTime;
-        uint32_t lastFaceUpTime = 0;
-        uint8_t carriedPosition = 0;
-        float context_scale = 1.0;
-        bool device_face_up = false;
-        float pre_scaled_ratio = ratio;
-        mLastEffectPlayedTime = now;
-
-        mContextListener->getCarriedPositionInfo(&carriedPosition, &lastFaceUpTime);
-        device_face_up = carriedPosition == capo::PositionType::ON_TABLE_FACE_UP;
-
-        ALOGD("Vibrator Now: %u, Last: %u, ScaleTime: %u, Since? %d", now, lastFaceUpTime,
-              mScaleTime, (now < lastFaceUpTime + mScaleTime));
-        /* If the device is face-up or within the fade scaling range, find new scaling factor */
-        if (device_face_up || now < lastFaceUpTime + mScaleTime) {
-            /* Device is face-up, so we will scale it down. Start with highest scaling factor */
-            context_scale = mScalingFactor <= 100 ? static_cast<float>(mScalingFactor) / 100 : 1.0;
-            if (mFadeEnable && mScaleTime > 0 && (context_scale < 1.0) &&
-                (now < lastFaceUpTime + mScaleTime) && !device_face_up) {
-                float fade_scale =
-                        static_cast<float>(now - lastFaceUpTime) / static_cast<float>(mScaleTime);
-                context_scale += ((1.0 - context_scale) * fade_scale);
-                ALOGD("Vibrator fade scale applied: %f", fade_scale);
-            }
-            ratio *= context_scale;
-            ALOGD("Vibrator adjusting for face-up: pre: %f, post: %f", std::round(pre_scaled_ratio),
-                  std::round(ratio));
-        }
-
-        /* If we haven't played an effect within the cooldown time, save the scaling factor */
-        if ((now - last_played) > mScaleCooldown) {
-            ALOGD("Vibrator updating lastplayed scale, old: %f, new: %f", mLastPlayedScale,
-                  context_scale);
-            mLastPlayedScale = context_scale;
-        } else {
-            /* Override the scale to match previously played scale */
-            ratio = mLastPlayedScale * pre_scaled_ratio;
-            ALOGD("Vibrator repeating last scale: %f, new ratio: %f, duration since last: %u",
-                  mLastPlayedScale, ratio, (now - last_played));
-        }
-    }
-#else
-    // Suppress compiler warning
-    (void)scalable;
-#endif /*ADAPTIVE_HAPTICS_V1*/
-
-    return std::round(ratio);
-}
-
-void Vibrator::updateContext() {
-    /* Don't enable capo from HAL if flag is set to remove it */
-    if (vibrator_aconfig_flags::remove_capo()) {
-        mContextEnable = false;
-        return;
-    }
-
-    VFTRACE();
-    mContextEnable = mHwApi->getContextEnable();
-    if (mContextEnable && !mContextEnabledPreviously) {
-        mContextListener = CapoDetector::start();
-        if (mContextListener == nullptr) {
-            ALOGE("%s, CapoDetector failed to start", __func__);
-        } else {
-            mFadeEnable = mHwApi->getContextFadeEnable();
-            mScalingFactor = mHwApi->getContextScale();
-            mScaleTime = mHwApi->getContextSettlingTime();
-            mScaleCooldown = mHwApi->getContextCooldownTime();
-            ALOGD("%s, CapoDetector started successfully! NanoAppID: 0x%x, Scaling Factor: %d, "
-                  "Scaling Time: %d, Cooldown Time: %d",
-                  __func__, (uint32_t)mContextListener->getNanoppAppId(), mScalingFactor,
-                  mScaleTime, mScaleCooldown);
-
-            /* We no longer need to use this path */
-            mContextEnabledPreviously = true;
-        }
-    }
-}
-
-ndk::ScopedAStatus Vibrator::setEffectAmplitude(float amplitude, float maximum, bool scalable) {
-    VFTRACE(amplitude, maximum, scalable);
-    uint16_t scale;
-
-#ifdef ADAPTIVE_HAPTICS_V1
-    updateContext();
-#endif /*ADAPTIVE_HAPTICS_V1*/
-
-    scale = amplitudeToScale(amplitude, maximum, scalable);
-
-    if (!mHwApi->setFFGain(scale)) {
-        mStatsApi->logError(kHwApiError);
-        ALOGE("Failed to set the gain to %u (%d): %s", scale, errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedAlwaysOnEffects(std::vector<Effect> * /*_aidl_return*/) {
-    VFTRACE();
-    mStatsApi->logError(kUnsupportedOpError);
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::alwaysOnEnable(int32_t /*id*/, Effect /*effect*/,
-                                            EffectStrength /*strength*/) {
-    VFTRACE();
-    mStatsApi->logError(kUnsupportedOpError);
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-ndk::ScopedAStatus Vibrator::alwaysOnDisable(int32_t /*id*/) {
-    mStatsApi->logError(kUnsupportedOpError);
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getResonantFrequency(float *resonantFreqHz) {
-    VFTRACE(resonantFreqHz);
-    *resonantFreqHz = mResonantFrequency;
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getQFactor(float *qFactor) {
-    VFTRACE(qFactor);
-    std::string caldata{8, '0'};
-    if (!mHwCal->getQ(&caldata)) {
-        mStatsApi->logError(kHwCalError);
-        ALOGE("Failed to get q factor (%d): %s", errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-    *qFactor = qValueToFloat(caldata, QValueFormat::FORMAT_7_16, false);
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getFrequencyResolution(float *freqResolutionHz) {
-    VFTRACE(freqResolutionHz);
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_FREQUENCY_CONTROL) {
-        *freqResolutionHz = PWLE_FREQUENCY_RESOLUTION_HZ;
-        return ndk::ScopedAStatus::ok();
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::getFrequencyMinimum(float *freqMinimumHz) {
-    VFTRACE(freqMinimumHz);
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_FREQUENCY_CONTROL) {
-        *freqMinimumHz = PWLE_FREQUENCY_MIN_HZ;
-        return ndk::ScopedAStatus::ok();
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-void Vibrator::createPwleMaxLevelLimitMap() {
-    VFTRACE();
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (!(capabilities & IVibrator::CAP_FREQUENCY_CONTROL)) {
-        mStatsApi->logError(kUnsupportedOpError);
-        ALOGE("Frequency control not support.");
-        return;
-    }
-
-    if (discretePwleMaxLevels.empty()) {
-        mStatsApi->logError(kInitError);
-        ALOGE("Discrete PWLE max level maps are empty.");
-        return;
-    }
-
-    int32_t pwleMaxLevelLimitMapIdx = 0;
-    std::map<float, float>::iterator itr0 = discretePwleMaxLevels.begin();
-    if (discretePwleMaxLevels.size() == 1) {
-        ALOGD("Discrete PWLE max level map size is 1");
-        pwleMaxLevelLimitMapIdx =
-                (itr0->first - PWLE_FREQUENCY_MIN_HZ) / PWLE_FREQUENCY_RESOLUTION_HZ;
-        pwleMaxLevelLimitMap[pwleMaxLevelLimitMapIdx] = itr0->second;
-        return;
-    }
-
-    auto itr1 = std::next(itr0, 1);
-
-    while (itr1 != discretePwleMaxLevels.end()) {
-        float x0 = itr0->first;
-        float y0 = itr0->second;
-        float x1 = itr1->first;
-        float y1 = itr1->second;
-        const float ratioOfXY = ((y1 - y0) / (x1 - x0));
-        pwleMaxLevelLimitMapIdx =
-                (itr0->first - PWLE_FREQUENCY_MIN_HZ) / PWLE_FREQUENCY_RESOLUTION_HZ;
-
-        // FixLater: avoid floating point loop counters
-        // NOLINTBEGIN(clang-analyzer-security.FloatLoopCounter,cert-flp30-c)
-        for (float xp = x0; xp < (x1 + PWLE_FREQUENCY_RESOLUTION_HZ);
-             xp += PWLE_FREQUENCY_RESOLUTION_HZ) {
-            // NOLINTEND(clang-analyzer-security.FloatLoopCounter,cert-flp30-c)
-            float yp = y0 + ratioOfXY * (xp - x0);
-
-            pwleMaxLevelLimitMap[pwleMaxLevelLimitMapIdx++] = yp;
-        }
-
-        itr0++;
-        itr1++;
-    }
-}
-
-void Vibrator::createBandwidthAmplitudeMap() {
-    VFTRACE();
-    // Use constant Q Factor of 10 from HW's suggestion
-    const float qFactor = 10.0f;
-    const float blSys = 1.1f;
-    const float gravity = 9.81f;
-    const float maxVoltage = 11.0f;
-    float deviceMass = 0, locCoeff = 0;
-
-    mHwCal->getDeviceMass(&deviceMass);
-    mHwCal->getLocCoeff(&locCoeff);
-    if (!deviceMass || !locCoeff) {
-        mStatsApi->logError(kInitError);
-        ALOGE("Failed to get Device Mass: %f and Loc Coeff: %f", deviceMass, locCoeff);
-        return;
-    }
-
-    // Resistance value need to be retrieved from calibration file
-    if (mRedc == 0.0) {
-        std::string caldata{8, '0'};
-        if (mHwCal->getRedc(&caldata)) {
-            mHwApi->setRedc(caldata);
-            mRedc = qValueToFloat(caldata, QValueFormat::FORMAT_8_15, false);
-        } else {
-            mStatsApi->logError(kHwCalError);
-            ALOGE("Failed to get resistance value from calibration file");
-            return;
-        }
-    }
-
-    std::vector<float> bandwidthAmplitudeMap(PWLE_BW_MAP_SIZE, 1.0);
-
-    const float wnSys = mResonantFrequency * 2 * M_PI;
-    const float powWnSys = pow(wnSys, 2);
-    const float var2Para = wnSys / qFactor;
-
-    float frequencyHz = PWLE_FREQUENCY_MIN_HZ;
-    float frequencyRadians = 0.0f;
-    float vLevel = 0.4473f;
-    float vSys = (mLongEffectVol[1] / 100.0) * maxVoltage * vLevel;
-    float maxAsys = 0;
-    const float amplitudeSysPara = blSys * locCoeff / mRedc / deviceMass;
-
-    for (int i = 0; i < PWLE_BW_MAP_SIZE; i++) {
-        frequencyRadians = frequencyHz * 2 * M_PI;
-        vLevel = pwleMaxLevelLimitMap[i];
-        vSys = (mLongEffectVol[1] / 100.0) * maxVoltage * vLevel;
-
-        float var1 = pow((powWnSys - pow(frequencyRadians, 2)), 2);
-        float var2 = pow((var2Para * frequencyRadians), 2);
-
-        float psysAbs = sqrt(var1 + var2);
-        // The equation and all related details can be found in the bug
-        float amplitudeSys =
-                (vSys * amplitudeSysPara) * pow(frequencyRadians, 2) / psysAbs / gravity;
-        // Record the maximum acceleration for the next for loop
-        if (amplitudeSys > maxAsys)
-            maxAsys = amplitudeSys;
-
-        bandwidthAmplitudeMap[i] = amplitudeSys;
-        frequencyHz += PWLE_FREQUENCY_RESOLUTION_HZ;
-    }
-    // Scaled the map between 0 and 1.0
-    if (maxAsys > 0) {
-        for (int j = 0; j < PWLE_BW_MAP_SIZE; j++) {
-            bandwidthAmplitudeMap[j] =
-                    std::floor((bandwidthAmplitudeMap[j] / maxAsys) * 1000) / 1000;
-        }
-        mBandwidthAmplitudeMap = bandwidthAmplitudeMap;
-        mCreateBandwidthAmplitudeMapDone = true;
-    } else {
-        mCreateBandwidthAmplitudeMapDone = false;
-    }
-}
-
-ndk::ScopedAStatus Vibrator::getBandwidthAmplitudeMap(std::vector<float> *_aidl_return) {
-    VFTRACE(_aidl_return);
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_FREQUENCY_CONTROL) {
-        if (!mCreateBandwidthAmplitudeMapDone) {
-            createPwleMaxLevelLimitMap();
-            createBandwidthAmplitudeMap();
-        }
-        *_aidl_return = mBandwidthAmplitudeMap;
-        return (!mBandwidthAmplitudeMap.empty())
-                       ? ndk::ScopedAStatus::ok()
-                       : ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::getPwlePrimitiveDurationMax(int32_t *durationMs) {
-    VFTRACE(durationMs);
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_COMPOSE_PWLE_EFFECTS) {
-        *durationMs = COMPOSE_PWLE_PRIMITIVE_DURATION_MAX_MS;
-        return ndk::ScopedAStatus::ok();
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::getPwleCompositionSizeMax(int32_t *maxSize) {
-    VFTRACE(maxSize);
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_COMPOSE_PWLE_EFFECTS) {
-        *maxSize = COMPOSE_PWLE_SIZE_MAX_DEFAULT;
-        return ndk::ScopedAStatus::ok();
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedBraking(std::vector<Braking> *supported) {
-    VFTRACE(supported);
-    int32_t capabilities;
-    Vibrator::getCapabilities(&capabilities);
-    if (capabilities & IVibrator::CAP_COMPOSE_PWLE_EFFECTS) {
-        *supported = {
-                Braking::NONE,
-        };
-        return ndk::ScopedAStatus::ok();
-    } else {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-}
-
-static void resetPreviousEndAmplitudeEndFrequency(float *prevEndAmplitude,
-                                                  float *prevEndFrequency) {
-    VFTRACE(prevEndAmplitude, prevEndFrequency);
-    const float reset = -1.0;
-    *prevEndAmplitude = reset;
-    *prevEndFrequency = reset;
-}
-
-static void incrementIndex(int *index) {
-    VFTRACE(index);
-    *index += 1;
-}
-
-ndk::ScopedAStatus Vibrator::composePwle(const std::vector<PrimitivePwle> &composite,
-                                         const std::shared_ptr<IVibratorCallback> &callback) {
-    VFTRACE(composite, callback);
-    int32_t capabilities;
-
-    mStatsApi->logLatencyStart(kPwleEffectLatency);
-
-    Vibrator::getCapabilities(&capabilities);
-    if ((capabilities & IVibrator::CAP_COMPOSE_PWLE_EFFECTS) == 0) {
-        ALOGE("%s: Not supported", __func__);
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    if (composite.empty() || composite.size() > COMPOSE_PWLE_SIZE_MAX_DEFAULT) {
-        ALOGE("%s: Invalid size", __func__);
-        mStatsApi->logError(kBadCompositeError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-
-    std::vector<Braking> supported;
-    Vibrator::getSupportedBraking(&supported);
-    bool isClabSupported =
-            std::find(supported.begin(), supported.end(), Braking::CLAB) != supported.end();
-
-    int segmentIdx = 0;
-    uint32_t totalDuration = 0;
-    float prevEndAmplitude;
-    float prevEndFrequency;
-    resetPreviousEndAmplitudeEndFrequency(&prevEndAmplitude, &prevEndFrequency);
-    DspMemChunk ch(WAVEFORM_PWLE, FF_CUSTOM_DATA_LEN_MAX_PWLE);
-    bool chirp = false;
-    uint16_t c = 0;
-
-    for (auto &e : composite) {
-        switch (e.getTag()) {
-            case PrimitivePwle::active: {
-                auto active = e.get<PrimitivePwle::active>();
-                if (active.duration < 0 ||
-                    active.duration > COMPOSE_PWLE_PRIMITIVE_DURATION_MAX_MS) {
-                    mStatsApi->logError(kBadPrimitiveError);
-                    ALOGE("%s: #%u: active: Invalid duration %d", __func__, c, active.duration);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-                if (active.startAmplitude < PWLE_LEVEL_MIN ||
-                    active.startAmplitude > PWLE_LEVEL_MAX ||
-                    active.endAmplitude < PWLE_LEVEL_MIN || active.endAmplitude > PWLE_LEVEL_MAX) {
-                    mStatsApi->logError(kBadPrimitiveError);
-                    ALOGE("%s: #%u: active: Invalid scale %f, %f", __func__, c,
-                          active.startAmplitude, active.endAmplitude);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-                if (active.startAmplitude > CS40L26_PWLE_LEVEL_MAX) {
-                    active.startAmplitude = CS40L26_PWLE_LEVEL_MAX;
-                    ALOGD("%s: #%u: active: trim the start scale", __func__, c);
-                }
-                if (active.endAmplitude > CS40L26_PWLE_LEVEL_MAX) {
-                    active.endAmplitude = CS40L26_PWLE_LEVEL_MAX;
-                    ALOGD("%s: #%u: active: trim the end scale", __func__, c);
-                }
-
-                if (active.startFrequency < PWLE_FREQUENCY_MIN_HZ ||
-                    active.startFrequency > PWLE_FREQUENCY_MAX_HZ ||
-                    active.endFrequency < PWLE_FREQUENCY_MIN_HZ ||
-                    active.endFrequency > PWLE_FREQUENCY_MAX_HZ) {
-                    mStatsApi->logError(kBadPrimitiveError);
-                    ALOGE("%s: #%u: active: Invalid frequency %f, %f", __func__, c,
-                          active.startFrequency, active.endFrequency);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-
-                /* Append a new segment if current and previous amplitude and
-                 * frequency are not all the same.
-                 */
-                if (!((active.startAmplitude == prevEndAmplitude) &&
-                      (active.startFrequency == prevEndFrequency))) {
-                    if (ch.constructActiveSegment(0, active.startAmplitude, active.startFrequency,
-                                                  false) < 0) {
-                        mStatsApi->logError(kPwleConstructionFailError);
-                        ALOGE("%s: #%u: active: Failed to construct for the start scale and "
-                              "frequency %f, %f",
-                              __func__, c, active.startAmplitude, active.startFrequency);
-                        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                    }
-                    incrementIndex(&segmentIdx);
-                }
-
-                if (active.startFrequency != active.endFrequency) {
-                    chirp = true;
-                }
-                if (ch.constructActiveSegment(active.duration, active.endAmplitude,
-                                              active.endFrequency, chirp) < 0) {
-                    mStatsApi->logError(kPwleConstructionFailError);
-                    ALOGE("%s: #%u: active: Failed to construct for the end scale and frequency "
-                          "%f, %f",
-                          __func__, c, active.startAmplitude, active.startFrequency);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-                incrementIndex(&segmentIdx);
-
-                prevEndAmplitude = active.endAmplitude;
-                prevEndFrequency = active.endFrequency;
-                totalDuration += active.duration;
-                chirp = false;
-                break;
-            }
-            case PrimitivePwle::braking: {
-                auto braking = e.get<PrimitivePwle::braking>();
-                if (braking.braking > Braking::CLAB) {
-                    mStatsApi->logError(kBadPrimitiveError);
-                    ALOGE("%s: #%u: braking: Invalid braking type %s", __func__, c,
-                          toString(braking.braking).c_str());
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                } else if (!isClabSupported && (braking.braking == Braking::CLAB)) {
-                    mStatsApi->logError(kBadPrimitiveError);
-                    ALOGE("%s: #%u: braking: Unsupported CLAB braking", __func__, c);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-
-                if (braking.duration > COMPOSE_PWLE_PRIMITIVE_DURATION_MAX_MS) {
-                    mStatsApi->logError(kBadPrimitiveError);
-                    ALOGE("%s: #%u: braking: Invalid duration %d", __func__, c, braking.duration);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-
-                if (ch.constructBrakingSegment(0, braking.braking) < 0) {
-                    mStatsApi->logError(kPwleConstructionFailError);
-                    ALOGE("%s: #%u: braking: Failed to construct for type %s", __func__, c,
-                          toString(braking.braking).c_str());
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-                incrementIndex(&segmentIdx);
-
-                if (ch.constructBrakingSegment(braking.duration, braking.braking) < 0) {
-                    mStatsApi->logError(kPwleConstructionFailError);
-                    ALOGE("%s: #%u: braking: Failed to construct for type %s with duration %d",
-                          __func__, c, toString(braking.braking).c_str(), braking.duration);
-                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-                }
-                incrementIndex(&segmentIdx);
-
-                resetPreviousEndAmplitudeEndFrequency(&prevEndAmplitude, &prevEndFrequency);
-                totalDuration += braking.duration;
-                break;
-            }
-        }
-
-        if (segmentIdx > COMPOSE_PWLE_SIZE_MAX_DEFAULT) {
-            mStatsApi->logError(kPwleConstructionFailError);
-            ALOGE("Too many PrimitivePwle section!");
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-        }
-
-        c++;
-    }
-    ch.flush();
-
-    /* Update wlength */
-    totalDuration += MAX_COLD_START_LATENCY_MS;
-    if (totalDuration > 0x7FFFF) {
-        mStatsApi->logError(kPwleConstructionFailError);
-        ALOGE("Total duration is too long (%d)!", totalDuration);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    } else {
-        // For now, let's pass the duration for PWLEs
-        mFfEffects[WAVEFORM_PWLE].replay.length = totalDuration;
-    }
-
-    /* Update word count */
-    if (ch.updateWCount(segmentIdx) < 0) {
-        mStatsApi->logError(kPwleConstructionFailError);
-        ALOGE("%s: Failed to update the waveform word count", __func__);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-
-    /* Update waveform length */
-    if (ch.updateWLength(totalDuration) < 0) {
-        mStatsApi->logError(kPwleConstructionFailError);
-        ALOGE("%s: Failed to update the waveform length length", __func__);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-
-    /* Update nsections */
-    if (ch.updateNSection(segmentIdx) < 0) {
-        mStatsApi->logError(kPwleConstructionFailError);
-        ALOGE("%s: Failed to update the section count", __func__);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-
-    return performEffect(WAVEFORM_MAX_INDEX /*ignored*/, VOLTAGE_SCALE_MAX /*ignored*/, &ch,
-                         callback);
-}
-
-bool Vibrator::isUnderExternalControl() {
-    VFTRACE();
-    return mIsUnderExternalControl;
-}
-
-binder_status_t Vibrator::dump(int fd, const char **args, uint32_t numArgs) {
-    if (fd < 0) {
-        ALOGE("Called debug() with invalid fd.");
-        return STATUS_OK;
-    }
-
-    (void)args;
-    (void)numArgs;
-
-    dprintf(fd, "AIDL:\n");
-
-    dprintf(fd, "  Global Amplitude: %0.2f\n", mGlobalAmplitude);
-    dprintf(fd, "  Active Effect ID: %" PRId32 "\n", mActiveId);
-    dprintf(fd, "  F0: %.02f\n", mResonantFrequency);
-    dprintf(fd, "  F0 Offset: %" PRIu32 "\n", mF0Offset);
-    dprintf(fd, "  Redc: %.02f\n", mRedc);
-    dprintf(fd, "  HAL State: %" PRIu32 "\n", halState);
-
-    dprintf(fd, "  Voltage Levels:\n");
-    dprintf(fd, "    Tick Effect Min: %" PRIu32 " Max: %" PRIu32 "\n", mTickEffectVol[0],
-            mTickEffectVol[1]);
-    dprintf(fd, "    Click Effect Min: %" PRIu32 " Max: %" PRIu32 "\n", mClickEffectVol[0],
-            mClickEffectVol[1]);
-    dprintf(fd, "    Long Effect Min: %" PRIu32 " Max: %" PRIu32 "\n", mLongEffectVol[0],
-            mLongEffectVol[1]);
-
-    dprintf(fd, "  FF Effect:\n");
-    dprintf(fd, "    Physical Waveform:\n");
-    dprintf(fd, "\tId\tIndex\tt   ->\tt'\tBrake\n");
-    for (uint8_t effectId = 0; effectId < WAVEFORM_MAX_PHYSICAL_INDEX; effectId++) {
-        dprintf(fd, "\t%d\t%d\t%d\t%d\t%d\n", mFfEffects[effectId].id,
-                mFfEffects[effectId].u.periodic.custom_data[1], mEffectDurations[effectId],
-                mFfEffects[effectId].replay.length, mEffectBrakingDurations[effectId]);
-    }
-    dprintf(fd, "    OWT Waveform:\n");
-    dprintf(fd, "\tId\tBytes\tData\n");
-    for (uint8_t effectId = WAVEFORM_MAX_PHYSICAL_INDEX; effectId < WAVEFORM_MAX_INDEX;
-         effectId++) {
-        uint32_t numBytes = mFfEffects[effectId].u.periodic.custom_len * 2;
-        std::stringstream ss;
-        ss << " ";
-        for (int i = 0; i < numBytes; i++) {
-            ss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex
-               << (uint16_t)(*(
-                          reinterpret_cast<uint8_t *>(mFfEffects[effectId].u.periodic.custom_data) +
-                          i))
-               << " ";
-        }
-        dprintf(fd, "\t%d\t%d\t{%s}\n", mFfEffects[effectId].id, numBytes, ss.str().c_str());
-    }
-
-    dprintf(fd, "\n");
-
-    dprintf(fd, "Versions:\n");
-    std::ifstream verFile;
-    const auto verBinFileMode = std::ifstream::in | std::ifstream::binary;
-    std::string ver;
-    verFile.open("/sys/module/cs40l26_core/version");
-    if (verFile.is_open()) {
-        getline(verFile, ver);
-        dprintf(fd, "  Haptics Driver: %s\n", ver.c_str());
-        verFile.close();
-    }
-    verFile.open("/sys/module/cl_dsp_core/version");
-    if (verFile.is_open()) {
-        getline(verFile, ver);
-        dprintf(fd, "  DSP Driver: %s\n", ver.c_str());
-        verFile.close();
-    }
-    verFile.open("/vendor/firmware/cs40l26.wmfw", verBinFileMode);
-    if (verFile.is_open()) {
-        verFile.seekg(113);
-        dprintf(fd, "  cs40l26.wmfw: %d.%d.%d\n", verFile.get(), verFile.get(), verFile.get());
-        verFile.close();
-    }
-    verFile.open("/vendor/firmware/cs40l26-calib.wmfw", verBinFileMode);
-    if (verFile.is_open()) {
-        verFile.seekg(113);
-        dprintf(fd, "  cs40l26-calib.wmfw: %d.%d.%d\n", verFile.get(), verFile.get(),
-                verFile.get());
-        verFile.close();
-    }
-    verFile.open("/vendor/firmware/cs40l26.bin", verBinFileMode);
-    if (verFile.is_open()) {
-        while (getline(verFile, ver)) {
-            auto pos = ver.find("Date: ");
-            if (pos != std::string::npos) {
-                ver = ver.substr(pos + 6, pos + 15);
-                dprintf(fd, "  cs40l26.bin: %s\n", ver.c_str());
-                break;
-            }
-        }
-        verFile.close();
-    }
-    verFile.open("/vendor/firmware/cs40l26-svc.bin", verBinFileMode);
-    if (verFile.is_open()) {
-        verFile.seekg(36);
-        getline(verFile, ver);
-        ver = ver.substr(ver.rfind('\\') + 1);
-        dprintf(fd, "  cs40l26-svc.bin: %s\n", ver.c_str());
-        verFile.close();
-    }
-    verFile.open("/vendor/firmware/cs40l26-calib.bin", verBinFileMode);
-    if (verFile.is_open()) {
-        verFile.seekg(36);
-        getline(verFile, ver);
-        ver = ver.substr(ver.rfind('\\') + 1);
-        dprintf(fd, "  cs40l26-calib.bin: %s\n", ver.c_str());
-        verFile.close();
-    }
-    verFile.open("/vendor/firmware/cs40l26-dvl.bin", verBinFileMode);
-    if (verFile.is_open()) {
-        verFile.seekg(36);
-        getline(verFile, ver);
-        ver = ver.substr(0, ver.find('\0') + 1);
-        ver = ver.substr(ver.rfind('\\') + 1);
-        dprintf(fd, "  cs40l26-dvl.bin: %s\n", ver.c_str());
-        verFile.close();
-    }
-
-    dprintf(fd, "\n");
-
-    mHwApi->debug(fd);
-
-    dprintf(fd, "\n");
-
-    mHwCal->debug(fd);
-
-    dprintf(fd, "\n");
-
-    dprintf(fd, "Capo Info:\n");
-    dprintf(fd, "Capo Enabled: %d\n", mContextEnable);
-    if (mContextListener) {
-        dprintf(fd, "Capo ID: 0x%x\n", (uint32_t)(mContextListener->getNanoppAppId()));
-        dprintf(fd, "Capo State: %d\n", mContextListener->getCarriedPosition());
-    }
-
-    dprintf(fd, "\n");
-
-    mStatsApi->debug(fd);
-
-    if (mHwApi->isDbcSupported()) {
-        dprintf(fd, "\nDBC Enabled\n");
-    }
-
-#ifdef VIBRATOR_TRACE
-    Trace::debug(fd);
-#endif
-
-    fsync(fd);
-    return STATUS_OK;
-}
-
-bool Vibrator::hasHapticAlsaDevice() {
-    VFTRACE();
-    // We need to call findHapticAlsaDevice once only. Calling in the
-    // constructor is too early in the boot process and the pcm file contents
-    // are empty. Hence we make the call here once only right before we need to.
-    if (!mConfigHapticAlsaDeviceDone) {
-        if (mHwApi->getHapticAlsaDevice(&mCard, &mDevice)) {
-            mHasHapticAlsaDevice = true;
-            mConfigHapticAlsaDeviceDone = true;
-        } else {
-            mStatsApi->logError(kAlsaFailError);
-            ALOGE("Haptic ALSA device not supported");
-        }
-    } else {
-        ALOGD("Haptic ALSA device configuration done.");
-    }
-    return mHasHapticAlsaDevice;
-}
-
-ndk::ScopedAStatus Vibrator::getSimpleDetails(Effect effect, EffectStrength strength,
-                                              uint32_t *outEffectIndex, uint32_t *outTimeMs,
-                                              uint32_t *outVolLevel) {
-    VFTRACE(effect, strength, outEffectIndex, outTimeMs, outVolLevel);
-    uint32_t effectIndex;
-    uint32_t timeMs;
-    float intensity;
-    uint32_t volLevel;
-    switch (strength) {
-        case EffectStrength::LIGHT:
-            intensity = 0.5f;
-            break;
-        case EffectStrength::MEDIUM:
-            intensity = 0.7f;
-            break;
-        case EffectStrength::STRONG:
-            intensity = 1.0f;
-            break;
-        default:
-            mStatsApi->logError(kUnsupportedOpError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    switch (effect) {
-        case Effect::TEXTURE_TICK:
-            effectIndex = WAVEFORM_LIGHT_TICK_INDEX;
-            intensity *= 0.5f;
-            break;
-        case Effect::TICK:
-            effectIndex = WAVEFORM_CLICK_INDEX;
-            intensity *= 0.5f;
-            break;
-        case Effect::CLICK:
-            effectIndex = WAVEFORM_CLICK_INDEX;
-            intensity *= 0.7f;
-            break;
-        case Effect::HEAVY_CLICK:
-            effectIndex = WAVEFORM_CLICK_INDEX;
-            intensity *= 1.0f;
-            break;
-        default:
-            mStatsApi->logError(kUnsupportedOpError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    volLevel = intensityToVolLevel(intensity, effectIndex);
-    timeMs = mEffectDurations[effectIndex] + MAX_COLD_START_LATENCY_MS;
-
-    *outEffectIndex = effectIndex;
-    *outTimeMs = timeMs;
-    *outVolLevel = volLevel;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getCompoundDetails(Effect effect, EffectStrength strength,
-                                                uint32_t *outTimeMs, DspMemChunk *outCh) {
-    VFTRACE(effect, strength, outTimeMs, outCh);
-    ndk::ScopedAStatus status;
-    uint32_t timeMs = 0;
-    uint32_t thisEffectIndex;
-    uint32_t thisTimeMs;
-    uint32_t thisVolLevel;
-    switch (effect) {
-        case Effect::DOUBLE_CLICK:
-            status = getSimpleDetails(Effect::CLICK, strength, &thisEffectIndex, &thisTimeMs,
-                                      &thisVolLevel);
-            if (!status.isOk()) {
-                mStatsApi->logError(kBadEffectError);
-                return status;
-            }
-            timeMs += thisTimeMs;
-            outCh->constructComposeSegment(thisVolLevel, thisEffectIndex, 0 /*repeat*/, 0 /*flags*/,
-                                           WAVEFORM_DOUBLE_CLICK_SILENCE_MS);
-
-            timeMs += WAVEFORM_DOUBLE_CLICK_SILENCE_MS + MAX_PAUSE_TIMING_ERROR_MS;
-
-            status = getSimpleDetails(Effect::HEAVY_CLICK, strength, &thisEffectIndex, &thisTimeMs,
-                                      &thisVolLevel);
-            if (!status.isOk()) {
-                mStatsApi->logError(kBadEffectError);
-                return status;
-            }
-            timeMs += thisTimeMs;
-
-            outCh->constructComposeSegment(thisVolLevel, thisEffectIndex, 0 /*repeat*/, 0 /*flags*/,
-                                           0 /*delay*/);
-            outCh->flush();
-            if (outCh->updateNSection(2) < 0) {
-                mStatsApi->logError(kComposeFailError);
-                ALOGE("%s: Failed to update the section count", __func__);
-                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-            }
-
-            break;
-        default:
-            mStatsApi->logError(kUnsupportedOpError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    *outTimeMs = timeMs;
-    // Compositions should have 0 duration
-    mFfEffects[WAVEFORM_COMPOSE].replay.length = 0;
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getPrimitiveDetails(CompositePrimitive primitive,
-                                                 uint32_t *outEffectIndex) {
-    VFTRACE(primitive, outEffectIndex);
-    uint32_t effectIndex;
-    uint32_t primitiveBit = 1 << int32_t(primitive);
-    if ((primitiveBit & mSupportedPrimitivesBits) == 0x0) {
-        mStatsApi->logError(kUnsupportedOpError);
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    switch (primitive) {
-        case CompositePrimitive::NOOP:
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-        case CompositePrimitive::CLICK:
-            effectIndex = WAVEFORM_CLICK_INDEX;
-            break;
-        case CompositePrimitive::THUD:
-            effectIndex = WAVEFORM_THUD_INDEX;
-            break;
-        case CompositePrimitive::SPIN:
-            effectIndex = WAVEFORM_SPIN_INDEX;
-            break;
-        case CompositePrimitive::QUICK_RISE:
-            effectIndex = WAVEFORM_QUICK_RISE_INDEX;
-            break;
-        case CompositePrimitive::SLOW_RISE:
-            effectIndex = WAVEFORM_SLOW_RISE_INDEX;
-            break;
-        case CompositePrimitive::QUICK_FALL:
-            effectIndex = WAVEFORM_QUICK_FALL_INDEX;
-            break;
-        case CompositePrimitive::LIGHT_TICK:
-            effectIndex = WAVEFORM_LIGHT_TICK_INDEX;
-            break;
-        case CompositePrimitive::LOW_TICK:
-            effectIndex = WAVEFORM_LOW_TICK_INDEX;
-            break;
-        default:
-            mStatsApi->logError(kUnsupportedOpError);
-            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    *outEffectIndex = effectIndex;
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::performEffect(Effect effect, EffectStrength strength,
-                                           const std::shared_ptr<IVibratorCallback> &callback,
-                                           int32_t *outTimeMs) {
-    VFTRACE(effect, strength, callback, outTimeMs);
-    ndk::ScopedAStatus status;
-    uint32_t effectIndex;
-    uint32_t timeMs = 0;
-    uint32_t volLevel;
-    std::optional<DspMemChunk> maybeCh;
-    switch (effect) {
-        case Effect::TEXTURE_TICK:
-            // fall-through
-        case Effect::TICK:
-            // fall-through
-        case Effect::CLICK:
-            // fall-through
-        case Effect::HEAVY_CLICK:
-            status = getSimpleDetails(effect, strength, &effectIndex, &timeMs, &volLevel);
-            break;
-        case Effect::DOUBLE_CLICK:
-            maybeCh.emplace(WAVEFORM_COMPOSE, FF_CUSTOM_DATA_LEN_MAX_COMP);
-            status = getCompoundDetails(effect, strength, &timeMs, &*maybeCh);
-            volLevel = VOLTAGE_SCALE_MAX;
-            break;
-        default:
-            mStatsApi->logError(kUnsupportedOpError);
-            status = ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-            break;
-    }
-    if (status.isOk()) {
-        DspMemChunk *ch = maybeCh ? &*maybeCh : nullptr;
-        status = performEffect(effectIndex, volLevel, ch, callback);
-    }
-
-    *outTimeMs = timeMs;
-    return status;
-}
-
-ndk::ScopedAStatus Vibrator::performEffect(uint32_t effectIndex, uint32_t volLevel,
-                                           const DspMemChunk *ch,
-                                           const std::shared_ptr<IVibratorCallback> &callback) {
-    VFTRACE(effectIndex, volLevel, ch, callback);
-    setEffectAmplitude(volLevel, VOLTAGE_SCALE_MAX, false);
-
-    return on(MAX_TIME_MS, effectIndex, ch, callback);
-}
-
-void Vibrator::waitForComplete(std::shared_ptr<IVibratorCallback> &&callback) {
-    VFTRACE(callback);
-
-    if (!mHwApi->pollVibeState(VIBE_STATE_HAPTIC, POLLING_TIMEOUT)) {
-        ALOGW("Failed to get state \"Haptic\"");
-    }
-    halState = PLAYING;
-    ATRACE_BEGIN("Vibrating");
-    mHwApi->pollVibeState(VIBE_STATE_STOPPED);
-    ATRACE_END();
-    halState = STOPPED;
-
-    const std::scoped_lock<std::mutex> lock(mActiveId_mutex);
-    uint32_t effectCount = WAVEFORM_MAX_PHYSICAL_INDEX;
-    if ((mActiveId >= WAVEFORM_MAX_PHYSICAL_INDEX) &&
-        (!mHwApi->eraseOwtEffect(mActiveId, &mFfEffects))) {
-        mStatsApi->logError(kHwApiError);
-        ALOGE("Failed to clean up the composed effect %d", mActiveId);
-    } else {
-        ALOGD("waitForComplete: Vibrator is already off");
-    }
-    mHwApi->getEffectCount(&effectCount);
-    // Do waveform number checking
-    if ((effectCount > WAVEFORM_MAX_PHYSICAL_INDEX) &&
-        (!mHwApi->eraseOwtEffect(WAVEFORM_MAX_INDEX, &mFfEffects))) {
-        mStatsApi->logError(kHwApiError);
-        ALOGE("Failed to forcibly clean up all composed effect");
-    }
-
-    mActiveId = -1;
-    halState = RESTORED;
-
-    if (callback) {
-        auto ret = callback->onComplete();
-        if (!ret.isOk()) {
-            ALOGE("Failed completion callback: %d", ret.getExceptionCode());
-        }
-    }
-}
-
-uint32_t Vibrator::intensityToVolLevel(float intensity, uint32_t effectIndex) {
-    VFTRACE(intensity, effectIndex);
-
-    uint32_t volLevel;
-    auto calc = [](float intst, std::array<uint32_t, 2> v) -> uint32_t {
-        return std::lround(intst * (v[1] - v[0])) + v[0];
-    };
-
-    switch (effectIndex) {
-        case WAVEFORM_LIGHT_TICK_INDEX:
-            volLevel = calc(intensity, mTickEffectVol);
-            break;
-        case WAVEFORM_LONG_VIBRATION_EFFECT_INDEX:
-            // fall-through
-        case WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX:
-            // fall-through
-        case WAVEFORM_QUICK_RISE_INDEX:
-            // fall-through
-        case WAVEFORM_QUICK_FALL_INDEX:
-            volLevel = calc(intensity, mLongEffectVol);
-            break;
-        case WAVEFORM_CLICK_INDEX:
-            // fall-through
-        case WAVEFORM_THUD_INDEX:
-            // fall-through
-        case WAVEFORM_SPIN_INDEX:
-            // fall-through
-        case WAVEFORM_SLOW_RISE_INDEX:
-            // fall-through
-        case WAVEFORM_LOW_TICK_INDEX:
-            // fall-through
-        default:
-            volLevel = calc(intensity, mClickEffectVol);
-            break;
-    }
-    return volLevel;
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/Vibrator.h b/vibrator/cs40l26/Vibrator.h
deleted file mode 100644
index 99261a7d..00000000
--- a/vibrator/cs40l26/Vibrator.h
+++ /dev/null
@@ -1,305 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#pragma once
-
-#include <aidl/android/hardware/vibrator/BnVibrator.h>
-#include <android-base/stringprintf.h>
-#include <android-base/unique_fd.h>
-#include <linux/input.h>
-#include <tinyalsa/asoundlib.h>
-
-#include <array>
-#include <chrono>
-#include <ctime>
-#include <fstream>
-#include <future>
-
-#include "CapoDetector.h"
-
-using CapoDetector = android::chre::CapoDetector;
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::android::base::StringPrintf;
-
-class Vibrator : public BnVibrator {
-  public:
-    // APIs for interfacing with the kernel driver.
-    class HwApi {
-      public:
-        virtual ~HwApi() = default;
-        // Stores the LRA resonant frequency to be used for PWLE playback
-        // and click compensation.
-        virtual bool setF0(std::string value) = 0;
-        // Stores the frequency offset for long vibrations.
-        virtual bool setF0Offset(uint32_t value) = 0;
-        // Stores the LRA series resistance to be used for click
-        // compensation.
-        virtual bool setRedc(std::string value) = 0;
-        // Stores the LRA Q factor to be used for Q-dependent waveform
-        // selection.
-        virtual bool setQ(std::string value) = 0;
-        // Reports the number of effect waveforms loaded in firmware.
-        virtual bool getEffectCount(uint32_t *value) = 0;
-        // Checks whether braking time bank is supported.
-        virtual bool hasEffectBrakingTimeBank() = 0;
-        // Specifies the bank of the effect for querying braking time.
-        // 0: RAM bank, 2: OWT bank
-        virtual bool setEffectBrakingTimeBank(uint32_t value) = 0;
-        // Specifies the index of an effect whose braking time is to be read.
-        virtual bool setEffectBrakingTimeIndex(uint32_t value) = 0;
-        // Gets the braking time duration of SVC effects (returns 0 if not SVC).
-        virtual bool getEffectBrakingTimeMs(uint32_t *value) = 0;
-        // Blocks until timeout or vibrator reaches desired state
-        // (2 = ASP enabled, 1 = haptic enabled, 0 = disabled).
-        virtual bool pollVibeState(uint32_t value, int32_t timeoutMs = -1) = 0;
-        // Reports whether getOwtFreeSpace() is supported.
-        virtual bool hasOwtFreeSpace() = 0;
-        // Reports the available OWT bytes.
-        virtual bool getOwtFreeSpace(uint32_t *value) = 0;
-        // Enables/Disables F0 compensation enable status
-        virtual bool setF0CompEnable(bool value) = 0;
-        // Enables/Disables Redc compensation enable status
-        virtual bool setRedcCompEnable(bool value) = 0;
-        // Stores the minumun delay time between playback and stop effects.
-        virtual bool setMinOnOffInterval(uint32_t value) = 0;
-        // Determine the /dev and /sys paths for input force-feedback control.
-        virtual bool initFF() = 0;
-        // Gets the scaling factor for contextual haptic events.
-        virtual uint32_t getContextScale() = 0;
-        // Gets the enable status for contextual haptic events.
-        virtual bool getContextEnable() = 0;
-        // Gets the settling time for contextual haptic events.
-        // This will allow the device to stay face up for the duration given,
-        // even if InMotion events were detected.
-        virtual uint32_t getContextSettlingTime() = 0;
-        // Gets the cooldown time for contextual haptic events.
-        // This is used to avoid changing the scale of close playback events.
-        virtual uint32_t getContextCooldownTime() = 0;
-        // Checks the enable status for contextual haptics fade feature.  When enabled
-        // this feature will cause the scaling factor to fade back up to max over
-        // the setting time set, instead of instantaneously changing it back to max.
-        virtual bool getContextFadeEnable() = 0;
-        // Indicates the number of 0.125-dB steps of attenuation to apply to
-        // waveforms triggered in response to vibration calls from the
-        // Android vibrator HAL.
-        virtual bool setFFGain(uint16_t value) = 0;
-        // Create/modify custom effects for all physical waveforms.
-        virtual bool setFFEffect(struct ff_effect *effect, uint16_t timeoutMs) = 0;
-        // Activates/deactivates the effect index after setFFGain() and setFFEffect().
-        virtual bool setFFPlay(int8_t index, bool value) = 0;
-        // Get the Alsa device for the audio coupled haptics effect
-        virtual bool getHapticAlsaDevice(int *card, int *device) = 0;
-        // Set haptics PCM amplifier before triggering audio haptics feature
-        virtual bool setHapticPcmAmp(struct pcm **haptic_pcm, bool enable, int card,
-                                     int device) = 0;
-        // Checks to see if the passthrough i2s haptics feature is supported by
-        // the target device.
-        virtual bool isPassthroughI2sHapticSupported() = 0;
-        // Set OWT waveform for compose or compose PWLE request
-        virtual bool uploadOwtEffect(const uint8_t *owtData, const uint32_t numBytes,
-                                     struct ff_effect *effect, uint32_t *outEffectIndex,
-                                     int *status) = 0;
-        // Erase OWT waveform
-        virtual bool eraseOwtEffect(int8_t effectIndex, std::vector<ff_effect> *effect) = 0;
-        // Checks to see if DBC (Dynamic Boost Control) feature is supported
-        // by the target device.
-        virtual bool isDbcSupported() = 0;
-        // Configures and enables the DBC feature and all associated parameters
-        virtual bool enableDbc() = 0;
-        // Emit diagnostic information to the given file.
-        virtual void debug(int fd) = 0;
-    };
-
-    // APIs for obtaining calibration/configuration data from persistent memory.
-    class HwCal {
-      public:
-        virtual ~HwCal() = default;
-        // Obtain the calibration version
-        virtual bool getVersion(uint32_t *value) = 0;
-        // Obtains the LRA resonant frequency to be used for PWLE playback
-        // and click compensation.
-        virtual bool getF0(std::string *value) = 0;
-        // Obtains the LRA series resistance to be used for click
-        // compensation.
-        virtual bool getRedc(std::string *value) = 0;
-        // Obtains the LRA Q factor to be used for Q-dependent waveform
-        // selection.
-        virtual bool getQ(std::string *value) = 0;
-        // Obtains frequency shift for long vibrations.
-        virtual bool getLongFrequencyShift(int32_t *value) = 0;
-        // Obtains device mass for calculating the bandwidth amplitude map
-        virtual bool getDeviceMass(float *value) = 0;
-        // Obtains loc coeff for calculating the bandwidth amplitude map
-        virtual bool getLocCoeff(float *value) = 0;
-        // Obtains the v0/v1(min/max) voltage levels to be applied for
-        // tick/click/long in units of 1%.
-        virtual bool getTickVolLevels(std::array<uint32_t, 2> *value) = 0;
-        virtual bool getClickVolLevels(std::array<uint32_t, 2> *value) = 0;
-        virtual bool getLongVolLevels(std::array<uint32_t, 2> *value) = 0;
-        // Checks if the chirp feature is enabled.
-        virtual bool isChirpEnabled() = 0;
-        // Obtains the supported primitive effects.
-        virtual bool getSupportedPrimitives(uint32_t *value) = 0;
-        // Checks if the f0 compensation feature needs to be enabled.
-        virtual bool isF0CompEnabled() = 0;
-        // Checks if the redc compensation feature needs to be enabled.
-        virtual bool isRedcCompEnabled() = 0;
-        // Emit diagnostic information to the given file.
-        virtual void debug(int fd) = 0;
-    };
-
-    // APIs for logging data to statistics backend
-    class StatsApi {
-      public:
-        virtual ~StatsApi() = default;
-        // Increment count for effect
-        virtual bool logPrimitive(uint16_t effectIndex) = 0;
-        // Increment count for long/short waveform and duration bucket
-        virtual bool logWaveform(uint16_t effectIndex, int32_t duration) = 0;
-        // Increment count for error
-        virtual bool logError(uint16_t errorIndex) = 0;
-        // Start new latency measurement
-        virtual bool logLatencyStart(uint16_t latencyIndex) = 0;
-        // Finish latency measurement and update latency statistics with result
-        virtual bool logLatencyEnd() = 0;
-        // Emit diagnostic information to the given file.
-        virtual void debug(int fd) = 0;
-    };
-
-  public:
-    Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal,
-             std::unique_ptr<StatsApi> statsapi);
-
-    ndk::ScopedAStatus getCapabilities(int32_t *_aidl_return) override;
-    ndk::ScopedAStatus off() override;
-    ndk::ScopedAStatus on(int32_t timeoutMs,
-                          const std::shared_ptr<IVibratorCallback> &callback) override;
-    ndk::ScopedAStatus perform(Effect effect, EffectStrength strength,
-                               const std::shared_ptr<IVibratorCallback> &callback,
-                               int32_t *_aidl_return) override;
-    ndk::ScopedAStatus getSupportedEffects(std::vector<Effect> *_aidl_return) override;
-    ndk::ScopedAStatus setAmplitude(float amplitude) override;
-    ndk::ScopedAStatus setExternalControl(bool enabled) override;
-    ndk::ScopedAStatus getCompositionDelayMax(int32_t *maxDelayMs);
-    ndk::ScopedAStatus getCompositionSizeMax(int32_t *maxSize);
-    ndk::ScopedAStatus getSupportedPrimitives(std::vector<CompositePrimitive> *supported) override;
-    ndk::ScopedAStatus getPrimitiveDuration(CompositePrimitive primitive,
-                                            int32_t *durationMs) override;
-    ndk::ScopedAStatus compose(const std::vector<CompositeEffect> &composite,
-                               const std::shared_ptr<IVibratorCallback> &callback) override;
-    ndk::ScopedAStatus getSupportedAlwaysOnEffects(std::vector<Effect> *_aidl_return) override;
-    ndk::ScopedAStatus alwaysOnEnable(int32_t id, Effect effect, EffectStrength strength) override;
-    ndk::ScopedAStatus alwaysOnDisable(int32_t id) override;
-    ndk::ScopedAStatus getResonantFrequency(float *resonantFreqHz) override;
-    ndk::ScopedAStatus getQFactor(float *qFactor) override;
-    ndk::ScopedAStatus getFrequencyResolution(float *freqResolutionHz) override;
-    ndk::ScopedAStatus getFrequencyMinimum(float *freqMinimumHz) override;
-    ndk::ScopedAStatus getBandwidthAmplitudeMap(std::vector<float> *_aidl_return) override;
-    ndk::ScopedAStatus getPwlePrimitiveDurationMax(int32_t *durationMs) override;
-    ndk::ScopedAStatus getPwleCompositionSizeMax(int32_t *maxSize) override;
-    ndk::ScopedAStatus getSupportedBraking(std::vector<Braking> *supported) override;
-    ndk::ScopedAStatus composePwle(const std::vector<PrimitivePwle> &composite,
-                                   const std::shared_ptr<IVibratorCallback> &callback) override;
-
-    binder_status_t dump(int fd, const char **args, uint32_t numArgs) override;
-
-  private:
-    ndk::ScopedAStatus on(uint32_t timeoutMs, uint32_t effectIndex, const class DspMemChunk *ch,
-                          const std::shared_ptr<IVibratorCallback> &callback);
-    // set 'amplitude' based on an arbitrary scale determined by 'maximum'
-    ndk::ScopedAStatus setEffectAmplitude(float amplitude, float maximum, bool scalable);
-    // 'simple' effects are those precompiled and loaded into the controller
-    ndk::ScopedAStatus getSimpleDetails(Effect effect, EffectStrength strength,
-                                        uint32_t *outEffectIndex, uint32_t *outTimeMs,
-                                        uint32_t *outVolLevel);
-    // 'compound' effects are those composed by stringing multiple 'simple' effects
-    ndk::ScopedAStatus getCompoundDetails(Effect effect, EffectStrength strength,
-                                          uint32_t *outTimeMs, class DspMemChunk *outCh);
-    ndk::ScopedAStatus getPrimitiveDetails(CompositePrimitive primitive, uint32_t *outEffectIndex);
-    ndk::ScopedAStatus performEffect(Effect effect, EffectStrength strength,
-                                     const std::shared_ptr<IVibratorCallback> &callback,
-                                     int32_t *outTimeMs);
-    ndk::ScopedAStatus performEffect(uint32_t effectIndex, uint32_t volLevel,
-                                     const class DspMemChunk *ch,
-                                     const std::shared_ptr<IVibratorCallback> &callback);
-    ndk::ScopedAStatus setPwle(const std::string &pwleQueue);
-    bool isUnderExternalControl();
-    void waitForComplete(std::shared_ptr<IVibratorCallback> &&callback);
-    uint32_t intensityToVolLevel(float intensity, uint32_t effectIndex);
-    bool findHapticAlsaDevice(int *card, int *device);
-    bool hasHapticAlsaDevice();
-    bool enableHapticPcmAmp(struct pcm **haptic_pcm, bool enable, int card, int device);
-    void createPwleMaxLevelLimitMap();
-    void createBandwidthAmplitudeMap();
-    uint16_t amplitudeToScale(float amplitude, float maximum, bool scalable);
-    void updateContext();
-
-    std::unique_ptr<HwApi> mHwApi;
-    std::unique_ptr<HwCal> mHwCal;
-    std::unique_ptr<StatsApi> mStatsApi;
-    uint32_t mF0Offset;
-    std::array<uint32_t, 2> mTickEffectVol;
-    std::array<uint32_t, 2> mClickEffectVol;
-    std::array<uint32_t, 2> mLongEffectVol;
-    std::vector<ff_effect> mFfEffects;
-    std::vector<uint32_t> mEffectDurations;
-    std::vector<uint32_t> mEffectBrakingDurations;
-    std::vector<std::vector<int16_t>> mEffectCustomData;
-    std::future<void> mAsyncHandle;
-    int8_t mActiveId{-1};
-    struct pcm *mHapticPcm;
-    int mCard;
-    int mDevice;
-    bool mHasHapticAlsaDevice{false};
-    bool mHasPassthroughHapticDevice;
-    bool mIsUnderExternalControl;
-    float mGlobalAmplitude = 1.0;
-    bool mIsChirpEnabled;
-    uint32_t mSupportedPrimitivesBits = 0x0;
-    float mRedc{0};
-    float mResonantFrequency{0};
-    std::vector<CompositePrimitive> mSupportedPrimitives;
-    bool mConfigHapticAlsaDeviceDone{false};
-    std::vector<float> mBandwidthAmplitudeMap{};
-    bool mCreateBandwidthAmplitudeMapDone{false};
-    uint32_t mScaleTime;
-    bool mFadeEnable;
-    uint32_t mScalingFactor;
-    uint32_t mScaleCooldown;
-    bool mContextEnable;
-    bool mContextEnabledPreviously{false};
-    uint32_t mLastEffectPlayedTime = 0;
-    float mLastPlayedScale = 0;
-    sp<CapoDetector> mContextListener;
-    enum hal_state {
-        IDLE,
-        PREPARING,
-        ISSUED,
-        PLAYING,
-        STOPPED,
-        RESTORED,
-    };
-    hal_state halState = IDLE;
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/VibratorFlags.aconfig b/vibrator/cs40l26/VibratorFlags.aconfig
deleted file mode 100644
index ec6e2d4e..00000000
--- a/vibrator/cs40l26/VibratorFlags.aconfig
+++ /dev/null
@@ -1,10 +0,0 @@
-package: "vendor.vibrator.hal.flags"
-container: "vendor"
-
-flag {
-  name: "remove_capo"
-  namespace: "vibrator"
-  is_exported: true
-  description: "This flag controls the removal of utilizing Capo at the HAL level"
-  bug: "290223630"
-}
diff --git a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26-dual.rc b/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26-dual.rc
deleted file mode 100644
index d48e7ee7..00000000
--- a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26-dual.rc
+++ /dev/null
@@ -1,35 +0,0 @@
-service vendor.vibrator.cs40l26-dual /vendor/bin/hw/android.hardware.vibrator-service.cs40l26-dual
-    class hal
-    user system
-    group system input
-
-    setenv INPUT_EVENT_NAME cs40l26_dual_input
-    setenv PROPERTY_PREFIX ro.vendor.vibrator.hal.
-    setenv CALIBRATION_FILEPATH /mnt/vendor/persist/haptics/cs40l26_dual.cal
-
-    setenv HWAPI_DEBUG_PATHS "
-        calibration/f0_stored
-        calibration/redc_stored
-        calibration/q_stored
-        default/vibe_state
-        default/num_waves
-        default/braking_time_bank
-        default/braking_time_index
-        default/braking_time_ms
-        default/f0_offset
-        default/owt_free_space
-        default/f0_comp_enable
-        default/redc_comp_enable
-        default/delay_before_stop_playback_us
-        dbc/dbc_env_rel_coef
-        dbc/dbc_rise_headroom
-        dbc/dbc_fall_headroom
-        dbc/dbc_tx_lvl_thresh_fs
-        dbc/dbc_tx_lvl_hold_off_ms
-        default/pm_active_timeout_ms
-        dbc/dbc_enable
-        "
-
-    setenv STATS_INSTANCE default
-
-    disabled
diff --git a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26-dual.xml b/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26-dual.xml
deleted file mode 100644
index 1bd3e7e8..00000000
--- a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26-dual.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<manifest version="1.0" type="device">
-    <hal format="aidl">
-        <name>android.hardware.vibrator</name>
-        <version>2</version>
-        <fqname>IVibrator/dual</fqname>
-    </hal>
-</manifest>
diff --git a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26.rc b/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26.rc
deleted file mode 100644
index ccf35d83..00000000
--- a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26.rc
+++ /dev/null
@@ -1,42 +0,0 @@
-service vendor.vibrator.cs40l26 /vendor/bin/hw/android.hardware.vibrator-service.cs40l26
-    class hal
-    user system
-    group system input context_hub
-
-    setenv INPUT_EVENT_NAME cs40l26_input
-    setenv PROPERTY_PREFIX ro.vendor.vibrator.hal.
-    setenv CALIBRATION_FILEPATH /mnt/vendor/persist/haptics/cs40l26.cal
-
-    setenv HWAPI_DEBUG_PATHS "
-        calibration/f0_stored
-        calibration/redc_stored
-        calibration/q_stored
-        default/vibe_state
-        default/num_waves
-        default/braking_time_bank
-        default/braking_time_index
-        default/braking_time_ms
-        default/f0_offset
-        default/owt_free_space
-        default/f0_comp_enable
-        default/redc_comp_enable
-        default/delay_before_stop_playback_us
-        dbc/dbc_env_rel_coef
-        dbc/dbc_rise_headroom
-        dbc/dbc_fall_headroom
-        dbc/dbc_tx_lvl_thresh_fs
-        dbc/dbc_tx_lvl_hold_off_ms
-        default/pm_active_timeout_ms
-        dbc/dbc_enable
-        "
-
-    setenv STATS_INSTANCE default
-
-    disabled
-
-# Route vibrator.adaptive_haptics.enabled to persist
-on property:vibrator.adaptive_haptics.enabled=0
-    setprop persist.vendor.vibrator.hal.context.enable false
-
-on property:vibrator.adaptive_haptics.enabled=1
-    setprop persist.vendor.vibrator.hal.context.enable true
diff --git a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26.xml b/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26.xml
deleted file mode 100644
index 4db8f8c5..00000000
--- a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<manifest version="1.0" type="device">
-    <hal format="aidl">
-        <name>android.hardware.vibrator</name>
-        <version>2</version>
-        <fqname>IVibrator/default</fqname>
-    </hal>
-</manifest>
diff --git a/vibrator/cs40l26/device-stereo.mk b/vibrator/cs40l26/device-stereo.mk
deleted file mode 100644
index c9212882..00000000
--- a/vibrator/cs40l26/device-stereo.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-PRODUCT_PACKAGES += \
-    android.hardware.vibrator-service.cs40l26 \
-    android.hardware.vibrator-service.cs40l26-dual
-
-BOARD_SEPOLICY_DIRS += \
-    hardware/google/pixel-sepolicy/vibrator/common \
-    hardware/google/pixel-sepolicy/vibrator/cs40l26
diff --git a/vibrator/cs40l26/device.mk b/vibrator/cs40l26/device.mk
deleted file mode 100644
index b83f3bb7..00000000
--- a/vibrator/cs40l26/device.mk
+++ /dev/null
@@ -1,5 +0,0 @@
-PRODUCT_PACKAGES += android.hardware.vibrator-service.cs40l26
-
-BOARD_SEPOLICY_DIRS += \
-    hardware/google/pixel-sepolicy/vibrator/common \
-    hardware/google/pixel-sepolicy/vibrator/cs40l26
diff --git a/vibrator/cs40l26/fuzzer/Android.bp b/vibrator/cs40l26/fuzzer/Android.bp
deleted file mode 100644
index c60c8bf9..00000000
--- a/vibrator/cs40l26/fuzzer/Android.bp
+++ /dev/null
@@ -1,39 +0,0 @@
-//
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_team: "trendy_team_pixel_system_sw_touch_haptic",
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_fuzz {
-    name: "VibratorHalCs40l26Fuzzer",
-    relative_install_path: "",
-    defaults: [
-        "VibratorHalCs40l26BinaryDefaults",
-        "VibratorCapoDefaults",
-        "service_fuzzer_defaults",
-    ],
-    srcs: [
-        "fuzzer-vibrator.cpp",
-    ],
-    shared_libs: [
-        "android.hardware.vibrator-impl.cs40l26",
-    ],
-    fuzz_config: {
-        triage_assignee: "pixel-haptics-triage@google.com",
-        componentid: 716924,
-    },
-}
diff --git a/vibrator/cs40l26/fuzzer/fuzzer-vibrator.cpp b/vibrator/cs40l26/fuzzer/fuzzer-vibrator.cpp
deleted file mode 100644
index 7fad1370..00000000
--- a/vibrator/cs40l26/fuzzer/fuzzer-vibrator.cpp
+++ /dev/null
@@ -1,55 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#include <fuzzbinder/libbinder_ndk_driver.h>
-#include <fuzzer/FuzzedDataProvider.h>
-
-#include "Hardware.h"
-#include "Vibrator.h"
-
-using ::aidl::android::hardware::vibrator::HwApi;
-using ::aidl::android::hardware::vibrator::HwCal;
-using ::aidl::android::hardware::vibrator::Vibrator;
-using android::fuzzService;
-using ndk::SharedRefBase;
-
-// No stats collection.
-class FakeStatsApi : public Vibrator::StatsApi {
-  public:
-    FakeStatsApi() = default;
-    ~FakeStatsApi() = default;
-
-    bool logPrimitive(uint16_t) override { return true; }
-
-    bool logWaveform(uint16_t, int32_t) override { return true; }
-
-    bool logError(uint16_t) override { return true; }
-
-    bool logLatencyStart(uint16_t) override { return true; }
-
-    bool logLatencyEnd() { return true; }
-
-    void debug(int32_t) override {}
-};
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
-    auto vibService = ndk::SharedRefBase::make<Vibrator>(
-            std::make_unique<HwApi>(), std::make_unique<HwCal>(), std::make_unique<FakeStatsApi>());
-
-    fuzzService(vibService->asBinder().get(), FuzzedDataProvider(data, size));
-
-    return 0;
-}
diff --git a/vibrator/cs40l26/service.cpp b/vibrator/cs40l26/service.cpp
deleted file mode 100644
index 2068b6da..00000000
--- a/vibrator/cs40l26/service.cpp
+++ /dev/null
@@ -1,46 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#include <android/binder_manager.h>
-#include <android/binder_process.h>
-#include <log/log.h>
-
-#include "Hardware.h"
-#include "Stats.h"
-#include "Vibrator.h"
-
-using ::aidl::android::hardware::vibrator::HwApi;
-using ::aidl::android::hardware::vibrator::HwCal;
-using ::aidl::android::hardware::vibrator::StatsApi;
-using ::aidl::android::hardware::vibrator::Vibrator;
-
-#if !defined(VIBRATOR_NAME)
-#define VIBRATOR_NAME "default"
-#endif
-
-int main() {
-    auto svc = ndk::SharedRefBase::make<Vibrator>(
-            std::make_unique<HwApi>(), std::make_unique<HwCal>(), std::make_unique<StatsApi>());
-    const auto svcName = std::string() + svc->descriptor + "/" + VIBRATOR_NAME;
-
-    auto svcBinder = svc->asBinder();
-    binder_status_t status = AServiceManager_addService(svcBinder.get(), svcName.c_str());
-    LOG_ALWAYS_FATAL_IF(status != STATUS_OK);
-
-    ABinderProcess_setThreadPoolMaxThreadCount(0);
-    ABinderProcess_joinThreadPool();
-
-    return EXIT_FAILURE;  // should not reach
-}
diff --git a/vibrator/cs40l26/tests/Android.bp b/vibrator/cs40l26/tests/Android.bp
deleted file mode 100644
index 348c9d5f..00000000
--- a/vibrator/cs40l26/tests/Android.bp
+++ /dev/null
@@ -1,38 +0,0 @@
-//
-// Copyright (C) 2022 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_test {
-    name: "VibratorHalCs40l26TestSuite",
-    defaults: [
-        "VibratorHalCs40l26TestDefaults",
-        "haptics_feature_defaults",
-    ],
-    srcs: [
-        "test-hwcal.cpp",
-        "test-hwapi.cpp",
-        "test-vibrator.cpp",
-    ],
-    static_libs: [
-        "libgmock",
-    ],
-    shared_libs: [
-        "libbase",
-        "PixelVibratorFlagsL26",
-    ],
-}
diff --git a/vibrator/cs40l26/tests/mocks.h b/vibrator/cs40l26/tests/mocks.h
deleted file mode 100644
index da8daf45..00000000
--- a/vibrator/cs40l26/tests/mocks.h
+++ /dev/null
@@ -1,108 +0,0 @@
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
-#ifndef ANDROID_HARDWARE_VIBRATOR_TEST_MOCKS_H
-#define ANDROID_HARDWARE_VIBRATOR_TEST_MOCKS_H
-
-#include <aidl/android/hardware/vibrator/BnVibratorCallback.h>
-
-#include "Vibrator.h"
-
-class MockApi : public ::aidl::android::hardware::vibrator::Vibrator::HwApi {
-  public:
-    MOCK_METHOD0(destructor, void());
-    MOCK_METHOD1(setF0, bool(std::string value));
-    MOCK_METHOD1(setF0Offset, bool(uint32_t value));
-    MOCK_METHOD1(setRedc, bool(std::string value));
-    MOCK_METHOD1(setQ, bool(std::string value));
-    MOCK_METHOD1(getEffectCount, bool(uint32_t *value));
-    MOCK_METHOD0(hasEffectBrakingTimeBank, bool());
-    MOCK_METHOD1(setEffectBrakingTimeBank, bool(uint32_t value));
-    MOCK_METHOD1(setEffectBrakingTimeIndex, bool(uint32_t value));
-    MOCK_METHOD1(getEffectBrakingTimeMs, bool(uint32_t *value));
-    MOCK_METHOD2(pollVibeState, bool(uint32_t value, int32_t timeoutMs));
-    MOCK_METHOD0(hasOwtFreeSpace, bool());
-    MOCK_METHOD1(getOwtFreeSpace, bool(uint32_t *value));
-    MOCK_METHOD1(setF0CompEnable, bool(bool value));
-    MOCK_METHOD1(setRedcCompEnable, bool(bool value));
-    MOCK_METHOD1(setMinOnOffInterval, bool(uint32_t value));
-    MOCK_METHOD0(initFF, bool());
-    MOCK_METHOD0(getContextScale, uint32_t());
-    MOCK_METHOD0(getContextEnable, bool());
-    MOCK_METHOD0(getContextSettlingTime, uint32_t());
-    MOCK_METHOD0(getContextCooldownTime, uint32_t());
-    MOCK_METHOD0(getContextFadeEnable, bool());
-    MOCK_METHOD1(setFFGain, bool(uint16_t value));
-    MOCK_METHOD2(setFFEffect, bool(struct ff_effect *effect, uint16_t timeoutMs));
-    MOCK_METHOD2(setFFPlay, bool(int8_t index, bool value));
-    MOCK_METHOD2(getHapticAlsaDevice, bool(int *card, int *device));
-    MOCK_METHOD4(setHapticPcmAmp, bool(struct pcm **haptic_pcm, bool enable, int card, int device));
-    MOCK_METHOD0(isPassthroughI2sHapticSupported, bool());
-    MOCK_METHOD5(uploadOwtEffect,
-                 bool(const uint8_t *owtData, const uint32_t numBytes, struct ff_effect *effect,
-                      uint32_t *outEffectIndex, int *status));
-    MOCK_METHOD2(eraseOwtEffect, bool(int8_t effectIndex, std::vector<ff_effect> *effect));
-    MOCK_METHOD0(isDbcSupported, bool());
-    MOCK_METHOD0(enableDbc, bool());
-    MOCK_METHOD1(debug, void(int fd));
-
-    ~MockApi() override { destructor(); };
-};
-
-class MockCal : public ::aidl::android::hardware::vibrator::Vibrator::HwCal {
-  public:
-    MOCK_METHOD0(destructor, void());
-    MOCK_METHOD1(getVersion, bool(uint32_t *value));
-    MOCK_METHOD1(getF0, bool(std::string &value));
-    MOCK_METHOD1(getRedc, bool(std::string &value));
-    MOCK_METHOD1(getQ, bool(std::string &value));
-    MOCK_METHOD1(getLongFrequencyShift, bool(int32_t *value));
-    MOCK_METHOD1(getTickVolLevels, bool(std::array<uint32_t, 2> *value));
-    MOCK_METHOD1(getClickVolLevels, bool(std::array<uint32_t, 2> *value));
-    MOCK_METHOD1(getLongVolLevels, bool(std::array<uint32_t, 2> *value));
-    MOCK_METHOD0(isChirpEnabled, bool());
-    MOCK_METHOD1(getSupportedPrimitives, bool(uint32_t *value));
-    MOCK_METHOD1(getDeviceMass, bool(float *value));
-    MOCK_METHOD1(getLocCoeff, bool(float *value));
-    MOCK_METHOD0(isF0CompEnabled, bool());
-    MOCK_METHOD0(isRedcCompEnabled, bool());
-    MOCK_METHOD1(debug, void(int fd));
-
-    ~MockCal() override { destructor(); };
-    // b/132668253: Workaround gMock Compilation Issue
-    bool getF0(std::string *value) { return getF0(*value); }
-    bool getRedc(std::string *value) { return getRedc(*value); }
-    bool getQ(std::string *value) { return getQ(*value); }
-};
-
-class MockStats : public ::aidl::android::hardware::vibrator::Vibrator::StatsApi {
-  public:
-    MOCK_METHOD0(destructor, void());
-    MOCK_METHOD1(logPrimitive, bool(uint16_t effectIndex));
-    MOCK_METHOD2(logWaveform, bool(uint16_t effectIndex, int32_t duration));
-    MOCK_METHOD1(logError, bool(uint16_t errorIndex));
-    MOCK_METHOD1(logLatencyStart, bool(uint16_t latencyIndex));
-    MOCK_METHOD0(logLatencyEnd, bool());
-    MOCK_METHOD1(debug, void(int fd));
-
-    ~MockStats() override { destructor(); };
-};
-
-class MockVibratorCallback : public aidl::android::hardware::vibrator::BnVibratorCallback {
-  public:
-    MOCK_METHOD(ndk::ScopedAStatus, onComplete, ());
-};
-
-#endif  // ANDROID_HARDWARE_VIBRATOR_TEST_MOCKS_H
diff --git a/vibrator/cs40l26/tests/test-hwapi.cpp b/vibrator/cs40l26/tests/test-hwapi.cpp
deleted file mode 100644
index cc4d4652..00000000
--- a/vibrator/cs40l26/tests/test-hwapi.cpp
+++ /dev/null
@@ -1,288 +0,0 @@
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
-#include <android-base/file.h>
-#include <cutils/fs.h>
-#include <gtest/gtest.h>
-
-#include <cstdlib>
-#include <fstream>
-
-#include "Hardware.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::testing::Test;
-using ::testing::TestParamInfo;
-using ::testing::ValuesIn;
-using ::testing::WithParamInterface;
-
-class HwApiTest : public Test {
-  private:
-    static constexpr const char *FILE_NAMES[]{
-            "calibration/f0_stored",
-            "default/f0_offset",
-            "calibration/redc_stored",
-            "calibration/q_stored",
-            "default/f0_comp_enable",
-            "default/redc_comp_enable",
-            "default/owt_free_space",
-            "default/num_waves",
-            "default/delay_before_stop_playback_us",
-    };
-
-  public:
-    void SetUp() override {
-        std::string prefix;
-        for (auto n : FILE_NAMES) {
-            auto name = std::filesystem::path(n);
-            auto path = std::filesystem::path(mFilesDir.path) / name;
-            fs_mkdirs(path.c_str(), S_IRWXU);
-            std::ofstream touch{path};
-            mFileMap[name] = path;
-        }
-        prefix = std::filesystem::path(mFilesDir.path) / "";
-        setenv("HWAPI_PATH_PREFIX", prefix.c_str(), true);
-        mHwApi = std::make_unique<HwApi>();
-
-        for (auto n : FILE_NAMES) {
-            auto name = std::filesystem::path(n);
-            auto path = std::filesystem::path(mEmptyDir.path) / name;
-        }
-        prefix = std::filesystem::path(mEmptyDir.path) / "";
-        setenv("HWAPI_PATH_PREFIX", prefix.c_str(), true);
-        mNoApi = std::make_unique<HwApi>();
-    }
-
-    void TearDown() override { verifyContents(); }
-
-    static auto ParamNameFixup(std::string str) {
-        std::replace(str.begin(), str.end(), '/', '_');
-        return str;
-    }
-
-  protected:
-    // Set expected file content for a test.
-    template <typename T>
-    void expectContent(const std::string &name, const T &value) {
-        mExpectedContent[name] << value << std::endl;
-    }
-
-    // Set actual file content for an input test.
-    template <typename T>
-    void updateContent(const std::string &name, const T &value) {
-        std::ofstream(mFileMap[name]) << value << std::endl;
-    }
-
-    template <typename T>
-    void expectAndUpdateContent(const std::string &name, const T &value) {
-        expectContent(name, value);
-        updateContent(name, value);
-    }
-
-    // Compare all file contents against expected contents.
-    void verifyContents() {
-        for (auto &a : mFileMap) {
-            std::ifstream file{a.second};
-            std::string expect = mExpectedContent[a.first].str();
-            std::string actual = std::string(std::istreambuf_iterator<char>(file),
-                                             std::istreambuf_iterator<char>());
-            EXPECT_EQ(expect, actual) << a.first;
-        }
-    }
-
-  protected:
-    std::unique_ptr<Vibrator::HwApi> mHwApi;
-    std::unique_ptr<Vibrator::HwApi> mNoApi;
-    std::map<std::string, std::string> mFileMap;
-    TemporaryDir mFilesDir;
-    TemporaryDir mEmptyDir;
-    std::map<std::string, std::stringstream> mExpectedContent;
-};
-
-template <typename T>
-class HwApiTypedTest : public HwApiTest,
-                       public WithParamInterface<std::tuple<std::string, std::function<T>>> {
-  public:
-    static auto PrintParam(const TestParamInfo<typename HwApiTypedTest::ParamType> &info) {
-        return ParamNameFixup(std::get<0>(info.param));
-    }
-    static auto MakeParam(std::string name, std::function<T> func) {
-        return std::make_tuple(name, func);
-    }
-};
-
-using HasTest = HwApiTypedTest<bool(Vibrator::HwApi &)>;
-
-TEST_P(HasTest, success_returnsTrue) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-
-    EXPECT_TRUE(func(*mHwApi));
-}
-
-TEST_P(HasTest, success_returnsFalse) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-
-    EXPECT_FALSE(func(*mNoApi));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, HasTest,
-                        ValuesIn({
-                                HasTest::MakeParam("default/owt_free_space",
-                                                   &Vibrator::HwApi::hasOwtFreeSpace),
-                        }),
-                        HasTest::PrintParam);
-
-using GetUint32Test = HwApiTypedTest<bool(Vibrator::HwApi &, uint32_t *)>;
-
-TEST_P(GetUint32Test, success) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    expectAndUpdateContent(name, expect);
-
-    EXPECT_TRUE(func(*mHwApi, &actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_P(GetUint32Test, failure) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-    uint32_t value;
-
-    EXPECT_FALSE(func(*mNoApi, &value));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, GetUint32Test,
-                        ValuesIn({
-                                GetUint32Test::MakeParam("default/num_waves",
-                                                         &Vibrator::HwApi::getEffectCount),
-                                GetUint32Test::MakeParam("default/owt_free_space",
-                                                         &Vibrator::HwApi::getOwtFreeSpace),
-                        }),
-                        GetUint32Test::PrintParam);
-
-using SetBoolTest = HwApiTypedTest<bool(Vibrator::HwApi &, bool)>;
-
-TEST_P(SetBoolTest, success_returnsTrue) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-
-    expectContent(name, "1");
-
-    EXPECT_TRUE(func(*mHwApi, true));
-}
-
-TEST_P(SetBoolTest, success_returnsFalse) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-
-    expectContent(name, "0");
-
-    EXPECT_TRUE(func(*mHwApi, false));
-}
-
-TEST_P(SetBoolTest, failure) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-
-    EXPECT_FALSE(func(*mNoApi, true));
-    EXPECT_FALSE(func(*mNoApi, false));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, SetBoolTest,
-                        ValuesIn({
-                                SetBoolTest::MakeParam("default/f0_comp_enable",
-                                                       &Vibrator::HwApi::setF0CompEnable),
-                                SetBoolTest::MakeParam("default/redc_comp_enable",
-                                                       &Vibrator::HwApi::setRedcCompEnable),
-                        }),
-                        SetBoolTest::PrintParam);
-
-using SetUint32Test = HwApiTypedTest<bool(Vibrator::HwApi &, uint32_t)>;
-
-TEST_P(SetUint32Test, success) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    uint32_t value = std::rand();
-
-    expectContent(name, value);
-
-    EXPECT_TRUE(func(*mHwApi, value));
-}
-
-TEST_P(SetUint32Test, failure) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-    uint32_t value = std::rand();
-
-    EXPECT_FALSE(func(*mNoApi, value));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, SetUint32Test,
-                        ValuesIn({
-                                SetUint32Test::MakeParam("default/f0_offset",
-                                                         &Vibrator::HwApi::setF0Offset),
-                                SetUint32Test::MakeParam("default/delay_before_stop_playback_us",
-                                                         &Vibrator::HwApi::setMinOnOffInterval),
-                        }),
-                        SetUint32Test::PrintParam);
-
-using SetStringTest = HwApiTypedTest<bool(Vibrator::HwApi &, std::string)>;
-
-TEST_P(SetStringTest, success) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    std::string value = TemporaryFile().path;
-
-    expectContent(name, value);
-
-    EXPECT_TRUE(func(*mHwApi, value));
-}
-
-TEST_P(SetStringTest, failure) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-    std::string value = TemporaryFile().path;
-
-    EXPECT_FALSE(func(*mNoApi, value));
-}
-
-INSTANTIATE_TEST_CASE_P(
-        HwApiTests, SetStringTest,
-        ValuesIn({
-                SetStringTest::MakeParam("calibration/f0_stored", &Vibrator::HwApi::setF0),
-                SetStringTest::MakeParam("calibration/redc_stored", &Vibrator::HwApi::setRedc),
-                SetStringTest::MakeParam("calibration/q_stored", &Vibrator::HwApi::setQ),
-        }),
-        SetStringTest::PrintParam);
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/tests/test-hwcal.cpp b/vibrator/cs40l26/tests/test-hwcal.cpp
deleted file mode 100644
index 5223c852..00000000
--- a/vibrator/cs40l26/tests/test-hwcal.cpp
+++ /dev/null
@@ -1,386 +0,0 @@
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
-#include <android-base/file.h>
-#include <gtest/gtest.h>
-
-#include <fstream>
-
-#include "Hardware.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::testing::Test;
-
-class HwCalTest : public Test {
-  protected:
-    static constexpr std::array<uint32_t, 2> V_TICK_DEFAULT = {5, 95};
-    static constexpr std::array<uint32_t, 2> V_CLICK_DEFAULT = {5, 95};
-    static constexpr std::array<uint32_t, 2> V_LONG_DEFAULT = {5, 95};
-
-  public:
-    void SetUp() override { setenv("CALIBRATION_FILEPATH", mCalFile.path, true); }
-
-  private:
-    template <typename T>
-    static void pack(std::ostream &stream, const T &value, std::string lpad, std::string rpad) {
-        stream << lpad << value << rpad;
-    }
-
-    template <typename T, typename std::array<T, 0>::size_type N>
-    static void pack(std::ostream &stream, const std::array<T, N> &value, std::string lpad,
-                     std::string rpad) {
-        for (auto &entry : value) {
-            pack(stream, entry, lpad, rpad);
-        }
-    }
-
-  protected:
-    void createHwCal() { mHwCal = std::make_unique<HwCal>(); }
-
-    template <typename T>
-    void write(const std::string key, const T &value, std::string lpad = " ",
-               std::string rpad = "") {
-        std::ofstream calfile{mCalFile.path, std::ios_base::app};
-        calfile << key << ":";
-        pack(calfile, value, lpad, rpad);
-        calfile << std::endl;
-    }
-
-    void unlink() { ::unlink(mCalFile.path); }
-
-  protected:
-    std::unique_ptr<Vibrator::HwCal> mHwCal;
-    TemporaryFile mCalFile;
-};
-
-TEST_F(HwCalTest, f0_measured) {
-    uint32_t randInput = std::rand();
-    std::string expect = std::to_string(randInput);
-    std::string actual = std::to_string(~randInput);
-
-    write("f0_measured", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getF0(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, f0_missing) {
-    std::string actual;
-
-    createHwCal();
-
-    EXPECT_FALSE(mHwCal->getF0(&actual));
-}
-
-TEST_F(HwCalTest, redc_measured) {
-    uint32_t randInput = std::rand();
-    std::string expect = std::to_string(randInput);
-    std::string actual = std::to_string(~randInput);
-
-    write("redc_measured", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getRedc(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, redc_missing) {
-    std::string actual;
-
-    createHwCal();
-
-    EXPECT_FALSE(mHwCal->getRedc(&actual));
-}
-
-TEST_F(HwCalTest, q_measured) {
-    uint32_t randInput = std::rand();
-    std::string expect = std::to_string(randInput);
-    std::string actual = std::to_string(~randInput);
-
-    write("q_measured", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getQ(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, q_missing) {
-    std::string actual;
-
-    createHwCal();
-
-    EXPECT_FALSE(mHwCal->getQ(&actual));
-}
-
-TEST_F(HwCalTest, v_levels) {
-    std::array<uint32_t, 2> expect;
-    std::array<uint32_t, 2> actual;
-
-    // voltage for tick effects
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) {
-        e = std::rand();
-        return ~e;
-    });
-
-    write("v_tick", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getTickVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-
-    // voltage for click effects
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) {
-        e = std::rand();
-        return ~e;
-    });
-
-    write("v_click", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getClickVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-
-    // voltage for long effects
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) {
-        e = std::rand();
-        return ~e;
-    });
-
-    write("v_long", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getLongVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, v_missing) {
-    std::array<uint32_t, 2> expect = V_TICK_DEFAULT;
-    std::array<uint32_t, 2> actual;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) { return ~e; });
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getTickVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-
-    expect = V_CLICK_DEFAULT;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) { return ~e; });
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getClickVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-
-    expect = V_LONG_DEFAULT;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) { return ~e; });
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getLongVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, v_short) {
-    std::array<uint32_t, 2> expect = V_TICK_DEFAULT;
-    std::array<uint32_t, 2> actual;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) { return ~e; });
-
-    write("v_tick", std::array<uint32_t, expect.size() - 1>());
-    write("v_click", std::array<uint32_t, expect.size() - 1>());
-    write("v_long", std::array<uint32_t, expect.size() - 1>());
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getTickVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-
-    expect = V_CLICK_DEFAULT;
-    EXPECT_TRUE(mHwCal->getClickVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-
-    expect = V_LONG_DEFAULT;
-    EXPECT_TRUE(mHwCal->getLongVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, v_long) {
-    std::array<uint32_t, 2> expect = V_TICK_DEFAULT;
-    std::array<uint32_t, 2> actual;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) { return ~e; });
-
-    write("v_tick", std::array<uint32_t, expect.size() + 1>());
-    write("v_click", std::array<uint32_t, expect.size() + 1>());
-    write("v_long", std::array<uint32_t, expect.size() + 1>());
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getTickVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-
-    expect = V_CLICK_DEFAULT;
-    EXPECT_TRUE(mHwCal->getClickVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-
-    expect = V_LONG_DEFAULT;
-    EXPECT_TRUE(mHwCal->getLongVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, v_nofile) {
-    std::array<uint32_t, 2> expect = V_TICK_DEFAULT;
-    std::array<uint32_t, 2> actual;
-
-    std::transform(expect.begin(), expect.end(), actual.begin(), [](uint32_t &e) { return ~e; });
-
-    write("v_tick", actual);
-    write("v_click", actual);
-    write("v_long", actual);
-    unlink();
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getTickVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-
-    expect = V_CLICK_DEFAULT;
-    EXPECT_TRUE(mHwCal->getClickVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-
-    expect = V_LONG_DEFAULT;
-    EXPECT_TRUE(mHwCal->getLongVolLevels(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, multiple) {
-    uint32_t randInput = std::rand();
-    std::string f0Expect = std::to_string(randInput);
-    std::string f0Actual = std::to_string(~randInput);
-    randInput = std::rand();
-    std::string redcExpect = std::to_string(randInput);
-    std::string redcActual = std::to_string(~randInput);
-    randInput = std::rand();
-    std::string qExpect = std::to_string(randInput);
-    std::string qActual = std::to_string(~randInput);
-    std::array<uint32_t, 2> volTickExpect, volClickExpect, volLongExpect;
-    std::array<uint32_t, 2> volActual;
-
-    std::transform(volTickExpect.begin(), volTickExpect.end(), volActual.begin(), [](uint32_t &e) {
-        e = std::rand();
-        return ~e;
-    });
-
-    write("f0_measured", f0Expect);
-    write("redc_measured", redcExpect);
-    write("q_measured", qExpect);
-    write("v_tick", volTickExpect);
-    std::transform(volClickExpect.begin(), volClickExpect.end(), volActual.begin(),
-                   [](uint32_t &e) {
-                       e = std::rand();
-                       return ~e;
-                   });
-    write("v_click", volClickExpect);
-    std::transform(volLongExpect.begin(), volLongExpect.end(), volActual.begin(), [](uint32_t &e) {
-        e = std::rand();
-        return ~e;
-    });
-    write("v_long", volLongExpect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getF0(&f0Actual));
-    EXPECT_EQ(f0Expect, f0Actual);
-    EXPECT_TRUE(mHwCal->getRedc(&redcActual));
-    EXPECT_EQ(redcExpect, redcActual);
-    EXPECT_TRUE(mHwCal->getQ(&qActual));
-    EXPECT_EQ(qExpect, qActual);
-    EXPECT_TRUE(mHwCal->getTickVolLevels(&volActual));
-    EXPECT_EQ(volTickExpect, volActual);
-    EXPECT_TRUE(mHwCal->getClickVolLevels(&volActual));
-    EXPECT_EQ(volClickExpect, volActual);
-    EXPECT_TRUE(mHwCal->getLongVolLevels(&volActual));
-    EXPECT_EQ(volLongExpect, volActual);
-}
-
-TEST_F(HwCalTest, trimming) {
-    uint32_t randInput = std::rand();
-    std::string f0Expect = std::to_string(randInput);
-    std::string f0Actual = std::to_string(~randInput);
-    randInput = std::rand();
-    std::string redcExpect = std::to_string(randInput);
-    std::string redcActual = std::to_string(randInput);
-    randInput = std::rand();
-    std::string qExpect = std::to_string(randInput);
-    std::string qActual = std::to_string(randInput);
-    std::array<uint32_t, 2> volTickExpect, volClickExpect, volLongExpect;
-    std::array<uint32_t, 2> volActual;
-
-    std::transform(volTickExpect.begin(), volTickExpect.end(), volActual.begin(), [](uint32_t &e) {
-        e = std::rand();
-        return ~e;
-    });
-
-    write("f0_measured", f0Expect, " \t", "\t ");
-    write("redc_measured", redcExpect, " \t", "\t ");
-    write("q_measured", qExpect, " \t", "\t ");
-    write("v_tick", volTickExpect, " \t", "\t ");
-    std::transform(volClickExpect.begin(), volClickExpect.end(), volActual.begin(),
-                   [](uint32_t &e) {
-                       e = std::rand();
-                       return ~e;
-                   });
-    write("v_click", volClickExpect, " \t", "\t ");
-    std::transform(volLongExpect.begin(), volLongExpect.end(), volActual.begin(), [](uint32_t &e) {
-        e = std::rand();
-        return ~e;
-    });
-    write("v_long", volLongExpect, " \t", "\t ");
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getF0(&f0Actual));
-    EXPECT_EQ(f0Expect, f0Actual);
-    EXPECT_TRUE(mHwCal->getRedc(&redcActual));
-    EXPECT_EQ(redcExpect, redcActual);
-    EXPECT_TRUE(mHwCal->getQ(&qActual));
-    EXPECT_EQ(qExpect, qActual);
-    EXPECT_TRUE(mHwCal->getTickVolLevels(&volActual));
-    EXPECT_EQ(volTickExpect, volActual);
-    EXPECT_TRUE(mHwCal->getClickVolLevels(&volActual));
-    EXPECT_EQ(volClickExpect, volActual);
-    EXPECT_TRUE(mHwCal->getLongVolLevels(&volActual));
-    EXPECT_EQ(volLongExpect, volActual);
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/tests/test-vibrator.cpp b/vibrator/cs40l26/tests/test-vibrator.cpp
deleted file mode 100644
index 76cb897a..00000000
--- a/vibrator/cs40l26/tests/test-vibrator.cpp
+++ /dev/null
@@ -1,747 +0,0 @@
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
-#include <aidl/android/hardware/vibrator/BnVibratorCallback.h>
-#include <android-base/logging.h>
-#include <gmock/gmock.h>
-#include <gtest/gtest.h>
-#include <linux/input.h>
-#include <linux/uinput.h>
-
-#include <future>
-
-#include "Stats.h"
-#include "Vibrator.h"
-#include "mocks.h"
-#include "types.h"
-#include "utils.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::testing::_;
-using ::testing::AnyNumber;
-using ::testing::Assign;
-using ::testing::AtLeast;
-using ::testing::AtMost;
-using ::testing::Combine;
-using ::testing::DoAll;
-using ::testing::DoDefault;
-using ::testing::Exactly;
-using ::testing::Expectation;
-using ::testing::ExpectationSet;
-using ::testing::Ge;
-using ::testing::Mock;
-using ::testing::MockFunction;
-using ::testing::Range;
-using ::testing::Return;
-using ::testing::Sequence;
-using ::testing::SetArgPointee;
-using ::testing::SetArgReferee;
-using ::testing::Test;
-using ::testing::TestParamInfo;
-using ::testing::ValuesIn;
-using ::testing::WithParamInterface;
-
-// Forward Declarations
-
-static EffectQueue Queue(const QueueEffect &effect);
-static EffectQueue Queue(const QueueDelay &delay);
-template <typename T, typename U, typename... Args>
-static EffectQueue Queue(const T &first, const U &second, Args... rest);
-
-static EffectLevel Level(float intensity, float levelLow, float levelHigh);
-static EffectScale Scale(float intensity, float levelLow, float levelHigh);
-
-// Constants With Arbitrary Values
-
-static constexpr uint32_t CAL_VERSION = 2;
-static constexpr std::array<EffectLevel, 2> V_TICK_DEFAULT = {1, 100};
-static constexpr std::array<EffectLevel, 2> V_CLICK_DEFAULT{1, 100};
-static constexpr std::array<EffectLevel, 2> V_LONG_DEFAULT{1, 100};
-static constexpr std::array<EffectDuration, 14> EFFECT_DURATIONS{
-#if defined(UNSPECIFIED_ACTUATOR)
-        /* For Z-LRA actuators */
-        1000, 100, 25, 1000, 247, 166, 150, 500, 100, 6, 17, 1000, 13, 5};
-#elif defined(LEGACY_ZLRA_ACTUATOR)
-        1000, 100, 25, 1000, 150, 100, 150, 500, 100, 6, 25, 1000, 13, 5};
-#else
-        1000, 100, 9, 1000, 300, 133, 150, 500, 100, 5, 12, 1000, 13, 5};
-#endif
-
-// Constants With Prescribed Values
-
-static const std::map<Effect, EffectIndex> EFFECT_INDEX{
-        {Effect::CLICK, 2},
-        {Effect::TICK, 2},
-        {Effect::HEAVY_CLICK, 2},
-        {Effect::TEXTURE_TICK, 9},
-};
-static constexpr uint32_t MIN_ON_OFF_INTERVAL_US = 8500;
-static constexpr uint8_t VOLTAGE_SCALE_MAX = 100;
-static constexpr int8_t MAX_COLD_START_LATENCY_MS = 6;  // I2C Transaction + DSP Return-From-Standby
-static constexpr auto POLLING_TIMEOUT = 50;  // POLLING_TIMEOUT < ASYNC_COMPLETION_TIMEOUT
-enum WaveformIndex : uint16_t {
-    /* Physical waveform */
-    WAVEFORM_LONG_VIBRATION_EFFECT_INDEX = 0,
-    WAVEFORM_RESERVED_INDEX_1 = 1,
-    WAVEFORM_CLICK_INDEX = 2,
-    WAVEFORM_SHORT_VIBRATION_EFFECT_INDEX = 3,
-    WAVEFORM_THUD_INDEX = 4,
-    WAVEFORM_SPIN_INDEX = 5,
-    WAVEFORM_QUICK_RISE_INDEX = 6,
-    WAVEFORM_SLOW_RISE_INDEX = 7,
-    WAVEFORM_QUICK_FALL_INDEX = 8,
-    WAVEFORM_LIGHT_TICK_INDEX = 9,
-    WAVEFORM_LOW_TICK_INDEX = 10,
-    WAVEFORM_RESERVED_MFG_1,
-    WAVEFORM_RESERVED_MFG_2,
-    WAVEFORM_RESERVED_MFG_3,
-    WAVEFORM_MAX_PHYSICAL_INDEX,
-    /* OWT waveform */
-    WAVEFORM_COMPOSE = WAVEFORM_MAX_PHYSICAL_INDEX,
-    WAVEFORM_PWLE,
-    /*
-     * Refer to <linux/input.h>, the WAVEFORM_MAX_INDEX must not exceed 96.
-     * #define FF_GAIN          0x60  // 96 in decimal
-     * #define FF_MAX_EFFECTS   FF_GAIN
-     */
-    WAVEFORM_MAX_INDEX,
-};
-
-static const EffectScale ON_GLOBAL_SCALE{levelToScale(V_LONG_DEFAULT[1])};
-static const EffectIndex ON_EFFECT_INDEX{0};
-
-static const std::map<EffectTuple, EffectScale> EFFECT_SCALE{
-        {{Effect::TICK, EffectStrength::LIGHT},
-         Scale(0.5f * 0.5f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-        {{Effect::TICK, EffectStrength::MEDIUM},
-         Scale(0.5f * 0.7f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-        {{Effect::TICK, EffectStrength::STRONG},
-         Scale(0.5f * 1.0f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-        {{Effect::CLICK, EffectStrength::LIGHT},
-         Scale(0.7f * 0.5f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-        {{Effect::CLICK, EffectStrength::MEDIUM},
-         Scale(0.7f * 0.7f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-        {{Effect::CLICK, EffectStrength::STRONG},
-         Scale(0.7f * 1.0f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-        {{Effect::HEAVY_CLICK, EffectStrength::LIGHT},
-         Scale(1.0f * 0.5f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-        {{Effect::HEAVY_CLICK, EffectStrength::MEDIUM},
-         Scale(1.0f * 0.7f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-        {{Effect::HEAVY_CLICK, EffectStrength::STRONG},
-         Scale(1.0f * 1.0f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-        {{Effect::TEXTURE_TICK, EffectStrength::LIGHT},
-         Scale(0.5f * 0.5f, V_TICK_DEFAULT[0], V_TICK_DEFAULT[1])},
-        {{Effect::TEXTURE_TICK, EffectStrength::MEDIUM},
-         Scale(0.5f * 0.7f, V_TICK_DEFAULT[0], V_TICK_DEFAULT[1])},
-        {{Effect::TEXTURE_TICK, EffectStrength::STRONG},
-         Scale(0.5f * 1.0f, V_TICK_DEFAULT[0], V_TICK_DEFAULT[1])},
-};
-
-static const std::map<EffectTuple, EffectQueue> EFFECT_QUEUE{
-        {{Effect::DOUBLE_CLICK, EffectStrength::LIGHT},
-         Queue(QueueEffect{EFFECT_INDEX.at(Effect::CLICK),
-                           Level(0.7f * 0.5f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-               100,
-               QueueEffect{EFFECT_INDEX.at(Effect::CLICK),
-                           Level(1.0f * 0.5f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])})},
-        {{Effect::DOUBLE_CLICK, EffectStrength::MEDIUM},
-         Queue(QueueEffect{EFFECT_INDEX.at(Effect::CLICK),
-                           Level(0.7f * 0.7f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-               100,
-               QueueEffect{EFFECT_INDEX.at(Effect::CLICK),
-                           Level(1.0f * 0.7f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])})},
-        {{Effect::DOUBLE_CLICK, EffectStrength::STRONG},
-         Queue(QueueEffect{EFFECT_INDEX.at(Effect::CLICK),
-                           Level(0.7f * 1.0f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])},
-               100,
-               QueueEffect{EFFECT_INDEX.at(Effect::CLICK),
-                           Level(1.0f * 1.0f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])})},
-};
-
-EffectQueue Queue(const QueueEffect &effect) {
-    auto index = std::get<0>(effect);
-    auto level = std::get<1>(effect);
-    auto string = std::to_string(index) + "." + std::to_string(level);
-    auto duration = EFFECT_DURATIONS[index];
-    return {string, duration};
-}
-
-EffectQueue Queue(const QueueDelay &delay) {
-    auto string = std::to_string(delay);
-    return {string, delay};
-}
-
-template <typename T, typename U, typename... Args>
-EffectQueue Queue(const T &first, const U &second, Args... rest) {
-    auto head = Queue(first);
-    auto tail = Queue(second, rest...);
-    auto string = std::get<0>(head) + "," + std::get<0>(tail);
-    auto duration = std::get<1>(head) + std::get<1>(tail);
-    return {string, duration};
-}
-
-static EffectLevel Level(float intensity, float levelLow, float levelHigh) {
-    return std::lround(intensity * (levelHigh - levelLow)) + levelLow;
-}
-
-static EffectScale Scale(float intensity, float levelLow, float levelHigh) {
-    return levelToScale(Level(intensity, levelLow, levelHigh));
-}
-
-class VibratorTest : public Test {
-  public:
-    void SetUp() override {
-        setenv("INPUT_EVENT_NAME", "CS40L26TestSuite", true);
-        std::unique_ptr<MockApi> mockapi;
-        std::unique_ptr<MockCal> mockcal;
-        std::unique_ptr<MockStats> mockstats;
-
-        createMock(&mockapi, &mockcal, &mockstats);
-        createVibrator(std::move(mockapi), std::move(mockcal), std::move(mockstats));
-    }
-
-    void TearDown() override { deleteVibrator(); }
-
-  protected:
-    void createMock(std::unique_ptr<MockApi> *mockapi, std::unique_ptr<MockCal> *mockcal,
-                    std::unique_ptr<MockStats> *mockstats) {
-        *mockapi = std::make_unique<MockApi>();
-        *mockcal = std::make_unique<MockCal>();
-        *mockstats = std::make_unique<MockStats>();
-
-        mMockApi = mockapi->get();
-        mMockCal = mockcal->get();
-        mMockStats = mockstats->get();
-
-        ON_CALL(*mMockApi, destructor()).WillByDefault(Assign(&mMockApi, nullptr));
-
-        ON_CALL(*mMockApi, initFF()).WillByDefault(Return(false));
-        ON_CALL(*mMockApi, setFFGain(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, setFFEffect(_, _)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, setFFPlay(_, _)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, pollVibeState(_, _)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, uploadOwtEffect(_, _, _, _, _)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, eraseOwtEffect(_, _)).WillByDefault(Return(true));
-
-        ON_CALL(*mMockApi, getOwtFreeSpace(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(11504), Return(true)));
-
-        ON_CALL(*mMockCal, destructor()).WillByDefault(Assign(&mMockCal, nullptr));
-
-        ON_CALL(*mMockCal, getVersion(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(CAL_VERSION), Return(true)));
-
-        ON_CALL(*mMockCal, getTickVolLevels(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(V_TICK_DEFAULT), Return(true)));
-        ON_CALL(*mMockCal, getClickVolLevels(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(V_CLICK_DEFAULT), Return(true)));
-        ON_CALL(*mMockCal, getLongVolLevels(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(V_LONG_DEFAULT), Return(true)));
-
-        ON_CALL(*mMockStats, destructor()).WillByDefault(Assign(&mMockStats, nullptr));
-        ON_CALL(*mMockStats, logPrimitive(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockStats, logWaveform(_, _)).WillByDefault(Return(true));
-        ON_CALL(*mMockStats, logLatencyStart(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockStats, logLatencyEnd()).WillByDefault(Return(true));
-
-        relaxMock(false);
-    }
-
-    void createVibrator(std::unique_ptr<MockApi> mockapi, std::unique_ptr<MockCal> mockcal,
-                        std::unique_ptr<MockStats> mockstats, bool relaxed = true) {
-        if (relaxed) {
-            relaxMock(true);
-        }
-        mVibrator = ndk::SharedRefBase::make<Vibrator>(std::move(mockapi), std::move(mockcal),
-                                                       std::move(mockstats));
-        if (relaxed) {
-            relaxMock(false);
-        }
-    }
-
-    void deleteVibrator(bool relaxed = true) {
-        if (relaxed) {
-            relaxMock(true);
-        }
-        mVibrator.reset();
-    }
-
-  private:
-    void relaxMock(bool relax) {
-        auto times = relax ? AnyNumber() : Exactly(0);
-
-        Mock::VerifyAndClearExpectations(mMockApi);
-        Mock::VerifyAndClearExpectations(mMockCal);
-        Mock::VerifyAndClearExpectations(mMockStats);
-
-        EXPECT_CALL(*mMockApi, destructor()).Times(times);
-        EXPECT_CALL(*mMockApi, setF0(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setF0Offset(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setRedc(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setQ(_)).Times(times);
-        EXPECT_CALL(*mMockApi, hasOwtFreeSpace()).Times(times);
-        EXPECT_CALL(*mMockApi, getOwtFreeSpace(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setF0CompEnable(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setRedcCompEnable(_)).Times(times);
-        EXPECT_CALL(*mMockApi, pollVibeState(_, _)).Times(times);
-        EXPECT_CALL(*mMockApi, initFF()).Times(times);
-        EXPECT_CALL(*mMockApi, setFFGain(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setFFEffect(_, _)).Times(times);
-        EXPECT_CALL(*mMockApi, setFFPlay(_, _)).Times(times);
-        EXPECT_CALL(*mMockApi, uploadOwtEffect(_, _, _, _, _)).Times(times);
-        EXPECT_CALL(*mMockApi, eraseOwtEffect(_, _)).Times(times);
-        EXPECT_CALL(*mMockApi, setMinOnOffInterval(_)).Times(times);
-        EXPECT_CALL(*mMockApi, getHapticAlsaDevice(_, _)).Times(times);
-        EXPECT_CALL(*mMockApi, setHapticPcmAmp(_, _, _, _)).Times(times);
-        EXPECT_CALL(*mMockApi, isPassthroughI2sHapticSupported()).Times(times);
-        EXPECT_CALL(*mMockApi, enableDbc()).Times(times);
-
-        EXPECT_CALL(*mMockApi, debug(_)).Times(times);
-
-        EXPECT_CALL(*mMockCal, destructor()).Times(times);
-        EXPECT_CALL(*mMockCal, getF0(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getRedc(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getQ(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getTickVolLevels(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getClickVolLevels(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getLongVolLevels(_)).Times(times);
-        EXPECT_CALL(*mMockCal, isChirpEnabled()).Times(times);
-        EXPECT_CALL(*mMockCal, getLongFrequencyShift(_)).Times(times);
-        EXPECT_CALL(*mMockCal, isF0CompEnabled()).Times(times);
-        EXPECT_CALL(*mMockCal, isRedcCompEnabled()).Times(times);
-        EXPECT_CALL(*mMockCal, debug(_)).Times(times);
-
-        EXPECT_CALL(*mMockStats, destructor()).Times(times);
-        EXPECT_CALL(*mMockStats, logPrimitive(_)).Times(times);
-        EXPECT_CALL(*mMockStats, logWaveform(_, _)).Times(times);
-        EXPECT_CALL(*mMockStats, logLatencyStart(_)).Times(times);
-        EXPECT_CALL(*mMockStats, logLatencyEnd()).Times(times);
-    }
-
-  protected:
-    MockApi *mMockApi;
-    MockCal *mMockCal;
-    MockStats *mMockStats;
-    std::shared_ptr<IVibrator> mVibrator;
-    uint32_t mEffectIndex;
-};
-
-TEST_F(VibratorTest, Constructor) {
-    std::unique_ptr<MockApi> mockapi;
-    std::unique_ptr<MockCal> mockcal;
-    std::unique_ptr<MockStats> mockstats;
-    int min_val = 0xC8000;
-    int max_val = 0x7FC000;
-    std::string f0Val = std::to_string(std::rand() % (max_val - min_val + 1) + min_val);
-    std::string redcVal = std::to_string(std::rand() % (max_val - min_val + 1) + min_val);
-    std::string qVal = std::to_string(std::rand() % (max_val - min_val + 1) + min_val);
-    uint32_t calVer;
-    uint32_t supportedPrimitivesBits = 0x0;
-    Expectation volGet;
-    Sequence f0Seq, redcSeq, qSeq, supportedPrimitivesSeq;
-
-    EXPECT_CALL(*mMockApi, destructor()).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockCal, destructor()).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockStats, destructor()).WillOnce(DoDefault());
-
-    deleteVibrator(false);
-
-    createMock(&mockapi, &mockcal, &mockstats);
-
-    EXPECT_CALL(*mMockCal, getF0(_))
-            .InSequence(f0Seq)
-            .WillOnce(DoAll(SetArgReferee<0>(f0Val), Return(true)));
-    EXPECT_CALL(*mMockApi, setF0(f0Val)).InSequence(f0Seq).WillOnce(Return(true));
-
-    EXPECT_CALL(*mMockCal, getRedc(_))
-            .InSequence(redcSeq)
-            .WillOnce(DoAll(SetArgReferee<0>(redcVal), Return(true)));
-    EXPECT_CALL(*mMockApi, setRedc(redcVal)).InSequence(redcSeq).WillOnce(Return(true));
-
-    EXPECT_CALL(*mMockCal, getQ(_))
-            .InSequence(qSeq)
-            .WillOnce(DoAll(SetArgReferee<0>(qVal), Return(true)));
-    EXPECT_CALL(*mMockApi, setQ(qVal)).InSequence(qSeq).WillOnce(Return(true));
-
-    EXPECT_CALL(*mMockCal, getLongFrequencyShift(_)).WillOnce(Return(true));
-
-    mMockCal->getVersion(&calVer);
-    if (calVer == 2) {
-        volGet = EXPECT_CALL(*mMockCal, getTickVolLevels(_)).WillOnce(DoDefault());
-        volGet = EXPECT_CALL(*mMockCal, getClickVolLevels(_)).WillOnce(DoDefault());
-        volGet = EXPECT_CALL(*mMockCal, getLongVolLevels(_)).WillOnce(DoDefault());
-    }
-
-    EXPECT_CALL(*mMockCal, isF0CompEnabled()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setF0CompEnable(true)).WillOnce(Return(true));
-    EXPECT_CALL(*mMockCal, isRedcCompEnabled()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setRedcCompEnable(true)).WillOnce(Return(true));
-
-    EXPECT_CALL(*mMockApi, isPassthroughI2sHapticSupported()).WillOnce(Return(false));
-    EXPECT_CALL(*mMockCal, isChirpEnabled()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockCal, getSupportedPrimitives(_))
-            .InSequence(supportedPrimitivesSeq)
-            .WillOnce(DoAll(SetArgPointee<0>(supportedPrimitivesBits), Return(true)));
-
-    EXPECT_CALL(*mMockApi, setMinOnOffInterval(MIN_ON_OFF_INTERVAL_US)).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, hasOwtFreeSpace()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setEffectBrakingTimeBank(0)).WillRepeatedly(Return(true));
-    for (uint32_t i = 0; i < WAVEFORM_MAX_PHYSICAL_INDEX; i++) {
-        EXPECT_CALL(*mMockApi, setEffectBrakingTimeIndex(i)).WillRepeatedly(Return(true));
-        EXPECT_CALL(*mMockApi, getEffectBrakingTimeMs(_)).WillRepeatedly(Return(true));
-    }
-    EXPECT_CALL(*mMockApi, getHapticAlsaDevice(_, _)).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, getContextScale()).WillRepeatedly(Return(0));
-    EXPECT_CALL(*mMockApi, getContextEnable()).WillRepeatedly(Return(false));
-    EXPECT_CALL(*mMockApi, getContextSettlingTime()).WillRepeatedly(Return(0));
-    EXPECT_CALL(*mMockApi, getContextCooldownTime()).WillRepeatedly(Return(0));
-    EXPECT_CALL(*mMockApi, getContextFadeEnable()).WillRepeatedly(Return(false));
-    EXPECT_CALL(*mMockApi, enableDbc()).WillOnce(Return(true));
-    createVibrator(std::move(mockapi), std::move(mockcal), std::move(mockstats), false);
-}
-
-TEST_F(VibratorTest, on) {
-    Sequence s1, s2;
-    uint16_t duration = std::rand() + 1;
-
-    EXPECT_CALL(*mMockStats, logLatencyStart(kWaveformEffectLatency))
-            .InSequence(s1, s2)
-            .WillOnce(DoDefault());
-    EXPECT_CALL(*mMockApi, setFFGain(ON_GLOBAL_SCALE)).InSequence(s1).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockStats, logWaveform(_, _)).InSequence(s1).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockApi, setFFEffect(_, duration + MAX_COLD_START_LATENCY_MS))
-            .InSequence(s2)
-            .WillOnce(DoDefault());
-    EXPECT_CALL(*mMockStats, logLatencyEnd()).InSequence(s1, s2).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockApi, setFFPlay(ON_EFFECT_INDEX, true))
-            .InSequence(s1, s2)
-            .WillOnce(DoDefault());
-    EXPECT_TRUE(mVibrator->on(duration, nullptr).isOk());
-}
-
-TEST_F(VibratorTest, off) {
-    Sequence s1;
-    EXPECT_CALL(*mMockApi, setFFGain(ON_GLOBAL_SCALE)).InSequence(s1).WillOnce(DoDefault());
-    EXPECT_TRUE(mVibrator->off().isOk());
-}
-
-TEST_F(VibratorTest, supportsAmplitudeControl_supported) {
-    int32_t capabilities;
-    EXPECT_CALL(*mMockApi, hasOwtFreeSpace()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, getHapticAlsaDevice(_, _)).WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_GT(capabilities & IVibrator::CAP_AMPLITUDE_CONTROL, 0);
-}
-
-TEST_F(VibratorTest, supportsExternalAmplitudeControl_unsupported) {
-    int32_t capabilities;
-    EXPECT_CALL(*mMockApi, hasOwtFreeSpace()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, getHapticAlsaDevice(_, _)).WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_EQ(capabilities & IVibrator::CAP_EXTERNAL_AMPLITUDE_CONTROL, 0);
-}
-
-TEST_F(VibratorTest, setAmplitude_supported) {
-    EffectAmplitude amplitude = static_cast<float>(std::rand()) / RAND_MAX ?: 1.0f;
-
-    EXPECT_CALL(*mMockApi, setFFGain(amplitudeToScale(amplitude))).WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->setAmplitude(amplitude).isOk());
-}
-
-TEST_F(VibratorTest, supportsExternalControl_supported) {
-    int32_t capabilities;
-    EXPECT_CALL(*mMockApi, hasOwtFreeSpace()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, getHapticAlsaDevice(_, _)).WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_GT(capabilities & IVibrator::CAP_EXTERNAL_CONTROL, 0);
-}
-
-TEST_F(VibratorTest, supportsExternalControl_unsupported) {
-    int32_t capabilities;
-    EXPECT_CALL(*mMockApi, hasOwtFreeSpace()).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, getHapticAlsaDevice(_, _)).WillOnce(Return(false));
-
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_EQ(capabilities & IVibrator::CAP_EXTERNAL_CONTROL, 0);
-}
-
-TEST_F(VibratorTest, setExternalControl_enable) {
-    Sequence s1, s2;
-    EXPECT_CALL(*mMockApi, setFFGain(ON_GLOBAL_SCALE)).InSequence(s1).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockApi, getHapticAlsaDevice(_, _)).InSequence(s2).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setHapticPcmAmp(_, true, _, _))
-            .InSequence(s1, s2)
-            .WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->setExternalControl(true).isOk());
-}
-
-TEST_F(VibratorTest, setExternalControl_disable) {
-    Sequence s1, s2, s3, s4;
-
-    // The default mIsUnderExternalControl is false, so it needs to turn on the External Control
-    // to make mIsUnderExternalControl become true.
-    EXPECT_CALL(*mMockApi, setFFGain(ON_GLOBAL_SCALE))
-            .InSequence(s1)
-            .InSequence(s1)
-            .WillOnce(DoDefault());
-    EXPECT_CALL(*mMockApi, getHapticAlsaDevice(_, _)).InSequence(s2).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setHapticPcmAmp(_, true, _, _)).InSequence(s3).WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->setExternalControl(true).isOk());
-
-    EXPECT_CALL(*mMockApi, setFFGain(levelToScale(VOLTAGE_SCALE_MAX)))
-            .InSequence(s4)
-            .WillOnce(DoDefault());
-    EXPECT_CALL(*mMockApi, setHapticPcmAmp(_, false, _, _))
-            .InSequence(s1, s2, s3, s4)
-            .WillOnce(Return(true));
-
-    EXPECT_TRUE(mVibrator->setExternalControl(false).isOk());
-}
-
-class EffectsTest : public VibratorTest, public WithParamInterface<EffectTuple> {
-  public:
-    static auto PrintParam(const TestParamInfo<ParamType> &info) {
-        auto param = info.param;
-        auto effect = std::get<0>(param);
-        auto strength = std::get<1>(param);
-        return toString(effect) + "_" + toString(strength);
-    }
-};
-
-TEST_P(EffectsTest, perform) {
-    auto param = GetParam();
-    auto effect = std::get<0>(param);
-    auto strength = std::get<1>(param);
-    auto scale = EFFECT_SCALE.find(param);
-    auto queue = EFFECT_QUEUE.find(param);
-    EffectDuration duration;
-    auto callback = ndk::SharedRefBase::make<MockVibratorCallback>();
-    std::promise<void> promise;
-    std::future<void> future{promise.get_future()};
-    auto complete = [&promise] {
-        promise.set_value();
-        return ndk::ScopedAStatus::ok();
-    };
-    bool composeEffect;
-
-    ExpectationSet eSetup;
-    Expectation eActivate, ePollHaptics, ePollStop, eEraseDone;
-
-    eSetup +=
-            EXPECT_CALL(*mMockStats, logLatencyStart(kPrebakedEffectLatency)).WillOnce(DoDefault());
-
-    if (scale != EFFECT_SCALE.end()) {
-        EffectIndex index = EFFECT_INDEX.at(effect);
-        duration = EFFECT_DURATIONS[index];
-
-        eSetup += EXPECT_CALL(*mMockApi, setFFGain(levelToScale(scale->second)))
-                          .WillOnce(DoDefault());
-        eSetup += EXPECT_CALL(*mMockStats, logLatencyEnd()).WillOnce(DoDefault());
-        eActivate =
-                EXPECT_CALL(*mMockApi, setFFPlay(index, true)).After(eSetup).WillOnce(DoDefault());
-    } else if (queue != EFFECT_QUEUE.end()) {
-        duration = std::get<1>(queue->second);
-        eSetup += EXPECT_CALL(*mMockApi, setFFGain(ON_GLOBAL_SCALE))
-                          .After(eSetup)
-                          .WillOnce(DoDefault());
-        eSetup += EXPECT_CALL(*mMockApi, getOwtFreeSpace(_)).WillOnce(DoDefault());
-        eSetup += EXPECT_CALL(*mMockApi, uploadOwtEffect(_, _, _, _, _))
-                          .After(eSetup)
-                          .WillOnce(DoDefault());
-        eSetup += EXPECT_CALL(*mMockStats, logLatencyEnd()).After(eSetup).WillOnce(DoDefault());
-        eActivate = EXPECT_CALL(*mMockApi, setFFPlay(WAVEFORM_COMPOSE, true))
-                            .After(eSetup)
-                            .WillOnce(DoDefault());
-        composeEffect = true;
-    } else {
-        duration = 0;
-    }
-
-    if (duration) {
-        ePollHaptics = EXPECT_CALL(*mMockApi, pollVibeState(1, POLLING_TIMEOUT))
-                               .After(eActivate)
-                               .WillOnce(DoDefault());
-        ePollStop = EXPECT_CALL(*mMockApi, pollVibeState(0, -1))
-                            .After(ePollHaptics)
-                            .WillOnce(DoDefault());
-        if (composeEffect) {
-            eEraseDone = EXPECT_CALL(*mMockApi, eraseOwtEffect(_, _))
-                                 .After(ePollStop)
-                                 .WillOnce(DoDefault());
-            EXPECT_CALL(*callback, onComplete()).After(eEraseDone).WillOnce(complete);
-        } else {
-            EXPECT_CALL(*callback, onComplete()).After(ePollStop).WillOnce(complete);
-        }
-    }
-
-    int32_t lengthMs;
-    ndk::ScopedAStatus status = mVibrator->perform(effect, strength, callback, &lengthMs);
-    if (status.isOk()) {
-        EXPECT_LE(duration, lengthMs);
-    } else {
-        EXPECT_EQ(EX_UNSUPPORTED_OPERATION, status.getExceptionCode());
-        EXPECT_EQ(0, lengthMs);
-    }
-
-    if (duration) {
-        EXPECT_EQ(future.wait_for(std::chrono::milliseconds(100)), std::future_status::ready);
-    }
-}
-
-const std::vector<Effect> kEffects{ndk::enum_range<Effect>().begin(),
-                                   ndk::enum_range<Effect>().end()};
-const std::vector<EffectStrength> kEffectStrengths{ndk::enum_range<EffectStrength>().begin(),
-                                                   ndk::enum_range<EffectStrength>().end()};
-
-INSTANTIATE_TEST_CASE_P(VibratorTests, EffectsTest,
-                        Combine(ValuesIn(kEffects.begin(), kEffects.end()),
-                                ValuesIn(kEffectStrengths.begin(), kEffectStrengths.end())),
-                        EffectsTest::PrintParam);
-
-struct PrimitiveParam {
-    CompositePrimitive primitive;
-    EffectIndex index;
-};
-
-class PrimitiveTest : public VibratorTest, public WithParamInterface<PrimitiveParam> {
-  public:
-    static auto PrintParam(const TestParamInfo<ParamType> &info) {
-        return toString(info.param.primitive);
-    }
-};
-
-const std::vector<PrimitiveParam> kPrimitiveParams = {
-        {CompositePrimitive::CLICK, 2},      {CompositePrimitive::THUD, 4},
-        {CompositePrimitive::SPIN, 5},       {CompositePrimitive::QUICK_RISE, 6},
-        {CompositePrimitive::SLOW_RISE, 7},  {CompositePrimitive::QUICK_FALL, 8},
-        {CompositePrimitive::LIGHT_TICK, 9}, {CompositePrimitive::LOW_TICK, 10},
-};
-
-TEST_P(PrimitiveTest, getPrimitiveDuration) {
-    auto param = GetParam();
-    auto primitive = param.primitive;
-    auto index = param.index;
-    int32_t duration;
-
-    EXPECT_EQ(EX_NONE, mVibrator->getPrimitiveDuration(primitive, &duration).getExceptionCode());
-    EXPECT_EQ(EFFECT_DURATIONS[index], duration);
-}
-
-INSTANTIATE_TEST_CASE_P(VibratorTests, PrimitiveTest,
-                        ValuesIn(kPrimitiveParams.begin(), kPrimitiveParams.end()),
-                        PrimitiveTest::PrintParam);
-
-struct ComposeParam {
-    std::string name;
-    std::vector<CompositeEffect> composite;
-    EffectQueue queue;
-};
-
-class ComposeTest : public VibratorTest, public WithParamInterface<ComposeParam> {
-  public:
-    static auto PrintParam(const TestParamInfo<ParamType> &info) { return info.param.name; }
-};
-
-TEST_P(ComposeTest, compose) {
-    auto param = GetParam();
-    auto composite = param.composite;
-    auto queue = std::get<0>(param.queue);
-    ExpectationSet eSetup;
-    Expectation eActivate, ePollHaptics, ePollStop, eEraseDone;
-    auto callback = ndk::SharedRefBase::make<MockVibratorCallback>();
-    std::promise<void> promise;
-    std::future<void> future{promise.get_future()};
-    auto complete = [&promise] {
-        promise.set_value();
-        return ndk::ScopedAStatus::ok();
-    };
-
-    eSetup += EXPECT_CALL(*mMockStats, logLatencyStart(kCompositionEffectLatency))
-                      .WillOnce(DoDefault());
-    for (auto &primitive : composite) {
-        eSetup += EXPECT_CALL(*mMockStats, logPrimitive(_)).After(eSetup).WillOnce(DoDefault());
-    }
-    eSetup +=
-            EXPECT_CALL(*mMockApi, setFFGain(ON_GLOBAL_SCALE)).After(eSetup).WillOnce(DoDefault());
-    eSetup += EXPECT_CALL(*mMockApi, getOwtFreeSpace(_)).WillOnce(DoDefault());
-    eSetup += EXPECT_CALL(*mMockApi, uploadOwtEffect(_, _, _, _, _))
-                      .After(eSetup)
-                      .WillOnce(DoDefault());
-    eSetup += EXPECT_CALL(*mMockStats, logLatencyEnd()).WillOnce(DoDefault());
-    eActivate = EXPECT_CALL(*mMockApi, setFFPlay(WAVEFORM_COMPOSE, true))
-                        .After(eSetup)
-                        .WillOnce(DoDefault());
-
-    ePollHaptics = EXPECT_CALL(*mMockApi, pollVibeState(1, POLLING_TIMEOUT))
-                           .After(eActivate)
-                           .WillOnce(DoDefault());
-    ePollStop =
-            EXPECT_CALL(*mMockApi, pollVibeState(0, -1)).After(ePollHaptics).WillOnce(DoDefault());
-    eEraseDone =
-            EXPECT_CALL(*mMockApi, eraseOwtEffect(_, _)).After(ePollStop).WillOnce(DoDefault());
-    EXPECT_CALL(*callback, onComplete()).After(eEraseDone).WillOnce(complete);
-
-    EXPECT_EQ(EX_NONE, mVibrator->compose(composite, callback).getExceptionCode());
-
-    EXPECT_EQ(future.wait_for(std::chrono::milliseconds(100)), std::future_status::ready);
-}
-
-const std::vector<ComposeParam> kComposeParams = {
-        {"click",
-         {{0, CompositePrimitive::CLICK, 1.0f}},
-         Queue(QueueEffect(2, Level(1.0f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])), 0)},
-        {"thud",
-         {{1, CompositePrimitive::THUD, 0.8f}},
-         Queue(1, QueueEffect(4, Level(0.8f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])), 0)},
-        {"spin",
-         {{2, CompositePrimitive::SPIN, 0.6f}},
-         Queue(2, QueueEffect(5, Level(0.6f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])), 0)},
-        {"quick_rise",
-         {{3, CompositePrimitive::QUICK_RISE, 0.4f}},
-         Queue(3, QueueEffect(6, Level(0.4f, V_LONG_DEFAULT[0], V_LONG_DEFAULT[1])), 0)},
-        {"slow_rise",
-         {{4, CompositePrimitive::SLOW_RISE, 0.0f}},
-         Queue(4, QueueEffect(7, Level(0.0f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])), 0)},
-        {"quick_fall",
-         {{5, CompositePrimitive::QUICK_FALL, 1.0f}},
-         Queue(5, QueueEffect(8, Level(1.0f, V_LONG_DEFAULT[0], V_LONG_DEFAULT[1])), 0)},
-        {"pop",
-         {{6, CompositePrimitive::SLOW_RISE, 1.0f}, {50, CompositePrimitive::THUD, 1.0f}},
-         Queue(6, QueueEffect(7, Level(1.0f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])), 50,
-               QueueEffect(4, Level(1.0f, V_CLICK_DEFAULT[0], V_CLICK_DEFAULT[1])), 0)},
-        {"snap",
-         {{7, CompositePrimitive::QUICK_RISE, 1.0f}, {0, CompositePrimitive::QUICK_FALL, 1.0f}},
-         Queue(7, QueueEffect(6, Level(1.0f, V_LONG_DEFAULT[0], V_LONG_DEFAULT[1])),
-               QueueEffect(8, Level(1.0f, V_LONG_DEFAULT[0], V_LONG_DEFAULT[1])), 0)},
-};
-
-INSTANTIATE_TEST_CASE_P(VibratorTests, ComposeTest,
-                        ValuesIn(kComposeParams.begin(), kComposeParams.end()),
-                        ComposeTest::PrintParam);
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/cs40l26/tests/types.h b/vibrator/cs40l26/tests/types.h
deleted file mode 100644
index e05c648e..00000000
--- a/vibrator/cs40l26/tests/types.h
+++ /dev/null
@@ -1,33 +0,0 @@
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
-#ifndef ANDROID_HARDWARE_VIBRATOR_TEST_TYPES_H
-#define ANDROID_HARDWARE_VIBRATOR_TEST_TYPES_H
-
-#include <aidl/android/hardware/vibrator/IVibrator.h>
-
-using EffectIndex = uint16_t;
-using EffectLevel = uint32_t;
-using EffectAmplitude = float;
-using EffectScale = uint16_t;
-using EffectDuration = uint32_t;
-using EffectQueue = std::tuple<std::string, EffectDuration>;
-using EffectTuple = std::tuple<::aidl::android::hardware::vibrator::Effect,
-                               ::aidl::android::hardware::vibrator::EffectStrength>;
-
-using QueueEffect = std::tuple<EffectIndex, EffectLevel>;
-using QueueDelay = uint32_t;
-
-#endif  // ANDROID_HARDWARE_VIBRATOR_TEST_TYPES_H
diff --git a/vibrator/cs40l26/tests/utils.h b/vibrator/cs40l26/tests/utils.h
deleted file mode 100644
index e7f6055c..00000000
--- a/vibrator/cs40l26/tests/utils.h
+++ /dev/null
@@ -1,46 +0,0 @@
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
-#ifndef ANDROID_HARDWARE_VIBRATOR_TEST_UTILS_H
-#define ANDROID_HARDWARE_VIBRATOR_TEST_UTILS_H
-
-#include <cmath>
-
-#include "types.h"
-
-static inline EffectScale toScale(float amplitude, float maximum) {
-    float ratio = 100; /* Unit: % */
-    if (maximum != 0)
-        ratio = amplitude / maximum * 100;
-
-    if (maximum == 0 || ratio > 100)
-        ratio = 100;
-
-    return std::round(ratio);
-}
-
-static inline EffectScale levelToScale(EffectLevel level) {
-    return toScale(level, 100);
-}
-
-static inline EffectScale amplitudeToScale(EffectAmplitude amplitude) {
-    return toScale(amplitude, 1.0f);
-}
-
-static inline uint32_t msToCycles(EffectDuration ms) {
-    return ms * 48;
-}
-
-#endif  // ANDROID_HARDWARE_VIBRATOR_TEST_UTILS_H
diff --git a/vibrator/drv2624/Android.bp b/vibrator/drv2624/Android.bp
deleted file mode 100644
index 508b82bf..00000000
--- a/vibrator/drv2624/Android.bp
+++ /dev/null
@@ -1,62 +0,0 @@
-//
-// Copyright (C) 2017 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_defaults {
-    name: "android.hardware.vibrator-defaults.drv2624",
-    cflags: [
-        "-DATRACE_TAG=(ATRACE_TAG_VIBRATOR | ATRACE_TAG_HAL)",
-        "-DLOG_TAG=\"Vibrator\"",
-    ],
-}
-
-cc_defaults {
-    name: "VibratorHalDrv2624BinaryDefaults",
-    defaults: [
-        "PixelVibratorBinaryDefaults",
-        "android.hardware.vibrator-defaults.drv2624",
-    ],
-}
-
-cc_defaults {
-    name: "VibratorHalDrv2624TestDefaults",
-    defaults: [
-        "PixelVibratorTestDefaults",
-        "android.hardware.vibrator-defaults.drv2624",
-    ],
-    static_libs: ["android.hardware.vibrator-impl.drv2624"],
-}
-
-cc_library {
-    name: "android.hardware.vibrator-impl.drv2624",
-    defaults: ["VibratorHalDrv2624BinaryDefaults"],
-    srcs: ["Vibrator.cpp"],
-    export_include_dirs: ["."],
-    vendor_available: true,
-    visibility: [":__subpackages__"],
-}
-
-cc_binary {
-    name: "android.hardware.vibrator-service.drv2624",
-    defaults: ["VibratorHalDrv2624BinaryDefaults"],
-    init_rc: ["android.hardware.vibrator-service.drv2624.rc"],
-    vintf_fragments: ["android.hardware.vibrator-service.drv2624.xml"],
-    srcs: ["service.cpp"],
-    static_libs: ["android.hardware.vibrator-impl.drv2624"],
-    proprietary: true,
-}
diff --git a/vibrator/drv2624/Hardware.h b/vibrator/drv2624/Hardware.h
deleted file mode 100644
index 0588e2b0..00000000
--- a/vibrator/drv2624/Hardware.h
+++ /dev/null
@@ -1,149 +0,0 @@
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
-#pragma once
-
-#include "HardwareBase.h"
-#include "Vibrator.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-class HwApi : public Vibrator::HwApi, private HwApiBase {
-  public:
-    static std::unique_ptr<HwApi> Create() {
-        auto hwapi = std::unique_ptr<HwApi>(new HwApi());
-        // the following streams are required
-        if (!hwapi->mActivate.is_open() || !hwapi->mDuration.is_open() ||
-            !hwapi->mState.is_open()) {
-            return nullptr;
-        }
-        return hwapi;
-    }
-
-    bool setAutocal(std::string value) override { return set(value, &mAutocal); }
-    bool setOlLraPeriod(uint32_t value) override { return set(value, &mOlLraPeriod); }
-    bool setActivate(bool value) override { return set(value, &mActivate); }
-    bool setDuration(uint32_t value) override { return set(value, &mDuration); }
-    bool setState(bool value) override { return set(value, &mState); }
-    bool hasRtpInput() override { return has(mRtpInput); }
-    bool setRtpInput(int8_t value) override { return set(value, &mRtpInput); }
-    bool setMode(std::string value) override { return set(value, &mMode); }
-    bool setSequencer(std::string value) override { return set(value, &mSequencer); }
-    bool setScale(uint8_t value) override { return set(value, &mScale); }
-    bool setCtrlLoop(bool value) override { return set(value, &mCtrlLoop); }
-    bool setLpTriggerEffect(uint32_t value) override { return set(value, &mLpTriggerEffect); }
-    bool setLpTriggerScale(uint8_t value) override { return set(value, &mLpTriggerScale); }
-    bool setLraWaveShape(uint32_t value) override { return set(value, &mLraWaveShape); }
-    bool setOdClamp(uint32_t value) override { return set(value, &mOdClamp); }
-    void debug(int fd) override { HwApiBase::debug(fd); }
-
-  private:
-    HwApi() {
-        open("device/autocal", &mAutocal);
-        open("device/ol_lra_period", &mOlLraPeriod);
-        open("activate", &mActivate);
-        open("duration", &mDuration);
-        open("state", &mState);
-        open("device/rtp_input", &mRtpInput);
-        open("device/mode", &mMode);
-        open("device/set_sequencer", &mSequencer);
-        open("device/scale", &mScale);
-        open("device/ctrl_loop", &mCtrlLoop);
-        open("device/lp_trigger_effect", &mLpTriggerEffect);
-        open("device/lp_trigger_scale", &mLpTriggerScale);
-        open("device/lra_wave_shape", &mLraWaveShape);
-        open("device/od_clamp", &mOdClamp);
-    }
-
-  private:
-    std::ofstream mAutocal;
-    std::ofstream mOlLraPeriod;
-    std::ofstream mActivate;
-    std::ofstream mDuration;
-    std::ofstream mState;
-    std::ofstream mRtpInput;
-    std::ofstream mMode;
-    std::ofstream mSequencer;
-    std::ofstream mScale;
-    std::ofstream mCtrlLoop;
-    std::ofstream mLpTriggerEffect;
-    std::ofstream mLpTriggerScale;
-    std::ofstream mLraWaveShape;
-    std::ofstream mOdClamp;
-};
-
-class HwCal : public Vibrator::HwCal, private HwCalBase {
-  private:
-    static constexpr char AUTOCAL_CONFIG[] = "autocal";
-    static constexpr char LRA_PERIOD_CONFIG[] = "lra_period";
-
-    static constexpr uint32_t WAVEFORM_CLICK_EFFECT_MS = 6;
-    static constexpr uint32_t WAVEFORM_TICK_EFFECT_MS = 2;
-    static constexpr uint32_t WAVEFORM_DOUBLE_CLICK_EFFECT_MS = 135;
-    static constexpr uint32_t WAVEFORM_HEAVY_CLICK_EFFECT_MS = 8;
-
-    static constexpr uint32_t DEFAULT_LRA_PERIOD = 262;
-    static constexpr uint32_t DEFAULT_FREQUENCY_SHIFT = 10;
-    static constexpr uint32_t DEFAULT_VOLTAGE_MAX = 107;  // 2.15V;
-
-  public:
-    HwCal() {}
-
-    bool getAutocal(std::string *value) override { return getPersist(AUTOCAL_CONFIG, value); }
-    bool getLraPeriod(uint32_t *value) override {
-        if (getPersist(LRA_PERIOD_CONFIG, value)) {
-            return true;
-        }
-        *value = DEFAULT_LRA_PERIOD;
-        return true;
-    }
-    bool getCloseLoopThreshold(uint32_t *value) override {
-        return getProperty("closeloop.threshold", value, UINT32_MAX);
-        return true;
-    }
-    bool getDynamicConfig(bool *value) override {
-        return getProperty("config.dynamic", value, false);
-    }
-    bool getLongFrequencyShift(uint32_t *value) override {
-        return getProperty("long.frequency.shift", value, DEFAULT_FREQUENCY_SHIFT);
-    }
-    bool getShortVoltageMax(uint32_t *value) override {
-        return getProperty("short.voltage", value, DEFAULT_VOLTAGE_MAX);
-    }
-    bool getLongVoltageMax(uint32_t *value) override {
-        return getProperty("long.voltage", value, DEFAULT_VOLTAGE_MAX);
-    }
-    bool getClickDuration(uint32_t *value) override {
-        return getProperty("click.duration", value, WAVEFORM_CLICK_EFFECT_MS);
-    }
-    bool getTickDuration(uint32_t *value) override {
-        return getProperty("tick.duration", value, WAVEFORM_TICK_EFFECT_MS);
-    }
-    bool getDoubleClickDuration(uint32_t *value) override {
-        return getProperty("double_click.duration", value, WAVEFORM_DOUBLE_CLICK_EFFECT_MS);
-    }
-    bool getHeavyClickDuration(uint32_t *value) override {
-        return getProperty("heavyclick.duration", value, WAVEFORM_HEAVY_CLICK_EFFECT_MS);
-    }
-    void debug(int fd) override { HwCalBase::debug(fd); }
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/drv2624/TEST_MAPPING b/vibrator/drv2624/TEST_MAPPING
deleted file mode 100644
index ec34f66b..00000000
--- a/vibrator/drv2624/TEST_MAPPING
+++ /dev/null
@@ -1,15 +0,0 @@
-{
-  "presubmit": [
-    {
-      "name": "VibratorHalDrv2624TestSuite"
-    }
-  ],
-  "postsubmit": [
-    {
-      "name": "VibratorHalDrv2624Benchmark",
-      "keywords": [
-        "primary-device"
-      ]
-    }
-  ]
-}
diff --git a/vibrator/drv2624/Vibrator.cpp b/vibrator/drv2624/Vibrator.cpp
deleted file mode 100644
index 213fc675..00000000
--- a/vibrator/drv2624/Vibrator.cpp
+++ /dev/null
@@ -1,451 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-
-#include "Vibrator.h"
-#include "utils.h"
-
-#include <cutils/properties.h>
-#include <hardware/hardware.h>
-#include <hardware/vibrator.h>
-#include <log/log.h>
-#include <utils/Trace.h>
-
-#include <cinttypes>
-#include <cmath>
-#include <fstream>
-#include <iostream>
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-static constexpr int8_t MAX_RTP_INPUT = 127;
-static constexpr int8_t MIN_RTP_INPUT = 0;
-
-static constexpr char RTP_MODE[] = "rtp";
-static constexpr char WAVEFORM_MODE[] = "waveform";
-
-// Use effect #1 in the waveform library for CLICK effect
-static constexpr uint8_t WAVEFORM_CLICK_EFFECT_INDEX = 1;
-
-// Use effect #2 in the waveform library for TICK effect
-static constexpr char WAVEFORM_TICK_EFFECT_INDEX = 2;
-
-// Use effect #3 in the waveform library for DOUBLE_CLICK effect
-static constexpr char WAVEFORM_DOUBLE_CLICK_EFFECT_INDEX = 3;
-
-// Use effect #4 in the waveform library for HEAVY_CLICK effect
-static constexpr char WAVEFORM_HEAVY_CLICK_EFFECT_INDEX = 4;
-
-static std::uint32_t freqPeriodFormula(std::uint32_t in) {
-    return 1000000000 / (24615 * in);
-}
-
-static float freqPeriodFormulaFloat(std::uint32_t in) {
-    return static_cast<float>(1000000000) / static_cast<float>(24615 * in);
-}
-
-using utils::toUnderlying;
-
-Vibrator::Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal)
-    : mHwApi(std::move(hwapi)), mHwCal(std::move(hwcal)) {
-    std::string autocal;
-    uint32_t lraPeriod;
-    bool dynamicConfig;
-
-    if (!mHwApi->setState(true)) {
-        ALOGE("Failed to set state (%d): %s", errno, strerror(errno));
-    }
-
-    if (mHwCal->getAutocal(&autocal)) {
-        mHwApi->setAutocal(autocal);
-    }
-    mHwCal->getLraPeriod(&lraPeriod);
-
-    mHwCal->getCloseLoopThreshold(&mCloseLoopThreshold);
-    mHwCal->getDynamicConfig(&dynamicConfig);
-
-    if (dynamicConfig) {
-        uint32_t longFreqencyShift;
-        uint32_t shortVoltageMax, longVoltageMax;
-
-        mHwCal->getLongFrequencyShift(&longFreqencyShift);
-        mHwCal->getShortVoltageMax(&shortVoltageMax);
-        mHwCal->getLongVoltageMax(&longVoltageMax);
-
-        mEffectConfig.reset(new VibrationConfig({
-                .shape = WaveShape::SINE,
-                .odClamp = shortVoltageMax,
-                .olLraPeriod = lraPeriod,
-        }));
-        mSteadyConfig.reset(new VibrationConfig({
-                .shape = WaveShape::SQUARE,
-                .odClamp = longVoltageMax,
-                // 1. Change long lra period to frequency
-                // 2. Get frequency': subtract the frequency shift from the frequency
-                // 3. Get final long lra period after put the frequency' to formula
-                .olLraPeriod = freqPeriodFormula(freqPeriodFormula(lraPeriod) - longFreqencyShift),
-        }));
-    } else {
-        mHwApi->setOlLraPeriod(lraPeriod);
-    }
-
-    mHwCal->getClickDuration(&mClickDuration);
-    mHwCal->getTickDuration(&mTickDuration);
-    mHwCal->getDoubleClickDuration(&mDoubleClickDuration);
-    mHwCal->getHeavyClickDuration(&mHeavyClickDuration);
-}
-
-ndk::ScopedAStatus Vibrator::getCapabilities(int32_t *_aidl_return) {
-    ATRACE_NAME("Vibrator::getCapabilities");
-    int32_t ret = IVibrator::CAP_ALWAYS_ON_CONTROL | IVibrator::CAP_GET_RESONANT_FREQUENCY;
-    if (mHwApi->hasRtpInput()) {
-        ret |= IVibrator::CAP_AMPLITUDE_CONTROL;
-    }
-    *_aidl_return = ret;
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::on(uint32_t timeoutMs, const char mode[],
-                                const std::unique_ptr<VibrationConfig> &config) {
-    LoopControl loopMode = LoopControl::OPEN;
-
-    // Open-loop mode is used for short click for over-drive
-    // Close-loop mode is used for long notification for stability
-    if (mode == RTP_MODE && timeoutMs > mCloseLoopThreshold) {
-        loopMode = LoopControl::CLOSE;
-    }
-
-    mHwApi->setCtrlLoop(toUnderlying(loopMode));
-    if (!mHwApi->setDuration(timeoutMs)) {
-        ALOGE("Failed to set duration (%d): %s", errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    mHwApi->setMode(mode);
-    if (config != nullptr) {
-        mHwApi->setLraWaveShape(toUnderlying(config->shape));
-        mHwApi->setOdClamp(config->odClamp);
-        mHwApi->setOlLraPeriod(config->olLraPeriod);
-    }
-
-    if (!mHwApi->setActivate(1)) {
-        ALOGE("Failed to activate (%d): %s", errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::on(int32_t timeoutMs,
-                                const std::shared_ptr<IVibratorCallback> &callback) {
-    ATRACE_NAME("Vibrator::on");
-    if (callback) {
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-    return on(timeoutMs, RTP_MODE, mSteadyConfig);
-}
-
-ndk::ScopedAStatus Vibrator::off() {
-    ATRACE_NAME("Vibrator::off");
-    if (!mHwApi->setActivate(0)) {
-        ALOGE("Failed to turn vibrator off (%d): %s", errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::setAmplitude(float amplitude) {
-    ATRACE_NAME("Vibrator::setAmplitude");
-    if (amplitude <= 0.0f || amplitude > 1.0f) {
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
-    }
-
-    int32_t rtp_input = std::round(amplitude * (MAX_RTP_INPUT - MIN_RTP_INPUT) + MIN_RTP_INPUT);
-
-    if (!mHwApi->setRtpInput(rtp_input)) {
-        ALOGE("Failed to set amplitude (%d): %s", errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::setExternalControl(bool enabled) {
-    ATRACE_NAME("Vibrator::setExternalControl");
-    ALOGE("Not support in DRV2624 solution, %d", enabled);
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-binder_status_t Vibrator::dump(int fd, const char **args, uint32_t numArgs) {
-    if (fd < 0) {
-        ALOGE("Called debug() with invalid fd.");
-        return STATUS_OK;
-    }
-
-    (void)args;
-    (void)numArgs;
-
-    dprintf(fd, "AIDL:\n");
-
-    dprintf(fd, "  Close Loop Thresh: %" PRIu32 "\n", mCloseLoopThreshold);
-    if (mSteadyConfig) {
-        dprintf(fd, "  Steady Shape: %" PRIu32 "\n", mSteadyConfig->shape);
-        dprintf(fd, "  Steady OD Clamp: %" PRIu32 "\n", mSteadyConfig->odClamp);
-        dprintf(fd, "  Steady OL LRA Period: %" PRIu32 "\n", mSteadyConfig->olLraPeriod);
-    }
-    if (mEffectConfig) {
-        dprintf(fd, "  Effect Shape: %" PRIu32 "\n", mEffectConfig->shape);
-        dprintf(fd, "  Effect OD Clamp: %" PRIu32 "\n", mEffectConfig->odClamp);
-        dprintf(fd, "  Effect OL LRA Period: %" PRIu32 "\n", mEffectConfig->olLraPeriod);
-    }
-    dprintf(fd, "  Click Duration: %" PRIu32 "\n", mClickDuration);
-    dprintf(fd, "  Tick Duration: %" PRIu32 "\n", mTickDuration);
-    dprintf(fd, "  Double Click Duration: %" PRIu32 "\n", mDoubleClickDuration);
-    dprintf(fd, "  Heavy Click Duration: %" PRIu32 "\n", mHeavyClickDuration);
-
-    dprintf(fd, "\n");
-
-    mHwApi->debug(fd);
-
-    dprintf(fd, "\n");
-
-    mHwCal->debug(fd);
-
-    fsync(fd);
-    return STATUS_OK;
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedEffects(std::vector<Effect> *_aidl_return) {
-    *_aidl_return = {Effect::TEXTURE_TICK, Effect::TICK, Effect::CLICK, Effect::HEAVY_CLICK,
-                     Effect::DOUBLE_CLICK};
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::perform(Effect effect, EffectStrength strength,
-                                     const std::shared_ptr<IVibratorCallback> &callback,
-                                     int32_t *_aidl_return) {
-    ATRACE_NAME("Vibrator::perform");
-    ndk::ScopedAStatus status;
-
-    if (callback) {
-        status = ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    } else {
-        status = performEffect(effect, strength, _aidl_return);
-    }
-
-    return status;
-}
-
-static ndk::ScopedAStatus convertEffectStrength(EffectStrength strength, uint8_t *outScale) {
-    uint8_t scale;
-
-    switch (strength) {
-        case EffectStrength::LIGHT:
-            scale = 2;  // 50%
-            break;
-        case EffectStrength::MEDIUM:
-        case EffectStrength::STRONG:
-            scale = 0;  // 100%
-            break;
-        default:
-            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    *outScale = scale;
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getEffectDetails(Effect effect, uint8_t *outIndex,
-                                              uint32_t *outTimeMs) {
-    switch (effect) {
-        case Effect::TEXTURE_TICK:
-            *outIndex = WAVEFORM_TICK_EFFECT_INDEX;
-            *outTimeMs = mTickDuration;
-            break;
-        case Effect::CLICK:
-            *outIndex = WAVEFORM_CLICK_EFFECT_INDEX;
-            *outTimeMs = mClickDuration;
-            break;
-        case Effect::DOUBLE_CLICK:
-            *outIndex = WAVEFORM_DOUBLE_CLICK_EFFECT_INDEX;
-            *outTimeMs = mDoubleClickDuration;
-            break;
-        case Effect::TICK:
-            *outIndex = WAVEFORM_TICK_EFFECT_INDEX;
-            *outTimeMs = mTickDuration;
-            break;
-        case Effect::HEAVY_CLICK:
-            *outIndex = WAVEFORM_HEAVY_CLICK_EFFECT_INDEX;
-            *outTimeMs = mHeavyClickDuration;
-            break;
-        default:
-            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::performEffect(Effect effect, EffectStrength strength,
-                                           int32_t *outTimeMs) {
-    ndk::ScopedAStatus status;
-    uint8_t index;
-    uint32_t timeMS;
-    uint8_t scale;
-
-    status = getEffectDetails(effect, &index, &timeMS);
-    if (!status.isOk()) {
-        return status;
-    }
-
-    status = convertEffectStrength(strength, &scale);
-    if (!status.isOk()) {
-        return status;
-    }
-
-    mHwApi->setSequencer(std::to_string(index) + " 0");
-    mHwApi->setScale(scale);
-    status = on(timeMS, WAVEFORM_MODE, mEffectConfig);
-    if (!status.isOk()) {
-        return status;
-    }
-
-    *outTimeMs = timeMS;
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedAlwaysOnEffects(std::vector<Effect> *_aidl_return) {
-    *_aidl_return = {
-            Effect::CLICK,       Effect::DOUBLE_CLICK, Effect::TICK,
-            Effect::HEAVY_CLICK, Effect::TEXTURE_TICK,
-    };
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::alwaysOnEnable(int32_t id, Effect effect, EffectStrength strength) {
-    if (id != 0) {
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    ndk::ScopedAStatus status;
-    uint8_t index;
-    uint32_t timeMs;
-    uint8_t scale;
-
-    status = getEffectDetails(effect, &index, &timeMs);
-    if (!status.isOk()) {
-        return status;
-    }
-
-    status = convertEffectStrength(strength, &scale);
-    if (!status.isOk()) {
-        return status;
-    }
-
-    if (!mHwApi->setLpTriggerEffect(index)) {
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    if (!mHwApi->setLpTriggerScale(scale)) {
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-
-    return ndk::ScopedAStatus::ok();
-}
-ndk::ScopedAStatus Vibrator::alwaysOnDisable(int32_t id) {
-    if (id != 0) {
-        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-    }
-
-    mHwApi->setLpTriggerEffect(0);
-
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getCompositionDelayMax(int32_t * /*maxDelayMs*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getCompositionSizeMax(int32_t * /*maxSize*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedPrimitives(
-        std::vector<CompositePrimitive> * /*supported*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getPrimitiveDuration(CompositePrimitive /*primitive*/,
-                                                  int32_t * /*durationMs*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::compose(const std::vector<CompositeEffect> & /*composite*/,
-                                     const std::shared_ptr<IVibratorCallback> & /*callback*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getResonantFrequency(float *resonantFreqHz) {
-    uint32_t lraPeriod;
-    if(!mHwCal->getLraPeriod(&lraPeriod)) {
-        ALOGE("Failed to get resonant frequency (%d): %s", errno, strerror(errno));
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-    *resonantFreqHz = freqPeriodFormulaFloat(lraPeriod);
-    return ndk::ScopedAStatus::ok();
-}
-
-ndk::ScopedAStatus Vibrator::getQFactor(float * /*qFactor*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getFrequencyResolution(float * /*freqResolutionHz*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getFrequencyMinimum(float * /*freqMinimumHz*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getBandwidthAmplitudeMap(std::vector<float> * /*_aidl_return*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getPwlePrimitiveDurationMax(int32_t * /*durationMs*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getPwleCompositionSizeMax(int32_t * /*maxSize*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::getSupportedBraking(std::vector<Braking> * /*supported*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-ndk::ScopedAStatus Vibrator::composePwle(const std::vector<PrimitivePwle> & /*composite*/,
-                                         const std::shared_ptr<IVibratorCallback> & /*callback*/) {
-    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/drv2624/Vibrator.h b/vibrator/drv2624/Vibrator.h
deleted file mode 100644
index 5f81ee38..00000000
--- a/vibrator/drv2624/Vibrator.h
+++ /dev/null
@@ -1,191 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-#pragma once
-
-#include <aidl/android/hardware/vibrator/BnVibrator.h>
-
-#include <fstream>
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-class Vibrator : public BnVibrator {
-  public:
-    // APIs for interfacing with the kernel driver.
-    class HwApi {
-      public:
-        virtual ~HwApi() = default;
-        // Stores the COMP, BEMF, and GAIN calibration values to use.
-        //   <COMP> <BEMF> <GAIN>
-        virtual bool setAutocal(std::string value) = 0;
-        // Stores the open-loop LRA frequency to be used.
-        virtual bool setOlLraPeriod(uint32_t value) = 0;
-        // Activates/deactivates the vibrator for durations specified by
-        // setDuration().
-        virtual bool setActivate(bool value) = 0;
-        // Specifies the vibration duration in milliseconds.
-        virtual bool setDuration(uint32_t value) = 0;
-        // Specifies the active state of the vibrator
-        // (true = enabled, false = disabled).
-        virtual bool setState(bool value) = 0;
-        // Reports whether setRtpInput() is supported.
-        virtual bool hasRtpInput() = 0;
-        // Specifies the playback amplitude of the haptic waveforms in RTP mode.
-        // Negative numbers indicates braking.
-        virtual bool setRtpInput(int8_t value) = 0;
-        // Specifies the mode of operation.
-        //   rtp        - RTP Mode
-        //   waveform   - Waveform Sequencer Mode
-        //   diag       - Diagnostics Routine
-        //   autocal    - Automatic Level Calibration Routine
-        virtual bool setMode(std::string value) = 0;
-        // Specifies a waveform sequence in index-count pairs.
-        //   <index-1> <count-1> [<index-2> <cound-2> ...]
-        virtual bool setSequencer(std::string value) = 0;
-        // Specifies the scaling of effects in Waveform mode.
-        //   0 - 100%
-        //   1 - 75%
-        //   2 - 50%
-        //   3 - 25%
-        virtual bool setScale(uint8_t value) = 0;
-        // Selects either closed loop or open loop mode.
-        // (true = open, false = closed).
-        virtual bool setCtrlLoop(bool value) = 0;
-        // Specifies waveform index to be played in low-power trigger mode.
-        //   0  - Disabled
-        //   1+ - Waveform Index
-        virtual bool setLpTriggerEffect(uint32_t value) = 0;
-        // Specifies scale to be used in low-power trigger mode.
-        // See setScale().
-        virtual bool setLpTriggerScale(uint8_t value) = 0;
-        // Specifies which shape to use for driving the LRA when in open loop
-        // mode.
-        //   0 - Square Wave
-        //   1 - Sine Wave
-        virtual bool setLraWaveShape(uint32_t value) = 0;
-        // Specifies the maximum voltage for automatic overdrive and automatic
-        // braking periods.
-        virtual bool setOdClamp(uint32_t value) = 0;
-        // Emit diagnostic information to the given file.
-        virtual void debug(int fd) = 0;
-    };
-
-    // APIs for obtaining calibration/configuration data from persistent memory.
-    class HwCal {
-      public:
-        virtual ~HwCal() = default;
-        // Obtains the COMP, BEMF, and GAIN calibration values to use.
-        virtual bool getAutocal(std::string *value) = 0;
-        // Obtains the open-loop LRA frequency to be used.
-        virtual bool getLraPeriod(uint32_t *value) = 0;
-        // Obtains threshold in ms, above which close-loop should be used.
-        virtual bool getCloseLoopThreshold(uint32_t *value) = 0;
-        // Obtains dynamic/static configuration choice.
-        virtual bool getDynamicConfig(bool *value) = 0;
-        // Obtains LRA frequency shift for long (steady) vibrations.
-        virtual bool getLongFrequencyShift(uint32_t *value) = 0;
-        // Obtains maximum voltage for short (effect) vibrations
-        virtual bool getShortVoltageMax(uint32_t *value) = 0;
-        // Obtains maximum voltage for long (steady) vibrations
-        virtual bool getLongVoltageMax(uint32_t *value) = 0;
-        // Obtains the duration for the click effect
-        virtual bool getClickDuration(uint32_t *value) = 0;
-        // Obtains the duration for the tick effect
-        virtual bool getTickDuration(uint32_t *value) = 0;
-        // Obtains the duration for the double-click effect
-        virtual bool getDoubleClickDuration(uint32_t *value) = 0;
-        // Obtains the duration for the heavy-click effect
-        virtual bool getHeavyClickDuration(uint32_t *value) = 0;
-        // Emit diagnostic information to the given file.
-        virtual void debug(int fd) = 0;
-    };
-
-  private:
-    enum class LoopControl : bool {
-        CLOSE = false,
-        OPEN = true,
-    };
-
-    enum class WaveShape : uint32_t {
-        SQUARE = 0,
-        SINE = 1,
-    };
-
-    struct VibrationConfig {
-        WaveShape shape;
-        uint32_t odClamp;
-        uint32_t olLraPeriod;
-    };
-
-  public:
-    Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal);
-
-    ndk::ScopedAStatus getCapabilities(int32_t *_aidl_return) override;
-    ndk::ScopedAStatus off() override;
-    ndk::ScopedAStatus on(int32_t timeoutMs,
-                          const std::shared_ptr<IVibratorCallback> &callback) override;
-    ndk::ScopedAStatus perform(Effect effect, EffectStrength strength,
-                               const std::shared_ptr<IVibratorCallback> &callback,
-                               int32_t *_aidl_return) override;
-    ndk::ScopedAStatus getSupportedEffects(std::vector<Effect> *_aidl_return) override;
-    ndk::ScopedAStatus setAmplitude(float amplitude) override;
-    ndk::ScopedAStatus setExternalControl(bool enabled) override;
-    ndk::ScopedAStatus getCompositionDelayMax(int32_t *maxDelayMs);
-    ndk::ScopedAStatus getCompositionSizeMax(int32_t *maxSize);
-    ndk::ScopedAStatus getSupportedPrimitives(std::vector<CompositePrimitive> *supported) override;
-    ndk::ScopedAStatus getPrimitiveDuration(CompositePrimitive primitive,
-                                            int32_t *durationMs) override;
-    ndk::ScopedAStatus compose(const std::vector<CompositeEffect> &composite,
-                               const std::shared_ptr<IVibratorCallback> &callback) override;
-    ndk::ScopedAStatus getSupportedAlwaysOnEffects(std::vector<Effect> *_aidl_return) override;
-    ndk::ScopedAStatus alwaysOnEnable(int32_t id, Effect effect, EffectStrength strength) override;
-    ndk::ScopedAStatus alwaysOnDisable(int32_t id) override;
-    ndk::ScopedAStatus getResonantFrequency(float *resonantFreqHz) override;
-    ndk::ScopedAStatus getQFactor(float *qFactor) override;
-    ndk::ScopedAStatus getFrequencyResolution(float *freqResolutionHz) override;
-    ndk::ScopedAStatus getFrequencyMinimum(float *freqMinimumHz) override;
-    ndk::ScopedAStatus getBandwidthAmplitudeMap(std::vector<float> *_aidl_return) override;
-    ndk::ScopedAStatus getPwlePrimitiveDurationMax(int32_t *durationMs) override;
-    ndk::ScopedAStatus getPwleCompositionSizeMax(int32_t *maxSize) override;
-    ndk::ScopedAStatus getSupportedBraking(std::vector<Braking> *supported) override;
-    ndk::ScopedAStatus composePwle(const std::vector<PrimitivePwle> &composite,
-                                   const std::shared_ptr<IVibratorCallback> &callback) override;
-
-    binder_status_t dump(int fd, const char **args, uint32_t numArgs) override;
-
-  private:
-    ndk::ScopedAStatus on(uint32_t timeoutMs, const char mode[],
-                          const std::unique_ptr<VibrationConfig> &config);
-    ndk::ScopedAStatus getEffectDetails(Effect effect, uint8_t *outIndex, uint32_t *outTimeMs);
-    ndk::ScopedAStatus performEffect(Effect effect, EffectStrength strength, int32_t *outTimeMs);
-
-    std::unique_ptr<HwApi> mHwApi;
-    std::unique_ptr<HwCal> mHwCal;
-    uint32_t mCloseLoopThreshold;
-    std::unique_ptr<VibrationConfig> mSteadyConfig;
-    std::unique_ptr<VibrationConfig> mEffectConfig;
-    uint32_t mClickDuration;
-    uint32_t mTickDuration;
-    uint32_t mDoubleClickDuration;
-    uint32_t mHeavyClickDuration;
-};
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/drv2624/android.hardware.vibrator-service.drv2624.rc b/vibrator/drv2624/android.hardware.vibrator-service.drv2624.rc
deleted file mode 100644
index d7ced06a..00000000
--- a/vibrator/drv2624/android.hardware.vibrator-service.drv2624.rc
+++ /dev/null
@@ -1,48 +0,0 @@
-on boot
-    wait /sys/class/leds/vibrator/device
-
-    mkdir /mnt/vendor/persist/haptics 0770 system system
-    chmod 770 /mnt/vendor/persist/haptics
-    chmod 440 /mnt/vendor/persist/haptics/drv2624.cal
-    chown system system /mnt/vendor/persist/haptics
-    chown system system /mnt/vendor/persist/haptics/drv2624.cal
-
-    write /sys/class/leds/vibrator/trigger transient
-    chown system system /sys/class/leds/vibrator/activate
-    chown system system /sys/class/leds/vibrator/brightness
-    chown system system /sys/class/leds/vibrator/duration
-    chown system system /sys/class/leds/vibrator/state
-
-    chown system system /sys/class/leds/vibrator/device/autocal
-    chown system system /sys/class/leds/vibrator/device/autocal_result
-    chown system system /sys/class/leds/vibrator/device/ctrl_loop
-    chown system system /sys/class/leds/vibrator/device/lp_trigger_effect
-    chown system system /sys/class/leds/vibrator/device/lp_trigger_scale
-    chown system system /sys/class/leds/vibrator/device/lra_wave_shape
-    chown system system /sys/class/leds/vibrator/device/mode
-    chown system system /sys/class/leds/vibrator/device/od_clamp
-    chown system system /sys/class/leds/vibrator/device/ol_lra_period
-    chown system system /sys/class/leds/vibrator/device/rtp_input
-    chown system system /sys/class/leds/vibrator/device/scale
-    chown system system /sys/class/leds/vibrator/device/set_sequencer
-
-    enable vendor.vibrator.drv2624
-
-service vendor.vibrator.drv2624 /vendor/bin/hw/android.hardware.vibrator-service.drv2624
-    class hal
-    user system
-    group system
-
-    setenv PROPERTY_PREFIX ro.vendor.vibrator.hal.
-    setenv CALIBRATION_FILEPATH /persist/haptics/drv2624.cal
-
-    setenv HWAPI_PATH_PREFIX /sys/class/leds/vibrator/
-    setenv HWAPI_DEBUG_PATHS "
-        device/autocal
-        device/lp_trigger_effect
-        device/lp_trigger_scale
-        device/ol_lra_period
-        state
-        "
-
-    disabled
diff --git a/vibrator/drv2624/android.hardware.vibrator-service.drv2624.xml b/vibrator/drv2624/android.hardware.vibrator-service.drv2624.xml
deleted file mode 100644
index 4db8f8c5..00000000
--- a/vibrator/drv2624/android.hardware.vibrator-service.drv2624.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<manifest version="1.0" type="device">
-    <hal format="aidl">
-        <name>android.hardware.vibrator</name>
-        <version>2</version>
-        <fqname>IVibrator/default</fqname>
-    </hal>
-</manifest>
diff --git a/vibrator/drv2624/bench/Android.bp b/vibrator/drv2624/bench/Android.bp
deleted file mode 100644
index d7bd3c4c..00000000
--- a/vibrator/drv2624/bench/Android.bp
+++ /dev/null
@@ -1,33 +0,0 @@
-//
-// Copyright (C) 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_benchmark {
-    name: "VibratorHalDrv2624Benchmark",
-    defaults: ["VibratorHalDrv2624TestDefaults"],
-    srcs: [
-        "benchmark.cpp",
-    ],
-    shared_libs: [
-        "libbase",
-    ],
-    // TODO(b/135767253): Remove when fixed.
-    test_suites: ["device-tests"],
-    // TODO(b/142024316): Remove when fixed.
-    require_root: true,
-}
diff --git a/vibrator/drv2624/bench/benchmark.cpp b/vibrator/drv2624/bench/benchmark.cpp
deleted file mode 100644
index 24b67640..00000000
--- a/vibrator/drv2624/bench/benchmark.cpp
+++ /dev/null
@@ -1,189 +0,0 @@
-/* * Copyright (C) 2019 The Android Open Source Project *
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
-#include "benchmark/benchmark.h"
-
-#include <android-base/file.h>
-#include <android-base/properties.h>
-#include <cutils/fs.h>
-
-#include "Hardware.h"
-#include "Vibrator.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::android::base::SetProperty;
-
-class VibratorBench : public benchmark::Fixture {
-  private:
-    static constexpr const char *FILE_NAMES[]{
-            "device/autocal",
-            "device/ol_lra_period",
-            "activate",
-            "duration",
-            "state",
-            "device/rtp_input",
-            "device/mode",
-            "device/set_sequencer",
-            "device/scale",
-            "device/ctrl_loop",
-            "device/lp_trigger_effect",
-            "device/lp_trigger_scale",
-            "device/lra_wave_shape",
-            "device/od_clamp",
-    };
-    static constexpr char PROPERTY_PREFIX[] = "test.vibrator.hal.";
-
-  public:
-    void SetUp(::benchmark::State &state) override {
-        auto prefix = std::filesystem::path(mFilesDir.path) / "";
-
-        setenv("HWAPI_PATH_PREFIX", prefix.c_str(), true);
-
-        for (auto n : FILE_NAMES) {
-            const auto name = std::filesystem::path(n);
-            const auto path = std::filesystem::path(mFilesDir.path) / name;
-
-            fs_mkdirs(path.c_str(), S_IRWXU);
-            symlink("/dev/null", path.c_str());
-        }
-
-        setenv("PROPERTY_PREFIX", PROPERTY_PREFIX, true);
-
-        SetProperty(std::string() + PROPERTY_PREFIX + "config.dynamic", getDynamicConfig(state));
-
-        mVibrator = ndk::SharedRefBase::make<Vibrator>(HwApi::Create(), std::make_unique<HwCal>());
-    }
-
-    static void DefaultConfig(benchmark::internal::Benchmark *b) {
-        b->Unit(benchmark::kMicrosecond);
-    }
-
-    static void DefaultArgs(benchmark::internal::Benchmark *b) {
-        b->ArgNames({"DynamicConfig"});
-        b->Args({false});
-        b->Args({true});
-    }
-
-  protected:
-    std::string getDynamicConfig(const ::benchmark::State &state) const {
-        return std::to_string(state.range(0));
-    }
-
-    auto getOtherArg(const ::benchmark::State &state, std::size_t index) const {
-        return state.range(index + 1);
-    }
-
-  protected:
-    TemporaryDir mFilesDir;
-    std::shared_ptr<IVibrator> mVibrator;
-};
-
-#define BENCHMARK_WRAPPER(fixt, test, code)                           \
-    BENCHMARK_DEFINE_F(fixt, test)                                    \
-    /* NOLINTNEXTLINE */                                              \
-    (benchmark::State & state){code} BENCHMARK_REGISTER_F(fixt, test) \
-            ->Apply(fixt::DefaultConfig)                              \
-            ->Apply(fixt::DefaultArgs)
-
-BENCHMARK_WRAPPER(VibratorBench, on, {
-    uint32_t duration = std::rand() ?: 1;
-
-    for (auto _ : state) {
-        mVibrator->on(duration, nullptr);
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, off, {
-    for (auto _ : state) {
-        mVibrator->off();
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, setAmplitude, {
-    uint8_t amplitude = std::rand() ?: 1;
-
-    for (auto _ : state) {
-        mVibrator->setAmplitude(amplitude);
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, setExternalControl_enable, {
-    for (auto _ : state) {
-        mVibrator->setExternalControl(true);
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, setExternalControl_disable, {
-    for (auto _ : state) {
-        mVibrator->setExternalControl(false);
-    }
-});
-
-BENCHMARK_WRAPPER(VibratorBench, getCapabilities, {
-    int32_t capabilities;
-
-    for (auto _ : state) {
-        mVibrator->getCapabilities(&capabilities);
-    }
-});
-
-class VibratorEffectsBench : public VibratorBench {
-  public:
-    static void DefaultArgs(benchmark::internal::Benchmark *b) {
-        b->ArgNames({"DynamicConfig", "Effect", "Strength"});
-        for (const auto &dynamic : {false, true}) {
-            for (const auto &effect : ndk::enum_range<Effect>()) {
-                for (const auto &strength : ndk::enum_range<EffectStrength>()) {
-                    b->Args({dynamic, static_cast<long>(effect), static_cast<long>(strength)});
-                }
-            }
-        }
-    }
-
-  protected:
-    auto getEffect(const ::benchmark::State &state) const {
-        return static_cast<Effect>(getOtherArg(state, 0));
-    }
-
-    auto getStrength(const ::benchmark::State &state) const {
-        return static_cast<EffectStrength>(getOtherArg(state, 1));
-    }
-};
-
-BENCHMARK_WRAPPER(VibratorEffectsBench, perform, {
-    Effect effect = getEffect(state);
-    EffectStrength strength = getStrength(state);
-    int32_t lengthMs;
-
-    ndk::ScopedAStatus status = mVibrator->perform(effect, strength, nullptr, &lengthMs);
-
-    if (status.getExceptionCode() == EX_UNSUPPORTED_OPERATION) {
-        return;
-    }
-
-    for (auto _ : state) {
-        mVibrator->perform(effect, strength, nullptr, &lengthMs);
-    }
-});
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
-
-BENCHMARK_MAIN();
diff --git a/vibrator/drv2624/device.mk b/vibrator/drv2624/device.mk
deleted file mode 100644
index c2719b5b..00000000
--- a/vibrator/drv2624/device.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-PRODUCT_PACKAGES += \
-    com.android.vibrator.drv2624 \
-
-BOARD_SEPOLICY_DIRS += \
-    hardware/google/pixel-sepolicy/vibrator/common \
-    hardware/google/pixel-sepolicy/vibrator/drv2624 \
diff --git a/vibrator/drv2624/fuzzer/Android.bp b/vibrator/drv2624/fuzzer/Android.bp
deleted file mode 100644
index ae8df095..00000000
--- a/vibrator/drv2624/fuzzer/Android.bp
+++ /dev/null
@@ -1,38 +0,0 @@
-//
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_team: "trendy_team_pixel_system_sw_touch_haptic",
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_fuzz {
-    name: "VibratorHalDrv2624Fuzzer",
-    relative_install_path: "",
-    defaults: [
-        "VibratorHalDrv2624BinaryDefaults",
-        "service_fuzzer_defaults",
-    ],
-    srcs: [
-        "fuzzer-vibrator.cpp",
-    ],
-    shared_libs: [
-        "android.hardware.vibrator-impl.drv2624",
-    ],
-    fuzz_config: {
-        triage_assignee: "pixel-haptics-triage@google.com",
-        componentid: 716924,
-    },
-}
diff --git a/vibrator/drv2624/fuzzer/fuzzer-vibrator.cpp b/vibrator/drv2624/fuzzer/fuzzer-vibrator.cpp
deleted file mode 100644
index d1b400ac..00000000
--- a/vibrator/drv2624/fuzzer/fuzzer-vibrator.cpp
+++ /dev/null
@@ -1,36 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#include <fuzzbinder/libbinder_ndk_driver.h>
-#include <fuzzer/FuzzedDataProvider.h>
-
-#include "Hardware.h"
-#include "Vibrator.h"
-
-using ::aidl::android::hardware::vibrator::HwApi;
-using ::aidl::android::hardware::vibrator::HwCal;
-using ::aidl::android::hardware::vibrator::Vibrator;
-using android::fuzzService;
-using ndk::SharedRefBase;
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
-    std::shared_ptr<Vibrator> vibService =
-            ndk::SharedRefBase::make<Vibrator>(HwApi::Create(), std::make_unique<HwCal>());
-
-    fuzzService(vibService->asBinder().get(), FuzzedDataProvider(data, size));
-
-    return 0;
-}
diff --git a/vibrator/drv2624/service.cpp b/vibrator/drv2624/service.cpp
deleted file mode 100644
index d4287a06..00000000
--- a/vibrator/drv2624/service.cpp
+++ /dev/null
@@ -1,44 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-#include "Hardware.h"
-#include "Vibrator.h"
-
-#include <android/binder_manager.h>
-#include <android/binder_process.h>
-#include <log/log.h>
-
-using aidl::android::hardware::vibrator::HwApi;
-using aidl::android::hardware::vibrator::HwCal;
-using aidl::android::hardware::vibrator::Vibrator;
-
-int main() {
-    auto hwapi = HwApi::Create();
-
-    if (!hwapi) {
-        return EXIT_FAILURE;
-    }
-
-    ABinderProcess_setThreadPoolMaxThreadCount(0);
-    std::shared_ptr<Vibrator> vib =
-            ndk::SharedRefBase::make<Vibrator>(std::move(hwapi), std::make_unique<HwCal>());
-
-    const std::string instance = std::string() + Vibrator::descriptor + "/default";
-    binder_status_t status = AServiceManager_addService(vib->asBinder().get(), instance.c_str());
-    LOG_ALWAYS_FATAL_IF(status != STATUS_OK);
-
-    ABinderProcess_joinThreadPool();
-    return EXIT_FAILURE;  // should not reach
-}
diff --git a/vibrator/drv2624/tests/Android.bp b/vibrator/drv2624/tests/Android.bp
deleted file mode 100644
index 23c868c7..00000000
--- a/vibrator/drv2624/tests/Android.bp
+++ /dev/null
@@ -1,34 +0,0 @@
-//
-// Copyright (C) 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_test {
-    name: "VibratorHalDrv2624TestSuite",
-    defaults: ["VibratorHalDrv2624TestDefaults"],
-    srcs: [
-        "test-hwapi.cpp",
-        "test-hwcal.cpp",
-        "test-vibrator.cpp",
-    ],
-    static_libs: [
-        "libgmock",
-    ],
-    shared_libs: [
-        "libbase",
-    ],
-}
diff --git a/vibrator/drv2624/tests/mocks.h b/vibrator/drv2624/tests/mocks.h
deleted file mode 100644
index b4d06d15..00000000
--- a/vibrator/drv2624/tests/mocks.h
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
-#ifndef ANDROID_HARDWARE_VIBRATOR_TEST_MOCKS_H
-#define ANDROID_HARDWARE_VIBRATOR_TEST_MOCKS_H
-
-#include "Vibrator.h"
-
-class MockApi : public ::aidl::android::hardware::vibrator::Vibrator::HwApi {
-  public:
-    MOCK_METHOD0(destructor, void());
-    MOCK_METHOD1(setAutocal, bool(std::string value));
-    MOCK_METHOD1(setOlLraPeriod, bool(uint32_t value));
-    MOCK_METHOD1(setActivate, bool(bool value));
-    MOCK_METHOD1(setDuration, bool(uint32_t value));
-    MOCK_METHOD1(setState, bool(bool value));
-    MOCK_METHOD0(hasRtpInput, bool());
-    MOCK_METHOD1(setRtpInput, bool(int8_t value));
-    MOCK_METHOD1(setMode, bool(std::string value));
-    MOCK_METHOD1(setSequencer, bool(std::string value));
-    MOCK_METHOD1(setScale, bool(uint8_t value));
-    MOCK_METHOD1(setCtrlLoop, bool(bool value));
-    MOCK_METHOD1(setLpTriggerEffect, bool(uint32_t value));
-    MOCK_METHOD1(setLpTriggerScale, bool(uint8_t value));
-    MOCK_METHOD1(setLraWaveShape, bool(uint32_t value));
-    MOCK_METHOD1(setOdClamp, bool(uint32_t value));
-    MOCK_METHOD1(debug, void(int fd));
-
-    ~MockApi() override { destructor(); };
-};
-
-class MockCal : public ::aidl::android::hardware::vibrator::Vibrator::HwCal {
-  public:
-    MOCK_METHOD0(destructor, void());
-    MOCK_METHOD1(getAutocal, bool(std::string &value));  // NOLINT
-    MOCK_METHOD1(getLraPeriod, bool(uint32_t *value));
-    MOCK_METHOD1(getCloseLoopThreshold, bool(uint32_t *value));
-    MOCK_METHOD1(getDynamicConfig, bool(bool *value));
-    MOCK_METHOD1(getLongFrequencyShift, bool(uint32_t *value));
-    MOCK_METHOD1(getShortVoltageMax, bool(uint32_t *value));
-    MOCK_METHOD1(getLongVoltageMax, bool(uint32_t *value));
-    MOCK_METHOD1(getClickDuration, bool(uint32_t *value));
-    MOCK_METHOD1(getTickDuration, bool(uint32_t *value));
-    MOCK_METHOD1(getDoubleClickDuration, bool(uint32_t *value));
-    MOCK_METHOD1(getHeavyClickDuration, bool(uint32_t *value));
-    MOCK_METHOD1(debug, void(int fd));
-
-    ~MockCal() override { destructor(); };
-    // b/132668253: Workaround gMock Compilation Issue
-    bool getAutocal(std::string *value) { return getAutocal(*value); }
-};
-
-#endif  // ANDROID_HARDWARE_VIBRATOR_TEST_MOCKS_H
diff --git a/vibrator/drv2624/tests/test-hwapi.cpp b/vibrator/drv2624/tests/test-hwapi.cpp
deleted file mode 100644
index af2b2f70..00000000
--- a/vibrator/drv2624/tests/test-hwapi.cpp
+++ /dev/null
@@ -1,405 +0,0 @@
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
-#include <android-base/file.h>
-#include <cutils/fs.h>
-#include <gtest/gtest.h>
-
-#include <cstdlib>
-#include <fstream>
-
-#include "Hardware.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::testing::Test;
-using ::testing::TestParamInfo;
-using ::testing::ValuesIn;
-using ::testing::WithParamInterface;
-
-class HwApiTest : public Test {
-  protected:
-    static constexpr const char *FILE_NAMES[]{
-            "device/autocal",
-            "device/ol_lra_period",
-            "activate",
-            "duration",
-            "state",
-            "device/rtp_input",
-            "device/mode",
-            "device/set_sequencer",
-            "device/scale",
-            "device/ctrl_loop",
-            "device/lp_trigger_effect",
-            "device/lp_trigger_scale",
-            "device/lra_wave_shape",
-            "device/od_clamp",
-    };
-
-    static constexpr const char *REQUIRED[]{
-            "activate",
-            "duration",
-            "state",
-    };
-
-  public:
-    void SetUp() override {
-        std::string prefix;
-        for (auto n : FILE_NAMES) {
-            auto name = std::filesystem::path(n);
-            auto path = std::filesystem::path(mFilesDir.path) / name;
-            fs_mkdirs(path.c_str(), S_IRWXU);
-            std::ofstream touch{path};
-            mFileMap[name] = path;
-        }
-        prefix = std::filesystem::path(mFilesDir.path) / "";
-        setenv("HWAPI_PATH_PREFIX", prefix.c_str(), true);
-        mHwApi = HwApi::Create();
-
-        for (auto n : REQUIRED) {
-            auto name = std::filesystem::path(n);
-            auto path = std::filesystem::path(mEmptyDir.path) / name;
-            fs_mkdirs(path.c_str(), S_IRWXU);
-            std::ofstream touch{path};
-        }
-        prefix = std::filesystem::path(mEmptyDir.path) / "";
-        setenv("HWAPI_PATH_PREFIX", prefix.c_str(), true);
-        mNoApi = HwApi::Create();
-    }
-
-    void TearDown() override { verifyContents(); }
-
-  protected:
-    // Set expected file content for a test.
-    template <typename T>
-    void expectContent(const std::string &name, const T &value) {
-        mExpectedContent[name] << value << std::endl;
-    }
-
-    // Set actual file content for an input test.
-    template <typename T>
-    void updateContent(const std::string &name, const T &value) {
-        std::ofstream(mFileMap[name]) << value << std::endl;
-    }
-
-    template <typename T>
-    void expectAndUpdateContent(const std::string &name, const T &value) {
-        expectContent(name, value);
-        updateContent(name, value);
-    }
-
-    // Compare all file contents against expected contents.
-    void verifyContents() {
-        for (auto &a : mFileMap) {
-            std::ifstream file{a.second};
-            std::string expect = mExpectedContent[a.first].str();
-            std::string actual = std::string(std::istreambuf_iterator<char>(file),
-                                             std::istreambuf_iterator<char>());
-            EXPECT_EQ(expect, actual) << a.first;
-        }
-    }
-
-    // TODO(eliptus): Determine how to induce errors in required files
-    static bool isRequired(const std::string &name) {
-        for (auto n : REQUIRED) {
-            if (std::string(n) == name) {
-                return true;
-            }
-        }
-        return false;
-    }
-
-    static auto ParamNameFixup(std::string str) {
-        std::replace(str.begin(), str.end(), '/', '_');
-        return str;
-    }
-
-  protected:
-    std::unique_ptr<Vibrator::HwApi> mHwApi;
-    std::unique_ptr<Vibrator::HwApi> mNoApi;
-    std::map<std::string, std::string> mFileMap;
-    TemporaryDir mFilesDir;
-    TemporaryDir mEmptyDir;
-    std::map<std::string, std::stringstream> mExpectedContent;
-};
-
-class CreateTest : public HwApiTest, public WithParamInterface<const char *> {
-  public:
-    void SetUp() override{};
-    void TearDown() override{};
-
-    static auto PrintParam(const TestParamInfo<CreateTest::ParamType> &info) {
-        return ParamNameFixup(info.param);
-    }
-    static auto &AllParams() { return FILE_NAMES; }
-};
-
-TEST_P(CreateTest, file_missing) {
-    auto skip = std::string(GetParam());
-    TemporaryDir dir;
-    std::unique_ptr<HwApi> hwapi;
-    std::string prefix;
-
-    for (auto n : FILE_NAMES) {
-        auto name = std::string(n);
-        auto path = std::string(dir.path) + "/" + name;
-        if (name == skip) {
-            continue;
-        }
-        fs_mkdirs(path.c_str(), S_IRWXU);
-        std::ofstream touch{path};
-    }
-
-    prefix = std::filesystem::path(dir.path) / "";
-    setenv("HWAPI_PATH_PREFIX", prefix.c_str(), true);
-    hwapi = HwApi::Create();
-    if (isRequired(skip)) {
-        EXPECT_EQ(nullptr, hwapi);
-    } else {
-        EXPECT_NE(nullptr, hwapi);
-    }
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, CreateTest, ValuesIn(CreateTest::AllParams()),
-                        CreateTest::PrintParam);
-
-template <typename T>
-class HwApiTypedTest : public HwApiTest,
-                       public WithParamInterface<std::tuple<std::string, std::function<T>>> {
-  public:
-    static auto PrintParam(const TestParamInfo<typename HwApiTypedTest::ParamType> &info) {
-        return ParamNameFixup(std::get<0>(info.param));
-    }
-    static auto MakeParam(std::string name, std::function<T> func) {
-        return std::make_tuple(name, func);
-    }
-};
-
-using HasTest = HwApiTypedTest<bool(Vibrator::HwApi &)>;
-
-TEST_P(HasTest, success_returnsTrue) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-
-    EXPECT_TRUE(func(*mHwApi));
-}
-
-TEST_P(HasTest, success_returnsFalse) {
-    auto param = GetParam();
-    auto func = std::get<1>(param);
-
-    EXPECT_FALSE(func(*mNoApi));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, HasTest,
-                        ValuesIn({
-                                HasTest::MakeParam("device/rtp_input",
-                                                   &Vibrator::HwApi::hasRtpInput),
-                        }),
-                        HasTest::PrintParam);
-
-using SetBoolTest = HwApiTypedTest<bool(Vibrator::HwApi &, bool)>;
-
-TEST_P(SetBoolTest, success_returnsTrue) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-
-    expectContent(name, "1");
-
-    EXPECT_TRUE(func(*mHwApi, true));
-}
-
-TEST_P(SetBoolTest, success_returnsFalse) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-
-    expectContent(name, "0");
-
-    EXPECT_TRUE(func(*mHwApi, false));
-}
-
-TEST_P(SetBoolTest, failure) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-
-    if (isRequired(name)) {
-        GTEST_SKIP();
-    }
-
-    EXPECT_FALSE(func(*mNoApi, true));
-    EXPECT_FALSE(func(*mNoApi, false));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, SetBoolTest,
-                        ValuesIn({
-                                SetBoolTest::MakeParam("activate", &Vibrator::HwApi::setActivate),
-                                SetBoolTest::MakeParam("state", &Vibrator::HwApi::setState),
-                                SetBoolTest::MakeParam("device/ctrl_loop",
-                                                       &Vibrator::HwApi::setCtrlLoop),
-                        }),
-                        SetBoolTest::PrintParam);
-
-using SetInt8Test = HwApiTypedTest<bool(Vibrator::HwApi &, int8_t)>;
-
-TEST_P(SetInt8Test, success) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    int8_t value = std::rand();
-
-    expectContent(name, +value);
-
-    EXPECT_TRUE(func(*mHwApi, value));
-}
-
-TEST_P(SetInt8Test, failure) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    int8_t value = std::rand();
-
-    if (isRequired(name)) {
-        GTEST_SKIP();
-    }
-
-    EXPECT_FALSE(func(*mNoApi, value));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, SetInt8Test,
-                        ValuesIn({
-                                SetInt8Test::MakeParam("device/rtp_input",
-                                                       &Vibrator::HwApi::setRtpInput),
-                        }),
-                        SetInt8Test::PrintParam);
-
-using SetUint8Test = HwApiTypedTest<bool(Vibrator::HwApi &, uint8_t)>;
-
-TEST_P(SetUint8Test, success) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    uint8_t value = std::rand();
-
-    expectContent(name, +value);
-
-    EXPECT_TRUE(func(*mHwApi, value));
-}
-
-TEST_P(SetUint8Test, failure) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    uint8_t value = std::rand();
-
-    if (isRequired(name)) {
-        GTEST_SKIP();
-    }
-
-    EXPECT_FALSE(func(*mNoApi, value));
-}
-
-INSTANTIATE_TEST_CASE_P(HwApiTests, SetUint8Test,
-                        ValuesIn({
-                                SetUint8Test::MakeParam("device/scale", &Vibrator::HwApi::setScale),
-                                SetUint8Test::MakeParam("device/lp_trigger_scale",
-                                                        &Vibrator::HwApi::setLpTriggerScale),
-                        }),
-                        SetUint8Test::PrintParam);
-
-using SetUint32Test = HwApiTypedTest<bool(Vibrator::HwApi &, uint32_t)>;
-
-TEST_P(SetUint32Test, success) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    uint32_t value = std::rand();
-
-    expectContent(name, value);
-
-    EXPECT_TRUE(func(*mHwApi, value));
-}
-
-TEST_P(SetUint32Test, failure) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    uint32_t value = std::rand();
-
-    if (isRequired(name)) {
-        GTEST_SKIP();
-    }
-
-    EXPECT_FALSE(func(*mNoApi, value));
-}
-
-INSTANTIATE_TEST_CASE_P(
-        HwApiTests, SetUint32Test,
-        ValuesIn({
-                SetUint32Test::MakeParam("device/ol_lra_period", &Vibrator::HwApi::setOlLraPeriod),
-                SetUint32Test::MakeParam("duration", &Vibrator::HwApi::setDuration),
-                SetUint32Test::MakeParam("device/lp_trigger_effect",
-                                         &Vibrator::HwApi::setLpTriggerEffect),
-                SetUint32Test::MakeParam("device/lra_wave_shape",
-                                         &Vibrator::HwApi::setLraWaveShape),
-                SetUint32Test::MakeParam("device/od_clamp", &Vibrator::HwApi::setOdClamp),
-        }),
-        SetUint32Test::PrintParam);
-
-using SetStringTest = HwApiTypedTest<bool(Vibrator::HwApi &, std::string)>;
-
-TEST_P(SetStringTest, success) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    std::string value = TemporaryFile().path;
-
-    expectContent(name, value);
-
-    EXPECT_TRUE(func(*mHwApi, value));
-}
-
-TEST_P(SetStringTest, failure) {
-    auto param = GetParam();
-    auto name = std::get<0>(param);
-    auto func = std::get<1>(param);
-    std::string value = TemporaryFile().path;
-
-    if (isRequired(name)) {
-        GTEST_SKIP();
-    }
-
-    EXPECT_FALSE(func(*mNoApi, value));
-}
-
-INSTANTIATE_TEST_CASE_P(
-        HwApiTests, SetStringTest,
-        ValuesIn({
-                SetStringTest::MakeParam("device/autocal", &Vibrator::HwApi::setAutocal),
-                SetStringTest::MakeParam("device/mode", &Vibrator::HwApi::setMode),
-                SetStringTest::MakeParam("device/set_sequencer", &Vibrator::HwApi::setSequencer),
-        }),
-        SetStringTest::PrintParam);
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/drv2624/tests/test-hwcal.cpp b/vibrator/drv2624/tests/test-hwcal.cpp
deleted file mode 100644
index 50fe373e..00000000
--- a/vibrator/drv2624/tests/test-hwcal.cpp
+++ /dev/null
@@ -1,394 +0,0 @@
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
-#include <android-base/file.h>
-#include <android-base/properties.h>
-#include <gtest/gtest.h>
-
-#include <fstream>
-
-#include "Hardware.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::android::base::SetProperty;
-using ::android::base::WaitForProperty;
-
-using ::testing::Test;
-
-class HwCalTest : public Test {
-  protected:
-    static constexpr char PROPERTY_PREFIX[] = "test.vibrator.hal.";
-
-    static constexpr uint32_t DEFAULT_LRA_PERIOD = 262;
-
-    static constexpr uint32_t DEFAULT_FREQUENCY_SHIFT = 10;
-    static constexpr uint32_t DEFAULT_VOLTAGE_MAX = 107;
-
-    static constexpr uint32_t DEFAULT_CLICK_DURATION_MS = 6;
-    static constexpr uint32_t DEFAULT_TICK_DURATION_MS = 2;
-    static constexpr uint32_t DEFAULT_DOUBLE_CLICK_DURATION_MS = 135;
-    static constexpr uint32_t DEFAULT_HEAVY_CLICK_DURATION_MS = 8;
-
-  public:
-    void SetUp() override {
-        setenv("PROPERTY_PREFIX", PROPERTY_PREFIX, true);
-        setenv("CALIBRATION_FILEPATH", mCalFile.path, true);
-    }
-
-  private:
-    template <typename T>
-    static void pack(std::ostream &stream, const T &value, std::string lpad, std::string rpad) {
-        stream << lpad << value << rpad;
-    }
-
-  protected:
-    void createHwCal() { mHwCal = std::make_unique<HwCal>(); }
-
-    template <typename T>
-    void write(const std::string key, const T &value, std::string lpad = " ",
-               std::string rpad = "") {
-        std::ofstream calfile{mCalFile.path, std::ios_base::app};
-        calfile << key << ":";
-        pack(calfile, value, lpad, rpad);
-        calfile << std::endl;
-    }
-
-    void unlink() { ::unlink(mCalFile.path); }
-
-  protected:
-    std::unique_ptr<Vibrator::HwCal> mHwCal;
-    TemporaryFile mCalFile;
-};
-
-TEST_F(HwCalTest, closeloop_present) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "closeloop.threshold", std::to_string(expect)));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getCloseLoopThreshold(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, closeloop_missing) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = UINT32_MAX;
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "closeloop.threshold", std::string()));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getCloseLoopThreshold(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, dynamicconfig_presentFalse) {
-    std::string prefix{PROPERTY_PREFIX};
-    bool expect = false;
-    bool actual = !expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "config.dynamic", "0"));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getDynamicConfig(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, dynamicconfig_presentTrue) {
-    std::string prefix{PROPERTY_PREFIX};
-    bool expect = true;
-    bool actual = !expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "config.dynamic", "1"));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getDynamicConfig(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, dynamicconfig_missing) {
-    std::string prefix{PROPERTY_PREFIX};
-    bool expect = false;
-    bool actual = !expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "config.dynamic", std::string()));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getDynamicConfig(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, freqshift_present) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "long.frequency.shift", std::to_string(expect)));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getLongFrequencyShift(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, freqshift_missing) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = DEFAULT_FREQUENCY_SHIFT;
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "long.frequency.shift", std::string()));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getLongFrequencyShift(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, shortvolt_present) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "short.voltage", std::to_string(expect)));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getShortVoltageMax(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, shortvolt_missing) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = DEFAULT_VOLTAGE_MAX;
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "short.voltage", std::string()));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getShortVoltageMax(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, longvolt_present) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "long.voltage", std::to_string(expect)));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getLongVoltageMax(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, longvolt_missing) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = DEFAULT_VOLTAGE_MAX;
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "long.voltage", std::string()));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getLongVoltageMax(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, click_present) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "click.duration", std::to_string(expect)));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getClickDuration(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, click_missing) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = DEFAULT_CLICK_DURATION_MS;
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "click.duration", std::string()));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getClickDuration(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, tick_present) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "tick.duration", std::to_string(expect)));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getTickDuration(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, tick_missing) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = DEFAULT_TICK_DURATION_MS;
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "tick.duration", std::string()));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getTickDuration(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, doubleclick) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = DEFAULT_DOUBLE_CLICK_DURATION_MS;
-    uint32_t actual = ~expect;
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getDoubleClickDuration(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, heavyclick_present) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "heavyclick.duration", std::to_string(expect)));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getHeavyClickDuration(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, heavyclick_missing) {
-    std::string prefix{PROPERTY_PREFIX};
-    uint32_t expect = DEFAULT_HEAVY_CLICK_DURATION_MS;
-    uint32_t actual = ~expect;
-
-    EXPECT_TRUE(SetProperty(prefix + "heavyclick.duration", std::string()));
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getHeavyClickDuration(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, autocal_present) {
-    std::string expect = std::to_string(std::rand()) + " " + std::to_string(std::rand()) + " " +
-                         std::to_string(std::rand());
-    std::string actual = "";
-
-    write("autocal", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getAutocal(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, autocal_missing) {
-    std::string actual;
-
-    createHwCal();
-
-    EXPECT_FALSE(mHwCal->getAutocal(&actual));
-}
-
-TEST_F(HwCalTest, lra_period_present) {
-    uint32_t expect = std::rand();
-    uint32_t actual = ~expect;
-
-    write("lra_period", expect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getLraPeriod(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, lra_period_missing) {
-    uint32_t expect = DEFAULT_LRA_PERIOD;
-    uint32_t actual = ~expect;
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getLraPeriod(&actual));
-    EXPECT_EQ(expect, actual);
-}
-
-TEST_F(HwCalTest, multiple) {
-    std::string autocalExpect = std::to_string(std::rand()) + " " + std::to_string(std::rand()) +
-                                " " + std::to_string(std::rand());
-    std::string autocalActual = "";
-    uint32_t lraPeriodExpect = std::rand();
-    uint32_t lraPeriodActual = ~lraPeriodExpect;
-
-    write("autocal", autocalExpect);
-    write("lra_period", lraPeriodExpect);
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getAutocal(&autocalActual));
-    EXPECT_EQ(autocalExpect, autocalActual);
-    EXPECT_TRUE(mHwCal->getLraPeriod(&lraPeriodActual));
-    EXPECT_EQ(lraPeriodExpect, lraPeriodActual);
-}
-
-TEST_F(HwCalTest, trimming) {
-    std::string autocalExpect = std::to_string(std::rand()) + " " + std::to_string(std::rand()) +
-                                " " + std::to_string(std::rand());
-    std::string autocalActual = "";
-    uint32_t lraPeriodExpect = std::rand();
-    uint32_t lraPeriodActual = ~lraPeriodExpect;
-
-    write("autocal", autocalExpect, " \t", "\t ");
-    write("lra_period", lraPeriodExpect, " \t", "\t ");
-
-    createHwCal();
-
-    EXPECT_TRUE(mHwCal->getAutocal(&autocalActual));
-    EXPECT_EQ(autocalExpect, autocalActual);
-    EXPECT_TRUE(mHwCal->getLraPeriod(&lraPeriodActual));
-    EXPECT_EQ(lraPeriodExpect, lraPeriodActual);
-}
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/drv2624/tests/test-vibrator.cpp b/vibrator/drv2624/tests/test-vibrator.cpp
deleted file mode 100644
index b64e493d..00000000
--- a/vibrator/drv2624/tests/test-vibrator.cpp
+++ /dev/null
@@ -1,515 +0,0 @@
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
-#include <android-base/logging.h>
-#include <gmock/gmock.h>
-#include <gtest/gtest.h>
-
-#include "Vibrator.h"
-#include "mocks.h"
-#include "types.h"
-#include "utils.h"
-
-namespace aidl {
-namespace android {
-namespace hardware {
-namespace vibrator {
-
-using ::testing::_;
-using ::testing::AnyNumber;
-using ::testing::AnyOf;
-using ::testing::Assign;
-using ::testing::Combine;
-using ::testing::DoAll;
-using ::testing::DoDefault;
-using ::testing::Exactly;
-using ::testing::ExpectationSet;
-using ::testing::Mock;
-using ::testing::Range;
-using ::testing::Return;
-using ::testing::Sequence;
-using ::testing::SetArgPointee;
-using ::testing::SetArgReferee;
-using ::testing::Test;
-using ::testing::TestParamInfo;
-using ::testing::ValuesIn;
-using ::testing::WithParamInterface;
-
-// Constants With Prescribed Values
-
-static const std::map<EffectTuple, EffectSequence> EFFECT_SEQUENCES{
-        {{Effect::CLICK, EffectStrength::LIGHT}, {1, 2}},
-        {{Effect::CLICK, EffectStrength::MEDIUM}, {1, 0}},
-        {{Effect::CLICK, EffectStrength::STRONG}, {1, 0}},
-        {{Effect::TICK, EffectStrength::LIGHT}, {2, 2}},
-        {{Effect::TICK, EffectStrength::MEDIUM}, {2, 0}},
-        {{Effect::TICK, EffectStrength::STRONG}, {2, 0}},
-        {{Effect::DOUBLE_CLICK, EffectStrength::LIGHT}, {3, 2}},
-        {{Effect::DOUBLE_CLICK, EffectStrength::MEDIUM}, {3, 0}},
-        {{Effect::DOUBLE_CLICK, EffectStrength::STRONG}, {3, 0}},
-        {{Effect::HEAVY_CLICK, EffectStrength::LIGHT}, {4, 2}},
-        {{Effect::HEAVY_CLICK, EffectStrength::MEDIUM}, {4, 0}},
-        {{Effect::HEAVY_CLICK, EffectStrength::STRONG}, {4, 0}},
-        {{Effect::TEXTURE_TICK, EffectStrength::LIGHT}, {2, 2}},
-        {{Effect::TEXTURE_TICK, EffectStrength::MEDIUM}, {2, 0}},
-        {{Effect::TEXTURE_TICK, EffectStrength::STRONG}, {2, 0}},
-};
-
-static uint32_t freqPeriodFormula(uint32_t in) {
-    return 1000000000 / (24615 * in);
-}
-
-template <typename... T>
-class VibratorTestTemplate : public Test, public WithParamInterface<std::tuple<bool, T...>> {
-  public:
-    static auto GetDynamicConfig(typename VibratorTestTemplate::ParamType param) {
-        return std::get<0>(param);
-    }
-    template <std::size_t I>
-    static auto GetOtherParam(typename VibratorTestTemplate::ParamType param) {
-        return std::get<I + 1>(param);
-    }
-
-    static auto PrintParam(const TestParamInfo<typename VibratorTestTemplate::ParamType> &info) {
-        auto dynamic = GetDynamicConfig(info.param);
-        return std::string() + (dynamic ? "Dynamic" : "Static") + "Config";
-    }
-
-    static auto MakeParam(bool dynamicConfig, T... others) {
-        return std::make_tuple(dynamicConfig, others...);
-    }
-
-    void SetUp() override {
-        std::unique_ptr<MockApi> mockapi;
-        std::unique_ptr<MockCal> mockcal;
-
-        mCloseLoopThreshold = std::rand();
-        // ensure close-loop test is possible
-        if (mCloseLoopThreshold == UINT32_MAX) {
-            mCloseLoopThreshold--;
-        }
-
-        mShortLraPeriod = std::rand();
-        if (getDynamicConfig()) {
-            mLongFrequencyShift = std::rand();
-            mLongLraPeriod =
-                    freqPeriodFormula(freqPeriodFormula(mShortLraPeriod) - mLongFrequencyShift);
-            mShortVoltageMax = std::rand();
-            mLongVoltageMax = std::rand();
-        }
-
-        mEffectDurations[Effect::CLICK] = std::rand();
-        mEffectDurations[Effect::TICK] = std::rand();
-        mEffectDurations[Effect::DOUBLE_CLICK] = std::rand();
-        mEffectDurations[Effect::HEAVY_CLICK] = std::rand();
-        mEffectDurations[Effect::TEXTURE_TICK] = mEffectDurations[Effect::TICK];
-
-        createMock(&mockapi, &mockcal);
-        createVibrator(std::move(mockapi), std::move(mockcal));
-    }
-
-    void TearDown() override { deleteVibrator(); }
-
-  protected:
-    auto getDynamicConfig() const { return GetDynamicConfig(VibratorTestTemplate::GetParam()); }
-
-    void createMock(std::unique_ptr<MockApi> *mockapi, std::unique_ptr<MockCal> *mockcal) {
-        *mockapi = std::make_unique<MockApi>();
-        *mockcal = std::make_unique<MockCal>();
-
-        mMockApi = mockapi->get();
-        mMockCal = mockcal->get();
-
-        ON_CALL(*mMockApi, destructor()).WillByDefault(Assign(&mMockApi, nullptr));
-        ON_CALL(*mMockApi, setOlLraPeriod(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, setActivate(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, setDuration(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, setMode(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, setCtrlLoop(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, setLraWaveShape(_)).WillByDefault(Return(true));
-        ON_CALL(*mMockApi, setOdClamp(_)).WillByDefault(Return(true));
-
-        ON_CALL(*mMockCal, destructor()).WillByDefault(Assign(&mMockCal, nullptr));
-        ON_CALL(*mMockCal, getLraPeriod(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(mShortLraPeriod), Return(true)));
-        ON_CALL(*mMockCal, getCloseLoopThreshold(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(mCloseLoopThreshold), Return(true)));
-        ON_CALL(*mMockCal, getDynamicConfig(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(getDynamicConfig()), Return(true)));
-
-        if (getDynamicConfig()) {
-            ON_CALL(*mMockCal, getLongFrequencyShift(_))
-                    .WillByDefault(DoAll(SetArgPointee<0>(mLongFrequencyShift), Return(true)));
-            ON_CALL(*mMockCal, getShortVoltageMax(_))
-                    .WillByDefault(DoAll(SetArgPointee<0>(mShortVoltageMax), Return(true)));
-            ON_CALL(*mMockCal, getLongVoltageMax(_))
-                    .WillByDefault(DoAll(SetArgPointee<0>(mLongVoltageMax), Return(true)));
-        }
-
-        ON_CALL(*mMockCal, getClickDuration(_))
-                .WillByDefault(
-                        DoAll(SetArgPointee<0>(mEffectDurations[Effect::CLICK]), Return(true)));
-        ON_CALL(*mMockCal, getTickDuration(_))
-                .WillByDefault(
-                        DoAll(SetArgPointee<0>(mEffectDurations[Effect::TICK]), Return(true)));
-        ON_CALL(*mMockCal, getDoubleClickDuration(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(mEffectDurations[Effect::DOUBLE_CLICK]),
-                                     Return(true)));
-        ON_CALL(*mMockCal, getHeavyClickDuration(_))
-                .WillByDefault(DoAll(SetArgPointee<0>(mEffectDurations[Effect::HEAVY_CLICK]),
-                                     Return(true)));
-
-        relaxMock(false);
-    }
-
-    void createVibrator(std::unique_ptr<MockApi> mockapi, std::unique_ptr<MockCal> mockcal,
-                        bool relaxed = true) {
-        if (relaxed) {
-            relaxMock(true);
-        }
-        mVibrator = ndk::SharedRefBase::make<Vibrator>(std::move(mockapi), std::move(mockcal));
-        if (relaxed) {
-            relaxMock(false);
-        }
-    }
-
-    void deleteVibrator(bool relaxed = true) {
-        if (relaxed) {
-            relaxMock(true);
-        }
-        mVibrator.reset();
-    }
-
-    void relaxMock(bool relax) {
-        auto times = relax ? AnyNumber() : Exactly(0);
-
-        Mock::VerifyAndClearExpectations(mMockApi);
-        Mock::VerifyAndClearExpectations(mMockCal);
-
-        EXPECT_CALL(*mMockApi, destructor()).Times(times);
-        EXPECT_CALL(*mMockApi, setAutocal(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setOlLraPeriod(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setActivate(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setDuration(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setState(_)).Times(times);
-        EXPECT_CALL(*mMockApi, hasRtpInput()).Times(times);
-        EXPECT_CALL(*mMockApi, setRtpInput(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setMode(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setSequencer(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setScale(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setCtrlLoop(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setLpTriggerEffect(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setLpTriggerScale(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setLraWaveShape(_)).Times(times);
-        EXPECT_CALL(*mMockApi, setOdClamp(_)).Times(times);
-        EXPECT_CALL(*mMockApi, debug(_)).Times(times);
-
-        EXPECT_CALL(*mMockCal, destructor()).Times(times);
-        EXPECT_CALL(*mMockCal, getAutocal(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getLraPeriod(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getCloseLoopThreshold(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getDynamicConfig(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getLongFrequencyShift(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getShortVoltageMax(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getLongVoltageMax(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getClickDuration(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getTickDuration(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getDoubleClickDuration(_)).Times(times);
-        EXPECT_CALL(*mMockCal, getHeavyClickDuration(_)).Times(times);
-        EXPECT_CALL(*mMockCal, debug(_)).Times(times);
-    }
-
-  protected:
-    MockApi *mMockApi;
-    MockCal *mMockCal;
-    std::shared_ptr<IVibrator> mVibrator;
-
-    EffectDuration mCloseLoopThreshold;
-    uint32_t mLongFrequencyShift;
-    uint32_t mShortLraPeriod;
-    uint32_t mLongLraPeriod;
-    uint32_t mShortVoltageMax;
-    uint32_t mLongVoltageMax;
-    std::map<Effect, EffectDuration> mEffectDurations;
-};
-
-using BasicTest = VibratorTestTemplate<>;
-
-TEST_P(BasicTest, Constructor) {
-    std::unique_ptr<MockApi> mockapi;
-    std::unique_ptr<MockCal> mockcal;
-    std::string autocalVal = std::to_string(std::rand()) + " " + std::to_string(std::rand()) + " " +
-                             std::to_string(std::rand());
-    Sequence autocalSeq, lraPeriodSeq;
-
-    EXPECT_CALL(*mMockApi, destructor()).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockCal, destructor()).WillOnce(DoDefault());
-
-    deleteVibrator(false);
-
-    createMock(&mockapi, &mockcal);
-
-    EXPECT_CALL(*mMockApi, setState(true)).WillOnce(Return(true));
-
-    EXPECT_CALL(*mMockCal, getAutocal(_))
-            .InSequence(autocalSeq)
-            .WillOnce(DoAll(SetArgReferee<0>(autocalVal), Return(true)));
-    EXPECT_CALL(*mMockApi, setAutocal(autocalVal)).InSequence(autocalSeq).WillOnce(DoDefault());
-
-    EXPECT_CALL(*mMockCal, getLraPeriod(_)).InSequence(lraPeriodSeq).WillOnce(DoDefault());
-
-    EXPECT_CALL(*mMockCal, getCloseLoopThreshold(_)).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockCal, getDynamicConfig(_)).WillOnce(DoDefault());
-
-    if (getDynamicConfig()) {
-        EXPECT_CALL(*mMockCal, getLongFrequencyShift(_)).WillOnce(DoDefault());
-        EXPECT_CALL(*mMockCal, getShortVoltageMax(_)).WillOnce(DoDefault());
-        EXPECT_CALL(*mMockCal, getLongVoltageMax(_)).WillOnce(DoDefault());
-    } else {
-        EXPECT_CALL(*mMockApi, setOlLraPeriod(mShortLraPeriod))
-                .InSequence(lraPeriodSeq)
-                .WillOnce(DoDefault());
-    }
-
-    EXPECT_CALL(*mMockCal, getClickDuration(_)).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockCal, getTickDuration(_)).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockCal, getDoubleClickDuration(_)).WillOnce(DoDefault());
-    EXPECT_CALL(*mMockCal, getHeavyClickDuration(_)).WillOnce(DoDefault());
-
-    createVibrator(std::move(mockapi), std::move(mockcal), false);
-}
-
-TEST_P(BasicTest, on) {
-    EffectDuration duration = std::rand();
-    ExpectationSet e;
-
-    e += EXPECT_CALL(*mMockApi, setCtrlLoop(_)).WillOnce(DoDefault());
-    e += EXPECT_CALL(*mMockApi, setMode("rtp")).WillOnce(DoDefault());
-    e += EXPECT_CALL(*mMockApi, setDuration(duration)).WillOnce(DoDefault());
-
-    if (getDynamicConfig()) {
-        e += EXPECT_CALL(*mMockApi, setLraWaveShape(0)).WillOnce(DoDefault());
-        e += EXPECT_CALL(*mMockApi, setOdClamp(mLongVoltageMax)).WillOnce(DoDefault());
-        e += EXPECT_CALL(*mMockApi, setOlLraPeriod(mLongLraPeriod)).WillOnce(DoDefault());
-    }
-
-    EXPECT_CALL(*mMockApi, setActivate(true)).After(e).WillOnce(DoDefault());
-
-    EXPECT_EQ(EX_NONE, mVibrator->on(duration, nullptr).getExceptionCode());
-}
-
-TEST_P(BasicTest, on_openLoop) {
-    EffectDuration duration = mCloseLoopThreshold;
-
-    relaxMock(true);
-
-    EXPECT_CALL(*mMockApi, setCtrlLoop(true)).WillOnce(DoDefault());
-
-    EXPECT_EQ(EX_NONE, mVibrator->on(duration, nullptr).getExceptionCode());
-}
-
-TEST_P(BasicTest, on_closeLoop) {
-    EffectDuration duration = mCloseLoopThreshold + 1;
-
-    relaxMock(true);
-
-    EXPECT_CALL(*mMockApi, setCtrlLoop(false)).WillOnce(DoDefault());
-
-    EXPECT_EQ(EX_NONE, mVibrator->on(duration, nullptr).getExceptionCode());
-}
-
-TEST_P(BasicTest, off) {
-    EXPECT_CALL(*mMockApi, setActivate(false)).WillOnce(DoDefault());
-
-    EXPECT_EQ(EX_NONE, mVibrator->off().getExceptionCode());
-}
-
-TEST_P(BasicTest, supportsAmplitudeControl_supported) {
-    EXPECT_CALL(*mMockApi, hasRtpInput()).WillOnce(Return(true));
-
-    int32_t capabilities;
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_GT(capabilities & IVibrator::CAP_AMPLITUDE_CONTROL, 0);
-}
-
-TEST_P(BasicTest, supportsAmplitudeControl_unsupported) {
-    EXPECT_CALL(*mMockApi, hasRtpInput()).WillOnce(Return(false));
-
-    int32_t capabilities;
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_EQ(capabilities & IVibrator::CAP_AMPLITUDE_CONTROL, 0);
-}
-
-TEST_P(BasicTest, setAmplitude) {
-    EffectAmplitude amplitude = static_cast<float>(std::rand()) / RAND_MAX ?: 1.0f;
-
-    EXPECT_CALL(*mMockApi, setRtpInput(amplitudeToRtpInput(amplitude))).WillOnce(Return(true));
-
-    EXPECT_EQ(EX_NONE, mVibrator->setAmplitude(amplitude).getExceptionCode());
-}
-
-TEST_P(BasicTest, supportsExternalControl_unsupported) {
-    EXPECT_CALL(*mMockApi, hasRtpInput()).WillOnce(Return(false));
-
-    int32_t capabilities;
-    EXPECT_TRUE(mVibrator->getCapabilities(&capabilities).isOk());
-    EXPECT_EQ(capabilities & IVibrator::CAP_EXTERNAL_CONTROL, 0);
-}
-
-TEST_P(BasicTest, setExternalControl_enable) {
-    EXPECT_EQ(EX_UNSUPPORTED_OPERATION, mVibrator->setExternalControl(true).getExceptionCode());
-}
-
-TEST_P(BasicTest, setExternalControl_disable) {
-    EXPECT_EQ(EX_UNSUPPORTED_OPERATION, mVibrator->setExternalControl(false).getExceptionCode());
-}
-
-INSTANTIATE_TEST_CASE_P(VibratorTests, BasicTest,
-                        ValuesIn({BasicTest::MakeParam(false), BasicTest::MakeParam(true)}),
-                        BasicTest::PrintParam);
-
-class EffectsTest : public VibratorTestTemplate<EffectTuple> {
-  public:
-    static auto GetEffectTuple(ParamType param) { return GetOtherParam<0>(param); }
-
-    static auto PrintParam(const TestParamInfo<ParamType> &info) {
-        auto prefix = VibratorTestTemplate::PrintParam(info);
-        auto tuple = GetEffectTuple(info.param);
-        auto effect = std::get<0>(tuple);
-        auto strength = std::get<1>(tuple);
-        return prefix + "_" + toString(effect) + "_" + toString(strength);
-    }
-
-  protected:
-    auto getEffectTuple() const { return GetEffectTuple(GetParam()); }
-};
-
-TEST_P(EffectsTest, perform) {
-    auto tuple = getEffectTuple();
-    auto effect = std::get<0>(tuple);
-    auto strength = std::get<1>(tuple);
-    auto seqIter = EFFECT_SEQUENCES.find(tuple);
-    auto durIter = mEffectDurations.find(effect);
-    EffectDuration duration;
-
-    if (seqIter != EFFECT_SEQUENCES.end() && durIter != mEffectDurations.end()) {
-        auto sequence = std::to_string(std::get<0>(seqIter->second)) + " 0";
-        auto scale = std::get<1>(seqIter->second);
-        ExpectationSet e;
-
-        duration = durIter->second;
-
-        e += EXPECT_CALL(*mMockApi, setSequencer(sequence)).WillOnce(Return(true));
-        e += EXPECT_CALL(*mMockApi, setScale(scale)).WillOnce(Return(true));
-        e += EXPECT_CALL(*mMockApi, setCtrlLoop(1)).WillOnce(DoDefault());
-        e += EXPECT_CALL(*mMockApi, setMode("waveform")).WillOnce(DoDefault());
-        e += EXPECT_CALL(*mMockApi, setDuration(duration)).WillOnce(DoDefault());
-
-        if (getDynamicConfig()) {
-            e += EXPECT_CALL(*mMockApi, setLraWaveShape(1)).WillOnce(DoDefault());
-            e += EXPECT_CALL(*mMockApi, setOdClamp(mShortVoltageMax)).WillOnce(DoDefault());
-            e += EXPECT_CALL(*mMockApi, setOlLraPeriod(mShortLraPeriod)).WillOnce(DoDefault());
-        }
-
-        EXPECT_CALL(*mMockApi, setActivate(true)).After(e).WillOnce(DoDefault());
-    } else {
-        duration = 0;
-    }
-
-    int32_t lengthMs;
-    ndk::ScopedAStatus status = mVibrator->perform(effect, strength, nullptr, &lengthMs);
-    if (duration) {
-        EXPECT_EQ(EX_NONE, status.getExceptionCode());
-        EXPECT_LE(duration, lengthMs);
-    } else {
-        EXPECT_EQ(EX_UNSUPPORTED_OPERATION, status.getExceptionCode());
-    }
-}
-
-TEST_P(EffectsTest, alwaysOnEnable) {
-    auto tuple = getEffectTuple();
-    auto effect = std::get<0>(tuple);
-    auto strength = std::get<1>(tuple);
-    auto seqIter = EFFECT_SEQUENCES.find(tuple);
-    bool supported = (seqIter != EFFECT_SEQUENCES.end());
-
-    if (supported) {
-        auto [index, scale] = seqIter->second;
-        EXPECT_CALL(*mMockApi, setLpTriggerEffect(index)).WillOnce(Return(true));
-        EXPECT_CALL(*mMockApi, setLpTriggerScale(scale)).WillOnce(Return(true));
-    }
-
-    ndk::ScopedAStatus status = mVibrator->alwaysOnEnable(0, effect, strength);
-    if (supported) {
-        EXPECT_EQ(EX_NONE, status.getExceptionCode());
-    } else {
-        EXPECT_EQ(EX_UNSUPPORTED_OPERATION, status.getExceptionCode());
-    }
-}
-
-INSTANTIATE_TEST_CASE_P(VibratorTests, EffectsTest,
-                        Combine(ValuesIn({false, true}),
-                                Combine(ValuesIn(ndk::enum_range<Effect>().begin(),
-                                                 ndk::enum_range<Effect>().end()),
-                                        ValuesIn(ndk::enum_range<EffectStrength>().begin(),
-                                                 ndk::enum_range<EffectStrength>().end()))),
-                        EffectsTest::PrintParam);
-
-class AlwaysOnTest : public VibratorTestTemplate<int32_t> {
-  public:
-    static auto GetId(ParamType param) { return GetOtherParam<0>(param); }
-
-    static auto PrintParam(const TestParamInfo<ParamType> &info) {
-        return std::to_string(GetId(info.param));
-    }
-
-  protected:
-    auto getId() const { return GetId(GetParam()); }
-};
-
-TEST_P(AlwaysOnTest, alwaysOnEnable) {
-    auto id = getId();
-    auto seqIter = EFFECT_SEQUENCES.begin();
-
-    std::advance(seqIter, std::rand() % EFFECT_SEQUENCES.size());
-
-    auto effect = std::get<0>(seqIter->first);
-    auto strength = std::get<1>(seqIter->first);
-    auto [index, scale] = seqIter->second;
-
-    EXPECT_CALL(*mMockApi, setLpTriggerEffect(index)).WillOnce(Return(true));
-    EXPECT_CALL(*mMockApi, setLpTriggerScale(scale)).WillOnce(Return(true));
-
-    ndk::ScopedAStatus status = mVibrator->alwaysOnEnable(id, effect, strength);
-    EXPECT_EQ(EX_NONE, status.getExceptionCode());
-}
-
-TEST_P(AlwaysOnTest, alwaysOnDisable) {
-    auto id = getId();
-
-    EXPECT_CALL(*mMockApi, setLpTriggerEffect(0)).WillOnce(Return(true));
-
-    ndk::ScopedAStatus status = mVibrator->alwaysOnDisable(id);
-    EXPECT_EQ(EX_NONE, status.getExceptionCode());
-}
-
-INSTANTIATE_TEST_CASE_P(VibratorTests, AlwaysOnTest, Combine(ValuesIn({false, true}), Range(0, 0)),
-                        AlwaysOnTest::PrintParam);
-
-}  // namespace vibrator
-}  // namespace hardware
-}  // namespace android
-}  // namespace aidl
diff --git a/vibrator/drv2624/tests/types.h b/vibrator/drv2624/tests/types.h
deleted file mode 100644
index 103678d5..00000000
--- a/vibrator/drv2624/tests/types.h
+++ /dev/null
@@ -1,27 +0,0 @@
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
-#ifndef ANDROID_HARDWARE_VIBRATOR_TEST_TYPES_H
-#define ANDROID_HARDWARE_VIBRATOR_TEST_TYPES_H
-
-#include <aidl/android/hardware/vibrator/IVibrator.h>
-
-using EffectAmplitude = float;
-using EffectDuration = uint32_t;
-using EffectSequence = std::tuple<uint32_t, uint8_t>;
-using EffectTuple = std::tuple<::aidl::android::hardware::vibrator::Effect,
-                               ::aidl::android::hardware::vibrator::EffectStrength>;
-
-#endif  // ANDROID_HARDWARE_VIBRATOR_TEST_TYPES_H
```

