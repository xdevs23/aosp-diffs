```diff
diff --git a/misc_writer/include/misc_writer/misc_writer.h b/misc_writer/include/misc_writer/misc_writer.h
index 765aec1e..d04a2ce4 100644
--- a/misc_writer/include/misc_writer/misc_writer.h
+++ b/misc_writer/include/misc_writer/misc_writer.h
@@ -47,6 +47,7 @@ enum class MiscWriterActions : int32_t {
   kWriteDstOffset,
   kSetDisplayMode,
   kClearDisplayMode,
+  kWriteEagleEyePatterns,
 
   kUnset = -1,
 };
@@ -70,6 +71,10 @@ class MiscWriter {
         char dsttransition[32];
         char dstoffset[32];
         char user_preferred_resolution[32];
+        char sota_csku[8];
+        char sota_csku_signature[96];
+        char eagleEye[2000];
+        char skipUnbootableCheck[32];
     } __attribute__((__packed__)) bootloader_message_vendor_t;
 
     static constexpr uint32_t kThemeFlagOffsetInVendorSpace =
@@ -115,6 +120,8 @@ class MiscWriter {
     static constexpr uint32_t kDisplayModeOffsetInVendorSpace =
             offsetof(bootloader_message_vendor_t, user_preferred_resolution);
     static constexpr char kDisplayModePrefix[] = "mode=";
+    static constexpr uint32_t kEagleEyeOffset =
+            offsetof(bootloader_message_vendor_t, eagleEye);
 
     // Minimum and maximum valid value for max-ram-size
     static constexpr int32_t kRamSizeDefault = -1;
@@ -144,6 +151,7 @@ class MiscWriter {
     // Performs the stored MiscWriterActions. If |override_offset| is set, writes to the input
     // offset in the vendor space of /misc instead of the default offset.
     bool PerformAction(std::optional<size_t> override_offset = std::nullopt);
+    bool UpdateSotaConfig(std::optional<size_t> override_offset = std::nullopt);
 
   private:
     MiscWriterActions action_{MiscWriterActions::kUnset};
diff --git a/misc_writer/misc_writer.cpp b/misc_writer/misc_writer.cpp
index 0f8983a0..7b025f29 100644
--- a/misc_writer/misc_writer.cpp
+++ b/misc_writer/misc_writer.cpp
@@ -22,6 +22,7 @@
 #include <android-base/stringprintf.h>
 #include <bootloader_message/bootloader_message.h>
 #include <string.h>
+#include <charconv>
 
 namespace android {
 namespace hardware {
@@ -104,7 +105,7 @@ bool MiscWriter::PerformAction(std::optional<size_t> override_offset) {
         content.resize(32);
         break;
     case MiscWriterActions::kSetSotaConfig:
-        goto sota_config;
+      return UpdateSotaConfig(override_offset);
     case MiscWriterActions::kWriteDstTransition:
         offset = override_offset.value_or(kDstTransitionOffsetInVendorSpace);
         content = std::string(kDstTransition) + stringdata_;
@@ -123,6 +124,11 @@ bool MiscWriter::PerformAction(std::optional<size_t> override_offset) {
                           : std::string(32, 0);
         content.resize(32, 0);
         break;
+    case MiscWriterActions::kWriteEagleEyePatterns:
+        offset = override_offset.value_or(kEagleEyeOffset);
+        content = stringdata_;
+        content.resize(sizeof(bootloader_message_vendor_t::eagleEye), 0);
+        break;
     case MiscWriterActions::kUnset:
       LOG(ERROR) << "The misc writer action must be set";
       return false;
@@ -133,26 +139,70 @@ bool MiscWriter::PerformAction(std::optional<size_t> override_offset) {
     LOG(ERROR) << "Failed to write " << content << " at offset " << offset << " : " << err;
     return false;
   }
+  return true;
+}
 
-sota_config:
-  if (action_ == MiscWriterActions::kSetSotaFlag || action_ == MiscWriterActions::kSetSotaConfig) {
-    content = ::android::base::GetProperty("persist.vendor.nfc.factoryota.state", "");
-    if (content.size() != 0 && content.size() <= 40) {
-      offset = kSotaStateOffsetInVendorSpace;
-      if (std::string err;
-          !WriteMiscPartitionVendorSpace(content.data(), content.size(), offset, &err)) {
-          LOG(ERROR) << "Failed to write " << content << " at offset " << offset << " : " << err;
-          return false;
-      }
+bool MiscWriter::UpdateSotaConfig(std::optional<size_t> override_offset) {
+  size_t offset = 0;
+  std::string content;
+  std::string err;
+
+  // Update sota state
+  offset = override_offset.value_or(kSotaStateOffsetInVendorSpace);
+  content = ::android::base::GetProperty("persist.vendor.nfc.factoryota.state", "");
+  if (content.size() != 0) {
+    content.resize(sizeof(bootloader_message_vendor_t::sota_client_state));
+    if (!WriteMiscPartitionVendorSpace(content.data(), content.size(), offset, &err)) {
+      LOG(ERROR) << "Failed to write " << content << " at offset " << offset << " : " << err;
+      return false;
+    }
+  }
+
+  // Update sota schedule_shipmode
+  offset = override_offset.value_or(kSotaScheduleShipmodeOffsetInVendorSpace);
+  content = ::android::base::GetProperty("persist.vendor.nfc.factoryota.schedule_shipmode", "");
+  if (content.size() != 0) {
+    content.resize(sizeof(bootloader_message_vendor_t::sota_schedule_shipmode));
+    if (!WriteMiscPartitionVendorSpace(content.data(), content.size(), offset, &err)) {
+      LOG(ERROR) << "Failed to write " << content << " at offset " << offset << " : " << err;
+      return false;
+    }
+  }
+
+  // Update sota csku signature
+  offset = override_offset.value_or(offsetof(bootloader_message_vendor_t, sota_csku_signature));
+  std::string signature;
+  signature += ::android::base::GetProperty("persist.vendor.factoryota.signature1", "");
+  signature += ::android::base::GetProperty("persist.vendor.factoryota.signature2", "");
+  signature += ::android::base::GetProperty("persist.vendor.factoryota.signature3", "");
+  if (signature.size() != 0) {
+    LOG(INFO) << "persist.vendor.factoryota.signature=" << signature;
+    if (signature.length() != 2 * sizeof(bootloader_message_vendor_t::sota_csku_signature)) {
+      LOG(ERROR) << "signature.length() should be "
+                << 2 * sizeof(bootloader_message_vendor_t::sota_csku_signature) << " not "
+                << signature.length();
+      return false;
     }
-    content = ::android::base::GetProperty("persist.vendor.nfc.factoryota.schedule_shipmode", "");
-    if (content.size() != 0 && content.size() <= 32) {
-      offset = kSotaScheduleShipmodeOffsetInVendorSpace;
-      if (std::string err;
-          !WriteMiscPartitionVendorSpace(content.data(), content.size(), offset, &err)) {
-          LOG(ERROR) << "Failed to write " << content << " at offset " << offset << " : " << err;
-          return false;
+    content.resize(sizeof(bootloader_message_vendor_t::sota_csku_signature));
+    // Traslate hex string to bytes
+    for (size_t i = 0; i < 2 * content.size(); i += 2)
+      if (std::from_chars(&signature[i], &signature[i + 2], content[i / 2], 16).ec != std::errc{}) {
+        LOG(ERROR) << "Failed to convert " << signature << " to bytes";
+        return false;
       }
+    if (!WriteMiscPartitionVendorSpace(content.data(), content.size(), offset, &err)) {
+      LOG(ERROR) << "Failed to write signature at offset " << offset << " : " << err;
+      return false;
+    }
+
+    // Update sota csku
+    offset = override_offset.value_or(offsetof(bootloader_message_vendor_t, sota_csku));
+    content = ::android::base::GetProperty("persist.vendor.factoryota.csku", "");
+    content.resize(sizeof(bootloader_message_vendor_t::sota_csku));
+    LOG(INFO) << "persist.vendor.factoryota.csku=" << content;
+    if (!WriteMiscPartitionVendorSpace(content.data(), content.size(), offset, &err)) {
+      LOG(ERROR) << "Failed to write " << content << " at offset " << offset << " : " << err;
+      return false;
     }
   }
 
diff --git a/misc_writer/misc_writer_main.cpp b/misc_writer/misc_writer_main.cpp
index 936aa66d..47649ac9 100644
--- a/misc_writer/misc_writer_main.cpp
+++ b/misc_writer/misc_writer_main.cpp
@@ -57,6 +57,8 @@ static int Usage(std::string_view name) {
   std::cerr << "  --set-dstoffset               Write the time offset during the next dst transition\n";
   std::cerr << "  --set-display-mode <mode>     Write the display mode at boot\n";
   std::cerr << "  --clear-display-mode          Clear the display mode at boot\n";
+  std::cerr << "  --set-trending-issue-pattern <string within 2000 byte> Write a regex string";
+  std::cerr << "  --read-trending-issue-pattern Read eagleEye misc portion";
   std::cerr << "Writes the given hex string to the specified offset in vendor space in /misc "
                "partition.\nDefault offset is used for each action unless "
                "--override-vendor-space-offset is specified.\n";
@@ -85,6 +87,8 @@ int main(int argc, char** argv) {
     { "set-dstoffset", required_argument, nullptr, 0 },
     { "set-display-mode", required_argument, nullptr, 0 },
     { "clear-display-mode", no_argument, nullptr, 0 },
+    { "set-trending-issue-pattern", required_argument, nullptr, 0 },
+    { "read-trending-issue-pattern", no_argument, nullptr, 0 },
     { nullptr, 0, nullptr, 0 },
   };
 
@@ -254,6 +258,26 @@ int main(int argc, char** argv) {
       }
       misc_writer = std::make_unique<MiscWriter>(MiscWriterActions::kWriteDstOffset,
                                                      std::to_string(dst_offset));
+    } else if (option_name == "set-trending-issue-pattern"s) {
+      if (argc != 3) {
+        std::cerr << "Not the right amount of arguements, we expect 1 argument but were provide " << argc - 2;
+        return EXIT_FAILURE;
+      }
+      if (misc_writer) {
+        LOG(ERROR) << "Misc writer action has already been set";
+        return Usage(argv[0]);
+      } else if (sizeof(argv[2]) >= 2000) {
+        std::cerr << "String is too large, we only take strings smaller than 2000, but you provide " << sizeof(argv[2]);
+        return Usage(argv[0]);
+      }
+      misc_writer = std::make_unique<MiscWriter>(MiscWriterActions::kWriteEagleEyePatterns, argv[2]);
+    } else if (option_name == "read-trending-issue-pattern"s) {
+      if (misc_writer) {
+        LOG(ERROR) << "Misc writer action has already been set";
+        return Usage(argv[0]);
+      }
+      std::cerr << "function is not yet implemented";
+      return EXIT_SUCCESS;
     } else {
       LOG(FATAL) << "Unreachable path, option_name: " << option_name;
     }
diff --git a/mm/fstab.zram.3g b/mm/fstab.zram.3g
index 2c45bcc6..02d7b5aa 100644
--- a/mm/fstab.zram.3g
+++ b/mm/fstab.zram.3g
@@ -1 +1 @@
-/dev/block/zram0	none	swap	defaults	zramsize=3221225472,zram_backingdev_size=512M
+/dev/block/zram0	none	swap	defaults	zramsize=3221225472,zram_backingdev_size=1G
diff --git a/mm/fstab.zram.50p b/mm/fstab.zram.50p
index 7a845e55..6f54d6f4 100644
--- a/mm/fstab.zram.50p
+++ b/mm/fstab.zram.50p
@@ -1 +1 @@
-/dev/block/zram0	none	swap	defaults	zramsize=50%,zram_backingdev_size=512M
+/dev/block/zram0	none	swap	defaults	zramsize=50%,zram_backingdev_size=1G
diff --git a/pixelstats/Android.bp b/pixelstats/Android.bp
index 643b884f..6f3cdf31 100644
--- a/pixelstats/Android.bp
+++ b/pixelstats/Android.bp
@@ -17,6 +17,16 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+filegroup {
+    name: "pixelatoms_proto",
+    srcs: [
+        "pixelatoms.proto",
+        ":libstats_shared_enum_protos",
+        ":libstats_atom_options_protos",
+        ":libprotobuf-internal-descriptor-proto",
+    ],
+}
+
 cc_library {
     name: "pixelatoms-cpp",
     vendor: true,
@@ -74,16 +84,15 @@ java_library_host {
 genrule {
     name: "pixelatoms_defs.h",
     tools: ["stats-log-api-gen"],
-    cmd: "$(location stats-log-api-gen) --header $(genDir)/pixelatoms_defs.h --namespace hardware,google,pixel,PixelAtoms --vendor-proto $(location pixelatoms.proto)",
-    srcs: [
-        "pixelatoms.proto",
-        ":libstats_shared_enum_protos",
-        ":libstats_atom_options_protos",
-        ":libprotobuf-internal-protos",
-    ],
+    cmd: "$(location stats-log-api-gen) --header $(out)" +
+        " --namespace hardware,google,pixel,PixelAtoms" +
+        " --vendor-proto hardware/google/pixel/pixelstats/pixelatoms.proto",
     out: [
         "pixelatoms_defs.h",
     ],
+    srcs: [
+        ":pixelatoms_proto",
+    ],
 }
 
 cc_library {
@@ -99,15 +108,12 @@ genrule {
     cmd: "$(location stats-log-api-gen) --header $(out)" +
         " --module pixelstats" +
         " --namespace android,hardware,google,pixel,PixelAtoms" +
-        " --vendor-proto $(location pixelatoms.proto)",
+        " --vendor-proto hardware/google/pixel/pixelstats/pixelatoms.proto",
     out: [
         "pixelstatsatoms.h",
     ],
     srcs: [
-        "pixelatoms.proto",
-        ":libstats_shared_enum_protos",
-        ":libstats_atom_options_protos",
-        ":libprotobuf-internal-protos",
+        ":pixelatoms_proto",
     ],
 }
 
@@ -118,15 +124,12 @@ genrule {
         " --module pixelstats" +
         " --importHeader pixelstatsatoms.h" +
         " --namespace android,hardware,google,pixel,PixelAtoms" +
-        " --vendor-proto $(location pixelatoms.proto)",
+        " --vendor-proto hardware/google/pixel/pixelstats/pixelatoms.proto",
     out: [
         "pixelstatsatoms.cpp",
     ],
     srcs: [
-        "pixelatoms.proto",
-        ":libstats_shared_enum_protos",
-        ":libstats_atom_options_protos",
-        ":libprotobuf-internal-protos",
+        ":pixelatoms_proto",
     ],
 }
 
@@ -196,10 +199,3 @@ cc_library {
     ],
     header_libs: ["chre_api"],
 }
-
-filegroup {
-    name: "pixelatoms_proto",
-    srcs: [
-        "pixelatoms.proto",
-    ],
-}
diff --git a/pixelstats/BatteryEEPROMReporter.cpp b/pixelstats/BatteryEEPROMReporter.cpp
index 2316a0e3..4f73b6d1 100644
--- a/pixelstats/BatteryEEPROMReporter.cpp
+++ b/pixelstats/BatteryEEPROMReporter.cpp
@@ -43,6 +43,14 @@ using android::hardware::google::pixel::PixelAtoms::BatteryEEPROM;
 
 BatteryEEPROMReporter::BatteryEEPROMReporter() {}
 
+void BatteryEEPROMReporter::setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset,
+                                              int content) {
+    std::vector<VendorAtomValue> &val = *values;
+
+    if (offset - kVendorAtomOffset < val.size())
+        val[offset - kVendorAtomOffset].set<VendorAtomValue::intValue>(content);
+}
+
 void BatteryEEPROMReporter::checkAndReport(const std::shared_ptr<IStats> &stats_client,
                                            const std::string &path) {
     std::string file_contents;
@@ -270,6 +278,52 @@ void BatteryEEPROMReporter::reportEvent(const std::shared_ptr<IStats> &stats_cli
         ALOGE("Unable to report BatteryEEPROM to Stats service");
 }
 
+void BatteryEEPROMReporter::reportEventInt32(const std::shared_ptr<IStats> &stats_client,
+                                             const struct BatteryHistoryInt32 &hist) {
+    std::vector<VendorAtomValue> values(23);
+
+    ALOGD("reportEvent: cycle_cnt:%d, full_cap:%d, esr:%d, rslow:%d, soh:%d, "
+          "batt_temp:%d, cutoff_soc:%d, cc_soc:%d, sys_soc:%d, msoc:%d, "
+          "batt_soc:%d, reserve:%d, max_temp:%d, min_temp:%d, max_vbatt:%d, "
+          "min_vbatt:%d, max_ibatt:%d, min_ibatt:%d, checksum:%#x, full_rep:%d, "
+          "tempco:%#x, rcomp0:%#x, timer_h:%d",
+          hist.cycle_cnt, hist.full_cap, hist.esr, hist.rslow, hist.soh, hist.batt_temp,
+          hist.cutoff_soc, hist.cc_soc, hist.sys_soc, hist.msoc, hist.batt_soc, hist.reserve,
+          hist.max_temp, hist.min_temp, hist.max_vbatt, hist.min_vbatt, hist.max_ibatt,
+          hist.min_ibatt, hist.checksum, hist.full_rep, hist.tempco, hist.rcomp0, hist.timer_h);
+
+    setAtomFieldValue(&values, BatteryEEPROM::kCycleCntFieldNumber, hist.cycle_cnt);
+    setAtomFieldValue(&values, BatteryEEPROM::kFullCapFieldNumber, hist.full_cap);
+    setAtomFieldValue(&values, BatteryEEPROM::kEsrFieldNumber, hist.esr);
+    setAtomFieldValue(&values, BatteryEEPROM::kRslowFieldNumber, hist.rslow);
+    setAtomFieldValue(&values, BatteryEEPROM::kSohFieldNumber, hist.soh);
+    setAtomFieldValue(&values, BatteryEEPROM::kBattTempFieldNumber, hist.batt_temp);
+    setAtomFieldValue(&values, BatteryEEPROM::kCutoffSocFieldNumber, hist.cutoff_soc);
+    setAtomFieldValue(&values, BatteryEEPROM::kCcSocFieldNumber, hist.cc_soc);
+    setAtomFieldValue(&values, BatteryEEPROM::kSysSocFieldNumber, hist.sys_soc);
+    setAtomFieldValue(&values, BatteryEEPROM::kMsocFieldNumber, hist.msoc);
+    setAtomFieldValue(&values, BatteryEEPROM::kBattSocFieldNumber, hist.batt_soc);
+    setAtomFieldValue(&values, BatteryEEPROM::kReserveFieldNumber, hist.reserve);
+    setAtomFieldValue(&values, BatteryEEPROM::kMaxTempFieldNumber, hist.max_temp);
+    setAtomFieldValue(&values, BatteryEEPROM::kMinTempFieldNumber, hist.min_temp);
+    setAtomFieldValue(&values, BatteryEEPROM::kMaxVbattFieldNumber, hist.max_vbatt);
+    setAtomFieldValue(&values, BatteryEEPROM::kMinVbattFieldNumber, hist.min_vbatt);
+    setAtomFieldValue(&values, BatteryEEPROM::kMaxIbattFieldNumber, hist.max_ibatt);
+    setAtomFieldValue(&values, BatteryEEPROM::kMinIbattFieldNumber, hist.min_ibatt);
+    setAtomFieldValue(&values, BatteryEEPROM::kChecksumFieldNumber, hist.checksum);
+    setAtomFieldValue(&values, BatteryEEPROM::kTempcoFieldNumber, hist.tempco);
+    setAtomFieldValue(&values, BatteryEEPROM::kRcomp0FieldNumber, hist.rcomp0);
+    setAtomFieldValue(&values, BatteryEEPROM::kTimerHFieldNumber, hist.timer_h);
+    setAtomFieldValue(&values, BatteryEEPROM::kFullRepFieldNumber, hist.full_rep);
+
+    VendorAtom event = {.reverseDomainName = "",
+                        .atomId = PixelAtoms::Atom::kBatteryEeprom,
+                        .values = std::move(values)};
+    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
+    if (!ret.isOk())
+        ALOGE("Unable to report BatteryEEPROM to Stats service");
+}
+
 void BatteryEEPROMReporter::checkAndReportGMSR(const std::shared_ptr<IStats> &stats_client,
                                                const std::vector<std::string> &paths) {
     struct BatteryHistory gmsr = {.checksum = EvtGMSR};
@@ -427,104 +481,98 @@ void BatteryEEPROMReporter::checkAndReportFGModelLoading(const std::shared_ptr<I
 
 void BatteryEEPROMReporter::checkAndReportFGLearning(const std::shared_ptr<IStats> &stats_client,
                                                      const std::vector<std::string> &paths) {
-    struct BatteryHistory params = {.checksum = EvtFGLearningHistory};
+    struct BatteryHistoryInt32 params = {.checksum = EvtFGLearningHistory};
+    std::string path;
     struct timespec boot_time;
     auto format = FormatIgnoreAddr;
-    int fg_idx = 0;
+    std::vector<std::vector<uint32_t>> events;
 
     if (paths.empty())
         return;
 
+    for (int i = 0; i < paths.size(); i++) {
+        if (fileExists(paths[i])) {
+            path = paths[i];
+            break;
+        }
+    }
+
+    /* not found */
+    if (path.empty())
+        return;
+
     clock_gettime(CLOCK_MONOTONIC, &boot_time);
-    for (int path_idx = 0; path_idx < paths.size(); path_idx++) {
-        std::vector<std::vector<uint16_t>> events;
-        std::string path = paths[path_idx];
-
-        if (!path.empty() && fileExists(path)) {
-            readLogbuffer(path, kNumFGLearningFieldsV2, params.checksum, format, last_lh_check_,
-                          events);
-            if (events.size() == 0)
-                readLogbuffer(path, kNumFGLearningFieldsV2, "learn", format, last_lh_check_,
-                              events);
-            if (events.size() == 0)
-                readLogbuffer(path, kNumFGLearningFields, "learn", format, last_lh_check_, events);
-
-            for (int event_idx = 0; event_idx < events.size(); event_idx++) {
-                std::vector<uint16_t> &event = events[event_idx];
-
-                if (event.size() == kNumFGLearningFieldsV2) {
-                    params.full_cap = event[0];                /* fcnom */
-                    params.esr = event[1];                     /* dpacc */
-                    params.rslow = event[2];                   /* dqacc */
-                    params.full_rep = event[3];                /* fcrep */
-                    params.msoc = (uint8_t)(event[4] >> 8);    /* repsoc */
-                    params.sys_soc = (uint8_t)(event[5] >> 8); /* mixsoc */
-                    params.batt_soc = (uint8_t)(event[6] >> 8);/* vfsoc */
-                    params.min_ibatt = event[7];               /* fstats */
-                    params.max_temp = (int8_t)(event[8] >> 8); /* avgtemp */
-                    params.min_temp = (int8_t)(event[9] >> 8); /* temp */
-                    params.max_ibatt = event[10];              /* qh */
-                    params.max_vbatt = event[11];              /* vcell */
-                    params.min_vbatt = event[12];              /* avgvcell */
-                    params.cycle_cnt = event[13];              /* vfocf */
-                    params.rcomp0 = event[14];                 /* rcomp0 */
-                    params.tempco = event[15];                 /* tempco */
-                    params.reserve = fg_idx  ;                 /* battery index */
-                } else if (event.size() == kNumFGLearningFields) {
-                    params.full_cap = event[0];     /* fcnom */
-                    params.esr = event[1];          /* dpacc */
-                    params.rslow = event[2];        /* dqacc */
-                    params.max_vbatt = event[3];    /* fcrep */
-                    params.full_rep = event[4];     /* repsoc */
-                    params.min_vbatt = event[5];    /* mixsoc */
-                    params.max_ibatt = event[6];    /* vfsoc */
-                    params.min_ibatt = event[7];    /* fstats */
-                    params.rcomp0 = event[8];       /* rcomp0 */
-                    params.tempco = event[9];       /* tempco */
-                    params.reserve = fg_idx;        /* battery index */
-                } else {
-                    ALOGE("Not support %zu fields for FG learning event", event.size());
-                    continue;
-                }
-                reportEvent(stats_client, params);
-            }
-            fg_idx++;
+
+    readLogbuffer(path, kNumFGLearningFieldsV3, params.checksum, format, last_lh_check_, events);
+    if (events.size() == 0)
+        readLogbuffer(path, kNumFGLearningFieldsV2, params.checksum, format, last_lh_check_, events);
+
+    for (int event_idx = 0; event_idx < events.size(); event_idx++) {
+        std::vector<uint32_t> &event = events[event_idx];
+        if (event.size() == kNumFGLearningFieldsV2 ||
+            event.size() == kNumFGLearningFieldsV3) {
+            params.full_cap = event[0];                /* fcnom */
+            params.esr = event[1];                     /* dpacc */
+            params.rslow = event[2];                   /* dqacc */
+            params.full_rep = event[3];                /* fcrep */
+            params.msoc = (uint8_t)(event[4] >> 8);    /* repsoc */
+            params.sys_soc = (uint8_t)(event[5] >> 8); /* mixsoc */
+            params.batt_soc = (uint8_t)(event[6] >> 8);/* vfsoc */
+            params.min_ibatt = event[7];               /* fstats */
+            params.max_temp = (int8_t)(event[8] >> 8); /* avgtemp */
+            params.min_temp = (int8_t)(event[9] >> 8); /* temp */
+            params.max_ibatt = event[10];              /* qh */
+            params.max_vbatt = event[11];              /* vcell */
+            params.min_vbatt = event[12];              /* avgvcell */
+            params.cycle_cnt = event[13];              /* vfocf */
+            params.rcomp0 = event[14];                 /* rcomp0 */
+            params.tempco = event[15];                 /* tempco */
+            if (event.size() == kNumFGLearningFieldsV3)
+                params.soh = event[16];                /* unix time */
+        } else {
+            ALOGE("Not support %zu fields for FG learning event", event.size());
+            continue;
         }
+        reportEventInt32(stats_client, params);
     }
     last_lh_check_ = (unsigned int)boot_time.tv_sec;
 }
 
 void BatteryEEPROMReporter::checkAndReportValidation(const std::shared_ptr<IStats> &stats_client,
                                                      const std::vector<std::string> &paths) {
-    struct BatteryHistory params = {.checksum = EvtHistoryValidation};
+    struct BatteryHistoryInt32 params = {.checksum = EvtHistoryValidation};
+    std::string path;
     struct timespec boot_time;
     auto format = FormatIgnoreAddr;
-    int fg_idx = 0;
+    std::vector<std::vector<uint32_t>> events;
 
     if (paths.empty())
         return;
 
-    clock_gettime(CLOCK_MONOTONIC, &boot_time);
     for (int i = 0; i < paths.size(); i++) {
-        std::vector<std::vector<uint16_t>> events;
-        std::string path = paths[i];
-
-        if (!path.empty() && fileExists(path)) {
-            readLogbuffer(path, kNumValidationFields, params.checksum, format, last_hv_check_, events);
-            for (int seq = 0; seq < events.size(); seq++) {
-                std::vector<uint16_t> &event = events[seq];
-                if (event.size() == kNumValidationFields) {
-                    params.full_cap = event[0]; /* fcnom */
-                    params.esr = event[1];      /* dpacc */
-                    params.rslow = event[2];    /* dqacc */
-                    params.full_rep = event[3]; /* fcrep */
-                    params.reserve = fg_idx;
-                    reportEvent(stats_client, params);
-                } else {
-                    ALOGE("Not support %zu fields for History Validation event", event.size());
-                }
-            }
-            fg_idx++;
+        if (fileExists(paths[i])) {
+            path = paths[i];
+            break;
+        }
+    }
+
+    /* not found */
+    if (path.empty())
+        return;
+
+    clock_gettime(CLOCK_MONOTONIC, &boot_time);
+
+    readLogbuffer(path, kNumValidationFields, params.checksum, format, last_hv_check_, events);
+    for (int event_idx = 0; event_idx < events.size(); event_idx++) {
+        std::vector<uint32_t> &event = events[event_idx];
+        if (event.size() == kNumValidationFields) {
+            params.full_cap = event[0]; /* fcnom */
+            params.esr = event[1];      /* dpacc */
+            params.rslow = event[2];    /* dqacc */
+            params.full_rep = event[3]; /* fcrep */
+            reportEventInt32(stats_client, params);
+        } else {
+            ALOGE("Not support %zu fields for History Validation event", event.size());
         }
     }
     last_hv_check_ = (unsigned int)boot_time.tv_sec;
diff --git a/pixelstats/BatteryFGReporter.cpp b/pixelstats/BatteryFGReporter.cpp
index aa928d55..9808b458 100644
--- a/pixelstats/BatteryFGReporter.cpp
+++ b/pixelstats/BatteryFGReporter.cpp
@@ -251,7 +251,7 @@ void BatteryFGReporter::checkAndReportFGAbnormality(const std::shared_ptr<IStats
                                                     const std::vector<std::string> &paths) {
     std::string path;
     struct timespec boot_time;
-    std::vector<std::vector<uint16_t>> events;
+    std::vector<std::vector<uint32_t>> events;
 
     if (paths.empty())
         return;
@@ -264,7 +264,7 @@ void BatteryFGReporter::checkAndReportFGAbnormality(const std::shared_ptr<IStats
     }
 
     clock_gettime(CLOCK_MONOTONIC, &boot_time);
-    readLogbuffer(path, kNumAbnormalEventFields, EvtFGAbnormalEvent, FormatNoAddr, last_ab_check_, events);
+    readLogbuffer(path, kNumAbnormalEventFields, EvtFGAbnormalEvent, FormatOnlyVal, last_ab_check_, events);
     for (int seq = 0; seq < events.size(); seq++) {
         if (events[seq].size() == kNumAbnormalEventFields) {
             struct BatteryFGAbnormalData data;
diff --git a/pixelstats/DisplayStatsReporter.cpp b/pixelstats/DisplayStatsReporter.cpp
index c72af6e4..67178cbf 100644
--- a/pixelstats/DisplayStatsReporter.cpp
+++ b/pixelstats/DisplayStatsReporter.cpp
@@ -320,6 +320,146 @@ void DisplayStatsReporter::logHDCPAuthTypeStats(const std::shared_ptr<IStats> &s
     if (!ret.isOk())
         ALOGE("Unable to report hdcp stats to Stats service");
 }
+
+// Capture dsc/fec support from sysfs nodes
+bool DisplayStatsReporter::captureDisplayPortFECDSCStats(
+        const std::vector<std::string> &displayport_fecdsc_stats_paths, int64_t *pcur_data) {
+    bool report_stats = false;
+    std::string path;
+
+    if (displayport_fecdsc_stats_paths.size() < DISPLAY_PORT_DSC_STATS_SIZE) {
+        ALOGE("Number of displayport dsc support stats paths (%zu) is less than expected (%d)",
+              displayport_fecdsc_stats_paths.size(), DISPLAY_PORT_DSC_STATS_SIZE);
+        return false;
+    }
+
+    // Iterate over the sysfs nodes and collect the data
+    for (int i = 0; i < DISPLAY_PORT_DSC_STATS_SIZE; i++) {
+        // Get the sysfs path from the stats path array
+        path = displayport_fecdsc_stats_paths[i];
+
+        if (!readDisplayErrorCount(path, &(pcur_data[i]))) {
+            // Failed to read new data, keep previous data that was saved.
+            pcur_data[i] = prev_dp_dsc_data_[i];
+        } else {
+            report_stats |= (pcur_data[i] > prev_dp_dsc_data_[i]);
+        }
+    }
+
+    return report_stats;
+}
+
+void DisplayStatsReporter::logDisplayPortFECDSCStats(
+        const std::shared_ptr<IStats> &stats_client,
+        const std::vector<std::string> &displayport_fecdsc_stats_paths) {
+    int64_t cur_data[DISPLAY_PORT_DSC_STATS_SIZE];
+    bool report_stats = false;
+
+    memcpy(cur_data, prev_dp_dsc_data_, sizeof(prev_dp_dsc_data_));
+    if (!captureDisplayPortFECDSCStats(displayport_fecdsc_stats_paths, &cur_data[0])) {
+        memcpy(prev_dp_dsc_data_, cur_data, sizeof(cur_data));
+        return;
+    }
+
+    VendorAtomValue tmp;
+    int64_t max_use_count = static_cast<int64_t>(INT32_MAX);
+    int use_count;
+    std::vector<VendorAtomValue> values(DISPLAY_PORT_DSC_STATS_SIZE);
+
+    for (int i = 0; i < DISPLAY_PORT_DSC_STATS_SIZE; i++) {
+        use_count = std::min<int64_t>(cur_data[i] - prev_dp_dsc_data_[i], max_use_count);
+        if (verifyCount(use_count, &report_stats) < 0)
+            return;
+
+        tmp.set<VendorAtomValue::intValue>(use_count);
+        values[i] = tmp;
+    }
+
+    memcpy(prev_dp_dsc_data_, cur_data, sizeof(cur_data));
+
+    if (!report_stats)
+        return;
+
+    ALOGD("Report updated DisplayPort FEC/DSC metrics to stats service");
+    // Send vendor atom to IStats HAL
+    VendorAtom event = {.reverseDomainName = "",
+                        .atomId = PixelAtoms::Atom::kDisplayPortDscSupportStats,
+                        .values = std::move(values)};
+    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
+    if (!ret.isOk())
+        ALOGE("Unable to report DisplayPort FEC/DSC stats to Stats service");
+}
+
+// Capture maximum resolution support from sysfs nodes
+bool DisplayStatsReporter::captureDisplayPortMaxResStats(
+        const std::vector<std::string> &displayport_max_res_stats_paths, int64_t *pcur_data) {
+    bool report_stats = false;
+    std::string path;
+
+    if (displayport_max_res_stats_paths.size() < DISPLAY_PORT_MAX_RES_STATS_SIZE) {
+        ALOGE("Number of displayport maximum resolution stats paths (%zu) is less than expected "
+              "(%d)",
+              displayport_max_res_stats_paths.size(), DISPLAY_PORT_MAX_RES_STATS_SIZE);
+        return false;
+    }
+
+    // Iterate over the sysfs nodes and collect the data
+    for (int i = 0; i < DISPLAY_PORT_MAX_RES_STATS_SIZE; i++) {
+        // Get the sysfs path from the stats path array
+        path = displayport_max_res_stats_paths[i];
+
+        if (!readDisplayErrorCount(path, &(pcur_data[i]))) {
+            // Failed to read new data, keep previous data that was saved.
+            pcur_data[i] = prev_dp_max_res_data_[i];
+        } else {
+            report_stats |= (pcur_data[i] > prev_dp_max_res_data_[i]);
+        }
+    }
+
+    return report_stats;
+}
+
+void DisplayStatsReporter::logDisplayPortMaxResStats(
+        const std::shared_ptr<IStats> &stats_client,
+        const std::vector<std::string> &displayport_max_res_stats_paths) {
+    int64_t cur_data[DISPLAY_PORT_MAX_RES_STATS_SIZE];
+    bool report_stats = false;
+
+    memcpy(cur_data, prev_dp_max_res_data_, sizeof(prev_dp_max_res_data_));
+    if (!captureDisplayPortMaxResStats(displayport_max_res_stats_paths, &cur_data[0])) {
+        memcpy(prev_dp_max_res_data_, cur_data, sizeof(cur_data));
+        return;
+    }
+
+    VendorAtomValue tmp;
+    int64_t max_use_count = static_cast<int64_t>(INT32_MAX);
+    int use_count;
+    std::vector<VendorAtomValue> values(DISPLAY_PORT_MAX_RES_STATS_SIZE);
+
+    for (int i = 0; i < DISPLAY_PORT_MAX_RES_STATS_SIZE; i++) {
+        use_count = std::min<int64_t>(cur_data[i] - prev_dp_max_res_data_[i], max_use_count);
+        if (verifyCount(use_count, &report_stats) < 0)
+            return;
+
+        tmp.set<VendorAtomValue::intValue>(use_count);
+        values[i] = tmp;
+    }
+
+    memcpy(prev_dp_max_res_data_, cur_data, sizeof(cur_data));
+
+    if (!report_stats)
+        return;
+
+    ALOGD("Report updated displayport maximum resolution metrics to stats service");
+    // Send vendor atom to IStats HAL
+    VendorAtom event = {.reverseDomainName = "",
+                        .atomId = PixelAtoms::Atom::kDisplayPortMaxResolutionStats,
+                        .values = std::move(values)};
+    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
+    if (!ret.isOk())
+        ALOGE("Unable to report DisplayPort maximum resolution stats to Stats service");
+}
+
 void DisplayStatsReporter::logDisplayStats(const std::shared_ptr<IStats> &stats_client,
                                            const std::vector<std::string> &display_stats_paths,
                                            const display_stats_type stats_type) {
@@ -333,6 +473,12 @@ void DisplayStatsReporter::logDisplayStats(const std::shared_ptr<IStats> &stats_
         case HDCP_STATE:
             logHDCPAuthTypeStats(stats_client, display_stats_paths);
             break;
+        case DISP_PORT_DSC_STATE:
+            logDisplayPortFECDSCStats(stats_client, display_stats_paths);
+            break;
+        case DISP_PORT_MAX_RES_STATE:
+            logDisplayPortMaxResStats(stats_client, display_stats_paths);
+            break;
         default:
             ALOGE("Unsupport display state type(%d)", stats_type);
     }
diff --git a/pixelstats/MmMetricsReporter.cpp b/pixelstats/MmMetricsReporter.cpp
index ac6c2586..a74d88c3 100644
--- a/pixelstats/MmMetricsReporter.cpp
+++ b/pixelstats/MmMetricsReporter.cpp
@@ -28,10 +28,16 @@
 #include <pixelstats/MmMetricsReporter.h>
 #include <sys/stat.h>
 #include <sys/types.h>
+#include <time.h>
 #include <unistd.h>
 #include <utils/Log.h>
 
+#include <array>
+#include <cinttypes>
+#include <cstdint>
 #include <numeric>
+#include <optional>
+#include <vector>
 
 #define SZ_4K 0x00001000
 #define SZ_2M 0x00200000
@@ -124,7 +130,15 @@ const std::vector<MmMetricsReporter::MmMetricsInfo> MmMetricsReporter::kCmaStatu
         {"latency_high", CmaStatusExt::kCmaAllocLatencyHighFieldNumber, false},
 };
 
-static bool file_exists(const char *path) {
+// Oom group range names
+const std::array oom_group_range_names{
+        "[951,1000]", "[901,950]", "[851,900]", "[801,850]", "[751,800]",  "[701,750]",
+        "[651,700]",  "[601,650]", "[551,600]", "[501,550]", "[451,500]",  "[401,450]",
+        "[351,400]",  "[301,350]", "[251,300]", "[201,250]", "[200,200]",  "[151,199]",
+        "[101,150]",  "[51,100]",  "[1,50]",    "[0,0]",     "[-1000,-1]",
+};
+
+static bool file_exists(const char *const path) {
     struct stat sbuf;
 
     return (stat(path, &sbuf) == 0);
@@ -166,6 +180,30 @@ bool MmMetricsReporter::checkKernelMMMetricSupport() {
     return !err_require_all && !err_require_one_ion_total_pools_path;
 }
 
+bool MmMetricsReporter::checkKernelOomUsageSupport() {
+    if (!file_exists(kProcVendorMmUsageByOom)) {
+        ALOGE("Oom score grouped memory usage metrics not supported"
+              " - %s not found.",
+              kProcVendorMmUsageByOom);
+        return false;
+    }
+    return true;
+}
+
+bool MmMetricsReporter::checkKernelGcmaSupport() {
+    std::string base_path(kGcmaBasePath);
+
+    for (auto parr : {kGcmaHourlySimpleKnobs, kGcmaHourlyHistogramKnobs}) {
+        for (auto p : kGcmaHourlySimpleKnobs) {
+            if (!file_exists((base_path + '/' + p).c_str())) {
+                ALOGE("kernel GCMA metrics not supported- %s not found.", p);
+                return false;
+            }
+        }
+    }
+    return true;
+}
+
 MmMetricsReporter::MmMetricsReporter()
     : kVmstatPath("/proc/vmstat"),
       kIonTotalPoolsPath("/sys/kernel/dma_heap/total_pools_kb"),
@@ -176,9 +214,13 @@ MmMetricsReporter::MmMetricsReporter()
       kPixelStatMm("/sys/kernel/pixel_stat/mm"),
       kMeminfoPath("/proc/meminfo"),
       kProcStatPath("/proc/stat"),
+      kProcVendorMmUsageByOom("/proc/vendor_mm/memory_usage_by_oom_score"),
+      kGcmaBasePath("/sys/kernel/vendor_mm/gcma"),
       prev_compaction_duration_(kNumCompactionDurationPrevMetrics, 0),
       prev_direct_reclaim_(kNumDirectReclaimPrevMetrics, 0) {
     ker_mm_metrics_support_ = checkKernelMMMetricSupport();
+    ker_oom_usage_support_ = checkKernelOomUsageSupport();
+    ker_gcma_support_ = checkKernelGcmaSupport();
 }
 
 bool MmMetricsReporter::ReadFileToUint(const std::string &path, uint64_t *val) {
@@ -632,6 +674,30 @@ void MmMetricsReporter::logPixelMmMetricsPerHour(const std::shared_ptr<IStats> &
     }
 }
 
+void MmMetricsReporter::logGcmaPerHour(const std::shared_ptr<IStats> &stats_client) {
+    std::vector<VendorAtomValue> values = readAndGenGcmaPerHour();
+
+    if (values.size() != 0) {
+        reportVendorAtom(stats_client, PixelAtoms::Atom::kMmGcmaSnapshot, values, "MmGcmaSnapshot");
+    }
+}
+
+void MmMetricsReporter::logMmProcessUsageByOomGroupSnapshot(
+        const std::shared_ptr<IStats> &stats_client) {
+    if (!OomUsageSupoorted())
+        return;
+
+    std::vector<MmMetricsReporter::OomGroupMemUsage> ogusage;
+    if (!readMmProcessUsageByOomGroup(&ogusage))
+        return;
+
+    for (const auto &m : ogusage) {
+        std::vector<VendorAtomValue> values = genMmProcessUsageByOomGroupSnapshotAtom(m);
+        reportVendorAtom(stats_client, PixelAtoms::Atom::kMmProcessUsageByOomGroupSnapshot, values,
+                         "MmProcessUsageByOomGroup");
+    }
+}
+
 std::vector<VendorAtomValue> MmMetricsReporter::genPixelMmMetricsPerHour() {
     if (!MmMetricsSupported())
         return std::vector<VendorAtomValue>();
@@ -674,6 +740,14 @@ void MmMetricsReporter::logPixelMmMetricsPerDay(const std::shared_ptr<IStats> &s
     }
 }
 
+void MmMetricsReporter::logGcmaPerDay(const std::shared_ptr<IStats> &stats_client) {
+    std::vector<VendorAtomValue> values = readAndGenGcmaPerDay();
+
+    if (values.size() != 0) {
+        reportVendorAtom(stats_client, PixelAtoms::Atom::kMmGcmaStats, values, "MmGcmaStats");
+    }
+}
+
 std::vector<VendorAtomValue> MmMetricsReporter::genPixelMmMetricsPerDay() {
     if (!MmMetricsSupported())
         return std::vector<VendorAtomValue>();
@@ -1516,6 +1590,168 @@ void MmMetricsReporter::logCmaStatus(const std::shared_ptr<IStats> &stats_client
     }
 }
 
+/*
+ * parse one line of proc fs "vendor_mm/memory_usage_by_oom_score"
+ */
+std::optional<MmMetricsReporter::OomGroupMemUsage>
+MmMetricsReporter::parseMmProcessUsageByOomGroupLine(const std::string &line) {
+    static_assert(OOM_NUM_OF_GROUPS == oom_group_range_names.size(),
+                  "Error: Number of groups must match.");
+
+    std::vector<std::string> tokens = android::base::Tokenize(line, " \t");
+    if (tokens.size() < 7) {
+        ALOGE("Error: Insufficient tokens on line: %s", line.c_str());
+        return std::nullopt;
+    }
+
+    MmMetricsReporter::OomGroupMemUsage data;
+
+    // Find the matching group range name and convert it to enumerate:int32_t
+    auto it = std::find(oom_group_range_names.begin(), oom_group_range_names.end(), tokens[0]);
+    if (it == oom_group_range_names.end()) {
+        ALOGE("Error: Unknown group range: %s", tokens[0].c_str());
+        return std::nullopt;
+    }
+    data.oom_group =
+            static_cast<OomScoreAdjGroup>(std::distance(oom_group_range_names.begin(), it));
+
+    bool success = android::base::ParseInt(tokens[1], &data.nr_task) &&
+                   android::base::ParseInt(tokens[2], &data.file_rss_kb) &&
+                   android::base::ParseInt(tokens[3], &data.anon_rss_kb) &&
+                   android::base::ParseInt(tokens[4], &data.pgtable_kb) &&
+                   android::base::ParseInt(tokens[5], &data.swap_ents_kb) &&
+                   android::base::ParseInt(tokens[6], &data.shmem_rss_kb) && data.nr_task >= 0 &&
+                   data.file_rss_kb >= 0 && data.anon_rss_kb >= 0 && data.pgtable_kb >= 0 &&
+                   data.swap_ents_kb >= 0 && data.shmem_rss_kb >= 0;
+
+    if (!success) {
+        ALOGE("Error parsing UInt values on line: %s", line.c_str());
+        return std::nullopt;
+    }
+
+    return data;
+}
+
+/*
+ * read proc fs "vendor_mm/memory_usage_by_oom_score"
+ */
+bool MmMetricsReporter::readMmProcessUsageByOomGroup(
+        std::vector<MmMetricsReporter::OomGroupMemUsage> *ogusage) {
+    ogusage->clear();
+    oom_usage_uid_++;  // Unique ID per read
+    std::string path = getSysfsPath(kProcVendorMmUsageByOom);
+
+    std::string file_contents;
+    if (!android::base::ReadFileToString(path, &file_contents)) {
+        ALOGE("Error reading file: %s", path.c_str());
+        goto error_out;
+    }
+
+    for (const auto &line : android::base::Split(file_contents, "\n")) {
+        if (line.empty() || line[0] == '#')
+            continue;  // Skip the header line or an empty line
+        std::optional<MmMetricsReporter::OomGroupMemUsage> parsedData =
+                parseMmProcessUsageByOomGroupLine(line);
+        if (parsedData.has_value())
+            ogusage->push_back(parsedData.value());
+    }
+
+    if (ogusage->size() != OOM_NUM_OF_GROUPS) {
+        ALOGE("Error file corrupted: number of oom_group %zu != expected %" PRId32, ogusage->size(),
+              OOM_NUM_OF_GROUPS);
+        goto error_out;
+    }
+
+    for (size_t i = 0; i < ogusage->size(); ++i) {
+        if ((*ogusage)[i].oom_group != static_cast<int32_t>(i)) {
+            goto error_out;  // Mismatch found
+        }
+    }
+    return true;
+
+error_out:
+    ogusage->clear();
+    return false;
+}
+
+/*
+ * generate one MmProcessUsageByOomGroupSnapshot atom
+ * Note: number of atoms = number of oom groups
+ */
+std::vector<VendorAtomValue> MmMetricsReporter::genMmProcessUsageByOomGroupSnapshotAtom(
+        const MmMetricsReporter::OomGroupMemUsage &data) {
+    std::vector<VendorAtomValue> values;
+
+    values.push_back(VendorAtomValue(oom_usage_uid_));
+    values.push_back(VendorAtomValue(static_cast<int32_t>(data.oom_group)));
+    values.push_back(VendorAtomValue(data.nr_task));
+    values.push_back(VendorAtomValue(data.file_rss_kb));
+    values.push_back(VendorAtomValue(data.anon_rss_kb));
+    values.push_back(VendorAtomValue(data.pgtable_kb));
+    values.push_back(VendorAtomValue(data.swap_ents_kb));
+    values.push_back(VendorAtomValue(data.shmem_rss_kb));
+    return values;
+}
+
+std::vector<VendorAtomValue> MmMetricsReporter::readAndGenGcmaPerHour() {
+    uint64_t val;
+    std::string path = getSysfsPath(std::string(kGcmaBasePath) + '/' + kGcmaCached);
+    std::vector<VendorAtomValue> values;
+
+    if (!GcmaSupported())
+        return values;
+
+    if (!ReadFileToUint(path, &val)) {
+        ALOGE("Error: GCMA.cached: file %s: parsed Uint failed.", path.c_str());
+    } else if (static_cast<int64_t>(val) < 0) {
+        ALOGE("Error: GCMA.cached: value overflow.");
+    } else {
+        values.push_back(VendorAtomValue(static_cast<int64_t>(val)));
+    }
+    return values;
+}
+
+std::vector<VendorAtomValue> MmMetricsReporter::readAndGenGcmaPerDay() {
+    std::vector<VendorAtomValue> values;
+    uint64_t val;
+    std::vector<int64_t> repeatedLongValue;
+    std::string path;
+    std::string base_path(kGcmaBasePath);
+
+    if (!GcmaSupported())
+        return values;
+
+    for (auto p : kGcmaHourlySimpleKnobs) {
+        path = getSysfsPath(base_path + '/' + p);
+        if (!ReadFileToUint(path, &val)) {
+            ALOGE("Error: GCMA.%s: file %s: parsed Uint failed.", p, path.c_str());
+            goto got_error;
+        } else if (static_cast<int64_t>(val) < 0) {
+            ALOGE("Error: GCMA.%s: value overflow.", p);
+            goto got_error;
+        }
+        values.push_back(VendorAtomValue(static_cast<int64_t>(val)));
+    }
+
+    for (auto p : kGcmaHourlyHistogramKnobs) {
+        path = getSysfsPath(base_path + '/' + p);
+        if (!ReadFileToUint(path, &val)) {
+            ALOGE("Error: GCMA.%s: file %s: parsed Uint failed.", p, path.c_str());
+            goto got_error;
+        } else if (static_cast<int64_t>(val) < 0) {
+            ALOGE("Error: GCMA.%s: value overflow.", p);
+            goto got_error;
+        }
+        repeatedLongValue.push_back(static_cast<int64_t>(val));
+    }
+    values.push_back(VendorAtomValue(std::optional<std::vector<int64_t>>(repeatedLongValue)));
+    return values;
+
+got_error:
+    values.clear();
+    return values;
+}
+
 }  // namespace pixel
 }  // namespace google
 }  // namespace hardware
diff --git a/pixelstats/StatsHelper.cpp b/pixelstats/StatsHelper.cpp
index 0a1b752d..6fb93e4f 100644
--- a/pixelstats/StatsHelper.cpp
+++ b/pixelstats/StatsHelper.cpp
@@ -237,24 +237,14 @@ void reportUsbDataSessionEvent(const std::shared_ptr<IStats> &stats_client,
 
 void readLogbuffer(const std::string &buf_path, int num_fields, uint16_t code,
                    enum ReportEventFormat format, unsigned int last_check_time,
-                   std::vector<std::vector<uint16_t>> &events) {
-    char hex_str[16];
-
-    snprintf(hex_str, sizeof(hex_str), "0x%X", code);
-
-    return readLogbuffer(buf_path, num_fields, hex_str, format, last_check_time, events);
-}
-
-void readLogbuffer(const std::string &buf_path, int num_fields, const char *code,
-                   enum ReportEventFormat format, unsigned int last_check_time,
-                   std::vector<std::vector<uint16_t>> &events) {
+                   std::vector<std::vector<uint32_t>> &events) {
     std::istringstream ss;
     std::string file_contents, line;
     int num, field_idx, pos, read;
-    unsigned int ts, reported = 0;
-    uint16_t addr, val;
-    char type[16];
-    std::vector<uint16_t> vect(num_fields);
+    unsigned int ts, addr, val;
+    unsigned int reported = 0;
+    uint16_t type;
+    std::vector<uint32_t> vect(num_fields);
 
     if (!ReadFileToString(buf_path, &file_contents)) {
         ALOGE("Unable to read logbuffer path: %s - %s", buf_path.c_str(), strerror(errno));
@@ -263,30 +253,29 @@ void readLogbuffer(const std::string &buf_path, int num_fields, const char *code
 
     ss.str(file_contents);
     while (getline(ss, line)) {
-        num = sscanf(line.c_str(), "[%u.%*u] %15s%n", &ts, type, &pos);
-        if (num != 2 || strncmp(type, code, strlen(code)))
+        num = sscanf(line.c_str(), "[%u.%*u] %hx%n", &ts, &type, &pos);
+        if (num != 2 || type != code)
             continue;
 
-        if (ts <= last_check_time) {
+        if (last_check_time != 0 && ts <= last_check_time) {
             reported++;
             continue;
         }
 
         for (field_idx = 0; field_idx < num_fields; field_idx++, pos += read) {
             if (format == FormatAddrWithVal) {
-                num = sscanf(&line.c_str()[pos], " %2" SCNx16 ":%4" SCNx16 "%n", &addr, &val,
-                             &read);
+                num = sscanf(&line.c_str()[pos], "%x:%x%n", &addr, &val, &read);
                 if (num != 2 || (num_fields - field_idx < 2))
                     break;
                 vect[field_idx++] = addr;
                 vect[field_idx] = val;
             } else if (format == FormatIgnoreAddr) {
-                num = sscanf(&line.c_str()[pos], " %*2" SCNx16 ":%4" SCNx16 "%n", &val, &read);
+                num = sscanf(&line.c_str()[pos], "%*[^:]:%x%n", &val, &read);
                 if (num != 1)
                     break;
                 vect[field_idx] = val;
-            } else if (format == FormatNoAddr) {
-                 num = sscanf(&line.c_str()[pos], " %4" SCNx16 "%n", &val, &read);
+            } else if (format == FormatOnlyVal) {
+                 num = sscanf(&line.c_str()[pos], "%x%n", &val, &read);
                 if (num != 1)
                     break;
                 vect[field_idx] = val;
@@ -299,7 +288,7 @@ void readLogbuffer(const std::string &buf_path, int num_fields, const char *code
             events.push_back(vect);
     }
     if (events.size() > 0 || reported > 0)
-        ALOGD("%s: new:%zu, reported:%d", code, events.size(), reported);
+        ALOGD("0x%04X: new:%zu, reported:%d", code, events.size(), reported);
 
     return;
 }
diff --git a/pixelstats/SysfsCollector.cpp b/pixelstats/SysfsCollector.cpp
index aa0f2f68..0d570110 100644
--- a/pixelstats/SysfsCollector.cpp
+++ b/pixelstats/SysfsCollector.cpp
@@ -51,7 +51,9 @@ using android::hardware::google::pixel::PixelAtoms::BatteryCapacity;
 using android::hardware::google::pixel::PixelAtoms::BlockStatsReported;
 using android::hardware::google::pixel::PixelAtoms::BootStatsInfo;
 using android::hardware::google::pixel::PixelAtoms::DisplayPanelErrorStats;
+using android::hardware::google::pixel::PixelAtoms::DisplayPortDSCSupportCountStatsReported;
 using android::hardware::google::pixel::PixelAtoms::DisplayPortErrorStats;
+using android::hardware::google::pixel::PixelAtoms::DisplayPortMaxResolutionCountStatsReported;
 using android::hardware::google::pixel::PixelAtoms::F2fsAtomicWriteInfo;
 using android::hardware::google::pixel::PixelAtoms::F2fsCompressionInfo;
 using android::hardware::google::pixel::PixelAtoms::F2fsGcSegmentInfo;
@@ -123,6 +125,8 @@ SysfsCollector::SysfsCollector(const struct SysfsPaths &sysfs_paths)
       kWifiPcieLinkStatsPath(sysfs_paths.WifiPcieLinkStatsPath),
       kDisplayStatsPaths(sysfs_paths.DisplayStatsPaths),
       kDisplayPortStatsPaths(sysfs_paths.DisplayPortStatsPaths),
+      kDisplayPortDSCStatsPaths(sysfs_paths.DisplayPortDSCStatsPaths),
+      kDisplayPortMaxResolutionStatsPaths(sysfs_paths.DisplayPortMaxResolutionStatsPaths),
       kHDCPStatsPaths(sysfs_paths.HDCPStatsPaths),
       kPDMStatePath(sysfs_paths.PDMStatePath),
       kWavesPath(sysfs_paths.WavesPath),
@@ -470,6 +474,15 @@ void SysfsCollector::logThermalStats(const std::shared_ptr<IStats> &stats_client
     thermal_stats_reporter_.logThermalStats(stats_client, kThermalStatsPaths);
 }
 
+void SysfsCollector::logDisplayPortDSCStats(const std::shared_ptr<IStats> &stats_client) {
+    display_stats_reporter_.logDisplayStats(stats_client, kDisplayPortDSCStatsPaths,
+                                            DisplayStatsReporter::DISP_PORT_DSC_STATE);
+}
+
+void SysfsCollector::logDisplayPortMaxResolutionStats(const std::shared_ptr<IStats> &stats_client) {
+    display_stats_reporter_.logDisplayStats(stats_client, kDisplayPortMaxResolutionStatsPaths,
+                                            DisplayStatsReporter::DISP_PORT_MAX_RES_STATE);
+}
 /**
  * Report the Speech DSP state.
  */
@@ -2114,11 +2127,14 @@ void SysfsCollector::logPerDay() {
     logBatteryEEPROM(stats_client);
     logBatteryHealth(stats_client);
     logBatteryTTF(stats_client);
+    logBatteryHistoryValidation();
     logBlockStatsReported(stats_client);
     logCodec1Failed(stats_client);
     logCodecFailed(stats_client);
     logDisplayStats(stats_client);
     logDisplayPortStats(stats_client);
+    logDisplayPortDSCStats(stats_client);
+    logDisplayPortMaxResolutionStats(stats_client);
     logHDCPStats(stats_client);
     logF2fsStats(stats_client);
     logF2fsAtomicWriteInfo(stats_client);
@@ -2133,6 +2149,7 @@ void SysfsCollector::logPerDay() {
     logSpeakerHealthStats(stats_client);
     mm_metrics_reporter_.logCmaStatus(stats_client);
     mm_metrics_reporter_.logPixelMmMetricsPerDay(stats_client);
+    mm_metrics_reporter_.logGcmaPerDay(stats_client);
     logVendorAudioHardwareStats(stats_client);
     logThermalStats(stats_client);
     logTempResidencyStats(stats_client);
@@ -2169,7 +2186,6 @@ void SysfsCollector::logBrownout() {
 
 void SysfsCollector::logOnce() {
     logBrownout();
-    logBatteryHistoryValidation();
 }
 
 void SysfsCollector::logPerHour() {
@@ -2179,6 +2195,8 @@ void SysfsCollector::logPerHour() {
         return;
     }
     mm_metrics_reporter_.logPixelMmMetricsPerHour(stats_client);
+    mm_metrics_reporter_.logGcmaPerHour(stats_client);
+    mm_metrics_reporter_.logMmProcessUsageByOomGroupSnapshot(stats_client);
     logZramStats(stats_client);
     if (kPowerMitigationStatsPath != nullptr && strlen(kPowerMitigationStatsPath) > 0)
         mitigation_stats_reporter_.logMitigationStatsPerHour(stats_client,
@@ -2230,6 +2248,7 @@ void SysfsCollector::collect(void) {
         return;
     }
 
+    ALOGI("Time-series metrics were initiated.");
     while (1) {
         int readval;
         union {
diff --git a/pixelstats/include/pixelstats/BatteryEEPROMReporter.h b/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
index 8a4a8938..6dc1c629 100644
--- a/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
+++ b/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
@@ -28,6 +28,7 @@ namespace google {
 namespace pixel {
 
 using aidl::android::frameworks::stats::IStats;
+using aidl::android::frameworks::stats::VendorAtomValue;
 
 // The storage for save whole history is 928 byte
 // each history contains 19 items with total size 28 byte
@@ -121,8 +122,9 @@ class BatteryEEPROMReporter {
     /* The number of elements in struct BatteryHistory for P20 series */
     const int kNumBatteryHistoryFields = 19;
     /* The number of elements for relaxation event */
-    const int kNumFGLearningFields = 10;
     const int kNumFGLearningFieldsV2 = 16;
+    /* with additional unix time field */
+    const int kNumFGLearningFieldsV3 = 17;
     unsigned int last_lh_check_ = 0;
     /* The number of elements for history validation event */
     const int kNumValidationFields = 4;
@@ -145,12 +147,41 @@ class BatteryEEPROMReporter {
         unsigned maxdischgcurr:4;
     };
 
+    struct BatteryHistoryInt32 {
+        int32_t cycle_cnt;
+        int32_t full_cap;
+        int32_t esr;
+        int32_t rslow;
+        int32_t soh;
+        int32_t batt_temp;
+        int32_t cutoff_soc;
+        int32_t cc_soc;
+        int32_t sys_soc;
+        int32_t msoc;
+        int32_t batt_soc;
+        int32_t reserve;
+        int32_t max_temp;
+        int32_t min_temp;
+        int32_t max_vbatt;
+        int32_t min_vbatt;
+        int32_t max_ibatt;
+        int32_t min_ibatt;
+        int32_t checksum;
+        int32_t tempco;
+        int32_t rcomp0;
+        int32_t timer_h;
+        int32_t full_rep;
+    };
+
     int64_t report_time_ = 0;
     int64_t getTimeSecs();
 
     bool checkLogEvent(struct BatteryHistory hist);
     void reportEvent(const std::shared_ptr<IStats> &stats_client,
                      const struct BatteryHistory &hist);
+    void reportEventInt32(const std::shared_ptr<IStats> &stats_client,
+                     const struct BatteryHistoryInt32 &hist);
+    void setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset, int content);
 
     const int kNum77759GMSRFields = 11;
     const int kNum77779GMSRFields = 9;
diff --git a/pixelstats/include/pixelstats/DisplayStatsReporter.h b/pixelstats/include/pixelstats/DisplayStatsReporter.h
index c465c416..00267f01 100644
--- a/pixelstats/include/pixelstats/DisplayStatsReporter.h
+++ b/pixelstats/include/pixelstats/DisplayStatsReporter.h
@@ -41,6 +41,8 @@ class DisplayStatsReporter {
         DISP_PANEL_STATE = 0,
         DISP_PORT_STATE,
         HDCP_STATE,
+        DISP_PORT_DSC_STATE,
+        DISP_PORT_MAX_RES_STATE,
     };
     void logDisplayStats(const std::shared_ptr<IStats> &stats_client,
                          const std::vector<std::string> &display_stats_paths,
@@ -116,6 +118,26 @@ class DisplayStatsReporter {
                               const std::vector<std::string> &hdcp_stats_paths);
     bool captureHDCPAuthTypeStats(const std::vector<std::string> &hdcp_stats_paths,
                                   int64_t *cur_data);
+
+    /* displayport FEC/DSC state */
+    /* Set the number of paths needed to be collected */
+    static constexpr int DISPLAY_PORT_DSC_STATS_SIZE = 2;
+
+    int64_t prev_dp_dsc_data_[DISPLAY_PORT_DSC_STATS_SIZE] = {0};
+    void logDisplayPortFECDSCStats(const std::shared_ptr<IStats> &stats_client,
+                                   const std::vector<std::string> &displayport_fecdsc_stats_paths);
+    bool captureDisplayPortFECDSCStats(
+            const std::vector<std::string> &displayport_fecdsc_stats_paths, int64_t *cur_data);
+
+    /* displayport maximum resolution state */
+    /* Set the number of paths needed to be collected */
+    static constexpr int DISPLAY_PORT_MAX_RES_STATS_SIZE = 11;
+
+    int64_t prev_dp_max_res_data_[DISPLAY_PORT_MAX_RES_STATS_SIZE] = {0};
+    void logDisplayPortMaxResStats(const std::shared_ptr<IStats> &stats_client,
+                                   const std::vector<std::string> &displayport_max_res_stats_paths);
+    bool captureDisplayPortMaxResStats(
+            const std::vector<std::string> &displayport_max_res_stats_paths, int64_t *cur_data);
 };
 
 }  // namespace pixel
diff --git a/pixelstats/include/pixelstats/MmMetricsReporter.h b/pixelstats/include/pixelstats/MmMetricsReporter.h
index dc2f2425..dcef6b24 100644
--- a/pixelstats/include/pixelstats/MmMetricsReporter.h
+++ b/pixelstats/include/pixelstats/MmMetricsReporter.h
@@ -36,13 +36,59 @@ using aidl::android::frameworks::stats::VendorAtomValue;
  */
 class MmMetricsReporter {
   public:
+    // Define the enum based on the group range names
+    enum OomScoreAdjGroup : int32_t {
+        OOMR_950 = 0,
+        OOMR_900,
+        OOMR_850,
+        OOMR_800,
+        OOMR_750,
+        OOMR_700,
+        OOMR_650,
+        OOMR_600,
+        OOMR_550,
+        OOMR_500,
+        OOMR_450,
+        OOMR_400,
+        OOMR_350,
+        OOMR_300,
+        OOMR_250,
+        OOMR_200,
+        OOMS_200,
+        OOMR_150,
+        OOMR_100,
+        OOMR_050,
+        OOMR_000,
+        OOMS_000,
+        OOMR_NEGATIVE,
+        OOM_NUM_OF_GROUPS,
+    };
+
+    struct OomGroupMemUsage {
+        OomScoreAdjGroup oom_group;  // the diemsion field
+        int64_t nr_task;
+        int64_t file_rss_kb;
+        int64_t anon_rss_kb;
+        int64_t pgtable_kb;
+        int64_t swap_ents_kb;
+        int64_t shmem_rss_kb;
+    };
+
     MmMetricsReporter();
     void aggregatePixelMmMetricsPer5Min();
     void logPixelMmMetricsPerHour(const std::shared_ptr<IStats> &stats_client);
     void logPixelMmMetricsPerDay(const std::shared_ptr<IStats> &stats_client);
+    void logGcmaPerDay(const std::shared_ptr<IStats> &stats_client);
+    void logGcmaPerHour(const std::shared_ptr<IStats> &stats_client);
+    void logMmProcessUsageByOomGroupSnapshot(const std::shared_ptr<IStats> &stats_client);
     void logCmaStatus(const std::shared_ptr<IStats> &stats_client);
     std::vector<VendorAtomValue> genPixelMmMetricsPerHour();
     std::vector<VendorAtomValue> genPixelMmMetricsPerDay();
+    bool readMmProcessUsageByOomGroup(std::vector<OomGroupMemUsage> *ogusage);
+    std::vector<VendorAtomValue> genMmProcessUsageByOomGroupSnapshotAtom(
+            const OomGroupMemUsage &data);
+    std::vector<VendorAtomValue> readAndGenGcmaPerHour();
+    std::vector<VendorAtomValue> readAndGenGcmaPerDay();
     virtual ~MmMetricsReporter() {}
 
   private:
@@ -119,8 +165,12 @@ class MmMetricsReporter {
             kPsiNumAllUploadTotalMetrics + kPsiNumAllUploadAvgMetrics;
 
     bool checkKernelMMMetricSupport();
+    bool checkKernelOomUsageSupport();
+    bool checkKernelGcmaSupport();
 
     bool MmMetricsSupported() { return ker_mm_metrics_support_; }
+    bool OomUsageSupoorted() { return ker_oom_usage_support_; }
+    bool GcmaSupported() { return ker_gcma_support_; }
 
     bool ReadFileToUint(const std::string &path, uint64_t *val);
     bool reportVendorAtom(const std::shared_ptr<IStats> &stats_client, int atom_id,
@@ -167,7 +217,12 @@ class MmMetricsReporter {
             int cma_name_offset, const std::vector<MmMetricsInfo> &metrics_info,
             std::map<std::string, std::map<std::string, uint64_t>> *all_prev_cma_stat);
 
+    std::optional<OomGroupMemUsage> parseMmProcessUsageByOomGroupLine(const std::string &line);
+    bool readMmProcessUsageByOomGroupFile(const std::string &path,
+                                          std::vector<OomGroupMemUsage> *ogusage, int32_t *m_uid);
+
     // test code could override this to inject test data
+    // though named 'Sysfs', it can be applied to proc fs
     virtual std::string getSysfsPath(const std::string &path) { return path; }
 
     const char *const kVmstatPath;
@@ -179,6 +234,28 @@ class MmMetricsReporter {
     const char *const kPixelStatMm;
     const char *const kMeminfoPath;
     const char *const kProcStatPath;
+    const char *const kProcVendorMmUsageByOom;
+    const char *const kGcmaBasePath;
+
+    // GCMA hourly metrics
+    const char *const kGcmaCached = "cached";
+
+    // GCMA hourly 1/2
+    const char *const kGcmaHourlySimpleKnobs[4] = {
+            "discarded",
+            "evicted",
+            "loaded",
+            "stored",
+    };
+
+    // GCMA hourly 2/2
+    const char *const kGcmaHourlyHistogramKnobs[4] = {
+            "latency_low",
+            "latency_mid",
+            "latency_high",
+            "latency_extreme_high",
+    };
+
     // Proto messages are 1-indexed and VendorAtom field numbers start at 2, so
     // store everything in the values array at the index of the field number
     // -2.
@@ -202,7 +279,10 @@ class MmMetricsReporter {
     int prev_kcompactd_pid_ = -1;
     uint64_t prev_kswapd_stime_ = 0;
     uint64_t prev_kcompactd_stime_ = 0;
+    int32_t oom_usage_uid_ = 0;
     bool ker_mm_metrics_support_;
+    bool ker_oom_usage_support_;
+    bool ker_gcma_support_;
 };
 
 }  // namespace pixel
diff --git a/pixelstats/include/pixelstats/StatsHelper.h b/pixelstats/include/pixelstats/StatsHelper.h
index 70fd4e34..db345c14 100644
--- a/pixelstats/include/pixelstats/StatsHelper.h
+++ b/pixelstats/include/pixelstats/StatsHelper.h
@@ -42,7 +42,7 @@ enum ReportEventType {
 enum ReportEventFormat {
   FormatAddrWithVal,
   FormatIgnoreAddr,
-  FormatNoAddr,
+  FormatOnlyVal,
 };
 
 void reportSpeakerImpedance(const std::shared_ptr<IStats> &stats_client,
@@ -70,11 +70,8 @@ void reportUsbDataSessionEvent(const std::shared_ptr<IStats> &stats_client,
                                const PixelAtoms::VendorUsbDataSessionEvent &usb_session);
 void readLogbuffer(const std::string &buf_path, int num_fields, uint16_t code,
                    enum ReportEventFormat format, unsigned int last_check_time,
-                   std::vector<std::vector<uint16_t>> &events);
+                   std::vector<std::vector<uint32_t>> &events);
 
-void readLogbuffer(const std::string &buf_path, int num_fields, const char *code,
-                   enum ReportEventFormat format, unsigned int last_check_time,
-                   std::vector<std::vector<uint16_t>> &events);
 }  // namespace pixel
 }  // namespace google
 }  // namespace hardware
diff --git a/pixelstats/include/pixelstats/SysfsCollector.h b/pixelstats/include/pixelstats/SysfsCollector.h
index 42a4b6f0..15d50ddf 100644
--- a/pixelstats/include/pixelstats/SysfsCollector.h
+++ b/pixelstats/include/pixelstats/SysfsCollector.h
@@ -75,6 +75,8 @@ class SysfsCollector {
         const std::vector<std::string> ThermalStatsPaths;
         const std::vector<std::string> DisplayStatsPaths;
         const std::vector<std::string> DisplayPortStatsPaths;
+        const std::vector<std::string> DisplayPortDSCStatsPaths;
+        const std::vector<std::string> DisplayPortMaxResolutionStatsPaths;
         const std::vector<std::string> HDCPStatsPaths;
         const char *const CCARatePath;
         const std::vector<std::pair<std::string, std::string>> TempResidencyAndResetPaths;
@@ -137,6 +139,8 @@ class SysfsCollector {
     void logMitigationDurationCounts(const std::shared_ptr<IStats> &stats_client);
     void logDisplayStats(const std::shared_ptr<IStats> &stats_client);
     void logDisplayPortStats(const std::shared_ptr<IStats> &stats_client);
+    void logDisplayPortDSCStats(const std::shared_ptr<IStats> &stats_client);
+    void logDisplayPortMaxResolutionStats(const std::shared_ptr<IStats> &stats_client);
     void logHDCPStats(const std::shared_ptr<IStats> &stats_client);
     void logVendorAudioPdmStatsReported(const std::shared_ptr<IStats> &stats_client);
 
@@ -199,6 +203,8 @@ class SysfsCollector {
     const char *const kWifiPcieLinkStatsPath;
     const std::vector<std::string> kDisplayStatsPaths;
     const std::vector<std::string> kDisplayPortStatsPaths;
+    const std::vector<std::string> kDisplayPortDSCStatsPaths;
+    const std::vector<std::string> kDisplayPortMaxResolutionStatsPaths;
     const std::vector<std::string> kHDCPStatsPaths;
     const char *const kPDMStatePath;
     const char *const kWavesPath;
diff --git a/pixelstats/include/pixelstats/UeventListener.h b/pixelstats/include/pixelstats/UeventListener.h
index 3768218c..a9e87cb5 100644
--- a/pixelstats/include/pixelstats/UeventListener.h
+++ b/pixelstats/include/pixelstats/UeventListener.h
@@ -164,9 +164,11 @@ class UeventListener {
                                                     GpuEvent_GpuEventInfo_MALI_PMODE_ENTRY_FAILURE},
                     {"GPU_PAGE_FAULT",
                      PixelAtoms::GpuEvent::GpuEventInfo::GpuEvent_GpuEventInfo_MALI_GPU_PAGE_FAULT},
-                    {"MMU_AS_ACTIVE_STUCK",
+                    {"MMU_AS_ACTIVE_STUCK", PixelAtoms::GpuEvent::GpuEventInfo::
+                                                    GpuEvent_GpuEventInfo_MALI_MMU_AS_ACTIVE_STUCK},
+                    {"TRACE_BUF_INVALID_SLOT",
                      PixelAtoms::GpuEvent::GpuEventInfo::
-                             GpuEvent_GpuEventInfo_MALI_MMU_AS_ACTIVE_STUCK}};
+                             GpuEvent_GpuEventInfo_MALI_TRACE_BUF_INVALID_SLOT}};
 
     const std::unordered_map<std::string,
                              PixelAtoms::ThermalSensorAbnormalityDetected::AbnormalityType>
diff --git a/pixelstats/pixelatoms.proto b/pixelstats/pixelatoms.proto
index 21bfbbf0..eb30e5d0 100644
--- a/pixelstats/pixelatoms.proto
+++ b/pixelstats/pixelatoms.proto
@@ -25,7 +25,7 @@ option java_package = "android.hardware.google.pixel";
 option java_outer_classname = "PixelAtoms";
 
 import "frameworks/proto_logging/stats/atom_field_options.proto";
-import "frameworks/proto_logging/stats/enums/app/app_enums.proto";
+import "frameworks/proto_logging/stats/enums/app_shared/app_enums.proto";
 
 /*
  * Please note that the following features are not currently supported by
@@ -57,7 +57,7 @@ message Atom {
       PixelMmMetricsPerDay pixel_mm_metrics_per_day = 105016;
       F2fsCompressionInfo f2fs_compression_info = 105017;
       VendorChargeCycles vendor_charge_cycles = 105018; // moved from atoms.proto
-      VendorHardwareFailed vendor_hardware_failed = 105019; // moved from atoms.proto
+      VendorHardwareFailed vendor_hardware_failed = 105019 [(android.os.statsd.module) = "pixelaudio"]; // moved from atoms.proto
       VendorSlowIo vendor_slow_io = 105020; // moved from atoms.proto
       VendorSpeechDspStat vendor_speech_dsp_stat = 105021; // moved from atoms.proto
       VendorPhysicalDropDetected vendor_physical_drop_detected =
@@ -74,7 +74,7 @@ message Atom {
 
       CitadelVersion citadel_version = 100018; // moved from vendor proprietary
       CitadelEvent citadel_event = 100019;  // moved from vendor proprietary
-      VendorSpeakerStatsReported vendor_speaker_stats_reported = 105030;
+      VendorSpeakerStatsReported vendor_speaker_stats_reported = 105030 [(android.os.statsd.module) = "pixelaudio"];
 
       ChreHalNanoappLoadFailed chre_hal_nanoapp_load_failed =
                 105031 [(android.os.statsd.module) = "chre"];
@@ -91,7 +91,7 @@ message Atom {
       BatteryHealthUsage battery_health_usage = 105038;
       F2fsSmartIdleMaintEnabledStateChanged f2fs_smart_idle_maint_enabled_state_changed = 105039;
       BlockStatsReported block_stats_reported = 105040;
-      VendorAudioHardwareStatsReported vendor_audio_hardware_stats_reported = 105041;
+      VendorAudioHardwareStatsReported vendor_audio_hardware_stats_reported = 105041 [(android.os.statsd.module) = "pixelaudio"];
 
       ThermalDfsStats thermal_dfs_stats = 105042;
       VendorLongIRQStatsReported vendor_long_irq_stats_reported = 105043;
@@ -101,22 +101,22 @@ message Atom {
       PcieLinkStatsReported pcie_link_stats = 105047;
       VendorSensorCoolingDeviceStats vendor_sensor_cooling_device_stats = 105048;
 
-      VibratorPlaycountReported vibrator_playcount_reported = 105049;
-      VibratorLatencyReported vibrator_latency_reported = 105050;
-      VibratorErrorsReported vibrator_errors_reported = 105051;
+      VibratorPlaycountReported vibrator_playcount_reported = 105049 [(android.os.statsd.module) = "vibrator"];
+      VibratorLatencyReported vibrator_latency_reported = 105050 [(android.os.statsd.module) = "vibrator"];
+      VibratorErrorsReported vibrator_errors_reported = 105051 [(android.os.statsd.module) = "vibrator"];
       F2fsAtomicWriteInfo f2fs_atomic_write_info = 105052;
       PartitionsUsedSpaceReported partition_used_space_reported = 105053;
       PowerMitigationDurationCounts mitigation_duration = 105054; // moved from atoms.proto
       DisplayPanelErrorStats display_panel_error_stats = 105055;
       VendorAudioPdmStatsReported vendor_audio_pdm_stats_reported = 105056;
-      VendorAudioThirdPartyEffectStatsReported vendor_audio_third_party_effect_stats_reported = 105057;
+      VendorAudioThirdPartyEffectStatsReported vendor_audio_third_party_effect_stats_reported = 105057 [(android.os.statsd.module) = "pixelaudio"];
       VendorAudioAdaptedInfoStatsReported vendor_audio_adapted_info_stats_reported = 105058;
       GpuEvent gpu_event = 105059;
-      VendorAudioPcmStatsReported vendor_audio_pcm_stats_reported = 105060;
+      VendorAudioPcmStatsReported vendor_audio_pcm_stats_reported = 105060 [(android.os.statsd.module) = "pixelaudio"];
       VendorUsbDataSessionEvent vendor_usb_data_session_event = 105061;
       ThermalSensorAbnormalityDetected thermal_sensor_abnormality_detected = 105062;
       VendorAudioOffloadedEffectStatsReported vendor_audio_offloaded_effect_stats_reported = 105063;
-      VendorAudioBtMediaStatsReported vendor_audio_bt_media_stats_reported = 105064;
+      VendorAudioBtMediaStatsReported vendor_audio_bt_media_stats_reported = 105064 [(android.os.statsd.module) = "pixelaudio"];
       PixelImpulseUsageReported pixel_impulse_usage_reported = 105065;
       DisplayPortErrorStats display_port_error_stats = 105066;
       HDCPAuthTypeStats hdcp_auth_type_stats = 105067;
@@ -129,6 +129,16 @@ message Atom {
       BatteryTimeToFullStatsReported battery_time_to_full_stats_reported = 105074;
       VendorAudioDirectUsbAccessUsageStats vendor_audio_direct_usb_access_usage_stats = 105075 [(android.os.statsd.module) = "pixelaudio"];
       VendorAudioUsbConfigStats vendor_audio_usb_config_stats = 105076 [(android.os.statsd.module) = "pixelaudio"];
+      GpuFrozenAppsMemoryPerUid gpu_frozen_apps_memory_per_uid = 105078;
+      RepairModeEntered repair_mode_entered = 105079;
+      RepairModeExited repair_mode_exited = 105080;
+      RepairModeLowStorageReported repair_mode_low_storage_reported = 105081;
+      RepairModeErrorReported repair_mode_error_reported = 105082;
+      DisplayPortDSCSupportCountStatsReported display_port_dsc_support_stats = 105083;
+      DisplayPortMaxResolutionCountStatsReported display_port_max_resolution_stats = 105084;
+      VendorAudioDspRecordUsageStatsReported vendor_audio_dsp_record_usage_stats_reported = 105085 [(android.os.statsd.module) = "pixelaudio"];
+      VendorAudioUsbConnectionState vendor_audio_usb_connection_state = 105086 [(android.os.statsd.module) = "pixelaudio"];
+      VendorAudioSpeakerPowerStatsReported vendor_audio_speaker_power_stats_reported = 105087 [(android.os.statsd.module) = "pixelaudio"];
     }
     // AOSP atom ID range ends at 109999
     reserved 109997; // reserved for VtsVendorAtomJavaTest test atom
@@ -802,7 +812,14 @@ message VendorHardwareFailed {
       FINGERPRINT_TOO_MANY_DEAD_PIXELS = 5;
       DEGRADE = 6;
     }
-    optional int32 failure_code = 4;
+    optional HardwareErrorCode failure_code = 4;
+
+    enum EventType {
+      UNKNOWN_EVENT = 0;
+      VOICE_CALL = 1;
+      VOIP_CALL = 2;
+    }
+    optional EventType event_type = 5;
 }
 
 /**
@@ -1378,6 +1395,15 @@ message VendorAudioHardwareStatsReported {
 
   /* cca_enable: UI enable & algorithm is inactive (C2 or C4) */
   optional int32 cca_enable_count_per_day = 8;
+
+  /* version: version of the data. */
+  optional int32 version = 9;
+
+  /* duration: duration in second of the voice/voip call. */
+  optional int32 duration_second = 10;
+
+  /* band: band value. */
+  optional int32 band = 11;
 }
 
 /**
@@ -1887,6 +1913,7 @@ message GpuEvent {
       MALI_PMODE_ENTRY_FAILURE = 21;
       MALI_GPU_PAGE_FAULT = 22;
       MALI_MMU_AS_ACTIVE_STUCK = 23;
+      MALI_TRACE_BUF_INVALID_SLOT = 24;
     }
 
     /* Vendor reverse domain name (expecting "com.google.pixel"). */
@@ -2196,6 +2223,8 @@ message PixelImpulseUsageReported {
       INTERNAL_CLIENT_LISTENER_ADD = 10004;
       INTERNAL_CLIENT_LISTENER_REMOVE = 10005;
       INTERNAL_WAIT = 10006;
+      INTERNAL_COROUTINE_ENQUEUE = 10007;
+      INTERNAL_COROUTINE_RUN = 10008;
   }
   /* Invoked API name */
   optional ApiName api_name = 4;
@@ -2203,6 +2232,9 @@ message PixelImpulseUsageReported {
   enum Tag {
       TAG_UNKNOWN = 0;
       TAG_TEMPERATURE_READ_DELAY = 1;
+      TAG_SKIN_TEMPERATURE = 2;
+      TAG_BUSINESS_SCOPE = 3;
+      TAG_NON_BUSINESS_SCOPE = 4;
   }
   /* Tag for debugging purpose */
   optional Tag tag = 5;
@@ -2260,6 +2292,12 @@ message PixelImpulseUsageReported {
    */
   /* Used when state_source == STATE_SOURCE_UID_IMPORTANCE */
   optional android.app.Importance uid_importance_cut_point = 15;
+
+  /* Expected value for temperature delta in Celsius */
+  optional float expected_temperature_celsius = 16;
+
+  /* Actual value for temperature delta in Celsius */
+  optional float actual_temperature_celsius = 17;
 }
 
 /**
@@ -2579,3 +2617,377 @@ message VendorAudioUsbConfigStats {
   /* Duration in second */
   optional int32 duration_second = 7;
 };
+
+/* GPU memory allocation information for frozen apps */
+message GpuFrozenAppsMemoryPerUid {
+  /* Vendor reverse domain name (expecting "com.google.pixel"). */
+  optional string reverse_domain_name = 1;
+
+  /* UID of the frozen app. */
+  optional int32 uid = 2 [(android.os.statsd.is_uid) = true];
+
+  /* Total amount of GPU memory allocated by this app, in kilobytes. */
+  optional int64 gpu_memory_kb = 3;
+}
+
+/**
+ * Logs for repair mode enter
+ * Logged from:
+ *   vendor/google/apps/RepairMode/
+ *
+ * Estimated Logging Rate:
+ * Peak: 5 times in 1 min | Avg: 3 times per device per year
+ */
+ message RepairModeEntered {
+  // Vendor reverse domain name (expecting "com.google.pixel").
+  optional string reverse_domain_name = 1;
+  // free storage size on device when entering repair mode in megabyte
+  optional int64 storage_size_mb = 2;
+}
+
+/**
+ * Logs for repair mode exit
+ * Logged from:
+ *   vendor/google/apps/RepairMode/
+ *
+ * Estimated Logging Rate:
+ * Peak: 5 times in 1 min | Avg: 3 times per device per year
+ */
+message RepairModeExited {
+  // Vendor reverse domain name (expecting "com.google.pixel").
+  optional string reverse_domain_name = 1;
+  // free storage size on device when exiting repair mode in megabyte
+  optional int64 storage_size_mb = 2;
+  // whether diagnostic tool is executed during repair mode
+  // false if diagnostic tool is never run
+  // true if diagnostic is run once or more
+  optional bool is_diagnostic_run = 3;
+
+  // how user auth/verify the credential to exit repair mode
+  enum ExitMethod {
+    UNSPECIFIED = 0;
+    // auth by google account
+    GAUTH = 1;
+    // auth by screen lock on the device
+    SCREEN_LOCK = 2;
+  }
+  // method for auth when exiting repair mode
+  optional ExitMethod exit_method = 4;
+}
+
+/**
+ * Logs when a user cannot enter repair mode due to insufficient storage
+ * Logged from:
+ *   vendor/google/apps/RepairMode/
+ *
+ * Estimated Logging Rate:
+ * Peak: 1 time in 5 mins | Avg: 20 times per device per year
+ */
+message RepairModeLowStorageReported {
+  // Vendor reverse domain name (expecting "com.google.pixel").
+  optional string reverse_domain_name = 1;
+  // free storage size on the device in megabyte
+  optional int64 storage_size_mb = 2;
+}
+
+/**
+ * Logs programmatic error that prevent users from entering repair mode
+ * Logged from:
+ *   vendor/google/apps/RepairMode/
+ *
+ * Estimated Logging Rate:
+ * Peak: 1 time in 3 mins | Avg: 2 times per device per year
+ */
+message RepairModeErrorReported {
+  // Vendor reverse domain name (expecting "com.google.pixel").
+  optional string reverse_domain_name = 1;
+
+  // Error type that prevent user from entering repair mode
+  enum ErrorType {
+    UNSPECIFIED = 0;
+    // Dynamic system failed to install image
+    INSTALLED_FAILED = 1;
+    // Failed to enable Dynamic system
+    ENABLE_DYN_FAILED = 2;
+    // Failed to reboot
+    REBOOT_FAILED = 3;
+  }
+
+  optional ErrorType error_type = 2;
+}
+
+/*
+ * Log if a device is plugged into a display that
+ * supports forward error correction (FEC) and
+ * display stream compression (DSC)
+ */
+message DisplayPortDSCSupportCountStatsReported{
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+
+  /* Counts of connections where FEC/DSC is
+   * supported or not
+   */
+  optional int32 fec_dsc_supported = 2;
+  optional int32 fec_dsc_not_supported = 3;
+}
+
+/*
+* A message containing the use counts of various maximum
+* resolutions the displays plugged into the phone use.
+*/
+message DisplayPortMaxResolutionCountStatsReported{
+
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+
+  /* Other Resolutions that don't fit into the current list */
+  optional int32 max_res_other = 2;
+
+  /* Predefined Resolutions */
+  optional int32 max_res_1366_768 = 3;
+  optional int32 max_res_1440_900 = 4;
+  optional int32 max_res_1600_900 = 5;
+  optional int32 max_res_1920_1080 = 6;
+  optional int32 max_res_2560_1080 = 7;
+  optional int32 max_res_2560_1440 = 8;
+  optional int32 max_res_3440_1440 = 9;
+  optional int32 max_res_3840_2160 = 10;
+  optional int32 max_res_5120_2880 = 11;
+  optional int32 max_res_7680_4320 = 12;
+}
+
+/*
+ * A message containing recording usage event.
+ * Logged from:
+ *   vendor/google/whitechapel/audio/hal/aidl/audio/metric/suez_data_adapter/statsd_suez_data_adapter.cc
+ *
+ * Estimated Logging Rate: Any time during audio recording that screen_orientation / audio device / use case changes.
+ * It will be aggregated in a count and value metric to keep the resource usage low.
+ */
+message VendorAudioDspRecordUsageStatsReported {
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+
+  enum Type {
+    UNKNOWN = 0;
+    UC_AUDIO_RECORD = 1;
+    UC_LOW_LATENCY_AUDIO_RECORD = 2;
+    UC_MMAP_RECORD = 3;
+    IN_HANDSET_MIC = 4;
+    IN_HANDSET_DUAL_MIC = 5;
+    IN_HANDSET_TRIPLE_MIC = 6;
+    IN_CAMCORDER_LANDSCAPE = 7;
+    IN_CAMCORDER_INVERT_LANDSCAPE = 8;
+    IN_CAMCORDER_PORTRAIT = 9;
+    IN_CAMCORDER_SELFIE_LANDSCAPE = 10;
+    IN_CAMCORDER_SELFIE_INVERT_LANDSCAPE = 11;
+    IN_CAMCORDER_SELFIE_PORTRAIT = 12;
+    IN_CAMCORDER_MIC = 13;
+    IN_CAMCORDER_TIRPLE_MIC = 14;
+    CUSTOM_IN_PCM1 = 15;
+    CUSTOM_IN_PCM2 = 16;
+    CUSTOM_IN_PCM3 = 17;
+    CUSTOM_IN_PCM4 = 18;
+    CUSTOM_IN_PCM5 = 19;
+  }
+
+  /* Audio Device Interface. */
+  enum AudioDeviceInterface {
+    UNKNOWN_DEVICE_INTERFACE = 0;
+
+    // Built-in speakers
+    SPEAKER = 1;
+    SPEAKER_EARPIECE = 2;
+    SPEAKER_SAFE = 3;
+
+    // Built-in microphones
+    MICROPHONES = 4;
+    BACK_MICROPHONES = 5;
+    // internal used microphones
+    ULTRASOUND_MICROPHONES = 6;
+    SOUND_TRIGGER_MICROPHONES = 7;
+
+    // BT SCO
+    BLUETOOTH_SCO_DEFAULT = 8;
+    BLUETOOTH_SCO_HEADSET = 9;
+    BLUETOOTH_SCO_CAR_KIT = 10;
+    BLUETOOTH_SCO_HEADSET_MICROPHONES = 11;
+
+    // BT A2DP
+    BLUETOOTH_A2DP_DEVICE = 12;
+    BLUETOOTH_A2DP_SPEAKER = 13;
+    BLUETOOTH_A2DP_HEADPHONE = 14;
+
+    // BT low energy (BLE)
+    BLUETOOTH_LOW_ENERGY_SPEAKER = 15;
+    BLUETOOTH_LOW_ENERGY_HEADSET = 16;
+    BLUETOOTH_LOW_ENERGY_BROADCAST = 17;
+    BLUETOOTH_LOW_ENERGY_HEADSET_MICROPHONES = 18;
+
+    // USB
+    USB_DEVICE = 19;
+    USB_HEADSET = 20;
+    USB_DOCK = 21;
+    USB_DEVICE_MICROPHONES = 22;
+    USB_HEADSET_MICROPHONES = 23;
+    USB_DOCK_MICROPHONES = 24;
+
+    // HDMI
+    HDMI_DEVICE = 25;
+
+    // Telephony
+    TELEPHONY_TX = 26;
+    TELEPHONY_RX = 27;
+    IN_CALL_CAPTURE_SOURCE0 = 28;
+    IN_CALL_CAPTURE_SOURCE1 = 29;
+    IN_CALL_CAPTURE_SOURCE2 = 30;
+
+    // Null sink and source
+    NULL_SOURCE = 31;
+    NULL_SINK = 32;
+
+    // Echo reference
+    ECHO_REFERENCE_DEVICE_INTERFACE = 33;
+  }
+
+  /* Audio Use Case. */
+  enum UseCase {
+    UNKNOWN_VENDOR_AUDIO_USECASE = 0;
+    // playback use cases
+    PRIMARY_PLAYBACK = 1;
+    RAW_PLAYBACK = 2;
+    DEEP_BUFFER_PLAYBACK = 3;
+    COMPRESS_OFFLOAD_PLAYBACK = 4;
+    MMAP_PLAYBACK = 5;
+    HIFI_PLAYBACK = 6;
+    VOIP_PLAYBACK = 7;
+    TELEPHONY_PLAYBACK = 8;
+    IN_CALL_PLAYBACK = 9;
+    SPATIALIZER_PLAYBACK = 10;
+    ULTRASOUND_PLAYBACK = 11;
+    HAPTIC_PLAYBACK = 12;
+    SPATIALIZER_OFFLOAD_PLAYBACK = 13;
+    // capture use cases
+    PRIMARY_CAPTURE = 14;
+    FAST_CAPTURE = 15;
+    HIFI_CAPTURE = 16;
+    MMAP_CAPTURE = 17;
+    VOIP_CAPTURE = 18;
+    VOIP_GSENET_CAPTURE = 19;
+    ULTRASOUND_CAPTURE = 20;
+    TELEPHONY_CAPTURE = 21;
+    IN_CALL_CAPTURE = 22;
+    SOUND_TRIGGER_CAPTURE = 23;
+    SOUND_TRIGGER_TAP_CAPTURE = 24;
+    HOTWORD_LOOKBACK_CAPTURE = 25;
+    ECHO_REFERENCE_CAPTURE = 26;
+
+    // voice call use case
+    VOICE_CALL_DOWNLINK = 27;
+    VOICE_CALL_UPLINK = 28;
+  }
+
+  /* Audio source with the original enum value. */
+  enum AudioSource {
+    DEFAULT = 0;
+    MIC = 1;
+    VOICE_UPLINK = 2;
+    VOICE_DOWNLINK = 3;
+    VOICE_CALL = 4;
+    CAMCORDER = 5;
+    VOICE_RECOGNITION = 6;
+    VOICE_COMMUNICATION = 7;
+    REMOTE_SUBMIX = 8;
+    UNPROCESSED = 9;
+    VOICE_PERFORMANCE = 10;
+    ECHO_REFERENCE = 1997;
+    FM_TUNER = 1998;
+    HOTWORD = 1999;
+    ULTRASOUND = 2000;
+  };
+
+  enum CameraType {
+    UNKNOWN_CAMERA_TYPE = 0;
+    FRONT_CAMERA = 1;
+    BACK_CAMERA = 2;
+  }
+
+  /* Type of Backend used in recording */
+  optional Type type = 2 [deprecated = true];
+
+  /* Duration in second */
+  optional int32 duration_second = 3;
+
+  optional AudioSource audio_source = 4;
+
+  /* Device interface used */
+  optional AudioDeviceInterface audio_device_interface = 5;
+
+  /* Usecase used */
+  optional UseCase vendor_audio_use_case = 6;
+
+  /* Camera Type */
+  optional CameraType camera_type = 7;
+
+  /* Screen orientation used. */
+  optional int32 screen_orientation = 8;
+
+  /* True if this atom represent the beginning of recording. If usecase/interfaces/orientation
+   * changes mid-recording, new atom will be uploaded but this value will be false.
+   */
+  optional bool is_beginning_of_recording = 9;
+};
+
+/*
+ * A message containing USB audio connection error event.
+ * Logged from:
+ *   vendor/google/whitechapel/audio/hal/aidl/audio/metric/suez_data_adapter/statsd_suez_data_adapter.cc
+ *
+ * Estimated Logging Rate: Very low, around once a month per user.
+ */
+message VendorAudioUsbConnectionState {
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+
+  enum ConnectionState {
+    UNKNOWN_CONNECTION_STATE = 0;
+    FAILED_TO_READ_CARD_ID_PCM_ID = 1;
+    FAILED_TO_READ_USB_ID = 2;
+    FAILED_TO_READ_BUS_ID_DEVICE_ID = 3;
+    FAILED_TO_ADD_NEW_DEVICE = 4;
+    FAILED_TO_PARSE_USB_CAPABILITY = 5;
+    FAILED_TO_PARSE_USB_CAPABILITY_IS_EMPTY = 6;
+    FAILED_TO_ADD_NEW_DEVICE_CAPABILITY = 7;
+    FAILED_TO_ADD_ALREADY_CONNECTED_PORT_ID = 8;
+    CONNECTION_SUCCESS = 9;
+  }
+
+  enum DisconnectionState {
+    UNKNOWN_DISCONNECTION_STATE = 0;
+    FAILED_PORT_ID_NOT_CONNECTED = 1;
+    DISCONNECTION_SUCCESS = 2;
+  }
+
+  /* Connection State. UNKNOWN_CONNECTION_STATE in disconnection event. */
+  optional ConnectionState connection_error = 2;
+
+  /* Disconnection State. UNKNOWN_DISCONNECTION_STATE in connection event. */
+  optional DisconnectionState disconnection_error = 3;
+};
+
+/*
+ * Logs the Audio Speaker Power information stats.
+ * Logged from:
+ *   vendor/google/whitechapel/audio/hal/aidl/audio/metric/suez_data_adapter/statsd_suez_data_adapter.cc
+ *
+ * Estimated Logging Rate: Once per audio playback through speaker.
+ */
+message VendorAudioSpeakerPowerStatsReported {
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+  /* The average power of the speaker. i-th value represent i-th speaker. There are at most 4 speakers. */
+  repeated float average_power = 2;
+  /* Duration in second that speaker is using the average power. i-th value represent i-th speaker. There are at most 4 speakers. */
+  repeated int32 duration_second = 3;
+}
diff --git a/pixelstats/test/mm/MmMetricsGoldenAtomFieldTypes.h b/pixelstats/test/mm/MmMetricsGoldenAtomFieldTypes.h
index 549e1175..8e281f60 100644
--- a/pixelstats/test/mm/MmMetricsGoldenAtomFieldTypes.h
+++ b/pixelstats/test/mm/MmMetricsGoldenAtomFieldTypes.h
@@ -156,6 +156,37 @@ const int PixelMmMetricsPerDay_field_types[]{
         longValue,  // optional int64 cpu_io_wait_time_cs = 63;
         longValue,  // optional int64 kswapd_pageout_run = 64;
 };
+
+const int MmMetricsOomGroupMemUsage_field_types[]{
+        intValue,   // metric_id
+        intValue,   // oom_group
+        longValue,  // nr_task
+        longValue,  // file_rss_kb
+        longValue,  // anon_rss_kb
+        longValue,  // pgtable_kb
+        longValue,  // swap_ents_kb
+        longValue,  // shmem_rss_kb
+};
+
+const int MmMetricsGcmaPerHour_field_types[]{
+        longValue,  // GCMA.cached
+};
+
+const int MmMetricsGcmaPerDaySimple_field_types[]{
+        longValue,          // GCMA.disarded
+        longValue,          // GCMA.evicted
+        longValue,          // GCMA.loaded
+        longValue,          // GCMA.stored
+        repeatedLongValue,  // GCMA repeated type (array of histograms)
+};
+
+const int MmMetricsGcmaPerDayHistogram_field_types[]{
+        longValue,  // GCMA.latency_low
+        longValue,  // GCMA.latency_mid
+        longValue,  // GCMA.latency_high
+        longValue,  // GCMA.latency_extreme_high
+};
+
 }  // namespace mm_metrics_atom_field_test_golden_results
 
 }  // namespace pixel
diff --git a/pixelstats/test/mm/MmMetricsGoldenResults.h b/pixelstats/test/mm/MmMetricsGoldenResults.h
index 9bcf300b..d7e192c8 100644
--- a/pixelstats/test/mm/MmMetricsGoldenResults.h
+++ b/pixelstats/test/mm/MmMetricsGoldenResults.h
@@ -177,6 +177,70 @@ const int64_t PixelMmMetricsPerDay_golden[]{
     1126601,
         // clang-format on
 };
+
+const uint64_t MmMetricsOomGroupMemUsage_golden[2][23][7]{
+        // clang-format off
+    {
+        {0, 0, 102, 103, 104, 105, 106},
+        {1, 201, 0, 203, 204, 205, 206},
+        {2, 301, 302, 0, 304, 305, 306},
+        {3, 401, 402, 403, 0, 405, 406},
+        {4, 501, 502, 503, 504, 0, 506},
+        {5, 601, 602, 603, 604, 605, 0},
+        {6, 701, 702, 703, 704, 705, 706},
+        {7, 801, 802, 803, 804, 805, 806},
+        {8, 901, 902, 903, 904, 905, 906},
+        {9, 1001, 1002, 1003, 1004, 1005, 1006},
+        {10, 1101, 1102, 1103, 1104, 1105, 1106},
+        {11, 1201, 1202, 1203, 1204, 1205, 1206},
+        {12, 1301, 1302, 1303, 1304, 1305, 1306},
+        {13, 1401, 1402, 1403, 1404, 1405, 1406},
+        {14, 1501, 1502, 1503, 1504, 1505, 1506},
+        {15, 1601, 1602, 1603, 1604, 1605, 1606},
+        {16, 1701, 1702, 1703, 1704, 1705, 1706},
+        {17, 1801, 1802, 1803, 1804, 1805, 1806},
+        {18, 1901, 1902, 1903, 1904, 1905, 1906},
+        {19, 2001, 2002, 2003, 2004, 2005, 2006},
+        {20, 2101, 2102, 2103, 2104, 2105, 2106},
+        {21, 2201, 2202, 2203, 2204, 2205, 2206},
+        {22, 2301, 2302, 2303, 2304, 2305, 2306},
+    },
+    {
+        {0, 3101, 3102, 3103, 3104, 3105, 3106},
+        {1, 3201, 3202, 3203, 3204, 3205, 3206},
+        {2, 3301, 3302, 3303, 3304, 3305, 3306},
+        {3, 3401, 3402, 3403, 3404, 3405, 3406},
+        {4, 3501, 3502, 3503, 3504, 3505, 3506},
+        {5, 3601, 3602, 3603, 3604, 3605, 3606},
+        {6, 3701, 3702, 3703, 3704, 3705, 3706},
+        {7, 3801, 3802, 3803, 3804, 3805, 3806},
+        {8, 3901, 3902, 3903, 3904, 3905, 3906},
+        {9, 4001, 4002, 4003, 4004, 4005, 4006},
+        {10, 4101, 4102, 4103, 4104, 4105, 4106},
+        {11, 4201, 4202, 4203, 4204, 4205, 4206},
+        {12, 4301, 4302, 4303, 4304, 4305, 4306},
+        {13, 4401, 4402, 4403, 4404, 4405, 4406},
+        {14, 4501, 4502, 4503, 4504, 4505, 4506},
+        {15, 4601, 4602, 4603, 4604, 4605, 4606},
+        {16, 4701, 4702, 4703, 4704, 4705, 4706},
+        {17, 4801, 4802, 4803, 4804, 4805, 4806},
+        {18, 4901, 4902, 4903, 4904, 4905, 4906},
+        {19, 5001, 5002, 5003, 5004, 5005, 5006},
+        {20, 5101, 5102, 5103, 5104, 5105, 5106},
+        {21, 5201, 5202, 5203, 5204, 5205, 5206},
+        {22, 5301, 5302, 5303, 5304, 5305, 5306},
+    }
+        // clang-format on
+};
+
+const uint64_t MmMetricsGcmaPerHour_golden[1] = {
+        13,
+};
+
+const uint64_t MmMetricsGcmaPerDaySimple_golden[4] = {1, 2, 3, 4};
+
+const uint64_t MmMetricsGcmaPerDayHistogram_golden[4] = {5, 6, 7, 8};
+
 }  // namespace mm_metrics_reporter_test_golden_result
 
 }  // namespace pixel
diff --git a/pixelstats/test/mm/MmMetricsReporterTest.cpp b/pixelstats/test/mm/MmMetricsReporterTest.cpp
index c8d2f14f..b5adb15f 100644
--- a/pixelstats/test/mm/MmMetricsReporterTest.cpp
+++ b/pixelstats/test/mm/MmMetricsReporterTest.cpp
@@ -16,6 +16,8 @@
 
 #include <gtest/gtest.h>
 #include <pixelstats/MmMetricsReporter.h>
+#include <sys/stat.h>
+#include <unistd.h>
 
 #include "MmMetricsGoldenAtomFieldTypes.h"
 #include "MmMetricsGoldenResults.h"
@@ -31,8 +33,17 @@ namespace hardware {
 namespace google {
 namespace pixel {
 
+using mm_metrics_atom_field_test_golden_results::MmMetricsGcmaPerDayHistogram_field_types;
+using mm_metrics_atom_field_test_golden_results::MmMetricsGcmaPerDaySimple_field_types;
+using mm_metrics_atom_field_test_golden_results::MmMetricsGcmaPerHour_field_types;
+using mm_metrics_atom_field_test_golden_results::MmMetricsOomGroupMemUsage_field_types;
 using mm_metrics_atom_field_test_golden_results::PixelMmMetricsPerDay_field_types;
 using mm_metrics_atom_field_test_golden_results::PixelMmMetricsPerHour_field_types;
+
+using mm_metrics_reporter_test_golden_result::MmMetricsGcmaPerDayHistogram_golden;
+using mm_metrics_reporter_test_golden_result::MmMetricsGcmaPerDaySimple_golden;
+using mm_metrics_reporter_test_golden_result::MmMetricsGcmaPerHour_golden;
+using mm_metrics_reporter_test_golden_result::MmMetricsOomGroupMemUsage_golden;
 using mm_metrics_reporter_test_golden_result::PixelMmMetricsPerDay_golden;
 using mm_metrics_reporter_test_golden_result::PixelMmMetricsPerHour_golden;
 
@@ -132,6 +143,235 @@ TEST(MmMetricsReporterTest, MmMetricsPerDayAtomFieldOffsetTypeTest) {
     }
 }
 
+TEST(MmMetricsReporterTest, MmMetricsOomGroupMemUsageSuccess) {
+    constexpr int kNumTests = 2;
+    MockMmMetricsReporter mreport;
+    const std::string data_path[kNumTests] = {
+            std::string(data_base_path) + "/test_data_0",
+            std::string(data_base_path) + "/test_data_1",
+    };
+    std::vector<MmMetricsReporter::OomGroupMemUsage> ogusage;
+    int32_t og_metric_uid[kNumTests];
+    auto &golden = MmMetricsOomGroupMemUsage_golden;
+    auto &gold_ftype = MmMetricsOomGroupMemUsage_field_types;
+
+    constexpr int kNumFields = ARRAY_SIZE(MmMetricsOomGroupMemUsage_field_types);
+    constexpr int kNumLines = ARRAY_SIZE(golden[0]);
+
+    ASSERT_LT(kNumLines, 100);
+
+    // Check testcase consistency (if fail, the test case itself has some bug)
+    ASSERT_EQ(ARRAY_SIZE(golden), kNumTests);
+    ASSERT_EQ(ARRAY_SIZE(golden[1]), kNumLines);
+    ASSERT_EQ(ARRAY_SIZE(MmMetricsOomGroupMemUsage_field_types), kNumFields);
+
+    for (int i = 0; i < kNumTests; i++) {
+        for (int j = 0; j < kNumLines; j++) {
+            // golden result does not have UID field, which is date/time based unique ID.
+            ASSERT_EQ(ARRAY_SIZE(golden[i][j]), kNumFields - 1);
+        }
+    }
+
+    for (int test_iteration = 0; test_iteration < kNumTests; ++test_iteration) {
+        // setup
+        mreport.setBasePath(data_path[test_iteration]);
+
+        // --- start test ---
+        ASSERT_TRUE(mreport.readMmProcessUsageByOomGroup(&ogusage));
+        ASSERT_EQ(ogusage.size(), kNumLines);
+
+        int line = 0;
+        for (const auto &u : ogusage) {
+            std::vector<VendorAtomValue> values =
+                    mreport.genMmProcessUsageByOomGroupSnapshotAtom(u);
+            int32_t &uid = og_metric_uid[test_iteration];
+
+            // check size
+            ASSERT_EQ(values.size(), kNumFields)
+                    << "Size mismatch: test# " << test_iteration << " line " << line;
+
+            if (line == 0) {
+                uid = getVendorAtomIntValue(values[0]);
+            } else {
+                // check UID
+                EXPECT_EQ(getVendorAtomIntValue(values[0]), uid)
+                        << "value mismatch: test# " << test_iteration << " line " << line
+                        << " field 0";
+            }
+
+            for (int field = 1; field < kNumFields; ++field) {
+                // check types
+                EXPECT_EQ(static_cast<int>(values[field].getTag()), gold_ftype[field])
+                        << "type mismatch: test# " << test_iteration << " line " << line
+                        << " field " << field;
+
+                if (static_cast<int>(values[field].getTag()) != gold_ftype[field])
+                    continue;  // no checking values when the type is already wrong.
+
+                // check values
+                EXPECT_EQ(getVendorAtomIntValue(values[field]),
+                          golden[test_iteration][line][field - 1])
+                        << "value mismatch: test# " << test_iteration << " line " << line
+                        << " field " << field;
+            }
+            line++;
+        }
+        // --- end test ---
+    }
+
+    // metric_uid must be unique
+    EXPECT_NE(og_metric_uid[0], og_metric_uid[1]);
+}
+
+TEST(MmMetricsReporterTest, MmMetricsOomGroupMemUsageFailFileNotFound) {
+    constexpr int kNumTests = 2;
+    MockMmMetricsReporter mreport;
+    const std::string data_path = std::string(data_base_path) + "/nonexisting_dir";
+    std::vector<MmMetricsReporter::OomGroupMemUsage> ogusage;
+    int32_t uid;
+
+    // setup
+    mreport.setBasePath(data_path);
+
+    // --- start test ---
+    ASSERT_FALSE(mreport.readMmProcessUsageByOomGroup(&ogusage));
+    ASSERT_EQ(ogusage.size(), 0);
+}
+
+static bool file_exists(const char *const path) {
+    struct stat sbuf;
+
+    return (stat(path, &sbuf) == 0);
+}
+
+TEST(MmMetricsReporterTest, MmMetricsOomGroupMemUsageMultipleFailCases) {
+    constexpr int kNumTests = 8;
+    MockMmMetricsReporter mreport;
+    const std::string data_path[kNumTests] = {
+            std::string(data_base_path) + "/test_data_oom_usage_fail/1",
+            std::string(data_base_path) + "/test_data_oom_usage_fail/2",
+            std::string(data_base_path) + "/test_data_oom_usage_fail/3",
+            std::string(data_base_path) + "/test_data_oom_usage_fail/4",
+            std::string(data_base_path) + "/test_data_oom_usage_fail/5",
+            std::string(data_base_path) + "/test_data_oom_usage_fail/6",
+            std::string(data_base_path) + "/test_data_oom_usage_fail/7",
+            std::string(data_base_path) + "/test_data_oom_usage_fail/8",
+    };
+    const char *file = "oom_mm_usage";
+    std::vector<MmMetricsReporter::OomGroupMemUsage> ogusage;
+
+    for (int test_iteration = 0; test_iteration < kNumTests; ++test_iteration) {
+        // setup
+        mreport.setBasePath(data_path[test_iteration]);
+
+        // check file exist, otherwise it is testing "file not found" rather than the desired test
+        ASSERT_TRUE(file_exists((data_path[test_iteration] + "/" + file).c_str()));
+
+        // --- start test ---
+        ASSERT_FALSE(mreport.readMmProcessUsageByOomGroup(&ogusage))
+                << "Iteration " << test_iteration << ": test fail.";
+        ASSERT_EQ(ogusage.size(), 0) << "Iteration " << test_iteration << ": test fail.";
+    }
+}
+
+TEST(MmMetricsReporterTest, MmMetricsGcmaPerHourSuccess) {
+    MockMmMetricsReporter mreport;
+    const std::string data_path = std::string(data_base_path) + "/test_data_0";
+    auto &golden = MmMetricsGcmaPerHour_golden;
+    auto &gold_ftype = MmMetricsGcmaPerHour_field_types;
+
+    constexpr int kNumFields = ARRAY_SIZE(gold_ftype);
+    constexpr int kNumLines = ARRAY_SIZE(golden);
+
+    // Check testcase consistency (if fail, the test case itself has some bug)
+    ASSERT_EQ(kNumFields, kNumLines);
+
+    // setup
+    mreport.setBasePath(data_path);
+
+    // --- start test ---
+    std::vector<VendorAtomValue> values = mreport.readAndGenGcmaPerHour();
+
+    // check size
+    ASSERT_EQ(values.size(), kNumLines);
+
+    for (int field = 0; field < kNumFields; ++field) {
+        // check type
+        EXPECT_EQ(static_cast<int>(values[field].getTag()), gold_ftype[field])
+                << "type mismatch @ field #" << field;
+
+        if (static_cast<int>(values[field].getTag()) != gold_ftype[field])
+            continue;  // no checking the value when the type is wrong.
+
+        // check value
+        EXPECT_EQ(getVendorAtomIntValue(values[field]), golden[field])
+                << "value mismatch @ field #" << field;
+    }
+}
+
+TEST(MmMetricsReporterTest, MmMetricsGcmaPerDaySuccess) {
+    MockMmMetricsReporter mreport;
+    const std::string data_path = std::string(data_base_path) + "/test_data_0";
+    auto &golden_simple = MmMetricsGcmaPerDaySimple_golden;
+    auto &golden_histogram = MmMetricsGcmaPerDayHistogram_golden;
+
+    auto &gold_simple_ftype = MmMetricsGcmaPerDaySimple_field_types;
+    auto &gold_histogram_ftype = MmMetricsGcmaPerDayHistogram_field_types;
+
+    constexpr int kNumSimpleValues = 4;
+    constexpr int kNumHistogramValues = 4;
+    // total field num in atom values need to count the histogram array as one.
+    constexpr int kNumAtomValues = kNumSimpleValues + 1;
+
+    // Check testcase consistency (if fail, the test case itself has some bug)
+    ASSERT_EQ(ARRAY_SIZE(golden_simple), kNumSimpleValues);
+    ASSERT_EQ(ARRAY_SIZE(golden_histogram), kNumHistogramValues);
+    ASSERT_EQ(ARRAY_SIZE(gold_simple_ftype), kNumSimpleValues + 1);  // count the last array type
+    ASSERT_EQ(ARRAY_SIZE(gold_histogram_ftype), kNumHistogramValues);
+
+    // setup
+    mreport.setBasePath(data_path);
+
+    // --- start test ---
+    std::vector<VendorAtomValue> values = mreport.readAndGenGcmaPerDay();
+
+    /*
+     * check size +1:
+     * Histogram in the form of a vector in the last element of 'Simple' value array.
+     */
+    ASSERT_EQ(values.size(), kNumAtomValues);
+
+    // check 'simple' values
+    for (int field = 0; field < kNumSimpleValues; ++field) {
+        // check type
+        EXPECT_EQ(static_cast<int>(values[field].getTag()), gold_simple_ftype[field])
+                << "type mismatch @ field #" << field;
+
+        if (static_cast<int>(values[field].getTag()) != gold_simple_ftype[field])
+            continue;  // no checking the value when the type is wrong.
+
+        if (field == kNumAtomValues - 1)
+            continue;  // same as break.  The last one is an array, compare type only here.
+
+        EXPECT_EQ(getVendorAtomIntValue(values[field]), golden_simple[field])
+                << "value mismatch @ field #" << field;
+    }
+
+    // check array validity
+    auto &arrAtomValue = values[kNumAtomValues - 1];
+    const std::optional<std::vector<int64_t>> &repeatedLongValue =
+            arrAtomValue.get<VendorAtomValue::repeatedLongValue>();
+    ASSERT_TRUE(repeatedLongValue.has_value());
+
+    // check array size
+    ASSERT_EQ(repeatedLongValue.value().size(), kNumHistogramValues);
+
+    // check array values
+    for (int field = 0; field < kNumHistogramValues; ++field) {
+        EXPECT_EQ(repeatedLongValue.value()[field], golden_histogram[field]);
+    }
+}
+
 }  // namespace pixel
 }  // namespace google
 }  // namespace hardware
diff --git a/pixelstats/test/mm/MockMmMetricsReporter.h b/pixelstats/test/mm/MockMmMetricsReporter.h
index bdf67c1e..25bddf3a 100644
--- a/pixelstats/test/mm/MockMmMetricsReporter.h
+++ b/pixelstats/test/mm/MockMmMetricsReporter.h
@@ -82,10 +82,30 @@ class MockMmMetricsReporter : public MmMetricsReporter {
             {"/proc/pressure/memory", "psi_memory"},
             {"kswapd0", "kswapd0_stat"},
             {"kcompactd0", "kcompactd0_stat"},
+            {"/proc/vendor_mm/memory_usage_by_oom_score", "oom_mm_usage"},
+            {"/sys/kernel/vendor_mm/gcma/cached", "gcma_cached"},
+            {"/sys/kernel/vendor_mm/gcma/discarded", "gcma_discarded"},
+            {"/sys/kernel/vendor_mm/gcma/evicted", "gcma_evicted"},
+            {"/sys/kernel/vendor_mm/gcma/loaded", "gcma_loaded"},
+            {"/sys/kernel/vendor_mm/gcma/stored", "gcma_stored"},
+            {"/sys/kernel/vendor_mm/gcma/latency_low", "gcma_latency_low"},
+            {"/sys/kernel/vendor_mm/gcma/latency_mid", "gcma_latency_mid"},
+            {"/sys/kernel/vendor_mm/gcma/latency_high", "gcma_latency_high"},
+            {"/sys/kernel/vendor_mm/gcma/latency_extreme_high", "gcma_latency_extreme_high"},
     };
 
     virtual std::string getSysfsPath(const std::string &path) {
-        return base_path_ + "/" + mock_path_map.at(path);
+        std::string ret(base_path_ + '/');
+        if (mock_path_map.find(path) == mock_path_map.end()) {
+            /*
+             * This mapped file won't exist in the test directory,
+             * so this effectively emulates a 'file-not-found' condition
+             * for testing the failed cases.
+             */
+            return ret + "not_found";
+        } else {
+            return ret + mock_path_map.at(path);
+        }
     }
 
     virtual std::string getProcessStatPath(const std::string &name, int *prev_pid) {
diff --git a/pixelstats/test/mm/VendorAtomIntValueUtil.h b/pixelstats/test/mm/VendorAtomIntValueUtil.h
index 1275112c..6063df86 100644
--- a/pixelstats/test/mm/VendorAtomIntValueUtil.h
+++ b/pixelstats/test/mm/VendorAtomIntValueUtil.h
@@ -23,6 +23,7 @@ constexpr int intValue = static_cast<int>(VendorAtomValue::intValue);
 constexpr int longValue = static_cast<int>(VendorAtomValue::longValue);
 constexpr int floatValue = static_cast<int>(VendorAtomValue::floatValue);
 constexpr int stringValue = static_cast<int>(VendorAtomValue::stringValue);
+constexpr int repeatedLongValue = static_cast<int>(VendorAtomValue::repeatedLongValue);
 
 static int64_t getVendorAtomIntValue(const VendorAtomValue &v) {
     switch (v.getTag()) {
diff --git a/pixelstats/test/mm/data/test_data_0/gcma_cached b/pixelstats/test/mm/data/test_data_0/gcma_cached
new file mode 100644
index 00000000..b1bd38b6
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_0/gcma_cached
@@ -0,0 +1 @@
+13
diff --git a/pixelstats/test/mm/data/test_data_0/gcma_discarded b/pixelstats/test/mm/data/test_data_0/gcma_discarded
new file mode 100644
index 00000000..d00491fd
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_0/gcma_discarded
@@ -0,0 +1 @@
+1
diff --git a/pixelstats/test/mm/data/test_data_0/gcma_evicted b/pixelstats/test/mm/data/test_data_0/gcma_evicted
new file mode 100644
index 00000000..0cfbf088
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_0/gcma_evicted
@@ -0,0 +1 @@
+2
diff --git a/pixelstats/test/mm/data/test_data_0/gcma_latency_extreme_high b/pixelstats/test/mm/data/test_data_0/gcma_latency_extreme_high
new file mode 100644
index 00000000..45a4fb75
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_0/gcma_latency_extreme_high
@@ -0,0 +1 @@
+8
diff --git a/pixelstats/test/mm/data/test_data_0/gcma_latency_high b/pixelstats/test/mm/data/test_data_0/gcma_latency_high
new file mode 100644
index 00000000..7f8f011e
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_0/gcma_latency_high
@@ -0,0 +1 @@
+7
diff --git a/pixelstats/test/mm/data/test_data_0/gcma_latency_low b/pixelstats/test/mm/data/test_data_0/gcma_latency_low
new file mode 100644
index 00000000..7ed6ff82
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_0/gcma_latency_low
@@ -0,0 +1 @@
+5
diff --git a/pixelstats/test/mm/data/test_data_0/gcma_latency_mid b/pixelstats/test/mm/data/test_data_0/gcma_latency_mid
new file mode 100644
index 00000000..1e8b3149
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_0/gcma_latency_mid
@@ -0,0 +1 @@
+6
diff --git a/pixelstats/test/mm/data/test_data_0/gcma_loaded b/pixelstats/test/mm/data/test_data_0/gcma_loaded
new file mode 100644
index 00000000..00750edc
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_0/gcma_loaded
@@ -0,0 +1 @@
+3
diff --git a/pixelstats/test/mm/data/test_data_0/gcma_stored b/pixelstats/test/mm/data/test_data_0/gcma_stored
new file mode 100644
index 00000000..b8626c4c
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_0/gcma_stored
@@ -0,0 +1 @@
+4
diff --git a/pixelstats/test/mm/data/test_data_0/oom_mm_usage b/pixelstats/test/mm/data/test_data_0/oom_mm_usage
new file mode 100644
index 00000000..2f72f521
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_0/oom_mm_usage
@@ -0,0 +1,25 @@
+# oom_group  <nr_task > <file_rss_kb> <anon_rss_kb> <pgtable_kb> <swap_ents_kb> <shmem_rss_kb>,
+[951,1000]             0          102         103          104        105           106
+[901,950]            201            0         203          204        205           206
+[851,900]            301          302           0          304        305           306
+[801,850]            401          402         403            0        405           406
+[751,800]            501          502         503          504          0           506
+[701,750]            601          602         603          604        605             0
+[651,700]            701          702         703          704        705           706
+[601,650]            801          802         803          804        805           806
+[551,600]            901          902         903          904        905           906
+[501,550]           1001         1002        1003         1004       1005          1006
+[451,500]           1101         1102        1103         1104       1105          1106
+[401,450]           1201         1202        1203         1204       1205          1206
+[351,400]           1301         1302        1303         1304       1305          1306
+[301,350]           1401         1402        1403         1404       1405          1406
+[251,300]           1501         1502        1503         1504       1505          1506
+[201,250]           1601         1602        1603         1604       1605          1606
+[200,200]           1701         1702        1703         1704       1705          1706
+[151,199]           1801         1802        1803         1804       1805          1806
+[101,150]           1901         1902        1903         1904       1905          1906
+[51,100]            2001         2002        2003         2004       2005          2006
+[1,50]              2101         2102        2103         2104       2105          2106
+[0,0]               2201         2202        2203         2204       2205          2206
+[-1000,-1]          2301         2302        2303         2304       2305          2306
+
diff --git a/pixelstats/test/mm/data/test_data_1/oom_mm_usage b/pixelstats/test/mm/data/test_data_1/oom_mm_usage
new file mode 100644
index 00000000..f204e96d
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_1/oom_mm_usage
@@ -0,0 +1,25 @@
+# oom_group  <nr_task > <file_rss_kb> <anon_rss_kb> <pgtable_kb> <swap_ents_kb> <shmem_rss_kb>,
+[951,1000]          3101         3102        3103         3104       3105          3106
+[901,950]           3201         3202        3203         3204       3205          3206
+[851,900]           3301         3302        3303         3304       3305          3306
+[801,850]           3401         3402        3403         3404       3405          3406
+[751,800]           3501         3502        3503         3504       3505          3506
+[701,750]           3601         3602        3603         3604       3605          3606
+[651,700]           3701         3702        3703         3704       3705          3706
+[601,650]           3801         3802        3803         3804       3805          3806
+[551,600]           3901         3902        3903         3904       3905          3906
+[501,550]           4001         4002        4003         4004       4005          4006
+[451,500]           4101         4102        4103         4104       4105          4106
+[401,450]           4201         4202        4203         4204       4205          4206
+[351,400]           4301         4302        4303         4304       4305          4306
+[301,350]           4401         4402        4403         4404       4405          4406
+[251,300]           4501         4502        4503         4504       4505          4506
+[201,250]           4601         4602        4603         4604       4605          4606
+[200,200]           4701         4702        4703         4704       4705          4706
+[151,199]           4801         4802        4803         4804       4805          4806
+[101,150]           4901         4902        4903         4904       4905          4906
+[51,100]            5001         5002        5003         5004       5005          5006
+[1,50]              5101         5102        5103         5104       5105          5106
+[0,0]               5201         5202        5203         5204       5205          5206
+[-1000,-1]          5301         5302        5303         5304       5305          5306
+
diff --git a/pixelstats/test/mm/data/test_data_oom_usage_fail/1/oom_mm_usage b/pixelstats/test/mm/data/test_data_oom_usage_fail/1/oom_mm_usage
new file mode 100644
index 00000000..332757c2
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_oom_usage_fail/1/oom_mm_usage
@@ -0,0 +1,26 @@
+# oom_group  <nr_task > <file_rss_kb> <anon_rss_kb> <pgtable_kb> <swap_ents_kb> <shmem_rss_kb>,
+[951,1000]             0          102         103          104        105           106
+[901,950]            201            0         203          204        205           206
+[851,900]            301          302           0          304        305           306
+# error line below: insufficient number of tokens
+[801,850]            401          402         403            0        405
+[751,800]            501          502         503          504          0           506
+[701,750]            601          602         603          604        605             0
+[651,700]            701          702         703          704        705           706
+[601,650]            801          802         803          804        805           806
+[551,600]            901          902         903          904        905           906
+[501,550]           1001         1002        1003         1004       1005          1006
+[451,500]           1101         1102        1103         1104       1105          1106
+[401,450]           1201         1202        1203         1204       1205          1206
+[351,400]           1301         1302        1303         1304       1305          1306
+[301,350]           1401         1402        1403         1404       1405          1406
+[251,300]           1501         1502        1503         1504       1505          1506
+[201,250]           1601         1602        1603         1604       1605          1606
+[200,200]           1701         1702        1703         1704       1705          1706
+[151,199]           1801         1802        1803         1804       1805          1806
+[101,150]           1901         1902        1903         1904       1905          1906
+[51,100]            2001         2002        2003         2004       2005          2006
+[1,50]              2101         2102        2103         2104       2105          2106
+[0,0]               2201         2202        2203         2204       2205          2206
+[-1000,-1]          2301         2302        2303         2304       2305          2306
+
diff --git a/pixelstats/test/mm/data/test_data_oom_usage_fail/2/oom_mm_usage b/pixelstats/test/mm/data/test_data_oom_usage_fail/2/oom_mm_usage
new file mode 100644
index 00000000..501f9112
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_oom_usage_fail/2/oom_mm_usage
@@ -0,0 +1,26 @@
+# oom_group  <nr_task > <file_rss_kb> <anon_rss_kb> <pgtable_kb> <swap_ents_kb> <shmem_rss_kb>,
+[951,1000]             0          102         103          104        105           106
+[901,950]            201            0         203          204        205           206
+[851,900]            301          302           0          304        305           306
+[801,850]            401          402         403            0        405           406
+[751,800]            501          502         503          504          0           506
+[701,750]            601          602         603          604        605             0
+[651,700]            701          702         703          704        705           706
+[601,650]            801          802         803          804        805           806
+# Error line: No such range "[225,431]"
+[225,431]            901          902         903          904        905           906
+[501,550]           1001         1002        1003         1004       1005          1006
+[451,500]           1101         1102        1103         1104       1105          1106
+[401,450]           1201         1202        1203         1204       1205          1206
+[351,400]           1301         1302        1303         1304       1305          1306
+[301,350]           1401         1402        1403         1404       1405          1406
+[251,300]           1501         1502        1503         1504       1505          1506
+[201,250]           1601         1602        1603         1604       1605          1606
+[200,200]           1701         1702        1703         1704       1705          1706
+[151,199]           1801         1802        1803         1804       1805          1806
+[101,150]           1901         1902        1903         1904       1905          1906
+[51,100]            2001         2002        2003         2004       2005          2006
+[1,50]              2101         2102        2103         2104       2105          2106
+[0,0]               2201         2202        2203         2204       2205          2206
+[-1000,-1]          2301         2302        2303         2304       2305          2306
+
diff --git a/pixelstats/test/mm/data/test_data_oom_usage_fail/3/oom_mm_usage b/pixelstats/test/mm/data/test_data_oom_usage_fail/3/oom_mm_usage
new file mode 100644
index 00000000..41be8423
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_oom_usage_fail/3/oom_mm_usage
@@ -0,0 +1,26 @@
+# oom_group  <nr_task > <file_rss_kb> <anon_rss_kb> <pgtable_kb> <swap_ents_kb> <shmem_rss_kb>,
+[951,1000]             0          102         103          104        105           106
+[901,950]            201            0         203          204        205           206
+[851,900]            301          302           0          304        305           306
+# Error line: negative number
+[801,850]            401          402         403           -3        405           406
+[751,800]            501          502         503          504          0           506
+[701,750]            601          602         603          604        605             0
+[651,700]            701          702         703          704        705           706
+[601,650]            801          802         803          804        805           806
+[551,600]            901          902         903          904        905           906
+[501,550]           1001         1002        1003         1004       1005          1006
+[451,500]           1101         1102        1103         1104       1105          1106
+[401,450]           1201         1202        1203         1204       1205          1206
+[351,400]           1301         1302        1303         1304       1305          1306
+[301,350]           1401         1402        1403         1404       1405          1406
+[251,300]           1501         1502        1503         1504       1505          1506
+[201,250]           1601         1602        1603         1604       1605          1606
+[200,200]           1701         1702        1703         1704       1705          1706
+[151,199]           1801         1802        1803         1804       1805          1806
+[101,150]           1901         1902        1903         1904       1905          1906
+[51,100]            2001         2002        2003         2004       2005          2006
+[1,50]              2101         2102        2103         2104       2105          2106
+[0,0]               2201         2202        2203         2204       2205          2206
+[-1000,-1]          2301         2302        2303         2304       2305          2306
+
diff --git a/pixelstats/test/mm/data/test_data_oom_usage_fail/4/oom_mm_usage b/pixelstats/test/mm/data/test_data_oom_usage_fail/4/oom_mm_usage
new file mode 100644
index 00000000..3ae807b1
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_oom_usage_fail/4/oom_mm_usage
@@ -0,0 +1,26 @@
+# oom_group  <nr_task > <file_rss_kb> <anon_rss_kb> <pgtable_kb> <swap_ents_kb> <shmem_rss_kb>,
+[951,1000]             0          102         103          104        105           106
+[901,950]            201            0         203          204        205           206
+[851,900]            301          302           0          304        305           306
+[801,850]            401          402         403            0        405           406
+[751,800]            501          502         503          504          0           506
+[701,750]            601          602         603          604        605             0
+# Error line: not an integer: "y04"
+[651,700]            701          702         703          y04        705           706
+[601,650]            801          802         803          804        805           806
+[551,600]            901          902         903          904        905           906
+[501,550]           1001         1002        1003         1004       1005          1006
+[451,500]           1101         1102        1103         1104       1105          1106
+[401,450]           1201         1202        1203         1204       1205          1206
+[351,400]           1301         1302        1303         1304       1305          1306
+[301,350]           1401         1402        1403         1404       1405          1406
+[251,300]           1501         1502        1503         1504       1505          1506
+[201,250]           1601         1602        1603         1604       1605          1606
+[200,200]           1701         1702        1703         1704       1705          1706
+[151,199]           1801         1802        1803         1804       1805          1806
+[101,150]           1901         1902        1903         1904       1905          1906
+[51,100]            2001         2002        2003         2004       2005          2006
+[1,50]              2101         2102        2103         2104       2105          2106
+[0,0]               2201         2202        2203         2204       2205          2206
+[-1000,-1]          2301         2302        2303         2304       2305          2306
+
diff --git a/pixelstats/test/mm/data/test_data_oom_usage_fail/5/oom_mm_usage b/pixelstats/test/mm/data/test_data_oom_usage_fail/5/oom_mm_usage
new file mode 100644
index 00000000..ab36e003
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_oom_usage_fail/5/oom_mm_usage
@@ -0,0 +1,26 @@
+# oom_group  <nr_task > <file_rss_kb> <anon_rss_kb> <pgtable_kb> <swap_ents_kb> <shmem_rss_kb>,
+[951,1000]             0          102         103          104        105           106
+[901,950]            201            0         203          204        205           206
+[851,900]            301          302           0          304        305           306
+[801,850]            401          402         403            0        405           406
+[751,800]            501          502         503          504          0           506
+[701,750]            601          602         603          604        605             0
+[651,700]            701          702         703          704        705           706
+[601,650]            801          802         803          804        805           806
+[551,600]            901          902         903          904        905           906
+# Error line: not an integer: floating point 1003.25"
+[501,550]           1001         1002        1003.25      1004       1005          1006
+[451,500]           1101         1102        1103         1104       1105          1106
+[401,450]           1201         1202        1203         1204       1205          1206
+[351,400]           1301         1302        1303         1304       1305          1306
+[301,350]           1401         1402        1403         1404       1405          1406
+[251,300]           1501         1502        1503         1504       1505          1506
+[201,250]           1601         1602        1603         1604       1605          1606
+[200,200]           1701         1702        1703         1704       1705          1706
+[151,199]           1801         1802        1803         1804       1805          1806
+[101,150]           1901         1902        1903         1904       1905          1906
+[51,100]            2001         2002        2003         2004       2005          2006
+[1,50]              2101         2102        2103         2104       2105          2106
+[0,0]               2201         2202        2203         2204       2205          2206
+[-1000,-1]          2301         2302        2303         2304       2305          2306
+
diff --git a/pixelstats/test/mm/data/test_data_oom_usage_fail/6/oom_mm_usage b/pixelstats/test/mm/data/test_data_oom_usage_fail/6/oom_mm_usage
new file mode 100644
index 00000000..40a9dae4
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_oom_usage_fail/6/oom_mm_usage
@@ -0,0 +1,25 @@
+#  23y03 not an integer: oom_group  <nr_task > <file_rss_kb> <anon_rss_kb> <pgtable_kb> <swap_ents_kb> <shmem_rss_kb>,
+[951,1000]             0          102         103          104        105           106
+[901,950]            201            0         203          204        205           206
+[851,900]            301          302           0          304        305           306
+[801,850]            401          402         403            0        405           406
+[751,800]            501          502         503          504          0           506
+[701,750]            601          602         603          604        605             0
+[651,700]            701          702         703          704        705           706
+[601,650]            801          802         803          804        805           806
+[551,600]            901          902         903          904        905           906
+[501,550]           1001         1002        1003.25      1004       1005          1006
+[451,500]           1101         1102        1103         1104       1105          1106
+[401,450]           1201         1202        1203         1204       1205          1206
+[351,400]           1301         1302        1303         1304       1305          1306
+[301,350]           1401         1402        1403         1404       1405          1406
+[251,300]           1501         1502        1503         1504       1505          1506
+[201,250]           1601         1602        1603         1604       1605          1606
+[200,200]           1701         1702        1703         1704       1705          1706
+[151,199]           1801         1802        1803         1804       1805          1806
+[101,150]           1901         1902        1903         1904       1905          1906
+[51,100]            2001         2002        2003         2004       2005          2006
+[1,50]              2101         2102        2103         2104       2105          2106
+[0,0]               2201         2202        2203         2204       2205          2206
+[-1000,-1]          2301         2302        23y03         2304       2305          2306
+
diff --git a/pixelstats/test/mm/data/test_data_oom_usage_fail/7/oom_mm_usage b/pixelstats/test/mm/data/test_data_oom_usage_fail/7/oom_mm_usage
new file mode 100644
index 00000000..64356930
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_oom_usage_fail/7/oom_mm_usage
@@ -0,0 +1,28 @@
+# Error file: trailing extra groups
+[951,1000]             0          102         103          104        105           106
+[901,950]            201            0         203          204        205           206
+[851,900]            301          302           0          304        305           306
+[801,850]            401          402         403            0        405           406
+[751,800]            501          502         503          504          0           506
+[701,750]            601          602         603          604        605             0
+[651,700]            701          702         703          704        705           706
+[601,650]            801          802         803          804        805           806
+[551,600]            901          902         903          904        905           906
+[501,550]           1001         1002        1003         1004       1005          1006
+[451,500]           1101         1102        1103         1104       1105          1106
+[401,450]           1201         1202        1203         1204       1205          1206
+[351,400]           1301         1302        1303         1304       1305          1306
+[301,350]           1401         1402        1403         1404       1405          1406
+[251,300]           1501         1502        1503         1504       1505          1506
+[201,250]           1601         1602        1603         1604       1605          1606
+[200,200]           1701         1702        1703         1704       1705          1706
+[151,199]           1801         1802        1803         1804       1805          1806
+[101,150]           1901         1902        1903         1904       1905          1906
+[51,100]            2001         2002        2003         2004       2005          2006
+[1,50]              2101         2102        2103         2104       2105          2106
+[0,0]               2201         2202        2203         2204       2205          2206
+[-1000,-1]          2301         2302        2303         2304       2305          2306
+[501,550]           1001         1002        1003         1004       1005          1006
+[451,500]           1101         1102        1103         1104       1105          1106
+[401,450]           1201         1202        1203         1204       1205          1206
+[351,400]           1301         1302        1303         1304       1305          1306
diff --git a/pixelstats/test/mm/data/test_data_oom_usage_fail/8/oom_mm_usage b/pixelstats/test/mm/data/test_data_oom_usage_fail/8/oom_mm_usage
new file mode 100644
index 00000000..98f38e10
--- /dev/null
+++ b/pixelstats/test/mm/data/test_data_oom_usage_fail/8/oom_mm_usage
@@ -0,0 +1,26 @@
+# Groups not in descending order error: [351,400] -> [651,700]
+[951,1000]             0          102         103          104        105           106
+[901,950]            201            0         203          204        205           206
+[851,900]            301          302           0          304        305           306
+[801,850]            401          402         403            0        405           406
+[751,800]            501          502         503          504          0           506
+[701,750]            601          602         603          604        605             0
+[601,650]            801          802         803          804        805           806
+[551,600]            901          902         903          904        905           906
+[501,550]           1001         1002        1003         1004       1005          1006
+[451,500]           1101         1102        1103         1104       1105          1106
+[401,450]           1201         1202        1203         1204       1205          1206
+[351,400]           1301         1302        1303         1304       1305          1306
+[651,700]            701          702         703          704        705           706
+[301,350]           1401         1402        1403         1404       1405          1406
+[251,300]           1501         1502        1503         1504       1505          1506
+[201,250]           1601         1602        1603         1604       1605          1606
+[200,200]           1701         1702        1703         1704       1705          1706
+[151,199]           1801         1802        1803         1804       1805          1806
+[101,150]           1901         1902        1903         1904       1905          1906
+[51,100]            2001         2002        2003         2004       2005          2006
+[1,50]              2101         2102        2103         2104       2105          2106
+[0,0]               2201         2202        2203         2204       2205          2206
+[-1000,-1]          2301         2302        2303         2304       2305          2306
+
+
diff --git a/power-libperfmgr/aidl/AdpfTypes.h b/power-libperfmgr/aidl/AdpfTypes.h
index 8f5a018b..4db48948 100644
--- a/power-libperfmgr/aidl/AdpfTypes.h
+++ b/power-libperfmgr/aidl/AdpfTypes.h
@@ -47,6 +47,24 @@ using FlagQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;
 
 enum class AdpfErrorCode : int32_t { ERR_OK = 0, ERR_BAD_STATE = -1, ERR_BAD_ARG = -2 };
 
+enum class SessionJankyLevel : int32_t {
+    /**
+     * Small number of jank frames in the monitoring window.
+     * No extra heuristic boost will be applied.
+     */
+    LIGHT = 0,
+    /**
+     * Moderate number of jank frames in the monitoring window.
+     * Heuristic boost applied.
+     */
+    MODERATE,
+    /**
+     * Significant number of jank frames in the monitoring window.
+     * Heuristic boost applied.
+     */
+    SEVERE,
+};
+
 enum class AdpfVoteType : int32_t {
     CPU_VOTE_DEFAULT = 0,
     CPU_LOAD_UP,
diff --git a/power-libperfmgr/aidl/AppDescriptorTrace.h b/power-libperfmgr/aidl/AppDescriptorTrace.h
index d2d12363..d9af140b 100644
--- a/power-libperfmgr/aidl/AppDescriptorTrace.h
+++ b/power-libperfmgr/aidl/AppDescriptorTrace.h
@@ -60,13 +60,19 @@ struct AppDescriptorTrace {
         trace_is_first_frame = StringPrintf("adpf.%s-%s", idString.c_str(), "is_first_frame");
         // traces for heuristic boost
         trace_avg_duration = StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.avgDuration");
-        trace_heuristic_boost_active =
-                StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.isActive");
+        trace_hboost_janky_level =
+                StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.jankyLevel");
         trace_low_frame_rate =
                 StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.isLowFrameRate");
         trace_max_duration = StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.maxDuration");
         trace_missed_cycles =
                 StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.numOfMissedCycles");
+        trace_uclamp_min_ceiling =
+                StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.uclampMinCeiling");
+        trace_uclamp_min_floor =
+                StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.uclampMinFloor");
+        trace_hboost_pid_pu = StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.uclampPidPu");
+
         for (size_t i = 0; i < trace_modes.size(); ++i) {
             trace_modes[i] = StringPrintf(
                     "adpf.%s-%s_mode", idString.c_str(),
@@ -100,10 +106,14 @@ struct AppDescriptorTrace {
     std::string trace_is_first_frame;
     // traces for heuristic boost
     std::string trace_avg_duration;
-    std::string trace_heuristic_boost_active;
+    std::string trace_hboost_janky_level;
+    std::string trace_hboost_pid_pu;
     std::string trace_low_frame_rate;
     std::string trace_max_duration;
     std::string trace_missed_cycles;
+    std::string trace_uclamp_min_ceiling;
+    std::string trace_uclamp_min_floor;
+
     std::array<std::string, enum_size<aidl::android::hardware::power::SessionMode>()> trace_modes;
     std::array<std::string, static_cast<int32_t>(AdpfVoteType::VOTE_TYPE_SIZE)> trace_votes;
     std::string trace_cpu_duration;
diff --git a/power-libperfmgr/aidl/Power.cpp b/power-libperfmgr/aidl/Power.cpp
index 1a66d70b..6ede0fb2 100644
--- a/power-libperfmgr/aidl/Power.cpp
+++ b/power-libperfmgr/aidl/Power.cpp
@@ -92,8 +92,7 @@ Power::Power(std::shared_ptr<DisplayLowPower> dlpw)
 
 ndk::ScopedAStatus Power::setMode(Mode type, bool enabled) {
     LOG(DEBUG) << "Power setMode: " << toString(type) << " to: " << enabled;
-    if (HintManager::GetInstance()->GetAdpfProfile() &&
-        HintManager::GetInstance()->GetAdpfProfile()->mReportingRateLimitNs > 0) {
+    if (HintManager::GetInstance()->IsAdpfSupported()) {
         PowerSessionManager<>::getInstance()->updateHintMode(toString(type), enabled);
     }
     switch (type) {
@@ -141,6 +140,15 @@ ndk::ScopedAStatus Power::setMode(Mode type, bool enabled) {
                 mVRModeOn = false;
             }
             break;
+        case Mode::AUTOMOTIVE_PROJECTION:
+            mDisplayLowPower->SetAAMode(enabled);
+            if (enabled) {
+                HintManager::GetInstance()->DoHint("AUTOMOTIVE_PROJECTION");
+            } else {
+                HintManager::GetInstance()->EndHint("AUTOMOTIVE_PROJECTION");
+                HintManager::GetInstance()->EndHint("DISPLAY_IDLE_AA");
+            }
+            break;
         case Mode::LAUNCH:
             if (mVRModeOn || mSustainedPerfModeOn) {
                 break;
@@ -219,10 +227,6 @@ ndk::ScopedAStatus Power::isModeSupported(Mode type, bool *_aidl_return) {
 
 ndk::ScopedAStatus Power::setBoost(Boost type, int32_t durationMs) {
     LOG(DEBUG) << "Power setBoost: " << toString(type) << " duration: " << durationMs;
-    if (HintManager::GetInstance()->GetAdpfProfile() &&
-        HintManager::GetInstance()->GetAdpfProfile()->mReportingRateLimitNs > 0) {
-        PowerSessionManager<>::getInstance()->updateHintBoost(toString(type), durationMs);
-    }
     switch (type) {
         case Boost::INTERACTION:
             if (mVRModeOn || mSustainedPerfModeOn) {
@@ -316,7 +320,7 @@ ndk::ScopedAStatus Power::createHintSession(int32_t tgid, int32_t uid,
 }
 
 ndk::ScopedAStatus Power::getHintSessionPreferredRate(int64_t *outNanoseconds) {
-    *outNanoseconds = HintManager::GetInstance()->GetAdpfProfile()
+    *outNanoseconds = HintManager::GetInstance()->IsAdpfSupported()
                               ? HintManager::GetInstance()->GetAdpfProfile()->mReportingRateLimitNs
                               : 0;
     if (*outNanoseconds <= 0) {
@@ -329,8 +333,7 @@ ndk::ScopedAStatus Power::getHintSessionPreferredRate(int64_t *outNanoseconds) {
 ndk::ScopedAStatus Power::createHintSessionWithConfig(
         int32_t tgid, int32_t uid, const std::vector<int32_t> &threadIds, int64_t durationNanos,
         SessionTag tag, SessionConfig *config, std::shared_ptr<IPowerHintSession> *_aidl_return) {
-    if (!HintManager::GetInstance()->GetAdpfProfile() ||
-        HintManager::GetInstance()->GetAdpfProfile()->mReportingRateLimitNs <= 0) {
+    if (!HintManager::GetInstance()->IsAdpfSupported()) {
         *_aidl_return = nullptr;
         return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
     }
diff --git a/power-libperfmgr/aidl/PowerExt.cpp b/power-libperfmgr/aidl/PowerExt.cpp
index ac72f41f..fce358f6 100644
--- a/power-libperfmgr/aidl/PowerExt.cpp
+++ b/power-libperfmgr/aidl/PowerExt.cpp
@@ -47,11 +47,18 @@ ndk::ScopedAStatus PowerExt::setMode(const std::string &mode, bool enabled) {
     } else {
         HintManager::GetInstance()->EndHint(mode);
     }
-    if (HintManager::GetInstance()->GetAdpfProfile() &&
-        HintManager::GetInstance()->GetAdpfProfile()->mReportingRateLimitNs > 0) {
+    if (HintManager::GetInstance()->IsAdpfSupported()) {
         PowerSessionManager<>::getInstance()->updateHintMode(mode, enabled);
     }
 
+    if (mode == "DISPLAY_IDLE" && mDisplayLowPower->IsAAModeOn()) {
+        if (enabled) {
+            HintManager::GetInstance()->DoHint("DISPLAY_IDLE_AA");
+        } else {
+            HintManager::GetInstance()->EndHint("DISPLAY_IDLE_AA");
+        }
+    }
+
     return ndk::ScopedAStatus::ok();
 }
 
@@ -68,10 +75,6 @@ ndk::ScopedAStatus PowerExt::isModeSupported(const std::string &mode, bool *_aid
 
 ndk::ScopedAStatus PowerExt::setBoost(const std::string &boost, int32_t durationMs) {
     LOG(DEBUG) << "PowerExt setBoost: " << boost << " duration: " << durationMs;
-    if (HintManager::GetInstance()->GetAdpfProfile() &&
-        HintManager::GetInstance()->GetAdpfProfile()->mReportingRateLimitNs > 0) {
-        PowerSessionManager<>::getInstance()->updateHintBoost(boost, durationMs);
-    }
 
     if (durationMs > 0) {
         HintManager::GetInstance()->DoHint(boost, std::chrono::milliseconds(durationMs));
diff --git a/power-libperfmgr/aidl/PowerHintSession.cpp b/power-libperfmgr/aidl/PowerHintSession.cpp
index 91f23b5f..e6f07317 100644
--- a/power-libperfmgr/aidl/PowerHintSession.cpp
+++ b/power-libperfmgr/aidl/PowerHintSession.cpp
@@ -23,7 +23,6 @@
 #include <android-base/parsedouble.h>
 #include <android-base/properties.h>
 #include <android-base/stringprintf.h>
-#include <perfmgr/AdpfConfig.h>
 #include <private/android_filesystem_config.h>
 #include <sys/syscall.h>
 #include <time.h>
@@ -44,6 +43,7 @@ namespace pixel {
 
 using ::android::base::StringPrintf;
 using ::android::perfmgr::AdpfConfig;
+using ::android::perfmgr::HintManager;
 using std::chrono::duration_cast;
 using std::chrono::nanoseconds;
 
@@ -62,7 +62,7 @@ static inline int64_t ns_to_100us(int64_t ns) {
 template <class HintManagerT, class PowerSessionManagerT>
 int64_t PowerHintSession<HintManagerT, PowerSessionManagerT>::convertWorkDurationToBoostByPid(
         const std::vector<WorkDuration> &actualDurations) {
-    std::shared_ptr<AdpfConfig> adpfConfig = HintManagerT::GetInstance()->GetAdpfProfile();
+    std::shared_ptr<AdpfConfig> adpfConfig = getAdpfProfile();
     const nanoseconds &targetDuration = mDescriptor->targetNs;
     int64_t &integral_error = mDescriptor->integral_error;
     int64_t &previous_error = mDescriptor->previous_error;
@@ -104,9 +104,20 @@ int64_t PowerHintSession<HintManagerT, PowerSessionManagerT>::convertWorkDuratio
 
     auto pid_pu_active = adpfConfig->mPidPu;
     if (adpfConfig->mHeuristicBoostOn.has_value() && adpfConfig->mHeuristicBoostOn.value()) {
-        pid_pu_active = mHeuristicBoostActive
-                                ? adpfConfig->mPidPu * adpfConfig->mHBoostPidPuFactor.value()
-                                : adpfConfig->mPidPu;
+        auto hboostPidPu = std::min(adpfConfig->mHBoostSevereJankPidPu.value(), adpfConfig->mPidPu);
+        if (mJankyLevel == SessionJankyLevel::MODERATE) {
+            double JankyFactor =
+                    mJankyFrameNum < adpfConfig->mHBoostModerateJankThreshold.value()
+                            ? 0.0
+                            : (mJankyFrameNum - adpfConfig->mHBoostModerateJankThreshold.value()) *
+                                      1.0 /
+                                      (adpfConfig->mHBoostSevereJankThreshold.value() -
+                                       adpfConfig->mHBoostModerateJankThreshold.value());
+            pid_pu_active = adpfConfig->mPidPu + JankyFactor * (hboostPidPu - adpfConfig->mPidPu);
+        } else if (mJankyLevel == SessionJankyLevel::SEVERE) {
+            pid_pu_active = hboostPidPu;
+        }
+        ATRACE_INT(mAppDescriptorTrace->trace_hboost_pid_pu.c_str(), pid_pu_active * 100);
     }
     int64_t pOut = static_cast<int64_t>((err_sum > 0 ? adpfConfig->mPidPo : pid_pu_active) *
                                         err_sum / (length - p_start));
@@ -133,31 +144,30 @@ PowerHintSession<HintManagerT, PowerSessionManagerT>::PowerHintSession(
         SessionTag tag)
     : mPSManager(PowerSessionManagerT::getInstance()),
       mSessionId(++sSessionIDCounter),
-      mIdString(StringPrintf("%" PRId32 "-%" PRId32 "-%" PRId64, tgid, uid, mSessionId)),
+      mIdString(StringPrintf("%" PRId32 "-%" PRId32 "-%" PRId64 "-%s", tgid, uid, mSessionId,
+                             toString(tag).c_str())),
       mDescriptor(std::make_shared<AppHintDesc>(mSessionId, tgid, uid, threadIds, tag,
                                                 std::chrono::nanoseconds(durationNs))),
       mAppDescriptorTrace(std::make_shared<AppDescriptorTrace>(mIdString)),
       mTag(tag),
-      mSessionRecords(
-              HintManagerT::GetInstance()->GetAdpfProfile()->mHeuristicBoostOn.has_value() &&
-                              HintManagerT::GetInstance()
-                                      ->GetAdpfProfile()
-                                      ->mHeuristicBoostOn.value()
-                      ? std::make_unique<SessionRecords>(HintManagerT::GetInstance()
-                                                                 ->GetAdpfProfile()
-                                                                 ->mMaxRecordsNum.value(),
-                                                         HintManagerT::GetInstance()
-                                                                 ->GetAdpfProfile()
-                                                                 ->mJankCheckTimeFactor.value())
-                      : nullptr) {
+      mAdpfProfile(HintManager::GetInstance()->GetAdpfProfile(toString(mTag))),
+      mOnAdpfUpdate(
+              [this](const std::shared_ptr<AdpfConfig> config) { this->setAdpfProfile(config); }),
+      mSessionRecords(getAdpfProfile()->mHeuristicBoostOn.has_value() &&
+                                      getAdpfProfile()->mHeuristicBoostOn.value()
+                              ? std::make_unique<SessionRecords>(
+                                        getAdpfProfile()->mMaxRecordsNum.value(),
+                                        getAdpfProfile()->mJankCheckTimeFactor.value())
+                              : nullptr) {
     ATRACE_CALL();
     ATRACE_INT(mAppDescriptorTrace->trace_target.c_str(), mDescriptor->targetNs.count());
     ATRACE_INT(mAppDescriptorTrace->trace_active.c_str(), mDescriptor->is_active.load());
+    HintManager::GetInstance()->RegisterAdpfUpdateEvent(toString(mTag), &mOnAdpfUpdate);
 
     mLastUpdatedTime = std::chrono::steady_clock::now();
     mPSManager->addPowerSession(mIdString, mDescriptor, mAppDescriptorTrace, threadIds);
     // init boost
-    auto adpfConfig = HintManagerT::GetInstance()->GetAdpfProfile();
+    auto adpfConfig = getAdpfProfile();
     mPSManager->voteSet(
             mSessionId, AdpfVoteType::CPU_LOAD_RESET, adpfConfig->mUclampMinLoadReset, kUclampMax,
             std::chrono::steady_clock::now(),
@@ -189,7 +199,7 @@ void PowerHintSession<HintManagerT, PowerSessionManagerT>::updatePidControlVaria
         int pidControlVariable, bool updateVote) {
     mDescriptor->pidControlVariable = pidControlVariable;
     if (updateVote) {
-        auto adpfConfig = HintManagerT::GetInstance()->GetAdpfProfile();
+        auto adpfConfig = getAdpfProfile();
         mPSManager->voteSet(mSessionId, AdpfVoteType::CPU_VOTE_DEFAULT, pidControlVariable,
                             kUclampMax, std::chrono::steady_clock::now(),
                             std::max(duration_cast<nanoseconds>(mDescriptor->targetNs *
@@ -265,6 +275,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::close()
     // Remove the session from PowerSessionManager first to avoid racing.
     mPSManager->removePowerSession(mSessionId);
     mDescriptor->is_active.store(false);
+    HintManager::GetInstance()->UnregisterAdpfUpdateEvent(toString(mTag), &mOnAdpfUpdate);
     ATRACE_INT(mAppDescriptorTrace->trace_min.c_str(), 0);
     return ndk::ScopedAStatus::ok();
 }
@@ -281,8 +292,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::updateT
         ALOGE("Error: targetDurationNanos(%" PRId64 ") should bigger than 0", targetDurationNanos);
         return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
     }
-    targetDurationNanos =
-            targetDurationNanos * HintManagerT::GetInstance()->GetAdpfProfile()->mTargetTimeFactor;
+    targetDurationNanos = targetDurationNanos * getAdpfProfile()->mTargetTimeFactor;
 
     mDescriptor->targetNs = std::chrono::nanoseconds(targetDurationNanos);
     mPSManager->updateTargetWorkDuration(mSessionId, AdpfVoteType::CPU_VOTE_DEFAULT,
@@ -293,14 +303,42 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::updateT
 }
 
 template <class HintManagerT, class PowerSessionManagerT>
-bool PowerHintSession<HintManagerT, PowerSessionManagerT>::updateHeuristicBoost() {
+SessionJankyLevel PowerHintSession<HintManagerT, PowerSessionManagerT>::updateSessionJankState(
+        SessionJankyLevel oldState, int32_t numOfJankFrames, double durationVariance,
+        bool isLowFPS) {
+    SessionJankyLevel newState = SessionJankyLevel::LIGHT;
+    if (isLowFPS) {
+        newState = SessionJankyLevel::LIGHT;
+        return newState;
+    }
+
+    auto adpfConfig = getAdpfProfile();
+    if (numOfJankFrames < adpfConfig->mHBoostModerateJankThreshold.value()) {
+        if (oldState == SessionJankyLevel::LIGHT ||
+            durationVariance < adpfConfig->mHBoostOffMaxAvgDurRatio.value()) {
+            newState = SessionJankyLevel::LIGHT;
+        } else {
+            newState = SessionJankyLevel::MODERATE;
+        }
+    } else if (numOfJankFrames < adpfConfig->mHBoostSevereJankThreshold.value()) {
+        newState = SessionJankyLevel::MODERATE;
+    } else {
+        newState = SessionJankyLevel::SEVERE;
+    }
+
+    return newState;
+}
+
+template <class HintManagerT, class PowerSessionManagerT>
+void PowerHintSession<HintManagerT, PowerSessionManagerT>::updateHeuristicBoost() {
     auto maxDurationUs = mSessionRecords->getMaxDuration();  // micro seconds
     auto avgDurationUs = mSessionRecords->getAvgDuration();  // micro seconds
     auto numOfReportedDurations = mSessionRecords->getNumOfRecords();
-    auto numOfMissedCycles = mSessionRecords->getNumOfMissedCycles();
+    auto numOfJankFrames = mSessionRecords->getNumOfMissedCycles();
 
     if (!maxDurationUs.has_value() || !avgDurationUs.has_value()) {
-        return false;
+        // No history data stored
+        return;
     }
 
     double maxToAvgRatio;
@@ -310,26 +348,18 @@ bool PowerHintSession<HintManagerT, PowerSessionManagerT>::updateHeuristicBoost(
         maxToAvgRatio = maxDurationUs.value() / avgDurationUs.value();
     }
 
-    auto adpfConfig = HintManagerT::GetInstance()->GetAdpfProfile();
-
-    if (mSessionRecords->isLowFrameRate(adpfConfig->mLowFrameRateThreshold.value())) {
-        // Turn off the boost when the FPS drops to a low value,
-        // since usually this is because of ui changing to low rate scenarios.
-        // Extra boost is not needed in these scenarios.
-        mHeuristicBoostActive = false;
-    } else if (numOfMissedCycles >= adpfConfig->mHBoostOnMissedCycles.value()) {
-        mHeuristicBoostActive = true;
-    } else if (numOfMissedCycles <= adpfConfig->mHBoostOffMissedCycles.value() &&
-               maxToAvgRatio < adpfConfig->mHBoostOffMaxAvgRatio.value()) {
-        mHeuristicBoostActive = false;
-    }
-    ATRACE_INT(mAppDescriptorTrace->trace_heuristic_boost_active.c_str(), mHeuristicBoostActive);
-    ATRACE_INT(mAppDescriptorTrace->trace_missed_cycles.c_str(), numOfMissedCycles);
+    auto isLowFPS =
+            mSessionRecords->isLowFrameRate(getAdpfProfile()->mLowFrameRateThreshold.value());
+
+    mJankyLevel = updateSessionJankState(mJankyLevel, numOfJankFrames, maxToAvgRatio, isLowFPS);
+    mJankyFrameNum = numOfJankFrames;
+
+    ATRACE_INT(mAppDescriptorTrace->trace_hboost_janky_level.c_str(),
+               static_cast<int32_t>(mJankyLevel));
+    ATRACE_INT(mAppDescriptorTrace->trace_missed_cycles.c_str(), mJankyFrameNum);
     ATRACE_INT(mAppDescriptorTrace->trace_avg_duration.c_str(), avgDurationUs.value());
     ATRACE_INT(mAppDescriptorTrace->trace_max_duration.c_str(), maxDurationUs.value());
-    ATRACE_INT(mAppDescriptorTrace->trace_low_frame_rate.c_str(),
-               mSessionRecords->isLowFrameRate(adpfConfig->mLowFrameRateThreshold.value()));
-    return mHeuristicBoostActive;
+    ATRACE_INT(mAppDescriptorTrace->trace_low_frame_rate.c_str(), isLowFPS);
 }
 
 template <class HintManagerT, class PowerSessionManagerT>
@@ -352,8 +382,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::reportA
         ALOGE("Error: shouldn't report duration during pause state.");
         return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
     }
-
-    auto adpfConfig = HintManagerT::GetInstance()->GetAdpfProfile();
+    auto adpfConfig = getAdpfProfile();
     mDescriptor->update_count++;
     bool isFirstFrame = isTimeout();
     ATRACE_INT(mAppDescriptorTrace->trace_batch_size.c_str(), actualDurations.size());
@@ -370,10 +399,6 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::reportA
 
     mLastUpdatedTime = std::chrono::steady_clock::now();
     if (isFirstFrame) {
-        if (isAppSession()) {
-            tryToSendPowerHint("ADPF_FIRST_FRAME");
-        }
-
         mPSManager->updateUniversalBoostMode();
     }
 
@@ -384,23 +409,54 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::reportA
         return ndk::ScopedAStatus::ok();
     }
 
-    if (adpfConfig->mHeuristicBoostOn.has_value() && adpfConfig->mHeuristicBoostOn.value()) {
+    bool hboostEnabled =
+            adpfConfig->mHeuristicBoostOn.has_value() && adpfConfig->mHeuristicBoostOn.value();
+
+    if (hboostEnabled) {
         mSessionRecords->addReportedDurations(actualDurations, mDescriptor->targetNs.count());
+        mPSManager->updateHboostStatistics(mSessionId, mJankyLevel, actualDurations.size());
         updateHeuristicBoost();
     }
 
     int64_t output = convertWorkDurationToBoostByPid(actualDurations);
 
     // Apply to all the threads in the group
+    auto uclampMinFloor = adpfConfig->mUclampMinLow;
     auto uclampMinCeiling = adpfConfig->mUclampMinHigh;
-    if (adpfConfig->mHeuristicBoostOn.has_value() && adpfConfig->mHeuristicBoostOn.value()) {
-        uclampMinCeiling = mHeuristicBoostActive ? adpfConfig->mHBoostUclampMin.value()
-                                                 : adpfConfig->mUclampMinHigh;
+    if (hboostEnabled) {
+        auto hboostMinUclampMinFloor = std::max(
+                adpfConfig->mUclampMinLow, adpfConfig->mHBoostUclampMinFloorRange.value().first);
+        auto hboostMaxUclampMinFloor = std::max(
+                adpfConfig->mUclampMinLow, adpfConfig->mHBoostUclampMinFloorRange.value().second);
+        auto hboostMinUclampMinCeiling = std::max(
+                adpfConfig->mUclampMinHigh, adpfConfig->mHBoostUclampMinCeilingRange.value().first);
+        auto hboostMaxUclampMinCeiling =
+                std::max(adpfConfig->mUclampMinHigh,
+                         adpfConfig->mHBoostUclampMinCeilingRange.value().second);
+        if (mJankyLevel == SessionJankyLevel::MODERATE) {
+            double JankyFactor =
+                    mJankyFrameNum < adpfConfig->mHBoostModerateJankThreshold.value()
+                            ? 0.0
+                            : (mJankyFrameNum - adpfConfig->mHBoostModerateJankThreshold.value()) *
+                                      1.0 /
+                                      (adpfConfig->mHBoostSevereJankThreshold.value() -
+                                       adpfConfig->mHBoostModerateJankThreshold.value());
+            uclampMinFloor = hboostMinUclampMinFloor +
+                             (hboostMaxUclampMinFloor - hboostMinUclampMinFloor) * JankyFactor;
+            uclampMinCeiling =
+                    hboostMinUclampMinCeiling +
+                    (hboostMaxUclampMinCeiling - hboostMinUclampMinCeiling) * JankyFactor;
+        } else if (mJankyLevel == SessionJankyLevel::SEVERE) {
+            uclampMinFloor = hboostMaxUclampMinFloor;
+            uclampMinCeiling = hboostMaxUclampMinCeiling;
+        }
+        ATRACE_INT(mAppDescriptorTrace->trace_uclamp_min_ceiling.c_str(), uclampMinCeiling);
+        ATRACE_INT(mAppDescriptorTrace->trace_uclamp_min_floor.c_str(), uclampMinFloor);
     }
 
     int next_min = std::min(static_cast<int>(uclampMinCeiling),
                             mDescriptor->pidControlVariable + static_cast<int>(output));
-    next_min = std::max(static_cast<int>(adpfConfig->mUclampMinLow), next_min);
+    next_min = std::max(static_cast<int>(uclampMinFloor), next_min);
 
     updatePidControlVariable(next_min);
 
@@ -432,65 +488,69 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::reportA
 template <class HintManagerT, class PowerSessionManagerT>
 ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::sendHint(
         SessionHint hint) {
-    std::scoped_lock lock{mPowerHintSessionLock};
-    if (mSessionClosed) {
-        ALOGE("Error: session is dead");
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-    if (mDescriptor->targetNs.count() == 0LL) {
-        ALOGE("Expect to call updateTargetWorkDuration() first.");
-        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
-    }
-    auto adpfConfig = HintManagerT::GetInstance()->GetAdpfProfile();
-
-    switch (hint) {
-        case SessionHint::CPU_LOAD_UP:
-            updatePidControlVariable(mDescriptor->pidControlVariable);
-            mPSManager->voteSet(mSessionId, AdpfVoteType::CPU_LOAD_UP, adpfConfig->mUclampMinLoadUp,
-                                kUclampMax, std::chrono::steady_clock::now(),
-                                mDescriptor->targetNs * 2);
-            break;
-        case SessionHint::CPU_LOAD_DOWN:
-            updatePidControlVariable(adpfConfig->mUclampMinLow);
-            break;
-        case SessionHint::CPU_LOAD_RESET:
-            updatePidControlVariable(
-                    std::max(adpfConfig->mUclampMinInit,
-                             static_cast<uint32_t>(mDescriptor->pidControlVariable)),
-                    false);
-            mPSManager->voteSet(mSessionId, AdpfVoteType::CPU_LOAD_RESET,
-                                adpfConfig->mUclampMinLoadReset, kUclampMax,
-                                std::chrono::steady_clock::now(),
-                                duration_cast<nanoseconds>(mDescriptor->targetNs *
-                                                           adpfConfig->mStaleTimeFactor / 2.0));
-            break;
-        case SessionHint::CPU_LOAD_RESUME:
-            mPSManager->voteSet(mSessionId, AdpfVoteType::CPU_LOAD_RESUME,
-                                mDescriptor->pidControlVariable, kUclampMax,
-                                std::chrono::steady_clock::now(),
-                                duration_cast<nanoseconds>(mDescriptor->targetNs *
-                                                           adpfConfig->mStaleTimeFactor / 2.0));
-            break;
-        case SessionHint::POWER_EFFICIENCY:
-            setMode(SessionMode::POWER_EFFICIENCY, true);
-            break;
-        case SessionHint::GPU_LOAD_UP:
-            mPSManager->voteSet(mSessionId, AdpfVoteType::GPU_LOAD_UP,
-                                Cycles(adpfConfig->mGpuCapacityLoadUpHeadroom),
-                                std::chrono::steady_clock::now(), mDescriptor->targetNs);
-            break;
-        case SessionHint::GPU_LOAD_DOWN:
-            // TODO(kevindubois): add impl
-            break;
-        case SessionHint::GPU_LOAD_RESET:
-            // TODO(kevindubois): add impl
-            break;
-        default:
-            ALOGE("Error: hint is invalid");
-            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
+    {
+        std::scoped_lock lock{mPowerHintSessionLock};
+        if (mSessionClosed) {
+            ALOGE("Error: session is dead");
+            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
+        }
+        if (mDescriptor->targetNs.count() == 0LL) {
+            ALOGE("Expect to call updateTargetWorkDuration() first.");
+            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
+        }
+        auto adpfConfig = getAdpfProfile();
+
+        switch (hint) {
+            case SessionHint::CPU_LOAD_UP:
+                updatePidControlVariable(mDescriptor->pidControlVariable);
+                mPSManager->voteSet(mSessionId, AdpfVoteType::CPU_LOAD_UP,
+                                    adpfConfig->mUclampMinLoadUp, kUclampMax,
+                                    std::chrono::steady_clock::now(), mDescriptor->targetNs * 2);
+                break;
+            case SessionHint::CPU_LOAD_DOWN:
+                updatePidControlVariable(adpfConfig->mUclampMinLow);
+                break;
+            case SessionHint::CPU_LOAD_RESET:
+                updatePidControlVariable(
+                        std::max(adpfConfig->mUclampMinInit,
+                                 static_cast<uint32_t>(mDescriptor->pidControlVariable)),
+                        false);
+                mPSManager->voteSet(mSessionId, AdpfVoteType::CPU_LOAD_RESET,
+                                    adpfConfig->mUclampMinLoadReset, kUclampMax,
+                                    std::chrono::steady_clock::now(),
+                                    duration_cast<nanoseconds>(mDescriptor->targetNs *
+                                                               adpfConfig->mStaleTimeFactor / 2.0));
+                break;
+            case SessionHint::CPU_LOAD_RESUME:
+                mPSManager->voteSet(mSessionId, AdpfVoteType::CPU_LOAD_RESUME,
+                                    mDescriptor->pidControlVariable, kUclampMax,
+                                    std::chrono::steady_clock::now(),
+                                    duration_cast<nanoseconds>(mDescriptor->targetNs *
+                                                               adpfConfig->mStaleTimeFactor / 2.0));
+                break;
+            case SessionHint::POWER_EFFICIENCY:
+                setMode(SessionMode::POWER_EFFICIENCY, true);
+                break;
+            case SessionHint::GPU_LOAD_UP:
+                mPSManager->voteSet(mSessionId, AdpfVoteType::GPU_LOAD_UP,
+                                    Cycles(adpfConfig->mGpuCapacityLoadUpHeadroom),
+                                    std::chrono::steady_clock::now(), mDescriptor->targetNs);
+                break;
+            case SessionHint::GPU_LOAD_DOWN:
+                // TODO(kevindubois): add impl
+                break;
+            case SessionHint::GPU_LOAD_RESET:
+                // TODO(kevindubois): add impl
+                break;
+            default:
+                ALOGE("Error: hint is invalid");
+                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
+        }
+        mLastUpdatedTime = std::chrono::steady_clock::now();
     }
+    // Don't hold a lock (mPowerHintSession) while DoHint will try to take another
+    // lock(NodeLooperThread).
     tryToSendPowerHint(toString(hint));
-    mLastUpdatedTime = std::chrono::steady_clock::now();
     return ndk::ScopedAStatus::ok();
 }
 
@@ -533,7 +593,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::setThre
     mDescriptor->thread_ids = threadIds;
     mPSManager->setThreadsFromPowerSession(mSessionId, threadIds);
     // init boost
-    updatePidControlVariable(HintManagerT::GetInstance()->GetAdpfProfile()->mUclampMinInit);
+    updatePidControlVariable(getAdpfProfile()->mUclampMinInit);
     return ndk::ScopedAStatus::ok();
 }
 
@@ -549,6 +609,23 @@ SessionTag PowerHintSession<HintManagerT, PowerSessionManagerT>::getSessionTag()
     return mTag;
 }
 
+template <class HintManagerT, class PowerSessionManagerT>
+const std::shared_ptr<AdpfConfig>
+PowerHintSession<HintManagerT, PowerSessionManagerT>::getAdpfProfile() const {
+    if (!mAdpfProfile) {
+        return HintManager::GetInstance()->GetAdpfProfile(toString(mTag));
+    }
+    return mAdpfProfile;
+}
+
+template <class HintManagerT, class PowerSessionManagerT>
+void PowerHintSession<HintManagerT, PowerSessionManagerT>::setAdpfProfile(
+        const std::shared_ptr<AdpfConfig> profile) {
+    // Must prevent profile from being changed in a binder call duration.
+    std::scoped_lock lock{mPowerHintSessionLock};
+    mAdpfProfile = profile;
+}
+
 std::string AppHintDesc::toString() const {
     std::string out = StringPrintf("session %" PRId64 "\n", sessionId);
     out.append(
@@ -563,9 +640,8 @@ bool PowerHintSession<HintManagerT, PowerSessionManagerT>::isTimeout() {
     auto now = std::chrono::steady_clock::now();
     time_point<steady_clock> staleTime =
             mLastUpdatedTime +
-            nanoseconds(static_cast<int64_t>(
-                    mDescriptor->targetNs.count() *
-                    HintManagerT::GetInstance()->GetAdpfProfile()->mStaleTimeFactor));
+            nanoseconds(static_cast<int64_t>(mDescriptor->targetNs.count() *
+                                             getAdpfProfile()->mStaleTimeFactor));
     return now >= staleTime;
 }
 
diff --git a/power-libperfmgr/aidl/PowerHintSession.h b/power-libperfmgr/aidl/PowerHintSession.h
index 54127dbf..da73c132 100644
--- a/power-libperfmgr/aidl/PowerHintSession.h
+++ b/power-libperfmgr/aidl/PowerHintSession.h
@@ -40,6 +40,7 @@ using aidl::android::hardware::power::BnPowerHintSession;
 using ::android::Message;
 using ::android::MessageHandler;
 using ::android::sp;
+using ::android::perfmgr::AdpfConfig;
 using std::chrono::milliseconds;
 using std::chrono::nanoseconds;
 using std::chrono::steady_clock;
@@ -69,6 +70,7 @@ class PowerHintSession : public BnPowerHintSession, public Immobile {
 
     void dumpToStream(std::ostream &stream);
     SessionTag getSessionTag() const;
+    void setAdpfProfile(const std::shared_ptr<AdpfConfig> profile);
 
   private:
     // In practice this lock should almost never get contested, but it's necessary for FMQ
@@ -76,12 +78,16 @@ class PowerHintSession : public BnPowerHintSession, public Immobile {
     bool isTimeout() REQUIRES(mPowerHintSessionLock);
     // Is hint session for a user application
     bool isAppSession() REQUIRES(mPowerHintSessionLock);
-    void tryToSendPowerHint(std::string hint) REQUIRES(mPowerHintSessionLock);
+    void tryToSendPowerHint(std::string hint);
     void updatePidControlVariable(int pidControlVariable, bool updateVote = true)
             REQUIRES(mPowerHintSessionLock);
     int64_t convertWorkDurationToBoostByPid(const std::vector<WorkDuration> &actualDurations)
             REQUIRES(mPowerHintSessionLock);
-    bool updateHeuristicBoost() REQUIRES(mPowerHintSessionLock);
+    SessionJankyLevel updateSessionJankState(SessionJankyLevel oldState, int32_t numOfJankFrames,
+                                             double durationVariance, bool isLowFPS)
+            REQUIRES(mPowerHintSessionLock);
+    void updateHeuristicBoost() REQUIRES(mPowerHintSessionLock);
+    const std::shared_ptr<AdpfConfig> getAdpfProfile() const;
 
     // Data
     PowerSessionManagerT *mPSManager;
@@ -94,14 +100,17 @@ class PowerHintSession : public BnPowerHintSession, public Immobile {
     time_point<steady_clock> mLastUpdatedTime GUARDED_BY(mPowerHintSessionLock);
     bool mSessionClosed GUARDED_BY(mPowerHintSessionLock) = false;
     // Are cpu load change related hints are supported
-    std::unordered_map<std::string, std::optional<bool>> mSupportedHints
-            GUARDED_BY(mPowerHintSessionLock);
+    std::unordered_map<std::string, std::optional<bool>> mSupportedHints;
     // Use the value of the last enum in enum_range +1 as array size
     std::array<bool, enum_size<SessionMode>()> mModes GUARDED_BY(mPowerHintSessionLock){};
     // Tag labeling what kind of session this is
     const SessionTag mTag;
+    std::shared_ptr<AdpfConfig> mAdpfProfile;
+    std::function<void(const std::shared_ptr<AdpfConfig>)> mOnAdpfUpdate;
     std::unique_ptr<SessionRecords> mSessionRecords GUARDED_BY(mPowerHintSessionLock) = nullptr;
     bool mHeuristicBoostActive GUARDED_BY(mPowerHintSessionLock){false};
+    SessionJankyLevel mJankyLevel GUARDED_BY(mPowerHintSessionLock){SessionJankyLevel::LIGHT};
+    uint32_t mJankyFrameNum GUARDED_BY(mPowerHintSessionLock){0};
 };
 
 }  // namespace pixel
diff --git a/power-libperfmgr/aidl/PowerSessionManager.cpp b/power-libperfmgr/aidl/PowerSessionManager.cpp
index f386db55..2ee4565f 100644
--- a/power-libperfmgr/aidl/PowerSessionManager.cpp
+++ b/power-libperfmgr/aidl/PowerSessionManager.cpp
@@ -20,7 +20,6 @@
 #include "PowerSessionManager.h"
 
 #include <android-base/file.h>
-#include <android-base/stringprintf.h>
 #include <log/log.h>
 #include <perfmgr/HintManager.h>
 #include <private/android_filesystem_config.h>
@@ -78,35 +77,15 @@ static int set_uclamp(int tid, UclampRange range) {
 }
 }  // namespace
 
+// TODO(jimmyshiu@): Deprecated. Remove once all powerhint.json up-to-date.
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::updateHintMode(const std::string &mode, bool enabled) {
-    if (enabled && mode.compare(0, 8, "REFRESH_") == 0) {
-        if (mode.compare("REFRESH_120FPS") == 0) {
-            mDisplayRefreshRate = 120;
-        } else if (mode.compare("REFRESH_90FPS") == 0) {
-            mDisplayRefreshRate = 90;
-        } else if (mode.compare("REFRESH_60FPS") == 0) {
-            mDisplayRefreshRate = 60;
-        }
-    }
-    if (HintManager::GetInstance()->GetAdpfProfile()) {
-        HintManager::GetInstance()->SetAdpfProfile(mode);
+    ALOGD("%s %s:%b", __func__, mode.c_str(), enabled);
+    if (enabled && HintManager::GetInstance()->GetAdpfProfileFromDoHint()) {
+        HintManager::GetInstance()->SetAdpfProfileFromDoHint(mode);
     }
 }
 
-template <class HintManagerT>
-void PowerSessionManager<HintManagerT>::updateHintBoost(const std::string &boost,
-                                                        int32_t durationMs) {
-    ATRACE_CALL();
-    ALOGV("PowerSessionManager::updateHintBoost: boost: %s, durationMs: %d", boost.c_str(),
-          durationMs);
-}
-
-template <class HintManagerT>
-int PowerSessionManager<HintManagerT>::getDisplayRefreshRate() {
-    return mDisplayRefreshRate;
-}
-
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::addPowerSession(
         const std::string &idString, const std::shared_ptr<AppHintDesc> &sessionDescriptor,
@@ -603,6 +582,30 @@ void PowerSessionManager<HintManagerT>::clear() {
     mSessionMap.clear();
 }
 
+template <class HintManagerT>
+void PowerSessionManager<HintManagerT>::updateHboostStatistics(int64_t sessionId,
+                                                               SessionJankyLevel jankyLevel,
+                                                               int32_t numOfFrames) {
+    std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
+    auto sessValPtr = mSessionTaskMap.findSession(sessionId);
+    if (nullptr == sessValPtr) {
+        return;
+    }
+    switch (jankyLevel) {
+        case SessionJankyLevel::LIGHT:
+            sessValPtr->hBoostModeDist.lightModeFrames += numOfFrames;
+            break;
+        case SessionJankyLevel::MODERATE:
+            sessValPtr->hBoostModeDist.moderateModeFrames += numOfFrames;
+            break;
+        case SessionJankyLevel::SEVERE:
+            sessValPtr->hBoostModeDist.severeModeFrames += numOfFrames;
+            break;
+        default:
+            ALOGW("Unknown janky level during updateHboostStatistics");
+    }
+}
+
 template class PowerSessionManager<>;
 template class PowerSessionManager<testing::NiceMock<mock::pixel::MockHintManager>>;
 
diff --git a/power-libperfmgr/aidl/PowerSessionManager.h b/power-libperfmgr/aidl/PowerSessionManager.h
index 4827d9aa..e71ed2e5 100644
--- a/power-libperfmgr/aidl/PowerSessionManager.h
+++ b/power-libperfmgr/aidl/PowerSessionManager.h
@@ -46,8 +46,6 @@ class PowerSessionManager : public Immobile {
 
     // Update the current hint info
     void updateHintMode(const std::string &mode, bool enabled);
-    void updateHintBoost(const std::string &boost, int32_t durationMs);
-    int getDisplayRefreshRate();
     // Add and remove power hint session
     void addPowerSession(const std::string &idString,
                          const std::shared_ptr<AppHintDesc> &sessionDescriptor,
@@ -78,6 +76,9 @@ class PowerSessionManager : public Immobile {
 
     void setPreferPowerEfficiency(int64_t sessionId, bool enabled);
 
+    void updateHboostStatistics(int64_t sessionId, SessionJankyLevel jankyLevel,
+                                int32_t numOfFrames);
+
     // Singleton
     static PowerSessionManager *getInstance() {
         static PowerSessionManager instance{};
@@ -98,8 +99,6 @@ class PowerSessionManager : public Immobile {
     void enableSystemTopAppBoost();
     const std::string kDisableBoostHintName;
 
-    int mDisplayRefreshRate;
-
     // Rewrite specific
     mutable std::mutex mSessionTaskMapMutex;
     SessionTaskMap mSessionTaskMap;
@@ -129,7 +128,6 @@ class PowerSessionManager : public Immobile {
     PowerSessionManager()
         : kDisableBoostHintName(::android::base::GetProperty(kPowerHalAdpfDisableTopAppBoost,
                                                              "ADPF_DISABLE_TA_BOOST")),
-          mDisplayRefreshRate(60),
           mPriorityQueueWorkerPool(new PriorityQueueWorkerPool(1, "adpf_handler")),
           mEventSessionTimeoutWorker([&](auto e) { handleEvent(e); }, mPriorityQueueWorkerPool),
           mGpuCapacityNode(createGpuCapacityNode()) {}
diff --git a/power-libperfmgr/aidl/SessionValueEntry.cpp b/power-libperfmgr/aidl/SessionValueEntry.cpp
index f250d938..cff5bf67 100644
--- a/power-libperfmgr/aidl/SessionValueEntry.cpp
+++ b/power-libperfmgr/aidl/SessionValueEntry.cpp
@@ -37,6 +37,16 @@ std::ostream &SessionValueEntry::dump(std::ostream &os) const {
         os << ", votes nullptr";
     }
     os << ", " << isActive;
+    auto totalFrames = hBoostModeDist.lightModeFrames + hBoostModeDist.moderateModeFrames +
+                       hBoostModeDist.severeModeFrames;
+    os << ", HBoost:"
+       << (totalFrames <= 0 ? 0 : (hBoostModeDist.lightModeFrames * 10000 / totalFrames / 100.0))
+       << "%-"
+       << (totalFrames <= 0 ? 0 : (hBoostModeDist.moderateModeFrames * 10000 / totalFrames / 100.0))
+       << "%-"
+       << (totalFrames <= 0 ? 0 : (hBoostModeDist.severeModeFrames * 10000 / totalFrames / 100.0))
+       << "%-" << totalFrames << ", ";
+
     return os;
 }
 
diff --git a/power-libperfmgr/aidl/SessionValueEntry.h b/power-libperfmgr/aidl/SessionValueEntry.h
index e3cd046a..3ccade81 100644
--- a/power-libperfmgr/aidl/SessionValueEntry.h
+++ b/power-libperfmgr/aidl/SessionValueEntry.h
@@ -28,6 +28,13 @@ namespace power {
 namespace impl {
 namespace pixel {
 
+// Record the heuristic boost mode distribution among the frames
+struct HeurBoostStatistics {
+    int64_t lightModeFrames{0};
+    int64_t moderateModeFrames{0};
+    int64_t severeModeFrames{0};
+};
+
 // Per-power-session values (equivalent to original PowerHintSession)
 // Responsible for maintaining the state of the power session via attributes
 // Primarily this means actual uclamp value and whether session is active
@@ -44,6 +51,7 @@ struct SessionValueEntry {
     std::shared_ptr<Votes> votes;
     std::shared_ptr<AppDescriptorTrace> sessionTrace;
     bool isPowerEfficient{false};
+    HeurBoostStatistics hBoostModeDist;
 
     // Write info about power session to ostream for logging and debugging
     std::ostream &dump(std::ostream &os) const;
diff --git a/power-libperfmgr/aidl/service.cpp b/power-libperfmgr/aidl/service.cpp
index caf7b7dd..f1e94c06 100644
--- a/power-libperfmgr/aidl/service.cpp
+++ b/power-libperfmgr/aidl/service.cpp
@@ -39,6 +39,7 @@ constexpr std::string_view kPowerHalInitProp("vendor.powerhal.init");
 
 int main() {
     android::base::SetDefaultTag(LOG_TAG);
+    android::base::SetMinimumLogSeverity(android::base::INFO);
     // Parse config but do not start the looper
     HintManager *hm = HintManager::GetInstance();
     if (!hm) {
diff --git a/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp b/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp
index a161bc7d..8e32ad98 100644
--- a/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp
+++ b/power-libperfmgr/aidl/tests/PowerHintSessionTest.cpp
@@ -325,6 +325,44 @@ TEST_F(PowerHintSessionTest, checkPauseResumeTag) {
     sess2->close();
 }
 
+TEST_F(PowerHintSessionMockedTest, updateSessionJankState) {
+    // Low FPS
+    ASSERT_EQ(SessionJankyLevel::LIGHT,
+              mHintSession->updateSessionJankState(SessionJankyLevel::SEVERE, 8, 5.0, true));
+    ASSERT_EQ(SessionJankyLevel::LIGHT,
+              mHintSession->updateSessionJankState(SessionJankyLevel::MODERATE, 8, 5.0, true));
+    ASSERT_EQ(SessionJankyLevel::LIGHT,
+              mHintSession->updateSessionJankState(SessionJankyLevel::LIGHT, 8, 5.0, true));
+    // Light number of jank frames, and high workload duration variance.
+    ASSERT_EQ(SessionJankyLevel::MODERATE,
+              mHintSession->updateSessionJankState(SessionJankyLevel::SEVERE, 1, 5.0, false));
+    ASSERT_EQ(SessionJankyLevel::MODERATE,
+              mHintSession->updateSessionJankState(SessionJankyLevel::MODERATE, 1, 5.0, false));
+    ASSERT_EQ(SessionJankyLevel::LIGHT,
+              mHintSession->updateSessionJankState(SessionJankyLevel::LIGHT, 1, 5.0, false));
+    // Light number of jank frames, and low workload duration variance.
+    ASSERT_EQ(SessionJankyLevel::LIGHT,
+              mHintSession->updateSessionJankState(SessionJankyLevel::SEVERE, 1, 1.0, false));
+    ASSERT_EQ(SessionJankyLevel::LIGHT,
+              mHintSession->updateSessionJankState(SessionJankyLevel::MODERATE, 1, 1.0, false));
+    ASSERT_EQ(SessionJankyLevel::LIGHT,
+              mHintSession->updateSessionJankState(SessionJankyLevel::LIGHT, 1, 1.0, false));
+    // Moderate number of jank frames
+    ASSERT_EQ(SessionJankyLevel::MODERATE,
+              mHintSession->updateSessionJankState(SessionJankyLevel::SEVERE, 4, 5.0, false));
+    ASSERT_EQ(SessionJankyLevel::MODERATE,
+              mHintSession->updateSessionJankState(SessionJankyLevel::MODERATE, 4, 5.0, false));
+    ASSERT_EQ(SessionJankyLevel::MODERATE,
+              mHintSession->updateSessionJankState(SessionJankyLevel::LIGHT, 4, 5.0, false));
+    // Significant number of jank frames
+    ASSERT_EQ(SessionJankyLevel::SEVERE,
+              mHintSession->updateSessionJankState(SessionJankyLevel::SEVERE, 9, 5.0, false));
+    ASSERT_EQ(SessionJankyLevel::SEVERE,
+              mHintSession->updateSessionJankState(SessionJankyLevel::MODERATE, 9, 5.0, false));
+    ASSERT_EQ(SessionJankyLevel::SEVERE,
+              mHintSession->updateSessionJankState(SessionJankyLevel::LIGHT, 9, 5.0, false));
+}
+
 }  // namespace pixel
 }  // namespace impl
 }  // namespace power
diff --git a/power-libperfmgr/aidl/tests/TestHelper.cpp b/power-libperfmgr/aidl/tests/TestHelper.cpp
index b7c72957..b07b94db 100644
--- a/power-libperfmgr/aidl/tests/TestHelper.cpp
+++ b/power-libperfmgr/aidl/tests/TestHelper.cpp
@@ -19,41 +19,43 @@
 namespace aidl::google::hardware::power::impl::pixel {
 
 ::android::perfmgr::AdpfConfig makeMockConfig() {
-    return ::android::perfmgr::AdpfConfig("REFRESH_60FPS", /* Name */
-                                          true,            /* PID_On */
-                                          2.0,             /* PID_Po */
-                                          1.0,             /* PID_Pu */
-                                          0.0,             /* PID_I */
-                                          200,             /* PID_I_Init */
-                                          512,             /* PID_I_High */
-                                          -30,             /* PID_I_Low */
-                                          500.0,           /* PID_Do */
-                                          0.0,             /* PID_Du */
-                                          true,            /* UclampMin_On */
-                                          162,             /* UclampMin_Init */
-                                          480,             /* UclampMin_High */
-                                          2,               /* UclampMin_Low */
-                                          1,               /* SamplingWindow_P */
-                                          0,               /* SamplingWindow_I */
-                                          1,               /* SamplingWindow_D */
-                                          166666660,       /* ReportingRateLimitNs */
-                                          1.0,             /* TargetTimeFactor */
-                                          15.0,            /* StaleTimeFactor */
-                                          true,            /* GpuBoost */
-                                          25000,           /* GpuCapacityBoostMax */
-                                          0,               /* GpuCapacityLoadUpHeadroom */
-                                          true,            /* HeuristicBoost_On */
-                                          8,               /* HBoostOnMissedCycles */
-                                          4.0,             /* HBoostOffMaxAvgRatio */
-                                          5,               /* HBoostOffMissedCycles */
-                                          0.5,             /* HBoostPidPuFactor */
-                                          722,             /* HBoostUclampMin */
-                                          1.2,             /* JankCheckTimeFactor */
-                                          25,              /* LowFrameRateThreshold */
-                                          300,             /* MaxRecordsNum */
-                                          480,             /* UclampMin_LoadUp */
-                                          480,             /* UclampMin_LoadReset */
-                                          500,             /* UclampMax_EfficientBase */
-                                          200);            /* UclampMax_EfficientOffset */
+    return ::android::perfmgr::AdpfConfig(
+            "REFRESH_60FPS",          /* Name */
+            true,                     /* PID_On */
+            2.0,                      /* PID_Po */
+            1.0,                      /* PID_Pu */
+            0.0,                      /* PID_I */
+            200,                      /* PID_I_Init */
+            512,                      /* PID_I_High */
+            -30,                      /* PID_I_Low */
+            500.0,                    /* PID_Do */
+            0.0,                      /* PID_Du */
+            true,                     /* UclampMin_On */
+            162,                      /* UclampMin_Init */
+            480,                      /* UclampMin_High */
+            2,                        /* UclampMin_Low */
+            1,                        /* SamplingWindow_P */
+            0,                        /* SamplingWindow_I */
+            1,                        /* SamplingWindow_D */
+            166666660,                /* ReportingRateLimitNs */
+            1.0,                      /* TargetTimeFactor */
+            15.0,                     /* StaleTimeFactor */
+            true,                     /* GpuBoost */
+            25000,                    /* GpuCapacityBoostMax */
+            0,                        /* GpuCapacityLoadUpHeadroom */
+            true,                     /* HeuristicBoost_On */
+            2,                        /* HBoostModerateJankThreshold */
+            4.0,                      /* HBoostOffMaxAvgDurRatio */
+            0.5,                      /* HBoostSevereJankPidPu */
+            8,                        /* HBoostSevereJankThreshold */
+            std::make_pair(480, 800), /* HBoostUclampMinCeilingRange */
+            std::make_pair(200, 400), /* HBoostUclampMinFloorRange */
+            1.2,                      /* JankCheckTimeFactor */
+            25,                       /* LowFrameRateThreshold */
+            300,                      /* MaxRecordsNum */
+            480,                      /* UclampMin_LoadUp */
+            480,                      /* UclampMin_LoadReset */
+            500,                      /* UclampMax_EfficientBase */
+            200);                     /* UclampMax_EfficientOffset */
 }
 }  // namespace aidl::google::hardware::power::impl::pixel
diff --git a/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h b/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
index cf0183e2..30926118 100644
--- a/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
+++ b/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
@@ -68,6 +68,9 @@ class MockPowerSessionManager {
     MOCK_METHOD(void, unregisterSession, (int64_t sessionId), ());
     MOCK_METHOD(void, clear, (), ());
     MOCK_METHOD(std::shared_ptr<void>, getSession, (int64_t sessionId), ());
+    MOCK_METHOD(void, updateHboostStatistics,
+                (int64_t sessionId, impl::pixel::SessionJankyLevel jankyLevel, int32_t numOfFrames),
+                ());
 
     static testing::NiceMock<MockPowerSessionManager> *getInstance() {
         static testing::NiceMock<MockPowerSessionManager> instance{};
diff --git a/power-libperfmgr/disp-power/DisplayLowPower.cpp b/power-libperfmgr/disp-power/DisplayLowPower.cpp
index f2da5746..81744be0 100644
--- a/power-libperfmgr/disp-power/DisplayLowPower.cpp
+++ b/power-libperfmgr/disp-power/DisplayLowPower.cpp
@@ -31,7 +31,7 @@ namespace power {
 namespace impl {
 namespace pixel {
 
-DisplayLowPower::DisplayLowPower() : mFossStatus(false) {}
+DisplayLowPower::DisplayLowPower() : mFossStatus(false), mAAModeOn(false) {}
 
 void DisplayLowPower::Init() {
     ConnectPpsDaemon();
@@ -79,6 +79,13 @@ void DisplayLowPower::SetFoss(bool enable) {
     }
 }
 
+void DisplayLowPower::SetAAMode(bool enable) {
+    mAAModeOn = enable;
+}
+bool DisplayLowPower::IsAAModeOn() {
+  return mAAModeOn;
+}
+
 }  // namespace pixel
 }  // namespace impl
 }  // namespace power
diff --git a/power-libperfmgr/disp-power/DisplayLowPower.h b/power-libperfmgr/disp-power/DisplayLowPower.h
index 53eb6c99..64a7dcfe 100644
--- a/power-libperfmgr/disp-power/DisplayLowPower.h
+++ b/power-libperfmgr/disp-power/DisplayLowPower.h
@@ -33,6 +33,8 @@ class DisplayLowPower {
     ~DisplayLowPower() {}
     void Init();
     void SetDisplayLowPower(bool enable);
+    void SetAAMode(bool enable);
+    bool IsAAModeOn();
 
   private:
     void ConnectPpsDaemon();
@@ -41,6 +43,7 @@ class DisplayLowPower {
 
     ::android::base::unique_fd mPpsSocket;
     bool mFossStatus;
+    std::atomic<bool> mAAModeOn;
 };
 
 }  // namespace pixel
diff --git a/power-libperfmgr/libperfmgr/AdpfConfig.cc b/power-libperfmgr/libperfmgr/AdpfConfig.cc
index 946673df..b04100fa 100644
--- a/power-libperfmgr/libperfmgr/AdpfConfig.cc
+++ b/power-libperfmgr/libperfmgr/AdpfConfig.cc
@@ -66,11 +66,14 @@ void AdpfConfig::dumpToFd(int fd) {
     dump_buf << "mGpuCapacityLoadUpHeadroom: " << mGpuCapacityLoadUpHeadroom << "\n";
     if (mHeuristicBoostOn.has_value()) {
         dump_buf << "HeuristicBoost_On: " << mHeuristicBoostOn.value() << "\n";
-        dump_buf << "HBoostOnMissedCycles: " << mHBoostOnMissedCycles.value() << "\n";
-        dump_buf << "HBoostOffMaxAvgRatio: " << mHBoostOffMaxAvgRatio.value() << "\n";
-        dump_buf << "HBoostOffMissedCycles: " << mHBoostOffMissedCycles.value() << "\n";
-        dump_buf << "HBoostPidPuFactor: " << mHBoostPidPuFactor.value() << "\n";
-        dump_buf << "HBoostUclampMin: " << mHBoostUclampMin.value() << "\n";
+        dump_buf << "HBoostModerateJankThreshold: " << mHBoostModerateJankThreshold.value() << "\n";
+        dump_buf << "HBoostOffMaxAvgDurRatio: " << mHBoostOffMaxAvgDurRatio.value() << "\n";
+        dump_buf << "HBoostSevereJankPidPu: " << mHBoostSevereJankPidPu.value() << "\n";
+        dump_buf << "HBoostSevereJankThreshold: " << mHBoostSevereJankThreshold.value() << "\n";
+        dump_buf << "HBoostUclampMinCeilingRange: [" << mHBoostUclampMinCeilingRange.value().first;
+        dump_buf << ", " << mHBoostUclampMinCeilingRange.value().second << "]\n";
+        dump_buf << "HBoostUclampMinFloorRange: [" << mHBoostUclampMinFloorRange.value().first;
+        dump_buf << ", " << mHBoostUclampMinFloorRange.value().second << "]\n";
         dump_buf << "JankCheckTimeFactor: " << mJankCheckTimeFactor.value() << "\n";
         dump_buf << "LowFrameRateThreshold: " << mLowFrameRateThreshold.value() << "\n";
         dump_buf << "MaxRecordsNum: " << mMaxRecordsNum.value() << "\n";
diff --git a/power-libperfmgr/libperfmgr/Android.bp b/power-libperfmgr/libperfmgr/Android.bp
index 96c10640..fe6b6951 100644
--- a/power-libperfmgr/libperfmgr/Android.bp
+++ b/power-libperfmgr/libperfmgr/Android.bp
@@ -59,6 +59,7 @@ cc_library {
         "NodeLooperThread.cc",
         "HintManager.cc",
         "AdpfConfig.cc",
+        "EventNode.cc",
     ]
 }
 
@@ -72,6 +73,7 @@ cc_test {
         "tests/PropertyNodeTest.cc",
         "tests/NodeLooperThreadTest.cc",
         "tests/HintManagerTest.cc",
+        "tests/EventNodeTest.cc",
     ],
     test_suites: ["device-tests"],
     require_root: true,
diff --git a/power-libperfmgr/libperfmgr/EventNode.cc b/power-libperfmgr/libperfmgr/EventNode.cc
new file mode 100644
index 00000000..2a2d2e39
--- /dev/null
+++ b/power-libperfmgr/libperfmgr/EventNode.cc
@@ -0,0 +1,90 @@
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
+#define ATRACE_TAG (ATRACE_TAG_POWER | ATRACE_TAG_HAL)
+#define LOG_TAG "libperfmgr"
+
+#include "perfmgr/EventNode.h"
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/properties.h>
+#include <android-base/stringprintf.h>
+#include <android-base/strings.h>
+#include <utils/Trace.h>
+
+namespace android {
+namespace perfmgr {
+
+EventNode::EventNode(
+        std::string name, std::string node_path, std::vector<RequestGroup> req_sorted,
+        std::size_t default_val_index, bool reset_on_init,
+        std::function<void(const std::string &, const std::string &, const std::string &)>
+                update_callback)
+    : Node(std::move(name), std::move(node_path), std::move(req_sorted), default_val_index,
+           reset_on_init),
+      update_callback_(update_callback) {}
+
+std::chrono::milliseconds EventNode::Update(bool) {
+    std::size_t value_index = default_val_index_;
+    std::chrono::milliseconds expire_time = std::chrono::milliseconds::max();
+
+    // Find the highest outstanding request's expire time
+    for (std::size_t i = 0; i < req_sorted_.size(); i++) {
+        if (req_sorted_[i].GetExpireTime(&expire_time)) {
+            value_index = i;
+            break;
+        }
+    }
+
+    // Update node only if request index changes
+    if (value_index != current_val_index_ || reset_on_init_) {
+        const std::string &req_value = req_sorted_[value_index].GetRequestValue();
+        if (ATRACE_ENABLED()) {
+            ATRACE_INT(("N:" + GetName()).c_str(), value_index);
+            const std::string tag =
+                    GetName() + ":" + req_value + ":" + std::to_string(expire_time.count());
+            ATRACE_BEGIN(tag.c_str());
+        }
+        update_callback_(name_, node_path_, req_value);
+        current_val_index_ = value_index;
+        reset_on_init_ = false;
+        if (ATRACE_ENABLED()) {
+            ATRACE_END();
+        }
+    }
+    return expire_time;
+}
+
+void EventNode::DumpToFd(int fd) const {
+    const std::string &node_value = req_sorted_[current_val_index_].GetRequestValue();
+    std::string buf(android::base::StringPrintf(
+            "Node Name\t"
+            "Event Path\t"
+            "Current Index\t"
+            "Current Value\n"
+            "%s\t%s\t%zu\t%s\n",
+            name_.c_str(), node_path_.c_str(), current_val_index_, node_value.c_str()));
+    if (!android::base::WriteStringToFd(buf, fd)) {
+        LOG(ERROR) << "Failed to dump fd: " << fd;
+    }
+    for (std::size_t i = 0; i < req_sorted_.size(); i++) {
+        req_sorted_[i].DumpToFd(fd, android::base::StringPrintf("\t\tReq%zu:\t", i));
+    }
+}
+
+}  // namespace perfmgr
+}  // namespace android
diff --git a/power-libperfmgr/libperfmgr/FileNode.cc b/power-libperfmgr/libperfmgr/FileNode.cc
index 05f0746d..8ccacbcf 100644
--- a/power-libperfmgr/libperfmgr/FileNode.cc
+++ b/power-libperfmgr/libperfmgr/FileNode.cc
@@ -31,7 +31,8 @@ namespace android {
 namespace perfmgr {
 
 FileNode::FileNode(std::string name, std::string node_path, std::vector<RequestGroup> req_sorted,
-                   std::size_t default_val_index, bool reset_on_init, bool truncate, bool hold_fd, bool write_only)
+                   std::size_t default_val_index, bool reset_on_init, bool truncate, bool hold_fd,
+                   bool write_only)
     : Node(std::move(name), std::move(node_path), std::move(req_sorted), default_val_index,
            reset_on_init),
       hold_fd_(hold_fd),
@@ -56,7 +57,9 @@ std::chrono::milliseconds FileNode::Update(bool log_error) {
         const std::string& req_value =
             req_sorted_[value_index].GetRequestValue();
         if (ATRACE_ENABLED()) {
-            const std::string tag = GetName() + ":" + req_value;
+            ATRACE_INT(("N:" + GetName()).c_str(), value_index);
+            const std::string tag =
+                    GetName() + ":" + req_value + ":" + std::to_string(expire_time.count());
             ATRACE_BEGIN(tag.c_str());
         }
         android::base::Timer t;
diff --git a/power-libperfmgr/libperfmgr/HintManager.cc b/power-libperfmgr/libperfmgr/HintManager.cc
index 961fd4a3..bc12cd94 100644
--- a/power-libperfmgr/libperfmgr/HintManager.cc
+++ b/power-libperfmgr/libperfmgr/HintManager.cc
@@ -30,7 +30,9 @@
 
 #include <algorithm>
 #include <set>
+#include <string>
 
+#include "perfmgr/EventNode.h"
 #include "perfmgr/FileNode.h"
 #include "perfmgr/PropertyNode.h"
 
@@ -43,10 +45,14 @@ constexpr std::chrono::steady_clock::time_point kTimePointMax =
         std::chrono::steady_clock::time_point::max();
 }  // namespace
 
+using ::android::base::GetProperty;
+using ::android::base::StringPrintf;
+
 constexpr char kPowerHalTruncateProp[] = "vendor.powerhal.truncate";
 constexpr std::string_view kConfigDebugPathProperty("vendor.powerhal.config.debug");
 constexpr std::string_view kConfigProperty("vendor.powerhal.config");
 constexpr std::string_view kConfigDefaultFileName("powerhint.json");
+constexpr char kAdpfEventNodePath[] = "<AdpfConfig>:";
 
 bool HintManager::ValidateHint(const std::string& hint_type) const {
     if (nm_.get() == nullptr) {
@@ -95,8 +101,9 @@ void HintManager::DoHintStatus(const std::string &hint_type, std::chrono::millis
     std::lock_guard<std::mutex> lock(actions_.at(hint_type).hint_lock);
     actions_.at(hint_type).status->stats.count.fetch_add(1);
     auto now = std::chrono::steady_clock::now();
-    ATRACE_INT(hint_type.c_str(), (timeout_ms == kMilliSecondZero) ? std::numeric_limits<int>::max()
-                                                                   : timeout_ms.count());
+    ATRACE_INT(("H:" + hint_type).c_str(), (timeout_ms == kMilliSecondZero)
+                                                   ? std::numeric_limits<int>::max()
+                                                   : timeout_ms.count());
     if (now > actions_.at(hint_type).status->end_time) {
         actions_.at(hint_type).status->stats.duration_ms.fetch_add(
                 std::chrono::duration_cast<std::chrono::milliseconds>(
@@ -113,7 +120,7 @@ void HintManager::EndHintStatus(const std::string &hint_type) {
     std::lock_guard<std::mutex> lock(actions_.at(hint_type).hint_lock);
     // Update HintStats if the hint ends earlier than expected end_time
     auto now = std::chrono::steady_clock::now();
-    ATRACE_INT(hint_type.c_str(), 0);
+    ATRACE_INT(("H:" + hint_type).c_str(), 0);
     if (now < actions_.at(hint_type).status->end_time) {
         actions_.at(hint_type).status->stats.duration_ms.fetch_add(
                 std::chrono::duration_cast<std::chrono::milliseconds>(
@@ -250,9 +257,8 @@ void HintManager::DumpToFd(int fd) {
     std::sort(keys.begin(), keys.end());
     for (const auto &ordered_key : keys) {
         HintStats hint_stats(GetHintStats(ordered_key));
-        hint_stats_string +=
-                android::base::StringPrintf("%s\t%" PRIu32 "\t%" PRIu64 "\n", ordered_key.c_str(),
-                                            hint_stats.count, hint_stats.duration_ms);
+        hint_stats_string += StringPrintf("%s\t%" PRIu32 "\t%" PRIu64 "\n", ordered_key.c_str(),
+                                          hint_stats.count, hint_stats.duration_ms);
     }
     if (!android::base::WriteStringToFd(hint_stats_string, fd)) {
         LOG(ERROR) << "Failed to dump fd: " << fd;
@@ -263,16 +269,22 @@ void HintManager::DumpToFd(int fd) {
     }
 
     // Dump current ADPF profile
-    if (GetAdpfProfile()) {
-        header = "========== Begin current adpf profile ==========\n";
+    if (IsAdpfSupported()) {
+        header = "========== ADPF Tag Profile begin ==========\n";
         if (!android::base::WriteStringToFd(header, fd)) {
             LOG(ERROR) << "Failed to dump fd: " << fd;
         }
-        GetAdpfProfile()->dumpToFd(fd);
-        footer = "==========  End current adpf profile  ==========\n";
+        // TODO(jimmyshiu@/guibing@): Update it when fully switched to the tag based adpf profiles.
+        GetAdpfProfileFromDoHint()->dumpToFd(fd);
+        footer = "========== ADPF Tag Profile end ==========\n";
         if (!android::base::WriteStringToFd(footer, fd)) {
             LOG(ERROR) << "Failed to dump fd: " << fd;
         }
+    } else {
+        header = "========== IsAdpfSupported: No ===========\n";
+        if (!android::base::WriteStringToFd(header, fd)) {
+            LOG(ERROR) << "Failed to dump fd: " << fd;
+        }
     }
     fsync(fd);
 }
@@ -289,8 +301,7 @@ void HintManager::Reload(bool start) {
         config_path = "/data/vendor/etc/";
         LOG(WARNING) << "Pixel Power HAL AIDL Service is using debug config from: " << config_path;
     }
-    config_path.append(
-            android::base::GetProperty(kConfigProperty.data(), kConfigDefaultFileName.data()));
+    config_path.append(GetProperty(kConfigProperty.data(), kConfigDefaultFileName.data()));
 
     LOG(INFO) << "Pixel Power HAL AIDL Service with Extension is starting with config: "
               << config_path;
@@ -344,6 +355,32 @@ HintManager *HintManager::GetFromJSON(const std::string &config_path, bool start
 
     std::unordered_map<std::string, Hint> actions = HintManager::ParseActions(json_doc, nodes);
 
+    // Parse ADPF Event Node
+    std::unordered_map<std::string, std::shared_ptr<AdpfConfig>> tag_adpfs;
+    LOG(VERBOSE) << "Parse ADPF Hint Event Table from all nodes.";
+    for (std::size_t i = 0; i < nodes.size(); ++i) {
+        const std::string &node_name = nodes[i]->GetName();
+        const std::string &node_path = nodes[i]->GetPath();
+        if (node_path.starts_with(kAdpfEventNodePath)) {
+            std::string tag = node_path.substr(strlen(kAdpfEventNodePath));
+            std::size_t index = nodes[i]->GetDefaultIndex();
+            std::string profile_name = nodes[i]->GetValues()[index];
+            for (std::size_t j = 0; j < adpfs.size(); ++j) {
+                if (adpfs[j]->mName == profile_name) {
+                    tag_adpfs[tag] = adpfs[j];
+                    LOG(INFO) << "[" << tag << ":" << node_name << "] set to '" << profile_name
+                              << "'";
+                    break;
+                }
+            }
+            if (!tag_adpfs[tag]) {
+                tag_adpfs[tag] = adpfs[0];
+                LOG(INFO) << "[" << tag << ":" << node_name << "] fallback to '" << adpfs[0]->mName
+                          << "'";
+            }
+        }
+    }
+
     if (actions.empty()) {
         LOG(ERROR) << "Failed to parse Actions section from " << config_path;
         return nullptr;
@@ -352,7 +389,8 @@ HintManager *HintManager::GetFromJSON(const std::string &config_path, bool start
     auto const gpu_sysfs_node = ParseGpuSysfsNode(json_doc);
 
     sp<NodeLooperThread> nm = new NodeLooperThread(std::move(nodes));
-    sInstance = std::make_unique<HintManager>(std::move(nm), actions, adpfs, gpu_sysfs_node);
+    sInstance =
+            std::make_unique<HintManager>(std::move(nm), actions, adpfs, tag_adpfs, gpu_sysfs_node);
 
     if (!HintManager::InitHintStatus(sInstance)) {
         LOG(ERROR) << "Failed to initialize hint status";
@@ -368,8 +406,7 @@ HintManager *HintManager::GetFromJSON(const std::string &config_path, bool start
     return HintManager::GetInstance();
 }
 
-std::vector<std::unique_ptr<Node>> HintManager::ParseNodes(
-    const std::string& json_doc) {
+std::vector<std::unique_ptr<Node>> HintManager::ParseNodes(const std::string &json_doc) {
     // function starts
     std::vector<std::unique_ptr<Node>> nodes_parsed;
     std::set<std::string> nodes_name_parsed;
@@ -418,12 +455,16 @@ std::vector<std::unique_ptr<Node>> HintManager::ParseNodes(
             return nodes_parsed;
         }
 
-        bool is_file = true;
+        bool is_event_node = false;
+        bool is_file = false;
         std::string node_type = nodes[i]["Type"].asString();
         LOG(VERBOSE) << "Node[" << i << "]'s Type: " << node_type;
         if (node_type.empty()) {
+            is_file = true;
             LOG(VERBOSE) << "Failed to read "
                          << "Node[" << i << "]'s Type, set to 'File' as default";
+        } else if (node_type == "Event") {
+            is_event_node = true;
         } else if (node_type == "File") {
             is_file = true;
         } else if (node_type == "Property") {
@@ -492,7 +533,15 @@ std::vector<std::unique_ptr<Node>> HintManager::ParseNodes(
         LOG(VERBOSE) << "Node[" << i << "]'s ResetOnInit: " << std::boolalpha
                      << reset << std::noboolalpha;
 
-        if (is_file) {
+        if (is_event_node) {
+            auto update_callback = [](const std::string &name, const std::string &path,
+                                      const std::string &val) {
+                HintManager::GetInstance()->OnNodeUpdate(name, path, val);
+            };
+            nodes_parsed.emplace_back(std::make_unique<EventNode>(
+                    name, path, values_parsed, static_cast<std::size_t>(default_index), reset,
+                    update_callback));
+        } else if (is_file) {
             bool truncate = android::base::GetBoolProperty(kPowerHalTruncateProp, true);
             if (nodes[i]["Truncate"].empty() || !nodes[i]["Truncate"].isBool()) {
                 LOG(INFO) << "Failed to read Node[" << i << "]'s Truncate, set to 'true'";
@@ -527,8 +576,7 @@ std::vector<std::unique_ptr<Node>> HintManager::ParseNodes(
                     truncate, hold_fd, write_only));
         } else {
             nodes_parsed.emplace_back(std::make_unique<PropertyNode>(
-                name, path, values_parsed,
-                static_cast<std::size_t>(default_index), reset));
+                    name, path, values_parsed, static_cast<std::size_t>(default_index), reset));
         }
     }
     LOG(INFO) << nodes_parsed.size() << " Nodes parsed successfully";
@@ -734,11 +782,12 @@ std::vector<std::shared_ptr<AdpfConfig>> HintManager::ParseAdpfConfigs(
 
         // heuristic boost configs
         std::optional<bool> heuristicBoostOn;
-        std::optional<uint32_t> hBoostOnMissedCycles;
-        std::optional<double> hBoostOffMaxAvgRatio;
-        std::optional<uint32_t> hBoostOffMissedCycles;
-        std::optional<double> hBoostPidPuFactor;
-        std::optional<uint32_t> hBoostUclampMin;
+        std::optional<uint32_t> hBoostModerateJankThreshold;
+        std::optional<double> hBoostOffMaxAvgDurRatio;
+        std::optional<double> hBoostSevereJankPidPu;
+        std::optional<uint32_t> hBoostSevereJankThreshold;
+        std::optional<std::pair<uint32_t, uint32_t>> hBoostUclampMinCeilingRange;
+        std::optional<std::pair<uint32_t, uint32_t>> hBoostUclampMinFloorRange;
         std::optional<double> jankCheckTimeFactor;
         std::optional<uint32_t> lowFrameRateThreshold;
         std::optional<uint32_t> maxRecordsNum;
@@ -770,11 +819,10 @@ std::vector<std::shared_ptr<AdpfConfig>> HintManager::ParseAdpfConfigs(
         ADPF_PARSE(reportingRate, "ReportingRateLimitNs", UInt64);
         ADPF_PARSE(targetTimeFactor, "TargetTimeFactor", Double);
         ADPF_PARSE_OPTIONAL(heuristicBoostOn, "HeuristicBoost_On", Bool);
-        ADPF_PARSE_OPTIONAL(hBoostOnMissedCycles, "HBoostOnMissedCycles", UInt);
-        ADPF_PARSE_OPTIONAL(hBoostOffMaxAvgRatio, "HBoostOffMaxAvgRatio", Double);
-        ADPF_PARSE_OPTIONAL(hBoostOffMissedCycles, "HBoostOffMissedCycles", UInt);
-        ADPF_PARSE_OPTIONAL(hBoostPidPuFactor, "HBoostPidPuFactor", Double);
-        ADPF_PARSE_OPTIONAL(hBoostUclampMin, "HBoostUclampMin", UInt);
+        ADPF_PARSE_OPTIONAL(hBoostModerateJankThreshold, "HBoostModerateJankThreshold", UInt);
+        ADPF_PARSE_OPTIONAL(hBoostOffMaxAvgDurRatio, "HBoostOffMaxAvgDurRatio", Double);
+        ADPF_PARSE_OPTIONAL(hBoostSevereJankPidPu, "HBoostSevereJankPidPu", Double);
+        ADPF_PARSE_OPTIONAL(hBoostSevereJankThreshold, "HBoostSevereJankThreshold", UInt);
         ADPF_PARSE_OPTIONAL(jankCheckTimeFactor, "JankCheckTimeFactor", Double);
         ADPF_PARSE_OPTIONAL(lowFrameRateThreshold, "LowFrameRateThreshold", UInt);
         ADPF_PARSE_OPTIONAL(maxRecordsNum, "MaxRecordsNum", UInt);
@@ -793,12 +841,29 @@ std::vector<std::shared_ptr<AdpfConfig>> HintManager::ParseAdpfConfigs(
             gpuCapacityLoadUpHeadroom = adpfs[i]["GpuCapacityLoadUpHeadroom"].asUInt64();
         }
 
+        if (!adpfs[i]["HBoostUclampMinCeilingRange"].empty()) {
+            Json::Value ceilRange = adpfs[i]["HBoostUclampMinCeilingRange"];
+            if (ceilRange.size() == 2 && ceilRange[0].isUInt() && ceilRange[1].isUInt()) {
+                hBoostUclampMinCeilingRange =
+                        std::make_pair(ceilRange[0].asUInt(), ceilRange[1].asUInt());
+            }
+        }
+
+        if (!adpfs[i]["HBoostUclampMinFloorRange"].empty()) {
+            Json::Value floorRange = adpfs[i]["HBoostUclampMinFloorRange"];
+            if (floorRange.size() == 2 && floorRange[0].isUInt() && floorRange[1].isUInt()) {
+                hBoostUclampMinFloorRange =
+                        std::make_pair(floorRange[0].asUInt(), floorRange[1].asUInt());
+            }
+        }
+
         // Check all the heuristic configurations are there if heuristic boost is going to
         // be used.
         if (heuristicBoostOn.has_value()) {
-            if (!hBoostOnMissedCycles.has_value() || !hBoostOffMaxAvgRatio.has_value() ||
-                !hBoostOffMissedCycles.has_value() || !hBoostPidPuFactor.has_value() ||
-                !hBoostUclampMin.has_value() || !jankCheckTimeFactor.has_value() ||
+            if (!hBoostModerateJankThreshold.has_value() || !hBoostOffMaxAvgDurRatio.has_value() ||
+                !hBoostSevereJankPidPu.has_value() || !hBoostSevereJankThreshold.has_value() ||
+                !hBoostUclampMinCeilingRange.has_value() ||
+                !hBoostUclampMinFloorRange.has_value() || !jankCheckTimeFactor.has_value() ||
                 !lowFrameRateThreshold.has_value() || !maxRecordsNum.has_value()) {
                 LOG(ERROR) << "Part of the heuristic boost configurations are missing!";
                 adpfs_parsed.clear();
@@ -824,31 +889,78 @@ std::vector<std::shared_ptr<AdpfConfig>> HintManager::ParseAdpfConfigs(
                 pidDOver, pidDUnder, adpfUclamp, uclampMinInit, uclampMinHighLimit,
                 uclampMinLowLimit, samplingWindowP, samplingWindowI, samplingWindowD, reportingRate,
                 targetTimeFactor, staleTimeFactor, gpuBoost, gpuBoostCapacityMax,
-                gpuCapacityLoadUpHeadroom, heuristicBoostOn, hBoostOnMissedCycles,
-                hBoostOffMaxAvgRatio, hBoostOffMissedCycles, hBoostPidPuFactor, hBoostUclampMin,
-                jankCheckTimeFactor, lowFrameRateThreshold, maxRecordsNum, uclampMinLoadUp.value(),
+                gpuCapacityLoadUpHeadroom, heuristicBoostOn, hBoostModerateJankThreshold,
+                hBoostOffMaxAvgDurRatio, hBoostSevereJankPidPu, hBoostSevereJankThreshold,
+                hBoostUclampMinCeilingRange, hBoostUclampMinFloorRange, jankCheckTimeFactor,
+                lowFrameRateThreshold, maxRecordsNum, uclampMinLoadUp.value(),
                 uclampMinLoadReset.value(), uclampMaxEfficientBase, uclampMaxEfficientOffset));
     }
     LOG(INFO) << adpfs_parsed.size() << " AdpfConfigs parsed successfully";
     return adpfs_parsed;
 }
 
-std::shared_ptr<AdpfConfig> HintManager::GetAdpfProfile() const {
+// TODO(jimmyshiu@): Deprecated. Remove once all powerhint.json up-to-date.
+std::shared_ptr<AdpfConfig> HintManager::GetAdpfProfileFromDoHint() const {
     if (adpfs_.empty())
         return nullptr;
     return adpfs_[adpf_index_];
 }
 
-bool HintManager::SetAdpfProfile(const std::string &profile_name) {
+// TODO(jimmyshiu@): Deprecated. Remove once all powerhint.json up-to-date.
+bool HintManager::SetAdpfProfileFromDoHint(const std::string &profile_name) {
     for (std::size_t i = 0; i < adpfs_.size(); ++i) {
         if (adpfs_[i]->mName == profile_name) {
-            adpf_index_ = i;
+            if (adpf_index_ != i) {
+                ATRACE_NAME(StringPrintf("%s %s:%s", __func__, adpfs_[adpf_index_]->mName.c_str(),
+                                         profile_name.c_str())
+                                    .c_str());
+                adpf_index_ = i;
+            }
             return true;
         }
     }
     return false;
 }
 
+bool HintManager::IsAdpfSupported() const {
+    return !adpfs_.empty();
+}
+
+std::shared_ptr<AdpfConfig> HintManager::GetAdpfProfile(const std::string &tag) const {
+    if (adpfs_.empty())
+        return nullptr;
+    if (tag_profile_map_.find(tag) == tag_profile_map_.end()) {
+        // TODO(jimmyshiu@): `return adpfs_[0]` once the GetAdpfProfileFromDoHint() retired.
+        return GetAdpfProfileFromDoHint();
+    }
+    return tag_profile_map_.at(tag);
+}
+
+bool HintManager::SetAdpfProfile(const std::string &tag, const std::string &profile) {
+    if (tag_profile_map_.find(tag) == tag_profile_map_.end()) {
+        LOG(WARNING) << "SetAdpfProfile('" << tag << "', " << profile << ") Invalidate Tag!!!";
+        return false;
+    }
+    if (tag_profile_map_[tag]->mName == profile) {
+        LOG(VERBOSE) << "SetAdpfProfile:(" << tag << ", " << profile << ") value not changed!";
+        return true;
+    }
+
+    bool updated = false;
+    for (std::size_t i = 0; i < adpfs_.size(); ++i) {
+        if (adpfs_[i]->mName == profile) {
+            LOG(DEBUG) << "SetAdpfProfile('" << tag << "', '" << profile << "') Done!";
+            tag_profile_map_[tag] = adpfs_[i];
+            updated = true;
+            break;
+        }
+    }
+    if (!updated) {
+        LOG(WARNING) << "SetAdpfProfile(" << tag << ") failed to find profile:'" << profile << "'";
+    }
+    return updated;
+}
+
 bool HintManager::IsAdpfProfileSupported(const std::string &profile_name) const {
     for (std::size_t i = 0; i < adpfs_.size(); ++i) {
         if (adpfs_[i]->mName == profile_name) {
@@ -858,6 +970,43 @@ bool HintManager::IsAdpfProfileSupported(const std::string &profile_name) const
     return false;
 }
 
+void HintManager::OnNodeUpdate(const std::string &name,
+                               __attribute__((unused)) const std::string &path,
+                               const std::string &value) {
+    // Check if the node is to update ADPF.
+    if (path.starts_with(kAdpfEventNodePath)) {
+        std::string tag = path.substr(strlen(kAdpfEventNodePath));
+        bool updated = SetAdpfProfile(tag, value);
+        if (!updated) {
+            LOG(DEBUG) << "OnNodeUpdate:[" << name << "] failed to update '" << value << "'";
+            return;
+        }
+        auto &callback_list = tag_update_callback_list_[tag];
+        for (const auto &callback : callback_list) {
+            (*callback)(tag_profile_map_[tag]);
+        }
+    }
+}
+
+void HintManager::RegisterAdpfUpdateEvent(const std::string &tag, AdpfCallback *update_adpf_func) {
+    tag_update_callback_list_[tag].push_back(update_adpf_func);
+}
+
+void HintManager::UnregisterAdpfUpdateEvent(const std::string &tag,
+                                            AdpfCallback *update_adpf_func) {
+    auto &callback_list = tag_update_callback_list_[tag];
+    // Use std::find to locate the function object
+    auto it = std::find_if(
+            callback_list.begin(), callback_list.end(),
+            [update_adpf_func](const std::function<void(const std::shared_ptr<AdpfConfig>)> *func) {
+                return func == update_adpf_func;
+            });
+    if (it != callback_list.end()) {
+        // Erase the found function object
+        callback_list.erase(it);
+    }
+}
+
 std::optional<std::string> HintManager::gpu_sysfs_config_path() const {
     return gpu_sysfs_config_path_;
 }
diff --git a/power-libperfmgr/libperfmgr/PropertyNode.cc b/power-libperfmgr/libperfmgr/PropertyNode.cc
index 2ed6d09b..cb4d2ca7 100644
--- a/power-libperfmgr/libperfmgr/PropertyNode.cc
+++ b/power-libperfmgr/libperfmgr/PropertyNode.cc
@@ -52,7 +52,9 @@ std::chrono::milliseconds PropertyNode::Update(bool) {
         const std::string& req_value =
             req_sorted_[value_index].GetRequestValue();
         if (ATRACE_ENABLED()) {
-            const std::string tag = GetName() + ":" + req_value;
+            ATRACE_INT(("N:" + GetName()).c_str(), value_index);
+            const std::string tag =
+                    GetName() + ":" + req_value + ":" + std::to_string(expire_time.count());
             ATRACE_BEGIN(tag.c_str());
         }
         if (!android::base::SetProperty(node_path_, req_value)) {
diff --git a/power-libperfmgr/libperfmgr/RequestGroup.cc b/power-libperfmgr/libperfmgr/RequestGroup.cc
index 4fedd33a..8787329c 100644
--- a/power-libperfmgr/libperfmgr/RequestGroup.cc
+++ b/power-libperfmgr/libperfmgr/RequestGroup.cc
@@ -47,9 +47,13 @@ const std::string& RequestGroup::GetRequestValue() const {
 }
 
 bool RequestGroup::GetExpireTime(std::chrono::milliseconds* expire_time) {
-    ReqTime now = std::chrono::steady_clock::now();
+
     *expire_time = std::chrono::milliseconds::max();
 
+    if (request_map_.empty()) return false;
+
+    ReqTime now = std::chrono::steady_clock::now();
+
     bool active = false;
     for (auto it = request_map_.begin(); it != request_map_.end();) {
         auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/AdpfConfig.h b/power-libperfmgr/libperfmgr/include/perfmgr/AdpfConfig.h
index c75e380e..f4491abe 100644
--- a/power-libperfmgr/libperfmgr/include/perfmgr/AdpfConfig.h
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/AdpfConfig.h
@@ -54,11 +54,12 @@ struct AdpfConfig {
 
     // Heuristic boost control
     std::optional<bool> mHeuristicBoostOn;
-    std::optional<uint32_t> mHBoostOnMissedCycles;
-    std::optional<double> mHBoostOffMaxAvgRatio;
-    std::optional<uint32_t> mHBoostOffMissedCycles;
-    std::optional<double> mHBoostPidPuFactor;
-    std::optional<uint32_t> mHBoostUclampMin;
+    std::optional<uint32_t> mHBoostModerateJankThreshold;
+    std::optional<double> mHBoostOffMaxAvgDurRatio;
+    std::optional<double> mHBoostSevereJankPidPu;
+    std::optional<uint32_t> mHBoostSevereJankThreshold;
+    std::optional<std::pair<uint32_t, uint32_t>> mHBoostUclampMinCeilingRange;
+    std::optional<std::pair<uint32_t, uint32_t>> mHBoostUclampMinFloorRange;
     std::optional<double> mJankCheckTimeFactor;
     std::optional<uint32_t> mLowFrameRateThreshold;
     std::optional<uint32_t> mMaxRecordsNum;
@@ -82,10 +83,13 @@ struct AdpfConfig {
                uint64_t samplingWindowD, int64_t reportingRateLimitNs, double targetTimeFactor,
                double staleTimeFactor, std::optional<bool> gpuBoostOn,
                std::optional<uint64_t> gpuBoostCapacityMax, uint64_t gpuCapacityLoadUpHeadroom,
-               std::optional<bool> heuristicBoostOn, std::optional<uint32_t> hBoostOnMissedCycles,
-               std::optional<double> hBoostOffMaxAvgRatio,
-               std::optional<uint32_t> hBoostOffMissedCycles,
-               std::optional<double> hBoostPidPuFactor, std::optional<uint32_t> hBoostUclampMin,
+               std::optional<bool> heuristicBoostOn,
+               std::optional<uint32_t> hBoostModerateJankThreshold,
+               std::optional<double> hBoostOffMaxAvgDurRatio,
+               std::optional<double> hBoostSevereJankPidPu,
+               std::optional<uint32_t> hBoostSevereJankThreshold,
+               std::optional<std::pair<uint32_t, uint32_t>> hBoostUclampMinCeilingRange,
+               std::optional<std::pair<uint32_t, uint32_t>> hBoostUclampMinFloorRange,
                std::optional<double> jankCheckTimeFactor,
                std::optional<uint32_t> lowFrameRateThreshold, std::optional<uint32_t> maxRecordsNum,
                uint32_t uclampMinLoadUp, uint32_t uclampMinLoadReset,
@@ -115,11 +119,12 @@ struct AdpfConfig {
           mGpuBoostCapacityMax(gpuBoostCapacityMax),
           mGpuCapacityLoadUpHeadroom(gpuCapacityLoadUpHeadroom),
           mHeuristicBoostOn(heuristicBoostOn),
-          mHBoostOnMissedCycles(hBoostOnMissedCycles),
-          mHBoostOffMaxAvgRatio(hBoostOffMaxAvgRatio),
-          mHBoostOffMissedCycles(hBoostOffMissedCycles),
-          mHBoostPidPuFactor(hBoostPidPuFactor),
-          mHBoostUclampMin(hBoostUclampMin),
+          mHBoostModerateJankThreshold(hBoostModerateJankThreshold),
+          mHBoostOffMaxAvgDurRatio(hBoostOffMaxAvgDurRatio),
+          mHBoostSevereJankPidPu(hBoostSevereJankPidPu),
+          mHBoostSevereJankThreshold(hBoostSevereJankThreshold),
+          mHBoostUclampMinCeilingRange(hBoostUclampMinCeilingRange),
+          mHBoostUclampMinFloorRange(hBoostUclampMinFloorRange),
           mJankCheckTimeFactor(jankCheckTimeFactor),
           mLowFrameRateThreshold(lowFrameRateThreshold),
           mMaxRecordsNum(maxRecordsNum),
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/EventNode.h b/power-libperfmgr/libperfmgr/include/perfmgr/EventNode.h
new file mode 100644
index 00000000..f1b97f15
--- /dev/null
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/EventNode.h
@@ -0,0 +1,51 @@
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
+#ifndef ANDROID_LIBPERFMGR_EVENTNODE_H_
+#define ANDROID_LIBPERFMGR_EVENTNODE_H_
+
+#include <cstddef>
+#include <string>
+#include <vector>
+
+#include "perfmgr/Node.h"
+
+namespace android {
+namespace perfmgr {
+
+// EventNode represents to handle events by callback function.
+class EventNode : public Node {
+  public:
+    EventNode(std::string name, std::string node_path, std::vector<RequestGroup> req_sorted,
+              std::size_t default_val_index, bool reset_on_init,
+              std::function<void(const std::string &, const std::string &, const std::string &)>
+                      update_callback);
+
+    std::chrono::milliseconds Update(bool log_error) override;
+    void DumpToFd(int fd) const override;
+
+  private:
+    EventNode(const Node &other) = delete;
+    EventNode &operator=(Node const &) = delete;
+    const std::function<void(const std::string &name, const std::string &path,
+                             const std::string &value)>
+            update_callback_;
+};
+
+}  // namespace perfmgr
+}  // namespace android
+
+#endif  // ANDROID_LIBPERFMGR_EVENTNODE_H_
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/HintManager.h b/power-libperfmgr/libperfmgr/include/perfmgr/HintManager.h
index 204f6f15..303818a8 100644
--- a/power-libperfmgr/libperfmgr/include/perfmgr/HintManager.h
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/HintManager.h
@@ -90,10 +90,12 @@ class HintManager {
   public:
     HintManager(sp<NodeLooperThread> nm, const std::unordered_map<std::string, Hint> &actions,
                 const std::vector<std::shared_ptr<AdpfConfig>> &adpfs,
+                const std::unordered_map<std::string, std::shared_ptr<AdpfConfig>> &tag_adpfs,
                 std::optional<std::string> gpu_sysfs_config_path)
         : nm_(std::move(nm)),
           actions_(actions),
           adpfs_(adpfs),
+          tag_profile_map_(tag_adpfs),
           adpf_index_(0),
           gpu_sysfs_config_path_(gpu_sysfs_config_path) {}
     ~HintManager() {
@@ -123,13 +125,23 @@ class HintManager {
     // Query if given hint enabled.
     bool IsHintEnabled(const std::string &hint_type) const;
 
-    // set ADPF config by profile name.
-    bool SetAdpfProfile(const std::string &profile_name);
+    // TODO(jimmyshiu@): Need to be removed once all powerhint.json up-to-date.
+    bool SetAdpfProfileFromDoHint(const std::string &profile_name);
+    std::shared_ptr<AdpfConfig> GetAdpfProfileFromDoHint() const;
+
+    bool SetAdpfProfile(const std::string &tag, const std::string &profile);
+
+    typedef std::function<void(std::shared_ptr<AdpfConfig>)> AdpfCallback;
+    void RegisterAdpfUpdateEvent(const std::string &tag, AdpfCallback *update_adpf_func);
+    void UnregisterAdpfUpdateEvent(const std::string &tag, AdpfCallback *update_adpf_func);
 
     std::optional<std::string> gpu_sysfs_config_path() const;
 
     // get current ADPF.
-    std::shared_ptr<AdpfConfig> GetAdpfProfile() const;
+    std::shared_ptr<AdpfConfig> GetAdpfProfile(const std::string &node_name = "OTHER") const;
+
+    // Check if ADPF is supported.
+    bool IsAdpfSupported() const;
 
     // Query if given AdpfProfile supported.
     bool IsAdpfProfileSupported(const std::string &name) const;
@@ -153,8 +165,7 @@ class HintManager {
     static HintManager *GetInstance();
 
   protected:
-    static std::vector<std::unique_ptr<Node>> ParseNodes(
-        const std::string& json_doc);
+    static std::vector<std::unique_ptr<Node>> ParseNodes(const std::string &json_doc);
     static std::unordered_map<std::string, Hint> ParseActions(
             const std::string &json_doc, const std::vector<std::unique_ptr<Node>> &nodes);
     static std::vector<std::shared_ptr<AdpfConfig>> ParseAdpfConfigs(const std::string &json_doc);
@@ -176,10 +187,17 @@ class HintManager {
     sp<NodeLooperThread> nm_;
     std::unordered_map<std::string, Hint> actions_;
     std::vector<std::shared_ptr<AdpfConfig>> adpfs_;
+    // TODO(jimmyshiu@): Need to be removed once all powerhint.json up-to-date.
+    std::unordered_map<std::string, std::shared_ptr<AdpfConfig>> tag_profile_map_;
     uint32_t adpf_index_;
     std::optional<std::string> gpu_sysfs_config_path_;
 
     static std::unique_ptr<HintManager> sInstance;
+
+    // Hint Update Callback
+    void OnNodeUpdate(const std::string &name, const std::string &path, const std::string &value);
+    // set ADPF config by hint name.
+    std::unordered_map<std::string, std::vector<AdpfCallback *>> tag_update_callback_list_;
 };
 
 }  // namespace perfmgr
diff --git a/power-libperfmgr/libperfmgr/tests/EventNodeTest.cc b/power-libperfmgr/libperfmgr/tests/EventNodeTest.cc
new file mode 100644
index 00000000..62ca90f6
--- /dev/null
+++ b/power-libperfmgr/libperfmgr/tests/EventNodeTest.cc
@@ -0,0 +1,229 @@
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
+#include <android-base/file.h>
+#include <android-base/stringprintf.h>
+#include <gtest/gtest.h>
+
+#include <algorithm>
+#include <thread>
+
+#include "perfmgr/EventNode.h"
+
+namespace android {
+namespace perfmgr {
+
+using std::literals::chrono_literals::operator""ms;
+
+constexpr double kTIMING_TOLERANCE_MS = std::chrono::milliseconds(25).count();
+constexpr auto kSLEEP_TOLERANCE_MS = 2ms;
+
+// Test init with no default value
+TEST(EventNodeTest, NoInitDefaultTest) {
+    std::string node_val = "uninitialize";
+    auto update_callback = [&node_val](const std::string &, const std::string &,
+                                       const std::string &val) { node_val = val; };
+    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 1, false,
+                update_callback);
+    t.Update(false);
+    EXPECT_EQ(node_val, "uninitialize");
+}
+
+// Test init with default value
+TEST(EventNodeTest, InitDefaultTest) {
+    std::string node_val = "uninitialize";
+    auto update_callback = [&node_val](const std::string &, const std::string &,
+                                       const std::string &val) { node_val = val; };
+    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 1, true,
+                update_callback);
+    t.Update(false);
+    EXPECT_EQ(node_val, "value1");
+    EventNode t2("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 0, true,
+                 update_callback);
+    t2.Update(false);
+    EXPECT_EQ(node_val, "value0");
+}
+
+// Test DumpToFd
+TEST(EventNodeTest, DumpToFdTest) {
+    std::string node_val = "uninitialize";
+    auto update_callback = [&node_val](const std::string &, const std::string &,
+                                       const std::string &val) { node_val = val; };
+    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 1, true,
+                update_callback);
+    t.Update(false);
+    t.Update(false);
+    TemporaryFile dumptf;
+    t.DumpToFd(dumptf.fd);
+    fsync(dumptf.fd);
+    std::string buf(android::base::StringPrintf(
+            "Node Name\t"
+            "Event Path\t"
+            "Current Index\t"
+            "Current Value\n"
+            "%s\t%s\t%zu\t%s\n",
+            "EventName", "<Event>:Node", static_cast<size_t>(1), "value1"));
+    std::string s;
+    EXPECT_TRUE(android::base::ReadFileToString(dumptf.path, &s)) << strerror(errno);
+    EXPECT_EQ(buf, s);
+}
+
+// Test GetValueIndex
+TEST(EventNodeTest, GetValueIndexTest) {
+    std::string node_val = "uninitialize";
+    auto update_callback = [&node_val](const std::string &, const std::string &,
+                                       const std::string &val) { node_val = val; };
+    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 1, false,
+                update_callback);
+    std::size_t index = 0;
+    EXPECT_TRUE(t.GetValueIndex("value2", &index));
+    EXPECT_EQ(2u, index);
+    index = 1234;
+    EXPECT_FALSE(t.GetValueIndex("NON_EXIST", &index));
+    EXPECT_EQ(1234u, index);
+}
+
+// Test GetValues
+TEST(EventNodeTest, GetValuesTest) {
+    std::string node_val = "uninitialize";
+    auto update_callback = [&node_val](const std::string &, const std::string &,
+                                       const std::string &val) { node_val = val; };
+    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 1, false,
+                update_callback);
+    std::vector values = t.GetValues();
+    EXPECT_EQ(3u, values.size());
+    EXPECT_EQ("value0", values[0]);
+    EXPECT_EQ("value1", values[1]);
+    EXPECT_EQ("value2", values[2]);
+}
+
+// Test get more properties
+TEST(EventNodeTest, GetPropertiesTest) {
+    std::string node_val = "uninitialize";
+    auto update_callback = [&node_val](const std::string &, const std::string &,
+                                       const std::string &val) { node_val = val; };
+    std::string test_name = "TESTREQ_1";
+    std::string test_path = "TEST_PATH";
+    EventNode t(test_name, test_path, {}, 0, false, update_callback);
+    EXPECT_EQ(test_name, t.GetName());
+    EXPECT_EQ(test_path, t.GetPath());
+    EXPECT_EQ(0u, t.GetValues().size());
+    EXPECT_EQ(0u, t.GetDefaultIndex());
+    EXPECT_FALSE(t.GetResetOnInit());
+}
+
+// Test add request
+TEST(EventNodeTest, AddRequestTest) {
+    std::string node_val = "uninitialize";
+    auto update_callback = [&node_val](const std::string &, const std::string &,
+                                       const std::string &val) { node_val = val; };
+    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {""}}, 2, true,
+                update_callback);
+    auto start = std::chrono::steady_clock::now();
+    EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
+    std::chrono::milliseconds expire_time = t.Update(true);
+    // Add request @ value1
+    EXPECT_EQ(node_val, "value1");
+    EXPECT_NEAR(std::chrono::milliseconds(500).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Add request @ value0 higher prio than value1
+    EXPECT_TRUE(t.AddRequest(0, "LAUNCH", start + 200ms));
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "value0");
+    EXPECT_NEAR(std::chrono::milliseconds(200).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Let high prio request timeout, now only request @ value1 active
+    std::this_thread::sleep_for(expire_time + kSLEEP_TOLERANCE_MS);
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "value1");
+    EXPECT_NEAR(std::chrono::milliseconds(300).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Let all requests timeout, now default value2
+    std::this_thread::sleep_for(expire_time + kSLEEP_TOLERANCE_MS);
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "");
+    EXPECT_EQ(std::chrono::milliseconds::max(), expire_time);
+}
+
+// Test remove request
+TEST(EventNodeTest, RemoveRequestTest) {
+    std::string node_val = "uninitialize";
+    auto update_callback = [&node_val](const std::string &, const std::string &,
+                                       const std::string &val) { node_val = val; };
+    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 2, true,
+                update_callback);
+    auto start = std::chrono::steady_clock::now();
+    EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
+    std::chrono::milliseconds expire_time = t.Update(true);
+    // Add request @ value1
+    EXPECT_EQ(node_val, "value1");
+    EXPECT_NEAR(std::chrono::milliseconds(500).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Add request @ value0 higher prio than value1
+    EXPECT_TRUE(t.AddRequest(0, "LAUNCH", start + 200ms));
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "value0");
+    EXPECT_NEAR(std::chrono::milliseconds(200).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Remove high prio request, now only request @ value1 active
+    t.RemoveRequest("LAUNCH");
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "value1");
+    EXPECT_NEAR(std::chrono::milliseconds(500).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Remove request, now default value2
+    t.RemoveRequest("INTERACTION");
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "value2");
+    EXPECT_EQ(std::chrono::milliseconds::max(), expire_time);
+}
+
+// Test add request
+TEST(EventNodeTest, AddRequestTestOverride) {
+    std::string node_val = "uninitialize";
+    auto update_callback = [&node_val](const std::string &, const std::string &,
+                                       const std::string &val) { node_val = val; };
+    EventNode t("EventName", "<Event>:Node", {{"value0"}, {"value1"}, {"value2"}}, 2, true,
+                update_callback);
+    auto start = std::chrono::steady_clock::now();
+    EXPECT_TRUE(t.AddRequest(1, "INTERACTION", start + 500ms));
+    std::chrono::milliseconds expire_time = t.Update(true);
+    // Add request @ value1
+    EXPECT_EQ(node_val, "value1");
+    EXPECT_NEAR(std::chrono::milliseconds(500).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Add request @ value0 higher prio than value1
+    EXPECT_TRUE(t.AddRequest(0, "LAUNCH", start + 200ms));
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "value0");
+    EXPECT_NEAR(std::chrono::milliseconds(200).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Add request @ value0 shorter
+    EXPECT_TRUE(t.AddRequest(0, "LAUNCH", start + 100ms));
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "value0");
+    EXPECT_NEAR(std::chrono::milliseconds(200).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Add request @ value0 longer
+    EXPECT_TRUE(t.AddRequest(0, "LAUNCH", start + 300ms));
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "value0");
+    EXPECT_NEAR(std::chrono::milliseconds(300).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Remove high prio request, now only request @ value1 active
+    t.RemoveRequest("LAUNCH");
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "value1");
+    EXPECT_NEAR(std::chrono::milliseconds(500).count(), expire_time.count(), kTIMING_TOLERANCE_MS);
+    // Remove request, now default value2
+    t.RemoveRequest("INTERACTION");
+    expire_time = t.Update(true);
+    EXPECT_EQ(node_val, "value2");
+    EXPECT_EQ(std::chrono::milliseconds::max(), expire_time);
+}
+
+}  // namespace perfmgr
+}  // namespace android
diff --git a/power-libperfmgr/libperfmgr/tests/FileNodeTest.cc b/power-libperfmgr/libperfmgr/tests/FileNodeTest.cc
index 45d11e4c..c3f269bb 100644
--- a/power-libperfmgr/libperfmgr/tests/FileNodeTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/FileNodeTest.cc
@@ -10,7 +10,7 @@
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specic language governing permissions and
+ * See the License for the specific language governing permissions and
  * limitations under the License.
  */
 
diff --git a/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc b/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc
index f91bd775..a3b8ca58 100644
--- a/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc
@@ -10,7 +10,7 @@
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specic language governing permissions and
+ * See the License for the specific language governing permissions and
  * limitations under the License.
  */
 
@@ -148,11 +148,48 @@ constexpr char kJSON_RAW[] = R"(
             "Type": "DoHint",
             "Value": "LAUNCH"
         }
+    ]
+}
+)";
+
+constexpr char kJSON_ADPF[] = R"(
+{
+    "Nodes": [
+        {
+            "Name": "OTHER",
+            "Path": "<AdpfConfig>:OTHER",
+            "Values": [
+                "ADPF_DEFAULT"
+            ],
+            "Type": "Event"
+        },
+        {
+            "Name": "SURFACEFLINGER",
+            "Path": "<AdpfConfig>:SURFACEFLINGER",
+            "Values": [
+                "ADPF_DEFAULT",
+                "ADPF_SF"
+            ],
+            "Type": "Event"
+        }
+    ],
+    "Actions": [
+        {
+        "PowerHint": "SF_PLAYING",
+        "Node": "SURFACEFLINGER",
+        "Duration": 0,
+        "Value": "ADPF_SF"
+        },
+        {
+        "PowerHint": "SF_RESET",
+        "Node": "SURFACEFLINGER",
+        "Duration": 0,
+        "Value": "ADPF_DEFAULT"
+        }
     ],
-    "GpuSysfsPath" : "/sys/devices/platform/123.abc",
     "AdpfConfig": [
         {
-            "Name": "REFRESH_120FPS",
+            "Name": "ADPF_DEFAULT",
             "PID_On": true,
             "PID_Po": 5.0,
             "PID_Pu": 3.0,
@@ -172,25 +209,24 @@ constexpr char kJSON_RAW[] = R"(
             "UclampMin_High": 384,
             "UclampMin_Low": 0,
             "ReportingRateLimitNs": 166666660,
-            "EarlyBoost_On": false,
-            "EarlyBoost_TimeFactor": 0.8,
             "TargetTimeFactor": 1.0,
             "StaleTimeFactor": 10.0,
             "GpuBoost": true,
-            "GpuCapacityBoostMax": 300000,
+            "GpuCapacityBoostMax": 325000,
             "GpuCapacityLoadUpHeadroom": 1000,
             "HeuristicBoost_On": true,
-            "HBoostOnMissedCycles": 4,
-            "HBoostOffMaxAvgRatio": 4.0,
-            "HBoostOffMissedCycles": 2,
-            "HBoostPidPuFactor": 0.5,
-            "HBoostUclampMin": 800,
+            "HBoostModerateJankThreshold": 4,
+            "HBoostOffMaxAvgDurRatio": 4.0,
+            "HBoostSevereJankPidPu": 0.5,
+            "HBoostSevereJankThreshold": 2,
+            "HBoostUclampMinCeilingRange": [480, 800],
+            "HBoostUclampMinFloorRange": [200, 400],
             "JankCheckTimeFactor": 1.2,
             "LowFrameRateThreshold": 25,
             "MaxRecordsNum": 50
         },
         {
-            "Name": "REFRESH_60FPS",
+            "Name": "ADPF_SF",
             "PID_On": false,
             "PID_Po": 0,
             "PID_Pu": 0,
@@ -205,15 +241,42 @@ constexpr char kJSON_RAW[] = R"(
             "SamplingWindow_D": 0,
             "UclampMin_On": true,
             "UclampMin_Init": 200,
+            "UclampMin_LoadUp": 157,
+            "UclampMin_LoadReset": 157,
             "UclampMin_High": 157,
             "UclampMin_Low": 157,
             "ReportingRateLimitNs": 83333330,
-            "EarlyBoost_On": true,
-            "EarlyBoost_TimeFactor": 1.2,
             "TargetTimeFactor": 1.4,
             "StaleTimeFactor": 5.0
+        },
+        {
+            "Name": "SF_VIDEO_30FPS",
+            "PID_On": true,
+            "PID_Po": 5.0,
+            "PID_Pu": 3.0,
+            "PID_I": 0.001,
+            "PID_I_Init": 200,
+            "PID_I_High": 512,
+            "PID_I_Low": -120,
+            "PID_Do": 500.0,
+            "PID_Du": 300.0,
+            "SamplingWindow_P": 0,
+            "SamplingWindow_I": 0,
+            "SamplingWindow_D": 0,
+            "UclampMin_On": true,
+            "UclampMin_Init": 200,
+            "UclampMin_LoadUp": 157,
+            "UclampMin_LoadReset": 157,
+            "UclampMin_High": 480,
+            "UclampMin_Low": 240,
+            "ReportingRateLimitNs": 83333330,
+            "TargetTimeFactor": 1.4,
+            "StaleTimeFactor": 5.0,
+            "GpuBoost": false,
+            "GpuCapacityBoostMax": 32500
         }
-    ]
+    ],
+    "GpuSysfsPath" : "/sys/devices/platform/123.abc"
 }
 )";
 
@@ -221,7 +284,7 @@ class HintManagerTest : public ::testing::Test, public HintManager {
   protected:
     HintManagerTest()
         : HintManager(nullptr, std::unordered_map<std::string, Hint>{},
-                      std::vector<std::shared_ptr<AdpfConfig>>(), {}) {
+                      std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, {}) {
         android::base::SetMinimumLogSeverity(android::base::VERBOSE);
         prop_ = "vendor.pwhal.mode";
     }
@@ -268,8 +331,7 @@ class HintManagerTest : public ::testing::Test, public HintManager {
         from = "/sys/devices/system/cpu/cpu4/cpufreq/scaling_min_freq";
         start_pos = json_doc_.find(from);
         json_doc_.replace(start_pos, from.length(), files_[1 + 2]->path);
-        EXPECT_TRUE(android::base::SetProperty(prop_, ""))
-            << "failed to clear property";
+        EXPECT_TRUE(android::base::SetProperty(prop_, "")) << "failed to clear property";
     }
 
     virtual void TearDown() {
@@ -277,6 +339,7 @@ class HintManagerTest : public ::testing::Test, public HintManager {
         nodes_.clear();
         files_.clear();
         nm_ = nullptr;
+        tag_adpfs_.clear();
     }
     sp<NodeLooperThread> nm_;
     std::unordered_map<std::string, Hint> actions_;
@@ -284,6 +347,7 @@ class HintManagerTest : public ::testing::Test, public HintManager {
     std::vector<std::unique_ptr<TemporaryFile>> files_;
     std::string json_doc_;
     std::string prop_;
+    std::unordered_map<std::string, std::shared_ptr<AdpfConfig>> tag_adpfs_;
 };
 
 static inline void _VerifyPropertyValue(const std::string& path,
@@ -308,7 +372,7 @@ static inline void _VerifyStats(const HintStats &stats, uint32_t count, uint64_t
 
 // Test GetHints
 TEST_F(HintManagerTest, GetHintsTest) {
-    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), {});
+    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, {});
     EXPECT_TRUE(hm.Start());
     std::vector<std::string> hints = hm.GetHints();
     EXPECT_TRUE(hm.IsRunning());
@@ -321,7 +385,7 @@ TEST_F(HintManagerTest, GetHintsTest) {
 TEST_F(HintManagerTest, GetHintStatsTest) {
     auto hm =
             std::make_unique<HintManager>(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(),
-                                          std::optional<std::string>{});
+                                          tag_adpfs_, std::optional<std::string>{});
     EXPECT_TRUE(InitHintStatus(hm));
     EXPECT_TRUE(hm->Start());
     HintStats launch_stats(hm->GetHintStats("LAUNCH"));
@@ -334,7 +398,7 @@ TEST_F(HintManagerTest, GetHintStatsTest) {
 
 // Test initialization of default values
 TEST_F(HintManagerTest, HintInitDefaultTest) {
-    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), {});
+    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, {});
     EXPECT_TRUE(hm.Start());
     std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
     EXPECT_TRUE(hm.IsRunning());
@@ -345,7 +409,7 @@ TEST_F(HintManagerTest, HintInitDefaultTest) {
 
 // Test IsHintSupported
 TEST_F(HintManagerTest, HintSupportedTest) {
-    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), {});
+    HintManager hm(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(), tag_adpfs_, {});
     EXPECT_TRUE(hm.IsHintSupported("INTERACTION"));
     EXPECT_TRUE(hm.IsHintSupported("LAUNCH"));
     EXPECT_FALSE(hm.IsHintSupported("NO_SUCH_HINT"));
@@ -355,7 +419,7 @@ TEST_F(HintManagerTest, HintSupportedTest) {
 TEST_F(HintManagerTest, HintTest) {
     auto hm =
             std::make_unique<HintManager>(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(),
-                                          std::optional<std::string>{});
+                                          tag_adpfs_, std::optional<std::string>{});
     EXPECT_TRUE(InitHintStatus(hm));
     EXPECT_TRUE(hm->Start());
     EXPECT_TRUE(hm->IsRunning());
@@ -406,7 +470,7 @@ TEST_F(HintManagerTest, HintTest) {
 TEST_F(HintManagerTest, HintStatsTest) {
     auto hm =
             std::make_unique<HintManager>(nm_, actions_, std::vector<std::shared_ptr<AdpfConfig>>(),
-                                          std::optional<std::string>{});
+                                          tag_adpfs_, std::optional<std::string>{});
     EXPECT_TRUE(InitHintStatus(hm));
     EXPECT_TRUE(hm->Start());
     EXPECT_TRUE(hm->IsRunning());
@@ -448,8 +512,7 @@ TEST_F(HintManagerTest, HintStatsTest) {
 
 // Test parsing nodes
 TEST_F(HintManagerTest, ParseNodesTest) {
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     EXPECT_EQ(4u, nodes.size());
     EXPECT_EQ("CPUCluster0MinFreq", nodes[0]->GetName());
     EXPECT_EQ("CPUCluster1MinFreq", nodes[1]->GetName());
@@ -482,8 +545,7 @@ TEST_F(HintManagerTest, ParseNodesDuplicateNameTest) {
     std::string from = "CPUCluster0MinFreq";
     size_t start_pos = json_doc_.find(from);
     json_doc_.replace(start_pos, from.length(), "CPUCluster1MinFreq");
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     EXPECT_EQ(0u, nodes.size());
 }
 
@@ -491,8 +553,7 @@ TEST_F(HintManagerTest, ParsePropertyNodesDuplicatNameTest) {
     std::string from = "ModeProperty";
     size_t start_pos = json_doc_.find(from);
     json_doc_.replace(start_pos, from.length(), "CPUCluster1MinFreq");
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     EXPECT_EQ(0u, nodes.size());
 }
 
@@ -501,8 +562,7 @@ TEST_F(HintManagerTest, ParseNodesDuplicatePathTest) {
     std::string from = files_[0 + 2]->path;
     size_t start_pos = json_doc_.find(from);
     json_doc_.replace(start_pos, from.length(), files_[1 + 2]->path);
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     EXPECT_EQ(0u, nodes.size());
 }
 
@@ -511,8 +571,7 @@ TEST_F(HintManagerTest, ParseFileNodesDuplicateValueTest) {
     std::string from = "1512000";
     size_t start_pos = json_doc_.find(from);
     json_doc_.replace(start_pos, from.length(), "1134000");
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     EXPECT_EQ(0u, nodes.size());
 }
 
@@ -521,8 +580,7 @@ TEST_F(HintManagerTest, ParsePropertyNodesDuplicateValueTest) {
     std::string from = "HIGH";
     size_t start_pos = json_doc_.find(from);
     json_doc_.replace(start_pos, from.length(), "LOW");
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     EXPECT_EQ(0u, nodes.size());
 }
 
@@ -531,8 +589,7 @@ TEST_F(HintManagerTest, ParseFileNodesEmptyValueTest) {
     std::string from = "384000";
     size_t start_pos = json_doc_.find(from);
     json_doc_.replace(start_pos, from.length(), "");
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     EXPECT_EQ(0u, nodes.size());
 }
 
@@ -541,8 +598,7 @@ TEST_F(HintManagerTest, ParsePropertyNodesEmptyValueTest) {
     std::string from = "LOW";
     size_t start_pos = json_doc_.find(from);
     json_doc_.replace(start_pos, from.length(), "");
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     EXPECT_EQ(4u, nodes.size());
     EXPECT_EQ("CPUCluster0MinFreq", nodes[0]->GetName());
     EXPECT_EQ("CPUCluster1MinFreq", nodes[1]->GetName());
@@ -572,8 +628,7 @@ TEST_F(HintManagerTest, ParsePropertyNodesEmptyValueTest) {
 
 // Test parsing invalid json for nodes
 TEST_F(HintManagerTest, ParseBadFileNodesTest) {
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes("invalid json");
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes("invalid json");
     EXPECT_EQ(0u, nodes.size());
     nodes = HintManager::ParseNodes(
         "{\"devices\":{\"15\":[\"armeabi-v7a\"],\"16\":[\"armeabi-v7a\"],"
@@ -583,8 +638,7 @@ TEST_F(HintManagerTest, ParseBadFileNodesTest) {
 
 // Test parsing actions
 TEST_F(HintManagerTest, ParseActionsTest) {
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     std::unordered_map<std::string, Hint> actions = HintManager::ParseActions(json_doc_, nodes);
     EXPECT_EQ(7u, actions.size());
 
@@ -643,8 +697,7 @@ TEST_F(HintManagerTest, ParseActionDuplicateFileNodeTest) {
     std::string from = R"("Node": "CPUCluster0MinFreq")";
     size_t start_pos = json_doc_.find(from);
     json_doc_.replace(start_pos, from.length(), R"("Node": "CPUCluster1MinFreq")");
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     EXPECT_EQ(4u, nodes.size());
     auto actions = HintManager::ParseActions(json_doc_, nodes);
     EXPECT_EQ(0u, actions.size());
@@ -663,8 +716,7 @@ TEST_F(HintManagerTest, ParseActionDuplicatePropertyNodeTest) {
 
 // Test parsing invalid json for actions
 TEST_F(HintManagerTest, ParseBadActionsTest) {
-    std::vector<std::unique_ptr<Node>> nodes =
-        HintManager::ParseNodes(json_doc_);
+    std::vector<std::unique_ptr<Node>> nodes = HintManager::ParseNodes(json_doc_);
     auto actions = HintManager::ParseActions("invalid json", nodes);
     EXPECT_EQ(0u, actions.size());
     actions = HintManager::ParseActions(
@@ -786,10 +838,11 @@ TEST_F(HintManagerTest, GetFromJSONTest) {
 
 // Test parsing AdpfConfig
 TEST_F(HintManagerTest, ParseAdpfConfigsTest) {
-    std::vector<std::shared_ptr<AdpfConfig>> adpfs = HintManager::ParseAdpfConfigs(json_doc_);
-    EXPECT_EQ(2u, adpfs.size());
-    EXPECT_EQ("REFRESH_120FPS", adpfs[0]->mName);
-    EXPECT_EQ("REFRESH_60FPS", adpfs[1]->mName);
+    std::string json_doc = std::string(kJSON_ADPF);
+    std::vector<std::shared_ptr<AdpfConfig>> adpfs = HintManager::ParseAdpfConfigs(json_doc);
+    EXPECT_EQ(3u, adpfs.size());
+    EXPECT_EQ("ADPF_DEFAULT", adpfs[0]->mName);
+    EXPECT_EQ("ADPF_SF", adpfs[1]->mName);
     EXPECT_TRUE(adpfs[0]->mPidOn);
     EXPECT_FALSE(adpfs[1]->mPidOn);
     EXPECT_EQ(5.0, adpfs[0]->mPidPo);
@@ -834,16 +887,20 @@ TEST_F(HintManagerTest, ParseAdpfConfigsTest) {
     EXPECT_EQ(5.0, adpfs[1]->mStaleTimeFactor);
     EXPECT_TRUE(adpfs[0]->mHeuristicBoostOn.value());
     EXPECT_FALSE(adpfs[1]->mHeuristicBoostOn.has_value());
-    EXPECT_EQ(4U, adpfs[0]->mHBoostOnMissedCycles.value());
-    EXPECT_FALSE(adpfs[1]->mHBoostOnMissedCycles.has_value());
-    EXPECT_EQ(4.0, adpfs[0]->mHBoostOffMaxAvgRatio.value());
-    EXPECT_FALSE(adpfs[1]->mHBoostOffMaxAvgRatio.has_value());
-    EXPECT_EQ(2U, adpfs[0]->mHBoostOffMissedCycles.value());
-    EXPECT_FALSE(adpfs[1]->mHBoostOffMissedCycles.has_value());
-    EXPECT_EQ(0.5, adpfs[0]->mHBoostPidPuFactor.value());
-    EXPECT_FALSE(adpfs[1]->mHBoostPidPuFactor.has_value());
-    EXPECT_EQ(800U, adpfs[0]->mHBoostUclampMin.value());
-    EXPECT_FALSE(adpfs[1]->mHBoostUclampMin.has_value());
+    EXPECT_EQ(4U, adpfs[0]->mHBoostModerateJankThreshold.value());
+    EXPECT_FALSE(adpfs[1]->mHBoostModerateJankThreshold.has_value());
+    EXPECT_EQ(4.0, adpfs[0]->mHBoostOffMaxAvgDurRatio.value());
+    EXPECT_FALSE(adpfs[1]->mHBoostOffMaxAvgDurRatio.has_value());
+    EXPECT_EQ(0.5, adpfs[0]->mHBoostSevereJankPidPu.value());
+    EXPECT_FALSE(adpfs[1]->mHBoostSevereJankPidPu.has_value());
+    EXPECT_EQ(2U, adpfs[0]->mHBoostSevereJankThreshold.value());
+    EXPECT_FALSE(adpfs[1]->mHBoostSevereJankThreshold.has_value());
+    EXPECT_EQ(480U, adpfs[0]->mHBoostUclampMinCeilingRange.value().first);
+    EXPECT_EQ(800U, adpfs[0]->mHBoostUclampMinCeilingRange.value().second);
+    EXPECT_FALSE(adpfs[1]->mHBoostUclampMinCeilingRange.has_value());
+    EXPECT_EQ(200U, adpfs[0]->mHBoostUclampMinFloorRange.value().first);
+    EXPECT_EQ(400U, adpfs[0]->mHBoostUclampMinFloorRange.value().second);
+    EXPECT_FALSE(adpfs[1]->mHBoostUclampMinFloorRange.has_value());
     EXPECT_EQ(1.2, adpfs[0]->mJankCheckTimeFactor.value());
     EXPECT_FALSE(adpfs[1]->mJankCheckTimeFactor.has_value());
     EXPECT_EQ(25U, adpfs[0]->mLowFrameRateThreshold.value());
@@ -854,77 +911,195 @@ TEST_F(HintManagerTest, ParseAdpfConfigsTest) {
 
 // Test parsing adpf configs with duplicate name
 TEST_F(HintManagerTest, ParseAdpfConfigsDuplicateNameTest) {
-    std::string from = "REFRESH_120FPS";
-    size_t start_pos = json_doc_.find(from);
-    json_doc_.replace(start_pos, from.length(), "REFRESH_60FPS");
-    std::vector<std::shared_ptr<AdpfConfig>> adpfs = HintManager::ParseAdpfConfigs(json_doc_);
+    std::string json_doc = std::string(kJSON_ADPF);
+    std::string from = "\"Name\": \"ADPF_DEFAULT\"";
+    size_t start_pos = json_doc.find(from);
+    json_doc.replace(start_pos, from.length(), "\"Name\": \"ADPF_SF\"");
+    std::vector<std::shared_ptr<AdpfConfig>> adpfs = HintManager::ParseAdpfConfigs(json_doc);
     EXPECT_EQ(0u, adpfs.size());
 }
 
 // Test parsing adpf configs without PID_Po
 TEST_F(HintManagerTest, ParseAdpfConfigsWithoutPIDPoTest) {
+    std::string json_doc = std::string(kJSON_ADPF);
     std::string from = "\"PID_Po\": 0,";
-    size_t start_pos = json_doc_.find(from);
-    json_doc_.replace(start_pos, from.length(), "");
-    std::vector<std::shared_ptr<AdpfConfig>> adpfs = HintManager::ParseAdpfConfigs(json_doc_);
+    size_t start_pos = json_doc.find(from);
+    json_doc.replace(start_pos, from.length(), "");
+    std::vector<std::shared_ptr<AdpfConfig>> adpfs = HintManager::ParseAdpfConfigs(json_doc);
     EXPECT_EQ(0u, adpfs.size());
 }
 
 // Test parsing adpf configs with partially missing heuristic boost config
 TEST_F(HintManagerTest, ParseAdpfConfigsWithBrokenHBoostConfig) {
-    std::string from = "\"HBoostUclampMin\": 800,";
-    size_t start_pos = json_doc_.find(from);
-    json_doc_.replace(start_pos, from.length(), "");
-    std::vector<std::shared_ptr<AdpfConfig>> adpfs = HintManager::ParseAdpfConfigs(json_doc_);
+    std::string json_doc = std::string(kJSON_ADPF);
+    std::string from = "\"JankCheckTimeFactor\": 1.2";
+    size_t start_pos = json_doc.find(from);
+    json_doc.replace(start_pos, from.length(), "");
+    std::vector<std::shared_ptr<AdpfConfig>> adpfs = HintManager::ParseAdpfConfigs(json_doc);
     EXPECT_EQ(0u, adpfs.size());
 }
 
 // Test hint/cancel/expire with json config
 TEST_F(HintManagerTest, GetFromJSONAdpfConfigTest) {
     TemporaryFile json_file;
-    ASSERT_TRUE(android::base::WriteStringToFile(json_doc_, json_file.path)) << strerror(errno);
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
     HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
     EXPECT_NE(nullptr, hm);
     EXPECT_TRUE(hm->Start());
     EXPECT_TRUE(hm->IsRunning());
 
     // Get default Adpf Profile
-    EXPECT_EQ("REFRESH_120FPS", hm->GetAdpfProfile()->mName);
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile()->mName);
+    EXPECT_EQ("ADPF_SF", hm->GetAdpfProfile("SURFACEFLINGER")->mName);
 
     // Set specific Adpf Profile
-    EXPECT_FALSE(hm->SetAdpfProfile("NoSuchProfile"));
-    EXPECT_TRUE(hm->SetAdpfProfile("REFRESH_60FPS"));
-    EXPECT_EQ("REFRESH_60FPS", hm->GetAdpfProfile()->mName);
-    EXPECT_TRUE(hm->SetAdpfProfile("REFRESH_120FPS"));
-    EXPECT_EQ("REFRESH_120FPS", hm->GetAdpfProfile()->mName);
+    EXPECT_FALSE(hm->SetAdpfProfile("OTHER", "NoSuchProfile"));
+    // Test SF_PLAYING
+    EXPECT_TRUE(hm->SetAdpfProfile("SURFACEFLINGER", "SF_VIDEO_30FPS"));
+    EXPECT_EQ("SF_VIDEO_30FPS", hm->GetAdpfProfile("SURFACEFLINGER")->mName);
+    // Test SF_RESET
+    EXPECT_TRUE(hm->SetAdpfProfile("SURFACEFLINGER", "ADPF_SF"));
+    EXPECT_EQ("ADPF_SF", hm->GetAdpfProfile("SURFACEFLINGER")->mName);
 }
 
 TEST_F(HintManagerTest, IsAdpfProfileSupported) {
     TemporaryFile json_file;
-    ASSERT_TRUE(android::base::WriteStringToFile(json_doc_, json_file.path)) << strerror(errno);
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
     HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
     EXPECT_NE(nullptr, hm);
 
     // Check if given AdpfProfile supported
     EXPECT_FALSE(hm->IsAdpfProfileSupported("NoSuchProfile"));
-    EXPECT_TRUE(hm->IsAdpfProfileSupported("REFRESH_60FPS"));
-    EXPECT_TRUE(hm->IsAdpfProfileSupported("REFRESH_120FPS"));
+    EXPECT_TRUE(hm->IsAdpfProfileSupported("ADPF_DEFAULT"));
+    EXPECT_TRUE(hm->IsAdpfProfileSupported("ADPF_SF"));
+}
+
+TEST_F(HintManagerTest, IsAdpfSupported) {
+    TemporaryFile json_file;
+    // Use json with AdpfConfig
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
+    HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
+    EXPECT_NE(nullptr, hm);
+    EXPECT_TRUE(hm->IsAdpfSupported());
+
+    // Use a json doc without AdpfConfig
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_RAW, json_file.path)) << strerror(errno);
+    hm = HintManager::GetFromJSON(json_file.path, false);
+    EXPECT_NE(nullptr, hm);
+    EXPECT_FALSE(hm->IsAdpfSupported());
+}
+
+TEST_F(HintManagerTest, GetAdpfProfile) {
+    TemporaryFile json_file;
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
+    HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
+    EXPECT_NE(nullptr, hm);
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile()->mName);
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile("OTHER")->mName);
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile("HWUI")->mName);
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile("APP")->mName);
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile("GAME")->mName);
+    EXPECT_EQ("ADPF_SF", hm->GetAdpfProfile("SURFACEFLINGER")->mName);
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile("NoSuchTag")->mName);
+}
+
+TEST_F(HintManagerTest, SetAdpfProfile) {
+    TemporaryFile json_file;
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
+    HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
+    EXPECT_NE(nullptr, hm);
+    EXPECT_TRUE(hm->SetAdpfProfile("OTHER", "ADPF_DEFAULT"));
+    EXPECT_FALSE(hm->SetAdpfProfile("OTHER", "NoSuchProfile"));
+    EXPECT_FALSE(hm->SetAdpfProfile("NoSuchTag", "ADPF_DEFAULT"));
+    EXPECT_TRUE(hm->SetAdpfProfile("OTHER", "ADPF_SF"));
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile("ADPF_SF")->mName);
+    EXPECT_TRUE(hm->SetAdpfProfile("OTHER", "SF_VIDEO_30FPS"));
+    EXPECT_EQ("SF_VIDEO_30FPS", hm->GetAdpfProfile("OTHER")->mName);
+}
+
+TEST_F(HintManagerTest, DoHintForEventNode) {
+    TemporaryFile json_file;
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
+    HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
+    EXPECT_NE(nullptr, hm);
+    EXPECT_TRUE(hm->Start());
+    EXPECT_TRUE(hm->IsRunning());
+    EXPECT_EQ("ADPF_SF", hm->GetAdpfProfile("SURFACEFLINGER")->mName);
+    hm->DoHint("SF_RESET");
+    std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile("SURFACEFLINGER")->mName);
+}
+
+TEST_F(HintManagerTest, RegisterAdpfUpdateEventAndUnregister) {
+    TemporaryFile json_file;
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
+    HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
+    EXPECT_NE(nullptr, hm);
+    EXPECT_TRUE(hm->Start());
+    EXPECT_TRUE(hm->IsRunning());
+    int count = 0;
+    std::string name;
+    AdpfCallback callback = [&](std::shared_ptr<AdpfConfig> profile) {
+        count++;
+        name = profile->mName;
+    };
+    // the callback should be invoked by DoHint().
+    hm->RegisterAdpfUpdateEvent("SURFACEFLINGER", &callback);
+    hm->DoHint("SF_RESET");
+    std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
+    EXPECT_EQ(1, count);
+    EXPECT_EQ("ADPF_DEFAULT", name);
+
+    // Unregister and DoHint('SF_PLAYING'). the callback shouldn't be called.
+    hm->UnregisterAdpfUpdateEvent("SURFACEFLINGER", &callback);
+    hm->EndHint("SF_RESET");
+    hm->DoHint("SF_PLAYING");
+    std::this_thread::sleep_for(kSLEEP_TOLERANCE_MS);
+    EXPECT_EQ("ADPF_SF", hm->GetAdpfProfile("SURFACEFLINGER")->mName);
+    EXPECT_EQ(1, count);
+    EXPECT_EQ("ADPF_DEFAULT", name);
+}
+
+TEST_F(HintManagerTest, GetAdpfProfileFromDoHint) {
+    TemporaryFile json_file;
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
+    HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
+    EXPECT_NE(nullptr, hm);
+    // Check the default profile is at index:0.
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfileFromDoHint()->mName);
+    // Make sure that SetAdpfProfile wouldn't impact GetAdpfProfileFromDoHint().
+    EXPECT_TRUE(hm->SetAdpfProfile("OTHER", "ADPF_SF"));
+    EXPECT_EQ("ADPF_SF", hm->GetAdpfProfile("OTHER")->mName);
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfileFromDoHint()->mName);
+}
+
+TEST_F(HintManagerTest, SetAdpfProfileFromDoHint) {
+    TemporaryFile json_file;
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
+    HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
+    EXPECT_NE(nullptr, hm);
+    // Check the default profile is at index:0.
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile("OTHER")->mName);
+    // Make sure that SetAdpfProfileFromDoHint wouldn't impact GetAdpfProfile().
+    EXPECT_TRUE(hm->SetAdpfProfileFromDoHint("ADPF_SF"));
+    EXPECT_EQ("ADPF_SF", hm->GetAdpfProfileFromDoHint()->mName);
+    EXPECT_EQ("ADPF_DEFAULT", hm->GetAdpfProfile("OTHER")->mName);
 }
 
 TEST_F(HintManagerTest, GpuConfigSupport) {
     TemporaryFile json_file;
-    ASSERT_TRUE(android::base::WriteStringToFile(json_doc_, json_file.path)) << strerror(errno);
+    ASSERT_TRUE(android::base::WriteStringToFile(kJSON_ADPF, json_file.path)) << strerror(errno);
     HintManager *hm = HintManager::GetFromJSON(json_file.path, false);
     ASSERT_TRUE(hm);
 
     EXPECT_THAT(hm->gpu_sysfs_config_path(), Optional(Eq("/sys/devices/platform/123.abc")));
-    ASSERT_TRUE(hm->SetAdpfProfile("REFRESH_120FPS"));
+    ASSERT_TRUE(hm->SetAdpfProfile("OTHER", "ADPF_DEFAULT"));
     auto profile = hm->GetAdpfProfile();
     EXPECT_THAT(profile->mGpuBoostOn, Optional(true));
-    EXPECT_THAT(profile->mGpuBoostCapacityMax, Optional(300000));
+    EXPECT_THAT(profile->mGpuBoostCapacityMax, Optional(325000));
     EXPECT_EQ(profile->mGpuCapacityLoadUpHeadroom, 1000);
 
-    ASSERT_TRUE(hm->SetAdpfProfile("REFRESH_60FPS"));
+    ASSERT_TRUE(hm->SetAdpfProfile("OTHER", "ADPF_SF"));
     profile = hm->GetAdpfProfile();
     EXPECT_FALSE(profile->mGpuBoostOn);
     EXPECT_FALSE(profile->mGpuBoostCapacityMax);
diff --git a/power-libperfmgr/libperfmgr/tests/NodeLooperThreadTest.cc b/power-libperfmgr/libperfmgr/tests/NodeLooperThreadTest.cc
index c2aa82b7..8deccd4a 100644
--- a/power-libperfmgr/libperfmgr/tests/NodeLooperThreadTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/NodeLooperThreadTest.cc
@@ -10,7 +10,7 @@
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specic language governing permissions and
+ * See the License for the specific language governing permissions and
  * limitations under the License.
  */
 
diff --git a/power-libperfmgr/libperfmgr/tests/PropertyNodeTest.cc b/power-libperfmgr/libperfmgr/tests/PropertyNodeTest.cc
index 17805032..5dd88a10 100644
--- a/power-libperfmgr/libperfmgr/tests/PropertyNodeTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/PropertyNodeTest.cc
@@ -10,7 +10,7 @@
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specic language governing permissions and
+ * See the License for the specific language governing permissions and
  * limitations under the License.
  */
 
diff --git a/power-libperfmgr/libperfmgr/tests/RequestGroupTest.cc b/power-libperfmgr/libperfmgr/tests/RequestGroupTest.cc
index c23c8211..47750d4f 100644
--- a/power-libperfmgr/libperfmgr/tests/RequestGroupTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/RequestGroupTest.cc
@@ -10,7 +10,7 @@
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specic language governing permissions and
+ * See the License for the specific language governing permissions and
  * limitations under the License.
  */
 
diff --git a/powerstats/PowerStatsAidl.cpp b/powerstats/PowerStatsAidl.cpp
index 455b26c9..bd7ba36b 100644
--- a/powerstats/PowerStatsAidl.cpp
+++ b/powerstats/PowerStatsAidl.cpp
@@ -285,16 +285,16 @@ void PowerStats::dumpStateResidency(std::ostringstream &oss, bool delta) {
     const char *dataFormatDelta = "  %16s   %18s   %13" PRIu64 " ms (%14" PRId64 ")   %15" PRIu64
                                   " (%16" PRId64 ")   %14" PRIu64 " ms (%14" PRId64 ")\n";
 
-    // Construct maps to entity and state names
-    std::unordered_map<int32_t, std::string> entityNames;
-    std::unordered_map<int32_t, std::unordered_map<int32_t, std::string>> stateNames;
-    getEntityStateNames(&entityNames, &stateNames);
-
     oss << "\n============= PowerStats HAL 2.0 state residencies ==============\n";
 
     std::vector<StateResidencyResult> results;
     getStateResidency({}, &results);
 
+    // Construct maps to entity and state names
+    std::unordered_map<int32_t, std::string> entityNames;
+    std::unordered_map<int32_t, std::unordered_map<int32_t, std::string>> stateNames;
+    getEntityStateNames(&entityNames, &stateNames);
+
     if (delta) {
         static std::vector<StateResidencyResult> prevResults;
         ::android::base::boot_clock::time_point curTime = ::android::base::boot_clock::now();
diff --git a/powerstats/dataproviders/IioEnergyMeterDataProvider.cpp b/powerstats/dataproviders/IioEnergyMeterDataProvider.cpp
index a249b01a..d999f248 100644
--- a/powerstats/dataproviders/IioEnergyMeterDataProvider.cpp
+++ b/powerstats/dataproviders/IioEnergyMeterDataProvider.cpp
@@ -105,8 +105,8 @@ void IioEnergyMeterDataProvider::parseEnabledRails() {
     }
 }
 
-IioEnergyMeterDataProvider::IioEnergyMeterDataProvider(
-        const std::vector<const std::string> &deviceNames, const bool useSelector)
+IioEnergyMeterDataProvider::IioEnergyMeterDataProvider(const std::vector<std::string> &deviceNames,
+                                                       const bool useSelector)
     : kDeviceNames(std::move(deviceNames)) {
     findIioEnergyMeterNodes();
     if (useSelector) {
diff --git a/powerstats/include/dataproviders/IioEnergyMeterDataProvider.h b/powerstats/include/dataproviders/IioEnergyMeterDataProvider.h
index 2f202c54..542cf4d1 100644
--- a/powerstats/include/dataproviders/IioEnergyMeterDataProvider.h
+++ b/powerstats/include/dataproviders/IioEnergyMeterDataProvider.h
@@ -28,7 +28,7 @@ namespace stats {
 
 class IioEnergyMeterDataProvider : public PowerStats::IEnergyMeterDataProvider {
   public:
-    IioEnergyMeterDataProvider(const std::vector<const std::string> &deviceNames,
+    IioEnergyMeterDataProvider(const std::vector<std::string> &deviceNames,
                                const bool useSelector = false);
 
     // Methods from PowerStats::IRailEnergyDataProvider
@@ -48,7 +48,7 @@ class IioEnergyMeterDataProvider : public PowerStats::IEnergyMeterDataProvider {
     std::vector<Channel> mChannelInfos;
     std::vector<EnergyMeasurement> mReading;
 
-    const std::vector<const std::string> kDeviceNames;
+    const std::vector<std::string> kDeviceNames;
     const std::string kDeviceType = "iio:device";
     const std::string kIioRootDir = "/sys/bus/iio/devices/";
     const std::string kNameNode = "/name";
diff --git a/powerstats/include/dataproviders/IioEnergyMeterDataSelector.h b/powerstats/include/dataproviders/IioEnergyMeterDataSelector.h
index 37d83407..0c72151e 100644
--- a/powerstats/include/dataproviders/IioEnergyMeterDataSelector.h
+++ b/powerstats/include/dataproviders/IioEnergyMeterDataSelector.h
@@ -48,7 +48,7 @@ class IioEnergyMeterDataSelector {
     const std::string kSelectionComplete = "CONFIG_COMPLETE";
 
     /* Order matters (ascending priority), see applyConfigsByAscendingPriority() */
-    const std::vector<const std::string> kConfigPaths = {
+    const std::vector<std::string> kConfigPaths = {
             "/data/vendor/powerstats/odpm_config",
     };
 };
diff --git a/radio/gril_carrier_nv_headers/inc/gril_carrier_nv.h b/radio/gril_carrier_nv_headers/inc/gril_carrier_nv.h
index 698d4307..57b851f0 100644
--- a/radio/gril_carrier_nv_headers/inc/gril_carrier_nv.h
+++ b/radio/gril_carrier_nv_headers/inc/gril_carrier_nv.h
@@ -93,6 +93,7 @@ typedef enum {
     GRIL_CARRIER_CSPIRE = 0x59,
     GRIL_CARRIER_CBRS = 0x64,
     GRIL_CARRIER_PLUS_PL = 0xB0,
+    GRIL_CARRIER_DNA_FI = 0xB2,
     GRIL_CARRIER_CRICKET_5G = 0xE2,
     GRIL_CARRIER_USCC_FI = 0xFB,
     GRIL_CARRIER_SPRINT_FI = 0xFC,
diff --git a/recovery/Android.bp b/recovery/Android.bp
index cd3526b2..0adc6c37 100644
--- a/recovery/Android.bp
+++ b/recovery/Android.bp
@@ -49,5 +49,6 @@ cc_library_static {
     shared_libs: [
         "libbase",
         "librecovery_ui",
+        "libboot_control_client",
     ],
 }
diff --git a/recovery/recovery_watch_ui.cpp b/recovery/recovery_watch_ui.cpp
index 2fe0a465..b6e72752 100644
--- a/recovery/recovery_watch_ui.cpp
+++ b/recovery/recovery_watch_ui.cpp
@@ -14,7 +14,14 @@
  * limitations under the License.
  */
 
+#include <BootControlClient.h>
+#include <android-base/endian.h>
+#include <android-base/logging.h>
+#include <android-base/strings.h>
 #include <dlfcn.h>
+#include <misc_writer/misc_writer.h>
+#include <recovery_ui/device.h>
+#include <recovery_ui/wear_ui.h>
 #include <stdint.h>
 #include <string.h>
 
@@ -22,13 +29,6 @@
 #include <string_view>
 #include <vector>
 
-#include <android-base/endian.h>
-#include <android-base/logging.h>
-#include <android-base/strings.h>
-#include <misc_writer/misc_writer.h>
-#include <recovery_ui/device.h>
-#include <recovery_ui/wear_ui.h>
-
 namespace android {
 namespace hardware {
 namespace google {
@@ -67,6 +67,24 @@ class PixelWatchDevice : public ::Device {
   public:
     explicit PixelWatchDevice(::WearRecoveryUI* const ui) : ::Device(ui) {}
 
+    bool PreWipeData() override {
+        uint32_t currentSlot = 0;
+        const auto module = android::hal::BootControlClient::WaitForService();
+        if (module == nullptr) {
+            LOG(ERROR) << "Error getting bootctrl module, slot attributes not reset";
+        } else {
+            // Reset current slot attributes
+            currentSlot = module->GetCurrentSlot();
+            LOG(INFO) << "Slot attributes reset for slot " << currentSlot;
+            const auto result = module->SetActiveBootSlot(currentSlot);
+            if (!result.IsOk()) {
+                LOG(ERROR) << "Unable to call SetActiveBootSlot for slot " << currentSlot;
+            }
+        }
+
+        // Loogging errors is sufficient, we don't want to block Wipe Data on this.
+        return true;
+    }
     /** Hook to wipe user data not stored in /data */
     bool PostWipeData() override {
         // Try to do everything but report a failure if anything wasn't successful
diff --git a/thermal/Thermal.cpp b/thermal/Thermal.cpp
index b71fd278..ef977b27 100644
--- a/thermal/Thermal.cpp
+++ b/thermal/Thermal.cpp
@@ -397,9 +397,14 @@ void Thermal::dumpThrottlingInfo(std::ostringstream *dump_buf) {
                     *dump_buf << name_info_pair.second.throttling_info->k_pu[i] << " ";
                 }
                 *dump_buf << "]" << std::endl;
-                *dump_buf << "   K_i: [";
+                *dump_buf << "   K_io: [";
                 for (size_t i = 0; i < kThrottlingSeverityCount; ++i) {
-                    *dump_buf << name_info_pair.second.throttling_info->k_i[i] << " ";
+                    *dump_buf << name_info_pair.second.throttling_info->k_io[i] << " ";
+                }
+                *dump_buf << "]" << std::endl;
+                *dump_buf << "   K_iu: [";
+                for (size_t i = 0; i < kThrottlingSeverityCount; ++i) {
+                    *dump_buf << name_info_pair.second.throttling_info->k_iu[i] << " ";
                 }
                 *dump_buf << "]" << std::endl;
                 *dump_buf << "   K_d: [";
@@ -738,7 +743,7 @@ void Thermal::dumpThermalData(int fd, const char **args, uint32_t numArgs) {
             dump_buf << "getCurrentTemperatures:" << std::endl;
             Temperature temp_2_0;
             for (const auto &name_info_pair : map) {
-                thermal_helper_->readTemperature(name_info_pair.first, &temp_2_0, nullptr, true);
+                thermal_helper_->readTemperature(name_info_pair.first, &temp_2_0, true);
                 dump_buf << " Type: " << toString(temp_2_0.type)
                          << " Name: " << name_info_pair.first << " CurrentValue: " << temp_2_0.value
                          << " ThrottlingStatus: " << toString(temp_2_0.throttlingStatus)
diff --git a/thermal/tests/mock_thermal_helper.h b/thermal/tests/mock_thermal_helper.h
index e5daa7f0..9ba6e7f3 100644
--- a/thermal/tests/mock_thermal_helper.h
+++ b/thermal/tests/mock_thermal_helper.h
@@ -38,9 +38,7 @@ class MockThermalHelper : public ThermalHelper {
     MOCK_METHOD(bool, emulSeverity, (std::string_view, const int, const bool), (override));
     MOCK_METHOD(bool, emulClear, (std::string_view), (override));
     MOCK_METHOD(bool, isInitializedOk, (), (const, override));
-    MOCK_METHOD(bool, readTemperature,
-                (std::string_view, Temperature *out,
-                 (std::pair<ThrottlingSeverity, ThrottlingSeverity> *), const bool),
+    MOCK_METHOD(bool, readTemperature, (std::string_view, Temperature *out, const bool),
                 (override));
     MOCK_METHOD(bool, readTemperatureThreshold, (std::string_view, TemperatureThreshold *),
                 (const, override));
diff --git a/thermal/thermal-helper.cpp b/thermal/thermal-helper.cpp
index 65d6f664..a7f878c6 100644
--- a/thermal/thermal-helper.cpp
+++ b/thermal/thermal-helper.cpp
@@ -153,11 +153,15 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
             ::android::base::GetBoolProperty(kThermalDisabledProperty.data(), false);
     bool ret = true;
     Json::Value config;
-    if (!ParseThermalConfig(config_path, &config)) {
+    std::unordered_set<std::string> loaded_config_paths;
+    if (!ParseThermalConfig(config_path, &config, &loaded_config_paths)) {
         LOG(ERROR) << "Failed to read JSON config";
         ret = false;
     }
 
+    const std::string &comment = config["Comment"].asString();
+    LOG(INFO) << "Comment: " << comment;
+
     if (!ParseCoolingDevice(config, &cooling_device_info_map_)) {
         LOG(ERROR) << "Failed to parse cooling device info config";
         ret = false;
@@ -199,6 +203,7 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
                 .prev_cold_severity = ThrottlingSeverity::NONE,
                 .last_update_time = boot_clock::time_point::min(),
                 .thermal_cached = {NAN, boot_clock::time_point::min()},
+                .pending_notification = false,
                 .override_status = {nullptr, false, false},
         };
 
@@ -268,6 +273,20 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
                     }
                 }
             }
+
+            // Check if the severity reference sensor is valid
+            if (name_status_pair.second.severity_reference != "") {
+                if (sensor_info_map_.contains(name_status_pair.second.severity_reference)) {
+                    sensor_info_map_[name_status_pair.second.severity_reference].is_watch = true;
+                    LOG(INFO) << "Enable is_watch for " << name_status_pair.first
+                              << "'s severity reference sensor: "
+                              << name_status_pair.second.severity_reference;
+                } else {
+                    LOG(ERROR) << name_status_pair.first << "'s severity reference sensor: "
+                               << name_status_pair.second.severity_reference << " is invalid";
+                    ret = false;
+                }
+            }
         }
         // Check predictor info config
         if (name_status_pair.second.predictor_info != nullptr) {
@@ -362,15 +381,14 @@ bool getThermalZoneTypeById(int tz_id, std::string *type) {
     std::string path =
             ::android::base::StringPrintf("%s/%s%d/%s", kThermalSensorsRoot.data(),
                                           kSensorPrefix.data(), tz_id, kThermalNameFile.data());
-    LOG(INFO) << "TZ Path: " << path;
     if (!::android::base::ReadFileToString(path, &tz_type)) {
-        LOG(ERROR) << "Failed to read sensor: " << tz_type;
+        LOG(ERROR) << "Failed to read sensor from: " << path;
         return false;
     }
 
     // Strip the newline.
     *type = ::android::base::Trim(tz_type);
-    LOG(INFO) << "TZ type: " << *type;
+    LOG(INFO) << "TZ path: " << path << " type: " << *type;
     return true;
 }
 
@@ -499,10 +517,8 @@ bool ThermalHelperImpl::readCoolingDevice(std::string_view cooling_device,
     return true;
 }
 
-bool ThermalHelperImpl::readTemperature(
-        std::string_view sensor_name, Temperature *out,
-        std::pair<ThrottlingSeverity, ThrottlingSeverity> *throttling_status,
-        const bool force_no_cache) {
+bool ThermalHelperImpl::readTemperature(std::string_view sensor_name, Temperature *out,
+                                        const bool force_no_cache) {
     // Return fail if the thermal sensor cannot be read.
     float temp = NAN;
     std::map<std::string, float> sensor_log_map;
@@ -519,6 +535,7 @@ bool ThermalHelperImpl::readTemperature(
         LOG(INFO) << "Sensor " << sensor_name.data() << " temperature is nan.";
         return false;
     }
+    const auto severity_reference = getSeverityReference(sensor_name.data());
 
     const auto &sensor_info = sensor_info_map_.at(sensor_name.data());
     out->type = sensor_info.type;
@@ -527,44 +544,60 @@ bool ThermalHelperImpl::readTemperature(
 
     std::pair<ThrottlingSeverity, ThrottlingSeverity> status =
             std::make_pair(ThrottlingSeverity::NONE, ThrottlingSeverity::NONE);
+
     // Only update status if the thermal sensor is being monitored
-    if (sensor_info.is_watch) {
-        ThrottlingSeverity prev_hot_severity, prev_cold_severity;
-        {
-            // reader lock, readTemperature will be called in Binder call and the watcher thread.
-            std::shared_lock<std::shared_mutex> _lock(sensor_status_map_mutex_);
-            prev_hot_severity = sensor_status.prev_hot_severity;
-            prev_cold_severity = sensor_status.prev_cold_severity;
-        }
+    if (!sensor_info.is_watch) {
+        return true;
+    }
+    ThrottlingSeverity prev_hot_severity, prev_cold_severity;
+    {
+        std::unique_lock<std::shared_mutex> _lock(sensor_status_map_mutex_);
+        prev_hot_severity = sensor_status.prev_hot_severity;
+        prev_cold_severity = sensor_status.prev_cold_severity;
         status = getSeverityFromThresholds(sensor_info.hot_thresholds, sensor_info.cold_thresholds,
                                            sensor_info.hot_hysteresis, sensor_info.cold_hysteresis,
                                            prev_hot_severity, prev_cold_severity, out->value);
-    }
-
-    if (throttling_status) {
-        *throttling_status = status;
-    }
 
-    if (sensor_status.override_status.emul_temp != nullptr &&
-        sensor_status.override_status.emul_temp->severity >= 0) {
-        std::shared_lock<std::shared_mutex> _lock(sensor_status_map_mutex_);
-        out->throttlingStatus =
-                static_cast<ThrottlingSeverity>(sensor_status.override_status.emul_temp->severity);
-    } else {
         out->throttlingStatus =
                 static_cast<size_t>(status.first) > static_cast<size_t>(status.second)
                         ? status.first
                         : status.second;
-    }
-    if (sensor_info.is_watch) {
-        std::ostringstream sensor_log;
-        for (const auto &sensor_log_pair : sensor_log_map) {
-            sensor_log << sensor_log_pair.first << ":" << sensor_log_pair.second << " ";
+
+        if (status.first != sensor_status.prev_hot_severity) {
+            sensor_status.prev_hot_severity = status.first;
+        }
+        if (status.second != sensor_status.prev_cold_severity) {
+            sensor_status.prev_cold_severity = status.second;
+        }
+
+        out->throttlingStatus = std::max(out->throttlingStatus, severity_reference);
+
+        if (sensor_status.override_status.emul_temp != nullptr &&
+            sensor_status.override_status.emul_temp->severity >= 0) {
+            out->throttlingStatus = static_cast<ThrottlingSeverity>(
+                    sensor_status.override_status.emul_temp->severity);
         }
-        // Update sensor temperature time in state
-        thermal_stats_helper_.updateSensorTempStatsBySeverity(sensor_name, out->throttlingStatus);
+
+        if (sensor_status.severity != out->throttlingStatus) {
+            sensor_status.severity = out->throttlingStatus;
+            sensor_status.pending_notification = true;
+        }
+    }
+
+    std::ostringstream sensor_log;
+    for (const auto &sensor_log_pair : sensor_log_map) {
+        sensor_log << sensor_log_pair.first << ":" << sensor_log_pair.second << " ";
+    }
+    // Update sensor temperature time in state
+    thermal_stats_helper_.updateSensorTempStatsBySeverity(sensor_name, out->throttlingStatus);
+    if (out->throttlingStatus >= sensor_info.log_level) {
         LOG(INFO) << sensor_name.data() << ":" << out->value << " raw data: " << sensor_log.str();
+    } else {
+        LOG(VERBOSE) << sensor_name.data() << ":" << out->value
+                     << " raw data: " << sensor_log.str();
     }
+    ATRACE_INT((sensor_name.data() + std::string("-severity")).c_str(),
+               static_cast<int>(out->throttlingStatus));
 
     return true;
 }
@@ -750,23 +783,31 @@ bool ThermalHelperImpl::initializeCoolingDevices(
             return false;
         }
 
-        std::string state2power_path = ::android::base::StringPrintf(
-                "%s/%s", path.data(), kCoolingDeviceState2powerSuffix.data());
-        std::string state2power_str;
-        if (::android::base::ReadFileToString(state2power_path, &state2power_str)) {
-            LOG(INFO) << "Cooling device " << cooling_device_info_pair.first
-                      << " use state2power read from sysfs";
-            cooling_device_info_pair.second.state2power.clear();
-
-            std::stringstream power(state2power_str);
-            unsigned int power_number;
-            int i = 0;
-            while (power >> power_number) {
-                cooling_device_info_pair.second.state2power.push_back(
-                        static_cast<float>(power_number));
-                LOG(INFO) << "Cooling device " << cooling_device_info_pair.first << " state:" << i
-                          << " power: " << power_number;
-                i++;
+        // Get cooling device state2power table from sysfs if not defined in config
+        if (!cooling_device_info_pair.second.state2power.size()) {
+            std::string state2power_path = ::android::base::StringPrintf(
+                    "%s/%s", path.data(), kCoolingDeviceState2powerSuffix.data());
+            std::string state2power_str;
+            if (::android::base::ReadFileToString(state2power_path, &state2power_str)) {
+                LOG(INFO) << "Cooling device " << cooling_device_info_pair.first
+                          << " use State2power read from sysfs";
+                std::stringstream power(state2power_str);
+                unsigned int power_number;
+                while (power >> power_number) {
+                    cooling_device_info_pair.second.state2power.push_back(
+                            static_cast<float>(power_number));
+                }
+            }
+        }
+
+        // Check if there's any wrong ordered state2power value to avoid cdev stuck issue
+        for (size_t i = 0; i < cooling_device_info_pair.second.state2power.size(); ++i) {
+            LOG(INFO) << "Cooling device " << cooling_device_info_pair.first << " state:" << i
+                      << " power: " << cooling_device_info_pair.second.state2power[i];
+            if (i > 0 && cooling_device_info_pair.second.state2power[i] >
+                                 cooling_device_info_pair.second.state2power[i - 1]) {
+                LOG(ERROR) << "Higher power with higher state on cooling device "
+                           << cooling_device_info_pair.first << "'s state" << i;
             }
         }
 
@@ -910,7 +951,7 @@ bool ThermalHelperImpl::fillCurrentTemperatures(bool filterType, bool filterCall
         if (filterCallback && !name_info_pair.second.send_cb) {
             continue;
         }
-        if (readTemperature(name_info_pair.first, &temp, nullptr, false)) {
+        if (readTemperature(name_info_pair.first, &temp, false)) {
             ret.emplace_back(std::move(temp));
         } else {
             LOG(ERROR) << __func__
@@ -964,6 +1005,25 @@ bool ThermalHelperImpl::fillCurrentCoolingDevices(
     return ret.size() > 0;
 }
 
+ThrottlingSeverity ThermalHelperImpl::getSeverityReference(std::string_view sensor_name) {
+    if (!sensor_info_map_.contains(sensor_name.data())) {
+        return ThrottlingSeverity::NONE;
+    }
+    const std::string &severity_reference =
+            sensor_info_map_.at(sensor_name.data()).severity_reference;
+    if (severity_reference == "") {
+        return ThrottlingSeverity::NONE;
+    }
+
+    Temperature temp;
+    if (!readTemperature(severity_reference, &temp, false)) {
+        return ThrottlingSeverity::NONE;
+    }
+    LOG(VERBOSE) << sensor_name << "'s severity reference " << severity_reference
+                 << " reading:" << toString(temp.throttlingStatus);
+    return temp.throttlingStatus;
+}
+
 bool ThermalHelperImpl::readDataByType(std::string_view sensor_data, float *reading_value,
                                        const SensorFusionType type, const bool force_no_cache,
                                        std::map<std::string, float> *sensor_log_map) {
@@ -986,6 +1046,15 @@ bool ThermalHelperImpl::readDataByType(std::string_view sensor_data, float *read
         case SensorFusionType::CONSTANT:
             *reading_value = std::atof(sensor_data.data());
             break;
+        case SensorFusionType::CDEV:
+            int max_state;
+            if (thermal_throttling_.getCdevMaxRequest(sensor_data.data(), &max_state)) {
+                *reading_value = max_state;
+                break;
+            } else {
+                return false;
+            }
+            break;
         default:
             break;
     }
@@ -1322,21 +1391,30 @@ bool ThermalHelperImpl::readThermalSensor(std::string_view sensor_name, float *t
 }
 
 // This is called in the different thread context and will update sensor_status
-// uevent_sensors is the set of sensors which trigger uevent from thermal core driver.
+// uevent_sensors_map maps sensor which trigger uevent from thermal core driver to the temperature
+// read from uevent.
 std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
-        const std::set<std::string> &uevent_sensors) {
+        const std::unordered_map<std::string, float> &uevent_sensor_map) {
     std::vector<Temperature> temps;
     std::vector<std::string> cooling_devices_to_update;
     boot_clock::time_point now = boot_clock::now();
     auto min_sleep_ms = std::chrono::milliseconds::max();
     bool power_data_is_updated = false;
 
+    for (const auto &[sensor, temp] : uevent_sensor_map) {
+        if (!std::isnan(temp)) {
+            std::unique_lock<std::shared_mutex> _lock(sensor_status_map_mutex_);
+            sensor_status_map_[sensor].thermal_cached.temp = temp;
+            sensor_status_map_[sensor].thermal_cached.timestamp = now;
+        }
+    }
+
     ATRACE_CALL();
+    // Go through all virtual and physical sensor and update if needed
     for (auto &name_status_pair : sensor_status_map_) {
         bool force_update = false;
         bool force_no_cache = false;
         Temperature temp;
-        TemperatureThreshold threshold;
         SensorStatus &sensor_status = name_status_pair.second;
         const SensorInfo &sensor_info = sensor_info_map_.at(name_status_pair.first);
         bool max_throttling = false;
@@ -1366,28 +1444,38 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
                 }
             }
         }
-        // Check if the sensor need to be updated
+        // Force update if it's first time we update temperature value after device boot
         if (sensor_status.last_update_time == boot_clock::time_point::min()) {
             force_update = true;
+
         } else {
+            // Handle other update event
             time_elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     now - sensor_status.last_update_time);
-            if (uevent_sensors.size()) {
+            // Update triggered from genlink or uevent
+            if (uevent_sensor_map.size()) {
+                // Checking virtual sensor
                 if (sensor_info.virtual_sensor_info != nullptr) {
                     for (size_t i = 0; i < sensor_info.virtual_sensor_info->trigger_sensors.size();
                          i++) {
-                        if (uevent_sensors.find(
+                        if (uevent_sensor_map.find(
                                     sensor_info.virtual_sensor_info->trigger_sensors[i]) !=
-                            uevent_sensors.end()) {
+                            uevent_sensor_map.end()) {
                             force_update = true;
                             break;
                         }
                     }
-                } else if (uevent_sensors.find(name_status_pair.first) != uevent_sensors.end()) {
+                } else if (uevent_sensor_map.find(name_status_pair.first) !=
+                           uevent_sensor_map.end()) {
+                    // Checking physical sensor
                     force_update = true;
-                    force_no_cache = true;
+                    if (std::isnan(uevent_sensor_map.at(name_status_pair.first))) {
+                        // Handle the case that uevent does not contain temperature
+                        force_no_cache = true;
+                    }
                 }
             } else if (time_elapsed_ms > sleep_ms) {
+                // Update triggered from normal polling cylce
                 force_update = true;
             }
         }
@@ -1415,32 +1503,20 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
         }
 
         std::pair<ThrottlingSeverity, ThrottlingSeverity> throttling_status;
-        if (!readTemperature(name_status_pair.first, &temp, &throttling_status, force_no_cache)) {
+        if (!readTemperature(name_status_pair.first, &temp, force_no_cache)) {
             LOG(ERROR) << __func__
                        << ": error reading temperature for sensor: " << name_status_pair.first;
             continue;
         }
-        if (!readTemperatureThreshold(name_status_pair.first, &threshold)) {
-            LOG(ERROR) << __func__ << ": error reading temperature threshold for sensor: "
-                       << name_status_pair.first;
-            continue;
-        }
 
         {
-            // writer lock
             std::unique_lock<std::shared_mutex> _lock(sensor_status_map_mutex_);
-            if (throttling_status.first != sensor_status.prev_hot_severity) {
-                sensor_status.prev_hot_severity = throttling_status.first;
-            }
-            if (throttling_status.second != sensor_status.prev_cold_severity) {
-                sensor_status.prev_cold_severity = throttling_status.second;
-            }
-            if (temp.throttlingStatus != sensor_status.severity) {
+            if (sensor_status.pending_notification) {
                 temps.push_back(temp);
-                sensor_status.severity = temp.throttlingStatus;
                 sleep_ms = (sensor_status.severity != ThrottlingSeverity::NONE)
                                    ? sensor_info.passive_delay
                                    : sensor_info.polling_delay;
+                sensor_status.pending_notification = false;
             }
         }
 
@@ -1481,10 +1557,6 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
         sensor_status.last_update_time = now;
     }
 
-    if (!cooling_devices_to_update.empty()) {
-        updateCoolingDevices(cooling_devices_to_update);
-    }
-
     if (!temps.empty()) {
         for (const auto &t : temps) {
             if (sensor_info_map_.at(t.name).send_cb && cb_) {
@@ -1497,6 +1569,10 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
         }
     }
 
+    if (!cooling_devices_to_update.empty()) {
+        updateCoolingDevices(cooling_devices_to_update);
+    }
+
     int count_failed_reporting = thermal_stats_helper_.reportStats();
     if (count_failed_reporting != 0) {
         LOG(ERROR) << "Failed to report " << count_failed_reporting << " thermal stats";
diff --git a/thermal/thermal-helper.h b/thermal/thermal-helper.h
index 7c9d2824..bd64505f 100644
--- a/thermal/thermal-helper.h
+++ b/thermal/thermal-helper.h
@@ -72,6 +72,7 @@ struct SensorStatus {
     ThrottlingSeverity prev_cold_severity;
     boot_clock::time_point last_update_time;
     ThermalSample thermal_cached;
+    bool pending_notification;
     OverrideStatus override_status;
 };
 
@@ -90,10 +91,8 @@ class ThermalHelper {
                               const bool max_throttling) = 0;
     virtual bool emulClear(std::string_view target_sensor) = 0;
     virtual bool isInitializedOk() const = 0;
-    virtual bool readTemperature(
-            std::string_view sensor_name, Temperature *out,
-            std::pair<ThrottlingSeverity, ThrottlingSeverity> *throtting_status = nullptr,
-            const bool force_sysfs = false) = 0;
+    virtual bool readTemperature(std::string_view sensor_name, Temperature *out,
+                                 const bool force_sysfs = false) = 0;
     virtual bool readTemperatureThreshold(std::string_view sensor_name,
                                           TemperatureThreshold *out) const = 0;
     virtual bool readCoolingDevice(std::string_view cooling_device, CoolingDevice *out) const = 0;
@@ -141,10 +140,8 @@ class ThermalHelperImpl : public ThermalHelper {
     bool isInitializedOk() const override { return is_initialized_; }
 
     // Read the temperature of a single sensor.
-    bool readTemperature(
-            std::string_view sensor_name, Temperature *out,
-            std::pair<ThrottlingSeverity, ThrottlingSeverity> *throtting_status = nullptr,
-            const bool force_sysfs = false) override;
+    bool readTemperature(std::string_view sensor_name, Temperature *out,
+                         const bool force_sysfs = false) override;
 
     bool readTemperatureThreshold(std::string_view sensor_name,
                                   TemperatureThreshold *out) const override;
@@ -205,7 +202,7 @@ class ThermalHelperImpl : public ThermalHelper {
     void clearAllThrottling();
     // For thermal_watcher_'s polling thread, return the sleep interval
     std::chrono::milliseconds thermalWatcherCallbackFunc(
-            const std::set<std::string> &uevent_sensors);
+            const std::unordered_map<std::string, float> &uevent_sensor_map);
     // Return hot and cold severity status as std::pair
     std::pair<ThrottlingSeverity, ThrottlingSeverity> getSeverityFromThresholds(
             const ThrottlingArray &hot_thresholds, const ThrottlingArray &cold_thresholds,
@@ -229,6 +226,8 @@ class ThermalHelperImpl : public ThermalHelper {
     void maxCoolingRequestCheck(
             std::unordered_map<std::string, BindedCdevInfo> *binded_cdev_info_map);
     void checkUpdateSensorForEmul(std::string_view target_sensor, const bool max_throttling);
+    ThrottlingSeverity getSeverityReference(std::string_view sensor_name);
+
     sp<ThermalWatcher> thermal_watcher_;
     PowerFiles power_files_;
     ThermalFiles thermal_sensors_;
diff --git a/thermal/utils/thermal_info.cpp b/thermal/utils/thermal_info.cpp
index 640da477..92ba07af 100644
--- a/thermal/utils/thermal_info.cpp
+++ b/thermal/utils/thermal_info.cpp
@@ -193,12 +193,14 @@ std::ostream &operator<<(std::ostream &stream, const SensorFusionType &sensor_fu
             return stream << "ODPM";
         case SensorFusionType::CONSTANT:
             return stream << "CONSTANT";
+        case SensorFusionType::CDEV:
+            return stream << "CDEV";
         default:
             return stream << "UNDEFINED";
     }
 }
 
-bool ParseThermalConfig(std::string_view config_path, Json::Value *config) {
+bool LoadThermalConfig(std::string_view config_path, Json::Value *config) {
     std::string json_doc;
     if (!::android::base::ReadFileToString(config_path.data(), &json_doc)) {
         LOG(ERROR) << "Failed to read JSON config from " << config_path;
@@ -214,6 +216,62 @@ bool ParseThermalConfig(std::string_view config_path, Json::Value *config) {
     return true;
 }
 
+void MergeConfigEntries(Json::Value *config, Json::Value *sub_config,
+                        std::string_view member_name) {
+    Json::Value &config_entries = (*config)[member_name.data()];
+    Json::Value &sub_config_entries = (*sub_config)[member_name.data()];
+    std::unordered_set<std::string> config_entries_set;
+
+    if (sub_config_entries.size() == 0) {
+        return;
+    }
+
+    for (Json::Value::ArrayIndex i = 0; i < config_entries.size(); i++) {
+        config_entries_set.insert(config_entries[i]["Name"].asString());
+    }
+
+    // Iterate through subconfig and add entries not found in main config
+    for (Json::Value::ArrayIndex i = 0; i < sub_config_entries.size(); ++i) {
+        if (config_entries_set.count(sub_config_entries[i]["Name"].asString()) == 0) {
+            config_entries.append(sub_config_entries[i]);
+        } else {
+            LOG(INFO) << "Base config entry " << sub_config_entries[i]["Name"].asString()
+                      << " is overwritten in main config";
+        }
+    }
+}
+
+bool ParseThermalConfig(std::string_view config_path, Json::Value *config,
+                        std::unordered_set<std::string> *loaded_config_paths) {
+    if (loaded_config_paths->count(config_path.data())) {
+        LOG(ERROR) << "Circular dependency detected in config " << config_path;
+        return false;
+    }
+
+    if (!LoadThermalConfig(config_path, config)) {
+        LOG(ERROR) << "Failed to read JSON config at " << config_path;
+        return false;
+    }
+
+    loaded_config_paths->insert(config_path.data());
+
+    Json::Value sub_configs_paths = (*config)["Include"];
+    for (Json::Value::ArrayIndex i = 0; i < sub_configs_paths.size(); ++i) {
+        const std::string sub_configs_path = "/vendor/etc/" + sub_configs_paths[i].asString();
+        Json::Value sub_config;
+
+        if (!ParseThermalConfig(sub_configs_path, &sub_config, loaded_config_paths)) {
+            return false;
+        }
+
+        MergeConfigEntries(config, &sub_config, "Sensors");
+        MergeConfigEntries(config, &sub_config, "CoolingDevices");
+        MergeConfigEntries(config, &sub_config, "PowerRails");
+    }
+
+    return true;
+}
+
 bool ParseOffsetThresholds(const std::string_view name, const Json::Value &sensor,
                            std::vector<float> *offset_thresholds,
                            std::vector<float> *offset_values) {
@@ -322,6 +380,8 @@ bool ParseVirtualSensorInfo(const std::string_view name, const Json::Value &sens
                 linked_sensors_type.emplace_back(SensorFusionType::ODPM);
             } else if (values[j].asString().compare("CONSTANT") == 0) {
                 linked_sensors_type.emplace_back(SensorFusionType::CONSTANT);
+            } else if (values[j].asString().compare("CDEV") == 0) {
+                linked_sensors_type.emplace_back(SensorFusionType::CDEV);
             } else {
                 LOG(ERROR) << "Sensor[" << name << "] has invalid CombinationType settings "
                            << values[j].asString();
@@ -833,8 +893,10 @@ bool ParseSensorThrottlingInfo(
     k_po.fill(0.0);
     std::array<float, kThrottlingSeverityCount> k_pu;
     k_pu.fill(0.0);
-    std::array<float, kThrottlingSeverityCount> k_i;
-    k_i.fill(0.0);
+    std::array<float, kThrottlingSeverityCount> k_io;
+    k_io.fill(0.0);
+    std::array<float, kThrottlingSeverityCount> k_iu;
+    k_iu.fill(0.0);
     std::array<float, kThrottlingSeverityCount> k_d;
     k_d.fill(0.0);
     std::array<float, kThrottlingSeverityCount> i_max;
@@ -869,13 +931,33 @@ bool ParseSensorThrottlingInfo(
             LOG(ERROR) << "Sensor[" << name << "]: Failed to parse K_Pu";
             return false;
         }
-        LOG(INFO) << "Start to parse"
-                  << " Sensor[" << name << "]'s K_I";
-        if (sensor["PIDInfo"]["K_I"].empty() ||
-            !getFloatFromJsonValues(sensor["PIDInfo"]["K_I"], &k_i, false, false)) {
-            LOG(ERROR) << "Sensor[" << name << "]: Failed to parse K_I";
+        if (!sensor["PIDInfo"]["K_I"].empty()) {
+            if (!sensor["PIDInfo"]["K_Io"].empty() || !sensor["PIDInfo"]["K_Iu"].empty()) {
+                LOG(ERROR) << "Sensor[" << name << "]: K_Io or K_Iu cannot coexist with K_I";
+                return false;
+            }
+            LOG(INFO) << "Start to parse" << " Sensor[" << name << "]'s K_I";
+            if (!getFloatFromJsonValues(sensor["PIDInfo"]["K_I"], &k_io, false, false) ||
+                !getFloatFromJsonValues(sensor["PIDInfo"]["K_I"], &k_iu, false, false)) {
+                LOG(ERROR) << "Sensor[" << name << "]: Failed to parse K_I";
+                return false;
+            }
+        } else if (!sensor["PIDInfo"]["K_Io"].empty() && !sensor["PIDInfo"]["K_Iu"].empty()) {
+            LOG(INFO) << "Start to parse" << " Sensor[" << name << "]'s K_Io";
+            if (!getFloatFromJsonValues(sensor["PIDInfo"]["K_Io"], &k_io, false, false)) {
+                LOG(ERROR) << "Sensor[" << name << "]: Failed to parse K_Io";
+                return false;
+            }
+            LOG(INFO) << "Start to parse" << " Sensor[" << name << "]'s K_Iu";
+            if (!getFloatFromJsonValues(sensor["PIDInfo"]["K_Iu"], &k_iu, false, false)) {
+                LOG(ERROR) << "Sensor[" << name << "]: Failed to parse K_Iu";
+                return false;
+            }
+        } else {
+            LOG(ERROR) << "Sensor[" << name << "]: No K_I related settings";
             return false;
         }
+
         LOG(INFO) << "Start to parse"
                   << " Sensor[" << name << "]'s K_D";
         if (sensor["PIDInfo"]["K_D"].empty() ||
@@ -939,9 +1021,10 @@ bool ParseSensorThrottlingInfo(
         bool valid_pid_combination = false;
         for (Json::Value::ArrayIndex j = 0; j < kThrottlingSeverityCount; ++j) {
             if (!std::isnan(s_power[j])) {
-                if (std::isnan(k_po[j]) || std::isnan(k_pu[j]) || std::isnan(k_i[j]) ||
-                    std::isnan(k_d[j]) || std::isnan(i_max[j]) || std::isnan(max_alloc_power[j]) ||
-                    std::isnan(min_alloc_power[j]) || std::isnan(i_cutoff[j])) {
+                if (std::isnan(k_po[j]) || std::isnan(k_pu[j]) || std::isnan(k_io[j]) ||
+                    std::isnan(k_iu[j]) || std::isnan(k_d[j]) || std::isnan(i_max[j]) ||
+                    std::isnan(max_alloc_power[j]) || std::isnan(min_alloc_power[j]) ||
+                    std::isnan(i_cutoff[j])) {
                     valid_pid_combination = false;
                     break;
                 } else {
@@ -1025,7 +1108,7 @@ bool ParseSensorThrottlingInfo(
         }
         excluded_power_info_map[power_rail] = power_weight;
     }
-    throttling_info->reset(new ThrottlingInfo{k_po, k_pu, k_i, k_d, i_max, max_alloc_power,
+    throttling_info->reset(new ThrottlingInfo{k_po, k_pu, k_io, k_iu, k_d, i_max, max_alloc_power,
                                               min_alloc_power, s_power, i_cutoff, i_default,
                                               i_default_pct, tran_cycle, excluded_power_info_map,
                                               binded_cdev_info_map, profile_map});
@@ -1041,12 +1124,14 @@ bool ParseSensorInfo(const Json::Value &config,
 
     LOG(INFO) << "Start reading ScalingAvailableFrequenciesPath from config";
     for (Json::Value::ArrayIndex i = 0; i < cdevs.size(); ++i) {
-        if (cdevs[i]["ScalingAvailableFrequenciesPath"].empty()) {
+        if (cdevs[i]["ScalingAvailableFrequenciesPath"].empty() ||
+            cdevs[i]["isDisabled"].asBool()) {
             continue;
         }
 
         const std::string &path = cdevs[i]["ScalingAvailableFrequenciesPath"].asString();
         const std::string &name = cdevs[i]["Name"].asString();
+
         LOG(INFO) << "Cdev[" << name << "]'s scaling frequency path: " << path;
         std::string scaling_frequency_str;
         if (::android::base::ReadFileToString(path, &scaling_frequency_str)) {
@@ -1090,6 +1175,11 @@ bool ParseSensorInfo(const Json::Value &config,
             return false;
         }
 
+        if (sensors[i]["isDisabled"].asBool()) {
+            LOG(INFO) << "sensors[" << name << "] is disabled. Skipping parsing";
+            continue;
+        }
+
         auto result = sensors_name_parsed.insert(name);
         if (!result.second) {
             LOG(ERROR) << "Duplicate Sensor[" << i << "]'s Name";
@@ -1134,6 +1224,17 @@ bool ParseSensorInfo(const Json::Value &config,
         LOG(INFO) << "Sensor[" << name << "]'s Hidden: " << std::boolalpha << is_hidden
                   << std::noboolalpha;
 
+        ThrottlingSeverity log_level = ThrottlingSeverity::NONE;
+        if (!sensors[i]["LogLevel"].empty()) {
+            const auto level = sensors[i]["LogLevel"].asInt();
+            if (level > static_cast<int>(ThrottlingSeverity::SHUTDOWN)) {
+                LOG(ERROR) << "Sensor[" << name << "]'s LogLevel is invalid";
+            } else {
+                log_level = static_cast<ThrottlingSeverity>(level);
+            }
+        }
+        LOG(INFO) << "Sensor[" << name << "]'s LogLevel: " << toString(log_level);
+
         std::array<float, kThrottlingSeverityCount> hot_thresholds;
         hot_thresholds.fill(NAN);
         std::array<float, kThrottlingSeverityCount> cold_thresholds;
@@ -1279,6 +1380,12 @@ bool ParseSensorInfo(const Json::Value &config,
             LOG(INFO) << "Sensor[" << name << "]'s TempPath: " << temp_path;
         }
 
+        std::string severity_reference;
+        if (!sensors[i]["SeverityReference"].empty()) {
+            severity_reference = sensors[i]["SeverityReference"].asString();
+            LOG(INFO) << "Sensor[" << name << "]'s SeverityReference: " << temp_path;
+        }
+
         float vr_threshold = NAN;
         if (!sensors[i]["VrThreshold"].empty()) {
             vr_threshold = getFloatFromValue(sensors[i]["VrThreshold"]);
@@ -1371,6 +1478,7 @@ bool ParseSensorInfo(const Json::Value &config,
                 .hot_hysteresis = hot_hysteresis,
                 .cold_hysteresis = cold_hysteresis,
                 .temp_path = temp_path,
+                .severity_reference = severity_reference,
                 .vr_threshold = vr_threshold,
                 .multiplier = multiplier,
                 .polling_delay = polling_delay,
@@ -1381,6 +1489,7 @@ bool ParseSensorInfo(const Json::Value &config,
                 .send_powerhint = send_powerhint,
                 .is_watch = is_watch,
                 .is_hidden = is_hidden,
+                .log_level = log_level,
                 .virtual_sensor_info = std::move(virtual_sensor_info),
                 .throttling_info = std::move(throttling_info),
                 .predictor_info = std::move(predictor_info),
@@ -1407,6 +1516,11 @@ bool ParseCoolingDevice(const Json::Value &config,
             return false;
         }
 
+        if (cooling_devices[i]["isDisabled"].asBool()) {
+            LOG(INFO) << "CoolingDevice[" << name << "] is disabled. Skipping parsing";
+            continue;
+        }
+
         auto result = cooling_devices_name_parsed.insert(name.data());
         if (!result.second) {
             LOG(ERROR) << "Duplicate CoolingDevice[" << i << "]'s Name";
@@ -1434,19 +1548,14 @@ bool ParseCoolingDevice(const Json::Value &config,
         std::vector<float> state2power;
         Json::Value values = cooling_devices[i]["State2Power"];
         if (values.size()) {
+            LOG(INFO) << "Cooling device " << name << " use State2power read from config";
             state2power.reserve(values.size());
             for (Json::Value::ArrayIndex j = 0; j < values.size(); ++j) {
                 state2power.emplace_back(getFloatFromValue(values[j]));
-                LOG(INFO) << "Cooling device[" << name << "]'s Power2State[" << j
-                          << "]: " << state2power[j];
-                if (j > 0 && state2power[j] < state2power[j - 1]) {
-                    LOG(ERROR) << "Higher power with higher state on cooling device " << name
-                               << "'s state" << j;
-                }
             }
         } else {
             LOG(INFO) << "CoolingDevice[" << i << "]'s Name: " << name
-                      << " does not support State2Power";
+                      << " does not support State2Power in thermal config";
         }
 
         const std::string &power_rail = cooling_devices[i]["PowerRail"].asString();
diff --git a/thermal/utils/thermal_info.h b/thermal/utils/thermal_info.h
index ada97a3a..dc1f6cb9 100644
--- a/thermal/utils/thermal_info.h
+++ b/thermal/utils/thermal_info.h
@@ -127,6 +127,7 @@ enum class SensorFusionType : uint32_t {
     SENSOR = 0,
     ODPM,
     CONSTANT,
+    CDEV,
 };
 
 std::ostream &operator<<(std::ostream &os, const SensorFusionType &sensor_fusion_type);
@@ -191,7 +192,8 @@ using ProfileMap = std::unordered_map<std::string, std::unordered_map<std::strin
 struct ThrottlingInfo {
     ThrottlingArray k_po;
     ThrottlingArray k_pu;
-    ThrottlingArray k_i;
+    ThrottlingArray k_io;
+    ThrottlingArray k_iu;
     ThrottlingArray k_d;
     ThrottlingArray i_max;
     ThrottlingArray max_alloc_power;
@@ -213,6 +215,7 @@ struct SensorInfo {
     ThrottlingArray hot_hysteresis;
     ThrottlingArray cold_hysteresis;
     std::string temp_path;
+    std::string severity_reference;
     float vr_threshold;
     float multiplier;
     std::chrono::milliseconds polling_delay;
@@ -225,6 +228,7 @@ struct SensorInfo {
     bool send_powerhint;
     bool is_watch;
     bool is_hidden;
+    ThrottlingSeverity log_level;
     std::unique_ptr<VirtualSensorInfo> virtual_sensor_info;
     std::shared_ptr<ThrottlingInfo> throttling_info;
     std::unique_ptr<PredictorInfo> predictor_info;
@@ -244,7 +248,10 @@ struct PowerRailInfo {
     std::unique_ptr<VirtualPowerRailInfo> virtual_power_rail_info;
 };
 
-bool ParseThermalConfig(std::string_view config_path, Json::Value *config);
+bool LoadThermalConfig(std::string_view config_path, Json::Value *config);
+bool ParseThermalConfig(std::string_view config_path, Json::Value *config,
+                        std::unordered_set<std::string> *loaded_config_paths);
+void MergeConfigEntries(Json::Value *config, Json::Value *sub_config, std::string_view member_name);
 bool ParseSensorInfo(const Json::Value &config,
                      std::unordered_map<std::string, SensorInfo> *sensors_parsed);
 bool ParseCoolingDevice(const Json::Value &config,
diff --git a/thermal/utils/thermal_throttling.cpp b/thermal/utils/thermal_throttling.cpp
index f5f079b3..1e011ec3 100644
--- a/thermal/utils/thermal_throttling.cpp
+++ b/thermal/utils/thermal_throttling.cpp
@@ -237,7 +237,16 @@ float ThermalThrottling::updatePowerBudget(
     }
 
     if (err < sensor_info.throttling_info->i_cutoff[target_state]) {
-        throttling_status.i_budget += err * sensor_info.throttling_info->k_i[target_state];
+        if (!(throttling_status.prev_power_budget <=
+                      sensor_info.throttling_info->min_alloc_power[target_state] &&
+              err < 0) &&
+            !(throttling_status.prev_power_budget >=
+                      sensor_info.throttling_info->max_alloc_power[target_state] &&
+              err > 0)) {
+            throttling_status.i_budget +=
+                    err * (err < 0 ? sensor_info.throttling_info->k_io[target_state]
+                                   : sensor_info.throttling_info->k_iu[target_state]);
+        }
     }
 
     if (fabsf(throttling_status.i_budget) > sensor_info.throttling_info->i_max[target_state]) {
@@ -269,12 +278,10 @@ float ThermalThrottling::updatePowerBudget(
     // Calculate power budget
     power_budget = sensor_info.throttling_info->s_power[target_state] + p +
                    throttling_status.i_budget + d + compensation;
-    if (power_budget < sensor_info.throttling_info->min_alloc_power[target_state]) {
-        power_budget = sensor_info.throttling_info->min_alloc_power[target_state];
-    }
-    if (power_budget > sensor_info.throttling_info->max_alloc_power[target_state]) {
-        power_budget = sensor_info.throttling_info->max_alloc_power[target_state];
-    }
+
+    power_budget =
+            std::clamp(power_budget, sensor_info.throttling_info->min_alloc_power[target_state],
+                       sensor_info.throttling_info->max_alloc_power[target_state]);
 
     if (target_changed) {
         throttling_status.budget_transient = throttling_status.prev_power_budget - power_budget;
diff --git a/thermal/utils/thermal_watcher.cpp b/thermal/utils/thermal_watcher.cpp
index f8ca2c2b..74bd4167 100644
--- a/thermal/utils/thermal_watcher.cpp
+++ b/thermal/utils/thermal_watcher.cpp
@@ -44,6 +44,66 @@ namespace implementation {
 
 namespace {
 
+using ::android::base::StringPrintf;
+
+constexpr static const char *const kNlAttributeStringMap[THERMAL_GENL_ATTR_MAX + 1] = {
+        [THERMAL_GENL_ATTR_TZ_ID] = "tz_id",
+        [THERMAL_GENL_ATTR_TZ_TEMP] = "tz_temp",
+        [THERMAL_GENL_ATTR_TZ_TRIP_ID] = "trip_id",
+        [THERMAL_GENL_ATTR_TZ_TRIP_TYPE] = "trip_type",
+        [THERMAL_GENL_ATTR_TZ_TRIP_TEMP] = "trip_temp",
+        [THERMAL_GENL_ATTR_TZ_TRIP_HYST] = "trip_hyst",
+        [THERMAL_GENL_ATTR_TZ_NAME] = "tz_name",
+        [THERMAL_GENL_ATTR_CDEV_ID] = "cdev_id",
+        [THERMAL_GENL_ATTR_CDEV_CUR_STATE] = "cdev_cur_state",
+        [THERMAL_GENL_ATTR_CDEV_MAX_STATE] = "cdev_max_state",
+        [THERMAL_GENL_ATTR_CDEV_NAME] = "cdev_name",
+        [THERMAL_GENL_ATTR_GOV_NAME] = "gov_name",
+};
+
+static void setAndLogTzId(const struct nlattr *const attrs[THERMAL_GENL_ATTR_MAX + 1], int &tz_id,
+                          std::string &out) {
+    if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
+        tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
+        out.append(StringPrintf(" %s=%d", kNlAttributeStringMap[THERMAL_GENL_ATTR_TZ_ID], tz_id));
+    }
+}
+
+static void setAndLogTzTemp(const struct nlattr *const attrs[THERMAL_GENL_ATTR_MAX + 1],
+                            float &tz_temp, std::string &out) {
+    if (attrs[THERMAL_GENL_ATTR_TZ_TEMP]) {
+        tz_temp = static_cast<float>(nla_get_s32(attrs[THERMAL_GENL_ATTR_TZ_TEMP]));
+        out.append(StringPrintf(" %s=%0.2f", kNlAttributeStringMap[THERMAL_GENL_ATTR_TZ_TEMP],
+                                tz_temp));
+    }
+}
+
+static void log32Attribute(const struct nlattr *const attrs[THERMAL_GENL_ATTR_MAX + 1],
+                           const thermal_genl_attr &attr_type, std::string &out) {
+    if (attrs[attr_type]) {
+        if (attr_type == THERMAL_GENL_ATTR_TZ_TEMP || attr_type == THERMAL_GENL_ATTR_TZ_TRIP_TEMP) {
+            out.append(StringPrintf(" %s=%d", kNlAttributeStringMap[attr_type],
+                                    nla_get_s32(attrs[attr_type])));
+        } else {
+            // id, hyst and state kind of attr_type will goes into this else
+            out.append(StringPrintf(" %s=%d", kNlAttributeStringMap[attr_type],
+                                    nla_get_u32(attrs[attr_type])));
+        }
+    }
+}
+
+static void log32AttributeList(const struct nlattr *const attrs[THERMAL_GENL_ATTR_MAX + 1],
+                               const std::vector<thermal_genl_attr> &attr_types, std::string &out) {
+    for (const auto &attr_type : attr_types) log32Attribute(attrs, attr_type, out);
+}
+
+static void logStringAttribute(const struct nlattr *const attrs[THERMAL_GENL_ATTR_MAX + 1],
+                               const thermal_genl_attr &attr_type, std::string &out) {
+    if (attrs[attr_type])
+        out.append(StringPrintf(" %s=%s", kNlAttributeStringMap[attr_type],
+                                nla_get_string(attrs[attr_type])));
+}
+
 static int nlErrorHandle(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
     int *ret = reinterpret_cast<int *>(arg);
     *ret = err->error;
@@ -190,151 +250,94 @@ static int handleEvent(struct nl_msg *n, void *arg) {
     struct nlmsghdr *nlh = nlmsg_hdr(n);
     struct genlmsghdr *glh = genlmsg_hdr(nlh);
     struct nlattr *attrs[THERMAL_GENL_ATTR_MAX + 1];
-    int *tz_id = reinterpret_cast<int *>(arg);
+    std::pair<int, float> *tz_info = reinterpret_cast<std::pair<int, float> *>(arg);
+    int &tz_id = tz_info->first;
+    float &tz_temp = tz_info->second;
+    std::string out;
 
     genlmsg_parse(nlh, 0, attrs, THERMAL_GENL_ATTR_MAX, NULL);
 
-    if (glh->cmd == THERMAL_GENL_EVENT_TZ_TRIP_UP) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_TZ_TRIP_UP";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-            *tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        }
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_ID])
-            LOG(INFO) << "Thermal zone trip id: "
-                      << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_ID]);
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_TZ_TRIP_DOWN) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_TZ_TRIP_DOWN";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-            *tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        }
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_ID])
-            LOG(INFO) << "Thermal zone trip id: "
-                      << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_ID]);
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_TZ_GOV_CHANGE) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_TZ_GOV_CHANGE";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-            *tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        }
-        if (attrs[THERMAL_GENL_ATTR_GOV_NAME])
-            LOG(INFO) << "Governor name: " << nla_get_string(attrs[THERMAL_GENL_ATTR_GOV_NAME]);
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_TZ_CREATE) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_TZ_CREATE";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-            *tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        }
-        if (attrs[THERMAL_GENL_ATTR_TZ_NAME])
-            LOG(INFO) << "Thermal zone name: " << nla_get_string(attrs[THERMAL_GENL_ATTR_TZ_NAME]);
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_TZ_DELETE) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_TZ_DELETE";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-            *tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        }
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_TZ_DISABLE) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_TZ_DISABLE";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-            *tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        }
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_TZ_ENABLE) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_TZ_ENABLE";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-            *tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        }
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_TZ_TRIP_CHANGE) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_TZ_TRIP_CHANGE";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-            *tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        }
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_ID])
-            LOG(INFO) << "Trip id:: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_ID]);
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_TYPE])
-            LOG(INFO) << "Trip type: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_TYPE]);
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_TEMP])
-            LOG(INFO) << "Trip temp: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_TEMP]);
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_HYST])
-            LOG(INFO) << "Trip hyst: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_HYST]);
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_TZ_TRIP_ADD) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_TZ_TRIP_ADD";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID])
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_ID])
-            LOG(INFO) << "Trip id:: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_ID]);
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_TYPE])
-            LOG(INFO) << "Trip type: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_TYPE]);
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_TEMP])
-            LOG(INFO) << "Trip temp: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_TEMP]);
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_HYST])
-            LOG(INFO) << "Trip hyst: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_HYST]);
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_TZ_TRIP_DELETE) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_TZ_TRIP_DELETE";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-            *tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        }
-        if (attrs[THERMAL_GENL_ATTR_TZ_TRIP_ID])
-            LOG(INFO) << "Trip id:: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TRIP_ID]);
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_CDEV_STATE_UPDATE) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_CDEV_STATE_UPDATE";
-        if (attrs[THERMAL_GENL_ATTR_CDEV_ID])
-            LOG(INFO) << "Cooling device id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_CDEV_ID]);
-        if (attrs[THERMAL_GENL_ATTR_CDEV_CUR_STATE])
-            LOG(INFO) << "Cooling device current state: "
-                      << nla_get_u32(attrs[THERMAL_GENL_ATTR_CDEV_CUR_STATE]);
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_CDEV_ADD) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_CDEV_ADD";
-        if (attrs[THERMAL_GENL_ATTR_CDEV_NAME])
-            LOG(INFO) << "Cooling device name: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_CDEV_NAME]);
-        if (attrs[THERMAL_GENL_ATTR_CDEV_ID])
-            LOG(INFO) << "Cooling device id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_CDEV_ID]);
-        if (attrs[THERMAL_GENL_ATTR_CDEV_MAX_STATE])
-            LOG(INFO) << "Cooling device max state: "
-                      << nla_get_u32(attrs[THERMAL_GENL_ATTR_CDEV_MAX_STATE]);
-    }
-
-    if (glh->cmd == THERMAL_GENL_EVENT_CDEV_DELETE) {
-        LOG(INFO) << "THERMAL_GENL_EVENT_CDEV_DELETE";
-        if (attrs[THERMAL_GENL_ATTR_CDEV_ID])
-            LOG(INFO) << "Cooling device id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_CDEV_ID]);
-    }
-
-    if (glh->cmd == THERMAL_GENL_SAMPLING_TEMP) {
-        LOG(INFO) << "THERMAL_GENL_SAMPLING_TEMP";
-        if (attrs[THERMAL_GENL_ATTR_TZ_ID]) {
-            LOG(INFO) << "Thermal zone id: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-            *tz_id = nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_ID]);
-        }
-        if (attrs[THERMAL_GENL_ATTR_TZ_TEMP])
-            LOG(INFO) << "Thermal zone temp: " << nla_get_u32(attrs[THERMAL_GENL_ATTR_TZ_TEMP]);
+    switch (glh->cmd) {
+        case THERMAL_GENL_EVENT_TZ_TRIP_UP:
+            out = "THERMAL_GENL_EVENT_TZ_TRIP_UP";
+            setAndLogTzId(attrs, tz_id, out);
+            setAndLogTzTemp(attrs, tz_temp, out);
+            log32Attribute(attrs, THERMAL_GENL_ATTR_TZ_TRIP_ID, out);
+            break;
+        case THERMAL_GENL_EVENT_TZ_TRIP_DOWN:
+            out = "THERMAL_GENL_EVENT_TZ_TRIP_DOWN";
+            setAndLogTzId(attrs, tz_id, out);
+            setAndLogTzTemp(attrs, tz_temp, out);
+            log32Attribute(attrs, THERMAL_GENL_ATTR_TZ_TRIP_ID, out);
+            break;
+        case THERMAL_GENL_EVENT_TZ_GOV_CHANGE:
+            out = "THERMAL_GENL_EVENT_TZ_GOV_CHANGE";
+            setAndLogTzId(attrs, tz_id, out);
+            logStringAttribute(attrs, THERMAL_GENL_ATTR_GOV_NAME, out);
+            break;
+        case THERMAL_GENL_EVENT_TZ_CREATE:
+            out = "THERMAL_GENL_EVENT_TZ_CREATE";
+            setAndLogTzId(attrs, tz_id, out);
+            logStringAttribute(attrs, THERMAL_GENL_ATTR_TZ_NAME, out);
+            break;
+        case THERMAL_GENL_EVENT_TZ_DELETE:
+            out = "THERMAL_GENL_EVENT_TZ_DELETE";
+            setAndLogTzId(attrs, tz_id, out);
+            break;
+        case THERMAL_GENL_EVENT_TZ_DISABLE:
+            out = "THERMAL_GENL_EVENT_TZ_DISABLE";
+            setAndLogTzId(attrs, tz_id, out);
+            break;
+        case THERMAL_GENL_EVENT_TZ_ENABLE:
+            out = "THERMAL_GENL_EVENT_TZ_ENABLE";
+            setAndLogTzId(attrs, tz_id, out);
+            break;
+        case THERMAL_GENL_EVENT_TZ_TRIP_CHANGE:
+            out = "THERMAL_GENL_EVENT_TZ_TRIP_CHANGE";
+            setAndLogTzId(attrs, tz_id, out);
+            log32AttributeList(attrs,
+                               {THERMAL_GENL_ATTR_TZ_TRIP_ID, THERMAL_GENL_ATTR_TZ_TRIP_TYPE,
+                                THERMAL_GENL_ATTR_TZ_TRIP_TEMP, THERMAL_GENL_ATTR_TZ_TRIP_HYST},
+                               out);
+            break;
+        case THERMAL_GENL_EVENT_TZ_TRIP_ADD:
+            out = "THERMAL_GENL_EVENT_TZ_TRIP_ADD";
+            setAndLogTzId(attrs, tz_id, out);
+            log32AttributeList(attrs,
+                               {THERMAL_GENL_ATTR_TZ_TRIP_ID, THERMAL_GENL_ATTR_TZ_TRIP_TYPE,
+                                THERMAL_GENL_ATTR_TZ_TRIP_TEMP, THERMAL_GENL_ATTR_TZ_TRIP_HYST},
+                               out);
+            break;
+        case THERMAL_GENL_EVENT_TZ_TRIP_DELETE:
+            out = "THERMAL_GENL_EVENT_TZ_TRIP_DELETE";
+            setAndLogTzId(attrs, tz_id, out);
+            log32Attribute(attrs, THERMAL_GENL_ATTR_TZ_TRIP_ID, out);
+            break;
+        case THERMAL_GENL_EVENT_CDEV_STATE_UPDATE:
+            out = "THERMAL_GENL_EVENT_CDEV_STATE_UPDATE:";
+            log32AttributeList(attrs, {THERMAL_GENL_ATTR_CDEV_ID, THERMAL_GENL_ATTR_CDEV_CUR_STATE},
+                               out);
+            break;
+        case THERMAL_GENL_EVENT_CDEV_ADD:
+            out = "THERMAL_GENL_EVENT_CDEV_ADD";
+            log32Attribute(attrs, THERMAL_GENL_ATTR_CDEV_ID, out);
+            logStringAttribute(attrs, THERMAL_GENL_ATTR_CDEV_NAME, out);
+            log32Attribute(attrs, THERMAL_GENL_ATTR_CDEV_MAX_STATE, out);
+            break;
+        case THERMAL_GENL_EVENT_CDEV_DELETE:
+            out = "THERMAL_GENL_EVENT_CDEV_DELETE";
+            log32Attribute(attrs, THERMAL_GENL_ATTR_CDEV_ID, out);
+            break;
+        case THERMAL_GENL_SAMPLING_TEMP:
+            out = "THERMAL_GENL_SAMPLING_TEMP";
+            setAndLogTzId(attrs, tz_id, out);
+            log32Attribute(attrs, THERMAL_GENL_ATTR_TZ_TEMP, out);
+            break;
+        default:
+            LOG(ERROR) << "Unknown genlink event command: " << glh->cmd;
+            return 0;
     }
+    LOG(INFO) << out;
 
     return 0;
 }
@@ -412,7 +415,7 @@ bool ThermalWatcher::startWatchingDeviceFiles() {
     }
     return false;
 }
-void ThermalWatcher::parseUevent(std::set<std::string> *sensors_set) {
+void ThermalWatcher::parseUevent(std::unordered_map<std::string, float> *sensor_map) {
     bool thermal_event = false;
     constexpr int kUeventMsgLen = 2048;
     char msg[kUeventMsgLen + 2];
@@ -453,7 +456,7 @@ void ThermalWatcher::parseUevent(std::set<std::string> *sensors_set) {
                     start_pos += 5;
                     std::string name = uevent.substr(start_pos);
                     if (monitored_sensors_.find(name) != monitored_sensors_.end()) {
-                        sensors_set->insert(name);
+                        sensor_map->insert({name, NAN});
                     }
                     break;
                 }
@@ -466,8 +469,9 @@ void ThermalWatcher::parseUevent(std::set<std::string> *sensors_set) {
 
 // TODO(b/175367921): Consider for potentially adding more type of event in the function
 // instead of just add the sensors to the list.
-void ThermalWatcher::parseGenlink(std::set<std::string> *sensors_set) {
-    int err = 0, done = 0, tz_id = -1;
+void ThermalWatcher::parseGenlink(std::unordered_map<std::string, float> *sensor_map) {
+    int err = 0, done = 0;
+    std::pair<int, float> tz_info(-1, NAN);
 
     std::unique_ptr<nl_cb, decltype(&nl_cb_put)> cb(nl_cb_alloc(NL_CB_DEFAULT), nl_cb_put);
 
@@ -475,19 +479,19 @@ void ThermalWatcher::parseGenlink(std::set<std::string> *sensors_set) {
     nl_cb_set(cb.get(), NL_CB_FINISH, NL_CB_CUSTOM, nlFinishHandle, &done);
     nl_cb_set(cb.get(), NL_CB_ACK, NL_CB_CUSTOM, nlAckHandle, &done);
     nl_cb_set(cb.get(), NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nlSeqCheckHandle, &done);
-    nl_cb_set(cb.get(), NL_CB_VALID, NL_CB_CUSTOM, handleEvent, &tz_id);
+    nl_cb_set(cb.get(), NL_CB_VALID, NL_CB_CUSTOM, handleEvent, &tz_info);
 
     while (!done && !err) {
         nl_recvmsgs(sk_thermal, cb.get());
 
-        if (tz_id < 0) {
+        if (tz_info.first < 0) {
             break;
         }
 
         std::string name;
-        if (getThermalZoneTypeById(tz_id, &name) &&
+        if (getThermalZoneTypeById(tz_info.first, &name) &&
             monitored_sensors_.find(name) != monitored_sensors_.end()) {
-            sensors_set->insert(name);
+            sensor_map->insert({name, tz_info.second});
         }
     }
 }
@@ -500,7 +504,7 @@ bool ThermalWatcher::threadLoop() {
     LOG(VERBOSE) << "ThermalWatcher polling...";
 
     int fd;
-    std::set<std::string> sensors;
+    std::unordered_map<std::string, float> sensors;
 
     auto time_elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(boot_clock::now() -
                                                                                  last_update_time_);
diff --git a/thermal/utils/thermal_watcher.h b/thermal/utils/thermal_watcher.h
index 8f8b3981..6d1dbedf 100644
--- a/thermal/utils/thermal_watcher.h
+++ b/thermal/utils/thermal_watcher.h
@@ -43,7 +43,8 @@ namespace implementation {
 
 using ::android::base::boot_clock;
 using ::android::base::unique_fd;
-using WatcherCallback = std::function<std::chrono::milliseconds(const std::set<std::string> &name)>;
+using WatcherCallback = std::function<std::chrono::milliseconds(
+        const std::unordered_map<std::string, float> &uevent_sensor_map)>;
 
 // A helper class for monitoring thermal files changes.
 class ThermalWatcher : public ::android::Thread {
@@ -77,10 +78,10 @@ class ThermalWatcher : public ::android::Thread {
     bool threadLoop() override;
 
     // Parse uevent message
-    void parseUevent(std::set<std::string> *sensor_name);
+    void parseUevent(std::unordered_map<std::string, float> *sensor_map);
 
     // Parse thermal netlink message
-    void parseGenlink(std::set<std::string> *sensor_name);
+    void parseGenlink(std::unordered_map<std::string, float> *sensor_map);
 
     // Maps watcher filer descriptor to watched file path.
     std::unordered_map<int, std::string> watch_to_file_path_map_;
diff --git a/thermal/virtualtemp_estimator/virtualtemp_estimator.cpp b/thermal/virtualtemp_estimator/virtualtemp_estimator.cpp
index 2b70a3ab..bb66e876 100644
--- a/thermal/virtualtemp_estimator/virtualtemp_estimator.cpp
+++ b/thermal/virtualtemp_estimator/virtualtemp_estimator.cpp
@@ -90,7 +90,7 @@ VtEstimatorStatus VirtualTempEstimator::DumpTraces() {
     std::unique_lock<std::mutex> lock(tflite_instance_->tflite_methods.mutex);
 
     if (!common_instance_->is_initialized) {
-        LOG(ERROR) << "tflite_instance_ not initialized for " << tflite_instance_->model_path;
+        LOG(ERROR) << "tflite_instance_ not initialized for " << common_instance_->sensor_name;
         return kVtEstimatorInitFailed;
     }
 
@@ -262,7 +262,7 @@ VtEstimatorStatus VirtualTempEstimator::TFliteInitialize(MLModelInitData data) {
         return kVtEstimatorInitFailed;
     }
 
-    std::string model_path = data.model_path;
+    std::string_view sensor_name = common_instance_->sensor_name;
     size_t num_linked_sensors = common_instance_->num_linked_sensors;
     bool use_prev_samples = data.use_prev_samples;
     size_t prev_samples_order = data.prev_samples_order;
@@ -271,17 +271,16 @@ VtEstimatorStatus VirtualTempEstimator::TFliteInitialize(MLModelInitData data) {
 
     std::unique_lock<std::mutex> lock(tflite_instance_->tflite_methods.mutex);
 
-    if (model_path.empty()) {
-        LOG(ERROR) << "Invalid model_path:" << model_path;
+    if (data.model_path.empty()) {
+        LOG(ERROR) << "Invalid model_path:" << data.model_path << " for " << sensor_name;
         return kVtEstimatorInvalidArgs;
     }
 
     if (num_linked_sensors == 0 || prev_samples_order < 1 ||
         (!use_prev_samples && prev_samples_order > 1)) {
-        LOG(ERROR) << "Invalid tflite_instance_ config: "
-                   << "number of linked sensor: " << num_linked_sensors
-                   << " use previous: " << use_prev_samples
-                   << " previous sample order: " << prev_samples_order;
+        LOG(ERROR) << "Invalid tflite_instance_ config: " << "number of linked sensor: "
+                   << num_linked_sensors << " use previous: " << use_prev_samples
+                   << " previous sample order: " << prev_samples_order << " for " << sensor_name;
         return kVtEstimatorInitFailed;
     }
 
@@ -296,9 +295,8 @@ VtEstimatorStatus VirtualTempEstimator::TFliteInitialize(MLModelInitData data) {
     }
 
     if (output_label_count < 1 || num_hot_spots < 1) {
-        LOG(ERROR) << "Invalid tflite_instance_ config:"
-                   << "number of hot spots: " << num_hot_spots
-                   << " predicted sample order: " << output_label_count;
+        LOG(ERROR) << "Invalid tflite_instance_ config:" << "number of hot spots: " << num_hot_spots
+                   << " predicted sample order: " << output_label_count << " for " << sensor_name;
         return kVtEstimatorInitFailed;
     }
 
@@ -311,48 +309,48 @@ VtEstimatorStatus VirtualTempEstimator::TFliteInitialize(MLModelInitData data) {
         !tflite_instance_->tflite_methods.invoke || !tflite_instance_->tflite_methods.destroy ||
         !tflite_instance_->tflite_methods.get_input_config_size ||
         !tflite_instance_->tflite_methods.get_input_config) {
-        LOG(ERROR) << "Invalid tflite methods";
+        LOG(ERROR) << "Invalid tflite methods for " << sensor_name;
         return kVtEstimatorInitFailed;
     }
 
     tflite_instance_->tflite_wrapper =
             tflite_instance_->tflite_methods.create(kNumInputTensors, kNumOutputTensors);
     if (!tflite_instance_->tflite_wrapper) {
-        LOG(ERROR) << "Failed to create tflite wrapper";
+        LOG(ERROR) << "Failed to create tflite wrapper for " << sensor_name;
         return kVtEstimatorInitFailed;
     }
 
     int ret = tflite_instance_->tflite_methods.init(tflite_instance_->tflite_wrapper,
-                                                    model_path.c_str());
+                                                    data.model_path.c_str());
     if (ret) {
-        LOG(ERROR) << "Failed to Init tflite_wrapper for " << model_path << " (ret: )" << ret
+        LOG(ERROR) << "Failed to Init tflite_wrapper for " << sensor_name << " (ret: " << ret
                    << ")";
         return kVtEstimatorInitFailed;
     }
 
     Json::Value input_config;
     if (!GetInputConfig(&input_config)) {
-        LOG(ERROR) << "Get Input Config failed for " << model_path;
+        LOG(ERROR) << "Get Input Config failed for " << sensor_name;
         return kVtEstimatorInitFailed;
     }
 
     if (!ParseInputConfig(input_config)) {
-        LOG(ERROR) << "Parse Input Config failed for " << model_path;
+        LOG(ERROR) << "Parse Input Config failed for " << sensor_name;
         return kVtEstimatorInitFailed;
     }
 
     if (tflite_instance_->enable_input_validation && !tflite_instance_->input_range.size()) {
         LOG(ERROR) << "Input ranges missing when input data validation is enabled for "
-                   << common_instance_->sensor_name;
+                   << sensor_name;
         return kVtEstimatorInitFailed;
     }
 
     common_instance_->offset_thresholds = data.offset_thresholds;
     common_instance_->offset_values = data.offset_values;
-    tflite_instance_->model_path = model_path;
+    tflite_instance_->model_path = data.model_path;
 
     common_instance_->is_initialized = true;
-    LOG(INFO) << "Successfully initialized VirtualTempEstimator for " << model_path;
+    LOG(INFO) << "Successfully initialized VirtualTempEstimator for " << sensor_name;
     return kVtEstimatorOk;
 }
 
@@ -363,6 +361,7 @@ VtEstimatorStatus VirtualTempEstimator::LinearModelEstimate(const std::vector<fl
         return kVtEstimatorInitFailed;
     }
 
+    std::string_view sensor_name = common_instance_->sensor_name;
     size_t prev_samples_order = common_instance_->prev_samples_order;
     size_t num_linked_sensors = common_instance_->num_linked_sensors;
 
@@ -370,12 +369,13 @@ VtEstimatorStatus VirtualTempEstimator::LinearModelEstimate(const std::vector<fl
 
     if ((thermistors.size() != num_linked_sensors) || (output == nullptr)) {
         LOG(ERROR) << "Invalid args Thermistors size[" << thermistors.size()
-                   << "] num_linked_sensors[" << num_linked_sensors << "] output[" << output << "]";
+                   << "] num_linked_sensors[" << num_linked_sensors << "] output[" << output << "]"
+                   << " for " << sensor_name;
         return kVtEstimatorInvalidArgs;
     }
 
     if (common_instance_->is_initialized == false) {
-        LOG(ERROR) << "VirtualTempEstimator not initialized to estimate";
+        LOG(ERROR) << "tflite_instance_ not initialized for " << sensor_name;
         return kVtEstimatorInitFailed;
     }
 
@@ -429,9 +429,10 @@ VtEstimatorStatus VirtualTempEstimator::TFliteEstimate(const std::vector<float>
         return kVtEstimatorInitFailed;
     }
 
+    std::string_view sensor_name = common_instance_->sensor_name;
     size_t num_linked_sensors = common_instance_->num_linked_sensors;
     if ((thermistors.size() != num_linked_sensors) || (output == nullptr)) {
-        LOG(ERROR) << "Invalid args for " << tflite_instance_->model_path
+        LOG(ERROR) << "Invalid args for " << sensor_name
                    << " thermistors.size(): " << thermistors.size()
                    << " num_linked_sensors: " << num_linked_sensors << " output: " << output;
         return kVtEstimatorInvalidArgs;
@@ -443,13 +444,13 @@ VtEstimatorStatus VirtualTempEstimator::TFliteEstimate(const std::vector<float>
         input_data_str += ::android::base::StringPrintf("%0.2f ", thermistors[i]);
     }
     input_data_str += "]";
-    LOG(INFO) << input_data_str;
+    LOG(INFO) << sensor_name << ": " << input_data_str;
 
     // check time gap between samples and ignore stale previous samples
     if (std::chrono::duration_cast<std::chrono::milliseconds>(boot_clock::now() -
                                                               tflite_instance_->prev_sample_time) >=
         tflite_instance_->max_sample_interval) {
-        LOG(INFO) << "Ignoring stale previous samples for " << common_instance_->sensor_name;
+        LOG(INFO) << "Ignoring stale previous samples for " << sensor_name;
         common_instance_->cur_sample_count = 0;
     }
 
@@ -463,7 +464,8 @@ VtEstimatorStatus VirtualTempEstimator::TFliteEstimate(const std::vector<float>
                 thermistors[i] > tflite_instance_->input_range[i].max_threshold) {
                 LOG(INFO) << "thermistors[" << i << "] value: " << thermistors[i]
                           << " not in range: " << tflite_instance_->input_range[i].min_threshold
-                          << " <= val <= " << tflite_instance_->input_range[i].max_threshold;
+                          << " <= val <= " << tflite_instance_->input_range[i].max_threshold
+                          << " for " << sensor_name;
                 common_instance_->cur_sample_count = 0;
                 return kVtEstimatorLowConfidence;
             }
@@ -505,8 +507,7 @@ VtEstimatorStatus VirtualTempEstimator::TFliteEstimate(const std::vector<float>
             tflite_instance_->tflite_wrapper, model_input, input_buffer_size,
             tflite_instance_->output_buffer, output_buffer_size);
     if (ret) {
-        LOG(ERROR) << "Failed to Invoke for " << tflite_instance_->model_path << " (ret: " << ret
-                   << ")";
+        LOG(ERROR) << "Failed to Invoke for " << sensor_name << " (ret: " << ret << ")";
         return kVtEstimatorInvokeFailed;
     }
     tflite_instance_->last_update_time = boot_clock::now();
@@ -524,8 +525,8 @@ VtEstimatorStatus VirtualTempEstimator::TFliteEstimate(const std::vector<float>
         predict_log << predicted_value << " ";
         data.emplace_back(predicted_value);
     }
-    LOG(INFO) << "model_output: [" << model_out_log.str() << "]";
-    LOG(INFO) << "predicted_value: [" << predict_log.str() << "]";
+    LOG(INFO) << sensor_name << ": model_output: [" << model_out_log.str() << "]";
+    LOG(INFO) << sensor_name << ": predicted_value: [" << predict_log.str() << "]";
     *output = data;
 
     return kVtEstimatorOk;
@@ -550,7 +551,7 @@ VtEstimatorStatus VirtualTempEstimator::TFliteGetMaxPredictWindowMs(size_t *pred
     }
 
     if (!common_instance_->is_initialized) {
-        LOG(ERROR) << "tflite_instance_ not initialized for " << tflite_instance_->model_path;
+        LOG(ERROR) << "tflite_instance_ not initialized for " << common_instance_->sensor_name;
         return kVtEstimatorInitFailed;
     }
 
@@ -579,7 +580,7 @@ VtEstimatorStatus VirtualTempEstimator::TFlitePredictAfterTimeMs(const size_t ti
     }
 
     if (!common_instance_->is_initialized) {
-        LOG(ERROR) << "tflite_instance_ not initialized for " << tflite_instance_->model_path;
+        LOG(ERROR) << "tflite_instance_ not initialized for " << common_instance_->sensor_name;
         return kVtEstimatorInitFailed;
     }
 
diff --git a/vibrator/common/Android.bp b/vibrator/common/Android.bp
index cb21005d..3dd55bf9 100644
--- a/vibrator/common/Android.bp
+++ b/vibrator/common/Android.bp
@@ -33,6 +33,7 @@ soong_config_string_variable {
     values: [
         "luxshare_ict_081545",
         "luxshare_ict_lt_xlra1906d",
+        "legacy_zlra_actuator",
     ],
 }
 
@@ -57,6 +58,11 @@ haptics_feature_cc_defaults {
                     "-DLUXSHARE_ICT_LT_XLRA1906D",
                 ],
             },
+            legacy_zlra_actuator: {
+                cflags: [
+                    "-DLEGACY_ZLRA_ACTUATOR",
+                ],
+            },
             conditions_default: {
                 cflags: [
                     "-DUNSPECIFIED_ACTUATOR",
@@ -166,14 +172,57 @@ cc_library {
         "-DATRACE_TAG=(ATRACE_TAG_VIBRATOR | ATRACE_TAG_HAL)",
         "-DLOG_TAG=\"VibratorStats\"",
     ],
+    static_libs: [
+        "libvibrator_atoms",
+    ],
     shared_libs: [
         "android.frameworks.stats-V2-ndk",
         "libbase",
         "libcutils",
         "libbinder_ndk",
         "liblog",
-        "libprotobuf-cpp-lite",
         "libutils",
-        "pixelatoms-cpp",
+    ],
+}
+
+genrule {
+    name: "vibrator_atoms.h",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --header $(out)" +
+        " --module vibrator" +
+        " --namespace android,hardware,google,pixel,VibratorAtoms" +
+        " --vendor-proto hardware/google/pixel/pixelstats/pixelatoms.proto",
+    out: [
+        "vibrator_atoms.h",
+    ],
+    srcs: [
+        ":pixelatoms_proto",
+    ],
+}
+
+genrule {
+    name: "vibrator_atoms.cpp",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --cpp $(out)" +
+        " --module vibrator" +
+        " --importHeader vibrator_atoms.h" +
+        " --namespace android,hardware,google,pixel,VibratorAtoms" +
+        " --vendor-proto hardware/google/pixel/pixelstats/pixelatoms.proto",
+    out: [
+        "vibrator_atoms.cpp",
+    ],
+    srcs: [
+        ":pixelatoms_proto",
+    ],
+}
+
+cc_library_static {
+    name: "libvibrator_atoms",
+    vendor: true,
+    generated_sources: ["vibrator_atoms.cpp"],
+    generated_headers: ["vibrator_atoms.h"],
+    export_generated_headers: ["vibrator_atoms.h"],
+    shared_libs: [
+        "android.frameworks.stats-V2-ndk",
     ],
 }
diff --git a/vibrator/common/HardwareBase.cpp b/vibrator/common/HardwareBase.cpp
index f162429b..fb15523a 100644
--- a/vibrator/common/HardwareBase.cpp
+++ b/vibrator/common/HardwareBase.cpp
@@ -40,10 +40,6 @@ void HwApiBase::saveName(const std::string &name, const std::ios *stream) {
     mNames[stream] = name;
 }
 
-bool HwApiBase::has(const std::ios &stream) {
-    return !!stream;
-}
-
 void HwApiBase::debug(int fd) {
     dprintf(fd, "Kernel:\n");
 
diff --git a/vibrator/common/HardwareBase.h b/vibrator/common/HardwareBase.h
index 36c3fcad..d038c198 100644
--- a/vibrator/common/HardwareBase.h
+++ b/vibrator/common/HardwareBase.h
@@ -26,6 +26,7 @@
 #include <map>
 #include <sstream>
 #include <string>
+#include <type_traits>
 
 #include "utils.h"
 
@@ -78,7 +79,8 @@ class HwApiBase {
     void saveName(const std::string &name, const std::ios *stream);
     template <typename T>
     void open(const std::string &name, T *stream);
-    bool has(const std::ios &stream);
+    template <typename T>
+    bool has(const T &stream);
     template <typename T>
     bool get(T *value, std::istream *stream);
     template <typename T>
@@ -104,6 +106,16 @@ void HwApiBase::open(const std::string &name, T *stream) {
     utils::openNoCreate(mPathPrefix + name, stream);
 }
 
+template <typename T>
+bool HwApiBase::has(const T &stream) {
+    if constexpr (std::is_same<T, std::fstream>::value || std::is_same<T, std::ofstream>::value ||
+                  std::is_same<T, std::ifstream>::value)
+        return stream.is_open() && !stream.fail();
+
+    ALOGE("File stream is not of the correct type");
+    return false;
+}
+
 template <typename T>
 bool HwApiBase::get(T *value, std::istream *stream) {
     ATRACE_NAME("HwApi::get");
diff --git a/vibrator/common/StatsBase.cpp b/vibrator/common/StatsBase.cpp
index a0402b4e..9160d81a 100644
--- a/vibrator/common/StatsBase.cpp
+++ b/vibrator/common/StatsBase.cpp
@@ -18,18 +18,19 @@
 
 #include <aidl/android/frameworks/stats/IStats.h>
 #include <android/binder_manager.h>
-#include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
 #include <log/log.h>
 #include <utils/Trace.h>
+#include <vibrator_atoms.h>
 
 #include <chrono>
 #include <sstream>
 
 using ::aidl::android::frameworks::stats::IStats;
 using ::aidl::android::frameworks::stats::VendorAtom;
-using ::aidl::android::frameworks::stats::VendorAtomValue;
 
-namespace PixelAtoms = ::android::hardware::google::pixel::PixelAtoms;
+namespace VibratorAtoms = ::android::hardware::google::pixel::VibratorAtoms;
+
+using VibratorAtoms::createVendorAtom;
 
 #ifndef ARRAY_SIZE
 #define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
@@ -41,13 +42,13 @@ static const char *kAtomLookup[] = {"HAPTICS_PLAYCOUNTS", "HAPTICS_LATENCIES", "
 
 const char *atomToString(uint32_t atomId) {
     switch (atomId) {
-        case PixelAtoms::Atom::kVibratorPlaycountReported:
+        case VibratorAtoms::VIBRATOR_PLAYCOUNT_REPORTED:
             return kAtomLookup[0];
             break;
-        case PixelAtoms::Atom::kVibratorLatencyReported:
+        case VibratorAtoms::VIBRATOR_LATENCY_REPORTED:
             return kAtomLookup[1];
             break;
-        case PixelAtoms::Atom::kVibratorErrorsReported:
+        case VibratorAtoms::VIBRATOR_ERRORS_REPORTED:
             return kAtomLookup[2];
             break;
         default:
@@ -223,62 +224,32 @@ void StatsBase::clearData(std::vector<int32_t> *data) {
 
 VendorAtom StatsBase::vibratorPlaycountAtom() {
     STATS_TRACE("vibratorPlaycountAtom()");
-    std::vector<VendorAtomValue> values(2);
-
-    {
-        std::scoped_lock<std::mutex> lock(mDataAccess);
-        values[0].set<VendorAtomValue::repeatedIntValue>(mWaveformCounts);
-        values[1].set<VendorAtomValue::repeatedIntValue>(mDurationCounts);
-    }
-
-    return VendorAtom{
-            .reverseDomainName = "",
-            .atomId = PixelAtoms::Atom::kVibratorPlaycountReported,
-            .values = std::move(values),
-    };
+    std::scoped_lock<std::mutex> lock(mDataAccess);
+    return createVendorAtom(VibratorAtoms::VIBRATOR_PLAYCOUNT_REPORTED, "", mWaveformCounts,
+                            mDurationCounts);
 }
 
 VendorAtom StatsBase::vibratorLatencyAtom() {
     STATS_TRACE("vibratorLatencyAtom()");
-    std::vector<VendorAtomValue> values(3);
     std::vector<int32_t> avgLatencies;
 
-    {
-        std::scoped_lock<std::mutex> lock(mDataAccess);
-        for (uint32_t i = 0; i < mLatencyCounts.size(); i++) {
-            int32_t avg = 0;
-            if (mLatencyCounts[0] > 0) {
-                avg = mLatencyTotals[i] / mLatencyCounts[i];
-            }
-            avgLatencies.push_back(avg);
+    std::scoped_lock<std::mutex> lock(mDataAccess);
+    for (uint32_t i = 0; i < mLatencyCounts.size(); i++) {
+        int32_t avg = 0;
+        if (mLatencyCounts[0] > 0) {
+            avg = mLatencyTotals[i] / mLatencyCounts[i];
         }
-
-        values[0].set<VendorAtomValue::repeatedIntValue>(mMinLatencies);
-        values[1].set<VendorAtomValue::repeatedIntValue>(mMaxLatencies);
+        avgLatencies.push_back(avg);
     }
-    values[2].set<VendorAtomValue::repeatedIntValue>(avgLatencies);
 
-    return VendorAtom{
-            .reverseDomainName = "",
-            .atomId = PixelAtoms::Atom::kVibratorLatencyReported,
-            .values = std::move(values),
-    };
+    return createVendorAtom(VibratorAtoms::VIBRATOR_LATENCY_REPORTED, "", mMinLatencies,
+                            mMaxLatencies, avgLatencies);
 }
 
 VendorAtom StatsBase::vibratorErrorAtom() {
     STATS_TRACE("vibratorErrorAtom()");
-    std::vector<VendorAtomValue> values(1);
-
-    {
-        std::scoped_lock<std::mutex> lock(mDataAccess);
-        values[0].set<VendorAtomValue::repeatedIntValue>(mErrorCounts);
-    }
-
-    return VendorAtom{
-            .reverseDomainName = "",
-            .atomId = PixelAtoms::Atom::kVibratorErrorsReported,
-            .values = std::move(values),
-    };
+    std::scoped_lock<std::mutex> lock(mDataAccess);
+    return createVendorAtom(VibratorAtoms::VIBRATOR_ERRORS_REPORTED, "", mErrorCounts);
 }
 
 }  // namespace vibrator
diff --git a/vibrator/common/utils.h b/vibrator/common/utils.h
index da0bca9b..b5005a6f 100644
--- a/vibrator/common/utils.h
+++ b/vibrator/common/utils.h
@@ -123,10 +123,12 @@ inline bool getProperty<bool>(const std::string &key, const bool def) {
 
 template <typename T>
 static void openNoCreate(const std::string &file, T *outStream) {
-    auto mode = std::is_base_of_v<std::ostream, T> ? std::ios_base::out : std::ios_base::in;
+    if (!std::filesystem::exists(file)) {
+        ALOGE("File does not exist: %s", file.c_str());
+        return;
+    }
 
-    // Force 'in' mode to prevent file creation
-    outStream->open(file, mode | std::ios_base::in);
+    outStream->open(file);
     if (!*outStream) {
         ALOGE("Failed to open %s (%d): %s", file.c_str(), errno, strerror(errno));
     }
diff --git a/vibrator/cs40l25/Vibrator.cpp b/vibrator/cs40l25/Vibrator.cpp
index 1363dbe1..e786048f 100644
--- a/vibrator/cs40l25/Vibrator.cpp
+++ b/vibrator/cs40l25/Vibrator.cpp
@@ -31,6 +31,7 @@
 #include <sstream>
 
 #include "Stats.h"
+#include "utils.h"
 
 #ifndef ARRAY_SIZE
 #define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
@@ -277,6 +278,21 @@ Vibrator::Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal,
 
     mHwApi->getEffectCount(&effectCount);
     mEffectDurations.resize(effectCount);
+
+    mIsPrimitiveDelayEnabled =
+            utils::getProperty("ro.vendor.vibrator.hal.cs40L25.primitive_delays.enabled", false);
+
+    mDelayEffectDurations.resize(effectCount);
+    if (mIsPrimitiveDelayEnabled) {
+        mDelayEffectDurations = {
+                25, 45, 45, 20, 20, 20, 20, 20,
+        }; /* delays for each effect based on measurements */
+    } else {
+        mDelayEffectDurations = {
+                0, 0, 0, 0, 0, 0, 0, 0,
+        }; /* no delay if property not set */
+    }
+
     for (size_t effectIndex = 0; effectIndex < effectCount; effectIndex++) {
         mHwApi->setEffectIndex(effectIndex);
         uint32_t effectDuration;
@@ -527,6 +543,8 @@ ndk::ScopedAStatus Vibrator::compose(const std::vector<CompositeEffect> &composi
 
             effectBuilder << effectIndex << "." << intensityToVolLevel(e.scale, effectIndex) << ",";
             mTotalDuration += mEffectDurations[effectIndex];
+
+            mTotalDuration += mDelayEffectDurations[effectIndex];
         }
     }
 
diff --git a/vibrator/cs40l25/Vibrator.h b/vibrator/cs40l25/Vibrator.h
index 72908056..e462cce2 100644
--- a/vibrator/cs40l25/Vibrator.h
+++ b/vibrator/cs40l25/Vibrator.h
@@ -239,12 +239,14 @@ class Vibrator : public BnVibrator {
     std::array<uint32_t, 2> mClickEffectVol;
     std::array<uint32_t, 2> mLongEffectVol;
     std::vector<uint32_t> mEffectDurations;
+    std::vector<uint32_t> mDelayEffectDurations;
     std::future<void> mAsyncHandle;
     int32_t mCompositionSizeMax;
     struct pcm *mHapticPcm;
     int mCard;
     int mDevice;
     bool mHasHapticAlsaDevice;
+    bool mIsPrimitiveDelayEnabled;
     bool mIsUnderExternalControl;
     float mResonantFrequency;
     uint32_t mRedc{0};
diff --git a/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25.rc b/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25.rc
index 13834efc..101cae87 100644
--- a/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25.rc
+++ b/vibrator/cs40l25/android.hardware.vibrator-service.cs40l25.rc
@@ -1,4 +1,4 @@
-on boot
+on property:vendor.all.modules.ready=1
     wait /sys/class/leds/vibrator/device
 
     mkdir /mnt/vendor/persist/haptics 0770 system system
diff --git a/vibrator/cs40l25/fuzzer/Android.bp b/vibrator/cs40l25/fuzzer/Android.bp
new file mode 100644
index 00000000..5d990c61
--- /dev/null
+++ b/vibrator/cs40l25/fuzzer/Android.bp
@@ -0,0 +1,38 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_pixel_system_sw_touch_haptic",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_fuzz {
+    name: "VibratorHalCs40l25Fuzzer",
+    relative_install_path: "",
+    defaults: [
+        "VibratorHalCs40l25BinaryDefaults",
+        "service_fuzzer_defaults",
+    ],
+    srcs: [
+        "fuzzer-vibrator.cpp",
+    ],
+    shared_libs: [
+        "android.hardware.vibrator-impl.cs40l25",
+    ],
+    fuzz_config: {
+        triage_assignee: "pixel-haptics-triage@google.com",
+        componentid: 716924,
+    },
+}
diff --git a/vibrator/cs40l25/fuzzer/fuzzer-vibrator.cpp b/vibrator/cs40l25/fuzzer/fuzzer-vibrator.cpp
new file mode 100644
index 00000000..7fad1370
--- /dev/null
+++ b/vibrator/cs40l25/fuzzer/fuzzer-vibrator.cpp
@@ -0,0 +1,55 @@
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
+#include <fuzzbinder/libbinder_ndk_driver.h>
+#include <fuzzer/FuzzedDataProvider.h>
+
+#include "Hardware.h"
+#include "Vibrator.h"
+
+using ::aidl::android::hardware::vibrator::HwApi;
+using ::aidl::android::hardware::vibrator::HwCal;
+using ::aidl::android::hardware::vibrator::Vibrator;
+using android::fuzzService;
+using ndk::SharedRefBase;
+
+// No stats collection.
+class FakeStatsApi : public Vibrator::StatsApi {
+  public:
+    FakeStatsApi() = default;
+    ~FakeStatsApi() = default;
+
+    bool logPrimitive(uint16_t) override { return true; }
+
+    bool logWaveform(uint16_t, int32_t) override { return true; }
+
+    bool logError(uint16_t) override { return true; }
+
+    bool logLatencyStart(uint16_t) override { return true; }
+
+    bool logLatencyEnd() { return true; }
+
+    void debug(int32_t) override {}
+};
+
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
+    auto vibService = ndk::SharedRefBase::make<Vibrator>(
+            std::make_unique<HwApi>(), std::make_unique<HwCal>(), std::make_unique<FakeStatsApi>());
+
+    fuzzService(vibService->asBinder().get(), FuzzedDataProvider(data, size));
+
+    return 0;
+}
diff --git a/vibrator/cs40l26/Hardware.h b/vibrator/cs40l26/Hardware.h
index 8ee3f348..58225c2c 100644
--- a/vibrator/cs40l26/Hardware.h
+++ b/vibrator/cs40l26/Hardware.h
@@ -76,6 +76,9 @@ class HwApi : public Vibrator::HwApi, private HwApiBase {
         open("calibration/q_stored", &mQ);
         open("default/vibe_state", &mVibeState);
         open("default/num_waves", &mEffectCount);
+        open("default/braking_time_bank", &mEffectBrakingTimeBank);
+        open("default/braking_time_index", &mEffectBrakingTimeIndex);
+        open("default/braking_time_ms", &mEffectBrakingTimeMs);
         open("default/owt_free_space", &mOwtFreeSpace);
         open("default/f0_comp_enable", &mF0CompEnable);
         open("default/redc_comp_enable", &mRedcCompEnable);
@@ -87,6 +90,16 @@ class HwApi : public Vibrator::HwApi, private HwApiBase {
     bool setRedc(std::string value) override { return set(value, &mRedc); }
     bool setQ(std::string value) override { return set(value, &mQ); }
     bool getEffectCount(uint32_t *value) override { return get(value, &mEffectCount); }
+    bool hasEffectBrakingTimeBank() override { return has(mEffectBrakingTimeBank); }
+    bool setEffectBrakingTimeBank(uint32_t value) override {
+        return set(value, &mEffectBrakingTimeBank);
+    }
+    bool setEffectBrakingTimeIndex(uint32_t value) override {
+        return set(value, &mEffectBrakingTimeIndex);
+    }
+    bool getEffectBrakingTimeMs(uint32_t *value) override {
+        return get(value, &mEffectBrakingTimeMs);
+    }
     bool pollVibeState(uint32_t value, int32_t timeoutMs) override {
         return poll(value, &mVibeState, timeoutMs);
     }
@@ -437,6 +450,9 @@ class HwApi : public Vibrator::HwApi, private HwApiBase {
     std::ofstream mRedc;
     std::ofstream mQ;
     std::ifstream mEffectCount;
+    std::ofstream mEffectBrakingTimeBank;
+    std::ofstream mEffectBrakingTimeIndex;
+    std::ifstream mEffectBrakingTimeMs;
     std::ifstream mVibeState;
     std::ifstream mOwtFreeSpace;
     std::ofstream mF0CompEnable;
diff --git a/vibrator/cs40l26/Vibrator.cpp b/vibrator/cs40l26/Vibrator.cpp
index 3161528f..81cc5fd7 100644
--- a/vibrator/cs40l26/Vibrator.cpp
+++ b/vibrator/cs40l26/Vibrator.cpp
@@ -29,10 +29,12 @@
 #include <cmath>
 #include <fstream>
 #include <iostream>
+#include <limits>
 #include <map>
 #include <memory>
 #include <optional>
 #include <sstream>
+#include <string_view>
 
 #include "DspMemChunk.h"
 #include "Stats.h"
@@ -83,26 +85,6 @@ static constexpr auto ASYNC_COMPLETION_TIMEOUT = std::chrono::milliseconds(100);
 static constexpr auto POLLING_TIMEOUT = 50;  // POLLING_TIMEOUT < ASYNC_COMPLETION_TIMEOUT
 static constexpr int32_t COMPOSE_DELAY_MAX_MS = 10000;
 
-// Measured resonant frequency, f0_measured, is represented by Q10.14 fixed
-// point format on cs40l26 devices. The expression to calculate f0 is:
-//   f0 = f0_measured / 2^Q14_BIT_SHIFT
-// See the LRA Calibration Support documentation for more details.
-static constexpr int32_t Q14_BIT_SHIFT = 14;
-
-// Measured ReDC. The LRA series resistance (ReDC), expressed as follows
-// redc(ohms) = redc_measured / 2^Q15_BIT_SHIFT.
-// This value represents the unit-specific ReDC input to the click compensation
-// algorithm. It can be overwritten at a later time by writing to the redc_stored
-// sysfs control.
-// See the LRA Calibration Support documentation for more details.
-static constexpr int32_t Q15_BIT_SHIFT = 15;
-
-// Measured Q factor, q_measured, is represented by Q8.16 fixed
-// point format on cs40l26 devices. The expression to calculate q is:
-//   q = q_measured / 2^Q16_BIT_SHIFT
-// See the LRA Calibration Support documentation for more details.
-static constexpr int32_t Q16_BIT_SHIFT = 16;
-
 static constexpr float PWLE_LEVEL_MIN = 0.0;
 static constexpr float PWLE_LEVEL_MAX = 1.0;
 static constexpr float PWLE_FREQUENCY_RESOLUTION_HZ = 1.00;
@@ -167,8 +149,51 @@ static std::map<float, float> discretePwleMaxLevels = {};
 std::vector<float> pwleMaxLevelLimitMap(PWLE_BW_MAP_SIZE, 1.0);
 #endif
 
-static float redcToFloat(std::string *caldata) {
-    return static_cast<float>(std::stoul(*caldata, nullptr, 16)) / (1 << Q15_BIT_SHIFT);
+enum class QValueFormat {
+    FORMAT_7_16,  // Q
+    FORMAT_8_15,  // Redc
+    FORMAT_9_14   // F0
+};
+
+static float qValueToFloat(std::string_view qValueInHex, QValueFormat qValueFormat, bool isSigned) {
+    uint32_t intBits = 0;
+    uint32_t fracBits = 0;
+    switch (qValueFormat) {
+        case QValueFormat::FORMAT_7_16:
+            intBits = 7;
+            fracBits = 16;
+            break;
+        case QValueFormat::FORMAT_8_15:
+            intBits = 8;
+            fracBits = 15;
+            break;
+        case QValueFormat::FORMAT_9_14:
+            intBits = 9;
+            fracBits = 14;
+            break;
+        default:
+            ALOGE("Q Format enum not implemented");
+            return std::numeric_limits<float>::quiet_NaN();
+    }
+
+    uint32_t totalBits = intBits + fracBits + (isSigned ? 1 : 0);
+
+    int valInt = 0;
+    std::stringstream ss;
+    ss << std::hex << qValueInHex;
+    ss >> valInt;
+
+    if (ss.fail() || !ss.eof()) {
+        ALOGE("Invalid hex format: %s", qValueInHex.data());
+        return std::numeric_limits<float>::quiet_NaN();
+    }
+
+    // Handle sign extension if necessary
+    if (isSigned && (valInt & (1 << (totalBits - 1)))) {
+        valInt -= 1 << totalBits;
+    }
+
+    return static_cast<float>(valInt) / (1 << fracBits);
 }
 
 Vibrator::Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal,
@@ -184,12 +209,15 @@ Vibrator::Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal,
 
     mFfEffects.resize(WAVEFORM_MAX_INDEX);
     mEffectDurations.resize(WAVEFORM_MAX_INDEX);
+    mEffectBrakingDurations.resize(WAVEFORM_MAX_INDEX);
     mEffectDurations = {
 #if defined(UNSPECIFIED_ACTUATOR)
             /* For Z-LRA actuators */
-            1000, 100, 25, 1000, 300, 133, 150, 500, 100, 6, 12, 1000, 13, 5,
+            1000, 100, 25, 1000, 247, 166, 150, 500, 100, 6, 17, 1000, 13, 5,
+#elif defined(LEGACY_ZLRA_ACTUATOR)
+            1000, 100, 25, 1000, 150, 100, 150, 500, 100, 6, 25, 1000, 13, 5,
 #else
-            1000, 100, 12, 1000, 300, 133, 150, 500, 100, 5, 12, 1000, 13, 5,
+            1000, 100, 9, 1000, 300, 133, 150, 500, 100, 5, 12, 1000, 13, 5,
 #endif
     }; /* 11+3 waveforms. The duration must < UINT16_MAX */
     mEffectCustomData.reserve(WAVEFORM_MAX_INDEX);
@@ -222,6 +250,11 @@ Vibrator::Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal,
             if (mFfEffects[effectIndex].id != effectIndex) {
                 ALOGW("Unexpected effect index: %d -> %d", effectIndex, mFfEffects[effectIndex].id);
             }
+
+            if (mHwApi->hasEffectBrakingTimeBank()) {
+                mHwApi->setEffectBrakingTimeIndex(effectIndex);
+                mHwApi->getEffectBrakingTimeMs(&mEffectBrakingDurations[effectIndex]);
+            }
         } else {
             /* Initiate placeholders for OWT effects. */
             numBytes = effectIndex == WAVEFORM_COMPOSE ? FF_CUSTOM_DATA_LEN_MAX_COMP
@@ -241,8 +274,7 @@ Vibrator::Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal,
 
     if (mHwCal->getF0(&caldata)) {
         mHwApi->setF0(caldata);
-        mResonantFrequency =
-                static_cast<float>(std::stoul(caldata, nullptr, 16)) / (1 << Q14_BIT_SHIFT);
+        mResonantFrequency = qValueToFloat(caldata, QValueFormat::FORMAT_9_14, false);
     } else {
         mStatsApi->logError(kHwCalError);
         ALOGE("Failed to get resonant frequency (%d): %s, using default resonant HZ: %f", errno,
@@ -251,7 +283,7 @@ Vibrator::Vibrator(std::unique_ptr<HwApi> hwapi, std::unique_ptr<HwCal> hwcal,
     }
     if (mHwCal->getRedc(&caldata)) {
         mHwApi->setRedc(caldata);
-        mRedc = redcToFloat(&caldata);
+        mRedc = qValueToFloat(caldata, QValueFormat::FORMAT_8_15, false);
     }
     if (mHwCal->getQ(&caldata)) {
         mHwApi->setQ(caldata);
@@ -497,7 +529,7 @@ ndk::ScopedAStatus Vibrator::getPrimitiveDuration(CompositePrimitive primitive,
             return status;
         }
 
-        *durationMs = mEffectDurations[effectIndex];
+        *durationMs = mEffectDurations[effectIndex] + mEffectBrakingDurations[effectIndex];
     } else {
         *durationMs = 0;
     }
@@ -509,7 +541,6 @@ ndk::ScopedAStatus Vibrator::compose(const std::vector<CompositeEffect> &composi
     VFTRACE(composite, callback);
     uint16_t size;
     uint16_t nextEffectDelay;
-    uint16_t totalDuration = 0;
 
     mStatsApi->logLatencyStart(kCompositionEffectLatency);
 
@@ -521,7 +552,6 @@ ndk::ScopedAStatus Vibrator::compose(const std::vector<CompositeEffect> &composi
 
     /* Check if there is a wait before the first effect. */
     nextEffectDelay = composite.front().delayMs;
-    totalDuration += nextEffectDelay;
     if (nextEffectDelay > COMPOSE_DELAY_MAX_MS || nextEffectDelay < 0) {
         ALOGE("%s: Invalid delay %u", __func__, nextEffectDelay);
         mStatsApi->logError(kBadCompositeError);
@@ -558,7 +588,6 @@ ndk::ScopedAStatus Vibrator::compose(const std::vector<CompositeEffect> &composi
                 return status;
             }
             effectVolLevel = intensityToVolLevel(e_curr.scale, effectIndex);
-            totalDuration += mEffectDurations[effectIndex];
         }
 
         /* Fetch the next composite effect delay and fill into the current section */
@@ -573,7 +602,6 @@ ndk::ScopedAStatus Vibrator::compose(const std::vector<CompositeEffect> &composi
                 return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
             }
             nextEffectDelay = delay;
-            totalDuration += delay;
         }
 
         if (effectIndex == 0 && nextEffectDelay == 0) {
@@ -581,6 +609,9 @@ ndk::ScopedAStatus Vibrator::compose(const std::vector<CompositeEffect> &composi
             mStatsApi->logError(kBadCompositeError);
             return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
         }
+
+        nextEffectDelay += mEffectBrakingDurations[effectIndex];
+
         mStatsApi->logPrimitive(effectIndex);
         ch.constructComposeSegment(effectVolLevel, effectIndex, 0 /*repeat*/, 0 /*flags*/,
                                    nextEffectDelay /*delay*/);
@@ -819,7 +850,7 @@ ndk::ScopedAStatus Vibrator::getQFactor(float *qFactor) {
         ALOGE("Failed to get q factor (%d): %s", errno, strerror(errno));
         return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
     }
-    *qFactor = static_cast<float>(std::stoul(caldata, nullptr, 16)) / (1 << Q16_BIT_SHIFT);
+    *qFactor = qValueToFloat(caldata, QValueFormat::FORMAT_7_16, false);
 
     return ndk::ScopedAStatus::ok();
 }
@@ -924,7 +955,7 @@ void Vibrator::createBandwidthAmplitudeMap() {
         std::string caldata{8, '0'};
         if (mHwCal->getRedc(&caldata)) {
             mHwApi->setRedc(caldata);
-            mRedc = redcToFloat(&caldata);
+            mRedc = qValueToFloat(caldata, QValueFormat::FORMAT_8_15, false);
         } else {
             mStatsApi->logError(kHwCalError);
             ALOGE("Failed to get resistance value from calibration file");
@@ -1276,11 +1307,11 @@ binder_status_t Vibrator::dump(int fd, const char **args, uint32_t numArgs) {
 
     dprintf(fd, "  FF Effect:\n");
     dprintf(fd, "    Physical Waveform:\n");
-    dprintf(fd, "\tId\tIndex\tt   ->\tt'\n");
+    dprintf(fd, "\tId\tIndex\tt   ->\tt'\tBrake\n");
     for (uint8_t effectId = 0; effectId < WAVEFORM_MAX_PHYSICAL_INDEX; effectId++) {
-        dprintf(fd, "\t%d\t%d\t%d\t%d\n", mFfEffects[effectId].id,
+        dprintf(fd, "\t%d\t%d\t%d\t%d\t%d\n", mFfEffects[effectId].id,
                 mFfEffects[effectId].u.periodic.custom_data[1], mEffectDurations[effectId],
-                mFfEffects[effectId].replay.length);
+                mFfEffects[effectId].replay.length, mEffectBrakingDurations[effectId]);
     }
     dprintf(fd, "    OWT Waveform:\n");
     dprintf(fd, "\tId\tBytes\tData\n");
diff --git a/vibrator/cs40l26/Vibrator.h b/vibrator/cs40l26/Vibrator.h
index 8a9002bb..99261a7d 100644
--- a/vibrator/cs40l26/Vibrator.h
+++ b/vibrator/cs40l26/Vibrator.h
@@ -57,6 +57,15 @@ class Vibrator : public BnVibrator {
         virtual bool setQ(std::string value) = 0;
         // Reports the number of effect waveforms loaded in firmware.
         virtual bool getEffectCount(uint32_t *value) = 0;
+        // Checks whether braking time bank is supported.
+        virtual bool hasEffectBrakingTimeBank() = 0;
+        // Specifies the bank of the effect for querying braking time.
+        // 0: RAM bank, 2: OWT bank
+        virtual bool setEffectBrakingTimeBank(uint32_t value) = 0;
+        // Specifies the index of an effect whose braking time is to be read.
+        virtual bool setEffectBrakingTimeIndex(uint32_t value) = 0;
+        // Gets the braking time duration of SVC effects (returns 0 if not SVC).
+        virtual bool getEffectBrakingTimeMs(uint32_t *value) = 0;
         // Blocks until timeout or vibrator reaches desired state
         // (2 = ASP enabled, 1 = haptic enabled, 0 = disabled).
         virtual bool pollVibeState(uint32_t value, int32_t timeoutMs = -1) = 0;
@@ -251,6 +260,7 @@ class Vibrator : public BnVibrator {
     std::array<uint32_t, 2> mLongEffectVol;
     std::vector<ff_effect> mFfEffects;
     std::vector<uint32_t> mEffectDurations;
+    std::vector<uint32_t> mEffectBrakingDurations;
     std::vector<std::vector<int16_t>> mEffectCustomData;
     std::future<void> mAsyncHandle;
     int8_t mActiveId{-1};
diff --git a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26-dual.rc b/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26-dual.rc
index 6ea9d3b9..d48e7ee7 100644
--- a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26-dual.rc
+++ b/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26-dual.rc
@@ -13,6 +13,9 @@ service vendor.vibrator.cs40l26-dual /vendor/bin/hw/android.hardware.vibrator-se
         calibration/q_stored
         default/vibe_state
         default/num_waves
+        default/braking_time_bank
+        default/braking_time_index
+        default/braking_time_ms
         default/f0_offset
         default/owt_free_space
         default/f0_comp_enable
diff --git a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26.rc b/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26.rc
index 9a46abce..ccf35d83 100644
--- a/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26.rc
+++ b/vibrator/cs40l26/android.hardware.vibrator-service.cs40l26.rc
@@ -13,6 +13,9 @@ service vendor.vibrator.cs40l26 /vendor/bin/hw/android.hardware.vibrator-service
         calibration/q_stored
         default/vibe_state
         default/num_waves
+        default/braking_time_bank
+        default/braking_time_index
+        default/braking_time_ms
         default/f0_offset
         default/owt_free_space
         default/f0_comp_enable
diff --git a/vibrator/cs40l26/fuzzer/Android.bp b/vibrator/cs40l26/fuzzer/Android.bp
new file mode 100644
index 00000000..c60c8bf9
--- /dev/null
+++ b/vibrator/cs40l26/fuzzer/Android.bp
@@ -0,0 +1,39 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_pixel_system_sw_touch_haptic",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_fuzz {
+    name: "VibratorHalCs40l26Fuzzer",
+    relative_install_path: "",
+    defaults: [
+        "VibratorHalCs40l26BinaryDefaults",
+        "VibratorCapoDefaults",
+        "service_fuzzer_defaults",
+    ],
+    srcs: [
+        "fuzzer-vibrator.cpp",
+    ],
+    shared_libs: [
+        "android.hardware.vibrator-impl.cs40l26",
+    ],
+    fuzz_config: {
+        triage_assignee: "pixel-haptics-triage@google.com",
+        componentid: 716924,
+    },
+}
diff --git a/vibrator/cs40l26/fuzzer/fuzzer-vibrator.cpp b/vibrator/cs40l26/fuzzer/fuzzer-vibrator.cpp
new file mode 100644
index 00000000..7fad1370
--- /dev/null
+++ b/vibrator/cs40l26/fuzzer/fuzzer-vibrator.cpp
@@ -0,0 +1,55 @@
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
+#include <fuzzbinder/libbinder_ndk_driver.h>
+#include <fuzzer/FuzzedDataProvider.h>
+
+#include "Hardware.h"
+#include "Vibrator.h"
+
+using ::aidl::android::hardware::vibrator::HwApi;
+using ::aidl::android::hardware::vibrator::HwCal;
+using ::aidl::android::hardware::vibrator::Vibrator;
+using android::fuzzService;
+using ndk::SharedRefBase;
+
+// No stats collection.
+class FakeStatsApi : public Vibrator::StatsApi {
+  public:
+    FakeStatsApi() = default;
+    ~FakeStatsApi() = default;
+
+    bool logPrimitive(uint16_t) override { return true; }
+
+    bool logWaveform(uint16_t, int32_t) override { return true; }
+
+    bool logError(uint16_t) override { return true; }
+
+    bool logLatencyStart(uint16_t) override { return true; }
+
+    bool logLatencyEnd() { return true; }
+
+    void debug(int32_t) override {}
+};
+
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
+    auto vibService = ndk::SharedRefBase::make<Vibrator>(
+            std::make_unique<HwApi>(), std::make_unique<HwCal>(), std::make_unique<FakeStatsApi>());
+
+    fuzzService(vibService->asBinder().get(), FuzzedDataProvider(data, size));
+
+    return 0;
+}
diff --git a/vibrator/cs40l26/tests/Android.bp b/vibrator/cs40l26/tests/Android.bp
index 86215373..348c9d5f 100644
--- a/vibrator/cs40l26/tests/Android.bp
+++ b/vibrator/cs40l26/tests/Android.bp
@@ -19,7 +19,10 @@ package {
 
 cc_test {
     name: "VibratorHalCs40l26TestSuite",
-    defaults: ["VibratorHalCs40l26TestDefaults"],
+    defaults: [
+        "VibratorHalCs40l26TestDefaults",
+        "haptics_feature_defaults",
+    ],
     srcs: [
         "test-hwcal.cpp",
         "test-hwapi.cpp",
diff --git a/vibrator/cs40l26/tests/mocks.h b/vibrator/cs40l26/tests/mocks.h
index 0837938c..da8daf45 100644
--- a/vibrator/cs40l26/tests/mocks.h
+++ b/vibrator/cs40l26/tests/mocks.h
@@ -28,6 +28,10 @@ class MockApi : public ::aidl::android::hardware::vibrator::Vibrator::HwApi {
     MOCK_METHOD1(setRedc, bool(std::string value));
     MOCK_METHOD1(setQ, bool(std::string value));
     MOCK_METHOD1(getEffectCount, bool(uint32_t *value));
+    MOCK_METHOD0(hasEffectBrakingTimeBank, bool());
+    MOCK_METHOD1(setEffectBrakingTimeBank, bool(uint32_t value));
+    MOCK_METHOD1(setEffectBrakingTimeIndex, bool(uint32_t value));
+    MOCK_METHOD1(getEffectBrakingTimeMs, bool(uint32_t *value));
     MOCK_METHOD2(pollVibeState, bool(uint32_t value, int32_t timeoutMs));
     MOCK_METHOD0(hasOwtFreeSpace, bool());
     MOCK_METHOD1(getOwtFreeSpace, bool(uint32_t *value));
diff --git a/vibrator/cs40l26/tests/test-vibrator.cpp b/vibrator/cs40l26/tests/test-vibrator.cpp
index 698b68e1..76cb897a 100644
--- a/vibrator/cs40l26/tests/test-vibrator.cpp
+++ b/vibrator/cs40l26/tests/test-vibrator.cpp
@@ -75,7 +75,14 @@ static constexpr std::array<EffectLevel, 2> V_TICK_DEFAULT = {1, 100};
 static constexpr std::array<EffectLevel, 2> V_CLICK_DEFAULT{1, 100};
 static constexpr std::array<EffectLevel, 2> V_LONG_DEFAULT{1, 100};
 static constexpr std::array<EffectDuration, 14> EFFECT_DURATIONS{
-        0, 100, 12, 1000, 300, 133, 150, 500, 100, 5, 12, 1000, 1000, 1000};
+#if defined(UNSPECIFIED_ACTUATOR)
+        /* For Z-LRA actuators */
+        1000, 100, 25, 1000, 247, 166, 150, 500, 100, 6, 17, 1000, 13, 5};
+#elif defined(LEGACY_ZLRA_ACTUATOR)
+        1000, 100, 25, 1000, 150, 100, 150, 500, 100, 6, 25, 1000, 13, 5};
+#else
+        1000, 100, 9, 1000, 300, 133, 150, 500, 100, 5, 12, 1000, 13, 5};
+#endif
 
 // Constants With Prescribed Values
 
@@ -395,6 +402,11 @@ TEST_F(VibratorTest, Constructor) {
 
     EXPECT_CALL(*mMockApi, setMinOnOffInterval(MIN_ON_OFF_INTERVAL_US)).WillOnce(Return(true));
     EXPECT_CALL(*mMockApi, hasOwtFreeSpace()).WillOnce(Return(true));
+    EXPECT_CALL(*mMockApi, setEffectBrakingTimeBank(0)).WillRepeatedly(Return(true));
+    for (uint32_t i = 0; i < WAVEFORM_MAX_PHYSICAL_INDEX; i++) {
+        EXPECT_CALL(*mMockApi, setEffectBrakingTimeIndex(i)).WillRepeatedly(Return(true));
+        EXPECT_CALL(*mMockApi, getEffectBrakingTimeMs(_)).WillRepeatedly(Return(true));
+    }
     EXPECT_CALL(*mMockApi, getHapticAlsaDevice(_, _)).WillOnce(Return(true));
     EXPECT_CALL(*mMockApi, getContextScale()).WillRepeatedly(Return(0));
     EXPECT_CALL(*mMockApi, getContextEnable()).WillRepeatedly(Return(false));
diff --git a/vibrator/drv2624/fuzzer/Android.bp b/vibrator/drv2624/fuzzer/Android.bp
new file mode 100644
index 00000000..ae8df095
--- /dev/null
+++ b/vibrator/drv2624/fuzzer/Android.bp
@@ -0,0 +1,38 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_pixel_system_sw_touch_haptic",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_fuzz {
+    name: "VibratorHalDrv2624Fuzzer",
+    relative_install_path: "",
+    defaults: [
+        "VibratorHalDrv2624BinaryDefaults",
+        "service_fuzzer_defaults",
+    ],
+    srcs: [
+        "fuzzer-vibrator.cpp",
+    ],
+    shared_libs: [
+        "android.hardware.vibrator-impl.drv2624",
+    ],
+    fuzz_config: {
+        triage_assignee: "pixel-haptics-triage@google.com",
+        componentid: 716924,
+    },
+}
diff --git a/vibrator/drv2624/fuzzer/fuzzer-vibrator.cpp b/vibrator/drv2624/fuzzer/fuzzer-vibrator.cpp
new file mode 100644
index 00000000..d1b400ac
--- /dev/null
+++ b/vibrator/drv2624/fuzzer/fuzzer-vibrator.cpp
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
+#include <fuzzbinder/libbinder_ndk_driver.h>
+#include <fuzzer/FuzzedDataProvider.h>
+
+#include "Hardware.h"
+#include "Vibrator.h"
+
+using ::aidl::android::hardware::vibrator::HwApi;
+using ::aidl::android::hardware::vibrator::HwCal;
+using ::aidl::android::hardware::vibrator::Vibrator;
+using android::fuzzService;
+using ndk::SharedRefBase;
+
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
+    std::shared_ptr<Vibrator> vibService =
+            ndk::SharedRefBase::make<Vibrator>(HwApi::Create(), std::make_unique<HwCal>());
+
+    fuzzService(vibService->asBinder().get(), FuzzedDataProvider(data, size));
+
+    return 0;
+}
```

