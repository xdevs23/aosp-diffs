```diff
diff --git a/atrace/atrace_categories.txt b/atrace/atrace_categories.txt
index 479d76de..6a93d0e2 100644
--- a/atrace/atrace_categories.txt
+++ b/atrace/atrace_categories.txt
@@ -31,6 +31,8 @@ gfx
  mali/mali_KCPU_CQS_SET
  mali/mali_KCPU_CQS_WAIT_BEGIN
  mali/mali_KCPU_CQS_WAIT_END
+ power/gpu_frequency
+ power/gpu_work_period
 memory
  fastrpc/fastrpc_dma_stat
  dmabuf_heap/dma_heap_stat
diff --git a/atrace/generate_rc.py b/atrace/generate_rc.py
index e18a734e..48594d21 100755
--- a/atrace/generate_rc.py
+++ b/atrace/generate_rc.py
@@ -7,7 +7,9 @@ parser.add_argument("filename", help="Path to the atrace_categories.txt file")
 
 args = parser.parse_args()
 
-print("# Sets permission for vendor ftrace events")
+on_boot_events = ["mali/", "power/gpu_work_period", "power/gpu_frequency"]
+
+print("# Sets permission for vendor ftrace events on late-init")
 print("on late-init")
 
 with open(args.filename, 'r') as f:
@@ -15,7 +17,29 @@ with open(args.filename, 'r') as f:
     line = line.rstrip('\n')
     if line.startswith(' ') or line.startswith('\t'):
       path = line.lstrip(" \t")
+
+      if any(path.startswith(event) for event in on_boot_events):
+        continue
+
       print("    chmod 0666 /sys/kernel/debug/tracing/events/{}/enable".format(path))
       print("    chmod 0666 /sys/kernel/tracing/events/{}/enable".format(path))
     else:
       print ("    # {} trace points".format(line))
+
+print("# Sets permission for vendor ftrace events on boot")
+print("on boot")
+
+with open(args.filename, 'r') as f:
+  for line in f:
+    line = line.rstrip('\n')
+    if not line.startswith(' ') or line.startswith('\t'):
+      print ("    # {} trace points".format(line))
+      continue
+
+    path = line.lstrip(" \t")
+
+    if not any(path.startswith(event) for event in on_boot_events):
+      continue
+
+    print("    chmod 0666 /sys/kernel/debug/tracing/events/{}/enable".format(path))
+    print("    chmod 0666 /sys/kernel/tracing/events/{}/enable".format(path))
diff --git a/common/init.pixel.rc b/common/init.pixel.rc
index 792793c0..dce772e7 100644
--- a/common/init.pixel.rc
+++ b/common/init.pixel.rc
@@ -2,6 +2,7 @@
 service vendor.theme_set /vendor/bin/misc_writer --set-dark-theme
     disabled
     oneshot
+    user root
 
 # Set dark boot flag when the device is provisioned.
 on property:persist.sys.device_provisioned=1
@@ -11,6 +12,7 @@ on property:persist.sys.device_provisioned=1
 service vendor.display_mode_set /vendor/bin/misc_writer --set-display-mode ${vendor.display.primary.boot_config}
     disabled
     oneshot
+    user root
 
 # Set preferred mode when resolution property changes
 on property:vendor.display.primary.boot_config=*
diff --git a/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk b/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk
index 9f6c95e7..46bf5d14 100644
--- a/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk
+++ b/connectivity_thermal_power_manager/connectivity_thermal_power_manager.mk
@@ -4,6 +4,4 @@ $(call soong_config_set,connectivity_thermal_power_manager_config,use_alcedo_mod
 ifeq ($(USES_ALCEDO_MODEM),true)
 PRODUCT_PACKAGES += ConnectivityThermalPowerManagerNextgen
 PRODUCT_PACKAGES_DEBUG += mipc_util
-else
-PRODUCT_PACKAGES += ConnectivityThermalPowerManager
 endif
diff --git a/fastboot/Fastboot.cpp b/fastboot/Fastboot.cpp
index 913d82d0..7d823360 100644
--- a/fastboot/Fastboot.cpp
+++ b/fastboot/Fastboot.cpp
@@ -46,6 +46,8 @@ namespace implementation {
 constexpr const char* BRIGHTNESS_FILE = "/sys/class/backlight/panel0-backlight/brightness";
 constexpr int DISPLAY_BRIGHTNESS_DIM_THRESHOLD = 20;
 
+bool WipeDigitalCarKeys(void);
+
 using  OEMCommandHandler = std::function<Result(const std::vector<std::string>&)>;
 
 Return<void> Fastboot::getPartitionType(const ::android::hardware::hidl_string& /* partitionName */,
@@ -108,10 +110,23 @@ Result SetBrightnessLevel(const std::vector<std::string>& args) {
     return { Status::FAILURE_UNKNOWN, "Unable to set display brightness" };
 }
 
+Result DckWipe(const std::vector<std::string> &args) {
+    if (args.size()) {
+        return {Status::INVALID_ARGUMENT, "extraneois parameters for dck_wipe"};
+    }
+
+    if (WipeDigitalCarKeys()) {
+        return {Status::SUCCESS, ""};
+    }
+
+    return {Status::FAILURE_UNKNOWN, "clearing digital car keys failed"};
+}
+
 Return<void> Fastboot::doOemCommand(const ::android::hardware::hidl_string& oemCmdArgs,
                           doOemCommand_cb _hidl_cb) {
     const std::unordered_map<std::string, OEMCommandHandler> kOEMCmdMap = {
-        {FB_OEM_SET_BRIGHTNESS, SetBrightnessLevel},
+            {FB_OEM_SET_BRIGHTNESS, SetBrightnessLevel},
+            {FB_OEM_DCK_WIPE, DckWipe},
     };
 
     auto args = android::base::Split(oemCmdArgs, " ");
diff --git a/fastboot/Fastboot_aidl.cpp b/fastboot/Fastboot_aidl.cpp
index 32df5f36..1a07f8d5 100644
--- a/fastboot/Fastboot_aidl.cpp
+++ b/fastboot/Fastboot_aidl.cpp
@@ -47,6 +47,8 @@ namespace fastboot {
 constexpr const char *BRIGHTNESS_FILE = "/sys/class/backlight/panel0-backlight/brightness";
 constexpr int DISPLAY_BRIGHTNESS_DIM_THRESHOLD = 20;
 
+bool WipeDigitalCarKeys(void);
+
 using OEMCommandHandler =
         std::function<ScopedAStatus(const std::vector<std::string> &, std::string *)>;
 
@@ -126,9 +128,25 @@ ScopedAStatus SetBrightnessLevel(const std::vector<std::string> &args, std::stri
                                                               message.c_str());
 }
 
+ScopedAStatus DckWipe(const std::vector<std::string> &args, std::string *_aidl_return) {
+    if (args.size()) {
+        return ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
+                                                           "extraneois parameters for dck_wipe");
+    }
+
+    if (WipeDigitalCarKeys()) {
+        *_aidl_return = "";
+        return ScopedAStatus::ok();
+    }
+
+    return ScopedAStatus::fromServiceSpecificErrorWithMessage(BnFastboot::FAILURE_UNKNOWN,
+                                                              "clearing digital car keys failed");
+}
+
 ScopedAStatus Fastboot::doOemCommand(const std::string &in_oemCmd, std::string *_aidl_return) {
     const std::unordered_map<std::string, OEMCommandHandler> kOEMCmdMap = {
             {FB_OEM_SET_BRIGHTNESS, SetBrightnessLevel},
+            {FB_OEM_DCK_WIPE, DckWipe},
     };
 
     auto args = ::android::base::Split(in_oemCmd, " ");
diff --git a/fastboot/include/fastboot/Fastboot.h b/fastboot/include/fastboot/Fastboot.h
index 2e3afb19..8744c611 100644
--- a/fastboot/include/fastboot/Fastboot.h
+++ b/fastboot/include/fastboot/Fastboot.h
@@ -27,6 +27,7 @@ namespace V1_1 {
 namespace implementation {
 
 #define FB_OEM_SET_BRIGHTNESS "setbrightness"
+#define FB_OEM_DCK_WIPE "dck_wipe"
 
 using ::android::hardware::hidl_vec;
 using ::android::hardware::Return;
diff --git a/fastboot/include/fastboot/Fastboot_aidl.h b/fastboot/include/fastboot/Fastboot_aidl.h
index 51ae7380..5761f3c8 100644
--- a/fastboot/include/fastboot/Fastboot_aidl.h
+++ b/fastboot/include/fastboot/Fastboot_aidl.h
@@ -24,6 +24,7 @@ namespace hardware {
 namespace fastboot {
 class Fastboot : public BnFastboot {
 #define FB_OEM_SET_BRIGHTNESS "setbrightness"
+#define FB_OEM_DCK_WIPE "dck_wipe"
     ::ndk::ScopedAStatus doOemCommand(const std::string &in_oemCmd,
                                       std::string *_aidl_return) override;
     ::ndk::ScopedAStatus doOemSpecificErase() override;
diff --git a/health/OWNERS b/health/OWNERS
index 7a238ea8..349caed0 100644
--- a/health/OWNERS
+++ b/health/OWNERS
@@ -1,4 +1,3 @@
-tstrudel@google.com
 stayfan@google.com
 apelosi@google.com
 vincentwang@google.com
diff --git a/misc_writer/Android.bp b/misc_writer/Android.bp
index 40aac497..a7184d64 100644
--- a/misc_writer/Android.bp
+++ b/misc_writer/Android.bp
@@ -18,6 +18,28 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+soong_config_module_type {
+    name: "misc_writer_cc_defaults",
+    module_type: "cc_defaults",
+    config_namespace: "misc_writer",
+    bool_variables: ["enable_sota_boot"],
+    properties: ["cflags"],
+}
+
+soong_config_bool_variable {
+    name: "enable_sota_boot",
+}
+
+misc_writer_cc_defaults {
+    name: "misc_writer_config_defaults",
+    vendor: true,
+    soong_config_variables: {
+        enable_sota_boot: {
+            cflags: ["-DENABLE_SOTA_BOOT=1"],
+        },
+    },
+}
+
 cc_defaults {
     name: "misc_writer_defaults",
     vendor: true,
@@ -71,6 +93,7 @@ cc_library_static {
     name: "libmisc_writer_vendor",
     defaults: [
         "misc_writer_defaults",
+        "misc_writer_config_defaults",
     ],
 
     srcs: [
diff --git a/misc_writer/include/misc_writer/misc_writer.h b/misc_writer/include/misc_writer/misc_writer.h
index 46554b33..c98704a3 100644
--- a/misc_writer/include/misc_writer/misc_writer.h
+++ b/misc_writer/include/misc_writer/misc_writer.h
@@ -48,8 +48,10 @@ enum class MiscWriterActions : int32_t {
   kSetDisplayMode,
   kClearDisplayMode,
   kWriteEagleEyePatterns,
+  kWipeFloodStatus,
   kSetDisableFaceauthEval,
   kClearDisableFaceauthEval,
+  kSetSotaBootFlag,
 
   kUnset = -1,
 };
@@ -75,8 +77,14 @@ class MiscWriter {
         char user_preferred_resolution[32];
         char sota_csku[8];
         char sota_csku_signature[96];
-        char eagleEye[32];
+        char flood_skip;
+        char flood_hit;
+        char reserve[30]; // not used
         char skipUnbootableCheck[32];
+        char sota_boot[32];
+        char reserve2[448]; // not used
+        char ramdump[48];
+        char eagleEye[2240];
     } __attribute__((__packed__)) bootloader_message_vendor_t;
 
     static constexpr uint32_t kThemeFlagOffsetInVendorSpace =
@@ -125,6 +133,11 @@ class MiscWriter {
     static constexpr char kDisplayModePrefix[] = "mode=";
     static constexpr uint32_t kEagleEyeOffset =
             offsetof(bootloader_message_vendor_t, eagleEye);
+    static constexpr uint32_t kFloodOffset =
+            offsetof(bootloader_message_vendor_t, flood_skip);
+    static constexpr char kSotaBoot[] = "sota-boot=1";
+    static constexpr uint32_t kSotaBootOffsetInVendorSpace =
+            offsetof(bootloader_message_vendor_t, sota_boot);
 
     // Minimum and maximum valid value for max-ram-size
     static constexpr int32_t kRamSizeDefault = -1;
diff --git a/misc_writer/misc_writer.cpp b/misc_writer/misc_writer.cpp
index 16876e99..cb64f5af 100644
--- a/misc_writer/misc_writer.cpp
+++ b/misc_writer/misc_writer.cpp
@@ -129,6 +129,10 @@ bool MiscWriter::PerformAction(std::optional<size_t> override_offset) {
         content = stringdata_;
         content.resize(sizeof(bootloader_message_vendor_t::eagleEye), 0);
         break;
+    case MiscWriterActions::kWipeFloodStatus:
+        offset = override_offset.value_or(kFloodOffset);
+        content = std::string(2, 0);
+        break;
     case MiscWriterActions::kSetDisableFaceauthEval:
     case MiscWriterActions::kClearDisableFaceauthEval:
         offset = override_offset.value_or(kFaceauthEvalValOffsetInVendorSpace);
@@ -137,6 +141,10 @@ bool MiscWriter::PerformAction(std::optional<size_t> override_offset) {
                           : std::string(32, 0);
         content.resize(32, 0);
         break;
+    case MiscWriterActions::kSetSotaBootFlag:
+        offset = override_offset.value_or(kSotaBootOffsetInVendorSpace);
+        content = kSotaBoot;
+        break;
     case MiscWriterActions::kUnset:
       LOG(ERROR) << "The misc writer action must be set";
       return false;
@@ -147,6 +155,18 @@ bool MiscWriter::PerformAction(std::optional<size_t> override_offset) {
     LOG(ERROR) << "Failed to write " << content << " at offset " << offset << " : " << err;
     return false;
   }
+
+#if ENABLE_SOTA_BOOT
+  if (action_ == MiscWriterActions::kSetSotaFlag) {
+    offset = override_offset.value_or(kSotaBootOffsetInVendorSpace);
+    content = kSotaBoot;
+    if (std::string err;
+      !WriteMiscPartitionVendorSpace(content.data(), content.size(), offset, &err)) {
+    LOG(ERROR) << "Failed to write " << content << " at offset " << offset << " : " << err;
+    return false;
+    }
+  }
+#endif //ENABLE_SOTA_BOOT
   return true;
 }
 
diff --git a/misc_writer/misc_writer_main.cpp b/misc_writer/misc_writer_main.cpp
index e52b4dc6..25865978 100644
--- a/misc_writer/misc_writer_main.cpp
+++ b/misc_writer/misc_writer_main.cpp
@@ -19,6 +19,7 @@
 #include <stdlib.h>
 
 #include <iostream>
+#include <vector>
 #include <map>
 #include <memory>
 #include <optional>
@@ -58,8 +59,10 @@ static int Usage(std::string_view name) {
   std::cerr << "  --set-display-mode <mode>     Write the display mode at boot\n";
   std::cerr << "  --clear-display-mode          Clear the display mode at boot\n";
   std::cerr << "  --set-trending-issue-pattern <string within 2000 byte> Write a regex string";
+  std::cerr << "  --wipe-flood-status           Clear flood status";
   std::cerr << "  --set-disable-faceauth-eval   Write disable-faceauth-eval flag\n";
   std::cerr << "  --clear-disable-faceauth-eval Clear disable-faceauth-eval flag\n";
+  std::cerr << "  --set-sota-boot      Set sota boot flag\n";
   std::cerr << "Writes the given hex string to the specified offset in vendor space in /misc "
                "partition.\nDefault offset is used for each action unless "
                "--override-vendor-space-offset is specified.\n";
@@ -91,6 +94,8 @@ int main(int argc, char** argv) {
     { "set-disable-faceauth-eval", no_argument, nullptr, 0 },
     { "clear-disable-faceauth-eval", no_argument, nullptr, 0 },
     { "set-trending-issue-pattern", required_argument, nullptr, 0 },
+    { "wipe-flood-status", no_argument, nullptr, 0 },
+    { "set-sota-boot", no_argument, nullptr, 0 },
     { nullptr, 0, nullptr, 0 },
   };
 
@@ -106,6 +111,7 @@ int main(int argc, char** argv) {
     { "clear-display-mode", MiscWriterActions::kClearDisplayMode },
     { "set-disable-faceauth-eval", MiscWriterActions::kSetDisableFaceauthEval },
     { "clear-disable-faceauth-eval", MiscWriterActions::kClearDisableFaceauthEval },
+    { "set-sota-boot", MiscWriterActions::kSetSotaBootFlag },
   };
 
   std::unique_ptr<MiscWriter> misc_writer;
@@ -259,18 +265,18 @@ int main(int argc, char** argv) {
       misc_writer = std::make_unique<MiscWriter>(MiscWriterActions::kWriteDstOffset,
                                                      std::to_string(dst_offset));
     } else if (option_name == "set-trending-issue-pattern"s) {
-      if (argc != 3) {
-        std::cerr << "Not the right amount of arguements, we expect 1 argument but were provide " << argc - 2;
-        return EXIT_FAILURE;
+      std::vector<char> merged;
+      for (int j = 2 ; j < argc ; j++) {
+        for (int i = 0 ; argv[j][i] != '\0'; ++i) {
+            merged.push_back(argv[j][i]);
+        }
+        merged.push_back('\0');
       }
-      if (misc_writer) {
-        LOG(ERROR) << "Misc writer action has already been set";
-        return Usage(argv[0]);
-      } else if (sizeof(argv[2]) >= 32) {
-        std::cerr << "String is too large, we only take strings smaller than 32, but you provide " << sizeof(argv[2]);
-        return Usage(argv[0]);
-      }
-      misc_writer = std::make_unique<MiscWriter>(MiscWriterActions::kWriteEagleEyePatterns, argv[2]);
+      std::string msg;
+      msg.assign(merged.begin(), merged.end());
+      misc_writer = std::make_unique<MiscWriter>(MiscWriterActions::kWriteEagleEyePatterns, msg);
+    } else if (option_name == "wipe-flood-status"s) {
+      misc_writer = std::make_unique<MiscWriter>(MiscWriterActions::kWipeFloodStatus, "\0\0");
     } else {
       LOG(FATAL) << "Unreachable path, option_name: " << option_name;
     }
diff --git a/mm/pixel-mm-gki.rc b/mm/pixel-mm-gki.rc
index 9f6fd2da..6c5354bb 100644
--- a/mm/pixel-mm-gki.rc
+++ b/mm/pixel-mm-gki.rc
@@ -29,55 +29,49 @@ on property:sys.boot_completed=1 && property:persist.vendor.boot.zram.size=*
 
 on property:sys.boot_completed=1
     swapon_all /vendor/etc/fstab.zram.${vendor.zram.size}
-
-on property:sys.boot_completed=1
     chmod 444 /sys/kernel/debug/page_owner
+    # Allow max_usage_kb to be reset by system processes
+    chown system system /sys/kernel/vendor_mm/gcma_heap/trusty:faceauth_rawimage_heap/max_usage_kb
+    chmod 0660 /sys/kernel/vendor_mm/gcma_heap/trusty:faceauth_rawimage_heap/max_usage_kb
 
-    # Create mm_event trace point.
-    # For legacy devices, only mm_event is using this trace instance.
-    # Debugfs is only used in legacy devices and going to be deprecated.
-    # If others want to put more,it should get hard review from pixel-perf-team.
+on property:ro.debuggable=1 && property:sys.boot_completed=1
+    # Only enable pixel mm trace point in debug builds.
+    # If others want to put more events, it should get hard review from pixel-perf-team.
     mkdir /sys/kernel/tracing/instances/pixel 0755 system system
     chown system system /sys/kernel/tracing/instances/pixel/trace
     chmod 0660 /sys/kernel/tracing/instances/pixel/trace
     chown system system /sys/kernel/tracing/instances/pixel/tracing_on
     chmod 0660 /sys/kernel/tracing/instances/pixel/tracing_on
-    write /sys/kernel/tracing/instances/pixel/buffer_size_kb 64
+    write /sys/kernel/tracing/instances/pixel/buffer_size_kb 7
     write /sys/kernel/tracing/instances/pixel/events/cma/cma_alloc_busy_retry/enable 1
     write /sys/kernel/tracing/instances/pixel/events/cma/cma_alloc_start/enable 1
-    write /sys/kernel/tracing/instances/pixel/events/cma/cma_alloc_info/enable 1
+    write /sys/kernel/tracing/instances/pixel/events/cma/cma_alloc_finish/enable 1
     write /sys/kernel/tracing/instances/pixel/events/cma/cma_release/enable 1
-    write /sys/kernel/tracing/instances/pixel/events/chunk_heap/enable 1
-    write /sys/kernel/tracing/instances/pixel/events/dmabuf_heap/dma_buf_release/enable 1
-    write /sys/kernel/tracing/instances/pixel/events/trusty/trusty_dma_buf_put/enable 1
-
-    # Allow max_usage_kb to be reset by system processes
-    chown system system /sys/kernel/vendor_mm/gcma_heap/trusty:faceauth_rawimage_heap/max_usage_kb
-    chmod 0660 /sys/kernel/vendor_mm/gcma_heap/trusty:faceauth_rawimage_heap/max_usage_kb
 
 # turns off tracing right before bugreporting to keep more traces
-on property:init.svc.dumpstatez=running
+on property:ro.debuggable=1 && property:init.svc.dumpstatez=running
     write /sys/kernel/tracing/instances/pixel/tracing_on 0
 
-on property:init.svc.dumpstatez=stopped
+on property:ro.debuggable=1 && property:init.svc.dumpstatez=stopped
     write /sys/kernel/tracing/instances/pixel/tracing_on 1
 
-on property:init.svc.bugreport=running
+on property:ro.debuggable=1 && property:init.svc.bugreport=running
     write /sys/kernel/tracing/instances/pixel/tracing_on 0
 
-on property:init.svc.bugreport=stopped
+on property:ro.debuggable=1 && property:init.svc.bugreport=stopped
     write /sys/kernel/tracing/instances/pixel/tracing_on 1
 
-on property:init.svc.bugreportd=running
+on property:ro.debuggable=1 && property:init.svc.bugreportd=running
     write /sys/kernel/tracing/instances/pixel/tracing_on 0
 
-on property:init.svc.bugreportd=stopped
+on property:ro.debuggable=1 && property:init.svc.bugreportd=stopped
     write /sys/kernel/tracing/instances/pixel/tracing_on 1
 
 # max-ram-size experiment
 service vendor.set_max_ram_size /vendor/bin/misc_writer --set-max-ram-size ${persist.device_config.vendor_system_native_boot.max_ram_size:--1}
     disabled
     oneshot
+    user root
 
 on property:persist.device_config.vendor_system_native_boot.max_ram_size=*
     start vendor.set_max_ram_size
diff --git a/pixelstats/Android.bp b/pixelstats/Android.bp
index 29fdc323..87590f83 100644
--- a/pixelstats/Android.bp
+++ b/pixelstats/Android.bp
@@ -157,11 +157,13 @@ cc_library {
         "BatteryEEPROMReporter.cpp",
         "BatteryHealthReporter.cpp",
         "BatteryFGReporter.cpp",
+        "BatteryFwUpdateReporter.cpp",
         "BatteryTTFReporter.cpp",
         "BrownoutDetectedReporter.cpp",
         "ChargeStatsReporter.cpp",
         "DisplayStatsReporter.cpp",
         "DropDetect.cpp",
+        "JsonConfigUtils.cpp",
         "MmMetricsReporter.cpp",
         "MitigationStatsReporter.cpp",
         "MitigationDurationReporter.cpp",
@@ -189,6 +191,7 @@ cc_library {
         "libutils",
         "libsensorndkbridge",
         "pixelatoms-cpp",
+        "libjsoncpp",
     ],
     export_shared_lib_headers: [
         "android.frameworks.stats-V2-ndk",
diff --git a/pixelstats/BatteryCapacityReporter.cpp b/pixelstats/BatteryCapacityReporter.cpp
index 76c54bb4..af6598d5 100644
--- a/pixelstats/BatteryCapacityReporter.cpp
+++ b/pixelstats/BatteryCapacityReporter.cpp
@@ -194,9 +194,7 @@ void BatteryCapacityReporter::reportEvent(const std::shared_ptr<IStats> &stats_c
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kFgCapacity,
                         .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report to IStats service");
+    reportVendorAtom(stats_client, event);
 }
 
 }  // namespace pixel
diff --git a/pixelstats/BatteryEEPROMReporter.cpp b/pixelstats/BatteryEEPROMReporter.cpp
index cce74488..0167d615 100644
--- a/pixelstats/BatteryEEPROMReporter.cpp
+++ b/pixelstats/BatteryEEPROMReporter.cpp
@@ -45,7 +45,7 @@ using android::hardware::google::pixel::PixelAtoms::BatteryEEPROM;
 
 BatteryEEPROMReporter::BatteryEEPROMReporter() {}
 
-bool BatteryEEPROMReporter::ReadFileToInt(const std::string &path, int16_t *val) {
+bool BatteryEEPROMReporter::ReadFileToInt(const std::string &path, int32_t *val) {
     std::string file_contents;
 
     if (!ReadFileToString(path.c_str(), &file_contents)) {
@@ -62,12 +62,18 @@ bool BatteryEEPROMReporter::ReadFileToInt(const std::string &path, int16_t *val)
     return true;
 }
 
-void BatteryEEPROMReporter::setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset,
-                                              int content) {
-    std::vector<VendorAtomValue> &val = *values;
+std::string BatteryEEPROMReporter::checkPaths(const std::vector<std::string>& paths) {
+    if (paths.empty()) {
+        return ""; // Or throw an exception if appropriate
+    }
+
+    for (const auto& path : paths) { // Use range-based for loop
+        if (fileExists(path)) {
+            return path;
+        }
+    }
 
-    if (offset - kVendorAtomOffset < val.size())
-        val[offset - kVendorAtomOffset].set<VendorAtomValue::intValue>(content);
+    return ""; // No path found
 }
 
 void BatteryEEPROMReporter::checkAndReport(const std::shared_ptr<IStats> &stats_client,
@@ -112,8 +118,8 @@ void BatteryEEPROMReporter::checkAndReport(const std::shared_ptr<IStats> &stats_
     }
     */
 
-    struct BatteryHistoryRawFormat hist_raw;
-    struct BatteryHistory hist;
+    struct BatteryEEPROMPipelineRawFormat hist_raw;
+    struct BatteryEEPROMPipeline hist;
     int16_t i;
 
     ReadFileToInt(kBatteryPairingPath, &hist.battery_pairing);
@@ -159,19 +165,19 @@ void BatteryEEPROMReporter::checkAndReport(const std::shared_ptr<IStats> &stats_
 
         /* Mapping to original format to collect data */
         /* go/pixel-battery-eeprom-atom#heading=h.dcawdjiz2ls6 */
-        hist.tempco = hist_raw.tempco;
-        hist.rcomp0 = hist_raw.rcomp0;
-        hist.timer_h = (uint8_t)hist_raw.timer_h * 5;
-        hist.max_temp = (int8_t)hist_raw.maxtemp * 3 + 22;
-        hist.min_temp = (int8_t)hist_raw.mintemp * 3 - 20;
-        hist.min_ibatt = (int16_t)hist_raw.maxchgcurr * 500 * (-1);
-        hist.max_ibatt = (int16_t)hist_raw.maxdischgcurr * 500;
-        hist.min_vbatt = (uint16_t)hist_raw.minvolt * 10 + 2500;
-        hist.max_vbatt = (uint16_t)hist_raw.maxvolt * 20 + 4200;
-        hist.batt_soc = (uint8_t)hist_raw.vfsoc * 2;
-        hist.msoc = (uint8_t)hist_raw.mixsoc * 2;
-        hist.full_cap = (int16_t)hist_raw.fullcaprep * 125 / 1000;
-        hist.full_rep = (int16_t)hist_raw.fullcapnom * 125 / 1000;
+        hist.tempco = (int32_t)hist_raw.tempco;
+        hist.rcomp0 = (int32_t)hist_raw.rcomp0;
+        hist.timer_h = (int32_t)hist_raw.timer_h * 5;
+        hist.max_temp = (int32_t)hist_raw.maxtemp * 3 + 22;
+        hist.min_temp = (int32_t)hist_raw.mintemp * 3 - 20;
+        hist.min_ibatt = (int32_t)hist_raw.maxchgcurr * 500 * (-1);
+        hist.max_ibatt = (int32_t)hist_raw.maxdischgcurr * 500;
+        hist.min_vbatt = (int32_t)hist_raw.minvolt * 10 + 2500;
+        hist.max_vbatt = (int32_t)hist_raw.maxvolt * 20 + 4200;
+        hist.batt_soc = (int32_t)hist_raw.vfsoc * 2;
+        hist.msoc = (int32_t)hist_raw.mixsoc * 2;
+        hist.full_cap = (int32_t)hist_raw.fullcaprep * 125 / 1000;
+        hist.full_rep = (int32_t)hist_raw.fullcapnom * 125 / 1000;
 
         /* i < sparse_index_count: 20 40 60 80  */
         if (i < sparse_index_count)
@@ -189,44 +195,9 @@ int64_t BatteryEEPROMReporter::getTimeSecs(void) {
     return nanoseconds_to_seconds(systemTime(SYSTEM_TIME_BOOTTIME));
 }
 
-/**
- * @return true if a log should be reported, else false.
- * Here we use checksum to confirm the data is usable or not.
- * The checksum mismatch when storage data overflow or corrupt.
- * We don't need data in such cases.
- */
-bool BatteryEEPROMReporter::checkLogEvent(struct BatteryHistory hist) {
-    int checksum = 0;
-
-    checksum = hist.cycle_cnt + hist.full_cap + hist.esr + hist.rslow
-                + hist.soh + hist.batt_temp + hist.cutoff_soc + hist.cc_soc
-                + hist.sys_soc + hist.msoc + hist.batt_soc + hist.reserve
-                + hist.max_temp + hist.min_temp + hist.max_vbatt
-                + hist.min_vbatt + hist.max_ibatt + hist.min_ibatt;
-    /* Compare with checksum data */
-    if (checksum == hist.checksum) {
-        return true;
-    } else {
-        return false;
-    }
-}
-
 void BatteryEEPROMReporter::reportEvent(const std::shared_ptr<IStats> &stats_client,
-                                        const struct BatteryHistory &hist) {
-    // upload atom
-    const std::vector<int> eeprom_history_fields = {
-            BatteryEEPROM::kCycleCntFieldNumber,  BatteryEEPROM::kFullCapFieldNumber,
-            BatteryEEPROM::kEsrFieldNumber,       BatteryEEPROM::kRslowFieldNumber,
-            BatteryEEPROM::kSohFieldNumber,       BatteryEEPROM::kBattTempFieldNumber,
-            BatteryEEPROM::kCutoffSocFieldNumber, BatteryEEPROM::kCcSocFieldNumber,
-            BatteryEEPROM::kSysSocFieldNumber,    BatteryEEPROM::kMsocFieldNumber,
-            BatteryEEPROM::kBattSocFieldNumber,   BatteryEEPROM::kReserveFieldNumber,
-            BatteryEEPROM::kMaxTempFieldNumber,   BatteryEEPROM::kMinTempFieldNumber,
-            BatteryEEPROM::kMaxVbattFieldNumber,  BatteryEEPROM::kMinVbattFieldNumber,
-            BatteryEEPROM::kMaxIbattFieldNumber,  BatteryEEPROM::kMinIbattFieldNumber,
-            BatteryEEPROM::kChecksumFieldNumber,  BatteryEEPROM::kTempcoFieldNumber,
-            BatteryEEPROM::kRcomp0FieldNumber,    BatteryEEPROM::kTimerHFieldNumber,
-            BatteryEEPROM::kFullRepFieldNumber,   BatteryEEPROM::kBatteryPairingFieldNumber};
+                                        const struct BatteryEEPROMPipeline &hist) {
+    std::vector<VendorAtomValue> values(kNumEEPROMPipelineFields);
 
     ALOGD("reportEvent: cycle_cnt:%d, full_cap:%d, esr:%d, rslow:%d, soh:%d, "
           "batt_temp:%d, cutoff_soc:%d, cc_soc:%d, sys_soc:%d, msoc:%d, "
@@ -239,80 +210,6 @@ void BatteryEEPROMReporter::reportEvent(const std::shared_ptr<IStats> &stats_cli
           hist.min_ibatt, hist.checksum, hist.full_rep, hist.tempco, hist.rcomp0, hist.timer_h,
           hist.battery_pairing);
 
-    std::vector<VendorAtomValue> values(eeprom_history_fields.size());
-    VendorAtomValue val;
-
-    val.set<VendorAtomValue::intValue>(hist.cycle_cnt);
-    values[BatteryEEPROM::kCycleCntFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.full_cap);
-    values[BatteryEEPROM::kFullCapFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.esr);
-    values[BatteryEEPROM::kEsrFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.rslow);
-    values[BatteryEEPROM::kRslowFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.soh);
-    values[BatteryEEPROM::kSohFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.batt_temp);
-    values[BatteryEEPROM::kBattTempFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.cutoff_soc);
-    values[BatteryEEPROM::kCutoffSocFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.cc_soc);
-    values[BatteryEEPROM::kCcSocFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.sys_soc);
-    values[BatteryEEPROM::kSysSocFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.msoc);
-    values[BatteryEEPROM::kMsocFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.batt_soc);
-    values[BatteryEEPROM::kBattSocFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.reserve);
-    values[BatteryEEPROM::kReserveFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.max_temp);
-    values[BatteryEEPROM::kMaxTempFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.min_temp);
-    values[BatteryEEPROM::kMinTempFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.max_vbatt);
-    values[BatteryEEPROM::kMaxVbattFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.min_vbatt);
-    values[BatteryEEPROM::kMinVbattFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.max_ibatt);
-    values[BatteryEEPROM::kMaxIbattFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.min_ibatt);
-    values[BatteryEEPROM::kMinIbattFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.checksum);
-    values[BatteryEEPROM::kChecksumFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.tempco);
-    values[BatteryEEPROM::kTempcoFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.rcomp0);
-    values[BatteryEEPROM::kRcomp0FieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.timer_h);
-    values[BatteryEEPROM::kTimerHFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.full_rep);
-    values[BatteryEEPROM::kFullRepFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(hist.battery_pairing);
-    values[BatteryEEPROM::kBatteryPairingFieldNumber - kVendorAtomOffset] = val;
-
-    VendorAtom event = {.reverseDomainName = "",
-                        .atomId = PixelAtoms::Atom::kBatteryEeprom,
-                        .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report BatteryEEPROM to Stats service");
-}
-
-void BatteryEEPROMReporter::reportEventInt32(const std::shared_ptr<IStats> &stats_client,
-                                             const struct BatteryHistoryInt32 &hist) {
-    std::vector<VendorAtomValue> values(23);
-
-    ALOGD("reportEvent: cycle_cnt:%d, full_cap:%d, esr:%d, rslow:%d, soh:%d, "
-          "batt_temp:%d, cutoff_soc:%d, cc_soc:%d, sys_soc:%d, msoc:%d, "
-          "batt_soc:%d, reserve:%d, max_temp:%d, min_temp:%d, max_vbatt:%d, "
-          "min_vbatt:%d, max_ibatt:%d, min_ibatt:%d, checksum:%#x, full_rep:%d, "
-          "tempco:%#x, rcomp0:%#x, timer_h:%d",
-          hist.cycle_cnt, hist.full_cap, hist.esr, hist.rslow, hist.soh, hist.batt_temp,
-          hist.cutoff_soc, hist.cc_soc, hist.sys_soc, hist.msoc, hist.batt_soc, hist.reserve,
-          hist.max_temp, hist.min_temp, hist.max_vbatt, hist.min_vbatt, hist.max_ibatt,
-          hist.min_ibatt, hist.checksum, hist.full_rep, hist.tempco, hist.rcomp0, hist.timer_h);
-
     setAtomFieldValue(&values, BatteryEEPROM::kCycleCntFieldNumber, hist.cycle_cnt);
     setAtomFieldValue(&values, BatteryEEPROM::kFullCapFieldNumber, hist.full_cap);
     setAtomFieldValue(&values, BatteryEEPROM::kEsrFieldNumber, hist.esr);
@@ -336,42 +233,32 @@ void BatteryEEPROMReporter::reportEventInt32(const std::shared_ptr<IStats> &stat
     setAtomFieldValue(&values, BatteryEEPROM::kRcomp0FieldNumber, hist.rcomp0);
     setAtomFieldValue(&values, BatteryEEPROM::kTimerHFieldNumber, hist.timer_h);
     setAtomFieldValue(&values, BatteryEEPROM::kFullRepFieldNumber, hist.full_rep);
+    setAtomFieldValue(&values, BatteryEEPROM::kBatteryPairingFieldNumber, hist.battery_pairing);
 
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kBatteryEeprom,
                         .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report BatteryEEPROM to Stats service");
+    reportVendorAtom(stats_client, event);
 }
 
 void BatteryEEPROMReporter::checkAndReportGMSR(const std::shared_ptr<IStats> &stats_client,
                                                const std::vector<std::string> &paths) {
-    struct BatteryHistory gmsr = {.checksum = EvtGMSR};
+    struct BatteryEEPROMPipeline gmsr = {.checksum = EvtGMSR};
+    std::string path = checkPaths(paths);
     std::string file_contents;
-    std::string path;
     int16_t num;
 
-    if (paths.empty())
+    if (path.empty())
         return;
 
-    for (int i = 0; i < paths.size(); i++) {
-        if (fileExists(paths[i])) {
-            path = paths[i];
-            break;
-        }
-    }
-
     if (!ReadFileToString(path, &file_contents)) {
         ALOGE("Unable to read gmsr path: %s - %s", path.c_str(), strerror(errno));
         return;
     }
 
-    num = sscanf(file_contents.c_str(),  "rcomp0\t:%4" SCNx16 "\ntempco\t:%4" SCNx16
-                 "\nfullcaprep\t:%4" SCNx16 "\ncycles\t:%4" SCNx16 "\nfullcapnom\t:%4" SCNx16
-                 "\nqresidual00\t:%4" SCNx16 "\nqresidual10\t:%4" SCNx16
-                 "\nqresidual20\t:%4" SCNx16 "\nqresidual30\t:%4" SCNx16
-                 "\ncv_mixcap\t:%4" SCNx16 "\nhalftime\t:%4" SCNx16,
+    num = sscanf(file_contents.c_str(), "rcomp0\t:%x\ntempco\t:%x\nfullcaprep\t:%x\ncycles\t:%x"
+                 "\nfullcapnom\t:%x\nqresidual00\t:%x\nqresidual10\t:%x\nqresidual20\t:%x"
+                 "\nqresidual30\t:%x\ncv_mixcap\t:%x\nhalftime\t:%x",
                  &gmsr.rcomp0, &gmsr.tempco, &gmsr.full_rep, &gmsr.cycle_cnt, &gmsr.full_cap,
                  &gmsr.max_vbatt, &gmsr.min_vbatt, &gmsr.max_ibatt, &gmsr.min_ibatt,
                  &gmsr.esr, &gmsr.rslow);
@@ -396,10 +283,9 @@ void BatteryEEPROMReporter::checkAndReportMaxfgHistory(const std::shared_ptr<ISt
     if (path.empty())
         return;
 
-    if (!ReadFileToString(path, &file_contents)) {
-        ALOGD("Unable to read maxfg_hist path: %s - %s", path.c_str(), strerror(errno));
+    /* not support max17201 */
+    if (!ReadFileToString(path, &file_contents))
         return;
-    }
 
     std::string hist_each;
     const int kHistTotalLen = file_contents.size();
@@ -407,7 +293,7 @@ void BatteryEEPROMReporter::checkAndReportMaxfgHistory(const std::shared_ptr<ISt
     ALOGD("checkAndReportMaxfgHistory:size=%d\n%s", kHistTotalLen, file_contents.c_str());
 
     for (i = 0; i < kHistTotalLen; i++) {
-        struct BatteryHistory maxfg_hist;
+        struct BatteryEEPROMPipeline maxfg_hist;
         uint16_t nQRTable00, nQRTable10, nQRTable20, nQRTable30, nCycles, nFullCapNom;
         uint16_t nRComp0, nTempCo, nIAvgEmpty, nFullCapRep, nVoltTemp, nMaxMinCurr, nMaxMinVolt;
         uint16_t nMaxMinTemp, nSOC, nTimerH;
@@ -455,23 +341,16 @@ void BatteryEEPROMReporter::checkAndReportMaxfgHistory(const std::shared_ptr<ISt
 
 void BatteryEEPROMReporter::checkAndReportFGModelLoading(const std::shared_ptr<IStats> &client,
                                                          const std::vector<std::string> &paths) {
-    struct BatteryHistory params = {.full_cap = 0, .esr = 0, .rslow = 0,
+    struct BatteryEEPROMPipeline params = {.full_cap = 0, .esr = 0, .rslow = 0,
                                     .checksum = EvtModelLoading, };
+    std::string path = checkPaths(paths);
     std::string file_contents;
-    std::string path;
     int num;
     const char *data;
 
-    if (paths.empty())
+    if (path.empty())
         return;
 
-    for (int i = 0; i < paths.size(); i++) {
-        if (fileExists(paths[i])) {
-            path = paths[i];
-            break;
-        }
-    }
-
     /* not found */
     if (path.empty())
         return;
@@ -483,7 +362,7 @@ void BatteryEEPROMReporter::checkAndReportFGModelLoading(const std::shared_ptr<I
 
     data = file_contents.c_str();
 
-    num = sscanf(data, "ModelNextUpdate: %" SCNu16 "%*[0-9a-f: \n]ATT: %" SCNu16 " FAIL: %" SCNu16,
+    num = sscanf(data, "ModelNextUpdate: %x%*[0-9a-f: \n]ATT: %x FAIL: %x",
                  &params.rslow, &params.full_cap, &params.esr);
     if (num != 3) {
         ALOGE("Couldn't process ModelLoading History. num=%d\n", num);
@@ -499,23 +378,12 @@ void BatteryEEPROMReporter::checkAndReportFGModelLoading(const std::shared_ptr<I
 
 void BatteryEEPROMReporter::checkAndReportFGLearning(const std::shared_ptr<IStats> &stats_client,
                                                      const std::vector<std::string> &paths) {
-    struct BatteryHistoryInt32 params = {.checksum = EvtFGLearningHistory};
-    std::string path;
+    struct BatteryEEPROMPipeline params = {.checksum = EvtFGLearningHistory};
+    std::string path = checkPaths(paths);
     struct timespec boot_time;
     auto format = FormatIgnoreAddr;
     std::vector<std::vector<uint32_t>> events;
 
-    if (paths.empty())
-        return;
-
-    for (int i = 0; i < paths.size(); i++) {
-        if (fileExists(paths[i])) {
-            path = paths[i];
-            break;
-        }
-    }
-
-    /* not found */
     if (path.empty())
         return;
 
@@ -533,12 +401,12 @@ void BatteryEEPROMReporter::checkAndReportFGLearning(const std::shared_ptr<IStat
             params.esr = event[1];                     /* dpacc */
             params.rslow = event[2];                   /* dqacc */
             params.full_rep = event[3];                /* fcrep */
-            params.msoc = (uint8_t)(event[4] >> 8);    /* repsoc */
-            params.sys_soc = (uint8_t)(event[5] >> 8); /* mixsoc */
-            params.batt_soc = (uint8_t)(event[6] >> 8);/* vfsoc */
+            params.msoc = event[4] >> 8;               /* repsoc */
+            params.sys_soc = event[5] >> 8;            /* mixsoc */
+            params.batt_soc = event[6] >> 8;           /* vfsoc */
             params.min_ibatt = event[7];               /* fstats */
-            params.max_temp = (int8_t)(event[8] >> 8); /* avgtemp */
-            params.min_temp = (int8_t)(event[9] >> 8); /* temp */
+            params.max_temp = event[8] >> 8;           /* avgtemp */
+            params.min_temp = event[9] >> 8;           /* temp */
             params.max_ibatt = event[10];              /* qh */
             params.max_vbatt = event[11];              /* vcell */
             params.min_vbatt = event[12];              /* avgvcell */
@@ -551,30 +419,19 @@ void BatteryEEPROMReporter::checkAndReportFGLearning(const std::shared_ptr<IStat
             ALOGE("Not support %zu fields for FG learning event", event.size());
             continue;
         }
-        reportEventInt32(stats_client, params);
+        reportEvent(stats_client, params);
     }
     last_lh_check_ = (unsigned int)boot_time.tv_sec;
 }
 
 void BatteryEEPROMReporter::checkAndReportValidation(const std::shared_ptr<IStats> &stats_client,
                                                      const std::vector<std::string> &paths) {
-    struct BatteryHistoryInt32 params = {.checksum = EvtHistoryValidation};
-    std::string path;
+    struct BatteryEEPROMPipeline params = {.checksum = EvtHistoryValidation};
+    std::string path = checkPaths(paths);
     struct timespec boot_time;
     auto format = FormatIgnoreAddr;
     std::vector<std::vector<uint32_t>> events;
 
-    if (paths.empty())
-        return;
-
-    for (int i = 0; i < paths.size(); i++) {
-        if (fileExists(paths[i])) {
-            path = paths[i];
-            break;
-        }
-    }
-
-    /* not found */
     if (path.empty())
         return;
 
@@ -588,7 +445,7 @@ void BatteryEEPROMReporter::checkAndReportValidation(const std::shared_ptr<IStat
             params.esr = event[1];      /* num of entries need to be recovered or fix result */
             params.rslow = event[2];    /* last cycle count */
             params.full_rep = event[3]; /* estimate cycle count after recovery */
-            reportEventInt32(stats_client, params);
+            reportEvent(stats_client, params);
             /* force report history metrics if it was recovered */
             if (last_hv_check_ != 0) {
                 report_time_ = 0;
diff --git a/pixelstats/BatteryFGReporter.cpp b/pixelstats/BatteryFGReporter.cpp
index 9808b458..b94409ad 100644
--- a/pixelstats/BatteryFGReporter.cpp
+++ b/pixelstats/BatteryFGReporter.cpp
@@ -45,37 +45,38 @@ int64_t BatteryFGReporter::getTimeSecs() {
     return nanoseconds_to_seconds(systemTime(SYSTEM_TIME_BOOTTIME));
 }
 
-void BatteryFGReporter::setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset,
-                                          int content) {
-    std::vector<VendorAtomValue> &val = *values;
-    if (offset - kVendorAtomOffset < val.size())
-        val[offset - kVendorAtomOffset].set<VendorAtomValue::intValue>(content);
-}
-
-void BatteryFGReporter::reportAbnormalEvent(const std::shared_ptr<IStats> &stats_client,
-                                            struct BatteryFGAbnormalData data) {
+void BatteryFGReporter::reportFGEvent(const std::shared_ptr<IStats> &stats_client,
+                                      struct BatteryFGPipeline &data) {
     // Load values array
-    std::vector<VendorAtomValue> values(35);
-    uint32_t duration = 0;
+    std::vector<VendorAtomValue> values(kNumFGPipelineFields);
+
+    if (data.event >= kNumMaxEvents) {
+        ALOGE("Exceed max number of events, expected=%d, event=%d",
+               kNumMaxEvents, data.event);
+        return;
+    }
 
     /* save time when trigger, calculate duration when clear */
     if (data.state == 1 && ab_trigger_time_[data.event] == 0) {
         ab_trigger_time_[data.event] = getTimeSecs();
     } else {
-        duration = getTimeSecs() - ab_trigger_time_[data.event];
+        data.duration = getTimeSecs() - ab_trigger_time_[data.event];
         ab_trigger_time_[data.event] = 0;
     }
 
-    ALOGD("reportEvent: event=%d,state=%d,cycles=%04X,vcel=%04X,avgv=%04X,curr=%04X,avgc=%04X,"
-          "timerh=%04X,temp=%04X,repcap=%04X,mixcap=%04X,fcrep=%04X,fcnom=%04X,qresd=%04X,"
-          "avcap=%04X,vfremcap=%04X,repsoc=%04X,vfsoc=%04X,msoc=%04X,vfocv=%04X,dpacc=%04X,"
-          "dqacc=%04X,qh=%04X,qh0=%04X,vfsoc0=%04X,qrtable20=%04X,qrtable30=%04X,status=%04X,"
-          "fstat=%04X,rcomp0=%04X,tempco=%04X,duration=%u",
-          data.event, data.state, data.cycles, data.vcel, data.avgv, data.curr, data.avgc,
-          data.timerh, data.temp, data.repcap, data.mixcap, data.fcrep, data.fcnom, data.qresd,
-          data.avcap, data.vfremcap, data.repsoc, data.vfsoc, data.msoc, data.vfocv, data.dpacc,
-          data.dqacc, data.qh, data.qh0, data.vfsoc0, data.qrtable20, data.qrtable30, data.status,
-          data.fstat, data.rcomp0, data.tempco, duration);
+    ALOGD("reportEvent: event=%d, state=%d, duration=%d, addr01=%04X, data01=%04X, "
+          "addr02=%04X, data02=%04X, addr03=%04X, data03=%04X, addr04=%04X, data04=%04X, "
+          "addr05=%04X, data05=%04X, addr06=%04X, data06=%04X, addr07=%04X, data07=%04X, "
+          "addr08=%04X, data08=%04X, addr09=%04X, data09=%04X, addr10=%04X, data10=%04X, "
+          "addr11=%04X, data11=%04X, addr12=%04X, data12=%04X, addr13=%04X, data13=%04X, "
+          "addr14=%04X, data14=%04X, addr15=%04X, data15=%04X, addr16=%04X, data16=%04X",
+          data.event, data.state, data.duration, data.addr01, data.data01,
+          data.addr02, data.data02, data.addr03, data.data03, data.addr04, data.data04,
+          data.addr05, data.data05, data.addr06, data.data06, data.addr07, data.data07,
+          data.addr08, data.data08, data.addr09, data.data09, data.addr10, data.data10,
+          data.addr11, data.data11, data.addr12, data.data12, data.addr13, data.data13,
+          data.addr14, data.data14, data.addr15, data.data15, data.addr16, data.data16);
+
 
     /*
      * state=0 -> untrigger, state=1 -> trigger
@@ -86,165 +87,77 @@ void BatteryFGReporter::reportAbnormalEvent(const std::shared_ptr<IStats> &stats
 
     setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kEventFieldNumber, data.event);
     setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kEventStateFieldNumber, data.state);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kDurationSecsFieldNumber, duration);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress1FieldNumber, data.cycles);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData1FieldNumber, data.vcel);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress2FieldNumber, data.avgv);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData2FieldNumber, data.curr);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress3FieldNumber, data.avgc);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData3FieldNumber, data.timerh);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress4FieldNumber, data.temp);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData4FieldNumber, data.repcap);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress5FieldNumber, data.mixcap);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData5FieldNumber, data.fcrep);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress6FieldNumber, data.fcnom);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData6FieldNumber, data.qresd);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress7FieldNumber, data.avcap);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData7FieldNumber, data.vfremcap);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress8FieldNumber, data.repsoc);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData8FieldNumber, data.vfsoc);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress9FieldNumber, data.msoc);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData9FieldNumber, data.vfocv);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress10FieldNumber, data.dpacc);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData10FieldNumber, data.dqacc);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress11FieldNumber, data.qh);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData11FieldNumber, data.qh0);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress12FieldNumber, data.vfsoc0);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData12FieldNumber, data.qrtable20);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress13FieldNumber, data.qrtable30);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData13FieldNumber, data.status);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress14FieldNumber, data.fstat);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData14FieldNumber, data.rcomp0);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress15FieldNumber, data.tempco);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData15FieldNumber, 0);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress16FieldNumber, 0);
-    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData16FieldNumber, 0);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kDurationSecsFieldNumber,
+                      data.duration);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress1FieldNumber,
+                      data.addr01);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData1FieldNumber,
+                      data.data01);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress2FieldNumber,
+                      data.addr02);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData2FieldNumber,
+                      data.data02);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress3FieldNumber,
+                      data.addr03);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData3FieldNumber,
+                      data.data03);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress4FieldNumber,
+                      data.addr04);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData4FieldNumber,
+                      data.data04);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress5FieldNumber,
+                      data.addr05);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData5FieldNumber,
+                      data.data05);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress6FieldNumber,
+                      data.addr06);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData6FieldNumber,
+                      data.data06);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress7FieldNumber,
+                      data.addr07);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData7FieldNumber,
+                      data.data07);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress8FieldNumber,
+                      data.addr08);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData8FieldNumber,
+                      data.data08);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress9FieldNumber,
+                      data.addr09);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData9FieldNumber,
+                      data.data09);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress10FieldNumber,
+                      data.addr10);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData10FieldNumber,
+                      data.data10);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress11FieldNumber,
+                      data.addr11);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData11FieldNumber,
+                      data.data11);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress12FieldNumber,
+                      data.addr12);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData12FieldNumber,
+                      data.data12);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress13FieldNumber,
+                      data.addr13);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData13FieldNumber,
+                      data.data13);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress14FieldNumber,
+                      data.addr14);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData14FieldNumber,
+                      data.data14);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress15FieldNumber,
+                      data.addr15);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData15FieldNumber,
+                      data.data15);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterAddress16FieldNumber,
+                      data.addr16);
+    setAtomFieldValue(&values, FuelGaugeAbnormalityReported::kFgRegisterData16FieldNumber,
+                      data.data16);
 
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kFuelGaugeAbnormalityReported,
                         .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report FuelGaugeAbnormalityReported to Stats service");
-}
-
-void BatteryFGReporter::reportEvent(const std::shared_ptr<IStats> &stats_client,
-                                    const struct BatteryFGLearningParam &params) {
-    // upload atom
-    const std::vector<int> eeprom_history_fields = {
-            BatteryEEPROM::kCycleCntFieldNumber,  BatteryEEPROM::kFullCapFieldNumber,
-            BatteryEEPROM::kEsrFieldNumber,       BatteryEEPROM::kRslowFieldNumber,
-            BatteryEEPROM::kSohFieldNumber,       BatteryEEPROM::kBattTempFieldNumber,
-            BatteryEEPROM::kCutoffSocFieldNumber, BatteryEEPROM::kCcSocFieldNumber,
-            BatteryEEPROM::kSysSocFieldNumber,    BatteryEEPROM::kMsocFieldNumber,
-            BatteryEEPROM::kBattSocFieldNumber,   BatteryEEPROM::kReserveFieldNumber,
-            BatteryEEPROM::kMaxTempFieldNumber,   BatteryEEPROM::kMinTempFieldNumber,
-            BatteryEEPROM::kMaxVbattFieldNumber,  BatteryEEPROM::kMinVbattFieldNumber,
-            BatteryEEPROM::kMaxIbattFieldNumber,  BatteryEEPROM::kMinIbattFieldNumber,
-            BatteryEEPROM::kChecksumFieldNumber,  BatteryEEPROM::kTempcoFieldNumber,
-            BatteryEEPROM::kRcomp0FieldNumber,    BatteryEEPROM::kTimerHFieldNumber,
-            BatteryEEPROM::kFullRepFieldNumber};
-
-    switch(params.type) {
-      case EvtFWUpdate:
-        ALOGD("reportEvent: firmware update try: %u, success: %u, fail: %u",
-              params.fcnom, params.dpacc, params.dqacc);
-              break;
-      default:
-        ALOGD("unknown event type %04x", params.type);
-        break;
-    }
-
-    std::vector<VendorAtomValue> values(eeprom_history_fields.size());
-    VendorAtomValue val;
-
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kCycleCntFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(params.fcnom);
-    values[BatteryEEPROM::kFullCapFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(params.dpacc);
-    values[BatteryEEPROM::kEsrFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(params.dqacc);
-    values[BatteryEEPROM::kRslowFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kSohFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kBattTempFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kCutoffSocFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kCcSocFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kSysSocFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kMsocFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kBattSocFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kReserveFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kMaxTempFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kMinTempFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(params.fcrep);
-    values[BatteryEEPROM::kMaxVbattFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(params.msoc);
-    values[BatteryEEPROM::kMinVbattFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(params.vfsoc);
-    values[BatteryEEPROM::kMaxIbattFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(params.fstat);
-    values[BatteryEEPROM::kMinIbattFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>((uint16_t)params.type);
-    values[BatteryEEPROM::kChecksumFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(params.tempco);
-    values[BatteryEEPROM::kTempcoFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(params.rcomp0);
-    values[BatteryEEPROM::kRcomp0FieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(0);
-    values[BatteryEEPROM::kTimerHFieldNumber - kVendorAtomOffset] = val;
-    val.set<VendorAtomValue::intValue>(params.repsoc);
-    values[BatteryEEPROM::kFullRepFieldNumber - kVendorAtomOffset] = val;
-
-    VendorAtom event = {.reverseDomainName = "",
-                        .atomId = PixelAtoms::Atom::kBatteryEeprom,
-                        .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report BatteryEEPROM to Stats service");
-}
-
-void BatteryFGReporter::checkAndReportFwUpdate(const std::shared_ptr<IStats> &stats_client,
-                                               const std::string &path) {
-    struct BatteryFGLearningParam params;
-    std::string file_contents;
-    int16_t num;
-
-    if (path.empty())
-        return;
-
-    if (!ReadFileToString(path, &file_contents)) {
-        ALOGE("Unable to read FirmwareUpdate path: %s - %s", path.c_str(), strerror(errno));
-        return;
-    }
-
-    /* FU: Firmware Update */
-    params.type = EvtFWUpdate;
-    num = sscanf(file_contents.c_str(), "%" SCNu16 " %" SCNu16 " %" SCNu16,
-                 &params.fcnom, &params.dpacc, &params.dqacc);
-    if (num != kNumFwUpdateFields) {
-        ALOGE("Couldn't process FirmwareUpdate history path. num=%d\n", num);
-        return;
-    }
-
-    /* No event to report */
-    if (params.fcnom == 0 )
-        return;
-
-    /* Reporting data only when can clear */
-    if (::android::base::WriteStringToFile("0", path.c_str()))
-        reportEvent(stats_client, params);
-    else
-        ALOGE("Couldn't clear %s - %s", path.c_str(), strerror(errno));
+    reportVendorAtom(stats_client, event);
 }
 
 void BatteryFGReporter::checkAndReportFGAbnormality(const std::shared_ptr<IStats> &stats_client,
@@ -264,14 +177,13 @@ void BatteryFGReporter::checkAndReportFGAbnormality(const std::shared_ptr<IStats
     }
 
     clock_gettime(CLOCK_MONOTONIC, &boot_time);
-    readLogbuffer(path, kNumAbnormalEventFields, EvtFGAbnormalEvent, FormatOnlyVal, last_ab_check_, events);
+    readLogbuffer(path, kNumFGPipelineFields, EvtFGAbnormalEvent, FormatOnlyVal, last_ab_check_,
+                  events);
     for (int seq = 0; seq < events.size(); seq++) {
-        if (events[seq].size() == kNumAbnormalEventFields) {
-            struct BatteryFGAbnormalData data;
-            uint16_t *pdata = (uint16_t *)&data;
-            for (int i = 0; i < kNumAbnormalEventFields; i++)
-                *pdata++ = events[seq][i];
-            reportAbnormalEvent(stats_client, data);
+        if (events[seq].size() == kNumFGPipelineFields) {
+            struct BatteryFGPipeline data;
+            std::copy(events[seq].begin(), events[seq].end(), (int32_t *)&data);
+            reportFGEvent(stats_client, data);
         } else {
             ALOGE("Not support %zu fields for FG abnormal event", events[seq].size());
         }
diff --git a/pixelstats/BatteryFwUpdateReporter.cpp b/pixelstats/BatteryFwUpdateReporter.cpp
new file mode 100644
index 00000000..c23dd7e0
--- /dev/null
+++ b/pixelstats/BatteryFwUpdateReporter.cpp
@@ -0,0 +1,133 @@
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
+#define LOG_TAG "pixelstats: BatteryFwUpdateReporter"
+
+#include <log/log.h>
+#include <time.h>
+#include <utils/Timers.h>
+#include <cinttypes>
+#include <cmath>
+
+#include <android-base/file.h>
+#include <android-base/parseint.h>
+#include <android-base/strings.h>
+#include <pixelstats/BatteryFwUpdateReporter.h>
+#include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
+
+namespace android {
+namespace hardware {
+namespace google {
+namespace pixel {
+
+using aidl::android::frameworks::stats::VendorAtom;
+using aidl::android::frameworks::stats::VendorAtomValue;
+using android::base::ReadFileToString;
+using android::hardware::google::pixel::PixelAtoms::BatteryFirmwareUpdateReported;
+
+BatteryFwUpdateReporter::BatteryFwUpdateReporter() {}
+
+void BatteryFwUpdateReporter::reportEvent(const std::shared_ptr<IStats> &stats_client,
+                                          struct BatteryFwUpdatePipeline &data) {
+    std::vector<VendorAtomValue> values(kNumFwUpdatePipelineFields);
+
+    ALOGD("reportEvent: msg_type=%d, msg_category=%d, major_ver_from=%d, minor_ver_from=%d, "
+          "major_ver_to=%d, minor_ver_to=%d, update_status=%d, attempts=%d, unix_time_sec=%d "
+          "fw_data0=%d, fw_data1=%d, fw_data2=%d, fw_data3=%d",
+          data.msg_type, data.msg_category, data.major_version_from, data.minor_version_from,
+          data.major_version_to, data.minor_version_to, data.update_status, data.attempts,
+          data.unix_time_sec, data.fw_data0, data.fw_data1, data.fw_data2, data.fw_data3);
+
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kMsgTypeFieldNumber, data.msg_type);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kMsgCategoryFieldNumber,
+                      data.msg_category);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kMajorVersionFromFieldNumber,
+                      data.major_version_from);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kMinorVersionFromFieldNumber,
+                      data.minor_version_from);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kMajorVersionToFieldNumber,
+                      data.major_version_to);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kMinorVersionToFieldNumber,
+                      data.minor_version_to);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kUpdateStatusFieldNumber,
+                      data.update_status);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kAttemptsFieldNumber, data.attempts);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kUnixTimeSecFieldNumber,
+                      data.unix_time_sec);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kFwData0FieldNumber, data.fw_data0);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kFwData1FieldNumber, data.fw_data1);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kFwData2FieldNumber, data.fw_data2);
+    setAtomFieldValue(&values, BatteryFirmwareUpdateReported::kFwData3FieldNumber, data.fw_data3);
+
+    VendorAtom event = {.reverseDomainName = "",
+                        .atomId = PixelAtoms::Atom::kBatteryFirmwareUpdateReported,
+                        .values = std::move(values)};
+    reportVendorAtom(stats_client, event);
+}
+
+void BatteryFwUpdateReporter::checkAndReportFwUpdate(const std::shared_ptr<IStats> &stats_client,
+                                                     const std::vector<std::string> &paths,
+                                                     const ReportEventType &event_type) {
+    struct BatteryFwUpdatePipeline params;
+    struct timespec boot_time;
+
+    if (paths.empty())
+        return;
+
+    if (paths.size() > kNumMaxFwUpdatePaths) {
+        ALOGE("Exceed max number of FwUpdatePath, expected=%d, paths=%zu",
+               kNumMaxFwUpdatePaths, paths.size());
+        return;
+    }
+
+    for (int i = 0; i < paths.size(); i++) {
+        if (!fileExists(paths[i]))
+            continue;
+
+        std::vector<std::vector<uint32_t>> events;
+
+        clock_gettime(CLOCK_MONOTONIC, &boot_time);
+        readLogbuffer(paths[i], kNumFwUpdatePipelineFields, event_type, FormatOnlyVal,
+                      last_check_[i], events);
+        for (int event_idx = 0; event_idx < events.size(); event_idx++) {
+            std::vector<uint32_t> &event = events[event_idx];
+            if (event.size() == kNumFwUpdatePipelineFields) {
+                params.msg_type = event[0];
+                params.msg_category = event[1];
+                params.major_version_from = event[2];
+                params.minor_version_from = event[3];
+                params.major_version_to = event[4];
+                params.minor_version_to = event[5];
+                params.update_status = event[6];
+                params.attempts = event[7];
+                params.unix_time_sec = event[8];
+                params.fw_data0 = event[9];
+                params.fw_data1 = event[10];
+                params.fw_data2 = event[11];
+                params.fw_data3 = event[12];
+                reportEvent(stats_client, params);
+            } else {
+                ALOGE("Not support %zu fields for Firmware Update event", event.size());
+            }
+        }
+        last_check_[i] = (unsigned int)boot_time.tv_sec;
+    }
+}
+
+}  // namespace pixel
+}  // namespace google
+}  // namespace hardware
+}  // namespace android
diff --git a/pixelstats/BatteryHealthReporter.cpp b/pixelstats/BatteryHealthReporter.cpp
index 102b5fed..da873f01 100644
--- a/pixelstats/BatteryHealthReporter.cpp
+++ b/pixelstats/BatteryHealthReporter.cpp
@@ -108,9 +108,7 @@ void BatteryHealthReporter::reportBatteryHealthStatusEvent(
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kBatteryHealthStatus,
                         .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report BatteryHealthStatus to Stats service");
+    reportVendorAtom(stats_client, event);
 }
 
 bool BatteryHealthReporter::reportBatteryHealthUsage(const std::shared_ptr<IStats> &stats_client) {
@@ -168,9 +166,7 @@ void BatteryHealthReporter::reportBatteryHealthUsageEvent(
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kBatteryHealthUsage,
                         .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report BatteryHealthStatus to Stats service");
+    reportVendorAtom(stats_client, event);
 }
 
 void BatteryHealthReporter::checkAndReportStatus(const std::shared_ptr<IStats> &stats_client) {
diff --git a/pixelstats/BatteryTTFReporter.cpp b/pixelstats/BatteryTTFReporter.cpp
index ceb4946c..97d46c22 100644
--- a/pixelstats/BatteryTTFReporter.cpp
+++ b/pixelstats/BatteryTTFReporter.cpp
@@ -67,7 +67,7 @@ bool BatteryTTFReporter::reportBatteryTTFStats(const std::shared_ptr<IStats> &st
 
 void BatteryTTFReporter::reportBatteryTTFStatsEvent(
         const std::shared_ptr<IStats> &stats_client, const char *line) {
-    int ttf_stats_stats_fields[] = {
+    int ttf_stats_fields[] = {
         BatteryTimeToFullStatsReported::kTtfTypeFieldNumber,
         BatteryTimeToFullStatsReported::kTtfRangeFieldNumber,
         BatteryTimeToFullStatsReported::kSoc0FieldNumber,
@@ -82,7 +82,7 @@ void BatteryTTFReporter::reportBatteryTTFStatsEvent(
         BatteryTimeToFullStatsReported::kSoc9FieldNumber,
     };
 
-    const int32_t fields_size = std::size(ttf_stats_stats_fields);
+    const int32_t fields_size = std::size(ttf_stats_fields);
     const int32_t soc_start = 2; /* after type and range */
     int32_t size, range, type, i = 0, soc[fields_size - soc_start] = { 0 };
     std::vector<VendorAtomValue> values(fields_size);
@@ -105,20 +105,18 @@ void BatteryTTFReporter::reportBatteryTTFStatsEvent(
 
     ALOGD("BatteryTTFStats: processed %s", line);
     val.set<VendorAtomValue::intValue>(type);
-    values[ttf_stats_stats_fields[0] - kVendorAtomOffset] = val;
+    values[ttf_stats_fields[0] - kVendorAtomOffset] = val;
     val.set<VendorAtomValue::intValue>(range);
-    values[ttf_stats_stats_fields[1] - kVendorAtomOffset] = val;
+    values[ttf_stats_fields[1] - kVendorAtomOffset] = val;
     for (i = soc_start; i < fields_size; i++) {
         val.set<VendorAtomValue::intValue>(soc[i - soc_start]);
-        values[ttf_stats_stats_fields[i] - kVendorAtomOffset] = val;
+        values[ttf_stats_fields[i] - kVendorAtomOffset] = val;
     }
 
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kBatteryTimeToFullStatsReported,
                         .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report BatteryTTFStats to Stats service");
+    reportVendorAtom(stats_client, event);
 }
 
 void BatteryTTFReporter::checkAndReportStats(const std::shared_ptr<IStats> &stats_client) {
diff --git a/pixelstats/BrownoutDetectedReporter.cpp b/pixelstats/BrownoutDetectedReporter.cpp
index afdf16d5..b2d38ed8 100644
--- a/pixelstats/BrownoutDetectedReporter.cpp
+++ b/pixelstats/BrownoutDetectedReporter.cpp
@@ -395,6 +395,11 @@ void BrownoutDetectedReporter::logBrownoutCsv(const std::shared_ptr<IStats> &sta
         for (int i = 0; i < ODPM_MAX_IDX; i++) {
             max_value.odpm_value_[i] = atoi(row[i + ODPM_CHANNEL_0].c_str());
         }
+        if (row.size() > MITIGATION_METHOD_0_TIME) {
+            max_value.mitigation_method_0_ = atoi(row[MITIGATION_METHOD_0].c_str());
+            max_value.mitigation_method_0_count_ = atoi(row[MITIGATION_METHOD_0_COUNT].c_str());
+            max_value.mitigation_method_0_time_us_ = atoi(row[MITIGATION_METHOD_0_TIME].c_str());
+        }
         if (row.size() > MAX_CURR) {
             max_value.evt_cnt_oilo1_ = atoi(row[EVT_CNT_IDX_OILO1].c_str());
             max_value.evt_cnt_oilo2_ = atoi(row[EVT_CNT_IDX_OILO2].c_str());
diff --git a/pixelstats/ChargeStatsReporter.cpp b/pixelstats/ChargeStatsReporter.cpp
index 6da2c97c..db6a6e85 100644
--- a/pixelstats/ChargeStatsReporter.cpp
+++ b/pixelstats/ChargeStatsReporter.cpp
@@ -41,6 +41,8 @@ using android::hardware::google::pixel::PixelAtoms::VoltageTierStats;
 
 #define DURATION_FILTER_SECS 15
 #define CHG_STATS_FMT "%d,%d,%d, %d,%d,%d,%d %d %d,%d, %d,%d"
+#define WLC_ASTATS_FMT "A:%d,%d,%d,%d"
+#define WLC_DSTATS_FMT "D:%x,%x,%x,%x,%x, %x,%x"
 
 ChargeStatsReporter::ChargeStatsReporter() {}
 
@@ -95,14 +97,16 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
     }
 
     if (!wline_at.empty()) {
-        int32_t ssoc_tmp = 0;
+        int32_t type = 0, soc = 0, voltage = 0, current = 0;
         ALOGD("wlc: processing %s", wline_at.c_str());
-        if (sscanf(wline_at.c_str(), "A:%d", &ssoc_tmp) != 1) {
+        if (sscanf(wline_at.c_str(), WLC_ASTATS_FMT, &type, &soc, &voltage, &current) != 4) {
             ALOGE("Couldn't process %s", wline_at.c_str());
         } else {
-            tmp[0] = wireless_charge_stats_.TranslateSysModeToAtomValue(ssoc_tmp);
+            tmp[0] = wireless_charge_stats_.TranslateSysModeToAtomValue(type);
+            tmp[1] = voltage;
+            tmp[2] = current;
             ALOGD("wlc: processing %s", wline_ac.c_str());
-            if (sscanf(wline_ac.c_str(), "D:%x,%x,%x,%x,%x, %x,%x", &tmp[10], &tmp[11], &tmp[12],
+            if (sscanf(wline_ac.c_str(), WLC_DSTATS_FMT, &tmp[10], &tmp[11], &tmp[12],
                        &tmp[13], &tmp[14], &tmp[15], &tmp[16]) != 7)
                 ALOGE("Couldn't process %s", wline_ac.c_str());
         }
@@ -156,9 +160,7 @@ void ChargeStatsReporter::ReportChargeStats(const std::shared_ptr<IStats> &stats
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kChargeStats,
                         .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report ChargeStats to Stats service");
+    reportVendorAtom(stats_client, event);
 }
 
 void ChargeStatsReporter::ReportVoltageTierStats(const std::shared_ptr<IStats> &stats_client,
@@ -225,9 +227,7 @@ void ChargeStatsReporter::ReportVoltageTierStats(const std::shared_ptr<IStats> &
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kVoltageTierStats,
                         .values = std::move(values)};
-    const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
-    if (!ret.isOk())
-        ALOGE("Unable to report VoltageTierStats to Stats service");
+    reportVendorAtom(stats_client, event);
 }
 
 /**
diff --git a/pixelstats/JsonConfigUtils.cpp b/pixelstats/JsonConfigUtils.cpp
new file mode 100644
index 00000000..223b949a
--- /dev/null
+++ b/pixelstats/JsonConfigUtils.cpp
@@ -0,0 +1,72 @@
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
+#include <pixelstats/JsonConfigUtils.h>
+
+#include <fstream>
+#include <iostream>
+
+namespace android {
+namespace hardware {
+namespace google {
+namespace pixel {
+
+// Helper function to read string vectors from JSON
+std::vector<std::string> readStringVectorFromJson(const Json::Value &jsonArr) {
+    std::vector<std::string> vec;
+    if (jsonArr.isArray()) { // Check if jsonArr is an array
+        for (unsigned int i = 0; i < jsonArr.size(); ++i) {
+            vec.push_back(jsonArr[i].asString());
+        }
+    }
+    return vec;
+}
+
+// Helper function to read pairs of strings from JSON
+std::vector<std::pair<std::string, std::string>>
+readStringPairVectorFromJson(const Json::Value &jsonArr) {
+    std::vector<std::pair<std::string, std::string>> vec;
+    if (jsonArr.isArray()) { // Check if jsonArr is an array
+        for (unsigned int i = 0; i < jsonArr.size(); ++i) {
+            const Json::Value& innerArr = jsonArr[i];
+            if (innerArr.isArray() && innerArr.size() == 2) { // Check if inner array is valid
+                vec.push_back({innerArr[0].asString(), innerArr[1].asString()});
+            }
+        }
+    }
+    return vec;
+}
+
+std::string getCStringOrDefault(const Json::Value configData, const std::string& key) {
+    if (configData.isMember(key)) {
+        return configData[key].asString();
+    } else {
+        return "";
+    }
+}
+
+int getIntOrDefault(const Json::Value configData, const std::string& key) {
+    if (configData.isMember(key) && configData[key].isInt()) {
+        return configData[key].asInt();
+    } else {
+        return 0;
+    }
+}
+
+}  // namespace pixel
+}  // namespace google
+}  // namespace hardware
+}  // namespace android
diff --git a/pixelstats/StatsHelper.cpp b/pixelstats/StatsHelper.cpp
index 6fb93e4f..d6fa577f 100644
--- a/pixelstats/StatsHelper.cpp
+++ b/pixelstats/StatsHelper.cpp
@@ -57,6 +57,15 @@ std::shared_ptr<IStats> getStatsService() {
     return IStats::fromBinder(ndk::SpAIBinder(AServiceManager_waitForService(instance.c_str())));
 }
 
+void reportVendorAtom(const std::shared_ptr<IStats> &stats_client, VendorAtom event) {
+    // consecutive Atom calls should be at least 10 milliseconds apart
+    usleep(10000);
+    if (!stats_client->reportVendorAtom(event).isOk()) {
+        ALOGE("Unable to report %d to Stats service", event.atomId);
+        return;
+    }
+}
+
 void reportSpeakerImpedance(const std::shared_ptr<IStats> &stats_client,
                             const PixelAtoms::VendorSpeakerImpedance &speakerImpedance) {
     // Load values array
@@ -262,6 +271,7 @@ void readLogbuffer(const std::string &buf_path, int num_fields, uint16_t code,
             continue;
         }
 
+        std::fill(vect.begin(), vect.end(), 0);
         for (field_idx = 0; field_idx < num_fields; field_idx++, pos += read) {
             if (format == FormatAddrWithVal) {
                 num = sscanf(&line.c_str()[pos], "%x:%x%n", &addr, &val, &read);
@@ -275,7 +285,7 @@ void readLogbuffer(const std::string &buf_path, int num_fields, uint16_t code,
                     break;
                 vect[field_idx] = val;
             } else if (format == FormatOnlyVal) {
-                 num = sscanf(&line.c_str()[pos], "%x%n", &val, &read);
+                num = sscanf(&line.c_str()[pos], "%x%n", &val, &read);
                 if (num != 1)
                     break;
                 vect[field_idx] = val;
@@ -284,7 +294,7 @@ void readLogbuffer(const std::string &buf_path, int num_fields, uint16_t code,
             }
         }
 
-        if (field_idx == num_fields)
+        if (field_idx == num_fields || format == FormatOnlyVal)
             events.push_back(vect);
     }
     if (events.size() > 0 || reported > 0)
@@ -293,6 +303,13 @@ void readLogbuffer(const std::string &buf_path, int num_fields, uint16_t code,
     return;
 }
 
+void setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset, int content) {
+    std::vector<VendorAtomValue> &val = *values;
+
+    if (offset - kVendorAtomOffset < val.size())
+        val[offset - kVendorAtomOffset].set<VendorAtomValue::intValue>(content);
+}
+
 }  // namespace pixel
 }  // namespace google
 }  // namespace hardware
diff --git a/pixelstats/SysfsCollector.cpp b/pixelstats/SysfsCollector.cpp
index a79dda0d..f5685162 100644
--- a/pixelstats/SysfsCollector.cpp
+++ b/pixelstats/SysfsCollector.cpp
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 
+#include <pixelstats/JsonConfigUtils.h>
 #include <pixelstats/StatsHelper.h>
 #include <pixelstats/SysfsCollector.h>
 
@@ -33,6 +34,8 @@
 #include <cinttypes>
 #include <string>
 #include <filesystem>
+#include <fstream>
+#include <iostream>
 
 #ifndef ARRAY_SIZE
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
@@ -87,66 +90,8 @@ using android::hardware::google::pixel::PixelAtoms::WaterEventReported;
 using android::hardware::google::pixel::PixelAtoms::ZramBdStat;
 using android::hardware::google::pixel::PixelAtoms::ZramMmStat;
 
-SysfsCollector::SysfsCollector(const struct SysfsPaths &sysfs_paths)
-    : kSlowioReadCntPath(sysfs_paths.SlowioReadCntPath),
-      kSlowioWriteCntPath(sysfs_paths.SlowioWriteCntPath),
-      kSlowioUnmapCntPath(sysfs_paths.SlowioUnmapCntPath),
-      kSlowioSyncCntPath(sysfs_paths.SlowioSyncCntPath),
-      kCycleCountBinsPath(sysfs_paths.CycleCountBinsPath),
-      kImpedancePath(sysfs_paths.ImpedancePath),
-      kCodecPath(sysfs_paths.CodecPath),
-      kCodec1Path(sysfs_paths.Codec1Path),
-      kSpeechDspPath(sysfs_paths.SpeechDspPath),
-      kBatteryCapacityCC(sysfs_paths.BatteryCapacityCC),
-      kBatteryCapacityVFSOC(sysfs_paths.BatteryCapacityVFSOC),
-      kUFSLifetimeA(sysfs_paths.UFSLifetimeA),
-      kUFSLifetimeB(sysfs_paths.UFSLifetimeB),
-      kUFSLifetimeC(sysfs_paths.UFSLifetimeC),
-      kF2fsStatsPath(sysfs_paths.F2fsStatsPath),
-      kZramMmStatPath("/sys/block/zram0/mm_stat"),
-      kZramBdStatPath("/sys/block/zram0/bd_stat"),
-      kEEPROMPath(sysfs_paths.EEPROMPath),
-      kBrownoutCsvPath(sysfs_paths.BrownoutCsvPath),
-      kBrownoutLogPath(sysfs_paths.BrownoutLogPath),
-      kBrownoutReasonProp(sysfs_paths.BrownoutReasonProp),
-      kPowerMitigationStatsPath(sysfs_paths.MitigationPath),
-      kPowerMitigationDurationPath(sysfs_paths.MitigationDurationPath),
-      kSpeakerTemperaturePath(sysfs_paths.SpeakerTemperaturePath),
-      kSpeakerExcursionPath(sysfs_paths.SpeakerExcursionPath),
-      kSpeakerHeartbeatPath(sysfs_paths.SpeakerHeartBeatPath),
-      kUFSErrStatsPath(sysfs_paths.UFSErrStatsPath),
-      kBlockStatsLength(sysfs_paths.BlockStatsLength),
-      kAmsRatePath(sysfs_paths.AmsRatePath),
-      kThermalStatsPaths(sysfs_paths.ThermalStatsPaths),
-      kCCARatePath(sysfs_paths.CCARatePath),
-      kTempResidencyAndResetPaths(sysfs_paths.TempResidencyAndResetPaths),
-      kLongIRQMetricsPath(sysfs_paths.LongIRQMetricsPath),
-      kStormIRQMetricsPath(sysfs_paths.StormIRQMetricsPath),
-      kIRQStatsResetPath(sysfs_paths.IRQStatsResetPath),
-      kResumeLatencyMetricsPath(sysfs_paths.ResumeLatencyMetricsPath),
-      kModemPcieLinkStatsPath(sysfs_paths.ModemPcieLinkStatsPath),
-      kWifiPcieLinkStatsPath(sysfs_paths.WifiPcieLinkStatsPath),
-      kDisplayStatsPaths(sysfs_paths.DisplayStatsPaths),
-      kDisplayPortStatsPaths(sysfs_paths.DisplayPortStatsPaths),
-      kDisplayPortDSCStatsPaths(sysfs_paths.DisplayPortDSCStatsPaths),
-      kDisplayPortMaxResolutionStatsPaths(sysfs_paths.DisplayPortMaxResolutionStatsPaths),
-      kHDCPStatsPaths(sysfs_paths.HDCPStatsPaths),
-      kPDMStatePath(sysfs_paths.PDMStatePath),
-      kWavesPath(sysfs_paths.WavesPath),
-      kAdaptedInfoCountPath(sysfs_paths.AdaptedInfoCountPath),
-      kAdaptedInfoDurationPath(sysfs_paths.AdaptedInfoDurationPath),
-      kPcmLatencyPath(sysfs_paths.PcmLatencyPath),
-      kPcmCountPath(sysfs_paths.PcmCountPath),
-      kTotalCallCountPath(sysfs_paths.TotalCallCountPath),
-      kOffloadEffectsIdPath(sysfs_paths.OffloadEffectsIdPath),
-      kOffloadEffectsDurationPath(sysfs_paths.OffloadEffectsDurationPath),
-      kBluetoothAudioUsagePath(sysfs_paths.BluetoothAudioUsagePath),
-      kGMSRPath(sysfs_paths.GMSRPath),
-      kMaxfgHistoryPath("/dev/maxfg_history"),
-      kFGModelLoadingPath(sysfs_paths.FGModelLoadingPath),
-      kFGLogBufferPath(sysfs_paths.FGLogBufferPath),
-      kSpeakerVersionPath(sysfs_paths.SpeakerVersionPath),
-      kWaterEventPath(sysfs_paths.WaterEventPath){}
+SysfsCollector::SysfsCollector(const Json::Value& configData)
+    : configData(configData) {}
 
 bool SysfsCollector::ReadFileToInt(const std::string &path, int *val) {
     return ReadFileToInt(path.c_str(), val);
@@ -178,12 +123,16 @@ bool SysfsCollector::ReadFileToInt(const char *const path, int *val) {
 void SysfsCollector::logBatteryChargeCycles(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
     int val;
-    if (kCycleCountBinsPath == nullptr || strlen(kCycleCountBinsPath) == 0) {
-        ALOGV("Battery charge cycle path not specified");
+
+    std::string cycleCountBinsPath = getCStringOrDefault(configData, "CycleCountBinsPath");
+
+    if (cycleCountBinsPath.empty()) {
+        ALOGV("Battery charge cycle path not specified in JSON");
         return;
     }
-    if (!ReadFileToString(kCycleCountBinsPath, &file_contents)) {
-        ALOGE("Unable to read battery charge cycles %s - %s", kCycleCountBinsPath, strerror(errno));
+
+    if (!ReadFileToString(cycleCountBinsPath, &file_contents)) {
+        ALOGE("Unable to read battery charge cycles %s - %s", cycleCountBinsPath.c_str(), strerror(errno));
         return;
     }
 
@@ -213,16 +162,22 @@ void SysfsCollector::logBatteryChargeCycles(const std::shared_ptr<IStats> &stats
  * Read the contents of kEEPROMPath and report them.
  */
 void SysfsCollector::logBatteryEEPROM(const std::shared_ptr<IStats> &stats_client) {
-    if (kEEPROMPath == nullptr || strlen(kEEPROMPath) == 0) {
-        ALOGV("Battery EEPROM path not specified");
+    std::string EEPROMPath = getCStringOrDefault(configData, "EEPROMPath");
+    std::vector<std::string> GMSRPath = readStringVectorFromJson(configData["GMSRPath"]);
+    std::string maxfgHistoryPath = getCStringOrDefault(configData, "MaxfgHistoryPath");
+    std::vector<std::string> FGModelLoadingPath = readStringVectorFromJson(configData["FGModelLoadingPath"]);
+    std::vector<std::string> FGLogBufferPath = readStringVectorFromJson(configData["FGLogBufferPath"]);
+
+    if (EEPROMPath.empty()) {
+        ALOGV("Battery EEPROM path not specified in JSON");
     } else {
-        battery_EEPROM_reporter_.checkAndReport(stats_client, kEEPROMPath);
+        battery_EEPROM_reporter_.checkAndReport(stats_client, EEPROMPath);
     }
 
-    battery_EEPROM_reporter_.checkAndReportGMSR(stats_client, kGMSRPath);
-    battery_EEPROM_reporter_.checkAndReportMaxfgHistory(stats_client, kMaxfgHistoryPath);
-    battery_EEPROM_reporter_.checkAndReportFGModelLoading(stats_client, kFGModelLoadingPath);
-    battery_EEPROM_reporter_.checkAndReportFGLearning(stats_client, kFGLogBufferPath);
+    battery_EEPROM_reporter_.checkAndReportGMSR(stats_client, GMSRPath);
+    battery_EEPROM_reporter_.checkAndReportMaxfgHistory(stats_client, maxfgHistoryPath);
+    battery_EEPROM_reporter_.checkAndReportFGModelLoading(stats_client, FGModelLoadingPath);
+    battery_EEPROM_reporter_.checkAndReportFGLearning(stats_client, FGLogBufferPath);
 }
 
 /**
@@ -235,7 +190,8 @@ void SysfsCollector::logBatteryHistoryValidation() {
         return;
     }
 
-    battery_EEPROM_reporter_.checkAndReportValidation(stats_client, kFGLogBufferPath);
+    std::vector<std::string> FGLogBufferPath = readStringVectorFromJson(configData["FGLogBufferPath"]);
+    battery_EEPROM_reporter_.checkAndReportValidation(stats_client, FGLogBufferPath);
 }
 
 /**
@@ -257,14 +213,17 @@ void SysfsCollector::logBatteryTTF(const std::shared_ptr<IStats> &stats_client)
  */
 void SysfsCollector::logCodecFailed(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
-    if (kCodecPath == nullptr || strlen(kCodecPath) == 0) {
-        ALOGV("Audio codec path not specified");
+    std::string codecPath = getCStringOrDefault(configData, "CodecPath");
+
+    if (codecPath.empty()) {
+        ALOGV("Audio codec path not specified in JSON");
         return;
     }
-    if (!ReadFileToString(kCodecPath, &file_contents)) {
-        ALOGE("Unable to read codec state %s - %s", kCodecPath, strerror(errno));
+    if (!ReadFileToString(codecPath, &file_contents)) {
+        ALOGE("Unable to read codec state %s - %s", codecPath.c_str(), strerror(errno));
         return;
     }
+
     if (file_contents == "0") {
         return;
     } else {
@@ -281,18 +240,20 @@ void SysfsCollector::logCodecFailed(const std::shared_ptr<IStats> &stats_client)
  */
 void SysfsCollector::logCodec1Failed(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
-    if (kCodec1Path == nullptr || strlen(kCodec1Path) == 0) {
-        ALOGV("Audio codec1 path not specified");
+    std::string codec1Path = getCStringOrDefault(configData, "Codec1Path");
+
+    if (codec1Path.empty()) {
+        ALOGV("Audio codec1 path not specified in JSON");
         return;
     }
-    if (!ReadFileToString(kCodec1Path, &file_contents)) {
-        ALOGE("Unable to read codec1 state %s - %s", kCodec1Path, strerror(errno));
+    if (!ReadFileToString(codec1Path, &file_contents)) {
+        ALOGE("Unable to read codec1 state %s - %s", codec1Path.c_str(), strerror(errno));
         return;
     }
     if (file_contents == "0") {
         return;
     } else {
-        ALOGE("%s report hardware fail", kCodec1Path);
+        ALOGE("%s report hardware fail", codec1Path.c_str());
         VendorHardwareFailed failure;
         failure.set_hardware_type(VendorHardwareFailed::HARDWARE_FAILED_CODEC);
         failure.set_hardware_location(1);
@@ -302,20 +263,20 @@ void SysfsCollector::logCodec1Failed(const std::shared_ptr<IStats> &stats_client
 }
 
 void SysfsCollector::reportSlowIoFromFile(const std::shared_ptr<IStats> &stats_client,
-                                          const char *path,
-                                          const VendorSlowIo::IoOperation &operation_s) {
+                                            const std::string& path,
+                                            const VendorSlowIo::IoOperation &operation_s) {
     std::string file_contents;
-    if (path == nullptr || strlen(path) == 0) {
-        ALOGV("slow_io path not specified");
+    if (path.empty()) {
+        ALOGV("slow_io path not specified in JSON");
         return;
     }
-    if (!ReadFileToString(path, &file_contents)) {
-        ALOGE("Unable to read slowio %s - %s", path, strerror(errno));
+    if (!ReadFileToString(path.c_str(), &file_contents)) {
+        ALOGE("Unable to read slowio %s - %s", path.c_str(), strerror(errno));
         return;
     } else {
         int32_t slow_io_count = 0;
         if (sscanf(file_contents.c_str(), "%d", &slow_io_count) != 1) {
-            ALOGE("Unable to parse %s from file %s to int.", file_contents.c_str(), path);
+            ALOGE("Unable to parse %s from file %s to int.", file_contents.c_str(), path.c_str());
         } else if (slow_io_count > 0) {
             VendorSlowIo slow_io;
             slow_io.set_operation(operation_s);
@@ -323,8 +284,8 @@ void SysfsCollector::reportSlowIoFromFile(const std::shared_ptr<IStats> &stats_c
             reportSlowIo(stats_client, slow_io);
         }
         // Clear the stats
-        if (!android::base::WriteStringToFile("0", path, true)) {
-            ALOGE("Unable to clear SlowIO entry %s - %s", path, strerror(errno));
+        if (!android::base::WriteStringToFile("0", path.c_str(), true)) {
+            ALOGE("Unable to clear SlowIO entry %s - %s", path.c_str(), strerror(errno));
         }
     }
 }
@@ -333,10 +294,15 @@ void SysfsCollector::reportSlowIoFromFile(const std::shared_ptr<IStats> &stats_c
  * Check for slow IO operations.
  */
 void SysfsCollector::logSlowIO(const std::shared_ptr<IStats> &stats_client) {
-    reportSlowIoFromFile(stats_client, kSlowioReadCntPath, VendorSlowIo::READ);
-    reportSlowIoFromFile(stats_client, kSlowioWriteCntPath, VendorSlowIo::WRITE);
-    reportSlowIoFromFile(stats_client, kSlowioUnmapCntPath, VendorSlowIo::UNMAP);
-    reportSlowIoFromFile(stats_client, kSlowioSyncCntPath, VendorSlowIo::SYNC);
+    std::string slowioReadCntPath = getCStringOrDefault(configData, "SlowioReadCntPath");
+    std::string slowioWriteCntPath = getCStringOrDefault(configData, "SlowioWriteCntPath");
+    std::string slowioUnmapCntPath = getCStringOrDefault(configData, "SlowioUnmapCntPath");
+    std::string slowioSyncCntPath = getCStringOrDefault(configData, "SlowioSyncCntPath");
+
+    reportSlowIoFromFile(stats_client, slowioReadCntPath, VendorSlowIo::READ);
+    reportSlowIoFromFile(stats_client, slowioWriteCntPath, VendorSlowIo::WRITE);
+    reportSlowIoFromFile(stats_client, slowioUnmapCntPath, VendorSlowIo::UNMAP);
+    reportSlowIoFromFile(stats_client, slowioSyncCntPath, VendorSlowIo::SYNC);
 }
 
 /**
@@ -344,12 +310,15 @@ void SysfsCollector::logSlowIO(const std::shared_ptr<IStats> &stats_client) {
  */
 void SysfsCollector::logSpeakerImpedance(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
-    if (kImpedancePath == nullptr || strlen(kImpedancePath) == 0) {
-        ALOGV("Audio impedance path not specified");
+    std::string impedancePath = getCStringOrDefault(configData, "ImpedancePath");
+
+    if (impedancePath.empty()) {
+        ALOGV("Audio impedance path not specified in JSON");
         return;
     }
-    if (!ReadFileToString(kImpedancePath, &file_contents)) {
-        ALOGE("Unable to read impedance path %s", kImpedancePath);
+
+    if (!ReadFileToString(impedancePath, &file_contents)) {
+        ALOGE("Unable to read impedance path %s", impedancePath.c_str());
         return;
     }
 
@@ -384,41 +353,47 @@ void SysfsCollector::logSpeakerHealthStats(const std::shared_ptr<IStats> &stats_
     float excursion_mm[4];
     float heartbeat[4];
 
-    if (kImpedancePath == nullptr || strlen(kImpedancePath) == 0) {
-        ALOGD("Audio impedance path not specified");
+    std::string impedancePath = getCStringOrDefault(configData, "ImpedancePath");
+    std::string speakerTemperaturePath = getCStringOrDefault(configData, "SpeakerTemperaturePath");
+    std::string speakerExcursionPath = getCStringOrDefault(configData, "SpeakerExcursionPath");
+    std::string speakerHeartbeatPath = getCStringOrDefault(configData, "SpeakerHeartBeatPath");
+    std::string speakerVersionPath = getCStringOrDefault(configData, "SpeakerVersionPath");
+
+    if (impedancePath.empty()) {
+        ALOGV("Audio impedance path not specified in JSON");
         return;
-    } else if (!ReadFileToString(kImpedancePath, &file_contents_impedance)) {
-        ALOGD("Unable to read speaker impedance path %s", kImpedancePath);
+    } else if (!ReadFileToString(impedancePath, &file_contents_impedance)) {
+        ALOGD("Unable to read speaker impedance path %s", impedancePath.c_str());
         return;
     }
 
-    if (kSpeakerTemperaturePath == nullptr || strlen(kSpeakerTemperaturePath) == 0) {
-        ALOGD("Audio speaker temperature path not specified");
+    if (speakerTemperaturePath.empty()) {
+        ALOGV("Audio speaker temperature path not specified in JSON");
         return;
-    } else if (!ReadFileToString(kSpeakerTemperaturePath, &file_contents_temperature)) {
-        ALOGD("Unable to read speaker temperature path %s", kSpeakerTemperaturePath);
+    } else if (!ReadFileToString(speakerTemperaturePath, &file_contents_temperature)) {
+        ALOGD("Unable to read speaker temperature path %s", speakerTemperaturePath.c_str());
         return;
     }
 
-    if (kSpeakerExcursionPath == nullptr || strlen(kSpeakerExcursionPath) == 0) {
-        ALOGD("Audio speaker excursion path not specified");
+    if (speakerExcursionPath.empty()) {
+        ALOGV("Audio speaker excursion path not specified in JSON");
         return;
-    } else if (!ReadFileToString(kSpeakerExcursionPath, &file_contents_excursion)) {
-        ALOGD("Unable to read speaker excursion path %s", kSpeakerExcursionPath);
+    } else if (!ReadFileToString(speakerExcursionPath, &file_contents_excursion)) {
+        ALOGD("Unable to read speaker excursion path %s", speakerExcursionPath.c_str());
         return;
     }
 
-    if (kSpeakerHeartbeatPath == nullptr || strlen(kSpeakerHeartbeatPath) == 0) {
-        ALOGD("Audio speaker heartbeat path not specified");
+    if (speakerHeartbeatPath.empty()) {
+        ALOGV("Audio speaker heartbeat path not specified in JSON");
         return;
-    } else if (!ReadFileToString(kSpeakerHeartbeatPath, &file_contents_heartbeat)) {
-        ALOGD("Unable to read speaker heartbeat path %s", kSpeakerHeartbeatPath);
+    } else if (!ReadFileToString(speakerHeartbeatPath, &file_contents_heartbeat)) {
+        ALOGD("Unable to read speaker heartbeat path %s", speakerHeartbeatPath.c_str());
         return;
     }
 
-    if (kSpeakerVersionPath == nullptr || strlen(kSpeakerVersionPath) == 0) {
-        ALOGD("Audio speaker version path not specified. Keep version 0");
-    } else if (!ReadFileToInt(kSpeakerVersionPath, &version)) {
+    if (speakerVersionPath.empty()) {
+        ALOGV("Audio speaker version path not specified in JSON. Keep version 0");
+    } else if (!ReadFileToInt(speakerVersionPath, &version)) {
         ALOGD("Unable to read version. Keep version 0");
     }
 
@@ -460,31 +435,43 @@ void SysfsCollector::logSpeakerHealthStats(const std::shared_ptr<IStats> &stats_
 }
 
 void SysfsCollector::logDisplayStats(const std::shared_ptr<IStats> &stats_client) {
-    display_stats_reporter_.logDisplayStats(stats_client, kDisplayStatsPaths,
+    std::vector<std::string> displayStatsPaths =
+        readStringVectorFromJson(configData["DisplayStatsPaths"]);
+    display_stats_reporter_.logDisplayStats(stats_client, displayStatsPaths,
                                             DisplayStatsReporter::DISP_PANEL_STATE);
 }
 
 void SysfsCollector::logDisplayPortStats(const std::shared_ptr<IStats> &stats_client) {
-    display_stats_reporter_.logDisplayStats(stats_client, kDisplayPortStatsPaths,
+    std::vector<std::string> displayPortStatsPaths =
+        readStringVectorFromJson(configData["DisplayPortStatsPaths"]);
+    display_stats_reporter_.logDisplayStats(stats_client, displayPortStatsPaths,
                                             DisplayStatsReporter::DISP_PORT_STATE);
 }
 
 void SysfsCollector::logHDCPStats(const std::shared_ptr<IStats> &stats_client) {
-    display_stats_reporter_.logDisplayStats(stats_client, kHDCPStatsPaths,
+    std::vector<std::string> HDCPStatsPaths =
+        readStringVectorFromJson(configData["HDCPStatsPaths"]);
+    display_stats_reporter_.logDisplayStats(stats_client, HDCPStatsPaths,
                                             DisplayStatsReporter::HDCP_STATE);
 }
 
 void SysfsCollector::logThermalStats(const std::shared_ptr<IStats> &stats_client) {
-    thermal_stats_reporter_.logThermalStats(stats_client, kThermalStatsPaths);
+    std::vector<std::string> thermalStatsPaths =
+        readStringVectorFromJson(configData["ThermalStatsPaths"]);
+    thermal_stats_reporter_.logThermalStats(stats_client, thermalStatsPaths);
 }
 
 void SysfsCollector::logDisplayPortDSCStats(const std::shared_ptr<IStats> &stats_client) {
-    display_stats_reporter_.logDisplayStats(stats_client, kDisplayPortDSCStatsPaths,
+    std::vector<std::string> displayPortDSCStatsPaths =
+        readStringVectorFromJson(configData["DisplayPortDSCStatsPaths"]);
+    display_stats_reporter_.logDisplayStats(stats_client, displayPortDSCStatsPaths,
                                             DisplayStatsReporter::DISP_PORT_DSC_STATE);
 }
 
 void SysfsCollector::logDisplayPortMaxResolutionStats(const std::shared_ptr<IStats> &stats_client) {
-    display_stats_reporter_.logDisplayStats(stats_client, kDisplayPortMaxResolutionStatsPaths,
+    std::vector<std::string> displayPortMaxResolutionStatsPaths =
+        readStringVectorFromJson(configData["DisplayPortMaxResolutionStatsPaths"]);
+    display_stats_reporter_.logDisplayStats(stats_client, displayPortMaxResolutionStatsPaths,
                                             DisplayStatsReporter::DISP_PORT_MAX_RES_STATE);
 }
 /**
@@ -492,12 +479,16 @@ void SysfsCollector::logDisplayPortMaxResolutionStats(const std::shared_ptr<ISta
  */
 void SysfsCollector::logSpeechDspStat(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
-    if (kSpeechDspPath == nullptr || strlen(kSpeechDspPath) == 0) {
-        ALOGV("Speech DSP path not specified");
+
+    std::string speechDspPath = getCStringOrDefault(configData, "SpeechDspPath");
+
+    if (speechDspPath.empty()) {
+        ALOGV("Speech DSP path not specified in JSON");
         return;
     }
-    if (!ReadFileToString(kSpeechDspPath, &file_contents)) {
-        ALOGE("Unable to read speech dsp path %s", kSpeechDspPath);
+
+    if (!ReadFileToString(speechDspPath, &file_contents)) {
+        ALOGE("Unable to read speech dsp path %s", speechDspPath.c_str());
         return;
     }
 
@@ -521,17 +512,22 @@ void SysfsCollector::logSpeechDspStat(const std::shared_ptr<IStats> &stats_clien
 
 void SysfsCollector::logBatteryCapacity(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
-    if (kBatteryCapacityCC == nullptr || strlen(kBatteryCapacityCC) == 0) {
-        ALOGV("Battery Capacity CC path not specified");
+
+    std::string batteryCapacityCC = getCStringOrDefault(configData, "BatteryCapacityCC");
+    std::string batteryCapacityVFSOC = getCStringOrDefault(configData, "BatteryCapacityVFSOC");
+
+    if (batteryCapacityCC.empty()) {
+        ALOGV("Battery Capacity CC path not specified in JSON");
         return;
     }
-    if (kBatteryCapacityVFSOC == nullptr || strlen(kBatteryCapacityVFSOC) == 0) {
-        ALOGV("Battery Capacity VFSOC path not specified");
+    if (batteryCapacityVFSOC.empty()) {
+        ALOGV("Battery Capacity VFSOC path not specified in JSON");
         return;
     }
+
     int delta_cc_sum, delta_vfsoc_sum;
-    if (!ReadFileToInt(kBatteryCapacityCC, &delta_cc_sum) ||
-            !ReadFileToInt(kBatteryCapacityVFSOC, &delta_vfsoc_sum))
+    if (!ReadFileToInt(batteryCapacityCC, &delta_cc_sum) ||
+        !ReadFileToInt(batteryCapacityVFSOC, &delta_vfsoc_sum))
         return;
 
     // Load values array
@@ -553,23 +549,28 @@ void SysfsCollector::logBatteryCapacity(const std::shared_ptr<IStats> &stats_cli
 
 void SysfsCollector::logUFSLifetime(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
-    if (kUFSLifetimeA == nullptr || strlen(kUFSLifetimeA) == 0) {
-        ALOGV("UFS lifetimeA path not specified");
+
+    std::string UFSLifetimeA = getCStringOrDefault(configData, "UFSLifetimeA");
+    std::string UFSLifetimeB = getCStringOrDefault(configData, "UFSLifetimeB");
+    std::string UFSLifetimeC = getCStringOrDefault(configData, "UFSLifetimeC");
+
+    if (UFSLifetimeA.empty()) {
+        ALOGV("UFS lifetimeA path not specified in JSON");
         return;
     }
-    if (kUFSLifetimeB == nullptr || strlen(kUFSLifetimeB) == 0) {
-        ALOGV("UFS lifetimeB path not specified");
+    if (UFSLifetimeB.empty()) {
+        ALOGV("UFS lifetimeB path not specified in JSON");
         return;
     }
-    if (kUFSLifetimeC == nullptr || strlen(kUFSLifetimeC) == 0) {
-        ALOGV("UFS lifetimeC path not specified");
+    if (UFSLifetimeC.empty()) {
+        ALOGV("UFS lifetimeC path not specified in JSON");
         return;
     }
 
     int lifetimeA = 0, lifetimeB = 0, lifetimeC = 0;
-    if (!ReadFileToInt(kUFSLifetimeA, &lifetimeA) ||
-        !ReadFileToInt(kUFSLifetimeB, &lifetimeB) ||
-        !ReadFileToInt(kUFSLifetimeC, &lifetimeC)) {
+    if (!ReadFileToInt(UFSLifetimeA, &lifetimeA) ||
+        !ReadFileToInt(UFSLifetimeB, &lifetimeB) ||
+        !ReadFileToInt(UFSLifetimeC, &lifetimeC)) {
         ALOGE("Unable to read UFS lifetime : %s", strerror(errno));
         return;
     }
@@ -597,13 +598,15 @@ void SysfsCollector::logUFSLifetime(const std::shared_ptr<IStats> &stats_client)
 void SysfsCollector::logUFSErrorStats(const std::shared_ptr<IStats> &stats_client) {
     int value, host_reset_count = 0;
 
-    if (kUFSErrStatsPath.empty() || strlen(kUFSErrStatsPath.front().c_str()) == 0) {
-        ALOGV("UFS host reset count path not specified");
+    std::vector<std::string> UFSErrStatsPath = readStringVectorFromJson(configData["UFSErrStatsPath"]);
+
+    if (UFSErrStatsPath.empty() || strlen(UFSErrStatsPath.front().c_str()) == 0) {
+        ALOGV("UFS host reset count path not specified in JSON");
         return;
     }
 
-    for (int i = 0; i < kUFSErrStatsPath.size(); i++) {
-        if (!ReadFileToInt(kUFSErrStatsPath[i], &value)) {
+    for (int i = 0; i < UFSErrStatsPath.size(); i++) {
+        if (!ReadFileToInt(UFSErrStatsPath[i], &value)) {
             ALOGE("Unable to read host reset count");
             return;
         }
@@ -646,47 +649,49 @@ void SysfsCollector::logF2fsStats(const std::shared_ptr<IStats> &stats_client) {
     int dirty, free, cp_calls_fg, gc_calls_fg, moved_block_fg, vblocks;
     int cp_calls_bg, gc_calls_bg, moved_block_bg;
 
-    if (kF2fsStatsPath == nullptr) {
-        ALOGE("F2fs stats path not specified");
+    std::string F2fsStatsPath = getCStringOrDefault(configData, "F2fsStatsPath");
+
+    if (F2fsStatsPath.empty()) {
+        ALOGV("F2fs stats path not specified in JSON");
         return;
     }
 
     const std::string userdataBlock = getUserDataBlock();
-    const std::string kF2fsStatsDir = kF2fsStatsPath + userdataBlock;
+    const std::string F2fsStatsDir = F2fsStatsPath + userdataBlock;
 
-    if (!ReadFileToInt(kF2fsStatsDir + "/dirty_segments", &dirty)) {
+    if (!ReadFileToInt(F2fsStatsDir + "/dirty_segments", &dirty)) {
         ALOGV("Unable to read dirty segments");
     }
 
-    if (!ReadFileToInt(kF2fsStatsDir + "/free_segments", &free)) {
+    if (!ReadFileToInt(F2fsStatsDir + "/free_segments", &free)) {
         ALOGV("Unable to read free segments");
     }
 
-    if (!ReadFileToInt(kF2fsStatsDir + "/cp_foreground_calls", &cp_calls_fg)) {
+    if (!ReadFileToInt(F2fsStatsDir + "/cp_foreground_calls", &cp_calls_fg)) {
         ALOGV("Unable to read cp_foreground_calls");
     }
 
-    if (!ReadFileToInt(kF2fsStatsDir + "/cp_background_calls", &cp_calls_bg)) {
+    if (!ReadFileToInt(F2fsStatsDir + "/cp_background_calls", &cp_calls_bg)) {
         ALOGV("Unable to read cp_background_calls");
     }
 
-    if (!ReadFileToInt(kF2fsStatsDir + "/gc_foreground_calls", &gc_calls_fg)) {
+    if (!ReadFileToInt(F2fsStatsDir + "/gc_foreground_calls", &gc_calls_fg)) {
         ALOGV("Unable to read gc_foreground_calls");
     }
 
-    if (!ReadFileToInt(kF2fsStatsDir + "/gc_background_calls", &gc_calls_bg)) {
+    if (!ReadFileToInt(F2fsStatsDir + "/gc_background_calls", &gc_calls_bg)) {
         ALOGV("Unable to read gc_background_calls");
     }
 
-    if (!ReadFileToInt(kF2fsStatsDir + "/moved_blocks_foreground", &moved_block_fg)) {
+    if (!ReadFileToInt(F2fsStatsDir + "/moved_blocks_foreground", &moved_block_fg)) {
         ALOGV("Unable to read moved_blocks_foreground");
     }
 
-    if (!ReadFileToInt(kF2fsStatsDir + "/moved_blocks_background", &moved_block_bg)) {
+    if (!ReadFileToInt(F2fsStatsDir + "/moved_blocks_background", &moved_block_bg)) {
         ALOGV("Unable to read moved_blocks_background");
     }
 
-    if (!ReadFileToInt(kF2fsStatsDir + "/avg_vblocks", &vblocks)) {
+    if (!ReadFileToInt(F2fsStatsDir + "/avg_vblocks", &vblocks)) {
         ALOGV("Unable to read avg_vblocks");
     }
 
@@ -725,14 +730,16 @@ void SysfsCollector::logF2fsStats(const std::shared_ptr<IStats> &stats_client) {
 void SysfsCollector::logF2fsAtomicWriteInfo(const std::shared_ptr<IStats> &stats_client) {
     int peak_atomic_write, committed_atomic_block, revoked_atomic_block;
 
-    if (kF2fsStatsPath == nullptr) {
-        ALOGV("F2fs stats path not specified");
+    std::string F2fsStatsPath = getCStringOrDefault(configData, "F2fsStatsPath");
+
+    if (F2fsStatsPath.empty()) {
+        ALOGV("F2fs stats path not specified in JSON");
         return;
     }
 
     std::string userdataBlock = getUserDataBlock();
 
-    std::string path = kF2fsStatsPath + (userdataBlock + "/peak_atomic_write");
+    std::string path = F2fsStatsPath + (userdataBlock + "/peak_atomic_write");
     if (!ReadFileToInt(path, &peak_atomic_write)) {
         ALOGE("Unable to read peak_atomic_write");
         return;
@@ -743,7 +750,7 @@ void SysfsCollector::logF2fsAtomicWriteInfo(const std::shared_ptr<IStats> &stats
         }
     }
 
-    path = kF2fsStatsPath + (userdataBlock + "/committed_atomic_block");
+    path = F2fsStatsPath + (userdataBlock + "/committed_atomic_block");
     if (!ReadFileToInt(path, &committed_atomic_block)) {
         ALOGE("Unable to read committed_atomic_block");
         return;
@@ -754,7 +761,7 @@ void SysfsCollector::logF2fsAtomicWriteInfo(const std::shared_ptr<IStats> &stats
         }
     }
 
-    path = kF2fsStatsPath + (userdataBlock + "/revoked_atomic_block");
+    path = F2fsStatsPath + (userdataBlock + "/revoked_atomic_block");
     if (!ReadFileToInt(path, &revoked_atomic_block)) {
         ALOGE("Unable to read revoked_atomic_block");
         return;
@@ -787,20 +794,22 @@ void SysfsCollector::logF2fsAtomicWriteInfo(const std::shared_ptr<IStats> &stats
 void SysfsCollector::logF2fsCompressionInfo(const std::shared_ptr<IStats> &stats_client) {
     int compr_written_blocks, compr_saved_blocks, compr_new_inodes;
 
-    if (kF2fsStatsPath == nullptr) {
-        ALOGV("F2fs stats path not specified");
+    std::string F2fsStatsPath = getCStringOrDefault(configData, "F2fsStatsPath");
+
+    if (F2fsStatsPath.empty()) {
+        ALOGV("F2fs stats path not specified in JSON");
         return;
     }
 
     std::string userdataBlock = getUserDataBlock();
 
-    std::string path = kF2fsStatsPath + (userdataBlock + "/compr_written_block");
+    std::string path = F2fsStatsPath + (userdataBlock + "/compr_written_block");
     if (!ReadFileToInt(path, &compr_written_blocks)) {
         ALOGE("Unable to read compression written blocks");
         return;
     }
 
-    path = kF2fsStatsPath + (userdataBlock + "/compr_saved_block");
+    path = F2fsStatsPath + (userdataBlock + "/compr_saved_block");
     if (!ReadFileToInt(path, &compr_saved_blocks)) {
         ALOGE("Unable to read compression saved blocks");
         return;
@@ -811,7 +820,7 @@ void SysfsCollector::logF2fsCompressionInfo(const std::shared_ptr<IStats> &stats
         }
     }
 
-    path = kF2fsStatsPath + (userdataBlock + "/compr_new_inode");
+    path = F2fsStatsPath + (userdataBlock + "/compr_new_inode");
     if (!ReadFileToInt(path, &compr_new_inodes)) {
         ALOGE("Unable to read compression new inodes");
         return;
@@ -843,7 +852,13 @@ void SysfsCollector::logF2fsCompressionInfo(const std::shared_ptr<IStats> &stats
 }
 
 int SysfsCollector::getReclaimedSegments(const std::string &mode) {
-    std::string userDataStatsPath = kF2fsStatsPath + getUserDataBlock();
+    std::string F2fsStatsPath = getCStringOrDefault(configData, "F2fsStatsPath");
+
+    if (F2fsStatsPath.empty()) {
+        ALOGV("F2fs stats path not specified in JSON");
+        return -1;
+    }
+    std::string userDataStatsPath = F2fsStatsPath + getUserDataBlock();
     std::string gcSegmentModePath = userDataStatsPath + "/gc_segment_mode";
     std::string gcReclaimedSegmentsPath = userDataStatsPath + "/gc_reclaimed_segments";
     int reclaimed_segments;
@@ -874,11 +889,6 @@ void SysfsCollector::logF2fsGcSegmentInfo(const std::shared_ptr<IStats> &stats_c
     std::string gc_urgent_low_mode = std::to_string(5);     // GC urgent low mode
     std::string gc_urgent_mid_mode = std::to_string(6);     // GC urgent mid mode
 
-    if (kF2fsStatsPath == nullptr) {
-        ALOGV("F2fs stats path not specified");
-        return;
-    }
-
     reclaimed_segments_normal = getReclaimedSegments(gc_normal_mode);
     if (reclaimed_segments_normal == -1) return;
     reclaimed_segments_urgent_high = getReclaimedSegments(gc_urgent_high_mode);
@@ -1038,9 +1048,16 @@ void SysfsCollector::logBlockStatsReported(const std::shared_ptr<IStats> &stats_
         stats.push_back(stat);
     }
 
-    if (stats.size() < kBlockStatsLength) {
+    int blockStatsLength = getIntOrDefault(configData, "BlockStatsLength");
+
+    if (blockStatsLength <= 0) {
+        ALOGV("BlockStatsLength not found or invalid in JSON");
+        return;
+    }
+
+    if (stats.size() < blockStatsLength) {
         ALOGE("block layer stat format is incorrect %s, length %zu/%d", file_contents.c_str(),
-              stats.size(), kBlockStatsLength);
+              stats.size(), blockStatsLength);
         return;
     }
 
@@ -1077,7 +1094,10 @@ void SysfsCollector::logBlockStatsReported(const std::shared_ptr<IStats> &stats_
 }
 
 void SysfsCollector::logTempResidencyStats(const std::shared_ptr<IStats> &stats_client) {
-    for (const auto &temp_residency_and_reset_path : kTempResidencyAndResetPaths) {
+    std::vector<std::pair<std::string, std::string>> tempResidencyAndResetPaths =
+        readStringPairVectorFromJson(configData["TempResidencyAndResetPaths"]);
+
+    for (const auto &temp_residency_and_reset_path : tempResidencyAndResetPaths) {
         temp_residency_reporter_.logTempResidencyStats(stats_client,
                                                        temp_residency_and_reset_path.first,
                                                        temp_residency_and_reset_path.second);
@@ -1086,13 +1106,10 @@ void SysfsCollector::logTempResidencyStats(const std::shared_ptr<IStats> &stats_
 
 void SysfsCollector::reportZramMmStat(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
-    if (!kZramMmStatPath) {
-        ALOGV("ZramMmStat path not specified");
-        return;
-    }
+    std::string ZramMmStatPath = "/sys/block/zram0/mm_stat";
 
-    if (!ReadFileToString(kZramMmStatPath, &file_contents)) {
-        ALOGE("Unable to ZramMmStat %s - %s", kZramMmStatPath, strerror(errno));
+    if (!ReadFileToString(ZramMmStatPath.c_str(), &file_contents)) {
+        ALOGE("Unable to ZramMmStat %s - %s", ZramMmStatPath.c_str(), strerror(errno));
         return;
     } else {
         int64_t orig_data_size = 0;
@@ -1113,7 +1130,7 @@ void SysfsCollector::reportZramMmStat(const std::shared_ptr<IStats> &stats_clien
                    &orig_data_size, &compr_data_size, &mem_used_total, &mem_limit, &max_used_total,
                    &same_pages, &pages_compacted, &huge_pages, &huge_pages_since_boot) < 8) {
             ALOGE("Unable to parse ZramMmStat %s from file %s to int.",
-                    file_contents.c_str(), kZramMmStatPath);
+                    file_contents.c_str(), ZramMmStatPath.c_str());
         }
 
         // Load values array.
@@ -1153,13 +1170,10 @@ void SysfsCollector::reportZramMmStat(const std::shared_ptr<IStats> &stats_clien
 
 void SysfsCollector::reportZramBdStat(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
-    if (!kZramBdStatPath) {
-        ALOGV("ZramBdStat path not specified");
-        return;
-    }
+    std::string ZramBdStatPath = "/sys/block/zram0/bd_stat";
 
-    if (!ReadFileToString(kZramBdStatPath, &file_contents)) {
-        ALOGE("Unable to ZramBdStat %s - %s", kZramBdStatPath, strerror(errno));
+    if (!ReadFileToString(ZramBdStatPath.c_str(), &file_contents)) {
+        ALOGE("Unable to ZramBdStat %s - %s", ZramBdStatPath.c_str(), strerror(errno));
         return;
     } else {
         int64_t bd_count = 0;
@@ -1169,7 +1183,7 @@ void SysfsCollector::reportZramBdStat(const std::shared_ptr<IStats> &stats_clien
         if (sscanf(file_contents.c_str(), "%" SCNd64 " %" SCNd64 " %" SCNd64,
                                 &bd_count, &bd_reads, &bd_writes) != 3) {
             ALOGE("Unable to parse ZramBdStat %s from file %s to int.",
-                    file_contents.c_str(), kZramBdStatPath);
+                    file_contents.c_str(), ZramBdStatPath.c_str());
         }
 
         // Load values array
@@ -1200,14 +1214,16 @@ void SysfsCollector::logZramStats(const std::shared_ptr<IStats> &stats_client) {
 void SysfsCollector::logBootStats(const std::shared_ptr<IStats> &stats_client) {
     int mounted_time_sec = 0;
 
-    if (kF2fsStatsPath == nullptr) {
-        ALOGE("F2fs stats path not specified");
+    std::string F2fsStatsPath = getCStringOrDefault(configData, "F2fsStatsPath");
+
+    if (F2fsStatsPath.empty()) {
+        ALOGV("F2fs stats path not specified in JSON");
         return;
     }
 
     std::string userdataBlock = getUserDataBlock();
 
-    if (!ReadFileToInt(kF2fsStatsPath + (userdataBlock + "/mounted_time_sec"), &mounted_time_sec)) {
+    if (!ReadFileToInt(F2fsStatsPath + (userdataBlock + "/mounted_time_sec"), &mounted_time_sec)) {
         ALOGV("Unable to read mounted_time_sec");
         return;
     }
@@ -1251,11 +1267,15 @@ void SysfsCollector::logVendorAudioHardwareStats(const std::shared_ptr<IStats> &
     uint32_t total_call_voice = 0, total_call_voip = 0;
     bool isAmsReady = false, isCCAReady = false;
 
-    if (kAmsRatePath == nullptr) {
-        ALOGD("Audio AMS Rate path not specified");
+    std::string AmsRatePath = getCStringOrDefault(configData, "AmsRatePath");
+    std::string CCARatePath = getCStringOrDefault(configData, "CCARatePath");
+    std::string TotalCallCountPath = getCStringOrDefault(configData, "TotalCallCountPath");
+
+    if (AmsRatePath.empty()) {
+        ALOGV("Audio AMS Rate path not specified in JSON");
     } else {
-        if (!ReadFileToString(kAmsRatePath, &file_contents)) {
-            ALOGD("Unable to read ams_rate path %s", kAmsRatePath);
+        if (!ReadFileToString(AmsRatePath.c_str(), &file_contents)) {
+            ALOGD("Unable to read ams_rate path %s", AmsRatePath.c_str());
         } else {
             if (sscanf(file_contents.c_str(), "%u", &milli_ams_rate) != 1) {
                 ALOGD("Unable to parse ams_rate %s", file_contents.c_str());
@@ -1266,11 +1286,11 @@ void SysfsCollector::logVendorAudioHardwareStats(const std::shared_ptr<IStats> &
         }
     }
 
-    if (kCCARatePath == nullptr) {
-        ALOGD("Audio CCA Rate path not specified");
+    if (CCARatePath.empty()) {
+        ALOGV("Audio CCA Rate path not specified in JSON");
     } else {
-        if (!ReadFileToString(kCCARatePath, &file_contents)) {
-            ALOGD("Unable to read cca_rate path %s", kCCARatePath);
+        if (!ReadFileToString(CCARatePath.c_str(), &file_contents)) {
+            ALOGD("Unable to read cca_rate path %s", CCARatePath.c_str());
         } else {
             if (sscanf(file_contents.c_str(), "%u %u %u %u", &c1, &c2, &c3, &c4) != 4) {
                 ALOGD("Unable to parse cca rates %s", file_contents.c_str());
@@ -1280,11 +1300,11 @@ void SysfsCollector::logVendorAudioHardwareStats(const std::shared_ptr<IStats> &
         }
     }
 
-    if (kTotalCallCountPath == nullptr) {
-        ALOGD("Total call count path not specified");
+    if (TotalCallCountPath.empty()) {
+        ALOGV("Total call count path not specified in JSON");
     } else {
-        if (!ReadFileToString(kTotalCallCountPath, &file_contents)) {
-            ALOGD("Unable to read total call path %s", kTotalCallCountPath);
+        if (!ReadFileToString(TotalCallCountPath.c_str(), &file_contents)) {
+            ALOGD("Unable to read total call path %s", TotalCallCountPath.c_str());
         } else {
             if (sscanf(file_contents.c_str(), "%u %u", &total_call_voice, &total_call_voip) != 2) {
                 ALOGD("Unable to parse total call %s", file_contents.c_str());
@@ -1373,12 +1393,13 @@ void SysfsCollector::logVendorAudioHardwareStats(const std::shared_ptr<IStats> &
 void SysfsCollector::logVendorAudioPdmStatsReported(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
     std::vector<int> pdm_states;
+    std::string PDMStatePath = getCStringOrDefault(configData, "PDMStatePath");
 
-    if (kPDMStatePath == nullptr) {
-        ALOGD("Audio PDM State path not specified");
+    if (PDMStatePath.empty()) {
+        ALOGV("Audio PDM State path not specified in JSON");
     } else {
-        if (!ReadFileToString(kPDMStatePath, &file_contents)) {
-            ALOGD("Unable to read PDM State path %s", kPDMStatePath);
+        if (!ReadFileToString(PDMStatePath.c_str(), &file_contents)) {
+            ALOGD("Unable to read PDM State path %s", PDMStatePath.c_str());
         } else {
             std::stringstream file_content_stream(file_contents);
             while (file_content_stream.good()) {
@@ -1436,17 +1457,18 @@ void SysfsCollector::logVendorAudioPdmStatsReported(const std::shared_ptr<IStats
 void SysfsCollector::logWavesStats(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
     std::vector<std::vector<int>> volume_duration_per_instance;
+    std::string wavesPath = getCStringOrDefault(configData, "WavesPath");
 
     constexpr int num_instances = 5;
     constexpr int num_volume = 10;
 
-    if (kWavesPath == nullptr) {
-        ALOGD("Audio Waves stats path not specified");
+    if (wavesPath.empty()) {
+        ALOGV("Audio Waves stats path not specified in JSON");
         return;
     }
 
-    if (!ReadFileToString(kWavesPath, &file_contents)) {
-        ALOGD("Unable to read Wave stats path %s", kWavesPath);
+    if (!ReadFileToString(wavesPath.c_str(), &file_contents)) {
+        ALOGD("Unable to read Wave stats path %s", wavesPath.c_str());
     } else {
         std::stringstream file_content_stream(file_contents);
         int duration;
@@ -1526,21 +1548,23 @@ void SysfsCollector::logAdaptedInfoStats(const std::shared_ptr<IStats> &stats_cl
     std::string file_contents;
     std::vector<int> count_per_feature;
     std::vector<int> duration_per_feature;
+    std::string adaptedInfoCountPath = getCStringOrDefault(configData, "AdaptedInfoCountPath");
+    std::string adaptedInfoDurationPath = getCStringOrDefault(configData, "AdaptedInfoDurationPath");
 
     constexpr int num_features = 6;
 
-    if (kAdaptedInfoCountPath == nullptr) {
-        ALOGD("Audio Adapted Info Count stats path not specified");
+    if (adaptedInfoCountPath.empty()) {
+        ALOGV("Audio Adapted Info Count stats path not specified in JSON");
         return;
     }
 
-    if (kAdaptedInfoDurationPath == nullptr) {
-        ALOGD("Audio Adapted Info Duration stats path not specified");
+    if (adaptedInfoDurationPath.empty()) {
+        ALOGV("Audio Adapted Info Duration stats path not specified in JSON");
         return;
     }
 
-    if (!ReadFileToString(kAdaptedInfoCountPath, &file_contents)) {
-        ALOGD("Unable to read Adapted Info Count stats path %s", kAdaptedInfoCountPath);
+    if (!ReadFileToString(adaptedInfoCountPath.c_str(), &file_contents)) {
+        ALOGD("Unable to read Adapted Info Count stats path %s", adaptedInfoCountPath.c_str());
     } else {
         std::stringstream file_content_stream(file_contents);
         int count;
@@ -1555,8 +1579,8 @@ void SysfsCollector::logAdaptedInfoStats(const std::shared_ptr<IStats> &stats_cl
         return;
     }
 
-    if (!ReadFileToString(kAdaptedInfoDurationPath, &file_contents)) {
-        ALOGD("Unable to read Adapted Info Duration stats path %s", kAdaptedInfoDurationPath);
+    if (!ReadFileToString(adaptedInfoDurationPath.c_str(), &file_contents)) {
+        ALOGD("Unable to read Adapted Info Duration stats path %s", adaptedInfoDurationPath.c_str());
     } else {
         std::stringstream file_content_stream(file_contents);
         int duration;
@@ -1610,21 +1634,22 @@ void SysfsCollector::logPcmUsageStats(const std::shared_ptr<IStats> &stats_clien
     std::string file_contents;
     std::vector<int> count_per_type;
     std::vector<int> latency_per_type;
+    std::string pcmLatencyPath = getCStringOrDefault(configData, "PcmLatencyPath");
+    std::string pcmCountPath = getCStringOrDefault(configData, "PcmCountPath");
 
     constexpr int num_type = 19;
-
-    if (kPcmLatencyPath == nullptr) {
-        ALOGD("PCM Latency path not specified");
+    if (pcmLatencyPath.empty()) {
+        ALOGV("PCM Latency path not specified in JSON");
         return;
     }
 
-    if (kPcmCountPath == nullptr) {
-        ALOGD("PCM Count path not specified");
+    if (pcmCountPath.empty()) {
+        ALOGV("PCM Count path not specified in JSON");
         return;
     }
 
-    if (!ReadFileToString(kPcmCountPath, &file_contents)) {
-        ALOGD("Unable to read PCM Count path %s", kPcmCountPath);
+    if (!ReadFileToString(pcmCountPath.c_str(), &file_contents)) {
+        ALOGD("Unable to read PCM Count path %s", pcmCountPath.c_str());
     } else {
         std::stringstream file_content_stream(file_contents);
         int count;
@@ -1639,8 +1664,8 @@ void SysfsCollector::logPcmUsageStats(const std::shared_ptr<IStats> &stats_clien
         return;
     }
 
-    if (!ReadFileToString(kPcmLatencyPath, &file_contents)) {
-        ALOGD("Unable to read PCM Latency path %s", kPcmLatencyPath);
+    if (!ReadFileToString(pcmLatencyPath.c_str(), &file_contents)) {
+        ALOGD("Unable to read PCM Latency path %s", pcmLatencyPath.c_str());
     } else {
         std::stringstream file_content_stream(file_contents);
         int duration;
@@ -1692,19 +1717,21 @@ void SysfsCollector::logOffloadEffectsStats(const std::shared_ptr<IStats> &stats
     std::string file_contents;
     std::vector<int> uuids;
     std::vector<int> durations;
+    std::string offloadEffectsIdPath = getCStringOrDefault(configData, "OffloadEffectsIdPath");
+    std::string offloadEffectsDurationPath = getCStringOrDefault(configData, "OffloadEffectsDurationPath");
 
-    if (kOffloadEffectsIdPath == nullptr) {
-        ALOGD("Offload Effects ID Path is not specified");
+    if (offloadEffectsIdPath.empty()) {
+        ALOGV("Offload Effects ID Path is not specified in JSON");
         return;
     }
 
-    if (kOffloadEffectsDurationPath == nullptr) {
-        ALOGD("Offload Effects Duration Path is not specified");
+    if (offloadEffectsDurationPath.empty()) {
+        ALOGV("Offload Effects Duration Path is not specified in JSON");
         return;
     }
 
-    if (!ReadFileToString(kOffloadEffectsIdPath, &file_contents)) {
-        ALOGD("Unable to read Offload Effect ID path %s", kOffloadEffectsIdPath);
+    if (!ReadFileToString(offloadEffectsIdPath.c_str(), &file_contents)) {
+        ALOGD("Unable to read Offload Effect ID path %s", offloadEffectsIdPath.c_str());
     } else {
         std::stringstream file_content_stream(file_contents);
         int uuid;
@@ -1713,8 +1740,8 @@ void SysfsCollector::logOffloadEffectsStats(const std::shared_ptr<IStats> &stats
         }
     }
 
-    if (!ReadFileToString(kOffloadEffectsDurationPath, &file_contents)) {
-        ALOGD("Unable to read Offload Effect duration path %s", kOffloadEffectsDurationPath);
+    if (!ReadFileToString(offloadEffectsDurationPath.c_str(), &file_contents)) {
+        ALOGD("Unable to read Offload Effect duration path %s", offloadEffectsDurationPath.c_str());
     } else {
         std::stringstream file_content_stream(file_contents);
         int duration;
@@ -1772,16 +1799,17 @@ void SysfsCollector::logOffloadEffectsStats(const std::shared_ptr<IStats> &stats
 void SysfsCollector::logBluetoothAudioUsage(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents;
     std::vector<int> duration_per_codec;
+    std::string bluetoothAudioUsagePath = getCStringOrDefault(configData, "BluetoothAudioUsagePath");
 
     constexpr int num_codec = 5;
 
-    if (kBluetoothAudioUsagePath == nullptr) {
-        ALOGD("Bluetooth Audio stats path not specified");
+    if (bluetoothAudioUsagePath.empty()) {
+        ALOGV("Bluetooth Audio stats path not specified in JSON");
         return;
     }
 
-    if (!ReadFileToString(kBluetoothAudioUsagePath, &file_contents)) {
-        ALOGD("Unable to read Bluetooth Audio stats path %s", kBluetoothAudioUsagePath);
+    if (!ReadFileToString(bluetoothAudioUsagePath.c_str(), &file_contents)) {
+        ALOGD("Unable to read Bluetooth Audio stats path %s", bluetoothAudioUsagePath.c_str());
     } else {
         std::stringstream file_content_stream(file_contents);
         int duration;
@@ -1831,16 +1859,18 @@ void SysfsCollector::logBluetoothAudioUsage(const std::shared_ptr<IStats> &stats
  */
 void SysfsCollector::logVendorResumeLatencyStats(const std::shared_ptr<IStats> &stats_client) {
     std::string uart_enabled = android::base::GetProperty("init.svc.console", "");
+    std::string resumeLatencyMetricsPath = getCStringOrDefault(configData, "ResumeLatencyMetricsPath");
+
     if (uart_enabled == "running") {
         return;
     }
     std::string file_contents;
-    if (!kResumeLatencyMetricsPath) {
-        ALOGE("ResumeLatencyMetrics path not specified");
+    if (resumeLatencyMetricsPath.empty()) {
+        ALOGV("ResumeLatencyMetrics path not specified in JSON");
         return;
     }
-    if (!ReadFileToString(kResumeLatencyMetricsPath, &file_contents)) {
-        ALOGE("Unable to ResumeLatencyMetric %s - %s", kResumeLatencyMetricsPath, strerror(errno));
+    if (!ReadFileToString(resumeLatencyMetricsPath.c_str(), &file_contents)) {
+        ALOGE("Unable to ResumeLatencyMetric %s - %s", resumeLatencyMetricsPath.c_str(), strerror(errno));
         return;
     }
 
@@ -1965,28 +1995,31 @@ void process_irqatom_values(std::string file_contents, int *offset,
  */
 void SysfsCollector::logVendorLongIRQStatsReported(const std::shared_ptr<IStats> &stats_client) {
     std::string uart_enabled = android::base::GetProperty("init.svc.console", "");
+    std::string longIRQMetricsPath = getCStringOrDefault(configData, "LongIRQMetricsPath");
+    std::string stormIRQMetricsPath = getCStringOrDefault(configData, "StormIRQMetricsPath");
+    std::string IRQStatsResetPath = getCStringOrDefault(configData, "IRQStatsResetPath");
     if (uart_enabled == "running") {
         return;
     }
     std::string irq_file_contents, storm_file_contents;
-    if (kLongIRQMetricsPath == nullptr || strlen(kLongIRQMetricsPath) == 0) {
-        ALOGV("LongIRQ path not specified");
+    if (longIRQMetricsPath.empty()) {
+        ALOGV("LongIRQ path not specified in JSON");
         return;
     }
-    if (!ReadFileToString(kLongIRQMetricsPath, &irq_file_contents)) {
-        ALOGE("Unable to read LongIRQ %s - %s", kLongIRQMetricsPath, strerror(errno));
+    if (!ReadFileToString(longIRQMetricsPath.c_str(), &irq_file_contents)) {
+        ALOGE("Unable to read LongIRQ %s - %s", longIRQMetricsPath.c_str(), strerror(errno));
         return;
     }
-    if (kStormIRQMetricsPath == nullptr || strlen(kStormIRQMetricsPath) == 0) {
-        ALOGV("StormIRQ path not specified");
+    if (stormIRQMetricsPath.empty()) {
+        ALOGV("StormIRQ path not specified in JSON");
         return;
     }
-    if (!ReadFileToString(kStormIRQMetricsPath, &storm_file_contents)) {
-        ALOGE("Unable to read StormIRQ %s - %s", kStormIRQMetricsPath, strerror(errno));
+    if (!ReadFileToString(stormIRQMetricsPath.c_str(), &storm_file_contents)) {
+        ALOGE("Unable to read StormIRQ %s - %s", stormIRQMetricsPath.c_str(), strerror(errno));
         return;
     }
-    if (kIRQStatsResetPath == nullptr || strlen(kIRQStatsResetPath) == 0) {
-        ALOGV("IRQStatsReset path not specified");
+    if (IRQStatsResetPath.empty()) {
+        ALOGV("IRQStatsReset path not specified in JSON");
         return;
     }
     int offset = 0;
@@ -2037,7 +2070,7 @@ void SysfsCollector::logVendorLongIRQStatsReported(const std::shared_ptr<IStats>
         ALOGE("Unable to report kVendorLongIRQStatsReported to Stats service");
 
     // Reset irq stats
-    if (!WriteStringToFile(std::to_string(1), kIRQStatsResetPath)) {
+    if (!WriteStringToFile(std::to_string(1), IRQStatsResetPath)) {
         ALOGE("Failed to write to stats_reset");
         return;
     }
@@ -2081,6 +2114,8 @@ void SysfsCollector::logPcieLinkStats(const std::shared_ptr<IStats> &stats_clien
         int modem_msg_field_number;
         int wifi_msg_field_number;
     };
+    std::string modemPcieLinkStatsPath = getCStringOrDefault(configData, "ModemPcieLinkStatsPath");
+    std::string wifiPcieLinkStatsPath = getCStringOrDefault(configData, "WifiPcieLinkStatsPath");
 
     int i;
     bool reportPcieLinkStats = false;
@@ -2113,12 +2148,12 @@ void SysfsCollector::logPcieLinkStats(const std::shared_ptr<IStats> &stats_clien
     };
 
 
-    if (kModemPcieLinkStatsPath == nullptr) {
-        ALOGD("Modem PCIe stats path not specified");
+    if (modemPcieLinkStatsPath.empty()) {
+        ALOGV("Modem PCIe stats path not specified in JSON");
     } else {
         for (i=0; i < ARRAY_SIZE(datamap); i++) {
             std::string modempath =
-                    std::string(kModemPcieLinkStatsPath) + "/" + datamap[i].sysfs_path;
+                    std::string(modemPcieLinkStatsPath) + "/" + datamap[i].sysfs_path;
 
             if (ReadFileToInt(modempath, &(datamap[i].modem_val))) {
                 reportPcieLinkStats = true;
@@ -2136,12 +2171,12 @@ void SysfsCollector::logPcieLinkStats(const std::shared_ptr<IStats> &stats_clien
         }
     }
 
-    if (kWifiPcieLinkStatsPath == nullptr) {
-        ALOGD("Wifi PCIe stats path not specified");
+    if (wifiPcieLinkStatsPath.empty()) {
+        ALOGV("Wifi PCIe stats path not specified in JSON");
     } else {
         for (i=0; i < ARRAY_SIZE(datamap); i++) {
             std::string wifipath =
-                    std::string(kWifiPcieLinkStatsPath) + "/" + datamap[i].sysfs_path;
+                    std::string(wifiPcieLinkStatsPath) + "/" + datamap[i].sysfs_path;
 
             if (ReadFileToInt(wifipath, &(datamap[i].wifi_val))) {
                 reportPcieLinkStats = true;
@@ -2193,11 +2228,13 @@ void SysfsCollector::logPcieLinkStats(const std::shared_ptr<IStats> &stats_clien
  * Read the contents of kPowerMitigationDurationPath and report them.
  */
 void SysfsCollector::logMitigationDurationCounts(const std::shared_ptr<IStats> &stats_client) {
-    if (kPowerMitigationDurationPath == nullptr || strlen(kPowerMitigationDurationPath) == 0) {
-        ALOGE("Mitigation Duration path is invalid!");
+    std::string powerMitigationDurationPath = getCStringOrDefault(configData, "PowerMitigationDurationPath");
+
+    if (powerMitigationDurationPath.empty()) {
+        ALOGV("Mitigation Duration path not specified in JSON");
         return;
     }
-    mitigation_duration_reporter_.logMitigationDuration(stats_client, kPowerMitigationDurationPath);
+    mitigation_duration_reporter_.logMitigationDuration(stats_client, powerMitigationDurationPath);
 }
 
 void SysfsCollector::logPerDay() {
@@ -2265,12 +2302,15 @@ void SysfsCollector::logBrownout() {
         ALOGE("Unable to get AIDL Stats service");
         return;
     }
-    if (kBrownoutCsvPath != nullptr && strlen(kBrownoutCsvPath) > 0)
-        brownout_detected_reporter_.logBrownoutCsv(stats_client, kBrownoutCsvPath,
-                                                   kBrownoutReasonProp);
-    else if (kBrownoutLogPath != nullptr && strlen(kBrownoutLogPath) > 0)
-        brownout_detected_reporter_.logBrownout(stats_client, kBrownoutLogPath,
-                                                kBrownoutReasonProp);
+    std::string brownoutCsvPath = getCStringOrDefault(configData, "BrownoutCsvPath");
+    std::string brownoutLogPath = getCStringOrDefault(configData, "BrownoutLogPath");
+    std::string brownoutReasonProp = getCStringOrDefault(configData, "BrownoutReasonProp");
+    if (brownoutCsvPath.empty())
+        brownout_detected_reporter_.logBrownoutCsv(stats_client, brownoutCsvPath.c_str(),
+                                                   brownoutReasonProp);
+    else if (brownoutLogPath.empty())
+        brownout_detected_reporter_.logBrownout(stats_client, brownoutLogPath.c_str(),
+                                                brownoutReasonProp);
 }
 
 void SysfsCollector::logWater() {
@@ -2279,11 +2319,9 @@ void SysfsCollector::logWater() {
         ALOGE("Unable to get AIDL Stats service");
         return;
     }
-    if (kWaterEventPath == nullptr || strlen(kWaterEventPath) == 0)
-        return;
-    PixelAtoms::WaterEventReported::EventPoint event_point =
-            PixelAtoms::WaterEventReported::EventPoint::WaterEventReported_EventPoint_BOOT;
-    water_event_reporter_.logEvent(stats_client, event_point, kWaterEventPath);
+    std::vector<std::string> waterEventPaths =
+        readStringVectorFromJson(configData["WaterEventPaths"]);
+    water_event_reporter_.logBootEvent(stats_client, waterEventPaths);
 }
 
 void SysfsCollector::logOnce() {
@@ -2297,13 +2335,14 @@ void SysfsCollector::logPerHour() {
         ALOGE("Unable to get AIDL Stats service");
         return;
     }
+    std::string powerMitigationStatsPath = getCStringOrDefault(configData, "PowerMitigationStatsPath");
     mm_metrics_reporter_.logPixelMmMetricsPerHour(stats_client);
     mm_metrics_reporter_.logGcmaPerHour(stats_client);
     mm_metrics_reporter_.logMmProcessUsageByOomGroupSnapshot(stats_client);
     logZramStats(stats_client);
-    if (kPowerMitigationStatsPath != nullptr && strlen(kPowerMitigationStatsPath) > 0)
+    if (powerMitigationStatsPath.empty())
         mitigation_stats_reporter_.logMitigationStatsPerHour(stats_client,
-                                                             kPowerMitigationStatsPath);
+                                                             powerMitigationStatsPath.c_str());
 }
 
 /**
diff --git a/pixelstats/UeventListener.cpp b/pixelstats/UeventListener.cpp
index ddbfa7ed..11e267f3 100644
--- a/pixelstats/UeventListener.cpp
+++ b/pixelstats/UeventListener.cpp
@@ -47,12 +47,15 @@
 #include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
 #include <linux/thermal.h>
 #include <log/log.h>
+#include <pixelstats/JsonConfigUtils.h>
 #include <pixelstats/StatsHelper.h>
 #include <pixelstats/UeventListener.h>
 #include <sys/stat.h>
 #include <sys/types.h>
 #include <unistd.h>
 #include <utils/StrongPointer.h>
+#include <fstream>
+#include <iostream>
 
 #include <string>
 #include <thread>
@@ -117,7 +120,14 @@ void UeventListener::ReportMicStatusUevents(const std::shared_ptr<IStats> &stats
                                             const char *devpath, const char *mic_status) {
     if (!devpath || !mic_status)
         return;
-    if (!strcmp(devpath, ("DEVPATH=" + kAudioUevent).c_str())) {
+
+    std::string audioUevent = getCStringOrDefault(configData, "AudioUevent");
+
+    if (audioUevent.empty()) {
+        ALOGV("audioUevent not specified in JSON");
+    }
+
+    if (!strcmp(devpath, ("DEVPATH=" + audioUevent).c_str())) {
         std::vector<std::string> value = android::base::Split(mic_status, "=");
         bool isbroken;
 
@@ -153,6 +163,13 @@ void UeventListener::ReportMicStatusUevents(const std::shared_ptr<IStats> &stats
 
 void UeventListener::ReportUsbPortOverheatEvent(const std::shared_ptr<IStats> &stats_client,
                                                 const char *driver) {
+
+    std::string usbPortOverheatPath = getCStringOrDefault(configData, "UsbPortOverheatPath");
+
+    if (usbPortOverheatPath.empty()) {
+        ALOGV("usbPortOverheatPath not specified in JSON");
+        usbPortOverheatPath = overheat_path_default;
+    }
     if (!driver || strcmp(driver, "DRIVER=google,overheat_mitigation")) {
         return;
     }
@@ -164,11 +181,11 @@ void UeventListener::ReportUsbPortOverheatEvent(const std::shared_ptr<IStats> &s
     int32_t time_to_inactive_secs = 0;
 
     // TODO(achant b/182941868): test return value and skip reporting in case of an error
-    ReadFileToInt((kUsbPortOverheatPath + "/plug_temp"), &plug_temperature_deci_c);
-    ReadFileToInt((kUsbPortOverheatPath + "/max_temp"), &max_temperature_deci_c);
-    ReadFileToInt((kUsbPortOverheatPath + "/trip_time"), &time_to_overheat_secs);
-    ReadFileToInt((kUsbPortOverheatPath + "/hysteresis_time"), &time_to_hysteresis_secs);
-    ReadFileToInt((kUsbPortOverheatPath + "/cleared_time"), &time_to_inactive_secs);
+    ReadFileToInt((usbPortOverheatPath + "/plug_temp"), &plug_temperature_deci_c);
+    ReadFileToInt((usbPortOverheatPath + "/max_temp"), &max_temperature_deci_c);
+    ReadFileToInt((usbPortOverheatPath + "/trip_time"), &time_to_overheat_secs);
+    ReadFileToInt((usbPortOverheatPath + "/hysteresis_time"), &time_to_hysteresis_secs);
+    ReadFileToInt((usbPortOverheatPath + "/cleared_time"), &time_to_inactive_secs);
 
     VendorUsbPortOverheat overheat_info;
     overheat_info.set_plug_temperature_deci_c(plug_temperature_deci_c);
@@ -182,23 +199,60 @@ void UeventListener::ReportUsbPortOverheatEvent(const std::shared_ptr<IStats> &s
 
 void UeventListener::ReportChargeMetricsEvent(const std::shared_ptr<IStats> &stats_client,
                                               const char *driver) {
+
+    std::string chargeMetricsPath = getCStringOrDefault(configData, "ChargeMetricsPath");
+
+    if (chargeMetricsPath.empty()) {
+        ALOGV("chargeMetricsPath not specified in JSON");
+        chargeMetricsPath = charge_metrics_path_default;
+    }
     if (!driver || strcmp(driver, "DRIVER=google,battery")) {
         return;
     }
 
-    charge_stats_reporter_.checkAndReport(stats_client, kChargeMetricsPath);
+    charge_stats_reporter_.checkAndReport(stats_client, chargeMetricsPath);
 }
 
 void UeventListener::ReportFGMetricsEvent(const std::shared_ptr<IStats> &stats_client,
-                                              const char *driver) {
-    if (!driver || (strcmp(driver, "DRIVER=max77779-fg") && strcmp(driver, "DRIVER=maxfg") &&
-        strcmp(driver, "DRIVER=max1720x")))
+                                          const char *driver) {
+    if (!driver || strcmp(driver, "DRIVER=max77779-fg"))
         return;
 
-    battery_fg_reporter_.checkAndReportFwUpdate(stats_client, kFwUpdatePath);
-    battery_fg_reporter_.checkAndReportFGAbnormality(stats_client, kFGAbnlPath);
+    std::vector<std::string> FGAbnlPath = {""};
+    if (configData.isMember("FGAbnlPath")) {
+        FGAbnlPath = readStringVectorFromJson(configData["FGAbnlPath"]);
+    } else {
+        ALOGV("FGAbnlPath not specified in JSON");
+    }
+    battery_fg_reporter_.checkAndReportFGAbnormality(stats_client, FGAbnlPath);
 }
 
+void UeventListener::ReportFwUpdateEvent(const std::shared_ptr<IStats> &stats_client,
+                                         const char *driver) {
+    if (!driver || strcmp(driver, "DRIVER=max77779-fg"))
+        return;
+
+    std::vector<std::string> FwUpdatePath = {""};
+    if (configData.isMember("FwUpdatePath")) {
+        FwUpdatePath = readStringVectorFromJson(configData["FwUpdatePath"]);
+    } else {
+        ALOGV("FwUpdatePath not specified in JSON");
+    }
+    battery_fw_update_reporter_.checkAndReportFwUpdate(stats_client, FwUpdatePath, EvtFwUpdate);
+}
+void UeventListener::ReportWlcFwUpdateEvent(const std::shared_ptr<IStats> &stats_client,
+                                            const char *driver) {
+    if (!driver || strcmp(driver, "DRIVER=google_wlc"))
+        return;
+
+    std::vector<std::string> FwUpdatePath = {""};
+    if (configData.isMember("FwUpdatePath")) {
+        FwUpdatePath = readStringVectorFromJson(configData["FwUpdatePath"]);
+    } else {
+        ALOGV("FwUpdatePath not specified in JSON");
+    }
+    battery_fw_update_reporter_.checkAndReportFwUpdate(stats_client, FwUpdatePath, EvtWlcFwUpdate);
+}
 /**
  * Report raw battery capacity, system battery capacity and associated
  * battery capacity curves. This data is collected to verify the filter
@@ -222,38 +276,54 @@ void UeventListener::ReportBatteryCapacityFGEvent(const std::shared_ptr<IStats>
         return;
     }
 
+    std::string batterySSOCPath = getCStringOrDefault(configData, "BatterySSOCPath");
+
     // Indicates an implicit disable of the battery capacity reporting
-    if (kBatterySSOCPath.empty()) {
-        return;
+    if (batterySSOCPath.empty()) {
+        ALOGV("batterySSOCPath not specified in JSON");
+        batterySSOCPath = ssoc_details_path;
     }
 
-    battery_capacity_reporter_.checkAndReport(stats_client, kBatterySSOCPath);
+    battery_capacity_reporter_.checkAndReport(stats_client, batterySSOCPath);
 }
 
 void UeventListener::ReportTypeCPartnerId(const std::shared_ptr<IStats> &stats_client) {
     std::string file_contents_vid, file_contents_pid;
     uint32_t pid, vid;
 
-    if (!ReadFileToString(kTypeCPartnerVidPath.c_str(), &file_contents_vid)) {
-        ALOGE("Unable to read %s - %s", kTypeCPartnerVidPath.c_str(), strerror(errno));
+    std::string typeCPartnerVidPath = getCStringOrDefault(configData, "TypeCPartnerVidPath");
+    std::string typeCPartnerPidPath = getCStringOrDefault(configData, "TypeCPartnerPidPath");
+
+
+    if (typeCPartnerVidPath.empty()) {
+        ALOGV("typeCPartnerVidPath not specified in JSON");
+        typeCPartnerPidPath = typec_partner_vid_path_default;
+    }
+    if (typeCPartnerPidPath.empty()) {
+        ALOGV("typeCPartnerPidPath not specified in JSON");
+        typeCPartnerPidPath = typec_partner_pid_path_default;
+    }
+
+    if (!ReadFileToString(typeCPartnerVidPath.c_str(), &file_contents_vid)) {
+        ALOGE("Unable to read %s - %s", typeCPartnerVidPath.c_str(), strerror(errno));
         return;
     }
 
     if (sscanf(file_contents_vid.c_str(), "%x", &vid) != 1) {
         ALOGE("Unable to parse vid %s from file %s to int.", file_contents_vid.c_str(),
-              kTypeCPartnerVidPath.c_str());
+              typeCPartnerVidPath.c_str());
         return;
     }
 
-    if (!ReadFileToString(kTypeCPartnerPidPath.c_str(), &file_contents_pid)) {
-        ALOGE("Unable to read %s - %s", kTypeCPartnerPidPath.c_str(), strerror(errno));
+    if (!ReadFileToString(typeCPartnerPidPath.c_str(), &file_contents_pid)) {
+        ALOGE("Unable to read %s - %s", typeCPartnerPidPath.c_str(), strerror(errno));
         return;
     }
 
     if (sscanf(file_contents_pid.substr(PID_OFFSET, PID_LENGTH).c_str(), "%x", &pid) != 1) {
         ALOGE("Unable to parse pid %s from file %s to int.",
               file_contents_pid.substr(PID_OFFSET, PID_LENGTH).c_str(),
-              kTypeCPartnerPidPath.c_str());
+              typeCPartnerPidPath.c_str());
         return;
     }
 
@@ -289,8 +359,14 @@ void UeventListener::ReportTypeCPartnerId(const std::shared_ptr<IStats> &stats_c
 
 void UeventListener::ReportGpuEvent(const std::shared_ptr<IStats> &stats_client, const char *driver,
                                     const char *gpu_event_type, const char *gpu_event_info) {
-    if (!stats_client || !driver || strncmp(driver, "DRIVER=mali", strlen("DRIVER=mali")) ||
-        !gpu_event_type || !gpu_event_info)
+
+    if (!stats_client || !driver || !gpu_event_type || !gpu_event_info)
+        return;
+
+    bool isPVREvent = (strncmp(driver, "DRIVER=pvrsrvkm", strlen("DRIVER=pvrsrvkm")) == 0);
+    bool isMaliEvent = (strncmp(driver, "DRIVER=mali", strlen("DRIVER=mali")) == 0);
+
+    if (!isMaliEvent && !isPVREvent)
         return;
 
     std::vector<std::string> type = android::base::Split(gpu_event_type, "=");
@@ -302,14 +378,32 @@ void UeventListener::ReportGpuEvent(const std::shared_ptr<IStats> &stats_client,
     if (type[0] != "GPU_UEVENT_TYPE" || info[0] != "GPU_UEVENT_INFO")
         return;
 
-    auto event_type = kGpuEventTypeStrToEnum.find(type[1]);
-    auto event_info = kGpuEventInfoStrToEnum.find(info[1]);
-    if (event_type == kGpuEventTypeStrToEnum.end() || event_info == kGpuEventInfoStrToEnum.end())
-        return;
+    PixelAtoms::GpuEvent::GpuEventType event_type;
+    PixelAtoms::GpuEvent::GpuEventInfo event_info;
+
+    if (isPVREvent) {
+        auto type_iter = kPVRGpuEventTypeStrToEnum.find(type[1]);
+        auto info_iter = kPVRGpuEventInfoStrToEnum.find(info[1]);
+        if (type_iter == kPVRGpuEventTypeStrToEnum.end() || info_iter == kPVRGpuEventInfoStrToEnum.end())
+            return;
+
+        event_type = type_iter->second;
+        event_info = info_iter->second;
+    }
+
+    if (isMaliEvent) {
+        auto type_iter = kMaliGpuEventTypeStrToEnum.find(type[1]);
+        auto info_iter = kMaliGpuEventInfoStrToEnum.find(info[1]);
+        if (type_iter == kMaliGpuEventTypeStrToEnum.end() || info_iter == kMaliGpuEventInfoStrToEnum.end())
+            return;
+
+        event_type = type_iter->second;
+        event_info = info_iter->second;
+    }
 
     VendorAtom event = {.reverseDomainName = "",
                         .atomId = PixelAtoms::Atom::kGpuEvent,
-                        .values = {event_type->second, event_info->second}};
+                        .values = {event_type, event_info}};
     const ndk::ScopedAStatus ret = stats_client->reportVendorAtom(event);
     if (!ret.isOk())
         ALOGE("Unable to report GPU event.");
@@ -444,6 +538,11 @@ bool UeventListener::ProcessUevent() {
     driver = product = subsystem = NULL;
     mic_break_status = mic_degrade_status = devpath = NULL;
 
+    std::string typeCPartnerUevent = getCStringOrDefault(configData, "TypeCPartnerUevent");
+
+    if (typeCPartnerUevent.empty()) {
+        ALOGV("typeCPartnerUevent not specified in JSON");
+    }
     /**
      * msg is a sequence of null-terminated strings.
      * Iterate through and record positions of string/value pairs of interest.
@@ -468,7 +567,7 @@ bool UeventListener::ProcessUevent() {
             devpath = cp;
         } else if (!strncmp(cp, "SUBSYSTEM=", strlen("SUBSYSTEM="))) {
             subsystem = cp;
-        } else if (!strncmp(cp, kTypeCPartnerUevent.c_str(), kTypeCPartnerUevent.size())) {
+        } else if (!strncmp(cp, typeCPartnerUevent.c_str(), typeCPartnerUevent.size())) {
             collect_partner_id = true;
         } else if (!strncmp(cp, "GPU_UEVENT_TYPE=", strlen("GPU_UEVENT_TYPE="))) {
             gpu_event_type = cp;
@@ -502,6 +601,8 @@ bool UeventListener::ProcessUevent() {
                                    thermal_abnormal_event_info);
         ReportFGMetricsEvent(stats_client, driver);
         ReportWaterEvent(stats_client, driver, devpath);
+        ReportFwUpdateEvent(stats_client, driver);
+        ReportWlcFwUpdateEvent(stats_client, driver);
     }
 
     if (log_fd_ > 0) {
@@ -510,46 +611,8 @@ bool UeventListener::ProcessUevent() {
     return true;
 }
 
-UeventListener::UeventListener(const std::string audio_uevent, const std::string ssoc_details_path,
-                               const std::string overheat_path,
-                               const std::string charge_metrics_path,
-                               const std::string typec_partner_vid_path,
-                               const std::string typec_partner_pid_path,
-                               const std::string fw_update_path,
-                               const std::vector<std::string> fg_abnl_path)
-    : kAudioUevent(audio_uevent),
-      kBatterySSOCPath(ssoc_details_path),
-      kUsbPortOverheatPath(overheat_path),
-      kChargeMetricsPath(charge_metrics_path),
-      kTypeCPartnerUevent(typec_partner_uevent_default),
-      kTypeCPartnerVidPath(typec_partner_vid_path),
-      kTypeCPartnerPidPath(typec_partner_pid_path),
-      kFwUpdatePath(fw_update_path),
-      kFGAbnlPath(fg_abnl_path),
-      uevent_fd_(-1),
-      log_fd_(-1) {}
-
-UeventListener::UeventListener(const struct UeventPaths &uevents_paths)
-    : kAudioUevent((uevents_paths.AudioUevent == nullptr) ? "" : uevents_paths.AudioUevent),
-      kBatterySSOCPath((uevents_paths.SsocDetailsPath == nullptr) ? ssoc_details_path
-                                                                  : uevents_paths.SsocDetailsPath),
-      kUsbPortOverheatPath((uevents_paths.OverheatPath == nullptr) ? overheat_path_default
-                                                                   : uevents_paths.OverheatPath),
-      kChargeMetricsPath((uevents_paths.ChargeMetricsPath == nullptr)
-                                 ? charge_metrics_path_default
-                                 : uevents_paths.ChargeMetricsPath),
-      kTypeCPartnerUevent((uevents_paths.TypeCPartnerUevent == nullptr)
-                                  ? typec_partner_uevent_default
-                                  : uevents_paths.TypeCPartnerUevent),
-      kTypeCPartnerVidPath((uevents_paths.TypeCPartnerVidPath == nullptr)
-                                   ? typec_partner_vid_path_default
-                                   : uevents_paths.TypeCPartnerVidPath),
-      kTypeCPartnerPidPath((uevents_paths.TypeCPartnerPidPath == nullptr)
-                                   ? typec_partner_pid_path_default
-                                   : uevents_paths.TypeCPartnerPidPath),
-      kFwUpdatePath((uevents_paths.FwUpdatePath == nullptr)
-                                   ? "" : uevents_paths.FwUpdatePath),
-      kFGAbnlPath(uevents_paths.FGAbnlPath),
+UeventListener::UeventListener(const Json::Value& configData)
+    : configData(configData),
       uevent_fd_(-1),
       log_fd_(-1) {}
 
diff --git a/pixelstats/WaterEventReporter.cpp b/pixelstats/WaterEventReporter.cpp
index d6fab923..f6c42ba3 100644
--- a/pixelstats/WaterEventReporter.cpp
+++ b/pixelstats/WaterEventReporter.cpp
@@ -78,23 +78,24 @@ void WaterEventReporter::logEvent(const std::shared_ptr<IStats> &stats_client,
         return;
     }
 
-    std::vector<VendorAtomValue> values(kNumOfWaterEventAtoms, 0);
+    std::vector<VendorAtomValue> values(kNumOfWaterEventAtomFields, 0);
 
     // Is this during boot or as a result of an event
     values[PixelAtoms::WaterEventReported::kCollectionEventFieldNumber - kVendorAtomOffset] = event_point;
 
     // Most important, what is the state of the fuse
-    std::string fuse_state_str;
-    if (ReadFileToString(sysfs_path + "/fuse/status", &fuse_state_str)) {
-        if (!fuse_state_str.compare(0, 4, "open")) {
-            values[PixelAtoms::WaterEventReported::kFuseStateFieldNumber - kVendorAtomOffset] =
-                    PixelAtoms::WaterEventReported::FuseState::WaterEventReported_FuseState_BLOWN;
-        } else if (!fuse_state_str.compare(0, 5, "short")) {
-            values[PixelAtoms::WaterEventReported::kFuseStateFieldNumber - kVendorAtomOffset] =
-                    PixelAtoms::WaterEventReported::FuseState::WaterEventReported_FuseState_INTACT;
-        } else {
-             values[PixelAtoms::WaterEventReported::kFuseStateFieldNumber - kVendorAtomOffset] =
-                     PixelAtoms::WaterEventReported::FuseState::WaterEventReported_FuseState_FUSE_STATE_UNKNOWN;
+    int fuse_state;
+    if (readFileToInt(sysfs_path + "/fuse/status", &fuse_state)) {
+        auto &fuse_state_field = values[PixelAtoms::WaterEventReported::kFuseStateFieldNumber - kVendorAtomOffset];
+        switch (fuse_state) {
+            case 1:
+                fuse_state_field = PixelAtoms::WaterEventReported::FuseState::WaterEventReported_FuseState_BLOWN;
+                break;
+            case 0:
+                fuse_state_field = PixelAtoms::WaterEventReported::FuseState::WaterEventReported_FuseState_INTACT;
+                break;
+            default:
+                fuse_state_field = PixelAtoms::WaterEventReported::FuseState::WaterEventReported_FuseState_FUSE_STATE_UNKNOWN;
         }
     }
 
@@ -112,51 +113,42 @@ void WaterEventReporter::logEvent(const std::shared_ptr<IStats> &stats_client,
                 fault_enable ? PixelAtoms::WaterEventReported::CircuitState::WaterEventReported_CircuitState_CIRCUIT_ENABLED :
                               PixelAtoms::WaterEventReported::CircuitState::WaterEventReported_CircuitState_CIRCUIT_DISABLED;
 
-    std::tuple<std::string, int, int> sensors[] = {
-        {"reference", PixelAtoms::WaterEventReported::kReferenceStateFieldNumber, PixelAtoms::WaterEventReported::kReferenceThresholdFieldNumber},
-        {"sensor0", PixelAtoms::WaterEventReported::kSensor0StateFieldNumber, PixelAtoms::WaterEventReported::kSensor0ThresholdFieldNumber},
-        {"sensor1", PixelAtoms::WaterEventReported::kSensor1StateFieldNumber, PixelAtoms::WaterEventReported::kSensor1ThresholdFieldNumber},
-        {"sensor2", PixelAtoms::WaterEventReported::kSensor1StateFieldNumber, PixelAtoms::WaterEventReported::kSensor1ThresholdFieldNumber}
+    const std::tuple<std::string, int> sensors[] = {
+            {"reference", PixelAtoms::WaterEventReported::kReferenceStateFieldNumber},
+            {"sensor0", PixelAtoms::WaterEventReported::kSensor0StateFieldNumber},
+            {"sensor1", PixelAtoms::WaterEventReported::kSensor1StateFieldNumber}
     };
 
     //   Get the sensor states (including reference) from either the boot_value (if this is during
     //   startup), or the latched_value if this is the result of a uevent
-    for (auto e : sensors) {
-        std::string sensor_path = std::get<0>(e);
+    for (const auto& e : sensors) {
+        const std::string &sensor_path = std::get<0>(e);
         int sensor_state_field_number = std::get<1>(e);
-        int threshold_field_number = std::get<2>(e);
 
         std::string sensor_state_path = sysfs_path + "/" + sensor_path;
         sensor_state_path += (event_point == PixelAtoms::WaterEventReported::EventPoint::WaterEventReported_EventPoint_BOOT) ? "/boot_value" : "/latched_value";
 
-        std::string sensor_state_str;
-        if (!ReadFileToString(sensor_state_path, &sensor_state_str)) {
+        int sensor_state;
+        if (!readFileToInt(sensor_state_path, &sensor_state)) {
             continue;
         }
 
-        if (!sensor_state_str.compare(0, 3, "dry")) {
-             values[sensor_state_field_number - kVendorAtomOffset] =
-                     PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_DRY;
-        } else if (sensor_state_str.compare(0, 3, "wet")) {
-             values[sensor_state_field_number- kVendorAtomOffset] =
-                PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_WET;
-        } else if (!sensor_state_str.compare(0, 3, "invl")) {
-            values[sensor_state_field_number - kVendorAtomOffset] =
-                PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_INVALID;
-        } else if (!sensor_state_str.compare(0, 3, "dis")) {
-                values[sensor_state_field_number - kVendorAtomOffset] =
-                        PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_DISABLED;
-        } else {
-                values[sensor_state_field_number - kVendorAtomOffset] =
-                    PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_SENSOR_STATE_UNKNOWN;
-            continue;
-        }
-
-        // report the threshold
-        std::string threshold_path = sysfs_path + "/" + sensor_path + "/threshold";
-        int sensor_threshold;
-        if (readFileToInt(threshold_path, &sensor_threshold)) {
-            values[PixelAtoms::WaterEventReported::kReferenceThresholdFieldNumber - kVendorAtomOffset] = sensor_threshold;
+        auto &sensor_state_field = values[sensor_state_field_number - kVendorAtomOffset];
+        switch (sensor_state) {
+            case 0:
+                sensor_state_field = PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_DRY;
+                break;
+            case 1:
+                sensor_state_field = PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_WET;
+                break;
+            case 2:
+                sensor_state_field = PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_DISABLED;
+                break;
+            case 3:
+                sensor_state_field = PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_INVALID;
+                break;
+            default:
+                sensor_state_field = PixelAtoms::WaterEventReported::SensorState::WaterEventReported_SensorState_SENSOR_STATE_UNKNOWN;
         }
     }
 
@@ -168,10 +160,20 @@ void WaterEventReporter::logEvent(const std::shared_ptr<IStats> &stats_client,
         ALOGE("Unable to report Water event.");
 }
 
+void WaterEventReporter::logBootEvent(const std::shared_ptr<IStats> &stats_client,
+                                      const std::vector<std::string> &sysfs_roots)
+{
+    ALOGD("Reporting at boot");
+    const PixelAtoms::WaterEventReported::EventPoint event_point =
+        PixelAtoms::WaterEventReported::EventPoint::WaterEventReported_EventPoint_BOOT;
+    for (const auto& sysfs_root : sysfs_roots)
+        logEvent(stats_client, event_point, sysfs_root);
+}
+
 void WaterEventReporter::logUevent(const std::shared_ptr<IStats> &stats_client,
                                    const std::string_view uevent_devpath)
 {
-    ALOGI("Reporting Water event");
+    ALOGI("Reporting at uevent");
     std::string dpath(uevent_devpath);
 
     std::vector<std::string> value = android::base::Split(dpath, "=");
diff --git a/pixelstats/WirelessChargeStats.cpp b/pixelstats/WirelessChargeStats.cpp
index 79d62089..5af84cfc 100644
--- a/pixelstats/WirelessChargeStats.cpp
+++ b/pixelstats/WirelessChargeStats.cpp
@@ -43,6 +43,10 @@ int WirelessChargeStats::TranslateSysModeToAtomValue(const int sys_mode) {
             return PixelAtoms::ChargeStats::ADAPTER_TYPE_WPC_EPP;
         case 3:
             return PixelAtoms::ChargeStats::ADAPTER_TYPE_WPC_L7;
+        case 4:
+            return PixelAtoms::ChargeStats::ADAPTER_TYPE_WPC_MPP;
+        case 5:
+            return PixelAtoms::ChargeStats::ADAPTER_TYPE_WPC_MPP25;
         case 0xe0:
             return PixelAtoms::ChargeStats::ADAPTER_TYPE_DL;
         case 0xa0:
diff --git a/pixelstats/include/pixelstats/BatteryEEPROMReporter.h b/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
index 5d127720..d84bf3b6 100644
--- a/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
+++ b/pixelstats/include/pixelstats/BatteryEEPROMReporter.h
@@ -48,70 +48,7 @@ class BatteryEEPROMReporter {
                                   const std::vector<std::string> &paths);
 
   private:
-    // Proto messages are 1-indexed and VendorAtom field numbers start at 2, so
-    // store everything in the values array at the index of the field number
-    // -2.
-    const int kVendorAtomOffset = 2;
-
-    struct BatteryHistory {
-        /* The cycle count number; record of charge/discharge times */
-        uint16_t cycle_cnt;
-        /* The current full capacity of the battery under nominal conditions */
-        uint16_t full_cap;
-        /* The battery equivalent series resistance */
-        uint16_t esr;
-        /* Battery resistance related to temperature change */
-        uint16_t rslow;
-        /* Battery health indicator reflecting the battery age state */
-        uint8_t soh;
-        /* The battery temperature */
-        int8_t batt_temp;
-        /* Battery state of charge (SOC) shutdown point */
-        uint8_t cutoff_soc;
-        /* Raw battery state of charge (SOC), based on battery current (CC = Coulomb Counter) */
-        uint8_t cc_soc;
-        /* Estimated battery state of charge (SOC) from batt_soc with endpoint limiting
-         * (0% and 100%)
-         */
-        uint8_t sys_soc;
-        /* Filtered monotonic SOC, handles situations where the cutoff_soc is increased and
-         * then decreased from the battery physical properties
-         */
-        uint8_t msoc;
-        /* Estimated SOC derived from cc_soc that provides voltage loop feedback correction using
-         * battery voltage, current, and status values
-         */
-        uint8_t batt_soc;
-
-        /* Field used for data padding in the EEPROM data */
-        uint8_t reserve;
-
-        /* The maximum battery temperature ever seen */
-        int8_t max_temp;
-        /* The minimum battery temperature ever seen */
-        int8_t min_temp;
-        /* The maximum battery voltage ever seen */
-        uint16_t max_vbatt;
-        /* The minimum battery voltage ever seen */
-        uint16_t min_vbatt;
-        /* The maximum battery current ever seen */
-        int16_t max_ibatt;
-        /* The minimum battery current ever seen */
-        int16_t min_ibatt;
-        /* Field used to verify the integrity of the EEPROM data */
-        uint16_t checksum;
-        /* Extend data for P21 */
-        /* Temperature compensation information */
-        uint16_t tempco;
-        /* Learned characterization related to the voltage gauge */
-        uint16_t rcomp0;
-        /* For time to monitor the life of cell */
-        uint8_t timer_h;
-         /* The full capacity of the battery learning at the end of every charge cycle */
-        uint16_t full_rep;
-        /* The battery pairing state */
-        int16_t battery_pairing;
-    };
+
     /* The number of elements for relaxation event */
     const int kNumFGLearningFieldsV2 = 16;
     /* with additional unix time field */
@@ -122,7 +59,7 @@ class BatteryEEPROMReporter {
     unsigned int last_hv_check_ = 0;
 
     /* P21+ history format */
-    struct BatteryHistoryRawFormat {
+    struct BatteryEEPROMPipelineRawFormat {
         uint16_t tempco;
         uint16_t rcomp0;
         uint8_t timer_h;
@@ -138,7 +75,7 @@ class BatteryEEPROMReporter {
         unsigned maxdischgcurr:4;
     };
 
-    struct BatteryHistoryInt32 {
+    struct BatteryEEPROMPipeline {
         int32_t cycle_cnt;
         int32_t full_cap;
         int32_t esr;
@@ -162,22 +99,21 @@ class BatteryEEPROMReporter {
         int32_t rcomp0;
         int32_t timer_h;
         int32_t full_rep;
+        int32_t battery_pairing;
     };
 
     int64_t report_time_ = 0;
     int64_t getTimeSecs();
 
-    bool checkLogEvent(struct BatteryHistory hist);
     void reportEvent(const std::shared_ptr<IStats> &stats_client,
-                     const struct BatteryHistory &hist);
-    void reportEventInt32(const std::shared_ptr<IStats> &stats_client,
-                     const struct BatteryHistoryInt32 &hist);
-    void setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset, int content);
-    bool ReadFileToInt(const std::string &path, int16_t *val);
+                     const struct BatteryEEPROMPipeline &hist);
+    bool ReadFileToInt(const std::string &path, int32_t *val);
+    std::string checkPaths(const std::vector<std::string>& paths);
 
     const int kNum77759GMSRFields = 11;
     const int kNum77779GMSRFields = 9;
     const int kNum17201HISTFields = 16;
+    const int kNumEEPROMPipelineFields = sizeof(BatteryEEPROMPipeline) / sizeof(int32_t);
 
     const std::string kBatteryPairingPath = "/sys/class/power_supply/battery/pairing_state";
 };
diff --git a/pixelstats/include/pixelstats/BatteryFGReporter.h b/pixelstats/include/pixelstats/BatteryFGReporter.h
index 9e8a14f6..b6b58983 100644
--- a/pixelstats/include/pixelstats/BatteryFGReporter.h
+++ b/pixelstats/include/pixelstats/BatteryFGReporter.h
@@ -40,70 +40,52 @@ class BatteryFGReporter {
   private:
     const int kVendorAtomOffset = 2;
 
-    enum FGEventType {
-      EvtFWUpdate = 0x4655,
-    };
-
-    struct BatteryFGLearningParam {
-      enum FGEventType type;
-      uint16_t fcnom;
-      uint16_t dpacc;
-      uint16_t dqacc;
-      uint16_t fcrep;
-      uint16_t repsoc;
-      uint16_t msoc;
-      uint16_t vfsoc;
-      uint16_t fstat;
-      uint16_t rcomp0;
-      uint16_t tempco;
-    };
-
-    struct BatteryFGAbnormalData {
-        uint16_t event;
-        uint16_t state;
-        uint16_t cycles;
-        uint16_t vcel;
-        uint16_t avgv;
-        uint16_t curr;
-        uint16_t avgc;
-        uint16_t timerh;
-        uint16_t temp;
-        uint16_t repcap;
-        uint16_t mixcap;
-        uint16_t fcrep;
-        uint16_t fcnom;
-        uint16_t qresd;
-        uint16_t avcap;
-        uint16_t vfremcap;
-        uint16_t repsoc;
-        uint16_t vfsoc;
-        uint16_t msoc;
-        uint16_t vfocv;
-        uint16_t dpacc;
-        uint16_t dqacc;
-        uint16_t qh;
-        uint16_t qh0;
-        uint16_t vfsoc0;
-        uint16_t qrtable20;
-        uint16_t qrtable30;
-        uint16_t status;
-        uint16_t fstat;
-        uint16_t rcomp0;
-        uint16_t tempco;
+    struct BatteryFGPipeline {
+      int32_t event;
+      int32_t state;
+      int32_t duration;
+      int32_t addr01;
+      int32_t data01;
+      int32_t addr02;
+      int32_t data02;
+      int32_t addr03;
+      int32_t data03;
+      int32_t addr04;
+      int32_t data04;
+      int32_t addr05;
+      int32_t data05;
+      int32_t addr06;
+      int32_t data06;
+      int32_t addr07;
+      int32_t data07;
+      int32_t addr08;
+      int32_t data08;
+      int32_t addr09;
+      int32_t data09;
+      int32_t addr10;
+      int32_t data10;
+      int32_t addr11;
+      int32_t data11;
+      int32_t addr12;
+      int32_t data12;
+      int32_t addr13;
+      int32_t data13;
+      int32_t addr14;
+      int32_t data14;
+      int32_t addr15;
+      int32_t data15;
+      int32_t addr16;
+      int32_t data16;
     };
 
     int64_t getTimeSecs();
 
     unsigned int last_ab_check_ = 0;
-    unsigned int ab_trigger_time_[8] = {0};
-    void setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset, int content);
-    void reportAbnormalEvent(const std::shared_ptr<IStats> &stats_client,
-                            struct BatteryFGAbnormalData data);
-    void reportEvent(const std::shared_ptr<IStats> &stats_client,
-                     const struct BatteryFGLearningParam &params);
+    static constexpr unsigned int kNumMaxEvents = 8;
+    unsigned int ab_trigger_time_[kNumMaxEvents] = {0};
+    void reportFGEvent(const std::shared_ptr<IStats> &stats_client, struct BatteryFGPipeline &data);
 
-    const int kNumFwUpdateFields = 3;
-    const int kNumAbnormalEventFields = sizeof(BatteryFGAbnormalData) / sizeof(uint16_t);
+    const int kNumFGPipelineFields = sizeof(BatteryFGPipeline) / sizeof(int32_t);
 };
 
 }  // namespace pixel
diff --git a/pixelstats/include/pixelstats/BatteryFwUpdateReporter.h b/pixelstats/include/pixelstats/BatteryFwUpdateReporter.h
new file mode 100644
index 00000000..da9136ec
--- /dev/null
+++ b/pixelstats/include/pixelstats/BatteryFwUpdateReporter.h
@@ -0,0 +1,73 @@
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
+ #ifndef HARDWARE_GOOGLE_PIXEL_PIXELSTATS_BATTERYFWUPDATEREPORTER_H
+ #define HARDWARE_GOOGLE_PIXEL_PIXELSTATS_BATTERYFWUPDATEREPORTER_H
+
+#include <cstdint>
+#include <string>
+
+#include <aidl/android/frameworks/stats/IStats.h>
+#include <pixelstats/StatsHelper.h>
+
+namespace android {
+namespace hardware {
+namespace google {
+namespace pixel {
+
+using aidl::android::frameworks::stats::IStats;
+using aidl::android::frameworks::stats::VendorAtomValue;
+
+class BatteryFwUpdateReporter {
+  public:
+    BatteryFwUpdateReporter();
+
+    void checkAndReportFwUpdate(const std::shared_ptr<IStats> &stats_client,
+                                const std::vector<std::string> &paths,
+                                const ReportEventType &event_type);
+
+  private:
+
+    struct BatteryFwUpdatePipeline {
+      int32_t msg_type;
+      int32_t msg_category;
+      int32_t major_version_from;
+      int32_t minor_version_from;
+      int32_t major_version_to;
+      int32_t minor_version_to;
+      int32_t update_status;
+      int32_t attempts;
+      int32_t unix_time_sec;
+      int32_t fw_data0;
+      int32_t fw_data1;
+      int32_t fw_data2;
+      int32_t fw_data3;
+    };
+
+    static constexpr unsigned int kNumMaxFwUpdatePaths = 2;
+    unsigned int last_check_[kNumMaxFwUpdatePaths] = {0};
+    void reportEvent(const std::shared_ptr<IStats> &stats_client,
+                     struct BatteryFwUpdatePipeline &data);
+
+    const int kNumFwUpdatePipelineFields = sizeof(BatteryFwUpdatePipeline) / sizeof(int32_t);
+};
+
+}  // namespace pixel
+}  // namespace google
+}  // namespace hardware
+}  // namespace android
+
+ #endif  // HARDWARE_GOOGLE_PIXEL_PIXELSTATS_BATTERYFWUPDATEREPORTER_H
diff --git a/pixelstats/include/pixelstats/JsonConfigUtils.h b/pixelstats/include/pixelstats/JsonConfigUtils.h
new file mode 100644
index 00000000..d3fcf2e9
--- /dev/null
+++ b/pixelstats/include/pixelstats/JsonConfigUtils.h
@@ -0,0 +1,39 @@
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
+#ifndef HARDWARE_GOOGLE_PIXEL_PIXELSTATS_JSON_CONFIG_UTILS_H
+#define HARDWARE_GOOGLE_PIXEL_PIXELSTATS_JSON_CONFIG_UTILS_H
+
+#include <json/reader.h>
+#include <string>
+#include <vector>
+
+namespace android {
+namespace hardware {
+namespace google {
+namespace pixel {
+
+std::vector<std::string> readStringVectorFromJson(const Json::Value &jsonArr);
+std::vector<std::pair<std::string, std::string>> readStringPairVectorFromJson(const Json::Value &jsonArr);
+std::string getCStringOrDefault(const Json::Value configData, const std::string& key);
+int getIntOrDefault(const Json::Value configData, const std::string& key);
+
+}  // namespace pixel
+}  // namespace google
+}  // namespace hardware
+}  // namespace android
+
+#endif // HARDWARE_GOOGLE_PIXEL_PIXELSTATS_JSON_CONFIG_UTILS_H
\ No newline at end of file
diff --git a/pixelstats/include/pixelstats/StatsHelper.h b/pixelstats/include/pixelstats/StatsHelper.h
index db345c14..8d08df7e 100644
--- a/pixelstats/include/pixelstats/StatsHelper.h
+++ b/pixelstats/include/pixelstats/StatsHelper.h
@@ -26,17 +26,21 @@ namespace google {
 namespace pixel {
 
 using aidl::android::frameworks::stats::IStats;
+using aidl::android::frameworks::stats::VendorAtom;
+using aidl::android::frameworks::stats::VendorAtomValue;
 
 bool fileExists(const std::string &path);
 std::shared_ptr<IStats> getStatsService();
 
 enum ReportEventType {
-  EvtFGAbnormalEvent   = 0x4142, /* AB */
-  EvtFGLearningHistory = 0x4C48, /* LH */
-  EvtGMSR              = 0xFFFF, /* GMSR */
-  EvtModelLoading      = 0x4D4C, /* ML */
+  EvtFGAbnormalEvent = 0x4142,   /* AB */
+  EvtFwUpdate = 0x4655,          /* FU */
   EvtHistoryValidation = 0x4856, /* HV */
-  EvtFGRegularMonitor  = 0x524D, /* RM */
+  EvtFGLearningHistory = 0x4C48, /* LH */
+  EvtModelLoading = 0x4D4C,      /* ML */
+  EvtFGRegularMonitor = 0x524D,  /* RM */
+  EvtGMSR = 0xFFFF,              /* GMSR */
+  EvtWlcFwUpdate = 0x574C,       /* WL */
 };
 
 enum ReportEventFormat {
@@ -45,6 +49,8 @@ enum ReportEventFormat {
   FormatOnlyVal,
 };
 
+void reportVendorAtom(const std::shared_ptr<IStats> &stats_client, VendorAtom event);
+
 void reportSpeakerImpedance(const std::shared_ptr<IStats> &stats_client,
                             const PixelAtoms::VendorSpeakerImpedance &speakerImpedance);
 
@@ -68,10 +74,13 @@ void reportSpeakerHealthStat(const std::shared_ptr<IStats> &stats_client,
 
 void reportUsbDataSessionEvent(const std::shared_ptr<IStats> &stats_client,
                                const PixelAtoms::VendorUsbDataSessionEvent &usb_session);
+
 void readLogbuffer(const std::string &buf_path, int num_fields, uint16_t code,
                    enum ReportEventFormat format, unsigned int last_check_time,
                    std::vector<std::vector<uint32_t>> &events);
 
+void setAtomFieldValue(std::vector<VendorAtomValue> *values, int offset, int content);
+
 }  // namespace pixel
 }  // namespace google
 }  // namespace hardware
diff --git a/pixelstats/include/pixelstats/SysfsCollector.h b/pixelstats/include/pixelstats/SysfsCollector.h
index 908dab23..8b712a5b 100644
--- a/pixelstats/include/pixelstats/SysfsCollector.h
+++ b/pixelstats/include/pixelstats/SysfsCollector.h
@@ -19,6 +19,7 @@
 
 #include <aidl/android/frameworks/stats/IStats.h>
 #include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
+#include <json/reader.h>
 
 #include "BatteryEEPROMReporter.h"
 #include "BatteryHealthReporter.h"
@@ -42,72 +43,11 @@ using android::hardware::google::pixel::PixelAtoms::VendorSlowIo;
 
 class SysfsCollector {
   public:
-    struct SysfsPaths {
-        const char *const SlowioReadCntPath;
-        const char *const SlowioWriteCntPath;
-        const char *const SlowioUnmapCntPath;
-        const char *const SlowioSyncCntPath;
-        const char *const CycleCountBinsPath;
-        const char *const ImpedancePath;
-        const char *const CodecPath;
-        const char *const Codec1Path;
-        const char *const SpeechDspPath;
-        const char *const BatteryCapacityCC;
-        const char *const BatteryCapacityVFSOC;
-        const char *const UFSLifetimeA;
-        const char *const UFSLifetimeB;
-        const char *const UFSLifetimeC;
-        const char *const F2fsStatsPath;
-        const char *const UserdataBlockProp;
-        const char *const ZramMmStatPath;
-        const char *const ZramBdStatPath;
-        const char *const EEPROMPath;
-        const char *const MitigationPath;
-        const char *const MitigationDurationPath;
-        const char *const BrownoutCsvPath;
-        const char *const BrownoutLogPath;
-        const char *const BrownoutReasonProp;
-        const char *const SpeakerTemperaturePath;
-        const char *const SpeakerExcursionPath;
-        const char *const SpeakerHeartBeatPath;
-        const std::vector<std::string> UFSErrStatsPath;
-        const int BlockStatsLength;
-        const char *const AmsRatePath;
-        const std::vector<std::string> ThermalStatsPaths;
-        const std::vector<std::string> DisplayStatsPaths;
-        const std::vector<std::string> DisplayPortStatsPaths;
-        const std::vector<std::string> DisplayPortDSCStatsPaths;
-        const std::vector<std::string> DisplayPortMaxResolutionStatsPaths;
-        const std::vector<std::string> HDCPStatsPaths;
-        const char *const CCARatePath;
-        const std::vector<std::pair<std::string, std::string>> TempResidencyAndResetPaths;
-        const char *const LongIRQMetricsPath;
-        const char *const StormIRQMetricsPath;
-        const char *const IRQStatsResetPath;
-        const char *const ResumeLatencyMetricsPath;
-        const char *const ModemPcieLinkStatsPath;
-        const char *const WifiPcieLinkStatsPath;
-        const char *const PDMStatePath;
-        const char *const WavesPath;
-        const char *const AdaptedInfoCountPath;
-        const char *const AdaptedInfoDurationPath;
-        const char *const PcmLatencyPath;
-        const char *const PcmCountPath;
-        const char *const TotalCallCountPath;
-        const char *const OffloadEffectsIdPath;
-        const char *const OffloadEffectsDurationPath;
-        const char *const BluetoothAudioUsagePath;
-        const std::vector<std::string> GMSRPath;
-        const std::vector<std::string> FGModelLoadingPath;
-        const std::vector<std::string> FGLogBufferPath;
-        const char *const SpeakerVersionPath;
-        const char *const WaterEventPath;
-    };
-
-    SysfsCollector(const struct SysfsPaths &paths);
+    SysfsCollector(const Json::Value& configData);
     void collect();
 
   private:
+    const Json::Value configData;
     bool ReadFileToInt(const std::string &path, int *val);
     bool ReadFileToInt(const char *path, int *val);
     void aggregatePer5Min();
@@ -147,7 +87,7 @@ class SysfsCollector {
     void logHDCPStats(const std::shared_ptr<IStats> &stats_client);
     void logVendorAudioPdmStatsReported(const std::shared_ptr<IStats> &stats_client);
 
-    void reportSlowIoFromFile(const std::shared_ptr<IStats> &stats_client, const char *path,
+    void reportSlowIoFromFile(const std::shared_ptr<IStats> &stats_client, const std::string& path,
                               const VendorSlowIo::IoOperation &operation_s);
     void logTempResidencyStats(const std::shared_ptr<IStats> &stats_client);
     void reportZramMmStat(const std::shared_ptr<IStats> &stats_client);
@@ -167,66 +107,6 @@ class SysfsCollector {
     void logDmVerityPartitionReadAmount(const std::shared_ptr<IStats> &stats_client);
     void logBatteryHistoryValidation();
 
-    const char *const kSlowioReadCntPath;
-    const char *const kSlowioWriteCntPath;
-    const char *const kSlowioUnmapCntPath;
-    const char *const kSlowioSyncCntPath;
-    const char *const kCycleCountBinsPath;
-    const char *const kImpedancePath;
-    const char *const kCodecPath;
-    const char *const kCodec1Path;
-    const char *const kSpeechDspPath;
-    const char *const kBatteryCapacityCC;
-    const char *const kBatteryCapacityVFSOC;
-    const char *const kUFSLifetimeA;
-    const char *const kUFSLifetimeB;
-    const char *const kUFSLifetimeC;
-    const char *const kF2fsStatsPath;
-    const char *const kZramMmStatPath;
-    const char *const kZramBdStatPath;
-    const char *const kEEPROMPath;
-    const char *const kBrownoutCsvPath;
-    const char *const kBrownoutLogPath;
-    const char *const kBrownoutReasonProp;
-    const char *const kPowerMitigationStatsPath;
-    const char *const kPowerMitigationDurationPath;
-    const char *const kSpeakerTemperaturePath;
-    const char *const kSpeakerExcursionPath;
-    const char *const kSpeakerHeartbeatPath;
-    const std::vector<std::string> kUFSErrStatsPath;
-    const int kBlockStatsLength;
-    const char *const kAmsRatePath;
-    const std::vector<std::string> kThermalStatsPaths;
-    const char *const kCCARatePath;
-    const std::vector<std::pair<std::string, std::string>> kTempResidencyAndResetPaths;
-    const char *const kLongIRQMetricsPath;
-    const char *const kStormIRQMetricsPath;
-    const char *const kIRQStatsResetPath;
-    const char *const kResumeLatencyMetricsPath;
-    const char *const kModemPcieLinkStatsPath;
-    const char *const kWifiPcieLinkStatsPath;
-    const std::vector<std::string> kDisplayStatsPaths;
-    const std::vector<std::string> kDisplayPortStatsPaths;
-    const std::vector<std::string> kDisplayPortDSCStatsPaths;
-    const std::vector<std::string> kDisplayPortMaxResolutionStatsPaths;
-    const std::vector<std::string> kHDCPStatsPaths;
-    const char *const kPDMStatePath;
-    const char *const kWavesPath;
-    const char *const kAdaptedInfoCountPath;
-    const char *const kAdaptedInfoDurationPath;
-    const char *const kPcmLatencyPath;
-    const char *const kPcmCountPath;
-    const char *const kTotalCallCountPath;
-    const char *const kOffloadEffectsIdPath;
-    const char *const kOffloadEffectsDurationPath;
-    const char *const kBluetoothAudioUsagePath;
-    const std::vector<std::string> kGMSRPath;
-    const char *const kMaxfgHistoryPath;
-    const std::vector<std::string> kFGModelLoadingPath;
-    const std::vector<std::string> kFGLogBufferPath;
-    const char *const kSpeakerVersionPath;
-    const char *const kWaterEventPath;
-
     BatteryEEPROMReporter battery_EEPROM_reporter_;
     MmMetricsReporter mm_metrics_reporter_;
     MitigationStatsReporter mitigation_stats_reporter_;
diff --git a/pixelstats/include/pixelstats/UeventListener.h b/pixelstats/include/pixelstats/UeventListener.h
index 125db874..a54587b7 100644
--- a/pixelstats/include/pixelstats/UeventListener.h
+++ b/pixelstats/include/pixelstats/UeventListener.h
@@ -19,9 +19,11 @@
 
 #include <aidl/android/frameworks/stats/IStats.h>
 #include <android-base/chrono_utils.h>
+#include <json/reader.h>
 #include <pixelstats/BatteryCapacityReporter.h>
 #include <pixelstats/ChargeStatsReporter.h>
 #include <pixelstats/BatteryFGReporter.h>
+#include <pixelstats/BatteryFwUpdateReporter.h>
 #include <pixelstats/WaterEventReporter.h>
 
 
@@ -39,19 +41,6 @@ using aidl::android::frameworks::stats::IStats;
  */
 class UeventListener {
   public:
-    struct UeventPaths {
-        const char *const AudioUevent;
-        const char *const SsocDetailsPath;
-        const char *const OverheatPath;
-        const char *const ChargeMetricsPath;
-        const char *const TypeCPartnerUevent;
-        const char *const TypeCPartnerVidPath;
-        const char *const TypeCPartnerPidPath;
-        const char *const WirelessChargerPtmcUevent;  // Deprecated.
-        const char *const WirelessChargerPtmcPath;    // Deprecated.
-        const char *const FwUpdatePath;
-        const std::vector<std::string> FGAbnlPath;
-    };
     constexpr static const char *const ssoc_details_path =
             "/sys/class/power_supply/battery/ssoc_details";
     constexpr static const char *const overheat_path_default =
@@ -64,19 +53,13 @@ class UeventListener {
             "/sys/class/typec/port0-partner/identity/product";
     constexpr static const char *const typec_partner_uevent_default = "DEVTYPE=typec_partner";
 
-    UeventListener(const std::string audio_uevent, const std::string ssoc_details_path = "",
-                   const std::string overheat_path = overheat_path_default,
-                   const std::string charge_metrics_path = charge_metrics_path_default,
-                   const std::string typec_partner_vid_path = typec_partner_vid_path_default,
-                   const std::string typec_partner_pid_path = typec_partner_pid_path_default,
-                   const std::string fw_update_path = "",
-                   const std::vector<std::string> fg_abnl_path = {""});
-    UeventListener(const struct UeventPaths &paths);
+    UeventListener(const Json::Value& configData);
 
     bool ProcessUevent();  // Process a single Uevent.
     void ListenForever();  // Process Uevents forever
 
   private:
+    const Json::Value configData;
     bool ReadFileToInt(const std::string &path, int *val);
     bool ReadFileToInt(const char *path, int *val);
     void ReportMicStatusUevents(const std::shared_ptr<IStats> &stats_client, const char *devpath,
@@ -102,27 +85,18 @@ class UeventListener {
     void ReportFGMetricsEvent(const std::shared_ptr<IStats> &stats_client, const char *driver);
     void ReportWaterEvent(const std::shared_ptr<IStats> &stats_client,
                           const char *driver, const char *devpath);
-
-    const std::string kAudioUevent;
-    const std::string kBatterySSOCPath;
-    const std::string kUsbPortOverheatPath;
-    const std::string kChargeMetricsPath;
-    const std::string kTypeCPartnerUevent;
-    const std::string kTypeCPartnerVidPath;
-    const std::string kTypeCPartnerPidPath;
-    const std::string kFwUpdatePath;
-    const std::vector<std::string> kFGAbnlPath;
-
+    void ReportFwUpdateEvent(const std::shared_ptr<IStats> &stats_client, const char *driver);
+    void ReportWlcFwUpdateEvent(const std::shared_ptr<IStats> &stats_client, const char *driver);
 
     const std::unordered_map<std::string, PixelAtoms::GpuEvent::GpuEventType>
-            kGpuEventTypeStrToEnum{
+            kMaliGpuEventTypeStrToEnum{
                     {"KMD_ERROR",
                      PixelAtoms::GpuEvent::GpuEventType::GpuEvent_GpuEventType_MALI_KMD_ERROR},
                     {"GPU_RESET",
                      PixelAtoms::GpuEvent::GpuEventType::GpuEvent_GpuEventType_MALI_GPU_RESET}};
 
     const std::unordered_map<std::string, PixelAtoms::GpuEvent::GpuEventInfo>
-            kGpuEventInfoStrToEnum{
+            kMaliGpuEventInfoStrToEnum{
                     {"CSG_REQ_STATUS_UPDATE",
                      PixelAtoms::GpuEvent::GpuEventInfo::
                              GpuEvent_GpuEventInfo_MALI_CSG_REQ_STATUS_UPDATE},
@@ -174,6 +148,20 @@ class UeventListener {
                      PixelAtoms::GpuEvent::GpuEventInfo::
                              GpuEvent_GpuEventInfo_MALI_TRACE_BUF_INVALID_SLOT}};
 
+    const std::unordered_map<std::string, PixelAtoms::GpuEvent::GpuEventType>
+            kPVRGpuEventTypeStrToEnum{
+                    {"KMD_ERROR",
+                     PixelAtoms::GpuEvent::GpuEventType::GpuEvent_GpuEventType_PVR_KMD_ERROR}};
+
+    const std::unordered_map<std::string, PixelAtoms::GpuEvent::GpuEventInfo>
+            kPVRGpuEventInfoStrToEnum{
+                    {"FW_PAGEFAULT", PixelAtoms::GpuEvent::GpuEventInfo::
+                                                   GpuEvent_GpuEventInfo_PVR_FW_PAGEFAULT},
+                    {"HOST_WDG_FW_ERROR", PixelAtoms::GpuEvent::GpuEventInfo::
+                                                    GpuEvent_GpuEventInfo_PVR_HOST_WDG_FW_ERROR},
+                    {"GUILTY_LOCKUP", PixelAtoms::GpuEvent::GpuEventInfo::
+                                                    GpuEvent_GpuEventInfo_PVR_GUILTY_LOCKUP}};
+
     const std::unordered_map<std::string,
                              PixelAtoms::ThermalSensorAbnormalityDetected::AbnormalityType>
             kThermalAbnormalityTypeStrToEnum{
@@ -199,6 +187,7 @@ class UeventListener {
     BatteryCapacityReporter battery_capacity_reporter_;
     ChargeStatsReporter charge_stats_reporter_;
     BatteryFGReporter battery_fg_reporter_;
+    BatteryFwUpdateReporter battery_fw_update_reporter_;
     WaterEventReporter water_event_reporter_;
 
     // Proto messages are 1-indexed and VendorAtom field numbers start at 2, so
diff --git a/pixelstats/include/pixelstats/WaterEventReporter.h b/pixelstats/include/pixelstats/WaterEventReporter.h
index def9715f..b09c74f1 100644
--- a/pixelstats/include/pixelstats/WaterEventReporter.h
+++ b/pixelstats/include/pixelstats/WaterEventReporter.h
@@ -35,18 +35,20 @@ using aidl::android::frameworks::stats::IStats;
 class WaterEventReporter {
   public:
     WaterEventReporter();
-    void logEvent(const std::shared_ptr<IStats> &stats_client,
-                  PixelAtoms::WaterEventReported::EventPoint event_point,
-                  const std::string_view sysfs_root);
+    void logBootEvent(const std::shared_ptr<IStats> &stats_client,
+                      const std::vector<std::string> &sysfs_roots);
     void logUevent(const std::shared_ptr<IStats> &stats_client,
                   const std::string_view uevent_devpath);
     bool ueventDriverMatch(const char * const driver);
   private:
+    void logEvent(const std::shared_ptr<IStats> &stats_client,
+                  const PixelAtoms::WaterEventReported::EventPoint event_point,
+                  const std::string_view sysfs_root);
     // Proto messages are 1-indexed and VendorAtom field numbers start at 2, so
     // store everything in the values array at the index of the field number
     // -2.
     const int kVendorAtomOffset = 2;
-    const int kNumOfWaterEventAtoms = 13;
+    const int kNumOfWaterEventAtomFields = 13;
 };
 
 }  // namespace pixel
diff --git a/pixelstats/pixelatoms.proto b/pixelstats/pixelatoms.proto
index d277645a..b3f2e448 100644
--- a/pixelstats/pixelatoms.proto
+++ b/pixelstats/pixelatoms.proto
@@ -129,6 +129,7 @@ message Atom {
       BatteryTimeToFullStatsReported battery_time_to_full_stats_reported = 105074;
       VendorAudioDirectUsbAccessUsageStats vendor_audio_direct_usb_access_usage_stats = 105075 [(android.os.statsd.module) = "pixelaudio"];
       VendorAudioUsbConfigStats vendor_audio_usb_config_stats = 105076 [(android.os.statsd.module) = "pixelaudio"];
+      GpuFrequencyTimeInStatePerUidReported gpu_frequency_time_in_state_per_uid_reported = 105077;
       GpuFrozenAppsMemoryPerUid gpu_frozen_apps_memory_per_uid = 105078;
       RepairModeEntered repair_mode_entered = 105079;
       RepairModeExited repair_mode_exited = 105080;
@@ -143,6 +144,9 @@ message Atom {
       WaterEventReported water_event_reported = 105089;
       MediaPlaybackUsageStatsReported media_playback_usage_stats_reported = 105090 [(android.os.statsd.module) = "pixelaudio"];
       CallUsageStatsReported call_usage_stats_reported = 105091 [(android.os.statsd.module) = "pixelaudio"];
+      BatteryFirmwareUpdateReported battery_firmware_update_reported = 105092;
+      PowerFifoDump power_fifo_dump = 105093 [(android.os.statsd.module) = "pixelpower"];
+      GnssTtffReported gnss_ttff_reported = 105094 [(android.os.statsd.module) = "pixelgnss"];
     }
     // AOSP atom ID range ends at 109999
     reserved 109997; // reserved for VtsVendorAtomJavaTest test atom
@@ -191,6 +195,8 @@ message ChargeStats {
         ADAPTER_TYPE_EXT_UNKNOWN = 29;
         ADAPTER_TYPE_USB_UNKNOWN = 30;
         ADAPTER_TYPE_WLC_UNKNOWN = 31;
+        ADAPTER_TYPE_WPC_MPP = 32;
+        ADAPTER_TYPE_WPC_MPP25 = 33;
     }
     optional string reverse_domain_name = 1;
     /* Type of charge adapter, enumerated above. */
@@ -513,6 +519,7 @@ message CitadelEvent {
     UPGRADED = 3;
     ALERT_V2 = 4;
     SEC_CH_STATE = 5;
+    ALERT_V3 = 6;
   };
   optional string reverse_domain_name = 1;
   optional Event event = 2;
@@ -560,6 +567,44 @@ message CitadelEvent {
   // SEC_CH_STATE-specific filed. This field corresponds to the state
   // of GSA-GSC secure channel.
   optional int32 sec_ch_state = 23;
+
+  // Added ALERT_V3 specific fields
+
+  // bitmask of all the alerts that occurred.
+  repeated bool alert_bitmask = 24;
+
+  // For V3 alerts there are 3 types of alerts - alerts of different types
+  // differ in how they are handled on GSC, with there being 3 types:
+  //  1. Informational - alerts that are not handled
+  //  2. Recoverable - alerts that are handled but SW
+  //  3. Fatal - alert cannot be handled by SW and always reset the chip
+  //  4. Reserved - alert type is not being used right now, may be
+  //     assigned in the future
+
+  // Alert types - used to index into the following fields.
+  enum AlertV3Types {
+    INFORMATIONAL = 0;
+    RECOVERABLE = 1;
+    FATAL = 2;
+    RESERVED = 3;
+  };
+
+  // Amount of time that alerts from each type must be handled in before
+  // escalation occurs.
+  repeated int64 type_escalation_ctrs = 25;
+  // Number of alerts that have occurred for each alert type.
+  repeated int32 type_cnts = 26;
+  // Escalation level for each alert type. A higher escalation level corresponds
+  // to greater severity and need for handling by SW/HW.
+  repeated int32 type_escalation_levels = 27;
+
+  // Invidivual alert fields. Information from single alerts are grouped by
+  // index.
+
+  // Cause of alerts
+  repeated int64 alert_causes = 28;
+  // ID of alerts
+  repeated int32 alerts = 29;
 }
 
 /* A message containing the citadel firmware version. */
@@ -1993,6 +2038,8 @@ message GpuEvent {
       MALI_TYPE_NONE = 0;
       MALI_KMD_ERROR = 1;
       MALI_GPU_RESET = 2;
+      /* Reserving up to 9 for mali event types */
+      PVR_KMD_ERROR = 10;
     }
     enum GpuEventInfo {
       MALI_INFO_NONE = 0;
@@ -2020,6 +2067,11 @@ message GpuEvent {
       MALI_GPU_PAGE_FAULT = 22;
       MALI_MMU_AS_ACTIVE_STUCK = 23;
       MALI_TRACE_BUF_INVALID_SLOT = 24;
+      /* Reserving up to 49 for mali event info */
+      PVR_INFO_NONE = 50;
+      PVR_FW_PAGEFAULT = 51;
+      PVR_HOST_WDG_FW_ERROR = 52;
+      PVR_GUILTY_LOCKUP = 53;
     }
 
     /* Vendor reverse domain name (expecting "com.google.pixel"). */
@@ -2724,6 +2776,87 @@ message VendorAudioUsbConfigStats {
   optional int32 duration_second = 7;
 };
 
+/*
+ * Per-app GPU DVFS time-in-state data, for each GPU frequency.
+ * Logging is capped at 15 apps/uids max, per 6 hours.
+ * Logged from:
+ *   hardware/google/pixel/pixelstats/
+ *
+ * See: b/341045478, b/340834608
+ *
+ * Estimated Logging Rate:
+ * Peak: 15 times in 6 hours | Avg: 15 times in 6 hours
+ */
+message GpuFrequencyTimeInStatePerUidReported {
+  /* Vendor reverse domain name (expecting "com.google.pixel"). */
+  optional string reverse_domain_name = 1;
+
+  /* App UID. */
+  optional int32 uid = 2 [(android.os.statsd.is_uid) = true];
+
+  /*
+   * Time passed, since the previous push of this atom for this uid, in
+   * milliseconds.
+   */
+  optional int32 reporting_duration_ms = 3;
+
+  /*
+   * Report up to 15 different frequencies, and how much time was spent in each
+   * frequency, by this app/uid since the previous push of this atom.
+   * Frequencies are given in KHz, and time is given in milliseconds since the
+   * previous push of this atom.
+   * Each individual device will always report the same frequency in the same
+   * field (for the aggregation in the metric(s) to work). If a frequency had 0
+   * time spent in it (since the previous atom push) for an app/uid - both
+   * frequency and duration fields for that frequency will not be set (to save
+   * space).
+   */
+  optional int32 frequency_1_khz = 4;
+  optional int32 time_1_millis = 5;
+
+  optional int32 frequency_2_khz = 6;
+  optional int32 time_2_millis = 7;
+
+  optional int32 frequency_3_khz = 8;
+  optional int32 time_3_millis = 9;
+
+  optional int32 frequency_4_khz = 10;
+  optional int32 time_4_millis = 11;
+
+  optional int32 frequency_5_khz = 12;
+  optional int32 time_5_millis = 13;
+
+  optional int32 frequency_6_khz = 14;
+  optional int32 time_6_millis = 15;
+
+  optional int32 frequency_7_khz = 16;
+  optional int32 time_7_millis = 17;
+
+  optional int32 frequency_8_khz = 18;
+  optional int32 time_8_millis = 19;
+
+  optional int32 frequency_9_khz = 20;
+  optional int32 time_9_millis = 21;
+
+  optional int32 frequency_10_khz = 22;
+  optional int32 time_10_millis = 23;
+
+  optional int32 frequency_11_khz = 24;
+  optional int32 time_11_millis = 25;
+
+  optional int32 frequency_12_khz = 26;
+  optional int32 time_12_millis = 27;
+
+  optional int32 frequency_13_khz = 28;
+  optional int32 time_13_millis = 29;
+
+  optional int32 frequency_14_khz = 30;
+  optional int32 time_14_millis = 31;
+
+  optional int32 frequency_15_khz = 32;
+  optional int32 time_15_millis = 33;
+}
+
 /* GPU memory allocation information for frozen apps */
 message GpuFrozenAppsMemoryPerUid {
   /* Vendor reverse domain name (expecting "com.google.pixel"). */
@@ -3101,6 +3234,38 @@ message MediaPlaybackUsageStatsReported {
 
   /* Average power in milliwatts. -1 if unavailable. */
   optional float average_power = 11;
+
+  /* Sample rate used in the media playback. */
+  optional int32 sample_rate = 12;
+
+  /* Sample rate used in the media playback. */
+  optional int32 channel_count = 13;
+
+  /* Sample rate used in the media playback. */
+  optional int32 audio_format_type = 14;
+
+  /* Sample rate used in the media playback. */
+  optional int32 pcm_type = 15;
+
+  enum OffloadEncoding {
+    UNKNOWN_ENCODING = 0;
+    NO_ENCODING = 1;
+    PCM_UINT_8_BIT = 2;
+    PCM_INT_16_BIT = 3;
+    PCM_INT_24_BIT = 4;
+    PCM_FIXED_Q_8_24 = 5;
+    PCM_INT_32_BIT = 6;
+    PCM_FLOAT_32_BIT = 7;
+    MP3 = 8;
+    AAC = 9;
+    AAC_LC = 10;
+    AAC_HE_V1 = 11;
+    AAC_HE_V2 = 12;
+    OPUS = 13;
+  }
+
+  /* Offload Encoding used in the media playback. */
+  optional OffloadEncoding offload_encoding = 16;
 }
 
 /*
@@ -3145,7 +3310,12 @@ message CallUsageStatsReported {
   optional float average_power = 11;
 
   /* background noise level from 1 (lowest) to 12 (highest). */
-  optional float noise_level = 12;
+  optional float noise_level = 12 [deprecated = true];
+
+  // durations list of size 12 representing percentage
+  // of duration of each background noise level
+  // from -1 (lowest) to 12 (highest).
+  repeated float noise_level_percentages = 13;
 }
 
 /*
@@ -3265,23 +3435,125 @@ message WaterEventReported {
   /* The state of the reference sensor. */
   optional SensorState reference_state = 4;
   /* The threshold of the reference in mV. */
-  optional int32 reference_threshold = 8;
+  optional int32 reference_threshold_mv = 8 [deprecated = true];
 
   /* The state of sensor 0. */
   optional SensorState sensor0_state = 5;
   /* The threshold of sensor 0 in mV. */
-  repeated int32 sensor0_threshold = 9;
+  repeated int32 sensor0_threshold_mv = 9 [packed = true, deprecated = true];
 
   /* The state of sensor 1. */
   optional SensorState sensor1_state = 6;
   /* The threshold of sensor1 in mv. */
-  repeated int32 sensor1_threshold = 10;
+  repeated int32 sensor1_threshold_mv = 10 [packed = true, deprecated = true];
 
-   /* The state of sensor 2. */
+  /* The state of sensor 2. */
   optional SensorState sensor2_state = 7;
   /* The threshold of the sensor 2 in mv. */
-  repeated int32 sensor2_threshold = 11;
+  repeated int32 sensor2_threshold_mv = 11 [packed = true, deprecated = true];
 
   /* Was system fault enabled */
   optional CircuitState fault_enabled = 12;
 }
+
+/**
+ * A message containing battery related firmware update stats
+ * Logged from:
+ *    hardware/google/pixel/pixelstats/BatteryFwUpdateReporter.cpp
+ */
+message BatteryFirmwareUpdateReported {
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+  optional int32 msg_type = 2;
+  optional int32 msg_category = 3;
+  /* current firmware version */
+  optional int32 major_version_from = 4;
+  optional int32 minor_version_from = 5;
+  /* target firmware version */
+  optional int32 major_version_to = 6;
+  optional int32 minor_version_to = 7;
+  optional int32 update_status = 8;
+  optional int32 attempts = 9;
+  optional int32 unix_time_sec = 10;
+  /* additional firmware data */
+  optional int32 fw_data0 = 11;
+  optional int32 fw_data1 = 12;
+  optional int32 fw_data2 = 13;
+  optional int32 fw_data3 = 14;
+}
+
+
+/*
+ * A message containing a list of 30 elements representing the battery history
+ * of milliwatts, and milliwatt durations which can be used to analyze battery
+ * behavior over time. The elements are ordered from oldest to newest.
+ * The history window is not measured in days but rather fluctuates between
+ * 100s of milliseconds and a few minutes based on the device's power state.
+ */
+message PowerFifoDump {
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+  /* The estimated milliwatts.*/
+  repeated int32 milliwatts = 2;
+  /* The estimated duration in milliseconds. */
+  repeated int32 duration_ms = 3;
+  /* The elapsed time in milliseconds, from when the final sample was taken. */
+  required int64 elapsed_time_ms = 4;
+}
+
+/*
+ * A message containing a TTFF, aiding data and related satellite information.
+ * Logged from:
+ *   vendor/google/gnss/aidl_service/GnssAtomsReporter.cpp
+ *
+ * Estimated Logging Rate:
+ * Any time that user turn on location function (only first location calculated).
+ * Peak: 1 times in 3 min | Avg: 48 times per device per day
+ */
+message GnssTtffReported {
+  enum TtffType {
+    TTFF_UNKNOWN = 0;
+    TTFF_COLD = 1;
+    TTFF_WARM = 2;
+    TTFF_HOT = 3;
+  }
+  /* Vendor reverse domain name */
+  optional string reverse_domain_name = 1;
+  /* The start type at which each TTFF event was collected. */
+  optional TtffType ttff_type = 2;
+  /* Time To First Fix in milliseconds. */
+  optional int32 ttff_milliseconds = 3;
+  /* Estimated position accuracy (meters). */
+  optional int32 ttff_horizontal_position_accuracy = 4;
+  /* The number of satellites used. */
+  optional int32 ttff_used_in_fix_sv_count = 5;
+  /* The L1 satellite constellations in view. */
+  repeated int32 ttff_l1_constellation_list = 6;
+  /* The L1 satellite PRNs in view. */
+  repeated int32 ttff_l1_prn_list = 7;
+  /* The L1 CN0 for each satellite. */
+  repeated int32 ttff_l1_cn0_list = 8;
+  /* The L5 satellite constellations in view. */
+  repeated int32 ttff_l5_constellation_list = 9;
+  /* The L5 PRN satellite in view. */
+  repeated int32 ttff_l5_prn_list = 10;
+  /* The L5 CN0 for each satelltie. */
+  repeated int32 ttff_l5_cn0_list = 11;
+  /*
+   * Aiding data provided by framework.
+   * Time elapsed since a location request was initiated.
+   * Zero indicates no request/inject was made.
+   */
+  optional int32 reference_location_request_milliseconds = 12;
+  optional int32 reference_location_inject_milliseconds = 13;
+  optional int32 reference_time_request_milliseconds = 14;
+  optional int32 reference_time_inject_milliseconds = 15;
+  optional int32 supl_aiding_request_milliseconds = 16;
+  optional int32 supl_aiding_inject_milliseconds = 17;
+  optional int32 vendor_aiding_request_milliseconds = 18;
+  optional int32 vendor_aiding_inject_milliseconds = 19;
+  /* The aiding data without precise timestamp */
+  optional bool reference_frequency_used = 20;
+  optional bool almanac_used = 21;
+  optional bool ephemeris_used = 22;
+}
diff --git a/power-libperfmgr/Android.bp b/power-libperfmgr/Android.bp
index c29d9d60..bd4ccc7e 100644
--- a/power-libperfmgr/Android.bp
+++ b/power-libperfmgr/Android.bp
@@ -72,6 +72,7 @@ cc_test {
         "aidl/SessionChannel.cpp",
         "aidl/SessionTaskMap.cpp",
         "aidl/SessionValueEntry.cpp",
+        "aidl/TaskRampupMultNode.cpp",
         "aidl/UClampVoter.cpp",
     ],
     cpp_std: "gnu++20",
@@ -110,6 +111,8 @@ cc_binary {
         "-Wthread-safety",
     ],
     shared_libs: [
+        "android.hardware.thermal@2.0",
+        "android.hardware.thermal-V1-ndk",
         "libbase",
         "libcutils",
         "liblog",
@@ -119,17 +122,20 @@ cc_binary {
         "libperfmgr",
         "libprocessgroup",
         "pixel-power-ext-V1-ndk",
+        "android.frameworks.stats-V2-ndk",
         "android.hardware.common.fmq-V1-ndk",
         "libfmq",
     ],
     static_libs: [
         "libgmock",
         "libgtest",
+        "libpixelstats",
     ],
     srcs: [
         "aidl/BackgroundWorker.cpp",
         "aidl/ChannelGroup.cpp",
         "aidl/ChannelManager.cpp",
+        "aidl/MetricUploader.cpp",
         "aidl/GpuCalculationHelpers.cpp",
         "aidl/GpuCapacityNode.cpp",
         "aidl/service.cpp",
@@ -143,6 +149,8 @@ cc_binary {
         "aidl/SessionChannel.cpp",
         "aidl/SessionTaskMap.cpp",
         "aidl/SessionValueEntry.cpp",
+        "aidl/TaskRampupMultNode.cpp",
+        "aidl/utils/ThermalStateListener.cpp",
     ],
     cpp_std: "gnu++20",
 }
diff --git a/power-libperfmgr/aidl/AppDescriptorTrace.h b/power-libperfmgr/aidl/AppDescriptorTrace.h
index 96b7060a..5e3524c5 100644
--- a/power-libperfmgr/aidl/AppDescriptorTrace.h
+++ b/power-libperfmgr/aidl/AppDescriptorTrace.h
@@ -67,6 +67,8 @@ struct AppDescriptorTrace {
         trace_uclamp_min_floor =
                 StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.uclampMinFloor");
         trace_hboost_pid_pu = StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.uclampPidPu");
+        trace_rampup_boost_active =
+                StringPrintf("adpf.%s-%s", idString.c_str(), "hboost.rampupBoostActive");
 
         for (size_t i = 0; i < trace_modes.size(); ++i) {
             trace_modes[i] = StringPrintf(
@@ -108,6 +110,7 @@ struct AppDescriptorTrace {
     std::string trace_low_frame_rate;
     std::string trace_max_duration;
     std::string trace_missed_cycles;
+    std::string trace_rampup_boost_active;
     std::string trace_uclamp_min_ceiling;
     std::string trace_uclamp_min_floor;
 
diff --git a/power-libperfmgr/aidl/AppHintDesc.h b/power-libperfmgr/aidl/AppHintDesc.h
index 14da80a2..294ff6f8 100644
--- a/power-libperfmgr/aidl/AppHintDesc.h
+++ b/power-libperfmgr/aidl/AppHintDesc.h
@@ -21,6 +21,8 @@
 
 #include <chrono>
 
+#include "AdpfTypes.h"
+
 namespace aidl::google::hardware::power::impl::pixel {
 
 // The App Hint Descriptor struct manages information necessary
@@ -29,13 +31,15 @@ namespace aidl::google::hardware::power::impl::pixel {
 // easily passing to the pid function
 struct AppHintDesc {
     AppHintDesc(int64_t sessionId, int32_t tgid, int32_t uid, const std::vector<int32_t> &threadIds,
-                android::hardware::power::SessionTag tag, std::chrono::nanoseconds pTargetNs)
+                android::hardware::power::SessionTag tag, ProcessTag procTag,
+                std::chrono::nanoseconds pTargetNs)
         : sessionId(sessionId),
           tgid(tgid),
           uid(uid),
           targetNs(pTargetNs),
           thread_ids(threadIds),
           tag(tag),
+          procTag(procTag),
           pidControlVariable(0),
           is_active(true),
           update_count(0),
@@ -49,6 +53,7 @@ struct AppHintDesc {
     std::chrono::nanoseconds targetNs;
     std::vector<int32_t> thread_ids;
     android::hardware::power::SessionTag tag;
+    ProcessTag procTag;
     int pidControlVariable;
     // status
     std::atomic<bool> is_active;
diff --git a/power-libperfmgr/aidl/MetricUploader.cpp b/power-libperfmgr/aidl/MetricUploader.cpp
new file mode 100644
index 00000000..bb6e05ec
--- /dev/null
+++ b/power-libperfmgr/aidl/MetricUploader.cpp
@@ -0,0 +1,99 @@
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
+#include "MetricUploader.h"
+
+#include <android-base/logging.h>
+#include <android/binder_manager.h>
+
+namespace aidl {
+namespace google {
+namespace hardware {
+namespace power {
+namespace impl {
+namespace pixel {
+
+using android::frameworks::stats::VendorAtom;
+
+bool MetricUploader::connectIStatsService() {
+    if (mIStatsClient) {
+        LOG(INFO) << "IStats service client exists, skip this";
+        return true;
+    }
+
+    const std::string iStatsServiceName = std::string(IStats::descriptor) + "/default";
+
+    if (!AServiceManager_isDeclared(iStatsServiceName.c_str())) {
+        LOG(ERROR) << "IStats service not declared";
+        return false;
+    }
+
+    ndk::SpAIBinder iStatsBinder =
+            ndk::SpAIBinder(AServiceManager_waitForService(iStatsServiceName.c_str()));
+    if (iStatsBinder.get() == nullptr) {
+        LOG(ERROR) << "Cannot get IStats binder!";
+        return false;
+    }
+
+    mIStatsClient = IStats::fromBinder(iStatsBinder);
+    if (mIStatsClient == nullptr) {
+        LOG(ERROR) << "Cannot create IStats AIDL client!";
+        return false;
+    }
+
+    LOG(INFO) << "Connected to IStats service.";
+    return true;
+}
+
+bool MetricUploader::init() {
+    return connectIStatsService();
+}
+
+bool MetricUploader::reportAtom(const int32_t &atomId, std::vector<VendorAtomValue> &&values) {
+    LOG(VERBOSE) << "Reporting powerhal metrics ...";
+    VendorAtom event = {.reverseDomainName = "", .atomId = atomId, .values = std::move(values)};
+    if (!mIStatsClient) {
+        if (!connectIStatsService()) {
+            LOG(ERROR) << "Don't have valid connection to IStats service!";
+            return false;
+        }
+    }
+    const ndk::ScopedAStatus ret = mIStatsClient->reportVendorAtom(event);
+    if (!ret.isOk()) {
+        LOG(ERROR) << "Failed at reporting atom: " << ret.getMessage();
+        return false;
+    }
+    return true;
+}
+
+bool MetricUploader::uploadMetrics(const SessionJankStatsWithThermal &sessMetrics) {
+    // TODO(guibing): Store the sessMetrics into the format of the metric atom
+    // and then call "reportAtom" to upload them.
+    std::string sessMetricDescriptor = std::string(toString(sessMetrics.scenarioType)) + "-" +
+                                       toString(sessMetrics.frameTimelineType);
+    if (sessMetrics.uid) {
+        sessMetricDescriptor += "-" + std::to_string(sessMetrics.uid.value());
+    }
+    LOG(VERBOSE) << "Uploading session metrics for " << sessMetricDescriptor;
+    return true;
+}
+
+}  // namespace pixel
+}  // namespace impl
+}  // namespace power
+}  // namespace hardware
+}  // namespace google
+}  // namespace aidl
diff --git a/power-libperfmgr/aidl/MetricUploader.h b/power-libperfmgr/aidl/MetricUploader.h
new file mode 100644
index 00000000..137cd213
--- /dev/null
+++ b/power-libperfmgr/aidl/MetricUploader.h
@@ -0,0 +1,64 @@
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
+#include <aidl/android/frameworks/stats/IStats.h>
+#include <hardware/google/pixel/pixelstats/pixelatoms.pb.h>
+
+#include "SessionMetrics.h"
+
+namespace aidl {
+namespace google {
+namespace hardware {
+namespace power {
+namespace impl {
+namespace pixel {
+
+using aidl::android::frameworks::stats::IStats;
+using android::frameworks::stats::VendorAtomValue;
+
+class MetricUploader {
+  public:
+    ~MetricUploader() = default;
+    MetricUploader(MetricUploader const &) = delete;
+    MetricUploader(MetricUploader &&) = delete;
+    MetricUploader &operator=(MetricUploader const &) = delete;
+    MetricUploader &operator=(MetricUploader &&) = delete;
+
+    bool init();
+    bool uploadMetrics(const SessionJankStatsWithThermal &sessMetrics);
+
+    // Singleton
+    static MetricUploader *getInstance() {
+        static MetricUploader instance{};
+        return &instance;
+    }
+
+  private:
+    MetricUploader() = default;
+    bool reportAtom(const int32_t &atomId, std::vector<VendorAtomValue> &&values);
+    bool connectIStatsService();
+
+    std::shared_ptr<IStats> mIStatsClient;
+};
+
+}  // namespace pixel
+}  // namespace impl
+}  // namespace power
+}  // namespace hardware
+}  // namespace google
+}  // namespace aidl
diff --git a/power-libperfmgr/aidl/Power.cpp b/power-libperfmgr/aidl/Power.cpp
index 50ec5439..1f1faa82 100644
--- a/power-libperfmgr/aidl/Power.cpp
+++ b/power-libperfmgr/aidl/Power.cpp
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 
+#define ATRACE_TAG (ATRACE_TAG_POWER | ATRACE_TAG_HAL)
 #define LOG_TAG "powerhal-libperfmgr"
 
 #include "Power.h"
@@ -26,6 +27,7 @@
 #include <fmq/EventFlag.h>
 #include <perfmgr/HintManager.h>
 #include <utils/Log.h>
+#include <utils/Trace.h>
 
 #include <cstdint>
 #include <memory>
@@ -96,6 +98,7 @@ Power::Power(std::shared_ptr<DisplayLowPower> dlpw)
 
 ndk::ScopedAStatus Power::setMode(Mode type, bool enabled) {
     LOG(DEBUG) << "Power setMode: " << toString(type) << " to: " << enabled;
+    ATRACE_NAME(("M:" + toString(type) + ":" + (enabled ? "on" : "off")).c_str());
     if (HintManager::GetInstance()->IsAdpfSupported()) {
         PowerSessionManager<>::getInstance()->updateHintMode(toString(type), enabled);
     }
@@ -194,6 +197,7 @@ ndk::ScopedAStatus Power::isModeSupported(Mode type, bool *_aidl_return) {
 
 ndk::ScopedAStatus Power::setBoost(Boost type, int32_t durationMs) {
     LOG(DEBUG) << "Power setBoost: " << toString(type) << " duration: " << durationMs;
+    ATRACE_NAME(("B:" + toString(type) + ":" + std::to_string(durationMs)).c_str());
     switch (type) {
         case Boost::INTERACTION:
             if (mVRModeOn || mSustainedPerfModeOn) {
diff --git a/power-libperfmgr/aidl/PowerExt.cpp b/power-libperfmgr/aidl/PowerExt.cpp
index 045772f5..098139b6 100644
--- a/power-libperfmgr/aidl/PowerExt.cpp
+++ b/power-libperfmgr/aidl/PowerExt.cpp
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 
+#define ATRACE_TAG (ATRACE_TAG_POWER | ATRACE_TAG_HAL)
 #define LOG_TAG "android.hardware.power-service.pixel.ext-libperfmgr"
 
 #include "PowerExt.h"
@@ -25,6 +26,7 @@
 #include <android-base/strings.h>
 #include <perfmgr/HintManager.h>
 #include <utils/Log.h>
+#include <utils/Trace.h>
 
 #include <mutex>
 
@@ -41,6 +43,7 @@ using ::android::perfmgr::HintManager;
 
 ndk::ScopedAStatus PowerExt::setMode(const std::string &mode, bool enabled) {
     LOG(DEBUG) << "PowerExt setMode: " << mode << " to: " << enabled;
+    ATRACE_NAME(("xM:" + mode + ":" + (enabled ? "on" : "off")).c_str());
 
     if (enabled) {
         HintManager::GetInstance()->DoHint(mode);
@@ -67,6 +70,7 @@ ndk::ScopedAStatus PowerExt::isModeSupported(const std::string &mode, bool *_aid
 
 ndk::ScopedAStatus PowerExt::setBoost(const std::string &boost, int32_t durationMs) {
     LOG(DEBUG) << "PowerExt setBoost: " << boost << " duration: " << durationMs;
+    ATRACE_NAME(("xB:" + boost + ":" + std::to_string(durationMs)).c_str());
 
     if (durationMs > 0) {
         HintManager::GetInstance()->DoHint(boost, std::chrono::milliseconds(durationMs));
diff --git a/power-libperfmgr/aidl/PowerHintSession.cpp b/power-libperfmgr/aidl/PowerHintSession.cpp
index ef9c7f03..95a666c4 100644
--- a/power-libperfmgr/aidl/PowerHintSession.cpp
+++ b/power-libperfmgr/aidl/PowerHintSession.cpp
@@ -74,7 +74,7 @@ int64_t PowerHintSession<HintManagerT, PowerSessionManagerT>::convertWorkDuratio
     uint64_t samplingWindowP = adpfConfig->mSamplingWindowP;
     uint64_t samplingWindowI = adpfConfig->mSamplingWindowI;
     uint64_t samplingWindowD = adpfConfig->mSamplingWindowD;
-    int64_t targetDurationNanos = (int64_t)targetDuration.count();
+    int64_t targetDurationNanos = static_cast<int64_t>(targetDuration.count());
     int64_t length = actualDurations.size();
     int64_t p_start =
             samplingWindowP == 0 || samplingWindowP > length ? 0 : length - samplingWindowP;
@@ -177,7 +177,7 @@ PowerHintSession<HintManagerT, PowerSessionManagerT>::PowerHintSession(
       mProcTag(getProcessTag(tgid)),
       mIdString(StringPrintf("%" PRId32 "-%" PRId32 "-%" PRId64 "-%s-%" PRId32, tgid, uid,
                              mSessionId, toString(tag).c_str(), static_cast<int32_t>(mProcTag))),
-      mDescriptor(std::make_shared<AppHintDesc>(mSessionId, tgid, uid, threadIds, tag,
+      mDescriptor(std::make_shared<AppHintDesc>(mSessionId, tgid, uid, threadIds, tag, mProcTag,
                                                 std::chrono::nanoseconds(durationNs))),
       mAppDescriptorTrace(std::make_shared<AppDescriptorTrace>(mIdString)),
       mAdpfProfile(mProcTag != ProcessTag::DEFAULT
@@ -202,7 +202,7 @@ PowerHintSession<HintManagerT, PowerSessionManagerT>::PowerHintSession(
     }
 
     mLastUpdatedTime = std::chrono::steady_clock::now();
-    mPSManager->addPowerSession(mIdString, mDescriptor, mAppDescriptorTrace, threadIds, mProcTag);
+    mPSManager->addPowerSession(mIdString, mDescriptor, mAppDescriptorTrace, threadIds);
     // init boost
     auto adpfConfig = getAdpfProfile();
     mPSManager->voteSet(
@@ -275,9 +275,9 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::pause()
     if (!mDescriptor->is_active.load())
         return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
     // Reset to default uclamp value.
-    mPSManager->setThreadsFromPowerSession(mSessionId, {}, mProcTag);
     mDescriptor->is_active.store(false);
     mPSManager->pause(mSessionId);
+    mPSManager->setThreadsFromPowerSession(mSessionId, {});
     ATRACE_INT(mAppDescriptorTrace->trace_active.c_str(), false);
     ATRACE_INT(mAppDescriptorTrace->trace_min.c_str(), 0);
     return ndk::ScopedAStatus::ok();
@@ -293,7 +293,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::resume(
     if (mDescriptor->is_active.load()) {
         return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
     }
-    mPSManager->setThreadsFromPowerSession(mSessionId, mDescriptor->thread_ids, mProcTag);
+    mPSManager->setThreadsFromPowerSession(mSessionId, mDescriptor->thread_ids);
     mDescriptor->is_active.store(true);
     // resume boost
     mPSManager->resume(mSessionId);
@@ -310,7 +310,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::close()
     }
     mSessionClosed = true;
     // Remove the session from PowerSessionManager first to avoid racing.
-    mPSManager->removePowerSession(mSessionId, mProcTag);
+    mPSManager->removePowerSession(mSessionId);
     mDescriptor->is_active.store(false);
 
     if (mProcTag != ProcessTag::DEFAULT) {
@@ -464,9 +464,6 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::reportA
                actualDurations.back().gpuDurationNanos);
 
     mLastUpdatedTime = std::chrono::steady_clock::now();
-    if (isFirstFrame) {
-        mPSManager->updateUniversalBoostMode();
-    }
 
     mPSManager->disableBoosts(mSessionId);
 
@@ -477,6 +474,8 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::reportA
 
     bool hboostEnabled =
             adpfConfig->mHeuristicBoostOn.has_value() && adpfConfig->mHeuristicBoostOn.value();
+    bool heurRampupEnabled =
+            adpfConfig->mHeuristicRampup.has_value() && adpfConfig->mHeuristicRampup.value();
 
     if (hboostEnabled) {
         FrameBuckets newFramesInBuckets;
@@ -486,6 +485,11 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::reportA
         mPSManager->updateHboostStatistics(mSessionId, mJankyLevel, actualDurations.size());
         mPSManager->updateFrameBuckets(mSessionId, newFramesInBuckets);
         updateHeuristicBoost();
+        if (heurRampupEnabled && mPSManager->hasValidTaskRampupMultNode()) {
+            mPSManager->updateRampupBoostMode(mSessionId, mJankyLevel,
+                                              adpfConfig->mDefaultRampupMult.value(),
+                                              adpfConfig->mHighRampupMult.value());
+        }
     }
 
     int64_t output = convertWorkDurationToBoostByPid(actualDurations);
@@ -673,7 +677,7 @@ ndk::ScopedAStatus PowerHintSession<HintManagerT, PowerSessionManagerT>::setThre
         return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
     }
     mDescriptor->thread_ids = threadIds;
-    mPSManager->setThreadsFromPowerSession(mSessionId, threadIds, mProcTag);
+    mPSManager->setThreadsFromPowerSession(mSessionId, threadIds);
     // init boost
     updatePidControlVariable(getAdpfProfile()->mUclampMinInit);
     return ndk::ScopedAStatus::ok();
diff --git a/power-libperfmgr/aidl/PowerSessionManager.cpp b/power-libperfmgr/aidl/PowerSessionManager.cpp
index 3547db30..fd17a906 100644
--- a/power-libperfmgr/aidl/PowerSessionManager.cpp
+++ b/power-libperfmgr/aidl/PowerSessionManager.cpp
@@ -21,12 +21,12 @@
 
 #include <android-base/file.h>
 #include <log/log.h>
-#include <perfmgr/HintManager.h>
 #include <private/android_filesystem_config.h>
 #include <processgroup/processgroup.h>
 #include <sys/syscall.h>
 #include <utils/Trace.h>
 
+#include "AdpfTypes.h"
 #include "AppDescriptorTrace.h"
 #include "AppHintDesc.h"
 #include "tests/mocks/MockHintManager.h"
@@ -38,8 +38,8 @@ namespace power {
 namespace impl {
 namespace pixel {
 
-using ::android::perfmgr::HintManager;
 constexpr char kGameModeName[] = "GAME";
+constexpr int32_t kBGRampupVal = 1;
 
 namespace {
 /* there is no glibc or bionic wrapper */
@@ -85,8 +85,8 @@ void PowerSessionManager<HintManagerT>::updateHintMode(const std::string &mode,
     }
 
     // TODO(jimmyshiu@): Deprecated. Remove once all powerhint.json up-to-date.
-    if (enabled && HintManager::GetInstance()->GetAdpfProfileFromDoHint()) {
-        HintManager::GetInstance()->SetAdpfProfileFromDoHint(mode);
+    if (enabled && HintManagerT::GetInstance()->GetAdpfProfileFromDoHint()) {
+        HintManagerT::GetInstance()->SetAdpfProfileFromDoHint(mode);
     }
 }
 
@@ -99,7 +99,7 @@ template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::addPowerSession(
         const std::string &idString, const std::shared_ptr<AppHintDesc> &sessionDescriptor,
         const std::shared_ptr<AppDescriptorTrace> &sessionTrace,
-        const std::vector<int32_t> &threadIds, const ProcessTag procTag) {
+        const std::vector<int32_t> &threadIds) {
     if (!sessionDescriptor) {
         ALOGE("sessionDescriptor is null. PowerSessionManager failed to add power session: %s",
               idString.c_str());
@@ -112,6 +112,8 @@ void PowerSessionManager<HintManagerT>::addPowerSession(
     sve.idString = idString;
     sve.isActive = sessionDescriptor->is_active;
     sve.isAppSession = sessionDescriptor->uid >= AID_APP_START;
+    sve.tag = sessionDescriptor->tag;
+    sve.procTag = sessionDescriptor->procTag;
     sve.lastUpdatedTime = timeNow;
     sve.votes = std::make_shared<Votes>();
     sve.sessionTrace = sessionTrace;
@@ -128,12 +130,11 @@ void PowerSessionManager<HintManagerT>::addPowerSession(
         ALOGE("sessionTaskMap failed to add power session: %" PRId64, sessionDescriptor->sessionId);
     }
 
-    setThreadsFromPowerSession(sessionDescriptor->sessionId, threadIds, procTag);
+    setThreadsFromPowerSession(sessionDescriptor->sessionId, threadIds);
 }
 
 template <class HintManagerT>
-void PowerSessionManager<HintManagerT>::removePowerSession(int64_t sessionId,
-                                                           const ProcessTag procTag) {
+void PowerSessionManager<HintManagerT>::removePowerSession(int64_t sessionId) {
     // To remove a session we also need to undo the effects the session
     // has on currently enabled votes which means setting vote to inactive
     // and then forceing a uclamp update to occur
@@ -141,6 +142,7 @@ void PowerSessionManager<HintManagerT>::removePowerSession(int64_t sessionId,
 
     std::vector<pid_t> addedThreads;
     std::vector<pid_t> removedThreads;
+    std::string profile = getSessionTaskProfile(sessionId, false);
 
     {
         // Wait till end to remove session because it needs to be around for apply U clamp
@@ -150,19 +152,9 @@ void PowerSessionManager<HintManagerT>::removePowerSession(int64_t sessionId,
         mSessionTaskMap.remove(sessionId);
     }
 
-    if (procTag == ProcessTag::SYSTEM_UI) {
-        for (auto tid : removedThreads) {
-            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_EXTREME_CLEAR"})) {
-                ALOGE("Failed to set SCHED_QOS_SENSITIVE_EXTREME_CLEAR task profile for tid:%d",
-                      tid);
-            }
-        }
-    } else {
-        for (auto tid : removedThreads) {
-            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_STANDARD_CLEAR"})) {
-                ALOGE("Failed to set SCHED_QOS_SENSITIVE_STANDARD_CLEAR task profile for tid:%d",
-                      tid);
-            }
+    for (auto tid : removedThreads) {
+        if (!SetTaskProfiles(tid, {profile})) {
+            ALOGE("Failed to set %s task profile for tid:%d", profile.c_str(), tid);
         }
     }
 
@@ -171,41 +163,26 @@ void PowerSessionManager<HintManagerT>::removePowerSession(int64_t sessionId,
 
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::setThreadsFromPowerSession(
-        int64_t sessionId, const std::vector<int32_t> &threadIds, const ProcessTag procTag) {
+        int64_t sessionId, const std::vector<int32_t> &threadIds) {
     std::vector<pid_t> addedThreads;
     std::vector<pid_t> removedThreads;
     forceSessionActive(sessionId, false);
+    std::string profile;
     {
         std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
         mSessionTaskMap.replace(sessionId, threadIds, &addedThreads, &removedThreads);
     }
-    if (procTag == ProcessTag::SYSTEM_UI) {
-        for (auto tid : addedThreads) {
-            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_EXTREME_SET"})) {
-                ALOGE("Failed to set SCHED_QOS_SENSITIVE_EXTREME_SET task profile for tid:%d", tid);
-            }
-        }
-    } else {
-        for (auto tid : addedThreads) {
-            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_STANDARD_SET"})) {
-                ALOGE("Failed to set SCHED_QOS_SENSITIVE_STANDARD_SET task profile for tid:%d",
-                      tid);
-            }
+
+    profile = getSessionTaskProfile(sessionId, true);
+    for (auto tid : addedThreads) {
+        if (!SetTaskProfiles(tid, {profile})) {
+            ALOGE("Failed to set %s task profile for tid:%d", profile.c_str(), tid);
         }
     }
-    if (procTag == ProcessTag::SYSTEM_UI) {
-        for (auto tid : removedThreads) {
-            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_EXTREME_CLEAR"})) {
-                ALOGE("Failed to set SCHED_QOS_SENSITIVE_EXTREME_CLEAR task profile for tid:%d",
-                      tid);
-            }
-        }
-    } else {
-        for (auto tid : removedThreads) {
-            if (!SetTaskProfiles(tid, {"SCHED_QOS_SENSITIVE_STANDARD_CLEAR"})) {
-                ALOGE("Failed to set SCHED_QOS_SENSITIVE_STANDARD_CLEAR task profile for tid:%d",
-                      tid);
-            }
+    profile = getSessionTaskProfile(sessionId, false);
+    for (auto tid : removedThreads) {
+        if (!SetTaskProfiles(tid, {profile})) {
+            ALOGE("Failed to set %s task profile for tid:%d", profile.c_str(), tid);
         }
     }
     forceSessionActive(sessionId, true);
@@ -222,19 +199,6 @@ std::optional<bool> PowerSessionManager<HintManagerT>::isAnyAppSessionActive() {
     return isAnyAppSessionActive;
 }
 
-template <class HintManagerT>
-void PowerSessionManager<HintManagerT>::updateUniversalBoostMode() {
-    const auto active = isAnyAppSessionActive();
-    if (!active.has_value()) {
-        return;
-    }
-    if (active.value()) {
-        disableSystemTopAppBoost();
-    } else {
-        enableSystemTopAppBoost();
-    }
-}
-
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::dumpToFd(int fd) {
     std::ostringstream dump_buf;
@@ -280,9 +244,14 @@ void PowerSessionManager<HintManagerT>::pause(int64_t sessionId) {
             return;
         }
         sessValPtr->isActive = false;
+        if (sessValPtr->rampupBoostActive) {
+            sessValPtr->rampupBoostActive = false;
+            // TODO(guibing): cancel the per task rampup qos vote instead of voting the
+            // default low value when session gets paused.
+            voteRampupBoostLocked(sessionId, false, kBGRampupVal, kBGRampupVal);
+        }
     }
     applyCpuAndGpuVotes(sessionId, std::chrono::steady_clock::now());
-    updateUniversalBoostMode();
 }
 
 template <class HintManagerT>
@@ -302,7 +271,6 @@ void PowerSessionManager<HintManagerT>::resume(int64_t sessionId) {
         sessValPtr->isActive = true;
     }
     applyCpuAndGpuVotes(sessionId, std::chrono::steady_clock::now());
-    updateUniversalBoostMode();
 }
 
 template <class HintManagerT>
@@ -417,22 +385,6 @@ void PowerSessionManager<HintManagerT>::disableBoosts(int64_t sessionId) {
     }
 }
 
-template <class HintManagerT>
-void PowerSessionManager<HintManagerT>::enableSystemTopAppBoost() {
-    if (HintManagerT::GetInstance()->IsHintSupported(kDisableBoostHintName)) {
-        ALOGV("PowerSessionManager::enableSystemTopAppBoost!!");
-        HintManagerT::GetInstance()->EndHint(kDisableBoostHintName);
-    }
-}
-
-template <class HintManagerT>
-void PowerSessionManager<HintManagerT>::disableSystemTopAppBoost() {
-    if (HintManagerT::GetInstance()->IsHintSupported(kDisableBoostHintName)) {
-        ALOGV("PowerSessionManager::disableSystemTopAppBoost!!");
-        HintManagerT::GetInstance()->DoHint(kDisableBoostHintName);
-    }
-}
-
 template <class HintManagerT>
 void PowerSessionManager<HintManagerT>::handleEvent(const EventSessionTimeout &eventTimeout) {
     bool recalcUclamp = false;
@@ -481,7 +433,6 @@ void PowerSessionManager<HintManagerT>::handleEvent(const EventSessionTimeout &e
     // than trying to use the event's timestamp which will be slightly off given
     // the background priority queue introduces latency
     applyCpuAndGpuVotes(eventTimeout.sessionId, tNow);
-    updateUniversalBoostMode();
 }
 
 template <class HintManagerT>
@@ -571,7 +522,6 @@ void PowerSessionManager<HintManagerT>::forceSessionActive(int64_t sessionId, bo
     // that the SessionId remains valid and mapped to the proper threads/tasks
     // which enables apply u clamp to work correctly
     applyCpuAndGpuVotes(sessionId, std::chrono::steady_clock::now());
-    updateUniversalBoostMode();
 }
 
 template <class HintManagerT>
@@ -657,6 +607,106 @@ void PowerSessionManager<HintManagerT>::updateHboostStatistics(int64_t sessionId
     }
 }
 
+template <class HintManagerT>
+std::string PowerSessionManager<HintManagerT>::getSessionTaskProfile(int64_t sessionId,
+                                                                     bool isSetProfile) const {
+    auto sessValPtr = mSessionTaskMap.findSession(sessionId);
+    if (isSetProfile) {
+        if (nullptr == sessValPtr) {
+            return "SCHED_QOS_SENSITIVE_STANDARD";
+        }
+        if (sessValPtr->procTag == ProcessTag::SYSTEM_UI) {
+            return "SCHED_QOS_SENSITIVE_EXTREME";
+        } else {
+            switch (sessValPtr->tag) {
+                case SessionTag::SURFACEFLINGER:
+                case SessionTag::HWUI:
+                    return "SCHED_QOS_SENSITIVE_EXTREME";
+                default:
+                    return "SCHED_QOS_SENSITIVE_STANDARD";
+            }
+        }
+    } else {
+        return "SCHED_QOS_NONE";
+    }
+}
+
+template <class HintManagerT>
+bool PowerSessionManager<HintManagerT>::hasValidTaskRampupMultNode() {
+    return mTaskRampupMultNode->isValid();
+}
+
+template <class HintManagerT>
+void PowerSessionManager<HintManagerT>::voteRampupBoostLocked(int64_t sessionId,
+                                                              bool rampupBoostVote,
+                                                              int32_t defaultRampupVal,
+                                                              int32_t highRampupVal) {
+    auto threadIds = mSessionTaskMap.getTaskIds(sessionId);
+    for (auto tid : threadIds) {
+        auto sessionIds = mSessionTaskMap.getSessionIds(tid);
+        // Check the aggregated rampup boost status for all the other sessions.
+        bool otherSessionsRampupBoost = false;
+        for (auto sess : sessionIds) {
+            if (sess != sessionId && mSessionTaskMap.findSession(sess)->rampupBoostActive) {
+                otherSessionsRampupBoost = true;
+                break;
+            }
+        }
+
+        if (!otherSessionsRampupBoost) {
+            if (rampupBoostVote) {
+                if (!mTaskRampupMultNode->updateTaskRampupMult(tid, highRampupVal)) {
+                    ALOGE("Failed to set high rampup boost value for task %d", tid);
+                }
+            } else {
+                if (!mTaskRampupMultNode->updateTaskRampupMult(tid, defaultRampupVal)) {
+                    ALOGE("Failed to reset to default rampup boost value for task %d", tid);
+                }
+            }
+        }
+    }
+}
+
+template <class HintManagerT>
+void PowerSessionManager<HintManagerT>::updateRampupBoostMode(int64_t sessionId,
+                                                              SessionJankyLevel jankyLevel,
+                                                              int32_t defaultRampupVal,
+                                                              int32_t highRampupVal) {
+    std::lock_guard<std::mutex> lock(mSessionTaskMapMutex);
+    auto sessValPtr = mSessionTaskMap.findSession(sessionId);
+    if (nullptr == sessValPtr) {
+        return;
+    }
+    auto lastRampupBoostActive = sessValPtr->rampupBoostActive;
+    if (!sessValPtr->isActive) {
+        sessValPtr->rampupBoostActive = false;
+    } else {
+        switch (jankyLevel) {
+            case SessionJankyLevel::LIGHT:
+                sessValPtr->rampupBoostActive = false;
+                break;
+            case SessionJankyLevel::MODERATE:
+                sessValPtr->rampupBoostActive = true;
+                break;
+            case SessionJankyLevel::SEVERE:
+                sessValPtr->rampupBoostActive = true;
+                break;
+            default:
+                ALOGW("Unknown janky level during updateHboostStatistics");
+        }
+    }
+
+    if (ATRACE_ENABLED()) {
+        ATRACE_INT(sessValPtr->sessionTrace->trace_rampup_boost_active.c_str(),
+                   sessValPtr->rampupBoostActive);
+    }
+
+    if (sessValPtr->rampupBoostActive != lastRampupBoostActive) {
+        voteRampupBoostLocked(sessionId, sessValPtr->rampupBoostActive, defaultRampupVal,
+                              highRampupVal);
+    }
+}
+
 template class PowerSessionManager<>;
 template class PowerSessionManager<testing::NiceMock<mock::pixel::MockHintManager>>;
 
diff --git a/power-libperfmgr/aidl/PowerSessionManager.h b/power-libperfmgr/aidl/PowerSessionManager.h
index e0d1352a..cc86feeb 100644
--- a/power-libperfmgr/aidl/PowerSessionManager.h
+++ b/power-libperfmgr/aidl/PowerSessionManager.h
@@ -23,11 +23,11 @@
 #include <mutex>
 #include <optional>
 
-#include "AdpfTypes.h"
 #include "AppHintDesc.h"
 #include "BackgroundWorker.h"
 #include "GpuCapacityNode.h"
 #include "SessionTaskMap.h"
+#include "TaskRampupMultNode.h"
 
 namespace aidl {
 namespace google {
@@ -38,8 +38,6 @@ namespace pixel {
 
 using ::android::Thread;
 
-constexpr char kPowerHalAdpfDisableTopAppBoost[] = "vendor.powerhal.adpf.disable.hint";
-
 template <class HintManagerT = ::android::perfmgr::HintManager>
 class PowerSessionManager : public Immobile {
   public:
@@ -51,16 +49,14 @@ class PowerSessionManager : public Immobile {
     void addPowerSession(const std::string &idString,
                          const std::shared_ptr<AppHintDesc> &sessionDescriptor,
                          const std::shared_ptr<AppDescriptorTrace> &sessionTrace,
-                         const std::vector<int32_t> &threadIds, const ProcessTag procTag);
-    void removePowerSession(int64_t sessionId, const ProcessTag procTag);
+                         const std::vector<int32_t> &threadIds);
+    void removePowerSession(int64_t sessionId);
     // Replace current threads in session with threadIds
-    void setThreadsFromPowerSession(int64_t sessionId, const std::vector<int32_t> &threadIds,
-                                    const ProcessTag procTag);
+    void setThreadsFromPowerSession(int64_t sessionId, const std::vector<int32_t> &threadIds);
     // Pause and resume power hint session
     void pause(int64_t sessionId);
     void resume(int64_t sessionId);
 
-    void updateUniversalBoostMode();
     void dumpToFd(int fd);
 
     void updateTargetWorkDuration(int64_t sessionId, AdpfVoteType voteId,
@@ -80,8 +76,10 @@ class PowerSessionManager : public Immobile {
 
     void updateHboostStatistics(int64_t sessionId, SessionJankyLevel jankyLevel,
                                 int32_t numOfFrames);
-
     void updateFrameBuckets(int64_t sessionId, const FrameBuckets &lastReportedFrames);
+    bool hasValidTaskRampupMultNode();
+    void updateRampupBoostMode(int64_t sessionId, SessionJankyLevel jankyLevel,
+                               int32_t defaultRampupVal, int32_t highRampupVal);
 
     // Singleton
     static PowerSessionManager *getInstance() {
@@ -100,8 +98,6 @@ class PowerSessionManager : public Immobile {
 
   private:
     std::optional<bool> isAnyAppSessionActive();
-    void disableSystemTopAppBoost();
-    void enableSystemTopAppBoost();
     const std::string kDisableBoostHintName;
 
     // Rewrite specific
@@ -128,14 +124,16 @@ class PowerSessionManager : public Immobile {
     void applyCpuAndGpuVotes(int64_t sessionId, std::chrono::steady_clock::time_point timePoint);
     // Force a session active or in-active, helper for other methods
     void forceSessionActive(int64_t sessionId, bool isActive);
+    std::string getSessionTaskProfile(int64_t sessionId, bool isSetProfile) const;
+    void voteRampupBoostLocked(int64_t sessionId, bool rampupBoostVote, int32_t defaultRampupVal,
+                               int32_t highRampupVal);
 
     // Singleton
     PowerSessionManager()
-        : kDisableBoostHintName(::android::base::GetProperty(kPowerHalAdpfDisableTopAppBoost,
-                                                             "ADPF_DISABLE_TA_BOOST")),
-          mPriorityQueueWorkerPool(new PriorityQueueWorkerPool(1, "adpf_handler")),
+        : mPriorityQueueWorkerPool(new PriorityQueueWorkerPool(1, "adpf_handler")),
           mEventSessionTimeoutWorker([&](auto e) { handleEvent(e); }, mPriorityQueueWorkerPool),
-          mGpuCapacityNode(createGpuCapacityNode()) {}
+          mGpuCapacityNode(createGpuCapacityNode()),
+          mTaskRampupMultNode(TaskRampupMultNode::getInstance()) {}
     PowerSessionManager(PowerSessionManager const &) = delete;
     PowerSessionManager &operator=(PowerSessionManager const &) = delete;
 
@@ -145,6 +143,7 @@ class PowerSessionManager : public Immobile {
     std::unordered_map<int, std::weak_ptr<void>> mSessionMap GUARDED_BY(mSessionMapMutex);
 
     std::atomic<bool> mGameModeEnabled{false};
+    std::shared_ptr<TaskRampupMultNode> mTaskRampupMultNode;
 };
 
 }  // namespace pixel
diff --git a/power-libperfmgr/aidl/SessionMetrics.h b/power-libperfmgr/aidl/SessionMetrics.h
index 6ae600f0..ad13b4ef 100644
--- a/power-libperfmgr/aidl/SessionMetrics.h
+++ b/power-libperfmgr/aidl/SessionMetrics.h
@@ -80,6 +80,39 @@ struct FrameBuckets {
     }
 };
 
+enum class ScenarioType : int32_t { DEFAULT = 0, GAME };
+
+constexpr const char *toString(ScenarioType scenType) {
+    switch (scenType) {
+        case ScenarioType::DEFAULT:
+            return "DEFAULT";
+        case ScenarioType::GAME:
+            return "GAME";
+        default:
+            return "INVALID_SCENARIO_TYPE";
+    }
+}
+
+enum class FrameTimelineType : int32_t { SURFACEFLINGER = 0, APP };
+
+constexpr const char *toString(FrameTimelineType timelineType) {
+    switch (timelineType) {
+        case FrameTimelineType::APP:
+            return "APP";
+        case FrameTimelineType::SURFACEFLINGER:
+            return "SURFACEFLINGER";
+        default:
+            return "INVALID_FRAME_TIMELINE_TYPE";
+    }
+}
+
+struct SessionJankStatsWithThermal {
+    std::optional<int32_t> uid;
+    ScenarioType scenarioType;
+    FrameTimelineType frameTimelineType;
+    // TODO(guibing) add more detailed definition of the jank metrics.
+};
+
 }  // namespace pixel
 }  // namespace impl
 }  // namespace power
diff --git a/power-libperfmgr/aidl/SessionValueEntry.cpp b/power-libperfmgr/aidl/SessionValueEntry.cpp
index 30b1ee0b..4e2649f9 100644
--- a/power-libperfmgr/aidl/SessionValueEntry.cpp
+++ b/power-libperfmgr/aidl/SessionValueEntry.cpp
@@ -47,6 +47,8 @@ std::ostream &SessionValueEntry::dump(std::ostream &os) const {
        << (totalFrames <= 0 ? 0 : (hBoostModeDist.severeModeFrames * 10000 / totalFrames / 100.0))
        << "%-" << totalFrames << ", ";
     os << sessFrameBuckets.toString() << ", ";
+    os << "Ramup boost active: " << rampupBoostActive << ", ";
+
     return os;
 }
 
diff --git a/power-libperfmgr/aidl/SessionValueEntry.h b/power-libperfmgr/aidl/SessionValueEntry.h
index 90392aaa..1c449088 100644
--- a/power-libperfmgr/aidl/SessionValueEntry.h
+++ b/power-libperfmgr/aidl/SessionValueEntry.h
@@ -18,6 +18,7 @@
 
 #include <ostream>
 
+#include "AdpfTypes.h"
 #include "AppDescriptorTrace.h"
 #include "SessionRecords.h"
 #include "UClampVoter.h"
@@ -48,12 +49,15 @@ struct SessionValueEntry {
     std::string idString;
     bool isActive{true};
     bool isAppSession{false};
+    android::hardware::power::SessionTag tag;
+    ProcessTag procTag;
     std::chrono::steady_clock::time_point lastUpdatedTime;
     std::shared_ptr<Votes> votes;
     std::shared_ptr<AppDescriptorTrace> sessionTrace;
     FrameBuckets sessFrameBuckets;
     bool isPowerEfficient{false};
     HeurBoostStatistics hBoostModeDist;
+    bool rampupBoostActive{false};
 
     // Write info about power session to ostream for logging and debugging
     std::ostream &dump(std::ostream &os) const;
diff --git a/power-libperfmgr/aidl/TaskRampupMultNode.cpp b/power-libperfmgr/aidl/TaskRampupMultNode.cpp
new file mode 100644
index 00000000..79e05124
--- /dev/null
+++ b/power-libperfmgr/aidl/TaskRampupMultNode.cpp
@@ -0,0 +1,78 @@
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
+#include "TaskRampupMultNode.h"
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
+static constexpr char taskRampupSetPath[] = "/proc/vendor_sched/sched_qos/rampup_multiplier_set";
+
+TaskRampupMultNode::TaskRampupMultNode() {
+    if (access(taskRampupSetPath, W_OK) != 0) {
+        mTaskRampupFd = -1;
+        LOG(WARNING) << "Can't find vendor node: " << taskRampupSetPath;
+        return;
+    }
+
+    int flags = O_WRONLY | O_TRUNC | O_CLOEXEC;
+    mTaskRampupFd = TEMP_FAILURE_RETRY(open(taskRampupSetPath, flags));
+    if (mTaskRampupFd < 0) {
+        LOG(ERROR) << "Failed to open the node: " << taskRampupSetPath;
+    }
+}
+
+TaskRampupMultNode::~TaskRampupMultNode() {
+    if (mTaskRampupFd >= 0) {
+        ::close(mTaskRampupFd);
+    }
+}
+
+bool TaskRampupMultNode::updateTaskRampupMult(int32_t tid, int32_t val) {
+    std::lock_guard lock(mMutex);
+    if (mTaskRampupFd < 0) {
+        LOG(WARNING) << "Invalid task tampup multiplier file descriptor, skipping the update";
+        return false;
+    }
+
+    // Prepare the tid and value pair in the required format for the vendor procfs node.
+    std::string tidValPair = std::to_string(tid) + ":" + std::to_string(val);
+    if (!::android::base::WriteStringToFd(tidValPair, mTaskRampupFd)) {
+        LOG(ERROR) << "Failed to write the new value " << tidValPair
+                   << " to task rampup multiplier node.";
+        return false;
+    }
+    return true;
+}
+
+bool TaskRampupMultNode::isValid() const {
+    return mTaskRampupFd >= 0;
+}
+
+}  // namespace pixel
+}  // namespace impl
+}  // namespace power
+}  // namespace hardware
+}  // namespace google
+}  // namespace aidl
diff --git a/power-libperfmgr/aidl/TaskRampupMultNode.h b/power-libperfmgr/aidl/TaskRampupMultNode.h
new file mode 100644
index 00000000..9015c717
--- /dev/null
+++ b/power-libperfmgr/aidl/TaskRampupMultNode.h
@@ -0,0 +1,59 @@
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
+namespace aidl {
+namespace google {
+namespace hardware {
+namespace power {
+namespace impl {
+namespace pixel {
+
+class TaskRampupMultNode {
+  public:
+    static std::shared_ptr<TaskRampupMultNode> getInstance() {
+        static std::shared_ptr<TaskRampupMultNode> instance(new TaskRampupMultNode());
+        return instance;
+    }
+
+    bool updateTaskRampupMult(int32_t tid, int32_t val);
+    bool isValid() const;
+
+    ~TaskRampupMultNode();
+
+  private:
+    // singleton
+    TaskRampupMultNode();
+    TaskRampupMultNode(TaskRampupMultNode const &) = delete;
+    TaskRampupMultNode &operator=(TaskRampupMultNode const &) = delete;
+
+    std::mutex mMutex;
+    int mTaskRampupFd = -1;
+};
+
+}  // namespace pixel
+}  // namespace impl
+}  // namespace power
+}  // namespace hardware
+}  // namespace google
+}  // namespace aidl
diff --git a/power-libperfmgr/aidl/service.cpp b/power-libperfmgr/aidl/service.cpp
index f1e94c06..4fe410eb 100644
--- a/power-libperfmgr/aidl/service.cpp
+++ b/power-libperfmgr/aidl/service.cpp
@@ -25,14 +25,18 @@
 
 #include <thread>
 
+#include "MetricUploader.h"
 #include "Power.h"
 #include "PowerExt.h"
 #include "PowerSessionManager.h"
 #include "disp-power/DisplayLowPower.h"
+#include "utils/ThermalStateListener.h"
 
 using aidl::google::hardware::power::impl::pixel::DisplayLowPower;
+using aidl::google::hardware::power::impl::pixel::MetricUploader;
 using aidl::google::hardware::power::impl::pixel::Power;
 using aidl::google::hardware::power::impl::pixel::PowerExt;
+using aidl::google::hardware::power::impl::pixel::ThermalStateListener;
 using ::android::perfmgr::HintManager;
 
 constexpr std::string_view kPowerHalInitProp("vendor.powerhal.init");
@@ -73,6 +77,8 @@ int main() {
         ::android::base::WaitForProperty(kPowerHalInitProp.data(), "1");
         HintManager::GetInstance()->Start();
         dlpw->Init();
+        MetricUploader::getInstance()->init();
+        ThermalStateListener::getInstance()->init();
     });
     initThread.detach();
 
diff --git a/power-libperfmgr/aidl/tests/TestHelper.cpp b/power-libperfmgr/aidl/tests/TestHelper.cpp
index b07b94db..9db9e923 100644
--- a/power-libperfmgr/aidl/tests/TestHelper.cpp
+++ b/power-libperfmgr/aidl/tests/TestHelper.cpp
@@ -53,6 +53,9 @@ namespace aidl::google::hardware::power::impl::pixel {
             1.2,                      /* JankCheckTimeFactor */
             25,                       /* LowFrameRateThreshold */
             300,                      /* MaxRecordsNum */
+            true,                     /* HeuristicRampup */
+            1,                        /* DefaultRampupMult */
+            4,                        /* HighRampupMult */
             480,                      /* UclampMin_LoadUp */
             480,                      /* UclampMin_LoadReset */
             500,                      /* UclampMax_EfficientBase */
diff --git a/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h b/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
index 5b0bf545..7b19c1ec 100644
--- a/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
+++ b/power-libperfmgr/aidl/tests/mocks/MockPowerSessionManager.h
@@ -37,17 +37,13 @@ class MockPowerSessionManager {
                 (const std::string &idString,
                  const std::shared_ptr<impl::pixel::AppHintDesc> &sessionDescriptor,
                  const std::shared_ptr<impl::pixel::AppDescriptorTrace> &sessionTrace,
-                 const std::vector<int32_t> &threadIds, const impl::pixel::ProcessTag procTag),
+                 const std::vector<int32_t> &threadIds),
                 ());
-    MOCK_METHOD(void, removePowerSession,
-                (int64_t sessionId, const impl::pixel::ProcessTag procTag), ());
+    MOCK_METHOD(void, removePowerSession, (int64_t sessionId), ());
     MOCK_METHOD(void, setThreadsFromPowerSession,
-                (int64_t sessionId, const std::vector<int32_t> &threadIds,
-                 const impl::pixel::ProcessTag procTag),
-                ());
+                (int64_t sessionId, const std::vector<int32_t> &threadIds), ());
     MOCK_METHOD(void, pause, (int64_t sessionId), ());
     MOCK_METHOD(void, resume, (int64_t sessionId), ());
-    MOCK_METHOD(void, updateUniversalBoostMode, (), ());
     MOCK_METHOD(void, dumpToFd, (int fd), ());
     MOCK_METHOD(void, updateTargetWorkDuration,
                 (int64_t sessionId, impl::pixel::AdpfVoteType voteId,
@@ -76,8 +72,13 @@ class MockPowerSessionManager {
                 (int64_t sessionId, impl::pixel::SessionJankyLevel jankyLevel, int32_t numOfFrames),
                 ());
     MOCK_METHOD(bool, getGameModeEnableState, (), ());
+    MOCK_METHOD(bool, hasValidTaskRampupMultNode, (), ());
     MOCK_METHOD(void, updateFrameBuckets,
                 (int64_t sessionId, const impl::pixel::FrameBuckets &lastReportedFrames), ());
+    MOCK_METHOD(void, updateRampupBoostMode,
+                (int64_t sessionId, impl::pixel::SessionJankyLevel jankyLevel,
+                 int32_t defaultRampupVal, int32_t highRampupVal),
+                ());
 
     static testing::NiceMock<MockPowerSessionManager> *getInstance() {
         static testing::NiceMock<MockPowerSessionManager> instance{};
diff --git a/power-libperfmgr/aidl/utils/ThermalStateListener.cpp b/power-libperfmgr/aidl/utils/ThermalStateListener.cpp
new file mode 100644
index 00000000..94647f77
--- /dev/null
+++ b/power-libperfmgr/aidl/utils/ThermalStateListener.cpp
@@ -0,0 +1,101 @@
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
+#include "ThermalStateListener.h"
+
+#include <android-base/logging.h>
+#include <android/binder_manager.h>
+
+namespace aidl {
+namespace google {
+namespace hardware {
+namespace power {
+namespace impl {
+namespace pixel {
+
+bool ThermalStateListener::connectThermalHal() {
+    const std::string thermalServiceName = std::string(IThermal::descriptor) + "/default";
+
+    if (!AServiceManager_isDeclared(thermalServiceName.c_str())) {
+        LOG(ERROR) << "Thermal HAL service not declared";
+        return false;
+    }
+
+    ndk::SpAIBinder thermalHalBinder =
+            ndk::SpAIBinder(AServiceManager_waitForService(thermalServiceName.c_str()));
+
+    if (thermalHalBinder.get() == nullptr) {
+        LOG(ERROR) << "Cannot get Thermal Hal binder!";
+        return false;
+    }
+
+    mThermalAIDL = IThermal::fromBinder(thermalHalBinder);
+    if (mThermalAIDL == nullptr) {
+        LOG(ERROR) << "Cannot get Thermal Hal AIDL!";
+        return false;
+    }
+
+    LOG(INFO) << "Connected to Thermalhal.";
+    return true;
+}
+
+void ThermalStateListener::thermalCallback(const Temperature &temp) {
+    if (temp.type == TemperatureType::SKIN) {
+        LOG(INFO) << "New skin throttling state: "
+                  << ::android::internal::ToString(temp.throttlingStatus);
+        mThermalThrotSev = temp.throttlingStatus;
+    }
+}
+
+bool ThermalStateListener::registerCallback() {
+    if (mThermalAIDL == nullptr) {
+        LOG(ERROR) << "Thermal Hal AIDL not connected!";
+        return false;
+    }
+
+    if (mThermalCallback == nullptr) {
+        mThermalCallback = ndk::SharedRefBase::make<ThermalCallback>(
+                [this](const Temperature &temperature) { thermalCallback(temperature); });
+    }
+
+    auto ret = mThermalAIDL->registerThermalChangedCallback(mThermalCallback);
+    if (!ret.isOk()) {
+        LOG(ERROR) << "Failed to register the Powerhal's thermal callback: " << ret.getMessage();
+        return false;
+    }
+    // TODO(guibing): handling the death connection
+    LOG(INFO) << "Registered the thermal callback.";
+    return true;
+}
+
+bool ThermalStateListener::init() {
+    if (connectThermalHal() && registerCallback()) {
+        return true;
+    }
+    LOG(ERROR) << "Failed to initialize the thermal state listener!";
+    return false;
+}
+
+ThrottlingSeverity ThermalStateListener::getThermalThrotSev() {
+    return mThermalThrotSev.load();
+}
+
+}  // namespace pixel
+}  // namespace impl
+}  // namespace power
+}  // namespace hardware
+}  // namespace google
+}  // namespace aidl
diff --git a/power-libperfmgr/aidl/utils/ThermalStateListener.h b/power-libperfmgr/aidl/utils/ThermalStateListener.h
new file mode 100644
index 00000000..e75935f1
--- /dev/null
+++ b/power-libperfmgr/aidl/utils/ThermalStateListener.h
@@ -0,0 +1,85 @@
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
+#include <aidl/android/hardware/thermal/BnThermalChangedCallback.h>
+#include <aidl/android/hardware/thermal/IThermal.h>
+
+namespace aidl {
+namespace google {
+namespace hardware {
+namespace power {
+namespace impl {
+namespace pixel {
+
+using ::aidl::android::hardware::thermal::BnThermalChangedCallback;
+using ::aidl::android::hardware::thermal::IThermal;
+using ::aidl::android::hardware::thermal::Temperature;
+using ::aidl::android::hardware::thermal::TemperatureType;
+using ::aidl::android::hardware::thermal::ThrottlingSeverity;
+
+/**
+ * Listen to the device thermal throttling status, so it could be used to
+ * aggregate the performance metrics with the thermal states.
+ */
+class ThermalStateListener {
+  public:
+    ~ThermalStateListener() = default;
+    ThermalStateListener(ThermalStateListener const &) = delete;
+    ThermalStateListener(ThermalStateListener &&) = delete;
+    ThermalStateListener &operator=(ThermalStateListener const &) = delete;
+    ThermalStateListener &operator=(ThermalStateListener &&) = delete;
+
+    bool init();
+    ThrottlingSeverity getThermalThrotSev();
+
+    // Singleton
+    static ThermalStateListener *getInstance() {
+        static ThermalStateListener instance{};
+        return &instance;
+    }
+
+  private:
+    ThermalStateListener() = default;
+    bool connectThermalHal();
+    bool registerCallback();
+    void thermalCallback(const Temperature &temp);
+
+    class ThermalCallback : public BnThermalChangedCallback {
+      public:
+        ThermalCallback(std::function<void(const Temperature &)> notify_function)
+            : mNotifyFunction(notify_function) {}
+
+        ndk::ScopedAStatus notifyThrottling(const Temperature &temperature) override {
+            mNotifyFunction(temperature);
+            return ndk::ScopedAStatus::ok();
+        }
+
+      private:
+        std::function<void(const Temperature &)> mNotifyFunction;
+    };
+
+    std::shared_ptr<IThermal> mThermalAIDL;
+    std::shared_ptr<ThermalCallback> mThermalCallback;
+    std::atomic<ThrottlingSeverity> mThermalThrotSev{ThrottlingSeverity::NONE};
+};
+
+}  // namespace pixel
+}  // namespace impl
+}  // namespace power
+}  // namespace hardware
+}  // namespace google
+}  // namespace aidl
diff --git a/power-libperfmgr/libperfmgr/AdpfConfig.cc b/power-libperfmgr/libperfmgr/AdpfConfig.cc
index b04100fa..7a47562c 100644
--- a/power-libperfmgr/libperfmgr/AdpfConfig.cc
+++ b/power-libperfmgr/libperfmgr/AdpfConfig.cc
@@ -77,6 +77,11 @@ void AdpfConfig::dumpToFd(int fd) {
         dump_buf << "JankCheckTimeFactor: " << mJankCheckTimeFactor.value() << "\n";
         dump_buf << "LowFrameRateThreshold: " << mLowFrameRateThreshold.value() << "\n";
         dump_buf << "MaxRecordsNum: " << mMaxRecordsNum.value() << "\n";
+        if (mHeuristicRampup.has_value()) {
+            dump_buf << "HeuristicRampup: " << mHeuristicRampup.value() << "\n";
+            dump_buf << "DefaultRampupMult: " << mDefaultRampupMult.value() << "\n";
+            dump_buf << "HighRampupMult: " << mHighRampupMult.value() << "\n";
+        }
     }
     if (mUclampMaxEfficientBase.has_value()) {
         dump_buf << "UclampMax_EfficientBase: " << *mUclampMaxEfficientBase << "\n";
diff --git a/power-libperfmgr/libperfmgr/HintManager.cc b/power-libperfmgr/libperfmgr/HintManager.cc
index 1b20e718..e22087ea 100644
--- a/power-libperfmgr/libperfmgr/HintManager.cc
+++ b/power-libperfmgr/libperfmgr/HintManager.cc
@@ -104,6 +104,9 @@ void HintManager::DoHintStatus(const std::string &hint_type, std::chrono::millis
     ATRACE_INT(("H:" + hint_type).c_str(), (timeout_ms == kMilliSecondZero)
                                                    ? std::numeric_limits<int>::max()
                                                    : timeout_ms.count());
+    ATRACE_NAME(("H:" + hint_type + ":" + std::to_string((timeout_ms == kMilliSecondZero)
+                                                   ? std::numeric_limits<int>::max()
+                                                   : timeout_ms.count())).c_str());
     if (now > actions_.at(hint_type).status->end_time) {
         actions_.at(hint_type).status->stats.duration_ms.fetch_add(
                 std::chrono::duration_cast<std::chrono::milliseconds>(
@@ -121,6 +124,7 @@ void HintManager::EndHintStatus(const std::string &hint_type) {
     // Update HintStats if the hint ends earlier than expected end_time
     auto now = std::chrono::steady_clock::now();
     ATRACE_INT(("H:" + hint_type).c_str(), 0);
+    ATRACE_NAME(("H:" + hint_type + ":0").c_str());
     if (now < actions_.at(hint_type).status->end_time) {
         actions_.at(hint_type).status->stats.duration_ms.fetch_add(
                 std::chrono::duration_cast<std::chrono::milliseconds>(
@@ -804,6 +808,9 @@ std::vector<std::shared_ptr<AdpfConfig>> HintManager::ParseAdpfConfigs(
         std::optional<double> jankCheckTimeFactor;
         std::optional<uint32_t> lowFrameRateThreshold;
         std::optional<uint32_t> maxRecordsNum;
+        std::optional<bool> heuristicRampup;
+        std::optional<uint32_t> defaultRampupMult;
+        std::optional<uint32_t> highRampupMult;
 
         std::optional<uint32_t> uclampMinLoadUp;
         std::optional<uint32_t> uclampMinLoadReset;
@@ -839,6 +846,9 @@ std::vector<std::shared_ptr<AdpfConfig>> HintManager::ParseAdpfConfigs(
         ADPF_PARSE_OPTIONAL(jankCheckTimeFactor, "JankCheckTimeFactor", Double);
         ADPF_PARSE_OPTIONAL(lowFrameRateThreshold, "LowFrameRateThreshold", UInt);
         ADPF_PARSE_OPTIONAL(maxRecordsNum, "MaxRecordsNum", UInt);
+        ADPF_PARSE_OPTIONAL(heuristicRampup, "HeuristicRampup", Bool);
+        ADPF_PARSE_OPTIONAL(defaultRampupMult, "DefaultRampupMult", UInt);
+        ADPF_PARSE_OPTIONAL(highRampupMult, "HighRampupMult", UInt);
         ADPF_PARSE_OPTIONAL(uclampMaxEfficientBase, "UclampMax_EfficientBase", Int);
         ADPF_PARSE_OPTIONAL(uclampMaxEfficientOffset, "UclampMax_EfficientOffset", Int);
 
@@ -882,6 +892,14 @@ std::vector<std::shared_ptr<AdpfConfig>> HintManager::ParseAdpfConfigs(
                 adpfs_parsed.clear();
                 return adpfs_parsed;
             }
+
+            // check heuristic rampup configurations.
+            if (heuristicRampup.has_value() &&
+                (!defaultRampupMult.has_value() || !highRampupMult.has_value())) {
+                LOG(ERROR) << "Part of the heuristic rampup configurations are missing!";
+                adpfs_parsed.clear();
+                return adpfs_parsed;
+            }
         }
 
         if (uclampMaxEfficientBase.has_value() != uclampMaxEfficientBase.has_value()) {
@@ -905,8 +923,9 @@ std::vector<std::shared_ptr<AdpfConfig>> HintManager::ParseAdpfConfigs(
                 gpuCapacityLoadUpHeadroom, heuristicBoostOn, hBoostModerateJankThreshold,
                 hBoostOffMaxAvgDurRatio, hBoostSevereJankPidPu, hBoostSevereJankThreshold,
                 hBoostUclampMinCeilingRange, hBoostUclampMinFloorRange, jankCheckTimeFactor,
-                lowFrameRateThreshold, maxRecordsNum, uclampMinLoadUp.value(),
-                uclampMinLoadReset.value(), uclampMaxEfficientBase, uclampMaxEfficientOffset));
+                lowFrameRateThreshold, maxRecordsNum, heuristicRampup, defaultRampupMult,
+                highRampupMult, uclampMinLoadUp.value(), uclampMinLoadReset.value(),
+                uclampMaxEfficientBase, uclampMaxEfficientOffset));
     }
     LOG(INFO) << adpfs_parsed.size() << " AdpfConfigs parsed successfully";
     return adpfs_parsed;
diff --git a/power-libperfmgr/libperfmgr/include/perfmgr/AdpfConfig.h b/power-libperfmgr/libperfmgr/include/perfmgr/AdpfConfig.h
index f4491abe..b8212d0d 100644
--- a/power-libperfmgr/libperfmgr/include/perfmgr/AdpfConfig.h
+++ b/power-libperfmgr/libperfmgr/include/perfmgr/AdpfConfig.h
@@ -64,6 +64,11 @@ struct AdpfConfig {
     std::optional<uint32_t> mLowFrameRateThreshold;
     std::optional<uint32_t> mMaxRecordsNum;
 
+    // Rampup boost control
+    std::optional<bool> mHeuristicRampup;
+    std::optional<uint32_t> mDefaultRampupMult;
+    std::optional<uint32_t> mHighRampupMult;
+
     uint32_t mUclampMinLoadUp;
     uint32_t mUclampMinLoadReset;
 
@@ -92,8 +97,9 @@ struct AdpfConfig {
                std::optional<std::pair<uint32_t, uint32_t>> hBoostUclampMinFloorRange,
                std::optional<double> jankCheckTimeFactor,
                std::optional<uint32_t> lowFrameRateThreshold, std::optional<uint32_t> maxRecordsNum,
-               uint32_t uclampMinLoadUp, uint32_t uclampMinLoadReset,
-               std::optional<int32_t> uclampMaxEfficientBase,
+               std::optional<bool> heuristicRampup, std::optional<uint32_t> defaultRampupMult,
+               std::optional<uint32_t> highRampupMult, uint32_t uclampMinLoadUp,
+               uint32_t uclampMinLoadReset, std::optional<int32_t> uclampMaxEfficientBase,
                std::optional<int32_t> uclampMaxEfficientOffset)
         : mName(std::move(name)),
           mPidOn(pidOn),
@@ -128,6 +134,9 @@ struct AdpfConfig {
           mJankCheckTimeFactor(jankCheckTimeFactor),
           mLowFrameRateThreshold(lowFrameRateThreshold),
           mMaxRecordsNum(maxRecordsNum),
+          mHeuristicRampup(heuristicRampup),
+          mDefaultRampupMult(defaultRampupMult),
+          mHighRampupMult(highRampupMult),
           mUclampMinLoadUp(uclampMinLoadUp),
           mUclampMinLoadReset(uclampMinLoadReset),
           mUclampMaxEfficientBase(uclampMaxEfficientBase),
diff --git a/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc b/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc
index a3b8ca58..b413f977 100644
--- a/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc
+++ b/power-libperfmgr/libperfmgr/tests/HintManagerTest.cc
@@ -223,7 +223,10 @@ constexpr char kJSON_ADPF[] = R"(
             "HBoostUclampMinFloorRange": [200, 400],
             "JankCheckTimeFactor": 1.2,
             "LowFrameRateThreshold": 25,
-            "MaxRecordsNum": 50
+            "MaxRecordsNum": 50,
+            "HeuristicRampup": true,
+            "DefaultRampupMult": 1,
+            "HighRampupMult": 4
         },
         {
             "Name": "ADPF_SF",
@@ -273,7 +276,17 @@ constexpr char kJSON_ADPF[] = R"(
             "TargetTimeFactor": 1.4,
             "StaleTimeFactor": 5.0,
             "GpuBoost": false,
-            "GpuCapacityBoostMax": 32500
+            "GpuCapacityBoostMax": 32500,
+            "HeuristicBoost_On": true,
+            "HBoostModerateJankThreshold": 4,
+            "HBoostOffMaxAvgDurRatio": 4.0,
+            "HBoostSevereJankPidPu": 0.5,
+            "HBoostSevereJankThreshold": 2,
+            "HBoostUclampMinCeilingRange": [480, 800],
+            "HBoostUclampMinFloorRange": [200, 400],
+            "JankCheckTimeFactor": 1.2,
+            "LowFrameRateThreshold": 25,
+            "MaxRecordsNum": 50
         }
     ],
     "GpuSysfsPath" : "/sys/devices/platform/123.abc"
@@ -907,6 +920,12 @@ TEST_F(HintManagerTest, ParseAdpfConfigsTest) {
     EXPECT_FALSE(adpfs[1]->mLowFrameRateThreshold.has_value());
     EXPECT_EQ(50U, adpfs[0]->mMaxRecordsNum.value());
     EXPECT_FALSE(adpfs[1]->mMaxRecordsNum.has_value());
+    EXPECT_TRUE(adpfs[0]->mHeuristicRampup.value());
+    EXPECT_FALSE(adpfs[1]->mHeuristicRampup.has_value());
+    EXPECT_EQ(1U, adpfs[0]->mDefaultRampupMult.value());
+    EXPECT_FALSE(adpfs[1]->mDefaultRampupMult.has_value());
+    EXPECT_EQ(4U, adpfs[0]->mHighRampupMult.value());
+    EXPECT_FALSE(adpfs[1]->mHighRampupMult.has_value());
 }
 
 // Test parsing adpf configs with duplicate name
@@ -939,6 +958,16 @@ TEST_F(HintManagerTest, ParseAdpfConfigsWithBrokenHBoostConfig) {
     EXPECT_EQ(0u, adpfs.size());
 }
 
+// Test parsing adpf configs with partially missing heuristic rampup config
+TEST_F(HintManagerTest, ParseAdpfConfigsWithBrokenRampupBoostConfig) {
+    std::string json_doc = std::string(kJSON_ADPF);
+    std::string from = "\"DefaultRampupMult\": 1";
+    size_t start_pos = json_doc.find(from);
+    json_doc.replace(start_pos, from.length(), "");
+    std::vector<std::shared_ptr<AdpfConfig>> adpfs = HintManager::ParseAdpfConfigs(json_doc);
+    EXPECT_EQ(0u, adpfs.size());
+}
+
 // Test hint/cancel/expire with json config
 TEST_F(HintManagerTest, GetFromJSONAdpfConfigTest) {
     TemporaryFile json_file;
diff --git a/preupload_hooks/pixel_json_checker/pixel_config_checker.py b/preupload_hooks/pixel_json_checker/pixel_config_checker.py
index e4773e2e..1e3cbc35 100644
--- a/preupload_hooks/pixel_json_checker/pixel_config_checker.py
+++ b/preupload_hooks/pixel_json_checker/pixel_config_checker.py
@@ -34,7 +34,7 @@ class PixelJSONFieldNameChecker(object):
     Typical usage example:
 
     foo = PixelFieldNameChecker(files, vocabulary_path)
-    success, error = foo.check_json_spelling()
+    success, error = foo.check_json_field_names()
   """
   valid_field_names = None
   json_files = None
diff --git a/preupload_hooks/pixel_json_checker/powerhint_config_checker.py b/preupload_hooks/pixel_json_checker/powerhint_config_checker.py
index e2a08d3f..5f1ef5db 100755
--- a/preupload_hooks/pixel_json_checker/powerhint_config_checker.py
+++ b/preupload_hooks/pixel_json_checker/powerhint_config_checker.py
@@ -33,6 +33,53 @@ import gitlint.git as git
 
 from pixel_config_checker import PixelJSONFieldNameChecker
 
+def powerhint_check_actions_and_nodes(powerhint_json_files):
+  """Preupload check for powerhint actions and nodes.
+
+    This function checks that all powerhint actions on nodes
+    and other actions (DoHint, EndHint, etc..) are valid and
+    nodes exist. It also validates that values specified in
+    actions are supported values in nodes. It also checks if
+    nodes are double declared.
+
+    Args: Map of powerhint json file names to actions.
+
+    Returns:
+        Status, Error Message.
+  """
+
+  for file_path, powerhint in powerhint_json_files.items():
+    nodes_dict = dict()
+    action_names = set()
+
+    # Create reference Nodes and Actions
+    for node in powerhint["Nodes"]:
+      if node["Name"] in nodes_dict:
+        return False, file_path + ": repeated node " + node["Name"]
+      nodes_dict[node["Name"]] = node["Values"]
+
+    for action in powerhint["Actions"]:
+      action_names.add(action["PowerHint"])
+
+    for action in powerhint["Actions"]:
+      if "Type" in action:
+        if action["Value"] not in action_names:
+          return False, file_path + ": Action " + action["PowerHint"] + \
+            ": unknown Hint " + action["Value"]
+
+      if "Node" in action:
+        if action["Node"] not in nodes_dict.keys():
+          return False, file_path + ": Action " + action["PowerHint"] + \
+            ": unknown Node " + action["Node"]
+
+        if action["Value"] not in nodes_dict[action["Node"]]:
+          return False, file_path + ": Action " + action["PowerHint"] + \
+            ": Node " + action["Node"] + " unknown value " + action["Value"]
+
+  return True, ""  # Return True if all actions are valid
+
+
+
 def get_powerhint_modified_files(commit):
   """Getter for finding which powerhint json files were modified
     in the commit.
@@ -99,6 +146,10 @@ def main(args=None):
   if not success:
     return "powerhint JSON field name check error: " + message
 
+  success, message = powerhint_check_actions_and_nodes(json_files)
+  if not success:
+    return "powerhint JSON field name check error: " + message
+
 if __name__ == '__main__':
   ret = main()
   if ret:
diff --git a/preupload_hooks/pixel_json_checker/thermal_config_checker.py b/preupload_hooks/pixel_json_checker/thermal_config_checker.py
index caac9b65..7af2f46d 100755
--- a/preupload_hooks/pixel_json_checker/thermal_config_checker.py
+++ b/preupload_hooks/pixel_json_checker/thermal_config_checker.py
@@ -49,6 +49,63 @@ def get_thermal_modified_files(commit):
 
   return modified_files
 
+def validate_sensor_config(sensors):
+  """Validates configuration fields sensors in thermal config
+
+    Args: Json object for sensors
+
+    Returns:
+      Tuple of Success and error message.
+  """
+  for sensor in sensors:
+    sensor_name = sensor["Name"]
+    combination_size = 0
+    coefficients_size = 0
+    combination_type_size = 0
+    coefficients_type_size = 0
+    message = sensor_name + ": "
+
+    if "Combination" in sensor.keys():
+      combination_size = len(sensor["Combination"])
+
+    if "Coefficient" in sensor.keys():
+      coefficients_size = len(sensor["Coefficient"])
+
+      if combination_size != coefficients_size:
+        message += "Combination size does not match with Coefficient size"
+        return False, message
+
+    if "CombinationType" in sensor.keys():
+      combination_type_size = len(sensor["CombinationType"])
+
+      if combination_size != combination_type_size:
+        message += "Combination size does not match with CombinationType size"
+        return False, message
+
+    if "CoefficientType" in sensor.keys():
+      coefficients_type_size = len(sensor["CoefficientType"])
+
+      if coefficients_size != coefficients_type_size:
+        message += "Coefficient size does not match with CoefficientType size"
+        return False, message
+
+  return True, None
+
+def check_thermal_config(file_path, json_file):
+  """Validates configuration fields in thermal config
+
+    Args: Json object for thermal config
+
+    Returns:
+      Tuple of Success and error message.
+  """
+  if "Sensors" in json_file.keys():
+    status, message = validate_sensor_config(json_file["Sensors"])
+    if not status:
+      return False, file_path + ": " + message
+
+  return True, None
+
 def main(args=None):
   """Main function for checking thermal configs.
 
@@ -90,6 +147,9 @@ def main(args=None):
     try:
         json_file = json.loads(content)
         json_files[rel_path] = json_file
+        success, message = check_thermal_config(rel_path, json_file)
+        if not success:
+          return "Thermal config check error: " + message
     except ValueError as e:
       return "Malformed JSON file " + rel_path + " with message "+ str(e)
 
diff --git a/pwrstats_util/OWNERS b/pwrstats_util/OWNERS
index b290b496..90c683c3 100644
--- a/pwrstats_util/OWNERS
+++ b/pwrstats_util/OWNERS
@@ -1,3 +1,2 @@
 bsschwar@google.com
 krossmo@google.com
-tstrudel@google.com
diff --git a/recovery/Android.bp b/recovery/Android.bp
index cd3526b2..d752ee50 100644
--- a/recovery/Android.bp
+++ b/recovery/Android.bp
@@ -9,7 +9,6 @@ cc_library_static {
         "-Wall",
         "-Wextra",
         "-Werror",
-        "-pedantic",
     ],
     srcs: [
         "recovery_ui.cpp",
@@ -35,7 +34,6 @@ cc_library_static {
         "-Wall",
         "-Wextra",
         "-Werror",
-        "-pedantic",
     ],
     srcs: [
         "recovery_watch_ui.cpp",
diff --git a/thermal/pixel-thermal-logd.rc b/thermal/pixel-thermal-logd.rc
index c2ec9ff8..b856fc6e 100644
--- a/thermal/pixel-thermal-logd.rc
+++ b/thermal/pixel-thermal-logd.rc
@@ -30,88 +30,10 @@ on property:vendor.disable.thermalhal.control=* && property:vendor.thermal.link_
     restart vendor.thermal-hal
 
 on property:vendor.disable.thermal.control=1 && property:vendor.thermal.link_ready=1
-    # common
-    stop vendor.thermal-engine
     setprop vendor.disable.thermalhal.control 1
-    # sdm845
-    write /dev/thermal/tz-by-name/quiet-therm-adc/mode disabled
-    write /dev/thermal/tz-by-name/quiet-therm-monitor/mode disabled
-    write /dev/thermal/tz-by-name/fps-therm-adc/mode disabled
-    write /dev/thermal/tz-by-name/fps-therm-monitor/mode disabled
-    # sdm670
-    write /dev/thermal/tz-by-name/mb-therm-adc/mode disabled
-    write /dev/thermal/tz-by-name/mb-therm-monitor/mode disabled
-    # sm8150
-    write /dev/thermal/tz-by-name/sdm-therm/mode disabled
-    write /dev/thermal/tz-by-name/sdm-therm-monitor/mode disabled
-    # sm7150
-    write /dev/thermal/tz-by-name/skin-therm-adc/mode disabled
-    write /dev/thermal/tz-by-name/skin-therm-monitor/mode disabled
-    # sm7250
-    write /dev/thermal/tz-by-name/skin-therm/emul_temp 25000
-    write /dev/thermal/tz-by-name/skin-therm/mode disabled
-    write /dev/thermal/tz-by-name/skin-virt/emul_temp 25000
-    write /dev/thermal/tz-by-name/skin-virt/mode disabled
-    write /dev/thermal/tz-by-name/skin-therm-cpu/emul_temp 25000
-    write /dev/thermal/tz-by-name/skin-therm-cpu/mode disabled
-    write /dev/thermal/tz-by-name/skin-virt-cpu/emul_temp 25000
-    write /dev/thermal/tz-by-name/skin-virt-cpu/mode disabled
-    write /dev/thermal/tz-by-name/skin-therm-monitor/emul_temp 25000
-    write /dev/thermal/tz-by-name/skin-therm-monitor/mode disabled
-    write /dev/thermal/tz-by-name/skin-virt-monitor/emul_temp 25000
-    write /dev/thermal/tz-by-name/skin-virt-monitor/mode disabled
-    write /dev/thermal/tz-by-name/panel-audio-therm/emul_temp 25000
-    write /dev/thermal/tz-by-name/panel-audio-therm/mode disabled
-    write /dev/thermal/tz-by-name/cellular-emergency/emul_temp 25000
-    write /dev/thermal/tz-by-name/cellular-emergency/mode disabled
-    write /dev/thermal/tz-by-name/sdm-therm/emul_temp 25000
-    write /dev/thermal/tz-by-name/sdm-therm/mode disabled
-    write /dev/thermal/tz-by-name/charger-therm/emul_temp 25000
-    write /dev/thermal/tz-by-name/charger-therm/mode disabled
-    # P21
-    write /dev/thermal/tz-by-name/disp_therm/mode disabled
 
 on property:vendor.disable.thermal.control=0 && property:vendor.thermal.link_ready=1
-    # common
-    start vendor.thermal-engine
     setprop vendor.disable.thermalhal.control 0
-    # sdm845
-    write /dev/thermal/tz-by-name/quiet-therm-adc/mode enabled
-    write /dev/thermal/tz-by-name/quiet-therm-monitor/mode enabled
-    write /dev/thermal/tz-by-name/fps-therm-adc/mode enabled
-    write /dev/thermal/tz-by-name/fps-therm-monitor/mode enabled
-    # sdm670
-    write /dev/thermal/tz-by-name/mb-therm-adc/mode enabled
-    write /dev/thermal/tz-by-name/mb-therm-monitor/mode enabled
-    # sm8150
-    write /dev/thermal/tz-by-name/sdm-therm/mode enabled
-    write /dev/thermal/tz-by-name/sdm-therm-monitor/mode enabled
-    # sm7150
-    write /dev/thermal/tz-by-name/skin-therm-adc/mode enabled
-    write /dev/thermal/tz-by-name/skin-therm-monitor/mode enabled
-    # sm7250
-    write /dev/thermal/tz-by-name/skin-therm/emul_temp 0
-    write /dev/thermal/tz-by-name/skin-therm/mode enabled
-    write /dev/thermal/tz-by-name/skin-virt/emul_temp 0
-    write /dev/thermal/tz-by-name/skin-virt/mode enabled
-    write /dev/thermal/tz-by-name/skin-therm-cpu/emul_temp 0
-    write /dev/thermal/tz-by-name/skin-therm-cpu/mode enabled
-    write /dev/thermal/tz-by-name/skin-virt-cpu/emul_temp 0
-    write /dev/thermal/tz-by-name/skin-virt-cpu/mode enabled
-    write /dev/thermal/tz-by-name/skin-therm-monitor/emul_temp 0
-    write /dev/thermal/tz-by-name/skin-therm-monitor/mode enabled
-    write /dev/thermal/tz-by-name/skin-virt-monitor/emul_temp 0
-    write /dev/thermal/tz-by-name/skin-virt-monitor/mode enabled
-    write /dev/thermal/tz-by-name/panel-audio-therm/emul_temp 0
-    write /dev/thermal/tz-by-name/panel-audio-therm/mode enabled
-    write /dev/thermal/tz-by-name/cellular-emergency/emul_temp 0
-    write /dev/thermal/tz-by-name/cellular-emergency/mode enabled
-    write /dev/thermal/tz-by-name/sdm-therm/emul_temp 0
-    write /dev/thermal/tz-by-name/sdm-therm/mode enabled
-    write /dev/thermal/tz-by-name/charger-therm/emul_temp 0
-    write /dev/thermal/tz-by-name/charger-therm/mode enabled
-    # P21
-    write /dev/thermal/tz-by-name/disp_therm/mode enabled
 
 # Toggle BCL control
 on property:vendor.disable.bcl.control=1
diff --git a/thermal/tests/pixel_config_checker.py b/thermal/tests/pixel_config_checker.py
deleted file mode 100644
index 525621e8..00000000
--- a/thermal/tests/pixel_config_checker.py
+++ /dev/null
@@ -1,101 +0,0 @@
-#!/usr/bin/env python3
-
-#
-# Copyright 2024, The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-"""This is a general Json Config checker that checks string values
-against a predefined vocabulary list.
-"""
-
-import json
-import os
-import subprocess
-import sys
-
-class PixelConfigLexiconChecker(object):
-  """A object for common JSON configuration checking.
-
-    Takes a json_files = dict(file_path, JSON Object) and
-    lexicon_path (list of words) and checks every field name and
-    string value against the list of words.
-
-    Typical usage example:
-
-    foo = PixelConfigLexiconChecker(files, vocabulary_path)
-    success, error = foo.check_json_spelling()
-  """
-  valid_words = None
-  json_files = None
-  commit_sha = None
-
-  def __init__(self, json_files, lexicon_path):
-    self.valid_words = self.load_words_from_txt(lexicon_path)
-    self.json_files = json_files
-
-  def load_words_from_txt(self, file_path):
-   """ Function to load list of words from file
-
-   input:
-    file_path: path to lexicon
-
-   output: Set of words.
-   """
-   words = set()
-   with open(file_path, 'r') as f:
-     for line in f:
-       word = line.strip()
-       if word:
-         words.add(word)
-   return words
-
-  def _check_json_spelling(self, data):
-    """ Recursive function that traverses the json object
-      checking every field and string value.
-
-    input:
-      data: JSON object
-
-    output:
-      Tuple of Success and word if unknown.
-    """
-    if isinstance(data, dict):
-      for key, value in data.items():
-        if key not in self.valid_words:
-          return False, key
-        ok, word = self._check_json_spelling(value)
-        if not ok:
-          return False, word
-
-    if isinstance(data, list):
-      for item in data:
-        ok, word = self._check_json_spelling(item)
-        if not ok:
-          return False, word
-
-    return True, None
-
-  def check_json_spelling(self):
-    """ Entry function to check strings and field names if known.
-
-    output:
-      Tuple of Success and error message.
-    """
-    for file_path, json_object in self.json_files.items():
-      success, message = self._check_json_spelling(json_object)
-      if not success:
-        return False, "File " + file_path +": Unknown string: " + message
-
-    return True, ""
diff --git a/thermal/tests/thermal_config_field_names.txt b/thermal/tests/thermal_config_field_names.txt
index 9c2820ed..a2a31d17 100644
--- a/thermal/tests/thermal_config_field_names.txt
+++ b/thermal/tests/thermal_config_field_names.txt
@@ -1,3 +1,4 @@
+Abnormality
 BackupSensor
 BindedCdevInfo
 CdevCeiling
@@ -6,6 +7,8 @@ CdevWeightForPID
 Coefficient
 CoefficientType
 Combination
+CombinationType
+Configs
 CoolingDevices
 Formula
 Hidden
@@ -20,26 +23,38 @@ K_I
 K_Po
 K_Pu
 LimitInfo
+LoggingName
 MaxAllocPower
 MaxReleaseStep
 MaxThrottleStep
 MinAllocPower
 ModelPath
+Monitor
 Multiplier
 Name
 Offset
+Outlier
 OutputLabelCount
 PassiveDelay
 PIDInfo
 PollingDelay
+PredictionDuration
 PreviousSampleCount
+RecordWithDefaultThreshold
+RecordWithThreshold
+SampleDuration
 SendCallback
 SendPowerHint
 Sensors
 S_Power
+Stats
+SupportPrediction
 SupportUnderSampling
+TempRange
+Thresholds
 TimeResolution
 TriggerSensor
+TripPointIgnorable
 Type
 Version
 VirtualSensor
diff --git a/thermal/thermal-helper.cpp b/thermal/thermal-helper.cpp
index 68f06488..43792a59 100644
--- a/thermal/thermal-helper.cpp
+++ b/thermal/thermal-helper.cpp
@@ -24,6 +24,7 @@
 #include <android-base/strings.h>
 #include <utils/Trace.h>
 
+#include <filesystem>
 #include <iterator>
 #include <set>
 #include <sstream>
@@ -48,6 +49,10 @@ constexpr std::string_view kUserSpaceSuffix("user_space");
 constexpr std::string_view kCoolingDeviceCurStateSuffix("cur_state");
 constexpr std::string_view kCoolingDeviceMaxStateSuffix("max_state");
 constexpr std::string_view kCoolingDeviceState2powerSuffix("state2power_table");
+constexpr std::string_view kPowerCapRoot("/sys/class/powercap");
+constexpr std::string_view kPowerCapNameFile("name");
+constexpr std::string_view kPowerCapState2powerSuffix("power_levels_uw");
+constexpr std::string_view kPowerCapCurBudgetSuffix("constraint_0_power_limit_uw");
 constexpr std::string_view kConfigProperty("vendor.thermal.config");
 constexpr std::string_view kConfigDefaultFileName("thermal_info_config.json");
 constexpr std::string_view kThermalGenlProperty("persist.vendor.enable.thermal.genl");
@@ -90,6 +95,28 @@ std::unordered_map<std::string, std::string> parseThermalPathMap(std::string_vie
     return path_map;
 }
 
+std::unordered_map<std::string, std::string> parsePowerCapPathMap(void) {
+    std::unordered_map<std::string, std::string> path_map;
+    std::error_code ec;
+
+    if (!std::filesystem::exists(kPowerCapRoot, ec)) {
+        LOG(INFO) << "powercap root " << kPowerCapRoot << " does not exist, ec " << ec.message();
+        return path_map;
+    }
+
+    for (const auto &entry : std::filesystem::directory_iterator(kPowerCapRoot)) {
+        std::string path = ::android::base::StringPrintf("%s/%s", entry.path().c_str(),
+                                                         kPowerCapNameFile.data());
+        std::string name;
+        if (::android::base::ReadFileToString(path, &name)) {
+            path_map.emplace(::android::base::Trim(name), entry.path());
+        } else {
+            PLOG(ERROR) << "Failed to read from " << path << ", errno " << errno;
+        }
+    }
+    return path_map;
+}
+
 }  // namespace
 
 // dump additional traces for a given sensor
@@ -167,7 +194,15 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
         ret = false;
     }
 
-    if (!ParseSensorInfo(config, &sensor_info_map_)) {
+    auto cdev_map = parseThermalPathMap(kCoolingDevicePrefix.data());
+    auto powercap_map = parsePowerCapPathMap();
+
+    if (!initializeThrottlingMap(cdev_map, powercap_map)) {
+        LOG(ERROR) << "Failed to initialize throttling map";
+        ret = false;
+    }
+
+    if (!ParseSensorInfo(config, &sensor_info_map_, cooling_device_info_map_)) {
         LOG(ERROR) << "Failed to parse sensor info config";
         ret = false;
     }
@@ -178,15 +213,16 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
         ret = false;
     }
 
-    auto cdev_map = parseThermalPathMap(kCoolingDevicePrefix.data());
-    if (!initializeCoolingDevices(cdev_map)) {
-        LOG(ERROR) << "Failed to initialize cooling device map";
+    if (!power_files_.registerPowerRailsToWatch(config, &power_rail_switch_map_)) {
+        LOG(ERROR) << "Failed to register power rails";
         ret = false;
     }
 
-    if (!power_files_.registerPowerRailsToWatch(config)) {
-        LOG(ERROR) << "Failed to register power rails";
-        ret = false;
+    // Check if the trigger sensor of power rails is valid
+    for (const auto &[sensor, _] : power_rail_switch_map_) {
+        if (!sensor_info_map_.contains(sensor)) {
+            LOG(FATAL) << "Power Rails's trigger sensor " << sensor << " is invalid";
+        }
     }
 
     if (!thermal_predictions_helper_.initializePredictionSensors(sensor_info_map_)) {
@@ -201,8 +237,8 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
         }
     }
 
-    for (auto &name_status_pair : sensor_info_map_) {
-        sensor_status_map_[name_status_pair.first] = {
+    for (auto &[sensor_name, sensor_info] : sensor_info_map_) {
+        sensor_status_map_[sensor_name] = {
                 .severity = ThrottlingSeverity::NONE,
                 .prev_hot_severity = ThrottlingSeverity::NONE,
                 .prev_cold_severity = ThrottlingSeverity::NONE,
@@ -212,34 +248,31 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
                 .override_status = {nullptr, false, false},
         };
 
-        if (name_status_pair.second.throttling_info != nullptr) {
+        if (sensor_info.throttling_info != nullptr) {
             if (!thermal_throttling_.registerThermalThrottling(
-                        name_status_pair.first, name_status_pair.second.throttling_info,
-                        cooling_device_info_map_)) {
-                LOG(ERROR) << name_status_pair.first << " failed to register thermal throttling";
+                        sensor_name, sensor_info.throttling_info, cooling_device_info_map_)) {
+                LOG(ERROR) << sensor_name << " failed to register thermal throttling";
                 ret = false;
                 break;
             }
 
             // Update cooling device max state for default mode
-            maxCoolingRequestCheck(&name_status_pair.second.throttling_info->binded_cdev_info_map);
+            maxCoolingRequestCheck(&sensor_info.throttling_info->binded_cdev_info_map);
 
             // Update cooling device max state for each profile mode
-            for (auto &cdev_throttling_profile_pair :
-                 name_status_pair.second.throttling_info->profile_map) {
-                maxCoolingRequestCheck(&cdev_throttling_profile_pair.second);
+            for (auto &[cdev_name, cdev_throttling_info] :
+                 sensor_info.throttling_info->profile_map) {
+                maxCoolingRequestCheck(&cdev_throttling_info);
             }
         }
         // Check the virtual sensor settings are valid
-        if (name_status_pair.second.virtual_sensor_info != nullptr) {
+        if (sensor_info.virtual_sensor_info != nullptr) {
             // Check if sub sensor setting is valid
-            for (size_t i = 0;
-                 i < name_status_pair.second.virtual_sensor_info->linked_sensors.size(); i++) {
-                if (!isSubSensorValid(
-                            name_status_pair.second.virtual_sensor_info->linked_sensors[i],
-                            name_status_pair.second.virtual_sensor_info->linked_sensors_type[i])) {
-                    LOG(ERROR) << name_status_pair.first << "'s link sensor "
-                               << name_status_pair.second.virtual_sensor_info->linked_sensors[i]
+            for (size_t i = 0; i < sensor_info.virtual_sensor_info->linked_sensors.size(); i++) {
+                if (!isSubSensorValid(sensor_info.virtual_sensor_info->linked_sensors[i],
+                                      sensor_info.virtual_sensor_info->linked_sensors_type[i])) {
+                    LOG(ERROR) << sensor_name << "'s link sensor "
+                               << sensor_info.virtual_sensor_info->linked_sensors[i]
                                << " is invalid";
                     ret = false;
                     break;
@@ -247,32 +280,28 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
             }
 
             // Check if the backup sensor is valid
-            if (!name_status_pair.second.virtual_sensor_info->backup_sensor.empty()) {
-                if (!isSubSensorValid(name_status_pair.second.virtual_sensor_info->backup_sensor,
+            if (!sensor_info.virtual_sensor_info->backup_sensor.empty()) {
+                if (!isSubSensorValid(sensor_info.virtual_sensor_info->backup_sensor,
                                       SensorFusionType::SENSOR)) {
-                    LOG(ERROR) << name_status_pair.first << "'s backup sensor "
-                               << name_status_pair.second.virtual_sensor_info->backup_sensor
-                               << " is invalid";
+                    LOG(ERROR) << sensor_name << "'s backup sensor "
+                               << sensor_info.virtual_sensor_info->backup_sensor << " is invalid";
                     ret = false;
                     break;
                 }
             }
 
             // Check if the trigger sensor is valid
-            if (!name_status_pair.second.virtual_sensor_info->trigger_sensors.empty() &&
-                name_status_pair.second.is_watch) {
-                for (size_t i = 0;
-                     i < name_status_pair.second.virtual_sensor_info->trigger_sensors.size(); i++) {
+            if (!sensor_info.virtual_sensor_info->trigger_sensors.empty() && sensor_info.is_watch) {
+                for (size_t i = 0; i < sensor_info.virtual_sensor_info->trigger_sensors.size();
+                     i++) {
                     if (sensor_info_map_.count(
-                                name_status_pair.second.virtual_sensor_info->trigger_sensors[i])) {
-                        sensor_info_map_[name_status_pair.second.virtual_sensor_info
-                                                 ->trigger_sensors[i]]
+                                sensor_info.virtual_sensor_info->trigger_sensors[i])) {
+                        sensor_info_map_[sensor_info.virtual_sensor_info->trigger_sensors[i]]
                                 .is_watch = true;
                     } else {
-                        LOG(ERROR)
-                                << name_status_pair.first << "'s trigger sensor: "
-                                << name_status_pair.second.virtual_sensor_info->trigger_sensors[i]
-                                << " is invalid";
+                        LOG(ERROR) << sensor_name << "'s trigger sensor: "
+                                   << sensor_info.virtual_sensor_info->trigger_sensors[i]
+                                   << " is invalid";
                         ret = false;
                         break;
                     }
@@ -280,25 +309,35 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
             }
 
             // Check if the severity reference sensor is valid
-            if (name_status_pair.second.severity_reference != "") {
-                if (sensor_info_map_.contains(name_status_pair.second.severity_reference)) {
-                    sensor_info_map_[name_status_pair.second.severity_reference].is_watch = true;
-                    LOG(INFO) << "Enable is_watch for " << name_status_pair.first
-                              << "'s severity reference sensor: "
-                              << name_status_pair.second.severity_reference;
-                } else {
-                    LOG(ERROR) << name_status_pair.first << "'s severity reference sensor: "
-                               << name_status_pair.second.severity_reference << " is invalid";
-                    ret = false;
+            if (!sensor_info.severity_reference.empty()) {
+                for (size_t i = 0; i < sensor_info.severity_reference.size(); i++) {
+                    if (!sensor_info_map_.contains(sensor_info.severity_reference[i])) {
+                        LOG(ERROR) << sensor_name
+                                   << "'s severity_reference: " << sensor_info.severity_reference[i]
+                                   << " is invalid";
+                        ret = false;
+                        break;
+                    } else {
+                        sensor_info_map_[sensor_info.severity_reference[i]].is_watch = true;
+                    }
+                }
+            }
+
+            // Pause the power rail calculation by default if it should be
+            // activated by trigger sensor
+            if (power_rail_switch_map_.contains(sensor_name)) {
+                const auto &target_rails = power_rail_switch_map_.at(sensor_name);
+                for (const auto &target_rail : target_rails) {
+                    power_files_.powerSamplingSwitch(target_rail, false);
                 }
             }
         }
         // Check predictor info config
-        if ((name_status_pair.second.predictor_info != nullptr) &&
-            name_status_pair.second.predictor_info->support_pid_compensation) {
-            std::string predict_sensor_name = name_status_pair.second.predictor_info->sensor;
+        if ((sensor_info.predictor_info != nullptr) &&
+            sensor_info.predictor_info->support_pid_compensation) {
+            std::string predict_sensor_name = sensor_info.predictor_info->sensor;
             if (!(sensor_info_map_.count(predict_sensor_name))) {
-                LOG(ERROR) << name_status_pair.first << "'s predictor " << predict_sensor_name
+                LOG(ERROR) << sensor_name << "'s predictor " << predict_sensor_name
                            << " is not part of sensor_info_map_";
                 ret = false;
                 break;
@@ -307,31 +346,29 @@ ThermalHelperImpl::ThermalHelperImpl(const NotificationCallback &cb)
             const auto &predictor_sensor_info = sensor_info_map_.at(predict_sensor_name);
             if (predictor_sensor_info.virtual_sensor_info == nullptr ||
                 predictor_sensor_info.virtual_sensor_info->vt_estimator == nullptr) {
-                LOG(ERROR) << name_status_pair.first << "'s predictor " << predict_sensor_name
+                LOG(ERROR) << sensor_name << "'s predictor " << predict_sensor_name
                            << " does not support prediction";
                 ret = false;
                 break;
             }
 
             std::vector<float> output_template;
-            size_t prediction_weight_count =
-                    name_status_pair.second.predictor_info->prediction_weights.size();
+            size_t prediction_weight_count = sensor_info.predictor_info->prediction_weights.size();
             // read predictor out to get the size of output vector
             ::thermal::vtestimator::VtEstimatorStatus predict_check =
                     predictor_sensor_info.virtual_sensor_info->vt_estimator->GetAllPredictions(
                             &output_template);
 
             if (predict_check != ::thermal::vtestimator::kVtEstimatorOk) {
-                LOG(ERROR) << "Failed to get output size of " << name_status_pair.first
-                           << "'s predictor " << predict_sensor_name
-                           << " GetAllPredictions ret: " << ret << ")";
+                LOG(ERROR) << "Failed to get output size of " << sensor_name << "'s predictor "
+                           << predict_sensor_name << " GetAllPredictions ret: " << ret << ")";
                 ret = false;
                 break;
             }
 
             if (prediction_weight_count != output_template.size()) {
-                LOG(ERROR) << "Sensor [" << name_status_pair.first
-                           << "]: " << "prediction weights size (" << prediction_weight_count
+                LOG(ERROR) << "Sensor [" << sensor_name << "]: "
+                           << "prediction weights size (" << prediction_weight_count
                            << ") doesn't match predictor [" << predict_sensor_name
                            << "]'s output size (" << output_template.size() << ")";
                 ret = false;
@@ -516,7 +553,7 @@ bool ThermalHelperImpl::readCoolingDevice(std::string_view cooling_device,
 
     out->type = type;
     out->name = cooling_device.data();
-    out->value = std::stoi(data);
+    out->value = std::atoi(data.c_str());
 
     return true;
 }
@@ -635,16 +672,26 @@ bool ThermalHelperImpl::readTemperatureThreshold(std::string_view sensor_name,
 }
 
 void ThermalHelperImpl::updateCoolingDevices(const std::vector<std::string> &updated_cdev) {
-    int max_state;
-
     for (const auto &target_cdev : updated_cdev) {
+        int max_state;
+        const auto &cdev_info = cooling_device_info_map_.at(target_cdev);
         if (thermal_throttling_.getCdevMaxRequest(target_cdev, &max_state)) {
-            if (cooling_devices_.writeCdevFile(target_cdev, std::to_string(max_state))) {
-                ATRACE_INT(target_cdev.c_str(), max_state);
-                LOG(INFO) << "Successfully update cdev " << target_cdev << " sysfs to "
-                          << max_state;
+            const auto request =
+                    cdev_info.apply_powercap
+                            ? static_cast<int>(std::lround(cdev_info.state2power[max_state] /
+                                                           cdev_info.multiplier))
+                            : max_state;
+            if (cooling_devices_.writeCdevFile(target_cdev, std::to_string(request))) {
+                ATRACE_INT(target_cdev.c_str(), request);
+                if (cdev_info.apply_powercap) {
+                    LOG(INFO) << "Successfully update cdev " << target_cdev << " budget to "
+                              << request << "(state:" << max_state << ")";
+                } else {
+                    LOG(INFO) << "Successfully update cdev " << target_cdev << " sysfs to "
+                              << request;
+                }
             } else {
-                LOG(ERROR) << "Failed to update cdev " << target_cdev << " sysfs to " << max_state;
+                LOG(ERROR) << "Failed to update cdev " << target_cdev << " sysfs to " << request;
             }
         }
     }
@@ -714,8 +761,12 @@ bool ThermalHelperImpl::isSubSensorValid(std::string_view sensor_data,
 
 void ThermalHelperImpl::clearAllThrottling(void) {
     // Clear the CDEV request
-    for (const auto &cdev_info_pair : cooling_device_info_map_) {
-        cooling_devices_.writeCdevFile(cdev_info_pair.first, "0");
+    for (const auto &[cdev_name, cdev_info] : cooling_device_info_map_) {
+        cooling_devices_.writeCdevFile(
+                cdev_name, cdev_info.apply_powercap
+                                   ? std::to_string(static_cast<int>(std::lround(
+                                             cdev_info.state2power[0] / cdev_info.multiplier)))
+                                   : "0");
     }
 
     for (auto &sensor_info_pair : sensor_info_map_) {
@@ -770,95 +821,156 @@ bool ThermalHelperImpl::initializeSensorMap(
     return true;
 }
 
-bool ThermalHelperImpl::initializeCoolingDevices(
-        const std::unordered_map<std::string, std::string> &path_map) {
-    for (auto &cooling_device_info_pair : cooling_device_info_map_) {
-        std::string cooling_device_name = cooling_device_info_pair.first;
-        if (!path_map.count(cooling_device_name)) {
-            LOG(ERROR) << "Could not find " << cooling_device_name << " in sysfs";
-            return false;
-        }
-        // Add cooling device path for thermalHAL to get current state
-        std::string_view path = path_map.at(cooling_device_name);
-        std::string read_path;
-        if (!cooling_device_info_pair.second.read_path.empty()) {
-            read_path = cooling_device_info_pair.second.read_path.data();
-        } else {
-            read_path = ::android::base::StringPrintf("%s/%s", path.data(),
-                                                      kCoolingDeviceCurStateSuffix.data());
-        }
-        if (!cooling_devices_.addThermalFile(cooling_device_name, read_path)) {
-            LOG(ERROR) << "Could not add " << cooling_device_name
-                       << " read path to cooling device map";
-            return false;
-        }
+bool ThermalHelperImpl::initializeCoolingDeviceEntry(
+        const std::unordered_map<std::string, std::string> &path_map, std::string_view name,
+        CdevInfo &cdev_info) {
+    if (!path_map.contains(name.data())) {
+        LOG(ERROR) << "Could not find " << name << " in CDEV sysfs";
+        return false;
+    }
+    // Add cooling device path for thermalHAL to get current state
+    std::string_view path = path_map.at(name.data());
+    std::string read_path;
+    if (!cdev_info.read_path.empty()) {
+        read_path = cdev_info.read_path.data();
+    } else {
+        read_path = ::android::base::StringPrintf("%s/%s", path.data(),
+                                                  kCoolingDeviceCurStateSuffix.data());
+    }
+    if (!cooling_devices_.addThermalFile(name, read_path)) {
+        LOG(ERROR) << "Could not add " << name << " read path to cooling device map";
+        return false;
+    }
 
-        // Get cooling device state2power table from sysfs if not defined in config
-        if (!cooling_device_info_pair.second.state2power.size()) {
-            std::string state2power_path = ::android::base::StringPrintf(
-                    "%s/%s", path.data(), kCoolingDeviceState2powerSuffix.data());
-            std::string state2power_str;
-            if (::android::base::ReadFileToString(state2power_path, &state2power_str)) {
-                LOG(INFO) << "Cooling device " << cooling_device_info_pair.first
-                          << " use State2power read from sysfs";
-                std::stringstream power(state2power_str);
-                unsigned int power_number;
-                while (power >> power_number) {
-                    cooling_device_info_pair.second.state2power.push_back(
-                            static_cast<float>(power_number));
-                }
+    // Get cooling device state2power table from sysfs if not defined in config
+    if (!cdev_info.state2power.size()) {
+        std::string state2power_path = ::android::base::StringPrintf(
+                "%s/%s", path.data(), kCoolingDeviceState2powerSuffix.data());
+        std::string state2power_str;
+        if (::android::base::ReadFileToString(state2power_path, &state2power_str)) {
+            LOG(INFO) << "Cooling device " << name << " use State2power read from sysfs";
+            std::stringstream power(state2power_str);
+            unsigned int power_number;
+            while (power >> power_number) {
+                cdev_info.state2power.push_back(static_cast<int>(power_number) *
+                                                cdev_info.multiplier);
             }
         }
+    }
 
-        // Check if there's any wrong ordered state2power value to avoid cdev stuck issue
-        for (size_t i = 0; i < cooling_device_info_pair.second.state2power.size(); ++i) {
-            LOG(INFO) << "Cooling device " << cooling_device_info_pair.first << " state:" << i
-                      << " power: " << cooling_device_info_pair.second.state2power[i];
-            if (i > 0 && cooling_device_info_pair.second.state2power[i] >
-                                 cooling_device_info_pair.second.state2power[i - 1]) {
-                LOG(ERROR) << "Higher power with higher state on cooling device "
-                           << cooling_device_info_pair.first << "'s state" << i;
-            }
+    // Check if there's any wrong ordered state2power value to avoid cdev stuck issue
+    for (size_t i = 0; i < cdev_info.state2power.size(); ++i) {
+        LOG(INFO) << "Cooling device " << name << " state:" << i
+                  << " power: " << cdev_info.state2power[i];
+        if (i > 0 && cdev_info.state2power[i] > cdev_info.state2power[i - 1]) {
+            LOG(ERROR) << "Higher power with higher state on cooling device " << name << "'s state"
+                       << i;
         }
+    }
 
-        // Get max cooling device request state
-        std::string max_state;
-        std::string max_state_path = ::android::base::StringPrintf(
-                "%s/%s", path.data(), kCoolingDeviceMaxStateSuffix.data());
-        if (!::android::base::ReadFileToString(max_state_path, &max_state)) {
-            LOG(ERROR) << cooling_device_info_pair.first
-                       << " could not open max state file:" << max_state_path;
-            cooling_device_info_pair.second.max_state = std::numeric_limits<int>::max();
-        } else {
-            cooling_device_info_pair.second.max_state = std::stoi(::android::base::Trim(max_state));
-            LOG(INFO) << "Cooling device " << cooling_device_info_pair.first
-                      << " max state: " << cooling_device_info_pair.second.max_state
-                      << " state2power number: "
-                      << cooling_device_info_pair.second.state2power.size();
-            if (cooling_device_info_pair.second.state2power.size() > 0 &&
-                static_cast<int>(cooling_device_info_pair.second.state2power.size()) !=
-                        (cooling_device_info_pair.second.max_state + 1)) {
-                LOG(ERROR) << "Invalid state2power number: "
-                           << cooling_device_info_pair.second.state2power.size()
-                           << ", number should be " << cooling_device_info_pair.second.max_state + 1
-                           << " (max_state + 1)";
-            }
+    // Get max cooling device request state
+    std::string max_state;
+    std::string max_state_path = ::android::base::StringPrintf("%s/%s", path.data(),
+                                                               kCoolingDeviceMaxStateSuffix.data());
+    if (!::android::base::ReadFileToString(max_state_path, &max_state)) {
+        LOG(ERROR) << name << " could not open max state file:" << max_state_path;
+        cdev_info.max_state = std::numeric_limits<int>::max();
+    } else {
+        cdev_info.max_state = std::atoi(::android::base::Trim(max_state).c_str());
+        LOG(INFO) << "Cooling device " << name << " max state: " << cdev_info.max_state
+                  << " state2power number: " << cdev_info.state2power.size();
+        if (cdev_info.state2power.size() > 0 &&
+            static_cast<int>(cdev_info.state2power.size()) != (cdev_info.max_state + 1)) {
+            LOG(ERROR) << "Invalid state2power number: " << cdev_info.state2power.size()
+                       << ", number should be " << cdev_info.max_state + 1 << " (max_state + 1)";
         }
+    }
+
+    // Add cooling device path for thermalHAL to request state
+    auto cdev_name = ::android::base::StringPrintf("%s_%s", name.data(), "w");
+    std::string write_path;
+    if (!cdev_info.write_path.empty()) {
+        write_path = cdev_info.write_path.data();
+    } else {
+        write_path = ::android::base::StringPrintf("%s/%s", path.data(),
+                                                   kCoolingDeviceCurStateSuffix.data());
+    }
+    if (!cooling_devices_.addThermalFile(cdev_name, write_path)) {
+        LOG(ERROR) << "Could not add " << name << " write path to cooling device map";
+        return false;
+    }
+    return true;
+}
+
+bool ThermalHelperImpl::initializePowercapEntry(
+        const std::unordered_map<std::string, std::string> &path_map, std::string_view name,
+        CdevInfo &cdev_info) {
+    if (!path_map.contains(name.data())) {
+        LOG(ERROR) << "Could not find " << name << " in powercap sysfs";
+        return false;
+    }
+    const auto &root_path = path_map.at(name.data());
+
+    // Add powercap path for thermalHAL to access the power budget via constraint_0_power_limit_uw
+    const auto powercap_path = ::android::base::StringPrintf("%s/%s", root_path.data(),
+                                                             kPowerCapCurBudgetSuffix.data());
 
-        // Add cooling device path for thermalHAL to request state
-        cooling_device_name =
-                ::android::base::StringPrintf("%s_%s", cooling_device_name.c_str(), "w");
-        std::string write_path;
-        if (!cooling_device_info_pair.second.write_path.empty()) {
-            write_path = cooling_device_info_pair.second.write_path.data();
+    if (!cooling_devices_.addThermalFile(name, powercap_path)) {
+        LOG(ERROR) << "Could not add " << name << " path to cooling device map";
+        return false;
+    }
+
+    const auto write_path_name = ::android::base::StringPrintf("%s_%s", name.data(), "w");
+    // Add powercap path for thermalHAL to request state
+    if (!cooling_devices_.addThermalFile(write_path_name, cdev_info.write_path.empty()
+                                                                  ? powercap_path
+                                                                  : cdev_info.write_path.data())) {
+        LOG(ERROR) << "Could not add " << name << " write path to cooling device map";
+        return false;
+    }
+
+    int power_number = 0;
+    // Get cooling device state2power table from sysfs if not defined in config
+    if (!cdev_info.state2power.size()) {
+        std::string state2power_path = ::android::base::StringPrintf(
+                "%s/%s", root_path.data(), kPowerCapState2powerSuffix.data());
+        std::string state2power_str;
+        if (::android::base::ReadFileToString(state2power_path, &state2power_str)) {
+            LOG(INFO) << "PowerCap " << name
+                      << " use State2power read from sysfs: " << state2power_str;
+            std::stringstream power(state2power_str);
+            while (power >> power_number) {
+                const auto power_mw = static_cast<int>(power_number * cdev_info.multiplier);
+                cdev_info.state2power.push_back(power_mw);
+            }
         } else {
-            write_path = ::android::base::StringPrintf("%s/%s", path.data(),
-                                                       kCoolingDeviceCurStateSuffix.data());
+            return false;
+        }
+    }
+
+    // Check if there's any wrong ordered state2power value to avoid cdev stuck issue
+    for (size_t i = 0; i < cdev_info.state2power.size(); ++i) {
+        LOG(INFO) << "PowerCap " << name << " state:" << i
+                  << " power: " << cdev_info.state2power[i];
+        if (i > 0 && cdev_info.state2power[i] > cdev_info.state2power[i - 1]) {
+            LOG(ERROR) << "Higher power with higher state on PowerCap " << name << "'s state" << i;
+            return false;
         }
+    }
+    cdev_info.max_state = cdev_info.state2power.size() - 1;
 
-        if (!cooling_devices_.addThermalFile(cooling_device_name, write_path)) {
-            LOG(ERROR) << "Could not add " << cooling_device_name
-                       << " write path to cooling device map";
+    return true;
+}
+
+bool ThermalHelperImpl::initializeThrottlingMap(
+        const std::unordered_map<std::string, std::string> &cdev_map,
+        const std::unordered_map<std::string, std::string> &powercap_map) {
+    for (auto &[cdev_name, cdev_info] : cooling_device_info_map_) {
+        if (cdev_info.apply_powercap) {
+            if (!initializePowercapEntry(powercap_map, cdev_name, cdev_info)) {
+                return false;
+            }
+        } else if (!initializeCoolingDeviceEntry(cdev_map, cdev_name, cdev_info)) {
             return false;
         }
     }
@@ -870,6 +982,28 @@ void ThermalHelperImpl::setMinTimeout(SensorInfo *sensor_info) {
     sensor_info->passive_delay = kMinPollIntervalMs;
 }
 
+bool ThermalHelperImpl::updateTripPointThreshold(std::string_view sensor_name,
+                                                 const bool is_trip_point_ignorable,
+                                                 std::string_view threshold,
+                                                 std::string_view trip_point_path) {
+    bool update_success = false;
+    if (::android::base::WriteStringToFile(threshold.data(), trip_point_path.data())) {
+        update_success = true;
+    } else {
+        if (FILE *fd = fopen(trip_point_path.data(), "r")) {
+            fclose(fd);
+        }
+        if (is_trip_point_ignorable) {
+            LOG(INFO) << "Skip the trip point threshold update at " << trip_point_path
+                      << " for ignorable sensor " << sensor_name << " , errno: " << errno;
+        } else {
+            LOG(ERROR) << "Failed to update sensor " << sensor_name << "'s trip threshold "
+                       << threshold << " at path " << trip_point_path << " , errno: " << errno;
+        }
+    }
+    return update_success | is_trip_point_ignorable;
+}
+
 void ThermalHelperImpl::initializeTrip(const std::unordered_map<std::string, std::string> &path_map,
                                        std::set<std::string> *monitored_sensors,
                                        bool thermal_genl_enabled) {
@@ -910,23 +1044,17 @@ void ThermalHelperImpl::initializeTrip(const std::unordered_map<std::string, std
                             sensor_info.second.hot_thresholds[i] / sensor_info.second.multiplier));
                     path = ::android::base::StringPrintf("%s/%s", (tz_path.data()),
                                                          kSensorTripPointTempZeroFile.data());
-                    if (!::android::base::WriteStringToFile(threshold, path)) {
-                        LOG(ERROR) << "fail to update " << sensor_name << " trip point: " << path
-                                   << " to " << threshold;
-                        trip_update = false;
-                        break;
-                    }
+                    trip_update &= updateTripPointThreshold(
+                            sensor_name, sensor_info.second.is_trip_point_ignorable, threshold,
+                            path);
                     // Update trip_point_0_hyst threshold
                     threshold = std::to_string(std::lround(sensor_info.second.hot_hysteresis[i] /
                                                            sensor_info.second.multiplier));
                     path = ::android::base::StringPrintf("%s/%s", (tz_path.data()),
                                                          kSensorTripPointHystZeroFile.data());
-                    if (!::android::base::WriteStringToFile(threshold, path)) {
-                        LOG(ERROR) << "fail to update " << sensor_name << "trip hyst" << threshold
-                                   << path;
-                        trip_update = false;
-                        break;
-                    }
+                    trip_update &= updateTripPointThreshold(
+                            sensor_name, sensor_info.second.is_trip_point_ignorable, threshold,
+                            path);
                     break;
                 } else if (i == kThrottlingSeverityCount - 1) {
                     LOG(ERROR) << sensor_name << ":all thresholds are NAN";
@@ -990,7 +1118,6 @@ bool ThermalHelperImpl::fillTemperatureThresholds(
         } else {
             LOG(ERROR) << __func__ << ": error reading temperature threshold for sensor: "
                        << name_info_pair.first;
-            return false;
         }
     }
     *thresholds = ret;
@@ -1009,7 +1136,6 @@ bool ThermalHelperImpl::fillCurrentCoolingDevices(
             ret.emplace_back(std::move(value));
         } else {
             LOG(ERROR) << __func__ << ": error reading cooling device: " << name_info_pair.first;
-            return false;
         }
     }
     *cooling_devices = ret;
@@ -1017,22 +1143,24 @@ bool ThermalHelperImpl::fillCurrentCoolingDevices(
 }
 
 ThrottlingSeverity ThermalHelperImpl::getSeverityReference(std::string_view sensor_name) {
+    ThrottlingSeverity target_ref_severity = ThrottlingSeverity::NONE;
     if (!sensor_info_map_.contains(sensor_name.data())) {
-        return ThrottlingSeverity::NONE;
-    }
-    const std::string &severity_reference =
-            sensor_info_map_.at(sensor_name.data()).severity_reference;
-    if (severity_reference == "") {
-        return ThrottlingSeverity::NONE;
+        return target_ref_severity;
     }
+    const auto &severity_ref_sensors = sensor_info_map_.at(sensor_name.data()).severity_reference;
 
-    Temperature temp;
-    if (readTemperature(severity_reference, &temp, false) != SensorReadStatus::OKAY) {
-        return ThrottlingSeverity::NONE;
+    for (size_t i = 0; i < severity_ref_sensors.size(); i++) {
+        Temperature temp;
+        if (readTemperature(severity_ref_sensors[i], &temp, false) != SensorReadStatus::OKAY) {
+            return ThrottlingSeverity::NONE;
+        }
+        LOG(VERBOSE) << sensor_name << "'s severity reference " << severity_ref_sensors[i]
+                     << " reading:" << toString(temp.throttlingStatus);
+
+        target_ref_severity = std::max(target_ref_severity, temp.throttlingStatus);
     }
-    LOG(VERBOSE) << sensor_name << "'s severity reference " << severity_reference
-                 << " reading:" << toString(temp.throttlingStatus);
-    return temp.throttlingStatus;
+
+    return target_ref_severity;
 }
 
 bool ThermalHelperImpl::readDataByType(std::string_view sensor_data, float *reading_value,
@@ -1310,7 +1438,7 @@ SensorReadStatus ThermalHelperImpl::readThermalSensor(
             LOG(ERROR) << "failed to read sensor: " << sensor_name;
             return SensorReadStatus::ERROR;
         }
-        *temp = std::stof(::android::base::Trim(file_reading));
+        *temp = std::atof(::android::base::Trim(file_reading).c_str());
     } else {
         const auto &linked_sensors_size = sensor_info.virtual_sensor_info->linked_sensors.size();
         std::vector<float> sensor_readings(linked_sensors_size, NAN);
@@ -1419,6 +1547,7 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
     boot_clock::time_point now = boot_clock::now();
     auto min_sleep_ms = std::chrono::milliseconds::max();
     bool power_data_is_updated = false;
+    bool shutdown_severity_reached = false;
 
     for (const auto &[sensor, temp] : uevent_sensor_map) {
         if (!std::isnan(temp)) {
@@ -1543,6 +1672,14 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
                                    ? sensor_info.passive_delay
                                    : sensor_info.polling_delay;
                 sensor_status.pending_notification = false;
+
+                if (power_rail_switch_map_.contains(name_status_pair.first)) {
+                    const auto &target_rails = power_rail_switch_map_.at(name_status_pair.first);
+                    for (const auto &target_rail : target_rails) {
+                        power_files_.powerSamplingSwitch(
+                                target_rail, sensor_status.severity != ThrottlingSeverity::NONE);
+                    }
+                }
             }
         }
 
@@ -1554,6 +1691,9 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
         if (sensor_status.severity == ThrottlingSeverity::NONE) {
             thermal_throttling_.clearThrottlingData(name_status_pair.first);
         } else {
+            if (sensor_status.severity == ThrottlingSeverity::SHUTDOWN) {
+                shutdown_severity_reached = true;
+            }
             // prepare for predictions for throttling compensation
             std::vector<float> sensor_predictions;
             if (sensor_info.predictor_info != nullptr &&
@@ -1606,7 +1746,7 @@ std::chrono::milliseconds ThermalHelperImpl::thermalWatcherCallbackFunc(
 
     const auto since_last_power_log_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             now - power_files_.GetPrevPowerLogTime());
-    if (since_last_power_log_ms >= kPowerLogIntervalMs) {
+    if ((since_last_power_log_ms >= kPowerLogIntervalMs) || (shutdown_severity_reached)) {
         power_files_.logPowerStatus(now);
     }
 
diff --git a/thermal/thermal-helper.h b/thermal/thermal-helper.h
index 8665d524..d81f3a61 100644
--- a/thermal/thermal-helper.h
+++ b/thermal/thermal-helper.h
@@ -195,8 +195,15 @@ class ThermalHelperImpl : public ThermalHelper {
 
   private:
     bool initializeSensorMap(const std::unordered_map<std::string, std::string> &path_map);
-    bool initializeCoolingDevices(const std::unordered_map<std::string, std::string> &path_map);
+    bool initializeThrottlingMap(const std::unordered_map<std::string, std::string> &cdev_map,
+                                 const std::unordered_map<std::string, std::string> &powercap_map);
+    bool initializePowercapEntry(const std::unordered_map<std::string, std::string> &powercap_map,
+                                 std::string_view name, CdevInfo &cdev_info);
+    bool initializeCoolingDeviceEntry(const std::unordered_map<std::string, std::string> &cdev_map,
+                                      std::string_view name, CdevInfo &cdev_info);
     bool isSubSensorValid(std::string_view sensor_data, const SensorFusionType sensor_fusion_type);
+    bool updateTripPointThreshold(std::string_view sensor_name, const bool is_trip_point_ignorable,
+                                  std::string_view threshold, std::string_view trip_point_path);
     void setMinTimeout(SensorInfo *sensor_info);
     void initializeTrip(const std::unordered_map<std::string, std::string> &path_map,
                         std::set<std::string> *monitored_sensors, bool thermal_genl_enabled);
@@ -224,7 +231,7 @@ class ThermalHelperImpl : public ThermalHelper {
     float readPredictionAfterTimeMs(std::string_view sensor_name, const size_t time_ms);
     bool readTemperaturePredictions(std::string_view sensor_name, std::vector<float> *predictions);
     void updateCoolingDevices(const std::vector<std::string> &cooling_devices_to_update);
-    // Check the max CDEV state for cdev_ceiling
+    // Check the max throttling for binded cooling device
     void maxCoolingRequestCheck(
             std::unordered_map<std::string, BindedCdevInfo> *binded_cdev_info_map);
     void checkUpdateSensorForEmul(std::string_view target_sensor, const bool max_throttling);
@@ -239,6 +246,8 @@ class ThermalHelperImpl : public ThermalHelper {
     const NotificationCallback cb_;
     std::unordered_map<std::string, CdevInfo> cooling_device_info_map_;
     std::unordered_map<std::string, SensorInfo> sensor_info_map_;
+    // The target ODPM railes which will be switched by the trigger sensor
+    std::unordered_map<std::string, std::vector<std::string>> power_rail_switch_map_;
     std::unordered_map<std::string, std::unordered_map<ThrottlingSeverity, ThrottlingSeverity>>
             supported_powerhint_map_;
     PowerHalService power_hal_service_;
diff --git a/thermal/utils/power_files.cpp b/thermal/utils/power_files.cpp
index 87947a63..32a6e700 100644
--- a/thermal/utils/power_files.cpp
+++ b/thermal/utils/power_files.cpp
@@ -43,7 +43,11 @@ namespace {
 bool calculateAvgPower(std::string_view power_rail, const PowerSample &last_sample,
                        const PowerSample &curr_sample, float *avg_power) {
     *avg_power = NAN;
-    if (curr_sample.duration == last_sample.duration) {
+
+    if (last_sample.duration == 0) {
+        LOG(VERBOSE) << "Power rail " << power_rail.data() << ": samples are under collecting";
+        return true;
+    } else if (curr_sample.duration == last_sample.duration) {
         LOG(VERBOSE) << "Power rail " << power_rail.data()
                      << ": has not collected min 2 samples yet";
         return true;
@@ -65,8 +69,10 @@ bool calculateAvgPower(std::string_view power_rail, const PowerSample &last_samp
 }
 }  // namespace
 
-bool PowerFiles::registerPowerRailsToWatch(const Json::Value &config) {
-    if (!ParsePowerRailInfo(config, &power_rail_info_map_)) {
+bool PowerFiles::registerPowerRailsToWatch(
+        const Json::Value &config,
+        std::unordered_map<std::string, std::vector<std::string>> *power_rail_switch_map) {
+    if (!ParsePowerRailInfo(config, &power_rail_info_map_, power_rail_switch_map)) {
         LOG(ERROR) << "Failed to parse power rail info config";
         return false;
     }
@@ -129,6 +135,7 @@ bool PowerFiles::registerPowerRailsToWatch(const Json::Value &config) {
                     .last_update_time = boot_clock::time_point::min(),
                     .power_history = power_history,
                     .last_updated_avg_power = NAN,
+                    .enabled = true,
             };
         } else {
             LOG(ERROR) << "power history size is zero";
@@ -338,12 +345,35 @@ bool PowerFiles::refreshPowerStatus(void) {
         return false;
     }
 
-    for (const auto &power_status_pair : power_status_map_) {
-        updatePowerRail(power_status_pair.first);
+    for (const auto &[power_rail, power_status] : power_status_map_) {
+        if (power_status.enabled) {
+            updatePowerRail(power_rail);
+        }
     }
     return true;
 }
 
+void PowerFiles::powerSamplingSwitch(std::string_view power_rail, const bool enabled) {
+    if (!power_rail_info_map_.contains(power_rail.data())) {
+        LOG(ERROR) << "Unable to clear status for invalid power rail: " << power_rail.data();
+        return;
+    }
+    auto &power_status = power_status_map_.at(power_rail.data());
+    power_status.enabled = enabled;
+
+    if (!enabled) {
+        PowerSample power_sample = {.energy_counter = 0, .duration = 0};
+
+        for (size_t i = 0; i < power_status.power_history.size(); i++) {
+            for (size_t j = 0; j < power_status.power_history[i].size(); j++) {
+                power_status.power_history[i].pop();
+                power_status.power_history[i].push(power_sample);
+            }
+        }
+        power_status.last_updated_avg_power = NAN;
+    }
+}
+
 void PowerFiles::logPowerStatus(const boot_clock::time_point &now) {
     // calculate energy and print
     uint8_t power_rail_log_cnt = 0;
diff --git a/thermal/utils/power_files.h b/thermal/utils/power_files.h
index 0b00604f..8a2bcd42 100644
--- a/thermal/utils/power_files.h
+++ b/thermal/utils/power_files.h
@@ -45,6 +45,7 @@ struct PowerStatus {
     // A vector to record the queues of power sample history.
     std::vector<std::queue<PowerSample>> power_history;
     float last_updated_avg_power;
+    bool enabled;
 };
 
 struct PowerStatusLog {
@@ -61,11 +62,15 @@ class PowerFiles {
     // Disallow copy and assign.
     PowerFiles(const PowerFiles &) = delete;
     void operator=(const PowerFiles &) = delete;
-    bool registerPowerRailsToWatch(const Json::Value &config);
+    bool registerPowerRailsToWatch(
+            const Json::Value &config,
+            std::unordered_map<std::string, std::vector<std::string>> *power_rail_switch_map);
     // Update the power data from ODPM sysfs
     bool refreshPowerStatus(void);
     // Log the power data for the duration
     void logPowerStatus(const boot_clock::time_point &now);
+    // OnOff the power calculation
+    void powerSamplingSwitch(std::string_view power_rail, const bool enabled);
     // Get previous power log time_point
     const boot_clock::time_point &GetPrevPowerLogTime() const {
         return power_status_log_.prev_log_time;
diff --git a/thermal/utils/thermal_info.cpp b/thermal/utils/thermal_info.cpp
index f4dd713f..87ba0fdf 100644
--- a/thermal/utils/thermal_info.cpp
+++ b/thermal/utils/thermal_info.cpp
@@ -49,7 +49,7 @@ bool getTypeFromString(std::string_view str, T *out) {
 
 float getFloatFromValue(const Json::Value &value) {
     if (value.isString()) {
-        return std::stof(value.asString());
+        return std::atof(value.asString().c_str());
     } else {
         return value.asFloat();
     }
@@ -267,6 +267,15 @@ bool ParseThermalConfig(std::string_view config_path, Json::Value *config,
         MergeConfigEntries(config, &sub_config, "Sensors");
         MergeConfigEntries(config, &sub_config, "CoolingDevices");
         MergeConfigEntries(config, &sub_config, "PowerRails");
+
+        if (!sub_config["Stats"].empty()) {
+            if ((*config)["Stats"].empty()) {
+                (*config)["Stats"] = sub_config["Stats"];
+            } else {
+                MergeConfigEntries(&(*config)["Stats"]["Sensors"], &sub_config["Stats"]["Sensors"],
+                                   "RecordWithThreshold");
+            }
+        }
     }
 
     return true;
@@ -699,10 +708,17 @@ bool ParseBindedCdevInfo(
         const Json::Value &values,
         std::unordered_map<std::string, BindedCdevInfo> *binded_cdev_info_map,
         const bool support_pid, bool *support_hard_limit,
-        const std::unordered_map<std::string, std::vector<int>> &scaling_frequency_map) {
+        const std::unordered_map<std::string, std::vector<int>> &scaling_frequency_map,
+        const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map_) {
     for (Json::Value::ArrayIndex j = 0; j < values.size(); ++j) {
         Json::Value sub_values;
         const std::string &cdev_name = values[j]["CdevRequest"].asString();
+
+        if (cooling_device_info_map_.find(cdev_name) == cooling_device_info_map_.end()) {
+            LOG(ERROR) << "Binded cdev " << cdev_name << " is not defined in cooling devices";
+            return false;
+        }
+
         ThrottlingArray cdev_weight_for_pid;
         cdev_weight_for_pid.fill(NAN);
         CdevArray cdev_ceiling;
@@ -934,7 +950,8 @@ bool ParseBindedCdevInfo(
 bool ParseSensorThrottlingInfo(
         const std::string_view name, const Json::Value &sensor, bool *support_throttling,
         std::shared_ptr<ThrottlingInfo> *throttling_info,
-        const std::unordered_map<std::string, std::vector<int>> &scaling_frequency_map) {
+        const std::unordered_map<std::string, std::vector<int>> &scaling_frequency_map,
+        const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map_) {
     std::array<float, kThrottlingSeverityCount> k_po;
     k_po.fill(0.0);
     std::array<float, kThrottlingSeverityCount> k_pu;
@@ -1089,7 +1106,8 @@ bool ParseSensorThrottlingInfo(
     // Parse binded cooling device
     std::unordered_map<std::string, BindedCdevInfo> binded_cdev_info_map;
     if (!ParseBindedCdevInfo(sensor["BindedCdevInfo"], &binded_cdev_info_map, support_pid,
-                             &support_hard_limit, scaling_frequency_map)) {
+                             &support_hard_limit, scaling_frequency_map,
+                             cooling_device_info_map_)) {
         LOG(ERROR) << "Sensor[" << name << "]: failed to parse BindedCdevInfo";
         return false;
     }
@@ -1102,7 +1120,8 @@ bool ParseSensorThrottlingInfo(
         const std::string &mode = values[j]["Mode"].asString();
         std::unordered_map<std::string, BindedCdevInfo> binded_cdev_info_map_profile;
         if (!ParseBindedCdevInfo(values[j]["BindedCdevInfo"], &binded_cdev_info_map_profile,
-                                 support_pid, &support_hard_limit, scaling_frequency_map)) {
+                                 support_pid, &support_hard_limit, scaling_frequency_map,
+                                 cooling_device_info_map_)) {
             LOG(ERROR) << "Sensor[" << name << " failed to parse BindedCdevInfo profile";
         }
         // Check if the binded_cdev_info_map_profile is valid
@@ -1163,7 +1182,8 @@ bool ParseSensorThrottlingInfo(
 }
 
 bool ParseSensorInfo(const Json::Value &config,
-                     std::unordered_map<std::string, SensorInfo> *sensors_parsed) {
+                     std::unordered_map<std::string, SensorInfo> *sensors_parsed,
+                     const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map_) {
     Json::Value sensors = config["Sensors"];
     Json::Value cdevs = config["CoolingDevices"];
     std::unordered_map<std::string, std::vector<int>> scaling_frequency_map;
@@ -1261,6 +1281,17 @@ bool ParseSensorInfo(const Json::Value &config,
         LOG(INFO) << "Sensor[" << name << "]'s SendPowerHint: " << std::boolalpha << send_powerhint
                   << std::noboolalpha;
 
+        bool is_trip_point_ignorable = false;
+        if (sensors[i]["TripPointIgnorable"].empty() ||
+            !sensors[i]["TripPointIgnorable"].isBool()) {
+            LOG(INFO) << "Failed to read Sensor[" << name
+                      << "]'s TripPointIgnorable, set to 'false'";
+        } else if (sensors[i]["TripPointIgnorable"].asBool()) {
+            is_trip_point_ignorable = true;
+        }
+        LOG(INFO) << "Sensor[" << name << "]'s TripPointIgnorable: " << std::boolalpha
+                  << is_trip_point_ignorable << std::noboolalpha;
+
         bool is_hidden = false;
         if (sensors[i]["Hidden"].empty() || !sensors[i]["Hidden"].isBool()) {
             LOG(INFO) << "Failed to read Sensor[" << name << "]'s Hidden, set to 'false'";
@@ -1426,10 +1457,19 @@ bool ParseSensorInfo(const Json::Value &config,
             LOG(INFO) << "Sensor[" << name << "]'s TempPath: " << temp_path;
         }
 
-        std::string severity_reference;
-        if (!sensors[i]["SeverityReference"].empty()) {
-            severity_reference = sensors[i]["SeverityReference"].asString();
-            LOG(INFO) << "Sensor[" << name << "]'s SeverityReference: " << temp_path;
+        std::vector<std::string> severity_reference;
+
+        values = sensors[i]["SeverityReference"];
+        if (values.isString()) {
+            severity_reference.emplace_back(values.asString());
+            LOG(INFO) << "Sensor[" << name << "]'s SeverityReference:" << values.asString();
+        } else if (values.size()) {
+            severity_reference.reserve(values.size());
+            for (Json::Value::ArrayIndex j = 0; j < values.size(); ++j) {
+                severity_reference.emplace_back(values[j].asString());
+                LOG(INFO) << "Sensor[" << name << "]'s SeverityReference[" << j
+                          << "]: " << severity_reference[j];
+            }
         }
 
         float vr_threshold = NAN;
@@ -1508,7 +1548,7 @@ bool ParseSensorInfo(const Json::Value &config,
         bool support_throttling = false;  // support pid or hard limit
         std::shared_ptr<ThrottlingInfo> throttling_info;
         if (!ParseSensorThrottlingInfo(name, sensors[i], &support_throttling, &throttling_info,
-                                       scaling_frequency_map)) {
+                                       scaling_frequency_map, cooling_device_info_map_)) {
             LOG(ERROR) << "Sensor[" << name << "]: failed to parse throttling info";
             sensors_parsed->clear();
             return false;
@@ -1535,6 +1575,7 @@ bool ParseSensorInfo(const Json::Value &config,
                 .send_powerhint = send_powerhint,
                 .is_watch = is_watch,
                 .is_hidden = is_hidden,
+                .is_trip_point_ignorable = is_trip_point_ignorable,
                 .log_level = log_level,
                 .virtual_sensor_info = std::move(virtual_sensor_info),
                 .throttling_info = std::move(throttling_info),
@@ -1554,6 +1595,8 @@ bool ParseCoolingDevice(const Json::Value &config,
     std::unordered_set<std::string> cooling_devices_name_parsed;
 
     for (Json::Value::ArrayIndex i = 0; i < cooling_devices.size(); ++i) {
+        bool apply_powercap = false;
+        float multiplier = 1.0;
         const std::string &name = cooling_devices[i]["Name"].asString();
         LOG(INFO) << "CoolingDevice[" << i << "]'s Name: " << name;
         if (name.empty()) {
@@ -1567,6 +1610,22 @@ bool ParseCoolingDevice(const Json::Value &config,
             continue;
         }
 
+        if (cooling_devices[i]["PowerCap"].asBool() && cooling_devices[i]["PowerCap"].isBool()) {
+            LOG(INFO) << "CoolingDevice[" << name << "] apply powercap";
+            apply_powercap = true;
+        }
+
+        if (!cooling_devices[i]["Multiplier"].empty()) {
+            multiplier = cooling_devices[i]["Multiplier"].asFloat();
+            if (multiplier <= 0) {
+                cooling_devices_parsed->clear();
+                LOG(INFO) << "CoolingDevice[" << name << "]'s Multiplier: " << multiplier
+                          << " is invalid";
+                return false;
+            }
+        }
+        LOG(INFO) << "CoolingDevice[" << name << "]'s Multiplier: " << multiplier;
+
         auto result = cooling_devices_name_parsed.insert(name.data());
         if (!result.second) {
             LOG(ERROR) << "Duplicate CoolingDevice[" << i << "]'s Name";
@@ -1604,14 +1663,13 @@ bool ParseCoolingDevice(const Json::Value &config,
                       << " does not support State2Power in thermal config";
         }
 
-        const std::string &power_rail = cooling_devices[i]["PowerRail"].asString();
-        LOG(INFO) << "Cooling device power rail : " << power_rail;
-
         (*cooling_devices_parsed)[name] = {
                 .type = cooling_device_type,
                 .read_path = read_path,
                 .write_path = write_path,
                 .state2power = state2power,
+                .apply_powercap = apply_powercap,
+                .multiplier = multiplier,
         };
         ++total_parsed;
     }
@@ -1619,8 +1677,10 @@ bool ParseCoolingDevice(const Json::Value &config,
     return true;
 }
 
-bool ParsePowerRailInfo(const Json::Value &config,
-                        std::unordered_map<std::string, PowerRailInfo> *power_rails_parsed) {
+bool ParsePowerRailInfo(
+        const Json::Value &config,
+        std::unordered_map<std::string, PowerRailInfo> *power_rails_parsed,
+        std::unordered_map<std::string, std::vector<std::string>> *power_rail_switch_map) {
     Json::Value power_rails = config["PowerRails"];
     std::size_t total_parsed = 0;
     std::unordered_set<std::string> power_rails_name_parsed;
@@ -1726,6 +1786,15 @@ bool ParsePowerRailInfo(const Json::Value &config,
                     std::chrono::milliseconds(getIntFromValue(power_rails[i]["PowerSampleDelay"]));
         }
 
+        std::string trigger_sensor;
+        values = power_rails[i]["TriggerSensor"];
+        if (!values.empty()) {
+            if (values.isString()) {
+                (*power_rail_switch_map)[values.asString()].emplace_back(name);
+                LOG(INFO) << "Power rail[" << name << "]'s TriggerSensor: " << values.asString();
+            }
+        }
+
         (*power_rails_parsed)[name] = {
                 .power_sample_count = power_sample_count,
                 .power_sample_delay = power_sample_delay,
diff --git a/thermal/utils/thermal_info.h b/thermal/utils/thermal_info.h
index c5b39dc8..6a6d5689 100644
--- a/thermal/utils/thermal_info.h
+++ b/thermal/utils/thermal_info.h
@@ -227,7 +227,7 @@ struct SensorInfo {
     ThrottlingArray hot_hysteresis;
     ThrottlingArray cold_hysteresis;
     std::string temp_path;
-    std::string severity_reference;
+    std::vector<std::string> severity_reference;
     float vr_threshold;
     float multiplier;
     std::chrono::milliseconds polling_delay;
@@ -240,6 +240,7 @@ struct SensorInfo {
     bool send_powerhint;
     bool is_watch;
     bool is_hidden;
+    bool is_trip_point_ignorable;
     ThrottlingSeverity log_level;
     std::unique_ptr<VirtualSensorInfo> virtual_sensor_info;
     std::shared_ptr<ThrottlingInfo> throttling_info;
@@ -252,6 +253,8 @@ struct CdevInfo {
     std::string write_path;
     std::vector<float> state2power;
     int max_state;
+    bool apply_powercap;
+    float multiplier;
 };
 
 struct PowerRailInfo {
@@ -265,11 +268,14 @@ bool ParseThermalConfig(std::string_view config_path, Json::Value *config,
                         std::unordered_set<std::string> *loaded_config_paths);
 void MergeConfigEntries(Json::Value *config, Json::Value *sub_config, std::string_view member_name);
 bool ParseSensorInfo(const Json::Value &config,
-                     std::unordered_map<std::string, SensorInfo> *sensors_parsed);
+                     std::unordered_map<std::string, SensorInfo> *sensors_parsed,
+                     const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map_);
 bool ParseCoolingDevice(const Json::Value &config,
                         std::unordered_map<std::string, CdevInfo> *cooling_device_parsed);
-bool ParsePowerRailInfo(const Json::Value &config,
-                        std::unordered_map<std::string, PowerRailInfo> *power_rail_parsed);
+bool ParsePowerRailInfo(
+        const Json::Value &config,
+        std::unordered_map<std::string, PowerRailInfo> *power_rail_parsed,
+        std::unordered_map<std::string, std::vector<std::string>> *power_rail_switch_map);
 bool ParseSensorStatsConfig(const Json::Value &config,
                             const std::unordered_map<std::string, SensorInfo> &sensor_info_map_,
                             StatsInfo<float> *sensor_stats_info_parsed,
diff --git a/thermal/utils/thermal_predictions_helper.h b/thermal/utils/thermal_predictions_helper.h
index 532ebe87..80a8056d 100644
--- a/thermal/utils/thermal_predictions_helper.h
+++ b/thermal/utils/thermal_predictions_helper.h
@@ -34,7 +34,7 @@ namespace thermal {
 namespace implementation {
 
 using ::android::base::boot_clock;
-constexpr int kToleranceIntervalMs = 1000;
+constexpr int kToleranceIntervalMs = 3750;
 
 struct PredictionSample {
     PredictionSample(int num_out_samples) {
diff --git a/thermal/utils/thermal_throttling.cpp b/thermal/utils/thermal_throttling.cpp
index b7fc634e..79b6aea2 100644
--- a/thermal/utils/thermal_throttling.cpp
+++ b/thermal/utils/thermal_throttling.cpp
@@ -187,7 +187,9 @@ float ThermalThrottling::updatePowerBudget(
         const Temperature &temp, const SensorInfo &sensor_info,
         const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map,
         std::chrono::milliseconds time_elapsed_ms, ThrottlingSeverity curr_severity,
-        const bool max_throttling, const std::vector<float> &sensor_predictions) {
+        const bool max_throttling,
+        const std::unordered_map<std::string, PowerStatus> &power_status_map,
+        const std::vector<float> &sensor_predictions) {
     float p = 0, d = 0;
     float power_budget = std::numeric_limits<float>::max();
     bool target_changed = false;
@@ -297,10 +299,18 @@ float ThermalThrottling::updatePowerBudget(
         compensation *= sensor_info.predictor_info->k_p_compensate[target_state];
     }
 
+    // Compute Exclude Powerbudget
+    std::string log_buf;
+    float excludepower = 0;
+    if (sensor_info.throttling_info->excluded_power_info_map.size()) {
+        excludepower = computeExcludedPower(sensor_info, curr_severity, power_status_map, &log_buf,
+                                            sensor_name);
+    }
+
     throttling_status.prev_err = err;
     // Calculate power budget
     power_budget = sensor_info.throttling_info->s_power[target_state] + p +
-                   throttling_status.i_budget + d + compensation;
+                   throttling_status.i_budget + d + compensation - excludepower;
 
     power_budget =
             std::clamp(power_budget, sensor_info.throttling_info->min_alloc_power[target_state],
@@ -323,7 +333,8 @@ float ThermalThrottling::updatePowerBudget(
               << " time_elapsed_ms=" << time_elapsed_ms.count() << " p=" << p
               << " i=" << throttling_status.i_budget << " d=" << d
               << " compensation=" << compensation << " budget transient=" << budget_transient
-              << " control target=" << target_state;
+              << " control target=" << target_state << " excluded power budget=" << excludepower
+              << log_buf;
 
     ATRACE_INT((sensor_name + std::string("-power_budget")).c_str(),
                static_cast<int>(power_budget));
@@ -344,6 +355,8 @@ float ThermalThrottling::updatePowerBudget(
     ATRACE_INT((sensor_name + std::string("-d")).c_str(), static_cast<int>(d));
     ATRACE_INT((sensor_name + std::string("-predict_compensation")).c_str(),
                static_cast<int>(compensation));
+    ATRACE_INT((sensor_name + std::string("-excluded_power_budget")).c_str(),
+               static_cast<int>(excludepower));
     ATRACE_INT((sensor_name + std::string("-temp")).c_str(),
                static_cast<int>(temp.value / sensor_info.multiplier));
 
@@ -366,7 +379,7 @@ float ThermalThrottling::computeExcludedPower(
             excluded_power += last_updated_avg_power *
                               excluded_power_info_pair.second[static_cast<size_t>(curr_severity)];
             log_buf->append(StringPrintf(
-                    "(%s: %0.2f mW, cdev_weight: %f)", excluded_power_info_pair.first.c_str(),
+                    " (%s: %0.2f mW, cdev_weight: %f)", excluded_power_info_pair.first.c_str(),
                     last_updated_avg_power,
                     excluded_power_info_pair.second[static_cast<size_t>(curr_severity)]));
 
@@ -402,19 +415,9 @@ bool ThermalThrottling::allocatePowerToCdev(
     std::unique_lock<std::shared_mutex> _lock(thermal_throttling_status_map_mutex_);
     auto total_power_budget =
             updatePowerBudget(temp, sensor_info, cooling_device_info_map, time_elapsed_ms,
-                              curr_severity, max_throttling, sensor_predictions);
+                              curr_severity, max_throttling, power_status_map, sensor_predictions);
     const auto &profile = thermal_throttling_status_map_[temp.name].profile;
 
-    if (sensor_info.throttling_info->excluded_power_info_map.size()) {
-        total_power_budget -= computeExcludedPower(sensor_info, curr_severity, power_status_map,
-                                                   &log_buf, temp.name);
-        total_power_budget = std::max(total_power_budget, 0.0f);
-        if (!log_buf.empty()) {
-            LOG(INFO) << temp.name << " power budget=" << total_power_budget << " after " << log_buf
-                      << " is excluded";
-        }
-    }
-
     // Go through binded cdev, compute total cdev weight
     for (const auto &binded_cdev_info_pair :
          (sensor_info.throttling_info->profile_map.count(profile)
diff --git a/thermal/utils/thermal_throttling.h b/thermal/utils/thermal_throttling.h
index cccce0dc..0d012209 100644
--- a/thermal/utils/thermal_throttling.h
+++ b/thermal/utils/thermal_throttling.h
@@ -101,6 +101,7 @@ class ThermalThrottling {
             const std::unordered_map<std::string, CdevInfo> &cooling_device_info_map,
             std::chrono::milliseconds time_elapsed_ms, ThrottlingSeverity curr_severity,
             const bool max_throttling,
+            const std::unordered_map<std::string, PowerStatus> &power_status_map,
             const std::vector<float> &sensor_predictions = std::vector<float>{});
 
     // PID algo - return the power number from excluded power rail list
diff --git a/thermal/virtualtemp_estimator/virtualtemp_estimator.cpp b/thermal/virtualtemp_estimator/virtualtemp_estimator.cpp
index bb66e876..72d07285 100644
--- a/thermal/virtualtemp_estimator/virtualtemp_estimator.cpp
+++ b/thermal/virtualtemp_estimator/virtualtemp_estimator.cpp
@@ -767,6 +767,21 @@ bool VirtualTempEstimator::ParseInputConfig(const Json::Value &input_config) {
             LOG(INFO) << "Parsed tflite model max_sample_interval: " << max_sample_interval_ms
                       << " for " << common_instance_->sensor_name;
         }
+
+        if (!input_config["ModelConfig"]["prev_samples_order"].empty()) {
+            // read prev_samples_order
+            size_t prev_samples_order = input_config["ModelConfig"]["prev_samples_order"].asUInt();
+
+            LOG(INFO) << "Parsed tflite model prev_samples_order: " << prev_samples_order << " for "
+                      << common_instance_->sensor_name;
+
+            if (prev_samples_order != common_instance_->prev_samples_order) {
+                LOG(ERROR) << "prev_samples_order from Model Config: " << prev_samples_order
+                           << " does not match thermal config prev_samples_order: "
+                           << common_instance_->prev_samples_order;
+                return false;
+            }
+        }
     }
 
     if (!input_config["InputData"].empty()) {
diff --git a/usb/Android.bp b/usb/Android.bp
index b593aee5..31de0813 100644
--- a/usb/Android.bp
+++ b/usb/Android.bp
@@ -126,6 +126,33 @@ cc_library_static {
     ],
 }
 
+cc_library_static {
+    name: "libpixelusb-datasession",
+    vendor: true,
+
+    srcs: [
+        "UsbDataSessionMonitor.cpp",
+    ],
+
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+
+    shared_libs: [
+        "libbase",
+        "libcutils",
+        "libutils",
+        "android.hardware.usb-V3-ndk",
+        "android.frameworks.stats-V2-ndk",
+        "server_configurable_flags",
+    ],
+    static_libs: [
+        "libpixelstats",
+        "android.hardware.usb.flags-aconfig-cc-lib",
+    ],
+}
+
 cc_fuzz {
     name: "libpixelusb_gadgetutils_fuzzer",
     vendor: true,
@@ -151,3 +178,9 @@ cc_fuzz {
         componentid: 175220,
     },
 }
+
+cc_aconfig_library {
+    name: "android.hardware.usb.flags-aconfig-cc-lib",
+    vendor: true,
+    aconfig_declarations: "android.hardware.usb.flags-aconfig",
+}
diff --git a/usb/UsbDataSessionMonitor.cpp b/usb/UsbDataSessionMonitor.cpp
new file mode 100644
index 00000000..d1af9792
--- /dev/null
+++ b/usb/UsbDataSessionMonitor.cpp
@@ -0,0 +1,552 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+#define LOG_TAG "libpixelusb-UsbDataSessionMonitor"
+
+#include "include/pixelusb/UsbDataSessionMonitor.h"
+
+#include <aidl/android/frameworks/stats/IStats.h>
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/strings.h>
+#include <android_hardware_usb_flags.h>
+#include <cutils/uevent.h>
+#include <pixelstats/StatsHelper.h>
+#include <sys/epoll.h>
+#include <sys/timerfd.h>
+#include <utils/Log.h>
+
+#include <regex>
+
+#include "include/pixelusb/CommonUtils.h"
+
+namespace usb_flags = android::hardware::usb::flags;
+
+using aidl::android::frameworks::stats::IStats;
+using android::base::ReadFileToString;
+using android::base::Trim;
+using android::hardware::google::pixel::getStatsService;
+using android::hardware::google::pixel::reportUsbDataSessionEvent;
+using android::hardware::google::pixel::PixelAtoms::VendorUsbDataSessionEvent;
+using android::hardware::google::pixel::usb::addEpollFd;
+using android::hardware::google::pixel::usb::BuildVendorUsbDataSessionEvent;
+
+namespace android {
+namespace hardware {
+namespace google {
+namespace pixel {
+namespace usb {
+
+#define UEVENT_MSG_LEN 2048
+#define USB_STATE_MAX_LEN 20
+#define DATA_ROLE_MAX_LEN 10
+// Extend delay to reduce false positives for missing data line warning (context: b/372885692)
+#define WARNING_SURFACE_DELAY_SEC 15
+#define ENUM_FAIL_DEFAULT_COUNT_THRESHOLD 3
+#define DEVICE_FLAKY_CONNECTION_CONFIGURED_COUNT_THRESHOLD 5
+
+constexpr char kUdcConfigfsPath[] = "/config/usb_gadget/g1/UDC";
+constexpr char kNotAttachedState[] = "not attached\n";
+constexpr char kAttachedState[] = "attached\n";
+constexpr char kPoweredState[] = "powered\n";
+constexpr char kDefaultState[] = "default\n";
+constexpr char kAddressedState[] = "addressed\n";
+constexpr char kConfiguredState[] = "configured\n";
+constexpr char kSuspendedState[] = "suspended\n";
+const std::set<std::string> kValidStates = {kNotAttachedState, kAttachedState,  kPoweredState,
+                                            kDefaultState,     kAddressedState, kConfiguredState,
+                                            kSuspendedState};
+
+static int addEpollFile(const int &epollFd, const std::string &filePath, unique_fd &fileFd) {
+    struct epoll_event ev;
+
+    unique_fd fd(open(filePath.c_str(), O_RDONLY));
+
+    if (fd.get() == -1) {
+        ALOGI("Cannot open %s", filePath.c_str());
+        return -1;
+    }
+
+    ev.data.fd = fd.get();
+    ev.events = EPOLLPRI;
+
+    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd.get(), &ev) != 0) {
+        ALOGE("epoll_ctl failed; errno=%d", errno);
+        return -1;
+    }
+
+    fileFd = std::move(fd);
+    ALOGI("epoll registered %s", filePath.c_str());
+    return 0;
+}
+
+static void removeEpollFile(const int &epollFd, const std::string &filePath, unique_fd &fileFd) {
+    epoll_ctl(epollFd, EPOLL_CTL_DEL, fileFd.get(), NULL);
+    close(fileFd.release());
+
+    ALOGI("epoll unregistered %s", filePath.c_str());
+}
+
+UsbDataSessionMonitor::UsbDataSessionMonitor(
+        const std::string &deviceUeventRegex, const std::string &deviceStatePath,
+        const std::string &host1UeventRegex, const std::string &host1StatePath,
+        const std::string &host2UeventRegex, const std::string &host2StatePath,
+        const std::string &dataRolePath, std::function<void()> updatePortStatusCb) {
+    struct epoll_event ev;
+    std::string udc;
+    int pipefds[2];
+
+    unique_fd epollFd(epoll_create(8));
+    if (epollFd.get() == -1) {
+        ALOGE("epoll_create failed; errno=%d", errno);
+        abort();
+    }
+
+    unique_fd ueventFd(uevent_open_socket(64 * 1024, true));
+    if (ueventFd.get() == -1) {
+        ALOGE("uevent_open_socket failed");
+        abort();
+    }
+    fcntl(ueventFd, F_SETFL, O_NONBLOCK);
+
+    if (addEpollFd(epollFd, ueventFd))
+        abort();
+
+    unique_fd timerFd(timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK));
+    if (timerFd.get() == -1) {
+        ALOGE("create timerFd failed");
+        abort();
+    }
+
+    if (addEpollFd(epollFd, timerFd))
+        abort();
+
+    if (addEpollFile(epollFd.get(), dataRolePath, mDataRoleFd) != 0) {
+        ALOGE("monitor data role failed");
+        abort();
+    }
+
+    pipe(pipefds);
+    mPipefd0.reset(pipefds[0]);
+    mPipefd1.reset(pipefds[1]);
+    if (addEpollFd(epollFd, mPipefd0))
+        abort();
+
+    /*
+     * The device state file could be absent depending on the current data role
+     * and driver architecture. It's ok for addEpollFile to fail here, the file
+     * will be monitored later when its presence is detected by uevent.
+     */
+    mDeviceState.name = "udc";
+    mDeviceState.filePath = deviceStatePath;
+    mDeviceState.ueventRegex = deviceUeventRegex;
+    addEpollFile(epollFd.get(), mDeviceState.filePath, mDeviceState.fd);
+
+    mHost1State.name = "host1";
+    mHost1State.filePath = host1StatePath;
+    mHost1State.ueventRegex = host1UeventRegex;
+    addEpollFile(epollFd.get(), mHost1State.filePath, mHost1State.fd);
+
+    mHost2State.name = "host2";
+    mHost2State.filePath = host2StatePath;
+    mHost2State.ueventRegex = host2UeventRegex;
+    addEpollFile(epollFd.get(), mHost2State.filePath, mHost2State.fd);
+
+    mEpollFd = std::move(epollFd);
+    mUeventFd = std::move(ueventFd);
+    mTimerFd = std::move(timerFd);
+    mUpdatePortStatusCb = updatePortStatusCb;
+
+    if (ReadFileToString(kUdcConfigfsPath, &udc) && !udc.empty())
+        mUdcBind = true;
+    else
+        mUdcBind = false;
+
+    if (pthread_create(&mMonitor, NULL, this->monitorThread, this)) {
+        ALOGE("pthread creation failed %d", errno);
+        abort();
+    }
+
+    ALOGI("feature flag enable_report_usb_data_compliance_warning: %d",
+          usb_flags::enable_report_usb_data_compliance_warning());
+}
+
+UsbDataSessionMonitor::~UsbDataSessionMonitor() {
+    /*
+     * Write a character to the pipe to signal the monitor thread to exit.
+     * The character is not important, it can be any value.
+     */
+    int c = 'q';
+    write(mPipefd1, &c, 1);
+    pthread_join(mMonitor, NULL);
+}
+
+void UsbDataSessionMonitor::reportUsbDataSessionMetrics() {
+    std::vector<VendorUsbDataSessionEvent> events;
+
+    if (mDataRole == PortDataRole::DEVICE) {
+        VendorUsbDataSessionEvent event;
+        BuildVendorUsbDataSessionEvent(false /* is_host */, boot_clock::now(), mDataSessionStart,
+                                       &mDeviceState.states, &mDeviceState.timestamps, &event);
+        events.push_back(event);
+    } else if (mDataRole == PortDataRole::HOST) {
+        bool empty = true;
+        for (auto e : {&mHost1State, &mHost2State}) {
+            /*
+             * Host port will at least get an not_attached event after enablement,
+             * skip upload if no additional state is added.
+             */
+            if (e->states.size() > 1) {
+                VendorUsbDataSessionEvent event;
+                BuildVendorUsbDataSessionEvent(true /* is_host */, boot_clock::now(),
+                                               mDataSessionStart, &e->states, &e->timestamps,
+                                               &event);
+                events.push_back(event);
+                empty = false;
+            }
+        }
+        // All host ports have no state update, upload an event to reflect it
+        if (empty) {
+            VendorUsbDataSessionEvent event;
+            BuildVendorUsbDataSessionEvent(true /* is_host */, boot_clock::now(), mDataSessionStart,
+                                           &mHost1State.states, &mHost1State.timestamps, &event);
+            events.push_back(event);
+        }
+    } else {
+        return;
+    }
+
+    const std::shared_ptr<IStats> stats_client = getStatsService();
+    if (!stats_client) {
+        ALOGE("Unable to get AIDL Stats service");
+        return;
+    }
+
+    for (auto &event : events) {
+        reportUsbDataSessionEvent(stats_client, event);
+    }
+}
+
+void UsbDataSessionMonitor::getComplianceWarnings(const PortDataRole &role,
+                                                  std::vector<ComplianceWarning> *warnings) {
+    if (!usb_flags::enable_report_usb_data_compliance_warning())
+        return;
+
+    if (role != mDataRole || role == PortDataRole::NONE)
+        return;
+
+    for (auto w : mWarningSet) {
+        warnings->push_back(w);
+    }
+}
+
+void UsbDataSessionMonitor::notifyComplianceWarning() {
+    if (!usb_flags::enable_report_usb_data_compliance_warning())
+        return;
+
+    if (mUpdatePortStatusCb)
+        mUpdatePortStatusCb();
+}
+
+void UsbDataSessionMonitor::evaluateComplianceWarning() {
+    std::set<ComplianceWarning> newWarningSet;
+    int elapsedTimeSec;
+
+    elapsedTimeSec =
+            std::chrono::duration_cast<std::chrono::seconds>(boot_clock::now() - mDataSessionStart)
+                    .count();
+
+    if (elapsedTimeSec >= WARNING_SURFACE_DELAY_SEC) {
+        if (mDataRole == PortDataRole::DEVICE && mUdcBind) {
+            int configuredCount = std::count(mDeviceState.states.begin(), mDeviceState.states.end(),
+                                             kConfiguredState);
+            int defaultCount = std::count(mDeviceState.states.begin(), mDeviceState.states.end(),
+                                          kDefaultState);
+
+            if (configuredCount == 0 && defaultCount > ENUM_FAIL_DEFAULT_COUNT_THRESHOLD)
+                newWarningSet.insert(ComplianceWarning::ENUMERATION_FAIL);
+
+            if (configuredCount > DEVICE_FLAKY_CONNECTION_CONFIGURED_COUNT_THRESHOLD)
+                newWarningSet.insert(ComplianceWarning::FLAKY_CONNECTION);
+        } else if (mDataRole == PortDataRole::HOST) {
+            int host1StateCount = mHost1State.states.size();
+            int host1ConfiguredCount = std::count(mHost1State.states.begin(),
+                                                  mHost1State.states.end(), kConfiguredState);
+            int host1DefaultCount =
+                    std::count(mHost1State.states.begin(), mHost1State.states.end(), kDefaultState);
+            int host2StateCount = mHost2State.states.size();
+            int host2ConfiguredCount = std::count(mHost2State.states.begin(),
+                                                  mHost2State.states.end(), kConfiguredState);
+            int host2DefaultCount =
+                    std::count(mHost2State.states.begin(), mHost2State.states.end(), kDefaultState);
+
+            if (host1ConfiguredCount == 0 && host2ConfiguredCount == 0 &&
+                (host1DefaultCount > ENUM_FAIL_DEFAULT_COUNT_THRESHOLD ||
+                 host2DefaultCount > ENUM_FAIL_DEFAULT_COUNT_THRESHOLD))
+                newWarningSet.insert(ComplianceWarning::ENUMERATION_FAIL);
+
+            if (host1StateCount == 1 && mHost1State.states.front() == kNotAttachedState &&
+                host2StateCount == 1 && mHost2State.states.front() == kNotAttachedState)
+                newWarningSet.insert(ComplianceWarning::MISSING_DATA_LINES);
+        }
+    }
+
+    if (newWarningSet != mWarningSet) {
+        std::string newWarningString;
+
+        for (auto e : newWarningSet) {
+            newWarningString += toString(e) + " ";
+        }
+        ALOGI("Usb data compliance warning changed to: %s", newWarningString.c_str());
+
+        mWarningSet = newWarningSet;
+        notifyComplianceWarning();
+    }
+}
+
+void UsbDataSessionMonitor::clearDeviceStateEvents(struct usbDeviceState *deviceState) {
+    deviceState->states.clear();
+    deviceState->timestamps.clear();
+}
+
+void UsbDataSessionMonitor::handleDeviceStateEvent(struct usbDeviceState *deviceState) {
+    char state[USB_STATE_MAX_LEN] = {0};
+
+    lseek(deviceState->fd.get(), 0, SEEK_SET);
+    read(deviceState->fd.get(), &state, USB_STATE_MAX_LEN);
+
+    if (kValidStates.find(state) == kValidStates.end()) {
+        ALOGE("Invalid state %s: %s", deviceState->name.c_str(), state);
+        return;
+    }
+
+    ALOGI("Update device state %s: %s", deviceState->name.c_str(), state);
+
+    deviceState->states.push_back(state);
+    deviceState->timestamps.push_back(boot_clock::now());
+    evaluateComplianceWarning();
+}
+
+void UsbDataSessionMonitor::setupNewSession() {
+    mWarningSet.clear();
+    mDataSessionStart = boot_clock::now();
+
+    if (mDataRole == PortDataRole::DEVICE) {
+        clearDeviceStateEvents(&mDeviceState);
+        if (mDeviceState.delayEpoll) {
+            addEpollFile(mEpollFd.get(), mDeviceState.filePath, mDeviceState.fd);
+            mDeviceState.delayEpoll = false;
+        }
+    } else if (mDataRole == PortDataRole::HOST) {
+        clearDeviceStateEvents(&mHost1State);
+        clearDeviceStateEvents(&mHost2State);
+        if (mHost1State.delayEpoll) {
+            addEpollFile(mEpollFd.get(), mHost1State.filePath, mHost1State.fd);
+            mHost1State.delayEpoll = false;
+        }
+        if (mHost2State.delayEpoll) {
+            addEpollFile(mEpollFd.get(), mHost2State.filePath, mHost2State.fd);
+            mHost2State.delayEpoll = false;
+        }
+    }
+
+    if (mDataRole != PortDataRole::NONE) {
+        struct itimerspec delay = itimerspec();
+        delay.it_value.tv_sec = WARNING_SURFACE_DELAY_SEC;
+        int ret = timerfd_settime(mTimerFd.get(), 0, &delay, NULL);
+        if (ret < 0)
+            ALOGE("timerfd_settime failed err:%d", errno);
+    }
+}
+
+void UsbDataSessionMonitor::handleDataRoleEvent() {
+    PortDataRole newDataRole;
+    char role[DATA_ROLE_MAX_LEN] = {0};
+
+    lseek(mDataRoleFd.get(), 0, SEEK_SET);
+    read(mDataRoleFd.get(), &role, DATA_ROLE_MAX_LEN);
+
+    ALOGI("Update USB data role %s", role);
+
+    // Remove trailing spaces and newlines
+    std::string roleStr = Trim(role);
+    if (roleStr == "host") {
+        newDataRole = PortDataRole::HOST;
+    } else if (roleStr == "device") {
+        newDataRole = PortDataRole::DEVICE;
+    } else {
+        newDataRole = PortDataRole::NONE;
+    }
+
+    if (newDataRole != mDataRole) {
+        // Upload metrics for the last data session that has ended
+        if (mDataRole == PortDataRole::HOST || (mDataRole == PortDataRole::DEVICE && mUdcBind)) {
+            reportUsbDataSessionMetrics();
+        }
+
+        mDataRole = newDataRole;
+        setupNewSession();
+    }
+}
+
+void UsbDataSessionMonitor::updateUdcBindStatus(const std::string &devname) {
+    std::string function;
+    bool newUdcBind;
+
+    /*
+     * /sys/class/udc/<udc>/function prints out name of currently running USB gadget driver
+     * Ref: https://www.kernel.org/doc/Documentation/ABI/stable/sysfs-class-udc
+     * Empty name string means the udc device is not bound and gadget is pulldown.
+     */
+    if (!ReadFileToString("/sys" + devname + "/function", &function))
+        return;
+
+    if (function == "")
+        newUdcBind = false;
+    else
+        newUdcBind = true;
+
+    if (newUdcBind == mUdcBind)
+        return;
+
+    if (mDataRole == PortDataRole::DEVICE) {
+        if (mUdcBind && !newUdcBind) {
+            /*
+             * Gadget soft pulldown: report metrics as the end of a data session and
+             * re-evaluate compliance warnings to clear existing warnings if any.
+             */
+            reportUsbDataSessionMetrics();
+            evaluateComplianceWarning();
+
+        } else if (!mUdcBind && newUdcBind) {
+            // Gadget soft pullup: reset and start accounting for a new data session.
+            setupNewSession();
+        }
+    }
+
+    ALOGI("Udc bind status changes from %b to %b", mUdcBind, newUdcBind);
+    mUdcBind = newUdcBind;
+}
+
+void UsbDataSessionMonitor::handleUevent() {
+    char msg[UEVENT_MSG_LEN + 2];
+    char *cp;
+    int n;
+
+    n = uevent_kernel_multicast_recv(mUeventFd.get(), msg, UEVENT_MSG_LEN);
+    if (n <= 0)
+        return;
+    if (n >= UEVENT_MSG_LEN)
+        return;
+
+    msg[n] = '\0';
+    msg[n + 1] = '\0';
+    cp = msg;
+
+    while (*cp) {
+        for (auto e : {&mHost1State, &mHost2State}) {
+            if (std::regex_search(cp, std::regex(e->ueventRegex))) {
+                if (!strncmp(cp, "bind@", strlen("bind@"))) {
+                    if (mDataRole == PortDataRole::HOST) {
+                        addEpollFile(mEpollFd.get(), e->filePath, e->fd);
+                    } else {
+                        e->delayEpoll = true;
+                        ALOGI("delay epoll to wait for data role host");
+                    }
+                } else if (!strncmp(cp, "unbind@", strlen("unbind@"))) {
+                    removeEpollFile(mEpollFd.get(), e->filePath, e->fd);
+                }
+            }
+        }
+
+        if (std::regex_search(cp, std::regex(mDeviceState.ueventRegex))) {
+            if (!strncmp(cp, "change@", strlen("change@"))) {
+                char *devname = cp + strlen("change@");
+                updateUdcBindStatus(devname);
+            } else if (!strncmp(cp, "add@", strlen("add@"))) {
+                if (mDataRole == PortDataRole::DEVICE) {
+                    addEpollFile(mEpollFd.get(), mDeviceState.filePath, mDeviceState.fd);
+                } else {
+                    mDeviceState.delayEpoll = true;
+                    ALOGI("delay epoll to wait for data role device");
+                }
+            } else if (!strncmp(cp, "remove@", strlen("remove@"))) {
+                removeEpollFile(mEpollFd.get(), mDeviceState.filePath, mDeviceState.fd);
+            }
+        }
+        /* advance to after the next \0 */
+        while (*cp++) {
+        }
+    }
+}
+
+void UsbDataSessionMonitor::handleTimerEvent() {
+    int byteRead;
+    uint64_t numExpiration;
+
+    byteRead = read(mTimerFd.get(), &numExpiration, sizeof(numExpiration));
+
+    if (byteRead != sizeof(numExpiration)) {
+        ALOGE("incorrect read size");
+    }
+
+    if (numExpiration != 1) {
+        ALOGE("incorrect expiration count");
+    }
+
+    evaluateComplianceWarning();
+}
+
+void *UsbDataSessionMonitor::monitorThread(void *param) {
+    UsbDataSessionMonitor *monitor = reinterpret_cast<UsbDataSessionMonitor *>(param);
+    struct epoll_event events[64];
+    int nevents = 0;
+
+    while (true) {
+        nevents = epoll_wait(monitor->mEpollFd.get(), events, 64, -1);
+        if (nevents == -1) {
+            if (errno == EINTR)
+                continue;
+            ALOGE("usb epoll_wait failed; errno=%d", errno);
+            break;
+        }
+
+        for (int n = 0; n < nevents; ++n) {
+            if (events[n].data.fd == monitor->mPipefd0.get()) {
+                return NULL;
+            } else if (events[n].data.fd == monitor->mUeventFd.get()) {
+                monitor->handleUevent();
+            } else if (events[n].data.fd == monitor->mTimerFd.get()) {
+                monitor->handleTimerEvent();
+            } else if (events[n].data.fd == monitor->mDataRoleFd.get()) {
+                monitor->handleDataRoleEvent();
+            } else if (events[n].data.fd == monitor->mDeviceState.fd.get()) {
+                monitor->handleDeviceStateEvent(&monitor->mDeviceState);
+            } else if (events[n].data.fd == monitor->mHost1State.fd.get()) {
+                monitor->handleDeviceStateEvent(&monitor->mHost1State);
+            } else if (events[n].data.fd == monitor->mHost2State.fd.get()) {
+                monitor->handleDeviceStateEvent(&monitor->mHost2State);
+            }
+        }
+    }
+    return NULL;
+}
+
+}  // namespace usb
+}  // namespace pixel
+}  // namespace google
+}  // namespace hardware
+}  // namespace android
diff --git a/usb/include/pixelusb/UsbDataSessionMonitor.h b/usb/include/pixelusb/UsbDataSessionMonitor.h
new file mode 100644
index 00000000..d081d7a1
--- /dev/null
+++ b/usb/include/pixelusb/UsbDataSessionMonitor.h
@@ -0,0 +1,124 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+#include <aidl/android/hardware/usb/ComplianceWarning.h>
+#include <aidl/android/hardware/usb/PortDataRole.h>
+#include <android-base/chrono_utils.h>
+#include <android-base/unique_fd.h>
+
+#include <set>
+#include <string>
+#include <vector>
+
+namespace android {
+namespace hardware {
+namespace google {
+namespace pixel {
+namespace usb {
+
+using ::aidl::android::hardware::usb::ComplianceWarning;
+using ::aidl::android::hardware::usb::PortDataRole;
+using ::android::base::boot_clock;
+using ::android::base::unique_fd;
+
+/*
+ * UsbDataSessionMonitor monitors the usb device state sysfs of 3 different usb devices
+ * including device mode (udc), host mode high-speed port and host mode super-speed port. It
+ * reports Suez metrics for each data session and also provides API to query the compliance
+ * warnings detected in the current usb data session.
+ */
+class UsbDataSessionMonitor {
+  public:
+    /*
+     * The host mode high-speed port and super-speed port can be assigned to either host1 or
+     * host2 without affecting functionality.
+     *
+     * UeventRegex: name regex of the device that's being monitored. The regex is matched against
+     *              uevent to detect dynamic creation/deletion/change of the device.
+     * StatePath: usb device state sysfs path of the device, monitored by epoll.
+     * dataRolePath: path to the usb data role sysfs, monitored by epoll.
+     * updatePortStatusCb: the callback is invoked when the compliance warings changes.
+     */
+    UsbDataSessionMonitor(const std::string &deviceUeventRegex, const std::string &deviceStatePath,
+                          const std::string &host1UeventRegex, const std::string &host1StatePath,
+                          const std::string &host2UeventRegex, const std::string &host2StatePath,
+                          const std::string &dataRolePath,
+                          std::function<void()> updatePortStatusCb);
+    ~UsbDataSessionMonitor();
+    // Returns the compliance warnings detected in the current data session.
+    void getComplianceWarnings(const PortDataRole &role, std::vector<ComplianceWarning> *warnings);
+
+  private:
+    struct usbDeviceState {
+        // The name of the usb device, e.g. udc, host1, host2.
+        std::string name;
+        unique_fd fd;
+        std::string filePath;
+        std::string ueventRegex;
+        bool delayEpoll;
+        // Usb device states reported by state sysfs
+        std::vector<std::string> states;
+        // Timestamps of when the usb device states were captured
+        std::vector<boot_clock::time_point> timestamps;
+    };
+
+    static void *monitorThread(void *param);
+    void handleUevent();
+    void handleTimerEvent();
+    void handleDataRoleEvent();
+    void handleDeviceStateEvent(struct usbDeviceState *deviceState);
+    void clearDeviceStateEvents(struct usbDeviceState *deviceState);
+    void setupNewSession();
+    void reportUsbDataSessionMetrics();
+    void evaluateComplianceWarning();
+    void notifyComplianceWarning();
+    void updateUdcBindStatus(const std::string &devname);
+
+    pthread_t mMonitor;
+    unique_fd mPipefd0;
+    unique_fd mPipefd1;
+    unique_fd mEpollFd;
+    unique_fd mUeventFd;
+    unique_fd mTimerFd;
+    unique_fd mDataRoleFd;
+    struct usbDeviceState mDeviceState;
+    struct usbDeviceState mHost1State;
+    struct usbDeviceState mHost2State;
+    std::set<ComplianceWarning> mWarningSet;
+    // Callback function to notify the caller when there's a change in compliance warnings.
+    std::function<void()> mUpdatePortStatusCb;
+    /*
+     * Cache relevant info for a USB data session when one starts, including
+     * the data role and the time when the session starts.
+     */
+    PortDataRole mDataRole;
+    boot_clock::time_point mDataSessionStart;
+    /*
+     * In gadget mode: this indicates whether the udc device is bound to the configfs driver, which
+     * is done by userspace writing the udc device name to /config/usb_gadget/g1/UDC. When unbound,
+     * the gadget is in soft pulldown state and is expected not to enumerate. During gadget
+     * function switch, the udc device usually go through unbind and bind.
+     */
+    bool mUdcBind;
+};
+
+}  // namespace usb
+}  // namespace pixel
+}  // namespace google
+}  // namespace hardware
+}  // namespace android
```

