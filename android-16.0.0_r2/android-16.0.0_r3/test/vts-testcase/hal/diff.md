```diff
diff --git a/treble/vintf/Android.bp b/treble/vintf/Android.bp
index 1453bac3..a8144fb3 100644
--- a/treble/vintf/Android.bp
+++ b/treble/vintf/Android.bp
@@ -104,6 +104,7 @@ cc_test {
         ":trusty_test_vm_elf",
         ":trusty_test_vm_config",
         ":trusty_vm_launcher_sh",
+        ":trusty_vm_kill_sh",
         ":trusty_wait_ready_sh",
         ":trusty-ut-ctrl.system",
     ],
diff --git a/treble/vintf/DeviceManifestTest.cpp b/treble/vintf/DeviceManifestTest.cpp
index b3061aa6..56d397d6 100644
--- a/treble/vintf/DeviceManifestTest.cpp
+++ b/treble/vintf/DeviceManifestTest.cpp
@@ -18,6 +18,8 @@
 
 #include <android-base/properties.h>
 #include <android-base/result.h>
+#include <android-base/strings.h>
+#include <android/api-level.h>
 #include <libvts_vintf_test_common/common.h>
 #include <vintf/VintfObject.h>
 
@@ -39,6 +41,78 @@ void DeviceManifestTest::SetUp() {
       << "Failed to get vendor HAL manifest." << endl;
 }
 
+// @VsrTest = TODO(FIXME) We need to add this to VSR/GMS somewhere explicitly
+TEST(FrameworkSupportTest, VendorApiLevel) {
+  // Android vendor implementations from Level::V onward have three
+  // additional years of upgrade support!
+  // clang-format off
+  static const std::map<uint64_t, std::set<Level>>
+      kSupportedVendorLevelPerSdkLevel{
+          {__ANDROID_API_R__,
+           {Level::R, Level::Q, Level::P, Level::O, Level::O_MR1, Level::LEGACY}},
+          {__ANDROID_API_S__,
+           {Level::S, Level::R, Level::Q, Level::P, Level::O, Level::O_MR1}},
+          {__ANDROID_API_T__,
+           {Level::T, Level::S, Level::R, Level::Q, Level::P}},
+          {__ANDROID_API_U__,
+           {Level::U, Level::T, Level::S, Level::R, Level::Q}},
+          {__ANDROID_API_V__,
+           {Level::V, Level::U, Level::T, Level::S, Level::R}},
+          {36 /* Android B */,
+           {Level::B, Level::V, Level::U, Level::T, Level::S}},
+          {37 /* Android C */,
+           {Level::C, Level::B, Level::V, Level::U, Level::T}},
+      };
+  // clang-format on
+  uint64_t boardApiLevel = GetBoardApiLevel();
+  ASSERT_NE(boardApiLevel, 0u)
+      << "Device's board API level cannot be determined.";
+  uint64_t buildVersionSdk =
+      android::base::GetUintProperty<uint64_t>("ro.build.version.sdk", 0);
+
+  if (auto it = kSupportedVendorLevelPerSdkLevel.find(buildVersionSdk);
+      it != kSupportedVendorLevelPerSdkLevel.end()) {
+    if (!it->second.contains(static_cast<Level>(boardApiLevel))) {
+      // During development it's common for devices to implement a newer vendor
+      // API level before bumping the SDK API level. So if this is not a REL
+      // device, also check the next SDKs supported vendor API levels.
+      if (android::base::GetProperty("ro.build.version.codename", "") !=
+          "REL") {
+        auto nextSdkVersion = buildVersionSdk + 1;
+        if (auto it = kSupportedVendorLevelPerSdkLevel.find(nextSdkVersion);
+            it != kSupportedVendorLevelPerSdkLevel.end()) {
+          if (it->second.contains(static_cast<Level>(boardApiLevel))) {
+            return;
+          }
+        } else {
+          FAIL()
+              << "VTS testcase failure! We are not yet prepared for the next "
+              << "version of Android. This requires a test fix.";
+        }
+      }
+
+      std::string acceptedBoardApis = android::base::Join(it->second, ",");
+      auto failMessage =
+          "This build is using a version of Android (" +
+          std::to_string(buildVersionSdk) +
+          ") that no longer supports this board API level (" +
+          std::to_string(boardApiLevel) +
+          "). This means we no longer support building the vendor image "
+          "from source code that is this old. The board API level must "
+          "be increased for this upgrade to one of " +
+          acceptedBoardApis;
+      if (GetVendorApiLevel() <= static_cast<uint64_t>(Level::B)) {
+        std::cout << "[  WARNING ] " << failMessage << std::endl;
+      } else {
+        ADD_FAILURE() << failMessage;
+      }
+    }
+  } else {
+    ADD_FAILURE() << "Unknown ro.build.version.sdk value of: "
+                  << buildVersionSdk;
+  }
+}
+
 // Tests that Shipping FCM Version in the device manifest is at least the
 // minimum Shipping FCM Version as required by Vendor API level.
 // @VsrTest = VSR-3.2-014
@@ -53,7 +127,13 @@ TEST_F(DeviceManifestTest, ShippingFcmVersion) {
 // Manifest must have an entry in the Compatibility Matrix
 TEST_F(DeviceManifestTest, UnusedHals) {
   auto vintfObject = VintfObject::GetInstance();
-  auto res = vintfObject->checkUnusedHals({});
+  // Don't check instance names because there may be android.* HALs with
+  // custom instance names in the product/system_ext FCM, not visible in the
+  // VTS test.
+  constexpr bool shouldCheckInstanceName = false;
+  auto res = vintfObject->checkUnusedHals({}, [](const std::string& hal) {
+    return android::base::StartsWith(hal, "android.");
+  }, shouldCheckInstanceName);
 
   if (!res.ok()) {
     uint64_t vendor_api_level = GetVendorApiLevel();
@@ -84,6 +164,7 @@ TEST_F(DeviceManifestTest, NoDeprecatedHalsOnManifest) {
 // compatibility matrix.
 // @VsrTest = VSR-3.2-014
 TEST_F(DeviceManifestTest, GraphicsMapperHalVersionCompatibility) {
+  SKIP_TEST_IN_TRUSTED_HAL_VTS();
   Level shipping_fcm_version = VintfObject::GetDeviceHalManifest()->level();
   bool is_go_device =
       android::base::GetBoolProperty("ro.config.low_ram", false);
@@ -145,6 +226,7 @@ TEST_F(DeviceManifestTest, GraphicsMapperHalVersionCompatibility) {
 // NoDeprecatedHalsOnManifest already checks it.
 // @VsrTest = VSR-3.2-014
 TEST_F(DeviceManifestTest, HealthHal) {
+  SKIP_TEST_IN_TRUSTED_HAL_VTS();
   bool has_hidl = vendor_manifest_->hasHidlInstance(
       "android.hardware.health", {2, 0}, "IHealth", "default");
   bool has_aidl = vendor_manifest_->hasAidlInstance("android.hardware.health",
@@ -159,6 +241,7 @@ TEST_F(DeviceManifestTest, HealthHal) {
 // The specific versions are handled by the framework compatibility matrix.
 // @VsrTest = VSR-3.2-014
 TEST_F(DeviceManifestTest, PowerHal) {
+  SKIP_TEST_IN_TRUSTED_HAL_VTS();
   Level fcm_version = VintfObject::GetDeviceHalManifest()->level();
   if (fcm_version == Level::UNSPECIFIED || fcm_version < Level::R) {
     GTEST_SKIP() << "Power HAL is only required on launching R+ devices";
@@ -192,6 +275,7 @@ TEST_F(DeviceManifestTest, GatekeeperHal) {
 // NoDeprecatedHalsOnManifest already checks it.
 // @VsrTest = VSR-3.2-014
 TEST_F(DeviceManifestTest, ComposerHal) {
+  SKIP_TEST_IN_TRUSTED_HAL_VTS();
   bool has_hidl = vendor_manifest_->hasHidlInstance(
       "android.hardware.graphics.composer", {2, 1}, "IComposer", "default");
   bool has_aidl = vendor_manifest_->hasAidlInstance(
@@ -208,6 +292,7 @@ TEST_F(DeviceManifestTest, ComposerHal) {
 // NoDeprecatedHalsOnManifest already checks it.
 // @VsrTest = VSR-3.2-014
 TEST_F(DeviceManifestTest, GrallocHal) {
+  SKIP_TEST_IN_TRUSTED_HAL_VTS();
   bool has_hidl = false;
   for (size_t hidl_major = 2; hidl_major <= 4; hidl_major++)
     has_hidl = has_hidl || vendor_manifest_->hasHidlInstance(
@@ -226,6 +311,7 @@ TEST_F(DeviceManifestTest, GrallocHal) {
 // between <hal>'s, add a test here.
 // @VsrTest = VSR-3.2-014
 TEST_F(DeviceManifestTest, ThermalHal) {
+  SKIP_TEST_IN_TRUSTED_HAL_VTS();
   Level shipping_fcm_version = VintfObject::GetDeviceHalManifest()->level();
   if (shipping_fcm_version == Level::UNSPECIFIED ||
       shipping_fcm_version < Level::T) {
@@ -246,6 +332,7 @@ TEST_F(DeviceManifestTest, ThermalHal) {
 // compatibility matrix.
 // @VsrTest = VSR-3.2-014
 TEST_F(DeviceManifestTest, GrallocHalVersionCompatibility) {
+  SKIP_TEST_IN_TRUSTED_HAL_VTS();
   Level shipping_fcm_version = VintfObject::GetDeviceHalManifest()->level();
   bool is_go_device =
       android::base::GetBoolProperty("ro.config.low_ram", false);
@@ -272,6 +359,7 @@ TEST_F(DeviceManifestTest, GrallocHalVersionCompatibility) {
 // compatibility matrices cannot express these conditions.
 // @VsrTest = VSR-3.2-014
 TEST_F(DeviceManifestTest, AudioHal) {
+  SKIP_TEST_IN_TRUSTED_HAL_VTS();
   Level shipping_fcm_version = VintfObject::GetDeviceHalManifest()->level();
   if (shipping_fcm_version == Level::UNSPECIFIED ||
       shipping_fcm_version < Level::U) {
diff --git a/treble/vintf/SingleManifestTest.cpp b/treble/vintf/SingleManifestTest.cpp
index 7e7f9a5e..ed60b81e 100644
--- a/treble/vintf/SingleManifestTest.cpp
+++ b/treble/vintf/SingleManifestTest.cpp
@@ -35,6 +35,7 @@
 #include <gmock/gmock.h>
 #include <hidl-util/FqInstance.h>
 #include <hidl/HidlTransportUtils.h>
+#include <linux/vm_sockets.h>
 #include <stdio.h>
 #include <vintf/constants.h>
 #include <vintf/parse_string.h>
@@ -55,10 +56,11 @@ namespace {
 
 constexpr int kAndroidApi202404 = 202404;
 constexpr int kAndroidApi202504 = 202504;
-constexpr int kTrustyTestVmVintfTaPort = 1000;
+constexpr unsigned int kTrustyTestVmVintfTaPort = 10;
 
 }  // namespace
 using android::FqInstance;
+using android::base::unique_fd;
 using android::vintf::IServiceInfoFetcher;
 using android::vintf::ServiceInfo;
 using android::vintf::toFQNameString;
@@ -587,8 +589,43 @@ sp<IServiceInfoFetcher> GetTrustedHalInfoFetcher() {
   }
 
   auto session = RpcSession::make();
-  status_t status =
-      session->setupVsockClient(test_vm_cid, kTrustyTestVmVintfTaPort);
+  auto request = [=] {
+    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
+    if (s < 0) {
+      cout << "failed to get vsock; errno:" << errno;
+      return unique_fd{};
+    }
+    struct timeval connect_timeout = {.tv_sec = 60, .tv_usec = 0};
+    int res = setsockopt(s, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
+                         &connect_timeout, sizeof(connect_timeout));
+    if (res) {
+      cout << "failed to set timeout; errno:" << errno;
+    }
+    struct sockaddr_vm addr = {
+        .svm_family = AF_VSOCK,
+        .svm_port = kTrustyTestVmVintfTaPort,
+        .svm_cid = static_cast<unsigned int>(test_vm_cid),
+    };
+    res =
+        TEMP_FAILURE_RETRY(connect(s, (struct sockaddr *)&addr, sizeof(addr)));
+    if (res != 0) {
+      cout << "failed to connect to VM. Error code:" << res;
+      return unique_fd{};
+    } else {
+      cout << "vsock connection successful\n";
+    }
+    // TODO(b/406418102): This is a temporary workaround because currently the
+    // TIPC bridge sends a packet back after initial connection
+    int8_t buf;
+    res = TEMP_FAILURE_RETRY(read(s, &buf, sizeof(buf)));
+    if (res == sizeof(buf)) {
+      return unique_fd(s);
+    } else {
+      cout << "failed to connect to Trusty VM service. Error code:" << res;
+      return unique_fd{};
+    }
+  };
+  auto status = session->setupPreconnectedClient(unique_fd{}, request);
   if (status != android::OK) {
     cout << "unable to set up vsock client";
     return nullptr;
@@ -751,24 +788,6 @@ static bool CheckAidlVersionMatchesDeclared(
   return false;
 }
 
-static std::vector<std::string> halsUpdatableViaSystem() {
-  std::vector<std::string> hals = {};
-  // The KeyMint HALs connecting to the Trusty VM in the system image are
-  // supposed to be enabled in vendor init when the system property
-  // |trusty.security_vm.keymint.enabled| is set to true in W.
-  if (base::GetBoolProperty("trusty.security_vm.keymint.enabled", false)) {
-    hals.push_back("android.hardware.security.keymint.IKeyMintDevice/default");
-    hals.push_back(
-        "android.hardware.security.keymint.IRemotelyProvisionedComponent/"
-        "default");
-    hals.push_back(
-        "android.hardware.security.sharedsecret.ISharedSecret/default");
-    hals.push_back(
-        "android.hardware.security.secureclock.ISecureClock/default");
-  }
-  return hals;
-}
-
 static inline void checkHash(
     const ServiceInfo &hal_info, bool ignore_rel,
     const std::optional<const std::string> &parent_interface) {
@@ -853,6 +872,25 @@ void checkVintfUpdatableViaApex(const std::string &exe,
   ASSERT_THAT(exe, StartsWith("/apex/" + apex_name + "/"));
 }
 
+#ifndef TRUSTED_HAL_TEST
+static std::vector<std::string> halsUpdatableViaSystem() {
+  std::vector<std::string> hals = {};
+  // The KeyMint HALs connecting to the Trusty VM in the system image are
+  // supposed to be enabled in vendor init when the system property
+  // |trusty.security_vm.keymint.enabled| is set to true in W.
+  if (base::GetBoolProperty("trusty.security_vm.keymint.enabled", false)) {
+    hals.push_back("android.hardware.security.keymint.IKeyMintDevice/default");
+    hals.push_back(
+        "android.hardware.security.keymint.IRemotelyProvisionedComponent/"
+        "default");
+    hals.push_back(
+        "android.hardware.security.sharedsecret.ISharedSecret/default");
+    hals.push_back(
+        "android.hardware.security.secureclock.ISecureClock/default");
+  }
+  return hals;
+}
+
 TEST_P(SingleAidlTest, ExpectedUpdatableViaSystemHals) {
   const auto &[aidl_instance, _] = GetParam();
   const std::string name = ServiceName(aidl_instance);
@@ -868,6 +906,7 @@ TEST_P(SingleAidlTest, ExpectedUpdatableViaSystemHals) {
         << "VINTF manifest but it does not have system dependency.";
   }
 }
+#endif  // TRUSTED_HAL_TEST
 
 // An AIDL HAL with VINTF stability can only be registered if it is in the
 // manifest. However, we still must manually check that every declared HAL is
@@ -967,6 +1006,20 @@ TEST_P(SingleAidlTest, HalIsServed) {
   }
 }
 
+TEST_P(SingleAidlTest, NoExclusiveToVmHalExistIfTrustedVmDisabled) {
+  const auto &[aidl_instance, _] = GetParam();
+  const std::string name = ServiceName(aidl_instance);
+
+  const bool trustyVmEnabled =
+      base::GetBoolProperty("trusty.security_vm.enabled", false) ||
+      base::GetBoolProperty("trusty.widevine_vm.enabled", false);
+  if (!trustyVmEnabled) {
+    ASSERT_NE(ExclusiveTo::VM, aidl_instance.exclusiveTo())
+        << "HAL " << name << " is exclusive to VM but the device does not "
+        << "support any Trusty VM.";
+  }
+}
+
 // We don't want to add more same process HALs in Android. We have some 3rd
 // party ones such as openGL and Vulkan. In the future, we should verify those
 // here as well. However we want to strictly limit other HALs because a
@@ -1003,6 +1056,7 @@ static std::optional<NativePackage> findKnownNativePackage(
 
 // using device manifest test for access to GetNativeInstances
 TEST(NativeDeclaredTest, NativeDeclaredIfExists) {
+  SKIP_TEST_IN_TRUSTED_HAL_VTS();
   std::set<std::string> names;  // e.g. 'mapper.instance_name'
 
   // read all the native HALs installed on disk
diff --git a/treble/vintf/aidl/Android.bp b/treble/vintf/aidl/Android.bp
new file mode 100644
index 00000000..48424a37
--- /dev/null
+++ b/treble/vintf/aidl/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_test_vts-testcase_hal_treble_vintf_aidl",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/treble/vintf/utils.cpp b/treble/vintf/utils.cpp
index 0f1712cf..914858e6 100644
--- a/treble/vintf/utils.cpp
+++ b/treble/vintf/utils.cpp
@@ -117,6 +117,10 @@ uint64_t GetVendorApiLevel() {
   return GetUintProperty<uint64_t>("ro.vendor.api_level", 0);
 }
 
+uint64_t GetBoardApiLevel() {
+  return GetUintProperty<uint64_t>("ro.board.api_level", 0);
+}
+
 // For a given interface returns package root if known. Returns empty string
 // otherwise.
 const string PackageRoot(const FQName &fq_iface_name) {
diff --git a/treble/vintf/utils.h b/treble/vintf/utils.h
index 94ca3d80..8d86d560 100644
--- a/treble/vintf/utils.h
+++ b/treble/vintf/utils.h
@@ -31,6 +31,19 @@
 #include <string>
 #include <vector>
 
+// Conditionally define if TRUSTED_HAL_TEST IS defined
+#ifdef TRUSTED_HAL_TEST
+#define SKIP_TEST_IN_TRUSTED_HAL_VTS()                                 \
+  do {                                                                 \
+    GTEST_SKIP() << "skipping this test in Trusted HAL VTS; it's not " \
+                    "relevant to Trusted HAL";                         \
+  } while (0)
+#else  // TRUSTED_HAL_TEST
+#define SKIP_TEST_IN_TRUSTED_HAL_VTS() \
+  do {                                 \
+  } while (0)
+#endif  // TRUSTED_HAL_TEST
+
 namespace android {
 namespace vintf {
 namespace testing {
@@ -154,6 +167,10 @@ extern const set<string> kPassthroughHals;
 // this is calculated. In system/core/init/property_service.cpp.
 uint64_t GetVendorApiLevel();
 
+// Read ro.board.api_level
+// This is set based on the level of source code the vendor image is built from
+uint64_t GetBoardApiLevel();
+
 // For a given interface returns package root if known. Returns empty string
 // otherwise.
 const string PackageRoot(const FQName& fq_iface_name);
diff --git a/treble/vintf/vts_treble_vintf_trusted_hal_test.xml b/treble/vintf/vts_treble_vintf_trusted_hal_test.xml
index f4f47b2e..15bbd02d 100644
--- a/treble/vintf/vts_treble_vintf_trusted_hal_test.xml
+++ b/treble/vintf/vts_treble_vintf_trusted_hal_test.xml
@@ -20,11 +20,11 @@
            value="(getprop trusty.security_vm.enabled | grep 1) || (getprop trusty.widevine_vm.enabled | grep 1)" />
     </object>
     <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
-    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
     <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
         <option name="cleanup" value="true" />
         <option name="push-file" key="trusty-ut-ctrl.system" value="/data/local/tmp/trusty_test_vm/trusty-ut-ctrl" />
         <option name="push-file" key="trusty-vm-launcher.sh" value="/data/local/tmp/trusty_test_vm/trusty-vm-launcher.sh" />
+        <option name="push-file" key="trusty-vm-kill.sh" value="/data/local/tmp/trusty_test_vm/trusty-vm-kill.sh" />
         <option name="push-file" key="trusty-wait-ready.sh" value="/data/local/tmp/trusty_test_vm/trusty-wait-ready.sh" />
         <option name="push-file" key="trusty-test_vm-config.json" value="/data/local/tmp/trusty_test_vm/trusty-test_vm-config.json" />
         <option name="push-file" key="trusty_test_vm.elf" value="/data/local/tmp/trusty_test_vm/trusty_test_vm.elf" />
@@ -40,12 +40,19 @@
         <!--Note: the first run-command shall not expect the background command to have started -->
         <option name="run-bg-command" value="sh /data/local/tmp/trusty_test_vm/trusty-vm-launcher.sh" />
         <option name="run-command" value="sh /data/local/tmp/trusty_test_vm/trusty-wait-ready.sh" />
-        <option name="run-command" value="start storageproxyd_test_vm_os" />
-        <option name="teardown-command" value="stop storageproxyd_test_vm_os" />
-        <option name="teardown-command" value="killall storageproxyd_test_vm_os || true" />
+        <!-- Wait one second for the VM to fully launch to reduce test flakiness -->
+        <option name="run-command" value="sleep 3" />
+        <option name="run-command" value="start storageproxyd_test_vm" />
+        <option name="teardown-command" value="stop storageproxyd_test_vm" />
+        <option name="teardown-command" value="killall storageproxyd_test_vm || true" />
+        <option name="teardown-command" value="sh /data/local/tmp/trusty_test_vm/trusty-vm-kill.sh" />
     </target_preparer>
     <test class="com.android.tradefed.testtype.GTest" >
         <option name="native-test-device-path" value="/data/local/tmp" />
         <option name="module-name" value="vts_treble_vintf_trusted_hal_test" />
     </test>
+    <metrics_collector class="com.android.tradefed.device.metric.FilePullerLogCollector">
+        <option name="directory-keys" value="/data/local/tmp/trusty_test_vm/logs" />
+        <option name="clean-up" value="false"/>
+    </metrics_collector>
 </configuration>
diff --git a/usb/OWNERS b/usb/OWNERS
index 82a48918..c1c5f22e 100644
--- a/usb/OWNERS
+++ b/usb/OWNERS
@@ -1,6 +1,4 @@
 # Bug component: 175220
-
-vmartensson@google.com
 nkapron@google.com
 febinthattil@google.com
 shubhankarm@google.com
```

