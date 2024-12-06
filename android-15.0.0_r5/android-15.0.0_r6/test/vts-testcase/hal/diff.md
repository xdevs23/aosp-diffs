```diff
diff --git a/treble/vintf/Android.bp b/treble/vintf/Android.bp
index 4c176ff7..c2f50f59 100644
--- a/treble/vintf/Android.bp
+++ b/treble/vintf/Android.bp
@@ -65,7 +65,7 @@ cc_test {
     test_config: "vts_treble_vintf_vendor_test.xml",
     test_suites: [
         "vts",
-        "device-tests",
+        "general-tests",
     ],
     defaults: ["vts_treble_vintf_test_defaults"],
     srcs: [
@@ -97,7 +97,7 @@ cc_test {
     test_config: "vts_treble_vintf_framework_test.xml",
     test_suites: [
         "vts",
-        "device-tests",
+        "general-tests",
     ],
     defaults: ["vts_treble_vintf_test_defaults"],
     srcs: [
diff --git a/treble/vintf/DeviceManifestTest.cpp b/treble/vintf/DeviceManifestTest.cpp
index 7d398a62..7c959887 100644
--- a/treble/vintf/DeviceManifestTest.cpp
+++ b/treble/vintf/DeviceManifestTest.cpp
@@ -40,12 +40,12 @@ void DeviceManifestTest::SetUp() {
 }
 
 // Tests that Shipping FCM Version in the device manifest is at least the
-// minimum Shipping FCM Version as required by Board API level.
+// minimum Shipping FCM Version as required by Vendor API level.
 // @VsrTest = VSR-3.2-014
 TEST_F(DeviceManifestTest, ShippingFcmVersion) {
-  uint64_t board_api_level = GetBoardApiLevel();
+  uint64_t vendor_api_level = GetVendorApiLevel();
   Level shipping_fcm_version = VintfObject::GetDeviceHalManifest()->level();
-  auto res = TestTargetFcmVersion(shipping_fcm_version, board_api_level);
+  auto res = TestTargetFcmVersion(shipping_fcm_version, vendor_api_level);
   ASSERT_RESULT_OK(res);
 }
 
diff --git a/treble/vintf/DeviceMatrixTest.cpp b/treble/vintf/DeviceMatrixTest.cpp
index 807f3a88..a3e9c952 100644
--- a/treble/vintf/DeviceMatrixTest.cpp
+++ b/treble/vintf/DeviceMatrixTest.cpp
@@ -39,7 +39,7 @@ void DeviceMatrixTest::SetUp() {
 
 // @VsrTest = VSR-3.2-014
 TEST_F(DeviceMatrixTest, VndkVersion) {
-  if (GetBoardApiLevel() < __ANDROID_API_P__) {
+  if (GetVendorApiLevel() < __ANDROID_API_P__) {
     GTEST_SKIP()
         << "VNDK version doesn't need to be set on devices before Android P";
   }
@@ -63,6 +63,13 @@ TEST_F(DeviceMatrixTest, VndkVersion) {
   if (syspropVndkVersionNumber == __ANDROID_API_V__) {
     GTEST_SKIP() << "Android based on 24Q1 release with VNDK version V should "
                     "be skipped from check";
+  } else if (board_api_level <= __ANDROID_API_U__ &&
+             board_api_level >= __ANDROID_API_R__ &&
+             syspropVndkVersion.empty()) {
+    GTEST_SKIP() << kVndkVersionProp
+                 << " is empty, but this is allowed when the "
+                    "ro.board.api_level is set to "
+                 << board_api_level;
   }
 
   ASSERT_LT(syspropVndkVersionNumber, __ANDROID_API_V__)
diff --git a/treble/vintf/SingleManifestTest.cpp b/treble/vintf/SingleManifestTest.cpp
index d47e7688..618d33ec 100644
--- a/treble/vintf/SingleManifestTest.cpp
+++ b/treble/vintf/SingleManifestTest.cpp
@@ -59,7 +59,7 @@ using android::vintf::toFQNameString;
 // For devices that launched <= Android O-MR1, systems/hals/implementations
 // were delivered to companies which either don't start up on device boot.
 bool LegacyAndExempt(const FQName &fq_name) {
-  return GetBoardApiLevel() <= 27 && !IsAndroidPlatformInterface(fq_name);
+  return GetVendorApiLevel() <= 27 && !IsAndroidPlatformInterface(fq_name);
 }
 
 void FailureHalMissing(const FQName &fq_name, const std::string &instance) {
@@ -649,6 +649,25 @@ static bool CheckAidlVersionMatchesDeclared(sp<IBinder> binder,
   return false;
 }
 
+static std::vector<std::string> halsUpdatableViaSystem() {
+  std::vector<std::string> hals = {};
+  // The KeyMint HALs connecting to the Trusty VM in the system image are
+  // supposed to be enabled in vendor init when the system property
+  // |ro.hardware.security.keymint.trusty.system| is set to true in W.
+  if (base::GetBoolProperty("ro.hardware.security.keymint.trusty.system",
+                            false)) {
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
 // This checks to make sure all vintf extensions are frozen.
 // We do not check for known hashes because the Android framework does not
 // support these extensions without out-of-tree changes from partners.
@@ -697,6 +716,24 @@ void checkVintfUpdatableViaApex(const sp<IBinder> &binder,
   ASSERT_THAT(exe, StartsWith("/apex/" + apex_name + "/"));
 }
 
+TEST_P(SingleAidlTest, ExpectedUpdatableViaSystemHals) {
+  const auto &[aidl_instance, _] = GetParam();
+  const std::string name = aidl_instance.package() + "." +
+                           aidl_instance.interface() + "/" +
+                           aidl_instance.instance();
+
+  const auto hals = halsUpdatableViaSystem();
+  if (std::find(hals.begin(), hals.end(), name) != hals.end()) {
+    ASSERT_TRUE(aidl_instance.updatable_via_system())
+        << "HAL " << name << " has system dependency but not declared with "
+        << "updatable-via-system in the VINTF manifest.";
+  } else {
+    ASSERT_FALSE(aidl_instance.updatable_via_system())
+        << "HAL " << name << " is declared with updatable-via-system in the "
+        << "VINTF manifest but it does not have system dependency.";
+  }
+}
+
 // An AIDL HAL with VINTF stability can only be registered if it is in the
 // manifest. However, we still must manually check that every declared HAL is
 // actually present on the device.
@@ -718,8 +755,11 @@ TEST_P(SingleAidlTest, HalIsServed) {
   ASSERT_NE(binder, nullptr) << "Failed to get " << name;
 
   // allow upgrade if updatable HAL's declared APEX is actually updated.
-  const bool allow_upgrade = updatable_via_apex.has_value() &&
-                             IsApexUpdated(updatable_via_apex.value());
+  // or if the HAL is updatable via system.
+  const bool allow_upgrade = (updatable_via_apex.has_value() &&
+                              IsApexUpdated(updatable_via_apex.value())) ||
+                             aidl_instance.updatable_via_system();
+
   const bool reliable_version =
       CheckAidlVersionMatchesDeclared(binder, name, version, allow_upgrade);
 
@@ -731,7 +771,7 @@ TEST_P(SingleAidlTest, HalIsServed) {
   ASSERT_TRUE(!is_aosp || metadata)
       << "AOSP interface must have metadata: " << package;
 
-  if (GetBoardApiLevel() >= kAndroidApi202404 &&
+  if (GetVendorApiLevel() >= kAndroidApi202404 &&
       !android::internal::Stability::requiresVintfDeclaration(binder)) {
     ADD_FAILURE() << "Interface " << name
                   << " is declared in the VINTF manifest "
@@ -780,7 +820,7 @@ TEST_P(SingleAidlTest, HalIsServed) {
       }
     }
   }
-  if (GetBoardApiLevel() >= kAndroidApi202404) {
+  if (GetVendorApiLevel() >= kAndroidApi202404) {
     checkVintfExtensionInterfaces(binder, is_release);
   }
 
diff --git a/treble/vintf/VtsNoHidl.cpp b/treble/vintf/VtsNoHidl.cpp
index a63ca87c..85d5462d 100644
--- a/treble/vintf/VtsNoHidl.cpp
+++ b/treble/vintf/VtsNoHidl.cpp
@@ -28,7 +28,6 @@ namespace vintf {
 namespace testing {
 
 static constexpr int kMaxNumberOfHidlHalsU = 100;
-static constexpr int kMaxNumberOfHidlHalsV = 0;
 
 // Tests that the device is not registering any HIDL interfaces.
 // HIDL is being deprecated. Only applicable to devices launching with Android
@@ -56,7 +55,7 @@ TEST_F(VintfNoHidlTest, NoHidl) {
     GTEST_SKIP() << "Not applicable to this device";
     return;
   }
-  int maxNumberOfHidlHals = 0;
+  int maxNumberOfHidlHals;
   std::set<std::string> halInterfaces;
   if (apiLevel == __ANDROID_API_U__) {
     maxNumberOfHidlHals = kMaxNumberOfHidlHalsU;
@@ -75,20 +74,23 @@ TEST_F(VintfNoHidlTest, NoHidl) {
             halInterfaces.insert(splitInterface[0]);
           }
         });
-  } else if (apiLevel == __ANDROID_VENDOR_API_24Q2__) {
-    maxNumberOfHidlHals = kMaxNumberOfHidlHalsV;
-    halInterfaces = allHidlManifestInterfaces();
   } else {
-    // TODO(232439834) We can remove this once kMaxNumberOfHidlHalsV is 0.
-    GTEST_FAIL() << "Unexpected Android vendor API level (" << apiLevel
-                 << "). Must be either " << __ANDROID_API_U__ << " or "
-                 << __ANDROID_VENDOR_API_24Q2__;
+    maxNumberOfHidlHals = 0;
+    halInterfaces = allHidlManifestInterfaces();
   }
   if (halInterfaces.size() > maxNumberOfHidlHals) {
-    ADD_FAILURE() << "There are " << halInterfaces.size()
-                  << " HIDL interfaces served on the device. "
-                  << "These must be converted to AIDL as part of HIDL's "
-                     "deprecation processes.";
+    ADD_FAILURE()
+        << "There are " << halInterfaces.size()
+        << " HIDL interfaces served on the device. "
+        << "These must be converted to AIDL as part of HIDL's "
+           "deprecation processes.\n"
+           "NOTE: vts_treble_vintf_vendor_test should pass before this test. "
+           "Make sure the device under test is targeting "
+           "the correct Framework Compatibility Matrix with "
+           "target-level=\"202404\" or greater. That will cause "
+           "the framework/system HIDL services to stop being registered. "
+           "If those are still registered because the device is targeting "
+           "and older FCM, this test will fail.";
     for (const auto& interface : halInterfaces) {
       ADD_FAILURE() << interface << " registered as a HIDL interface "
                     << "but must be in AIDL";
diff --git a/treble/vintf/libvts_vintf_test_common/common.cpp b/treble/vintf/libvts_vintf_test_common/common.cpp
index 3c3fd19a..a09522fc 100644
--- a/treble/vintf/libvts_vintf_test_common/common.cpp
+++ b/treble/vintf/libvts_vintf_test_common/common.cpp
@@ -51,6 +51,7 @@ static const std::map<uint64_t /* Vendor API Level */, Level /* FCM Version */>
         {34, Level::U},
         // Starting from 2024Q2, vendor api level has YYYYMM format.
         {202404, Level::V},
+        {202504, Level::W},  // TODO(b/346861728) placeholder level
     }};
 
 android::base::Result<Level> GetFcmVersionFromApiLevel(uint64_t api_level) {
diff --git a/treble/vintf/utils.cpp b/treble/vintf/utils.cpp
index c749539d..c64828b8 100644
--- a/treble/vintf/utils.cpp
+++ b/treble/vintf/utils.cpp
@@ -113,7 +113,7 @@ ostream &operator<<(ostream &os, const NativeInstance &val) {
   return os;
 }
 
-uint64_t GetBoardApiLevel() {
+uint64_t GetVendorApiLevel() {
   return GetUintProperty<uint64_t>("ro.vendor.api_level", 0);
 }
 
diff --git a/treble/vintf/utils.h b/treble/vintf/utils.h
index cd89e16f..8b1c842d 100644
--- a/treble/vintf/utils.h
+++ b/treble/vintf/utils.h
@@ -95,6 +95,9 @@ struct AidlInstance : private ManifestInstance {
   std::optional<string> updatable_via_apex() const {
     return ManifestInstance::updatableViaApex();
   }
+  bool updatable_via_system() const {
+    return ManifestInstance::updatableViaSystem();
+  }
 
   string test_case_name() const;
 };
@@ -145,18 +148,10 @@ extern const map<string, string> kPackageRoot;
 // HALs that are allowed to be passthrough under Treble rules.
 extern const set<string> kPassthroughHals;
 
-// Read ro.vendor.api_level, that shows the minimum of the following two
-// values:
-// * First non-empty value for the board api level from the following
-// properties:
-// -- ro.board.api_level
-// -- ro.board.first_api_level
-// -- ro.vendor.build.version.sdk
-// * First non-empty value for the device api level from the following
-// properties:
-// -- ro.product.first_api_level
-// -- ro.build.version.sdk
-uint64_t GetBoardApiLevel();
+// Read ro.vendor.api_level
+// See `property_initialize_ro_vendor_api_level()` for details on how
+// this is calculated. In system/core/init/property_service.cpp.
+uint64_t GetVendorApiLevel();
 
 // For a given interface returns package root if known. Returns empty string
 // otherwise.
diff --git a/usb/usb/aidl/host/src/com/android/usb/vts/VtsAidlUsbHostTest.java b/usb/usb/aidl/host/src/com/android/usb/vts/VtsAidlUsbHostTest.java
index ee64b083..e5d1d905 100644
--- a/usb/usb/aidl/host/src/com/android/usb/vts/VtsAidlUsbHostTest.java
+++ b/usb/usb/aidl/host/src/com/android/usb/vts/VtsAidlUsbHostTest.java
@@ -43,6 +43,8 @@ public final class VtsAidlUsbHostTest extends BaseHostJUnit4Test {
 
     private static final String HAL_SERVICE = "android.hardware.usb.IUsb/default";
     private static final long CONN_TIMEOUT = 5000;
+    // Extra time to wait for device to be available after being NOT_AVAILABLE state.
+    private static final long EXTRA_RECOVERY_TIMEOUT = 1000;
 
     private static boolean mHasService;
 
@@ -105,10 +107,10 @@ public final class VtsAidlUsbHostTest extends BaseHostJUnit4Test {
         }
 
         RunUtil.getDefault().sleep(100);
-        while (!mReconnected.get() && System.currentTimeMillis() - startTime < CONN_TIMEOUT) {
+        while (!mReconnected.get() && System.currentTimeMillis() - startTime < CONN_TIMEOUT + EXTRA_RECOVERY_TIMEOUT) {
             RunUtil.getDefault().sleep(300);
         }
 
-        Assert.assertTrue("usb not reconnect", mReconnected.get());
+        Assert.assertTrue("USB port did not reconnect within 6000ms timeout.", mReconnected.get());
     }
 }
```

