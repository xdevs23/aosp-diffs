```diff
diff --git a/neuralnetworks/V1_2/benchmark/java/Android.bp b/neuralnetworks/V1_2/benchmark/java/Android.bp
index 0f3ce9f0..d9924921 100644
--- a/neuralnetworks/V1_2/benchmark/java/Android.bp
+++ b/neuralnetworks/V1_2/benchmark/java/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_renderscript_nnapi",
     // See: http://go/android-license-faq
     default_applicable_licenses: [
         "Android-Apache-2.0",
diff --git a/neuralnetworks/V1_3/benchmark/java/Android.bp b/neuralnetworks/V1_3/benchmark/java/Android.bp
index bbc8200c..b1cf9ec3 100644
--- a/neuralnetworks/V1_3/benchmark/java/Android.bp
+++ b/neuralnetworks/V1_3/benchmark/java/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_renderscript_nnapi",
     // See: http://go/android-license-faq
     default_applicable_licenses: [
         "Android-Apache-2.0",
diff --git a/treble/platform_version/Android.bp b/treble/platform_version/Android.bp
index b383d0e1..9a59e772 100644
--- a/treble/platform_version/Android.bp
+++ b/treble/platform_version/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/treble/platform_version/vts_treble_platform_version_test.py b/treble/platform_version/vts_treble_platform_version_test.py
index f879af81..46730c38 100644
--- a/treble/platform_version/vts_treble_platform_version_test.py
+++ b/treble/platform_version/vts_treble_platform_version_test.py
@@ -90,10 +90,12 @@ class VtsTreblePlatformVersionTest(unittest.TestCase):
             asserts.fail("Unexpected value returned from getprop: %s" % e)
 
     def testVndkVersion(self):
-        """Test that VNDK version is specified.
+        """Test that VNDK version is specified only when ro.board.api_level is
+        not set because some devices that have ro.board.api_level may unset
+        ro.vndk.version.
 
-        If ro.vndk.version is not defined on boot, GSI sets LD_CONFIG_FILE to
-        temporary configuration file and ro.vndk.version to default value.
+        ro.vndk.version is deprecated in 202404. Test if the version is not
+        defined in that case.
         """
 
         boardApiLevelStr = self.getProp("ro.board.api_level", required=False)
@@ -104,8 +106,6 @@ class VtsTreblePlatformVersionTest(unittest.TestCase):
                 boardApiLevel = int(boardApiLevelStr)
                 if boardApiLevel >= 202404:
                     self.assertIsNone(vndkVersion, "VNDK version is defined")
-                else:
-                    self.assertIsNotNone(vndkVersion, "VNDK version is not defined")
             except ValueError as e:
                 asserts.fail("Unexpected value returned from ro.board.api_level: %s" % e)
         else:
diff --git a/treble/vintf/Android.bp b/treble/vintf/Android.bp
index c2f50f59..f2cefdea 100644
--- a/treble/vintf/Android.bp
+++ b/treble/vintf/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/treble/vintf/DeviceManifestTest.cpp b/treble/vintf/DeviceManifestTest.cpp
index 7c959887..b3061aa6 100644
--- a/treble/vintf/DeviceManifestTest.cpp
+++ b/treble/vintf/DeviceManifestTest.cpp
@@ -49,6 +49,25 @@ TEST_F(DeviceManifestTest, ShippingFcmVersion) {
   ASSERT_RESULT_OK(res);
 }
 
+// Check for unused HALs being declared. Every HAL that is declared in the vintf
+// Manifest must have an entry in the Compatibility Matrix
+TEST_F(DeviceManifestTest, UnusedHals) {
+  auto vintfObject = VintfObject::GetInstance();
+  auto res = vintfObject->checkUnusedHals({});
+
+  if (!res.ok()) {
+    uint64_t vendor_api_level = GetVendorApiLevel();
+    if (vendor_api_level < 202504) {
+      GTEST_LOG_(ERROR) << res.error();
+      GTEST_SKIP()
+          << "Not enforcing this so that existing devices can continue "
+             "to pass without changes";
+    } else {
+      ADD_FAILURE() << res.error();
+    }
+  }
+}
+
 // Tests that deprecated HALs are not in the manifest, unless a higher,
 // non-deprecated minor version is in the manifest.
 // @VsrTest = VSR-3.2-014
@@ -68,10 +87,17 @@ TEST_F(DeviceManifestTest, GraphicsMapperHalVersionCompatibility) {
   Level shipping_fcm_version = VintfObject::GetDeviceHalManifest()->level();
   bool is_go_device =
       android::base::GetBoolProperty("ro.config.low_ram", false);
-  if (shipping_fcm_version == Level::UNSPECIFIED ||
-      shipping_fcm_version < Level::R ||
-      (is_go_device && shipping_fcm_version < Level::V)) {
-    GTEST_SKIP() << "Graphics mapper 4 is only required on launching R devices";
+  const auto sdkLevel =
+      android::base::GetUintProperty<uint64_t>("ro.build.version.sdk", 10000);
+  // API 36+ requires mapper4.0 or newer regardless of the initial shipping
+  // version
+  if (sdkLevel < 36) {
+    if (shipping_fcm_version == Level::UNSPECIFIED ||
+        shipping_fcm_version < Level::R ||
+        (is_go_device && shipping_fcm_version < Level::V)) {
+      GTEST_SKIP()
+          << "Graphics mapper 4 is only required on launching R devices";
+    }
   }
 
   if (shipping_fcm_version >= Level::V) {
diff --git a/treble/vintf/SingleManifestTest.cpp b/treble/vintf/SingleManifestTest.cpp
index 618d33ec..3b23c2d3 100644
--- a/treble/vintf/SingleManifestTest.cpp
+++ b/treble/vintf/SingleManifestTest.cpp
@@ -653,9 +653,8 @@ static std::vector<std::string> halsUpdatableViaSystem() {
   std::vector<std::string> hals = {};
   // The KeyMint HALs connecting to the Trusty VM in the system image are
   // supposed to be enabled in vendor init when the system property
-  // |ro.hardware.security.keymint.trusty.system| is set to true in W.
-  if (base::GetBoolProperty("ro.hardware.security.keymint.trusty.system",
-                            false)) {
+  // |trusty.security_vm.keymint.enabled| is set to true in W.
+  if (base::GetBoolProperty("trusty.security_vm.keymint.enabled", false)) {
     hals.push_back("android.hardware.security.keymint.IKeyMintDevice/default");
     hals.push_back(
         "android.hardware.security.keymint.IRemotelyProvisionedComponent/"
diff --git a/usb/OWNERS b/usb/OWNERS
index 21aef715..0aa06c44 100644
--- a/usb/OWNERS
+++ b/usb/OWNERS
@@ -1,10 +1,10 @@
 # Bug component: 175220
 
-aprasath@google.com
-kumarashishg@google.com
-sarup@google.com
 anothermark@google.com
+febinthattil@google.com
+aprasath@google.com
 badhri@google.com
 albertccwang@google.com
 rickyniu@google.com
 khoahong@google.com
+kumarashishg@google.com
\ No newline at end of file
diff --git a/usb/gadget/V1_0/host/Android.bp b/usb/gadget/V1_0/host/Android.bp
index 47d1b92b..41927e70 100644
--- a/usb/gadget/V1_0/host/Android.bp
+++ b/usb/gadget/V1_0/host/Android.bp
@@ -14,6 +14,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_usb",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/usb/gadget/V1_0/host/src/com/android/tests/usbgadget/HalUsbGadgetV1_0HostTest.java b/usb/gadget/V1_0/host/src/com/android/tests/usbgadget/HalUsbGadgetV1_0HostTest.java
index 43c1f0b4..8f2fbd01 100644
--- a/usb/gadget/V1_0/host/src/com/android/tests/usbgadget/HalUsbGadgetV1_0HostTest.java
+++ b/usb/gadget/V1_0/host/src/com/android/tests/usbgadget/HalUsbGadgetV1_0HostTest.java
@@ -113,7 +113,7 @@ public class HalUsbGadgetV1_0HostTest extends BaseHostJUnit4Test {
         assumeTrue(String.format("The device doesn't have service %s", HAL_SERVICE), mHasService);
         getDevice().executeShellCommand("svc usb setFunctions mtp true");
         RunUtil.getDefault().sleep(WAIT_TIME);
-        assertTrue("MTP not present", checkProtocol(6, 1, 1));
+        assertTrue("MTP not present", checkProtocol(6, 1, 1) || checkProtocol(255, 255, 0));
     }
 
     /**
diff --git a/usb/gadget/V1_1/host/Android.bp b/usb/gadget/V1_1/host/Android.bp
index 14604ad9..7fdcff82 100644
--- a/usb/gadget/V1_1/host/Android.bp
+++ b/usb/gadget/V1_1/host/Android.bp
@@ -14,6 +14,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_usb",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/usb/gadget/V1_2/host/Android.bp b/usb/gadget/V1_2/host/Android.bp
index 7d71cb46..fa481a98 100644
--- a/usb/gadget/V1_2/host/Android.bp
+++ b/usb/gadget/V1_2/host/Android.bp
@@ -14,6 +14,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_usb",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/usb/gadget/aidl/host/Android.bp b/usb/gadget/aidl/host/Android.bp
index fae3b522..698ffa5c 100644
--- a/usb/gadget/aidl/host/Android.bp
+++ b/usb/gadget/aidl/host/Android.bp
@@ -14,6 +14,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_usb",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/usb/gadget/aidl/host/src/com/android/usb/gadget/vts/VtsHalUsbGadgetV2_0HostTest.java b/usb/gadget/aidl/host/src/com/android/usb/gadget/vts/VtsHalUsbGadgetV2_0HostTest.java
index 3f036c79..6131932d 100644
--- a/usb/gadget/aidl/host/src/com/android/usb/gadget/vts/VtsHalUsbGadgetV2_0HostTest.java
+++ b/usb/gadget/aidl/host/src/com/android/usb/gadget/vts/VtsHalUsbGadgetV2_0HostTest.java
@@ -211,9 +211,7 @@ public final class VtsHalUsbGadgetV2_0HostTest extends BaseHostJUnit4Test {
         CLog.i("testGetUsbSpeed on device [%s]", deviceSerialNumber);
 
         String output = mDevice.executeShellCommand("svc usb getUsbSpeed");
-        int speed = Integer.parseInt(output.trim());
-
-        Assert.assertNotNull("There is no USB enumeration", speed);
+        int unused = Integer.parseInt(output.trim());
     }
 
     /**
diff --git a/usb/usb/aidl/host/Android.bp b/usb/usb/aidl/host/Android.bp
index 02ebf29e..044da263 100644
--- a/usb/usb/aidl/host/Android.bp
+++ b/usb/usb/aidl/host/Android.bp
@@ -14,6 +14,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_usb",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
```

