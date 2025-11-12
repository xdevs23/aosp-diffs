```diff
diff --git a/avb/VtsSecurityAvbTest.cpp b/avb/VtsSecurityAvbTest.cpp
index e262675..ee0c323 100644
--- a/avb/VtsSecurityAvbTest.cpp
+++ b/avb/VtsSecurityAvbTest.cpp
@@ -476,10 +476,15 @@ TEST(AvbTest, SystemDescriptor) {
   }
   // https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity#optional-parameters
   std::set<std::string> opt_params = {
-      "check_at_most_once",
       "ignore_corruption",
-      "ignore_zero_blocks",
       "restart_on_corruption",
+      "panic_on_corruption",
+      "restart_on_error",
+      "panic_on_error",
+      "ignore_zero_blocks",
+      "check_at_most_once",
+      "root_hash_sig_key_desc",
+      "try_verify_in_tasklet"
   };
   // https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity#optional-fec-forward-error-correction-parameters
   std::map<std::string, std::string> opt_fec_params = {
diff --git a/avb/vts_built_with_ddk_test.cpp b/avb/vts_built_with_ddk_test.cpp
index 734b299..9ee9e4f 100644
--- a/avb/vts_built_with_ddk_test.cpp
+++ b/avb/vts_built_with_ddk_test.cpp
@@ -291,15 +291,17 @@ TEST_F(BuiltWithDdkTest, VendorBootModules) {
   if (!std::filesystem::exists(vendor_boot_path)) {
     GTEST_SKIP() << "Boot path " << vendor_boot_path << " does not exist.";
   }
-  const auto extracted_vendor_ramdisk =
-      android::ExtractVendorRamdiskToDirectory(vendor_boot_path);
+  const auto extracted_vendor_ramdisks =
+      android::ExtractVendorRamdisks(vendor_boot_path);
 
-  ASSERT_TRUE(extracted_vendor_ramdisk.ok())
+  ASSERT_TRUE(extracted_vendor_ramdisks.ok())
       << "Failed to extract vendor_ramdisk: "
-      << extracted_vendor_ramdisk.error();
+      << extracted_vendor_ramdisks.error();
 
-  InspectExtractedRamdisk((*extracted_vendor_ramdisk)->path,
-                          ack_modules_.value());
+  for (const auto& extracted_vendor_ramdisk : *extracted_vendor_ramdisks) {
+    InspectExtractedRamdisk(extracted_vendor_ramdisk->path,
+                            ack_modules_.value());
+  }
 }
 
 }  // namespace
diff --git a/gbl/Android.bp b/gbl/Android.bp
new file mode 100644
index 0000000..e335a52
--- /dev/null
+++ b/gbl/Android.bp
@@ -0,0 +1,40 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+    default_team: "trendy_team_android_kernel",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_test_host {
+    name: "VtsGblHostTest",
+    srcs: ["java/**/*.java"],
+    static_libs: [
+        "hamcrest-library",
+    ],
+    libs: [
+        "tradefed",
+        "compatibility-tradefed",
+    ],
+    data: [
+        ":gbl_keystore_keys",
+    ],
+    data_native_bins: [
+        "gblsigntool",
+    ],
+    test_suites: [
+        "general-tests",
+        "vts",
+    ],
+}
diff --git a/gbl/AndroidTest.xml b/gbl/AndroidTest.xml
new file mode 100644
index 0000000..781e31c
--- /dev/null
+++ b/gbl/AndroidTest.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Runs VtsGblHostTest">
+    <object type="module_controller" class="com.android.tradefed.testtype.suite.module.ShippingApiLevelModuleController">
+        <option name="vsr-min-api-level" value="202504" />
+    </object>
+
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer" />
+
+    <test class="com.android.tradefed.testtype.HostTest" >
+        <option name="class" value="com.android.test.gbl.VtsGblHostTest" />
+    </test>
+</configuration>
diff --git a/gbl/OWNERS b/gbl/OWNERS
new file mode 100644
index 0000000..59a1394
--- /dev/null
+++ b/gbl/OWNERS
@@ -0,0 +1,4 @@
+rammuthiah@google.com
+yochiang@google.com
+
+include platform/bootable/libbootloader:/gbl/OWNERS
diff --git a/gbl/README.md b/gbl/README.md
new file mode 100644
index 0000000..8950327
--- /dev/null
+++ b/gbl/README.md
@@ -0,0 +1,19 @@
+# GBL Compliance Requirement Test
+
+Host-driven test that checks device properties when booted with GBL.
+
+## Manual instructions (2025Q2)
+
+Per 2025Q2 requirements, GBL is strongly recommended. To test device
+compatibility with GBL:
+
+1.  Reboot device to bootloader mode then flash the officially signed GBL image
+    to the `efisp` partition.
+2.  Reboot device to Android userspace. It is expected to be booted with GBL.
+3.  Run the test `atest VtsGblHostTest`.
+4.  (Optional) Restore device to its original bootloader.
+    1.  Reboot to bootloader mode. Since we were booting with GBL, this should
+        be the fastboot interface provided by GBL.
+    2.  Erase the `efisp` partition with `fastboot erase efisp` then reboot.
+    3.  Since GBL is wiped, device should be booted with its original bootloader
+        (e.g. ABL) and GBL-specific properties should no longer be present.
diff --git a/gbl/data/Android.bp b/gbl/data/Android.bp
new file mode 100644
index 0000000..20b5ce6
--- /dev/null
+++ b/gbl/data/Android.bp
@@ -0,0 +1,23 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+    default_team: "trendy_team_android_kernel",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+filegroup {
+    name: "gbl_keystore_keys",
+    srcs: ["**/*"],
+}
diff --git a/gbl/data/gbl/202504/gbl_key.x509.pem b/gbl/data/gbl/202504/gbl_key.x509.pem
new file mode 100644
index 0000000..0e6f830
--- /dev/null
+++ b/gbl/data/gbl/202504/gbl_key.x509.pem
@@ -0,0 +1,29 @@
+-----BEGIN CERTIFICATE-----
+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
+XVY=
+-----END CERTIFICATE-----
diff --git a/gbl/data/gbl/202504/gbl_key_pub.pem b/gbl/data/gbl/202504/gbl_key_pub.pem
new file mode 100644
index 0000000..b9894a1
--- /dev/null
+++ b/gbl/data/gbl/202504/gbl_key_pub.pem
@@ -0,0 +1,14 @@
+-----BEGIN PUBLIC KEY-----
+MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqCN2o7MDR7R4CTTCt+/C
+gxXJerwPWwViVSdy/UchsgziI4fHIDRELzQNCfXpiN63FxIfUH8a0kXY98g25FX7
+1WiRwEMWi9COUe41Q45d9IP6urbNTxUUM/vl/v/d2aiZ3VHzB36GhDLmwczA8u/g
+4TY6n1uBwbijn54beCFD+kDw0Ds916RhF2H7vRHJnIHsVO/w2R/gGeg+GLFalBoq
+tXYXd5Y/PcKQaVe2cbqC+Wvc9duCV1jHv7x1/n97WFxbpKmObFucFWTi4aUVZMu3
+DFHM1VEYsJwxPCDTkl8m8XzM4V2YE89DrsFOjorkH2BZm1AGMLuW0AWU/0UvhHyF
+ZO4n00E6P54KbKMxXKb5LwzawHD8nQznbyM/Zt2nQIlG1fr6DlXgzdpih/Y2pUQH
+zwlABi+D+CrtUv7mRypmr/PRhHntm0kcPnuzJvGvSFaVHgDv6V5zq7/x5pguKRL3
+b/Jh80oSBm0G7tqri/1zksXqklo9UYPh9c15IXa2rFl+2aYjinHiHHoL+PfRAK8D
+hwyC5ssngcEfoPqrFYbLHsz4I8VS28DwV6YHaXXErVsgJCboD2JDElBBzfNhAW/5
+SZtoGkY5dfShpXh/t1aqjQ96b16HVMUUskv5cbiN8cKxpvChJG2UWXT7YGir7EbH
+cg6DNB1la5Az3DLTi3UxeXUCAwEAAQ==
+-----END PUBLIC KEY-----
diff --git a/gbl/java/com/android/test/gbl/VtsGblHostTest.java b/gbl/java/com/android/test/gbl/VtsGblHostTest.java
new file mode 100644
index 0000000..688c920
--- /dev/null
+++ b/gbl/java/com/android/test/gbl/VtsGblHostTest.java
@@ -0,0 +1,115 @@
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
+package com.android.test.gbl;
+
+import static org.hamcrest.CoreMatchers.not;
+import static org.hamcrest.Matchers.matchesPattern;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertThat;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assume.assumeThat;
+
+import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
+import com.android.tradefed.util.CommandResult;
+import com.android.tradefed.util.CommandStatus;
+import com.android.tradefed.util.FileUtil;
+import com.android.tradefed.util.RunUtil;
+import java.io.File;
+import java.io.IOException;
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(DeviceJUnit4ClassRunner.class)
+public class VtsGblHostTest extends BaseHostJUnit4Test {
+    private File mTempDir;
+    private CompatibilityBuildHelper mBuildHelper;
+
+    @Before
+    public final void setUp() throws DeviceNotAvailableException, IOException {
+        ITestDevice device = getDevice();
+        final long gblVersion = device.getIntProperty("ro.boot.gbl.version", -1L);
+        assumeThat("GBL version prop", gblVersion, not(-1L));
+
+        mTempDir = FileUtil.createTempDir("VtsGblHostTest");
+        mBuildHelper = new CompatibilityBuildHelper(getBuild());
+    }
+
+    @After
+    public final void tearDown() {
+        FileUtil.recursiveDelete(mTempDir);
+    }
+
+    private CommandResult logCommandResult(final String name, final CommandResult result) {
+        CLog.i("Result of command: %s", name);
+        CLog.i("Status: %s", result.getStatus());
+        CLog.i("Exit code: %s", result.getExitCode());
+        CLog.i("Stdout: %s", result.getStdout());
+        CLog.i("Stderr: %s", result.getStderr());
+        return result;
+    }
+
+    @Test
+    public void testSystemProperties() throws DeviceNotAvailableException, NumberFormatException {
+        ITestDevice device = getDevice();
+        final long gblVersion = device.getIntProperty("ro.boot.gbl.version", -1);
+        final String gblBuildNumber = device.getProperty("ro.boot.gbl.build_number");
+
+        CLog.i("GBL version: %s", gblVersion);
+        CLog.i("GBL build_number: %s", gblBuildNumber);
+
+        assertNotNull(gblBuildNumber);
+
+        if (gblBuildNumber.startsWith("eng.")) {
+            CLog.w("GBL is a local eng build");
+        }
+
+        assertThat("Invalid build ID", gblBuildNumber, matchesPattern("P?[0-9]+"));
+
+        if (gblBuildNumber.startsWith("P")) {
+            CLog.i("Skipping rest of test because GBL is presubmit build");
+            return;
+        }
+    }
+
+    @Test
+    public void testCertificate() throws DeviceNotAvailableException, IOException {
+        ITestDevice device = getDevice();
+        File bootEfi = new File(mTempDir, "boot.efi");
+        assertTrue("Pull efisp partition", device.pullFile("/dev/block/by-name/efisp", bootEfi));
+
+        File gblsigntool = mBuildHelper.getTestFile("gblsigntool");
+        File gblPublicKey = new File(mBuildHelper.getTestFile("gbl"), "202504/gbl_key_pub.pem");
+
+        CommandResult result = logCommandResult("gblsigntool info",
+                new RunUtil().runTimedCmd(
+                        5000, gblsigntool.getAbsolutePath(), "info", bootEfi.getAbsolutePath()));
+        assertEquals("gblsigntool info command", CommandStatus.SUCCESS, result.getStatus());
+
+        result = logCommandResult("gblsigntool verify",
+                new RunUtil().runTimedCmd(5000, gblsigntool.getAbsolutePath(), "verify",
+                        bootEfi.getAbsolutePath(), "--key", gblPublicKey.getAbsolutePath()));
+        assertEquals("gblsigntool verify command", CommandStatus.SUCCESS, result.getStatus());
+    }
+}
diff --git a/system_property/Android.bp b/system_property/Android.bp
index e9d6828..526f3ac 100644
--- a/system_property/Android.bp
+++ b/system_property/Android.bp
@@ -29,9 +29,6 @@ python_test_host {
         "vndk_utils",
         "vts_vndk_utils",
     ],
-    data: [
-        ":private_property_contexts",
-    ],
     test_suites: [
         "vts",
     ],
diff --git a/system_property/vts_treble_sys_prop_test.py b/system_property/vts_treble_sys_prop_test.py
index 56314e0..783a2a1 100644
--- a/system_property/vts_treble_sys_prop_test.py
+++ b/system_property/vts_treble_sys_prop_test.py
@@ -93,8 +93,6 @@ class VtsTrebleSysPropTest(unittest.TestCase):
 
     Attributes:
         _temp_dir: The temporary directory to which necessary files are copied.
-        _PUBLIC_PROPERTY_CONTEXTS_FILE_PATH:  The path of public property
-                                              contexts file.
         _SYSTEM_PROPERTY_CONTEXTS_FILE_PATH:  The path of system property
                                               contexts file.
         _PRODUCT_PROPERTY_CONTEXTS_FILE_PATH: The path of product property
@@ -115,7 +113,6 @@ class VtsTrebleSysPropTest(unittest.TestCase):
             "vendor_" or "odm_", but these are exceptions.
     """
 
-    _PUBLIC_PROPERTY_CONTEXTS_FILE_PATH  = ("private/property_contexts")
     _SYSTEM_PROPERTY_CONTEXTS_FILE_PATH  = ("/system/etc/selinux/"
                                             "plat_property_contexts")
     _PRODUCT_PROPERTY_CONTEXTS_FILE_PATH = ("/product/etc/selinux/"
@@ -384,48 +381,6 @@ class VtsTrebleSysPropTest(unittest.TestCase):
             typename.startswith(self._ODM_TYPE_PREFIX) or
             typename in self._VENDOR_OR_ODM_WHITELISTED_TYPES)
 
-    def testExportedPlatformPropertyIntegrity(self):
-        """Ensures public property contexts isn't modified at all.
-
-        Public property contexts must not be modified.
-        """
-        logging.info("Checking existence of %s",
-                     self._SYSTEM_PROPERTY_CONTEXTS_FILE_PATH)
-        self.AssertPermissionsAndExistence(
-            self._SYSTEM_PROPERTY_CONTEXTS_FILE_PATH,
-            IsReadable)
-
-        # Pull system property contexts file from device.
-        self.dut.AdbPull(self._SYSTEM_PROPERTY_CONTEXTS_FILE_PATH,
-                          self._temp_dir)
-        logging.info("Adb pull %s to %s",
-                     self._SYSTEM_PROPERTY_CONTEXTS_FILE_PATH, self._temp_dir)
-
-        with open(os.path.join(self._temp_dir, "plat_property_contexts"),
-                  "r") as property_contexts_file:
-            sys_property_dict = self._ParsePropertyDictFromPropertyContextsFile(
-                property_contexts_file, True)
-        logging.info(
-            "Found %d exact-matching properties "
-            "in system property contexts", len(sys_property_dict))
-
-        # Extract data from parfile.
-        resource_name = os.path.basename(self._PUBLIC_PROPERTY_CONTEXTS_FILE_PATH)
-        package_name = os.path.dirname(
-            self._PUBLIC_PROPERTY_CONTEXTS_FILE_PATH).replace(os.path.sep, '.')
-        with resources.files(package_name).joinpath(resource_name).open('r') \
-            as resource:
-            pub_property_dict = self._ParsePropertyDictFromPropertyContextsFile(
-                resource, True)
-        for name in pub_property_dict:
-            public_tokens = pub_property_dict[name]
-            self.assertTrue(name in sys_property_dict,
-                               "Exported property (%s) doesn't exist" % name)
-            system_tokens = sys_property_dict[name]
-            self.assertEqual(public_tokens, system_tokens,
-                                "Exported property (%s) is modified" % name)
-
-
     def AssertPermissionsAndExistence(self, path, check_permission):
         """Asserts that the specified path exists and has the correct permission.
         Args:
```

