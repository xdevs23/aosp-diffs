```diff
diff --git a/tests/gpu_test/OWNERS b/tests/gpu_test/OWNERS
index 528bf6e44..52214e58e 100644
--- a/tests/gpu_test/OWNERS
+++ b/tests/gpu_test/OWNERS
@@ -4,5 +4,4 @@ chrisforbes@google.com
 cnorthrop@google.com
 ianelliott@google.com
 lpy@google.com
-vantablack@google.com
 kocdemir@google.com
diff --git a/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java b/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java
index 50005d3fe..fd01cf06c 100644
--- a/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java
+++ b/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java
@@ -387,7 +387,7 @@ public class VulkanTest extends BaseHostJUnit4Test {
 
         for (JSONObject device : mVulkanDevices) {
             if (device.getJSONObject("properties").getInt("deviceType")
-                    != VK_PHYSICAL_DEVICE_TYPE_CPU) {
+                    == VK_PHYSICAL_DEVICE_TYPE_CPU) {
                 continue;
             }
 
diff --git a/tests/kernel_proc_file_api_test/proc_tests/ProcMiscTest.py b/tests/kernel_proc_file_api_test/proc_tests/ProcMiscTest.py
index 95bfafa9e..8cb6470ee 100644
--- a/tests/kernel_proc_file_api_test/proc_tests/ProcMiscTest.py
+++ b/tests/kernel_proc_file_api_test/proc_tests/ProcMiscTest.py
@@ -24,13 +24,17 @@ class ProcMisc(KernelProcFileTestBase.KernelProcFileTestBase):
     '''
 
     t_ignore = ' '
+    # t_DRIVERNAME is different from t_STRING in that it
+    # also allowes forward slash, which is sometime present
+    # in the name
+    t_DRIVERNAME = r'[a-zA-Z\(\)_0-9\-/.@]+'
 
     start = 'drivers'
 
     p_drivers = repeat_rule('driver')
 
     def p_line(self, p):
-        'driver : NUMBER STRING NEWLINE'
+        'driver : NUMBER DRIVERNAME NEWLINE'
         p[0] = [p[1], p[2]]
 
     def get_path(self):
diff --git a/tests/kernel_proc_file_api_test/proc_tests/ProcQtaguidCtrlTest.py b/tests/kernel_proc_file_api_test/proc_tests/ProcQtaguidCtrlTest.py
deleted file mode 100644
index 7e1ee1001..000000000
--- a/tests/kernel_proc_file_api_test/proc_tests/ProcQtaguidCtrlTest.py
+++ /dev/null
@@ -1,106 +0,0 @@
-#
-# Copyright (C) 2020 The Android Open Source Project
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
-import logging
-import re
-
-from proc_tests import KernelProcFileTestBase
-import target_file_utils
-
-
-class ProcQtaguidCtrlTest(KernelProcFileTestBase.KernelProcFileTestBase):
-    '''/proc/net/xt_qtaguid/ctrl provides information about tagged sockets.
-
-    File content consists of possibly several lines of socket info followed by a
-    single line of events info, followed by a terminating newline.'''
-
-    def parse_contents(self, contents):
-        result = []
-        lines = contents.split('\n')
-        if len(lines) == 0 or lines[-1] != '':
-            raise SyntaxError
-        for line in lines[:-2]:
-            parsed = self.parse_line(
-                "sock={:x} tag=0x{:x} (uid={:d}) pid={:d} f_count={:d}", line)
-            if any(map(lambda x: x < 0, parsed)):
-                raise SyntaxError("Negative numbers not allowed!")
-            result.append(parsed)
-        parsed = self.parse_line(
-            "events: sockets_tagged={:d} sockets_untagged={:d} counter_set_changes={:d} "
-            "delete_cmds={:d} iface_events={:d} match_calls={:d} match_calls_prepost={:d} "
-            "match_found_sk={:d} match_found_sk_in_ct={:d} match_found_no_sk_in_ct={:d} "
-            "match_no_sk={:d} match_no_sk_{:w}={:d}", lines[-2])
-        if parsed[-2] not in {"file", "gid"}:
-            raise SyntaxError("match_no_sk_{file|gid} incorrect")
-        del parsed[-2]
-        if any(map(lambda x: x < 0, parsed)):
-            raise SyntaxError("Negative numbers not allowed!")
-        result.append(parsed)
-        return result
-
-    def get_path(self):
-        return "/proc/net/xt_qtaguid/ctrl"
-
-    def file_optional(self, shell=None, dut=None):
-        """Specifies if the /proc/net/xt_qtaguid/ctrl file is mandatory.
-
-        For device running kernel 4.9 or above, it should use the eBPF cgroup
-        filter to monitor networking stats instead. So it may not have
-        xt_qtaguid module and /proc/net/xt_qtaguid/ctrl file on device.
-        But for device that still has xt_qtaguid module, this file is mandatory.
-
-        Same logic as checkKernelSupport in file:
-        test/vts-testcase/kernel/api/qtaguid/SocketTagUserSpace.cpp
-
-        Returns:
-            True when the kernel is 4.9 or newer, otherwise False is returned
-        """
-        (version, patchlevel, sublevel) = self._kernel_version(dut)
-        if version == 4 and patchlevel >= 9 or version > 4:
-            return True
-        else:
-            return False
-
-    def _kernel_version(self, dut):
-        """Gets the kernel version from the device.
-
-        This method reads the output of command "uname -r" from the device.
-
-        Returns:
-            A tuple of kernel version information
-            in the format of (version, patchlevel, sublevel).
-
-            It will fail if failed to get the output or correct format
-            from the output of "uname -r" command
-        """
-        cmd = 'uname -r'
-        out, _, _ = dut.shell.Execute(cmd)
-        out = out.strip()
-
-        match = re.match(r"(\d+)\.(\d+)\.(\d+)", out)
-        if match is None:
-            raise RuntimeError("Failed to detect kernel version of device. out:%s" % out)
-
-        version = int(match.group(1))
-        patchlevel = int(match.group(2))
-        sublevel = int(match.group(3))
-        logging.info("Detected kernel version: %s", match.group(0))
-        return (version, patchlevel, sublevel)
-
-    def get_permission_checker(self):
-        """Get r/w file permission checker.
-        """
-        return target_file_utils.IsReadWrite
diff --git a/tests/kernel_proc_file_api_test/vts_kernel_proc_file_api_test.py b/tests/kernel_proc_file_api_test/vts_kernel_proc_file_api_test.py
index 88cdc3025..e2d17599d 100644
--- a/tests/kernel_proc_file_api_test/vts_kernel_proc_file_api_test.py
+++ b/tests/kernel_proc_file_api_test/vts_kernel_proc_file_api_test.py
@@ -32,7 +32,6 @@ from proc_tests import ProcMapsTest
 from proc_tests import ProcMiscTest
 from proc_tests import ProcMemInfoTest
 from proc_tests import ProcModulesTest
-from proc_tests import ProcQtaguidCtrlTest
 from proc_tests import ProcRemoveUidRangeTest
 from proc_tests import ProcSimpleFileTests
 from proc_tests import ProcShowUidStatTest
@@ -60,7 +59,6 @@ TEST_OBJECTS = {
     ProcMiscTest.ProcMisc(),
     ProcMemInfoTest.ProcMemInfoTest(),
     ProcModulesTest.ProcModulesTest(),
-    ProcQtaguidCtrlTest.ProcQtaguidCtrlTest(),
     ProcRemoveUidRangeTest.ProcRemoveUidRangeTest(),
     ProcSimpleFileTests.ProcCorePattern(),
     ProcSimpleFileTests.ProcCorePipeLimit(),
diff --git a/tools/vts-core-tradefed/Android.bp b/tools/vts-core-tradefed/Android.bp
index d54fd84b4..0acc29df5 100644
--- a/tools/vts-core-tradefed/Android.bp
+++ b/tools/vts-core-tradefed/Android.bp
@@ -35,7 +35,7 @@ tradefed_binary_host {
     wrapper: "etc/vts-tradefed",
     short_name: "VTS",
     full_name: "Vendor Test Suite",
-    version: "15_r1",
+    version: "15_r2",
     static_libs: [
         "vts-core-tradefed-harness",
         "cts-tradefed-harness",
diff --git a/tools/vts-core-tradefed/res/config/vts-presubmit.xml b/tools/vts-core-tradefed/res/config/vts-presubmit.xml
index 0d670c51e..6920f49a4 100644
--- a/tools/vts-core-tradefed/res/config/vts-presubmit.xml
+++ b/tools/vts-core-tradefed/res/config/vts-presubmit.xml
@@ -21,7 +21,6 @@
   <option name="test-tag" value="vts-presubmit" />
 
   <option name="compatibility:include-filter" value="VtsHalAudioV4_0TargetTest" />
-  <option name="compatibility:include-filter" value="VtsHalBluetoothA2dpV1_0TargetTest" />
   <option name="compatibility:include-filter" value="VtsHalMediaOmxV1_0TargetComponentTest" />
   <option name="compatibility:include-filter" value="VtsHalMediaOmxV1_0TargetAudioEncTest" />
   <option name="compatibility:include-filter" value="VtsHalMediaOmxV1_0TargetAudioDecTest" />
```

