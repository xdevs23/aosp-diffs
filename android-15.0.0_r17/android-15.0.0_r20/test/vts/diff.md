```diff
diff --git a/tests/fastboot_getvar/Android.bp b/tests/fastboot_getvar/Android.bp
index ffc90eba0..08d1cbe25 100644
--- a/tests/fastboot_getvar/Android.bp
+++ b/tests/fastboot_getvar/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/tests/fastboot_test/Android.bp b/tests/fastboot_test/Android.bp
index 6baec3c73..5f43a8c57 100644
--- a/tests/fastboot_test/Android.bp
+++ b/tests/fastboot_test/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/tests/firmware_dtbo_test/Android.bp b/tests/firmware_dtbo_test/Android.bp
index 1a6d7ef4b..12b77a938 100644
--- a/tests/firmware_dtbo_test/Android.bp
+++ b/tests/firmware_dtbo_test/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/tests/firmware_test/Android.bp b/tests/firmware_test/Android.bp
index bff7b7647..0734a04e1 100644
--- a/tests/firmware_test/Android.bp
+++ b/tests/firmware_test/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/tests/gpu_test/src/com/android/gpu/vts/Build.java b/tests/gpu_test/src/com/android/gpu/vts/Build.java
index 08953fef4..f3219cd64 100644
--- a/tests/gpu_test/src/com/android/gpu/vts/Build.java
+++ b/tests/gpu_test/src/com/android/gpu/vts/Build.java
@@ -52,5 +52,7 @@ public class Build {
     public static final int TM = 33; // provisional
     public static final int UDC = 34; // provisional
     // vendor api levels are decoupled from the SDK version in Android VIC
+    // Levels are named after the first platform release to employ them.
     public static final int VENDOR_24Q2 = 202404;
+    public static final int VENDOR_25Q2 = 202504;
 }
diff --git a/tests/gpu_test/src/com/android/gpu/vts/OpenGlEsTest.java b/tests/gpu_test/src/com/android/gpu/vts/OpenGlEsTest.java
index a55683ef5..592de7e77 100644
--- a/tests/gpu_test/src/com/android/gpu/vts/OpenGlEsTest.java
+++ b/tests/gpu_test/src/com/android/gpu/vts/OpenGlEsTest.java
@@ -54,10 +54,15 @@ public class OpenGlEsTest extends BaseHostJUnit4Test {
                 requiredOpenGlEsDeqpLevel = VulkanTest.DEQP_LEVEL_FOR_T;
                 break;
             case Build.VENDOR_24Q2:
+            case Build.VENDOR_25Q2:
                 requiredOpenGlEsDeqpLevel = VulkanTest.DEQP_LEVEL_FOR_V;
                 break;
             default:
-                fail("Test should only run for API levels: S, Sv2, T, UDC, 202404...");
+                final String message = String.format("Test should only run for API levels: "
+                                + "S, Sv2, T, UDC, VENDOR_24Q2, VENDOR_25Q2...\n"
+                                + "Actual: %s",
+                        ReflectionUtils.valueName(Build.class, apiLevel));
+                fail(message);
                 return;
         }
 
diff --git a/tests/gpu_test/src/com/android/gpu/vts/ReflectionUtils.java b/tests/gpu_test/src/com/android/gpu/vts/ReflectionUtils.java
new file mode 100644
index 000000000..68b6f2b30
--- /dev/null
+++ b/tests/gpu_test/src/com/android/gpu/vts/ReflectionUtils.java
@@ -0,0 +1,39 @@
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
+package com.android.gpu.vts;
+
+import java.lang.reflect.Field;
+
+public class ReflectionUtils {
+    /**
+     * Returns a string representation pf static int member, e.g. for a static class-style enum.
+     * @param clz The target class.
+     * @param value The static value to match.
+     * @return The name of the field if one matches the value, otherwise the integer string.
+     */
+    static <T> String valueName(Class<T> clz, int value) {
+        for (Field f : clz.getDeclaredFields()) {
+            try {
+                if (f.getInt(null) == value) {
+                    return f.getName();
+                }
+            } catch (IllegalAccessException e) {
+                // Ignore by design.
+            }
+        }
+        return Integer.toString(value);
+    }
+}
diff --git a/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java b/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java
index fd01cf06c..e1e6dddff 100644
--- a/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java
+++ b/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java
@@ -19,6 +19,7 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
 import static org.junit.Assume.assumeTrue;
 
 import android.platform.test.annotations.RequiresDevice;
@@ -330,6 +331,7 @@ public class VulkanTest extends BaseHostJUnit4Test {
         final int apiLevel = PropertyUtil.getVendorApiLevel(getDevice());
 
         assumeTrue("Test does not apply for SoCs launched before V", apiLevel >= Build.VENDOR_24Q2);
+        assumeFalse("Exclude new graphocs requirements for TV", FeatureUtil.isTV(getDevice()));
 
         boolean hasOnlyCpuDevice = true;
         for (JSONObject device : mVulkanDevices) {
@@ -356,6 +358,7 @@ public class VulkanTest extends BaseHostJUnit4Test {
         final int apiLevel = PropertyUtil.getVendorApiLevel(getDevice());
 
         assumeTrue("Test does not apply for SoCs launched before V", apiLevel >= Build.VENDOR_24Q2);
+        assumeFalse("Exclude new graphocs requirements for TV", FeatureUtil.isTV(getDevice()));
 
         boolean hasOnlyCpuDevice = true;
         for (JSONObject device : mVulkanDevices) {
@@ -375,13 +378,15 @@ public class VulkanTest extends BaseHostJUnit4Test {
 
     /**
      * All SoCs released with V must support protectedMemory and VK_EXT_global_priority
+     * ProtectedMemory and VK_EXT_global_priority should be reuqired for Android 16.
      */
     @VsrTest(requirements = {"VSR-3.2.1-011"})
     @Test
     public void checkProtectedMemoryAndGlobalPrioritySupport() throws Exception {
         final int apiLevel = PropertyUtil.getVendorApiLevel(getDevice());
 
-        assumeTrue("Test does not apply for SoCs launched before V", apiLevel >= Build.VENDOR_24Q2);
+        assumeTrue("Test does not apply for SoCs launched before W", apiLevel >= Build.VENDOR_25Q2);
+        assumeFalse("Exclude new graphocs requirements for TV", FeatureUtil.isTV(getDevice()));
 
         assertTrue(mVulkanDevices.length > 0);
 
diff --git a/tests/kernel_proc_file_api_test/Android.bp b/tests/kernel_proc_file_api_test/Android.bp
index 8a37d5ba4..ebebf8093 100644
--- a/tests/kernel_proc_file_api_test/Android.bp
+++ b/tests/kernel_proc_file_api_test/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/tests/selinux_test/Android.bp b/tests/selinux_test/Android.bp
index 0b365231b..0baffcf99 100644
--- a/tests/selinux_test/Android.bp
+++ b/tests/selinux_test/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/tools/vts-core-tradefed/Android.bp b/tools/vts-core-tradefed/Android.bp
index 0acc29df5..84c8c839e 100644
--- a/tools/vts-core-tradefed/Android.bp
+++ b/tools/vts-core-tradefed/Android.bp
@@ -35,7 +35,7 @@ tradefed_binary_host {
     wrapper: "etc/vts-tradefed",
     short_name: "VTS",
     full_name: "Vendor Test Suite",
-    version: "15_r2",
+    version: "15_r3",
     static_libs: [
         "vts-core-tradefed-harness",
         "cts-tradefed-harness",
diff --git a/tools/vts-core-tradefed/res/config/vts-platinum-staging-normal.xml b/tools/vts-core-tradefed/res/config/vts-platinum-staging-normal.xml
new file mode 100644
index 000000000..c52ed5fb4
--- /dev/null
+++ b/tools/vts-core-tradefed/res/config/vts-platinum-staging-normal.xml
@@ -0,0 +1,2810 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!-- Copyright (C) 2024 The Android Open Source Project
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
+<configuration description="Run VTS platinum candidate tests.">
+    <include name="vts"/>
+    <!-- CtsResourcesLoaderTests -->
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[fileBased EMPTY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[fileBasedApkAssetsProvider APK_DISK_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[fileBasedApkAssetsProvider DIRECTORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableBased APK_DISK_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableBased APK_DISK_FD_NO_ASSETS_PROVIDER]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableBased DIRECTORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableBased SPLIT]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableFileBased APK_DISK_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableFileBased APK_DISK_FD_NO_ASSETS_PROVIDER]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableFileBased DIRECTORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#appLoadersIncludedInActivityContexts[tableFileBased SPLIT]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[fileBased EMPTY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[fileBasedApkAssetsProvider APK_DISK_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[fileBasedApkAssetsProvider DIRECTORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased APK_DISK_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased APK_DISK_FD_NO_ASSETS_PROVIDER]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased ARSC_DISK_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased DIRECTORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableBased SPLIT]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableFileBased APK_DISK_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableFileBased APK_DISK_FD_NO_ASSETS_PROVIDER]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableFileBased DIRECTORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loadersApplicationInfoChanged[tableFileBased SPLIT]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableFileBased APK_RAM_OFFSETS]"/>
+    <!-- CtsUsbManagerTestCases -->
+    <option name="compatibility:include-filter" value="CtsUsbManagerTestCases android.usb.cts.UsbManagerApiTest#test_UsbApiForUsbGadgetHal"/>
+    <option name="compatibility:include-filter" value="CtsUsbManagerTestCases android.usb.cts.UsbManagerApiTest#test_UsbApiSetGetCurrentFunctionsSys"/>
+    <!-- CtsVoiceInteractionHostTestCases -->
+    <option name="compatibility:include-filter" value="CtsVoiceInteractionHostTestCases com.android.cts.voiceinteraction.host.VoiceInteractionCompatTests#testDefaultPhraseIdEnforcementBehavior"/>
+    <option name="compatibility:include-filter" value="CtsVoiceInteractionHostTestCases com.android.cts.voiceinteraction.host.VoiceInteractionCompatTests#testEnforceHotwordPhraseIdChangeDisabled"/>
+    <option name="compatibility:include-filter" value="CtsVoiceInteractionHostTestCases com.android.cts.voiceinteraction.host.VoiceInteractionCompatTests#testEnforceHotwordPhraseIdChangeEnabled"/>
+    <!-- FastbootVerifyUserspaceTest -->
+    <option name="compatibility:include-filter" value="FastbootVerifyUserspaceTest com.android.tests.fastboot.FastbootVerifyUserspaceTest#testFastbootReboot"/>
+    <!-- FirmwareDtboVerification -->
+    <option name="compatibility:include-filter" value="FirmwareDtboVerification com.android.tests.firmwaredtbo.FirmwareDtboVerification#testCheckDTBOPartition"/>
+    <option name="compatibility:include-filter" value="FirmwareDtboVerification com.android.tests.firmwaredtbo.FirmwareDtboVerification#testVerifyOverlay"/>
+    <!-- FsVerityTest -->
+    <option name="compatibility:include-filter" value="FsVerityTest com.android.fsverity.FsVerityHostTest#testFsVerityLargerFileWithOneMoreMerkleTreeLevel"/>
+    <option name="compatibility:include-filter" value="FsVerityTest com.android.fsverity.FsVerityHostTest#testFsVeritySmallFile"/>
+    <!-- GpuServiceVendorTests -->
+    <option name="compatibility:include-filter" value="GpuServiceVendorTests com.android.tests.gpuservice.GpuWorkTracepointTest#testGpuWorkPeriodTracepointFormat"/>
+    <option name="compatibility:include-filter" value="GpuServiceVendorTests com.android.tests.gpuservice.GpuWorkTracepointTest#testReadTracingEvents"/>
+    <!-- HalUsbGadgetV1_0HostTest -->
+    <option name="compatibility:include-filter" value="HalUsbGadgetV1_0HostTest com.android.tests.usbgadget.HalUsbGadgetV1_0HostTest#testMIDI"/>
+    <option name="compatibility:include-filter" value="HalUsbGadgetV1_0HostTest com.android.tests.usbgadget.HalUsbGadgetV1_0HostTest#testPtp"/>
+    <!-- KernelApiSysfsTest -->
+    <option name="compatibility:include-filter" value="KernelApiSysfsTest com.android.tests.sysfs.KernelApiSysfsTest#testKernelMax"/>
+    <option name="compatibility:include-filter" value="KernelApiSysfsTest com.android.tests.sysfs.KernelApiSysfsTest#testKernelStackInitialization"/>
+    <option name="compatibility:include-filter" value="KernelApiSysfsTest com.android.tests.sysfs.KernelApiSysfsTest#testKfenceSampleRate"/>
+    <option name="compatibility:include-filter" value="KernelApiSysfsTest com.android.tests.sysfs.KernelApiSysfsTest#testNetMTU"/>
+    <option name="compatibility:include-filter" value="KernelApiSysfsTest com.android.tests.sysfs.KernelApiSysfsTest#testPerCpuCpufreq"/>
+    <option name="compatibility:include-filter" value="KernelApiSysfsTest com.android.tests.sysfs.KernelApiSysfsTest#testRtcHctosys"/>
+    <!-- KernelSelinuxFileApiTest -->
+    <option name="compatibility:include-filter" value="KernelSelinuxFileApiTest com.android.tests.selinux.KernelSelinuxFileApiTest#testSelinuxNull"/>
+    <!-- MicrodroidTestApp -->
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidCapabilitiesTest#avfIsRequired"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidCapabilitiesTest#supportForProtectedOrNonProtectedVms"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#accessToCdisIsRestricted[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#accessToCdisIsRestricted[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#autoCloseVmDescriptor[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#autoCloseVmDescriptor[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#autoCloseVm[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#autoCloseVm[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bccIsSuperficiallyWellFormed[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bccIsSuperficiallyWellFormed[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#binderCallbacksWork[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#binderCallbacksWork[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenApkPathIsInvalid[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenBinaryIsMissingEntryFunction[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenBinaryIsMissingEntryFunction[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenBinaryNameIsInvalid[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenBinaryNameIsInvalid[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenBinaryTriesToLinkAgainstPrivateLibs[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenBinaryTriesToLinkAgainstPrivateLibs[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenConfigIsInvalid[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenConfigIsInvalid[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenExtraApkPackageIsInvalid[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenLowMem[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenLowMem[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenMicrodroidDataIsCompromised[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenMicrodroidDataIsCompromised[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenPvmFwDataIsCompromised[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenPvmFwDataIsCompromised[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWithCustomVendorPartitionForPvm[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootsWithCustomVendorPartitionForNonPvm[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootsWithVendorPartition[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootsWithVendorPartition[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#canReadFileFromAssets_debugFull[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#canReadFileFromAssets_debugFull[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#changingDebuggableVmNonDebuggableInvalidatesVmIdentity[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#changingDebuggableVmNonDebuggableInvalidatesVmIdentity[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#changingNonDebuggableVmDebuggableInvalidatesVmIdentity[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#changingNonDebuggableVmDebuggableInvalidatesVmIdentity[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#compatibleConfigTests[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#compatibleConfigTests[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#concurrentVms[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#configuringVendorDiskImageRequiresCustomPermission[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#configuringVendorDiskImageRequiresCustomPermission[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#connectVsock[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#connectVsock[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createAndConnectToVm[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createAndConnectToVm[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createAndConnectToVm_HostCpuTopology[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createAndConnectToVm_HostCpuTopology[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createAndRunNoDebugVm[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createAndRunNoDebugVm[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createAndRunRustVmWithEncryptedStorage[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createAndRunRustVmWithEncryptedStorage[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createAndRunRustVm[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createAndRunRustVm[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createVmWithConfigRequiresPermission[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createVmWithConfigRequiresPermission[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#creationFailsWithUnsignedVendorPartition[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#creationFailsWithUnsignedVendorPartition[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#dataIsMountedWithNoExec[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#dataIsMountedWithNoExec[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#deleteVmFiles[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#deleteVmFiles[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#deleteVm[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#deleteVm[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#differentManagersForDifferentContexts[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#differentManagersForDifferentContexts[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#encryptedStorageAvailable[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#encryptedStorageAvailable[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#encryptedStorageIsInaccessibleToDifferentVm[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#encryptedStorageIsInaccessibleToDifferentVm[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#encryptedStorageIsPersistent[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#encryptedStorageIsPersistent[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#encryptedStoreIsMountedWithNoExec[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#encryptedStoreIsMountedWithNoExec[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#extraApkInVmConfig[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#extraApkInVmConfig[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#extraApk[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#extraApk[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#importedVmAndOriginalVmHaveTheSameCdi[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#importedVmAndOriginalVmHaveTheSameCdi[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#importedVmIsEqualToTheOriginalVm_WithStorage[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#importedVmIsEqualToTheOriginalVm_WithStorage[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#importedVmIsEqualToTheOriginalVm_WithoutStorage[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#importedVmIsEqualToTheOriginalVm_WithoutStorage[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#inputShouldBeExplicitlyAllowed[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#inputShouldBeExplicitlyAllowed[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#instancesOfSameVmHaveDifferentCdis[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#instancesOfSameVmHaveDifferentCdis[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#invalidVmNameIsRejected[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#invalidVmNameIsRejected[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#kernelVersionRequirement[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#kernelVersionRequirement[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#microdroidLauncherHasEmptyCapabilities[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#microdroidLauncherHasEmptyCapabilities[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#outputIsNotRedirectedToLogcatIfNotDebuggable[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#outputIsNotRedirectedToLogcatIfNotDebuggable[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#outputIsRedirectedToLogcatIfNotCaptured[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#outputIsRedirectedToLogcatIfNotCaptured[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#outputShouldBeExplicitlyCaptured[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#outputShouldBeExplicitlyCaptured[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#payloadIsNotRoot[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#payloadIsNotRoot[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#protectedVmHasValidDiceChain[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#sameInstanceKeepsSameCdis[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#sameInstanceKeepsSameCdis[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#sameInstancesShareTheSameVmObject[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#sameInstancesShareTheSameVmObject[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#systemPartitionMountFlags[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#systemPartitionMountFlags[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testAvfRequiresUpdatableApex[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testAvfRequiresUpdatableApex[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testConsoleInputSupported[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testConsoleInputSupported[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testFileUnderBinHasExecutePermission[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testFileUnderBinHasExecutePermission[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testShareVmWithAnotherApp[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testShareVmWithAnotherApp[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testShareVmWithAnotherApp_encryptedStorage[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testShareVmWithAnotherApp_encryptedStorage[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testStartVmWithPayloadOfAnotherApp[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testStartVmWithPayloadOfAnotherApp[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testVmDescriptorParcelUnparcel_noTrustedStorage[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testVmDescriptorParcelUnparcel_noTrustedStorage[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testVmDescriptorParcelUnparcel_withTrustedStorage[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testVmDescriptorParcelUnparcel_withTrustedStorage[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#validApkPathIsAccepted[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#validApkPathIsAccepted[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmAttestationWhenRemoteAttestationIsNotSupported[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmAttestationWhenRemoteAttestationIsSupported[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmConfigBuilderValidationTests[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmConfigBuilderValidationTests[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmConfigGetAndSetTests[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmConfigGetAndSetTests[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmDescriptorClosedOnImport[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmDescriptorClosedOnImport[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmFilesStoredInCeDirWhenCreatedFromCEContext[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmFilesStoredInCeDirWhenCreatedFromCEContext[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmFilesStoredInDeDirWhenCreatedFromDEContext[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmFilesStoredInDeDirWhenCreatedFromDEContext[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmLifecycleChecks[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmLifecycleChecks[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmUnitTests[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmUnitTests[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmmGetAndCreate[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmmGetAndCreate[protectedVm=true,gki=null]"/>
+    <!-- SuspendSepolicyTests -->
+    <option name="compatibility:include-filter" value="SuspendSepolicyTests SuspendSepolicyTests#SuspendSepolicyTests"/>
+    <!-- UpdatableSystemFontTest -->
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#fdLeakTest"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#fdLeakTest_withoutPermission"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#getAvailableFonts"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#launchApp"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#launchApp_afterUpdateFont"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#reboot"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#updateFont"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#updateFontFamily"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#updateFontFamily_asNewFont"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#updateFont_allowSameVersion"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#updateFont_downgradeFromData"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#updateFont_downgradeFromSystem"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#updateFont_invalidCert"/>
+    <option name="compatibility:include-filter" value="UpdatableSystemFontTest com.android.updatablesystemfont.UpdatableSystemFontTest#updateFont_twice"/>
+    <!-- VtsAidlCameraServiceTargetTest -->
+    <option name="compatibility:include-filter" value="VtsAidlCameraServiceTargetTest PerInstance/VtsAidlCameraServiceTargetTest#BasicCameraLifeCycleTest/0_android_frameworks_cameraservice_service_ICameraService_default"/>
+    <!-- VtsAidlHalCameraProvider_TargetTest -->
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#configureConcurrentStreamsAvailableOutputs/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#configureStreamsAvailableOutputs/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#configureStreamsConstrainedOutputs/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#configureStreamsInvalidOutputs/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#configureStreamsPreviewStillOutputs/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#configureStreamsUseCases/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#configureStreamsVideoStillOutputs/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#configureStreamsWithSessionParameters/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#configureStreamsZSLInputOutputs/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#flushEmpty/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#flushPreviewRequest/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#getCameraCharacteristics/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#process10BitColorSpaceRequests/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#process10BitDynamicRangeRequest/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#processCaptureRequestBurstISO/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#processCaptureRequestInvalidBuffer/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#processCaptureRequestInvalidSinglePreview/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#processCaptureRequestPreview/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#processCaptureRequestPreviewStabilization/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#processMultiCaptureRequestPreview/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#processUltraHighResolutionRequest/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalCameraProvider_TargetTest PerInstance/CameraAidlTest#processZoomSettingsOverrideRequests/0_android_hardware_camera_provider_ICameraProvider_internal_0"/>
+    <!-- VtsAidlHalContextHubTargetTest -->
+    <option name="compatibility:include-filter" value="VtsAidlHalContextHubTargetTest ContextHub/ContextHubAidl#TestDisableTestMode/CONTEXT_HUB_ID_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalContextHubTargetTest ContextHub/ContextHubAidl#TestEnableTestMode/CONTEXT_HUB_ID_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalContextHubTargetTest ContextHub/ContextHubAidl#TestOnLocationSettingChanged/CONTEXT_HUB_ID_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalContextHubTargetTest ContextHub/ContextHubAidl#TestQueryApps/CONTEXT_HUB_ID_0"/>
+    <!-- VtsAidlHalDrmTargetTest -->
+    <option name="compatibility:include-filter" value="VtsAidlHalDrmTargetTest PerInstance/DrmHalTest#ClearSegmentTest/1_widevine"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalDrmTargetTest PerInstance/DrmHalTest#DoProvisioning/1_widevine"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalDrmTargetTest PerInstance/DrmHalTest#EncryptedAesCtrSegmentTest/1_widevine"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalDrmTargetTest PerInstance/DrmHalTest#EncryptedAesCtrSegmentTestNoKeys/1_widevine"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalDrmTargetTest PerInstance/DrmHalTest#ErrorFrameTooLarge/1_widevine"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalDrmTargetTest PerInstance/DrmHalTest#GetKeyRequestBadMime/1_widevine"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalDrmTargetTest PerInstance/DrmHalTest#OfflineLicenseStateTest/1_widevine"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalDrmTargetTest PerInstance/DrmHalTest#OfflineLicenseTest/1_widevine"/>
+    <!-- VtsAidlHalNfcTargetTest -->
+    <option name="compatibility:include-filter" value="VtsAidlHalNfcTargetTest Nfc/NfcAidl#CloseAfterClose/0_android_hardware_nfc_INfc_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalNfcTargetTest Nfc/NfcAidl#CoreInitializedAfterOpen/0_android_hardware_nfc_INfc_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalNfcTargetTest Nfc/NfcAidl#OpenAndCloseForDisable/0_android_hardware_nfc_INfc_default"/>
+    <!-- VtsAidlHalSensorsTargetTest -->
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#Activate/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#Batch/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#CallInitializeTwice/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#CleanupConnectionsOnInitialize/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#DirectChannelAshmem/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#DirectChannelGralloc/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#FlushInactiveSensor/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#FlushOneShotSensor/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#FlushSensor/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#InjectSensorEventData/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#NoStaleEvents/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#SensorListValid/0_android_hardware_sensors_ISensors_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalSensorsTargetTest Sensors/SensorsAidlTest#SetOperationMode/0_android_hardware_sensors_ISensors_default"/>
+    <!-- VtsBootconfigTest -->
+    <option name="compatibility:include-filter" value="VtsBootconfigTest VtsBootconfigTest#ProcCmdlineAndroidbootTest"/>
+    <!-- VtsGpuTests -->
+    <option name="compatibility:include-filter" value="VtsGpuTests com.android.gpu.vts.GpuProfilingTest#checkGpuProfilingRequirements"/>
+    <option name="compatibility:include-filter" value="VtsGpuTests com.android.gpu.vts.OpenGlEsTest#checkOpenGlEsDeqpLevelIsHighEnough"/>
+    <option name="compatibility:include-filter" value="VtsGpuTests com.android.gpu.vts.VulkanTest#checkCpuVulkanRequirements"/>
+    <option name="compatibility:include-filter" value="VtsGpuTests com.android.gpu.vts.VulkanTest#checkSkiaVulkanSupport"/>
+    <option name="compatibility:include-filter" value="VtsGpuTests com.android.gpu.vts.VulkanTest#checkVpAndroid15MinimumsSupport"/>
+    <option name="compatibility:include-filter" value="VtsGpuTests com.android.gpu.vts.VulkanTest#checkVulkanDeqpLevelIsHighEnough"/>
+    <!-- VtsHalAltitudeServiceTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalAltitudeServiceTargetTest AltitudeService/AltitudeServiceTest#TestAddMslAltitudeToLocation/0_android_frameworks_location_altitude_IAltitudeService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAltitudeServiceTargetTest AltitudeService/AltitudeServiceTest#TestGetGeoidHeight/0_android_frameworks_location_altitude_IAltitudeService_default"/>
+    <!-- VtsHalAudioCoreTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothA2dpTest/AudioCoreBluetoothA2dp#Enabled/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothA2dpTest/AudioCoreBluetoothA2dp#OffloadReconfiguration/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothA2dpTest/AudioCoreBluetoothA2dp#SameInstance/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothLeTest/AudioCoreBluetoothLe#Enabled/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothLeTest/AudioCoreBluetoothLe#OffloadReconfiguration/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothLeTest/AudioCoreBluetoothLe#SameInstance/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothTest/AudioCoreBluetooth#HfpConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothTest/AudioCoreBluetooth#HfpConfigInvalid/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothTest/AudioCoreBluetooth#SameInstance/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothTest/AudioCoreBluetooth#ScoConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreConfigTest/AudioCoreConfig#CanBeRestarted/0_android_hardware_audio_core_IConfig_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreConfigTest/AudioCoreConfig#GetEngineConfigIsValid/0_android_hardware_audio_core_IConfig_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreConfigTest/AudioCoreConfig#GetSurroundSoundConfigIsValid/0_android_hardware_audio_core_IConfig_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#AddRemoveEffectInvalidArguments/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#BluetoothVariableLatency/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#CanBeRestarted/0_android_hardware_audio_core_IModule_bluetooth"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#CanBeRestarted/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#ConnectDisconnectExternalDeviceInvalidPorts/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#ConnectDisconnectExternalDeviceTwice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#DisconnectExternalDeviceNonResetPortConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#ExternalDeviceMixPortConfigs/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#ExternalDevicePortRoutes/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GenerateHwAvSyncId/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GetAAudioHardwareBurstMinUsec/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GetAAudioMixerBurstCount/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GetMicrophones/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GetMmapPolicyInfos/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GetVendorParameters/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#MasterMute/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#MasterVolume/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#MicMute/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#Published/0_android_hardware_audio_core_IModule_bluetooth"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#Published/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#Published/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetAllExternalDevicePortConfigs/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetAllStaticAudioPortConfigs/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetAudioPortConfigInvalidPortAudioGain/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetAudioPortConfigInvalidPortConfigId/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetAudioPortConfigInvalidPortId/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetVendorParameters/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#TryChangingConnectionSimulationMidway/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#TryConnectMissingDevice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#TwoExternalDevicesMixPortConfigsInterleaved/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#TwoExternalDevicesMixPortConfigsNested/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#UpdateAudioMode/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#UpdateScreenRotation/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#UpdateScreenState/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreSoundDoseTest/AudioCoreSoundDose#CheckDefaultRs2UpperBound/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreSoundDoseTest/AudioCoreSoundDose#GetSetOutputRs2UpperBound/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreSoundDoseTest/AudioCoreSoundDose#RegisterSoundDoseCallbackTwiceThrowsException/0_android_hardware_audio_core_IModule_bluetooth"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreSoundDoseTest/AudioCoreSoundDose#RegisterSoundDoseCallbackTwiceThrowsException/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreSoundDoseTest/AudioCoreSoundDose#RegisterSoundDoseCallbackTwiceThrowsException/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreSoundDoseTest/AudioCoreSoundDose#RegisterSoundDoseNullCallbackThrowsException/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreSoundDoseTest/AudioCoreSoundDose#SameInstance/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreTelephonyTest/AudioCoreTelephony#GetSupportedAudioModes/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreTelephonyTest/AudioCoreTelephony#SameInstance/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreTelephonyTest/AudioCoreTelephony#SwitchAudioMode/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreTelephonyTest/AudioCoreTelephony#TelecomConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreTelephonyTest/AudioCoreTelephony#TelecomConfigInvalid/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#ResetInvalidPatchId/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#ResetPortConfigUsedByPatchInput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#ResetPortConfigUsedByPatchOutput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#SetInvalidPatchInput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#SetInvalidPatchOutput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#SetNonRoutablePatchInput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#SetNonRoutablePatchOutput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#SetPatchInput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#SetPatchOutput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#UpdateInvalidPatchIdInput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#UpdateInvalidPatchIdOutput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#UpdatePatchInput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#UpdatePatchOutput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#UpdatePatchPortsInput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioPatchTest/AudioModulePatch#UpdatePatchPortsOutput/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#ActiveMicrophones/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#AddRemoveEffectInvalidArguments/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#CloseTwice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#GetStreamCommon/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#GetVendorParameters/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#HwGainHwVolume/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#MicrophoneDirection/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#MicrophoneFieldDimension/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#OpenAllConfigs/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#OpenInvalidBufferSize/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#OpenInvalidDirection/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#OpenOverMaxCount/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#OpenTwiceSamePortConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#PrepareToCloseTwice/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#PrepareToCloseTwice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#ResetPortConfigWithOpenStream/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#SendInvalidCommand/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#SetVendorParameters/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#UpdateHwAvSyncId/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/10_android_hardware_audio_core_IModule_default_Read_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/19_android_hardware_audio_core_IModule_default_Flush_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/20_android_hardware_audio_core_IModule_r_submix_Read_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/21_android_hardware_audio_core_IModule_r_submix_Read_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/22_android_hardware_audio_core_IModule_r_submix_Drain_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/23_android_hardware_audio_core_IModule_r_submix_Drain_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/24_android_hardware_audio_core_IModule_r_submix_Standby_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/25_android_hardware_audio_core_IModule_r_submix_Standby_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/26_android_hardware_audio_core_IModule_r_submix_Pause_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/27_android_hardware_audio_core_IModule_r_submix_Pause_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/28_android_hardware_audio_core_IModule_r_submix_Flush_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoInTest/AudioStreamIoIn#Run/29_android_hardware_audio_core_IModule_r_submix_Flush_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/26_android_hardware_audio_core_IModule_default_WriteSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/27_android_hardware_audio_core_IModule_default_WriteSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/32_android_hardware_audio_core_IModule_default_DrainSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/33_android_hardware_audio_core_IModule_default_DrainSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/34_android_hardware_audio_core_IModule_default_DrainPauseSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/35_android_hardware_audio_core_IModule_default_DrainPauseSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/38_android_hardware_audio_core_IModule_default_StandbySync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/39_android_hardware_audio_core_IModule_default_StandbySync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/42_android_hardware_audio_core_IModule_default_PauseSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/43_android_hardware_audio_core_IModule_default_PauseSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/44_android_hardware_audio_core_IModule_default_FlushSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/45_android_hardware_audio_core_IModule_default_FlushSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/48_android_hardware_audio_core_IModule_default_DrainPauseFlushSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/49_android_hardware_audio_core_IModule_default_DrainPauseFlushSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/52_android_hardware_audio_core_IModule_r_submix_WriteSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/53_android_hardware_audio_core_IModule_r_submix_WriteSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/54_android_hardware_audio_core_IModule_r_submix_WriteAsync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/55_android_hardware_audio_core_IModule_r_submix_WriteAsync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/56_android_hardware_audio_core_IModule_r_submix_WriteDrainAsync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/57_android_hardware_audio_core_IModule_r_submix_WriteDrainAsync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/58_android_hardware_audio_core_IModule_r_submix_DrainSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/59_android_hardware_audio_core_IModule_r_submix_DrainSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/60_android_hardware_audio_core_IModule_r_submix_DrainPauseSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/61_android_hardware_audio_core_IModule_r_submix_DrainPauseSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/62_android_hardware_audio_core_IModule_r_submix_DrainPauseAsync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/63_android_hardware_audio_core_IModule_r_submix_DrainPauseAsync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/64_android_hardware_audio_core_IModule_r_submix_StandbySync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/65_android_hardware_audio_core_IModule_r_submix_StandbySync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/66_android_hardware_audio_core_IModule_r_submix_StandbyAsync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/67_android_hardware_audio_core_IModule_r_submix_StandbyAsync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/68_android_hardware_audio_core_IModule_r_submix_PauseSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/69_android_hardware_audio_core_IModule_r_submix_PauseSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/70_android_hardware_audio_core_IModule_r_submix_FlushSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/71_android_hardware_audio_core_IModule_r_submix_FlushSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/72_android_hardware_audio_core_IModule_r_submix_FlushAsync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/73_android_hardware_audio_core_IModule_r_submix_FlushAsync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/74_android_hardware_audio_core_IModule_r_submix_DrainPauseFlushSync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/75_android_hardware_audio_core_IModule_r_submix_DrainPauseFlushSync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/76_android_hardware_audio_core_IModule_r_submix_DrainPauseFlushAsync_SetupSeq1"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamIoOutTest/AudioStreamIoOut#Run/77_android_hardware_audio_core_IModule_r_submix_DrainPauseFlushAsync_SetupSeq2"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#AddRemoveEffectInvalidArguments/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#AddRemoveEffectInvalidArguments/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#AudioDescriptionMixLevel/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#AudioDescriptionMixLevel/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#CloseTwice/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#CloseTwice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#DualMonoMode/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#DualMonoMode/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#GetStreamCommon/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#GetStreamCommon/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#GetVendorParameters/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#GetVendorParameters/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#HwGainHwVolume/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#HwGainHwVolume/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#LatencyMode/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#LatencyMode/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#OpenAllConfigs/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#OpenAllConfigs/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#OpenInvalidBufferSize/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#OpenInvalidDirection/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#OpenOverMaxCount/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#OpenTwicePrimary/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#OpenTwicePrimary/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#OpenTwiceSamePortConfig/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#OpenTwiceSamePortConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#PlaybackRate/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#PrepareToCloseTwice/0_android_hardware_audio_core_IModule_bluetooth"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#PrepareToCloseTwice/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#PrepareToCloseTwice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#RequireAsyncCallback/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#RequireOffloadInfo/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#ResetPortConfigWithOpenStream/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#ResetPortConfigWithOpenStream/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#SelectPresentation/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#SendInvalidCommand/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#SendInvalidCommand/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#SetVendorParameters/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#SetVendorParameters/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#UpdateHwAvSyncId/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#UpdateHwAvSyncId/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#UpdateOffloadMetadata/2_android_hardware_audio_core_IModule_r_submix"/>
+    <!-- VtsHalAudioEffectFactoryTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#CanBeRestarted/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#CreateAndDestroyRepeat/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#CreateDestroyWithRestart/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#CreateMultipleInstanceOfSameEffect/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#CreateWithInvalidUuid/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#DestroyWithInvalidInterface/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#EffectInvalidAfterRestart/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#QueriedNullImplUuid/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#QueriedNullProxyUuid/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#QueryNullTypeUuid/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#QueryProcess/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#SetupAndTearDown/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#SupportMandatoryEffectTypes/0_android_hardware_audio_effect_IFactory_default"/>
+    <!-- VtsHalAudioEffectTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Auxiliary_Preset_Reverb_UUID_f29a1400_a3bb_11df_8ddc_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Dynamic_Bass_Boost_UUID_8631f300_72e2_11df_b57e_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_EqualizerBundle_UUID_ce772f20_847d_11df_bb17_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Insert_Preset_Reverb_UUID_172cdf00_a3bc_11df_a72f_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Virtualizer_UUID_1d4033c0_8557_11df_9f2d_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Volume_UUID_119341a0_8469_11df_81f9_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_The_Android_Open_Source_Project_name_DynamicsProcessing_UUID_e0e6539b_1781_7261_676f_6d7573696340"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_The_Android_Open_Source_Project_name_Haptic_Generator_UUID_97c4acd1_8b82_4f2f_832e_c2fe5d7a9931"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_The_Android_Open_Source_Project_name_Loudness_Enhancer_UUID_fa415329_2034_4bea_b5dc_5b381c8d1e2c"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_The_Android_Open_Source_Project_name_Visualizer_UUID_d069d9e0_8329_11df_9168_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterRestart/Implementor_NXP_Software_Ltd__name_Insert_Preset_Reverb_UUID_172cdf00_a3bc_11df_a72f_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAndRestart/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_NXP_Software_Ltd__name_Dynamic_Bass_Boost_UUID_8631f300_72e2_11df_b57e_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_NXP_Software_Ltd__name_EqualizerBundle_UUID_ce772f20_847d_11df_bb17_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_NXP_Software_Ltd__name_Virtualizer_UUID_1d4033c0_8557_11df_9f2d_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_NXP_Software_Ltd__name_Volume_UUID_119341a0_8469_11df_81f9_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_The_Android_Open_Source_Project_name_DynamicsProcessing_UUID_e0e6539b_1781_7261_676f_6d7573696340"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_The_Android_Open_Source_Project_name_Visualizer_UUID_d069d9e0_8329_11df_9168_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Auxiliary_Preset_Reverb_UUID_f29a1400_a3bb_11df_8ddc_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Dynamic_Bass_Boost_UUID_8631f300_72e2_11df_b57e_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_EqualizerBundle_UUID_ce772f20_847d_11df_bb17_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Insert_Preset_Reverb_UUID_172cdf00_a3bc_11df_a72f_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Virtualizer_UUID_1d4033c0_8557_11df_9f2d_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Volume_UUID_119341a0_8469_11df_81f9_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_The_Android_Open_Source_Project_name_DynamicsProcessing_UUID_e0e6539b_1781_7261_676f_6d7573696340"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_The_Android_Open_Source_Project_name_Haptic_Generator_UUID_97c4acd1_8b82_4f2f_832e_c2fe5d7a9931"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_The_Android_Open_Source_Project_name_Loudness_Enhancer_UUID_fa415329_2034_4bea_b5dc_5b381c8d1e2c"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_The_Android_Open_Source_Project_name_Visualizer_UUID_d069d9e0_8329_11df_9168_0002a5d5c51b"/>
+    <!-- VtsHalAudioEffectV7_0TargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectV7_0TargetTest CheckConfig#audioEffectsConfigurationValidation"/>
+    <!-- VtsHalBassBoostTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBassBoostTargetTest BassBoostTest/BassBoostDataTest#IncreasingStrength/Implementor_NXP_Software_Ltd__name_Dynamic_Bass_Boost_UUID_8631f300_72e2_11df_b57e_0002a5d5c51b_layout_3"/>
+    <!-- VtsHalBiometricsFaceTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBiometricsFaceTargetTest IFace/Face#EnrollWithBadHatResultsInErrorTest/0_android_hardware_biometrics_face_IFace_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBiometricsFaceTargetTest IFace/Face#GenerateChallengeProducesUniqueChallengesTest/0_android_hardware_biometrics_face_IFace_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBiometricsFaceTargetTest IFace/Face#GetSensorPropsWorksTest/0_android_hardware_biometrics_face_IFace_default"/>
+    <!-- VtsHalBiometricsFingerprintTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBiometricsFingerprintTargetTest IFingerprint/Fingerprint#GenerateChallengeProducesUniqueChallengesTest/0_android_hardware_biometrics_fingerprint_IFingerprint_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBiometricsFingerprintTargetTest IFingerprint/Fingerprint#GetSensorPropsWorksTest/0_android_hardware_biometrics_fingerprint_IFingerprint_default"/>
+    <!-- VtsHalBluetoothAudioTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest AidlTestHelper#CheckNoUnimplementedInterfaces"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_hintBitdepth/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_hintChannelMode/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_hintCodecId/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_hintSamplingFrequencyHz/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_invalidRemoteCapabilities/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_invalidSessionType/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_unknownRemoteCapabilities/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_validRemoteCapabilities/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#parseA2dpConfiguration_valid/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#startSession_invalidConfiguration/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#startSession_valid/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderFactoryAidl#GetProviderFactoryService/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderFactoryAidl#OpenProviderAndCheckCapabilitiesBySession/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderHfpHardwareAidl#StartAndEndHfpHardwareSessionWithPossiblePcmConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderHfpSoftwareDecodingAidl#OpenHfpSoftwareDecodingProvider/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderHfpSoftwareDecodingAidl#StartAndEndHfpDecodingSoftwareSessionWithPossiblePcmConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderHfpSoftwareEncodingAidl#OpenHfpSoftwareEncodingProvider/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderHfpSoftwareEncodingAidl#StartAndEndHfpEncodingSoftwareSessionWithPossiblePcmConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioBroadcastHardwareAidl#GetBroadcastConfigurationEmptyCapability/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioBroadcastHardwareAidl#GetEmptyBroadcastConfigurationEmptyCapability/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioBroadcastHardwareAidl#OpenLeAudioOutputHardwareProvider/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioBroadcastHardwareAidl#StartAndEndLeAudioBroadcastSessionWithPossibleBroadcastConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioBroadcastHardwareAidl#StartAndEndLeAudioBroadcastSessionWithPossibleUnicastConfigFromProviderInfo/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioInputHardwareAidl#GetAseConfiguration_Multidirectional/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioInputHardwareAidl#OpenLeAudioInputHardwareProvider/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioInputHardwareAidl#StartAndEndLeAudioInputSessionWithPossibleUnicastConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioInputHardwareAidl#StartAndEndLeAudioInputSessionWithPossibleUnicastConfigFromProviderInfo/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#BluetoothAudioProviderLeAudioOutputHardwareAidl_StartAndEndLeAudioOutputSessionWithInvalidAptxAdaptiveLeAudioConfiguration/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#GetAseConfiguration_Multidirectional/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#GetDataPathConfiguration/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#GetEmptyAseConfigurationEmptyCapability/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#GetEmptyAseConfigurationMismatchedRequirement/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#GetQoSConfiguration/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#OpenLeAudioOutputHardwareProvider/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#StartAndEndLeAudioOutputSessionWithAptxAdaptiveLeUnicastConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#StartAndEndLeAudioOutputSessionWithPossibleUnicastConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#StartAndEndLeAudioOutputSessionWithPossibleUnicastConfigFromProviderInfo/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <!-- VtsHalBluetoothRangingTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBluetoothRangingTargetTest PerInstance/BluetoothRangingTest#WriteRawData/0_android_hardware_bluetooth_ranging_IBluetoothChannelSounding_default"/>
+    <!-- VtsHalBluetoothTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBluetoothTargetTest PerInstance/BluetoothAidlTest#CallInitializeTwice/0_android_hardware_bluetooth_IBluetoothHci_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothTargetTest PerInstance/BluetoothAidlTest#HciReset/0_android_hardware_bluetooth_IBluetoothHci_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothTargetTest PerInstance/BluetoothAidlTest#LoopbackModeScoBandwidth/0_android_hardware_bluetooth_IBluetoothHci_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothTargetTest PerInstance/BluetoothAidlTest#LoopbackModeSingleSco/0_android_hardware_bluetooth_IBluetoothHci_default"/>
+    <!-- VtsHalCasAidlTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeyApisWithSession/0_android_hardware_cas_IMediaCasService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeyDefaultSessionClosedAfterRelease/0_android_hardware_cas_IMediaCasService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeyErrors/0_android_hardware_cas_IMediaCasService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeyOobFails/0_android_hardware_cas_IMediaCasService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeyPluginInstalled/0_android_hardware_cas_IMediaCasService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeySessionClosedAfterRelease/0_android_hardware_cas_IMediaCasService_default"/>
+    <!-- VtsHalDownmixTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_11"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_15"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_1539"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_1551"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_1599"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_16777215"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_184383"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_185919"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_259"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_263"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_3"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_319"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_50517567"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_51"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_51303999"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_55"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_63"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_7"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_7534087"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_786435"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_786439"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_786443"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_786447"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_786495"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_788031"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_11"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_15"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_1539"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_1551"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_1599"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_16777215"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_184383"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_185919"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_259"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_263"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_319"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_50517567"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_51"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_51303999"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_55"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_63"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_7"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_7534087"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_786435"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_786439"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_786443"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_786447"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_786495"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_788031"/>
+    <!-- VtsHalDumpstateTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestDeviceLoggingDisabled/0_android_hardware_dumpstate_IDumpstateDevice_default_FULL"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestDeviceLoggingDisabled/7_android_hardware_dumpstate_IDumpstateDevice_default_PROTO"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestHandleWithTwoFds/0_android_hardware_dumpstate_IDumpstateDevice_default_FULL"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestHandleWithTwoFds/1_android_hardware_dumpstate_IDumpstateDevice_default_INTERACTIVE"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestHandleWithTwoFds/2_android_hardware_dumpstate_IDumpstateDevice_default_REMOTE"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestHandleWithTwoFds/3_android_hardware_dumpstate_IDumpstateDevice_default_WEAR"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestHandleWithTwoFds/4_android_hardware_dumpstate_IDumpstateDevice_default_CONNECTIVITY"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestHandleWithTwoFds/6_android_hardware_dumpstate_IDumpstateDevice_default_DEFAULT"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestNullHandle/0_android_hardware_dumpstate_IDumpstateDevice_default_FULL"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestNullHandle/3_android_hardware_dumpstate_IDumpstateDevice_default_WEAR"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestNullHandle/4_android_hardware_dumpstate_IDumpstateDevice_default_CONNECTIVITY"/>
+    <!-- VtsHalEnvironmentalReverbTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b_Tag_decayHfRatioPm"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b_Tag_decayTimeMs"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b_Tag_levelMb"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b_Tag_roomHfLevelMb"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b_Tag_roomLevelMb"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b_Tag_decayHfRatioPm"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b_Tag_decayTimeMs"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b_Tag_levelMb"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b_Tag_roomHfLevelMb"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b_Tag_roomLevelMb"/>
+    <!-- VtsHalGatekeeperTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalGatekeeperTargetTest PerInstance/GatekeeperAidlTest#EnrollSuccess/0_android_hardware_gatekeeper_IGatekeeper_default"/>
+    <!-- VtsHalGnssTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#BlocklistConstellationLocationOff/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#BlocklistConstellationLocationOn/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#BlocklistIndividualSatellites/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#GetLocationLowPower/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#GetLocations/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#GnssCapabilites/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#GnssDebugValuesSanityTest/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#InjectBestLocation/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#InjectDelete/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#InjectSeedLocation/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestAGnssExtension/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestAGnssRilExtension/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestAccumulatedDeltaRange/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestAllExtensions/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestCorrelationVector/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssAgcInGnssMeasurement/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssAntennaInfo/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssMeasurementExtensionAndSatellitePvt/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssMeasurementIntervals_LocationOnAfterMeasurement/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssMeasurementIntervals_LocationOnBeforeMeasurement/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssMeasurementIntervals_WithoutLocation/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssMeasurementIntervals_changeIntervals/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssMeasurementIsFullTracking/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssPowerIndication/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssSvInfoFields/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssVisibilityControlExtension/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestStopSvStatusAndNmea/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestSvStatusIntervals/0_android_hardware_gnss_IGnss_default"/>
+    <!-- VtsHalGraphicsAllocatorAidl_TargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsAllocatorAidlTests#CanAllocate/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsAllocatorAidlTests#RejectsUnknownOptions/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsAllocatorAidlTests#RejectsUnknownUsages/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsFrontBufferTests#FrontBufferGpuToCpu/0_glFinish"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsFrontBufferTests#FrontBufferGpuToCpu/1_glFlush"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsFrontBufferTests#FrontBufferGpuToCpu/2_eglClientWaitSync"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsFrontBufferTests#FrontBufferGpuToGpu/0_glFinish"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsFrontBufferTests#FrontBufferGpuToGpu/1_glFlush"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsFrontBufferTests#FrontBufferGpuToGpu/2_eglClientWaitSync"/>
+    <!-- VtsHalGraphicsMapperStableC_TargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#AllV5CallbacksDefined/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#CanAllocate/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#CheckRequiredSettersIfHasGetters/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#DualLoadIsIdentical/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#FlushLockedBufferBadBuffer/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#FlushRereadBasic/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#FreeBufferNegative/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetAllocationSize/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetBufferId/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetChromaSiting/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetCompression/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetCrop/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetCta861_3/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetInterlaced/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetLayerCount/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetMetadataBadValue/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetName/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetPixelFormatFourCC/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetPixelFormatModifier/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetPixelFormatRequested/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetPlaneLayouts/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetProtectedContent/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetSetBlendMode/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetSetDataspace/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetSetSmpte2086/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetSmpte2094_10/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetSmpte2094_40/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetStride/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetUnsupportedMetadata/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetUsage/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetUsage64/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetWidthHeight/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#ImportBufferNegative/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#ImportFreeBuffer/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#ImportFreeBufferSingleton/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#ListSupportedWorks/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#LockBadAccessRegion/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#LockUnlockBasic/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#LockUnlockNested/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#LockUnlockNoCPUUsage/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_RAW10/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_RAW12/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_YCBCR_420_888/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_YCBCR_P010/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_YCRCB_420_SP/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_YV12/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#RereadLockedBufferBadBuffer/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#SupportsRequiredGettersSetters/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#UnlockNegative/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#UnlockNotImported/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#UnlockNotLocked/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#VersionChecks/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#YV12SubsampleMetadata/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <!-- VtsHalHealthTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/BatteryTest#AverageCurrentAgainstChargeStatusFromHal/0_android_hardware_health_IHealth_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/BatteryTest#ConnectedAgainstStatusFromHal/0_android_hardware_health_IHealth_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/BatteryTest#ConnectedAgainstStatusInHealthInfo/0_android_hardware_health_IHealth_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/BatteryTest#InstantCurrentAgainstChargeStatusFromHal/0_android_hardware_health_IHealth_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/HealthAidl#Callbacks/0_android_hardware_health_IHealth_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/HealthAidl#getBatteryHealthData/0_android_hardware_health_IHealth_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/HealthAidl#setChargingPolicy/0_android_hardware_health_IHealth_default"/>
+    <!-- VtsHalHostapdTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalHostapdTargetTest Hostapd/HostapdAidl#AddAccessPointWithDualBandConfig/0_android_hardware_wifi_hostapd_IHostapd_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHostapdTargetTest Hostapd/HostapdAidl#AddOpenAccessPointWithVendorData/0_android_hardware_wifi_hostapd_IHostapd_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHostapdTargetTest Hostapd/HostapdAidl#AddOpenAccessPointWithoutAcs/0_android_hardware_wifi_hostapd_IHostapd_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHostapdTargetTest Hostapd/HostapdAidl#AddPskAccessPointWithoutAcs/0_android_hardware_wifi_hostapd_IHostapd_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHostapdTargetTest Hostapd/HostapdAidl#AddPskAccessPointWithoutAcsAndNonMetered/0_android_hardware_wifi_hostapd_IHostapd_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHostapdTargetTest Hostapd/HostapdAidl#DisconnectClientWhenIfacAvailable/0_android_hardware_wifi_hostapd_IHostapd_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHostapdTargetTest Hostapd/HostapdAidl#RegisterCallback/0_android_hardware_wifi_hostapd_IHostapd_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHostapdTargetTest Hostapd/HostapdAidl#RemoveAccessPointWithoutAcs/0_android_hardware_wifi_hostapd_IHostapd_default"/>
+    <!-- VtsHalLoudnessEnhancerTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalLoudnessEnhancerTargetTest LoudnessEnhancerTest/LoudnessEnhancerDataTest#DecreasingGains/Implementor_The_Android_Open_Source_Project_name_Loudness_Enhancer_UUID_fa415329_2034_4bea_b5dc_5b381c8d1e2c"/>
+    <!-- VtsHalMediaC2V1_0TargetAudioDecTest -->
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioDecTest CsdInputs/Codec2AudioDecCsdInputTests#CSDFlushTest/software_c2_android_aac_decoder_0_1"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioDecTest CsdInputs/Codec2AudioDecCsdInputTests#CSDFlushTest/software_c2_android_flac_decoder_1_6"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioDecTest StreamIndexAndEOS/Codec2AudioDecDecodeTest#DecodeTest/software_c2_android_flac_decoder_0_0_12"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioDecTest StreamIndexAndEOS/Codec2AudioDecDecodeTest#DecodeTest/software_c2_android_raw_decoder_1_0_38"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioDecTest StreamIndexAndEOS/Codec2AudioDecDecodeTest#DecodeTest/software_c2_android_raw_decoder_1_1_39"/>
+    <!-- VtsHalMediaC2V1_0TargetAudioEncTest -->
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_aac_encoder_0_2_1"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_aac_encoder_1_1_2"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_aac_encoder_1_2_3"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_amrnb_encoder_0_2_5"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_amrnb_encoder_1_1_6"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_amrwb_encoder_0_2_9"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_amrwb_encoder_1_1_10"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_amrwb_encoder_1_2_11"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_flac_encoder_0_1_12"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_flac_encoder_0_2_13"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_flac_encoder_1_1_14"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_opus_encoder_0_2_17"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_opus_encoder_1_1_18"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_opus_encoder_1_2_19"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#FlushTest/software_c2_android_aac_encoder_0"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#FlushTest/software_c2_android_amrnb_encoder_1"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#FlushTest/software_c2_android_amrwb_encoder_2"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#FlushTest/software_c2_android_flac_encoder_3"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#FlushTest/software_c2_android_opus_encoder_4"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiChannelCountTest/software_c2_android_aac_encoder_0"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiChannelCountTest/software_c2_android_amrnb_encoder_1"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiChannelCountTest/software_c2_android_amrwb_encoder_2"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiChannelCountTest/software_c2_android_flac_encoder_3"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiChannelCountTest/software_c2_android_opus_encoder_4"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiSampleRateTest/software_c2_android_aac_encoder_0"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiSampleRateTest/software_c2_android_amrnb_encoder_1"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiSampleRateTest/software_c2_android_opus_encoder_4"/>
+    <!-- VtsHalNetNetdV1TargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalNetNetdV1TargetTest PerInstance/NetdAidlTest#TestAddRemoveRoutes/0_android_system_net_netd_INetd_default"/>
+    <option name="compatibility:include-filter" value="VtsHalNetNetdV1TargetTest PerInstance/NetdAidlTest#TestForwarding/0_android_system_net_netd_INetd_default"/>
+    <!-- VtsHalOemLockTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalOemLockTargetTest PerInstance/OemLockAidlTest#AllowedByDeviceCanBeToggled/0_android_hardware_oemlock_IOemLock_default"/>
+    <option name="compatibility:include-filter" value="VtsHalOemLockTargetTest PerInstance/OemLockAidlTest#CarrierUnlock/0_android_hardware_oemlock_IOemLock_default"/>
+    <!-- VtsHalPowerStatsTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalPowerStatsTargetTest PowerStats/PowerStatsAidl#TestGetStateResidencyAllResultsExceptSkippedEntities/0_android_hardware_power_stats_IPowerStats_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerStatsTargetTest PowerStats/PowerStatsAidl#TestGetStateResidencyAllStateResidenciesExceptSkippedEntities/0_android_hardware_power_stats_IPowerStats_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerStatsTargetTest PowerStats/PowerStatsAidl#TestGetStateResidencySelectedResultsExceptTimedEntities/0_android_hardware_power_stats_IPowerStats_default"/>
+    <!-- VtsHalPowerTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/FMQAidl#getAndCloseSessionChannel/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/FMQAidl#writeExcess/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/FMQAidl#writeItems/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#createAndCloseHintSession/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#createHintSessionFailed/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#getSessionConfig/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#sendSessionHint/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#setSessionMode/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#setThreads/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#updateAndReportDurations/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#createHintSessionWithConfig/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#getHintSessionPreferredRate/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#hasFixedPerformance/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#isBoostSupported/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#isModeSupported/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#setMode/0_android_hardware_power_IPower_default"/>
+    <!-- VtsHalPresetReverbTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalPresetReverbTargetTest PresetReverbTest/PresetReverbProcessTest#DecreasingRoomSize/Implementor_NXP_Software_Ltd__name_Auxiliary_Preset_Reverb_UUID_f29a1400_a3bb_11df_8ddc_0002a5d5c51b"/>
+    <!-- VtsHalRemotelyProvisionedComponentTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestTest#EmptyRequest_testMode/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestTest#NewKeyPerCallInTestMode/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestTest#NonEmptyRequest_testMode/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestV2Test#DeviceInfo/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestV2Test#EmptyRequest/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestV2Test#NonEmptyRequest/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestV2Test#NonEmptyRequestMultipleKeys/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestV2Test#NonEmptyRequestReproducible/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/GenerateKeyTests#generateAndUseEcdsaP256Key_prodMode/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/GenerateKeyTests#generateEcdsaP256Key_testMode/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/GetHardwareInfoTests#supportsValidCurve/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <!-- VtsHalSensorManagerTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalSensorManagerTargetTest PerInstance/SensorManagerTest#Accelerometer/0_android_frameworks_sensorservice_ISensorManager_default"/>
+    <option name="compatibility:include-filter" value="VtsHalSensorManagerTargetTest PerInstance/SensorManagerTest#Ashmem/0_android_frameworks_sensorservice_ISensorManager_default"/>
+    <option name="compatibility:include-filter" value="VtsHalSensorManagerTargetTest PerInstance/SensorManagerTest#GetDefaultAccelerometer/0_android_frameworks_sensorservice_ISensorManager_default"/>
+    <option name="compatibility:include-filter" value="VtsHalSensorManagerTargetTest PerInstance/SensorManagerTest#List/0_android_frameworks_sensorservice_ISensorManager_default"/>
+    <!-- VtsHalThermalTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#CoolingDeviceTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#NotifyCoolingDeviceChangedTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#NotifyThrottlingTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#RegisterCoolingDeviceChangedCallbackWithTypeTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#RegisterThermalChangedCallbackTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#RegisterThermalChangedCallbackWithTypeTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#SkinTemperatureThresholdsTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#TemperatureTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#TemperatureThresholdTest/0_android_hardware_thermal_IThermal_default"/>
+    <!-- VtsHalUsbGadgetV1_1HostTest -->
+    <option name="compatibility:include-filter" value="VtsHalUsbGadgetV1_1HostTest com.android.tests.usbgadget.VtsHalUsbGadgetV1_1HostTest#testResetUsbGadget"/>
+    <!-- VtsHalUsbGadgetV2_0HostTest -->
+    <option name="compatibility:include-filter" value="VtsHalUsbGadgetV2_0HostTest com.android.tests.usbgadget.VtsHalUsbGadgetV2_0HostTest#testAndroidNcm"/>
+    <option name="compatibility:include-filter" value="VtsHalUsbGadgetV2_0HostTest com.android.tests.usbgadget.VtsHalUsbGadgetV2_0HostTest#testMIDI"/>
+    <option name="compatibility:include-filter" value="VtsHalUsbGadgetV2_0HostTest com.android.tests.usbgadget.VtsHalUsbGadgetV2_0HostTest#testMtp"/>
+    <option name="compatibility:include-filter" value="VtsHalUsbGadgetV2_0HostTest com.android.tests.usbgadget.VtsHalUsbGadgetV2_0HostTest#testPtp"/>
+    <!-- VtsHalUwbTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalUwbTargetTest Uwb/UwbAidl#ChipClose/0_android_hardware_uwb_IUwb_default"/>
+    <option name="compatibility:include-filter" value="VtsHalUwbTargetTest Uwb/UwbAidl#ChipCoreInit/0_android_hardware_uwb_IUwb_default"/>
+    <option name="compatibility:include-filter" value="VtsHalUwbTargetTest Uwb/UwbAidl#ChipGetSupportedAndroidUciVersion/0_android_hardware_uwb_IUwb_default"/>
+    <option name="compatibility:include-filter" value="VtsHalUwbTargetTest Uwb/UwbAidl#ChipOpen/0_android_hardware_uwb_IUwb_default"/>
+    <option name="compatibility:include-filter" value="VtsHalUwbTargetTest Uwb/UwbAidl#ChipSessionInit/0_android_hardware_uwb_IUwb_default"/>
+    <option name="compatibility:include-filter" value="VtsHalUwbTargetTest Uwb/UwbAidl#GetChip/0_android_hardware_uwb_IUwb_default"/>
+    <!-- VtsHalVibratorTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#AlwaysOn/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#AmplitudeReturnsUnsupportedMatchingCapabilities/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ChangeVibrationAmplitude/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ChangeVibrationExternalControl/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeCallback/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeDelayBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposePwleAmplitudeParameterBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposePwleSegmentBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposePwleSegmentDurationBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposePwleV2Unsupported/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeScaleBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeSizeBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeValidPrimitives/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeValidPwle/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeValidPwleWithCallback/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ExternalAmplitudeControl/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ExternalControlUnsupportedMatchingCapabilities/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetBandwidthAmplitudeMap/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetFrequencyMinimum/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetFrequencyResolution/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetPrimitiveDuration/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetPwleCompositionSizeMax/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetPwlePrimitiveDurationMax/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetQFactor/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetResonantFrequency/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetSupportedBraking/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#OnThenOffBeforeTimeout/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#OnWithCallback/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#PerformVendorEffectEmptyVendorData/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#PerformVendorEffectInvalidScale/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#PerformVendorEffectStability/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#PerformVendorEffectSupported/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ValidateEffect/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ValidateEffectWithCallback/TOP_LEVEL_VIBRATOR_0"/>
+    <!-- VtsHalVirtualizerTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalVirtualizerTargetTest VirtualizerTest/VirtualizerProcessTest#IncreasingStrength/Implementor_NXP_Software_Ltd__name_Virtualizer_UUID_1d4033c0_8557_11df_9f2d_0002a5d5c51b_isInputZero_0"/>
+    <!-- VtsHalVolumeTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalVolumeTargetTest VolumeTest/VolumeDataTest#ApplyLevelMuteUnmute/Implementor_NXP_Software_Ltd__name_Volume_UUID_119341a0_8469_11df_81f9_0002a5d5c51b"/>
+    <!-- VtsHalWifiApIfaceTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalWifiApIfaceTargetTest WifiTest/WifiApIfaceAidlTest#GetBridgedInstances/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiApIfaceTargetTest WifiTest/WifiApIfaceAidlTest#GetBridgedInstances_Bridged/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiApIfaceTargetTest WifiTest/WifiApIfaceAidlTest#GetFactoryMacAddress/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiApIfaceTargetTest WifiTest/WifiApIfaceAidlTest#ResetToFactoryMacAddress/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiApIfaceTargetTest WifiTest/WifiApIfaceAidlTest#ResetToFactoryMacAddress_Bridged/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiApIfaceTargetTest WifiTest/WifiApIfaceAidlTest#SetCountryCode/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiApIfaceTargetTest WifiTest/WifiApIfaceAidlTest#SetMacAddress/0_android_hardware_wifi_IWifi_default"/>
+    <!-- VtsHalWifiChipTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#ConfigureChip/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#CreateApIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#CreateBridgedApIfaceAndremoveIfaceInstanceFromBridgedApIfaceTest/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#CreateNanIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#CreateP2pIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#CreateRttController/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#CreateStaIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#ForceDumpToDebugRingBuffer/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetApIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetApIfaceNames/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetAvailableModes/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetDebugHostWakeReasonStats/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetDebugRingBuffersStatus/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetFeatureSet/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetId/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetMode/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetNanIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetNanIfaceNames/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetP2pIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetP2pIfaceNames/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetStaIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetStaIfaceNames/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetSupportedRadioCombinations/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetUsableChannels/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#RegisterEventCallback/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#RemoveApIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#RemoveNanIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#RemoveP2pIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#RemoveStaIface/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#RequestChipDebugInfo/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#RequestDriverDebugDump/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#RequestFirmwareDebugDump/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#ResetTxPowerScenario/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#SelectTxPowerScenario_body/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#SelectTxPowerScenario_voiceCall/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#SetCoexUnsafeChannels/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#SetCountryCode/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#SetLatencyMode_low/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#SetLatencyMode_normal/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#SetMultiStaPrimaryConnection/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#SetVoipMode_off/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#SetVoipMode_voice/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#StartLoggingToDebugRingBuffer/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#setMultiStaUseCase/0_android_hardware_wifi_IWifi_default"/>
+    <!-- VtsHalWifiNanIfaceTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalWifiNanIfaceTargetTest WifiTest/WifiNanIfaceAidlTest#EnableRequest_InvalidArgs/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiNanIfaceTargetTest WifiTest/WifiNanIfaceAidlTest#FailOnIfaceInvalid/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiNanIfaceTargetTest WifiTest/WifiNanIfaceAidlTest#RespondToDataPathIndicationRequest_InvalidArgs/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiNanIfaceTargetTest WifiTest/WifiNanIfaceAidlTest#StartPublishRequest/0_android_hardware_wifi_IWifi_default"/>
+    <!-- VtsHalWifiRttControllerTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalWifiRttControllerTargetTest WifiTest/WifiRttControllerAidlTest#RangeRequest/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiRttControllerTargetTest WifiTest/WifiRttControllerAidlTest#RegisterEventCallback/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiRttControllerTargetTest WifiTest/WifiRttControllerAidlTest#Request2SidedRangeMeasurement/0_android_hardware_wifi_IWifi_default"/>
+    <!-- VtsHalWifiStaIfaceTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalWifiStaIfaceTargetTest WifiTest/WifiStaIfaceAidlTest#CheckApfIsSupported/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiStaIfaceTargetTest WifiTest/WifiStaIfaceAidlTest#GetLinkLayerStats/0_android_hardware_wifi_IWifi_default"/>
+    <!-- VtsHalWifiSupplicantP2pIfaceTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#AddAndRemoveBonjourService/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#AddAndRemoveUpnpService/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#AddGroup/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#AddGroupWithConfig_FailureInvalidFrequency/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#AddGroupWithConfig_FailureInvalidPassphrase/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#AddGroupWithConfig_FailureInvalidSsid/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#AddGroupWithConfig_Success/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#AddGroupWithConfigurationParams/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#CancelConnect/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#ConfigureExtListen/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#ConfigureExtListenWithParams/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#Connect/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#ConnectWithParams/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#CreateGroupOwner/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#EnableMacRandomization/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#EnableWfd/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#Find/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#FindSocialChannelsOnly/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#FindSpecificFrequency/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#FindWithParams/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#Flush/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#FlushServices/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#GetDeviceAddress/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#GetGroupCapability/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#GetName/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#GetSsid/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#GetType/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#Invite/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#ProvisionDiscovery/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#RegisterCallback/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#Reinvoke/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#Reject/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#RemoveGroup/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetDisallowedFrequencies/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetGetEdmg/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetGroupIdle/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetListenChannel/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetMiracastMode/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetPowerSave/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetSsidPostfix/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetVendorElements/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetWfdDeviceInfo/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetWfdR2DeviceInfo/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetWpsConfigMethods/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetWpsDeviceName/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetWpsDeviceType/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetWpsManufacturer/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetWpsModelName/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetWpsModelNumber/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#SetWpsSerialNumber/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantP2pIfaceTargetTest Supplicant/SupplicantP2pIfaceAidlTest#StopFind/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <!-- VtsHalWifiSupplicantStaIfaceTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaIfaceTargetTest Supplicant/SupplicantStaIfaceAidlTest#GetConnectionCapabilities/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaIfaceTargetTest Supplicant/SupplicantStaIfaceAidlTest#GetKeyMgmtCapabilities/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaIfaceTargetTest Supplicant/SupplicantStaIfaceAidlTest#GetMacAddress/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaIfaceTargetTest Supplicant/SupplicantStaIfaceAidlTest#GetName/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaIfaceTargetTest Supplicant/SupplicantStaIfaceAidlTest#GetWpaDriverCapabilities/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaIfaceTargetTest Supplicant/SupplicantStaIfaceAidlTest#ListNetworks/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaIfaceTargetTest Supplicant/SupplicantStaIfaceAidlTest#RegisterCallback/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaIfaceTargetTest Supplicant/SupplicantStaIfaceAidlTest#SetBtCoexistenceMode/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaIfaceTargetTest Supplicant/SupplicantStaIfaceAidlTest#SetBtCoexistenceScanModeEnabled/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <!-- VtsHalWifiSupplicantStaNetworkTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#DisableEht/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#EnableSaePkOnlyMode/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#EnableTlsSuiteBEapPhase1Param/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#GetInterfaceName/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#GetType/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#RegisterCallback/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SendNetworkEapSimUmtsAuthFailure/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SendNetworkEapSimUmtsAutsResponse/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetEapEncryptedImsiIdentity/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetEapErp/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetBssid/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetEapAltSubjectMatch/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetEapAnonymousIdentity/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetEapCACert/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetEapEngine/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetEapEngineId/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetEapIdentity/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetEapMethod/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetEapPhase2Method/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetEapPrivateKeyId/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetGroupCipher/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetIdStr/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetKeyMgmt/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetProto/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetRequirePmf/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetSaePasswordId/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetScanSsid/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetWapiCertSuite/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetGetWepKeys/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetMinimumTlsVersionEapPhase1Param/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetSaeH2eMode/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetUpdateIdentifier/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiSupplicantStaNetworkTargetTest Supplicant/SupplicantStaNetworkAidlTest#SetVendorData/0_android_hardware_wifi_supplicant_ISupplicant_default"/>
+    <!-- VtsVendorAtomHostJavaTest -->
+    <option name="compatibility:include-filter" value="VtsVendorAtomHostJavaTest com.android.vts.istats.VendorAtomTests#testReportVendorAtomInt"/>
+    <option name="compatibility:include-filter" value="VtsVendorAtomHostJavaTest com.android.vts.istats.VendorAtomTests#testReportVendorAtomRepeated"/>
+    <option name="compatibility:include-filter" value="VtsVendorAtomHostJavaTest com.android.vts.istats.VendorAtomTests#testReportVendorAtomWrongId"/>
+    <!-- binderDriverInterfaceTest -->
+    <option name="compatibility:include-filter" value="binderDriverInterfaceTest BinderDriverInterfaceTest#RequestDeathNotification"/>
+    <!-- binderLibTest -->
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibRpcTest#SetRpcClientDebug"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibRpcTest#SetRpcClientDebugTwice"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest#BinderCallContextGuard"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest#CheckNoHeaderMappedInUser"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest#Freeze"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest#HangingServices"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest#ThreadPoolAvailableThreads"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest/BinderLibRpcTestP#SetRpcClientDebugNoKeepAliveBinder/local"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest/BinderLibRpcTestP#SetRpcClientDebugNoKeepAliveBinder/remote"/>
+    <option name="compatibility:include-filter" value="binderLibTest ServiceNotifications#Unregister"/>
+    <!-- binderRpcTest -->
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc#CanUseExperimentalWireVersion"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc#Java"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#CheckWaitingForRead/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#CheckWaitingForRead/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#CheckWaitingForRead/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#GoodCertificate/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#GoodCertificate/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#GoodCertificate/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#GoodCertificate/raw_uds_tls_PEM_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousClient/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousClient/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousClient/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousServer/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousServer/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousServer/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousServer/raw_uds_tls_DER_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MultipleClients/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MultipleClients/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MultipleClients/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#Trigger/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#Trigger/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#Trigger/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedClient/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedClient/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedClient/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedServer/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedServer/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedServer/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#CannotMixBindersBetweenTwoSessionsToTheSameServer/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#GetInterfaceDescriptor/unix_domain_socket_raw_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#GetInterfaceDescriptor/unix_domain_socket_tls_clientV0_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#MultipleSessions/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#MultipleSessions/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#NestedTransactions/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallExhaustion/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallExhaustion/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallQueueing/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallQueueing/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallQueueingWithFds/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallQueueingWithFds/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayCallQueueingWithFds/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#OnewayStressTest/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#RepeatBinder/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#RepeatBinderNull/unix_domain_socket_raw_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#RepeatBinderNull/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#RepeatTheirBinder/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendAndGetResultBack/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendAndGetResultBackBig/unix_domain_socket_raw_clientV0_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendAndGetResultBackBig/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendSomethingOneway/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendSomethingOneway/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolOverSaturated/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolOverSaturated/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolOverSaturated/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolOverSaturated/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolOverSaturated/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadingStressTest/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#WorksWithLibbinderNdkUserTransaction/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <!-- binderRpcTestNoKernel -->
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel BinderRpc#CanUseExperimentalWireVersion"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallExhaustion/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallExhaustion/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallExhaustion/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallExhaustion/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallQueueing/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallQueueingWithFds/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallQueueingWithFds/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallQueueingWithFds/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallQueueingWithFds/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallQueueingWithFds/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayStressTest/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayStressTest/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayStressTest/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayStressTest/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayStressTest/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolLimitOutgoing/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolOverSaturated/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolOverSaturated/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolOverSaturated/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolOverSaturated/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolOverSaturated/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolOverSaturated/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolOverSaturated/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolOverSaturated/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadingStressTest/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadingStressTest/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <!-- binderRpcTestSingleThreaded -->
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded BinderARpcNdk#ARpcDoubleRemoveProvider"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded BinderRpc#CanUseExperimentalWireVersion"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded BinderRpc#Java"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#AidlDelegatorTest/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#AidlDelegatorTest/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#AppendInvalidFd/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#AppendSeparateFormats/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#AppendSeparateFormats/unix_domain_socket_tls_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Callbacks/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenTwoSessionsToTheSameServer/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenTwoSessionsToTheSameServer/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Die/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Die/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Die/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Fds/unix_domain_socket_raw_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Fds/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#FileDescriptorTransportOptionalUnix/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#FileDescriptorTransportOptionalUnix/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#GetInterfaceDescriptor/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#HoldBinder/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#HoldBinder/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#HoldBinder/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#InvalidNullBinderReturn/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#InvalidNullBinderReturn/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#MultipleSessions/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#NestedTransactions/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallbackWithNoThread/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#RepeatBinder/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#RepeatRootObject/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#RepeatRootObject/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#RepeatTheirBinder/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#RepeatTheirBinder/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SameBinderEquality/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SameBinderEquality/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SameBinderEquality/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SameBinderEqualityWeak/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SameBinderEqualityWeak/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendSomethingOneway/unix_domain_socket_tls_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendTooManyFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SingleSession/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SingleSession/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SingleSession/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SingleSession/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SingleSession/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpcAccessor#InjectAndGetServiceHappyPath/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <!-- binderRpcTestSingleThreadedNoKernel -->
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel BinderRpc#CanUseExperimentalWireVersion"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel BinderRpc/RpcTransportTest#GoodCertificate/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AidlDelegatorTest/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AidlDelegatorTest/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AidlDelegatorTest/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AppendInvalidFd/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AppendSeparateFormats/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AppendSeparateFormats/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#CallMeBack/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#CallMeBack/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_raw_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Die/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Die/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Die/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Fds/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Fds/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#GetInterfaceDescriptor/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#InvalidNullBinderReturn/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ManySessions/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ManySessions/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ManySessions/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#NestedTransactions/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallDoesNotWait/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallbackWithNoThread/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallbackWithNoThread/unix_domain_socket_raw_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallbackWithNoThread/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallbackWithNoThread/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#RepeatBinderNull/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#RepeatRootObject/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#RepeatTheirBinder/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#RepeatTheirBinder/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SameBinderEqualityWeak/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SameBinderEqualityWeak/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SameBinderEqualityWeak/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendAndGetResultBack/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendAndGetResultBackBig/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendSomethingOneway/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#UnknownTransaction/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <!-- binderRpcWireProtocolTest -->
+    <option name="compatibility:include-filter" value="binderRpcWireProtocolTest RpcWire#ReleaseBranchHasFrozenRpcWireProtocol"/>
+    <!-- binderSafeInterfaceTest -->
+    <option name="compatibility:include-filter" value="binderSafeInterfaceTest SafeInterfaceTest#TestIncrementNativeHandle"/>
+    <!-- bpf_module_test -->
+    <option name="compatibility:include-filter" value="bpf_module_test BpfRaceTest#testRaceWithBarrier"/>
+    <!-- connectivity_native_test -->
+    <option name="compatibility:include-filter" value="connectivity_native_test ConnectivityNativeBinderTest#BlockPort4Tcp"/>
+    <option name="compatibility:include-filter" value="connectivity_native_test ConnectivityNativeBinderTest#BlockPort4Udp"/>
+    <option name="compatibility:include-filter" value="connectivity_native_test ConnectivityNativeBinderTest#BlockPort6Tcp"/>
+    <option name="compatibility:include-filter" value="connectivity_native_test ConnectivityNativeBinderTest#BlockPortTwice"/>
+    <!-- drop_caches_test -->
+    <option name="compatibility:include-filter" value="drop_caches_test drop_caches#set_perf_property"/>
+    <!-- elf_alignment_test -->
+    <option name="compatibility:include-filter" value="elf_alignment_test ElfTestPartitionsAligned/ElfAlignmentTest#VerifyLoadSegmentAlignment/7"/>
+    <!-- fiemap_writer_test -->
+    <option name="compatibility:include-filter" value="fiemap_writer_test FiemapWriterTest#CheckFileSizeActual"/>
+    <!-- fmq_test -->
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_32_to_32"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_32_to_64"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_64_to_32"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_64_to_64"/>
+    <!-- hidl_test_java -->
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_32_to_64"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_32_to_java"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_64_to_32"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_64_to_64"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_64_to_java"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_java_to_32"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_java_to_64"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_java_to_java"/>
+    <!-- keystore2_client_tests -->
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_3des_key_tests::keystore2_3des_ecb_cbc_generate_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_3des_key_tests::keystore2_3des_key_encrypt_fails_invalid_input_length"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_3des_key_tests::keystore2_3des_key_fails_unsupported_block_mode"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_ctr_gcm_generate_key_fails_incompatible"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_ctr_gcm_generate_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_ecb_cbc_generate_key"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_gcm_op_fails_invalid_mac_len"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_gcm_op_fails_missing_mac_len"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_gcm_op_fails_unsupported_mac_len"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_key_op_fails_incompatible_blockmode"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_key_op_fails_incompatible_padding"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_key_op_fails_nonce_prohibited"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_attest_key_tests::keystore2_attest_ecdsa_attestation_id"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_attest_key_tests::keystore2_attest_key_fails_with_invalid_attestation_id"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_attest_key_tests::keystore2_attest_key_without_attestation_id_support_fails_with_cannot_attest_id"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_attest_key_tests::keystore2_attest_rsa_attestation_id"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_attest_key_tests::keystore2_attest_rsa_encrypt_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_attest_key_tests::keystore2_generate_attested_key_fail_to_get_aaid"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_attestation_key_with_auth_app_id_app_data_test_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_attested_key_auth_app_id_app_data_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_active_datetime_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_app_data_test_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_app_data_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_app_id_test_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_app_id_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_creation_date_time_test_fail_with_invalid_arg_error"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_early_boot_only_op_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_future_active_datetime_test_op_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_future_origination_expire_datetime_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_future_usage_expire_datetime_hmac_verify_op_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_include_unique_id_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_max_uses_per_boot"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_origination_expire_datetime_test_op_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_serial_number_subject_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_usage_count_limit"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_usage_count_limit_one"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_usage_expire_datetime_decrypt_op_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_usage_expire_datetime_hmac_verify_op_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_usage_future_expire_datetime_decrypt_op_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_non_attested_key_auth_usage_count_limit"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_delete_key_tests::keystore2_delete_key_blob_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_delete_key_tests::keystore2_delete_key_blob_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_delete_key_tests::keystore2_delete_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_delete_key_tests::keystore2_delete_key_with_blob_domain_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_device_unique_attestation_tests::keystore2_gen_ec_key_device_unique_attest_with_strongbox_sec_level_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_device_unique_attestation_tests::keystore2_gen_key_device_unique_attest_with_default_sec_level_unimplemented"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_device_unique_attestation_tests::keystore2_gen_rsa_key_device_unique_attest_with_strongbox_sec_level_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::keystore2_create_op_with_incompatible_key_digest"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::keystore2_generate_key_with_blob_domain"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::keystore2_get_key_entry_blob_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::keystore2_key_owner_validation"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_md5_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_md5_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_md5_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_md5_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_none_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_none_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_none_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_none_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha1_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha1_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha1_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha1_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha224_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha224_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha224_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha224_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha256_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha256_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha256_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha256_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha384_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha384_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha384_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha384_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha512_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha512_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha512_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha512_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_delete_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_get_info_use_key_perm"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_fails_with_grant_perm_expect_perm_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_fails_with_permission_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_to_multi_users_delete_fails_with_key_not_found_error"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_to_multi_users_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_with_invalid_perm_expecting_syserror"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_with_perm_none"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_ungrant_fails_with_non_existing_key_expect_key_not_found_error"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_ungrant_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_hmac_key_tests::keystore2_hmac_gen_keys_fails_expect_unsupported_key_size"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_hmac_key_tests::keystore2_hmac_gen_keys_fails_expect_unsupported_min_mac_length"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_hmac_key_tests::keystore2_hmac_key_op_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_hmac_key_tests::keystore2_hmac_key_op_with_mac_len_greater_than_digest_len_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_hmac_key_tests::keystore2_hmac_key_op_with_mac_len_less_than_min_mac_len_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_import_3des_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_import_aes_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_import_ec_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_import_hmac_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_rsa_import_key_determine_key_size_and_pub_exponent"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_rsa_import_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_rsa_import_key_with_multipurpose_fails_incompt_purpose_error"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_agreement_tests::keystore2_ec_agree_key_with_different_curves_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_agreement_tests::test_ec_p224_key_agreement"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_agreement_tests::test_ec_p256_key_agreement"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_agreement_tests::test_ec_p384_key_agreement"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_agreement_tests::test_ec_p521_key_agreement"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_id_domain_tests::keystore2_find_key_with_key_id_as_domain"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_id_domain_tests::keystore2_key_id_alias_rebind_verify_by_alias"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_id_domain_tests::keystore2_key_id_alias_rebind_verify_by_key_id"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_get_number_of_entries_fails_perm_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_fails_perm_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_validate_count_and_order_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_with_empty_keystore_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_with_long_aliases_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_with_multi_procs_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_with_selinux_domain_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_fails_perm_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_with_long_aliases_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_abort_finalized_op_fail_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_backend_busy_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_forced_op_after_backendbusy_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_forced_op_perm_denied_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_forced_op_success_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_max_forced_ops_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_op_abort_fails_with_operation_busy_error_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_op_abort_success_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_op_fails_operation_busy"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_ops_prune_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_md5_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_md5_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_none_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_none_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_none_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_pad_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_pad_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_pad_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha1_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha1_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha224_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha224_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha256_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha256_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha384_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha384_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha512_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_none_sha512_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_md5_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_md5_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_no_mgf_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_no_mgf_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha1_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha1_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha224_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha224_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha256_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha256_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha384_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha384_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha512_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha512_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_md5_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_md5_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_no_mgf_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_no_mgf_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha1_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha1_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha224_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha224_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha256_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha256_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha384_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha384_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha512_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha512_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_md5_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_md5_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_no_mgf_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_no_mgf_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha1_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha1_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha224_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha224_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha256_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha256_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha384_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha384_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha512_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha512_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_md5_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_md5_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_no_mgf_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_no_mgf_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha1_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha1_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha224_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha224_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha256_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha256_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha384_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha384_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha512_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha512_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_md5_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_md5_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_no_mgf_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_no_mgf_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha1_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha1_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha224_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha224_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha256_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha256_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha384_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha384_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha512_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha512_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_md5_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_md5_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_no_mgf_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_no_mgf_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha1_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha1_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha224_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha224_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha256_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha256_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha384_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha384_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha512_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha512_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_md5_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_md5_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_none_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_none_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_none_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_pad_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_pad_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_pad_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha1_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha1_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha224_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha224_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha256_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha256_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha384_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha384_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha512_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha512_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_encrypt_key_op_invalid_purpose"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_encrypt_key_unsupported_padding"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_gen_keys_with_oaep_paddings_without_digest"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_generate_key_with_oaep_padding_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_generate_keys"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_generate_signing_key_padding_pss_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_key_missing_purpose"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_key_unsupported_op"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_key_unsupported_purpose"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_sign_key_op_invalid_purpose"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_signing_key_unsupported_padding"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_none_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_none_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_none_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_md5_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_md5_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_none_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_none_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_none_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha1_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha1_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha224_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha224_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha256_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha256_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha384_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha384_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha512_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha512_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_md5_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_md5_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha1_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha1_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha224_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha224_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha256_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha256_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha384_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha384_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha512_3072"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha512_4096"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_update_subcomponent_tests::keystore2_update_subcomponent_fails_permission_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_update_subcomponent_tests::keystore2_update_subcomponent_success"/>
+    <!-- libbinder_ndk_unit_test -->
+    <option name="compatibility:include-filter" value="libbinder_ndk_unit_test NdkBinder#CheckLazyServiceShutDown"/>
+    <option name="compatibility:include-filter" value="libbinder_ndk_unit_test NdkBinder#ForcedPersistenceTest"/>
+    <option name="compatibility:include-filter" value="libbinder_ndk_unit_test NdkBinder#GetServiceThatDoesntExist"/>
+    <option name="compatibility:include-filter" value="libbinder_ndk_unit_test NdkBinder#GetTestServiceStressTest"/>
+    <!-- netd_integration_test -->
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestBpfJitAlwaysOn"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestHaveEfficientUnalignedAccess"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestIsLTS"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestMinRequiredLTS_4_19"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestMinRequiredLTS_5_10"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestSupportsAcceptRaMinLft"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestSupportsCommonUsbEthernetDongles"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetUtilsWrapperTest#TestFileCapabilities"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#BypassableVPNFallthrough"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#GetFwmarkForNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#GetProcSysNet"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#InterfaceAddRemoveAddress"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#InterfaceGetCfg"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#IpSecSetEncapSocketOwner"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#IpSecTunnelInterface"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#NetworkPermissionDefault"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#PerAppDefaultNetwork_ExplicitlySelectNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#PerAppDefaultNetwork_ImplicitlySelectNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#PerAppDefaultNetwork_OverlappedUidRanges"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#PerAppDefaultNetwork_UnconnectedSocket"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#SecureVPNFallthrough"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#SetProcSysNet"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#SocketDestroy"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#SocketDestroyLinkLocal"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#TetherDeletedInterface"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#TetherForwardAddRemove"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#TetherStartStopStatus"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#UidRangeSubPriority_ImplicitlySelectNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#UidRangeSubPriority_VerifyPhysicalNwIpRules"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#XfrmControllerInit"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdNamespaceTest#CheckFullNamespaceSupport"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdNamespaceTest#CheckMountNamespaceSupport"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdNamespaceTest#CheckNetworkNamespaceSupport"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdNamespaceTest#CheckNoUserNamespaceSupport"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdNamespaceTest#CheckUTSNamespaceSupport"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdSELinuxTest#CheckProperBpfLabels"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdSELinuxTest#CheckProperMTULabels"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/BypassableVPN_selectAppDefaultNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/BypassableVPN_selectSystemDefaultNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/BypassableVPN_selectVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/SecureVPN_selectAppDefaultNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/SecureVPN_selectSystemDefaultNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/SecureVPN_selectVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnParameterizedTest#ImplicitlySelectNetwork/BypassableVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnParameterizedTest#ImplicitlySelectNetwork/SecureVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnParameterizedTest#UnconnectedSocket/BypassableVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnParameterizedTest#UnconnectedSocket/SecureVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppNetworkPermissionsTest#DoesNotAffectDefaultNetworkSelection"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppNetworkPermissionsTest#HasExplicitAccess"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppNetworkPermissionsTest#HasImplicitAccess"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppNetworkPermissionsTest#PermissionDoesNotAffectPerAppDefaultNetworkSelection"/>
+    <!-- vts_approvedBuild_validate_test -->
+    <option name="compatibility:include-filter" value="vts_approvedBuild_validate_test CheckConfig#approvedBuildValidation"/>
+    <!-- vts_eol_enforcement_test -->
+    <option name="compatibility:include-filter" value="vts_eol_enforcement_test EolEnforcementTest#KernelNotEol"/>
+    <!-- vts_fs_test -->
+    <option name="compatibility:include-filter" value="vts_fs_test fs#PartitionTypes"/>
+    <!-- vts_generic_boot_image_test -->
+    <option name="compatibility:include-filter" value="vts_generic_boot_image_test GenericBootImageTest#GenericRamdisk"/>
+    <option name="compatibility:include-filter" value="vts_generic_boot_image_test GenericBootImageTest#KernelReleaseFormat"/>
+    <!-- vts_gki_compliance_test -->
+    <option name="compatibility:include-filter" value="vts_gki_compliance_test KernelVersionTest#AgainstPlatformRelease"/>
+    <option name="compatibility:include-filter" value="vts_gki_compliance_test KernelVersionTest#GrfDevicesMustUseLatestKernel"/>
+    <!-- vts_halManifest_validate_test -->
+    <option name="compatibility:include-filter" value="vts_halManifest_validate_test CheckConfig#halManifestValidation"/>
+    <!-- vts_ibase_test -->
+    <option name="compatibility:include-filter" value="vts_ibase_test VtsHalBaseV1_0TargetTest#CanPing"/>
+    <option name="compatibility:include-filter" value="vts_ibase_test VtsHalBaseV1_0TargetTest#Descriptor"/>
+    <option name="compatibility:include-filter" value="vts_ibase_test VtsHalBaseV1_0TargetTest#InterfaceChain"/>
+    <!-- vts_kernelLifetimes_validate_test -->
+    <option name="compatibility:include-filter" value="vts_kernelLifetimes_validate_test CheckConfig#approvedBuildValidation"/>
+    <!-- vts_kernel_checkpoint_test -->
+    <option name="compatibility:include-filter" value="vts_kernel_checkpoint_test __main__.VtsKernelCheckpointTest#testCheckpointEnabled"/>
+    <option name="compatibility:include-filter" value="vts_kernel_checkpoint_test __main__.VtsKernelCheckpointTest#testCommit"/>
+    <!-- vts_kernel_encryption_test -->
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test DmDefaultKeyTest#TestAdiantum"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test DmDefaultKeyTest#TestAes256Xts"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test DmDefaultKeyTest#TestHwWrappedKey"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAdiantumPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAesEmmcOptimizedHwWrappedKeyPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAesEmmcOptimizedPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAesInlineCryptOptimizedHwWrappedKeyPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAesInlineCryptOptimizedPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAesPerFileKeysPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestHwWrappedKeyCorruption"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBETest#TestFileContentsRandomness"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBETest#TestUserDirectoryPolicies"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test MetadataEncryptionTest#TestRandomness"/>
+    <!-- vts_kernel_fuse_bpf_test -->
+    <option name="compatibility:include-filter" value="vts_kernel_fuse_bpf_test __main__.VtsKernelFuseBpfTest#testFuseBpfEnabled"/>
+    <!-- vts_kernel_loopconfig_test -->
+    <option name="compatibility:include-filter" value="vts_kernel_loopconfig_test KernelLoopConfigTest#ValidLoopPartParameter"/>
+    <!-- vts_kernel_net_tests -->
+    <option name="compatibility:include-filter" value="vts_kernel_net_tests vts_kernel_net_tests#vts_kernel_net_tests"/>
+    <!-- vts_kernel_proc_file_api_test -->
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#testProcUidProcstatSet"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcAsoundCardsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcCmdlineTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcCorePattern"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcCorePipeLimit"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcCpuInfoTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDirtyBackgroundBytes"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDirtyBackgroundRatio"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDirtyExpireCentisecs"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDiskstatsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDmesgRestrict"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDomainname"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDropCaches"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcExtraFreeKbytes"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcFilesystemsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcHostname"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcHungTaskTimeoutSecs"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcKmsgTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcKptrRestrictTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcLoadavgTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMapsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMaxMapCount"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMemInfoTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMisc"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMmapMinAddrTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMmapRndBitsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcModulesDisabled"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcModulesTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMountsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcOverCommitMemoryTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPageCluster"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPanicOnOops"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPerfEventMaxSampleRate"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPerfEventParanoid"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPidMax"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPipeMaxSize"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcProtectedHardlinks"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcProtectedSymlinks"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcRandomizeVaSpaceTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcRemoveUidRangeTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSchedChildRunsFirst"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSchedRTPeriodUS"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSchedRTRuntimeUS"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcShowUidStatTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcStatTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSuidDumpable"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSwapsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSysKernelRandomBootId"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSysRqTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidConcurrentActiveTimeTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidConcurrentPolicyTimeTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidCpuPowerConcurrentActiveTimeTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidCpuPowerConcurrentPolicyTimeTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidCpuPowerTimeInStateTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidIoStatsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidTimeInStateTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUptime"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcVersionTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcVmallocInfoTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcVmstat"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcZoneInfoTest"/>
+    <!-- vts_libsnapshot_test -->
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test MetadataMountedTest#Recovery"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test Snapshot/FlashAfterUpdateTest#FlashSlotAfterUpdate/FlashNewSlotAfterMerge"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test Snapshot/FlashAfterUpdateTest#FlashSlotAfterUpdate/FlashOldSlotAfterMerge"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotTest#FirstStageMountAndMerge"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotTest#FlashSuperDuringMerge"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotTest#Merge"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotTest#NoMergeBeforeReboot"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#AddPartition"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#CancelOnTargetSlot"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#DaemonTransition"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#DataWipeRequiredInPackage"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#DataWipeRollbackInRecovery"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#DataWipeWithStaleSnapshots"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#DuplicateOps"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#FullUpdateFlow"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#Hashtree"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#MapAllSnapshots"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#MapAllSnapshotsWithoutSlotSwitch"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#MergeCannotRemoveCow"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#MergeInFastboot"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#MergeInRecovery"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#ReclaimCow"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#SpaceSwapUpdate"/>
+    <option name="compatibility:include-filter" value="vts_libsnapshot_test SnapshotUpdateTest#TestRollback"/>
+    <!-- vts_snapuserd_test -->
+    <option name="compatibility:include-filter" value="vts_snapuserd_test Io/SnapuserdTest#Snapshot_COPY_Overlap_Merge_Resume_IO_Validate_TEST/0"/>
+    <option name="compatibility:include-filter" value="vts_snapuserd_test Io/SnapuserdTest#Snapshot_COPY_Overlap_Merge_Resume_IO_Validate_TEST/3"/>
+    <option name="compatibility:include-filter" value="vts_snapuserd_test Io/SnapuserdTest#Snapshot_IO_TEST/1"/>
+    <!-- vts_treble_platform_version_test -->
+    <option name="compatibility:include-filter" value="vts_treble_platform_version_test __main__.VtsTreblePlatformVersionTest#testSdkVersion"/>
+    <option name="compatibility:include-filter" value="vts_treble_platform_version_test __main__.VtsTreblePlatformVersionTest#testVndkVersion"/>
+    <!-- vts_treble_sys_prop_test -->
+    <option name="compatibility:include-filter" value="vts_treble_sys_prop_test __main__.VtsTrebleSysPropTest#testExportedPlatformPropertyIntegrity"/>
+    <!-- vts_treble_vintf_framework_test -->
+    <option name="compatibility:include-filter" value="vts_treble_vintf_framework_test SystemVendorTest#DeviceManifestFrameworkMatrixCompatibility"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_framework_test SystemVendorTest#FrameworkManifestDeviceMatrixCompatibility"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_framework_test SystemVendorTest#KernelCompatibility"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_framework_test SystemVendorTest#NoMainlineKernel"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_framework_test SystemVendorTest#VendorFrameworkCompatibility"/>
+    <!-- vts_treble_vintf_vendor_test -->
+    <option name="compatibility:include-filter" value="vts_treble_vintf_vendor_test DeviceManifest/SingleAidlTest#HalIsServed/android_hardware_bluetooth_IBluetoothHci_default_V1_8"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_vendor_test DeviceManifest/SingleAidlTest#HalIsServed/android_hardware_bluetooth_finder_IBluetoothFinder_default_V1_10"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_vendor_test DeviceManifestTest#NoDeprecatedHalsOnManifest"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_vendor_test DeviceMatrixTest#VndkVersion"/>
+    <!-- vts_vndk_abi_test -->
+    <option name="compatibility:include-filter" value="vts_vndk_abi_test __main__.VtsVndkAbiTest#testAbiCompatibility32"/>
+    <option name="compatibility:include-filter" value="vts_vndk_abi_test __main__.VtsVndkAbiTest#testAbiCompatibility64"/>
+    <!-- vts_vndk_dependency_test -->
+    <option name="compatibility:include-filter" value="vts_vndk_dependency_test vts_vndk_dependency_test#vts_vndk_dependency_test"/>
+    <!-- vts_vndk_files_test -->
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testNoLlndkInOdm32"/>
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testNoLlndkInOdm64"/>
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testNoLlndkInVendor32"/>
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testNoLlndkInVendor64"/>
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testVndkCoreDirectory32"/>
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testVndkCoreDirectory64"/>
+</configuration>
diff --git a/tools/vts-core-tradefed/res/config/vts-validation-exclude.xml b/tools/vts-core-tradefed/res/config/vts-validation-exclude.xml
index 27c3698b6..af6920583 100644
--- a/tools/vts-core-tradefed/res/config/vts-validation-exclude.xml
+++ b/tools/vts-core-tradefed/res/config/vts-validation-exclude.xml
@@ -28,6 +28,7 @@
     <option name="compatibility:exclude-filter" value="vts_compatibilityMatrix_validate_test" />
     <option name="compatibility:exclude-filter" value="vts_core_liblp_test" />
     <option name="compatibility:exclude-filter" value="vts_defaultPermissions_validate_test" />
+    <option name="compatibility:exclude-filter" value="vts_eol_enforcement_test" />
     <option name="compatibility:exclude-filter" value="vts_gsi_boot_test" />
     <option name="compatibility:exclude-filter" value="vts_ibase_test" />
     <option name="compatibility:exclude-filter" value="vts_kernel_checkpoint_test" />
@@ -36,6 +37,7 @@
     <option name="compatibility:exclude-filter" value="vts_kernel_net_tests" />
     <option name="compatibility:exclude-filter" value="vts_kernel_toolchain" />
     <option name="compatibility:exclude-filter" value="vts_kernel_tun_test" />
+    <option name="compatibility:exclude-filter" value="vts_kernelLifetimes_validate_test" />
     <option name="compatibility:exclude-filter" value="vts_libdm_test" />
     <option name="compatibility:exclude-filter" value="vts_libsnapshot_test" />
     <option name="compatibility:exclude-filter" value="vts_linux_kselftest_arm_32" />
```

