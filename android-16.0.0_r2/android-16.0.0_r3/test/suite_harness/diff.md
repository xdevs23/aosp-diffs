```diff
diff --git a/common/host-side/tradefed/res/config/tf-aosp-compatibility-config.xml b/common/host-side/tradefed/res/config/tf-aosp-compatibility-config.xml
index 9d023690..7c0130b0 100644
--- a/common/host-side/tradefed/res/config/tf-aosp-compatibility-config.xml
+++ b/common/host-side/tradefed/res/config/tf-aosp-compatibility-config.xml
@@ -21,4 +21,12 @@
         <option name="run-command" value="am switch-user 10" />
     </target_preparer>
     <option name="post-boot-command" value="am switch-user 10" />
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.DeviceInfoCollector">
+        <option name="apk" value="CtsDeviceInfo.apk"/>
+        <option name="package" value="com.android.compatibility.common.deviceinfo"/>
+        <option name="src-dir" value="/sdcard/device-info-files/"/>
+        <option name="dest-dir" value="device-info-files/"/>
+        <option name="temp-dir" value="temp-device-info-files/"/>
+        <option name="throw-error" value="false"/>
+    </target_preparer>
 </configuration>
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/BusinessLogicPreparer.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/BusinessLogicPreparer.java
index bd425657..88f0e8ab 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/BusinessLogicPreparer.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/BusinessLogicPreparer.java
@@ -72,6 +72,7 @@ import java.util.Map;
 import java.util.regex.Pattern;
 import java.util.regex.Matcher;
 import java.util.Set;
+import java.util.stream.Collectors;
 
 /**
  * Pushes business Logic to the host and the test device, for use by test cases in the test suite.
@@ -415,7 +416,12 @@ public class BusinessLogicPreparer extends BaseTargetPreparer
             List<String> dynamicConfigFeatures = DynamicConfigFileReader.getValuesFromConfig(
                     buildInfo, getSuiteNames(), DYNAMIC_CONFIG_FEATURES_KEY);
             Set<String> deviceFeatures = FeatureUtil.getAllFeatures(device);
-            dynamicConfigFeatures.retainAll(deviceFeatures);
+            // Strip version number from feature strings
+            Set<String> featuresWithoutVersion =
+                deviceFeatures.stream()
+                              .map(feature -> feature.split("=")[0])
+                              .collect(Collectors.toSet());
+            dynamicConfigFeatures.retainAll(featuresWithoutVersion);
             return dynamicConfigFeatures;
         } catch (XmlPullParserException | IOException e) {
             CLog.e("Failed to pull business logic features from dynamic config");
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
index cf3857cb..489072f4 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
@@ -157,6 +157,11 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
                             ? BASELINE_DEQP_TEST_LIST
                             : REPRESENTATIVE_DEQP_TEST_LIST;
             Set<String> dependencies = getDeqpDependencies(device, deqpTestList);
+            if (dependencies.isEmpty()) {
+                throw new TargetSetupError(
+                        "Fail to detect dEQP dependencies from the device.",
+                        TestErrorIdentifier.TEST_ABORTED);
+            }
 
             // Identify and write dependencies to device info report.
             try (HostInfoStore store = new HostInfoStore(jsonFile)) {
@@ -213,10 +218,11 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
 
                 String command =
                         String.format(
-                                "cd %s && simpleperf record -o %s %s --deqp-caselist-file=%s"
-                                    + " --deqp-log-images=disable --deqp-log-shader-sources=disable"
-                                    + " --deqp-log-filename=%s --deqp-surface-type=fbo"
-                                    + " --deqp-surface-width=2048 --deqp-surface-height=2048",
+                                "cd %s && simpleperf record -e cpu-cycles:u -o %s %s"
+                                    + " --deqp-caselist-file=%s --deqp-log-images=disable"
+                                    + " --deqp-log-shader-sources=disable --deqp-log-filename=%s"
+                                    + " --deqp-surface-type=fbo --deqp-surface-width=2048"
+                                    + " --deqp-surface-height=2048",
                                 DEVICE_DEQP_DIR, perfFile, binaryFile, testFile, logFile);
                 device.executeShellCommand(command);
 
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
index 08118f94..d984f680 100644
--- a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
@@ -18,6 +18,7 @@ package com.android.compatibility.common.tradefed.targetprep;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.endsWith;
 import static org.mockito.Mockito.mock;
@@ -149,6 +150,40 @@ public class IncrementalDeqpPreparerTest {
         }
     }
 
+    @Test
+    public void testRunIncrementalDeqp_emptyDependencies() throws Exception {
+        File resultDir = FileUtil.createTempDir("result");
+        try {
+            IBuildInfo mMockBuildInfo = new BuildInfo();
+            IInvocationContext mMockContext = new InvocationContext();
+            mMockContext.addDeviceBuildInfo("build", mMockBuildInfo);
+            mMockContext.addAllocatedDevice("device", mMockDevice);
+            File deviceInfoDir = new File(resultDir, "device-info-files");
+            deviceInfoDir.mkdir();
+            CompatibilityBuildHelper mMockBuildHelper =
+                    new CompatibilityBuildHelper(mMockBuildInfo) {
+                        @Override
+                        public File getResultDir() {
+                            return resultDir;
+                        }
+                    };
+            File dumpFile = FileUtil.createTempFile("parseDump", "perf-dump.txt");
+            when(mMockDevice.pullFile(endsWith("-perf-dump.txt")))
+                    .thenReturn(dumpFile, null, null, null);
+
+            assertThrows(
+                    TargetSetupError.class,
+                    () ->
+                            mPreparer.runIncrementalDeqp(
+                                    mMockContext,
+                                    mMockDevice,
+                                    mMockBuildHelper,
+                                    IncrementalDeqpPreparer.RunMode.LIGHTWEIGHT_RUN));
+        } finally {
+            FileUtil.recursiveDelete(resultDir);
+        }
+    }
+
     @Test
     public void testParseDump() throws Exception {
         InputStream inputStream = getClass().getResourceAsStream("/testdata/perf-dump.txt");
diff --git a/common/host-side/util/src/com/android/compatibility/common/util/FeatureUtil.java b/common/host-side/util/src/com/android/compatibility/common/util/FeatureUtil.java
index ff26d794..06d96a65 100644
--- a/common/host-side/util/src/com/android/compatibility/common/util/FeatureUtil.java
+++ b/common/host-side/util/src/com/android/compatibility/common/util/FeatureUtil.java
@@ -34,7 +34,7 @@ public class FeatureUtil {
     public static final String TV_FEATURE = "android.hardware.type.television";
     public static final String WATCH_FEATURE = "android.hardware.type.watch";
     public static final String FEATURE_MICROPHONE = "android.hardware.microphone";
-    public static final String XR_FEATURE = "android.software.xr.immersive";
+    public static final String XR_API_FEATURE = "android.software.xr.api.spatial";
 
     /** Returns true if the device has a given system feature */
     public static boolean hasSystemFeature(ITestDevice device, String feature)
@@ -92,7 +92,7 @@ public class FeatureUtil {
 
     /** Returns true if the device has feature XR_FEATURE */
     public static boolean isXrHeadset(ITestDevice device) throws DeviceNotAvailableException {
-        return hasSystemFeature(device, XR_FEATURE);
+        return hasSystemFeature(device, XR_API_FEATURE);
     }
 
     /** Returns true if the device is a low ram device:
```

