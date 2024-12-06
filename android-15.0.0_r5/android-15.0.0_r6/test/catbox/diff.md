```diff
diff --git a/report/src/com/android/catbox/util/TestMetricsUtil.java b/report/src/com/android/catbox/util/TestMetricsUtil.java
index e801335..488309e 100644
--- a/report/src/com/android/catbox/util/TestMetricsUtil.java
+++ b/report/src/com/android/catbox/util/TestMetricsUtil.java
@@ -84,12 +84,17 @@ public class TestMetricsUtil {
 
         // Group test cases which differs only by the iteration separator or test the same name.
         String className = testDescription.getClassName();
-        int iterationSeparatorIndex = testDescription.getClassName()
-                .indexOf(mTestIterationSeparator);
-        if (iterationSeparatorIndex != -1) {
-            className = testDescription.getClassName().substring(0, iterationSeparatorIndex);
+        String testName = testDescription.getTestName();
+
+        // Check if the class name has an iteration separator.
+        if(className.contains(mTestIterationSeparator)) {
+            className = className.substring(0, className.indexOf(mTestIterationSeparator));
+        }
+        // Also check if the test(method) name has an iteration separator. See - http://b/342206870
+        if(testName.contains(mTestIterationSeparator)) {
+            testName = testName.substring(0, testName.indexOf(mTestIterationSeparator));
         }
-        String newTestId = CLASS_METHOD_JOINER.join(className, testDescription.getTestName());
+        String newTestId = CLASS_METHOD_JOINER.join(className, testName);
 
         if (!mStoredTestMetrics.containsKey(newTestId)) {
             mStoredTestMetrics.put(newTestId, ArrayListMultimap.create());
@@ -99,14 +104,11 @@ public class TestMetricsUtil {
 
         // Store only raw metrics
         HashMap<String, Metric> rawMetrics = getRawMetricsOnly(testMetrics);
-
         for (Map.Entry<String, Metric> entry : rawMetrics.entrySet()) {
             String key = entry.getKey();
-            // In case of Multi User test, the metric conatins className with iteration separator
-            if (key.indexOf(mTestIterationSeparator) != -1 &&
-                        key.contains(testDescription.getClassName())) {
-                key = key.substring(0, key.indexOf(mTestIterationSeparator));
-                key = CLASS_METHOD_JOINER.join(key, testDescription.getTestName());
+            // In case of Multi User tests, explicitly filter out the method name(that also includes the iteration separator)
+            if (key.contains("#")) {
+                key = key.substring(0, key.indexOf("#"));
             }
             storedMetricsForThisTest.put(key, entry.getValue());
         }
@@ -127,7 +129,7 @@ public class TestMetricsUtil {
                 List<Metric> metrics = currentTest.get(metricKey);
                 List<Measurements> measures = metrics.stream().map(Metric::getMeasurements)
                         .collect(Collectors.toList());
-                // Parse metrics into a list of SingleString values, concating lists in the process
+                // Parse metrics into a list of SingleString values, concatenating lists in the process
                 List<String> rawValues = measures.stream()
                         .map(Measurements::getSingleString)
                         .map(
@@ -136,7 +138,7 @@ public class TestMetricsUtil {
                                     // in a certain run
                                     List<String> splitVals = Arrays.asList(m.split(",", 0));
                                     if (splitVals.size() == 1 && splitVals.get(0).isEmpty()) {
-                                        return Collections.<String> emptyList();
+                                        return Collections.<String>emptyList();
                                     }
                                     return splitVals;
                                 })
diff --git a/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml b/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml
index 2929ac9..b642c56 100644
--- a/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml
+++ b/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml
@@ -28,6 +28,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:iterations:=5" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:rename-iterations:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:iteration-separator:=$" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener" />
 
   <!-- Default metrics post processor -->
   <include name="catbox-performance-postprocessors" />
diff --git a/tools/catbox-common/res/config/catbox-performance-start-new-user-base.xml b/tools/catbox-common/res/config/catbox-performance-start-new-user-base.xml
new file mode 100644
index 0000000..95fbc6d
--- /dev/null
+++ b/tools/catbox-common/res/config/catbox-performance-start-new-user-base.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 Google Inc.
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
+
+<configuration description="CATBox Performance Test to measure latency to switch to a Existing User">
+  <include name="catbox-performance-multiuser-base" />
+  <!-- Test -->
+  <option name="compatibility:include-filter" value="AndroidAutomotiveMultiuserScenarioTests android.platform.scenario.multiuser.StartNewUserBenchmark" />
+
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:perfetto_config_file:=trace_config.textproto" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+
+
+  <!-- Test Metrics Report -->
+  <option name="report-log-name" value="CatboxPerformanceTests" />
+  <option name="report-test-name-mapping" key="android.platform.scenario.multiuser.StartNewUserBenchmark#testStartNewUser" value="start_new_user" />
+  <option name="report-all-metrics" value="false" />
+  <option name="report-metric-key-mapping" key="duration_ms_android.platform.scenario.multiuser.StartNewUserBenchmark-median" value="duration_ms" />
+</configuration>
diff --git a/tools/catbox-common/res/config/catbox-preparer.xml b/tools/catbox-common/res/config/catbox-preparer.xml
index 53ca96e..cede900 100644
--- a/tools/catbox-common/res/config/catbox-preparer.xml
+++ b/tools/catbox-common/res/config/catbox-preparer.xml
@@ -25,6 +25,11 @@
     <option name="disable" value="true" />
   </target_preparer>
 
+  <!-- Target Preparers - Start user on secondary display -->
+  <target_preparer class="com.android.tradefed.targetprep.VisibleBackgroundUserPreparer">
+    <option name="disable" value="true" />
+  </target_preparer>
+
   <!-- Target Preparers - Setup the Device -->
   <target_preparer class="com.android.tradefed.targetprep.DeviceSetup">
     <option name="disable" value="true" />
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-bluetooth-setting.xml b/tools/catbox-tradefed/res/config/catbox-functional-bluetooth-setting.xml
new file mode 100644
index 0000000..46e90a7
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-functional-bluetooth-setting.xml
@@ -0,0 +1,33 @@
+<!--
+ Copyright (C) 2021 Google Inc.
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
+<configuration description="Complete Automotive Tests - Bluetooth Setting Functional Tests.">
+  <!-- Common Base -->
+  <include name="catbox-common"/>
+
+  <!-- Device Preparers -->
+  <include name="catbox-preparer"/>
+
+  <!-- Plan -->
+  <option name="plan" value="catbox-functional-bluetooth-setting"/>
+
+  <!-- Test Args -->
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:runner:androidx.test.runner.AndroidJUnitRunner" />
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.tests" />
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:no-rerun:true" />
+
+  <!-- Tests -->
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.BluetoothSettingTest" />
+</configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-sound-palette.xml b/tools/catbox-tradefed/res/config/catbox-functional-sound-palette.xml
new file mode 100644
index 0000000..4be4b0d
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-functional-sound-palette.xml
@@ -0,0 +1,31 @@
+<!--
+ Copyright (C) 2024 Google Inc.
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+          http://www.apache.org/licenses/LICENSE-2.0
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration
+    description="Complete Automotive Tests - Status Bar Functional Tests.">
+  <!-- Common Base -->
+  <include name="catbox-common" />
+  <!-- Device Preparers -->
+  <include name="catbox-preparer" />
+  <!-- Plan -->
+  <option name="plan" value="catbox-functional-sound-palette" />
+  <!-- Test Args -->
+  <option name="compatibility:test-arg"
+      value="com.android.tradefed.testtype.AndroidJUnitTest:runner:androidx.test.runner.AndroidJUnitRunner" />
+  <option name="compatibility:test-arg"
+      value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.tests" />
+  <option name="compatibility:test-arg"
+      value="com.android.tradefed.testtype.AndroidJUnitTest:no-rerun:true" />
+  <!-- Tests -->
+  <option name="compatibility:include-filter"
+      value="AndroidAutomotiveStatusBarTests android.platform.tests.SoundPaletteTest" />
+</configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-system-setting-ui-elements.xml b/tools/catbox-tradefed/res/config/catbox-functional-system-setting-ui-elements.xml
new file mode 100644
index 0000000..2aa1510
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-functional-system-setting-ui-elements.xml
@@ -0,0 +1,33 @@
+<!--
+ Copyright (C) 2024 Google Inc.
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
+<configuration description="Complete Automotive Tests - System Setting Functional Tests.">
+  <!-- Common Base -->
+  <include name="catbox-common"/>
+
+  <!-- Device Preparers -->
+  <include name="catbox-preparer"/>
+
+  <!-- Plan -->
+  <option name="plan" value="catbox-functional-system-setting-ui-elements"/>
+
+  <!-- Test Args -->
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:runner:androidx.test.runner.AndroidJUnitRunner" />
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.tests" />
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:no-rerun:true" />
+
+  <!-- Tests -->
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.SystemSettingVerifyUIElementsTest" />
+</configuration>
\ No newline at end of file
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml
index 7cbb12a..887cb8f 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml
@@ -26,8 +26,16 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=4.0" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
+  <!-- Total PSS Options -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:totalpss-collector:process-names:=com.android.car.dialer" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:totalpss-collector:log:=false "/>
+
+  <!-- Show Map Listener Options -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:showmapsnapshot-collector:metric-name-index:=rss:1,pss:2,shareddirty:4,privatedirty:6:7" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:showmapsnapshot-collector:process-names:=com.android.car.dialer" />
+
   <!-- App Start Up Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener,android.device.collectors.TotalPssMetricListener,android.device.collectors.ShowmapSnapshotListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:rename-iterations:=true" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml
index 4a75c5c..4531c9d 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml
@@ -26,8 +26,16 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=4.0" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
+  <!-- Total PSS Options -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:totalpss-collector:process-names:=com.android.car.media"/>
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:totalpss-collector:log:=false"/>
+
+  <!-- Show Map Listener Options -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:showmapsnapshot-collector:metric-name-index:=rss:1,pss:2,shareddirty:4,privatedirty:6:7"/>
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:showmapsnapshot-collector:process-names:=com.android.car.media"/>
+
   <!-- App Start Up Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener,android.device.collectors.TotalPssMetricListener,android.device.collectors.ShowmapSnapshotListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:rename-iterations:=true" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml
index 94649b6..013442b 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml
@@ -26,8 +26,16 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=4.0" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
+  <!-- Total PSS Options -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:totalpss-collector:process-names:=com.android.car.settings" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:totalpss-collector:log:=false" />
+
+  <!-- Show Map Listener Options -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:showmapsnapshot-collector:metric-name-index:=rss:1,pss:2,shareddirty:4,privatedirty:6:7" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:showmapsnapshot-collector:process-names:=com.android.car.settings" />
+
   <!-- App Start Up Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener,android.device.collectors.TotalPssMetricListener,android.device.collectors.ShowmapSnapshotListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:rename-iterations:=true" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-create-and-switch-to-new-guest.xml b/tools/catbox-tradefed/res/config/catbox-performance-create-and-switch-to-new-guest.xml
index e4deff5..f479477 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-create-and-switch-to-new-guest.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-create-and-switch-to-new-guest.xml
@@ -31,7 +31,7 @@
   <option name="report-log-name" value="CatboxPerformanceTests" />
   <option name="report-test-name-mapping" key="android.platform.scenario.multiuser.SwitchToNewGuestBenchmark#testSwitch" value="switch_to_new_guest" />
   <option name="report-all-metrics" value="false" />
-  <option name="report-metric-key-mapping" key="duration_ms_android.platform.scenario.multiuser.SwitchToNewGuestBenchmark#testSwitch-median" value="duration_ms" />
+  <option name="report-metric-key-mapping" key="duration_ms_android.platform.scenario.multiuser.SwitchToNewGuestBenchmark-median" value="duration_ms" />
 
   <option name="plan" value="catbox-performance-create-and-switch-to-new-guest" />
 </configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-create-and-switch-to-new-user.xml b/tools/catbox-tradefed/res/config/catbox-performance-create-and-switch-to-new-user.xml
index c066a6c..2bc730c 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-create-and-switch-to-new-user.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-create-and-switch-to-new-user.xml
@@ -31,7 +31,7 @@
   <option name="report-log-name" value="CatboxPerformanceTests" />
   <option name="report-test-name-mapping" key="android.platform.scenario.multiuser.SwitchToNewSecondaryUserBenchmark#testSwitch" value="switch_to_new_user" />
   <option name="report-all-metrics" value="false" />
-  <option name="report-metric-key-mapping" key="duration_ms_android.platform.scenario.multiuser.SwitchToNewSecondaryUserBenchmark#testSwitch-median" value="duration_ms" />
+  <option name="report-metric-key-mapping" key="duration_ms_android.platform.scenario.multiuser.SwitchToNewSecondaryUserBenchmark-median" value="duration_ms" />
 
   <option name="plan" value="catbox-performance-create-and-switch-to-new-user" />
 </configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml
index 688efa0..7174e4e 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml
@@ -44,7 +44,7 @@
 
   <!-- Test Metrics Report Options -->
   <option name="report-log-name" value="CatboxPerformanceTests" />
-  <option name="report-test-name-mapping" key="android.platform.test.scenario.settings.ScrollInAppMicrobenchmark#testScrollDownAndUp" value="settings_scroll_jank" />
+  <option name="report-test-name-mapping" key="android.platform.test.scenario.settings.ScrollInAppMicrobenchmark#testScrollForwardAndBackward" value="settings_scroll_jank" />
   <option name="report-all-metrics" value="false" />
   <option name="report-metric-key-mapping" key="gfxinfo_com.android.car.settings_janky_frames_percent-mean" value="jank_frames_percent" />
-</configuration>
+</configuration>
\ No newline at end of file
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-start-new-guest-on-second-display.xml b/tools/catbox-tradefed/res/config/catbox-performance-start-new-guest-on-second-display.xml
new file mode 100644
index 0000000..f1f6012
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-performance-start-new-guest-on-second-display.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 Google Inc.
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
+
+<configuration description="CATBox Performance Test to measure latency to start a new user on second display">
+  <include name="catbox-performance-start-new-user-base" />
+
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:start-users-on-additional-displays:=0" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:display-under-test:=1" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:target-user-guest:=true" />
+</configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-start-new-guest-on-third-display.xml b/tools/catbox-tradefed/res/config/catbox-performance-start-new-guest-on-third-display.xml
new file mode 100644
index 0000000..17fc888
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-performance-start-new-guest-on-third-display.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 Google Inc.
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
+
+<configuration description="CATBox Performance Test to measure latency to start a new user on second display">
+  <include name="catbox-performance-start-new-user-base" />
+
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:start-users-on-additional-displays:=1" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:display-under-test:=2" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:target-user-guest:=true" />
+</configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-start-new-user-on-second-display.xml b/tools/catbox-tradefed/res/config/catbox-performance-start-new-user-on-second-display.xml
new file mode 100644
index 0000000..af8b7ef
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-performance-start-new-user-on-second-display.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 Google Inc.
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
+
+<configuration description="CATBox Performance Test to measure latency to start a new user on second display">
+  <include name="catbox-performance-start-new-user-base" />
+
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:start-users-on-additional-displays:=0" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:display-under-test:=1" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:target-user-guest:=false" />
+</configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-start-new-user-on-third-display.xml b/tools/catbox-tradefed/res/config/catbox-performance-start-new-user-on-third-display.xml
new file mode 100644
index 0000000..b7df760
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-performance-start-new-user-on-third-display.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 Google Inc.
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
+
+<configuration description="CATBox Performance Test to measure latency to start a new user on second display">
+  <include name="catbox-performance-start-new-user-base" />
+
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:start-users-on-additional-displays:=1" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:display-under-test:=2" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:target-user-guest:=false" />
+</configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-switch-to-existing-user.xml b/tools/catbox-tradefed/res/config/catbox-performance-switch-to-existing-user.xml
index 514cf42..994fab6 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-switch-to-existing-user.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-switch-to-existing-user.xml
@@ -23,7 +23,7 @@
   <option name="report-log-name" value="CatboxPerformanceTests" />
   <option name="report-test-name-mapping" key="android.platform.scenario.multiuser.SwitchToExistingSecondaryUserBenchmark#testSwitch" value="switch_to_existing_user" />
   <option name="report-all-metrics" value="false" />
-  <option name="report-metric-key-mapping" key="duration_ms_android.platform.scenario.multiuser.SwitchToExistingSecondaryUserBenchmark#testSwitch-median" value="duration_ms" />
+  <option name="report-metric-key-mapping" key="duration_ms_android.platform.scenario.multiuser.SwitchToExistingSecondaryUserBenchmark-median" value="duration_ms" />
 
   <option name="plan" value="catbox-performance-switch-to-existing-user" />
 </configuration>
\ No newline at end of file
```

