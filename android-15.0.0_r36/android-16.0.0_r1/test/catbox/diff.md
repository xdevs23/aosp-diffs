```diff
diff --git a/OWNERS b/OWNERS
index 5270c1a..ef9627a 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,5 +2,4 @@
 # OWNERS of CATBox Repo
 schinchalkar@google.com
 smara@google.com
-tongfei@google.com
-zhaomingyin@google.com
\ No newline at end of file
+zhaomingyin@google.com
diff --git a/tools/catbox-common/res/config/catbox-performance-app-start-up-base.xml b/tools/catbox-common/res/config/catbox-performance-app-start-up-base.xml
index 890e591..26fa857 100644
--- a/tools/catbox-common/res/config/catbox-performance-app-start-up-base.xml
+++ b/tools/catbox-common/res/config/catbox-performance-app-start-up-base.xml
@@ -24,4 +24,9 @@
 
   <!-- Post Processors -->
   <include name ="catbox-performance-postprocessors"/>
+
+  <!-- Perfetto -->
+  <!-- TODO(b/383865164): replace with trace_config.textproto once it's available -->
+  <option name="push-file:push-file" key="long_trace_config.textproto" value="/data/misc/perfetto-traces/trace_config.textproto" />
+  <option name="perfetto-generic-processor:perfetto-include-all-metrics" value="true" />
 </configuration>
diff --git a/tools/catbox-common/res/config/catbox-performance-base.xml b/tools/catbox-common/res/config/catbox-performance-base.xml
index fd51a31..ee5fc88 100644
--- a/tools/catbox-common/res/config/catbox-performance-base.xml
+++ b/tools/catbox-common/res/config/catbox-performance-base.xml
@@ -52,18 +52,6 @@
     <metrics_collector class="com.android.tradefed.device.metric.PerfettoPullerMetricCollector">
         <option name="collect-on-run-ended-only" value="false" />
         <option name="pull-pattern-keys" value="perfetto_file_path" />
-        <option name="trace-processor-run-metrics" value="android_mem" />
-        <option name="trace-processor-run-metrics" value="android_auto_multiuser" />
-        <option name="trace-processor-run-metrics" value="android_monitor_contention" />
-        <option name="trace-processor-run-metrics" value="android_monitor_contention_agg" />
-        <option name="trace-processor-run-metrics" value="android_binder" />
-        <option name="trace-processor-run-metrics" value="android_boot" />
-        <option name="trace-processor-run-metrics" value="android_startup" />
-        <option name="trace-processor-run-metrics" value="android_jank_cuj" />
-        <option name="trace-processor-run-metrics" value="android_frame_timeline_metric" />
-        <option name="trace-processor-run-metrics" value="android_app_process_starts" />
-        <option name="trace-processor-run-metrics" value="android_boot_unagg" />
-        <option name="trace-processor-run-metrics" value="android_garbage_collection_unagg" />
-        <option name="trace-processor-run-metrics" value="android_io" />
+        <option name="trace-processor-run-metrics" value="android_mem,android_auto_multiuser,android_monitor_contention,android_monitor_contention_agg,android_binder,android_boot,android_startup,android_jank_cuj,android_frame_timeline_metric,android_app_process_starts,android_boot_unagg,android_garbage_collection_unagg,android_io" />
     </metrics_collector>
 </configuration>
diff --git a/tools/catbox-common/res/config/catbox-performance-jank-base.xml b/tools/catbox-common/res/config/catbox-performance-jank-base.xml
index 231f2db..456972e 100644
--- a/tools/catbox-common/res/config/catbox-performance-jank-base.xml
+++ b/tools/catbox-common/res/config/catbox-performance-jank-base.xml
@@ -24,4 +24,9 @@
 
   <!-- Post Processors -->
   <include name ="catbox-performance-postprocessors"/>
+
+  <!-- Perfetto -->
+  <!-- TODO(b/383865164): replace with trace_config.textproto once it's available -->
+  <option name="push-file:push-file" key="long_trace_config.textproto" value="/data/misc/perfetto-traces/trace_config.textproto" />
+  <option name="perfetto-generic-processor:perfetto-include-all-metrics" value="true" />
 </configuration>
diff --git a/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml b/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml
index aca9a34..d4edcb3 100644
--- a/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml
+++ b/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml
@@ -34,6 +34,20 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:iteration-separator:=$" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener" />
 
+  <!-- Perfetto -->
+  <option name="push-file:push-file" key="trace_config_light.textproto" value="/data/misc/perfetto-traces/trace_config.textproto" />
+  <option name="perfetto-metric-collector:trace-processor-run-metrics" value="android_auto_multiuser" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:perfetto_config_file:=trace_config.textproto" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMultiuserScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Default metrics post processor -->
   <include name="catbox-performance-postprocessors" />
+  <option name="perfetto-generic-processor:perfetto-prefix-key-field" value="perfetto.protos.AndroidAutoMultiuserMetric.EventData.end_event" />
+  <option name="perfetto-generic-processor:perfetto-prefix-key-field" value="perfetto.protos.AndroidAutoMultiuserMetric.EventData.UserData.user_id" />
+  <option name="perfetto-generic-processor:perfetto-metric-filter-regex" value="android_auto_multiuser-user_switch-end_event.*duration_ms" />
+  <!-- use lookahead to filter out strings with duplicated end_event and start_event -->
+  <option name="perfetto-generic-processor:perfetto-metric-filter-regex" value="android_auto_multiuser(?=.*-end_event-)(?!.*-end_event-.*-end_event-)(?!.*-start_event-).*previous_user_info-user_id-10-total_cpu_time_ms" />
+  <option name="perfetto-generic-processor:perfetto-metric-filter-regex" value="android_auto_multiuser(?=.*-end_event-)(?!.*-end_event-.*-end_event-)(?!.*-start_event-).*previous_user_info-user_id-10-total_memory_usage_kb" />
 </configuration>
diff --git a/tools/catbox-common/res/config/catbox-performance-postprocessors.xml b/tools/catbox-common/res/config/catbox-performance-postprocessors.xml
index 5d1aa34..7e23789 100644
--- a/tools/catbox-common/res/config/catbox-performance-postprocessors.xml
+++ b/tools/catbox-common/res/config/catbox-performance-postprocessors.xml
@@ -23,7 +23,5 @@
   <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoGenericPostProcessor">
     <option name="perfetto-include-all-metrics" value="false" />
     <option name="perfetto-proto-file-prefix" value="metric_perfetto" />
-    <option name="perfetto-prefix-key-field" value="perfetto.protos.AndroidAutoMultiuserMetric.EventData.end_event" />
-    <option name="perfetto-metric-filter-regex" value="android_auto_multiuser-user_switch-end_event.*duration_ms" />
   </metric_post_processor>
 </configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-certification-tests.xml b/tools/catbox-tradefed/res/config/catbox-certification-tests.xml
new file mode 100644
index 0000000..3930a5e
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-certification-tests.xml
@@ -0,0 +1,52 @@
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
+<configuration description="Bluetooth Tests Using Mobly">
+  <!-- Plan -->
+  <!-- TODO(@vitalidim) rename test plan since it's not for bt discovery only -->
+  <option name="plan" value="catbox-certification-tests"/>
+
+  <include name="everything" />
+
+  <!-- Template for Result Reporters -->
+  <template-include name="reporters" default="empty" />
+
+  <!-- Test Tag -->
+  <option name="test-tag" value="catbox" />
+
+  <!-- Basic Reporters -->
+  <include name="basic-reporters" />
+
+  <!-- Template for Metadata Reporters -->
+  <template-include name="metadata-reporters" default="empty" />
+
+  <!-- Default ABI -->
+  <option name="compatibility:primary-abi-only" value="true" />
+
+  <!--
+      CATBox Runs all modules if it is not specified.
+      So, we need to skip these modules in case of Mobly tests
+      which can be done by adding following option.
+   -->
+  <option name="compatibility:reverse-exclude-filters" value="true" />
+
+  <test class="com.android.tradefed.testtype.mobly.MoblyBinaryHostTest">
+    <!-- The mobly-par-file-name should match the module name , it is passed on runtime-->
+    <!-- Timeout limit in milliseconds for all test cases of the python binary -->
+    <option name="mobly-test-timeout" value="300000" />
+    <!-- Testbed config file -->
+    <option name="mobly-config-file-name" value="device.yaml" />
+  </test>
+</configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-mediacenter.xml b/tools/catbox-tradefed/res/config/catbox-functional-mediacenter.xml
index 8401762..7eb60bb 100644
--- a/tools/catbox-tradefed/res/config/catbox-functional-mediacenter.xml
+++ b/tools/catbox-tradefed/res/config/catbox-functional-mediacenter.xml
@@ -32,8 +32,8 @@
 
   <!-- Tests -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveMediaCenterTests android.platform.tests.OpenAppFromMediaCenterTest" />
-  <!--
   <option name="compatibility:include-filter" value="AndroidAutomotiveMediaCenterTests android.platform.tests.MediaTestAppTest" />
+  <!--
   <option name="compatibility:include-filter" value="AndroidAutomotiveMediaCenterTests android.platform.tests.NoUserLoggedInTest" />
   -->
 
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-multiuser.xml b/tools/catbox-tradefed/res/config/catbox-functional-multiuser.xml
index a3d0d0e..862af6a 100644
--- a/tools/catbox-tradefed/res/config/catbox-functional-multiuser.xml
+++ b/tools/catbox-tradefed/res/config/catbox-functional-multiuser.xml
@@ -41,4 +41,5 @@
   <option name="compatibility:include-filter" value="AndroidAutomotiveMultiuserTests android.platform.tests.DeleteNonAdminUser" />
   <option name="compatibility:include-filter" value="AndroidAutomotiveMultiuserTests android.platform.tests.SwitchUserQuickSettings" />
   <option name="compatibility:include-filter" value="AndroidAutomotiveMultiuserTests android.platform.tests.DeleteGuestSelfNotAllowed" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveMultiuserTests android.platform.tests.EditAdminName" />
 </configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-settings-location.xml b/tools/catbox-tradefed/res/config/catbox-functional-settings-location.xml
index 8b5ab15..486a514 100644
--- a/tools/catbox-tradefed/res/config/catbox-functional-settings-location.xml
+++ b/tools/catbox-tradefed/res/config/catbox-functional-settings-location.xml
@@ -30,4 +30,5 @@
 
   <!-- Tests -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsLocationTests android.platform.tests.SettingsLocationTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsLocationTests android.platform.tests.LocationAccessTest" />
 </configuration>
\ No newline at end of file
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml
index 887cb8f..4e1162d 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml
@@ -35,7 +35,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:showmapsnapshot-collector:process-names:=com.android.car.dialer" />
 
   <!-- App Start Up Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener,android.device.collectors.TotalPssMetricListener,android.device.collectors.ShowmapSnapshotListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener,android.device.collectors.TotalPssMetricListener,android.device.collectors.ShowmapSnapshotListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -46,6 +46,11 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:kill-app:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:drop-cache:=true" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.dial" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml
index 4531c9d..83e7341 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml
@@ -35,7 +35,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:showmapsnapshot-collector:process-names:=com.android.car.media"/>
 
   <!-- App Start Up Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener,android.device.collectors.TotalPssMetricListener,android.device.collectors.ShowmapSnapshotListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener,android.device.collectors.TotalPssMetricListener,android.device.collectors.ShowmapSnapshotListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -49,6 +49,11 @@
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.mediacenter" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveMediaCenterScenarioTests android.platform.test.scenario.mediacenter.OpenAppMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml
index 013442b..bf323bb 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml
@@ -35,7 +35,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:showmapsnapshot-collector:process-names:=com.android.car.settings" />
 
   <!-- App Start Up Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener,android.device.collectors.TotalPssMetricListener,android.device.collectors.ShowmapSnapshotListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener,android.device.collectors.TotalPssMetricListener,android.device.collectors.ShowmapSnapshotListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -49,6 +49,11 @@
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.settings" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsScenarioTests android.platform.test.scenario.settings.OpenAppMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-dialer.xml b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-dialer.xml
index a182b80..647f03c 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-dialer.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-dialer.xml
@@ -27,7 +27,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
   <!-- App Start Up Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -41,6 +41,11 @@
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.dial" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveDialScenarioTests android.platform.test.scenario.dial.OpenAppMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-mediacenter.xml b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-mediacenter.xml
index b2aa489..145beee 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-mediacenter.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-mediacenter.xml
@@ -27,7 +27,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
   <!-- App Start Up Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -41,6 +41,11 @@
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.mediacenter" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveMediaCenterScenarioTests android.platform.test.scenario.mediacenter.OpenAppMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-settings.xml b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-settings.xml
index 45b190b..9006def 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-settings.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-settings.xml
@@ -27,7 +27,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
   <!-- App Start Up Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -41,6 +41,11 @@
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.settings" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsScenarioTests android.platform.test.scenario.settings.OpenAppMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-appgrid.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-appgrid.xml
index acf5e76..f263ff2 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-appgrid.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-appgrid.xml
@@ -27,7 +27,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
   <!-- Jank Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -36,6 +36,11 @@
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.appgrid" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveAppGridScenarioTests android.platform.test.scenario.appgrid.ScrollMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-contact-list.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-contact-list.xml
index defd204..ee6b6ab 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-contact-list.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-contact-list.xml
@@ -27,7 +27,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
   <!-- Jank Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -36,6 +36,11 @@
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.dial" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveDialScenarioTests android.platform.test.scenario.dial.ScrollContactListMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-media-switch-playback.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-media-switch-playback.xml
index 9f5af76..aa6c36c 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-media-switch-playback.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-media-switch-playback.xml
@@ -28,7 +28,7 @@
     <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
     <!-- Jank Options -->
-    <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
+    <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
     <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:iterations:=20" />
     <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
     <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -37,6 +37,11 @@
     <!-- Test Package -->
     <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.mediacenter" />
 
+    <!-- Perfetto -->
+    <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+    <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+    <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
     <!-- Test -->
     <option name="compatibility:include-filter" value="AndroidAutomotiveMediaCenterScenarioTests android.platform.test.scenario.mediacenter.SwitchPlaybackMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-media.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-media.xml
index 7a0dd7d..825e0de 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-media.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-media.xml
@@ -27,7 +27,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
   <!-- Jank Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -36,6 +36,11 @@
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.mediacenter" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveMediaCenterScenarioTests android.platform.test.scenario.mediacenter.ScrollMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-notifications.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-notifications.xml
index 42266cc..598f79c 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-notifications.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-notifications.xml
@@ -27,7 +27,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
   <!-- Jank Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -36,6 +36,11 @@
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.notification" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveNotificationScenarioTests android.platform.test.scenario.notification.ScrollMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml
index 7174e4e..23719b1 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml
@@ -27,7 +27,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
 
   <!-- Jank Options -->
-  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:listener:=android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:iterations:=20" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:favor-shell-commands:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:rename-iterations:=true" />
@@ -36,6 +36,11 @@
   <!-- Test Package -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.test.scenario.settings" />
 
+  <!-- Perfetto -->
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:perfetto_config_text_proto:=true" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:test_output_root:=/data/misc/perfetto-traces" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:perfetto_should_use_content_provider:=false" />
+
   <!-- Test -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsScenarioTests android.platform.test.scenario.settings.ScrollInAppMicrobenchmark" />
 
diff --git a/tools/catbox-tradefed/res/config/device-config/three-devices.xml b/tools/catbox-tradefed/res/config/device-config/three-devices.xml
index ebf0151..ed0d964 100644
--- a/tools/catbox-tradefed/res/config/device-config/three-devices.xml
+++ b/tools/catbox-tradefed/res/config/device-config/three-devices.xml
@@ -17,6 +17,11 @@
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" >
       <option name="test-file-name" value="AutomotiveSnippet.apk" />
     </target_preparer>
+    <!--To exit the SUW and gTos screens -->
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+      <option name="run-command" value="am start -n com.google.android.car.setupwizard/.ExitActivity" />
+      <option name="run-command" value="am start -n com.google.android.car.setupwizard/.ExitActivity" />
+    </target_preparer>
   </device>
 
   <device name="phone">
diff --git a/tools/catbox-tradefed/res/config/device-config/two-devices.xml b/tools/catbox-tradefed/res/config/device-config/two-devices.xml
index 9c2ab57..91c3755 100644
--- a/tools/catbox-tradefed/res/config/device-config/two-devices.xml
+++ b/tools/catbox-tradefed/res/config/device-config/two-devices.xml
@@ -17,6 +17,11 @@
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" >
       <option name="test-file-name" value="AutomotiveSnippet.apk" />
     </target_preparer>
+    <!--To exit the SUW and gTos screens -->
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+      <option name="run-command" value="am start -n com.google.android.car.setupwizard/.ExitActivity" />
+      <option name="run-command" value="am start -n com.google.android.car.setupwizard/.ExitActivity" />
+    </target_preparer>
   </device>
 
   <device name="phone">
```

