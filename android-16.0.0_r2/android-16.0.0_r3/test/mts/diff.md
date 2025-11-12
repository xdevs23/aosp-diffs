```diff
diff --git a/tools/build/config.mk b/tools/build/config.mk
index 06067d9..29cfb05 100644
--- a/tools/build/config.mk
+++ b/tools/build/config.mk
@@ -55,6 +55,7 @@ mts_modules += \
                scheduling \
                sdkextensions \
                statsd \
+               telephony2 \
                tethering \
                tzdata \
                uprobestats \
diff --git a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml
index ef3261c..efca4b6 100644
--- a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml
+++ b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml
@@ -36,6 +36,7 @@
     <option name="compatibility:include-filter" value="art_standalone_runtime_tests"/>
     <option name="compatibility:include-filter" value="art_standalone_sigchain_tests"/>
     <option name="compatibility:include-filter" value="libnativebridge-lazy-tests"/>
+    <option name="compatibility:include-filter" value="libnativebridge-tests"/>
     <option name="compatibility:include-filter" value="libnativeloader_test"/>
     <!-- Enable MainlineTestModuleController for ART gtests. -->
     <option name="compatibility:module-arg" value="art_libnativebridge_cts_tests:enable:true"/>
@@ -58,5 +59,6 @@
     <option name="compatibility:module-arg" value="art_standalone_runtime_tests:enable:true"/>
     <option name="compatibility:module-arg" value="art_standalone_sigchain_tests:enable:true"/>
     <option name="compatibility:module-arg" value="libnativebridge-lazy-tests:enable:true"/>
+    <option name="compatibility:module-arg" value="libnativebridge-tests:enable:true"/>
     <option name="compatibility:module-arg" value="libnativeloader_test:enable:true"/>
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-art-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-art-tests-list-user.xml
index 8c2b25c..16fce14 100644
--- a/tools/mts-tradefed/res/config/mts-art-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-art-tests-list-user.xml
@@ -35,7 +35,4 @@
     <option name="compatibility:exclude-filter" value="CtsLibcoreTestCases com.android.org.conscrypt.javax.net.ssl.SSLSocketVersionCompatibilityTest#test_SSLSocket_setSoWriteTimeout[3: TLSv1.3 client, TLSv1.3 server]"/>
     <option name="compatibility:exclude-filter" value="CtsLibcoreTestCases libcore.dalvik.system.DelegateLastClassLoaderTest#testLookupOrderNodelegate_getResource"/>
     <option name="compatibility:exclude-filter" value="CtsLibcoreTestCases libcore.dalvik.system.DelegateLastClassLoaderTest#testLookupOrder_getResource"/>
-    <!-- Excluded failing tests (b/247108425). -->
-    <option name="compatibility:exclude-filter" value="art_standalone_compiler_tests JniCompilerTest*"/>
-    <option name="compatibility:exclude-filter" value="art_standalone_libartpalette_tests PaletteClientJniTest*"/>
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-bt-navi.xml b/tools/mts-tradefed/res/config/mts-bt-navi.xml
new file mode 100644
index 0000000..7059b6f
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-bt-navi.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright 2025 The Android Open Source Project
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
+<configuration description="Runs Navi Bluetooth MTS tests from a pre-existing MTS installation">
+
+    <include name="mts" />
+    <include name="mts-bt-tests-list-navi" />
+    <option name="plan" value="mts-bt-navi" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+        <option name="property-name" value="ro.build.type" />
+        <option name="expected-value" value="userdebug"/> <!-- Device should have userdebug/eng build -->
+        <option name="throw-error" value="false"/> <!-- Only print warning if not user build -->
+    </target_preparer>
+
+    <option name="compatibility:primary-abi-only" value="true" />
+</configuration>
+
diff --git a/tools/mts-tradefed/res/config/mts-bt-tests-list-native.xml b/tools/mts-tradefed/res/config/mts-bt-tests-list-native.xml
index eea4f94..815841f 100644
--- a/tools/mts-tradefed/res/config/mts-bt-tests-list-native.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-tests-list-native.xml
@@ -29,7 +29,6 @@
     <option name="compatibility:include-filter" value="bluetooth-test-audio-hal-aidl-leaudio-utils" />
     <option name="compatibility:include-filter" value="bluetooth-test-audio-hal-hfp-client-interface" />
     <option name="compatibility:include-filter" value="bluetooth-test-audio-hal-le-audio-software" />
-    <option name="compatibility:include-filter" value="bluetooth-test-audio-hal-interface" />
     <option name="compatibility:include-filter" value="bluetooth_test_broadcaster" />
     <option name="compatibility:include-filter" value="bluetooth_test_broadcaster_state_machine" />
     <option name="compatibility:include-filter" value="bluetooth_test_common" />
@@ -100,7 +99,6 @@
     <option name="compatibility:module-arg" value="bluetooth-test-audio-hal-aidl-leaudio-utils:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth-test-audio-hal-hfp-client-interface:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth-test-audio-hal-le-audio-software:enable:true" />
-    <option name="compatibility:module-arg" value="bluetooth-test-audio-hal-interface:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_test_broadcaster:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_test_broadcaster_state_machine:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_test_common:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-bt-tests-list-navi.xml b/tools/mts-tradefed/res/config/mts-bt-tests-list-navi.xml
new file mode 100644
index 0000000..1fc3c47
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-bt-tests-list-navi.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright 2025 The Android Open Source Project
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
+<configuration description="List of Navi Bluetooth MTS tests.">
+    <option name="compatibility:include-filter" value="navi-tf" />
+    <option name="compatibility:module-arg" value="navi-tf:enable:true" />
+</configuration>
+
diff --git a/tools/mts-tradefed/res/config/mts-bt-tests-list-pts-bot.xml b/tools/mts-tradefed/res/config/mts-bt-tests-list-pts-bot.xml
index 33d2c8f..80313f8 100644
--- a/tools/mts-tradefed/res/config/mts-bt-tests-list-pts-bot.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-tests-list-pts-bot.xml
@@ -14,6 +14,25 @@
      limitations under the License.
 -->
 <configuration description="List of PTS-bot Bluetooth MTS tests.">
-    <option name="compatibility:include-filter" value="pts-bot-mts" />
+    <option name="compatibility:include-filter" value="pts-bot-mts AVCTP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts AVDTP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts AVRCP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts BNEP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts GAP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts GATT" />
+    <option name="compatibility:include-filter" value="pts-bot-mts HAP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts HFP_HF" />
+    <option name="compatibility:include-filter" value="pts-bot-mts HFP_AG" />
+    <option name="compatibility:include-filter" value="pts-bot-mts HID" />
+    <option name="compatibility:include-filter" value="pts-bot-mts HOGP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts L2CAP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts MAP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts OPP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts PAN" />
+    <option name="compatibility:include-filter" value="pts-bot-mts PBAP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts RFCOMM" />
+    <option name="compatibility:include-filter" value="pts-bot-mts SDP" />
+    <option name="compatibility:include-filter" value="pts-bot-mts SM" />
+    <option name="compatibility:include-filter" value="pts-bot-mts VCP" />
     <option name="compatibility:module-arg" value="pts-bot-mts:enable:true" />
 </configuration>
\ No newline at end of file
diff --git a/tools/mts-tradefed/res/config/mts-bt.xml b/tools/mts-tradefed/res/config/mts-bt.xml
index e46a246..315fb21 100644
--- a/tools/mts-tradefed/res/config/mts-bt.xml
+++ b/tools/mts-tradefed/res/config/mts-bt.xml
@@ -21,6 +21,7 @@
     <include name="mts-bt-tests-list-pts-bot" />
     <include name="mts-bt-tests-list-avatar" />
     <include name="mts-bt-tests-list-bumble" />
+    <include name="mts-bt-tests-list-navi" />
     <option name="plan" value="mts-bt" />
 
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
diff --git a/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml b/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml
index e9774ed..72fa2ad 100644
--- a/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml
@@ -29,7 +29,6 @@
       <option name="compatibility:include-filter" value="CtsExerciseRouteTestCases" />
       <option name="compatibility:include-filter" value="CtsHealthFitnessPhrTestCases" />
       <option name="compatibility:include-filter" value="HealthConnectControllerDataScreensNewTests" />
-      <option name="compatibility:include-filter" value="HealthConnectControllerDataScreensOldTests" />
       <option name="compatibility:include-filter" value="HealthConnectControllerDeletionTests" />
       <option name="compatibility:include-filter" value="HealthConnectControllerExerciseRouteTests" />
       <option name="compatibility:include-filter" value="HealthConnectControllerExportTests" />
@@ -57,7 +56,6 @@
       <option name="compatibility:module-arg" value="CtsExerciseRouteTestCases:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthFitnessPhrTestCases:enable:true" />
       <option name="compatibility:module-arg" value="HealthConnectControllerDataScreensNewTests:enable:true" />
-      <option name="compatibility:module-arg" value="HealthConnectControllerDataScreensOldTests:enable:true" />
       <option name="compatibility:module-arg" value="HealthConnectControllerDeletionTests:enable:true" />
       <option name="compatibility:module-arg" value="HealthConnectControllerExerciseRouteTests:enable:true" />
       <option name="compatibility:module-arg" value="HealthConnectControllerExportTests:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-mediaprovider.xml b/tools/mts-tradefed/res/config/mts-mediaprovider.xml
index ecbcaa2..c4e9780 100644
--- a/tools/mts-tradefed/res/config/mts-mediaprovider.xml
+++ b/tools/mts-tradefed/res/config/mts-mediaprovider.xml
@@ -21,5 +21,6 @@
     <include name="mts-mediaprovider-tests-list-eng-only" />
 
     <option name="plan" value="mts-mediaprovider" />
+    <option name="compatibility:primary-abi-only" value="true" />
 
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-ondevicepersonalization-tests-list.xml b/tools/mts-tradefed/res/config/mts-ondevicepersonalization-tests-list.xml
index 274f710..b5c8ebb 100644
--- a/tools/mts-tradefed/res/config/mts-ondevicepersonalization-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-ondevicepersonalization-tests-list.xml
@@ -20,6 +20,8 @@
             value="FrameworkOnDevicePersonalizationTests" />
     <option name="compatibility:include-filter"
             value="OnDevicePersonalizationManagingServicesTests" />
+    <option name="compatibility:include-filter"
+            value="OnDevicePersonalizationEndToEndTests" />
     <option name="compatibility:include-filter"
             value="OnDevicePersonalizationPluginTests" />
     <option name="compatibility:include-filter"
@@ -33,6 +35,7 @@
     <option name="compatibility:module-arg" value="CtsOnDevicePersonalizationConfigTests:enable:true" />
     <option name="compatibility:module-arg" value="FrameworkOnDevicePersonalizationTests:enable:true" />
     <option name="compatibility:module-arg" value="OnDevicePersonalizationManagingServicesTests:enable:true" />
+    <option name="compatibility:module-arg" value="OnDevicePersonalizationEndToEndTests:enable:true" />
     <option name="compatibility:module-arg" value="OnDevicePersonalizationPluginTests:enable:true" />
     <option name="compatibility:module-arg" value="OnDevicePersonalizationSystemServiceImplTests:enable:true" />
     <option name="compatibility:module-arg" value="OdpChronicleTests:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-telephony.xml b/tools/mts-tradefed/res/config/mts-telephony.xml
deleted file mode 100644
index 8877345..0000000
--- a/tools/mts-tradefed/res/config/mts-telephony.xml
+++ /dev/null
@@ -1,38 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2019 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-
-<configuration description="Runs MTS-telephony from a pre-existing MTS installation">
-
-    <include name="mts" />
-    <include name="mts-exclude" />
-
-    <option name="plan" value="mts-telephony" />
-    <option name="compatibility:include-filter" value="FrameworksTelephonyTests" />
-    <option name="compatibility:include-filter" value="ImsCommonTests" />
-    <option name="compatibility:include-filter" value="CtsSimRestrictedApisTestCases" />
-    <option name="compatibility:include-filter" value="CtsTelephony3TestCases" />
-    <option name="compatibility:include-filter" value="CtsTelephony2TestCases" />
-    <option name="compatibility:include-filter" value="CtsTelephonyTestCases" />
-
-    <!-- TODO: Uncomment this after the instrumentation signature issue is resolved:
-     MTS runs on goog/dev-keys signed devices, but MTS is built with aosp/test-keys so
-     instrumentation doesn't work properly. Solution is pending, either a short term solution
-     based on adding a new MTS target in vendor/unbundled_google or something else the
-     release team cooks up.
-    <option name="compatibility:include-filter" value="TeleServiceTests" />
-    -->
-    <option name="compatibility:primary-abi-only" value="true" />
-</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-telephony2-tests-list.xml b/tools/mts-tradefed/res/config/mts-telephony2-tests-list.xml
new file mode 100644
index 0000000..05afe1e
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-telephony2-tests-list.xml
@@ -0,0 +1,23 @@
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
+<configuration description="List MTS telephony tests.">
+    <option name="compatibility:include-filter" value="TelephonyModuleTests" />
+    <option name="compatibility:include-filter" value="CtsTelephonyModuleTests" />
+
+    <!-- Enable MainlineTestModuleController. -->
+    <option name="compatibility:module-arg" value="TelephonyModuleTests:enable:true" />
+    <option name="compatibility:module-arg" value="CtsTelephonyModuleTests:enable:true" />
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-telephony2.xml b/tools/mts-tradefed/res/config/mts-telephony2.xml
new file mode 100644
index 0000000..5a346ed
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-telephony2.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2019 The Android Open Source Project
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
+<configuration description="Runs MTS-telephony from a pre-existing MTS installation">
+
+    <include name="mts" />
+
+    <include name="mts-telephony2-tests-list" />
+
+    <option name="plan" value="mts-telephony2" />
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-tests-list-user.xml
index 15a9092..59fec76 100644
--- a/tools/mts-tradefed/res/config/mts-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-tests-list-user.xml
@@ -42,6 +42,7 @@
     <include name="mts-scheduling-tests-list" />
     <include name="mts-sdkextensions-tests-list" />
     <include name="mts-statsd-tests-list-user" />
+    <!-- TODO: Enable when 25Q4 is next. include name="mts-telephony2-tests-list-user" / -->
     <include name="mts-tethering-tests-list-user" />
     <include name="mts-tzdata-tests-list" />
     <!-- TODO: Enable when 25Q2 is next. include name="mts-uprobestats-tests-list-user" / -->
diff --git a/tools/mts-tradefed/res/config/mts-tethering-tests-list-eng-only.xml b/tools/mts-tradefed/res/config/mts-tethering-tests-list-eng-only.xml
index aabf1ff..212e7e4 100644
--- a/tools/mts-tradefed/res/config/mts-tethering-tests-list-eng-only.xml
+++ b/tools/mts-tradefed/res/config/mts-tethering-tests-list-eng-only.xml
@@ -15,6 +15,7 @@
 -->
 <configuration description="List of tethering MTS tests that need root access or userdebug build.">
     <option name="compatibility:include-filter" value="bpf_existence_test" />
+    <option name="compatibility:include-filter" value="libnetworkstats_test" />
     <option name="compatibility:include-filter" value="connectivity_native_test" />
     <option name="compatibility:include-filter" value="ThreadNetworkIntegrationTests" />
 </configuration>
```

