```diff
diff --git a/OWNERS b/OWNERS
index 692055e..ef10640 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,6 +1,6 @@
 # Root Owners of the MTS repo for code reviews
-chenzhu@google.com
-kunniu@google.com
-yuwu@google.com
+lancefluger@google.com
 liutongbo@google.com
 wenshan@google.com
+angli@google.com
+ruaire@google.com
diff --git a/tools/build/config.mk b/tools/build/config.mk
index 5be510c..06067d9 100644
--- a/tools/build/config.mk
+++ b/tools/build/config.mk
@@ -31,6 +31,7 @@ mts_modules += \
                appsearch \
                art \
                bluetooth \
+               bt \
                cellbroadcast \
                configinfrastructure \
                conscrypt \
@@ -56,6 +57,7 @@ mts_modules += \
                statsd \
                tethering \
                tzdata \
+               uprobestats \
                uwb \
                webviewbootstrap \
                wifi
diff --git a/tools/mts-tradefed/res/config/OWNERS b/tools/mts-tradefed/res/config/OWNERS
index 10ecc5c..dbd3ba3 100644
--- a/tools/mts-tradefed/res/config/OWNERS
+++ b/tools/mts-tradefed/res/config/OWNERS
@@ -1,8 +1,11 @@
 per-file mts-art*.xml = rpl@google.com
 per-file mts-sdkextensions*.xml = file: platform/packages/modules/SdkExtensions:/OWNERS
-per-file mts-bluetooth*.xml = file: platform/packages/modules/Bluetooth/:/pandora/OWNERS
+per-file mts-bt*.xml = file: platform/packages/modules/Bluetooth/:/OWNERS
+per-file mts-bluetooth*.xml = file: platform/packages/modules/Bluetooth/:/OWNERS
 per-file mts-mediaprovider*.xml = file: platform/frameworks/base:/core/java/android/os/storage/OWNERS
 per-file mts-media.xml = file: platform/frameworks/av/:/media/janitors/reliability_mainline_OWNERS
 per-file mts-media-*.xml = file: platform/frameworks/av/:/media/janitors/reliability_mainline_OWNERS
 per-file mts-rkpd*.xml = file: platform/packages/modules/RemoteKeyProvisioning:/OWNERS
 per-file mts-ondevicepersonalization*.xml = file: platform/packages/modules/OnDevicePersonalization:/OWNERS
+per-file mts-profiling*.xml = file: platform/packages/modules/Profiling:/OWNERS
+per-file mts-uwb*.xml = file: platform/packages/modules/Uwb/:/OWNERS
diff --git a/tools/mts-tradefed/res/config/mts-adservices-tests-list.xml b/tools/mts-tradefed/res/config/mts-adservices-tests-list.xml
index dbe8816..8c03cce 100644
--- a/tools/mts-tradefed/res/config/mts-adservices-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-adservices-tests-list.xml
@@ -14,9 +14,11 @@
 <configuration description="List test modules of AdServices module. This is a placeholder xml instead of a runnable plan.">
     <option name="compatibility:include-filter" value="AdServicesApkUINotificationTests" />
     <option name="compatibility:include-filter" value="AdServicesApkUISettingsGaOtaTests" />
+    <option name="compatibility:include-filter" value="AdServicesApkUISettingsGaUXSelectorTests" />
     <option name="compatibility:include-filter" value="AdServicesApkUISettingsTests" />
     <option name="compatibility:include-filter" value="AdServicesApkUITestsAppConsent" />
     <option name="compatibility:include-filter" value="AdServicesApkUnitTests" />
+    <option name="compatibility:include-filter" value="AdServicesCobaltUnitTests" />
     <option name="compatibility:include-filter" value="AdServicesFrameworkUnitTests" />
     <option name="compatibility:include-filter" value="AdServicesJsEngineUnitTests" />
     <option name="compatibility:include-filter" value="AdServicesManagerServiceTests" />
@@ -30,6 +32,7 @@
     <option name="compatibility:include-filter" value="AdServicesServiceCoreProtectedAudienceUnitTests" />
     <option name="compatibility:include-filter" value="AdServicesServiceCoreTopicsUnitTests" />
     <option name="compatibility:include-filter" value="AdServicesSharedLibrariesUnitTests" />
+    <option name="compatibility:include-filter" value="AdServicesTestUtilityTests" />
     <option name="compatibility:include-filter" value="AdServicesUIUnitTests" />
     <option name="compatibility:include-filter" value="CtsAdIdEndToEndTest" />
     <option name="compatibility:include-filter" value="CtsAdServicesCobaltTest" />
@@ -54,19 +57,23 @@
     <option name="compatibility:include-filter" value="CtsSandboxedMeasurementManagerTests" />
     <option name="compatibility:include-filter" value="CtsSandboxedTopicsManagerTests" />
 
-    <option name="compatibility:include-filter" value="SdkSandboxManagerTests" />
     <option name="compatibility:include-filter" value="CtsSdkSandboxHostSideTests" />
     <option name="compatibility:include-filter" value="CtsSdkSandboxInprocessTests" />
+    <option name="compatibility:include-filter" value="SdkSandboxFrameworkUnitTests" />
+    <option name="compatibility:include-filter" value="SdkSandboxManagerDisabledTests" />
+    <option name="compatibility:include-filter" value="SdkSandboxManagerTests" />
     <option name="compatibility:include-filter" value="SdkSandboxManagerServiceUnitTests" />
+    <option name="compatibility:include-filter" value="SdkSandboxRestrictionsTests" />
     <option name="compatibility:include-filter" value="SdkSandboxUnitTests" />
-    <option name="compatibility:include-filter" value="SdkSandboxFrameworkUnitTests" />
 
 
     <option name="compatibility:module-arg" value="AdServicesApkUINotificationTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesApkUISettingsGaOtaTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdServicesApkUISettingsGaUXSelectorTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesApkUISettingsTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesApkUITestsAppConsent:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesApkUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdServicesCobaltUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesFrameworkUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesJsEngineUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesManagerServiceTests:enable:true" />
@@ -80,6 +87,7 @@
     <option name="compatibility:module-arg" value="AdServicesServiceCoreProtectedAudienceUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesServiceCoreTopicsUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesSharedLibrariesUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdServicesTestUtilityTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesUIUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdIdEndToEndTest:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdServicesCobaltTest:enable:true" />
@@ -104,11 +112,12 @@
     <option name="compatibility:module-arg" value="CtsSandboxedMeasurementManagerTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsSandboxedTopicsManagerTests:enable:true" />
 
-    <option name="compatibility:module-arg" value="SdkSandboxManagerTests:enable:true" />
-    <option name="compatibility:module-arg" value="SdkSandboxManagerDisabledTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsSdkSandboxHostSideTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsSdkSandboxInprocessTests:enable:true" />
-    <option name="compatibility:module-arg" value="SdkSandboxManagerServiceUnitTests:enable:true" />
-    <option name="compatibility:module-arg" value="SdkSandboxUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="SdkSandboxFrameworkUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="SdkSandboxManagerDisabledTests:enable:true" />
+    <option name="compatibility:module-arg" value="SdkSandboxManagerTests:enable:true" />
+    <option name="compatibility:module-arg" value="SdkSandboxManagerServiceUnitTest:enable:trues" />
+    <option name="compatibility:module-arg" value="SdkSandboxRestrictionsTests:enable:true" />
+    <option name="compatibility:module-arg" value="SdkSandboxUnitTests:enable:true" />
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-art-extra-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-art-extra-tests-list-user.xml
index 27706fb..b63e06b 100644
--- a/tools/mts-tradefed/res/config/mts-art-extra-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-art-extra-tests-list-user.xml
@@ -14,5 +14,5 @@
      limitations under the License.
 -->
 <configuration description="List of additional MTS tests relevant for the ART Module.">
-    <option name="compatibility:include-filter" value="CtsPerfettoTestCases HeapprofdJavaCtsTest*" />
+    <option name="compatibility:include-filter" value="CtsHeapprofdJavaCtsTest" />
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml
index 9fe75f6..caf678a 100644
--- a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml
+++ b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml
@@ -63,7 +63,6 @@
     <option name="compatibility:include-filter" value="art-run-test-050-sync-test"/>
     <option name="compatibility:include-filter" value="art-run-test-052-verifier-fun"/>
     <option name="compatibility:include-filter" value="art-run-test-053-wait-some"/>
-    <option name="compatibility:include-filter" value="art-run-test-055-enum-performance"/>
     <option name="compatibility:include-filter" value="art-run-test-057-math-intrinsics"/>
     <option name="compatibility:include-filter" value="art-run-test-058-enum-order"/>
     <option name="compatibility:include-filter" value="art-run-test-059-finalizer-throw"/>
@@ -532,7 +531,6 @@
     <option name="compatibility:module-arg" value="art-run-test-050-sync-test:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-052-verifier-fun:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-053-wait-some:enable:true"/>
-    <option name="compatibility:module-arg" value="art-run-test-055-enum-performance:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-057-math-intrinsics:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-058-enum-order:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-059-finalizer-throw:enable:true"/>
diff --git a/tools/mts-tradefed/res/config/mts-bluetooth-shard-00.xml b/tools/mts-tradefed/res/config/mts-bt-avatar.xml
similarity index 80%
rename from tools/mts-tradefed/res/config/mts-bluetooth-shard-00.xml
rename to tools/mts-tradefed/res/config/mts-bt-avatar.xml
index a80b99b..d82b504 100644
--- a/tools/mts-tradefed/res/config/mts-bluetooth-shard-00.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-avatar.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
+<!-- Copyright 2025 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,11 +13,11 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="Runs mts-bluetooth-shard-00 from a pre-existing MTS installation">
+<configuration description="Runs avatar Bluetooth MTS tests from a pre-existing MTS installation">
 
     <include name="mts" />
-    <include name="mts-bluetooth-tests-list-shard-00" />
-    <option name="plan" value="mts-bluetooth-shard-00" />
+    <include name="mts-bt-tests-list-avatar" />
+    <option name="plan" value="mts-bt-avatar" />
 
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
         <option name="property-name" value="ro.build.type" />
@@ -27,3 +27,4 @@
 
     <option name="compatibility:primary-abi-only" value="true" />
 </configuration>
+
diff --git a/tools/mts-tradefed/res/config/mts-bluetooth-shard-01.xml b/tools/mts-tradefed/res/config/mts-bt-bumble.xml
similarity index 80%
rename from tools/mts-tradefed/res/config/mts-bluetooth-shard-01.xml
rename to tools/mts-tradefed/res/config/mts-bt-bumble.xml
index 4949def..cbd7e66 100644
--- a/tools/mts-tradefed/res/config/mts-bluetooth-shard-01.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-bumble.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
+<!-- Copyright 2025 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,11 +13,11 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="Runs mts-bluetooth-shard-01 from a pre-existing MTS installation">
+<configuration description="Runs BumbleBluetoothTests Bluetooth MTS tests from a pre-existing MTS installation">
 
     <include name="mts" />
-    <include name="mts-bluetooth-tests-list-shard-01" />
-    <option name="plan" value="mts-bluetooth-shard-01" />
+    <include name="mts-bt-tests-list-bumble" />
+    <option name="plan" value="mts-bt-bumble" />
 
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
         <option name="property-name" value="ro.build.type" />
@@ -27,3 +27,4 @@
 
     <option name="compatibility:primary-abi-only" value="true" />
 </configuration>
+
diff --git a/tools/mts-tradefed/res/config/mts-bt-device.xml b/tools/mts-tradefed/res/config/mts-bt-device.xml
new file mode 100644
index 0000000..c82ca3f
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-bt-device.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
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
+<configuration description="Runs MTS Bluetooth device tests from a pre-existing MTS installation">
+
+    <include name="mts" />
+    <include name="mts-bt-tests-list-java" />
+    <include name="mts-bt-tests-list-native" />
+    <option name="plan" value="mts-bt-device" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+        <option name="property-name" value="ro.build.type" />
+        <option name="expected-value" value="userdebug"/> <!-- Device should have userdebug/eng build -->
+        <option name="throw-error" value="false"/> <!-- Only print warning if not user build -->
+    </target_preparer>
+
+    <option name="compatibility:primary-abi-only" value="true" />
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-bluetooth.xml b/tools/mts-tradefed/res/config/mts-bt-java.xml
similarity index 81%
rename from tools/mts-tradefed/res/config/mts-bluetooth.xml
rename to tools/mts-tradefed/res/config/mts-bt-java.xml
index 1a9168c..ab8563c 100644
--- a/tools/mts-tradefed/res/config/mts-bluetooth.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-java.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,11 +13,11 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="Runs mts-bluetooth from a pre-existing MTS installation">
+<configuration description="Runs Java Bluetooth MTS tests from a pre-existing MTS installation">
 
     <include name="mts" />
-    <include name="mts-bluetooth-tests-list" />
-    <option name="plan" value="mts-bluetooth" />
+    <include name="mts-bt-tests-list-java" />
+    <option name="plan" value="mts-bt-java" />
 
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
         <option name="property-name" value="ro.build.type" />
diff --git a/tools/mts-tradefed/res/config/mts-bluetooth-shard-02.xml b/tools/mts-tradefed/res/config/mts-bt-native.xml
similarity index 80%
rename from tools/mts-tradefed/res/config/mts-bluetooth-shard-02.xml
rename to tools/mts-tradefed/res/config/mts-bt-native.xml
index b595c20..769a865 100644
--- a/tools/mts-tradefed/res/config/mts-bluetooth-shard-02.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-native.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,11 +13,11 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="Runs mts-bluetooth-shard-02 from a pre-existing MTS installation">
+<configuration description="Runs native Bluetooth MTS tests from a pre-existing MTS installation">
 
     <include name="mts" />
-    <include name="mts-bluetooth-tests-list-shard-02" />
-    <option name="plan" value="mts-bluetooth-shard-02" />
+    <include name="mts-bt-tests-list-native" />
+    <option name="plan" value="mts-bt-native" />
 
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
         <option name="property-name" value="ro.build.type" />
diff --git a/tools/mts-tradefed/res/config/mts-bt-pts-bot.xml b/tools/mts-tradefed/res/config/mts-bt-pts-bot.xml
new file mode 100644
index 0000000..5f136b8
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-bt-pts-bot.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="utf-8"?>
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
+<configuration description="Runs PTS-bot Bluetooth MTS tests from a pre-existing MTS installation">
+
+    <include name="mts" />
+    <include name="mts-bt-tests-list-pts-bot" />
+    <option name="plan" value="mts-bt-pts-bot" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+        <option name="property-name" value="ro.build.type" />
+        <option name="expected-value" value="userdebug"/> <!-- Device should have userdebug/eng build -->
+        <option name="throw-error" value="false"/> <!-- Only print warning if not user build -->
+    </target_preparer>
+
+    <option name="compatibility:primary-abi-only" value="true" />
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-bluetooth-tests-list.xml b/tools/mts-tradefed/res/config/mts-bt-tests-list-avatar.xml
similarity index 66%
rename from tools/mts-tradefed/res/config/mts-bluetooth-tests-list.xml
rename to tools/mts-tradefed/res/config/mts-bt-tests-list-avatar.xml
index e0b7e80..b5f2c4f 100644
--- a/tools/mts-tradefed/res/config/mts-bluetooth-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-tests-list-avatar.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
+<!-- Copyright 2025 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,9 +13,8 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="List of Bluetooth MTS tests that do not need root access.">
-    <include name="mts-bluetooth-tests-list-shard-00"/>
-    <include name="mts-bluetooth-tests-list-shard-01"/>
-    <include name="mts-bluetooth-tests-list-shard-02"/>
-
+<configuration description="List of avatar Bluetooth MTS tests.">
+    <option name="compatibility:include-filter" value="avatar" />
+    <option name="compatibility:module-arg" value="avatar:enable:true" />
 </configuration>
+
diff --git a/tools/mts-tradefed/res/config/mts-bluetooth-tests-list-internal.xml b/tools/mts-tradefed/res/config/mts-bt-tests-list-bumble.xml
similarity index 65%
rename from tools/mts-tradefed/res/config/mts-bluetooth-tests-list-internal.xml
rename to tools/mts-tradefed/res/config/mts-bt-tests-list-bumble.xml
index 9922fc1..3e95af0 100644
--- a/tools/mts-tradefed/res/config/mts-bluetooth-tests-list-internal.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-tests-list-bumble.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2020 The Android Open Source Project
+<!-- Copyright 2025 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,10 +13,8 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="List of internal MTS tests.">
-    <!-- Include Pandora tests -->
-    <option name="compatibility:include-filter" value="pts-bot-mts" />
-
-    <!-- Enable Pandora tests -->
-    <option name="compatibility:module-arg" value="pts-bot-mts:enable:true" />
+<configuration description="List of BumbleBluetoothTests Bluetooth MTS tests.">
+    <option name="compatibility:include-filter" value="BumbleBluetoothTests" />
+    <option name="compatibility:module-arg" value="BumbleBluetoothTests:enable:true" />
 </configuration>
+
diff --git a/tools/mts-tradefed/res/config/mts-bluetooth-tests-list-shard-01.xml b/tools/mts-tradefed/res/config/mts-bt-tests-list-java.xml
similarity index 82%
rename from tools/mts-tradefed/res/config/mts-bluetooth-tests-list-shard-01.xml
rename to tools/mts-tradefed/res/config/mts-bt-tests-list-java.xml
index 843dbd3..df76c0b 100644
--- a/tools/mts-tradefed/res/config/mts-bluetooth-tests-list-shard-01.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-tests-list-java.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,11 +13,13 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="List of Bluetooth MTS tests that do not need root access (shard 01).">
+<configuration description="List of Java Bluetooth MTS tests.">
+    <option name="compatibility:include-filter" value="BluetoothJavaUnitTests" />
     <option name="compatibility:include-filter" value="CtsBluetoothTestCases" />
     <option name="compatibility:include-filter" value="FrameworkBluetoothTests" />
     <option name="compatibility:include-filter" value="ServiceBluetoothTests" />
     <option name="compatibility:include-filter" value="GoogleBluetoothInstrumentationTests" />
+    <option name="compatibility:module-arg" value="BluetoothJavaUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsBluetoothTestCases:enable:true" />
     <option name="compatibility:module-arg" value="FrameworkBluetoothTests:enable:true" />
     <option name="compatibility:module-arg" value="ServiceBluetoothTests:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-bluetooth-tests-list-shard-02.xml b/tools/mts-tradefed/res/config/mts-bt-tests-list-native.xml
similarity index 71%
rename from tools/mts-tradefed/res/config/mts-bluetooth-tests-list-shard-02.xml
rename to tools/mts-tradefed/res/config/mts-bt-tests-list-native.xml
index 4cff588..eea4f94 100644
--- a/tools/mts-tradefed/res/config/mts-bluetooth-tests-list-shard-02.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-tests-list-native.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,39 +13,54 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="List of Bluetooth MTS tests that do not need root access (shard 02).">
+<configuration description="List of native Bluetooth MTS tests.">
+    <option name="compatibility:include-filter" value="audio_bluetooth_hw_test" />
+    <option name="compatibility:include-filter" value="bluetooth_audio_hal_version_test" />
     <option name="compatibility:include-filter" value="bluetooth_csis_test" />
-    <option name="compatibility:include-filter" value="bluetooth_flatbuffer_tests" />
     <option name="compatibility:include-filter" value="bluetooth_groups_test" />
     <option name="compatibility:include-filter" value="bluetooth_has_test" />
+    <option name="compatibility:include-filter" value="bluetooth_hh_test" />
     <option name="compatibility:include-filter" value="bluetooth_le_audio_client_test" />
+    <option name="compatibility:include-filter" value="bluetooth_le_audio_codec_manager_test" />
     <option name="compatibility:include-filter" value="bluetooth_le_audio_test" />
     <option name="compatibility:include-filter" value="bluetooth_packet_parser_test" />
-    <option name="compatibility:include-filter" value="bluetoothtbd_test" />
+    <option name="compatibility:include-filter" value="bluetooth_ras_test" />
+    <option name="compatibility:include-filter" value="bluetooth-test-audio-hal-a2dp-provider-info" />
+    <option name="compatibility:include-filter" value="bluetooth-test-audio-hal-aidl-leaudio-utils" />
+    <option name="compatibility:include-filter" value="bluetooth-test-audio-hal-hfp-client-interface" />
+    <option name="compatibility:include-filter" value="bluetooth-test-audio-hal-le-audio-software" />
+    <option name="compatibility:include-filter" value="bluetooth-test-audio-hal-interface" />
     <option name="compatibility:include-filter" value="bluetooth_test_broadcaster" />
+    <option name="compatibility:include-filter" value="bluetooth_test_broadcaster_state_machine" />
     <option name="compatibility:include-filter" value="bluetooth_test_common" />
     <option name="compatibility:include-filter" value="bluetooth_test_gd_unit" />
-    <option name="compatibility:include-filter" value="bluetooth_test_sdp" />
+    <option name="compatibility:include-filter" value="bluetooth_test_with_timerfd" />
     <option name="compatibility:include-filter" value="bluetooth_vc_test" />
-    <option name="compatibility:include-filter" value="bt_host_test_bta" />
+    <option name="compatibility:include-filter" value="bt_host_test_bta_scn" />
     <option name="compatibility:include-filter" value="libaptx_enc_tests" />
     <option name="compatibility:include-filter" value="libaptxhd_enc_tests" />
-    <option name="compatibility:include-filter" value="net_test_audio_a2dp_hw" />
-    <option name="compatibility:include-filter" value="net_test_audio_hearing_aid_hw" />
+    <option name="compatibility:include-filter" value="libbluetooth_core_rs_test" />
+    <option name="compatibility:include-filter" value="libbluetooth_log_test" />
+    <option name="compatibility:include-filter" value="libbluetooth_offload_hci_test" />
+    <option name="compatibility:include-filter" value="libbluetooth_offload_leaudio_hci_test" />
     <option name="compatibility:include-filter" value="net_test_avrcp" />
     <option name="compatibility:include-filter" value="net_test_bluetooth" />
     <option name="compatibility:include-filter" value="net_test_bta" />
-    <option name="compatibility:include-filter" value="net_test_btcore" />
+    <option name="compatibility:include-filter" value="net_test_bta_gatt" />
+    <option name="compatibility:include-filter" value="net_test_bta_jv" />
+    <option name="compatibility:include-filter" value="net_test_bta_security" />
     <option name="compatibility:include-filter" value="net_test_btif" />
     <option name="compatibility:include-filter" value="net_test_btif_avrcp_audio_track" />
-    <option name="compatibility:include-filter" value="net_test_btif_config_cache" />
     <option name="compatibility:include-filter" value="net_test_btif_hf_client_service" />
+    <option name="compatibility:include-filter" value="net_test_btif_hh" />
     <option name="compatibility:include-filter" value="net_test_btif_profile_queue" />
     <option name="compatibility:include-filter" value="net_test_btif_rc" />
     <option name="compatibility:include-filter" value="net_test_btif_stack" />
     <option name="compatibility:include-filter" value="net_test_btm_iso" />
     <option name="compatibility:include-filter" value="net_test_btpackets" />
+    <option name="compatibility:include-filter" value="net_test_conn_multiplexing" />
     <option name="compatibility:include-filter" value="net_test_device" />
+    <option name="compatibility:include-filter" value="net_test_device_iot_config" />
     <option name="compatibility:include-filter" value="net_test_eatt" />
     <option name="compatibility:include-filter" value="net_test_hci" />
     <option name="compatibility:include-filter" value="net_test_main_shim" />
@@ -53,9 +68,9 @@
     <option name="compatibility:include-filter" value="net_test_performance" />
     <option name="compatibility:include-filter" value="net_test_stack" />
     <option name="compatibility:include-filter" value="net_test_stack_a2dp_codecs_native" />
-    <option name="compatibility:include-filter" value="net_test_stack_a2dp_native" />
     <option name="compatibility:include-filter" value="net_test_stack_acl" />
     <option name="compatibility:include-filter" value="net_test_stack_ad_parser" />
+    <option name="compatibility:include-filter" value="net_test_stack_avctp" />
     <option name="compatibility:include-filter" value="net_test_stack_avdtp" />
     <option name="compatibility:include-filter" value="net_test_stack_btm" />
     <option name="compatibility:include-filter" value="net_test_stack_btu" />
@@ -65,53 +80,67 @@
     <option name="compatibility:include-filter" value="net_test_stack_hci" />
     <option name="compatibility:include-filter" value="net_test_stack_hid" />
     <option name="compatibility:include-filter" value="net_test_stack_l2cap" />
-    <option name="compatibility:include-filter" value="net_test_stack_multi_adv" />
     <option name="compatibility:include-filter" value="net_test_stack_rfcomm" />
+    <option name="compatibility:include-filter" value="net_test_stack_rnr" />
     <option name="compatibility:include-filter" value="net_test_stack_sdp" />
     <option name="compatibility:include-filter" value="net_test_stack_smp" />
     <option name="compatibility:include-filter" value="net_test_types" />
+    <option name="compatibility:module-arg" value="audio_bluetooth_hw_test:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth_audio_hal_version_test:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_csis_test:enable:true" />
-    <option name="compatibility:module-arg" value="bluetooth_flatbuffer_tests:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_groups_test:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_has_test:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth_hh_test:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_le_audio_client_test:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth_le_audio_codec_manager_test:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_le_audio_test:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_packet_parser_test:enable:true" />
-    <option name="compatibility:module-arg" value="bluetoothtbd_test:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth_ras_test:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth-test-audio-hal-a2dp-provider-info:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth-test-audio-hal-aidl-leaudio-utils:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth-test-audio-hal-hfp-client-interface:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth-test-audio-hal-le-audio-software:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth-test-audio-hal-interface:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_test_broadcaster:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth_test_broadcaster_state_machine:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_test_common:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_test_gd_unit:enable:true" />
-    <option name="compatibility:module-arg" value="bluetooth_test_sdp:enable:true" />
+    <option name="compatibility:module-arg" value="bluetooth_test_with_timerfd:enable:true" />
     <option name="compatibility:module-arg" value="bluetooth_vc_test:enable:true" />
-    <option name="compatibility:module-arg" value="bt_host_test_bta:enable:true" />
+    <option name="compatibility:module-arg" value="bt_host_test_bta_scn:enable:true" />
     <option name="compatibility:module-arg" value="libaptx_enc_tests:enable:true" />
     <option name="compatibility:module-arg" value="libaptxhd_enc_tests:enable:true" />
-    <option name="compatibility:module-arg" value="net_test_audio_a2dp_hw:enable:true" />
-    <option name="compatibility:module-arg" value="net_test_audio_hearing_aid_hw:enable:true" />
+    <option name="compatibility:module-arg" value="libbluetooth_core_rs_test:enable:true" />
+    <option name="compatibility:module-arg" value="libbluetooth_log_test:enable:true" />
+    <option name="compatibility:module-arg" value="libbluetooth_offload_hci_test:enable:true" />
+    <option name="compatibility:module-arg" value="libbluetooth_offload_leaudio_hci_test:enable:true" />
     <option name="compatibility:module-arg" value="net_test_avrcp:enable:true" />
     <option name="compatibility:module-arg" value="net_test_bluetooth:enable:true" />
     <option name="compatibility:module-arg" value="net_test_bta:enable:true" />
-    <option name="compatibility:module-arg" value="net_test_btcore:enable:true" />
+    <option name="compatibility:module-arg" value="net_test_bta_gatt:enable:true" />
+    <option name="compatibility:module-arg" value="net_test_bta_jv:enable:true" />
+    <option name="compatibility:module-arg" value="net_test_bta_security:enable:true" />
     <option name="compatibility:module-arg" value="net_test_btif:enable:true" />
     <option name="compatibility:module-arg" value="net_test_btif_avrcp_audio_track:enable:true" />
-    <option name="compatibility:module-arg" value="net_test_btif_config_cache:enable:true" />
     <option name="compatibility:module-arg" value="net_test_btif_hf_client_service:enable:true" />
+    <option name="compatibility:module-arg" value="net_test_btif_hh:enable:true" />
     <option name="compatibility:module-arg" value="net_test_btif_profile_queue:enable:true" />
     <option name="compatibility:module-arg" value="net_test_btif_rc:enable:true" />
     <option name="compatibility:module-arg" value="net_test_btif_stack:enable:true" />
     <option name="compatibility:module-arg" value="net_test_btm_iso:enable:true" />
     <option name="compatibility:module-arg" value="net_test_btpackets:enable:true" />
+    <option name="compatibility:module-arg" value="net_test_conn_multiplexing:enable:true" />
     <option name="compatibility:module-arg" value="net_test_device:enable:true" />
+    <option name="compatibility:module-arg" value="net_test_device_iot_config:enable:true" />
     <option name="compatibility:module-arg" value="net_test_eatt:enable:true" />
     <option name="compatibility:module-arg" value="net_test_hci:enable:true" />
-    <option name="compatibility:module-arg" value="net_test_hci_fragmenter_native:enable:true" />
     <option name="compatibility:module-arg" value="net_test_main_shim:enable:true" />
     <option name="compatibility:module-arg" value="net_test_osi:enable:true" />
     <option name="compatibility:module-arg" value="net_test_performance:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_a2dp_codecs_native:enable:true" />
-    <option name="compatibility:module-arg" value="net_test_stack_a2dp_native:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_acl:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_ad_parser:enable:true" />
+    <option name="compatibility:module-arg" value="net_test_stack_avctp:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_avdtp:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_btm:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_btu:enable:true" />
@@ -122,8 +151,8 @@
     <option name="compatibility:module-arg" value="net_test_stack_hci:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_hid:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_l2cap:enable:true" />
-    <option name="compatibility:module-arg" value="net_test_stack_multi_adv:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_rfcomm:enable:true" />
+    <option name="compatibility:module-arg" value="net_test_stack_rnr:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_sdp:enable:true" />
     <option name="compatibility:module-arg" value="net_test_stack_smp:enable:true" />
     <option name="compatibility:module-arg" value="net_test_types:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-bluetooth-tests-list-shard-00.xml b/tools/mts-tradefed/res/config/mts-bt-tests-list-pts-bot.xml
similarity index 83%
rename from tools/mts-tradefed/res/config/mts-bluetooth-tests-list-shard-00.xml
rename to tools/mts-tradefed/res/config/mts-bt-tests-list-pts-bot.xml
index 1d19960..33d2c8f 100644
--- a/tools/mts-tradefed/res/config/mts-bluetooth-tests-list-shard-00.xml
+++ b/tools/mts-tradefed/res/config/mts-bt-tests-list-pts-bot.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,7 +13,7 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="List of Bluetooth MTS tests that do not need root access (shard 00).">
+<configuration description="List of PTS-bot Bluetooth MTS tests.">
     <option name="compatibility:include-filter" value="pts-bot-mts" />
     <option name="compatibility:module-arg" value="pts-bot-mts:enable:true" />
 </configuration>
\ No newline at end of file
diff --git a/tools/mts-tradefed/res/config/mts-bt.xml b/tools/mts-tradefed/res/config/mts-bt.xml
new file mode 100644
index 0000000..e46a246
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-bt.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="utf-8"?>
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
+<configuration description="Runs mts-bt from a pre-existing MTS installation">
+
+    <include name="mts" />
+    <include name="mts-bt-tests-list-java" />
+    <include name="mts-bt-tests-list-native" />
+    <include name="mts-bt-tests-list-pts-bot" />
+    <include name="mts-bt-tests-list-avatar" />
+    <include name="mts-bt-tests-list-bumble" />
+    <option name="plan" value="mts-bt" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+        <option name="property-name" value="ro.build.type" />
+        <option name="expected-value" value="userdebug"/> <!-- Device should have userdebug/eng build -->
+        <option name="throw-error" value="false"/> <!-- Only print warning if not user build -->
+    </target_preparer>
+
+    <option name="compatibility:primary-abi-only" value="true" />
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-crashrecovery-tests-list-eng-only.xml b/tools/mts-tradefed/res/config/mts-crashrecovery-tests-list-eng-only.xml
index 58d0eb5..0f43d0a 100644
--- a/tools/mts-tradefed/res/config/mts-crashrecovery-tests-list-eng-only.xml
+++ b/tools/mts-tradefed/res/config/mts-crashrecovery-tests-list-eng-only.xml
@@ -17,9 +17,15 @@
 <configuration description="List of crashrecovery MTS tests that need root access.">
 
   <option name="compatibility:include-filter" value="CtsRootPackageWatchdogTestCases" />
+  <option name="compatibility:include-filter" value="CrashRecoveryModuleTests" />
+  <option name="compatibility:include-filter" value="RollbackPackageHealthObserverTests" />
+  <option name="compatibility:include-filter" value="PackageWatchdogTest" />
 
   <!-- Enable MainlineTestModuleController. -->
   <option name="compatibility:module-arg" value="CtsRootPackageWatchdogTestCases:enable:true" />
+  <option name="compatibility:module-arg" value="CrashRecoveryModuleTests:enable:true" />
+  <option name="compatibility:module-arg" value="PackageWatchdogTest:enable:true" />
+  <option name="compatibility:module-arg" value="RollbackPackageHealthObserverTests:enable:true" />
 
 </configuration>
 
diff --git a/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml
index c91550c..8e7366c 100644
--- a/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml
@@ -46,9 +46,11 @@
     <!-- Add remaining AdServices CTS test modules here once they're ported over to Android S -->
     <option name="compatibility:include-filter" value="AdExtServicesApkUINotificationTests" />
     <option name="compatibility:include-filter" value="AdExtServicesApkUISettingsGaOtaTests" />
+    <option name="compatibility:include-filter" value="AdExtServicesApkUISettingsGaUXSelectorTests" />
     <option name="compatibility:include-filter" value="AdExtServicesApkUISettingsTests" />
     <option name="compatibility:include-filter" value="AdExtServicesApkUITestsAppConsent" />
     <option name="compatibility:include-filter" value="AdExtServicesApkUnitTests" />
+    <option name="compatibility:include-filter" value="AdExtServicesCobaltUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesFrameworkRvcUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesFrameworkUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesJsEngineUnitTests" />
@@ -104,9 +106,11 @@
 
     <option name="compatibility:module-arg" value="AdExtServicesApkUINotificationTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesApkUISettingsGaOtaTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdExtServicesApkUISettingsGaUXSelectorTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesApkUISettingsTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesApkUITestsAppConsent:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesApkUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdExtServicesCobaltUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesFrameworkUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesFrameworkRvcUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesJsEngineUnitTests:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-media-tests-list.xml b/tools/mts-tradefed/res/config/mts-media-tests-list.xml
index c038278..03df57c 100644
--- a/tools/mts-tradefed/res/config/mts-media-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-media-tests-list.xml
@@ -17,9 +17,6 @@
         <!-- These Media CTS tests are mostly relevant to mainline.
             The "mostly" is addressed with annotations to exclude specific tests in each suite.
         -->
-    <option name="compatibility:include-filter" value="MctsMediaBetterTogetherTestCases" />
-    <option name="compatibility:module-arg" value="MctsMediaBetterTogetherTestCases:instrumentation-arg:mts-media:=true" />
-    <option name="compatibility:module-arg" value="MctsMediaBetterTogetherTestCases:instrumentation-arg:media-testing-mode:=mts" />
 
     <option name="compatibility:include-filter" value="MctsMediaCodecTestCases" />
     <option name="compatibility:module-arg" value="MctsMediaCodecTestCases:instrumentation-arg:mts-media:=true" />
@@ -49,11 +46,14 @@
     <option name="compatibility:module-arg" value="MctsMediaV2TestCases:instrumentation-arg:mts-media:=true" />
     <option name="compatibility:module-arg" value="MctsMediaV2TestCases:instrumentation-arg:media-testing-mode:=mts" />
 
-
     <option name="compatibility:include-filter" value="MctsMediaParserTestCases" />
     <option name="compatibility:module-arg" value="MctsMediaParserTestCases:instrumentation-arg:mts-media:=true" />
     <option name="compatibility:module-arg" value="MctsMediaParserTestCases:instrumentation-arg:media-testing-mode:=mts" />
 
+    <option name="compatibility:include-filter" value="MctsMediaSessionTestCases" />
+    <option name="compatibility:module-arg" value="MctsMediaSessionTestCases:instrumentation-arg:mts-media:=true" />
+    <option name="compatibility:module-arg" value="MctsMediaSessionTestCases:instrumentation-arg:media-testing-mode:=mts" />
+
     <!-- b/344653352 dropped MctsMediaStressTestCases -->
 
     <option name="compatibility:include-filter" value="MctsMediaTranscodingTestCases" />
diff --git a/tools/mts-tradefed/res/config/mts-network-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-network-tests-list-user.xml
index a1bc9b2..360f313 100644
--- a/tools/mts-tradefed/res/config/mts-network-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-network-tests-list-user.xml
@@ -17,5 +17,6 @@
     <option name="compatibility:include-filter" value="CtsNetTestCases" />
     <option name="compatibility:include-filter" value="CaptivePortalLoginTests" />
     <option name="compatibility:module-arg" value="CtsNetTestCases:exclude-annotation:com.android.testutils.ConnectivityModuleTest" />
+    <option name="compatibility:module-arg" value="CtsNetTestCases:exclude-annotation:com.android.testutils.DnsResolverModuleTest" />
 </configuration>
 
diff --git a/tools/mts-tradefed/res/config/mts-nfc-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-nfc-tests-list-user.xml
index 1fe2f7d..55abb46 100644
--- a/tools/mts-tradefed/res/config/mts-nfc-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-nfc-tests-list-user.xml
@@ -15,13 +15,15 @@
 -->
 
 <configuration description="List of NFC MTS tests that do not need root access.">
+    <option name="compatibility:include-filter" value="NfcManagerTests" />
     <option name="compatibility:include-filter" value="NfcNciUnitTests" />
-    <option name="compatibility:include-filter" value="NfcNciInstrumentationTests" />
     <option name="compatibility:include-filter" value="CtsNfcTestCases" />
     <option name="compatibility:include-filter" value="NfcTestCases" />
+    <option name="compatibility:include-filter" value="CtsNdefTestCases" />
 
+    <option name="compatibility:module-arg" value="NfcManagerTests:enable:true" />
     <option name="compatibility:module-arg" value="NfcNciUnitTests:enable:true" />
-    <option name="compatibility:module-arg" value="NfcNciInstrumentationTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsNfcTestCases:enable:true" />
     <option name="compatibility:module-arg" value="NfcTestCases:enable:true" />
+    <option name="compatibility:module-arg" value="CtsNdefTestCases:enable:true" />
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-permission-tests-list-oem.xml b/tools/mts-tradefed/res/config/mts-permission-tests-list-oem.xml
index 43cda4e..e1f1f7f 100644
--- a/tools/mts-tradefed/res/config/mts-permission-tests-list-oem.xml
+++ b/tools/mts-tradefed/res/config/mts-permission-tests-list-oem.xml
@@ -43,6 +43,7 @@
     <option name="compatibility:module-arg" value="CtsHibernationTestCases:exclude-annotation:android.permission.cts.MtsIgnore" />
     <option name="compatibility:include-filter" value="CtsRoleTestCases" />
     <option name="compatibility:module-arg" value="CtsRoleTestCases:exclude-annotation:android.permission.cts.MtsIgnore" />
+    <option name="compatibility:include-filter" value="CtsRoleMultiUserTestCases" />
     <option name="compatibility:include-filter" value="CtsSafetyCenterTestCases" />
     <option name="compatibility:module-arg" value="CtsSafetyCenterTestCases:exclude-annotation:android.permission.cts.MtsIgnore" />
     <option name="compatibility:include-filter" value="GtsIncidentManagerTestCases" />
diff --git a/tools/mts-tradefed/res/config/mts-profiling-tests-list.xml b/tools/mts-tradefed/res/config/mts-profiling-tests-list.xml
new file mode 100644
index 0000000..3b38497
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-profiling-tests-list.xml
@@ -0,0 +1,21 @@
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
+
+<configuration description="List of profiling module MTS tests">
+  <option name="compatibility:include-filter" value="CtsProfilingModuleTests" />
+
+  <option name="compatibility:module-arg" value="CtsProfilingMaduleTests:enable:true" />
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-profiling.xml b/tools/mts-tradefed/res/config/mts-profiling.xml
new file mode 100644
index 0000000..51d50f6
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-profiling.xml
@@ -0,0 +1,27 @@
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
+<configuration description="Runs MTS-profiling from a pre-existing MTS installation">
+
+    <include name="mts" />
+    <include name="mts-profiling-tests-list" />
+    <option name="plan" value="mts-profiling" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+        <option name="property-name" value="ro.build.type" />
+        <option name="expected-value" value="userdebug"/> <!-- Device should have userdebug/eng build -->
+        <option name="throw-error" value="false"/> <!-- Only print warning if not user build -->
+    </target_preparer>
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-tests-list-eng-only.xml b/tools/mts-tradefed/res/config/mts-tests-list-eng-only.xml
index 34b9f7d..0b6c1a1 100644
--- a/tools/mts-tradefed/res/config/mts-tests-list-eng-only.xml
+++ b/tools/mts-tradefed/res/config/mts-tests-list-eng-only.xml
@@ -25,7 +25,8 @@
     <include name="mts-extservices-tests-list-eng-only" />
     <include name="mts-mediaprovider-tests-list-eng-only" />
     <include name="mts-network-tests-list-eng-only" />
-    <!-- TODO: Enable when 25Q2 is next. include name="mts-nfc-tests-list-eng-only" / -->
+    <include name="mts-nfc-tests-list-eng-only" />
+    <!-- TODO: Enable when 25Q2 is next. include name="mts-uprobestats-tests-list-eng-only" / -->
     <include name="mts-rkpd-tests-list-eng-only" />
     <include name="mts-statsd-tests-list-eng-only" />
     <include name="mts-tethering-tests-list-eng-only" />
diff --git a/tools/mts-tradefed/res/config/mts-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-tests-list-user.xml
index 9fc5eef..15a9092 100644
--- a/tools/mts-tradefed/res/config/mts-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-tests-list-user.xml
@@ -33,16 +33,18 @@
     <include name="mts-mediaprovider-tests-list-user" />
     <include name="mts-network-tests-list-user" />
     <include name="mts-neuralnetworks-tests-list" />
-    <!-- TODO: Enable when 25Q2 is next. include name="mts-nfc-tests-list-user" / -->
+    <include name="mts-nfc-tests-list-user" />
     <include name="mts-ondevicepersonalization-tests-list" />
     <include name="mts-permission-tests-list-oem" />
     <include name="mts-preload-verify-tests-list" />
+    <include name="mts-profiling-tests-list" />
     <include name="mts-rkpd-tests-list-user" />
     <include name="mts-scheduling-tests-list" />
     <include name="mts-sdkextensions-tests-list" />
     <include name="mts-statsd-tests-list-user" />
     <include name="mts-tethering-tests-list-user" />
     <include name="mts-tzdata-tests-list" />
+    <!-- TODO: Enable when 25Q2 is next. include name="mts-uprobestats-tests-list-user" / -->
     <include name="mts-uwb-tests-list-user" />
     <include name="mts-wifi-oem-tests-list" />
 
diff --git a/tools/mts-tradefed/res/config/mts-tethering-coverage.xml b/tools/mts-tradefed/res/config/mts-tethering-coverage.xml
index 4e18591..f49eb12 100644
--- a/tools/mts-tradefed/res/config/mts-tethering-coverage.xml
+++ b/tools/mts-tradefed/res/config/mts-tethering-coverage.xml
@@ -30,6 +30,7 @@
     <option name="compatibility:include-filter" value="NetHttpCoverageTests" />
     <option name="compatibility:include-filter" value="net_unittests_tester" />
     <option name="compatibility:include-filter" value="cronet_unittests_tester" />
+    <option name="compatibility:include-filter" value="FrameworksVcnTests" />
 
     <!-- Coverage runs are significantly slower than normal runs, and testFuzzing cannot
          complete before the general test timeout (5 minutes) on such configurations. It is
diff --git a/tools/mts-tradefed/res/config/mts-tethering-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-tethering-tests-list-user.xml
index 39560d0..0b49ec3 100644
--- a/tools/mts-tradefed/res/config/mts-tethering-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-tethering-tests-list-user.xml
@@ -13,7 +13,7 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="List of MTS tethering tests that do not need root acccess">
+<configuration description="List of MTS tethering tests that do not need root access">
 
     <option name="compatibility:include-filter" value="CtsNetTestCases" />
     <option name="compatibility:include-filter" value="CtsNetTestCasesMaxTargetSdk33" />
@@ -26,6 +26,8 @@
     <option name="compatibility:include-filter" value="CtsNetHttpTestCases" />
     <option name="compatibility:include-filter" value="ThreadNetworkUnitTests" />
     <option name="compatibility:include-filter" value="CtsThreadNetworkTestCases" />
+    <option name="compatibility:include-filter" value="CtsVcnTestCases" />
+    <option name="compatibility:include-filter" value="FrameworksVcnTests" />
 
     <!-- Do not include NetworkStack module-specific tests as Connectivity MTS may not run
          with the latest version of that module installed -->
@@ -41,6 +43,18 @@
             value="MtsTetheringTestLatestSdk:exclude-annotation:com.android.testutils.NetworkStackModuleTest" />
     <option name="compatibility:module-arg"
             value="CtsTetheringTest:exclude-annotation:com.android.testutils.NetworkStackModuleTest" />
+    <option name="compatibility:module-arg"
+            value="CtsNetTestCases:exclude-annotation:com.android.testutils.DnsResolverModuleTest" />
+    <option name="compatibility:module-arg"
+            value="CtsNetTestCasesMaxTargetSdk33:exclude-annotation:com.android.testutils.DnsResolverModuleTest" />
+    <option name="compatibility:module-arg"
+            value="CtsNetTestCasesMaxTargetSdk31:exclude-annotation:com.android.testutils.DnsResolverModuleTest" />
+    <option name="compatibility:module-arg"
+            value="CtsNetTestCasesMaxTargetSdk30:exclude-annotation:com.android.testutils.DnsResolverModuleTest" />
+    <option name="compatibility:module-arg"
+            value="MtsTetheringTestLatestSdk:exclude-annotation:com.android.testutils.DnsResolverModuleTest" />
+    <option name="compatibility:module-arg"
+            value="CtsTetheringTest:exclude-annotation:com.android.testutils.DnsResolverModuleTest" />
 
     <!-- Enable tethering MTS tests to use MainlineTestModuleController -->
     <option name="compatibility:module-arg" value="CtsNetTestCases:enable:true" />
@@ -54,5 +68,7 @@
     <option name="compatibility:module-arg" value="CtsNetHttpTestCases:enable:true" />
     <option name="compatibility:module-arg" value="ThreadNetworkUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsThreadNetworkTestCases:enable:true" />
+    <option name="compatibility:module-arg" value="CtsVcnTestCases:enable:true" />
+    <option name="compatibility:module-arg" value="FrameworksVcnTests:enable:true" />
 </configuration>
 
diff --git a/tools/mts-tradefed/res/config/mts-uprobestats-tests-list-eng-only.xml b/tools/mts-tradefed/res/config/mts-uprobestats-tests-list-eng-only.xml
new file mode 100644
index 0000000..fa9ec44
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-uprobestats-tests-list-eng-only.xml
@@ -0,0 +1,10 @@
+<configuration description="List of uprobestats MTS tests that need root access.">
+
+    <option name="compatibility:include-filter" value="uprobestats-test test.SmokeTest" />
+    <option name="compatibility:include-filter" value="libuprobestats_test" />
+    <option name="compatibility:include-filter" value="uprobestats_libbpf_android_test" />
+
+    <!-- use MainlineTestModuleController -->
+    <option name="compatibility:module-arg" value="uprobestats-test:enable:true" />
+
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-uprobestats-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-uprobestats-tests-list-user.xml
new file mode 100644
index 0000000..36b3a64
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-uprobestats-tests-list-user.xml
@@ -0,0 +1,5 @@
+<configuration description="List of uprobestats MTS tests that don't need root access.">
+
+    <option name="compatibility:include-filter" value="CtsStatsdAtomHostTestCases android.cts.statsdatom.perf.UprobeStatsTest" />
+
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-uprobestats.xml b/tools/mts-tradefed/res/config/mts-uprobestats.xml
new file mode 100644
index 0000000..8578948
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-uprobestats.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
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
+<configuration description="Runs MTS-uprobestats from a pre-existing MTS installation">
+
+    <include name="mts" />
+
+    <include name="mts-uprobestats-tests-list-eng-only" />
+    <include name="mts-uprobestats-tests-list-user" />
+
+    <option name="plan" value="mts-uprobestats" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+        <option name="property-name" value="ro.build.type" />
+        <option name="expected-value" value="userdebug"/> <!-- Device should have userdebug/eng build -->
+        <option name="throw-error" value="false"/> <!-- Only print warning if not user build -->
+    </target_preparer>
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-uwb-tests-list-multi-devices.xml b/tools/mts-tradefed/res/config/mts-uwb-tests-list-multi-devices.xml
index 9cf4dc1..79d5975 100644
--- a/tools/mts-tradefed/res/config/mts-uwb-tests-list-multi-devices.xml
+++ b/tools/mts-tradefed/res/config/mts-uwb-tests-list-multi-devices.xml
@@ -1,7 +1,9 @@
 <configuration description="List of UWB MTS tests that need multi devices.">
     <option name="compatibility:include-filter" value="CtsUwbMultiDeviceTestCase_UwbManagerTests" />
     <option name="compatibility:include-filter" value="CtsUwbMultiDeviceTestCase_FiraRangingTests" />
+    <option name="compatibility:include-filter" value="MultiDeviceRangingTestCases" />
 
     <option name="compatibility:module-arg" value="CtsUwbMultiDeviceTestCase_UwbManagerTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsUwbMultiDeviceTestCase_FiraRangingTests:enable:true" />
+    <option name="compatibility:module-arg" value="MultiDeviceRangingTestCases:enable:true" />
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-uwb-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-uwb-tests-list-user.xml
index 24eb4c2..19d89ee 100644
--- a/tools/mts-tradefed/res/config/mts-uwb-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-uwb-tests-list-user.xml
@@ -18,8 +18,20 @@
     <option name="compatibility:include-filter" value="FrameworkUwbTests" />
     <option name="compatibility:include-filter" value="ServiceUwbTests" />
     <option name="compatibility:include-filter" value="CtsUwbTestCases" />
+    <option name="compatibility:include-filter" value="CtsRangingTestCases" />
+    <option name="compatibility:include-filter" value="RangingServiceTests" />
+    <option name="compatibility:include-filter" value="RangingRttBackendTests" />
+    <option name="compatibility:include-filter" value="RangingUwbBackendTests" />
+    <option name="compatibility:include-filter" value="RangingFrameworkTests" />
+    <option name="compatibility:include-filter" value="UwbFusionLibTests" />
 
     <option name="compatibility:module-arg" value="FrameworkUwbTests:enable:true" />
     <option name="compatibility:module-arg" value="ServiceUwbTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsUwbTestCases:enable:true" />
+    <option name="compatibility:module-arg" value="CtsRangingTestCases:enable:true" />
+    <option name="compatibility:module-arg" value="RangingServiceTests:enable:true" />
+    <option name="compatibility:module-arg" value="RangingRttBackendTests:enable:true" />
+    <option name="compatibility:module-arg" value="RangingUwbBackendTests:enable:true" />
+    <option name="compatibility:module-arg" value="RangingFrameworkTests:enable:true" />
+    <option name="compatibility:module-arg" value="UwbFusionLibTests:enable:true" />
 </configuration>
diff --git a/tools/mts-tradefed/tests/src/com/android/compatibility/tradefed/MtsTradefedTest.java b/tools/mts-tradefed/tests/src/com/android/compatibility/tradefed/MtsTradefedTest.java
index 44053d2..cb7944a 100644
--- a/tools/mts-tradefed/tests/src/com/android/compatibility/tradefed/MtsTradefedTest.java
+++ b/tools/mts-tradefed/tests/src/com/android/compatibility/tradefed/MtsTradefedTest.java
@@ -156,7 +156,7 @@ public class MtsTradefedTest {
       ZipEntry zipEntry = enumeration.nextElement();
 
       if (zipEntry.getName().endsWith(".xml") && zipEntry.getName().contains("tests-list")) {
-        if (zipEntry.getName().contains("bluetooth") || zipEntry.getName().contains("smoke")) {
+        if (zipEntry.getName().contains("smoke")) {
           continue;
         }
         // Relative path of file into the jar.
```

