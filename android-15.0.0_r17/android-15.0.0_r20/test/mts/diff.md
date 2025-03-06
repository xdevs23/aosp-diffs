```diff
diff --git a/tools/build/config.mk b/tools/build/config.mk
index 60001fd..5be510c 100644
--- a/tools/build/config.mk
+++ b/tools/build/config.mk
@@ -34,6 +34,7 @@ mts_modules += \
                cellbroadcast \
                configinfrastructure \
                conscrypt \
+               crashrecovery \
                cronet \
                dnsresolver \
                documentsui \
@@ -45,6 +46,7 @@ mts_modules += \
                mediaprovider \
                networking \
                neuralnetworks \
+               nfc \
                ondevicepersonalization \
                permission \
                profiling \
diff --git a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml
index 54d659e..9fe75f6 100644
--- a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml
+++ b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml
@@ -194,6 +194,8 @@
     <option name="compatibility:include-filter" value="art-run-test-2278-nested-loops"/>
     <option name="compatibility:include-filter" value="art-run-test-2279-aconfig-flags"/>
     <option name="compatibility:include-filter" value="art-run-test-2279-second-inner-loop-references-first"/>
+    <option name="compatibility:include-filter" value="art-run-test-2282-checker-always-throws-try-catch"/>
+    <option name="compatibility:include-filter" value="art-run-test-2283-checker-remove-null-check"/>
     <option name="compatibility:include-filter" value="art-run-test-300-package-override"/>
     <option name="compatibility:include-filter" value="art-run-test-301-abstract-protected"/>
     <option name="compatibility:include-filter" value="art-run-test-302-float-conversion"/>
@@ -477,6 +479,8 @@
     <option name="compatibility:include-filter" value="art-run-test-853-checker-inlining"/>
     <option name="compatibility:include-filter" value="art-run-test-856-clone"/>
     <option name="compatibility:include-filter" value="art-run-test-857-default-access"/>
+    <option name="compatibility:include-filter" value="art-run-test-858-checker-unsafe"/>
+    <option name="compatibility:include-filter" value="art-run-test-859-checker-var-handles-intrinsics"/>
     <option name="compatibility:include-filter" value="art-run-test-963-default-range-smali"/>
     <option name="compatibility:include-filter" value="art-run-test-965-default-verify"/>
     <option name="compatibility:include-filter" value="art-run-test-967-default-ame"/>
@@ -659,6 +663,8 @@
     <option name="compatibility:module-arg" value="art-run-test-2278-nested-loops:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-2279-aconfig-flags:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-2279-second-inner-loop-references-first:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-2282-checker-always-throws-try-catch:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-2283-checker-remove-null-check:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-300-package-override:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-301-abstract-protected:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-302-float-conversion:enable:true"/>
@@ -942,6 +948,8 @@
     <option name="compatibility:module-arg" value="art-run-test-853-checker-inlining:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-856-clone:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-857-default-access:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-858-checker-unsafe:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-859-checker-var-handles-intrinsics:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-963-default-range-smali:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-965-default-verify:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-967-default-ame:enable:true"/>
diff --git a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml
index f90bc9a..ef3261c 100644
--- a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml
+++ b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml
@@ -35,6 +35,7 @@
     <option name="compatibility:include-filter" value="art_standalone_odrefresh_tests"/>
     <option name="compatibility:include-filter" value="art_standalone_runtime_tests"/>
     <option name="compatibility:include-filter" value="art_standalone_sigchain_tests"/>
+    <option name="compatibility:include-filter" value="libnativebridge-lazy-tests"/>
     <option name="compatibility:include-filter" value="libnativeloader_test"/>
     <!-- Enable MainlineTestModuleController for ART gtests. -->
     <option name="compatibility:module-arg" value="art_libnativebridge_cts_tests:enable:true"/>
@@ -56,5 +57,6 @@
     <option name="compatibility:module-arg" value="art_standalone_odrefresh_tests:enable:true"/>
     <option name="compatibility:module-arg" value="art_standalone_runtime_tests:enable:true"/>
     <option name="compatibility:module-arg" value="art_standalone_sigchain_tests:enable:true"/>
+    <option name="compatibility:module-arg" value="libnativebridge-lazy-tests:enable:true"/>
     <option name="compatibility:module-arg" value="libnativeloader_test:enable:true"/>
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-linkerconfig-tests-list.xml b/tools/mts-tradefed/res/config/mts-crashrecovery-tests-list-eng-only.xml
similarity index 58%
rename from tools/mts-tradefed/res/config/mts-linkerconfig-tests-list.xml
rename to tools/mts-tradefed/res/config/mts-crashrecovery-tests-list-eng-only.xml
index 442e3d9..58d0eb5 100644
--- a/tools/mts-tradefed/res/config/mts-linkerconfig-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-crashrecovery-tests-list-eng-only.xml
@@ -1,5 +1,5 @@
-<?xml version="1.0" encoding="utf-8" ?>
-<!-- Copyright (C) 2021 The Android Open Source Project
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,8 +13,13 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="List of linkerconfig MTS tests">
-  <!-- Include tests from GTS -->
-  <option name="compatibility:include-filter" value="GtsLinkerConfigTestCases" />
+
+<configuration description="List of crashrecovery MTS tests that need root access.">
+
+  <option name="compatibility:include-filter" value="CtsRootPackageWatchdogTestCases" />
+
+  <!-- Enable MainlineTestModuleController. -->
+  <option name="compatibility:module-arg" value="CtsRootPackageWatchdogTestCases:enable:true" />
 
 </configuration>
+
diff --git a/tools/mts-tradefed/res/config/mts-linkerconfig.xml b/tools/mts-tradefed/res/config/mts-crashrecovery-tests-list-user.xml
similarity index 62%
rename from tools/mts-tradefed/res/config/mts-linkerconfig.xml
rename to tools/mts-tradefed/res/config/mts-crashrecovery-tests-list-user.xml
index 955417a..ddafd74 100644
--- a/tools/mts-tradefed/res/config/mts-linkerconfig.xml
+++ b/tools/mts-tradefed/res/config/mts-crashrecovery-tests-list-user.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2021 The Android Open Source Project
+<!-- Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,11 +13,13 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="Runs MTS-linkerconfig from a pre-existing MTS installation">
-  <include name="mts" />
 
-  <include name="mts-linkerconfig-tests-list" />
+<configuration description="List of crashrecovery MTS tests that do not need root access.">
 
-  <option name="plan" value="mts-linkerconfig" />
+  <option name="compatibility:include-filter" value="CtsPackageWatchdogTestCases" />
+
+  <!-- Enable MainlineTestModuleController. -->
+  <option name="compatibility:module-arg" value="CtsPackageWatchdogTestCases:enable:true" />
 
 </configuration>
+
diff --git a/tools/mts-tradefed/res/config/mts-crashrecovery.xml b/tools/mts-tradefed/res/config/mts-crashrecovery.xml
new file mode 100644
index 0000000..a1e5537
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-crashrecovery.xml
@@ -0,0 +1,31 @@
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
+<configuration description="Runs MTS-crashrecovery from a pre-existing MTS installation">
+
+    <include name="mts" />
+
+    <include name="mts-crashrecovery-tests-list-eng-only" />
+    <include name="mts-crashrecovery-tests-list-user" />
+
+    <option name="plan" value="mts-crashrecovery" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+      <option name="property-name" value="ro.build.type" />
+      <option name="expected-value" value="userdebug"/> <!-- Device should have userdebug/eng build -->
+      <option name="throw-error" value="false"/> <!-- Only print warning if not user build -->
+    </target_preparer>
+</configuration>
+
diff --git a/tools/mts-tradefed/res/config/mts-extservices-cts-only-tests-list.xml b/tools/mts-tradefed/res/config/mts-extservices-cts-only-tests-list.xml
index cfaf200..a7e3271 100644
--- a/tools/mts-tradefed/res/config/mts-extservices-cts-only-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-extservices-cts-only-tests-list.xml
@@ -27,11 +27,14 @@
 
     <!-- for AdServices -->
     <option name="compatibility:include-filter" value="CtsAdExtServicesAdIdEndToEndTest" />
+    <option name="compatibility:include-filter" value="CtsAdExtServicesAdIdRvcEndToEndTest" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesAdServicesCobaltTest" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesAppSetIdEndToEndTest" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesDebuggableDeviceTestCases" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesDeviceTestCases" />
+    <option name="compatibility:include-filter" value="CtsAdExtServicesRvcDeviceTestCases" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesCustomAudienceTests" />
+    <option name="compatibility:include-filter" value="CtsAdExtServicesEndToEndRvcTestMeasurement" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesEndToEndTestMeasurement" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesEndToEndTests" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesExtDataStorageServiceTest" />
@@ -51,12 +54,15 @@
 
     <!-- AdServices -->
     <option name="compatibility:module-arg" value="CtsAdExtServicesAdIdEndToEndTest:enable:true" />
+    <option name="compatibility:module-arg" value="CtsAdExtServicesAdIdRvcEndToEndTest:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesAdServicesCobaltTest:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesAppSetIdEndToEndTest:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesDebuggableDeviceTestCases:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesDeviceTestCases:enable:true" />
+    <option name="compatibility:module-arg" value="CtsAdExtServicesRvcDeviceTestCases:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesCustomAudienceTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesEndToEndTestMeasurement:enable:true" />
+    <option name="compatibility:module-arg" value="CtsAdExtServicesEndToEndRvcTestMeasurement:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesEndToEndTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesExtDataStorageServiceTest:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesHostTests:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml
index 4e65fb0..c91550c 100644
--- a/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml
@@ -49,24 +49,30 @@
     <option name="compatibility:include-filter" value="AdExtServicesApkUISettingsTests" />
     <option name="compatibility:include-filter" value="AdExtServicesApkUITestsAppConsent" />
     <option name="compatibility:include-filter" value="AdExtServicesApkUnitTests" />
+    <option name="compatibility:include-filter" value="AdExtServicesFrameworkRvcUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesFrameworkUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesJsEngineUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesMddIntegrationTests" />
+    <option name="compatibility:include-filter" value="AdExtServicesServiceCoreAdIdRvcUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreAdIdUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreAppSearchUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreAppsetIdUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreCommonUnitTests" />
+    <option name="compatibility:include-filter" value="AdExtServicesServiceCoreMeasurementRvcUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreMeasurementUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreProtectedAudienceUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreTopicsUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesUIUnitTests" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesAdIdEndToEndTest" />
+    <option name="compatibility:include-filter" value="CtsAdExtServicesAdIdRvcEndToEndTest" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesAdServicesCobaltTest" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesAppSetIdEndToEndTest" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesDebuggableDeviceTestCases" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesDeviceTestCases" />
+    <option name="compatibility:include-filter" value="CtsAdExtServicesRvcDeviceTestCases" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesCustomAudienceTests" />
+    <option name="compatibility:include-filter" value="CtsAdExtServicesEndToEndRvcTestMeasurement" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesEndToEndTestMeasurement" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesEndToEndTests" />
     <option name="compatibility:include-filter" value="CtsAdExtServicesExtDataStorageServiceTest" />
@@ -102,23 +108,29 @@
     <option name="compatibility:module-arg" value="AdExtServicesApkUITestsAppConsent:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesApkUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesFrameworkUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdExtServicesFrameworkRvcUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesJsEngineUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesMddIntegrationTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdExtServicesServiceCoreAdIdRvcUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreAdIdUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreAppSearchUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreAppsetIdUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreCommonUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdExtServicesServiceCoreMeasurementRvcUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreMeasurementUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreProtectedAudienceUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreTopicsUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesUIUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesAdIdEndToEndTest:enable:true" />
+    <option name="compatibility:module-arg" value="CtsAdExtServicesAdIdRvcEndToEndTest:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesAdServicesCobaltTest:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesAppSetIdEndToEndTest:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesDebuggableDeviceTestCases:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesDeviceTestCases:enable:true" />
+    <option name="compatibility:module-arg" value="CtsAdExtServicesRvcDeviceTestCases:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesCustomAudienceTests:enable:true" />
+    <option name="compatibility:module-arg" value="CtsAdExtServicesEndToEndRvcTestMeasurement:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesEndToEndTestMeasurement:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesEndToEndTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsAdExtServicesExtDataStorageServiceTest:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-healthfitness-no-unittests-tests-list.xml b/tools/mts-tradefed/res/config/mts-healthfitness-no-unittests-tests-list.xml
index 94759bb..25a1a7d 100644
--- a/tools/mts-tradefed/res/config/mts-healthfitness-no-unittests-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-healthfitness-no-unittests-tests-list.xml
@@ -13,8 +13,8 @@
 
 <configuration description="List test modules of HealthFitness module excluding unit tests. This is a placeholder xml instead of a runnable plan.">
       <option name="compatibility:include-filter" value="CtsHealthFitnessDeviceTestCases" />
-      <option name="compatibility:include-filter" value="CtsHealthFitnessDeviceTestCasesNoPermission"/>
-      <option name="compatibility:include-filter" value="CtsHealthFitnessDeviceTestCasesNotAllPermissionsAreGranted"/>
+      <option name="compatibility:include-filter" value="CtsHealthFitnessDeviceTestCasesNoPermission" />
+      <option name="compatibility:include-filter" value="CtsHealthFitnessDeviceTestCasesNotAllPermissionsAreGranted" />
       <option name="compatibility:include-filter" value="CtsHealthConnectControllerTestCases" />
       <option name="compatibility:include-filter" value="HealthFitnessIntegrationTests" />
       <option name="compatibility:include-filter" value="CtsHealthFitnessDeviceTestCasesHistoricAccessLimitWithPermission"/>
@@ -23,6 +23,8 @@
       <option name="compatibility:include-filter" value="HealthFitnessIntegrationBackupRestoreTests"/>
       <option name="compatibility:include-filter" value="HealthFitnessIntegrationExportImportTests"/>
       <option name="compatibility:include-filter" value="CtsHealthConnectHostSideDeviceTestCases" />
+      <option name="compatibility:include-filter" value="CtsExerciseRouteTestCases" />
+      <option name="compatibility:include-filter" value="CtsHealthFitnessPhrTestCases" />
 
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCases:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCasesNoPermission:enable:true" />
@@ -35,5 +37,7 @@
       <option name="compatibility:module-arg" value="HealthFitnessIntegrationBackupRestoreTests:enable:true" />
       <option name="compatibility:module-arg" value="HealthFitnessIntegrationExportImportTests:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthConnectHostSideDeviceTestCases:enable:true" />
+      <option name="compatibility:module-arg" value="CtsExerciseRouteTestCases:enable:true" />
+      <option name="compatibility:module-arg" value="CtsHealthFitnessPhrTestCases:enable:true" />
 
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml b/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml
index 1e30087..e9774ed 100644
--- a/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml
@@ -16,7 +16,6 @@
       <option name="compatibility:include-filter" value="CtsHealthFitnessDeviceTestCasesNoPermission" />
       <option name="compatibility:include-filter" value="CtsHealthFitnessDeviceTestCasesNotAllPermissionsAreGranted" />
       <option name="compatibility:include-filter" value="HealthFitnessUnitTests" />
-      <option name="compatibility:include-filter" value="HealthConnectControllerUITests" />
       <option name="compatibility:include-filter" value="CtsHealthConnectControllerTestCases" />
       <option name="compatibility:include-filter" value="HealthFitnessIntegrationTests" />
       <option name="compatibility:include-filter" value="HealthConnectBackupRestoreUnitTests" />
@@ -26,12 +25,25 @@
       <option name="compatibility:include-filter" value="HealthFitnessIntegrationBackupRestoreTests"/>
       <option name="compatibility:include-filter" value="HealthFitnessIntegrationExportImportTests"/>
       <option name="compatibility:include-filter" value="CtsHealthConnectHostSideDeviceTestCases" />
+     <option name="compatibility:include-filter" value="CtsHealthConnectHostTestCases" />
+      <option name="compatibility:include-filter" value="CtsExerciseRouteTestCases" />
+      <option name="compatibility:include-filter" value="CtsHealthFitnessPhrTestCases" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerDataScreensNewTests" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerDataScreensOldTests" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerDeletionTests" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerExerciseRouteTests" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerExportTests" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerHomePageAndOnboardingTests" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerManageDataTests" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerMigrationTests" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerNavigationTests" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerPermissionTests" />
+      <option name="compatibility:include-filter" value="HealthConnectControllerExtraTests" />
 
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCases:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCasesNoPermission:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCasesNotAllPermissionsAreGranted:enable:true" />
       <option name="compatibility:module-arg" value="HealthFitnessUnitTests:enable:true" />
-      <option name="compatibility:module-arg" value="HealthConnectControllerUITests:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthConnectControllerTestCases:enable:true" />
       <option name="compatibility:module-arg" value="HealthFitnessIntegrationTests:enable:true" />
       <option name="compatibility:module-arg" value="HealthConnectBackupRestoreUnitTests:enable:true" />
@@ -41,5 +53,19 @@
       <option name="compatibility:module-arg" value="HealthFitnessIntegrationBackupRestoreTests:enable:true" />
       <option name="compatibility:module-arg" value="HealthFitnessIntegrationExportImportTests:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthConnectHostSideDeviceTestCases:enable:true" />
+      <option name="compatibility:module-arg" value="CtsHealthConnectHostTestCases:enable:true" />
+      <option name="compatibility:module-arg" value="CtsExerciseRouteTestCases:enable:true" />
+      <option name="compatibility:module-arg" value="CtsHealthFitnessPhrTestCases:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerDataScreensNewTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerDataScreensOldTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerDeletionTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerExerciseRouteTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerExportTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerHomePageAndOnboardingTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerManageDataTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerMigrationTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerNavigationTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerPermissionTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthConnectControllerExtraTests:enable:true" />
 
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-nfc-multi-devices.xml b/tools/mts-tradefed/res/config/mts-nfc-multi-devices.xml
new file mode 100644
index 0000000..43b5db9
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-nfc-multi-devices.xml
@@ -0,0 +1,13 @@
+<configuration description="Runs MTS-nfc-multi-devices from a pre-existing MTS installation">
+    <include name="mts-multi-device" />
+
+    <include name="mts-nfc-tests-list-multi-devices" />
+
+    <option name="plan" value="mts-nfc-multi-devices.xml" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+        <option name="property-name" value="ro.build.type" />
+        <option name="expected-value" value="userdebug"/> <!-- Device should have userdebug/eng build -->
+        <option name="throw-error" value="false"/> <!-- Only print warning if not user build -->
+    </target_preparer>
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-nfc-tests-list-eng-only.xml b/tools/mts-tradefed/res/config/mts-nfc-tests-list-eng-only.xml
new file mode 100644
index 0000000..65bdaed
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-nfc-tests-list-eng-only.xml
@@ -0,0 +1,23 @@
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
+
+<configuration description="List of NFC MTS tests that need root access.">
+    <option name="compatibility:include-filter" value="libnfc-nci-tests" />
+    <option name="compatibility:include-filter" value="libnfc-nci-jni-tests" />
+
+    <option name="compatibility:module-arg" value="libnfc-nci-tests:enable:true" />
+    <option name="compatibility:module-arg" value="libnfc-nci-jni-tests:enable:true" />
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-nfc-tests-list-multi-devices.xml b/tools/mts-tradefed/res/config/mts-nfc-tests-list-multi-devices.xml
new file mode 100644
index 0000000..42fe921
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-nfc-tests-list-multi-devices.xml
@@ -0,0 +1,2 @@
+<configuration description="List of NFC MTS tests that need multi devices.">
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-nfc-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-nfc-tests-list-user.xml
new file mode 100644
index 0000000..1fe2f7d
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-nfc-tests-list-user.xml
@@ -0,0 +1,27 @@
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
+
+<configuration description="List of NFC MTS tests that do not need root access.">
+    <option name="compatibility:include-filter" value="NfcNciUnitTests" />
+    <option name="compatibility:include-filter" value="NfcNciInstrumentationTests" />
+    <option name="compatibility:include-filter" value="CtsNfcTestCases" />
+    <option name="compatibility:include-filter" value="NfcTestCases" />
+
+    <option name="compatibility:module-arg" value="NfcNciUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="NfcNciInstrumentationTests:enable:true" />
+    <option name="compatibility:module-arg" value="CtsNfcTestCases:enable:true" />
+    <option name="compatibility:module-arg" value="NfcTestCases:enable:true" />
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-nfc.xml b/tools/mts-tradefed/res/config/mts-nfc.xml
new file mode 100644
index 0000000..750c879
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mts-nfc.xml
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
+<configuration description="Runs MTS-nfc from a pre-existing MTS installation">
+
+    <include name="mts" />
+
+    <include name="mts-nfc-tests-list-eng-only" />
+    <include name="mts-nfc-tests-list-user" />
+
+    <option name="plan" value="mts-nfc" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+	<option name="property-name" value="ro.build.type" />
+	<option name="expected-value" value="userdebug"/> <!-- Device should have userdebug/eng build -->
+	<option name="throw-error" value="false"/> <!-- Only print warning if not user build -->
+    </target_preparer>
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-tests-list-eng-only.xml b/tools/mts-tradefed/res/config/mts-tests-list-eng-only.xml
index 1b2d04f..34b9f7d 100644
--- a/tools/mts-tradefed/res/config/mts-tests-list-eng-only.xml
+++ b/tools/mts-tradefed/res/config/mts-tests-list-eng-only.xml
@@ -19,11 +19,13 @@
     <include name="mts-cellbroadcast-tests-list-eng-only" />
     <include name="mts-conscrypt-tests-list-eng-only" />
     <include name="mts-core-tests-list-eng-only" />
+    <!-- TODO: Enable when 25Q2 is next. include name="mts-crashrecovery-tests-list-eng-only" / -->
     <include name="mts-dnsresolver-tests-list-eng-only" />
     <include name="mts-documentsUI-usedapi-tests-list-eng-only" />
     <include name="mts-extservices-tests-list-eng-only" />
     <include name="mts-mediaprovider-tests-list-eng-only" />
     <include name="mts-network-tests-list-eng-only" />
+    <!-- TODO: Enable when 25Q2 is next. include name="mts-nfc-tests-list-eng-only" / -->
     <include name="mts-rkpd-tests-list-eng-only" />
     <include name="mts-statsd-tests-list-eng-only" />
     <include name="mts-tethering-tests-list-eng-only" />
diff --git a/tools/mts-tradefed/res/config/mts-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-tests-list-user.xml
index 7df7f4f..9fc5eef 100644
--- a/tools/mts-tradefed/res/config/mts-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-tests-list-user.xml
@@ -14,6 +14,7 @@
      limitations under the License.
 -->
 <configuration description="List all tests that do not need root access in active test plans.">
+    <include name="mts-adservices-tests-list" />
     <include name="mts-appsearch-tests-list" />
     <include name="mts-art-tests-list-user" />
     <include name="mts-art-extra-tests-list-user" />
@@ -22,16 +23,18 @@
     <include name="mts-conscrypt-tests-list-user" />
     <include name="mts-core-tests-list-user" />
     <include name="mts-dnsresolver-tests-list-user" />
+    <!-- TODO: Enable when 25Q2 is next. include name="mts-crashrecovery-tests-list-user" / -->
     <include name="mts-documentsUI-oem-tests-list" />
     <include name="mts-documentsUI-usedapi-tests-list" />
     <include name="mts-extservices-tests-list-user" />
     <include name="mts-healthfitness-tests-list" />
-    <include name="mts-linkerconfig-tests-list" />
     <include name="mts-ipsec-tests-list" />
     <include name="mts-media-tests-list" />
     <include name="mts-mediaprovider-tests-list-user" />
     <include name="mts-network-tests-list-user" />
     <include name="mts-neuralnetworks-tests-list" />
+    <!-- TODO: Enable when 25Q2 is next. include name="mts-nfc-tests-list-user" / -->
+    <include name="mts-ondevicepersonalization-tests-list" />
     <include name="mts-permission-tests-list-oem" />
     <include name="mts-preload-verify-tests-list" />
     <include name="mts-rkpd-tests-list-user" />
diff --git a/tools/mts-tradefed/res/config/mts-uwb-tests-list-eng-only.xml b/tools/mts-tradefed/res/config/mts-uwb-tests-list-eng-only.xml
index a720841..469d113 100644
--- a/tools/mts-tradefed/res/config/mts-uwb-tests-list-eng-only.xml
+++ b/tools/mts-tradefed/res/config/mts-uwb-tests-list-eng-only.xml
@@ -18,10 +18,8 @@
     <option name="compatibility:include-filter" value="libuwb_core_tests" />
     <option name="compatibility:include-filter" value="libuwb_uci_jni_rust_tests" />
     <option name="compatibility:include-filter" value="libuwb_uci_packet_tests" />
-    <option name="compatibility:include-filter" value="libuci_hal_android_tests" />
 
     <option name="compatibility:module-arg" value="libuwb_core_tests:enable:true" />
     <option name="compatibility:module-arg" value="libuwb_uci_jni_rust_tests:enable:true" />
     <option name="compatibility:module-arg" value="libuwb_uci_packet_tests:enable:true" />
-    <option name="compatibility:module-arg" value="libuci_hal_android_tests:enable:true" />
 </configuration>
```

