```diff
diff --git a/tools/build/config.mk b/tools/build/config.mk
index e9bdd6c..60001fd 100644
--- a/tools/build/config.mk
+++ b/tools/build/config.mk
@@ -15,7 +15,7 @@
 
 COMPATIBILITY_TESTCASES_OUT_mts := $(HOST_OUT)/mts/android-mts/testcases
 COMPATIBILITY_TESTCASES_OUT_INCLUDE_MODULE_FOLDER_mts := true
-COMPATIBILITY_TESTCASES_OUT_mcts := $(HOST_OUT)/mcts/android-mts/testcases
+COMPATIBILITY_TESTCASES_OUT_mcts := $(HOST_OUT)/mcts/android-mcts/testcases
 COMPATIBILITY_TESTCASES_OUT_INCLUDE_MODULE_FOLDER_mcts := true
 
 # A list of MCTS modules that should not be removed from CTS
@@ -47,6 +47,7 @@ mts_modules += \
                neuralnetworks \
                ondevicepersonalization \
                permission \
+               profiling \
                rkpd \
                scheduling \
                sdkextensions \
diff --git a/tools/mts-tradefed/Android.bp b/tools/mts-tradefed/Android.bp
index 1eeebda..b9aa95c 100644
--- a/tools/mts-tradefed/Android.bp
+++ b/tools/mts-tradefed/Android.bp
@@ -22,7 +22,17 @@ tradefed_binary_host {
     wrapper: "etc/mts-tradefed",
     short_name: "MTS",
     full_name: "Mainline Test Suite",
-    version: "4.0",
+    version: "6.0",
+    static_libs: ["cts-tradefed-harness"],
+    java_resource_dirs: ["res"],
+}
+
+tradefed_binary_host {
+    name: "mcts-tradefed",
+    wrapper: "etc/mcts-tradefed",
+    short_name: "MCTS",
+    full_name: "Mainline CTS",
+    version: "6.0",
     static_libs: ["cts-tradefed-harness"],
     java_resource_dirs: ["res"],
 }
diff --git a/tools/mts-tradefed/etc/mcts-tradefed b/tools/mts-tradefed/etc/mcts-tradefed
new file mode 100644
index 0000000..50fb2cf
--- /dev/null
+++ b/tools/mts-tradefed/etc/mcts-tradefed
@@ -0,0 +1,105 @@
+#!/bin/bash
+
+# Copyright (C) 2024 The Android Open Source Project.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#       http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# launcher script for mcts-tradefed harness
+# can be used from an Android build environment, or a standalone mcts zip
+
+UTILS_SCRIPT="$(dirname $(realpath $0))/test-utils-script"
+
+if [ ! -f "${UTILS_SCRIPT}" ]
+then
+  UTILS_SCRIPT="${ANDROID_BUILD_TOP}/platform_testing/scripts/test-utils-script"
+fi
+
+if [ ! -f "${UTILS_SCRIPT}" ]
+then
+  echo -e "Cannot find test-utils-script in the same location as this script and ANDROID_BUILD_TOP is not defined."
+  exit 1
+fi
+
+source ${UTILS_SCRIPT}
+
+checkPath adb
+checkPath java
+checkJavaVersion java
+
+RDBG_FLAG=$(getRemoteDbgFlag)
+
+# get OS
+HOST=`uname`
+if [ "$HOST" == "Linux" ]; then
+    OS="linux-x86"
+elif [ "$HOST" == "Darwin" ]; then
+    OS="darwin-x86"
+else
+    echo "Unrecognized OS"
+    exit
+fi
+
+# check if in Android build env
+if [ ! -z "${ANDROID_BUILD_TOP}" ]; then
+    if [ ! -z "${ANDROID_HOST_OUT}" ]; then
+      MCTS_ROOT=${ANDROID_HOST_OUT}/mcts
+    else
+      MCTS_ROOT=${ANDROID_BUILD_TOP}/${OUT_DIR:-out}/host/${OS}/mcts
+    fi
+    if [ ! -d ${MCTS_ROOT} ]; then
+        echo "Could not find $MCTS_ROOT in Android build environment. Try 'make mcts'"
+        exit
+    fi;
+fi;
+
+if [ -z ${MCTS_ROOT} ]; then
+    # assume we're in an extracted mcts install
+    MCTS_ROOT="$(dirname $0)/../.."
+fi;
+
+JAR_DIR=${MCTS_ROOT}/android-mcts/tools
+
+for JAR in ${JAR_DIR}/*.jar; do
+    JAR_PATH=${JAR_PATH}:${JAR}
+done
+
+# check if APE_API_KEY is set in the env by user.
+if [ ! -n "${APE_API_KEY}" ]; then
+    GTS_GOOGLE_SERVICE_ACCOUNT=${ANDROID_BUILD_TOP}/vendor/xts/tools/gts-google-service-account/gts-google-service-account.json
+    # set KEY only for google if APE_API_KEY isn't set and GTS_GOOGLE_SERVICE_ACCOUNT exists in the soure tree.
+    if [ -f "$GTS_GOOGLE_SERVICE_ACCOUNT" ]; then
+        APE_API_KEY=${GTS_GOOGLE_SERVICE_ACCOUNT}
+        export APE_API_KEY
+    else
+        echo "APE_API_KEY not set, GTS tests may fail without authentication."
+    fi;
+fi;
+echo "APE_API_KEY: $APE_API_KEY"
+
+LIB_DIR=${MCTS_ROOT}/android-mcts/lib
+loadSharedLibraries "$HOST" "$LIB_DIR"
+
+# include any host-side test jars
+for j in $(find ${MCTS_ROOT}/android-mcts/testcases -name '*.jar'); do
+    case "$j" in
+      *testcases/art*)
+        /bin/true
+        ;;
+      *)
+        JAR_PATH=${JAR_PATH}:$j
+        ;;
+    esac
+done
+
+echo "java $RDBG_FLAG -cp ${JAR_PATH} -DMCTS_ROOT=${MCTS_ROOT} com.android.compatibility.common.tradefed.command.CompatibilityConsole "$@""
+java $RDBG_FLAG -cp ${JAR_PATH} -DMCTS_ROOT=${MCTS_ROOT} com.android.compatibility.common.tradefed.command.CompatibilityConsole "$@"
diff --git a/tools/mts-tradefed/res/config/mcts-all.xml b/tools/mts-tradefed/res/config/mcts-all.xml
new file mode 100644
index 0000000..8264dbd
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mcts-all.xml
@@ -0,0 +1,64 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project.
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
+<configuration description="Runs all the tests in MCTS">
+
+    <include name="everything" />
+    <option name="plan" value="mcts-all" />
+    <option name="test-tag" value="mcts" />
+
+    <include name="mcts-preconditions" />
+
+    <include name="cts-system-checkers" />
+    <include name="cts-exclude" />
+    <include name="cts-exclude-instant" />
+    <include name="cts-known-failures" />
+    <include name="mcts-exclude" />
+
+    <!-- Enable module parameterization to run instant_app modules in main MCTS -->
+    <option name="compatibility:enable-parameterized-modules" value="true" />
+
+    <option name="enable-root" value="false" />
+    <!-- retain 200MB of host log -->
+    <option name="max-log-size" value="200" />
+    <!--  retain 200MB of logcat -->
+    <option name="max-tmp-logcat-file" value="209715200" />
+
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="settings put global package_verifier_enable 0" />
+        <option name="teardown-command" value="settings put global package_verifier_enable 1"/>
+    </target_preparer>
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+        <option name="property-name" value="ro.build.type" />
+        <option name="expected-value" value="user"/> <!-- Device should have user build -->
+        <option name="throw-error" value="false"/> <!-- Only print warning if not user build -->
+    </target_preparer>
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+        <option name="property-name" value="ro.product.locale" />
+        <option name="expected-value" value="en-US"/> <!-- Device locale should be US English -->
+        <option name="throw-error" value="false"/> <!-- Only print warning if not en-US -->
+    </target_preparer>
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.PropertyCheck">
+        <option name="property-name" value="persist.sys.test_harness" />
+        <option name="expected-value" value="false"/> <!-- Device shouldn't be in test harness mode -->
+        <option name="throw-error" value="true"/>
+    </target_preparer>
+
+    <template-include name="reporters" default="basic-reporters" />
+
+</configuration>
\ No newline at end of file
diff --git a/tools/mts-tradefed/res/config/mcts-collect-tests-only.xml b/tools/mts-tradefed/res/config/mcts-collect-tests-only.xml
index a7a8e23..ab54120 100644
--- a/tools/mts-tradefed/res/config/mcts-collect-tests-only.xml
+++ b/tools/mts-tradefed/res/config/mcts-collect-tests-only.xml
@@ -17,7 +17,7 @@
 
 <option name="plan" value="mcts-collect-tests-only" />
 
-<include name="mcts" />
+<include name="mcts-all" />
 
 <option name="compatibility:collect-tests-only" value="true" />
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mcts-preconditions.xml b/tools/mts-tradefed/res/config/mcts-preconditions.xml
new file mode 100644
index 0000000..8005edd
--- /dev/null
+++ b/tools/mts-tradefed/res/config/mcts-preconditions.xml
@@ -0,0 +1,53 @@
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
+<configuration description="MCTS precondition configs">
+
+    <option name="plan" value="mcts-preconditions" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.DynamicConfigPusher">
+        <option name="target" value="host" />
+        <!-- the name under which to find the configuration -->
+        <option name="config-filename" value="mcts"/>
+        <option name="extract-from-resource" value="true" />
+        <!-- the name of the resource inside the jar -->
+        <option name="dynamic-resource-name" value="mcts-tradefed" />
+    </target_preparer>
+
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.StayAwakePreparer" />
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.SettingsPreparer">
+        <option name="device-setting" value="verifier_verify_adb_installs"/>
+        <option name="setting-type" value="global"/>
+        <option name="set-value" value="0"/>
+    </target_preparer>
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.WifiCheck" />
+
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="rm -rf /sdcard/device-info-files" />
+        <option name="run-command" value="rm -rf /sdcard/report-log-files" />
+    </target_preparer>
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.DeviceInfoCollector">
+        <option name="apk" value="CtsDeviceInfo.apk"/>
+        <option name="package" value="com.android.compatibility.common.deviceinfo"/>
+        <option name="src-dir" value="/sdcard/device-info-files/"/>
+        <option name="dest-dir" value="device-info-files/"/>
+        <option name="temp-dir" value="temp-device-info-files/"/>
+        <option name="throw-error" value="false"/>
+    </target_preparer>
+</configuration>
diff --git a/tools/mts-tradefed/res/config/mts-adservices-tests-list.xml b/tools/mts-tradefed/res/config/mts-adservices-tests-list.xml
index 9b549a9..dbe8816 100644
--- a/tools/mts-tradefed/res/config/mts-adservices-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-adservices-tests-list.xml
@@ -27,7 +27,9 @@
     <option name="compatibility:include-filter" value="AdServicesServiceCoreCommonUnitTests" />
     <option name="compatibility:include-filter" value="AdServicesServiceCoreUnitTests" />
     <option name="compatibility:include-filter" value="AdServicesServiceCoreMeasurementUnitTests" />
+    <option name="compatibility:include-filter" value="AdServicesServiceCoreProtectedAudienceUnitTests" />
     <option name="compatibility:include-filter" value="AdServicesServiceCoreTopicsUnitTests" />
+    <option name="compatibility:include-filter" value="AdServicesSharedLibrariesUnitTests" />
     <option name="compatibility:include-filter" value="AdServicesUIUnitTests" />
     <option name="compatibility:include-filter" value="CtsAdIdEndToEndTest" />
     <option name="compatibility:include-filter" value="CtsAdServicesCobaltTest" />
@@ -75,6 +77,7 @@
     <option name="compatibility:module-arg" value="AdServicesServiceCoreCommonUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesServiceCoreUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesServiceCoreMeasurementUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdServicesServiceCoreProtectedAudienceUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesServiceCoreTopicsUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesSharedLibrariesUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesUIUnitTests:enable:true" />
@@ -102,6 +105,7 @@
     <option name="compatibility:module-arg" value="CtsSandboxedTopicsManagerTests:enable:true" />
 
     <option name="compatibility:module-arg" value="SdkSandboxManagerTests:enable:true" />
+    <option name="compatibility:module-arg" value="SdkSandboxManagerDisabledTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsSdkSandboxHostSideTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsSdkSandboxInprocessTests:enable:true" />
     <option name="compatibility:module-arg" value="SdkSandboxManagerServiceUnitTests:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-adservices-unittest-only-tests-list.xml b/tools/mts-tradefed/res/config/mts-adservices-unittest-only-tests-list.xml
index ecd2060..54775d0 100644
--- a/tools/mts-tradefed/res/config/mts-adservices-unittest-only-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-adservices-unittest-only-tests-list.xml
@@ -11,24 +11,22 @@
      limitations under the License.
 -->
 <configuration description="List test modules of AdServices module. This is a placeholder xml instead of a runnable plan.">
-    <option name="compatibility:include-filter"
-            value="AdServicesFrameworkUnitTests" />
-    <option name="compatibility:include-filter"
-            value="AdServicesServiceCoreUnitTests" />
-    <option name="compatibility:include-filter"
-            value="AdServicesApkUnitTests" />
-    <option name="compatibility:include-filter"
-            value="AdServicesApkUITests" />
-    <option name="compatibility:include-filter"
-            value="SdkSandboxManagerServiceUnitTests" />
-    <option name="compatibility:include-filter"
-            value="SdkSandboxUnitTests" />
-    <option name="compatibility:include-filter"
-            value="SdkSandboxFrameworkUnitTests" />
+    <option name="compatibility:include-filter" value="AdServicesFrameworkUnitTests" />
+    <option name="compatibility:include-filter" value="AdServicesServiceCoreUnitTests" />
+    <option name="compatibility:include-filter" value="AdServicesServiceCoreMeasurementUnitTests" />
+    <option name="compatibility:include-filter" value="AdServicesServiceCoreProtectedAudienceUnitTests" />
+    <option name="compatibility:include-filter" value="AdServicesServiceCoreTopicsUnitTests" />
+    <option name="compatibility:include-filter" value="AdServicesApkUnitTests" />
+    <option name="compatibility:include-filter" value="SdkSandboxManagerServiceUnitTests" />
+    <option name="compatibility:include-filter" value="SdkSandboxUnitTests" />
+    <option name="compatibility:include-filter" value="SdkSandboxFrameworkUnitTests" />
+
     <option name="compatibility:module-arg" value="AdServicesFrameworkUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesServiceCoreUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdServicesServiceCoreMeasurementUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdServicesServiceCoreProtectedAudienceUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdServicesServiceCoreTopicsUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdServicesApkUnitTests:enable:true" />
-    <option name="compatibility:module-arg" value="AdServicesApkUITests:enable:true" />
     <option name="compatibility:module-arg" value="SdkSandboxManagerServiceUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="SdkSandboxUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="SdkSandboxFrameworkUnitTests:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-appsearch-tests-list.xml b/tools/mts-tradefed/res/config/mts-appsearch-tests-list.xml
index 16b50ef..c13f737 100644
--- a/tools/mts-tradefed/res/config/mts-appsearch-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-appsearch-tests-list.xml
@@ -19,6 +19,7 @@
     <option name="compatibility:include-filter" value="AppSearchCoreTests" />
     <option name="compatibility:include-filter" value="AppSearchServicesTests" />
     <option name="compatibility:include-filter" value="AppSearchMockingServicesTests" />
+    <option name="compatibility:include-filter" value="AppsIndexerTests" />
     <option name="compatibility:include-filter" value="ContactsIndexerTests" />
     <option name="compatibility:include-filter" value="CtsAppSearchTestCases" />
     <option name="compatibility:include-filter" value="CtsAppSearchHostTestCases" />
@@ -26,6 +27,7 @@
     <option name="compatibility:module-arg" value="AppSearchCoreTests:enable:true" />
     <option name="compatibility:module-arg" value="AppSearchServicesTests:enable:true" />
     <option name="compatibility:module-arg" value="AppSearchMockingServicesTests:enable:true" />
+    <option name="compatibility:module-arg" value="AppsIndexerTests:enable:true" />
     <option name="compatibility:module-arg" value="ContactsIndexerTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsAppSearchTestCases:enable:true" />
     <option name="compatibility:module-arg" value="CtsAppSearchHostTestCases:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-art-shard-03.xml b/tools/mts-tradefed/res/config/mts-art-shard-03.xml
index d36225d..fc06f06 100644
--- a/tools/mts-tradefed/res/config/mts-art-shard-03.xml
+++ b/tools/mts-tradefed/res/config/mts-art-shard-03.xml
@@ -17,5 +17,6 @@
 <configuration description="Run mts-art-shard-03 from a preexisting MTS installation.">
     <include name="mts"/>
     <include name="mts-art-tests-list-user-shard-03"/>
+    <include name="mts-art-tests-list-eng-only"/>
     <option name="plan" value="mts-art-shard-03"/>
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-art-tests-list-eng-only.xml b/tools/mts-tradefed/res/config/mts-art-tests-list-eng-only.xml
index 96ded34..9df816b 100644
--- a/tools/mts-tradefed/res/config/mts-art-tests-list-eng-only.xml
+++ b/tools/mts-tradefed/res/config/mts-art-tests-list-eng-only.xml
@@ -1,4 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
+<!-- Generated by `regen-test-files`. Do not edit manually. -->
 <!-- Copyright (C) 2020 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
@@ -15,9 +16,13 @@
 -->
 <configuration description="List of ART MTS tests that need root access.">
     <!-- ART gtests. -->
-    <option name="compatibility:include-filter" value="art_standalone_dexopt_chroot_setup_tests" />
-    <option name="compatibility:include-filter" value="libnativeloader_e2e_tests" />
-    <!-- Enable MainlineTestModuleController. -->
-    <option name="compatibility:module-arg" value="art_standalone_dexopt_chroot_setup_tests:enable:true" />
-    <option name="compatibility:module-arg" value="libnativeloader_e2e_tests:enable:true" />
+    <option name="compatibility:include-filter" value="art_standalone_dexopt_chroot_setup_tests"/>
+    <option name="compatibility:include-filter" value="art_standalone_dexoptanalyzer_tests"/>
+    <option name="compatibility:include-filter" value="art_standalone_profman_tests"/>
+    <option name="compatibility:include-filter" value="libnativeloader_e2e_tests"/>
+    <!-- Enable MainlineTestModuleController for ART gtests. -->
+    <option name="compatibility:module-arg" value="art_standalone_dexopt_chroot_setup_tests:enable:true"/>
+    <option name="compatibility:module-arg" value="art_standalone_dexoptanalyzer_tests:enable:true"/>
+    <option name="compatibility:module-arg" value="art_standalone_profman_tests:enable:true"/>
+    <option name="compatibility:module-arg" value="libnativeloader_e2e_tests:enable:true"/>
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml
index 27e69fa..54d659e 100644
--- a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml
+++ b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-00.xml
@@ -27,6 +27,7 @@
     <option name="compatibility:include-filter" value="art-run-test-009-instanceof"/>
     <option name="compatibility:include-filter" value="art-run-test-010-instance"/>
     <option name="compatibility:include-filter" value="art-run-test-011-array-copy"/>
+    <option name="compatibility:include-filter" value="art-run-test-011-array-copy2"/>
     <option name="compatibility:include-filter" value="art-run-test-012-math"/>
     <option name="compatibility:include-filter" value="art-run-test-013-math2"/>
     <option name="compatibility:include-filter" value="art-run-test-014-math3"/>
@@ -63,6 +64,7 @@
     <option name="compatibility:include-filter" value="art-run-test-052-verifier-fun"/>
     <option name="compatibility:include-filter" value="art-run-test-053-wait-some"/>
     <option name="compatibility:include-filter" value="art-run-test-055-enum-performance"/>
+    <option name="compatibility:include-filter" value="art-run-test-057-math-intrinsics"/>
     <option name="compatibility:include-filter" value="art-run-test-058-enum-order"/>
     <option name="compatibility:include-filter" value="art-run-test-059-finalizer-throw"/>
     <option name="compatibility:include-filter" value="art-run-test-061-out-of-memory"/>
@@ -184,8 +186,14 @@
     <option name="compatibility:include-filter" value="art-run-test-2265-checker-select-binary-unary"/>
     <option name="compatibility:include-filter" value="art-run-test-2266-checker-remove-empty-ifs"/>
     <option name="compatibility:include-filter" value="art-run-test-2268-checker-remove-dead-phis"/>
-    <option name="compatibility:include-filter" value="art-run-test-2269-checker-constant-folding-instrinsics"/>
+    <option name="compatibility:include-filter" value="art-run-test-2269-checker-constant-folding-intrinsics"/>
     <option name="compatibility:include-filter" value="art-run-test-2273-checker-unreachable-intrinsics"/>
+    <option name="compatibility:include-filter" value="art-run-test-2274-checker-bitwise-gvn"/>
+    <option name="compatibility:include-filter" value="art-run-test-2275-checker-empty-loops"/>
+    <option name="compatibility:include-filter" value="art-run-test-2275-integral-unsigned-arithmetic"/>
+    <option name="compatibility:include-filter" value="art-run-test-2278-nested-loops"/>
+    <option name="compatibility:include-filter" value="art-run-test-2279-aconfig-flags"/>
+    <option name="compatibility:include-filter" value="art-run-test-2279-second-inner-loop-references-first"/>
     <option name="compatibility:include-filter" value="art-run-test-300-package-override"/>
     <option name="compatibility:include-filter" value="art-run-test-301-abstract-protected"/>
     <option name="compatibility:include-filter" value="art-run-test-302-float-conversion"/>
@@ -242,6 +250,7 @@
     <option name="compatibility:include-filter" value="art-run-test-451-spill-splot"/>
     <option name="compatibility:include-filter" value="art-run-test-455-checker-gvn"/>
     <option name="compatibility:include-filter" value="art-run-test-456-baseline-array-set"/>
+    <option name="compatibility:include-filter" value="art-run-test-458-checker-riscv64-shift-add"/>
     <option name="compatibility:include-filter" value="art-run-test-458-long-to-fpu"/>
     <option name="compatibility:include-filter" value="art-run-test-464-checker-inline-sharpen-calls"/>
     <option name="compatibility:include-filter" value="art-run-test-465-checker-clinit-gvn"/>
@@ -466,6 +475,8 @@
     <option name="compatibility:include-filter" value="art-run-test-843-default-interface"/>
     <option name="compatibility:include-filter" value="art-run-test-851-null-instanceof"/>
     <option name="compatibility:include-filter" value="art-run-test-853-checker-inlining"/>
+    <option name="compatibility:include-filter" value="art-run-test-856-clone"/>
+    <option name="compatibility:include-filter" value="art-run-test-857-default-access"/>
     <option name="compatibility:include-filter" value="art-run-test-963-default-range-smali"/>
     <option name="compatibility:include-filter" value="art-run-test-965-default-verify"/>
     <option name="compatibility:include-filter" value="art-run-test-967-default-ame"/>
@@ -481,6 +492,7 @@
     <option name="compatibility:module-arg" value="art-run-test-009-instanceof:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-010-instance:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-011-array-copy:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-011-array-copy2:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-012-math:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-013-math2:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-014-math3:enable:true"/>
@@ -517,6 +529,7 @@
     <option name="compatibility:module-arg" value="art-run-test-052-verifier-fun:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-053-wait-some:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-055-enum-performance:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-057-math-intrinsics:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-058-enum-order:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-059-finalizer-throw:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-061-out-of-memory:enable:true"/>
@@ -638,8 +651,14 @@
     <option name="compatibility:module-arg" value="art-run-test-2265-checker-select-binary-unary:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-2266-checker-remove-empty-ifs:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-2268-checker-remove-dead-phis:enable:true"/>
-    <option name="compatibility:module-arg" value="art-run-test-2269-checker-constant-folding-instrinsics:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-2269-checker-constant-folding-intrinsics:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-2273-checker-unreachable-intrinsics:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-2274-checker-bitwise-gvn:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-2275-checker-empty-loops:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-2275-integral-unsigned-arithmetic:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-2278-nested-loops:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-2279-aconfig-flags:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-2279-second-inner-loop-references-first:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-300-package-override:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-301-abstract-protected:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-302-float-conversion:enable:true"/>
@@ -696,6 +715,7 @@
     <option name="compatibility:module-arg" value="art-run-test-451-spill-splot:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-455-checker-gvn:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-456-baseline-array-set:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-458-checker-riscv64-shift-add:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-458-long-to-fpu:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-464-checker-inline-sharpen-calls:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-465-checker-clinit-gvn:enable:true"/>
@@ -920,6 +940,8 @@
     <option name="compatibility:module-arg" value="art-run-test-843-default-interface:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-851-null-instanceof:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-853-checker-inlining:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-856-clone:enable:true"/>
+    <option name="compatibility:module-arg" value="art-run-test-857-default-access:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-963-default-range-smali:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-965-default-verify:enable:true"/>
     <option name="compatibility:module-arg" value="art-run-test-967-default-ame:enable:true"/>
diff --git a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-02.xml b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-02.xml
index ad04c6a..6045d4e 100644
--- a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-02.xml
+++ b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-02.xml
@@ -15,7 +15,128 @@
      limitations under the License.
 -->
 <configuration description="List of ART MTS tests that do not need root access (shard 02)">
-    <!-- CTS Libcore OJ tests. -->
+    <!-- Other CTS tests. -->
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1900HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1901HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1902HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1903HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1904HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1906HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1907HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1908HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1909HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1910HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1911HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1912HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1913HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1914HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1915HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1916HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1917HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1920HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1921HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1922HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1923HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1924HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1925HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1926HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1927HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1928HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1930HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1931HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1932HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1933HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1934HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1936HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1937HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1939HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1940HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1941HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1942HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1943HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1953HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1958HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1962HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1967HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1968HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1969HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1970HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1971HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1974HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1975HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1976HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1977HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1978HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1979HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1981HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1982HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1983HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1984HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1988HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1989HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1990HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1991HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1992HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1994HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1995HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1996HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1997HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1998HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest1999HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest2001HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest2002HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest2003HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest2004HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest2005HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest2006HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest2007HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest902HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest903HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest904HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest905HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest906HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest907HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest908HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest910HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest911HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest912HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest913HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest914HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest915HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest917HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest918HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest919HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest920HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest922HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest923HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest924HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest926HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest927HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest928HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest930HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest931HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest932HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest940HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest942HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest944HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest945HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest947HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest951HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest982HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest983HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest984HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest985HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest986HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest988HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest989HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest990HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest991HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest992HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest993HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest994HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest995HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest996HostTestCases"/>
+    <option name="compatibility:include-filter" value="CtsJvmtiRunTest997HostTestCases"/>
     <option name="compatibility:include-filter" value="CtsLibcoreApiEvolutionTestCases"/>
     <option name="compatibility:include-filter" value="CtsLibcoreFileIOTestCases"/>
     <option name="compatibility:include-filter" value="CtsLibcoreJsr166TestCases"/>
@@ -24,7 +145,128 @@
     <option name="compatibility:include-filter" value="CtsLibcoreWycheproofBCTestCases"/>
     <option name="compatibility:include-filter" value="MtsLibcoreOkHttpTestCases"/>
     <option name="compatibility:include-filter" value="MtsLibcoreBouncyCastleTestCases"/>
-    <!-- Enable MainlineTestModuleController for CTS Libcore OJ tests. -->
+    <!-- Enable MainlineTestModuleController for Other CTS tests. -->
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1900HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1901HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1902HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1903HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1904HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1906HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1907HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1908HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1909HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1910HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1911HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1912HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1913HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1914HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1915HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1916HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1917HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1920HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1921HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1922HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1923HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1924HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1925HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1926HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1927HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1928HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1930HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1931HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1932HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1933HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1934HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1936HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1937HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1939HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1940HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1941HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1942HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1943HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1953HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1958HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1962HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1967HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1968HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1969HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1970HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1971HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1974HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1975HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1976HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1977HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1978HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1979HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1981HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1982HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1983HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1984HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1988HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1989HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1990HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1991HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1992HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1994HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1995HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1996HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1997HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1998HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest1999HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest2001HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest2002HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest2003HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest2004HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest2005HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest2006HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest2007HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest902HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest903HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest904HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest905HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest906HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest907HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest908HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest910HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest911HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest912HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest913HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest914HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest915HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest917HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest918HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest919HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest920HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest922HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest923HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest924HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest926HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest927HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest928HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest930HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest931HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest932HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest940HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest942HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest944HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest945HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest947HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest951HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest982HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest983HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest984HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest985HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest986HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest988HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest989HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest990HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest991HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest992HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest993HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest994HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest995HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest996HostTestCases:enable:true"/>
+    <option name="compatibility:module-arg" value="CtsJvmtiRunTest997HostTestCases:enable:true"/>
     <option name="compatibility:module-arg" value="CtsLibcoreApiEvolutionTestCases:enable:true"/>
     <option name="compatibility:module-arg" value="CtsLibcoreFileIOTestCases:enable:true"/>
     <option name="compatibility:module-arg" value="CtsLibcoreJsr166TestCases:enable:true"/>
diff --git a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml
index 7a7ce4f..f90bc9a 100644
--- a/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml
+++ b/tools/mts-tradefed/res/config/mts-art-tests-list-user-shard-03.xml
@@ -20,6 +20,7 @@
     <option name="compatibility:include-filter" value="art_standalone_artd_tests"/>
     <option name="compatibility:include-filter" value="art_standalone_cmdline_tests"/>
     <option name="compatibility:include-filter" value="art_standalone_compiler_tests"/>
+    <option name="compatibility:include-filter" value="art_standalone_dex2oat_cts_tests"/>
     <option name="compatibility:include-filter" value="art_standalone_dex2oat_tests"/>
     <option name="compatibility:include-filter" value="art_standalone_dexdump_tests"/>
     <option name="compatibility:include-filter" value="art_standalone_dexlist_tests"/>
@@ -40,6 +41,7 @@
     <option name="compatibility:module-arg" value="art_standalone_artd_tests:enable:true"/>
     <option name="compatibility:module-arg" value="art_standalone_cmdline_tests:enable:true"/>
     <option name="compatibility:module-arg" value="art_standalone_compiler_tests:enable:true"/>
+    <option name="compatibility:module-arg" value="art_standalone_dex2oat_cts_tests:enable:true"/>
     <option name="compatibility:module-arg" value="art_standalone_dex2oat_tests:enable:true"/>
     <option name="compatibility:module-arg" value="art_standalone_dexdump_tests:enable:true"/>
     <option name="compatibility:module-arg" value="art_standalone_dexlist_tests:enable:true"/>
diff --git a/tools/mts-tradefed/res/config/mts-configinfrastructure-tests-list.xml b/tools/mts-tradefed/res/config/mts-configinfrastructure-tests-list.xml
index 58aeb5b..97f60e1 100644
--- a/tools/mts-tradefed/res/config/mts-configinfrastructure-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-configinfrastructure-tests-list.xml
@@ -15,8 +15,9 @@
 -->
 <configuration description="List MTS configinfrastructure tests.">
     <option name="compatibility:include-filter" value="CtsDeviceConfigTestCases" />
-
     <option name="compatibility:include-filter" value="ConfigInfrastructureServiceUnitTests" />
+
     <!-- Enable MainlineTestModuleController. -->
     <option name="compatibility:module-arg" value="CtsDeviceConfigTestCases:enable:true" />
+    <option name="compatibility:module-arg" value="ConfigInfrastructureServiceUnitTests:enable:true" />
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-documentsUI-usedapi-tests-list.xml b/tools/mts-tradefed/res/config/mts-documentsUI-usedapi-tests-list.xml
index 492f3d3..51842f6 100644
--- a/tools/mts-tradefed/res/config/mts-documentsUI-usedapi-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-documentsUI-usedapi-tests-list.xml
@@ -14,8 +14,8 @@
      limitations under the License.
 -->
 <configuration description="List MTS api tests used by documentsUI.">
-    <option name="compatibility:include-filter" value="CtsContentTestCases android.content.cts.ContextTest#testCreatePackageContextAsUser" />
-    <option name="compatibility:include-filter" value="CtsContentTestCases android.content.cts.ContextTest#testStartActivityAsUser" />
+    <option name="compatibility:include-filter" value="CtsDocumentContentTestCases android.content.cts.DocumentsUIUsedContentApiTest#testCreatePackageContextAsUser" />
+    <option name="compatibility:include-filter" value="CtsDocumentContentTestCases android.content.cts.DocumentsUIUsedContentApiTest#testStartActivityAsUser" />
     <option name="compatibility:include-filter" value="CtsProviderTestCases android.provider.cts.DocumentsContractTest#testGetDocumentThumbnail" />
     <option name="compatibility:include-filter" value="CtsProviderTestCases android.provider.cts.DocumentsContractTest#testManageMode" />
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-exclude.xml b/tools/mts-tradefed/res/config/mts-exclude.xml
index e98c33d..cad0156 100644
--- a/tools/mts-tradefed/res/config/mts-exclude.xml
+++ b/tools/mts-tradefed/res/config/mts-exclude.xml
@@ -193,9 +193,6 @@
     <option name="compatibility:exclude-filter" value="DocumentsUIGoogleTests com.android.documentsui.files.ActionHandlerTest#testDocumentPicked_Recent_ManagesApks" />
     <option name="compatibility:exclude-filter" value="DocumentsUIGoogleTests com.android.documentsui.RecentsLoaderTests#testContentsUpdate_observable" />
 
-    <!-- b/144850069: MTS flaky test -->
-    <option name="compatibility:exclude-filter" value="MctsMediaStressTestCases android.mediastress.cts.H264R1080pAacLongPlayerTest#testPlay00" />
-
     <!-- b/144590142: MTS flaky test -->
     <option name="compatibility:exclude-filter" value="MctsMediaDecoderTestCases android.media.decoder.cts.DecoderTest#testVP8Decode640x360" />
 
diff --git a/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml
index e442d92..4e65fb0 100644
--- a/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-extservices-tests-list-user.xml
@@ -57,6 +57,7 @@
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreAppsetIdUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreCommonUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreMeasurementUnitTests" />
+    <option name="compatibility:include-filter" value="AdExtServicesServiceCoreProtectedAudienceUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreTopicsUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesServiceCoreUnitTests" />
     <option name="compatibility:include-filter" value="AdExtServicesUIUnitTests" />
@@ -108,6 +109,7 @@
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreAppsetIdUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreCommonUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreMeasurementUnitTests:enable:true" />
+    <option name="compatibility:module-arg" value="AdExtServicesServiceCoreProtectedAudienceUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreTopicsUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesServiceCoreUnitTests:enable:true" />
     <option name="compatibility:module-arg" value="AdExtServicesUIUnitTests:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-healthfitness-no-unittests-tests-list.xml b/tools/mts-tradefed/res/config/mts-healthfitness-no-unittests-tests-list.xml
index 83a865a..94759bb 100644
--- a/tools/mts-tradefed/res/config/mts-healthfitness-no-unittests-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-healthfitness-no-unittests-tests-list.xml
@@ -21,6 +21,8 @@
       <option name="compatibility:include-filter" value="CtsHealthFitnessDeviceTestCasesRateLimiter"/>
       <option name="compatibility:include-filter" value="CtsHealthFitnessShowMigrationInfoIntentAbsentTests"/>
       <option name="compatibility:include-filter" value="HealthFitnessIntegrationBackupRestoreTests"/>
+      <option name="compatibility:include-filter" value="HealthFitnessIntegrationExportImportTests"/>
+      <option name="compatibility:include-filter" value="CtsHealthConnectHostSideDeviceTestCases" />
 
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCases:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCasesNoPermission:enable:true" />
@@ -31,5 +33,7 @@
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCasesRateLimiter:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthFitnessShowMigrationInfoIntentAbsentTests:enable:true" />
       <option name="compatibility:module-arg" value="HealthFitnessIntegrationBackupRestoreTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthFitnessIntegrationExportImportTests:enable:true" />
+      <option name="compatibility:module-arg" value="CtsHealthConnectHostSideDeviceTestCases:enable:true" />
 
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml b/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml
index 5161468..1e30087 100644
--- a/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-healthfitness-tests-list.xml
@@ -24,6 +24,8 @@
       <option name="compatibility:include-filter" value="CtsHealthFitnessDeviceTestCasesRateLimiter"/>
       <option name="compatibility:include-filter" value="CtsHealthFitnessShowMigrationInfoIntentAbsentTests"/>
       <option name="compatibility:include-filter" value="HealthFitnessIntegrationBackupRestoreTests"/>
+      <option name="compatibility:include-filter" value="HealthFitnessIntegrationExportImportTests"/>
+      <option name="compatibility:include-filter" value="CtsHealthConnectHostSideDeviceTestCases" />
 
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCases:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCasesNoPermission:enable:true" />
@@ -37,5 +39,7 @@
       <option name="compatibility:module-arg" value="CtsHealthFitnessDeviceTestCasesRateLimiter:enable:true" />
       <option name="compatibility:module-arg" value="CtsHealthFitnessShowMigrationInfoIntentAbsentTests:enable:true" />
       <option name="compatibility:module-arg" value="HealthFitnessIntegrationBackupRestoreTests:enable:true" />
+      <option name="compatibility:module-arg" value="HealthFitnessIntegrationExportImportTests:enable:true" />
+      <option name="compatibility:module-arg" value="CtsHealthConnectHostSideDeviceTestCases:enable:true" />
 
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-media-tests-list.xml b/tools/mts-tradefed/res/config/mts-media-tests-list.xml
index c4469ff..c038278 100644
--- a/tools/mts-tradefed/res/config/mts-media-tests-list.xml
+++ b/tools/mts-tradefed/res/config/mts-media-tests-list.xml
@@ -54,9 +54,7 @@
     <option name="compatibility:module-arg" value="MctsMediaParserTestCases:instrumentation-arg:mts-media:=true" />
     <option name="compatibility:module-arg" value="MctsMediaParserTestCases:instrumentation-arg:media-testing-mode:=mts" />
 
-    <option name="compatibility:include-filter" value="MctsMediaStressTestCases" />
-    <option name="compatibility:module-arg" value="MctsMediaStressTestCases:instrumentation-arg:mts-media:=true" />
-    <option name="compatibility:module-arg" value="MctsMediaStressTestCases:instrumentation-arg:media-testing-mode:=mts" />
+    <!-- b/344653352 dropped MctsMediaStressTestCases -->
 
     <option name="compatibility:include-filter" value="MctsMediaTranscodingTestCases" />
     <option name="compatibility:module-arg" value="MctsMediaTranscodingTestCases:instrumentation-arg:mts-media:=true" />
diff --git a/tools/mts-tradefed/res/config/mts-mediaprovider-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-mediaprovider-tests-list-user.xml
index 98c4d43..05b91df 100644
--- a/tools/mts-tradefed/res/config/mts-mediaprovider-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-mediaprovider-tests-list-user.xml
@@ -27,6 +27,7 @@
     <option name="compatibility:include-filter" value="CtsAppCloningHostTest" />
     <option name="compatibility:include-filter" value="MediaProviderTests" />
     <option name="compatibility:include-filter" value="CtsMediaProviderTranscodeTests" />
+    <option name="compatibility:include-filter" value="PhotopickerTests" />
     <option name="compatibility:include-filter" value="CtsPhotoPickerTest" />
     <option name="compatibility:include-filter" value="CtsAppCloningMediaProviderHostTest" />
 
@@ -44,12 +45,12 @@
     <!-- <option name="compatibility:module-arg" value="CtsScopedStoragePublicVolumeHostTest:enable:true" /> -->
     <option name="compatibility:module-arg" value="CtsAppCloningHostTest:enable:true" />
     <option name="compatibility:module-arg" value="MediaProviderTests:enable:true" />
+    <option name="compatibility:module-arg" value="PhotopickerTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsMediaProviderTranscodeTests:enable:true" />
     <option name="compatibility:module-arg" value="CtsPhotoPickerTest:enable:true" />
     <option name="compatibility:module-arg" value="CtsAppCloningMediaProviderHostTest:enable:true" />
 
-    <!-- Enable PdfViewer tests to use 
-    MainlineTestModuleController -->
+    <!-- Enable PdfViewer tests to use MainlineTestModuleController -->
     <option name="compatibility:module-arg" value="CtsPdfModuleTestCases:enable:true" />
 
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts-permission-tests-list-oem.xml b/tools/mts-tradefed/res/config/mts-permission-tests-list-oem.xml
index 2d59327..43cda4e 100644
--- a/tools/mts-tradefed/res/config/mts-permission-tests-list-oem.xml
+++ b/tools/mts-tradefed/res/config/mts-permission-tests-list-oem.xml
@@ -22,6 +22,7 @@
     <option name="compatibility:include-filter" value="PermissionControllerOutOfProcessTests" />
     <option name="compatibility:include-filter" value="PermissionUiTestCases" />
     <option name="compatibility:include-filter" value="CtsPermissionMultiDeviceTestCases" />
+    <option name="compatibility:include-filter" value="CtsPermissionMultiUserTestCases" />
     <option name="compatibility:include-filter" value="CtsPermissionTestCases android.permission.cts.AccessibilityPrivacySourceTest" />
     <option name="compatibility:include-filter" value="CtsPermissionTestCases android.permission.cts.BackgroundPermissionsTest" />
     <option name="compatibility:include-filter" value="CtsPermissionTestCases android.permission.cts.LocationAccessCheckTest" />
diff --git a/tools/mts-tradefed/res/config/mts-tethering-tests-list-user.xml b/tools/mts-tradefed/res/config/mts-tethering-tests-list-user.xml
index 19d9115..39560d0 100644
--- a/tools/mts-tradefed/res/config/mts-tethering-tests-list-user.xml
+++ b/tools/mts-tradefed/res/config/mts-tethering-tests-list-user.xml
@@ -21,6 +21,12 @@
     <option name="compatibility:include-filter" value="CtsNetTestCasesMaxTargetSdk30" />
     <option name="compatibility:include-filter" value="MtsTetheringTestLatestSdk" />
     <option name="compatibility:include-filter" value="CtsTetheringTest" />
+    <option name="compatibility:include-filter" value="NearbyUnitTests" />
+    <option name="compatibility:include-filter" value="CtsNearbyFastPairTestCases" />
+    <option name="compatibility:include-filter" value="CtsNetHttpTestCases" />
+    <option name="compatibility:include-filter" value="ThreadNetworkUnitTests" />
+    <option name="compatibility:include-filter" value="CtsThreadNetworkTestCases" />
+
     <!-- Do not include NetworkStack module-specific tests as Connectivity MTS may not run
          with the latest version of that module installed -->
     <option name="compatibility:module-arg"
@@ -35,11 +41,6 @@
             value="MtsTetheringTestLatestSdk:exclude-annotation:com.android.testutils.NetworkStackModuleTest" />
     <option name="compatibility:module-arg"
             value="CtsTetheringTest:exclude-annotation:com.android.testutils.NetworkStackModuleTest" />
-    <option name="compatibility:include-filter" value="NearbyUnitTests" />
-    <option name="compatibility:include-filter" value="CtsNearbyFastPairTestCases" />
-    <option name="compatibility:include-filter" value="CtsNetHttpTestCases" />
-    <option name="compatibility:include-filter" value="ThreadNetworkUnitTests" />
-    <option name="compatibility:include-filter" value="CtsThreadNetworkTestCases" />
 
     <!-- Enable tethering MTS tests to use MainlineTestModuleController -->
     <option name="compatibility:module-arg" value="CtsNetTestCases:enable:true" />
diff --git a/tools/mts-tradefed/res/config/mts-uwb-tests-list-eng-only.xml b/tools/mts-tradefed/res/config/mts-uwb-tests-list-eng-only.xml
index 469d113..a720841 100644
--- a/tools/mts-tradefed/res/config/mts-uwb-tests-list-eng-only.xml
+++ b/tools/mts-tradefed/res/config/mts-uwb-tests-list-eng-only.xml
@@ -18,8 +18,10 @@
     <option name="compatibility:include-filter" value="libuwb_core_tests" />
     <option name="compatibility:include-filter" value="libuwb_uci_jni_rust_tests" />
     <option name="compatibility:include-filter" value="libuwb_uci_packet_tests" />
+    <option name="compatibility:include-filter" value="libuci_hal_android_tests" />
 
     <option name="compatibility:module-arg" value="libuwb_core_tests:enable:true" />
     <option name="compatibility:module-arg" value="libuwb_uci_jni_rust_tests:enable:true" />
     <option name="compatibility:module-arg" value="libuwb_uci_packet_tests:enable:true" />
+    <option name="compatibility:module-arg" value="libuci_hal_android_tests:enable:true" />
 </configuration>
diff --git a/tools/mts-tradefed/res/config/mts.xml b/tools/mts-tradefed/res/config/mts.xml
index 5f25d48..91f5c41 100644
--- a/tools/mts-tradefed/res/config/mts.xml
+++ b/tools/mts-tradefed/res/config/mts.xml
@@ -67,8 +67,7 @@
     <option name="compatibility:module-arg" value="MctsMediaV2TestCases:instrumentation-arg:media-testing-mode:=mts" />
     <option name="compatibility:module-arg" value="MctsMediaParserTestCases:instrumentation-arg:mts-media:=true" />
     <option name="compatibility:module-arg" value="MctsMediaParserTestCases:instrumentation-arg:media-testing-mode:=mts" />
-    <option name="compatibility:module-arg" value="MctsMediaStressTestCases:instrumentation-arg:mts-media:=true" />
-    <option name="compatibility:module-arg" value="MctsMediaStressTestCases:instrumentation-arg:media-testing-mode:=mts" />
+    <!-- b/344653352 dropped MctsMediaStressTestCases -->
     <option name="compatibility:module-arg" value="MctsMediaTranscodingTestCases:instrumentation-arg:mts-media:=true" />
     <option name="compatibility:module-arg" value="MctsMediaTranscodingTestCases:instrumentation-arg:media-testing-mode:=mts" />
     <!-- core-test-mode=mts tells ExpectationBasedFilter to exclude @NonMts Tests -->
diff --git a/tools/mts-tradefed/tests/Android.bp b/tools/mts-tradefed/tests/Android.bp
index 2dfa8f0..3252430 100644
--- a/tools/mts-tradefed/tests/Android.bp
+++ b/tools/mts-tradefed/tests/Android.bp
@@ -32,3 +32,19 @@ java_library_host {
         "suite-loading-tests",
     ],
 }
+
+java_library_host {
+    name: "mcts-tradefed-tests",
+
+    srcs: ["src/**/*.java"],
+
+    libs: [
+        "tradefed",
+        "mcts-tradefed",
+    ],
+
+    static_libs: [
+        // Import common validation tests
+        "suite-loading-tests",
+    ],
+}
```

