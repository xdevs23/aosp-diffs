```diff
diff --git a/target_preparers/src/com/android/catbox/targetpreparer/ChromeMdPassengerLoadPreparer.java b/target_preparers/src/com/android/catbox/targetpreparer/ChromeMdPassengerLoadPreparer.java
index 9fc4e88..14e8a9c 100644
--- a/target_preparers/src/com/android/catbox/targetpreparer/ChromeMdPassengerLoadPreparer.java
+++ b/target_preparers/src/com/android/catbox/targetpreparer/ChromeMdPassengerLoadPreparer.java
@@ -34,144 +34,254 @@ import com.android.tradefed.util.CommandStatus;
 
 import java.io.ByteArrayOutputStream;
 import java.io.OutputStream;
+import java.io.File;
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 
+// @TODO(b/378562019): rename to more appropriate ChromeMdLoadPreparer
 @OptionClass(alias = "chrome-md-passenger-load")
 public class ChromeMdPassengerLoadPreparer extends BaseTargetPreparer {
-    private static final String INSTR_SUCCESS = "OK (1 test)";
-
-    @Option(name = "skip-display-id", description = "Display id to skip passenger load for")
-    private List<Integer> mSkipDisplayIds = new ArrayList<>();
-
-    @Option(name = "url", description = "Url to open in Chrome browser", mandatory = true)
-    private String mUrl;
-
-    @Option(name = "package", description = "Chrome package")
-    private String mPackage = "com.android.chrome";
-
-    @Option(name = "activity", description = "Chrome activity")
-    private String mActivity = "com.google.android.apps.chrome.Main";
-
-    @Option(
-            name = "test-app-file-name",
-            description =
-                    "the name of an apk file to be installed in the user profiles.")
-    private List<String> mTestFiles = new ArrayList<>();
-
-    Map<Integer, Integer> mDisplayToCreatedUsers = new HashMap<>();
-    private final ArrayList<TestAppInstallSetup> mInstallPreparers =
-            new ArrayList<TestAppInstallSetup>();
-
-    @Override
-    public void setUp(TestInformation testInfo) throws TargetSetupError, BuildError,
-            DeviceNotAvailableException {
-        ITestDevice device = testInfo.getDevice();
-        Set<Integer> displayIds = device.listDisplayIdsForStartingVisibleBackgroundUsers();
-        for (Integer displayId : displayIds) {
-            if (mSkipDisplayIds.contains(displayId)) {
-                LogUtil.CLog.d("Skipping load on display %d", displayId);
-                continue;
-            }
-            int userId = createUser(device, displayId);
-            mDisplayToCreatedUsers.put(displayId, userId);
-        }
 
-        if (mDisplayToCreatedUsers.size() == 0) {
-            LogUtil.CLog.w("Won't create any passenger load. No display ids matched.");
-            throw new TargetSetupError(
-                    String.format("Available displays on the device %s. Skipped displays %s",
-                            displayIds, mSkipDisplayIds),
-                    device.getDeviceDescriptor());
-        }
+  @Option(name = "skip-display-id", description = "Display id to skip passenger load for")
+  private List<Integer> mSkipDisplayIds = new ArrayList<>();
 
-        installApks(testInfo);
+  @Option(
+      name = "skip-passenger-loading",
+      description = "Only create additional passenger users, skip loading them")
+  boolean skipLoading = false;
 
-        for (Integer displayId : mDisplayToCreatedUsers.keySet()) {
-            int userId = mDisplayToCreatedUsers.get(displayId);
-            dismissInitialDialog(device, userId);
-            simulatePassengerLoad(device, userId);
-        }
+  @Option(name = "post-test-cleanup", description = "Clean up users and uninstall test apks")
+  boolean postTestCleanup = true;
+
+  @Option(name = "url", description = "Youtube video URL", mandatory = true)
+  private String mUrl;
+
+  @Option(name = "package", description = "Youtube package")
+  private String mPackage = "com.google.android.apps.automotive.youtube";
+
+  @Option(name = "install-apk", description = "Re-install a custom Youtube APK if necessary")
+  boolean mInstallYTApk = false;
+
+  @Option(name = "max-users", description = "Maximum number of users to support")
+  int maxUsers = 10;
+
+  @Option(
+      name = "test-app-file-name",
+      description = "full qualified path to the custom Youtube APK")
+  private List<String> mTestFiles = new ArrayList<>();
+
+  Map<Integer, Integer> mDisplayToCreatedUsers = new HashMap<>();
+  private final ArrayList<TestAppInstallSetup> mInstallPreparers =
+      new ArrayList<TestAppInstallSetup>();
+
+  @Override
+  public void setUp(TestInformation testInfo)
+      throws TargetSetupError, BuildError, DeviceNotAvailableException {
+    ITestDevice device = testInfo.getDevice();
+    increaseSupportedUsers(device);
+    Set<Integer> displayIds = device.listDisplayIdsForStartingVisibleBackgroundUsers();
+    for (Integer displayId : displayIds) {
+      if (mSkipDisplayIds.contains(displayId)) {
+        LogUtil.CLog.d("Skipping user creation for display %d", displayId);
+        continue;
+      }
+      int userId = createAndStartUser(device, displayId);
+      LogUtil.CLog.d(
+          "Created and started new passenger user: %s on Display: %s", userId, displayId);
+      mDisplayToCreatedUsers.put(displayId, userId);
     }
 
-    @Override
-    public void tearDown(TestInformation testInfo, Throwable e)
-            throws DeviceNotAvailableException {
-        ITestDevice device = testInfo.getDevice();
-        for (TestAppInstallSetup installPreparer : mInstallPreparers) {
-            installPreparer.tearDown(testInfo, e);
-        }
-        for (int userId : mDisplayToCreatedUsers.values()) {
-            device.removeUser(userId);
-        }
+    // Assume current user is on the main display
+    int currentUser = device.getCurrentUser();
+    LogUtil.CLog.d("Mapping current user %d to display 0", currentUser);
+    mDisplayToCreatedUsers.put(0, currentUser);
+
+    skipGtos(device);
+    skipSuw(device);
+    dismissChromeDialogs(device);
+
+    if (!skipLoading && mInstallYTApk) {
+      installApk(testInfo);
     }
 
-    private int createUser(ITestDevice device, int displayId)
-            throws TargetSetupError,
-            DeviceNotAvailableException {
-        int userId = device.createUser(String.format("user-display-%d", displayId));
-        LogUtil.CLog.d(
-                String.format("Created user with id %d for display %d", userId, displayId));
-        if (!device.startVisibleBackgroundUser(userId, displayId, true)) {
-            throw new TargetSetupError(
-                    String.format("Device failed to switch to user %d", userId),
-                    device.getDeviceDescriptor());
-        }
-        LogUtil.CLog.d(
-                String.format("Started background user %d for display %d", userId, displayId));
-        return userId;
+    for (Integer displayId : mDisplayToCreatedUsers.keySet()) {
+      int userId = mDisplayToCreatedUsers.get(displayId);
+      simulatePassengerLoad(device, userId);
     }
+  }
 
-    private void installApks(TestInformation testInfo)
-            throws TargetSetupError, BuildError, DeviceNotAvailableException {
-        for (int userId : mDisplayToCreatedUsers.values()) {
-            TestAppInstallSetup installPreparer = new TestAppInstallSetup();
-            LogUtil.CLog.d(
-                    String.format("Installing the following test APKs in user %d: \n%s", userId,
-                            mTestFiles));
-            installPreparer.setUserId(userId);
-            installPreparer.setShouldGrantPermission(true);
-            for (String file : mTestFiles) {
-                installPreparer.addTestFileName(file);
-            }
-            installPreparer.addInstallArg("-r");
-            installPreparer.addInstallArg("-d");
-            installPreparer.setUp(testInfo);
-            mInstallPreparers.add(installPreparer);
-        }
+  @Override
+  public void tearDown(TestInformation testInfo, Throwable e) throws DeviceNotAvailableException {
+    ITestDevice device = testInfo.getDevice();
+    if (!skipLoading) {
+      stopTestApps(device);
     }
 
-    private void simulatePassengerLoad(ITestDevice device, int userId)
-            throws TargetSetupError, DeviceNotAvailableException {
-        LogUtil.CLog.d(String.format("Launching Chrome for User %d with url %s", userId, mUrl));
-        String launchChromeActivityWithUrlCommand = String.format(
-                "am start -n %s/%s --user %d -a android.intent.action.VIEW -d %s", mPackage,
-                mActivity, userId, mUrl);
-        CommandResult result = device.executeShellV2Command(launchChromeActivityWithUrlCommand);
-        if (!CommandStatus.SUCCESS.equals(result.getStatus())) {
-            throw new TargetSetupError(
-                    String.format("Chrome activity failed to launch for user %d", userId),
-                    device.getDeviceDescriptor());
-        }
+    stopUsers(device);
+
+    if (postTestCleanup) {
+      // Remove all the passenger users
+      for (int userId : mDisplayToCreatedUsers.values()) {
+        LogUtil.CLog.d("Removing user: %s", userId);
+        device.removeUser(userId);
+      }
     }
+    device.reboot();
+  }
 
-    private void dismissInitialDialog(ITestDevice device, int userId)
-            throws DeviceNotAvailableException, TargetSetupError {
-        OutputStream output = new ByteArrayOutputStream();
-        String dismissCommand = String.format(
-                "am instrument -w --user %d -e class android.platform.tests"
-                        + ".ChromeDismissDialogsTest android.platform.tests/androidx.test.runner"
-                        + ".AndroidJUnitRunner",
-                userId);
-        device.executeShellV2Command(dismissCommand, output);
-        if (!output.toString().contains(INSTR_SUCCESS)) {
-            throw new TargetSetupError(
-                    String.format("Failed dismissal.\nCommand output: %s", output),
-                    device.getDeviceDescriptor(),
-                    DeviceErrorIdentifier.DEVICE_UNEXPECTED_RESPONSE);
+  private void stopTestApps(ITestDevice device) throws DeviceNotAvailableException {
+    LogUtil.CLog.d("Stopping the Youtube application for all the passengers");
+    for (int userID : mDisplayToCreatedUsers.values()) {
+      String stopYoutube = String.format("am force-stop --user %d %s", userID, mPackage);
+      String stopChrome = String.format("am force-stop --user %d com.chrome.beta", userID);
+      CommandResult stopYoutubeResult = device.executeShellV2Command(stopYoutube);
+      CommandResult stopChromeResult = device.executeShellV2Command(stopChrome);
+      if (stopYoutubeResult.getExitCode() != 0 || stopChromeResult.getExitCode() != 0) {
+        LogUtil.CLog.d("Failed to kill the Youtube application for user: %d", userID);
+      }
+    }
+  }
+
+  private void dismissChromeDialogs(ITestDevice device) throws DeviceNotAvailableException {
+    LogUtil.CLog.d("Dismissing initial Chrome Dialogs");
+    String dismissCommand = "am set-debug-app --persistent com.chrome.beta";
+    CommandResult dismissResult = device.executeShellV2Command(dismissCommand);
+    if (dismissResult.getExitCode() != 0) {
+      LogUtil.CLog.d("Failed to dismiss Chrome dialogs");
+    }
+    LogUtil.CLog.d("Successfully dismissed initial Chrome Dialogs");
+  }
+
+  private void increaseSupportedUsers(ITestDevice device)
+      throws TargetSetupError, DeviceNotAvailableException {
+    LogUtil.CLog.d("Temporarily increasing maximum supported users to " + maxUsers);
+    String setMaxUsers = "setprop fw.max_users " + maxUsers;
+    CommandResult setMaxUsersResult = device.executeShellV2Command(setMaxUsers);
+    if (!CommandStatus.SUCCESS.equals(setMaxUsersResult.getStatus())) {
+      throw new TargetSetupError(
+          "Failed to increase the number of supported users", device.getDeviceDescriptor());
+    }
+    LogUtil.CLog.d("Successfully increased the maximum supported users");
+  }
+
+  private int createAndStartUser(ITestDevice device, int displayId)
+      throws TargetSetupError, DeviceNotAvailableException {
+    int userId = device.createUser(String.format("user-display-%d", displayId));
+    LogUtil.CLog.d(String.format("Created user with id %d for display %d", userId, displayId));
+    if (!device.startVisibleBackgroundUser(userId, displayId, true)) {
+      throw new TargetSetupError(
+          String.format("Device failed to switch to user %d", userId),
+          device.getDeviceDescriptor());
+    }
+    LogUtil.CLog.d(String.format("Started background user %d for display %d", userId, displayId));
+    return userId;
+  }
+
+  private void stopUsers(ITestDevice device) throws DeviceNotAvailableException {
+    LogUtil.CLog.d("Stopping all passenger users");
+    for (int userID : mDisplayToCreatedUsers.values()) {
+      String startUserCommand = String.format("am stop-user %d", userID);
+      CommandResult startUserResult = device.executeShellV2Command(startUserCommand);
+      if (startUserResult.getExitCode() != 0) {
+        LogUtil.CLog.d("Failed to stop the user: %d", userID);
+      }
+    }
+    LogUtil.CLog.d("Successfully stopped all passenger users");
+  }
+
+  private void installApk(TestInformation testInfo)
+      throws TargetSetupError, BuildError, DeviceNotAvailableException {
+    for (int userId : mDisplayToCreatedUsers.values()) {
+      TestAppInstallSetup installPreparer = new TestAppInstallSetup();
+      LogUtil.CLog.d(
+          String.format("Installing the following test APKs in user %d: \n%s", userId, mTestFiles));
+      installPreparer.setUserId(userId);
+      installPreparer.setShouldGrantPermission(true);
+      for (String file : mTestFiles) {
+        installPreparer.addTestFileName(file);
+      }
+      installPreparer.addInstallArg("-r");
+      installPreparer.addInstallArg("-d");
+      installPreparer.setUp(testInfo);
+      mInstallPreparers.add(installPreparer);
+    }
+  }
+
+  private void simulatePassengerLoad(ITestDevice device, int userId)
+      throws TargetSetupError, DeviceNotAvailableException {
+    LogUtil.CLog.d(
+        String.format("Launching the Youtube App for User: %d with url: %s", userId, mUrl));
+    String launchYoutubeWithUrlCommand =
+        String.format(
+            "am start --user %d -a android.intent.action.VIEW -e FullScreen true  -d "
+                + "\"%s\" %s",
+            userId, mUrl, mPackage);
+    LogUtil.CLog.d("Youtube launch command: %s", launchYoutubeWithUrlCommand);
+    CommandResult result = device.executeShellV2Command(launchYoutubeWithUrlCommand);
+    if (!CommandStatus.SUCCESS.equals(result.getStatus())) {
+      throw new TargetSetupError(
+          String.format("Failed to launch the Youtube app for the user %d", userId),
+          device.getDeviceDescriptor());
+    }
+    LogUtil.CLog.d("Successfully launched the Youtube video for user: %d", userId);
+  }
+
+  // Skips the Set-up wizard for all the passenger users.
+  private void skipSuw(ITestDevice device) throws DeviceNotAvailableException, TargetSetupError {
+    LogUtil.CLog.d("Skipping set-up wizard for all passenger users");
+    for (int userID : mDisplayToCreatedUsers.values()) {
+      String suwSkipCommand =
+          String.format(
+              "am start --user %d -n com.google.android.car.setupwizard/.ExitActivity", userID);
+      CommandResult suwSkipCommandResult = device.executeShellV2Command(suwSkipCommand);
+      if (suwSkipCommandResult.getExitCode() != 0) {
+        throw new TargetSetupError(
+            String.format("Failed to skip the set-up wizard for user: %d", userID),
+            device.getDeviceDescriptor());
+      }
+    }
+    LogUtil.CLog.d("Successfully skipped set-up wizard across all passenger users");
+  }
+
+  // Skips the Google Terms and Conditions for all the users. This would remove the restrictions
+  // enforced on GAS apps for all users.
+  private void skipGtos(ITestDevice device) throws DeviceNotAvailableException, TargetSetupError {
+    LogUtil.CLog.d("Skipping gTOS on behalf of all users");
+    if (!device.isAdbRoot()) {
+      device.enableAdbRoot();
+    }
+    List<String> gasPackageNames =
+        Arrays.asList(
+            "com.google.android.apps.maps",
+            "com.android.vending",
+            "com.google.android.carassistant",
+            mPackage,
+            "com.chrome.beta");
+    for (int userID : mDisplayToCreatedUsers.values()) {
+      for (String gasPackageName : gasPackageNames) {
+        String gTOSPmCommand = String.format("pm enable --user %d %s ", userID, gasPackageName);
+        CommandResult gTOSPmResult = device.executeShellV2Command(gTOSPmCommand);
+        if (gTOSPmResult.getExitCode() != 0) {
+          throw new TargetSetupError(
+              String.format(
+                  "Failed to skip gTOS for user: %d and package: %s", userID, gasPackageName),
+              device.getDeviceDescriptor());
         }
+      }
+      String gTOSKeyUserCommand =
+          String.format(
+              "settings put secure --user %d android.car.KEY_USER_TOS_ACCEPTED 2 ", userID);
+      CommandResult gTOSKeyUserResult = device.executeShellV2Command(gTOSKeyUserCommand);
+      if (gTOSKeyUserResult.getExitCode() != 0) {
+        throw new TargetSetupError(
+            String.format("Failed to accept gTOS for user: %d", userID),
+            device.getDeviceDescriptor());
+      }
     }
+    LogUtil.CLog.d("Successfully skipped gTOS across all passenger users");
+  }
 }
diff --git a/tools/catbox-common/res/config/catbox-performance-base.xml b/tools/catbox-common/res/config/catbox-performance-base.xml
index 01a0d97..fd51a31 100644
--- a/tools/catbox-common/res/config/catbox-performance-base.xml
+++ b/tools/catbox-common/res/config/catbox-performance-base.xml
@@ -41,12 +41,29 @@
     </target_preparer>
     <target_preparer class="com.android.catbox.targetpreparer.ChromeMdPassengerLoadPreparer">
         <option name="disable" value="true"/>
-        <option name="url" value="https://youtu.be/dQw4w9WgXcQ"/>
+        <option name="skip-passenger-loading" value="false"/>
+        <option name="max-users" value="10"/>
+        <option name="post-test-cleanup" value="true"/>
+        <option name="url" value="https://youtu.be/YB8BX0Pt1Lk?si=k7Sbae9AAj4lU6-7"/>
+        <option name="install-apk" value="false"/>
     </target_preparer>
 
     <!-- Enable perfetto host side metric collector -->
     <metrics_collector class="com.android.tradefed.device.metric.PerfettoPullerMetricCollector">
         <option name="collect-on-run-ended-only" value="false" />
         <option name="pull-pattern-keys" value="perfetto_file_path" />
+        <option name="trace-processor-run-metrics" value="android_mem" />
+        <option name="trace-processor-run-metrics" value="android_auto_multiuser" />
+        <option name="trace-processor-run-metrics" value="android_monitor_contention" />
+        <option name="trace-processor-run-metrics" value="android_monitor_contention_agg" />
+        <option name="trace-processor-run-metrics" value="android_binder" />
+        <option name="trace-processor-run-metrics" value="android_boot" />
+        <option name="trace-processor-run-metrics" value="android_startup" />
+        <option name="trace-processor-run-metrics" value="android_jank_cuj" />
+        <option name="trace-processor-run-metrics" value="android_frame_timeline_metric" />
+        <option name="trace-processor-run-metrics" value="android_app_process_starts" />
+        <option name="trace-processor-run-metrics" value="android_boot_unagg" />
+        <option name="trace-processor-run-metrics" value="android_garbage_collection_unagg" />
+        <option name="trace-processor-run-metrics" value="android_io" />
     </metrics_collector>
 </configuration>
diff --git a/tools/catbox-common/res/config/catbox-performance-longevity-base.xml b/tools/catbox-common/res/config/catbox-performance-longevity-base.xml
new file mode 100644
index 0000000..1ade662
--- /dev/null
+++ b/tools/catbox-common/res/config/catbox-performance-longevity-base.xml
@@ -0,0 +1,58 @@
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
+<configuration description="CATBOX Longevity Base Configuration">
+    <include name="catbox-performance-base"/>
+
+    <!-- Base Test Arguments -->
+    <option name="compatibility:test-arg"
+            value="com.android.tradefed.testtype.AndroidJUnitTest:runner:androidx.test.runner.AndroidJUnitRunner"/>
+    <option name="compatibility:test-arg"
+            value="com.android.tradefed.testtype.AndroidJUnitTest:no-rerun:true"/>
+    <!-- Set test timeout for 14 hours -->
+    <option name="compatibility:test-arg"
+            value="com.android.tradefed.testtype.AndroidJUnitTest:shell-timeout:50400000"/>
+
+    <!-- Install and start mock GPS injector -->
+    <option name="compatibility:test-arg"
+            value="com.android.tradefed.targetprep.RunCommandTargetPreparer:run-command:appops set android.support.test.locationsimulator android:mock_location allow"/>
+    <option name="compatibility:test-arg"
+            value="com.android.tradefed.targetprep.RunCommandTargetPreparer:run-command:am start-foreground-service -n android.support.test.locationsimulator/.LocationSimulatorService -e gpxFile /data/local/tmp/mtv_san.gpx"/>
+
+    <!-- Listeners -->
+    <option name="compatibility:module-arg"
+            value="AndroidAutomotiveLongevityTests:instrumentation-arg:listener:=android.device.collectors.CrashListener,android.device.collectors.CpuUsageListener,android.device.collectors.FreeMemListener,android.device.collectors.DumpsysMeminfoListener"/>
+
+    <!-- Metrics collectors -->
+    <metrics_collector class="com.android.tradefed.device.metric.FilePullerLogCollector"/>
+    <option name="directory-keys"
+            value="/storage/emulated/10/test_results/ScheduledDumpsysMeminfoListener"/>
+    <option name="directory-keys"
+            value="/storage/emulated/10/test_results/ScheduledFreeMemListener"/>
+    <option name="directory-keys"
+            value="/storage/emulated/10/test_results/ScheduledProcCpuUtilizationListener"/>
+    <option name="collect-on-run-ended-only" value="true"/>
+    <metrics_collector class="com.android.tradefed.device.metric.PerfettoPullerMetricCollector"/>
+    <metrics_collector class="com.android.tradefed.device.metric.RebootReasonCollector">
+        <option name="disable" value="false"/>
+    </metrics_collector>
+    <metrics_collector class="com.android.tradefed.device.metric.RuntimeRestartCollector">
+        <option name="disable" value="false"/>
+    </metrics_collector>
+
+    <!-- Post Processors -->
+    <include name="catbox-performance-postprocessors"/>
+
+</configuration>
\ No newline at end of file
diff --git a/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml b/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml
index b642c56..aca9a34 100644
--- a/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml
+++ b/tools/catbox-common/res/config/catbox-performance-multiuser-base.xml
@@ -17,6 +17,10 @@
 <configuration description="Base config for Multi-User latency metrics">
   <include name="catbox-performance-base" />
 
+  <!-- Disable SUW for multiuser tests -->
+  <option name="device-setup:disable" value="false" />
+  <option name="device-setup:set-property" key="aae.suw.provisioning_mode_override" value="DISABLED" />
+
   <!-- TradeFed test harness -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:runner:androidx.test.runner.AndroidJUnitRunner" />
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.scenario.multiuser" />
diff --git a/tools/catbox-common/res/config/catbox-performance-postprocessors.xml b/tools/catbox-common/res/config/catbox-performance-postprocessors.xml
index 0fcebad..5d1aa34 100644
--- a/tools/catbox-common/res/config/catbox-performance-postprocessors.xml
+++ b/tools/catbox-common/res/config/catbox-performance-postprocessors.xml
@@ -21,6 +21,9 @@
     <option name="enable-per-test-log" value="false" />
   </metric_post_processor>
   <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoGenericPostProcessor">
+    <option name="perfetto-include-all-metrics" value="false" />
     <option name="perfetto-proto-file-prefix" value="metric_perfetto" />
+    <option name="perfetto-prefix-key-field" value="perfetto.protos.AndroidAutoMultiuserMetric.EventData.end_event" />
+    <option name="perfetto-metric-filter-regex" value="android_auto_multiuser-user_switch-end_event.*duration_ms" />
   </metric_post_processor>
 </configuration>
diff --git a/tools/catbox-common/res/config/catbox-preparer.xml b/tools/catbox-common/res/config/catbox-preparer.xml
index cede900..b48e004 100644
--- a/tools/catbox-common/res/config/catbox-preparer.xml
+++ b/tools/catbox-common/res/config/catbox-preparer.xml
@@ -33,9 +33,6 @@
   <!-- Target Preparers - Setup the Device -->
   <target_preparer class="com.android.tradefed.targetprep.DeviceSetup">
     <option name="disable" value="true" />
-    <option name="screen-always-on" value="on" />
-    <option name="screen-adaptive-brightness" value="off" />
-    <option name="screen-saver" value="off" />
     <option name="set-secure-setting" key="location_mode" value="1" />
   </target_preparer>
 
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-bluetooth-setting.xml b/tools/catbox-tradefed/res/config/catbox-functional-bluetooth-default-state.xml
similarity index 84%
rename from tools/catbox-tradefed/res/config/catbox-functional-bluetooth-setting.xml
rename to tools/catbox-tradefed/res/config/catbox-functional-bluetooth-default-state.xml
index 46e90a7..9308bfb 100644
--- a/tools/catbox-tradefed/res/config/catbox-functional-bluetooth-setting.xml
+++ b/tools/catbox-tradefed/res/config/catbox-functional-bluetooth-default-state.xml
@@ -13,7 +13,7 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="Complete Automotive Tests - Bluetooth Setting Functional Tests.">
+<configuration description="Complete Automotive Tests - Bluetooth Default State Functional Tests.">
   <!-- Common Base -->
   <include name="catbox-common"/>
 
@@ -21,7 +21,7 @@
   <include name="catbox-preparer"/>
 
   <!-- Plan -->
-  <option name="plan" value="catbox-functional-bluetooth-setting"/>
+  <option name="plan" value="catbox-functional-bluetooth-default-state"/>
 
   <!-- Test Args -->
   <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:runner:androidx.test.runner.AndroidJUnitRunner" />
@@ -30,4 +30,5 @@
 
   <!-- Tests -->
   <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.BluetoothSettingTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveBluetoothMediaTests android.platform.tests.BluetoothMediaTest" />
 </configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-common.xml b/tools/catbox-tradefed/res/config/catbox-functional-common.xml
new file mode 100644
index 0000000..79b3144
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-functional-common.xml
@@ -0,0 +1,31 @@
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
+<configuration description="Complete Automotive Tests - Functional Tests.">
+  <!-- Common Base -->
+  <include name="catbox-common"/>
+
+  <!-- Device Preparers -->
+  <include name="catbox-preparer"/>
+
+  <!-- Plan -->
+  <option name="plan" value="catbox-functional-common"/>
+
+  <!-- Test Args -->
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:runner:androidx.test.runner.AndroidJUnitRunner" />
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.tests" />
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:no-rerun:true" />
+</configuration>
+
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-status-bar.xml b/tools/catbox-tradefed/res/config/catbox-functional-status-bar.xml
index 2ab8336..214b206 100644
--- a/tools/catbox-tradefed/res/config/catbox-functional-status-bar.xml
+++ b/tools/catbox-tradefed/res/config/catbox-functional-status-bar.xml
@@ -35,4 +35,6 @@
   <!-- Tests -->
   <option name="compatibility:include-filter"
       value="AndroidAutomotiveStatusBarTests android.platform.tests.StatusBarTest" />
+  <option name="compatibility:include-filter"
+      value="AndroidAutomotiveStatusBarTests android.platform.tests.CurrentDateTimeTest" />
 </configuration>
\ No newline at end of file
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-boot-test-common.xml b/tools/catbox-tradefed/res/config/catbox-performance-boot-test-common.xml
index ec7a831..6e94f20 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-boot-test-common.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-boot-test-common.xml
@@ -45,10 +45,10 @@
     <option name="collect-on-run-ended-only" value="false" />
   </metrics_collector>
 
-  <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoGenericPostProcessor" />
   <metric_post_processor class="com.android.tradefed.postprocessor.MetricFilePostProcessor">
     <option name="aggregate-similar-tests" value="true" />
   </metric_post_processor>
+  <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoGenericPostProcessor" />
   <metric_post_processor class="android.boottime.postprocessor.LogcatPostProcessor">
     <option name="file-regex" value=".*Successive_reboots_logcat.*"/>
     <!-- For custom boot time metrics -->
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-successive-boottime.xml b/tools/catbox-tradefed/res/config/catbox-performance-successive-boottime.xml
index 95422d7..99fd7dd 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-successive-boottime.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-successive-boottime.xml
@@ -18,6 +18,11 @@
     <include name="catbox-performance-base" />
     <include name="catbox-performance-boot-test-common" />
 
+    <option name="push-file:push-file" key="trace_config_post_boot.textproto" value="/data/misc/perfetto-configs/boottrace.pbtxt" />
+    <option name="perfetto-metric-collector:trace-processor-timeout" value="1200000" />
+    <option name="perfetto-generic-processor:perfetto-proto-file-prefix" value="metric_BootTime" />
+    <option name="perfetto-generic-processor:perfetto-include-all-metrics" value="true" />
+
     <!-- Artificially disabling tests in CompatibilityTestSuite -->
     <!-- See com.android.tradefed.testtype.suite.CompatibilityTestSuite:loadTests() -->
     <option name="compatibility:reverse-exclude-filters" value="true" />
```

