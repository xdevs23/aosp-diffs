```diff
diff --git a/target_preparers/src/com/android/catbox/targetpreparer/ChromeMdPassengerLoadPreparer.java b/target_preparers/src/com/android/catbox/targetpreparer/ChromeMdPassengerLoadPreparer.java
deleted file mode 100644
index 14e8a9c..0000000
--- a/target_preparers/src/com/android/catbox/targetpreparer/ChromeMdPassengerLoadPreparer.java
+++ /dev/null
@@ -1,287 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.catbox.targetpreparer;
-
-import com.android.tradefed.build.IBuildInfo;
-import com.android.tradefed.config.Option;
-import com.android.tradefed.config.OptionClass;
-import com.android.tradefed.device.CollectingOutputReceiver;
-import com.android.tradefed.device.DeviceNotAvailableException;
-import com.android.tradefed.device.ITestDevice;
-import com.android.tradefed.invoker.TestInformation;
-import com.android.tradefed.log.LogUtil;
-import com.android.tradefed.result.error.DeviceErrorIdentifier;
-import com.android.tradefed.targetprep.BaseTargetPreparer;
-import com.android.tradefed.targetprep.BuildError;
-import com.android.tradefed.targetprep.TargetSetupError;
-import com.android.tradefed.targetprep.TestAppInstallSetup;
-import com.android.tradefed.util.CommandResult;
-import com.android.tradefed.util.CommandStatus;
-
-import java.io.ByteArrayOutputStream;
-import java.io.OutputStream;
-import java.io.File;
-import java.util.ArrayList;
-import java.util.Arrays;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Map;
-import java.util.Set;
-
-// @TODO(b/378562019): rename to more appropriate ChromeMdLoadPreparer
-@OptionClass(alias = "chrome-md-passenger-load")
-public class ChromeMdPassengerLoadPreparer extends BaseTargetPreparer {
-
-  @Option(name = "skip-display-id", description = "Display id to skip passenger load for")
-  private List<Integer> mSkipDisplayIds = new ArrayList<>();
-
-  @Option(
-      name = "skip-passenger-loading",
-      description = "Only create additional passenger users, skip loading them")
-  boolean skipLoading = false;
-
-  @Option(name = "post-test-cleanup", description = "Clean up users and uninstall test apks")
-  boolean postTestCleanup = true;
-
-  @Option(name = "url", description = "Youtube video URL", mandatory = true)
-  private String mUrl;
-
-  @Option(name = "package", description = "Youtube package")
-  private String mPackage = "com.google.android.apps.automotive.youtube";
-
-  @Option(name = "install-apk", description = "Re-install a custom Youtube APK if necessary")
-  boolean mInstallYTApk = false;
-
-  @Option(name = "max-users", description = "Maximum number of users to support")
-  int maxUsers = 10;
-
-  @Option(
-      name = "test-app-file-name",
-      description = "full qualified path to the custom Youtube APK")
-  private List<String> mTestFiles = new ArrayList<>();
-
-  Map<Integer, Integer> mDisplayToCreatedUsers = new HashMap<>();
-  private final ArrayList<TestAppInstallSetup> mInstallPreparers =
-      new ArrayList<TestAppInstallSetup>();
-
-  @Override
-  public void setUp(TestInformation testInfo)
-      throws TargetSetupError, BuildError, DeviceNotAvailableException {
-    ITestDevice device = testInfo.getDevice();
-    increaseSupportedUsers(device);
-    Set<Integer> displayIds = device.listDisplayIdsForStartingVisibleBackgroundUsers();
-    for (Integer displayId : displayIds) {
-      if (mSkipDisplayIds.contains(displayId)) {
-        LogUtil.CLog.d("Skipping user creation for display %d", displayId);
-        continue;
-      }
-      int userId = createAndStartUser(device, displayId);
-      LogUtil.CLog.d(
-          "Created and started new passenger user: %s on Display: %s", userId, displayId);
-      mDisplayToCreatedUsers.put(displayId, userId);
-    }
-
-    // Assume current user is on the main display
-    int currentUser = device.getCurrentUser();
-    LogUtil.CLog.d("Mapping current user %d to display 0", currentUser);
-    mDisplayToCreatedUsers.put(0, currentUser);
-
-    skipGtos(device);
-    skipSuw(device);
-    dismissChromeDialogs(device);
-
-    if (!skipLoading && mInstallYTApk) {
-      installApk(testInfo);
-    }
-
-    for (Integer displayId : mDisplayToCreatedUsers.keySet()) {
-      int userId = mDisplayToCreatedUsers.get(displayId);
-      simulatePassengerLoad(device, userId);
-    }
-  }
-
-  @Override
-  public void tearDown(TestInformation testInfo, Throwable e) throws DeviceNotAvailableException {
-    ITestDevice device = testInfo.getDevice();
-    if (!skipLoading) {
-      stopTestApps(device);
-    }
-
-    stopUsers(device);
-
-    if (postTestCleanup) {
-      // Remove all the passenger users
-      for (int userId : mDisplayToCreatedUsers.values()) {
-        LogUtil.CLog.d("Removing user: %s", userId);
-        device.removeUser(userId);
-      }
-    }
-    device.reboot();
-  }
-
-  private void stopTestApps(ITestDevice device) throws DeviceNotAvailableException {
-    LogUtil.CLog.d("Stopping the Youtube application for all the passengers");
-    for (int userID : mDisplayToCreatedUsers.values()) {
-      String stopYoutube = String.format("am force-stop --user %d %s", userID, mPackage);
-      String stopChrome = String.format("am force-stop --user %d com.chrome.beta", userID);
-      CommandResult stopYoutubeResult = device.executeShellV2Command(stopYoutube);
-      CommandResult stopChromeResult = device.executeShellV2Command(stopChrome);
-      if (stopYoutubeResult.getExitCode() != 0 || stopChromeResult.getExitCode() != 0) {
-        LogUtil.CLog.d("Failed to kill the Youtube application for user: %d", userID);
-      }
-    }
-  }
-
-  private void dismissChromeDialogs(ITestDevice device) throws DeviceNotAvailableException {
-    LogUtil.CLog.d("Dismissing initial Chrome Dialogs");
-    String dismissCommand = "am set-debug-app --persistent com.chrome.beta";
-    CommandResult dismissResult = device.executeShellV2Command(dismissCommand);
-    if (dismissResult.getExitCode() != 0) {
-      LogUtil.CLog.d("Failed to dismiss Chrome dialogs");
-    }
-    LogUtil.CLog.d("Successfully dismissed initial Chrome Dialogs");
-  }
-
-  private void increaseSupportedUsers(ITestDevice device)
-      throws TargetSetupError, DeviceNotAvailableException {
-    LogUtil.CLog.d("Temporarily increasing maximum supported users to " + maxUsers);
-    String setMaxUsers = "setprop fw.max_users " + maxUsers;
-    CommandResult setMaxUsersResult = device.executeShellV2Command(setMaxUsers);
-    if (!CommandStatus.SUCCESS.equals(setMaxUsersResult.getStatus())) {
-      throw new TargetSetupError(
-          "Failed to increase the number of supported users", device.getDeviceDescriptor());
-    }
-    LogUtil.CLog.d("Successfully increased the maximum supported users");
-  }
-
-  private int createAndStartUser(ITestDevice device, int displayId)
-      throws TargetSetupError, DeviceNotAvailableException {
-    int userId = device.createUser(String.format("user-display-%d", displayId));
-    LogUtil.CLog.d(String.format("Created user with id %d for display %d", userId, displayId));
-    if (!device.startVisibleBackgroundUser(userId, displayId, true)) {
-      throw new TargetSetupError(
-          String.format("Device failed to switch to user %d", userId),
-          device.getDeviceDescriptor());
-    }
-    LogUtil.CLog.d(String.format("Started background user %d for display %d", userId, displayId));
-    return userId;
-  }
-
-  private void stopUsers(ITestDevice device) throws DeviceNotAvailableException {
-    LogUtil.CLog.d("Stopping all passenger users");
-    for (int userID : mDisplayToCreatedUsers.values()) {
-      String startUserCommand = String.format("am stop-user %d", userID);
-      CommandResult startUserResult = device.executeShellV2Command(startUserCommand);
-      if (startUserResult.getExitCode() != 0) {
-        LogUtil.CLog.d("Failed to stop the user: %d", userID);
-      }
-    }
-    LogUtil.CLog.d("Successfully stopped all passenger users");
-  }
-
-  private void installApk(TestInformation testInfo)
-      throws TargetSetupError, BuildError, DeviceNotAvailableException {
-    for (int userId : mDisplayToCreatedUsers.values()) {
-      TestAppInstallSetup installPreparer = new TestAppInstallSetup();
-      LogUtil.CLog.d(
-          String.format("Installing the following test APKs in user %d: \n%s", userId, mTestFiles));
-      installPreparer.setUserId(userId);
-      installPreparer.setShouldGrantPermission(true);
-      for (String file : mTestFiles) {
-        installPreparer.addTestFileName(file);
-      }
-      installPreparer.addInstallArg("-r");
-      installPreparer.addInstallArg("-d");
-      installPreparer.setUp(testInfo);
-      mInstallPreparers.add(installPreparer);
-    }
-  }
-
-  private void simulatePassengerLoad(ITestDevice device, int userId)
-      throws TargetSetupError, DeviceNotAvailableException {
-    LogUtil.CLog.d(
-        String.format("Launching the Youtube App for User: %d with url: %s", userId, mUrl));
-    String launchYoutubeWithUrlCommand =
-        String.format(
-            "am start --user %d -a android.intent.action.VIEW -e FullScreen true  -d "
-                + "\"%s\" %s",
-            userId, mUrl, mPackage);
-    LogUtil.CLog.d("Youtube launch command: %s", launchYoutubeWithUrlCommand);
-    CommandResult result = device.executeShellV2Command(launchYoutubeWithUrlCommand);
-    if (!CommandStatus.SUCCESS.equals(result.getStatus())) {
-      throw new TargetSetupError(
-          String.format("Failed to launch the Youtube app for the user %d", userId),
-          device.getDeviceDescriptor());
-    }
-    LogUtil.CLog.d("Successfully launched the Youtube video for user: %d", userId);
-  }
-
-  // Skips the Set-up wizard for all the passenger users.
-  private void skipSuw(ITestDevice device) throws DeviceNotAvailableException, TargetSetupError {
-    LogUtil.CLog.d("Skipping set-up wizard for all passenger users");
-    for (int userID : mDisplayToCreatedUsers.values()) {
-      String suwSkipCommand =
-          String.format(
-              "am start --user %d -n com.google.android.car.setupwizard/.ExitActivity", userID);
-      CommandResult suwSkipCommandResult = device.executeShellV2Command(suwSkipCommand);
-      if (suwSkipCommandResult.getExitCode() != 0) {
-        throw new TargetSetupError(
-            String.format("Failed to skip the set-up wizard for user: %d", userID),
-            device.getDeviceDescriptor());
-      }
-    }
-    LogUtil.CLog.d("Successfully skipped set-up wizard across all passenger users");
-  }
-
-  // Skips the Google Terms and Conditions for all the users. This would remove the restrictions
-  // enforced on GAS apps for all users.
-  private void skipGtos(ITestDevice device) throws DeviceNotAvailableException, TargetSetupError {
-    LogUtil.CLog.d("Skipping gTOS on behalf of all users");
-    if (!device.isAdbRoot()) {
-      device.enableAdbRoot();
-    }
-    List<String> gasPackageNames =
-        Arrays.asList(
-            "com.google.android.apps.maps",
-            "com.android.vending",
-            "com.google.android.carassistant",
-            mPackage,
-            "com.chrome.beta");
-    for (int userID : mDisplayToCreatedUsers.values()) {
-      for (String gasPackageName : gasPackageNames) {
-        String gTOSPmCommand = String.format("pm enable --user %d %s ", userID, gasPackageName);
-        CommandResult gTOSPmResult = device.executeShellV2Command(gTOSPmCommand);
-        if (gTOSPmResult.getExitCode() != 0) {
-          throw new TargetSetupError(
-              String.format(
-                  "Failed to skip gTOS for user: %d and package: %s", userID, gasPackageName),
-              device.getDeviceDescriptor());
-        }
-      }
-      String gTOSKeyUserCommand =
-          String.format(
-              "settings put secure --user %d android.car.KEY_USER_TOS_ACCEPTED 2 ", userID);
-      CommandResult gTOSKeyUserResult = device.executeShellV2Command(gTOSKeyUserCommand);
-      if (gTOSKeyUserResult.getExitCode() != 0) {
-        throw new TargetSetupError(
-            String.format("Failed to accept gTOS for user: %d", userID),
-            device.getDeviceDescriptor());
-      }
-    }
-    LogUtil.CLog.d("Successfully skipped gTOS across all passenger users");
-  }
-}
diff --git a/target_preparers/src/com/android/catbox/targetpreparer/YoutubeMdPassengerLoadPreparer.java b/target_preparers/src/com/android/catbox/targetpreparer/YoutubeMdPassengerLoadPreparer.java
new file mode 100644
index 0000000..22059ed
--- /dev/null
+++ b/target_preparers/src/com/android/catbox/targetpreparer/YoutubeMdPassengerLoadPreparer.java
@@ -0,0 +1,411 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+
+package com.android.catbox.targetpreparer;
+
+import com.android.tradefed.build.IBuildInfo;
+import com.android.tradefed.config.Option;
+import com.android.tradefed.config.OptionClass;
+import com.android.tradefed.device.CollectingOutputReceiver;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.invoker.TestInformation;
+import com.android.tradefed.log.LogUtil;
+import com.android.tradefed.result.error.DeviceErrorIdentifier;
+import com.android.tradefed.targetprep.BaseTargetPreparer;
+import com.android.tradefed.targetprep.BuildError;
+import com.android.tradefed.targetprep.TargetSetupError;
+import com.android.tradefed.targetprep.TestAppInstallSetup;
+import com.android.tradefed.util.CommandResult;
+import com.android.tradefed.util.CommandStatus;
+
+import java.io.ByteArrayOutputStream;
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.TimeUnit;
+import java.io.OutputStream;
+import java.io.File;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.HashMap;
+import java.util.List;
+import java.util.LinkedList;
+import java.util.Map;
+import java.util.Random;
+import java.util.Set;
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.TimeUnit;
+
+@OptionClass(alias = "youtube-md-passenger-load")
+public class YoutubeMdPassengerLoadPreparer extends BaseTargetPreparer {
+
+    @Option(name = "skip-display-ids", description = "Display IDs to skip passenger load for")
+    private List<Integer> mSkipDisplayIds = new ArrayList<>();
+
+    @Option(
+            name = "override-user-ids",
+            description = "Manually override the display IDS with pre-created users")
+    private String mOverrideUserIds = "";
+
+    @Option(
+            name = "skip-passenger-loading",
+            description = "Only create additional passenger users, skip loading them")
+    boolean skipPassengerLoading = false;
+
+    @Option(
+            name = "skip-driver-loading",
+            description = "Only load the passenger users, skip loading the driver")
+    boolean skipDriverLoading = true;
+
+    @Option(name = "post-test-cleanup", description = "Clean up users and uninstall test apks")
+    boolean postTestCleanup = false;
+
+    @Option(
+            name = "skip-device-setup",
+            description = "Skips exiting set-up wizard and accepting gTOS")
+    boolean skipDeviceSetup = false;
+
+    @Option(name = "urls", description = "Youtube video URLs separated by commas", mandatory = true)
+    private String mUrls;
+
+    @Option(name = "package", description = "Youtube package")
+    private String mPackage = "com.google.android.apps.automotive.youtube";
+
+    @Option(name = "install-apk", description = "Re-install a custom Youtube APK if necessary")
+    boolean mInstallYTApk = false;
+
+    @Option(name = "max-users", description = "Maximum number of users to support")
+    int maxUsers = 10;
+
+    @Option(
+            name = "test-app-file-name",
+            description = "full qualified path to the custom Youtube APK")
+    private List<String> mTestFiles = new ArrayList<>();
+
+    private HashMap<Integer, Integer> mDisplayToCreatedUsers = new HashMap<>();
+    private final ArrayList<TestAppInstallSetup> mInstallPreparers =
+            new ArrayList<TestAppInstallSetup>();
+    private int mYtLaunches = 0;
+
+    @Override
+    public void setUp(TestInformation testInfo)
+            throws TargetSetupError, BuildError, DeviceNotAvailableException {
+        try {
+            ITestDevice device = testInfo.getDevice();
+            increaseSupportedUsers(device);
+            if (mOverrideUserIds.length() == 0) {
+                Set<Integer> displayIds = device.listDisplayIdsForStartingVisibleBackgroundUsers();
+                for (Integer displayId : displayIds) {
+                    if (mSkipDisplayIds.contains(displayId)) {
+                        LogUtil.CLog.d("Skipping user creation for display %d", displayId);
+                        continue;
+                    }
+                    int userId = createAndStartUser(device, displayId);
+                    LogUtil.CLog.d(
+                            "Created and started new passenger user: %s on Display: %s",
+                            userId, displayId);
+                    mDisplayToCreatedUsers.put(displayId, userId);
+                }
+            } else {
+                int displayId = 1;
+                for (String userId : mOverrideUserIds.split(",")) {
+                    LogUtil.CLog.d(
+                            "Created and started new passenger user: %s on Display: %s",
+                            userId, displayId);
+                    mDisplayToCreatedUsers.put(displayId, Integer.parseInt(userId));
+                    displayId++;
+                }
+            }
+
+            // Assume current user is on the main display(this is needed for driver loading)
+            if (!skipDriverLoading) {
+                int currentUser = device.getCurrentUser();
+                LogUtil.CLog.d("Mapping current user %d to display 0", currentUser);
+                mDisplayToCreatedUsers.put(0, currentUser);
+            }
+
+            if (!skipDeviceSetup) {
+                deviceSetup(device);
+            }
+
+            if (!skipPassengerLoading && mInstallYTApk) {
+                installApk(testInfo);
+            }
+
+            for (Integer displayId : mDisplayToCreatedUsers.keySet()) {
+                int userId = mDisplayToCreatedUsers.get(displayId);
+                mYtLaunches = 0; // Reset retry counter for each new user's attempt
+                simulatePassengerLoad(device, userId);
+            }
+        } catch (TargetSetupError e) {
+            LogUtil.CLog.e("Set-up failed: " + e.getMessage());
+            try {
+                tearDown(testInfo, e);
+            } catch (DeviceNotAvailableException tearDownException) {
+                LogUtil.CLog.e("Teardown failed: " + tearDownException.getMessage());
+                e.addSuppressed(tearDownException);
+            }
+            throw new RuntimeException(e);
+        }
+    }
+
+    @Override
+    public void tearDown(TestInformation testInfo, Throwable e) throws DeviceNotAvailableException {
+        ITestDevice device = testInfo.getDevice();
+        if (!skipPassengerLoading) {
+            stopTestApps(device);
+        }
+
+        stopUsers(device);
+
+        if (postTestCleanup) {
+            // Remove all the passenger users
+            for (int userId : mDisplayToCreatedUsers.values()) {
+                LogUtil.CLog.d("Removing user: %s", userId);
+                device.removeUser(userId);
+            }
+        }
+        device.reboot();
+    }
+
+    private void deviceSetup(ITestDevice device)
+            throws TargetSetupError, DeviceNotAvailableException {
+        skipGtos(device);
+        skipSuw(device);
+    }
+
+    private void stopTestApps(ITestDevice device) throws DeviceNotAvailableException {
+        LogUtil.CLog.d("Stopping the Youtube application for all the passengers");
+        for (int userID : mDisplayToCreatedUsers.values()) {
+            String stopYoutube = String.format("am force-stop --user %d %s", userID, mPackage);
+            CommandResult stopYoutubeResult = device.executeShellV2Command(stopYoutube);
+            if (stopYoutubeResult.getExitCode() != 0) {
+                LogUtil.CLog.d("Failed to kill the Youtube application for user: %d", userID);
+            }
+        }
+    }
+
+    private void increaseSupportedUsers(ITestDevice device)
+            throws TargetSetupError, DeviceNotAvailableException {
+        LogUtil.CLog.d("Temporarily increasing maximum supported users to " + maxUsers);
+        String setMaxUsers = "setprop fw.max_users " + maxUsers;
+        CommandResult setMaxUsersResult = device.executeShellV2Command(setMaxUsers);
+        if (!CommandStatus.SUCCESS.equals(setMaxUsersResult.getStatus())) {
+            throw new TargetSetupError(
+                    "Failed to increase the number of supported users",
+                    device.getDeviceDescriptor());
+        }
+        LogUtil.CLog.d("Successfully increased the maximum supported users");
+    }
+
+    private int createAndStartUser(ITestDevice device, int displayId)
+            throws TargetSetupError, DeviceNotAvailableException {
+        int userId = device.createUser(String.format("user-display-%d", displayId));
+        LogUtil.CLog.d(String.format("Created user with id %d for display %d", userId, displayId));
+        if (!device.startVisibleBackgroundUser(userId, displayId, true)) {
+            throw new TargetSetupError(
+                    String.format("Device failed to switch to user %d", userId),
+                    device.getDeviceDescriptor());
+        }
+        LogUtil.CLog.d(
+                String.format("Started background user %d for display %d", userId, displayId));
+        return userId;
+    }
+
+    private void stopUsers(ITestDevice device) throws DeviceNotAvailableException {
+        LogUtil.CLog.d("Stopping all passenger users");
+        for (int userID : mDisplayToCreatedUsers.values()) {
+            String startUserCommand = String.format("am stop-user %d", userID);
+            CommandResult startUserResult = device.executeShellV2Command(startUserCommand);
+            if (startUserResult.getExitCode() != 0) {
+                LogUtil.CLog.d("Failed to stop the user: %d", userID);
+            }
+        }
+        LogUtil.CLog.d("Successfully stopped all passenger users");
+    }
+
+    private void installApk(TestInformation testInfo)
+            throws TargetSetupError, BuildError, DeviceNotAvailableException {
+        for (int userId : mDisplayToCreatedUsers.values()) {
+            TestAppInstallSetup installPreparer = new TestAppInstallSetup();
+            LogUtil.CLog.d(
+                    String.format(
+                            "Installing the following test APKs in user %d: \n%s",
+                            userId, mTestFiles));
+            installPreparer.setUserId(userId);
+            installPreparer.setShouldGrantPermission(true);
+            for (String file : mTestFiles) {
+                installPreparer.addTestFileName(file);
+            }
+            installPreparer.addInstallArg("-r");
+            installPreparer.addInstallArg("-d");
+            installPreparer.setUp(testInfo);
+            mInstallPreparers.add(installPreparer);
+        }
+    }
+
+    private void simulatePassengerLoad(ITestDevice device, int userId)
+            throws TargetSetupError, DeviceNotAvailableException {
+        String youtubeUrl =
+                mUrls.split(",").length == 0
+                        ? null
+                        : new Random()
+                                .ints(0, mUrls.split(",").length)
+                                .limit(1)
+                                .mapToObj(index -> mUrls.split(",")[index])
+                                .findFirst()
+                                .orElse(null);
+        LogUtil.CLog.d(
+                String.format(
+                        "Launching the Youtube App for User: %d with url: %s", userId, youtubeUrl));
+        launchYoutube(device, userId, youtubeUrl);
+    }
+
+    private void launchYoutube(ITestDevice device, int userId, String url)
+            throws TargetSetupError, DeviceNotAvailableException {
+        String launchYoutubeWithUrlCommand =
+                String.format(
+                        "am start --user %d -a android.intent.action.VIEW -e FullScreen true  -d "
+                                + "\"%s\" %s",
+                        userId, url, mPackage);
+        LogUtil.CLog.d("Youtube launch command: %s", launchYoutubeWithUrlCommand);
+        CommandResult result = device.executeShellV2Command(launchYoutubeWithUrlCommand);
+        if (!CommandStatus.SUCCESS.equals(result.getStatus())) {
+            throw new TargetSetupError(
+                    String.format("Failed to launch the Youtube app for the user %d", userId),
+                    device.getDeviceDescriptor());
+        }
+        try {
+            CountDownLatch latch = new CountDownLatch(1);
+            latch.await(5, TimeUnit.SECONDS);
+        } catch (InterruptedException e) {
+            throw new TargetSetupError(
+                    String.format("Thread interrupted while launching Youtube for user %d", userId),
+                    e,
+                    DeviceErrorIdentifier.DEVICE_UNAVAILABLE);
+        }
+        boolean isYoutubeLaunched = isYoutubeLaunchedForUser(device, userId);
+        if (!isYoutubeLaunched) {
+            retryYoutubeLaunch(device, userId);
+        } else {
+            LogUtil.CLog.d("Successfully launched the Youtube video for user: %d", userId);
+        }
+    }
+
+    private void retryYoutubeLaunch(ITestDevice device, int userId)
+            throws TargetSetupError, DeviceNotAvailableException {
+        if (mYtLaunches < 2) {
+            LogUtil.CLog.d(
+                    "Custom Youtube app launch check failed for the user %d, retrying...", userId);
+            mYtLaunches++;
+            try {
+                simulatePassengerLoad(device, userId);
+            } catch (TargetSetupError | DeviceNotAvailableException e) {
+                throw new TargetSetupError(
+                        String.format(
+                                "Custom Youtube app launch check failed for the user %d after"
+                                        + " retry",
+                                userId),
+                        e,
+                        device.getDeviceDescriptor());
+            }
+        } else {
+            throw new TargetSetupError(
+                    String.format("Custom Youtube app launch check failed for the user %d", userId),
+                    device.getDeviceDescriptor());
+        }
+    }
+
+    private boolean isYoutubeLaunchedForUser(ITestDevice device, int userId)
+            throws TargetSetupError, DeviceNotAvailableException {
+        LogUtil.CLog.d(
+                String.format("Checking if the Youtube App is launched for User: %d", userId));
+        String checkYoutubeLaunchedCommand =
+                String.format(
+                        "ps -efw | grep -i %s | awk -F'_' '{print $1}' | grep u%d",
+                        mPackage, userId);
+        LogUtil.CLog.d("Running the command: %s", checkYoutubeLaunchedCommand);
+        CommandResult result = device.executeShellV2Command(checkYoutubeLaunchedCommand);
+        LogUtil.CLog.d("Full check command output is %s", result.getStdout());
+        String output =
+                result.getStdout().split("\n").length > 0
+                        ? result.getStdout().split("\n")[0].replaceAll("[^0-9]", "")
+                        : ""; // 11
+        if (result.getExitCode() != 0
+                || output.length() == 0
+                || userId != Integer.parseInt(output)) {
+            return false;
+        } else {
+            mYtLaunches = 0;
+            return true;
+        }
+    }
+
+    // Skips the Set-up wizard for all the passenger users.
+    private void skipSuw(ITestDevice device) throws DeviceNotAvailableException, TargetSetupError {
+        LogUtil.CLog.d("Skipping set-up wizard for all passenger users");
+        for (int displayID : mDisplayToCreatedUsers.keySet()) {
+            String suwSkipCommand =
+                    String.format(
+                            "am start --user %d --display %d -n"
+                                    + " com.google.android.car.setupwizard/.ExitActivity",
+                            mDisplayToCreatedUsers.get(displayID), displayID);
+            CommandResult suwSkipCommandResult = device.executeShellV2Command(suwSkipCommand);
+            if (suwSkipCommandResult.getExitCode() != 0) {
+                throw new TargetSetupError(
+                        String.format(
+                                "Failed to skip the set-up wizard for user: %d and display: %d",
+                                mDisplayToCreatedUsers.get(displayID), displayID),
+                        device.getDeviceDescriptor());
+            }
+        }
+        LogUtil.CLog.d("Successfully skipped set-up wizard across all passenger users");
+    }
+
+    // Skips the Google Terms and Conditions and Set-up wizard for all the users.
+    private void skipGtos(ITestDevice device) throws DeviceNotAvailableException, TargetSetupError {
+        LogUtil.CLog.d("Skipping gTOS on behalf of all users");
+        if (!device.isAdbRoot()) {
+            device.enableAdbRoot();
+        }
+        for (int userID : mDisplayToCreatedUsers.values()) {
+            String gTOSPmCommand =
+                    String.format(
+                            "am broadcast --user %d -a"
+                                    + " com.google.android.setupservices.GOOGLE_SERVICES_ACCEPTED"
+                                    + " com.google.android.gms ",
+                            userID);
+            CommandResult gTOSPmResult = device.executeShellV2Command(gTOSPmCommand);
+            if (gTOSPmResult.getExitCode() != 0) {
+                throw new TargetSetupError(
+                        String.format("Failed to skip gTOS for user: %d", userID),
+                        device.getDeviceDescriptor());
+            }
+
+            String gTOSKeyUserCommand =
+                    String.format(
+                            "settings put secure --user %d"
+                                    + " android.car.ENABLE_INITIAL_NOTICE_SCREEN_TO_USER 0 ",
+                            userID);
+            CommandResult gTOSKeyUserResult = device.executeShellV2Command(gTOSKeyUserCommand);
+            if (gTOSKeyUserResult.getExitCode() != 0) {
+                throw new TargetSetupError(
+                        String.format("Failed to accept gTOS for user: %d", userID),
+                        device.getDeviceDescriptor());
+            }
+        }
+        LogUtil.CLog.d("Successfully skipped gTOS for all passenger users");
+    }
+}
diff --git a/tools/catbox-common/res/config/catbox-performance-base.xml b/tools/catbox-common/res/config/catbox-performance-base.xml
index ee5fc88..ad13b64 100644
--- a/tools/catbox-common/res/config/catbox-performance-base.xml
+++ b/tools/catbox-common/res/config/catbox-performance-base.xml
@@ -39,19 +39,25 @@
         <option name="dest-dir" value="report-log-files/"/>
         <option name="temp-dir" value="temp-report-logs/"/>
     </target_preparer>
-    <target_preparer class="com.android.catbox.targetpreparer.ChromeMdPassengerLoadPreparer">
+    <target_preparer class="com.android.catbox.targetpreparer.YoutubeMdPassengerLoadPreparer">
         <option name="disable" value="true"/>
         <option name="skip-passenger-loading" value="false"/>
         <option name="max-users" value="10"/>
         <option name="post-test-cleanup" value="true"/>
-        <option name="url" value="https://youtu.be/YB8BX0Pt1Lk?si=k7Sbae9AAj4lU6-7"/>
+        <option name="urls" value="https://youtu.be/u-ENQiXgukU?si=5fIAOwTyaOqrvPKL, https://youtu.be/uK7XTwbx5PQ?si=livI7rt6kVPwMz72, https://www.youtube.com/live/u79zKRZiGtU?si=CLjpvhP2By1xyFQx, https://youtu.be/CRw1raqz6nE?si=_uenzqVkQhTzn51d, https://www.youtube.com/live/F3z8tqfSs2I?si=7oIDJuc5_t8_JoB7, https://youtu.be/IApvC32Lmn8?si=YrV6r15BsZY006CA, https://www.youtube.com/live/X0AzBQrAJoM?si=n_d--iEiqKRBIFEI, https://youtu.be/S9-tw35hCsg?si=L-igCZbTkeZNYYs8, https://youtu.be/p296ksiDBb8?si=J8d38p05cc8vPr9s, https://youtu.be/RwK5pQtoVjM?si=WqcMnNSsSp1vb4B5"/>
         <option name="install-apk" value="false"/>
     </target_preparer>
 
     <!-- Enable perfetto host side metric collector -->
     <metrics_collector class="com.android.tradefed.device.metric.PerfettoPullerMetricCollector">
         <option name="collect-on-run-ended-only" value="false" />
-        <option name="pull-pattern-keys" value="perfetto_file_path" />
+        <option name="pull-pattern-keys" value="^perfetto_file_path(_\d+)?$" />
         <option name="trace-processor-run-metrics" value="android_mem,android_auto_multiuser,android_monitor_contention,android_monitor_contention_agg,android_binder,android_boot,android_startup,android_jank_cuj,android_frame_timeline_metric,android_app_process_starts,android_boot_unagg,android_garbage_collection_unagg,android_io" />
     </metrics_collector>
+
+    <metrics_collector class="com.android.tradefed.device.metric.FilePullerLogCollector">
+        <option name="collect-on-run-ended-only" value="false"/>
+        <!-- Passing case already collected by PerfettoPullerMetricCollector -->
+        <option name="pull-pattern-keys" value="^perfetto_file_path_FAILED(_\d+)?$"/>
+    </metrics_collector>
 </configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-multiuser.xml b/tools/catbox-tradefed/res/config/catbox-functional-multiuser.xml
index 862af6a..612a775 100644
--- a/tools/catbox-tradefed/res/config/catbox-functional-multiuser.xml
+++ b/tools/catbox-tradefed/res/config/catbox-functional-multiuser.xml
@@ -42,4 +42,6 @@
   <option name="compatibility:include-filter" value="AndroidAutomotiveMultiuserTests android.platform.tests.SwitchUserQuickSettings" />
   <option name="compatibility:include-filter" value="AndroidAutomotiveMultiuserTests android.platform.tests.DeleteGuestSelfNotAllowed" />
   <option name="compatibility:include-filter" value="AndroidAutomotiveMultiuserTests android.platform.tests.EditAdminName" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveMultiuserTests android.platform.tests.GuestUserSettings" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveMultiuserTests android.platform.tests.NonAdminUserSettings" />
 </configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-status-bar-palette.xml b/tools/catbox-tradefed/res/config/catbox-functional-status-bar-palette.xml
new file mode 100644
index 0000000..73ccfef
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-functional-status-bar-palette.xml
@@ -0,0 +1,41 @@
+<!--
+ Copyright (C) 2023 Google Inc.
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
+  <option name="plan" value="catbox-functional-status-bar-palette" />
+  <!-- Test Args -->
+  <option name="compatibility:test-arg"
+      value="com.android.tradefed.testtype.AndroidJUnitTest:runner:androidx.test.runner.AndroidJUnitRunner" />
+  <option name="compatibility:test-arg"
+      value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.tests" />
+  <option name="compatibility:test-arg"
+      value="com.android.tradefed.testtype.AndroidJUnitTest:no-rerun:true" />
+  <!-- Tests -->
+  <option name="compatibility:include-filter"
+      value="AndroidAutomotiveStatusBarTests android.platform.tests.BluetoothPaletteTest" />
+  <option name="compatibility:include-filter"
+      value="AndroidAutomotiveNavigationBarTests android.platform.tests.BrightnessPaletteTest" />
+  <option name="compatibility:include-filter"
+      value="AndroidAutomotiveStatusBarTests android.platform.tests.NetworkPaletteTest" />
+  <option name="compatibility:include-filter"
+      value="AndroidAutomotiveStatusBarTests android.platform.tests.StatusBarTest" />
+  <option name="compatibility:include-filter"
+      value="AndroidAutomotiveStatusBarTests android.platform.tests.SoundPaletteTest" />
+  <option name="compatibility:include-filter"
+      value="AndroidAutomotiveStatusBarTests android.platform.tests.CurrentDateTimeTest" />
+</configuration>
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-unified-privacy-setting.xml b/tools/catbox-tradefed/res/config/catbox-functional-unified-privacy-setting.xml
new file mode 100644
index 0000000..cc6cd77
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-functional-unified-privacy-setting.xml
@@ -0,0 +1,35 @@
+<!--
+ Copyright (C) 2023 Google Inc.
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
+<configuration description="Complete Automotive Tests - Privacy Setting Functional Tests.">
+  <!-- Common Base -->
+  <include name="catbox-common"/>
+
+  <!-- Device Preparers -->
+  <include name="catbox-preparer"/>
+
+  <!-- Plan -->
+  <option name="plan" value="catbox-functional-unified-privacy-setting"/>
+
+  <!-- Test Args -->
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:runner:androidx.test.runner.AndroidJUnitRunner" />
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.tests" />
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:no-rerun:true" />
+
+  <!-- Tests -->
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.PrivacyPermissionManagerTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.PrivacySettingVerifyUIElementsTest" />
+</configuration>
+
diff --git a/tools/catbox-tradefed/res/config/catbox-functional-unified-setting.xml b/tools/catbox-tradefed/res/config/catbox-functional-unified-setting.xml
new file mode 100644
index 0000000..bf895da
--- /dev/null
+++ b/tools/catbox-tradefed/res/config/catbox-functional-unified-setting.xml
@@ -0,0 +1,42 @@
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
+<configuration description="Complete Automotive Tests - Setting Functional Tests.">
+  <!-- Common Base -->
+  <include name="catbox-common"/>
+
+  <!-- Device Preparers -->
+  <include name="catbox-preparer"/>
+
+  <!-- Plan -->
+  <option name="plan" value="catbox-functional-unified-setting"/>
+
+  <!-- Test Args -->
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:runner:androidx.test.runner.AndroidJUnitRunner" />
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:package:android.platform.tests" />
+  <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:no-rerun:true" />
+
+  <!-- Tests -->
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.SettingTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.SettingSearchTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.AppInfoSettingTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.AppInfoVerifyUIElementsTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.DisplaySettingTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.WifiSettingTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.SystemSettingVerifyUIElementsTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.SystemSettingTest" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.EnableDevelopersOption" />
+  <option name="compatibility:include-filter" value="AndroidAutomotiveSettingsTests android.platform.tests.StorageSettingTest" />
+</configuration>
\ No newline at end of file
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml
index 4e1162d..af194cd 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-dialer.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=4.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- Total PSS Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:totalpss-collector:process-names:=com.android.car.dialer" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml
index 83e7341..bd6ca82 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-mediacenter.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=4.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- Total PSS Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:totalpss-collector:process-names:=com.android.car.media"/>
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml
index bf323bb..c15d5bb 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-cold-app-start-up-settings.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=4.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- Total PSS Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:totalpss-collector:process-names:=com.android.car.settings" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-dialer.xml b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-dialer.xml
index 647f03c..5d0a8a4 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-dialer.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-dialer.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=4.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- App Start Up Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-mediacenter.xml b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-mediacenter.xml
index 145beee..53fca4f 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-mediacenter.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-mediacenter.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=4.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- App Start Up Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-settings.xml b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-settings.xml
index 9006def..8cf2c1c 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-settings.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-hot-app-start-up-settings.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=4.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- App Start Up Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.AppStartupListener" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-appgrid.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-appgrid.xml
index f263ff2..c34224b 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-appgrid.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-appgrid.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=2.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- Jank Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveAppGridScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-contact-list.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-contact-list.xml
index ee6b6ab..71cf197 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-contact-list.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-contact-list.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=2.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- Jank Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveDialScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-media-switch-playback.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-media-switch-playback.xml
index aa6c36c..3aa8afd 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-media-switch-playback.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-media-switch-playback.xml
@@ -25,7 +25,7 @@
     <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
     <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
     <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=2.0" />
-    <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+    <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
     <!-- Jank Options -->
     <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-media.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-media.xml
index 825e0de..fffa49c 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-media.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-media.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=2.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- Jank Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveMediaCenterScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-notifications.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-notifications.xml
index 598f79c..f555310 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-notifications.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-notifications.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=2.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- Jank Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveNotificationScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
diff --git a/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml b/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml
index 23719b1..466ef73 100644
--- a/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml
+++ b/tools/catbox-tradefed/res/config/catbox-performance-jank-settings.xml
@@ -24,7 +24,7 @@
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:per_run:=true" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-interval:=20000" />
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-threshold:=2.0" />
-  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=900000" />
+  <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:procload-collector:proc-loadavg-timeout:=200000" />
 
   <!-- Jank Options -->
   <option name="compatibility:module-arg" value="AndroidAutomotiveSettingsScenarioTests:instrumentation-arg:listener:=android.device.collectors.PerfettoListener,android.device.collectors.ProcLoadListener,android.device.collectors.JankListener" />
```

