```diff
diff --git a/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java b/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
index b9dbf71..27c192e 100644
--- a/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
+++ b/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
@@ -18,10 +18,9 @@ package com.android.csuite.core;
 
 import com.android.csuite.core.ApkInstaller.ApkInstallerException;
 import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
-import com.android.csuite.core.DeviceUtils.DropboxEntry;
+import com.android.csuite.core.DropboxEntryCrashDetector.DropboxEntry;
 import com.android.csuite.core.TestUtils.RoboscriptSignal;
 import com.android.csuite.core.TestUtils.TestUtilsException;
-import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.log.LogUtil.CLog;
@@ -49,6 +48,7 @@ import java.nio.file.Path;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
+import java.util.Locale;
 import java.util.Optional;
 import java.util.concurrent.atomic.AtomicReference;
 import java.util.regex.Matcher;
@@ -56,69 +56,57 @@ import java.util.regex.Pattern;
 import java.util.stream.Collectors;
 import java.util.stream.Stream;
 
-
 /** A tester that interact with an app crawler during testing. */
 public final class AppCrawlTester {
     @VisibleForTesting Path mOutput;
     private final RunUtilProvider mRunUtilProvider;
     private final TestUtils mTestUtils;
-    private final String mPackageName;
-    private FileSystem mFileSystem;
+    private final ApkInstaller mApkInstaller;
+    private final FileSystem mFileSystem;
     private DeviceTimestamp mScreenRecordStartTime;
-    private IConfiguration mConfiguration;
-    private ApkInstaller mApkInstaller;
-    private ExecutionStage mExecutionStage = new ExecutionStage();
+    private final ExecutionStage mExecutionStage = new ExecutionStage();
+    private boolean mNoThrowOnFailure = false;
+    private AppCrawlTesterOptions mConfigOptions;
+    private AutoFDOProfileCollector mAutoFDOProfileCollector;
 
     /**
      * Creates an {@link AppCrawlTester} instance.
      *
-     * @param packageName The package name of the apk files.
      * @param testInformation The TradeFed test information.
      * @param testLogData The TradeFed test output receiver.
      * @return an {@link AppCrawlTester} instance.
+     * @throws CrawlerException
      */
     public static AppCrawlTester newInstance(
-            String packageName,
-            TestInformation testInformation,
-            TestLogData testLogData,
-            IConfiguration configuration) {
+            TestInformation testInformation, TestLogData testLogData) throws CrawlerException {
+        TestUtils testUtils = TestUtils.getInstance(testInformation, testLogData);
         return new AppCrawlTester(
-                packageName,
-                TestUtils.getInstance(testInformation, testLogData),
+                testUtils,
                 () -> new RunUtil(),
                 FileSystems.getDefault(),
-                configuration);
+                ApkInstaller.getInstance(testUtils.getDeviceUtils().getITestDevice()));
     }
 
     @VisibleForTesting
     AppCrawlTester(
-            String packageName,
             TestUtils testUtils,
             RunUtilProvider runUtilProvider,
             FileSystem fileSystem,
-            IConfiguration configuration) {
+            ApkInstaller apkInstaller)
+            throws CrawlerException {
         mRunUtilProvider = runUtilProvider;
-        mPackageName = packageName;
         mTestUtils = testUtils;
         mFileSystem = fileSystem;
-        mConfiguration = configuration;
+        mApkInstaller = apkInstaller;
+        loadConfigOptions();
     }
 
-    /** Returns the options object for the app crawl tester */
-    public AppCrawlTesterOptions getOptions() {
-        List<?> configurations =
-                mConfiguration.getConfigurationObjectList(AppCrawlTesterOptions.OBJECT_TYPE);
-        Preconditions.checkNotNull(
-                configurations,
-                "Expecting a "
-                        + ModuleInfoProvider.MODULE_INFO_PROVIDER_OBJECT_TYPE
-                        + " in the module configuration.");
-        Preconditions.checkArgument(
-                configurations.size() == 1,
-                "Expecting exactly 1 instance of "
-                        + ModuleInfoProvider.MODULE_INFO_PROVIDER_OBJECT_TYPE
-                        + " in the module configuration.");
-        return (AppCrawlTesterOptions) configurations.get(0);
+    /** Loads the config options for the app crawl tester. */
+    private void loadConfigOptions() throws CrawlerException {
+        if (mConfigOptions != null) {
+            return;
+        }
+        mConfigOptions = AppCrawlTesterOptions.load(mTestUtils.getTestInformation(), mFileSystem);
     }
 
     /** An exception class representing crawler test failures. */
@@ -128,7 +116,7 @@ public final class AppCrawlTester {
          *
          * @param message A error message describing the cause of the error.
          */
-        private CrawlerException(String message) {
+        CrawlerException(String message) {
             super(message);
         }
 
@@ -138,7 +126,7 @@ public final class AppCrawlTester {
          * @param message A detailed error message.
          * @param cause A {@link Throwable} capturing the original cause of the CrawlerException.
          */
-        private CrawlerException(String message, Throwable cause) {
+        CrawlerException(String message, Throwable cause) {
             super(message, cause);
         }
 
@@ -147,7 +135,7 @@ public final class AppCrawlTester {
          *
          * @param cause A {@link Throwable} capturing the original cause of the CrawlerException.
          */
-        private CrawlerException(Throwable cause) {
+        CrawlerException(Throwable cause) {
             super(cause);
         }
     }
@@ -158,17 +146,14 @@ public final class AppCrawlTester {
      * <p>Test won't run if setup failed, and teardown will always run.
      *
      * @throws DeviceNotAvailableException when the device is lost.
-     * @throws CrawlerException when unexpected happened.
-     * @throws IOException
-     * @throws ApkInstallerException
+     * @throws CrawlerException when apk failed to install or unexpected happened.
      */
-    public void run()
-            throws DeviceNotAvailableException,
-                    CrawlerException,
-                    ApkInstallerException,
-                    IOException {
+    public void run() throws DeviceNotAvailableException, CrawlerException {
         try {
             runSetup();
+            if (!isSetupComplete()) {
+                CLog.i("Skipping test run as setup failed.");
+            }
             runTest();
         } finally {
             runTearDown();
@@ -179,55 +164,96 @@ public final class AppCrawlTester {
      * Runs only the setup step of the crawl test.
      *
      * @throws DeviceNotAvailableException when the device is lost.
-     * @throws IOException when IO operations fail.
-     * @throws ApkInstallerException when APK installation fails.
+     * @throws CrawlerException when APK installation fails.
      */
-    public void runSetup() throws DeviceNotAvailableException, ApkInstallerException, IOException {
+    public void runSetup() throws DeviceNotAvailableException, CrawlerException {
+        Preconditions.checkNotNull(
+                mConfigOptions.getSubjectPackageName(), "Package name cannot be null");
         // For Espresso mode, checks that a path with the location of the apk to repackage was
         // provided
-        if (!getOptions().isUiAutomatorMode()) {
+        if (mConfigOptions.isEspressoMode()) {
             Preconditions.checkNotNull(
-                    getOptions().getRepackApk(),
-                    "Apk file path is required when not running in UIAutomator mode");
+                    mConfigOptions.getSubjectApkPath(),
+                    "Subject apk path is required when not running in UIAutomator mode");
         }
 
-        mApkInstaller = ApkInstaller.getInstance(mTestUtils.getDeviceUtils().getITestDevice());
-        mApkInstaller.install(
-                getOptions().getInstallApkPaths().stream()
-                        .map(File::toPath)
-                        .collect(Collectors.toList()),
-                getOptions().getInstallArgs());
+        try {
+            mApkInstaller.install(
+                    mConfigOptions.getExtraApkPaths().stream()
+                            .map(file -> mFileSystem.getPath(file.getPath()))
+                            .collect(Collectors.toList()),
+                    mConfigOptions.getExtraApkInstallArgs());
+            File subjectApkPath = mConfigOptions.getSubjectApkPath();
+            if (subjectApkPath != null) {
+                mApkInstaller.install(
+                        mFileSystem.getPath(subjectApkPath.getPath()),
+                        mConfigOptions.getSubjectApkInstallArgs());
+            }
+        } catch (ApkInstallerException | IOException e) {
+            if (!mNoThrowOnFailure) {
+                throw new CrawlerException(e);
+            }
+            mExecutionStage.addFailureMessage(e.getMessage());
+            return;
+        }
 
         // Grant external storage permission
-        if (getOptions().isGrantExternalStoragePermission()) {
-            mTestUtils.getDeviceUtils().grantExternalStoragePermissions(mPackageName);
+        if (mConfigOptions.isGrantExternalStoragePermission()) {
+            mTestUtils
+                    .getDeviceUtils()
+                    .grantExternalStoragePermissions(mConfigOptions.getSubjectPackageName());
+        }
+
+        String[] unlockScreenCmd =
+                new String[] {
+                    "input keyevent KEYCODE_WAKEUP",
+                    "input keyevent KEYCODE_WAKEUP",
+                    "input keyevent KEYCODE_MENU"
+                };
+        for (String cmd : unlockScreenCmd) {
+            mTestUtils.getDeviceUtils().getITestDevice().executeShellV2Command(cmd);
         }
+        if (mConfigOptions.isCollectAutoFDOProfile()) {
+            mAutoFDOProfileCollector =
+                    new AutoFDOProfileCollector(
+                            mTestUtils.getDeviceUtils().getITestDevice(), mRunUtilProvider);
+        }
+
         mExecutionStage.setSetupComplete(true);
     }
 
     /** Runs only the teardown step of the crawl test. */
     public void runTearDown() {
+        if (mConfigOptions.isCollectAutoFDOProfile()) {
+            try {
+                mAutoFDOProfileCollector.collectAutoFDOProfile(
+                        mTestUtils.getTestArtifactReceiver());
+            } catch (DeviceNotAvailableException e) {
+                CLog.e("AutoFDO profile collection failed during teardown: %s", e.getMessage());
+            }
+        }
+
+        List<File> apksToSave = new ArrayList<>(mConfigOptions.getExtraApkPaths());
+        if (mConfigOptions.getSubjectApkPath() != null) {
+            apksToSave.add(mConfigOptions.getSubjectApkPath());
+        }
         mTestUtils.saveApks(
-                getOptions().getSaveApkWhen(),
+                mConfigOptions.getSaveApkWhen(),
                 mExecutionStage.isTestPassed(),
-                mPackageName,
-                getOptions().getInstallApkPaths());
-        if (getOptions().getRepackApk() != null) {
-            mTestUtils.saveApks(
-                    getOptions().getSaveApkWhen(),
-                    mExecutionStage.isTestPassed(),
-                    mPackageName,
-                    Arrays.asList(getOptions().getRepackApk()));
-        }
+                mConfigOptions.getSubjectPackageName(),
+                apksToSave);
 
         try {
             mApkInstaller.uninstallAllInstalledPackages();
         } catch (ApkInstallerException e) {
             CLog.e("Uninstallation of installed apps failed during teardown: %s", e.getMessage());
         }
-        if (!getOptions().isUiAutomatorMode()) {
+        if (mConfigOptions.isEspressoMode()) {
             try {
-                mTestUtils.getDeviceUtils().getITestDevice().uninstallPackage(mPackageName);
+                mTestUtils
+                        .getDeviceUtils()
+                        .getITestDevice()
+                        .uninstallPackage(mConfigOptions.getSubjectPackageName());
             } catch (DeviceNotAvailableException e) {
                 CLog.e(
                         "Uninstallation of installed apps failed during teardown: %s",
@@ -246,7 +272,7 @@ public final class AppCrawlTester {
      */
     public void runTest() throws DeviceNotAvailableException, CrawlerException {
         if (!mExecutionStage.isSetupComplete()) {
-            throw new CrawlerException("Crawler setup has not run.");
+            throw new CrawlerException("Crawler setup has not run successfully.");
         }
         if (mExecutionStage.isTestExecuted()) {
             throw new CrawlerException(
@@ -266,42 +292,35 @@ public final class AppCrawlTester {
         }
         DeviceTimestamp endTime = mTestUtils.getDeviceUtils().currentTimeMillis();
 
-        ArrayList<String> failureMessages = new ArrayList<>();
-
         try {
-
             List<DropboxEntry> crashEntries =
                     mTestUtils
                             .getDeviceUtils()
-                            .getDropboxEntries(
-                                    DeviceUtils.DROPBOX_APP_CRASH_TAGS,
-                                    mPackageName,
-                                    startTime,
-                                    endTime);
+                            .getCrashEntriesFromDropbox(
+                                    mConfigOptions.getSubjectPackageName(), startTime, endTime);
             String dropboxCrashLog =
                     mTestUtils.compileTestFailureMessage(
-                            mPackageName, crashEntries, true, mScreenRecordStartTime);
+                            mConfigOptions.getSubjectPackageName(),
+                            crashEntries,
+                            true,
+                            mScreenRecordStartTime);
 
-            if (dropboxCrashLog != null) {
+            if (!dropboxCrashLog.isBlank()) {
                 // Put dropbox crash log on the top of the failure messages.
-                failureMessages.add(dropboxCrashLog);
+                mExecutionStage.addFailureMessage(dropboxCrashLog);
             }
         } catch (IOException e) {
-            failureMessages.add("Error while getting dropbox crash log: " + e.getMessage());
+            mExecutionStage.addFailureMessage(
+                    "Error while getting dropbox crash log: " + e.getMessage());
         }
 
         if (crawlerException != null) {
-            failureMessages.add(crawlerException.getMessage());
+            mExecutionStage.addFailureMessage(crawlerException.getMessage());
         }
 
-        if (!failureMessages.isEmpty()) {
-            Assert.fail(
-                    String.join(
-                            "\n============\n",
-                            failureMessages.toArray(new String[failureMessages.size()])));
+        if (!isTestPassed() && !mNoThrowOnFailure) {
+            Assert.fail(getFailureMessage());
         }
-
-        mExecutionStage.setTestPassed(true);
     }
 
     /**
@@ -332,8 +351,6 @@ public final class AppCrawlTester {
         AtomicReference<String[]> command = new AtomicReference<>();
         AtomicReference<CommandResult> commandResult = new AtomicReference<>();
 
-        CLog.d("Start to crawl package: %s.", mPackageName);
-
         Path bin =
                 mFileSystem.getPath(
                         AppCrawlTesterHostPreparer.getCrawlerBinPath(
@@ -357,32 +374,43 @@ public final class AppCrawlTester {
                     "Crawler executable binaries not found in " + bin.toString());
         }
 
-        if (getOptions().isCollectGmsVersion()) {
-            mTestUtils.collectGmsVersion(mPackageName);
+        if (mConfigOptions.isCollectGmsVersion()) {
+            mTestUtils.collectGmsVersion(mConfigOptions.getSubjectPackageName());
+        }
+
+        if (mConfigOptions.isCollectAutoFDOProfile()
+                && !mAutoFDOProfileCollector.recordAutoFDOProfile(
+                        mConfigOptions.getCrawlDurationSec())) {
+            CLog.e("Failed to record AutoFDO profile");
         }
 
-        // Minimum timeout 3 minutes plus crawl test timeout.
-        long commandTimeout = 3L * 60 * 1000 + getOptions().getTimeoutSec() * 1000;
+        // Minimum timeout 3 minutes plus crawl test timeout. In espresso mode, extend the timeout
+        // for another 3 minutes for apk recompile and OBB upload
+        long commandTimeout =
+                3L * 60 * 1000
+                        + mConfigOptions.getCrawlDurationSec() * 1000L
+                        + (mConfigOptions.isEspressoMode() ? 3L * 60 * 1000 : 0);
 
         CLog.i(
                 "Starting to crawl the package %s with command %s",
-                mPackageName, String.join(" ", command.get()));
+                mConfigOptions.getSubjectPackageName(), String.join(" ", command.get()));
         // TODO(yuexima): When the obb_file option is supported in espresso mode, the timeout need
         // to be extended.
-        if (getOptions().isRecordScreen()) {
+
+        if (mConfigOptions.isRecordScreen()) {
             mTestUtils.collectScreenRecord(
                     () -> {
                         commandResult.set(runUtil.runTimedCmd(commandTimeout, command.get()));
                     },
-                    mPackageName,
+                    mConfigOptions.getSubjectPackageName(),
                     deviceTime -> mScreenRecordStartTime = deviceTime);
         } else {
             commandResult.set(runUtil.runTimedCmd(commandTimeout, command.get()));
         }
 
         // Must be done after the crawler run because the app is installed by the crawler.
-        if (getOptions().isCollectAppVersion()) {
-            mTestUtils.collectAppVersion(mPackageName);
+        if (mConfigOptions.isCollectAppVersion()) {
+            mTestUtils.collectAppVersion(mConfigOptions.getSubjectPackageName());
         }
 
         collectOutputZip();
@@ -394,10 +422,12 @@ public final class AppCrawlTester {
             throw new CrawlerException("Crawler command failed: " + commandResult.get());
         }
 
-        CLog.i("Completed crawling the package %s. Outputs: %s", mPackageName, commandResult.get());
+        CLog.i(
+                "Completed crawling the package %s. Outputs: %s",
+                mConfigOptions.getSubjectPackageName(), commandResult.get());
     }
 
-    /** Copys the step screenshots into test outputs for easier access. */
+    /** Copies the step screenshots into test outputs for easier access. */
     private void collectCrawlStepScreenshots(boolean isUtpClient) {
         if (mOutput == null) {
             CLog.e("Output directory is not created yet. Skipping collecting step screenshots.");
@@ -413,13 +443,18 @@ public final class AppCrawlTester {
         }
 
         try (Stream<Path> files = Files.list(subDir)) {
-            files.filter(path -> path.getFileName().toString().toLowerCase().endsWith(".png"))
+            files.filter(
+                            path ->
+                                    path.getFileName()
+                                            .toString()
+                                            .toLowerCase(Locale.getDefault())
+                                            .endsWith(".png"))
                     .forEach(
                             path -> {
                                 mTestUtils
                                         .getTestArtifactReceiver()
                                         .addTestArtifact(
-                                                mPackageName
+                                                mConfigOptions.getSubjectPackageName()
                                                         + "-crawl_step_screenshot_"
                                                         + path.getFileName(),
                                                 LogDataType.PNG,
@@ -454,11 +489,12 @@ public final class AppCrawlTester {
                                     path ->
                                             path.getFileName()
                                                     .toString()
-                                                    .toLowerCase()
+                                                    .toLowerCase(Locale.getDefault())
                                                     .endsWith("crawl_outputs.txt"))
                             .findFirst();
             if (roboOutputFile.isPresent()) {
-                generateRoboscriptSignalFile(roboOutputFile.get(), mPackageName);
+                generateRoboscriptSignalFile(
+                        roboOutputFile.get(), mConfigOptions.getSubjectPackageName());
             }
         } catch (IOException e) {
             CLog.e(e);
@@ -480,7 +516,7 @@ public final class AppCrawlTester {
                                             + "_roboscript_"
                                             + getRoboscriptSignal(Optional.of(roboOutputFile))
                                                     .toString()
-                                                    .toLowerCase(),
+                                                    .toLowerCase(Locale.getDefault()),
                                     ".txt")
                             .toFile();
             mTestUtils
@@ -550,7 +586,10 @@ public final class AppCrawlTester {
             File outputZip = ZipUtil.createZip(mOutput.toFile());
             mTestUtils
                     .getTestArtifactReceiver()
-                    .addTestArtifact(mPackageName + "-crawler_output", LogDataType.ZIP, outputZip);
+                    .addTestArtifact(
+                            mConfigOptions.getSubjectPackageName() + "-crawler_output",
+                            LogDataType.ZIP,
+                            outputZip);
         } catch (IOException e) {
             CLog.e("Failed to zip the output directory: " + e);
         }
@@ -574,7 +613,7 @@ public final class AppCrawlTester {
                         "--device-id",
                         testInfo.getDevice().getSerialNumber(),
                         "--app-id",
-                        mPackageName,
+                        mConfigOptions.getSubjectPackageName(),
                         "--controller-endpoint",
                         "PROD",
                         "--utp-binaries-dir",
@@ -590,34 +629,39 @@ public final class AppCrawlTester {
                         "--tmp-dir",
                         mOutput.toString()));
 
-        if (getOptions().getTimeoutSec() > 0) {
+        if (mConfigOptions.getCrawlDurationSec() > 0) {
             cmd.add("--crawler-flag");
-            cmd.add("crawlDurationSec=" + Integer.toString(getOptions().getTimeoutSec()));
+            cmd.add("crawlDurationSec=" + Integer.toString(mConfigOptions.getCrawlDurationSec()));
         }
 
-        if (getOptions().isUiAutomatorMode()) {
+        if (!mConfigOptions.isEspressoMode()) {
             cmd.addAll(Arrays.asList("--ui-automator-mode", "--app-installed-on-device"));
         } else {
             Preconditions.checkNotNull(
-                    getOptions().getRepackApk(),
+                    mConfigOptions.getSubjectApkPath(),
                     "Apk file path is required when not running in UIAutomator mode");
 
             try {
-                TestUtils.listApks(mFileSystem.getPath(getOptions().getRepackApk().toString()))
+                TestUtils.listApks(
+                                mFileSystem.getPath(mConfigOptions.getSubjectApkPath().toString()))
                         .forEach(
                                 path -> {
                                     String nameLowercase =
                                             path.getFileName().toString().toLowerCase();
-                                    if (nameLowercase.endsWith(".apk")) {
+                                    if (nameLowercase
+                                            .toLowerCase(Locale.getDefault())
+                                            .endsWith(".apk")) {
                                         cmd.add("--apks-to-crawl");
                                         cmd.add(path.toString());
-                                    } else if (nameLowercase.endsWith(".obb")) {
+                                    } else if (nameLowercase
+                                            .toLowerCase(Locale.getDefault())
+                                            .endsWith(".obb")) {
                                         cmd.add("--files-to-push");
                                         cmd.add(
                                                 String.format(
                                                         "%s=/sdcard/Android/obb/%s/%s",
                                                         path.toString(),
-                                                        mPackageName,
+                                                        mConfigOptions.getSubjectPackageName(),
                                                         path.getFileName().toString()));
                                     } else {
                                         CLog.d("Skipping unrecognized file %s", path.toString());
@@ -628,30 +672,33 @@ public final class AppCrawlTester {
             }
         }
 
-        if (getOptions().getRoboscriptFile() != null) {
+        if (mConfigOptions.getRoboscriptFile() != null) {
             Assert.assertTrue(
                     "Please provide a valid roboscript file.",
                     Files.isRegularFile(
-                            mFileSystem.getPath(getOptions().getRoboscriptFile().toString())));
+                            mFileSystem.getPath(mConfigOptions.getRoboscriptFile().toString())));
             cmd.add("--crawler-asset");
-            cmd.add("robo.script=" + getOptions().getRoboscriptFile().toString());
+            cmd.add("robo.script=" + mConfigOptions.getRoboscriptFile().toString());
         }
 
-        if (getOptions().getCrawlGuidanceProtoFile() != null) {
+        if (mConfigOptions.getCrawlGuidanceProtoFile() != null) {
             Assert.assertTrue(
                     "Please provide a valid CrawlGuidance file.",
                     Files.isRegularFile(
                             mFileSystem.getPath(
-                                    getOptions().getCrawlGuidanceProtoFile().toString())));
+                                    mConfigOptions.getCrawlGuidanceProtoFile().toString())));
             cmd.add("--crawl-guidance-proto-path");
-            cmd.add(getOptions().getCrawlGuidanceProtoFile().toString());
+            cmd.add(mConfigOptions.getCrawlGuidanceProtoFile().toString());
         }
 
-        if (getOptions().getLoginConfigDir() != null) {
+        if (mConfigOptions.getLoginConfigDir() != null) {
             RoboLoginConfigProvider configProvider =
                     new RoboLoginConfigProvider(
-                            mFileSystem.getPath(getOptions().getLoginConfigDir().toString()));
-            cmd.addAll(configProvider.findConfigFor(mPackageName, true).getLoginArgs());
+                            mFileSystem.getPath(mConfigOptions.getLoginConfigDir().toString()));
+            cmd.addAll(
+                    configProvider
+                            .findConfigFor(mConfigOptions.getSubjectPackageName(), true)
+                            .getLoginArgs());
         }
 
         return cmd.toArray(new String[cmd.size()]);
@@ -683,29 +730,35 @@ public final class AppCrawlTester {
                         // Using the publicly known default password of the debug keystore.
                         "android"));
 
-        if (getOptions().getCrawlControllerEndpoint() != null
-                && getOptions().getCrawlControllerEndpoint().length() > 0) {
-            cmd.addAll(Arrays.asList("--endpoint", getOptions().getCrawlControllerEndpoint()));
+        if (mConfigOptions.getCrawlControllerEndpoint() != null
+                && mConfigOptions.getCrawlControllerEndpoint().length() > 0) {
+            cmd.addAll(Arrays.asList("--endpoint", mConfigOptions.getCrawlControllerEndpoint()));
         }
 
-        if (getOptions().isUiAutomatorMode()) {
-            cmd.addAll(Arrays.asList("--ui-automator-mode", "--app-package-name", mPackageName));
+        if (!mConfigOptions.isEspressoMode()) {
+            cmd.addAll(
+                    Arrays.asList(
+                            "--ui-automator-mode",
+                            "--app-package-name",
+                            mConfigOptions.getSubjectPackageName()));
         } else {
             Preconditions.checkNotNull(
-                    getOptions().getRepackApk(),
+                    mConfigOptions.getSubjectApkPath(),
                     "Apk file path is required when not running in UIAutomator mode");
 
             List<Path> apks;
             try {
                 apks =
                         TestUtils.listApks(
-                                        mFileSystem.getPath(getOptions().getRepackApk().toString()))
+                                        mFileSystem.getPath(
+                                                mConfigOptions.getSubjectApkPath().toString()))
                                 .stream()
                                 .filter(
                                         path ->
                                                 path.getFileName()
                                                         .toString()
                                                         .toLowerCase()
+                                                        .toLowerCase(Locale.getDefault())
                                                         .endsWith(".apk"))
                                 .collect(Collectors.toList());
             } catch (TestUtilsException e) {
@@ -721,47 +774,190 @@ public final class AppCrawlTester {
             }
         }
 
-        if (getOptions().getTimeoutSec() > 0) {
+        if (mConfigOptions.getCrawlDurationSec() > 0) {
             cmd.add("--timeout-sec");
-            cmd.add(Integer.toString(getOptions().getTimeoutSec()));
+            cmd.add(Integer.toString(mConfigOptions.getCrawlDurationSec()));
         }
 
-        if (getOptions().getRoboscriptFile() != null) {
+        if (mConfigOptions.getRoboscriptFile() != null) {
             Assert.assertTrue(
                     "Please provide a valid roboscript file.",
                     Files.isRegularFile(
-                            mFileSystem.getPath(getOptions().getRoboscriptFile().toString())));
+                            mFileSystem.getPath(mConfigOptions.getRoboscriptFile().toString())));
             cmd.addAll(
                     Arrays.asList(
-                            "--robo-script-file", getOptions().getRoboscriptFile().toString()));
+                            "--robo-script-file", mConfigOptions.getRoboscriptFile().toString()));
         }
 
-        if (getOptions().getCrawlGuidanceProtoFile() != null) {
+        if (mConfigOptions.getCrawlGuidanceProtoFile() != null) {
             Assert.assertTrue(
                     "Please provide a valid CrawlGuidance file.",
                     Files.isRegularFile(
                             mFileSystem.getPath(
-                                    getOptions().getCrawlGuidanceProtoFile().toString())));
+                                    mConfigOptions.getCrawlGuidanceProtoFile().toString())));
             cmd.addAll(
                     Arrays.asList(
                             "--text-guide-file",
-                            getOptions().getCrawlGuidanceProtoFile().toString()));
+                            mConfigOptions.getCrawlGuidanceProtoFile().toString()));
         }
 
-        if (getOptions().getLoginConfigDir() != null) {
+        if (mConfigOptions.getLoginConfigDir() != null) {
             RoboLoginConfigProvider configProvider =
                     new RoboLoginConfigProvider(
-                            mFileSystem.getPath(getOptions().getLoginConfigDir().toString()));
-            cmd.addAll(configProvider.findConfigFor(mPackageName, false).getLoginArgs());
+                            mFileSystem.getPath(mConfigOptions.getLoginConfigDir().toString()));
+            cmd.addAll(
+                    configProvider
+                            .findConfigFor(mConfigOptions.getSubjectPackageName(), false)
+                            .getLoginArgs());
         }
 
         return cmd.toArray(new String[cmd.size()]);
     }
 
+    /** Returns whether setup completed successfully. */
+    public boolean isSetupComplete() {
+        return mExecutionStage.isSetupComplete();
+    }
+
+    /** Returns whether the test passed. */
+    public boolean isTestPassed() {
+        return mExecutionStage.isTestPassed();
+    }
+
+    /** Returns the failure message. Will return empty string if no failure. */
+    public String getFailureMessage() {
+        return mExecutionStage.getFailureMessage();
+    }
+
+    /** Sets the crawler to not throw on failure. Failure includes setup and test failures. */
+    public AppCrawlTester setNoThrowOnFailure(boolean noThrowOnFailure) {
+        mNoThrowOnFailure = noThrowOnFailure;
+        return this;
+    }
+
+    private void checkOptionSettable() {
+        if (mExecutionStage.mIsSetupComplete) {
+            throw new IllegalStateException("Changing options after test start is not allowed.");
+        }
+    }
+
+    /** Sets the package name to crawl. */
+    public AppCrawlTester setSubjectPackageName(String subjectPackageName) {
+        checkOptionSettable();
+        mConfigOptions.setSubjectPackageName(subjectPackageName);
+        return this;
+    }
+
+    /** Sets whether to enable screen recording. */
+    public AppCrawlTester setRecordScreen(boolean recordScreen) {
+        checkOptionSettable();
+        mConfigOptions.setRecordScreen(recordScreen);
+        return this;
+    }
+
+    /** Sets whether to enable app version collection. */
+    public AppCrawlTester setCollectAppVersion(boolean collectAppVersion) {
+        checkOptionSettable();
+        mConfigOptions.setCollectAppVersion(collectAppVersion);
+        return this;
+    }
+
+    /** Sets whether to enable GMS version collection. */
+    public AppCrawlTester setCollectGmsVersion(boolean collectGmsVersion) {
+        checkOptionSettable();
+        mConfigOptions.setCollectGmsVersion(collectGmsVersion);
+        return this;
+    }
+
+    /** Sets the subject APK file path. */
+    public AppCrawlTester setSubjectApkPath(File apkPath) {
+        checkOptionSettable();
+        mConfigOptions.setSubjectApkPath(apkPath);
+        return this;
+    }
+
+    /** Sets the list of installation arguments for the subject APK. */
+    public AppCrawlTester setSubjectApkInstallArgs(List<String> installArgs) {
+        checkOptionSettable();
+        mConfigOptions.setSubjectApkInstallArgs(installArgs);
+        return this;
+    }
+
+    /** Sets the list of extra APK paths for installation before. */
+    public AppCrawlTester setExtraApkPaths(List<File> apkPaths) {
+        checkOptionSettable();
+        mConfigOptions.setExtraApkPaths(apkPaths);
+        return this;
+    }
+
+    /** Sets the list of installation arguments for extra APKs. */
+    public AppCrawlTester setExtraApkInstallArgs(List<String> installArgs) {
+        checkOptionSettable();
+        mConfigOptions.setExtraApkInstallArgs(installArgs);
+        return this;
+    }
+
+    /** Sets the crawl controller endpoint URL. */
+    public AppCrawlTester setCrawlControllerEndpoint(String crawlControllerEndpoint) {
+        checkOptionSettable();
+        mConfigOptions.setCrawlControllerEndpoint(crawlControllerEndpoint);
+        return this;
+    }
+
+    /** Sets whether to enable espresso mode. */
+    public AppCrawlTester setEspressoMode(boolean espressoMode) {
+        checkOptionSettable();
+        mConfigOptions.setEspressoMode(espressoMode);
+        return this;
+    }
+
+    /** Sets the crawler duration timeout in seconds. */
+    public AppCrawlTester setCrawlDurationSec(int timeoutSec) {
+        checkOptionSettable();
+        mConfigOptions.setCrawlDurationSec(timeoutSec);
+        return this;
+    }
+
+    /** Sets the Roboscript file path. */
+    public AppCrawlTester setRoboscriptFile(File roboscriptFile) {
+        checkOptionSettable();
+        mConfigOptions.setRoboscriptFile(roboscriptFile);
+        return this;
+    }
+
+    /** Sets the crawl guidance proto file path. */
+    public AppCrawlTester setCrawlGuidanceProtoFile(File crawlGuidanceProtoFile) {
+        checkOptionSettable();
+        mConfigOptions.setCrawlGuidanceProtoFile(crawlGuidanceProtoFile);
+        return this;
+    }
+
+    /** Sets the login config directory. */
+    public AppCrawlTester setLoginConfigDir(File loginConfigDir) {
+        checkOptionSettable();
+        mConfigOptions.setLoginConfigDir(loginConfigDir);
+        return this;
+    }
+
+    /** Sets when to save the apks to test artifacts. */
+    public AppCrawlTester setSaveApkWhen(TestUtils.TakeEffectWhen saveApkWhen) {
+        checkOptionSettable();
+        mConfigOptions.setSaveApkWhen(saveApkWhen);
+        return this;
+    }
+
+    /** Sets whether to grant external storage permission to the subject package. */
+    public AppCrawlTester setGrantExternalStoragePermission(
+            boolean grantExternalStoragePermission) {
+        checkOptionSettable();
+        mConfigOptions.setGrantExternalStoragePermission(grantExternalStoragePermission);
+        return this;
+    }
+
     private class ExecutionStage {
         private boolean mIsSetupComplete = false;
         private boolean mIsTestExecuted = false;
-        private boolean mIsTestPassed = false;
+        private ArrayList<String> mFailureMessages = new ArrayList<>();
 
         private boolean isSetupComplete() {
             return mIsSetupComplete;
@@ -780,11 +976,17 @@ public final class AppCrawlTester {
         }
 
         private boolean isTestPassed() {
-            return mIsTestPassed;
+            return isTestExecuted() && getFailureMessage().isBlank();
+        }
+
+        private void addFailureMessage(String msg) {
+            mFailureMessages.add(msg);
         }
 
-        private void setTestPassed(boolean isTestPassed) {
-            mIsTestPassed = isTestPassed;
+        private String getFailureMessage() {
+            return String.join(
+                    "\n============\n",
+                    mFailureMessages.toArray(new String[mFailureMessages.size()]));
         }
     }
 
diff --git a/harness/src/main/java/com/android/csuite/core/AppCrawlTesterHostPreparer.java b/harness/src/main/java/com/android/csuite/core/AppCrawlTesterHostPreparer.java
index abb3de3..410ae2d 100644
--- a/harness/src/main/java/com/android/csuite/core/AppCrawlTesterHostPreparer.java
+++ b/harness/src/main/java/com/android/csuite/core/AppCrawlTesterHostPreparer.java
@@ -17,6 +17,7 @@
 package com.android.csuite.core;
 
 import com.android.tradefed.config.Option;
+import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.targetprep.ITargetPreparer;
@@ -39,10 +40,11 @@ import java.nio.file.Path;
 /** A Tradefed preparer that preparers an app crawler on the host before testing. */
 public final class AppCrawlTesterHostPreparer implements ITargetPreparer {
     private static final long COMMAND_TIMEOUT_MILLIS = 4 * 60 * 1000;
-    private static final String SDK_PATH_KEY = "SDK_PATH_KEY";
+    private static final String TEMP_DIR_PATH_KEY = "CSUITE_INTERNAL_CRAWLER_TEMP_DIR_PATH";
     private static final String CRAWLER_BIN_PATH_KEY = "CSUITE_INTERNAL_CRAWLER_BIN_PATH";
     private static final String CREDENTIAL_PATH_KEY = "CSUITE_INTERNAL_CREDENTIAL_PATH";
     private static final String IS_READY_KEY = "CSUITE_INTERNAL_IS_READY";
+    private static final String ANDROID_SDK = "ANDROID_SDK";
     @VisibleForTesting static final String SDK_TAR_OPTION = "sdk-tar";
     @VisibleForTesting static final String CRAWLER_BIN_OPTION = "crawler-bin";
     @VisibleForTesting static final String CREDENTIAL_JSON_OPTION = "credential-json";
@@ -50,19 +52,16 @@ public final class AppCrawlTesterHostPreparer implements ITargetPreparer {
 
     @Option(
             name = SDK_TAR_OPTION,
-            mandatory = true,
             description = "The path to a tar file that contains the Android SDK.")
     private File mSdkTar;
 
     @Option(
             name = CRAWLER_BIN_OPTION,
-            mandatory = true,
             description = "Path to the directory containing the required crawler binary files.")
     private File mCrawlerBin;
 
     @Option(
             name = CREDENTIAL_JSON_OPTION,
-            mandatory = true,
             description = "The credential json file to access the crawler server.")
     private File mCredential;
 
@@ -77,6 +76,15 @@ public final class AppCrawlTesterHostPreparer implements ITargetPreparer {
         mRunUtilProvider = runUtilProvider;
         mFileSystem = fileSystem;
     }
+    /**
+     * Returns the temp directory path created for the AppCrawlTester.
+     *
+     * @param testInfo The test info where the path is stored in.
+     * @return The path to the temp directory; Null if not set.
+     */
+    public static String getTempDirPath(TestInformation testInfo) {
+        return getPathFromBuildInfo(testInfo, TEMP_DIR_PATH_KEY);
+    }
 
     /**
      * Returns a path that contains Android SDK.
@@ -85,7 +93,9 @@ public final class AppCrawlTesterHostPreparer implements ITargetPreparer {
      * @return The path to Android SDK; Null if not set.
      */
     public static String getSdkPath(TestInformation testInfo) {
-        return getPathFromBuildInfo(testInfo, SDK_PATH_KEY);
+        return Path.of(getPathFromBuildInfo(testInfo, TEMP_DIR_PATH_KEY))
+                .resolve(ANDROID_SDK)
+                .toString();
     }
 
     /**
@@ -108,6 +118,16 @@ public final class AppCrawlTesterHostPreparer implements ITargetPreparer {
         return getPathFromBuildInfo(testInfo, CREDENTIAL_PATH_KEY);
     }
 
+    private boolean isEnabled() {
+        if (mSdkTar == null && mCrawlerBin == null && mCredential == null) {
+            return false;
+        }
+        if (mSdkTar != null && mCrawlerBin != null && mCredential != null) {
+            return true;
+        }
+        throw new AssertionError("All option values should be provided.");
+    }
+
     /**
      * Checks whether the preparer has successfully executed.
      *
@@ -123,8 +143,8 @@ public final class AppCrawlTesterHostPreparer implements ITargetPreparer {
     }
 
     @VisibleForTesting
-    static void setSdkPath(TestInformation testInfo, Path path) {
-        testInfo.getBuildInfo().addBuildAttribute(SDK_PATH_KEY, path.toString());
+    static void setTempDirPath(TestInformation testInfo, Path path) {
+        testInfo.getBuildInfo().addBuildAttribute(TEMP_DIR_PATH_KEY, path.toString());
     }
 
     @VisibleForTesting
@@ -138,25 +158,43 @@ public final class AppCrawlTesterHostPreparer implements ITargetPreparer {
     }
 
     @Override
-    public void setUp(TestInformation testInfo) throws TargetSetupError {
+    public void setUp(TestInformation testInfo)
+            throws TargetSetupError, DeviceNotAvailableException {
+        if (!isEnabled()) {
+            return;
+        }
+
         IRunUtil runUtil = mRunUtilProvider.get();
 
-        Path sdkPath;
+        Path tempDirPath;
         try {
-            sdkPath = Files.createTempDirectory("android-sdk");
+            tempDirPath = Files.createTempDirectory(TEMP_DIR_PATH_KEY);
         } catch (IOException e) {
-            throw new TargetSetupError("Failed to create the output path for android sdk.", e);
+            throw new TargetSetupError(
+                    "Failed to create the temp dir.",
+                    e,
+                    testInfo.getDevice().getDeviceDescriptor());
         }
+        setTempDirPath(testInfo, tempDirPath);
 
-        String cmd = "tar -xvzf " + mSdkTar.getPath() + " -C " + sdkPath.toString();
+        Path sdkPath;
+        try {
+            sdkPath = Files.createDirectory(tempDirPath.resolve(ANDROID_SDK));
+        } catch (IOException e) {
+            throw new TargetSetupError(
+                    "Failed to create the output path for android sdk.",
+                    e,
+                    testInfo.getDevice().getDeviceDescriptor());
+        }
+        String cmd = "tar -xzf " + mSdkTar.getPath() + " -C " + sdkPath.toString();
         CLog.i("Decompressing Android SDK to " + sdkPath.toString());
         CommandResult res = runUtil.runTimedCmd(COMMAND_TIMEOUT_MILLIS, cmd.split(" "));
         if (!res.getStatus().equals(CommandStatus.SUCCESS)) {
-            throw new TargetSetupError(String.format("Failed to untar android sdk: %s", res));
+            throw new TargetSetupError(
+                    String.format("Failed to untar android sdk: %s", res),
+                    testInfo.getDevice().getDeviceDescriptor());
         }
 
-        setSdkPath(testInfo, sdkPath);
-
         Path jar = mCrawlerBin.toPath().resolve("crawl_launcher_deploy.jar");
         if (!Files.exists(jar)) {
             jar = mCrawlerBin.toPath().resolve("utp-cli-android_deploy.jar");
@@ -167,23 +205,31 @@ public final class AppCrawlTesterHostPreparer implements ITargetPreparer {
         CommandResult chmodRes = runUtil.runTimedCmd(COMMAND_TIMEOUT_MILLIS, chmodCmd.split(" "));
         if (!chmodRes.getStatus().equals(CommandStatus.SUCCESS)) {
             throw new TargetSetupError(
-                    String.format("Failed to make crawler binary executable: %s", chmodRes));
+                    String.format("Failed to make crawler binary executable: %s", chmodRes),
+                    testInfo.getDevice().getDeviceDescriptor());
         }
 
-        setCrawlerBinPath(testInfo, mCrawlerBin.toPath());
+        testInfo.getDevice()
+                .executeShellV2Command("settings put global package_verifier_user_consent -1");
 
+        setCrawlerBinPath(testInfo, mCrawlerBin.toPath());
         setCredentialPath(testInfo, mCredential.toPath());
 
         testInfo.getBuildInfo().addBuildAttribute(IS_READY_KEY, "true");
     }
 
     @Override
-    public void tearDown(TestInformation testInfo, Throwable e) {
+    public void tearDown(TestInformation testInfo, Throwable e) throws DeviceNotAvailableException {
+        if (!isEnabled()) {
+            return;
+        }
         try {
             cleanUp(mFileSystem.getPath(getSdkPath(testInfo)));
         } catch (IOException ioException) {
             CLog.e(ioException);
         }
+        testInfo.getDevice()
+                .executeShellV2Command("settings put global package_verifier_user_consent 1");
     }
 
     private static void cleanUp(Path path) throws IOException {
diff --git a/harness/src/main/java/com/android/csuite/core/AppCrawlTesterOptions.java b/harness/src/main/java/com/android/csuite/core/AppCrawlTesterOptions.java
index 56a2934..57ff974 100644
--- a/harness/src/main/java/com/android/csuite/core/AppCrawlTesterOptions.java
+++ b/harness/src/main/java/com/android/csuite/core/AppCrawlTesterOptions.java
@@ -15,16 +15,32 @@
  */
 package com.android.csuite.core;
 
+import com.android.csuite.core.AppCrawlTester.CrawlerException;
 import com.android.tradefed.config.Option;
+import com.android.tradefed.invoker.TestInformation;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.targetprep.ITargetPreparer;
+import com.android.tradefed.targetprep.TargetSetupError;
+
+import com.google.common.annotations.VisibleForTesting;
+import com.google.common.base.Preconditions;
 
 import java.io.File;
+import java.io.IOException;
+import java.io.InputStream;
+import java.io.ObjectInputStream;
+import java.io.ObjectOutputStream;
+import java.io.OutputStream;
+import java.io.Serializable;
+import java.nio.file.FileSystem;
+import java.nio.file.FileSystems;
+import java.nio.file.Files;
+import java.nio.file.Path;
 import java.util.ArrayList;
 import java.util.List;
 
 /** A class for receiving and storing option values for the AppCrawlTester class. */
-public class AppCrawlTesterOptions {
-
-    public static final String OBJECT_TYPE = "APP_CRAWL_TESTER_OPTIONS";
+public class AppCrawlTesterOptions implements ITargetPreparer, Serializable {
 
     @Option(name = "record-screen", description = "Whether to record screen during test.")
     private boolean mRecordScreen;
@@ -44,50 +60,51 @@ public class AppCrawlTesterOptions {
     private boolean mCollectGmsVersion;
 
     @Option(
-            name = "repack-apk",
-            mandatory = false,
+            name = "collect-autofdo-profile",
             description =
-                    "Path to an apk file or a directory containing apk files of a single"
-                            + " package to repack and install in Espresso mode")
-    private File mRepackApk;
+                    "Whether to collect kernel AutoFDO profile and store the information in"
+                            + " test log files.")
+    private boolean mCollectAutoFDOProfile;
+
+    @Option(name = "subject-package-name", description = "Package name of the app being crawled.")
+    private String mSubjectPackageName;
 
     @Option(
-            name = "install-apk",
-            mandatory = false,
+            name = "subject-apk-path",
             description =
-                    "The path to an apk file or a directory of apk files to be installed on the"
-                            + " device. In Ui-automator mode, this includes both the target apk to"
-                            + " install and any dependencies. In Espresso mode this can include"
-                            + " additional libraries or dependencies.")
-    private List<File> mInstallApkPaths = new ArrayList<>();
+                    "The path to the apk files of the subject package being tested. Optional in"
+                            + " ui-automator mode and required in Espresso mode")
+    private File mSubjectApkPath;
+
+    @Option(name = "subject-apk-install-arg", description = "Adb install arg for the subject apk.")
+    private List<String> mSubjectApkInstallArgs = new ArrayList<>();
 
     @Option(
-            name = "install-arg",
+            name = "extra-apk-path",
             description =
-                    "Arguments for the 'adb install-multiple' package installation command for"
-                            + " UI-automator mode.")
-    private List<String> mInstallArgs = new ArrayList<>();
+                    "The paths to extra apks to be installed before test. Split apks of a single"
+                            + " package should be included in one directory path.")
+    private List<File> mExtraApkPaths = new ArrayList<>();
+
+    @Option(name = "extra-apk-install-arg", description = "Adb install arg for extra apka.")
+    private List<String> mExtraApkInstallArgs = new ArrayList<>();
 
     @Option(
             name = "crawl-controller-endpoint",
-            mandatory = false,
             description = "The crawl controller endpoint to target.")
     private String mCrawlControllerEndpoint;
 
     @Option(
-            name = "ui-automator-mode",
-            mandatory = false,
+            name = "espresso-mode",
             description =
-                    "Run the crawler with UIAutomator mode. Apk option is not required in this"
-                            + " mode. This option is by default true. Setting it to false enables"
-                            + " espresso mode which is less stable.")
-    private boolean mUiAutomatorMode = true;
+                    "Run the crawler in Espresso mode. Subject APK path is required in this"
+                            + " mode. This option is by default false.")
+    private boolean mEspressoMode = false;
 
     @Option(
-            name = "timeout-sec",
-            mandatory = false,
-            description = "The timeout for the crawl test.")
-    private int mTimeoutSec = 60;
+            name = "crawl-duration-sec",
+            description = "The max duration timeout for the crawler in seconds.")
+    private int mCrawlDurationSec = 60;
 
     @Option(
             name = "robo-script-file",
@@ -117,149 +134,175 @@ public class AppCrawlTesterOptions {
 
     @Option(
             name = "grant-external-storage",
-            mandatory = false,
             description = "After an apks are installed, grant MANAGE_EXTERNAL_STORAGE permissions.")
     private boolean mGrantExternalStoragePermission = false;
 
+    /** Returns the config value for the package name to crawl. */
+    String getSubjectPackageName() {
+        return mSubjectPackageName;
+    }
+
+    /** Sets the package name to crawl. */
+    AppCrawlTesterOptions setSubjectPackageName(String subjectPackageName) {
+        this.mSubjectPackageName = subjectPackageName;
+        return this;
+    }
+
     /** Returns the config value for whether to record the screen. */
-    public boolean isRecordScreen() {
+    boolean isRecordScreen() {
         return mRecordScreen;
     }
 
     /** Sets whether to enable screen recording. */
-    public AppCrawlTesterOptions setRecordScreen(boolean recordScreen) {
+    AppCrawlTesterOptions setRecordScreen(boolean recordScreen) {
         this.mRecordScreen = recordScreen;
         return this;
     }
 
     /** Returns the config value for whether to collect app version information. */
-    public boolean isCollectAppVersion() {
+    boolean isCollectAppVersion() {
         return mCollectAppVersion;
     }
 
     /** Sets whether to enable app version collection. */
-    public AppCrawlTesterOptions setCollectAppVersion(boolean collectAppVersion) {
+    AppCrawlTesterOptions setCollectAppVersion(boolean collectAppVersion) {
         this.mCollectAppVersion = collectAppVersion;
         return this;
     }
 
     /** Returns the config value for whether to collect GMS version information. */
-    public boolean isCollectGmsVersion() {
+    boolean isCollectGmsVersion() {
         return mCollectGmsVersion;
     }
 
     /** Sets whether to enable GMS version collection. */
-    public AppCrawlTesterOptions setCollectGmsVersion(boolean collectGmsVersion) {
+    AppCrawlTesterOptions setCollectGmsVersion(boolean collectGmsVersion) {
         this.mCollectGmsVersion = collectGmsVersion;
         return this;
     }
 
-    /** Returns the config value for the repacked APK file path. */
-    public File getRepackApk() {
-        return mRepackApk;
+    /** Returns the config value for whether to collect AutoFDO profile. */
+    boolean isCollectAutoFDOProfile() {
+        return mCollectAutoFDOProfile;
+    }
+
+    /** Returns the config value for the subject APK path. */
+    File getSubjectApkPath() {
+        return mSubjectApkPath;
     }
 
-    /** Sets the repacked APK file path. */
-    public AppCrawlTesterOptions setRepackApk(File repackApk) {
-        this.mRepackApk = repackApk;
+    /** Sets the subject APK path. */
+    AppCrawlTesterOptions setSubjectApkPath(File subjectApkPath) {
+        this.mSubjectApkPath = subjectApkPath;
         return this;
     }
 
-    /** Returns the config value for the list of APK paths for installation. */
-    public List<File> getInstallApkPaths() {
-        return mInstallApkPaths;
+    /** Returns the config value for the list of extra APK paths for installation. */
+    List<File> getExtraApkPaths() {
+        return mExtraApkPaths;
     }
 
-    /** Sets the list of APK paths for installation. */
-    public AppCrawlTesterOptions setInstallApkPaths(List<File> installApkPaths) {
-        this.mInstallApkPaths = installApkPaths;
+    /** Sets the list of extra APK paths for installation before test. */
+    AppCrawlTesterOptions setExtraApkPaths(List<File> extraApkPaths) {
+        this.mExtraApkPaths = extraApkPaths;
         return this;
     }
 
-    /** Returns the config value for the list of installation arguments. */
-    public List<String> getInstallArgs() {
-        return mInstallArgs;
+    /** Returns the config value for the list of installation arguments for the subject APK. */
+    List<String> getSubjectApkInstallArgs() {
+        return mSubjectApkInstallArgs;
     }
 
-    /** Sets the list of installation arguments. */
-    public AppCrawlTesterOptions setInstallArgs(List<String> installArgs) {
-        this.mInstallArgs = installArgs;
+    /** Sets the list of installation arguments for the subject APK. */
+    AppCrawlTesterOptions setSubjectApkInstallArgs(List<String> subjectApkInstallArgs) {
+        this.mSubjectApkInstallArgs = subjectApkInstallArgs;
+        return this;
+    }
+
+    /** Returns the config value for the list of installation arguments for the extra APKs. */
+    List<String> getExtraApkInstallArgs() {
+        return mExtraApkInstallArgs;
+    }
+
+    /** Sets the list of installation arguments for the extra APKs. */
+    AppCrawlTesterOptions setExtraApkInstallArgs(List<String> extraApkInstallArgs) {
+        this.mExtraApkInstallArgs = extraApkInstallArgs;
         return this;
     }
 
     /** Returns the config value for the crawl controller endpoint URL. */
-    public String getCrawlControllerEndpoint() {
+    String getCrawlControllerEndpoint() {
         return mCrawlControllerEndpoint;
     }
 
     /** Sets the crawl controller endpoint URL. */
-    public AppCrawlTesterOptions setCrawlControllerEndpoint(String crawlControllerEndpoint) {
+    AppCrawlTesterOptions setCrawlControllerEndpoint(String crawlControllerEndpoint) {
         this.mCrawlControllerEndpoint = crawlControllerEndpoint;
         return this;
     }
 
-    /** Returns the config value for whether to enable UiAutomator mode. */
-    public boolean isUiAutomatorMode() {
-        return mUiAutomatorMode;
+    /** Returns the config value for whether to enable espresso mode. */
+    boolean isEspressoMode() {
+        return mEspressoMode;
     }
 
-    /** Sets whether to enable UiAutomator mode. */
-    public AppCrawlTesterOptions setUiAutomatorMode(boolean uiAutomatorMode) {
-        this.mUiAutomatorMode = uiAutomatorMode;
+    /** Sets whether to enable espresso mode. */
+    AppCrawlTesterOptions setEspressoMode(boolean espressoMode) {
+        this.mEspressoMode = espressoMode;
         return this;
     }
 
-    /** Returns the config value for the timeout duration in seconds. */
-    public int getTimeoutSec() {
-        return mTimeoutSec;
+    /** Returns the config value for the crawler duration timeout in seconds. */
+    int getCrawlDurationSec() {
+        return mCrawlDurationSec;
     }
 
-    /** Sets the timeout duration in seconds. */
-    public AppCrawlTesterOptions setTimeoutSec(int timeoutSec) {
-        this.mTimeoutSec = timeoutSec;
+    /** Sets the crawler duration timeout in seconds. */
+    AppCrawlTesterOptions setCrawlDurationSec(int crawlDurationSec) {
+        this.mCrawlDurationSec = crawlDurationSec;
         return this;
     }
 
     /** Returns the config value for the Roboscript file path. */
-    public File getRoboscriptFile() {
+    File getRoboscriptFile() {
         return mRoboscriptFile;
     }
 
     /** Sets the Roboscript file path. */
-    public AppCrawlTesterOptions setRoboscriptFile(File roboscriptFile) {
+    AppCrawlTesterOptions setRoboscriptFile(File roboscriptFile) {
         this.mRoboscriptFile = roboscriptFile;
         return this;
     }
 
     /** Returns the config value for the crawl guidance proto file path. */
-    public File getCrawlGuidanceProtoFile() {
+    File getCrawlGuidanceProtoFile() {
         return mCrawlGuidanceProtoFile;
     }
 
     /** Sets the crawl guidance proto file path. */
-    public AppCrawlTesterOptions setCrawlGuidanceProtoFile(File crawlGuidanceProtoFile) {
+    AppCrawlTesterOptions setCrawlGuidanceProtoFile(File crawlGuidanceProtoFile) {
         this.mCrawlGuidanceProtoFile = crawlGuidanceProtoFile;
         return this;
     }
 
     /** Gets the config value of login config directory. */
-    public File getLoginConfigDir() {
+    File getLoginConfigDir() {
         return mLoginConfigDir;
     }
 
     /** Sets the login config directory. */
-    public AppCrawlTesterOptions setLoginConfigDir(File loginConfigDir) {
+    AppCrawlTesterOptions setLoginConfigDir(File loginConfigDir) {
         this.mLoginConfigDir = loginConfigDir;
         return this;
     }
 
     /** Gets the config value for when to save apks. */
-    public TestUtils.TakeEffectWhen getSaveApkWhen() {
+    TestUtils.TakeEffectWhen getSaveApkWhen() {
         return mSaveApkWhen;
     }
 
     /** Sets when to save the apks to test artifacts. */
-    public AppCrawlTesterOptions setSaveApkWhen(TestUtils.TakeEffectWhen saveApkWhen) {
+    AppCrawlTesterOptions setSaveApkWhen(TestUtils.TakeEffectWhen saveApkWhen) {
         this.mSaveApkWhen = saveApkWhen;
         return this;
     }
@@ -267,14 +310,87 @@ public class AppCrawlTesterOptions {
     /**
      * Gets the config value for whether to grant external storage permission to the subject package
      */
-    public boolean isGrantExternalStoragePermission() {
+    boolean isGrantExternalStoragePermission() {
         return mGrantExternalStoragePermission;
     }
 
     /** Sets whether to grant external storage permission to the subject package. */
-    public AppCrawlTesterOptions setGrantExternalStoragePermission(
+    AppCrawlTesterOptions setGrantExternalStoragePermission(
             boolean grantExternalStoragePermission) {
         this.mGrantExternalStoragePermission = grantExternalStoragePermission;
         return this;
     }
+
+    /** {@inheritDoc} */
+    @Override
+    public void setUp(TestInformation testInfo) throws TargetSetupError {
+        try {
+            dump(testInfo, FileSystems.getDefault());
+        } catch (IOException e) {
+            throw new TargetSetupError(
+                    "Failed to dump options", e, testInfo.getDevice().getDeviceDescriptor());
+        }
+    }
+
+    /** {@inheritDoc} */
+    @Override
+    public void tearDown(TestInformation testInfo, Throwable e) {
+        cleanUpDump(testInfo);
+    }
+
+    private void cleanUpDump(TestInformation testInfo) {
+        String tmpPathStr = AppCrawlTesterHostPreparer.getTempDirPath(testInfo);
+        if (tmpPathStr == null) {
+            return;
+        }
+        Path objFile = Path.of(tmpPathStr).resolve(GetObjFileName(testInfo));
+        if (!Files.exists(objFile)) {
+            return;
+        }
+        try {
+            Files.delete(objFile);
+        } catch (IOException e2) {
+            CLog.w("Failed to delete %s: %s", objFile, e2);
+        }
+    }
+
+    @VisibleForTesting
+    void dump(TestInformation testInfo, FileSystem fileSystem) throws IOException {
+        String tmpPathStr = AppCrawlTesterHostPreparer.getTempDirPath(testInfo);
+        Preconditions.checkNotNull(tmpPathStr, "Temp dir not found.");
+        Preconditions.checkArgument(
+                Files.exists(fileSystem.getPath(tmpPathStr)), "Temp dir not exist.");
+        Path objFile = fileSystem.getPath(tmpPathStr).resolve(GetObjFileName(testInfo));
+        Files.createFile(objFile);
+
+        try (OutputStream fos = Files.newOutputStream(objFile);
+                ObjectOutputStream oos = new ObjectOutputStream(fos)) {
+            oos.writeObject(this);
+        }
+    }
+
+    /** Loads the option object from test information. */
+    public static AppCrawlTesterOptions load(TestInformation testInfo, FileSystem fileSystem)
+            throws CrawlerException {
+        if (!AppCrawlTesterHostPreparer.isReady(testInfo)) {
+            throw new CrawlerException("");
+        }
+        String tmpPathStr = AppCrawlTesterHostPreparer.getTempDirPath(testInfo);
+        Preconditions.checkNotNull(
+                tmpPathStr, "Temp dir not found, crawl host preparer likely not run.");
+        Path dump = fileSystem.getPath(tmpPathStr).resolve(GetObjFileName(testInfo));
+
+        try {
+            try (InputStream fis = Files.newInputStream(dump);
+                    ObjectInputStream ois = new ObjectInputStream(fis)) {
+                return (AppCrawlTesterOptions) ois.readObject();
+            }
+        } catch (ClassNotFoundException | IOException e) {
+            throw new CrawlerException(e);
+        }
+    }
+
+    private static String GetObjFileName(TestInformation testInfo) {
+        return testInfo.hashCode() + ".dump";
+    }
 }
diff --git a/harness/src/main/java/com/android/csuite/core/AutoFDOProfileCollector.java b/harness/src/main/java/com/android/csuite/core/AutoFDOProfileCollector.java
new file mode 100644
index 0000000..13c530a
--- /dev/null
+++ b/harness/src/main/java/com/android/csuite/core/AutoFDOProfileCollector.java
@@ -0,0 +1,158 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.csuite.core;
+
+import com.android.csuite.core.AppCrawlTester.RunUtilProvider;
+import com.android.csuite.core.TestUtils.TestArtifactReceiver;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.result.LogDataType;
+import com.android.tradefed.util.RunUtil;
+
+import com.google.common.annotations.VisibleForTesting;
+
+import java.io.File;
+import java.io.IOException;
+
+/** A utility class for collecting AutoFDO profile from the test device. */
+public class AutoFDOProfileCollector {
+    @VisibleForTesting
+    static final String RECORD_CMDLINE =
+            "adb -s %s shell su root simpleperf record -e cs-etm:k -z --duration %f -a"
+                    + " --log-to-android-buffer -o /data/local/tmp/perf.data";
+
+    @VisibleForTesting
+    static final String INJECT_CMDLINE =
+            "adb -s %s shell su root simpleperf inject --output branch-list -i"
+                    + " /data/local/tmp/perf.data --exclude-perf -z --binary kernel.kallsyms -o"
+                    + " /data/local/tmp/perf_inject.data --log-to-android-buffer";
+
+    @VisibleForTesting
+    static final String ON_DEVICE_PROFILE_PATH = "/data/local/tmp/perf_inject.data";
+
+    private final ITestDevice mDevice;
+    private final RunUtilProvider mRunUtilProvider;
+    private Process mRecordProcess;
+
+    /**
+     * Create an {@link AutoFDOProfileCollector} instance.
+     *
+     * @param device The test device.
+     * @return an {@link AutoFDOProfileCollector} instance
+     */
+    public static AutoFDOProfileCollector newInstance(ITestDevice device) {
+        return new AutoFDOProfileCollector(device, () -> new RunUtil());
+    }
+
+    @VisibleForTesting
+    AutoFDOProfileCollector(ITestDevice device, RunUtilProvider runUtilProvider) {
+        mDevice = device;
+        mRunUtilProvider = runUtilProvider;
+    }
+
+    /**
+     * Starts recording an AutoFDO profile on device.
+     *
+     * <p>The recording runs in the background for the specified duration.
+     *
+     * @param durationSec The duration in seconds for which to record the profile.
+     * @return {@code true} if the recording was successfully started; {@code false} otherwise.
+     */
+    public boolean recordAutoFDOProfile(double durationSec) {
+        CLog.i("Record AutoFDO profile for " + durationSec + " seconds");
+        try {
+            mRecordProcess =
+                    mRunUtilProvider
+                            .get()
+                            .runCmdInBackground(
+                                    String.format(
+                                                    RECORD_CMDLINE,
+                                                    mDevice.getSerialNumber(),
+                                                    durationSec)
+                                            .split("\\s+"));
+        } catch (IOException e) {
+            CLog.e("Failed to start recording AutoFDO profile: " + e.getMessage());
+            return false;
+        }
+        return true;
+    }
+
+    /**
+     * Collects the recorded AutoFDO profile from the device to the host.
+     *
+     * <p>This method adds the AutoFDO profile into test log files.
+     *
+     * @param testArtifactReceiver An instance of {@link TestArtifactReceiver}.
+     * @return {@code true} if the profile was successfully collected; {@code false} otherwise.
+     * @throws DeviceNotAvailableException when the device is lost.
+     */
+    public boolean collectAutoFDOProfile(TestArtifactReceiver testArtifactReceiver)
+            throws DeviceNotAvailableException {
+        if (!finishRecordingAutoFDOProfile()) {
+            return false;
+        }
+        CLog.i("Pulling AutoFDO profile on host");
+        File profile = mDevice.pullFile(ON_DEVICE_PROFILE_PATH);
+        if (profile == null) {
+            CLog.e("Failed to pull AutoFDO profile to host");
+            return false;
+        }
+        testArtifactReceiver.addTestArtifact("autofdo_file", LogDataType.UNKNOWN, profile);
+        return true;
+    }
+
+    private boolean finishRecordingAutoFDOProfile() {
+        Process injectProcess = null;
+        try {
+            if (mRecordProcess == null) {
+                CLog.e("Recording process isn't available");
+                return false;
+            }
+            int retCode = mRecordProcess.waitFor();
+            if (retCode != 0) {
+                CLog.e("Error recording AutoFDO profile with exit code: " + retCode);
+                return false;
+            }
+            mRecordProcess = null;
+            injectProcess =
+                    mRunUtilProvider
+                            .get()
+                            .runCmdInBackground(
+                                    String.format(INJECT_CMDLINE, mDevice.getSerialNumber())
+                                            .split("\\s+"));
+            retCode = injectProcess.waitFor();
+            if (retCode != 0) {
+                CLog.e("Error converting AutoFDO profile: " + retCode);
+                return false;
+            }
+            return true;
+        } catch (InterruptedException e) {
+            CLog.e("Error recording AutoFDO profile: " + e.getMessage());
+            if (mRecordProcess != null) {
+                mRecordProcess.destroyForcibly();
+            }
+            if (injectProcess != null) {
+                injectProcess.destroyForcibly();
+            }
+            return false;
+        } catch (IOException e) {
+            CLog.e("Error recording AutoFDO profile: " + e.getMessage());
+            return false;
+        }
+    }
+}
diff --git a/harness/src/main/java/com/android/csuite/core/DeviceJUnit4ClassRunner.java b/harness/src/main/java/com/android/csuite/core/DeviceJUnit4ClassRunner.java
deleted file mode 100644
index b110a7a..0000000
--- a/harness/src/main/java/com/android/csuite/core/DeviceJUnit4ClassRunner.java
+++ /dev/null
@@ -1,46 +0,0 @@
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
-package com.android.csuite.core;
-
-import com.android.tradefed.config.IConfiguration;
-import com.android.tradefed.config.IConfigurationReceiver;
-
-import org.junit.runners.model.InitializationError;
-
-public class DeviceJUnit4ClassRunner extends com.android.tradefed.testtype.DeviceJUnit4ClassRunner
-        implements IConfigurationReceiver {
-    private IConfiguration mConfiguration;
-
-    public DeviceJUnit4ClassRunner(Class<?> klass) throws InitializationError {
-        super(klass);
-    }
-
-    @Override
-    protected Object createTest() throws Exception {
-        Object testObj = super.createTest();
-
-        if (testObj instanceof IConfigurationReceiver) {
-            ((IConfigurationReceiver) testObj).setConfiguration(mConfiguration);
-        }
-
-        return testObj;
-    }
-
-    @Override
-    public void setConfiguration(IConfiguration configuration) {
-        mConfiguration = configuration;
-    }
-}
diff --git a/harness/src/main/java/com/android/csuite/core/DeviceUtils.java b/harness/src/main/java/com/android/csuite/core/DeviceUtils.java
index ba8cc50..4394629 100644
--- a/harness/src/main/java/com/android/csuite/core/DeviceUtils.java
+++ b/harness/src/main/java/com/android/csuite/core/DeviceUtils.java
@@ -16,9 +16,7 @@
 
 package com.android.csuite.core;
 
-import android.service.dropbox.DropBoxManagerServiceDumpProto;
-import android.service.dropbox.DropBoxManagerServiceDumpProto.Entry;
-
+import com.android.csuite.core.DropboxEntryCrashDetector.DropboxEntry;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.DeviceRuntimeException;
 import com.android.tradefed.device.ITestDevice;
@@ -30,12 +28,9 @@ import com.android.tradefed.util.IRunUtil;
 import com.android.tradefed.util.RunUtil;
 
 import com.google.common.annotations.VisibleForTesting;
-import com.google.protobuf.InvalidProtocolBufferException;
 
 import java.io.File;
 import java.io.IOException;
-import java.nio.file.Files;
-import java.nio.file.Path;
 import java.time.Instant;
 import java.time.ZoneId;
 import java.time.format.DateTimeFormatter;
@@ -43,11 +38,9 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.Comparator;
-import java.util.HashMap;
 import java.util.List;
 import java.util.ListIterator;
 import java.util.Random;
-import java.util.Set;
 import java.util.concurrent.TimeUnit;
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
@@ -59,25 +52,8 @@ public class DeviceUtils {
     @VisibleForTesting static final String VERSION_CODE_PREFIX = "versionCode=";
     @VisibleForTesting static final String VERSION_NAME_PREFIX = "versionName=";
     @VisibleForTesting static final String RESET_PACKAGE_COMMAND_PREFIX = "pm clear ";
-    public static final Set<String> DROPBOX_APP_CRASH_TAGS =
-            Set.of(
-                    "SYSTEM_TOMBSTONE",
-                    "system_app_anr",
-                    "system_app_native_crash",
-                    "system_app_crash",
-                    "data_app_anr",
-                    "data_app_native_crash",
-                    "data_app_crash");
 
     private static final String VIDEO_PATH_ON_DEVICE_TEMPLATE = "/sdcard/screenrecord_%s.mp4";
-    private static final DateTimeFormatter DROPBOX_TIME_FORMATTER =
-            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss_SSS");
-    // Pattern for finding a package name following one of the tags such as "Process:" or
-    // "Package:".
-    private static final Pattern DROPBOX_PACKAGE_NAME_PATTERN =
-            Pattern.compile(
-                    "\\b(Process|Cmdline|Package|Cmd line):("
-                            + " *)([a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+)");
 
     @VisibleForTesting
     static final int WAIT_FOR_SCREEN_RECORDING_START_STOP_TIMEOUT_MILLIS = 10 * 1000;
@@ -88,7 +64,6 @@ public class DeviceUtils {
     private final Sleeper mSleeper;
     private final Clock mClock;
     private final RunUtilProvider mRunUtilProvider;
-    private final TempFileSupplier mTempFileSupplier;
 
     public static DeviceUtils getInstance(ITestDevice device) {
         return new DeviceUtils(
@@ -97,22 +72,15 @@ public class DeviceUtils {
                     Thread.sleep(duration);
                 },
                 () -> System.currentTimeMillis(),
-                () -> RunUtil.getDefault(),
-                () -> Files.createTempFile(TestUtils.class.getName(), ".tmp"));
+                () -> RunUtil.getDefault());
     }
 
     @VisibleForTesting
-    DeviceUtils(
-            ITestDevice device,
-            Sleeper sleeper,
-            Clock clock,
-            RunUtilProvider runUtilProvider,
-            TempFileSupplier tempFileSupplier) {
+    DeviceUtils(ITestDevice device, Sleeper sleeper, Clock clock, RunUtilProvider runUtilProvider) {
         mDevice = device;
         mSleeper = sleeper;
         mClock = clock;
         mRunUtilProvider = runUtilProvider;
-        mTempFileSupplier = tempFileSupplier;
     }
 
     /**
@@ -374,6 +342,68 @@ public class DeviceUtils {
                         + " command failed: %s",
                 packageName, monkeyResult);
 
+        String activity = getLaunchActivityName(packageName);
+
+        CommandResult amResult =
+                mDevice.executeShellV2Command(String.format("am start -n %s", activity));
+        if (amResult.getStatus() != CommandStatus.SUCCESS
+                || amResult.getExitCode() != 0
+                || amResult.getStdout().contains("Error")) {
+            throw new DeviceUtilsException(
+                    String.format(
+                            "The command to start the package %s with activity %s failed: %s",
+                            packageName, activity, amResult));
+        }
+    }
+
+    /**
+     * Warm launches a package on the device.
+     *
+     * @param packageName The package name to launch.
+     * @throws DeviceNotAvailableException When device was lost.
+     * @throws DeviceUtilsException When failed to launch the package.
+     */
+    public void warmLaunchPackage(String packageName)
+            throws DeviceUtilsException, DeviceNotAvailableException {
+        String activity = getLaunchActivityName(packageName);
+
+        // 0x00008000: Set the FLAG_ACTIVITY_CLEAR_TASK flag to the intent when it launches the app.
+        CommandResult amResult =
+                mDevice.executeShellV2Command(String.format("am start -f 0x00008000 -W -n %s", activity));
+        if (amResult.getStatus() != CommandStatus.SUCCESS
+                || amResult.getExitCode() != 0
+                || amResult.getStdout().contains("Error")) {
+            throw new DeviceUtilsException(
+                    String.format(
+                            "The command to warm start the package %s with activity %s failed: %s",
+                            packageName, activity, amResult));
+        }
+    }
+
+    /**
+     * Presses the home button on the device.
+     *
+     * @throws DeviceNotAvailableException When device was lost.
+     */
+    public void pressHome() throws DeviceNotAvailableException {
+        CommandResult homeResult = mDevice.executeShellV2Command("am start -a android.intent.action.MAIN -c android.intent.category.HOME");
+        if (homeResult.getStatus() != CommandStatus.SUCCESS || homeResult.getExitCode() != 0) {
+            throw new DeviceNotAvailableException(
+                    String.format(
+                            "The command to press home failed: %s",
+                            homeResult));
+        }
+    }
+
+    /**
+     * Gets the launch activity name of a package.
+     *
+     * @param packageName The package name to get the launch activity name for.
+     * @return The launch activity name of the package.
+     * @throws DeviceNotAvailableException When device was lost.
+     * @throws DeviceUtilsException When failed to get the launch activity name.
+     */
+    String getLaunchActivityName(String packageName) throws DeviceUtilsException, DeviceNotAvailableException {
         CommandResult pmResult =
                 mDevice.executeShellV2Command(String.format("pm dump %s", packageName));
         if (pmResult.getStatus() != CommandStatus.SUCCESS || pmResult.getExitCode() != 0) {
@@ -387,19 +417,7 @@ public class DeviceUtils {
                         String.format("Package %s is not installed on the device.", packageName));
             }
         }
-
-        String activity = getLaunchActivity(pmResult.getStdout());
-
-        CommandResult amResult =
-                mDevice.executeShellV2Command(String.format("am start -n %s", activity));
-        if (amResult.getStatus() != CommandStatus.SUCCESS
-                || amResult.getExitCode() != 0
-                || amResult.getStdout().contains("Error")) {
-            throw new DeviceUtilsException(
-                    String.format(
-                            "The command to start the package %s with activity %s failed: %s",
-                            packageName, activity, amResult));
-        }
+        return getLaunchActivity(pmResult.getStdout());
     }
 
     /**
@@ -627,284 +645,23 @@ public class DeviceUtils {
     }
 
     /**
-     * Gets dropbox entries from the device filtered by the provided tags.
+     * Gets dropbox entries from the device filtered by the crash tags.
      *
-     * @param tags Dropbox tags to query.
-     * @return A list of dropbox entries.
-     * @throws IOException when failed to dump or read the dropbox protos.
-     */
-    public List<DropboxEntry> getDropboxEntries(Set<String> tags) throws IOException {
-        CommandResult resHelp =
-                mRunUtilProvider
-                        .get()
-                        .runTimedCmd(
-                                1L * 60 * 1000,
-                                "sh",
-                                "-c",
-                                String.format(
-                                        "adb -s %s shell dumpsys dropbox --help",
-                                        mDevice.getSerialNumber()));
-        if (resHelp.getStatus() != CommandStatus.SUCCESS) {
-            throw new IOException("Dropbox dump help command failed: " + resHelp);
-        }
-        if (!resHelp.getStdout().contains("--proto")) {
-            // If dumping proto format is not supported such as in Android 10, the command will
-            // still succeed with exit code 0 and output strings instead of protobuf bytes,
-            // causing parse error. In this case we fallback to dumping dropbox --print option.
-            return getDropboxEntriesFromStdout(tags);
-        }
-
-        List<DropboxEntry> entries = new ArrayList<>();
-
-        for (String tag : tags) {
-            Path dumpFile = mTempFileSupplier.get();
-
-            CommandResult res =
-                    mRunUtilProvider
-                            .get()
-                            .runTimedCmd(
-                                    4L * 60 * 1000,
-                                    "sh",
-                                    "-c",
-                                    String.format(
-                                            "adb -s %s shell dumpsys dropbox --proto %s > %s",
-                                            mDevice.getSerialNumber(), tag, dumpFile));
-            if (res.getStatus() != CommandStatus.SUCCESS) {
-                throw new IOException("Dropbox dump command failed: " + res);
-            }
-
-            if (Files.size(dumpFile) == 0) {
-                CLog.d("Skipping empty proto " + dumpFile);
-                continue;
-            }
-
-            CLog.d("Parsing proto for tag %s. Size: %s", tag, Files.size(dumpFile));
-            DropBoxManagerServiceDumpProto proto;
-            try {
-                proto = DropBoxManagerServiceDumpProto.parseFrom(Files.readAllBytes(dumpFile));
-            } catch (InvalidProtocolBufferException e) {
-                CLog.e(
-                        "Falling back to stdout dropbox dump due to unexpected proto parse error:"
-                                + " %s",
-                        e);
-                return getDropboxEntriesFromStdout(tags);
-            }
-            Files.delete(dumpFile);
-
-            for (Entry entry : proto.getEntriesList()) {
-                entries.add(
-                        new DropboxEntry(entry.getTimeMs(), tag, entry.getData().toStringUtf8()));
-            }
-        }
-        return entries.stream()
-                .sorted(Comparator.comparing(DropboxEntry::getTime))
-                .collect(Collectors.toList());
-    }
-
-    /**
-     * Gets dropbox entries from the device filtered by the provided tags.
-     *
-     * @param tags Dropbox tags to query.
      * @param packageName package name for filtering the entries. Can be null.
      * @param startTime entry start timestamp to filter the results. Can be null.
      * @param endTime entry end timestamp to filter the results. Can be null.
      * @return A list of dropbox entries.
      * @throws IOException when failed to dump or read the dropbox protos.
      */
-    public List<DropboxEntry> getDropboxEntries(
-            Set<String> tags,
-            String packageName,
-            DeviceTimestamp startTime,
-            DeviceTimestamp endTime)
+    public List<DropboxEntry> getCrashEntriesFromDropbox(
+            String packageName, DeviceTimestamp startTime, DeviceTimestamp endTime)
             throws IOException {
-        return getDropboxEntries(tags).stream()
-                .filter(
-                        entry ->
-                                ((startTime == null || entry.getTime() >= startTime.get())
-                                        && (endTime == null || entry.getTime() < endTime.get())))
-                .filter(
-                        entry ->
-                                packageName == null
-                                        || isDropboxEntryFromPackageProcess(
-                                                entry.getData(), packageName))
-                .collect(Collectors.toList());
-    }
-
-    /* Checks whether a dropbox entry is logged from the given package name. */
-    @VisibleForTesting
-    boolean isDropboxEntryFromPackageProcess(String entryData, String packageName) {
-        Matcher m = DROPBOX_PACKAGE_NAME_PATTERN.matcher(entryData);
-
-        boolean matched = false;
-        while (m.find()) {
-            matched = true;
-            if (m.group(3).equals(packageName)) {
-                return true;
-            }
-        }
-
-        // Package/process name is identified but not equal to the packageName provided
-        if (matched) {
-            return false;
-        }
-
-        // If the process name is not identified, fall back to checking if the package name is
-        // present in the entry. This is because the process name detection logic above does not
-        // guarantee to identify the process name.
-        return Pattern.compile(
-                        String.format(
-                                // Pattern for checking whether a given package name exists.
-                                "(.*(?:[^a-zA-Z0-9_\\.]+)|^)%s((?:[^a-zA-Z0-9_\\.]+).*|$)",
-                                packageName.replaceAll("\\.", "\\\\.")))
-                .matcher(entryData)
-                .find();
-    }
-
-    @VisibleForTesting
-    List<DropboxEntry> getDropboxEntriesFromStdout(Set<String> tags) throws IOException {
-        HashMap<String, DropboxEntry> entries = new HashMap<>();
-
-        // The first step is to read the entry names and timestamps from the --file dump option
-        // output because the --print dump option does not contain timestamps.
-        CommandResult res;
-        Path fileDumpFile = mTempFileSupplier.get();
-        res =
-                mRunUtilProvider
-                        .get()
-                        .runTimedCmd(
-                                4L * 60 * 1000,
-                                "sh",
-                                "-c",
-                                String.format(
-                                        "adb -s %s shell dumpsys dropbox --file  > %s",
-                                        mDevice.getSerialNumber(), fileDumpFile));
-        if (res.getStatus() != CommandStatus.SUCCESS) {
-            throw new IOException("Dropbox dump command failed: " + res);
-        }
-
-        String lastEntryName = null;
-        for (String line : Files.readAllLines(fileDumpFile)) {
-            if (DropboxEntry.isDropboxEntryName(line)) {
-                lastEntryName = line.trim();
-                entries.put(lastEntryName, DropboxEntry.fromEntryName(line));
-            } else if (DropboxEntry.isDropboxFilePath(line) && lastEntryName != null) {
-                entries.get(lastEntryName).parseTimeFromFilePath(line);
-            }
-        }
-        Files.delete(fileDumpFile);
-
-        // Then we get the entry data from the --print dump output. Entry names parsed from the
-        // --print dump output are verified against the entry names from the --file dump output to
-        // ensure correctness.
-        Path printDumpFile = mTempFileSupplier.get();
-        res =
-                mRunUtilProvider
-                        .get()
-                        .runTimedCmd(
-                                4L * 60 * 1000,
-                                "sh",
-                                "-c",
-                                String.format(
-                                        "adb -s %s shell dumpsys dropbox --print > %s",
-                                        mDevice.getSerialNumber(), printDumpFile));
-        if (res.getStatus() != CommandStatus.SUCCESS) {
-            throw new IOException("Dropbox dump command failed: " + res);
-        }
-
-        lastEntryName = null;
-        for (String line : Files.readAllLines(printDumpFile)) {
-            if (DropboxEntry.isDropboxEntryName(line)) {
-                lastEntryName = line.trim();
-            }
-
-            if (lastEntryName != null && entries.containsKey(lastEntryName)) {
-                entries.get(lastEntryName).addData(line);
-                entries.get(lastEntryName).addData("\n");
-            }
-        }
-        Files.delete(printDumpFile);
-
-        return entries.values().stream()
-                .filter(entry -> tags.contains(entry.getTag()))
-                .collect(Collectors.toList());
-    }
-
-    /** A class that stores the information of a dropbox entry. */
-    public static final class DropboxEntry {
-        private long mTime;
-        private String mTag;
-        private final StringBuilder mData = new StringBuilder();
-        private static final Pattern ENTRY_NAME_PATTERN =
-                Pattern.compile(
-                        "\\d{4}\\-\\d{2}\\-\\d{2} \\d{2}:\\d{2}:\\d{2} .+ \\(.+, [0-9]+ .+\\)");
-        private static final Pattern DATE_PATTERN =
-                Pattern.compile("\\d{4}\\-\\d{2}\\-\\d{2} \\d{2}:\\d{2}:\\d{2}");
-        private static final Pattern FILE_NAME_PATTERN = Pattern.compile(" +/.+@[0-9]+\\..+");
-
-        /** Returns the entrt's time stamp on device. */
-        public long getTime() {
-            return mTime;
-        }
-
-        private void addData(String data) {
-            mData.append(data);
-        }
-
-        private void parseTimeFromFilePath(String input) {
-            mTime = Long.parseLong(input.substring(input.indexOf('@') + 1, input.indexOf('.')));
-        }
-
-        /** Returns the entrt's tag. */
-        public String getTag() {
-            return mTag;
-        }
-
-        /** Returns the entrt's data. */
-        public String getData() {
-            return mData.toString();
-        }
-
-        @Override
-        public String toString() {
-            long time = getTime();
-            String formattedTime =
-                    DROPBOX_TIME_FORMATTER.format(
-                            Instant.ofEpochMilli(time).atZone(ZoneId.systemDefault()));
-            return String.format(
-                    "Dropbox entry tag: %s\n"
-                            + "Dropbox entry timestamp: %s\n"
-                            + "Dropbox entry time: %s\n%s",
-                    getTag(), time, formattedTime, getData());
-        }
-
-        @VisibleForTesting
-        DropboxEntry(long time, String tag, String data) {
-            mTime = time;
-            mTag = tag;
-            addData(data);
-        }
-
-        private DropboxEntry() {
-            // Intentionally left blank;
-        }
-
-        private static DropboxEntry fromEntryName(String name) {
-            DropboxEntry entry = new DropboxEntry();
-            Matcher matcher = DATE_PATTERN.matcher(name);
-            if (!matcher.find()) {
-                throw new RuntimeException("Unexpected entry name: " + name);
-            }
-            entry.mTag = name.trim().substring(matcher.group().length()).trim().split(" ")[0];
-            return entry;
-        }
-
-        private static boolean isDropboxEntryName(String input) {
-            return ENTRY_NAME_PATTERN.matcher(input).find();
-        }
-
-        private static boolean isDropboxFilePath(String input) {
-            return FILE_NAME_PATTERN.matcher(input).find();
-        }
+        return DropboxEntryCrashDetector.getInstance(getITestDevice())
+                .getDropboxEntries(
+                        DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS,
+                        packageName,
+                        startTime,
+                        endTime);
     }
 
     /** A general exception class representing failed device utility operations. */
@@ -985,9 +742,4 @@ public class DeviceUtils {
     interface RunUtilProvider {
         IRunUtil get();
     }
-
-    @VisibleForTesting
-    interface TempFileSupplier {
-        Path get() throws IOException;
-    }
 }
diff --git a/harness/src/main/java/com/android/csuite/core/DropboxEntryCrashDetector.java b/harness/src/main/java/com/android/csuite/core/DropboxEntryCrashDetector.java
new file mode 100644
index 0000000..f25e486
--- /dev/null
+++ b/harness/src/main/java/com/android/csuite/core/DropboxEntryCrashDetector.java
@@ -0,0 +1,616 @@
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
+package com.android.csuite.core;
+
+import android.service.dropbox.DropBoxManagerServiceDumpProto;
+import android.service.dropbox.DropBoxManagerServiceDumpProto.Entry;
+
+import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.util.CommandResult;
+import com.android.tradefed.util.CommandStatus;
+import com.android.tradefed.util.IRunUtil;
+import com.android.tradefed.util.RunUtil;
+
+import com.google.common.annotations.VisibleForTesting;
+
+import java.io.IOException;
+import java.nio.charset.StandardCharsets;
+import java.nio.file.FileVisitResult;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.nio.file.SimpleFileVisitor;
+import java.nio.file.attribute.BasicFileAttributes;
+import java.time.Instant;
+import java.time.ZoneId;
+import java.time.format.DateTimeFormatter;
+import java.util.ArrayList;
+import java.util.Comparator;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Set;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
+import java.util.stream.Collectors;
+import java.util.stream.Stream;
+
+/** A package crash detector based on dropbox entries. */
+public class DropboxEntryCrashDetector {
+    public static final Set<String> DROPBOX_APP_CRASH_TAGS =
+            Set.of(
+                    "SYSTEM_TOMBSTONE",
+                    "system_app_anr",
+                    "system_app_native_crash",
+                    "system_app_crash",
+                    "data_app_anr",
+                    "data_app_native_crash",
+                    "data_app_crash");
+    private static final DateTimeFormatter DROPBOX_TIME_FORMATTER =
+            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss_SSS");
+    // Pattern for finding a package name following one of the tags such as "Process:" or
+    // "Package:".
+    private static final Pattern DROPBOX_PACKAGE_NAME_PATTERN =
+            Pattern.compile(
+                    "\\b(Process|Cmdline|Package|Cmd line):("
+                            + " *)([a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+)");
+
+    private final TempDirectorySupplier mTempDirectorySupplier;
+    private final RunUtilProvider mRunUtilProvider;
+    private final ITestDevice mDevice;
+    @VisibleForTesting static final String FILE_OUTPUT_NAME = "file-output.txt";
+    @VisibleForTesting static final String PRINT_OUTPUT_NAME = "print-output.txt";
+    @VisibleForTesting static final String DROPBOX_TAR_NAME = "dropbox.tar.gz";
+
+    /** Get an instance of a dropbox entry based crash detector */
+    public static DropboxEntryCrashDetector getInstance(ITestDevice device) {
+        return new DropboxEntryCrashDetector(
+                device,
+                () -> RunUtil.getDefault(),
+                () -> Files.createTempDirectory(TestUtils.class.getName()));
+    }
+
+    @VisibleForTesting
+    DropboxEntryCrashDetector(
+            ITestDevice device,
+            RunUtilProvider runUtilProvider,
+            TempDirectorySupplier tempDirectorySupplier) {
+        mDevice = device;
+        mRunUtilProvider = runUtilProvider;
+        mTempDirectorySupplier = tempDirectorySupplier;
+    }
+
+    /**
+     * Gets dropbox entries from the device filtered by the provided tags.
+     *
+     * @param tags Dropbox tags to query.
+     * @param packageName package name for filtering the entries. Can be null.
+     * @param startTime entry start timestamp to filter the results. Can be null.
+     * @param endTime entry end timestamp to filter the results. Can be null.
+     * @return A list of dropbox entries.
+     * @throws IOException when failed to dump or read the dropbox protos.
+     */
+    public List<DropboxEntry> getDropboxEntries(
+            Set<String> tags,
+            String packageName,
+            DeviceTimestamp startTime,
+            DeviceTimestamp endTime)
+            throws IOException {
+        // Will first attempt the adb pull method as it's most reliable and fast among all the
+        // methods.
+        List<DropboxEntry> entries = null;
+
+        try {
+            entries = getDropboxEntriesFromProtoDump(tags);
+        } catch (IOException e) {
+            // This method could fail when the data of dropbox is too large and the proto will
+            // be truncated causing parse error.
+            CLog.e(
+                    "Falling back to adb pull method. Failed to get dropbox entries from proto"
+                            + " dump: "
+                            + e);
+        }
+
+        if (entries == null) {
+            try {
+                entries = getDropboxEntriesFromAdbPull(tags, startTime, endTime);
+            } catch (IOException e) {
+                // This method relies on a few compress and decompress tools on the host and the
+                // device. It could fail if they aren't available.
+                CLog.e(
+                        "Falling back to text dump method. Failed to get dropbox entries from adb"
+                                + " pull: "
+                                + e);
+            }
+        }
+
+        if (entries == null) {
+            entries = getDropboxEntriesFromStdout();
+        }
+
+        return entries.stream()
+                .filter(entry -> tags.contains(entry.getTag()))
+                .filter(
+                        entry ->
+                                ((startTime == null || entry.getTime() >= startTime.get())
+                                        && (endTime == null || entry.getTime() < endTime.get())))
+                .filter(
+                        entry ->
+                                packageName == null
+                                        || isDropboxEntryFromPackageProcess(
+                                                entry.getData(), packageName))
+                .collect(Collectors.toList());
+    }
+
+    /* Checks whether a dropbox entry is logged from the given package name. */
+    @VisibleForTesting
+    boolean isDropboxEntryFromPackageProcess(String entryData, String packageName) {
+        Matcher m = DROPBOX_PACKAGE_NAME_PATTERN.matcher(entryData);
+
+        boolean matched = false;
+        while (m.find()) {
+            matched = true;
+            if (m.group(3).equals(packageName)) {
+                return true;
+            }
+        }
+
+        // Package/process name is identified but not equal to the packageName provided
+        if (matched) {
+            return false;
+        }
+
+        // If the process name is not identified, fall back to checking if the package name is
+        // present in the entry. This is because the process name detection logic above does not
+        // guarantee to identify the process name.
+        return Pattern.compile(
+                        String.format(
+                                // Pattern for checking whether a given package name exists.
+                                "(.*(?:[^a-zA-Z0-9_\\.]+)|^)%s((?:[^a-zA-Z0-9_\\.]+).*|$)",
+                                packageName.replaceAll("\\.", "\\\\.")))
+                .matcher(entryData)
+                .find();
+    }
+
+    @VisibleForTesting
+    List<DropboxEntry> getDropboxEntriesFromAdbPull(
+            Set<String> tags, DeviceTimestamp startTime, DeviceTimestamp endTime)
+            throws IOException {
+        List<DropboxEntry> entries = new ArrayList<>();
+
+        CommandResult resLs =
+                mRunUtilProvider
+                        .get()
+                        .runTimedCmd(
+                                1L * 60 * 1000,
+                                "sh",
+                                "-c",
+                                String.format(
+                                        "adb -s %s shell ls /data/system/dropbox/",
+                                        mDevice.getSerialNumber()));
+        if (resLs.getStatus() != CommandStatus.SUCCESS) {
+            throw new IOException("tar command failed: " + resLs);
+        }
+        List<String> compressList = new ArrayList<>();
+        for (String line : resLs.getStdout().split("\\s+")) {
+            if (line.isEmpty()) {
+                continue;
+            }
+            Path path = Path.of("/data/system/dropbox/").resolve(line);
+            EntryFile entryFile = new EntryFile(path);
+            if (tags.contains(entryFile.getTag())
+                    && entryFile.getTime() >= startTime.get()
+                    && entryFile.getTime() <= endTime.get()) {
+                compressList.add(path.toString());
+            }
+        }
+
+        if (compressList.isEmpty()) {
+            return entries;
+        }
+
+        CommandResult resTar =
+                mRunUtilProvider
+                        .get()
+                        .runTimedCmd(
+                                1L * 60 * 1000,
+                                "sh",
+                                "-c",
+                                String.format(
+                                        "adb -s %s shell tar -czf /data/local/tmp/%s %s",
+                                        mDevice.getSerialNumber(),
+                                        DROPBOX_TAR_NAME,
+                                        String.join(" ", compressList)));
+        if (resTar.getStatus() != CommandStatus.SUCCESS) {
+            throw new IOException("tar command failed: " + resTar);
+        }
+
+        Path tmpDir = mTempDirectorySupplier.get();
+        try {
+            CommandResult resPull =
+                    mRunUtilProvider
+                            .get()
+                            .runTimedCmd(
+                                    1L * 60 * 1000,
+                                    "sh",
+                                    "-c",
+                                    String.format(
+                                            "adb -s %s pull /data/local/tmp/%s %s",
+                                            mDevice.getSerialNumber(), DROPBOX_TAR_NAME, tmpDir));
+            if (resPull.getStatus() != CommandStatus.SUCCESS) {
+                throw new IOException("Adb pull command failed: " + resPull);
+            }
+
+            mRunUtilProvider
+                    .get()
+                    .runTimedCmd(
+                            1L * 60 * 1000,
+                            "sh",
+                            "-c",
+                            String.format(
+                                    "adb -s %s shell rm -rf /data/local/tmp/%s",
+                                    mDevice.getSerialNumber(), DROPBOX_TAR_NAME));
+
+            CommandResult resUntar =
+                    mRunUtilProvider
+                            .get()
+                            .runTimedCmd(
+                                    1L * 60 * 1000,
+                                    "tar",
+                                    "-xzf",
+                                    tmpDir.resolve(DROPBOX_TAR_NAME).toString(),
+                                    "-C",
+                                    tmpDir.toString());
+            if (resUntar.getStatus() != CommandStatus.SUCCESS) {
+                throw new IOException("Decompress command failed: " + resUntar);
+            }
+
+            Path dropboxDir = tmpDir.resolve("data/system/dropbox/");
+            try (Stream<Path> originalEntryFiles = Files.list(dropboxDir)) {
+                for (Path path : originalEntryFiles.collect(Collectors.toList())) {
+                    EntryFile entryFile = new EntryFile(path);
+
+                    String data = null;
+                    switch (entryFile.getExtension()) {
+                        case "txt.gz":
+                            CommandResult resRead =
+                                    mRunUtilProvider
+                                            .get()
+                                            .runTimedCmd(
+                                                    1L * 60 * 1000,
+                                                    "gunzip",
+                                                    "-c",
+                                                    path.toString());
+                            if (resRead.getStatus() != CommandStatus.SUCCESS) {
+                                throw new IOException("Decompress command failed: " + resRead);
+                            }
+                            data = resRead.getStdout();
+                            break;
+                        case "txt":
+                            data = Files.readString(path, StandardCharsets.UTF_8);
+                            break;
+                        case "lost":
+                        case "dat.gz":
+                        default:
+                            // Ignore
+                    }
+                    if (data == null) {
+                        continue;
+                    }
+                    entries.add(new DropboxEntry(entryFile.getTime(), entryFile.getTag(), data));
+                }
+            }
+
+        } finally {
+            deleteDirectory(tmpDir);
+        }
+
+        return entries;
+    }
+
+    /**
+     * Gets dropbox entries from the device filtered by the provided tags.
+     *
+     * @param tags Dropbox tags to query.
+     * @return A list of dropbox entries.
+     * @throws IOException when failed to dump or read the dropbox protos.
+     */
+    @VisibleForTesting
+    List<DropboxEntry> getDropboxEntriesFromProtoDump(Set<String> tags) throws IOException {
+        CommandResult resHelp =
+                mRunUtilProvider
+                        .get()
+                        .runTimedCmd(
+                                1L * 60 * 1000,
+                                "sh",
+                                "-c",
+                                String.format(
+                                        "adb -s %s shell dumpsys dropbox --help",
+                                        mDevice.getSerialNumber()));
+        if (resHelp.getStatus() != CommandStatus.SUCCESS) {
+            throw new IOException("Dropbox dump help command failed: " + resHelp);
+        }
+        if (!resHelp.getStdout().contains("--proto")) {
+            throw new IOException(
+                    "The current device doesn't support dumping dropbox entries in proto format.");
+        }
+
+        List<DropboxEntry> entries = new ArrayList<>();
+
+        Path tmpDir = mTempDirectorySupplier.get();
+        try {
+            for (String tag : tags) {
+                Path dumpFile = getProtoDumpFilePath(tmpDir, tag);
+                CommandResult res =
+                        mRunUtilProvider
+                                .get()
+                                .runTimedCmd(
+                                        4L * 60 * 1000,
+                                        "sh",
+                                        "-c",
+                                        String.format(
+                                                "adb -s %s shell dumpsys dropbox --proto %s > %s",
+                                                mDevice.getSerialNumber(), tag, dumpFile));
+                if (res.getStatus() != CommandStatus.SUCCESS) {
+                    throw new IOException("Dropbox dump command failed: " + res);
+                }
+
+                if (Files.size(dumpFile) == 0) {
+                    CLog.d("Skipping empty proto " + dumpFile);
+                    continue;
+                }
+
+                CLog.d("Parsing proto for tag %s. Size: %s", tag, Files.size(dumpFile));
+                DropBoxManagerServiceDumpProto proto =
+                        DropBoxManagerServiceDumpProto.parseFrom(Files.readAllBytes(dumpFile));
+                for (Entry entry : proto.getEntriesList()) {
+                    entries.add(
+                            new DropboxEntry(
+                                    entry.getTimeMs(), tag, entry.getData().toStringUtf8()));
+                }
+            }
+        } finally {
+            deleteDirectory(tmpDir);
+        }
+        return entries.stream()
+                .sorted(Comparator.comparing(DropboxEntry::getTime))
+                .collect(Collectors.toList());
+    }
+
+    @VisibleForTesting
+    List<DropboxEntry> getDropboxEntriesFromStdout() throws IOException {
+        HashMap<String, DropboxEntry> entries = new HashMap<>();
+
+        // The first step is to read the entry names and timestamps from the --file dump option
+        // output because the --print dump option does not contain timestamps.
+        CommandResult res;
+        Path tmpDir = mTempDirectorySupplier.get();
+        try {
+            res =
+                    mRunUtilProvider
+                            .get()
+                            .runTimedCmd(
+                                    4L * 60 * 1000,
+                                    "sh",
+                                    "-c",
+                                    String.format(
+                                            "adb -s %s shell dumpsys dropbox --file  > %s",
+                                            mDevice.getSerialNumber(),
+                                            tmpDir.resolve(FILE_OUTPUT_NAME)));
+            if (res.getStatus() != CommandStatus.SUCCESS) {
+                throw new IOException("Dropbox dump command failed: " + res);
+            }
+
+            String lastEntryName = null;
+            for (String line : Files.readAllLines(tmpDir.resolve(FILE_OUTPUT_NAME))) {
+                if (DropboxEntry.isDropboxEntryName(line)) {
+                    lastEntryName = line.trim();
+                    entries.put(lastEntryName, DropboxEntry.fromEntryName(line));
+                } else if (DropboxEntry.isDropboxFilePath(line) && lastEntryName != null) {
+                    entries.get(lastEntryName).parseTimeFromFilePath(line);
+                }
+            }
+
+            // Then we get the entry data from the --print dump output. Entry names parsed from the
+            // --print dump output are verified against the entry names from the --file dump output
+            // to
+            // ensure correctness.
+            res =
+                    mRunUtilProvider
+                            .get()
+                            .runTimedCmd(
+                                    4L * 60 * 1000,
+                                    "sh",
+                                    "-c",
+                                    String.format(
+                                            "adb -s %s shell dumpsys dropbox --print > %s",
+                                            mDevice.getSerialNumber(),
+                                            tmpDir.resolve(PRINT_OUTPUT_NAME)));
+            if (res.getStatus() != CommandStatus.SUCCESS) {
+                throw new IOException("Dropbox dump command failed: " + res);
+            }
+
+            lastEntryName = null;
+            for (String line : Files.readAllLines(tmpDir.resolve(PRINT_OUTPUT_NAME))) {
+                if (DropboxEntry.isDropboxEntryName(line)) {
+                    lastEntryName = line.trim();
+                }
+
+                if (lastEntryName != null && entries.containsKey(lastEntryName)) {
+                    entries.get(lastEntryName).addData(line);
+                    entries.get(lastEntryName).addData("\n");
+                }
+            }
+        } finally {
+            deleteDirectory(tmpDir);
+        }
+
+        return new ArrayList<>(entries.values());
+    }
+
+    private void deleteDirectory(Path directory) throws IOException {
+        Files.walkFileTree(
+                directory,
+                new SimpleFileVisitor<Path>() {
+                    @Override
+                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
+                            throws IOException {
+                        Files.delete(file);
+                        return FileVisitResult.CONTINUE;
+                    }
+
+                    @Override
+                    public FileVisitResult postVisitDirectory(Path dir, IOException exc)
+                            throws IOException {
+                        if (exc == null) {
+                            Files.delete(dir);
+                            return FileVisitResult.CONTINUE;
+                        } else {
+                            throw exc;
+                        }
+                    }
+                });
+    }
+
+    /** A class that stores the information of a dropbox entry. */
+    public static final class DropboxEntry {
+        private long mTime;
+        private String mTag;
+        private final StringBuilder mData = new StringBuilder();
+        private static final Pattern ENTRY_NAME_PATTERN =
+                Pattern.compile(
+                        "\\d{4}\\-\\d{2}\\-\\d{2} \\d{2}:\\d{2}:\\d{2} .+ \\(.+, [0-9]+ .+\\)");
+        private static final Pattern DATE_PATTERN =
+                Pattern.compile("\\d{4}\\-\\d{2}\\-\\d{2} \\d{2}:\\d{2}:\\d{2}");
+        private static final Pattern FILE_NAME_PATTERN = Pattern.compile(" +/.+@[0-9]+\\..+");
+
+        /** Returns the entrt's time stamp on device. */
+        public long getTime() {
+            return mTime;
+        }
+
+        private void addData(String data) {
+            mData.append(data);
+        }
+
+        private void parseTimeFromFilePath(String input) {
+            mTime = Long.parseLong(input.substring(input.indexOf('@') + 1, input.indexOf('.')));
+        }
+
+        /** Returns the entrt's tag. */
+        public String getTag() {
+            return mTag;
+        }
+
+        /** Returns the entrt's data. */
+        public String getData() {
+            return mData.toString();
+        }
+
+        @Override
+        public String toString() {
+            long time = getTime();
+            String formattedTime =
+                    DROPBOX_TIME_FORMATTER.format(
+                            Instant.ofEpochMilli(time).atZone(ZoneId.systemDefault()));
+            return String.format(
+                    "Dropbox entry tag: %s\n"
+                            + "Dropbox entry timestamp: %s\n"
+                            + "Dropbox entry time: %s\n%s",
+                    getTag(), time, formattedTime, getData());
+        }
+
+        @VisibleForTesting
+        DropboxEntry(long time, String tag, String data) {
+            mTime = time;
+            mTag = tag;
+            addData(data);
+        }
+
+        private DropboxEntry() {
+            // Intentionally left blank;
+        }
+
+        private static DropboxEntry fromEntryName(String name) {
+            DropboxEntry entry = new DropboxEntry();
+            Matcher matcher = DATE_PATTERN.matcher(name);
+            if (!matcher.find()) {
+                throw new RuntimeException("Unexpected entry name: " + name);
+            }
+            entry.mTag = name.trim().substring(matcher.group().length()).trim().split(" ")[0];
+            return entry;
+        }
+
+        private static boolean isDropboxEntryName(String input) {
+            return ENTRY_NAME_PATTERN.matcher(input).find();
+        }
+
+        private static boolean isDropboxFilePath(String input) {
+            return FILE_NAME_PATTERN.matcher(input).find();
+        }
+    }
+
+    private static class EntryFile {
+        private String mTag;
+        private long mTime;
+        private String mExtension;
+
+        private EntryFile(Path path) throws IOException {
+            String fileName = path.getFileName().toString();
+            int idxAt = fileName.indexOf('@');
+            int idxDot = fileName.indexOf('.');
+            if (idxAt <= 0 || idxDot <= 0) {
+                throw new IOException("Unrecognized dropbox entry file name " + path);
+            }
+            mTag = fileName.substring(0, idxAt);
+            try {
+                mTime = Long.parseLong(fileName.substring(idxAt + 1, idxDot));
+            } catch (NumberFormatException e) {
+                throw new IOException(e);
+            }
+
+            mExtension = fileName.substring(idxDot + 1);
+        }
+
+        private String getTag() {
+            return mTag;
+        }
+
+        private long getTime() {
+            return mTime;
+        }
+
+        private String getExtension() {
+            return mExtension;
+        }
+    }
+
+    @VisibleForTesting
+    interface RunUtilProvider {
+        IRunUtil get();
+    }
+
+    @VisibleForTesting
+    interface TempDirectorySupplier {
+        Path get() throws IOException;
+    }
+
+    @VisibleForTesting
+    static Path getProtoDumpFilePath(Path dir, String tag) {
+        return dir.resolve(tag + ".proto");
+    }
+}
diff --git a/harness/src/main/java/com/android/csuite/core/TestUtils.java b/harness/src/main/java/com/android/csuite/core/TestUtils.java
index e9971f9..537af17 100644
--- a/harness/src/main/java/com/android/csuite/core/TestUtils.java
+++ b/harness/src/main/java/com/android/csuite/core/TestUtils.java
@@ -17,7 +17,7 @@
 package com.android.csuite.core;
 
 import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
-import com.android.csuite.core.DeviceUtils.DropboxEntry;
+import com.android.csuite.core.DropboxEntryCrashDetector.DropboxEntry;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.log.LogUtil.CLog;
@@ -34,6 +34,7 @@ import java.io.File;
 import java.io.IOException;
 import java.nio.file.Files;
 import java.nio.file.Path;
+import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.List;
@@ -246,8 +247,7 @@ public class TestUtils {
             String packageName, DeviceTimestamp startTimeOnDevice, boolean saveToFile)
             throws IOException {
         List<DropboxEntry> crashEntries =
-                mDeviceUtils.getDropboxEntries(
-                        DeviceUtils.DROPBOX_APP_CRASH_TAGS, packageName, startTimeOnDevice, null);
+                mDeviceUtils.getCrashEntriesFromDropbox(packageName, startTimeOnDevice, null);
         return compileTestFailureMessage(packageName, crashEntries, saveToFile, null);
     }
 
@@ -270,7 +270,7 @@ public class TestUtils {
             DeviceTimestamp screenRecordStartTime)
             throws IOException {
         if (entries.size() == 0) {
-            return null;
+            return "";
         }
 
         BiFunction<String, Integer, String> truncateFunction =
@@ -443,19 +443,32 @@ public class TestUtils {
                                     apksAndObbs.toArray(new Path[apksAndObbs.size()])));
         }
 
-        Collections.sort(
-                apksAndObbs,
-                (first, second) -> {
-                    if (first.getFileName().toString().equals("base.apk")) {
-                        return -1;
-                    } else if (first.getFileName().toString().toLowerCase().endsWith(".obb")) {
-                        return 1;
-                    } else {
-                        return first.getFileName().compareTo(second.getFileName());
-                    }
-                });
-
-        return apksAndObbs;
+        // Reorder the apks and obbs to put the base.apk on the first index and .obb files on the
+        // end.
+        var reorderedApksAndObbs = new ArrayList<Path>();
+        apksAndObbs.stream()
+                .filter(path -> path.getFileName().toString().equals("base.apk"))
+                .forEach(reorderedApksAndObbs::add);
+        apksAndObbs.stream()
+                .filter(
+                        path ->
+                                path.getFileName().toString().endsWith(".apk")
+                                        && !path.getFileName().toString().equals("base.apk"))
+                .forEach(reorderedApksAndObbs::add);
+        apksAndObbs.stream()
+                .filter(
+                        path ->
+                                path.getFileName().toString().endsWith(".obb")
+                                        && path.getFileName().toString().startsWith("main"))
+                .forEach(reorderedApksAndObbs::add);
+        apksAndObbs.stream()
+                .filter(
+                        path ->
+                                path.getFileName().toString().endsWith(".obb")
+                                        && !path.getFileName().toString().startsWith("main"))
+                .forEach(reorderedApksAndObbs::add);
+
+        return reorderedApksAndObbs;
     }
 
     /** Returns the test information. */
diff --git a/harness/src/main/resources/config/csuite-base.xml b/harness/src/main/resources/config/csuite-base.xml
index ac8e426..ec35377 100644
--- a/harness/src/main/resources/config/csuite-base.xml
+++ b/harness/src/main/resources/config/csuite-base.xml
@@ -37,5 +37,9 @@
   <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
   <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
       <option name="run-command" value="settings put secure immersive_mode_confirmations confirmed" />
+      <option name="run-command" value="settings put global package_verifier_user_consent -1" />
+      <option name="teardown-command" value="settings put global package_verifier_user_consent 1" />
   </target_preparer>
+
+  <target_preparer class="com.android.csuite.core.AppCrawlTesterHostPreparer"/>
 </configuration>
diff --git a/harness/src/test/java/com/android/compatibility/targetprep/CheckGmsPreparerTest.java b/harness/src/test/java/com/android/compatibility/targetprep/CheckGmsPreparerTest.java
index 81e9011..f833df5 100644
--- a/harness/src/test/java/com/android/compatibility/targetprep/CheckGmsPreparerTest.java
+++ b/harness/src/test/java/com/android/compatibility/targetprep/CheckGmsPreparerTest.java
@@ -19,9 +19,9 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.testng.Assert.assertThrows;
 
-import com.android.ddmlib.Log;
-import com.android.ddmlib.Log.ILogOutput;
-import com.android.ddmlib.Log.LogLevel;
+import com.android.tradefed.log.Log;
+import com.android.tradefed.log.Log.ILogOutput;
+import com.android.tradefed.log.Log.LogLevel;
 import com.android.tradefed.build.BuildInfo;
 import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.device.ITestDevice;
diff --git a/harness/src/test/java/com/android/csuite/core/AppCrawlTesterHostPreparerTest.java b/harness/src/test/java/com/android/csuite/core/AppCrawlTesterHostPreparerTest.java
index 7a060ea..f8c6bbf 100644
--- a/harness/src/test/java/com/android/csuite/core/AppCrawlTesterHostPreparerTest.java
+++ b/harness/src/test/java/com/android/csuite/core/AppCrawlTesterHostPreparerTest.java
@@ -15,6 +15,11 @@
  */
 package com.android.csuite.core;
 
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
+
 import com.android.tradefed.build.BuildInfo;
 import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.device.ITestDevice;
@@ -26,13 +31,8 @@ import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
 import com.android.tradefed.util.IRunUtil;
 
-import static com.google.common.truth.Truth.assertThat;
-
 import com.google.common.jimfs.Jimfs;
 
-import static org.junit.Assert.assertNull;
-import static org.junit.Assert.assertThrows;
-
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -52,18 +52,18 @@ public final class AppCrawlTesterHostPreparerTest {
     IRunUtil mRunUtil = Mockito.mock(IRunUtil.class);
 
     @Test
-    public void getSdkPath_wasSet_returnsPath() {
+    public void getTempDirPath_wasSet_returnsPath() {
         Path path = Path.of("some");
-        AppCrawlTesterHostPreparer.setSdkPath(mTestInfo, path);
+        AppCrawlTesterHostPreparer.setTempDirPath(mTestInfo, path);
 
-        String result = AppCrawlTesterHostPreparer.getSdkPath(mTestInfo);
+        String result = AppCrawlTesterHostPreparer.getTempDirPath(mTestInfo);
 
         assertThat(result).isEqualTo(path.toString());
     }
 
     @Test
-    public void getSdkPath_wasNotSet_returnsNull() {
-        String result = AppCrawlTesterHostPreparer.getSdkPath(mTestInfo);
+    public void getTempDirPath_wasNotSet_returnsNull() {
+        String result = AppCrawlTesterHostPreparer.getTempDirPath(mTestInfo);
 
         assertNull(result);
     }
diff --git a/harness/src/test/java/com/android/csuite/core/AppCrawlTesterTest.java b/harness/src/test/java/com/android/csuite/core/AppCrawlTesterTest.java
index 1d2869b..28ed6ee 100644
--- a/harness/src/test/java/com/android/csuite/core/AppCrawlTesterTest.java
+++ b/harness/src/test/java/com/android/csuite/core/AppCrawlTesterTest.java
@@ -25,11 +25,10 @@ import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.Mockito.when;
 
+import com.android.csuite.core.AppCrawlTester.CrawlerException;
 import com.android.csuite.core.TestUtils.TestArtifactReceiver;
 import com.android.tradefed.build.BuildInfo;
-import com.android.tradefed.config.Configuration;
 import com.android.tradefed.config.ConfigurationException;
-import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.ITestDevice;
@@ -72,6 +71,7 @@ public final class AppCrawlTesterTest {
     private TestInformation mTestInfo;
     private TestUtils mTestUtils;
     private DeviceUtils mDeviceUtils = Mockito.spy(DeviceUtils.getInstance(mDevice));
+    private ApkInstaller mApkInstaller = new ApkInstaller("serial", mRunUtil, apk -> PACKAGE_NAME);
 
     @Before
     public void setUp() throws Exception {
@@ -81,49 +81,110 @@ public final class AppCrawlTesterTest {
     }
 
     @Test
-    public void startCrawl_apkNotProvided_throwsException() throws Exception {
+    public void run_noThrowNotEnabled_throwsOnFail() throws Exception {
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()));
+        Mockito.doReturn(new DeviceUtils.DeviceTimestamp(1L))
+                .when(mDeviceUtils)
+                .currentTimeMillis();
+        Mockito.doReturn("crash")
+                .when(mTestUtils)
+                .getDropboxPackageCrashLog(
+                        Mockito.anyString(), Mockito.any(), Mockito.anyBoolean());
+
+        assertThrows(AssertionError.class, () -> sut.run());
+    }
+
+    @Test
+    public void run_noThrowEnabled_doesNotThrowOnFail() throws Exception {
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()))
+                        .setNoThrowOnFailure(true);
+        Mockito.doReturn(new DeviceUtils.DeviceTimestamp(1L))
+                .when(mDeviceUtils)
+                .currentTimeMillis();
+        Mockito.doReturn("crash")
+                .when(mTestUtils)
+                .getDropboxPackageCrashLog(
+                        Mockito.anyString(), Mockito.any(), Mockito.anyBoolean());
+
+        sut.run();
+
+        assertThat(sut.isTestPassed()).isFalse();
+    }
+
+    @Test
+    public void runSetup_noThrowNotEnabled_throwsOnFail() throws Exception {
+        AppCrawlTester sut = createPreparedTestSubject().setSubjectApkPath(new File("invalid"));
+
+        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.runSetup());
+    }
+
+    @Test
+    public void runSetup_noThrowEnabled_doesNotThrowOnFail() throws Exception {
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setSubjectApkPath(new File("invalid"))
+                        .setNoThrowOnFailure(true);
+
+        sut.runSetup();
+
+        assertThat(sut.isTestPassed()).isFalse();
+    }
+
+    @Test
+    public void setOption_crawlerStarted_throws() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
+        sut.runSetup();
+
+        assertThrows(IllegalStateException.class, () -> sut.setSubjectPackageName(""));
+    }
+
+    @Test
+    public void startCrawl_apkNotProvided_throwsException() throws Exception {
+        AppCrawlTester sut = createPreparedTestSubject().setEspressoMode(true);
 
         assertThrows(NullPointerException.class, () -> sut.startCrawl());
     }
 
     @Test
     public void startCrawl_roboscriptDirectoryProvided_throws() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(true);
+        AppCrawlTester sut = createPreparedTestSubject().setEspressoMode(false);
         Path roboDir = mFileSystem.getPath("robo");
         Files.createDirectories(roboDir);
 
-        sut.getOptions().setRoboscriptFile(new File(roboDir.toString()));
+        sut.setRoboscriptFile(new File(roboDir.toString()));
 
         assertThrows(AssertionError.class, () -> sut.startCrawl());
     }
 
     @Test
     public void startCrawl_crawlGuidanceDirectoryProvided_throws() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(true);
+        AppCrawlTester sut = createPreparedTestSubject().setEspressoMode(false);
         Path crawlGuidanceDir = mFileSystem.getPath("crawlguide");
         Files.createDirectories(crawlGuidanceDir);
 
-        sut.getOptions().setCrawlGuidanceProtoFile(new File(crawlGuidanceDir.toString()));
+        sut.setCrawlGuidanceProtoFile(new File(crawlGuidanceDir.toString()));
 
         assertThrows(AssertionError.class, () -> sut.startCrawl());
     }
 
     @Test
     public void runTest_noCrashDetected_doesNotThrow() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()));
         Mockito.doReturn(new DeviceUtils.DeviceTimestamp(1L))
                 .when(mDeviceUtils)
                 .currentTimeMillis();
         Mockito.doReturn(new ArrayList<>())
                 .when(mDeviceUtils)
-                .getDropboxEntries(
-                        Mockito.any(), Mockito.anyString(), Mockito.any(), Mockito.any());
+                .getCrashEntriesFromDropbox(Mockito.anyString(), Mockito.any(), Mockito.any());
         sut.runSetup();
 
         sut.runTest();
@@ -131,9 +192,10 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void runTest_dropboxEntriesDetected_throws() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()));
         Mockito.doReturn(new DeviceUtils.DeviceTimestamp(1L))
                 .when(mDeviceUtils)
                 .currentTimeMillis();
@@ -148,14 +210,14 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void runTest_crawlerExceptionIsThrown_throws() throws Exception {
-        AppCrawlTester sut = createNotPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()));
         Mockito.doReturn(new DeviceUtils.DeviceTimestamp(1L))
                 .when(mDeviceUtils)
                 .currentTimeMillis();
-        String noCrashLog = null;
-        Mockito.doReturn(noCrashLog)
+        Mockito.doReturn("")
                 .when(mTestUtils)
                 .getDropboxPackageCrashLog(
                         Mockito.anyString(), Mockito.any(), Mockito.anyBoolean());
@@ -166,10 +228,11 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void startCrawl_screenRecordEnabled_screenIsRecorded() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
-        sut.getOptions().setRecordScreen(true);
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()))
+                        .setRecordScreen(true);
 
         sut.startCrawl();
 
@@ -179,10 +242,11 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void startCrawl_screenRecordDisabled_screenIsNotRecorded() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
-        sut.getOptions().setRecordScreen(false);
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()))
+                        .setRecordScreen(false);
 
         sut.startCrawl();
 
@@ -192,10 +256,11 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void startCrawl_collectGmsVersionEnabled_versionIsCollected() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
-        sut.getOptions().setCollectGmsVersion(true);
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()))
+                        .setCollectGmsVersion(true);
 
         sut.startCrawl();
 
@@ -204,10 +269,11 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void startCrawl_collectGmsVersionDisabled_versionIsNotCollected() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
-        sut.getOptions().setCollectGmsVersion(false);
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()))
+                        .setCollectGmsVersion(false);
 
         sut.startCrawl();
 
@@ -216,10 +282,11 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void startCrawl_collectAppVersionEnabled_versionIsCollected() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
-        sut.getOptions().setCollectAppVersion(true);
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()))
+                        .setCollectAppVersion(true);
 
         sut.startCrawl();
 
@@ -228,10 +295,11 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void startCrawl_collectAppVersionDisabled_versionIsNotCollected() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
-        sut.getOptions().setCollectAppVersion(false);
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()))
+                        .setCollectAppVersion(false);
 
         sut.startCrawl();
 
@@ -240,18 +308,20 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void startCrawl_withSplitApksDirectory_doesNotThrowException() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()));
 
         sut.startCrawl();
     }
 
     @Test
     public void startCrawl_sdkPathIsProvidedToCrawler() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()));
 
         sut.startCrawl();
 
@@ -265,9 +335,10 @@ public final class AppCrawlTesterTest {
         Files.createDirectories(root.resolve("sub"));
         Files.createFile(root.resolve("sub").resolve("base.apk"));
         Files.createFile(root.resolve("sub").resolve("config.apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(root));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(root));
 
         sut.startCrawl();
     }
@@ -277,9 +348,10 @@ public final class AppCrawlTesterTest {
         Path root = mFileSystem.getPath("apk");
         Files.createDirectories(root);
         Files.createFile(root.resolve("base.apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(root));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(root));
 
         sut.startCrawl();
     }
@@ -289,9 +361,10 @@ public final class AppCrawlTesterTest {
         Path root = mFileSystem.getPath("apk");
         Files.createDirectories(root);
         Files.createFile(root.resolve("single.apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(root));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(root));
 
         sut.startCrawl();
     }
@@ -300,9 +373,10 @@ public final class AppCrawlTesterTest {
     public void startCrawl_withSingleApkFile_doesNotThrowException() throws Exception {
         Path root = mFileSystem.getPath("single.apk");
         Files.createFile(root);
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(root));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(root));
 
         sut.startCrawl();
     }
@@ -314,9 +388,10 @@ public final class AppCrawlTesterTest {
         Files.createDirectories(root);
         Files.createFile(root.resolve("single.apk"));
         Files.createFile(root.resolve("single.not_apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(root));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(root));
 
         sut.startCrawl();
     }
@@ -326,9 +401,10 @@ public final class AppCrawlTesterTest {
         Path root = mFileSystem.getPath("apk");
         Files.createDirectories(root);
         Files.createFile(root.resolve("single.not_apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(root));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(root));
 
         assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.startCrawl());
     }
@@ -337,9 +413,10 @@ public final class AppCrawlTesterTest {
     public void startCrawl_withNonApkPath_throwException() throws Exception {
         Path root = mFileSystem.getPath("single.not_apk");
         Files.createFile(root);
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(root));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(root));
 
         assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.startCrawl());
     }
@@ -352,34 +429,33 @@ public final class AppCrawlTesterTest {
         Files.createDirectories(root.resolve("2"));
         Files.createFile(root.resolve("1").resolve("single.apk"));
         Files.createFile(root.resolve("2").resolve("single.apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(root));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(root));
 
         assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.startCrawl());
     }
 
     @Test
-    public void startCrawl_preparerNotRun_throwsException() throws Exception {
-        AppCrawlTester sut = createNotPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
-
-        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.startCrawl());
+    public void newCrawlTesterInstance_preparerNotRun_throwsException() throws Exception {
+        assertThrows(
+                AppCrawlTester.CrawlerException.class,
+                () -> new AppCrawlTester(mTestUtils, () -> mRunUtil, mFileSystem, mApkInstaller));
     }
 
     @Test
     public void runTest_alreadyRun_throwsException() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()));
         Mockito.doReturn(new DeviceUtils.DeviceTimestamp(1L))
                 .when(mDeviceUtils)
                 .currentTimeMillis();
         Mockito.doReturn(new ArrayList<>())
                 .when(mDeviceUtils)
-                .getDropboxEntries(
-                        Mockito.any(), Mockito.anyString(), Mockito.any(), Mockito.any());
+                .getCrashEntriesFromDropbox(Mockito.anyString(), Mockito.any(), Mockito.any());
         sut.runSetup();
         sut.runTest();
 
@@ -388,9 +464,10 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void cleanUpOutputDir_removesOutputDirectory() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(createApkPathWithSplitApks()));
         sut.startCrawl();
         assertTrue(Files.exists(sut.mOutput));
 
@@ -404,9 +481,10 @@ public final class AppCrawlTesterTest {
         Path apkRoot = mFileSystem.getPath("apk");
         Files.createDirectories(apkRoot);
         Files.createFile(apkRoot.resolve("some.apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(apkRoot));
         sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
@@ -423,12 +501,13 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void createUtpCrawlerRunCommand_containsRoboscriptFileWhenProvided() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
         Path roboDir = mFileSystem.getPath("/robo");
         Files.createDirectory(roboDir);
         Path roboFile = Files.createFile(roboDir.resolve("app.roboscript"));
-        sut.getOptions().setUiAutomatorMode(true);
-        sut.getOptions().setRoboscriptFile(new File(roboFile.toString()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(false)
+                        .setRoboscriptFile(new File(roboFile.toString()));
         sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
@@ -445,9 +524,9 @@ public final class AppCrawlTesterTest {
         Files.createDirectory(crawlGuideDir);
         Path crawlGuideFile = Files.createFile(crawlGuideDir.resolve("app.crawlguide"));
 
-        sut.getOptions().setUiAutomatorMode(true);
-        sut.getOptions().setCrawlGuidanceProtoFile(new File(crawlGuideFile.toString()));
-        sut.startCrawl();
+        sut.setEspressoMode(false)
+                .setCrawlGuidanceProtoFile(new File(crawlGuideFile.toString()))
+                .startCrawl();
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
         assertThat(result).asList().contains("--crawl-guidance-proto-path");
@@ -456,15 +535,16 @@ public final class AppCrawlTesterTest {
     @Test
     public void createUtpCrawlerRunCommand_loginDirContainsOnlyCrawlGuidanceFile_addsFilePath()
             throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
         Path loginFilesDir = mFileSystem.getPath("/login");
         Files.createDirectory(loginFilesDir);
         Path crawlGuideFile =
                 Files.createFile(loginFilesDir.resolve(PACKAGE_NAME + CRAWL_GUIDANCE_FILE_SUFFIX));
-
-        sut.getOptions().setUiAutomatorMode(true);
-        sut.getOptions().setLoginConfigDir(new File(loginFilesDir.toString()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(false)
+                        .setLoginConfigDir(new File(loginFilesDir.toString()));
         sut.startCrawl();
+
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
         assertThat(result).asList().contains("--crawl-guidance-proto-path");
@@ -474,15 +554,16 @@ public final class AppCrawlTesterTest {
     @Test
     public void createUtpCrawlerRunCommand_loginDirContainsOnlyRoboscriptFile_addsFilePath()
             throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
         Path loginFilesDir = mFileSystem.getPath("/login");
         Files.createDirectory(loginFilesDir);
         Path roboscriptFile =
                 Files.createFile(loginFilesDir.resolve(PACKAGE_NAME + ROBOSCRIPT_FILE_SUFFIX));
-
-        sut.getOptions().setUiAutomatorMode(true);
-        sut.getOptions().setLoginConfigDir(new File(loginFilesDir.toString()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(false)
+                        .setLoginConfigDir(new File(loginFilesDir.toString()));
         sut.startCrawl();
+
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
         assertThat(result).asList().contains("--crawler-asset");
@@ -493,17 +574,18 @@ public final class AppCrawlTesterTest {
     public void
             createUtpCrawlerRunCommand_loginDirContainsMultipleLoginFiles_addsRoboscriptFilePath()
                     throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
         Path loginFilesDir = mFileSystem.getPath("/login");
         Files.createDirectory(loginFilesDir);
         Path roboscriptFile =
                 Files.createFile(loginFilesDir.resolve(PACKAGE_NAME + ROBOSCRIPT_FILE_SUFFIX));
         Path crawlGuideFile =
                 Files.createFile(loginFilesDir.resolve(PACKAGE_NAME + CRAWL_GUIDANCE_FILE_SUFFIX));
-
-        sut.getOptions().setUiAutomatorMode(true);
-        sut.getOptions().setLoginConfigDir(new File(loginFilesDir.toString()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(false)
+                        .setLoginConfigDir(new File(loginFilesDir.toString()));
         sut.startCrawl();
+
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
         assertThat(result).asList().contains("--crawler-asset");
@@ -513,14 +595,14 @@ public final class AppCrawlTesterTest {
 
     @Test
     public void createUtpCrawlerRunCommand_loginDirEmpty_doesNotAddFlag() throws Exception {
-        AppCrawlTester sut = createPreparedTestSubject();
         Path loginFilesDir = mFileSystem.getPath("/login");
         Files.createDirectory(loginFilesDir);
-
-        sut.getOptions()
-                .setUiAutomatorMode(true)
-                .setLoginConfigDir(new File(loginFilesDir.toString()));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(false)
+                        .setLoginConfigDir(new File(loginFilesDir.toString()));
         sut.startCrawl();
+
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
         assertThat(result).asList().doesNotContain("--crawler-asset");
@@ -532,9 +614,10 @@ public final class AppCrawlTesterTest {
         Path apkRoot = mFileSystem.getPath("apk");
         Files.createDirectories(apkRoot);
         Files.createFile(apkRoot.resolve("some.apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(apkRoot));
         sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
@@ -551,9 +634,10 @@ public final class AppCrawlTesterTest {
         Files.createFile(apkRoot.resolve("base.apk"));
         Files.createFile(apkRoot.resolve("config1.apk"));
         Files.createFile(apkRoot.resolve("config2.apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(apkRoot));
         sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
@@ -572,9 +656,10 @@ public final class AppCrawlTesterTest {
         Files.createFile(apkRoot.resolve("config1.apk"));
         Files.createFile(apkRoot.resolve("main.package.obb"));
         Files.createFile(apkRoot.resolve("patch.package.obb"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(apkRoot));
         sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
@@ -598,10 +683,11 @@ public final class AppCrawlTesterTest {
         Files.createFile(apkRoot.resolve("base.apk"));
         Files.createFile(apkRoot.resolve("config1.apk"));
         Files.createFile(apkRoot.resolve("config2.apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(apkRoot));
-        sut.getOptions().setUiAutomatorMode(true);
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(apkRoot))
+                        .setEspressoMode(false);
         sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
@@ -618,10 +704,11 @@ public final class AppCrawlTesterTest {
         Files.createFile(apkRoot.resolve("base.apk"));
         Files.createFile(apkRoot.resolve("config1.apk"));
         Files.createFile(apkRoot.resolve("config2.apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(apkRoot));
-        sut.getOptions().setUiAutomatorMode(true);
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(apkRoot))
+                        .setEspressoMode(false);
         sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
@@ -645,9 +732,10 @@ public final class AppCrawlTesterTest {
         Files.createFile(apkRoot.resolve("base.apk"));
         Files.createFile(apkRoot.resolve("config1.apk"));
         Files.createFile(apkRoot.resolve("config2.apk"));
-        AppCrawlTester sut = createPreparedTestSubject();
-        sut.getOptions().setUiAutomatorMode(false);
-        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        AppCrawlTester sut =
+                createPreparedTestSubject()
+                        .setEspressoMode(true)
+                        .setSubjectApkPath(convertToFile(apkRoot));
         sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
@@ -715,7 +803,10 @@ public final class AppCrawlTesterTest {
     }
 
     private void simulatePreparerWasExecutedSuccessfully()
-            throws ConfigurationException, IOException, TargetSetupError {
+            throws ConfigurationException,
+                    IOException,
+                    TargetSetupError,
+                    DeviceNotAvailableException {
         IRunUtil runUtil = Mockito.mock(IRunUtil.class);
         Mockito.when(runUtil.runTimedCmd(Mockito.anyLong(), ArgumentMatchers.<String>any()))
                 .thenReturn(createSuccessfulCommandResult());
@@ -734,27 +825,13 @@ public final class AppCrawlTesterTest {
                 AppCrawlTesterHostPreparer.CREDENTIAL_JSON_OPTION,
                 Files.createDirectories(mFileSystem.getPath("/cred.json")).toString());
         preparer.setUp(mTestInfo);
-    }
-
-    private AppCrawlTester createNotPreparedTestSubject()
-            throws DeviceNotAvailableException, ConfigurationException {
-        Mockito.when(mRunUtil.runTimedCmd(Mockito.anyLong(), ArgumentMatchers.<String>any()))
-                .thenReturn(createSuccessfulCommandResult());
-        Mockito.when(mDevice.getSerialNumber()).thenReturn("serial");
-        when(mDevice.executeShellV2Command(Mockito.startsWith("echo ${EPOCHREALTIME")))
-                .thenReturn(createSuccessfulCommandResultWithStdout("1"));
-        when(mDevice.executeShellV2Command(Mockito.eq("getprop ro.build.version.sdk")))
-                .thenReturn(createSuccessfulCommandResultWithStdout("33"));
-        IConfiguration configuration = new Configuration("name", "description");
-        configuration.setConfigurationObject(
-                AppCrawlTesterOptions.OBJECT_TYPE, new AppCrawlTesterOptions());
-        return new AppCrawlTester(
-                PACKAGE_NAME, mTestUtils, () -> mRunUtil, mFileSystem, configuration);
+        String tempPathStr = AppCrawlTesterHostPreparer.getTempDirPath(mTestInfo);
+        Files.createDirectories(mFileSystem.getPath(tempPathStr));
     }
 
     private AppCrawlTester createPreparedTestSubject()
             throws IOException, ConfigurationException, TargetSetupError,
-                    DeviceNotAvailableException {
+                    DeviceNotAvailableException, CrawlerException {
         simulatePreparerWasExecutedSuccessfully();
         Mockito.when(mRunUtil.runTimedCmd(Mockito.anyLong(), ArgumentMatchers.<String>any()))
                 .thenReturn(createSuccessfulCommandResult());
@@ -763,11 +840,12 @@ public final class AppCrawlTesterTest {
                 .thenReturn(createSuccessfulCommandResultWithStdout("1"));
         when(mDevice.executeShellV2Command(Mockito.eq("getprop ro.build.version.sdk")))
                 .thenReturn(createSuccessfulCommandResultWithStdout("33"));
-        IConfiguration configuration = new Configuration("name", "description");
-        configuration.setConfigurationObject(
-                AppCrawlTesterOptions.OBJECT_TYPE, new AppCrawlTesterOptions());
-        return new AppCrawlTester(
-                PACKAGE_NAME, mTestUtils, () -> mRunUtil, mFileSystem, configuration);
+        AppCrawlTesterOptions preparer = new AppCrawlTesterOptions();
+        preparer.dump(mTestInfo, mFileSystem);
+        AppCrawlTester sut =
+                new AppCrawlTester(mTestUtils, () -> mRunUtil, mFileSystem, mApkInstaller)
+                        .setSubjectPackageName(PACKAGE_NAME);
+        return sut;
     }
 
     private TestUtils createTestUtils() throws DeviceNotAvailableException {
diff --git a/harness/src/test/java/com/android/csuite/core/AutoFDOProfileCollectorTest.java b/harness/src/test/java/com/android/csuite/core/AutoFDOProfileCollectorTest.java
new file mode 100644
index 0000000..22d3f86
--- /dev/null
+++ b/harness/src/test/java/com/android/csuite/core/AutoFDOProfileCollectorTest.java
@@ -0,0 +1,93 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.csuite.core;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.when;
+
+import com.android.csuite.core.TestUtils.TestArtifactReceiver;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.util.IRunUtil;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.ArgumentMatchers;
+import org.mockito.Mockito;
+
+import java.io.File;
+
+@RunWith(JUnit4.class)
+public class AutoFDOProfileCollectorTest {
+    private final ITestDevice mDevice = Mockito.mock(ITestDevice.class);
+    private final IRunUtil mRunUtil = Mockito.mock(IRunUtil.class);
+    private final TestArtifactReceiver mTestArtifactReceiver =
+            Mockito.mock(TestArtifactReceiver.class);
+    private AutoFDOProfileCollector mAutoFDOProfileCollector;
+
+    @Before
+    public void setUp() throws Exception {
+        when(mDevice.getSerialNumber()).thenReturn("serial");
+        mAutoFDOProfileCollector = new AutoFDOProfileCollector(mDevice, () -> mRunUtil);
+    }
+
+    @Test
+    public void recordAndCollectAutoFDOProfile_successScenario() throws Exception {
+        when(mRunUtil.runCmdInBackground(ArgumentMatchers.<String>any()))
+                .thenReturn(Mockito.mock(Process.class));
+        when(mDevice.pullFile(Mockito.eq(mAutoFDOProfileCollector.ON_DEVICE_PROFILE_PATH)))
+                .thenReturn(Mockito.mock(File.class));
+        assertThat(mAutoFDOProfileCollector.recordAutoFDOProfile(1)).isTrue();
+        assertThat(mAutoFDOProfileCollector.collectAutoFDOProfile(mTestArtifactReceiver)).isTrue();
+
+        Mockito.verify(mDevice, times(1)).pullFile(Mockito.any(String.class));
+        Mockito.verify(mTestArtifactReceiver, times(1))
+                .addTestArtifact(
+                        Mockito.contains("autofdo_file"), Mockito.any(), Mockito.any(File.class));
+    }
+
+    @Test
+    public void recordAndCollectAutoFDOProfile_failsToRecord() throws Exception {
+        when(mRunUtil.runCmdInBackground(ArgumentMatchers.<String>any())).thenReturn(null);
+        when(mDevice.pullFile(Mockito.eq(mAutoFDOProfileCollector.ON_DEVICE_PROFILE_PATH)))
+                .thenReturn(Mockito.mock(File.class));
+        assertThat(mAutoFDOProfileCollector.recordAutoFDOProfile(1)).isTrue();
+        assertThat(mAutoFDOProfileCollector.collectAutoFDOProfile(mTestArtifactReceiver)).isFalse();
+
+        Mockito.verify(mDevice, times(0)).pullFile(Mockito.any(String.class));
+        Mockito.verify(mTestArtifactReceiver, times(0))
+                .addTestArtifact(
+                        Mockito.contains("autofdo_file"), Mockito.any(), Mockito.any(File.class));
+    }
+
+    @Test
+    public void recordAndCollectAutoFDOProfile_failsToPullFile() throws Exception {
+        when(mRunUtil.runCmdInBackground(ArgumentMatchers.<String>any()))
+                .thenReturn(Mockito.mock(Process.class));
+        when(mDevice.pullFile(Mockito.eq(mAutoFDOProfileCollector.ON_DEVICE_PROFILE_PATH)))
+                .thenReturn(null);
+        assertThat(mAutoFDOProfileCollector.recordAutoFDOProfile(1)).isTrue();
+        assertThat(mAutoFDOProfileCollector.collectAutoFDOProfile(mTestArtifactReceiver)).isFalse();
+
+        Mockito.verify(mDevice, times(1)).pullFile(Mockito.any(String.class));
+        Mockito.verify(mTestArtifactReceiver, times(0))
+                .addTestArtifact(
+                        Mockito.contains("autofdo_file"), Mockito.any(), Mockito.any(File.class));
+    }
+}
diff --git a/harness/src/test/java/com/android/csuite/core/DeviceUtilsTest.java b/harness/src/test/java/com/android/csuite/core/DeviceUtilsTest.java
index f635c20..1219939 100644
--- a/harness/src/test/java/com/android/csuite/core/DeviceUtilsTest.java
+++ b/harness/src/test/java/com/android/csuite/core/DeviceUtilsTest.java
@@ -22,11 +22,8 @@ import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.Mockito.when;
 
-import android.service.dropbox.DropBoxManagerServiceDumpProto;
-
 import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
 import com.android.csuite.core.DeviceUtils.DeviceUtilsException;
-import com.android.csuite.core.DeviceUtils.DropboxEntry;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.DeviceRuntimeException;
 import com.android.tradefed.device.ITestDevice;
@@ -34,9 +31,6 @@ import com.android.tradefed.util.CommandResult;
 import com.android.tradefed.util.CommandStatus;
 import com.android.tradefed.util.IRunUtil;
 
-import com.google.common.jimfs.Jimfs;
-import com.google.protobuf.ByteString;
-
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -45,22 +39,13 @@ import org.mockito.ArgumentMatcher;
 import org.mockito.Mockito;
 
 import java.io.IOException;
-import java.nio.file.FileSystem;
-import java.nio.file.Files;
-import java.nio.file.Path;
 import java.util.Arrays;
-import java.util.Iterator;
-import java.util.List;
-import java.util.Set;
 import java.util.concurrent.atomic.AtomicBoolean;
-import java.util.stream.Collectors;
 
 @RunWith(JUnit4.class)
 public final class DeviceUtilsTest {
     private ITestDevice mDevice = Mockito.mock(ITestDevice.class);
     private IRunUtil mRunUtil = Mockito.mock(IRunUtil.class);
-    private final FileSystem mFileSystem =
-            Jimfs.newFileSystem(com.google.common.jimfs.Configuration.unix());
     private static final String TEST_PACKAGE_NAME = "package.name";
 
     @Test
@@ -216,6 +201,148 @@ public final class DeviceUtilsTest {
         sut.launchPackage("package.name");
     }
 
+  @Test
+    public void warmLaunchPackage_pmDumpFailedAndPackageDoesNotExist_throws() throws Exception {
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm dump")))
+                .thenReturn(createFailedCommandResult());
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm list packages")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("no packages"));
+        DeviceUtils sut = createSubjectUnderTest();
+
+        assertThrows(DeviceUtilsException.class, () -> sut.warmLaunchPackage("package.name"));
+    }
+
+    @Test
+    public void warmLaunchPackage_pmDumpFailedAndPackageExists_throws() throws Exception {
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm dump")))
+                .thenReturn(createFailedCommandResult());
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm list packages")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("package:package.name"));
+        DeviceUtils sut = createSubjectUnderTest();
+
+        assertThrows(DeviceUtilsException.class, () -> sut.warmLaunchPackage("package.name"));
+    }
+
+    @Test
+    public void warmLaunchPackage_amStartCommandFailed_throws() throws Exception {
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm dump")))
+                .thenReturn(
+                        createSuccessfulCommandResultWithStdout(
+                                "        87f1610"
+                                    + " com.google.android.gms/.app.settings.GoogleSettingsActivity"
+                                    + " filter 7357509\n"
+                                    + "          Action: \"android.intent.action.MAIN\"\n"
+                                    + "          Category: \"android.intent.category.LAUNCHER\"\n"
+                                    + "          Category: \"android.intent.category.DEFAULT\"\n"
+                                    + "          Category:"
+                                    + " \"android.intent.category.NOTIFICATION_PREFERENCES\""));
+        when(mDevice.executeShellV2Command(Mockito.startsWith("am start")))
+                .thenReturn(createFailedCommandResult());
+        DeviceUtils sut = createSubjectUnderTest();
+
+        assertThrows(DeviceUtilsException.class, () -> sut.warmLaunchPackage("com.google.android.gms"));
+    }
+
+    @Test
+    public void warmLaunchPackage_amFailedToLaunchThePackage_throws() throws Exception {
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm dump")))
+                .thenReturn(
+                        createSuccessfulCommandResultWithStdout(
+                                "        87f1610"
+                                    + " com.google.android.gms/.app.settings.GoogleSettingsActivity"
+                                    + " filter 7357509\n"
+                                    + "          Action: \"android.intent.action.MAIN\"\n"
+                                    + "          Category: \"android.intent.category.LAUNCHER\"\n"
+                                    + "          Category: \"android.intent.category.DEFAULT\"\n"
+                                    + "          Category:"
+                                    + " \"android.intent.category.NOTIFICATION_PREFERENCES\""));
+        when(mDevice.executeShellV2Command(Mockito.startsWith("am start")))
+                .thenReturn(
+                        createSuccessfulCommandResultWithStdout(
+                                "Error: Activity not started, unable to resolve Intent"));
+        DeviceUtils sut = createSubjectUnderTest();
+
+        assertThrows(DeviceUtilsException.class, () -> sut.warmLaunchPackage("com.google.android.gms"));
+    }
+
+    @Test
+    public void warmLaunchPackage_amSucceed_doesNotThrow() throws Exception {
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm dump")))
+                .thenReturn(
+                        createSuccessfulCommandResultWithStdout(
+                                "        87f1610"
+                                    + " com.google.android.gms/.app.settings.GoogleSettingsActivity"
+                                    + " filter 7357509\n"
+                                    + "          Action: \"android.intent.action.MAIN\"\n"
+                                    + "          Category: \"android.intent.category.LAUNCHER\"\n"
+                                    + "          Category: \"android.intent.category.DEFAULT\"\n"
+                                    + "          Category:"
+                                    + " \"android.intent.category.NOTIFICATION_PREFERENCES\""));
+        when(mDevice.executeShellV2Command(Mockito.startsWith("am start")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+        DeviceUtils sut = createSubjectUnderTest();
+
+        sut.warmLaunchPackage("com.google.android.gms");
+    }
+
+    @Test
+    public void pressHome_amFailed_throw() throws Exception {
+        when(mDevice.executeShellV2Command(Mockito.startsWith("am start -a")))
+                .thenReturn(createFailedCommandResult());
+        DeviceUtils sut = createSubjectUnderTest();
+
+        assertThrows(DeviceNotAvailableException.class, () -> sut.pressHome());
+    }
+
+    @Test
+    public void pressHome_amSucceed_doesNotThrow() throws Exception {
+        when(mDevice.executeShellV2Command(Mockito.startsWith("am start -a")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+        DeviceUtils sut = createSubjectUnderTest();
+
+        sut.pressHome();
+    }
+
+    @Test
+    public void getLaunchActivityName_pmDumpFailedAndPackageDoesNotExists_throw() throws Exception {
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm dump")))
+                .thenReturn(createFailedCommandResult());
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm list packages")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("no packages"));
+        DeviceUtils sut = createSubjectUnderTest();
+
+        assertThrows(DeviceUtilsException.class, () -> sut.getLaunchActivityName("package.name"));
+    }
+
+    @Test
+    public void getLaunchActivityName_pmDumpFailedAndPackageExists_throw() throws Exception {
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm dump")))
+                .thenReturn(createFailedCommandResult());
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm list packages")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("package:package.name"));
+        DeviceUtils sut = createSubjectUnderTest();
+
+        assertThrows(DeviceUtilsException.class, () -> sut.getLaunchActivityName("package.name"));
+    }
+
+    @Test
+    public void getLaunchActivityName_pmDumpSucceed_doesNotThrow() throws Exception {
+        when(mDevice.executeShellV2Command(Mockito.startsWith("pm dump")))
+                .thenReturn(
+                        createSuccessfulCommandResultWithStdout(
+                                "        87f1610"
+                                    + " com.google.android.gms/.app.settings.GoogleSettingsActivity"
+                                    + " filter 7357509\n"
+                                    + "          Action: \"android.intent.action.MAIN\"\n"
+                                    + "          Category: \"android.intent.category.LAUNCHER\"\n"
+                                    + "          Category: \"android.intent.category.DEFAULT\"\n"
+                                    + "          Category:"
+                                    + " \"android.intent.category.NOTIFICATION_PREFERENCES\""));
+        DeviceUtils sut = createSubjectUnderTest();
+
+        sut.getLaunchActivityName("com.google.android.gms");
+    }
+
     @Test
     public void getLaunchActivity_oneActivityIsLauncherAndMainAndDefault_returnsIt()
             throws Exception {
@@ -524,459 +651,6 @@ public final class DeviceUtilsTest {
         assertThat(result).isEqualTo("123");
     }
 
-    @Test
-    public void isDropboxEntryFromPackageProcess_cmdlineMatched_returnsTrue() throws Exception {
-        String dropboxEntryData = "Cmd line: com.app.package";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isTrue();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_processMatched_returnsTrue() throws Exception {
-        String dropboxEntryData = "Process: com.app.package";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isTrue();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_processMatchedInLines_returnsTrue()
-            throws Exception {
-        String dropboxEntryData = "line\nProcess: com.app.package\nline";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isTrue();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_processNameFollowedByOtherChar_returnsTrue()
-            throws Exception {
-        String dropboxEntryData = "line\nProcess: com.app.package, (time)\nline";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isTrue();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_processNameFollowedByDot_returnsFalse()
-            throws Exception {
-        String dropboxEntryData = "line\nProcess: com.app.package.sub, (time)\nline";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isFalse();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_processNameFollowedByColon_returnsTrue()
-            throws Exception {
-        String dropboxEntryData = "line\nProcess: com.app.package:sub, (time)\nline";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isTrue();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_processNameFollowedByUnderscore_returnsFalse()
-            throws Exception {
-        String dropboxEntryData = "line\nProcess: com.app.package_sub, (time)\nline";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isFalse();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_doesNotContainPackageName_returnsFalse()
-            throws Exception {
-        String dropboxEntryData = "line\n";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isFalse();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_packageNameWithUnderscorePrefix_returnsFalse()
-            throws Exception {
-        String dropboxEntryData = "line\na_com.app.package\n";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isFalse();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_packageNameWithUnderscorePostfix_returnsFalse()
-            throws Exception {
-        String dropboxEntryData = "line\ncom.app.package_a\n";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isFalse();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_packageNameWithDotPrefix_returnsFalse()
-            throws Exception {
-        String dropboxEntryData = "line\na.com.app.package\n";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isFalse();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_packageNameWithDotPostfix_returnsFalse()
-            throws Exception {
-        String dropboxEntryData = "line\ncom.app.package.a\n";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isFalse();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_packageNameWithColonPostfix_returnsTrue()
-            throws Exception {
-        String dropboxEntryData = "line\ncom.app.package:a\n";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isTrue();
-    }
-
-    @Test
-    public void
-            isDropboxEntryFromPackageProcess_packageNameWithAcceptiblePrefixAndPostfix_returnsTrue()
-                    throws Exception {
-        String dropboxEntryData = "line\ncom.app.package)\n";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isTrue();
-    }
-
-    @Test
-    public void
-            isDropboxEntryFromPackageProcess_wrongProcessNameWithCorrectPackageName_returnsFalse()
-                    throws Exception {
-        String dropboxEntryData = "line\nProcess: com.app.package_other\ncom.app.package";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isFalse();
-    }
-
-    @Test
-    public void isDropboxEntryFromPackageProcess_MultipleProcessNamesWithOneMatching_returnsTrue()
-            throws Exception {
-        String dropboxEntryData =
-                "line\n"
-                        + "Process: com.app.package_other\n"
-                        + "Process: com.app.package\n"
-                        + "Process: com.other";
-        String packageName = "com.app.package";
-        DeviceUtils sut = createSubjectUnderTest();
-
-        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
-
-        assertThat(res).isTrue();
-    }
-
-    @Test
-    public void getDropboxEntries_containsEntriesOutsideTimeRange_onlyReturnsNewEntries()
-            throws Exception {
-        DeviceUtils sut = Mockito.spy(createSubjectUnderTest());
-        DeviceTimestamp startTime = new DeviceTimestamp(1);
-        DeviceTimestamp endTime = new DeviceTimestamp(3);
-        Mockito.doAnswer(
-                        inv ->
-                                List.of(
-                                        new DeviceUtils.DropboxEntry(
-                                                0,
-                                                DeviceUtils.DROPBOX_APP_CRASH_TAGS
-                                                        .toArray(
-                                                                new String
-                                                                        [DeviceUtils
-                                                                                .DROPBOX_APP_CRASH_TAGS
-                                                                                .size()])[0],
-                                                TEST_PACKAGE_NAME + " entry1"),
-                                        new DeviceUtils.DropboxEntry(
-                                                2,
-                                                DeviceUtils.DROPBOX_APP_CRASH_TAGS
-                                                        .toArray(
-                                                                new String
-                                                                        [DeviceUtils
-                                                                                .DROPBOX_APP_CRASH_TAGS
-                                                                                .size()])[0],
-                                                TEST_PACKAGE_NAME + " entry2"),
-                                        new DeviceUtils.DropboxEntry(
-                                                100,
-                                                DeviceUtils.DROPBOX_APP_CRASH_TAGS
-                                                        .toArray(
-                                                                new String
-                                                                        [DeviceUtils
-                                                                                .DROPBOX_APP_CRASH_TAGS
-                                                                                .size()])[0],
-                                                TEST_PACKAGE_NAME + " entry3")))
-                .when(sut)
-                .getDropboxEntries(DeviceUtils.DROPBOX_APP_CRASH_TAGS);
-
-        String result =
-                sut
-                        .getDropboxEntries(
-                                DeviceUtils.DROPBOX_APP_CRASH_TAGS,
-                                TEST_PACKAGE_NAME,
-                                startTime,
-                                endTime)
-                        .stream()
-                        .map(DropboxEntry::toString)
-                        .collect(Collectors.joining("\n"));
-
-        assertThat(result).doesNotContain("entry1");
-        assertThat(result).contains("entry2");
-        assertThat(result).doesNotContain("entry3");
-    }
-
-    @Test
-    public void getDropboxEntries_containsOtherProcessEntries_onlyReturnsPackageEntries()
-            throws Exception {
-        DeviceUtils sut = Mockito.spy(createSubjectUnderTest());
-        DeviceTimestamp startTime = new DeviceTimestamp(1);
-        Mockito.doAnswer(
-                        inv ->
-                                List.of(
-                                        new DeviceUtils.DropboxEntry(
-                                                2,
-                                                DeviceUtils.DROPBOX_APP_CRASH_TAGS
-                                                        .toArray(
-                                                                new String
-                                                                        [DeviceUtils
-                                                                                .DROPBOX_APP_CRASH_TAGS
-                                                                                .size()])[0],
-                                                "other.package" + " entry1"),
-                                        new DeviceUtils.DropboxEntry(
-                                                2,
-                                                DeviceUtils.DROPBOX_APP_CRASH_TAGS
-                                                        .toArray(
-                                                                new String
-                                                                        [DeviceUtils
-                                                                                .DROPBOX_APP_CRASH_TAGS
-                                                                                .size()])[0],
-                                                TEST_PACKAGE_NAME + " entry2")))
-                .when(sut)
-                .getDropboxEntries(DeviceUtils.DROPBOX_APP_CRASH_TAGS);
-
-        String result =
-                sut
-                        .getDropboxEntries(
-                                DeviceUtils.DROPBOX_APP_CRASH_TAGS,
-                                TEST_PACKAGE_NAME,
-                                startTime,
-                                null)
-                        .stream()
-                        .map(DropboxEntry::toString)
-                        .collect(Collectors.joining("\n"));
-
-        assertThat(result).doesNotContain("entry1");
-        assertThat(result).contains("entry2");
-    }
-
-    @Test
-    public void getDropboxEntries_noEntries_returnsEmptyList() throws Exception {
-        DeviceUtils sut = createSubjectUnderTest();
-        when(mRunUtil.runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq("sh"),
-                        Mockito.eq("-c"),
-                        Mockito.contains("dumpsys dropbox --help")))
-                .thenReturn(createSuccessfulCommandResultWithStdout("--proto"));
-        when(mRunUtil.runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq("sh"),
-                        Mockito.eq("-c"),
-                        Mockito.contains("dumpsys dropbox --proto")))
-                .thenReturn(createSuccessfulCommandResultWithStdout(""));
-
-        List<DropboxEntry> result = sut.getDropboxEntries(Set.of(""));
-
-        assertThat(result).isEmpty();
-    }
-
-    @Test
-    public void getDropboxEntries_entryExists_returnsEntry() throws Exception {
-        when(mRunUtil.runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq("sh"),
-                        Mockito.eq("-c"),
-                        Mockito.contains("dumpsys dropbox --help")))
-                .thenReturn(createSuccessfulCommandResultWithStdout("--proto"));
-        Path dumpFile = Files.createTempFile(mFileSystem.getPath("/"), "dropbox", ".proto");
-        long time = 123;
-        String data = "abc";
-        String tag = "tag";
-        DropBoxManagerServiceDumpProto proto =
-                DropBoxManagerServiceDumpProto.newBuilder()
-                        .addEntries(
-                                DropBoxManagerServiceDumpProto.Entry.newBuilder()
-                                        .setTimeMs(time)
-                                        .setData(ByteString.copyFromUtf8(data)))
-                        .build();
-        Files.write(dumpFile, proto.toByteArray());
-        DeviceUtils sut = createSubjectUnderTestWithTempFile(dumpFile);
-        when(mRunUtil.runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq("sh"),
-                        Mockito.eq("-c"),
-                        Mockito.contains("dumpsys dropbox --proto")))
-                .thenReturn(createSuccessfulCommandResultWithStdout(""));
-
-        List<DropboxEntry> result = sut.getDropboxEntries(Set.of(tag));
-
-        assertThat(result.get(0).getTime()).isEqualTo(time);
-        assertThat(result.get(0).getData()).isEqualTo(data);
-        assertThat(result.get(0).getTag()).isEqualTo(tag);
-    }
-
-    @Test
-    public void getDropboxEntriesFromStdout_entryExists_returnsEntry() throws Exception {
-        when(mRunUtil.runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq("sh"),
-                        Mockito.eq("-c"),
-                        Mockito.contains("dumpsys dropbox --file")))
-                .thenReturn(createSuccessfulCommandResultWithStdout(""));
-        when(mRunUtil.runTimedCmd(
-                        Mockito.anyLong(),
-                        Mockito.eq("sh"),
-                        Mockito.eq("-c"),
-                        Mockito.contains("dumpsys dropbox --print")))
-                .thenReturn(createSuccessfulCommandResultWithStdout(""));
-        Path fileDumpFile = Files.createTempFile(mFileSystem.getPath("/"), "file", ".dump");
-        Path printDumpFile = Files.createTempFile(mFileSystem.getPath("/"), "print", ".dump");
-        String fileResult =
-                "Drop box contents: 351 entries\n"
-                        + "Max entries: 1000\n"
-                        + "Low priority rate limit period: 2000 ms\n"
-                        + "Low priority tags: {data_app_wtf, keymaster, system_server_wtf,"
-                        + " system_app_strictmode, system_app_wtf, system_server_strictmode,"
-                        + " data_app_strictmode, netstats}\n"
-                        + "\n"
-                        + "2022-09-05 04:17:21 system_server_wtf (text, 1730 bytes)\n"
-                        + "    /data/system/dropbox/system_server_wtf@1662351441269.txt\n"
-                        + "2022-09-05 04:31:06 event_data (text, 39 bytes)\n"
-                        + "    /data/system/dropbox/event_data@1662352266197.txt\n";
-        String printResult =
-                "Drop box contents: 351 entries\n"
-                    + "Max entries: 1000\n"
-                    + "Low priority rate limit period: 2000 ms\n"
-                    + "Low priority tags: {data_app_wtf, keymaster, system_server_wtf,"
-                    + " system_app_strictmode, system_app_wtf, system_server_strictmode,"
-                    + " data_app_strictmode, netstats}\n"
-                    + "\n"
-                    + "========================================\n"
-                    + "2022-09-05 04:17:21 system_server_wtf (text, 1730 bytes)\n"
-                    + "Process: system_server\n"
-                    + "Subject: ActivityManager\n"
-                    + "Build:"
-                    + " generic/cf_x86_64_phone/vsoc_x86_64:UpsideDownCake/MASTER/8990215:userdebug/dev-keys\n"
-                    + "Dropped-Count: 0\n"
-                    + "\n"
-                    + "android.util.Log$TerribleFailure: Sending non-protected broadcast"
-                    + " com.android.bluetooth.btservice.BLUETOOTH_COUNTER_METRICS_ACTION from"
-                    + " system uid 1002 pkg com.android.bluetooth\n"
-                    + "    at android.util.Log.wtf(Log.java:332)\n"
-                    + "    at android.util.Log.wtf(Log.java:326)\n"
-                    + "    at"
-                    + " com.android.server.am.ActivityManagerService.checkBroadcastFromSystem(ActivityManagerService.java:13609)\n"
-                    + "    at"
-                    + " com.android.server.am.ActivityManagerService.broadcastIntentLocked(ActivityManagerService.java:14330)\n"
-                    + "    at"
-                    + " com.android.server.am.ActivityManagerService.broadcastIntentInPackage(ActivityManagerService.java:14530)\n"
-                    + "    at"
-                    + " com.android.server.am.ActivityManagerService$LocalService.broadcastIntentInPackage(ActivityManagerService.java:17065)\n"
-                    + "    at"
-                    + " com.android.server.am.PendingIntentRecord.sendInner(PendingIntentRecord.java:526)\n"
-                    + "    at"
-                    + " com.android.server.am.PendingIntentRecord.sendWithResult(PendingIntentRecord.java:311)\n"
-                    + "    at"
-                    + " com.android.server.am.ActivityManagerService.sendIntentSender(ActivityManagerService.java:5379)\n"
-                    + "    at"
-                    + " android.app.PendingIntent.sendAndReturnResult(PendingIntent.java:1012)\n"
-                    + "    at android.app.PendingIntent.send(PendingIntent.java:983)\n"
-                    + "    at"
-                    + " com.android.server.alarm.AlarmManagerService$DeliveryTracker.deliverLocked(AlarmManagerService.java:5500)\n"
-                    + "    at"
-                    + " com.android.server.alarm.AlarmManagerService.deliverAlarmsLocked(AlarmManagerService.java:4400)\n"
-                    + "    at"
-                    + " com.android.server.alarm.AlarmManagerService$AlarmThread.run(AlarmManagerService.java:4711)\n"
-                    + "Caused by: java.lang.Throwable\n"
-                    + "    at"
-                    + " com.android.server.am.ActivityManagerService.checkBroadcastFromSystem(ActivityManagerService.java:13610)\n"
-                    + "    ... 11 more\n"
-                    + "\n"
-                    + "========================================\n"
-                    + "2022-09-05 04:31:06 event_data (text, 39 bytes)\n"
-                    + "start=1662350731248\n"
-                    + "end=1662352266140\n"
-                    + "\n";
-        Files.write(fileDumpFile, fileResult.getBytes());
-        Files.write(printDumpFile, printResult.getBytes());
-        DeviceUtils sut = createSubjectUnderTestWithTempFile(fileDumpFile, printDumpFile);
-
-        List<DropboxEntry> result = sut.getDropboxEntriesFromStdout(Set.of("system_server_wtf"));
-
-        assertThat(result.get(0).getTime()).isEqualTo(1662351441269L);
-        assertThat(result.get(0).getData()).contains("Sending non-protected broadcast");
-        assertThat(result.get(0).getTag()).isEqualTo("system_server_wtf");
-        assertThat(result.size()).isEqualTo(1);
-    }
-
-    private DeviceUtils createSubjectUnderTestWithTempFile(Path... tempFiles) {
-        when(mDevice.getSerialNumber()).thenReturn("SERIAL");
-        FakeClock fakeClock = new FakeClock();
-        Iterator<Path> iter = Arrays.asList(tempFiles).iterator();
-        return new DeviceUtils(
-                mDevice, fakeClock.getSleeper(), fakeClock, () -> mRunUtil, () -> iter.next());
-    }
-
     private DeviceUtils createSubjectUnderTest() throws DeviceNotAvailableException {
         when(mDevice.getSerialNumber()).thenReturn("SERIAL");
         when(mDevice.executeShellV2Command(Mockito.startsWith("echo ${EPOCHREALTIME")))
@@ -984,12 +658,7 @@ public final class DeviceUtilsTest {
         when(mDevice.executeShellV2Command(Mockito.eq("getprop ro.build.version.sdk")))
                 .thenReturn(createSuccessfulCommandResultWithStdout("34"));
         FakeClock fakeClock = new FakeClock();
-        return new DeviceUtils(
-                mDevice,
-                fakeClock.getSleeper(),
-                fakeClock,
-                () -> mRunUtil,
-                () -> Files.createTempFile(mFileSystem.getPath("/"), "test", ".tmp"));
+        return new DeviceUtils(mDevice, fakeClock.getSleeper(), fakeClock, () -> mRunUtil);
     }
 
     private static class FakeClock implements DeviceUtils.Clock {
diff --git a/harness/src/test/java/com/android/csuite/core/DropboxEntryCrashDetectorTest.java b/harness/src/test/java/com/android/csuite/core/DropboxEntryCrashDetectorTest.java
new file mode 100644
index 0000000..879e75e
--- /dev/null
+++ b/harness/src/test/java/com/android/csuite/core/DropboxEntryCrashDetectorTest.java
@@ -0,0 +1,690 @@
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
+package com.android.csuite.core;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.Mockito.when;
+
+import android.service.dropbox.DropBoxManagerServiceDumpProto;
+
+import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
+import com.android.csuite.core.DropboxEntryCrashDetector.DropboxEntry;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.util.CommandResult;
+import com.android.tradefed.util.CommandStatus;
+import com.android.tradefed.util.IRunUtil;
+
+import com.google.common.jimfs.Jimfs;
+import com.google.protobuf.ByteString;
+
+import org.junit.Test;
+import org.mockito.Mockito;
+
+import java.io.IOException;
+import java.nio.file.FileSystem;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.util.List;
+import java.util.Set;
+import java.util.stream.Collectors;
+
+public class DropboxEntryCrashDetectorTest {
+    private ITestDevice mDevice = Mockito.mock(ITestDevice.class);
+    private IRunUtil mRunUtil = Mockito.mock(IRunUtil.class);
+    private static final String TEST_PACKAGE_NAME = "package.name";
+
+    private final FileSystem mFileSystem =
+            Jimfs.newFileSystem(com.google.common.jimfs.Configuration.unix());
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_notStartOfLine_returnsFalse() throws Exception {
+        String dropboxEntryData = "\nPackage: gms.package\ncallingPackage: com.app.package \n";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isFalse();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_cmdlineMatched_returnsTrue() throws Exception {
+        String dropboxEntryData = "Cmd line: com.app.package";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isTrue();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_processMatched_returnsTrue() throws Exception {
+        String dropboxEntryData = "Process: com.app.package";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isTrue();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_processMatchedInLines_returnsTrue()
+            throws Exception {
+        String dropboxEntryData = "line\nProcess: com.app.package\nline";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isTrue();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_processNameFollowedByOtherChar_returnsTrue()
+            throws Exception {
+        String dropboxEntryData = "line\nProcess: com.app.package, (time)\nline";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isTrue();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_processNameFollowedByDot_returnsFalse()
+            throws Exception {
+        String dropboxEntryData = "line\nProcess: com.app.package.sub, (time)\nline";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isFalse();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_processNameFollowedByColon_returnsTrue()
+            throws Exception {
+        String dropboxEntryData = "line\nProcess: com.app.package:sub, (time)\nline";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isTrue();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_processNameFollowedByUnderscore_returnsFalse()
+            throws Exception {
+        String dropboxEntryData = "line\nProcess: com.app.package_sub, (time)\nline";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isFalse();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_doesNotContainPackageName_returnsFalse()
+            throws Exception {
+        String dropboxEntryData = "line\n";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isFalse();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_packageNameWithUnderscorePrefix_returnsFalse()
+            throws Exception {
+        String dropboxEntryData = "line\na_com.app.package\n";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isFalse();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_packageNameWithUnderscorePostfix_returnsFalse()
+            throws Exception {
+        String dropboxEntryData = "line\ncom.app.package_a\n";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isFalse();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_packageNameWithDotPrefix_returnsFalse()
+            throws Exception {
+        String dropboxEntryData = "line\na.com.app.package\n";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isFalse();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_packageNameWithDotPostfix_returnsFalse()
+            throws Exception {
+        String dropboxEntryData = "line\ncom.app.package.a\n";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isFalse();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_packageNameWithColonPostfix_returnsTrue()
+            throws Exception {
+        String dropboxEntryData = "line\ncom.app.package:a\n";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isTrue();
+    }
+
+    @Test
+    public void
+            isDropboxEntryFromPackageProcess_packageNameWithAcceptiblePrefixAndPostfix_returnsTrue()
+                    throws Exception {
+        String dropboxEntryData = "line\ncom.app.package)\n";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isTrue();
+    }
+
+    @Test
+    public void
+            isDropboxEntryFromPackageProcess_wrongProcessNameWithCorrectPackageName_returnsFalse()
+                    throws Exception {
+        String dropboxEntryData = "line\nProcess: com.app.package_other\ncom.app.package";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isFalse();
+    }
+
+    @Test
+    public void isDropboxEntryFromPackageProcess_MultipleProcessNamesWithOneMatching_returnsTrue()
+            throws Exception {
+        String dropboxEntryData =
+                "line\n"
+                        + "Process: com.app.package_other\n"
+                        + "Process: com.app.package\n"
+                        + "Process: com.other";
+        String packageName = "com.app.package";
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+
+        boolean res = sut.isDropboxEntryFromPackageProcess(dropboxEntryData, packageName);
+
+        assertThat(res).isTrue();
+    }
+
+    @Test
+    public void getDropboxEntriesFromAdbPull_noEntriesWithinTimeRange_returnsEmpty()
+            throws Exception {
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("ls /data/system/dropbox")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("tag@1.txt"));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("shell tar")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("pull /data/local/tmp")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("tar"),
+                        Mockito.eq("-xzf"),
+                        Mockito.any(),
+                        Mockito.any(),
+                        Mockito.any()))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+
+        List<DropboxEntry> entries =
+                sut.getDropboxEntriesFromAdbPull(
+                        Set.of("tag"), new DeviceTimestamp(2), new DeviceTimestamp(3));
+
+        assertThat(entries).isEmpty();
+    }
+
+    @Test
+    public void getDropboxEntriesFromAdbPull_noEntriesUnderTag_returnsEmpty() throws Exception {
+        DropboxEntryCrashDetector sut = createSubjectUnderTest();
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("ls /data/system/dropbox")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("tag2@2.txt"));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("shell tar")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("pull /data/local/tmp")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("tar"),
+                        Mockito.eq("-xzf"),
+                        Mockito.any(),
+                        Mockito.any(),
+                        Mockito.any()))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+
+        List<DropboxEntry> entries =
+                sut.getDropboxEntriesFromAdbPull(
+                        Set.of("tag1"), new DeviceTimestamp(1), new DeviceTimestamp(3));
+
+        assertThat(entries).isEmpty();
+    }
+
+    @Test
+    public void getDropboxEntriesFromAdbPull_entryMatched_returnsEntry() throws Exception {
+        String tag = "tag";
+        long time = 2;
+        String data = "content";
+        Path tmpDir = mFileSystem.getPath("tmp");
+        Files.createDirectories(tmpDir);
+        Path dumpFile = tmpDir.resolve("data/system/dropbox/" + tag + "@" + time + ".txt");
+        Files.createDirectories(dumpFile.getParent());
+        Files.createFile(dumpFile);
+        Files.writeString(dumpFile, data);
+        DropboxEntryCrashDetector sut = createSubjectUnderTestWithTempDirectory(tmpDir);
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("ls /data/system/dropbox")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(tag + "@" + time + ".txt"));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("shell tar")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("pull /data/local/tmp")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("tar"),
+                        Mockito.eq("-xzf"),
+                        Mockito.any(),
+                        Mockito.any(),
+                        Mockito.any()))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+
+        List<DropboxEntry> entries =
+                sut.getDropboxEntriesFromAdbPull(
+                        Set.of(tag), new DeviceTimestamp(time - 1), new DeviceTimestamp(time + 1));
+
+        assertThat(entries).hasSize(1);
+        assertThat(entries.get(0).getTag()).isEqualTo(tag);
+        assertThat(entries.get(0).getTime()).isEqualTo(time);
+        assertThat(entries.get(0).getData()).isEqualTo(data);
+    }
+
+    @Test
+    public void
+            getDropboxEntriesFromProtoDump_containsEntriesOutsideTimeRange_onlyReturnsNewEntries()
+                    throws Exception {
+        DropboxEntryCrashDetector sut = Mockito.spy(createSubjectUnderTest());
+        DeviceTimestamp startTime = new DeviceTimestamp(1);
+        DeviceTimestamp endTime = new DeviceTimestamp(3);
+        Mockito.doThrow(new IOException())
+                .when(sut)
+                .getDropboxEntriesFromAdbPull(Mockito.any(), Mockito.any(), Mockito.any());
+        Mockito.doAnswer(
+                        inv ->
+                                List.of(
+                                        new DropboxEntryCrashDetector.DropboxEntry(
+                                                0,
+                                                DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS
+                                                        .toArray(
+                                                                new String
+                                                                        [DropboxEntryCrashDetector
+                                                                                .DROPBOX_APP_CRASH_TAGS
+                                                                                .size()])[0],
+                                                TEST_PACKAGE_NAME + " entry1"),
+                                        new DropboxEntryCrashDetector.DropboxEntry(
+                                                2,
+                                                DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS
+                                                        .toArray(
+                                                                new String
+                                                                        [DropboxEntryCrashDetector
+                                                                                .DROPBOX_APP_CRASH_TAGS
+                                                                                .size()])[0],
+                                                TEST_PACKAGE_NAME + " entry2"),
+                                        new DropboxEntryCrashDetector.DropboxEntry(
+                                                100,
+                                                DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS
+                                                        .toArray(
+                                                                new String
+                                                                        [DropboxEntryCrashDetector
+                                                                                .DROPBOX_APP_CRASH_TAGS
+                                                                                .size()])[0],
+                                                TEST_PACKAGE_NAME + " entry3")))
+                .when(sut)
+                .getDropboxEntriesFromProtoDump(DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS);
+
+        String result =
+                sut
+                        .getDropboxEntries(
+                                DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS,
+                                TEST_PACKAGE_NAME,
+                                startTime,
+                                endTime)
+                        .stream()
+                        .map(DropboxEntry::toString)
+                        .collect(Collectors.joining("\n"));
+
+        assertThat(result).doesNotContain("entry1");
+        assertThat(result).contains("entry2");
+        assertThat(result).doesNotContain("entry3");
+    }
+
+    @Test
+    public void
+            getDropboxEntriesFromProtoDump_containsOtherProcessEntries_onlyReturnsPackageEntries()
+                    throws Exception {
+        DropboxEntryCrashDetector sut = Mockito.spy(createSubjectUnderTest());
+        DeviceTimestamp startTime = new DeviceTimestamp(1);
+        Mockito.doThrow(new IOException())
+                .when(sut)
+                .getDropboxEntriesFromAdbPull(Mockito.any(), Mockito.any(), Mockito.any());
+        Mockito.doAnswer(
+                        inv ->
+                                List.of(
+                                        new DropboxEntryCrashDetector.DropboxEntry(
+                                                2,
+                                                DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS
+                                                        .toArray(
+                                                                new String
+                                                                        [DropboxEntryCrashDetector
+                                                                                .DROPBOX_APP_CRASH_TAGS
+                                                                                .size()])[0],
+                                                "other.package" + " entry1"),
+                                        new DropboxEntryCrashDetector.DropboxEntry(
+                                                2,
+                                                DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS
+                                                        .toArray(
+                                                                new String
+                                                                        [DropboxEntryCrashDetector
+                                                                                .DROPBOX_APP_CRASH_TAGS
+                                                                                .size()])[0],
+                                                TEST_PACKAGE_NAME + " entry2")))
+                .when(sut)
+                .getDropboxEntriesFromProtoDump(DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS);
+
+        String result =
+                sut
+                        .getDropboxEntries(
+                                DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS,
+                                TEST_PACKAGE_NAME,
+                                startTime,
+                                null)
+                        .stream()
+                        .map(DropboxEntry::toString)
+                        .collect(Collectors.joining("\n"));
+
+        assertThat(result).doesNotContain("entry1");
+        assertThat(result).contains("entry2");
+    }
+
+    @Test
+    public void getDropboxEntriesFromProtoDump_noEntries_returnsEmptyList() throws Exception {
+        String tag = "tag";
+        Path tmpDir = mFileSystem.getPath("tmp");
+        Files.createDirectories(tmpDir);
+        Path dumpFile = DropboxEntryCrashDetector.getProtoDumpFilePath(tmpDir, tag);
+        Files.createFile(dumpFile);
+        DropboxEntryCrashDetector sut = createSubjectUnderTestWithTempDirectory(tmpDir);
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("dumpsys dropbox --help")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("--proto"));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("dumpsys dropbox --proto")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+
+        List<DropboxEntry> result = sut.getDropboxEntriesFromProtoDump(Set.of(tag));
+
+        assertThat(result).isEmpty();
+    }
+
+    @Test
+    public void getDropboxEntriesFromProtoDump_entryExists_returnsEntry() throws Exception {
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("dumpsys dropbox --help")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("--proto"));
+        long time = 123;
+        String data = "abc";
+        String tag = "tag";
+        Path tmpDir = mFileSystem.getPath("tmp");
+        Files.createDirectories(tmpDir);
+        Path dumpFile = DropboxEntryCrashDetector.getProtoDumpFilePath(tmpDir, tag);
+        Files.createFile(dumpFile);
+        DropBoxManagerServiceDumpProto proto =
+                DropBoxManagerServiceDumpProto.newBuilder()
+                        .addEntries(
+                                DropBoxManagerServiceDumpProto.Entry.newBuilder()
+                                        .setTimeMs(time)
+                                        .setData(ByteString.copyFromUtf8(data)))
+                        .build();
+        Files.write(dumpFile, proto.toByteArray());
+        DropboxEntryCrashDetector sut = createSubjectUnderTestWithTempDirectory(tmpDir);
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("dumpsys dropbox --proto")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+
+        List<DropboxEntry> result = sut.getDropboxEntriesFromProtoDump(Set.of(tag));
+
+        assertThat(result.get(0).getTime()).isEqualTo(time);
+        assertThat(result.get(0).getData()).isEqualTo(data);
+        assertThat(result.get(0).getTag()).isEqualTo(tag);
+    }
+
+    @Test
+    public void getDropboxEntriesFromStdout_entryExists_returnsEntry() throws Exception {
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("dumpsys dropbox --file")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("dumpsys dropbox --print")))
+                .thenReturn(createSuccessfulCommandResultWithStdout(""));
+
+        Path tmpDir = mFileSystem.getPath("tmp");
+        Files.createDirectories(tmpDir);
+        Path fileDumpFile = tmpDir.resolve(DropboxEntryCrashDetector.FILE_OUTPUT_NAME);
+        Files.createFile(fileDumpFile);
+        Path printDumpFile = tmpDir.resolve(DropboxEntryCrashDetector.PRINT_OUTPUT_NAME);
+        Files.createFile(printDumpFile);
+        String fileResult =
+                "Drop box contents: 351 entries\n"
+                        + "Max entries: 1000\n"
+                        + "Low priority rate limit period: 2000 ms\n"
+                        + "Low priority tags: {data_app_wtf, keymaster, system_server_wtf,"
+                        + " system_app_strictmode, system_app_wtf, system_server_strictmode,"
+                        + " data_app_strictmode, netstats}\n"
+                        + "\n"
+                        + "2022-09-05 04:17:21 system_server_wtf (text, 1730 bytes)\n"
+                        + "    /data/system/dropbox/system_server_wtf@1662351441269.txt\n"
+                        + "2022-09-05 04:31:06 event_data (text, 39 bytes)\n"
+                        + "    /data/system/dropbox/event_data@1662352266197.txt\n";
+        String printResult =
+                "Drop box contents: 351 entries\n"
+                    + "Max entries: 1000\n"
+                    + "Low priority rate limit period: 2000 ms\n"
+                    + "Low priority tags: {data_app_wtf, keymaster, system_server_wtf,"
+                    + " system_app_strictmode, system_app_wtf, system_server_strictmode,"
+                    + " data_app_strictmode, netstats}\n"
+                    + "\n"
+                    + "========================================\n"
+                    + "2022-09-05 04:17:21 system_server_wtf (text, 1730 bytes)\n"
+                    + "Process: system_server\n"
+                    + "Subject: ActivityManager\n"
+                    + "Build:"
+                    + " generic/cf_x86_64_phone/vsoc_x86_64:UpsideDownCake/MASTER/8990215:userdebug/dev-keys\n"
+                    + "Dropped-Count: 0\n"
+                    + "\n"
+                    + "android.util.Log$TerribleFailure: Sending non-protected broadcast"
+                    + " com.android.bluetooth.btservice.BLUETOOTH_COUNTER_METRICS_ACTION from"
+                    + " system uid 1002 pkg com.android.bluetooth\n"
+                    + "    at android.util.Log.wtf(Log.java:332)\n"
+                    + "    at android.util.Log.wtf(Log.java:326)\n"
+                    + "    at"
+                    + " com.android.server.am.ActivityManagerService.checkBroadcastFromSystem(ActivityManagerService.java:13609)\n"
+                    + "    at"
+                    + " com.android.server.am.ActivityManagerService.broadcastIntentLocked(ActivityManagerService.java:14330)\n"
+                    + "    at"
+                    + " com.android.server.am.ActivityManagerService.broadcastIntentInPackage(ActivityManagerService.java:14530)\n"
+                    + "    at"
+                    + " com.android.server.am.ActivityManagerService$LocalService.broadcastIntentInPackage(ActivityManagerService.java:17065)\n"
+                    + "    at"
+                    + " com.android.server.am.PendingIntentRecord.sendInner(PendingIntentRecord.java:526)\n"
+                    + "    at"
+                    + " com.android.server.am.PendingIntentRecord.sendWithResult(PendingIntentRecord.java:311)\n"
+                    + "    at"
+                    + " com.android.server.am.ActivityManagerService.sendIntentSender(ActivityManagerService.java:5379)\n"
+                    + "    at"
+                    + " android.app.PendingIntent.sendAndReturnResult(PendingIntent.java:1012)\n"
+                    + "    at android.app.PendingIntent.send(PendingIntent.java:983)\n"
+                    + "    at"
+                    + " com.android.server.alarm.AlarmManagerService$DeliveryTracker.deliverLocked(AlarmManagerService.java:5500)\n"
+                    + "    at"
+                    + " com.android.server.alarm.AlarmManagerService.deliverAlarmsLocked(AlarmManagerService.java:4400)\n"
+                    + "    at"
+                    + " com.android.server.alarm.AlarmManagerService$AlarmThread.run(AlarmManagerService.java:4711)\n"
+                    + "Caused by: java.lang.Throwable\n"
+                    + "    at"
+                    + " com.android.server.am.ActivityManagerService.checkBroadcastFromSystem(ActivityManagerService.java:13610)\n"
+                    + "    ... 11 more\n"
+                    + "\n"
+                    + "========================================\n"
+                    + "2022-09-05 04:31:06 event_data (text, 39 bytes)\n"
+                    + "start=1662350731248\n"
+                    + "end=1662352266140\n"
+                    + "\n";
+        Files.write(fileDumpFile, fileResult.getBytes());
+        Files.write(printDumpFile, printResult.getBytes());
+        DropboxEntryCrashDetector sut =
+                Mockito.spy(createSubjectUnderTestWithTempDirectory(tmpDir));
+        Mockito.doThrow(new IOException())
+                .when(sut)
+                .getDropboxEntriesFromAdbPull(Mockito.any(), Mockito.any(), Mockito.any());
+        Mockito.doThrow(new IOException()).when(sut).getDropboxEntriesFromProtoDump(Mockito.any());
+
+        List<DropboxEntry> result =
+                sut.getDropboxEntries(
+                        Set.of("system_server_wtf"),
+                        "system_server",
+                        new DeviceTimestamp(Long.MIN_VALUE),
+                        new DeviceTimestamp(Long.MAX_VALUE));
+
+        assertThat(result.get(0).getTime()).isEqualTo(1662351441269L);
+        assertThat(result.get(0).getData()).contains("Sending non-protected broadcast");
+        assertThat(result.get(0).getTag()).isEqualTo("system_server_wtf");
+        assertThat(result.size()).isEqualTo(1);
+    }
+
+    private DropboxEntryCrashDetector createSubjectUnderTestWithTempDirectory(Path dir) {
+        when(mDevice.getSerialNumber()).thenReturn("SERIAL");
+        return new DropboxEntryCrashDetector(mDevice, () -> mRunUtil, () -> dir);
+    }
+
+    private DropboxEntryCrashDetector createSubjectUnderTest() throws DeviceNotAvailableException {
+        when(mDevice.getSerialNumber()).thenReturn("SERIAL");
+        when(mDevice.executeShellV2Command(Mockito.startsWith("echo ${EPOCHREALTIME")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("1"));
+        when(mDevice.executeShellV2Command(Mockito.eq("getprop ro.build.version.sdk")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("34"));
+        return new DropboxEntryCrashDetector(
+                mDevice,
+                () -> mRunUtil,
+                () -> Files.createTempFile(mFileSystem.getPath("/"), "test", ".tmp"));
+    }
+
+    private static CommandResult createSuccessfulCommandResultWithStdout(String stdout) {
+        CommandResult commandResult = new CommandResult(CommandStatus.SUCCESS);
+        commandResult.setExitCode(0);
+        commandResult.setStdout(stdout);
+        commandResult.setStderr("");
+        return commandResult;
+    }
+}
diff --git a/harness/src/test/java/com/android/csuite/core/TestUtilsTest.java b/harness/src/test/java/com/android/csuite/core/TestUtilsTest.java
index 8d58c48..a51c913 100644
--- a/harness/src/test/java/com/android/csuite/core/TestUtilsTest.java
+++ b/harness/src/test/java/com/android/csuite/core/TestUtilsTest.java
@@ -23,7 +23,7 @@ import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.when;
 
 import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
-import com.android.csuite.core.DeviceUtils.DropboxEntry;
+import com.android.csuite.core.DropboxEntryCrashDetector.DropboxEntry;
 import com.android.csuite.core.TestUtils.TestArtifactReceiver;
 import com.android.tradefed.build.BuildInfo;
 import com.android.tradefed.device.ITestDevice;
@@ -159,6 +159,29 @@ public final class TestUtilsTest {
         assertThat(fileNames).containsExactly("single.apk", "main.123.package.obb");
     }
 
+    @Test
+    public void listApks_withSplitApkAndObbFiles_returnsApksWithObbInCorrectOrder()
+            throws Exception {
+        Path root = mFileSystem.getPath("apk");
+        Files.createDirectories(root);
+        Files.createFile(root.resolve("config.apk"));
+        Files.createFile(root.resolve("base.apk"));
+        Files.createFile(root.resolve("main.123.package.obb"));
+        Files.createFile(root.resolve("patch.123.package.obb"));
+
+        List<Path> res = TestUtils.listApks(root);
+
+        List<String> fileNames =
+                res.stream()
+                        .map(Path::getFileName)
+                        .map(Path::toString)
+                        .collect(Collectors.toList());
+        assertThat(fileNames)
+                .containsExactly(
+                        "base.apk", "config.apk", "main.123.package.obb", "patch.123.package.obb")
+                .inOrder();
+    }
+
     @Test
     public void listApks_withApkDirectoryContainingOtherFileTypes_returnsApksOnly()
             throws Exception {
@@ -352,20 +375,24 @@ public final class TestUtilsTest {
     }
 
     @Test
-    public void getDropboxPackageCrashLog_noEntries_returnsNull() throws Exception {
+    public void getDropboxPackageCrashLog_noEntries_returnsEmpty() throws Exception {
         TestUtils sut = createSubjectUnderTest();
-        when(mMockDeviceUtils.getDropboxEntries(Mockito.any())).thenReturn(List.of());
+        when(mMockDeviceUtils.getCrashEntriesFromDropbox(
+                        Mockito.any(), Mockito.any(), Mockito.any()))
+                .thenReturn(List.of());
         DeviceTimestamp startTime = new DeviceTimestamp(0);
 
         String result = sut.getDropboxPackageCrashLog(TEST_PACKAGE_NAME, startTime, false);
 
-        assertThat(result).isNull();
+        assertThat(result).isEmpty();
     }
 
     @Test
     public void getDropboxPackageCrashLog_noEntries_doesNotSaveOutput() throws Exception {
         TestUtils sut = createSubjectUnderTest();
-        when(mMockDeviceUtils.getDropboxEntries(Mockito.any())).thenReturn(List.of());
+        when(mMockDeviceUtils.getCrashEntriesFromDropbox(
+                        Mockito.any(), Mockito.any(), Mockito.any()))
+                .thenReturn(List.of());
         DeviceTimestamp startTime = new DeviceTimestamp(0);
         boolean saveToFile = true;
 
@@ -379,16 +406,17 @@ public final class TestUtilsTest {
     @Test
     public void getDropboxPackageCrashLog_appCrashed_saveOutput() throws Exception {
         TestUtils sut = createSubjectUnderTest();
-        when(mMockDeviceUtils.getDropboxEntries(
-                        Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
+        when(mMockDeviceUtils.getCrashEntriesFromDropbox(
+                        Mockito.any(), Mockito.any(), Mockito.any()))
                 .thenReturn(
                         List.of(
-                                new DeviceUtils.DropboxEntry(
+                                new DropboxEntry(
                                         2,
-                                        DeviceUtils.DROPBOX_APP_CRASH_TAGS
+                                        DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS
                                                 .toArray(
                                                         new String
-                                                                [DeviceUtils.DROPBOX_APP_CRASH_TAGS
+                                                                [DropboxEntryCrashDetector
+                                                                        .DROPBOX_APP_CRASH_TAGS
                                                                         .size()])[0],
                                         "Package: " + TEST_PACKAGE_NAME)));
         DeviceTimestamp startTime = new DeviceTimestamp(0);
@@ -412,20 +440,22 @@ public final class TestUtilsTest {
         String expectedTime2 = "01:02";
         List<DropboxEntry> crashEntries =
                 List.of(
-                        new DeviceUtils.DropboxEntry(
+                        new DropboxEntry(
                                 crashTime1,
-                                DeviceUtils.DROPBOX_APP_CRASH_TAGS
+                                DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS
                                         .toArray(
                                                 new String
-                                                        [DeviceUtils.DROPBOX_APP_CRASH_TAGS
+                                                        [DropboxEntryCrashDetector
+                                                                .DROPBOX_APP_CRASH_TAGS
                                                                 .size()])[0],
                                 TEST_PACKAGE_NAME + " entry1"),
-                        new DeviceUtils.DropboxEntry(
+                        new DropboxEntry(
                                 crashTime2,
-                                DeviceUtils.DROPBOX_APP_CRASH_TAGS
+                                DropboxEntryCrashDetector.DROPBOX_APP_CRASH_TAGS
                                         .toArray(
                                                 new String
-                                                        [DeviceUtils.DROPBOX_APP_CRASH_TAGS
+                                                        [DropboxEntryCrashDetector
+                                                                .DROPBOX_APP_CRASH_TAGS
                                                                 .size()])[0],
                                 TEST_PACKAGE_NAME + " entry2"));
 
diff --git a/test_scripts/src/main/java/com/android/art/tests/AppCompileLaunchTest.java b/test_scripts/src/main/java/com/android/art/tests/AppCompileLaunchTest.java
index 5524fc9..da858b7 100644
--- a/test_scripts/src/main/java/com/android/art/tests/AppCompileLaunchTest.java
+++ b/test_scripts/src/main/java/com/android/art/tests/AppCompileLaunchTest.java
@@ -23,8 +23,8 @@ import com.android.csuite.core.BlankScreenDetectorWithSameColorRectangle.BlankSc
 import com.android.csuite.core.DeviceUtils;
 import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
 import com.android.csuite.core.DeviceUtils.DeviceUtilsException;
-import com.android.csuite.core.DeviceUtils.DropboxEntry;
 import com.android.csuite.core.DeviceUtils.RunnableThrowingDeviceNotAvailable;
+import com.android.csuite.core.DropboxEntryCrashDetector.DropboxEntry;
 import com.android.csuite.core.TestUtils;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.device.DeviceNotAvailableException;
@@ -158,8 +158,8 @@ public class AppCompileLaunchTest extends BaseHostJUnit4Test {
                 getDevice().executeShellV2Command("cmd package compile -m speed " + mPackageName);
         Assert.assertEquals(
                 "Failed to execute compile command: " + cmdResult,
-                cmdResult.getStatus(),
-                CommandStatus.SUCCESS);
+                CommandStatus.SUCCESS,
+                cmdResult.getStatus());
 
         try {
             doTestAppCrash(false);
@@ -194,6 +194,7 @@ public class AppCompileLaunchTest extends BaseHostJUnit4Test {
             mIsLastTestPass = true;
             // Do not throw to fail the test here as it's not compile related
             Assume.assumeNoException(e);
+            return;
         }
 
         throw testFailureThrowable;
@@ -250,11 +251,7 @@ public class AppCompileLaunchTest extends BaseHostJUnit4Test {
 
         try {
             List<DropboxEntry> crashEntries =
-                    deviceUtils.getDropboxEntries(
-                            DeviceUtils.DROPBOX_APP_CRASH_TAGS,
-                            mPackageName,
-                            startTime.get(),
-                            endTime);
+                    deviceUtils.getCrashEntriesFromDropbox(mPackageName, startTime.get(), endTime);
             String crashLog =
                     testUtils.compileTestFailureMessage(
                             mPackageName, crashEntries, true, videoStartTime.get());
diff --git a/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java b/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java
index e9b2f4e..1244f19 100644
--- a/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java
+++ b/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java
@@ -16,15 +16,12 @@
 
 package com.android.csuite.tests;
 
-import com.android.csuite.core.ApkInstaller;
 import com.android.csuite.core.AppCrawlTester;
 import com.android.csuite.core.AppCrawlTester.CrawlerException;
-import com.android.csuite.core.DeviceJUnit4ClassRunner;
 import com.android.csuite.core.TestUtils;
-import com.android.tradefed.config.IConfiguration;
-import com.android.tradefed.config.IConfigurationReceiver;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
 import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
 import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
 
@@ -35,30 +32,41 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 
 import java.io.File;
-import java.io.IOException;
 import java.util.ArrayList;
 import java.util.List;
 
 /** A test that verifies that a single app can be successfully launched. */
 @RunWith(DeviceJUnit4ClassRunner.class)
-public class AppCrawlTest extends BaseHostJUnit4Test implements IConfigurationReceiver {
-    @Deprecated private static final String COLLECT_APP_VERSION = "collect-app-version";
-    @Deprecated private static final String COLLECT_GMS_VERSION = "collect-gms-version";
-    @Deprecated private static final String RECORD_SCREEN = "record-screen";
-    @Deprecated private static final int DEFAULT_TIMEOUT_SEC = 60;
+public class AppCrawlTest extends BaseHostJUnit4Test {
 
     @Rule public TestLogData mLogData = new TestLogData();
 
     private AppCrawlTester mCrawler;
-    private IConfiguration mConfiguration;
+
+    @Before
+    public void setUp() throws DeviceNotAvailableException, CrawlerException {
+        mCrawler = AppCrawlTester.newInstance(getTestInformation(), mLogData);
+        processDeprecatedOptions();
+        mCrawler.runSetup();
+    }
+
+    @Test
+    public void testAppCrash() throws DeviceNotAvailableException, CrawlerException {
+        mCrawler.runTest();
+    }
+
+    @After
+    public void tearDown() {
+        mCrawler.runTearDown();
+    }
 
     @Deprecated
-    @Option(name = RECORD_SCREEN, description = "Whether to record screen during test.")
+    @Option(name = "record-screen", description = "Whether to record screen during test.")
     private boolean mRecordScreen;
 
     @Deprecated
     @Option(
-            name = COLLECT_APP_VERSION,
+            name = "collect-app-version",
             description =
                     "Whether to collect package version information and store the information in"
                             + " test log files.")
@@ -66,7 +74,7 @@ public class AppCrawlTest extends BaseHostJUnit4Test implements IConfigurationRe
 
     @Deprecated
     @Option(
-            name = COLLECT_GMS_VERSION,
+            name = "collect-gms-version",
             description =
                     "Whether to collect GMS core version information and store the information in"
                             + " test log files.")
@@ -117,14 +125,14 @@ public class AppCrawlTest extends BaseHostJUnit4Test implements IConfigurationRe
             description =
                     "Run the crawler with UIAutomator mode. Apk option is not required in this"
                             + " mode.")
-    private boolean mUiAutomatorMode = false;
+    private boolean mUiAutomatorMode = true;
 
     @Deprecated
     @Option(
             name = "timeout-sec",
             mandatory = false,
             description = "The timeout for the crawl test.")
-    private int mTimeoutSec = DEFAULT_TIMEOUT_SEC;
+    private int mTimeoutSec = 60;
 
     @Deprecated
     @Option(
@@ -132,8 +140,6 @@ public class AppCrawlTest extends BaseHostJUnit4Test implements IConfigurationRe
             description = "A Roboscript file to be executed by the crawler.")
     private File mRoboscriptFile;
 
-    // TODO(b/234512223): add support for contextual roboscript files
-
     @Deprecated
     @Option(
             name = "crawl-guidance-proto-file",
@@ -163,55 +169,52 @@ public class AppCrawlTest extends BaseHostJUnit4Test implements IConfigurationRe
             description = "After an apks are installed, grant MANAGE_EXTERNAL_STORAGE permissions.")
     private boolean mGrantExternalStoragePermission = false;
 
-    @Before
-    public void setUp()
-            throws ApkInstaller.ApkInstallerException, IOException, DeviceNotAvailableException {
-        mCrawler =
-                AppCrawlTester.newInstance(
-                        mPackageName, getTestInformation(), mLogData, mConfiguration);
-        if (mCrawlControllerEndpoint != null) {
-            mCrawler.getOptions().setCrawlControllerEndpoint(mCrawlControllerEndpoint);
-        }
+    /** Convert deprecated options to new options if set. */
+    private void processDeprecatedOptions() {
         if (mRecordScreen) {
-            mCrawler.getOptions().setRecordScreen(mRecordScreen);
+            mCrawler.setRecordScreen(mRecordScreen);
+        }
+        if (mCollectAppVersion) {
+            mCrawler.setCollectAppVersion(mCollectAppVersion);
         }
         if (mCollectGmsVersion) {
-            mCrawler.getOptions().setCollectGmsVersion(mCollectGmsVersion);
+            mCrawler.setCollectGmsVersion(mCollectGmsVersion);
         }
-        if (mCollectAppVersion) {
-            mCrawler.getOptions().setCollectAppVersion(mCollectAppVersion);
+        if (mRepackApk != null) {
+            mCrawler.setSubjectApkPath(mRepackApk);
         }
-        if (mUiAutomatorMode) {
-            mCrawler.getOptions().setUiAutomatorMode(mUiAutomatorMode);
+        if (!mInstallApkPaths.isEmpty()) {
+            mCrawler.setExtraApkPaths(mInstallApkPaths);
+        }
+        if (!mInstallArgs.isEmpty()) {
+            mCrawler.setExtraApkInstallArgs(mInstallArgs);
+        }
+        if (!mUiAutomatorMode) {
+            mCrawler.setEspressoMode(true);
+        }
+        if (mTimeoutSec > 0) {
+            mCrawler.setCrawlDurationSec(mTimeoutSec);
         }
         if (mRoboscriptFile != null) {
-            mCrawler.getOptions().setRoboscriptFile(mRoboscriptFile);
+            mCrawler.setRoboscriptFile(mRoboscriptFile);
         }
         if (mCrawlGuidanceProtoFile != null) {
-            mCrawler.getOptions().setCrawlGuidanceProtoFile(mCrawlGuidanceProtoFile);
+            mCrawler.setCrawlGuidanceProtoFile(mCrawlGuidanceProtoFile);
         }
         if (mLoginConfigDir != null) {
-            mCrawler.getOptions().setLoginConfigDir(mLoginConfigDir);
+            mCrawler.setLoginConfigDir(mLoginConfigDir);
         }
-        if (mTimeoutSec != DEFAULT_TIMEOUT_SEC) {
-            mCrawler.getOptions().setTimeoutSec(mTimeoutSec);
+        if (mSaveApkWhen != TestUtils.TakeEffectWhen.NEVER) {
+            mCrawler.setSaveApkWhen(mSaveApkWhen);
+        }
+        if (mGrantExternalStoragePermission) {
+            mCrawler.setGrantExternalStoragePermission(true);
+        }
+        if (mCrawlControllerEndpoint != null) {
+            mCrawler.setCrawlControllerEndpoint(mCrawlControllerEndpoint);
+        }
+        if (mPackageName != null) {
+            mCrawler.setSubjectPackageName(mPackageName);
         }
-
-        mCrawler.runSetup();
-    }
-
-    @Test
-    public void testAppCrash() throws DeviceNotAvailableException, CrawlerException {
-        mCrawler.runTest();
-    }
-
-    @After
-    public void tearDown() {
-        mCrawler.runTearDown();
-    }
-
-    @Override
-    public void setConfiguration(IConfiguration configuration) {
-        mConfiguration = configuration;
     }
 }
diff --git a/test_scripts/src/main/java/com/android/csuite/tests/AppLaunchTest.java b/test_scripts/src/main/java/com/android/csuite/tests/AppLaunchTest.java
index a8017ac..5721559 100644
--- a/test_scripts/src/main/java/com/android/csuite/tests/AppLaunchTest.java
+++ b/test_scripts/src/main/java/com/android/csuite/tests/AppLaunchTest.java
@@ -16,160 +16,34 @@
 
 package com.android.csuite.tests;
 
-import com.android.csuite.core.ApkInstaller;
-import com.android.csuite.core.ApkInstaller.ApkInstallerException;
-import com.android.csuite.core.BlankScreenDetectorWithSameColorRectangle;
-import com.android.csuite.core.BlankScreenDetectorWithSameColorRectangle.BlankScreen;
-import com.android.csuite.core.DeviceUtils;
 import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
 import com.android.csuite.core.DeviceUtils.DeviceUtilsException;
-import com.android.csuite.core.DeviceUtils.DropboxEntry;
 import com.android.csuite.core.DeviceUtils.RunnableThrowingDeviceNotAvailable;
-import com.android.csuite.core.TestUtils;
-import com.android.tradefed.config.Option;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.log.LogUtil.CLog;
-import com.android.tradefed.result.InputStreamSource;
-import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
-import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
-import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
 import com.android.tradefed.util.RunUtil;
 
-import com.google.common.annotations.VisibleForTesting;
-import com.google.common.base.Preconditions;
-
-import org.junit.After;
 import org.junit.Assert;
-import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
-import org.junit.runner.RunWith;
 
-import java.awt.image.BufferedImage;
-import java.io.File;
-import java.io.IOException;
-import java.util.ArrayList;
-import java.util.List;
 import java.util.concurrent.atomic.AtomicReference;
-import java.util.stream.Collectors;
-
-import javax.imageio.ImageIO;
 
 /** A test that verifies that a single app can be successfully launched. */
-@RunWith(DeviceJUnit4ClassRunner.class)
-public class AppLaunchTest extends BaseHostJUnit4Test {
-    @VisibleForTesting static final String SCREENSHOT_AFTER_LAUNCH = "screenshot-after-launch";
-    @VisibleForTesting static final String COLLECT_APP_VERSION = "collect-app-version";
-    @VisibleForTesting static final String COLLECT_GMS_VERSION = "collect-gms-version";
-    @VisibleForTesting static final String RECORD_SCREEN = "record-screen";
-    @Rule public TestLogData mLogData = new TestLogData();
-    private ApkInstaller mApkInstaller;
-    private boolean mIsLastTestPass;
-    private boolean mIsApkSaved = false;
-
-    @Option(name = RECORD_SCREEN, description = "Whether to record screen during test.")
-    private boolean mRecordScreen;
-
-    @Option(
-            name = SCREENSHOT_AFTER_LAUNCH,
-            description = "Whether to take a screenshost after a package is launched.")
-    private boolean mScreenshotAfterLaunch;
-
-    @Option(
-            name = COLLECT_APP_VERSION,
-            description =
-                    "Whether to collect package version information and store the information in"
-                            + " test log files.")
-    private boolean mCollectAppVersion;
-
-    @Option(
-            name = COLLECT_GMS_VERSION,
-            description =
-                    "Whether to collect GMS core version information and store the information in"
-                            + " test log files.")
-    private boolean mCollectGmsVersion;
-
-    @Option(
-            name = "install-apk",
-            description =
-                    "The path to an apk file or a directory of apk files of a singe package to be"
-                            + " installed on device. Can be repeated.")
-    private final List<File> mApkPaths = new ArrayList<>();
-
-    @Option(
-            name = "install-arg",
-            description = "Arguments for the 'adb install-multiple' package installation command.")
-    private final List<String> mInstallArgs = new ArrayList<>();
-
-    @Option(
-            name = "save-apk-when",
-            description = "When to save apk files to the test result artifacts.")
-    private TestUtils.TakeEffectWhen mSaveApkWhen = TestUtils.TakeEffectWhen.NEVER;
-
-    @Option(name = "package-name", description = "Package name of testing app.")
-    protected String mPackageName;
+public class AppLaunchTest extends BaseAppLaunchTest {
 
-    @Option(
-            name = "app-launch-timeout-ms",
-            description = "Time to wait for app to launch in msecs.")
-    private int mAppLaunchTimeoutMs = 15000;
-
-    @Option(
-            name = "blank-screen-same-color-area-threshold",
-            description =
-                    "Percentage of the screen which, if occupied by a same-color rectangle "
-                            + "area, indicates that the app has reached a blank screen.")
-    private double mBlankScreenSameColorThreshold = -1;
-
-    @Before
-    public void setUp() throws DeviceNotAvailableException, ApkInstallerException, IOException {
-        Assert.assertNotNull("Package name cannot be null", mPackageName);
-        mIsLastTestPass = false;
-
-        DeviceUtils deviceUtils = DeviceUtils.getInstance(getDevice());
-        TestUtils testUtils = TestUtils.getInstance(getTestInformation(), mLogData);
-
-        mApkInstaller = ApkInstaller.getInstance(getDevice());
-        mApkInstaller.install(
-                mApkPaths.stream().map(File::toPath).collect(Collectors.toList()), mInstallArgs);
-
-        if (mCollectGmsVersion) {
-            testUtils.collectGmsVersion(mPackageName);
-        }
-
-        if (mCollectAppVersion) {
-            testUtils.collectAppVersion(mPackageName);
-        }
-
-        deviceUtils.freezeRotation();
-    }
-
-    @Test
-    public void testAppCrash() throws DeviceNotAvailableException, IOException {
-        CLog.d("Launching package: %s.", mPackageName);
-
-        DeviceUtils deviceUtils = DeviceUtils.getInstance(getDevice());
-        TestUtils testUtils = TestUtils.getInstance(getTestInformation(), mLogData);
-
-        try {
-            if (!deviceUtils.isPackageInstalled(mPackageName)) {
-                Assert.fail(
-                        "Package "
-                                + mPackageName
-                                + " is not installed on the device. Aborting the test.");
-            }
-        } catch (DeviceUtilsException e) {
-            Assert.fail("Failed to check the installed package list: " + e.getMessage());
-        }
-
-        AtomicReference<DeviceTimestamp> startTime = new AtomicReference<>();
-        AtomicReference<DeviceTimestamp> videoStartTime = new AtomicReference<>();
+    /**
+     * Implements the specific app launch logic.
+     */
+    @Override
+    protected void performAppLaunch(
+        AtomicReference<DeviceTimestamp> startTime,
+        AtomicReference<DeviceTimestamp> videoStartTime) throws DeviceNotAvailableException {
 
         RunnableThrowingDeviceNotAvailable launchJob =
                 () -> {
-                    startTime.set(deviceUtils.currentTimeMillis());
+                    startTime.set(mDeviceUtils.currentTimeMillis());
                     try {
-                        deviceUtils.launchPackage(mPackageName);
+                        mDeviceUtils.launchPackage(mPackageName);
                     } catch (DeviceUtilsException e) {
                         Assert.fail(
                                 "Failed to launch package " + mPackageName + ": " + e.getMessage());
@@ -182,78 +56,12 @@ public class AppLaunchTest extends BaseHostJUnit4Test {
                 };
 
         if (mRecordScreen) {
-            testUtils.collectScreenRecord(
-                    launchJob,
-                    mPackageName,
-                    videoStartTimeOnDevice -> videoStartTime.set(videoStartTimeOnDevice));
+            mTestUtils.collectScreenRecord(
+                launchJob,
+                mPackageName,
+                videoStartTimeOnDevice -> videoStartTime.set(videoStartTimeOnDevice));
         } else {
             launchJob.run();
         }
-
-        CLog.d("Completed launching package: %s", mPackageName);
-        DeviceTimestamp endTime = deviceUtils.currentTimeMillis();
-
-        try {
-            List<DropboxEntry> crashEntries =
-                    deviceUtils.getDropboxEntries(
-                            DeviceUtils.DROPBOX_APP_CRASH_TAGS,
-                            mPackageName,
-                            startTime.get(),
-                            endTime);
-            String crashLog =
-                    testUtils.compileTestFailureMessage(
-                            mPackageName, crashEntries, true, videoStartTime.get());
-            if (crashLog != null) {
-                Assert.fail(crashLog);
-            }
-        } catch (IOException e) {
-            Assert.fail("Error while getting dropbox crash log: " + e);
-        }
-
-        if (mBlankScreenSameColorThreshold > 0) {
-            BufferedImage screen;
-            try (InputStreamSource screenShot =
-                    testUtils.getTestInformation().getDevice().getScreenshot()) {
-                Preconditions.checkNotNull(screenShot);
-                screen = ImageIO.read(screenShot.createInputStream());
-            }
-            BlankScreen blankScreen =
-                    BlankScreenDetectorWithSameColorRectangle.getBlankScreen(screen);
-            double blankScreenPercent = blankScreen.getBlankScreenPercent();
-            if (blankScreenPercent > mBlankScreenSameColorThreshold) {
-                BlankScreenDetectorWithSameColorRectangle.saveBlankScreenArtifact(
-                        mPackageName,
-                        blankScreen,
-                        testUtils.getTestArtifactReceiver(),
-                        testUtils.getTestInformation().getDevice().getSerialNumber());
-                Assert.fail(
-                        String.format(
-                                "Blank screen detected with same-color rectangle area percentage of"
-                                        + " %.2f%%",
-                                blankScreenPercent * 100));
-            }
-        }
-
-        mIsLastTestPass = true;
-    }
-
-    @After
-    public void tearDown() throws DeviceNotAvailableException, ApkInstallerException {
-        DeviceUtils deviceUtils = DeviceUtils.getInstance(getDevice());
-        TestUtils testUtils = TestUtils.getInstance(getTestInformation(), mLogData);
-
-        if (!mIsApkSaved) {
-            mIsApkSaved =
-                    testUtils.saveApks(mSaveApkWhen, mIsLastTestPass, mPackageName, mApkPaths);
-        }
-
-        if (mScreenshotAfterLaunch) {
-            testUtils.collectScreenshot(mPackageName);
-        }
-
-        deviceUtils.stopPackage(mPackageName);
-        deviceUtils.unfreezeRotation();
-
-        mApkInstaller.uninstallAllInstalledPackages();
     }
-}
+}
\ No newline at end of file
diff --git a/test_scripts/src/main/java/com/android/csuite/tests/BaseAppLaunchTest.java b/test_scripts/src/main/java/com/android/csuite/tests/BaseAppLaunchTest.java
new file mode 100644
index 0000000..488c0bf
--- /dev/null
+++ b/test_scripts/src/main/java/com/android/csuite/tests/BaseAppLaunchTest.java
@@ -0,0 +1,269 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.csuite.tests;
+
+import com.android.csuite.core.ApkInstaller;
+import com.android.csuite.core.ApkInstaller.ApkInstallerException;
+import com.android.csuite.core.AutoFDOProfileCollector;
+import com.android.csuite.core.BlankScreenDetectorWithSameColorRectangle;
+import com.android.csuite.core.BlankScreenDetectorWithSameColorRectangle.BlankScreen;
+import com.android.csuite.core.DeviceUtils;
+import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
+import com.android.csuite.core.DeviceUtils.DeviceUtilsException;
+import com.android.csuite.core.DropboxEntryCrashDetector.DropboxEntry;
+import com.android.csuite.core.TestUtils;
+import com.android.tradefed.config.Option;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.result.InputStreamSource;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
+
+import com.google.common.annotations.VisibleForTesting;
+import com.google.common.base.Preconditions;
+
+import org.junit.After;
+import org.junit.Assert;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+import java.awt.image.BufferedImage;
+import java.io.File;
+import java.io.IOException;
+import java.util.ArrayList;
+import java.util.List;
+import java.util.concurrent.atomic.AtomicReference;
+import java.util.stream.Collectors;
+
+import javax.imageio.ImageIO;
+
+/**
+ * Base abstract class for app launch related tests, providing common options, setup, teardown,
+ * and crash/blank screen detection logic.
+ */
+@RunWith(DeviceJUnit4ClassRunner.class)
+public abstract class BaseAppLaunchTest extends BaseHostJUnit4Test {
+
+  @VisibleForTesting static final String SCREENSHOT_AFTER_LAUNCH = "screenshot-after-launch";
+  @VisibleForTesting static final String COLLECT_APP_VERSION = "collect-app-version";
+  @VisibleForTesting static final String COLLECT_GMS_VERSION = "collect-gms-version";
+  @VisibleForTesting static final String RECORD_SCREEN = "record-screen";
+
+  @Rule public TestLogData mLogData = new TestLogData();
+  protected ApkInstaller mApkInstaller;
+  protected boolean mIsLastTestPass;
+  protected boolean mIsApkSaved = false;
+  protected AutoFDOProfileCollector mAutoFDOProfileCollector;
+
+  @Option(name = RECORD_SCREEN, description = "Whether to record screen during test.")
+  protected boolean mRecordScreen;
+
+  @Option(
+          name = SCREENSHOT_AFTER_LAUNCH,
+          description = "Whether to take a screenshot after a package is launched.")
+  protected boolean mScreenshotAfterLaunch;
+
+  @Option(
+          name = COLLECT_APP_VERSION,
+          description =
+                  "Whether to collect package version information and store the information in"
+                          + " test log files.")
+  protected boolean mCollectAppVersion;
+
+  @Option(
+          name = COLLECT_GMS_VERSION,
+          description =
+                  "Whether to collect GMS core version information and store the information in"
+                          + " test log files.")
+  protected boolean mCollectGmsVersion;
+
+  @Option(
+          name = "collect-autofdo-profile",
+          description =
+                  "Whether to collect kernel AutoFDO profile and store the information in"
+                          + " test log files.")
+  private boolean mCollectAutoFDOProfile;
+
+  @Option(
+          name = "install-apk",
+          description =
+                  "The path to an apk file or a directory of apk files of a single package to be"
+                          + " installed on device. Can be repeated.")
+  protected final List<File> mApkPaths = new ArrayList<>();
+
+  @Option(
+          name = "install-arg",
+          description = "Arguments for the 'adb install-multiple' package installation command.")
+  protected final List<String> mInstallArgs = new ArrayList<>();
+
+  @Option(
+          name = "save-apk-when",
+          description = "When to save apk files to the test result artifacts.")
+  protected TestUtils.TakeEffectWhen mSaveApkWhen = TestUtils.TakeEffectWhen.NEVER;
+
+  @Option(name = "package-name", description = "Package name of testing app.")
+  protected String mPackageName;
+
+  @Option(
+          name = "app-launch-timeout-ms",
+          description = "Time to wait for app to launch in msecs.")
+  protected int mAppLaunchTimeoutMs = 15000;
+
+  @Option(
+          name = "blank-screen-same-color-area-threshold",
+          description =
+                  "Percentage of the screen which, if occupied by a same-color rectangle "
+                          + "area, indicates that the app has reached a blank screen.")
+  protected double mBlankScreenSameColorThreshold = -1;
+
+  protected DeviceUtils mDeviceUtils;
+  protected TestUtils mTestUtils;
+
+  @Before
+  public void setUp() throws DeviceNotAvailableException, ApkInstallerException, IOException {
+    Assert.assertNotNull("Package name cannot be null", mPackageName);
+    mIsLastTestPass = false;
+
+    mDeviceUtils = DeviceUtils.getInstance(getDevice());
+    mTestUtils = TestUtils.getInstance(getTestInformation(), mLogData);
+
+    mApkInstaller = ApkInstaller.getInstance(getDevice());
+    mApkInstaller.install(
+      mApkPaths.stream().map(File::toPath).collect(Collectors.toList()), mInstallArgs);
+
+    if (mCollectGmsVersion) {
+      mTestUtils.collectGmsVersion(mPackageName);
+    }
+
+    if (mCollectAppVersion) {
+      mTestUtils.collectAppVersion(mPackageName);
+    }
+
+    if (mCollectAutoFDOProfile) {
+      mAutoFDOProfileCollector = AutoFDOProfileCollector.newInstance(getDevice());
+    }
+
+    mDeviceUtils.freezeRotation();
+  }
+
+  /**
+   * Abstract method to be implemented by subclasses to define their specific app launch logic.
+   *
+   * @param startTime A reference to capture the device timestamp when the launch job starts.
+   * @param videoStartTime A reference to capture the device timestamp when screen recording starts (if enabled).
+   * @throws DeviceNotAvailableException
+   */
+  protected abstract void performAppLaunch(
+    AtomicReference<DeviceTimestamp> startTime,
+    AtomicReference<DeviceTimestamp> videoStartTime) throws DeviceNotAvailableException;
+
+  @Test
+  public void testAppLaunchCommonLogic() throws DeviceNotAvailableException, IOException {
+    CLog.d("Launching package: %s.", mPackageName);
+
+    try {
+        if (!mDeviceUtils.isPackageInstalled(mPackageName)) {
+            Assert.fail(
+              "Package "
+                  + mPackageName
+                  + " is not installed on the device. Aborting the test.");
+        }
+    } catch (DeviceUtilsException e) {
+        Assert.fail("Failed to check the installed package list: " + e.getMessage());
+    }
+
+    AtomicReference<DeviceTimestamp> startTime = new AtomicReference<>();
+    AtomicReference<DeviceTimestamp> videoStartTime = new AtomicReference<>();
+
+    if (mCollectAutoFDOProfile
+            && !mAutoFDOProfileCollector.recordAutoFDOProfile(mAppLaunchTimeoutMs / 1000.0)) {
+        CLog.e("Failed to record AutoFDO profile.");
+    }
+
+    performAppLaunch(startTime, videoStartTime);
+
+    CLog.d("Completed launching package: %s", mPackageName);
+    DeviceTimestamp endTime = mDeviceUtils.currentTimeMillis();
+
+    try {
+        List<DropboxEntry> crashEntries =
+          mDeviceUtils.getCrashEntriesFromDropbox(mPackageName, startTime.get(), endTime);
+        String crashLog =
+          mTestUtils.compileTestFailureMessage(
+            mPackageName, crashEntries, true, videoStartTime.get());
+        if (!crashLog.isBlank()) {
+          Assert.fail(crashLog);
+        }
+    } catch (IOException e) {
+      Assert.fail("Error while getting dropbox crash log: " + e);
+    }
+
+    if (mBlankScreenSameColorThreshold > 0) {
+      BufferedImage screen;
+      try (InputStreamSource screenShot =
+              mTestUtils.getTestInformation().getDevice().getScreenshot()) {
+          Preconditions.checkNotNull(screenShot);
+          screen = ImageIO.read(screenShot.createInputStream());
+      }
+      BlankScreen blankScreen =
+          BlankScreenDetectorWithSameColorRectangle.getBlankScreen(screen);
+      double blankScreenPercent = blankScreen.getBlankScreenPercent();
+      if (blankScreenPercent > mBlankScreenSameColorThreshold) {
+          BlankScreenDetectorWithSameColorRectangle.saveBlankScreenArtifact(
+              mPackageName,
+              blankScreen,
+              mTestUtils.getTestArtifactReceiver(),
+              mTestUtils.getTestInformation().getDevice().getSerialNumber());
+          Assert.fail(
+              String.format(
+                  "Blank screen detected with same-color rectangle area percentage of"
+                      + " %.2f%%",
+                  blankScreenPercent * 100));
+      }
+    }
+
+    mIsLastTestPass = true;
+  }
+
+  @After
+  public void tearDown() throws DeviceNotAvailableException, ApkInstallerException {
+    if (!mIsApkSaved) {
+      mIsApkSaved =
+        mTestUtils.saveApks(mSaveApkWhen, mIsLastTestPass, mPackageName, mApkPaths);
+    }
+
+    if (mScreenshotAfterLaunch) {
+      mTestUtils.collectScreenshot(mPackageName);
+    }
+
+    if (mCollectAutoFDOProfile) {
+      try {
+        mAutoFDOProfileCollector.collectAutoFDOProfile(mTestUtils.getTestArtifactReceiver());
+      } catch (DeviceNotAvailableException e) {
+        CLog.e("AutoFDO profile collection failed during teardown: %s", e.getMessage());
+      }
+    }
+
+    mDeviceUtils.stopPackage(mPackageName);
+    mDeviceUtils.unfreezeRotation();
+
+    mApkInstaller.uninstallAllInstalledPackages();
+  }
+}
\ No newline at end of file
diff --git a/test_scripts/src/main/java/com/android/csuite/tests/WarmAppLaunchTest.java b/test_scripts/src/main/java/com/android/csuite/tests/WarmAppLaunchTest.java
new file mode 100644
index 0000000..776b084
--- /dev/null
+++ b/test_scripts/src/main/java/com/android/csuite/tests/WarmAppLaunchTest.java
@@ -0,0 +1,91 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.csuite.tests;
+
+import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
+import com.android.csuite.core.DeviceUtils.DeviceUtilsException;
+import com.android.csuite.core.DeviceUtils.RunnableThrowingDeviceNotAvailable;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.csuite.core.ApkInstaller.ApkInstallerException;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.util.RunUtil;
+
+import org.junit.Assert;
+import com.android.tradefed.config.Option;
+import org.junit.Before;
+import java.io.IOException;
+
+import java.util.concurrent.atomic.AtomicReference;
+
+/** A test that collects warm start launch time of a single app using perfetto. */
+public class WarmAppLaunchTest extends BaseAppLaunchTest {
+
+    @Option(
+            name = "warm-app-launch-count",
+            description = "Number of times to launch the app.")
+    private int mAppLaunchCount = 9;
+
+    @Override
+    @Before
+    public void setUp() throws DeviceNotAvailableException, ApkInstallerException, IOException {
+        super.setUp();
+
+        try {
+            mDeviceUtils.warmLaunchPackage(mPackageName);
+        } catch (DeviceUtilsException e) {
+            Assert.fail("Failed to launch package: " + e.getMessage());
+        }
+        mDeviceUtils.pressHome();
+    }
+
+    /**
+     * Implements the specific logic for warm app launching the app repeatedly.
+     */
+    @Override
+    protected void performAppLaunch(
+        AtomicReference<DeviceTimestamp> startTime,
+        AtomicReference<DeviceTimestamp> videoStartTime) throws DeviceNotAvailableException {
+
+        RunnableThrowingDeviceNotAvailable launchJob =
+                () -> {
+                    startTime.set(mDeviceUtils.currentTimeMillis());
+                    try {
+                        for (int i = 0; i < mAppLaunchCount; i++) {
+                            mDeviceUtils.warmLaunchPackage(mPackageName);
+                            CLog.d(
+                                    "Waiting %s milliseconds for the app to launch fully.",
+                                    mAppLaunchTimeoutMs);
+                            RunUtil.getDefault().sleep(mAppLaunchTimeoutMs);
+                            mDeviceUtils.pressHome();
+                        }
+                    } catch (DeviceUtilsException e) {
+                        Assert.fail(
+                                "Failed to launch package " + mPackageName + ": " + e.getMessage());
+                    }
+                };
+
+        if (mRecordScreen) {
+            mTestUtils.collectScreenRecord(
+                launchJob,
+                mPackageName,
+                videoStartTimeOnDevice -> videoStartTime.set(videoStartTimeOnDevice));
+        } else {
+            launchJob.run();
+        }
+    }
+}
\ No newline at end of file
diff --git a/test_scripts/src/main/java/com/android/webview/lib/WebviewUtils.java b/test_scripts/src/main/java/com/android/webview/lib/WebviewUtils.java
index 89949e7..90ee022 100644
--- a/test_scripts/src/main/java/com/android/webview/lib/WebviewUtils.java
+++ b/test_scripts/src/main/java/com/android/webview/lib/WebviewUtils.java
@@ -69,8 +69,8 @@ public class WebviewUtils {
         Assert.assertEquals(
                 "The WebView installer tool failed to install WebView:\n"
                         + commandResult.toString(),
-                commandResult.getStatus(),
-                CommandStatus.SUCCESS);
+                CommandStatus.SUCCESS,
+                commandResult.getStatus());
 
         printWebviewVersion();
         return getCurrentWebviewPackage();
diff --git a/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java b/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java
index 83f6753..f8c032f 100644
--- a/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java
+++ b/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java
@@ -16,18 +16,14 @@
 
 package com.android.webview.tests;
 
-import com.android.csuite.core.ApkInstaller;
-import com.android.csuite.core.ApkInstaller.ApkInstallerException;
 import com.android.csuite.core.AppCrawlTester;
 import com.android.csuite.core.AppCrawlTester.CrawlerException;
-import com.android.csuite.core.DeviceJUnit4ClassRunner;
 import com.android.csuite.core.DeviceUtils;
 import com.android.csuite.core.TestUtils;
-import com.android.tradefed.config.IConfiguration;
-import com.android.tradefed.config.IConfigurationReceiver;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
 import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
 import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
 import com.android.webview.lib.WebviewPackage;
@@ -48,23 +44,13 @@ import java.util.List;
 
 /** A test that verifies that a single app can be successfully launched. */
 @RunWith(DeviceJUnit4ClassRunner.class)
-public class WebviewAppCrawlTest extends BaseHostJUnit4Test implements IConfigurationReceiver {
+public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
     @Rule public TestLogData mLogData = new TestLogData();
 
-    @Deprecated private static final String COLLECT_APP_VERSION = "collect-app-version";
-    @Deprecated private static final String COLLECT_GMS_VERSION = "collect-gms-version";
-    @Deprecated private static final int DEFAULT_TIMEOUT_SEC = 60;
-
     private WebviewUtils mWebviewUtils;
     private WebviewPackage mPreInstalledWebview;
-    private ApkInstaller mApkInstaller;
     private AppCrawlTester mCrawler;
     private AppCrawlTester mCrawlerVerify;
-    private IConfiguration mConfiguration;
-
-    @Deprecated
-    @Option(name = "record-screen", description = "Whether to record screen during test.")
-    private boolean mRecordScreen;
 
     @Option(name = "webview-version-to-test", description = "Version of Webview to test.")
     private String mWebviewVersionToTest;
@@ -77,28 +63,75 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test implements IConfigur
     @Option(name = "package-name", description = "Package name of testing app.")
     private String mPackageName;
 
-    @Deprecated
-    @Option(
-            name = "install-apk",
-            description =
-                    "The path to an apk file or a directory of apk files of a singe package to be"
-                            + " installed on device. Can be repeated.")
-    private List<File> mApkPaths = new ArrayList<>();
+    @Before
+    public void setUp() throws DeviceNotAvailableException, CrawlerException {
+        Assert.assertNotNull("Package name cannot be null", mPackageName);
+        Assert.assertTrue(
+                "Either the --release-channel or --webview-version-to-test arguments "
+                        + "must be used",
+                mWebviewVersionToTest != null || mReleaseChannel != null);
 
-    @Deprecated
-    @Option(
-            name = "install-arg",
-            description = "Arguments for the 'adb install-multiple' package installation command.")
-    private final List<String> mInstallArgs = new ArrayList<>();
+        // Only save apk on the verification run.
+        // Only record screen on the webview run.
+        mCrawler =
+                AppCrawlTester.newInstance(getTestInformation(), mLogData)
+                        .setSaveApkWhen(TestUtils.TakeEffectWhen.NEVER)
+                        .setRecordScreen(true)
+                        .setNoThrowOnFailure(true);
+        mCrawlerVerify =
+                AppCrawlTester.newInstance(getTestInformation(), mLogData)
+                        .setSaveApkWhen(TestUtils.TakeEffectWhen.ON_PASS)
+                        .setRecordScreen(false)
+                        .setNoThrowOnFailure(true);
 
-    @Option(
-            name = "app-launch-timeout-ms",
-            description = "Time to wait for an app to launch in msecs.")
-    private int mAppLaunchTimeoutMs = 20000;
+        mWebviewUtils = new WebviewUtils(getTestInformation());
+        mPreInstalledWebview = mWebviewUtils.getCurrentWebviewPackage();
+
+        DeviceUtils.getInstance(getDevice()).freezeRotation();
+        mWebviewUtils.printWebviewVersion();
+    }
+
+    @Test
+    public void testAppCrawl()
+            throws DeviceNotAvailableException, IOException, CrawlerException, JSONException {
+        WebviewPackage lastWebviewInstalled =
+                mWebviewUtils.installWebview(mWebviewVersionToTest, mReleaseChannel);
+        mCrawler.run();
+        mWebviewUtils.uninstallWebview(lastWebviewInstalled, mPreInstalledWebview);
+
+        // If the test doesn't fail, complete the test.
+        if (mCrawler.isTestPassed()) {
+            return;
+        }
+
+        // If the test fails, try the app with the original webview version that comes with the
+        // device.
+        mCrawlerVerify.run();
+        if (!mCrawlerVerify.isTestPassed()) {
+            CLog.w(
+                    "Test on app %s failed both with and without the webview installation,"
+                            + " ignoring the failure...",
+                    mPackageName);
+            return;
+        }
+        throw new AssertionError(
+                String.format(
+                        "Package %s crashed since webview version %s",
+                        mPackageName, lastWebviewInstalled.getVersion()));
+    }
+
+    @After
+    public void tearDown() throws DeviceNotAvailableException {
+        mWebviewUtils.printWebviewVersion();
+    }
+
+    @Deprecated
+    @Option(name = "record-screen", description = "Whether to record screen during test.")
+    private boolean mRecordScreen;
 
     @Deprecated
     @Option(
-            name = COLLECT_APP_VERSION,
+            name = "collect-app-version",
             description =
                     "Whether to collect package version information and store the information in"
                             + " test log files.")
@@ -106,7 +139,7 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test implements IConfigur
 
     @Deprecated
     @Option(
-            name = COLLECT_GMS_VERSION,
+            name = "collect-gms-version",
             description =
                     "Whether to collect GMS core version information and store the information in"
                             + " test log files.")
@@ -121,6 +154,25 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test implements IConfigur
                             + "to repack and install in Espresso mode")
     private File mRepackApk;
 
+    @Deprecated
+    @Option(
+            name = "install-apk",
+            mandatory = false,
+            description =
+                    "The path to an apk file or a directory of apk files to be installed on the"
+                            + " device. In Ui-automator mode, this includes both the target apk to"
+                            + " install and any dependencies. In Espresso mode this can include"
+                            + " additional libraries or dependencies.")
+    private final List<File> mInstallApkPaths = new ArrayList<>();
+
+    @Deprecated
+    @Option(
+            name = "install-arg",
+            description =
+                    "Arguments for the 'adb install-multiple' package installation command for"
+                            + " UI-automator mode.")
+    private final List<String> mInstallArgs = new ArrayList<>();
+
     @Deprecated
     @Option(
             name = "crawl-controller-endpoint",
@@ -135,7 +187,14 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test implements IConfigur
             description =
                     "Run the crawler with UIAutomator mode. Apk option is not required in this"
                             + " mode.")
-    private boolean mUiAutomatorMode = false;
+    private boolean mUiAutomatorMode = true;
+
+    @Deprecated
+    @Option(
+            name = "timeout-sec",
+            mandatory = false,
+            description = "The timeout for the crawl test.")
+    private int mTimeoutSec = 60;
 
     @Deprecated
     @Option(
@@ -143,27 +202,12 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test implements IConfigur
             description = "A Roboscript file to be executed by the crawler.")
     private File mRoboscriptFile;
 
-    // TODO(b/234512223): add support for contextual roboscript files
-
     @Deprecated
     @Option(
             name = "crawl-guidance-proto-file",
             description = "A CrawlGuidance file to be executed by the crawler.")
     private File mCrawlGuidanceProtoFile;
 
-    @Deprecated
-    @Option(
-            name = "timeout-sec",
-            mandatory = false,
-            description = "The timeout for the crawl test.")
-    private int mTimeoutSec = DEFAULT_TIMEOUT_SEC;
-
-    @Deprecated
-    @Option(
-            name = "save-apk-when",
-            description = "When to save apk files to the test result artifacts.")
-    private TestUtils.TakeEffectWhen mSaveApkWhen = TestUtils.TakeEffectWhen.NEVER;
-
     @Deprecated
     @Option(
             name = "login-config-dir",
@@ -174,128 +218,65 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test implements IConfigur
                         + " present, only the Roboscript file will be used.")
     private File mLoginConfigDir;
 
-    @Before
-    public void setUp() throws DeviceNotAvailableException, ApkInstallerException, IOException {
-        Assert.assertNotNull("Package name cannot be null", mPackageName);
-        Assert.assertTrue(
-                "Either the --release-channel or --webview-version-to-test arguments "
-                        + "must be used",
-                mWebviewVersionToTest != null || mReleaseChannel != null);
-
-        mCrawler =
-                AppCrawlTester.newInstance(
-                        mPackageName, getTestInformation(), mLogData, mConfiguration);
-        mCrawlerVerify =
-                AppCrawlTester.newInstance(
-                        mPackageName, getTestInformation(), mLogData, mConfiguration);
-
-        setCrawlerOptions(mCrawler);
-        setCrawlerOptions(mCrawlerVerify);
-
-        // Only save apk on the verification run.
-        mCrawler.getOptions().setSaveApkWhen(TestUtils.TakeEffectWhen.NEVER);
-        mCrawlerVerify.getOptions().setSaveApkWhen(TestUtils.TakeEffectWhen.ON_FAIL);
-        // Only record screen on the webview run.
-        mCrawler.getOptions().setRecordScreen(true);
-        mCrawlerVerify.getOptions().setRecordScreen(false);
-
-        mApkInstaller = ApkInstaller.getInstance(getDevice());
-        mWebviewUtils = new WebviewUtils(getTestInformation());
-        mPreInstalledWebview = mWebviewUtils.getCurrentWebviewPackage();
-
-        DeviceUtils.getInstance(getDevice()).freezeRotation();
-        mWebviewUtils.printWebviewVersion();
-
-        mCrawler.runSetup();
-        mCrawlerVerify.runSetup();
-    }
+    @Deprecated
+    @Option(
+            name = "save-apk-when",
+            description = "When to save apk files to the test result artifacts.")
+    private TestUtils.TakeEffectWhen mSaveApkWhen = TestUtils.TakeEffectWhen.NEVER;
 
-    @Test
-    public void testAppCrawl()
-            throws DeviceNotAvailableException, IOException, CrawlerException, JSONException {
-        AssertionError lastError = null;
-        WebviewPackage lastWebviewInstalled =
-                mWebviewUtils.installWebview(mWebviewVersionToTest, mReleaseChannel);
+    @Deprecated
+    @Option(
+            name = "grant-external-storage",
+            mandatory = false,
+            description = "After an apks are installed, grant MANAGE_EXTERNAL_STORAGE permissions.")
+    private boolean mGrantExternalStoragePermission = false;
 
-        try {
-            mCrawler.runTest();
-        } catch (AssertionError e) {
-            lastError = e;
-        } finally {
-            mWebviewUtils.uninstallWebview(lastWebviewInstalled, mPreInstalledWebview);
+    /** Convert deprecated options to new options if set. */
+    private void processDeprecatedOptions() {
+        if (mRecordScreen) {
+            mCrawler.setRecordScreen(mRecordScreen);
         }
-
-        // If the app doesn't crash, complete the test.
-        if (lastError == null) {
-            return;
+        if (mCollectAppVersion) {
+            mCrawler.setCollectAppVersion(mCollectAppVersion);
         }
-
-        // If the app crashes, try the app with the original webview version that comes with the
-        // device.
-        try {
-            mCrawlerVerify.runTest();
-        } catch (AssertionError newError) {
-            CLog.w(
-                    "The app %s crashed both with and without the webview installation,"
-                            + " ignoring the failure...",
-                    mPackageName);
-            return;
+        if (mCollectGmsVersion) {
+            mCrawler.setCollectGmsVersion(mCollectGmsVersion);
         }
-        throw new AssertionError(
-                String.format(
-                        "Package %s crashed since webview version %s",
-                        mPackageName, lastWebviewInstalled.getVersion()),
-                lastError);
-    }
-
-    @After
-    public void tearDown() throws DeviceNotAvailableException, ApkInstallerException {
-        TestUtils testUtils = TestUtils.getInstance(getTestInformation(), mLogData);
-        testUtils.collectScreenshot(mPackageName);
-
-        DeviceUtils deviceUtils = DeviceUtils.getInstance(getDevice());
-        deviceUtils.stopPackage(mPackageName);
-        deviceUtils.unfreezeRotation();
-
-        mApkInstaller.uninstallAllInstalledPackages();
-        mWebviewUtils.printWebviewVersion();
-
-        mCrawler.runTearDown();
-        mCrawlerVerify.runTearDown();
-    }
-
-    private void setCrawlerOptions(AppCrawlTester crawler) {
-        if (mCrawlControllerEndpoint != null) {
-            crawler.getOptions().setCrawlControllerEndpoint(mCrawlControllerEndpoint);
+        if (mRepackApk != null) {
+            mCrawler.setSubjectApkPath(mRepackApk);
         }
-        if (mRecordScreen) {
-            crawler.getOptions().setRecordScreen(mRecordScreen);
+        if (!mInstallApkPaths.isEmpty()) {
+            mCrawler.setExtraApkPaths(mInstallApkPaths);
         }
-        if (mCollectGmsVersion) {
-            crawler.getOptions().setCollectGmsVersion(mCollectGmsVersion);
+        if (!mInstallArgs.isEmpty()) {
+            mCrawler.setExtraApkInstallArgs(mInstallArgs);
         }
-        if (mCollectAppVersion) {
-            crawler.getOptions().setCollectAppVersion(mCollectAppVersion);
+        if (!mUiAutomatorMode) {
+            mCrawler.setEspressoMode(true);
         }
-        if (mUiAutomatorMode) {
-            crawler.getOptions().setUiAutomatorMode(mUiAutomatorMode);
+        if (mTimeoutSec > 0) {
+            mCrawler.setCrawlDurationSec(mTimeoutSec);
         }
         if (mRoboscriptFile != null) {
-            crawler.getOptions().setRoboscriptFile(mRoboscriptFile);
+            mCrawler.setRoboscriptFile(mRoboscriptFile);
         }
         if (mCrawlGuidanceProtoFile != null) {
-            crawler.getOptions().setCrawlGuidanceProtoFile(mCrawlGuidanceProtoFile);
+            mCrawler.setCrawlGuidanceProtoFile(mCrawlGuidanceProtoFile);
         }
         if (mLoginConfigDir != null) {
-            crawler.getOptions().setLoginConfigDir(mLoginConfigDir);
+            mCrawler.setLoginConfigDir(mLoginConfigDir);
         }
-        if (mTimeoutSec != DEFAULT_TIMEOUT_SEC) {
-            crawler.getOptions().setTimeoutSec(mTimeoutSec);
+        if (mSaveApkWhen != TestUtils.TakeEffectWhen.NEVER) {
+            mCrawler.setSaveApkWhen(mSaveApkWhen);
+        }
+        if (mGrantExternalStoragePermission) {
+            mCrawler.setGrantExternalStoragePermission(true);
+        }
+        if (mCrawlControllerEndpoint != null) {
+            mCrawler.setCrawlControllerEndpoint(mCrawlControllerEndpoint);
+        }
+        if (mPackageName != null) {
+            mCrawler.setSubjectPackageName(mPackageName);
         }
-    }
-
-    @Override
-    public void setConfiguration(IConfiguration configuration) {
-        mConfiguration = configuration;
     }
 }
diff --git a/test_scripts/src/main/java/com/android/webview/tests/WebviewAppLaunchTest.java b/test_scripts/src/main/java/com/android/webview/tests/WebviewAppLaunchTest.java
index ffcaaae..4b768f4 100644
--- a/test_scripts/src/main/java/com/android/webview/tests/WebviewAppLaunchTest.java
+++ b/test_scripts/src/main/java/com/android/webview/tests/WebviewAppLaunchTest.java
@@ -191,7 +191,7 @@ public class WebviewAppLaunchTest extends BaseHostJUnit4Test {
 
         try {
             String crashLog = testUtils.getDropboxPackageCrashLog(mPackageName, startTime, true);
-            if (crashLog != null) {
+            if (!crashLog.isBlank()) {
                 Assert.fail(crashLog);
             }
         } catch (IOException e) {
diff --git a/test_targets/csuite-app-crawl/Android.bp b/test_targets/csuite-app-crawl/Android.bp
index c7bfc7f..c97b659 100644
--- a/test_targets/csuite-app-crawl/Android.bp
+++ b/test_targets/csuite-app-crawl/Android.bp
@@ -19,7 +19,6 @@ package {
 
 csuite_test {
     name: "csuite-app-crawl",
-    test_plan_include: "plan.xml",
     test_config_template: "ui-automator-crawl.xml",
     extra_test_config_templates: [
         "espresso-crawl.xml",
diff --git a/test_targets/csuite-app-crawl/espresso-crawl.xml b/test_targets/csuite-app-crawl/espresso-crawl.xml
index 3900cc9..e703b0a 100644
--- a/test_targets/csuite-app-crawl/espresso-crawl.xml
+++ b/test_targets/csuite-app-crawl/espresso-crawl.xml
@@ -14,18 +14,14 @@
      limitations under the License.
 -->
 <configuration description="C-Suite Crawler test configuration">
-    <object type="APP_CRAWL_TESTER_OPTIONS" class="com.android.csuite.core.AppCrawlTesterOptions" >
-        <option name="repack-apk" value="app://{package}"/>
-        <option name="ui-automator-mode" value="false"/>
-    </object>
-    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
-    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
-        <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
-        <option name="run-command" value="input keyevent KEYCODE_MENU"/>
-        <option name="run-command" value="input keyevent KEYCODE_HOME"/>
+    <target_preparer class="com.android.csuite.core.AppCrawlTesterOptions" >
+        <option name="subject-package-name" value="{package}"/>
+        <option name="subject-apk-path" value="app://{package}"/>
+        <option name="espresso-mode" value="true"/>
     </target_preparer>
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer" />
     <test class="com.android.tradefed.testtype.HostTest" >
-        <option name="set-option" value="package-name:{package}"/>
         <option name="class" value="com.android.csuite.tests.AppCrawlTest" />
     </test>
 </configuration>
\ No newline at end of file
diff --git a/test_targets/csuite-app-crawl/plan.xml b/test_targets/csuite-app-crawl/plan.xml
deleted file mode 100644
index 3ae9e50..0000000
--- a/test_targets/csuite-app-crawl/plan.xml
+++ /dev/null
@@ -1,3 +0,0 @@
-<configuration description="C-Suite Crawler Test Plan">
-  <target_preparer class="com.android.csuite.core.AppCrawlTesterHostPreparer"/>
-</configuration>
\ No newline at end of file
diff --git a/test_targets/csuite-app-crawl/pre-installed-crawl.xml b/test_targets/csuite-app-crawl/pre-installed-crawl.xml
index c687258..f9400df 100644
--- a/test_targets/csuite-app-crawl/pre-installed-crawl.xml
+++ b/test_targets/csuite-app-crawl/pre-installed-crawl.xml
@@ -14,17 +14,12 @@
      limitations under the License.
 -->
 <configuration description="C-Suite Crawler test configuration">
-    <object type="APP_CRAWL_TESTER_OPTIONS" class="com.android.csuite.core.AppCrawlTesterOptions" >
-        <option name="ui-automator-mode" value="true"/>
-    </object>
-    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
-    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
-        <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
-        <option name="run-command" value="input keyevent KEYCODE_MENU"/>
-        <option name="run-command" value="input keyevent KEYCODE_HOME"/>
+    <target_preparer class="com.android.csuite.core.AppCrawlTesterOptions" >
+        <option name="subject-package-name" value="{package}"/>
     </target_preparer>
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer" />
     <test class="com.android.tradefed.testtype.HostTest" >
-        <option name="set-option" value="package-name:{package}"/>
         <option name="class" value="com.android.csuite.tests.AppCrawlTest" />
     </test>
 </configuration>
\ No newline at end of file
diff --git a/test_targets/csuite-app-crawl/ui-automator-crawl.xml b/test_targets/csuite-app-crawl/ui-automator-crawl.xml
index 8d912e6..39e5034 100644
--- a/test_targets/csuite-app-crawl/ui-automator-crawl.xml
+++ b/test_targets/csuite-app-crawl/ui-automator-crawl.xml
@@ -14,19 +14,14 @@
      limitations under the License.
 -->
 <configuration description="C-Suite Crawler test configuration">
-    <object type="APP_CRAWL_TESTER_OPTIONS" class="com.android.csuite.core.AppCrawlTesterOptions" >
-        <option name="install-apk" value="app://{package}"/>
-        <option name="install-arg" value="-g"/>
-        <option name="ui-automator-mode" value="true"/>
-    </object>
-    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
-    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
-        <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
-        <option name="run-command" value="input keyevent KEYCODE_MENU"/>
-        <option name="run-command" value="input keyevent KEYCODE_HOME"/>
+    <target_preparer class="com.android.csuite.core.AppCrawlTesterOptions" >
+        <option name="subject-package-name" value="{package}"/>
+        <option name="subject-apk-path" value="app://{package}"/>
+        <option name="subject-apk-install-arg" value="-g"/>
     </target_preparer>
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer" />
     <test class="com.android.tradefed.testtype.HostTest" >
-        <option name="set-option" value="package-name:{package}"/>
         <option name="class" value="com.android.csuite.tests.AppCrawlTest" />
     </test>
 </configuration>
\ No newline at end of file
diff --git a/test_targets/csuite-app-launch-metric-collection/Android.bp b/test_targets/csuite-app-launch-metric-collection/Android.bp
new file mode 100644
index 0000000..ceae9d8
--- /dev/null
+++ b/test_targets/csuite-app-launch-metric-collection/Android.bp
@@ -0,0 +1,24 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_app_compat",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+csuite_test {
+    name: "csuite-app-launch-metric-collection",
+    test_config_template: "default-launch.xml",
+    extra_test_config_templates: ["pre-installed-launch.xml"],
+}
diff --git a/test_targets/csuite-app-launch-metric-collection/OWNERS b/test_targets/csuite-app-launch-metric-collection/OWNERS
new file mode 100644
index 0000000..0cfab1d
--- /dev/null
+++ b/test_targets/csuite-app-launch-metric-collection/OWNERS
@@ -0,0 +1,3 @@
+jelenacvetic@google.com
+mattlui@google.com
+ppawel@google.com
\ No newline at end of file
diff --git a/test_targets/csuite-app-launch-metric-collection/default-launch.xml b/test_targets/csuite-app-launch-metric-collection/default-launch.xml
new file mode 100644
index 0000000..158fe89
--- /dev/null
+++ b/test_targets/csuite-app-launch-metric-collection/default-launch.xml
@@ -0,0 +1,53 @@
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
+<configuration description="Launches an app and check for crashes while collecting metrics">
+    <target_preparer class="com.android.compatibility.targetprep.CheckGmsPreparer"/>
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
+        <option name="run-command" value="input keyevent KEYCODE_MENU"/>
+        <option name="run-command" value="input keyevent KEYCODE_HOME"/>
+    </target_preparer>
+
+    <test class="com.android.tradefed.testtype.HostTest" >
+        <option name="set-option" value="package-name:{package}"/>
+        <option name="set-option" value="install-apk:app\://{package}"/>
+        <option name="set-option" value="install-arg:-g"/>
+        <option name="class" value="com.android.csuite.tests.AppLaunchTest" />
+    </test>
+
+    <option name="config-descriptor:metadata" key="test-type" value="performance" />
+
+    <metrics_collector class="com.android.tradefed.device.metric.DeviceTraceCollector">
+        <option name="trace-config-file" value="trace_config.textproto"/>
+        <option name="per-run" value="false"/>
+    </metrics_collector>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.MetricFilePostProcessor"/>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoGenericPostProcessor">
+        <option name="perfetto-proto-file-prefix" value="metric_device-trace"/>
+        <option name="perfetto-indexed-list-field" value="perfetto.protos.AndroidStartupMetric.startup" />
+        <option name="perfetto-prefix-key-field" value="perfetto.protos.AndroidStartupMetric.Startup.process_name" />
+        <option name="perfetto-metric-filter-regex" value="android_startup-startup-.*process_name-.*startup_type.*-to_first_frame-dur_ms"/>
+    </metric_post_processor>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoTracePostProcessor">
+        <option name="perfetto-trace-file-regex" value="device-trace.*"/>
+        <option name="trace-processor-run-metrics" value="android_startup"/>
+        <option name="trace-processor-binary" value="gs://tradefed_crystalball/trace_processor_lab_version/Feb-27-2025/trace_processor_shell"/>
+    </metric_post_processor>
+</configuration>
\ No newline at end of file
diff --git a/test_targets/csuite-app-launch-metric-collection/pre-installed-launch.xml b/test_targets/csuite-app-launch-metric-collection/pre-installed-launch.xml
new file mode 100644
index 0000000..6e49401
--- /dev/null
+++ b/test_targets/csuite-app-launch-metric-collection/pre-installed-launch.xml
@@ -0,0 +1,49 @@
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
+<configuration description="Launches an app that exists on the device and check for crashes while collecting metrics">
+    <target_preparer class="com.android.compatibility.targetprep.CheckGmsPreparer"/>
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
+        <option name="run-command" value="input keyevent KEYCODE_MENU"/>
+        <option name="run-command" value="input keyevent KEYCODE_HOME"/>
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.HostTest" >
+        <option name="set-option" value="package-name:{package}"/>
+        <option name="class" value="com.android.csuite.tests.AppLaunchTest" />
+    </test>
+
+    <option name="config-descriptor:metadata" key="test-type" value="performance" />
+    <metrics_collector class="com.android.tradefed.device.metric.DeviceTraceCollector">
+        <option name="trace-config-file" value="trace_config.textproto"/>
+        <option name="per-run" value="false"/>
+    </metrics_collector>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.MetricFilePostProcessor"/>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoGenericPostProcessor">
+        <option name="perfetto-proto-file-prefix" value="metric_device-trace"/>
+        <option name="perfetto-indexed-list-field" value="perfetto.protos.AndroidStartupMetric.startup" />
+        <option name="perfetto-prefix-key-field" value="perfetto.protos.AndroidStartupMetric.Startup.process_name" />
+        <option name="perfetto-metric-filter-regex" value="android_startup-startup-.*process_name-.*startup_type.*-to_first_frame-dur_ms"/>
+    </metric_post_processor>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoTracePostProcessor">
+        <option name="perfetto-trace-file-regex" value="device-trace.*"/>
+        <option name="trace-processor-run-metrics" value="android_startup"/>
+        <option name="trace-processor-binary" value="gs://tradefed_crystalball/trace_processor_lab_version/Feb-27-2025/trace_processor_shell"/>
+    </metric_post_processor>
+</configuration>
\ No newline at end of file
diff --git a/test_targets/csuite-warm-app-launch/Android.bp b/test_targets/csuite-warm-app-launch/Android.bp
new file mode 100644
index 0000000..bf2e4ed
--- /dev/null
+++ b/test_targets/csuite-warm-app-launch/Android.bp
@@ -0,0 +1,24 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_app_compat",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+csuite_test {
+    name: "csuite-warm-app-launch-metric-collection",
+    test_config_template: "default-launch.xml",
+    extra_test_config_templates: ["pre-installed-launch.xml"],
+}
diff --git a/test_targets/csuite-warm-app-launch/OWNERS b/test_targets/csuite-warm-app-launch/OWNERS
new file mode 100644
index 0000000..0cfab1d
--- /dev/null
+++ b/test_targets/csuite-warm-app-launch/OWNERS
@@ -0,0 +1,3 @@
+jelenacvetic@google.com
+mattlui@google.com
+ppawel@google.com
\ No newline at end of file
diff --git a/test_targets/csuite-warm-app-launch/default-launch.xml b/test_targets/csuite-warm-app-launch/default-launch.xml
new file mode 100644
index 0000000..301423a
--- /dev/null
+++ b/test_targets/csuite-warm-app-launch/default-launch.xml
@@ -0,0 +1,53 @@
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
+<configuration description="Warm launches an app and check for crashes while collecting perfetto traces">
+    <target_preparer class="com.android.compatibility.targetprep.CheckGmsPreparer"/>
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
+        <option name="run-command" value="input keyevent KEYCODE_MENU"/>
+        <option name="run-command" value="input keyevent KEYCODE_HOME"/>
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.HostTest" >
+        <option name="set-option" value="package-name:{package}"/>
+        <option name="set-option" value="install-apk:app\://{package}"/>
+        <option name="set-option" value="install-arg:-g"/>
+        <option name="set-option" value="warm-app-launch-count:9"/>
+        <option name="class" value="com.android.csuite.tests.WarmAppLaunchTest" />
+    </test>
+
+    <option name="config-descriptor:metadata" key="test-type" value="performance" />
+
+    <metrics_collector class="com.android.tradefed.device.metric.DeviceTraceCollector">
+        <option name="trace-config-file" value="trace_config.textproto"/>
+        <option name="per-run" value="false"/>
+    </metrics_collector>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.MetricFilePostProcessor"/>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoGenericPostProcessor">
+        <option name="perfetto-proto-file-prefix" value="metric_device-trace"/>
+        <option name="perfetto-indexed-list-field" value="perfetto.protos.AndroidStartupMetric.startup" />
+        <option name="perfetto-prefix-key-field" value="perfetto.protos.AndroidStartupMetric.Startup.process_name" />
+        <option name="perfetto-metric-filter-regex" value="android_startup-startup-.*process_name-.*startup_type.*-to_first_frame-dur_ms"/>
+    </metric_post_processor>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoTracePostProcessor">
+        <option name="perfetto-trace-file-regex" value="device-trace.*"/>
+        <option name="trace-processor-run-metrics" value="android_startup"/>
+        <option name="trace-processor-binary" value="gs://tradefed_crystalball/trace_processor_lab_version/Feb-27-2025/trace_processor_shell"/>
+    </metric_post_processor>
+</configuration>
\ No newline at end of file
diff --git a/test_targets/csuite-warm-app-launch/pre-installed-launch.xml b/test_targets/csuite-warm-app-launch/pre-installed-launch.xml
new file mode 100644
index 0000000..65086ca
--- /dev/null
+++ b/test_targets/csuite-warm-app-launch/pre-installed-launch.xml
@@ -0,0 +1,50 @@
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
+<configuration description="Warm launches an app that exists on the device and check for crashes while collecting perfetto traces">
+    <target_preparer class="com.android.compatibility.targetprep.CheckGmsPreparer"/>
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
+        <option name="run-command" value="input keyevent KEYCODE_MENU"/>
+        <option name="run-command" value="input keyevent KEYCODE_HOME"/>
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.HostTest" >
+        <option name="set-option" value="package-name:{package}"/>
+        <option name="set-option" value="warm-app-launch-count:9"/>
+        <option name="class" value="com.android.csuite.tests.WarmAppLaunchTest" />
+    </test>
+
+    <option name="config-descriptor:metadata" key="test-type" value="performance" />
+    <metrics_collector class="com.android.tradefed.device.metric.DeviceTraceCollector">
+        <option name="trace-config-file" value="trace_config.textproto"/>
+        <option name="per-run" value="false"/>
+    </metrics_collector>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.MetricFilePostProcessor"/>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoGenericPostProcessor">
+        <option name="perfetto-proto-file-prefix" value="metric_device-trace"/>
+        <option name="perfetto-indexed-list-field" value="perfetto.protos.AndroidStartupMetric.startup" />
+        <option name="perfetto-prefix-key-field" value="perfetto.protos.AndroidStartupMetric.Startup.process_name" />
+        <option name="perfetto-metric-filter-regex" value="android_startup-startup-.*process_name-.*startup_type.*-to_first_frame-dur_ms"/>
+    </metric_post_processor>
+
+    <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoTracePostProcessor">
+        <option name="perfetto-trace-file-regex" value="device-trace.*"/>
+        <option name="trace-processor-run-metrics" value="android_startup"/>
+        <option name="trace-processor-binary" value="gs://tradefed_crystalball/trace_processor_lab_version/Feb-27-2025/trace_processor_shell"/>
+    </metric_post_processor>
+</configuration>
\ No newline at end of file
diff --git a/test_targets/webview-app-crawl/plan.xml b/test_targets/webview-app-crawl/plan.xml
index 1a96800..7629fe3 100644
--- a/test_targets/webview-app-crawl/plan.xml
+++ b/test_targets/webview-app-crawl/plan.xml
@@ -15,5 +15,4 @@
 -->
 <configuration description="WebView C-Suite Crawler Test Plan">
   <target_preparer class="com.android.webview.lib.WebviewInstallerToolPreparer"/>
-  <target_preparer class="com.android.csuite.core.AppCrawlTesterHostPreparer"/>
 </configuration>
diff --git a/test_targets/webview-app-crawl/ui-automator-mode.xml b/test_targets/webview-app-crawl/ui-automator-mode.xml
index b1d50dc..dd0437b 100644
--- a/test_targets/webview-app-crawl/ui-automator-mode.xml
+++ b/test_targets/webview-app-crawl/ui-automator-mode.xml
@@ -14,18 +14,14 @@
      limitations under the License.
 -->
 <configuration description="Crawl's an app after installing WebView">
-    <object type="APP_CRAWL_TESTER_OPTIONS" class="com.android.csuite.core.AppCrawlTesterOptions" >
-        <option name="install-apk" value="app://{package}"/>
-        <option name="install-arg" value="-g"/>
-        <option name="ui-automator-mode" value="true"/>
-    </object>
+    <target_preparer class="com.android.csuite.core.AppCrawlTesterOptions" >
+        <option name="subject-package-name" value="{package}"/>
+        <option name="subject-apk-path" value="app://{package}"/>
+        <option name="subject-apk-install-arg" value="-g"/>
+    </target_preparer>
     <target_preparer class="com.android.compatibility.targetprep.CheckGmsPreparer"/>
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
-    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
-        <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
-        <option name="run-command" value="input keyevent KEYCODE_MENU"/>
-        <option name="run-command" value="input keyevent KEYCODE_HOME"/>
-    </target_preparer>
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer" />
     <test class="com.android.tradefed.testtype.HostTest" >
         <option name="set-option" value="package-name:{package}"/>
         <option name="class" value="com.android.webview.tests.WebviewAppCrawlTest" />
```

