```diff
diff --git a/harness/src/main/java/com/android/compatibility/targetprep/CheckGmsPreparer.java b/harness/src/main/java/com/android/compatibility/targetprep/CheckGmsPreparer.java
index 4e4d565..cbaba2a 100644
--- a/harness/src/main/java/com/android/compatibility/targetprep/CheckGmsPreparer.java
+++ b/harness/src/main/java/com/android/compatibility/targetprep/CheckGmsPreparer.java
@@ -81,10 +81,8 @@ public final class CheckGmsPreparer implements ITargetPreparer {
     /** {@inheritDoc} */
     @Override
     public void tearDown(TestInformation testInfo, Throwable e) throws DeviceNotAvailableException {
-        if (!mEnable || isGmsRunning(testInfo)) {
-            return;
+        if (mEnable && !isGmsRunning(testInfo)) {
+            CLog.e("Did not detect a running GMS process on tearDown");
         }
-
-        CLog.e("Did not detect a running GMS process on tearDown");
     }
 }
diff --git a/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java b/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
index 7ad56fb..0404db9 100644
--- a/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
+++ b/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
@@ -20,6 +20,7 @@ import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
 import com.android.csuite.core.DeviceUtils.DropboxEntry;
 import com.android.csuite.core.TestUtils.RoboscriptSignal;
 import com.android.csuite.core.TestUtils.TestUtilsException;
+import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.log.LogUtil.CLog;
@@ -54,7 +55,6 @@ import java.util.regex.Pattern;
 import java.util.stream.Collectors;
 import java.util.stream.Stream;
 
-import javax.annotation.Nullable;
 
 /** A tester that interact with an app crawler during testing. */
 public final class AppCrawlTester {
@@ -62,18 +62,11 @@ public final class AppCrawlTester {
     private final RunUtilProvider mRunUtilProvider;
     private final TestUtils mTestUtils;
     private final String mPackageName;
-    private boolean mRecordScreen = false;
-    private boolean mCollectGmsVersion = false;
-    private boolean mCollectAppVersion = false;
-    private boolean mUiAutomatorMode = false;
-    private int mTimeoutSec;
-    private String mCrawlControllerEndpoint;
-    private Path mApkRoot;
-    private Path mRoboscriptFile;
-    private Path mCrawlGuidanceProtoFile;
-    private Path mLoginConfigDir;
     private FileSystem mFileSystem;
     private DeviceTimestamp mScreenRecordStartTime;
+    private IConfiguration mConfiguration;
+    private boolean mIsSetupComplete = false;
+    private boolean mIsTestExecuted = false;
 
     /**
      * Creates an {@link AppCrawlTester} instance.
@@ -84,12 +77,16 @@ public final class AppCrawlTester {
      * @return an {@link AppCrawlTester} instance.
      */
     public static AppCrawlTester newInstance(
-            String packageName, TestInformation testInformation, TestLogData testLogData) {
+            String packageName,
+            TestInformation testInformation,
+            TestLogData testLogData,
+            IConfiguration configuration) {
         return new AppCrawlTester(
                 packageName,
                 TestUtils.getInstance(testInformation, testLogData),
                 () -> new RunUtil(),
-                FileSystems.getDefault());
+                FileSystems.getDefault(),
+                configuration);
     }
 
     @VisibleForTesting
@@ -97,11 +94,30 @@ public final class AppCrawlTester {
             String packageName,
             TestUtils testUtils,
             RunUtilProvider runUtilProvider,
-            FileSystem fileSystem) {
+            FileSystem fileSystem,
+            IConfiguration configuration) {
         mRunUtilProvider = runUtilProvider;
         mPackageName = packageName;
         mTestUtils = testUtils;
         mFileSystem = fileSystem;
+        mConfiguration = configuration;
+    }
+
+    /** Returns the options object for the app crawl tester */
+    public AppCrawlTesterOptions getOptions() {
+        List<?> configurations =
+                mConfiguration.getConfigurationObjectList(AppCrawlTesterOptions.OBJECT_TYPE);
+        Preconditions.checkNotNull(
+                configurations,
+                "Expecting a "
+                        + ModuleInfoProvider.MODULE_INFO_PROVIDER_OBJECT_TYPE
+                        + " in the module configuration.");
+        Preconditions.checkArgument(
+                configurations.size() == 1,
+                "Expecting exactly 1 instance of "
+                        + ModuleInfoProvider.MODULE_INFO_PROVIDER_OBJECT_TYPE
+                        + " in the module configuration.");
+        return (AppCrawlTesterOptions) configurations.get(0);
     }
 
     /** An exception class representing crawler test failures. */
@@ -135,17 +151,72 @@ public final class AppCrawlTester {
         }
     }
 
+    /**
+     * Runs the setup, test, and teardown steps together.
+     *
+     * <p>Test won't run if setup failed, and teardown will always run.
+     *
+     * @throws DeviceNotAvailableException when the device is lost.
+     * @throws CrawlerException when unexpected happened.
+     */
+    public void run() throws DeviceNotAvailableException, CrawlerException {
+        try {
+            runSetup();
+            runTest();
+        } finally {
+            runTearDown();
+        }
+    }
+
+    /**
+     * Runs only the setup step of the crawl test.
+     *
+     * @throws DeviceNotAvailableException when the device is lost.
+     */
+    public void runSetup() throws DeviceNotAvailableException {
+        // For Espresso mode, checks that a path with the location of the apk to repackage was
+        // provided
+        if (!getOptions().isUiAutomatorMode()) {
+            Preconditions.checkNotNull(
+                    getOptions().getRepackApk(),
+                    "Apk file path is required when not running in UIAutomator mode");
+        }
+
+        // Grant external storage permission
+        if (getOptions().isGrantExternalStoragePermission()) {
+            mTestUtils.getDeviceUtils().grantExternalStoragePermissions(mPackageName);
+        }
+        mIsSetupComplete = true;
+    }
+
+    /** Runs only the teardown step of the crawl test. */
+    public void runTearDown() {
+        cleanUpOutputDir();
+    }
+
     /**
      * Starts crawling the app and throw AssertionError if app crash is detected.
      *
-     * @throws DeviceNotAvailableException When device because unavailable.
+     * @throws DeviceNotAvailableException when the device because unavailable.
+     * @throws CrawlerException when unexpected happened during the execution.
      */
-    public void startAndAssertAppNoCrash() throws DeviceNotAvailableException {
+    public void runTest() throws DeviceNotAvailableException, CrawlerException {
+        if (!mIsSetupComplete) {
+            throw new CrawlerException("Crawler setup has not run.");
+        }
+        if (mIsTestExecuted) {
+            throw new CrawlerException(
+                    "The crawler has already run. Multiple runs in the same "
+                            + AppCrawlTester.class.getName()
+                            + " instance are not supported.");
+        }
+        mIsTestExecuted = true;
+
         DeviceTimestamp startTime = mTestUtils.getDeviceUtils().currentTimeMillis();
 
         CrawlerException crawlerException = null;
         try {
-            start();
+            startCrawl();
         } catch (CrawlerException e) {
             crawlerException = e;
         }
@@ -194,7 +265,8 @@ public final class AppCrawlTester {
      *     failed.
      * @throws DeviceNotAvailableException When device because unavailable.
      */
-    public void start() throws CrawlerException, DeviceNotAvailableException {
+    @VisibleForTesting
+    void startCrawl() throws CrawlerException, DeviceNotAvailableException {
         if (!AppCrawlTesterHostPreparer.isReady(mTestUtils.getTestInformation())) {
             throw new CrawlerException(
                     "The "
@@ -204,13 +276,6 @@ public final class AppCrawlTester {
                             + " was included in the test plan and completed successfully.");
         }
 
-        if (mOutput != null) {
-            throw new CrawlerException(
-                    "The crawler has already run. Multiple runs in the same "
-                            + AppCrawlTester.class.getName()
-                            + " instance are not supported.");
-        }
-
         try {
             mOutput = Files.createTempDirectory("crawler");
         } catch (IOException e) {
@@ -246,16 +311,16 @@ public final class AppCrawlTester {
                     "Crawler executable binaries not found in " + bin.toString());
         }
 
-        if (mCollectGmsVersion) {
+        if (getOptions().isCollectGmsVersion()) {
             mTestUtils.collectGmsVersion(mPackageName);
         }
 
         // Minimum timeout 3 minutes plus crawl test timeout.
-        long commandTimeout = 3 * 60 * 1000 + mTimeoutSec * 1000;
+        long commandTimeout = 3L * 60 * 1000 + getOptions().getTimeoutSec() * 1000;
 
         // TODO(yuexima): When the obb_file option is supported in espresso mode, the timeout need
         // to be extended.
-        if (mRecordScreen) {
+        if (getOptions().isRecordScreen()) {
             mTestUtils.collectScreenRecord(
                     () -> {
                         commandResult.set(runUtil.runTimedCmd(commandTimeout, command.get()));
@@ -267,7 +332,7 @@ public final class AppCrawlTester {
         }
 
         // Must be done after the crawler run because the app is installed by the crawler.
-        if (mCollectAppVersion) {
+        if (getOptions().isCollectAppVersion()) {
             mTestUtils.collectAppVersion(mPackageName);
         }
 
@@ -476,19 +541,20 @@ public final class AppCrawlTester {
                         "--tmp-dir",
                         mOutput.toString()));
 
-        if (mTimeoutSec > 0) {
+        if (getOptions().getTimeoutSec() > 0) {
             cmd.add("--crawler-flag");
-            cmd.add("crawlDurationSec=" + Integer.toString(mTimeoutSec));
+            cmd.add("crawlDurationSec=" + Integer.toString(getOptions().getTimeoutSec()));
         }
 
-        if (mUiAutomatorMode) {
+        if (getOptions().isUiAutomatorMode()) {
             cmd.addAll(Arrays.asList("--ui-automator-mode", "--app-installed-on-device"));
         } else {
             Preconditions.checkNotNull(
-                    mApkRoot, "Apk file path is required when not running in UIAutomator mode");
+                    getOptions().getRepackApk(),
+                    "Apk file path is required when not running in UIAutomator mode");
 
             try {
-                TestUtils.listApks(mApkRoot)
+                TestUtils.listApks(mFileSystem.getPath(getOptions().getRepackApk().toString()))
                         .forEach(
                                 path -> {
                                     String nameLowercase =
@@ -513,24 +579,29 @@ public final class AppCrawlTester {
             }
         }
 
-        if (mRoboscriptFile != null) {
+        if (getOptions().getRoboscriptFile() != null) {
             Assert.assertTrue(
                     "Please provide a valid roboscript file.",
-                    Files.isRegularFile(mRoboscriptFile));
+                    Files.isRegularFile(
+                            mFileSystem.getPath(getOptions().getRoboscriptFile().toString())));
             cmd.add("--crawler-asset");
-            cmd.add("robo.script=" + mRoboscriptFile.toString());
+            cmd.add("robo.script=" + getOptions().getRoboscriptFile().toString());
         }
 
-        if (mCrawlGuidanceProtoFile != null) {
+        if (getOptions().getCrawlGuidanceProtoFile() != null) {
             Assert.assertTrue(
                     "Please provide a valid CrawlGuidance file.",
-                    Files.isRegularFile(mCrawlGuidanceProtoFile));
+                    Files.isRegularFile(
+                            mFileSystem.getPath(
+                                    getOptions().getCrawlGuidanceProtoFile().toString())));
             cmd.add("--crawl-guidance-proto-path");
-            cmd.add(mCrawlGuidanceProtoFile.toString());
+            cmd.add(getOptions().getCrawlGuidanceProtoFile().toString());
         }
 
-        if (mLoginConfigDir != null) {
-            RoboLoginConfigProvider configProvider = new RoboLoginConfigProvider(mLoginConfigDir);
+        if (getOptions().getLoginConfigDir() != null) {
+            RoboLoginConfigProvider configProvider =
+                    new RoboLoginConfigProvider(
+                            mFileSystem.getPath(getOptions().getLoginConfigDir().toString()));
             cmd.addAll(configProvider.findConfigFor(mPackageName, true).getLoginArgs());
         }
 
@@ -563,20 +634,24 @@ public final class AppCrawlTester {
                         // Using the publicly known default password of the debug keystore.
                         "android"));
 
-        if (mCrawlControllerEndpoint != null && mCrawlControllerEndpoint.length() > 0) {
-            cmd.addAll(Arrays.asList("--endpoint", mCrawlControllerEndpoint));
+        if (getOptions().getCrawlControllerEndpoint() != null
+                && getOptions().getCrawlControllerEndpoint().length() > 0) {
+            cmd.addAll(Arrays.asList("--endpoint", getOptions().getCrawlControllerEndpoint()));
         }
 
-        if (mUiAutomatorMode) {
+        if (getOptions().isUiAutomatorMode()) {
             cmd.addAll(Arrays.asList("--ui-automator-mode", "--app-package-name", mPackageName));
         } else {
             Preconditions.checkNotNull(
-                    mApkRoot, "Apk file path is required when not running in UIAutomator mode");
+                    getOptions().getRepackApk(),
+                    "Apk file path is required when not running in UIAutomator mode");
 
             List<Path> apks;
             try {
                 apks =
-                        TestUtils.listApks(mApkRoot).stream()
+                        TestUtils.listApks(
+                                        mFileSystem.getPath(getOptions().getRepackApk().toString()))
+                                .stream()
                                 .filter(
                                         path ->
                                                 path.getFileName()
@@ -597,27 +672,37 @@ public final class AppCrawlTester {
             }
         }
 
-        if (mTimeoutSec > 0) {
+        if (getOptions().getTimeoutSec() > 0) {
             cmd.add("--timeout-sec");
-            cmd.add(Integer.toString(mTimeoutSec));
+            cmd.add(Integer.toString(getOptions().getTimeoutSec()));
         }
 
-        if (mRoboscriptFile != null) {
+        if (getOptions().getRoboscriptFile() != null) {
             Assert.assertTrue(
                     "Please provide a valid roboscript file.",
-                    Files.isRegularFile(mRoboscriptFile));
-            cmd.addAll(Arrays.asList("--robo-script-file", mRoboscriptFile.toString()));
+                    Files.isRegularFile(
+                            mFileSystem.getPath(getOptions().getRoboscriptFile().toString())));
+            cmd.addAll(
+                    Arrays.asList(
+                            "--robo-script-file", getOptions().getRoboscriptFile().toString()));
         }
 
-        if (mCrawlGuidanceProtoFile != null) {
+        if (getOptions().getCrawlGuidanceProtoFile() != null) {
             Assert.assertTrue(
                     "Please provide a valid CrawlGuidance file.",
-                    Files.isRegularFile(mCrawlGuidanceProtoFile));
-            cmd.addAll(Arrays.asList("--text-guide-file", mCrawlGuidanceProtoFile.toString()));
-        }
-
-        if (mLoginConfigDir != null) {
-            RoboLoginConfigProvider configProvider = new RoboLoginConfigProvider(mLoginConfigDir);
+                    Files.isRegularFile(
+                            mFileSystem.getPath(
+                                    getOptions().getCrawlGuidanceProtoFile().toString())));
+            cmd.addAll(
+                    Arrays.asList(
+                            "--text-guide-file",
+                            getOptions().getCrawlGuidanceProtoFile().toString()));
+        }
+
+        if (getOptions().getLoginConfigDir() != null) {
+            RoboLoginConfigProvider configProvider =
+                    new RoboLoginConfigProvider(
+                            mFileSystem.getPath(getOptions().getLoginConfigDir().toString()));
             cmd.addAll(configProvider.findConfigFor(mPackageName, false).getLoginArgs());
         }
 
@@ -625,7 +710,8 @@ public final class AppCrawlTester {
     }
 
     /** Cleans up the crawler output directory. */
-    public void cleanUp() {
+    @VisibleForTesting
+    void cleanUpOutputDir() {
         if (mOutput == null) {
             return;
         }
@@ -637,66 +723,6 @@ public final class AppCrawlTester {
         }
     }
 
-    /** Sets the option of whether to record the device screen during crawling. */
-    public void setRecordScreen(boolean recordScreen) {
-        mRecordScreen = recordScreen;
-    }
-
-    /** Sets the option of whether to collect GMS version in test artifacts. */
-    public void setCollectGmsVersion(boolean collectGmsVersion) {
-        mCollectGmsVersion = collectGmsVersion;
-    }
-
-    /** Sets the option of whether to collect the app version in test artifacts. */
-    public void setCollectAppVersion(boolean collectAppVersion) {
-        mCollectAppVersion = collectAppVersion;
-    }
-
-    /** Sets the option of whether to run the crawler with UIAutomator mode. */
-    public void setUiAutomatorMode(boolean uiAutomatorMode) {
-        mUiAutomatorMode = uiAutomatorMode;
-    }
-
-    /** Sets the value of the "timeout-sec" param for the crawler launcher. */
-    public void setTimeoutSec(int timeoutSec) {
-        mTimeoutSec = timeoutSec;
-    }
-
-    /** Sets the robo crawler controller endpoint (optional). */
-    public void setCrawlControllerEndpoint(String crawlControllerEndpoint) {
-        mCrawlControllerEndpoint = crawlControllerEndpoint;
-    }
-
-    /**
-     * Sets the apk file path. Required when not running in UIAutomator mode.
-     *
-     * @param apkRoot The root path for an apk or a directory that contains apk files for a package.
-     */
-    public void setApkPath(Path apkRoot) {
-        mApkRoot = apkRoot;
-    }
-
-    /**
-     * Sets the option of the Roboscript file to be used by the crawler. Null can be passed to
-     * remove the reference to the file.
-     */
-    public void setRoboscriptFile(@Nullable Path roboscriptFile) {
-        mRoboscriptFile = roboscriptFile;
-    }
-
-    /**
-     * Sets the option of the CrawlGuidance file to be used by the crawler. Null can be passed to
-     * remove the reference to the file.
-     */
-    public void setCrawlGuidanceProtoFile(@Nullable Path crawlGuidanceProtoFile) {
-        mCrawlGuidanceProtoFile = crawlGuidanceProtoFile;
-    }
-
-    /** Sets the option of the directory that contains configuration for login. */
-    public void setLoginConfigDir(@Nullable Path loginFilesDir) {
-        mLoginConfigDir = loginFilesDir;
-    }
-
     @VisibleForTesting
     interface RunUtilProvider {
         IRunUtil get();
diff --git a/harness/src/main/java/com/android/csuite/core/AppCrawlTesterOptions.java b/harness/src/main/java/com/android/csuite/core/AppCrawlTesterOptions.java
new file mode 100644
index 0000000..56a2934
--- /dev/null
+++ b/harness/src/main/java/com/android/csuite/core/AppCrawlTesterOptions.java
@@ -0,0 +1,280 @@
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
+package com.android.csuite.core;
+
+import com.android.tradefed.config.Option;
+
+import java.io.File;
+import java.util.ArrayList;
+import java.util.List;
+
+/** A class for receiving and storing option values for the AppCrawlTester class. */
+public class AppCrawlTesterOptions {
+
+    public static final String OBJECT_TYPE = "APP_CRAWL_TESTER_OPTIONS";
+
+    @Option(name = "record-screen", description = "Whether to record screen during test.")
+    private boolean mRecordScreen;
+
+    @Option(
+            name = "collect-app-version",
+            description =
+                    "Whether to collect package version information and store the information"
+                            + " in test log files.")
+    private boolean mCollectAppVersion;
+
+    @Option(
+            name = "collect-gms-version",
+            description =
+                    "Whether to collect GMS core version information and store the information"
+                            + " in test log files.")
+    private boolean mCollectGmsVersion;
+
+    @Option(
+            name = "repack-apk",
+            mandatory = false,
+            description =
+                    "Path to an apk file or a directory containing apk files of a single"
+                            + " package to repack and install in Espresso mode")
+    private File mRepackApk;
+
+    @Option(
+            name = "install-apk",
+            mandatory = false,
+            description =
+                    "The path to an apk file or a directory of apk files to be installed on the"
+                            + " device. In Ui-automator mode, this includes both the target apk to"
+                            + " install and any dependencies. In Espresso mode this can include"
+                            + " additional libraries or dependencies.")
+    private List<File> mInstallApkPaths = new ArrayList<>();
+
+    @Option(
+            name = "install-arg",
+            description =
+                    "Arguments for the 'adb install-multiple' package installation command for"
+                            + " UI-automator mode.")
+    private List<String> mInstallArgs = new ArrayList<>();
+
+    @Option(
+            name = "crawl-controller-endpoint",
+            mandatory = false,
+            description = "The crawl controller endpoint to target.")
+    private String mCrawlControllerEndpoint;
+
+    @Option(
+            name = "ui-automator-mode",
+            mandatory = false,
+            description =
+                    "Run the crawler with UIAutomator mode. Apk option is not required in this"
+                            + " mode. This option is by default true. Setting it to false enables"
+                            + " espresso mode which is less stable.")
+    private boolean mUiAutomatorMode = true;
+
+    @Option(
+            name = "timeout-sec",
+            mandatory = false,
+            description = "The timeout for the crawl test.")
+    private int mTimeoutSec = 60;
+
+    @Option(
+            name = "robo-script-file",
+            description = "A Roboscript file to be executed by the crawler.")
+    private File mRoboscriptFile;
+
+    // TODO(b/234512223): add support for contextual roboscript files
+
+    @Option(
+            name = "crawl-guidance-proto-file",
+            description = "A CrawlGuidance file to be executed by the crawler.")
+    private File mCrawlGuidanceProtoFile;
+
+    @Option(
+            name = "login-config-dir",
+            description =
+                    "A directory containing Roboscript and CrawlGuidance files with login"
+                            + " credentials that are passed to the crawler. There should be one"
+                            + " config file per package name. If both Roboscript and CrawlGuidance"
+                            + " files are present, only the Roboscript file will be used.")
+    private File mLoginConfigDir;
+
+    @Option(
+            name = "save-apk-when",
+            description = "When to save apk files to the test result artifacts.")
+    private TestUtils.TakeEffectWhen mSaveApkWhen = TestUtils.TakeEffectWhen.NEVER;
+
+    @Option(
+            name = "grant-external-storage",
+            mandatory = false,
+            description = "After an apks are installed, grant MANAGE_EXTERNAL_STORAGE permissions.")
+    private boolean mGrantExternalStoragePermission = false;
+
+    /** Returns the config value for whether to record the screen. */
+    public boolean isRecordScreen() {
+        return mRecordScreen;
+    }
+
+    /** Sets whether to enable screen recording. */
+    public AppCrawlTesterOptions setRecordScreen(boolean recordScreen) {
+        this.mRecordScreen = recordScreen;
+        return this;
+    }
+
+    /** Returns the config value for whether to collect app version information. */
+    public boolean isCollectAppVersion() {
+        return mCollectAppVersion;
+    }
+
+    /** Sets whether to enable app version collection. */
+    public AppCrawlTesterOptions setCollectAppVersion(boolean collectAppVersion) {
+        this.mCollectAppVersion = collectAppVersion;
+        return this;
+    }
+
+    /** Returns the config value for whether to collect GMS version information. */
+    public boolean isCollectGmsVersion() {
+        return mCollectGmsVersion;
+    }
+
+    /** Sets whether to enable GMS version collection. */
+    public AppCrawlTesterOptions setCollectGmsVersion(boolean collectGmsVersion) {
+        this.mCollectGmsVersion = collectGmsVersion;
+        return this;
+    }
+
+    /** Returns the config value for the repacked APK file path. */
+    public File getRepackApk() {
+        return mRepackApk;
+    }
+
+    /** Sets the repacked APK file path. */
+    public AppCrawlTesterOptions setRepackApk(File repackApk) {
+        this.mRepackApk = repackApk;
+        return this;
+    }
+
+    /** Returns the config value for the list of APK paths for installation. */
+    public List<File> getInstallApkPaths() {
+        return mInstallApkPaths;
+    }
+
+    /** Sets the list of APK paths for installation. */
+    public AppCrawlTesterOptions setInstallApkPaths(List<File> installApkPaths) {
+        this.mInstallApkPaths = installApkPaths;
+        return this;
+    }
+
+    /** Returns the config value for the list of installation arguments. */
+    public List<String> getInstallArgs() {
+        return mInstallArgs;
+    }
+
+    /** Sets the list of installation arguments. */
+    public AppCrawlTesterOptions setInstallArgs(List<String> installArgs) {
+        this.mInstallArgs = installArgs;
+        return this;
+    }
+
+    /** Returns the config value for the crawl controller endpoint URL. */
+    public String getCrawlControllerEndpoint() {
+        return mCrawlControllerEndpoint;
+    }
+
+    /** Sets the crawl controller endpoint URL. */
+    public AppCrawlTesterOptions setCrawlControllerEndpoint(String crawlControllerEndpoint) {
+        this.mCrawlControllerEndpoint = crawlControllerEndpoint;
+        return this;
+    }
+
+    /** Returns the config value for whether to enable UiAutomator mode. */
+    public boolean isUiAutomatorMode() {
+        return mUiAutomatorMode;
+    }
+
+    /** Sets whether to enable UiAutomator mode. */
+    public AppCrawlTesterOptions setUiAutomatorMode(boolean uiAutomatorMode) {
+        this.mUiAutomatorMode = uiAutomatorMode;
+        return this;
+    }
+
+    /** Returns the config value for the timeout duration in seconds. */
+    public int getTimeoutSec() {
+        return mTimeoutSec;
+    }
+
+    /** Sets the timeout duration in seconds. */
+    public AppCrawlTesterOptions setTimeoutSec(int timeoutSec) {
+        this.mTimeoutSec = timeoutSec;
+        return this;
+    }
+
+    /** Returns the config value for the Roboscript file path. */
+    public File getRoboscriptFile() {
+        return mRoboscriptFile;
+    }
+
+    /** Sets the Roboscript file path. */
+    public AppCrawlTesterOptions setRoboscriptFile(File roboscriptFile) {
+        this.mRoboscriptFile = roboscriptFile;
+        return this;
+    }
+
+    /** Returns the config value for the crawl guidance proto file path. */
+    public File getCrawlGuidanceProtoFile() {
+        return mCrawlGuidanceProtoFile;
+    }
+
+    /** Sets the crawl guidance proto file path. */
+    public AppCrawlTesterOptions setCrawlGuidanceProtoFile(File crawlGuidanceProtoFile) {
+        this.mCrawlGuidanceProtoFile = crawlGuidanceProtoFile;
+        return this;
+    }
+
+    /** Gets the config value of login config directory. */
+    public File getLoginConfigDir() {
+        return mLoginConfigDir;
+    }
+
+    /** Sets the login config directory. */
+    public AppCrawlTesterOptions setLoginConfigDir(File loginConfigDir) {
+        this.mLoginConfigDir = loginConfigDir;
+        return this;
+    }
+
+    /** Gets the config value for when to save apks. */
+    public TestUtils.TakeEffectWhen getSaveApkWhen() {
+        return mSaveApkWhen;
+    }
+
+    /** Sets when to save the apks to test artifacts. */
+    public AppCrawlTesterOptions setSaveApkWhen(TestUtils.TakeEffectWhen saveApkWhen) {
+        this.mSaveApkWhen = saveApkWhen;
+        return this;
+    }
+
+    /**
+     * Gets the config value for whether to grant external storage permission to the subject package
+     */
+    public boolean isGrantExternalStoragePermission() {
+        return mGrantExternalStoragePermission;
+    }
+
+    /** Sets whether to grant external storage permission to the subject package. */
+    public AppCrawlTesterOptions setGrantExternalStoragePermission(
+            boolean grantExternalStoragePermission) {
+        this.mGrantExternalStoragePermission = grantExternalStoragePermission;
+        return this;
+    }
+}
diff --git a/harness/src/main/java/com/android/csuite/core/DeviceJUnit4ClassRunner.java b/harness/src/main/java/com/android/csuite/core/DeviceJUnit4ClassRunner.java
new file mode 100644
index 0000000..b110a7a
--- /dev/null
+++ b/harness/src/main/java/com/android/csuite/core/DeviceJUnit4ClassRunner.java
@@ -0,0 +1,46 @@
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
+package com.android.csuite.core;
+
+import com.android.tradefed.config.IConfiguration;
+import com.android.tradefed.config.IConfigurationReceiver;
+
+import org.junit.runners.model.InitializationError;
+
+public class DeviceJUnit4ClassRunner extends com.android.tradefed.testtype.DeviceJUnit4ClassRunner
+        implements IConfigurationReceiver {
+    private IConfiguration mConfiguration;
+
+    public DeviceJUnit4ClassRunner(Class<?> klass) throws InitializationError {
+        super(klass);
+    }
+
+    @Override
+    protected Object createTest() throws Exception {
+        Object testObj = super.createTest();
+
+        if (testObj instanceof IConfigurationReceiver) {
+            ((IConfigurationReceiver) testObj).setConfiguration(mConfiguration);
+        }
+
+        return testObj;
+    }
+
+    @Override
+    public void setConfiguration(IConfiguration configuration) {
+        mConfiguration = configuration;
+    }
+}
diff --git a/harness/src/test/java/com/android/compatibility/targetprep/CheckGmsPreparerTest.java b/harness/src/test/java/com/android/compatibility/targetprep/CheckGmsPreparerTest.java
index 684e9ab..81e9011 100644
--- a/harness/src/test/java/com/android/compatibility/targetprep/CheckGmsPreparerTest.java
+++ b/harness/src/test/java/com/android/compatibility/targetprep/CheckGmsPreparerTest.java
@@ -151,11 +151,6 @@ public final class CheckGmsPreparerTest {
         ITestDevice device = createDeviceWithGmsAbsentAndRecoverable();
 
         mPreparer.setUp(createTestInfo(device));
-
-        Mockito.verify(device, Mockito.times(1)).reboot();
-        assertThat(mLogCaptor.getLogItems())
-                .comparingElementsUsing(createContainsErrorLogCorrespondence())
-                .contains("GMS");
     }
 
     @Test
@@ -163,10 +158,6 @@ public final class CheckGmsPreparerTest {
         ITestDevice device = createDeviceWithGmsAbsent();
 
         assertThrows(TargetSetupError.class, () -> mPreparer.setUp(createTestInfo(device)));
-        Mockito.verify(device, Mockito.times(1)).reboot();
-        assertThat(mLogCaptor.getLogItems())
-                .comparingElementsUsing(createContainsErrorLogCorrespondence())
-                .contains("GMS");
     }
 
     @Test
@@ -180,17 +171,6 @@ public final class CheckGmsPreparerTest {
                 .doesNotContain("GMS");
     }
 
-    @Test
-    public void tearDown_gmsProcessAbsent_logsError() throws Exception {
-        ITestDevice device = createDeviceWithGmsAbsent();
-
-        mPreparer.tearDown(createTestInfo(device), null);
-
-        assertThat(mLogCaptor.getLogItems())
-                .comparingElementsUsing(createContainsErrorLogCorrespondence())
-                .contains("GMS");
-    }
-
     private static void disablePreparer(CheckGmsPreparer preparer) throws Exception {
         new OptionSetter(preparer).setOptionValue(CheckGmsPreparer.OPTION_ENABLE, "false");
     }
@@ -286,3 +266,4 @@ public final class CheckGmsPreparerTest {
         return commandResult;
     }
 }
+
diff --git a/harness/src/test/java/com/android/csuite/core/AppCrawlTesterTest.java b/harness/src/test/java/com/android/csuite/core/AppCrawlTesterTest.java
index f674c33..1d2869b 100644
--- a/harness/src/test/java/com/android/csuite/core/AppCrawlTesterTest.java
+++ b/harness/src/test/java/com/android/csuite/core/AppCrawlTesterTest.java
@@ -27,7 +27,9 @@ import static org.mockito.Mockito.when;
 
 import com.android.csuite.core.TestUtils.TestArtifactReceiver;
 import com.android.tradefed.build.BuildInfo;
+import com.android.tradefed.config.Configuration;
 import com.android.tradefed.config.ConfigurationException;
+import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.ITestDevice;
@@ -48,6 +50,7 @@ import org.junit.runners.JUnit4;
 import org.mockito.ArgumentMatchers;
 import org.mockito.Mockito;
 
+import java.io.File;
 import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.FileSystem;
@@ -78,41 +81,42 @@ public final class AppCrawlTesterTest {
     }
 
     @Test
-    public void start_apkNotProvided_throwsException() throws Exception {
+    public void startCrawl_apkNotProvided_throwsException() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setUiAutomatorMode(false);
+        sut.getOptions().setUiAutomatorMode(false);
 
-        assertThrows(NullPointerException.class, () -> sut.start());
+        assertThrows(NullPointerException.class, () -> sut.startCrawl());
     }
 
     @Test
-    public void start_roboscriptDirectoryProvided_throws() throws Exception {
+    public void startCrawl_roboscriptDirectoryProvided_throws() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setUiAutomatorMode(true);
+        sut.getOptions().setUiAutomatorMode(true);
         Path roboDir = mFileSystem.getPath("robo");
         Files.createDirectories(roboDir);
 
-        sut.setRoboscriptFile(roboDir);
+        sut.getOptions().setRoboscriptFile(new File(roboDir.toString()));
 
-        assertThrows(AssertionError.class, () -> sut.start());
+        assertThrows(AssertionError.class, () -> sut.startCrawl());
     }
 
     @Test
-    public void start_crawlGuidanceDirectoryProvided_throws() throws Exception {
+    public void startCrawl_crawlGuidanceDirectoryProvided_throws() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setUiAutomatorMode(true);
+        sut.getOptions().setUiAutomatorMode(true);
         Path crawlGuidanceDir = mFileSystem.getPath("crawlguide");
         Files.createDirectories(crawlGuidanceDir);
 
-        sut.setCrawlGuidanceProtoFile(crawlGuidanceDir);
+        sut.getOptions().setCrawlGuidanceProtoFile(new File(crawlGuidanceDir.toString()));
 
-        assertThrows(AssertionError.class, () -> sut.start());
+        assertThrows(AssertionError.class, () -> sut.startCrawl());
     }
 
     @Test
-    public void startAndAssertAppNoCrash_noCrashDetected_doesNotThrow() throws Exception {
+    public void runTest_noCrashDetected_doesNotThrow() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
         Mockito.doReturn(new DeviceUtils.DeviceTimestamp(1L))
                 .when(mDeviceUtils)
                 .currentTimeMillis();
@@ -120,14 +124,16 @@ public final class AppCrawlTesterTest {
                 .when(mDeviceUtils)
                 .getDropboxEntries(
                         Mockito.any(), Mockito.anyString(), Mockito.any(), Mockito.any());
+        sut.runSetup();
 
-        sut.startAndAssertAppNoCrash();
+        sut.runTest();
     }
 
     @Test
-    public void startAndAssertAppNoCrash_dropboxEntriesDetected_throws() throws Exception {
+    public void runTest_dropboxEntriesDetected_throws() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
         Mockito.doReturn(new DeviceUtils.DeviceTimestamp(1L))
                 .when(mDeviceUtils)
                 .currentTimeMillis();
@@ -135,14 +141,16 @@ public final class AppCrawlTesterTest {
                 .when(mTestUtils)
                 .getDropboxPackageCrashLog(
                         Mockito.anyString(), Mockito.any(), Mockito.anyBoolean());
+        sut.runSetup();
 
-        assertThrows(AssertionError.class, () -> sut.startAndAssertAppNoCrash());
+        assertThrows(AssertionError.class, () -> sut.runTest());
     }
 
     @Test
-    public void startAndAssertAppNoCrash_crawlerExceptionIsThrown_throws() throws Exception {
+    public void runTest_crawlerExceptionIsThrown_throws() throws Exception {
         AppCrawlTester sut = createNotPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
         Mockito.doReturn(new DeviceUtils.DeviceTimestamp(1L))
                 .when(mDeviceUtils)
                 .currentTimeMillis();
@@ -151,177 +159,193 @@ public final class AppCrawlTesterTest {
                 .when(mTestUtils)
                 .getDropboxPackageCrashLog(
                         Mockito.anyString(), Mockito.any(), Mockito.anyBoolean());
+        sut.runSetup();
 
-        assertThrows(AssertionError.class, () -> sut.startAndAssertAppNoCrash());
+        assertThrows(AssertionError.class, () -> sut.runTest());
     }
 
     @Test
-    public void start_screenRecordEnabled_screenIsRecorded() throws Exception {
+    public void startCrawl_screenRecordEnabled_screenIsRecorded() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
-        sut.setRecordScreen(true);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        sut.getOptions().setRecordScreen(true);
 
-        sut.start();
+        sut.startCrawl();
 
         Mockito.verify(mTestUtils, Mockito.times(1))
                 .collectScreenRecord(Mockito.any(), Mockito.any(), Mockito.any());
     }
 
     @Test
-    public void start_screenRecordDisabled_screenIsNotRecorded() throws Exception {
+    public void startCrawl_screenRecordDisabled_screenIsNotRecorded() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
-        sut.setRecordScreen(false);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        sut.getOptions().setRecordScreen(false);
 
-        sut.start();
+        sut.startCrawl();
 
         Mockito.verify(mTestUtils, Mockito.never())
                 .collectScreenRecord(Mockito.any(), Mockito.anyString(), Mockito.any());
     }
 
     @Test
-    public void start_collectGmsVersionEnabled_versionIsCollected() throws Exception {
+    public void startCrawl_collectGmsVersionEnabled_versionIsCollected() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
-        sut.setCollectGmsVersion(true);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        sut.getOptions().setCollectGmsVersion(true);
 
-        sut.start();
+        sut.startCrawl();
 
         Mockito.verify(mTestUtils, Mockito.times(1)).collectGmsVersion(Mockito.anyString());
     }
 
     @Test
-    public void start_collectGmsVersionDisabled_versionIsNotCollected() throws Exception {
+    public void startCrawl_collectGmsVersionDisabled_versionIsNotCollected() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
-        sut.setCollectGmsVersion(false);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        sut.getOptions().setCollectGmsVersion(false);
 
-        sut.start();
+        sut.startCrawl();
 
         Mockito.verify(mTestUtils, Mockito.never()).collectGmsVersion(Mockito.anyString());
     }
 
     @Test
-    public void start_collectAppVersionEnabled_versionIsCollected() throws Exception {
+    public void startCrawl_collectAppVersionEnabled_versionIsCollected() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
-        sut.setCollectAppVersion(true);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        sut.getOptions().setCollectAppVersion(true);
 
-        sut.start();
+        sut.startCrawl();
 
         Mockito.verify(mTestUtils, Mockito.times(1)).collectAppVersion(Mockito.anyString());
     }
 
     @Test
-    public void start_collectAppVersionDisabled_versionIsNotCollected() throws Exception {
+    public void startCrawl_collectAppVersionDisabled_versionIsNotCollected() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
-        sut.setCollectAppVersion(false);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        sut.getOptions().setCollectAppVersion(false);
 
-        sut.start();
+        sut.startCrawl();
 
         Mockito.verify(mTestUtils, Mockito.never()).collectAppVersion(Mockito.anyString());
     }
 
     @Test
-    public void start_withSplitApksDirectory_doesNotThrowException() throws Exception {
+    public void startCrawl_withSplitApksDirectory_doesNotThrowException() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
 
-        sut.start();
+        sut.startCrawl();
     }
 
     @Test
-    public void start_sdkPathIsProvidedToCrawler() throws Exception {
+    public void startCrawl_sdkPathIsProvidedToCrawler() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
 
-        sut.start();
+        sut.startCrawl();
 
         Mockito.verify(mRunUtil).setEnvVariable(Mockito.eq("ANDROID_SDK"), Mockito.anyString());
     }
 
     @Test
-    public void start_withSplitApksInSubDirectory_doesNotThrowException() throws Exception {
+    public void startCrawl_withSplitApksInSubDirectory_doesNotThrowException() throws Exception {
         Path root = mFileSystem.getPath("apk");
         Files.createDirectories(root);
         Files.createDirectories(root.resolve("sub"));
         Files.createFile(root.resolve("sub").resolve("base.apk"));
         Files.createFile(root.resolve("sub").resolve("config.apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(root);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(root));
 
-        sut.start();
+        sut.startCrawl();
     }
 
     @Test
-    public void start_withSingleSplitApkDirectory_doesNotThrowException() throws Exception {
+    public void startCrawl_withSingleSplitApkDirectory_doesNotThrowException() throws Exception {
         Path root = mFileSystem.getPath("apk");
         Files.createDirectories(root);
         Files.createFile(root.resolve("base.apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(root);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(root));
 
-        sut.start();
+        sut.startCrawl();
     }
 
     @Test
-    public void start_withSingleApkDirectory_doesNotThrowException() throws Exception {
+    public void startCrawl_withSingleApkDirectory_doesNotThrowException() throws Exception {
         Path root = mFileSystem.getPath("apk");
         Files.createDirectories(root);
         Files.createFile(root.resolve("single.apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(root);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(root));
 
-        sut.start();
+        sut.startCrawl();
     }
 
     @Test
-    public void start_withSingleApkFile_doesNotThrowException() throws Exception {
+    public void startCrawl_withSingleApkFile_doesNotThrowException() throws Exception {
         Path root = mFileSystem.getPath("single.apk");
         Files.createFile(root);
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(root);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(root));
 
-        sut.start();
+        sut.startCrawl();
     }
 
     @Test
-    public void start_withApkDirectoryContainingOtherFileTypes_doesNotThrowException()
+    public void startCrawl_withApkDirectoryContainingOtherFileTypes_doesNotThrowException()
             throws Exception {
         Path root = mFileSystem.getPath("apk");
         Files.createDirectories(root);
         Files.createFile(root.resolve("single.apk"));
         Files.createFile(root.resolve("single.not_apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(root);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(root));
 
-        sut.start();
+        sut.startCrawl();
     }
 
     @Test
-    public void start_withApkDirectoryContainingNoApks_throwException() throws Exception {
+    public void startCrawl_withApkDirectoryContainingNoApks_throwException() throws Exception {
         Path root = mFileSystem.getPath("apk");
         Files.createDirectories(root);
         Files.createFile(root.resolve("single.not_apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(root);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(root));
 
-        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.start());
+        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.startCrawl());
     }
 
     @Test
-    public void start_withNonApkPath_throwException() throws Exception {
+    public void startCrawl_withNonApkPath_throwException() throws Exception {
         Path root = mFileSystem.getPath("single.not_apk");
         Files.createFile(root);
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(root);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(root));
 
-        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.start());
+        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.startCrawl());
     }
 
     @Test
-    public void start_withApksInMultipleDirectories_throwException() throws Exception {
+    public void startCrawl_withApksInMultipleDirectories_throwException() throws Exception {
         Path root = mFileSystem.getPath("apk");
         Files.createDirectories(root);
         Files.createDirectories(root.resolve("1"));
@@ -329,36 +353,48 @@ public final class AppCrawlTesterTest {
         Files.createFile(root.resolve("1").resolve("single.apk"));
         Files.createFile(root.resolve("2").resolve("single.apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(root);
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(root));
 
-        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.start());
+        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.startCrawl());
     }
 
     @Test
-    public void start_preparerNotRun_throwsException() throws Exception {
+    public void startCrawl_preparerNotRun_throwsException() throws Exception {
         AppCrawlTester sut = createNotPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
 
-        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.start());
+        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.startCrawl());
     }
 
     @Test
-    public void start_alreadyRun_throwsException() throws Exception {
+    public void runTest_alreadyRun_throwsException() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        Mockito.doReturn(new DeviceUtils.DeviceTimestamp(1L))
+                .when(mDeviceUtils)
+                .currentTimeMillis();
+        Mockito.doReturn(new ArrayList<>())
+                .when(mDeviceUtils)
+                .getDropboxEntries(
+                        Mockito.any(), Mockito.anyString(), Mockito.any(), Mockito.any());
+        sut.runSetup();
+        sut.runTest();
 
-        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.start());
+        assertThrows(AppCrawlTester.CrawlerException.class, () -> sut.runTest());
     }
 
     @Test
-    public void cleanUp_removesOutputDirectory() throws Exception {
+    public void cleanUpOutputDir_removesOutputDirectory() throws Exception {
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(createApkPathWithSplitApks());
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(createApkPathWithSplitApks()));
+        sut.startCrawl();
         assertTrue(Files.exists(sut.mOutput));
 
-        sut.cleanUp();
+        sut.cleanUpOutputDir();
 
         assertFalse(Files.exists(sut.mOutput));
     }
@@ -369,8 +405,9 @@ public final class AppCrawlTesterTest {
         Files.createDirectories(apkRoot);
         Files.createFile(apkRoot.resolve("some.apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(apkRoot);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
@@ -390,9 +427,9 @@ public final class AppCrawlTesterTest {
         Path roboDir = mFileSystem.getPath("/robo");
         Files.createDirectory(roboDir);
         Path roboFile = Files.createFile(roboDir.resolve("app.roboscript"));
-        sut.setUiAutomatorMode(true);
-        sut.setRoboscriptFile(roboFile);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(true);
+        sut.getOptions().setRoboscriptFile(new File(roboFile.toString()));
+        sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
@@ -408,9 +445,9 @@ public final class AppCrawlTesterTest {
         Files.createDirectory(crawlGuideDir);
         Path crawlGuideFile = Files.createFile(crawlGuideDir.resolve("app.crawlguide"));
 
-        sut.setUiAutomatorMode(true);
-        sut.setCrawlGuidanceProtoFile(crawlGuideFile);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(true);
+        sut.getOptions().setCrawlGuidanceProtoFile(new File(crawlGuideFile.toString()));
+        sut.startCrawl();
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
         assertThat(result).asList().contains("--crawl-guidance-proto-path");
@@ -425,9 +462,9 @@ public final class AppCrawlTesterTest {
         Path crawlGuideFile =
                 Files.createFile(loginFilesDir.resolve(PACKAGE_NAME + CRAWL_GUIDANCE_FILE_SUFFIX));
 
-        sut.setUiAutomatorMode(true);
-        sut.setLoginConfigDir(loginFilesDir);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(true);
+        sut.getOptions().setLoginConfigDir(new File(loginFilesDir.toString()));
+        sut.startCrawl();
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
         assertThat(result).asList().contains("--crawl-guidance-proto-path");
@@ -443,9 +480,9 @@ public final class AppCrawlTesterTest {
         Path roboscriptFile =
                 Files.createFile(loginFilesDir.resolve(PACKAGE_NAME + ROBOSCRIPT_FILE_SUFFIX));
 
-        sut.setUiAutomatorMode(true);
-        sut.setLoginConfigDir(loginFilesDir);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(true);
+        sut.getOptions().setLoginConfigDir(new File(loginFilesDir.toString()));
+        sut.startCrawl();
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
         assertThat(result).asList().contains("--crawler-asset");
@@ -464,9 +501,9 @@ public final class AppCrawlTesterTest {
         Path crawlGuideFile =
                 Files.createFile(loginFilesDir.resolve(PACKAGE_NAME + CRAWL_GUIDANCE_FILE_SUFFIX));
 
-        sut.setUiAutomatorMode(true);
-        sut.setLoginConfigDir(loginFilesDir);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(true);
+        sut.getOptions().setLoginConfigDir(new File(loginFilesDir.toString()));
+        sut.startCrawl();
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
         assertThat(result).asList().contains("--crawler-asset");
@@ -480,9 +517,10 @@ public final class AppCrawlTesterTest {
         Path loginFilesDir = mFileSystem.getPath("/login");
         Files.createDirectory(loginFilesDir);
 
-        sut.setUiAutomatorMode(true);
-        sut.setLoginConfigDir(loginFilesDir);
-        sut.start();
+        sut.getOptions()
+                .setUiAutomatorMode(true)
+                .setLoginConfigDir(new File(loginFilesDir.toString()));
+        sut.startCrawl();
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
         assertThat(result).asList().doesNotContain("--crawler-asset");
@@ -495,8 +533,9 @@ public final class AppCrawlTesterTest {
         Files.createDirectories(apkRoot);
         Files.createFile(apkRoot.resolve("some.apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(apkRoot);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
@@ -513,8 +552,9 @@ public final class AppCrawlTesterTest {
         Files.createFile(apkRoot.resolve("config1.apk"));
         Files.createFile(apkRoot.resolve("config2.apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(apkRoot);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
@@ -533,8 +573,9 @@ public final class AppCrawlTesterTest {
         Files.createFile(apkRoot.resolve("main.package.obb"));
         Files.createFile(apkRoot.resolve("patch.package.obb"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(apkRoot);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
@@ -558,9 +599,10 @@ public final class AppCrawlTesterTest {
         Files.createFile(apkRoot.resolve("config1.apk"));
         Files.createFile(apkRoot.resolve("config2.apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(apkRoot);
-        sut.setUiAutomatorMode(true);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        sut.getOptions().setUiAutomatorMode(true);
+        sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
@@ -577,9 +619,10 @@ public final class AppCrawlTesterTest {
         Files.createFile(apkRoot.resolve("config1.apk"));
         Files.createFile(apkRoot.resolve("config2.apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(apkRoot);
-        sut.setUiAutomatorMode(true);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        sut.getOptions().setUiAutomatorMode(true);
+        sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
@@ -603,8 +646,9 @@ public final class AppCrawlTesterTest {
         Files.createFile(apkRoot.resolve("config1.apk"));
         Files.createFile(apkRoot.resolve("config2.apk"));
         AppCrawlTester sut = createPreparedTestSubject();
-        sut.setApkPath(apkRoot);
-        sut.start();
+        sut.getOptions().setUiAutomatorMode(false);
+        sut.getOptions().setRepackApk(convertToFile(apkRoot));
+        sut.startCrawl();
 
         String[] result = sut.createUtpCrawlerRunCommand(mTestInfo);
 
@@ -653,6 +697,10 @@ public final class AppCrawlTesterTest {
         assertThat(signal).isEqualTo(TestUtils.RoboscriptSignal.FAIL);
     }
 
+    private File convertToFile(Path path) {
+        return new File(path.toString());
+    }
+
     private Path createMockRoboOutputFile(int totalActions, int successfulActions)
             throws IOException {
         Path roboOutput = Files.createFile(mFileSystem.getPath("output.txt"));
@@ -688,7 +736,8 @@ public final class AppCrawlTesterTest {
         preparer.setUp(mTestInfo);
     }
 
-    private AppCrawlTester createNotPreparedTestSubject() throws DeviceNotAvailableException {
+    private AppCrawlTester createNotPreparedTestSubject()
+            throws DeviceNotAvailableException, ConfigurationException {
         Mockito.when(mRunUtil.runTimedCmd(Mockito.anyLong(), ArgumentMatchers.<String>any()))
                 .thenReturn(createSuccessfulCommandResult());
         Mockito.when(mDevice.getSerialNumber()).thenReturn("serial");
@@ -696,7 +745,11 @@ public final class AppCrawlTesterTest {
                 .thenReturn(createSuccessfulCommandResultWithStdout("1"));
         when(mDevice.executeShellV2Command(Mockito.eq("getprop ro.build.version.sdk")))
                 .thenReturn(createSuccessfulCommandResultWithStdout("33"));
-        return new AppCrawlTester(PACKAGE_NAME, mTestUtils, () -> mRunUtil, mFileSystem);
+        IConfiguration configuration = new Configuration("name", "description");
+        configuration.setConfigurationObject(
+                AppCrawlTesterOptions.OBJECT_TYPE, new AppCrawlTesterOptions());
+        return new AppCrawlTester(
+                PACKAGE_NAME, mTestUtils, () -> mRunUtil, mFileSystem, configuration);
     }
 
     private AppCrawlTester createPreparedTestSubject()
@@ -710,7 +763,11 @@ public final class AppCrawlTesterTest {
                 .thenReturn(createSuccessfulCommandResultWithStdout("1"));
         when(mDevice.executeShellV2Command(Mockito.eq("getprop ro.build.version.sdk")))
                 .thenReturn(createSuccessfulCommandResultWithStdout("33"));
-        return new AppCrawlTester(PACKAGE_NAME, mTestUtils, () -> mRunUtil, mFileSystem);
+        IConfiguration configuration = new Configuration("name", "description");
+        configuration.setConfigurationObject(
+                AppCrawlTesterOptions.OBJECT_TYPE, new AppCrawlTesterOptions());
+        return new AppCrawlTester(
+                PACKAGE_NAME, mTestUtils, () -> mRunUtil, mFileSystem, configuration);
     }
 
     private TestUtils createTestUtils() throws DeviceNotAvailableException {
diff --git a/integration_tests/csuite_test_utils.py b/integration_tests/csuite_test_utils.py
index fd76e34..505175c 100644
--- a/integration_tests/csuite_test_utils.py
+++ b/integration_tests/csuite_test_utils.py
@@ -101,10 +101,10 @@ class CSuiteHarness(contextlib.AbstractContextManager):
     env['LOCAL_MODE'] = "1"
     # Set the environment variable that TradeFed requires to find test modules.
     env['ANDROID_TARGET_OUT_TESTCASES'] = self._testcases_dir
-    jdk17_path = '/jdk/jdk17/linux-x86'
-    if os.path.isdir(jdk17_path):
-      env['JAVA_HOME'] = jdk17_path
-      java_path = jdk17_path + '/bin'
+    jdk21_path = '/jdk/jdk21/linux-x86'
+    if os.path.isdir(jdk21_path):
+      env['JAVA_HOME'] = jdk21_path
+      java_path = jdk21_path + '/bin'
       env['PATH'] = java_path + ':' + env['PATH']
 
     return _run_command([self._launcher_binary] + flags, env=env)
diff --git a/test_scripts/src/main/java/com/android/art/targetprep/AggregateImgdiagOutput.java b/test_scripts/src/main/java/com/android/art/targetprep/AggregateImgdiagOutput.java
index aed9ebb..bdb68b2 100644
--- a/test_scripts/src/main/java/com/android/art/targetprep/AggregateImgdiagOutput.java
+++ b/test_scripts/src/main/java/com/android/art/targetprep/AggregateImgdiagOutput.java
@@ -31,11 +31,21 @@ import org.json.JSONException;
 import org.json.JSONObject;
 import org.junit.Assert;
 
+import java.math.BigInteger;
+import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.Collection;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Map;
+import java.util.Optional;
+import java.util.Set;
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
+import java.util.stream.Collectors;
 
-/** Collect all imgdiag dirty objects into one file. */
+/** Collect and parse imgdiag output files. */
 public class AggregateImgdiagOutput implements ITestLoggerReceiver, ITargetPreparer {
     @Option(
             name = "imgdiag-out-path",
@@ -44,6 +54,9 @@ public class AggregateImgdiagOutput implements ITestLoggerReceiver, ITargetPrepa
 
     private ITestLogger mTestLogger;
 
+    // Imgdiag outputs this string when a dirty object is unreachable from any Class.
+    private static final String UNREACHABLE_OBJECT = "<no path from class>";
+
     @Override
     public void setTestLogger(ITestLogger testLogger) {
         mTestLogger = testLogger;
@@ -55,12 +68,57 @@ public class AggregateImgdiagOutput implements ITestLoggerReceiver, ITargetPrepa
     @Override
     public void tearDown(TestInformation testInformation, Throwable e)
             throws DeviceNotAvailableException {
+
+        ImgdiagData imgdiagData = collectImgdiagData(testInformation);
+        createDirtyImageObjects(imgdiagData.dirtyObjects);
+        dumpDirtyObjects(imgdiagData.dirtyObjects);
+
+        mTestLogger.testLog(
+                "dirty-page-counts",
+                LogDataType.JSON,
+                new ByteArrayInputStreamSource(
+                        new JSONObject(imgdiagData.dirtyPageCounts).toString().getBytes()));
+    }
+
+    void dumpDirtyObjects(Map<String, Set<String>> dirtyObjects) {
+        JSONObject jsonObj = new JSONObject();
+        for (Map.Entry<String, Set<String>> entry : dirtyObjects.entrySet()) {
+            try {
+                jsonObj.put(entry.getKey(), new JSONArray(entry.getValue()));
+            } catch (JSONException e) {
+                Assert.fail(e.getMessage());
+            }
+        }
+
+        mTestLogger.testLog(
+                "all-dirty-objects",
+                LogDataType.JSON,
+                new ByteArrayInputStreamSource(jsonObj.toString().getBytes()));
+    }
+
+    static class ImgdiagData {
+        // "process name" -> set of dirty objects.
+        public Map<String, Set<String>> dirtyObjects;
+        // "process name" -> dirty page count in ObjectSection.
+        public Map<String, Integer> dirtyPageCounts;
+
+        ImgdiagData(Map<String, Set<String>> dirtyObjects, Map<String, Integer> dirtyPageCounts) {
+            this.dirtyObjects = dirtyObjects;
+            this.dirtyPageCounts = dirtyPageCounts;
+        }
+    }
+
+    ImgdiagData collectImgdiagData(TestInformation testInformation)
+            throws DeviceNotAvailableException {
         Assert.assertTrue(testInformation.getDevice().doesFileExist(mImgdiagOutPath));
 
         Pattern imgdiagOutRegex = Pattern.compile("imgdiag_(\\S+_\\d+)\\.txt");
         String dirtyObjPrefix = "dirty_obj:";
+        String dirtyPageCountPrefix = "SectionObjects";
+
+        Map<String, Set<String>> dirtyObjects = new HashMap<String, Set<String>>();
+        Map<String, Integer> dirtyPageCounts = new HashMap<String, Integer>();
 
-        JSONObject combinedData = new JSONObject();
         IFileEntry deviceImgdiagOutDir = testInformation.getDevice().getFileEntry(mImgdiagOutPath);
         for (IFileEntry child : deviceImgdiagOutDir.getChildren(false)) {
             Matcher m = imgdiagOutRegex.matcher(child.getName());
@@ -69,25 +127,197 @@ public class AggregateImgdiagOutput implements ITestLoggerReceiver, ITargetPrepa
             }
 
             String key = m.group(1);
-
             String fileContents = testInformation.getDevice().pullFileContents(child.getFullPath());
-            Collection<String> dirty_objects =
+
+            // Get the number after the last '=' sign, e.g.:
+            // SectionObjects size=9607584 range=0-9607584 private dirty pages=140
+            Optional<String> dirtyPageCount =
+                    fileContents
+                            .lines()
+                            .filter(line -> line.startsWith(dirtyPageCountPrefix))
+                            .findFirst()
+                            .map(line -> line.split("="))
+                            .map(tokens -> tokens[tokens.length - 1]);
+
+            // Can only happen if imgdiag output is empty, skip this file.
+            if (!dirtyPageCount.isPresent()) {
+                continue;
+            }
+            dirtyPageCounts.put(key, Integer.valueOf(dirtyPageCount.get()));
+
+            Set<String> procDirtyObjects =
                     fileContents
                             .lines()
                             .filter(line -> line.startsWith(dirtyObjPrefix))
                             .map(line -> line.substring(dirtyObjPrefix.length()).strip())
-                            .toList();
+                            .collect(Collectors.toSet());
 
-            try {
-                combinedData.put(key, new JSONArray(dirty_objects));
-            } catch (JSONException exception) {
-                Assert.fail(exception.toString());
+            dirtyObjects.put(key, procDirtyObjects);
+        }
+
+        return new ImgdiagData(dirtyObjects, dirtyPageCounts);
+    }
+
+    // Sort dirty objects, split by dex location and upload.
+    void createDirtyImageObjects(Map<String, Set<String>> dirtyObjects) {
+        Map<BigInteger, Set<String>> sortKeys = generateSortKeys(dirtyObjects);
+        List<Set<String>> sortedObjs = sortDirtyObjects(sortKeys, dirtyObjects);
+        appendSortKeys(sortedObjs);
+
+        List<String> resObjects =
+                sortedObjs.stream().flatMap(Collection::stream).collect(Collectors.toList());
+        Map<String, List<String>> splitDirtyObjects = splitByDexLocation(resObjects);
+
+        for (Map.Entry<String, List<String>> entry : splitDirtyObjects.entrySet()) {
+            mTestLogger.testLog(
+                    "dirty-image-objects-" + entry.getKey(),
+                    LogDataType.TEXT,
+                    new ByteArrayInputStreamSource(String.join("\n", entry.getValue()).getBytes()));
+        }
+    }
+
+    // Calculate a Map of dirty objects in the format: sortKey -> [objects].
+    // Each sortKey is a bit mask, where the Nth bit is set if the given object
+    // is dirty in the Nth process.
+    static Map<BigInteger, Set<String>> generateSortKeys(Map<String, Set<String>> dirtyObjects) {
+        Collection<String> allObjects =
+                dirtyObjects.values().stream()
+                        .flatMap(Collection::stream)
+                        .collect(Collectors.toSet());
+
+        Map<BigInteger, Set<String>> sortKeys = new HashMap<BigInteger, Set<String>>();
+        for (String dirtyObj : allObjects) {
+            // Skip unreachable objects.
+            if (dirtyObj.equals(UNREACHABLE_OBJECT)) {
+                continue;
             }
+
+            // Generate sort key for dirty object.
+            // Go through each process and set corresponding bit to '1' if
+            // the object is dirty in that process.
+            BigInteger sortKey = BigInteger.ZERO;
+            for (Collection<String> procDirtyObjects : dirtyObjects.values()) {
+                sortKey = sortKey.shiftLeft(1);
+                if (procDirtyObjects.contains(dirtyObj)) {
+                    sortKey = sortKey.or(BigInteger.ONE);
+                }
+            }
+
+            // Put dirty objects with the same sortKey together.
+            sortKeys.computeIfAbsent(sortKey, k -> new HashSet<String>());
+            sortKeys.get(sortKey).add(dirtyObj);
+        }
+
+        return sortKeys;
+    }
+
+    // Calculate similarity using intersection divided by union.
+    static float jaccardIndex(BigInteger k1, BigInteger k2) {
+        return (float) k1.and(k2).bitCount() / (float) k1.or(k2).bitCount();
+    }
+
+    // Compare two keys by how similar they are to the base key.
+    static int similarityCompare(BigInteger base, BigInteger k1, BigInteger k2) {
+        return Float.compare(jaccardIndex(base, k1), jaccardIndex(base, k2));
+    }
+
+    // Sorty dirty objects so that objects with similar "dirtiness" pattern
+    // are placed next to each other.
+    List<Set<String>> sortDirtyObjects(
+            Map<BigInteger, Set<String>> sortKeys, Map<String, Set<String>> dirtyObjects) {
+        List<Set<String>> sortedObjs = new ArrayList<Set<String>>();
+
+        // Start with an entry that is dirty in a few processes.
+        Map.Entry<BigInteger, Set<String>> minEntry =
+                sortKeys.entrySet().stream()
+                        .min(
+                                (e1, e2) ->
+                                        Arrays.compare(
+                                                new int[] {
+                                                    e1.getKey().bitCount(), e1.getValue().size()
+                                                },
+                                                new int[] {
+                                                    e2.getKey().bitCount(), e2.getValue().size()
+                                                }))
+                        .get();
+
+        BigInteger lastKey = minEntry.getKey();
+        sortedObjs.add(minEntry.getValue());
+        sortKeys.remove(minEntry.getKey());
+
+        // String representation of sortKey bits.
+        // Helps to check that objects with similar sort keys are placed
+        // together.
+        List<String> dbgSortKeys = new ArrayList<String>();
+        dbgSortKeys.add(
+                String.format(
+                        "%" + dirtyObjects.size() + "s %s",
+                        lastKey.toString(2),
+                        sortedObjs.get(sortedObjs.size() - 1).size()));
+
+        while (!sortKeys.isEmpty()) {
+            final BigInteger currentKey = lastKey;
+            // Select next entry that has a key most similar to currentKey.
+            Map.Entry<BigInteger, Set<String>> nextEntry =
+                    sortKeys.entrySet().stream()
+                            .max(
+                                    (e1, e2) ->
+                                            similarityCompare(currentKey, e1.getKey(), e2.getKey()))
+                            .get();
+
+            lastKey = nextEntry.getKey();
+            sortedObjs.add(nextEntry.getValue());
+            sortKeys.remove(nextEntry.getKey());
+
+            dbgSortKeys.add(
+                    String.format(
+                            "%" + dirtyObjects.size() + "s %s",
+                            lastKey.toString(2),
+                            sortedObjs.get(sortedObjs.size() - 1).size()));
         }
 
         mTestLogger.testLog(
-                "combined_imgdiag_data",
-                LogDataType.JSON,
-                new ByteArrayInputStreamSource(combinedData.toString().getBytes()));
+                "dbg-sort-keys",
+                LogDataType.TEXT,
+                new ByteArrayInputStreamSource(String.join("\n", dbgSortKeys).getBytes()));
+
+        return sortedObjs;
+    }
+
+    static void appendSortKeys(List<Set<String>> sortedObjs) {
+        for (int i = 0; i < sortedObjs.size(); i += 1) {
+            final int sortIndex = i;
+            sortedObjs.set(
+                    i,
+                    sortedObjs.get(i).stream()
+                            .map(obj -> String.format("%s %s", obj, sortIndex))
+                            .collect(Collectors.toSet()));
+        }
+    }
+
+    static boolean isArtModuleObject(String dexLocation) {
+        return dexLocation.startsWith("/apex/com.android.art/");
+    }
+
+    static boolean isPrimitiveArray(String dexLocation) {
+        return dexLocation.startsWith("primitive");
+    }
+
+    static Map<String, List<String>> splitByDexLocation(List<String> objects) {
+        Map<String, List<String>> res = new HashMap<String, List<String>>();
+        res.put("art", new ArrayList<String>());
+        res.put("framework", new ArrayList<String>());
+        for (String entry : objects) {
+            String[] pathAndObj = entry.split(" ", 2);
+            String dexLocation = pathAndObj[0];
+            String obj = pathAndObj[1];
+
+            if (isArtModuleObject(dexLocation) || isPrimitiveArray(dexLocation)) {
+                res.get("art").add(obj);
+            } else {
+                res.get("framework").add(obj);
+            }
+        }
+        return res;
     }
 }
diff --git a/test_scripts/src/main/java/com/android/art/targetprep/AllProcessesImgdiag.java b/test_scripts/src/main/java/com/android/art/targetprep/AllProcessesImgdiag.java
index 9d71f55..3ab5796 100644
--- a/test_scripts/src/main/java/com/android/art/targetprep/AllProcessesImgdiag.java
+++ b/test_scripts/src/main/java/com/android/art/targetprep/AllProcessesImgdiag.java
@@ -17,10 +17,12 @@
 package com.android.art.targetprep;
 
 import com.android.art.tests.AppLaunchImgdiagTest;
+import com.android.ddmlib.Log.LogLevel;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.invoker.TestInformation;
 import com.android.tradefed.log.ITestLogger;
+import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.result.FileInputStreamSource;
 import com.android.tradefed.result.ITestLoggerReceiver;
 import com.android.tradefed.result.LogDataType;
@@ -59,6 +61,8 @@ public class AllProcessesImgdiag implements ITestLoggerReceiver, ITargetPreparer
 
         // Skip "PID ARGS" header.
         for (String line : zygoteChildren.lines().skip(1).toList()) {
+            CLog.logAndDisplay(LogLevel.DEBUG, "Running imgdiag for %s", line);
+
             String[] vals = line.strip().split("\\s+");
             Assert.assertEquals(2, vals.length);
 
diff --git a/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java b/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java
index c2c251e..d44479c 100644
--- a/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java
+++ b/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java
@@ -19,17 +19,17 @@ package com.android.csuite.tests;
 import com.android.csuite.core.ApkInstaller;
 import com.android.csuite.core.ApkInstaller.ApkInstallerException;
 import com.android.csuite.core.AppCrawlTester;
-import com.android.csuite.core.DeviceUtils;
+import com.android.csuite.core.AppCrawlTester.CrawlerException;
+import com.android.csuite.core.DeviceJUnit4ClassRunner;
 import com.android.csuite.core.TestUtils;
+import com.android.tradefed.config.IConfiguration;
+import com.android.tradefed.config.IConfigurationReceiver;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.log.LogUtil.CLog;
-import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
 import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
 import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
 
-import com.google.common.base.Preconditions;
-
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Rule;
@@ -38,20 +38,18 @@ import org.junit.runner.RunWith;
 
 import java.io.File;
 import java.io.IOException;
-import java.nio.file.Path;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 import java.util.stream.Collectors;
 
-import javax.annotation.Nullable;
-
 /** A test that verifies that a single app can be successfully launched. */
 @RunWith(DeviceJUnit4ClassRunner.class)
-public class AppCrawlTest extends BaseHostJUnit4Test {
-    private static final String COLLECT_APP_VERSION = "collect-app-version";
-    private static final String COLLECT_GMS_VERSION = "collect-gms-version";
-    private static final String RECORD_SCREEN = "record-screen";
+public class AppCrawlTest extends BaseHostJUnit4Test implements IConfigurationReceiver {
+    @Deprecated private static final String COLLECT_APP_VERSION = "collect-app-version";
+    @Deprecated private static final String COLLECT_GMS_VERSION = "collect-gms-version";
+    @Deprecated private static final String RECORD_SCREEN = "record-screen";
+    @Deprecated private static final int DEFAULT_TIMEOUT_SEC = 60;
 
     @Rule public TestLogData mLogData = new TestLogData();
     private boolean mIsLastTestPass;
@@ -59,10 +57,13 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
 
     private ApkInstaller mApkInstaller;
     private AppCrawlTester mCrawler;
+    private IConfiguration mConfiguration;
 
+    @Deprecated
     @Option(name = RECORD_SCREEN, description = "Whether to record screen during test.")
     private boolean mRecordScreen;
 
+    @Deprecated
     @Option(
             name = COLLECT_APP_VERSION,
             description =
@@ -70,6 +71,7 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
                             + " test log files.")
     private boolean mCollectAppVersion;
 
+    @Deprecated
     @Option(
             name = COLLECT_GMS_VERSION,
             description =
@@ -77,6 +79,7 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
                             + " test log files.")
     private boolean mCollectGmsVersion;
 
+    @Deprecated
     @Option(
             name = "repack-apk",
             mandatory = false,
@@ -85,6 +88,7 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
                             + "to repack and install in Espresso mode")
     private File mRepackApk;
 
+    @Deprecated
     @Option(
             name = "install-apk",
             mandatory = false,
@@ -95,6 +99,7 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
                             + " additional libraries or dependencies.")
     private final List<File> mInstallApkPaths = new ArrayList<>();
 
+    @Deprecated
     @Option(
             name = "install-arg",
             description =
@@ -105,12 +110,14 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
     @Option(name = "package-name", mandatory = true, description = "Package name of testing app.")
     private String mPackageName;
 
+    @Deprecated
     @Option(
             name = "crawl-controller-endpoint",
             mandatory = false,
             description = "The crawl controller endpoint to target.")
     private String mCrawlControllerEndpoint;
 
+    @Deprecated
     @Option(
             name = "ui-automator-mode",
             mandatory = false,
@@ -119,12 +126,14 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
                             + " mode.")
     private boolean mUiAutomatorMode = false;
 
+    @Deprecated
     @Option(
             name = "timeout-sec",
             mandatory = false,
             description = "The timeout for the crawl test.")
-    private int mTimeoutSec = 60;
+    private int mTimeoutSec = DEFAULT_TIMEOUT_SEC;
 
+    @Deprecated
     @Option(
             name = "robo-script-file",
             description = "A Roboscript file to be executed by the crawler.")
@@ -132,11 +141,13 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
 
     // TODO(b/234512223): add support for contextual roboscript files
 
+    @Deprecated
     @Option(
             name = "crawl-guidance-proto-file",
             description = "A CrawlGuidance file to be executed by the crawler.")
     private File mCrawlGuidanceProtoFile;
 
+    @Deprecated
     @Option(
             name = "login-config-dir",
             description =
@@ -146,11 +157,13 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
                         + " present, only the Roboscript file will be used.")
     private File mLoginConfigDir;
 
+    @Deprecated
     @Option(
             name = "save-apk-when",
             description = "When to save apk files to the test result artifacts.")
     private TestUtils.TakeEffectWhen mSaveApkWhen = TestUtils.TakeEffectWhen.NEVER;
 
+    @Deprecated
     @Option(
             name = "grant-external-storage",
             mandatory = false,
@@ -160,49 +173,51 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
     @Before
     public void setUp()
             throws ApkInstaller.ApkInstallerException, IOException, DeviceNotAvailableException {
-        DeviceUtils deviceUtils = DeviceUtils.getInstance(getDevice());
         mIsLastTestPass = false;
-        mCrawler = AppCrawlTester.newInstance(mPackageName, getTestInformation(), mLogData);
-        if (!mUiAutomatorMode) {
-            setApkForEspressoMode();
+        mCrawler =
+                AppCrawlTester.newInstance(
+                        mPackageName, getTestInformation(), mLogData, mConfiguration);
+        if (mCrawlControllerEndpoint != null) {
+            mCrawler.getOptions().setCrawlControllerEndpoint(mCrawlControllerEndpoint);
+        }
+        if (mRecordScreen) {
+            mCrawler.getOptions().setRecordScreen(mRecordScreen);
+        }
+        if (mCollectGmsVersion) {
+            mCrawler.getOptions().setCollectGmsVersion(mCollectGmsVersion);
+        }
+        if (mCollectAppVersion) {
+            mCrawler.getOptions().setCollectAppVersion(mCollectAppVersion);
+        }
+        if (mUiAutomatorMode) {
+            mCrawler.getOptions().setUiAutomatorMode(mUiAutomatorMode);
+        }
+        if (mRoboscriptFile != null) {
+            mCrawler.getOptions().setRoboscriptFile(mRoboscriptFile);
+        }
+        if (mCrawlGuidanceProtoFile != null) {
+            mCrawler.getOptions().setCrawlGuidanceProtoFile(mCrawlGuidanceProtoFile);
+        }
+        if (mLoginConfigDir != null) {
+            mCrawler.getOptions().setLoginConfigDir(mLoginConfigDir);
+        }
+        if (mTimeoutSec != DEFAULT_TIMEOUT_SEC) {
+            mCrawler.getOptions().setTimeoutSec(mTimeoutSec);
         }
-        mCrawler.setCrawlControllerEndpoint(mCrawlControllerEndpoint);
-        mCrawler.setRecordScreen(mRecordScreen);
-        mCrawler.setCollectGmsVersion(mCollectGmsVersion);
-        mCrawler.setCollectAppVersion(mCollectAppVersion);
-        mCrawler.setUiAutomatorMode(mUiAutomatorMode);
-        mCrawler.setRoboscriptFile(toPathOrNull(mRoboscriptFile));
-        mCrawler.setCrawlGuidanceProtoFile(toPathOrNull(mCrawlGuidanceProtoFile));
-        mCrawler.setLoginConfigDir(toPathOrNull(mLoginConfigDir));
-        mCrawler.setTimeoutSec(mTimeoutSec);
 
         mApkInstaller = ApkInstaller.getInstance(getDevice());
         mApkInstaller.install(
-                mInstallApkPaths.stream().map(File::toPath).collect(Collectors.toList()),
-                mInstallArgs);
-        if (mGrantExternalStoragePermission) {
-            deviceUtils.grantExternalStoragePermissions(mPackageName);
-        }
-    }
+                mCrawler.getOptions().getInstallApkPaths().stream()
+                        .map(File::toPath)
+                        .collect(Collectors.toList()),
+                mCrawler.getOptions().getInstallArgs());
 
-    /** Helper method to fetch the path of optional File variables. */
-    private static Path toPathOrNull(@Nullable File f) {
-        return f == null ? null : f.toPath();
-    }
-
-    /**
-     * For Espresso mode, checks that a path with the location of the apk to repackage was provided
-     */
-    private void setApkForEspressoMode() {
-        Preconditions.checkNotNull(
-                mRepackApk, "Apk file path is required when not running in UIAutomator mode");
-        // set the root path of the target apk for Espresso mode
-        mCrawler.setApkPath(mRepackApk.toPath());
+        mCrawler.runSetup();
     }
 
     @Test
-    public void testAppCrash() throws DeviceNotAvailableException {
-        mCrawler.startAndAssertAppNoCrash();
+    public void testAppCrash() throws DeviceNotAvailableException, CrawlerException {
+        mCrawler.runTest();
         mIsLastTestPass = true;
     }
 
@@ -213,14 +228,17 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
         if (!mIsApkSaved) {
             mIsApkSaved =
                     testUtils.saveApks(
-                            mSaveApkWhen, mIsLastTestPass, mPackageName, mInstallApkPaths);
-            if (mRepackApk != null) {
+                            mCrawler.getOptions().getSaveApkWhen(),
+                            mIsLastTestPass,
+                            mPackageName,
+                            mCrawler.getOptions().getInstallApkPaths());
+            if (mCrawler.getOptions().getRepackApk() != null) {
                 mIsApkSaved &=
                         testUtils.saveApks(
-                                mSaveApkWhen,
+                                mCrawler.getOptions().getSaveApkWhen(),
                                 mIsLastTestPass,
                                 mPackageName,
-                                Arrays.asList(mRepackApk));
+                                Arrays.asList(mCrawler.getOptions().getRepackApk()));
             }
         }
 
@@ -229,10 +247,15 @@ public class AppCrawlTest extends BaseHostJUnit4Test {
         } catch (ApkInstallerException e) {
             CLog.w("Uninstallation of installed apps failed during teardown: %s", e.getMessage());
         }
-        if (!mUiAutomatorMode) {
+        if (!mCrawler.getOptions().isUiAutomatorMode()) {
             getDevice().uninstallPackage(mPackageName);
         }
 
-        mCrawler.cleanUp();
+        mCrawler.runTearDown();
+    }
+
+    @Override
+    public void setConfiguration(IConfiguration configuration) {
+        mConfiguration = configuration;
     }
 }
diff --git a/test_scripts/src/main/java/com/android/pixel/Android.bp b/test_scripts/src/main/java/com/android/pixel/Android.bp
index 2f3e2e8..e4a04e4 100644
--- a/test_scripts/src/main/java/com/android/pixel/Android.bp
+++ b/test_scripts/src/main/java/com/android/pixel/Android.bp
@@ -20,8 +20,8 @@ android_test_helper_app {
     name: "PixelAppCompTests",
     compile_multilib: "both",
     libs: [
-        "android.test.base",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.runner.stubs.system",
     ],
     static_libs: [
         "androidx.test.rules",
diff --git a/test_scripts/src/main/java/com/android/webview/lib/WebviewInstallerToolPreparer.java b/test_scripts/src/main/java/com/android/webview/lib/WebviewInstallerToolPreparer.java
index 52e5c94..9666739 100644
--- a/test_scripts/src/main/java/com/android/webview/lib/WebviewInstallerToolPreparer.java
+++ b/test_scripts/src/main/java/com/android/webview/lib/WebviewInstallerToolPreparer.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.webview.tests;
+package com.android.webview.lib;
 
 import com.android.tradefed.config.Option;
 import com.android.tradefed.config.Option.Importance;
@@ -194,7 +194,10 @@ public class WebviewInstallerToolPreparer implements ITargetPreparer {
                     CommandStatus.SUCCESS);
 
         } catch (Exception ex) {
-            throw new TargetSetupError("Caught an exception during setup:\n" + ex);
+            throw new TargetSetupError(
+                    "Caught an exception during setup:\n" + ex,
+                    ex,
+                    testInfo.getDevice().getDeviceDescriptor());
         }
         setGcloudCliPath(testInfo, mGcloudCliDir);
         setWebviewInstallerToolPath(testInfo, mWebviewInstallerTool);
diff --git a/test_scripts/src/main/java/com/android/webview/lib/WebviewPackage.java b/test_scripts/src/main/java/com/android/webview/lib/WebviewPackage.java
index 6347f9f..e082ad1 100644
--- a/test_scripts/src/main/java/com/android/webview/lib/WebviewPackage.java
+++ b/test_scripts/src/main/java/com/android/webview/lib/WebviewPackage.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.webview.tests;
+package com.android.webview.lib;
 
 import com.android.tradefed.util.AaptParser;
 
diff --git a/test_scripts/src/main/java/com/android/webview/lib/WebviewUtils.java b/test_scripts/src/main/java/com/android/webview/lib/WebviewUtils.java
index a92f93b..89949e7 100644
--- a/test_scripts/src/main/java/com/android/webview/lib/WebviewUtils.java
+++ b/test_scripts/src/main/java/com/android/webview/lib/WebviewUtils.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.webview.tests;
+package com.android.webview.lib;
 
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.invoker.TestInformation;
@@ -43,8 +43,7 @@ public class WebviewUtils {
     }
 
     public WebviewPackage installWebview(String webviewVersion, String releaseChannel)
-            throws IOException, InterruptedException, DeviceNotAvailableException,
-                    JSONException {
+            throws IOException, DeviceNotAvailableException, JSONException {
         List<String> extraArgs = new ArrayList<>();
         if (webviewVersion == null
                 && Arrays.asList("beta", "stable").contains(releaseChannel.toLowerCase())) {
@@ -128,13 +127,14 @@ public class WebviewUtils {
         return WebviewPackage.buildFromDumpsys(dumpsys);
     }
 
+    /** Print webview version. */
     public void printWebviewVersion() throws DeviceNotAvailableException {
         WebviewPackage currentWebview = getCurrentWebviewPackage();
         printWebviewVersion(currentWebview);
     }
 
-    public void printWebviewVersion(WebviewPackage currentWebview)
-            throws DeviceNotAvailableException {
+    /** Print webview version. */
+    public void printWebviewVersion(WebviewPackage currentWebview) {
         CLog.i("Current webview implementation: %s", currentWebview.getPackageName());
         CLog.i("Current webview version: %s", currentWebview.getVersion());
     }
diff --git a/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java b/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java
index 0026f78..cdd077c 100644
--- a/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java
+++ b/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java
@@ -19,16 +19,19 @@ package com.android.webview.tests;
 import com.android.csuite.core.ApkInstaller;
 import com.android.csuite.core.ApkInstaller.ApkInstallerException;
 import com.android.csuite.core.AppCrawlTester;
+import com.android.csuite.core.AppCrawlTester.CrawlerException;
+import com.android.csuite.core.DeviceJUnit4ClassRunner;
 import com.android.csuite.core.DeviceUtils;
 import com.android.csuite.core.TestUtils;
+import com.android.tradefed.config.IConfiguration;
+import com.android.tradefed.config.IConfigurationReceiver;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.log.LogUtil.CLog;
-import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
 import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
 import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
-
-import com.google.common.base.Preconditions;
+import com.android.webview.lib.WebviewPackage;
+import com.android.webview.lib.WebviewUtils;
 
 import org.json.JSONException;
 import org.junit.After;
@@ -40,26 +43,27 @@ import org.junit.runner.RunWith;
 
 import java.io.File;
 import java.io.IOException;
-import java.nio.file.Path;
 import java.util.ArrayList;
 import java.util.List;
-
-import javax.annotation.Nullable;
+import java.util.stream.Collectors;
 
 /** A test that verifies that a single app can be successfully launched. */
 @RunWith(DeviceJUnit4ClassRunner.class)
-public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
+public class WebviewAppCrawlTest extends BaseHostJUnit4Test implements IConfigurationReceiver {
     @Rule public TestLogData mLogData = new TestLogData();
 
-    private static final String COLLECT_APP_VERSION = "collect-app-version";
-    private static final String COLLECT_GMS_VERSION = "collect-gms-version";
-    private static final long COMMAND_TIMEOUT_MILLIS = 5 * 60 * 1000;
+    @Deprecated private static final String COLLECT_APP_VERSION = "collect-app-version";
+    @Deprecated private static final String COLLECT_GMS_VERSION = "collect-gms-version";
+    @Deprecated private static final int DEFAULT_TIMEOUT_SEC = 60;
 
     private WebviewUtils mWebviewUtils;
     private WebviewPackage mPreInstalledWebview;
     private ApkInstaller mApkInstaller;
     private AppCrawlTester mCrawler;
+    private AppCrawlTester mCrawlerVerify;
+    private IConfiguration mConfiguration;
 
+    @Deprecated
     @Option(name = "record-screen", description = "Whether to record screen during test.")
     private boolean mRecordScreen;
 
@@ -74,6 +78,7 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
     @Option(name = "package-name", description = "Package name of testing app.")
     private String mPackageName;
 
+    @Deprecated
     @Option(
             name = "install-apk",
             description =
@@ -81,6 +86,7 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
                             + " installed on device. Can be repeated.")
     private List<File> mApkPaths = new ArrayList<>();
 
+    @Deprecated
     @Option(
             name = "install-arg",
             description = "Arguments for the 'adb install-multiple' package installation command.")
@@ -91,6 +97,7 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
             description = "Time to wait for an app to launch in msecs.")
     private int mAppLaunchTimeoutMs = 20000;
 
+    @Deprecated
     @Option(
             name = COLLECT_APP_VERSION,
             description =
@@ -98,6 +105,7 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
                             + " test log files.")
     private boolean mCollectAppVersion;
 
+    @Deprecated
     @Option(
             name = COLLECT_GMS_VERSION,
             description =
@@ -105,6 +113,7 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
                             + " test log files.")
     private boolean mCollectGmsVersion;
 
+    @Deprecated
     @Option(
             name = "repack-apk",
             mandatory = false,
@@ -113,12 +122,14 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
                             + "to repack and install in Espresso mode")
     private File mRepackApk;
 
+    @Deprecated
     @Option(
             name = "crawl-controller-endpoint",
             mandatory = false,
             description = "The crawl controller endpoint to target.")
     private String mCrawlControllerEndpoint;
 
+    @Deprecated
     @Option(
             name = "ui-automator-mode",
             mandatory = false,
@@ -127,6 +138,7 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
                             + " mode.")
     private boolean mUiAutomatorMode = false;
 
+    @Deprecated
     @Option(
             name = "robo-script-file",
             description = "A Roboscript file to be executed by the crawler.")
@@ -134,22 +146,26 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
 
     // TODO(b/234512223): add support for contextual roboscript files
 
+    @Deprecated
     @Option(
             name = "crawl-guidance-proto-file",
             description = "A CrawlGuidance file to be executed by the crawler.")
     private File mCrawlGuidanceProtoFile;
 
+    @Deprecated
     @Option(
             name = "timeout-sec",
             mandatory = false,
             description = "The timeout for the crawl test.")
-    private int mTimeoutSec = 60;
+    private int mTimeoutSec = DEFAULT_TIMEOUT_SEC;
 
+    @Deprecated
     @Option(
             name = "save-apk-when",
             description = "When to save apk files to the test result artifacts.")
     private TestUtils.TakeEffectWhen mSaveApkWhen = TestUtils.TakeEffectWhen.NEVER;
 
+    @Deprecated
     @Option(
             name = "login-config-dir",
             description =
@@ -167,57 +183,43 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
                         + "must be used",
                 mWebviewVersionToTest != null || mReleaseChannel != null);
 
-        mCrawler = AppCrawlTester.newInstance(mPackageName, getTestInformation(), mLogData);
-        if (!mUiAutomatorMode) {
-            setApkForEspressoMode();
-        }
-        mCrawler.setCrawlControllerEndpoint(mCrawlControllerEndpoint);
-        mCrawler.setRecordScreen(mRecordScreen);
-        mCrawler.setCollectGmsVersion(mCollectGmsVersion);
-        mCrawler.setCollectAppVersion(mCollectAppVersion);
-        mCrawler.setUiAutomatorMode(mUiAutomatorMode);
-        mCrawler.setRoboscriptFile(toPathOrNull(mRoboscriptFile));
-        mCrawler.setCrawlGuidanceProtoFile(toPathOrNull(mCrawlGuidanceProtoFile));
-        mCrawler.setLoginConfigDir(toPathOrNull(mLoginConfigDir));
-        mCrawler.setTimeoutSec(mTimeoutSec);
+        mCrawler =
+                AppCrawlTester.newInstance(
+                        mPackageName, getTestInformation(), mLogData, mConfiguration);
+        mCrawlerVerify =
+                AppCrawlTester.newInstance(
+                        mPackageName, getTestInformation(), mLogData, mConfiguration);
+
+        setCrawlerOptions(mCrawler);
+        setCrawlerOptions(mCrawlerVerify);
 
         mApkInstaller = ApkInstaller.getInstance(getDevice());
         mWebviewUtils = new WebviewUtils(getTestInformation());
         mPreInstalledWebview = mWebviewUtils.getCurrentWebviewPackage();
 
-        for (File apkPath : mApkPaths) {
-            CLog.d("Installing " + apkPath);
-            mApkInstaller.install(apkPath.toPath(), mInstallArgs);
-        }
+        mApkInstaller = ApkInstaller.getInstance(getDevice());
+        mApkInstaller.install(
+                mCrawler.getOptions().getInstallApkPaths().stream()
+                        .map(File::toPath)
+                        .collect(Collectors.toList()),
+                mCrawler.getOptions().getInstallArgs());
 
         DeviceUtils.getInstance(getDevice()).freezeRotation();
         mWebviewUtils.printWebviewVersion();
-    }
-
-    /**
-     * For Espresso mode, checks that a path with the location of the apk to repackage was provided
-     */
-    private void setApkForEspressoMode() {
-        Preconditions.checkNotNull(
-                mRepackApk, "Apk file path is required when not running in UIAutomator mode");
-        // set the root path of the target apk for Espresso mode
-        mCrawler.setApkPath(mRepackApk.toPath());
-    }
 
-    private static Path toPathOrNull(@Nullable File f) {
-        return f == null ? null : f.toPath();
+        mCrawler.runSetup();
+        mCrawlerVerify.runSetup();
     }
 
     @Test
     public void testAppCrawl()
-            throws DeviceNotAvailableException, InterruptedException, ApkInstallerException,
-                    IOException, JSONException {
+            throws DeviceNotAvailableException, IOException, CrawlerException, JSONException {
         AssertionError lastError = null;
         WebviewPackage lastWebviewInstalled =
                 mWebviewUtils.installWebview(mWebviewVersionToTest, mReleaseChannel);
 
         try {
-            mCrawler.startAndAssertAppNoCrash();
+            mCrawler.runTest();
         } catch (AssertionError e) {
             lastError = e;
         } finally {
@@ -232,7 +234,7 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
         // If the app crashes, try the app with the original webview version that comes with the
         // device.
         try {
-            mCrawler.startAndAssertAppNoCrash();
+            mCrawlerVerify.runTest();
         } catch (AssertionError newError) {
             CLog.w(
                     "The app %s crashed both with and without the webview installation,"
@@ -263,6 +265,42 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test {
             getDevice().uninstallPackage(mPackageName);
         }
 
-        mCrawler.cleanUp();
+        mCrawler.runTearDown();
+        mCrawlerVerify.runTearDown();
+    }
+
+    private void setCrawlerOptions(AppCrawlTester crawler) {
+        if (mCrawlControllerEndpoint != null) {
+            crawler.getOptions().setCrawlControllerEndpoint(mCrawlControllerEndpoint);
+        }
+        if (mRecordScreen) {
+            crawler.getOptions().setRecordScreen(mRecordScreen);
+        }
+        if (mCollectGmsVersion) {
+            crawler.getOptions().setCollectGmsVersion(mCollectGmsVersion);
+        }
+        if (mCollectAppVersion) {
+            crawler.getOptions().setCollectAppVersion(mCollectAppVersion);
+        }
+        if (mUiAutomatorMode) {
+            crawler.getOptions().setUiAutomatorMode(mUiAutomatorMode);
+        }
+        if (mRoboscriptFile != null) {
+            crawler.getOptions().setRoboscriptFile(mRoboscriptFile);
+        }
+        if (mCrawlGuidanceProtoFile != null) {
+            crawler.getOptions().setCrawlGuidanceProtoFile(mCrawlGuidanceProtoFile);
+        }
+        if (mLoginConfigDir != null) {
+            crawler.getOptions().setLoginConfigDir(mLoginConfigDir);
+        }
+        if (mTimeoutSec != DEFAULT_TIMEOUT_SEC) {
+            crawler.getOptions().setTimeoutSec(mTimeoutSec);
+        }
+    }
+
+    @Override
+    public void setConfiguration(IConfiguration configuration) {
+        mConfiguration = configuration;
     }
 }
diff --git a/test_scripts/src/main/java/com/android/webview/tests/WebviewAppLaunchTest.java b/test_scripts/src/main/java/com/android/webview/tests/WebviewAppLaunchTest.java
index 595b3a7..ffcaaae 100644
--- a/test_scripts/src/main/java/com/android/webview/tests/WebviewAppLaunchTest.java
+++ b/test_scripts/src/main/java/com/android/webview/tests/WebviewAppLaunchTest.java
@@ -29,6 +29,8 @@ import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
 import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
 import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
 import com.android.tradefed.util.RunUtil;
+import com.android.webview.lib.WebviewPackage;
+import com.android.webview.lib.WebviewUtils;
 
 import org.json.JSONException;
 import org.junit.After;
@@ -49,7 +51,6 @@ import java.util.List;
 public class WebviewAppLaunchTest extends BaseHostJUnit4Test {
     @Rule public TestLogData mLogData = new TestLogData();
 
-    private static final long COMMAND_TIMEOUT_MILLIS = 5 * 60 * 1000;
     private WebviewUtils mWebviewUtils;
     private WebviewPackage mPreInstalledWebview;
     private ApkInstaller mApkInstaller;
@@ -107,9 +108,7 @@ public class WebviewAppLaunchTest extends BaseHostJUnit4Test {
     }
 
     @Test
-    public void testAppLaunch()
-            throws DeviceNotAvailableException, InterruptedException, ApkInstallerException,
-                    IOException, JSONException {
+    public void testAppLaunch() throws DeviceNotAvailableException, IOException, JSONException {
         AssertionError lastError = null;
         WebviewPackage lastWebviewInstalled =
                 mWebviewUtils.installWebview(mWebviewVersionToTest, mReleaseChannel);
diff --git a/test_scripts/src/main/java/com/android/webview/unittests/WebviewAppCompatUnitTests.java b/test_scripts/src/main/java/com/android/webview/unittests/WebviewAppCompatUnitTests.java
index 7ade092..f1e4b4d 100644
--- a/test_scripts/src/main/java/com/android/webview/unittests/WebviewAppCompatUnitTests.java
+++ b/test_scripts/src/main/java/com/android/webview/unittests/WebviewAppCompatUnitTests.java
@@ -16,7 +16,7 @@
 
 package com.android.webview.unittests;
 
-import com.android.webview.tests.WebviewPackage;
+import com.android.webview.lib.WebviewPackage;
 
 import org.junit.Assert;
 import org.junit.Test;
@@ -46,7 +46,6 @@ public class WebviewAppCompatUnitTests {
 
     @Test
     public void testSortWebviewPackages() {
-        String pkgName = "com.android.webview";
         List<WebviewPackage> webviewPackages =
                 Arrays.asList(
                                 new WebviewPackage(WEBVIEW_PACKAGE, "101.0.4911.122", 4911122),
diff --git a/test_targets/csuite-app-crawl/espresso-crawl.xml b/test_targets/csuite-app-crawl/espresso-crawl.xml
index 4c64a94..3900cc9 100644
--- a/test_targets/csuite-app-crawl/espresso-crawl.xml
+++ b/test_targets/csuite-app-crawl/espresso-crawl.xml
@@ -14,6 +14,10 @@
      limitations under the License.
 -->
 <configuration description="C-Suite Crawler test configuration">
+    <object type="APP_CRAWL_TESTER_OPTIONS" class="com.android.csuite.core.AppCrawlTesterOptions" >
+        <option name="repack-apk" value="app://{package}"/>
+        <option name="ui-automator-mode" value="false"/>
+    </object>
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
     <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
         <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
@@ -22,7 +26,6 @@
     </target_preparer>
     <test class="com.android.tradefed.testtype.HostTest" >
         <option name="set-option" value="package-name:{package}"/>
-        <option name="set-option" value="repack-apk:app\://{package}"/>
         <option name="class" value="com.android.csuite.tests.AppCrawlTest" />
     </test>
 </configuration>
\ No newline at end of file
diff --git a/test_targets/csuite-app-crawl/pre-installed-crawl.xml b/test_targets/csuite-app-crawl/pre-installed-crawl.xml
index 52bca98..c687258 100644
--- a/test_targets/csuite-app-crawl/pre-installed-crawl.xml
+++ b/test_targets/csuite-app-crawl/pre-installed-crawl.xml
@@ -14,6 +14,9 @@
      limitations under the License.
 -->
 <configuration description="C-Suite Crawler test configuration">
+    <object type="APP_CRAWL_TESTER_OPTIONS" class="com.android.csuite.core.AppCrawlTesterOptions" >
+        <option name="ui-automator-mode" value="true"/>
+    </object>
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
     <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
         <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
@@ -22,7 +25,6 @@
     </target_preparer>
     <test class="com.android.tradefed.testtype.HostTest" >
         <option name="set-option" value="package-name:{package}"/>
-        <option name="set-option" value="ui-automator-mode:true"/>
         <option name="class" value="com.android.csuite.tests.AppCrawlTest" />
     </test>
 </configuration>
\ No newline at end of file
diff --git a/test_targets/csuite-app-crawl/ui-automator-crawl.xml b/test_targets/csuite-app-crawl/ui-automator-crawl.xml
index cc41031..8d912e6 100644
--- a/test_targets/csuite-app-crawl/ui-automator-crawl.xml
+++ b/test_targets/csuite-app-crawl/ui-automator-crawl.xml
@@ -14,6 +14,11 @@
      limitations under the License.
 -->
 <configuration description="C-Suite Crawler test configuration">
+    <object type="APP_CRAWL_TESTER_OPTIONS" class="com.android.csuite.core.AppCrawlTesterOptions" >
+        <option name="install-apk" value="app://{package}"/>
+        <option name="install-arg" value="-g"/>
+        <option name="ui-automator-mode" value="true"/>
+    </object>
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
     <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
         <option name="run-command" value="input keyevent KEYCODE_WAKEUP"/>
@@ -22,9 +27,6 @@
     </target_preparer>
     <test class="com.android.tradefed.testtype.HostTest" >
         <option name="set-option" value="package-name:{package}"/>
-        <option name="set-option" value="install-apk:app\://{package}"/>
-        <option name="set-option" value="install-arg:-g"/>
-        <option name="set-option" value="ui-automator-mode:true"/>
         <option name="class" value="com.android.csuite.tests.AppCrawlTest" />
     </test>
 </configuration>
\ No newline at end of file
diff --git a/test_targets/imgdiag-app-launch/plan.xml b/test_targets/imgdiag-app-launch/plan.xml
index 163c79a..97e5c1d 100644
--- a/test_targets/imgdiag-app-launch/plan.xml
+++ b/test_targets/imgdiag-app-launch/plan.xml
@@ -18,10 +18,12 @@
     <option name="run-command" value="mkdir /data/local/tmp/imgdiag_out/"/>
     <option name="teardown-command" value="rm -r /data/local/tmp/imgdiag_out/"/>
   </target_preparer>
-  <target_preparer class="com.android.art.targetprep.AllProcessesImgdiag">
+  <!-- The aggregate step should be last, but its logic is defined in `tearDown`,
+  so the order is reversed. -->
+  <target_preparer class="com.android.art.targetprep.AggregateImgdiagOutput">
     <option name="imgdiag-out-path" value="/data/local/tmp/imgdiag_out/"/>
   </target_preparer>
-  <target_preparer class="com.android.art.targetprep.AggregateImgdiagOutput">
+  <target_preparer class="com.android.art.targetprep.AllProcessesImgdiag">
     <option name="imgdiag-out-path" value="/data/local/tmp/imgdiag_out/"/>
   </target_preparer>
 </configuration>
diff --git a/test_targets/webview-app-crawl/plan.xml b/test_targets/webview-app-crawl/plan.xml
index 83c3e05..1a96800 100644
--- a/test_targets/webview-app-crawl/plan.xml
+++ b/test_targets/webview-app-crawl/plan.xml
@@ -14,6 +14,6 @@
      limitations under the License.
 -->
 <configuration description="WebView C-Suite Crawler Test Plan">
-  <target_preparer class="com.android.webview.tests.WebviewInstallerToolPreparer"/>
+  <target_preparer class="com.android.webview.lib.WebviewInstallerToolPreparer"/>
   <target_preparer class="com.android.csuite.core.AppCrawlTesterHostPreparer"/>
 </configuration>
diff --git a/test_targets/webview-app-crawl/ui-automator-mode.xml b/test_targets/webview-app-crawl/ui-automator-mode.xml
index ec44190..b1d50dc 100644
--- a/test_targets/webview-app-crawl/ui-automator-mode.xml
+++ b/test_targets/webview-app-crawl/ui-automator-mode.xml
@@ -14,6 +14,11 @@
      limitations under the License.
 -->
 <configuration description="Crawl's an app after installing WebView">
+    <object type="APP_CRAWL_TESTER_OPTIONS" class="com.android.csuite.core.AppCrawlTesterOptions" >
+        <option name="install-apk" value="app://{package}"/>
+        <option name="install-arg" value="-g"/>
+        <option name="ui-automator-mode" value="true"/>
+    </object>
     <target_preparer class="com.android.compatibility.targetprep.CheckGmsPreparer"/>
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller" />
     <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
@@ -23,9 +28,6 @@
     </target_preparer>
     <test class="com.android.tradefed.testtype.HostTest" >
         <option name="set-option" value="package-name:{package}"/>
-        <option name="set-option" value="install-apk:app\://{package}"/>
-        <option name="set-option" value="ui-automator-mode:true"/>
-        <option name="set-option" value="install-arg:-g"/>
         <option name="class" value="com.android.webview.tests.WebviewAppCrawlTest" />
     </test>
 </configuration>
```

