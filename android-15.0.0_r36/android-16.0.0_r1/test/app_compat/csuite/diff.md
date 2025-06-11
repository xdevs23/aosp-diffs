```diff
diff --git a/OWNERS b/OWNERS
index b78e055..24748d2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,5 @@
-adirao@google.com
-fdeng@google.com
-hzalek@google.com
+# Bug component: 517632
+liuyg@google.com
 yuexima@google.com
 zhuoyao@google.com
+adirao@google.com
diff --git a/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java b/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
index 4d8fa66..b9dbf71 100644
--- a/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
+++ b/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
@@ -16,6 +16,7 @@
 
 package com.android.csuite.core;
 
+import com.android.csuite.core.ApkInstaller.ApkInstallerException;
 import com.android.csuite.core.DeviceUtils.DeviceTimestamp;
 import com.android.csuite.core.DeviceUtils.DropboxEntry;
 import com.android.csuite.core.TestUtils.RoboscriptSignal;
@@ -65,8 +66,8 @@ public final class AppCrawlTester {
     private FileSystem mFileSystem;
     private DeviceTimestamp mScreenRecordStartTime;
     private IConfiguration mConfiguration;
-    private boolean mIsSetupComplete = false;
-    private boolean mIsTestExecuted = false;
+    private ApkInstaller mApkInstaller;
+    private ExecutionStage mExecutionStage = new ExecutionStage();
 
     /**
      * Creates an {@link AppCrawlTester} instance.
@@ -158,8 +159,14 @@ public final class AppCrawlTester {
      *
      * @throws DeviceNotAvailableException when the device is lost.
      * @throws CrawlerException when unexpected happened.
+     * @throws IOException
+     * @throws ApkInstallerException
      */
-    public void run() throws DeviceNotAvailableException, CrawlerException {
+    public void run()
+            throws DeviceNotAvailableException,
+                    CrawlerException,
+                    ApkInstallerException,
+                    IOException {
         try {
             runSetup();
             runTest();
@@ -172,8 +179,10 @@ public final class AppCrawlTester {
      * Runs only the setup step of the crawl test.
      *
      * @throws DeviceNotAvailableException when the device is lost.
+     * @throws IOException when IO operations fail.
+     * @throws ApkInstallerException when APK installation fails.
      */
-    public void runSetup() throws DeviceNotAvailableException {
+    public void runSetup() throws DeviceNotAvailableException, ApkInstallerException, IOException {
         // For Espresso mode, checks that a path with the location of the apk to repackage was
         // provided
         if (!getOptions().isUiAutomatorMode()) {
@@ -182,15 +191,50 @@ public final class AppCrawlTester {
                     "Apk file path is required when not running in UIAutomator mode");
         }
 
+        mApkInstaller = ApkInstaller.getInstance(mTestUtils.getDeviceUtils().getITestDevice());
+        mApkInstaller.install(
+                getOptions().getInstallApkPaths().stream()
+                        .map(File::toPath)
+                        .collect(Collectors.toList()),
+                getOptions().getInstallArgs());
+
         // Grant external storage permission
         if (getOptions().isGrantExternalStoragePermission()) {
             mTestUtils.getDeviceUtils().grantExternalStoragePermissions(mPackageName);
         }
-        mIsSetupComplete = true;
+        mExecutionStage.setSetupComplete(true);
     }
 
     /** Runs only the teardown step of the crawl test. */
     public void runTearDown() {
+        mTestUtils.saveApks(
+                getOptions().getSaveApkWhen(),
+                mExecutionStage.isTestPassed(),
+                mPackageName,
+                getOptions().getInstallApkPaths());
+        if (getOptions().getRepackApk() != null) {
+            mTestUtils.saveApks(
+                    getOptions().getSaveApkWhen(),
+                    mExecutionStage.isTestPassed(),
+                    mPackageName,
+                    Arrays.asList(getOptions().getRepackApk()));
+        }
+
+        try {
+            mApkInstaller.uninstallAllInstalledPackages();
+        } catch (ApkInstallerException e) {
+            CLog.e("Uninstallation of installed apps failed during teardown: %s", e.getMessage());
+        }
+        if (!getOptions().isUiAutomatorMode()) {
+            try {
+                mTestUtils.getDeviceUtils().getITestDevice().uninstallPackage(mPackageName);
+            } catch (DeviceNotAvailableException e) {
+                CLog.e(
+                        "Uninstallation of installed apps failed during teardown: %s",
+                        e.getMessage());
+            }
+        }
+
         cleanUpOutputDir();
     }
 
@@ -201,16 +245,16 @@ public final class AppCrawlTester {
      * @throws CrawlerException when unexpected happened during the execution.
      */
     public void runTest() throws DeviceNotAvailableException, CrawlerException {
-        if (!mIsSetupComplete) {
+        if (!mExecutionStage.isSetupComplete()) {
             throw new CrawlerException("Crawler setup has not run.");
         }
-        if (mIsTestExecuted) {
+        if (mExecutionStage.isTestExecuted()) {
             throw new CrawlerException(
                     "The crawler has already run. Multiple runs in the same "
                             + AppCrawlTester.class.getName()
                             + " instance are not supported.");
         }
-        mIsTestExecuted = true;
+        mExecutionStage.setTestExecuted(true);
 
         DeviceTimestamp startTime = mTestUtils.getDeviceUtils().currentTimeMillis();
 
@@ -256,6 +300,8 @@ public final class AppCrawlTester {
                             "\n============\n",
                             failureMessages.toArray(new String[failureMessages.size()])));
         }
+
+        mExecutionStage.setTestPassed(true);
     }
 
     /**
@@ -712,6 +758,36 @@ public final class AppCrawlTester {
         return cmd.toArray(new String[cmd.size()]);
     }
 
+    private class ExecutionStage {
+        private boolean mIsSetupComplete = false;
+        private boolean mIsTestExecuted = false;
+        private boolean mIsTestPassed = false;
+
+        private boolean isSetupComplete() {
+            return mIsSetupComplete;
+        }
+
+        private void setSetupComplete(boolean isSetupComplete) {
+            mIsSetupComplete = isSetupComplete;
+        }
+
+        private boolean isTestExecuted() {
+            return mIsTestExecuted;
+        }
+
+        private void setTestExecuted(boolean misTestExecuted) {
+            mIsTestExecuted = misTestExecuted;
+        }
+
+        private boolean isTestPassed() {
+            return mIsTestPassed;
+        }
+
+        private void setTestPassed(boolean isTestPassed) {
+            mIsTestPassed = isTestPassed;
+        }
+    }
+
     /** Cleans up the crawler output directory. */
     @VisibleForTesting
     void cleanUpOutputDir() {
diff --git a/harness/src/main/java/com/android/csuite/core/DeviceUtils.java b/harness/src/main/java/com/android/csuite/core/DeviceUtils.java
index d140085..ba8cc50 100644
--- a/harness/src/main/java/com/android/csuite/core/DeviceUtils.java
+++ b/harness/src/main/java/com/android/csuite/core/DeviceUtils.java
@@ -123,6 +123,11 @@ public class DeviceUtils {
         void run() throws DeviceNotAvailableException;
     }
 
+    /** Returns the stored ITestDevice instance. */
+    public ITestDevice getITestDevice() {
+        return mDevice;
+    }
+
     /**
      * Grants additional permissions for installed an installed app
      *
@@ -629,6 +634,26 @@ public class DeviceUtils {
      * @throws IOException when failed to dump or read the dropbox protos.
      */
     public List<DropboxEntry> getDropboxEntries(Set<String> tags) throws IOException {
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
+            // If dumping proto format is not supported such as in Android 10, the command will
+            // still succeed with exit code 0 and output strings instead of protobuf bytes,
+            // causing parse error. In this case we fallback to dumping dropbox --print option.
+            return getDropboxEntriesFromStdout(tags);
+        }
+
         List<DropboxEntry> entries = new ArrayList<>();
 
         for (String tag : tags) {
@@ -638,24 +663,30 @@ public class DeviceUtils {
                     mRunUtilProvider
                             .get()
                             .runTimedCmd(
-                                    12L * 1000,
+                                    4L * 60 * 1000,
                                     "sh",
                                     "-c",
                                     String.format(
                                             "adb -s %s shell dumpsys dropbox --proto %s > %s",
                                             mDevice.getSerialNumber(), tag, dumpFile));
-
             if (res.getStatus() != CommandStatus.SUCCESS) {
                 throw new IOException("Dropbox dump command failed: " + res);
             }
 
+            if (Files.size(dumpFile) == 0) {
+                CLog.d("Skipping empty proto " + dumpFile);
+                continue;
+            }
+
+            CLog.d("Parsing proto for tag %s. Size: %s", tag, Files.size(dumpFile));
             DropBoxManagerServiceDumpProto proto;
             try {
                 proto = DropBoxManagerServiceDumpProto.parseFrom(Files.readAllBytes(dumpFile));
             } catch (InvalidProtocolBufferException e) {
-                // If dumping proto format is not supported such as in Android 10, the command will
-                // still succeed with exit code 0 and output strings instead of protobuf bytes,
-                // causing parse error. In this case we fallback to dumping dropbox --print option.
+                CLog.e(
+                        "Falling back to stdout dropbox dump due to unexpected proto parse error:"
+                                + " %s",
+                        e);
                 return getDropboxEntriesFromStdout(tags);
             }
             Files.delete(dumpFile);
@@ -741,7 +772,7 @@ public class DeviceUtils {
                 mRunUtilProvider
                         .get()
                         .runTimedCmd(
-                                6000,
+                                4L * 60 * 1000,
                                 "sh",
                                 "-c",
                                 String.format(
@@ -770,7 +801,7 @@ public class DeviceUtils {
                 mRunUtilProvider
                         .get()
                         .runTimedCmd(
-                                6000,
+                                4L * 60 * 1000,
                                 "sh",
                                 "-c",
                                 String.format(
diff --git a/harness/src/test/java/com/android/csuite/core/DeviceUtilsTest.java b/harness/src/test/java/com/android/csuite/core/DeviceUtilsTest.java
index edb2d39..f635c20 100644
--- a/harness/src/test/java/com/android/csuite/core/DeviceUtilsTest.java
+++ b/harness/src/test/java/com/android/csuite/core/DeviceUtilsTest.java
@@ -822,6 +822,12 @@ public final class DeviceUtilsTest {
     @Test
     public void getDropboxEntries_noEntries_returnsEmptyList() throws Exception {
         DeviceUtils sut = createSubjectUnderTest();
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("dumpsys dropbox --help")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("--proto"));
         when(mRunUtil.runTimedCmd(
                         Mockito.anyLong(),
                         Mockito.eq("sh"),
@@ -836,6 +842,12 @@ public final class DeviceUtilsTest {
 
     @Test
     public void getDropboxEntries_entryExists_returnsEntry() throws Exception {
+        when(mRunUtil.runTimedCmd(
+                        Mockito.anyLong(),
+                        Mockito.eq("sh"),
+                        Mockito.eq("-c"),
+                        Mockito.contains("dumpsys dropbox --help")))
+                .thenReturn(createSuccessfulCommandResultWithStdout("--proto"));
         Path dumpFile = Files.createTempFile(mFileSystem.getPath("/"), "dropbox", ".proto");
         long time = 123;
         String data = "abc";
diff --git a/integration_tests/Android.bp b/integration_tests/Android.bp
index 78c2152..155f782 100644
--- a/integration_tests/Android.bp
+++ b/integration_tests/Android.bp
@@ -84,11 +84,6 @@ python_test_host {
     libs: [
         "csuite_test_utils",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_test_host {
@@ -107,11 +102,6 @@ python_test_host {
     test_options: {
         unit_test: false,
     },
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 // importlib.resources cannot load resources from the root package, so move the test apps
diff --git a/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java b/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java
index d44479c..e9b2f4e 100644
--- a/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java
+++ b/test_scripts/src/main/java/com/android/csuite/tests/AppCrawlTest.java
@@ -17,7 +17,6 @@
 package com.android.csuite.tests;
 
 import com.android.csuite.core.ApkInstaller;
-import com.android.csuite.core.ApkInstaller.ApkInstallerException;
 import com.android.csuite.core.AppCrawlTester;
 import com.android.csuite.core.AppCrawlTester.CrawlerException;
 import com.android.csuite.core.DeviceJUnit4ClassRunner;
@@ -26,7 +25,6 @@ import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.IConfigurationReceiver;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.device.DeviceNotAvailableException;
-import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
 import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
 
@@ -39,9 +37,7 @@ import org.junit.runner.RunWith;
 import java.io.File;
 import java.io.IOException;
 import java.util.ArrayList;
-import java.util.Arrays;
 import java.util.List;
-import java.util.stream.Collectors;
 
 /** A test that verifies that a single app can be successfully launched. */
 @RunWith(DeviceJUnit4ClassRunner.class)
@@ -52,10 +48,7 @@ public class AppCrawlTest extends BaseHostJUnit4Test implements IConfigurationRe
     @Deprecated private static final int DEFAULT_TIMEOUT_SEC = 60;
 
     @Rule public TestLogData mLogData = new TestLogData();
-    private boolean mIsLastTestPass;
-    private boolean mIsApkSaved = false;
 
-    private ApkInstaller mApkInstaller;
     private AppCrawlTester mCrawler;
     private IConfiguration mConfiguration;
 
@@ -173,7 +166,6 @@ public class AppCrawlTest extends BaseHostJUnit4Test implements IConfigurationRe
     @Before
     public void setUp()
             throws ApkInstaller.ApkInstallerException, IOException, DeviceNotAvailableException {
-        mIsLastTestPass = false;
         mCrawler =
                 AppCrawlTester.newInstance(
                         mPackageName, getTestInformation(), mLogData, mConfiguration);
@@ -205,52 +197,16 @@ public class AppCrawlTest extends BaseHostJUnit4Test implements IConfigurationRe
             mCrawler.getOptions().setTimeoutSec(mTimeoutSec);
         }
 
-        mApkInstaller = ApkInstaller.getInstance(getDevice());
-        mApkInstaller.install(
-                mCrawler.getOptions().getInstallApkPaths().stream()
-                        .map(File::toPath)
-                        .collect(Collectors.toList()),
-                mCrawler.getOptions().getInstallArgs());
-
         mCrawler.runSetup();
     }
 
     @Test
     public void testAppCrash() throws DeviceNotAvailableException, CrawlerException {
         mCrawler.runTest();
-        mIsLastTestPass = true;
     }
 
     @After
-    public void tearDown() throws DeviceNotAvailableException {
-        TestUtils testUtils = TestUtils.getInstance(getTestInformation(), mLogData);
-
-        if (!mIsApkSaved) {
-            mIsApkSaved =
-                    testUtils.saveApks(
-                            mCrawler.getOptions().getSaveApkWhen(),
-                            mIsLastTestPass,
-                            mPackageName,
-                            mCrawler.getOptions().getInstallApkPaths());
-            if (mCrawler.getOptions().getRepackApk() != null) {
-                mIsApkSaved &=
-                        testUtils.saveApks(
-                                mCrawler.getOptions().getSaveApkWhen(),
-                                mIsLastTestPass,
-                                mPackageName,
-                                Arrays.asList(mCrawler.getOptions().getRepackApk()));
-            }
-        }
-
-        try {
-            mApkInstaller.uninstallAllInstalledPackages();
-        } catch (ApkInstallerException e) {
-            CLog.w("Uninstallation of installed apps failed during teardown: %s", e.getMessage());
-        }
-        if (!mCrawler.getOptions().isUiAutomatorMode()) {
-            getDevice().uninstallPackage(mPackageName);
-        }
-
+    public void tearDown() {
         mCrawler.runTearDown();
     }
 
diff --git a/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java b/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java
index cdd077c..83f6753 100644
--- a/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java
+++ b/test_scripts/src/main/java/com/android/webview/tests/WebviewAppCrawlTest.java
@@ -45,7 +45,6 @@ import java.io.File;
 import java.io.IOException;
 import java.util.ArrayList;
 import java.util.List;
-import java.util.stream.Collectors;
 
 /** A test that verifies that a single app can be successfully launched. */
 @RunWith(DeviceJUnit4ClassRunner.class)
@@ -193,17 +192,17 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test implements IConfigur
         setCrawlerOptions(mCrawler);
         setCrawlerOptions(mCrawlerVerify);
 
+        // Only save apk on the verification run.
+        mCrawler.getOptions().setSaveApkWhen(TestUtils.TakeEffectWhen.NEVER);
+        mCrawlerVerify.getOptions().setSaveApkWhen(TestUtils.TakeEffectWhen.ON_FAIL);
+        // Only record screen on the webview run.
+        mCrawler.getOptions().setRecordScreen(true);
+        mCrawlerVerify.getOptions().setRecordScreen(false);
+
         mApkInstaller = ApkInstaller.getInstance(getDevice());
         mWebviewUtils = new WebviewUtils(getTestInformation());
         mPreInstalledWebview = mWebviewUtils.getCurrentWebviewPackage();
 
-        mApkInstaller = ApkInstaller.getInstance(getDevice());
-        mApkInstaller.install(
-                mCrawler.getOptions().getInstallApkPaths().stream()
-                        .map(File::toPath)
-                        .collect(Collectors.toList()),
-                mCrawler.getOptions().getInstallArgs());
-
         DeviceUtils.getInstance(getDevice()).freezeRotation();
         mWebviewUtils.printWebviewVersion();
 
@@ -261,10 +260,6 @@ public class WebviewAppCrawlTest extends BaseHostJUnit4Test implements IConfigur
         mApkInstaller.uninstallAllInstalledPackages();
         mWebviewUtils.printWebviewVersion();
 
-        if (!mUiAutomatorMode) {
-            getDevice().uninstallPackage(mPackageName);
-        }
-
         mCrawler.runTearDown();
         mCrawlerVerify.runTearDown();
     }
diff --git a/test_targets/pixel-app-launch-lock/OWNERS b/test_targets/pixel-app-launch-lock/OWNERS
index 05ffe9a..1617d41 100644
--- a/test_targets/pixel-app-launch-lock/OWNERS
+++ b/test_targets/pixel-app-launch-lock/OWNERS
@@ -1,2 +1 @@
 murphykuo@google.com
-huilingchi@google.com
diff --git a/test_targets/pixel-app-launch-recentapp/OWNERS b/test_targets/pixel-app-launch-recentapp/OWNERS
index 05ffe9a..1617d41 100644
--- a/test_targets/pixel-app-launch-recentapp/OWNERS
+++ b/test_targets/pixel-app-launch-recentapp/OWNERS
@@ -1,2 +1 @@
 murphykuo@google.com
-huilingchi@google.com
diff --git a/test_targets/pixel-app-launch-rotate/OWNERS b/test_targets/pixel-app-launch-rotate/OWNERS
index 05ffe9a..1617d41 100644
--- a/test_targets/pixel-app-launch-rotate/OWNERS
+++ b/test_targets/pixel-app-launch-rotate/OWNERS
@@ -1,2 +1 @@
 murphykuo@google.com
-huilingchi@google.com
diff --git a/tools/csuite_test/csuite_test_test.go b/tools/csuite_test/csuite_test_test.go
index 91edaf9..c01580f 100644
--- a/tools/csuite_test/csuite_test_test.go
+++ b/tools/csuite_test/csuite_test_test.go
@@ -119,7 +119,7 @@ func TestValidBpMissingPlanIncludeGeneratesPlanXmlWithoutPlaceholders(t *testing
 		}
 	`)
 
-	module := ctx.ModuleForTests("plan_name", config.BuildOS.String()+"_common")
+	module := ctx.ModuleForTests(t, "plan_name", config.BuildOS.String()+"_common")
 	content := android.ContentFromFileRuleForTests(t, ctx, module.Output("config/plan_name.xml"))
 	if strings.Contains(content, "{") || strings.Contains(content, "}") {
 		t.Errorf("The generated plan name contains a placeholder: %s", content)
@@ -134,7 +134,7 @@ func TestGeneratedTestPlanContainsPlanName(t *testing.T) {
 		}
 	`)
 
-	module := ctx.ModuleForTests("plan_name", config.BuildOS.String()+"_common")
+	module := ctx.ModuleForTests(t, "plan_name", config.BuildOS.String()+"_common")
 	content := android.ContentFromFileRuleForTests(t, ctx, module.Output("config/plan_name.xml"))
 	if !strings.Contains(content, "plan_name") {
 		t.Errorf("The plan name is missing from the generated plan: %s", content)
@@ -149,7 +149,7 @@ func TestGeneratedTestPlanContainsTemplatePath(t *testing.T) {
 		}
 	`)
 
-	module := ctx.ModuleForTests("plan_name", config.BuildOS.String()+"_common")
+	module := ctx.ModuleForTests(t, "plan_name", config.BuildOS.String()+"_common")
 	content := android.ContentFromFileRuleForTests(t, ctx, module.Output("config/plan_name.xml"))
 	if !strings.Contains(content, "config/plan_name/config_template.xml.template") {
 		t.Errorf("The template path is missing from the generated plan: %s", content)
@@ -165,7 +165,7 @@ func TestGeneratedTestPlanContainsExtraTemplatePath(t *testing.T) {
 		}
 	`)
 
-	module := ctx.ModuleForTests("plan_name", config.BuildOS.String()+"_common")
+	module := ctx.ModuleForTests(t, "plan_name", config.BuildOS.String()+"_common")
 	content := android.ContentFromFileRuleForTests(t, ctx, module.Output("config/plan_name.xml"))
 	if !strings.Contains(content, "config/plan_name/extra.xml.template") {
 		t.Errorf("The extra template path is missing from the generated plan: %s", content)
@@ -183,7 +183,7 @@ func TestGeneratedTestPlanDoesNotContainExtraTemplatePath(t *testing.T) {
 		}
 	`)
 
-	module := ctx.ModuleForTests("plan_name", config.BuildOS.String()+"_common")
+	module := ctx.ModuleForTests(t, "plan_name", config.BuildOS.String()+"_common")
 	content := android.ContentFromFileRuleForTests(t, ctx, module.Output("config/plan_name.xml"))
 	if strings.Contains(content, "extra-templates") {
 		t.Errorf("The extra-templates param should not be included in the generated plan: %s", content)
@@ -198,7 +198,7 @@ func TestTemplateFileCopyRuleExists(t *testing.T) {
 		}
 	`)
 
-	params := ctx.ModuleForTests("plan_name", config.BuildOS.String()+"_common").Rule("CSuite")
+	params := ctx.ModuleForTests(t, "plan_name", config.BuildOS.String()+"_common").Rule("CSuite")
 	assertFileCopyRuleExists(t, params, "config_template.xml", "config/plan_name/config_template.xml.template")
 }
 
@@ -211,7 +211,7 @@ func TestExtraTemplateFileCopyRuleExists(t *testing.T) {
 		}
 	`)
 
-	params := ctx.ModuleForTests("plan_name", config.BuildOS.String()+"_common").Rule("CSuite")
+	params := ctx.ModuleForTests(t, "plan_name", config.BuildOS.String()+"_common").Rule("CSuite")
 	assertFileCopyRuleExists(t, params, "config_template.xml", "config/plan_name/extra.xml.template")
 }
 
@@ -224,7 +224,7 @@ func TestGeneratedTestPlanContainsPlanInclude(t *testing.T) {
 		}
 	`)
 
-	module := ctx.ModuleForTests("plan_name", config.BuildOS.String()+"_common")
+	module := ctx.ModuleForTests(t, "plan_name", config.BuildOS.String()+"_common")
 	content := android.ContentFromFileRuleForTests(t, ctx, module.Output("config/plan_name.xml"))
 	if !strings.Contains(content, `"includes/plan_name.xml"`) {
 		t.Errorf("The plan include path is missing from the generated plan: %s", content)
@@ -240,7 +240,7 @@ func TestPlanIncludeFileCopyRuleExists(t *testing.T) {
 		}
 	`)
 
-	params := ctx.ModuleForTests("plan_name", config.BuildOS.String()+"_common").Rule("CSuite")
+	params := ctx.ModuleForTests(t, "plan_name", config.BuildOS.String()+"_common").Rule("CSuite")
 	assertFileCopyRuleExists(t, params, "include.xml", "config/includes/plan_name.xml")
 }
 
```

