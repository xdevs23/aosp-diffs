```diff
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/build/CompatibilityBuildHelper.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/build/CompatibilityBuildHelper.java
index 70afb5b8..d7a947ce 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/build/CompatibilityBuildHelper.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/build/CompatibilityBuildHelper.java
@@ -19,8 +19,12 @@ import com.android.tradefed.build.IBuildInfo;
 import com.android.tradefed.build.IDeviceBuildInfo;
 import com.android.tradefed.build.IFolderBuildInfo;
 import com.android.tradefed.build.VersionedFile;
+import com.android.tradefed.invoker.logger.InvocationMetricLogger;
+import com.android.tradefed.invoker.logger.InvocationMetricLogger.InvocationMetricKey;
+import com.android.tradefed.log.LogUtil.CLog;
 import com.android.tradefed.testtype.IAbi;
 import com.android.tradefed.util.FileUtil;
+import com.android.tradefed.util.SearchArtifactUtil;
 
 import java.io.File;
 import java.io.FileNotFoundException;
@@ -336,11 +340,25 @@ public class CompatibilityBuildHelper {
      * @throws FileNotFoundException if the test file cannot be found
      */
     public File getTestFile(String filename, IAbi abi) throws FileNotFoundException {
+        File testFile = null;
+        try {
+            testFile = SearchArtifactUtil.searchFile(filename, false, abi);
+        } catch (Exception e) {
+            // TODO: handle error when migration is complete.
+            CLog.e(e);
+        }
+        if (testFile != null && testFile.isFile()) {
+            return testFile;
+        } else {
+            // Silently report not found and fall back to old logic.
+            InvocationMetricLogger.addInvocationMetrics(
+                    InvocationMetricKey.SEARCH_ARTIFACT_FAILURE_COUNT, 1);
+        }
+
         File testsDir = getTestsDir();
 
         // The file may be in a subdirectory so do a more thorough search
         // if it did not exist.
-        File testFile = null;
         try {
             testFile = FileUtil.findFile(filename, abi, testsDir);
             if (testFile != null) {
@@ -360,12 +378,17 @@ public class CompatibilityBuildHelper {
                 }
             }
         } catch (IOException e) {
+            // if old logic fails too, do not report search artifact failure
+            InvocationMetricLogger.addInvocationMetrics(
+                    InvocationMetricKey.SEARCH_ARTIFACT_FAILURE_COUNT, -1);
             throw new FileNotFoundException(
                     String.format(
                             "Failure in finding compatibility test file %s due to %s",
                             filename, e));
         }
-
+        // if old logic fails too, do not report search artifact failure
+        InvocationMetricLogger.addInvocationMetrics(
+                InvocationMetricKey.SEARCH_ARTIFACT_FAILURE_COUNT, -1);
         throw new FileNotFoundException(String.format(
                 "Compatibility test file %s does not exist", filename));
     }
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationChecksumHelper.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationChecksumHelper.java
index c154681a..ba82d8cd 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationChecksumHelper.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationChecksumHelper.java
@@ -20,6 +20,7 @@ import com.android.tradefed.result.TestDescription;
 import com.android.tradefed.result.TestResult;
 import com.android.tradefed.result.TestRunResult;
 import com.android.tradefed.result.TestStatus;
+import com.android.tradefed.result.suite.XmlSuiteResultFormatter;
 
 import com.google.common.hash.BloomFilter;
 import com.google.common.hash.Funnels;
@@ -171,6 +172,13 @@ public class CertificationChecksumHelper {
         String stacktrace = testResult.getValue().getStackTrace();
 
         stacktrace = stacktrace == null ? "" : stacktrace.trim();
+        // Truncates and sanitizes the full stack trace to get consistent with {@link
+        // XmlSuiteResultFormatter}.
+        stacktrace =
+                XmlSuiteResultFormatter.truncateStackTrace(
+                        stacktrace, testResult.getKey().getTestName());
+        stacktrace = XmlSuiteResultFormatter.sanitizeXmlContent(stacktrace);
+
         // Line endings for stacktraces are somewhat unpredictable and there is no need to
         // actually read the result they are all removed for consistency.
         stacktrace = stacktrace.replaceAll("\\r?\\n|\\r", "");
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationResultXml.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationResultXml.java
index 16e5be70..df9f47cf 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationResultXml.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationResultXml.java
@@ -142,11 +142,17 @@ public class CertificationResultXml extends XmlSuiteResultFormatter {
     @Override
     public void addBuildInfoAttributes(XmlSerializer serializer, SuiteResultHolder holder)
             throws IllegalArgumentException, IllegalStateException, IOException {
+        HashMap<String, String> processedKeys = new HashMap<>();
+
         for (IBuildInfo build : holder.context.getBuildInfos()) {
             for (String key : build.getBuildAttributes().keySet()) {
                 if (key.startsWith(getAttributesPrefix())) {
                     String newKey = key.split(getAttributesPrefix())[1];
-                    serializer.attribute(NS, newKey, build.getBuildAttributes().get(key));
+                    // Check for duplicates before processing
+                    if (!processedKeys.containsKey(newKey)) {
+                        processedKeys.put(newKey, key);
+                        serializer.attribute(NS, newKey, build.getBuildAttributes().get(key));
+                    }
                 }
             }
         }
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/InteractiveResultReporter.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/InteractiveResultReporter.java
new file mode 100644
index 00000000..6d181eba
--- /dev/null
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/InteractiveResultReporter.java
@@ -0,0 +1,320 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.compatibility.common.tradefed.result.suite;
+
+import com.android.annotations.VisibleForTesting;
+import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
+import com.android.tradefed.config.OptionClass;
+import com.android.tradefed.invoker.IInvocationContext;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.result.ITestInvocationListener;
+
+import org.xmlpull.v1.XmlPullParserException;
+import org.xmlpull.v1.XmlPullParserFactory;
+import org.xmlpull.v1.XmlSerializer;
+
+import java.io.File;
+import java.io.FileNotFoundException;
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import java.util.ArrayList;
+import java.util.Collections;
+import java.util.List;
+import java.util.Locale;
+import java.util.Map;
+import java.util.TreeMap;
+import java.util.stream.Stream;
+
+/** A reporter that helps merge and generate result files required for xTS Interactive tests. */
+@OptionClass(alias = "result-reporter")
+public class InteractiveResultReporter implements ITestInvocationListener {
+
+    // The default directory under results/ which contains all screenshot files of xTS Interactive
+    // tests.
+    @VisibleForTesting static final String SCREENSHOTS_DIR_NAME = "screenshots";
+
+    // The name of the XML file that contains the info of all screenshot files taken during xTS
+    // Interactive tests' execution.
+    @VisibleForTesting
+    static final String SCREENSHOTS_METADATA_FILE_NAME = "screenshots_metadata.xml";
+
+    // XML constants
+    @VisibleForTesting static final String ENCODING = "UTF-8";
+    @VisibleForTesting static final String NS = null;
+    @VisibleForTesting static final String NAME_ATTR = "name";
+    @VisibleForTesting static final String ABI_ATTR = "abi";
+    private static final String DESCRIPTION_ATTR = "description";
+
+    private static final String RESULT_TAG = "Result";
+    @VisibleForTesting static final String MODULE_TAG = "Module";
+    @VisibleForTesting static final String CASE_TAG = "TestCase";
+    @VisibleForTesting static final String TEST_TAG = "Test";
+    private static final String SCREENSHOTS_TAG = "Screenshots";
+    @VisibleForTesting static final String SCREENSHOT_TAG = "Screenshot";
+
+    // Default module name for all screenshot files that don't belong to a module.
+    @VisibleForTesting static final String DEFAULT_MODULE_NAME = "UNKNOWN_MODULE";
+
+    /** A model that contains the required data to create a new screenshot tag in an XML tree. */
+    @VisibleForTesting
+    static final class ScreenshotTagData {
+
+        /** The name of the test case tag the screenshot tag belongs to. */
+        final String mTestCaseName;
+
+        /** The name of the test tag the screenshot tag belongs to. */
+        final String mTestName;
+
+        /** The name of the screenshot tag. */
+        final String mScreenshotName;
+
+        /** The description of the screenshot tag. */
+        final String mScreenshotDescription;
+
+        ScreenshotTagData(
+                String testCaseName,
+                String testName,
+                String screenshotName,
+                String screenshotDescription) {
+            mTestCaseName = testCaseName;
+            mTestName = testName;
+            mScreenshotName = screenshotName;
+            mScreenshotDescription = screenshotDescription;
+        }
+    }
+
+    private CompatibilityBuildHelper mBuildHelper;
+
+    /** The root directory of all results of this invocation. */
+    private File mResultDir;
+
+    @Override
+    public void invocationStarted(IInvocationContext context) {
+        if (mBuildHelper == null) {
+            mBuildHelper = new CompatibilityBuildHelper(context.getBuildInfos().get(0));
+            if (mResultDir == null) {
+                try {
+                    mResultDir = mBuildHelper.getResultDir();
+                    CLog.i("Initialized mResultDir: %s", mResultDir);
+                } catch (FileNotFoundException e) {
+                    throw new RuntimeException(
+                            "An initialized result directory is required for the reporter!", e);
+                }
+            }
+        }
+    }
+
+    @Override
+    public void invocationEnded(long elapsedTime) {
+        if (!Files.exists(Paths.get(mResultDir.getAbsolutePath(), SCREENSHOTS_DIR_NAME))) {
+            CLog.i("No screenshot files are generated for the invocation.");
+            return;
+        }
+        try {
+            genScreenshotsMetadataFile(getScreenshotsMetadataFilePath());
+        } catch (IOException | XmlPullParserException e) {
+            throw new RuntimeException(
+                    "Failed to generate the " + SCREENSHOTS_METADATA_FILE_NAME, e);
+        }
+    }
+
+    /** Gets the {@code File} that represents the path to the screenshot metadata file. */
+    @VisibleForTesting
+    File getScreenshotsMetadataFilePath() {
+        return Paths.get(
+                        mResultDir.getAbsolutePath(),
+                        SCREENSHOTS_DIR_NAME,
+                        SCREENSHOTS_METADATA_FILE_NAME)
+                .toFile();
+    }
+
+    /** Generates the screenshot metadata file under the result directory. */
+    @VisibleForTesting
+    void genScreenshotsMetadataFile(File screenshotsMetadataFile)
+            throws IOException, XmlPullParserException {
+        XmlSerializer serializer =
+                XmlPullParserFactory.newInstance(
+                                "org.kxml2.io.KXmlParser,org.kxml2.io.KXmlSerializer", null)
+                        .newSerializer();
+        serializer.setOutput(new FileOutputStream(screenshotsMetadataFile), ENCODING);
+        serializer.startDocument(ENCODING, false);
+        serializer.setFeature("http://xmlpull.org/v1/doc/features.html#indent-output", true);
+        serializer.processingInstruction(
+                "xml-stylesheet type=\"text/xsl\" href=\"compatibility_result.xsl\"");
+        serializer.startTag(NS, RESULT_TAG);
+
+        List<String> moduleNameWithAbis = new ArrayList<>();
+        List<String> screenshotsInRoot = new ArrayList<>();
+        try (Stream<Path> fileOrDirs =
+                Files.list(Paths.get(mResultDir.getAbsolutePath(), SCREENSHOTS_DIR_NAME))) {
+            fileOrDirs.forEach(
+                    fileOrDir -> {
+                        if (Files.isDirectory(fileOrDir)) {
+                            moduleNameWithAbis.add(fileOrDir.getFileName().toString());
+                        } else if (isScreenshotFile(fileOrDir)) {
+                            screenshotsInRoot.add(fileOrDir.getFileName().toString());
+                        }
+                    });
+        }
+
+        // To keep module names in the metadata XML sorted.
+        Collections.sort(moduleNameWithAbis);
+        for (String moduleNameWithAbi : moduleNameWithAbis) {
+            serializer.startTag(NS, MODULE_TAG);
+            addModuleTagAttributes(serializer, moduleNameWithAbi);
+
+            List<String> screenshotsOfModule = new ArrayList<>();
+            try (Stream<Path> fileOrDirs =
+                    Files.list(
+                            Paths.get(
+                                    mResultDir.getAbsolutePath(),
+                                    SCREENSHOTS_DIR_NAME,
+                                    moduleNameWithAbi))) {
+                fileOrDirs.forEach(
+                        fileOrDir -> {
+                            if (!Files.isDirectory(fileOrDir) && isScreenshotFile(fileOrDir)) {
+                                screenshotsOfModule.add(fileOrDir.getFileName().toString());
+                            }
+                        });
+            }
+            addScreenshotTags(serializer, screenshotsOfModule);
+
+            serializer.endTag(NS, MODULE_TAG);
+        }
+
+        // All screenshots under the root directory are under the default module.
+        if (!screenshotsInRoot.isEmpty()) {
+            serializer.startTag(NS, MODULE_TAG);
+            serializer.attribute(NS, NAME_ATTR, DEFAULT_MODULE_NAME);
+
+            // No need to sort screenshotsInRoot as the tags map is sorted.
+            addScreenshotTags(serializer, screenshotsInRoot);
+
+            serializer.endTag(NS, MODULE_TAG);
+        }
+
+        serializer.endTag(NS, RESULT_TAG);
+        serializer.endDocument();
+        CLog.i("Successfully generated the screenshots metadata file: %s", screenshotsMetadataFile);
+    }
+
+    /** Adds the name and abi attributes (if have) for the <Module> tag. */
+    private static void addModuleTagAttributes(XmlSerializer serializer, String moduleNameWithAbi)
+            throws IOException {
+        String[] splitModuleAbis = moduleNameWithAbi.split("__");
+        if (splitModuleAbis.length == 2) {
+            serializer.attribute(NS, NAME_ATTR, splitModuleAbis[0]);
+            serializer.attribute(NS, ABI_ATTR, splitModuleAbis[1]);
+        } else {
+            serializer.attribute(NS, NAME_ATTR, moduleNameWithAbi);
+        }
+    }
+
+    /** Checks if the given {@link Path} is a screenshot file. */
+    @VisibleForTesting
+    static boolean isScreenshotFile(Path filePath) {
+        String extSuffix = filePath.getFileName().toString().toLowerCase(Locale.ROOT);
+        return extSuffix.endsWith(".png")
+                || extSuffix.endsWith(".jpeg")
+                || extSuffix.endsWith(".jpg");
+    }
+
+    /** Parses a list of screenshot file names to add tags into the given {@code XmlSerializer}. */
+    @VisibleForTesting
+    static void addScreenshotTags(XmlSerializer serializer, List<String> screenshotFileNames)
+            throws IOException, XmlPullParserException {
+        Map<String, Map<String, List<ScreenshotTagData>>> screenshotTagDatas =
+                getScreenshotTagDatas(screenshotFileNames);
+        for (String testCaseName : screenshotTagDatas.keySet()) {
+            serializer.startTag(NS, CASE_TAG);
+            serializer.attribute(NS, NAME_ATTR, testCaseName);
+
+            Map<String, List<ScreenshotTagData>> testCaseScreenshotTagDatas =
+                    screenshotTagDatas.get(testCaseName);
+            for (String testName : testCaseScreenshotTagDatas.keySet()) {
+                serializer.startTag(NS, TEST_TAG);
+                serializer.attribute(NS, NAME_ATTR, testName);
+                serializer.startTag(NS, SCREENSHOTS_TAG);
+
+                List<ScreenshotTagData> testScreenshotTagDatas =
+                        testCaseScreenshotTagDatas.get(testName);
+                for (ScreenshotTagData tagData : testScreenshotTagDatas) {
+                    serializer.startTag(NS, SCREENSHOT_TAG);
+                    serializer.attribute(NS, NAME_ATTR, tagData.mScreenshotName);
+                    serializer.attribute(NS, DESCRIPTION_ATTR, tagData.mScreenshotDescription);
+                    serializer.endTag(NS, SCREENSHOT_TAG);
+                }
+                serializer.endTag(NS, SCREENSHOTS_TAG);
+                serializer.endTag(NS, TEST_TAG);
+            }
+            serializer.endTag(NS, CASE_TAG);
+        }
+    }
+
+    /**
+     * Gets TestClass -> (TestCase -> List of screenshots mappings) mappings by the given list of
+     * screenshot file names.
+     */
+    @VisibleForTesting
+    static Map<String, Map<String, List<ScreenshotTagData>>> getScreenshotTagDatas(
+            List<String> screenshotFileNames) {
+        Map<String, Map<String, List<ScreenshotTagData>>> screenshotTagDatas = new TreeMap<>();
+        for (String screenshotFileName : screenshotFileNames) {
+            ScreenshotTagData screenshotTagData = getScreenshotTagData(screenshotFileName);
+            screenshotTagDatas.putIfAbsent(screenshotTagData.mTestCaseName, new TreeMap<>());
+
+            Map<String, List<ScreenshotTagData>> testCaseScreenshotTagDatas =
+                    screenshotTagDatas.get(screenshotTagData.mTestCaseName);
+            testCaseScreenshotTagDatas.putIfAbsent(screenshotTagData.mTestName, new ArrayList<>());
+            testCaseScreenshotTagDatas.get(screenshotTagData.mTestName).add(screenshotTagData);
+        }
+        return screenshotTagDatas;
+    }
+
+    /** Parses the given screenshot file name to get a {@link ScreenshotTagData}. */
+    @VisibleForTesting
+    static ScreenshotTagData getScreenshotTagData(String screenshotFileName) {
+        String[] screenshotDetails = screenshotFileName.split("__");
+        // The length of the array is 3 if the screenshot is taken via Interactive framework.
+        if (screenshotDetails.length == 3) {
+            String[] testDetails = screenshotDetails[0].split("#");
+            // If com.android.interactive.testrules.TestNameSaver is enabled,
+            // the test class and test case are parsed. Otherwise aren't.
+            if (testDetails.length == 2) {
+                return new ScreenshotTagData(
+                        testDetails[0], testDetails[1], screenshotFileName, screenshotDetails[1]);
+            } else {
+                CLog.w(
+                        "Found a screenshot that doesn't contain test package and class info: %s",
+                        screenshotFileName);
+                return new ScreenshotTagData(
+                        screenshotDetails[0],
+                        screenshotDetails[0],
+                        screenshotFileName,
+                        screenshotDetails[1]);
+            }
+        } else {
+            CLog.i(
+                    "Found a screenshot that isn't taken via Interactive library: %s",
+                    screenshotFileName);
+            return new ScreenshotTagData(
+                    screenshotFileName, screenshotFileName, screenshotFileName, screenshotFileName);
+        }
+    }
+}
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/DynamicConfigPusher.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/DynamicConfigPusher.java
index 15f9f2b2..ceb888d3 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/DynamicConfigPusher.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/DynamicConfigPusher.java
@@ -15,6 +15,8 @@
  */
 package com.android.compatibility.common.tradefed.targetprep;
 
+import static com.android.tradefed.targetprep.UserHelper.getRunTestsAsUser;
+
 import com.android.annotations.VisibleForTesting;
 import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
 import com.android.compatibility.common.util.DynamicConfig;
@@ -176,11 +178,12 @@ public class DynamicConfigPusher extends BaseTargetPreparer
                     String.format(
                             "%s%s.dynamic",
                             DynamicConfig.CONFIG_FOLDER_ON_DEVICE, createModuleName());
-            if (!device.pushFile(hostFile, deviceDest)) {
+            int userId = getRunTestsAsUser(testInfo);
+            if (!device.pushFile(hostFile, deviceDest, userId)) {
                 throw new TargetSetupError(
                         String.format(
-                                "Failed to push local '%s' to remote '%s'",
-                                hostFile.getAbsolutePath(), deviceDest),
+                                "Failed to push local '%s' to remote '%s for user %d'",
+                                hostFile.getAbsolutePath(), deviceDest, userId),
                         device.getDeviceDescriptor(),
                         DeviceErrorIdentifier.FAIL_PUSH_FILE);
             }
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
index b7887796..4644af55 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
@@ -34,13 +34,19 @@ import com.android.tradefed.targetprep.TargetSetupError;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.StreamUtil;
 
+import com.google.common.collect.Sets;
+
+import java.io.BufferedReader;
 import java.io.File;
 import java.io.FileNotFoundException;
+import java.io.FileReader;
 import java.io.IOException;
 import java.io.InputStream;
 import java.nio.file.Files;
+import java.util.Arrays;
 import java.util.HashMap;
 import java.util.HashSet;
+import java.util.List;
 import java.util.Map;
 import java.util.Properties;
 import java.util.Set;
@@ -74,6 +80,9 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
                             + "dependencies. Optional for incremental dEQP.")
     private File mExtraDependency = null;
 
+    @Option(name = "run-mode", description = "The run mode for incremental dEQP.")
+    private RunMode mRunMode = RunMode.BUILD_APPROVAL;
+
     @Option(
             name = "fallback-strategy",
             description =
@@ -81,6 +90,14 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
                             + "for the builds fails.")
     private FallbackStrategy mFallbackStrategy = FallbackStrategy.ABORT_IF_ANY_EXCEPTION;
 
+    private enum RunMode {
+        // Initial application for a device to verify that the feature can capture all the
+        // dependencies by the representative dEQP tests.
+        DEVICE_APPLICATION,
+        // Running incremental dEQP for build approvals after the device is allowlisted.
+        BUILD_APPROVAL;
+    }
+
     private enum FallbackStrategy {
         // Continues to run full dEQP tests no matter an exception is thrown or not.
         RUN_FULL_DEQP,
@@ -91,12 +108,26 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
 
     private static final String MODULE_NAME = "CtsDeqpTestCases";
     private static final String DEVICE_DEQP_DIR = "/data/local/tmp";
-    private static final String[] TEST_LIST =
-            new String[] {"vk-32", "vk-64", "gles3-32", "gles3-64"};
+    private static final List<String> BASELINE_DEQP_TEST_LIST =
+            Arrays.asList(
+                    "gles2-incremental-deqp-baseline",
+                    "gles3-incremental-deqp-baseline",
+                    "gles31-incremental-deqp-baseline",
+                    "vk-incremental-deqp-baseline");
+    private static final List<String> REPRESENTATIVE_DEQP_TEST_LIST =
+            Arrays.asList("vk-incremental-deqp", "gles3-incremental-deqp");
+    private static final List<String> DEQP_BINARY_LIST =
+            Arrays.asList("deqp-binary32", "deqp-binary64");
+    private static final String DEQP_CASE_LIST_FILE_EXTENSION = ".txt";
+    private static final String PERF_FILE_EXTENSION = ".data";
+    private static final String LOG_FILE_EXTENSION = ".qpa";
     private static final String BASE_BUILD_FINGERPRINT_ATTRIBUTE = "base_build_fingerprint";
     private static final String CURRENT_BUILD_FINGERPRINT_ATTRIBUTE = "current_build_fingerprint";
     private static final String MODULE_ATTRIBUTE = "module";
     private static final String MODULE_NAME_ATTRIBUTE = "module_name";
+    private static final String FINGERPRINT = "ro.build.fingerprint";
+    private static final String BASELINE_DEPENDENCY_ATTRIBUTE = "baseline_deps";
+    private static final String MISSING_DEPENDENCY_ATTRIBUTE = "missing_deps";
     private static final String DEPENDENCY_ATTRIBUTE = "deps";
     private static final String EXTRA_DEPENDENCY_ATTRIBUTE = "extra_deps";
     private static final String DEPENDENCY_CHANGES_ATTRIBUTE = "deps_changes";
@@ -105,7 +136,6 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
     private static final String DEPENDENCY_BASE_BUILD_HASH_ATTRIBUTE = "base_build_hash";
     private static final String DEPENDENCY_CURRENT_BUILD_HASH_ATTRIBUTE = "current_build_hash";
     private static final String NULL_BUILD_HASH = "0";
-    private static final String DEQP_BINARY_FILE_NAME_32 = "deqp-binary32";
 
     private static final String DEPENDENCY_DETAIL_MISSING_IN_CURRENT = "MISSING_IN_CURRENT_BUILD";
     private static final String DEPENDENCY_DETAIL_MISSING_IN_BASE = "MISSING_IN_BASE_BUILD";
@@ -117,8 +147,13 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
     private static final Pattern EXCLUDE_DEQP_PATTERN =
             Pattern.compile("(^/data/|^/apex/|^\\[vdso" + "\\]|^/dmabuf|^/kgsl-3d0|^/mali csf)");
 
+    public static final String INCREMENTAL_DEQP_BASELINE_ATTRIBUTE_NAME =
+            "incremental-deqp-baseline";
     public static final String INCREMENTAL_DEQP_ATTRIBUTE_NAME = "incremental-deqp";
-    public static final String REPORT_NAME = "IncrementalCtsDeviceInfo.deviceinfo.json";
+    public static final String INCREMENTAL_DEQP_BASELINE_REPORT_NAME =
+            "IncrementalCtsBaselineDeviceInfo.deviceinfo.json";
+    public static final String INCREMENTAL_DEQP_REPORT_NAME =
+            "IncrementalCtsDeviceInfo.deviceinfo.json";
 
     @Override
     public void setUp(TestInformation testInfo)
@@ -128,7 +163,11 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
             CompatibilityBuildHelper buildHelper =
                     new CompatibilityBuildHelper(testInfo.getBuildInfo());
             IInvocationContext context = testInfo.getContext();
-            runIncrementalDeqp(context, device, buildHelper);
+            if (RunMode.DEVICE_APPLICATION.equals(mRunMode)) {
+                verifyIncrementalDeqp(context, device, buildHelper);
+            } else {
+                runIncrementalDeqp(context, device, buildHelper);
+            }
         } catch (Exception e) {
             if (mFallbackStrategy == FallbackStrategy.ABORT_IF_ANY_EXCEPTION) {
                 // Rethrows the exception to abort the task.
@@ -138,6 +177,79 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
         }
     }
 
+    /**
+     * Checks if the dependencies identified by the incremental dEQP test list match up with the
+     * dependencies identified by the dEQP baseline test list.
+     *
+     * <p>Synchronize this method so that multiple shards won't run it multiple times.
+     */
+    protected void verifyIncrementalDeqp(
+            IInvocationContext context, ITestDevice device, CompatibilityBuildHelper buildHelper)
+            throws TargetSetupError, DeviceNotAvailableException {
+        // Make sure synchronization is on the class not the object.
+        synchronized (IncrementalDeqpPreparer.class) {
+            File jsonFile;
+            try {
+                File deviceInfoDir =
+                        new File(buildHelper.getResultDir(), DeviceInfo.RESULT_DIR_NAME);
+                jsonFile = new File(deviceInfoDir, INCREMENTAL_DEQP_BASELINE_REPORT_NAME);
+                if (jsonFile.exists()) {
+                    CLog.i("Another shard has already checked dEQP baseline dependencies.");
+                    return;
+                }
+            } catch (FileNotFoundException e) {
+                throw new TargetSetupError(
+                        "Fail to read invocation result directory.",
+                        device.getDeviceDescriptor(),
+                        TestErrorIdentifier.TEST_ABORTED);
+            }
+
+            Set<String> baselineDependencies = getDeqpDependencies(device, BASELINE_DEQP_TEST_LIST);
+            Set<String> representativeDependencies =
+                    getDeqpDependencies(device, REPRESENTATIVE_DEQP_TEST_LIST);
+            Set<String> missingDependencies =
+                    Sets.difference(baselineDependencies, representativeDependencies);
+
+            // Write identified dependencies to device info report.
+            try (HostInfoStore store = new HostInfoStore(jsonFile)) {
+                store.open();
+
+                store.addResult(BASE_BUILD_FINGERPRINT_ATTRIBUTE, device.getProperty(FINGERPRINT));
+                store.startArray(MODULE_ATTRIBUTE);
+                store.startGroup(); // Module
+                store.addResult(MODULE_NAME_ATTRIBUTE, MODULE_NAME);
+                store.addListResult(
+                        BASELINE_DEPENDENCY_ATTRIBUTE,
+                        baselineDependencies.stream().sorted().collect(Collectors.toList()));
+                store.addListResult(
+                        MISSING_DEPENDENCY_ATTRIBUTE,
+                        missingDependencies.stream().sorted().collect(Collectors.toList()));
+                // Add an attribute to all shard's build info.
+                for (IBuildInfo bi : context.getBuildInfos()) {
+                    bi.addBuildAttribute(INCREMENTAL_DEQP_BASELINE_ATTRIBUTE_NAME, "");
+                }
+                store.endGroup(); // Module
+                store.endArray();
+            } catch (IOException e) {
+                throw new TargetSetupError(
+                        "Failed to collect dependencies",
+                        e,
+                        device.getDeviceDescriptor(),
+                        TestErrorIdentifier.TEST_ABORTED);
+            } catch (Exception e) {
+                throw new TargetSetupError(
+                        "Failed to write incremental dEQP baseline report",
+                        e,
+                        device.getDeviceDescriptor(),
+                        TestErrorIdentifier.TEST_ABORTED);
+            } finally {
+                if (jsonFile.exists() && jsonFile.length() == 0) {
+                    FileUtil.deleteFile(jsonFile);
+                }
+            }
+        }
+    }
+
     /**
      * Runs a check to determine if the current build has changed dEQP dependencies or not. Will
      * signal to dEQP test runner whether the majority of dEQP cases can be skipped, and also
@@ -154,7 +266,7 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
             try {
                 File deviceInfoDir =
                         new File(buildHelper.getResultDir(), DeviceInfo.RESULT_DIR_NAME);
-                jsonFile = new File(deviceInfoDir, REPORT_NAME);
+                jsonFile = new File(deviceInfoDir, INCREMENTAL_DEQP_REPORT_NAME);
                 if (jsonFile.exists()) {
                     CLog.i("Another shard has already checked dEQP dependencies.");
                     return;
@@ -166,7 +278,8 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
                         TestErrorIdentifier.TEST_ABORTED);
             }
 
-            Set<String> simpleperfDependencies = getDeqpDependencies(device);
+            Set<String> simpleperfDependencies =
+                    getDeqpDependencies(device, REPRESENTATIVE_DEQP_TEST_LIST);
             Set<String> extraDependencies = parseExtraDependency(device);
             Set<String> dependencies = new HashSet<>(simpleperfDependencies);
             dependencies.addAll(extraDependencies);
@@ -299,54 +412,40 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
     }
 
     /** Gets the filename of dEQP dependencies in build. */
-    private Set<String> getDeqpDependencies(ITestDevice device)
-            throws DeviceNotAvailableException, TargetSetupError {
+    private Set<String> getDeqpDependencies(ITestDevice device, List<String> testList)
+            throws TargetSetupError, DeviceNotAvailableException {
         Set<String> result = new HashSet<>();
 
-        for (String testName : TEST_LIST) {
-            String perfFile = DEVICE_DEQP_DIR + "/" + testName + ".data";
-            String binaryFile = DEVICE_DEQP_DIR + "/" + getBinaryFileName(testName);
-            String testFile = DEVICE_DEQP_DIR + "/" + getTestFileName(testName);
-            String logFile = DEVICE_DEQP_DIR + "/" + testName + ".qpa";
-
-            String command =
-                    String.format(
-                            "cd %s && simpleperf record -o %s %s --deqp-caselist-file=%s "
-                                    + "--deqp-log-images=disable --deqp-log-shader-sources=disable "
-                                    + "--deqp-log-filename=%s --deqp-surface-type=fbo "
-                                    + "--deqp-surface-width=2048 --deqp-surface-height=2048",
-                            DEVICE_DEQP_DIR, perfFile, binaryFile, testFile, logFile);
-            device.executeShellCommand(command);
-
-            // Check the test log.
-            String testFileContent = device.pullFileContents(testFile);
-            if (testFileContent == null || testFileContent.isEmpty()) {
-                throw new TargetSetupError(
-                        String.format("Fail to read test file: %s", testFile),
-                        device.getDeviceDescriptor(),
-                        TestErrorIdentifier.TEST_ABORTED);
-            }
-            String logContent = device.pullFileContents(logFile);
-            if (logContent == null || logContent.isEmpty()) {
-                throw new TargetSetupError(
-                        String.format("Fail to read simpleperf log file: %s", logFile),
-                        device.getDeviceDescriptor(),
-                        TestErrorIdentifier.TEST_ABORTED);
-            }
+        for (String test : testList) {
+            for (String binaryName : DEQP_BINARY_LIST) {
+                String fileNamePrefix = test + "-" + binaryName;
+                String perfFile = DEVICE_DEQP_DIR + "/" + fileNamePrefix + PERF_FILE_EXTENSION;
+                String binaryFile = DEVICE_DEQP_DIR + "/" + binaryName;
+                String testFile = DEVICE_DEQP_DIR + "/" + test + DEQP_CASE_LIST_FILE_EXTENSION;
+                String logFile = DEVICE_DEQP_DIR + "/" + fileNamePrefix + LOG_FILE_EXTENSION;
 
-            if (!checkTestLog(testFileContent, logContent)) {
-                throw new TargetSetupError(
-                        "dEQP binary tests are not executed. This may caused by test crash.",
-                        device.getDeviceDescriptor(),
-                        TestErrorIdentifier.TEST_ABORTED);
+                String command =
+                        String.format(
+                                "cd %s && simpleperf record -o %s %s --deqp-caselist-file=%s"
+                                    + " --deqp-log-images=disable --deqp-log-shader-sources=disable"
+                                    + " --deqp-log-filename=%s --deqp-surface-type=fbo"
+                                    + " --deqp-surface-width=2048 --deqp-surface-height=2048",
+                                DEVICE_DEQP_DIR, perfFile, binaryFile, testFile, logFile);
+                device.executeShellCommand(command);
+
+                String dumpFile = DEVICE_DEQP_DIR + "/" + fileNamePrefix + "-perf-dump.txt";
+                String dumpCommand = String.format("simpleperf dump %s > %s", perfFile, dumpFile);
+                device.executeShellCommand(dumpCommand);
+
+                File localDumpFile = device.pullFile(dumpFile);
+                try {
+                    result.addAll(parseDump(localDumpFile));
+                } finally {
+                    if (localDumpFile != null) {
+                        localDumpFile.delete();
+                    }
+                }
             }
-
-            String dumpFile = DEVICE_DEQP_DIR + "/" + testName + "-perf-dump.txt";
-            String dumpCommand = String.format("simpleperf dump %s > %s", perfFile, dumpFile);
-            device.executeShellCommand(dumpCommand);
-            String dumpContent = device.pullFileContents(dumpFile);
-
-            result.addAll(parseDump(dumpContent));
         }
 
         return result;
@@ -387,68 +486,52 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
     }
 
     /** Parses the dump file and gets list of dependencies. */
-    protected Set<String> parseDump(String dumpContent) {
+    protected Set<String> parseDump(File localDumpFile) throws TargetSetupError {
         boolean binaryExecuted = false;
         boolean correctMmap = false;
         Set<String> result = new HashSet<>();
-        for (String line : dumpContent.split("\n")) {
-            if (!binaryExecuted) {
-                // dEQP binary has first been executed.
-                Pattern pattern = Pattern.compile(" comm .*deqp-binary");
-                if (pattern.matcher(line).find()) {
-                    binaryExecuted = true;
-                }
-            } else {
-                // New perf event
-                if (!line.startsWith(" ")) {
-                    // Ignore mmap with misc 1, they are not related to deqp binary
-                    correctMmap = line.startsWith("record mmap") && !line.contains("misc 1");
-                }
+        if (localDumpFile == null) {
+            return result;
+        }
+        BufferedReader br = null;
+        try {
+            br = new BufferedReader(new FileReader(localDumpFile));
+            String line = null;
+            while ((line = br.readLine()) != null) {
+                if (!binaryExecuted) {
+                    // dEQP binary has first been executed.
+                    Pattern pattern = Pattern.compile(" comm .*deqp-binary");
+                    if (pattern.matcher(line).find()) {
+                        binaryExecuted = true;
+                    }
+                } else {
+                    // New perf event
+                    if (!line.startsWith(" ")) {
+                        // Ignore mmap with misc 1, they are not related to deqp binary
+                        correctMmap = line.startsWith("record mmap") && !line.contains("misc 1");
+                    }
 
-                // We have reached the filename for a valid perf event, add to the dependency map if
-                // it isn't in the exclusion pattern
-                if (line.contains("filename") && correctMmap) {
-                    String dependency = line.substring(line.indexOf("filename") + 9).trim();
-                    if (!EXCLUDE_DEQP_PATTERN.matcher(dependency).find()) {
-                        result.add(dependency);
+                    // We have reached the filename for a valid perf event, add to the dependency
+                    // map if it isn't in the exclusion pattern
+                    if (line.contains("filename") && correctMmap) {
+                        String dependency = line.substring(line.indexOf("filename") + 9).trim();
+                        if (!EXCLUDE_DEQP_PATTERN.matcher(dependency).find()) {
+                            result.add(dependency);
+                        }
                     }
                 }
             }
+        } catch (IOException e) {
+            throw new TargetSetupError(
+                    String.format("Could not parse file: %s", localDumpFile.getAbsoluteFile()),
+                    e,
+                    TestErrorIdentifier.TEST_ABORTED);
+        } finally {
+            StreamUtil.close(br);
         }
         return result;
     }
 
-    /** Checks the test log to see if all tests are executed. */
-    protected boolean checkTestLog(String testListContent, String logContent) {
-        int testCount = testListContent.split("\n").length;
-
-        int executedTestCount = 0;
-        for (String line : logContent.split("\n")) {
-            if (line.contains("StatusCode=")) {
-                executedTestCount++;
-            }
-        }
-        return executedTestCount == testCount;
-    }
-
-    /** Gets dEQP binary's test list file based on test name */
-    protected String getTestFileName(String testName) {
-        if (testName.startsWith("vk")) {
-            return "vk-incremental-deqp.txt";
-        } else {
-            return "gles3-incremental-deqp.txt";
-        }
-    }
-
-    /** Gets dEQP binary's name based on the test name. */
-    protected String getBinaryFileName(String testName) {
-        if (testName.endsWith("32")) {
-            return DEQP_BINARY_FILE_NAME_32;
-        } else {
-            return "deqp-binary64";
-        }
-    }
-
     /** Gets the build fingerprint from target files. */
     protected String getBuildFingerPrint(File targetFile, ITestDevice device)
             throws TargetSetupError {
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/InteractiveResultCollector.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/InteractiveResultCollector.java
index 86024b5d..6ee7859c 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/InteractiveResultCollector.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/InteractiveResultCollector.java
@@ -59,7 +59,7 @@ public class InteractiveResultCollector extends BaseTargetPreparer
             description =
                     "Whether creating a sub-directory under the host-path to distinguish "
                             + "files of different modules.")
-    private boolean createModuleDir = false;
+    private boolean createModuleDir = true;
 
     @Option(
             name = "device-cleanup",
@@ -76,6 +76,8 @@ public class InteractiveResultCollector extends BaseTargetPreparer
 
     // Paired with create-module-dir option to create the sub-directory with the module name.
     private String mModuleName = null;
+    // Paired with create-module-dir option to create the sub-directory with the module abi.
+    private String mModuleAbi = null;
 
     @Override
     public void setUp(TestInformation testInfo)
@@ -91,7 +93,7 @@ public class InteractiveResultCollector extends BaseTargetPreparer
             for (String devicePath : devicePaths) {
                 if (!devicePath.isEmpty()) {
                     CLog.d("Start clean up path: %s", devicePath);
-                    mDevice.executeAdbCommand("shell", "rm", "-rf", devicePath);
+                    mDevice.deleteFile(devicePath);
                 }
             }
         }
@@ -136,10 +138,19 @@ public class InteractiveResultCollector extends BaseTargetPreparer
 
     @Override
     public void setInvocationContext(IInvocationContext invocationContext) {
-        if (createModuleDir
-                && invocationContext.getAttributes().get(ModuleDefinition.MODULE_NAME) != null) {
-            mModuleName =
-                    invocationContext.getAttributes().get(ModuleDefinition.MODULE_NAME).get(0);
+        if (createModuleDir) {
+            List<String> moduleNames =
+                    invocationContext.getAttributes().get(ModuleDefinition.MODULE_NAME);
+            if (moduleNames != null && !moduleNames.isEmpty()) {
+                mModuleName = moduleNames.get(0);
+            }
+            List<String> moduleAbis =
+                    invocationContext.getAttributes().get(ModuleDefinition.MODULE_ABI);
+            if (moduleAbis != null && !moduleAbis.isEmpty()) {
+                mModuleAbi = moduleAbis.get(0);
+            }
+        } else {
+            CLog.d("Skip initializing the module name and abi as create-module-dir is false.");
         }
     }
 
@@ -147,6 +158,12 @@ public class InteractiveResultCollector extends BaseTargetPreparer
         File resultDir = new CompatibilityBuildHelper(testInfo.getBuildInfo()).getResultDir();
         return mModuleName == null
                 ? Paths.get(resultDir.getAbsolutePath(), hostPath).toFile()
-                : Paths.get(resultDir.getAbsolutePath(), hostPath, mModuleName).toFile();
+                : getHostResultDir(resultDir.getAbsolutePath());
+    }
+
+    private File getHostResultDir(String resultDir) {
+        String subDirName =
+                mModuleAbi == null ? mModuleName : String.format("%s__%s", mModuleName, mModuleAbi);
+        return Paths.get(resultDir, hostPath, subDirName).toFile();
     }
 }
diff --git a/common/host-side/tradefed/tests/res/testdata/log_2.qpa b/common/host-side/tradefed/tests/res/testdata/log_2.qpa
deleted file mode 100644
index 98c9946d..00000000
--- a/common/host-side/tradefed/tests/res/testdata/log_2.qpa
+++ /dev/null
@@ -1,31 +0,0 @@
-#beginTestCaseResult dEQP-VK.info.build
-<?xml version="1.0" encoding="UTF-8"?>
-<TestCaseResult Version="0.3.4" CasePath="dEQP-VK.info.build" CaseType="SelfValidate">
- <Text>DE_OS: DE_OS_ANDROID
-DE_CPU: DE_CPU_ARM
-DE_PTR_SIZE: 4
-DE_ENDIANNESS: DE_LITTLE_ENDIAN
-DE_COMPILER: DE_COMPILER_CLANG
-DE_DEBUG: false
-</Text>
- <Number Name="TestDuration" Description="Test case duration in microseconds" Tag="Time" Unit="us">52</Number>
- <Result StatusCode="Pass">Not validated</Result>
-</TestCaseResult>
-
-#endTestCaseResult
-
-#beginTestCaseResult dEQP-VK.info.device
-<?xml version="1.0" encoding="UTF-8"?>
-<TestCaseResult Version="0.3.4" CasePath="dEQP-VK.info.device" CaseType="SelfValidate">
- <Text>Using --deqp-vk-device-id=1</Text>
- <Text>apiVersion: 1.1.128
-driverVersion: 0x801ea000
-deviceName: Adreno (TM) 640
-vendorID: 0x00005143
-deviceID: 0x06040001
-</Text>
- <Number Name="TestDuration" Description="Test case duration in microseconds" Tag="Time" Unit="us">24</Number>
- <Result StatusCode="Pass">Not validated</Result>
-</TestCaseResult>
-
-#endTestCaseResult
diff --git a/common/host-side/tradefed/tests/res/testdata/perf-dump.txt b/common/host-side/tradefed/tests/res/testdata/perf-dump.txt
index 1e29eb07..a144abea 100644
--- a/common/host-side/tradefed/tests/res/testdata/perf-dump.txt
+++ b/common/host-side/tradefed/tests/res/testdata/perf-dump.txt
@@ -29,7 +29,7 @@ record comm: type 3, misc 8192, size 64
 record mmap2: type 10, misc 8194, size 136
   pid 23365, tid 23365, addr 0x58b817b000, len 0x3228000
   pgoff 0x0, maj 253, min 9, ino 14709, ino_generation 2575019956
-  prot 1, flags 6146, filename file_2
+  prot 1, flags 6146, filename /system/deqp_dependency_file_a.so
   sample_id: pid 23365, tid 23365
   sample_id: time 595063921188552
   sample_id: id 23808
@@ -69,7 +69,7 @@ record mmap2: type 10, misc 8194, size 136
 record mmap2: type 10, misc 8194, size 136
   pid 23365, tid 23365, addr 0x58b817b000, len 0x3228000
   pgoff 0x0, maj 253, min 9, ino 14709, ino_generation 2575019956
-  prot 1, flags 6146, filename file_3
+  prot 1, flags 6146, filename /vendor/deqp_dependency_file_b.so
   sample_id: pid 23365, tid 23365
   sample_id: time 595063921188552
   sample_id: id 23808
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/CertificationChecksumHelperTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/CertificationChecksumHelperTest.java
index c92dbed7..64e07037 100644
--- a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/CertificationChecksumHelperTest.java
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/CertificationChecksumHelperTest.java
@@ -70,6 +70,9 @@ public class CertificationChecksumHelperTest {
         results.add(run1);
         TestRunResult run2 = createFakeResults("run2", 3);
         results.add(run2);
+        TestRunResult run3 =
+                createFakeResultWithAssumptionFailure("run3", "expected:<-25.0> but was:<15.0>");
+        results.add(run3);
         boolean res = CertificationChecksumHelper.tryCreateChecksum(
                 mWorkingDir, results, FINGERPRINT);
         assertTrue(res);
@@ -112,6 +115,13 @@ public class CertificationChecksumHelperTest {
         assertTrue(
                 resultChecksum.mightContain(
                         "thisismyfingerprint/run2/com.class.path#testMethod2/pass//"));
+        // Check run3
+        assertTrue(resultChecksum.mightContain("thisismyfingerprint/run3/true/0"));
+        assertTrue(resultChecksum.mightContain("thisismyfingerprint/run3/0"));
+        assertTrue(
+                resultChecksum.mightContain(
+                        "thisismyfingerprint/run3/com.class.path#testMethod/ASSUMPTION_FAILURE/expected:&lt;-25.0&gt;"
+                            + " but was:&lt;15.0&gt;/"));
     }
 
     private TestRunResult createFakeResults(String runName, int testCount) {
@@ -125,4 +135,14 @@ public class CertificationChecksumHelperTest {
         results.testRunEnded(500L, new HashMap<String, Metric>());
         return results;
     }
+
+    private TestRunResult createFakeResultWithAssumptionFailure(String runName, String trackTrace) {
+        TestRunResult results = new TestRunResult();
+        results.testRunStarted(runName, 1);
+        TestDescription test = new TestDescription("com.class.path", "testMethod");
+        results.testStarted(test);
+        results.testAssumptionFailure(test, trackTrace);
+        results.testRunEnded(500L, new HashMap<String, Metric>());
+        return results;
+    }
 }
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/InteractiveResultReporterTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/InteractiveResultReporterTest.java
new file mode 100644
index 00000000..66b43b51
--- /dev/null
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/InteractiveResultReporterTest.java
@@ -0,0 +1,331 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.compatibility.common.tradefed.result.suite;
+
+import static com.android.compatibility.common.tradefed.result.suite.InteractiveResultReporter.CASE_TAG;
+import static com.android.compatibility.common.tradefed.result.suite.InteractiveResultReporter.DEFAULT_MODULE_NAME;
+import static com.android.compatibility.common.tradefed.result.suite.InteractiveResultReporter.ENCODING;
+import static com.android.compatibility.common.tradefed.result.suite.InteractiveResultReporter.MODULE_TAG;
+import static com.android.compatibility.common.tradefed.result.suite.InteractiveResultReporter.NS;
+import static com.android.compatibility.common.tradefed.result.suite.InteractiveResultReporter.SCREENSHOTS_DIR_NAME;
+import static com.android.compatibility.common.tradefed.result.suite.InteractiveResultReporter.SCREENSHOTS_METADATA_FILE_NAME;
+import static com.android.compatibility.common.tradefed.result.suite.InteractiveResultReporter.SCREENSHOT_TAG;
+import static com.android.compatibility.common.tradefed.result.suite.InteractiveResultReporter.ScreenshotTagData;
+import static com.android.compatibility.common.tradefed.result.suite.InteractiveResultReporter.TEST_TAG;
+
+import static org.hamcrest.CoreMatchers.containsString;
+import static org.hamcrest.MatcherAssert.assertThat;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+
+import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
+import com.android.tradefed.build.DeviceBuildInfo;
+import com.android.tradefed.config.ConfigurationDef;
+import com.android.tradefed.invoker.IInvocationContext;
+import com.android.tradefed.invoker.InvocationContext;
+import com.android.tradefed.util.FileUtil;
+
+import org.junit.After;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.xmlpull.v1.XmlPullParserFactory;
+import org.xmlpull.v1.XmlSerializer;
+
+import java.io.File;
+import java.io.IOException;
+import java.io.StringWriter;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import java.util.Arrays;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+
+/** Unit tests for {@link InteractiveResultReporter}. */
+@RunWith(JUnit4.class)
+public final class InteractiveResultReporterTest {
+
+    private static final String INTERACTIVE_STEP_1 = "VerifyAppMenuStep";
+    private static final String INTERACTIVE_STEP_2 = "VerifyScreenshot";
+    private static final String SCREENSHOT_SUFFIX = "123456789.png";
+    private static final String TEST_CLASS_1 = "com.google.android.gts.SampleTest";
+    private static final String TEST_CLASS_2 = "com.google.android.gts.SampleDeviceTest";
+    private static final String TEST_CASE_1 = "testScreenshot";
+    private static final String TEST_CASE_2 = "testDeviceScreenshot";
+    private static final String SCREENSHOT_FILE_1 = "screenshot.png";
+    private static final String SCREENSHOT_FILE_2 =
+            String.format("%s__%s__%s", TEST_CLASS_1, INTERACTIVE_STEP_1, SCREENSHOT_SUFFIX);
+    private static final String SCREENSHOT_FILE_3 =
+            String.format(
+                    "%s#%s__%s__%s",
+                    TEST_CLASS_1, TEST_CASE_1, INTERACTIVE_STEP_1, SCREENSHOT_SUFFIX);
+    private static final String SCREENSHOT_FILE_4 =
+            String.format(
+                    "%s#%s__%s__%s",
+                    TEST_CLASS_1, TEST_CASE_1, INTERACTIVE_STEP_2, SCREENSHOT_SUFFIX);
+    private static final String SCREENSHOT_FILE_5 =
+            String.format(
+                    "%s#%s__%s__%s",
+                    TEST_CLASS_2, TEST_CASE_1, INTERACTIVE_STEP_1, SCREENSHOT_SUFFIX);
+    private static final String SCREENSHOT_FILE_6 =
+            String.format(
+                    "%s#%s__%s__%s",
+                    TEST_CLASS_2, TEST_CASE_2, INTERACTIVE_STEP_2, SCREENSHOT_SUFFIX);
+
+    private DeviceBuildInfo mDeviceBuild;
+
+    @After
+    public void tearDown() throws Exception {
+        if (mDeviceBuild != null) {
+            FileUtil.recursiveDelete(new CompatibilityBuildHelper(mDeviceBuild).getRootDir());
+        }
+    }
+
+    @Test
+    public void invocationStarted_mResultDirInitialized() throws Exception {
+        File resultDir = getFakeResultDir(false);
+        IInvocationContext context = new InvocationContext();
+        context.addDeviceBuildInfo(ConfigurationDef.DEFAULT_DEVICE_NAME, mDeviceBuild);
+        InteractiveResultReporter resultReporter = new InteractiveResultReporter();
+
+        resultReporter.invocationStarted(context);
+
+        assertEquals(
+                resultReporter.getScreenshotsMetadataFilePath().getAbsolutePath(),
+                Paths.get(
+                                resultDir.getAbsolutePath(),
+                                SCREENSHOTS_DIR_NAME,
+                                SCREENSHOTS_METADATA_FILE_NAME)
+                        .toAbsolutePath()
+                        .toString());
+    }
+
+    @Test
+    public void invocationEnded_noScreenshotsDir_doesNothing() throws Exception {
+        File resultDir = getFakeResultDir(false);
+        IInvocationContext context = new InvocationContext();
+        context.addDeviceBuildInfo(ConfigurationDef.DEFAULT_DEVICE_NAME, mDeviceBuild);
+        InteractiveResultReporter resultReporter = new InteractiveResultReporter();
+
+        resultReporter.invocationStarted(context);
+        resultReporter.invocationEnded(1000);
+
+        assertFalse(Files.exists(Paths.get(resultDir.getAbsolutePath(), SCREENSHOTS_DIR_NAME)));
+    }
+
+    @Test
+    public void isScreenshotFile_byFileExtension() {
+        assertTrue(InteractiveResultReporter.isScreenshotFile(Path.of("tmp/screenshot_1.png")));
+        assertTrue(InteractiveResultReporter.isScreenshotFile(Path.of("screenshot_2.jpeg")));
+        assertTrue(InteractiveResultReporter.isScreenshotFile(Path.of("../screenshot_3.jpg")));
+        assertFalse(InteractiveResultReporter.isScreenshotFile(Path.of("screenshot_4")));
+    }
+
+    @Test
+    public void genScreenshotsMetadataFile_verifyFileContent() throws Exception {
+        File resultDir = getFakeResultDir(true);
+        File screenshotsDir = new File(resultDir, SCREENSHOTS_DIR_NAME);
+        String moduleName1 = "testModule1";
+        String moduleName2 = "testModule2";
+        prepareModuleDir(
+                screenshotsDir,
+                moduleName1 + "__x86",
+                Arrays.asList(SCREENSHOT_FILE_3, SCREENSHOT_FILE_6));
+        prepareModuleDir(screenshotsDir, moduleName2, Arrays.asList(SCREENSHOT_FILE_1));
+        new File(screenshotsDir, SCREENSHOT_FILE_1).createNewFile();
+        IInvocationContext context = new InvocationContext();
+        context.addDeviceBuildInfo(ConfigurationDef.DEFAULT_DEVICE_NAME, mDeviceBuild);
+        InteractiveResultReporter resultReporter = new InteractiveResultReporter();
+        File screenshotMetadataFile = new File(screenshotsDir, SCREENSHOTS_METADATA_FILE_NAME);
+
+        resultReporter.invocationStarted(context);
+        resultReporter.genScreenshotsMetadataFile(screenshotMetadataFile);
+
+        String xmlContent = FileUtil.readStringFromFile(screenshotMetadataFile);
+        verifyModuleTags(xmlContent, Arrays.asList(moduleName1, moduleName2, DEFAULT_MODULE_NAME));
+        verifyTestCaseTags(
+                xmlContent, Arrays.asList(TEST_CLASS_1, TEST_CLASS_2, SCREENSHOT_FILE_1));
+        verifyTestTags(xmlContent, Arrays.asList(TEST_CASE_1, TEST_CASE_2, SCREENSHOT_FILE_1));
+        verifyScreenshotTags(
+                xmlContent, Arrays.asList(SCREENSHOT_FILE_3, SCREENSHOT_FILE_6, SCREENSHOT_FILE_1));
+    }
+
+    private static void prepareModuleDir(
+            File screenshotsDir, String moduleNameWithAbi, List<String> screenshotNames)
+            throws IOException {
+        File moduleDir = new File(screenshotsDir, moduleNameWithAbi);
+        moduleDir.mkdirs();
+        for (String screenshotName : screenshotNames) {
+            new File(moduleDir, screenshotName).createNewFile();
+        }
+    }
+
+    @Test
+    public void addScreenshotTags_verifyXmlContent() throws Exception {
+        XmlSerializer serializer = XmlPullParserFactory.newInstance().newSerializer();
+        StringWriter writer = new StringWriter();
+        serializer.setOutput(writer);
+        serializer.startDocument(ENCODING, false);
+        serializer.startTag(NS, MODULE_TAG);
+        InteractiveResultReporter.addScreenshotTags(
+                serializer, Arrays.asList(SCREENSHOT_FILE_1, SCREENSHOT_FILE_3, SCREENSHOT_FILE_6));
+        serializer.endTag(NS, MODULE_TAG);
+        serializer.endDocument();
+
+        String xmlContent = writer.toString();
+
+        verifyTestCaseTags(
+                xmlContent, Arrays.asList(SCREENSHOT_FILE_1, TEST_CLASS_1, TEST_CLASS_2));
+        verifyTestTags(xmlContent, Arrays.asList(SCREENSHOT_FILE_1, TEST_CASE_1, TEST_CASE_2));
+        verifyScreenshotTags(
+                xmlContent, Arrays.asList(SCREENSHOT_FILE_1, SCREENSHOT_FILE_3, SCREENSHOT_FILE_6));
+    }
+
+    @Test
+    public void getScreenshotTagDatas_verifyResultSorted() {
+        Map<String, Map<String, List<ScreenshotTagData>>> screenshotTagDatas =
+                InteractiveResultReporter.getScreenshotTagDatas(
+                        Arrays.asList(
+                                SCREENSHOT_FILE_4,
+                                SCREENSHOT_FILE_3,
+                                SCREENSHOT_FILE_5,
+                                SCREENSHOT_FILE_6));
+
+        verifyKeys(screenshotTagDatas.keySet(), Arrays.asList(TEST_CLASS_2, TEST_CLASS_1));
+
+        Map<String, List<ScreenshotTagData>> tagDataOfClass = screenshotTagDatas.get(TEST_CLASS_1);
+        verifyKeys(tagDataOfClass.keySet(), Arrays.asList(TEST_CASE_1));
+        verifyScreenshotTagDatas(
+                tagDataOfClass.get(TEST_CASE_1),
+                Arrays.asList(
+                        new ScreenshotTagData(
+                                TEST_CLASS_1, TEST_CASE_1, SCREENSHOT_FILE_4, INTERACTIVE_STEP_2),
+                        new ScreenshotTagData(
+                                TEST_CLASS_1, TEST_CASE_1, SCREENSHOT_FILE_3, INTERACTIVE_STEP_1)));
+
+        tagDataOfClass = screenshotTagDatas.get(TEST_CLASS_2);
+        verifyKeys(tagDataOfClass.keySet(), Arrays.asList(TEST_CASE_2, TEST_CASE_1));
+        verifyScreenshotTagDatas(
+                tagDataOfClass.get(TEST_CASE_1),
+                Arrays.asList(
+                        new ScreenshotTagData(
+                                TEST_CLASS_2, TEST_CASE_1, SCREENSHOT_FILE_5, INTERACTIVE_STEP_1)));
+        verifyScreenshotTagDatas(
+                tagDataOfClass.get(TEST_CASE_2),
+                Arrays.asList(
+                        new ScreenshotTagData(
+                                TEST_CLASS_2, TEST_CASE_2, SCREENSHOT_FILE_6, INTERACTIVE_STEP_2)));
+    }
+
+    @Test
+    public void getScreenshotTagData_withoutStepInfo() {
+        verifyScreenshotTagData(
+                InteractiveResultReporter.getScreenshotTagData(SCREENSHOT_FILE_1),
+                new ScreenshotTagData(
+                        SCREENSHOT_FILE_1,
+                        SCREENSHOT_FILE_1,
+                        SCREENSHOT_FILE_1,
+                        SCREENSHOT_FILE_1));
+    }
+
+    @Test
+    public void getScreenshotTagData_withoutTestInfo() {
+        verifyScreenshotTagData(
+                InteractiveResultReporter.getScreenshotTagData(SCREENSHOT_FILE_2),
+                new ScreenshotTagData(
+                        TEST_CLASS_1, TEST_CLASS_1, SCREENSHOT_FILE_2, INTERACTIVE_STEP_1));
+    }
+
+    @Test
+    public void getScreenshotTagData_withTestInfo() {
+        verifyScreenshotTagData(
+                InteractiveResultReporter.getScreenshotTagData(SCREENSHOT_FILE_3),
+                new ScreenshotTagData(
+                        TEST_CLASS_1, TEST_CASE_1, SCREENSHOT_FILE_3, INTERACTIVE_STEP_1));
+    }
+
+    private static void verifyModuleTags(String xmlContent, List<String> moduleNames) {
+        for (String moduleName : moduleNames) {
+            verifyXmlContent(xmlContent, MODULE_TAG, moduleName);
+        }
+    }
+
+    private static void verifyTestCaseTags(String xmlContent, List<String> testCaseNames) {
+        for (String testCaseName : testCaseNames) {
+            verifyXmlContent(xmlContent, CASE_TAG, testCaseName);
+        }
+    }
+
+    private static void verifyTestTags(String xmlContent, List<String> testNames) {
+        for (String testName : testNames) {
+            verifyXmlContent(xmlContent, TEST_TAG, testName);
+        }
+    }
+
+    private static void verifyScreenshotTags(String xmlContent, List<String> screenshotNames) {
+        for (String screenshotName : screenshotNames) {
+            verifyXmlContent(xmlContent, SCREENSHOT_TAG, screenshotName);
+        }
+    }
+
+    private static void verifyXmlContent(String xmlContent, String tagName, String nameAttr) {
+        assertThat(xmlContent, containsString(String.format("<%s name=\"%s\"", tagName, nameAttr)));
+    }
+
+    private static void verifyKeys(Set<String> keys, List<String> expected) {
+        int i = 0;
+        for (String key : keys) {
+            assertEquals(key, expected.get(i++));
+        }
+        assertEquals(i, expected.size());
+    }
+
+    private static void verifyScreenshotTagDatas(
+            List<ScreenshotTagData> results, List<ScreenshotTagData> expected) {
+        assertEquals(results.size(), expected.size());
+        for (int i = 0; i < results.size(); i++) {
+            verifyScreenshotTagData(results.get(i), expected.get(i));
+        }
+    }
+
+    private static void verifyScreenshotTagData(
+            ScreenshotTagData result, ScreenshotTagData expected) {
+        assertEquals(result.mTestCaseName, expected.mTestCaseName);
+        assertEquals(result.mTestName, expected.mTestName);
+        assertEquals(result.mScreenshotName, expected.mScreenshotName);
+        assertEquals(result.mScreenshotDescription, expected.mScreenshotDescription);
+    }
+
+    private File getFakeResultDir(boolean withScreenshotDir) throws IOException {
+        mDeviceBuild = new DeviceBuildInfo();
+        mDeviceBuild.addBuildAttribute(CompatibilityBuildHelper.SUITE_NAME, "CTS");
+        File rootDir = FileUtil.createTempDir("cts-root-dir");
+        new File(rootDir, "android-cts/results/").mkdirs();
+        mDeviceBuild.addBuildAttribute(
+                CompatibilityBuildHelper.ROOT_DIR, rootDir.getAbsolutePath());
+        mDeviceBuild.addBuildAttribute(
+                CompatibilityBuildHelper.START_TIME_MS, Long.toString(System.currentTimeMillis()));
+        File resultDir = new CompatibilityBuildHelper(mDeviceBuild).getResultDir();
+        resultDir.mkdirs();
+        if (withScreenshotDir) {
+            new File(resultDir, SCREENSHOTS_DIR_NAME).mkdirs();
+        }
+        return resultDir;
+    }
+}
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/DynamicConfigPusherTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/DynamicConfigPusherTest.java
index 06968ae3..13cfc2c5 100644
--- a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/DynamicConfigPusherTest.java
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/DynamicConfigPusherTest.java
@@ -44,10 +44,10 @@ import org.mockito.Mockito;
 
 import java.io.File;
 import java.io.FileNotFoundException;
+import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collection;
 import java.util.HashMap;
-import java.util.LinkedList;
 import java.util.Map;
 
 /**
@@ -56,6 +56,7 @@ import java.util.Map;
 @RunWith(JUnit4.class)
 public class DynamicConfigPusherTest {
     private static final String RESOURCE_DYNAMIC_CONFIG = "test-dynamic-config";
+    private static final String RUN_TESTS_AS_USER_KEY = "RUN_TESTS_AS_USER";
     private DynamicConfigPusher mPreparer;
     private ITestDevice mMockDevice;
     private CompatibilityBuildHelper mMockBuildHelper;
@@ -229,12 +230,77 @@ public class DynamicConfigPusherTest {
         }
     }
 
+    @Test
+    public void testSetUp_usesRunTestsAsUserFromProperty() throws Exception {
+        final File[] localConfig = new File[1];
+        OptionSetter setter = prepareSetupTestTarget(localConfig);
+        // Set target to DEVICE.
+        setter.setOptionValue("target", "device");
+
+        int runTestsAsUserId = 101;
+        mTestInfo.properties().put(RUN_TESTS_AS_USER_KEY, String.valueOf(runTestsAsUserId));
+        when(mMockDevice.pushFile(Mockito.any(), Mockito.any(), Mockito.anyInt())).thenReturn(true);
+
+        mPreparer.setUp(mTestInfo);
+
+        verify(mMockDevice, Mockito.never()).getCurrentUser();
+        // pushFile() is called for the RUN_TESTS_AS_USER set in the TestInfo property.
+        verify(mMockDevice).pushFile(Mockito.any(), Mockito.any(), Mockito.eq(runTestsAsUserId));
+    }
+
+    @Test
+    public void testSetUp_currentUser() throws Exception {
+        final File[] localConfig = new File[1];
+        OptionSetter setter = prepareSetupTestTarget(localConfig);
+        // Set target to DEVICE.
+        setter.setOptionValue("target", "device");
+
+        int currentUserId = 100;
+        when(mMockDevice.getCurrentUser()).thenReturn(currentUserId);
+        when(mMockDevice.pushFile(Mockito.any(), Mockito.any(), Mockito.anyInt())).thenReturn(true);
+
+        mPreparer.setUp(mTestInfo);
+
+        // pushFile() is called for the current user.
+        verify(mMockDevice).pushFile(Mockito.any(), Mockito.any(), Mockito.eq(currentUserId));
+    }
+
     /**
      * Test an end-to-end usage of the dynamic config file from the jar.
      */
     @Test
     public void testSetUp() throws Exception {
         final File[] localConfig = new File[1];
+        prepareSetupTestTarget(localConfig);
+
+        Map<String, String> attributes = new HashMap<>();
+        attributes.put(CompatibilityBuildHelper.SUITE_VERSION, "v1");
+        when(mMockBuildInfo.getBuildAttributes()).thenReturn(attributes);
+        Collection<VersionedFile> versionedFiles = new ArrayList<VersionedFile>();
+        when(mMockBuildInfo.getFiles()).thenReturn(versionedFiles);
+        mPreparer.setInvocationContext(mModuleContext);
+
+        mPreparer.setUp(mTestInfo);
+        ArgumentCaptor<File> capture = ArgumentCaptor.forClass(File.class);
+        verify(mMockBuildInfo)
+                .setFile(
+                        Mockito.contains("moduleName"),
+                        capture.capture(),
+                        Mockito.eq("DYNAMIC_CONFIG_FILE:moduleName"));
+        assertNotNull(localConfig[0]);
+        // Ensure that the extracted file was deleted.
+        assertFalse(localConfig[0].exists());
+        File dynamicFile = capture.getValue();
+        assertTrue(dynamicFile.exists());
+        FileUtil.deleteFile(dynamicFile);
+    }
+
+    /**
+     * Prepares for running tests for DynamicConfigPusher#setUp method.
+     *
+     * @return an {@link OptionSetter} so that each test can override option valuses as necessary.
+     */
+    private OptionSetter prepareSetupTestTarget(File[] localConfig) throws Exception {
         mPreparer =
                 new DynamicConfigPusher() {
                     @Override
@@ -256,22 +322,6 @@ public class DynamicConfigPusherTest {
         // Look up the file under that name instead of the config-filename
         setter.setOptionValue("dynamic-resource-name", RESOURCE_DYNAMIC_CONFIG);
 
-        Map<String, String> attributes = new HashMap<>();
-        attributes.put(CompatibilityBuildHelper.SUITE_VERSION, "v1");
-        when(mMockBuildInfo.getBuildAttributes()).thenReturn(attributes);
-        Collection<VersionedFile> versionedFiles = new LinkedList<VersionedFile>();
-        when(mMockBuildInfo.getFiles()).thenReturn(versionedFiles);
-        mPreparer.setInvocationContext(mModuleContext);
-
-        mPreparer.setUp(mTestInfo);
-        ArgumentCaptor<File> capture = ArgumentCaptor.forClass(File.class);
-        verify(mMockBuildInfo).setFile(Mockito.contains("moduleName"), capture.capture(),
-                Mockito.eq("DYNAMIC_CONFIG_FILE:moduleName"));
-        assertNotNull(localConfig[0]);
-        // Ensure that the extracted file was deleted.
-        assertFalse(localConfig[0].exists());
-        File dynamicFile = capture.getValue();
-        assertTrue(dynamicFile.exists());
-        FileUtil.deleteFile(dynamicFile);
+        return setter;
     }
 }
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
index 82abbaf6..5fb094d4 100644
--- a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
@@ -19,11 +19,14 @@ package com.android.compatibility.common.tradefed.targetprep;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
+import static org.mockito.ArgumentMatchers.endsWith;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.when;
 
 import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
 import com.android.tradefed.build.BuildInfo;
 import com.android.tradefed.build.IBuildInfo;
+import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.invoker.IInvocationContext;
 import com.android.tradefed.invoker.InvocationContext;
@@ -52,6 +55,7 @@ public class IncrementalDeqpPreparerTest {
 
     private IncrementalDeqpPreparer mPreparer;
     private ITestDevice mMockDevice;
+    private OptionSetter mPreparerSetter = null;
 
     @Before
     public void setUp() throws Exception {
@@ -59,6 +63,99 @@ public class IncrementalDeqpPreparerTest {
         mMockDevice = mock(ITestDevice.class);
     }
 
+    @SuppressWarnings("ResultOfMethodCallIgnored")
+    @Test
+    public void testVerifyIncrementalDeqp() throws Exception {
+        File resultDir = FileUtil.createTempDir("result");
+        try {
+            mPreparerSetter = new OptionSetter(mPreparer);
+            mPreparerSetter.setOptionValue(
+                    "incremental-deqp-preparer:run-mode", "DEVICE_APPLICATION");
+            IBuildInfo mMockBuildInfo = new BuildInfo();
+            IInvocationContext mMockContext = new InvocationContext();
+            mMockContext.addDeviceBuildInfo("build", mMockBuildInfo);
+            mMockContext.addAllocatedDevice("device", mMockDevice);
+            File deviceInfoDir = new File(resultDir, "device-info-files");
+            deviceInfoDir.mkdir();
+            CompatibilityBuildHelper mMockBuildHelper =
+                    new CompatibilityBuildHelper(mMockBuildInfo) {
+                        @Override
+                        public File getResultDir() {
+                            return resultDir;
+                        }
+                    };
+            InputStream perfDumpStream = getClass().getResourceAsStream("/testdata/perf-dump.txt");
+            File dumpFile = FileUtil.createTempFile("parseDump", "perf-dump.txt");
+            FileUtil.writeToFile(perfDumpStream, dumpFile);
+            when(mMockDevice.pullFile(endsWith("-perf-dump.txt")))
+                    .thenReturn(dumpFile, null, null, null, null, null);
+
+            File incrementalDeqpBaselineReport =
+                    new File(
+                            deviceInfoDir,
+                            IncrementalDeqpPreparer.INCREMENTAL_DEQP_BASELINE_REPORT_NAME);
+            assertFalse(incrementalDeqpBaselineReport.exists());
+            mPreparer.verifyIncrementalDeqp(mMockContext, mMockDevice, mMockBuildHelper);
+            assertTrue(
+                    mMockBuildInfo
+                            .getBuildAttributes()
+                            .containsKey(
+                                    IncrementalDeqpPreparer
+                                            .INCREMENTAL_DEQP_BASELINE_ATTRIBUTE_NAME));
+            assertTrue(incrementalDeqpBaselineReport.exists());
+        } finally {
+            FileUtil.recursiveDelete(resultDir);
+        }
+    }
+
+    @SuppressWarnings("ResultOfMethodCallIgnored")
+    @Test
+    public void testRunIncrementalDeqp() throws Exception {
+        File resultDir = FileUtil.createTempDir("result");
+        InputStream zipStream =
+                getClass().getResourceAsStream("/testdata/base_build_target-files.zip");
+        File zipFile = FileUtil.createTempFile("targetFile", ".zip");
+        try {
+            FileUtil.writeToFile(zipStream, zipFile);
+            mPreparerSetter = new OptionSetter(mPreparer);
+            mPreparerSetter.setOptionValue(
+                    "incremental-deqp-preparer:base-build", zipFile.getAbsolutePath());
+            mPreparerSetter.setOptionValue(
+                    "incremental-deqp-preparer:current-build", zipFile.getAbsolutePath());
+            IBuildInfo mMockBuildInfo = new BuildInfo();
+            IInvocationContext mMockContext = new InvocationContext();
+            mMockContext.addDeviceBuildInfo("build", mMockBuildInfo);
+            mMockContext.addAllocatedDevice("device", mMockDevice);
+            File deviceInfoDir = new File(resultDir, "device-info-files");
+            deviceInfoDir.mkdir();
+            CompatibilityBuildHelper mMockBuildHelper =
+                    new CompatibilityBuildHelper(mMockBuildInfo) {
+                        @Override
+                        public File getResultDir() {
+                            return resultDir;
+                        }
+                    };
+            InputStream perfDumpStream = getClass().getResourceAsStream("/testdata/perf-dump.txt");
+            File dumpFile = FileUtil.createTempFile("parseDump", "perf-dump.txt");
+            FileUtil.writeToFile(perfDumpStream, dumpFile);
+            when(mMockDevice.pullFile(endsWith("-perf-dump.txt")))
+                    .thenReturn(dumpFile, null, null, null);
+
+            File incrementalDeqpReport =
+                    new File(deviceInfoDir, IncrementalDeqpPreparer.INCREMENTAL_DEQP_REPORT_NAME);
+            assertFalse(incrementalDeqpReport.exists());
+            mPreparer.runIncrementalDeqp(mMockContext, mMockDevice, mMockBuildHelper);
+            assertTrue(
+                    mMockBuildInfo
+                            .getBuildAttributes()
+                            .containsKey(IncrementalDeqpPreparer.INCREMENTAL_DEQP_ATTRIBUTE_NAME));
+            assertTrue(incrementalDeqpReport.exists());
+        } finally {
+            FileUtil.recursiveDelete(resultDir);
+            FileUtil.deleteFile(zipFile);
+        }
+    }
+
     @SuppressWarnings("ResultOfMethodCallIgnored")
     @Test
     public void testSkipPreparerWhenReportExists() throws Exception {
@@ -70,7 +167,8 @@ public class IncrementalDeqpPreparerTest {
             mMockContext.addAllocatedDevice("device", mMockDevice);
             File deviceInfoDir = new File(resultDir, "device-info-files");
             deviceInfoDir.mkdir();
-            File report = new File(deviceInfoDir, IncrementalDeqpPreparer.REPORT_NAME);
+            File report =
+                    new File(deviceInfoDir, IncrementalDeqpPreparer.INCREMENTAL_DEQP_REPORT_NAME);
             report.createNewFile();
             CompatibilityBuildHelper mMockBuildHelper =
                     new CompatibilityBuildHelper(mMockBuildInfo) {
@@ -87,14 +185,19 @@ public class IncrementalDeqpPreparerTest {
     }
 
     @Test
-    public void testParseDump() throws IOException {
+    public void testParseDump() throws Exception {
         InputStream inputStream = getClass().getResourceAsStream("/testdata/perf-dump.txt");
-        String content = StreamUtil.getStringFromStream(inputStream);
-        Set<String> dependency = mPreparer.parseDump(content);
-        Set<String> expect = new HashSet<>();
-        expect.add("file_2");
-        expect.add("file_3");
-        assertEquals(dependency, expect);
+        File dumpFile = FileUtil.createTempFile("parseDump", ".txt");
+        try {
+            FileUtil.writeToFile(inputStream, dumpFile);
+            Set<String> dependency = mPreparer.parseDump(dumpFile);
+            Set<String> expect = new HashSet<>();
+            expect.add("/system/deqp_dependency_file_a.so");
+            expect.add("/vendor/deqp_dependency_file_b.so");
+            assertEquals(dependency, expect);
+        } finally {
+            FileUtil.deleteFile(dumpFile);
+        }
     }
 
     @Test
@@ -132,38 +235,6 @@ public class IncrementalDeqpPreparerTest {
         }
     }
 
-    @Test
-    public void testCheckTestLogAllTestExecuted() throws IOException {
-        InputStream testListStream = getClass().getResourceAsStream("/testdata/test_list.txt");
-        InputStream logStream = getClass().getResourceAsStream("/testdata/log_1.qpa");
-        String testListContent = StreamUtil.getStringFromStream(testListStream);
-        String logContent = StreamUtil.getStringFromStream(logStream);
-
-        assertTrue(mPreparer.checkTestLog(testListContent, logContent));
-    }
-
-    @Test
-    public void testCheckTestLogTestCrashes() throws IOException {
-        InputStream testListStream = getClass().getResourceAsStream("/testdata/test_list.txt");
-        InputStream logStream = getClass().getResourceAsStream("/testdata/log_2.qpa");
-        String testListContent = StreamUtil.getStringFromStream(testListStream);
-        String logContent = StreamUtil.getStringFromStream(logStream);
-
-        assertFalse(mPreparer.checkTestLog(testListContent, logContent));
-    }
-
-    @Test
-    public void testGetTestFileName() {
-        assertEquals(mPreparer.getTestFileName("vk-32"), "vk-incremental-deqp.txt");
-        assertEquals(mPreparer.getTestFileName("gles-32"), "gles3-incremental-deqp.txt");
-    }
-
-    @Test
-    public void testGetBinaryFileName() {
-        assertEquals(mPreparer.getBinaryFileName("vk-32"), "deqp-binary32");
-        assertEquals(mPreparer.getBinaryFileName("vk-64"), "deqp-binary64");
-    }
-
     @Test
     public void getBuildFingerPrint() throws IOException, TargetSetupError {
         // base_build_target-files.zip is a stripped down version of the target-files.zip generated
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/InteractiveResultCollectorTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/InteractiveResultCollectorTest.java
index e66bf65e..02b7928e 100644
--- a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/InteractiveResultCollectorTest.java
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/InteractiveResultCollectorTest.java
@@ -61,17 +61,6 @@ public final class InteractiveResultCollectorTest {
         assertThrows(TargetSetupError.class, () -> mCollector.setUp(mTestInfo));
     }
 
-    @Test
-    public void setUp_deviceCleanup_emptyDevicePaths_doNothing() throws Exception {
-        ITestDevice testDevice = mock(ITestDevice.class);
-        initTestInfo(new DeviceBuildInfo("0", ""), testDevice);
-
-        mCollector.setUp(mTestInfo);
-
-        verify(testDevice, never())
-                .executeAdbCommand(anyString(), anyString(), anyString(), anyString());
-    }
-
     @Test
     public void setUp_deviceClenup_emptyDevicePathSkipped() throws Exception {
         ITestDevice testDevice = mock(ITestDevice.class);
@@ -83,8 +72,8 @@ public final class InteractiveResultCollectorTest {
         mCollector.setUp(mTestInfo);
 
         // Only one execution for DEVICE_PATH.
-        verify(testDevice).executeAdbCommand(anyString(), anyString(), anyString(), anyString());
-        verify(testDevice).executeAdbCommand("shell", "rm", "-rf", DEVICE_PATH);
+        verify(testDevice, never()).deleteFile("");
+        verify(testDevice).deleteFile(DEVICE_PATH);
     }
 
     @Test
```

