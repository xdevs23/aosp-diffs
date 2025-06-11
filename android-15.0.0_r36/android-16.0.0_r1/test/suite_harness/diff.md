```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 2cabacc7..60c5d306 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -4,8 +4,3 @@ google_java_format = true
 [Tool Paths]
 google-java-format = ${REPO_ROOT}/prebuilts/tools/common/google-java-format/google-java-format
 google-java-format-diff = ${REPO_ROOT}/prebuilts/tools/common/google-java-format/google-java-format-diff.py
-
-[Hook Scripts]
-# `^.` is a RegExr that matches any character at the beginning, so this hook
-# is basically applied to ALL files in a git commit.
-aospcheck_hook = ${REPO_ROOT}/tools/tradefederation/core/aosp_sha.sh ${PREUPLOAD_COMMIT} "^."
diff --git a/common/host-side/tradefed/res/config/common-compatibility-config.xml b/common/host-side/tradefed/res/config/common-compatibility-config.xml
index d0f151bd..80628b83 100644
--- a/common/host-side/tradefed/res/config/common-compatibility-config.xml
+++ b/common/host-side/tradefed/res/config/common-compatibility-config.xml
@@ -24,12 +24,12 @@
         <option name="log-level-display" value="WARN" />
     </logger>
     <result_reporter class="com.android.compatibility.common.tradefed.result.ConsoleReporter" />
+    <result_reporter class="com.android.compatibility.common.tradefed.result.suite.CertificationSuiteResultReporter" />
     <result_reporter class="com.android.compatibility.common.tradefed.result.suite.CompatibilityProtoResultReporter">
         <option name="periodic-proto-writing" value="true" />
     </result_reporter>
     <!-- Compact the protos to save space -->
     <result_reporter class="com.android.compatibility.common.tradefed.result.suite.CompactProtoReporter" />
-    <result_reporter class="com.android.compatibility.common.tradefed.result.suite.CertificationSuiteResultReporter" />
     <!-- Create the zip report last always -->
     <result_reporter class="com.android.compatibility.common.tradefed.result.suite.CertificationReportCreator" />
 </configuration>
diff --git a/common/host-side/tradefed/res/config/tf-aosp-compatibility-config.xml b/common/host-side/tradefed/res/config/tf-aosp-compatibility-config.xml
new file mode 100644
index 00000000..9d023690
--- /dev/null
+++ b/common/host-side/tradefed/res/config/tf-aosp-compatibility-config.xml
@@ -0,0 +1,24 @@
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
+<configuration description="AOSP tradefed config for Compatibility suites to run all modules">
+    <include name="common-compatibility-config" />
+    <target_preparer class="com.android.tradefed.targetprep.DeviceSetup" />
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="settings put global verifier_verify_adb_installs 0" />
+        <option name="run-command" value="am switch-user 10" />
+    </target_preparer>
+    <option name="post-boot-command" value="am switch-user 10" />
+</configuration>
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationSuiteResultReporter.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationSuiteResultReporter.java
index c47708db..ff689c91 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationSuiteResultReporter.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CertificationSuiteResultReporter.java
@@ -19,7 +19,6 @@ import com.android.annotations.VisibleForTesting;
 import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
 import com.android.compatibility.common.util.DeviceInfo;
 import com.android.tradefed.build.IBuildInfo;
-import com.android.tradefed.cluster.SubprocessConfigBuilder;
 import com.android.tradefed.config.IConfiguration;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.config.OptionClass;
@@ -324,7 +323,7 @@ public class CertificationSuiteResultReporter extends XmlFormattedGeneratorRepor
     @Override
     public IFormatterGenerator createFormatter() {
         return new CertificationResultXml(
-                createSuiteName(mBuildHelper.getSuiteName()),
+                mBuildHelper.getSuiteName(),
                 mBuildHelper.getSuiteVersion(),
                 createSuiteVariant(),
                 mBuildHelper.getSuitePlan(),
@@ -502,20 +501,6 @@ public class CertificationSuiteResultReporter extends XmlFormattedGeneratorRepor
         CertificationChecksumHelper.tryCreateChecksum(resultDir, results, buildFingerprint);
     }
 
-    private String createSuiteName(String originalSuiteName) {
-        if (mCtsOnGsiVariant) {
-            String commandLine = getConfiguration().getCommandLine();
-            // SubprocessConfigBuilder is added to support ATS current way of running things.
-            // It won't be needed after the R release.
-            if (commandLine.startsWith("cts-on-gsi")
-                    || commandLine.startsWith(
-                            SubprocessConfigBuilder.createConfigName("cts-on-gsi"))) {
-                return "VTS";
-            }
-        }
-        return originalSuiteName;
-    }
-
     private String createSuiteVariant() {
         IConfiguration currentConfig = getConfiguration();
         String commandLine = currentConfig.getCommandLine();
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CompactProtoReporter.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CompactProtoReporter.java
index 2f4fb870..a6778812 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CompactProtoReporter.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CompactProtoReporter.java
@@ -95,7 +95,7 @@ public class CompactProtoReporter
 
     private void compactAllProtos() {
         FileProtoResultReporter fprr = new FileProtoResultReporter();
-        fprr.setFileOutput(mBaseProtoFile);
+        fprr.setOutputFile(mBaseProtoFile);
         ProtoResultParser parser = new ProtoResultParser(fprr, new InvocationContext(), true);
         int index = 0;
         while (new File(mBaseProtoFile.getAbsolutePath() + index).exists()) {
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CompatibilityProtoResultReporter.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CompatibilityProtoResultReporter.java
index f1957987..41bf32cd 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CompatibilityProtoResultReporter.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/result/suite/CompatibilityProtoResultReporter.java
@@ -52,7 +52,7 @@ public class CompatibilityProtoResultReporter extends FileProtoResultReporter
             mBuildHelper = new CompatibilityBuildHelper(invocationContext.getBuildInfos().get(0));
             mResultDir = getProtoResultDirectory(mBuildHelper);
             mBaseProtoFile = new File(mResultDir, PROTO_FILE_NAME);
-            setFileOutput(mBaseProtoFile);
+            setOutputFile(mBaseProtoFile);
         }
         super.processStartInvocation(invocationStartRecord, invocationContext);
     }
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
index 100072ce..cf3857cb 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
@@ -39,28 +39,17 @@ import java.io.File;
 import java.io.FileNotFoundException;
 import java.io.FileReader;
 import java.io.IOException;
-import java.io.InputStream;
 import java.util.Arrays;
 import java.util.HashMap;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Map;
-import java.util.Properties;
 import java.util.Set;
 import java.util.regex.Pattern;
-import java.util.zip.ZipEntry;
-import java.util.zip.ZipFile;
 
 /** Collects the dEQP dependencies and compares the builds. */
 @OptionClass(alias = "incremental-deqp-preparer")
 public class IncrementalDeqpPreparer extends BaseTargetPreparer {
-    @Option(
-            name = "current-build",
-            description =
-                    "Absolute file path to a target file of the current build. Required for"
-                            + " incremental dEQP.")
-    private File mCurrentBuild = null;
-
     @Option(name = "run-mode", description = "The run mode for incremental dEQP.")
     private RunMode mRunMode = RunMode.LIGHTWEIGHT_RUN;
 
@@ -104,19 +93,12 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
     private static final String RUN_MODE_ATTRIBUTE = "run_mode";
     private static final String MODULE_ATTRIBUTE = "module";
     private static final String MODULE_NAME_ATTRIBUTE = "module_name";
-    private static final String FINGERPRINT = "ro.build.fingerprint";
-    private static final String MISSING_DEPENDENCY_ATTRIBUTE = "missing_deps";
     private static final String DEPENDENCY_DETAILS_ATTRIBUTE = "deps_details";
     private static final String DEPENDENCY_NAME_ATTRIBUTE = "dep_name";
     private static final String DEPENDENCY_FILE_HASH_ATTRIBUTE = "file_hash";
 
     private static final Pattern EXCLUDE_DEQP_PATTERN =
             Pattern.compile("(^/data/|^/apex/|^\\[vdso" + "\\]|^/dmabuf|^/kgsl-3d0|^/mali csf)");
-
-    public static final String INCREMENTAL_DEQP_BASELINE_ATTRIBUTE_NAME =
-            "incremental-deqp-baseline";
-    public static final String INCREMENTAL_DEQP_TRUSTED_BUILD_ATTRIBUTE_NAME =
-            "incremental-deqp-trusted-build";
     public static final String INCREMENTAL_DEQP_ATTRIBUTE_NAME = "incremental-deqp";
     public static final String INCREMENTAL_DEQP_REPORT_NAME =
             "IncrementalCtsDeviceInfo.deviceinfo.json";
@@ -169,7 +151,6 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
                         device.getDeviceDescriptor(),
                         TestErrorIdentifier.TEST_ABORTED);
             }
-            validateBuildFingerprint(mCurrentBuild, device);
 
             List<String> deqpTestList =
                     RunMode.FULL_RUN.equals(mRunMode)
@@ -185,8 +166,7 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
                 store.startGroup(); // Module
                 store.addResult(MODULE_NAME_ATTRIBUTE, MODULE_NAME);
                 store.startArray(DEPENDENCY_DETAILS_ATTRIBUTE);
-                Map<String, String> currentBuildHashMap =
-                        getTargetFileHash(dependencies, mCurrentBuild);
+                Map<String, String> currentBuildHashMap = getFileHash(dependencies, device);
                 for (String dependency : dependencies) {
                     store.startGroup();
                     store.addResult(DEPENDENCY_NAME_ATTRIBUTE, dependency);
@@ -258,38 +238,21 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
         return result;
     }
 
-    /** Gets the hash value of the specified file's content from the target file. */
-    protected Map<String, String> getTargetFileHash(Set<String> fileNames, File targetFile)
-            throws IOException, TargetSetupError {
-        ZipFile zipFile = new ZipFile(targetFile);
-
-        Map<String, String> hashMap = new HashMap<>();
+    /** Gets the hash value of the specified file's content from the device. */
+    protected Map<String, String> getFileHash(Set<String> fileNames, ITestDevice device)
+            throws DeviceNotAvailableException, TargetSetupError {
+        Map<String, String> fileHashes = new HashMap<>();
         for (String file : fileNames) {
-            // Convert top directory's name to upper case.
-            String[] arr = file.split("/", 3);
-            if (arr.length < 3) {
+            File localFile = device.pullFile(file);
+            if (localFile == null) {
                 throw new TargetSetupError(
-                        String.format(
-                                "Fail to generate zip file entry for dependency: %s. A"
-                                        + " valid dependency should be a file path located at a sub"
-                                        + " directory.",
-                                file),
+                        String.format("Fail to load file: %s from the device.", file),
                         TestErrorIdentifier.TEST_ABORTED);
             }
-            String formattedName = arr[1].toUpperCase() + "/" + arr[2];
-
-            ZipEntry entry = zipFile.getEntry(formattedName);
-            if (entry == null) {
-                CLog.i(
-                        "Fail to find the file: %s in target files: %s",
-                        formattedName, targetFile.getName());
-                continue;
-            }
-            InputStream is = zipFile.getInputStream(entry);
-            String md5 = StreamUtil.calculateMd5(is);
-            hashMap.put(file, md5);
+            String md5 = FileUtil.calculateMd5(localFile);
+            fileHashes.put(file, md5);
         }
-        return hashMap;
+        return fileHashes;
     }
 
     /** Parses the dump file and gets list of dependencies. */
@@ -339,36 +302,6 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
         return result;
     }
 
-    /** Validates if the build fingerprint matches on both the target file and the device. */
-    protected void validateBuildFingerprint(File targetFile, ITestDevice device)
-            throws TargetSetupError {
-        String deviceFingerprint;
-        String targetFileFingerprint;
-        try {
-            deviceFingerprint = device.getProperty(FINGERPRINT);
-            ZipFile zipFile = new ZipFile(targetFile);
-            ZipEntry entry = zipFile.getEntry("SYSTEM/build.prop");
-            InputStream is = zipFile.getInputStream(entry);
-            Properties prop = new Properties();
-            prop.load(is);
-            targetFileFingerprint = prop.getProperty("ro.system.build.fingerprint");
-        } catch (IOException | DeviceNotAvailableException e) {
-            throw new TargetSetupError(
-                    String.format("Fail to get fingerprint from: %s", targetFile.getName()),
-                    e,
-                    device.getDeviceDescriptor(),
-                    TestErrorIdentifier.TEST_ABORTED);
-        }
-        if (deviceFingerprint == null || !deviceFingerprint.equals(targetFileFingerprint)) {
-            throw new TargetSetupError(
-                    String.format(
-                            "Fingerprint on the target file %s doesn't match the one %s on the"
-                                    + " device",
-                            targetFileFingerprint, deviceFingerprint),
-                    TestErrorIdentifier.TEST_ABORTED);
-        }
-    }
-
     /** Adds a build attribute to all the {@link IBuildInfo} tracked for the invocation. */
     private static void addBuildAttribute(IInvocationContext context, String buildAttributeName) {
         for (IBuildInfo bi : context.getBuildInfos()) {
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparer.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparer.java
index 07b560d8..0738ec12 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparer.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparer.java
@@ -112,12 +112,15 @@ public class MediaPreparer extends BaseTargetPreparer
             " is the test suite.")
     private String mDynamicConfigModule = "cts";
 
-    @Option(name = "media-folder-name",
-            description = "The name of local directory into which media" +
-            " files will be downloaded, if option 'local-media-path' is not" +
-            " provided. This directory will live inside the temp directory." +
-            " If option 'push-all' is set, this is also the subdirectory name on device" +
-            " where media files are pushed to")
+    @Option(
+            name = "media-folder-name",
+            description =
+                    "This serves two purposes. When option 'push-all' is set, this specifies the"
+                        + " on-device directory where media files are pushed; if the path does not"
+                        + " begin with /, it is a subdirectory inside the /sdcard/test directory."
+                        + " When 'local-media-path' is not specified, this names a subdirectory"
+                        + " within the hosts's temp directory where the media files will be"
+                        + " downloaded before being sent to the device.")
     private String mMediaFolderName = MEDIA_FOLDER_NAME;
 
     @Option(name = "use-legacy-folder-structure",
@@ -369,6 +372,7 @@ public class MediaPreparer extends BaseTargetPreparer
             // Retrieve default directory for storing media files
             File mediaFolder = getMediaDir();
 
+            CLog.i("host downloads to: " + mediaFolder);
             // manage caching the content on the host side
             //
             if (mediaFolder.exists() && mediaFolder.list().length > 0) {
@@ -554,6 +558,19 @@ public class MediaPreparer extends BaseTargetPreparer
 
     // Initialize directory strings where media files live on device
     protected void setMountPoint(ITestDevice device) {
+
+        if (mMediaFolderName.startsWith("/")) {
+            // test has a specific location for these files.
+            // Primarily for GTest use, where the user identity is managed differently.
+            mBaseDeviceModuleDir = String.format("%s/", mMediaFolderName);
+            // regardless of mUseLegacyFolderStructure
+            mBaseDeviceShortDir = String.format("%s/bbb_short/", mMediaFolderName);
+            mBaseDeviceFullDir = String.format("%s/bbb_full/", mMediaFolderName);
+            return;
+        }
+
+        // Let the harness decide where the assets should go
+        // Best for larger sets of assets, and for CTS testing.
         String mountPoint = device.getMountPoint(IDevice.MNT_EXTERNAL_STORAGE);
         mBaseDeviceModuleDir = String.format("%s/test/%s/", mountPoint, mMediaFolderName);
         if (mUseLegacyFolderStructure) {
@@ -570,6 +587,7 @@ public class MediaPreparer extends BaseTargetPreparer
     @Override
     public void setUp(TestInformation testInfo)
             throws TargetSetupError, BuildError, DeviceNotAvailableException {
+
         ITestDevice device = testInfo.getDevice();
         IBuildInfo buildInfo = testInfo.getBuildInfo();
         mUserId = getRunTestsAsUser(testInfo);
@@ -590,6 +608,16 @@ public class MediaPreparer extends BaseTargetPreparer
         }
 
         try {
+
+            if (mLocalMediaPath == null) {
+                // Option 'local-media-path' has not been defined
+                // Get directory to store media files on this host
+                File mediaFolder = downloadMediaToHost(device, buildInfo);
+                // set mLocalMediaPath to extraction location of media files
+                updateLocalMediaPath(device, mediaFolder);
+            }
+            CLog.i("Media files located on host at: " + mLocalMediaPath);
+
             // set up the host-side sentinel file that we copy when we've finished installing
             // Put some useful triaging and diagnostic information in the file
             FileWriter myWriter = null;
@@ -604,6 +632,7 @@ public class MediaPreparer extends BaseTargetPreparer
                     SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);
                     myWriter.write("Downloaded at: " + sdf.format(cal.getTime()) + "\n");
                 }
+                myWriter.write("Cached on host   path: " + mLocalMediaPath + "\n");
                 myWriter.write("Pushed to device path: " + mBaseDeviceModuleDir + "\n");
             } catch (IOException e) {
                 // we'll write an empty sentinel
@@ -612,14 +641,6 @@ public class MediaPreparer extends BaseTargetPreparer
                 StreamUtil.close(myWriter);
             }
 
-            if (mLocalMediaPath == null) {
-                // Option 'local-media-path' has not been defined
-                // Get directory to store media files on this host
-                File mediaFolder = downloadMediaToHost(device, buildInfo);
-                // set mLocalMediaPath to extraction location of media files
-                updateLocalMediaPath(device, mediaFolder);
-            }
-            CLog.i("Media files located on host at: " + mLocalMediaPath);
             if (!mMediaDownloadOnly) {
                 copyMediaFiles(device);
             }
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/testtype/suite/CompatibilitySuiteModuleLoader.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/testtype/suite/CompatibilitySuiteModuleLoader.java
index ff052c8a..36fbb3eb 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/testtype/suite/CompatibilitySuiteModuleLoader.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/testtype/suite/CompatibilitySuiteModuleLoader.java
@@ -22,7 +22,6 @@ import com.android.tradefed.testtype.suite.SuiteModuleLoader;
 import com.android.tradefed.testtype.suite.SuiteTestFilter;
 import com.android.tradefed.util.AbiUtils;
 
-import java.io.File;
 import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Map;
@@ -48,7 +47,6 @@ public class CompatibilitySuiteModuleLoader extends SuiteModuleLoader {
     /** {@inheritDoc} */
     @Override
     public void addFiltersToTest(
-            File moduleDir,
             IRemoteTest test,
             IAbi abi,
             String name,
@@ -60,6 +58,6 @@ public class CompatibilitySuiteModuleLoader extends SuiteModuleLoader {
             throw new IllegalArgumentException(String.format(
                     "Test in module %s must implement ITestFilterReceiver.", moduleId));
         }
-        super.addFiltersToTest(moduleDir, test, abi, name, includeFilters, excludeFilters);
+        super.addFiltersToTest(test, abi, name, includeFilters, excludeFilters);
     }
 }
diff --git a/common/host-side/tradefed/tests/res/testdata/current_build_target-files.zip b/common/host-side/tradefed/tests/res/testdata/current_build_target-files.zip
deleted file mode 100644
index c8c96cbc..00000000
Binary files a/common/host-side/tradefed/tests/res/testdata/current_build_target-files.zip and /dev/null differ
diff --git a/common/host-side/tradefed/tests/res/testdata/deqp_dependency_file.so b/common/host-side/tradefed/tests/res/testdata/deqp_dependency_file.so
new file mode 100644
index 00000000..88220399
--- /dev/null
+++ b/common/host-side/tradefed/tests/res/testdata/deqp_dependency_file.so
@@ -0,0 +1,2 @@
+placeholder
+placeholder
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/CertificationSuiteResultReporterTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/CertificationSuiteResultReporterTest.java
index 192f5a73..d46d3dda 100644
--- a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/CertificationSuiteResultReporterTest.java
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/result/suite/CertificationSuiteResultReporterTest.java
@@ -23,7 +23,6 @@ import com.android.tradefed.build.IBuildInfo;
 import com.android.tradefed.config.Configuration;
 import com.android.tradefed.config.ConfigurationDef;
 import com.android.tradefed.config.IConfiguration;
-import com.android.tradefed.config.OptionSetter;
 import com.android.tradefed.invoker.IInvocationContext;
 import com.android.tradefed.invoker.InvocationContext;
 import com.android.tradefed.util.FileUtil;
@@ -139,66 +138,4 @@ public class CertificationSuiteResultReporterTest {
         assertTrue(content.contains("suite_variant=\"CTS_ON_GSI\""));
         assertTrue(content.contains("suite_version=\"version\""));
     }
-
-    /**
-     * For the R release, ensure that CTS-on-GSI still report as VTS for APFE to ingest it properly
-     */
-    @Test
-    public void testSuiteVariantGSI_R_Compatibility() throws Exception {
-        mConfiguration = new Configuration("test", "test");
-        mConfiguration.setCommandLine(new String[] {"cts-on-gsi"});
-
-        mReporter =
-                new CertificationSuiteResultReporter() {
-                    @Override
-                    CompatibilityBuildHelper createBuildHelper() {
-                        return mBuildHelper;
-                    }
-                };
-        OptionSetter setter = new OptionSetter(mReporter);
-        setter.setOptionValue("cts-on-gsi-variant", "true");
-        mReporter.setConfiguration(mConfiguration);
-
-        mReporter.invocationStarted(mContext);
-        mReporter.invocationEnded(500L);
-
-        File reportFile = new File(mBuildHelper.getResultDir(), "test_result.xml");
-        assertTrue(reportFile.exists());
-        String content = FileUtil.readStringFromFile(reportFile);
-        // Suite name is overridden to VTS for the R release
-        assertTrue(content.contains("suite_name=\"VTS\""));
-        assertTrue(content.contains("suite_variant=\"CTS_ON_GSI\""));
-        assertTrue(content.contains("suite_version=\"version\""));
-    }
-
-    /**
-     * For the R release, ensure that CTS-on-GSI still report as VTS for APFE to ingest it properly
-     */
-    @Test
-    public void testSuiteVariantGSI_R_Compatibility_ATS() throws Exception {
-        mConfiguration = new Configuration("test", "test");
-        // ATS renames the config so we need to handle it.
-        mConfiguration.setCommandLine(new String[] {"_cts-on-gsi.xml"});
-
-        mReporter =
-                new CertificationSuiteResultReporter() {
-                    @Override
-                    CompatibilityBuildHelper createBuildHelper() {
-                        return mBuildHelper;
-                    }
-                };
-        OptionSetter setter = new OptionSetter(mReporter);
-        setter.setOptionValue("cts-on-gsi-variant", "true");
-        mReporter.setConfiguration(mConfiguration);
-
-        mReporter.invocationStarted(mContext);
-        mReporter.invocationEnded(500L);
-
-        File reportFile = new File(mBuildHelper.getResultDir(), "test_result.xml");
-        assertTrue(reportFile.exists());
-        String content = FileUtil.readStringFromFile(reportFile);
-        // Suite name is overridden to VTS for the R release
-        assertTrue(content.contains("suite_name=\"VTS\""));
-        assertTrue(content.contains("suite_version=\"version\""));
-    }
 }
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
index 5dabf97e..08118f94 100644
--- a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
@@ -18,7 +18,6 @@ package com.android.compatibility.common.tradefed.targetprep;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
-import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.endsWith;
 import static org.mockito.Mockito.mock;
@@ -27,7 +26,7 @@ import static org.mockito.Mockito.when;
 import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
 import com.android.tradefed.build.BuildInfo;
 import com.android.tradefed.build.IBuildInfo;
-import com.android.tradefed.config.OptionSetter;
+import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.invoker.IInvocationContext;
 import com.android.tradefed.invoker.InvocationContext;
@@ -53,13 +52,8 @@ import java.util.Set;
 /** Unit tests for {@link IncrementalDeqpPreparer}. */
 @RunWith(JUnit4.class)
 public class IncrementalDeqpPreparerTest {
-    private static final String DEVICE_FINGERPRINT =
-            "generic/aosp_cf_x86_64_phone/vsoc_x86_64:S/AOSP"
-                    + ".MASTER/7363308:userdebug/test-keys";
-
     private IncrementalDeqpPreparer mPreparer;
     private ITestDevice mMockDevice;
-    private OptionSetter mPreparerSetter = null;
 
     @Before
     public void setUp() throws Exception {
@@ -71,14 +65,11 @@ public class IncrementalDeqpPreparerTest {
     @Test
     public void testRunIncrementalDeqp() throws Exception {
         File resultDir = FileUtil.createTempDir("result");
-        InputStream zipStream =
-                getClass().getResourceAsStream("/testdata/current_build_target-files.zip");
-        File zipFile = FileUtil.createTempFile("targetFile", ".zip");
+        InputStream deqpDependencyStream =
+                getClass().getResourceAsStream("/testdata/deqp_dependency_file.so");
+        File deqpDependencyFile = FileUtil.createTempFile("deqp_dependency_file", ".so");
         try {
-            FileUtil.writeToFile(zipStream, zipFile);
-            mPreparerSetter = new OptionSetter(mPreparer);
-            mPreparerSetter.setOptionValue(
-                    "incremental-deqp-preparer:current-build", zipFile.getAbsolutePath());
+            FileUtil.writeToFile(deqpDependencyStream, deqpDependencyFile);
             IBuildInfo mMockBuildInfo = new BuildInfo();
             IInvocationContext mMockContext = new InvocationContext();
             mMockContext.addDeviceBuildInfo("build", mMockBuildInfo);
@@ -97,7 +88,7 @@ public class IncrementalDeqpPreparerTest {
             FileUtil.writeToFile(perfDumpStream, dumpFile);
             when(mMockDevice.pullFile(endsWith("-perf-dump.txt")))
                     .thenReturn(dumpFile, null, null, null);
-            when(mMockDevice.getProperty("ro.build.fingerprint")).thenReturn(DEVICE_FINGERPRINT);
+            when(mMockDevice.pullFile(endsWith(".so"))).thenReturn(deqpDependencyFile);
 
             File incrementalDeqpReport =
                     new File(deviceInfoDir, IncrementalDeqpPreparer.INCREMENTAL_DEQP_REPORT_NAME);
@@ -114,7 +105,7 @@ public class IncrementalDeqpPreparerTest {
             assertTrue(incrementalDeqpReport.exists());
         } finally {
             FileUtil.recursiveDelete(resultDir);
-            FileUtil.deleteFile(zipFile);
+            FileUtil.deleteFile(deqpDependencyFile);
         }
     }
 
@@ -175,74 +166,32 @@ public class IncrementalDeqpPreparerTest {
     }
 
     @Test
-    public void testGetTargetFileHash() throws IOException, TargetSetupError {
+    public void testGetFileHash()
+            throws IOException, DeviceNotAvailableException, TargetSetupError {
         Set<String> fileSet =
                 new HashSet<>(
                         Arrays.asList(
                                 "/system/deqp_dependency_file_a.so",
                                 "/vendor/deqp_dependency_file_b.so",
-                                "/vendor/file_not_exists.so"));
-        // current_build_target-files.zip is a stripped down version of the target-files.zip
-        // generated from the android build system, with a few added mocked target files for
-        // testing.
-        InputStream zipStream =
-                getClass().getResourceAsStream("/testdata/current_build_target-files.zip");
-        File zipFile = FileUtil.createTempFile("targetFile", ".zip");
+                                "/vendor/deqp_dependency_file_c.so"));
+        InputStream deqpDependencyStream =
+                getClass().getResourceAsStream("/testdata/deqp_dependency_file.so");
+        File deqpDependencyFile = FileUtil.createTempFile("deqp_dependency_file", ".so");
         try {
-            FileUtil.writeToFile(zipStream, zipFile);
-            Map<String, String> fileHashMap = mPreparer.getTargetFileHash(fileSet, zipFile);
+            FileUtil.writeToFile(deqpDependencyStream, deqpDependencyFile);
+            when(mMockDevice.pullFile(endsWith(".so"))).thenReturn(deqpDependencyFile);
+            Map<String, String> fileHashMap = mPreparer.getFileHash(fileSet, mMockDevice);
 
-            assertEquals(fileHashMap.size(), 2);
-            assertEquals(
-                    fileHashMap.get("/system/deqp_dependency_file_a.so"),
-                    StreamUtil.calculateMd5(
-                            new ByteArrayInputStream(
-                                    "placeholder\nplaceholder\n"
-                                            .getBytes(StandardCharsets.UTF_8))));
-            assertEquals(
-                    fileHashMap.get("/vendor/deqp_dependency_file_b.so"),
+            assertEquals(fileHashMap.size(), 3);
+            String md5 =
                     StreamUtil.calculateMd5(
                             new ByteArrayInputStream(
-                                    ("placeholder\nplaceholder" + "\nplaceholder\n\n")
-                                            .getBytes(StandardCharsets.UTF_8))));
-        } finally {
-            FileUtil.deleteFile(zipFile);
-        }
-    }
-
-    @Test
-    public void testValidateBuildFingerprint() throws Exception {
-        // current_build_target-files.zip is a stripped down version of the target-files.zip
-        // generated from the android build system, with a few added mocked target files for
-        // testing.
-        InputStream zipStream =
-                getClass().getResourceAsStream("/testdata/current_build_target-files.zip");
-        File zipFile = FileUtil.createTempFile("targetFile", ".zip");
-        try {
-            FileUtil.writeToFile(zipStream, zipFile);
-            when(mMockDevice.getProperty("ro.build.fingerprint")).thenReturn(DEVICE_FINGERPRINT);
-
-            mPreparer.validateBuildFingerprint(zipFile, mMockDevice);
-        } finally {
-            FileUtil.deleteFile(zipFile);
-        }
-    }
-
-    @Test
-    public void testValidateBuildFingerprint_fingerprintMismatch() throws Exception {
-        InputStream zipStream =
-                getClass().getResourceAsStream("/testdata/current_build_target-files.zip");
-        File zipFile = FileUtil.createTempFile("targetFile", ".zip");
-        try {
-            FileUtil.writeToFile(zipStream, zipFile);
-            when(mMockDevice.getProperty("ro.build.fingerprint"))
-                    .thenReturn(DEVICE_FINGERPRINT + "modified");
-
-            assertThrows(
-                    TargetSetupError.class,
-                    () -> mPreparer.validateBuildFingerprint(zipFile, mMockDevice));
+                                    "placeholder\nplaceholder\n".getBytes(StandardCharsets.UTF_8)));
+            assertEquals(fileHashMap.get("/system/deqp_dependency_file_a.so"), md5);
+            assertEquals(fileHashMap.get("/vendor/deqp_dependency_file_b.so"), md5);
+            assertEquals(fileHashMap.get("/vendor/deqp_dependency_file_c.so"), md5);
         } finally {
-            FileUtil.deleteFile(zipFile);
+            FileUtil.deleteFile(deqpDependencyFile);
         }
     }
 }
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparerTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparerTest.java
index 0fd1f91d..0a63d356 100644
--- a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparerTest.java
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparerTest.java
@@ -152,7 +152,6 @@ public class MediaPreparerTest {
                     resolution.toString());
             String fullFile = String.format("%s%s", mMediaPreparer.mBaseDeviceFullDir,
                     resolution.toString());
-            // RBE these are the things I have to fix up.
             when(mMockDevice.doesFileExist(shortFile, TEST_USER_ID)).thenReturn(true);
             when(mMockDevice.doesFileExist(fullFile, TEST_USER_ID)).thenReturn(true);
         }
@@ -276,9 +275,30 @@ public class MediaPreparerTest {
         when(mMockDevice.doesFileExist(
                         mMediaPreparer.mBaseDeviceModuleDir + SENTINEL, TEST_USER_ID))
                 .thenReturn(true);
-        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceShortDir + SENTINEL, TEST_USER_ID))
+        // and these directories should no longer be created.
+        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceShortDir, TEST_USER_ID))
                 .thenReturn(false);
-        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceFullDir + SENTINEL, TEST_USER_ID))
+        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceFullDir, TEST_USER_ID))
+                .thenReturn(false);
+
+        mMediaPreparer.copyMediaFiles(mMockDevice);
+    }
+
+    @Test
+    public void testPushAllMediaFolderFullPath() throws Exception {
+        mOptionSetter.setOptionValue("push-all", "true");
+        mOptionSetter.setOptionValue("media-folder-name", "/data/local/tmp/FullPathtest");
+        mMediaPreparer.mBaseDeviceModuleDir = "/data/local/tmp/FullPathtest/";
+        mMediaPreparer.mBaseDeviceShortDir = "/data/local/tmp/bbb_short/";
+        mMediaPreparer.mBaseDeviceFullDir = "/data/local/tmp/bbb_full/";
+        // Preparer uses sentinel files in directories, not the directories themselves
+        when(mMockDevice.doesFileExist(
+                        mMediaPreparer.mBaseDeviceModuleDir + SENTINEL, TEST_USER_ID))
+                .thenReturn(true);
+        // ensure we didn't land anything under the standard test directory
+        when(mMockDevice.doesFileExist("/sdcard/test/data/local/tmp/FullPathtest", TEST_USER_ID))
+                .thenReturn(false);
+        when(mMockDevice.doesFileExist("/sdcard/test/FullPathtest", TEST_USER_ID))
                 .thenReturn(false);
 
         mMediaPreparer.copyMediaFiles(mMockDevice);
diff --git a/common/host-side/util/src/com/android/compatibility/common/util/FeatureUtil.java b/common/host-side/util/src/com/android/compatibility/common/util/FeatureUtil.java
index df772a28..ff26d794 100644
--- a/common/host-side/util/src/com/android/compatibility/common/util/FeatureUtil.java
+++ b/common/host-side/util/src/com/android/compatibility/common/util/FeatureUtil.java
@@ -34,6 +34,7 @@ public class FeatureUtil {
     public static final String TV_FEATURE = "android.hardware.type.television";
     public static final String WATCH_FEATURE = "android.hardware.type.watch";
     public static final String FEATURE_MICROPHONE = "android.hardware.microphone";
+    public static final String XR_FEATURE = "android.software.xr.immersive";
 
     /** Returns true if the device has a given system feature */
     public static boolean hasSystemFeature(ITestDevice device, String feature)
@@ -89,6 +90,11 @@ public class FeatureUtil {
         return hasSystemFeature(device, AUTOMOTIVE_FEATURE);
     }
 
+    /** Returns true if the device has feature XR_FEATURE */
+    public static boolean isXrHeadset(ITestDevice device) throws DeviceNotAvailableException {
+        return hasSystemFeature(device, XR_FEATURE);
+    }
+
     /** Returns true if the device is a low ram device:
      *  1. API level &gt;= O
      *  2. device has feature LOW_RAM_FEATURE
```

