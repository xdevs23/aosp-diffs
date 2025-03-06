```diff
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/build/CompatibilityBuildHelper.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/build/CompatibilityBuildHelper.java
index d7a947ce..527dead9 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/build/CompatibilityBuildHelper.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/build/CompatibilityBuildHelper.java
@@ -347,7 +347,7 @@ public class CompatibilityBuildHelper {
             // TODO: handle error when migration is complete.
             CLog.e(e);
         }
-        if (testFile != null && testFile.isFile()) {
+        if (testFile != null && testFile.exists()) {
             return testFile;
         } else {
             // Silently report not found and fall back to old logic.
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
index 4644af55..100072ce 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparer.java
@@ -34,15 +34,12 @@ import com.android.tradefed.targetprep.TargetSetupError;
 import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.StreamUtil;
 
-import com.google.common.collect.Sets;
-
 import java.io.BufferedReader;
 import java.io.File;
 import java.io.FileNotFoundException;
 import java.io.FileReader;
 import java.io.IOException;
 import java.io.InputStream;
-import java.nio.file.Files;
 import java.util.Arrays;
 import java.util.HashMap;
 import java.util.HashSet;
@@ -51,21 +48,12 @@ import java.util.Map;
 import java.util.Properties;
 import java.util.Set;
 import java.util.regex.Pattern;
-import java.util.stream.Collectors;
 import java.util.zip.ZipEntry;
 import java.util.zip.ZipFile;
 
 /** Collects the dEQP dependencies and compares the builds. */
 @OptionClass(alias = "incremental-deqp-preparer")
 public class IncrementalDeqpPreparer extends BaseTargetPreparer {
-
-    @Option(
-            name = "base-build",
-            description =
-                    "Absolute file path to a target file of the base build. Required for "
-                            + "incremental dEQP.")
-    private File mBaseBuild = null;
-
     @Option(
             name = "current-build",
             description =
@@ -73,15 +61,8 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
                             + " incremental dEQP.")
     private File mCurrentBuild = null;
 
-    @Option(
-            name = "extra-dependency",
-            description =
-                    "Absolute file path to a text file that includes extra dEQP test "
-                            + "dependencies. Optional for incremental dEQP.")
-    private File mExtraDependency = null;
-
     @Option(name = "run-mode", description = "The run mode for incremental dEQP.")
-    private RunMode mRunMode = RunMode.BUILD_APPROVAL;
+    private RunMode mRunMode = RunMode.LIGHTWEIGHT_RUN;
 
     @Option(
             name = "fallback-strategy",
@@ -90,12 +71,11 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
                             + "for the builds fails.")
     private FallbackStrategy mFallbackStrategy = FallbackStrategy.ABORT_IF_ANY_EXCEPTION;
 
-    private enum RunMode {
-        // Initial application for a device to verify that the feature can capture all the
-        // dependencies by the representative dEQP tests.
-        DEVICE_APPLICATION,
-        // Running incremental dEQP for build approvals after the device is allowlisted.
-        BUILD_APPROVAL;
+    public enum RunMode {
+        // Collects the dependencies information for the build via the full dEQP tests.
+        FULL_RUN,
+        // Collects the dependencies information for the build via the representative dEQP tests.
+        LIGHTWEIGHT_RUN
     }
 
     private enum FallbackStrategy {
@@ -103,7 +83,7 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
         RUN_FULL_DEQP,
         // Aborts if an exception is thrown in the preparer. Otherwise, runs full dEQP tests due to
         // dependency modifications.
-        ABORT_IF_ANY_EXCEPTION;
+        ABORT_IF_ANY_EXCEPTION
     }
 
     private static final String MODULE_NAME = "CtsDeqpTestCases";
@@ -121,37 +101,23 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
     private static final String DEQP_CASE_LIST_FILE_EXTENSION = ".txt";
     private static final String PERF_FILE_EXTENSION = ".data";
     private static final String LOG_FILE_EXTENSION = ".qpa";
-    private static final String BASE_BUILD_FINGERPRINT_ATTRIBUTE = "base_build_fingerprint";
-    private static final String CURRENT_BUILD_FINGERPRINT_ATTRIBUTE = "current_build_fingerprint";
+    private static final String RUN_MODE_ATTRIBUTE = "run_mode";
     private static final String MODULE_ATTRIBUTE = "module";
     private static final String MODULE_NAME_ATTRIBUTE = "module_name";
     private static final String FINGERPRINT = "ro.build.fingerprint";
-    private static final String BASELINE_DEPENDENCY_ATTRIBUTE = "baseline_deps";
     private static final String MISSING_DEPENDENCY_ATTRIBUTE = "missing_deps";
-    private static final String DEPENDENCY_ATTRIBUTE = "deps";
-    private static final String EXTRA_DEPENDENCY_ATTRIBUTE = "extra_deps";
-    private static final String DEPENDENCY_CHANGES_ATTRIBUTE = "deps_changes";
+    private static final String DEPENDENCY_DETAILS_ATTRIBUTE = "deps_details";
     private static final String DEPENDENCY_NAME_ATTRIBUTE = "dep_name";
-    private static final String DEPENDENCY_DETAIL_ATTRIBUTE = "detail";
-    private static final String DEPENDENCY_BASE_BUILD_HASH_ATTRIBUTE = "base_build_hash";
-    private static final String DEPENDENCY_CURRENT_BUILD_HASH_ATTRIBUTE = "current_build_hash";
-    private static final String NULL_BUILD_HASH = "0";
-
-    private static final String DEPENDENCY_DETAIL_MISSING_IN_CURRENT = "MISSING_IN_CURRENT_BUILD";
-    private static final String DEPENDENCY_DETAIL_MISSING_IN_BASE = "MISSING_IN_BASE_BUILD";
-    private static final String DEPENDENCY_DETAIL_MISSING_IN_BASE_AND_CURRENT =
-            "MISSING_IN_BASE_AND_CURRENT_BUILDS";
-    private static final String DEPENDENCY_DETAIL_DIFFERENT_HASH =
-            "BASE_AND_CURRENT_BUILD_DIFFERENT_HASH";
+    private static final String DEPENDENCY_FILE_HASH_ATTRIBUTE = "file_hash";
 
     private static final Pattern EXCLUDE_DEQP_PATTERN =
             Pattern.compile("(^/data/|^/apex/|^\\[vdso" + "\\]|^/dmabuf|^/kgsl-3d0|^/mali csf)");
 
     public static final String INCREMENTAL_DEQP_BASELINE_ATTRIBUTE_NAME =
             "incremental-deqp-baseline";
+    public static final String INCREMENTAL_DEQP_TRUSTED_BUILD_ATTRIBUTE_NAME =
+            "incremental-deqp-trusted-build";
     public static final String INCREMENTAL_DEQP_ATTRIBUTE_NAME = "incremental-deqp";
-    public static final String INCREMENTAL_DEQP_BASELINE_REPORT_NAME =
-            "IncrementalCtsBaselineDeviceInfo.deviceinfo.json";
     public static final String INCREMENTAL_DEQP_REPORT_NAME =
             "IncrementalCtsDeviceInfo.deviceinfo.json";
 
@@ -163,11 +129,7 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
             CompatibilityBuildHelper buildHelper =
                     new CompatibilityBuildHelper(testInfo.getBuildInfo());
             IInvocationContext context = testInfo.getContext();
-            if (RunMode.DEVICE_APPLICATION.equals(mRunMode)) {
-                verifyIncrementalDeqp(context, device, buildHelper);
-            } else {
-                runIncrementalDeqp(context, device, buildHelper);
-            }
+            runIncrementalDeqp(context, device, buildHelper, mRunMode);
         } catch (Exception e) {
             if (mFallbackStrategy == FallbackStrategy.ABORT_IF_ANY_EXCEPTION) {
                 // Rethrows the exception to abort the task.
@@ -178,87 +140,15 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
     }
 
     /**
-     * Checks if the dependencies identified by the incremental dEQP test list match up with the
-     * dependencies identified by the dEQP baseline test list.
-     *
-     * <p>Synchronize this method so that multiple shards won't run it multiple times.
-     */
-    protected void verifyIncrementalDeqp(
-            IInvocationContext context, ITestDevice device, CompatibilityBuildHelper buildHelper)
-            throws TargetSetupError, DeviceNotAvailableException {
-        // Make sure synchronization is on the class not the object.
-        synchronized (IncrementalDeqpPreparer.class) {
-            File jsonFile;
-            try {
-                File deviceInfoDir =
-                        new File(buildHelper.getResultDir(), DeviceInfo.RESULT_DIR_NAME);
-                jsonFile = new File(deviceInfoDir, INCREMENTAL_DEQP_BASELINE_REPORT_NAME);
-                if (jsonFile.exists()) {
-                    CLog.i("Another shard has already checked dEQP baseline dependencies.");
-                    return;
-                }
-            } catch (FileNotFoundException e) {
-                throw new TargetSetupError(
-                        "Fail to read invocation result directory.",
-                        device.getDeviceDescriptor(),
-                        TestErrorIdentifier.TEST_ABORTED);
-            }
-
-            Set<String> baselineDependencies = getDeqpDependencies(device, BASELINE_DEQP_TEST_LIST);
-            Set<String> representativeDependencies =
-                    getDeqpDependencies(device, REPRESENTATIVE_DEQP_TEST_LIST);
-            Set<String> missingDependencies =
-                    Sets.difference(baselineDependencies, representativeDependencies);
-
-            // Write identified dependencies to device info report.
-            try (HostInfoStore store = new HostInfoStore(jsonFile)) {
-                store.open();
-
-                store.addResult(BASE_BUILD_FINGERPRINT_ATTRIBUTE, device.getProperty(FINGERPRINT));
-                store.startArray(MODULE_ATTRIBUTE);
-                store.startGroup(); // Module
-                store.addResult(MODULE_NAME_ATTRIBUTE, MODULE_NAME);
-                store.addListResult(
-                        BASELINE_DEPENDENCY_ATTRIBUTE,
-                        baselineDependencies.stream().sorted().collect(Collectors.toList()));
-                store.addListResult(
-                        MISSING_DEPENDENCY_ATTRIBUTE,
-                        missingDependencies.stream().sorted().collect(Collectors.toList()));
-                // Add an attribute to all shard's build info.
-                for (IBuildInfo bi : context.getBuildInfos()) {
-                    bi.addBuildAttribute(INCREMENTAL_DEQP_BASELINE_ATTRIBUTE_NAME, "");
-                }
-                store.endGroup(); // Module
-                store.endArray();
-            } catch (IOException e) {
-                throw new TargetSetupError(
-                        "Failed to collect dependencies",
-                        e,
-                        device.getDeviceDescriptor(),
-                        TestErrorIdentifier.TEST_ABORTED);
-            } catch (Exception e) {
-                throw new TargetSetupError(
-                        "Failed to write incremental dEQP baseline report",
-                        e,
-                        device.getDeviceDescriptor(),
-                        TestErrorIdentifier.TEST_ABORTED);
-            } finally {
-                if (jsonFile.exists() && jsonFile.length() == 0) {
-                    FileUtil.deleteFile(jsonFile);
-                }
-            }
-        }
-    }
-
-    /**
-     * Runs a check to determine if the current build has changed dEQP dependencies or not. Will
-     * signal to dEQP test runner whether the majority of dEQP cases can be skipped, and also
-     * generate an incremental cts report with more details.
+     * Collects dEQP dependencies and generate an incremental cts report with more details.
      *
      * <p>Synchronize this method so that multiple shards won't run it multiple times.
      */
     protected void runIncrementalDeqp(
-            IInvocationContext context, ITestDevice device, CompatibilityBuildHelper buildHelper)
+            IInvocationContext context,
+            ITestDevice device,
+            CompatibilityBuildHelper buildHelper,
+            RunMode runMode)
             throws TargetSetupError, DeviceNotAvailableException {
         // Make sure synchronization is on the class not the object.
         synchronized (IncrementalDeqpPreparer.class) {
@@ -269,6 +159,8 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
                 jsonFile = new File(deviceInfoDir, INCREMENTAL_DEQP_REPORT_NAME);
                 if (jsonFile.exists()) {
                     CLog.i("Another shard has already checked dEQP dependencies.");
+                    // Add an attribute to the shard's build info.
+                    addBuildAttribute(context, INCREMENTAL_DEQP_ATTRIBUTE_NAME);
                     return;
                 }
             } catch (FileNotFoundException e) {
@@ -277,103 +169,38 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
                         device.getDeviceDescriptor(),
                         TestErrorIdentifier.TEST_ABORTED);
             }
+            validateBuildFingerprint(mCurrentBuild, device);
 
-            Set<String> simpleperfDependencies =
-                    getDeqpDependencies(device, REPRESENTATIVE_DEQP_TEST_LIST);
-            Set<String> extraDependencies = parseExtraDependency(device);
-            Set<String> dependencies = new HashSet<>(simpleperfDependencies);
-            dependencies.addAll(extraDependencies);
+            List<String> deqpTestList =
+                    RunMode.FULL_RUN.equals(mRunMode)
+                            ? BASELINE_DEQP_TEST_LIST
+                            : REPRESENTATIVE_DEQP_TEST_LIST;
+            Set<String> dependencies = getDeqpDependencies(device, deqpTestList);
 
-            // Write data of incremental dEQP to device info report.
+            // Identify and write dependencies to device info report.
             try (HostInfoStore store = new HostInfoStore(jsonFile)) {
                 store.open();
-
-                store.addResult(
-                        BASE_BUILD_FINGERPRINT_ATTRIBUTE, getBuildFingerPrint(mBaseBuild, device));
-                store.addResult(
-                        CURRENT_BUILD_FINGERPRINT_ATTRIBUTE,
-                        getBuildFingerPrint(mCurrentBuild, device));
-
+                store.addResult(RUN_MODE_ATTRIBUTE, runMode.name());
                 store.startArray(MODULE_ATTRIBUTE);
                 store.startGroup(); // Module
                 store.addResult(MODULE_NAME_ATTRIBUTE, MODULE_NAME);
-                store.addListResult(
-                        DEPENDENCY_ATTRIBUTE,
-                        simpleperfDependencies.stream().sorted().collect(Collectors.toList()));
-                store.addListResult(
-                        EXTRA_DEPENDENCY_ATTRIBUTE,
-                        extraDependencies.stream().sorted().collect(Collectors.toList()));
-                store.startArray(DEPENDENCY_CHANGES_ATTRIBUTE);
-                boolean noChange = true;
+                store.startArray(DEPENDENCY_DETAILS_ATTRIBUTE);
                 Map<String, String> currentBuildHashMap =
                         getTargetFileHash(dependencies, mCurrentBuild);
-                Map<String, String> baseBuildHashMap = getTargetFileHash(dependencies, mBaseBuild);
-
                 for (String dependency : dependencies) {
-                    if (!baseBuildHashMap.containsKey(dependency)
-                            && currentBuildHashMap.containsKey(dependency)) {
-                        noChange = false;
-                        store.startGroup();
-                        store.addResult(DEPENDENCY_NAME_ATTRIBUTE, dependency);
-                        store.addResult(
-                                DEPENDENCY_DETAIL_ATTRIBUTE, DEPENDENCY_DETAIL_MISSING_IN_BASE);
-                        store.addResult(DEPENDENCY_BASE_BUILD_HASH_ATTRIBUTE, NULL_BUILD_HASH);
-                        store.addResult(
-                                DEPENDENCY_CURRENT_BUILD_HASH_ATTRIBUTE,
-                                currentBuildHashMap.get(dependency));
-                        store.endGroup();
-                    } else if (!currentBuildHashMap.containsKey(dependency)
-                            && baseBuildHashMap.containsKey(dependency)) {
-                        noChange = false;
-                        store.startGroup();
-                        store.addResult(DEPENDENCY_NAME_ATTRIBUTE, dependency);
-                        store.addResult(
-                                DEPENDENCY_DETAIL_ATTRIBUTE, DEPENDENCY_DETAIL_MISSING_IN_CURRENT);
-                        store.addResult(
-                                DEPENDENCY_BASE_BUILD_HASH_ATTRIBUTE,
-                                baseBuildHashMap.get(dependency));
-                        store.addResult(DEPENDENCY_CURRENT_BUILD_HASH_ATTRIBUTE, NULL_BUILD_HASH);
-                        store.endGroup();
-                    } else if (!currentBuildHashMap.containsKey(dependency)
-                            && !baseBuildHashMap.containsKey(dependency)) {
-                        noChange = false;
-                        store.startGroup();
-                        store.addResult(DEPENDENCY_NAME_ATTRIBUTE, dependency);
-                        store.addResult(
-                                DEPENDENCY_DETAIL_ATTRIBUTE,
-                                DEPENDENCY_DETAIL_MISSING_IN_BASE_AND_CURRENT);
-                        store.addResult(DEPENDENCY_BASE_BUILD_HASH_ATTRIBUTE, NULL_BUILD_HASH);
-                        store.addResult(DEPENDENCY_CURRENT_BUILD_HASH_ATTRIBUTE, NULL_BUILD_HASH);
-                        store.endGroup();
-                    } else if (!currentBuildHashMap
-                            .get(dependency)
-                            .equals(baseBuildHashMap.get(dependency))) {
-                        noChange = false;
-                        store.startGroup();
-                        store.addResult(DEPENDENCY_NAME_ATTRIBUTE, dependency);
-                        store.addResult(
-                                DEPENDENCY_DETAIL_ATTRIBUTE, DEPENDENCY_DETAIL_DIFFERENT_HASH);
-                        store.addResult(
-                                DEPENDENCY_BASE_BUILD_HASH_ATTRIBUTE,
-                                baseBuildHashMap.get(dependency));
-                        store.addResult(
-                                DEPENDENCY_CURRENT_BUILD_HASH_ATTRIBUTE,
-                                currentBuildHashMap.get(dependency));
-                        store.endGroup();
-                    }
-                }
-                store.endArray(); // dEQP changes
-                if (noChange) {
-                    // Add an attribute to all shard's build info.
-                    for (IBuildInfo bi : context.getBuildInfos()) {
-                        bi.addBuildAttribute(INCREMENTAL_DEQP_ATTRIBUTE_NAME, "");
-                    }
+                    store.startGroup();
+                    store.addResult(DEPENDENCY_NAME_ATTRIBUTE, dependency);
+                    store.addResult(
+                            DEPENDENCY_FILE_HASH_ATTRIBUTE, currentBuildHashMap.get(dependency));
+                    store.endGroup();
                 }
+                store.endArray(); // dEQP details
                 store.endGroup(); // Module
                 store.endArray();
+                addBuildAttribute(context, INCREMENTAL_DEQP_ATTRIBUTE_NAME);
             } catch (IOException e) {
                 throw new TargetSetupError(
-                        "Failed to compare the builds",
+                        "Failed to collect dependencies",
                         e,
                         device.getDeviceDescriptor(),
                         TestErrorIdentifier.TEST_ABORTED);
@@ -391,26 +218,6 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
         }
     }
 
-    /** Parses the extra dependency file and get dependencies. */
-    private Set<String> parseExtraDependency(ITestDevice device) throws TargetSetupError {
-        Set<String> result = new HashSet<>();
-        if (mExtraDependency == null) {
-            return result;
-        }
-        try {
-            for (String line : Files.readAllLines(mExtraDependency.toPath())) {
-                result.add(line.trim());
-            }
-        } catch (IOException e) {
-            throw new TargetSetupError(
-                    "Failed to parse extra dependencies file.",
-                    e,
-                    device.getDeviceDescriptor(),
-                    TestErrorIdentifier.TEST_ABORTED);
-        }
-        return result;
-    }
-
     /** Gets the filename of dEQP dependencies in build. */
     private Set<String> getDeqpDependencies(ITestDevice device, List<String> testList)
             throws TargetSetupError, DeviceNotAvailableException {
@@ -496,7 +303,7 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
         BufferedReader br = null;
         try {
             br = new BufferedReader(new FileReader(localDumpFile));
-            String line = null;
+            String line;
             while ((line = br.readLine()) != null) {
                 if (!binaryExecuted) {
                     // dEQP binary has first been executed.
@@ -532,24 +339,40 @@ public class IncrementalDeqpPreparer extends BaseTargetPreparer {
         return result;
     }
 
-    /** Gets the build fingerprint from target files. */
-    protected String getBuildFingerPrint(File targetFile, ITestDevice device)
+    /** Validates if the build fingerprint matches on both the target file and the device. */
+    protected void validateBuildFingerprint(File targetFile, ITestDevice device)
             throws TargetSetupError {
-        String fingerprint;
+        String deviceFingerprint;
+        String targetFileFingerprint;
         try {
+            deviceFingerprint = device.getProperty(FINGERPRINT);
             ZipFile zipFile = new ZipFile(targetFile);
             ZipEntry entry = zipFile.getEntry("SYSTEM/build.prop");
             InputStream is = zipFile.getInputStream(entry);
             Properties prop = new Properties();
             prop.load(is);
-            fingerprint = prop.getProperty("ro.system.build.fingerprint");
-        } catch (IOException e) {
+            targetFileFingerprint = prop.getProperty("ro.system.build.fingerprint");
+        } catch (IOException | DeviceNotAvailableException e) {
             throw new TargetSetupError(
                     String.format("Fail to get fingerprint from: %s", targetFile.getName()),
                     e,
                     device.getDeviceDescriptor(),
                     TestErrorIdentifier.TEST_ABORTED);
         }
-        return fingerprint;
+        if (deviceFingerprint == null || !deviceFingerprint.equals(targetFileFingerprint)) {
+            throw new TargetSetupError(
+                    String.format(
+                            "Fingerprint on the target file %s doesn't match the one %s on the"
+                                    + " device",
+                            targetFileFingerprint, deviceFingerprint),
+                    TestErrorIdentifier.TEST_ABORTED);
+        }
+    }
+
+    /** Adds a build attribute to all the {@link IBuildInfo} tracked for the invocation. */
+    private static void addBuildAttribute(IInvocationContext context, String buildAttributeName) {
+        for (IBuildInfo bi : context.getBuildInfos()) {
+            bi.addBuildAttribute(buildAttributeName, "");
+        }
     }
 }
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparer.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparer.java
index 3a42aa84..07b560d8 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparer.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparer.java
@@ -61,6 +61,8 @@ import java.io.IOException;
 import java.io.InputStream;
 import java.net.URL;
 import java.net.URLConnection;
+import java.text.SimpleDateFormat;
+import java.util.Calendar;
 import java.util.HashMap;
 import java.util.HashSet;
 import java.util.Set;
@@ -176,6 +178,21 @@ public class MediaPreparer extends BaseTargetPreparer
             new Resolution(1920, 1080)
     };
 
+    /*
+     * We place a file with this name in the device directories after we've pushed the
+     * test assets to the device. The presence of this files indicates that the assets
+     * were pushed in their entirety. This provides a stronger answer to the question
+     * "are all of these test assets on the device".
+     */
+
+    private static final String SENTINEL = ".download-completed";
+
+    /*
+     * the host-side file that we push to the device as a sentinel. This is populated
+     * with information about what was downloaded and when.
+     */
+    private File localSentinel;
+
     /** {@inheritDoc} */
     @Override
     public Set<ExternalDependency> getDependencies() {
@@ -243,19 +260,33 @@ public class MediaPreparer extends BaseTargetPreparer
     protected boolean mediaFilesExistOnDevice(ITestDevice device)
             throws DeviceNotAvailableException {
         if (mPushAll) {
-            return device.doesFileExist(mBaseDeviceModuleDir, mUserId);
+            // ModuleDir already has a trailing separator
+            String sentinelPath = mBaseDeviceModuleDir + SENTINEL;
+            boolean exists = device.doesFileExist(sentinelPath, mUserId);
+            CLog.i("sentinel " + sentinelPath + (exists ? " exists" : " is missing"));
+            return exists;
         }
+
         for (Resolution resolution : RESOLUTIONS) {
             if (resolution.width > mMaxRes.width) {
                 break; // no need to check for resolutions greater than this
             }
+
             String deviceShortFilePath = mBaseDeviceShortDir + resolution.toString();
             String deviceFullFilePath = mBaseDeviceFullDir + resolution.toString();
-            if (!device.doesFileExist(deviceShortFilePath, mUserId)
-                    || !device.doesFileExist(deviceFullFilePath, mUserId)) {
+            String deviceShortSentinelPath = deviceShortFilePath + File.separator + SENTINEL;
+            String deviceFullSentinelPath = deviceFullFilePath + File.separator + SENTINEL;
+            if (!device.doesFileExist(deviceShortSentinelPath, mUserId)) {
+                CLog.i("Missing Sentinel file " + deviceShortSentinelPath);
                 return false;
             }
+            if (!device.doesFileExist(deviceFullSentinelPath, mUserId)) {
+                CLog.i("Missing Sentinel file " + deviceFullSentinelPath);
+                return false;
+            }
+            CLog.i("Sentinels present for resolution: " + resolution.toString());
         }
+        CLog.i("Sentinel files present");
         return true;
     }
 
@@ -480,31 +511,45 @@ public class MediaPreparer extends BaseTargetPreparer
             }
             String deviceShortFilePath = mBaseDeviceShortDir + resolution.toString();
             String deviceFullFilePath = mBaseDeviceFullDir + resolution.toString();
-            if (!device.doesFileExist(deviceShortFilePath, mUserId)
-                    || !device.doesFileExist(deviceFullFilePath, mUserId)) {
-                CLog.i("Copying files of resolution %s to device", resolution.toString());
+            String deviceShortSentinelPath = deviceShortFilePath + File.separator + SENTINEL;
+            String deviceFullSentinelPath = deviceFullFilePath + File.separator + SENTINEL;
+
+            // deal with missing short assets
+            if (!device.doesFileExist(deviceShortSentinelPath, mUserId)) {
+                CLog.i("Copying short files of resolution %s to device", resolution.toString());
                 String localShortDirName = "bbb_short/" + resolution.toString();
-                String localFullDirName = "bbb_full/" + resolution.toString();
                 File localShortDir = new File(mLocalMediaPath, localShortDirName);
+
+                device.pushDir(localShortDir, deviceShortFilePath, mUserId);
+                device.pushFile(localSentinel, deviceShortSentinelPath, mUserId);
+                CLog.i("Placed sentinel on device at " + deviceShortSentinelPath);
+            }
+
+            // deal with missing full assets
+            if (!device.doesFileExist(deviceFullSentinelPath, mUserId)) {
+                CLog.i("Copying full files of resolution %s to device", resolution.toString());
+                String localFullDirName = "bbb_full/" + resolution.toString();
                 File localFullDir = new File(mLocalMediaPath, localFullDirName);
-                // push short directory of given resolution, if not present on device
-                if (!device.doesFileExist(deviceShortFilePath, mUserId)) {
-                    device.pushDir(localShortDir, deviceShortFilePath, mUserId);
-                }
-                // push full directory of given resolution, if not present on device
-                if (!device.doesFileExist(deviceFullFilePath, mUserId)) {
-                    device.pushDir(localFullDir, deviceFullFilePath, mUserId);
-                }
+
+                device.pushDir(localFullDir, deviceFullFilePath, mUserId);
+                device.pushFile(localSentinel, deviceFullSentinelPath, mUserId);
+                CLog.i("Placed sentinel on device at " + deviceFullSentinelPath);
             }
         }
     }
 
     // copy everything from the host directory to the device
     protected void copyAll(ITestDevice device) throws DeviceNotAvailableException {
-        if (!device.doesFileExist(mBaseDeviceModuleDir, mUserId)) {
-            CLog.i("Copying files to device");
-            device.pushDir(new File(mLocalMediaPath), mBaseDeviceModuleDir, mUserId);
+        String deviceSentinelPath = mBaseDeviceModuleDir + SENTINEL;
+        if (device.doesFileExist(deviceSentinelPath, mUserId)) {
+            CLog.i("device has " + deviceSentinelPath + " indicating all files are downloaded");
+            return;
         }
+        CLog.i("Copying files to device directory " + mBaseDeviceModuleDir);
+        device.pushDir(new File(mLocalMediaPath), mBaseDeviceModuleDir, mUserId);
+
+        device.pushFile(localSentinel, deviceSentinelPath, mUserId);
+        CLog.i("Placed sentinel on device at " + deviceSentinelPath);
     }
 
     // Initialize directory strings where media files live on device
@@ -539,22 +584,49 @@ public class MediaPreparer extends BaseTargetPreparer
                 setMaxRes(testInfo); // max resolution only applies to video files
             }
             if (mediaFilesExistOnDevice(device)) {
-                // if files already on device, do nothing
                 CLog.i("Media files found on the device");
                 return;
             }
         }
 
-        if (mLocalMediaPath == null) {
-            // Option 'local-media-path' has not been defined
-            // Get directory to store media files on this host
-            File mediaFolder = downloadMediaToHost(device, buildInfo);
-            // set mLocalMediaPath to extraction location of media files
-            updateLocalMediaPath(device, mediaFolder);
-        }
-        CLog.i("Media files located on host at: " + mLocalMediaPath);
-        if (!mMediaDownloadOnly) {
-            copyMediaFiles(device);
+        try {
+            // set up the host-side sentinel file that we copy when we've finished installing
+            // Put some useful triaging and diagnostic information in the file
+            FileWriter myWriter = null;
+            try {
+                localSentinel = File.createTempFile("download-sentinel", null);
+
+                myWriter = new FileWriter(localSentinel, /*append*/ false);
+                myWriter.write("Asset Download Completion Sentinel\n");
+                {
+                    final String DATE_FORMAT_NOW = "yyyy-MM-dd HH:mm:ss a, z";
+                    Calendar cal = Calendar.getInstance();
+                    SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);
+                    myWriter.write("Downloaded at: " + sdf.format(cal.getTime()) + "\n");
+                }
+                myWriter.write("Pushed to device path: " + mBaseDeviceModuleDir + "\n");
+            } catch (IOException e) {
+                // we'll write an empty sentinel
+                CLog.w("error creating the local sentinel file, device installation may fail");
+            } finally {
+                StreamUtil.close(myWriter);
+            }
+
+            if (mLocalMediaPath == null) {
+                // Option 'local-media-path' has not been defined
+                // Get directory to store media files on this host
+                File mediaFolder = downloadMediaToHost(device, buildInfo);
+                // set mLocalMediaPath to extraction location of media files
+                updateLocalMediaPath(device, mediaFolder);
+            }
+            CLog.i("Media files located on host at: " + mLocalMediaPath);
+            if (!mMediaDownloadOnly) {
+                copyMediaFiles(device);
+            }
+        } finally {
+            // some cleanup on the host side
+            FileUtil.deleteFile(localSentinel);
+            localSentinel = null;
         }
     }
 
diff --git a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/testtype/suite/CompatibilitySuiteModuleLoader.java b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/testtype/suite/CompatibilitySuiteModuleLoader.java
index 7796e123..ff052c8a 100644
--- a/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/testtype/suite/CompatibilitySuiteModuleLoader.java
+++ b/common/host-side/tradefed/src/com/android/compatibility/common/tradefed/testtype/suite/CompatibilitySuiteModuleLoader.java
@@ -22,6 +22,7 @@ import com.android.tradefed.testtype.suite.SuiteModuleLoader;
 import com.android.tradefed.testtype.suite.SuiteTestFilter;
 import com.android.tradefed.util.AbiUtils;
 
+import java.io.File;
 import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Map;
@@ -44,11 +45,10 @@ public class CompatibilitySuiteModuleLoader extends SuiteModuleLoader {
         super(includeFilters,excludeFilters,testArgs,moduleArgs);
     }
 
-    /**
-     * {@inheritDoc}
-     */
+    /** {@inheritDoc} */
     @Override
     public void addFiltersToTest(
+            File moduleDir,
             IRemoteTest test,
             IAbi abi,
             String name,
@@ -60,6 +60,6 @@ public class CompatibilitySuiteModuleLoader extends SuiteModuleLoader {
             throw new IllegalArgumentException(String.format(
                     "Test in module %s must implement ITestFilterReceiver.", moduleId));
         }
-        super.addFiltersToTest(test,abi,name,includeFilters,excludeFilters);
+        super.addFiltersToTest(moduleDir, test, abi, name, includeFilters, excludeFilters);
     }
 }
diff --git a/common/host-side/tradefed/tests/res/testdata/IncrementalCtsDeviceInfo.deviceinfo.json b/common/host-side/tradefed/tests/res/testdata/IncrementalCtsDeviceInfo.deviceinfo.json
new file mode 100644
index 00000000..3c33857a
--- /dev/null
+++ b/common/host-side/tradefed/tests/res/testdata/IncrementalCtsDeviceInfo.deviceinfo.json
@@ -0,0 +1,42 @@
+{
+  "run_mode": "LIGHTWEIGHT_RUN",
+  "module": [
+    {
+      "module_name": "CtsDeqpTestCases",
+      "deps_details": [
+        {
+          "dep_name": "\/system\/lib64\/libmedia_helper.so",
+          "file_hash": "9c14151911ea6a64b795799885c66eb5"
+        },
+        {
+          "dep_name": "\/vendor\/lib64\/libdmabufheap.so",
+          "file_hash": "132dc8947db65da997716de0a3edd670"
+        },
+        {
+          "dep_name": "\/system\/lib64\/android.hardware.cas@1.0.so",
+          "file_hash": "c41b577815320f9ad3944d96c53b6dbe"
+        },
+        {
+          "dep_name": "\/system\/lib\/libion.so",
+          "file_hash": "92846cd4db2124f1d597a3fedf109df7"
+        },
+        {
+          "dep_name": "\/system\/lib64\/libtracing_perfetto.so",
+          "file_hash": "6d879b6ca866f1cec5acb2c8373b9e71"
+        },
+        {
+          "dep_name": "\/system\/lib64\/libc++.so",
+          "file_hash": "ce7f5940bb1f2b8083cb1e0ade97bea4"
+        },
+        {
+          "dep_name": "\/system\/lib64\/libETC1.so",
+          "file_hash": "8f9f7a2029fe58cac82ee4fade9e7df5"
+        },
+        {
+          "dep_name": "\/system\/lib64\/audiopolicy-types-aidl-cpp.so",
+          "file_hash": "36af8be478dbcf95f15d5b0171d3b483"
+        }
+      ]
+    }
+  ]
+}
diff --git a/common/host-side/tradefed/tests/res/testdata/base_build_target-files.zip b/common/host-side/tradefed/tests/res/testdata/current_build_target-files.zip
similarity index 100%
rename from common/host-side/tradefed/tests/res/testdata/base_build_target-files.zip
rename to common/host-side/tradefed/tests/res/testdata/current_build_target-files.zip
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
index 5fb094d4..5dabf97e 100644
--- a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/IncrementalDeqpPreparerTest.java
@@ -18,6 +18,7 @@ package com.android.compatibility.common.tradefed.targetprep;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.endsWith;
 import static org.mockito.Mockito.mock;
@@ -52,6 +53,9 @@ import java.util.Set;
 /** Unit tests for {@link IncrementalDeqpPreparer}. */
 @RunWith(JUnit4.class)
 public class IncrementalDeqpPreparerTest {
+    private static final String DEVICE_FINGERPRINT =
+            "generic/aosp_cf_x86_64_phone/vsoc_x86_64:S/AOSP"
+                    + ".MASTER/7363308:userdebug/test-keys";
 
     private IncrementalDeqpPreparer mPreparer;
     private ITestDevice mMockDevice;
@@ -63,63 +67,16 @@ public class IncrementalDeqpPreparerTest {
         mMockDevice = mock(ITestDevice.class);
     }
 
-    @SuppressWarnings("ResultOfMethodCallIgnored")
-    @Test
-    public void testVerifyIncrementalDeqp() throws Exception {
-        File resultDir = FileUtil.createTempDir("result");
-        try {
-            mPreparerSetter = new OptionSetter(mPreparer);
-            mPreparerSetter.setOptionValue(
-                    "incremental-deqp-preparer:run-mode", "DEVICE_APPLICATION");
-            IBuildInfo mMockBuildInfo = new BuildInfo();
-            IInvocationContext mMockContext = new InvocationContext();
-            mMockContext.addDeviceBuildInfo("build", mMockBuildInfo);
-            mMockContext.addAllocatedDevice("device", mMockDevice);
-            File deviceInfoDir = new File(resultDir, "device-info-files");
-            deviceInfoDir.mkdir();
-            CompatibilityBuildHelper mMockBuildHelper =
-                    new CompatibilityBuildHelper(mMockBuildInfo) {
-                        @Override
-                        public File getResultDir() {
-                            return resultDir;
-                        }
-                    };
-            InputStream perfDumpStream = getClass().getResourceAsStream("/testdata/perf-dump.txt");
-            File dumpFile = FileUtil.createTempFile("parseDump", "perf-dump.txt");
-            FileUtil.writeToFile(perfDumpStream, dumpFile);
-            when(mMockDevice.pullFile(endsWith("-perf-dump.txt")))
-                    .thenReturn(dumpFile, null, null, null, null, null);
-
-            File incrementalDeqpBaselineReport =
-                    new File(
-                            deviceInfoDir,
-                            IncrementalDeqpPreparer.INCREMENTAL_DEQP_BASELINE_REPORT_NAME);
-            assertFalse(incrementalDeqpBaselineReport.exists());
-            mPreparer.verifyIncrementalDeqp(mMockContext, mMockDevice, mMockBuildHelper);
-            assertTrue(
-                    mMockBuildInfo
-                            .getBuildAttributes()
-                            .containsKey(
-                                    IncrementalDeqpPreparer
-                                            .INCREMENTAL_DEQP_BASELINE_ATTRIBUTE_NAME));
-            assertTrue(incrementalDeqpBaselineReport.exists());
-        } finally {
-            FileUtil.recursiveDelete(resultDir);
-        }
-    }
-
     @SuppressWarnings("ResultOfMethodCallIgnored")
     @Test
     public void testRunIncrementalDeqp() throws Exception {
         File resultDir = FileUtil.createTempDir("result");
         InputStream zipStream =
-                getClass().getResourceAsStream("/testdata/base_build_target-files.zip");
+                getClass().getResourceAsStream("/testdata/current_build_target-files.zip");
         File zipFile = FileUtil.createTempFile("targetFile", ".zip");
         try {
             FileUtil.writeToFile(zipStream, zipFile);
             mPreparerSetter = new OptionSetter(mPreparer);
-            mPreparerSetter.setOptionValue(
-                    "incremental-deqp-preparer:base-build", zipFile.getAbsolutePath());
             mPreparerSetter.setOptionValue(
                     "incremental-deqp-preparer:current-build", zipFile.getAbsolutePath());
             IBuildInfo mMockBuildInfo = new BuildInfo();
@@ -140,11 +97,16 @@ public class IncrementalDeqpPreparerTest {
             FileUtil.writeToFile(perfDumpStream, dumpFile);
             when(mMockDevice.pullFile(endsWith("-perf-dump.txt")))
                     .thenReturn(dumpFile, null, null, null);
+            when(mMockDevice.getProperty("ro.build.fingerprint")).thenReturn(DEVICE_FINGERPRINT);
 
             File incrementalDeqpReport =
                     new File(deviceInfoDir, IncrementalDeqpPreparer.INCREMENTAL_DEQP_REPORT_NAME);
             assertFalse(incrementalDeqpReport.exists());
-            mPreparer.runIncrementalDeqp(mMockContext, mMockDevice, mMockBuildHelper);
+            mPreparer.runIncrementalDeqp(
+                    mMockContext,
+                    mMockDevice,
+                    mMockBuildHelper,
+                    IncrementalDeqpPreparer.RunMode.LIGHTWEIGHT_RUN);
             assertTrue(
                     mMockBuildInfo
                             .getBuildAttributes()
@@ -158,8 +120,11 @@ public class IncrementalDeqpPreparerTest {
 
     @SuppressWarnings("ResultOfMethodCallIgnored")
     @Test
-    public void testSkipPreparerWhenReportExists() throws Exception {
+    public void testRunIncrementalDeqp_skipPreparerWhenReportExists() throws Exception {
         File resultDir = FileUtil.createTempDir("result");
+        InputStream reportStream =
+                getClass()
+                        .getResourceAsStream("/testdata/IncrementalCtsDeviceInfo.deviceinfo.json");
         try {
             IBuildInfo mMockBuildInfo = new BuildInfo();
             IInvocationContext mMockContext = new InvocationContext();
@@ -170,6 +135,7 @@ public class IncrementalDeqpPreparerTest {
             File report =
                     new File(deviceInfoDir, IncrementalDeqpPreparer.INCREMENTAL_DEQP_REPORT_NAME);
             report.createNewFile();
+            FileUtil.writeToFile(reportStream, report);
             CompatibilityBuildHelper mMockBuildHelper =
                     new CompatibilityBuildHelper(mMockBuildInfo) {
                         @Override
@@ -178,7 +144,15 @@ public class IncrementalDeqpPreparerTest {
                         }
                     };
 
-            mPreparer.runIncrementalDeqp(mMockContext, mMockDevice, mMockBuildHelper);
+            mPreparer.runIncrementalDeqp(
+                    mMockContext,
+                    mMockDevice,
+                    mMockBuildHelper,
+                    IncrementalDeqpPreparer.RunMode.LIGHTWEIGHT_RUN);
+            assertTrue(
+                    mMockBuildInfo
+                            .getBuildAttributes()
+                            .containsKey(IncrementalDeqpPreparer.INCREMENTAL_DEQP_ATTRIBUTE_NAME));
         } finally {
             FileUtil.recursiveDelete(resultDir);
         }
@@ -208,10 +182,11 @@ public class IncrementalDeqpPreparerTest {
                                 "/system/deqp_dependency_file_a.so",
                                 "/vendor/deqp_dependency_file_b.so",
                                 "/vendor/file_not_exists.so"));
-        // base_build_target-files.zip is a stripped down version of the target-files.zip generated
-        // from the android build system, with a few added mocked target files for testing.
+        // current_build_target-files.zip is a stripped down version of the target-files.zip
+        // generated from the android build system, with a few added mocked target files for
+        // testing.
         InputStream zipStream =
-                getClass().getResourceAsStream("/testdata/base_build_target-files.zip");
+                getClass().getResourceAsStream("/testdata/current_build_target-files.zip");
         File zipFile = FileUtil.createTempFile("targetFile", ".zip");
         try {
             FileUtil.writeToFile(zipStream, zipFile);
@@ -236,19 +211,36 @@ public class IncrementalDeqpPreparerTest {
     }
 
     @Test
-    public void getBuildFingerPrint() throws IOException, TargetSetupError {
-        // base_build_target-files.zip is a stripped down version of the target-files.zip generated
-        // from the android build system, with a few added mocked target files for testing.
+    public void testValidateBuildFingerprint() throws Exception {
+        // current_build_target-files.zip is a stripped down version of the target-files.zip
+        // generated from the android build system, with a few added mocked target files for
+        // testing.
         InputStream zipStream =
-                getClass().getResourceAsStream("/testdata/base_build_target-files.zip");
+                getClass().getResourceAsStream("/testdata/current_build_target-files.zip");
         File zipFile = FileUtil.createTempFile("targetFile", ".zip");
         try {
             FileUtil.writeToFile(zipStream, zipFile);
+            when(mMockDevice.getProperty("ro.build.fingerprint")).thenReturn(DEVICE_FINGERPRINT);
 
-            assertEquals(
-                    mPreparer.getBuildFingerPrint(zipFile, mMockDevice),
-                    "generic/aosp_cf_x86_64_phone/vsoc_x86_64:S/AOSP"
-                            + ".MASTER/7363308:userdebug/test-keys");
+            mPreparer.validateBuildFingerprint(zipFile, mMockDevice);
+        } finally {
+            FileUtil.deleteFile(zipFile);
+        }
+    }
+
+    @Test
+    public void testValidateBuildFingerprint_fingerprintMismatch() throws Exception {
+        InputStream zipStream =
+                getClass().getResourceAsStream("/testdata/current_build_target-files.zip");
+        File zipFile = FileUtil.createTempFile("targetFile", ".zip");
+        try {
+            FileUtil.writeToFile(zipStream, zipFile);
+            when(mMockDevice.getProperty("ro.build.fingerprint"))
+                    .thenReturn(DEVICE_FINGERPRINT + "modified");
+
+            assertThrows(
+                    TargetSetupError.class,
+                    () -> mPreparer.validateBuildFingerprint(zipFile, mMockDevice));
         } finally {
             FileUtil.deleteFile(zipFile);
         }
diff --git a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparerTest.java b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparerTest.java
index 04460bde..0fd1f91d 100644
--- a/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparerTest.java
+++ b/common/host-side/tradefed/tests/src/com/android/compatibility/common/tradefed/targetprep/MediaPreparerTest.java
@@ -55,6 +55,8 @@ public class MediaPreparerTest {
     private static final String RUN_TESTS_AS_USER_KEY = "RUN_TESTS_AS_USER";
     private static final int TEST_USER_ID = 99;
 
+    private static final String SENTINEL = ".download-completed";
+
     private MediaPreparer mMediaPreparer;
     private DeviceBuildInfo mMockBuildInfo;
     private ITestDevice mMockDevice;
@@ -150,6 +152,7 @@ public class MediaPreparerTest {
                     resolution.toString());
             String fullFile = String.format("%s%s", mMediaPreparer.mBaseDeviceFullDir,
                     resolution.toString());
+            // RBE these are the things I have to fix up.
             when(mMockDevice.doesFileExist(shortFile, TEST_USER_ID)).thenReturn(true);
             when(mMockDevice.doesFileExist(fullFile, TEST_USER_ID)).thenReturn(true);
         }
@@ -165,10 +168,15 @@ public class MediaPreparerTest {
         mMediaPreparer.mBaseDeviceShortDir = "/sdcard/test/bbb_short/";
         mMediaPreparer.mBaseDeviceFullDir = "/sdcard/test/bbb_full/";
         for (MediaPreparer.Resolution resolution : MediaPreparer.RESOLUTIONS) {
-            String shortFile = String.format("%s%s", mMediaPreparer.mBaseDeviceShortDir,
-                    resolution.toString());
-            String fullFile = String.format("%s%s", mMediaPreparer.mBaseDeviceFullDir,
-                    resolution.toString());
+            // Preparer uses sentinel files in directories, not the directories themselves
+            String shortFile =
+                    String.format(
+                            "%s%s/%s",
+                            mMediaPreparer.mBaseDeviceShortDir, resolution.toString(), SENTINEL);
+            String fullFile =
+                    String.format(
+                            "%s%s/%s",
+                            mMediaPreparer.mBaseDeviceFullDir, resolution.toString(), SENTINEL);
             when(mMockDevice.doesFileExist(shortFile, TEST_USER_ID)).thenReturn(true);
             when(mMockDevice.doesFileExist(fullFile, TEST_USER_ID)).thenReturn(true);
         }
@@ -176,11 +184,28 @@ public class MediaPreparerTest {
     }
 
     @Test
-    public void testMediaFilesExistOnDeviceTrueWithPushAll() throws Exception {
+    public void testMediaFilesExistOnDeviceFalseWithPushAllInterrupted() throws Exception {
         mOptionSetter.setOptionValue("push-all", "true");
         mMediaPreparer.mBaseDeviceModuleDir = "/sdcard/test/android-cts-media/";
+        // Preparer uses sentinel files in directories, not the directories themselves
+        // directory, but not the sentinel
         when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceModuleDir, TEST_USER_ID))
                 .thenReturn(true);
+        when(mMockDevice.doesFileExist(
+                        mMediaPreparer.mBaseDeviceModuleDir + SENTINEL, TEST_USER_ID))
+                .thenReturn(false);
+
+        assertFalse(mMediaPreparer.mediaFilesExistOnDevice(mMockDevice));
+    }
+
+    @Test
+    public void testMediaFilesExistOnDeviceTrueWithPushAll() throws Exception {
+        mOptionSetter.setOptionValue("push-all", "true");
+        mMediaPreparer.mBaseDeviceModuleDir = "/sdcard/test/android-cts-media/";
+        // Preparer uses sentinel files in directories, not the directories themselves
+        when(mMockDevice.doesFileExist(
+                        mMediaPreparer.mBaseDeviceModuleDir + SENTINEL, TEST_USER_ID))
+                .thenReturn(true);
 
         assertTrue(mMediaPreparer.mediaFilesExistOnDevice(mMockDevice));
     }
@@ -189,7 +214,8 @@ public class MediaPreparerTest {
     public void testMediaFilesExistOnDeviceFalse() throws Exception {
         mMediaPreparer.mMaxRes = MediaPreparer.RESOLUTIONS[1];
         mMediaPreparer.mBaseDeviceShortDir = "/sdcard/test/bbb_short/";
-        String firstFileChecked = "/sdcard/test/bbb_short/176x144";
+        // Preparer uses sentinel files in directories, not the directories themselves
+        String firstFileChecked = "/sdcard/test/bbb_short/176x144/" + SENTINEL;
         when(mMockDevice.doesFileExist(firstFileChecked, TEST_USER_ID)).thenReturn(false);
 
         assertFalse(mMediaPreparer.mediaFilesExistOnDevice(mMockDevice));
@@ -199,7 +225,9 @@ public class MediaPreparerTest {
     public void testMediaFilesExistOnDevice_differentUserId() throws Exception {
         mOptionSetter.setOptionValue("push-all", "true");
         mMediaPreparer.mBaseDeviceModuleDir = "/sdcard/test/android-cts-media/";
-        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceModuleDir, TEST_USER_ID))
+        // Preparer uses sentinel files in directories, not the directories themselves
+        when(mMockDevice.doesFileExist(
+                        mMediaPreparer.mBaseDeviceModuleDir + SENTINEL, TEST_USER_ID))
                 .thenReturn(true);
 
         assertTrue(mMediaPreparer.mediaFilesExistOnDevice(mMockDevice));
@@ -215,7 +243,9 @@ public class MediaPreparerTest {
         mOptionSetter.setOptionValue("push-all", "true");
         mMediaPreparer.mBaseDeviceModuleDir = "/sdcard/test/android-cts-media/";
         int newTestUserId = TEST_USER_ID + 1;
-        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceModuleDir, newTestUserId))
+        // Preparer uses sentinel files in directories, not the directories themselves
+        when(mMockDevice.doesFileExist(
+                        mMediaPreparer.mBaseDeviceModuleDir + SENTINEL, newTestUserId))
                 .thenReturn(true);
 
         // The file exists for newTestUserId, not for TEST_USER_ID.
@@ -242,11 +272,13 @@ public class MediaPreparerTest {
         mMediaPreparer.mBaseDeviceModuleDir = "/sdcard/test/unittest/";
         mMediaPreparer.mBaseDeviceShortDir = "/sdcard/test/bbb_short/";
         mMediaPreparer.mBaseDeviceFullDir = "/sdcard/test/bbb_full/";
-        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceModuleDir, TEST_USER_ID))
+        // Preparer uses sentinel files in directories, not the directories themselves
+        when(mMockDevice.doesFileExist(
+                        mMediaPreparer.mBaseDeviceModuleDir + SENTINEL, TEST_USER_ID))
                 .thenReturn(true);
-        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceShortDir, TEST_USER_ID))
+        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceShortDir + SENTINEL, TEST_USER_ID))
                 .thenReturn(false);
-        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceFullDir, TEST_USER_ID))
+        when(mMockDevice.doesFileExist(mMediaPreparer.mBaseDeviceFullDir + SENTINEL, TEST_USER_ID))
                 .thenReturn(false);
 
         mMediaPreparer.copyMediaFiles(mMockDevice);
```

