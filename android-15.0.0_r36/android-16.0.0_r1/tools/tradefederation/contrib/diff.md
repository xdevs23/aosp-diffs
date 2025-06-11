```diff
diff --git a/.classpath b/.classpath
index afd7ef1..af25577 100644
--- a/.classpath
+++ b/.classpath
@@ -10,7 +10,7 @@
 	<classpathentry combineaccessrules="false" kind="src" path="/tradefederation"/>
 	<classpathentry combineaccessrules="false" kind="src" path="/loganalysis"/>
 	<classpathentry kind="var" path="TRADEFED_ROOT/out/soong/.intermediates/tools/tradefederation/core/tradefed-protos/linux_glibc_common/combined/tradefed-protos.jar"/>
-	<classpathentry kind="var" path="TRADEFED_ROOT/out/soong/.intermediates/external/guava/guava-jre/linux_glibc_common/combined/guava-jre.jar"/>
-	<classpathentry kind="var" path="TRADEFED_ROOT/out/soong/.intermediates/external/protobuf/libprotobuf-java-full/linux_glibc_common/javac/classes"/>
+	<classpathentry kind="var" path="TRADEFED_ROOT/out/soong/.intermediates/external/guava/guava/linux_glibc_common/combined/guava.jar"/>
+	<classpathentry kind="var" path="TRADEFED_ROOT/out/host/linux-x86/framework/libprotobuf-java-full.jar"/>
 	<classpathentry kind="output" path="bin"/>
 </classpath>
diff --git a/src/com/android/performance/PerfettoJavaHeapConfigTargetPreparer.java b/src/com/android/performance/PerfettoJavaHeapConfigTargetPreparer.java
new file mode 100644
index 0000000..912649a
--- /dev/null
+++ b/src/com/android/performance/PerfettoJavaHeapConfigTargetPreparer.java
@@ -0,0 +1,149 @@
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
+package com.android.performance;
+
+import com.android.tradefed.config.Option;
+import com.android.tradefed.config.OptionClass;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.invoker.TestInformation;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.targetprep.BaseTargetPreparer;
+import com.android.tradefed.targetprep.TargetSetupError;
+
+import java.io.File;
+import java.io.FileWriter;
+import java.io.IOException;
+
+/** A {@link ITargetPreparer} that generate Java heap profile for perfetto config */
+@OptionClass(alias = "perfetto-java-heap-config")
+public class PerfettoJavaHeapConfigTargetPreparer extends BaseTargetPreparer {
+
+    @Option(
+            name = "push-trace-config-file",
+            description = "Full path to push the trace on the device")
+    private String mOutputFile = "/data/misc/perfetto-traces/trace_config_java_heap.textproto";
+
+    @Option(
+            name = "process-names-to-profile",
+            description = "Comma-separated list of process names to profile.")
+    private String mProcessNames = "com.android.systemui";
+
+    @Option(
+            name = "buffer-size-kb",
+            description = "Buffer size in memory that store the whole java heap graph in kb")
+    private int mBufferSizeKb = 256000;
+
+    /** {@inheritDoc} */
+    @Override
+    public void setUp(TestInformation testInfo)
+            throws TargetSetupError, DeviceNotAvailableException {
+        File tempFile = null;
+        try {
+            tempFile = File.createTempFile("trace_config_java_heap", ".textproto");
+            writeTraceConfig(tempFile);
+            pushFile(testInfo.getDevice(), tempFile, mOutputFile);
+        } catch (IOException e) {
+            CLog.e("Error when creating Perfetto config", e);
+        } finally {
+            if (tempFile != null) {
+                tempFile.delete();
+            }
+        }
+    }
+
+    private void writeTraceConfig(File srcFile) {
+        CLog.i("Writing perfetto trace config for heap dump collection");
+        String result = generateConfig(mProcessNames, mBufferSizeKb);
+        CLog.i(String.format("Command result = %s", result));
+
+        FileWriter fileWriter = null;
+        try {
+            fileWriter = new FileWriter(srcFile, true);
+            storeToFile(srcFile.getName(), result, fileWriter);
+        } catch (IOException e) {
+            CLog.e(String.format("Unable to update file %s ", srcFile.getName()), e);
+        } finally {
+            if (fileWriter != null) {
+                try {
+                    fileWriter.close();
+                } catch (IOException closeException) {
+                    CLog.e(
+                            String.format("Unable to close file %s ", srcFile.getName()),
+                            closeException);
+                }
+            }
+        }
+    }
+
+    private String generateConfig(String processNames, int bufferSizeKb) {
+        return "buffers {\n"
+                + "  size_kb: "
+                + bufferSizeKb
+                + "\n"
+                + "  fill_policy: DISCARD\n"
+                + "}\n"
+                + "\n"
+                + "data_sources {\n"
+                + "  config {\n"
+                + "    name: \"android.java_hprof\"\n"
+                + "    java_hprof_config {\n"
+                + "      process_cmdline: \""
+                + processNames
+                + "\"\n"
+                + "      dump_smaps: true\n"
+                + "    }\n"
+                + "  }\n"
+                + "}\n"
+                + "\n"
+                + "data_source_stop_timeout_ms: 100000\n"
+                + "data_sources {\n"
+                + "  config {\n"
+                + "    name: \"android.packages_list\"\n"
+                + "  }\n"
+                + "}\n"
+                + "\n"
+                + "data_sources: {\n"
+                + "  config {\n"
+                + "    name: \"linux.process_stats\"\n"
+                + "    process_stats_config {\n"
+                + "      scan_all_processes_on_start: true\n"
+                + "    }\n"
+                + "  }\n"
+                + "}";
+    }
+
+    private void pushFile(ITestDevice device, File src, String remotePath)
+            throws DeviceNotAvailableException {
+        if (!device.pushFile(src, remotePath)) {
+            CLog.e(
+                    String.format(
+                            "Failed to push local '%s' to remote '%s'", src.getPath(), remotePath));
+        }
+    }
+
+    private void storeToFile(String targetFileName, String content, FileWriter target)
+            throws RuntimeException {
+        try {
+            target.write('\n');
+            target.write(content);
+            target.write('\n');
+        } catch (IOException e) {
+            throw new RuntimeException(
+                    String.format("Unable to write file %s ", targetFileName), e);
+        }
+    }
+}
diff --git a/src/com/android/uicd/tests/UiConductorTest.java b/src/com/android/uicd/tests/UiConductorTest.java
index dafbfd5..c72c0d8 100644
--- a/src/com/android/uicd/tests/UiConductorTest.java
+++ b/src/com/android/uicd/tests/UiConductorTest.java
@@ -501,7 +501,7 @@ public class UiConductorTest implements IRemoteTest, ITestFilterReceiver {
         public void processStartInvocation(
                 TestRecordProto.TestRecord record, IInvocationContext context) {
             mOutputFile = new File(mOutputPath + ".tmp").getAbsoluteFile();
-            setFileOutput(mOutputFile);
+            setOutputFile(mOutputFile);
             super.processStartInvocation(record, context);
         }
 
diff --git a/tests/.classpath b/tests/.classpath
index 75fef6d..1b6d370 100644
--- a/tests/.classpath
+++ b/tests/.classpath
@@ -12,9 +12,8 @@
 	<classpathentry combineaccessrules="false" kind="src" path="/tradefederation"/>
 	<classpathentry combineaccessrules="false" kind="src" path="/ddmlib"/>
 	<classpathentry combineaccessrules="false" kind="src" path="/tradefederation-contrib"/>
-	<classpathentry kind="var" path="TRADEFED_ROOT/out/soong/.intermediates/external/mockito/mockito-byte-buddy-agent/linux_glibc_common/combined/mockito-byte-buddy-agent.jar"/>
-	<classpathentry kind="var" path="TRADEFED_ROOT/out/soong/.intermediates/external/mockito/mockito-byte-buddy/linux_glibc_common/combined/mockito-byte-buddy.jar"/>
+	<classpathentry kind="var" path="TRADEFED_ROOT/out/soong/.intermediates/external/mockito/mockito/linux_glibc_common/combined/mockito.jar"/>
 	<classpathentry kind="var" path="TRADEFED_ROOT/out/soong/.intermediates/tools/tradefederation/core/tradefed-protos/linux_glibc_common/combined/tradefed-protos.jar"/>
-	<classpathentry kind="var" path="TRADEFED_ROOT/out/soong/.intermediates/external/guava/guava-jre/linux_glibc_common/combined/guava-jre.jar"/>
+	<classpathentry kind="var" path="TRADEFED_ROOT/out/soong/.intermediates/external/guava/guava/linux_glibc_common/combined/guava.jar"/>
 	<classpathentry kind="output" path="bin"/>
 </classpath>
diff --git a/tests/src/com/android/performance/PerfettoJavaHeapConfigTargetPreparerTest.java b/tests/src/com/android/performance/PerfettoJavaHeapConfigTargetPreparerTest.java
new file mode 100644
index 0000000..ff1a913
--- /dev/null
+++ b/tests/src/com/android/performance/PerfettoJavaHeapConfigTargetPreparerTest.java
@@ -0,0 +1,166 @@
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
+package com.android.performance;
+
+import static org.junit.Assert.assertEquals;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.when;
+
+import com.android.tradefed.config.ConfigurationException;
+import com.android.tradefed.config.OptionSetter;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.invoker.TestInformation;
+import com.android.tradefed.util.Pair;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.stubbing.Answer;
+
+import java.io.File;
+import java.nio.charset.StandardCharsets;
+import java.nio.file.Files;
+import java.util.ArrayList;
+import java.util.List;
+
+/** Unit tests for {@link PerfettoJavaHeapConfigTargetPreparer}. */
+@RunWith(JUnit4.class)
+public class PerfettoJavaHeapConfigTargetPreparerTest {
+
+    private final PerfettoJavaHeapConfigTargetPreparer mPreparer =
+            new PerfettoJavaHeapConfigTargetPreparer();
+    private ITestDevice mITestDevice = mock(ITestDevice.class);
+    private List<Pair<String, String>> mPushedFiles = new ArrayList<>();
+
+    @Before
+    public void setUp() {
+        try {
+            when(mITestDevice.pushFile(any(), any()))
+                    .thenAnswer(
+                            (Answer<File>)
+                                    invocation -> {
+                                        final File localFile = (File) invocation.getArguments()[0];
+                                        final String deviceFile =
+                                                (String) invocation.getArguments()[1];
+                                        final String content =
+                                                Files.readString(
+                                                        localFile.toPath(), StandardCharsets.UTF_8);
+                                        mPushedFiles.add(new Pair<>(deviceFile, content));
+                                        return null;
+                                    });
+        } catch (DeviceNotAvailableException e) {
+            throw new RuntimeException(e);
+        }
+    }
+
+    @Test
+    public void testNoParameters_pushesDefaultConfig() {
+        runPreparer();
+
+        assertOneFilePushed(
+                "/data/misc/perfetto-traces/trace_config_java_heap.textproto",
+                "buffers {\n"
+                        + "  size_kb: 256000\n"
+                        + "  fill_policy: DISCARD\n"
+                        + "}\n"
+                        + "\n"
+                        + "data_sources {\n"
+                        + "  config {\n"
+                        + "    name: \"android.java_hprof\"\n"
+                        + "    java_hprof_config {\n"
+                        + "      process_cmdline: \"com.android.systemui\"\n"
+                        + "      dump_smaps: true\n"
+                        + "    }\n"
+                        + "  }\n"
+                        + "}\n"
+                        + "\n"
+                        + "data_source_stop_timeout_ms: 100000\n"
+                        + "data_sources {\n"
+                        + "  config {\n"
+                        + "    name: \"android.packages_list\"\n"
+                        + "  }\n"
+                        + "}\n"
+                        + "\n"
+                        + "data_sources: {\n"
+                        + "  config {\n"
+                        + "    name: \"linux.process_stats\"\n"
+                        + "    process_stats_config {\n"
+                        + "      scan_all_processes_on_start: true\n"
+                        + "    }\n"
+                        + "  }\n"
+                        + "}");
+    }
+
+    @Test
+    public void testChangeProcessName_pushesConfigWithPassedProcessName()
+            throws ConfigurationException {
+        new OptionSetter(mPreparer).setOptionValue("process-names-to-profile", "com.other");
+
+        runPreparer();
+
+        assertOneFilePushed(
+                "/data/misc/perfetto-traces/trace_config_java_heap.textproto",
+                "buffers {\n"
+                        + "  size_kb: 256000\n"
+                        + "  fill_policy: DISCARD\n"
+                        + "}\n"
+                        + "\n"
+                        + "data_sources {\n"
+                        + "  config {\n"
+                        + "    name: \"android.java_hprof\"\n"
+                        + "    java_hprof_config {\n"
+                        + "      process_cmdline: \"com.other\"\n"
+                        + "      dump_smaps: true\n"
+                        + "    }\n"
+                        + "  }\n"
+                        + "}\n"
+                        + "\n"
+                        + "data_source_stop_timeout_ms: 100000\n"
+                        + "data_sources {\n"
+                        + "  config {\n"
+                        + "    name: \"android.packages_list\"\n"
+                        + "  }\n"
+                        + "}\n"
+                        + "\n"
+                        + "data_sources: {\n"
+                        + "  config {\n"
+                        + "    name: \"linux.process_stats\"\n"
+                        + "    process_stats_config {\n"
+                        + "      scan_all_processes_on_start: true\n"
+                        + "    }\n"
+                        + "  }\n"
+                        + "}");
+    }
+
+    private void runPreparer() {
+        final TestInformation testInformation = mock(TestInformation.class);
+        when(testInformation.getDevice()).thenReturn(mITestDevice);
+        try {
+            mPreparer.setUp(testInformation);
+        } catch (Throwable e) {
+            throw new RuntimeException(e);
+        }
+    }
+
+    private void assertOneFilePushed(String pushedPath, String fileContent) {
+        assertEquals(1, mPushedFiles.size());
+        assertEquals(pushedPath, mPushedFiles.get(0).first);
+        assertEquals(fileContent.strip(), mPushedFiles.get(0).second.strip());
+    }
+}
```

