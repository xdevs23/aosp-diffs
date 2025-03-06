```diff
diff --git a/tests/AacDecBenchmark/AacDecBenchmark.cpp b/tests/AacDecBenchmark/AacDecBenchmark.cpp
new file mode 100644
index 0000000..6a8b421
--- /dev/null
+++ b/tests/AacDecBenchmark/AacDecBenchmark.cpp
@@ -0,0 +1,320 @@
+/******************************************************************************
+ *
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at:
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ *
+ *****************************************************************************
+ */
+
+#include <benchmark/benchmark.h>
+#include <log/log.h>
+
+#include <cstdio>
+#include <iostream>
+#include <memory>
+#include <string>
+#include <vector>
+
+#include "aacdecoder_lib.h"
+
+class AACDecoder {
+   private:
+    HANDLE_AACDECODER mAACDecoder;
+    CStreamInfo* mStreamInfo;
+
+   public:
+    AACDecoder() : mAACDecoder(nullptr), mStreamInfo(nullptr) {}
+
+    bool initialize() {
+        mAACDecoder = aacDecoder_Open(TT_MP4_RAW, 1);
+        if (!mAACDecoder) {
+            ALOGE("Failed to initialize AAC decoder");
+            return false;
+        }
+
+        mStreamInfo = aacDecoder_GetStreamInfo(mAACDecoder);
+        if (!mStreamInfo) {
+            ALOGE("Failed to get stream info after initialization");
+            return false;
+        }
+        return true;
+    }
+
+    ~AACDecoder() {
+        if (mAACDecoder) {
+            aacDecoder_Close(mAACDecoder);
+        }
+    }
+
+    int getChannels() const { return mStreamInfo ? mStreamInfo->numChannels : 0; }
+    int getFrameSize() const { return mStreamInfo ? mStreamInfo->frameSize : 0; }
+    int getSampleRate() const { return mStreamInfo ? mStreamInfo->sampleRate : 0; }
+
+    bool decode(const std::vector<std::pair<std::vector<uint8_t>, int>>& inputBuffers) {
+        for (const auto& [buffer, flag] : inputBuffers) {
+            std::vector<INT_PCM> frameOutput;
+            if (flag == 2) {
+                if (!configureDecoder(buffer)) {
+                    return false;
+                }
+            } else {
+                if (!decodeFrame(buffer, frameOutput)) {
+                    return false;
+                }
+            }
+        }
+        return true;
+    }
+
+   private:
+    bool configureDecoder(const std::vector<uint8_t>& configBuffer) {
+        UINT bytesRead = configBuffer.size();
+        UCHAR* configData = const_cast<UCHAR*>(configBuffer.data());
+        UCHAR* configArray[1] = {configData};
+
+        AAC_DECODER_ERROR err = aacDecoder_ConfigRaw(mAACDecoder, configArray, &bytesRead);
+        if (err != AAC_DEC_OK) {
+            ALOGE("Failed to configure decoder: error %d", err);
+            return false;
+        }
+        return true;
+    }
+
+    bool decodeFrame(const std::vector<uint8_t>& inputBuffer, std::vector<INT_PCM>& outputBuffer) {
+        constexpr size_t kOutputBufferSize = 10240;
+        UINT bytesRead = inputBuffer.size();
+        UINT validBytes = bytesRead;
+        UCHAR* inputPtr = const_cast<UCHAR*>(inputBuffer.data());
+        UCHAR* bufferArray[1] = {inputPtr};
+
+        AAC_DECODER_ERROR err = aacDecoder_Fill(mAACDecoder, bufferArray, &bytesRead, &validBytes);
+        if (err != AAC_DEC_OK) {
+            ALOGE("Failed to fill decoder buffer: error %d", err);
+            return false;
+        }
+
+        outputBuffer.resize(kOutputBufferSize);  // Ensure buffer is large enough
+        err = aacDecoder_DecodeFrame(mAACDecoder, outputBuffer.data(), outputBuffer.size(), 0);
+        if (err != AAC_DEC_OK) {
+            ALOGE("Failed to decode frame: error %d", err);
+            return false;
+        }
+
+        outputBuffer.resize(mStreamInfo->numChannels * mStreamInfo->frameSize);
+        return true;
+    }
+};
+
+std::vector<std::pair<std::vector<uint8_t>, int>> readInputFiles(const std::string& folderPath,
+                                                                 const std::string& bitstreamFile,
+                                                                 const std::string& infoFile) {
+    std::string fullBitstreamPath = folderPath + "/" + bitstreamFile;
+    std::string fullInfoPath = folderPath + "/" + infoFile;
+    std::vector<std::pair<std::vector<uint8_t>, int>> inputBuffers;
+
+    FILE* bitStreamFilePtr = fopen(fullBitstreamPath.c_str(), "rb");
+    if (!bitStreamFilePtr) {
+        ALOGE("Failed to open bitstream file %s", fullBitstreamPath.c_str());
+        return inputBuffers;
+    }
+
+    FILE* infoFilePtr = fopen(fullInfoPath.c_str(), "r");
+    if (!infoFilePtr) {
+        ALOGE("Failed to open info file %s", fullInfoPath.c_str());
+        return inputBuffers;
+    }
+
+    int bufferSize, flag;
+    long pts;
+
+    while (fscanf(infoFilePtr, "%d %d %ld", &bufferSize, &flag, &pts) == 3) {
+        std::vector<uint8_t> buffer(bufferSize);
+        size_t bytesRead = fread(buffer.data(), 1, bufferSize, bitStreamFilePtr);
+        if (bytesRead != bufferSize) {
+            ALOGE("Failed to read input data");
+            return std::vector<std::pair<std::vector<uint8_t>, int>>();
+        }
+        inputBuffers.emplace_back(std::move(buffer), flag);
+    }
+
+    fclose(bitStreamFilePtr);
+    fclose(infoFilePtr);
+    return inputBuffers;
+}
+
+static void BM_DecodeAAC(benchmark::State& state, const std::string& inpFolderPath,
+                         const std::string& bitstreamFile, const std::string& infoFile) {
+    auto inputBuffers = readInputFiles(inpFolderPath, bitstreamFile, infoFile);
+    if(inputBuffers.empty()) {
+        state.SkipWithError("Failed to read input data completely");
+    }
+    AACDecoder decoder;
+
+    if (!decoder.initialize()) {
+        state.SkipWithError("Unable to initialize decoder");
+    }
+
+    for (auto _ : state) {
+        if(!decoder.decode(inputBuffers)) {
+            state.SkipWithError("Unable to decode the Stream");
+        }
+    }
+
+    state.SetLabel(bitstreamFile + ", " + std::to_string(decoder.getChannels()) + ", "
+                   + std::to_string(decoder.getSampleRate()) + ", "
+                   + std::to_string(decoder.getFrameSize()));
+}
+
+// Function to register benchmarks
+void RegisterBenchmarks(const std::string& folderPath) {
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_1ch_8kHz_64kbps_lc", BM_DecodeAAC,
+                                 folderPath, "bbb_1ch_8kHz_64kbps_lc.bin",
+                                 "bbb_1ch_8kHz_64kbps_lc.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_1ch_48kHz_128kbps_lc", BM_DecodeAAC,
+                                 folderPath, "bbb_1ch_48kHz_128kbps_lc.bin",
+                                 "bbb_1ch_48kHz_128kbps_lc.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_2ch_8kHz_64kbps_lc", BM_DecodeAAC,
+                                 folderPath, "bbb_2ch_8kHz_64kbps_lc.bin",
+                                 "bbb_2ch_8kHz_64kbps_lc.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_2ch_48kHz_128kbps_lc", BM_DecodeAAC,
+                                 folderPath, "bbb_2ch_48kHz_128kbps_lc.bin",
+                                 "bbb_2ch_48kHz_128kbps_lc.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_6ch_8kHz_64kbps_lc", BM_DecodeAAC,
+                                 folderPath, "bbb_6ch_8kHz_64kbps_lc.bin",
+                                 "bbb_6ch_8kHz_64kbps_lc.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_6ch_48kHz_128kbps_lc", BM_DecodeAAC,
+                                 folderPath, "bbb_6ch_48kHz_128kbps_lc.bin",
+                                 "bbb_6ch_48kHz_128kbps_lc.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_1ch_16kHz_64kbps_he", BM_DecodeAAC,
+                                 folderPath, "bbb_1ch_16kHz_64kbps_he.bin",
+                                 "bbb_1ch_16kHz_64kbps_he.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_1ch_48kHz_128kbps_he", BM_DecodeAAC,
+                                 folderPath, "bbb_1ch_48kHz_128kbps_he.bin",
+                                 "bbb_1ch_48kHz_128kbps_he.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_2ch_16kHz_64kbps_he", BM_DecodeAAC,
+                                 folderPath, "bbb_2ch_16kHz_64kbps_he.bin",
+                                 "bbb_2ch_16kHz_64kbps_he.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_2ch_48kHz_128kbps_he", BM_DecodeAAC,
+                                 folderPath, "bbb_2ch_48kHz_128kbps_he.bin",
+                                 "bbb_2ch_48kHz_128kbps_he.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_2ch_16kHz_64kbps_hev2", BM_DecodeAAC,
+                                 folderPath, "bbb_2ch_16kHz_64kbps_hev2.bin",
+                                 "bbb_2ch_16kHz_64kbps_hev2.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_2ch_48kHz_128kbps_hev2", BM_DecodeAAC,
+                                 folderPath, "bbb_2ch_48kHz_128kbps_hev2.bin",
+                                 "bbb_2ch_48kHz_128kbps_hev2.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_1ch_48kHz_128kbps_ld", BM_DecodeAAC,
+                                 folderPath, "bbb_1ch_48kHz_128kbps_ld.bin",
+                                 "bbb_1ch_48kHz_128kbps_ld.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_2ch_48kHz_128kbps_ld", BM_DecodeAAC,
+                                 folderPath, "bbb_2ch_48kHz_128kbps_ld.bin",
+                                 "bbb_2ch_48kHz_128kbps_ld.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_6ch_48kHz_128kbps_ld", BM_DecodeAAC,
+                                 folderPath, "bbb_6ch_48kHz_128kbps_ld.bin",
+                                 "bbb_6ch_48kHz_128kbps_ld.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_1ch_16kHz_64kbps_eld", BM_DecodeAAC,
+                                 folderPath, "bbb_1ch_16kHz_64kbps_eld.bin",
+                                 "bbb_1ch_16kHz_64kbps_eld.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_1ch_48kHz_128kbps_eld", BM_DecodeAAC,
+                                 folderPath, "bbb_1ch_48kHz_128kbps_eld.bin",
+                                 "bbb_1ch_48kHz_128kbps_eld.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_2ch_16kHz_64kbps_eld", BM_DecodeAAC,
+                                 folderPath, "bbb_2ch_16kHz_64kbps_eld.bin",
+                                 "bbb_2ch_16kHz_64kbps_eld.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_2ch_48kHz_128kbps_eld", BM_DecodeAAC,
+                                 folderPath, "bbb_2ch_48kHz_128kbps_eld.bin",
+                                 "bbb_2ch_48kHz_128kbps_eld.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_6ch_16kHz_64kbps_eld", BM_DecodeAAC,
+                                 folderPath, "bbb_6ch_16kHz_64kbps_eld.bin",
+                                 "bbb_6ch_16kHz_64kbps_eld.info");
+    benchmark::RegisterBenchmark("BM_DecodeAAC/bbb_6ch_48kHz_128kbps_eld", BM_DecodeAAC,
+                                 folderPath, "bbb_6ch_48kHz_128kbps_eld.bin",
+                                 "bbb_6ch_48kHz_128kbps_eld.info");
+}
+
+class CustomCsvReporter : public benchmark::BenchmarkReporter {
+   public:
+    CustomCsvReporter() : mPrintedHeader(false) {}
+    virtual bool ReportContext(const Context& context);
+    virtual void ReportRuns(const std::vector<Run>& reports);
+
+   private:
+    void PrintRunData(const Run& report);
+    bool mPrintedHeader;
+    std::vector<std::string> mHeaders = {"File",      "Channels",      "SampleRate",
+                                         "FrameSize", "real_time(ns)", "cpu_time(ns)"};
+};
+
+bool CustomCsvReporter::ReportContext(const Context& context /* __unused */) { return true; }
+
+void CustomCsvReporter::ReportRuns(const std::vector<Run>& reports) {
+    std::ostream& Out = GetOutputStream();
+
+    if (!mPrintedHeader) {
+        // print the header
+        for (auto header = mHeaders.begin(); header != mHeaders.end();) {
+            Out << *header++;
+            if (header != mHeaders.end()) Out << ",";
+        }
+        Out << "\n";
+        mPrintedHeader = true;
+    }
+
+    // print results for each run
+    for (const auto& run : reports) {
+        PrintRunData(run);
+    }
+}
+
+void CustomCsvReporter::PrintRunData(const Run& run) {
+    if (run.skipped) {
+        return;
+    }
+    std::ostream& Out = GetOutputStream();
+    Out << run.report_label << ",";
+    Out << run.GetAdjustedRealTime() << ",";
+    Out << run.GetAdjustedCPUTime() << ",";
+    Out << '\n';
+}
+
+int main(int argc, char** argv) {
+    std::unique_ptr<benchmark::BenchmarkReporter> csvReporter;
+    std::string pathArg, inpFolderPath;
+
+    for (int i = 1; i < argc; ++i) {
+        // pass --path=/path/to/resourcefolder in command line while running without atest
+        // to specify where resources are present
+        if (std::string(argv[i]).find("--path") != std::string ::npos) {
+            pathArg = argv[i];
+            auto separator = pathArg.find('=');
+            if (separator != std::string::npos) {
+                inpFolderPath = pathArg.substr(separator + 1);
+            }
+        }
+        // pass --benchmark_out=/path/to/.csv in command line to generate csv report
+        if (std::string(argv[i]).find("--benchmark_out") != std::string::npos) {
+            csvReporter.reset(new CustomCsvReporter);
+            break;
+        }
+    }
+
+    if (inpFolderPath.empty()) {
+        inpFolderPath = "/sdcard/test/AacDecBenchmark-1.0";
+    }
+    RegisterBenchmarks(inpFolderPath);
+    benchmark::Initialize(&argc, argv);
+    benchmark::RunSpecifiedBenchmarks(nullptr, csvReporter.get());
+    benchmark::Shutdown();
+    return 0;
+}
diff --git a/tests/AacDecBenchmark/Android.bp b/tests/AacDecBenchmark/Android.bp
new file mode 100644
index 0000000..58f15b2
--- /dev/null
+++ b/tests/AacDecBenchmark/Android.bp
@@ -0,0 +1,33 @@
+// Copyright (C) 2024 The Android Open Source Project
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
+    // See: http://go/android-license-faq
+    default_team: "trendy_team_android_media_codec_framework",
+    default_applicable_licenses: ["external_aac_license"],
+}
+
+cc_benchmark {
+    name: "AacDecBenchmark",
+    host_supported: true,
+    srcs: ["AacDecBenchmark.cpp"],
+    shared_libs: [
+        "liblog",
+    ],
+    static_libs: [
+        "libFraunhoferAAC",
+        "libgoogle-benchmark",
+    ],
+    test_suites: ["device-tests"],
+}
diff --git a/tests/AacDecBenchmark/AndroidTest.xml b/tests/AacDecBenchmark/AndroidTest.xml
new file mode 100644
index 0000000..5df315d
--- /dev/null
+++ b/tests/AacDecBenchmark/AndroidTest.xml
@@ -0,0 +1,41 @@
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
+<configuration description="Unit test configuration for AacDecBenchmark">
+    <option name="test-suite-tag" value="device-tests" />
+    <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
+        <option name="cleanup" value="true" />
+        <option name="push-file" key="AacDecBenchmark" value="/data/local/tmp/AacDecBenchmark" />
+    </target_preparer>
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.DynamicConfigPusher">
+        <option name="target" value="host" />
+        <option name="config-filename" value="AacDecBenchmark" />
+        <option name="version" value="1.0"/>
+    </target_preparer>
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.DynamicConfigPusher">
+        <option name="target" value="device" />
+        <option name="config-filename" value="AacDecBenchmark" />
+        <option name="version" value="1.0"/>
+    </target_preparer>
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.MediaPreparer">
+        <option name="push-all" value="true" />
+        <option name="media-folder-name" value="AacDecBenchmark-1.0" />
+        <option name="dynamic-config-module" value="AacDecBenchmark" />
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.GoogleBenchmarkTest" >
+        <option name="native-benchmark-device-path" value="/data/local/tmp" />
+        <option name="benchmark-module-name" value="AacDecBenchmark" />
+    </test>
+</configuration>
diff --git a/tests/AacDecBenchmark/DynamicConfig.xml b/tests/AacDecBenchmark/DynamicConfig.xml
new file mode 100644
index 0000000..48a2b94
--- /dev/null
+++ b/tests/AacDecBenchmark/DynamicConfig.xml
@@ -0,0 +1,20 @@
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
+
+<dynamicConfig>
+    <entry key="media_files_url">
+        <value>https://dl.google.com/android-unittest/media/external/aac/tests/AacDecBenchmark/AacDecBenchmark-1.0.zip</value>
+    </entry>
+</dynamicConfig>
diff --git a/tests/AacDecBenchmark/README.md b/tests/AacDecBenchmark/README.md
new file mode 100644
index 0000000..e60a63e
--- /dev/null
+++ b/tests/AacDecBenchmark/README.md
@@ -0,0 +1,120 @@
+# Benchmark tests
+
+This Benchmark app analyses the time taken by AAC Decoder for given set of inputs. It is used to benchmark decoder module on android devices.
+
+This page describes steps to run the AAC decoder Benchmark test.
+
+Run the following steps to build the test suite:
+```
+mmm external/aac/tests/AacDecBenchmark/
+```
+
+# Resources
+The resource folder for the tests is taken from [here](https://dl.google.com/android-unittest/media/external/aac/tests/AacDecBenchmark/AacDecBenchmark-1.0.zip)
+
+Download the AacDecBenchmark-1.0.zip folder, unzip and push it to any path on the device, Let's say the path be /sdcard/test. You can give the path wherever you chose to put the files.
+
+```
+unzip AacDecBenchmark-1.0.zip
+adb push AacDecBenchmark-1.0 /sdcard/test
+```
+
+# <a name="BenchmarkApplication"></a> Benchmark Application
+To run the test suite for measuring performance, follow the following steps:
+
+Benchmark Application can be run in two ways.
+
+## Steps to run with atest
+Note that atest command will install Benchmark application and push the required test files to the device as well.
+
+For running the benchmark test, run the following command
+```
+atest AacDecBenchmark
+```
+
+## Steps to run without atest (push binary to the device and run)
+
+To run the test suite for measuring performance of the decoder, follow the following steps:
+
+The 64-bit binaries will be created in the following path : ${OUT}/data/benchmarktest64/
+
+The 32-bit binaries will be created in the following path : ${OUT}/data/benchmarktest/
+
+To test 64-bit binary push binaries from benchmarktest64.
+
+```
+adb push $(OUT)/data/benchmarktest64/AacDecBenchmark/AacDecBenchmark /data/local/tmp/
+```
+
+To test 32-bit binary push binaries from benchmarktest.
+
+```
+adb push $(OUT)/data/benchmarktest/AacDecBenchmark/AacDecBenchmark /data/local/tmp/
+```
+
+To get the resource files for the test follow instructions given in [Resources](#Resources)
+
+After running the above steps, /sdcard/test should contain AacDecBenchmark-1.0 folder and /data/local/tmp should contain benchmark binary to be executed.
+
+Run the following commands to see the benchmark results
+```
+adb shell
+cd /data/local/tmp/
+chmod a+x AacDecBenchmark
+./AacDecBenchmark
+```
+
+Run the below commands to generate a csv report and see the benchmark results
+```
+adb shell
+cd /data/local/tmp/
+chmod a+x AacDecBenchmark
+./AacDecBenchmark --benchmark_out=output.csv
+```
+
+if the folder path where the resource files are pushed is different from /sdcard/test/ , pass the actual folder path as an argument as shown below and run the following commands to see the benchmark results. Here let's say the path be /sdcard/test/AacDecBenchmark-1.0
+```
+adb shell
+cd /data/local/tmp/
+chmod a+x AacDecBenchmark
+./AacDecBenchmark --path=/sdcard/test/AacDecBenchmark-1.0
+```
+
+Run the below commands to store the benchmark results in an output.csv file which will be generated in the same path on the device.
+
+You can modify the output csv filename to any name and can be generated in any given absolute path.
+```
+adb shell
+cd /data/local/tmp/
+chmod a+x AacDecBenchmark
+./AacDecBenchmark --path=/sdcard/test/AacDecBenchmark-1.0 --benchmark_out=output.csv
+```
+
+# Analysis
+
+The benchmark results are stored in a CSV file if opted, which can be used for analysis.
+
+Note: This timestamp is in nano seconds and will change based on current system time.
+
+This csv file can be pulled from the device using "adb pull" command.
+```
+adb pull /data/local/tmp/output.csv ./output.csv
+```
+
+## CSV Columns
+
+Following columns are available in CSV.
+
+Note: All time values are in nano seconds
+
+1. **fileName**: The file being used as an input for the benchmark test.
+
+2. **Channels**: Number of channels does the input audio bitstream contain.
+
+3. **SampleRate**: SampleRate of the input audio bitstream.
+
+4. **FrameSize**: FrameSize of the input audio bitstream.
+
+5. **real_time**: Measures total elapsed time  from start to end of process, including wait times and delays.
+
+6. **cpu_time**: Measures total time spent by cpu actively executing instructions for a process.
```

