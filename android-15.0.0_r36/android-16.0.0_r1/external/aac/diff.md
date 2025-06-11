```diff
diff --git a/Android.bp b/Android.bp
index 6060256..1c7192d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -94,7 +94,7 @@ cc_library_static {
 
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.media.swcodec",
     ],
     min_sdk_version: "29",
diff --git a/OWNERS b/OWNERS
index 5f90cef..c642718 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 jmtrivi@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/tests/AacEncBenchmark/AacEncBenchmark.cpp b/tests/AacEncBenchmark/AacEncBenchmark.cpp
new file mode 100644
index 0000000..71a3bee
--- /dev/null
+++ b/tests/AacEncBenchmark/AacEncBenchmark.cpp
@@ -0,0 +1,340 @@
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
+#include <iostream>
+#include <sys/stat.h>
+#include <vector>
+
+#include "aacenc_lib.h"
+
+class AACEncoder {
+   private:
+    HANDLE_AACENCODER mAACEncoder;
+    AACENC_InfoStruct mEncInfo;
+    const AUDIO_OBJECT_TYPE mProfile;
+    const CHANNEL_MODE mChannelCount;
+    const int mSampleRate;
+    const int mBitRate;
+
+   public:
+    AACEncoder(int sampleRate, int bitRate, AUDIO_OBJECT_TYPE profile, CHANNEL_MODE channelCount)
+        : mAACEncoder(nullptr), mProfile(profile), mChannelCount(channelCount),
+        mSampleRate(sampleRate), mBitRate(bitRate) {}
+
+    bool initialize() {
+        if (aacEncOpen(&mAACEncoder, 0, 0) != AACENC_OK) {
+            ALOGE("Failed to initialize AAC encoder");
+            return false;
+        }
+
+        if (aacEncoder_SetParam(mAACEncoder, AACENC_AOT, mProfile) != AACENC_OK
+            || aacEncoder_SetParam(mAACEncoder, AACENC_SAMPLERATE, mSampleRate) != AACENC_OK
+            || aacEncoder_SetParam(mAACEncoder, AACENC_CHANNELMODE, mChannelCount) != AACENC_OK
+            || aacEncoder_SetParam(mAACEncoder, AACENC_BITRATE, mBitRate) != AACENC_OK
+            || aacEncoder_SetParam(mAACEncoder, AACENC_TRANSMUX, TT_MP4_RAW) != AACENC_OK) {
+            ALOGE("Failed to set AAC encoder parameters");
+            return false;
+        }
+
+        if (aacEncEncode(mAACEncoder, nullptr, nullptr, nullptr, nullptr) != AACENC_OK) {
+            ALOGE("Unable to initialize encoder for profile:%d, sample-rate: %d, bit-rate: %d, "
+                "channels: %d", mProfile, mSampleRate, mBitRate, mChannelCount);
+            return false;
+        }
+
+        if (aacEncInfo(mAACEncoder, &mEncInfo) != AACENC_OK) {
+            ALOGE("Failed to get AAC encoder info");
+            return false;
+        }
+        return true;
+    }
+
+    ~AACEncoder() {
+        if (mAACEncoder) {
+            aacEncClose(&mAACEncoder);
+        }
+    }
+
+    int getChannels() const { return aacEncoder_GetParam(mAACEncoder, AACENC_CHANNELMODE); }
+    int getSampleRate() const { return aacEncoder_GetParam(mAACEncoder, AACENC_SAMPLERATE); }
+    int getBitRate() const { return aacEncoder_GetParam(mAACEncoder, AACENC_BITRATE); }
+    int getProfile() const { return aacEncoder_GetParam(mAACEncoder, AACENC_AOT); }
+
+    bool encode(const std::vector<uint8_t>& pcmFrames) {
+        size_t frameSize = mEncInfo.frameLength * mChannelCount * sizeof(uint16_t);
+        std::vector<uint8_t> encodedBuffer(frameSize);
+        AACENC_BufDesc inBufDesc, outBufDesc;
+        AACENC_InArgs inArgs;
+        AACENC_OutArgs outArgs;
+
+        void* outBuffer[] = {encodedBuffer.data()};
+        int outBufferIds[] = {OUT_BITSTREAM_DATA};
+        int outBufferSize[] = {static_cast<int>(encodedBuffer.size())};
+        int outBufferElSize[] = {sizeof(UCHAR)};
+
+        outBufDesc.numBufs = sizeof(outBuffer) / sizeof(void*);
+        outBufDesc.bufs = (void**)&outBuffer;
+        outBufDesc.bufferIdentifiers = outBufferIds;
+        outBufDesc.bufSizes = outBufferSize;
+        outBufDesc.bufElSizes = outBufferElSize;
+
+        size_t numFrames = pcmFrames.size() / frameSize;
+
+        for (size_t frameIdx = 0; ; ++frameIdx) {
+
+            const uint8_t* frameData = nullptr;
+            void* inBuffer[1];
+            int inBufferSize[1];
+            if (frameIdx < numFrames) {
+                frameData = pcmFrames.data() + frameIdx * frameSize;
+            }
+
+            if (frameData != nullptr) {
+                inBuffer[0] = const_cast<uint8_t*>(frameData);
+                inBufferSize[0] = static_cast<int>(frameSize);
+                inArgs.numInSamples = frameSize / sizeof(uint16_t);
+            } else {
+                inBuffer[0] = nullptr;
+                inBufferSize[0] = 0;
+                inArgs.numInSamples = -1;
+            }
+
+            int inBufferIds[] = {IN_AUDIO_DATA};
+            int inBufferElSize[] = {sizeof(int16_t)};
+
+            inBufDesc.numBufs = sizeof(inBuffer) / sizeof(void*);
+            inBufDesc.bufs = (void**)&inBuffer;
+            inBufDesc.bufferIdentifiers = inBufferIds;
+            inBufDesc.bufSizes = inBufferSize;
+            inBufDesc.bufElSizes = inBufferElSize;
+            AACENC_ERROR err =
+                aacEncEncode(mAACEncoder, &inBufDesc, &outBufDesc, &inArgs, &outArgs);
+            if (err != AACENC_OK) {
+                if (err == AACENC_ENCODE_EOF) {
+                    break;
+                }
+                ALOGE("Failed to encode AAC frame");
+                return false;
+            }
+        }
+        return true;
+    }
+};
+
+std::vector<uint8_t> readInputFile(const std::string& folderPath, const std::string& pcmFile) {
+    std::string fullPcmPath = folderPath + "/" + pcmFile;
+    std::vector<uint8_t> inputBuffer;
+
+    FILE* pcmFilePtr = fopen(fullPcmPath.c_str(), "rb");
+    if (!pcmFilePtr) {
+        ALOGE("Failed to open pcm file %s", fullPcmPath.c_str());
+        return inputBuffer;
+    }
+
+    struct stat fileStat;
+    int fd = fileno(pcmFilePtr);
+
+    if (fstat(fd, &fileStat) == -1) {
+        ALOGE("Error occured while accessing the pcm file");
+        return inputBuffer;
+    }
+    size_t fileSize = fileStat.st_size;
+    inputBuffer.resize(fileSize);
+    size_t bytesRead = fread(inputBuffer.data(), sizeof(uint8_t), inputBuffer.size(), pcmFilePtr);
+    if (bytesRead != fileSize) {
+        ALOGE("Failed to read the complete pcm data");
+        return std::vector<uint8_t>();
+    }
+
+    fclose(pcmFilePtr);
+    return inputBuffer;
+}
+
+static void BM_EncodeAAC(benchmark::State& state, const std::string& inpFolderPath,
+                         const std::string& pcmFile, const int sampleRate, const int bitRate,
+                         const AUDIO_OBJECT_TYPE profile, const CHANNEL_MODE channelCount) {
+    auto inputBuffer = readInputFile(inpFolderPath, pcmFile);
+    if (inputBuffer.empty()) {
+        state.SkipWithError("Failed to read input from pcm file");
+        return;
+    }
+    AACEncoder encoder(sampleRate, bitRate, profile, channelCount);
+
+    if (!encoder.initialize()) {
+        state.SkipWithError("Unable to initialize encoder");
+        return;
+    }
+
+    for (auto _ : state) {
+        if (!encoder.encode(inputBuffer)) {
+            state.SkipWithError("Unable to encode the Stream");
+            return;
+        }
+    }
+
+    state.SetLabel(pcmFile + ", " + std::to_string(encoder.getChannels()) + ", "
+                   + std::to_string(encoder.getSampleRate()) + ", "
+                   + std::to_string(encoder.getBitRate()) + ", "
+                   + std::to_string(encoder.getProfile()));
+}
+
+void RegisterBenchmarks(const std::string& folderPath) {
+    // testlabel, BM function, folderpath, pcm file, sampleRate, bitRate, profile, ChannelCount
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_1ch_8kHz_48kbps_lc", BM_EncodeAAC,
+                                folderPath, "bbb_1ch_8kHz.pcm", 8000, 48000, AOT_AAC_LC,
+                                MODE_1);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_1ch_48kHz_128kbps_lc", BM_EncodeAAC,
+                                folderPath, "bbb_1ch_48kHz.pcm", 48000, 128000, AOT_AAC_LC,
+                                MODE_1);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_2ch_48kHz_128kbps_lc", BM_EncodeAAC,
+                                folderPath, "bbb_2ch_48kHz.pcm", 48000, 128000, AOT_AAC_LC,
+                                MODE_2);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_6ch_48kHz_128kbps_lc", BM_EncodeAAC,
+                                folderPath, "bbb_6ch_48kHz.pcm", 48000, 128000, AOT_AAC_LC,
+                                MODE_1_2_2_1);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_1ch_16kHz_48kbps_he", BM_EncodeAAC,
+                                folderPath, "bbb_1ch_16kHz.pcm", 16000, 48000, AOT_SBR,
+                                MODE_1);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_1ch_48kHz_128kbps_he", BM_EncodeAAC,
+                                folderPath, "bbb_1ch_48kHz.pcm", 48000, 128000, AOT_SBR,
+                                MODE_1);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_2ch_48kHz_128kbps_he", BM_EncodeAAC,
+                                folderPath, "bbb_2ch_48kHz.pcm", 48000, 128000, AOT_SBR,
+                                MODE_2);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_2ch_16kHz_48kbps_hev2", BM_EncodeAAC,
+                                folderPath, "bbb_2ch_16kHz.pcm", 16000, 48000, AOT_PS,
+                                MODE_2);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_2ch_48kHz_128kbps_hev2", BM_EncodeAAC,
+                                folderPath, "bbb_2ch_48kHz.pcm", 48000, 128000, AOT_PS,
+                                MODE_2);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_1ch_48kHz_128kbps_ld", BM_EncodeAAC,
+                                folderPath, "bbb_1ch_48kHz.pcm", 48000, 128000, AOT_ER_AAC_LD,
+                                MODE_1);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_2ch_48kHz_128kbps_ld", BM_EncodeAAC,
+                                folderPath, "bbb_2ch_48kHz.pcm", 48000, 128000, AOT_ER_AAC_LD,
+                                MODE_2);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_6ch_48kHz_128kbps_ld", BM_EncodeAAC,
+                                folderPath, "bbb_6ch_48kHz.pcm", 48000, 128000, AOT_ER_AAC_LD,
+                                MODE_1_2_2_1);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_1ch_16kHz_64kbps_eld", BM_EncodeAAC,
+                                folderPath, "bbb_1ch_16kHz.pcm", 16000, 64000, AOT_ER_AAC_ELD,
+                                MODE_1);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_1ch_48kHz_128kbps_eld", BM_EncodeAAC,
+                                folderPath, "bbb_1ch_48kHz.pcm", 48000, 128000, AOT_ER_AAC_ELD,
+                                MODE_1);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_2ch_16kHz_64kbps_eld", BM_EncodeAAC,
+                                folderPath, "bbb_2ch_16kHz.pcm", 16000, 64000, AOT_ER_AAC_ELD,
+                                MODE_2);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_2ch_48kHz_128kbps_eld", BM_EncodeAAC,
+                                folderPath, "bbb_2ch_48kHz.pcm", 48000, 128000, AOT_ER_AAC_ELD,
+                                MODE_2);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_6ch_16kHz_64kbps_eld", BM_EncodeAAC,
+                                folderPath, "bbb_6ch_16kHz.pcm", 16000, 64000, AOT_ER_AAC_ELD,
+                                MODE_1_2_2_1);
+    benchmark::RegisterBenchmark("BM_EncodeAAC/bbb_6ch_48kHz_128kbps_eld", BM_EncodeAAC,
+                                folderPath, "bbb_6ch_48kHz.pcm", 48000, 128000, AOT_ER_AAC_ELD,
+                                MODE_1_2_2_1);
+}
+
+class CustomCsvReporter : public benchmark::BenchmarkReporter {
+   public:
+    CustomCsvReporter() : mPrintedHeader(false) {};
+    virtual bool ReportContext(const Context& context);
+    virtual void ReportRuns(const std::vector<Run>& reports);
+
+   private:
+    void PrintRunData(const Run& report);
+    bool mPrintedHeader;
+    std::vector<std::string> mHeaders = {"File",    "Channels",      "SampleRate",  "BitRate",
+                                         "profile", "real_time(ns)", "cpu_time(ns)"};
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
+        inpFolderPath = "/sdcard/test/AacEncBenchmark-1.0";
+    }
+
+    FILE* pcmFilePath = fopen(inpFolderPath.c_str(), "r");
+    if (!pcmFilePath) {
+        std::cerr << "Error: Invalid path provided: " << inpFolderPath << std::endl;
+        return -1;
+    }
+    fclose(pcmFilePath);
+
+    RegisterBenchmarks(inpFolderPath);
+    benchmark::Initialize(&argc, argv);
+    benchmark::RunSpecifiedBenchmarks(nullptr, csvReporter.get());
+    benchmark::Shutdown();
+    return 0;
+}
diff --git a/tests/AacEncBenchmark/Android.bp b/tests/AacEncBenchmark/Android.bp
new file mode 100644
index 0000000..aae4210
--- /dev/null
+++ b/tests/AacEncBenchmark/Android.bp
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
+    name: "AacEncBenchmark",
+    host_supported: true,
+    srcs: ["AacEncBenchmark.cpp"],
+    shared_libs: [
+        "liblog",
+    ],
+    static_libs: [
+        "libFraunhoferAAC",
+        "libgoogle-benchmark",
+    ],
+    test_suites: ["device-tests"],
+}
diff --git a/tests/AacEncBenchmark/AndroidTest.xml b/tests/AacEncBenchmark/AndroidTest.xml
new file mode 100644
index 0000000..45adb94
--- /dev/null
+++ b/tests/AacEncBenchmark/AndroidTest.xml
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
+<configuration description="Unit test configuration for AacEncBenchmark">
+    <option name="test-suite-tag" value="device-tests" />
+    <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
+        <option name="cleanup" value="true" />
+        <option name="push-file" key="AacEncBenchmark" value="/data/local/tmp/AacEncBenchmark" />
+    </target_preparer>
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.DynamicConfigPusher">
+        <option name="target" value="host" />
+        <option name="config-filename" value="AacEncBenchmark" />
+        <option name="version" value="1.0"/>
+    </target_preparer>
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.DynamicConfigPusher">
+        <option name="target" value="device" />
+        <option name="config-filename" value="AacEncBenchmark" />
+        <option name="version" value="1.0"/>
+    </target_preparer>
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.MediaPreparer">
+        <option name="push-all" value="true" />
+        <option name="media-folder-name" value="AacEncBenchmark-1.0" />
+        <option name="dynamic-config-module" value="AacEncBenchmark" />
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.GoogleBenchmarkTest" >
+        <option name="native-benchmark-device-path" value="/data/local/tmp" />
+        <option name="benchmark-module-name" value="AacEncBenchmark" />
+    </test>
+</configuration>
diff --git a/tests/AacEncBenchmark/DynamicConfig.xml b/tests/AacEncBenchmark/DynamicConfig.xml
new file mode 100644
index 0000000..f03e976
--- /dev/null
+++ b/tests/AacEncBenchmark/DynamicConfig.xml
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
+        <value>https://dl.google.com/android-unittest/media/external/aac/tests/AacEncBenchmark/AacEncBenchmark-1.0.zip</value>
+    </entry>
+</dynamicConfig>
diff --git a/tests/AacEncBenchmark/README.md b/tests/AacEncBenchmark/README.md
new file mode 100644
index 0000000..bdaa706
--- /dev/null
+++ b/tests/AacEncBenchmark/README.md
@@ -0,0 +1,121 @@
+# Benchmark tests
+
+This Benchmark app analyses the time taken by AAC Encoder for given set of inputs. It is used to benchmark encoder module on android devices.
+
+This page describes steps to run the AAC encoder Benchmark test.
+
+Run the following steps to build the test suite:
+```
+mmm external/aac/tests/AacEncBenchmark/
+```
+
+# Resources
+The resource folder for the tests is taken from [here](https://dl.google.com/android-unittest/media/external/aac/tests/AacEncBenchmark/AacEncBenchmark-1.0.zip)
+
+Download the AacEncBenchmark-1.0.zip folder, unzip and push it to any path on the device, Let's say the path be /sdcard/test. You can give the path wherever you chose to put the files.
+
+```
+unzip AacEncBenchmark-1.0.zip
+adb push AacEncBenchmark-1.0 /sdcard/test
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
+atest AacEncBenchmark
+```
+
+## Steps to run without atest (push binary to the device and run)
+
+To run the test suite for measuring performance of the encoder, follow the following steps:
+
+The 64-bit binaries will be created in the following path : ${OUT}/data/benchmarktest64/AacEncBenchmark/
+
+The 32-bit binaries will be created in the following path : ${OUT}/data/benchmarktest/AacEncBenchmark/
+
+To test 64-bit binary push binaries from benchmarktest64.
+
+```
+adb push $(OUT)/data/benchmarktest64/AacEncBenchmark/AacEncBenchmark /data/local/tmp/
+```
+
+To test 32-bit binary push binaries from benchmarktest.
+
+```
+adb push $(OUT)/data/benchmarktest/AacEncBenchmark/AacEncBenchmark /data/local/tmp/
+```
+
+To get the resource files for the test follow instructions given in [Resources](#Resources)
+
+After running the above steps, /sdcard/test should contain AacEncBenchmark-1.0 folder and /data/local/tmp should contain benchmark binary to be executed.
+
+Run the following commands to see the benchmark results
+```
+adb shell
+cd /data/local/tmp/
+chmod a+x AacEncBenchmark
+./AacEncBenchmark
+```
+
+Run the below commands to generate a csv report and see the benchmark results
+```
+adb shell
+cd /data/local/tmp/
+chmod a+x AacEncBenchmark
+./AacEncBenchmark --benchmark_out=output.csv
+```
+
+if the folder path where the resource files are pushed is different from /sdcard/test/ , pass the actual folder path as an argument as shown below and run the following commands to see the benchmark results. Here let's say the path be /sdcard/test/AacEncBenchmark-1.0
+```
+adb shell
+cd /data/local/tmp/
+chmod a+x AacEncBenchmark
+./AacEncBenchmark --path=/sdcard/test/AacEncBenchmark-1.0
+```
+
+Run the below commands to store the benchmark results in an output.csv file which will be generated in the same path on the device.
+
+You can modify the output csv filename to any name and can be generated in any given absolute path.
+```
+adb shell
+cd /data/local/tmp/
+chmod a+x AacEncBenchmark
+./AacEncBenchmark --path=/sdcard/test/AacEncBenchmark-1.0/ --benchmark_out=output.csv
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
+4. **bitRate**: bitRate of the input audio bitstream.
+
+5. **profile**: profile of the input audio bitstream.
+
+6. **real_time**: Measures total elapsed time  from start to end of process, including wait times and delays.
+
+7. **cpu_time**: Measures total time spent by cpu actively executing instructions for a process.
```

