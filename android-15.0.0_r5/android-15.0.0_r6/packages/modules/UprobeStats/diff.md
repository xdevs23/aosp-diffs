```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index c8dbf77..b37c0e0 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -1,5 +1,7 @@
 [Builtin Hooks]
 clang_format = true
+google_java_format = true
+bpfmt = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
diff --git a/apex/Android.bp b/apex/Android.bp
new file mode 100644
index 0000000..5aa6f81
--- /dev/null
+++ b/apex/Android.bp
@@ -0,0 +1,46 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+apex_key {
+    name: "com.android.uprobestats.key",
+    public_key: "com.android.uprobestats.avbpubkey",
+    private_key: "com.android.uprobestats.pem",
+}
+
+android_app_certificate {
+    name: "com.android.uprobestats.certificate",
+    certificate: "com.android.uprobestats",
+}
+
+apex {
+    // This apex will be enabled using release_uprobestats_module flag
+    enabled: select(release_flag("RELEASE_UPROBESTATS_MODULE"), {
+        true: true,
+        false: false,
+    }),
+
+    name: "com.android.uprobestats",
+    manifest: "manifest.json",
+    file_contexts: ":com.android.uprobestats-file_contexts",
+    key: "com.android.uprobestats.key",
+    certificate: ":com.android.uprobestats.certificate",
+    defaults: ["b-launched-apex-module"],
+    // temporarily override the value from the V defaults so that
+    // the build still works on `next` for now.
+    min_sdk_version: "35",
+}
diff --git a/apex/com.android.uprobestats.avbpubkey b/apex/com.android.uprobestats.avbpubkey
new file mode 100644
index 0000000..2525792
Binary files /dev/null and b/apex/com.android.uprobestats.avbpubkey differ
diff --git a/apex/com.android.uprobestats.pem b/apex/com.android.uprobestats.pem
new file mode 100644
index 0000000..237b79a
--- /dev/null
+++ b/apex/com.android.uprobestats.pem
@@ -0,0 +1,51 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIIJKgIBAAKCAgEA5bIyNG0nplQrHlJonr9Lir7Yly7W9kO+eAVBZv4wOvwN3Quw
+5Cup8m0VVHybGDOp2/y52EnpHzkV+8EeB+tmJ4oThCkNtkP177tCwVCOXMyiiNiS
+fnZMHHTAIb4AS486yeHqgYhngFZqw+oLYdriLorzk0+MrITiTQBe9uUD3AIcx5AP
+PhJzUBRASJEHmLcNQRJOJHzTyqqMPrW9qLR2oCwh7AqJWmoLYDn7ceSMDn+O34Hd
+2Gn6WkmG+spL7+2XNkn9EKwucuzGTtfQTCiTRwvYnaOcEqhzPkUJZJT2kP5PQuqG
+blqVFNKq74dbrigoQfF6V+UUDfVNiSRSsfNzUQc0eZGLk/2JzYHCD1hzvm9iQTKw
+sMBvQru3vul829EZ192Qc2mr+KmeqX8Jl39D6ybtoGEzJq0r+a0Zf7UB6OyF0+S5
+8AC/Ujbgg4kql3R29lbIqmeKr4dqrEaBdTV+pwL/L305FMwWrFvJRpmfO8c28ZD1
+rLFRjNp58T7s/hKagl/dO+Nd/qIGe1andoPMDcoXSRIjGIDUOeZlExn70aVhhRIL
+IVlWfbKMtxaIM2JWZ2YNPQWcmdpgCjqbnKo3WCe4t57zHWgRALmLkn8dtgLqApck
+d0Pi1ysaXNlHdmD29p5Z+a2smNoNI0ZMZtZu1GwzDzGteGiEbGdve+ZOJL8CAwEA
+AQKCAgBnAOMMqYpnR0VSwqfR0H0CyhR8r2+MXdKzJcAvfHuKZ++bmZuIpp/+a7Zt
+/bbbQofAc/OvL23QJ5xZGj/qU0CrKHsaAAL7IjzOdY44/HPq34VfkqcW+NumwyBJ
+wVeGisNVNu8fiVjIr3gPRQw3pJ1bO8qA2+J8ltaYqzrqwsZZScU4JL0BG+sEFSDC
+qe7bJ/NUo+3Q5P1g29wqXvufBNZRe5j2rb7sgbN6QmYkq9W2xrL+PdGLM/Mlu+VA
+36jv/f6aRNGsQVpPBSjkwFjTXjq1WHWaM31QzKNpYDIXHcn4OWK34k3IfOxvuw0W
+fv+4+J8c+zne4oZ8v+02O8itrjueV/xH57lcJJRDQ5ae3ByfUcde6kRRUVJiUItb
+XutuguvPJ3f4aU6S7EcJKi8Xi3ehAUtOy/fZjDDCb1GM71quSUp6exlkE4qGdFQU
+Sx4XVvSU9ZkMIqRcQwEmxlcvSGSrhu8aPXF5SJqnNunmka2xvTbxTAGWsVCkclOj
+em/32oNMq728nkfVX5MmVDJ4RLwa9p79/Ko1TvpNfvvNAWRgpWacsfrNeNjLz6It
+b+KECqYh9Ccs/i6v4K2edKMCZLKBLE59bYO90eEQRGVvHzPiwBKBI8t6cSi6/rz4
+XLo3AabFeRUSrKzt6J6zKerxjgeW3fTv2A1pQAfVkwkBUSplkQKCAQEA8/zViHsB
++tfBN8PlAT4V5WHa9e72PmrFkvlNwy/yi+nTujS15VxwNpMJdPf1bToW0bDD1/7J
+GYoxaXBnHonOMOi9yfOaD+W0yJJ6oTJtG6KKIaQekiBGYu1neJLNVd7crnMZOcBK
+RhovGTHwGkEXT5cX+PE2OIg18hbxKCje0EkUWc9Z+IsYOpyieNLxBQNpz4yjvvKU
+/fcm95LSPhJcRtowYXfvgQhzfpquDpdiETbAnZAidKpxWKVjwOc5M8XIW8UPYWgN
+/pMpudoSriha3Bw+3JnKfxaFl7U9q31+q2F5LlF1jVkQ9NF69WMBXqwEVjmdm30W
+I+BCmMVhuVQmOQKCAQEA8QE8Av20PE4IWmMwTRecets1CJPPI1fT5r7X6qIxv9CJ
+fQsHEWPV8z3kGC2UWtmYC+znn1DESxzDiJ+khtP4lkXQvp/7FGSzDV32GRGJK/Yg
+Evqq1EUujQg0/7SuKpbYWWt0e5+v2++L9XuQVyyQ5APT0azBxus+Z5s62dbbO5Dg
+kc5KexrIuRA7WxnhjHBeVrOdp15QpcVZuPyAJBGCmBZDuYru2E+r92Ny0otUVW8W
+lUJ6rWpZOQZhXLYUAX57GgL9i27lPOtyIhPHL7+nnWX3K/V5qEKeLsKWUX0+50Nj
+4a+vo3zFZ+o9dLzw+rMZfIuKwInU8y17nqVTYK1itwKCAQEAs6E/rL2zVXSnQmEt
+Jt8Iy9phlJMcJBQD5hM51yxjy/KY+Qx5pqWJ0AQtADrWLFaKGlOjvFBOykjd3Bzv
+LqKSdZvErvx0PqQFl22Qb0Fq5t+iBuaHw1mTuJ3EghbCqifsHVuMBOK3TClW55vG
+g+3MNcKt2Y/tNW3DGbseTUzZzksfeoeYW848Rlqvm3jiDajXrACFRb3fR6NAwyEL
+PLvTyC43VGsyn7MTJPDImOGHR9khsl89ntslm/gYGxuhF6bTvgy1KCettfGu1K/i
+9OmtC0SYW122oh54uJqtDqbULWUUDK/YdfpO64+WkTcU+Rh4EOtWR/Wt6TfgkA0x
+x3pWsQKCAQEAkhWKd9Gq54bxP0CybXhrbHjlK57UxvqcwlhZ7qqD914DiN0fWqYm
+cLvKP/GY5HzS0h+2wnYlldYInA8Qnn1sSEJnZrT4b4MemXKkEsvzVsdo57gzxlls
+/yXDYl/11nD7ETC2OZ0w7uLD9ngApSapaNz9DzJlfxrnB8wrHxJCb1fBGABwWzCA
+DNVO9Ui50/Pk6y8S1/mubt0yJpQ/ZB2NCH0ubhBN+KZKebk5R3AXHXYpvS2/yNAW
+5x7780OW2tT872Zyo4sDvyqEUy2j5kiI5DqDWY0BQkGnOnbOwPRnJa1OpOVmVHXz
+/qoYuGMyuvPG9hxrbYvencyrCx3xbT+L/wKCAQEAkZROhQhbBK5x5X4fSA3bzL4G
+aV0Tp4ZxJq5LN9iuKjGPIADtLyA+KTrajpXQE8oM9WvGnE1zWPf3AFTKiK+YpQYN
+BQ3rodYycP32K6gJ7NQnkrFcBaG+O4UOfBOrpmmbR68BK+K2DhHMhL4ggqf8/maT
+z+i0C12SL7rZWHwVOJ5l+5yDweRnO44RbctRR3x9X9OD/x1CTrmBCoYUDWxCsqpU
+x93Taph4vuot/j4+y7auagRHPZfJCg+EuBUwXtPNWs6sDxdk99hmYekk/R23ql2q
+xIlZpnRXjfhP5P2kZAf63DcRGJeBx2+fYfC3QCJnfir5wKcYJWdhJG0lZceHQA==
+-----END RSA PRIVATE KEY-----
diff --git a/apex/com.android.uprobestats.pk8 b/apex/com.android.uprobestats.pk8
new file mode 100644
index 0000000..242ec34
Binary files /dev/null and b/apex/com.android.uprobestats.pk8 differ
diff --git a/apex/com.android.uprobestats.x509.pem b/apex/com.android.uprobestats.x509.pem
new file mode 100644
index 0000000..23f5350
--- /dev/null
+++ b/apex/com.android.uprobestats.x509.pem
@@ -0,0 +1,34 @@
+-----BEGIN CERTIFICATE-----
+MIIF0zCCA7sCFEV5QS17Jujwj3qmLqQseCpaJAM+MA0GCSqGSIb3DQEBCwUAMIGk
+MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91
+bnRhaW4gVmlldzEQMA4GA1UECgwHQW5kcm9pZDEQMA4GA1UECwwHQW5kcm9pZDEi
+MCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTEgMB4GA1UEAwwXY29t
+LmFuZHJvaWQudXByb2Jlc3RhdHMwIBcNMjQwODI5MTc1MTUzWhgPNDc2MjA3MjYx
+NzUxNTNaMIGkMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQG
+A1UEBwwNTW91bnRhaW4gVmlldzEQMA4GA1UECgwHQW5kcm9pZDEQMA4GA1UECwwH
+QW5kcm9pZDEiMCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTEgMB4G
+A1UEAwwXY29tLmFuZHJvaWQudXByb2Jlc3RhdHMwggIiMA0GCSqGSIb3DQEBAQUA
+A4ICDwAwggIKAoICAQDmZAzul11Q1mXzmxjsDW7d3k4EySVVIBjfy7x0DsY9m0ss
+9e5MvxU7Izwalh6mbQG68sy0INOLAcXQ/H8c8OjK3J9gGCdVXbUVQ36Jyunm+9Ju
+0fetryET6DQjXcsZRLBEvQKsZZToxoNWiHHSFAvORChX4otGTYGFw8aYl0sVnc65
+YJpJdrx2MCfYJSZO0f1sCUGTvp6BVxzm9FZrQKZp4pDuu/wDNhFCaj5zclNIZYzy
+Orrdl7cI4cCCIiGUm8D9+z1VZYMNQd+hEROQ8SPzoaR+mr4Ii4rb6HgaJPdXXlzm
+v8iGf1Jl3eHzt/7m/YEfbrjn7L0LUKap4fuiaxOV2g9w9zU92kGq2m6p67Y7P6pa
+gOju5pVI2NO1hAdkpG8lE94jEHZrTjYtF1aA0solz4X1b3WOBuINXyy+qupi9CX+
+vwF1dmCiD0aJPZUzg0IIyhOkxyXMIU761o9v5BAV158y4SpLuzOWVXjHb+Gq+Ad0
+bbwOC+Fr7ch+1IJ+dfCJnpxfbbFIJnzgWaJQOsXiP+CP3hoFshX+oxHaHSYD2lX0
+VKCdgzlX6O5vAZA00v4f/u+mg85p4fHI2BHuQ9c1Jq/5i6FTo/h1EkWG9+KxeL4v
+SijMU+T7xXwab1k2HDGOwf/Z8sRVM9SRnCRehRxy+Rf2fKSupIVMNIlE4DYhlQID
+AQABMA0GCSqGSIb3DQEBCwUAA4ICAQAUm6Ltldym7fEZ6YHjtjhu5mTr4qhwBHgA
+UKe561nnVNKxy2suEvNsGxsTN078BrSONhdPkYsF4Ey1kfnExMQRFBL5ERJm9bko
+c20D4DBqpPWlYaCmKbDkR1257lsz67zwjQuVhznUt54nvTgpEVwyh/BtmUQ08BPL
+H3BVSwLUTRCDFJ0hWKUZVRxGd4YA9ibnEGUm0JdYL9ZNnKn7MjwjpuStl1qAJNH1
+YVPEA2xv//sJzDuOYWU1O3G7EcuhDLWeveYJ/s2aAIOfTipB22qzH4D2Hhh+KbWJ
+LSFlq+DYbLpS1wzdeBnSZjN3T6DvE9NiidFl7Cv3wYKQyNTGTX038lanqYPz2f6O
+7AhvOx4dmaqV/OmiEcFESiqa/Ggf9ojxH7b3XVfuYA4Q68iqj/n+Pi0EGXH5WwWI
+r1E1A8mWROtDZMl+qliojArDnP+8uap00xivN3DfIDtuTSlkDCLCKNJT7d8hRPeh
+RxgQ3KF3TzaBfeAb8Wsi2kQR/cC9o208p2BOpE+j1+Kx+65cSmZ1aRbjqnJqs2eb
+IXZ1NY5RJAtu2ot1DWPgTJUA0kSJf6Vx0FF4r+mObWB8M5grtiEz6ujv6wO7ImF2
+NP9VCJGTiHO5PyDyNOjojzTigV8utoJ3weN+Dep40Gwpt9P02THw5F3wyqvTY/Mk
+vAfewtpqOg==
+-----END CERTIFICATE-----
diff --git a/apex/manifest.json b/apex/manifest.json
new file mode 100644
index 0000000..c9ed8fc
--- /dev/null
+++ b/apex/manifest.json
@@ -0,0 +1,4 @@
+{
+    "name": "com.android.uprobestats",
+    "version": 0
+}
diff --git a/src/Android.bp b/src/Android.bp
index 78dc33c..69ae4ec 100644
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -1,5 +1,6 @@
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_performance",
 }
 
 aconfig_declarations {
@@ -21,11 +22,11 @@ cc_library {
         "Bpf.cpp",
         "ConfigResolver.cpp",
         "Process.cpp",
+        "Guardrail.cpp",
         "config.proto",
     ],
     header_libs: [
         "bpf_headers",
-        "bpf_syscall_wrappers",
     ],
     shared_libs: [
         "libbase",
@@ -58,12 +59,15 @@ cc_binary {
     shared_libs: [
         "libbase",
         "liblog",
+        "libstatssocket",
     ],
     init_rc: [
         "UprobeStats.rc",
     ],
     required: [
         "BitmapAllocation.o",
+        "GenericInstrumentation.o",
+        "ProcessManagement.o",
     ],
     proto: {
         type: "lite",
@@ -71,6 +75,34 @@ cc_binary {
     },
 }
 
+java_test_host {
+    name: "uprobestats-test",
+    srcs: [
+        "test/*.java",
+        "config.proto",
+    ],
+    java_resources: ["test/*.textproto"],
+    libs: [
+        "compatibility-host-util",
+        "core_cts_test_resources",
+        "cts-tradefed",
+        "host-libprotobuf-java-full",
+        "tradefed",
+        "truth",
+    ],
+    static_libs: [
+        "android.hardware.usb.flags-aconfig-java-host",
+        "android.os.flags-aconfig-java-host",
+        "cts-statsd-atom-host-test-utils",
+        "flag-junit-host",
+        "perfetto_config-full",
+    ],
+    proto: {
+        type: "full",
+    },
+    test_suites: ["general-tests"],
+}
+
 python_binary_host {
     name: "hello_uprobestats",
     main: "test/hello_uprobestats.py",
@@ -84,3 +116,25 @@ python_binary_host {
         canonical_path_from_root: false,
     },
 }
+
+cc_test {
+    name: "libuprobestats_test",
+    srcs: [
+        "config.proto",
+        "Guardrail-test.cpp",
+    ],
+    shared_libs: [
+        "libbase",
+    ],
+    static_libs: [
+        "libbase",
+        "libgtest",
+        "liblog",
+        "libprotoutil",
+        "libuprobestats",
+    ],
+    proto: {
+        type: "lite",
+        static: true,
+    },
+}
diff --git a/src/Art.cpp b/src/Art.cpp
index 2ced892..593e321 100644
--- a/src/Art.cpp
+++ b/src/Art.cpp
@@ -22,10 +22,10 @@ namespace uprobestats {
 namespace art {
 
 // Uses the oatdump binary to retrieve the offset for a given method
-int getMethodOffsetFromOatdump(std::string oat_file,
-                               std::string method_signature) {
+int getMethodOffsetFromOatdump(std::string oatFile,
+                               std::string methodSignature) {
   // call oatdump and collect stdout
-  auto command = std::string("oatdump --oat-file=") + oat_file +
+  auto command = std::string("oatdump --oat-file=") + oatFile +
                  std::string(" --dump-method-and-offset-as-json");
   FILE *pipe = popen(command.c_str(), "r");
   char buffer[256];
@@ -43,13 +43,16 @@ int getMethodOffsetFromOatdump(std::string oat_file,
     Json::Value entry;
     bool success = reader.parse(line, entry);
     if (success) {
-      auto found_method_signature = entry["method"].asString();
-      if (found_method_signature == method_signature) {
-        auto hex_string = entry["offset"].asString();
+      auto foundMethodSignature = entry["method"].asString();
+      if (foundMethodSignature == methodSignature) {
+        auto hexString = entry["offset"].asString();
         int offset;
-        std::istringstream stream(hex_string);
+        std::istringstream stream(hexString);
         stream >> std::hex >> offset;
-        return offset + 4096;
+        if (offset == 0) {
+          return 0;
+        }
+        return offset;
       }
     }
   }
@@ -59,4 +62,4 @@ int getMethodOffsetFromOatdump(std::string oat_file,
 
 } // namespace art
 } // namespace uprobestats
-} // namespace android
\ No newline at end of file
+} // namespace android
diff --git a/src/Art.h b/src/Art.h
index df8c842..20c7423 100644
--- a/src/Art.h
+++ b/src/Art.h
@@ -21,8 +21,8 @@ namespace uprobestats {
 namespace art {
 
 // Uses the oatdump binary to retrieve the offset for a given method
-int getMethodOffsetFromOatdump(std::string oat_file,
-                               std::string method_signature);
+int getMethodOffsetFromOatdump(std::string oatFile,
+                               std::string methodSignature);
 
 } // namespace art
 } // namespace uprobestats
diff --git a/src/Bpf.cpp b/src/Bpf.cpp
index cd0d0ab..9ff8920 100644
--- a/src/Bpf.cpp
+++ b/src/Bpf.cpp
@@ -23,8 +23,11 @@
 
 #include <string>
 
+#include "bpf/BpfMap.h"
 #include "bpf/BpfRingbuf.h"
 
+#include "Bpf.h"
+
 namespace android {
 namespace uprobestats {
 namespace bpf {
@@ -75,34 +78,42 @@ int bpfPerfEventOpen(const char *filename, int offset, int pid,
   return 0;
 }
 
-std::vector<int32_t> pollRingBuf(const char *map_path, int timeout_ms) {
-  auto result = android::bpf::BpfRingbuf<uint64_t>::Create(map_path);
-  std::vector<int32_t> vec;
-  if (!result.value()->wait(timeout_ms)) {
+template <typename T>
+std::vector<T> pollRingBuf(const char *mapPath, int timeoutMs) {
+  auto result = android::bpf::BpfRingbuf<T>::Create(mapPath);
+  std::vector<T> vec;
+  if (!result.value()->wait(timeoutMs)) {
     return vec;
   }
-  auto callback = [&](const uint64_t &value) { vec.push_back(value); };
+  auto callback = [&](const T &value) { vec.push_back(value); };
   result.value()->ConsumeAll(callback);
   return vec;
 }
 
-std::vector<int32_t> consumeRingBuf(const char *map_path) {
-  auto result = android::bpf::BpfRingbuf<uint64_t>::Create(map_path);
+template std::vector<uint64_t> pollRingBuf(const char *mapPath, int timeoutMs);
+template std::vector<CallResult> pollRingBuf(const char *mapPath,
+                                             int timeoutMs);
+template std::vector<CallTimestamp> pollRingBuf(const char *mapPath,
+                                                int timeoutMs);
+template std::vector<SetUidTempAllowlistStateRecord>
+pollRingBuf(const char *mapPath, int timeoutMs);
+
+std::vector<int32_t> consumeRingBuf(const char *mapPath) {
+  auto result = android::bpf::BpfRingbuf<uint64_t>::Create(mapPath);
   std::vector<int32_t> vec;
   auto callback = [&](const uint64_t &value) { vec.push_back(value); };
   result.value()->ConsumeAll(callback);
   return vec;
 }
 
-void printRingBuf(const char *map_path) {
-  auto result = android::bpf::BpfRingbuf<uint64_t>::Create(map_path);
+void printRingBuf(const char *mapPath) {
+  auto result = android::bpf::BpfRingbuf<uint64_t>::Create(mapPath);
   auto callback = [&](const uint64_t &value) {
     LOG(INFO) << "ringbuf result callback. value: " << value
-              << " map_path: " << map_path;
+              << " mapPath: " << mapPath;
   };
-  int num_consumed = result.value()->ConsumeAll(callback).value_or(-1);
-  LOG(INFO) << "ring buffer size: " << num_consumed
-            << " map_path: " << map_path;
+  int numConsumed = result.value()->ConsumeAll(callback).value_or(-1);
+  LOG(INFO) << "ring buffer size: " << numConsumed << " mapPath: " << mapPath;
 }
 
 } // namespace bpf
diff --git a/src/Bpf.h b/src/Bpf.h
index bffe8fc..16a64d9 100644
--- a/src/Bpf.h
+++ b/src/Bpf.h
@@ -23,11 +23,28 @@ namespace bpf {
 int bpfPerfEventOpen(const char *filename, int offset, int pid,
                      const char *bpfProgramPath);
 
-std::vector<int32_t> consumeRingBuf(const char *map_path);
+std::vector<int32_t> consumeRingBuf(const char *mapPath);
 
-std::vector<int32_t> pollRingBuf(const char *map_path, int timeout_ms);
+// TODO: share this struct with bpf
+struct CallResult {
+  unsigned long pc;
+  unsigned long regs[10];
+};
 
-void printRingBuf(const char *map_path);
+struct CallTimestamp {
+  unsigned int event;
+  unsigned long timestampNs;
+};
+
+struct SetUidTempAllowlistStateRecord {
+  __u64 uid;
+  bool onAllowlist;
+};
+
+template <typename T>
+std::vector<T> pollRingBuf(const char *mapPath, int timeoutMs);
+
+void printRingBuf(const char *mapPath);
 
 } // namespace bpf
 } // namespace uprobestats
diff --git a/src/ConfigResolver.cpp b/src/ConfigResolver.cpp
index e7a72eb..68dcd1f 100644
--- a/src/ConfigResolver.cpp
+++ b/src/ConfigResolver.cpp
@@ -37,13 +37,13 @@ namespace uprobestats {
 namespace config_resolver {
 
 std::ostream &operator<<(std::ostream &os, const ResolvedTask &c) {
-  os << "pid: " << c.pid << " task_config: " << c.task_config.DebugString();
+  os << "pid: " << c.pid << " taskConfig: " << c.taskConfig.DebugString();
   return os;
 }
 
 std::ostream &operator<<(std::ostream &os, const ResolvedProbe &c) {
   os << "filename: " << c.filename << " offset: " << c.offset
-     << " probe_config: " << c.probe_config.DebugString();
+     << " probeConfig: " << c.probeConfig.DebugString();
   return os;
 }
 
@@ -80,58 +80,61 @@ resolveSingleTask(::uprobestats::protos::UprobestatsConfig config) {
                << " tasks. Only 1 is supported. The first task is read and the "
                   "rest are ignored.";
   }
-  auto task_config = config.tasks().Get(0);
-  if (!task_config.has_duration_seconds()) {
+  auto taskConfig = config.tasks().Get(0);
+  if (!taskConfig.has_duration_seconds()) {
     LOG(ERROR) << "config task has no duration";
     return {};
   }
-  if (task_config.duration_seconds() <= 0) {
+  if (taskConfig.duration_seconds() <= 0) {
     LOG(ERROR) << "config task cannot have zero or negative duration";
   }
-  if (!task_config.has_target_process_name()) {
+  if (!taskConfig.has_target_process_name()) {
     LOG(ERROR) << "task.target_process_name is required.";
     return {};
   }
-  auto process_name = task_config.target_process_name();
+  auto process_name = taskConfig.target_process_name();
   int pid = process::getPid(process_name);
   if (pid < 0) {
     LOG(ERROR) << "Unable to find pid of " << process_name;
     return {};
   }
   ResolvedTask task;
-  task.task_config = task_config;
+  task.taskConfig = taskConfig;
   task.pid = pid;
   return task;
 }
 
 std::optional<std::vector<ResolvedProbe>>
-resolveProbes(::uprobestats::protos::UprobestatsConfig::Task task_config) {
-  if (task_config.probe_configs().size() == 0) {
+resolveProbes(::uprobestats::protos::UprobestatsConfig::Task taskConfig) {
+  if (taskConfig.probe_configs().size() == 0) {
     LOG(ERROR) << "task has no probe configs";
     return {};
   }
   std::vector<ResolvedProbe> result;
-  for (auto &probe_config : task_config.probe_configs()) {
+  for (auto &probeConfig : taskConfig.probe_configs()) {
     int offset = 0;
     std::string matched_file_path;
-    for (auto &file_path : probe_config.file_paths()) {
+    for (auto &file_path : probeConfig.file_paths()) {
       offset = art::getMethodOffsetFromOatdump(file_path,
-                                               probe_config.method_signature());
+                                               probeConfig.method_signature());
       if (offset > 0) {
         matched_file_path = file_path;
         break;
+      } else {
+        LOG(WARNING) << "File " << file_path << " has no offset for "
+                     << probeConfig.method_signature();
       }
     }
     if (offset == 0) {
       LOG(ERROR) << "Unable to find method offset for "
-                 << probe_config.method_signature();
+                 << probeConfig.method_signature();
       return {};
     }
 
     ResolvedProbe probe;
     probe.filename = matched_file_path;
     probe.offset = offset;
-    probe.probe_config = probe_config;
+    probe.probeConfig = probeConfig;
     result.push_back(probe);
   }
 
@@ -140,4 +143,4 @@ resolveProbes(::uprobestats::protos::UprobestatsConfig::Task task_config) {
 
 } // namespace config_resolver
 } // namespace uprobestats
-} // namespace android
\ No newline at end of file
+} // namespace android
diff --git a/src/ConfigResolver.h b/src/ConfigResolver.h
index 355683a..8793c2d 100644
--- a/src/ConfigResolver.h
+++ b/src/ConfigResolver.h
@@ -21,13 +21,13 @@ namespace uprobestats {
 namespace config_resolver {
 
 struct ResolvedProbe {
-  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probe_config;
+  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfig;
   std::string filename;
   int offset;
 };
 
 struct ResolvedTask {
-  ::uprobestats::protos::UprobestatsConfig::Task task_config;
+  ::uprobestats::protos::UprobestatsConfig::Task taskConfig;
   int pid;
 };
 
@@ -42,7 +42,7 @@ std::optional<ResolvedTask>
 resolveSingleTask(::uprobestats::protos::UprobestatsConfig config);
 
 std::optional<std::vector<ResolvedProbe>>
-resolveProbes(::uprobestats::protos::UprobestatsConfig::Task task_config);
+resolveProbes(::uprobestats::protos::UprobestatsConfig::Task taskConfig);
 
 } // namespace config_resolver
 } // namespace uprobestats
diff --git a/src/Guardrail-test.cpp b/src/Guardrail-test.cpp
new file mode 100644
index 0000000..968c534
--- /dev/null
+++ b/src/Guardrail-test.cpp
@@ -0,0 +1,66 @@
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
+
+#include <gtest/gtest.h>
+
+#include "Guardrail.h"
+
+namespace android {
+namespace uprobestats {
+
+class GuardrailTest : public ::testing::Test {};
+
+TEST_F(GuardrailTest, EverythingAllowedOnUserDebugAndEng) {
+  ::uprobestats::protos::UprobestatsConfig config;
+  config.add_tasks()->add_probe_configs()->set_method_signature(
+      "void com.android.server.am.SomeClass.doWork()");
+  EXPECT_TRUE(guardrail::isAllowed(config, "userdebug"));
+  EXPECT_TRUE(guardrail::isAllowed(config, "eng"));
+}
+
+TEST_F(GuardrailTest, OomAdjusterAllowed) {
+  ::uprobestats::protos::UprobestatsConfig config;
+  config.add_tasks()->add_probe_configs()->set_method_signature(
+      "void com.android.server.am.OomAdjuster.setUidTempAllowlistStateLSP(int, "
+      "boolean)");
+  config.add_tasks()->add_probe_configs()->set_method_signature(
+      "void "
+      "com.android.server.am.OomAdjuster$$ExternalSyntheticLambda0.accept(java."
+      "lang.Object)");
+  EXPECT_TRUE(guardrail::isAllowed(config, "user"));
+  EXPECT_TRUE(guardrail::isAllowed(config, "userdebug"));
+  EXPECT_TRUE(guardrail::isAllowed(config, "eng"));
+}
+
+TEST_F(GuardrailTest, DisallowOomAdjusterWithSuffix) {
+  ::uprobestats::protos::UprobestatsConfig config;
+  config.add_tasks()->add_probe_configs()->set_method_signature(
+      "void com.android.server.am.OomAdjusterWithSomeSuffix.doWork()");
+  EXPECT_FALSE(guardrail::isAllowed(config, "user"));
+}
+
+TEST_F(GuardrailTest, DisallowedMethodInSecondTask) {
+  ::uprobestats::protos::UprobestatsConfig config;
+  config.add_tasks()->add_probe_configs()->set_method_signature(
+      "void com.android.server.am.OomAdjuster.setUidTempAllowlistStateLSP(int, "
+      "boolean)");
+  config.add_tasks()->add_probe_configs()->set_method_signature(
+      "void com.android.server.am.disallowedClass.doWork()");
+  EXPECT_FALSE(guardrail::isAllowed(config, "user"));
+}
+
+} // namespace uprobestats
+} // namespace android
diff --git a/src/Guardrail.cpp b/src/Guardrail.cpp
new file mode 100644
index 0000000..a55411e
--- /dev/null
+++ b/src/Guardrail.cpp
@@ -0,0 +1,69 @@
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
+
+#include <android-base/strings.h>
+#include <config.pb.h>
+#include <string>
+
+namespace android {
+namespace uprobestats {
+namespace guardrail {
+
+using std::string;
+
+namespace {
+
+constexpr std::array kAllowedMethodPrefixes = {
+    "com.android.server.am.CachedAppOptimizer",
+    "com.android.server.am.OomAdjuster",
+    "com.android.server.am.OomAdjusterModernImpl",
+};
+
+} // namespace
+
+bool isAllowed(const ::uprobestats::protos::UprobestatsConfig &config,
+               const string &buildType) {
+  if (buildType != "user") {
+    return true;
+  }
+  for (const auto &task : config.tasks()) {
+    for (const auto &probeConfig : task.probe_configs()) {
+      const string &methodSignature = probeConfig.method_signature();
+      std::vector<string> components =
+          android::base::Split(methodSignature, " ");
+      if (components.size() < 2) {
+        return false;
+      }
+      const string &fullMethodName = components[1];
+      bool allowed = false;
+      for (const std::string allowedPrefix : kAllowedMethodPrefixes) {
+        if (android::base::StartsWith(fullMethodName, allowedPrefix + ".") ||
+            android::base::StartsWith(fullMethodName, allowedPrefix + "$")) {
+          allowed = true;
+          break;
+        }
+      }
+      if (!allowed) {
+        return false;
+      }
+    }
+  }
+  return true;
+}
+
+} // namespace guardrail
+} // namespace uprobestats
+} // namespace android
diff --git a/src/Guardrail.h b/src/Guardrail.h
new file mode 100644
index 0000000..30c5591
--- /dev/null
+++ b/src/Guardrail.h
@@ -0,0 +1,31 @@
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
+
+#pragma once
+
+#include <config.pb.h>
+#include <string>
+
+namespace android {
+namespace uprobestats {
+namespace guardrail {
+
+bool isAllowed(const ::uprobestats::protos::UprobestatsConfig &config,
+               const std::string &buildType);
+
+} // namespace guardrail
+} // namespace uprobestats
+} // namespace android
diff --git a/src/TEST_MAPPING b/src/TEST_MAPPING
new file mode 100644
index 0000000..b7f5416
--- /dev/null
+++ b/src/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+    "presubmit": [
+        {
+            "name": "uprobestats-test"
+        }
+    ]
+}
diff --git a/src/UprobeStats.cpp b/src/UprobeStats.cpp
index 93d421b..ad660cc 100644
--- a/src/UprobeStats.cpp
+++ b/src/UprobeStats.cpp
@@ -30,53 +30,145 @@
 
 #include "Bpf.h"
 #include "ConfigResolver.h"
+#include "Guardrail.h"
+#include <stats_event.h>
 
 using namespace android::uprobestats;
 
-bool isUserBuild() {
-  return android::base::GetProperty("ro.build.type", "unknown") == "user";
-}
+const std::string kGenericBpfMapDetail =
+    std::string("GenericInstrumentation_call_detail");
+const std::string kGenericBpfMapTimestamp =
+    std::string("GenericInstrumentation_call_timestamp");
+const std::string kProcessManagementMap =
+    std::string("ProcessManagement_output_buf");
+const int kJavaArgumentRegisterOffset = 2;
+const bool kDebug = true;
+
+#define LOG_IF_DEBUG(msg)                                                      \
+  do {                                                                         \
+    if (kDebug) {                                                              \
+      LOG(INFO) << msg;                                                        \
+    }                                                                          \
+  } while (0)
 
 bool isUprobestatsEnabled() {
   return android::uprobestats::flags::enable_uprobestats();
 }
 
-const std::string bpf_path = std::string("/sys/fs/bpf/uprobestats/");
-std::string prefix_bpf(std::string value) { return bpf_path + value.c_str(); }
+const std::string kBpfPath = std::string("/sys/fs/bpf/uprobestats/");
+std::string prefixBpf(std::string value) { return kBpfPath + value.c_str(); }
 
 struct PollArgs {
-  std::string map_path;
-  int duration_seconds;
+  std::string mapPath;
+  ::uprobestats::protos::UprobestatsConfig::Task taskConfig;
 };
 
 void doPoll(PollArgs args) {
-  auto map_path = args.map_path;
-  auto duration_seconds = args.duration_seconds;
-  auto duration = std::chrono::seconds(duration_seconds);
-  auto start_time = std::chrono::steady_clock::now();
-  auto now = start_time;
-  while (now - start_time < duration) {
-    auto remaining = duration - (std::chrono::steady_clock::now() - start_time);
-    auto timeout_ms = static_cast<int>(
+  auto mapPath = args.mapPath;
+  auto durationSeconds = args.taskConfig.duration_seconds();
+  auto duration = std::chrono::seconds(durationSeconds);
+  auto startTime = std::chrono::steady_clock::now();
+  auto now = startTime;
+  while (now - startTime < duration) {
+    auto remaining = duration - (std::chrono::steady_clock::now() - startTime);
+    auto timeoutMs = static_cast<int>(
         std::chrono::duration_cast<std::chrono::milliseconds>(remaining)
             .count());
-    auto result = bpf::pollRingBuf(map_path.c_str(), timeout_ms);
-    for (auto value : result) {
-      LOG(INFO) << "ringbuf result callback. value: " << value
-                << " map_path: " << map_path;
+    if (mapPath.find(kGenericBpfMapDetail) != std::string::npos) {
+      LOG_IF_DEBUG("polling for GenericDetail result");
+      auto result =
+          bpf::pollRingBuf<bpf::CallResult>(mapPath.c_str(), timeoutMs);
+      for (auto value : result) {
+        LOG_IF_DEBUG("GenericDetail result...");
+        LOG_IF_DEBUG("register: pc = " << value.pc);
+        for (int i = 0; i < 10; i++) {
+          auto reg = value.regs[i];
+          LOG_IF_DEBUG("register: " << i << " = " << reg);
+        }
+        if (!args.taskConfig.has_statsd_logging_config()) {
+          LOG_IF_DEBUG("no statsd logging config");
+          continue;
+        }
+
+        auto statsd_logging_config = args.taskConfig.statsd_logging_config();
+        int atom_id = statsd_logging_config.atom_id();
+        LOG_IF_DEBUG("attempting to write atom id: " << atom_id);
+        AStatsEvent *event = AStatsEvent_obtain();
+        AStatsEvent_setAtomId(event, atom_id);
+        for (int primitiveArgumentPosition :
+             statsd_logging_config.primitive_argument_positions()) {
+          int primitiveArgument = value.regs[primitiveArgumentPosition +
+                                             kJavaArgumentRegisterOffset];
+          LOG_IF_DEBUG("writing argument value: " << primitiveArgument
+                                                  << " from position: "
+                                                  << primitiveArgumentPosition);
+          AStatsEvent_writeInt32(event, primitiveArgument);
+        }
+        AStatsEvent_write(event);
+        AStatsEvent_release(event);
+        LOG_IF_DEBUG("successfully wrote atom id: " << atom_id);
+      }
+    } else if (mapPath.find(kGenericBpfMapTimestamp) != std::string::npos) {
+      LOG_IF_DEBUG("polling for GenericTimestamp result");
+      auto result =
+          bpf::pollRingBuf<bpf::CallTimestamp>(mapPath.c_str(), timeoutMs);
+      for (auto value : result) {
+        LOG_IF_DEBUG("GenericTimestamp result: event "
+                     << value.event << " timestampNs: " << value.timestampNs);
+        if (!args.taskConfig.has_statsd_logging_config()) {
+          LOG_IF_DEBUG("no statsd logging config");
+          continue;
+        }
+        // TODO: for now, we assume an atom structure of event, then timestamp.
+        // We will build a cleaner abstraction for handling "just give me
+        // timestamps when X API is called", but we're just trying ot get things
+        // working for now.
+        auto statsd_logging_config = args.taskConfig.statsd_logging_config();
+        int atom_id = statsd_logging_config.atom_id();
+        LOG_IF_DEBUG("attempting to write atom id: " << atom_id);
+        AStatsEvent *event = AStatsEvent_obtain();
+        AStatsEvent_setAtomId(event, atom_id);
+        AStatsEvent_writeInt32(event, value.event);
+        AStatsEvent_writeInt64(event, value.timestampNs);
+        AStatsEvent_write(event);
+        AStatsEvent_release(event);
+        LOG_IF_DEBUG("successfully wrote atom id: " << atom_id);
+      }
+    } else if (mapPath.find(kProcessManagementMap) != std::string::npos) {
+      LOG_IF_DEBUG("Polling for SetUidTempAllowlistStateRecord result");
+      auto result = bpf::pollRingBuf<bpf::SetUidTempAllowlistStateRecord>(
+          mapPath.c_str(), timeoutMs);
+      for (auto value : result) {
+        LOG_IF_DEBUG("SetUidTempAllowlistStateRecord result... uid: "
+                     << value.uid << " onAllowlist: " << value.onAllowlist
+                     << " mapPath: " << mapPath);
+        if (!args.taskConfig.has_statsd_logging_config()) {
+          LOG_IF_DEBUG("no statsd logging config");
+          continue;
+        }
+        auto statsd_logging_config = args.taskConfig.statsd_logging_config();
+        int atom_id = statsd_logging_config.atom_id();
+        AStatsEvent *event = AStatsEvent_obtain();
+        AStatsEvent_setAtomId(event, atom_id);
+        AStatsEvent_writeInt32(event, value.uid);
+        AStatsEvent_writeBool(event, value.onAllowlist);
+        AStatsEvent_write(event);
+        AStatsEvent_release(event);
+      }
+    } else {
+      LOG_IF_DEBUG("Polling for i64 result");
+      auto result = bpf::pollRingBuf<uint64_t>(mapPath.c_str(), timeoutMs);
+      for (auto value : result) {
+        LOG_IF_DEBUG("Other result... value: " << value
+                                               << " mapPath: " << mapPath);
+      }
     }
     now = std::chrono::steady_clock::now();
   }
-  LOG(INFO) << "finished polling for map_path: " << map_path;
+  LOG_IF_DEBUG("finished polling for mapPath: " << mapPath);
 }
 
 int main(int argc, char **argv) {
-  if (isUserBuild()) {
-    // TODO(296108553): See if we could avoid shipping this binary on user
-    // builds.
-    LOG(ERROR) << "uprobestats disabled on user build. Exiting.";
-    return 1;
-  }
   if (!isUprobestatsEnabled()) {
     LOG(ERROR) << "uprobestats disabled by flag. Exiting.";
     return 1;
@@ -89,42 +181,53 @@ int main(int argc, char **argv) {
   auto config = config_resolver::readConfig(
       std::string("/data/misc/uprobestats-configs/") + argv[1]);
   if (!config.has_value()) {
+    LOG(ERROR) << "Failed to parse uprobestats config: " << argv[1];
+    return 1;
+  }
+  if (!guardrail::isAllowed(config.value(), android::base::GetProperty(
+                                                "ro.build.type", "unknown"))) {
+    LOG(ERROR) << "uprobestats probing config disallowed on this device.";
     return 1;
   }
-  auto resolved_task = config_resolver::resolveSingleTask(config.value());
-  if (!resolved_task.has_value()) {
+  auto resolvedTask = config_resolver::resolveSingleTask(config.value());
+  if (!resolvedTask.has_value()) {
+    LOG(ERROR) << "Failed to parse task";
     return 1;
   }
 
-  LOG(INFO) << "Found task config: " << resolved_task.value();
-  std::set<std::string> map_paths;
-  auto resolved_probe_configs =
-      config_resolver::resolveProbes(resolved_task.value().task_config);
-  if (!resolved_probe_configs.has_value()) {
+  LOG_IF_DEBUG("Found task config: " << resolvedTask.value());
+  auto resolvedProbeConfigs =
+      config_resolver::resolveProbes(resolvedTask.value().taskConfig);
+  if (!resolvedProbeConfigs.has_value()) {
+    LOG(ERROR) << "Failed to resolve a probe config from task";
     return 1;
   }
-  for (auto &resolved_probe : resolved_probe_configs.value()) {
-    LOG(INFO) << "Opening bpf perf event from probe: " << resolved_probe;
-    map_paths.insert(prefix_bpf(resolved_probe.probe_config.bpf_map()));
-    bpf::bpfPerfEventOpen(
-        resolved_probe.filename.c_str(), resolved_probe.offset,
-        resolved_task.value().pid,
-        prefix_bpf(resolved_probe.probe_config.bpf_name()).c_str());
+  for (auto &resolvedProbe : resolvedProbeConfigs.value()) {
+    LOG_IF_DEBUG("Opening bpf perf event from probe: " << resolvedProbe);
+    auto openResult = bpf::bpfPerfEventOpen(
+        resolvedProbe.filename.c_str(), resolvedProbe.offset,
+        resolvedTask.value().pid,
+        prefixBpf(resolvedProbe.probeConfig.bpf_name()).c_str());
+    if (openResult != 0) {
+      LOG(ERROR) << "Failed to open bpf "
+                 << resolvedProbe.probeConfig.bpf_name();
+      return 1;
+    }
   }
 
   std::vector<std::thread> threads;
-  for (auto map_path : map_paths) {
-    auto poll_args = PollArgs{
-        map_path, resolved_task.value().task_config.duration_seconds()};
-    LOG(INFO) << "Starting thread to collect results from map_path: "
-              << map_path;
-    threads.emplace_back(doPoll, poll_args);
+  for (auto mapPath : resolvedTask.value().taskConfig.bpf_maps()) {
+    auto pollArgs =
+        PollArgs{prefixBpf(mapPath), resolvedTask.value().taskConfig};
+    LOG_IF_DEBUG(
+        "Starting thread to collect results from mapPath: " << mapPath);
+    threads.emplace_back(doPoll, pollArgs);
   }
   for (auto &thread : threads) {
     thread.join();
   }
 
-  LOG(INFO) << "done.";
+  LOG_IF_DEBUG("done.");
 
   return 0;
 }
diff --git a/src/bpf_progs/Android.bp b/src/bpf_progs/Android.bp
index 697d596..1b7bf63 100644
--- a/src/bpf_progs/Android.bp
+++ b/src/bpf_progs/Android.bp
@@ -5,6 +5,18 @@ package {
 bpf {
     name: "BitmapAllocation.o",
     srcs: ["BitmapAllocation.c"],
+    sub_dir: "uprobestats",
+}
+
+bpf {
+    name: "GenericInstrumentation.o",
+    srcs: ["GenericInstrumentation.c"],
+    sub_dir: "uprobestats",
+}
+
+bpf {
+    name: "ProcessManagement.o",
+    srcs: ["ProcessManagement.c"],
     btf: true,
     cflags: [
         "-Wall",
diff --git a/src/bpf_progs/BitmapAllocation.c b/src/bpf_progs/BitmapAllocation.c
index 641a922..de5c10b 100644
--- a/src/bpf_progs/BitmapAllocation.c
+++ b/src/bpf_progs/BitmapAllocation.c
@@ -24,7 +24,7 @@ DEFINE_BPF_RINGBUF_EXT(output_buf, __u64, 4096, AID_UPROBESTATS, AID_UPROBESTATS
                        LOAD_ON_USERDEBUG);
 
 DEFINE_BPF_PROG("uprobe/bitmap_constructor_heap", AID_UPROBESTATS, AID_UPROBESTATS, BPF_KPROBE2)
-(void* this_ptr, void* buffer_address, __u32 size) {
+(__unused void* this_ptr, __unused void* buffer_address, __unused __u32 size) {
     __u64* output = bpf_output_buf_reserve();
     if (output == NULL) return 1;
     (*output) = 123;
diff --git a/src/bpf_progs/GenericInstrumentation.c b/src/bpf_progs/GenericInstrumentation.c
new file mode 100644
index 0000000..d1df06c
--- /dev/null
+++ b/src/bpf_progs/GenericInstrumentation.c
@@ -0,0 +1,150 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+#include <bpf_helpers.h>
+#include <linux/bpf.h>
+#include <stdbool.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <string.h>
+
+// TODO: import this struct from generic header, access registers via generic
+// function
+struct pt_regs {
+  unsigned long regs[16];
+  unsigned long pc;
+  unsigned long pr;
+  unsigned long sr;
+  unsigned long gbr;
+  unsigned long mach;
+  unsigned long macl;
+  long tra;
+};
+
+// TODO: share this struct between bpf and uprobestats
+struct CallResult {
+  unsigned long pc;
+  unsigned long regs[10];
+};
+
+struct CallTimestamp {
+  unsigned int event;
+  unsigned long timestampNs;
+};
+
+DEFINE_BPF_RINGBUF_EXT(call_detail_buf, struct CallResult, 4096,
+                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
+                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
+                       LOAD_ON_USER, LOAD_ON_USERDEBUG);
+
+DEFINE_BPF_RINGBUF_EXT(call_timestamp_buf, struct CallTimestamp, 4096,
+                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
+                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
+                       LOAD_ON_USER, LOAD_ON_USERDEBUG);
+
+DEFINE_BPF_PROG("uprobe/call_detail", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE11)
+(struct pt_regs *ctx) {
+  struct CallResult result;
+  // for whatever reason, reading past register 10 causes bpf verifier to fail
+  for (int i = 0; i < 11; i++) {
+    result.regs[i] = ctx->regs[i];
+  }
+  result.pc = ctx->pc;
+  struct CallResult *output = bpf_call_detail_buf_reserve();
+  if (output == NULL)
+    return 1;
+  (*output) = result;
+  bpf_call_detail_buf_submit(output);
+  return 0;
+}
+
+DEFINE_BPF_PROG("uprobe/call_timestamp_1", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE1)
+() {
+  struct CallTimestamp result;
+  result.event = 1;
+  result.timestampNs = bpf_ktime_get_ns();
+  struct CallTimestamp *output = bpf_call_timestamp_buf_reserve();
+  if (output == NULL) {
+    return 1;
+  }
+  (*output) = result;
+  bpf_call_timestamp_buf_submit(output);
+  return 0;
+}
+
+DEFINE_BPF_PROG("uprobe/call_timestamp_2", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE2)
+() {
+  struct CallTimestamp result;
+  result.event = 2;
+  result.timestampNs = bpf_ktime_get_ns();
+  struct CallTimestamp *output = bpf_call_timestamp_buf_reserve();
+  if (output == NULL) {
+    return 1;
+  }
+  (*output) = result;
+  bpf_call_timestamp_buf_submit(output);
+  return 0;
+}
+
+DEFINE_BPF_PROG("uprobe/call_timestamp_3", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE3)
+() {
+  struct CallTimestamp result;
+  result.event = 3;
+  result.timestampNs = bpf_ktime_get_ns();
+  struct CallTimestamp *output = bpf_call_timestamp_buf_reserve();
+  if (output == NULL) {
+    return 1;
+  }
+  (*output) = result;
+  bpf_call_timestamp_buf_submit(output);
+  return 0;
+}
+
+DEFINE_BPF_PROG("uprobe/call_timestamp_4", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE4)
+() {
+  struct CallTimestamp result;
+  result.event = 4;
+  result.timestampNs = bpf_ktime_get_ns();
+  struct CallTimestamp *output = bpf_call_timestamp_buf_reserve();
+  if (output == NULL) {
+    return 1;
+  }
+  (*output) = result;
+  bpf_call_timestamp_buf_submit(output);
+  return 0;
+}
+
+DEFINE_BPF_PROG("uprobe/call_timestamp_5", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE5)
+() {
+  struct CallTimestamp result;
+  result.event = 5;
+  result.timestampNs = bpf_ktime_get_ns();
+  struct CallTimestamp *output = bpf_call_timestamp_buf_reserve();
+  if (output == NULL) {
+    return 1;
+  }
+  (*output) = result;
+  bpf_call_timestamp_buf_submit(output);
+  return 0;
+}
+
+LICENSE("GPL");
diff --git a/src/bpf_progs/ProcessManagement.c b/src/bpf_progs/ProcessManagement.c
new file mode 100644
index 0000000..b8623d6
--- /dev/null
+++ b/src/bpf_progs/ProcessManagement.c
@@ -0,0 +1,57 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include <bpf_helpers.h>
+#include <linux/bpf.h>
+#include <stdbool.h>
+#include <stdint.h>
+
+// TODO: import this struct from generic header, access registers via generic
+// function
+struct pt_regs {
+  unsigned long regs[16];
+  unsigned long pc;
+  unsigned long pr;
+  unsigned long sr;
+  unsigned long gbr;
+  unsigned long mach;
+  unsigned long macl;
+  long tra;
+};
+
+struct SetUidTempAllowlistStateRecord {
+  __u64 uid;
+  bool onAllowlist;
+};
+
+DEFINE_BPF_RINGBUF_EXT(output_buf, struct SetUidTempAllowlistStateRecord, 4096,
+                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
+                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
+                       LOAD_ON_USER, LOAD_ON_USERDEBUG);
+
+DEFINE_BPF_PROG("uprobe/set_uid_temp_allowlist_state", AID_UPROBESTATS,
+                AID_UPROBESTATS, BPF_KPROBE2)
+(struct pt_regs *ctx) {
+  struct SetUidTempAllowlistStateRecord *output = bpf_output_buf_reserve();
+  if (output == NULL)
+    return 1;
+  output->uid = ctx->regs[2];
+  output->onAllowlist = ctx->regs[3];
+  bpf_output_buf_submit(output);
+  return 0;
+}
+
+LICENSE("GPL");
diff --git a/src/config.proto b/src/config.proto
index a47db5f..7ffcd09 100644
--- a/src/config.proto
+++ b/src/config.proto
@@ -28,22 +28,39 @@ message UprobestatsConfig {
       // Full method signature. E.g.
       // void android.content.pm.PackageManagerInternal.finishPackageInstall(int, boolean)
       optional string method_signature = 3;
-
-      // Name of the FD that the BPF program writes to. E.g.
-      // map_BitmapAllocation_output_buf. Note that this does not include the full file path.
-      optional string bpf_map = 4;
     }
 
     repeated ProbeConfig probe_configs = 1;
 
+    // Name of the FDs that the BPF programs write to. E.g.
+    // map_BitmapAllocation_output_buf. Note that this does not include the full file path.
+    repeated string bpf_maps = 2;
+
     // Name of the process to be probed, e.g. system_server.
-    optional string target_process_name = 2;
+    optional string target_process_name = 3;
 
     // How long the probes should remain active.
-    optional int32 duration_seconds = 3;
+    optional int32 duration_seconds = 4;
 
     message StatsdLoggingConfig {
       optional int64 atom_id = 1;
+      // The positions of any arguments to the method call that should be sent to the atom.
+      // These arguments MUST be primitive types (e.g. bool, int), NOT complex objects
+      // (that will be nothing but pointers). The positions should be ordered in the same
+      // order as the corresponding fields of the atom to be populated.
+      // 
+      // For example, given the method:
+      // `void startThing(int argA, int argB, int argC)`
+      // and the atom:
+      // ```
+      // proto StartAppInvocations {
+      //   optional int logged_arg_b = 1;
+      //   optional int logged_arg_a = 2;
+      // }
+      // ```
+      // The config value should be [1, 0], meaning the 2nd argument is actually the
+      // first field in the atom, and vice versa. 
+      repeated int32 primitive_argument_positions = 2;
     }
     optional StatsdLoggingConfig statsd_logging_config = 5;
 
diff --git a/src/lib/Android.bp b/src/lib/Android.bp
index 000b1a1..574066a 100644
--- a/src/lib/Android.bp
+++ b/src/lib/Android.bp
@@ -42,4 +42,8 @@ cc_library_shared {
     header_libs: [
         "libcutils_headers",
     ],
+
+    ldflags: [
+        "-Wl,-rpath,/system/${LIB}",
+    ],
 }
diff --git a/src/test/SmokeTest.java b/src/test/SmokeTest.java
new file mode 100644
index 0000000..eb56018
--- /dev/null
+++ b/src/test/SmokeTest.java
@@ -0,0 +1,114 @@
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
+
+package test;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.cts.statsdatom.lib.AtomTestUtils;
+import android.cts.statsdatom.lib.ConfigUtils;
+import android.cts.statsdatom.lib.DeviceUtils;
+import android.cts.statsdatom.lib.ReportUtils;
+
+import com.android.internal.os.StatsdConfigProto;
+import com.android.os.StatsLog;
+import com.android.os.uprobestats.TestUprobeStatsAtomReported;
+import com.android.os.uprobestats.UprobestatsExtensionAtoms;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.testtype.DeviceTestCase;
+import com.android.tradefed.util.RunUtil;
+
+import com.google.protobuf.ExtensionRegistry;
+import com.google.protobuf.TextFormat;
+
+import uprobestats.protos.Config.UprobestatsConfig;
+
+import java.io.File;
+import java.nio.file.Files;
+import java.util.List;
+import java.util.Scanner;
+
+public class SmokeTest extends DeviceTestCase {
+
+    private static final String BATTERY_STATS_CONFIG = "test_bss_setBatteryState.textproto";
+    private static final String CONFIG_NAME = "test";
+    private static final String CMD_SETPROP_UPROBESTATS = "setprop uprobestats.start_with_config ";
+    private static final String CONFIG_DIR = "/data/misc/uprobestats-configs/";
+
+    @Override
+    protected void setUp() throws Exception {
+        ConfigUtils.removeConfig(getDevice());
+        ReportUtils.clearReports(getDevice());
+        getDevice().deleteFile(CONFIG_DIR + CONFIG_NAME);
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+    }
+
+    public void testBatteryStats() throws Exception {
+        // 1. Parse config from resources
+        String textProto =
+                new Scanner(this.getClass().getResourceAsStream(BATTERY_STATS_CONFIG))
+                        .useDelimiter("\\A")
+                        .next();
+        UprobestatsConfig.Builder builder = UprobestatsConfig.newBuilder();
+        TextFormat.getParser().merge(textProto, builder);
+        UprobestatsConfig config = builder.build();
+
+        // 2. Write config to a file and drop it on the device
+        File tmp = File.createTempFile("uprobestats", CONFIG_NAME);
+        assertTrue(tmp.setWritable(true));
+        Files.write(tmp.toPath(), config.toByteArray());
+        ITestDevice device = getDevice();
+        assertTrue(getDevice().enableAdbRoot());
+        assertTrue(getDevice().pushFile(tmp, CONFIG_DIR + CONFIG_NAME));
+
+        // 3. Configure StatsD
+        ExtensionRegistry registry = ExtensionRegistry.newInstance();
+        UprobestatsExtensionAtoms.registerAllExtensions(registry);
+        StatsdConfigProto.StatsdConfig.Builder configBuilder =
+                ConfigUtils.createConfigBuilder("AID_UPROBESTATS");
+        ConfigUtils.addEventMetric(
+                configBuilder,
+                UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);
+        ConfigUtils.uploadConfig(getDevice(), configBuilder);
+
+        // 4. Start UprobeStats
+        device.executeShellCommand(CMD_SETPROP_UPROBESTATS + CONFIG_NAME);
+        // Allow UprobeStats time to attach probe
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+
+        // 5. Set charging state, which should invoke BatteryStatsService#setBatteryState.
+        // Assumptions:
+        //   - uprobestats flag is enabled
+        //   - userdebug build
+        //   - said method is precompiled (specified in frameworks/base/services/art-profile)
+        // If this test fails, check those assumptions first.
+        DeviceUtils.setChargingState(getDevice(), 2);
+        // Allow UprobeStats/StatsD time to collect metric
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+
+        // 6. See if the atom made it
+        List<StatsLog.EventMetricData> data =
+                ReportUtils.getEventMetricDataList(getDevice(), registry);
+        assertThat(data.size()).isEqualTo(1);
+        TestUprobeStatsAtomReported reported =
+                data.get(0)
+                        .getAtom()
+                        .getExtension(UprobestatsExtensionAtoms.testUprobestatsAtomReported);
+        assertThat(reported.getFirstField()).isEqualTo(1);
+        assertThat(reported.getSecondField()).isGreaterThan(0);
+        assertThat(reported.getThirdField()).isEqualTo(0);
+    }
+}
diff --git a/src/test/test_bss_noteEvent.textproto b/src/test/test_bss_noteEvent.textproto
new file mode 100644
index 0000000..2d55b38
--- /dev/null
+++ b/src/test/test_bss_noteEvent.textproto
@@ -0,0 +1,17 @@
+# proto-file: config.proto
+# proto-message: UprobestatsConfig
+
+tasks {
+    probe_configs {
+        bpf_name: "prog_GenericInstrumentation_uprobe_call_detail"
+        bpf_map: "map_GenericInstrumentation_call_detail_buf""
+        file_paths: "/system/framework/oat/arm64/services.odex"
+        method_signature: "void com.android.server.am.BatteryStatsService.noteEvent(int, java.lang.String, int)"
+    }
+    target_process_name: "system_server"
+    duration_seconds: 60
+    statsd_logging_config {
+        atom_id: 915
+        primitive_argument_positions: [0, 2]
+    }
+}
diff --git a/src/test/test_bss_noteScreenState.textproto b/src/test/test_bss_noteScreenState.textproto
new file mode 100644
index 0000000..e9754fe
--- /dev/null
+++ b/src/test/test_bss_noteScreenState.textproto
@@ -0,0 +1,17 @@
+# proto-file: config.proto
+# proto-message: UprobestatsConfig
+
+tasks {
+    probe_configs {
+        bpf_name: "prog_GenericInstrumentation_uprobe_call_timestamp_1"
+        file_paths: ["/system/framework/oat/arm64/services.odex","/system/framework/oat/x86_64/services.odex"]
+        method_signature: "void com.android.server.am.BatteryStatsService.noteScreenState(int)"
+    }
+    bpf_maps: "map_GenericInstrumentation_call_timestamp_buf"
+    target_process_name: "system_server"
+    duration_seconds: 60
+    statsd_logging_config {
+        atom_id: 915
+        primitive_argument_positions: [0]
+    }
+}
diff --git a/src/test/test_bss_setBatteryState.textproto b/src/test/test_bss_setBatteryState.textproto
new file mode 100644
index 0000000..744214d
--- /dev/null
+++ b/src/test/test_bss_setBatteryState.textproto
@@ -0,0 +1,16 @@
+# proto-file: config.proto
+# proto-message: UprobestatsConfig
+
+tasks {
+    probe_configs {
+        bpf_name: "prog_GenericInstrumentation_uprobe_call_timestamp_1"
+        file_paths: ["/system/framework/oat/arm64/services.odex", "/system/framework/oat/x86_64/services.odex"]
+        method_signature: "void com.android.server.am.BatteryStatsService.setBatteryState(int, int, int, int, int, int, int, int, long)"
+    }
+    bpf_maps: "map_GenericInstrumentation_call_timestamp_buf"
+    target_process_name: "system_server"
+    duration_seconds: 60
+    statsd_logging_config {
+        atom_id: 915
+    }
+}
diff --git a/src/test/test_setUidTempAllowlistStateLSP.textproto b/src/test/test_setUidTempAllowlistStateLSP.textproto
new file mode 100644
index 0000000..d7b7b6e
--- /dev/null
+++ b/src/test/test_setUidTempAllowlistStateLSP.textproto
@@ -0,0 +1,16 @@
+# proto-file: config.proto
+# proto-message: UprobestatsConfig
+
+tasks {
+    probe_configs: {
+        bpf_name: "prog_ProcessManagement_uprobe_set_uid_temp_allowlist_state"
+        file_paths: "/system/framework/oat/arm64/services.odex"
+        method_signature: "void com.android.server.am.OomAdjuster.setUidTempAllowlistStateLSP(int, boolean)"
+    }
+    bpf_maps: "map_ProcessManagement_output_buf"
+    target_process_name: "system_server"
+    duration_seconds: 180
+    statsd_logging_config {
+      atom_id: 926
+    }
+}
```

