```diff
diff --git a/default.xml b/default.xml
index a04f29de2..5b70d528c 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-16.0.0_r2"
+  <default revision="refs/tags/android-16.0.0_r3"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-16.0.0_r2"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-16.0.0_r3"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
@@ -20,11 +20,6 @@
     <linkfile src="target" dest="build/target" />
     <linkfile src="tools" dest="build/tools" />
   </project>
-  <project path="build/bazel" name="platform/build/bazel" groups="pdk" >
-    <linkfile src="bazel.WORKSPACE" dest="WORKSPACE" />
-    <linkfile src="bazel.BUILD" dest="BUILD" />
-  </project>
-  <project path="build/bazel_common_rules" name="platform/build/bazel_common_rules" groups="pdk" />
   <project path="build/blueprint" name="platform/build/blueprint" groups="pdk,tradefed" />
   <project path="build/pesto" name="platform/build/pesto" groups="pdk" />
   <project path="build/release" name="platform/build/release" groups="pdk,tradefed,sysui-studio" />
@@ -51,7 +46,6 @@
   <project path="device/generic/car" name="device/generic/car" groups="pdk" />
   <project path="device/generic/common" name="device/generic/common" groups="pdk" />
   <project path="device/generic/goldfish" name="device/generic/goldfish" groups="pdk" />
-  <project path="device/generic/goldfish-opengl" name="device/generic/goldfish-opengl" groups="pdk" />
   <project path="device/generic/trusty" name="device/generic/trusty" groups="pdk" />
   <project path="device/generic/x86" name="device/generic/x86" groups="pdk" />
   <project path="device/generic/x86_64" name="device/generic/x86_64" groups="pdk" />
@@ -91,6 +85,7 @@
   <project path="external/arm-optimized-routines" name="platform/external/arm-optimized-routines" groups="pdk" />
   <project path="external/arm-trusted-firmware" name="platform/external/arm-trusted-firmware" groups="pdk" />
   <project path="external/auto" name="platform/external/auto" groups="pdk" />
+  <project path="external/automotive-design-compose-protos" name="platform/external/automotive-design-compose-protos" groups="pdk"/>
   <project path="external/autotest" name="platform/external/autotest" groups="pdk-fs" />
   <project path="external/android-nn-driver" name="platform/external/android-nn-driver" groups="pdk-lassen,pdk-gs-arm" />
   <project path="external/armnn" name="platform/external/armnn" groups="pdk-lassen,pdk-gs-arm" />
@@ -98,18 +93,7 @@
   <project path="external/aws-crt-java" name="platform/external/aws-crt-java" groups="pdk,tradefed" />
   <project path="external/aws-eventstream-java" name="platform/external/aws-eventstream-java" groups="pdk,tradefed" />
   <project path="external/aws-sdk-java-v2" name="platform/external/aws-sdk-java-v2" groups="pdk,tradefed" />
-  <project path="external/bazelbuild-rules_android" name="platform/external/bazelbuild-rules_android" groups="pdk" />
-  <project path="external/bazelbuild-rules_cc" name="platform/external/bazelbuild-rules_cc" groups="pdk" />
-  <project path="external/bazelbuild-rules_java" name="platform/external/bazelbuild-rules_java" groups="pdk" />
-  <project path="external/bazelbuild-rules_go" name="platform/external/bazelbuild-rules_go" groups="pdk" />
-  <project path="external/bazelbuild-kotlin-rules" name="platform/external/bazelbuild-kotlin-rules" groups="pdk" />
-  <project path="external/bazelbuild-platforms" name="platform/external/bazelbuild-platforms" groups="pdk" />
-  <project path="external/bazelbuild-rules_license" name="platform/external/bazelbuild-rules_license" groups="pdk" />
-  <project path="external/bazelbuild-rules_python" name="platform/external/bazelbuild-rules_python" groups="pdk" />
-  <project path="external/bazelbuild-rules_rust" name="platform/external/bazelbuild-rules_rust" groups="pdk" />
-  <project path="external/bazelbuild-rules_testing" name="platform/external/bazelbuild-rules_testing" groups="pdk" />
   <project path="external/bazelbuild-remote-apis" name="platform/external/bazelbuild-remote-apis" groups="pdk,tradefed" />
-  <project path="external/bazel-skylib" name="platform/external/bazel-skylib" groups="pdk" />
   <project path="external/bc" name="platform/external/bc" groups="pdk" />
   <project path="external/bcc" name="platform/external/bcc" groups="pdk" />
   <project path="external/blktrace" name="platform/external/blktrace" groups="pdk" />
@@ -119,17 +103,21 @@
   <project path="external/brotli" name="platform/external/brotli" groups="pdk" />
   <project path="external/bsdiff" name="platform/external/bsdiff" groups="pdk" />
   <project path="external/bzip2" name="platform/external/bzip2" groups="pdk" />
+  <project path="external/cairo" name="platform/external/cairo" groups="pdk" />
   <project path="external/caliper" name="platform/external/caliper" groups="pdk" />
   <project path="external/capstone" name="platform/external/capstone" groups="pdk" />
   <project path="external/cblas" name="platform/external/cblas" groups="pdk" />
   <project path="external/cbor-java" name="platform/external/cbor-java" groups="pdk" />
   <project path="external/chromium-crossbench" name="platform/external/chromium-crossbench" groups="pdk" />
   <project path="external/chromium-trace" name="platform/external/chromium-trace" groups="pdk" />
+  <project path="external/chromium-web-tests" name="platform/external/chromium-web-tests" groups="pdk" />
   <project path="external/chromium-webview" name="platform/external/chromium-webview" groups="pdk" clone-depth="1" />
   <project path="external/chromiumos-config" name="platform/external/chromiumos-config" groups="pdk" clone-depth="1" />
   <project path="external/clang" name="platform/external/clang" groups="pdk" />
   <project path="external/cldr" name="platform/external/cldr" groups="pdk" />
-  <project path="external/clpeak" name="platform/external/clpeak" />
+  <project path="external/clpeak" name="platform/external/clpeak" groups="pdk" />
+  <project path="external/clspv" name="platform/external/clspv" groups="pdk" />
+  <project path="external/clvk" name="platform/external/clvk" groups="pdk" />
   <project path="external/cn-cbor" name="platform/external/cn-cbor" groups="pdk" />
   <project path="external/compiler-rt" name="platform/external/compiler-rt" groups="pdk" />
   <project path="external/ComputeLibrary" name="platform/external/ComputeLibrary" groups="pdk-lassen,pdk-gs-arm" />
@@ -138,7 +126,6 @@
   <project path="external/coreboot" name="platform/external/coreboot" groups="pdk"/>
   <project path="external/cpu_features" name="platform/external/cpu_features" groups="pdk" />
   <project path="external/cpuinfo" name="platform/external/cpuinfo" groups="pdk" />
-  <project path="external/crcalc" name="platform/external/crcalc" groups="pdk" />
   <project path="external/cronet" name="platform/external/cronet" groups="pdk" />
   <project path="external/crosvm" name="platform/external/crosvm" groups="pdk" />
   <project path="external/curl" name="platform/external/curl" groups="pdk" />
@@ -166,6 +153,7 @@
   <project path="external/elfutils" name="platform/external/elfutils" groups="pdk" />
   <project path="external/emboss" name="platform/external/emboss" groups="pdk" />
   <project path="external/emma" name="platform/external/emma" groups="pdk" />
+  <project path="external/epson-inkjet-printer-escpr" name="platform/external/epson-inkjet-printer-escpr" groups="pdk" />
   <project path="external/erofs-utils" name="platform/external/erofs-utils" groups="pdk" />
   <project path="external/error_prone" name="platform/external/error_prone" groups="pdk" />
   <project path="external/escapevelocity" name="platform/external/escapevelocity" groups="pdk" />
@@ -225,7 +213,6 @@
   <project path="external/google-fruit" name="platform/external/google-fruit" groups="pdk" />
   <project path="external/google-java-format" name="platform/external/google-java-format" groups="pdk" />
   <project path="external/google-smali" name="platform/external/google-smali" groups="pdk" />
-  <project path="external/google-styleguide" name="platform/external/google-styleguide" groups="pdk" />
   <project path="external/googletest" name="platform/external/googletest" groups="pdk" />
   <project path="external/gptfdisk" name="platform/external/gptfdisk" groups="pdk" />
   <project path="external/grpc-grpc" name="platform/external/grpc-grpc" groups="pdk,tradefed" />
@@ -239,6 +226,7 @@
   <project path="external/gwp_asan" name="platform/external/gwp_asan" groups="pdk" />
   <project path="external/hamcrest" name="platform/external/hamcrest" groups="pdk" />
   <project path="external/harfbuzz_ng" name="platform/external/harfbuzz_ng" groups="pdk,qcom_msm8x26" />
+  <project path="external/hplip" name="platform/external/hplip" groups="pdk" />
   <project path="external/hyphenation-patterns" name="platform/external/hyphenation-patterns" groups="pdk" />
   <project path="external/iamf_tools" name="platform/external/iamf_tools" groups="pdk" />
   <project path="external/icing" name="platform/external/icing" groups="pdk" />
@@ -247,6 +235,7 @@
   <project path="external/image_io" name="platform/external/image_io" groups="pdk" />
   <project path="external/ims" name="platform/external/ims" groups="pdk" />
   <project path="external/intel-media-driver" name="platform/external/intel-media-driver" groups="pdk" />
+  <project path="external/intel-pmt-metadata" name="platform/external/intel-pmt-metadata" groups="pdk" />
   <project path="external/iperf3" name="platform/external/iperf3" groups="pdk" />
   <project path="external/iproute2" name="platform/external/iproute2" groups="pdk" />
   <project path="external/iptables" name="platform/external/iptables" groups="pdk" />
@@ -278,6 +267,7 @@
   <project path="external/jsr330" name="platform/external/jsr330" groups="pdk" />
   <project path="external/junit" name="platform/external/junit" groups="pdk" />
   <project path="external/junit-params" name="platform/external/junit-params" groups="pdk" />
+  <project path="external/jxmpp" name="platform/external/jxmpp" groups="pdk" />
   <project path="external/kernel-headers" name="platform/external/kernel-headers" groups="pdk" />
   <project path="external/kmod" name="platform/external/kmod" groups="pdk" />
   <project path="external/kotlinc" name="platform/external/kotlinc" groups="pdk" />
@@ -298,12 +288,14 @@
   <project path="external/libbackup" name="platform/external/libbackup" groups="pdk" />
   <project path="external/libbrillo" name="platform/external/libbrillo" groups="pdk" />
   <project path="external/libbpf" name="platform/external/libbpf" groups="pdk" />
+  <project path="external/libcamera" name="platform/external/libcamera" groups="pdk" />
   <project path="external/libcap" name="platform/external/libcap" groups="pdk" />
   <project path="external/libcap-ng" name="platform/external/libcap-ng" groups="pdk" />
   <project path="external/libchrome" name="platform/external/libchrome" groups="pdk" />
   <project path="external/libchrome-gestures" name="platform/external/libchrome-gestures" groups="pdk" />
   <project path="external/libconfig" name="platform/external/libconfig" groups="pdk" />
   <project path="external/libcups" name="platform/external/libcups" groups="pdk-cw-fs,pdk-fs" />
+  <project path="external/libcupsfilters" name="platform/external/libcupsfilters" groups="pdk" />
   <project path="external/libcxx" name="platform/external/libcxx" groups="pdk" />
   <project path="external/libcxxabi" name="platform/external/libcxxabi" groups="pdk" />
   <project path="external/libdisplay-info" name="platform/external/libdisplay-info" groups="pdk" />
@@ -336,11 +328,13 @@
   <project path="external/libpciaccess" name="platform/external/libpciaccess" groups="pdk" />
   <project path="external/libphonenumber" name="platform/external/libphonenumber" groups="pdk" />
   <project path="external/libpng" name="platform/external/libpng" groups="pdk" />
+  <project path="external/libppd" name="platform/external/libppd" groups="pdk" />
   <project path="external/libprotobuf-mutator" name="platform/external/libprotobuf-mutator" groups="pdk" />
   <project path="external/libsrtp2" name="platform/external/libsrtp2" groups="pdk" />
   <project path="external/libtextclassifier" name="platform/external/libtextclassifier" groups="pdk" />
   <project path="external/libtraceevent" name="platform/external/libtraceevent" groups="pdk" />
   <project path="external/libtracefs" name="platform/external/libtracefs" groups="pdk" />
+  <project path="external/libudev-zero" name="platform/external/libudev-zero" groups="pdk" />
   <project path="external/libultrahdr" name="platform/external/libultrahdr" groups="pdk" />
   <project path="external/liburing" name="platform/external/liburing" groups="pdk" />
   <project path="external/libusb" name="platform/external/libusb" groups="pdk" />
@@ -353,10 +347,12 @@
   <project path="external/libxaac" name="platform/external/libxaac" groups="pdk" />
   <project path="external/libxkbcommon" name="platform/external/libxkbcommon" groups="pdk" />
   <project path="external/libxml2" name="platform/external/libxml2" groups="pdk,libxml2" />
+  <project path="external/libyaml" name="platform/external/libyaml" groups="pdk" />
   <project path="external/libyuv" name="platform/external/libyuv" groups="pdk,libyuv" />
   <project path="external/licenseclassifier" name="platform/external/licenseclassifier" groups="pdk" />
   <project path="external/linux-firmware" name="platform/external/linux-firmware" groups="pdk" />
   <project path="external/linux-kselftest" name="platform/external/linux-kselftest" groups="vts,pdk" clone-depth="1" />
+  <project path="external/Little-CMS" name="platform/external/Little-CMS" groups="pdk" />
   <project path="external/llvm" name="platform/external/llvm" groups="pdk" />
   <project path="external/llvm-libc" name="platform/external/llvm-libc" groups="pdk" />
   <project path="external/lottie" name="platform/external/lottie" groups="pdk" />
@@ -373,8 +369,7 @@
   <project path="external/minijail" name="platform/external/minijail" groups="pdk" />
   <project path="external/mksh" name="platform/external/mksh" groups="pdk" />
   <project path="external/ml_dtypes" name="platform/external/ml_dtypes" groups="pdk" />
-  <project path="external/python/mobly" name="platform/external/python/mobly" groups="pdk" />
-  <project path="external/private-join-and-compute" name="platform/external/private-join-and-compute" groups="pdk" />
+  <project path="external/minidns" name="platform/external/minidns" groups="pdk" />
   <project path="external/mobile-data-download" name="platform/external/mobile-data-download" groups="pdk" />
   <project path="external/mobly-bundled-snippets" name="platform/external/mobly-bundled-snippets" groups="pdk" />
   <project path="external/mobly-snippet-lib" name="platform/external/mobly-snippet-lib" groups="pdk" />
@@ -411,15 +406,17 @@
   <project path="external/okio" name="platform/external/okio" groups="pdk" />
   <project path="external/one-true-awk" name="platform/external/one-true-awk" groups="pdk" />
   <project path="external/opencensus-java" name="platform/external/opencensus-java" groups="pdk,tradefed" />
-  <project path="external/OpenCL-CLHPP" name="platform/external/OpenCL-CLHPP" />
-  <project path="external/OpenCL-CTS" name="platform/external/OpenCL-CTS" />
-  <project path="external/OpenCL-Headers" name="platform/external/OpenCL-Headers" />
-  <project path="external/OpenCL-ICD-Loader" name="platform/external/OpenCL-ICD-Loader" />
+  <project path="external/opencl/llvm-project" name="platform/external/opencl/llvm-project" groups="pdk" />
+  <project path="external/OpenCL-CLHPP" name="platform/external/OpenCL-CLHPP" groups="pdk" />
+  <project path="external/OpenCL-CTS" name="platform/external/OpenCL-CTS" groups="pdk" />
+  <project path="external/OpenCL-Headers" name="platform/external/OpenCL-Headers" groups="pdk" />
+  <project path="external/OpenCL-ICD-Loader" name="platform/external/OpenCL-ICD-Loader" groups="pdk" />
   <project path="external/OpenCSD" name="platform/external/OpenCSD" groups="pdk" />
   <project path="external/open-dice" name="platform/external/open-dice" groups="pdk" />
   <project path="external/openscreen" name="platform/external/openscreen" groups="pdk" />
   <project path="external/openthread" name="platform/external/openthread" groups="pdk" />
-  <project path="external/openwrt-prebuilts" name="platform/external/openwrt-prebuilts" groups="pdk" />
+  <project path="external/openwrt-prebuilts" name="platform/external/openwrt-prebuilts" groups="pdk" clone-depth="1" />
+  <project path="external/opus-experimental" name="platform/external/opus-experimental" groups="pdk" />
   <project path="external/ot-br-posix" name="platform/external/ot-br-posix" groups="pdk" />
   <project path="external/ow2-asm" name="platform/external/ow2-asm" groups="pdk" />
   <project path="external/owasp/java-encoder" name="platform/external/owasp/java-encoder" groups="pdk" />
@@ -436,7 +433,9 @@
   <project path="external/perfmark" name="platform/external/perfmark" groups="pdk" />
   <project path="external/piex" name="platform/external/piex" groups="pdk" />
   <project path="external/pigweed" name="platform/external/pigweed" groups="pdk" />
+  <project path="external/pixman" name="platform/external/pixman" groups="pdk" />
   <project path="external/ply" name="platform/external/ply" groups="pdk" />
+  <project path="external/private-join-and-compute" name="platform/external/private-join-and-compute" groups="pdk" />
   <project path="external/protobuf" name="platform/external/protobuf" groups="pdk,sysui-studio" />
   <project path="external/pthreadpool" name="platform/external/pthreadpool" groups="pdk" />
   <project path="external/puffin" name="platform/external/puffin" groups="pdk" />
@@ -445,6 +444,7 @@
   <project path="external/python/asn1crypto" name="platform/external/python/asn1crypto" groups="pdk" />
   <project path="external/python/bumble" name="platform/external/python/bumble" groups="pdk" />
   <project path="external/python/cachetools" name="platform/external/python/cachetools" groups="pdk" />
+  <project path="external/python/cpplint" name="platform/external/python/cpplint" groups="pdk" />
   <project path="external/python/cpython3" name="platform/external/python/cpython3" groups="pdk" />
   <project path="external/python/dateutil" name="platform/external/python/dateutil" groups="pdk" />
   <project path="external/python/enum34" name="platform/external/python/enum34" groups="vts,pdk" />
@@ -455,9 +455,11 @@
   <project path="external/python/jinja" name="platform/external/python/jinja" groups="pdk" />
   <project path="external/python/mako" name="platform/external/python/mako" groups="pdk" />
   <project path="external/python/markupsafe" name="platform/external/python/markupsafe" groups="pdk" />
+  <project path="external/python/mobly" name="platform/external/python/mobly" groups="pdk" />
   <project path="external/python/oauth2client" name="platform/external/python/oauth2client" groups="vts,pdk" />
   <project path="external/python/parse_type" name="platform/external/python/parse_type" groups="vts,pdk" />
   <project path="external/python/portpicker" name="platform/external/python/portpicker" groups="pdk" />
+  <project path="external/python/ptyprocess" name="platform/external/python/ptyprocess" groups="pdk" />
   <project path="external/python/pyasn1" name="platform/external/python/pyasn1" groups="vts,pdk" />
   <project path="external/python/pyasn1-modules" name="platform/external/python/pyasn1-modules" groups="vts,pdk" />
   <project path="external/python/pycparser" name="platform/external/python/pycparser" groups="pdk" />
@@ -474,6 +476,8 @@
   <project path="external/python/uritemplates" name="platform/external/python/uritemplates" groups="vts,pdk" />
   <project path="external/python/watchdog" name="platform/external/python/watchdog" groups="pdk" />
   <project path="external/pytorch" name="platform/external/pytorch" groups="pdk" />
+  <project path="external/qdl" name="platform/external/qdl" groups="pdk" />
+  <project path="external/qpdf" name="platform/external/qpdf" groups="pdk" />
   <project path="external/rappor" name="platform/external/rappor" groups="pdk" />
   <project path="external/regex-re2" name="platform/external/regex-re2" groups="pdk" />
   <project path="external/renderscript-intrinsics-replacement-toolkit" name="platform/external/renderscript-intrinsics-replacement-toolkit" groups="pdk,sysui-studio" />
@@ -514,6 +518,7 @@
   <project path="external/sl4a" name="platform/external/sl4a" groups="pdk" />
   <project path="external/slf4j" name="platform/external/slf4j" groups="pdk" />
   <project path="external/snakeyaml" name="platform/external/snakeyaml" groups="pdk" />
+  <project path="external/python/snippet-uiautomator" name="platform/external/python/snippet-uiautomator" groups="pdk" />
   <project path="external/sonic" name="platform/external/sonic" groups="pdk" />
   <project path="external/sonivox" name="platform/external/sonivox" groups="pdk" />
   <project path="external/speex" name="platform/external/speex" groups="pdk" />
@@ -526,6 +531,8 @@
   <project path="external/stressapptest" name="platform/external/stressapptest" groups="pdk" />
   <project path="external/subsampling-scale-image-view" name="platform/external/subsampling-scale-image-view" groups="pdk" clone-depth="1" />
   <project path="external/swiftshader" name="platform/external/swiftshader" groups="pdk" />
+  <project path="external/SPIRV-Headers" name="platform/external/SPIRV-Headers" groups="pdk" />
+  <project path="external/SPIRV-Tools" name="platform/external/SPIRV-Tools" groups="pdk" />
   <project path="external/tagsoup" name="platform/external/tagsoup" groups="pdk" />
   <project path="external/tcpdump" name="platform/external/tcpdump" groups="pdk" />
   <project path="external/tensorflow" name="platform/external/tensorflow" groups="pdk" />
@@ -710,6 +717,7 @@
   <project path="packages/apps/Dialer" name="platform/packages/apps/Dialer" groups="pdk-fs" />
   <project path="packages/apps/DocumentsUI" name="platform/packages/apps/DocumentsUI" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/apps/EmergencyInfo" name="platform/packages/apps/EmergencyInfo" groups="pdk-fs" />
+  <project path="packages/apps/EyeDropper" name="platform/packages/apps/EyeDropper" groups="pdk-fs" />
   <project path="packages/apps/Gallery" name="platform/packages/apps/Gallery" groups="pdk-fs" />
   <project path="packages/apps/Gallery2" name="platform/packages/apps/Gallery2" groups="pdk-fs" />
   <project path="packages/apps/HTMLViewer" name="platform/packages/apps/HTMLViewer" groups="pdk-fs" />
@@ -785,6 +793,7 @@
   <project path="packages/modules/Scheduling" name="platform/packages/modules/Scheduling" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/SdkExtensions" name="platform/packages/modules/SdkExtensions" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/StatsD" name="platform/packages/modules/StatsD" groups="pdk-cw-fs,pdk-fs" />
+  <project path="packages/modules/Telecom" name="platform/packages/modules/Telecom" groups="pdk-cw-fs,pdk-fs"/>
   <project path="packages/modules/Telephony" name="platform/packages/modules/Telephony" groups="pdk-cw-fs,pdk-fs"/>
   <project path="packages/modules/ThreadNetwork" name="platform/packages/modules/ThreadNetwork" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/Uwb" name="platform/packages/modules/Uwb" groups="pdk-cw-fs,pdk-fs" />
@@ -813,6 +822,7 @@
   <project path="packages/services/Iwlan" name="platform/packages/services/Iwlan" groups="pdk-cw-fs,pdk-fs"/>
   <project path="packages/services/Mms" name="platform/packages/services/Mms" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/services/Mtp" name="platform/packages/services/Mtp" groups="pdk-cw-fs,pdk-fs" />
+  <project path="packages/services/QualifiedNetworksService" name="platform/packages/services/QualifiedNetworksService" groups="pdk-cw-fs,pdk-fs"/>
   <project path="packages/services/Telecomm" name="platform/packages/services/Telecomm" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/services/Telephony" name="platform/packages/services/Telephony" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/wallpapers/LivePicker" name="platform/packages/wallpapers/LivePicker" groups="pdk-fs" />
@@ -824,8 +834,6 @@
   <project path="prebuilts/android-emulator" name="platform/prebuilts/android-emulator" groups="pdk-fs" clone-depth="1" />
   <project path="prebuilts/asuite" name="platform/prebuilts/asuite" groups="pdk" clone-depth="1" />
   <project path="prebuilts/bazel/common" name="platform/prebuilts/bazel/common" groups="pdk" clone-depth="1" />
-  <project path="prebuilts/bazel/darwin-x86_64" name="platform/prebuilts/bazel/darwin-x86_64" groups="notdefault,platform-darwin,darwin,pdk" clone-depth="1" />
-  <project path="prebuilts/bazel/linux-x86_64" name="platform/prebuilts/bazel/linux-x86_64" groups="linux,pdk" clone-depth="1" />
   <project path="prebuilts/build-tools" name="platform/prebuilts/build-tools" groups="pdk,sysui-studio" clone-depth="1" />
   <project path="prebuilts/bundletool" name="platform/prebuilts/bundletool" groups="pdk" clone-depth="1" />
   <project path="prebuilts/checkcolor" name="platform/prebuilts/checkcolor" groups="pdk,sysui-studio" clone-depth="1" />
@@ -867,6 +875,7 @@
   <project path="prebuilts/module_sdk/Scheduling" name="platform/prebuilts/module_sdk/Scheduling" groups="pdk" clone-depth="1" />
   <project path="prebuilts/module_sdk/SdkExtensions" name="platform/prebuilts/module_sdk/SdkExtensions" groups="pdk" clone-depth="1" />
   <project path="prebuilts/module_sdk/StatsD" name="platform/prebuilts/module_sdk/StatsD" groups="pdk" clone-depth="1" />
+  <project path="prebuilts/module_sdk/Telephony" name="platform/prebuilts/module_sdk/Telephony" groups="pdk" clone-depth="1"/>
   <project path="prebuilts/module_sdk/Uwb" name="platform/prebuilts/module_sdk/Uwb" groups="pdk" clone-depth="1" />
   <project path="prebuilts/module_sdk/Wifi" name="platform/prebuilts/module_sdk/Wifi" groups="pdk" clone-depth="1" />
   <project path="prebuilts/ndk" name="platform/prebuilts/ndk" groups="pdk" clone-depth="1" />
@@ -970,9 +979,9 @@
   <project path="tools/apkzlib" name="platform/tools/apkzlib" groups="pdk,tradefed" />
   <project path="tools/asuite" name="platform/tools/asuite" groups="pdk,sysui-studio" />
   <project path="tools/carrier_settings" name="platform/tools/carrier_settings" groups="tools" />
-  <project path="tools/content_addressed_storage/prebuilts" name="platform/tools/content_addressed_storage/prebuilts" groups="pdk,tools" />
+  <project path="tools/content_addressed_storage/prebuilts" name="platform/tools/content_addressed_storage/prebuilts" groups="pdk,tools" clone-depth="1" />
   <project path="tools/currysrc" name="platform/tools/currysrc" groups="pdk" />
-  <project path="tools/deviceinfra/prebuilts" name="platform/tools/deviceinfra/prebuilts" groups="pdk,tools" />
+  <project path="tools/deviceinfra/prebuilts" name="platform/tools/deviceinfra/prebuilts" groups="pdk,tools" clone-depth="1" />
   <project path="tools/dexter" name="platform/tools/dexter" groups="tools,pdk-cw-fs,pdk-fs" />
   <project path="tools/doc_generation" name="platform/tools/doc_generation" groups="tools,pdk" />
   <project path="tools/external_updater" name="platform/tools/external_updater" groups="tools" />
```

