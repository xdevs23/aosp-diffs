```diff
diff --git a/default.xml b/default.xml
index 02b220a40..c7172cbcf 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r5"
+  <default revision="refs/tags/android-15.0.0_r6"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r5"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r6"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
@@ -42,7 +42,7 @@
   <project path="developers/build" name="platform/developers/build" groups="developers,pdk" />
   <project path="developers/demos" name="platform/developers/demos" groups="developers" />
   <project path="developers/samples/android" name="platform/developers/samples/android" groups="developers" />
-  <project path="development" name="platform/development" groups="developers,pdk-cw-fs,pdk-fs" />
+  <project path="development" name="platform/development" groups="developers,pdk-cw-fs,pdk-fs,sysui-studio" />
   <project path="device/amlogic/yukawa" name="device/amlogic/yukawa" groups="device,yukawa,pdk" />
   <project path="device/amlogic/yukawa-kernel" name="device/amlogic/yukawa-kernel" groups="device,yukawa,pdk" clone-depth="2" />
   <project path="device/common" name="device/common" groups="pdk-cw-fs,pdk" />
@@ -57,18 +57,13 @@
   <project path="device/generic/mini-emulator-armv7-a-neon" name="device/generic/mini-emulator-armv7-a-neon" groups="pdk" />
   <project path="device/generic/mini-emulator-x86" name="device/generic/mini-emulator-x86" groups="pdk" />
   <project path="device/generic/mini-emulator-x86_64" name="device/generic/mini-emulator-x86_64" groups="pdk" />
-  <project path="device/generic/opengl-transport" name="device/generic/opengl-transport" groups="pdk" />
   <project path="device/generic/trusty" name="device/generic/trusty" groups="pdk" />
-  <project path="device/generic/uml" name="device/generic/uml" groups="device,pdk" />
   <project path="device/generic/x86" name="device/generic/x86" groups="pdk" />
   <project path="device/generic/x86_64" name="device/generic/x86_64" groups="pdk" />
-  <project path="device/generic/vulkan-cereal" name="device/generic/vulkan-cereal" groups="pdk" />
   <project path="device/google/akita" name="device/google/akita" groups="device,akita" />
   <project path="device/google/akita-sepolicy" name="device/google/akita-sepolicy" groups="device,akita" />
   <project path="device/google/akita-kernels/5.15" name="device/google/akita-kernels/5.15" groups="device,akita" clone-depth="1" />
   <project path="device/google/atv" name="device/google/atv" groups="device,broadcom_pdk,generic_fs,pdk" />
-  <project path="device/google/barbet" name="device/google/barbet" groups="device,barbet" />
-  <project path="device/google/barbet-sepolicy" name="device/google/barbet-sepolicy" groups="device,barbet" />
   <project path="device/google/bluejay" name="device/google/bluejay" groups="device,bluejay" />
   <project path="device/google/bluejay-sepolicy" name="device/google/bluejay-sepolicy" groups="device,bluejay" />
   <project path="device/google/bluejay-kernels/5.10" name="device/google/bluejay-kernels/5.10" groups="device,bluejay" clone-depth="1" />
@@ -80,17 +75,14 @@
   <project path="device/google/comet-kernels/6.1" name="device/google/comet-kernels/6.1" groups="device,comet" clone-depth="1" />
   <project path="device/google/comet-sepolicy" name="device/google/comet-sepolicy" groups="device,comet" />
   <project path="device/google/common/etm" name="device/google/common/etm" groups="device" clone-depth="1" />
-  <project path="device/google/coral" name="device/google/coral" groups="device,coral,generic_fs" />
-  <project path="device/google/coral-kernel" name="device/google/coral-kernel" groups="device,coral,generic_fs" clone-depth="1" />
-  <project path="device/google/coral-sepolicy" name="device/google/coral-sepolicy" groups="device,coral,generic_fs" />
   <project path="device/google/felix" name="device/google/felix" groups="device,felix" />
   <project path="device/google/felix-sepolicy" name="device/google/felix-sepolicy" groups="device,felix" />
   <project path="device/google/felix-kernels/5.10" name="device/google/felix-kernels/5.10" groups="device,felix" clone-depth="1" />
-  <project path="device/google/gs101" name="device/google/gs101" groups="device,slider,bluejay,blueport,pdk-gs-arm" />
-  <project path="device/google/gs101-sepolicy" name="device/google/gs101-sepolicy" groups="device,slider,bluejay,blueport,pdk-gs-arm" />
+  <project path="device/google/gs101" name="device/google/gs101" groups="device,slider,bluejay,pdk-gs-arm" />
+  <project path="device/google/gs101-sepolicy" name="device/google/gs101-sepolicy" groups="device,slider,bluejay,pdk-gs-arm" />
   <project path="device/google/gs201" name="device/google/gs201" groups="device,cloudripper,pdk-gs-arm" />
   <project path="device/google/gs201-sepolicy" name="device/google/gs201-sepolicy" groups="device,cloudripper,pdk-gs-arm" />
-  <project path="device/google/gs-common" name="device/google/gs-common" groups="device,slider,bluejay,blueport,cloudripper,pdk-gs-arm,pdk-cw-tvc" />
+  <project path="device/google/gs-common" name="device/google/gs-common" groups="device,slider,bluejay,cloudripper,pdk-gs-arm,pdk-cw-tvc" />
   <project path="device/google/lynx" name="device/google/lynx" groups="device,lynx" />
   <project path="device/google/lynx-sepolicy" name="device/google/lynx-sepolicy" groups="device,lynx" />
   <project path="device/google/lynx-kernels/5.10" name="device/google/lynx-kernels/5.10" groups="device,lynx" clone-depth="1" />
@@ -99,25 +91,16 @@
   <project path="device/google/pantah-kernels/5.10" name="device/google/pantah-kernels/5.10" groups="device,cloudripper,pdk-gs-arm" clone-depth="1" />
   <project path="device/google/raviole" name="device/google/raviole" groups="device,slider,pdk-gs-arm" />
   <project path="device/google/raviole-kernels/5.10" name="device/google/raviole-kernels/5.10" groups="device,slider,pdk-gs-arm" clone-depth="1" />
-  <project path="device/google/redbull" name="device/google/redbull" groups="device,redbull" />
-  <project path="device/google/redbull-kernel" name="device/google/redbull-kernel" groups="device,bramble,redfin" clone-depth="1" />
-  <project path="device/google/redbull-sepolicy" name="device/google/redbull-sepolicy" groups="device,redbull" />
-  <project path="device/google/redfin" name="device/google/redfin" groups="device,redfin" />
-  <project path="device/google/redfin-sepolicy" name="device/google/redfin-sepolicy" groups="device,redfin" />
   <project path="device/google/tangorpro" name="device/google/tangorpro" groups="device,tangorpro" />
   <project path="device/google/tangorpro-sepolicy" name="device/google/tangorpro-sepolicy" groups="device,tangorpro" />
   <project path="device/google/tangorpro-kernels/5.10" name="device/google/tangorpro-kernels/5.10" groups="device,tangorpro" clone-depth="1" />
   <project path="device/google/shusky" name="device/google/shusky" groups="device,ripcurrent,pdk-gs-arm" />
   <project path="device/google/shusky-kernels/5.15" name="device/google/shusky-kernels/5.15" groups="device,ripcurrent,pdk-gs-arm" clone-depth="1" />
   <project path="device/google/shusky-sepolicy" name="device/google/shusky-sepolicy" groups="device,ripcurrent,pdk-gs-arm" />
-  <project path="device/google/sunfish" name="device/google/sunfish" groups="device,sunfish" />
-  <project path="device/google/sunfish-kernel" name="device/google/sunfish-kernel" groups="device,sunfish" clone-depth="1" />
-  <project path="device/google/sunfish-sepolicy" name="device/google/sunfish-sepolicy" groups="device,sunfish" />
   <project path="device/google/cuttlefish" name="device/google/cuttlefish" groups="device,pdk" />
   <project path="device/google/cuttlefish_prebuilts" name="device/google/cuttlefish_prebuilts" groups="device,pdk" clone-depth="1" />
   <project path="device/google/cuttlefish_vmm" name="device/google/cuttlefish_vmm" groups="device,pdk" clone-depth="1" />
-  <project path="device/google/trout" name="device/google/trout" groups="device,trout,gull,pdk" />
-  <project path="device/google/vrservices" name="device/google/vrservices" groups="pdk" />
+  <project path="device/google/trout" name="device/google/trout" groups="device,pdk" clone-depth="1"/>
   <project path="device/google/zuma" name="device/google/zuma" groups="device,ripcurrent,pdk-gs-arm" />
   <project path="device/google/zuma-sepolicy" name="device/google/zuma-sepolicy" groups="device,ripcurrent,pdk-gs-arm" />
   <project path="device/google/zumapro" name="device/google/zumapro" groups="device,ripcurrentpro" />
@@ -190,11 +173,13 @@
   <project path="external/chromium-webview" name="platform/external/chromium-webview" groups="pdk" clone-depth="1" />
   <project path="external/clang" name="platform/external/clang" groups="pdk" />
   <project path="external/cldr" name="platform/external/cldr" groups="pdk" />
+  <project path="external/clpeak" name="platform/external/clpeak" />
   <project path="external/cn-cbor" name="platform/external/cn-cbor" groups="pdk" />
   <project path="external/compiler-rt" name="platform/external/compiler-rt" groups="pdk" />
   <project path="external/ComputeLibrary" name="platform/external/ComputeLibrary" groups="pdk-lassen,pdk-gs-arm" />
   <project path="external/connectedappssdk" name="platform/external/connectedappssdk" groups="pdk" />
   <project path="external/conscrypt" name="platform/external/conscrypt" groups="pdk" />
+  <project path="external/coreboot" name="platform/external/coreboot" groups="pdk"/>
   <project path="external/cpu_features" name="platform/external/cpu_features" groups="pdk" />
   <project path="external/cpuinfo" name="platform/external/cpuinfo" groups="pdk" />
   <project path="external/crcalc" name="platform/external/crcalc" groups="pdk" />
@@ -207,7 +192,6 @@
   <project path="external/deqp-deps/SPIRV-Tools" name="platform/external/deqp-deps/SPIRV-Tools" groups="pdk-fs" />
   <project path="external/deqp-deps/glslang" name="platform/external/deqp-deps/glslang" groups="pdk-fs" />
   <project path="external/deqp-deps/amber" name="platform/external/deqp-deps/amber" groups="pdk-fs" />
-  <project path="external/desugar" name="platform/external/desugar" groups="pdk" />
   <project path="external/dexmaker" name="platform/external/dexmaker" groups="pdk" />
   <project path="external/dlmalloc" name="platform/external/dlmalloc" groups="pdk" />
   <project path="external/dng_sdk" name="platform/external/dng_sdk" groups="pdk" />
@@ -221,8 +205,10 @@
   <project path="external/dynamic_depth" name="platform/external/dynamic_depth" groups="pdk" />
   <project path="external/e2fsprogs" name="platform/external/e2fsprogs" groups="pdk" />
   <project path="external/easymock" name="platform/external/easymock" groups="pdk" />
+  <project path="external/edid-decode" name="platform/external/edid-decode" groups="pdk" />
   <project path="external/eigen" name="platform/external/eigen" groups="pdk" />
   <project path="external/elfutils" name="platform/external/elfutils" groups="pdk" />
+  <project path="external/emboss" name="platform/external/emboss" groups="pdk" />
   <project path="external/emma" name="platform/external/emma" groups="pdk" />
   <project path="external/erofs-utils" name="platform/external/erofs-utils" groups="pdk" />
   <project path="external/error_prone" name="platform/external/error_prone" groups="pdk" />
@@ -239,6 +225,7 @@
   <project path="external/fft2d" name="platform/external/fft2d" groups="pdk" />
   <project path="external/firebase-messaging" name="platform/external/firebase-messaging" groups="pdk"/>
   <project path="external/flac" name="platform/external/flac" groups="pdk" />
+  <project path="external/flashrom" name="platform/external/flashrom" groups="pdk" />
   <project path="external/flatbuffers" name="platform/external/flatbuffers" groups="pdk" />
   <project path="external/fonttools" name="platform/external/fonttools" groups="pdk" />
   <project path="external/fmtlib" name="platform/external/fmtlib" groups="pdk" />
@@ -253,6 +240,7 @@
   <project path="external/gflags" name="platform/external/gflags" groups="pdk" />
   <project path="external/giflib" name="platform/external/giflib" groups="pdk,qcom_msm8x26" />
   <project path="external/glide" name="platform/external/glide" groups="pdk" />
+  <project path="external/gmmlib" name="platform/external/gmmlib" groups="pdk" />
   <project path="external/go-cmp" name="platform/external/go-cmp" groups="pdk" />
   <project path="external/golang-protobuf" name="platform/external/golang-protobuf" groups="pdk" />
   <project path="external/googleapis" name="platform/external/googleapis" groups="pdk,tradefed" />
@@ -283,19 +271,22 @@
   <project path="external/gptfdisk" name="platform/external/gptfdisk" groups="pdk" />
   <project path="external/grpc-grpc" name="platform/external/grpc-grpc" groups="pdk,tradefed" />
   <project path="external/grpc-grpc-java" name="platform/external/grpc-grpc-java" groups="pdk,tradefed" />
+  <project path="external/gsc-utils" name="platform/external/gsc-utils" groups="pdk" />
   <project path="external/gson" name="platform/external/gson" groups="pdk,tradefed" />
+  <project path="external/gturri-aXMLRPC" name="platform/external/gturri-aXMLRPC" groups="pdk-desktop" />
+  <project path="external/gturri-jISO8601" name="platform/external/gturri-jISO8601" groups="pdk-desktop" />
   <project path="external/guava" name="platform/external/guava" groups="pdk" />
   <project path="external/guice" name="platform/external/guice" groups="pdk" />
   <project path="external/gwp_asan" name="platform/external/gwp_asan" groups="pdk" />
   <project path="external/hamcrest" name="platform/external/hamcrest" groups="pdk" />
   <project path="external/harfbuzz_ng" name="platform/external/harfbuzz_ng" groups="pdk,qcom_msm8x26" />
-  <project path="external/horologist" name="platform/external/horologist" groups="pdk" />
   <project path="external/hyphenation-patterns" name="platform/external/hyphenation-patterns" groups="pdk" />
   <project path="external/icing" name="platform/external/icing" groups="pdk" />
   <project path="external/icu" name="platform/external/icu" groups="pdk" />
   <project path="external/igt-gpu-tools" name="platform/external/igt-gpu-tools" groups="pdk" />
   <project path="external/image_io" name="platform/external/image_io" groups="pdk" />
   <project path="external/ims" name="platform/external/ims" groups="pdk" />
+  <project path="external/intel-media-driver" name="platform/external/intel-media-driver" groups="pdk" />
   <project path="external/iperf3" name="platform/external/iperf3" groups="pdk" />
   <project path="external/iproute2" name="platform/external/iproute2" groups="pdk" />
   <project path="external/ipsec-tools" name="platform/external/ipsec-tools" groups="pdk" />
@@ -388,6 +379,7 @@
   <project path="external/liburing" name="platform/external/liburing" groups="pdk" />
   <project path="external/libusb" name="platform/external/libusb" groups="pdk" />
   <project path="external/libutf" name="platform/external/libutf" groups="pdk" />
+  <project path="external/libva" name="platform/external/libva" groups="pdk" />
   <project path="external/libvpx" name="platform/external/libvpx" groups="pdk" />
   <project path="external/libwebm" name="platform/external/libwebm" groups="pdk" />
   <project path="external/libwebsockets" name="platform/external/libwebsockets" groups="pdk" />
@@ -423,11 +415,11 @@
   <project path="external/mockito-kotlin" name="platform/external/mockito-kotlin" groups="pdk" />
   <project path="external/mockwebserver" name="platform/external/mockwebserver" groups="pdk" />
   <project path="external/modp_b64" name="platform/external/modp_b64" groups="pdk" />
+  <project path="external/moshi" name="platform/external/moshi" groups="pdk" />
   <project path="external/mp4parser" name="platform/external/mp4parser" groups="pdk" />
   <project path="external/MPAndroidChart" name="platform/external/MPAndroidChart" groups="pdk" />
   <project path="external/ms-tpm-20-ref" name="platform/external/ms-tpm-20-ref" groups="pdk" />
   <project path="external/mtools" name="platform/external/mtools" groups="pdk" />
-  <project path="external/mtpd" name="platform/external/mtpd" groups="pdk" />
   <project path="external/musl" name="platform/external/musl" groups="pdk" />
   <project path="external/nanohttpd" name="platform/external/nanohttpd" groups="pdk" />
   <project path="external/nanopb-c" name="platform/external/nanopb-c" groups="pdk" />
@@ -453,12 +445,12 @@
   <project path="external/OpenCL-CLHPP" name="platform/external/OpenCL-CLHPP" />
   <project path="external/OpenCL-CTS" name="platform/external/OpenCL-CTS" />
   <project path="external/OpenCL-Headers" name="platform/external/OpenCL-Headers" />
+  <project path="external/OpenCL-ICD-Loader" name="platform/external/OpenCL-ICD-Loader" />
   <project path="external/OpenCSD" name="platform/external/OpenCSD" groups="pdk" />
   <project path="external/open-dice" name="platform/external/open-dice" groups="pdk" />
   <project path="external/openscreen" name="platform/external/openscreen" groups="pdk" />
   <project path="external/openthread" name="platform/external/openthread" groups="pdk" />
   <project path="external/openwrt-prebuilts" name="platform/external/openwrt-prebuilts" groups="pdk" />
-  <project path="external/oss-fuzz" name="platform/external/oss-fuzz" groups="pdk" />
   <project path="external/ot-br-posix" name="platform/external/ot-br-posix" groups="pdk" />
   <project path="external/ow2-asm" name="platform/external/ow2-asm" groups="pdk" />
   <project path="external/owasp/java-encoder" name="platform/external/owasp/java-encoder" groups="pdk" />
@@ -469,15 +461,14 @@
   <project path="external/pandora/mmi2grpc" name="platform/external/pandora/mmi2grpc" groups="pdk" />
   <project path="external/parameter-framework" name="platform/external/parameter-framework" groups="pdk" />
   <project path="external/pcre" name="platform/external/pcre" groups="pdk" />
+  <project path="external/pciutils" name="platform/external/pciutils" groups="pdk" />
   <project path="external/pdfium" name="platform/external/pdfium" groups="pdk" />
   <project path="external/perfetto" name="platform/external/perfetto" groups="pdk,sysui-studio" />
   <project path="external/perfmark" name="platform/external/perfmark" groups="pdk" />
   <project path="external/piex" name="platform/external/piex" groups="pdk" />
   <project path="external/pigweed" name="platform/external/pigweed" groups="pdk" />
   <project path="external/ply" name="platform/external/ply" groups="pdk" />
-  <project path="external/ppp" name="platform/external/ppp" groups="pdk" />
   <project path="external/protobuf" name="platform/external/protobuf" groups="pdk,sysui-studio" />
-  <project path="external/psimd" name="platform/external/psimd" groups="pdk" />
   <project path="external/pthreadpool" name="platform/external/pthreadpool" groups="pdk" />
   <project path="external/puffin" name="platform/external/puffin" groups="pdk" />
   <project path="external/python/absl-py" name="platform/external/python/absl-py" groups="pdk" />
@@ -512,6 +503,7 @@
   <project path="external/python/six" name="platform/external/python/six" groups="vts,pdk" />
   <project path="external/python/timeout-decorator" name="platform/external/python/timeout-decorator" groups="pdk" />
   <project path="external/python/typing" name="platform/external/python/typing" groups="pdk" />
+  <project path="external/python/typing_extensions" name="platform/external/python/typing_extensions" groups="pdk" />
   <project path="external/python/uritemplates" name="platform/external/python/uritemplates" groups="vts,pdk" />
   <project path="external/rappor" name="platform/external/rappor" groups="pdk" />
   <project path="external/regex-re2" name="platform/external/regex-re2" groups="pdk" />
@@ -524,6 +516,7 @@
   <project path="external/rootdev" name="platform/external/rootdev" groups="pdk" />
   <project path="external/rnnoise" name="platform/external/rnnoise" groups="pdk" />
   <project path="external/rust/android-crates-io" name="platform/external/rust/android-crates-io" groups="pdk" />
+  <project path="external/rust/crabbyavif" name="platform/external/rust/crabbyavif" groups="pdk" />
   <project path="external/rust/crates/aarch64-paging" name="platform/external/rust/crates/aarch64-paging" groups="pdk" />
   <project path="external/rust/crates/acpi" name="platform/external/rust/crates/acpi" groups="pdk" />
   <project path="external/rust/crates/ahash" name="platform/external/rust/crates/ahash" groups="pdk" />
@@ -583,6 +576,7 @@
   <project path="external/rust/crates/configparser" name="platform/external/rust/crates/configparser" groups="pdk" />
   <project path="external/rust/crates/const-oid" name="platform/external/rust/crates/const-oid" groups="pdk" />
   <project path="external/rust/crates/coset" name="platform/external/rust/crates/coset" groups="pdk" />
+  <project path="external/rust/crates/cov-mark" name="platform/external/rust/crates/cov-mark" groups="pdk" />
   <project path="external/rust/crates/crc32fast" name="platform/external/rust/crates/crc32fast" groups="pdk" />
   <project path="external/rust/crates/criterion" name="platform/external/rust/crates/criterion" groups="pdk" />
   <project path="external/rust/crates/criterion-plot" name="platform/external/rust/crates/criterion-plot" groups="pdk" />
@@ -613,10 +607,12 @@
   <project path="external/rust/crates/enumn" name="platform/external/rust/crates/enumn" groups="pdk" />
   <project path="external/rust/crates/env_logger" name="platform/external/rust/crates/env_logger" groups="pdk" />
   <project path="external/rust/crates/epoll" name="platform/external/rust/crates/epoll" groups="pdk" />
+  <project path="external/rust/crates/equivalent" name="platform/external/rust/crates/equivalent" groups="pdk" />
   <project path="external/rust/crates/errno" name="platform/external/rust/crates/errno" groups="pdk" />
   <project path="external/rust/crates/fallible-iterator" name="platform/external/rust/crates/fallible-iterator" groups="pdk" />
   <project path="external/rust/crates/fallible-streaming-iterator" name="platform/external/rust/crates/fallible-streaming-iterator" groups="pdk" />
   <project path="external/rust/crates/fastrand" name="platform/external/rust/crates/fastrand" groups="pdk" />
+  <project path="external/rust/crates/fixedbitset" name="platform/external/rust/crates/fixedbitset" groups="pdk" />
   <project path="external/rust/crates/flagset" name="platform/external/rust/crates/flagset" groups="pdk" />
   <project path="external/rust/crates/flate2" name="platform/external/rust/crates/flate2" groups="pdk" />
   <project path="external/rust/crates/fnv" name="platform/external/rust/crates/fnv" groups="pdk" />
@@ -654,6 +650,7 @@
   <project path="external/rust/crates/hashlink" name="platform/external/rust/crates/hashlink" groups="pdk" />
   <project path="external/rust/crates/heck" name="platform/external/rust/crates/heck" groups="pdk" />
   <project path="external/rust/crates/hex" name="platform/external/rust/crates/hex" groups="pdk" />
+  <project path="external/rust/crates/hound" name="platform/external/rust/crates/hound" groups="pdk" />
   <project path="external/rust/crates/http" name="platform/external/rust/crates/http" groups="pdk" />
   <project path="external/rust/crates/http-body" name="platform/external/rust/crates/http-body" groups="pdk" />
   <project path="external/rust/crates/httparse" name="platform/external/rust/crates/httparse" groups="pdk" />
@@ -672,6 +669,8 @@
   <project path="external/rust/crates/kernlog" name="platform/external/rust/crates/kernlog" groups="pdk" />
   <project path="external/rust/crates/lazy_static" name="platform/external/rust/crates/lazy_static" groups="pdk" />
   <project path="external/rust/crates/lazycell" name="platform/external/rust/crates/lazycell" groups="pdk" />
+  <project path="external/rust/crates/libbpf-rs" name="platform/external/rust/crates/libbpf-rs" groups="pdk" />
+  <project path="external/rust/crates/libbpf-sys" name="platform/external/rust/crates/libbpf-sys" groups="pdk" />
   <project path="external/rust/crates/libc" name="platform/external/rust/crates/libc" groups="pdk" />
   <project path="external/rust/crates/libfuzzer-sys" name="platform/external/rust/crates/libfuzzer-sys" groups="pdk" />
   <project path="external/rust/crates/libloading" name="platform/external/rust/crates/libloading" groups="pdk" />
@@ -721,6 +720,8 @@
   <project path="external/rust/crates/num-integer" name="platform/external/rust/crates/num-integer" groups="pdk" />
   <project path="external/rust/crates/num-traits" name="platform/external/rust/crates/num-traits" groups="pdk" />
   <project path="external/rust/crates/num_cpus" name="platform/external/rust/crates/num_cpus" groups="pdk" />
+  <project path="external/rust/crates/num_enum" name="platform/external/rust/crates/num_enum" groups="pdk" />
+  <project path="external/rust/crates/num_enum_derive" name="platform/external/rust/crates/num_enum_derive" groups="pdk" />
   <project path="external/rust/crates/octets" name="platform/external/rust/crates/octets" groups="pdk" />
   <project path="external/rust/crates/once_cell" name="platform/external/rust/crates/once_cell" groups="pdk" />
   <project path="external/rust/crates/oneshot-uniffi" name="platform/external/rust/crates/oneshot-uniffi" groups="pdk" />
@@ -736,12 +737,13 @@
   <project path="external/rust/crates/pathdiff" name="platform/external/rust/crates/pathdiff" groups="pdk" />
   <project path="external/rust/crates/pdl-compiler" name="platform/external/rust/crates/pdl-compiler" groups="pdk" />
   <project path="external/rust/crates/pdl-runtime" name="platform/external/rust/crates/pdl-runtime" groups="pdk" />
-  <project path="external/rust/crates/peeking_take_while" name="platform/external/rust/crates/peeking_take_while" groups="pdk" />
   <project path="external/rust/crates/percent-encoding" name="platform/external/rust/crates/percent-encoding" groups="pdk" />
+  <project path="external/rust/crates/percore" name="platform/external/rust/crates/percore" groups="pdk" />
   <project path="external/rust/crates/pest" name="platform/external/rust/crates/pest" groups="pdk" />
   <project path="external/rust/crates/pest_derive" name="platform/external/rust/crates/pest_derive" groups="pdk" />
   <project path="external/rust/crates/pest_generator" name="platform/external/rust/crates/pest_generator" groups="pdk" />
   <project path="external/rust/crates/pest_meta" name="platform/external/rust/crates/pest_meta" groups="pdk" />
+  <project path="external/rust/crates/petgraph" name="platform/external/rust/crates/petgraph" groups="pdk" />
   <project path="external/rust/crates/pin-project" name="platform/external/rust/crates/pin-project" groups="pdk" />
   <project path="external/rust/crates/pin-project-internal" name="platform/external/rust/crates/pin-project-internal" groups="pdk" />
   <project path="external/rust/crates/pin-project-lite" name="platform/external/rust/crates/pin-project-lite" groups="pdk" />
@@ -782,6 +784,7 @@
   <project path="external/rust/crates/rustc-demangle-capi" name="platform/external/rust/crates/rustc-demangle-capi" groups="pdk" />
   <project path="external/rust/crates/rustc-hash" name="platform/external/rust/crates/rustc-hash" groups="pdk" />
   <project path="external/rust/crates/rustix" name="platform/external/rust/crates/rustix" groups="pdk" />
+  <project path="external/rust/crates/rust-stemmers" name="platform/external/rust/crates/rust-stemmers" groups="pdk" />
   <project path="external/rust/crates/rustversion" name="platform/external/rust/crates/rustversion" groups="pdk" />
   <project path="external/rust/crates/ryu" name="platform/external/rust/crates/ryu" groups="pdk" />
   <project path="external/rust/crates/same-file" name="platform/external/rust/crates/same-file" groups="pdk" />
@@ -870,6 +873,7 @@
   <project path="external/rust/crates/uuid" name="platform/external/rust/crates/uuid" groups="pdk" />
   <project path="external/rust/crates/vhost" name="platform/external/rust/crates/vhost" groups="pdk" />
   <project path="external/rust/crates/vhost-device-vsock" name="platform/external/rust/crates/vhost-device-vsock" groups="pdk" />
+  <project path="external/rust/crates/vsprintf" name="platform/external/rust/crates/vsprintf" groups="pdk" />
   <project path="external/rust/crates/vhost-user-backend" name="platform/external/rust/crates/vhost-user-backend" groups="pdk" />
   <project path="external/rust/crates/virtio-bindings" name="platform/external/rust/crates/virtio-bindings" groups="pdk" />
   <project path="external/rust/crates/virtio-drivers" name="platform/external/rust/crates/virtio-drivers" groups="pdk" />
@@ -959,7 +963,7 @@
   <project path="external/universal-tween-engine" name="platform/external/universal-tween-engine" />
   <project path="external/uwb" name="platform/external/uwb" groups="pdk" />
   <project path="external/v4l2_codec2" name="platform/external/v4l2_codec2" groups="pdk" />
-  <project path="external/vboot_reference" name="platform/external/vboot_reference" groups="vboot,pdk-fs" />
+  <project path="external/vboot_reference" name="platform/external/vboot_reference" groups="pdk" />
   <project path="external/virglrenderer" name="platform/external/virglrenderer" groups="pdk" />
   <project path="external/vixl" name="platform/external/vixl" groups="pdk" />
   <project path="external/vogar" name="platform/external/vogar" groups="pdk" />
@@ -1009,7 +1013,6 @@
   <project path="frameworks/opt/chips" name="platform/frameworks/opt/chips" groups="pdk-cw-fs,pdk-fs" />
   <project path="frameworks/opt/colorpicker" name="platform/frameworks/opt/colorpicker" groups="pdk-cw-fs,pdk-fs" />
   <project path="frameworks/opt/localepicker" name="platform/frameworks/opt/localepicker" />
-  <project path="frameworks/opt/net/ethernet" name="platform/frameworks/opt/net/ethernet" groups="pdk-fs" />
   <project path="frameworks/opt/net/ims" name="platform/frameworks/opt/net/ims" groups="frameworks_ims,pdk-cw-fs,pdk-fs" />
   <project path="frameworks/opt/net/voip" name="platform/frameworks/opt/net/voip" groups="pdk-cw-fs,pdk-fs" />
   <project path="frameworks/opt/net/wifi" name="platform/frameworks/opt/net/wifi" groups="pdk,sysui-studio" />
@@ -1028,7 +1031,6 @@
   <project path="hardware/google/apf" name="platform/hardware/google/apf" groups="pdk" />
   <project path="hardware/google/av" name="platform/hardware/google/av" groups="pdk" />
   <project path="hardware/google/camera" name="platform/hardware/google/camera" groups="pdk" />
-  <project path="hardware/google/easel" name="platform/hardware/google/easel" groups="pdk,easel" />
   <project path="hardware/google/gchips" name="platform/hardware/google/gchips" groups="pdk-lassen,pdk-gs-arm" />
   <project path="hardware/google/gfxstream" name="platform/hardware/google/gfxstream" groups="pdk" />
   <project path="hardware/google/graphics/common" name="platform/hardware/google/graphics/common" groups="pdk-lassen,pdk-gs-arm" />
@@ -1039,10 +1041,8 @@
   <project path="hardware/google/interfaces" name="platform/hardware/google/interfaces" groups="pdk,sysui-studio" />
   <project path="hardware/google/pixel" name="platform/hardware/google/pixel" groups="generic_fs,pixel,pdk-gs-arm" />
   <project path="hardware/google/pixel-sepolicy" name="platform/hardware/google/pixel-sepolicy" groups="generic_fs,pixel" />
-  <project path="hardware/google/trusty" name="platform/hardware/google/trusty" groups="pdk" />
   <project path="hardware/interfaces" name="platform/hardware/interfaces" groups="pdk,sysui-studio" />
   <project path="hardware/invensense" name="platform/hardware/invensense" groups="invensense,pdk" />
-  <project path="hardware/knowles/athletico/sound_trigger_hal" name="platform/hardware/knowles/athletico/sound_trigger_hal" groups="coral,generic_fs" />
   <project path="hardware/libhardware" name="platform/hardware/libhardware" groups="pdk" />
   <project path="hardware/libhardware_legacy" name="platform/hardware/libhardware_legacy" groups="pdk" />
   <project path="hardware/nxp/keymint" name="platform/hardware/nxp/keymint" groups="pdk" />
@@ -1050,39 +1050,6 @@
   <project path="hardware/nxp/uwb" name="platform/hardware/nxp/uwb" />
   <project path="hardware/nxp/secure_element" name="platform/hardware/nxp/secure_element" groups="pdk" />
   <project path="hardware/nxp/weaver" name="platform/hardware/nxp/weaver" groups="pdk" />
-  <project path="hardware/qcom/audio" name="platform/hardware/qcom/audio" groups="qcom,qcom_audio,pdk-qcom" />
-  <project path="hardware/qcom/bootctrl" name="platform/hardware/qcom/bootctrl" groups="pdk-qcom" />
-  <project path="hardware/qcom/bt" name="platform/hardware/qcom/bt" groups="qcom,pdk-qcom" />
-  <project path="hardware/qcom/camera" name="platform/hardware/qcom/camera" groups="qcom_camera,pdk-qcom" />
-  <project path="hardware/qcom/data/ipacfg-mgr" name="platform/hardware/qcom/data/ipacfg-mgr" groups="qcom,pdk-qcom" />
-  <project path="hardware/qcom/display" name="platform/hardware/qcom/display" groups="pdk-qcom,qcom,qcom_display" />
-  <project path="hardware/qcom/gps" name="platform/hardware/qcom/gps" groups="qcom,qcom_gps,pdk-qcom" />
-  <project path="hardware/qcom/keymaster" name="platform/hardware/qcom/keymaster" groups="qcom,qcom_keymaster,pdk-qcom" />
-  <project path="hardware/qcom/media" name="platform/hardware/qcom/media" groups="qcom,pdk-qcom" />
-  <project path="hardware/qcom/power" name="platform/hardware/qcom/power" groups="qcom,pdk-qcom" />
-  <project path="hardware/qcom/sm7150/gps" name="platform/hardware/qcom/sm7150/gps" groups="qcom_sm7150" >
-    <linkfile src="os_pickup.mk" dest="hardware/qcom/sm7150/Android.mk" />
-    <linkfile src="os_pickup.bp" dest="hardware/qcom/sm7150/Android.bp" />
-  </project>
-  <project path="hardware/qcom/sm7250/display" name="platform/hardware/qcom/sm7250/display" groups="qcom_sm7250" />
-  <project path="hardware/qcom/sm7250/gps" name="platform/hardware/qcom/sm7250/gps" groups="qcom_sm7250" >
-    <linkfile src="os_pickup.mk" dest="hardware/qcom/sm7250/Android.mk" />
-    <linkfile src="os_pickup.bp" dest="hardware/qcom/sm7250/Android.bp" />
-  </project>
-  <project path="hardware/qcom/sm7250/media" name="platform/hardware/qcom/sm7250/media" groups="qcom_sm7250" />
-  <project path="hardware/qcom/sm8150/data/ipacfg-mgr" name="platform/hardware/qcom/sm8150/data/ipacfg-mgr" groups="qcom_sm8150" >
-    <linkfile src="os_pickup.mk" dest="hardware/qcom/sm8150/Android.mk" />
-    <linkfile src="os_pickup.bp" dest="hardware/qcom/sm8150/Android.bp" />
-  </project>
-  <project path="hardware/qcom/sm8150/display" name="platform/hardware/qcom/sm8150/display" groups="qcom_sm8150" />
-  <project path="hardware/qcom/sm8150/gps" name="platform/hardware/qcom/sm8150/gps" groups="qcom_sm8150" />
-  <project path="hardware/qcom/sm8150/media" name="platform/hardware/qcom/sm8150/media" groups="qcom_sm8150" />
-  <project path="hardware/qcom/sm8150/thermal" name="platform/hardware/qcom/sm8150/thermal" groups="qcom_sm8150" />
-  <project path="hardware/qcom/sm8150/vr" name="platform/hardware/qcom/sm8150/vr" groups="qcom_sm8150" />
-  <project path="hardware/qcom/sm8150p/gps" name="platform/hardware/qcom/sm8150p/gps" groups="qcom_sm8150p" >
-    <linkfile src="os_pickup.mk" dest="hardware/qcom/sm8150p/Android.mk" />
-    <linkfile src="os_pickup.bp" dest="hardware/qcom/sm8150p/Android.bp" />
-  </project>
   <project path="hardware/qcom/wlan" name="platform/hardware/qcom/wlan" groups="qcom_wlan,pdk-qcom" />
   <project path="hardware/ril" name="platform/hardware/ril" groups="pdk" />
   <project path="hardware/st/nfc" name="platform/hardware/st/nfc" groups="pdk" />
@@ -1092,27 +1059,12 @@
   <project path="hardware/synaptics/wlan" name="platform/hardware/synaptics/wlan" groups="pdk" />
   <project path="hardware/ti/am57x" name="platform/hardware/ti/am57x" groups="pdk" />
   <project path="kernel/configs" name="kernel/configs" groups="vts,pdk" />
-  <project path="kernel/prebuilts/4.19/arm64" name="kernel/prebuilts/4.19/arm64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/5.4/arm64" name="kernel/prebuilts/5.4/arm64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/5.4/x86_64" name="kernel/prebuilts/5.4/x86-64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/5.10/arm64" name="kernel/prebuilts/5.10/arm64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/5.10/x86_64" name="kernel/prebuilts/5.10/x86-64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/5.15/arm64" name="kernel/prebuilts/5.15/arm64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/5.15/x86_64" name="kernel/prebuilts/5.15/x86-64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/6.1/arm64" name="kernel/prebuilts/6.1/arm64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/6.1/x86_64" name="kernel/prebuilts/6.1/x86-64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/6.6/arm64" name="kernel/prebuilts/6.6/arm64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/6.6/x86_64" name="kernel/prebuilts/6.6/x86-64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/mainline/arm64" name="kernel/prebuilts/mainline/arm64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/mainline/x86_64" name="kernel/prebuilts/mainline/x86-64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/common-modules/virtual-device/4.19/arm64" name="kernel/prebuilts/common-modules/virtual-device/4.19/arm64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/common-modules/virtual-device/4.19/x86-64" name="kernel/prebuilts/common-modules/virtual-device/4.19/x86-64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/common-modules/virtual-device/5.4/arm64" name="kernel/prebuilts/common-modules/virtual-device/5.4/arm64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/common-modules/virtual-device/5.4/x86-64" name="kernel/prebuilts/common-modules/virtual-device/5.4/x86-64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/common-modules/virtual-device/5.10/arm64" name="kernel/prebuilts/common-modules/virtual-device/5.10/arm64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/common-modules/virtual-device/5.10/x86-64" name="kernel/prebuilts/common-modules/virtual-device/5.10/x86-64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/common-modules/virtual-device/5.15/arm64" name="kernel/prebuilts/common-modules/virtual-device/5.15/arm64" groups="pdk" clone-depth="1" />
-  <project path="kernel/prebuilts/common-modules/virtual-device/5.15/x86-64" name="kernel/prebuilts/common-modules/virtual-device/5.15/x86-64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/common-modules/virtual-device/6.1/arm64" name="kernel/prebuilts/common-modules/virtual-device/6.1/arm64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/common-modules/virtual-device/6.1/x86-64" name="kernel/prebuilts/common-modules/virtual-device/6.1/x86-64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/common-modules/virtual-device/6.6/arm64" name="kernel/prebuilts/common-modules/virtual-device/6.6/arm64" groups="pdk" clone-depth="1" />
@@ -1145,7 +1097,7 @@
   <project path="packages/apps/Car/RotaryController" name="platform/packages/apps/Car/RotaryController" groups="pdk-fs" />
   <project path="packages/apps/Car/Settings" name="platform/packages/apps/Car/Settings" groups="pdk-fs" />
   <project path="packages/apps/Car/SettingsIntelligence" name="platform/packages/apps/Car/SettingsIntelligence" groups="pdk-fs" />
-  <project path="packages/apps/Car/systemlibs" name="platform/packages/apps/Car/systemlibs" groups="pdk-fs" />
+  <project path="packages/apps/Car/systemlibs" name="platform/packages/apps/Car/systemlibs" groups="pdk-fs,pdk-cw-tvc" />
   <project path="packages/apps/Car/SystemUpdater" name="platform/packages/apps/Car/SystemUpdater" groups="pdk-fs" />
   <project path="packages/apps/Car/Templates" name="platform/packages/apps/Car/Templates" groups="pdk-fs" />
   <project path="packages/apps/Car/VoiceControl" name="platform/packages/apps/Car/VoiceControl" groups="pdk-fs" />
@@ -1181,7 +1133,7 @@
   <project path="packages/apps/SafetyRegulatoryInfo" name="platform/packages/apps/SafetyRegulatoryInfo" groups="pdk-fs" />
   <project path="packages/apps/SampleLocationAttribution" name="platform/packages/apps/SampleLocationAttribution" groups="pdk-fs" />
   <project path="packages/apps/SecureElement" name="platform/packages/apps/SecureElement" groups="apps_se,pdk-fs,pdk-cw-fs" />
-  <project path="packages/apps/Settings" name="platform/packages/apps/Settings" groups="pdk-fs" />
+  <project path="packages/apps/Settings" name="platform/packages/apps/Settings" groups="pdk-fs,pdk-cw-tvc" />
   <project path="packages/apps/SettingsIntelligence" name="platform/packages/apps/SettingsIntelligence" groups="pdk-fs" />
   <project path="packages/apps/SpareParts" name="platform/packages/apps/SpareParts" groups="pdk-fs" />
   <project path="packages/apps/Stk" name="platform/packages/apps/Stk" groups="apps_stk,pdk-fs" />
@@ -1210,7 +1162,6 @@
   <project path="packages/modules/ConfigInfrastructure" name="platform/packages/modules/ConfigInfrastructure" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/Connectivity" name="platform/packages/modules/Connectivity" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/CrashRecovery" name="platform/packages/modules/CrashRecovery" groups="pdk-cw-fs,pdk-fs" />
-  <project path="packages/modules/Cronet" name="platform/packages/modules/Cronet" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/DeviceLock" name="platform/packages/modules/DeviceLock" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/ExtServices" name="platform/packages/modules/ExtServices" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/GeoTZ" name="platform/packages/modules/GeoTZ" groups="pdk-cw-fs,pdk-fs" />
@@ -1222,7 +1173,6 @@
   <project path="packages/modules/DnsResolver" name="platform/packages/modules/DnsResolver" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/Media" name="platform/packages/modules/Media" groups="pdk" />
   <project path="packages/modules/ModuleMetadata" name="platform/packages/modules/ModuleMetadata" groups="pdk" />
-  <project path="packages/modules/NetworkPermissionConfig" name="platform/packages/modules/NetworkPermissionConfig" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/NetworkStack" name="platform/packages/modules/NetworkStack" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/NeuralNetworks" name="platform/packages/modules/NeuralNetworks" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/OnDevicePersonalization" name="platform/packages/modules/OnDevicePersonalization" groups="pdk-cw-fs,pdk-fs" />
@@ -1231,11 +1181,9 @@
   <project path="packages/modules/RemoteKeyProvisioning" name="platform/packages/modules/RemoteKeyProvisioning" groups="pdk-cw-fs,pdk-fs"/>
   <project path="packages/modules/RuntimeI18n" name="platform/packages/modules/RuntimeI18n" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/Scheduling" name="platform/packages/modules/Scheduling" groups="pdk-cw-fs,pdk-fs" />
-  <project path="packages/modules/SEPolicy" name="platform/packages/modules/SEPolicy" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/SdkExtensions" name="platform/packages/modules/SdkExtensions" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/StatsD" name="platform/packages/modules/StatsD" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/Telephony" name="platform/packages/modules/Telephony" groups="pdk-cw-fs,pdk-fs"/>
-  <project path="packages/modules/TestModule" name="platform/packages/modules/TestModule" />
   <project path="packages/modules/ThreadNetwork" name="platform/packages/modules/ThreadNetwork" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/Uwb" name="platform/packages/modules/Uwb" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/UprobeStats" name="platform/packages/modules/UprobeStats" groups="pdk-cw-fs,pdk-fs" />
@@ -1265,7 +1213,6 @@
   <project path="packages/services/Mtp" name="platform/packages/services/Mtp" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/services/Telecomm" name="platform/packages/services/Telecomm" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/services/Telephony" name="platform/packages/services/Telephony" groups="pdk-cw-fs,pdk-fs" />
-  <project path="packages/wallpapers/ImageWallpaper" name="platform/packages/wallpapers/ImageWallpaper" groups="pdk-fs" />
   <project path="packages/wallpapers/LivePicker" name="platform/packages/wallpapers/LivePicker" groups="pdk-fs" />
   <project path="pdk" name="platform/pdk" groups="pdk" />
   <project path="platform_testing" name="platform/platform_testing" groups="pdk-fs,pdk-cw-fs,cts,sysui-studio" />
@@ -1275,7 +1222,7 @@
   <project path="prebuilts/android-emulator" name="platform/prebuilts/android-emulator" groups="pdk-fs" clone-depth="1" />
   <project path="prebuilts/asuite" name="platform/prebuilts/asuite" groups="pdk" clone-depth="1" />
   <project path="prebuilts/bazel/common" name="platform/prebuilts/bazel/common" groups="pdk" clone-depth="1" />
-  <project path="prebuilts/bazel/darwin-x86_64" name="platform/prebuilts/bazel/darwin-x86_64" groups="darwin,pdk" clone-depth="1" />
+  <project path="prebuilts/bazel/darwin-x86_64" name="platform/prebuilts/bazel/darwin-x86_64" groups="notdefault,platform-darwin,darwin,pdk" clone-depth="1" />
   <project path="prebuilts/bazel/linux-x86_64" name="platform/prebuilts/bazel/linux-x86_64" groups="linux,pdk" clone-depth="1" />
   <project path="prebuilts/build-tools" name="platform/prebuilts/build-tools" groups="pdk,sysui-studio" clone-depth="1" />
   <project path="prebuilts/bundletool" name="platform/prebuilts/bundletool" groups="pdk" clone-depth="1" />
@@ -1292,8 +1239,7 @@
   <project path="prebuilts/go/darwin-x86" name="platform/prebuilts/go/darwin-x86" groups="notdefault,platform-darwin,darwin,pdk,tradefed" clone-depth="1" />
   <project path="prebuilts/go/linux-x86" name="platform/prebuilts/go/linux-x86" groups="linux,pdk,tradefed" clone-depth="1" />
   <project path="prebuilts/gradle-plugin" name="platform/prebuilts/gradle-plugin" groups="pdk,pdk-cw-fs,pdk-fs" clone-depth="1" />
-  <project path="prebuilts/jdk/jdk17" name="platform/prebuilts/jdk/jdk17" groups="pdk" clone-depth="1" />
-  <project path="prebuilts/jdk/jdk21" name="platform/prebuilts/jdk/jdk21" groups="pdk" clone-depth="1" />
+  <project path="prebuilts/jdk/jdk21" name="platform/prebuilts/jdk/jdk21" groups="pdk,sysui-studio" clone-depth="1" />
   <project path="prebuilts/jdk/jdk8" name="platform/prebuilts/jdk/jdk8" groups="pdk" clone-depth="1" />
   <project path="prebuilts/manifest-merger" name="platform/prebuilts/manifest-merger" groups="pdk" clone-depth="1" />
   <project path="prebuilts/maven_repo/bumptech" name="platform/prebuilts/maven_repo/bumptech" groups="pdk-cw-fs,pdk-fs" clone-depth="1" />
@@ -1351,7 +1297,6 @@
   <project path="system/hardware/interfaces" name="platform/system/hardware/interfaces" groups="pdk,sysui-studio" />
   <project path="system/hwservicemanager" name="platform/system/hwservicemanager" groups="pdk" />
   <project path="system/incremental_delivery" name="platform/system/incremental_delivery" groups="pdk" />
-  <project path="system/iorap" name="platform/system/iorap" groups="pdk" />
   <project path="system/keymaster" name="platform/system/keymaster" groups="pdk" />
   <project path="system/keymint" name="platform/system/keymint" groups="pdk" />
   <project path="system/libartpalette" name="platform/system/libartpalette" groups="pdk" />
@@ -1394,7 +1339,6 @@
   <project path="system/update_engine" name="platform/system/update_engine" groups="pdk" />
   <project path="system/vold" name="platform/system/vold" groups="pdk" />
   <project path="test/dittosuite" name="platform/test/dittosuite" groups="pdk" />
-  <project path="test/framework" name="platform/test/framework" groups="vts,projectarch,pdk" />
   <project path="test/robolectric-extensions" name="platform/test/robolectric-extensions"  groups="pdk-cw-fs,pdk-fs,sysui-studio" />
   <project path="test/mlts/benchmark" name="platform/test/mlts/benchmark" groups="pdk" />
   <project path="test/mlts/models" name="platform/test/mlts/models" groups="pdk" />
@@ -1410,7 +1354,7 @@
   <project path="test/vts-testcase/performance" name="platform/test/vts-testcase/performance" groups="vts,projectarch,pdk" />
   <project path="test/vts-testcase/security" name="platform/test/vts-testcase/security" groups="vts,projectarch,pdk" />
   <project path="test/vts-testcase/vndk" name="platform/test/vts-testcase/vndk" groups="vts,pdk" />
-  <project path="test/catbox" name="platform/test/catbox" />
+  <project path="test/catbox" name="platform/test/catbox" groups="pdk" />
   <project path="toolchain/pgo-profiles" name="toolchain/pgo-profiles" groups="pdk" clone-depth="1" />
   <project path="tools/aadevtools" name="platform/tools/aadevtools" groups="pdk" />
   <project path="tools/acloud" name="platform/tools/acloud" groups="tools,vts,projectarch,pdk,tradefed" />
@@ -1419,13 +1363,13 @@
   <project path="tools/apkzlib" name="platform/tools/apkzlib" groups="pdk,tradefed" />
   <project path="tools/asuite" name="platform/tools/asuite" groups="pdk" />
   <project path="tools/carrier_settings" name="platform/tools/carrier_settings" groups="tools" />
+  <project path="tools/content_addressed_storage/prebuilts" name="platform/tools/content_addressed_storage/prebuilts" groups="pdk,tools" />
   <project path="tools/currysrc" name="platform/tools/currysrc" groups="pdk" />
   <project path="tools/deviceinfra/prebuilts" name="platform/tools/deviceinfra/prebuilts" groups="pdk,tools" />
   <project path="tools/dexter" name="platform/tools/dexter" groups="tools,pdk-cw-fs,pdk-fs" />
   <project path="tools/doc_generation" name="platform/tools/doc_generation" groups="tools,pdk" />
   <project path="tools/external_updater" name="platform/tools/external_updater" groups="tools" />
   <project path="tools/external/fat32lib" name="platform/tools/external/fat32lib" groups="tools" />
-  <project path="tools/lint_checks" name="platform/tools/lint_checks" groups="pdk" />
   <project path="tools/loganalysis" name="platform/tools/loganalysis" groups="nopresubmit,pdk,tradefed" />
   <project path="tools/metalava" name="platform/tools/metalava" groups="pdk,tools" />
   <project path="tools/netsim" name="platform/tools/netsim" groups="pdk" />
@@ -1434,7 +1378,6 @@
   <project path="tools/repohooks" name="platform/tools/repohooks" groups="adt-infra,cts,developers,motodev,pdk,tools,tradefed,sysui-studio" />
   <project path="tools/security" name="platform/tools/security" groups="pdk,tools" />
   <project path="tools/test/connectivity" name="platform/tools/test/connectivity" groups="pdk" />
-  <project path="tools/test/graphicsbenchmark" name="platform/tools/test/graphicsbenchmark" groups="pdk" />
   <project path="tools/test/mobly_extensions" name="platform/tools/test/mobly_extensions" groups="pdk" />
   <project path="tools/test/mobly_snippets" name="platform/tools/test/mobly_snippets" groups="pdk" />
   <project path="tools/test/openhst" name="platform/tools/test/openhst" groups="tools" />
@@ -1452,7 +1395,6 @@
     <linkfile src="bazel/WORKSPACE.bazel" dest="trusty/WORKSPACE.bazel" />
     <linkfile src="bazel/bazelrc" dest="trusty/.bazelrc" />
   </project>
-  <project path="trusty/interfaces" name="trusty/interfaces" groups="trusty" />
   <project path="trusty/kernel" name="trusty/lk/trusty" groups="trusty" />
   <project path="trusty/user/app/avb" name="trusty/app/avb" groups="trusty" />
   <project path="trusty/user/app/cast-auth" name="trusty/app/cast-auth" groups="trusty" />
```

