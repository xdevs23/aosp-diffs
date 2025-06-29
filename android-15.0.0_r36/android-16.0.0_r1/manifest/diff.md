```diff
diff --git a/default.xml b/default.xml
index a7c482a..da4b298 100644
--- a/default.xml
+++ b/default.xml
@@ -4,12 +4,13 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r36"
+  <default revision="refs/tags/android-16.0.0_r1"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r36"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-16.0.0_r1"/>
   <contactinfo bugurl="go/repo-bug" />
+
   <!-- BEGIN open-source projects -->
   <project path="build/make" name="platform/build" groups="pdk,sysui-studio" >
     <linkfile src="CleanSpec.mk" dest="build/CleanSpec.mk" />
@@ -39,7 +40,6 @@
   <project path="cts" name="platform/cts" groups="cts,pdk-cw-fs,pdk-fs" />
   <project path="dalvik" name="platform/dalvik" groups="pdk-cw-fs,pdk-fs" />
   <project path="developers/build" name="platform/developers/build" groups="developers,pdk" />
-  <project path="developers/demos" name="platform/developers/demos" groups="developers" />
   <project path="developers/samples/android" name="platform/developers/samples/android" groups="developers" />
   <project path="development" name="platform/development" groups="developers,pdk-cw-fs,pdk-fs,sysui-studio" />
   <project path="device/amlogic/yukawa" name="device/amlogic/yukawa" groups="device,yukawa,pdk" />
@@ -52,65 +52,21 @@
   <project path="device/generic/common" name="device/generic/common" groups="pdk" />
   <project path="device/generic/goldfish" name="device/generic/goldfish" groups="pdk" />
   <project path="device/generic/goldfish-opengl" name="device/generic/goldfish-opengl" groups="pdk" />
-  <project path="device/generic/mini-emulator-arm64" name="device/generic/mini-emulator-arm64" groups="pdk" />
-  <project path="device/generic/mini-emulator-armv7-a-neon" name="device/generic/mini-emulator-armv7-a-neon" groups="pdk" />
-  <project path="device/generic/mini-emulator-x86" name="device/generic/mini-emulator-x86" groups="pdk" />
-  <project path="device/generic/mini-emulator-x86_64" name="device/generic/mini-emulator-x86_64" groups="pdk" />
   <project path="device/generic/trusty" name="device/generic/trusty" groups="pdk" />
   <project path="device/generic/x86" name="device/generic/x86" groups="pdk" />
   <project path="device/generic/x86_64" name="device/generic/x86_64" groups="pdk" />
-  <project path="device/google/akita" name="device/google/akita" groups="device,akita" />
-  <project path="device/google/akita-sepolicy" name="device/google/akita-sepolicy" groups="device,akita" />
-  <project path="device/google/akita-kernels/6.1" name="device/google/akita-kernels/6.1" groups="device,akita" clone-depth="1" />
   <project path="device/google/atv" name="device/google/atv" groups="device,broadcom_pdk,generic_fs,pdk" />
-  <project path="device/google/bluejay" name="device/google/bluejay" groups="device,bluejay" />
-  <project path="device/google/bluejay-sepolicy" name="device/google/bluejay-sepolicy" groups="device,bluejay" />
-  <project path="device/google/bluejay-kernels/6.1" name="device/google/bluejay-kernels/6.1" groups="device,bluejay" clone-depth="1" />
   <project path="device/google/contexthub" name="device/google/contexthub" groups="device,pdk" />
-  <project path="device/google/caimito" name="device/google/caimito" groups="device,caimito" />
-  <project path="device/google/caimito-kernels/6.1" name="device/google/caimito-kernels/6.1" groups="device,caimito" clone-depth="1" />
-  <project path="device/google/caimito-sepolicy" name="device/google/caimito-sepolicy" groups="device,caimito" />
-  <project path="device/google/comet" name="device/google/comet" groups="device,comet" />
-  <project path="device/google/comet-kernels/6.1" name="device/google/comet-kernels/6.1" groups="device,comet" clone-depth="1" />
-  <project path="device/google/comet-sepolicy" name="device/google/comet-sepolicy" groups="device,comet" />
   <project path="device/google/common/etm" name="device/google/common/etm" groups="device" clone-depth="1" />
-  <project path="device/google/felix" name="device/google/felix" groups="device,felix" />
-  <project path="device/google/felix-sepolicy" name="device/google/felix-sepolicy" groups="device,felix" />
-  <project path="device/google/felix-kernels/6.1" name="device/google/felix-kernels/6.1" groups="device,felix" clone-depth="1" />
-  <project path="device/google/gs101" name="device/google/gs101" groups="device,slider,bluejay,pdk-gs-arm" />
-  <project path="device/google/gs101-sepolicy" name="device/google/gs101-sepolicy" groups="device,slider,bluejay,pdk-gs-arm" />
-  <project path="device/google/gs201" name="device/google/gs201" groups="device,cloudripper,pdk-gs-arm" />
-  <project path="device/google/gs201-sepolicy" name="device/google/gs201-sepolicy" groups="device,cloudripper,pdk-gs-arm" />
-  <project path="device/google/gs-common" name="device/google/gs-common" groups="device,slider,bluejay,cloudripper,pdk-gs-arm,pdk-cw-tvc,pdk-gs-imgtec" />
-  <project path="device/google/lynx" name="device/google/lynx" groups="device,lynx" />
-  <project path="device/google/lynx-sepolicy" name="device/google/lynx-sepolicy" groups="device,lynx" />
-  <project path="device/google/lynx-kernels/6.1" name="device/google/lynx-kernels/6.1" groups="device,lynx" clone-depth="1" />
-  <project path="device/google/pantah" name="device/google/pantah" groups="device,cloudripper,pdk-gs-arm" />
-  <project path="device/google/pantah-sepolicy" name="device/google/pantah-sepolicy" groups="device,cloudripper,pdk-gs-arm" />
-  <project path="device/google/pantah-kernels/6.1" name="device/google/pantah-kernels/6.1" groups="device,cloudripper" clone-depth="1" />
-  <project path="device/google/raviole" name="device/google/raviole" groups="device,slider,pdk-gs-arm" />
-  <project path="device/google/raviole-kernels/6.1" name="device/google/raviole-kernels/6.1" groups="device,slider" clone-depth="1" />
-  <project path="device/google/tangorpro" name="device/google/tangorpro" groups="device,tangorpro" />
-  <project path="device/google/tangorpro-sepolicy" name="device/google/tangorpro-sepolicy" groups="device,tangorpro" />
-  <project path="device/google/tangorpro-kernels/6.1" name="device/google/tangorpro-kernels/6.1" groups="device,tangorpro" clone-depth="1" />
-  <project path="device/google/shusky" name="device/google/shusky" groups="device,ripcurrent,pdk-gs-arm" />
-  <project path="device/google/shusky-kernels/6.1" name="device/google/shusky-kernels/6.1" groups="device,ripcurrent" clone-depth="1" />
-  <project path="device/google/shusky-sepolicy" name="device/google/shusky-sepolicy" groups="device,ripcurrent,pdk-gs-arm" />
   <project path="device/google/cuttlefish" name="device/google/cuttlefish" groups="device,pdk" />
   <project path="device/google/cuttlefish_prebuilts" name="device/google/cuttlefish_prebuilts" groups="device,pdk" clone-depth="1" />
   <project path="device/google/cuttlefish_vmm" name="device/google/cuttlefish_vmm" groups="device,pdk" clone-depth="1" />
   <project path="device/google/trout" name="device/google/trout" groups="device,pdk" clone-depth="1"/>
-  <project path="device/google/zuma" name="device/google/zuma" groups="device,ripcurrent,pdk-gs-arm" />
-  <project path="device/google/zuma-sepolicy" name="device/google/zuma-sepolicy" groups="device,ripcurrent,pdk-gs-arm" />
-  <project path="device/google/zumapro" name="device/google/zumapro" groups="device,ripcurrentpro" />
-  <project path="device/google/zumapro-sepolicy" name="device/google/zumapro-sepolicy" groups="device,ripcurrentpro" />
   <project path="device/google_car" name="device/google_car" groups="pdk" />
   <project path="device/linaro/dragonboard" name="device/linaro/dragonboard" groups="device,dragonboard,pdk" />
   <project path="device/linaro/dragonboard-kernel" name="device/linaro/dragonboard-kernel" groups="device,dragonboard,pdk" clone-depth="1" />
   <project path="device/linaro/hikey" name="device/linaro/hikey" groups="device,hikey,pdk" />
   <project path="device/linaro/hikey-kernel" name="device/linaro/hikey-kernel" groups="device,hikey,pdk" clone-depth="1" />
-  <project path="device/linaro/poplar" name="device/linaro/poplar" groups="device,poplar,pdk" />
-  <project path="device/linaro/poplar-kernel" name="device/linaro/poplar-kernel" groups="device,poplar,pdk" clone-depth="1" />
   <project path="device/sample" name="device/sample" groups="pdk" />
   <project path="external/aac" name="platform/external/aac" groups="pdk" />
   <project path="external/abseil-cpp" name="platform/external/abseil-cpp" groups="pdk" />
@@ -121,7 +77,6 @@
   <project path="external/androidplot" name="platform/external/androidplot" groups="pdk" />
   <project path="external/angle" name="platform/external/angle" groups="pdk" />
   <project path="external/anonymous-counting-tokens" name="platform/external/anonymous-counting-tokens" groups="pdk" />
-  <project path="external/ant-glob" name="platform/external/ant-glob" groups="pdk" />
   <project path="external/antlr" name="platform/external/antlr" groups="pdk" />
   <project path="external/apache-commons-bcel" name="platform/external/apache-commons-bcel" groups="pdk" />
   <project path="external/apache-commons-compress" name="platform/external/apache-commons-compress" groups="pdk" />
@@ -171,6 +126,7 @@
   <project path="external/chromium-crossbench" name="platform/external/chromium-crossbench" groups="pdk" />
   <project path="external/chromium-trace" name="platform/external/chromium-trace" groups="pdk" />
   <project path="external/chromium-webview" name="platform/external/chromium-webview" groups="pdk" clone-depth="1" />
+  <project path="external/chromiumos-config" name="platform/external/chromiumos-config" groups="pdk" clone-depth="1" />
   <project path="external/clang" name="platform/external/clang" groups="pdk" />
   <project path="external/cldr" name="platform/external/cldr" groups="pdk" />
   <project path="external/clpeak" name="platform/external/clpeak" />
@@ -187,11 +143,11 @@
   <project path="external/crosvm" name="platform/external/crosvm" groups="pdk" />
   <project path="external/curl" name="platform/external/curl" groups="pdk" />
   <project path="external/dagger2" name="platform/external/dagger2" groups="pdk" />
-  <project path="external/deqp" name="platform/external/deqp" groups="pdk-fs" />
-  <project path="external/deqp-deps/SPIRV-Headers" name="platform/external/deqp-deps/SPIRV-Headers" groups="pdk-fs" />
-  <project path="external/deqp-deps/SPIRV-Tools" name="platform/external/deqp-deps/SPIRV-Tools" groups="pdk-fs" />
-  <project path="external/deqp-deps/glslang" name="platform/external/deqp-deps/glslang" groups="pdk-fs" />
-  <project path="external/deqp-deps/amber" name="platform/external/deqp-deps/amber" groups="pdk-fs" />
+  <project path="external/deqp" name="platform/external/deqp" groups="pdk-fs,pdk-cw-tvc" />
+  <project path="external/deqp-deps/SPIRV-Headers" name="platform/external/deqp-deps/SPIRV-Headers" groups="pdk-fs,pdk-cw-tvc" />
+  <project path="external/deqp-deps/SPIRV-Tools" name="platform/external/deqp-deps/SPIRV-Tools" groups="pdk-fs,pdk-cw-tvc" />
+  <project path="external/deqp-deps/glslang" name="platform/external/deqp-deps/glslang" groups="pdk-fs,pdk-cw-tvc" />
+  <project path="external/deqp-deps/amber" name="platform/external/deqp-deps/amber" groups="pdk-fs,pdk-cw-tvc" />
   <project path="external/dexmaker" name="platform/external/dexmaker" groups="pdk" />
   <project path="external/dlmalloc" name="platform/external/dlmalloc" groups="pdk" />
   <project path="external/dng_sdk" name="platform/external/dng_sdk" groups="pdk" />
@@ -276,14 +232,15 @@
   <project path="external/grpc-grpc-java" name="platform/external/grpc-grpc-java" groups="pdk,tradefed" />
   <project path="external/gsc-utils" name="platform/external/gsc-utils" groups="pdk" />
   <project path="external/gson" name="platform/external/gson" groups="pdk,tradefed" />
-  <project path="external/gturri-aXMLRPC" name="platform/external/gturri-aXMLRPC" groups="pdk-desktop" />
-  <project path="external/gturri-jISO8601" name="platform/external/gturri-jISO8601" groups="pdk-desktop" />
+  <project path="external/gturri-aXMLRPC" name="platform/external/gturri-aXMLRPC" groups="pdk" />
+  <project path="external/gturri-jISO8601" name="platform/external/gturri-jISO8601" groups="pdk" />
   <project path="external/guava" name="platform/external/guava" groups="pdk" />
   <project path="external/guice" name="platform/external/guice" groups="pdk" />
   <project path="external/gwp_asan" name="platform/external/gwp_asan" groups="pdk" />
   <project path="external/hamcrest" name="platform/external/hamcrest" groups="pdk" />
   <project path="external/harfbuzz_ng" name="platform/external/harfbuzz_ng" groups="pdk,qcom_msm8x26" />
   <project path="external/hyphenation-patterns" name="platform/external/hyphenation-patterns" groups="pdk" />
+  <project path="external/iamf_tools" name="platform/external/iamf_tools" groups="pdk" />
   <project path="external/icing" name="platform/external/icing" groups="pdk" />
   <project path="external/icu" name="platform/external/icu" groups="pdk" />
   <project path="external/igt-gpu-tools" name="platform/external/igt-gpu-tools" groups="pdk" />
@@ -299,6 +256,7 @@
   <project path="external/jackson-annotations" name="platform/external/jackson-annotations" groups="pdk" />
   <project path="external/jackson-core" name="platform/external/jackson-core" groups="pdk" />
   <project path="external/jackson-databind" name="platform/external/jackson-databind" groups="pdk" />
+  <project path="external/jakarta.inject" name="platform/external/jakarta.inject" groups="pdk" />
   <project path="external/jarjar" name="platform/external/jarjar" groups="pdk" />
   <project path="external/javaparser" name="platform/external/javaparser" groups="pdk" />
   <project path="external/javapoet" name="platform/external/javapoet" groups="pdk" />
@@ -329,6 +287,7 @@
   <project path="external/kotlinx.metadata" name="platform/external/kotlinx.metadata" groups="pdk" />
   <project path="external/kotlinx.serialization" name="platform/external/kotlinx.serialization" groups="pdk" />
   <project path="external/kotlin-compose-compiler" name="platform/external/kotlin-compose-compiler" groups="pdk" />
+  <project path="external/kotlin.metadata" name="platform/external/kotlin.metadata" groups="pdk" />
   <project path="external/ktfmt" name="platform/external/ktfmt" groups="pdk,sysui-studio" />
   <project path="external/ksoap2" name="platform/external/ksoap2" groups="pdk" />
   <project path="external/ksp" name="platform/external/ksp" groups="pdk" />
@@ -347,6 +306,7 @@
   <project path="external/libcups" name="platform/external/libcups" groups="pdk-cw-fs,pdk-fs" />
   <project path="external/libcxx" name="platform/external/libcxx" groups="pdk" />
   <project path="external/libcxxabi" name="platform/external/libcxxabi" groups="pdk" />
+  <project path="external/libdisplay-info" name="platform/external/libdisplay-info" groups="pdk" />
   <project path="external/libdivsufsort" name="platform/external/libdivsufsort" groups="pdk" />
   <project path="external/libdrm" name="platform/external/libdrm" groups="pdk" />
   <project path="external/libepoxy" name="platform/external/libepoxy" groups="pdk" />
@@ -373,6 +333,7 @@
   <project path="external/libopus" name="platform/external/libopus" groups="pdk" />
   <project path="external/libpalmrejection" name="platform/external/libpalmrejection" groups="pdk" />
   <project path="external/libpcap" name="platform/external/libpcap" groups="pdk" />
+  <project path="external/libpciaccess" name="platform/external/libpciaccess" groups="pdk" />
   <project path="external/libphonenumber" name="platform/external/libphonenumber" groups="pdk" />
   <project path="external/libpng" name="platform/external/libpng" groups="pdk" />
   <project path="external/libprotobuf-mutator" name="platform/external/libprotobuf-mutator" groups="pdk" />
@@ -385,6 +346,7 @@
   <project path="external/libusb" name="platform/external/libusb" groups="pdk" />
   <project path="external/libutf" name="platform/external/libutf" groups="pdk" />
   <project path="external/libva" name="platform/external/libva" groups="pdk" />
+  <project path="external/libva-utils" name="platform/external/libva-utils" groups="pdk" />
   <project path="external/libvpx" name="platform/external/libvpx" groups="pdk" />
   <project path="external/libwebm" name="platform/external/libwebm" groups="pdk" />
   <project path="external/libwebsockets" name="platform/external/libwebsockets" groups="pdk" />
@@ -397,7 +359,6 @@
   <project path="external/linux-kselftest" name="platform/external/linux-kselftest" groups="vts,pdk" clone-depth="1" />
   <project path="external/llvm" name="platform/external/llvm" groups="pdk" />
   <project path="external/llvm-libc" name="platform/external/llvm-libc" groups="pdk" />
-  <project path="external/lmfit" name="platform/external/lmfit" groups="pdk" />
   <project path="external/lottie" name="platform/external/lottie" groups="pdk" />
   <project path="external/lua" name="platform/external/lua" groups="pdk" />
   <project path="external/ltp" name="platform/external/ltp" groups="vts,pdk" />
@@ -411,6 +372,7 @@
   <project path="external/minigbm" name="platform/external/minigbm" groups="pdk" />
   <project path="external/minijail" name="platform/external/minijail" groups="pdk" />
   <project path="external/mksh" name="platform/external/mksh" groups="pdk" />
+  <project path="external/ml_dtypes" name="platform/external/ml_dtypes" groups="pdk" />
   <project path="external/python/mobly" name="platform/external/python/mobly" groups="pdk" />
   <project path="external/private-join-and-compute" name="platform/external/private-join-and-compute" groups="pdk" />
   <project path="external/mobile-data-download" name="platform/external/mobile-data-download" groups="pdk" />
@@ -424,6 +386,7 @@
   <project path="external/moshi" name="platform/external/moshi" groups="pdk" />
   <project path="external/mp4parser" name="platform/external/mp4parser" groups="pdk" />
   <project path="external/MPAndroidChart" name="platform/external/MPAndroidChart" groups="pdk" />
+  <project path="external/mpdecimal" name="platform/external/mpdecimal" groups="pdk" />
   <project path="external/ms-tpm-20-ref" name="platform/external/ms-tpm-20-ref" groups="pdk" />
   <project path="external/mtools" name="platform/external/mtools" groups="pdk" />
   <project path="external/musl" name="platform/external/musl" groups="pdk" />
@@ -482,7 +445,6 @@
   <project path="external/python/asn1crypto" name="platform/external/python/asn1crypto" groups="pdk" />
   <project path="external/python/bumble" name="platform/external/python/bumble" groups="pdk" />
   <project path="external/python/cachetools" name="platform/external/python/cachetools" groups="pdk" />
-  <project path="external/python/cpython2" name="platform/external/python/cpython2" groups="pdk" />
   <project path="external/python/cpython3" name="platform/external/python/cpython3" groups="pdk" />
   <project path="external/python/dateutil" name="platform/external/python/dateutil" groups="pdk" />
   <project path="external/python/enum34" name="platform/external/python/enum34" groups="vts,pdk" />
@@ -505,7 +467,6 @@
   <project path="external/python/python-api-core" name="platform/external/python/python-api-core" groups="pdk" />
   <project path="external/python/pyyaml" name="platform/external/python/pyyaml" groups="pdk" />
   <project path="external/python/rsa" name="platform/external/python/rsa" groups="vts,pdk" />
-  <project path="external/python/setuptools" name="platform/external/python/setuptools" groups="vts,pdk" />
   <project path="external/python/six" name="platform/external/python/six" groups="vts,pdk" />
   <project path="external/python/timeout-decorator" name="platform/external/python/timeout-decorator" groups="pdk" />
   <project path="external/python/typing" name="platform/external/python/typing" groups="pdk" />
@@ -525,21 +486,7 @@
   <project path="external/rnnoise" name="platform/external/rnnoise" groups="pdk" />
   <project path="external/rust/android-crates-io" name="platform/external/rust/android-crates-io" groups="pdk" />
   <project path="external/rust/crabbyavif" name="platform/external/rust/crabbyavif" groups="pdk" />
-  <project path="external/rust/crates/inotify-sys" name="platform/external/rust/crates/inotify-sys" groups="pdk" />
-  <project path="external/rust/crates/inotify" name="platform/external/rust/crates/inotify" groups="pdk" />
-  <project path="external/rust/crates/libsqlite3-sys" name="platform/external/rust/crates/libsqlite3-sys" groups="pdk" />
-  <project path="external/rust/crates/libusb1-sys" name="platform/external/rust/crates/libusb1-sys" groups="pdk" />
-  <project path="external/rust/crates/maplit" name="platform/external/rust/crates/maplit" groups="pdk" />
   <project path="external/rust/crates/openssl" name="platform/external/rust/crates/openssl" groups="pdk" />
-  <project path="external/rust/crates/ptr_meta" name="platform/external/rust/crates/ptr_meta" groups="pdk" />
-  <project path="external/rust/crates/ptr_meta_derive" name="platform/external/rust/crates/ptr_meta_derive" groups="pdk" />
-  <project path="external/rust/crates/quiche" name="platform/external/rust/crates/quiche" groups="pdk" />
-  <project path="external/rust/crates/rusb" name="platform/external/rust/crates/rusb" groups="pdk" />
-  <project path="external/rust/crates/ucs2" name="platform/external/rust/crates/ucs2" groups="pdk" />
-  <project path="external/rust/crates/uefi" name="platform/external/rust/crates/uefi" groups="pdk" />
-  <project path="external/rust/crates/uefi-macros" name="platform/external/rust/crates/uefi-macros" groups="pdk" />
-  <project path="external/rust/crates/uefi-raw" name="platform/external/rust/crates/uefi-raw" groups="pdk" />
-  <project path="external/rust/crates/uguid" name="platform/external/rust/crates/uguid" groups="pdk" />
   <project path="external/rust/crates/v4l2r" name="platform/external/rust/crates/v4l2r" groups="pdk" />
   <project path="external/rust/crates/vhost-device-vsock" name="platform/external/rust/crates/vhost-device-vsock" groups="pdk" />
   <project path="external/rust/beto-rust" name="platform/external/rust/beto-rust" groups="pdk" />
@@ -550,7 +497,7 @@
   <project path="external/ruy" name="platform/external/ruy" groups="pdk" />
   <project path="external/s2-geometry-library-java" name="platform/external/s2-geometry-library-java" groups="pdk" />
   <project path="external/sandboxed-api" name="platform/external/sandboxed-api" groups="pdk" />
-  <project path="external/scapy" name="platform/external/scapy" groups="pdk-fs" />
+  <project path="external/scapy" name="platform/external/scapy" groups="pdk-fs,pdk-cw-tvc" />
   <project path="external/scrypt" name="platform/external/scrypt" groups="pdk" />
   <project path="external/scudo" name="platform/external/scudo" groups="pdk" />
   <project path="external/sdk-platform-java" name="platform/external/sdk-platform-java" groups="pdk,tradefed" />
@@ -573,7 +520,6 @@
   <project path="external/sqlite" name="platform/external/sqlite" groups="pdk" />
   <project path="external/spdx-tools" name="platform/external/spdx-tools" groups="pdk" />
   <project path="external/squashfs-tools" name="platform/external/squashfs-tools" groups="pdk" />
-  <project path="external/stardoc" name="platform/external/stardoc" groups="pdk" />
   <project path="external/starlark-go" name="platform/external/starlark-go" groups="pdk" />
   <project path="external/stg" name="platform/external/stg" groups="pdk" />
   <project path="external/strace" name="platform/external/strace" groups="pdk" />
@@ -589,6 +535,7 @@
   <project path="external/threetenbp" name="platform/external/threetenbp" groups="pdk,tradefed" />
   <project path="external/timezone-boundary-builder" name="platform/external/timezone-boundary-builder" groups="pdk" clone-depth="2" />
   <project path="external/tink" name="platform/external/tink" groups="pdk" />
+  <project path="external/tink-java" name="platform/external/tink-java" groups="pdk" />
   <project path="external/tinyalsa" name="platform/external/tinyalsa" groups="pdk" />
   <project path="external/tinyalsa_new" name="platform/external/tinyalsa_new" groups="pdk" />
   <project path="external/tinycompress" name="platform/external/tinycompress" groups="pdk" />
@@ -607,9 +554,10 @@
   <project path="external/turbine" name="platform/external/turbine" groups="pdk" />
   <project path="external/ublksrv" name="platform/external/ublksrv" groups="pdk" />
   <project path="external/unicode" name="platform/external/unicode" groups="pdk" />
-  <project path="external/universal-tween-engine" name="platform/external/universal-tween-engine" />
+  <project path="external/usb-ids" name="platform/external/usb-ids" groups="pdk" />
   <project path="external/uwb" name="platform/external/uwb" groups="pdk" />
   <project path="external/v4l2_codec2" name="platform/external/v4l2_codec2" groups="pdk" />
+  <project path="external/v4l-utils" name="platform/external/v4l-utils" groups="pdk" />
   <project path="external/vboot_reference" name="platform/external/vboot_reference" groups="pdk" />
   <project path="external/virglrenderer" name="platform/external/virglrenderer" groups="pdk" />
   <project path="external/virtio-media" name="platform/external/virtio-media" groups="pdk" />
@@ -637,7 +585,7 @@
   <project path="external/zstd" name="platform/external/zstd" groups="pdk" />
   <project path="external/zucchini" name="platform/external/zucchini" groups="pdk" />
   <project path="external/zxing" name="platform/external/zxing" groups="pdk" />
-  <project path="frameworks/av" name="platform/frameworks/av" groups="pdk" />
+  <project path="frameworks/av" name="platform/frameworks/av" groups="pdk,sysui-studio" />
   <project path="frameworks/base" name="platform/frameworks/base" groups="pdk-cw-fs,pdk-fs,sysui-studio" />
   <project path="frameworks/compile/libbcc" name="platform/frameworks/compile/libbcc" groups="pdk" />
   <project path="frameworks/compile/mclinker" name="platform/frameworks/compile/mclinker" groups="pdk" />
@@ -666,7 +614,7 @@
   <project path="frameworks/opt/net/wifi" name="platform/frameworks/opt/net/wifi" groups="pdk,sysui-studio" />
   <project path="frameworks/opt/photoviewer" name="platform/frameworks/opt/photoviewer" groups="pdk-cw-fs,pdk-fs" />
   <project path="frameworks/opt/setupwizard" name="platform/frameworks/opt/setupwizard" groups="pdk-cw-fs,pdk-fs" />
-  <project path="frameworks/opt/telephony" name="platform/frameworks/opt/telephony" groups="pdk" />
+  <project path="frameworks/opt/telephony" name="platform/frameworks/opt/telephony" groups="pdk,sysui-studio" />
   <project path="frameworks/opt/timezonepicker" name="platform/frameworks/opt/timezonepicker" groups="pdk-cw-fs,pdk-fs" />
   <project path="frameworks/opt/tv/tvsystem" name="platform/frameworks/opt/tv/tvsystem" groups="pdk-cw-fs,pdk-fs" />
   <project path="frameworks/opt/vcard" name="platform/frameworks/opt/vcard" groups="pdk-cw-fs,pdk-fs" />
@@ -679,13 +627,7 @@
   <project path="hardware/google/apf" name="platform/hardware/google/apf" groups="pdk" />
   <project path="hardware/google/av" name="platform/hardware/google/av" groups="pdk" />
   <project path="hardware/google/camera" name="platform/hardware/google/camera" groups="pdk" />
-  <project path="hardware/google/gchips" name="platform/hardware/google/gchips" groups="pdk-lassen,pdk-gs-arm,pdk-gs-imgtec" />
   <project path="hardware/google/gfxstream" name="platform/hardware/google/gfxstream" groups="pdk" />
-  <project path="hardware/google/graphics/common" name="platform/hardware/google/graphics/common" groups="pdk-lassen,pdk-gs-arm,pdk-gs-imgtec" />
-  <project path="hardware/google/graphics/gs101" name="platform/hardware/google/graphics/gs101" groups="pdk-lassen,pdk-gs-arm" />
-  <project path="hardware/google/graphics/gs201" name="platform/hardware/google/graphics/gs201" groups="cloudripper,pdk-gs-arm" />
-  <project path="hardware/google/graphics/zuma" name="platform/hardware/google/graphics/zuma" groups="ripcurrent,pdk-gs-arm" />
-  <project path="hardware/google/graphics/zumapro" name="platform/hardware/google/graphics/zumapro" groups="ripcurrentpro" />
   <project path="hardware/google/interfaces" name="platform/hardware/google/interfaces" groups="pdk,sysui-studio" />
   <project path="hardware/google/pixel" name="platform/hardware/google/pixel" groups="generic_fs,pixel,pdk-gs-arm,pdk-gs-imgtec,pdk-desktop" />
   <project path="hardware/google/pixel-sepolicy" name="platform/hardware/google/pixel-sepolicy" groups="generic_fs,pixel,pdk-desktop" />
@@ -711,12 +653,18 @@
   <project path="kernel/prebuilts/6.1/x86_64" name="kernel/prebuilts/6.1/x86-64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/6.6/arm64" name="kernel/prebuilts/6.6/arm64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/6.6/x86_64" name="kernel/prebuilts/6.6/x86-64" groups="pdk" clone-depth="1" />
+  <project path="kernel/prebuilts/6.12/arm64" name="kernel/prebuilts/6.12/arm64" groups="pdk" clone-depth="1" />
+  <project path="kernel/prebuilts/6.12/x86_64" name="kernel/prebuilts/6.12/x86-64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/mainline/arm64" name="kernel/prebuilts/mainline/arm64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/mainline/x86_64" name="kernel/prebuilts/mainline/x86-64" groups="pdk" clone-depth="1" />
+  <project path="kernel/prebuilts/common-modules/trusty/6.6/arm64" name="kernel/prebuilts/common-modules/trusty/6.6/arm64" groups="pdk" clone-depth="1" />
+  <project path="kernel/prebuilts/common-modules/trusty/6.12/arm64" name="kernel/prebuilts/common-modules/trusty/6.12/arm64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/common-modules/virtual-device/6.1/arm64" name="kernel/prebuilts/common-modules/virtual-device/6.1/arm64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/common-modules/virtual-device/6.1/x86-64" name="kernel/prebuilts/common-modules/virtual-device/6.1/x86-64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/common-modules/virtual-device/6.6/arm64" name="kernel/prebuilts/common-modules/virtual-device/6.6/arm64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/common-modules/virtual-device/6.6/x86-64" name="kernel/prebuilts/common-modules/virtual-device/6.6/x86-64" groups="pdk" clone-depth="1" />
+  <project path="kernel/prebuilts/common-modules/virtual-device/6.12/arm64" name="kernel/prebuilts/common-modules/virtual-device/6.12/arm64" groups="pdk" clone-depth="1" />
+  <project path="kernel/prebuilts/common-modules/virtual-device/6.12/x86-64" name="kernel/prebuilts/common-modules/virtual-device/6.12/x86-64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/common-modules/virtual-device/mainline/arm64" name="kernel/prebuilts/common-modules/virtual-device/mainline/arm64" groups="pdk" clone-depth="1" />
   <project path="kernel/prebuilts/common-modules/virtual-device/mainline/x86-64" name="kernel/prebuilts/common-modules/virtual-device/mainline/x86-64" groups="pdk" clone-depth="1" />
   <project path="kernel/tests" name="kernel/tests" groups="vts,pdk" />
@@ -728,7 +676,7 @@
   <project path="packages/apps/Calendar" name="platform/packages/apps/Calendar" groups="pdk-fs" />
   <project path="packages/apps/Camera2" name="platform/packages/apps/Camera2" groups="pdk-fs" />
   <project path="packages/apps/Car/CalendarPrebuilt" name="platform/packages/apps/Car/CalendarPrebuilt" groups="pdk-fs" />
-  <project path="packages/apps/Car/SystemUI" name="platform/packages/apps/Car/SystemUI" groups="pdk-fs" />
+  <project path="packages/apps/Car/SystemUI" name="platform/packages/apps/Car/SystemUI" groups="pdk-fs,pdk-cw-tvc" />
   <project path="packages/apps/Car/Cluster" name="platform/packages/apps/Car/Cluster" groups="pdk-fs" />
   <project path="packages/apps/Car/DebuggingRestrictionController" name="platform/packages/apps/Car/DebuggingRestrictionController" groups="pdk-fs" />
   <project path="packages/apps/Car/DialerPrebuilt" name="platform/packages/apps/Car/DialerPrebuilt" groups="pdk-fs" />
@@ -742,15 +690,16 @@
   <project path="packages/apps/Car/Notification" name="platform/packages/apps/Car/Notification" groups="pdk-fs" />
   <project path="packages/apps/Car/Provision" name="platform/packages/apps/Car/Provision" groups="pdk-fs" />
   <project path="packages/apps/Car/RadioPrebuilt" name="platform/packages/apps/Car/RadioPrebuilt" groups="pdk-fs" />
-  <project path="packages/apps/Car/RotaryController" name="platform/packages/apps/Car/RotaryController" groups="pdk-fs" />
+  <project path="packages/apps/Car/RotaryController" name="platform/packages/apps/Car/RotaryController" groups="pdk-fs,pdk-cw-tvc" />
   <project path="packages/apps/Car/RotaryImePrebuilt" name="platform/packages/apps/Car/RotaryImePrebuilt" groups="pdk-fs" />
-  <project path="packages/apps/Car/Settings" name="platform/packages/apps/Car/Settings" groups="pdk-fs" />
+  <project path="packages/apps/Car/Settings" name="platform/packages/apps/Car/Settings" groups="pdk-fs,pdk-cw-tvc" />
   <project path="packages/apps/Car/SettingsIntelligence" name="platform/packages/apps/Car/SettingsIntelligence" groups="pdk-fs" />
   <project path="packages/apps/Car/systemlibs" name="platform/packages/apps/Car/systemlibs" groups="pdk-fs,pdk-cw-tvc" />
   <project path="packages/apps/Car/SystemUpdater" name="platform/packages/apps/Car/SystemUpdater" groups="pdk-fs" />
   <project path="packages/apps/Car/Templates" name="platform/packages/apps/Car/Templates" groups="pdk-fs" />
   <project path="packages/apps/Car/VoiceControl" name="platform/packages/apps/Car/VoiceControl" groups="pdk-fs" />
   <project path="packages/apps/Car/DataSubscriptionReference" name="platform/packages/apps/Car/DataSubscriptionReference" groups="pdk-fs" />
+  <project path="packages/apps/Car/References" name="platform/packages/apps/Car/References" groups="pdk-fs" />
   <project path="packages/apps/CarrierConfig" name="platform/packages/apps/CarrierConfig" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/apps/CellBroadcastReceiver" name="platform/packages/apps/CellBroadcastReceiver" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/apps/CertInstaller" name="platform/packages/apps/CertInstaller" groups="pdk-cw-fs,pdk-fs" />
@@ -774,9 +723,9 @@
   <project path="packages/apps/Multiuser" name="platform/packages/apps/Multiuser" groups="pdk-fs" />
   <project path="packages/apps/Music" name="platform/packages/apps/Music" groups="pdk-fs" />
   <project path="packages/apps/MusicFX" name="platform/packages/apps/MusicFX" groups="pdk-fs" />
-  <project path="packages/apps/Nfc" name="platform/packages/apps/Nfc" groups="apps_nfc,pdk-fs,pdk-cw-fs" />
   <project path="packages/apps/OnDeviceAppPrediction" name="platform/packages/apps/OnDeviceAppPrediction" groups="pdk-fs" />
   <project path="packages/apps/PhoneCommon" name="platform/packages/apps/PhoneCommon" groups="pdk-cw-fs,pdk-fs" />
+  <project path="packages/apps/PrivateSpace" name="platform/packages/apps/PrivateSpace" groups="pdk-fs" />
   <project path="packages/apps/Protips" name="platform/packages/apps/Protips" groups="pdk-fs" />
   <project path="packages/apps/Provision" name="platform/packages/apps/Provision" groups="pdk-fs" />
   <project path="packages/apps/QuickSearchBox" name="platform/packages/apps/QuickSearchBox" groups="pdk-fs" />
@@ -784,7 +733,7 @@
   <project path="packages/apps/SafetyRegulatoryInfo" name="platform/packages/apps/SafetyRegulatoryInfo" groups="pdk-fs" />
   <project path="packages/apps/SampleLocationAttribution" name="platform/packages/apps/SampleLocationAttribution" groups="pdk-fs" />
   <project path="packages/apps/SecureElement" name="platform/packages/apps/SecureElement" groups="apps_se,pdk-fs,pdk-cw-fs" />
-  <project path="packages/apps/Settings" name="platform/packages/apps/Settings" groups="pdk-fs,pdk-cw-tvc" />
+  <project path="packages/apps/Settings" name="platform/packages/apps/Settings" groups="pdk-fs,pdk-cw-tvc,sysui-studio" />
   <project path="packages/apps/SettingsIntelligence" name="platform/packages/apps/SettingsIntelligence" groups="pdk-fs" />
   <project path="packages/apps/SpareParts" name="platform/packages/apps/SpareParts" groups="pdk-fs" />
   <project path="packages/apps/Stk" name="platform/packages/apps/Stk" groups="apps_stk,pdk-fs" />
@@ -794,7 +743,7 @@
   <project path="packages/apps/Test/connectivity" name="platform/packages/apps/Test/connectivity" groups="pdk" />
   <project path="packages/apps/ThemePicker" name="platform/packages/apps/ThemePicker" groups="pdk-fs,sysui-studio" />
   <project path="packages/apps/Traceur" name="platform/packages/apps/Traceur" groups="pdk-fs,sysui-studio,pdk-cw-tvc" />
-  <project path="packages/apps/TvSettings" name="platform/packages/apps/TvSettings" groups="pdk-fs" />
+  <project path="packages/apps/TvSettings" name="platform/packages/apps/TvSettings" groups="pdk-fs,pdk-cw-tvc" />
   <project path="packages/apps/TvFeedbackConsent" name="platform/packages/apps/TvFeedbackConsent" groups="pdk-fs" />
   <project path="packages/apps/TvSystemUI" name="platform/packages/apps/TvSystemUI" groups="pdk-fs" />
   <project path="packages/apps/TV" name="platform/packages/apps/TV" groups="pdk" />
@@ -814,6 +763,7 @@
   <project path="packages/modules/Connectivity" name="platform/packages/modules/Connectivity" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/CrashRecovery" name="platform/packages/modules/CrashRecovery" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/DeviceLock" name="platform/packages/modules/DeviceLock" groups="pdk-cw-fs,pdk-fs" />
+  <project path="packages/modules/desktop/Serviceability" name="platform/packages/modules/desktop/Serviceability" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/ExtServices" name="platform/packages/modules/ExtServices" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/GeoTZ" name="platform/packages/modules/GeoTZ" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/Gki" name="platform/packages/modules/Gki" groups="pdk-cw-fs,pdk-fs" />
@@ -826,6 +776,7 @@
   <project path="packages/modules/ModuleMetadata" name="platform/packages/modules/ModuleMetadata" groups="pdk" />
   <project path="packages/modules/NetworkStack" name="platform/packages/modules/NetworkStack" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/NeuralNetworks" name="platform/packages/modules/NeuralNetworks" groups="pdk-cw-fs,pdk-fs" />
+  <project path="packages/modules/Nfc" name="platform/packages/modules/Nfc" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/OnDevicePersonalization" name="platform/packages/modules/OnDevicePersonalization" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/Permission" name="platform/packages/modules/Permission" groups="pdk-cw-fs,pdk-fs" />
   <project path="packages/modules/Profiling" name="platform/packages/modules/Profiling" groups="pdk" />
@@ -908,6 +859,7 @@
   <project path="prebuilts/module_sdk/IPsec" name="platform/prebuilts/module_sdk/IPsec" groups="pdk" clone-depth="1" />
   <project path="prebuilts/module_sdk/Media" name="platform/prebuilts/module_sdk/Media" groups="pdk" clone-depth="1" />
   <project path="prebuilts/module_sdk/MediaProvider" name="platform/prebuilts/module_sdk/MediaProvider" groups="pdk" clone-depth="1" />
+  <project path="prebuilts/module_sdk/Nfc" name="platform/prebuilts/module_sdk/Nfc" groups="pdk" clone-depth="1" />
   <project path="prebuilts/module_sdk/OnDevicePersonalization" name="platform/prebuilts/module_sdk/OnDevicePersonalization" groups="pdk" clone-depth="1" />
   <project path="prebuilts/module_sdk/Permission" name="platform/prebuilts/module_sdk/Permission" groups="pdk" clone-depth="1" />
   <project path="prebuilts/module_sdk/Profiling" name="platform/prebuilts/module_sdk/Profiling" groups="pdk" clone-depth="1" />
@@ -940,6 +892,7 @@
   <project path="system/chre" name="platform/system/chre" groups="pdk" />
   <project path="system/connectivity/wificond" name="platform/system/connectivity/wificond" groups="pdk" />
   <project path="system/core" name="platform/system/core" groups="pdk" />
+  <project path="system/cros-codecs" name="platform/system/cros-codecs" groups="pdk" />
   <project path="system/dmesgd" name="platform/system/dmesgd" groups="pdk" />
   <project path="system/extras" name="platform/system/extras" groups="pdk" />
   <project path="system/gatekeeper" name="platform/system/gatekeeper" groups="pdk" />
@@ -959,6 +912,7 @@
   <project path="system/librustutils" name="platform/system/librustutils" groups="pdk" />
   <project path="system/libsysprop" name="platform/system/libsysprop" groups="pdk" />
   <project path="system/libufdt" name="platform/system/libufdt" groups="pdk" />
+  <project path="system/liburingutils" name="platform/system/liburingutils" groups="pdk" />
   <project path="system/libvintf" name="platform/system/libvintf" groups="pdk" />
   <project path="system/libziparchive" name="platform/system/libziparchive" groups="pdk" />
   <project path="system/linkerconfig" name="platform/system/linkerconfig" groups="pdk" />
@@ -972,10 +926,11 @@
   <project path="system/memory/lmkd" name="platform/system/memory/lmkd" groups="pdk" />
   <project path="system/memory/mmd" name="platform/system/memory/mmd" groups="pdk" />
   <project path="system/netd" name="platform/system/netd" groups="pdk" />
-  <project path="system/nfc" name="platform/system/nfc" groups="pdk" />
   <project path="system/nvram" name="platform/system/nvram" groups="pdk" />
   <project path="system/secretkeeper" name="platform/system/secretkeeper" groups="pdk" />
+  <project path="system/secure_element" name="platform/system/secure_element" groups="pdk" />
   <project path="system/security" name="platform/system/security" groups="pdk" />
+  <project path="system/see/authmgr" name="platform/system/see/authmgr" groups="pdk" />
   <project path="system/sepolicy" name="platform/system/sepolicy" groups="pdk" />
   <project path="system/server_configurable_flags" name="platform/system/server_configurable_flags" groups="pdk"/>
   <project path="system/teeui" name="platform/system/teeui" groups="pdk" />
@@ -990,6 +945,7 @@
   <project path="system/update_engine" name="platform/system/update_engine" groups="pdk" />
   <project path="system/usb_info_tools" name="platform/system/usb_info_tools" groups="pdk" />
   <project path="system/vold" name="platform/system/vold" groups="pdk" />
+  <project path="system/zygote" name="platform/system/zygote" groups="pdk" />
   <project path="test/dittosuite" name="platform/test/dittosuite" groups="pdk" />
   <project path="test/robolectric-extensions" name="platform/test/robolectric-extensions"  groups="pdk-cw-fs,pdk-fs,sysui-studio" />
   <project path="test/mlts/benchmark" name="platform/test/mlts/benchmark" groups="pdk" />
@@ -1000,7 +956,6 @@
   <project path="test/suite_harness" name="platform/test/suite_harness" groups="cts,pdk-cw-fs,pdk-fs" />
   <project path="test/vts" name="platform/test/vts" groups="vts,pdk" />
   <project path="test/vts-testcase/hal" name="platform/test/vts-testcase/hal" groups="vts,pdk" />
-  <project path="test/vts-testcase/hal-trace" name="platform/test/vts-testcase/hal-trace" groups="vts,pdk" />
   <project path="test/vts-testcase/kernel" name="platform/test/vts-testcase/kernel" groups="vts,pdk" />
   <project path="test/vts-testcase/nbu" name="platform/test/vts-testcase/nbu" groups="vts,projectarch,pdk" />
   <project path="test/vts-testcase/performance" name="platform/test/vts-testcase/performance" groups="vts,projectarch,pdk" />
@@ -1040,6 +995,8 @@
   <project path="tools/trebuchet" name="platform/tools/trebuchet" groups="tools,cts,pdk,pdk-cw-fs,pdk-fs" />
   <project path="trusty/device/arm/generic-arm64" name="trusty/device/arm/generic-arm64" groups="trusty,pdk" />
   <project path="trusty/device/arm/vexpress-a15" name="trusty/device/arm/vexpress-a15" groups="trusty,pdk" />
+  <project path="trusty/device/common" name="trusty/device/common" groups="trusty,pdk" />
+  <project path="trusty/device/desktop" name="trusty/device/desktop" groups="android-desktop,pdk,trusty" />
   <project path="trusty/device/nxp/imx7d" name="trusty/device/nxp/imx7d" groups="trusty,pdk" />
   <project path="trusty/device/x86/generic-x86_64" name="trusty/device/x86/generic-x86_64" groups="trusty,pdk" />
   <project path="trusty/hardware/nxp" name="trusty/lk/nxp" groups="trusty,pdk" />
@@ -1059,6 +1016,7 @@
   <project path="trusty/user/app/secretkeeper" name="trusty/app/secretkeeper" groups="trusty,pdk" />
   <project path="trusty/user/app/storage" name="trusty/app/storage" groups="trusty,pdk" />
   <project path="trusty/user/base" name="trusty/lib" groups="trusty,pdk" />
+  <project path="trusty/user/desktop" name="trusty/user/desktop" groups="android-desktop,pdk,trusty" />
   <project path="trusty/vendor/google/aosp" name="trusty/vendor/google/aosp" groups="trusty,pdk">
     <copyfile src="lk_inc.mk" dest="lk_inc.mk" />
   </project>
```

