```diff
diff --git a/default.xml b/default.xml
index 452f0f6..37a935c 100644
--- a/default.xml
+++ b/default.xml
@@ -4,13 +4,12 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r17"
+  <default revision="refs/tags/android-15.0.0_r20"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r17"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r20"/>
   <contactinfo bugurl="go/repo-bug" />
-
   <!-- BEGIN open-source projects -->
   <project path="build/make" name="platform/build" groups="pdk,sysui-studio" >
     <linkfile src="CleanSpec.mk" dest="build/CleanSpec.mk" />
@@ -27,8 +26,8 @@
   <project path="build/bazel_common_rules" name="platform/build/bazel_common_rules" groups="pdk" />
   <project path="build/blueprint" name="platform/build/blueprint" groups="pdk,tradefed" />
   <project path="build/pesto" name="platform/build/pesto" groups="pdk" />
-  <project path="build/release" name="platform/build/release" groups="pdk,tradefed" />
-  <project path="build/soong" name="platform/build/soong" groups="pdk,tradefed" >
+  <project path="build/release" name="platform/build/release" groups="pdk,tradefed,sysui-studio" />
+  <project path="build/soong" name="platform/build/soong" groups="pdk,tradefed,sysui-studio" >
     <linkfile src="root.bp" dest="Android.bp" />
     <linkfile src="bootstrap.bash" dest="bootstrap.bash" />
   </project>
@@ -62,11 +61,11 @@
   <project path="device/generic/x86_64" name="device/generic/x86_64" groups="pdk" />
   <project path="device/google/akita" name="device/google/akita" groups="device,akita" />
   <project path="device/google/akita-sepolicy" name="device/google/akita-sepolicy" groups="device,akita" />
-  <project path="device/google/akita-kernels/5.15" name="device/google/akita-kernels/5.15" groups="device,akita" clone-depth="1" />
+  <project path="device/google/akita-kernels/6.1" name="device/google/akita-kernels/6.1" groups="device,akita" clone-depth="1" />
   <project path="device/google/atv" name="device/google/atv" groups="device,broadcom_pdk,generic_fs,pdk" />
   <project path="device/google/bluejay" name="device/google/bluejay" groups="device,bluejay" />
   <project path="device/google/bluejay-sepolicy" name="device/google/bluejay-sepolicy" groups="device,bluejay" />
-  <project path="device/google/bluejay-kernels/5.10" name="device/google/bluejay-kernels/5.10" groups="device,bluejay" clone-depth="1" />
+  <project path="device/google/bluejay-kernels/6.1" name="device/google/bluejay-kernels/6.1" groups="device,bluejay" clone-depth="1" />
   <project path="device/google/contexthub" name="device/google/contexthub" groups="device,pdk" />
   <project path="device/google/caimito" name="device/google/caimito" groups="device,caimito" />
   <project path="device/google/caimito-kernels/6.1" name="device/google/caimito-kernels/6.1" groups="device,caimito" clone-depth="1" />
@@ -77,25 +76,25 @@
   <project path="device/google/common/etm" name="device/google/common/etm" groups="device" clone-depth="1" />
   <project path="device/google/felix" name="device/google/felix" groups="device,felix" />
   <project path="device/google/felix-sepolicy" name="device/google/felix-sepolicy" groups="device,felix" />
-  <project path="device/google/felix-kernels/5.10" name="device/google/felix-kernels/5.10" groups="device,felix" clone-depth="1" />
+  <project path="device/google/felix-kernels/6.1" name="device/google/felix-kernels/6.1" groups="device,felix" clone-depth="1" />
   <project path="device/google/gs101" name="device/google/gs101" groups="device,slider,bluejay,pdk-gs-arm" />
   <project path="device/google/gs101-sepolicy" name="device/google/gs101-sepolicy" groups="device,slider,bluejay,pdk-gs-arm" />
   <project path="device/google/gs201" name="device/google/gs201" groups="device,cloudripper,pdk-gs-arm" />
   <project path="device/google/gs201-sepolicy" name="device/google/gs201-sepolicy" groups="device,cloudripper,pdk-gs-arm" />
-  <project path="device/google/gs-common" name="device/google/gs-common" groups="device,slider,bluejay,cloudripper,pdk-gs-arm,pdk-cw-tvc" />
+  <project path="device/google/gs-common" name="device/google/gs-common" groups="device,slider,bluejay,cloudripper,pdk-gs-arm,pdk-cw-tvc,pdk-gs-imgtec" />
   <project path="device/google/lynx" name="device/google/lynx" groups="device,lynx" />
   <project path="device/google/lynx-sepolicy" name="device/google/lynx-sepolicy" groups="device,lynx" />
-  <project path="device/google/lynx-kernels/5.10" name="device/google/lynx-kernels/5.10" groups="device,lynx" clone-depth="1" />
+  <project path="device/google/lynx-kernels/6.1" name="device/google/lynx-kernels/6.1" groups="device,lynx" clone-depth="1" />
   <project path="device/google/pantah" name="device/google/pantah" groups="device,cloudripper,pdk-gs-arm" />
   <project path="device/google/pantah-sepolicy" name="device/google/pantah-sepolicy" groups="device,cloudripper,pdk-gs-arm" />
-  <project path="device/google/pantah-kernels/5.10" name="device/google/pantah-kernels/5.10" groups="device,cloudripper,pdk-gs-arm" clone-depth="1" />
+  <project path="device/google/pantah-kernels/6.1" name="device/google/pantah-kernels/6.1" groups="device,cloudripper" clone-depth="1" />
   <project path="device/google/raviole" name="device/google/raviole" groups="device,slider,pdk-gs-arm" />
-  <project path="device/google/raviole-kernels/5.10" name="device/google/raviole-kernels/5.10" groups="device,slider,pdk-gs-arm" clone-depth="1" />
+  <project path="device/google/raviole-kernels/6.1" name="device/google/raviole-kernels/6.1" groups="device,slider" clone-depth="1" />
   <project path="device/google/tangorpro" name="device/google/tangorpro" groups="device,tangorpro" />
   <project path="device/google/tangorpro-sepolicy" name="device/google/tangorpro-sepolicy" groups="device,tangorpro" />
-  <project path="device/google/tangorpro-kernels/5.10" name="device/google/tangorpro-kernels/5.10" groups="device,tangorpro" clone-depth="1" />
+  <project path="device/google/tangorpro-kernels/6.1" name="device/google/tangorpro-kernels/6.1" groups="device,tangorpro" clone-depth="1" />
   <project path="device/google/shusky" name="device/google/shusky" groups="device,ripcurrent,pdk-gs-arm" />
-  <project path="device/google/shusky-kernels/5.15" name="device/google/shusky-kernels/5.15" groups="device,ripcurrent,pdk-gs-arm" clone-depth="1" />
+  <project path="device/google/shusky-kernels/6.1" name="device/google/shusky-kernels/6.1" groups="device,ripcurrent" clone-depth="1" />
   <project path="device/google/shusky-sepolicy" name="device/google/shusky-sepolicy" groups="device,ripcurrent,pdk-gs-arm" />
   <project path="device/google/cuttlefish" name="device/google/cuttlefish" groups="device,pdk" />
   <project path="device/google/cuttlefish_prebuilts" name="device/google/cuttlefish_prebuilts" groups="device,pdk" clone-depth="1" />
@@ -169,6 +168,7 @@
   <project path="external/capstone" name="platform/external/capstone" groups="pdk" />
   <project path="external/cblas" name="platform/external/cblas" groups="pdk" />
   <project path="external/cbor-java" name="platform/external/cbor-java" groups="pdk" />
+  <project path="external/chromium-crossbench" name="platform/external/chromium-crossbench" groups="pdk" />
   <project path="external/chromium-trace" name="platform/external/chromium-trace" groups="pdk" />
   <project path="external/chromium-webview" name="platform/external/chromium-webview" groups="pdk" clone-depth="1" />
   <project path="external/clang" name="platform/external/clang" groups="pdk" />
@@ -214,15 +214,18 @@
   <project path="external/error_prone" name="platform/external/error_prone" groups="pdk" />
   <project path="external/escapevelocity" name="platform/external/escapevelocity" groups="pdk" />
   <project path="external/ethtool" name="platform/external/ethtool" groups="pdk" />
+  <project path="external/executorch" name="platform/external/executorch" groups="pdk" />
   <project path="external/exfatprogs" name="platform/external/exfatprogs" groups="pdk" />
   <project path="external/exoplayer" name="platform/external/exoplayer" groups="pdk" />
   <project path="external/expat" name="platform/external/expat" groups="pdk" />
   <project path="external/f2fs-tools" name="platform/external/f2fs-tools" groups="pdk" />
   <project path="external/fastrpc" name="platform/external/fastrpc" groups="pdk" />
+  <project path="external/fbjni" name="platform/external/fbjni" groups="pdk" />
   <project path="external/federated-compute" name="platform/external/federated-compute" groups="pdk" />
   <project path="external/fdlibm" name="platform/external/fdlibm" groups="pdk" />
   <project path="external/fec" name="platform/external/fec" groups="pdk" />
   <project path="external/fft2d" name="platform/external/fft2d" groups="pdk" />
+  <project path="external/fhir/spec/r4" name="platform/external/fhir/spec/r4" groups="pdk" />
   <project path="external/firebase-messaging" name="platform/external/firebase-messaging" groups="pdk"/>
   <project path="external/flac" name="platform/external/flac" groups="pdk" />
   <project path="external/flashrom" name="platform/external/flashrom" groups="pdk" />
@@ -289,7 +292,6 @@
   <project path="external/intel-media-driver" name="platform/external/intel-media-driver" groups="pdk" />
   <project path="external/iperf3" name="platform/external/iperf3" groups="pdk" />
   <project path="external/iproute2" name="platform/external/iproute2" groups="pdk" />
-  <project path="external/ipsec-tools" name="platform/external/ipsec-tools" groups="pdk" />
   <project path="external/iptables" name="platform/external/iptables" groups="pdk" />
   <project path="external/iputils" name="platform/external/iputils" groups="pdk" />
   <project path="external/iw" name="platform/external/iw" groups="pdk" />
@@ -310,9 +312,10 @@
   <project path="external/jline" name="platform/external/jline" groups="pdk,tradefed,pdk-fs" />
   <project path="external/jsilver" name="platform/external/jsilver" groups="pdk" />
   <project path="external/jsmn" name="platform/external/jsmn" groups="pdk" />
+  <project path="external/json-schema-validator" name="platform/external/json-schema-validator" groups="pdk" />
   <project path="external/jsoncpp" name="platform/external/jsoncpp" groups="pdk" />
   <project path="external/jsoup" name="platform/external/jsoup" groups="pdk" />
-  <project path="external/jsoup-1p-stubs" name="platform/external/jsoup-1p-stubs" groups="pdk" />
+  <project path="external/jspecify" name="platform/external/jspecify" groups="pdk" />
   <project path="external/jsr305" name="platform/external/jsr305" groups="pdk" />
   <project path="external/jsr330" name="platform/external/jsr330" groups="pdk" />
   <project path="external/junit" name="platform/external/junit" groups="pdk" />
@@ -325,6 +328,7 @@
   <project path="external/kotlinx.coroutines" name="platform/external/kotlinx.coroutines" groups="pdk" />
   <project path="external/kotlinx.metadata" name="platform/external/kotlinx.metadata" groups="pdk" />
   <project path="external/kotlinx.serialization" name="platform/external/kotlinx.serialization" groups="pdk" />
+  <project path="external/kotlin-compose-compiler" name="platform/external/kotlin-compose-compiler" groups="pdk" />
   <project path="external/ktfmt" name="platform/external/ktfmt" groups="pdk,sysui-studio" />
   <project path="external/ksoap2" name="platform/external/ksoap2" groups="pdk" />
   <project path="external/ksp" name="platform/external/ksp" groups="pdk" />
@@ -365,6 +369,7 @@
   <project path="external/libnfnetlink" name="platform/external/libnfnetlink" groups="pdk" />
   <project path="external/libnl" name="platform/external/libnl" groups="pdk" />
   <project path="external/libogg" name="platform/external/libogg" groups="pdk" />
+  <project path="external/libopenapv" name="platform/external/libopenapv" groups="pdk" />
   <project path="external/libopus" name="platform/external/libopus" groups="pdk" />
   <project path="external/libpalmrejection" name="platform/external/libpalmrejection" groups="pdk" />
   <project path="external/libpcap" name="platform/external/libpcap" groups="pdk" />
@@ -388,6 +393,7 @@
   <project path="external/libxml2" name="platform/external/libxml2" groups="pdk,libxml2" />
   <project path="external/libyuv" name="platform/external/libyuv" groups="pdk,libyuv" />
   <project path="external/licenseclassifier" name="platform/external/licenseclassifier" groups="pdk" />
+  <project path="external/linux-firmware" name="platform/external/linux-firmware" groups="pdk" />
   <project path="external/linux-kselftest" name="platform/external/linux-kselftest" groups="vts,pdk" clone-depth="1" />
   <project path="external/llvm" name="platform/external/llvm" groups="pdk" />
   <project path="external/llvm-libc" name="platform/external/llvm-libc" groups="pdk" />
@@ -505,6 +511,8 @@
   <project path="external/python/typing" name="platform/external/python/typing" groups="pdk" />
   <project path="external/python/typing_extensions" name="platform/external/python/typing_extensions" groups="pdk" />
   <project path="external/python/uritemplates" name="platform/external/python/uritemplates" groups="vts,pdk" />
+  <project path="external/python/watchdog" name="platform/external/python/watchdog" groups="pdk" />
+  <project path="external/pytorch" name="platform/external/pytorch" groups="pdk" />
   <project path="external/rappor" name="platform/external/rappor" groups="pdk" />
   <project path="external/regex-re2" name="platform/external/regex-re2" groups="pdk" />
   <project path="external/renderscript-intrinsics-replacement-toolkit" name="platform/external/renderscript-intrinsics-replacement-toolkit" groups="pdk,sysui-studio" />
@@ -517,387 +525,25 @@
   <project path="external/rnnoise" name="platform/external/rnnoise" groups="pdk" />
   <project path="external/rust/android-crates-io" name="platform/external/rust/android-crates-io" groups="pdk" />
   <project path="external/rust/crabbyavif" name="platform/external/rust/crabbyavif" groups="pdk" />
-  <project path="external/rust/crates/aarch64-paging" name="platform/external/rust/crates/aarch64-paging" groups="pdk" />
-  <project path="external/rust/crates/acpi" name="platform/external/rust/crates/acpi" groups="pdk" />
-  <project path="external/rust/crates/ahash" name="platform/external/rust/crates/ahash" groups="pdk" />
-  <project path="external/rust/crates/aho-corasick" name="platform/external/rust/crates/aho-corasick" groups="pdk" />
-  <project path="external/rust/crates/android_log-sys" name="platform/external/rust/crates/android_log-sys" groups="pdk" />
-  <project path="external/rust/crates/android_logger" name="platform/external/rust/crates/android_logger" groups="pdk" />
-  <project path="external/rust/crates/anes" name="platform/external/rust/crates/anes" groups="pdk" />
-  <project path="external/rust/crates/annotate-snippets" name="platform/external/rust/crates/annotate-snippets" groups="pdk" />
-  <project path="external/rust/crates/anyhow" name="platform/external/rust/crates/anyhow" groups="pdk" />
-  <project path="external/rust/crates/arbitrary" name="platform/external/rust/crates/arbitrary" groups="pdk" />
-  <project path="external/rust/crates/arc-swap" name="platform/external/rust/crates/arc-swap" groups="pdk" />
-  <project path="external/rust/crates/argh" name="platform/external/rust/crates/argh" groups="pdk" />
-  <project path="external/rust/crates/argh_derive" name="platform/external/rust/crates/argh_derive" groups="pdk" />
-  <project path="external/rust/crates/argh_shared" name="platform/external/rust/crates/argh_shared" groups="pdk" />
-  <project path="external/rust/crates/arrayvec" name="platform/external/rust/crates/arrayvec" groups="trusty" />
-  <project path="external/rust/crates/ash" name="platform/external/rust/crates/ash" groups="pdk" />
-  <project path="external/rust/crates/async-stream" name="platform/external/rust/crates/async-stream" groups="pdk" />
-  <project path="external/rust/crates/async-stream-impl" name="platform/external/rust/crates/async-stream-impl" groups="pdk" />
-  <project path="external/rust/crates/async-task" name="platform/external/rust/crates/async-task" groups="pdk" />
-  <project path="external/rust/crates/async-trait" name="platform/external/rust/crates/async-trait" groups="pdk" />
-  <project path="external/rust/crates/atomic" name="platform/external/rust/crates/atomic" groups="pdk" />
-  <project path="external/rust/crates/atty" name="platform/external/rust/crates/atty" groups="pdk" />
-  <project path="external/rust/crates/axum" name="platform/external/rust/crates/axum" groups="pdk" />
-  <project path="external/rust/crates/axum-core" name="platform/external/rust/crates/axum-core" groups="pdk" />
-  <project path="external/rust/crates/base64" name="platform/external/rust/crates/base64" groups="pdk" />
-  <project path="external/rust/crates/bencher" name="platform/external/rust/crates/bencher" groups="pdk" />
-  <project path="external/rust/crates/bincode" name="platform/external/rust/crates/bincode" groups="pdk" />
-  <project path="external/rust/crates/bindgen" name="platform/external/rust/crates/bindgen" groups="pdk" />
-  <project path="external/rust/crates/bindgen-cli" name="platform/external/rust/crates/bindgen-cli" groups="pdk" />
-  <project path="external/rust/crates/bit_field" name="platform/external/rust/crates/bit_field" groups="pdk" />
-  <project path="external/rust/crates/bitflags" name="platform/external/rust/crates/bitflags" groups="pdk" />
-  <project path="external/rust/crates/bitreader" name="platform/external/rust/crates/bitreader" groups="pdk" />
-  <project path="external/rust/crates/bstr" name="platform/external/rust/crates/bstr" groups="pdk" />
-  <project path="external/rust/crates/buddy_system_allocator" name="platform/external/rust/crates/buddy_system_allocator" groups="pdk" />
-  <project path="external/rust/crates/bytemuck" name="platform/external/rust/crates/bytemuck" groups="pdk" />
-  <project path="external/rust/crates/bytemuck_derive" name="platform/external/rust/crates/bytemuck_derive" groups="pdk" />
-  <project path="external/rust/crates/byteorder" name="platform/external/rust/crates/byteorder" groups="pdk" />
-  <project path="external/rust/crates/bytes" name="platform/external/rust/crates/bytes" groups="pdk" />
-  <project path="external/rust/crates/camino" name="platform/external/rust/crates/camino" groups="pdk" />
-  <project path="external/rust/crates/cast" name="platform/external/rust/crates/cast" groups="pdk" />
-  <project path="external/rust/crates/cesu8" name="platform/external/rust/crates/cesu8" groups="pdk" />
-  <project path="external/rust/crates/cexpr" name="platform/external/rust/crates/cexpr" groups="pdk" />
-  <project path="external/rust/crates/cfg-if" name="platform/external/rust/crates/cfg-if" groups="pdk" />
-  <project path="external/rust/crates/chrono" name="platform/external/rust/crates/chrono" groups="pdk" />
-  <project path="external/rust/crates/ciborium" name="platform/external/rust/crates/ciborium" groups="pdk" />
-  <project path="external/rust/crates/ciborium-io" name="platform/external/rust/crates/ciborium-io" groups="pdk" />
-  <project path="external/rust/crates/ciborium-ll" name="platform/external/rust/crates/ciborium-ll" groups="pdk" />
-  <project path="external/rust/crates/clang-sys" name="platform/external/rust/crates/clang-sys" groups="pdk" />
-  <project path="external/rust/crates/clap" name="platform/external/rust/crates/clap" groups="pdk" />
-  <project path="external/rust/crates/clap_complete" name="platform/external/rust/crates/clap_complete" groups="pdk" />
-  <project path="external/rust/crates/clap_derive" name="platform/external/rust/crates/clap_derive" groups="pdk" />
-  <project path="external/rust/crates/clap_lex" name="platform/external/rust/crates/clap_lex" groups="pdk" />
-  <project path="external/rust/crates/codespan-reporting" name="platform/external/rust/crates/codespan-reporting" groups="pdk" />
-  <project path="external/rust/crates/combine" name="platform/external/rust/crates/combine" groups="pdk" />
-  <project path="external/rust/crates/command-fds" name="platform/external/rust/crates/command-fds" groups="pdk" />
-  <project path="external/rust/crates/config" name="platform/external/rust/crates/config" groups="pdk" />
-  <project path="external/rust/crates/configparser" name="platform/external/rust/crates/configparser" groups="pdk" />
-  <project path="external/rust/crates/const-oid" name="platform/external/rust/crates/const-oid" groups="pdk" />
-  <project path="external/rust/crates/coset" name="platform/external/rust/crates/coset" groups="pdk" />
-  <project path="external/rust/crates/cov-mark" name="platform/external/rust/crates/cov-mark" groups="pdk" />
-  <project path="external/rust/crates/crc32fast" name="platform/external/rust/crates/crc32fast" groups="pdk" />
-  <project path="external/rust/crates/criterion" name="platform/external/rust/crates/criterion" groups="pdk" />
-  <project path="external/rust/crates/criterion-plot" name="platform/external/rust/crates/criterion-plot" groups="pdk" />
-  <project path="external/rust/crates/crossbeam-channel" name="platform/external/rust/crates/crossbeam-channel" groups="pdk" />
-  <project path="external/rust/crates/crossbeam-deque" name="platform/external/rust/crates/crossbeam-deque" groups="pdk" />
-  <project path="external/rust/crates/crossbeam-epoch" name="platform/external/rust/crates/crossbeam-epoch" groups="pdk" />
-  <project path="external/rust/crates/crossbeam-queue" name="platform/external/rust/crates/crossbeam-queue" groups="pdk" />
-  <project path="external/rust/crates/crossbeam-utils" name="platform/external/rust/crates/crossbeam-utils" groups="pdk" />
-  <project path="external/rust/crates/csv" name="platform/external/rust/crates/csv" groups="pdk" />
-  <project path="external/rust/crates/csv-core" name="platform/external/rust/crates/csv-core" groups="pdk" />
-  <project path="external/rust/crates/darling" name="platform/external/rust/crates/darling" groups="pdk" />
-  <project path="external/rust/crates/darling_core" name="platform/external/rust/crates/darling_core" groups="pdk" />
-  <project path="external/rust/crates/darling_macro" name="platform/external/rust/crates/darling_macro" groups="pdk" />
-  <project path="external/rust/crates/dashmap" name="platform/external/rust/crates/dashmap" groups="pdk" />
-  <project path="external/rust/crates/data-encoding" name="platform/external/rust/crates/data-encoding" groups="pdk" />
-  <project path="external/rust/crates/debug_tree" name="platform/external/rust/crates/debug_tree" groups="pdk" />
-  <project path="external/rust/crates/der" name="platform/external/rust/crates/der" groups="pdk" />
-  <project path="external/rust/crates/der_derive" name="platform/external/rust/crates/der_derive" groups="pdk" />
-  <project path="external/rust/crates/derive_arbitrary" name="platform/external/rust/crates/derive_arbitrary" groups="pdk" />
-  <project path="external/rust/crates/displaydoc" name="platform/external/rust/crates/displaydoc" groups="pdk" />
-  <project path="external/rust/crates/document-features" name="platform/external/rust/crates/document-features" groups="pdk" />
-  <project path="external/rust/crates/downcast" name="platform/external/rust/crates/downcast" groups="pdk" />
-  <project path="external/rust/crates/downcast-rs" name="platform/external/rust/crates/downcast-rs" groups="pdk" />
-  <project path="external/rust/crates/drm" name="platform/external/rust/crates/drm" groups="pdk" />
-  <project path="external/rust/crates/drm-ffi" name="platform/external/rust/crates/drm-ffi" groups="pdk" />
-  <project path="external/rust/crates/drm-fourcc" name="platform/external/rust/crates/drm-fourcc" groups="pdk" />
-  <project path="external/rust/crates/either" name="platform/external/rust/crates/either" groups="pdk" />
-  <project path="external/rust/crates/enumn" name="platform/external/rust/crates/enumn" groups="pdk" />
-  <project path="external/rust/crates/env_logger" name="platform/external/rust/crates/env_logger" groups="pdk" />
-  <project path="external/rust/crates/epoll" name="platform/external/rust/crates/epoll" groups="pdk" />
-  <project path="external/rust/crates/equivalent" name="platform/external/rust/crates/equivalent" groups="pdk" />
-  <project path="external/rust/crates/errno" name="platform/external/rust/crates/errno" groups="pdk" />
-  <project path="external/rust/crates/fallible-iterator" name="platform/external/rust/crates/fallible-iterator" groups="pdk" />
-  <project path="external/rust/crates/fallible-streaming-iterator" name="platform/external/rust/crates/fallible-streaming-iterator" groups="pdk" />
-  <project path="external/rust/crates/fastrand" name="platform/external/rust/crates/fastrand" groups="pdk" />
-  <project path="external/rust/crates/fixedbitset" name="platform/external/rust/crates/fixedbitset" groups="pdk" />
-  <project path="external/rust/crates/flagset" name="platform/external/rust/crates/flagset" groups="pdk" />
-  <project path="external/rust/crates/flate2" name="platform/external/rust/crates/flate2" groups="pdk" />
-  <project path="external/rust/crates/fnv" name="platform/external/rust/crates/fnv" groups="pdk" />
-  <project path="external/rust/crates/foreign-types" name="platform/external/rust/crates/foreign-types" groups="pdk" />
-  <project path="external/rust/crates/foreign-types-shared" name="platform/external/rust/crates/foreign-types-shared" groups="pdk" />
-  <project path="external/rust/crates/form_urlencoded" name="platform/external/rust/crates/form_urlencoded" groups="pdk" />
-  <project path="external/rust/crates/fragile" name="platform/external/rust/crates/fragile" groups="pdk" />
-  <project path="external/rust/crates/fs-err" name="platform/external/rust/crates/fs-err" groups="pdk" />
-  <project path="external/rust/crates/futures" name="platform/external/rust/crates/futures" groups="pdk" />
-  <project path="external/rust/crates/futures-channel" name="platform/external/rust/crates/futures-channel" groups="pdk" />
-  <project path="external/rust/crates/futures-core" name="platform/external/rust/crates/futures-core" groups="pdk" />
-  <project path="external/rust/crates/futures-executor" name="platform/external/rust/crates/futures-executor" groups="pdk" />
-  <project path="external/rust/crates/futures-io" name="platform/external/rust/crates/futures-io" groups="pdk" />
-  <project path="external/rust/crates/futures-macro" name="platform/external/rust/crates/futures-macro" groups="pdk" />
-  <project path="external/rust/crates/futures-sink" name="platform/external/rust/crates/futures-sink" groups="pdk" />
-  <project path="external/rust/crates/futures-task" name="platform/external/rust/crates/futures-task" groups="pdk" />
-  <project path="external/rust/crates/futures-test" name="platform/external/rust/crates/futures-test" groups="pdk" />
-  <project path="external/rust/crates/futures-util" name="platform/external/rust/crates/futures-util" groups="pdk" />
-  <project path="external/rust/crates/fxhash" name="platform/external/rust/crates/fxhash" groups="pdk" />
-  <project path="external/rust/crates/gbm" name="platform/external/rust/crates/gbm" groups="pdk" />
-  <project path="external/rust/crates/gdbstub" name="platform/external/rust/crates/gdbstub" groups="pdk" />
-  <project path="external/rust/crates/gdbstub_arch" name="platform/external/rust/crates/gdbstub_arch" groups="pdk" />
-  <project path="external/rust/crates/getrandom" name="platform/external/rust/crates/getrandom" groups="pdk" />
-  <project path="external/rust/crates/glam" name="platform/external/rust/crates/glam" groups="pdk" />
-  <project path="external/rust/crates/glob" name="platform/external/rust/crates/glob" groups="pdk" />
-  <project path="external/rust/crates/googletest" name="platform/external/rust/crates/googletest" groups="pdk" />
-  <project path="external/rust/crates/googletest_macro" name="platform/external/rust/crates/googletest_macro" groups="pdk" />
-  <project path="external/rust/crates/gpio-cdev" name="platform/external/rust/crates/gpio-cdev" groups="pdk" />
-  <project path="external/rust/crates/grpcio" name="platform/external/rust/crates/grpcio" groups="pdk" />
-  <project path="external/rust/crates/grpcio-compiler" name="platform/external/rust/crates/grpcio-compiler" groups="pdk" />
-  <project path="external/rust/crates/grpcio-sys" name="platform/external/rust/crates/grpcio-sys" groups="pdk" />
-  <project path="external/rust/crates/h2" name="platform/external/rust/crates/h2" groups="pdk" />
-  <project path="external/rust/crates/half" name="platform/external/rust/crates/half" groups="pdk" />
-  <project path="external/rust/crates/hashbrown" name="platform/external/rust/crates/hashbrown" groups="pdk" />
-  <project path="external/rust/crates/hashlink" name="platform/external/rust/crates/hashlink" groups="pdk" />
-  <project path="external/rust/crates/heck" name="platform/external/rust/crates/heck" groups="pdk" />
-  <project path="external/rust/crates/hex" name="platform/external/rust/crates/hex" groups="pdk" />
-  <project path="external/rust/crates/hound" name="platform/external/rust/crates/hound" groups="pdk" />
-  <project path="external/rust/crates/http" name="platform/external/rust/crates/http" groups="pdk" />
-  <project path="external/rust/crates/http-body" name="platform/external/rust/crates/http-body" groups="pdk" />
-  <project path="external/rust/crates/httparse" name="platform/external/rust/crates/httparse" groups="pdk" />
-  <project path="external/rust/crates/httpdate" name="platform/external/rust/crates/httpdate" groups="pdk" />
-  <project path="external/rust/crates/hyper" name="platform/external/rust/crates/hyper" groups="pdk" />
-  <project path="external/rust/crates/hyper-timeout" name="platform/external/rust/crates/hyper-timeout" groups="pdk" />
-  <project path="external/rust/crates/ident_case" name="platform/external/rust/crates/ident_case" groups="pdk" />
-  <project path="external/rust/crates/idna" name="platform/external/rust/crates/idna" groups="pdk" />
-  <project path="external/rust/crates/indexmap" name="platform/external/rust/crates/indexmap" groups="pdk" />
-  <project path="external/rust/crates/instant" name="platform/external/rust/crates/instant" groups="pdk" />
-  <project path="external/rust/crates/intrusive-collections" name="platform/external/rust/crates/intrusive-collections" groups="pdk" />
-  <project path="external/rust/crates/itertools" name="platform/external/rust/crates/itertools" groups="pdk" />
-  <project path="external/rust/crates/itoa" name="platform/external/rust/crates/itoa" groups="pdk" />
-  <project path="external/rust/crates/jni" name="platform/external/rust/crates/jni" groups="pdk" />
-  <project path="external/rust/crates/jni-sys" name="platform/external/rust/crates/jni-sys" groups="pdk" />
-  <project path="external/rust/crates/kernlog" name="platform/external/rust/crates/kernlog" groups="pdk" />
-  <project path="external/rust/crates/lazy_static" name="platform/external/rust/crates/lazy_static" groups="pdk" />
-  <project path="external/rust/crates/lazycell" name="platform/external/rust/crates/lazycell" groups="pdk" />
-  <project path="external/rust/crates/libbpf-rs" name="platform/external/rust/crates/libbpf-rs" groups="pdk" />
-  <project path="external/rust/crates/libbpf-sys" name="platform/external/rust/crates/libbpf-sys" groups="pdk" />
-  <project path="external/rust/crates/libc" name="platform/external/rust/crates/libc" groups="pdk" />
-  <project path="external/rust/crates/libfuzzer-sys" name="platform/external/rust/crates/libfuzzer-sys" groups="pdk" />
-  <project path="external/rust/crates/libloading" name="platform/external/rust/crates/libloading" groups="pdk" />
-  <project path="external/rust/crates/libm" name="platform/external/rust/crates/libm" groups="pdk" />
+  <project path="external/rust/crates/inotify-sys" name="platform/external/rust/crates/inotify-sys" groups="pdk" />
+  <project path="external/rust/crates/inotify" name="platform/external/rust/crates/inotify" groups="pdk" />
   <project path="external/rust/crates/libsqlite3-sys" name="platform/external/rust/crates/libsqlite3-sys" groups="pdk" />
-  <project path="external/rust/crates/libtest-mimic" name="platform/external/rust/crates/libtest-mimic" groups="pdk" />
-  <project path="external/rust/crates/libz-sys" name="platform/external/rust/crates/libz-sys" groups="pdk" />
-  <project path="external/rust/crates/linked-hash-map" name="platform/external/rust/crates/linked-hash-map" groups="pdk" />
-  <project path="external/rust/crates/linkme" name="platform/external/rust/crates/linkme" groups="pdk" />
-  <project path="external/rust/crates/linkme-impl" name="platform/external/rust/crates/linkme-impl" groups="pdk" />
-  <project path="external/rust/crates/litrs" name="platform/external/rust/crates/litrs" groups="pdk" />
-  <project path="external/rust/crates/lock_api" name="platform/external/rust/crates/lock_api" groups="pdk" />
-  <project path="external/rust/crates/log" name="platform/external/rust/crates/log" groups="pdk" />
-  <project path="external/rust/crates/lru-cache" name="platform/external/rust/crates/lru-cache" groups="pdk" />
-  <project path="external/rust/crates/lz4_flex" name="platform/external/rust/crates/lz4_flex" groups="pdk" />
-  <project path="external/rust/crates/macaddr" name="platform/external/rust/crates/macaddr" groups="pdk" />
-  <project path="external/rust/crates/managed" name="platform/external/rust/crates/managed" groups="pdk" />
-  <project path="external/rust/crates/matches" name="platform/external/rust/crates/matches" groups="trusty" />
-  <project path="external/rust/crates/matchit" name="platform/external/rust/crates/matchit" groups="pdk" />
-  <project path="external/rust/crates/maybe-async" name="platform/external/rust/crates/maybe-async" groups="pdk" />
-  <project path="external/rust/crates/memchr" name="platform/external/rust/crates/memchr" groups="pdk" />
-  <project path="external/rust/crates/memmap2" name="platform/external/rust/crates/memmap2" groups="pdk" />
-  <project path="external/rust/crates/memoffset" name="platform/external/rust/crates/memoffset" groups="pdk" />
-  <project path="external/rust/crates/merge" name="platform/external/rust/crates/merge" groups="pdk" />
-  <project path="external/rust/crates/merge_derive" name="platform/external/rust/crates/merge_derive" groups="pdk" />
-  <project path="external/rust/crates/miette" name="platform/external/rust/crates/miette" groups="pdk" />
-  <project path="external/rust/crates/miette-derive" name="platform/external/rust/crates/miette-derive" groups="pdk" />
-  <project path="external/rust/crates/mime" name="platform/external/rust/crates/mime" groups="pdk" />
-  <project path="external/rust/crates/minimal-lexical" name="platform/external/rust/crates/minimal-lexical" groups="pdk" />
-  <project path="external/rust/crates/mio" name="platform/external/rust/crates/mio" groups="pdk" />
-  <project path="external/rust/crates/mls-rs" name="platform/external/rust/crates/mls-rs" groups="pdk" />
-  <project path="external/rust/crates/mls-rs-codec" name="platform/external/rust/crates/mls-rs-codec" groups="pdk" />
-  <project path="external/rust/crates/mls-rs-codec-derive" name="platform/external/rust/crates/mls-rs-codec-derive" groups="pdk" />
-  <project path="external/rust/crates/mls-rs-core" name="platform/external/rust/crates/mls-rs-core" groups="pdk" />
-  <project path="external/rust/crates/mls-rs-crypto-traits" name="platform/external/rust/crates/mls-rs-crypto-traits" groups="pdk" />
-  <project path="external/rust/crates/mls-rs-uniffi" name="platform/external/rust/crates/mls-rs-uniffi" groups="pdk" />
-  <project path="external/rust/crates/mockall" name="platform/external/rust/crates/mockall" groups="pdk" />
-  <project path="external/rust/crates/mockall_derive" name="platform/external/rust/crates/mockall_derive" groups="pdk" />
-  <project path="external/rust/crates/moveit" name="platform/external/rust/crates/moveit" groups="pdk" />
-  <project path="external/rust/crates/named-lock" name="platform/external/rust/crates/named-lock" groups="pdk" />
-  <project path="external/rust/crates/nix" name="platform/external/rust/crates/nix" groups="pdk" />
-  <project path="external/rust/crates/no-panic" name="platform/external/rust/crates/no-panic" groups="pdk" />
-  <project path="external/rust/crates/nom" name="platform/external/rust/crates/nom" groups="pdk" />
-  <project path="external/rust/crates/num-bigint" name="platform/external/rust/crates/num-bigint" groups="pdk" />
-  <project path="external/rust/crates/num-complex" name="platform/external/rust/crates/num-complex" groups="pdk" />
-  <project path="external/rust/crates/num-derive" name="platform/external/rust/crates/num-derive" groups="pdk" />
-  <project path="external/rust/crates/num-integer" name="platform/external/rust/crates/num-integer" groups="pdk" />
-  <project path="external/rust/crates/num-traits" name="platform/external/rust/crates/num-traits" groups="pdk" />
-  <project path="external/rust/crates/num_cpus" name="platform/external/rust/crates/num_cpus" groups="pdk" />
-  <project path="external/rust/crates/num_enum" name="platform/external/rust/crates/num_enum" groups="pdk" />
-  <project path="external/rust/crates/num_enum_derive" name="platform/external/rust/crates/num_enum_derive" groups="pdk" />
-  <project path="external/rust/crates/octets" name="platform/external/rust/crates/octets" groups="pdk" />
-  <project path="external/rust/crates/once_cell" name="platform/external/rust/crates/once_cell" groups="pdk" />
-  <project path="external/rust/crates/oneshot-uniffi" name="platform/external/rust/crates/oneshot-uniffi" groups="pdk" />
-  <project path="external/rust/crates/oorandom" name="platform/external/rust/crates/oorandom" groups="pdk" />
+  <project path="external/rust/crates/libusb1-sys" name="platform/external/rust/crates/libusb1-sys" groups="pdk" />
+  <project path="external/rust/crates/maplit" name="platform/external/rust/crates/maplit" groups="pdk" />
   <project path="external/rust/crates/openssl" name="platform/external/rust/crates/openssl" groups="pdk" />
-  <project path="external/rust/crates/openssl-macros" name="platform/external/rust/crates/openssl-macros" groups="pdk" />
-  <project path="external/rust/crates/os_str_bytes" name="platform/external/rust/crates/os_str_bytes" groups="pdk" />
-  <project path="external/rust/crates/p9" name="platform/external/rust/crates/p9" groups="pdk" />
-  <project path="external/rust/crates/p9_wire_format_derive" name="platform/external/rust/crates/p9_wire_format_derive" groups="pdk" />
-  <project path="external/rust/crates/parking_lot" name="platform/external/rust/crates/parking_lot" groups="pdk" />
-  <project path="external/rust/crates/parking_lot_core" name="platform/external/rust/crates/parking_lot_core" groups="pdk" />
-  <project path="external/rust/crates/paste" name="platform/external/rust/crates/paste" groups="pdk" />
-  <project path="external/rust/crates/pathdiff" name="platform/external/rust/crates/pathdiff" groups="pdk" />
-  <project path="external/rust/crates/pdl-compiler" name="platform/external/rust/crates/pdl-compiler" groups="pdk" />
-  <project path="external/rust/crates/pdl-runtime" name="platform/external/rust/crates/pdl-runtime" groups="pdk" />
-  <project path="external/rust/crates/percent-encoding" name="platform/external/rust/crates/percent-encoding" groups="pdk" />
-  <project path="external/rust/crates/percore" name="platform/external/rust/crates/percore" groups="pdk" />
-  <project path="external/rust/crates/pest" name="platform/external/rust/crates/pest" groups="pdk" />
-  <project path="external/rust/crates/pest_derive" name="platform/external/rust/crates/pest_derive" groups="pdk" />
-  <project path="external/rust/crates/pest_generator" name="platform/external/rust/crates/pest_generator" groups="pdk" />
-  <project path="external/rust/crates/pest_meta" name="platform/external/rust/crates/pest_meta" groups="pdk" />
-  <project path="external/rust/crates/petgraph" name="platform/external/rust/crates/petgraph" groups="pdk" />
-  <project path="external/rust/crates/pin-project" name="platform/external/rust/crates/pin-project" groups="pdk" />
-  <project path="external/rust/crates/pin-project-internal" name="platform/external/rust/crates/pin-project-internal" groups="pdk" />
-  <project path="external/rust/crates/pin-project-lite" name="platform/external/rust/crates/pin-project-lite" groups="pdk" />
-  <project path="external/rust/crates/pin-utils" name="platform/external/rust/crates/pin-utils" groups="pdk" />
-  <project path="external/rust/crates/pkcs1" name="platform/external/rust/crates/pkcs1" groups="pdk" />
-  <project path="external/rust/crates/pkcs8" name="platform/external/rust/crates/pkcs8" groups="pdk" />
-  <project path="external/rust/crates/plotters" name="platform/external/rust/crates/plotters" groups="pdk" />
-  <project path="external/rust/crates/plotters-backend" name="platform/external/rust/crates/plotters-backend" groups="pdk" />
-  <project path="external/rust/crates/plotters-svg" name="platform/external/rust/crates/plotters-svg" groups="pdk" />
-  <project path="external/rust/crates/ppv-lite86" name="platform/external/rust/crates/ppv-lite86" groups="pdk" />
-  <project path="external/rust/crates/predicates" name="platform/external/rust/crates/predicates" groups="pdk" />
-  <project path="external/rust/crates/predicates-core" name="platform/external/rust/crates/predicates-core" groups="pdk" />
-  <project path="external/rust/crates/predicates-tree" name="platform/external/rust/crates/predicates-tree" groups="pdk" />
-  <project path="external/rust/crates/prettyplease" name="platform/external/rust/crates/prettyplease" groups="pdk" />
-  <project path="external/rust/crates/proc-macro2" name="platform/external/rust/crates/proc-macro2" groups="pdk" />
-  <project path="external/rust/crates/protobuf" name="platform/external/rust/crates/protobuf" groups="pdk" />
-  <project path="external/rust/crates/protobuf-codegen" name="platform/external/rust/crates/protobuf-codegen" groups="pdk" />
-  <project path="external/rust/crates/protobuf-json-mapping" name="platform/external/rust/crates/protobuf-json-mapping" groups="pdk" />
-  <project path="external/rust/crates/protobuf-parse" name="platform/external/rust/crates/protobuf-parse" groups="pdk" />
-  <project path="external/rust/crates/protobuf-support" name="platform/external/rust/crates/protobuf-support" groups="pdk" />
+  <project path="external/rust/crates/ptr_meta" name="platform/external/rust/crates/ptr_meta" groups="pdk" />
+  <project path="external/rust/crates/ptr_meta_derive" name="platform/external/rust/crates/ptr_meta_derive" groups="pdk" />
   <project path="external/rust/crates/quiche" name="platform/external/rust/crates/quiche" groups="pdk" />
-  <project path="external/rust/crates/quickcheck" name="platform/external/rust/crates/quickcheck" groups="pdk" />
-  <project path="external/rust/crates/quote" name="platform/external/rust/crates/quote" groups="pdk" />
-  <project path="external/rust/crates/rand" name="platform/external/rust/crates/rand" groups="pdk" />
-  <project path="external/rust/crates/rand_chacha" name="platform/external/rust/crates/rand_chacha" groups="pdk" />
-  <project path="external/rust/crates/rand_core" name="platform/external/rust/crates/rand_core" groups="pdk" />
-  <project path="external/rust/crates/rand_xorshift" name="platform/external/rust/crates/rand_xorshift" groups="pdk" />
-  <project path="external/rust/crates/rayon" name="platform/external/rust/crates/rayon" groups="pdk" />
-  <project path="external/rust/crates/rayon-core" name="platform/external/rust/crates/rayon-core" groups="pdk" />
-  <project path="external/rust/crates/regex" name="platform/external/rust/crates/regex" groups="pdk" />
-  <project path="external/rust/crates/regex-automata" name="platform/external/rust/crates/regex-automata" groups="pdk" />
-  <project path="external/rust/crates/regex-syntax" name="platform/external/rust/crates/regex-syntax" groups="pdk" />
-  <project path="external/rust/crates/remain" name="platform/external/rust/crates/remain" groups="pdk" />
-  <project path="external/rust/crates/remove_dir_all" name="platform/external/rust/crates/remove_dir_all" groups="pdk" />
-  <project path="external/rust/crates/ring" name="platform/external/rust/crates/ring" groups="pdk" />
-  <project path="external/rust/crates/rusqlite" name="platform/external/rust/crates/rusqlite" groups="pdk" />
-  <project path="external/rust/crates/rustc-demangle" name="platform/external/rust/crates/rustc-demangle" groups="pdk" />
-  <project path="external/rust/crates/rustc-demangle-capi" name="platform/external/rust/crates/rustc-demangle-capi" groups="pdk" />
-  <project path="external/rust/crates/rustc-hash" name="platform/external/rust/crates/rustc-hash" groups="pdk" />
-  <project path="external/rust/crates/rustix" name="platform/external/rust/crates/rustix" groups="pdk" />
-  <project path="external/rust/crates/rust-stemmers" name="platform/external/rust/crates/rust-stemmers" groups="pdk" />
-  <project path="external/rust/crates/rustversion" name="platform/external/rust/crates/rustversion" groups="pdk" />
-  <project path="external/rust/crates/ryu" name="platform/external/rust/crates/ryu" groups="pdk" />
-  <project path="external/rust/crates/same-file" name="platform/external/rust/crates/same-file" groups="pdk" />
-  <project path="external/rust/crates/scopeguard" name="platform/external/rust/crates/scopeguard" groups="pdk" />
-  <project path="external/rust/crates/sec1" name="platform/external/rust/crates/sec1" groups="pdk" />
-  <project path="external/rust/crates/semver" name="platform/external/rust/crates/semver" groups="pdk" />
-  <project path="external/rust/crates/serde" name="platform/external/rust/crates/serde" groups="pdk" />
-  <project path="external/rust/crates/serde-xml-rs" name="platform/external/rust/crates/serde-xml-rs" groups="pdk" />
-  <project path="external/rust/crates/serde_cbor" name="platform/external/rust/crates/serde_cbor" groups="pdk" />
-  <project path="external/rust/crates/serde_derive" name="platform/external/rust/crates/serde_derive" groups="pdk" />
-  <project path="external/rust/crates/serde_json" name="platform/external/rust/crates/serde_json" groups="pdk" />
-  <project path="external/rust/crates/serde_spanned" name="platform/external/rust/crates/serde_spanned" groups="pdk" />
-  <project path="external/rust/crates/serde_test" name="platform/external/rust/crates/serde_test" groups="pdk" />
-  <project path="external/rust/crates/serde_yaml" name="platform/external/rust/crates/serde_yaml" groups="pdk" />
-  <project path="external/rust/crates/sharded-slab" name="platform/external/rust/crates/sharded-slab" groups="pdk" />
-  <project path="external/rust/crates/shared_child" name="platform/external/rust/crates/shared_child" groups="pdk" />
-  <project path="external/rust/crates/shared_library" name="platform/external/rust/crates/shared_library" groups="pdk" />
-  <project path="external/rust/crates/shlex" name="platform/external/rust/crates/shlex" groups="pdk" />
-  <project path="external/rust/crates/siphasher" name="platform/external/rust/crates/siphasher" groups="pdk" />
-  <project path="external/rust/crates/slab" name="platform/external/rust/crates/slab" groups="pdk" />
-  <project path="external/rust/crates/smallvec" name="platform/external/rust/crates/smallvec" groups="pdk" />
-  <project path="external/rust/crates/smccc" name="platform/external/rust/crates/smccc" groups="pdk" />
-  <project path="external/rust/crates/socket2" name="platform/external/rust/crates/socket2" groups="pdk" />
-  <project path="external/rust/crates/spin" name="platform/external/rust/crates/spin" groups="pdk" />
-  <project path="external/rust/crates/spki" name="platform/external/rust/crates/spki" groups="pdk" />
-  <project path="external/rust/crates/static_assertions" name="platform/external/rust/crates/static_assertions" groups="pdk" />
-  <project path="external/rust/crates/strsim" name="platform/external/rust/crates/strsim" groups="pdk" />
-  <project path="external/rust/crates/strum" name="platform/external/rust/crates/strum" groups="pdk" />
-  <project path="external/rust/crates/strum_macros" name="platform/external/rust/crates/strum_macros" groups="pdk" />
-  <project path="external/rust/crates/syn" name="platform/external/rust/crates/syn" groups="pdk" />
-  <project path="external/rust/crates/syn-mid" name="platform/external/rust/crates/syn-mid" groups="pdk" />
-  <project path="external/rust/crates/sync_wrapper" name="platform/external/rust/crates/sync_wrapper" groups="pdk" />
-  <project path="external/rust/crates/synstructure" name="platform/external/rust/crates/synstructure" groups="pdk" />
-  <project path="external/rust/crates/tempfile" name="platform/external/rust/crates/tempfile" groups="pdk" />
-  <project path="external/rust/crates/termcolor" name="platform/external/rust/crates/termcolor" groups="pdk" />
-  <project path="external/rust/crates/termtree" name="platform/external/rust/crates/termtree" groups="pdk" />
-  <project path="external/rust/crates/textwrap" name="platform/external/rust/crates/textwrap" groups="pdk" />
-  <project path="external/rust/crates/thiserror" name="platform/external/rust/crates/thiserror" groups="pdk" />
-  <project path="external/rust/crates/thiserror-impl" name="platform/external/rust/crates/thiserror-impl" groups="pdk" />
-  <project path="external/rust/crates/thread_local" name="platform/external/rust/crates/thread_local" groups="pdk" />
-  <project path="external/rust/crates/threadpool" name="platform/external/rust/crates/threadpool" groups="pdk" />
-  <project path="external/rust/crates/tikv-jemalloc-sys" name="platform/external/rust/crates/tikv-jemalloc-sys" groups="pdk" />
-  <project path="external/rust/crates/tikv-jemallocator" name="platform/external/rust/crates/tikv-jemallocator" groups="pdk" />
-  <project path="external/rust/crates/tinyjson" name="platform/external/rust/crates/tinyjson" groups="pdk" />
-  <project path="external/rust/crates/tinytemplate" name="platform/external/rust/crates/tinytemplate" groups="pdk" />
-  <project path="external/rust/crates/tinyvec" name="platform/external/rust/crates/tinyvec" groups="pdk" />
-  <project path="external/rust/crates/tinyvec_macros" name="platform/external/rust/crates/tinyvec_macros" groups="pdk" />
-  <project path="external/rust/crates/tokio" name="platform/external/rust/crates/tokio" groups="pdk" />
-  <project path="external/rust/crates/tokio-io-timeout" name="platform/external/rust/crates/tokio-io-timeout" groups="pdk" />
-  <project path="external/rust/crates/tokio-macros" name="platform/external/rust/crates/tokio-macros" groups="pdk" />
-  <project path="external/rust/crates/tokio-stream" name="platform/external/rust/crates/tokio-stream" groups="pdk" />
-  <project path="external/rust/crates/tokio-test" name="platform/external/rust/crates/tokio-test" groups="pdk" />
-  <project path="external/rust/crates/tokio-util" name="platform/external/rust/crates/tokio-util" groups="pdk" />
-  <project path="external/rust/crates/toml" name="platform/external/rust/crates/toml" groups="pdk" />
-  <project path="external/rust/crates/toml_datetime" name="platform/external/rust/crates/toml_datetime" groups="pdk" />
-  <project path="external/rust/crates/toml_edit" name="platform/external/rust/crates/toml_edit" groups="pdk" />
-  <project path="external/rust/crates/tonic" name="platform/external/rust/crates/tonic" groups="pdk" />
-  <project path="external/rust/crates/tower" name="platform/external/rust/crates/tower" groups="pdk" />
-  <project path="external/rust/crates/tower-layer" name="platform/external/rust/crates/tower-layer" groups="pdk" />
-  <project path="external/rust/crates/tower-service" name="platform/external/rust/crates/tower-service" groups="pdk" />
-  <project path="external/rust/crates/tracing" name="platform/external/rust/crates/tracing" groups="pdk" />
-  <project path="external/rust/crates/tracing-attributes" name="platform/external/rust/crates/tracing-attributes" groups="pdk" />
-  <project path="external/rust/crates/tracing-core" name="platform/external/rust/crates/tracing-core" groups="pdk" />
-  <project path="external/rust/crates/tracing-subscriber" name="platform/external/rust/crates/tracing-subscriber" groups="pdk" />
-  <project path="external/rust/crates/try-lock" name="platform/external/rust/crates/try-lock" groups="pdk" />
-  <project path="external/rust/crates/tungstenite" name="platform/external/rust/crates/tungstenite" groups="pdk" />
-  <project path="external/rust/crates/twox-hash" name="platform/external/rust/crates/twox-hash" groups="pdk" />
-  <project path="external/rust/crates/ucd-trie" name="platform/external/rust/crates/ucd-trie" groups="pdk" />
-  <project path="external/rust/crates/unicode-bidi" name="platform/external/rust/crates/unicode-bidi" groups="pdk" />
-  <project path="external/rust/crates/unicode-ident" name="platform/external/rust/crates/unicode-ident" groups="pdk" />
-  <project path="external/rust/crates/unicode-normalization" name="platform/external/rust/crates/unicode-normalization" groups="pdk" />
-  <project path="external/rust/crates/unicode-segmentation" name="platform/external/rust/crates/unicode-segmentation" groups="pdk" />
-  <project path="external/rust/crates/unicode-width" name="platform/external/rust/crates/unicode-width" groups="pdk" />
-  <project path="external/rust/crates/unicode-xid" name="platform/external/rust/crates/unicode-xid" groups="pdk" />
-  <project path="external/rust/crates/uniffi" name="platform/external/rust/crates/uniffi" groups="pdk" />
-  <project path="external/rust/crates/uniffi_checksum_derive" name="platform/external/rust/crates/uniffi_checksum_derive" groups="pdk" />
-  <project path="external/rust/crates/uniffi_core" name="platform/external/rust/crates/uniffi_core" groups="pdk" />
-  <project path="external/rust/crates/uniffi_macros" name="platform/external/rust/crates/uniffi_macros" groups="pdk" />
-  <project path="external/rust/crates/uniffi_meta" name="platform/external/rust/crates/uniffi_meta" groups="pdk" />
-  <project path="external/rust/crates/unsafe-libyaml" name="platform/external/rust/crates/unsafe-libyaml" groups="pdk" />
-  <project path="external/rust/crates/untrusted" name="platform/external/rust/crates/untrusted" groups="pdk" />
-  <project path="external/rust/crates/url" name="platform/external/rust/crates/url" groups="pdk" />
-  <project path="external/rust/crates/userfaultfd" name="platform/external/rust/crates/userfaultfd" groups="pdk" />
-  <project path="external/rust/crates/userfaultfd-sys" name="platform/external/rust/crates/userfaultfd-sys" groups="pdk" />
-  <project path="external/rust/crates/utf-8" name="platform/external/rust/crates/utf-8" groups="pdk" />
-  <project path="external/rust/crates/uuid" name="platform/external/rust/crates/uuid" groups="pdk" />
-  <project path="external/rust/crates/vhost" name="platform/external/rust/crates/vhost" groups="pdk" />
+  <project path="external/rust/crates/rusb" name="platform/external/rust/crates/rusb" groups="pdk" />
+  <project path="external/rust/crates/ucs2" name="platform/external/rust/crates/ucs2" groups="pdk" />
+  <project path="external/rust/crates/uefi" name="platform/external/rust/crates/uefi" groups="pdk" />
+  <project path="external/rust/crates/uefi-macros" name="platform/external/rust/crates/uefi-macros" groups="pdk" />
+  <project path="external/rust/crates/uefi-raw" name="platform/external/rust/crates/uefi-raw" groups="pdk" />
+  <project path="external/rust/crates/uguid" name="platform/external/rust/crates/uguid" groups="pdk" />
+  <project path="external/rust/crates/v4l2r" name="platform/external/rust/crates/v4l2r" groups="pdk" />
   <project path="external/rust/crates/vhost-device-vsock" name="platform/external/rust/crates/vhost-device-vsock" groups="pdk" />
-  <project path="external/rust/crates/vsprintf" name="platform/external/rust/crates/vsprintf" groups="pdk" />
-  <project path="external/rust/crates/vhost-user-backend" name="platform/external/rust/crates/vhost-user-backend" groups="pdk" />
-  <project path="external/rust/crates/virtio-bindings" name="platform/external/rust/crates/virtio-bindings" groups="pdk" />
-  <project path="external/rust/crates/virtio-drivers" name="platform/external/rust/crates/virtio-drivers" groups="pdk" />
-  <project path="external/rust/crates/virtio-queue" name="platform/external/rust/crates/virtio-queue" groups="pdk" />
-  <project path="external/rust/crates/virtio-vsock" name="platform/external/rust/crates/virtio-vsock" groups="pdk" />
-  <project path="external/rust/crates/vm-memory" name="platform/external/rust/crates/vm-memory" groups="pdk" />
-  <project path="external/rust/crates/vmm-sys-util" name="platform/external/rust/crates/vmm-sys-util" groups="pdk" />
-  <project path="external/rust/crates/vsock" name="platform/external/rust/crates/vsock" groups="pdk" />
-  <project path="external/rust/crates/vulkano" name="platform/external/rust/crates/vulkano" groups="pdk" />
-  <project path="external/rust/crates/walkdir" name="platform/external/rust/crates/walkdir" groups="pdk" />
-  <project path="external/rust/crates/want" name="platform/external/rust/crates/want" groups="pdk" />
-  <project path="external/rust/crates/weak-table" name="platform/external/rust/crates/weak-table" groups="pdk" />
-  <project path="external/rust/crates/webpki" name="platform/external/rust/crates/webpki" groups="pdk" />
-  <project path="external/rust/crates/which" name="platform/external/rust/crates/which" groups="pdk" />
-  <project path="external/rust/crates/winnow" name="platform/external/rust/crates/winnow" groups="pdk" />
-  <project path="external/rust/crates/x509-cert" name="platform/external/rust/crates/x509-cert" groups="pdk" />
-  <project path="external/rust/crates/xml-rs" name="platform/external/rust/crates/xml-rs" groups="pdk" />
-  <project path="external/rust/crates/yaml-rust" name="platform/external/rust/crates/yaml-rust" groups="pdk" />
-  <project path="external/rust/crates/zerocopy" name="platform/external/rust/crates/zerocopy" groups="pdk" />
-  <project path="external/rust/crates/zerocopy-derive" name="platform/external/rust/crates/zerocopy-derive" groups="pdk" />
-  <project path="external/rust/crates/zeroize" name="platform/external/rust/crates/zeroize" groups="pdk" />
-  <project path="external/rust/crates/zeroize_derive" name="platform/external/rust/crates/zeroize_derive" groups="pdk" />
-  <project path="external/rust/crates/zip" name="platform/external/rust/crates/zip" groups="pdk" />
   <project path="external/rust/beto-rust" name="platform/external/rust/beto-rust" groups="pdk" />
+  <project path="external/rust/cros-libva" name="platform/external/rust/cros-libva" groups="pdk" />
   <project path="external/rust/cxx" name="platform/external/rust/cxx" groups="pdk" />
   <project path="external/rust/autocxx" name="platform/external/rust/autocxx" groups="pdk" />
   <project path="external/rust/pica" name="platform/external/rust/pica" groups="pdk" />
@@ -952,19 +598,21 @@
   <project path="external/tpm2-tss" name="platform/external/tpm2-tss" groups="pdk" />
   <project path="external/trace-cmd" name="platform/external/trace-cmd" groups="pdk" />
   <project path="external/tremolo" name="platform/external/tremolo" groups="pdk" />
-  <project path="external/trusty/arm-trusted-firmware" name="trusty/external/trusted-firmware-a" groups="trusty" />
-  <project path="external/trusty/bootloader" name="trusty/external/trusty" groups="trusty" />
-  <project path="external/trusty/headers" name="trusty/external/headers" groups="trusty" />
-  <project path="external/trusty/lk" name="trusty/lk/common" groups="trusty" />
-  <project path="external/trusty/musl" name="trusty/external/musl" groups="trusty" />
+  <project path="external/trusty/arm-trusted-firmware" name="trusty/external/trusted-firmware-a" groups="trusty,pdk" />
+  <project path="external/trusty/bootloader" name="trusty/external/trusty" groups="trusty,pdk" />
+  <project path="external/trusty/headers" name="trusty/external/headers" groups="trusty,pdk" />
+  <project path="external/trusty/lk" name="trusty/lk/common" groups="trusty,pdk" />
+  <project path="external/trusty/musl" name="trusty/external/musl" groups="trusty,pdk" />
   <project path="external/truth" name="platform/external/truth" groups="pdk" />
   <project path="external/turbine" name="platform/external/turbine" groups="pdk" />
+  <project path="external/ublksrv" name="platform/external/ublksrv" groups="pdk" />
   <project path="external/unicode" name="platform/external/unicode" groups="pdk" />
   <project path="external/universal-tween-engine" name="platform/external/universal-tween-engine" />
   <project path="external/uwb" name="platform/external/uwb" groups="pdk" />
   <project path="external/v4l2_codec2" name="platform/external/v4l2_codec2" groups="pdk" />
   <project path="external/vboot_reference" name="platform/external/vboot_reference" groups="pdk" />
   <project path="external/virglrenderer" name="platform/external/virglrenderer" groups="pdk" />
+  <project path="external/virtio-media" name="platform/external/virtio-media" groups="pdk" />
   <project path="external/vixl" name="platform/external/vixl" groups="pdk" />
   <project path="external/vogar" name="platform/external/vogar" groups="pdk" />
   <project path="external/volley" name="platform/external/volley" groups="pdk" />
@@ -1031,16 +679,16 @@
   <project path="hardware/google/apf" name="platform/hardware/google/apf" groups="pdk" />
   <project path="hardware/google/av" name="platform/hardware/google/av" groups="pdk" />
   <project path="hardware/google/camera" name="platform/hardware/google/camera" groups="pdk" />
-  <project path="hardware/google/gchips" name="platform/hardware/google/gchips" groups="pdk-lassen,pdk-gs-arm" />
+  <project path="hardware/google/gchips" name="platform/hardware/google/gchips" groups="pdk-lassen,pdk-gs-arm,pdk-gs-imgtec" />
   <project path="hardware/google/gfxstream" name="platform/hardware/google/gfxstream" groups="pdk" />
-  <project path="hardware/google/graphics/common" name="platform/hardware/google/graphics/common" groups="pdk-lassen,pdk-gs-arm" />
+  <project path="hardware/google/graphics/common" name="platform/hardware/google/graphics/common" groups="pdk-lassen,pdk-gs-arm,pdk-gs-imgtec" />
   <project path="hardware/google/graphics/gs101" name="platform/hardware/google/graphics/gs101" groups="pdk-lassen,pdk-gs-arm" />
   <project path="hardware/google/graphics/gs201" name="platform/hardware/google/graphics/gs201" groups="cloudripper,pdk-gs-arm" />
   <project path="hardware/google/graphics/zuma" name="platform/hardware/google/graphics/zuma" groups="ripcurrent,pdk-gs-arm" />
   <project path="hardware/google/graphics/zumapro" name="platform/hardware/google/graphics/zumapro" groups="ripcurrentpro" />
   <project path="hardware/google/interfaces" name="platform/hardware/google/interfaces" groups="pdk,sysui-studio" />
-  <project path="hardware/google/pixel" name="platform/hardware/google/pixel" groups="generic_fs,pixel,pdk-gs-arm" />
-  <project path="hardware/google/pixel-sepolicy" name="platform/hardware/google/pixel-sepolicy" groups="generic_fs,pixel" />
+  <project path="hardware/google/pixel" name="platform/hardware/google/pixel" groups="generic_fs,pixel,pdk-gs-arm,pdk-gs-imgtec,pdk-desktop" />
+  <project path="hardware/google/pixel-sepolicy" name="platform/hardware/google/pixel-sepolicy" groups="generic_fs,pixel,pdk-desktop" />
   <project path="hardware/interfaces" name="platform/hardware/interfaces" groups="pdk,sysui-studio" />
   <project path="hardware/invensense" name="platform/hardware/invensense" groups="invensense,pdk" />
   <project path="hardware/libhardware" name="platform/hardware/libhardware" groups="pdk" />
@@ -1095,6 +743,7 @@
   <project path="packages/apps/Car/Provision" name="platform/packages/apps/Car/Provision" groups="pdk-fs" />
   <project path="packages/apps/Car/RadioPrebuilt" name="platform/packages/apps/Car/RadioPrebuilt" groups="pdk-fs" />
   <project path="packages/apps/Car/RotaryController" name="platform/packages/apps/Car/RotaryController" groups="pdk-fs" />
+  <project path="packages/apps/Car/RotaryImePrebuilt" name="platform/packages/apps/Car/RotaryImePrebuilt" groups="pdk-fs" />
   <project path="packages/apps/Car/Settings" name="platform/packages/apps/Car/Settings" groups="pdk-fs" />
   <project path="packages/apps/Car/SettingsIntelligence" name="platform/packages/apps/Car/SettingsIntelligence" groups="pdk-fs" />
   <project path="packages/apps/Car/systemlibs" name="platform/packages/apps/Car/systemlibs" groups="pdk-fs,pdk-cw-tvc" />
@@ -1121,6 +770,7 @@
   <project path="packages/apps/ManagedProvisioning" name="platform/packages/apps/ManagedProvisioning" groups="pdk-fs" />
   <project path="external/android_onboarding" name="platform/external/android_onboarding" groups="pdk-fs" />
   <project path="packages/apps/Messaging" name="platform/packages/apps/Messaging" groups="pdk-fs" />
+  <project path="packages/apps/Multiuser" name="platform/packages/apps/Multiuser" groups="pdk-fs" />
   <project path="packages/apps/Music" name="platform/packages/apps/Music" groups="pdk-fs" />
   <project path="packages/apps/MusicFX" name="platform/packages/apps/MusicFX" groups="pdk-fs" />
   <project path="packages/apps/Nfc" name="platform/packages/apps/Nfc" groups="apps_nfc,pdk-fs,pdk-cw-fs" />
@@ -1275,7 +925,6 @@
   <project path="prebuilts/r8" name="platform/prebuilts/r8" groups="pdk,sysui-studio" clone-depth="1" />
   <project path="prebuilts/sdk" name="platform/prebuilts/sdk" groups="pdk,sysui-studio" clone-depth="1" />
   <project path="prebuilts/tools" name="platform/prebuilts/tools" groups="pdk,tools,sysui-studio" clone-depth="1" />
-  <project path="prebuilts/vndk/v29" name="platform/prebuilts/vndk/v29" groups="pdk" clone-depth="1" />
   <project path="prebuilts/vndk/v30" name="platform/prebuilts/vndk/v30" groups="pdk" clone-depth="1" />
   <project path="prebuilts/vndk/v31" name="platform/prebuilts/vndk/v31" groups="pdk" clone-depth="1" />
   <project path="prebuilts/vndk/v32" name="platform/prebuilts/vndk/v32" groups="pdk" clone-depth="1" />
@@ -1320,6 +969,7 @@
   <project path="system/memory/libmemtrack" name="platform/system/memory/libmemtrack" groups="pdk" />
   <project path="system/memory/libmemunreachable" name="platform/system/memory/libmemunreachable" groups="pdk" />
   <project path="system/memory/lmkd" name="platform/system/memory/lmkd" groups="pdk" />
+  <project path="system/memory/mmd" name="platform/system/memory/mmd" groups="pdk" />
   <project path="system/netd" name="platform/system/netd" groups="pdk" />
   <project path="system/nfc" name="platform/system/nfc" groups="pdk" />
   <project path="system/nvram" name="platform/system/nvram" groups="pdk" />
@@ -1337,6 +987,7 @@
   <project path="system/tools/xsdc" name="platform/system/tools/xsdc" groups="pdk" />
   <project path="system/unwinding" name="platform/system/unwinding" groups="pdk" />
   <project path="system/update_engine" name="platform/system/update_engine" groups="pdk" />
+  <project path="system/usb_info_tools" name="platform/system/usb_info_tools" groups="pdk" />
   <project path="system/vold" name="platform/system/vold" groups="pdk" />
   <project path="test/dittosuite" name="platform/test/dittosuite" groups="pdk" />
   <project path="test/robolectric-extensions" name="platform/test/robolectric-extensions"  groups="pdk-cw-fs,pdk-fs,sysui-studio" />
@@ -1361,7 +1012,7 @@
   <project path="tools/apifinder" name="platform/tools/apifinder" groups="pdk,tools" />
   <project path="tools/apksig" name="platform/tools/apksig" groups="pdk,tradefed" />
   <project path="tools/apkzlib" name="platform/tools/apkzlib" groups="pdk,tradefed" />
-  <project path="tools/asuite" name="platform/tools/asuite" groups="pdk" />
+  <project path="tools/asuite" name="platform/tools/asuite" groups="pdk,sysui-studio" />
   <project path="tools/carrier_settings" name="platform/tools/carrier_settings" groups="tools" />
   <project path="tools/content_addressed_storage/prebuilts" name="platform/tools/content_addressed_storage/prebuilts" groups="pdk,tools" />
   <project path="tools/currysrc" name="platform/tools/currysrc" groups="pdk" />
@@ -1386,27 +1037,28 @@
   <project path="tools/tradefederation/prebuilts" name="platform/tools/tradefederation/prebuilts" groups="pdk,tradefed" clone-depth="1" />
   <project path="tools/treble" name="platform/tools/treble" groups="tools,pdk" />
   <project path="tools/trebuchet" name="platform/tools/trebuchet" groups="tools,cts,pdk,pdk-cw-fs,pdk-fs" />
-  <project path="trusty/device/arm/generic-arm64" name="trusty/device/arm/generic-arm64" groups="trusty" />
-  <project path="trusty/device/arm/vexpress-a15" name="trusty/device/arm/vexpress-a15" groups="trusty" />
-  <project path="trusty/device/nxp/imx7d" name="trusty/device/nxp/imx7d" groups="trusty" />
-  <project path="trusty/device/x86/generic-x86_64" name="trusty/device/x86/generic-x86_64" groups="trusty" />
-  <project path="trusty/hardware/nxp" name="trusty/lk/nxp" groups="trusty" />
-  <project path="trusty/host/common" name="trusty/host/common" groups="trusty">
+  <project path="trusty/device/arm/generic-arm64" name="trusty/device/arm/generic-arm64" groups="trusty,pdk" />
+  <project path="trusty/device/arm/vexpress-a15" name="trusty/device/arm/vexpress-a15" groups="trusty,pdk" />
+  <project path="trusty/device/nxp/imx7d" name="trusty/device/nxp/imx7d" groups="trusty,pdk" />
+  <project path="trusty/device/x86/generic-x86_64" name="trusty/device/x86/generic-x86_64" groups="trusty,pdk" />
+  <project path="trusty/hardware/nxp" name="trusty/lk/nxp" groups="trusty,pdk" />
+  <project path="trusty/host/common" name="trusty/host/common" groups="trusty,pdk">
     <linkfile src="bazel/WORKSPACE.bazel" dest="trusty/WORKSPACE.bazel" />
     <linkfile src="bazel/bazelrc" dest="trusty/.bazelrc" />
   </project>
-  <project path="trusty/kernel" name="trusty/lk/trusty" groups="trusty" />
-  <project path="trusty/user/app/avb" name="trusty/app/avb" groups="trusty" />
-  <project path="trusty/user/app/cast-auth" name="trusty/app/cast-auth" groups="trusty" />
-  <project path="trusty/user/app/confirmationui" name="trusty/app/confirmationui" groups="trusty" />
-  <project path="trusty/user/app/gatekeeper" name="trusty/app/gatekeeper" groups="trusty" />
-  <project path="trusty/user/app/keymaster" name="trusty/app/keymaster" groups="trusty" />
-  <project path="trusty/user/app/keymint" name="trusty/app/keymint" groups="trusty" />
-  <project path="trusty/user/app/sample" name="trusty/app/sample" groups="trusty" />
-  <project path="trusty/user/app/secretkeeper" name="trusty/app/secretkeeper" groups="trusty" />
-  <project path="trusty/user/app/storage" name="trusty/app/storage" groups="trusty" />
-  <project path="trusty/user/base" name="trusty/lib" groups="trusty" />
-  <project path="trusty/vendor/google/aosp" name="trusty/vendor/google/aosp" groups="trusty" >
+  <project path="trusty/kernel" name="trusty/lk/trusty" groups="trusty,pdk" />
+  <project path="trusty/user/app/authmgr" name="trusty/app/authmgr" groups="trusty,pdk" />
+  <project path="trusty/user/app/avb" name="trusty/app/avb" groups="trusty,pdk" />
+  <project path="trusty/user/app/cast-auth" name="trusty/app/cast-auth" groups="trusty,pdk" />
+  <project path="trusty/user/app/confirmationui" name="trusty/app/confirmationui" groups="trusty,pdk" />
+  <project path="trusty/user/app/gatekeeper" name="trusty/app/gatekeeper" groups="trusty,pdk" />
+  <project path="trusty/user/app/keymaster" name="trusty/app/keymaster" groups="trusty,pdk" />
+  <project path="trusty/user/app/keymint" name="trusty/app/keymint" groups="trusty,pdk" />
+  <project path="trusty/user/app/sample" name="trusty/app/sample" groups="trusty,pdk" />
+  <project path="trusty/user/app/secretkeeper" name="trusty/app/secretkeeper" groups="trusty,pdk" />
+  <project path="trusty/user/app/storage" name="trusty/app/storage" groups="trusty,pdk" />
+  <project path="trusty/user/base" name="trusty/lib" groups="trusty,pdk" />
+  <project path="trusty/vendor/google/aosp" name="trusty/vendor/google/aosp" groups="trusty,pdk">
     <copyfile src="lk_inc.mk" dest="lk_inc.mk" />
   </project>
   <!-- END open-source projects -->
```

