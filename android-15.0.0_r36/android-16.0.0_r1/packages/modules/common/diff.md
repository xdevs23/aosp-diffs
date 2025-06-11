```diff
diff --git a/OWNERS b/OWNERS
index ad79640..c6cea76 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,16 +2,16 @@
 # Mainline modularization team
 
 amhk@google.com
-ancr@google.com
 dariofreni@google.com
 gurpreetgs@google.com
 harshitmahajan@google.com
 kalyssa@google.com
 marcots@google.com
+oyalcin@google.com
 paulduffin@google.com
 pedroql@google.com
+psych@google.com
 robertogil@google.com
-oyalcin@google.com
 
 # Escalations
 jham@google.com
diff --git a/PREBUILTS_MODULE_OWNERS b/PREBUILTS_MODULE_OWNERS
index f9bd4cb..21effee 100644
--- a/PREBUILTS_MODULE_OWNERS
+++ b/PREBUILTS_MODULE_OWNERS
@@ -9,7 +9,9 @@
 #
 # See go/mainline-owners-policy for more details.
 
+include platform/frameworks/base:/SDK_OWNERS
 include platform/packages/modules/common:/MODULES_OWNERS
+
 marielos@google.com #{LAST_RESORT_SUGGESTION}
 robojoe@google.com #{LAST_RESORT_SUGGESTION}
 andyq@google.com #{LAST_RESORT_SUGGESTION}
@@ -17,4 +19,4 @@ ahomer@google.com #{LAST_RESORT_SUGGESTION}
 robertogil@google.com #{LAST_RESORT_SUGGESTION}
 gurpreetgs@google.com #{LAST_RESORT_SUGGESTION}
 kalyssa@google.com #{LAST_RESORT_SUGGESTION}
-psych@google.com #{LAST_RESORT_SUGGESTION}
\ No newline at end of file
+psych@google.com #{LAST_RESORT_SUGGESTION}
diff --git a/build/Android.bp b/build/Android.bp
index 765b4c7..5f2b9a6 100644
--- a/build/Android.bp
+++ b/build/Android.bp
@@ -27,11 +27,6 @@ python_test_host {
     data: [
         "mainline_modules_sdks_test_data/**/*",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     test_suites: ["general-tests"],
 }
 
@@ -41,7 +36,7 @@ phony {
         "com.android.adbd",
         "com.android.adservices",
         "com.android.appsearch",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.configinfrastructure",
         "com.android.conscrypt",
         "com.android.devicelock",
diff --git a/build/allowed_deps.txt b/build/allowed_deps.txt
index 4c1db62..943419f 100644
--- a/build/allowed_deps.txt
+++ b/build/allowed_deps.txt
@@ -14,13 +14,17 @@
 # TODO(b/157465465): introduce automated quality signals and remove this list.
 
 aconfig_mediacodec_flags_c_lib(minSdkVersion:30)
+aconfig_settingslib_exported_flags_java_lib(minSdkVersion:30)
+aconfig_settingstheme_exported_flags_java_lib(minSdkVersion:21)
 aconfig_storage_file_java(minSdkVersion:29)
 aconfig_storage_reader_java(minSdkVersion:29)
 aconfigd-mainline(minSdkVersion:34)
+aconfigd_java_proto_lib(minSdkVersion:34)
+aconfigd_java_proto_lib_repackaged(minSdkVersion:34)
 aconfigd_java_proto_lite_lib(minSdkVersion:34)
 android.app.appfunctions.exported-flags-aconfig-java(minSdkVersion:30)
-android.app.ondeviceintelligence-aconfig-java(minSdkVersion:35)
 android.app.flags-aconfig-java(minSdkVersion:34)
+android.app.ondeviceintelligence-aconfig-java(minSdkVersion:35)
 android.companion.virtualdevice.flags-aconfig-java-export(minSdkVersion:30)
 android.content.pm.flags-aconfig-java-export(minSdkVersion:30)
 android.crashrecovery.flags-aconfig-java(minSdkVersion:35)
@@ -101,6 +105,7 @@ android.hardware.tetheroffload.control-V1.0-java(minSdkVersion:current)
 android.hardware.tetheroffload.control-V1.1-java(minSdkVersion:current)
 android.hardware.threadnetwork-V1-ndk(minSdkVersion:30)
 android.hardware.uwb-V1-ndk(minSdkVersion:Tiramisu)
+android.hardware.uwb-V1-rust(minSdkVersion:33)
 android.hardware.uwb-V1-rust(minSdkVersion:Tiramisu)
 android.hardware.wifi-V1-java(minSdkVersion:30)
 android.hardware.wifi-V1.0-java(minSdkVersion:30)
@@ -154,6 +159,7 @@ android.media.extractor.flags-aconfig-cc(minSdkVersion:29)
 android.media.swcodec.flags-aconfig-cc(minSdkVersion:apex_inherit)
 android.net.ipsec.ike(minSdkVersion:30)
 android.net.ipsec.ike.xml(minSdkVersion:(no version))
+android.net.vcn.flags-aconfig-java(minSdkVersion:35)
 android.net.wifi.flags-aconfig-java(minSdkVersion:30)
 android.nfc.flags-aconfig-java(minSdkVersion:34)
 android.os.flags-aconfig-java-export(minSdkVersion:30)
@@ -170,6 +176,8 @@ android.system.suspend-V1-ndk(minSdkVersion:Tiramisu)
 android.system.suspend.control-V1-ndk(minSdkVersion:30)
 android.system.wifi.mainline_supplicant-java(minSdkVersion:30)
 android.system.wifi.mainline_supplicant-ndk(minSdkVersion:30)
+android.xr.flags-aconfig-java(minSdkVersion:30)
+android.xr.flags-aconfig-java-export(minSdkVersion:30)
 android_checker_annotation_stubs(minSdkVersion:current)
 android_downloader_lib(minSdkVersion:30)
 android_nfc_flags_aconfig_c_lib(minSdkVersion:34)
@@ -183,6 +191,7 @@ apache-commons-io(minSdkVersion:33)
 apache-commons-lang(minSdkVersion:33)
 apache-velocity-engine-core(minSdkVersion:33)
 apache-xml(minSdkVersion:31)
+app-compat-annotations(minSdkVersion:current)
 appsearch_flags_java_lib(minSdkVersion:33)
 art-aconfig-flags-java-lib(minSdkVersion:31)
 art-aconfig-flags-lib(minSdkVersion:31)
@@ -198,6 +207,7 @@ avrcp_headers(minSdkVersion:30)
 bcm_object(minSdkVersion:29)
 bionic_libc_platform_headers(minSdkVersion:29)
 bluetooth-protos-nfc-enums-java-gen(minSdkVersion:35)
+bluetooth-protos-nfc-enums-java-gen(minSdkVersion:36)
 boringssl_self_test(minSdkVersion:29)
 bouncycastle(minSdkVersion:31)
 bouncycastle-unbundled(minSdkVersion:30)
@@ -227,6 +237,11 @@ clatd(minSdkVersion:30)
 codecs_g711dec(minSdkVersion:29)
 com.android.media.audio-aconfig-cc(minSdkVersion:29)
 com.android.media.audioserver-aconfig-cc(minSdkVersion:29)
+com.android.nfc.flags-aconfig-java(minSdkVersion:35)
+com.android.nfc.flags-aconfig-java(minSdkVersion:36)
+com.android.nfc.module.flags-aconfig-cpp(minSdkVersion:35)
+com.android.nfc.module.flags-aconfig-cpp(minSdkVersion:36)
+com.android.permission.flags-aconfig-java-export(minSdkVersion:30)
 com.android.vcard(minSdkVersion:9)
 com.google.android.material_material(minSdkVersion:21)
 com.uwb.support.aliro(minSdkVersion:30)
@@ -287,6 +302,7 @@ docsui-change-ids(minSdkVersion:29)
 docsui-flags-aconfig-java-lib(minSdkVersion:29)
 DocumentsUI-lib(minSdkVersion:29)
 DocumentsUIManifestLib(minSdkVersion:29)
+elfutils_headers(minSdkVersion:apex_inherit)
 ethtool(minSdkVersion:30)
 exoplayer-annotation_stubs(minSdkVersion:21)
 exoplayer-media_apex(minSdkVersion:21)
@@ -297,6 +313,7 @@ ExtServices(minSdkVersion:30)
 ExtServices(minSdkVersion:current)
 ExtServices-core(minSdkVersion:30)
 ExtServices-core(minSdkVersion:current)
+extservices-mainline-aconfig-java-lib(minSdkVersion:30)
 ExtServices-tplus(minSdkVersion:30)
 ExtServices-tplus(minSdkVersion:current)
 flatbuffer_headers(minSdkVersion:(no version))
@@ -307,12 +324,16 @@ fmtlib_headers(minSdkVersion:29)
 fmtlib_ndk(minSdkVersion:29)
 fp16_headers(minSdkVersion:30)
 framework-bluetooth(minSdkVersion:33)
+framework-connectivity-b(minSdkVersion:current)
+framework-connectivity-b.impl(minSdkVersion:current)
 framework-mediaprovider(minSdkVersion:30)
 framework-mediaprovider.impl(minSdkVersion:30)
-framework-ondeviceintelligence(minSdkVersion:35)
-framework-ondeviceintelligence.impl(minSdkVersion:35)
+framework-nfc(minSdkVersion:35)
 framework-nfc(minSdkVersion:current)
+framework-nfc.impl(minSdkVersion:35)
 framework-nfc.impl(minSdkVersion:current)
+framework-ondeviceintelligence(minSdkVersion:35)
+framework-ondeviceintelligence.impl(minSdkVersion:35)
 framework-permission(minSdkVersion:30)
 framework-permission(minSdkVersion:current)
 framework-permission-s(minSdkVersion:31)
@@ -338,15 +359,6 @@ gemmlowp_headers(minSdkVersion:apex_inherit)
 geotz_common(minSdkVersion:31)
 geotz_lookup(minSdkVersion:31)
 geotz_s2storage_ro(minSdkVersion:31)
-google.sdv.authz-aidl-V1-rust(minSdkVersion:34)
-google.sdv.identity-aidl-V1-rust(minSdkVersion:34)
-google.sdv.lifecycle.test-V1-ndk(minSdkVersion:34)
-google.sdv.lifecycle.test-V1-rust(minSdkVersion:34)
-google.sdv.rpc-aidl-V1-rust(minSdkVersion:34)
-google.sdv.sd-aidl-V1-rust(minSdkVersion:34)
-google.sdv.sd_common-aidl-V1-rust(minSdkVersion:34)
-google.sdv.service_discovery.common-aidl-V1-rust(minSdkVersion:34)
-google.sdv.service_discovery.discovery-aidl-V1-rust(minSdkVersion:34)
 GoogleCellBroadcastApp(minSdkVersion:29)
 GoogleCellBroadcastServiceModule(minSdkVersion:29)
 GoogleExtServices(minSdkVersion:30)
@@ -361,6 +373,7 @@ grpc-java-core-android(minSdkVersion:30)
 grpc-java-core-internal(minSdkVersion:30)
 grpc-java-core-util(minSdkVersion:30)
 grpc-java-okhttp(minSdkVersion:30)
+grpc-java-okhttp-client-lite(minSdkVersion:30)
 grpc-java-protobuf-lite(minSdkVersion:30)
 grpc-java-stub(minSdkVersion:30)
 guava(minSdkVersion:current)
@@ -378,7 +391,9 @@ ipmemorystore-aidl-interfaces-V10-java(minSdkVersion:29)
 ipmemorystore-aidl-interfaces-V10-java(minSdkVersion:30)
 ipmemorystore-aidl-interfaces-V11-java(minSdkVersion:30)
 jacocoagent(minSdkVersion:9)
+jakarta.inject(minSdkVersion:current)
 jni_headers(minSdkVersion:29)
+jni_platform_headers(minSdkVersion:31)
 jni_platform_headers(minSdkVersion:S)
 jspecify(minSdkVersion:1)
 jsr305(minSdkVersion:14)
@@ -394,9 +409,14 @@ kotlinx_serialization_core(minSdkVersion:current)
 ksoap2(minSdkVersion:30)
 libaacextractor(minSdkVersion:29)
 libabsl(minSdkVersion:apex_inherit)
+libaconfig_device_paths(minSdkVersion:34)
+libaconfig_flags(minSdkVersion:34)
+libaconfig_flags_rust(minSdkVersion:34)
 libaconfig_java_proto_lite(minSdkVersion:34)
 libaconfig_java_proto_lite(minSdkVersion:UpsideDownCake)
 libaconfig_new_storage_flags_rust(minSdkVersion:34)
+libaconfig_protos(minSdkVersion:34)
+libaconfig_rust_proto(minSdkVersion:34)
 libaconfig_storage_file(minSdkVersion:29)
 libaconfig_storage_protos(minSdkVersion:29)
 libaconfig_storage_protos_cc(minSdkVersion:29)
@@ -404,6 +424,7 @@ libaconfig_storage_read_api(minSdkVersion:29)
 libaconfig_storage_read_api_cc(minSdkVersion:29)
 libaconfig_storage_read_api_cxx_bridge(minSdkVersion:29)
 libaconfig_storage_write_api(minSdkVersion:34)
+libaconfig_test_rust_library(minSdkVersion:34)
 libaconfigd_protos_rust(minSdkVersion:34)
 libaconfigd_rust(minSdkVersion:34)
 libaconfigd_rust_proto(minSdkVersion:34)
@@ -415,7 +436,7 @@ libadbd_services(minSdkVersion:(no version))
 libadbd_services(minSdkVersion:30)
 libaddress_sorting(minSdkVersion:30)
 libahash(minSdkVersion:29)
-libahash(minSdkVersion:34)
+libaho_corasick(minSdkVersion:29)
 libaidlcommonsupport(minSdkVersion:29)
 liballoc.rust_sysroot(minSdkVersion:29)
 libalts_frame_protector(minSdkVersion:30)
@@ -427,8 +448,12 @@ libanstyle(minSdkVersion:29)
 libanyhow(minSdkVersion:29)
 libaom(minSdkVersion:29)
 libaom_arm_crc32(minSdkVersion:29)
+libaom_avx(minSdkVersion:29)
+libaom_avx2(minSdkVersion:29)
 libaom_neon_dotprod(minSdkVersion:29)
 libaom_neon_i8mm(minSdkVersion:29)
+libaom_sse4_1(minSdkVersion:29)
+libaom_sse4_2(minSdkVersion:29)
 libaom_sve(minSdkVersion:29)
 libaom_sve2(minSdkVersion:29)
 libapp_processes_protos_lite(minSdkVersion:(no version))
@@ -437,7 +462,6 @@ libarect(minSdkVersion:29)
 libarect_headers(minSdkVersion:29)
 libasync_safe(minSdkVersion:apex_inherit)
 libasync_stream(minSdkVersion:29)
-libasync_stream(minSdkVersion:34)
 libasyncio(minSdkVersion:(no version))
 libasyncio(minSdkVersion:apex_inherit)
 libatomic(minSdkVersion:(no version))
@@ -453,9 +477,7 @@ libavcdec(minSdkVersion:29)
 libavcenc(minSdkVersion:29)
 libavservices_minijail(minSdkVersion:29)
 libaxum(minSdkVersion:29)
-libaxum(minSdkVersion:34)
 libaxum_core(minSdkVersion:29)
-libaxum_core(minSdkVersion:34)
 libbacktrace(minSdkVersion:apex_inherit)
 libbacktrace_headers(minSdkVersion:apex_inherit)
 libbacktrace_rs.rust_sysroot(minSdkVersion:29)
@@ -467,9 +489,13 @@ libbase_ndk(minSdkVersion:29)
 libbinder_headers(minSdkVersion:29)
 libbinder_headers_base(minSdkVersion:29)
 libbinder_headers_platform_shared(minSdkVersion:29)
+libbinder_ndk_bindgen(minSdkVersion:33)
 libbinder_ndk_bindgen(minSdkVersion:Tiramisu)
+libbinder_ndk_sys(minSdkVersion:33)
 libbinder_ndk_sys(minSdkVersion:Tiramisu)
+libbinder_rs(minSdkVersion:33)
 libbinder_rs(minSdkVersion:Tiramisu)
+libbinder_tokio_rs(minSdkVersion:33)
 libbinder_tokio_rs(minSdkVersion:Tiramisu)
 libbinderthreadstateutils(minSdkVersion:29)
 libbitflags(minSdkVersion:29)
@@ -477,11 +503,13 @@ libbitflags-1.3.2(minSdkVersion:29)
 libbluetooth-types(minSdkVersion:29)
 libbluetooth-types-header(minSdkVersion:29)
 libbluetooth_headers(minSdkVersion:30)
+libbpf(minSdkVersion:apex_inherit)
 libbrotli(minSdkVersion:(no version))
 libbrotli(minSdkVersion:apex_inherit)
 libbssl_rust_support(minSdkVersion:29)
 libbssl_sys(minSdkVersion:29)
 libbssl_sys_raw(minSdkVersion:29)
+libbssl_sys_raw_staticfns(minSdkVersion:29)
 libbt-platform-protos-lite(minSdkVersion:30)
 libbt_keystore_cc(minSdkVersion:30)
 libbt_keystore_cc_headers(minSdkVersion:30)
@@ -489,15 +517,12 @@ libbtcore_headers(minSdkVersion:30)
 libbuildversion(minSdkVersion:(no version))
 libbuildversion(minSdkVersion:26)
 libbytemuck(minSdkVersion:29)
-libbytemuck(minSdkVersion:34)
 libbyteorder(minSdkVersion:29)
-libbyteorder(minSdkVersion:34)
 libbytes(minSdkVersion:29)
 libc++(minSdkVersion:apex_inherit)
 libc++_static(minSdkVersion:apex_inherit)
 libc++abi(minSdkVersion:apex_inherit)
 libc++demangle(minSdkVersion:apex_inherit)
-libc++fs(minSdkVersion:apex_inherit)
 libc_headers(minSdkVersion:apex_inherit)
 libc_headers_arch(minSdkVersion:apex_inherit)
 libc_scudo(minSdkVersion:apex_inherit)
@@ -558,9 +583,9 @@ libcodec2_vndk(minSdkVersion:29)
 libcom_android_networkstack_tethering_util_jni(minSdkVersion:30)
 libcombine(minSdkVersion:29)
 libcompiler_builtins.rust_sysroot(minSdkVersion:29)
+libconfiginfra_framework_flags_rust(minSdkVersion:34)
 libcore.rust_sysroot(minSdkVersion:29)
 libcrypto(minSdkVersion:29)
-libcrypto_rpc_rs(minSdkVersion:34)
 libcrypto_static(minSdkVersion:(no version))
 libcrypto_static(minSdkVersion:29)
 libcrypto_utils(minSdkVersion:(no version))
@@ -571,7 +596,7 @@ libcutils_headers(minSdkVersion:29)
 libcutils_sockets(minSdkVersion:29)
 libcxx(minSdkVersion:29)
 libcxxbridge05(minSdkVersion:29)
-libdata_encoding(minSdkVersion:34)
+libdata_encoding(minSdkVersion:29)
 libdav1d(minSdkVersion:29)
 libdav1d_16bit(minSdkVersion:29)
 libdav1d_8bit(minSdkVersion:29)
@@ -589,6 +614,8 @@ libdoubleconversion(minSdkVersion:30)
 libdowncast_rs(minSdkVersion:29)
 libeigen(minSdkVersion:(no version))
 libeigen(minSdkVersion:apex_inherit)
+libelf(minSdkVersion:apex_inherit)
+libenv_filter(minSdkVersion:29)
 libenv_logger(minSdkVersion:29)
 liberrno(minSdkVersion:30)
 liberror_headers(minSdkVersion:29)
@@ -613,7 +640,6 @@ libflatbuffers-cpp(minSdkVersion:30)
 libfmq(minSdkVersion:29)
 libfmq-base(minSdkVersion:29)
 libfnv(minSdkVersion:29)
-libfnv(minSdkVersion:34)
 libforeign_types(minSdkVersion:29)
 libforeign_types_shared(minSdkVersion:29)
 libform_urlencoded(minSdkVersion:29)
@@ -635,7 +661,6 @@ libgav1(minSdkVersion:29)
 libgcc_stripped(minSdkVersion:(no version))
 libgetopts(minSdkVersion:29)
 libgetrandom(minSdkVersion:29)
-libgetrandom(minSdkVersion:34)
 libgralloctypes(minSdkVersion:29)
 libgrallocusage(minSdkVersion:29)
 libgrpc(minSdkVersion:30)
@@ -685,40 +710,31 @@ libgui_bufferqueue_static(minSdkVersion:29)
 libgui_headers(minSdkVersion:29)
 libguiflags(minSdkVersion:29)
 libh2(minSdkVersion:29)
-libh2(minSdkVersion:34)
 libhardware(minSdkVersion:29)
 libhardware_headers(minSdkVersion:29)
 libhashbrown(minSdkVersion:29)
-libhashbrown(minSdkVersion:34)
+libhashbrown-0.12.3(minSdkVersion:29)
 libhashbrown.rust_sysroot(minSdkVersion:29)
 libhevcdec(minSdkVersion:29)
 libhevcenc(minSdkVersion:29)
 libhidlbase(minSdkVersion:29)
 libhidlmemory(minSdkVersion:29)
 libhttp(minSdkVersion:29)
-libhttp(minSdkVersion:34)
 libhttp_body(minSdkVersion:29)
-libhttp_body(minSdkVersion:34)
 libhttparse(minSdkVersion:29)
-libhttparse(minSdkVersion:34)
 libhttpdate(minSdkVersion:29)
-libhttpdate(minSdkVersion:34)
 libhwbinder-impl-internal(minSdkVersion:29)
 libhwbinder_headers(minSdkVersion:29)
 libhyper(minSdkVersion:29)
-libhyper(minSdkVersion:34)
 libhyper_timeout(minSdkVersion:29)
-libhyper_timeout(minSdkVersion:34)
 libidna(minSdkVersion:29)
 libimapper_providerutils(minSdkVersion:29)
 libimapper_stablec(minSdkVersion:29)
 libindexmap(minSdkVersion:29)
-libindexmap(minSdkVersion:34)
 libion(minSdkVersion:29)
 libion_headers(minSdkVersion:29)
 libip_checksum(minSdkVersion:30)
 libitoa(minSdkVersion:29)
-libitoa(minSdkVersion:34)
 libjni(minSdkVersion:29)
 libjni_legacy(minSdkVersion:29)
 libjni_sys(minSdkVersion:29)
@@ -728,15 +744,16 @@ libkll(minSdkVersion:30)
 libkll-encoder(minSdkVersion:30)
 libkll-protos(minSdkVersion:30)
 liblazy_static(minSdkVersion:29)
+liblc3(minSdkVersion:33)
+libldacBT_abr(minSdkVersion:33)
 libldacBT_abr(minSdkVersion:Tiramisu)
+libldacBT_enc(minSdkVersion:33)
 libldacBT_enc(minSdkVersion:Tiramisu)
 liblibc(minSdkVersion:29)
 liblibc.rust_sysroot(minSdkVersion:29)
 libLibGuiProperties(minSdkVersion:29)
 liblibm(minSdkVersion:29)
 liblibz_sys(minSdkVersion:29)
-liblifecycle_cpp_service_bundle_test(minSdkVersion:34)
-liblifecycle_rust_service_bundle_test(minSdkVersion:34)
 liblock_api(minSdkVersion:29)
 liblog_headers(minSdkVersion:29)
 liblog_rust(minSdkVersion:29)
@@ -748,7 +765,6 @@ liblz4(minSdkVersion:apex_inherit)
 liblzma(minSdkVersion:apex_inherit)
 libmatches(minSdkVersion:29)
 libmatchit(minSdkVersion:29)
-libmatchit(minSdkVersion:34)
 libmath(minSdkVersion:29)
 libmath_headers(minSdkVersion:apex_inherit)
 libmdnssd(minSdkVersion:(no version))
@@ -765,7 +781,6 @@ libmeminfo(minSdkVersion:S)
 libmemmap2(minSdkVersion:29)
 libmemoffset(minSdkVersion:29)
 libmime(minSdkVersion:29)
-libmime(minSdkVersion:34)
 libminijail(minSdkVersion:29)
 libminijail_gen_constants(minSdkVersion:(no version))
 libminijail_gen_constants_obj(minSdkVersion:29)
@@ -789,7 +804,6 @@ libnativeloader-headers(minSdkVersion:31)
 libnativewindow_headers(minSdkVersion:29)
 libnet_utils_device_common_bpfjni(minSdkVersion:30)
 libnet_utils_device_common_bpfutils(minSdkVersion:30)
-libnet_utils_device_common_timerfdjni(minSdkVersion:30)
 libnetdbinder_utils_headers(minSdkVersion:29)
 libnetdutils(minSdkVersion:29)
 libnetdutils(minSdkVersion:30)
@@ -803,17 +817,18 @@ libneuralnetworks_headers(minSdkVersion:(no version))
 libneuralnetworks_headers(minSdkVersion:30)
 libneuralnetworks_shim_static(minSdkVersion:30)
 libnfc-nci(minSdkVersion:35)
+libnfc-nci(minSdkVersion:36)
 libnfc-nci_flags(minSdkVersion:35)
+libnfc-nci_flags(minSdkVersion:36)
 libnfc_nci_jni(minSdkVersion:35)
+libnfc_nci_jni(minSdkVersion:36)
 libnfcutils(minSdkVersion:35)
+libnfcutils(minSdkVersion:36)
 libnix(minSdkVersion:29)
 libnl(minSdkVersion:apex_inherit)
 libnum_cpus(minSdkVersion:29)
 libnum_traits(minSdkVersion:29)
 liboctets(minSdkVersion:29)
-liboem_deadline_sched_service_bundle_rust_sample(minSdkVersion:34)
-liboem_service_bundle_cpp_sample(minSdkVersion:34)
-liboem_service_bundle_rust_sample(minSdkVersion:34)
 liboggextractor(minSdkVersion:29)
 libonce_cell(minSdkVersion:29)
 libopenapv(minSdkVersion:apex_inherit)
@@ -853,15 +868,14 @@ libpercent_encoding(minSdkVersion:29)
 libperfetto_client_experimental(minSdkVersion:30)
 libperfetto_client_experimental(minSdkVersion:S)
 libpin_project(minSdkVersion:29)
-libpin_project(minSdkVersion:34)
 libpin_project_lite(minSdkVersion:29)
 libpin_utils(minSdkVersion:29)
+libPlatformProperties(minSdkVersion:31)
 libPlatformProperties(minSdkVersion:S)
 libpng(minSdkVersion:30)
 libpng(minSdkVersion:apex_inherit)
 libpower(minSdkVersion:Tiramisu)
 libppv_lite86(minSdkVersion:29)
-libppv_lite86(minSdkVersion:34)
 libproc_macro_nested(minSdkVersion:29)
 libprocessgroup(minSdkVersion:29)
 libprocessgroup_headers(minSdkVersion:29)
@@ -892,50 +906,26 @@ libprotoutil(minSdkVersion:30)
 libqemu_pipe(minSdkVersion:(no version))
 libquiche(minSdkVersion:29)
 librand(minSdkVersion:29)
-librand(minSdkVersion:34)
 librand_chacha(minSdkVersion:29)
-librand_chacha(minSdkVersion:34)
 librand_core(minSdkVersion:29)
-librand_core(minSdkVersion:34)
+libregex(minSdkVersion:29)
+libregex_syntax(minSdkVersion:29)
 libremove_dir_all(minSdkVersion:29)
 libring(minSdkVersion:29)
 libring-core(minSdkVersion:29)
 libring-test(minSdkVersion:29)
 librkpd(minSdkVersion:33)
+librustc_demangle(minSdkVersion:31)
 librustc_demangle(minSdkVersion:S)
 librustc_demangle.rust_sysroot(minSdkVersion:29)
+librustc_demangle_static(minSdkVersion:31)
 librustc_demangle_static(minSdkVersion:S)
 librustix(minSdkVersion:30)
 librustutils(minSdkVersion:29)
 libruy_static(minSdkVersion:30)
 libscopeguard(minSdkVersion:29)
-libsdv_comms_bindgen(minSdkVersion:34)
-libsdv_comms_bindgen_private(minSdkVersion:34)
-libsdv_comms_common(minSdkVersion:34)
-libsdv_comms_common_hdrs(minSdkVersion:34)
-libsdv_comms_cpp(minSdkVersion:34)
-libsdv_comms_ctx_hdrs(minSdkVersion:34)
-libsdv_comms_dt_hdrs(minSdkVersion:34)
-libsdv_comms_id_hdrs(minSdkVersion:34)
-libsdv_comms_rpc(minSdkVersion:34)
-libsdv_comms_rpc_hdrs(minSdkVersion:34)
-libsdv_comms_rs(minSdkVersion:34)
-libsdv_comms_sd_hdrs(minSdkVersion:34)
-libsdv_lifecycle_client_cpp(minSdkVersion:34)
-libsdv_lifecycle_client_rust(minSdkVersion:34)
-libsdv_log(minSdkVersion:34)
-libsdv_log_ffi_rs(minSdkVersion:34)
-libsdv_log_rust(minSdkVersion:34)
-libsdv_service_bundle_metadata(minSdkVersion:34)
-libsdv_service_bundles_manifest_proto(minSdkVersion:34)
-libsdv_service_bundles_scheduling(minSdkVersion:34)
-libsdv_service_bundles_scheduling_proto(minSdkVersion:34)
-libsdv_status(minSdkVersion:34)
-libsdv_status_cpp(minSdkVersion:34)
-libsdv_status_hdrs(minSdkVersion:34)
-libsdv_status_rs(minSdkVersion:34)
-libsdv_status_sys(minSdkVersion:34)
 libserde(minSdkVersion:29)
+libserviceconnectivityjni(minSdkVersion:30)
 libsfplugin_ccodec_utils(minSdkVersion:29)
 libslab(minSdkVersion:29)
 libsmallvec(minSdkVersion:29)
@@ -974,14 +964,16 @@ libstagefright_mpeg2support(minSdkVersion:29)
 libstatic_assertions(minSdkVersion:29)
 libstatslog_express(minSdkVersion:33)
 libstatslog_nfc(minSdkVersion:35)
+libstatslog_nfc(minSdkVersion:36)
+libstatslog_rust_header(minSdkVersion:29)
 libstatspull_bindgen(minSdkVersion:apex_inherit)
+libstatspull_headers(minSdkVersion:30)
 libstatssocket_headers(minSdkVersion:29)
 libstd(minSdkVersion:29)
 libstd_detect.rust_sysroot(minSdkVersion:29)
 libstrsim(minSdkVersion:29)
 libsync(minSdkVersion:(no version))
 libsync_wrapper(minSdkVersion:29)
-libsync_wrapper(minSdkVersion:34)
 libsystem_headers(minSdkVersion:apex_inherit)
 libsystem_properties_bindgen(minSdkVersion:29)
 libsystem_properties_bindgen_sys(minSdkVersion:29)
@@ -1009,27 +1001,20 @@ libtflite_static(minSdkVersion:30)
 libthiserror(minSdkVersion:29)
 libtinyvec(minSdkVersion:29)
 libtinyvec_macros(minSdkVersion:29)
+libtinyxml2(minSdkVersion:31)
 libtinyxml2(minSdkVersion:S)
 libtokio(minSdkVersion:29)
 libtokio_io_timeout(minSdkVersion:29)
-libtokio_io_timeout(minSdkVersion:34)
 libtokio_openssl(minSdkVersion:29)
 libtokio_stream(minSdkVersion:29)
 libtokio_util(minSdkVersion:29)
 libtonic(minSdkVersion:29)
-libtonic(minSdkVersion:34)
 libtower(minSdkVersion:29)
-libtower(minSdkVersion:34)
 libtower_layer(minSdkVersion:29)
-libtower_layer(minSdkVersion:34)
 libtower_service(minSdkVersion:29)
-libtower_service(minSdkVersion:34)
 libtracing(minSdkVersion:29)
-libtracing(minSdkVersion:34)
 libtracing_core(minSdkVersion:29)
-libtracing_core(minSdkVersion:34)
 libtry_lock(minSdkVersion:29)
-libtry_lock(minSdkVersion:34)
 libtsi(minSdkVersion:30)
 libtsi_interface(minSdkVersion:30)
 libui(minSdkVersion:29)
@@ -1056,15 +1041,20 @@ libutils_headers(minSdkVersion:29)
 libutils_headers(minSdkVersion:30)
 libutils_headers(minSdkVersion:apex_inherit)
 libuwb_aconfig_flags_rust(minSdkVersion:33)
+libuwb_uci_packets(minSdkVersion:33)
 libuwb_uci_packets(minSdkVersion:Tiramisu)
 libvendorsupport_llndk_headers(minSdkVersion:apex_inherit)
 libvorbisidec(minSdkVersion:29)
 libvpx(minSdkVersion:29)
+libvpx_avx(minSdkVersion:29)
+libvpx_avx2(minSdkVersion:29)
+libvpx_avx512(minSdkVersion:29)
 libvpx_neon_dotprod(minSdkVersion:29)
 libvpx_neon_i8mm(minSdkVersion:29)
+libvpx_sse4(minSdkVersion:29)
 libvpx_sve(minSdkVersion:29)
+libvpx_sve2(minSdkVersion:29)
 libwant(minSdkVersion:29)
-libwant(minSdkVersion:34)
 libwavextractor(minSdkVersion:29)
 libwebm(minSdkVersion:29)
 libwebm_mkvparser(minSdkVersion:29)
@@ -1072,9 +1062,11 @@ libwpa_shared_aidl_headers_mainline(minSdkVersion:30)
 libxml2(minSdkVersion:apex_inherit)
 libyuv(minSdkVersion:29)
 libyuv_static(minSdkVersion:29)
+libz(minSdkVersion:apex_inherit)
 libz_static(minSdkVersion:apex_inherit)
 libzerocopy(minSdkVersion:29)
 libzerocopy-0.7.35(minSdkVersion:29)
+libzeroize(minSdkVersion:33)
 libzeroize(minSdkVersion:Tiramisu)
 libziparchive(minSdkVersion:apex_inherit)
 libzstd(minSdkVersion:(no version))
@@ -1141,6 +1133,7 @@ net-utils-framework-common(minSdkVersion:current)
 net-utils-framework-connectivity(minSdkVersion:30)
 net-utils-non-bootclasspath-aidl-java(minSdkVersion:30)
 net-utils-service-connectivity(minSdkVersion:30)
+net-utils-service-vcn(minSdkVersion:30)
 net-utils-service-wifi(minSdkVersion:30)
 net-utils-services-common(minSdkVersion:30)
 net-utils-tethering(minSdkVersion:30)
@@ -1165,6 +1158,10 @@ netd_aidl_interface-V14-java(minSdkVersion:30)
 netd_aidl_interface-V14-ndk(minSdkVersion:30)
 netd_aidl_interface-V15-java(minSdkVersion:30)
 netd_aidl_interface-V15-ndk(minSdkVersion:30)
+netd_aidl_interface-V16-java(minSdkVersion:30)
+netd_aidl_interface-V16-ndk(minSdkVersion:30)
+netd_aidl_interface-V17-java(minSdkVersion:30)
+netd_aidl_interface-V17-ndk(minSdkVersion:30)
 netd_aidl_interface-V3-java(minSdkVersion:29)
 netd_aidl_interface-V5-java(minSdkVersion:29)
 netd_aidl_interface-V6-java(minSdkVersion:29)
@@ -1198,6 +1195,7 @@ networkstack-aidl-interfaces-V19-java(minSdkVersion:30)
 networkstack-aidl-interfaces-V20-java(minSdkVersion:30)
 networkstack-aidl-interfaces-V21-java(minSdkVersion:30)
 networkstack-aidl-interfaces-V22-java(minSdkVersion:30)
+networkstack-aidl-interfaces-V23-java(minSdkVersion:30)
 networkstack-aidl-latest(minSdkVersion:29)
 networkstack-aidl-latest(minSdkVersion:30)
 networkstack-client(minSdkVersion:29)
@@ -1237,6 +1235,9 @@ neuralnetworks_utils_hal_aidl(minSdkVersion:30)
 neuralnetworks_utils_hal_common(minSdkVersion:30)
 neuralnetworks_utils_hal_service(minSdkVersion:30)
 nfc-event-log-proto(minSdkVersion:35)
+nfc-event-log-proto(minSdkVersion:36)
+NfcNciApex(minSdkVersion:35)
+NfcNciApexGoogle(minSdkVersion:35)
 note_memtag_heap_async(minSdkVersion:16)
 note_memtag_heap_sync(minSdkVersion:16)
 offlinelocationtimezoneprovider(minSdkVersion:31)
@@ -1251,6 +1252,7 @@ OsuLoginGoogle(minSdkVersion:30)
 owasp-java-encoder(minSdkVersion:33)
 pdfium-headers(minSdkVersion:apex_inherit)
 pdfium-third-party-headers(minSdkVersion:apex_inherit)
+perfetto_trace_protos(minSdkVersion:31)
 perfetto_trace_protos(minSdkVersion:S)
 perfmark(minSdkVersion:30)
 perfmark-impl(minSdkVersion:30)
@@ -1361,6 +1363,7 @@ s2-geometry-library-java(minSdkVersion:30)
 s2storage_ro(minSdkVersion:31)
 sap-api-java-static(minSdkVersion:30)
 server_configurable_flags(minSdkVersion:29)
+service-connectivity-b-pre-jarjar(minSdkVersion:30)
 service-entitlement(minSdkVersion:29)
 service-entitlement-api(minSdkVersion:29)
 service-entitlement-data(minSdkVersion:29)
@@ -1374,12 +1377,15 @@ SettingsLibActionBarShadow(minSdkVersion:21)
 SettingsLibActionBarShadow(minSdkVersion:28)
 SettingsLibActivityEmbedding(minSdkVersion:21)
 SettingsLibAppPreference(minSdkVersion:21)
+SettingsLibBannerMessagePreference(minSdkVersion:28)
 SettingsLibBarChartPreference(minSdkVersion:21)
+SettingsLibButtonPreference(minSdkVersion:21)
 SettingsLibCollapsingToolbarBaseActivity(minSdkVersion:29)
 SettingsLibColor(minSdkVersion:28)
 SettingsLibFooterPreference(minSdkVersion:21)
 SettingsLibHelpUtils(minSdkVersion:21)
 SettingsLibIllustrationPreference(minSdkVersion:28)
+SettingsLibIntroPreference(minSdkVersion:21)
 SettingsLibLayoutPreference(minSdkVersion:21)
 SettingsLibMainSwitchPreference(minSdkVersion:28)
 SettingsLibProfileSelector(minSdkVersion:23)
@@ -1394,6 +1400,10 @@ SettingsLibSettingsTransition(minSdkVersion:29)
 SettingsLibTopIntroPreference(minSdkVersion:21)
 SettingsLibTwoTargetPreference(minSdkVersion:21)
 SettingsLibUtils(minSdkVersion:21)
+SettingsLibZeroStatePreference(minSdkVersion:28)
+setupcompat(minSdkVersion:21)
+setupdesign(minSdkVersion:21)
+setupdesign-strings(minSdkVersion:19)
 slf4j-jdk14(minSdkVersion:current)
 spatializer-aidl-cpp(minSdkVersion:29)
 statsd-aidl-ndk(minSdkVersion:30)
@@ -1425,8 +1435,12 @@ uprobestats(minSdkVersion:35)
 uprobestats_bpf_headers(minSdkVersion:35)
 uprobestats_bpf_syscall_wrappers(minSdkVersion:35)
 uprobestats_flags_c_lib(minSdkVersion:35)
+uprobestats_flags_c_lib(minSdkVersion:36)
 uprobestats_mainline_flags_c_lib(minSdkVersion:35)
+uprobestats_mainline_flags_c_lib(minSdkVersion:36)
 uwb_androidx_backend(minSdkVersion:30)
+volumegroupcallback-aidl-cpp(minSdkVersion:29)
+wear-permission-components(minSdkVersion:30)
 wifi-lite-protos(minSdkVersion:30)
 wifi-nano-protos(minSdkVersion:30)
 wifi-service-pre-jarjar(minSdkVersion:30)
diff --git a/build/mainline_modules_sdks.py b/build/mainline_modules_sdks.py
index 75e3536..060b580 100755
--- a/build/mainline_modules_sdks.py
+++ b/build/mainline_modules_sdks.py
@@ -330,7 +330,7 @@ def module_sdk_project_for_module(module, root_dir):
     # art, hence adding special case for art.
     if module == "art":
         return "prebuilts/module_sdk/art"
-    if module == "btservices":
+    if module == "bt":
         return "prebuilts/module_sdk/Bluetooth"
     if module == "media":
         return "prebuilts/module_sdk/Media"
@@ -874,9 +874,6 @@ VanillaIceCream = BuildRelease(
     name="VanillaIceCream",
     # Generate a snapshot for this build release using Soong.
     creator=create_sdk_snapshots_in_soong,
-    # There are no build release specific environment variables to pass to
-    # Soong.
-    soong_env={},
     # Starting with V, setting `prefer|use_source_config_var` on soong modules
     # in prebuilts/module_sdk is not necessary.
     # prebuilts will be enabled using apex_contributions release build flags.
@@ -1126,10 +1123,10 @@ MAINLINE_MODULES = [
         module_proto_key="ART",
     ),
     MainlineModule(
-        apex="com.android.btservices",
-        sdks=["btservices-module-sdk"],
-        first_release=UpsideDownCake,
-        # Bluetooth has always been and is still optional.
+        apex="com.android.bt",
+        sdks=["bt-module-sdk"],
+        first_release=Baklava,
+        # Bluetooth is optional.
         last_optional_release=LATEST,
         module_proto_key="",
     ),
@@ -1155,6 +1152,13 @@ MAINLINE_MODULES = [
         last_optional_release=LATEST,
         module_proto_key="CONSCRYPT",
     ),
+    MainlineModule(
+        apex="com.android.crashrecovery",
+        sdks=["crashrecovery-sdk"],
+        first_release=Baklava,
+        last_optional_release=LATEST,
+        module_proto_key="",
+    ),
     MainlineModule(
         apex="com.android.devicelock",
         sdks=["devicelock-module-sdk"],
@@ -1239,6 +1243,14 @@ MAINLINE_MODULES = [
         last_optional_release=LATEST,
         module_proto_key="PERMISSIONS",
     ),
+    MainlineModule(
+        apex="com.android.profiling",
+        sdks=["profiling-module-sdk"],
+        first_release=Baklava,
+        # Profiling is optional.
+        last_optional_release=LATEST,
+        module_proto_key="",
+    ),
     MainlineModule(
         apex="com.android.rkpd",
         sdks=["rkpd-sdk"],
@@ -1256,7 +1268,10 @@ MAINLINE_MODULES = [
     ),
     MainlineModule(
         apex="com.android.sdkext",
-        sdks=["sdkextensions-sdk"],
+        sdks=[
+            "sdkextensions-sdk",
+            "sdkextensions-host-exports",
+        ],
         first_release=R,
         for_r_build=ForRBuild(sdk_libraries=[
             SdkLibrary(name="framework-sdkextensions"),
@@ -1511,9 +1526,12 @@ class SdkDistProducer:
         sdk_type = sdk_type_from_name(sdk)
         subdir = sdk_type.name
 
+        # HostExports are not needed for R.
+        if build_release == R and sdk_type == HostExports:
+            return
+
         sdk_dist_subdir = os.path.join(sdk_dist_dir, module.apex, subdir)
         sdk_path = sdk_snapshot_zip_file(snapshots_dir, sdk)
-        sdk_type = sdk_type_from_name(sdk)
         transformations = module.transformations(build_release, sdk_type)
         self.dist_sdk_snapshot_zip(
             build_release, sdk_path, sdk_dist_subdir, transformations)
diff --git a/javatests/com/android/modules/apkinapex/OWNERS b/javatests/com/android/modules/apkinapex/OWNERS
index 55f5b97..115d5fe 100644
--- a/javatests/com/android/modules/apkinapex/OWNERS
+++ b/javatests/com/android/modules/apkinapex/OWNERS
@@ -1,5 +1,3 @@
 # Mainline modularization team
 
-andreionea@google.com
 pedroql@google.com
-satayev@google.com
diff --git a/javatests/com/android/modules/updatablesharedlibs/OWNERS b/javatests/com/android/modules/updatablesharedlibs/OWNERS
index 778e15d..c3b19c4 100644
--- a/javatests/com/android/modules/updatablesharedlibs/OWNERS
+++ b/javatests/com/android/modules/updatablesharedlibs/OWNERS
@@ -1,5 +1,4 @@
 # Mainline modularization team
 
-andreionea@google.com
 pedroql@google.com
 robertogil@google.com
diff --git a/proguard/Android.bp b/proguard/Android.bp
index 693b8ca..f5a5ce0 100644
--- a/proguard/Android.bp
+++ b/proguard/Android.bp
@@ -17,7 +17,13 @@ package {
     default_visibility: [
         ":__subpackages__",
         "//art/libartservice:__subpackages__",
+        "//frameworks/base:__subpackages__",
+        "//frameworks/opt:__subpackages__",
+        "//libcore:__subpackages__",
         "//packages/modules:__subpackages__",
+        "//packages/providers/MediaProvider:__subpackages__",
+        "//system/apex/apexd:__subpackages__",
+
     ],
 }
 
@@ -63,3 +69,10 @@ java_defaults {
         proguard_flags_files: [":standalone-system-server-module-optimize-proguard-rules"],
     },
 }
+
+filegroup {
+    name: "framework-sdk-proguard-rules",
+    srcs: [
+        "framework-sdk.pro",
+    ],
+}
diff --git a/proguard/framework-sdk.pro b/proguard/framework-sdk.pro
new file mode 100644
index 0000000..1200fef
--- /dev/null
+++ b/proguard/framework-sdk.pro
@@ -0,0 +1,10 @@
+# This set of Proguard rules is intended for any module java_sdk_library
+# target. It is intentionally more conservative than the default global
+# Proguard configuration, as library targets, particularly updatable
+# targets, must preserve certain levels of compatiblity across the API
+# boundary for stable interop with downstream targets.
+
+# A minimal set of attributes necessary to preserve public API signature
+# stability across releases, particularly for generic types that might be
+# referenced via reflection. See also Cts*ApiSignatureTestCases.
+-keepattributes EnclosingMethod,InnerClasses,Signature
diff --git a/proto/Android.bp b/proto/Android.bp
index f12a52d..f8ecbf2 100644
--- a/proto/Android.bp
+++ b/proto/Android.bp
@@ -56,6 +56,7 @@ python_library_host {
 
 cc_library_static {
     name: "libclasspaths_proto",
+    host_supported: true,
     proto: {
         export_proto_headers: true,
         type: "lite",
diff --git a/proto/sdk.proto b/proto/sdk.proto
index eb58cb0..ea0c6f2 100644
--- a/proto/sdk.proto
+++ b/proto/sdk.proto
@@ -61,6 +61,9 @@ enum SdkModule {
 
   // V modules
   // No new modules introduced in V
+
+  // B Modules
+  NEURAL_NETWORKS = 17;
 }
 
 // A single extension version.
diff --git a/sdk/Android.bp b/sdk/Android.bp
index da8370d..c364beb 100644
--- a/sdk/Android.bp
+++ b/sdk/Android.bp
@@ -58,6 +58,13 @@ java_defaults {
     // we shouldn't ordinarily need (and it can create issues), so disable that.
     installable: false,
 
+    optimize: {
+        // Note that we don't enable optimizations by default, but we do
+        // bundle an additional set of Proguard rules that should always
+        // be used downstream for selectively optimized targets.
+        proguard_flags_files: [":framework-sdk-proguard-rules"],
+    },
+
     // Configure framework module specific metalava options.
     droiddoc_options: [
         "--error UnhiddenSystemApi",
@@ -294,7 +301,7 @@ apex_defaults {
 apex_defaults {
     name: "b-launched-apex-module",
     defaults: ["any-launched-apex-modules"],
-    min_sdk_version: "Baklava",
+    min_sdk_version: "36",
     // Indicates that pre-installed version of this apex can be compressed.
     // Whether it actually will be compressed is controlled on per-device basis.
     compressible: true,
diff --git a/tools/Android.bp b/tools/Android.bp
index 8352244..1810a2b 100644
--- a/tools/Android.bp
+++ b/tools/Android.bp
@@ -21,11 +21,6 @@ package {
 
 python_defaults {
     name: "modules-common-tools-python-defaults",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_binary_host {
@@ -42,6 +37,13 @@ python_binary_host {
     libs: ["sdk_proto_python"],
 }
 
+python_binary_host {
+    name: "check_derive_classpath",
+    defaults: ["modules-common-tools-python-defaults"],
+    srcs: ["check_derive_classpath.py"],
+    libs: ["classpaths_proto_python"],
+}
+
 genrule {
     name: "cur_sdkinfo_src",
     tools: ["gen_sdkinfo"],
@@ -68,6 +70,7 @@ prebuilt_etc {
         "//packages/modules/ConfigInfrastructure:__subpackages__",
         "//packages/modules/HealthFitness:__subpackages__",
         "//packages/modules/IPsec/apex:__subpackages__",
+        "//packages/modules/NeuralNetworks:__subpackages__",
         "//packages/modules/Permission:__subpackages__",
         "//packages/modules/OnDevicePersonalization:__subpackages__",
         "//packages/modules/Scheduling:__subpackages__",
diff --git a/tools/check_allowed_deps.py b/tools/check_allowed_deps.py
index bfdd4c6..bf439c5 100755
--- a/tools/check_allowed_deps.py
+++ b/tools/check_allowed_deps.py
@@ -15,6 +15,9 @@ AllowedDepsTxt = "build/allowed_deps.txt"
 DisableAllowedDepsCheckKey = "No-Allowed-Deps-Check"
 ExpectedKeys = set(["Apex-Size-Increase", "Previous-Platform-Support", "Aosp-First", "Test-Info"])
 
+def is_aconfig_dep(dep: str):
+  return bool(re.search(r"aconfig(d)?[-_]", dep))
+
 def get_deps(allowed_deps):
   """ Parse allowed_deps.txt contents returning just dependency names """
   deps = set()
@@ -24,6 +27,9 @@ def get_deps(allowed_deps):
     # Allowlist androidx deps
     if line.startswith("androidx."):
       continue
+    # Allowlist aconfig deps
+    if is_aconfig_dep(line):
+      continue
     if len(line.strip()) == 0:
       continue
     dep = line[:line.find("(")]
diff --git a/tools/check_derive_classpath.py b/tools/check_derive_classpath.py
new file mode 100644
index 0000000..c202046
--- /dev/null
+++ b/tools/check_derive_classpath.py
@@ -0,0 +1,136 @@
+#!/usr/bin/env python
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Script to debug the protobuf data read by derive_classpath.
+
+If the Android device was compiled against a REL SDK, none of its jar files on
+the classpaths may have been compiled against a non-REL SDK. If this is the
+case, derive_classpath will crash to indicate an error in the way the system
+was configured. This script helps detect that scenario.
+"""
+
+import classpaths_pb2
+import subprocess
+import sys
+import textwrap
+
+RESET_CURSOR_AND_CLEAR_LINE = "\033[G\033[2K"
+
+
+def progress(msg):
+    if not sys.stdout.isatty():
+        return
+    if msg is None:
+        msg = RESET_CURSOR_AND_CLEAR_LINE
+    else:
+        msg = RESET_CURSOR_AND_CLEAR_LINE + "> " + msg
+    sys.stdout.write(msg)
+    sys.stdout.flush()
+
+
+def find_codename_versions_in_protobuf(binary_proto_data):
+    def is_codename(s):
+        return s != "" and not s.isdigit()
+
+    jars = classpaths_pb2.ExportedClasspathsJars()
+    jars.ParseFromString(binary_proto_data)
+
+    # each jar's {min,max}_sdk_version is a string that is either
+    #   - the empty string (value not set)
+    #   - a numerical API level
+    #   - a string codename
+    # we're only interested in the codename cases
+    return [
+        jar
+        for jar in jars.jars
+        if is_codename(jar.min_sdk_version) or is_codename(jar.max_sdk_version)
+    ]
+
+
+def exec(cmd, encoding="UTF-8"):
+    completed_proc = subprocess.run(
+        cmd,
+        capture_output=True,
+        encoding=encoding,
+    )
+    completed_proc.check_returncode()
+    return completed_proc.stdout
+
+
+def get_protobuf_paths():
+    preinstalled_paths = exec(
+        [
+            "adb",
+            "exec-out",
+            "find",
+            "/system/etc/classpaths",
+            "-type",
+            "f",
+            "-name",
+            "*.pb",
+        ]
+    ).splitlines()
+
+    stdout = exec(
+        [
+            "adb",
+            "exec-out",
+            "find",
+            "/apex",
+            "-type",
+            "f",
+            "-path",
+            "*/etc/classpaths/*.pb",
+        ]
+    ).splitlines()
+    apex_paths = [dir_ for dir_ in stdout if "@" not in dir_]
+
+    return set(preinstalled_paths + apex_paths)
+
+
+def main():
+    if not exec(["adb", "exec-out", "id"]).startswith("uid=0(root)"):
+        raise Exception("must run adb as root")
+
+    total_jars_with_codename = 0
+    for path in get_protobuf_paths():
+        progress(path)
+        stdout = exec(
+            ["adb", "exec-out", "cat", path],
+            encoding=None,
+        )
+        jars_with_codename = find_codename_versions_in_protobuf(stdout)
+        if len(jars_with_codename) > 0:
+            progress(None)
+            print(path)
+            for jar in jars_with_codename:
+                print(textwrap.indent(str(jar), "    "))
+            total_jars_with_codename += len(jars_with_codename)
+    progress(None)
+
+    if total_jars_with_codename > 0:
+        if exec(["adb", "exec-out", "getprop", "ro.build.version.codename"]) == "REL":
+            print(
+                f"{total_jars_with_codename} jar(s) with codename version(s) found on REL device: derive_classpath will detect this configuration error and crash during boot"
+            )
+            sys.exit(total_jars_with_codename)
+        else:
+            print(
+                f"{total_jars_with_codename} jar(s) with codename version(s) found on non-REL device: this configuration would be an issue on a REL device"
+            )
+
+
+if __name__ == "__main__":
+    main()
diff --git a/tools/conv_classpaths_proto.py b/tools/conv_classpaths_proto.py
index f49fbbb..78fa0a8 100644
--- a/tools/conv_classpaths_proto.py
+++ b/tools/conv_classpaths_proto.py
@@ -13,6 +13,7 @@
 #  limitations under the License.
 
 import argparse
+import sys
 
 import classpaths_pb2
 
diff --git a/tools/finalize_sdk.py b/tools/finalize_sdk.py
index db1ffc8..e9707da 100755
--- a/tools/finalize_sdk.py
+++ b/tools/finalize_sdk.py
@@ -126,15 +126,16 @@ def maybe_tweak_compat_stem(file):
     return file.with_stem(new_stem)
 
 parser = argparse.ArgumentParser(description=('Finalize an extension SDK with prebuilts'))
-parser.add_argument('-f', '--finalize_sdk', type=int, required=True, help='The numbered SDK to finalize.')
-parser.add_argument('-c', '--release_config', type=str, help='The release config to use to finalize.')
-parser.add_argument('-b', '--bug', type=int, required=True, help='The bug number to add to the commit message.')
-parser.add_argument('-r', '--readme', required=True, help='Version history entry to add to %s' % (COMPAT_REPO / COMPAT_README))
 parser.add_argument('-a', '--amend_last_commit', action="store_true", help='Amend current HEAD commits instead of making new commits.')
-parser.add_argument('-m', '--modules', action='append', help='Modules to include. Can be provided multiple times, or not at all for all modules.')
-parser.add_argument('-l', '--local_mode', action="store_true", help='Local mode: use locally built artifacts and don\'t upload the result to Gerrit.')
+parser.add_argument('-b', '--bug', type=int, required=True, help='The bug number to add to the commit message.')
+parser.add_argument('-c', '--release_config', type=str, help='The release config to use to finalize.')
+parser.add_argument('-d', '--dry_run', action='store_true', help='Leaves git and repo out it')
+parser.add_argument('-f', '--finalize_sdk', type=int, required=True, help='The numbered SDK to finalize.')
 # This flag is only required when executed via Gantry. It points to the downloaded directory to be used.
 parser.add_argument('-g', '--gantry_download_dir', type=str, help=argparse.SUPPRESS)
+parser.add_argument('-l', '--local_mode', action="store_true", help='Local mode: use locally built artifacts and don\'t upload the result to Gerrit.')
+parser.add_argument('-m', '--modules', action='append', help='Modules to include. Can be provided multiple times, or not at all for all modules.')
+parser.add_argument('-r', '--readme', required=True, help='Version history entry to add to %s' % (COMPAT_REPO / COMPAT_README))
 parser.add_argument('bid', help='Build server build ID')
 args = parser.parse_args()
 
@@ -206,6 +207,9 @@ if args.local_mode:
 if args.gantry_download_dir:
     sys.exit(0)
 
+if args.dry_run:
+    sys.exit(0)
+
 subprocess.check_output(['repo', 'start', branch_name] + list(created_dirs.keys()))
 print('Running git commit')
 for repo in created_dirs:
```

