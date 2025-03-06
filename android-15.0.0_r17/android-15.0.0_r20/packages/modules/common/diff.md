```diff
diff --git a/PREBUILTS_MODULE_OWNERS b/PREBUILTS_MODULE_OWNERS
index 5984e4c..f9bd4cb 100644
--- a/PREBUILTS_MODULE_OWNERS
+++ b/PREBUILTS_MODULE_OWNERS
@@ -11,7 +11,8 @@
 
 include platform/packages/modules/common:/MODULES_OWNERS
 marielos@google.com #{LAST_RESORT_SUGGESTION}
-pranavgupta@google.com #{LAST_RESORT_SUGGESTION}
+robojoe@google.com #{LAST_RESORT_SUGGESTION}
+andyq@google.com #{LAST_RESORT_SUGGESTION}
 ahomer@google.com #{LAST_RESORT_SUGGESTION}
 robertogil@google.com #{LAST_RESORT_SUGGESTION}
 gurpreetgs@google.com #{LAST_RESORT_SUGGESTION}
diff --git a/build/allowed_deps.txt b/build/allowed_deps.txt
index 88fed22..4c1db62 100644
--- a/build/allowed_deps.txt
+++ b/build/allowed_deps.txt
@@ -14,9 +14,16 @@
 # TODO(b/157465465): introduce automated quality signals and remove this list.
 
 aconfig_mediacodec_flags_c_lib(minSdkVersion:30)
+aconfig_storage_file_java(minSdkVersion:29)
+aconfig_storage_reader_java(minSdkVersion:29)
+aconfigd-mainline(minSdkVersion:34)
+aconfigd_java_proto_lite_lib(minSdkVersion:34)
 android.app.appfunctions.exported-flags-aconfig-java(minSdkVersion:30)
+android.app.ondeviceintelligence-aconfig-java(minSdkVersion:35)
+android.app.flags-aconfig-java(minSdkVersion:34)
 android.companion.virtualdevice.flags-aconfig-java-export(minSdkVersion:30)
 android.content.pm.flags-aconfig-java-export(minSdkVersion:30)
+android.crashrecovery.flags-aconfig-java(minSdkVersion:35)
 android.hardware.audio.common-V1-ndk(minSdkVersion:31)
 android.hardware.audio.common-V2-ndk(minSdkVersion:31)
 android.hardware.audio.common-V3-ndk(minSdkVersion:31)
@@ -32,6 +39,8 @@ android.hardware.bluetooth.audio-V5-ndk(minSdkVersion:31)
 android.hardware.bluetooth.audio@2.0(minSdkVersion:30)
 android.hardware.bluetooth.audio@2.1(minSdkVersion:30)
 android.hardware.bluetooth.ranging-V1-ndk(minSdkVersion:33)
+android.hardware.bluetooth.ranging-V2-ndk(minSdkVersion:33)
+android.hardware.bluetooth.socket-V1-ndk(minSdkVersion:33)
 android.hardware.bluetooth@1.0(minSdkVersion:30)
 android.hardware.bluetooth@1.1(minSdkVersion:30)
 android.hardware.cas.native@1.0(minSdkVersion:29)
@@ -40,6 +49,7 @@ android.hardware.common-ndk_platform(minSdkVersion:29)
 android.hardware.common-V2-ndk(minSdkVersion:29)
 android.hardware.common-V2-ndk_platform(minSdkVersion:29)
 android.hardware.common.fmq-V1-ndk(minSdkVersion:29)
+android.hardware.contexthub-V4-ndk(minSdkVersion:33)
 android.hardware.graphics.allocator-V1-ndk(minSdkVersion:29)
 android.hardware.graphics.allocator-V2-ndk(minSdkVersion:29)
 android.hardware.graphics.allocator@2.0(minSdkVersion:29)
@@ -53,6 +63,7 @@ android.hardware.graphics.common-V2-ndk_platform(minSdkVersion:29)
 android.hardware.graphics.common-V3-ndk(minSdkVersion:29)
 android.hardware.graphics.common-V4-ndk(minSdkVersion:29)
 android.hardware.graphics.common-V5-ndk(minSdkVersion:29)
+android.hardware.graphics.common-V6-ndk(minSdkVersion:29)
 android.hardware.graphics.common@1.0(minSdkVersion:29)
 android.hardware.graphics.common@1.1(minSdkVersion:29)
 android.hardware.graphics.common@1.2(minSdkVersion:29)
@@ -78,6 +89,10 @@ android.hardware.neuralnetworks@1.0(minSdkVersion:30)
 android.hardware.neuralnetworks@1.1(minSdkVersion:30)
 android.hardware.neuralnetworks@1.2(minSdkVersion:30)
 android.hardware.neuralnetworks@1.3(minSdkVersion:30)
+android.hardware.nfc-V2-ndk(minSdkVersion:35)
+android.hardware.nfc@1.0(minSdkVersion:29)
+android.hardware.nfc@1.1(minSdkVersion:29)
+android.hardware.nfc@1.2(minSdkVersion:29)
 android.hardware.radio-V1.0-java(minSdkVersion:current)
 android.hardware.radio.sap-V1-java(minSdkVersion:33)
 android.hardware.security.rkp-V3-java(minSdkVersion:33)
@@ -99,6 +114,7 @@ android.hardware.wifi-V1.6-java(minSdkVersion:30)
 android.hardware.wifi-V2-java(minSdkVersion:30)
 android.hardware.wifi-V3-java(minSdkVersion:30)
 android.hardware.wifi.common-V1-java(minSdkVersion:30)
+android.hardware.wifi.common-V2-java(minSdkVersion:30)
 android.hardware.wifi.hostapd-V1-java(minSdkVersion:30)
 android.hardware.wifi.hostapd-V1.0-java(minSdkVersion:30)
 android.hardware.wifi.hostapd-V1.1-java(minSdkVersion:30)
@@ -133,20 +149,31 @@ android.media.audio.common.types-V3-cpp(minSdkVersion:29)
 android.media.audio.common.types-V3-ndk(minSdkVersion:29)
 android.media.audio.common.types-V4-cpp(minSdkVersion:29)
 android.media.audio.common.types-V4-ndk(minSdkVersion:29)
+android.media.codec-aconfig-cc(minSdkVersion:30)
+android.media.extractor.flags-aconfig-cc(minSdkVersion:29)
+android.media.swcodec.flags-aconfig-cc(minSdkVersion:apex_inherit)
 android.net.ipsec.ike(minSdkVersion:30)
 android.net.ipsec.ike.xml(minSdkVersion:(no version))
 android.net.wifi.flags-aconfig-java(minSdkVersion:30)
+android.nfc.flags-aconfig-java(minSdkVersion:34)
 android.os.flags-aconfig-java-export(minSdkVersion:30)
 android.permission.flags-aconfig-java(minSdkVersion:30)
 android.permission.flags-aconfig-java-export(minSdkVersion:30)
+android.se.omapi-V1-java(minSdkVersion:35)
+android.security.flags-aconfig-java-export(minSdkVersion:30)
 android.security.rkpd-ndk(minSdkVersion:33)
 android.security.rkpd-rust(minSdkVersion:33)
+android.service.chooser.flags-aconfig-java(minSdkVersion:34)
 android.service.notification.flags-aconfig-export-java(minSdkVersion:30)
 android.system.suspend-V1-ndk(minSdkVersion:30)
 android.system.suspend-V1-ndk(minSdkVersion:Tiramisu)
 android.system.suspend.control-V1-ndk(minSdkVersion:30)
+android.system.wifi.mainline_supplicant-java(minSdkVersion:30)
+android.system.wifi.mainline_supplicant-ndk(minSdkVersion:30)
 android_checker_annotation_stubs(minSdkVersion:current)
 android_downloader_lib(minSdkVersion:30)
+android_nfc_flags_aconfig_c_lib(minSdkVersion:34)
+android_trade_in_mode_flags_cc_lib(minSdkVersion:apex_inherit)
 androidx-constraintlayout_constraintlayout(minSdkVersion:21)
 androidx-constraintlayout_constraintlayout-core(minSdkVersion:24)
 androidx-constraintlayout_constraintlayout-solver(minSdkVersion:24)
@@ -159,6 +186,7 @@ apache-xml(minSdkVersion:31)
 appsearch_flags_java_lib(minSdkVersion:33)
 art-aconfig-flags-java-lib(minSdkVersion:31)
 art-aconfig-flags-lib(minSdkVersion:31)
+art_flags_uprobestats_c_lib(minSdkVersion:35)
 audioclient-types-aidl-cpp(minSdkVersion:29)
 audioflinger-aidl-cpp(minSdkVersion:29)
 audiopolicy-aidl-cpp(minSdkVersion:29)
@@ -169,6 +197,7 @@ av-types-aidl-cpp(minSdkVersion:29)
 avrcp_headers(minSdkVersion:30)
 bcm_object(minSdkVersion:29)
 bionic_libc_platform_headers(minSdkVersion:29)
+bluetooth-protos-nfc-enums-java-gen(minSdkVersion:35)
 boringssl_self_test(minSdkVersion:29)
 bouncycastle(minSdkVersion:31)
 bouncycastle-unbundled(minSdkVersion:30)
@@ -210,6 +239,8 @@ com.uwb.support.multichip(minSdkVersion:30)
 com.uwb.support.oemextension(minSdkVersion:30)
 com.uwb.support.profile(minSdkVersion:30)
 com.uwb.support.radar(minSdkVersion:30)
+com.uwb.support.rftest(minSdkVersion:30)
+configinfra_framework_flags_java_lib(minSdkVersion:34)
 connectivity_native_aidl_interface-V1-java(minSdkVersion:30)
 conscrypt(minSdkVersion:29)
 core-libart(minSdkVersion:31)
@@ -217,6 +248,7 @@ core-oj(minSdkVersion:31)
 crt_pad_segment(minSdkVersion:16)
 crt_pad_segment(minSdkVersion:30)
 crt_pad_segment(minSdkVersion:35)
+crt_pad_segment(minSdkVersion:current)
 crt_pad_segment(minSdkVersion:VanillaIceCream)
 crtbegin_dynamic(minSdkVersion:16)
 crtbegin_dynamic(minSdkVersion:apex_inherit)
@@ -247,9 +279,12 @@ crtend_so(minSdkVersion:current)
 crtend_so(minSdkVersion:VanillaIceCream)
 dagger2(minSdkVersion:current)
 datastallprotosnano(minSdkVersion:29)
+device_policy_aconfig_flags_java_export(minSdkVersion:30)
 dlmalloc(minSdkVersion:apex_inherit)
 dnsproxyd_protocol_headers(minSdkVersion:29)
 dnsproxyd_protocol_headers(minSdkVersion:30)
+docsui-change-ids(minSdkVersion:29)
+docsui-flags-aconfig-java-lib(minSdkVersion:29)
 DocumentsUI-lib(minSdkVersion:29)
 DocumentsUIManifestLib(minSdkVersion:29)
 ethtool(minSdkVersion:30)
@@ -274,12 +309,18 @@ fp16_headers(minSdkVersion:30)
 framework-bluetooth(minSdkVersion:33)
 framework-mediaprovider(minSdkVersion:30)
 framework-mediaprovider.impl(minSdkVersion:30)
+framework-ondeviceintelligence(minSdkVersion:35)
+framework-ondeviceintelligence.impl(minSdkVersion:35)
+framework-nfc(minSdkVersion:current)
+framework-nfc.impl(minSdkVersion:current)
 framework-permission(minSdkVersion:30)
 framework-permission(minSdkVersion:current)
 framework-permission-s(minSdkVersion:31)
 framework-permission.impl(minSdkVersion:30)
 framework-profiling(minSdkVersion:34)
+framework-profiling(minSdkVersion:35)
 framework-profiling(minSdkVersion:current)
+framework-profiling.impl(minSdkVersion:35)
 framework-ranging(minSdkVersion:current)
 framework-ranging.impl(minSdkVersion:current)
 framework-statsd(minSdkVersion:30)
@@ -297,6 +338,15 @@ gemmlowp_headers(minSdkVersion:apex_inherit)
 geotz_common(minSdkVersion:31)
 geotz_lookup(minSdkVersion:31)
 geotz_s2storage_ro(minSdkVersion:31)
+google.sdv.authz-aidl-V1-rust(minSdkVersion:34)
+google.sdv.identity-aidl-V1-rust(minSdkVersion:34)
+google.sdv.lifecycle.test-V1-ndk(minSdkVersion:34)
+google.sdv.lifecycle.test-V1-rust(minSdkVersion:34)
+google.sdv.rpc-aidl-V1-rust(minSdkVersion:34)
+google.sdv.sd-aidl-V1-rust(minSdkVersion:34)
+google.sdv.sd_common-aidl-V1-rust(minSdkVersion:34)
+google.sdv.service_discovery.common-aidl-V1-rust(minSdkVersion:34)
+google.sdv.service_discovery.discovery-aidl-V1-rust(minSdkVersion:34)
 GoogleCellBroadcastApp(minSdkVersion:29)
 GoogleCellBroadcastServiceModule(minSdkVersion:29)
 GoogleExtServices(minSdkVersion:30)
@@ -313,7 +363,6 @@ grpc-java-core-util(minSdkVersion:30)
 grpc-java-okhttp(minSdkVersion:30)
 grpc-java-protobuf-lite(minSdkVersion:30)
 grpc-java-stub(minSdkVersion:30)
-gson(minSdkVersion:30)
 guava(minSdkVersion:current)
 guava-android-annotation-stubs(minSdkVersion:30)
 gwp_asan_headers(minSdkVersion:S)
@@ -331,6 +380,7 @@ ipmemorystore-aidl-interfaces-V11-java(minSdkVersion:30)
 jacocoagent(minSdkVersion:9)
 jni_headers(minSdkVersion:29)
 jni_platform_headers(minSdkVersion:S)
+jspecify(minSdkVersion:1)
 jsr305(minSdkVersion:14)
 jsr330(minSdkVersion:current)
 kotlinx-coroutines-android(minSdkVersion:28)
@@ -343,14 +393,20 @@ kotlinx_coroutines_android(minSdkVersion:28)
 kotlinx_serialization_core(minSdkVersion:current)
 ksoap2(minSdkVersion:30)
 libaacextractor(minSdkVersion:29)
+libabsl(minSdkVersion:apex_inherit)
 libaconfig_java_proto_lite(minSdkVersion:34)
 libaconfig_java_proto_lite(minSdkVersion:UpsideDownCake)
+libaconfig_new_storage_flags_rust(minSdkVersion:34)
 libaconfig_storage_file(minSdkVersion:29)
 libaconfig_storage_protos(minSdkVersion:29)
 libaconfig_storage_protos_cc(minSdkVersion:29)
 libaconfig_storage_read_api(minSdkVersion:29)
 libaconfig_storage_read_api_cc(minSdkVersion:29)
 libaconfig_storage_read_api_cxx_bridge(minSdkVersion:29)
+libaconfig_storage_write_api(minSdkVersion:34)
+libaconfigd_protos_rust(minSdkVersion:34)
+libaconfigd_rust(minSdkVersion:34)
+libaconfigd_rust_proto(minSdkVersion:34)
 libadbconnection_server(minSdkVersion:(no version))
 libadbconnection_server(minSdkVersion:30)
 libadbd_core(minSdkVersion:(no version))
@@ -358,6 +414,8 @@ libadbd_core(minSdkVersion:30)
 libadbd_services(minSdkVersion:(no version))
 libadbd_services(minSdkVersion:30)
 libaddress_sorting(minSdkVersion:30)
+libahash(minSdkVersion:29)
+libahash(minSdkVersion:34)
 libaidlcommonsupport(minSdkVersion:29)
 liballoc.rust_sysroot(minSdkVersion:29)
 libalts_frame_protector(minSdkVersion:30)
@@ -365,6 +423,7 @@ libalts_util(minSdkVersion:30)
 libamrextractor(minSdkVersion:29)
 libandroid_log_sys(minSdkVersion:29)
 libandroid_logger(minSdkVersion:29)
+libanstyle(minSdkVersion:29)
 libanyhow(minSdkVersion:29)
 libaom(minSdkVersion:29)
 libaom_arm_crc32(minSdkVersion:29)
@@ -377,6 +436,8 @@ libapp_processes_protos_lite(minSdkVersion:30)
 libarect(minSdkVersion:29)
 libarect_headers(minSdkVersion:29)
 libasync_safe(minSdkVersion:apex_inherit)
+libasync_stream(minSdkVersion:29)
+libasync_stream(minSdkVersion:34)
 libasyncio(minSdkVersion:(no version))
 libasyncio(minSdkVersion:apex_inherit)
 libatomic(minSdkVersion:(no version))
@@ -391,6 +452,10 @@ libaudioutils_fixedfft(minSdkVersion:29)
 libavcdec(minSdkVersion:29)
 libavcenc(minSdkVersion:29)
 libavservices_minijail(minSdkVersion:29)
+libaxum(minSdkVersion:29)
+libaxum(minSdkVersion:34)
+libaxum_core(minSdkVersion:29)
+libaxum_core(minSdkVersion:34)
 libbacktrace(minSdkVersion:apex_inherit)
 libbacktrace_headers(minSdkVersion:apex_inherit)
 libbacktrace_rs.rust_sysroot(minSdkVersion:29)
@@ -414,12 +479,19 @@ libbluetooth-types-header(minSdkVersion:29)
 libbluetooth_headers(minSdkVersion:30)
 libbrotli(minSdkVersion:(no version))
 libbrotli(minSdkVersion:apex_inherit)
+libbssl_rust_support(minSdkVersion:29)
+libbssl_sys(minSdkVersion:29)
+libbssl_sys_raw(minSdkVersion:29)
 libbt-platform-protos-lite(minSdkVersion:30)
 libbt_keystore_cc(minSdkVersion:30)
 libbt_keystore_cc_headers(minSdkVersion:30)
 libbtcore_headers(minSdkVersion:30)
 libbuildversion(minSdkVersion:(no version))
 libbuildversion(minSdkVersion:26)
+libbytemuck(minSdkVersion:29)
+libbytemuck(minSdkVersion:34)
+libbyteorder(minSdkVersion:29)
+libbyteorder(minSdkVersion:34)
 libbytes(minSdkVersion:29)
 libc++(minSdkVersion:apex_inherit)
 libc++_static(minSdkVersion:apex_inherit)
@@ -436,6 +508,7 @@ libcfg_if(minSdkVersion:29)
 libcfg_if.rust_sysroot(minSdkVersion:29)
 libchrome(minSdkVersion:30)
 libclap(minSdkVersion:29)
+libclap_builder(minSdkVersion:29)
 libclap_lex(minSdkVersion:29)
 libcodec2(minSdkVersion:29)
 libcodec2_aidl(minSdkVersion:30)
@@ -452,6 +525,8 @@ libcodec2_soft_amrnbdec(minSdkVersion:29)
 libcodec2_soft_amrnbenc(minSdkVersion:29)
 libcodec2_soft_amrwbdec(minSdkVersion:29)
 libcodec2_soft_amrwbenc(minSdkVersion:29)
+libcodec2_soft_apvdec(minSdkVersion:29)
+libcodec2_soft_apvenc(minSdkVersion:29)
 libcodec2_soft_av1dec_dav1d(minSdkVersion:29)
 libcodec2_soft_av1dec_gav1(minSdkVersion:29)
 libcodec2_soft_av1enc(minSdkVersion:29)
@@ -485,6 +560,7 @@ libcombine(minSdkVersion:29)
 libcompiler_builtins.rust_sysroot(minSdkVersion:29)
 libcore.rust_sysroot(minSdkVersion:29)
 libcrypto(minSdkVersion:29)
+libcrypto_rpc_rs(minSdkVersion:34)
 libcrypto_static(minSdkVersion:(no version))
 libcrypto_static(minSdkVersion:29)
 libcrypto_utils(minSdkVersion:(no version))
@@ -495,9 +571,12 @@ libcutils_headers(minSdkVersion:29)
 libcutils_sockets(minSdkVersion:29)
 libcxx(minSdkVersion:29)
 libcxxbridge05(minSdkVersion:29)
+libdata_encoding(minSdkVersion:34)
 libdav1d(minSdkVersion:29)
 libdav1d_16bit(minSdkVersion:29)
 libdav1d_8bit(minSdkVersion:29)
+libdav1d_dotprod_i8mm(minSdkVersion:29)
+libdav1d_sve2(minSdkVersion:29)
 libdexfile_external_headers(minSdkVersion:31)
 libdexfile_support(minSdkVersion:31)
 libdiagnose_usb(minSdkVersion:(no version))
@@ -506,6 +585,7 @@ libdmabufheap(minSdkVersion:29)
 libdmabufinfo(minSdkVersion:S)
 libdoh_ffi(minSdkVersion:29)
 libdoh_ffi(minSdkVersion:30)
+libdoubleconversion(minSdkVersion:30)
 libdowncast_rs(minSdkVersion:29)
 libeigen(minSdkVersion:(no version))
 libeigen(minSdkVersion:apex_inherit)
@@ -532,6 +612,10 @@ libflags_rust_cpp_bridge(minSdkVersion:33)
 libflatbuffers-cpp(minSdkVersion:30)
 libfmq(minSdkVersion:29)
 libfmq-base(minSdkVersion:29)
+libfnv(minSdkVersion:29)
+libfnv(minSdkVersion:34)
+libforeign_types(minSdkVersion:29)
+libforeign_types_shared(minSdkVersion:29)
 libform_urlencoded(minSdkVersion:29)
 libFraunhoferAAC(minSdkVersion:29)
 libfstab(minSdkVersion:31)
@@ -550,6 +634,8 @@ libfutures_util(minSdkVersion:29)
 libgav1(minSdkVersion:29)
 libgcc_stripped(minSdkVersion:(no version))
 libgetopts(minSdkVersion:29)
+libgetrandom(minSdkVersion:29)
+libgetrandom(minSdkVersion:34)
 libgralloctypes(minSdkVersion:29)
 libgrallocusage(minSdkVersion:29)
 libgrpc(minSdkVersion:30)
@@ -598,20 +684,41 @@ libgtest_prod_headers(minSdkVersion:apex_inherit)
 libgui_bufferqueue_static(minSdkVersion:29)
 libgui_headers(minSdkVersion:29)
 libguiflags(minSdkVersion:29)
+libh2(minSdkVersion:29)
+libh2(minSdkVersion:34)
 libhardware(minSdkVersion:29)
 libhardware_headers(minSdkVersion:29)
+libhashbrown(minSdkVersion:29)
+libhashbrown(minSdkVersion:34)
 libhashbrown.rust_sysroot(minSdkVersion:29)
 libhevcdec(minSdkVersion:29)
 libhevcenc(minSdkVersion:29)
 libhidlbase(minSdkVersion:29)
 libhidlmemory(minSdkVersion:29)
+libhttp(minSdkVersion:29)
+libhttp(minSdkVersion:34)
+libhttp_body(minSdkVersion:29)
+libhttp_body(minSdkVersion:34)
+libhttparse(minSdkVersion:29)
+libhttparse(minSdkVersion:34)
+libhttpdate(minSdkVersion:29)
+libhttpdate(minSdkVersion:34)
 libhwbinder-impl-internal(minSdkVersion:29)
 libhwbinder_headers(minSdkVersion:29)
+libhyper(minSdkVersion:29)
+libhyper(minSdkVersion:34)
+libhyper_timeout(minSdkVersion:29)
+libhyper_timeout(minSdkVersion:34)
 libidna(minSdkVersion:29)
 libimapper_providerutils(minSdkVersion:29)
 libimapper_stablec(minSdkVersion:29)
+libindexmap(minSdkVersion:29)
+libindexmap(minSdkVersion:34)
 libion(minSdkVersion:29)
+libion_headers(minSdkVersion:29)
 libip_checksum(minSdkVersion:30)
+libitoa(minSdkVersion:29)
+libitoa(minSdkVersion:34)
 libjni(minSdkVersion:29)
 libjni_legacy(minSdkVersion:29)
 libjni_sys(minSdkVersion:29)
@@ -628,6 +735,8 @@ liblibc.rust_sysroot(minSdkVersion:29)
 libLibGuiProperties(minSdkVersion:29)
 liblibm(minSdkVersion:29)
 liblibz_sys(minSdkVersion:29)
+liblifecycle_cpp_service_bundle_test(minSdkVersion:34)
+liblifecycle_rust_service_bundle_test(minSdkVersion:34)
 liblock_api(minSdkVersion:29)
 liblog_headers(minSdkVersion:29)
 liblog_rust(minSdkVersion:29)
@@ -638,6 +747,8 @@ liblz4(minSdkVersion:(no version))
 liblz4(minSdkVersion:apex_inherit)
 liblzma(minSdkVersion:apex_inherit)
 libmatches(minSdkVersion:29)
+libmatchit(minSdkVersion:29)
+libmatchit(minSdkVersion:34)
 libmath(minSdkVersion:29)
 libmath_headers(minSdkVersion:apex_inherit)
 libmdnssd(minSdkVersion:(no version))
@@ -653,6 +764,8 @@ libmemchr(minSdkVersion:29)
 libmeminfo(minSdkVersion:S)
 libmemmap2(minSdkVersion:29)
 libmemoffset(minSdkVersion:29)
+libmime(minSdkVersion:29)
+libmime(minSdkVersion:34)
 libminijail(minSdkVersion:29)
 libminijail_gen_constants(minSdkVersion:(no version))
 libminijail_gen_constants_obj(minSdkVersion:29)
@@ -676,6 +789,7 @@ libnativeloader-headers(minSdkVersion:31)
 libnativewindow_headers(minSdkVersion:29)
 libnet_utils_device_common_bpfjni(minSdkVersion:30)
 libnet_utils_device_common_bpfutils(minSdkVersion:30)
+libnet_utils_device_common_timerfdjni(minSdkVersion:30)
 libnetdbinder_utils_headers(minSdkVersion:29)
 libnetdutils(minSdkVersion:29)
 libnetdutils(minSdkVersion:30)
@@ -688,13 +802,23 @@ libneuralnetworks_common(minSdkVersion:30)
 libneuralnetworks_headers(minSdkVersion:(no version))
 libneuralnetworks_headers(minSdkVersion:30)
 libneuralnetworks_shim_static(minSdkVersion:30)
+libnfc-nci(minSdkVersion:35)
+libnfc-nci_flags(minSdkVersion:35)
+libnfc_nci_jni(minSdkVersion:35)
+libnfcutils(minSdkVersion:35)
 libnix(minSdkVersion:29)
+libnl(minSdkVersion:apex_inherit)
 libnum_cpus(minSdkVersion:29)
 libnum_traits(minSdkVersion:29)
 liboctets(minSdkVersion:29)
+liboem_deadline_sched_service_bundle_rust_sample(minSdkVersion:34)
+liboem_service_bundle_cpp_sample(minSdkVersion:34)
+liboem_service_bundle_rust_sample(minSdkVersion:34)
 liboggextractor(minSdkVersion:29)
 libonce_cell(minSdkVersion:29)
+libopenapv(minSdkVersion:apex_inherit)
 libopenjdkjvmti_headers(minSdkVersion:31)
+libopenssl(minSdkVersion:29)
 libopus(minSdkVersion:29)
 libos_str_bytes(minSdkVersion:29)
 libpanic_abort.rust_sysroot(minSdkVersion:29)
@@ -728,12 +852,16 @@ libpdl_runtime(minSdkVersion:33)
 libpercent_encoding(minSdkVersion:29)
 libperfetto_client_experimental(minSdkVersion:30)
 libperfetto_client_experimental(minSdkVersion:S)
+libpin_project(minSdkVersion:29)
+libpin_project(minSdkVersion:34)
 libpin_project_lite(minSdkVersion:29)
 libpin_utils(minSdkVersion:29)
 libPlatformProperties(minSdkVersion:S)
 libpng(minSdkVersion:30)
 libpng(minSdkVersion:apex_inherit)
 libpower(minSdkVersion:Tiramisu)
+libppv_lite86(minSdkVersion:29)
+libppv_lite86(minSdkVersion:34)
 libproc_macro_nested(minSdkVersion:29)
 libprocessgroup(minSdkVersion:29)
 libprocessgroup_headers(minSdkVersion:29)
@@ -763,6 +891,12 @@ libprotoutil(minSdkVersion:(no version))
 libprotoutil(minSdkVersion:30)
 libqemu_pipe(minSdkVersion:(no version))
 libquiche(minSdkVersion:29)
+librand(minSdkVersion:29)
+librand(minSdkVersion:34)
+librand_chacha(minSdkVersion:29)
+librand_chacha(minSdkVersion:34)
+librand_core(minSdkVersion:29)
+librand_core(minSdkVersion:34)
 libremove_dir_all(minSdkVersion:29)
 libring(minSdkVersion:29)
 libring-core(minSdkVersion:29)
@@ -775,6 +909,32 @@ librustix(minSdkVersion:30)
 librustutils(minSdkVersion:29)
 libruy_static(minSdkVersion:30)
 libscopeguard(minSdkVersion:29)
+libsdv_comms_bindgen(minSdkVersion:34)
+libsdv_comms_bindgen_private(minSdkVersion:34)
+libsdv_comms_common(minSdkVersion:34)
+libsdv_comms_common_hdrs(minSdkVersion:34)
+libsdv_comms_cpp(minSdkVersion:34)
+libsdv_comms_ctx_hdrs(minSdkVersion:34)
+libsdv_comms_dt_hdrs(minSdkVersion:34)
+libsdv_comms_id_hdrs(minSdkVersion:34)
+libsdv_comms_rpc(minSdkVersion:34)
+libsdv_comms_rpc_hdrs(minSdkVersion:34)
+libsdv_comms_rs(minSdkVersion:34)
+libsdv_comms_sd_hdrs(minSdkVersion:34)
+libsdv_lifecycle_client_cpp(minSdkVersion:34)
+libsdv_lifecycle_client_rust(minSdkVersion:34)
+libsdv_log(minSdkVersion:34)
+libsdv_log_ffi_rs(minSdkVersion:34)
+libsdv_log_rust(minSdkVersion:34)
+libsdv_service_bundle_metadata(minSdkVersion:34)
+libsdv_service_bundles_manifest_proto(minSdkVersion:34)
+libsdv_service_bundles_scheduling(minSdkVersion:34)
+libsdv_service_bundles_scheduling_proto(minSdkVersion:34)
+libsdv_status(minSdkVersion:34)
+libsdv_status_cpp(minSdkVersion:34)
+libsdv_status_hdrs(minSdkVersion:34)
+libsdv_status_rs(minSdkVersion:34)
+libsdv_status_sys(minSdkVersion:34)
 libserde(minSdkVersion:29)
 libsfplugin_ccodec_utils(minSdkVersion:29)
 libslab(minSdkVersion:29)
@@ -813,11 +973,15 @@ libstagefright_mpeg2extractor(minSdkVersion:29)
 libstagefright_mpeg2support(minSdkVersion:29)
 libstatic_assertions(minSdkVersion:29)
 libstatslog_express(minSdkVersion:33)
+libstatslog_nfc(minSdkVersion:35)
 libstatspull_bindgen(minSdkVersion:apex_inherit)
 libstatssocket_headers(minSdkVersion:29)
 libstd(minSdkVersion:29)
 libstd_detect.rust_sysroot(minSdkVersion:29)
+libstrsim(minSdkVersion:29)
 libsync(minSdkVersion:(no version))
+libsync_wrapper(minSdkVersion:29)
+libsync_wrapper(minSdkVersion:34)
 libsystem_headers(minSdkVersion:apex_inherit)
 libsystem_properties_bindgen(minSdkVersion:29)
 libsystem_properties_bindgen_sys(minSdkVersion:29)
@@ -847,7 +1011,25 @@ libtinyvec(minSdkVersion:29)
 libtinyvec_macros(minSdkVersion:29)
 libtinyxml2(minSdkVersion:S)
 libtokio(minSdkVersion:29)
+libtokio_io_timeout(minSdkVersion:29)
+libtokio_io_timeout(minSdkVersion:34)
+libtokio_openssl(minSdkVersion:29)
 libtokio_stream(minSdkVersion:29)
+libtokio_util(minSdkVersion:29)
+libtonic(minSdkVersion:29)
+libtonic(minSdkVersion:34)
+libtower(minSdkVersion:29)
+libtower(minSdkVersion:34)
+libtower_layer(minSdkVersion:29)
+libtower_layer(minSdkVersion:34)
+libtower_service(minSdkVersion:29)
+libtower_service(minSdkVersion:34)
+libtracing(minSdkVersion:29)
+libtracing(minSdkVersion:34)
+libtracing_core(minSdkVersion:29)
+libtracing_core(minSdkVersion:34)
+libtry_lock(minSdkVersion:29)
+libtry_lock(minSdkVersion:34)
 libtsi(minSdkVersion:30)
 libtsi_interface(minSdkVersion:30)
 libui(minSdkVersion:29)
@@ -860,6 +1042,7 @@ libuntrusted(minSdkVersion:29)
 libunwind.rust_sysroot(minSdkVersion:29)
 libunwind_llvm(minSdkVersion:apex_inherit)
 libunwindstack(minSdkVersion:29)
+libuprobestats(minSdkVersion:35)
 liburl(minSdkVersion:29)
 libutf(minSdkVersion:(no version))
 libutf(minSdkVersion:14)
@@ -877,18 +1060,28 @@ libuwb_uci_packets(minSdkVersion:Tiramisu)
 libvendorsupport_llndk_headers(minSdkVersion:apex_inherit)
 libvorbisidec(minSdkVersion:29)
 libvpx(minSdkVersion:29)
+libvpx_neon_dotprod(minSdkVersion:29)
+libvpx_neon_i8mm(minSdkVersion:29)
+libvpx_sve(minSdkVersion:29)
+libwant(minSdkVersion:29)
+libwant(minSdkVersion:34)
 libwavextractor(minSdkVersion:29)
 libwebm(minSdkVersion:29)
 libwebm_mkvparser(minSdkVersion:29)
+libwpa_shared_aidl_headers_mainline(minSdkVersion:30)
 libxml2(minSdkVersion:apex_inherit)
 libyuv(minSdkVersion:29)
 libyuv_static(minSdkVersion:29)
 libz_static(minSdkVersion:apex_inherit)
+libzerocopy(minSdkVersion:29)
+libzerocopy-0.7.35(minSdkVersion:29)
 libzeroize(minSdkVersion:Tiramisu)
 libziparchive(minSdkVersion:apex_inherit)
 libzstd(minSdkVersion:(no version))
 libzstd(minSdkVersion:apex_inherit)
 lottie(minSdkVersion:21)
+mainline_supplicant_aidl_bp(minSdkVersion:30)
+mainline_supplicant_aidl_headers(minSdkVersion:30)
 marisa-trie(minSdkVersion:30)
 mdns_aidl_interface-V1-java(minSdkVersion:30)
 media_ndk_headers(minSdkVersion:29)
@@ -910,6 +1103,7 @@ modules-utils-bytesmatcher(minSdkVersion:29)
 modules-utils-expresslog(minSdkVersion:30)
 modules-utils-fastxmlserializer(minSdkVersion:29)
 modules-utils-handlerexecutor(minSdkVersion:29)
+modules-utils-infra(minSdkVersion:33)
 modules-utils-list-slice(minSdkVersion:30)
 modules-utils-locallog(minSdkVersion:30)
 modules-utils-os(minSdkVersion:30)
@@ -1042,6 +1236,7 @@ neuralnetworks_utils_hal_1_3(minSdkVersion:30)
 neuralnetworks_utils_hal_aidl(minSdkVersion:30)
 neuralnetworks_utils_hal_common(minSdkVersion:30)
 neuralnetworks_utils_hal_service(minSdkVersion:30)
+nfc-event-log-proto(minSdkVersion:35)
 note_memtag_heap_async(minSdkVersion:16)
 note_memtag_heap_sync(minSdkVersion:16)
 offlinelocationtimezoneprovider(minSdkVersion:31)
@@ -1156,6 +1351,9 @@ prebuilt_test_framework-sdkextensions(minSdkVersion:(no version))
 prebuilt_transport-api-aar(minSdkVersion:14)
 prebuilt_transport-backend-cct-aar(minSdkVersion:14)
 prebuilt_transport-runtime-aar(minSdkVersion:14)
+profiling_flags_lib(minSdkVersion:35)
+ranging_rtt_backend(minSdkVersion:33)
+ranging_uwb_backend(minSdkVersion:33)
 resourceobserver_aidl_interface-V1-ndk(minSdkVersion:29)
 resourceobserver_aidl_interface-V1-ndk_platform(minSdkVersion:29)
 rkpd(minSdkVersion:33)
@@ -1167,6 +1365,8 @@ service-entitlement(minSdkVersion:29)
 service-entitlement-api(minSdkVersion:29)
 service-entitlement-data(minSdkVersion:29)
 service-entitlement-impl(minSdkVersion:29)
+service-ondeviceintelligence(minSdkVersion:35)
+service-ondeviceintelligence.impl(minSdkVersion:35)
 ServiceWifiResourcesGoogle(minSdkVersion:30)
 settingslib_illustrationpreference_flags_lib(minSdkVersion:30)
 settingslib_selectorwithwidgetpreference_flags_lib(minSdkVersion:30)
@@ -1220,10 +1420,18 @@ tflite_support_libz(minSdkVersion:30)
 tflite_support_metadata_extractor(minSdkVersion:30)
 tflite_support_task_core_proto(minSdkVersion:30)
 tflite_support_tokenizers(minSdkVersion:30)
+trace_redactor(minSdkVersion:35)
+uprobestats(minSdkVersion:35)
+uprobestats_bpf_headers(minSdkVersion:35)
+uprobestats_bpf_syscall_wrappers(minSdkVersion:35)
+uprobestats_flags_c_lib(minSdkVersion:35)
+uprobestats_mainline_flags_c_lib(minSdkVersion:35)
 uwb_androidx_backend(minSdkVersion:30)
 wifi-lite-protos(minSdkVersion:30)
 wifi-nano-protos(minSdkVersion:30)
 wifi-service-pre-jarjar(minSdkVersion:30)
 wifi_aconfig_flags_lib(minSdkVersion:30)
+wpa_supplicant_headers_mainline(minSdkVersion:30)
+wpa_supplicant_mainline(minSdkVersion:30)
 xz-java(minSdkVersion:29)
 xz-java(minSdkVersion:current)
diff --git a/build/mainline_modules_sdks.py b/build/mainline_modules_sdks.py
index 07ea6d7..75e3536 100755
--- a/build/mainline_modules_sdks.py
+++ b/build/mainline_modules_sdks.py
@@ -334,6 +334,8 @@ def module_sdk_project_for_module(module, root_dir):
         return "prebuilts/module_sdk/Bluetooth"
     if module == "media":
         return "prebuilts/module_sdk/Media"
+    if module == "nfcservices":
+        return "prebuilts/module_sdk/Nfc"
     if module == "rkpd":
         return "prebuilts/module_sdk/RemoteKeyProvisioning"
     if module == "tethering":
@@ -868,6 +870,30 @@ UpsideDownCake = BuildRelease(
     # This build release supports the use_source_config_var property.
     preferHandling=PreferHandling.USE_SOURCE_CONFIG_VAR_PROPERTY,
 )
+VanillaIceCream = BuildRelease(
+    name="VanillaIceCream",
+    # Generate a snapshot for this build release using Soong.
+    creator=create_sdk_snapshots_in_soong,
+    # There are no build release specific environment variables to pass to
+    # Soong.
+    soong_env={},
+    # Starting with V, setting `prefer|use_source_config_var` on soong modules
+    # in prebuilts/module_sdk is not necessary.
+    # prebuilts will be enabled using apex_contributions release build flags.
+    preferHandling=PreferHandling.USE_NO_PREFER_PROPERTY,
+)
+Baklava = BuildRelease(
+    name="Baklava",
+    # Generate a snapshot for this build release using Soong.
+    creator=create_sdk_snapshots_in_soong,
+    # There are no build release specific environment variables to pass to
+    # Soong.
+    soong_env={},
+    # Starting with V, setting `prefer|use_source_config_var` on soong modules
+    # in prebuilts/module_sdk is not necessary.
+    # prebuilts will be enabled using apex_contributions release build flags.
+    preferHandling=PreferHandling.USE_NO_PREFER_PROPERTY,
+)
 
 # Insert additional BuildRelease definitions for following releases here,
 # before LATEST.
@@ -1181,6 +1207,14 @@ MAINLINE_MODULES = [
         last_optional_release=LATEST,
         module_proto_key="MEDIA_PROVIDER",
     ),
+    MainlineModule(
+        apex="com.android.nfcservices",
+        sdks=["nfcservices-module-sdk"],
+        first_release=Baklava,
+        # NFC is optional.
+        last_optional_release=LATEST,
+        module_proto_key="",
+    ),
     MainlineModule(
         apex="com.android.ondevicepersonalization",
         sdks=["ondevicepersonalization-module-sdk"],
diff --git a/javatests/com/android/modules/apkinapex/Android.bp b/javatests/com/android/modules/apkinapex/Android.bp
index 101ffb3..9ccba92 100644
--- a/javatests/com/android/modules/apkinapex/Android.bp
+++ b/javatests/com/android/modules/apkinapex/Android.bp
@@ -25,7 +25,7 @@ java_test_host {
         "ApkInApexTest.java",
     ],
     libs: ["tradefed"],
-    java_resources: [
+    device_common_java_resources: [
         ":test_com.android.modules.apkinapex",
     ],
     static_libs: [
diff --git a/javatests/com/android/modules/targetprep/Android.bp b/javatests/com/android/modules/targetprep/Android.bp
index 3e56a25..b9463fb 100644
--- a/javatests/com/android/modules/targetprep/Android.bp
+++ b/javatests/com/android/modules/targetprep/Android.bp
@@ -35,7 +35,7 @@ java_test_host {
         "junit",
         "tradefed",
     ],
-    java_resources: [
+    device_common_java_resources: [
         ":LibraryA",
         ":LibraryB",
     ],
diff --git a/javatests/com/android/modules/updatablesharedlibs/Android.bp b/javatests/com/android/modules/updatablesharedlibs/Android.bp
index 68f3b37..a1ce8b6 100644
--- a/javatests/com/android/modules/updatablesharedlibs/Android.bp
+++ b/javatests/com/android/modules/updatablesharedlibs/Android.bp
@@ -25,10 +25,10 @@ java_test_host {
         "UpdatableSharedLibsTest.java",
     ],
     libs: ["tradefed"],
-    java_resources: [
+    device_common_java_resources: [
         ":test_com.android.modules.updatablesharedlibs",
     ],
-    data: [
+    device_common_data: [
         ":com.android.modules.updatablesharedlibs.apps.targetS",
         ":com.android.modules.updatablesharedlibs.apps.targetT",
         ":com.android.modules.updatablesharedlibs.apps.targetTWithLib",
diff --git a/proguard/system-api.pro b/proguard/system-api.pro
index 6e08c50..2ed95ed 100644
--- a/proguard/system-api.pro
+++ b/proguard/system-api.pro
@@ -1,13 +1,14 @@
--keep @interface android.annotation.SystemApi
+-keep interface android.annotation.SystemApi
 -keep @android.annotation.SystemApi public class * {
     public protected *;
 }
 -keepclasseswithmembers public class * {
-    @android.annotation.SystemApi public protected <fields>;
+    @android.annotation.SystemApi public protected *;
 }
--keepclasseswithmembers public class * {
-    @android.annotation.SystemApi public protected <init>(...);
-}
--keepclasseswithmembers public class * {
-    @android.annotation.SystemApi public protected <methods>;
+# Also ensure nested classes are kept. This is overly conservative, but handles
+# cases where such classes aren't explicitly marked @SystemApi.
+# TODO(b/248580093): Rely on Metalava-generated Proguard rules instead.
+-if @android.annotation.SystemApi class *
+-keep public class <1>$** {
+    public protected *;
 }
diff --git a/sdk/Android.bp b/sdk/Android.bp
index 2fda6f9..da8370d 100644
--- a/sdk/Android.bp
+++ b/sdk/Android.bp
@@ -1,4 +1,4 @@
-// Copyright (C) 2021 The Android Open Source Project
+// Copyright (C) 2019 The Android Open Source Project
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -12,6 +12,310 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-build = [
-    "ModuleDefaults.bp",
-]
+package {
+    default_visibility: [":__subpackages__"],
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// Defaults common to all mainline module java_sdk_library instances.
+java_defaults {
+    name: "framework-module-common-defaults",
+
+    // Use the source of annotations that affect metalava doc generation, since
+    // the relevant generation instructions are themselves in javadoc, which is
+    // not present in class files.
+    api_srcs: [":framework-metalava-annotations"],
+
+    // Make the source retention annotations available on the classpath when compiling
+    // the implementation library. (This should be in impl_only_libs but some modules
+    // use these defaults for java_library, sigh.)
+    libs: ["framework-annotations-lib"],
+
+    // Framework modules are not generally shared libraries, i.e. they are not
+    // intended, and must not be allowed, to be used in a <uses-library> manifest
+    // entry.
+    shared_library: false,
+
+    // Prevent dependencies that do not specify an sdk_version from accessing the
+    // implementation library by default and force them to use stubs instead.
+    default_to_stubs: true,
+
+    // Enable api lint. This will eventually become the default for java_sdk_library
+    // but it cannot yet be turned on because some usages have not been cleaned up.
+    // TODO(b/156126315) - Remove when no longer needed.
+    api_lint: {
+        enabled: true,
+        legacy_errors_allowed: false,
+    },
+
+    // The API scope specific properties.
+    public: {
+        enabled: true,
+        sdk_version: "module_current",
+    },
+
+    // installable implies we'll create a non-apex (platform) variant, which
+    // we shouldn't ordinarily need (and it can create issues), so disable that.
+    installable: false,
+
+    // Configure framework module specific metalava options.
+    droiddoc_options: [
+        "--error UnhiddenSystemApi",
+        "--error UnflaggedApi",
+        "--error-when-new FlaggedApiLiteral",
+        "--hide CallbackInterface",
+        "--enhance-documentation",
+    ],
+
+    annotations_enabled: true,
+
+    // Allow access to the stubs from anywhere
+    visibility: ["//visibility:public"],
+    stubs_library_visibility: ["//visibility:public"],
+
+    // Hide impl library and stub sources
+    impl_library_visibility: [
+        ":__pkg__",
+        "//frameworks/base/api", // For framework-all
+    ],
+    stubs_source_visibility: [
+        ":__pkg__",
+        "//frameworks/base/api", // For all-modules-public-stubs-source-exportable
+    ],
+
+    defaults_visibility: ["//visibility:private"],
+
+    dist_group: "android",
+}
+
+// Defaults for the java_sdk_libraries of non-updatable modules.
+// java_sdk_libraries using these defaults should also add themselves to the
+// non_updatable_modules list in frameworks/base/api/api.go
+java_defaults {
+    name: "non-updatable-framework-module-defaults",
+    defaults: ["framework-module-common-defaults"],
+
+    system: {
+        enabled: true,
+        sdk_version: "module_current",
+    },
+    module_lib: {
+        enabled: true,
+        sdk_version: "module_current",
+    },
+    // Non-updatable modules are allowed to provide @TestApi
+    test: {
+        enabled: true,
+        sdk_version: "module_current",
+    },
+
+    defaults_visibility: [
+        "//frameworks/base",
+        "//frameworks/base/api",
+        "//packages/modules/Virtualization:__subpackages__",
+    ],
+}
+
+// Defaults for mainline module provided java_sdk_library instances.
+java_defaults {
+    name: "framework-module-defaults",
+    defaults: ["framework-module-common-defaults"],
+    sdk_version: "module_current",
+
+    system: {
+        enabled: true,
+        sdk_version: "module_current",
+    },
+    module_lib: {
+        enabled: true,
+        sdk_version: "module_current",
+    },
+
+    defaults_visibility: [
+        ":__subpackages__",
+        // TODO(b/237461653): Move this to packages/modules/Nfc
+        "//frameworks/base/nfc",
+        "//frameworks/base/apex:__subpackages__",
+        "//frameworks/base/libs/hwui",
+        "//frameworks/base/packages/Vcn:__subpackages__",
+        "//frameworks/base/wifi",
+        "//packages/modules:__subpackages__",
+        "//packages/providers/MediaProvider:__subpackages__",
+        "//system/apex/apexd:__subpackages__",
+    ],
+}
+
+// Defaults for mainline module system server provided java_sdk_library instances.
+java_defaults {
+    name: "framework-system-server-module-defaults",
+    defaults: ["framework-module-common-defaults"],
+    sdk_version: "system_server_current",
+
+    system_server: {
+        enabled: true,
+        sdk_version: "system_server_current",
+    },
+
+    defaults_visibility: [
+        ":__subpackages__",
+        "//art/libartservice:__subpackages__",
+        "//frameworks/base/apex:__subpackages__",
+        "//frameworks/base/packages/Vcn:__subpackages__",
+        "//packages/modules:__subpackages__",
+        "//system/apex/apexd:__subpackages__",
+    ],
+}
+
+filegroup_defaults {
+    name: "framework-sources-module-defaults",
+    visibility: [
+        "//frameworks/base",
+        "//frameworks/base/api",
+    ],
+    defaults_visibility: ["//visibility:public"],
+}
+
+// These apex_defaults serve as a common place to add properties which should
+// affect all mainline modules.
+
+APEX_LOWEST_MIN_SDK_VERSION = "30"
+DCLA_MIN_SDK_VERSION = "31"
+
+apex_defaults {
+    name: "any-launched-apex-modules",
+    updatable: true,
+    defaults_visibility: ["//visibility:public"],
+}
+
+apex_defaults {
+    name: "q-launched-apex-module",
+    defaults: ["any-launched-apex-modules"],
+    min_sdk_version: APEX_LOWEST_MIN_SDK_VERSION,
+    defaults_visibility: ["//visibility:public"],
+}
+
+soong_config_module_type_import {
+    from: "system/apex/Android.bp",
+    module_types: [
+        "library_linking_strategy_apex_defaults",
+        "library_linking_strategy_cc_defaults",
+    ],
+}
+
+library_linking_strategy_apex_defaults {
+    name: "q-launched-dcla-enabled-apex-module",
+    defaults_visibility: [
+        "//external/conscrypt/apex",
+        "//packages/modules/DnsResolver/apex",
+        "//frameworks/av/apex",
+    ],
+    defaults: ["q-launched-apex-module"],
+    soong_config_variables: {
+        library_linking_strategy: {
+            // Use the Q min_sdk_version
+            prefer_static: {},
+            // Override the Q min_sdk_version to min_sdk_version that supports dcla
+            conditions_default: {
+                min_sdk_version: DCLA_MIN_SDK_VERSION,
+            },
+        },
+    },
+}
+
+apex_defaults {
+    name: "r-launched-apex-module",
+    defaults: ["any-launched-apex-modules"],
+    min_sdk_version: "30",
+    defaults_visibility: ["//visibility:public"],
+}
+
+library_linking_strategy_apex_defaults {
+    name: "r-launched-dcla-enabled-apex-module",
+    defaults_visibility: [
+        "//packages/modules/adb:__subpackages__",
+        "//packages/modules/Connectivity/Tethering/apex",
+    ],
+    defaults: ["r-launched-apex-module"],
+    soong_config_variables: {
+        library_linking_strategy: {
+            // Use the R min_sdk_version
+            prefer_static: {},
+            // Override the R min_sdk_version to min_sdk_version that supports dcla
+            conditions_default: {
+                min_sdk_version: DCLA_MIN_SDK_VERSION,
+            },
+        },
+    },
+}
+
+apex_defaults {
+    name: "s-launched-apex-module",
+    defaults: ["any-launched-apex-modules"],
+    min_sdk_version: "31",
+    // Indicates that pre-installed version of this apex can be compressed.
+    // Whether it actually will be compressed is controlled on per-device basis.
+    compressible: true,
+    defaults_visibility: [
+        "//art:__subpackages__",
+        "//packages/modules:__subpackages__",
+    ],
+}
+
+apex_defaults {
+    name: "t-launched-apex-module",
+    defaults: ["any-launched-apex-modules"],
+    min_sdk_version: "Tiramisu",
+    // Indicates that pre-installed version of this apex can be compressed.
+    // Whether it actually will be compressed is controlled on per-device basis.
+    compressible: true,
+    defaults_visibility: ["//packages/modules:__subpackages__"],
+}
+
+apex_defaults {
+    name: "u-launched-apex-module",
+    defaults: ["any-launched-apex-modules"],
+    min_sdk_version: "UpsideDownCake",
+    // Indicates that pre-installed version of this apex can be compressed.
+    // Whether it actually will be compressed is controlled on per-device basis.
+    compressible: true,
+    defaults_visibility: ["//packages/modules:__subpackages__"],
+}
+
+apex_defaults {
+    name: "v-launched-apex-module",
+    defaults: ["any-launched-apex-modules"],
+    min_sdk_version: "VanillaIceCream",
+    // Indicates that pre-installed version of this apex can be compressed.
+    // Whether it actually will be compressed is controlled on per-device basis.
+    compressible: true,
+    defaults_visibility: ["//packages/modules:__subpackages__"],
+}
+
+apex_defaults {
+    name: "b-launched-apex-module",
+    defaults: ["any-launched-apex-modules"],
+    min_sdk_version: "Baklava",
+    // Indicates that pre-installed version of this apex can be compressed.
+    // Whether it actually will be compressed is controlled on per-device basis.
+    compressible: true,
+    defaults_visibility: [
+        "//packages/modules:__subpackages__",
+        // TODO(b/367426693): Remove this once NFC codebase is moved.
+        "//packages/apps/Nfc:__subpackages__",
+    ],
+}
+
+library_linking_strategy_cc_defaults {
+    name: "apex-lowest-min-sdk-version",
+    defaults_visibility: [
+        "//system/core/libutils:__subpackages__",
+    ],
+    min_sdk_version: APEX_LOWEST_MIN_SDK_VERSION,
+    soong_config_variables: {
+        library_linking_strategy: {
+            prefer_static: {
+                min_sdk_version: "apex_inherit",
+            },
+        },
+    },
+}
diff --git a/sdk/ModuleDefaults.bp b/sdk/ModuleDefaults.bp
deleted file mode 100644
index c1e84fd..0000000
--- a/sdk/ModuleDefaults.bp
+++ /dev/null
@@ -1,311 +0,0 @@
-// Copyright (C) 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_visibility: [":__subpackages__"],
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-// Defaults common to all mainline module java_sdk_library instances.
-java_defaults {
-    name: "framework-module-common-defaults",
-
-    // Use the source of annotations that affect metalava doc generation, since
-    // the relevant generation instructions are themselves in javadoc, which is
-    // not present in class files.
-    api_srcs: [":framework-metalava-annotations"],
-
-    // Make the source retention annotations available on the classpath when compiling
-    // the implementation library. (This should be in impl_only_libs but some modules
-    // use these defaults for java_library, sigh.)
-    libs: ["framework-annotations-lib"],
-
-    // Framework modules are not generally shared libraries, i.e. they are not
-    // intended, and must not be allowed, to be used in a <uses-library> manifest
-    // entry.
-    shared_library: false,
-
-    // Prevent dependencies that do not specify an sdk_version from accessing the
-    // implementation library by default and force them to use stubs instead.
-    default_to_stubs: true,
-
-    // Enable api lint. This will eventually become the default for java_sdk_library
-    // but it cannot yet be turned on because some usages have not been cleaned up.
-    // TODO(b/156126315) - Remove when no longer needed.
-    api_lint: {
-        enabled: true,
-        legacy_errors_allowed: false,
-    },
-
-    // The API scope specific properties.
-    public: {
-        enabled: true,
-        sdk_version: "module_current",
-    },
-
-    // installable implies we'll create a non-apex (platform) variant, which
-    // we shouldn't ordinarily need (and it can create issues), so disable that.
-    installable: false,
-
-    // Configure framework module specific metalava options.
-    droiddoc_options: [
-        "--error UnhiddenSystemApi",
-        "--error UnflaggedApi",
-        "--hide CallbackInterface",
-        "--enhance-documentation",
-    ],
-
-    annotations_enabled: true,
-
-    // Allow access to the stubs from anywhere
-    visibility: ["//visibility:public"],
-    stubs_library_visibility: ["//visibility:public"],
-
-    // Hide impl library and stub sources
-    impl_library_visibility: [
-        ":__pkg__",
-        "//frameworks/base/api", // For framework-all
-    ],
-    stubs_source_visibility: ["//visibility:private"],
-
-    defaults_visibility: ["//visibility:private"],
-
-    dist_group: "android",
-}
-
-// Defaults for the java_sdk_libraries of non-updatable modules.
-// java_sdk_libraries using these defaults should also add themselves to the
-// non_updatable_modules list in frameworks/base/api/api.go
-java_defaults {
-    name: "non-updatable-framework-module-defaults",
-    defaults: ["framework-module-common-defaults"],
-
-    system: {
-        enabled: true,
-        sdk_version: "module_current",
-    },
-    module_lib: {
-        enabled: true,
-        sdk_version: "module_current",
-    },
-    // Non-updatable modules are allowed to provide @TestApi
-    test: {
-        enabled: true,
-        sdk_version: "module_current",
-    },
-
-    defaults_visibility: [
-        "//frameworks/base",
-        "//frameworks/base/api",
-        "//packages/modules/Virtualization:__subpackages__",
-    ],
-}
-
-// Defaults for mainline module provided java_sdk_library instances.
-java_defaults {
-    name: "framework-module-defaults",
-    defaults: ["framework-module-common-defaults"],
-    sdk_version: "module_current",
-
-    system: {
-        enabled: true,
-        sdk_version: "module_current",
-    },
-    module_lib: {
-        enabled: true,
-        sdk_version: "module_current",
-    },
-
-    defaults_visibility: [
-        ":__subpackages__",
-        // TODO(b/237461653): Move this to packages/modules/Nfc
-        "//frameworks/base/nfc",
-        "//frameworks/base/apex:__subpackages__",
-        "//frameworks/base/libs/hwui",
-        "//frameworks/base/wifi",
-        "//packages/modules:__subpackages__",
-        "//packages/providers/MediaProvider:__subpackages__",
-        "//system/apex/apexd:__subpackages__",
-    ],
-}
-
-// Defaults for mainline module system server provided java_sdk_library instances.
-java_defaults {
-    name: "framework-system-server-module-defaults",
-    defaults: ["framework-module-common-defaults"],
-    sdk_version: "system_server_current",
-
-    system_server: {
-        enabled: true,
-        sdk_version: "system_server_current",
-    },
-
-    defaults_visibility: [
-        ":__subpackages__",
-        "//art/libartservice:__subpackages__",
-        "//frameworks/base/apex:__subpackages__",
-        "//packages/modules:__subpackages__",
-        "//system/apex/apexd:__subpackages__",
-    ],
-}
-
-filegroup_defaults {
-    name: "framework-sources-module-defaults",
-    visibility: [
-        "//frameworks/base",
-        "//frameworks/base/api",
-    ],
-    defaults_visibility: ["//visibility:public"],
-}
-
-// These apex_defaults serve as a common place to add properties which should
-// affect all mainline modules.
-
-APEX_LOWEST_MIN_SDK_VERSION = "30"
-DCLA_MIN_SDK_VERSION = "31"
-
-apex_defaults {
-    name: "any-launched-apex-modules",
-    updatable: true,
-    defaults_visibility: ["//visibility:public"],
-}
-
-apex_defaults {
-    name: "q-launched-apex-module",
-    defaults: ["any-launched-apex-modules"],
-    min_sdk_version: APEX_LOWEST_MIN_SDK_VERSION,
-    defaults_visibility: ["//visibility:public"],
-}
-
-soong_config_module_type_import {
-    from: "system/apex/Android.bp",
-    module_types: [
-        "library_linking_strategy_apex_defaults",
-        "library_linking_strategy_cc_defaults",
-    ],
-}
-
-library_linking_strategy_apex_defaults {
-    name: "q-launched-dcla-enabled-apex-module",
-    defaults_visibility: [
-         "//external/conscrypt/apex",
-         "//packages/modules/DnsResolver/apex",
-         "//frameworks/av/apex"
-    ],
-    defaults: ["q-launched-apex-module"],
-    soong_config_variables: {
-        library_linking_strategy: {
-            // Use the Q min_sdk_version
-            prefer_static: {},
-            // Override the Q min_sdk_version to min_sdk_version that supports dcla
-            conditions_default: {
-                min_sdk_version: DCLA_MIN_SDK_VERSION,
-            },
-        },
-    },
-}
-
-apex_defaults {
-    name: "r-launched-apex-module",
-    defaults: ["any-launched-apex-modules"],
-    min_sdk_version: "30",
-    defaults_visibility: ["//visibility:public"],
-}
-
-library_linking_strategy_apex_defaults {
-    name: "r-launched-dcla-enabled-apex-module",
-    defaults_visibility: [
-         "//packages/modules/adb:__subpackages__",
-         "//packages/modules/Connectivity/Tethering/apex",
-    ],
-    defaults: ["r-launched-apex-module"],
-    soong_config_variables: {
-        library_linking_strategy: {
-            // Use the R min_sdk_version
-            prefer_static: {},
-            // Override the R min_sdk_version to min_sdk_version that supports dcla
-            conditions_default: {
-                min_sdk_version: DCLA_MIN_SDK_VERSION,
-            },
-        },
-    },
-}
-
-apex_defaults {
-    name: "s-launched-apex-module",
-    defaults: ["any-launched-apex-modules"],
-    min_sdk_version: "31",
-    // Indicates that pre-installed version of this apex can be compressed.
-    // Whether it actually will be compressed is controlled on per-device basis.
-    compressible:true,
-    defaults_visibility: [
-        "//art:__subpackages__",
-        "//packages/modules:__subpackages__",
-    ],
-}
-
-apex_defaults {
-    name: "t-launched-apex-module",
-    defaults: ["any-launched-apex-modules"],
-    min_sdk_version: "Tiramisu",
-    // Indicates that pre-installed version of this apex can be compressed.
-    // Whether it actually will be compressed is controlled on per-device basis.
-    compressible: true,
-    defaults_visibility: ["//packages/modules:__subpackages__"],
-}
-
-apex_defaults {
-    name: "u-launched-apex-module",
-    defaults: ["any-launched-apex-modules"],
-    min_sdk_version: "UpsideDownCake",
-    // Indicates that pre-installed version of this apex can be compressed.
-    // Whether it actually will be compressed is controlled on per-device basis.
-    compressible: true,
-    defaults_visibility: ["//packages/modules:__subpackages__"],
-}
-
-apex_defaults {
-    name: "v-launched-apex-module",
-    defaults: ["any-launched-apex-modules"],
-    min_sdk_version: "VanillaIceCream",
-    // Indicates that pre-installed version of this apex can be compressed.
-    // Whether it actually will be compressed is controlled on per-device basis.
-    compressible: true,
-    defaults_visibility: ["//packages/modules:__subpackages__"],
-}
-
-apex_defaults {
-    name: "b-launched-apex-module",
-    defaults: ["any-launched-apex-modules"],
-    min_sdk_version: "Baklava",
-    // Indicates that pre-installed version of this apex can be compressed.
-    // Whether it actually will be compressed is controlled on per-device basis.
-    compressible: true,
-    defaults_visibility: ["//packages/modules:__subpackages__"],
-}
-
-library_linking_strategy_cc_defaults {
-    name: "apex-lowest-min-sdk-version",
-    defaults_visibility: [
-         "//system/core/libutils:__subpackages__",
-    ],
-    min_sdk_version: APEX_LOWEST_MIN_SDK_VERSION,
-    soong_config_variables: {
-        library_linking_strategy: {
-            prefer_static: {
-                min_sdk_version: "apex_inherit",
-            },
-        },
-    },
-}
```

