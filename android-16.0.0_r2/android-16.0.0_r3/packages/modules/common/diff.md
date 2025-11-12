```diff
diff --git a/OWNERS b/OWNERS
index c6cea76..8c43595 100644
--- a/OWNERS
+++ b/OWNERS
@@ -5,13 +5,17 @@ amhk@google.com
 dariofreni@google.com
 gurpreetgs@google.com
 harshitmahajan@google.com
+ishcheikin@google.com
 kalyssa@google.com
 marcots@google.com
+mast@google.com
 oyalcin@google.com
 paulduffin@google.com
 pedroql@google.com
 psych@google.com
 robertogil@google.com
+rpl@google.com
+scianciulli@google.com
 
 # Escalations
 jham@google.com
diff --git a/build/allowed_deps.txt b/build/allowed_deps.txt
index 943419f..30ad466 100644
--- a/build/allowed_deps.txt
+++ b/build/allowed_deps.txt
@@ -13,6 +13,174 @@
 # See go/apex-allowed-deps-error for more details.
 # TODO(b/157465465): introduce automated quality signals and remove this list.
 
+absl_algorithm(minSdkVersion:apex_inherit)
+absl_algorithm_container(minSdkVersion:apex_inherit)
+absl_base(minSdkVersion:apex_inherit)
+absl_base_atomic_hook(minSdkVersion:apex_inherit)
+absl_base_base_internal(minSdkVersion:apex_inherit)
+absl_base_config(minSdkVersion:apex_inherit)
+absl_base_core_headers(minSdkVersion:apex_inherit)
+absl_base_cycleclock_internal(minSdkVersion:apex_inherit)
+absl_base_dynamic_annotations(minSdkVersion:apex_inherit)
+absl_base_endian(minSdkVersion:apex_inherit)
+absl_base_errno_saver(minSdkVersion:apex_inherit)
+absl_base_fast_type_id(minSdkVersion:apex_inherit)
+absl_base_log_severity(minSdkVersion:apex_inherit)
+absl_base_malloc_internal(minSdkVersion:apex_inherit)
+absl_base_no_destructor(minSdkVersion:apex_inherit)
+absl_base_nullability(minSdkVersion:apex_inherit)
+absl_base_prefetch(minSdkVersion:apex_inherit)
+absl_base_raw_logging_internal(minSdkVersion:apex_inherit)
+absl_base_spinlock_wait(minSdkVersion:apex_inherit)
+absl_base_strerror(minSdkVersion:apex_inherit)
+absl_base_throw_delegate(minSdkVersion:apex_inherit)
+absl_cleanup(minSdkVersion:apex_inherit)
+absl_cleanup_cleanup_internal(minSdkVersion:apex_inherit)
+absl_container_btree(minSdkVersion:apex_inherit)
+absl_container_common(minSdkVersion:apex_inherit)
+absl_container_common_policy_traits(minSdkVersion:apex_inherit)
+absl_container_compressed_tuple(minSdkVersion:apex_inherit)
+absl_container_container_memory(minSdkVersion:apex_inherit)
+absl_container_fixed_array(minSdkVersion:apex_inherit)
+absl_container_flat_hash_map(minSdkVersion:apex_inherit)
+absl_container_flat_hash_set(minSdkVersion:apex_inherit)
+absl_container_hash_container_defaults(minSdkVersion:apex_inherit)
+absl_container_hash_function_defaults(minSdkVersion:apex_inherit)
+absl_container_hash_policy_traits(minSdkVersion:apex_inherit)
+absl_container_hashtable_debug_hooks(minSdkVersion:apex_inherit)
+absl_container_hashtablez_sampler(minSdkVersion:apex_inherit)
+absl_container_inlined_vector(minSdkVersion:apex_inherit)
+absl_container_inlined_vector_internal(minSdkVersion:apex_inherit)
+absl_container_layout(minSdkVersion:apex_inherit)
+absl_container_node_hash_map(minSdkVersion:apex_inherit)
+absl_container_node_hash_set(minSdkVersion:apex_inherit)
+absl_container_node_slot_policy(minSdkVersion:apex_inherit)
+absl_container_raw_hash_map(minSdkVersion:apex_inherit)
+absl_container_raw_hash_set(minSdkVersion:apex_inherit)
+absl_crc_cpu_detect(minSdkVersion:apex_inherit)
+absl_crc_crc32c(minSdkVersion:apex_inherit)
+absl_crc_crc_cord_state(minSdkVersion:apex_inherit)
+absl_crc_crc_internal(minSdkVersion:apex_inherit)
+absl_crc_non_temporal_arm_intrinsics(minSdkVersion:apex_inherit)
+absl_crc_non_temporal_memcpy(minSdkVersion:apex_inherit)
+absl_debugging_bounded_utf8_length_sequence(minSdkVersion:apex_inherit)
+absl_debugging_debugging_internal(minSdkVersion:apex_inherit)
+absl_debugging_decode_rust_punycode(minSdkVersion:apex_inherit)
+absl_debugging_demangle_internal(minSdkVersion:apex_inherit)
+absl_debugging_demangle_rust(minSdkVersion:apex_inherit)
+absl_debugging_examine_stack(minSdkVersion:apex_inherit)
+absl_debugging_failure_signal_handler(minSdkVersion:apex_inherit)
+absl_debugging_stacktrace(minSdkVersion:apex_inherit)
+absl_debugging_symbolize(minSdkVersion:apex_inherit)
+absl_debugging_utf8_for_code_point(minSdkVersion:apex_inherit)
+absl_flags_commandlineflag(minSdkVersion:apex_inherit)
+absl_flags_commandlineflag_internal(minSdkVersion:apex_inherit)
+absl_flags_config(minSdkVersion:apex_inherit)
+absl_flags_flag(minSdkVersion:apex_inherit)
+absl_flags_flag_internal(minSdkVersion:apex_inherit)
+absl_flags_marshalling(minSdkVersion:apex_inherit)
+absl_flags_parse(minSdkVersion:apex_inherit)
+absl_flags_path_util(minSdkVersion:apex_inherit)
+absl_flags_private_handle_accessor(minSdkVersion:apex_inherit)
+absl_flags_program_name(minSdkVersion:apex_inherit)
+absl_flags_reflection(minSdkVersion:apex_inherit)
+absl_flags_usage(minSdkVersion:apex_inherit)
+absl_flags_usage_internal(minSdkVersion:apex_inherit)
+absl_functional_any_invocable(minSdkVersion:apex_inherit)
+absl_functional_bind_front(minSdkVersion:apex_inherit)
+absl_functional_function_ref(minSdkVersion:apex_inherit)
+absl_hash(minSdkVersion:apex_inherit)
+absl_hash_city(minSdkVersion:apex_inherit)
+absl_hash_low_level_hash(minSdkVersion:apex_inherit)
+absl_log(minSdkVersion:apex_inherit)
+absl_log_absl_check(minSdkVersion:apex_inherit)
+absl_log_absl_log(minSdkVersion:apex_inherit)
+absl_log_absl_vlog_is_on(minSdkVersion:apex_inherit)
+absl_log_check(minSdkVersion:apex_inherit)
+absl_log_globals(minSdkVersion:apex_inherit)
+absl_log_initialize(minSdkVersion:apex_inherit)
+absl_log_internal_append_truncated(minSdkVersion:apex_inherit)
+absl_log_internal_check_impl(minSdkVersion:apex_inherit)
+absl_log_internal_check_op(minSdkVersion:apex_inherit)
+absl_log_internal_conditions(minSdkVersion:apex_inherit)
+absl_log_internal_config(minSdkVersion:apex_inherit)
+absl_log_internal_fnmatch(minSdkVersion:apex_inherit)
+absl_log_internal_format(minSdkVersion:apex_inherit)
+absl_log_internal_globals(minSdkVersion:apex_inherit)
+absl_log_internal_log_impl(minSdkVersion:apex_inherit)
+absl_log_internal_log_message(minSdkVersion:apex_inherit)
+absl_log_internal_log_sink_set(minSdkVersion:apex_inherit)
+absl_log_internal_nullguard(minSdkVersion:apex_inherit)
+absl_log_internal_nullstream(minSdkVersion:apex_inherit)
+absl_log_internal_proto(minSdkVersion:apex_inherit)
+absl_log_internal_strip(minSdkVersion:apex_inherit)
+absl_log_internal_vlog_config(minSdkVersion:apex_inherit)
+absl_log_internal_voidify(minSdkVersion:apex_inherit)
+absl_log_log_entry(minSdkVersion:apex_inherit)
+absl_log_log_sink(minSdkVersion:apex_inherit)
+absl_log_log_sink_registry(minSdkVersion:apex_inherit)
+absl_log_vlog_is_on(minSdkVersion:apex_inherit)
+absl_memory(minSdkVersion:apex_inherit)
+absl_meta_type_traits(minSdkVersion:apex_inherit)
+absl_numeric_bits(minSdkVersion:apex_inherit)
+absl_numeric_int128(minSdkVersion:apex_inherit)
+absl_numeric_representation(minSdkVersion:apex_inherit)
+absl_profiling_exponential_biased(minSdkVersion:apex_inherit)
+absl_profiling_sample_recorder(minSdkVersion:apex_inherit)
+absl_random(minSdkVersion:apex_inherit)
+absl_random_bit_gen_ref(minSdkVersion:apex_inherit)
+absl_random_distributions(minSdkVersion:apex_inherit)
+absl_random_internal_distribution_caller(minSdkVersion:apex_inherit)
+absl_random_internal_fast_uniform_bits(minSdkVersion:apex_inherit)
+absl_random_internal_fastmath(minSdkVersion:apex_inherit)
+absl_random_internal_generate_real(minSdkVersion:apex_inherit)
+absl_random_internal_iostream_state_saver(minSdkVersion:apex_inherit)
+absl_random_internal_nonsecure_base(minSdkVersion:apex_inherit)
+absl_random_internal_pcg_engine(minSdkVersion:apex_inherit)
+absl_random_internal_platform(minSdkVersion:apex_inherit)
+absl_random_internal_pool_urbg(minSdkVersion:apex_inherit)
+absl_random_internal_randen(minSdkVersion:apex_inherit)
+absl_random_internal_randen_engine(minSdkVersion:apex_inherit)
+absl_random_internal_randen_hwaes(minSdkVersion:apex_inherit)
+absl_random_internal_randen_hwaes_impl(minSdkVersion:apex_inherit)
+absl_random_internal_randen_slow(minSdkVersion:apex_inherit)
+absl_random_internal_salted_seed_seq(minSdkVersion:apex_inherit)
+absl_random_internal_seed_material(minSdkVersion:apex_inherit)
+absl_random_internal_traits(minSdkVersion:apex_inherit)
+absl_random_internal_uniform_helper(minSdkVersion:apex_inherit)
+absl_random_internal_wide_multiply(minSdkVersion:apex_inherit)
+absl_random_seed_gen_exception(minSdkVersion:apex_inherit)
+absl_random_seed_sequences(minSdkVersion:apex_inherit)
+absl_status(minSdkVersion:apex_inherit)
+absl_status_statusor(minSdkVersion:apex_inherit)
+absl_strings(minSdkVersion:apex_inherit)
+absl_strings_charset(minSdkVersion:apex_inherit)
+absl_strings_cord(minSdkVersion:apex_inherit)
+absl_strings_cord_internal(minSdkVersion:apex_inherit)
+absl_strings_cordz_functions(minSdkVersion:apex_inherit)
+absl_strings_cordz_handle(minSdkVersion:apex_inherit)
+absl_strings_cordz_info(minSdkVersion:apex_inherit)
+absl_strings_cordz_statistics(minSdkVersion:apex_inherit)
+absl_strings_cordz_update_scope(minSdkVersion:apex_inherit)
+absl_strings_cordz_update_tracker(minSdkVersion:apex_inherit)
+absl_strings_has_ostream_operator(minSdkVersion:apex_inherit)
+absl_strings_internal(minSdkVersion:apex_inherit)
+absl_strings_str_format(minSdkVersion:apex_inherit)
+absl_strings_str_format_internal(minSdkVersion:apex_inherit)
+absl_strings_string_view(minSdkVersion:apex_inherit)
+absl_synchronization(minSdkVersion:apex_inherit)
+absl_synchronization_graphcycles_internal(minSdkVersion:apex_inherit)
+absl_synchronization_kernel_timeout_internal(minSdkVersion:apex_inherit)
+absl_time(minSdkVersion:apex_inherit)
+absl_time_internal_cctz_civil_time(minSdkVersion:apex_inherit)
+absl_time_internal_cctz_time_zone(minSdkVersion:apex_inherit)
+absl_types_bad_optional_access(minSdkVersion:apex_inherit)
+absl_types_bad_variant_access(minSdkVersion:apex_inherit)
+absl_types_compare(minSdkVersion:apex_inherit)
+absl_types_optional(minSdkVersion:apex_inherit)
+absl_types_span(minSdkVersion:apex_inherit)
+absl_types_variant(minSdkVersion:apex_inherit)
+absl_utility(minSdkVersion:apex_inherit)
 aconfig_mediacodec_flags_c_lib(minSdkVersion:30)
 aconfig_settingslib_exported_flags_java_lib(minSdkVersion:30)
 aconfig_settingstheme_exported_flags_java_lib(minSdkVersion:21)
@@ -22,6 +190,7 @@ aconfigd-mainline(minSdkVersion:34)
 aconfigd_java_proto_lib(minSdkVersion:34)
 aconfigd_java_proto_lib_repackaged(minSdkVersion:34)
 aconfigd_java_proto_lite_lib(minSdkVersion:34)
+adbd_flags_c_lib(minSdkVersion:apex_inherit)
 android.app.appfunctions.exported-flags-aconfig-java(minSdkVersion:30)
 android.app.flags-aconfig-java(minSdkVersion:34)
 android.app.ondeviceintelligence-aconfig-java(minSdkVersion:35)
@@ -68,6 +237,7 @@ android.hardware.graphics.common-V3-ndk(minSdkVersion:29)
 android.hardware.graphics.common-V4-ndk(minSdkVersion:29)
 android.hardware.graphics.common-V5-ndk(minSdkVersion:29)
 android.hardware.graphics.common-V6-ndk(minSdkVersion:29)
+android.hardware.graphics.common-V7-ndk(minSdkVersion:29)
 android.hardware.graphics.common@1.0(minSdkVersion:29)
 android.hardware.graphics.common@1.1(minSdkVersion:29)
 android.hardware.graphics.common@1.2(minSdkVersion:29)
@@ -159,6 +329,7 @@ android.media.extractor.flags-aconfig-cc(minSdkVersion:29)
 android.media.swcodec.flags-aconfig-cc(minSdkVersion:apex_inherit)
 android.net.ipsec.ike(minSdkVersion:30)
 android.net.ipsec.ike.xml(minSdkVersion:(no version))
+android.net.platform.flags-aconfig-java-export(minSdkVersion:30)
 android.net.vcn.flags-aconfig-java(minSdkVersion:35)
 android.net.wifi.flags-aconfig-java(minSdkVersion:30)
 android.nfc.flags-aconfig-java(minSdkVersion:34)
@@ -192,9 +363,11 @@ apache-commons-lang(minSdkVersion:33)
 apache-velocity-engine-core(minSdkVersion:33)
 apache-xml(minSdkVersion:31)
 app-compat-annotations(minSdkVersion:current)
+appfunctions-schema(minSdkVersion:30)
 appsearch_flags_java_lib(minSdkVersion:33)
 art-aconfig-flags-java-lib(minSdkVersion:31)
 art-aconfig-flags-lib(minSdkVersion:31)
+art-aconfig-native-flags-lib(minSdkVersion:31)
 art_flags_uprobestats_c_lib(minSdkVersion:35)
 audioclient-types-aidl-cpp(minSdkVersion:29)
 audioflinger-aidl-cpp(minSdkVersion:29)
@@ -203,7 +376,7 @@ auto_service_annotations(minSdkVersion:current)
 auto_value_annotations(minSdkVersion:19)
 av-headers(minSdkVersion:29)
 av-types-aidl-cpp(minSdkVersion:29)
-avrcp_headers(minSdkVersion:30)
+avrcp_headers(minSdkVersion:36)
 bcm_object(minSdkVersion:29)
 bionic_libc_platform_headers(minSdkVersion:29)
 bluetooth-protos-nfc-enums-java-gen(minSdkVersion:35)
@@ -235,6 +408,7 @@ cellbroadcastreceiver_flags_lib(minSdkVersion:30)
 census(minSdkVersion:30)
 clatd(minSdkVersion:30)
 codecs_g711dec(minSdkVersion:29)
+com.android.crashrecovery.flags-aconfig-java(minSdkVersion:36)
 com.android.media.audio-aconfig-cc(minSdkVersion:29)
 com.android.media.audioserver-aconfig-cc(minSdkVersion:29)
 com.android.nfc.flags-aconfig-java(minSdkVersion:35)
@@ -243,6 +417,7 @@ com.android.nfc.module.flags-aconfig-cpp(minSdkVersion:35)
 com.android.nfc.module.flags-aconfig-cpp(minSdkVersion:36)
 com.android.permission.flags-aconfig-java-export(minSdkVersion:30)
 com.android.vcard(minSdkVersion:9)
+com.android.window.flags.window-aconfig-java-export(minSdkVersion:30)
 com.google.android.material_material(minSdkVersion:21)
 com.uwb.support.aliro(minSdkVersion:30)
 com.uwb.support.base(minSdkVersion:30)
@@ -260,15 +435,15 @@ connectivity_native_aidl_interface-V1-java(minSdkVersion:30)
 conscrypt(minSdkVersion:29)
 core-libart(minSdkVersion:31)
 core-oj(minSdkVersion:31)
-crt_pad_segment(minSdkVersion:16)
+crt_pad_segment(minSdkVersion:21)
 crt_pad_segment(minSdkVersion:30)
 crt_pad_segment(minSdkVersion:35)
 crt_pad_segment(minSdkVersion:current)
 crt_pad_segment(minSdkVersion:VanillaIceCream)
-crtbegin_dynamic(minSdkVersion:16)
+crtbegin_dynamic(minSdkVersion:21)
 crtbegin_dynamic(minSdkVersion:apex_inherit)
 crtbegin_dynamic1(minSdkVersion:apex_inherit)
-crtbegin_so(minSdkVersion:16)
+crtbegin_so(minSdkVersion:21)
 crtbegin_so(minSdkVersion:29)
 crtbegin_so(minSdkVersion:30)
 crtbegin_so(minSdkVersion:35)
@@ -276,16 +451,16 @@ crtbegin_so(minSdkVersion:apex_inherit)
 crtbegin_so(minSdkVersion:current)
 crtbegin_so(minSdkVersion:VanillaIceCream)
 crtbegin_so1(minSdkVersion:apex_inherit)
-crtbrand(minSdkVersion:16)
+crtbrand(minSdkVersion:21)
 crtbrand(minSdkVersion:29)
 crtbrand(minSdkVersion:30)
 crtbrand(minSdkVersion:35)
 crtbrand(minSdkVersion:apex_inherit)
 crtbrand(minSdkVersion:current)
 crtbrand(minSdkVersion:VanillaIceCream)
-crtend_android(minSdkVersion:16)
+crtend_android(minSdkVersion:21)
 crtend_android(minSdkVersion:apex_inherit)
-crtend_so(minSdkVersion:16)
+crtend_so(minSdkVersion:21)
 crtend_so(minSdkVersion:29)
 crtend_so(minSdkVersion:30)
 crtend_so(minSdkVersion:35)
@@ -385,7 +560,7 @@ icing-java-proto-lite(minSdkVersion:current)
 iconloader(minSdkVersion:21)
 iconloader(minSdkVersion:26)
 iconloader_sc_mainline_prod(minSdkVersion:26)
-internal_include_headers(minSdkVersion:30)
+internal_include_headers(minSdkVersion:36)
 ipmemorystore-aidl-interfaces-java(minSdkVersion:29)
 ipmemorystore-aidl-interfaces-V10-java(minSdkVersion:29)
 ipmemorystore-aidl-interfaces-V10-java(minSdkVersion:30)
@@ -500,8 +675,8 @@ libbinder_tokio_rs(minSdkVersion:Tiramisu)
 libbinderthreadstateutils(minSdkVersion:29)
 libbitflags(minSdkVersion:29)
 libbitflags-1.3.2(minSdkVersion:29)
-libbluetooth-types(minSdkVersion:29)
-libbluetooth-types-header(minSdkVersion:29)
+libbluetooth-types(minSdkVersion:36)
+libbluetooth-types-header(minSdkVersion:36)
 libbluetooth_headers(minSdkVersion:30)
 libbpf(minSdkVersion:apex_inherit)
 libbrotli(minSdkVersion:(no version))
@@ -513,7 +688,7 @@ libbssl_sys_raw_staticfns(minSdkVersion:29)
 libbt-platform-protos-lite(minSdkVersion:30)
 libbt_keystore_cc(minSdkVersion:30)
 libbt_keystore_cc_headers(minSdkVersion:30)
-libbtcore_headers(minSdkVersion:30)
+libbtcore_headers(minSdkVersion:36)
 libbuildversion(minSdkVersion:(no version))
 libbuildversion(minSdkVersion:26)
 libbytemuck(minSdkVersion:29)
@@ -567,6 +742,7 @@ libcodec2_soft_h263dec(minSdkVersion:29)
 libcodec2_soft_h263enc(minSdkVersion:29)
 libcodec2_soft_hevcdec(minSdkVersion:29)
 libcodec2_soft_hevcenc(minSdkVersion:29)
+libcodec2_soft_iamfdec(minSdkVersion:31)
 libcodec2_soft_mp3dec(minSdkVersion:29)
 libcodec2_soft_mpeg2dec(minSdkVersion:29)
 libcodec2_soft_mpeg4dec(minSdkVersion:29)
@@ -584,6 +760,7 @@ libcom_android_networkstack_tethering_util_jni(minSdkVersion:30)
 libcombine(minSdkVersion:29)
 libcompiler_builtins.rust_sysroot(minSdkVersion:29)
 libconfiginfra_framework_flags_rust(minSdkVersion:34)
+libcore-aconfig-flags-native-lib(minSdkVersion:31)
 libcore.rust_sysroot(minSdkVersion:29)
 libcrypto(minSdkVersion:29)
 libcrypto_static(minSdkVersion:(no version))
@@ -612,6 +789,8 @@ libdoh_ffi(minSdkVersion:29)
 libdoh_ffi(minSdkVersion:30)
 libdoubleconversion(minSdkVersion:30)
 libdowncast_rs(minSdkVersion:29)
+libdynamic_instrumentation_manager(minSdkVersion:36)
+libdynamic_instrumentation_manager_bindgen(minSdkVersion:36)
 libeigen(minSdkVersion:(no version))
 libeigen(minSdkVersion:apex_inherit)
 libelf(minSdkVersion:apex_inherit)
@@ -661,6 +840,8 @@ libgav1(minSdkVersion:29)
 libgcc_stripped(minSdkVersion:(no version))
 libgetopts(minSdkVersion:29)
 libgetrandom(minSdkVersion:29)
+libgetrandom-0.2(minSdkVersion:29)
+libgetrandom-0.2.16(minSdkVersion:29)
 libgralloctypes(minSdkVersion:29)
 libgrallocusage(minSdkVersion:29)
 libgrpc(minSdkVersion:30)
@@ -827,6 +1008,7 @@ libnfcutils(minSdkVersion:36)
 libnix(minSdkVersion:29)
 libnl(minSdkVersion:apex_inherit)
 libnum_cpus(minSdkVersion:29)
+libnum_enum(minSdkVersion:29)
 libnum_traits(minSdkVersion:29)
 liboctets(minSdkVersion:29)
 liboggextractor(minSdkVersion:29)
@@ -906,9 +1088,13 @@ libprotoutil(minSdkVersion:30)
 libqemu_pipe(minSdkVersion:(no version))
 libquiche(minSdkVersion:29)
 librand(minSdkVersion:29)
+librand-0.8(minSdkVersion:29)
 librand_chacha(minSdkVersion:29)
+librand_chacha-0.3(minSdkVersion:29)
 librand_core(minSdkVersion:29)
+librand_core-0.6(minSdkVersion:29)
 libregex(minSdkVersion:29)
+libregex_automata(minSdkVersion:29)
 libregex_syntax(minSdkVersion:29)
 libremove_dir_all(minSdkVersion:29)
 libring(minSdkVersion:29)
@@ -923,8 +1109,10 @@ librustc_demangle_static(minSdkVersion:S)
 librustix(minSdkVersion:30)
 librustutils(minSdkVersion:29)
 libruy_static(minSdkVersion:30)
+libryu(minSdkVersion:29)
 libscopeguard(minSdkVersion:29)
 libserde(minSdkVersion:29)
+libserde_json(minSdkVersion:29)
 libserviceconnectivityjni(minSdkVersion:30)
 libsfplugin_ccodec_utils(minSdkVersion:29)
 libslab(minSdkVersion:29)
@@ -944,7 +1132,6 @@ libstagefright_amrwbdec(minSdkVersion:29)
 libstagefright_amrwbenc(minSdkVersion:29)
 libstagefright_bufferpool@2.0.1(minSdkVersion:29)
 libstagefright_bufferqueue_helper(minSdkVersion:29)
-libstagefright_bufferqueue_helper_novndk(minSdkVersion:29)
 libstagefright_enc_common(minSdkVersion:29)
 libstagefright_esds(minSdkVersion:29)
 libstagefright_flacdec(minSdkVersion:29)
@@ -966,9 +1153,12 @@ libstatslog_express(minSdkVersion:33)
 libstatslog_nfc(minSdkVersion:35)
 libstatslog_nfc(minSdkVersion:36)
 libstatslog_rust_header(minSdkVersion:29)
+libstatslog_uprobestats_rs(minSdkVersion:36)
 libstatspull_bindgen(minSdkVersion:apex_inherit)
 libstatspull_headers(minSdkVersion:30)
+libstatssocket_bindgen(minSdkVersion:36)
 libstatssocket_headers(minSdkVersion:29)
+libstatssocket_rs(minSdkVersion:36)
 libstd(minSdkVersion:29)
 libstd_detect.rust_sysroot(minSdkVersion:29)
 libstrsim(minSdkVersion:29)
@@ -1002,6 +1192,7 @@ libthiserror(minSdkVersion:29)
 libtinyvec(minSdkVersion:29)
 libtinyvec_macros(minSdkVersion:29)
 libtinyxml2(minSdkVersion:31)
+libtinyxml2(minSdkVersion:apex_inherit)
 libtinyxml2(minSdkVersion:S)
 libtokio(minSdkVersion:29)
 libtokio_io_timeout(minSdkVersion:29)
@@ -1028,6 +1219,14 @@ libunwind.rust_sysroot(minSdkVersion:29)
 libunwind_llvm(minSdkVersion:apex_inherit)
 libunwindstack(minSdkVersion:29)
 libuprobestats(minSdkVersion:35)
+libuprobestats_bpf(minSdkVersion:36)
+libuprobestats_bpf_bindgen(minSdkVersion:36)
+libuprobestats_bpf_cc(minSdkVersion:36)
+libuprobestats_mainline_flags_rust(minSdkVersion:36)
+libuprobestats_proto(minSdkVersion:36)
+libuprobestats_rs(minSdkVersion:36)
+liburing(minSdkVersion:apex_inherit)
+liburingutils(minSdkVersion:30)
 liburl(minSdkVersion:29)
 libutf(minSdkVersion:(no version))
 libutf(minSdkVersion:14)
@@ -1101,6 +1300,7 @@ modules-utils-locallog(minSdkVersion:30)
 modules-utils-os(minSdkVersion:30)
 modules-utils-package-state(minSdkVersion:31)
 modules-utils-preconditions(minSdkVersion:29)
+modules-utils-ravenwood(minSdkVersion:29)
 modules-utils-shell-command-handler(minSdkVersion:29)
 modules-utils-statemachine(minSdkVersion:29)
 modules-utils-synchronous-result-receiver(minSdkVersion:29)
@@ -1238,8 +1438,8 @@ nfc-event-log-proto(minSdkVersion:35)
 nfc-event-log-proto(minSdkVersion:36)
 NfcNciApex(minSdkVersion:35)
 NfcNciApexGoogle(minSdkVersion:35)
-note_memtag_heap_async(minSdkVersion:16)
-note_memtag_heap_sync(minSdkVersion:16)
+note_memtag_heap_async(minSdkVersion:21)
+note_memtag_heap_sync(minSdkVersion:21)
 offlinelocationtimezoneprovider(minSdkVersion:31)
 okhttp(minSdkVersion:31)
 okhttp-norepackage(minSdkVersion:30)
@@ -1372,7 +1572,6 @@ service-ondeviceintelligence(minSdkVersion:35)
 service-ondeviceintelligence.impl(minSdkVersion:35)
 ServiceWifiResourcesGoogle(minSdkVersion:30)
 settingslib_illustrationpreference_flags_lib(minSdkVersion:30)
-settingslib_selectorwithwidgetpreference_flags_lib(minSdkVersion:30)
 SettingsLibActionBarShadow(minSdkVersion:21)
 SettingsLibActionBarShadow(minSdkVersion:28)
 SettingsLibActivityEmbedding(minSdkVersion:21)
@@ -1380,14 +1579,18 @@ SettingsLibAppPreference(minSdkVersion:21)
 SettingsLibBannerMessagePreference(minSdkVersion:28)
 SettingsLibBarChartPreference(minSdkVersion:21)
 SettingsLibButtonPreference(minSdkVersion:21)
+SettingsLibCategory(minSdkVersion:21)
 SettingsLibCollapsingToolbarBaseActivity(minSdkVersion:29)
 SettingsLibColor(minSdkVersion:28)
+SettingsLibDataStore(minSdkVersion:21)
 SettingsLibFooterPreference(minSdkVersion:21)
 SettingsLibHelpUtils(minSdkVersion:21)
 SettingsLibIllustrationPreference(minSdkVersion:28)
 SettingsLibIntroPreference(minSdkVersion:21)
 SettingsLibLayoutPreference(minSdkVersion:21)
 SettingsLibMainSwitchPreference(minSdkVersion:28)
+SettingsLibMetadata(minSdkVersion:21)
+SettingsLibPreference(minSdkVersion:21)
 SettingsLibProfileSelector(minSdkVersion:23)
 SettingsLibProgressBar(minSdkVersion:21)
 SettingsLibRadioButtonPreference(minSdkVersion:21)
@@ -1395,11 +1598,13 @@ SettingsLibRestrictedLockUtils(minSdkVersion:21)
 SettingsLibSearchWidget(minSdkVersion:21)
 SettingsLibSelectorWithWidgetPreference(minSdkVersion:21)
 SettingsLibSettingsSpinner(minSdkVersion:21)
+SettingsLibSettingsSpinner(minSdkVersion:23)
 SettingsLibSettingsTheme(minSdkVersion:21)
 SettingsLibSettingsTransition(minSdkVersion:29)
 SettingsLibTopIntroPreference(minSdkVersion:21)
 SettingsLibTwoTargetPreference(minSdkVersion:21)
 SettingsLibUtils(minSdkVersion:21)
+SettingsLibValuePreference(minSdkVersion:23)
 SettingsLibZeroStatePreference(minSdkVersion:28)
 setupcompat(minSdkVersion:21)
 setupdesign(minSdkVersion:21)
@@ -1438,6 +1643,7 @@ uprobestats_flags_c_lib(minSdkVersion:35)
 uprobestats_flags_c_lib(minSdkVersion:36)
 uprobestats_mainline_flags_c_lib(minSdkVersion:35)
 uprobestats_mainline_flags_c_lib(minSdkVersion:36)
+uprobestats_rs(minSdkVersion:36)
 uwb_androidx_backend(minSdkVersion:30)
 volumegroupcallback-aidl-cpp(minSdkVersion:29)
 wear-permission-components(minSdkVersion:30)
diff --git a/build/mainline_modules_sdks.py b/build/mainline_modules_sdks.py
index 060b580..8ddc7ca 100755
--- a/build/mainline_modules_sdks.py
+++ b/build/mainline_modules_sdks.py
@@ -21,6 +21,7 @@ the APEXes in it are built, otherwise all configured SDKs are built.
 import argparse
 import dataclasses
 import datetime
+import difflib
 import enum
 import functools
 import io
@@ -286,6 +287,11 @@ class SubprocessRunner:
             *args, check=True, stdout=self.stdout, stderr=self.stderr, **kwargs)
 
 
+def unified_diff(a, b, label_a, label_b):
+    diff = difflib.unified_diff(a.splitlines(keepends=True), b.splitlines(keepends=True), fromfile=label_a, tofile=label_b)
+    return ''.join(diff)
+
+
 def sdk_snapshot_zip_file(snapshots_dir, sdk_name):
     """Get the path to the sdk snapshot zip file."""
     return os.path.join(snapshots_dir, f"{sdk_name}-{SDK_VERSION}.zip")
@@ -594,16 +600,11 @@ java_sdk_library_import {{
         with zipfile.ZipFile(sdk_zip_file, "r") as zipObj:
             extracted_current_api = zipObj.extract(
                 member=current_api, path=snapshots_dir)
-            # The diff tool has an exit code of 0, 1 or 2 depending on whether
-            # it find no differences, some differences or an error (like missing
-            # file). As 0 or 1 are both valid results this cannot use check=True
-            # so disable the pylint check.
-            # pylint: disable=subprocess-run-check
-            diff = subprocess.run([
-                "diff", "-u0", latest_api, extracted_current_api, "--label",
-                latest_api, "--label", extracted_current_api
-            ],
-                                  capture_output=True).stdout.decode("utf-8")
+            with open(latest_api) as f:
+                a = f.read()
+            with open(extracted_current_api) as f:
+                b = f.read()
+            diff = unified_diff(a, b, latest_api, extracted_current_api)
             file_object.write(diff)
 
     def create_snapshot_gantry_metadata_and_api_diff(self, sdk, target_dict,
diff --git a/build/mainline_modules_sdks_test.py b/build/mainline_modules_sdks_test.py
index 5492f80..73ba374 100644
--- a/build/mainline_modules_sdks_test.py
+++ b/build/mainline_modules_sdks_test.py
@@ -348,7 +348,7 @@ class TestProduceDist(unittest.TestCase):
             msg="Incorrect api-diff file name.")
         self.assertEqual(
             json_data["api_diff_file_size"],
-            267,
+            238,
             msg="Incorrect api-diff file size.")
         self.assertEqual(
             json_data["module_extension_version"],
@@ -787,6 +787,42 @@ class TestModuleProperties(unittest.TestCase):
                 self.assertTrue(module.is_bundled())
                 self.assertEqual(module.first_release, mm.LATEST)
 
+class TestGlobalFunctions(unittest.TestCase):
+    def test_unified_diff(self):
+        self.assertEqual(mm.unified_diff("foo", "foo", "left", "right"), "")
+        self.assertEqual(mm.unified_diff("""\
+0
+1
+2
+3
+4
+5
+6
+7
+8
+""", """\
+0
+1
+2
+3
+four
+5
+6
+7
+8
+""", "left", "right"), """\
+--- left
++++ right
+@@ -2,7 +2,7 @@
+ 1
+ 2
+ 3
+-4
++four
+ 5
+ 6
+ 7
+""")
 
 if __name__ == "__main__":
     unittest.main(verbosity=2)
diff --git a/proguard/Android.bp b/proguard/Android.bp
index f5a5ce0..e773322 100644
--- a/proguard/Android.bp
+++ b/proguard/Android.bp
@@ -14,17 +14,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
-    default_visibility: [
-        ":__subpackages__",
-        "//art/libartservice:__subpackages__",
-        "//frameworks/base:__subpackages__",
-        "//frameworks/opt:__subpackages__",
-        "//libcore:__subpackages__",
-        "//packages/modules:__subpackages__",
-        "//packages/providers/MediaProvider:__subpackages__",
-        "//system/apex/apexd:__subpackages__",
-
-    ],
+    default_visibility: ["//visibility:public"],
 }
 
 // Needed because otherwise java_defaults would resolve it in module directory.
@@ -57,6 +47,9 @@ filegroup {
     ],
 }
 
+// Defaults for jars on PRODUCT_APEX_STANDALONE_SYSTEM_SERVER_JARS. These jars
+// have a single entry point in SystemServer.java, and can be easily shrunk
+// based on a single keep rule.
 java_defaults {
     name: "standalone-system-server-module-optimize-defaults",
     optimize: {
diff --git a/sdk/Android.bp b/sdk/Android.bp
index c364beb..82a290a 100644
--- a/sdk/Android.bp
+++ b/sdk/Android.bp
@@ -63,6 +63,10 @@ java_defaults {
         // bundle an additional set of Proguard rules that should always
         // be used downstream for selectively optimized targets.
         proguard_flags_files: [":framework-sdk-proguard-rules"],
+
+        // Disallow access modification during optimization that would promote
+        // members into the public or protected API surface.
+        protect_api_surface: true,
     },
 
     // Configure framework module specific metalava options.
@@ -138,18 +142,7 @@ java_defaults {
         sdk_version: "module_current",
     },
 
-    defaults_visibility: [
-        ":__subpackages__",
-        // TODO(b/237461653): Move this to packages/modules/Nfc
-        "//frameworks/base/nfc",
-        "//frameworks/base/apex:__subpackages__",
-        "//frameworks/base/libs/hwui",
-        "//frameworks/base/packages/Vcn:__subpackages__",
-        "//frameworks/base/wifi",
-        "//packages/modules:__subpackages__",
-        "//packages/providers/MediaProvider:__subpackages__",
-        "//system/apex/apexd:__subpackages__",
-    ],
+    defaults_visibility: ["//visibility:public"],
 }
 
 // Defaults for mainline module system server provided java_sdk_library instances.
@@ -163,14 +156,7 @@ java_defaults {
         sdk_version: "system_server_current",
     },
 
-    defaults_visibility: [
-        ":__subpackages__",
-        "//art/libartservice:__subpackages__",
-        "//frameworks/base/apex:__subpackages__",
-        "//frameworks/base/packages/Vcn:__subpackages__",
-        "//packages/modules:__subpackages__",
-        "//system/apex/apexd:__subpackages__",
-    ],
+    defaults_visibility: ["//visibility:public"],
 }
 
 filegroup_defaults {
diff --git a/tools/finalize_sdk.py b/tools/finalize_sdk.py
index e9707da..3197f5d 100755
--- a/tools/finalize_sdk.py
+++ b/tools/finalize_sdk.py
@@ -136,16 +136,20 @@ parser.add_argument('-g', '--gantry_download_dir', type=str, help=argparse.SUPPR
 parser.add_argument('-l', '--local_mode', action="store_true", help='Local mode: use locally built artifacts and don\'t upload the result to Gerrit.')
 parser.add_argument('-m', '--modules', action='append', help='Modules to include. Can be provided multiple times, or not at all for all modules.')
 parser.add_argument('-r', '--readme', required=True, help='Version history entry to add to %s' % (COMPAT_REPO / COMPAT_README))
+parser.add_argument('-t', '--topic_branch', type=str, help='Name of the topic branch "repo start" will create.')
+parser.add_argument('--build_target', type=str, help=f'Which build target to download targets from (e.g. "{BUILD_TARGET_CONTINUOUS}"); used together with the <bid> argument. If not provided, will calculate a default value based on the <release_config> argument.')
 parser.add_argument('bid', help='Build server build ID')
 args = parser.parse_args()
 
 if not os.path.isdir('build/soong') and not args.gantry_download_dir:
     fail("This script must be run from the top of an Android source tree.")
 
-if args.release_config:
+if args.build_target:
+    BUILD_TARGET_CONTINUOUS = args.build_target
+elif args.release_config:
     BUILD_TARGET_CONTINUOUS = BUILD_TARGET_CONTINUOUS_MAIN.format(release_config=args.release_config)
 build_target = BUILD_TARGET_TRAIN if args.bid[0] == 'T' else BUILD_TARGET_CONTINUOUS
-branch_name = 'finalize-%d' % args.finalize_sdk
+topic_branch = 'finalize-%d' % args.finalize_sdk if args.topic_branch is None else args.topic_branch
 cmdline = shlex.join([x for x in sys.argv if x not in ['-a', '--amend_last_commit', '-l', '--local_mode']])
 commit_message = COMMIT_TEMPLATE % (args.finalize_sdk, args.bid, cmdline, args.bug)
 module_names = args.modules or ['*']
@@ -210,7 +214,7 @@ if args.gantry_download_dir:
 if args.dry_run:
     sys.exit(0)
 
-subprocess.check_output(['repo', 'start', branch_name] + list(created_dirs.keys()))
+subprocess.check_output(['repo', 'start', topic_branch] + list(created_dirs.keys()))
 print('Running git commit')
 for repo in created_dirs:
     git = ['git', '-C', str(repo)]
```

