```diff
diff --git a/Android.bp b/Android.bp
index 2cdee681..28403b35 100644
--- a/Android.bp
+++ b/Android.bp
@@ -16,157 +16,3 @@ package {
     default_visibility: ["//packages/modules/common:__subpackages__"],
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
-
-soong_config_bool_variable {
-    name: "module_build_from_source",
-}
-
-soong_config_module_type {
-    name: "module_apex_set",
-    module_type: "apex_set",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_android_app_import",
-    module_type: "android_app_import",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_android_app_set",
-    module_type: "android_app_set",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_prebuilt_bootclasspath_fragment",
-    module_type: "prebuilt_bootclasspath_fragment",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_prebuilt_systemserverclasspath_fragment",
-    module_type: "prebuilt_systemserverclasspath_fragment",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_java_import",
-    module_type: "java_import",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_java_test_import",
-    module_type: "java_test_import",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_java_sdk_library_import",
-    module_type: "java_sdk_library_import",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_cc_prebuilt_binary",
-    module_type: "cc_prebuilt_binary",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_cc_prebuilt_library_shared",
-    module_type: "cc_prebuilt_library_shared",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_cc_prebuilt_library_headers",
-    module_type: "cc_prebuilt_library_headers",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "prefer",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_java_library",
-    module_type: "java_library",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "enabled",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_apex",
-    module_type: "apex",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "enabled",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_apex_test",
-    module_type: "apex_test",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "enabled",
-    ],
-}
-
-soong_config_module_type {
-    name: "module_override_apex",
-    module_type: "override_apex",
-    config_namespace: "ANDROID",
-    bool_variables: ["module_build_from_source"],
-    properties: [
-        "enabled",
-    ],
-}
diff --git a/OWNERS b/OWNERS
index 9979011d..ad796402 100644
--- a/OWNERS
+++ b/OWNERS
@@ -5,7 +5,6 @@ amhk@google.com
 ancr@google.com
 dariofreni@google.com
 gurpreetgs@google.com
-hansson@google.com
 harshitmahajan@google.com
 kalyssa@google.com
 marcots@google.com
diff --git a/PREBUILTS_MODULE_OWNERS b/PREBUILTS_MODULE_OWNERS
index 064f1599..5984e4c0 100644
--- a/PREBUILTS_MODULE_OWNERS
+++ b/PREBUILTS_MODULE_OWNERS
@@ -12,11 +12,8 @@
 include platform/packages/modules/common:/MODULES_OWNERS
 marielos@google.com #{LAST_RESORT_SUGGESTION}
 pranavgupta@google.com #{LAST_RESORT_SUGGESTION}
-mattcarp@google.com #{LAST_RESORT_SUGGESTION}
 ahomer@google.com #{LAST_RESORT_SUGGESTION}
 robertogil@google.com #{LAST_RESORT_SUGGESTION}
-paulduffin@google.com #{LAST_RESORT_SUGGESTION}
-amhk@google.com #{LAST_RESORT_SUGGESTION}
 gurpreetgs@google.com #{LAST_RESORT_SUGGESTION}
-hsnali@google.com #{LAST_RESORT_SUGGESTION}
-kalyssa@google.com #{LAST_RESORT_SUGGESTION}
\ No newline at end of file
+kalyssa@google.com #{LAST_RESORT_SUGGESTION}
+psych@google.com #{LAST_RESORT_SUGGESTION}
\ No newline at end of file
diff --git a/build/Android.bp b/build/Android.bp
index 773d91cf..765b4c71 100644
--- a/build/Android.bp
+++ b/build/Android.bp
@@ -38,7 +38,6 @@ python_test_host {
 phony {
     name: "aosp_mainline_modules",
     required: [
-        "com.android.art",
         "com.android.adbd",
         "com.android.adservices",
         "com.android.appsearch",
@@ -66,7 +65,13 @@ phony {
         "com.android.uwb",
         "com.android.virt",
         "com.android.wifi",
-    ],
+    ] + select(product_variable("use_debug_art"), {
+        true: [
+            "com.android.art.debug",
+        ],
+        default: [
+            "com.android.art",
+        ],
+    }),
     visibility: ["//visibility:any_system_partition"],
 }
-
diff --git a/build/allowed_deps.txt b/build/allowed_deps.txt
index 03be9e76..88fed221 100644
--- a/build/allowed_deps.txt
+++ b/build/allowed_deps.txt
@@ -14,10 +14,13 @@
 # TODO(b/157465465): introduce automated quality signals and remove this list.
 
 aconfig_mediacodec_flags_c_lib(minSdkVersion:30)
+android.app.appfunctions.exported-flags-aconfig-java(minSdkVersion:30)
+android.companion.virtualdevice.flags-aconfig-java-export(minSdkVersion:30)
 android.content.pm.flags-aconfig-java-export(minSdkVersion:30)
 android.hardware.audio.common-V1-ndk(minSdkVersion:31)
 android.hardware.audio.common-V2-ndk(minSdkVersion:31)
 android.hardware.audio.common-V3-ndk(minSdkVersion:31)
+android.hardware.audio.common-V4-ndk(minSdkVersion:31)
 android.hardware.audio.common@5.0(minSdkVersion:30)
 android.hardware.bluetooth-V1-ndk(minSdkVersion:33)
 android.hardware.bluetooth.a2dp@1.0(minSdkVersion:30)
@@ -25,6 +28,7 @@ android.hardware.bluetooth.audio-V1-ndk(minSdkVersion:31)
 android.hardware.bluetooth.audio-V2-ndk(minSdkVersion:31)
 android.hardware.bluetooth.audio-V3-ndk(minSdkVersion:31)
 android.hardware.bluetooth.audio-V4-ndk(minSdkVersion:31)
+android.hardware.bluetooth.audio-V5-ndk(minSdkVersion:31)
 android.hardware.bluetooth.audio@2.0(minSdkVersion:30)
 android.hardware.bluetooth.audio@2.1(minSdkVersion:30)
 android.hardware.bluetooth.ranging-V1-ndk(minSdkVersion:33)
@@ -93,6 +97,7 @@ android.hardware.wifi-V1.4-java(minSdkVersion:30)
 android.hardware.wifi-V1.5-java(minSdkVersion:30)
 android.hardware.wifi-V1.6-java(minSdkVersion:30)
 android.hardware.wifi-V2-java(minSdkVersion:30)
+android.hardware.wifi-V3-java(minSdkVersion:30)
 android.hardware.wifi.common-V1-java(minSdkVersion:30)
 android.hardware.wifi.hostapd-V1-java(minSdkVersion:30)
 android.hardware.wifi.hostapd-V1.0-java(minSdkVersion:30)
@@ -100,6 +105,7 @@ android.hardware.wifi.hostapd-V1.1-java(minSdkVersion:30)
 android.hardware.wifi.hostapd-V1.2-java(minSdkVersion:30)
 android.hardware.wifi.hostapd-V1.3-java(minSdkVersion:30)
 android.hardware.wifi.hostapd-V2-java(minSdkVersion:30)
+android.hardware.wifi.hostapd-V3-java(minSdkVersion:30)
 android.hardware.wifi.supplicant-V1-java(minSdkVersion:30)
 android.hardware.wifi.supplicant-V1.0-java(minSdkVersion:30)
 android.hardware.wifi.supplicant-V1.1-java(minSdkVersion:30)
@@ -108,6 +114,7 @@ android.hardware.wifi.supplicant-V1.3-java(minSdkVersion:30)
 android.hardware.wifi.supplicant-V1.4-java(minSdkVersion:30)
 android.hardware.wifi.supplicant-V2-java(minSdkVersion:30)
 android.hardware.wifi.supplicant-V3-java(minSdkVersion:30)
+android.hardware.wifi.supplicant-V4-java(minSdkVersion:30)
 android.hidl.allocator@1.0(minSdkVersion:29)
 android.hidl.base-V1.0-java(minSdkVersion:current)
 android.hidl.manager-V1.0-java(minSdkVersion:30)
@@ -124,6 +131,8 @@ android.media.audio.common.types-V2-cpp(minSdkVersion:29)
 android.media.audio.common.types-V2-ndk(minSdkVersion:29)
 android.media.audio.common.types-V3-cpp(minSdkVersion:29)
 android.media.audio.common.types-V3-ndk(minSdkVersion:29)
+android.media.audio.common.types-V4-cpp(minSdkVersion:29)
+android.media.audio.common.types-V4-ndk(minSdkVersion:29)
 android.net.ipsec.ike(minSdkVersion:30)
 android.net.ipsec.ike.xml(minSdkVersion:(no version))
 android.net.wifi.flags-aconfig-java(minSdkVersion:30)
@@ -141,172 +150,19 @@ android_downloader_lib(minSdkVersion:30)
 androidx-constraintlayout_constraintlayout(minSdkVersion:21)
 androidx-constraintlayout_constraintlayout-core(minSdkVersion:24)
 androidx-constraintlayout_constraintlayout-solver(minSdkVersion:24)
-androidx.activity_activity(minSdkVersion:21)
-androidx.activity_activity-compose(minSdkVersion:21)
-androidx.activity_activity-ktx(minSdkVersion:21)
-androidx.annotation_annotation(minSdkVersion:24)
-androidx.annotation_annotation-experimental(minSdkVersion:21)
-androidx.annotation_annotation-jvm(minSdkVersion:24)
-androidx.appcompat_appcompat(minSdkVersion:19)
-androidx.appcompat_appcompat-resources(minSdkVersion:19)
-androidx.appsearch_appsearch(minSdkVersion:19)
-androidx.appsearch_appsearch-platform-storage(minSdkVersion:19)
-androidx.arch.core_core-common(minSdkVersion:24)
-androidx.arch.core_core-runtime(minSdkVersion:19)
-androidx.asynclayoutinflater_asynclayoutinflater(minSdkVersion:19)
-androidx.autofill_autofill(minSdkVersion:19)
-androidx.browser_browser(minSdkVersion:19)
-androidx.cardview_cardview(minSdkVersion:19)
-androidx.collection_collection(minSdkVersion:24)
-androidx.collection_collection-jvm(minSdkVersion:24)
-androidx.collection_collection-ktx(minSdkVersion:24)
-androidx.compose.animation_animation(minSdkVersion:21)
-androidx.compose.animation_animation-android(minSdkVersion:21)
-androidx.compose.animation_animation-core(minSdkVersion:21)
-androidx.compose.animation_animation-core-android(minSdkVersion:21)
-androidx.compose.foundation_foundation(minSdkVersion:21)
-androidx.compose.foundation_foundation-android(minSdkVersion:21)
-androidx.compose.foundation_foundation-layout(minSdkVersion:21)
-androidx.compose.foundation_foundation-layout-android(minSdkVersion:21)
-androidx.compose.material3_material3(minSdkVersion:21)
-androidx.compose.material3_material3-android(minSdkVersion:21)
-androidx.compose.material3_material3-window-size-class(minSdkVersion:21)
-androidx.compose.material_material-icons-core(minSdkVersion:21)
-androidx.compose.material_material-icons-core-android(minSdkVersion:21)
-androidx.compose.material_material-icons-extended(minSdkVersion:21)
-androidx.compose.material_material-ripple(minSdkVersion:21)
-androidx.compose.material_material-ripple-android(minSdkVersion:21)
-androidx.compose.runtime_runtime(minSdkVersion:21)
-androidx.compose.runtime_runtime-android(minSdkVersion:21)
-androidx.compose.runtime_runtime-livedata(minSdkVersion:21)
-androidx.compose.runtime_runtime-saveable(minSdkVersion:21)
-androidx.compose.runtime_runtime-saveable-android(minSdkVersion:21)
-androidx.compose.ui_ui(minSdkVersion:21)
-androidx.compose.ui_ui-android(minSdkVersion:21)
-androidx.compose.ui_ui-geometry(minSdkVersion:21)
-androidx.compose.ui_ui-geometry-android(minSdkVersion:21)
-androidx.compose.ui_ui-graphics(minSdkVersion:21)
-androidx.compose.ui_ui-graphics-android(minSdkVersion:21)
-androidx.compose.ui_ui-text(minSdkVersion:21)
-androidx.compose.ui_ui-text-android(minSdkVersion:21)
-androidx.compose.ui_ui-unit(minSdkVersion:21)
-androidx.compose.ui_ui-unit-android(minSdkVersion:21)
-androidx.compose.ui_ui-util(minSdkVersion:21)
-androidx.compose.ui_ui-util-android(minSdkVersion:21)
-androidx.concurrent_concurrent-futures(minSdkVersion:24)
-androidx.concurrent_concurrent-futures-ktx(minSdkVersion:24)
-androidx.constraintlayout_constraintlayout-core(minSdkVersion:24)
-androidx.coordinatorlayout_coordinatorlayout(minSdkVersion:21)
-androidx.core.uwb.backend.aidl_interface-V1-java(minSdkVersion:30)
-androidx.core.uwb.backend.aidl_interface-V2-java(minSdkVersion:30)
-androidx.core_core(minSdkVersion:19)
-androidx.core_core-ktx(minSdkVersion:19)
-androidx.cursoradapter_cursoradapter(minSdkVersion:19)
-androidx.customview_customview(minSdkVersion:19)
-androidx.customview_customview-poolingcontainer(minSdkVersion:19)
-androidx.documentfile_documentfile(minSdkVersion:19)
-androidx.drawerlayout_drawerlayout(minSdkVersion:19)
-androidx.dynamicanimation_dynamicanimation(minSdkVersion:19)
-androidx.emoji2_emoji2(minSdkVersion:19)
-androidx.emoji2_emoji2-views-helper(minSdkVersion:19)
-androidx.exifinterface_exifinterface(minSdkVersion:19)
-androidx.fragment_fragment(minSdkVersion:19)
-androidx.fragment_fragment-ktx(minSdkVersion:19)
-androidx.graphics_graphics-path(minSdkVersion:21)
-androidx.hilt_hilt-navigation(minSdkVersion:19)
-androidx.hilt_hilt-navigation-compose(minSdkVersion:21)
-androidx.interpolator_interpolator(minSdkVersion:19)
-androidx.javascriptengine_javascriptengine(minSdkVersion:26)
-androidx.leanback_leanback(minSdkVersion:19)
-androidx.leanback_leanback-grid(minSdkVersion:19)
-androidx.leanback_leanback-preference(minSdkVersion:21)
-androidx.legacy_legacy-preference-v14(minSdkVersion:19)
-androidx.legacy_legacy-preference-v14(minSdkVersion:21)
-androidx.legacy_legacy-support-core-ui(minSdkVersion:19)
-androidx.legacy_legacy-support-core-ui(minSdkVersion:21)
-androidx.legacy_legacy-support-core-utils(minSdkVersion:19)
-androidx.legacy_legacy-support-core-utils(minSdkVersion:21)
-androidx.legacy_legacy-support-v13(minSdkVersion:19)
-androidx.legacy_legacy-support-v13(minSdkVersion:21)
-androidx.legacy_legacy-support-v4(minSdkVersion:19)
-androidx.legacy_legacy-support-v4(minSdkVersion:21)
-androidx.lifecycle_lifecycle-common(minSdkVersion:24)
-androidx.lifecycle_lifecycle-common-java8(minSdkVersion:24)
-androidx.lifecycle_lifecycle-extensions(minSdkVersion:19)
-androidx.lifecycle_lifecycle-livedata(minSdkVersion:19)
-androidx.lifecycle_lifecycle-livedata-core(minSdkVersion:19)
-androidx.lifecycle_lifecycle-livedata-core-ktx(minSdkVersion:19)
-androidx.lifecycle_lifecycle-livedata-ktx(minSdkVersion:19)
-androidx.lifecycle_lifecycle-process(minSdkVersion:19)
-androidx.lifecycle_lifecycle-runtime(minSdkVersion:19)
-androidx.lifecycle_lifecycle-runtime-compose(minSdkVersion:21)
-androidx.lifecycle_lifecycle-runtime-ktx(minSdkVersion:19)
-androidx.lifecycle_lifecycle-service(minSdkVersion:19)
-androidx.lifecycle_lifecycle-viewmodel(minSdkVersion:19)
-androidx.lifecycle_lifecycle-viewmodel-compose(minSdkVersion:21)
-androidx.lifecycle_lifecycle-viewmodel-ktx(minSdkVersion:19)
-androidx.lifecycle_lifecycle-viewmodel-savedstate(minSdkVersion:19)
-androidx.loader_loader(minSdkVersion:19)
-androidx.localbroadcastmanager_localbroadcastmanager(minSdkVersion:19)
-androidx.localbroadcastmanager_localbroadcastmanager(minSdkVersion:21)
-androidx.media_media(minSdkVersion:19)
-androidx.navigation_navigation-common(minSdkVersion:21)
-androidx.navigation_navigation-common-ktx(minSdkVersion:21)
-androidx.navigation_navigation-compose(minSdkVersion:21)
-androidx.navigation_navigation-fragment(minSdkVersion:21)
-androidx.navigation_navigation-fragment-ktx(minSdkVersion:21)
-androidx.navigation_navigation-runtime(minSdkVersion:21)
-androidx.navigation_navigation-runtime-ktx(minSdkVersion:21)
-androidx.navigation_navigation-ui(minSdkVersion:21)
-androidx.navigation_navigation-ui-ktx(minSdkVersion:21)
-androidx.paging_paging-common(minSdkVersion:19)
-androidx.paging_paging-common(minSdkVersion:24)
-androidx.paging_paging-common-ktx(minSdkVersion:24)
-androidx.paging_paging-compose(minSdkVersion:21)
-androidx.paging_paging-runtime(minSdkVersion:19)
-androidx.preference_preference(minSdkVersion:19)
-androidx.print_print(minSdkVersion:19)
-androidx.profileinstaller_profileinstaller(minSdkVersion:19)
-androidx.recyclerview_recyclerview(minSdkVersion:19)
-androidx.recyclerview_recyclerview-selection(minSdkVersion:19)
-androidx.resourceinspection_resourceinspection-annotation(minSdkVersion:24)
-androidx.room_room-common(minSdkVersion:24)
-androidx.room_room-ktx(minSdkVersion:19)
-androidx.room_room-runtime(minSdkVersion:19)
-androidx.savedstate_savedstate(minSdkVersion:19)
-androidx.savedstate_savedstate-ktx(minSdkVersion:19)
-androidx.slidingpanelayout_slidingpanelayout(minSdkVersion:19)
-androidx.sqlite_sqlite(minSdkVersion:21)
-androidx.sqlite_sqlite-framework(minSdkVersion:21)
-androidx.startup_startup-runtime(minSdkVersion:19)
-androidx.swiperefreshlayout_swiperefreshlayout(minSdkVersion:19)
-androidx.tracing_tracing(minSdkVersion:19)
-androidx.tracing_tracing-ktx(minSdkVersion:19)
-androidx.transition_transition(minSdkVersion:19)
-androidx.vectordrawable_vectordrawable(minSdkVersion:19)
-androidx.vectordrawable_vectordrawable-animated(minSdkVersion:19)
-androidx.versionedparcelable_versionedparcelable(minSdkVersion:19)
-androidx.viewpager2_viewpager2(minSdkVersion:19)
-androidx.viewpager_viewpager(minSdkVersion:19)
-androidx.wear.compose_compose-foundation(minSdkVersion:25)
-androidx.wear.compose_compose-material(minSdkVersion:25)
-androidx.wear.compose_compose-material-core(minSdkVersion:25)
-androidx.wear.compose_compose-navigation(minSdkVersion:25)
-androidx.wear_wear(minSdkVersion:23)
-androidx.webkit_webkit(minSdkVersion:19)
-androidx.window.extensions.core_core(minSdkVersion:19)
-androidx.window.extensions.core_core(minSdkVersion:21)
-androidx.window_window(minSdkVersion:19)
-androidx.work_work-runtime(minSdkVersion:19)
 apache-commons-compress(minSdkVersion:29)
 apache-commons-compress(minSdkVersion:current)
 apache-commons-io(minSdkVersion:33)
 apache-commons-lang(minSdkVersion:33)
 apache-velocity-engine-core(minSdkVersion:33)
 apache-xml(minSdkVersion:31)
+appsearch_flags_java_lib(minSdkVersion:33)
+art-aconfig-flags-java-lib(minSdkVersion:31)
+art-aconfig-flags-lib(minSdkVersion:31)
 audioclient-types-aidl-cpp(minSdkVersion:29)
 audioflinger-aidl-cpp(minSdkVersion:29)
 audiopolicy-aidl-cpp(minSdkVersion:29)
+auto_service_annotations(minSdkVersion:current)
 auto_value_annotations(minSdkVersion:19)
 av-headers(minSdkVersion:29)
 av-types-aidl-cpp(minSdkVersion:29)
@@ -323,6 +179,7 @@ brotli-java(minSdkVersion:29)
 brotli-java(minSdkVersion:current)
 captiveportal-lib(minSdkVersion:29)
 captiveportal-lib(minSdkVersion:30)
+CaptivePortalLoginLib(minSdkVersion:30)
 car-rotary-lib(minSdkVersion:28)
 car-rotary-lib-overlayable-resources(minSdkVersion:28)
 car-rotary-lib-resources(minSdkVersion:28)
@@ -334,6 +191,8 @@ car-ui-lib-source-no-overlayable(minSdkVersion:28)
 cbor-java(minSdkVersion:30)
 cellbroadcast-java-proto-lite(minSdkVersion:current)
 CellBroadcastCommon(minSdkVersion:30)
+cellbroadcastreceiver_aconfig_flags_lib(minSdkVersion:30)
+cellbroadcastreceiver_flags_lib(minSdkVersion:30)
 census(minSdkVersion:30)
 clatd(minSdkVersion:30)
 codecs_g711dec(minSdkVersion:29)
@@ -421,6 +280,8 @@ framework-permission-s(minSdkVersion:31)
 framework-permission.impl(minSdkVersion:30)
 framework-profiling(minSdkVersion:34)
 framework-profiling(minSdkVersion:current)
+framework-ranging(minSdkVersion:current)
+framework-ranging.impl(minSdkVersion:current)
 framework-statsd(minSdkVersion:30)
 framework-statsd(minSdkVersion:current)
 framework-statsd.impl(minSdkVersion:30)
@@ -452,6 +313,7 @@ grpc-java-core-util(minSdkVersion:30)
 grpc-java-okhttp(minSdkVersion:30)
 grpc-java-protobuf-lite(minSdkVersion:30)
 grpc-java-stub(minSdkVersion:30)
+gson(minSdkVersion:30)
 guava(minSdkVersion:current)
 guava-android-annotation-stubs(minSdkVersion:30)
 gwp_asan_headers(minSdkVersion:S)
@@ -465,6 +327,7 @@ internal_include_headers(minSdkVersion:30)
 ipmemorystore-aidl-interfaces-java(minSdkVersion:29)
 ipmemorystore-aidl-interfaces-V10-java(minSdkVersion:29)
 ipmemorystore-aidl-interfaces-V10-java(minSdkVersion:30)
+ipmemorystore-aidl-interfaces-V11-java(minSdkVersion:30)
 jacocoagent(minSdkVersion:9)
 jni_headers(minSdkVersion:29)
 jni_platform_headers(minSdkVersion:S)
@@ -504,6 +367,11 @@ libandroid_log_sys(minSdkVersion:29)
 libandroid_logger(minSdkVersion:29)
 libanyhow(minSdkVersion:29)
 libaom(minSdkVersion:29)
+libaom_arm_crc32(minSdkVersion:29)
+libaom_neon_dotprod(minSdkVersion:29)
+libaom_neon_i8mm(minSdkVersion:29)
+libaom_sve(minSdkVersion:29)
+libaom_sve2(minSdkVersion:29)
 libapp_processes_protos_lite(minSdkVersion:(no version))
 libapp_processes_protos_lite(minSdkVersion:30)
 libarect(minSdkVersion:29)
@@ -560,8 +428,8 @@ libc++demangle(minSdkVersion:apex_inherit)
 libc++fs(minSdkVersion:apex_inherit)
 libc_headers(minSdkVersion:apex_inherit)
 libc_headers_arch(minSdkVersion:apex_inherit)
-libc_llndk_headers(minSdkVersion:apex_inherit)
 libc_scudo(minSdkVersion:apex_inherit)
+libc_uapi_headers(minSdkVersion:apex_inherit)
 libcap(minSdkVersion:29)
 libcesu8(minSdkVersion:29)
 libcfg_if(minSdkVersion:29)
@@ -642,10 +510,12 @@ libdowncast_rs(minSdkVersion:29)
 libeigen(minSdkVersion:(no version))
 libeigen(minSdkVersion:apex_inherit)
 libenv_logger(minSdkVersion:29)
+liberrno(minSdkVersion:30)
 liberror_headers(minSdkVersion:29)
 libevent(minSdkVersion:30)
 libexpat(minSdkVersion:apex_inherit)
 libexpectedutils_headers(minSdkVersion:29)
+libexpresslog(minSdkVersion:33)
 libexpresslog_jni(minSdkVersion:30)
 libextservices(minSdkVersion:30)
 libextservices_jni(minSdkVersion:30)
@@ -867,6 +737,7 @@ libpower(minSdkVersion:Tiramisu)
 libproc_macro_nested(minSdkVersion:29)
 libprocessgroup(minSdkVersion:29)
 libprocessgroup_headers(minSdkVersion:29)
+libprocessgroup_util(minSdkVersion:30)
 libprocinfo(minSdkVersion:apex_inherit)
 libprocpartition(minSdkVersion:(no version))
 libprocpartition(minSdkVersion:30)
@@ -900,6 +771,7 @@ librkpd(minSdkVersion:33)
 librustc_demangle(minSdkVersion:S)
 librustc_demangle.rust_sysroot(minSdkVersion:29)
 librustc_demangle_static(minSdkVersion:S)
+librustix(minSdkVersion:30)
 librustutils(minSdkVersion:29)
 libruy_static(minSdkVersion:30)
 libscopeguard(minSdkVersion:29)
@@ -940,6 +812,7 @@ libstagefright_mp3dec_headers(minSdkVersion:29)
 libstagefright_mpeg2extractor(minSdkVersion:29)
 libstagefright_mpeg2support(minSdkVersion:29)
 libstatic_assertions(minSdkVersion:29)
+libstatslog_express(minSdkVersion:33)
 libstatspull_bindgen(minSdkVersion:apex_inherit)
 libstatssocket_headers(minSdkVersion:29)
 libstd(minSdkVersion:29)
@@ -951,6 +824,7 @@ libsystem_properties_bindgen_sys(minSdkVersion:29)
 libsysutils(minSdkVersion:apex_inherit)
 libtcutils(minSdkVersion:30)
 libtempfile(minSdkVersion:29)
+libtempfile(minSdkVersion:30)
 libterm(minSdkVersion:29)
 libtest(minSdkVersion:29)
 libtextclassifier(minSdkVersion:(no version))
@@ -1055,6 +929,7 @@ ndk_libc++abi(minSdkVersion:(no version))
 ndk_libc++abi(minSdkVersion:16)
 ndk_libunwind(minSdkVersion:16)
 ndk_system(minSdkVersion:(no version))
+net-utils-connectivity-apks(minSdkVersion:30)
 net-utils-device-common(minSdkVersion:29)
 net-utils-device-common(minSdkVersion:30)
 net-utils-device-common-bpf(minSdkVersion:29)
@@ -1069,7 +944,12 @@ net-utils-device-common-struct-base(minSdkVersion:30)
 net-utils-framework-common(minSdkVersion:29)
 net-utils-framework-common(minSdkVersion:30)
 net-utils-framework-common(minSdkVersion:current)
+net-utils-framework-connectivity(minSdkVersion:30)
+net-utils-non-bootclasspath-aidl-java(minSdkVersion:30)
+net-utils-service-connectivity(minSdkVersion:30)
+net-utils-service-wifi(minSdkVersion:30)
 net-utils-services-common(minSdkVersion:30)
+net-utils-tethering(minSdkVersion:30)
 netbpfload(minSdkVersion:30)
 netd-client(minSdkVersion:29)
 netd-client(minSdkVersion:30)
@@ -1123,6 +1003,7 @@ networkstack-aidl-interfaces-V18-java(minSdkVersion:30)
 networkstack-aidl-interfaces-V19-java(minSdkVersion:30)
 networkstack-aidl-interfaces-V20-java(minSdkVersion:30)
 networkstack-aidl-interfaces-V21-java(minSdkVersion:30)
+networkstack-aidl-interfaces-V22-java(minSdkVersion:30)
 networkstack-aidl-latest(minSdkVersion:29)
 networkstack-aidl-latest(minSdkVersion:30)
 networkstack-client(minSdkVersion:29)
@@ -1190,6 +1071,7 @@ philox_random(minSdkVersion:(no version))
 philox_random(minSdkVersion:30)
 philox_random_headers(minSdkVersion:(no version))
 philox_random_headers(minSdkVersion:30)
+Photopicker(minSdkVersion:30)
 PhotopickerGoogle(minSdkVersion:30)
 PhotopickerLib(minSdkVersion:30)
 PlatformProperties(minSdkVersion:current)
@@ -1199,352 +1081,6 @@ prebuilt_androidx-constraintlayout_constraintlayout-nodeps(minSdkVersion:(no ver
 prebuilt_androidx-constraintlayout_constraintlayout-nodeps(minSdkVersion:21)
 prebuilt_androidx-constraintlayout_constraintlayout-solver-nodeps(minSdkVersion:24)
 prebuilt_androidx-constraintlayout_constraintlayout-solver-nodeps(minSdkVersion:current)
-prebuilt_androidx.activity_activity(minSdkVersion:21)
-prebuilt_androidx.activity_activity-compose(minSdkVersion:21)
-prebuilt_androidx.activity_activity-compose-nodeps(minSdkVersion:21)
-prebuilt_androidx.activity_activity-ktx(minSdkVersion:21)
-prebuilt_androidx.activity_activity-ktx-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.activity_activity-ktx-nodeps(minSdkVersion:21)
-prebuilt_androidx.activity_activity-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.activity_activity-nodeps(minSdkVersion:21)
-prebuilt_androidx.annotation_annotation(minSdkVersion:24)
-prebuilt_androidx.annotation_annotation-experimental(minSdkVersion:21)
-prebuilt_androidx.annotation_annotation-experimental-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.annotation_annotation-experimental-nodeps(minSdkVersion:21)
-prebuilt_androidx.annotation_annotation-jvm-nodeps(minSdkVersion:24)
-prebuilt_androidx.annotation_annotation-nodeps(minSdkVersion:24)
-prebuilt_androidx.annotation_annotation-nodeps(minSdkVersion:30)
-prebuilt_androidx.annotation_annotation-nodeps(minSdkVersion:current)
-prebuilt_androidx.appcompat_appcompat(minSdkVersion:21)
-prebuilt_androidx.appcompat_appcompat-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.appcompat_appcompat-nodeps(minSdkVersion:19)
-prebuilt_androidx.appcompat_appcompat-resources(minSdkVersion:21)
-prebuilt_androidx.appcompat_appcompat-resources-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.appcompat_appcompat-resources-nodeps(minSdkVersion:19)
-prebuilt_androidx.appsearch_appsearch(minSdkVersion:19)
-prebuilt_androidx.appsearch_appsearch-nodeps(minSdkVersion:19)
-prebuilt_androidx.appsearch_appsearch-platform-storage(minSdkVersion:19)
-prebuilt_androidx.appsearch_appsearch-platform-storage-nodeps(minSdkVersion:19)
-prebuilt_androidx.arch.core_core-common(minSdkVersion:24)
-prebuilt_androidx.arch.core_core-common-nodeps(minSdkVersion:24)
-prebuilt_androidx.arch.core_core-common-nodeps(minSdkVersion:30)
-prebuilt_androidx.arch.core_core-common-nodeps(minSdkVersion:current)
-prebuilt_androidx.arch.core_core-runtime(minSdkVersion:19)
-prebuilt_androidx.arch.core_core-runtime-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.arch.core_core-runtime-nodeps(minSdkVersion:19)
-prebuilt_androidx.asynclayoutinflater_asynclayoutinflater(minSdkVersion:19)
-prebuilt_androidx.asynclayoutinflater_asynclayoutinflater-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.asynclayoutinflater_asynclayoutinflater-nodeps(minSdkVersion:19)
-prebuilt_androidx.autofill_autofill(minSdkVersion:19)
-prebuilt_androidx.autofill_autofill-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.autofill_autofill-nodeps(minSdkVersion:19)
-prebuilt_androidx.browser_browser-nodeps(minSdkVersion:19)
-prebuilt_androidx.cardview_cardview(minSdkVersion:19)
-prebuilt_androidx.cardview_cardview-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.cardview_cardview-nodeps(minSdkVersion:19)
-prebuilt_androidx.collection_collection(minSdkVersion:24)
-prebuilt_androidx.collection_collection-jvm-nodeps(minSdkVersion:24)
-prebuilt_androidx.collection_collection-ktx(minSdkVersion:24)
-prebuilt_androidx.collection_collection-ktx-nodeps(minSdkVersion:24)
-prebuilt_androidx.collection_collection-ktx-nodeps(minSdkVersion:30)
-prebuilt_androidx.collection_collection-ktx-nodeps(minSdkVersion:current)
-prebuilt_androidx.collection_collection-nodeps(minSdkVersion:24)
-prebuilt_androidx.collection_collection-nodeps(minSdkVersion:30)
-prebuilt_androidx.collection_collection-nodeps(minSdkVersion:current)
-prebuilt_androidx.compose.animation_animation(minSdkVersion:21)
-prebuilt_androidx.compose.animation_animation-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.animation_animation-core(minSdkVersion:21)
-prebuilt_androidx.compose.animation_animation-core-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.animation_animation-core-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.animation_animation-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.foundation_foundation(minSdkVersion:21)
-prebuilt_androidx.compose.foundation_foundation-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.foundation_foundation-layout(minSdkVersion:21)
-prebuilt_androidx.compose.foundation_foundation-layout-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.foundation_foundation-layout-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.foundation_foundation-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.material3_material3(minSdkVersion:21)
-prebuilt_androidx.compose.material3_material3-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.material3_material3-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.material3_material3-window-size-class(minSdkVersion:21)
-prebuilt_androidx.compose.material3_material3-window-size-class-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.material_material-icons-core(minSdkVersion:21)
-prebuilt_androidx.compose.material_material-icons-core-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.material_material-icons-core-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.material_material-icons-extended(minSdkVersion:21)
-prebuilt_androidx.compose.material_material-icons-extended-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.material_material-ripple(minSdkVersion:21)
-prebuilt_androidx.compose.material_material-ripple-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.material_material-ripple-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.runtime_runtime(minSdkVersion:21)
-prebuilt_androidx.compose.runtime_runtime-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.runtime_runtime-livedata(minSdkVersion:21)
-prebuilt_androidx.compose.runtime_runtime-livedata-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.runtime_runtime-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.runtime_runtime-saveable(minSdkVersion:21)
-prebuilt_androidx.compose.runtime_runtime-saveable-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.runtime_runtime-saveable-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-geometry(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-geometry-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-geometry-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-graphics(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-graphics-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-graphics-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-text(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-text-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-text-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-unit(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-unit-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-unit-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-util(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-util-android-nodeps(minSdkVersion:21)
-prebuilt_androidx.compose.ui_ui-util-nodeps(minSdkVersion:21)
-prebuilt_androidx.concurrent_concurrent-futures(minSdkVersion:24)
-prebuilt_androidx.concurrent_concurrent-futures-ktx(minSdkVersion:24)
-prebuilt_androidx.concurrent_concurrent-futures-ktx-nodeps(minSdkVersion:24)
-prebuilt_androidx.concurrent_concurrent-futures-nodeps(minSdkVersion:24)
-prebuilt_androidx.constraintlayout_constraintlayout-core(minSdkVersion:24)
-prebuilt_androidx.constraintlayout_constraintlayout-core-nodeps(minSdkVersion:24)
-prebuilt_androidx.coordinatorlayout_coordinatorlayout(minSdkVersion:19)
-prebuilt_androidx.coordinatorlayout_coordinatorlayout-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.coordinatorlayout_coordinatorlayout-nodeps(minSdkVersion:19)
-prebuilt_androidx.core_core(minSdkVersion:21)
-prebuilt_androidx.core_core-ktx(minSdkVersion:21)
-prebuilt_androidx.core_core-ktx-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.core_core-ktx-nodeps(minSdkVersion:19)
-prebuilt_androidx.core_core-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.core_core-nodeps(minSdkVersion:19)
-prebuilt_androidx.cursoradapter_cursoradapter(minSdkVersion:19)
-prebuilt_androidx.cursoradapter_cursoradapter-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.cursoradapter_cursoradapter-nodeps(minSdkVersion:19)
-prebuilt_androidx.customview_customview(minSdkVersion:19)
-prebuilt_androidx.customview_customview-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.customview_customview-nodeps(minSdkVersion:19)
-prebuilt_androidx.customview_customview-poolingcontainer(minSdkVersion:19)
-prebuilt_androidx.customview_customview-poolingcontainer-nodeps(minSdkVersion:19)
-prebuilt_androidx.documentfile_documentfile(minSdkVersion:19)
-prebuilt_androidx.documentfile_documentfile-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.documentfile_documentfile-nodeps(minSdkVersion:19)
-prebuilt_androidx.drawerlayout_drawerlayout(minSdkVersion:19)
-prebuilt_androidx.drawerlayout_drawerlayout-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.drawerlayout_drawerlayout-nodeps(minSdkVersion:19)
-prebuilt_androidx.dynamicanimation_dynamicanimation(minSdkVersion:19)
-prebuilt_androidx.dynamicanimation_dynamicanimation-nodeps(minSdkVersion:19)
-prebuilt_androidx.emoji2_emoji-nodeps(minSdkVersion:19)
-prebuilt_androidx.emoji2_emoji2(minSdkVersion:21)
-prebuilt_androidx.emoji2_emoji2-nodeps(minSdkVersion:19)
-prebuilt_androidx.emoji2_emoji2-views-helpe-nodeps(minSdkVersion:19)
-prebuilt_androidx.emoji2_emoji2-views-helper(minSdkVersion:21)
-prebuilt_androidx.emoji2_emoji2-views-helper-nodeps(minSdkVersion:19)
-prebuilt_androidx.exifinterface_exifinterface(minSdkVersion:19)
-prebuilt_androidx.exifinterface_exifinterface-nodeps(minSdkVersion:19)
-prebuilt_androidx.fragment_fragment(minSdkVersion:21)
-prebuilt_androidx.fragment_fragment-ktx(minSdkVersion:21)
-prebuilt_androidx.fragment_fragment-ktx-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.fragment_fragment-ktx-nodeps(minSdkVersion:19)
-prebuilt_androidx.fragment_fragment-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.fragment_fragment-nodeps(minSdkVersion:19)
-prebuilt_androidx.graphics_graphics-path(minSdkVersion:21)
-prebuilt_androidx.graphics_graphics-path-nodeps(minSdkVersion:21)
-prebuilt_androidx.hilt_hilt-navigation(minSdkVersion:21)
-prebuilt_androidx.hilt_hilt-navigation-compose(minSdkVersion:21)
-prebuilt_androidx.hilt_hilt-navigation-compose-nodeps(minSdkVersion:21)
-prebuilt_androidx.hilt_hilt-navigation-nodeps(minSdkVersion:19)
-prebuilt_androidx.interpolator_interpolator(minSdkVersion:19)
-prebuilt_androidx.interpolator_interpolator-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.interpolator_interpolator-nodeps(minSdkVersion:19)
-prebuilt_androidx.javascriptengine_javascriptengine(minSdkVersion:26)
-prebuilt_androidx.javascriptengine_javascriptengine-nodeps(minSdkVersion:26)
-prebuilt_androidx.leanback_leanback(minSdkVersion:19)
-prebuilt_androidx.leanback_leanback-grid(minSdkVersion:19)
-prebuilt_androidx.leanback_leanback-grid-nodeps(minSdkVersion:19)
-prebuilt_androidx.leanback_leanback-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.leanback_leanback-nodeps(minSdkVersion:19)
-prebuilt_androidx.leanback_leanback-preference(minSdkVersion:21)
-prebuilt_androidx.leanback_leanback-preference-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.leanback_leanback-preference-nodeps(minSdkVersion:21)
-prebuilt_androidx.legacy_legacy-support-core-ui-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.legacy_legacy-support-core-ui-nodeps(minSdkVersion:19)
-prebuilt_androidx.legacy_legacy-support-core-ui-nodeps(minSdkVersion:21)
-prebuilt_androidx.legacy_legacy-support-core-utils-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.legacy_legacy-support-core-utils-nodeps(minSdkVersion:19)
-prebuilt_androidx.legacy_legacy-support-core-utils-nodeps(minSdkVersion:21)
-prebuilt_androidx.legacy_legacy-support-v13-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.legacy_legacy-support-v13-nodeps(minSdkVersion:19)
-prebuilt_androidx.legacy_legacy-support-v13-nodeps(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-common(minSdkVersion:24)
-prebuilt_androidx.lifecycle_lifecycle-common-java8(minSdkVersion:24)
-prebuilt_androidx.lifecycle_lifecycle-common-java8-nodeps(minSdkVersion:24)
-prebuilt_androidx.lifecycle_lifecycle-common-java8-nodeps(minSdkVersion:30)
-prebuilt_androidx.lifecycle_lifecycle-common-java8-nodeps(minSdkVersion:current)
-prebuilt_androidx.lifecycle_lifecycle-common-nodeps(minSdkVersion:24)
-prebuilt_androidx.lifecycle_lifecycle-common-nodeps(minSdkVersion:30)
-prebuilt_androidx.lifecycle_lifecycle-common-nodeps(minSdkVersion:current)
-prebuilt_androidx.lifecycle_lifecycle-extensions-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-extensions-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-extensions-nodeps(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-livedata(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-livedata(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-livedata-core(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-livedata-core(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-livedata-core-ktx(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-livedata-core-ktx(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-livedata-core-ktx-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-livedata-core-ktx-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-livedata-core-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-livedata-core-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-livedata-ktx(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-livedata-ktx-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-livedata-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-livedata-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-process(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-process-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-process-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-runtime(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-runtime-compose(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-runtime-compose-nodeps(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-runtime-ktx(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-runtime-ktx-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-runtime-ktx-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-runtime-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-runtime-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-service(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-service-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-service-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-viewmodel(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-viewmodel-compose(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-viewmodel-compose-nodeps(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-viewmodel-ktx(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-viewmodel-ktx-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-viewmodel-ktx-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-viewmodel-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-viewmodel-nodeps(minSdkVersion:19)
-prebuilt_androidx.lifecycle_lifecycle-viewmodel-savedstate(minSdkVersion:21)
-prebuilt_androidx.lifecycle_lifecycle-viewmodel-savedstate-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.lifecycle_lifecycle-viewmodel-savedstate-nodeps(minSdkVersion:19)
-prebuilt_androidx.loader_loader(minSdkVersion:19)
-prebuilt_androidx.loader_loader-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.loader_loader-nodeps(minSdkVersion:19)
-prebuilt_androidx.localbroadcastmanager_localbroadcastmanager-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.localbroadcastmanager_localbroadcastmanager-nodeps(minSdkVersion:19)
-prebuilt_androidx.localbroadcastmanager_localbroadcastmanager-nodeps(minSdkVersion:21)
-prebuilt_androidx.media_media(minSdkVersion:19)
-prebuilt_androidx.media_media-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.media_media-nodeps(minSdkVersion:19)
-prebuilt_androidx.navigation_navigation-common(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-common-ktx(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-common-ktx-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.navigation_navigation-common-ktx-nodeps(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-common-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.navigation_navigation-common-nodeps(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-compose(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-compose-nodeps(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-fragment(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-fragment-ktx(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-fragment-ktx-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.navigation_navigation-fragment-ktx-nodeps(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-fragment-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.navigation_navigation-fragment-nodeps(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-runtime(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-runtime-ktx(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-runtime-ktx-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.navigation_navigation-runtime-ktx-nodeps(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-runtime-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.navigation_navigation-runtime-nodeps(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-ui(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-ui-ktx(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-ui-ktx-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.navigation_navigation-ui-ktx-nodeps(minSdkVersion:21)
-prebuilt_androidx.navigation_navigation-ui-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.navigation_navigation-ui-nodeps(minSdkVersion:21)
-prebuilt_androidx.paging_paging-common(minSdkVersion:19)
-prebuilt_androidx.paging_paging-common-ktx(minSdkVersion:24)
-prebuilt_androidx.paging_paging-common-ktx-nodeps(minSdkVersion:24)
-prebuilt_androidx.paging_paging-common-nodeps(minSdkVersion:19)
-prebuilt_androidx.paging_paging-common-nodeps(minSdkVersion:24)
-prebuilt_androidx.paging_paging-compose(minSdkVersion:21)
-prebuilt_androidx.paging_paging-compose-nodeps(minSdkVersion:21)
-prebuilt_androidx.paging_paging-runtime(minSdkVersion:19)
-prebuilt_androidx.paging_paging-runtime-nodeps(minSdkVersion:19)
-prebuilt_androidx.preference_preference(minSdkVersion:19)
-prebuilt_androidx.preference_preference-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.preference_preference-nodeps(minSdkVersion:19)
-prebuilt_androidx.print_print(minSdkVersion:19)
-prebuilt_androidx.print_print-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.print_print-nodeps(minSdkVersion:19)
-prebuilt_androidx.profileinstaller_profileinstaller(minSdkVersion:19)
-prebuilt_androidx.profileinstaller_profileinstaller-nodeps(minSdkVersion:19)
-prebuilt_androidx.recyclerview_recyclerview(minSdkVersion:21)
-prebuilt_androidx.recyclerview_recyclerview-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.recyclerview_recyclerview-nodeps(minSdkVersion:19)
-prebuilt_androidx.recyclerview_recyclerview-selection(minSdkVersion:21)
-prebuilt_androidx.recyclerview_recyclerview-selection-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.recyclerview_recyclerview-selection-nodeps(minSdkVersion:19)
-prebuilt_androidx.resourceinspection_resourceinspection-annotation(minSdkVersion:24)
-prebuilt_androidx.resourceinspection_resourceinspection-annotation-nodeps(minSdkVersion:24)
-prebuilt_androidx.room_room-common(minSdkVersion:24)
-prebuilt_androidx.room_room-common-nodeps(minSdkVersion:24)
-prebuilt_androidx.room_room-ktx(minSdkVersion:21)
-prebuilt_androidx.room_room-ktx-nodeps(minSdkVersion:19)
-prebuilt_androidx.room_room-runtime(minSdkVersion:21)
-prebuilt_androidx.room_room-runtime-nodeps(minSdkVersion:19)
-prebuilt_androidx.savedstate_savedstate(minSdkVersion:19)
-prebuilt_androidx.savedstate_savedstate-ktx(minSdkVersion:19)
-prebuilt_androidx.savedstate_savedstate-ktx-nodeps(minSdkVersion:19)
-prebuilt_androidx.savedstate_savedstate-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.savedstate_savedstate-nodeps(minSdkVersion:19)
-prebuilt_androidx.slidingpanelayout_slidingpanelayout(minSdkVersion:19)
-prebuilt_androidx.slidingpanelayout_slidingpanelayout-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.slidingpanelayout_slidingpanelayout-nodeps(minSdkVersion:19)
-prebuilt_androidx.sqlite_sqlite(minSdkVersion:21)
-prebuilt_androidx.sqlite_sqlite-framework(minSdkVersion:21)
-prebuilt_androidx.sqlite_sqlite-framework-nodeps(minSdkVersion:21)
-prebuilt_androidx.sqlite_sqlite-nodeps(minSdkVersion:21)
-prebuilt_androidx.startup_startup-runtime(minSdkVersion:19)
-prebuilt_androidx.startup_startup-runtime-nodeps(minSdkVersion:19)
-prebuilt_androidx.swiperefreshlayout_swiperefreshlayout(minSdkVersion:19)
-prebuilt_androidx.swiperefreshlayout_swiperefreshlayout-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.swiperefreshlayout_swiperefreshlayout-nodeps(minSdkVersion:19)
-prebuilt_androidx.tracing_tracing(minSdkVersion:19)
-prebuilt_androidx.tracing_tracing-ktx(minSdkVersion:19)
-prebuilt_androidx.tracing_tracing-ktx-nodeps(minSdkVersion:19)
-prebuilt_androidx.tracing_tracing-nodeps(minSdkVersion:19)
-prebuilt_androidx.transition_transition(minSdkVersion:19)
-prebuilt_androidx.transition_transition-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.transition_transition-nodeps(minSdkVersion:19)
-prebuilt_androidx.vectordrawable_vectordrawable(minSdkVersion:19)
-prebuilt_androidx.vectordrawable_vectordrawable-animated(minSdkVersion:19)
-prebuilt_androidx.vectordrawable_vectordrawable-animated-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.vectordrawable_vectordrawable-animated-nodeps(minSdkVersion:19)
-prebuilt_androidx.vectordrawable_vectordrawable-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.vectordrawable_vectordrawable-nodeps(minSdkVersion:19)
-prebuilt_androidx.versionedparcelable_versionedparcelable(minSdkVersion:19)
-prebuilt_androidx.versionedparcelable_versionedparcelable-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.versionedparcelable_versionedparcelable-nodeps(minSdkVersion:19)
-prebuilt_androidx.viewpager2_viewpager2(minSdkVersion:19)
-prebuilt_androidx.viewpager2_viewpager2-nodeps(minSdkVersion:19)
-prebuilt_androidx.viewpager_viewpager(minSdkVersion:19)
-prebuilt_androidx.viewpager_viewpager-nodeps(minSdkVersion:(no version))
-prebuilt_androidx.viewpager_viewpager-nodeps(minSdkVersion:19)
-prebuilt_androidx.wear.compose_compose-foundation(minSdkVersion:25)
-prebuilt_androidx.wear.compose_compose-foundation-nodeps(minSdkVersion:25)
-prebuilt_androidx.wear.compose_compose-material(minSdkVersion:25)
-prebuilt_androidx.wear.compose_compose-material-core(minSdkVersion:25)
-prebuilt_androidx.wear.compose_compose-material-core-nodeps(minSdkVersion:25)
-prebuilt_androidx.wear.compose_compose-material-nodeps(minSdkVersion:25)
-prebuilt_androidx.wear.compose_compose-navigation-nodeps(minSdkVersion:25)
-prebuilt_androidx.wear_wear-nodeps(minSdkVersion:23)
-prebuilt_androidx.webkit_webkit(minSdkVersion:19)
-prebuilt_androidx.webkit_webkit-nodeps(minSdkVersion:19)
-prebuilt_androidx.window.extensions.core_core-nodeps(minSdkVersion:19)
-prebuilt_androidx.window.extensions.core_core-nodeps(minSdkVersion:21)
-prebuilt_androidx.window_window(minSdkVersion:21)
-prebuilt_androidx.window_window-nodeps(minSdkVersion:21)
-prebuilt_androidx.work_work-runtime(minSdkVersion:21)
-prebuilt_androidx.work_work-runtime-nodeps(minSdkVersion:21)
 prebuilt_asm-7.0(minSdkVersion:current)
 prebuilt_asm-9.2(minSdkVersion:current)
 prebuilt_asm-9.6(minSdkVersion:current)
@@ -1589,7 +1125,9 @@ prebuilt_glide-prebuilt(minSdkVersion:14)
 prebuilt_guava-listenablefuture-prebuilt-jar(minSdkVersion:29)
 prebuilt_guava-listenablefuture-prebuilt-jar(minSdkVersion:current)
 prebuilt_jni_headers(minSdkVersion:(no version))
+prebuilt_kotlin-annotations(minSdkVersion:current)
 prebuilt_kotlin-stdlib(minSdkVersion:current)
+prebuilt_kotlin-stdlib-jdk7(minSdkVersion:current)
 prebuilt_kotlin-stdlib-jdk8(minSdkVersion:current)
 prebuilt_kotlinx-coroutines-android-nodeps(minSdkVersion:(no version))
 prebuilt_kotlinx-coroutines-android-nodeps(minSdkVersion:current)
@@ -1607,6 +1145,8 @@ prebuilt_libnativehelper_compat_libc++(minSdkVersion:(no version))
 prebuilt_libnativehelper_header_only(minSdkVersion:(no version))
 prebuilt_libperfetto_client_experimental(minSdkVersion:(no version))
 prebuilt_libunwind(minSdkVersion:(no version))
+prebuilt_ndk_libc++_static(minSdkVersion:(no version))
+prebuilt_ndk_libc++abi(minSdkVersion:(no version))
 prebuilt_perfetto_trace_protos(minSdkVersion:(no version))
 prebuilt_play-services-basement-aar(minSdkVersion:14)
 prebuilt_play-services-cloud-messaging-aar(minSdkVersion:14)
@@ -1629,6 +1169,7 @@ service-entitlement-data(minSdkVersion:29)
 service-entitlement-impl(minSdkVersion:29)
 ServiceWifiResourcesGoogle(minSdkVersion:30)
 settingslib_illustrationpreference_flags_lib(minSdkVersion:30)
+settingslib_selectorwithwidgetpreference_flags_lib(minSdkVersion:30)
 SettingsLibActionBarShadow(minSdkVersion:21)
 SettingsLibActionBarShadow(minSdkVersion:28)
 SettingsLibActivityEmbedding(minSdkVersion:21)
diff --git a/build/mainline_modules_sdks.py b/build/mainline_modules_sdks.py
index d76b0c0a..07ea6d7a 100755
--- a/build/mainline_modules_sdks.py
+++ b/build/mainline_modules_sdks.py
@@ -1036,11 +1036,6 @@ class MainlineModule:
                 "Android.bp", configVar=config_var
             )
             transformations.append(transformation)
-        elif prefer_handling == PreferHandling.USE_NO_PREFER_PROPERTY:
-            transformation = UseNoPreferPropertyTransformation(
-                "Android.bp", configVar=config_var
-            )
-            transformations.append(transformation)
 
         if self.additional_transformations and build_release > R:
             transformations.extend(self.additional_transformations)
diff --git a/build/mainline_modules_sdks_test_data/OWNERS b/build/mainline_modules_sdks_test_data/OWNERS
index 2fba2131..c577aa93 100644
--- a/build/mainline_modules_sdks_test_data/OWNERS
+++ b/build/mainline_modules_sdks_test_data/OWNERS
@@ -1,3 +1,2 @@
-hansson@google.com
 paulduffin@google.com
 robertogil@google.com
diff --git a/javatests/com/android/modules/updatablesharedlibs/apps/targetTWithLib/Android.bp b/javatests/com/android/modules/updatablesharedlibs/apps/targetTWithLib/Android.bp
index f81e903a..614ca449 100644
--- a/javatests/com/android/modules/updatablesharedlibs/apps/targetTWithLib/Android.bp
+++ b/javatests/com/android/modules/updatablesharedlibs/apps/targetTWithLib/Android.bp
@@ -23,7 +23,7 @@ android_test_helper_app {
     name: "com.android.modules.updatablesharedlibs.apps.targetTWithLib",
     srcs: ["UpdatableSharedLibraryTargetTWithLibraryTest.java"],
     libs: [
-        "com.android.modules.updatablesharedlibs.libs.since.t",
+        "com.android.modules.updatablesharedlibs.libs.since.t.stubs",
     ],
     static_libs: [
         "androidx.test.rules",
diff --git a/sdk/ModuleDefaults.bp b/sdk/ModuleDefaults.bp
index 47ae7df0..c1e84fdf 100644
--- a/sdk/ModuleDefaults.bp
+++ b/sdk/ModuleDefaults.bp
@@ -285,6 +285,16 @@ apex_defaults {
     defaults_visibility: ["//packages/modules:__subpackages__"],
 }
 
+apex_defaults {
+    name: "b-launched-apex-module",
+    defaults: ["any-launched-apex-modules"],
+    min_sdk_version: "Baklava",
+    // Indicates that pre-installed version of this apex can be compressed.
+    // Whether it actually will be compressed is controlled on per-device basis.
+    compressible: true,
+    defaults_visibility: ["//packages/modules:__subpackages__"],
+}
+
 library_linking_strategy_cc_defaults {
     name: "apex-lowest-min-sdk-version",
     defaults_visibility: [
diff --git a/tools/finalize_sdk.py b/tools/finalize_sdk.py
index 70aa8d29..db1ffc81 100755
--- a/tools/finalize_sdk.py
+++ b/tools/finalize_sdk.py
@@ -44,6 +44,22 @@ def fail(*args, **kwargs):
     print(*args, file=sys.stderr, **kwargs)
     sys.exit(1)
 
+def fetch_artifacts(build_id, target, artifact_path, dest):
+    print('Fetching %s from %s ...' % (artifact_path, target))
+    fetch_cmd = [FETCH_ARTIFACT]
+    fetch_cmd.extend(['--bid', str(build_id)])
+    fetch_cmd.extend(['--target', target])
+    fetch_cmd.append(artifact_path)
+    fetch_cmd.append(str(dest))
+    print("Running: " + ' '.join(fetch_cmd))
+    try:
+        subprocess.check_output(fetch_cmd, stderr=subprocess.STDOUT)
+    except subprocess.CalledProcessError as e:
+        fail(
+            'FAIL: Unable to retrieve %s artifact for build ID %s for %s target\n Error: %s'
+            % (artifact_path, build_id, target, e.output.decode())
+        )
+
 def fetch_mainline_modules_info_artifact(target, build_id):
     tmpdir = Path(tempfile.TemporaryDirectory().name)
     tmpdir.mkdir()
@@ -53,23 +69,10 @@ def fetch_mainline_modules_info_artifact(target, build_id):
         shutil.copy(artifact_path, tmpdir)
     else:
         artifact_path = ARTIFACT_MODULES_INFO
-        print('Fetching %s from %s ...' % (artifact_path, target))
-        fetch_cmd = [FETCH_ARTIFACT]
-        fetch_cmd.extend(['--bid', str(build_id)])
-        fetch_cmd.extend(['--target', target])
-        fetch_cmd.append(artifact_path)
-        fetch_cmd.append(str(tmpdir))
-        print("Running: " + ' '.join(fetch_cmd))
-        try:
-            subprocess.check_output(fetch_cmd, stderr=subprocess.STDOUT)
-        except subprocess.CalledProcessError:
-            fail(
-                'FAIL: Unable to retrieve %s artifact for build ID %s for %s target'
-                % (artifact_path, build_id, target)
-            )
-    return os.path.join(tmpdir, ARTIFACT_MODULES_INFO)
-
-def fetch_artifacts(target, build_id, module_name):
+        fetch_artifacts(build_id, target, artifact_path, tmpdir)
+    return tmpdir / ARTIFACT_MODULES_INFO
+
+def fetch_module_sdk_artifacts(target, build_id, module_name):
     tmpdir = Path(tempfile.TemporaryDirectory().name)
     tmpdir.mkdir()
     if args.local_mode:
@@ -79,31 +82,18 @@ def fetch_artifacts(target, build_id, module_name):
             shutil.copy(file, tmpdir)
     else:
         artifact_path = ARTIFACT_PATTERN.format(module_name=module_name)
-        print('Fetching %s from %s ...' % (artifact_path, target))
-        fetch_cmd = [FETCH_ARTIFACT]
-        fetch_cmd.extend(['--bid', str(build_id)])
-        fetch_cmd.extend(['--target', target])
-        fetch_cmd.append(artifact_path)
-        fetch_cmd.append(str(tmpdir))
-        print("Running: " + ' '.join(fetch_cmd))
-        try:
-            subprocess.check_output(fetch_cmd, stderr=subprocess.STDOUT)
-        except subprocess.CalledProcessError:
-            fail(
-                "FAIL: Unable to retrieve %s artifact for build ID %s"
-                % (artifact_path, build_id)
-            )
+        fetch_artifacts(build_id, target, artifact_path, tmpdir)
     return tmpdir
 
 def repo_for_sdk(sdk_filename, mainline_modules_info):
     for module in mainline_modules_info:
         if mainline_modules_info[module]["sdk_name"] in sdk_filename:
-            project_path = mainline_modules_info[module]["module_sdk_project"]
-            if args.gantry_mode:
-                project_path = "/tmp/" + project_path
+            project_path = Path(mainline_modules_info[module]["module_sdk_project"])
+            if args.gantry_download_dir:
+                project_path = args.gantry_download_dir / project_path
                 os.makedirs(project_path , exist_ok = True, mode = 0o777)
             print(f"module_sdk_path for {module}: {project_path}")
-            return Path(project_path)
+            return project_path
 
     fail('"%s" has no valid mapping to any mainline module.' % sdk_filename)
 
@@ -143,11 +133,12 @@ parser.add_argument('-r', '--readme', required=True, help='Version history entry
 parser.add_argument('-a', '--amend_last_commit', action="store_true", help='Amend current HEAD commits instead of making new commits.')
 parser.add_argument('-m', '--modules', action='append', help='Modules to include. Can be provided multiple times, or not at all for all modules.')
 parser.add_argument('-l', '--local_mode', action="store_true", help='Local mode: use locally built artifacts and don\'t upload the result to Gerrit.')
-parser.add_argument('-g', '--gantry_mode', action="store_true", help='Script executed via Gantry in google3.')
+# This flag is only required when executed via Gantry. It points to the downloaded directory to be used.
+parser.add_argument('-g', '--gantry_download_dir', type=str, help=argparse.SUPPRESS)
 parser.add_argument('bid', help='Build server build ID')
 args = parser.parse_args()
 
-if not os.path.isdir('build/soong') and not args.gantry_mode:
+if not os.path.isdir('build/soong') and not args.gantry_download_dir:
     fail("This script must be run from the top of an Android source tree.")
 
 if args.release_config:
@@ -158,20 +149,27 @@ cmdline = shlex.join([x for x in sys.argv if x not in ['-a', '--amend_last_commi
 commit_message = COMMIT_TEMPLATE % (args.finalize_sdk, args.bid, cmdline, args.bug)
 module_names = args.modules or ['*']
 
-if args.gantry_mode:
-    COMPAT_REPO = Path('/tmp/') / COMPAT_REPO
+if args.gantry_download_dir:
+    args.gantry_download_dir = Path(args.gantry_download_dir)
+    COMPAT_REPO = args.gantry_download_dir / COMPAT_REPO
+    mainline_modules_info_file = args.gantry_download_dir / ARTIFACT_MODULES_INFO
+else:
+    mainline_modules_info_file = fetch_mainline_modules_info_artifact(build_target, args.bid)
+
 compat_dir = COMPAT_REPO.joinpath('extensions/%d' % args.finalize_sdk)
 if compat_dir.is_dir():
     print('Removing existing dir %s' % compat_dir)
     shutil.rmtree(compat_dir)
 
 created_dirs = defaultdict(set)
-mainline_modules_info_file = fetch_mainline_modules_info_artifact(build_target, args.bid)
 with open(mainline_modules_info_file, "r", encoding="utf8",) as file:
     mainline_modules_info = json.load(file)
 
 for m in module_names:
-    tmpdir = fetch_artifacts(build_target, args.bid, m)
+    if args.gantry_download_dir:
+        tmpdir = args.gantry_download_dir / "sdk_artifacts"
+    else:
+        tmpdir = fetch_module_sdk_artifacts(build_target, args.bid, m)
     for f in tmpdir.iterdir():
         repo = repo_for_sdk(f.name, mainline_modules_info)
         dir = dir_for_sdk(f.name, args.finalize_sdk)
@@ -205,7 +203,7 @@ if args.local_mode:
     sys.exit(0)
 
 # Do not commit any changes when the script is executed via Gantry.
-if args.gantry_mode:
+if args.gantry_download_dir:
     sys.exit(0)
 
 subprocess.check_output(['repo', 'start', branch_name] + list(created_dirs.keys()))
```

