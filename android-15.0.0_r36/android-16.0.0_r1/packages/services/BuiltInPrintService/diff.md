```diff
diff --git a/Android.bp b/Android.bp
index 906734c..114f7fa 100644
--- a/Android.bp
+++ b/Android.bp
@@ -23,14 +23,37 @@ android_app {
     srcs: [
         "src/**/*.java",
         "src/**/I*.aidl",
+        "src/**/*.kt",
     ],
     static_libs: [
         "androidx.core_core",
+        "bips_aconfig_flags_java_lib",
+        "androidx.appcompat_appcompat",
+        "androidx-constraintlayout_constraintlayout",
+        "androidx.recyclerview_recyclerview",
+        "androidx.preference_preference",
+        "androidx.fragment_fragment",
+        "androidx.lifecycle_lifecycle-common",
+        "androidx.lifecycle_lifecycle-runtime",
+        "androidx.lifecycle_lifecycle-livedata",
+        "androidx.lifecycle_lifecycle-viewmodel-ktx",
+        "androidx.lifecycle_lifecycle-livedata-ktx",
+        "androidx.lifecycle_lifecycle-extensions",
+        "androidx.annotation_annotation",
+        "kotlin-stdlib",
+        "kotlinx_coroutines",
+        "kotlinx-coroutines-android",
+        "androidx.core_core-ktx",
+    ],
+    flags_packages: [
+        "bips_aconfig_flags",
     ],
     resource_dirs: ["res"],
     sdk_version: "system_current",
     optimize: {
         proguard_flags_files: ["proguard.flags"],
+        shrink_resources: true,
+        optimize: true,
     },
     jni_libs: [
         "libwfds",
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index e135a31..f3aef28 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -37,7 +37,9 @@
         android:label="@string/app_name"
         android:icon="@drawable/ic_printservice"
         android:allowBackup="true"
-        android:supportsRtl="true">
+        android:enableOnBackInvokedCallback="false"
+        android:supportsRtl="true"
+        android:usesCleartextTraffic="true">
         <service android:name="com.android.bips.BuiltInPrintService"
                  android:exported="true"
                  android:permission="android.permission.BIND_PRINT_SERVICE">
@@ -59,7 +61,7 @@
 
         <activity
             android:name="com.android.bips.ui.MoreOptionsActivity"
-            android:theme="@style/Theme.BuiltInPrintService"
+            android:theme="@android:style/Theme.DeviceDefault.Settings"
             android:configChanges="orientation|screenSize"
             android:exported="true"
             android:permission="android.permission.START_PRINT_SERVICE_CONFIG_ACTIVITY" />
@@ -67,7 +69,7 @@
         <activity
             android:name="com.android.bips.ui.AddPrintersActivity"
             android:label="@string/title_activity_add_printer"
-            android:theme="@style/Theme.BuiltInPrintService"
+            android:theme="@android:style/Theme.DeviceDefault.Settings"
             android:excludeFromRecents="true"
             android:exported="true"
             android:configChanges="orientation|keyboardHidden|screenSize"
diff --git a/OWNERS b/OWNERS
index b93f9e4..fe84ced 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,4 @@
 # Bug component: 47273
 include platform/frameworks/base:/OWNERS
 anothermark@google.com
-kumarashishg@google.com
 bmgordon@google.com
diff --git a/flags/Android.bp b/flags/Android.bp
new file mode 100644
index 0000000..08ad74c
--- /dev/null
+++ b/flags/Android.bp
@@ -0,0 +1,38 @@
+//
+// Copyright (C) 2025 The Android Open Source Project
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aconfig_declarations {
+    name: "bips_aconfig_flags",
+    package: "com.android.bips.flags",
+    container: "system",
+    srcs: [
+        "flags.aconfig",
+    ],
+}
+
+java_aconfig_library {
+    name: "bips_aconfig_flags_java_lib",
+    aconfig_declarations: "bips_aconfig_flags",
+}
+
+cc_aconfig_library {
+    name: "bips_aconfig_flags_cc_lib",
+    aconfig_declarations: "bips_aconfig_flags",
+}
diff --git a/flags/flags.aconfig b/flags/flags.aconfig
new file mode 100644
index 0000000..cb61359
--- /dev/null
+++ b/flags/flags.aconfig
@@ -0,0 +1,10 @@
+package: "com.android.bips.flags"
+container: "system"
+
+flag {
+    name: "printer_info_details"
+    namespace: "printing"
+    description: "Display media and supply info in printer info page"
+    bug: "374764554"
+    is_fixed_read_only: true
+}
diff --git a/jni/Android.bp b/jni/Android.bp
index deb9f0f..7ad1e26 100644
--- a/jni/Android.bp
+++ b/jni/Android.bp
@@ -20,8 +20,6 @@ package {
 cc_library_shared {
     name: "libwfds",
 
-    sdk_version: "current",
-
     cflags: [
         "-DINCLUDE_PDF=1",
         "-Werror",
@@ -67,10 +65,14 @@ cc_library_shared {
         "plugins/genPCLm/inc",
         "ipphelper",
     ],
-    static_libs: ["libjpeg_static_ndk"],
+    static_libs: [
+        "bips_aconfig_flags_cc_lib",
+        "libjpeg_static_ndk",
+    ],
     shared_libs: [
         "libcups",
         "liblog",
         "libz",
+        "server_configurable_flags",
     ],
 }
diff --git a/jni/include/lib_wprint.h b/jni/include/lib_wprint.h
old mode 100755
new mode 100644
index 18f753e..1975a3f
--- a/jni/include/lib_wprint.h
+++ b/jni/include/lib_wprint.h
@@ -141,7 +141,7 @@ typedef struct {
     float job_left_margin;
     float job_right_margin;
     float job_bottom_margin;
-    bool preserve_scaling;
+    bool print_at_scale;
 
     bool face_down_tray;
 
@@ -317,6 +317,15 @@ bool wprintIsRunning();
 status_t wprintGetCapabilities(const wprint_connect_info_t *connect_info,
         printer_capabilities_t *printer_cap);
 
+wStatus_t wprintStatusMonitorSetup(const wprint_connect_info_t *connect_info);
+
+int wprintStatusMonitorStart(wStatus_t status_handle, void (*status_callback)
+        (const printer_state_dyn_t *new_status,
+         const printer_state_dyn_t *old_status,
+         void *param), void *param);
+
+void wprintStatusMonitorStop(wStatus_t status_handle);
+
 /*
  * Returns a preferred print format supported by the printer
  */
diff --git a/jni/include/printer_capabilities_types.h b/jni/include/printer_capabilities_types.h
index 6313a31..8cc6909 100644
--- a/jni/include/printer_capabilities_types.h
+++ b/jni/include/printer_capabilities_types.h
@@ -28,14 +28,16 @@
 #define MAX_UUID 46
 #define MAX_PRINT_SCALING_LENGTH    32
 #define MAX_PRINT_SCALING_COUNT     10
+#define MAX_PRINTER_ICONS_SUPPORTED 3
+#define MAX_MARKER 30
+#define MAX_MARKER_NAME 256
 
 #include "wprint_df_types.h"
 
 /*
  * Media ready set definition
  */
-typedef struct
-{
+typedef struct {
     unsigned int x_dimension;
     unsigned int y_dimension;
     char media_tray_tag[MAX_STRING + 1];
@@ -62,6 +64,8 @@ typedef struct {
     unsigned char faceDownTray;
     media_size_t supportedMediaSizes[MAX_SIZES_SUPPORTED];
     unsigned int numSupportedMediaSizes;
+    media_size_t supportedMediaReadySizes[MAX_SIZES_SUPPORTED];
+    unsigned int numSupportedMediaReadySizes;
 
     // IPP major version (0 = not supported)
     int ippVersionMajor;
@@ -98,6 +102,17 @@ typedef struct {
     int print_scalings_supported_count;
     char print_scaling_default[MAX_PRINT_SCALING_LENGTH]; /* Printer default value */
     unsigned char jobPagesPerSetSupported;
+
+    char certification[256];
+    int num_printer_icons;            /* Number of printer icon available*/
+    char printer_icons[MAX_PRINTER_ICONS_SUPPORTED][MAX_URI_LENGTH]; /* Printer Icon URIs */
+    int marker_levels_count;
+    char marker_names[MAX_MARKER][MAX_MARKER_NAME];
+    char marker_types[MAX_MARKER][MAX_MARKER_NAME];
+    char marker_colors[MAX_MARKER][MAX_MARKER_NAME];
+    int marker_levels[MAX_MARKER];
+    int marker_low_levels[MAX_MARKER];
+    int marker_high_levels[MAX_MARKER];
 } printer_capabilities_t;
 
 #endif // __PRINTER_CAPABILITIES_TYPES_H__
\ No newline at end of file
diff --git a/jni/include/wtypes.h b/jni/include/wtypes.h
index 29ed6b0..8372e5d 100644
--- a/jni/include/wtypes.h
+++ b/jni/include/wtypes.h
@@ -20,6 +20,7 @@
 
 #include <stddef.h>
 #include <stdbool.h>
+#include <stdint.h>
 
 /*
  * A return type for functions.
@@ -68,5 +69,6 @@ typedef unsigned long long uint64;
 
 /** A job handle */
 typedef unsigned long wJob_t;
+typedef uintptr_t wStatus_t;
 
 #endif // __WTYPES_H__
\ No newline at end of file
diff --git a/jni/ipphelper/ipp_print.c b/jni/ipphelper/ipp_print.c
index a95b2db..049ef77 100644
--- a/jni/ipphelper/ipp_print.c
+++ b/jni/ipphelper/ipp_print.c
@@ -323,9 +323,6 @@ static ipp_t *_fill_job(int ipp_op, char *printer_uri, const wprint_job_params_t
                 job_params->print_quality);
     }
 
-    ippAddResolution(request, IPP_TAG_JOB, "printer-resolution", IPP_RES_PER_INCH,
-            job_params->pixel_units, job_params->pixel_units);
-
     if (printer_caps->sidesSupported) {
         if (job_params->duplex == DUPLEX_MODE_BOOK) {
             ippAddString(request, IPP_TAG_JOB, IPP_TAG_KEYWORD, IPP_SIDES_TAG, NULL,
diff --git a/jni/ipphelper/ipphelper.c b/jni/ipphelper/ipphelper.c
index 4eef2c2..e29189d 100644
--- a/jni/ipphelper/ipphelper.c
+++ b/jni/ipphelper/ipphelper.c
@@ -24,6 +24,7 @@
 
 #include "ipp_print.h"
 #include "../plugins/media.h"
+#include "com_android_bips_flags.h"
 
 #define TAG "ipphelper"
 #define IPP_JOB_UNKNOWN ((ipp_jstate_t)(-1))
@@ -1093,6 +1094,12 @@ void parse_getMediaSupported(
     if (sizes_idx > 0) {
         strlcpy(capabilities->mediaDefault, mapDFMediaToIPPKeyword(media_supported->media_size[0]),
                     sizeof(capabilities->mediaDefault));
+        if (com_android_bips_flags_printer_info_details()) {
+            capabilities->numSupportedMediaReadySizes = sizes_idx;
+            for (i = 0; i < sizes_idx; i++) {
+                capabilities->supportedMediaReadySizes[i] = media_supported->media_size[i];
+            }
+        }
     }
 
     // Append media-supported. media is de-duplicated later in java
@@ -1241,6 +1248,21 @@ void parse_printerAttributes(ipp_t *response, printer_capabilities_t *capabiliti
                 sizeof(capabilities->location));
     }
 
+    if (com_android_bips_flags_printer_info_details()) {
+        capabilities->num_printer_icons = 0;
+        if ((attrptr = ippFindAttribute(response, "printer-icons", IPP_TAG_URI)) != NULL) {
+            for (i = 0; i < ippGetCount(attrptr) && i < MAX_PRINTER_ICONS_SUPPORTED; i++) {
+                capabilities->num_printer_icons++;
+                LOGD("parse_printerAttributes printer-icons[%d]: %s", i,
+                     ippGetString(attrptr, i, NULL));
+                strlcpy(capabilities->printer_icons[i], ippGetString(attrptr, i, NULL),
+                        sizeof(capabilities->printer_icons[i]));
+            }
+        } else {
+            LOGD("printer-icons not found");
+        }
+    }
+
     if ((attrptr = ippFindAttribute(response, "media-default", IPP_TAG_KEYWORD)) != NULL
          && strlen(capabilities->mediaDefault) <= 0) {
         strlcpy(capabilities->mediaDefault, ippGetString(attrptr, 0, NULL),
@@ -1587,8 +1609,8 @@ void parse_printerAttributes(ipp_t *response, printer_capabilities_t *capabiliti
         LOGD("print-scaling-default not found");
     }
 
-    if ((attrptr = ippFindAttribute(response, "job-pages-per-set-supported",
-            IPP_TAG_BOOLEAN)) != NULL && ippGetBoolean(attrptr, 0)) {
+    if ((attrptr = ippFindAttribute(response, "job-pages-per-set-supported", IPP_TAG_BOOLEAN)) !=
+        NULL && ippGetBoolean(attrptr, 0)) {
         capabilities->jobPagesPerSetSupported = 1;
     }
 
@@ -1596,6 +1618,10 @@ void parse_printerAttributes(ipp_t *response, printer_capabilities_t *capabiliti
     float certVersion = 0.0;
     if ((attrptr = ippFindAttribute(response, "mopria-certified", IPP_TAG_TEXT)) != NULL ||
         (attrptr = ippFindAttribute(response, "mopria_certified", IPP_TAG_TEXT)) != NULL) {
+        if (com_android_bips_flags_printer_info_details()) {
+            strlcpy(capabilities->certification, ippGetString(attrptr, 0, NULL),
+                    sizeof(capabilities->certification));
+        }
         certVersion = atof(ippGetString(attrptr, 0, NULL));
         LOGD("Mopria certified version: %f", certVersion);
     }
@@ -1603,6 +1629,88 @@ void parse_printerAttributes(ipp_t *response, printer_capabilities_t *capabiliti
         capabilities->jobPagesPerSetSupported = 0;
     }
 
+    if (com_android_bips_flags_printer_info_details()) {
+        ipp_attribute_t *marker_levels_attrptr, *marker_types_attrptr, *marker_names_attrptr,
+                *marker_colors_attrptr, *marker_low_levels_attrptr, *marker_high_levels_attrptr;
+        marker_levels_attrptr = ippFindAttribute(response, "marker-levels", IPP_TAG_INTEGER);
+        marker_types_attrptr = ippFindAttribute(response, "marker-types", IPP_TAG_KEYWORD);
+        marker_names_attrptr = ippFindAttribute(response, "marker-names", IPP_TAG_NAME);
+        marker_colors_attrptr = ippFindAttribute(response, "marker-colors", IPP_TAG_NAME);
+        marker_low_levels_attrptr = ippFindAttribute(response, "marker-low-levels",
+                                                     IPP_TAG_INTEGER);
+        marker_high_levels_attrptr = ippFindAttribute(response, "marker-high-levels",
+                                                      IPP_TAG_INTEGER);
+
+        bool has_markers = (((marker_levels_attrptr) != NULL) &&
+                            ((marker_types_attrptr) != NULL) &&
+                            ((marker_names_attrptr) != NULL) &&
+                            ((marker_colors_attrptr) != NULL) &&
+                            ((marker_low_levels_attrptr) != NULL) &&
+                            ((marker_high_levels_attrptr) != NULL));
+
+        if (has_markers) {
+            int marker_levels_count = MIN(MAX_MARKER, ippGetCount(marker_levels_attrptr));
+            int marker_types_count = MIN(MAX_MARKER, ippGetCount(marker_types_attrptr));
+            int marker_names_count = MIN(MAX_MARKER, ippGetCount(marker_names_attrptr));
+            int marker_colors_count = MIN(MAX_MARKER, ippGetCount(marker_colors_attrptr));
+            int marker_low_levels_count = MIN(MAX_MARKER, ippGetCount(marker_low_levels_attrptr));
+            int marker_high_levels_count = MIN(MAX_MARKER, ippGetCount(marker_high_levels_attrptr));
+
+            LOGD("DPS Marker has_markers=true,  Count of levels=%d , Count of types=%d, "
+                 "Count of names=%d, Count of  colors=%d, Count of lowlevels=%d, Count of highlevel=%d",
+                 marker_levels_count, marker_types_count, marker_names_count, marker_colors_count,
+                 marker_low_levels_count, marker_high_levels_count);
+
+            if (marker_levels_count == marker_types_count &&
+                marker_types_count == marker_names_count &&
+                marker_names_count == marker_colors_count &&
+                marker_colors_count == marker_low_levels_count &&
+                marker_low_levels_count == marker_high_levels_count) {
+                capabilities->marker_levels_count = marker_levels_count;
+
+                for (i = 0; i < marker_levels_count; i++) {
+                    capabilities->marker_levels[i] = ippGetInteger(marker_levels_attrptr, i);
+                    LOGD("%d  DPS Marker marker-levels=%d", i, capabilities->marker_levels[i]);
+                }
+
+                for (i = 0; i < marker_types_count; i++) {
+                    strlcpy(capabilities->marker_types[i],
+                            ippGetString(marker_types_attrptr, i, NULL),
+                            sizeof(capabilities->marker_types[i]));
+                    LOGD("%d  DPS Marker marker-types=%s", i, capabilities->marker_types[i]);
+                }
+
+                for (i = 0; i < marker_names_count; i++) {
+                    strlcpy(capabilities->marker_names[i],
+                            ippGetString(marker_names_attrptr, i, NULL),
+                            sizeof(capabilities->marker_names[i]));
+                    LOGD("%d  DPS Marker marker-names=%s", i, capabilities->marker_names[i]);
+                }
+
+                for (i = 0; i < marker_colors_count; i++) {
+                    strlcpy(capabilities->marker_colors[i],
+                            ippGetString(marker_colors_attrptr, i, NULL),
+                            sizeof(capabilities->marker_colors[i]));
+                    LOGD("%d  DPS Marker marker-colors=%s", i, capabilities->marker_colors[i]);
+                }
+
+                for (i = 0; i < marker_low_levels_count; i++) {
+                    capabilities->marker_low_levels[i] = ippGetInteger(marker_low_levels_attrptr,
+                                                                       i);
+                    LOGD("%d  DPS Marker marker-low-levels=%d", i,
+                         capabilities->marker_low_levels[i]);
+                }
+
+                for (i = 0; i < marker_high_levels_count; i++) {
+                    capabilities->marker_high_levels[i] = ippGetInteger(marker_high_levels_attrptr,
+                                                                        i);
+                    LOGD("%d DPS Marker marker-high-levels=%d", i,
+                         capabilities->marker_high_levels[i]);
+                }
+            }
+        }
+    }
+
     debuglist_printerCapabilities(capabilities);
 }
 
diff --git a/jni/ipphelper/ippstatus_capabilities.c b/jni/ipphelper/ippstatus_capabilities.c
index d0c6773..f1550bf 100644
--- a/jni/ipphelper/ippstatus_capabilities.c
+++ b/jni/ipphelper/ippstatus_capabilities.c
@@ -25,6 +25,7 @@
 #include "cups.h"
 #include "http-private.h"
 #include "wprint_debug.h"
+#include "com_android_bips_flags.h"
 
 #define TAG "ippstatus_capabilities"
 
@@ -32,6 +33,53 @@
  * Requested printer attributes
  */
 static const char *pattrs[] = {
+        "ipp-versions-supported",
+        "printer-make-and-model",
+        "printer-info",
+        "printer-dns-sd-name",
+        "printer-name",
+        "printer-location",
+        "printer-uuid",
+        "printer-uri-supported",
+        "uri-security-supported",
+        "uri-authentication-supported",
+        "color-supported",
+        "copies-supported",
+        "document-format-supported",
+        "media-col-default",
+        "media-default",
+        "media-left-margin-supported",
+        "media-right-margin-supported",
+        "media-top-margin-supported",
+        "media-bottom-margin-supported",
+        "media-supported",
+        "media-type-supported",
+        "output-bin-supported",
+        "print-color-mode-supported",
+        "print-quality-supported",
+        "printer-output-tray",
+        "printer-resolution-supported",
+        "sides-supported",
+        "printer-device-id",
+        "epcl-version-supported",
+        "pclm-raster-back-side",
+        "pclm-strip-height-preferred",
+        "pclm-compression-method-preferred",
+        "pclm-source-resolution-supported",
+        "pwg-raster-document-sheet-back",
+        "document-format-details-supported",
+        "media-ready",
+        "media-col-ready",
+        "print-scaling-supported",
+        "print-scaling-default",
+        "job-pages-per-set-supported",
+        "mopria-certified"
+};
+
+/*
+ * Requested printer attributes including printer info
+ */
+static const char *pattrs_printer_info[] = {
         "ipp-versions-supported",
         "printer-make-and-model",
         "printer-info",
@@ -73,7 +121,13 @@ static const char *pattrs[] = {
         "print-scaling-default",
         "job-pages-per-set-supported",
         "mopria-certified",
-        "mopria_certified"
+        "marker-colors",
+        "marker-high-levels",
+        "marker-levels",
+        "marker-low-levels",
+        "marker-names",
+        "marker-types",
+        "printer-icons"
 };
 
 static void _init(const ifc_printer_capabilities_t *this_p,
@@ -165,8 +219,14 @@ static status_t _get_capabilities(const ifc_printer_capabilities_t *this_p,
         ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL,
                 caps->printer_caps.printerUri);
 
-        ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes",
-                sizeof(pattrs) / sizeof(pattrs[0]), NULL, pattrs);
+        if (com_android_bips_flags_printer_info_details()) {
+            ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes",
+                          sizeof(pattrs_printer_info) / sizeof(pattrs_printer_info[0]), NULL,
+                          pattrs_printer_info);
+        } else {
+            ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes",
+                          sizeof(pattrs) / sizeof(pattrs[0]), NULL, pattrs);
+        }
 
         LOGD("IPP_GET_PRINTER_ATTRIBUTES %s request:", ippOpString(op));
         for (attrptr = ippFirstAttribute(request); attrptr; attrptr = ippNextAttribute(request)) {
diff --git a/jni/lib/lib_wprint.c b/jni/lib/lib_wprint.c
old mode 100755
new mode 100644
index c354c5d..4aab7ce
--- a/jni/lib/lib_wprint.c
+++ b/jni/lib/lib_wprint.c
@@ -31,6 +31,7 @@
 #include <pthread.h>
 
 #include <semaphore.h>
+#include <lib_wprint.h>
 #include <printer_capabilities_types.h>
 
 #include "ifc_print_job.h"
@@ -71,6 +72,7 @@
 #define MAX_IDLE_WAIT        (5 * 60)
 
 #define DEFAULT_RESOLUTION   (300)
+#define HIGH_RESOLUTION_PHOTO (600)
 
 // When searching for a supported resolution this is the max resolution we will consider.
 #define MAX_SUPPORTED_RESOLUTION (720)
@@ -1682,6 +1684,111 @@ status_t wprintGetCapabilities(const wprint_connect_info_t *connect_info,
     return result;
 }
 
+typedef struct _status_handle_st {
+    const ifc_status_monitor_t *status_ifc;
+    pthread_t status_tid;
+
+    void (*status_callback)(const printer_state_dyn_t *new_status,
+                            const printer_state_dyn_t *old_status,
+                            void *param);
+
+    void *param;
+} _status_handle_t;
+
+wStatus_t wprintStatusMonitorSetup(const wprint_connect_info_t *connect_info) {
+    const ifc_status_monitor_t *status_ifc;
+    int port_num = connect_info->port_num;
+    _status_handle_t *handle = NULL;
+    if (connect_info->printer_addr != NULL) {
+        status_ifc = _get_status_ifc(((port_num == 0) ? PORT_FILE : PORT_IPP));
+        if (status_ifc != NULL) {
+            handle = malloc(sizeof(_status_handle_t));
+            if (handle != NULL) {
+                handle->status_ifc = status_ifc;
+                handle->status_ifc->init(handle->status_ifc, connect_info);
+                handle->status_tid = pthread_self();
+                handle->param = NULL;
+            } else {
+                LOGE("wprintStatusMonitorSetup(): failed to allocate memory for status handle");
+                status_ifc->destroy(status_ifc);
+            }
+        }
+    }
+
+    return (wStatus_t) handle;
+}
+
+static void *_printer_status_thread(void *param) {
+    _status_handle_t *handle = (_status_handle_t *) param;
+    handle->status_ifc->start(handle->status_ifc, handle->status_callback, NULL, handle->param);
+    return (NULL);
+}
+
+static int _start_printer_status_thread(_status_handle_t *handle) {
+    sigset_t allsig, oldsig;
+    int result = ERROR;
+
+    if (handle == NULL)
+        return (result);
+
+    result = OK;
+    sigfillset(&allsig);
+#if CHECK_PTHREAD_SIGMASK_STATUS
+    result = pthread_sigmask(SIG_SETMASK, &allsig, &oldsig);
+#else /* else CHECK_PTHREAD_SIGMASK_STATUS */
+    pthread_sigmask(SIG_SETMASK, &allsig, &oldsig);
+#endif /* CHECK_PTHREAD_SIGMASK_STATUS */
+    if (result == OK) {
+        result = pthread_create(&handle->status_tid, 0, _printer_status_thread, handle);
+        if ((result == ERROR) && (handle->status_tid != pthread_self())) {
+#if USE_PTHREAD_CANCEL
+            pthread_cancel(handle->status_tid);
+#else /* else USE_PTHREAD_CANCEL */
+            pthread_kill(handle->status_tid, SIGKILL);
+#endif /* USE_PTHREAD_CANCEL */
+            handle->status_tid = pthread_self();
+        }
+    }
+
+    if (result == OK) {
+        sched_yield();
+#if CHECK_PTHREAD_SIGMASK_STATUS
+        result = pthread_sigmask(SIG_SETMASK, &oldsig, 0);
+#else /* else CHECK_PTHREAD_SIGMASK_STATUS */
+        pthread_sigmask(SIG_SETMASK, &oldsig, 0);
+#endif /* CHECK_PTHREAD_SIGMASK_STATUS */
+    }
+
+    return (result);
+} /*  _start_status_thread  */
+
+int wprintStatusMonitorStart(wStatus_t status_handle,
+                             void (*status_callback)(const printer_state_dyn_t *new_status,
+                                                     const printer_state_dyn_t *old_status,
+                                                     void *param),
+                             void *param) {
+    int result = ERROR;
+    _status_handle_t *handle = (_status_handle_t *) status_handle;
+    if (handle != NULL) {
+        handle->status_callback = status_callback;
+        handle->param = param;
+        result = _start_printer_status_thread(handle);
+    } else {
+        LOGE("wprintStatusMonitorStart(): status handle is NULL");
+    }
+    return result;
+}
+
+void wprintStatusMonitorStop(wStatus_t status_handle) {
+    _status_handle_t *handle = (_status_handle_t *) status_handle;
+    if (handle != NULL) {
+        handle->status_ifc->stop(handle->status_ifc);
+        pthread_join(handle->status_tid, 0);
+        handle->status_ifc->destroy(handle->status_ifc);
+        free(handle);
+    }
+}
+
 /*
  * Returns a preferred print format supported by the printer
  */
@@ -1732,7 +1839,7 @@ status_t wprintGetDefaultJobParams(wprint_job_params_t *job_params) {
             .borderless = false, .cancelled = false, .face_down_tray = false,
             .ipp_1_0_supported = false, .ipp_2_0_supported = false, .epcl_ipp_supported = false,
             .strip_height = STRIPE_HEIGHT, .docCategory = {0},
-            .copies_supported = false, .preserve_scaling = false};
+            .copies_supported = false, .print_at_scale = false};
 
     if (job_params == NULL) return result;
 
@@ -1801,6 +1908,11 @@ status_t wprintGetFinalJobParams(wprint_job_params_t *job_params,
     if (strcasecmp(job_params->docCategory, "photo") == 0 && int_array_contains(
             printer_cap->supportedQuality, printer_cap->numSupportedQuality, IPP_QUALITY_HIGH)) {
         job_params->print_quality = IPP_QUALITY_HIGH;
+    } else if (int_array_contains(printer_cap->supportedQuality, printer_cap->numSupportedQuality,
+            IPP_QUALITY_NORMAL)) {
+        job_params->print_quality = IPP_QUALITY_NORMAL;
+    } else {
+        job_params->print_quality = IPP_QUALITY_DRAFT;
     }
 
     // confirm that the media size is supported
@@ -1873,7 +1985,9 @@ status_t wprintGetFinalJobParams(wprint_job_params_t *job_params,
         job_params->render_flags |= AUTO_FIT_RENDER_FLAGS;
     }
 
-    job_params->pixel_units = _findCloseResolutionSupported(DEFAULT_RESOLUTION,
+    job_params->pixel_units = _findCloseResolutionSupported(
+            job_params->print_quality == IPP_QUALITY_HIGH ? HIGH_RESOLUTION_PHOTO
+                                                          : DEFAULT_RESOLUTION,
             MAX_SUPPORTED_RESOLUTION, printer_cap);
 
     printable_area_get_default_margins(job_params, printer_cap, &margins[TOP_MARGIN],
diff --git a/jni/lib/printable_area.c b/jni/lib/printable_area.c
index 701f34a..3c0f262 100755
--- a/jni/lib/printable_area.c
+++ b/jni/lib/printable_area.c
@@ -42,12 +42,8 @@ void printable_area_get(wprint_job_params_t *job_params, float top_margin,
         }
     }
 
-    // Threshold value for catering slight variation b/w source dims and page dims
-    const float PAGE_SIZE_EPSILON = 0.04f;
-    if (fabsf(job_params->source_width - job_params->page_width) < PAGE_SIZE_EPSILON &&
-        fabsf(job_params->source_height - job_params->page_height) < PAGE_SIZE_EPSILON) {
+    if (job_params->print_at_scale) {
         top_margin = left_margin = right_margin = bottom_margin = 0.0f;
-        job_params->preserve_scaling = true;
     }
 
     // don't adjust for margins if job is PCLm.  dimensions of image will not
@@ -156,19 +152,13 @@ void printable_area_get_default_margins(const wprint_job_params_t *job_params,
     } else {
         switch (job_params->pcl_type) {
             case PCLm:
+            case PCLPWG:
                 *top_margin = (float) printer_cap->printerTopMargin / 2540;
                 *bottom_margin = (float) printer_cap->printerBottomMargin / 2540;
                 *left_margin = (float) printer_cap->printerLeftMargin / 2540;
                 *right_margin = (float) printer_cap->printerRightMargin / 2540;
                 useDefaultMargins = false;
                 break;
-            case PCLPWG:
-                *top_margin = 0.0f;
-                *left_margin = 0.0f;
-                *right_margin = 0.0f;
-                *bottom_margin = 0.00f;
-                useDefaultMargins = false;
-                break;
             default:
                 break;
         }
diff --git a/jni/lib/wprintJNI.c b/jni/lib/wprintJNI.c
old mode 100755
new mode 100644
index 990d701..308cf34
--- a/jni/lib/wprintJNI.c
+++ b/jni/lib/wprintJNI.c
@@ -23,6 +23,7 @@
 #include <bits/strcasecmp.h>
 #include <string.h>
 #include "../plugins/wprint_mupdf.h"
+#include "com_android_bips_flags.h"
 
 #define TAG "wprintJNI"
 
@@ -66,7 +67,7 @@ static jfieldID _LocalJobParamsField__pdf_render_resolution;
 static jfieldID _LocalJobParamsField__source_width;
 static jfieldID _LocalJobParamsField__source_height;
 static jfieldID _LocalJobParamsField__shared_photo;
-static jfieldID _LocalJobParamsField__preserve_scaling;
+static jfieldID _LocalJobParamsField__print_at_scale;
 
 static jclass _LocalPrinterCapabilitiesClass;
 static jfieldID _LocalPrinterCapabilitiesField__name;
@@ -76,12 +77,25 @@ static jfieldID _LocalPrinterCapabilitiesField__location;
 static jfieldID _LocalPrinterCapabilitiesField__duplex;
 static jfieldID _LocalPrinterCapabilitiesField__borderless;
 static jfieldID _LocalPrinterCapabilitiesField__color;
+static jfieldID _LocalPrinterCapabilitiesField__printerTopMargin;
+static jfieldID _LocalPrinterCapabilitiesField__printerBottomMargin;
+static jfieldID _LocalPrinterCapabilitiesField__printerLeftMargin;
+static jfieldID _LocalPrinterCapabilitiesField__printerRightMargin;
 static jfieldID _LocalPrinterCapabilitiesField__isSupported;
 static jfieldID _LocalPrinterCapabilitiesField__mediaDefault;
 static jfieldID _LocalPrinterCapabilitiesField__supportedMediaTypes;
 static jfieldID _LocalPrinterCapabilitiesField__supportedMediaSizes;
 static jfieldID _LocalPrinterCapabilitiesField__nativeData;
 static jfieldID _LocalPrinterCapabilitiesField__certificate;
+static jfieldID _LocalPrinterCapabilitiesField__mediaReadySizes;
+static jfieldID _LocalPrinterCapabilitiesField__mopriaCertified;
+static jfieldID _LocalPrinterCapabilitiesField__markerNames;
+static jfieldID _LocalPrinterCapabilitiesField__markerTypes;
+static jfieldID _LocalPrinterCapabilitiesField__markerColors;
+static jfieldID _LocalPrinterCapabilitiesField__markerHighLevel;
+static jfieldID _LocalPrinterCapabilitiesField__markerLowLevel;
+static jfieldID _LocalPrinterCapabilitiesField__markerLevel;
+static jfieldID _LocalPrinterCapabilitiesField__mPrinterIconUris;
 
 static jclass _JobCallbackClass;
 static jobject _callbackReceiver;
@@ -90,6 +104,7 @@ static jmethodID _JobCallbackMethod__jobCallback;
 static jclass _JobCallbackParamsClass;
 static jmethodID _JobCallbackParamsMethod__init;
 static jfieldID _JobCallbackParamsField__jobId;
+static jfieldID _JobCallbackParamsField__printerState;
 static jfieldID _JobCallbackParamsField__jobState;
 static jfieldID _JobCallbackParamsField__jobDoneResult;
 static jfieldID _JobCallbackParamsField__blockedReasons;
@@ -98,6 +113,11 @@ static jfieldID _JobCallbackParamsField__certificate;
 static jclass _PrintServiceStringsClass;
 static jfieldID _PrintServiceStringsField__JOB_STATE_QUEUED;
 static jfieldID _PrintServiceStringsField__JOB_STATE_RUNNING;
+static jfieldID _PrintServiceStringsField__PRINTER_STATE_UNKNOWN;
+static jfieldID _PrintServiceStringsField__PRINTER_STATE_IDLE;
+static jfieldID _PrintServiceStringsField__PRINTER_STATE_RUNNING;
+static jfieldID _PrintServiceStringsField__PRINTER_STATE_UNABLE_TO_CONNECT;
+static jfieldID _PrintServiceStringsField__PRINTER_STATE_BLOCKED;
 static jfieldID _PrintServiceStringsField__JOB_STATE_BLOCKED;
 static jfieldID _PrintServiceStringsField__JOB_STATE_DONE;
 static jfieldID _PrintServiceStringsField__JOB_STATE_OTHER;
@@ -190,6 +210,9 @@ static jfieldID _PrintServiceStringField__JOB_FAIL_REASON__DOCUMENT_UNPRINTABLE_
 static jfieldID _PrintServiceStringField__JOB_FAIL_REASON__DOCUMENT_ACCESS_ERROR;
 static jfieldID _PrintServiceStringField__JOB_FAIL_REASON__SUBMISSION_INTERRUPTED;
 
+static jclass _WPrintPrinterStatusMonitorClass;
+static jmethodID _WPrintPrinterStatusMonitorMethod__callbackReceiver;
+
 // Global so it can be used in PDF render code
 JavaVM *_JVM = NULL;
 
@@ -503,8 +526,8 @@ static void _initJNI(JNIEnv *env, jobject callbackReceiver, jstring fakeDir) {
             "Z");
     _LocalJobParamsField__shared_photo = (*env)->GetFieldID(env, _LocalJobParamsClass,
             "shared_photo", "Z");
-    _LocalJobParamsField__preserve_scaling = (*env)->GetFieldID(env, _LocalJobParamsClass,
-            "preserve_scaling", "Z");
+    _LocalJobParamsField__print_at_scale = (*env)->GetFieldID(env, _LocalJobParamsClass,
+            "print_at_scale", "Z");
     _LocalJobParamsField__auto_rotate = (*env)->GetFieldID(env, _LocalJobParamsClass, "auto_rotate",
             "Z");
     _LocalJobParamsField__portrait_mode = (*env)->GetFieldID(env, _LocalJobParamsClass,
@@ -554,6 +577,14 @@ static void _initJNI(JNIEnv *env, jobject callbackReceiver, jstring fakeDir) {
             env, _LocalPrinterCapabilitiesClass, "borderless", "Z");
     _LocalPrinterCapabilitiesField__color = (*env)->GetFieldID(
             env, _LocalPrinterCapabilitiesClass, "color", "Z");
+    _LocalPrinterCapabilitiesField__printerTopMargin = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "printerTopMargin", "I");
+    _LocalPrinterCapabilitiesField__printerBottomMargin = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "printerBottomMargin", "I");
+    _LocalPrinterCapabilitiesField__printerLeftMargin = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "printerLeftMargin", "I");
+    _LocalPrinterCapabilitiesField__printerRightMargin = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "printerRightMargin", "I");
     _LocalPrinterCapabilitiesField__isSupported = (*env)->GetFieldID(
             env, _LocalPrinterCapabilitiesClass, "isSupported", "Z");
     _LocalPrinterCapabilitiesField__mediaDefault = (*env)->GetFieldID(
@@ -566,6 +597,32 @@ static void _initJNI(JNIEnv *env, jobject callbackReceiver, jstring fakeDir) {
             env, _LocalPrinterCapabilitiesClass, "nativeData", "[B");
     _LocalPrinterCapabilitiesField__certificate = (*env)->GetFieldID(
             env, _LocalPrinterCapabilitiesClass, "certificate", "[B");
+    _LocalPrinterCapabilitiesField__mediaReadySizes = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "mediaReadySizes", "[I");
+    _LocalPrinterCapabilitiesField__markerNames = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "markerNames", "[Ljava/lang/String;");
+    _LocalPrinterCapabilitiesField__markerTypes = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "markerTypes", "[Ljava/lang/String;");
+    _LocalPrinterCapabilitiesField__markerColors = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "markerColors", "[Ljava/lang/String;");
+    _LocalPrinterCapabilitiesField__markerHighLevel = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "markerHighLevel", "[I");
+    _LocalPrinterCapabilitiesField__markerLowLevel = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "markerLowLevel", "[I");
+    _LocalPrinterCapabilitiesField__markerLevel = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "markerLevel", "[I");
+    _LocalPrinterCapabilitiesField__mopriaCertified = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "mopriaCertified", "Ljava/lang/String;");
+    _LocalPrinterCapabilitiesField__mPrinterIconUris = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "mPrinterIconUris", "[Ljava/lang/String;");
+
+    if (com_android_bips_flags_printer_info_details()) {
+        _WPrintPrinterStatusMonitorClass = (jclass) (*env)->NewGlobalRef(env, (*env)->
+                FindClass(env, "com/android/bips/jni/PrinterStatusMonitor"));
+        _WPrintPrinterStatusMonitorMethod__callbackReceiver = (*env)->
+                GetMethodID(env, _WPrintPrinterStatusMonitorClass, "callbackReceiver",
+                            "(Lcom/android/bips/jni/JobCallbackParams;)V");
+    }
 
     _JobCallbackParamsClass = (jclass) (*env)->NewGlobalRef(env, (*env)->FindClass(
             env, "com/android/bips/jni/JobCallbackParams"));
@@ -573,6 +630,9 @@ static void _initJNI(JNIEnv *env, jobject callbackReceiver, jstring fakeDir) {
             "<init>", "()V");
     _JobCallbackParamsField__jobId = (*env)->GetFieldID(env, _JobCallbackParamsClass, "jobId",
             "I");
+    _JobCallbackParamsField__printerState = (*env)->GetFieldID(
+            env, _JobCallbackParamsClass, "printerState", "Ljava/lang/String;");
+
     _JobCallbackParamsField__jobState = (*env)->GetFieldID(
             env, _JobCallbackParamsClass, "jobState", "Ljava/lang/String;");
     _JobCallbackParamsField__jobDoneResult = (*env)->GetFieldID(
@@ -597,6 +657,18 @@ static void _initJNI(JNIEnv *env, jobject callbackReceiver, jstring fakeDir) {
 
     _PrintServiceStringsClass = (jclass) (*env)->NewGlobalRef(env, (*env)->FindClass(
             env, "com/android/bips/jni/BackendConstants"));
+    _PrintServiceStringsField__PRINTER_STATE_UNKNOWN = (*env)->GetStaticFieldID(
+            env, _PrintServiceStringsClass, "PRINTER_STATE_UNKNOWN", "Ljava/lang/String;");
+    _PrintServiceStringsField__PRINTER_STATE_IDLE = (*env)->GetStaticFieldID(
+            env, _PrintServiceStringsClass, "PRINTER_STATE_IDLE", "Ljava/lang/String;");
+    _PrintServiceStringsField__PRINTER_STATE_RUNNING = (*env)->GetStaticFieldID(
+            env, _PrintServiceStringsClass, "PRINTER_STATE_RUNNING", "Ljava/lang/String;");
+    _PrintServiceStringsField__PRINTER_STATE_UNABLE_TO_CONNECT = (*env)->GetStaticFieldID(
+            env, _PrintServiceStringsClass, "PRINTER_STATE_UNABLE_TO_CONNECT",
+            "Ljava/lang/String;");
+    _PrintServiceStringsField__PRINTER_STATE_BLOCKED = (*env)->GetStaticFieldID(
+            env, _PrintServiceStringsClass, "PRINTER_STATE_BLOCKED", "Ljava/lang/String;");
+
     _PrintServiceStringsField__JOB_STATE_QUEUED = (*env)->GetStaticFieldID(
             env, _PrintServiceStringsClass, "JOB_STATE_QUEUED", "Ljava/lang/String;");
     _PrintServiceStringsField__JOB_STATE_RUNNING = (*env)->GetStaticFieldID(
@@ -860,6 +932,14 @@ static int _convertPrinterCaps_to_Java(JNIEnv *env, jobject javaPrinterCaps,
             (jboolean) wprintPrinterCaps->borderless);
     (*env)->SetBooleanField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__color,
             (jboolean) wprintPrinterCaps->color);
+    (*env)->SetIntField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__printerTopMargin,
+            (jint) wprintPrinterCaps->printerTopMargin);
+    (*env)->SetIntField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__printerBottomMargin,
+            (jint) wprintPrinterCaps->printerBottomMargin);
+    (*env)->SetIntField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__printerLeftMargin,
+            (jint) wprintPrinterCaps->printerLeftMargin);
+    (*env)->SetIntField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__printerRightMargin,
+            (jint) wprintPrinterCaps->printerRightMargin);
     (*env)->SetBooleanField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__isSupported,
             (jboolean) wprintPrinterCaps->isSupported);
 
@@ -905,6 +985,98 @@ static int _convertPrinterCaps_to_Java(JNIEnv *env, jobject javaPrinterCaps,
         }
     }
 
+    if (com_android_bips_flags_printer_info_details()) {
+        stringToJava(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__mopriaCertified,
+                     wprintPrinterCaps->certification);
+
+        jstring jStr;
+        jobjectArray jPrinterIconArray =
+                (jobjectArray) (*env)->NewObjectArray(env, wprintPrinterCaps->num_printer_icons,
+                                                      (*env)->FindClass(env, "java/lang/String"),
+                                                      (*env)->NewStringUTF(env, ""));
+        for (index = 0; index < wprintPrinterCaps->num_printer_icons; index++) {
+            jStr = (*env)->NewStringUTF(env, wprintPrinterCaps->printer_icons[index]);
+            (*env)->SetObjectArrayElement(env, jPrinterIconArray, index, jStr);
+        }
+
+        (*env)->SetObjectField(env, javaPrinterCaps,
+                               _LocalPrinterCapabilitiesField__mPrinterIconUris,
+                               jPrinterIconArray);
+
+        jobjectArray jMarkerTypesArray =
+                (jobjectArray) (*env)->NewObjectArray(env, wprintPrinterCaps->marker_levels_count,
+                                                      (*env)->FindClass(env, "java/lang/String"),
+                                                      (*env)->NewStringUTF(env, ""));
+        for (index = 0; index < wprintPrinterCaps->marker_levels_count; index++) {
+            jStr = (*env)->NewStringUTF(env, wprintPrinterCaps->marker_types[index]);
+            (*env)->SetObjectArrayElement(env, jMarkerTypesArray, index, jStr);
+        }
+        (*env)->SetObjectField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__markerTypes,
+                               jMarkerTypesArray);
+
+        jobjectArray jMarkerNamesArray =
+                (jobjectArray) (*env)->NewObjectArray(env, wprintPrinterCaps->marker_levels_count,
+                                                      (*env)->FindClass(env, "java/lang/String"),
+                                                      (*env)->NewStringUTF(env, ""));
+        for (index = 0; index < wprintPrinterCaps->marker_levels_count; index++) {
+            jStr = (*env)->NewStringUTF(env, wprintPrinterCaps->marker_names[index]);
+            (*env)->SetObjectArrayElement(env, jMarkerNamesArray, index, jStr);
+        }
+        (*env)->SetObjectField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__markerNames,
+                               jMarkerNamesArray);
+
+        jobjectArray jMarkerColorsArray =
+                (jobjectArray) (*env)->NewObjectArray(env, wprintPrinterCaps->marker_levels_count,
+                                                      (*env)->FindClass(env, "java/lang/String"),
+                                                      (*env)->NewStringUTF(env, ""));
+        for (index = 0; index < wprintPrinterCaps->marker_levels_count; index++) {
+            jStr = (*env)->NewStringUTF(env, wprintPrinterCaps->marker_colors[index]);
+            (*env)->SetObjectArrayElement(env, jMarkerColorsArray, index, jStr);
+        }
+        (*env)->SetObjectField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__markerColors,
+                               jMarkerColorsArray);
+
+        intArray = (*env)->NewIntArray(env, wprintPrinterCaps->marker_levels_count);
+        intArrayPtr = (*env)->GetIntArrayElements(env, intArray, NULL);
+        for (index = 0; index < wprintPrinterCaps->marker_levels_count; index++) {
+            intArrayPtr[index] = (int) wprintPrinterCaps->marker_levels[index];
+        }
+        (*env)->ReleaseIntArrayElements(env, intArray, intArrayPtr, 0);
+        (*env)->SetObjectField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__markerLevel,
+                               intArray);
+        (*env)->DeleteLocalRef(env, intArray);
+
+        intArray = (*env)->NewIntArray(env, wprintPrinterCaps->marker_levels_count);
+        intArrayPtr = (*env)->GetIntArrayElements(env, intArray, NULL);
+        for (index = 0; index < wprintPrinterCaps->marker_levels_count; index++) {
+            intArrayPtr[index] = (int) wprintPrinterCaps->marker_low_levels[index];
+        }
+        (*env)->ReleaseIntArrayElements(env, intArray, intArrayPtr, 0);
+        (*env)->SetObjectField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__markerLowLevel,
+                               intArray);
+        (*env)->DeleteLocalRef(env, intArray);
+
+        intArray = (*env)->NewIntArray(env, wprintPrinterCaps->marker_levels_count);
+        intArrayPtr = (*env)->GetIntArrayElements(env, intArray, NULL);
+        for (index = 0; index < wprintPrinterCaps->marker_levels_count; index++) {
+            intArrayPtr[index] = (int) wprintPrinterCaps->marker_high_levels[index];
+        }
+        (*env)->ReleaseIntArrayElements(env, intArray, intArrayPtr, 0);
+        (*env)->SetObjectField(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__markerHighLevel,
+                               intArray);
+        (*env)->DeleteLocalRef(env, intArray);
+
+        intArray = (*env)->NewIntArray(env, wprintPrinterCaps->numSupportedMediaReadySizes);
+        intArrayPtr = (*env)->GetIntArrayElements(env, intArray, NULL);
+        for (index = 0; index < wprintPrinterCaps->numSupportedMediaReadySizes; index++) {
+            intArrayPtr[index] = (int) wprintPrinterCaps->supportedMediaReadySizes[index];
+        }
+        (*env)->ReleaseIntArrayElements(env, intArray, intArrayPtr, 0);
+        (*env)->SetObjectField(env, javaPrinterCaps,
+                               _LocalPrinterCapabilitiesField__mediaReadySizes, intArray);
+        (*env)->DeleteLocalRef(env, intArray);
+    }
+
     return OK;
 }
 
@@ -973,8 +1145,8 @@ static int _convertJobParams_to_C(JNIEnv *env, jobject javaJobParams,
             env, javaJobParams, _LocalJobParamsField__source_height);
     wprintJobParams->source_width = (float) (*env)->GetFloatField(
             env, javaJobParams, _LocalJobParamsField__source_width);
-    wprintJobParams->preserve_scaling = (bool) (*env)->GetBooleanField(env, javaJobParams,
-            _LocalJobParamsField__preserve_scaling);
+    wprintJobParams->print_at_scale = (bool) (*env)->GetBooleanField(env, javaJobParams,
+            _LocalJobParamsField__print_at_scale);
 
     if ((*env)->GetBooleanField(env, javaJobParams, _LocalJobParamsField__portrait_mode)) {
         wprintJobParams->render_flags |= RENDER_FLAG_PORTRAIT_MODE;
@@ -1128,8 +1300,8 @@ static int _covertJobParams_to_Java(JNIEnv *env, jobject javaJobParams,
             (wprintJobParams->render_flags & RENDER_FLAG_PORTRAIT_MODE) != 0));
     (*env)->SetBooleanField(env, javaJobParams, _LocalJobParamsField__landscape_mode, (jboolean) (
             (wprintJobParams->render_flags & RENDER_FLAG_LANDSCAPE_MODE) != 0));
-    (*env)->SetBooleanField(env, javaJobParams, _LocalJobParamsField__preserve_scaling,
-            (jboolean) (wprintJobParams->preserve_scaling));
+    (*env)->SetBooleanField(env, javaJobParams, _LocalJobParamsField__print_at_scale,
+            (jboolean) (wprintJobParams->print_at_scale));
 
     // update the printable area & DPI information
     (*env)->SetIntField(env, javaJobParams, _LocalJobParamsField__print_resolution,
@@ -1737,6 +1909,151 @@ JNIEXPORT jint JNICALL Java_com_android_bips_ipp_Backend_nativeGetCapabilities(
     return result;
 }
 
+/*
+ * JNI call to wprint to get Status of Printer.
+ */
+JNIEXPORT jlong JNICALL
+Java_com_android_bips_ipp_Backend_nativeMonitorStatusSetup(JNIEnv *env, jobject obj,
+                                                           jstring address, jint port,
+                                                           jstring httpResource,
+                                                           jstring uriScheme) {
+    LOGI("nativeMonitorStatusSetup, JNIenv is %p", env);
+    wStatus_t status_handle;
+    wprint_connect_info_t connect_info = {0};
+
+    connect_info.printer_addr = (*env)->GetStringUTFChars(env, address, NULL);
+    connect_info.uri_path = ((httpResource != NULL) ? (*env)->GetStringUTFChars(env, httpResource,
+                                                                                NULL) : NULL);
+    connect_info.uri_scheme = ((uriScheme != NULL) ? (*env)->GetStringUTFChars(env, uriScheme, NULL)
+                                                   : NULL);
+    connect_info.port_num = port;
+    status_handle = wprintStatusMonitorSetup(&connect_info);
+    (*env)->ReleaseStringUTFChars(env, address, connect_info.printer_addr);
+    if (httpResource != NULL) {
+        (*env)->ReleaseStringUTFChars(env, httpResource, connect_info.uri_path);
+    }
+    if (uriScheme != NULL) {
+        (*env)->ReleaseStringUTFChars(env, uriScheme, connect_info.uri_scheme);
+    }
+
+    return (jlong) status_handle;
+}
+
+static jobject _process_printer_status(JNIEnv *env, const printer_state_dyn_t *printer_status) {
+    jobject statusObj = (*env)->NewObject(env, _JobCallbackParamsClass,
+                                          _JobCallbackParamsMethod__init);
+    if (statusObj != NULL) {
+        print_status_t statusnew;
+        unsigned int i, count;
+        unsigned long long blocked_reasons;
+        jstring jStr;
+
+        statusnew = printer_status->printer_status & ~PRINTER_IDLE_BIT;
+
+        count = blocked_reasons = 0;
+        for (count = i = 0; i < PRINT_STATUS_MAX_STATE; i++) {
+            if (printer_status->printer_reasons[i] == PRINT_STATUS_MAX_STATE)
+                break;
+            if ((blocked_reasons & (LONG_ONE << printer_status->printer_reasons[i])) == 0) {
+                count++;
+                blocked_reasons |= (LONG_ONE << printer_status->printer_reasons[i]);
+            }
+        }
+
+        if (count > 0) {
+            jobjectArray stringArray = processBlockStatus(env, blocked_reasons, count);
+            (*env)->SetObjectField(env, statusObj, _JobCallbackParamsField__blockedReasons,
+                                   stringArray);
+            (*env)->DeleteLocalRef(env, stringArray);
+        }
+
+        switch (statusnew) {
+            case PRINT_STATUS_UNKNOWN:
+                jStr = (jstring) (*env)->GetStaticObjectField(env, _PrintServiceStringsClass,
+                                                              _PrintServiceStringsField__PRINTER_STATE_UNKNOWN);
+                break;
+            case PRINT_STATUS_IDLE:
+                jStr = (jstring) (*env)->GetStaticObjectField(env, _PrintServiceStringsClass,
+                                                              _PrintServiceStringsField__PRINTER_STATE_IDLE);
+                break;
+            case PRINT_STATUS_CANCELLED:
+            case PRINT_STATUS_PRINTING:
+                jStr = (jstring) (*env)->GetStaticObjectField(env, _PrintServiceStringsClass,
+                                                              _PrintServiceStringsField__PRINTER_STATE_RUNNING);
+                break;
+            case PRINT_STATUS_UNABLE_TO_CONNECT:
+                jStr = (jstring) (*env)->GetStaticObjectField(env, _PrintServiceStringsClass,
+                                                              _PrintServiceStringsField__PRINTER_STATE_UNABLE_TO_CONNECT);
+                break;
+            default:
+                jStr = (jstring) (*env)->GetStaticObjectField(env, _PrintServiceStringsClass,
+                                                              _PrintServiceStringsField__PRINTER_STATE_BLOCKED);
+                break;
+        }
+        (*env)->SetObjectField(env, statusObj, _JobCallbackParamsField__printerState, jStr);
+    }
+    return statusObj;
+}
+
+static void _printer_status_callback(const printer_state_dyn_t *new_status,
+                                     const printer_state_dyn_t *old_status,
+                                     void *param) {
+    int needDetach = 0;
+    JNIEnv *env;
+    if ((*_JVM)->GetEnv(_JVM, (void **) &env, JNI_VERSION_1_6) < 0) {
+        needDetach = 1;
+        if ((*_JVM)->AttachCurrentThread(_JVM, &env, NULL) < 0)
+            return;
+    }
+
+    jobject receiver = (jobject) param;
+    if (new_status->printer_status == PRINT_STATUS_UNKNOWN) {
+        if (new_status->printer_reasons[0] == PRINT_STATUS_INITIALIZING) {
+            receiver = NULL;
+        } else if (new_status->printer_reasons[0] == PRINT_STATUS_SHUTTING_DOWN) {
+            if (receiver != NULL) {
+                (*env)->DeleteGlobalRef(env, receiver);
+            }
+            receiver = NULL;
+        }
+    }
+
+    if (receiver != NULL) {
+        jobject statusObj = _process_printer_status(env, new_status);
+        (*env)->CallVoidMethod(env, receiver, _WPrintPrinterStatusMonitorMethod__callbackReceiver,
+                               statusObj);
+    }
+
+    if (needDetach)
+        (*_JVM)->DetachCurrentThread(_JVM);
+}
+
+JNIEXPORT void JNICALL
+Java_com_android_bips_ipp_Backend_nativeMonitorStatusStart(JNIEnv *env, jobject obj, jlong statusID,
+                                                           jobject receiver) {
+    LOGI("nativeMonitorStatusStart, JNIenv is %p", env);
+    wStatus_t status_handle = (wStatus_t) statusID;
+    if (status_handle != 0) {
+        if (receiver != NULL) {
+            receiver = (*env)->NewGlobalRef(env, receiver);
+        }
+        if (wprintStatusMonitorStart(status_handle, _printer_status_callback, receiver) != OK) {
+            if (receiver != NULL) {
+                (*env)->DeleteGlobalRef(env, receiver);
+            }
+        }
+    }
+}
+
+JNIEXPORT void JNICALL
+Java_com_android_bips_ipp_Backend_nativeMonitorStatusStop(JNIEnv *env, jobject obj,
+                                                          jlong statusID) {
+    LOGI("nativeMonitorStatusStop, JNIenv is %p", env);
+    wStatus_t status_handle = (wStatus_t) statusID;
+    if (status_handle != 0) {
+        wprintStatusMonitorStop(status_handle);
+    }
+}
 /*
  * JNI call to wprint to get default job params. Returns job params converted to java.
  */
@@ -1881,7 +2198,7 @@ JNIEXPORT jint JNICALL Java_com_android_bips_ipp_Backend_nativeStartJob(
         bool shared_photo = (*env)->GetBooleanField(env, jobParams,
                                                     _LocalJobParamsField__shared_photo);
         bool preserve_scaling = (*env)->GetBooleanField(env, jobParams,
-                                                        _LocalJobParamsField__preserve_scaling);
+                                                        _LocalJobParamsField__print_at_scale);
         LOGD("setting print-scaling job param");
         LOGD("shared_photo = %d", shared_photo);
         LOGD("preserve_scaling = %d", preserve_scaling);
@@ -1898,18 +2215,12 @@ JNIEXPORT jint JNICALL Java_com_android_bips_ipp_Backend_nativeStartJob(
                     }
                 }
             } else {
-                bool auto_supported = false;
-                for (int i = 0; i < caps.print_scalings_supported_count; i++) {
-                    if (strcmp(caps.print_scalings_supported[i], "auto") == 0) {
-                        strlcpy(print_scaling, "auto", sizeof(print_scaling));
-                        auto_supported = true;
-                        break;
-                    }
-                }
-                if (!auto_supported) {
-                    if (strcmp(caps.print_scaling_default, "") != 0) {
-                        strlcpy(print_scaling, caps.print_scaling_default,
-                                sizeof(caps.print_scaling_default));
+                if (strcmp(caps.print_scaling_default, "") != 0) {
+                    strlcpy(print_scaling, caps.print_scaling_default,
+                            sizeof(caps.print_scaling_default));
+                } else {
+                    if (is_photo) {
+                        strlcpy(print_scaling, "fill", sizeof(print_scaling));
                     } else {
                         strlcpy(print_scaling, "fit", sizeof(print_scaling));
                     }
@@ -2034,6 +2345,9 @@ JNIEXPORT jint JNICALL Java_com_android_bips_ipp_Backend_nativeExit(JNIEnv *env,
     if (_PrintServiceStringsClass) {
         (*env)->DeleteGlobalRef(env, _PrintServiceStringsClass);
     }
+    if (_WPrintPrinterStatusMonitorClass) {
+        (*env)->DeleteGlobalRef(env, _WPrintPrinterStatusMonitorClass);
+    }
 
     pdf_render_deinit(env);
     return wprintExit();
diff --git a/jni/plugins/plugin_pcl.c b/jni/plugins/plugin_pcl.c
index 8b4a9c7..55c333f 100755
--- a/jni/plugins/plugin_pcl.c
+++ b/jni/plugins/plugin_pcl.c
@@ -350,7 +350,7 @@ static status_t _setup_image_info(wprint_job_params_t *job_params, wprint_image_
                 job_params->print_top_margin, job_params->print_left_margin,
                 job_params->print_right_margin, job_params->print_bottom_margin,
                 job_params->render_flags, job_params->strip_height, MAX_SEND_BUFFS,
-                image_padding);
+                image_padding, job_params->pcl_type);
     } else {
         LOGE("_setup_image_info(): file does not appear to be valid");
         result = CORRUPT;
diff --git a/jni/plugins/wprint_image.c b/jni/plugins/wprint_image.c
index 8d249ac..617b518 100755
--- a/jni/plugins/wprint_image.c
+++ b/jni/plugins/wprint_image.c
@@ -86,7 +86,7 @@ status_t wprint_image_set_output_properties(wprint_image_info_t *image_info,
         wprint_rotation_t rotation, unsigned int printable_width, unsigned int printable_height,
         unsigned int top_margin, unsigned int left_margin, unsigned int right_margin,
         unsigned int bottom_margin, unsigned int render_flags, unsigned int max_decode_stripe,
-        unsigned int concurrent_stripes, unsigned int padding_options) {
+        unsigned int concurrent_stripes, unsigned int padding_options, pcl_t pclenum) {
     // validate rotation
     switch (rotation) {
         default:
@@ -120,8 +120,14 @@ status_t wprint_image_set_output_properties(wprint_image_info_t *image_info,
     image_info->padding_options = (padding_options & PAD_ALL);
 
     // store margin adjusted printable area
-    image_info->printable_width = printable_width - (left_margin + right_margin);
-    image_info->printable_height = printable_height - (top_margin + bottom_margin);
+    if (pclenum == PCLPWG) {
+        // no need to adjust the margins again for PWG raster
+        image_info->printable_width = printable_width;
+        image_info->printable_height = printable_height;
+    } else {
+        image_info->printable_width = printable_width - (left_margin + right_margin);
+        image_info->printable_height = printable_height - (top_margin + bottom_margin);
+    }
 
     // store rendering parameters
     image_info->render_flags = render_flags;
@@ -288,8 +294,7 @@ status_t wprint_image_set_output_properties(wprint_image_info_t *image_info,
             (image_info->render_flags & RENDER_FLAG_DOCUMENT_SCALING)) {
         LOGD("checking native document scaling factor");
         if ((native_image_output_height <= image_info->printable_height)
-                && (native_image_output_width <= image_output_width
-                        <= image_info->printable_width)) {
+                && (native_image_output_width <= image_info->printable_width)) {
             LOGD("fit in printable area, just scale to native units");
             image_info->render_flags &= ~(RENDER_FLAG_AUTO_SCALE | RENDER_FLAG_AUTO_FIT);
         } else {
diff --git a/jni/plugins/wprint_image.h b/jni/plugins/wprint_image.h
index e03b9a4..4b29d8e 100755
--- a/jni/plugins/wprint_image.h
+++ b/jni/plugins/wprint_image.h
@@ -60,6 +60,7 @@ typedef enum {
 #define __DEFINE_WPRINT_PLATFORM_TYPES__
 
 #include "wprint_image_platform.h"
+#include "lib_wprint.h"
 
 #undef __DEFINE_WPRINT_PLATFORM_TYPES__
 
@@ -187,7 +188,7 @@ status_t wprint_image_set_output_properties(wprint_image_info_t *image_info,
         wprint_rotation_t rotation, unsigned int printable_width, unsigned int printable_height,
         unsigned int top_margin, unsigned int left_margin, unsigned int right_margin,
         unsigned int bottom_margin, unsigned int render_flags, unsigned int max_decode_stripe,
-        unsigned int concurrent_stripes, unsigned int padding_options);
+        unsigned int concurrent_stripes, unsigned int padding_options, pcl_t pclenum);
 
 /*
  * Return true if the image is wider than it is high (landscape orientation)
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/drawable/ic_info.xml b/res/flag(com.android.bips.flags.printer_info_details)/drawable/ic_info.xml
new file mode 100644
index 0000000..efa1020
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/drawable/ic_info.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+     Copyright (C) 2024 Mopria Alliance, Inc.
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+android:width="24dp"
+android:height="24dp"
+android:viewportWidth="960"
+android:viewportHeight="960"
+android:tint="?attr/colorControlNormal">
+<path
+    android:fillColor="?android:attr/textColorPrimary"
+    android:pathData="M440,680L520,680L520,440L440,440L440,680ZM480,360Q497,360 508.5,348.5Q520,337 520,320Q520,303 508.5,291.5Q497,280 480,280Q463,280 451.5,291.5Q440,303 440,320Q440,337 451.5,348.5Q463,360 480,360ZM480,880Q397,880 324,848.5Q251,817 197,763Q143,709 111.5,636Q80,563 80,480Q80,397 111.5,324Q143,251 197,197Q251,143 324,111.5Q397,80 480,80Q563,80 636,111.5Q709,143 763,197Q817,251 848.5,324Q880,397 880,480Q880,563 848.5,636Q817,709 763,763Q709,817 636,848.5Q563,880 480,880ZM480,800Q614,800 707,707Q800,614 800,480Q800,346 707,253Q614,160 480,160Q346,160 253,253Q160,346 160,480Q160,614 253,707Q346,800 480,800ZM480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Z"/>
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/drawable/ic_supply_marker_warning.xml b/res/flag(com.android.bips.flags.printer_info_details)/drawable/ic_supply_marker_warning.xml
new file mode 100644
index 0000000..8316dca
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/drawable/ic_supply_marker_warning.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+     Copyright (C) 2024 Mopria Alliance, Inc.
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:tint="?attr/colorControlNormal"
+    android:viewportHeight="960"
+    android:viewportWidth="960">
+    <path
+        android:fillColor="?android:colorAccent"
+        android:pathData="M480,680Q497,680 508.5,668.5Q520,657 520,640Q520,623 508.5,611.5Q497,600 480,600Q463,600 451.5,611.5Q440,623 440,640Q440,657 451.5,668.5Q463,680 480,680ZM440,520L520,520L520,280L440,280L440,520ZM480,880Q397,880 324,848.5Q251,817 197,763Q143,709 111.5,636Q80,563 80,480Q80,397 111.5,324Q143,251 197,197Q251,143 324,111.5Q397,80 480,80Q563,80 636,111.5Q709,143 763,197Q817,251 848.5,324Q880,397 880,480Q880,563 848.5,636Q817,709 763,763Q709,817 636,848.5Q563,880 480,880ZM480,800Q614,800 707,707Q800,614 800,480Q800,346 707,253Q614,160 480,160Q346,160 253,253Q160,346 160,480Q160,614 253,707Q346,800 480,800ZM480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Q480,480 480,480Z" />
+</vector>
\ No newline at end of file
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/drawable/supply_marker_shape.xml b/res/flag(com.android.bips.flags.printer_info_details)/drawable/supply_marker_shape.xml
new file mode 100644
index 0000000..deee6fc
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/drawable/supply_marker_shape.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+     Copyright (C) 2024 Mopria Alliance, Inc.
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+          http://www.apache.org/licenses/LICENSE-2.0
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:id="@+id/background">
+        <shape android:shape="rectangle">
+            <corners android:radius="@dimen/corner_radius" />
+            <solid android:color="@android:color/darker_gray" />
+        </shape>
+    </item>
+    <item android:id="@+id/progress">
+        <clip>
+            <scale android:scaleWidth="100%">
+                <shape android:shape="rectangle">
+                    <corners android:radius="@dimen/corner_radius" />
+                    <solid android:color="?android:colorAccent" />
+                </shape>
+            </scale>
+        </clip>
+    </item>
+</layer-list>
\ No newline at end of file
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/layout/combined_info_recs.xml b/res/flag(com.android.bips.flags.printer_info_details)/layout/combined_info_recs.xml
new file mode 100644
index 0000000..3ad1ef7
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/layout/combined_info_recs.xml
@@ -0,0 +1,88 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+     Copyright (C) 2024 Mopria Alliance, Inc.
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
+<ScrollView xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content">
+
+    <androidx.constraintlayout.widget.ConstraintLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content">
+
+        <FrameLayout
+            android:id="@+id/fragment_container"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+
+        <LinearLayout
+            android:id="@+id/ll_recommended_services"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginTop="@dimen/mopria_padding_18dp"
+            android:gravity="center_vertical"
+            android:minHeight="40dip"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintTop_toBottomOf="@id/fragment_container">
+
+            <TextView
+                style="@style/TextAppearance.AppCompat.Subhead"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:drawableLeft="@drawable/ic_menu_add"
+                android:drawablePadding="@dimen/mopria_padding_2dp"
+                android:maxLines="1"
+                android:padding="@dimen/mopria_padding_5dp"
+                android:text="@string/recommendation_link"
+                android:textAppearance="?android:attr/textAppearanceListItem"
+                android:textColor="?android:attr/colorAccent" />
+        </LinearLayout>
+
+        <LinearLayout
+            android:id="@+id/ll_recommended_services_summary"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginTop="@dimen/mopria_padding_12dp"
+            android:orientation="vertical"
+            android:padding="@dimen/mopria_padding_5dp"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintTop_toBottomOf="@id/ll_recommended_services">
+
+            <ImageView
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:padding="@dimen/mopria_padding_5dp"
+                android:src="@drawable/ic_info" />
+
+            <TextView
+                style="@style/TextAppearance.AppCompat.Subhead"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_marginTop="@dimen/mopria_padding_5dp"
+                android:drawablePadding="@dimen/mopria_padding_2dp"
+                android:padding="@dimen/mopria_padding_5dp"
+                android:text="@string/recommendation_summary_new"
+                android:textAppearance="?android:attr/textAppearanceListItem"
+                android:textColor="?android:attr/textColorPrimary" />
+        </LinearLayout>
+    </androidx.constraintlayout.widget.ConstraintLayout>
+
+</ScrollView>
\ No newline at end of file
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/layout/item_marker_type.xml b/res/flag(com.android.bips.flags.printer_info_details)/layout/item_marker_type.xml
new file mode 100644
index 0000000..c4f6c73
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/layout/item_marker_type.xml
@@ -0,0 +1,54 @@
+<?xml version="1.0" encoding="utf-8"?><!--
+     Copyright (C) 2024 The Android Open Source Project
+     Copyright (C) 2024 Mopria Alliance, Inc.
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:gravity="center"
+    android:orientation="horizontal"
+    android:paddingTop="@dimen/mopria_padding_12dp"
+    android:weightSum="100">
+
+    <RelativeLayout
+        android:layout_width="@dimen/mopria_width_0_dp"
+        android:layout_height="@dimen/marker_item_height"
+        android:layout_weight="80">
+
+        <ProgressBar
+            android:id="@+id/seekbar"
+            style="@style/Widget.AppCompat.ProgressBar.Horizontal"
+            android:layout_height="@dimen/marker_item_height"
+            android:layout_width="match_parent"
+            android:layout_centerInParent="true"
+            android:layout_marginStart="@dimen/mopria_margin_1dp"
+            android:layout_marginEnd="@dimen/mopria_margin_1dp"
+            android:max="100"
+            android:progressDrawable="@drawable/supply_marker_shape"
+            android:minHeight="@dimen/marker_item_height"/>
+    </RelativeLayout>
+
+    <ImageView
+        android:id="@+id/warningImage"
+        android:layout_width="@dimen/mopria_width_0_dp"
+        android:layout_height="wrap_content"
+        android:layout_weight="20"
+        android:contentDescription="@null"
+        android:gravity="center"
+        android:padding="@dimen/mopria_margin_1dp"
+        android:src="@drawable/ic_supply_marker_warning"
+        android:visibility="invisible" />
+</LinearLayout>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/layout/printer_information.xml b/res/flag(com.android.bips.flags.printer_info_details)/layout/printer_information.xml
new file mode 100644
index 0000000..105e2da
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/layout/printer_information.xml
@@ -0,0 +1,136 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+     Copyright (C) 2024 Mopria Alliance, Inc.
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
+<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="vertical"
+    android:paddingEnd="@dimen/mopria_padding_10dp"
+    android:paddingStart="@dimen/mopria_padding_10dp">
+
+    <TextView
+        android:id="@+id/printerNameLabel"
+        style="@style/TextAppearance.AppCompat.Medium"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="@dimen/mopria_padding_18dp"
+        android:textColor="?android:attr/textColorPrimary"
+        android:text="@string/printer_name"
+        app:layout_constraintLeft_toLeftOf="parent"
+        app:layout_constraintTop_toBottomOf="@+id/printerIcon" />
+
+    <TextView
+        android:id="@+id/printerName"
+        style="@style/TextAppearance.AppCompat.Small"
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_marginEnd="@dimen/mopria_padding_10dp"
+        android:textColor="?android:attr/textColorSecondary"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintTop_toBottomOf="@+id/printerNameLabel" />
+
+    <TextView
+        android:id="@+id/mediaReadyLabel"
+        style="@style/TextAppearance.AppCompat.Medium"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="@dimen/mopria_padding_18dp"
+        android:textColor="?android:attr/textColorPrimary"
+        android:text="@string/media_ready"
+        app:layout_constraintLeft_toLeftOf="parent"
+        app:layout_constraintTop_toBottomOf="@id/printerStatusLayout" />
+
+    <TextView
+        android:id="@+id/mediaReady"
+        style="@style/TextAppearance.AppCompat.Small"
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_marginEnd="@dimen/mopria_padding_10dp"
+        android:textColor="?android:attr/textColorSecondary"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintTop_toBottomOf="@+id/mediaReadyLabel" />
+
+    <TextView
+        android:id="@+id/inkLevelsLabel"
+        style="@style/TextAppearance.AppCompat.Medium"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="@dimen/mopria_padding_18dp"
+        android:textColor="?android:attr/textColorPrimary"
+        android:text="@string/supply_levels"
+        app:layout_constraintLeft_toLeftOf="parent"
+        app:layout_constraintTop_toBottomOf="@+id/mediaReady" />
+
+    <androidx.appcompat.widget.AppCompatImageView
+        android:id="@+id/printerIcon"
+        android:layout_width="142dp"
+        android:layout_height="142dp"
+        android:layout_margin="@dimen/mopria_padding_10dp"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintTop_toTopOf="parent" />
+
+    <androidx.constraintlayout.widget.ConstraintLayout
+        android:id="@+id/printerStatusLayout"
+        android:layout_width="0dp"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="@dimen/mopria_padding_18dp"
+        app:layout_constraintEnd_toEndOf="parent"
+        app:layout_constraintStart_toStartOf="parent"
+        app:layout_constraintTop_toBottomOf="@id/printerName">
+
+        <ProgressBar
+            android:id="@+id/progressBarPrinterStatus"
+            style="?android:attr/progressBarStyleHorizontal"
+            android:layout_width="@dimen/linear_progress_bar_width"
+            android:layout_height="@dimen/linear_progress_bar_height"
+            android:indeterminate="true"
+            app:layout_constraintLeft_toLeftOf="parent"
+            app:layout_constraintTop_toBottomOf="@id/printerStatusLabel" />
+
+        <TextView
+            android:id="@+id/printerStatus"
+            style="@style/TextAppearance.AppCompat.Small"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_marginEnd="@dimen/mopria_padding_10dp"
+            android:textColor="?android:attr/textColorSecondary"
+            app:layout_constraintEnd_toEndOf="parent"
+            app:layout_constraintStart_toStartOf="parent"
+            app:layout_constraintTop_toBottomOf="@id/printerStatusLabel" />
+
+        <TextView
+            android:id="@+id/printerStatusLabel"
+            style="@style/TextAppearance.AppCompat.Medium"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:text="@string/status"
+            android:textColor="?android:attr/textColorPrimary"
+            app:layout_constraintLeft_toLeftOf="parent"
+            app:layout_constraintTop_toTopOf="parent" />
+    </androidx.constraintlayout.widget.ConstraintLayout>
+
+    <androidx.recyclerview.widget.RecyclerView
+        android:id="@+id/inkLevelsRecyclerView"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        app:layout_constraintLeft_toLeftOf="parent"
+        app:layout_constraintTop_toBottomOf="@id/inkLevelsLabel" />
+
+</androidx.constraintlayout.widget.ConstraintLayout>
\ No newline at end of file
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-af/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-af/strings.xml
new file mode 100644
index 0000000..32450ed
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-af/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Die verstekdrukdiens verskaf basiese opsies. Bykomende drukdienste is beskikbaar vir gevorderde opsies."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Bykomende drukdienste"</string>
+    <string name="yes" msgid="1887141030777316285">"Ja"</string>
+    <string name="unknown" msgid="2526777102391303730">"Onbekend"</string>
+    <string name="printer_name" msgid="386653719801075739">"Drukkernaam"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Gelaaide papiergroottes"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Voorraadvlakke"</string>
+    <string name="information" msgid="7896978544179559432">"Inligting"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Gereed"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Drukwerk"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Vanlyn"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Gaan drukker na"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-am/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-am/strings.xml
new file mode 100644
index 0000000..1fa605f
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-am/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ነባሪው የህትመት አገልግሎት መሠረታዊ አማራጮችን ያቀርባል። ለላቁ አማራጮች ተጨማሪ የህትመት አገልግሎቶች ይገኛሉ።"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"ተጨማሪ የህትመት አገልግሎት"</string>
+    <string name="yes" msgid="1887141030777316285">"አዎ"</string>
+    <string name="unknown" msgid="2526777102391303730">"ያልታወቀ"</string>
+    <string name="printer_name" msgid="386653719801075739">"የአታሚ ስም"</string>
+    <string name="status" msgid="5948149021115901261">"ሁኔታ"</string>
+    <string name="media_ready" msgid="7205545458156298899">"የተጫኑ የወረቀት መጠኖች"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"የአቅርቦት ደረጃዎች"</string>
+    <string name="information" msgid="7896978544179559432">"መረጃ"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"ዝግጁ"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"በማተም ላይ"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ከመስመር ውጭ"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"አታሚን ይፈትሹ"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ar/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ar/strings.xml
new file mode 100644
index 0000000..c7e7a26
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ar/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"توفِّر خدمة الطباعة التلقائية خيارات أساسية. وتتوفّر خدمات طباعة إضافية للخيارات المتقدّمة."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"خدمات طباعة إضافية"</string>
+    <string name="yes" msgid="1887141030777316285">"نعم"</string>
+    <string name="unknown" msgid="2526777102391303730">"غير معروف"</string>
+    <string name="printer_name" msgid="386653719801075739">"اسم الطابعة"</string>
+    <string name="status" msgid="5948149021115901261">"الحالة"</string>
+    <string name="media_ready" msgid="7205545458156298899">"أحجام الورق الذي تم تحميله"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"مستويات الإمداد"</string>
+    <string name="information" msgid="7896978544179559432">"معلومات"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"جاهزة للاستخدام"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"جارٍ الطباعة"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"غير متصلة بالإنترنت"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"يُرجى التحقّق من الطابعة"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-as/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-as/strings.xml
new file mode 100644
index 0000000..c000503
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-as/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ডিফ’ল্ট প্ৰিণ্ট সেৱাটোৱে সাধাৰণ বিকল্পসমূহ প্ৰদান কৰে। উচ্চখাপৰ বিকল্পৰ বাবে অতিৰিক্ত প্ৰিণ্ট সেৱা উপলব্ধ।"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"অতিৰিক্ত প্ৰিণ্ট সেৱা"</string>
+    <string name="yes" msgid="1887141030777316285">"হয়"</string>
+    <string name="unknown" msgid="2526777102391303730">"অজ্ঞাত"</string>
+    <string name="printer_name" msgid="386653719801075739">"প্ৰিণ্টাৰৰ নাম"</string>
+    <string name="status" msgid="5948149021115901261">"স্থিতি"</string>
+    <string name="media_ready" msgid="7205545458156298899">"ল’ড কৰা পেপাৰৰ আকাৰ"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"যোগানৰ স্তৰ"</string>
+    <string name="information" msgid="7896978544179559432">"তথ্য"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"সাজু"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"প্ৰিণ্ট কৰি থকা হৈছে"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"অফলাইন"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"প্ৰিণ্টাৰ পৰীক্ষা কৰক"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-az/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-az/strings.xml
new file mode 100644
index 0000000..e34dcbc
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-az/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Defolt çap xidməti sadə seçimlər təmin edir. Təkmil seçimlər üçün əlavə çap xidmətləri əlçatandır."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Əlavə çap xidmətləri"</string>
+    <string name="yes" msgid="1887141030777316285">"Bəli"</string>
+    <string name="unknown" msgid="2526777102391303730">"Naməlum"</string>
+    <string name="printer_name" msgid="386653719801075739">"Printer adı"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Yüklənən kağız ölçüləri"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Təchizat səviyyələri"</string>
+    <string name="information" msgid="7896978544179559432">"Məlumat"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Hazır"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Çap"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Oflayn"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Printeri yoxlayın"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-b+sr+Latn/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-b+sr+Latn/strings.xml
new file mode 100644
index 0000000..ce87235
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-b+sr+Latn/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Podrazumevana usluga štampanja pruža osnovne opcije. Za napredne opcije su dostupne dodatne usluge štampanja."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Dodatne usluge štampanja"</string>
+    <string name="yes" msgid="1887141030777316285">"Da"</string>
+    <string name="unknown" msgid="2526777102391303730">"Nepoznato"</string>
+    <string name="printer_name" msgid="386653719801075739">"Naziv štampača"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Umetnute veličine papira"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Nivoi zaliha"</string>
+    <string name="information" msgid="7896978544179559432">"Informacije"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Spremno"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Štampanje"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Oflajn"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Proverite štampač"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-be/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-be/strings.xml
new file mode 100644
index 0000000..0a8bceb
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-be/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Стандартны сэрвіс друку забяспечвае асноўныя параметры друку. Пашыраныя параметры даступныя ў дадатковых сэрвісах друку."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Дадатковыя сэрвісы друку"</string>
+    <string name="yes" msgid="1887141030777316285">"Так"</string>
+    <string name="unknown" msgid="2526777102391303730">"Невядома"</string>
+    <string name="printer_name" msgid="386653719801075739">"Імя прынтара"</string>
+    <string name="status" msgid="5948149021115901261">"Стан"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Памеры загружанай паперы"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Узроўні расходных матэрыялаў"</string>
+    <string name="information" msgid="7896978544179559432">"Інфармацыя"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Гатова"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Друк"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Па-за сеткай"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Праверце прынтар"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-bg/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-bg/strings.xml
new file mode 100644
index 0000000..30c661a
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-bg/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Стандартната услуга за отпечатване предоставя основни опции. За разширени опции се предлагат допълнителни услуги за отпечатване."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Допълнителни услуги за отпечатване"</string>
+    <string name="yes" msgid="1887141030777316285">"Да"</string>
+    <string name="unknown" msgid="2526777102391303730">"Неизвестно"</string>
+    <string name="printer_name" msgid="386653719801075739">"Име на принтера"</string>
+    <string name="status" msgid="5948149021115901261">"Състояние"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Заредени размери хартия"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Нива на консумативите"</string>
+    <string name="information" msgid="7896978544179559432">"Информация"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Готово"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Отпечатва се"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Офлайн"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Проверка на принтера"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-bn/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-bn/strings.xml
new file mode 100644
index 0000000..90982bc
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-bn/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ডিফল্ট প্রিন্ট পরিষেবা প্রাথমিক বিকল্প প্রদান করে। উন্নত বিকল্পের জন্য অতিরিক্ত প্রিন্ট পরিষেবা উপলভ্য আছে।"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"প্রিন্ট করার অতিরিক্ত পরিষেবা"</string>
+    <string name="yes" msgid="1887141030777316285">"হ্যাঁ"</string>
+    <string name="unknown" msgid="2526777102391303730">"অজানা"</string>
+    <string name="printer_name" msgid="386653719801075739">"প্রিন্টারের নাম"</string>
+    <string name="status" msgid="5948149021115901261">"স্ট্যাটাস"</string>
+    <string name="media_ready" msgid="7205545458156298899">"কাগজের সাইজ লোড করা হয়েছে"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"সরবরাহের স্তর"</string>
+    <string name="information" msgid="7896978544179559432">"তথ্য"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"রেডি"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"প্রিন্ট করা হচ্ছে"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"অফলাইন আছে"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"প্রিন্টার চেক করুন"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-bs/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-bs/strings.xml
new file mode 100644
index 0000000..a92f90c
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-bs/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Zadana usluga štampanja pruža osnovne opcije. Za napredne opcije su dostupne dodatne usluge štampanja."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Dodatne usluge štampanja"</string>
+    <string name="yes" msgid="1887141030777316285">"Da"</string>
+    <string name="unknown" msgid="2526777102391303730">"Nepoznato"</string>
+    <string name="printer_name" msgid="386653719801075739">"Naziv štampača"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Veličine umetnutog papira"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Nivoi snabdijevanja"</string>
+    <string name="information" msgid="7896978544179559432">"Informacije"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Spremno"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Štampanje"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Provjerite štampač"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ca/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ca/strings.xml
new file mode 100644
index 0000000..9bb5baf
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ca/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"El servei d\'impressió predeterminat ofereix algunes opcions bàsiques. Per a les opcions avançades, hi ha disponibles serveis d\'impressió addicionals."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Serveis d\'impressió addicionals"</string>
+    <string name="yes" msgid="1887141030777316285">"Sí"</string>
+    <string name="unknown" msgid="2526777102391303730">"Desconegut"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nom de la impressora"</string>
+    <string name="status" msgid="5948149021115901261">"Estat"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Mides del paper carregades"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Nivells de subministrament"</string>
+    <string name="information" msgid="7896978544179559432">"Informació"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"A punt"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"S\'està imprimint"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Sense connexió"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Comprova la impressora"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-cs/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-cs/strings.xml
new file mode 100644
index 0000000..2c2ffee
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-cs/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Výchozí tisková služba nabízí základní možnosti. Pro pokročilé možnosti jsou k dispozici další tiskové služby."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Další tiskové služby"</string>
+    <string name="yes" msgid="1887141030777316285">"Ano"</string>
+    <string name="unknown" msgid="2526777102391303730">"Neznámé"</string>
+    <string name="printer_name" msgid="386653719801075739">"Název tiskárny"</string>
+    <string name="status" msgid="5948149021115901261">"Stav"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Velikosti vloženého papíru"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Úrovně nabídky"</string>
+    <string name="information" msgid="7896978544179559432">"Informace"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Připraveno"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Tisk"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Zkontrolovat tiskárnu"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-da/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-da/strings.xml
new file mode 100644
index 0000000..a134721
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-da/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Tjenesten Standardudskrivning giver dig grundlæggende valgmuligheder. Der er yderligere udskrivningstjenester tilgængelige, hvis du vil have avancerede valgmuligheder."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Yderligere udskrivningstjenester"</string>
+    <string name="yes" msgid="1887141030777316285">"Ja"</string>
+    <string name="unknown" msgid="2526777102391303730">"Ukendt"</string>
+    <string name="printer_name" msgid="386653719801075739">"Printernavn"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Indlæste papirstørrelser"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Forsyningsniveauer"</string>
+    <string name="information" msgid="7896978544179559432">"Oplysninger"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Klar"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Udskriver"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Tjek printeren"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-de/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-de/strings.xml
new file mode 100644
index 0000000..220a115
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-de/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Der Standarddruckdienst bietet grundlegende Optionen. Erweiterte Optionen sind bei weiteren Druckdiensten verfügbar."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Zusätzliche Druckdienste"</string>
+    <string name="yes" msgid="1887141030777316285">"Ja"</string>
+    <string name="unknown" msgid="2526777102391303730">"Unbekannt"</string>
+    <string name="printer_name" msgid="386653719801075739">"Druckername"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Installierte Papierformate"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Versorgungsstufen"</string>
+    <string name="information" msgid="7896978544179559432">"Informationen"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Bereit"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Drucken"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Drucker prüfen"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-el/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-el/strings.xml
new file mode 100644
index 0000000..ff6f9ef
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-el/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Η υπηρεσία Προεπιλεγμένης εκτύπωσης παρέχει βασικές επιλογές. Για τις σύνθετες επιλογές, διατίθενται πρόσθετες υπηρεσίες εκτύπωσης."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Πρόσθετες υπηρεσίες εκτύπωσης"</string>
+    <string name="yes" msgid="1887141030777316285">"Ναι"</string>
+    <string name="unknown" msgid="2526777102391303730">"Άγνωστο"</string>
+    <string name="printer_name" msgid="386653719801075739">"Όνομα εκτυπωτή"</string>
+    <string name="status" msgid="5948149021115901261">"Κατάσταση"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Μεγέθη χαρτιού που έχουν φορτώσει"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Επίπεδα προμηθειών"</string>
+    <string name="information" msgid="7896978544179559432">"Πληροφορίες"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Έτοιμο"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Εκτύπωση σε εξέλιξη"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Εκτός σύνδεσης"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Έλεγχος εκτυπωτή"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rAU/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rAU/strings.xml
new file mode 100644
index 0000000..5c05202
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rAU/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"The default print service provides basic options. For advanced options, additional print services are available."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Additional print services"</string>
+    <string name="yes" msgid="1887141030777316285">"Yes"</string>
+    <string name="unknown" msgid="2526777102391303730">"Unknown"</string>
+    <string name="printer_name" msgid="386653719801075739">"Printer name"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Loaded paper sizes"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Supply levels"</string>
+    <string name="information" msgid="7896978544179559432">"Information"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Ready"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Printing"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Check printer"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rCA/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rCA/strings.xml
new file mode 100644
index 0000000..7dfa18c
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rCA/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"The default print service provides basic options. For advanced options additional print services are available."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Additional print services"</string>
+    <string name="yes" msgid="1887141030777316285">"Yes"</string>
+    <string name="unknown" msgid="2526777102391303730">"Unknown"</string>
+    <string name="printer_name" msgid="386653719801075739">"Printer name"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Loaded paper sizes"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Supply levels"</string>
+    <string name="information" msgid="7896978544179559432">"Information"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Ready"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Printing"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Check printer"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rGB/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rGB/strings.xml
new file mode 100644
index 0000000..5c05202
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rGB/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"The default print service provides basic options. For advanced options, additional print services are available."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Additional print services"</string>
+    <string name="yes" msgid="1887141030777316285">"Yes"</string>
+    <string name="unknown" msgid="2526777102391303730">"Unknown"</string>
+    <string name="printer_name" msgid="386653719801075739">"Printer name"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Loaded paper sizes"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Supply levels"</string>
+    <string name="information" msgid="7896978544179559432">"Information"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Ready"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Printing"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Check printer"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rIN/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rIN/strings.xml
new file mode 100644
index 0000000..5c05202
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rIN/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"The default print service provides basic options. For advanced options, additional print services are available."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Additional print services"</string>
+    <string name="yes" msgid="1887141030777316285">"Yes"</string>
+    <string name="unknown" msgid="2526777102391303730">"Unknown"</string>
+    <string name="printer_name" msgid="386653719801075739">"Printer name"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Loaded paper sizes"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Supply levels"</string>
+    <string name="information" msgid="7896978544179559432">"Information"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Ready"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Printing"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Check printer"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-es-rUS/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-es-rUS/strings.xml
new file mode 100644
index 0000000..c0dfad0
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-es-rUS/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"El servicio de impresión predeterminado brinda opciones básicas. Para opciones avanzadas, hay servicios de impresión adicionales disponibles."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Servicios de impresión adicionales"</string>
+    <string name="yes" msgid="1887141030777316285">"Sí"</string>
+    <string name="unknown" msgid="2526777102391303730">"Desconocido"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nombre de la impresora"</string>
+    <string name="status" msgid="5948149021115901261">"Estado"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Tamaños de papel cargados"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Niveles de suministro"</string>
+    <string name="information" msgid="7896978544179559432">"Información"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Listo"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Impresión"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Sin conexión"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Verificar impresora"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-es/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-es/strings.xml
new file mode 100644
index 0000000..02c300a
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-es/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"El servicio de impresión predeterminado solo cuenta con opciones básicas. Si quieres usar opciones avanzadas, hay otros servicios de impresión disponibles."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Servicios de impresión adicionales"</string>
+    <string name="yes" msgid="1887141030777316285">"Sí"</string>
+    <string name="unknown" msgid="2526777102391303730">"Desconocido"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nombre de la impresora"</string>
+    <string name="status" msgid="5948149021115901261">"Estado"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Tamaños del papel cargado"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Niveles de suministro"</string>
+    <string name="information" msgid="7896978544179559432">"Información"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Listo"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Imprimiendo"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Sin conexión"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Comprobar impresora"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-et/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-et/strings.xml
new file mode 100644
index 0000000..09b9ddf
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-et/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Printimise vaiketeenus hõlmab põhivalikuid. Täpsemate valikute jaoks on saadaval printimise lisateenused."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Printimise lisateenused"</string>
+    <string name="yes" msgid="1887141030777316285">"Jah"</string>
+    <string name="unknown" msgid="2526777102391303730">"Teadmata"</string>
+    <string name="printer_name" msgid="386653719801075739">"Printeri nimi"</string>
+    <string name="status" msgid="5948149021115901261">"Olek"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Laaditud paberi suurused"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Tarvikute tasemed"</string>
+    <string name="information" msgid="7896978544179559432">"Teave"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Valmis"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Printimine"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Võrguühenduseta"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Printeri kontrollimine"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-eu/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-eu/strings.xml
new file mode 100644
index 0000000..03d7e1c
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-eu/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Inprimatze-zerbitzu lehenetsiak oinarrizko aukerak eskaintzen ditu. Aukera aurreratuak behar badituzu, inprimatze-zerbitzu gehigarriak dauzkazu erabilgarri."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Inprimatze-zerbitzu gehigarriak"</string>
+    <string name="yes" msgid="1887141030777316285">"Bai"</string>
+    <string name="unknown" msgid="2526777102391303730">"Ezezaguna"</string>
+    <string name="printer_name" msgid="386653719801075739">"Inprimagailuaren izena"</string>
+    <string name="status" msgid="5948149021115901261">"Egoera"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Kargatutako paper-tamainak"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Hornidura-mailak"</string>
+    <string name="information" msgid="7896978544179559432">"Informazioa"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Prest"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Inprimatzen"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Deskonektatuta"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Egiaztatu inprimagailua"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-fa/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-fa/strings.xml
new file mode 100644
index 0000000..dd67281
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-fa/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"سرویس چاپ پیش‌فرض گزینه‌های اصلی را ارائه می‌دهد. برای گزینه‌های پیشرفته، سرویس‌های چاپ دیگری دردسترس هستند."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"سرویس‌های چاپ بیشتر"</string>
+    <string name="yes" msgid="1887141030777316285">"بله"</string>
+    <string name="unknown" msgid="2526777102391303730">"نامشخص"</string>
+    <string name="printer_name" msgid="386653719801075739">"نام چاپگر"</string>
+    <string name="status" msgid="5948149021115901261">"وضعیت"</string>
+    <string name="media_ready" msgid="7205545458156298899">"اندازه‌های کاغذ بارشده"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"سطح عرضه"</string>
+    <string name="information" msgid="7896978544179559432">"اطلاعات"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"آماده"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"درحال چاپ کردن"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"آفلاین"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"بررسی چاپگر"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-fi/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-fi/strings.xml
new file mode 100644
index 0000000..eca18d1
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-fi/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Oletustulostuspalveluun kuuluu perusvaihtoehdot. Lisää vaihtoehtoja on saatavilla lisäpalveluiden kautta."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Muita tulostuspalveluja"</string>
+    <string name="yes" msgid="1887141030777316285">"Kyllä"</string>
+    <string name="unknown" msgid="2526777102391303730">"Tuntematon"</string>
+    <string name="printer_name" msgid="386653719801075739">"Tulostimen nimi"</string>
+    <string name="status" msgid="5948149021115901261">"Tila"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Ladatut paperikoot"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Täyttötasot"</string>
+    <string name="information" msgid="7896978544179559432">"Tiedot"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Valmis"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Tulostaa"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline-tila"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Tarkista tulostin"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-fr-rCA/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-fr-rCA/strings.xml
new file mode 100644
index 0000000..854ad3f
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-fr-rCA/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Le service d\'impression par défaut offre des options de base. Pour les options avancées, des services d\'impression supplémentaires sont proposés."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Services d\'impression supplémentaires"</string>
+    <string name="yes" msgid="1887141030777316285">"Oui"</string>
+    <string name="unknown" msgid="2526777102391303730">"Inconnu"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nom de l\'imprimante"</string>
+    <string name="status" msgid="5948149021115901261">"État"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Formats de papier chargés"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Niveaux d\'approvisionnement"</string>
+    <string name="information" msgid="7896978544179559432">"Information"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Prête"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Impression en cours…"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Hors ligne"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Vérifier l\'imprimante"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-fr/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-fr/strings.xml
new file mode 100644
index 0000000..0253be0
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-fr/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Le service d\'impression par défaut fournit des options de base. Pour les options avancées, d\'autres services d\'impression sont disponibles."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Services d\'impression supplémentaires"</string>
+    <string name="yes" msgid="1887141030777316285">"Oui"</string>
+    <string name="unknown" msgid="2526777102391303730">"Inconnu"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nom de l\'imprimante"</string>
+    <string name="status" msgid="5948149021115901261">"État"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Formats de papier chargés"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Niveaux d\'approvisionnement"</string>
+    <string name="information" msgid="7896978544179559432">"Informations"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Prête"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Impression"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Hors connexion"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Vérifier l\'imprimante"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-gl/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-gl/strings.xml
new file mode 100644
index 0000000..2aabca3
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-gl/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"O servizo de impresión predeterminado só ten opcións básicas. Hai servizos de impresión adicionais dispoñibles nas opcións avanzadas."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Servizos de impresión adicionais"</string>
+    <string name="yes" msgid="1887141030777316285">"Si"</string>
+    <string name="unknown" msgid="2526777102391303730">"Descoñécese"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nome da impresora"</string>
+    <string name="status" msgid="5948149021115901261">"Estado"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Tamaños de papel cargados"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Niveis de subministración"</string>
+    <string name="information" msgid="7896978544179559432">"Información"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Lista"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Imprimindo"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Sen conexión"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Comprobar impresora"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-gu/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-gu/strings.xml
new file mode 100644
index 0000000..7866e10
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-gu/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ડિફૉલ્ટ પ્રિન્ટ સેવા મૂળભૂત વિકલ્પો આપે છે. વિગતવાર વિકલ્પો માટે વધારાની પ્રિન્ટ સેવાઓ ઉપલબ્ધ છે."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"વધારાની પ્રિન્ટ સેવાઓ"</string>
+    <string name="yes" msgid="1887141030777316285">"હા"</string>
+    <string name="unknown" msgid="2526777102391303730">"અજાણ"</string>
+    <string name="printer_name" msgid="386653719801075739">"પ્રિન્ટરનું નામ"</string>
+    <string name="status" msgid="5948149021115901261">"સ્ટેટસ"</string>
+    <string name="media_ready" msgid="7205545458156298899">"લોડ કરેલા પેપરના કદ"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"સપ્લાય લેવલ"</string>
+    <string name="information" msgid="7896978544179559432">"માહિતી"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"તૈયાર"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"પ્રિન્ટિંગ"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ઑફલાઇન"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"પ્રિન્ટર ચેક કરો"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-hi/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-hi/strings.xml
new file mode 100644
index 0000000..d72b0fb
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-hi/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"प्रिंट करने की डिफ़ॉल्ट सेवा में बुनियादी विकल्प मिलते हैं. बेहतर विकल्पों में, प्रिंट करने की अतिरिक्त सेवाएं उपलब्ध हैं."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"प्रिंट करने की अतिरिक्त सेवाएं"</string>
+    <string name="yes" msgid="1887141030777316285">"हां"</string>
+    <string name="unknown" msgid="2526777102391303730">"कोई जानकारी नहीं है"</string>
+    <string name="printer_name" msgid="386653719801075739">"प्रिंटर का नाम"</string>
+    <string name="status" msgid="5948149021115901261">"स्थिति"</string>
+    <string name="media_ready" msgid="7205545458156298899">"लोड किए गए पेपर के साइज़"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"सप्लाई के लेवल"</string>
+    <string name="information" msgid="7896978544179559432">"जानकारी"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"तैयार है"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"प्रिंटिंग"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ऑफ़लाइन"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"प्रिंटर की जांच करें"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-hr/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-hr/strings.xml
new file mode 100644
index 0000000..9ddb71b
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-hr/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Zadana usluga ispisa nudi osnovne opcije. Za napredne opcije dostupne su dodatne usluge ispisa."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Dodatne usluge ispisa"</string>
+    <string name="yes" msgid="1887141030777316285">"Da"</string>
+    <string name="unknown" msgid="2526777102391303730">"Nepoznato"</string>
+    <string name="printer_name" msgid="386653719801075739">"Naziv pisača"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Veličine umetnutog papira"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Razine potrošnog materijala"</string>
+    <string name="information" msgid="7896978544179559432">"Informacije"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Spremno"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Ispis"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Provjerite pisač"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-hu/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-hu/strings.xml
new file mode 100644
index 0000000..f452854
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-hu/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Az alapértelmezett nyomtatási szolgáltatás alapvető funkciókat kínál. Speciális funkciókhoz további nyomtatási szolgáltatások állnak rendelkezésre."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"További nyomtatási szolgáltatások"</string>
+    <string name="yes" msgid="1887141030777316285">"Igen"</string>
+    <string name="unknown" msgid="2526777102391303730">"Ismeretlen"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nyomtató neve"</string>
+    <string name="status" msgid="5948149021115901261">"Állapot"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Betöltött papírméretek"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Utántöltési szintek"</string>
+    <string name="information" msgid="7896978544179559432">"Információ"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Készen áll"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Nyomtatás"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Nyomtató ellenőrzése"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-hy/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-hy/strings.xml
new file mode 100644
index 0000000..d38aef6
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-hy/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Կանխադրված տպման ծառայությունը տրամադրում է հիմնական պարամետրերը։ Ընդլայնված տարբերակների համար հասանելի են լրացուցիչ տպագրական ծառայություններ։"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Լրացուցիչ տպագրական ծառայություններ"</string>
+    <string name="yes" msgid="1887141030777316285">"Այո"</string>
+    <string name="unknown" msgid="2526777102391303730">"Անհայտ"</string>
+    <string name="printer_name" msgid="386653719801075739">"Տպիչի անունը"</string>
+    <string name="status" msgid="5948149021115901261">"Կարգավիճակ"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Բեռնված թղթի չափսերը"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Մատակարարման մակարդակներ"</string>
+    <string name="information" msgid="7896978544179559432">"Տեղեկություններ"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Պատրաստ է"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Տպում"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Կապ չկա"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Ստուգել տպիչը"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-in/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-in/strings.xml
new file mode 100644
index 0000000..5be47ce
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-in/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Layanan cetak default menyediakan opsi dasar. Untuk opsi lanjutan, layanan cetak tambahan tersedia."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Layanan cetak tambahan"</string>
+    <string name="yes" msgid="1887141030777316285">"Ya"</string>
+    <string name="unknown" msgid="2526777102391303730">"Tidak diketahui"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nama printer"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Ukuran kertas yang dimasukkan"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Tingkat persediaan"</string>
+    <string name="information" msgid="7896978544179559432">"Informasi"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Siap"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Mencetak"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Periksa printer"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-is/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-is/strings.xml
new file mode 100644
index 0000000..8b33e20
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-is/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Sjálfgefin prentþjónusta inniheldur grunnvalkosti. Viðbótarprentþjónusta er í boði fyrir ítarlegri valkosti."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Viðbótarprentþjónusta"</string>
+    <string name="yes" msgid="1887141030777316285">"Já"</string>
+    <string name="unknown" msgid="2526777102391303730">"Óþekkt"</string>
+    <string name="printer_name" msgid="386653719801075739">"Heiti prentara"</string>
+    <string name="status" msgid="5948149021115901261">"Staða"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Pappírsstærðir sem hefur verið hlaðið"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Birgðir"</string>
+    <string name="information" msgid="7896978544179559432">"Upplýsingar"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Tilbúinn"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Prentar"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Án nettengingar"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Athugaðu prentara"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-it/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-it/strings.xml
new file mode 100644
index 0000000..4b4b94e
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-it/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Il servizio di stampa predefinito offre opzioni di base. Per le opzioni avanzate sono disponibili altri servizi di stampa."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Servizi di stampa aggiuntivi"</string>
+    <string name="yes" msgid="1887141030777316285">"Sì"</string>
+    <string name="unknown" msgid="2526777102391303730">"Sconosciuto"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nome stampante"</string>
+    <string name="status" msgid="5948149021115901261">"Stato"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Dimensioni foglio caricato"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Livelli di alimentazione"</string>
+    <string name="information" msgid="7896978544179559432">"Informazioni"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Pronto"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Stampa in corso…"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Controlla la stampante"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-iw/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-iw/strings.xml
new file mode 100644
index 0000000..0c19372
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-iw/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"בשירות ההדפסה שמוגדר כברירת מחדל יש אפשרויות בסיסיות. בשירותי ההדפסה הנוספים יש אפשרויות מתקדמות."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"שירותי הדפסה נוספים"</string>
+    <string name="yes" msgid="1887141030777316285">"כן"</string>
+    <string name="unknown" msgid="2526777102391303730">"לא ידוע"</string>
+    <string name="printer_name" msgid="386653719801075739">"שם המדפסת"</string>
+    <string name="status" msgid="5948149021115901261">"סטטוס"</string>
+    <string name="media_ready" msgid="7205545458156298899">"הגדלים של הדפים שנטענו"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"רמות האספקה"</string>
+    <string name="information" msgid="7896978544179559432">"מידע"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"אפשר להתחיל"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"הדפסה"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"אופליין"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"צריך לבדוק את המדפסת"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ja/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ja/strings.xml
new file mode 100644
index 0000000..88c6574
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ja/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"デフォルトの印刷サービスには基本的なオプションがあります。高度なオプションでは、追加の印刷サービスを利用できます。"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"追加の印刷サービス"</string>
+    <string name="yes" msgid="1887141030777316285">"はい"</string>
+    <string name="unknown" msgid="2526777102391303730">"不明"</string>
+    <string name="printer_name" msgid="386653719801075739">"プリンタ名"</string>
+    <string name="status" msgid="5948149021115901261">"ステータス"</string>
+    <string name="media_ready" msgid="7205545458156298899">"読み込まれた用紙のサイズ"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"供給レベル"</string>
+    <string name="information" msgid="7896978544179559432">"情報"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"準備完了"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"印刷"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"オフライン"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"プリンタを確認してください"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ka/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ka/strings.xml
new file mode 100644
index 0000000..02932a9
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ka/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ბეჭდვის ნაგულისხმევი სერვისი გთავაზობთ ძირითად ვარიანტებს. გაფართოებული პარამეტრებისთვის ხელმისაწვდომია დამატებითი ბეჭდვის სერვისები."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"დამატებითი ბეჭდვის სერვისები"</string>
+    <string name="yes" msgid="1887141030777316285">"დიახ"</string>
+    <string name="unknown" msgid="2526777102391303730">"უცნობი"</string>
+    <string name="printer_name" msgid="386653719801075739">"პრინტერის სახელი"</string>
+    <string name="status" msgid="5948149021115901261">"სტატუსი"</string>
+    <string name="media_ready" msgid="7205545458156298899">"მოთავსებული ფურცლის ზომა"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"სახარჯი მასალის დონე"</string>
+    <string name="information" msgid="7896978544179559432">"ინფორმაცია"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"მზადაა"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"იბეჭდება"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ხაზგარეშე"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"პრინტერის შემოწმება"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-kk/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-kk/strings.xml
new file mode 100644
index 0000000..7780f72
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-kk/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Әдепкі басып шығару қызметі негізгі мүмкіндіктерді ұсынады. Кеңейтілген мүмкіндіктерді қосымша басып шығару қызметтері арқылы пайдалануға болады."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Қосымша басып шығару қызметтері"</string>
+    <string name="yes" msgid="1887141030777316285">"Иә"</string>
+    <string name="unknown" msgid="2526777102391303730">"Белгісіз"</string>
+    <string name="printer_name" msgid="386653719801075739">"Принтер атауы"</string>
+    <string name="status" msgid="5948149021115901261">"Күйі"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Салынған қағаз өлшемдері"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Шығыс материалдарының деңгейі"</string>
+    <string name="information" msgid="7896978544179559432">"Ақпарат"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Дайын"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Басып шығару"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Офлайн"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Принтерді тексеру"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-km/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-km/strings.xml
new file mode 100644
index 0000000..5435e34
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-km/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"សេវាកម្ម​បោះពុម្ពលំនាំដើម​ផ្ដល់ជូនជម្រើស​មូលដ្ឋាន។ សម្រាប់ជម្រើសកម្រិតខ្ពស់ អាចប្រើសេវាកម្មបោះពុម្ពបន្ថែមបាន។"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"សេវាកម្មបោះពុម្ពបន្ថែម"</string>
+    <string name="yes" msgid="1887141030777316285">"បាទ/ចាស"</string>
+    <string name="unknown" msgid="2526777102391303730">"មិនស្គាល់"</string>
+    <string name="printer_name" msgid="386653719801075739">"ឈ្មោះម៉ាស៊ីនបោះពុម្ព"</string>
+    <string name="status" msgid="5948149021115901261">"ស្ថានភាព"</string>
+    <string name="media_ready" msgid="7205545458156298899">"ទំហំក្រដាសដែលបានផ្ទុក"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"កម្រិតផ្គត់ផ្គង់"</string>
+    <string name="information" msgid="7896978544179559432">"ព័ត៌មាន"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"រួចរាល់"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"ការ​បោះពុម្ព"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"គ្មានអ៊ីនធឺណិត"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"ពិនិត្យ​ម៉ាស៊ីនបោះពុម្ព"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-kn/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-kn/strings.xml
new file mode 100644
index 0000000..7a7542f
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-kn/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ಡೀಫಾಲ್ಟ್ ಮುದ್ರಣ ಸೇವೆಯು ಮೂಲ ಆಯ್ಕೆಗಳನ್ನು ಒದಗಿಸುತ್ತದೆ. ಸುಧಾರಿತ ಆಯ್ಕೆಗಳಿಗಾಗಿ ಹೆಚ್ಚುವರಿ ಮುದ್ರಣ ಸೇವೆಗಳು ಲಭ್ಯವಿವೆ."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"ಹೆಚ್ಚುವರಿ ಮುದ್ರಣ ಸೇವೆಗಳು"</string>
+    <string name="yes" msgid="1887141030777316285">"ಹೌದು"</string>
+    <string name="unknown" msgid="2526777102391303730">"ಅಪರಿಚಿತ"</string>
+    <string name="printer_name" msgid="386653719801075739">"ಪ್ರಿಂಟರ್ ಹೆಸರು"</string>
+    <string name="status" msgid="5948149021115901261">"ಸ್ಥಿತಿ"</string>
+    <string name="media_ready" msgid="7205545458156298899">"ಲೋಡ್ ಮಾಡಲಾದ ಕಾಗದದ ಗಾತ್ರಗಳು"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"ಪೂರೈಕೆ ಹಂತಗಳು"</string>
+    <string name="information" msgid="7896978544179559432">"ಮಾಹಿತಿ"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"ಸಿದ್ಧವಾಗಿದೆ"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"ಮುದ್ರಣ"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ಆಫ್‌ಲೈನ್"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"ಪ್ರಿಂಟರ್ ಅನ್ನು ಪರಿಶೀಲಿಸಿ"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ko/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ko/strings.xml
new file mode 100644
index 0000000..d58165c
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ko/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"기본인쇄 서비스에서는 기본적인 옵션만 제공됩니다. 고급 옵션의 경우 추가 인쇄 서비스를 이용할 수 있습니다."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"추가 인쇄 서비스"</string>
+    <string name="yes" msgid="1887141030777316285">"예"</string>
+    <string name="unknown" msgid="2526777102391303730">"알 수 없음"</string>
+    <string name="printer_name" msgid="386653719801075739">"프린터 이름"</string>
+    <string name="status" msgid="5948149021115901261">"상태"</string>
+    <string name="media_ready" msgid="7205545458156298899">"로드된 용지 크기"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"공급 수준"</string>
+    <string name="information" msgid="7896978544179559432">"정보"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"준비됨"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"인쇄 중"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"오프라인"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"프린터 확인"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ky/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ky/strings.xml
new file mode 100644
index 0000000..bf8c4f4
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ky/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Демейки басып чыгаруу кызматы негизги параметрлерди сунуштайт. Өркүндөтүлгөн параметрлер үчүн кошумча басып чыгаруу кызматтары жеткиликтүү."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Кошумча басып чыгаруу кызматтары"</string>
+    <string name="yes" msgid="1887141030777316285">"Ооба"</string>
+    <string name="unknown" msgid="2526777102391303730">"Белгисиз"</string>
+    <string name="printer_name" msgid="386653719801075739">"принтердин аталышы"</string>
+    <string name="status" msgid="5948149021115901261">"Абалы"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Жүктөлгөн кагаз өлчөмдөрү"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Камсыздоо деңгээли"</string>
+    <string name="information" msgid="7896978544179559432">"Маалымат"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Даяр"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Басып чыгаруу"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Офлайн"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Принтерди текшерүү"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-lo/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-lo/strings.xml
new file mode 100644
index 0000000..470be12
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-lo/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ບໍລິການການພິມມາດຕະຖານມີຕົວເລືອກພື້ນຖານຕ່າງໆ. ບໍລິການເພີ່ມເຕີມກ່ຽວກັບການພິມຈະມີຕົວເລືອກຂັ້ນສູງພ້ອມໃຫ້ນຳໃຊ້."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"ບໍລິການເພີ່ມເຕີມກ່ຽວກັບການພິມ"</string>
+    <string name="yes" msgid="1887141030777316285">"ແມ່ນ"</string>
+    <string name="unknown" msgid="2526777102391303730">"ບໍ່ຮູ້ຈັກ"</string>
+    <string name="printer_name" msgid="386653719801075739">"ຊື່ເຄື່ອງພິມ"</string>
+    <string name="status" msgid="5948149021115901261">"ສະຖານະ"</string>
+    <string name="media_ready" msgid="7205545458156298899">"ຂະໜາດເຈ້ຍທີ່ມີຢູ່ໃນເຄື່ອງ"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"ລະດັບຂອງສິ່ງຕ່າງໆທີ່ຈຳເປັນຕໍ່ການເຮັດວຽກ"</string>
+    <string name="information" msgid="7896978544179559432">"ຂໍ້ມູນ"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"ພ້ອມນຳໃຊ້"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"ກຳລັງພິມ"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ອອບລາຍ"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"ກວດສອບເຄື່ອງພິມ"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-lt/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-lt/strings.xml
new file mode 100644
index 0000000..e582b88
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-lt/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Naudojantis numatytojo spausdinimo paslauga teikiamos pagrindinės parinktys. Išplėstinėms parinktims yra teikiamos papildomos spausdinimo paslaugos."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Papildomos spausdinimo paslaugos"</string>
+    <string name="yes" msgid="1887141030777316285">"Taip"</string>
+    <string name="unknown" msgid="2526777102391303730">"Nežinoma"</string>
+    <string name="printer_name" msgid="386653719801075739">"Spausdintuvo pavadinimas"</string>
+    <string name="status" msgid="5948149021115901261">"Būsena"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Įkeliamo popieriaus dydžiai"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Įrangos lygiai"</string>
+    <string name="information" msgid="7896978544179559432">"Informacija"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Parengta"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Spausdinimas"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Neprisijungus"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Tikrinti spausdintuvą"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-lv/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-lv/strings.xml
new file mode 100644
index 0000000..88e3b7c
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-lv/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Noklusējuma drukāšanas pakalpojums nodrošina pamatiespējas. Lai nodrošinātu papildu iespējas, ir pieejami papildu drukāšanas pakalpojumi."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Papildu drukāšanas pakalpojumi"</string>
+    <string name="yes" msgid="1887141030777316285">"Jā"</string>
+    <string name="unknown" msgid="2526777102391303730">"Nav zināms"</string>
+    <string name="printer_name" msgid="386653719801075739">"Printera nosaukums"</string>
+    <string name="status" msgid="5948149021115901261">"Statuss"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Ielādēti papīra izmēru dati"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Izejmateriālu līmenis"</string>
+    <string name="information" msgid="7896978544179559432">"Informācija"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Gatavs"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Notiek drukāšana…"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Bezsaistē"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Pārbaudīt printeri"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-mk/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-mk/strings.xml
new file mode 100644
index 0000000..4dfaee5
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-mk/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Услугата за стандардно печатење обезбедува основни опции. За напредни опции, достапни се дополнителни услуги за печатење."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Дополнителни услуги за печатење"</string>
+    <string name="yes" msgid="1887141030777316285">"Да"</string>
+    <string name="unknown" msgid="2526777102391303730">"Непознато"</string>
+    <string name="printer_name" msgid="386653719801075739">"Име на печатачот"</string>
+    <string name="status" msgid="5948149021115901261">"Статус"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Големина на вметнатата хартија"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Нивоа на снабдување"</string>
+    <string name="information" msgid="7896978544179559432">"Информации"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Подготвено"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Се печати"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Офлајн"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Проверете го печатачот"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ml/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ml/strings.xml
new file mode 100644
index 0000000..b868761
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ml/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ഡിഫോൾട്ട് പ്രിന്റ് സേവനം അടിസ്ഥാന ഓപ്ഷനുകൾ നൽകുന്നു. വിപുലമായ ഓപ്ഷനുകൾക്ക് അധിക പ്രിന്റ് സേവനങ്ങൾ ലഭ്യമാണ്."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"അധിക പ്രിന്റ് സേവനങ്ങൾ"</string>
+    <string name="yes" msgid="1887141030777316285">"ഉവ്വ്"</string>
+    <string name="unknown" msgid="2526777102391303730">"അജ്ഞാതം"</string>
+    <string name="printer_name" msgid="386653719801075739">"പ്രിന്ററിന്റെ പേര്"</string>
+    <string name="status" msgid="5948149021115901261">"നില"</string>
+    <string name="media_ready" msgid="7205545458156298899">"പേപ്പർ വലുപ്പങ്ങൾ ലോഡ് ചെയ്തു"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"വിതരണ നിലകൾ"</string>
+    <string name="information" msgid="7896978544179559432">"വിവരങ്ങൾ"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"തയ്യാറാണ്"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"പ്രിന്റിംഗ്"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ഓഫ്‌ലൈനാണ്"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"പ്രിന്റർ പരിശോധിക്കുക"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-mn/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-mn/strings.xml
new file mode 100644
index 0000000..d7bf090
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-mn/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Өгөгдмөл хэвлэх үйлчилгээ нь үндсэн сонголтуудаар хангадаг. Нарийвчилсан сонголтуудын хувьд нэмэлт хэвлэх үйлчилгээ боломжтой."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Хэвлэх нэмэлт үйлчилгээ"</string>
+    <string name="yes" msgid="1887141030777316285">"Тийм"</string>
+    <string name="unknown" msgid="2526777102391303730">"Тодорхойгүй"</string>
+    <string name="printer_name" msgid="386653719801075739">"Хэвлэгчийн нэр"</string>
+    <string name="status" msgid="5948149021115901261">"Төлөв"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Ачаалсан цаасны хэмжээ"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Хангамжийн түвшин"</string>
+    <string name="information" msgid="7896978544179559432">"Мэдээлэл"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Бэлэн"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Хэвлэж байна"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Офлайн"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Хэвлэгчийг шалгах"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-mr/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-mr/strings.xml
new file mode 100644
index 0000000..a89338c
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-mr/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"डीफॉल्ट प्रिंट सेवा पुरवठादार मूलभूत पर्याय देतात. प्रगत पर्यायांसाठी अतिरिक्त प्रिंट सेवा उपलब्ध आहेत."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"अतिरिक्त प्रिंट सेवा"</string>
+    <string name="yes" msgid="1887141030777316285">"होय"</string>
+    <string name="unknown" msgid="2526777102391303730">"अज्ञात"</string>
+    <string name="printer_name" msgid="386653719801075739">"प्रिंटरचे नाव"</string>
+    <string name="status" msgid="5948149021115901261">"स्टेटस"</string>
+    <string name="media_ready" msgid="7205545458156298899">"लोड केलेल्या कागदाचे आकार"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"पुरवठ्याच्या पातळ्या"</string>
+    <string name="information" msgid="7896978544179559432">"माहिती"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"तयार आहे"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"प्रिंटिंग"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ऑफलाइन"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"प्रिंटर तपासा"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ms/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ms/strings.xml
new file mode 100644
index 0000000..4be3c4f
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ms/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Perkhidmatan cetak lalai menyediakan pilihan asas. Untuk pilihan lanjutan, perkhidmatan cetak tambahan tersedia."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Perkhidmatan cetak tambahan"</string>
+    <string name="yes" msgid="1887141030777316285">"Ya"</string>
+    <string name="unknown" msgid="2526777102391303730">"Tidak diketahui"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nama pencetak"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Saiz kertas yang dimuatkan"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Tahap bekalan"</string>
+    <string name="information" msgid="7896978544179559432">"Maklumat"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Sedia"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Pencetakan"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Luar talian"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Semak pencetak"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-my/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-my/strings.xml
new file mode 100644
index 0000000..91d1e8f
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-my/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ပုံသေ ပုံနှိပ်ပေးခြင်း ဝန်ဆောင်မှုသည် အခြေခံရွေးစရာများကို ပေးသည်။ အဆင့်မြင့်ရွေးစရာများအတွက် ထပ်ဆောင်း ပုံနှိပ်ပေးခြင်း ဝန်ဆောင်မှုများ ရနိုင်သည်။"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"ထပ်ဆောင်း ပုံနှိပ်ပေးခြင်း ဝန်ဆောင်မှုများ"</string>
+    <string name="yes" msgid="1887141030777316285">"Yes"</string>
+    <string name="unknown" msgid="2526777102391303730">"မသိပါ"</string>
+    <string name="printer_name" msgid="386653719801075739">"ပုံနှိပ်စက်အမည်"</string>
+    <string name="status" msgid="5948149021115901261">"အခြေအနေ"</string>
+    <string name="media_ready" msgid="7205545458156298899">"ဖွင့်ထားသော စာရွက်အရွယ်အစားများ"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"ပံ့ပိုးမှုအဆင့်များ"</string>
+    <string name="information" msgid="7896978544179559432">"အချက်အလက်"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"အဆင်သင့်"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"ပုံနှိပ်ထုတ်ယူနေသည်"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"အော့ဖ်လိုင်း"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"ပရင်တာကို စစ်ဆေးရန်"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-nb/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-nb/strings.xml
new file mode 100644
index 0000000..f3eb5c0
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-nb/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Standardtjenesten for utskrift har grunnleggende alternativer. For avanserte alternativer finnes det andre utskriftstjenester tilgjengelig."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Andre utskriftstjenester"</string>
+    <string name="yes" msgid="1887141030777316285">"Ja"</string>
+    <string name="unknown" msgid="2526777102391303730">"Ukjent"</string>
+    <string name="printer_name" msgid="386653719801075739">"Skrivernavn"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Innlastede papirstørrelser"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Beholdningsnivåer"</string>
+    <string name="information" msgid="7896978544179559432">"Informasjon"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Klar"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Skriver ut"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Uten nett"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Sjekk skriveren"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ne/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ne/strings.xml
new file mode 100644
index 0000000..fddf1c6
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ne/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"डिफल्ट प्रिन्ट सेवाअन्तर्गत आधारभूत विकल्पहरू प्रदान गरिन्छ। उन्नत विकल्पहरूका निम्ति अतिरिक्त प्रिन्ट सेवाहरू उपलब्ध छन्।"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"अतिरिक्त प्रिन्ट सेवाहरू"</string>
+    <string name="yes" msgid="1887141030777316285">"अँ"</string>
+    <string name="unknown" msgid="2526777102391303730">"अज्ञात"</string>
+    <string name="printer_name" msgid="386653719801075739">"प्रिन्टरको नाम"</string>
+    <string name="status" msgid="5948149021115901261">"स्थिति"</string>
+    <string name="media_ready" msgid="7205545458156298899">"लोड गरिएका कागजका आकार"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"सप्लाई लेभलहरू"</string>
+    <string name="information" msgid="7896978544179559432">"जानकारी"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"तयार छ"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"प्रिन्ट गरिँदै छ"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"अफलाइन छ"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"प्रिन्टर जाँच्नुहोस्"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-nl/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-nl/strings.xml
new file mode 100644
index 0000000..e6b1906
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-nl/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"De standaard afdrukservice biedt basisopties. Voor geavanceerde opties zijn aanvullende afdrukservices beschikbaar."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Aanvullende afdrukservices"</string>
+    <string name="yes" msgid="1887141030777316285">"Ja"</string>
+    <string name="unknown" msgid="2526777102391303730">"Onbekend"</string>
+    <string name="printer_name" msgid="386653719801075739">"Naam printer"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Geladen papierformaten"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Voorraadniveaus"</string>
+    <string name="information" msgid="7896978544179559432">"Informatie"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Klaar"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Afdrukken"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Printer controleren"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-or/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-or/strings.xml
new file mode 100644
index 0000000..5eb199f
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-or/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ଡିଫଲ୍ଟ ପ୍ରିଣ୍ଟ ସେବା ପ୍ରଦାନକାରୀ ମୌଳିକ ବିକଳ୍ପ ଉନ୍ନତ ବିକଳ୍ପ ପାଇଁ ଅତିରିକ୍ତ ପ୍ରିଣ୍ଟ ସେବା ଉପଲବ୍ଧ।"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"ଅତିରିକ୍ତ ପ୍ରିଣ୍ଟ ସେବା"</string>
+    <string name="yes" msgid="1887141030777316285">"ହଁ"</string>
+    <string name="unknown" msgid="2526777102391303730">"ଅଜଣା"</string>
+    <string name="printer_name" msgid="386653719801075739">"ପ୍ରିଣ୍ଟର ନାମ"</string>
+    <string name="status" msgid="5948149021115901261">"ସ୍ଥିତି"</string>
+    <string name="media_ready" msgid="7205545458156298899">"ଲୋଡ କରାଯାଇଥିବା କାଗଜ ଆକାର"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"ସପ୍ଲାଏ ଲେଭେଲ"</string>
+    <string name="information" msgid="7896978544179559432">"ସୂଚନା"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"ପ୍ରସ୍ତୁତ"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"ପ୍ରିଣ୍ଟ କରାଯାଉଛି"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ଅଫଲାଇନ"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"ପ୍ରିଣ୍ଟର ଯାଞ୍ଚ କରନ୍ତୁ"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-pa/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-pa/strings.xml
new file mode 100644
index 0000000..71efd68
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-pa/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ਪ੍ਰਿੰਟ ਕਰਨ ਦੀ ਪੂਰਵ-ਨਿਰਧਾਰਿਤ ਸੇਵਾ ਮੂਲ ਵਿਕਲਪ ਮੁਹੱਈਆ ਕਰਵਾਉਂਦੀ ਹੈ। ਅਡਵਾਂਸ ਵਿਕਲਪਾਂ ਵਿੱਚ ਪ੍ਰਿੰਟ ਕਰਨ ਦੀਆਂ ਵਧੀਕ ਸੇਵਾਵਾਂ ਉਪਲਬਧ ਹਨ।"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"ਪ੍ਰਿੰਟ ਕਰਨ ਦੀਆਂ ਵਧੀਕ ਸੇਵਾਵਾਂ"</string>
+    <string name="yes" msgid="1887141030777316285">"ਹਾਂ"</string>
+    <string name="unknown" msgid="2526777102391303730">"ਅਗਿਆਤ"</string>
+    <string name="printer_name" msgid="386653719801075739">"ਪ੍ਰਿੰਟਰ ਦਾ ਨਾਮ"</string>
+    <string name="status" msgid="5948149021115901261">"ਸਥਿਤੀ"</string>
+    <string name="media_ready" msgid="7205545458156298899">"ਲੋਡ ਕੀਤੇ ਕਾਗਜ਼ ਦੇ ਆਕਾਰ"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"ਸਪਲਾਈ ਦੇ ਪੱਧਰ"</string>
+    <string name="information" msgid="7896978544179559432">"ਜਾਣਕਾਰੀ"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"ਤਿਆਰ ਹੈ"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"ਪ੍ਰਿੰਟਿੰਗ"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ਆਫ਼ਲਾਈਨ"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"ਪ੍ਰਿੰਟਰ ਦੀ ਜਾਂਚ ਕਰੋ"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-pl/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-pl/strings.xml
new file mode 100644
index 0000000..a1fd986
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-pl/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Domyślna usługa drukowania zapewnia opcje podstawowe. Dostępne są dodatkowe usługi drukowania z opcjami zaawansowanymi."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Dodatkowe usługi drukowania"</string>
+    <string name="yes" msgid="1887141030777316285">"Tak"</string>
+    <string name="unknown" msgid="2526777102391303730">"Nieznane"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nazwa drukarki"</string>
+    <string name="status" msgid="5948149021115901261">"Stan"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Formaty załadowanego papieru"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Poziomy materiałów"</string>
+    <string name="information" msgid="7896978544179559432">"Informacje"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Gotowa"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Drukuje"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Sprawdź drukarkę"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rBR/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rBR/strings.xml
new file mode 100644
index 0000000..c80286c
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rBR/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"O serviço de impressão padrão oferece opções básicas. Para acessar as opções avançadas, outros serviços de impressão estão disponíveis."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Serviços de impressão extras"</string>
+    <string name="yes" msgid="1887141030777316285">"Sim"</string>
+    <string name="unknown" msgid="2526777102391303730">"Desconhecido"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nome da impressora"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Tamanhos de papel carregados"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Níveis de fornecimento"</string>
+    <string name="information" msgid="7896978544179559432">"Informações"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Pronto"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Imprimindo"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Off-line"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Verificar impressora"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rPT/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rPT/strings.xml
new file mode 100644
index 0000000..5c095bd
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rPT/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"O serviço de impressão padrão oferece opções básicas. Para opções avançadas, estão disponíveis serviços de impressão adicionais."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Serviços de impressão adicionais"</string>
+    <string name="yes" msgid="1887141030777316285">"Sim"</string>
+    <string name="unknown" msgid="2526777102391303730">"Desconhecido"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nome da impressora"</string>
+    <string name="status" msgid="5948149021115901261">"Estado"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Tamanhos de papel carregados"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Níveis dos consumíveis"</string>
+    <string name="information" msgid="7896978544179559432">"Informações"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Pronta"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"A imprimir"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Verificar impressora"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-pt/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-pt/strings.xml
new file mode 100644
index 0000000..c80286c
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-pt/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"O serviço de impressão padrão oferece opções básicas. Para acessar as opções avançadas, outros serviços de impressão estão disponíveis."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Serviços de impressão extras"</string>
+    <string name="yes" msgid="1887141030777316285">"Sim"</string>
+    <string name="unknown" msgid="2526777102391303730">"Desconhecido"</string>
+    <string name="printer_name" msgid="386653719801075739">"Nome da impressora"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Tamanhos de papel carregados"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Níveis de fornecimento"</string>
+    <string name="information" msgid="7896978544179559432">"Informações"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Pronto"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Imprimindo"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Off-line"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Verificar impressora"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ro/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ro/strings.xml
new file mode 100644
index 0000000..a0c5068
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ro/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Serviciul de printare prestabilit oferă opțiuni de bază. Pentru opțiunile avansate sunt disponibile servicii de printare suplimentare."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Servicii de printare suplimentare"</string>
+    <string name="yes" msgid="1887141030777316285">"Da"</string>
+    <string name="unknown" msgid="2526777102391303730">"Necunoscut"</string>
+    <string name="printer_name" msgid="386653719801075739">"Numele imprimantei"</string>
+    <string name="status" msgid="5948149021115901261">"Stare"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Dimensiunile hârtiei încărcate"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Niveluri de aprovizionare"</string>
+    <string name="information" msgid="7896978544179559432">"Informații"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Gata"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Printare"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Verifică imprimanta"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ru/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ru/strings.xml
new file mode 100644
index 0000000..95748a4
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ru/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Служба печати по умолчанию включает базовый набор функций. Дополнительные возможности доступны в других службах."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Дополнительные службы печати"</string>
+    <string name="yes" msgid="1887141030777316285">"Да"</string>
+    <string name="unknown" msgid="2526777102391303730">"Неизвестно"</string>
+    <string name="printer_name" msgid="386653719801075739">"Название принтера"</string>
+    <string name="status" msgid="5948149021115901261">"Статус"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Размер загруженной бумаги"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Уровень расходных материалов"</string>
+    <string name="information" msgid="7896978544179559432">"Информация"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Можно использовать"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Печать"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Офлайн"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Проверьте принтер"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-si/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-si/strings.xml
new file mode 100644
index 0000000..aacfb86
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-si/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"පෙරනිමි මුද්‍රණ සේවාව මූලික විකල්ප සපයයි. උසස් විකල්ප සඳහා අමතර මුද්‍රණ සේවා තිබේ."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"අමතර මුද්‍රණ සේවා"</string>
+    <string name="yes" msgid="1887141030777316285">"ඔව්"</string>
+    <string name="unknown" msgid="2526777102391303730">"නොදනී"</string>
+    <string name="printer_name" msgid="386653719801075739">"මුද්‍රණ යන්ත්‍රයේ නම"</string>
+    <string name="status" msgid="5948149021115901261">"තත්ත්වය"</string>
+    <string name="media_ready" msgid="7205545458156298899">"පූරණ කරන ලද කඩදාසි ප්‍රමාණ"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"සැපයුම් මට්ටම්"</string>
+    <string name="information" msgid="7896978544179559432">"තොරතුරු"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"සූදානම්"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"මුද්‍රණය කිරීම්"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"නොබැඳි"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"මුද්‍රණ යන්ත්‍රය පරීක්ෂා කරන්න"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sk/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sk/strings.xml
new file mode 100644
index 0000000..fa519c6
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sk/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Predvolená tlačová služba poskytuje základné možnosti. V prípade potreby rozšírených možností sú k dispozícii ďalšie tlačové služby."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Ďalšie tlačové služby"</string>
+    <string name="yes" msgid="1887141030777316285">"Áno"</string>
+    <string name="unknown" msgid="2526777102391303730">"Neznáme"</string>
+    <string name="printer_name" msgid="386653719801075739">"Názov tlačiarne"</string>
+    <string name="status" msgid="5948149021115901261">"Stav"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Veľkosti vkladaného papiera"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Úrovne zásob"</string>
+    <string name="information" msgid="7896978544179559432">"Informácia"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Pripravené"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Tlač"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Kontrola tlačiarne"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sl/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sl/strings.xml
new file mode 100644
index 0000000..174fd1d
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sl/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Privzeta storitev tiskanja zagotavlja osnovne možnosti. Za napredne možnosti so na voljo dodatne storitve tiskanja."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Dodatne storitve tiskanja"</string>
+    <string name="yes" msgid="1887141030777316285">"Da"</string>
+    <string name="unknown" msgid="2526777102391303730">"Neznano"</string>
+    <string name="printer_name" msgid="386653719801075739">"Ime tiskalnika"</string>
+    <string name="status" msgid="5948149021115901261">"Stanje"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Naložene velikosti papirja"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Ravni oskrbe"</string>
+    <string name="information" msgid="7896978544179559432">"Informacije"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Pripravljeno"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Tiskanje"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Brez povezave"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Preveri tiskalnik"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sq/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sq/strings.xml
new file mode 100644
index 0000000..cfa27b2
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sq/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Shërbimi i parazgjedhur i printimit ofron opsionet bazë. Për opsionet e përparuara, ofrohen shërbime shtesë printimi."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Shërbime shtesë të printimit"</string>
+    <string name="yes" msgid="1887141030777316285">"Po"</string>
+    <string name="unknown" msgid="2526777102391303730">"I panjohur"</string>
+    <string name="printer_name" msgid="386653719801075739">"Emri i printerit"</string>
+    <string name="status" msgid="5948149021115901261">"Statusi"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Madhësitë e letrës së ngarkuar"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Nivelet e furnizimit"</string>
+    <string name="information" msgid="7896978544179559432">"Informacione"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Gati"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Po printon"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Kontrollo printerin"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sr/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sr/strings.xml
new file mode 100644
index 0000000..0b5dd7b
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sr/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Подразумевана услуга штампања пружа основне опције. За напредне опције су доступне додатне услуге штампања."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Додатне услуге штампања"</string>
+    <string name="yes" msgid="1887141030777316285">"Да"</string>
+    <string name="unknown" msgid="2526777102391303730">"Непознато"</string>
+    <string name="printer_name" msgid="386653719801075739">"Назив штампача"</string>
+    <string name="status" msgid="5948149021115901261">"Статус"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Уметнуте величине папира"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Нивои залиха"</string>
+    <string name="information" msgid="7896978544179559432">"Информације"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Спремно"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Штампање"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Офлајн"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Проверите штампач"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sv/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sv/strings.xml
new file mode 100644
index 0000000..c7a03be
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sv/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Standardutskriftstjänsten har de grundläggande alternativen. Ytterligare utskriftstjänster finns tillgängliga för avancerade alternativ."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Ytterligare utskriftstjänster"</string>
+    <string name="yes" msgid="1887141030777316285">"Ja"</string>
+    <string name="unknown" msgid="2526777102391303730">"Okänt"</string>
+    <string name="printer_name" msgid="386653719801075739">"Skrivarens namn"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Laddade pappersformat"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Tillgångsnivåer"</string>
+    <string name="information" msgid="7896978544179559432">"Information"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Klar"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Skriver ut"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Kontrollera skrivare"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sw/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sw/strings.xml
new file mode 100644
index 0000000..ad7900e
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sw/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Huduma chaguomsingi ya uchapishaji hutoa chaguo za msingi. Kwa chaguo za kina, huduma za ziada za uchapishaji zinapatikana."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Huduma za ziada za uchapishaji"</string>
+    <string name="yes" msgid="1887141030777316285">"Ndiyo"</string>
+    <string name="unknown" msgid="2526777102391303730">"Haijulikani"</string>
+    <string name="printer_name" msgid="386653719801075739">"Jina la printa"</string>
+    <string name="status" msgid="5948149021115901261">"Hali"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Ukubwa wa karatasi zilizopakiwa"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Viwango vya usambazaji"</string>
+    <string name="information" msgid="7896978544179559432">"Maelezo"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Tayari"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Inachapisha"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Nje ya mtandao"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Angalia printa"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ta/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ta/strings.xml
new file mode 100644
index 0000000..0177e9f
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ta/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"இயல்பு அச்சிடல் சேவை அடிப்படையான விருப்பங்களை வழங்குகிறது. மேம்பட்ட விருப்பங்களுக்கு, கூடுதல் பிரிண்ட் சேவைகள் கிடைக்கின்றன."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"கூடுதல் பிரிண்ட் சேவைகள்"</string>
+    <string name="yes" msgid="1887141030777316285">"ஆம்"</string>
+    <string name="unknown" msgid="2526777102391303730">"தெரியவில்லை"</string>
+    <string name="printer_name" msgid="386653719801075739">"பிரிண்ட்டர் பெயர்"</string>
+    <string name="status" msgid="5948149021115901261">"நிலை"</string>
+    <string name="media_ready" msgid="7205545458156298899">"ஏற்றப்பட்டிருக்கும் பேப்பர் அளவுகள்"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"சப்ளை நிலைகள்"</string>
+    <string name="information" msgid="7896978544179559432">"தகவல்கள்"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"தயார்"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"அச்சிடுகிறது"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ஆஃப்லைன்"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"பிரிண்ட்டரைச் சரிபாருங்கள்"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-te/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-te/strings.xml
new file mode 100644
index 0000000..03ea1ea
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-te/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ఆటోమేటిక్ ప్రింట్ సర్వీస్‌లో ప్రాథమిక ఆప్షన్‌ అందించబడతాయి. అధునాతన ఆప్షన్‌ల కోసం అదనపు ప్రింట్ సర్వీస్‌లు అందుబాటులో ఉన్నాయి."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"అదనపు ప్రింట్ సర్వీస్‌లు"</string>
+    <string name="yes" msgid="1887141030777316285">"అవును"</string>
+    <string name="unknown" msgid="2526777102391303730">"తెలియనిది"</string>
+    <string name="printer_name" msgid="386653719801075739">"ప్రింటర్ పేరు"</string>
+    <string name="status" msgid="5948149021115901261">"స్టేటస్"</string>
+    <string name="media_ready" msgid="7205545458156298899">"లోడ్ చేసిన పేపర్ సైజ్‌లు"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"సరఫరా స్థాయిలు"</string>
+    <string name="information" msgid="7896978544179559432">"సమాచారం"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"సిద్ధంగా ఉంది"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"ప్రింట్ చేస్తోంది"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ఆఫ్‌లైన్‌లో ఉంది"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"ప్రింటర్‌ను చెక్ చేయండి"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-th/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-th/strings.xml
new file mode 100644
index 0000000..51bffef
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-th/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"บริการการพิมพ์เริ่มต้นมีตัวเลือกพื้นฐานต่างๆ ส่วนบริการเพิ่มเติมเกี่ยวกับการพิมพ์จะมีตัวเลือกขั้นสูงพร้อมให้ใช้งาน"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"บริการเพิ่มเติมเกี่ยวกับการพิมพ์"</string>
+    <string name="yes" msgid="1887141030777316285">"ใช่"</string>
+    <string name="unknown" msgid="2526777102391303730">"ไม่ทราบ"</string>
+    <string name="printer_name" msgid="386653719801075739">"ชื่อเครื่องพิมพ์"</string>
+    <string name="status" msgid="5948149021115901261">"สถานะ"</string>
+    <string name="media_ready" msgid="7205545458156298899">"ขนาดกระดาษที่มีอยู่ในเครื่อง"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"ระดับของสิ่งต่างๆ ที่จำเป็นต่อการทำงาน"</string>
+    <string name="information" msgid="7896978544179559432">"ข้อมูล"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"พร้อมใช้งาน"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"กำลังพิมพ์"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"ออฟไลน์"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"ตรวจสอบเครื่องพิมพ์"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-tl/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-tl/strings.xml
new file mode 100644
index 0000000..a123d23
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-tl/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Nagbibigay ng mga basic na opsyon ang serbisyo sa default na pag-print. Para sa mga advanced na opsyon, available ang mga karagdagang serbisyo sa pag-print."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Mga karagdagang serbisyo sa pag-print"</string>
+    <string name="yes" msgid="1887141030777316285">"Oo"</string>
+    <string name="unknown" msgid="2526777102391303730">"Hindi alam"</string>
+    <string name="printer_name" msgid="386653719801075739">"Pangalan ng printer"</string>
+    <string name="status" msgid="5948149021115901261">"Status"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Mga laki ng papel na na-load"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Mga level ng supply"</string>
+    <string name="information" msgid="7896978544179559432">"Impormasyon"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Handa na"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Pag-print"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Suriin ang printer"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-tr/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-tr/strings.xml
new file mode 100644
index 0000000..fe55ce4
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-tr/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Varsayılan yazdırma hizmeti, temel seçenekler sağlar. Gelişmiş seçeneklerde ek yazdırma hizmetleri mevcuttur."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Ek yazdırma hizmetleri"</string>
+    <string name="yes" msgid="1887141030777316285">"Evet"</string>
+    <string name="unknown" msgid="2526777102391303730">"Bilinmiyor"</string>
+    <string name="printer_name" msgid="386653719801075739">"Yazıcı adı"</string>
+    <string name="status" msgid="5948149021115901261">"Durum"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Yüklenen kağıt boyutları"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Malzeme seviyeleri"</string>
+    <string name="information" msgid="7896978544179559432">"Bilgi"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Hazır"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Yazdırma"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Çevrimdışı"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Yazıcıyı kontrol et"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-uk/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-uk/strings.xml
new file mode 100644
index 0000000..55f41b9
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-uk/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Стандартний сервіс друку надає основні параметри. Розширені параметри доступні в додаткових сервісах друку."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Додаткові сервіси друку"</string>
+    <string name="yes" msgid="1887141030777316285">"Так"</string>
+    <string name="unknown" msgid="2526777102391303730">"Невідомо"</string>
+    <string name="printer_name" msgid="386653719801075739">"Назва принтера"</string>
+    <string name="status" msgid="5948149021115901261">"Статус"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Розміри завантаженого паперу"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Рівні витратних матеріалів"</string>
+    <string name="information" msgid="7896978544179559432">"Інформація"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Готово"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Друк"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Не в мережі"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Перевірте принтер"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ur/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ur/strings.xml
new file mode 100644
index 0000000..a92d2c4
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ur/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ڈیفالٹ پرنٹ سروس بنیادی اختیارات فراہم کرتا ہے۔ جدید اختیارات کے لیے، اضافی پرنٹ سروسز دستیاب ہیں۔"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"اضافی پرنٹ سروسز"</string>
+    <string name="yes" msgid="1887141030777316285">"ہاں"</string>
+    <string name="unknown" msgid="2526777102391303730">"نامعلوم"</string>
+    <string name="printer_name" msgid="386653719801075739">"پرنٹر کا نام"</string>
+    <string name="status" msgid="5948149021115901261">"صورتحال"</string>
+    <string name="media_ready" msgid="7205545458156298899">"لوڈ کردہ کاغذ کے سائزز"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"سپلائی لیولز"</string>
+    <string name="information" msgid="7896978544179559432">"معلومات"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"تیار"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"پرنٹنگ"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"آف لائن"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"پرنٹر چیک کریں"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-uz/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-uz/strings.xml
new file mode 100644
index 0000000..a3e4bf0
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-uz/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Standart chop etish xizmati taqdim qiladigan oddiy variantlar. Kengaytirilgan parametrlar uchun qoʻshimcha chop etish xizmatlari mavjud."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Qoʻshimcha chop etish xizmatlari"</string>
+    <string name="yes" msgid="1887141030777316285">"Ha"</string>
+    <string name="unknown" msgid="2526777102391303730">"Noaniq"</string>
+    <string name="printer_name" msgid="386653719801075739">"Printer nomi"</string>
+    <string name="status" msgid="5948149021115901261">"Holati"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Yuklangan qogʻoz oʻlchamlari"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Sarf materiallari darajalari"</string>
+    <string name="information" msgid="7896978544179559432">"Axborot"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Tayyor"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Chop etish"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Oflayn"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Printerni tekshirish"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-vi/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-vi/strings.xml
new file mode 100644
index 0000000..37ee9a3
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-vi/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Dịch vụ in mặc định đưa ra các lựa chọn cơ bản. Hiện có các dịch vụ in khác trong các lựa chọn nâng cao."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Dịch vụ in bổ sung"</string>
+    <string name="yes" msgid="1887141030777316285">"Có"</string>
+    <string name="unknown" msgid="2526777102391303730">"Không xác định"</string>
+    <string name="printer_name" msgid="386653719801075739">"Tên máy in"</string>
+    <string name="status" msgid="5948149021115901261">"Trạng thái"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Khổ giấy đã nạp"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Mức cung ứng"</string>
+    <string name="information" msgid="7896978544179559432">"Thông tin"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Sẵn sàng"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Đang in"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Không có mạng"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Kiểm tra máy in"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rCN/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rCN/strings.xml
new file mode 100644
index 0000000..a03a673
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rCN/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"默认打印服务会提供基本选项。如需高级选项，请使用其他打印服务。"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"其他打印服务"</string>
+    <string name="yes" msgid="1887141030777316285">"是"</string>
+    <string name="unknown" msgid="2526777102391303730">"未知"</string>
+    <string name="printer_name" msgid="386653719801075739">"打印机名称"</string>
+    <string name="status" msgid="5948149021115901261">"状态"</string>
+    <string name="media_ready" msgid="7205545458156298899">"装入的纸张大小"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"耗材等级"</string>
+    <string name="information" msgid="7896978544179559432">"信息"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"准备就绪"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"正在打印"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"离线"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"检查打印机"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rHK/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rHK/strings.xml
new file mode 100644
index 0000000..f7e7191
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rHK/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"預設列印服務提供基本選項。如需進階選項，可選用額外列印服務。"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"額外列印服務"</string>
+    <string name="yes" msgid="1887141030777316285">"是"</string>
+    <string name="unknown" msgid="2526777102391303730">"不明"</string>
+    <string name="printer_name" msgid="386653719801075739">"打印機名稱"</string>
+    <string name="status" msgid="5948149021115901261">"狀態"</string>
+    <string name="media_ready" msgid="7205545458156298899">"已載入的紙張大小"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"供應等級"</string>
+    <string name="information" msgid="7896978544179559432">"資訊"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"準備就緒"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"列印"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"離線"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"檢查打印機"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rTW/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rTW/strings.xml
new file mode 100644
index 0000000..ee48704
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rTW/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"預設列印服務會提供基本選項，如需進階選項，請使用其他列印服務。"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"其他列印服務"</string>
+    <string name="yes" msgid="1887141030777316285">"是"</string>
+    <string name="unknown" msgid="2526777102391303730">"不明"</string>
+    <string name="printer_name" msgid="386653719801075739">"印表機名稱"</string>
+    <string name="status" msgid="5948149021115901261">"狀態"</string>
+    <string name="media_ready" msgid="7205545458156298899">"裝入紙張大小"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"供應等級"</string>
+    <string name="information" msgid="7896978544179559432">"資訊"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"就緒"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"列印中"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"離線"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"檢查印表機"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-zu/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-zu/strings.xml
new file mode 100644
index 0000000..aeb2dd1
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-zu/strings.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+     Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Isevisi yokuphrinta ezenzakalelayo inikeza okungakhethwa kukho okuyisisekelo. Ngokungakhethwa kukho okuthuthukisiwe izinsiza zokuphrinta ezengeziwe ziyatholakala."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Amasevisi engeziwe wokuphrinta"</string>
+    <string name="yes" msgid="1887141030777316285">"Yebo"</string>
+    <string name="unknown" msgid="2526777102391303730">"Akwaziwa"</string>
+    <string name="printer_name" msgid="386653719801075739">"Igama lephrinta"</string>
+    <string name="status" msgid="5948149021115901261">"Isimo"</string>
+    <string name="media_ready" msgid="7205545458156298899">"Osayizi bephepha abalayishiwe"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Amazinga okuhlinzeka"</string>
+    <string name="information" msgid="7896978544179559432">"Ulwazi"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Isikulungele"</string>
+    <string name="printer_state__printing" msgid="596624975473301735">"Iyaphrinta"</string>
+    <string name="printer_state__offline" msgid="6755924316852857893">"Okungaxhunyiwe kwi-inthanethi"</string>
+    <string name="printer_state__check_printer" msgid="4854932117258619033">"Hlola iphrinta"</string>
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values/dimens.xml b/res/flag(com.android.bips.flags.printer_info_details)/values/dimens.xml
new file mode 100644
index 0000000..7a47a8a
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values/dimens.xml
@@ -0,0 +1,32 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+     Copyright (C) 2024 Mopria Alliance, Inc.
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
+<resources>
+    <!-- Marker item -->
+    <dimen name="corner_radius">24dp</dimen>
+    <dimen name="marker_item_height">20dp</dimen>
+    <dimen name="mopria_margin_1dp">1dp</dimen>
+    <dimen name="mopria_padding_2dp">2dp</dimen>
+    <dimen name="mopria_padding_5dp">5dp</dimen>
+    <dimen name="mopria_padding_10dp">10dp</dimen>
+    <dimen name="mopria_padding_12dp">12dp</dimen>
+    <dimen name="mopria_padding_18dp">18dp</dimen>
+    <dimen name="mopria_width_0_dp">0dp</dimen>
+    <dimen name="linear_progress_bar_width">100dp</dimen>
+    <dimen name="linear_progress_bar_height">24dp</dimen>
+</resources>
\ No newline at end of file
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values/strings.xml
new file mode 100644
index 0000000..afb905f
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values/strings.xml
@@ -0,0 +1,39 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2025 The Android Open Source Project
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
+<resources xmlns:android="http://schemas.android.com/apk/res/android" xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+
+    <!-- Explain purpose of recommendation fragment [CHAR LIMIT=UNLIMITED] -->
+    <string name="recommendation_summary_new">The default print service provides basic options. For advanced options additional print services are available.</string>
+    <!-- Heading for link to services that are not currently installed, but recommended [CHAR LIMIT=UNLIMITED] -->
+    <string name="recommendation_link">Additional print services</string>
+
+    <!-- Printer Information Screen Strings -->
+    <string name="yes">Yes</string>
+    <string name="unknown">Unknown</string>
+    <string name="printer_name">Printer name</string>
+    <string name="status">Status</string>
+    <string name="media_ready">Loaded paper sizes</string>
+    <string name="supply_levels">Supply levels</string>
+    <string name="information">Information</string>
+    <string name="printer_ready">Ready</string>
+    <!-- Printer status messages-->
+    <string name="printer_state__printing">Printing</string>
+    <string name="printer_state__offline">Offline</string>
+    <string name="printer_state__check_printer">Check printer</string>
+
+</resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/xml/more_options_prefs_new.xml b/res/flag(com.android.bips.flags.printer_info_details)/xml/more_options_prefs_new.xml
new file mode 100644
index 0000000..957a624
--- /dev/null
+++ b/res/flag(com.android.bips.flags.printer_info_details)/xml/more_options_prefs_new.xml
@@ -0,0 +1,34 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2025 The Android Open Source Project
+     Copyright (C) 2025 Mopria Alliance, Inc.
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
+<PreferenceScreen
+    xmlns:android="http://schemas.android.com/apk/res/android">
+    <PreferenceCategory
+        android:key="recommendation_category"
+        android:title="@string/recommendations_heading"
+        android:persistent="false"
+        android:order="0"
+        android:featureFlag="com.android.bips.flags.printer_info_details" />
+
+    <Preference
+        android:key="manage"
+        android:title="@string/recommendation_manage"
+        android:icon="@drawable/ic_settings_gear"
+        android:persistent="false"
+        android:order="1"
+        android:featureFlag="com.android.bips.flags.printer_info_details" />
+</PreferenceScreen>
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 3a09a7c..ec62acf 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Koppel via Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Koppel via huidige netwerk by <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Die verstekdrukdiens verskaf basiese opsies. Ander opsies vir hierdie drukker kan dalk van \'n ander drukdiens af beskikbaar wees."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Aanbevole dienste"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Aanbevole dienste"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Kies om te installeer"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Kies om te aktiveer"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Bestuur dienste"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Bestuur dienste"</string>
     <string name="security" msgid="2279008326210305401">"Sekuriteit"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Hierdie drukker het \'n nuwe sekuriteitsertifikaat verskaf, of \'n ander toestel boots dit tans na. Aanvaar die nuwe sertifikaat?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Hierdie drukker aanvaar nie meer geënkripteerde take nie. Hou aan druk?"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index ffa8766..6223e40 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"በWi-Fi Direct በኩል ያገናኛል"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"አሁን ባለ አውታረ መረብ በኩል በ<xliff:g id="IP_ADDRESS">%1$s</xliff:g> ላይ ያገናኛል"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ነባሪው የህትመት አገልግሎት መሠረታዊ አማራጮችን ያቀርባል። ሌሎች የዚህ አታሚ አማራጮች ከሌላ የአታሚ አገልግሎት ሊገኙ ይችላሉ።"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"የሚመከሩ አገልግሎቶች"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"የሚመከሩ አገልግሎቶች"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ለመጫን ይምረጡ"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"ለማንቃት ይምረጡ"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"አገልግሎቶችን ያቀናብሩ"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"አገልግሎቶችን አስተዳድር"</string>
     <string name="security" msgid="2279008326210305401">"ደኅንነት"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ይህ አታሚ አዲስ የደህንነት እውቅና ማረጋገጫ አቅርቧል፣ ወይም ሌላ መሣሪያ እያስመሰለው ነው። አዲሱ የእውቅና ማረጋገጫ ይቀበሉ?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"ይህ አታሚ ከእንግዲህ የተመሰጠሩ ስራዎችን አይቀበልም። ማተም ይቀጥሉ?"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index efabce1..acdb4e9 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"‏يتم الاتصال عبر اتصال Wi-Fi مباشر."</string>
     <string name="connects_via_network" msgid="5990041581556733898">"يتم الاتصال عبر الشبكة الحالية باستخدام العنوان <xliff:g id="IP_ADDRESS">%1$s</xliff:g>."</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"تقدم \"خدمة النسبة التلقائية للصفحات المطبوعة\" خيارات أساسية. وقد تتوفر خيارات أخرى لهذا الطابعة من خدمة طباعة أخرى."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"الخدمات الموصى بها"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"الخدمات الموصّى بها"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"اختيار للتثبيت"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"اختيار للتفعيل"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"إدارة الخدمات"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"إدارة الخدمات"</string>
     <string name="security" msgid="2279008326210305401">"الأمان"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"قدّمت هذه الطابعة شهادة أمان جديدة، أو هناك جهاز آخر يمثل وظيفتها. هل توافق على الشهادة الجديدة؟"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"لم تعُد هذه الطابعة تقبل المهام المشفّرة. هل تريد متابعة الطباعة؟"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 2b7a15a..eb9256d 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"ৱাই-ফাই ডাইৰেক্টৰ জৰিয়তে সংযোগ কৰে"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> ঠিকনাত চলিত নেটৱৰ্কৰ জৰিয়তে সংযোগ কৰে"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ডিফ’ল্ট প্ৰিণ্ট সেৱাটোৱে সাধাৰণ বিকল্পসমূহ প্ৰদান কৰে। এই প্ৰিণ্টাৰটোৰ অন্য বিকল্পসমূহ বেলেগ এটা প্ৰিণ্ট সেৱাৰ পৰা ল’ব পৰা যাব পাৰে।"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"চুপাৰিছ কৰা সেৱাসমূহ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"চুপাৰিছ কৰা সেৱাসমূহ"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ইনষ্টল কৰিবলৈ বাছনি কৰক"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"সক্ষম কৰিবলৈ বাছনি কৰক"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"সেৱাসমূহ পৰিচালনা কৰক"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"সেৱা পৰিচালনা কৰক"</string>
     <string name="security" msgid="2279008326210305401">"সুৰক্ষা"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"এই প্ৰিণ্টাৰটোৱে এখন নতুন সুৰক্ষা প্ৰমাণপত্ৰ যোগান ধৰিছে বা আন এটা ডিভাইচে সেইটোৰ ভাও ধৰিছে। নতুন প্ৰমাণপত্ৰখন গ্ৰহণ কৰিবনে?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"প্ৰিণ্টাৰটোৱে আৰু এনক্ৰিপ্ট কৰা কার্য সমথর্ন নকৰে প্ৰিণ্ট কৰা কার্য অব্যাহত ৰাখিবনে?"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 91be810..eabd093 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct ilə qoşulur"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Cari şəbəkə ilə <xliff:g id="IP_ADDRESS">%1$s</xliff:g> ünvanında qoşulur"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Standart çap xidməti təməl variantları təmin edir. Bu printerin digər variantları başqa çap xidmətindədir."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Tövsiyə olunan xidmətlər"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Tövsiyə olunan xidmətlər"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Quraşdırmaq üçün seçin"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Aktiv etmək üçün seçin"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Xidmətləri idarə edin"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Xidmətləri idarə edin"</string>
     <string name="security" msgid="2279008326210305401">"Güvənlik"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Bu printer yeni sertifikat təqdim etdi və ya digər cihaz onun şəxsiyyətini oğurlayır. Yeni sertifikat qəbul edilsin?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Bu printer artıq şifrələnmiş işləri qəbul etmir. Çapa davam edilsin?"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 2e938c8..5465f42 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Povezuje se preko WiFi Direct-a"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Povezuje se preko trenutne mreže pomoću IP adrese <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Podrazumevana usluga štampanja pruža osnovne opcije. Ostale opcije ovog štampača su možda dostupne u drugoj usluzi štampanja."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Preporučene usluge"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Preporučene usluge"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Izaberite da biste instalirali"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Izaberite da biste omogućili"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Upravljaj uslugama"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Upravljajte uslugama"</string>
     <string name="security" msgid="2279008326210305401">"Bezbednost"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Ovaj štampač pruža novi bezbednosni sertifikat ili se neki drugi uređaj lažno predstavlja kao on. Želite li da prihvatite novi sertifikat?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Ovaj štampač više ne prihvata šifrovane zadatke. Želite li da nastavite sa štampanjem?"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index fa78b12..d60d74d 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Падключэнне праз Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Падключэнне праз бягучую сетку па адрасе <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Стандартная служба друку забяспечвае асноўныя параметры друку. Іншыя параметры для гэтага прынтара можна задаць у іншых службах друку."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Рэкамендаваныя службы"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Рэкамендаваныя сэрвісы"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Выберыце для ўсталёўкі"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Выберыце, каб уключыць"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Кіраваць службамі"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Кіраваць сэрвісамі"</string>
     <string name="security" msgid="2279008326210305401">"Бяспека"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Гэты прынтар мае новы сертыфікат бяспекі, ці пад яго выглядам працуе іншая прылада. Прыняць новы сертыфікат?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Гэты прынтар больш не прымае зашыфраваныя заданні. Прадоўжыць друкаванне?"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 9833d96..c22eba8 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Свързва се чрез Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Свързва се чрез текущата мрежа на адрес <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Услугата за отпечатване по подразбиране предоставя основни опции. Още опции за този принтер може да са налице в друга услуга за печат."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Препоръчителни услуги"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Препоръчителни услуги"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Изберете, за да инсталирате"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Изберете, за да активирате"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Управление на услугите"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Управление на услугите"</string>
     <string name="security" msgid="2279008326210305401">"Сигурност"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Този принтер предостави нов сертификат за сигурност или друго устройство се представя за него. Приемате ли новия сертификат?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Този принтер вече не приема шифровани задания. Искате ли да продължите да отпечатвате?"</string>
@@ -75,5 +75,5 @@
     <string name="disable_wifi_direct" msgid="4824677957241687577">"Wi-Fi Direct: Деакт."</string>
     <string name="wifi_direct_permission_rationale" msgid="4671416845852665202">"За да намира принтери в близост, стандартната услуга за отпечатване се нуждае от съответното разрешение."</string>
     <string name="fix" msgid="7784394272611365393">"Разрешение: Преглед"</string>
-    <string name="print" msgid="7851318072404916362">"Отпечатване"</string>
+    <string name="print" msgid="7851318072404916362">"Отпечат­ване"</string>
 </resources>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index bfa968a..0335804 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"ওয়াই-ফাই ডাইরেক্টের মাধ্যমে সংযুক্ত হয়"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"বর্তমান নেটওয়ার্কের মাধ্যমে <xliff:g id="IP_ADDRESS">%1$s</xliff:g> অ্যাড্রেসে সংযুক্ত হয়"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ডিফল্ট প্রিন্টিং পরিষেবার প্রাথমিক বিকল্প। এই প্রিন্টারের জন্য অন্যান্য বিকল্প অন্য প্রিন্ট পরিষেবার সাথে উপলভ্য হতে পারে।"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"সাজেস্ট করা পরিষেবা"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"সাজেস্ট করা পরিষেবা"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ইনস্টল করতে বেছে নিন"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"চালু করতে বেছে নিন"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"পরিষেবা ম্যানেজ করুন"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"পরিষেবা ম্যানেজ করুন"</string>
     <string name="security" msgid="2279008326210305401">"নিরাপত্তা"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"এই প্রিন্টার একটি নতুন নিরাপত্তার সার্টিফিকেট দেবে, অথবা ডিভাইস থেকে এটি ব্যবহার করা হচ্ছে। নতুন সার্টিফিকেট গ্রহণ করতে চান?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"এই প্রিন্টারের মাধ্যমে আর এনক্রিপ্ট করা ডকুমেন্ট প্রিন্ট করা যাবে না। প্রিন্টিং করা চালিয়ে যেতে চান?"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 79606fb..2f42a75 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Povezivanje putem opcije WiFi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Povezivanje putem trenutne mreže na <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Zadana usluga štampanja pruža osnovne opcije. Moguće je da su ostale opcije za ovaj štampač dostupne u drugoj usluzi štampanja."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Preporučene usluge"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Preporučene usluge"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Odaberite da instalirate"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Odaberite da omogućite"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Upravljanje uslugama"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Upravljajte uslugama"</string>
     <string name="security" msgid="2279008326210305401">"Sigurnost"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Ovaj štampač je pružio novu potvrdu sigurnosti ili ga drugi uređaj imitira. Prihvatiti novu potvrdu?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Ovaj štampač više ne prihvata šifrirane zadatke. Nastaviti štampati?"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index b4c0c4a..859fffc 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Es connecta per Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Es connecta a través de la xarxa actual a l\'adreça IP <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"El servei d\'impressió predeterminat ofereix algunes opcions bàsiques. Pot ser que hi hagi més opcions disponibles per a aquesta impressora en un altre servei d\'impressió."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Serveis recomanats"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Serveis recomanats"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Selecciona\'n un per instal·lar-lo"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecciona\'n per activar-lo"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Gestiona els serveis"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Gestiona els serveis"</string>
     <string name="security" msgid="2279008326210305401">"Seguretat"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Aquesta impressora ha proporcionat un certificat de seguretat nou o bé hi ha un altre dispositiu suplantant-la. Vols acceptar el certificat nou?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Aquesta impressora ja no accepta tasques encriptades. Vols continuar imprimint?"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 71da51e..a4e10c7 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Připojení prostřednictvím Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Připojení prostřednictvím stávající sítě s IP adresou <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Výchozí služba tisku nabízí základní možnosti. Další možnosti mohou být k dispozici z jiné služby tisku."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Doporučené služby"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Doporučené služby"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Vyberte, co nainstalovat"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Vyberte, co aktivovat"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Spravovat služby"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Spravovat služby"</string>
     <string name="security" msgid="2279008326210305401">"Zabezpečení"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Tato tiskárna poskytla nový bezpečnostní certifikát, nebo se za ni vydává jiné zařízení. Chcete nový certifikát přijmout?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Tato tiskárna už nepřijímá šifrované tiskové úlohy. Pokračovat v tisku?"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 42fa76f..116300c 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Opretter forbindelse via Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Opretter forbindelse via netværk med adressen <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Tjenesten Standardudskrivning giver dig grundlæggende valgmuligheder. Du kan muligvis få adgang til andre muligheder for denne printer via en anden udskrivningstjeneste."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Anbefalede tjenester"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Anbefalede tjenester"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Vælg for at installere"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Vælg for at aktivere"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Administrer tjenester"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Administrer tjenester"</string>
     <string name="security" msgid="2279008326210305401">"Sikkerhed"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Denne printer angav et nyt sikkerhedscertifikat, eller en anden enhed efterligner den. Vil du acceptere det nye certifikat?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Denne printer understøtter ikke længere krypterede jobs. Vil du fortsætte med at udskrive?"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 03a7c3b..eb97446 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Verbindung über Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Verbindung über das aktuelle Netzwerk mit der IP-Adresse <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Der Standarddruckdienst bietet Basisoptionen. Ein anderer Druckdienst hat für diesen Drucker möglicherweise weitere Optionen."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Empfohlene Dienste"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Empfohlene Dienste"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Zum Installieren auswählen"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Zum Aktivieren auswählen"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Dienste verwalten"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Dienste verwalten"</string>
     <string name="security" msgid="2279008326210305401">"Sicherheit"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Dieser Drucker hat ein neues Sicherheitszertifikat oder ein anderes Gerät nutzt dessen Identität. Möchtest du das neue Zertifikat akzeptieren?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Dieser Drucker akzeptiert keine verschlüsselten Aufträge mehr. Weiter drucken?"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index c845747..6d11322 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Συνδέεται μέσω του Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Συνδέεται μέσω του τρέχοντος δικτύου στη διεύθυνση <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Η υπηρεσία Προεπιλεγμένης εκτύπωσης παρέχει βασικές επιλογές. Κάποια άλλη υπηρεσία εκτύπωσης ενδέχεται να προσφέρει άλλες επιλογές για αυτόν τον εκτυπωτή."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Προτεινόμενες υπηρεσίες"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Προτεινόμενες υπηρεσίες"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Επιλέξτε για εγκατάσταση"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Επιλέξτε για ενεργοποίηση"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Διαχείριση υπηρεσιών"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Διαχείριση υπηρεσιών"</string>
     <string name="security" msgid="2279008326210305401">"Ασφάλεια"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Αυτός ο εκτυπωτής παρείχε ένα νέο πιστοποιητικό ασφαλείας ή κάποια άλλη συσκευή έχει κλέψει τα στοιχεία ταυτότητάς του. Αποδοχή του νέου πιστοποιητικού ασφαλείας;"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Αυτός ο εκτυπωτής δεν δέχεται πλέον κρυπτογραφημένες εργασίες. Να συνεχιστεί η εκτύπωση;"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 8cd9ba3..ede974b 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Connects via Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Connects via current network at <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"The default print service provides basic options. Other options for this printer may be available from another print service."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Recommended services"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Recommended services"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Select to install"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Select to enable"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Manage services"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Manage services"</string>
     <string name="security" msgid="2279008326210305401">"Security"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"This printer provided a new security certificate, or another device is impersonating it. Accept the new certificate?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"This printer no longer accepts encrypted jobs. Continue printing?"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 7771e9f..386039d 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Connects via Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Connects via current network at <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"The Default Print Service provides basic options. Other options for this printer may be available from another print service."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Recommended services"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Recommended Services"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Select to install"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Select to enable"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Manage services"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Manage Services"</string>
     <string name="security" msgid="2279008326210305401">"Security"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"This printer provided a new security certificate, or another device is impersonating it. Accept the new certificate?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"This printer no longer accepts encrypted jobs. Continue printing?"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 8cd9ba3..ede974b 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Connects via Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Connects via current network at <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"The default print service provides basic options. Other options for this printer may be available from another print service."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Recommended services"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Recommended services"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Select to install"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Select to enable"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Manage services"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Manage services"</string>
     <string name="security" msgid="2279008326210305401">"Security"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"This printer provided a new security certificate, or another device is impersonating it. Accept the new certificate?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"This printer no longer accepts encrypted jobs. Continue printing?"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index feb2fc1..207ab38 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Connects via Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Connects via current network at <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"The default print service provides basic options. Other options for this printer may be available from another print service."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Recommended services"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Recommended services"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Select to install"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Select to enable"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Manage services"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Manage services"</string>
     <string name="security" msgid="2279008326210305401">"Security"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"This printer provided a new security certificate, or another device is impersonating it. Accept the new certificate?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"This printer no longer accepts encrypted jobs. Continue printing?"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 6287dd0..cfc5614 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Se conecta mediante Wi-Fi directo"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Se conecta mediante la red actual a <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"El servicio de impresión predeterminado brinda opciones básicas. Otros servicios pueden brindar opciones adicionales para esta impresora."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Servicios recomendados"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Servicios recomendados"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Selecciona para instalar"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecciona para habilitar"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Administrar servicios"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Administrar servicios"</string>
     <string name="security" msgid="2279008326210305401">"Seguridad"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Esta impresora emitió un nuevo certificado de seguridad, o bien está suplantándola otro dispositivo. ¿Quieres aceptar el nuevo certificado?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Esta impresora ya no acepta tareas encriptadas. ¿Quieres continuar con la impresión?"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 3ad3ead..4712795 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Se conecta a través de Wi‑Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Se conecta a través de la red actual con la dirección IP <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"El servicio de impresión predeterminado solo tiene opciones básicas. Es posible que en otro servicio de impresión haya más opciones disponibles para esta impresora."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Servicios recomendados"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Servicios recomendados"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Selecciona lo que quieras instalar"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecciona lo que quieras habilitar"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Gestionar servicios"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Gestionar servicios"</string>
     <string name="security" msgid="2279008326210305401">"Seguridad"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Esta impresora ha proporcionado un nuevo certificado de seguridad, o bien otro dispositivo está suplantándola. ¿Quieres aceptar el nuevo certificado?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Esta impresora ya no acepta tareas cifradas. ¿Quieres continuar con la impresión?"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index c2845b9..2b5ef69 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Ühendab funktsiooni Wi-Fi Direct kaudu"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Ühendab praeguse võrgu kaudu IP-aadressil <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Printimise vaiketeenus hõlmab põhivalikuid. Printeri muud valikud võivad olla saadaval muu printimisteenuse kaudu."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Soovitatud teenused"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Soovitatud teenused"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Valige installitavad teenused"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Valige lubamiseks"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Teenuste haldamine"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Teenuste haldamine"</string>
     <string name="security" msgid="2279008326210305401">"Turvalisus"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"See printer esitas uue turvasertifikaadi mõni teine seade esineb selle printerina. Kas nõustuda uue sertifikaadiga?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"See printer ei aktsepteeri enam krüpteeritud töid. Kas jätkata printimist?"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 560a6db..cf3417f 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct zerbitzuaren bidez konektatzen da"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Sare honen bidez konektatzen da (<xliff:g id="IP_ADDRESS">%1$s</xliff:g>)"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Inprimatze-zerbitzu lehenetsiak oinarrizko aukerak eskaintzen ditu. Baliteke beste inprimatze-zerbitzu batek bestelako aukerak eskaintzea inprimagailurako."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Gomendatutako zerbitzuak"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Gomendatutako zerbitzuak"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Hautatu instalatzeko"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Hautatu gaitzeko"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Kudeatu zerbitzuak"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Kudeatu zerbitzuak"</string>
     <string name="security" msgid="2279008326210305401">"Segurtasuna"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Inprimagailuak segurtasun-ziurtagiri berri bat eman du, edo beste gailu bat ziurtagiria faltsutzen ari da. Ziurtagiri berria onartu nahi duzu?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Inprimagailu honek ez du jada onartzen lan enkriptaturik. Aurrera egin nahi duzu inprimaketarekin?"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index a500493..595e5ab 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"‏ازطریق Wi-Fi بی‌واسطه متصل می‌شود"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"ازطریق شبکه فعلی به نشانی <xliff:g id="IP_ADDRESS">%1$s</xliff:g> متصل می‌شود"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"«سرویس چاپ پیش‌فرض» گزینه‌های اصلی را ارائه می‌کند. ممکن است سایر گزینه‌ها برای این چاپگر از سرویس چاپ دیگری دردسترس باشد."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"خدمات توصیه‌شده"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"سرویس‌های توصیه‌شده"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"برای نصب انتخاب کنید"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"برای فعال کردن، انتخاب کنید"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"مدیریت سرویس‌ها"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"مدیریت سرویس‌ها"</string>
     <string name="security" msgid="2279008326210305401">"امنیت"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"این چاپگر گواهینامه امنیتی جدیدی ارائه کرده است، یا دستگاه دیگری درحال جعل کردن هویت آن است. گواهینامه جدید پذیرفته شود؟"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"این چاپگر دیگر کارهای رمزگذاری‌شده را نمی‌پذیرد. به چاپ کردن ادامه می‌دهید؟"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 088d1fb..0fc6eac 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Yhteys muodostettu Wi-Fi Directin kautta"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Yhdistetään nykyisen verkon kautta osoitteessa <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Oletustulostuspalveluun kuuluu perusvaihtoehdot. Muita vaihtoehtoja voi olla saatavilla toisissa tulostuspalveluissa."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Suositellut palvelut"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Suositellut palvelut"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Asenna valitsemalla"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Ota käyttöön valitsemalla"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Hallinnoi palveluita"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Ylläpidä palveluita"</string>
     <string name="security" msgid="2279008326210305401">"Suojaus"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Tämä tulostin antoi uuden turvallisuusvarmenteen, tai toinen laite esiintyy tulostimena. Hyväksytäänkö uusi varmenne?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Tämä tulostin ei enää hyväksy salattuja töitä. Jatketaanko tulostamista?"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 3afee64..fc021b1 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Se connecte par Wi-Fi direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Se connecte à l\'aide du réseau actuel, avec l\'adresse <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Le service d\'impression par défaut offre des options de base. Les autres options de cette imprimante pourraient être accessibles à l\'aide d\'un autre service d\'impression."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Services recommandés"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Services recommandés"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Sélectionnez un service pour l\'installer"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Sélectionnez un service pour l\'activer"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Gérer les services"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Gérer les services"</string>
     <string name="security" msgid="2279008326210305401">"Sécurité"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Cette imprimante a fourni un nouveau certificat de sécurité, ou bien un autre appareil tente d\'usurper son identité. Accepter le nouveau certificat?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Cette imprimante n\'accepte plus les tâches chiffrées. Continuer l\'impression?"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 328454c..6d07b7a 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Se connecte via Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Se connecte via le réseau actuel à l\'adresse <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Le service d\'impression par défaut offre des options de base. Les autres options de cette imprimante peuvent être disponibles via un autre service d\'impression."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Services recommandés"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Services recommandés"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Sélectionner pour installer"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Appuyer ici pour activer"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Gérer les services"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Gérer les services"</string>
     <string name="security" msgid="2279008326210305401">"Sécurité"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Cette imprimante a fourni un nouveau certificat de sécurité, ou bien un autre appareil a usurpé son identité. Voulez-vous accepter le nouveau certificat ?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Cette imprimante n\'accepte plus les tâches chiffrées. Poursuivre l\'impression ?"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 818c8b9..38f78d4 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Conéctase a través de Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Conéctase a través da rede actual ao enderezo IP <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"O servizo de impresión predeterminado só ten opcións básicas. É posible que noutro servizo de impresión haxa máis opcións dispoñibles para esta impresora."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Servizos recomendados"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Servizos recomendados"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Selecciona o que queiras instalar"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecciona o que queiras activar"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Xestionar servizos"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Xestionar servizos"</string>
     <string name="security" msgid="2279008326210305401">"Seguranza"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Esta impresora proporcionou un novo certificado de seguranza ou ben outro dispositivo está suplantando a súa identidade. Queres aceptar o novo certificado?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Esta impresora xa non acepta traballos encriptados. Queres continuar coa impresión?"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 890a38b..f3271e0 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct મારફતે કનેક્ટ થશે"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"હાલના નેટવર્ક મારફતે <xliff:g id="IP_ADDRESS">%1$s</xliff:g> પર કનેક્ટ થશે"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ડિફૉલ્ટ પ્રિન્ટ સેવા મૂળભૂત વિકલ્પો આપે છે. આ પ્રિન્ટર માટેના અન્ય વિકલ્પો બીજી પ્રિન્ટ સેવામાંથી ઉપલબ્ધ હોઈ શકે છે."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"સુઝાવ આપેલી સેવાઓ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"સુઝાવ આપેલી સેવાઓ"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ઇન્સ્ટૉલ કરવા માટે પસંદ કરો"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"ચાલુ કરવા માટે પસંદ કરો"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"સેવાઓ મેનેજ કરો"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"સેવાઓ મેનેજ કરો"</string>
     <string name="security" msgid="2279008326210305401">"સુરક્ષા"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"આ પ્રિન્ટરે નવું સુરક્ષા પ્રમાણપત્ર રજૂ કર્યું છે અથવા કોઈ અન્ય ડિવાઇસ ખોટી ઓળખ રજૂ કરી રહ્યું છે. શું નવા પ્રમાણપત્રનો સ્વીકાર કરીએ?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"આ પ્રિન્ટર હવે કોઈ એન્ક્રિપ્ટ કરેલા કાર્યનો સ્વીકાર કરતું નથી. પ્રિન્ટ કરવાનું ચાલુ રાખીએ?"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 40c17ce..967b26b 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -17,7 +17,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="3551052199033657984">"डिफ़ॉल्ट प्रिंट सेवा"</string>
+    <string name="app_name" msgid="3551052199033657984">"प्रिंट करने की डिफ़ॉल्ट सेवा"</string>
     <string name="printer_busy" msgid="8604311528104955859">"व्यस्त"</string>
     <string name="printer_out_of_paper" msgid="4882186432807703877">"कागज़ नहीं है"</string>
     <string name="printer_out_of_ink" msgid="7361897651097675464">"इंक खत्म है"</string>
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct के ज़रिए कनेक्ट किया जाता है"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> पर मौजूदा नेटवर्क के ज़रिए कनेक्ट किया जाता है"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"डिफ़ॉल्ट रूप से प्रिंट करने की सेवा में बुनियादी विकल्प मिलते हैं. इस प्रिंटर के लिए दूसरे विकल्प, किसी और प्रिंट सेवा में उपलब्ध हो सकते हैं."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"सुझाई गई सेवाएं"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"सुझाई गई सेवाएं"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"इंस्टॉल करने के लिए चुनें"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"चालू करने के लिए चुनें"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"सेवाएं प्रबंधित करें"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"सेवाएं मैनेज करें"</string>
     <string name="security" msgid="2279008326210305401">"सुरक्षा"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"इस प्रिंटर ने एक नया सुरक्षा प्रमाणपत्र दिया या फिर कोई दूसरा डिवाइस इसके नाम से काम कर रहा है. नया प्रमाणपत्र स्वीकार करें?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"यह प्रिंटर अब सुरक्षित किए गए काम स्वीकार नहीं करता है प्रिंट करना चाहते हैं?"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index e9ee5a1..0922176 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -47,7 +47,7 @@
     <string name="add_named" msgid="9074106244018070583">"Dodaj pisač <xliff:g id="PRINTER">%1$s</xliff:g>"</string>
     <string name="no_printer_found" msgid="4777867380924351173">"Na ovoj adresi nije pronađen pisač"</string>
     <string name="printer_not_supported" msgid="281955849350938408">"Pisač nije podržan"</string>
-    <string name="wifi_direct" msgid="4629404342852294985">"Izravni Wi-Fi"</string>
+    <string name="wifi_direct" msgid="4629404342852294985">"Wi-Fi Direct"</string>
     <string name="find_wifi_direct" msgid="5270504288829123954">"Pronađite pisače s Izravnim Wi-Fijem"</string>
     <string name="wifi_direct_printing" msgid="8423811041563144048">"Ispis putem Izravnog Wi-Fija"</string>
     <string name="wifi_direct_printers" msgid="541168032444693191">"Pisači s Izravnim Wi-Fijem"</string>
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Povezuje se putem Izravnog Wi-Fija"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Povezuje se putem trenutačne mreže na IP adresi <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Zadana usluga ispisa nudi osnovne opcije. Ostale opcije za ovaj pisač mogu biti dostupne iz druge usluge ispisa."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Preporučene usluge"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Preporučene usluge"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Odaberite za instaliranje"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Odaberite za omogućavanje"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Upravljanje uslugama"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Upravljajte uslugama"</string>
     <string name="security" msgid="2279008326210305401">"Sigurnost"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Ovaj je pisač pružio novi sigurnosni certifikat ili ga drugi uređaj lažno predstavlja. Želite li prihvatiti novi certifikat?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Ovaj pisač više ne prihvaća kriptirane zadatke. Želite li nastaviti s ispisom?"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index bdd5599..980a640 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Directen keresztül csatlakozik"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"A következő címen csatlakozik az aktuális hálózaton keresztül: <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Az alapértelmezett nyomtatási szolgáltatás alapvető funkciókat kínál. Másik nyomtatási szolgáltatásban lehetséges, hogy a nyomtató további funkcióit is tudja használni."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Javasolt szolgáltatások"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Javasolt szolgáltatások"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Válasszon szolgáltatást a telepítéshez"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Válasszon szolgáltatást az engedélyezéshez"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Szolgáltatások kezelése"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Szolgáltatások kezelése"</string>
     <string name="security" msgid="2279008326210305401">"Biztonság"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"A nyomtató új biztonsági tanúsítványt adott meg, vagy egy másik eszköz a nyomtatónak álcázza magát. Elfogadja az új tanúsítványt?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Ez a nyomtató már nem fogad titkosított feladatokat. Folytatja a nyomtatást?"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index ce20989..d8aa05d 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Միանում է Wi-Fi Direct-ի միջոցով"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Միանում է ընթացիկ ցանցի միջոցով (IP հասցե՝ <xliff:g id="IP_ADDRESS">%1$s</xliff:g>)"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Կանխադրված տպման ծառայությունը տրամադրում է հիմնական պարամետրերը։ Այս տպիչի մյուս պարամետրերը կարող են հասանելի լինել այլ տպման ծառայություններում։"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Խորհուրդ տրվող ծառայություններ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Խորհուրդ տրվող ծառայություններ"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Ընտրեք՝ տեղադրելու համար"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Ընտրեք՝ միացնելու համար"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Կառավարել ծառայությունները"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Կառավարել ծառայությունները"</string>
     <string name="security" msgid="2279008326210305401">"Անվտանգություն"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Այս տպիչը տրամադրել է անվտանգության նոր հավաստագիր, կամ մեկ այլ սարք նմանակում է դրան։ Ընդունե՞լ նոր հավաստագիրը:"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Տպիչն այլևս չի ընդունում գաղտնագրված առաջադրանքներ: Շարունակե՞լ տպումը:"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 16bc8e2..c75887d 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Menghubungkan melalui Wi-Fi Langsung"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Menghubungkan melalui jaringan saat ini di <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Layanan Cetak Default menyediakan opsi dasar. Opsi lain untuk printer ini mungkin tersedia dari layanan cetak lain."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Layanan yang direkomendasikan"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Layanan yang Direkomendasikan"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Pilih untuk menginstal"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Pilih untuk mengaktifkan"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Kelola layanan"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Kelola Layanan"</string>
     <string name="security" msgid="2279008326210305401">"Keamanan"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Printer ini menyediakan sertifikat keamanan baru, atau perangkat lain sedang meniru identitasnya. Setujui sertifikat baru?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Printer ini tidak menerima pekerjaan yang terenkripsi lagi. Lanjutkan mencetak?"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 6f492cb..22d619c 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Tengist um Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Tengist um núverandi netkerfi á <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Sjálfgefin prentþjónusta inniheldur grunnvalkosti. Aðrar prentþjónustur kunna að bjóða upp á aðra valkosti fyrir þennan prentara."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Þjónusta sem mælt er með"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Þjónusta sem mælt er með"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Veldu til að setja upp"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Veldu til að virkja"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Stjórna þjónustu"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Stjórna þjónustu"</string>
     <string name="security" msgid="2279008326210305401">"Öryggi"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Þessi prentari útvegaði öryggisvottorð, eða annað tæki er að villa á sér heimildir. Viltu samþykkja nýja vottorðið?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Þessi prentari styður ekki lengur dulkóðuð verk. Halda áfram að prenta?"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 7cf164f..05c3743 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Si connette tramite Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Si connette tramite la rete attuale all\'indirizzo <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Il servizio di stampa predefinito offre opzioni di base. Un altro servizio di stampa potrebbe offrire altre opzioni per questa stampante."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Servizi consigliati"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Servizi consigliati"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Seleziona per installare"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Seleziona per attivare"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Gestisci servizi"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Gestisci servizi"</string>
     <string name="security" msgid="2279008326210305401">"Sicurezza"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"La stampante ha fornito un nuovo certificato di sicurezza oppure un altro dispositivo viene identificato come tale. Accettare il nuovo certificato?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Questa stampante non accetta più processi criptati. Vuoi continuare a stampare?"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 7591b6b..fcd66fa 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"‏מתחבר דרך Wi-Fi ישיר"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"מתבצע חיבור דרך הרשת הנוכחית בכתובת <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"שירות ההדפסה המוגדר כברירת מחדל מספק אפשרויות בסיסיות. ייתכן שאפשרויות נוספות למדפסת הזו יהיו זמינות משירות הדפסה אחר."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"שירותים מומלצים"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"שירותים מומלצים"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"יש לבחור כדי להתקין"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"יש לבחור כדי להפעיל"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"ניהול שירותים"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"ניהול השירותים"</string>
     <string name="security" msgid="2279008326210305401">"אבטחה"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"המדפסת הזו סיפקה אישור אבטחה חדש, או שמכשיר אחר מתחזה לה. האם לקבל את האישור החדש?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"המדפסת הזו כבר לא מקבלת משימות מוצפנות. להמשיך בהדפסה?"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index a31ec85..ca350af 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct 経由で接続する"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"現在のネットワーク（<xliff:g id="IP_ADDRESS">%1$s</xliff:g>）経由で接続する"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"デフォルトの印刷サービスには基本的なオプションがあります。このプリンタの他のオプションは別の印刷サービスから利用できる場合があります。"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"推奨されているサービス"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"おすすめのサービス"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"選択してインストール"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"選択して有効にする"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"サービスを管理"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"サービスを管理"</string>
     <string name="security" msgid="2279008326210305401">"セキュリティ"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"このプリンタが新しいセキュリティ証明書を提示しました。これは他のデバイスによるなりすましの可能性もあります。新しい証明書を承認しますか？"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"このプリンタは暗号化されたジョブに対応しなくなりました。印刷を続行しますか？"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 67dca43..c8ea24d 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"უკავშირდება Wi-Fi Direct-ის მეშვეობით"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"უკავშირდება ამჟამინდელი ქსელით, შემდეგ IP მისამართზე: <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ბეჭდვის ნაგულისხმევი სერვისი გთავაზობთ ძირითად ვარიანტებს. სხვა ვარიანტები ამ პრინტერისთვის შეიძლება ხელმისაწვდომი იყოს ბეჭდვის სხვა სერვისიდან."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"რეკომენდებული სერვისები"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"რეკომენდებული სერვისები"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"აირჩიეთ დასაინსტალირებლად"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"აირჩიეთ ჩასართავად"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"სერვისების მართვა"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"სერვისების მართვა"</string>
     <string name="security" msgid="2279008326210305401">"უსაფრთხოება"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ამ პრინტერმა უზრუნველყო უსაფრთხოების ახალი სერტიფიკატი, ან მის იმიტირებას ახდენს სხვა მოწყობილობა. გსურთ ახალი სერტიფიკატის მიღება?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"ეს პრინტერი აღარ იღებს დაშიფრულ დავალებებს. გსურთ ბეჭდვის გაგრძელება?"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 2ed1937..0b74739 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct арқылы жалғанады"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> мекенжайындағы желі арқылы жалғанады"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Әдепкі баспа қызметі негізгі функцияларды атқарады. Бұл принтердің өзге функциялары басқа басып шығару қызметінде болуы мүмкін."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Ұсынылған қызметтер"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Ұсынылған қызметтер"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Орнату үшін таңдаңыз."</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Қосу үшін таңдаңыз."</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Қызметтерді басқару"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Қызметтерді басқару"</string>
     <string name="security" msgid="2279008326210305401">"Қауіпсіздік"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Бұл принтер жаңа қауіпсіздік сертификатын ұсынды немесе оның атынан басқа бір құрылғы жұмыс істеп тұр. Жаңа сертификатты қабылдайсыз ба?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Принтер енді шифрланған тапсырмаларды қабылдамайды. Басып шығару жалғассын ба?"</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 98cf19d..841e23f 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"ភ្ជាប់​តាមរយៈ Wi-Fi​ ផ្ទាល់"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"ភ្ជាប់​តាមរយៈ​បណ្តាញបច្ចុប្បន្ន​នៅ <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"សេវាកម្ម​បោះពុម្ពលំនាំដើម​ផ្ដល់ជូនជម្រើស​មូលដ្ឋាន។ ជម្រើសផ្សេង​ទៀតសម្រាប់ម៉ាស៊ីន​បោះពុម្ពនេះអាចនឹងមាន​ពីសេវាកម្ម​បោះពុម្ពផ្សេងទៀត។"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"សេវាកម្មដែល​បានណែនាំ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"សេវាកម្មដែល​បានណែនាំ"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ជ្រើសរើស​ដើម្បីដំឡើង"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"ជ្រើសរើសដើម្បីបើក"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"គ្រប់គ្រង​សេវាកម្ម"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"គ្រប់គ្រង​សេវាកម្ម"</string>
     <string name="security" msgid="2279008326210305401">"សុវត្ថិភាព"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ម៉ាស៊ីនបោះពុម្ព​នេះបានផ្តល់​វិញ្ញាបនបត្រ​សុវត្ថិភាពថ្មី ឬ​មានឧបករណ៍​ផ្សេងកំពុង​បន្លំខ្លួនជា​ម៉ាស៊ីនបោះពុម្ព។ ទទួលយក​វិញ្ញាបនបត្រ​ថ្មី?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"ម៉ាស៊ីនបោះ​ពុម្ពនេះលែង​ទទួល​កិច្ចការ​ដែលមាន​ការអ៊ីនគ្រីប​ទៀតហើយ។ បន្តបោះ​ពុម្ព?"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index f39bed8..1a61927 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -61,13 +61,13 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"ವೈ-ಫೈ ಡೈರೆಕ್ಟ್ ಮೂಲಕ ಸಂಪರ್ಕಿಸುತ್ತದೆ"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"ಪ್ರಸ್ತುತ ನೆಟ್‌ವರ್ಕ್‌ನಲ್ಲಿ <xliff:g id="IP_ADDRESS">%1$s</xliff:g> ಮೂಲಕ ಸಂಪರ್ಕಿಸುತ್ತದೆ"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ಡೀಫಾಲ್ಟ್ ಮುದ್ರಣ ಸೇವೆ ಮೂಲ ಆಯ್ಕೆಗಳನ್ನು ಒದಗಿಸುತ್ತದೆ. ಈ ಪ್ರಿಂಟರ್‌ನ ಇತರ ಆಯ್ಕೆಗಳು ಮತ್ತೊಂದು ಮುದ್ರಣ ಸೇವೆಯಿಂದ ಲಭ್ಯವಿರಬಹುದು."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"ಶಿಫಾರಸು ಮಾಡಲಾದ ಸೇವೆಗಳು"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"ಶಿಫಾರಸು ಮಾಡಲಾದ ಸೇವೆಗಳು"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಲು ಆಯ್ಕೆ ಮಾಡಿ"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"ಸಕ್ರಿಯಗೊಳಿಸಲು ಆಯ್ಕೆಮಾಡಿ"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"ಸೇವೆಗಳನ್ನು ನಿರ್ವಹಿಸಿ"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"ಸೇವೆಗಳನ್ನು ನಿರ್ವಹಿಸಿ"</string>
     <string name="security" msgid="2279008326210305401">"ಭದ್ರತೆ"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ಈ ಪ್ರಿಂಟರ್ ಹೊಸ ಭದ್ರತೆ ಪ್ರಮಾಣಪತ್ರವನ್ನು ಒದಗಿಸಿದೆ ಅಥವಾ ಇನ್ನೊಂದು ಸಾಧನ ಅದನ್ನು ಸೋಗು ಹಾಕುತ್ತಿದೆ. ಹೊಸ ಪ್ರಮಾಣಪತ್ರವನ್ನು ಸ್ವೀಕರಿಸುವುದೇ?"</string>
-    <string name="not_encrypted_request" msgid="4871472176807381642">"ಪ್ರಿಂಟರ್ ಇನ್ನು ಮುಂದೆ ಎನ್‌ಕ್ರಿಪ್ಟ್ ಮಾಡಿದ ಕೆಲಸಗಳನ್ನು ಸ್ವೀಕರಿಸುವುದಿಲ್ಲ. ಪ್ರಿಂಟಿಂಗ್ ಮುಂದುವರಿಸುವುದೇ?"</string>
+    <string name="not_encrypted_request" msgid="4871472176807381642">"ಪ್ರಿಂಟರ್ ಇನ್ನು ಮುಂದೆ ಎನ್‌ಕ್ರಿಪ್ಟ್ ಮಾಡಿದ ಕೆಲಸಗಳನ್ನು ಸ್ವೀಕರಿಸುವುದಿಲ್ಲ. ಪ್ರಿಂಟಿಂಗ್ ಮುಂದುವರಿಸಬೇಕೇ?"</string>
     <string name="accept" msgid="4426153292469698134">"ಸ್ವೀಕರಿಸಿ"</string>
     <string name="reject" msgid="24751635160440693">"ತಿರಸ್ಕರಿಸಿ"</string>
     <string name="connections" msgid="8895413761760117180">"ಸಂಪರ್ಕಗಳು"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index a0e03cc..2e822de 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct를 통해 연결"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g>에서 현재 네트워크를 통해 연결"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"기본인쇄 서비스에서는 기본적인 옵션만 제공됩니다. 다른 인쇄 서비스를 통해 이 프린터에 관한 다른 옵션을 이용할 수도 있습니다."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"권장 서비스"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"권장 서비스"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"설치하려면 선택하세요."</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"사용 설정하려면 선택하세요."</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"서비스 관리"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"서비스 관리"</string>
     <string name="security" msgid="2279008326210305401">"보안"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"이 프린터에서 새로운 보안 인증서를 제공했거나 다른 기기가 이 프린터로 위장하고 있습니다. 새 인증서를 수락할까요?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"프린터가 더 이상 암호화된 작업을 지원하지 않습니다. 인쇄를 계속하시겠습니까?"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 3259e8a..651b1d3 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct аркылуу туташат"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> IP дарегиндеги учурдагы тармак аркылуу туташат"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Демейки басып чыгаруу кызматы негизги параметрлерди сунуштайт. Бул принтердин кошумча параметрлери башка басып чыгаруу кызматында жеткиликтүү болушу мүмкүн."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Сунушталган кызматтар"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Сунушталган кызматтар"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Орнотуу үчүн тандаңыз"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Иштетүү үчүн басыңыз"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Кызматтарды башкаруу"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Кызматтарды тескөө"</string>
     <string name="security" msgid="2279008326210305401">"Коопсуздук"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Бул принтердин жаңы коопсуздук тастыктамасы бар же анын ордуна башка түзмөк иштеп жатат. Жаңы тастыктама кабыл алынсынбы?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Бул принтер мындан ары шифрленген тапшырмаларды кабыл албайт. Бастыра бересизби?"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index d8ab4ab..b212ac1 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"ເຊື່ອມຕໍ່ຜ່ານ Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"ເຊື່ອມຕໍ່ຜ່ານເຄືອຂ່າຍປັດຈຸບັນທີ່ <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ບໍລິການການ​ພິມ​ມາດ​ຕະ​ຖານສະໜອງຕົວເລືອກພື້ນຖານໃຫ້. ຕົວເລືອກອື່ນໆສຳລັບເຄື່ອງພິມນີ້ອາດມີໃຫ້ໃຊ້ໄດ້ຈາກບໍລິການພິມອື່ນ."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"ບໍລິການທີ່ແນະນຳ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"ບໍລິການທີ່ແນະນຳ"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ເລືອກເພື່ອຕິດຕັ້ງ"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"ເລືອກເພື່ອເປີດໃຊ້"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"ຈັດການການບໍລິການ"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"ຈັດການບໍລິການ"</string>
     <string name="security" msgid="2279008326210305401">"ຄວາມປອດໄພ"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ເຄື່ອງພິມນີ້ໃຫ້ໃບຮັບຮອງຄວາມປອດໄພໃໝ່ ຫຼື ອຸປະກອນອື່ນກຳລັງປອມເປັນມັນຢູ່. ຍອມຮັບໃບຮັບຮອງໃໝ່ບໍ?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"ເຄື່ອງພິມນີ້ບໍ່ຮັບໜ້າວຽກທີ່ເຂົ້າລະຫັດໄວ້. ສືບຕໍ່ການພິມບໍ?"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index ece4a50..406659c 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Užmezgamas ryšys per „Wi-Fi Direct“"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Užmezgamas ryšys per dabartinį tinklą adresu <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Naudojantis numatytojo spausdinimo paslauga teikiamos pagrindinės parinktys. Kitos šio spausdintuvo parinktys gali būti pasiekiamos naudojant kitą spausdinimo paslaugą."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Rekomenduojamos paslaugos"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Rekomenduojamos paslaugos"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Pasirinkite, kad įdiegtumėte"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Pasirinkite, kad įgalintumėte"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Tvarkyti paslaugas"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Tvarkyti paslaugas"</string>
     <string name="security" msgid="2279008326210305401">"Sauga"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Šis spausdintuvas pateikė naują saugos sertifikatą arba kitas įrenginys juo apsimetinėja. Priimti naują sertifikatą?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Šis spausdintuvas nebepriima šifruotų užduočių. Spausdinti toliau?"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 04014f3..038a9ad 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Notiek savienojuma izveide, izmantojot Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Notiek savienojuma izveide, izmantojot pašreizējo tīklu ar šādu IP adresi: <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Noklusējuma drukāšanas pakalpojums nodrošina pamatiespējas. Citas iespējas šim printerim var būt pieejamas, izmantojot citu drukāšanas pakalpojumu."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Ieteiktie pakalpojumi"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Ieteiktie pakalpojumi"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Atlasiet, lai instalētu"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Atlasiet, lai iespējotu"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Pārvaldīt pakalpojumus"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Pārvaldīt pakalpojumus"</string>
     <string name="security" msgid="2279008326210305401">"Drošība"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Šim printerim ir jauns drošības sertifikāts, vai arī cita ierīce uzdodas par to. Vai apstiprināt jauno sertifikātu?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Šis printeris vairs nepieņem šifrētus uzdevumus. Vai turpināt drukāšanu?"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 82371bf..0f8f3f2 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Се поврзува преку Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Се поврзува преку моменталната мрежа на <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Стандардната услуга за печатење обезбедува основни опции. Други опции за печатачов можеби се достапни од друга услуга за печатење."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Препорачани услуги"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Препорачани услуги"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Изберете за да инсталирате"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Изберете за да овозможите"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Управувајте со услугите"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Управувајте со услугите"</string>
     <string name="security" msgid="2279008326210305401">"Безбедност"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Овој печатач обезбедил нов безбедносен сертификат или друг уред лажно се претставува како него. Да се прифати новиот сертификат?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Овој печатач веќе не прифаќа шифрирани задачи. Да се продолжи со печатење?"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index cd56c28..8a3394a 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"വൈഫൈ ഡയറക്‌റ്റ് വഴി കണക്റ്റ് ചെയ്യുന്നു"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> വിലാസത്തിലെ നിലവിലെ നെറ്റ്‍വര്‍ക്ക് വഴി കണക്റ്റ് ചെയ്യുന്നു"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ഡിഫോൾട്ട് പ്രിന്റ് സേവനം അടിസ്ഥാന ഓപ്ഷനുകൾ നൽകുന്നു. ഈ പ്രിന്ററിനുള്ള മറ്റ് ഓപ്ഷനുകൾ മറ്റ് പ്രിന്റ് സേവനത്തിൽ നിന്ന് ലഭ്യമായേക്കും."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"നിർദ്ദേശിച്ചിട്ടുള്ള സേവനങ്ങൾ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"നിർദ്ദേശിച്ചിട്ടുള്ള സേവനങ്ങൾ"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ഇൻസ്‌റ്റാൾ ചെയ്യാൻ തിരഞ്ഞെടുക്കുക"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"പ്രവർത്തനക്ഷമമാക്കാൻ തിരഞ്ഞെടുക്കുക"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"സേവനങ്ങൾ മാനേജ് ചെയ്യുക"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"സേവനങ്ങൾ മാനേജ് ചെയ്യുക"</string>
     <string name="security" msgid="2279008326210305401">"സുരക്ഷ"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ഈ പ്രിന്റർ ഒരു പുതിയ സുരക്ഷാ സർട്ടിഫിക്കറ്റ് നൽകുകയോ മറ്റൊരു ഉപകരണം ഇതായി ആൾമാറാട്ടം നടത്തുകയോ ചെയ്യുന്നു. പുതിയ സർട്ടിഫിക്കറ്റ് സ്വീകരിക്കട്ടെ?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"ഈ പ്രിന്റർ ഇനി എൻക്രിപ്റ്റ് ചെയ്‌ത ജോലികൾ സ്വീകരിക്കില്ല. പ്രിന്റ് ചെയ്യൽ തുടരണോ?"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index c75ef7e..80a6f1a 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Шуудаар холбогддог"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Одоогийн сүлжээгээр <xliff:g id="IP_ADDRESS">%1$s</xliff:g>-д холбогддог"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Стандарт хэвлэлтийн үйлчилгээ энгийн сонголттой байдаг. Энэ хэвлэгчийн бусад сонголт хэвлэлийн өөр үйлчилгээнээс боломжтой байж болзошгүй."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Санал болгосон үйлчилгээ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Санал болгосон үйлчилгээ"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Суулгахын тулд сонгох"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Идэвхжүүлэхийн тулд сонгох"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Үйлчилгээг удирдах"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Үйлчилгээг удирдах"</string>
     <string name="security" msgid="2279008326210305401">"Аюулгүй байдал"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Энэ хэвлэгч аюулгүй байдлын шинэ сертификат олгосон эсвэл үүнийг өөр төхөөрөмж хуурамчаар дуурайж байна. Шинэ сертификатыг зөвшөөрөх үү?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Энэ хэвлэгч шифрлэсэн ажлыг цаашид зөвшөөрөхөө больсон байна. Үргэлжлүүлэн хэвлэх үү?"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index fbc1615..583fe5a 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"वाय-फाय थेट मार्फत कनेक्ट होते"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> वर सध्याच्या नेटवर्कमार्फत कनेक्ट होते"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"डीफॉल्ट प्रिंट सेवा पुरवठादार मूलभूत पर्याय देतात. या प्रिंटरचे इतर पर्याय कदाचित दुसऱ्या एखाद्या प्रिंट सेवेसाठी उपलब्ध असतील."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"शिफारस केलेल्या सेवा"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"शिफारस केलेल्या सेवा"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"इंस्टॉल करण्यासाठी निवडा"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"सुरू करण्यासाठी निवडा"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"सेवा व्यवस्थापित करा"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"सेवा व्यवस्थापित करा"</string>
     <string name="security" msgid="2279008326210305401">"सुरक्षा"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"हा प्रिंटर नवीन सुरक्षा सर्टिफिकेट प्रदान करतो किंवा दुसरे एखादे डिव्हाइस तोतयागिरी करत असेल. नवीन सर्टिफिकेट स्वीकारायचे का?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"यापुढे हा प्रिंटर एंक्रिप्ट केलेली कामे स्वीकारणार नाही. प्रिंट करणे सुरू ठेवायचे आहे का?"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index b50628c..25d32dd 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Bersambung melalui Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Bersambung melalui rangkaian semasa di <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Perkhidmatan Cetak Lalai menyediakan pilihan asas. Pilihan lain bagi pencetak ini mungkin tersedia daripada perkhidmatan cetak lain."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Perkhidmatan yang disyorkan"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Perkhidmatan Yang Disyorkan"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Pilih untuk pasang"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Pilih untuk dayakan"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Urus perkhidmatan"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Urus Perkhidmatan"</string>
     <string name="security" msgid="2279008326210305401">"Keselamatan"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Pencetak ini memberikan sijil keselamatan baharu atau peranti lain sedang menyamar menjadi pencetak tersebut. Terima sijil baharu?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Pencetak ini tidak lagi menerima kerja yang disulitkan. Teruskan mencetak?"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 513a994..904ca39 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct ဖြင့် ချိတ်ဆက်သည်"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> ရှိ လက်ရှိကွန်ရက် မှတစ်ဆင့် ချိတ်ဆက်သည်"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"မူရင်းပုံနှိပ်ခြင်းဝန်ဆောင်မှုတွင် အခြေခံလုပ်ဆောင်ချက်များ ပါဝင်သည်။ ဤပရင်တာအတွက် အခြားလုပ်ဆောင်ချက်များကို အခြားပုံနှိပ်ခြင်းဝန်ဆောင်မှုမှ ရနိုင်ပါမည်။"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"အကြံပြုထားသည့် ဝန်ဆောင်မှုများ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"အကြံပြုထားသည့် ဝန်ဆောင်မှုများ"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ထည့်သွင်းရန် ရွေးပါ"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"ဖွင့်ရန် ရွေးပါ"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"ဝန်ဆောင်မှုများ စီမံခန့်ခွဲရန်"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"ဝန်ဆောင်မှုများ စီမံရန်"</string>
     <string name="security" msgid="2279008326210305401">"လုံခြုံရေး"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ဤပရင်တာက လုံခြုံရေး အသိအမှတ်ပြုလက်မှတ်အသစ်ကို ထုတ်ပေးလိုက်သည် သို့မဟုတ် အခြားစက်ပစ္စည်းတစ်ခုက ၎င်းအဖြစ် အယောင်ဆောင်နေခြင်းဖြစ်သည်။ အသိအမှတ်ပြုလက်မှတ်အသစ်ကို လက်ခံမလား။"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"ဤပရင်တာက အသွင်ဝှက်ထားသော အလုပ်များကို လက်ခံတော့မည် မဟုတ်ပါ။ ဆက်လက် ပုံနှိပ်ထုတ်လိုသလား။"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index a2e50f1..4d3e851 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Kobler til via Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Kobler til via nåværende nettverk på <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Standard utskriftstjeneste gir grunnleggende alternativer. Andre alternativer for denne skriveren kan være tilgjengelige fra en annen utskriftstjeneste."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Anbefalte tjenester"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Anbefalte tjenester"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Velg for å installere"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Velg for å slå på"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Administrer tjenester"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Administrer tjenester"</string>
     <string name="security" msgid="2279008326210305401">"Sikkerhet"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Denne skriveren har oppgitt et nytt sikkerhetssertifikat, eller en annen enhet utgir seg for å være den. Vil du akseptere det nye sertifikatet?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Denne skriveren aksepterer ikke krypterte jobber lenger. Vil du fortsette utskriften?"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 1e2315d..6b24f1a 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -57,14 +57,14 @@
     <string name="failed_printer_connection" msgid="4196305972749960362">"प्रिन्टरमा जडान गर्न सकिएन"</string>
     <string name="failed_connection" msgid="8068661997318286575">"<xliff:g id="PRINTER">%1$s</xliff:g> मा जडान गर्न सकिएन"</string>
     <string name="saved_printers" msgid="4567534965213125526">"सुरक्षित गरिएका प्रिन्टरहरू"</string>
-    <string name="forget" msgid="892068061425802502">"बिर्सनुहोस्"</string>
+    <string name="forget" msgid="892068061425802502">"हटाउनुहोस्"</string>
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi प्रत्यक्षमार्फत जडान गर्छ"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> को हालको नेटवर्कमार्फत जडान गर्छ"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"डिफल्ट छपाइ सेवाले आधारभूत विकल्पहरू प्रदान गर्दछ। यो प्रिन्टरका अन्य विकल्पहरू अन्य छपाइ सेवाबाट उपलब्ध हुन सक्छन्।"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"सिफारिस गरिएका सेवाहरू"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"सिफारिस गरिएका सेवाहरू"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"स्थापना गर्न चयन गर्नुहोस्"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"सक्षम पार्न चयन गर्नुहोस्"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"सेवाहरूको व्यवस्थापन गर्नुहोस्"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"सेवाहरू व्यवस्थापन गर्नुहोस्"</string>
     <string name="security" msgid="2279008326210305401">"सुरक्षा"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"यो प्रिन्टरले सुरक्षासम्बन्धी कुनै नयाँ प्रमाणपत्र प्रदान गर्‍यो नयाँ प्रमाणपत्र स्वीकार गर्ने हो?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"यो प्रिन्टरले अब उप्रान्त इन्क्रिप्ट गरिएका कार्यहरू स्वीकार गर्दैन। छाप्ने कार्य जारी राख्ने हो?"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 0a9ae47..6bc9fc8 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Maakt verbinding via Wifi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Maakt verbinding via huidige netwerk op <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"De standaard afdrukservice biedt basisopties. Er kunnen andere opties voor deze printer beschikbaar zijn via een andere afdrukservice."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Aanbevolen services"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Aanbevolen services"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Selecteer om te installeren"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecteer om aan te zetten"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Services beheren"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Services beheren"</string>
     <string name="security" msgid="2279008326210305401">"Beveiliging"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Deze printer biedt een nieuw beveiligingscertificaat aan, of een ander apparaat imiteert deze printer. Wil je het nieuwe certificaat accepteren?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Deze printer accepteert geen versleutelde taken meer. Doorgaan met afdrukken?"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index db4bb4e..98c3608 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"ୱାଇ-ଫାଇ ଡାଇରେକ୍ଟ ମାଧ୍ୟମରେ କନେକ୍ଟ ହେବ"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g>ରେ ବର୍ତ୍ତମାନର ନେଟ୍‌ୱର୍କ ମାଧ୍ୟମରେ କନେକ୍ଟ କରାଯାଇଥାଏ"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ଡିଫଲ୍ଟ ପ୍ରିଣ୍ଟ ସେବା ପ୍ରଦାନକାରୀ ମୌଳିକ ବିକଳ୍ପଗୁଡ଼ିକ। ଏହି ଫ୍ରିଣ୍ଟର୍ ପାଇଁ ଅନ୍ୟ ବିକଳ୍ପଗୁଡ଼ିକ ଅନ୍ୟ ପ୍ରିଣ୍ଟ ସେବାରୁ ଉପଲବ୍ଧ ହୋଇପାରେ।"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"ସୁପାରିଶ କରାଯାଇଥିବା ସେବାଗୁଡ଼ିକ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"ସୁପାରିଶ କରାଯାଇଥିବା ସେବା"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ଇନ୍‌ଷ୍ଟଲ୍ କରିବା ପାଇଁ ଚୟନ କରନ୍ତୁ"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"ସକ୍ଷମ କରିବା ପାଇଁ ଚୟନ କରନ୍ତୁ"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"ସେବାଗୁଡ଼ିକ ପରିଚାଳନା କରନ୍ତୁ"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"ସେବାଗୁଡ଼ିକୁ ପରିଚାଳନା କରନ୍ତୁ"</string>
     <string name="security" msgid="2279008326210305401">"ସୁରକ୍ଷା"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ଏହି ପ୍ରିଣ୍ଟର୍ ଏକ ନୂଆ ସୁରକ୍ଷା ସାର୍ଟିଫିକେଟ୍ ପ୍ରଦାନ କରିଛି କିମ୍ବା ଅନ୍ୟ ଏକ ଡିଭାଇସ୍ ଏହାକୁ ପ୍ରତିରୂପଣ କରୁଛି। ନୂଆ ସାର୍ଟିଫିକେଟ୍ ସ୍ୱୀକାର କରିବେ?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"ଏହି ପ୍ରିଣ୍ଟର୍‌ ଏନ୍‌କ୍ରିପ୍ଟ ହୋ‍ଇଥିବା କାର୍ଯ୍ୟ ଆଉ ଗ୍ରହଣ କରୁନାହିଁ ପ୍ରିଣ୍ଟିଂ ଜାରି ରଖିବେ?"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 299d925..ec0f816 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"ਵਾਈ-ਫਾਈ ਡਾਇਰੈਕਟ ਰਾਹੀਂ ਕਨੈਕਟ ਕਰਦਾ ਹੈ"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> \'ਤੇ ਵਰਤਮਾਨ ਨੈੱਟਵਰਕ ਰਾਹੀਂ ਕਨੈਕਟ ਕਰਦਾ ਹੈ"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ਪੂਰਵ-ਨਿਰਧਾਰਤ ਪ੍ਰਿੰਟ ਸੇਵਾ ਮੂਲ ਵਿਕਲਪ ਪ੍ਰਦਾਨ ਕਰਦੀ ਹੈ। ਇਸ ਪ੍ਰਿੰਟਰ ਲਈ ਹੋਰ ਵਿਕਲਪ ਕਿਸੇ ਹੋਰ ਪ੍ਰਿੰਟ ਸੇਵਾ ਤੋਂ ਉਪਲਬਧ ਹੋ ਸਕਦੇ ਹਨ।"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"ਸਿਫ਼ਾਰਸ਼ ਕੀਤੀਆਂ ਸੇਵਾਵਾਂ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"ਸਿਫ਼ਾਰਸ਼ੀ ਸੇਵਾਵਾਂ"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ਸਥਾਪਤ ਕਰਨ ਲਈ ਚੁਣੋ"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"ਚਾਲੂ ਕਰਨ ਲਈ ਚੁਣੋ"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"ਸੇਵਾਵਾਂ ਦਾ ਪ੍ਰਬੰਧਨ ਕਰੋ"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"ਸੇਵਾਵਾਂ ਦਾ ਪ੍ਰਬੰਧਨ ਕਰੋ"</string>
     <string name="security" msgid="2279008326210305401">"ਸੁਰੱਖਿਆ"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ਇਸ ਪ੍ਰਿੰਟਰ ਨੇ ਇੱਕ ਨਵਾਂ ਸੁਰ ਪ੍ਰਮਾਣ-ਪੱਤਰ ਮੁਹੱਈਆ ਕਰਵਾਇਆ ਹੈ, ਜਾਂ ਕਿਸੇ ਹੋਰ ਡੀਵਾਈਸ ਨੇ ਇਸਦਾ ਪਰਰੂਪਣ ਕੀਤਾ ਹੈ। ਨਵਾਂ ਪ੍ਰਮਾਣ-ਪੱਤਰ ਸਵੀਕਾਰ ਕਰੋ?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"ਇਹ ਪ੍ਰਿੰਟਰ ਹੁਣ ਇਨਕ੍ਰਿਪਟਡ ਜੌਬਾਂ ਸਵੀਕਾਰ ਨਹੀਂ ਕਰਦਾ ਹੈ। ਕੀ ਪ੍ਰਿੰਟਿੰਗ ਜਾਰੀ ਰੱਖਣੀ ਹੈ?"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 4d833bb..1855a71 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Łączenie przez Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Łączenie przez bieżącą sieć, adres: <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Domyślna usługa drukowania udostępnia opcje podstawowe. Inne opcje tej drukarki mogą być dostępne w innej usłudze drukowania."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Polecane usługi"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Polecane usługi"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Wybierz, by zainstalować"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Wybierz, by włączyć"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Zarządzaj usługami"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Zarządzaj usługami"</string>
     <string name="security" msgid="2279008326210305401">"Zabezpieczenia"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Ta drukarka przekazała nowy certyfikat bezpieczeństwa lub inne urządzenie podszywa się pod nią. Zaakceptować nowy certyfikat?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Ta drukarka nie przyjmuje już zaszyfrowanych zadań. Kontynuować drukowanie?"</string>
diff --git a/res/values-pt-rBR/strings.xml b/res/values-pt-rBR/strings.xml
index 40453ee..7696f06 100644
--- a/res/values-pt-rBR/strings.xml
+++ b/res/values-pt-rBR/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Conecta via Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Conecta via rede atual em <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"O serviço de impressão padrão oferece opções básicas. É possível que existam outras opções disponíveis para essa impressora em outro serviço de impressão."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Serviços recomendados"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Serviços recomendados"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Selecione para instalar"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecione para ativar"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Gerenciar serviços"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Gerenciar serviços"</string>
     <string name="security" msgid="2279008326210305401">"Segurança"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Um novo certificado de segurança foi emitido pela impressora ou a identidade dela foi falsificada por outro dispositivo. Aceitar o novo certificado?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Esta impressora não aceita mais trabalhos criptografados. Continuar imprimindo?"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index b8503d8..4179324 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"A ligação é efetuada através de Wi-Fi Direct."</string>
     <string name="connects_via_network" msgid="5990041581556733898">"A ligação é efetuada através da rede atual em <xliff:g id="IP_ADDRESS">%1$s</xliff:g>."</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"O serviço de impressão padrão fornece opções básicas. Podem estar disponíveis outras opções para esta impressora a partir de outro serviço de impressão."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Serviços recomendados"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Serviços recomendados"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Selecione para instalar."</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecione para ativar."</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Gerir serviços"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Gerir serviços"</string>
     <string name="security" msgid="2279008326210305401">"Segurança"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Esta impressora forneceu um novo certificado de segurança ou outro dispositivo está a roubar a respetiva identidade. Quer aceitar o novo certificado?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Esta impressora já não aceita tarefas encriptadas. Quer continuar com a impressão?"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 40453ee..7696f06 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Conecta via Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Conecta via rede atual em <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"O serviço de impressão padrão oferece opções básicas. É possível que existam outras opções disponíveis para essa impressora em outro serviço de impressão."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Serviços recomendados"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Serviços recomendados"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Selecione para instalar"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecione para ativar"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Gerenciar serviços"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Gerenciar serviços"</string>
     <string name="security" msgid="2279008326210305401">"Segurança"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Um novo certificado de segurança foi emitido pela impressora ou a identidade dela foi falsificada por outro dispositivo. Aceitar o novo certificado?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Esta impressora não aceita mais trabalhos criptografados. Continuar imprimindo?"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index f91a840..9d3a071 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Se conectează prin Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Se conectează prin rețeaua curentă la <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Serviciul de printare prestabilit oferă opțiuni de bază. Alte opțiuni pentru această imprimantă pot fi disponibile din alt serviciu de printare."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Servicii recomandate"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Servicii recomandate"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Selectează pentru a instala"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selectează pentru a activa"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Gestionează serviciile"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Gestionează serviciile"</string>
     <string name="security" msgid="2279008326210305401">"Securitate"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Imprimanta a oferit un nou certificat de securitate sau un alt dispozitiv îi folosește identitatea. Accepți noul certificat?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Această imprimantă nu mai acceptă sarcini criptate. Continui printarea?"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 7243933..c855115 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Подключено через Wi-Fi Direct."</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Подключено к текущей сети с IP-адресом <xliff:g id="IP_ADDRESS">%1$s</xliff:g>."</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Служба печати по умолчанию предоставляет базовый набор функций. Выбрав другую службу, вы можете получить доступ к расширенным функциям."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Рекомендуемые службы"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Рекомендуемые службы"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Выберите, чтобы установить"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Выберите, чтобы включить"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Управление службами"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Управление службами"</string>
     <string name="security" msgid="2279008326210305401">"Безопасность"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Для принтера предоставлен новый сертификат безопасности. Возможно, под видом принтера работает другое устройство. Принять новый сертификат?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Принтер больше не принимает зашифрованные задания. Продолжить печать?"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 66b951e..9191856 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct හරහා සම්බන්ධ වෙමින්"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> හි වත්මන් ජාලය හරහා සම්බන්ධ වෙමින්"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"පෙරනිමි මුද්‍රණ සේවාව මූලික විකල්ප සපයයි. මෙම මුද්‍රණ යන්ත්‍රය සඳහා වෙනත් විකල්ප වෙනත් මුද්‍රණ සේවාවකින් ලබා ගත හැකිය."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"නිර්දේශිත සේවා"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"නිර්දේශිත සේවා"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ස්ථාපනය කිරීමට තෝරන්න"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"සබල කිරීමට තෝරන්න"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"සේවා කළමණාකරණය කරන්න"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"සේවා කළමණාකරණය කරන්න"</string>
     <string name="security" msgid="2279008326210305401">"ආරක්ෂාව"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"මෙම මුද්‍රකය නව ආරක්‍ෂණ සහතිතකයක් සැපයුවේය, නැති නම් වෙනත් උපාංගයක් එය මූර්තිමත් කරයි. නව සහතිකය පිළිගන්නේද?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"මෙම මුද්‍රණ යන්ත්‍රය සංකේතනය කළ කාර්යයන් තවදුරටත් පිළිනොගනී. මුද්‍රණය කිරිම දිගටම කර ගෙන යන්නද?"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index e054800..f3e6e87 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Pripája sa prostredníctvom rozhrania Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Pripája sa prostredníctvom aktuálnej siete na adrese IP – <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Predvolená tlačová služba poskytuje základné možnosti. Ďalšie možnosti tejto tlačiarne môžu byť k dispozícii v inej tlačovej službe."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Odporúčané služby"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Odporúčané služby"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Vyberte a nainštalujte"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Vyberte a povoľte"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Spravovať služby"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Spravovať služby"</string>
     <string name="security" msgid="2279008326210305401">"Zabezpečenie"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Táto tlačiareň poskytla nový bezpečnostný certifikát alebo ju napodobňuje iné zariadenie. Chcete nový certifikát prijať?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Tlačiareň už neprijíma šifrované úlohy. Chcete pokračovať v tlačení?"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index e5c5848..199f9ef 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Vzpostavitev povezave prek povezave Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Vzpostavitev povezave prek trenutnega omrežja z naslovom <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Privzeta storitev tiskanja zagotavlja osnovne možnosti. Druge možnosti za ta tiskalnik so morda na voljo v kateri drugi storitvi tiskanja."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Priporočene storitve"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Priporočene storitve"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Izberite, če želite namestiti"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Izberite, če želite omogočiti"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Upravljanje storitev"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Upravljanje storitev"</string>
     <string name="security" msgid="2279008326210305401">"Varnost"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Ta tiskalnik je posredoval novo varnostno potrdilo ali pa se zanj lažno predstavlja druga naprava. Želite sprejeti novo potrdilo?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Ta tiskalnik ne sprejema več šifriranih opravil. Želite nadaljevati tiskanje?"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index e674d15..be64105 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Lidhet përmes Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Lidhet përmes rrjetit aktual në <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Shërbimi i parazgjedhur i printimit ofron opsionet bazë. Opsione të tjera për këtë printer mund të ofrohen nga një shërbim tjetër printimi."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Shërbimet e rekomanduara"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Shërbimet e rekomanduara"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Zgjidh për të instaluar"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Zgjidh për të aktivizuar"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Menaxho shërbimet"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Menaxho shërbimet"</string>
     <string name="security" msgid="2279008326210305401">"Siguria"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Ky printer ka dhënë një certifikatë të re sigurie ose një pajisje tjetër po e imiton atë. Do ta pranosh certifikatën e re?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Ky printer nuk pranon më punë të enkriptuara. Të vazhdohet printimi?"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 8e2ddf9..a5e8805 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Повезује се преко WiFi Direct-а"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Повезује се преко тренутне мреже помоћу IP адресе <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Подразумевана услуга штампања пружа основне опције. Остале опције овог штампача су можда доступне у другој услузи штампања."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Препоручене услуге"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Препоручене услуге"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Изаберите да бисте инсталирали"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Изаберите да бисте омогућили"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Управљај услугама"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Управљајте услугама"</string>
     <string name="security" msgid="2279008326210305401">"Безбедност"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Овај штампач пружа нови безбедносни сертификат или се неки други уређај лажно представља као он. Желите ли да прихватите нови сертификат?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Овај штампач више не прихвата шифроване задатке. Желите ли да наставите са штампањем?"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index da59a85..1acadfc 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Ansluter via wifi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Ansluter via det nuvarande nätverket på <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Standardutskriftstjänsten har de grundläggande alternativen. Med en annan utskriftstjänst kan det finnas fler alternativ tillgängliga för den här skrivaren."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Rekommenderade tjänster"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Rekommenderade tjänster"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Välj om du vill installera"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Välj om du vill aktivera"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Hantera tjänster"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Hantera tjänster"</string>
     <string name="security" msgid="2279008326210305401">"Säkerhet"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Skrivaren har ett nytt säkerhetscertifikat, om inte en annan enhet har övertagit dess identitet. Godkänner du det nya certifikatet?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Krypterade jobb godkänns inte längre på denna skrivare. Vill du fortsätta att skriva ut?"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 4e8dde1..93d066b 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Huunganisha kupitia Wi-Fi moja kwa moja"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Huunganisha kupitia mtandao wa sasa kwenye <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Huduma Chaguomsingi ya Kuchapisha hutoa chaguo za msingi. Huenda chaguo zingine za printa hii zikapatikana kutoka huduma nyingine ya kuchapisha."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Huduma zinazopendekezwa"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Huduma Zinazopendekezwa"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Chagua ili usakinishe"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Chagua ili uwashe"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Dhibiti huduma"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Dhibiti Huduma"</string>
     <string name="security" msgid="2279008326210305401">"Usalama"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Printa hii imetoa cheti kipya cha usalama au kifaa kingine kinaiiga. Je, ungependa kukubali cheti kipya?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Printa hii haichapishi tena kazi zilizosimbwa kwa njia fiche. Ungependa kuendelea kuchapisha?"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 9a06855..fb6afa3 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"வைஃபை டைரக்ட் மூலமாக இணைக்கிறது"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> இல் தற்போதைய நெட்வொர்க் மூலம் இணைக்கிறது"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"இயல்புநிலை அச்சிடுதல் சேவையானது அடிப்படையான விருப்பத்தேர்வுகளை வழங்குகிறது. இந்த பிரிண்ட்டருக்கான மற்ற விருப்பத்தேர்வுகள் வேறு அச்சிடுதல் சேவை மூலம் கிடைக்கக்கூடும்."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"பரிந்துரைக்கப்படும் சேவைகள்"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"பரிந்துரைக்கப்படும் சேவைகள்"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"நிறுவுவதற்கு தேர்வு செய்யவும்"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"இயக்குவதற்குத் தேர்ந்தெடுக்கவும்"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"சேவைகளை நிர்வகி"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"சேவைகளை நிர்வகியுங்கள்"</string>
     <string name="security" msgid="2279008326210305401">"பாதுகாப்பு"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"இந்தப் பிரிண்டரோ இதன் பெயரில் வேறொரு சாதனமோ புதிய பாதுகாப்பு சான்றிதழை வழங்கியுள்ளது. புதிய சான்றிதழை ஏற்கவா?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"இந்தப் பிரிண்ட்டரானது என்க்ரிப்ஷன் செய்தவற்றை அச்சிடாது. அச்சிடுவதைத் தொடரவா?"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 278f19a..a938e9b 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct ద్వారా కనెక్ట్ చేస్తోంది"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> వద్ద ప్రస్తుత నెట్‌వర్క్ ద్వారా కనెక్ట్ చేస్తోంది"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ఆటోమేటిక్ ప్రింట్ సర్వీస్‌లో ప్రాథమిక ఆప్షన్‌లు అందించబడతాయి. ఈ ప్రింటర్‌కు సంబంధించిన ఇతర ఆప్షన్‌లు మరొక ప్రింట్ సర్వీస్‌లో అందుబాటులో ఉండవచ్చు."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"సిఫార్సు చేయబడిన సేవలు"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"సిఫార్సు చేసిన సర్వీస్‌లు"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ఇన్‌స్టాల్ చేయడానికి ఎంచుకోండి"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"ప్రారంభించడానికి ఎంచుకోండి"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"సేవలను మేనేజ్ చేయండి"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"సర్వీస్‌లను మేనేజ్ చేస్తుంది"</string>
     <string name="security" msgid="2279008326210305401">"సెక్యూరిటీ"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ఈ ప్రింటర్‌కు కొత్త సెక్యూరిటీ సర్టిఫికెట్‌ అందించి ఉండవచ్చు, లేదా వేరే పరికరం ఏదైనా దీన్ని అనుకరిస్తూ ఉండవచ్చు. కొత్త సర్టిఫికెట్‌ను ఆమోదిస్తారా?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"ఈ ప్రింటర్ ఇకపై ఎన్‌క్రిప్ట్ చేసిన ఫైళ్లను తీసుకోదు అయినా ప్రింట్ చేయడాన్ని కొనసాగిస్తారా?"</string>
@@ -75,5 +75,5 @@
     <string name="disable_wifi_direct" msgid="4824677957241687577">"Wi-Fi Directను డిజేబుల్ చేయి"</string>
     <string name="wifi_direct_permission_rationale" msgid="4671416845852665202">"సమీపంలోని ప్రింటర్‌లను కనుగొనడానికి ఆటోమేటిక్ ప్రింట్ సర్వీస్‌కు సమీపంలోని పరికరాల అనుమతి అవసరం."</string>
     <string name="fix" msgid="7784394272611365393">"అనుమతిని రివ్యూ చేయండి"</string>
-    <string name="print" msgid="7851318072404916362">"ప్రింట్ చేయి"</string>
+    <string name="print" msgid="7851318072404916362">"ప్రింట్ చేయండి"</string>
 </resources>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index abdac1f..e4f0833 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"เชื่อมต่อผ่าน Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"เชื่อมต่อผ่านเครือข่ายปัจจุบันที่ <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"บริการพิมพ์เริ่มต้นมีตัวเลือกพื้นฐานต่างๆ ตัวเลือกอื่นๆ สำหรับเครื่องพิมพ์นี้อาจพร้อมให้ใช้งานจากบริการพิมพ์อื่น"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"บริการที่แนะนำ"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"บริการที่แนะนำ"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"เลือกเพื่อติดตั้ง"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"เลือกเพื่อเปิดใช้"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"จัดการบริการ"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"จัดการบริการ"</string>
     <string name="security" msgid="2279008326210305401">"ความปลอดภัย"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"เครื่องพิมพ์นี้ให้ใบรับรองความปลอดภัยใหม่ หรืออุปกรณ์อื่นแอบอ้างว่าเป็นเครื่องพิมพ์นี้ ยอมรับใบรับรองใหม่ไหม"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"เครื่องพิมพ์นี้ไม่ยอมรับงานที่เข้ารหัสอีกต่อไป พิมพ์ต่อไหม"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index c49ce30..2becd42 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Kumokonekta sa pamamagitan ng Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Kumokonekta sa pamamagitan ng kasalukuyang network sa <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Nagbibigay ng mga basic na opsyon ang Serbisyo sa Default na Pag-print. Puwedeng available ang ibang opsyon para sa printer na ito sa ibang serbisyo sa pag-print."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Mga inirerekomendang serbisyo"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Mga Inirerekomendang Serbisyo"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Piliin para ma-install"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Piliin para ma-enable"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Pamahalaan ang mga serbisyo"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Pamahalaan ang Mga Serbisyo"</string>
     <string name="security" msgid="2279008326210305401">"Seguridad"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Nagbigay ang printer na ito ng bagong certificate ng seguridad, o may ibang device na nagpapanggap bilang ito. Tanggapin ang bagong certificate?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Hindi na tumatanggap ng mga naka-encrypt na gawa ang printer na ito. Ipagpatuloy ang pag-print?"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index b2f79da..2ff8a06 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Kablosuz Doğrudan Bağlantı ile bağlanıyor"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Geçerli ağ ile <xliff:g id="IP_ADDRESS">%1$s</xliff:g> adresinden bağlanıyor"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Varsayılan Yazdırma Hizmeti, temel seçenekler sağlar. Bu yazıcı için diğer seçenekler başka yazdırma hizmetinde de olabilir."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Önerilen hizmetler"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Önerilen Hizmetler"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Yüklemek için seçin"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Etkinleştirmek için seçin"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Hizmetleri yönet"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Hizmetleri Yönet"</string>
     <string name="security" msgid="2279008326210305401">"Güvenlik"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Bu yazıcı yeni bir güvenlik sertifikası sağladı veya başka bir cihaz bu yazıcının kimliğine bürünüyor. Yeni sertifikayı kabul ediyor musunuz?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Bu yazıcı artık şifrelenmiş işleri kabul etmiyor. Yazdırmaya devam etmek istiyor musunuz?"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index eabbf7b..327efcc 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Під’єднується через Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Під’єднується через поточну мережу за IP-адресою <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Стандартний сервіс друку надає основні параметри. Інші параметри цього принтера можуть походити з інших сервісів друку."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Рекомендовані сервіси"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Рекомендовані сервіси"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Виберіть, щоб установити"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Виберіть, щоб увімкнути"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Керувати сервісами"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Керувати сервісами"</string>
     <string name="security" msgid="2279008326210305401">"Безпека"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Цей принтер надав новий сертифікат безпеки або інший пристрій видає себе за нього. Прийняти новий сертифікат?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Цей принтер більше не підтримує зашифровані завдання. Продовжити друк?"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index a91b63a..3ace22d 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"‏بذریعہ Wi-Fi ڈائریکٹ منسلک کرتا ہے"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> پر موجودہ نیٹ ورک کے ذریعہ منسلک کرتا ہے"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"ڈیفالٹ سروس بنیادی اختیارات فراہم کرتا ہے۔ دوسرے پرنٹ سروس کی جانب سے اس پرنٹر کے لیے دیگر اختیارات دستیاب ہو سکتے ہیں۔"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"تجویز کردہ سروسز"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"تجویز کردہ سروسز"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"انسٹال کرنے کے لیے منتخب کریں"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"فعال کرنے کیلئے منتخب کریں"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"سروسز کا نظم کریں"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"سروسز کا نظم کریں"</string>
     <string name="security" msgid="2279008326210305401">"سیکیورٹی"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"اس پرنٹر نے سیکیورٹی کا ایک نیا سرٹیفیکیٹ فراہم کیا ہے یا کوئی دوسرا آلہ اس کی شخصیت گیری کر رہا ہے۔ نیا سرٹیفیکیٹ قبول کریں؟"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"یہ پرنٹر اب مرموز کردہ جابز کو قبول نہیں کرتا ہے۔ پرنٹ کرنا جاری رکھیں؟"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 187e1f8..ee74509 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Wi-Fi Direct orqali ulanadi"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> manzilida joriy tarmoq orqali ulanadi"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Standart chop etish xizmati taqdim qiladigan oddiy variantlar. Qolgan variantlarni boshqa chop etish xizmatidan olish mumkin."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Tavsiya etilgan xizmatlar"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Tavsiya etilgan xizmatlar"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Oʻrnatish uchun tanlang"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Yoqish uchun tanlang"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Xizmatlarni boshqarish"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Xizmatlarni boshqarish"</string>
     <string name="security" msgid="2279008326210305401">"Xavfsizlik"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Bu printerga yangi xavfsizlik sertifikati berilgan. Bu printer nomi ostida boshqa printer ishlayotganga oʻxshaydi. Yangi sertifikatni qabul qilasizmi?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Bu printer endi shifrlangan vazifalarni qabul qilmaydi. Bosmaga chiqarilsinmi?"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 76d65c7..37bae88 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Kết nối qua Wi-Fi Direct"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Kết nối qua mạng hiện tại tại <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Dịch vụ in mặc định có các tùy chọn cơ bản. Bạn có thể sử dụng các tùy chọn khác của một dịch vụ in khác cho máy in này."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Dịch vụ đề xuất"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Dịch vụ được đề xuất"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Chọn để cài đặt"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Chọn để bật"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Quản lý dịch vụ"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Quản lý dịch vụ"</string>
     <string name="security" msgid="2279008326210305401">"Bảo mật"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Máy in này đã cung cấp một chứng chỉ bảo mật mới hoặc một thiết bị khác đang mạo danh máy in này. Chấp nhận chứng chỉ mới?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Máy in này không còn chấp nhận các lệnh in đã mã hóa. Bạn muốn tiếp tục in?"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 1abaff9..3e23404 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"通过 WLAN 直连连接"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"在 <xliff:g id="IP_ADDRESS">%1$s</xliff:g> 通过当前网络连接"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"默认打印服务会提供基本选项。这个打印机的其他选项可能由其他打印服务提供。"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"推荐的服务"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"推荐的服务"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"选择以安装"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"选择以启用"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"管理服务"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"管理服务"</string>
     <string name="security" msgid="2279008326210305401">"安全"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"此打印机提供了新的安全证书，或其他设备正在冒充此打印机。要接受新证书吗？"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"此打印机不再接受加密的作业。要继续打印吗？"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index fc19c26..287b1ce 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"透過 Wi-Fi Direct 連線"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"透過目前的網絡 (<xliff:g id="IP_ADDRESS">%1$s</xliff:g>) 連線"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"「預設列印服務」提供基本選項，此打印機的其他選項或可在其他列印服務中使用。"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"推薦服務"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"建議的服務"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"選取即可安裝"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"選取即可啟用"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"管理服務"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"管理服務"</string>
     <string name="security" msgid="2279008326210305401">"安全性"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"此打印機提供了新的安全憑證，或者另一部裝置正在冒用其身分。要接受新的憑證嗎？"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"此打印機不再接受加密工作。要繼續列印嗎？"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 8900179..3bca89f 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"透過 Wi-Fi Direct 連線"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"透過目前的網路 (<xliff:g id="IP_ADDRESS">%1$s</xliff:g>) 連線"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"預設列印服務會提供基本選項，這個印表機的其他選項則可能由其他列印服務提供。"</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"建議的服務"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"推薦的服務"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"選取即可安裝"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"選取即可啟用"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"管理服務"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"管理服務"</string>
     <string name="security" msgid="2279008326210305401">"安全性"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"這台印表機提供新的安全性憑證，或有其他裝置冒用該印表機的身分。要接受新的憑證嗎？"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"這台印表機不再支援已加密的工作。要繼續列印嗎？"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 319fc99..36267e4 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -61,10 +61,10 @@
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"Ixhuma nge-Wi-Fi eqondile"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Ixhuma ngenethiwekhi ku-<xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Isevisi yokuphrinta ezenzakalelayo inikezela ngezinketho eziyisisekelo. Ezinye izinketho zale phrinti zingatholakala kusuka kwenye isevisi yokuphrinta."</string>
-    <string name="recommendations_heading" msgid="5086762263560605249">"Amasevisi anconyiwe"</string>
+    <string name="recommendations_heading" msgid="5609754983795588470">"Amasevisi Anconyiwe"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"Khetha ukuze ufake"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Khetha ukuze unike amandla"</string>
-    <string name="recommendation_manage" msgid="4683640588502866284">"Phatha amasevisi"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"Lawula Amasevisi"</string>
     <string name="security" msgid="2279008326210305401">"Ezokuvikela"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"Le phrinta inikeze isitifiketi esisha sokuvikela, noma enye idivayisi izenza yona. Yamukela isitifiketi esisha?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"Le phrinta ayisamukeli imisebenzi ebetheliwe. Qhubeka uphrinte?"</string>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 2c6508f..75bd1b0 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -15,7 +15,7 @@
      limitations under the License.
 -->
 
-<resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+<resources xmlns:android="http://schemas.android.com/apk/res/android" xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
 
     <string name="app_name">Default Print Service</string>
 
@@ -89,13 +89,13 @@
     <!-- Explain purpose of recommendation fragment [CHAR LIMIT=UNLIMITED] -->
     <string name="recommendation_summary">The Default Print Service provides basic options. Other options for this printer may be available from another print service.</string>
     <!-- Heading for services that are not currently installed, but recommended [CHAR LIMIT=UNLIMITED] -->
-    <string name="recommendations_heading">Recommended services</string>
+    <string name="recommendations_heading">Recommended Services</string>
     <!-- Summary for recommended services that are not installed [CHAR LIMIT=UNLIMITED] -->
     <string name="recommendation_install_summary">Select to install</string>
     <!-- Summary for recommended services that are installed [CHAR LIMIT=UNLIMITED] -->
     <string name="recommendation_enable_summary">Select to enable</string>
     <!-- Button to allow user to enable/disable installed print services. [CHAR LIMIT=UNLIMITED] -->
-    <string name="recommendation_manage">Manage services</string>
+    <string name="recommendation_manage">Manage Services</string>
 
     <!-- Channel name for security-related notifications [CHAR LIMIT=40] -->
     <string name="security">Security</string>
@@ -122,4 +122,5 @@
 
     <!-- Share-to-print label [CHAR LIMIT=20] -->
     <string name="print">Print</string>
+
 </resources>
diff --git a/res/values/themes.xml b/res/values/themes.xml
deleted file mode 100644
index a88edcf..0000000
--- a/res/values/themes.xml
+++ /dev/null
@@ -1,6 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<resources>
-    <style name="Theme.BuiltInPrintService" parent="@android:style/Theme.DeviceDefault.Settings">
-        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
-    </style>
-</resources>
\ No newline at end of file
diff --git a/res/xml/more_options_prefs.xml b/res/xml/more_options_prefs.xml
index b491a74..6da2974 100644
--- a/res/xml/more_options_prefs.xml
+++ b/res/xml/more_options_prefs.xml
@@ -34,4 +34,4 @@
         android:icon="@drawable/ic_settings_gear"
         android:persistent="false"
         android:order="2" />
-</PreferenceScreen>
+</PreferenceScreen>
\ No newline at end of file
diff --git a/src/com/android/bips/BuiltInPrintService.java b/src/com/android/bips/BuiltInPrintService.java
index e62cb66..10432b5 100644
--- a/src/com/android/bips/BuiltInPrintService.java
+++ b/src/com/android/bips/BuiltInPrintService.java
@@ -181,6 +181,10 @@ public class BuiltInPrintService extends PrintService {
         return mAllDiscovery;
     }
 
+    public Backend getBackend() {
+        return mBackend;
+    }
+
     /**
      * Return the global object for MDNS discoveries
      */
diff --git a/src/com/android/bips/ipp/Backend.java b/src/com/android/bips/ipp/Backend.java
index a77904a..7d8c293 100644
--- a/src/com/android/bips/ipp/Backend.java
+++ b/src/com/android/bips/ipp/Backend.java
@@ -35,6 +35,7 @@ import com.android.bips.jni.JobCallbackParams;
 import com.android.bips.jni.LocalJobParams;
 import com.android.bips.jni.LocalPrinterCapabilities;
 import com.android.bips.jni.PdfRender;
+import com.android.bips.jni.PrinterStatusMonitor;
 import com.android.bips.util.FileUtils;
 
 import java.io.File;
@@ -177,7 +178,7 @@ public class Backend implements JobCallback {
      * is no longer required. After closing this object it should be discarded.
      */
     public void close() {
-        new Thread(this::nativeExit).start();
+        nativeExit();
         PdfRender.getInstance(mContext).close();
     }
 
@@ -239,7 +240,7 @@ public class Backend implements JobCallback {
      * @param address any string in the format xxx/yyy/zzz
      * @return the part before the "/" or "xxx" in this case
      */
-    static String getIp(String address) {
+   public static String getIp(String address) {
         int i = address.indexOf('/');
         return i == -1 ? address : address.substring(0, i);
     }
@@ -277,6 +278,34 @@ public class Backend implements JobCallback {
     native int nativeGetCapabilities(String address, int port, String httpResource,
             String uriScheme, long timeout, LocalPrinterCapabilities capabilities);
 
+    /**
+     * Java native interface to setup to monitor status
+     *
+     * @param address      printer address
+     * @param port         printer port
+     * @param httpResource printer http resource
+     * @param uriScheme    printer URI scheme
+     * @return status handle
+     */
+    public native long nativeMonitorStatusSetup(
+            String address, int port, String httpResource, String uriScheme
+    );
+
+    /**
+     * Java native interface to start to monitor status
+     *
+     * @param statusId status ID
+     * @param monitor  print status monitor
+     */
+    public native void nativeMonitorStatusStart(long statusId, PrinterStatusMonitor monitor);
+
+    /**
+     * Java native interface to stop to monitor status
+     *
+     * @param statusId status ID
+     */
+    public native void nativeMonitorStatusStop(long statusId);
+
     /**
      * Determine initial parameters to be used for jobs
      *
diff --git a/src/com/android/bips/ipp/JobStatus.java b/src/com/android/bips/ipp/JobStatus.java
index 57ad694..b804587 100644
--- a/src/com/android/bips/ipp/JobStatus.java
+++ b/src/com/android/bips/ipp/JobStatus.java
@@ -173,4 +173,8 @@ public class JobStatus {
             return new JobStatus(mPrototype);
         }
     }
+
+    public static Map<String, Integer> getBlockReasonsMap() {
+        return sBlockReasonsMap;
+    }
 }
diff --git a/src/com/android/bips/ipp/StartJobTask.java b/src/com/android/bips/ipp/StartJobTask.java
old mode 100755
new mode 100644
index 196c8c9..fbdd8e2
--- a/src/com/android/bips/ipp/StartJobTask.java
+++ b/src/com/android/bips/ipp/StartJobTask.java
@@ -1,6 +1,6 @@
 /*
  * Copyright (C) 2016 The Android Open Source Project
- * Copyright (C) 2016 Mopria Alliance, Inc.
+ * Copyright (C) 2016 - 2024 Mopria Alliance, Inc.
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -18,7 +18,13 @@
 package com.android.bips.ipp;
 
 import android.content.Context;
-import android.graphics.pdf.PdfRenderer;
+import android.graphics.Bitmap;
+import android.graphics.Canvas;
+import android.graphics.Matrix;
+import android.graphics.Paint;
+import android.graphics.Path;
+import android.graphics.PorterDuff;
+import android.graphics.PorterDuffXfermode;
 import android.net.Uri;
 import android.os.AsyncTask;
 import android.os.Build;
@@ -35,6 +41,8 @@ import com.android.bips.jni.BackendConstants;
 import com.android.bips.jni.LocalJobParams;
 import com.android.bips.jni.LocalPrinterCapabilities;
 import com.android.bips.jni.MediaSizes;
+import com.android.bips.jni.PdfRender;
+import com.android.bips.jni.SizeD;
 import com.android.bips.util.FileUtils;
 
 import java.io.BufferedOutputStream;
@@ -42,6 +50,7 @@ import java.io.File;
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.util.Objects;
+import java.nio.ByteBuffer;
 
 /**
  * A background task that starts sending a print job. The result of this task is an integer
@@ -65,13 +74,18 @@ class StartJobTask extends AsyncTask<Void, Void, Integer> {
     private static final int SIDES_DUPLEX_SHORT_EDGE = 2;
 
     private static final int RESOLUTION_300_DPI = 300;
+    private static final int MARGIN_CHECK_72_DPI = 72;
 
     private static final int COLOR_SPACE_MONOCHROME = 0;
     private static final int COLOR_SPACE_COLOR = 1;
 
     private static final int BORDERLESS_OFF = 0;
     private static final int BORDERLESS_ON = 1;
+    private static final float POINTS_PER_INCH = 72;
 
+    /** Threshold value for catering slight variation b/w source and paper size dimensions*/
+    private static final float PAGE_SIZE_EPSILON = 0.04f;
+    private final double mZoomFactor = MARGIN_CHECK_72_DPI / POINTS_PER_INCH;
     private final Context mContext;
     private final Backend mBackend;
     private final Uri mDestination;
@@ -116,7 +130,6 @@ class StartJobTask extends AsyncTask<Void, Void, Integer> {
         mJobParams.color_space = getColorSpace();
         mJobParams.document_category = getDocumentCategory();
         mJobParams.shared_photo = isSharedPhoto();
-        mJobParams.preserve_scaling = false;
 
         mJobParams.job_margin_top = Math.max(mJobParams.job_margin_top, 0.0f);
         mJobParams.job_margin_left = Math.max(mJobParams.job_margin_left, 0.0f);
@@ -166,18 +179,28 @@ class StartJobTask extends AsyncTask<Void, Void, Integer> {
 
             // Fill in job parameters from capabilities and print job info.
             populateJobParams();
-            try (PdfRenderer renderer = new PdfRenderer(
-                    ParcelFileDescriptor.open(pdfFile, ParcelFileDescriptor.MODE_READ_ONLY));
-                 PdfRenderer.Page page = renderer.openPage(0)) {
+            PdfRender pdfRender = PdfRender.getInstance(mContext);
+            int pageCount = pdfRender.openDocument(pdfFile.getPath());
+            if (pageCount > 0) {
+                SizeD pageSize = pdfRender.getPageSize(1);
                 if (mJobParams.portrait_mode) {
-                    mJobParams.source_height = (float) page.getHeight() / 72;
-                    mJobParams.source_width = (float) page.getWidth() / 72;
+                    mJobParams.source_height = (float) pageSize.getHeight() / POINTS_PER_INCH;
+                    mJobParams.source_width = (float) pageSize.getWidth() / POINTS_PER_INCH;
                 } else {
-                    mJobParams.source_width = (float) page.getHeight() / 72;
-                    mJobParams.source_height = (float) page.getWidth() / 72;
+                    mJobParams.source_width = (float) pageSize.getHeight() / POINTS_PER_INCH;
+                    mJobParams.source_height = (float) pageSize.getWidth() / POINTS_PER_INCH;
                 }
-            } catch (IOException e) {
-                Log.w(TAG, "Error while getting source width, height", e);
+
+                // Print at 1:1 scale only if the page count is 1, the document is not a photo, the
+                // document size matches the paper size, and there is no content in the margins.
+                if (pageCount == 1) {
+                    mJobParams.print_at_scale = !getDocumentCategory().equals(
+                            BackendConstants.PRINT_DOCUMENT_CATEGORY__PHOTO) &&
+                            isDocSizeEqualsPaperSize() &&
+                            isContentAtMarginsEmpty(pdfRender, pointsToPixels(pageSize.getHeight()),
+                                    pointsToPixels(pageSize.getWidth()));
+                }
+                pdfRender.closeDocument();
             }
 
             // Finalize job parameters
@@ -209,6 +232,85 @@ class StartJobTask extends AsyncTask<Void, Void, Integer> {
         }
     }
 
+    private boolean isDocSizeEqualsPaperSize() {
+        PrintAttributes.MediaSize mediaSize = mJobInfo.getAttributes().getMediaSize();
+        if (mediaSize == null) {
+            return false;
+        }
+        float paperWidth = mediaSize.getWidthMils() / 1000f;
+        float paperHeight = mediaSize.getHeightMils() / 1000f;
+        return Math.abs(mJobParams.source_width - paperWidth) < PAGE_SIZE_EPSILON
+                && Math.abs(mJobParams.source_height - paperHeight) < PAGE_SIZE_EPSILON;
+    }
+
+    /** Converts cmm(hundredths of mm) to pixels at 72 DPI. */
+    private int cmmToPixels(int cmm) {
+        return Math.round((float) cmm / 2540 * MARGIN_CHECK_72_DPI);
+    }
+
+    /** Converts points to pixels. */
+    private int pointsToPixels(double points) {
+        return (int) Math.round(points * mZoomFactor);
+    }
+
+    /**
+     * Returns true if there is no content in the margins of the printer.
+     */
+    private boolean isContentAtMarginsEmpty(PdfRender pdfRender, int pageHeight, int pageWidth) {
+        int topMargin = cmmToPixels(mCapabilities.printerTopMargin);
+        int bottomMargin = cmmToPixels(mCapabilities.printerBottomMargin);
+        int leftMargin = cmmToPixels(mCapabilities.printerLeftMargin);
+        int rightMargin = cmmToPixels(mCapabilities.printerRightMargin);
+
+        if (topMargin == 0 && bottomMargin == 0 && leftMargin == 0 && rightMargin == 0) {
+            return false;
+        }
+
+        boolean emptyContentAtMargins = false;
+        Bitmap pageBitmap = pdfRender.renderPage(1, pageWidth, pageHeight);
+        if (pageBitmap != null) {
+            Bitmap overlayBmp = overlayBitmap(pageBitmap, topMargin, bottomMargin, leftMargin,
+                    rightMargin);
+            ByteBuffer buff = ByteBuffer.allocate(overlayBmp.getByteCount());
+            overlayBmp.copyPixelsToBuffer(buff);
+            emptyContentAtMargins = isEmptyByteArray(buff.array());
+            overlayBmp.recycle();
+        }
+        return emptyContentAtMargins;
+    }
+
+    private boolean isEmptyByteArray(byte[] byteArray) {
+        for (byte b : byteArray) {
+            if (b > 0) {
+                return false;
+            }
+        }
+        return true;
+    }
+
+    private Bitmap overlayBitmap(Bitmap bmp, int topMargin, int bottomMargin, int leftMargin,
+            int rightMargin) {
+        Bitmap bmpOverlay = Bitmap.createBitmap(bmp.getWidth(), bmp.getHeight(), bmp.getConfig());
+        Canvas canvas = new Canvas(bmpOverlay);
+        canvas.drawBitmap(bmp, new Matrix(), null);
+
+        int printableWidth = bmp.getWidth() - (leftMargin + rightMargin);
+        int printableHeight = bmp.getHeight() - (topMargin + bottomMargin);
+        int posX = leftMargin;
+        int posY = topMargin;
+
+        Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
+        paint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
+
+        Path path = new Path();
+        path.addRect(posX, posY, posX + printableWidth, posY + printableHeight, Path.Direction.CW);
+        // Draw the path to clip on the canvas, thus removing the pixels.
+        canvas.drawPath(path, paint);
+
+        bmp.recycle();
+        return bmpOverlay;
+    }
+
     private boolean isBorderless() {
         return mCapabilities.borderless
                 && mDocInfo.getContentType() == PrintDocumentInfo.CONTENT_TYPE_PHOTO;
diff --git a/src/com/android/bips/jni/BackendConstants.java b/src/com/android/bips/jni/BackendConstants.java
index f780303..899f188 100644
--- a/src/com/android/bips/jni/BackendConstants.java
+++ b/src/com/android/bips/jni/BackendConstants.java
@@ -171,4 +171,10 @@ public class BackendConstants {
     public static final String PARAM_RESULT = "result";
     public static final String PARAM_ERROR_MESSAGES = "error_messages";
     public static final String PARAM_ELAPSED_TIME_ALL = "elapsed_time_all";
+
+    public static final String PRINTER_STATE_UNKNOWN = "print-state-unknown";
+    public static final String PRINTER_STATE_IDLE = "print-state-idle";
+    public static final String PRINTER_STATE_RUNNING = "print-state-running";
+    public static final String PRINTER_STATE_UNABLE_TO_CONNECT = "print-state-unable-to-connect";
+    public static final String PRINTER_STATE_BLOCKED = "print-state-blocked";
 }
diff --git a/src/com/android/bips/jni/LocalJobParams.java b/src/com/android/bips/jni/LocalJobParams.java
old mode 100755
new mode 100644
index 1f3af5b..b83b73e
--- a/src/com/android/bips/jni/LocalJobParams.java
+++ b/src/com/android/bips/jni/LocalJobParams.java
@@ -66,7 +66,7 @@ public final class LocalJobParams {
     public float source_height;
 
     public boolean shared_photo;
-    public boolean preserve_scaling;
+    public boolean print_at_scale;
 
     @Override
     public String toString() {
@@ -108,7 +108,7 @@ public final class LocalJobParams {
                 + " source_width=" + source_width
                 + " source_height=" + source_height
                 + " shared_photo=" + shared_photo
-                + " preserve_scaling=" + preserve_scaling
+                + " print_at_scale=" + print_at_scale
                 + "}";
     }
 }
diff --git a/src/com/android/bips/jni/LocalPrinterCapabilities.java b/src/com/android/bips/jni/LocalPrinterCapabilities.java
index 332ce5d..17b0f22 100644
--- a/src/com/android/bips/jni/LocalPrinterCapabilities.java
+++ b/src/com/android/bips/jni/LocalPrinterCapabilities.java
@@ -42,6 +42,11 @@ public class LocalPrinterCapabilities {
     public boolean borderless;
     public boolean color;
 
+    public int printerTopMargin;
+    public int printerBottomMargin;
+    public int printerLeftMargin;
+    public int printerRightMargin;
+
     /** Reported MIME types include at least one that the lower layer supports */
     public boolean isSupported;
 
@@ -57,6 +62,16 @@ public class LocalPrinterCapabilities {
     /** Public key of certificate for this printer, if known */
     public byte[] certificate;
 
+    public int[] mediaReadySizes;
+    public String mopriaCertified;
+    public String[] markerNames;
+    public String[] markerTypes;
+    public String[] markerColors;
+    public int[] markerHighLevel;
+    public int[] markerLowLevel;
+    public int[] markerLevel;
+    public String[] mPrinterIconUris;
+
     public void buildCapabilities(BuiltInPrintService service,
             PrinterCapabilitiesInfo.Builder builder) {
         builder.setColorModes(
@@ -120,6 +135,10 @@ public class LocalPrinterCapabilities {
                 + " duplex=" + duplex
                 + " borderless=" + borderless
                 + " color=" + color
+                + " printerTopMargin=" + printerTopMargin
+                + " printerBottomMargin=" + printerBottomMargin
+                + " printerLeftMargin=" + printerLeftMargin
+                + " printerRightMargin=" + printerRightMargin
                 + " isSupported=" + isSupported
                 + " mediaDefault=" + mediaDefault
                 + " supportedMediaTypes=" + Arrays.toString(supportedMediaTypes)
diff --git a/src/com/android/bips/jni/MediaSizes.java b/src/com/android/bips/jni/MediaSizes.java
index 1efad5f..059dead 100644
--- a/src/com/android/bips/jni/MediaSizes.java
+++ b/src/com/android/bips/jni/MediaSizes.java
@@ -20,6 +20,7 @@ package com.android.bips.jni;
 import android.annotation.SuppressLint;
 import android.content.Context;
 import android.print.PrintAttributes;
+import android.util.Log;
 
 import com.android.bips.R;
 
@@ -62,7 +63,8 @@ public class MediaSizes {
 
     /** The backend string name for the default media size */
     static final String DEFAULT_MEDIA_NAME = ISO_A4;
-
+    private static final String TAG = MediaSizes.class.getSimpleName();
+    private static final boolean DEBUG = false;
     @SuppressLint("UseSparseArrays")
     private static final Map<Integer, String> sCodeToStringMap = new HashMap<>();
 
@@ -203,4 +205,13 @@ public class MediaSizes {
         }
         return 0;
     }
+
+    public String getMediaName(int code, Context context) {
+        try {
+            return mNameToSizeMap.get(toMediaName(code)).getLabel(context.getPackageManager());
+        } catch (Exception e) {
+            if (DEBUG) Log.d(TAG, e.toString());
+            return context.getString(R.string.unknown);
+        }
+    }
 }
diff --git a/src/com/android/bips/jni/PdfRender.java b/src/com/android/bips/jni/PdfRender.java
index f2f854e..fb84d8d 100644
--- a/src/com/android/bips/jni/PdfRender.java
+++ b/src/com/android/bips/jni/PdfRender.java
@@ -21,6 +21,7 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.ServiceConnection;
+import android.graphics.Bitmap;
 import android.os.IBinder;
 import android.os.ParcelFileDescriptor;
 import android.os.RemoteException;
@@ -98,7 +99,7 @@ public class PdfRender {
      * Opens the specified document, returning the page count or 0 on error. (Called by native
      * code.)
      */
-    private int openDocument(String fileName) {
+    public int openDocument(String fileName) {
         if (DEBUG) Log.d(TAG, "openDocument() " + fileName);
         if (mService == null) {
             return 0;
@@ -120,7 +121,7 @@ public class PdfRender {
 
     /**
      * Returns the size of the specified page or null on error. (Called by native code.)
-     * @param page 0-based page
+     * @param page 1-based page
      * @return width and height of page in points (1/72")
      */
     public SizeD getPageSize(int page) {
@@ -139,7 +140,7 @@ public class PdfRender {
 
     /**
      * Renders the content of the page. (Called by native code.)
-     * @param page 0-based page
+     * @param page 1-based page
      * @param y y-offset onto page
      * @param width width of area to render
      * @param height height of area to render
@@ -185,6 +186,29 @@ public class PdfRender {
         }
     }
 
+    /**
+     * Renders the content of the page to a bitmap.
+     *
+     * @param page   1-based page
+     * @param width  width of area to render
+     * @param height height of area to render
+     * @return Bitmap if rendering was successful or null on error
+     */
+    public Bitmap renderPage(int page, int width, int height) {
+        if (DEBUG) {
+            Log.d(TAG, "renderPage() page=" + " w=" + width + " h=" + height);
+        }
+        if (mService == null || page < 1) {
+            return null;
+        }
+        try {
+            return mService.renderPage(page - 1, width, height);
+        } catch (RemoteException | IllegalArgumentException | OutOfMemoryError ex) {
+            Log.w(TAG, "Render failed", ex);
+            return null;
+        }
+    }
+
     /**
      * Releases any open resources for the current document and page.
      */
diff --git a/src/com/android/bips/jni/PrinterStatusMonitor.kt b/src/com/android/bips/jni/PrinterStatusMonitor.kt
new file mode 100644
index 0000000..b96bd6b
--- /dev/null
+++ b/src/com/android/bips/jni/PrinterStatusMonitor.kt
@@ -0,0 +1,49 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2024 Mopria Alliance, Inc.
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
+package com.android.bips.jni
+
+import android.net.Uri
+import com.android.bips.BuiltInPrintService
+import com.android.bips.ipp.Backend
+
+class PrinterStatusMonitor(
+    path: Uri, service: BuiltInPrintService,
+    private val onPrinterStatus: (JobCallbackParams) -> Unit
+) {
+    private val statusId: Long
+    init {
+        statusId = service.backend.nativeMonitorStatusSetup(
+            Backend.getIp(path.host),
+            path.port, path.path, path.scheme
+        )
+        if (statusId != 0L) {
+            service.backend.nativeMonitorStatusStart(statusId, this)
+        }
+    }
+
+    fun stopMonitor(service: BuiltInPrintService) {
+        service.backend.nativeMonitorStatusStop(statusId)
+    }
+
+    /**
+     * This method is calling from JNI layer
+     */
+    private fun callbackReceiver(status: JobCallbackParams) {
+        onPrinterStatus(status)
+    }
+}
\ No newline at end of file
diff --git a/src/com/android/bips/render/IPdfRender.aidl b/src/com/android/bips/render/IPdfRender.aidl
index a7a692f..0b16e1e 100644
--- a/src/com/android/bips/render/IPdfRender.aidl
+++ b/src/com/android/bips/render/IPdfRender.aidl
@@ -48,6 +48,16 @@ interface IPdfRender {
     ParcelFileDescriptor renderPageStripe(int page, int y, int width, int height,
         double zoomFactor);
 
+    /**
+     * Render a page from the open document as a bitmap.
+     *
+     * @param page number to render
+     * @param width full-page width of bitmap to render
+     * @param height height of strip to render
+     * @return Bitmap of the rendered page or null on error
+     */
+    Bitmap renderPage(int page, int width, int height);
+
     /**
      * Release all internal resources related to the open document
      */
diff --git a/src/com/android/bips/render/PdfRenderService.java b/src/com/android/bips/render/PdfRenderService.java
index 4f15a92..8a6d076 100644
--- a/src/com/android/bips/render/PdfRenderService.java
+++ b/src/com/android/bips/render/PdfRenderService.java
@@ -62,7 +62,7 @@ public class PdfRenderService extends Service {
 
     private final IPdfRender.Stub mBinder = new IPdfRender.Stub() {
         @Override
-        public int openDocument(ParcelFileDescriptor pfd) throws RemoteException {
+        public synchronized int openDocument(ParcelFileDescriptor pfd) throws RemoteException {
             if (!open(pfd)) {
                 return 0;
             }
@@ -70,7 +70,7 @@ public class PdfRenderService extends Service {
         }
 
         @Override
-        public SizeD getPageSize(int page) throws RemoteException {
+        public synchronized SizeD getPageSize(int page) throws RemoteException {
             if (!openPage(page)) {
                 return null;
             }
@@ -78,8 +78,19 @@ public class PdfRenderService extends Service {
         }
 
         @Override
-        public ParcelFileDescriptor renderPageStripe(int page, int y, int width, int height,
-                double zoomFactor)
+        public synchronized Bitmap renderPage(int page, int width, int height)
+                throws RemoteException {
+            if (!openPage(page)) {
+                return null;
+            }
+            Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
+            mPage.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_PRINT);
+            return bitmap;
+        }
+
+        @Override
+        public synchronized ParcelFileDescriptor renderPageStripe(int page, int y, int width,
+                int height, double zoomFactor)
                 throws RemoteException {
             if (!openPage(page)) {
                 return null;
@@ -101,7 +112,7 @@ public class PdfRenderService extends Service {
         }
 
         @Override
-        public void closeDocument() throws RemoteException {
+        public synchronized void closeDocument() throws RemoteException {
             if (DEBUG) Log.d(TAG, "closeDocument");
             closeAll();
         }
diff --git a/src/com/android/bips/ui/AddPrintersActivity.java b/src/com/android/bips/ui/AddPrintersActivity.java
index 182b108..7e0d9f2 100644
--- a/src/com/android/bips/ui/AddPrintersActivity.java
+++ b/src/com/android/bips/ui/AddPrintersActivity.java
@@ -39,6 +39,8 @@ public class AddPrintersActivity extends Activity {
         if (actionBar != null) {
             actionBar.setDisplayHomeAsUpEnabled(true);
         }
+
+        ViewUtil.setWindowInsetsListener(getWindow().getDecorView(), this);
     }
 
     @Override
@@ -46,7 +48,7 @@ public class AddPrintersActivity extends Activity {
         switch (item.getItemId()) {
             // Respond to the action bar's Up/Home button
             case android.R.id.home:
-                onBackPressed();
+                finish();
                 return true;
         }
         return super.onOptionsItemSelected(item);
diff --git a/src/com/android/bips/ui/MarkerAdapter.kt b/src/com/android/bips/ui/MarkerAdapter.kt
new file mode 100644
index 0000000..90f2f19
--- /dev/null
+++ b/src/com/android/bips/ui/MarkerAdapter.kt
@@ -0,0 +1,91 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2024 Mopria Alliance, Inc.
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
+package com.android.bips.ui
+
+import android.graphics.Color
+import android.graphics.drawable.LayerDrawable
+import android.view.LayoutInflater
+import android.view.View
+import android.view.ViewGroup
+import android.widget.ImageView
+import android.widget.ProgressBar
+import androidx.core.graphics.BlendModeColorFilterCompat
+import androidx.core.graphics.BlendModeCompat
+import androidx.recyclerview.widget.RecyclerView
+import com.android.bips.R
+
+/**
+ * Marker Adapter
+ *
+ * Recyclerview adapter for showing ink levels in printer information screen
+ *
+ * @property mMarkerInfoList list of marker info
+ * @constructor constructor
+ */
+class MarkerAdapter(private val mMarkerInfoList: ArrayList<MarkerInfo>) :
+    RecyclerView.Adapter<MarkerAdapter.MarkerViewHolder>() {
+        inner class MarkerViewHolder(val view: View) : RecyclerView.ViewHolder(view) {
+            var seekbar: ProgressBar = itemView.findViewById(R.id.seekbar)
+            var warningImage: ImageView = itemView.findViewById(R.id.warningImage)
+        }
+
+    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MarkerViewHolder {
+        val v =
+            LayoutInflater.from(parent.context).inflate(R.layout.item_marker_type, parent, false)
+        return MarkerViewHolder(v)
+    }
+
+    override fun onBindViewHolder(holder: MarkerViewHolder, position: Int) {
+        with(mMarkerInfoList[position]) {
+            holder.seekbar.max = markerHighLevel
+            val progressBarDrawable = holder.seekbar.progressDrawable as LayerDrawable
+            progressBarDrawable.getDrawable(0).colorFilter =
+                BlendModeColorFilterCompat.createBlendModeColorFilterCompat(
+                    Color.parseColor(BACKGROUND_COLOR),
+                    BlendModeCompat.SRC_IN
+                )
+            progressBarDrawable.getDrawable(1).colorFilter =
+                BlendModeColorFilterCompat.createBlendModeColorFilterCompat(
+                    Color.parseColor(markerColor),
+                    BlendModeCompat.SRC_IN
+                )
+            // Set progress level on a scale of 0-10000
+            progressBarDrawable.getDrawable(1).level =
+                if (markerHighLevel != 0 && markerLevel > 1) {
+                    markerLevel * 10000 / markerHighLevel
+                } else {
+                    100 // set 1% as minimum level
+                }
+
+            if (markerLevel <= markerLowLevel) {
+                holder.warningImage.visibility = View.VISIBLE
+            } else {
+                holder.warningImage.visibility = View.INVISIBLE
+            }
+        }
+    }
+
+    override fun getItemCount(): Int {
+        return mMarkerInfoList.size
+    }
+
+    companion object {
+        /** Seekbar background */
+        private const val BACKGROUND_COLOR = "#898383"
+    }
+}
\ No newline at end of file
diff --git a/src/com/android/bips/ui/MarkerInfo.kt b/src/com/android/bips/ui/MarkerInfo.kt
new file mode 100644
index 0000000..25f1c05
--- /dev/null
+++ b/src/com/android/bips/ui/MarkerInfo.kt
@@ -0,0 +1,33 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2024 Mopria Alliance, Inc.
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
+package com.android.bips.ui
+
+/**
+ * Marker info class for showing printer supply levels
+ */
+data class MarkerInfo(
+    val markerType: String,
+
+    val markerColor: String,
+
+    val markerHighLevel: Int,
+
+    val markerLowLevel: Int,
+
+    val markerLevel: Int
+)
\ No newline at end of file
diff --git a/src/com/android/bips/ui/MoreOptionsActivity.java b/src/com/android/bips/ui/MoreOptionsActivity.java
index 2814d07..fcbeb9a 100644
--- a/src/com/android/bips/ui/MoreOptionsActivity.java
+++ b/src/com/android/bips/ui/MoreOptionsActivity.java
@@ -17,8 +17,6 @@
 package com.android.bips.ui;
 
 import android.app.ActionBar;
-import android.app.Activity;
-import android.app.FragmentManager;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
@@ -30,13 +28,20 @@ import android.print.PrinterId;
 import android.printservice.PrintService;
 import android.util.Log;
 import android.view.MenuItem;
+import android.view.View;
+import android.widget.LinearLayout;
 import android.widget.Toast;
 
+import androidx.fragment.app.FragmentActivity;
+import androidx.fragment.app.FragmentManager;
+import androidx.lifecycle.ViewModelProvider;
+
 import com.android.bips.BuiltInPrintService;
 import com.android.bips.R;
 import com.android.bips.discovery.ConnectionListener;
 import com.android.bips.discovery.DiscoveredPrinter;
 import com.android.bips.discovery.Discovery;
+import com.android.bips.flags.Flags;
 import com.android.bips.p2p.P2pPrinterConnection;
 import com.android.bips.p2p.P2pUtils;
 
@@ -48,7 +53,8 @@ import java.util.concurrent.Executors;
 /**
  * Launched by system in response to a "More Options" request while tracking a printer.
  */
-public class MoreOptionsActivity extends Activity implements ServiceConnection, Discovery.Listener {
+public class MoreOptionsActivity extends FragmentActivity implements ServiceConnection,
+        Discovery.Listener {
     private static final String TAG = MoreOptionsActivity.class.getSimpleName();
 
     private static final boolean DEBUG = false;
@@ -58,6 +64,11 @@ public class MoreOptionsActivity extends Activity implements ServiceConnection,
     DiscoveredPrinter mPrinter;
     InetAddress mPrinterAddress;
     public static final String EXTRA_PRINTER_ID = "EXTRA_PRINTER_ID";
+    private static final String TAG_RECOMMENDATION_FRAGMENT = "recommendation_fragment";
+    private static final String TAG_PRINTER_INFORMATION_FRAGMENT = "printer_information_fragment";
+    private PrinterInformationViewModel mPrinterInformationViewModel;
+    private LinearLayout mLlRecommendedServices;
+    private LinearLayout mLlRecommendedServicesSummary;
     private final ExecutorService mExecutorService = Executors.newSingleThreadExecutor();
     private P2pPrinterConnection mP2pPrinterConnection;
 
@@ -79,14 +90,50 @@ public class MoreOptionsActivity extends Activity implements ServiceConnection,
         if (actionBar != null) {
             actionBar.setDisplayHomeAsUpEnabled(true);
         }
-        getFragmentManager().popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE);
+        if ((Flags.printerInfoDetails())) {
+            setContentView(R.layout.combined_info_recs);
+            mPrinterInformationViewModel =
+                    new ViewModelProvider(this).get(PrinterInformationViewModel.class);
+            getSupportFragmentManager().popBackStack(null,
+                    FragmentManager.POP_BACK_STACK_INCLUSIVE);
+            mLlRecommendedServicesSummary = findViewById(R.id.ll_recommended_services_summary);
+            mLlRecommendedServices = findViewById(R.id.ll_recommended_services);
+            mLlRecommendedServices.setOnClickListener(view -> {
+                if (getSupportFragmentManager().findFragmentByTag(TAG_RECOMMENDATION_FRAGMENT)
+                        == null) {
+                    MoreOptionsFragment fragment = new MoreOptionsFragment();
+                    getSupportFragmentManager().beginTransaction()
+                            .replace(R.id.fragment_container, fragment, TAG_RECOMMENDATION_FRAGMENT)
+                            .setReorderingAllowed(true)
+                            .addToBackStack(null)
+                            .commit();
+                    mLlRecommendedServices.setVisibility(View.GONE);
+                    mLlRecommendedServicesSummary.setVisibility(View.GONE);
+                }
+            });
+            getSupportFragmentManager().addOnBackStackChangedListener(
+                    () -> {
+                        if (getSupportFragmentManager().getBackStackEntryCount() == 0) {
+                            mLlRecommendedServices.setVisibility(View.VISIBLE);
+                            mLlRecommendedServicesSummary.setVisibility(View.VISIBLE);
+                            if (mPrinter != null) {
+                                setTitle(mPrinter.name);
+                            }
+                        }
+                    });
+            setTitle(R.string.information);
+        } else {
+            getFragmentManager().popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE);
+        }
+
+        ViewUtil.setWindowInsetsListener(getWindow().getDecorView(), this);
     }
 
     @Override
     public boolean onOptionsItemSelected(MenuItem item) {
         switch (item.getItemId()) {
             case android.R.id.home:
-                onBackPressed();
+                finish();
                 return true;
         }
         return super.onOptionsItemSelected(item);
@@ -109,6 +156,9 @@ public class MoreOptionsActivity extends Activity implements ServiceConnection,
         }
 
         if (mPrintService != null) {
+            if ((Flags.printerInfoDetails())) {
+                mPrinterInformationViewModel.stopPrinterStatusMonitor(mPrintService);
+            }
             mPrintService.getDiscovery().stop(this);
         }
         unbindService(this);
@@ -185,6 +235,13 @@ public class MoreOptionsActivity extends Activity implements ServiceConnection,
     private void loadPrinterInfoFragment(DiscoveredPrinter printer) {
         mPrinter = printer;
         setTitle(mPrinter.name);
+        if ((Flags.printerInfoDetails())) {
+            if (printer.path != null) {
+                mPrinterInformationViewModel.getPrinterStatus(printer.path, mPrintService);
+            } else {
+                mPrinterInformationViewModel.setPrinterUnavailableLiveData(true);
+            }
+        }
         // Network operation in non UI thread
         mExecutorService.execute(() -> {
             try {
@@ -193,11 +250,38 @@ public class MoreOptionsActivity extends Activity implements ServiceConnection,
                 mPrintService.getDiscovery().stop(this);
                 if (!mExecutorService.isShutdown() && mPrintService != null) {
                     mPrintService.getMainHandler().post(() -> {
-                        if (getFragmentManager().findFragmentByTag(TAG) == null) {
-                            MoreOptionsFragment fragment = new MoreOptionsFragment();
-                            getFragmentManager().beginTransaction()
-                                    .replace(android.R.id.content, fragment, TAG)
-                                    .commit();
+                        if ((Flags.printerInfoDetails())) {
+                            if (getSupportFragmentManager().findFragmentByTag(
+                                    TAG_PRINTER_INFORMATION_FRAGMENT) == null) {
+                                PrinterInformationFragment informationFragment =
+                                        new PrinterInformationFragment();
+                                getSupportFragmentManager().beginTransaction()
+                                        .replace(R.id.fragment_container, informationFragment,
+                                                TAG_PRINTER_INFORMATION_FRAGMENT)
+                                        .commit();
+                            }
+                            mPrintService.getCapabilitiesCache().request(mPrinter, true,
+                                    capabilities -> {
+                                        if (capabilities != null) {
+                                            mPrinterInformationViewModel.setPrinterCapsLiveData(
+                                                    capabilities);
+                                        } else {
+                                            mPrinterInformationViewModel.setPrinterUnavailableLiveData(
+                                                    true);
+                                            Toast.makeText(mPrintService,
+                                                    R.string.failed_printer_connection,
+                                                    Toast.LENGTH_LONG).show();
+                                        }
+                                    });
+                        } else {
+                            if (getFragmentManager().findFragmentByTag(TAG_RECOMMENDATION_FRAGMENT)
+                                    == null) {
+                                MoreOptionsFragment fragment = new MoreOptionsFragment();
+                                getSupportFragmentManager().beginTransaction()
+                                        .replace(android.R.id.content, fragment,
+                                                TAG_RECOMMENDATION_FRAGMENT)
+                                        .commit();
+                            }
                         }
                     });
                 }
diff --git a/src/com/android/bips/ui/MoreOptionsFragment.java b/src/com/android/bips/ui/MoreOptionsFragment.java
index 5798a3d..f05ec8f 100644
--- a/src/com/android/bips/ui/MoreOptionsFragment.java
+++ b/src/com/android/bips/ui/MoreOptionsFragment.java
@@ -21,14 +21,16 @@ import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.net.Uri;
 import android.os.Bundle;
-import android.preference.Preference;
-import android.preference.PreferenceCategory;
-import android.preference.PreferenceFragment;
 import android.print.PrintManager;
 import android.printservice.recommendation.RecommendationInfo;
 import android.util.Log;
 
+import androidx.preference.Preference;
+import androidx.preference.PreferenceCategory;
+import androidx.preference.PreferenceFragmentCompat;
+
 import com.android.bips.R;
+import com.android.bips.flags.Flags;
 
 import java.net.InetAddress;
 import java.text.Collator;
@@ -41,7 +43,7 @@ import java.util.Map;
 /**
  * A fragment allowing the user to review recommended print services and install or enable them.
  */
-public class MoreOptionsFragment extends PreferenceFragment implements
+public class MoreOptionsFragment extends PreferenceFragmentCompat implements
         PrintManager.PrintServiceRecommendationsChangeListener {
     private static final String TAG = MoreOptionsFragment.class.getSimpleName();
     private static final boolean DEBUG = false;
@@ -59,13 +61,18 @@ public class MoreOptionsFragment extends PreferenceFragment implements
     private Map<String, RecommendationItem> mItems = new HashMap<>();
 
     @Override
-    public void onCreate(Bundle in) {
-        super.onCreate(in);
-
-        addPreferencesFromResource(R.xml.more_options_prefs);
+    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
+        if ((Flags.printerInfoDetails())) {
+            addPreferencesFromResource(R.xml.more_options_prefs_new);
+        } else {
+            addPreferencesFromResource(R.xml.more_options_prefs);
+        }
 
-        mRecommendations = (PreferenceCategory) getPreferenceScreen().findPreference(
+        mRecommendations = getPreferenceScreen().findPreference(
                 KEY_RECOMMENDATION_CATEGORY);
+        if ((Flags.printerInfoDetails())) {
+            mRecommendations.setIconSpaceReserved(false);
+        }
 
         getPreferenceScreen().findPreference(KEY_MANAGE)
                 .setOnPreferenceClickListener(preference -> {
@@ -88,6 +95,9 @@ public class MoreOptionsFragment extends PreferenceFragment implements
         }
 
         mActivity = (MoreOptionsActivity) getActivity();
+        if ((Flags.printerInfoDetails())) {
+            mActivity.setTitle(mActivity.getResources().getString(R.string.recommendation_link));
+        }
 
         mPrintManager = getContext().getSystemService(PrintManager.class);
 
diff --git a/src/com/android/bips/ui/PrinterInformationFragment.kt b/src/com/android/bips/ui/PrinterInformationFragment.kt
new file mode 100644
index 0000000..bcce538
--- /dev/null
+++ b/src/com/android/bips/ui/PrinterInformationFragment.kt
@@ -0,0 +1,232 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2024 Mopria Alliance, Inc.
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
+package com.android.bips.ui
+
+import android.os.Bundle
+import android.text.TextUtils
+import android.util.Log
+import android.view.LayoutInflater
+import android.view.View
+import android.view.ViewGroup
+import android.widget.ImageView
+import android.widget.ProgressBar
+import android.widget.TextView
+import androidx.constraintlayout.widget.ConstraintLayout
+import androidx.fragment.app.Fragment
+import androidx.fragment.app.FragmentActivity
+import androidx.fragment.app.activityViewModels
+import androidx.recyclerview.widget.LinearLayoutManager
+import androidx.recyclerview.widget.RecyclerView
+import com.android.bips.R
+import com.android.bips.ipp.JobStatus
+import com.android.bips.jni.BackendConstants
+import com.android.bips.jni.LocalPrinterCapabilities
+import com.android.bips.jni.MediaSizes
+import java.util.*
+
+/**
+ * Printer information fragment
+ */
+class PrinterInformationFragment : Fragment() {
+
+    /** Printer Information view model */
+    private val printerInformationViewModel: Lazy<PrinterInformationViewModel> =
+        activityViewModels()
+    private val statusMapping = LinkedHashMap(JobStatus.getBlockReasonsMap())
+    private lateinit var printerName: TextView
+    private lateinit var printerIcon: ImageView
+    private lateinit var printerStatus: TextView
+    private lateinit var printerStatusLayout: ConstraintLayout
+    private lateinit var progressBarPrinterStatus: ProgressBar
+    private lateinit var mediaReady: TextView
+    private lateinit var mediaReadyLabel: TextView
+    private lateinit var inkLevelsRecyclerView: RecyclerView
+
+    override fun onCreateView(
+        inflater: LayoutInflater,
+        container: ViewGroup?,
+        savedInstanceState: Bundle?
+    ): View {
+        return inflater.inflate(R.layout.printer_information,
+            container, false)
+    }
+
+    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
+        printerName = view.findViewById(R.id.printerName)
+        printerIcon = view.findViewById(R.id.printerIcon)
+        printerStatus = view.findViewById(R.id.printerStatus)
+        printerStatusLayout = view.findViewById(R.id.printerStatusLayout)
+        progressBarPrinterStatus = view.findViewById(R.id.progressBarPrinterStatus)
+        mediaReady = view.findViewById(R.id.mediaReady)
+        mediaReadyLabel = view.findViewById(R.id.mediaReadyLabel)
+        inkLevelsRecyclerView = view.findViewById(R.id.inkLevelsRecyclerView)
+        super.onViewCreated(view, savedInstanceState)
+        statusMapping[BackendConstants.PRINTER_STATE_IDLE] = R.string.printer_ready
+        statusMapping[BackendConstants.PRINTER_STATE_RUNNING] = R.string.printer_state__printing
+        statusMapping[BackendConstants.PRINTER_STATE_UNABLE_TO_CONNECT] =
+            R.string.printer_state__offline
+        statusMapping[BackendConstants.PRINTER_STATE_BLOCKED] =
+            R.string.printer_state__check_printer
+
+        activity?.apply {
+            setPrinterImage(this)
+            setPrinterStatus(this)
+            printerInformationViewModel.value.getPrinterCapsLiveData().observe(this) {
+                it?.also { caps ->
+                    getIconBitmap(caps)
+                    setMediaReadySize(caps)
+                    setMarkerView(caps)
+                    view.visibility = View.VISIBLE
+                    printerName.text = caps.name
+                } ?: run {
+                    view.visibility = View.GONE
+                }
+            }
+        }
+    }
+
+    private fun setMediaReadySize(caps: LocalPrinterCapabilities) {
+        var mediaReadyString = ""
+        caps.mediaReadySizes?.also { mediaReadySizes ->
+            if (mediaReadySizes.isEmpty()) {
+                mediaReady.visibility = View.GONE
+                mediaReadyLabel.visibility = View.GONE
+            }
+            for (i in mediaReadySizes) {
+                mediaReadyString += MediaSizes.getInstance(context)
+                    .getMediaName(i, context) + "\n"
+            }
+            mediaReady.text = mediaReadyString.dropLast(1)
+        } ?: run {
+            mediaReady.visibility = View.GONE
+            mediaReadyLabel.visibility = View.GONE
+        }
+    }
+
+    private fun getIconBitmap(caps: LocalPrinterCapabilities) {
+        caps.mPrinterIconUris?.also { iconUri ->
+            if (iconUri.isNotEmpty()) {
+                printerInformationViewModel.value.getBitmap(iconUri.last())
+            }
+        }
+    }
+
+    private fun setPrinterImage(fragmentActivity: FragmentActivity) {
+        printerInformationViewModel.value.getPrinterBitmapLiveData()
+            .observe(fragmentActivity) { printerImage ->
+                if (printerImage != null) {
+                    printerIcon.visibility = View.VISIBLE
+                    printerIcon.setImageBitmap(printerImage)
+                } else {
+                    printerIcon.visibility = View.GONE
+                }
+            }
+    }
+
+    /**
+     * Set Status Of Printer
+     */
+    private fun setPrinterStatus(fragmentActivity: FragmentActivity) {
+        printerInformationViewModel.value.getPrinterUnavailableLiveData()
+            .observe(fragmentActivity) {
+                if (it) printerStatusLayout.visibility = View.GONE
+            }
+        printerInformationViewModel.value.getPrinterStatusLiveData()
+            .observe(fragmentActivity) { callbackParams ->
+                callbackParams.apply {
+                    val reasonsList = blockedReasons?.toList() ?: emptyList()
+                    val statusList = getPrinterStatus(printerState, reasonsList)
+                    if (statusList.isEmpty()) {
+                        printerStatusLayout.visibility = View.GONE
+                    } else {
+                        if (DEBUG) {
+                            Log.e(TAG, "printer status list ${TextUtils.join("\n", statusList)}")
+                        }
+                        printerStatus.text = TextUtils.join("\n", statusList)
+                        printerStatusLayout.visibility = View.VISIBLE
+                        printerStatus.visibility = View.VISIBLE
+                        progressBarPrinterStatus.visibility = View.GONE
+                    }
+                }
+            }
+    }
+
+    /**
+     * Maps the printer state and reasons into a list of status strings
+     * If the printerReasons is not empty (printer is blocked), returns a list of (one or more)
+     * blocked reasons, otherwise it will be a one item list of printer state. May return an empty
+     * list if no resource id is found for the given status(es)
+     */
+    private fun getPrinterStatus(printerState: String, printerReasons: List<String>): Set<String> {
+        val resourceIds: MutableSet<String> = LinkedHashSet()
+        for (reason in printerReasons) {
+            if (TextUtils.isEmpty(reason) ||
+                reason == BackendConstants.BLOCKED_REASON__SPOOL_AREA_FULL &&
+                BackendConstants.PRINTER_STATE_BLOCKED != printerState
+            ) {
+                continue
+            }
+            statusMapping[reason]?.also { resourceIds.add(getString(it)) }
+        }
+        if (resourceIds.isEmpty() || BackendConstants.PRINTER_STATE_RUNNING == printerState) {
+            statusMapping[printerState]?.also { resourceIds.add(getString(it)) }
+        }
+        return resourceIds
+    }
+
+    /**
+     * Set marker view
+     * Fills supplies levels views based on capabilities
+     * @param view view
+     * @param caps the selected printer's capabilities
+     */
+    private fun setMarkerView(caps: LocalPrinterCapabilities) {
+        val mMarkerInfoList = ArrayList<MarkerInfo>()
+        for (i in caps.markerTypes.indices) {
+            if ((validTonerTypes.contains(caps.markerTypes[i]) ||
+                        validInkTypes.contains(caps.markerTypes[i])) && caps.markerLevel[i] >= 0
+            ) {
+                caps.markerColors[i].split("#").apply {
+                    for (j in 1 until size) {
+                        mMarkerInfoList.add(
+                            MarkerInfo(
+                                caps.markerTypes[i],
+                                "#" + this[j],
+                                caps.markerHighLevel[i],
+                                caps.markerLowLevel[i],
+                                caps.markerLevel[i]
+                            )
+                        )
+
+                    }
+                }
+            }
+        }
+        with(inkLevelsRecyclerView) {
+            this.layoutManager = LinearLayoutManager(activity)
+            this.adapter = MarkerAdapter(mMarkerInfoList)
+        }
+    }
+
+    companion object {
+        private val validTonerTypes = listOf("toner", "toner-cartridge")
+        private val validInkTypes = listOf("ink", "inkCartridge", "ink-cartridge")
+        private const val TAG = "PrinterInformationFragment"
+        private const val DEBUG = false
+    }
+}
\ No newline at end of file
diff --git a/src/com/android/bips/ui/PrinterInformationViewModel.kt b/src/com/android/bips/ui/PrinterInformationViewModel.kt
new file mode 100644
index 0000000..4e7ab6d
--- /dev/null
+++ b/src/com/android/bips/ui/PrinterInformationViewModel.kt
@@ -0,0 +1,140 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2024 Mopria Alliance, Inc.
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
+package com.android.bips.ui
+
+import android.graphics.Bitmap
+import android.graphics.BitmapFactory
+import android.net.SSLCertificateSocketFactory
+import android.net.TrafficStats
+import android.net.Uri
+import android.util.Log
+import androidx.lifecycle.LiveData
+import androidx.lifecycle.MutableLiveData
+import androidx.lifecycle.ViewModel
+import androidx.lifecycle.viewModelScope
+import com.android.bips.BuiltInPrintService
+import com.android.bips.jni.JobCallbackParams
+import com.android.bips.jni.LocalPrinterCapabilities
+import com.android.bips.jni.PrinterStatusMonitor
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.launch
+import java.io.IOException
+import java.net.HttpURLConnection
+import java.net.URL
+import javax.net.ssl.HostnameVerifier
+import javax.net.ssl.HttpsURLConnection
+
+/**
+ * Printer Information ViewModel
+ */
+class PrinterInformationViewModel : ViewModel() {
+    companion object {
+        private const val TAG = "PrinterInformationViewModel"
+        private const val DEBUG = false
+    }
+    private val HTTPS = "https"
+    private val HTTP = "http"
+
+    /** Printer capabilities live data */
+    private val printerCapsLiveData = MutableLiveData<LocalPrinterCapabilities>()
+
+    /** Printer status live data */
+    private val printerStatusLiveData = MutableLiveData<JobCallbackParams>()
+    private val printerUnavailableLiveData = MutableLiveData<Boolean>()
+    private val printerBitmapLiveData = MutableLiveData<Bitmap>()
+
+    private lateinit var printerStatusMonitor: PrinterStatusMonitor
+
+    fun getPrinterCapsLiveData(): LiveData<LocalPrinterCapabilities> {
+        return printerCapsLiveData
+    }
+
+    fun setPrinterCapsLiveData(localPrinterCapabilities: LocalPrinterCapabilities) {
+        printerCapsLiveData.value = localPrinterCapabilities
+    }
+
+    fun getPrinterStatusLiveData(): LiveData<JobCallbackParams> {
+        return printerStatusLiveData
+    }
+
+    fun getPrinterUnavailableLiveData(): LiveData<Boolean> {
+        return printerUnavailableLiveData
+    }
+
+    fun setPrinterUnavailableLiveData(status: Boolean) {
+        printerUnavailableLiveData.value = status
+    }
+
+    fun getPrinterBitmapLiveData(): LiveData<Bitmap> {
+        return printerBitmapLiveData
+    }
+
+    fun getBitmap(iconUri: String) {
+        viewModelScope.launch(Dispatchers.IO) {
+            TrafficStats.setThreadStatsTag(0xF00D)
+            var con: HttpURLConnection? = null
+            try {
+                if (DEBUG) Log.d(TAG, "Fetching icon from $iconUri")
+                val url = URL(iconUri)
+                val protocol = url.protocol
+                if (protocol.equals(HTTPS, ignoreCase = true)) {
+                    con = url.openConnection() as HttpsURLConnection
+                    (con as HttpsURLConnection?)?.sslSocketFactory =
+                        SSLCertificateSocketFactory.getInsecure(0, null)
+                    (con as HttpsURLConnection?)?.hostnameVerifier =
+                        HostnameVerifier { s, sslSession -> true }
+                } else if (protocol.equals(HTTP, ignoreCase = true)) {
+                    con = url.openConnection() as HttpURLConnection
+                } else {
+                    printerBitmapLiveData.postValue(null)
+                }
+                con?.doInput = true
+                con?.connect()
+                if (DEBUG) Log.d(TAG, "Connected with " + con?.responseCode?.toString())
+                if (con?.responseCode == HttpURLConnection.HTTP_OK) {
+                    con.inputStream.use { `in` ->
+                        printerBitmapLiveData.postValue(BitmapFactory.decodeStream(`in`))
+                    }
+                }
+            } catch (e: IllegalStateException) {
+                if (DEBUG) Log.e(TAG, "Failed to download printer icon $e")
+            } catch (e: IOException) {
+                if (DEBUG) Log.e(TAG, "Failed to download printer icon $e")
+            } finally {
+                con?.disconnect()
+                TrafficStats.clearThreadStatsTag()
+            }
+        }
+    }
+
+    fun getPrinterStatus(uri: Uri, printService: BuiltInPrintService) {
+        viewModelScope.launch(Dispatchers.IO) {
+            printerStatusMonitor = PrinterStatusMonitor(uri, printService, ::onPrinterStatus)
+        }
+    }
+
+    fun stopPrinterStatusMonitor(printService: BuiltInPrintService) {
+        if (::printerStatusMonitor.isInitialized) {
+            printerStatusMonitor.stopMonitor(printService)
+        }
+    }
+
+    private fun onPrinterStatus(status: JobCallbackParams?) {
+        printerStatusLiveData.postValue(status)
+    }
+}
\ No newline at end of file
diff --git a/src/com/android/bips/ui/ViewUtil.java b/src/com/android/bips/ui/ViewUtil.java
index 1bec839..36737ec 100644
--- a/src/com/android/bips/ui/ViewUtil.java
+++ b/src/com/android/bips/ui/ViewUtil.java
@@ -26,13 +26,18 @@ import androidx.core.view.WindowInsetsCompat;
 
 public final class ViewUtil {
     public static void setWindowInsetsListener(View view, Activity activity) {
-        ViewCompat.setOnApplyWindowInsetsListener(view, (v, windowInsets) -> {
-            if (activity.isFinishing()) {
-                return windowInsets;
-            }
-            Insets insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars());
-            v.setPadding(insets.left, insets.top, insets.right, insets.bottom);
-            return WindowInsetsCompat.CONSUMED;
-        });
+        ViewCompat.setOnApplyWindowInsetsListener(
+                view,
+                (v, windowInsets) -> {
+                    if (activity.isFinishing()) {
+                        return windowInsets;
+                    }
+                    Insets insets =
+                            windowInsets.getInsets(
+                                    WindowInsetsCompat.Type.systemBars()
+                                            | WindowInsetsCompat.Type.displayCutout());
+                    v.setPadding(insets.left, insets.top, insets.right, insets.bottom);
+                    return WindowInsetsCompat.CONSUMED;
+                });
     }
 }
```

