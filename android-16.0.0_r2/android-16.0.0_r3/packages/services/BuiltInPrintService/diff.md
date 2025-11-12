```diff
diff --git a/Android.bp b/Android.bp
index 114f7fa..bff0962 100644
--- a/Android.bp
+++ b/Android.bp
@@ -24,6 +24,7 @@ android_app {
         "src/**/*.java",
         "src/**/I*.aidl",
         "src/**/*.kt",
+        ":statslog-builtinprintservice-java-gen",
     ],
     static_libs: [
         "androidx.core_core",
@@ -60,3 +61,36 @@ android_app {
         "libcups",
     ],
 }
+
+genrule {
+    name: "statslog-builtinprintservice-java-gen",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --java $(out) --module builtinprintservice --javaPackage com.android.bips.stats --javaClass BipsStatsLog",
+    out: ["com/android/bips/BipsStatsLog.java"],
+}
+
+android_robolectric_test {
+    name: "BuiltInPrintServiceRobolectricTest",
+
+    srcs: [
+        "tests/robolectric/**/*.kt",
+    ],
+    static_libs: [
+        "androidx.test.core",
+        "androidx.test.ext.junit",
+        "truth",
+        "kotlin-test",
+        // Order matters, keep robolectric before kotlin2
+        "mockito-robolectric-prebuilt",
+        "mockito-kotlin2",
+    ],
+    test_suites: [
+        "general-tests",
+    ],
+    instrumentation_for: "BuiltInPrintService",
+    java_resource_dirs: ["tests/robolectric/config"],
+    // TODO(b/422187009): We may turn strict mode off or create a
+    // separate unstrict test when we figure out how to properly
+    // shadow some of the printing framework from BIPS.
+    strict_mode: true,
+}
diff --git a/OWNERS b/OWNERS
index fe84ced..51eadd4 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,5 @@
 # Bug component: 47273
 include platform/frameworks/base:/OWNERS
+aaronmassey@google.com
 anothermark@google.com
 bmgordon@google.com
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 1a4ce24..84f086b 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -1,7 +1,13 @@
 [Builtin Hooks]
 xmllint = true
 commit_msg_changeid_field = true
+ktfmt = true
+
+[Builtin Hooks Options]
+ktfmt = --kotlinlang-style
 
 [Hook Scripts]
 checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
 
+[Tool Paths]
+ktfmt = ${REPO_ROOT}/external/ktfmt/ktfmt.sh
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 0000000..2e0e6d1
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "postsubmit": [
+    {
+      "name": "BuiltInPrintServiceRobolectricTest"
+    }
+  ]
+}
\ No newline at end of file
diff --git a/flags/flags.aconfig b/flags/flags.aconfig
index cb61359..7c4287b 100644
--- a/flags/flags.aconfig
+++ b/flags/flags.aconfig
@@ -8,3 +8,17 @@ flag {
     bug: "374764554"
     is_fixed_read_only: true
 }
+
+flag {
+    name: "printing_telemetry"
+    namespace: "printing"
+    description: "Metrics tracking final print job status, printer discovery, printer capabilities, and major UI actions."
+    bug: "390478410"
+}
+
+flag {
+    name: "enable_print_debug_option"
+    namespace: "printing"
+    description: "Enable extra debug logging by checking a runtime system property."
+    bug: "397418860"
+}
\ No newline at end of file
diff --git a/jni/Android.bp b/jni/Android.bp
index 7ad1e26..971a813 100644
--- a/jni/Android.bp
+++ b/jni/Android.bp
@@ -70,6 +70,8 @@ cc_library_shared {
         "libjpeg_static_ndk",
     ],
     shared_libs: [
+        "libaconfig_storage_read_api_cc",
+        "libcutils",
         "libcups",
         "liblog",
         "libz",
diff --git a/jni/include/wprint_debug.h b/jni/include/wprint_debug.h
index e0a1867..882f324 100644
--- a/jni/include/wprint_debug.h
+++ b/jni/include/wprint_debug.h
@@ -21,6 +21,8 @@
 #include <stdio.h>
 #include <stdarg.h>
 #include <android/log.h>
+#include <cutils/properties.h>
+#include "com_android_bips_flags.h"
 
 #define LEVEL_DEBUG     3
 #define LEVEL_INFO      4
@@ -33,22 +35,36 @@
 #define LOG_LEVEL       LEVEL_ERROR
 #endif // LOG_LEVEL
 
+#define DEBUG_SYSPROP_STR "debug.printing.logs.enabled"
+
+static inline int print_debug_enabled() {
+  return property_get_bool(DEBUG_SYSPROP_STR, 0);
+}
+
+#define _LOG_PRINT_IF_DEBUG_PROP_ENABLED(ANDROID_LOG_LEVEL, ...)              \
+  com_android_bips_flags_enable_print_debug_option() && print_debug_enabled() \
+      ? __android_log_print(ANDROID_LOG_LEVEL, TAG, __VA_ARGS__)              \
+      : 0
+
 #if LOG_LEVEL > LEVEL_DEBUG
-#define LOGD(...)
+#define LOGD(...) \
+  _LOG_PRINT_IF_DEBUG_PROP_ENABLED(ANDROID_LOG_DEBUG, __VA_ARGS__)
 #else
 #define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
 #endif
 
 #if LOG_LEVEL > LEVEL_INFO
-#define LOGI(...)
+#define LOGI(...) \
+  _LOG_PRINT_IF_DEBUG_PROP_ENABLED(ANDROID_LOG_INFO, __VA_ARGS__)
 #else
 #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
 #endif
 
 #if LOG_LEVEL > LEVEL_ERROR
-#define LOGE(...)
+#define LOGE(...) \
+  _LOG_PRINT_IF_DEBUG_PROP_ENABLED(ANDROID_LOG_ERROR, __VA_ARGS__)
 #else
 #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
 #endif
 
-#endif // __WPRINT_DEBUG_H__
\ No newline at end of file
+#endif // __WPRINT_DEBUG_H__
diff --git a/jni/include/wprint_df_types.h b/jni/include/wprint_df_types.h
index 5f53990..0024b51 100644
--- a/jni/include/wprint_df_types.h
+++ b/jni/include/wprint_df_types.h
@@ -42,6 +42,7 @@ typedef enum {
 /*
  * Enumeration for supported media types
  */
+// LINT.IfChange
 typedef enum {
     MEDIA_PLAIN,
     MEDIA_SPECIAL,
@@ -63,5 +64,6 @@ typedef enum {
     MEDIA_AUTO = 98,
     MEDIA_UNKNOWN = 99 // New types above this line
 } media_type_t;
+// LINT.ThenChange(/src/com/android/bips/stats/StatsAsyncLogger.kt:localMediaTypeMap)
 
 #endif // __WPRINT_DF_TYPES_H__
\ No newline at end of file
diff --git a/jni/include/wtypes.h b/jni/include/wtypes.h
index 8372e5d..082ed75 100644
--- a/jni/include/wtypes.h
+++ b/jni/include/wtypes.h
@@ -25,6 +25,7 @@
 /*
  * A return type for functions.
  */
+// LINT.IfChange
 typedef enum {
     /* Request succeeded */
     OK = 0,
@@ -41,6 +42,7 @@ typedef enum {
     /* Request failed because unexpected ssl certificate received */
     BAD_CERTIFICATE = -4
 } status_t;
+// LINT.ThenChange(/src/com/android/bips/stats/StatsAsyncLogger.kt:localPrintJobResultMap)
 
 #define ARRAY_SIZE(X) (sizeof(X)/sizeof(X[0]))
 
diff --git a/jni/ipphelper/ippstatus_capabilities.c b/jni/ipphelper/ippstatus_capabilities.c
index f1550bf..82ffdc0 100644
--- a/jni/ipphelper/ippstatus_capabilities.c
+++ b/jni/ipphelper/ippstatus_capabilities.c
@@ -245,12 +245,22 @@ static status_t _get_capabilities(const ifc_printer_capabilities_t *this_p,
             LOGD("%s received, now call parse_printerAttributes:", ippOpString(op));
             parse_printerAttributes(response, capabilities);
 
+            if (com_android_bips_flags_enable_print_debug_option() &&
+                print_debug_enabled()) {
+              LOGD("Begin Printing IPP Attributes");
+              for (attrptr = ippFirstAttribute(response); attrptr;
+                   attrptr = ippNextAttribute(response)) {
+                print_attr(attrptr);
+              }
+              LOGD("End Printing IPP Attributes");
+            } else {
 #if LOG_LEVEL <= LEVEL_DEBUG
-            for (attrptr = ippFirstAttribute(response); attrptr; attrptr = ippNextAttribute(
-                    response)) {
+              for (attrptr = ippFirstAttribute(response); attrptr;
+                   attrptr = ippNextAttribute(response)) {
                 print_attr(attrptr);
-            }
+              }
 #endif // LOG_LEVEL <= LEVEL_DEBUG
+            }
             if ((attrptr = ippFindAttribute(response, "printer-state", IPP_TAG_ENUM)) == NULL) {
                 LOGD("printer-state: null");
             } else {
diff --git a/jni/lib/wprintJNI.c b/jni/lib/wprintJNI.c
index 308cf34..8ea55a1 100644
--- a/jni/lib/wprintJNI.c
+++ b/jni/lib/wprintJNI.c
@@ -74,6 +74,7 @@ static jfieldID _LocalPrinterCapabilitiesField__name;
 static jfieldID _LocalPrinterCapabilitiesField__path;
 static jfieldID _LocalPrinterCapabilitiesField__uuid;
 static jfieldID _LocalPrinterCapabilitiesField__location;
+static jfieldID _LocalPrinterCapabilitiesField__makeAndModel;
 static jfieldID _LocalPrinterCapabilitiesField__duplex;
 static jfieldID _LocalPrinterCapabilitiesField__borderless;
 static jfieldID _LocalPrinterCapabilitiesField__color;
@@ -571,6 +572,10 @@ static void _initJNI(JNIEnv *env, jobject callbackReceiver, jstring fakeDir) {
             env, _LocalPrinterCapabilitiesClass, "uuid", "Ljava/lang/String;");
     _LocalPrinterCapabilitiesField__location = (*env)->GetFieldID(
             env, _LocalPrinterCapabilitiesClass, "location", "Ljava/lang/String;");
+    if (com_android_bips_flags_printing_telemetry()) {
+      _LocalPrinterCapabilitiesField__makeAndModel = (*env)->GetFieldID(
+            env, _LocalPrinterCapabilitiesClass, "makeAndModel", "Ljava/lang/String;");
+    }
     _LocalPrinterCapabilitiesField__duplex = (*env)->GetFieldID(
             env, _LocalPrinterCapabilitiesClass, "duplex", "Z");
     _LocalPrinterCapabilitiesField__borderless = (*env)->GetFieldID(
@@ -953,6 +958,11 @@ static int _convertPrinterCaps_to_Java(JNIEnv *env, jobject javaPrinterCaps,
             wprintPrinterCaps->uuid);
     stringToJava(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__location,
             wprintPrinterCaps->location);
+    if (com_android_bips_flags_printing_telemetry()) {
+      stringToJava(env, javaPrinterCaps, _LocalPrinterCapabilitiesField__makeAndModel,
+            // make represents make and model.
+            wprintPrinterCaps->make);
+    }
 
     jintArray intArray;
     int *intArrayPtr;
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/layout/combined_info_recs.xml b/res/flag(com.android.bips.flags.printer_info_details)/layout/combined_info_recs.xml
index 3ad1ef7..ee75b57 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/layout/combined_info_recs.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/layout/combined_info_recs.xml
@@ -38,7 +38,7 @@
             android:layout_height="wrap_content"
             android:layout_marginTop="@dimen/mopria_padding_18dp"
             android:gravity="center_vertical"
-            android:minHeight="40dip"
+            android:minHeight="48dip"
             app:layout_constraintEnd_toEndOf="parent"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintTop_toBottomOf="@id/fragment_container">
@@ -85,4 +85,4 @@
         </LinearLayout>
     </androidx.constraintlayout.widget.ConstraintLayout>
 
-</ScrollView>
\ No newline at end of file
+</ScrollView>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-af/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-af/strings.xml
index 32450ed..1648086 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-af/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-af/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Drukwerk"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Vanlyn"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Gaan drukker na"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Siaan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Geel. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Swart. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rooi. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Groen. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blou. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Liggrys. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Donkergrys. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ligsiaan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Ligmagenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Gepasmaakte kleur #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-am/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-am/strings.xml
index 1fa605f..e558397 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-am/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-am/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"በማተም ላይ"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ከመስመር ውጭ"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"አታሚን ይፈትሹ"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"ሳያን። %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"ማጀንታ። %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"ቢጫ። %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"ጥቁር። %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"ቀይ። %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"አረንጓዴ። %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"ሰማያዊ። %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"ፈካ ያለ ግራጫ። %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"ደማቅ ግራጫ። %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"ፈካ ያለ ሳያን። %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ነጣ ያለ ማጀንታ። %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"ሐምራዊ። %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"ብጁ ቀለም #%1$02X%2$02X%3$02X። %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ar/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ar/strings.xml
index c7e7a26..771b470 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ar/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ar/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"جارٍ الطباعة"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"غير متصلة بالإنترنت"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"يُرجى التحقّق من الطابعة"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"‏سماوي: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"‏أحمر أرجواني: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"‏أصفر: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"‏أسود: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"‏أحمر: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"‏أخضر: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"‏أزرق: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"‏رمادي فاتح: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"‏رمادي داكن: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"‏أزرق سماوي فاتح: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"‏أحمر أرجواني فاتح: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"‏بنفسجي: ‫‎%1$d%%‎"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"‏اللون المخصّص #%1$02X%2$02X%3$02X: ‫‎%4$d%%‎"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-as/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-as/strings.xml
index c000503..c9f8ca3 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-as/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-as/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"প্ৰিণ্ট কৰি থকা হৈছে"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"অফলাইন"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"প্ৰিণ্টাৰ পৰীক্ষা কৰক"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"সেউজ নীলা। %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"মেজেণ্টা। %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"হালধীয়া। %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"ক’লা। %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"ৰঙা। %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"সেউজীয়া। %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"নীলা। %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"পাতল ধোঁৱাবৰণীয়া। %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"গাঢ় ধোঁৱাবৰণীয়া। %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"পাতল সেউজ নীলা। %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"পাতল মেজেণ্টা। %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"বেঙুনীয়া। %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"কাষ্টম ৰং #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-az/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-az/strings.xml
index e34dcbc..4f95834 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-az/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-az/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Çap"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Oflayn"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Printeri yoxlayın"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Yaşılımtıl mavi. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Madjenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Sarı. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Qara. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Qırmızı. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Yaşıl. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Mavi. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Açıq-boz. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Tünd-boz. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Açıq-yaşılımtıl mavi. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Açıq-madjenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Bənövşəyi. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Fərdi rəng #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-b+sr+Latn/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-b+sr+Latn/strings.xml
index ce87235..62a37cf 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-b+sr+Latn/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-b+sr+Latn/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Štampanje"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Oflajn"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Proverite štampač"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cijan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Ciklama. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Žuta. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Crna. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Crvena. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Zelena. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Plava. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Svetlosiva. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Tamnosiva. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Svetlocijan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Svetlociklama. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Ljubičasta. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Prilagođena boja #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-be/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-be/strings.xml
index 0a8bceb..a0f6d5f 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-be/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-be/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Друк"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Па-за сеткай"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Праверце прынтар"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Блакітнае. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Пурпурнае. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Жоўтае. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Чорнае. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Чырвонае. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Зялёнае. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Сіняе. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Светла-шэрае. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Цёмна-шэрае. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Светла-блакітнае. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Светла-пурпурнае. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Фіялетавае. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Карыстальніцкі колер: #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-bg/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-bg/strings.xml
index 30c661a..9236f9f 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-bg/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-bg/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Отпечатва се"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Офлайн"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Проверка на принтера"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Синьо-зелено. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Пурпурно. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Жълто. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Черно. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Червено. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Зелено. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Синьо. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Светлосиво. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Тъмносиво. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Светло синьо-зелено. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Светлопурпурно. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Виолетово. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Персонализиран цвят #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-bn/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-bn/strings.xml
index 90982bc..032365d 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-bn/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-bn/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"প্রিন্ট করা হচ্ছে"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"অফলাইন আছে"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"প্রিন্টার চেক করুন"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"সায়ান। %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"ম্যাজেন্টা। %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"হলুদ। %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"কালো। %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"লাল। %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"সবুজ। %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"নীল। %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"লাইট গ্রে। %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"ডার্ক-গ্রে। %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"লাইট সায়ান। %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"লাইট ম্যাজেন্টা। %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"বেগুনি। %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"কাস্টম কালার #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-bs/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-bs/strings.xml
index a92f90c..b2a328b 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-bs/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-bs/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Štampanje"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Provjerite štampač"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cijan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Žuta. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Crna. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Crvena. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Zelena. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Plava. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Svijetlosiva. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Tamnosiva. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Svijetlocijan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Svijetlomagenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Ljubičasta. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Prilagođena boja #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ca/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ca/strings.xml
index 9bb5baf..90b1d0c 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ca/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ca/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"S\'està imprimint"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Sense connexió"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Comprova la impressora"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cian. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Groc. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Negre. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Vermell. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Verd. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blau. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Gris clar. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Gris fosc. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Cian clar. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta clar. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violeta. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Color personalitzat #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-cs/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-cs/strings.xml
index 2c2ffee..83f89d2 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-cs/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-cs/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"Název tiskárny"</string>
     <string name="status" msgid="5948149021115901261">"Stav"</string>
     <string name="media_ready" msgid="7205545458156298899">"Velikosti vloženého papíru"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Úrovně nabídky"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Stav náplně"</string>
     <string name="information" msgid="7896978544179559432">"Informace"</string>
     <string name="printer_ready" msgid="1602057851194259669">"Připraveno"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Tisk"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Zkontrolovat tiskárnu"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Azurová. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Purpurová. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Žlutá. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Černá. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Červená. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Zelená. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Modrá. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Světle šedá. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Tmavě šedá. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Světle azurová. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Světle purpurová. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Fialová. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Vlastní barva #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-da/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-da/strings.xml
index a134721..5040bba 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-da/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-da/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Udskriver"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Tjek printeren"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d %%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d %%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Gul. %1$d %%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Sort. %1$d %%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rød. %1$d %%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Grøn. %1$d %%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blå. %1$d %%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Lysegrå. %1$d %%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Mørkegrå. %1$d %%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Lys cyan. %1$d %%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Lys magenta. %1$d %%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d %%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Tilpasset farve #%1$02X%2$02X%3$02X. %4$d %%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-de/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-de/strings.xml
index 220a115..2bc0f7f 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-de/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-de/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"Druckername"</string>
     <string name="status" msgid="5948149021115901261">"Status"</string>
     <string name="media_ready" msgid="7205545458156298899">"Installierte Papierformate"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Versorgungsstufen"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Füllstände"</string>
     <string name="information" msgid="7896978544179559432">"Informationen"</string>
     <string name="printer_ready" msgid="1602057851194259669">"Bereit"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Drucken"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Drucker prüfen"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d %%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d %%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Gelb. %1$d %%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Schwarz. %1$d %%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rot. %1$d %%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Grün. %1$d %%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blau. %1$d %%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Hellgrau. %1$d %%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Dunkelgrau. %1$d %%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Helles Cyan. %1$d %%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Helles Magenta. %1$d %%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violett. %1$d %%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Benutzerdefinierte Farbe #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-el/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-el/strings.xml
index ff6f9ef..8f52dcf 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-el/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-el/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Εκτύπωση σε εξέλιξη"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Εκτός σύνδεσης"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Έλεγχος εκτυπωτή"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Κυανό. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Ματζέντα. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Κίτρινο. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Μαύρο. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Κόκκινο. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Πράσινο. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Μπλε. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Ανοιχτό γκρι. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Σκούρο γκρι. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ανοιχτό κυανό. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Ανοιχτό ματζέντα. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Βιολετί. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Προσαρμοσμένο χρώμα #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rAU/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rAU/strings.xml
index 5c05202..265948d 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rAU/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rAU/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Printing"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Check printer"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Yellow. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Black. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Red. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Green. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blue. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Light grey. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Dark grey. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Light cyan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Light magenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Custom colour #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rCA/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rCA/strings.xml
index 7dfa18c..f091454 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rCA/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rCA/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Printing"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Check printer"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Yellow. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Black. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Red. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Green. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blue. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Light gray. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Dark gray. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Light cyan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Light magenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Custom color #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rGB/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rGB/strings.xml
index 5c05202..265948d 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rGB/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rGB/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Printing"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Check printer"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Yellow. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Black. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Red. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Green. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blue. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Light grey. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Dark grey. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Light cyan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Light magenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Custom colour #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rIN/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rIN/strings.xml
index 5c05202..265948d 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-en-rIN/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-en-rIN/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Printing"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Check printer"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Yellow. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Black. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Red. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Green. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blue. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Light grey. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Dark grey. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Light cyan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Light magenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Custom colour #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-es-rUS/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-es-rUS/strings.xml
index c0dfad0..edaa604 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-es-rUS/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-es-rUS/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Impresión"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Sin conexión"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Verificar impresora"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cian: %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta: %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Amarillo: %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Negro: %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rojo: %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Verde: %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Azul: %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Gris claro: %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Gris oscuro: %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Cian claro: %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta claro: %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violeta: %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Color personalizado #%1$02X%2$02X%3$02X: %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-es/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-es/strings.xml
index 02c300a..c86efd2 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-es/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-es/strings.xml
@@ -26,8 +26,21 @@
     <string name="media_ready" msgid="7205545458156298899">"Tamaños del papel cargado"</string>
     <string name="supply_levels" msgid="5058409966884929190">"Niveles de suministro"</string>
     <string name="information" msgid="7896978544179559432">"Información"</string>
-    <string name="printer_ready" msgid="1602057851194259669">"Listo"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Lista"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Imprimiendo"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Sin conexión"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Comprobar impresora"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cian. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Amarillo. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Negro. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rojo. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Verde. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Azul. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Gris claro. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Gris oscuro. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Cian claro. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta claro. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violeta. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Color personalizado #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-et/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-et/strings.xml
index 09b9ddf..08140d3 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-et/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-et/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Printimine"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Võrguühenduseta"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Printeri kontrollimine"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Tsüaansinine. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Kollane. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Must. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Punane. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Roheline. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Sinine. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Helehall. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Tumehall. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Hele tsüaansinine. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Hele magenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violetne. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Kohandatud värv: #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-eu/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-eu/strings.xml
index 03d7e1c..1962340 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-eu/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-eu/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Inprimatzen"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Deskonektatuta"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Egiaztatu inprimagailua"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Ziana. %% %1$d"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %% %1$d"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Horia. %% %1$d"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Beltza. %% %1$d"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Gorria. %% %1$d"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Berdea. %% %1$d"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Urdina. %% %1$d"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Gris argia. %% %1$d"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Gris iluna. %% %1$d"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Zian argia. %% %1$d"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta argia. %% %1$d"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Bioleta. %% %1$d"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Kolore pertsonalizatua #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-fa/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-fa/strings.xml
index dd67281..00d5b79 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-fa/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-fa/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"درحال چاپ کردن"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"آفلاین"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"بررسی چاپگر"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"‏فیروزه‌ای. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"‏سرخابی. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"‏زرد. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"‏سیاه. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"‏قرمز. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"‏سبز. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"‏آبی. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"‏خاکستری روشن. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"‏خاکستری تیره. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"‏فیروزه‌ای روشن. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"‏سرخابی روشن. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"‏بنفش. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"‏رنگ سفارشی #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-fi/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-fi/strings.xml
index eca18d1..11934e1 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-fi/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-fi/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Tulostaa"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline-tila"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Tarkista tulostin"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Syaani. %1$d %%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d %%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Keltainen. %1$d %%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Musta. %1$d %%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Punainen. %1$d %%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Vihreä. %1$d %%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Sininen. %1$d %%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Vaaleanharmaa. %1$d %%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Tummanharmaa. %1$d %%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Vaalea syaani. %1$d %%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Vaalea magenta. %1$d %%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violetti. %1$d %%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Oma väri #%1$02X%2$02X%3$02X. %4$d %%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-fr-rCA/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-fr-rCA/strings.xml
index 854ad3f..0d87f64 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-fr-rCA/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-fr-rCA/strings.xml
@@ -18,7 +18,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="recommendation_summary_new" msgid="7827367046167645850">"Le service d\'impression par défaut offre des options de base. Pour les options avancées, des services d\'impression supplémentaires sont proposés."</string>
-    <string name="recommendation_link" msgid="8300104407684336172">"Services d\'impression supplémentaires"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Services d\'impression suppl."</string>
     <string name="yes" msgid="1887141030777316285">"Oui"</string>
     <string name="unknown" msgid="2526777102391303730">"Inconnu"</string>
     <string name="printer_name" msgid="386653719801075739">"Nom de l\'imprimante"</string>
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Impression en cours…"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Hors ligne"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Vérifier l\'imprimante"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Jaune. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Noir. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rouge. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Vert. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Bleu. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Gris clair. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Gris foncé. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Cyan clair. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta clair. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Couleur personnalisée #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-fr/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-fr/strings.xml
index 0253be0..cfbe8fa 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-fr/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-fr/strings.xml
@@ -18,16 +18,29 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="recommendation_summary_new" msgid="7827367046167645850">"Le service d\'impression par défaut fournit des options de base. Pour les options avancées, d\'autres services d\'impression sont disponibles."</string>
-    <string name="recommendation_link" msgid="8300104407684336172">"Services d\'impression supplémentaires"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Autres services d\'impression"</string>
     <string name="yes" msgid="1887141030777316285">"Oui"</string>
     <string name="unknown" msgid="2526777102391303730">"Inconnu"</string>
     <string name="printer_name" msgid="386653719801075739">"Nom de l\'imprimante"</string>
     <string name="status" msgid="5948149021115901261">"État"</string>
     <string name="media_ready" msgid="7205545458156298899">"Formats de papier chargés"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Niveaux d\'approvisionnement"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Niveaux des consommables"</string>
     <string name="information" msgid="7896978544179559432">"Informations"</string>
     <string name="printer_ready" msgid="1602057851194259669">"Prête"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Impression"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Hors connexion"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Vérifier l\'imprimante"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Jaune. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Noir. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rouge. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Vert. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Bleu. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Gris clair. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Gris foncé. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Cyan clair. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta clair. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Couleur personnalisée #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-gl/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-gl/strings.xml
index 2aabca3..3473971 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-gl/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-gl/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Imprimindo"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Sen conexión"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Comprobar impresora"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Ciano. %1$d %%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Maxenta. %1$d %%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Amarelo. %1$d %%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Negro. %1$d %%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Vermello. %1$d %%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Verde. %1$d %%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Azul. %1$d %%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Gris claro. %1$d %%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Gris escuro. %1$d %%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ciano claro. %1$d %%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Maxenta claro. %1$d %%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violeta. %1$d %%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Cor personalizada #%1$02X%2$02X%3$02X. %4$d %%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-gu/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-gu/strings.xml
index 7866e10..de57a38 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-gu/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-gu/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"પ્રિન્ટિંગ"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ઑફલાઇન"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"પ્રિન્ટર ચેક કરો"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"સાયન. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"મજેન્ટા. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"પીળો. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"કાળો. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"લાલ. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"લીલો. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"વાદળી. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"આછો રાખોડી. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"ઘાટો રાખોડી. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"આછો સાયન. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"આછો મજેન્ટા. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"જાંબલી. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"કસ્ટમ રંગ #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-hi/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-hi/strings.xml
index d72b0fb..3683758 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-hi/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-hi/strings.xml
@@ -17,17 +17,30 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"प्रिंट करने की डिफ़ॉल्ट सेवा में बुनियादी विकल्प मिलते हैं. बेहतर विकल्पों में, प्रिंट करने की अतिरिक्त सेवाएं उपलब्ध हैं."</string>
-    <string name="recommendation_link" msgid="8300104407684336172">"प्रिंट करने की अतिरिक्त सेवाएं"</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"प्रिंट से जुड़ी डिफ़ॉल्ट सेवा में बुनियादी सुविधाएं मिलती हैं. बेहतर विकल्पों के लिए, प्रिंट से जुड़ी अतिरिक्ट सेवाओं का इस्तेमाल करें."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"प्रिंट से जुड़ी अलग-अलग सेवाएं"</string>
     <string name="yes" msgid="1887141030777316285">"हां"</string>
     <string name="unknown" msgid="2526777102391303730">"कोई जानकारी नहीं है"</string>
     <string name="printer_name" msgid="386653719801075739">"प्रिंटर का नाम"</string>
     <string name="status" msgid="5948149021115901261">"स्थिति"</string>
     <string name="media_ready" msgid="7205545458156298899">"लोड किए गए पेपर के साइज़"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"सप्लाई के लेवल"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"इंक के लेवल"</string>
     <string name="information" msgid="7896978544179559432">"जानकारी"</string>
     <string name="printer_ready" msgid="1602057851194259669">"तैयार है"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"प्रिंटिंग"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ऑफ़लाइन"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"प्रिंटर की जांच करें"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"सायन. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"मजेंटा. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"पीला. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"काला. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"लाल. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"हरा. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"नीला. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"हल्का स्लेटी. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"गहरा स्लेटी. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"हल्का सायन. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"हल्का मजेंटा. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"बैंगनी. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"पसंद के हिसाब से रंग #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-hr/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-hr/strings.xml
index 9ddb71b..a41f0dc 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-hr/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-hr/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Ispis"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Provjerite pisač"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cijan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Grimizna. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Žuta. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Crna. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Crvena. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Zelena. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Plava. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Svjetlosiva. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Tamnosiva. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Svjetlocijan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Svjetlogrimizna. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Ljubičasta. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Personalizirana boja #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-hu/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-hu/strings.xml
index f452854..80d4053 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-hu/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-hu/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Nyomtatás"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Nyomtató ellenőrzése"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Ciánkék. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Sárga. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Fekete. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Piros. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Zöld. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Kék. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Világosszürke. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Sötétszürke. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Világos ciánkék. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Világosmagenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Ibolyaszín. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Egyéni szín: #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-hy/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-hy/strings.xml
index d38aef6..f4616b7 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-hy/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-hy/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Տպում"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Կապ չկա"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Ստուգել տպիչը"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Կապտականաչ։ %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Ծիրանեգույն։ %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Դեղին։ %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Սև։ %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Կարմիր։ %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Կանաչ։ %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Կապույտ։ %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Բաց մոխրագույն։ %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Մուգ մոխրագույն։ %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Բաց կապույտ։ %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Բաց ծիրանեգույն։ %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Մանուշակագույն։ %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Հատուկ գույն #%1$02X%2$02X%3$02X։ %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-in/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-in/strings.xml
index 5be47ce..a5c5d8e 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-in/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-in/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Mencetak"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Periksa printer"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Sian. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Kuning. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Hitam. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Merah. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Hijau. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Biru. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Abu-abu muda. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Abu-abu tua. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Sian muda. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta muda. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Warna kustom #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-is/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-is/strings.xml
index 8b33e20..086d437 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-is/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-is/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Prentar"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Án nettengingar"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Athugaðu prentara"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Blágrænn. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Blárauður. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Gulur. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Svartur. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rauður. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Grænn. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blár. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Ljósgrár. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Dökkgrár. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ljósblágrænn. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Ljósblárauður. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Fjólublár. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Sérsniðinn litur: #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-it/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-it/strings.xml
index 4b4b94e..497e692 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-it/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-it/strings.xml
@@ -26,8 +26,21 @@
     <string name="media_ready" msgid="7205545458156298899">"Dimensioni foglio caricato"</string>
     <string name="supply_levels" msgid="5058409966884929190">"Livelli di alimentazione"</string>
     <string name="information" msgid="7896978544179559432">"Informazioni"</string>
-    <string name="printer_ready" msgid="1602057851194259669">"Pronto"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Pronta"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Stampa in corso…"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Controlla la stampante"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Ciano. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Giallo. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Nero. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rosso. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Verde. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blu. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Grigio chiaro. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Grigio scuro. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ciano chiaro. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta chiaro. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Viola. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Colore personalizzato #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-iw/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-iw/strings.xml
index 0c19372..84c08e7 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-iw/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-iw/strings.xml
@@ -24,10 +24,49 @@
     <string name="printer_name" msgid="386653719801075739">"שם המדפסת"</string>
     <string name="status" msgid="5948149021115901261">"סטטוס"</string>
     <string name="media_ready" msgid="7205545458156298899">"הגדלים של הדפים שנטענו"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"רמות האספקה"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"רמות הדיו"</string>
     <string name="information" msgid="7896978544179559432">"מידע"</string>
     <string name="printer_ready" msgid="1602057851194259669">"אפשר להתחיל"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"הדפסה"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"אופליין"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"צריך לבדוק את המדפסת"</string>
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_cyan (5336603473668190361) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_magenta (7522291481654771752) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_yellow (1394790774846459656) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_black (8169613731999901161) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_red (6322728797617451050) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_green (4341485089035826733) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_blue (6093087793287535042) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_ltgray (35187469450032645) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_dkgray (5314300850228586851) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_ltcyan (6793088455903750830) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_ltmagenta (3104489452878039184) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_violet (1616979275172835644) -->
+    <skip />
+    <!-- String.format failed for translation -->
+    <!-- no translation found for marker_level_custom (586736254509490403) -->
+    <skip />
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ja/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ja/strings.xml
index 88c6574..00038a6 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ja/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ja/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"プリンタ名"</string>
     <string name="status" msgid="5948149021115901261">"ステータス"</string>
     <string name="media_ready" msgid="7205545458156298899">"読み込まれた用紙のサイズ"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"供給レベル"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"サプライのレベル"</string>
     <string name="information" msgid="7896978544179559432">"情報"</string>
     <string name="printer_ready" msgid="1602057851194259669">"準備完了"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"印刷"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"オフライン"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"プリンタを確認してください"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"シアン。%1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"マゼンタ。%1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"黄色。%1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"黒色。%1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"赤色。%1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"緑色。%1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"青色。%1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"明るいグレー。%1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"ダークグレー。%1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"明るいシアン。%1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"明るいマゼンタ。%1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"紫色。%1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"カスタム色 #%1$02X%2$02X%3$02X。%4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ka/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ka/strings.xml
index 02932a9..2d90509 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ka/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ka/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"იბეჭდება"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ხაზგარეშე"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"პრინტერის შემოწმება"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"მომწვანო-მოცისფრო. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"მეწამული. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"ყვითელი. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"შავი. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"წითელი. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"მწვანე. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"ლურჯი. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"ღია ნაცრისფერი. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"მუქი ნაცრისფერი. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"ღია მომწვანო-მოცისფრო. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ღია მეწამული. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"იისფერი. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"მორგებული ფერები #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-kk/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-kk/strings.xml
index 7780f72..e4a1e09 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-kk/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-kk/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Басып шығару"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Офлайн"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Принтерді тексеру"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Көкшіл. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Қызылкүрең. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Сары. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Қара. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Қызыл. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Жасыл. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Көк. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Ашық сұр. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Қою сұр. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ашық көкшіл. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Ашық қызылкүрең. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Күлгін. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"#%1$02X%2$02X%3$02X арнаулы түсі. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-km/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-km/strings.xml
index 5435e34..7b0f09d 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-km/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-km/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"ការ​បោះពុម្ព"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"គ្មានអ៊ីនធឺណិត"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"ពិនិត្យ​ម៉ាស៊ីនបោះពុម្ព"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"ស៊ីលៀប។ %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"ក្រហមស្វាយ។ %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"លឿង។ %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"ខ្មៅ។ %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"ក្រហម។ %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"បៃតង។ %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"ខៀវ។ %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"ប្រផេះ​ស្រាល។ %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"ប្រផេះ​ចាស់។ %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"ស៊ីលៀប​ស្រាល។ %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ក្រហម​ស្វាយស្រាល។ %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"ត្របែកព្រៃ។ %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"ពណ៌ផ្ទាល់ខ្លួន #%1$02X%2$02X%3$02X។ %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-kn/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-kn/strings.xml
index 7a7542f..df857a5 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-kn/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-kn/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"ಮುದ್ರಣ"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ಆಫ್‌ಲೈನ್"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"ಪ್ರಿಂಟರ್ ಅನ್ನು ಪರಿಶೀಲಿಸಿ"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"ಹಸಿರುನೀಲಿ. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"ಮೆಜೆಂತಾ. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"ಹಳದಿ. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"ಕಪ್ಪು. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"ಕೆಂಪು. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"ಹಸಿರು. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"ನೀಲಿ. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"ತಿಳಿ ಬೂದು. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"ಗಾಢ ಬೂದು. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"ತಿಳಿ ಹಸಿರುನೀಲಿ. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ತಿಳಿ ಮೆಜೆಂತಾ. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"ನೇರಳೆ. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"ಕಸ್ಟಮ್ ಬಣ್ಣ #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ko/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ko/strings.xml
index d58165c..9e12d8f 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ko/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ko/strings.xml
@@ -17,17 +17,30 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"기본인쇄 서비스에서는 기본적인 옵션만 제공됩니다. 고급 옵션의 경우 추가 인쇄 서비스를 이용할 수 있습니다."</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"기본 인쇄 서비스에서는 기본적인 옵션만 제공됩니다. 고급 옵션의 경우 추가 인쇄 서비스를 이용할 수 있습니다."</string>
     <string name="recommendation_link" msgid="8300104407684336172">"추가 인쇄 서비스"</string>
     <string name="yes" msgid="1887141030777316285">"예"</string>
     <string name="unknown" msgid="2526777102391303730">"알 수 없음"</string>
     <string name="printer_name" msgid="386653719801075739">"프린터 이름"</string>
     <string name="status" msgid="5948149021115901261">"상태"</string>
     <string name="media_ready" msgid="7205545458156298899">"로드된 용지 크기"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"공급 수준"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"소모품 잔량"</string>
     <string name="information" msgid="7896978544179559432">"정보"</string>
     <string name="printer_ready" msgid="1602057851194259669">"준비됨"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"인쇄 중"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"오프라인"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"프린터 확인"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"녹청색. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"자홍색. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"노란색. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"검은색. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"빨간색. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"초록색. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"파란색. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"연한 회색. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"진한 회색. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"연한 녹청색. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"연한 자홍색. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"보라색. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"사용자 지정 색상 #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ky/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ky/strings.xml
index bf8c4f4..2a03eca 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ky/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ky/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Басып чыгаруу"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Офлайн"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Принтерди текшерүү"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Көгүлтүр. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Маджента. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Сары. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Кара. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Кызыл. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Жашыл. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Көк. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Бозомук. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Кочкул боз. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ачык көгүлтүр. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Ачык кызгылт көк. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Кызгылт көк. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Ыңгайлаштырылган түс #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-lo/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-lo/strings.xml
index 470be12..aedf4a1 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-lo/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-lo/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"ກຳລັງພິມ"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ອອບລາຍ"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"ກວດສອບເຄື່ອງພິມ"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"ສີຟ້າອົມຂຽວ. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"ສີມ່ວງອົມແດງ. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"ສີເຫຼືອງ. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"ສີດຳ. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"ສີແດງ. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"ສີຂຽວ. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"ສີຟ້າ. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"ສີເທົາອ່ອນ. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"ສີເທົາເຂັ້ມ. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"ສີຟ້າອົມຂຽວອ່ອນ. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ສີມ່ວງອົມແດງອ່ອນ. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"ສີມ່ວງ. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"ສີແບບກຳນົດເອງ #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-lt/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-lt/strings.xml
index e582b88..e520d8f 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-lt/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-lt/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Spausdinimas"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Neprisijungus"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Tikrinti spausdintuvą"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Žalsvai mėlyna. %1$d %%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Purpurinė. %1$d %%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Geltona. %1$d %%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Juoda. %1$d %%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Raudona. %1$d %%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Žalia. %1$d %%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Mėlyna. %1$d %%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Šviesiai pilka. %1$d %%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Tamsiai pilka. %1$d %%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Šviesi žalsvai mėlyna. %1$d %%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Šviesiai purpurinė. %1$d %%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violetinė. %1$d %%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Tinkinta spalva #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-lv/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-lv/strings.xml
index 88e3b7c..70472a1 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-lv/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-lv/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Notiek drukāšana…"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Bezsaistē"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Pārbaudīt printeri"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Ciānzila. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Fuksīnsarkana. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Dzeltena. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Melna. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Sarkana. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Zaļa. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Zila. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Gaiši pelēka. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Tumši pelēka. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Gaiši ciānzila. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Gaiši fuksīnsarkana. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violeta. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Pielāgota krāsa #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-mk/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-mk/strings.xml
index 4dfaee5..2e0a4de 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-mk/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-mk/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"Име на печатачот"</string>
     <string name="status" msgid="5948149021115901261">"Статус"</string>
     <string name="media_ready" msgid="7205545458156298899">"Големина на вметнатата хартија"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Нивоа на снабдување"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Нивоа на бои"</string>
     <string name="information" msgid="7896978544179559432">"Информации"</string>
     <string name="printer_ready" msgid="1602057851194259669">"Подготвено"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Се печати"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Офлајн"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Проверете го печатачот"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Сино-зелена. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Магента. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Жолта. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Црна. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Црвена. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Зелена. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Сина. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Светлосива. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Темносива. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Светла сино-зелена. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Светла магента. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Виолетова. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Приспособена боја #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ml/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ml/strings.xml
index b868761..a469338 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ml/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ml/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"പ്രിന്ററിന്റെ പേര്"</string>
     <string name="status" msgid="5948149021115901261">"നില"</string>
     <string name="media_ready" msgid="7205545458156298899">"പേപ്പർ വലുപ്പങ്ങൾ ലോഡ് ചെയ്തു"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"വിതരണ നിലകൾ"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"സപ്ലൈ നിലകൾ"</string>
     <string name="information" msgid="7896978544179559432">"വിവരങ്ങൾ"</string>
     <string name="printer_ready" msgid="1602057851194259669">"തയ്യാറാണ്"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"പ്രിന്റിംഗ്"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ഓഫ്‌ലൈനാണ്"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"പ്രിന്റർ പരിശോധിക്കുക"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"സിയാൻ. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"മജന്ത. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"മഞ്ഞ. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"കറുപ്പ്. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"ചുവപ്പ്. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"പച്ച. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"നീല. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"ഇളം ചാരനിറം. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"കടും ചാരനിറം. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"ഇളം സിയാൻ. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ഇളം മജന്ത. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"വയലറ്റ്. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"ഇഷ്ടാനുസൃത നിറം #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-mn/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-mn/strings.xml
index d7bf090..2f9f3bf 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-mn/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-mn/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Хэвлэж байна"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Офлайн"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Хэвлэгчийг шалгах"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Шар хөх. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Улаан ягаан. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Шар. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Хар. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Улаан. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Ногоон. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Цэнхэр. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Цайвар саарал. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Хар саарал. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Цайвар шар хөх. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Цайвар улаан ягаан. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Хөх ягаан. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Захиалгат өнгө #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-mr/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-mr/strings.xml
index a89338c..5368e75 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-mr/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-mr/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"प्रिंटिंग"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ऑफलाइन"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"प्रिंटर तपासा"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"सियान. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"मजेंटा. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"पिवळा. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"काळा. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"लाल. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"हिरवा. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"निळा. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"फिकट राखाडी. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"गडद राखाडी. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"फिकट सियान. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"फिकट किरमिजी. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"जांभळा. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"कस्टम रंग #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ms/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ms/strings.xml
index 4be3c4f..1a1b05b 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ms/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ms/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Pencetakan"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Luar talian"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Semak pencetak"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Sian. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Kuning. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Hitam. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Merah. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Hijau. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Biru. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Kelabu cerah. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Kelabu tua. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Sian cerah. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta cerah. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Warna tersuai #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-my/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-my/strings.xml
index 91d1e8f..d3a71b9 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-my/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-my/strings.xml
@@ -17,17 +17,30 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"ပုံသေ ပုံနှိပ်ပေးခြင်း ဝန်ဆောင်မှုသည် အခြေခံရွေးစရာများကို ပေးသည်။ အဆင့်မြင့်ရွေးစရာများအတွက် ထပ်ဆောင်း ပုံနှိပ်ပေးခြင်း ဝန်ဆောင်မှုများ ရနိုင်သည်။"</string>
-    <string name="recommendation_link" msgid="8300104407684336172">"ထပ်ဆောင်း ပုံနှိပ်ပေးခြင်း ဝန်ဆောင်မှုများ"</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"မူလ ပုံနှိပ်ဝန်ဆောင်မှုသည် အခြေခံရွေးစရာများကို ပေးသည်။ အဆင့်မြင့်ရွေးစရာများအတွက် ထပ်ဆောင်း ပုံနှိပ်ဝန်ဆောင်မှုများ ရနိုင်သည်။"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"ထပ်ဆောင်း ပုံနှိပ်ဝန်ဆောင်မှုများ"</string>
     <string name="yes" msgid="1887141030777316285">"Yes"</string>
     <string name="unknown" msgid="2526777102391303730">"မသိပါ"</string>
     <string name="printer_name" msgid="386653719801075739">"ပုံနှိပ်စက်အမည်"</string>
     <string name="status" msgid="5948149021115901261">"အခြေအနေ"</string>
     <string name="media_ready" msgid="7205545458156298899">"ဖွင့်ထားသော စာရွက်အရွယ်အစားများ"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"ပံ့ပိုးမှုအဆင့်များ"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"လက်ကျန်ပမာဏ"</string>
     <string name="information" msgid="7896978544179559432">"အချက်အလက်"</string>
     <string name="printer_ready" msgid="1602057851194259669">"အဆင်သင့်"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"ပုံနှိပ်ထုတ်ယူနေသည်"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"အော့ဖ်လိုင်း"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"ပရင်တာကို စစ်ဆေးရန်"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"စိမ်းပြာ။ %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"ပန်းခရမ်း။ %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"အဝါ။ %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"အနက်။ %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"အနီ။ %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"အစိမ်း။ %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"အပြာ။ %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"မီးခိုးဖျော့။ %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"မီးခိုးရင့်။ %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"စိမ်းပြာဖျော့။ %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ပန်းခရမ်းဖျော့။ %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"ခရမ်း။ %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"စိတ်ကြိုက်အရောင် #%1$02X%2$02X%3$02X။ %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-nb/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-nb/strings.xml
index f3eb5c0..ab179f4 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-nb/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-nb/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Skriver ut"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Uten nett"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Sjekk skriveren"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d %%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d %%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Gul. %1$d %%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Svart. %1$d %%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rød. %1$d %%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Grønn. %1$d %%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blå. %1$d %%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Lys grå. %1$d %%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Mørkegrå. %1$d %%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Lys cyan. %1$d %%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Lys magenta. %1$d %%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Fiolett. %1$d %%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Egendefinert farge #%1$02X%2$02X%3$02X. %4$d %%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ne/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ne/strings.xml
index fddf1c6..a7ea141 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ne/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ne/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"प्रिन्ट गरिँदै छ"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"अफलाइन छ"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"प्रिन्टर जाँच्नुहोस्"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"सायन। %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"मजेन्टा। %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"पहेँलो। %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"कालो। %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"रातो। %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"हरियो। %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"निलो। %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"हल्का खरानी रङ। %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"गाढा खरानी रङ। %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"हल्का सायन। %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"हल्का मजेन्टा। %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"बैजनी। %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"कस्टम रङ #%1$02X%2$02X%3$02X। %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-nl/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-nl/strings.xml
index e6b1906..a983435 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-nl/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-nl/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"Naam printer"</string>
     <string name="status" msgid="5948149021115901261">"Status"</string>
     <string name="media_ready" msgid="7205545458156298899">"Geladen papierformaten"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Voorraadniveaus"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Inktniveaus"</string>
     <string name="information" msgid="7896978544179559432">"Informatie"</string>
     <string name="printer_ready" msgid="1602057851194259669">"Klaar"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Afdrukken"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Printer controleren"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyaan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Geel. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Zwart. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rood. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Groen. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blauw. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Lichtgrijs. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Donkergrijs. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Lichtcyaan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Lichtmagenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Aangepaste kleur #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-or/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-or/strings.xml
index 5eb199f..5c812e3 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-or/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-or/strings.xml
@@ -17,7 +17,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"ଡିଫଲ୍ଟ ପ୍ରିଣ୍ଟ ସେବା ପ୍ରଦାନକାରୀ ମୌଳିକ ବିକଳ୍ପ ଉନ୍ନତ ବିକଳ୍ପ ପାଇଁ ଅତିରିକ୍ତ ପ୍ରିଣ୍ଟ ସେବା ଉପଲବ୍ଧ।"</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ଡିଫଲ୍ଟ ପ୍ରିଣ୍ଟ ସେବା ବେସିକ ବିକଳ୍ପଗୁଡ଼ିକ ପ୍ରଦାନ କରେ। ଉନ୍ନତ ବିକଳ୍ପଗୁଡ଼ିକ ପାଇଁ ଅତିରିକ୍ତ ପ୍ରିଣ୍ଟ ସେବା ଉପଲବ୍ଧ।"</string>
     <string name="recommendation_link" msgid="8300104407684336172">"ଅତିରିକ୍ତ ପ୍ରିଣ୍ଟ ସେବା"</string>
     <string name="yes" msgid="1887141030777316285">"ହଁ"</string>
     <string name="unknown" msgid="2526777102391303730">"ଅଜଣା"</string>
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"ପ୍ରିଣ୍ଟ କରାଯାଉଛି"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ଅଫଲାଇନ"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"ପ୍ରିଣ୍ଟର ଯାଞ୍ଚ କରନ୍ତୁ"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"ସାଇଆନ। %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"ମାଜେଣ୍ଟା। %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"ହଳଦିଆ। %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"କଳା। %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"ଲାଲ। %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"ସବୁଜ। %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"ନୀଳ। %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"ଫିକା ଧୂସର। %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"ଗାଢ଼ ଧୂସର। %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"ଫିକା ସାଇଆନ। %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ଫିକା ମାଜେଣ୍ଟା। %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"ବାଇଗଣୀ। %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"କଷ୍ଟମ ରଙ୍ଗ #%1$02X%2$02X%3$02X। %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-pa/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-pa/strings.xml
index 71efd68..7a163ef 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-pa/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-pa/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"ਪ੍ਰਿੰਟਿੰਗ"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ਆਫ਼ਲਾਈਨ"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"ਪ੍ਰਿੰਟਰ ਦੀ ਜਾਂਚ ਕਰੋ"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"ਸੀਆਨ। %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"ਮੈਜੰਟਾ। %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"ਪੀਲਾ। %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"ਕਾਲਾ। %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"ਲਾਲ। %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"ਹਰਾ। %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"ਨੀਲਾ। %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"ਹਲਕਾ ਸਲੇਟੀ। %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"ਗੂੜ੍ਹਾ ਸਲੇਟੀ। %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"ਹਲਕਾ ਸੀਆਨ। %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ਹਲਕਾ ਮੈਜੰਟਾ। %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"ਬੈਂਗਣੀ। %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"ਵਿਉਂਤਿਆ ਰੰਗ #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-pl/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-pl/strings.xml
index a1fd986..e5c1fc5 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-pl/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-pl/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Drukuje"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Sprawdź drukarkę"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Błękitny. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Purpurowy. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Żółty. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Czarny. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Czerwony. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Zielony. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Niebieski. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Jasnoszary. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Ciemnoszary. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Jasnobłękitny. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Jasnopurpurowy. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Fioletowy. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Kolor niestandardowy #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rBR/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rBR/strings.xml
index c80286c..010c3f9 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rBR/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rBR/strings.xml
@@ -17,17 +17,30 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"O serviço de impressão padrão oferece opções básicas. Para acessar as opções avançadas, outros serviços de impressão estão disponíveis."</string>
-    <string name="recommendation_link" msgid="8300104407684336172">"Serviços de impressão extras"</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"O serviço de impressão padrão oferece opções básicas. Para opções avançadas, serviços adicionais de impressão estão disponíveis."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Serviços adicionais de impressão"</string>
     <string name="yes" msgid="1887141030777316285">"Sim"</string>
     <string name="unknown" msgid="2526777102391303730">"Desconhecido"</string>
     <string name="printer_name" msgid="386653719801075739">"Nome da impressora"</string>
     <string name="status" msgid="5948149021115901261">"Status"</string>
     <string name="media_ready" msgid="7205545458156298899">"Tamanhos de papel carregados"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Níveis de fornecimento"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Níveis de tinta"</string>
     <string name="information" msgid="7896978544179559432">"Informações"</string>
-    <string name="printer_ready" msgid="1602057851194259669">"Pronto"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Pronta"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Imprimindo"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Off-line"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Verificar impressora"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Ciano. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Amarela. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Preta. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Vermelha. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Verde. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Azul. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Cinza-claro. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Cinza-escuro. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ciano-claro. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta-claro. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violeta. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Cor personalizada #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rPT/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rPT/strings.xml
index 5c095bd..81c5cf6 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rPT/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-pt-rPT/strings.xml
@@ -17,7 +17,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"O serviço de impressão padrão oferece opções básicas. Para opções avançadas, estão disponíveis serviços de impressão adicionais."</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"O serviço de impressão predefinido oferece opções básicas. Para opções avançadas, estão disponíveis serviços de impressão adicionais."</string>
     <string name="recommendation_link" msgid="8300104407684336172">"Serviços de impressão adicionais"</string>
     <string name="yes" msgid="1887141030777316285">"Sim"</string>
     <string name="unknown" msgid="2526777102391303730">"Desconhecido"</string>
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"A imprimir"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Verificar impressora"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Ciano. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Amarelo. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Preto. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Vermelho. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Verde. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Azul. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Cinzento-claro. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Cinzento-escuro. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ciano-claro. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta-claro. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violeta. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Cor personalizada #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-pt/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-pt/strings.xml
index c80286c..010c3f9 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-pt/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-pt/strings.xml
@@ -17,17 +17,30 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"O serviço de impressão padrão oferece opções básicas. Para acessar as opções avançadas, outros serviços de impressão estão disponíveis."</string>
-    <string name="recommendation_link" msgid="8300104407684336172">"Serviços de impressão extras"</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"O serviço de impressão padrão oferece opções básicas. Para opções avançadas, serviços adicionais de impressão estão disponíveis."</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Serviços adicionais de impressão"</string>
     <string name="yes" msgid="1887141030777316285">"Sim"</string>
     <string name="unknown" msgid="2526777102391303730">"Desconhecido"</string>
     <string name="printer_name" msgid="386653719801075739">"Nome da impressora"</string>
     <string name="status" msgid="5948149021115901261">"Status"</string>
     <string name="media_ready" msgid="7205545458156298899">"Tamanhos de papel carregados"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Níveis de fornecimento"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Níveis de tinta"</string>
     <string name="information" msgid="7896978544179559432">"Informações"</string>
-    <string name="printer_ready" msgid="1602057851194259669">"Pronto"</string>
+    <string name="printer_ready" msgid="1602057851194259669">"Pronta"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Imprimindo"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Off-line"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Verificar impressora"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Ciano. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Amarela. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Preta. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Vermelha. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Verde. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Azul. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Cinza-claro. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Cinza-escuro. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ciano-claro. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta-claro. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violeta. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Cor personalizada #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ro/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ro/strings.xml
index a0c5068..bd7c24b 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ro/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ro/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Printare"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Verifică imprimanta"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Galben. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Negru. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Roșu. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Verde. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Albastru. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Gri deschis. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Gri închis. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Cyan deschis. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Magenta deschis. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Culoare personalizată #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ru/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ru/strings.xml
index 95748a4..456427e 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ru/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ru/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Печать"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Офлайн"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Проверьте принтер"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Голубые чернила: %1$d %%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Пурпурные чернила: %1$d %%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Желтые чернила: %1$d %%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Черные чернила: %1$d %%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Красные чернила: %1$d %%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Зеленые чернила: %1$d %%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Синие чернила: %1$d %%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Светло-серые чернила: %1$d %%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Темно-серые чернила: %1$d %%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Светло-голубые чернила: %1$d %%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Светло-пурпурные чернила: %1$d %%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Фиолетовые чернила: %1$d %%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Чернила пользовательского цвета #%1$02X%2$02X%3$02X: %4$d %%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-si/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-si/strings.xml
index aacfb86..9ec559d 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-si/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-si/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"මුද්‍රණය කිරීම්"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"නොබැඳි"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"මුද්‍රණ යන්ත්‍රය පරීක්ෂා කරන්න"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"සියන්. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"මැජෙන්ටා. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"කහ. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"කළු. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"රතු. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"කොළ. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"නිල්. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"ලා අළු. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"තද අළු. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"ලා සියන්. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ලා මැජෙන්ටා. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"වයලට්. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"අභිරුචි වර්ණය #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sk/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sk/strings.xml
index fa519c6..3730ea6 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-sk/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sk/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"Názov tlačiarne"</string>
     <string name="status" msgid="5948149021115901261">"Stav"</string>
     <string name="media_ready" msgid="7205545458156298899">"Veľkosti vkladaného papiera"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Úrovne zásob"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Stav náplní"</string>
     <string name="information" msgid="7896978544179559432">"Informácia"</string>
     <string name="printer_ready" msgid="1602057851194259669">"Pripravené"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Tlač"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Kontrola tlačiarne"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Azúrový. %1$d %%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Purpurový. %1$d %%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Žltý. %1$d %%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Čierny. %1$d %%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Červený. %1$d %%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Zelený. %1$d %%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Modrý. %1$d %%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Svetlosivý. %1$d %%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Tmavosivý. %1$d %%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Svetloazúrový. %1$d %%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Svetlopurpurový. %1$d %%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Fialový. %1$d %%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Vlastná farba #%1$02X%2$02X%3$02X. %4$d %%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sl/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sl/strings.xml
index 174fd1d..47c7c89 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-sl/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sl/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"Ime tiskalnika"</string>
     <string name="status" msgid="5948149021115901261">"Stanje"</string>
     <string name="media_ready" msgid="7205545458156298899">"Naložene velikosti papirja"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Ravni oskrbe"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Zaloge"</string>
     <string name="information" msgid="7896978544179559432">"Informacije"</string>
     <string name="printer_ready" msgid="1602057851194259669">"Pripravljeno"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Tiskanje"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Brez povezave"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Preveri tiskalnik"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cijan. %1$d %%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d %%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Rumena. %1$d %%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Črna. %1$d %%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Rdeča. %1$d %%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Zelena. %1$d %%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Modra. %1$d %%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Svetlo siva. %1$d %%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Temno siva. %1$d %%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Svetlo cijan. %1$d %%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Svetlo magenta. %1$d %%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Vijolična. %1$d %%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Barva po meri #%1$02X%2$02X%3$02X. %4$d %%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sq/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sq/strings.xml
index cfa27b2..ddc1c4f 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-sq/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sq/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Po printon"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Kontrollo printerin"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"E bruztë. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"E purpurt. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"E verdhë. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"E zezë. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"E kuqe. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"E gjelbër. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blu. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Gri e çelur. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Gri e errët. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"E bruztë e çelur. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"E purpurt e çelur. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Vjollcë. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Ngjyrë e personalizuar #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sr/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sr/strings.xml
index 0b5dd7b..b17c382 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-sr/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sr/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Штампање"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Офлајн"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Проверите штампач"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Цијан. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Циклама. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Жута. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Црна. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Црвена. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Зелена. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Плава. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Светлосива. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Тамносива. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Светлоцијан. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Светлоциклама. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Љубичаста. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Прилагођена боја #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sv/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sv/strings.xml
index c7a03be..900a117 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-sv/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sv/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Skriver ut"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Kontrollera skrivare"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Gul. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Svart. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Röd. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Grön. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Blå. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Ljusgrå. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Mörkgrå. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Ljus cyan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Ljus magenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Lila. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Anpassad färg #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-sw/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-sw/strings.xml
index ad7900e..65e38dd 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-sw/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-sw/strings.xml
@@ -17,17 +17,30 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"Huduma chaguomsingi ya uchapishaji hutoa chaguo za msingi. Kwa chaguo za kina, huduma za ziada za uchapishaji zinapatikana."</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Huduma chaguomsingi ya uchapishaji hutoa huduma za msingi. Kwa chaguo za kina, kuna huduma za ziada za uchapishaji."</string>
     <string name="recommendation_link" msgid="8300104407684336172">"Huduma za ziada za uchapishaji"</string>
     <string name="yes" msgid="1887141030777316285">"Ndiyo"</string>
     <string name="unknown" msgid="2526777102391303730">"Haijulikani"</string>
     <string name="printer_name" msgid="386653719801075739">"Jina la printa"</string>
     <string name="status" msgid="5948149021115901261">"Hali"</string>
     <string name="media_ready" msgid="7205545458156298899">"Ukubwa wa karatasi zilizopakiwa"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Viwango vya usambazaji"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Viwango vya wino"</string>
     <string name="information" msgid="7896978544179559432">"Maelezo"</string>
     <string name="printer_ready" msgid="1602057851194259669">"Tayari"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Inachapisha"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Nje ya mtandao"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Angalia printa"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Samawati kijani. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Majenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Manjano. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Nyeusi. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Nyekundu. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Kijani. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Buluu. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Rangi ya kijivu isiyokolea. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Rangi ya kijivu iliyokolea. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Samawati kijani isiyokolea. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Majenta isiyokolea. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Urujuani. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Rangi maalum #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ta/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ta/strings.xml
index 0177e9f..de5456f 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ta/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ta/strings.xml
@@ -17,7 +17,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"இயல்பு அச்சிடல் சேவை அடிப்படையான விருப்பங்களை வழங்குகிறது. மேம்பட்ட விருப்பங்களுக்கு, கூடுதல் பிரிண்ட் சேவைகள் கிடைக்கின்றன."</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"இயல்பு பிரிண்ட் சேவை அடிப்படையான விருப்பங்களை வழங்குகிறது. மேம்பட்ட விருப்பங்களுக்கு, கூடுதல் பிரிண்ட் சேவைகள் கிடைக்கின்றன."</string>
     <string name="recommendation_link" msgid="8300104407684336172">"கூடுதல் பிரிண்ட் சேவைகள்"</string>
     <string name="yes" msgid="1887141030777316285">"ஆம்"</string>
     <string name="unknown" msgid="2526777102391303730">"தெரியவில்லை"</string>
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"அச்சிடுகிறது"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ஆஃப்லைன்"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"பிரிண்ட்டரைச் சரிபாருங்கள்"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"சியான். %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"மெஜந்தா. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"மஞ்சள். %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"கருப்பு. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"சிவப்பு. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"பச்சை. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"நீலம். %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"வெளிர் சாம்பல். %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"அடர் சாம்பல். %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"வெளிர் சியான். %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"வெளிர் மெஜந்தா. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"ஊதா. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"பிரத்தியேக வண்ணம் #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-te/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-te/strings.xml
index 03ea1ea..f56344e 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-te/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-te/strings.xml
@@ -17,17 +17,30 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"ఆటోమేటిక్ ప్రింట్ సర్వీస్‌లో ప్రాథమిక ఆప్షన్‌ అందించబడతాయి. అధునాతన ఆప్షన్‌ల కోసం అదనపు ప్రింట్ సర్వీస్‌లు అందుబాటులో ఉన్నాయి."</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"ఆటోమేటిక్ (డిఫాల్ట్) ప్రింట్ సర్వీస్‌లో బేసిక్ ఆప్షన్లు ఉంటాయి. అడ్వాన్స్‌డ్ ఆప్షన్‌ల కోసం అదనపు ప్రింట్ సర్వీస్‌లు అందుబాటులో ఉన్నాయి."</string>
     <string name="recommendation_link" msgid="8300104407684336172">"అదనపు ప్రింట్ సర్వీస్‌లు"</string>
     <string name="yes" msgid="1887141030777316285">"అవును"</string>
     <string name="unknown" msgid="2526777102391303730">"తెలియనిది"</string>
     <string name="printer_name" msgid="386653719801075739">"ప్రింటర్ పేరు"</string>
     <string name="status" msgid="5948149021115901261">"స్టేటస్"</string>
     <string name="media_ready" msgid="7205545458156298899">"లోడ్ చేసిన పేపర్ సైజ్‌లు"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"సరఫరా స్థాయిలు"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"సప్లయి లెవల్స్"</string>
     <string name="information" msgid="7896978544179559432">"సమాచారం"</string>
     <string name="printer_ready" msgid="1602057851194259669">"సిద్ధంగా ఉంది"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"ప్రింట్ చేస్తోంది"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ఆఫ్‌లైన్‌లో ఉంది"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"ప్రింటర్‌ను చెక్ చేయండి"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"సయాన్ రంగు. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"మెజెంటా రంగు. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"పసుపు రంగు. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"నలుపు రంగు. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"ఎరుపు రంగు. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"ఆకుపచ్చ రంగు. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"నీలం రంగు. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"లేత బూడిద రంగు. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"ముదురు బూడిద రంగు. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"లేత సయాన్ రంగు. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"లేత మెజెంటా రంగు. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"వయొలెట్ రంగు. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"అనుకూల రంగు #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-th/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-th/strings.xml
index 51bffef..4b11393 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-th/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-th/strings.xml
@@ -17,17 +17,30 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"บริการการพิมพ์เริ่มต้นมีตัวเลือกพื้นฐานต่างๆ ส่วนบริการเพิ่มเติมเกี่ยวกับการพิมพ์จะมีตัวเลือกขั้นสูงพร้อมให้ใช้งาน"</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"บริการการพิมพ์เริ่มต้นมีตัวเลือกพื้นฐานต่างๆ และในส่วนของตัวเลือกขั้นสูง จะมีบริการการพิมพ์เพิ่มเติมให้ใช้งาน"</string>
     <string name="recommendation_link" msgid="8300104407684336172">"บริการเพิ่มเติมเกี่ยวกับการพิมพ์"</string>
     <string name="yes" msgid="1887141030777316285">"ใช่"</string>
     <string name="unknown" msgid="2526777102391303730">"ไม่ทราบ"</string>
     <string name="printer_name" msgid="386653719801075739">"ชื่อเครื่องพิมพ์"</string>
     <string name="status" msgid="5948149021115901261">"สถานะ"</string>
     <string name="media_ready" msgid="7205545458156298899">"ขนาดกระดาษที่มีอยู่ในเครื่อง"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"ระดับของสิ่งต่างๆ ที่จำเป็นต่อการทำงาน"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"ปริมาณหมึกพิมพ์"</string>
     <string name="information" msgid="7896978544179559432">"ข้อมูล"</string>
     <string name="printer_ready" msgid="1602057851194259669">"พร้อมใช้งาน"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"กำลังพิมพ์"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"ออฟไลน์"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"ตรวจสอบเครื่องพิมพ์"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"น้ำเงินอมเขียว %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"ม่วงแดง %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"เหลือง %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"ดำ %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"แดง %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"เขียว %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"น้ำเงิน %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"เทาอ่อน %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"เทาเข้ม %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"ฟ้าอ่อน %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"ม่วงแดงอ่อน %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"ม่วงอมน้ำเงิน %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"สีแบบกำหนดเอง #%1$02X%2$02X%3$02X %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-tl/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-tl/strings.xml
index a123d23..2cc0f0e 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-tl/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-tl/strings.xml
@@ -18,7 +18,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="recommendation_summary_new" msgid="7827367046167645850">"Nagbibigay ng mga basic na opsyon ang serbisyo sa default na pag-print. Para sa mga advanced na opsyon, available ang mga karagdagang serbisyo sa pag-print."</string>
-    <string name="recommendation_link" msgid="8300104407684336172">"Mga karagdagang serbisyo sa pag-print"</string>
+    <string name="recommendation_link" msgid="8300104407684336172">"Dagdag na services sa pag-print"</string>
     <string name="yes" msgid="1887141030777316285">"Oo"</string>
     <string name="unknown" msgid="2526777102391303730">"Hindi alam"</string>
     <string name="printer_name" msgid="386653719801075739">"Pangalan ng printer"</string>
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Pag-print"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Offline"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Suriin ang printer"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Cyan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Dilaw. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Itim. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Pula. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Berde. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Asul. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Light gray. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Dark gray. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Light cyan. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Light magenta. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Violet. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Custom na kulay #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-tr/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-tr/strings.xml
index fe55ce4..74ead5e 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-tr/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-tr/strings.xml
@@ -17,7 +17,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"Varsayılan yazdırma hizmeti, temel seçenekler sağlar. Gelişmiş seçeneklerde ek yazdırma hizmetleri mevcuttur."</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Varsayılan yazdırma hizmeti, temel seçenekler sağlar. Sunulan ek yazdırma hizmetlerinde gelişmiş seçenekler bulabilirsiniz."</string>
     <string name="recommendation_link" msgid="8300104407684336172">"Ek yazdırma hizmetleri"</string>
     <string name="yes" msgid="1887141030777316285">"Evet"</string>
     <string name="unknown" msgid="2526777102391303730">"Bilinmiyor"</string>
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Yazdırma"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Çevrimdışı"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Yazıcıyı kontrol et"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Camgöbeği. %%%1$d"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Macenta. %%%1$d"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Sarı. %%%1$d"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Siyah. %%%1$d"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Kırmızı. %%%1$d"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Yeşil. %%%1$d"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Mavi. %%%1$d"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Açık gri. %%%1$d"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Koyu gri. %%%1$d"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Açık camgöbeği. %%%1$d"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Açık macenta. %%%1$d"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Mor. %%%1$d"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Özel renk #%1$02X%2$02X%3$02X. %%%4$d"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-uk/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-uk/strings.xml
index 55f41b9..e55c9f3 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-uk/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-uk/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"Назва принтера"</string>
     <string name="status" msgid="5948149021115901261">"Статус"</string>
     <string name="media_ready" msgid="7205545458156298899">"Розміри завантаженого паперу"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Рівні витратних матеріалів"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Рівень чорнил"</string>
     <string name="information" msgid="7896978544179559432">"Інформація"</string>
     <string name="printer_ready" msgid="1602057851194259669">"Готово"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Друк"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Не в мережі"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Перевірте принтер"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Блакитний. %1$d%%."</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Пурпуровий. %1$d%%."</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Жовтий. %1$d%%."</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Чорний. %1$d%%."</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Червоний. %1$d%%."</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Зелений. %1$d%%."</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Синій. %1$d%%."</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Світло-сірий. %1$d%%."</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Темно-сірий. %1$d%%."</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Світло-блакитний. %1$d%%."</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Світло-пурпуровий. %1$d%%."</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Фіолетовий. %1$d%%."</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Власний колір: #%1$02X%2$02X%3$02X. %4$d%%."</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-ur/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-ur/strings.xml
index a92d2c4..bb3ee04 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-ur/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-ur/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"پرنٹنگ"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"آف لائن"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"پرنٹر چیک کریں"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"‏سبزی مائل نیلا %1$d%%‎"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"‏میجنٹا۔ %1$d%%‎"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"‏پیلا۔ %1$d%%‎"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"‏سیاہ۔ %1$d%%‎"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"‏سرخ۔ %1$d%%‎"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"‏سبز۔ %1$d%%‎"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"‏نیلا۔ %1$d%%‎"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"‏ہلکا خاکستری۔ %1$d%%‎"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"‏گہرا خاکستری۔ %1$d%%‎"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"‏ہلکا سبزی مائل نیلا۔ %1$d%%‎"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"‏ہلکا میجنٹا۔ %1$d%%‎"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"‏بیگنی۔ %1$d%%‎"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"‏حسب ضرورت رنگ #%1$02X%2$02X%3$02X۔ %4$d%%‎"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-uz/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-uz/strings.xml
index a3e4bf0..f3b08fc 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-uz/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-uz/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Chop etish"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Oflayn"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Printerni tekshirish"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Havorang. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Qirmizi. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Sariq. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Qora. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Qizil. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Yashil. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Koʻk. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Och kulrang. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Toʻq kulrang. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Och havorang. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Och qirmizi. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Siyohrang. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Maxsus rang #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-vi/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-vi/strings.xml
index 37ee9a3..7033b02 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-vi/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-vi/strings.xml
@@ -17,17 +17,30 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"Dịch vụ in mặc định đưa ra các lựa chọn cơ bản. Hiện có các dịch vụ in khác trong các lựa chọn nâng cao."</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"Dịch vụ in mặc định cung cấp các lựa chọn cơ bản. Đối với các lựa chọn nâng cao, vui lòng sử dụng các dịch vụ in bổ sung."</string>
     <string name="recommendation_link" msgid="8300104407684336172">"Dịch vụ in bổ sung"</string>
     <string name="yes" msgid="1887141030777316285">"Có"</string>
     <string name="unknown" msgid="2526777102391303730">"Không xác định"</string>
     <string name="printer_name" msgid="386653719801075739">"Tên máy in"</string>
     <string name="status" msgid="5948149021115901261">"Trạng thái"</string>
     <string name="media_ready" msgid="7205545458156298899">"Khổ giấy đã nạp"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"Mức cung ứng"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"Mức mực"</string>
     <string name="information" msgid="7896978544179559432">"Thông tin"</string>
     <string name="printer_ready" msgid="1602057851194259669">"Sẵn sàng"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"Đang in"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Không có mạng"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Kiểm tra máy in"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Lục lam. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Hồng tím. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Vàng. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Đen. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Đỏ. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Xanh lục. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Xanh dương. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Xám nhạt. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Xám đậm. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Lục lam nhạt. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Hồng tím nhạt. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Tím. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Màu tuỳ chỉnh #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rCN/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rCN/strings.xml
index a03a673..6a47dc1 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rCN/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rCN/strings.xml
@@ -17,17 +17,30 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="recommendation_summary_new" msgid="7827367046167645850">"默认打印服务会提供基本选项。如需高级选项，请使用其他打印服务。"</string>
+    <string name="recommendation_summary_new" msgid="7827367046167645850">"默认打印服务只提供基本选项。如需高级选项，请使用其他打印服务。"</string>
     <string name="recommendation_link" msgid="8300104407684336172">"其他打印服务"</string>
     <string name="yes" msgid="1887141030777316285">"是"</string>
     <string name="unknown" msgid="2526777102391303730">"未知"</string>
     <string name="printer_name" msgid="386653719801075739">"打印机名称"</string>
     <string name="status" msgid="5948149021115901261">"状态"</string>
     <string name="media_ready" msgid="7205545458156298899">"装入的纸张大小"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"耗材等级"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"耗材余量"</string>
     <string name="information" msgid="7896978544179559432">"信息"</string>
     <string name="printer_ready" msgid="1602057851194259669">"准备就绪"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"正在打印"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"离线"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"检查打印机"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"青色：%1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"品红色：%1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"黄色：%1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"黑色：%1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"红色：%1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"绿色：%1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"蓝色：%1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"浅灰色：%1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"深灰色：%1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"浅青色：%1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"浅品红色：%1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"紫罗兰色：%1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"自定义颜色 #%1$02X%2$02X%3$02X：%4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rHK/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rHK/strings.xml
index f7e7191..4cc9d93 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rHK/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rHK/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"打印機名稱"</string>
     <string name="status" msgid="5948149021115901261">"狀態"</string>
     <string name="media_ready" msgid="7205545458156298899">"已載入的紙張大小"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"供應等級"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"墨水餘量"</string>
     <string name="information" msgid="7896978544179559432">"資訊"</string>
     <string name="printer_ready" msgid="1602057851194259669">"準備就緒"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"列印"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"離線"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"檢查打印機"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"藍綠色：%1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"紫紅色：%1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"黃色：%1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"黑色：%1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"紅色：%1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"綠色：%1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"藍色：%1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"淺灰色：%1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"深灰色：%1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"淺青藍色：%1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"淺紫紅色：%1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"紫羅蘭色：%1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"自訂顏色 #%1$02X%2$02X%3$02X：%4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rTW/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rTW/strings.xml
index ee48704..9a46dba 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rTW/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-zh-rTW/strings.xml
@@ -24,10 +24,23 @@
     <string name="printer_name" msgid="386653719801075739">"印表機名稱"</string>
     <string name="status" msgid="5948149021115901261">"狀態"</string>
     <string name="media_ready" msgid="7205545458156298899">"裝入紙張大小"</string>
-    <string name="supply_levels" msgid="5058409966884929190">"供應等級"</string>
+    <string name="supply_levels" msgid="5058409966884929190">"墨水存量"</string>
     <string name="information" msgid="7896978544179559432">"資訊"</string>
     <string name="printer_ready" msgid="1602057851194259669">"就緒"</string>
     <string name="printer_state__printing" msgid="596624975473301735">"列印中"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"離線"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"檢查印表機"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"青色：%1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"洋紅色：%1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"黃色：%1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"黑色：%1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"紅色：%1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"綠色：%1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"藍色：%1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"淺灰色：%1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"深灰色：%1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"淺青色：%1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"淺洋紅色：%1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"紫羅蘭色：%1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"自訂顏色 #%1$02X%2$02X%3$02X：%4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values-zu/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values-zu/strings.xml
index aeb2dd1..9eb1e4b 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values-zu/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values-zu/strings.xml
@@ -30,4 +30,17 @@
     <string name="printer_state__printing" msgid="596624975473301735">"Iyaphrinta"</string>
     <string name="printer_state__offline" msgid="6755924316852857893">"Okungaxhunyiwe kwi-inthanethi"</string>
     <string name="printer_state__check_printer" msgid="4854932117258619033">"Hlola iphrinta"</string>
+    <string name="marker_level_cyan" msgid="5336603473668190361">"Oku-cyan. %1$d%%"</string>
+    <string name="marker_level_magenta" msgid="7522291481654771752">"Oku-magenta. %1$d%%"</string>
+    <string name="marker_level_yellow" msgid="1394790774846459656">"Okuphuzi. %1$d%%"</string>
+    <string name="marker_level_black" msgid="8169613731999901161">"Okumnyama. %1$d%%"</string>
+    <string name="marker_level_red" msgid="6322728797617451050">"Okubomvu. %1$d%%"</string>
+    <string name="marker_level_green" msgid="4341485089035826733">"Okuluhlaza okotshani. %1$d%%"</string>
+    <string name="marker_level_blue" msgid="6093087793287535042">"Okuluhlaza okwesibhakabhaka. %1$d%%"</string>
+    <string name="marker_level_ltgray" msgid="35187469450032645">"Okumpunga okukhanyayo. %1$d%%"</string>
+    <string name="marker_level_dkgray" msgid="5314300850228586851">"Okumpunga obumnyama. %1$d%%"</string>
+    <string name="marker_level_ltcyan" msgid="6793088455903750830">"Oku-cyan okhanyayo. %1$d%%"</string>
+    <string name="marker_level_ltmagenta" msgid="3104489452878039184">"Oku-magenta okhanyayo. %1$d%%"</string>
+    <string name="marker_level_violet" msgid="1616979275172835644">"Okuvayolethi. %1$d%%"</string>
+    <string name="marker_level_custom" msgid="586736254509490403">"Umbala wokomuntu ngamunye #%1$02X%2$02X%3$02X. %4$d%%"</string>
 </resources>
diff --git a/res/flag(com.android.bips.flags.printer_info_details)/values/strings.xml b/res/flag(com.android.bips.flags.printer_info_details)/values/strings.xml
index afb905f..728160b 100644
--- a/res/flag(com.android.bips.flags.printer_info_details)/values/strings.xml
+++ b/res/flag(com.android.bips.flags.printer_info_details)/values/strings.xml
@@ -36,4 +36,33 @@
     <string name="printer_state__offline">Offline</string>
     <string name="printer_state__check_printer">Check printer</string>
 
+    <!-- Supply levels -->
+
+    <!-- Accessibility description of the percent of cyan printer ink available -->
+    <string name="marker_level_cyan">Cyan. %1$d%%</string>
+    <!-- Accessibility description of the percent of magenta printer ink available -->
+    <string name="marker_level_magenta">Magenta. %1$d%%</string>
+    <!-- Accessibility description of the percent of yellow printer ink available -->
+    <string name="marker_level_yellow">Yellow. %1$d%%</string>
+    <!-- Accessibility description of the percent of black printer ink available -->
+    <string name="marker_level_black">Black. %1$d%%</string>
+    <!-- Accessibility description of the percent of red printer ink available -->
+    <string name="marker_level_red">Red. %1$d%%</string>
+    <!-- Accessibility description of the percent of green printer ink available -->
+    <string name="marker_level_green">Green. %1$d%%</string>
+    <!-- Accessibility description of the percent of blue printer ink available -->
+    <string name="marker_level_blue">Blue. %1$d%%</string>
+    <!-- Accessibility description of the percent of light gray printer ink available -->
+    <string name="marker_level_ltgray">Light gray. %1$d%%</string>
+    <!-- Accessibility description of the percent of dark gray printer ink available -->
+    <string name="marker_level_dkgray">Dark gray. %1$d%%</string>
+    <!-- Accessibility description of the percent of light cyan printer ink available -->
+    <string name="marker_level_ltcyan">Light cyan. %1$d%%</string>
+    <!-- Accessibility description of the percent of light magenta printer ink available -->
+    <string name="marker_level_ltmagenta">Light magenta. %1$d%%</string>
+    <!-- Accessibility description of the percent of violet printer ink available -->
+    <string name="marker_level_violet">Violet. %1$d%%</string>
+    <!-- Accessibility description of the percent of unknown color printer ink available. The coloris represented as a hex value -->
+    <string name="marker_level_custom">Custom color #%1$02X%2$02X%3$02X. %4$d%%</string>
+
 </resources>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index acdb4e9..a4d599c 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"يتم الاتصال عبر الشبكة الحالية باستخدام العنوان <xliff:g id="IP_ADDRESS">%1$s</xliff:g>."</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"تقدم \"خدمة النسبة التلقائية للصفحات المطبوعة\" خيارات أساسية. وقد تتوفر خيارات أخرى لهذا الطابعة من خدمة طباعة أخرى."</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"الخدمات الموصّى بها"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"اختيار للتثبيت"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"انقر لتثبيتها"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"اختيار للتفعيل"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"إدارة الخدمات"</string>
     <string name="security" msgid="2279008326210305401">"الأمان"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 859fffc..d70bce9 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"Es connecta a través de la xarxa actual a l\'adreça IP <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"El servei d\'impressió predeterminat ofereix algunes opcions bàsiques. Pot ser que hi hagi més opcions disponibles per a aquesta impressora en un altre servei d\'impressió."</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"Serveis recomanats"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"Selecciona\'n un per instal·lar-lo"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"Selecciona per instal·lar"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecciona\'n per activar-lo"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"Gestiona els serveis"</string>
     <string name="security" msgid="2279008326210305401">"Seguretat"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index a4e10c7..6475e4e 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"Připojení prostřednictvím stávající sítě s IP adresou <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Výchozí služba tisku nabízí základní možnosti. Další možnosti mohou být k dispozici z jiné služby tisku."</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"Doporučené služby"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"Vyberte, co nainstalovat"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"Vybrat a nainstalovat"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Vyberte, co aktivovat"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"Spravovat služby"</string>
     <string name="security" msgid="2279008326210305401">"Zabezpečení"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 4712795..4d1cb3a 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"Se conecta a través de la red actual con la dirección IP <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"El servicio de impresión predeterminado solo tiene opciones básicas. Es posible que en otro servicio de impresión haya más opciones disponibles para esta impresora."</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"Servicios recomendados"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"Selecciona lo que quieras instalar"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"Selecciónalo para instalarlo"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecciona lo que quieras habilitar"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"Gestionar servicios"</string>
     <string name="security" msgid="2279008326210305401">"Seguridad"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 0fc6eac..48ad80c 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"Yhdistetään nykyisen verkon kautta osoitteessa <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Oletustulostuspalveluun kuuluu perusvaihtoehdot. Muita vaihtoehtoja voi olla saatavilla toisissa tulostuspalveluissa."</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"Suositellut palvelut"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"Asenna valitsemalla"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"Valitse ja asenna"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Ota käyttöön valitsemalla"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"Ylläpidä palveluita"</string>
     <string name="security" msgid="2279008326210305401">"Suojaus"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 38f78d4..3dc7938 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"Conéctase a través da rede actual ao enderezo IP <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"O servizo de impresión predeterminado só ten opcións básicas. É posible que noutro servizo de impresión haxa máis opcións dispoñibles para esta impresora."</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"Servizos recomendados"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"Selecciona o que queiras instalar"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"Selecciónao para instalalo"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecciona o que queiras activar"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"Xestionar servizos"</string>
     <string name="security" msgid="2279008326210305401">"Seguranza"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 967b26b..5313dd7 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -19,7 +19,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="3551052199033657984">"प्रिंट करने की डिफ़ॉल्ट सेवा"</string>
     <string name="printer_busy" msgid="8604311528104955859">"व्यस्त"</string>
-    <string name="printer_out_of_paper" msgid="4882186432807703877">"कागज़ नहीं है"</string>
+    <string name="printer_out_of_paper" msgid="4882186432807703877">"काग़ज़ नहीं है"</string>
     <string name="printer_out_of_ink" msgid="7361897651097675464">"इंक खत्म है"</string>
     <string name="printer_out_of_toner" msgid="2077516357225364154">"टोनर खत्म है"</string>
     <string name="printer_low_on_ink" msgid="3515015872393897705">"इंक कम है"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 0922176..952f463 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -48,9 +48,9 @@
     <string name="no_printer_found" msgid="4777867380924351173">"Na ovoj adresi nije pronađen pisač"</string>
     <string name="printer_not_supported" msgid="281955849350938408">"Pisač nije podržan"</string>
     <string name="wifi_direct" msgid="4629404342852294985">"Wi-Fi Direct"</string>
-    <string name="find_wifi_direct" msgid="5270504288829123954">"Pronađite pisače s Izravnim Wi-Fijem"</string>
-    <string name="wifi_direct_printing" msgid="8423811041563144048">"Ispis putem Izravnog Wi-Fija"</string>
-    <string name="wifi_direct_printers" msgid="541168032444693191">"Pisači s Izravnim Wi-Fijem"</string>
+    <string name="find_wifi_direct" msgid="5270504288829123954">"Pronađite pisače s Wi-Fi Directom"</string>
+    <string name="wifi_direct_printing" msgid="8423811041563144048">"Ispis putem Wi-Fi Directa"</string>
+    <string name="wifi_direct_printers" msgid="541168032444693191">"Pisači s Wi-Fi Directom"</string>
     <string name="searching" msgid="2114018057619514587">"Pretraživanje…"</string>
     <string name="connect_hint_text" msgid="587112503851044234">"Možda ćete morati odobriti tu vezu na prednjoj ploči pisača"</string>
     <string name="connecting_to" msgid="2665161014972086194">"Povezivanje s pisačem <xliff:g id="PRINTER">%1$s</xliff:g>"</string>
@@ -58,7 +58,7 @@
     <string name="failed_connection" msgid="8068661997318286575">"Povezivanje s pisačem <xliff:g id="PRINTER">%1$s</xliff:g> nije uspjelo"</string>
     <string name="saved_printers" msgid="4567534965213125526">"Spremljeni pisači"</string>
     <string name="forget" msgid="892068061425802502">"Zaboravi"</string>
-    <string name="connects_via_wifi_direct" msgid="652300632780158437">"Povezuje se putem Izravnog Wi-Fija"</string>
+    <string name="connects_via_wifi_direct" msgid="652300632780158437">"Povezuje se putem Wi-Fi Directa"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"Povezuje se putem trenutačne mreže na IP adresi <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Zadana usluga ispisa nudi osnovne opcije. Ostale opcije za ovaj pisač mogu biti dostupne iz druge usluge ispisa."</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"Preporučene usluge"</string>
@@ -71,8 +71,8 @@
     <string name="accept" msgid="4426153292469698134">"Prihvati"</string>
     <string name="reject" msgid="24751635160440693">"Odbij"</string>
     <string name="connections" msgid="8895413761760117180">"Veze"</string>
-    <string name="wifi_direct_problem" msgid="8995174986718516990">"Zadana usluga ispisa ne može pronaći pisače Izravnog Wi-Fija"</string>
-    <string name="disable_wifi_direct" msgid="4824677957241687577">"Onem. Izravni Wi-Fi"</string>
+    <string name="wifi_direct_problem" msgid="8995174986718516990">"Zadana usluga ispisa ne može pronaći pisače s Wi-Fi Directom"</string>
+    <string name="disable_wifi_direct" msgid="4824677957241687577">"Onemog. Wi-Fi Direct"</string>
     <string name="wifi_direct_permission_rationale" msgid="4671416845852665202">"Zadana usluga za ispis treba dopuštenje za uređaje u blizini da bi pronašla pisače u blizini."</string>
     <string name="fix" msgid="7784394272611365393">"Pregled dopuštenja"</string>
     <string name="print" msgid="7851318072404916362">"Ispis"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index fcd66fa..9adcd50 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"מתבצע חיבור דרך הרשת הנוכחית בכתובת <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"שירות ההדפסה המוגדר כברירת מחדל מספק אפשרויות בסיסיות. ייתכן שאפשרויות נוספות למדפסת הזו יהיו זמינות משירות הדפסה אחר."</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"שירותים מומלצים"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"יש לבחור כדי להתקין"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"כדי להתקין, צריך ללחוץ כאן"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"יש לבחור כדי להפעיל"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"ניהול השירותים"</string>
     <string name="security" msgid="2279008326210305401">"אבטחה"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 6b24f1a..5488555 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -19,7 +19,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="3551052199033657984">"डिफल्ट प्रिन्ट सेवा"</string>
     <string name="printer_busy" msgid="8604311528104955859">"व्यस्त"</string>
-    <string name="printer_out_of_paper" msgid="4882186432807703877">"पाना सकियो"</string>
+    <string name="printer_out_of_paper" msgid="4882186432807703877">"पाना सकिएको"</string>
     <string name="printer_out_of_ink" msgid="7361897651097675464">"मसी सकियो"</string>
     <string name="printer_out_of_toner" msgid="2077516357225364154">"टोनर सकियो"</string>
     <string name="printer_low_on_ink" msgid="3515015872393897705">"प्रिन्टरमा मसी कम छ"</string>
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"<xliff:g id="IP_ADDRESS">%1$s</xliff:g> को हालको नेटवर्कमार्फत जडान गर्छ"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"डिफल्ट छपाइ सेवाले आधारभूत विकल्पहरू प्रदान गर्दछ। यो प्रिन्टरका अन्य विकल्पहरू अन्य छपाइ सेवाबाट उपलब्ध हुन सक्छन्।"</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"सिफारिस गरिएका सेवाहरू"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"स्थापना गर्न चयन गर्नुहोस्"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"इन्स्टल गर्न चयन गर्नुहोस्"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"सक्षम पार्न चयन गर्नुहोस्"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"सेवाहरू व्यवस्थापन गर्नुहोस्"</string>
     <string name="security" msgid="2279008326210305401">"सुरक्षा"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 98c3608..7eebfa6 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -19,7 +19,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="3551052199033657984">"ଡିଫଲ୍ଟ ପ୍ରିଣ୍ଟ ସେବା"</string>
     <string name="printer_busy" msgid="8604311528104955859">"ବ୍ୟସ୍ତ"</string>
-    <string name="printer_out_of_paper" msgid="4882186432807703877">"ପେପର୍‍ ଶେଷ ହୋଇଯାଇଛି"</string>
+    <string name="printer_out_of_paper" msgid="4882186432807703877">"ପେପର ଶେଷ ହୋଇଯାଇଛି"</string>
     <string name="printer_out_of_ink" msgid="7361897651097675464">"ଇଙ୍କ ଶେଷ ହୋଇଯାଇଛି"</string>
     <string name="printer_out_of_toner" msgid="2077516357225364154">"ଟୋନର୍‍ ନାହିଁ"</string>
     <string name="printer_low_on_ink" msgid="3515015872393897705">"ଇଙ୍କ କମ୍‍ ଅଛି"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 4179324..f9e887a 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"A ligação é efetuada através da rede atual em <xliff:g id="IP_ADDRESS">%1$s</xliff:g>."</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"O serviço de impressão padrão fornece opções básicas. Podem estar disponíveis outras opções para esta impressora a partir de outro serviço de impressão."</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"Serviços recomendados"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"Selecione para instalar."</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"Selecione para instalar"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Selecione para ativar."</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"Gerir serviços"</string>
     <string name="security" msgid="2279008326210305401">"Segurança"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index a938e9b..5ce35cf 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -19,7 +19,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="3551052199033657984">"ఆటోమేటిక్ ప్రింట్‌ సర్వీస్"</string>
     <string name="printer_busy" msgid="8604311528104955859">"బిజీగా ఉంది"</string>
-    <string name="printer_out_of_paper" msgid="4882186432807703877">"కాగితం లేదు"</string>
+    <string name="printer_out_of_paper" msgid="4882186432807703877">"పేపర్ లేదు"</string>
     <string name="printer_out_of_ink" msgid="7361897651097675464">"ఇంక్ లేదు"</string>
     <string name="printer_out_of_toner" msgid="2077516357225364154">"టోనర్ లేదు"</string>
     <string name="printer_low_on_ink" msgid="3515015872393897705">"ఇంక్ తక్కువగా ఉంది"</string>
@@ -64,7 +64,7 @@
     <string name="recommendations_heading" msgid="5609754983795588470">"సిఫార్సు చేసిన సర్వీస్‌లు"</string>
     <string name="recommendation_install_summary" msgid="374785283809791669">"ఇన్‌స్టాల్ చేయడానికి ఎంచుకోండి"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"ప్రారంభించడానికి ఎంచుకోండి"</string>
-    <string name="recommendation_manage" msgid="6861960243377871340">"సర్వీస్‌లను మేనేజ్ చేస్తుంది"</string>
+    <string name="recommendation_manage" msgid="6861960243377871340">"సర్వీస్‌లను మేనేజ్ చేయండి"</string>
     <string name="security" msgid="2279008326210305401">"సెక్యూరిటీ"</string>
     <string name="certificate_update_request" msgid="1314796413107139475">"ఈ ప్రింటర్‌కు కొత్త సెక్యూరిటీ సర్టిఫికెట్‌ అందించి ఉండవచ్చు, లేదా వేరే పరికరం ఏదైనా దీన్ని అనుకరిస్తూ ఉండవచ్చు. కొత్త సర్టిఫికెట్‌ను ఆమోదిస్తారా?"</string>
     <string name="not_encrypted_request" msgid="4871472176807381642">"ఈ ప్రింటర్ ఇకపై ఎన్‌క్రిప్ట్ చేసిన ఫైళ్లను తీసుకోదు అయినా ప్రింట్ చేయడాన్ని కొనసాగిస్తారా?"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 2becd42..49e5250 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"Kumokonekta sa pamamagitan ng kasalukuyang network sa <xliff:g id="IP_ADDRESS">%1$s</xliff:g>"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"Nagbibigay ng mga basic na opsyon ang Serbisyo sa Default na Pag-print. Puwedeng available ang ibang opsyon para sa printer na ito sa ibang serbisyo sa pag-print."</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"Mga Inirerekomendang Serbisyo"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"Piliin para ma-install"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"Piliin para i-install"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"Piliin para ma-enable"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"Pamahalaan ang Mga Serbisyo"</string>
     <string name="security" msgid="2279008326210305401">"Seguridad"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 3e23404..ca91d78 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -60,9 +60,9 @@
     <string name="forget" msgid="892068061425802502">"取消保存"</string>
     <string name="connects_via_wifi_direct" msgid="652300632780158437">"通过 WLAN 直连连接"</string>
     <string name="connects_via_network" msgid="5990041581556733898">"在 <xliff:g id="IP_ADDRESS">%1$s</xliff:g> 通过当前网络连接"</string>
-    <string name="recommendation_summary" msgid="2979700524954307566">"默认打印服务会提供基本选项。这个打印机的其他选项可能由其他打印服务提供。"</string>
+    <string name="recommendation_summary" msgid="2979700524954307566">"默认打印服务只提供基本选项。其他打印服务可能为这台打印机提供更多选项。"</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"推荐的服务"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"选择以安装"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"选择即可安装"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"选择以启用"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"管理服务"</string>
     <string name="security" msgid="2279008326210305401">"安全"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 287b1ce..bc0e9ad 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -62,7 +62,7 @@
     <string name="connects_via_network" msgid="5990041581556733898">"透過目前的網絡 (<xliff:g id="IP_ADDRESS">%1$s</xliff:g>) 連線"</string>
     <string name="recommendation_summary" msgid="2979700524954307566">"「預設列印服務」提供基本選項，此打印機的其他選項或可在其他列印服務中使用。"</string>
     <string name="recommendations_heading" msgid="5609754983795588470">"建議的服務"</string>
-    <string name="recommendation_install_summary" msgid="374785283809791669">"選取即可安裝"</string>
+    <string name="recommendation_install_summary" msgid="374785283809791669">"選取以安裝"</string>
     <string name="recommendation_enable_summary" msgid="3500907868251326224">"選取即可啟用"</string>
     <string name="recommendation_manage" msgid="6861960243377871340">"管理服務"</string>
     <string name="security" msgid="2279008326210305401">"安全性"</string>
diff --git a/src/com/android/bips/BuiltInPrintService.java b/src/com/android/bips/BuiltInPrintService.java
index 10432b5..49634ec 100644
--- a/src/com/android/bips/BuiltInPrintService.java
+++ b/src/com/android/bips/BuiltInPrintService.java
@@ -45,11 +45,13 @@ import com.android.bips.discovery.MdnsDiscovery;
 import com.android.bips.discovery.MultiDiscovery;
 import com.android.bips.discovery.NsdResolveQueue;
 import com.android.bips.discovery.P2pDiscovery;
+import com.android.bips.flags.Flags;
 import com.android.bips.ipp.Backend;
 import com.android.bips.ipp.CapabilitiesCache;
 import com.android.bips.ipp.CertificateStore;
 import com.android.bips.p2p.P2pMonitor;
 import com.android.bips.p2p.P2pUtils;
+import com.android.bips.stats.StatsAsyncLogger;
 import com.android.bips.util.BroadcastMonitor;
 
 import java.lang.ref.WeakReference;
@@ -153,6 +155,12 @@ public class BuiltInPrintService extends PrintService {
         unlockWifi();
         sInstance = null;
         mMainHandler.removeCallbacksAndMessages(null);
+        if (Flags.printingTelemetry()) {
+            // Await stats events after main handler callbacks and
+            // messages are removed to reduce risk of waiting too long
+            // while awaiting events.
+            StatsAsyncLogger.INSTANCE.tryAwaitingAllEvents();
+        }
         super.onDestroy();
     }
 
diff --git a/src/com/android/bips/PdfPrintActivity.java b/src/com/android/bips/PdfPrintActivity.java
index 2549779..fa582bc 100644
--- a/src/com/android/bips/PdfPrintActivity.java
+++ b/src/com/android/bips/PdfPrintActivity.java
@@ -160,7 +160,7 @@ public class PdfPrintActivity extends Activity {
      *
      * @return A PrintJobId, can be null
      */
-    static PrintJobId getLastPrintJobId() {
+    public static PrintJobId getLastPrintJobId() {
         return sPrintJobId;
     }
 }
diff --git a/src/com/android/bips/ipp/GetCapabilitiesTask.java b/src/com/android/bips/ipp/GetCapabilitiesTask.java
index 987e917..d72df55 100644
--- a/src/com/android/bips/ipp/GetCapabilitiesTask.java
+++ b/src/com/android/bips/ipp/GetCapabilitiesTask.java
@@ -21,8 +21,10 @@ import android.net.Uri;
 import android.os.AsyncTask;
 import android.util.Log;
 
+import com.android.bips.flags.Flags;
 import com.android.bips.jni.BackendConstants;
 import com.android.bips.jni.LocalPrinterCapabilities;
+import com.android.bips.stats.StatsAsyncLogger;
 import com.android.bips.util.PriorityLock;
 
 import java.io.IOException;
@@ -123,6 +125,11 @@ public class GetCapabilitiesTask extends AsyncTask<Void, Void, LocalPrinterCapab
                     + " (" + (System.currentTimeMillis() - start) + "ms)");
         }
 
+        if (Flags.printingTelemetry()) {
+            final Boolean isSecure = mUri.getScheme().equals("ipps");
+            StatsAsyncLogger.INSTANCE.RequestPrinterCapabilitiesStatus(status, isSecure);
+        }
+
         return status == BackendConstants.STATUS_OK ? printerCaps : null;
     }
 }
diff --git a/src/com/android/bips/ipp/StartJobTask.java b/src/com/android/bips/ipp/StartJobTask.java
index fbdd8e2..d5111b2 100644
--- a/src/com/android/bips/ipp/StartJobTask.java
+++ b/src/com/android/bips/ipp/StartJobTask.java
@@ -37,20 +37,23 @@ import android.util.Log;
 import android.view.Gravity;
 
 import com.android.bips.ImagePrintActivity;
+import com.android.bips.PdfPrintActivity;
+import com.android.bips.flags.Flags;
 import com.android.bips.jni.BackendConstants;
 import com.android.bips.jni.LocalJobParams;
 import com.android.bips.jni.LocalPrinterCapabilities;
 import com.android.bips.jni.MediaSizes;
 import com.android.bips.jni.PdfRender;
 import com.android.bips.jni.SizeD;
+import com.android.bips.stats.StatsAsyncLogger;
 import com.android.bips.util.FileUtils;
 
 import java.io.BufferedOutputStream;
 import java.io.File;
 import java.io.FileOutputStream;
 import java.io.IOException;
-import java.util.Objects;
 import java.nio.ByteBuffer;
+import java.util.Objects;
 
 /**
  * A background task that starts sending a print job. The result of this task is an integer
@@ -206,6 +209,44 @@ class StartJobTask extends AsyncTask<Void, Void, Integer> {
             // Finalize job parameters
             mBackend.nativeGetFinalJobParameters(mJobParams, mCapabilities);
 
+            if (Flags.printingTelemetry()) {
+                // Convert back to framework duplex mode. See StartJobtask.getSides()
+                int frameworkDuplex = -1;
+                switch (getSides()) {
+                    case SIDES_SIMPLEX:
+                        frameworkDuplex = PrintAttributes.DUPLEX_MODE_NONE;
+                        break;
+                    case SIDES_DUPLEX_LONG_EDGE:
+                        frameworkDuplex = PrintAttributes.DUPLEX_MODE_LONG_EDGE;
+                        break;
+                    case SIDES_DUPLEX_SHORT_EDGE:
+                        frameworkDuplex = PrintAttributes.DUPLEX_MODE_SHORT_EDGE;
+                        break;
+                    default:
+                        // The above cases should catch every one.
+                        Log.e(TAG, "getSides() returned an unrecognized duplex mode");
+                }
+                StatsAsyncLogger.JobOrigin origin;
+                if (isSharedPhoto()) {
+                    origin = StatsAsyncLogger.JobOrigin.SHARED_IMAGE;
+                } else if (isSharedPdf()) {
+                    origin = StatsAsyncLogger.JobOrigin.SHARED_PDF;
+                } else {
+                    origin = StatsAsyncLogger.JobOrigin.DIRECT_PRINT;
+                }
+                final Boolean isSecure = mDestination.getScheme().equals("ipps");
+
+                StatsAsyncLogger.INSTANCE.PrintJob(mCapabilities.makeAndModel,
+                                                   isSecure,
+                                                   origin,
+                                                   result,
+                                                   mJobInfo,
+                                                   mDocInfo,
+                                                   isBorderless(),
+                                                   frameworkDuplex,
+                                                   getMediaType());
+            }
+
             if (isCancelled()) {
                 return Backend.ERROR_CANCEL;
             }
@@ -384,4 +425,8 @@ class StartJobTask extends AsyncTask<Void, Void, Integer> {
     private boolean isSharedPhoto() {
         return Objects.equals(mJobInfo.getId(), ImagePrintActivity.getLastPrintJobId());
     }
+
+    private boolean isSharedPdf() {
+        return Objects.equals(mJobInfo.getId(), PdfPrintActivity.getLastPrintJobId());
+    }
 }
diff --git a/src/com/android/bips/jni/LocalPrinterCapabilities.java b/src/com/android/bips/jni/LocalPrinterCapabilities.java
index 17b0f22..ebb95fd 100644
--- a/src/com/android/bips/jni/LocalPrinterCapabilities.java
+++ b/src/com/android/bips/jni/LocalPrinterCapabilities.java
@@ -37,6 +37,7 @@ public class LocalPrinterCapabilities {
     public String name;
     public String uuid;
     public String location;
+    public String makeAndModel;
 
     public boolean duplex;
     public boolean borderless;
diff --git a/src/com/android/bips/jni/PrinterStatusMonitor.kt b/src/com/android/bips/jni/PrinterStatusMonitor.kt
index b96bd6b..ad9f17f 100644
--- a/src/com/android/bips/jni/PrinterStatusMonitor.kt
+++ b/src/com/android/bips/jni/PrinterStatusMonitor.kt
@@ -22,15 +22,20 @@ import com.android.bips.BuiltInPrintService
 import com.android.bips.ipp.Backend
 
 class PrinterStatusMonitor(
-    path: Uri, service: BuiltInPrintService,
-    private val onPrinterStatus: (JobCallbackParams) -> Unit
+    path: Uri,
+    service: BuiltInPrintService,
+    private val onPrinterStatus: (JobCallbackParams) -> Unit,
 ) {
     private val statusId: Long
+
     init {
-        statusId = service.backend.nativeMonitorStatusSetup(
-            Backend.getIp(path.host),
-            path.port, path.path, path.scheme
-        )
+        statusId =
+            service.backend.nativeMonitorStatusSetup(
+                Backend.getIp(path.host),
+                path.port,
+                path.path,
+                path.scheme,
+            )
         if (statusId != 0L) {
             service.backend.nativeMonitorStatusStart(statusId, this)
         }
@@ -40,10 +45,8 @@ class PrinterStatusMonitor(
         service.backend.nativeMonitorStatusStop(statusId)
     }
 
-    /**
-     * This method is calling from JNI layer
-     */
+    /** This method is calling from JNI layer */
     private fun callbackReceiver(status: JobCallbackParams) {
         onPrinterStatus(status)
     }
-}
\ No newline at end of file
+}
diff --git a/src/com/android/bips/stats/StatsAsyncLogger.kt b/src/com/android/bips/stats/StatsAsyncLogger.kt
new file mode 100644
index 0000000..d066eed
--- /dev/null
+++ b/src/com/android/bips/stats/StatsAsyncLogger.kt
@@ -0,0 +1,465 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.bips.stats
+
+import android.os.Handler
+import android.os.HandlerThread
+import android.os.SystemClock
+import android.print.PageRange
+import android.print.PrintAttributes
+import android.print.PrintDocumentInfo
+import android.print.PrintJobInfo
+import android.util.Log
+import androidx.annotation.VisibleForTesting
+import java.util.concurrent.Semaphore
+import java.util.concurrent.TimeUnit
+import kotlin.math.max
+import kotlin.time.Duration
+import kotlin.time.Duration.Companion.milliseconds
+
+object StatsAsyncLogger {
+
+    enum class JobOrigin(val code: Int) {
+        SHARED_IMAGE(BipsStatsLog.BIPS_PRINT_JOB__JOB_ORIGIN__BIPS_JOB_ORIGIN_SHARED_IMAGE),
+        SHARED_PDF(BipsStatsLog.BIPS_PRINT_JOB__JOB_ORIGIN__BIPS_JOB_ORIGIN_SHARED_PDF),
+        DIRECT_PRINT(BipsStatsLog.BIPS_PRINT_JOB__JOB_ORIGIN__BIPS_JOB_ORIGIN_DIRECT_PRINT),
+    }
+
+    private val TAG = StatsAsyncLogger::class.java.simpleName
+    private val DEBUG = false
+
+    @VisibleForTesting val EVENT_REPORTED_MIN_INTERVAL: Duration = 10.milliseconds
+    private val MAX_EVENT_QUEUE = 150
+
+    // Only var for testing purposes
+    private var semaphore = Semaphore(MAX_EVENT_QUEUE)
+    // We must call start() before getting the HandlerThread's looper.
+    // NOTE: We never quit() this HandlerThread because we want this
+    // running for the lifetime of the process.
+    private val handlerThread = HandlerThread("StatsEventLoggerWrapper").also { it.start() }
+    private var eventHandler = Handler(handlerThread.getLooper())
+    private var nextAvailableTimeMillis = SystemClock.uptimeMillis()
+    private var statsLogWrapper = StatsLogWrapper()
+
+    @VisibleForTesting
+    fun testSetStatsLogWrapper(wrapper: StatsLogWrapper) {
+        statsLogWrapper = wrapper
+    }
+
+    @VisibleForTesting
+    fun testSetSemaphore(s: Semaphore) {
+        semaphore = s
+    }
+
+    @VisibleForTesting
+    fun testSetHandler(handler: Handler) {
+        eventHandler = handler
+    }
+
+    fun PrintJob(
+        makeAndModel: String,
+        secure: Boolean,
+        jobOrigin: JobOrigin,
+        localJobRawResult: Int,
+        jobInfo: PrintJobInfo,
+        docInfo: PrintDocumentInfo,
+        borderless: Boolean,
+        duplexMode: Int,
+        localMediaType: Int,
+    ): Boolean {
+        if (DEBUG) {
+            Log.d(TAG, "Logging PrintJob event")
+        }
+
+        synchronized(semaphore) {
+            if (!semaphore.tryAcquire()) {
+                Log.w(TAG, "Logging too many events, dropping PrintJob event")
+                return false
+            }
+            val pageCount =
+                // pageRange.getSize() is hidden so this is essentially copied from framework
+                jobInfo.getPages()?.sumOf { pageRange: PageRange ->
+                    (pageRange.getEnd() - pageRange.getStart() + 1)
+                } ?: 0
+            val result =
+                eventHandler.postAtTime(
+                    Runnable {
+                        synchronized(semaphore) {
+                            statsLogWrapper.internalPrintJob(
+                                makeAndModel,
+                                jobOrigin.code,
+                                localPrintJobResultMap.getOrDefault(
+                                    localJobRawResult,
+                                    BipsStatsLog
+                                        .BIPS_PRINT_JOB__RESULT__BIPS_PRINT_JOB_RESULT_UNSPECIFIED,
+                                ),
+                                borderless,
+                                frameworkMediaSizeMap.getOrDefault(
+                                    jobInfo.getAttributes().getMediaSize()?.getId(),
+                                    BipsStatsLog
+                                        .BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_UNSPECIFIED,
+                                ),
+                                duplexModeMap.getOrDefault(
+                                    duplexMode,
+                                    BipsStatsLog
+                                        .BIPS_PRINT_JOB__DUPLEX_MODE__FRAMEWORK_DUPLEX_MODE_UNSPECIFIED,
+                                ),
+                                localMediaTypeMap.getOrDefault(
+                                    localMediaType,
+                                    BipsStatsLog
+                                        .BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_UNSPECIFIED,
+                                ),
+                                frameworkColorModeMap.getOrDefault(
+                                    jobInfo.getAttributes().getColorMode(),
+                                    BipsStatsLog
+                                        .BIPS_PRINT_JOB__COLOR__FRAMEWORK_COLOR_MODE_UNSPECIFIED,
+                                ),
+                                secure,
+                                jobInfo.getAttributes().getResolution()?.getHorizontalDpi() ?: 0,
+                                jobInfo.getAttributes().getResolution()?.getVerticalDpi() ?: 0,
+                                pageCount,
+                            )
+                            semaphore.release()
+                        }
+                    },
+                    nextAvailableTimeMillis,
+                )
+            if (!result) {
+                Log.e(TAG, "Could not log PrintJob event")
+                semaphore.release()
+                return false
+            }
+            nextAvailableTimeMillis = getNextAvailableTimeMillis()
+        }
+        return true
+    }
+
+    // Returns true if event is now pending to be logged, false otherwise
+    fun RequestPrinterCapabilitiesStatus(getLocalCapsStatus: Int, secure: Boolean): Boolean {
+        if (DEBUG) {
+            Log.d(TAG, "Logging RequestPrinterCapabilitiesStatus event")
+        }
+        synchronized(semaphore) {
+            if (!semaphore.tryAcquire()) {
+                Log.w(
+                    TAG,
+                    "Logging too many events, dropping RequestPrinterCapabilitiesStatus event",
+                )
+                return false
+            }
+            val result =
+                eventHandler.postAtTime(
+                    Runnable {
+                        synchronized(semaphore) {
+                            if (DEBUG) {
+                                Log.d(TAG, "Async logging RequestPrinterCapabilitiesStatus event")
+                            }
+                            statsLogWrapper.internalRequestPrinterCapabilitiesStatus(
+                                getLocalCapsStatus,
+                                secure,
+                            )
+                            semaphore.release()
+                        }
+                    },
+                    nextAvailableTimeMillis,
+                )
+            if (!result) {
+                Log.e(TAG, "Could not log RequestPrinterCapabilitiesStatus event")
+                semaphore.release()
+                return false
+            }
+            nextAvailableTimeMillis = getNextAvailableTimeMillis()
+        }
+        return true
+    }
+
+    private fun getNextAvailableTimeMillis(): Long {
+        return max(
+            // Handles back to back records
+            nextAvailableTimeMillis + EVENT_REPORTED_MIN_INTERVAL.inWholeMilliseconds,
+            // Updates next time to more recent value if it wasn't recently
+            SystemClock.uptimeMillis() + EVENT_REPORTED_MIN_INTERVAL.inWholeMilliseconds,
+        )
+    }
+
+    // Returns true if successfully awaited all pending events, false otherwise
+    fun tryAwaitingAllEvents(): Boolean {
+        if (DEBUG) {
+            Log.d(TAG, "Begin flushing events")
+        }
+        val acquired =
+            semaphore.tryAcquire(
+                MAX_EVENT_QUEUE,
+                MAX_EVENT_QUEUE * EVENT_REPORTED_MIN_INTERVAL.inWholeMilliseconds,
+                TimeUnit.MILLISECONDS,
+            )
+        if (!acquired) {
+            Log.w(TAG, "Time exceeded awaiting stats events")
+            return false
+        }
+        if (DEBUG) {
+            Log.d(TAG, "End flushing events")
+        }
+        return true
+    }
+
+    // Mappings for internal values to associated proto values.
+
+    private val frameworkMediaSizeMap =
+        // Keep this up to date to map any new media sizes in the framework
+        mapOf(
+            PrintAttributes.MediaSize.UNKNOWN_PORTRAIT.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_UNKNOWN_PORTRAIT,
+            PrintAttributes.MediaSize.UNKNOWN_LANDSCAPE.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_UNKNOWN_LANDSCAPE,
+            PrintAttributes.MediaSize.ISO_A0.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A0,
+            PrintAttributes.MediaSize.ISO_A1.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A1,
+            PrintAttributes.MediaSize.ISO_A2.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A2,
+            PrintAttributes.MediaSize.ISO_A3.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A3,
+            PrintAttributes.MediaSize.ISO_A4.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A4,
+            PrintAttributes.MediaSize.ISO_A5.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A5,
+            PrintAttributes.MediaSize.ISO_A6.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A6,
+            PrintAttributes.MediaSize.ISO_A7.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A7,
+            PrintAttributes.MediaSize.ISO_A8.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A8,
+            PrintAttributes.MediaSize.ISO_A9.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A9,
+            PrintAttributes.MediaSize.ISO_A10.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_A10,
+            PrintAttributes.MediaSize.ISO_B0.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B0,
+            PrintAttributes.MediaSize.ISO_B1.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B1,
+            PrintAttributes.MediaSize.ISO_B2.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B2,
+            PrintAttributes.MediaSize.ISO_B3.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B3,
+            PrintAttributes.MediaSize.ISO_B4.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B4,
+            PrintAttributes.MediaSize.ISO_B5.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B5,
+            PrintAttributes.MediaSize.ISO_B6.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B6,
+            PrintAttributes.MediaSize.ISO_B7.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B7,
+            PrintAttributes.MediaSize.ISO_B8.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B8,
+            PrintAttributes.MediaSize.ISO_B9.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B9,
+            PrintAttributes.MediaSize.ISO_B10.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_B10,
+            PrintAttributes.MediaSize.ISO_C0.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C0,
+            PrintAttributes.MediaSize.ISO_C1.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C1,
+            PrintAttributes.MediaSize.ISO_C2.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C2,
+            PrintAttributes.MediaSize.ISO_C3.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C3,
+            PrintAttributes.MediaSize.ISO_C4.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C4,
+            PrintAttributes.MediaSize.ISO_C5.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C5,
+            PrintAttributes.MediaSize.ISO_C6.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C6,
+            PrintAttributes.MediaSize.ISO_C7.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C7,
+            PrintAttributes.MediaSize.ISO_C8.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C8,
+            PrintAttributes.MediaSize.ISO_C9.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C9,
+            PrintAttributes.MediaSize.ISO_C10.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ISO_C10,
+            PrintAttributes.MediaSize.NA_LETTER.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_LETTER,
+            PrintAttributes.MediaSize.NA_GOVT_LETTER.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_GOVT_LETTER,
+            PrintAttributes.MediaSize.NA_LEGAL.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_LEGAL,
+            PrintAttributes.MediaSize.NA_JUNIOR_LEGAL.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_JUNIOR_LEGAL,
+            PrintAttributes.MediaSize.NA_LEDGER.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_LEDGER,
+            PrintAttributes.MediaSize.NA_TABLOID.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_TABLOID,
+            PrintAttributes.MediaSize.NA_INDEX_3X5.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_INDEX_3X5,
+            PrintAttributes.MediaSize.NA_INDEX_4X6.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_INDEX_4X6,
+            PrintAttributes.MediaSize.NA_INDEX_5X8.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_INDEX_5X8,
+            PrintAttributes.MediaSize.NA_MONARCH.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_MONARCH,
+            PrintAttributes.MediaSize.NA_QUARTO.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_QUARTO,
+            PrintAttributes.MediaSize.NA_FOOLSCAP.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_FOOLSCAP,
+            PrintAttributes.MediaSize.ANSI_C.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ANSI_C,
+            PrintAttributes.MediaSize.ANSI_D.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ANSI_D,
+            PrintAttributes.MediaSize.ANSI_E.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ANSI_E,
+            PrintAttributes.MediaSize.ANSI_F.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ANSI_F,
+            PrintAttributes.MediaSize.NA_ARCH_A.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_ARCH_A,
+            PrintAttributes.MediaSize.NA_ARCH_B.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_ARCH_B,
+            PrintAttributes.MediaSize.NA_ARCH_C.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_ARCH_C,
+            PrintAttributes.MediaSize.NA_ARCH_D.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_ARCH_D,
+            PrintAttributes.MediaSize.NA_ARCH_E.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_ARCH_E,
+            PrintAttributes.MediaSize.NA_ARCH_E1.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_ARCH_E1,
+            PrintAttributes.MediaSize.NA_SUPER_B.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_NA_SUPER_B,
+            PrintAttributes.MediaSize.ROC_8K.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ROC_8K,
+            PrintAttributes.MediaSize.ROC_16K.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_ROC_16K,
+            PrintAttributes.MediaSize.PRC_1.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_1,
+            PrintAttributes.MediaSize.PRC_2.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_2,
+            PrintAttributes.MediaSize.PRC_3.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_3,
+            PrintAttributes.MediaSize.PRC_4.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_4,
+            PrintAttributes.MediaSize.PRC_5.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_5,
+            PrintAttributes.MediaSize.PRC_6.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_6,
+            PrintAttributes.MediaSize.PRC_7.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_7,
+            PrintAttributes.MediaSize.PRC_8.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_8,
+            PrintAttributes.MediaSize.PRC_9.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_9,
+            PrintAttributes.MediaSize.PRC_10.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_10,
+            PrintAttributes.MediaSize.PRC_16K.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_PRC_16K,
+            PrintAttributes.MediaSize.OM_PA_KAI.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_OM_PA_KAI,
+            PrintAttributes.MediaSize.OM_DAI_PA_KAI.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_OM_DAI_PA_KAI,
+            PrintAttributes.MediaSize.OM_JUURO_KU_KAI.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_OM_JUURO_KU_KAI,
+            PrintAttributes.MediaSize.JIS_B10.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B10,
+            PrintAttributes.MediaSize.JIS_B9.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B9,
+            PrintAttributes.MediaSize.JIS_B8.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B8,
+            PrintAttributes.MediaSize.JIS_B7.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B7,
+            PrintAttributes.MediaSize.JIS_B6.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B6,
+            PrintAttributes.MediaSize.JIS_B5.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B5,
+            PrintAttributes.MediaSize.JIS_B4.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B4,
+            PrintAttributes.MediaSize.JIS_B3.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B3,
+            PrintAttributes.MediaSize.JIS_B2.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B2,
+            PrintAttributes.MediaSize.JIS_B1.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B1,
+            PrintAttributes.MediaSize.JIS_B0.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_B0,
+            PrintAttributes.MediaSize.JIS_EXEC.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JIS_EXEC,
+            PrintAttributes.MediaSize.JPN_CHOU4.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JPN_CHOU4,
+            PrintAttributes.MediaSize.JPN_CHOU3.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JPN_CHOU3,
+            PrintAttributes.MediaSize.JPN_CHOU2.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JPN_CHOU2,
+            PrintAttributes.MediaSize.JPN_HAGAKI.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JPN_HAGAKI,
+            PrintAttributes.MediaSize.JPN_OUFUKU.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JPN_OUFUKU,
+            PrintAttributes.MediaSize.JPN_KAHU.getId() to
+                BipsStatsLog.BIPS_PRINT_JOB__SIZE__FRAMEWORK_MEDIA_SIZE_JPN_KAHU,
+        )
+
+    private val localMediaTypeMap =
+        mapOf(
+            // These keys are defined in jni/include/wprint_df_types.h
+            0 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_PLAIN,
+            1 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_SPECIAL,
+            2 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_PHOTO,
+            3 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_TRANSPARENCY,
+            4 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_IRON_ON,
+            5 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_IRON_ON_MIRROR,
+            6 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_ADVANCED_PHOTO,
+            7 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_FAST_TRANSPARENCY,
+            8 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_BROCHURE_GLOSSY,
+            9 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_BROCHURE_MATTE,
+            10 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_PHOTO_GLOSSY,
+            11 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_PHOTO_MATTE,
+            12 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_PREMIUM_PHOTO,
+            13 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_OTHER_PHOTO,
+            14 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_PRINTABLE_CD,
+            15 to
+                BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_PREMIUM_PRESENTATION,
+            // New types above this line
+            98 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_AUTO,
+            99 to BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_UNKNOWN,
+        )
+
+    private val frameworkColorModeMap =
+        // Keep this up to date to map any new color modes in the framework
+        mapOf(
+            PrintAttributes.COLOR_MODE_COLOR to
+                BipsStatsLog.BIPS_PRINT_JOB__COLOR__FRAMEWORK_COLOR_MODE_COLOR,
+            PrintAttributes.COLOR_MODE_MONOCHROME to
+                BipsStatsLog.BIPS_PRINT_JOB__COLOR__FRAMEWORK_COLOR_MODE_MONOCRHOME,
+        )
+
+    private val duplexModeMap =
+        // Keep this up to date to map any new duplex modes in the framework
+        mapOf(
+            PrintAttributes.DUPLEX_MODE_LONG_EDGE to
+                BipsStatsLog.BIPS_PRINT_JOB__DUPLEX_MODE__FRAMEWORK_DUPLEX_MODE_LONG_EDGE,
+            PrintAttributes.DUPLEX_MODE_SHORT_EDGE to
+                BipsStatsLog.BIPS_PRINT_JOB__DUPLEX_MODE__FRAMEWORK_DUPLEX_MODE_SHORT_EDGE,
+            PrintAttributes.DUPLEX_MODE_NONE to
+                BipsStatsLog.BIPS_PRINT_JOB__DUPLEX_MODE__FRAMEWORK_DUPLEX_MODE_NONE,
+        )
+
+    private val localPrintJobResultMap =
+        // These keys are defined in jni/include/wtypes.h
+        mapOf(
+            0 to BipsStatsLog.BIPS_PRINT_JOB__RESULT__BIPS_PRINT_JOB_RESULT_COMPLETED,
+            -2 to BipsStatsLog.BIPS_PRINT_JOB__RESULT__BIPS_PRINT_JOB_RESULT_CANCELLED,
+            -3 to BipsStatsLog.BIPS_PRINT_JOB__RESULT__BIPS_PRINT_JOB_RESULT_FAILED_CORRUPT,
+            -4 to BipsStatsLog.BIPS_PRINT_JOB__RESULT__BIPS_PRINT_JOB_RESULT_FAILED_CERTIFICATE,
+            -1 to BipsStatsLog.BIPS_PRINT_JOB__RESULT__BIPS_PRINT_JOB_RESULT_FAILED_UNKNOWN,
+        )
+}
diff --git a/src/com/android/bips/stats/StatsLogWrapper.kt b/src/com/android/bips/stats/StatsLogWrapper.kt
new file mode 100644
index 0000000..b77ae2c
--- /dev/null
+++ b/src/com/android/bips/stats/StatsLogWrapper.kt
@@ -0,0 +1,67 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.bips.stats
+
+// Thin wrapper around the generated atom logger for dependency
+// injection and testability
+
+// Kotlin does not offer package-private visibility modifier.
+// Clients outside of the package should use StatsAsyncLogger instead.
+
+// Not intended to be subclassed, left "open" for mocking.  internal
+// modifier isn't used as it doesn't play nice with @VisibleForTesting
+// annotation within package clients.
+open class StatsLogWrapper {
+    open fun internalRequestPrinterCapabilitiesStatus(getLocalCapsStatus: Int, secure: Boolean) {
+        BipsStatsLog.write(
+            BipsStatsLog.BIPS_REQUEST_PRINTER_CAPABILITIES_STATUS,
+            getLocalCapsStatus,
+            secure,
+        )
+    }
+
+    open fun internalPrintJob(
+        makeAndModel: String,
+        jobOrigin: Int,
+        result: Int,
+        borderless: Boolean,
+        size: Int,
+        duplexMode: Int,
+        mediaType: Int,
+        color: Int,
+        secure: Boolean,
+        horizontalDpi: Int,
+        verticalDpi: Int,
+        pageCount: Int,
+    ) {
+        BipsStatsLog.write(
+            BipsStatsLog.BIPS_PRINT_JOB,
+            makeAndModel,
+            jobOrigin,
+            result,
+            borderless,
+            size,
+            duplexMode,
+            mediaType,
+            color,
+            secure,
+            horizontalDpi,
+            verticalDpi,
+            pageCount,
+        )
+    }
+}
diff --git a/src/com/android/bips/ui/MarkerAdapter.kt b/src/com/android/bips/ui/MarkerAdapter.kt
index 90f2f19..7d43bfe 100644
--- a/src/com/android/bips/ui/MarkerAdapter.kt
+++ b/src/com/android/bips/ui/MarkerAdapter.kt
@@ -39,10 +39,10 @@ import com.android.bips.R
  */
 class MarkerAdapter(private val mMarkerInfoList: ArrayList<MarkerInfo>) :
     RecyclerView.Adapter<MarkerAdapter.MarkerViewHolder>() {
-        inner class MarkerViewHolder(val view: View) : RecyclerView.ViewHolder(view) {
-            var seekbar: ProgressBar = itemView.findViewById(R.id.seekbar)
-            var warningImage: ImageView = itemView.findViewById(R.id.warningImage)
-        }
+    inner class MarkerViewHolder(val view: View) : RecyclerView.ViewHolder(view) {
+        var seekbar: ProgressBar = itemView.findViewById(R.id.seekbar)
+        var warningImage: ImageView = itemView.findViewById(R.id.warningImage)
+    }
 
     override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MarkerViewHolder {
         val v =
@@ -57,12 +57,12 @@ class MarkerAdapter(private val mMarkerInfoList: ArrayList<MarkerInfo>) :
             progressBarDrawable.getDrawable(0).colorFilter =
                 BlendModeColorFilterCompat.createBlendModeColorFilterCompat(
                     Color.parseColor(BACKGROUND_COLOR),
-                    BlendModeCompat.SRC_IN
+                    BlendModeCompat.SRC_IN,
                 )
             progressBarDrawable.getDrawable(1).colorFilter =
                 BlendModeColorFilterCompat.createBlendModeColorFilterCompat(
                     Color.parseColor(markerColor),
-                    BlendModeCompat.SRC_IN
+                    BlendModeCompat.SRC_IN,
                 )
             // Set progress level on a scale of 0-10000
             progressBarDrawable.getDrawable(1).level =
@@ -77,6 +77,49 @@ class MarkerAdapter(private val mMarkerInfoList: ArrayList<MarkerInfo>) :
             } else {
                 holder.warningImage.visibility = View.INVISIBLE
             }
+
+            // Marker level rounded down to the nearest int.  This goes all the
+            // way to 0 instead of stopping at 1 because we do not need to leave
+            // any visual indicator of the color.
+            val level: Int =
+                if (markerHighLevel != 0 && markerLevel > 0) {
+                    markerLevel * 100 / markerHighLevel
+                } else {
+                    0 // set 0% for unknown
+                }
+
+            // Map common colors to human-friendly names.  Everything else has a fallback to
+            // declaring the underying color value.
+            val color = Color.parseColor(markerColor)
+            val label =
+                when (color) {
+                    Color.BLACK -> holder.view.context.getString(R.string.marker_level_black, level)
+                    Color.CYAN -> holder.view.context.getString(R.string.marker_level_cyan, level)
+                    Color.MAGENTA ->
+                        holder.view.context.getString(R.string.marker_level_magenta, level)
+                    Color.YELLOW ->
+                        holder.view.context.getString(R.string.marker_level_yellow, level)
+                    Color.RED -> holder.view.context.getString(R.string.marker_level_red, level)
+                    Color.GREEN -> holder.view.context.getString(R.string.marker_level_green, level)
+                    Color.BLUE -> holder.view.context.getString(R.string.marker_level_blue, level)
+                    Color.LTGRAY ->
+                        holder.view.context.getString(R.string.marker_level_ltgray, level)
+                    Color.DKGRAY ->
+                        holder.view.context.getString(R.string.marker_level_dkgray, level)
+                    LTCYAN -> holder.view.context.getString(R.string.marker_level_ltcyan, level)
+                    LTMAGENTA ->
+                        holder.view.context.getString(R.string.marker_level_ltmagenta, level)
+                    VIOLET -> holder.view.context.getString(R.string.marker_level_violet, level)
+                    else ->
+                        holder.view.context.getString(
+                            R.string.marker_level_custom,
+                            Color.red(color),
+                            Color.green(color),
+                            Color.blue(color),
+                            level,
+                        )
+                }
+            holder.view.contentDescription = label
         }
     }
 
@@ -87,5 +130,14 @@ class MarkerAdapter(private val mMarkerInfoList: ArrayList<MarkerInfo>) :
     companion object {
         /** Seekbar background */
         private const val BACKGROUND_COLOR = "#898383"
+
+        /** Ink color for light cyan */
+        private const val LTCYAN = 0x7FFFFF
+
+        /** Ink color for light magenta */
+        private const val LTMAGENTA = 0xFF7FFF
+
+        /** Ink color for violet */
+        private const val VIOLET = 0x7F00FF
     }
-}
\ No newline at end of file
+}
diff --git a/src/com/android/bips/ui/MarkerInfo.kt b/src/com/android/bips/ui/MarkerInfo.kt
index 25f1c05..8385e31 100644
--- a/src/com/android/bips/ui/MarkerInfo.kt
+++ b/src/com/android/bips/ui/MarkerInfo.kt
@@ -17,17 +17,11 @@
 
 package com.android.bips.ui
 
-/**
- * Marker info class for showing printer supply levels
- */
+/** Marker info class for showing printer supply levels */
 data class MarkerInfo(
     val markerType: String,
-
     val markerColor: String,
-
     val markerHighLevel: Int,
-
     val markerLowLevel: Int,
-
-    val markerLevel: Int
-)
\ No newline at end of file
+    val markerLevel: Int,
+)
diff --git a/src/com/android/bips/ui/PrinterInformationFragment.kt b/src/com/android/bips/ui/PrinterInformationFragment.kt
index bcce538..25f8481 100644
--- a/src/com/android/bips/ui/PrinterInformationFragment.kt
+++ b/src/com/android/bips/ui/PrinterInformationFragment.kt
@@ -39,9 +39,7 @@ import com.android.bips.jni.LocalPrinterCapabilities
 import com.android.bips.jni.MediaSizes
 import java.util.*
 
-/**
- * Printer information fragment
- */
+/** Printer information fragment */
 class PrinterInformationFragment : Fragment() {
 
     /** Printer Information view model */
@@ -60,10 +58,9 @@ class PrinterInformationFragment : Fragment() {
     override fun onCreateView(
         inflater: LayoutInflater,
         container: ViewGroup?,
-        savedInstanceState: Bundle?
+        savedInstanceState: Bundle?,
     ): View {
-        return inflater.inflate(R.layout.printer_information,
-            container, false)
+        return inflater.inflate(R.layout.printer_information, container, false)
     }
 
     override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
@@ -93,9 +90,7 @@ class PrinterInformationFragment : Fragment() {
                     setMarkerView(caps)
                     view.visibility = View.VISIBLE
                     printerName.text = caps.name
-                } ?: run {
-                    view.visibility = View.GONE
-                }
+                } ?: run { view.visibility = View.GONE }
             }
         }
     }
@@ -108,14 +103,14 @@ class PrinterInformationFragment : Fragment() {
                 mediaReadyLabel.visibility = View.GONE
             }
             for (i in mediaReadySizes) {
-                mediaReadyString += MediaSizes.getInstance(context)
-                    .getMediaName(i, context) + "\n"
+                mediaReadyString += MediaSizes.getInstance(context).getMediaName(i, context) + "\n"
             }
             mediaReady.text = mediaReadyString.dropLast(1)
-        } ?: run {
-            mediaReady.visibility = View.GONE
-            mediaReadyLabel.visibility = View.GONE
         }
+            ?: run {
+                mediaReady.visibility = View.GONE
+                mediaReadyLabel.visibility = View.GONE
+            }
     }
 
     private fun getIconBitmap(caps: LocalPrinterCapabilities) {
@@ -127,57 +122,57 @@ class PrinterInformationFragment : Fragment() {
     }
 
     private fun setPrinterImage(fragmentActivity: FragmentActivity) {
-        printerInformationViewModel.value.getPrinterBitmapLiveData()
-            .observe(fragmentActivity) { printerImage ->
-                if (printerImage != null) {
-                    printerIcon.visibility = View.VISIBLE
-                    printerIcon.setImageBitmap(printerImage)
-                } else {
-                    printerIcon.visibility = View.GONE
-                }
+        printerInformationViewModel.value.getPrinterBitmapLiveData().observe(fragmentActivity) {
+            printerImage ->
+            if (printerImage != null) {
+                printerIcon.visibility = View.VISIBLE
+                printerIcon.setImageBitmap(printerImage)
+            } else {
+                printerIcon.visibility = View.GONE
             }
+        }
     }
 
-    /**
-     * Set Status Of Printer
-     */
+    /** Set Status Of Printer */
     private fun setPrinterStatus(fragmentActivity: FragmentActivity) {
-        printerInformationViewModel.value.getPrinterUnavailableLiveData()
-            .observe(fragmentActivity) {
-                if (it) printerStatusLayout.visibility = View.GONE
-            }
-        printerInformationViewModel.value.getPrinterStatusLiveData()
-            .observe(fragmentActivity) { callbackParams ->
-                callbackParams.apply {
-                    val reasonsList = blockedReasons?.toList() ?: emptyList()
-                    val statusList = getPrinterStatus(printerState, reasonsList)
-                    if (statusList.isEmpty()) {
-                        printerStatusLayout.visibility = View.GONE
-                    } else {
-                        if (DEBUG) {
-                            Log.e(TAG, "printer status list ${TextUtils.join("\n", statusList)}")
-                        }
-                        printerStatus.text = TextUtils.join("\n", statusList)
-                        printerStatusLayout.visibility = View.VISIBLE
-                        printerStatus.visibility = View.VISIBLE
-                        progressBarPrinterStatus.visibility = View.GONE
+        printerInformationViewModel.value.getPrinterUnavailableLiveData().observe(
+            fragmentActivity
+        ) {
+            if (it) printerStatusLayout.visibility = View.GONE
+        }
+        printerInformationViewModel.value.getPrinterStatusLiveData().observe(fragmentActivity) {
+            callbackParams ->
+            callbackParams.apply {
+                val reasonsList = blockedReasons?.toList() ?: emptyList()
+                val statusList = getPrinterStatus(printerState, reasonsList)
+                if (statusList.isEmpty()) {
+                    printerStatusLayout.visibility = View.GONE
+                } else {
+                    if (DEBUG) {
+                        Log.e(TAG, "printer status list ${TextUtils.join("\n", statusList)}")
                     }
+                    printerStatus.text = TextUtils.join("\n", statusList)
+                    printerStatusLayout.visibility = View.VISIBLE
+                    printerStatus.visibility = View.VISIBLE
+                    progressBarPrinterStatus.visibility = View.GONE
                 }
             }
+        }
     }
 
     /**
-     * Maps the printer state and reasons into a list of status strings
-     * If the printerReasons is not empty (printer is blocked), returns a list of (one or more)
-     * blocked reasons, otherwise it will be a one item list of printer state. May return an empty
-     * list if no resource id is found for the given status(es)
+     * Maps the printer state and reasons into a list of status strings If the printerReasons is not
+     * empty (printer is blocked), returns a list of (one or more) blocked reasons, otherwise it
+     * will be a one item list of printer state. May return an empty list if no resource id is found
+     * for the given status(es)
      */
     private fun getPrinterStatus(printerState: String, printerReasons: List<String>): Set<String> {
         val resourceIds: MutableSet<String> = LinkedHashSet()
         for (reason in printerReasons) {
-            if (TextUtils.isEmpty(reason) ||
-                reason == BackendConstants.BLOCKED_REASON__SPOOL_AREA_FULL &&
-                BackendConstants.PRINTER_STATE_BLOCKED != printerState
+            if (
+                TextUtils.isEmpty(reason) ||
+                    reason == BackendConstants.BLOCKED_REASON__SPOOL_AREA_FULL &&
+                        BackendConstants.PRINTER_STATE_BLOCKED != printerState
             ) {
                 continue
             }
@@ -190,16 +185,17 @@ class PrinterInformationFragment : Fragment() {
     }
 
     /**
-     * Set marker view
-     * Fills supplies levels views based on capabilities
+     * Set marker view Fills supplies levels views based on capabilities
+     *
      * @param view view
      * @param caps the selected printer's capabilities
      */
     private fun setMarkerView(caps: LocalPrinterCapabilities) {
         val mMarkerInfoList = ArrayList<MarkerInfo>()
         for (i in caps.markerTypes.indices) {
-            if ((validTonerTypes.contains(caps.markerTypes[i]) ||
-                        validInkTypes.contains(caps.markerTypes[i])) && caps.markerLevel[i] >= 0
+            if (
+                (validTonerTypes.contains(caps.markerTypes[i]) ||
+                    validInkTypes.contains(caps.markerTypes[i])) && caps.markerLevel[i] >= 0
             ) {
                 caps.markerColors[i].split("#").apply {
                     for (j in 1 until size) {
@@ -209,10 +205,9 @@ class PrinterInformationFragment : Fragment() {
                                 "#" + this[j],
                                 caps.markerHighLevel[i],
                                 caps.markerLowLevel[i],
-                                caps.markerLevel[i]
+                                caps.markerLevel[i],
                             )
                         )
-
                     }
                 }
             }
@@ -229,4 +224,4 @@ class PrinterInformationFragment : Fragment() {
         private const val TAG = "PrinterInformationFragment"
         private const val DEBUG = false
     }
-}
\ No newline at end of file
+}
diff --git a/src/com/android/bips/ui/PrinterInformationViewModel.kt b/src/com/android/bips/ui/PrinterInformationViewModel.kt
index 4e7ab6d..9e44786 100644
--- a/src/com/android/bips/ui/PrinterInformationViewModel.kt
+++ b/src/com/android/bips/ui/PrinterInformationViewModel.kt
@@ -31,22 +31,21 @@ import com.android.bips.BuiltInPrintService
 import com.android.bips.jni.JobCallbackParams
 import com.android.bips.jni.LocalPrinterCapabilities
 import com.android.bips.jni.PrinterStatusMonitor
-import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.launch
 import java.io.IOException
 import java.net.HttpURLConnection
 import java.net.URL
 import javax.net.ssl.HostnameVerifier
 import javax.net.ssl.HttpsURLConnection
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.launch
 
-/**
- * Printer Information ViewModel
- */
+/** Printer Information ViewModel */
 class PrinterInformationViewModel : ViewModel() {
     companion object {
         private const val TAG = "PrinterInformationViewModel"
         private const val DEBUG = false
     }
+
     private val HTTPS = "https"
     private val HTTP = "http"
 
@@ -97,7 +96,9 @@ class PrinterInformationViewModel : ViewModel() {
                     (con as HttpsURLConnection?)?.sslSocketFactory =
                         SSLCertificateSocketFactory.getInsecure(0, null)
                     (con as HttpsURLConnection?)?.hostnameVerifier =
-                        HostnameVerifier { s, sslSession -> true }
+                        HostnameVerifier { s, sslSession ->
+                            true
+                        }
                 } else if (protocol.equals(HTTP, ignoreCase = true)) {
                     con = url.openConnection() as HttpURLConnection
                 } else {
@@ -137,4 +138,4 @@ class PrinterInformationViewModel : ViewModel() {
     private fun onPrinterStatus(status: JobCallbackParams?) {
         printerStatusLiveData.postValue(status)
     }
-}
\ No newline at end of file
+}
diff --git a/tests/robolectric/config/robolectric.properties b/tests/robolectric/config/robolectric.properties
new file mode 100644
index 0000000..c1d5b17
--- /dev/null
+++ b/tests/robolectric/config/robolectric.properties
@@ -0,0 +1,2 @@
+sdk=NEWEST_SDK
+graphicsMode=NATIVE
\ No newline at end of file
diff --git a/tests/robolectric/src/com/android/bips/stats/StatsAsyncLoggerTest.kt b/tests/robolectric/src/com/android/bips/stats/StatsAsyncLoggerTest.kt
new file mode 100644
index 0000000..3ee2a3d
--- /dev/null
+++ b/tests/robolectric/src/com/android/bips/stats/StatsAsyncLoggerTest.kt
@@ -0,0 +1,259 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.bips.stats
+
+import android.os.Handler
+import android.print.PrintAttributes
+import android.print.PrintDocumentInfo
+import android.print.PrintJobInfo
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.google.common.truth.Truth.assertThat
+import java.util.concurrent.Semaphore
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.kotlin.*
+
+// These are clear-box tests that primarily validate basic and concurrent interactions.
+
+@RunWith(AndroidJUnit4::class)
+open class StatsAsyncLoggerTest {
+    val mStatsLogWrapper = mock<StatsLogWrapper>()
+    val mHandler = mock<Handler>()
+    val mSemaphore = mock<Semaphore>()
+
+    val mPrintJobInfo = mock<PrintJobInfo>()
+    val mPrintDocumentInfo = mock<PrintDocumentInfo>()
+    val mPrintAttributes = mock<PrintAttributes>()
+
+    @Before
+    fun setup() {
+        reset(mStatsLogWrapper)
+        reset(mHandler)
+        reset(mSemaphore)
+
+        reset(mPrintJobInfo)
+        reset(mPrintDocumentInfo)
+        reset(mPrintAttributes)
+
+        StatsAsyncLogger.testSetSemaphore(mSemaphore)
+        StatsAsyncLogger.testSetStatsLogWrapper(mStatsLogWrapper)
+        StatsAsyncLogger.testSetHandler(mHandler)
+
+        // Mocks should succeed by default
+        whenever(mHandler.postAtTime(any(), any())).thenReturn(true)
+        whenever(mSemaphore.tryAcquire()).thenReturn(true)
+        whenever(mPrintJobInfo.getAttributes()).thenReturn(mPrintAttributes)
+    }
+
+    @Test
+    fun printJobSuccessfullyLoggedTest() {
+        val logWrapperInOrder = inOrder(mStatsLogWrapper)
+        val handlerInOrder = inOrder(mHandler)
+        val semaphoreInOrder = inOrder(mSemaphore)
+        val timeCaptor = argumentCaptor<Long>()
+        val runnableCaptor = argumentCaptor<Runnable>()
+
+        // Arbitrary arguments
+        assertThat(
+                StatsAsyncLogger.PrintJob(
+                    "foo",
+                    true, // is secure
+                    StatsAsyncLogger.JobOrigin.DIRECT_PRINT,
+                    0, // Job success
+                    mPrintJobInfo,
+                    mPrintDocumentInfo,
+                    true, // borderless
+                    PrintAttributes.DUPLEX_MODE_LONG_EDGE,
+                    0, // MEDIA_PLAIN defined in wprint_df_types.h
+                )
+            )
+            .isTrue()
+        assertThat(
+                StatsAsyncLogger.PrintJob(
+                    "bar",
+                    false,
+                    StatsAsyncLogger.JobOrigin.SHARED_IMAGE,
+                    -1, // Job failed unknown
+                    mPrintJobInfo,
+                    mPrintDocumentInfo,
+                    false,
+                    PrintAttributes.DUPLEX_MODE_NONE,
+                    100, // Should be not exist (unspecified)
+                )
+            )
+            .isTrue()
+
+        handlerInOrder
+            .verify(mHandler, times(2))
+            .postAtTime(runnableCaptor.capture(), timeCaptor.capture())
+        handlerInOrder.verifyNoMoreInteractions()
+
+        // Validate delay args
+        val firstTime = timeCaptor.firstValue
+        val secondTime = timeCaptor.secondValue
+        assertThat(secondTime - firstTime)
+            .isAtLeast(StatsAsyncLogger.EVENT_REPORTED_MIN_INTERVAL.inWholeMilliseconds)
+        assertThat(secondTime - firstTime)
+            .isAtMost(2 * StatsAsyncLogger.EVENT_REPORTED_MIN_INTERVAL.inWholeMilliseconds)
+
+        // Validate Runnable logic
+        runnableCaptor.firstValue.run()
+        runnableCaptor.secondValue.run()
+        logWrapperInOrder
+            .verify(mStatsLogWrapper)
+            .internalPrintJob(
+                eq("foo"),
+                eq(StatsAsyncLogger.JobOrigin.DIRECT_PRINT.code),
+                eq(BipsStatsLog.BIPS_PRINT_JOB__RESULT__BIPS_PRINT_JOB_RESULT_COMPLETED),
+                eq(true),
+                // TODO(b/422187009): Figure out how to properly mock/shadow PrintAttributes
+                any(),
+                eq(BipsStatsLog.BIPS_PRINT_JOB__DUPLEX_MODE__FRAMEWORK_DUPLEX_MODE_LONG_EDGE),
+                eq(BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_MEDIA_PLAIN),
+                // TODO(b/422187009): Figure out how to properly mock/shadow PrintAttributes
+                any(),
+                eq(true),
+                // TODO(b/422187009): Figure out how to properly mock/shadow PrintAttributes
+                any(),
+                any(),
+                any(),
+            )
+        logWrapperInOrder
+            .verify(mStatsLogWrapper)
+            .internalPrintJob(
+                eq("bar"),
+                eq(StatsAsyncLogger.JobOrigin.SHARED_IMAGE.code),
+                eq(BipsStatsLog.BIPS_PRINT_JOB__RESULT__BIPS_PRINT_JOB_RESULT_FAILED_UNKNOWN),
+                eq(false),
+                // TODO(b/422187009): Figure out how to properly mock/shadow PrintAttributes
+                any(),
+                eq(BipsStatsLog.BIPS_PRINT_JOB__DUPLEX_MODE__FRAMEWORK_DUPLEX_MODE_NONE),
+                eq(BipsStatsLog.BIPS_PRINT_JOB__MEDIA_TYPE__BIPS_MEDIA_TYPE_UNSPECIFIED),
+                // TODO(b/422187009): Figure out how to properly mock/shadow PrintAttributes
+                any(),
+                eq(false),
+                // TODO(b/422187009): Figure out how to properly mock/shadow PrintAttributes
+                any(),
+                any(),
+                any(),
+            )
+
+        logWrapperInOrder.verifyNoMoreInteractions()
+
+        // Validate Semaphore logic
+        semaphoreInOrder.verify(mSemaphore, times(2)).tryAcquire()
+        semaphoreInOrder.verify(mSemaphore, times(2)).release()
+    }
+
+    @Test
+    fun printerCapsSuccessfullyLoggedTest() {
+        val logWrapperInOrder = inOrder(mStatsLogWrapper)
+        val handlerInOrder = inOrder(mHandler)
+        val semaphoreInOrder = inOrder(mSemaphore)
+        val timeCaptor = argumentCaptor<Long>()
+        val runnableCaptor = argumentCaptor<Runnable>()
+
+        // Arbitrary arguments
+        StatsAsyncLogger.RequestPrinterCapabilitiesStatus(0, false)
+        StatsAsyncLogger.RequestPrinterCapabilitiesStatus(42, true)
+
+        handlerInOrder
+            .verify(mHandler, times(2))
+            .postAtTime(runnableCaptor.capture(), timeCaptor.capture())
+        handlerInOrder.verifyNoMoreInteractions()
+
+        // Validate delay args
+        val firstTime = timeCaptor.firstValue
+        val secondTime = timeCaptor.secondValue
+        assertThat(secondTime - firstTime)
+            .isAtLeast(StatsAsyncLogger.EVENT_REPORTED_MIN_INTERVAL.inWholeMilliseconds)
+        assertThat(secondTime - firstTime)
+            .isAtMost(2 * StatsAsyncLogger.EVENT_REPORTED_MIN_INTERVAL.inWholeMilliseconds)
+
+        // Validate Runnable logic
+        runnableCaptor.firstValue.run()
+        runnableCaptor.secondValue.run()
+        logWrapperInOrder
+            .verify(mStatsLogWrapper)
+            .internalRequestPrinterCapabilitiesStatus(0, false)
+        logWrapperInOrder
+            .verify(mStatsLogWrapper)
+            .internalRequestPrinterCapabilitiesStatus(42, true)
+        logWrapperInOrder.verifyNoMoreInteractions()
+
+        // Validate Semaphore logic
+        semaphoreInOrder.verify(mSemaphore, times(2)).tryAcquire()
+        semaphoreInOrder.verify(mSemaphore, times(2)).release()
+    }
+
+    @Test
+    fun failureToAcquireSemaphoreTicketNeverSchedulesEvent() {
+        whenever(mSemaphore.tryAcquire()).thenReturn(false)
+        // Arbitrary Arguments
+        assertThat(StatsAsyncLogger.RequestPrinterCapabilitiesStatus(0, false)).isFalse()
+        assertThat(
+                StatsAsyncLogger.PrintJob(
+                    "foo",
+                    true, // is secure
+                    StatsAsyncLogger.JobOrigin.DIRECT_PRINT,
+                    0, // Job success
+                    mPrintJobInfo,
+                    mPrintDocumentInfo,
+                    true, // borderless
+                    PrintAttributes.DUPLEX_MODE_LONG_EDGE,
+                    2,
+                )
+            )
+            .isFalse()
+        verifyNoInteractions(mHandler)
+    }
+
+    @Test
+    fun failureToScheduleReleasesSemaphoreTicket() {
+        whenever(mHandler.postAtTime(any(), any())).thenReturn(false)
+        // Arbitrary Arguments
+        assertThat(StatsAsyncLogger.RequestPrinterCapabilitiesStatus(0, false)).isFalse()
+        assertThat(
+                StatsAsyncLogger.PrintJob(
+                    "foo",
+                    true, // is secure
+                    StatsAsyncLogger.JobOrigin.DIRECT_PRINT,
+                    0, // Job success
+                    mPrintJobInfo,
+                    mPrintDocumentInfo,
+                    true, // borderless
+                    PrintAttributes.DUPLEX_MODE_LONG_EDGE,
+                    0, // MEDIA_PLAIN defined in wprint_df_types.h
+                )
+            )
+            .isFalse()
+        verify(mSemaphore, times(2)).release()
+    }
+
+    @Test
+    fun tryAwaitingAllEventsSucceeds() {
+        whenever(mSemaphore.tryAcquire(any(), any(), any())).thenReturn(true)
+        assertThat(StatsAsyncLogger.tryAwaitingAllEvents()).isTrue()
+    }
+
+    @Test
+    fun tryAwaitingAllEventsFails() {
+        whenever(mSemaphore.tryAcquire(any(), any(), any())).thenReturn(false)
+        assertThat(StatsAsyncLogger.tryAwaitingAllEvents()).isFalse()
+    }
+}
```

