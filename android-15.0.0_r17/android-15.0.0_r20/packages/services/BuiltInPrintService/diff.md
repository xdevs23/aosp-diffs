```diff
diff --git a/OWNERS b/OWNERS
index 20b3746..b93f9e4 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@
 include platform/frameworks/base:/OWNERS
 anothermark@google.com
 kumarashishg@google.com
+bmgordon@google.com
diff --git a/jni/Android.bp b/jni/Android.bp
index c25eb46..deb9f0f 100644
--- a/jni/Android.bp
+++ b/jni/Android.bp
@@ -29,7 +29,6 @@ cc_library_shared {
         "-Wno-unused-parameter",
         "-Wno-sign-compare",
         "-Wno-missing-field-initializers",
-        "-Wno-implicit-function-declaration",
         "-Wno-format",
         "-Wno-missing-braces",
         "-Wno-deprecated-declarations",
diff --git a/jni/include/lib_wprint.h b/jni/include/lib_wprint.h
index 6c1d26e..18f753e 100755
--- a/jni/include/lib_wprint.h
+++ b/jni/include/lib_wprint.h
@@ -228,6 +228,7 @@ struct wprint_connect_info_st {
                                 uint8 *data, int data_len);
     /* User-supplied data. */
     void *user;
+    const char *requesting_user_name;
 };
 
 /*
diff --git a/jni/ipphelper/ipphelper.c b/jni/ipphelper/ipphelper.c
index e4683b9..4eef2c2 100644
--- a/jni/ipphelper/ipphelper.c
+++ b/jni/ipphelper/ipphelper.c
@@ -1592,6 +1592,17 @@ void parse_printerAttributes(ipp_t *response, printer_capabilities_t *capabiliti
         capabilities->jobPagesPerSetSupported = 1;
     }
 
+    // Certification override because of spec issue, 2.1 and above are mapped to 2.0
+    float certVersion = 0.0;
+    if ((attrptr = ippFindAttribute(response, "mopria-certified", IPP_TAG_TEXT)) != NULL ||
+        (attrptr = ippFindAttribute(response, "mopria_certified", IPP_TAG_TEXT)) != NULL) {
+        certVersion = atof(ippGetString(attrptr, 0, NULL));
+        LOGD("Mopria certified version: %f", certVersion);
+    }
+    if (certVersion < 2.0f) {
+        capabilities->jobPagesPerSetSupported = 0;
+    }
+
     debuglist_printerCapabilities(capabilities);
 }
 
diff --git a/jni/ipphelper/ipphelper.h b/jni/ipphelper/ipphelper.h
index e595cb9..4a56176 100644
--- a/jni/ipphelper/ipphelper.h
+++ b/jni/ipphelper/ipphelper.h
@@ -149,6 +149,13 @@ extern int getJobId(http_t *http, char *http_resource, char *printer_uri,
 
 extern int tryNextResourceExtension(char *printer_uri);
 
+extern ipp_status_t get_JobStatus(http_t *http,
+        char *printer_uri,        /* I - URI buffer */
+        int job_id,
+        job_state_dyn_t *job_state_dyn,
+        ipp_jstate_t *job_state,
+        const char *requesting_user);
+
 #define IPP_PREFIX "ipp"
 #define IPPS_PREFIX "ipps"
 #define DEFAULT_IPP_URI_RESOURCE "/ipp/print"
diff --git a/jni/ipphelper/ippstatus_capabilities.c b/jni/ipphelper/ippstatus_capabilities.c
index 48fa143..d0c6773 100644
--- a/jni/ipphelper/ippstatus_capabilities.c
+++ b/jni/ipphelper/ippstatus_capabilities.c
@@ -71,7 +71,9 @@ static const char *pattrs[] = {
         "media-col-ready",
         "print-scaling-supported",
         "print-scaling-default",
-        "job-pages-per-set-supported"
+        "job-pages-per-set-supported",
+        "mopria-certified",
+        "mopria_certified"
 };
 
 static void _init(const ifc_printer_capabilities_t *this_p,
diff --git a/jni/ipphelper/ippstatus_monitor.c b/jni/ipphelper/ippstatus_monitor.c
index 01f6cd9..edf3a56 100644
--- a/jni/ipphelper/ippstatus_monitor.c
+++ b/jni/ipphelper/ippstatus_monitor.c
@@ -114,6 +114,10 @@ static void _init(const ifc_status_monitor_t *this_p, const wprint_connect_info_
         pthread_mutex_init(&monitor->mutex, &monitor->mutexattr);
         sem_init(&monitor->monitor_sem, 0, 0);
         monitor->initialized = 1;
+        if (connect_info->requesting_user_name) {
+            strlcpy(monitor->requesting_user, connect_info->requesting_user_name,
+                    sizeof(monitor->requesting_user));
+        }
     } while (0);
 }
 
@@ -189,7 +193,6 @@ static void _get_status(const ifc_status_monitor_t *this_p,
     } while (0);
 }
 
-// TODO (b/312004304): job_state_cb code removed due to crash.
 static void _start(const ifc_status_monitor_t *this_p,
         void (*status_cb)(const printer_state_dyn_t *new_status,
                 const printer_state_dyn_t *old_status, void *status_param),
@@ -274,7 +277,23 @@ static void _start(const ifc_status_monitor_t *this_p,
                     (*status_cb)(&curr_status, &last_status, param);
                     memcpy(&last_status, &curr_status, sizeof(printer_state_dyn_t));
                 }
-                // TODO (b/312004304): Code removed due to crash. Will add it back with proper mitigation.
+
+                // Do not call for job state if thread has been stopped
+                if (job_state_cb != NULL && !monitor->stop_monitor) {
+                    pthread_mutex_lock(&monitor->mutex);
+                    if (job_id == -1) {
+                        job_id = getJobId(monitor->http, monitor->http_resource,
+                                          monitor->printer_uri, &new_state,
+                                          monitor->requesting_user);
+                    }
+                    _get_job_state(this_p, &new_state, job_id);
+                    pthread_mutex_unlock(&monitor->mutex);
+
+                    if (memcmp(&new_state, &old_state, sizeof(job_state_dyn_t)) != 0) {
+                        (*job_state_cb)(&new_state, param);
+                        memcpy(&old_state, &new_state, sizeof(job_state_dyn_t));
+                    }
+                }
                 sleep(1);
             }
         }
diff --git a/jni/lib/lib_wprint.c b/jni/lib/lib_wprint.c
index 8ceab2e..c354c5d 100755
--- a/jni/lib/lib_wprint.c
+++ b/jni/lib/lib_wprint.c
@@ -628,7 +628,6 @@ static void _job_status_callback(const printer_state_dyn_t *new_status,
 
 /*
  * Callback after getting the print job state
- * TODO (b/312004304): _print_job_state_callback code call removed due to crash.
  */
 static void _print_job_state_callback(const job_state_dyn_t *new_state, void *param) {
     wprint_job_callback_params_t cb_param = {};
@@ -825,6 +824,7 @@ static void _initialize_status_ifc(_job_queue_t *jq) {
         connect_info.validate_certificate = NULL;
     }
     connect_info.timeout = DEFAULT_IPP_TIMEOUT;
+    connect_info.requesting_user_name = jq->job_params.job_originating_user_name;
 
     // Initialize the status interface with this connection info
     jq->status_ifc->init(jq->status_ifc, &connect_info);
@@ -1658,8 +1658,6 @@ status_t wprintGetCapabilities(const wprint_connect_info_t *connect_info,
             printer_cap->canPrintPWG);
 
     if (result == OK) {
-        memcpy(&g_printer_caps, printer_cap, sizeof(printer_capabilities_t));
-
         LOGD("\tmake: %s", printer_cap->make);
         LOGD("\thas color: %d", printer_cap->color);
         LOGD("\tcan duplex: %d", printer_cap->duplex);
@@ -2033,6 +2031,7 @@ wJob_t wprintStartJob(const char *printer_addr, port_t port_num,
         msg.id = MSG_RUN_JOB;
         msg.job_id = job_handle;
 
+        memcpy(&g_printer_caps, printer_cap, sizeof(printer_capabilities_t));
         if (print_ifc && plugin && plugin->print_page &&
                 (msgQSend(_msgQ, (char *) &msg, sizeof(msg), NO_WAIT, MSG_Q_FIFO) == OK)) {
             errno = OK;
@@ -2298,7 +2297,7 @@ void wprintSetSourceInfo(const char *appName, const char *appVersion, const char
 bool wprintBlankPageForPclm(const wprint_job_params_t *job_params,
         const printer_capabilities_t *printer_cap) {
     return ((job_params->job_pages_per_set % 2) &&
-            ((job_params->num_copies > 1 && printer_cap->sidesSupported) ||
+            ((job_params->num_copies > 1 && printer_cap->duplex) ||
                     (job_params->num_copies == 1)) && (job_params->duplex != DUPLEX_MODE_NONE));
 }
 
diff --git a/jni/lib/printer.c b/jni/lib/printer.c
index 625d549..1dd380d 100644
--- a/jni/lib/printer.c
+++ b/jni/lib/printer.c
@@ -18,6 +18,7 @@
 
 #include <stdio.h>
 #include <stdlib.h>
+#include <string.h>
 #include <sys/stat.h>
 #include <unistd.h>
 #include <errno.h>
@@ -265,4 +266,4 @@ const ifc_print_job_t *printer_connect(int port_num) {
     } else {
         return NULL;
     }
-}
\ No newline at end of file
+}
diff --git a/jni/lib/wprintJNI.c b/jni/lib/wprintJNI.c
index 38834c1..990d701 100755
--- a/jni/lib/wprintJNI.c
+++ b/jni/lib/wprintJNI.c
@@ -1049,8 +1049,8 @@ static int _convertJobParams_to_C(JNIEnv *env, jobject javaJobParams,
     if (jobOriginatingUserName != NULL) {
         const char *name = (*env)->GetStringUTFChars(env, jobOriginatingUserName, NULL);
         if (name != NULL) {
-            strncpy(wprintJobParams->job_originating_user_name, name,
-                    sizeof(wprintJobParams->job_originating_user_name) - 1);
+            strlcpy(wprintJobParams->job_originating_user_name, name,
+                    sizeof(wprintJobParams->job_originating_user_name));
             (*env)->ReleaseStringUTFChars(env, jobOriginatingUserName, name);
         }
     }
diff --git a/jni/lib/wprint_msgq.c b/jni/lib/wprint_msgq.c
index ac412aa..0e20de0 100644
--- a/jni/lib/wprint_msgq.c
+++ b/jni/lib/wprint_msgq.c
@@ -22,6 +22,7 @@
 
 #include <stdio.h>
 #include <stdlib.h>
+#include <string.h>
 #include <pthread.h>
 #include <semaphore.h>
 
@@ -155,4 +156,4 @@ int msgQNumMsgs(msg_q_id msgQ) {
         pthread_mutex_unlock(&(msgq->mutex));
     }
     return num_msgs;
-}
\ No newline at end of file
+}
diff --git a/jni/plugins/lib_pclm.c b/jni/plugins/lib_pclm.c
index fab8a27..ae44bd6 100644
--- a/jni/plugins/lib_pclm.c
+++ b/jni/plugins/lib_pclm.c
@@ -19,6 +19,7 @@
 #include <sys/types.h>
 #include <stdio.h>
 #include <stdlib.h>
+#include <string.h>
 #include <math.h>
 
 #include "lib_pcl.h"
@@ -313,4 +314,4 @@ static const ifc_pcl_t _pcl_ifc = {
 
 ifc_pcl_t *pclm_connect(void) {
     return ((ifc_pcl_t *) &_pcl_ifc);
-}
\ No newline at end of file
+}
diff --git a/jni/plugins/plugin_pcl.c b/jni/plugins/plugin_pcl.c
index 6433cd7..8b4a9c7 100755
--- a/jni/plugins/plugin_pcl.c
+++ b/jni/plugins/plugin_pcl.c
@@ -403,8 +403,10 @@ static status_t _print_page(wprint_job_params_t *job_params, const char *mime_ty
             msg.id = MSG_START_PAGE;
             msg.param.start_page.extra_margin = ((job_params->duplex != DUPLEX_MODE_NONE) &&
                     ((job_params->page_num & 0x1) == 0)) ? job_params->page_bottom_margin : 0.0f;
-            msg.param.start_page.width = wprint_image_get_width(image_info);
-            msg.param.start_page.height = wprint_image_get_height(image_info);
+            msg.param.start_page.width = priv->job_info.pixel_width = wprint_image_get_width(
+                    image_info);
+            msg.param.start_page.height = priv->job_info.pixel_height = wprint_image_get_height(
+                    image_info);
             priv->job_info.num_components = image_info->num_components;
             priv->job_info.wprint_ifc->msgQSend(priv->msgQ, (char *) &msg, sizeof(msgQ_msg_t),
                     NO_WAIT, MSG_Q_FIFO);
@@ -538,6 +540,7 @@ static int _print_blank_page(wJob_t job_handle, wprint_job_params_t *job_params,
     msg.param.end_page.count = 0;
     priv->job_info.wprint_ifc->msgQSend(priv->msgQ, (char *) &msg, sizeof(msgQ_msg_t), NO_WAIT,
             MSG_Q_FIFO);
+    LOGD("_print_blank_page: added blank page to msgQ");
     return OK;
 }
 
diff --git a/jni/plugins/plugin_pdf.c b/jni/plugins/plugin_pdf.c
index 2e7854b..4c54fd7 100644
--- a/jni/plugins/plugin_pdf.c
+++ b/jni/plugins/plugin_pdf.c
@@ -18,6 +18,7 @@
 
 #include <stdlib.h>
 #include <stdio.h>
+#include <string.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <errno.h>
@@ -130,4 +131,4 @@ wprint_plugin_t *libwprintplugin_pdf_reg(void) {
             .get_print_formats = _get_print_formats, .start_job = _start_job,
             .print_page = _print_page, .print_blank_page = NULL, .end_job = _end_job,};
     return ((wprint_plugin_t *) &_pdf_plugin);
-}
\ No newline at end of file
+}
diff --git a/jni/plugins/wprint_image.c b/jni/plugins/wprint_image.c
index f5e148e..8d249ac 100755
--- a/jni/plugins/wprint_image.c
+++ b/jni/plugins/wprint_image.c
@@ -16,8 +16,9 @@
  * limitations under the License.
  */
 
-#include <stdlib.h>
 #include <math.h>
+#include <stdlib.h>
+#include <string.h>
 #include "wprint_image.h"
 #include "lib_wprint.h"
 
@@ -1123,4 +1124,4 @@ void wprint_image_cleanup(wprint_image_info_t *image_info) {
         free(image_info->output_cache);
         image_info->output_cache = NULL;
     }
-}
\ No newline at end of file
+}
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index a9e164e..fa78b12 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -41,7 +41,7 @@
     <string name="printer_description" msgid="8580767673213837142">"%1$s – %2$s"</string>
     <string name="title_activity_add_printer" msgid="9119216095769228566">"Дадаць прынтар"</string>
     <string name="add_printer_by_ip" msgid="562864787592910327">"Дадаць прынтар па IP-адрасе"</string>
-    <string name="hostname_or_ip" msgid="3460546103553992915">"Імя вузла або IP-адрас"</string>
+    <string name="hostname_or_ip" msgid="3460546103553992915">"Імя хоста або IP-адрас"</string>
     <string name="ip_hint" msgid="7939777481941979799">"192.168.0.4"</string>
     <string name="add" msgid="1950342261671100906">"Дадаць"</string>
     <string name="add_named" msgid="9074106244018070583">"Дадаць прынтар <xliff:g id="PRINTER">%1$s</xliff:g>"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index bc78954..bfa968a 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -50,7 +50,7 @@
     <string name="wifi_direct" msgid="4629404342852294985">"ওয়াই-ফাই ডাইরেক্ট"</string>
     <string name="find_wifi_direct" msgid="5270504288829123954">"ওয়াই-ফাই ডাইরেক্ট সমর্থিত প্রিন্টার খুঁজুন"</string>
     <string name="wifi_direct_printing" msgid="8423811041563144048">"Wi-Fi ডাইরেক্ট প্রিন্টিং"</string>
-    <string name="wifi_direct_printers" msgid="541168032444693191">"ওয়াই-ফাই ডাইরেক্ট সমর্থিত প্রিন্টার"</string>
+    <string name="wifi_direct_printers" msgid="541168032444693191">"ওয়াই-ফাই ডাইরেক্ট প্রিন্টার"</string>
     <string name="searching" msgid="2114018057619514587">"খোঁজা হচ্ছে…"</string>
     <string name="connect_hint_text" msgid="587112503851044234">"প্রিন্টারের সামনের প্যানেলে এই সংযোগটি অনুমোদন করতে হবে"</string>
     <string name="connecting_to" msgid="2665161014972086194">"<xliff:g id="PRINTER">%1$s</xliff:g> এর সাথে সংযুক্ত করা হচ্ছে"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 4ebd0be..a500493 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -49,7 +49,7 @@
     <string name="printer_not_supported" msgid="281955849350938408">"چاپگر پشتیبانی نمی‌شود"</string>
     <string name="wifi_direct" msgid="4629404342852294985">"‏Wi-Fi بی‌واسطه"</string>
     <string name="find_wifi_direct" msgid="5270504288829123954">"‏پیدا کردن چاپگرهای Wi-Fi بی‌واسطه"</string>
-    <string name="wifi_direct_printing" msgid="8423811041563144048">"‏چاپ ازطریق Wi-Fi بی‌واسطه"</string>
+    <string name="wifi_direct_printing" msgid="8423811041563144048">"‏چاپ مستقیم ازطریق Wi-Fi"</string>
     <string name="wifi_direct_printers" msgid="541168032444693191">"‏چاپگرهای Wi-Fi بی‌واسطه"</string>
     <string name="searching" msgid="2114018057619514587">"درحال جستجو…"</string>
     <string name="connect_hint_text" msgid="587112503851044234">"ممکن است لازم باشد این اتصال را در پانل جلوی چاپگر تأیید کنید"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 862cf8f..40c17ce 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -49,9 +49,9 @@
     <string name="printer_not_supported" msgid="281955849350938408">"प्रिंटर इस पर काम नहीं करता है"</string>
     <string name="wifi_direct" msgid="4629404342852294985">"Wi-Fi Direct"</string>
     <string name="find_wifi_direct" msgid="5270504288829123954">"Wi-Fi Direct प्रिंटर ढूंढें"</string>
-    <string name="wifi_direct_printing" msgid="8423811041563144048">"Wi-Fi Direct प्रिंटिंग की सुविधा"</string>
-    <string name="wifi_direct_printers" msgid="541168032444693191">"Wi-Fi Direct प्रिंटर"</string>
-    <string name="searching" msgid="2114018057619514587">"खोज की जा रही है…"</string>
+    <string name="wifi_direct_printing" msgid="8423811041563144048">"Wi-Fi Direct से प्रिंट करने की सुविधा"</string>
+    <string name="wifi_direct_printers" msgid="541168032444693191">"Wi-Fi Direct की सुविधा वाले प्रिंटर"</string>
+    <string name="searching" msgid="2114018057619514587">"खोजे जा रहे हैं…"</string>
     <string name="connect_hint_text" msgid="587112503851044234">"अपने प्रिंटर के सामने के पैनल पर आपको इस कनेक्शन के लिए मंज़ूरी देनी पड़ सकती है"</string>
     <string name="connecting_to" msgid="2665161014972086194">"<xliff:g id="PRINTER">%1$s</xliff:g> से कनेक्ट किया जा रहा है"</string>
     <string name="failed_printer_connection" msgid="4196305972749960362">"प्रिंटर से कनेक्ट नहीं हो सका"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 05635f1..16bc8e2 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -40,7 +40,7 @@
     <string name="media_size_4x6in" msgid="3093276425529958253">"4x6 inci (10x15 cm)"</string>
     <string name="printer_description" msgid="8580767673213837142">"%1$s – %2$s"</string>
     <string name="title_activity_add_printer" msgid="9119216095769228566">"Tambahkan printer"</string>
-    <string name="add_printer_by_ip" msgid="562864787592910327">"Tambahkan printer dengan alamat IP"</string>
+    <string name="add_printer_by_ip" msgid="562864787592910327">"Tambahkan printer menggunakan alamat IP"</string>
     <string name="hostname_or_ip" msgid="3460546103553992915">"Hostname atau alamat IP"</string>
     <string name="ip_hint" msgid="7939777481941979799">"192.168.0.4"</string>
     <string name="add" msgid="1950342261671100906">"Tambahkan"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index ca9775d..513a994 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -50,7 +50,7 @@
     <string name="wifi_direct" msgid="4629404342852294985">"Wi-Fi Direct"</string>
     <string name="find_wifi_direct" msgid="5270504288829123954">"Wi-Fi တိုက်ရိုက်သုံး ပုံနှိပ်စက်များကို ရှာရန်"</string>
     <string name="wifi_direct_printing" msgid="8423811041563144048">"တိုက်ရိုက် Wi-Fi ပုံနှိပ်ခြင်း"</string>
-    <string name="wifi_direct_printers" msgid="541168032444693191">"Wi-Fi Direct သုံး ပရင်တာများ"</string>
+    <string name="wifi_direct_printers" msgid="541168032444693191">"တိုက်ရိုက် Wi-Fi သုံး ပရင်တာများ"</string>
     <string name="searching" msgid="2114018057619514587">"ရှာဖွေနေသည်…"</string>
     <string name="connect_hint_text" msgid="587112503851044234">"သင့်ပရင်တာ၏ အရှေ့ဘက်အကွက်တွင် ဤချိတ်ဆက်မှုကို အတည်ပြုရန် လိုအပ်နိုင်သည်"</string>
     <string name="connecting_to" msgid="2665161014972086194">"<xliff:g id="PRINTER">%1$s</xliff:g> သို့ ချိတ်ဆက်နေသည်"</string>
@@ -71,7 +71,7 @@
     <string name="accept" msgid="4426153292469698134">"လက်ခံရန်"</string>
     <string name="reject" msgid="24751635160440693">"ပယ်ရန်"</string>
     <string name="connections" msgid="8895413761760117180">"ချိတ်ဆက်မှုများ"</string>
-    <string name="wifi_direct_problem" msgid="8995174986718516990">"\'မူရင်း ပုံနှိပ်ဝန်ဆောင်မှု\' က တိုက်ရိုက် Wi-Fi ပုံနှိပ်စက်များကို ရှာမတွေ့ပါ"</string>
+    <string name="wifi_direct_problem" msgid="8995174986718516990">"\'မူရင်း ပုံနှိပ်ဝန်ဆောင်မှု\' က တိုက်ရိုက် Wi-Fi သုံး ပရင်တာများကို ရှာမတွေ့ပါ"</string>
     <string name="disable_wifi_direct" msgid="4824677957241687577">"တိုက်ရိုက် Wi-Fi ကို ပိတ်ရန်"</string>
     <string name="wifi_direct_permission_rationale" msgid="4671416845852665202">"အနီးရှိပုံနှိပ်စက်များကို ရှာရန် ‘ပုံသေပုံနှိပ်ပေးသည့် ဝန်ဆောင်မှု’ က အနီးတစ်ဝိုက်ရှိ စက်များဆိုင်ရာ ခွင့်ပြုချက်လိုအပ်သည်။"</string>
     <string name="fix" msgid="7784394272611365393">"ခွင့်ပြုချက် စစ်ရန်"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 24c1253..1e2315d 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -39,7 +39,7 @@
     <string name="media_size_8x10in" msgid="1872576638522812402">"८x१० इन्च"</string>
     <string name="media_size_4x6in" msgid="3093276425529958253">"४x६ इन्च"</string>
     <string name="printer_description" msgid="8580767673213837142">"%1$s – %2$s"</string>
-    <string name="title_activity_add_printer" msgid="9119216095769228566">"प्रिन्टर थप्नुहोस्"</string>
+    <string name="title_activity_add_printer" msgid="9119216095769228566">"प्रिन्टर कनेक्ट गर्नुहोस्"</string>
     <string name="add_printer_by_ip" msgid="562864787592910327">"IP एड्रेसअनुसार प्रिन्टर हाल्नुहोस्"</string>
     <string name="hostname_or_ip" msgid="3460546103553992915">"होस्टनेम वा IP एड्रेस"</string>
     <string name="ip_hint" msgid="7939777481941979799">"192.168.0.4"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 88acfd7..db4bb4e 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -40,8 +40,8 @@
     <string name="media_size_4x6in" msgid="3093276425529958253">"4x6 ଇଞ୍ଚ"</string>
     <string name="printer_description" msgid="8580767673213837142">"%1$s – %2$s"</string>
     <string name="title_activity_add_printer" msgid="9119216095769228566">"ପ୍ରିଣ୍ଟର୍‌ ଯୋଗ କରନ୍ତୁ"</string>
-    <string name="add_printer_by_ip" msgid="562864787592910327">"IP ଠିକଣା ମାଧ୍ୟମରେ ପ୍ରିଣ୍ଟର୍‌କୁ ଯୋଗ କରନ୍ତୁ"</string>
-    <string name="hostname_or_ip" msgid="3460546103553992915">"ହୋଷ୍ଟନେମ୍‍ କିମ୍ବା IP ଠିକଣା"</string>
+    <string name="add_printer_by_ip" msgid="562864787592910327">"IP ଠିକଣା ମାଧ୍ୟମରେ ପ୍ରିଣ୍ଟରକୁ ଯୋଗ କରନ୍ତୁ"</string>
+    <string name="hostname_or_ip" msgid="3460546103553992915">"ହୋଷ୍ଟନେମ କିମ୍ବା IP ଠିକଣା"</string>
     <string name="ip_hint" msgid="7939777481941979799">"192.168.0.4"</string>
     <string name="add" msgid="1950342261671100906">"ଯୋଡ଼ନ୍ତୁ"</string>
     <string name="add_named" msgid="9074106244018070583">"<xliff:g id="PRINTER">%1$s</xliff:g>କୁ ଯୋଡ଼ନ୍ତୁ"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index c4087c4..da59a85 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -49,7 +49,7 @@
     <string name="printer_not_supported" msgid="281955849350938408">"Skrivaren stöds inte"</string>
     <string name="wifi_direct" msgid="4629404342852294985">"wifi Direct"</string>
     <string name="find_wifi_direct" msgid="5270504288829123954">"Hitta skrivare med wifi Direct"</string>
-    <string name="wifi_direct_printing" msgid="8423811041563144048">"Utskrift via wifi Direct"</string>
+    <string name="wifi_direct_printing" msgid="8423811041563144048">"Utskrift via Wi-Fi Direct"</string>
     <string name="wifi_direct_printers" msgid="541168032444693191">"Skrivare med Wi-Fi Direct"</string>
     <string name="searching" msgid="2114018057619514587">"Söker …"</string>
     <string name="connect_hint_text" msgid="587112503851044234">"Du kan behöva godkänna anslutningen på frontpanelen på skrivaren"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index aee92d3..a91b63a 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -49,7 +49,7 @@
     <string name="printer_not_supported" msgid="281955849350938408">"پرنٹر تعاون یافتہ نہیں ہے"</string>
     <string name="wifi_direct" msgid="4629404342852294985">"‏Wi-Fi ڈائریکٹ"</string>
     <string name="find_wifi_direct" msgid="5270504288829123954">"‏Wi-Fi ڈائریکٹ پرنٹرز تلاش کریں"</string>
-    <string name="wifi_direct_printing" msgid="8423811041563144048">"‏Wi-Fi براہ راست پرنٹ کریں"</string>
+    <string name="wifi_direct_printing" msgid="8423811041563144048">"‏Wi-Fi براہ راست پرنٹنگ"</string>
     <string name="wifi_direct_printers" msgid="541168032444693191">"‏Wi-Fi ڈائریکٹ پرنٹرز"</string>
     <string name="searching" msgid="2114018057619514587">"تلاش کیا جا رہا ہے…"</string>
     <string name="connect_hint_text" msgid="587112503851044234">"آپ کو اپنے پرنٹر کے سامنے والے پینل پر اس کنکشن کو منظوری دینی پڑ سکتی ہے"</string>
diff --git a/src/com/android/bips/LocalPrintJob.java b/src/com/android/bips/LocalPrintJob.java
index d9ff70d..630cda9 100644
--- a/src/com/android/bips/LocalPrintJob.java
+++ b/src/com/android/bips/LocalPrintJob.java
@@ -36,6 +36,7 @@ import com.android.bips.p2p.P2pPrinterConnection;
 import com.android.bips.p2p.P2pUtils;
 
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.StringJoiner;
 import java.util.function.Consumer;
 
@@ -48,6 +49,8 @@ class LocalPrintJob implements MdnsDiscovery.Listener, ConnectionListener,
     private static final boolean DEBUG = false;
     private static final String IPP_SCHEME = "ipp";
     private static final String IPPS_SCHEME = "ipps";
+    private static final String SHARE_TO_PRINT = "SP";
+    private static final String DIRECT_PRINT = "DP";
 
     /** Maximum time to wait to find a printer before failing the job */
     private static final int DISCOVERY_TIMEOUT = 2 * 60 * 1000;
@@ -411,10 +414,6 @@ class LocalPrintJob implements MdnsDiscovery.Listener, ConnectionListener,
         Bundle bundle = new Bundle();
         bundle.putString(BackendConstants.PARAM_JOB_ID, mPrintJob.getId().toString());
         bundle.putLong(BackendConstants.PARAM_DATE_TIME, System.currentTimeMillis());
-        // TODO: Add real location
-        bundle.putString(BackendConstants.PARAM_LOCATION, "United States");
-        // TODO: Add real user id
-        bundle.putString(BackendConstants.PARAM_USER_ID, "userid");
         bundle.putString(BackendConstants.PARAM_RESULT, result);
         bundle.putLong(
                 BackendConstants.PARAM_ELAPSED_TIME_ALL, System.currentTimeMillis() - mStartTime);
@@ -430,15 +429,15 @@ class LocalPrintJob implements MdnsDiscovery.Listener, ConnectionListener,
         Bundle bundle = new Bundle();
         bundle.putString(BackendConstants.PARAM_JOB_ID, mPrintJob.getId().toString());
         bundle.putLong(BackendConstants.PARAM_DATE_TIME, System.currentTimeMillis());
-        // TODO: Add real location
-        bundle.putString(BackendConstants.PARAM_LOCATION, "United States");
-        bundle.putInt(
-                BackendConstants.PARAM_JOB_PAGES,
+        bundle.putInt(BackendConstants.PARAM_JOB_PAGES,
                 mPrintJob.getInfo().getCopies() * mPrintJob.getDocument().getInfo().getPageCount());
-        // TODO: Add real user id
-        bundle.putString(BackendConstants.PARAM_USER_ID, "userid");
-        // TODO: Determine whether the print job came from share to BIPS or from print system
-        bundle.putString(BackendConstants.PARAM_SOURCE_PATH, "ShareToBips || PrintSystem");
+        bundle.putString(BackendConstants.PARAM_SOURCE_PATH,
+                isSharedPrint() ? SHARE_TO_PRINT : DIRECT_PRINT);
         return bundle;
     }
+
+    private boolean isSharedPrint() {
+        return Arrays.asList(ImagePrintActivity.getLastPrintJobId(),
+                PdfPrintActivity.getLastPrintJobId()).contains(mPrintJob.getInfo().getId());
+    }
 }
diff --git a/src/com/android/bips/PdfPrintActivity.java b/src/com/android/bips/PdfPrintActivity.java
index 4463fae..2549779 100644
--- a/src/com/android/bips/PdfPrintActivity.java
+++ b/src/com/android/bips/PdfPrintActivity.java
@@ -28,6 +28,8 @@ import android.print.PageRange;
 import android.print.PrintAttributes;
 import android.print.PrintDocumentAdapter;
 import android.print.PrintDocumentInfo;
+import android.print.PrintJob;
+import android.print.PrintJobId;
 import android.print.PrintManager;
 import android.util.Log;
 import android.webkit.URLUtil;
@@ -44,6 +46,8 @@ public class PdfPrintActivity extends Activity {
     private static final String TAG = PdfPrintActivity.class.getSimpleName();
     private static final boolean DEBUG = false;
 
+    private static PrintJobId sPrintJobId;
+
     private CancellationSignal mCancellationSignal;
     private String mJobName;
     Uri mContentUri = null;
@@ -73,7 +77,8 @@ public class PdfPrintActivity extends Activity {
         PrintAttributes printAttributes = new PrintAttributes.Builder()
                 .setColorMode(PrintAttributes.COLOR_MODE_COLOR)
                 .build();
-        printManager.print(mJobName, new PdfAdapter(), printAttributes);
+        PrintJob printJob = printManager.print(mJobName, new PdfAdapter(), printAttributes);
+        sPrintJobId = printJob.getId();
     }
 
     @Override
@@ -149,4 +154,13 @@ public class PdfPrintActivity extends Activity {
             return null;
         }
     }
+
+    /**
+     * Get the print job id from PrintManager created print job.
+     *
+     * @return A PrintJobId, can be null
+     */
+    static PrintJobId getLastPrintJobId() {
+        return sPrintJobId;
+    }
 }
diff --git a/src/com/android/bips/ipp/StartJobTask.java b/src/com/android/bips/ipp/StartJobTask.java
index 10aba16..196c8c9 100755
--- a/src/com/android/bips/ipp/StartJobTask.java
+++ b/src/com/android/bips/ipp/StartJobTask.java
@@ -41,6 +41,7 @@ import java.io.BufferedOutputStream;
 import java.io.File;
 import java.io.FileOutputStream;
 import java.io.IOException;
+import java.util.Objects;
 
 /**
  * A background task that starts sending a print job. The result of this task is an integer
@@ -279,6 +280,6 @@ class StartJobTask extends AsyncTask<Void, Void, Integer> {
     }
 
     private boolean isSharedPhoto() {
-        return mJobInfo.getId().equals(ImagePrintActivity.getLastPrintJobId());
+        return Objects.equals(mJobInfo.getId(), ImagePrintActivity.getLastPrintJobId());
     }
 }
diff --git a/src/com/android/bips/jni/BackendConstants.java b/src/com/android/bips/jni/BackendConstants.java
index 3147050..f780303 100644
--- a/src/com/android/bips/jni/BackendConstants.java
+++ b/src/com/android/bips/jni/BackendConstants.java
@@ -168,8 +168,6 @@ public class BackendConstants {
     public static final String PARAM_JOB_PAGES = "job_pages";
     public static final String PARAM_SOURCE_PATH = "source_path";
     public static final String PARAM_DATE_TIME = "date_time";
-    public static final String PARAM_USER_ID = "user_id";
-    public static final String PARAM_LOCATION = "location";
     public static final String PARAM_RESULT = "result";
     public static final String PARAM_ERROR_MESSAGES = "error_messages";
     public static final String PARAM_ELAPSED_TIME_ALL = "elapsed_time_all";
diff --git a/src/com/android/bips/p2p/P2pMonitor.java b/src/com/android/bips/p2p/P2pMonitor.java
index 1c9ce30..625beeb 100644
--- a/src/com/android/bips/p2p/P2pMonitor.java
+++ b/src/com/android/bips/p2p/P2pMonitor.java
@@ -104,9 +104,12 @@ public class P2pMonitor {
      * Request connection to a peer (which may already be connected) at least until stopped. Keeps
      * the current connection open as long as it might be useful.
      */
-    public void connect(WifiP2pDevice peer, P2pConnectionListener listener) {
+    public void connect(WifiP2pDevice peer, P2pConnectionListener listener,
+            P2pPeerListener discoveryListener) {
         if (DEBUG) Log.d(TAG, "connect(" + toString(peer) + ")");
 
+        boolean isP2pAlreadyConnected = false;
+
         if (mP2pManager == null) {
             // Device has no P2P support so indicate failure
             mService.getMainHandler().post(listener::onConnectionClosed);
@@ -120,6 +123,14 @@ public class P2pMonitor {
                 // The only listener is our internal one, so close this connection to make room
                 mConnection.close();
                 mConnection = null;
+                isP2pAlreadyConnected = true;
+                // Restarting p2p discovery and re-initiating the p2p connection after a delay of
+                // 1 second makes subsequent WFD(p2p) connection possible
+                // more info - https://issuetracker.google.com/issues/298540041
+                mService.delay(1000, () -> {
+                    stopDiscover(discoveryListener);
+                    discover(discoveryListener);
+                });
             } else {
                 // Cannot open connection
                 mService.getMainHandler().post(listener::onConnectionClosed);
@@ -127,7 +138,13 @@ public class P2pMonitor {
             }
         }
 
-        // Check for existing connection to the same device
+        // If connected to other device, bail out and wait for connect(..) to be called again after
+        // re-discovery
+        if (isP2pAlreadyConnected) {
+            return;
+        }
+
+        // Check for existing connection to the same device.
         if (mConnection == null) {
             // Create a new connection request with our internal listener
             mConnection = new P2pConnectionProcedure(mService, mP2pManager, peer,
diff --git a/src/com/android/bips/p2p/P2pPrinterConnection.java b/src/com/android/bips/p2p/P2pPrinterConnection.java
index edfad3f..7fd2be7 100644
--- a/src/com/android/bips/p2p/P2pPrinterConnection.java
+++ b/src/com/android/bips/p2p/P2pPrinterConnection.java
@@ -16,6 +16,8 @@
 
 package com.android.bips.p2p;
 
+import static com.android.bips.discovery.P2pDiscovery.toPrinter;
+
 import android.net.wifi.p2p.WifiP2pDevice;
 import android.net.wifi.p2p.WifiP2pInfo;
 import android.util.Log;
@@ -32,6 +34,7 @@ import java.net.Inet4Address;
 import java.net.NetworkInterface;
 import java.net.SocketException;
 import java.net.UnknownHostException;
+import java.util.Arrays;
 
 /**
  * Manage the process of connecting to a P2P device, discovering a printer on the new network, and
@@ -63,6 +66,8 @@ public class P2pPrinterConnection implements Discovery.Listener, P2pConnectionLi
             ConnectionListener listener) {
         this(service, listener);
         if (DEBUG) Log.d(TAG, "Connecting to " + P2pMonitor.toString(peer));
+        // Initialize mPrinter to handle onPeerFound callback for re-discover cases
+        mPrinter = toPrinter(peer);
         connectToPeer(peer);
     }
 
@@ -83,7 +88,7 @@ public class P2pPrinterConnection implements Discovery.Listener, P2pConnectionLi
 
     private void connectToPeer(WifiP2pDevice peer) {
         mPeer = peer;
-        mService.getP2pMonitor().connect(mPeer, this);
+        mService.getP2pMonitor().connect(mPeer, this, this);
     }
 
     @Override
@@ -188,9 +193,10 @@ public class P2pPrinterConnection implements Discovery.Listener, P2pConnectionLi
             mListener.onConnectionComplete(null);
             close();
         } else {
-            // Make a copy of the printer bearing its P2P path
+            // Make a copy of the printer bearing its P2P path as primary and discovered path
+            // as secondary
             DiscoveredPrinter p2pPrinter = new DiscoveredPrinter(printer.uuid, printer.name,
-                    P2pDiscovery.toPath(mPeer), printer.location);
+                    Arrays.asList(P2pDiscovery.toPath(mPeer), printer.path), printer.location);
             mListener.onConnectionComplete(p2pPrinter);
         }
     }
diff --git a/src/com/android/bips/ui/MoreOptionsActivity.java b/src/com/android/bips/ui/MoreOptionsActivity.java
index 4087725..2814d07 100644
--- a/src/com/android/bips/ui/MoreOptionsActivity.java
+++ b/src/com/android/bips/ui/MoreOptionsActivity.java
@@ -30,10 +30,15 @@ import android.print.PrinterId;
 import android.printservice.PrintService;
 import android.util.Log;
 import android.view.MenuItem;
+import android.widget.Toast;
 
 import com.android.bips.BuiltInPrintService;
+import com.android.bips.R;
+import com.android.bips.discovery.ConnectionListener;
 import com.android.bips.discovery.DiscoveredPrinter;
 import com.android.bips.discovery.Discovery;
+import com.android.bips.p2p.P2pPrinterConnection;
+import com.android.bips.p2p.P2pUtils;
 
 import java.net.InetAddress;
 import java.net.UnknownHostException;
@@ -54,6 +59,7 @@ public class MoreOptionsActivity extends Activity implements ServiceConnection,
     InetAddress mPrinterAddress;
     public static final String EXTRA_PRINTER_ID = "EXTRA_PRINTER_ID";
     private final ExecutorService mExecutorService = Executors.newSingleThreadExecutor();
+    private P2pPrinterConnection mP2pPrinterConnection;
 
     @Override
     protected void onCreate(Bundle savedInstanceState) {
@@ -96,6 +102,12 @@ public class MoreOptionsActivity extends Activity implements ServiceConnection,
     @Override
     protected void onStop() {
         super.onStop();
+
+        if (mP2pPrinterConnection != null) {
+            mP2pPrinterConnection.close();
+            mP2pPrinterConnection = null;
+        }
+
         if (mPrintService != null) {
             mPrintService.getDiscovery().stop(this);
         }
@@ -121,28 +133,77 @@ public class MoreOptionsActivity extends Activity implements ServiceConnection,
 
     @Override
     public void onPrinterFound(DiscoveredPrinter printer) {
+        // Return when P2P connection is in progress
+        if (mP2pPrinterConnection != null) {
+            return;
+        }
+
         if (printer.getUri().toString().equals(mPrinterId.getLocalId())) {
             // We discovered a printer matching the job's PrinterId, so show recommendations
-            mPrinter = printer;
-            setTitle(mPrinter.name);
-            mExecutorService.execute(() -> {
-                try {
-                    mPrinterAddress = InetAddress.getByName(mPrinter.path.getHost());
-                    // No need for continued discovery after we find the printer.
-                    mPrintService.getDiscovery().stop(this);
-                    if (!mExecutorService.isShutdown() && mPrintService != null) {
-                        mPrintService.getMainHandler().post(() -> {
-                            if (getFragmentManager().findFragmentByTag(TAG) == null) {
-                                MoreOptionsFragment fragment = new MoreOptionsFragment();
-                                getFragmentManager().beginTransaction()
-                                        .replace(android.R.id.content, fragment, TAG)
-                                        .commit();
+            if (P2pUtils.isP2p(printer)) {
+                // Printer is not connected on p2p interface
+                connectP2P(printer);
+            } else {
+                loadPrinterInfoFragment(printer);
+            }
+        }
+    }
+
+    private void connectP2P(DiscoveredPrinter printer) {
+        Toast.makeText(mPrintService, getString(R.string.connecting_to, printer.name),
+                Toast.LENGTH_LONG).show();
+
+        mP2pPrinterConnection = new P2pPrinterConnection(mPrintService, printer,
+                new ConnectionListener() {
+                    @Override
+                    public void onConnectionComplete(DiscoveredPrinter printer) {
+                        if (DEBUG) Log.d(TAG, "onConnectionComplete(), printer = " + printer);
+                        if (printer != null && printer.paths.size() > 1) {
+                            loadPrinterInfoFragment(
+                                    new DiscoveredPrinter(printer.uuid, printer.name,
+                                            printer.paths.get(1), printer.location));
+                        } else {
+                            Toast.makeText(mPrintService, R.string.failed_printer_connection,
+                                    Toast.LENGTH_LONG).show();
+                            if (mP2pPrinterConnection != null) {
+                                mP2pPrinterConnection.close();
+                                mP2pPrinterConnection = null;
                             }
-                        });
+                        }
                     }
-                } catch (UnknownHostException ignored) { }
-            });
-        }
+
+                    @Override
+                    public void onConnectionDelayed(boolean delayed) {
+                        if (delayed) {
+                            Toast.makeText(mPrintService, R.string.connect_hint_text,
+                                    Toast.LENGTH_LONG).show();
+                        }
+                    }
+                });
+    }
+
+    private void loadPrinterInfoFragment(DiscoveredPrinter printer) {
+        mPrinter = printer;
+        setTitle(mPrinter.name);
+        // Network operation in non UI thread
+        mExecutorService.execute(() -> {
+            try {
+                mPrinterAddress = InetAddress.getByName(mPrinter.path.getHost());
+                // No need for continued discovery after we find the printer.
+                mPrintService.getDiscovery().stop(this);
+                if (!mExecutorService.isShutdown() && mPrintService != null) {
+                    mPrintService.getMainHandler().post(() -> {
+                        if (getFragmentManager().findFragmentByTag(TAG) == null) {
+                            MoreOptionsFragment fragment = new MoreOptionsFragment();
+                            getFragmentManager().beginTransaction()
+                                    .replace(android.R.id.content, fragment, TAG)
+                                    .commit();
+                        }
+                    });
+                }
+            } catch (UnknownHostException ignored) {
+            }
+        });
     }
 
     @Override
```

