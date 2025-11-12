```diff
diff --git a/bcmdhd/config/Android.bp b/bcmdhd/config/Android.bp
new file mode 100644
index 0000000..dd70b06
--- /dev/null
+++ b/bcmdhd/config/Android.bp
@@ -0,0 +1,27 @@
+// Copyright (C) 2008 The Android Open Source Project
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
+
+prebuilt_etc {
+    name: "wpa_supplicant.conf",
+    src: ":wpa_supplicant_conf_gen",
+    sub_dir: "wifi",
+    vendor: true,
+    enabled: select(soong_config_variable("wpa_supplicant_8", "board_wlan_device"), {
+        "bcmdhd": true,
+        default: false,
+    }),
+    licenses: [
+        "external_wpa_supplicant_8_license",
+    ],
+}
diff --git a/bcmdhd/config/Android.mk b/bcmdhd/config/Android.mk
deleted file mode 100644
index 8c3b13f..0000000
--- a/bcmdhd/config/Android.mk
+++ /dev/null
@@ -1,30 +0,0 @@
-#
-# Copyright (C) 2008 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-LOCAL_PATH := $(call my-dir)
-
-########################
-
-WIFI_DRIVER_SOCKET_IFACE := wlan0
-ifeq ($(strip $(WPA_SUPPLICANT_VERSION)),VER_0_8_X)
-  include external/wpa_supplicant_8/wpa_supplicant/wpa_supplicant_conf.mk
-else
-ifeq ($(strip $(WPA_SUPPLICANT_VERSION)),VER_0_6_X)
-  include external/wpa_supplicant_6/wpa_supplicant/wpa_supplicant_conf.mk
-else
-  include external/wpa_supplicant/wpa_supplicant_conf.mk
-endif
-endif
-#######################
diff --git a/bcmdhd/halutil/halutil.cpp b/bcmdhd/halutil/halutil.cpp
index f2f59a8..606c2ef 100644
--- a/bcmdhd/halutil/halutil.cpp
+++ b/bcmdhd/halutil/halutil.cpp
@@ -402,6 +402,17 @@ wifi_ring_buffer_id ringId = -1;
 
 #define C2S(x)  case x: return #x;
 
+static const char *TrafficACToString(int ac) {
+    switch (ac) {
+    C2S(WIFI_AC_VO)
+    C2S(WIFI_AC_VI)
+    C2S(WIFI_AC_BE)
+    C2S(WIFI_AC_BK)
+    default:
+        return "Unknown traffic ac";
+    }
+}
+
 static const char *RBentryTypeToString(int cmd) {
     switch (cmd) {
         C2S(ENTRY_TYPE_CONNECT_EVENT)
@@ -538,6 +549,7 @@ static const char *RttTypeToString(wifi_rtt_type type)
         C2S(RTT_TYPE_2_SIDED)
         /* C2S(RTT_TYPE_2_SIDED_11MC) is same as above */
         C2S(RTT_TYPE_2_SIDED_11AZ_NTB)
+        C2S(RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)
         default:
             return "UNKNOWN TYPE";
     }
@@ -613,6 +625,13 @@ struct rtt_params_v3 {
     u32 num_frames_per_burst;
 };
 
+wifi_rtt_akm base_akm = WPA_KEY_MGMT_NONE;
+wifi_rtt_cipher_suite pairwise_cipher_suite = WPA_CIPHER_NONE;
+bool enable_secure_he_ltf = false;
+bool enable_ranging_frame_protection = false;
+char passphrase[RTT_SECURITY_MAX_PASSPHRASE_LEN] = {0};
+u32 passphrase_len = 0;
+
 struct rtt_params default_rtt_param = {0, 0, 0, 0, 0, 15, 0, 0, 0, 0, RTT_TYPE_2_SIDED};
 struct rtt_params_v3 default_rtt_param_v3 = {5000, 500, 5};
 
@@ -1234,74 +1253,108 @@ static int removeDuplicateScanResults(wifi_scan_result **results, int num) {
     return num_results;
 }
 
-static void onRTTResultsV3(wifi_request_id id, unsigned num_results,
-    wifi_rtt_result_v3 *result[]) {
+static void onRTTResultsV4(wifi_request_id id, unsigned num_results,
+    wifi_rtt_result_v4 *result[]) {
 
     printMsg("RTT results: num_results %d\n", num_results);
-    wifi_rtt_result_v3 *rtt_result_v3;
+    wifi_rtt_result *rtt_result_v1 = NULL;
+    wifi_rtt_result_v2 *rtt_result_v2 = NULL;
+    wifi_rtt_result_v3 *rtt_result_v3 = NULL;
+    wifi_rtt_result_v4 *rtt_result_v4 = NULL;
+
     mac_addr addr = {0};
 
     for (unsigned i = 0; i < num_results; i++) {
-        rtt_result_v3 = result[i];
-        if (memcmp(addr, rtt_result_v3->rtt_result.rtt_result.addr, sizeof(mac_addr))) {
-            printMsg("Target mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
-                    rtt_result_v3->rtt_result.rtt_result.addr[0],
-                    rtt_result_v3->rtt_result.rtt_result.addr[1],
-                    rtt_result_v3->rtt_result.rtt_result.addr[2],
-                    rtt_result_v3->rtt_result.rtt_result.addr[3],
-                    rtt_result_v3->rtt_result.rtt_result.addr[4],
-                    rtt_result_v3->rtt_result.rtt_result.addr[5]);
-            memcpy(addr, rtt_result_v3->rtt_result.rtt_result.addr, sizeof(mac_addr));
-        }
-
-        printMsg("\tburst_num : %d, measurement_number : %d,\n"
-                "\tsuccess_number : %d, number_per_burst_peer : %d,\n"
-                "\tstatus : %d, retry_after_duration : %ds,\n"
-                "\ttype : %d, rssi : %d dbm, rx_rate : %d Kbps, rtt : %lu ps,\n"
-                "\trtt_sd : %lu ps, distance : %d mm, burst_duration : %d ms,\n"
-                "\tnegotiated_burst_num : %d, frequency : %d, packet_bw : %d\n",
-                rtt_result_v3->rtt_result.rtt_result.burst_num,
-                rtt_result_v3->rtt_result.rtt_result.measurement_number,
-                rtt_result_v3->rtt_result.rtt_result.success_number,
-                rtt_result_v3->rtt_result.rtt_result.number_per_burst_peer,
-                rtt_result_v3->rtt_result.rtt_result.status,
-                rtt_result_v3->rtt_result.rtt_result.retry_after_duration,
-                rtt_result_v3->rtt_result.rtt_result.type,
-                rtt_result_v3->rtt_result.rtt_result.rssi,
-                rtt_result_v3->rtt_result.rtt_result.rx_rate.bitrate * 100,
-                (unsigned long)rtt_result_v3->rtt_result.rtt_result.rtt,
-                (unsigned long)rtt_result_v3->rtt_result.rtt_result.rtt_sd,
-                rtt_result_v3->rtt_result.rtt_result.distance_mm,
-                rtt_result_v3->rtt_result.rtt_result.burst_duration,
-                rtt_result_v3->rtt_result.rtt_result.negotiated_burst_num,
-                rtt_result_v3->rtt_result.frequency,
-                rtt_result_v3->rtt_result.packet_bw);
-
-        if (rtt_result_v3->rtt_result.rtt_result.LCI) {
-            printMsg("LCI id %d\n", rtt_result_v3->rtt_result.rtt_result.LCI->id);
-            printMsg("LCI Len %d\n", rtt_result_v3->rtt_result.rtt_result.LCI->len);
-            prhex_msg("LCI data",
-                    rtt_result_v3->rtt_result.rtt_result.LCI->data,
-                    rtt_result_v3->rtt_result.rtt_result.LCI->len);
-        }
-
-        if (rtt_result_v3->rtt_result.rtt_result.LCR) {
-            printMsg("LCR id %d\n", rtt_result_v3->rtt_result.rtt_result.LCR->id);
-            printMsg("LCR Len %d\n", rtt_result_v3->rtt_result.rtt_result.LCR->len);
-            prhex_msg("LCR data",
-                    rtt_result_v3->rtt_result.rtt_result.LCR->data,
-                    rtt_result_v3->rtt_result.rtt_result.LCR->len);
-        }
-
-        if (rtt_result_v3->rtt_result.rtt_result.type == RTT_TYPE_2_SIDED_11AZ_NTB) {
-            printMsg("\t i2r_tx_ltf_repetition_cnt: %u,\n"
-                    " \t r2i_tx_ltf_repetition_cnt: %u,\n"
-                    " \t ntb min meas_time: %lu units of 100us,\n"
-                    " \t ntb max meas_time: %lu units of 10ms\n",
-                    rtt_result_v3->i2r_tx_ltf_repetition_count,
-                    rtt_result_v3->r2i_tx_ltf_repetition_count,
-                    rtt_result_v3->ntb_min_measurement_time,
-                    rtt_result_v3->ntb_max_measurement_time);
+        rtt_result_v4 = result[i];
+        if (rtt_result_v4) {
+            rtt_result_v3 = &rtt_result_v4->rtt_result_v3;
+            if (rtt_result_v3) {
+                rtt_result_v2 = &rtt_result_v3->rtt_result;
+                if (rtt_result_v2) {
+                    printMsg("RTT results: target %d\n", i);
+                    rtt_result_v1 = &rtt_result_v2->rtt_result;
+                    if (rtt_result_v1) {
+                        if (memcmp(addr, rtt_result_v1->addr, sizeof(mac_addr))) {
+                            printMsg("Target mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
+                                    rtt_result_v1->addr[0], rtt_result_v1->addr[1],
+                                    rtt_result_v1->addr[2], rtt_result_v1->addr[3],
+                                    rtt_result_v1->addr[4], rtt_result_v1->addr[5]);
+                            memcpy(addr, rtt_result_v1->addr, sizeof(mac_addr));
+                        }
+                        printMsg("\tburst_num : %d,"
+                                " measurement_number : %d,\n"
+                                "\tsuccess_number : %d,"
+                                " number_per_burst_peer : %d,\n"
+                                "\tstatus : %d,"
+                                " retry_after_duration : %ds,\n"
+                                "\ttype : %d, rssi : %d dbm, rx_rate : %d"
+                                " Kbps, rtt : %lu ps,\n"
+                                "\trtt_sd : %lu ps, distance : %d mm,"
+                                " timestamp : %lu us,\n"
+                                " burst_duration : %d ms,\n"
+                                "\tnegotiated_burst_num : %d,\n",
+                                rtt_result_v1->burst_num,
+                                rtt_result_v1->measurement_number,
+                                rtt_result_v1->success_number,
+                                rtt_result_v1->number_per_burst_peer,
+                                rtt_result_v1->status,
+                                rtt_result_v1->retry_after_duration,
+                                rtt_result_v1->type,
+                                rtt_result_v1->rssi,
+                                rtt_result_v1->rx_rate.bitrate * 100,
+                                (unsigned long)rtt_result_v1->rtt,
+                                (unsigned long)rtt_result_v1->rtt_sd,
+                                rtt_result_v1->distance_mm,
+                                rtt_result_v1->ts,
+                                rtt_result_v1->burst_duration,
+                                rtt_result_v1->negotiated_burst_num);
+
+                        if (rtt_result_v1->LCI) {
+                                printMsg("LCI id %d\n", rtt_result_v1->LCI->id);
+                                printMsg("LCI Len %d\n", rtt_result_v1->LCI->len);
+                                prhex_msg("LCI data", rtt_result_v1->LCI->data,
+                                        rtt_result_v1->LCI->len);
+                        }
+                        if (rtt_result_v1->LCR) {
+                                printMsg("LCR id %d\n", rtt_result_v1->LCR->id);
+                                printMsg("LCR Len %d\n", rtt_result_v1->LCR->len);
+                                prhex_msg("LCR data", rtt_result_v1->LCR->data,
+                                        rtt_result_v1->LCR->len);
+                        }
+                    }
+                    printMsg("\tfrequency : %d, packet_bw : %d\n",
+                            rtt_result_v2->frequency, rtt_result_v2->packet_bw);
+                }
+
+                if ((rtt_result_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB) ||
+                        (rtt_result_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)) {
+                        printMsg("\ti2r_tx_ltf_repetition_cnt: %u,\n"
+                                " \tr2i_tx_ltf_repetition_cnt: %u,\n"
+                                " \tntb min meas_time: %lu units of 100us,\n"
+                                " \tntb max meas_time: %lu units of 10ms\n"
+                                " \tnum_tx_sts: %u,\n"
+                                " \tnum_rx_sts: %u,\n",
+                                rtt_result_v3->i2r_tx_ltf_repetition_count,
+                                rtt_result_v3->r2i_tx_ltf_repetition_count,
+                                rtt_result_v3->ntb_min_measurement_time,
+                                rtt_result_v3->ntb_max_measurement_time,
+                                rtt_result_v3->num_tx_sts,
+                                rtt_result_v3->num_rx_sts);
+                }
+            }
+
+            if (rtt_result_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE) {
+                printMsg("\tis_ranging_protection_enabled: %u,\n"
+                        " \tis_secure_he_ltf_enabled: %u,\n"
+                        " \trtt_akm %x,\n"
+                        " \tcipher_suite %x,\n"
+                        " \tsecure_he_ltf_protocol_version %d\n",
+                        rtt_result_v4->is_ranging_protection_enabled,
+                        rtt_result_v4->is_secure_he_ltf_enabled,
+                        rtt_result_v4->base_akm,
+                        rtt_result_v4->cipher_suite,
+                        rtt_result_v4->secure_he_ltf_protocol_version);
+            }
         }
     }
 
@@ -1545,7 +1598,12 @@ static void testRTT()
     int result = 0;
     /* Run by a provided rtt-ap-list file */
     FILE* w_fp = NULL;
-    wifi_rtt_config_v3 params[max_ap];
+    wifi_rtt_config_v4 params[max_ap];
+    wifi_rtt_config *rtt_config_v1 = NULL;
+    wifi_rtt_config_v3 *rtt_config = NULL;
+    wifi_rtt_secure_config *rtt_secure_config = NULL;
+
+    memset(params, 0, sizeof(wifi_rtt_config_v4));
 
     if (!rtt_from_file && !rtt_sta && !rtt_nan) {
         /* band filter for a specific band */
@@ -1574,98 +1632,127 @@ static void testRTT()
                 printMsg("failed to open the file : %s\n", rtt_aplist);
                 return;
             }
-            fprintf(w_fp, "|SSID|BSSID|Primary Freq|Center Freq|Channel BW(0=20MHZ,1=40MZ,2=80MHZ)\n"
-                    "is_6g|rtt_type(1=1WAY,2=2WAY,3=auto)|Peer Type(STA=0, AP=1)|burst period|\n"
-                    "Num of Burst|FTM retry count|FTMR retry count|LCI|LCR|\n"
-                    "Burst Duration|Preamble|BW||NTB Min Meas Time in units of 100us|\n"
-                    "NTB Max Meas Time in units of 10ms\n");
+            fprintf(w_fp, "|SSID|BSSID|Channel|Channel BW(0=20MHZ,1=40MZ,2=80MHZ)\n"
+                    "is_6g | rtt_type(1=1WAY,2=2WAY,3=auto)| Peer Type(STA=0, AP=1)|burst period|\n"
+                    "Num of Burst | num_frames_per_burst | num_retries_per_rtt_frame| num_retries_per_ftmr | LCI| LCR|\n"
+                    "Burst Duration|Preamble| NTB Min Meas Time in units of 100us|\n"
+                    "NTB Max Meas Time in units of 10ms\n | "
+                    "RTT_AKM | RTT_CIPHER_TYPE | Enabled_secure_LTF\n"
+                    "Enable_Ranging_Config | PASSPHRASE\n");
         }
 
         for (int i = 0; i < min(num_results, max_ap); i++) {
             scan_param = results[i];
+
             if(is11mcAP(&scan_param->ie_data[0], scan_param->ie_length)) {
-                memcpy(params[num_ap].rtt_config.addr, scan_param->bssid,
-                        sizeof(mac_addr));
-                mac_addr &addr = params[num_ap].rtt_config.addr;
+                rtt_config = &params[num_ap].rtt_config;
+                rtt_secure_config = &params[num_ap].rtt_secure_config;
+                rtt_config_v1 = &rtt_config->rtt_config;
+
+                if (!rtt_config || !rtt_secure_config || !rtt_config_v1) {
+                    printMsg("Failed to allocate while reading the file!");
+                    return;
+                }
+
+                memcpy(rtt_config_v1->addr, scan_param->bssid, sizeof(mac_addr));
+                mac_addr &addr = rtt_config_v1->addr;
                 printMsg("Adding %s(%02x:%02x:%02x:%02x:%02x:%02x) on Freq (%d) for %s type RTT\n",
                         scan_param->ssid, addr[0], addr[1],
                         addr[2], addr[3], addr[4], addr[5],
                         scan_param->channel, RttTypeToString(type));
-
-                if (type > RTT_TYPE_2_SIDED_11AZ_NTB) {
-                    printf("Unsupported rtt_type %d, exit!!\n", type);
-                    return;
-                }
-                params[num_ap].rtt_config.type = type;
-                params[num_ap].rtt_config.channel = get_channel_of_ie(&scan_param->ie_data[0],
-                        scan_param->ie_length);
-                params[num_ap].rtt_config.peer = RTT_PEER_AP;
-                params[num_ap].rtt_config.num_burst = default_rtt_param.num_burst;
-                params[num_ap].rtt_config.num_frames_per_burst =
+                rtt_config_v1->type = type;
+                rtt_config_v1->channel =
+                        get_channel_of_ie(&scan_param->ie_data[0], scan_param->ie_length);
+                rtt_config_v1->peer = RTT_PEER_AP;
+                rtt_config_v1->num_burst = default_rtt_param.num_burst;
+                rtt_config_v1->num_frames_per_burst =
                         default_rtt_param.num_frames_per_burst;
-                params[num_ap].rtt_config.num_retries_per_rtt_frame =
+                rtt_config_v1->num_retries_per_rtt_frame =
                         default_rtt_param.num_retries_per_ftm;
-                params[num_ap].rtt_config.num_retries_per_ftmr =
+                rtt_config_v1->num_retries_per_ftmr =
                         default_rtt_param.num_retries_per_ftmr;
-                params[num_ap].rtt_config.burst_period = default_rtt_param.burst_period;
-                params[num_ap].rtt_config.burst_duration = default_rtt_param.burst_duration;
-                params[num_ap].rtt_config.LCI_request = default_rtt_param.LCI_request;
-                params[num_ap].rtt_config.LCR_request = default_rtt_param.LCR_request;
-                params[num_ap].rtt_config.preamble = (wifi_rtt_preamble)default_rtt_param.preamble;
-                params[num_ap].rtt_config.bw = convert_channel_width_to_rtt_bw(channel_width);
-                if (params[num_ap].rtt_config.bw == WIFI_RTT_BW_5) {
+                rtt_config_v1->burst_period = default_rtt_param.burst_period;
+                rtt_config_v1->burst_duration = default_rtt_param.burst_duration;
+                rtt_config_v1->LCI_request = default_rtt_param.LCI_request;
+                rtt_config_v1->LCR_request = default_rtt_param.LCR_request;
+                rtt_config_v1->preamble = (wifi_rtt_preamble)default_rtt_param.preamble;
+                rtt_config_v1->bw = convert_channel_width_to_rtt_bw(channel_width);
+                if (rtt_config_v1->bw == WIFI_RTT_BW_5) {
                     printf("Unsupported rtt bw %x \n",
-                            params[num_ap].rtt_config.bw);
+                            rtt_config_v1->bw);
                     return;
                 }
-                if (params[num_ap].rtt_config.type == RTT_TYPE_2_SIDED_11AZ_NTB) {
-                    params[num_ap].rtt_config.num_frames_per_burst =
+
+                if ((rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB) ||
+                        (rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)) {
+                    rtt_config_v1->num_frames_per_burst =
                             default_rtt_param_v3.num_frames_per_burst;
-                    printf("num_frames_per_burst %d \n",
-                            params[num_ap].rtt_config.num_frames_per_burst);
-                    if (!ntb_min_meas_time) {
-                        params[num_ap].ntb_min_measurement_time =
+
+                    rtt_config->ntb_min_measurement_time = ntb_min_meas_time;
+                    rtt_config->ntb_max_measurement_time = ntb_max_meas_time;
+
+                    if (!rtt_config->ntb_min_measurement_time) {
+                        rtt_config->ntb_min_measurement_time =
                                 default_rtt_param_v3.ntb_min_measurement_time;
-                    } else {
-                        params[num_ap].ntb_min_measurement_time =
-                                ntb_min_meas_time;
-                    }
-                    if (!ntb_max_meas_time) {
-                         params[num_ap].ntb_max_measurement_time =
-                                default_rtt_param_v3.ntb_max_measurement_time;
-                    } else {
-                        params[num_ap].ntb_max_measurement_time =
-                                ntb_max_meas_time;
                     }
+
+                   if (!rtt_config->ntb_max_measurement_time) {
+                       rtt_config->ntb_max_measurement_time =
+                               default_rtt_param_v3.ntb_max_measurement_time;
+                   }
+
+                    printf("file: num_frames_per_burst %d, ntb_min %lld, ntb_max %lld\n",
+                            rtt_config_v1->num_frames_per_burst,
+                            rtt_config->ntb_min_measurement_time,
+                            rtt_config->ntb_max_measurement_time);
                 }
+
+                if (rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE) {
+                        rtt_secure_config->pasn_config.base_akm = base_akm;
+                        rtt_secure_config->pasn_config.pairwise_cipher_suite = pairwise_cipher_suite;
+                        if (passphrase_len) {
+                            memcpy(rtt_secure_config->pasn_config.passphrase,
+                                    passphrase, passphrase_len);
+                            rtt_secure_config->pasn_config.passphrase_len = passphrase_len;
+                        }
+                        rtt_secure_config->enable_secure_he_ltf = enable_secure_he_ltf;
+                        rtt_secure_config->enable_ranging_frame_protection = enable_ranging_frame_protection;
+                }
+
                 if (rtt_to_file) {
                     fprintf(w_fp, "%s %02x:%02x:%02x:%02x:%02x:%02x"
                             " %d %d %d %d %d %d %d %d %d "
-                            "%d %d %d %d %d %d %lu %lu\n",
+                            "%d %d %d %d %d %d %lu %lu\n"
+                            "%d %d %s %d %d\n",
                             scan_param->ssid,
-                            params[num_ap].rtt_config.addr[0],
-                            params[num_ap].rtt_config.addr[1],
-                            params[num_ap].rtt_config.addr[2],
-                            params[num_ap].rtt_config.addr[3],
-                            params[num_ap].rtt_config.addr[4],
-                            params[num_ap].rtt_config.addr[5],
-                            params[num_ap].rtt_config.channel.center_freq,
-                            params[num_ap].rtt_config.channel.center_freq0,
-                            params[num_ap].rtt_config.channel.width,
-                            params[num_ap].rtt_config.type,
-                            params[num_ap].rtt_config.peer,
-                            params[num_ap].rtt_config.burst_period,
-                            params[num_ap].rtt_config.num_burst,
-                            params[num_ap].rtt_config.num_frames_per_burst,
-                            params[num_ap].rtt_config.num_retries_per_rtt_frame,
-                            params[num_ap].rtt_config.num_retries_per_ftmr,
-                            params[num_ap].rtt_config.LCI_request,
-                            params[num_ap].rtt_config.LCR_request,
-                            params[num_ap].rtt_config.burst_duration,
-                            params[num_ap].rtt_config.preamble,
-                            params[num_ap].rtt_config.bw,
-                            params[num_ap].ntb_min_measurement_time,
-                            params[num_ap].ntb_max_measurement_time);
+                            rtt_config_v1->addr[0],
+                            rtt_config_v1->addr[1],
+                            rtt_config_v1->addr[2],
+                            rtt_config_v1->addr[3],
+                            rtt_config_v1->addr[4],
+                            rtt_config_v1->addr[5],
+                            rtt_config_v1->channel.center_freq,
+                            rtt_config_v1->channel.center_freq0,
+                            rtt_config_v1->channel.width,
+                            rtt_config_v1->type,
+                            rtt_config_v1->peer,
+                            rtt_config_v1->burst_period,
+                            rtt_config_v1->num_burst,
+                            rtt_config_v1->num_frames_per_burst,
+                            rtt_config_v1->num_retries_per_rtt_frame,
+                            rtt_config_v1->num_retries_per_ftmr,
+                            rtt_config_v1->LCI_request,
+                            rtt_config_v1->LCR_request,
+                            rtt_config_v1->burst_duration,
+                            rtt_config_v1->preamble,
+                            rtt_config_v1->bw,
+                            rtt_config->ntb_min_measurement_time,
+                            rtt_config->ntb_max_measurement_time,
+                            rtt_secure_config->pasn_config.base_akm,
+                            rtt_secure_config->pasn_config.pairwise_cipher_suite,
+                            rtt_secure_config->pasn_config.passphrase,
+                            rtt_secure_config->enable_secure_he_ltf,
+                            rtt_secure_config->enable_ranging_frame_protection);
                 }
                 num_ap++;
             } else {
@@ -1683,63 +1770,89 @@ static void testRTT()
         printf(" Run initiator rtt sta/nan, rtt_sta = %d, rtt_nan = %d \n",
                 rtt_sta, rtt_nan);
         /* As we have only one target */
-        memcpy(params[num_sta].rtt_config.addr, responder_addr, sizeof(mac_addr));
-        params[num_sta].rtt_config.channel =
-                convert_channel(responder_channel, channel_width, is_6g);
+        rtt_config = &params[num_sta].rtt_config;
+        rtt_secure_config = &params[num_sta].rtt_secure_config;
+        if (!rtt_config || !rtt_secure_config) {
+                printMsg("Failed to allocate for single target ranging! rtt_sta = %d, rtt_nan = %d \n",
+                        rtt_sta, rtt_nan);
+                return;
+        }
+
+        rtt_config_v1 = &rtt_config->rtt_config;
+        if (!rtt_config_v1) {
+            printMsg("Failed to allocate rtt_config_v1 for single target ranging! rtt_sta = %d, rtt_nan = %d \n",
+                    rtt_sta, rtt_nan);
+            return;
+        }
+
+        memcpy(rtt_config_v1->addr, responder_addr, sizeof(mac_addr));
+        rtt_config_v1->channel = convert_channel(responder_channel, channel_width, is_6g);
         printMsg("Adding(" MACSTR ") on Freq (%d) for %s RTT\n",
-                MAC2STR(responder_addr),
-                params[num_sta].rtt_config.channel.center_freq,
+                MAC2STR(responder_addr), rtt_config_v1->channel.center_freq,
                 RttTypeToString(type));
-        if (type > RTT_TYPE_2_SIDED_11AZ_NTB) {
-             printf("Unsupported rtt_type %d, exit!!\n", type);
-             return;
-        }
         /*As we are doing STA-STA RTT */
-        params[num_sta].rtt_config.type = type;
+        rtt_config_v1->type = type;
         if (rtt_nan) {
-            params[num_sta].rtt_config.peer = RTT_PEER_NAN;
+            rtt_config_v1->peer = RTT_PEER_NAN;
         } else if (rtt_sta) {
-            params[num_sta].rtt_config.peer = RTT_PEER_STA;
-        }
-        params[num_sta].rtt_config.num_burst = default_rtt_param.num_burst;
-        params[num_sta].rtt_config.num_frames_per_burst = default_rtt_param.num_frames_per_burst;
-        params[num_sta].rtt_config.num_retries_per_rtt_frame =
-            default_rtt_param.num_retries_per_ftm;
-        params[num_sta].rtt_config.num_retries_per_ftmr = default_rtt_param.num_retries_per_ftmr;
-        params[num_sta].rtt_config.burst_period = default_rtt_param.burst_period;
-        params[num_sta].rtt_config.burst_duration = default_rtt_param.burst_duration;
-        params[num_sta].rtt_config.LCI_request = default_rtt_param.LCI_request;
-        params[num_sta].rtt_config.LCR_request = default_rtt_param.LCR_request;
-        params[num_sta].rtt_config.preamble = (wifi_rtt_preamble)default_rtt_param.preamble;
-        params[num_sta].rtt_config.bw = convert_channel_width_to_rtt_bw(channel_width);
-        if (params[num_sta].rtt_config.bw == WIFI_RTT_BW_5) {
+            rtt_config_v1->peer = RTT_PEER_STA;
+        }
+        rtt_config_v1->num_burst = default_rtt_param.num_burst;
+        rtt_config_v1->num_frames_per_burst = default_rtt_param.num_frames_per_burst;
+        rtt_config_v1->num_retries_per_rtt_frame = default_rtt_param.num_retries_per_ftm;
+        rtt_config_v1->num_retries_per_ftmr = default_rtt_param.num_retries_per_ftmr;
+        rtt_config_v1->burst_period = default_rtt_param.burst_period;
+        rtt_config_v1->burst_duration = default_rtt_param.burst_duration;
+        rtt_config_v1->LCI_request = default_rtt_param.LCI_request;
+        rtt_config_v1->LCR_request = default_rtt_param.LCR_request;
+        rtt_config_v1->preamble = (wifi_rtt_preamble)default_rtt_param.preamble;
+        rtt_config_v1->bw = convert_channel_width_to_rtt_bw(channel_width);
+
+        if (rtt_config_v1->bw == WIFI_RTT_BW_5) {
             printf("Unsupported rtt bw %x \n",
-                    params[num_sta].rtt_config.bw);
+                    rtt_config_v1->bw);
             return;
         }
 
-        if (params[num_sta].rtt_config.type == RTT_TYPE_2_SIDED_11AZ_NTB) {
-            params[num_sta].rtt_config.num_frames_per_burst =
+        if ((rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB) ||
+                (rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)) {
+            rtt_config_v1->num_frames_per_burst =
                     default_rtt_param_v3.num_frames_per_burst;
 
-            printf("num_frames_per_burst %d \n",
-                    params[num_sta].rtt_config.num_frames_per_burst);
-            if (!ntb_min_meas_time) {
-                params[num_sta].ntb_min_measurement_time =
-                        default_rtt_param_v3.ntb_min_measurement_time;
-                } else {
-                    params[num_sta].ntb_min_measurement_time =
-                            ntb_min_meas_time;
-                }
-                if (!ntb_max_meas_time) {
-                    params[num_sta].ntb_max_measurement_time =
-                            default_rtt_param_v3.ntb_max_measurement_time;
-                } else {
-                    params[num_sta].ntb_max_measurement_time =
-                            ntb_max_meas_time;
-                }
+            rtt_config->ntb_min_measurement_time =
+                    ntb_min_meas_time;
+
+            rtt_config->ntb_max_measurement_time =
+                         ntb_max_meas_time;
+
+            if (!rtt_config->ntb_min_measurement_time) {
+                rtt_config->ntb_min_measurement_time =
+                    default_rtt_param_v3.ntb_min_measurement_time;
+            }
+
+            if (!rtt_config->ntb_max_measurement_time) {
+                rtt_config->ntb_max_measurement_time =
+                         default_rtt_param_v3.ntb_max_measurement_time;
+            }
+
+            printf("single target: type %d num_frames_per_burst %d, ntb_min %lld, ntb_max %lld\n",
+                    rtt_config_v1->type,
+                    rtt_config_v1->num_frames_per_burst,
+                    rtt_config->ntb_min_measurement_time,
+                    rtt_config->ntb_max_measurement_time);
         }
 
+        if (rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE) {
+            rtt_secure_config->pasn_config.base_akm = base_akm;
+            rtt_secure_config->pasn_config.pairwise_cipher_suite = pairwise_cipher_suite;
+            if (passphrase_len) {
+                memcpy(rtt_secure_config->pasn_config.passphrase,
+                        passphrase, passphrase_len);
+                rtt_secure_config->pasn_config.passphrase_len = passphrase_len;
+            }
+            rtt_secure_config->enable_secure_he_ltf = enable_secure_he_ltf;
+            rtt_secure_config->enable_ranging_frame_protection = enable_ranging_frame_protection;
+        }
         num_sta++;
 
     } else {
@@ -1747,9 +1860,11 @@ static void testRTT()
         FILE* fp;
         char bssid[ETHER_ADDR_STR_LEN];
         char ssid[MAX_SSID_LEN];
+        char passphrase[RTT_SECURITY_MAX_PASSPHRASE_LEN];
         char first_char;
         memset(bssid, 0, sizeof(bssid));
         memset(ssid, 0, sizeof(ssid));
+        memset(passphrase, 0, sizeof(passphrase));
         memset(params, 0, sizeof(params));
 
         /* Read a RTT AP list from a file */
@@ -1760,10 +1875,13 @@ static void testRTT()
                     "  by following order in file, such as:\n"
                     "SSID | BSSID | chan_num | Channel BW(0=20MHZ,1=40MZ,2=80MHZ)| is_6g |"
                     " RTT_Type(1=1WAY,2=2WAY,3=auto) |Peer Type(STA=0, AP=1)| Burst Period|"
-                    " No of Burst| No of FTM Burst| FTM Retry Count| FTMR Retry Count| LCI| LCR|"
-                    " Burst Duration| Preamble|Channel_Bandwith|"
-                    " NTB Min Meas Time in units of 100us|\n",
-                    " NTB Max Meas Time in units of 10ms\n",
+                    " No of Burst| num_frames_per_burst | num_retries_per_rtt_frame|"
+                    " num_retries_per_ftmr | LCI| LCR|"
+                    " Burst Duration| Preamble |"
+                    " NTB Min Meas Time in units of 100us|"
+                    " NTB Max Meas Time in units of 10ms |"
+                    " RTT_AKM | CIPHER_TYPE |"
+                    " enable_secure_he_ltf | enable_ranging_frame_protection | PASSPHRASE\n",
                     rtt_aplist, DEFAULT_RTT_FILE);
             return;
         }
@@ -1776,61 +1894,102 @@ static void testRTT()
                     break;
                 }
 
-                result = fscanf(fp,"%s %s %u %u %u %u\n",
+                rtt_config = &params[i].rtt_config;
+                rtt_secure_config = &params[i].rtt_secure_config;
+                if (!rtt_config || !rtt_secure_config) {
+                    printMsg("Failed to allocate for multi target ranging!\n");
+                    return;
+                }
+
+                rtt_config_v1 = &rtt_config->rtt_config;
+                if (!rtt_config_v1) {
+                    printMsg("rtt_config_v1 is null\n");
+                    break;
+                }
+
+                result = fscanf(fp,"%s %s %d %d %d %d\n",
                         ssid, bssid, (unsigned int*)&responder_channel,
                         (unsigned int*)&channel_width,
                         (unsigned int*)&is_6g,
-                        (unsigned int*)&params[i].rtt_config.type);
+                        (unsigned int*)&rtt_config_v1->type);
                 if (result != 6) {
-                    printMsg("fscanf failed to read ssid, bssid, channel, width, is_6g, type. err: %d\n", result);
-                    break;
-                }
-
-                if (params[i].rtt_config.type > RTT_TYPE_2_SIDED_11AZ_NTB) {
-                    printf("Unsupported rtt_type %d, exit!!\n", type);
+                    printMsg("fscanf failed to read ssid, bssid, "
+                            "channel, width, is_6g, type. err: %d\n", result);
                     break;
                 }
 
-                result = fscanf(fp, "%u %u %u %u %u %u %hhu %hhu %u %hhu\n",
-                        (unsigned int*)&params[i].rtt_config.peer,
-                        &params[i].rtt_config.burst_period,
-                        &params[i].rtt_config.num_burst,
-                        &params[i].rtt_config.num_frames_per_burst,
-                        (unsigned int*)&params[i].rtt_config.num_retries_per_rtt_frame,
-                        (unsigned int*)&params[i].rtt_config.num_retries_per_ftmr,
-                        (unsigned char*)&params[i].rtt_config.LCI_request,
-                        (unsigned char*)&params[i].rtt_config.LCR_request,
-                        (unsigned int*)&params[i].rtt_config.burst_duration,
-                        (unsigned char*)&params[i].rtt_config.preamble);
+                result = fscanf(fp, "%d %d %d %d %d %d %hhu %hhu %d %hhu\n",
+                        (unsigned int*)&rtt_config_v1->peer,
+                        (unsigned int*)&rtt_config_v1->burst_period,
+                        (unsigned int*)&rtt_config_v1->num_burst,
+                        (unsigned int*)&rtt_config_v1->num_frames_per_burst,
+                        (unsigned int*)&rtt_config_v1->num_retries_per_rtt_frame,
+                        (unsigned int*)&rtt_config_v1->num_retries_per_ftmr,
+                        (unsigned char*)&rtt_config_v1->LCI_request,
+                        (unsigned char*)&rtt_config_v1->LCR_request,
+                        (unsigned int*)&rtt_config_v1->burst_duration,
+                        (unsigned char*)&rtt_config_v1->preamble);
                 if (result != 10) {
                     printMsg("fscanf failed to read mc params %d\n", result);
                     break;
                 }
-                params[i].rtt_config.bw = convert_channel_width_to_rtt_bw(channel_width);
-                if (params[i].rtt_config.bw == WIFI_RTT_BW_5) {
-                    printf("Unsupported rtt bw %x \n", params[i].rtt_config.bw);
+
+                rtt_config_v1->bw = convert_channel_width_to_rtt_bw(channel_width);
+                if (rtt_config_v1->bw == WIFI_RTT_BW_5) {
+                    printf("Unsupported rtt bw %x \n", rtt_config_v1->bw);
                     break;
                 }
 
-                if (params[i].rtt_config.type == RTT_TYPE_2_SIDED_11AZ_NTB) {
-                    result = fscanf(fp, "%14lu %14lu\n",
-                            &params[i].ntb_min_measurement_time,
-                            &params[i].ntb_max_measurement_time);
+                if ((rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB) ||
+                        (rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)) {
+                    result = fscanf(fp, "%lld %lld\n",
+                            (unsigned long int*)&rtt_config->ntb_min_measurement_time,
+                            (unsigned long int*)&rtt_config->ntb_max_measurement_time);
                     if (result != 2) {
-                        printMsg("fscanf failed to read az params %d\n", result);
+                        printMsg("fscanf failed to read ntb min and max params %d\n", result);
+                        break;
+                    }
+                    printMsg("ap-list: ntb_min_measurement_time: %lld\n"
+                                " ntb_max_measurement_time: %lld\n",
+                                rtt_config->ntb_min_measurement_time,
+                                rtt_config->ntb_max_measurement_time);
+                }
+
+                if (rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE) {
+                    result = fscanf(fp, "%u %u %u %u %s\n",
+                            (unsigned int*)&rtt_secure_config->pasn_config.base_akm,
+                            (unsigned int*)&rtt_secure_config->pasn_config.pairwise_cipher_suite,
+                            (unsigned int*)&rtt_secure_config->enable_secure_he_ltf,
+                            (unsigned int*)&rtt_secure_config->enable_ranging_frame_protection,
+                            passphrase);
+                    if (result != 5) {
+                        printMsg("fscanf failed to read secure az params %d\n", result);
                         break;
                     }
                 }
 
-                params[i].rtt_config.channel = convert_channel(responder_channel,
+                if (rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE) {
+                    if (strlen(passphrase) > RTT_SECURITY_MAX_PASSPHRASE_LEN) {
+                        printMsg("Invalid passphrase\n");
+                        break;
+                    } else {
+                        rtt_secure_config->pasn_config.passphrase_len =
+                                min(strlen(passphrase), (RTT_SECURITY_MAX_PASSPHRASE_LEN - 1));
+
+                        memcpy(rtt_secure_config->pasn_config.passphrase,
+                                passphrase, rtt_secure_config->pasn_config.passphrase_len);
+                    }
+                }
+
+                rtt_config_v1->channel = convert_channel(responder_channel,
                         channel_width, is_6g);
-                parseMacAddress(bssid, params[i].rtt_config.addr);
+                parseMacAddress(bssid, rtt_config_v1->addr);
 
-                printMsg("Target: [%d]: ssid: %-16s\n"
+                printMsg("ap-list: Target: [%d]: ssid: %-16s\n"
                         " BSSID:%-20s\n"
                         " center freq: %-8u\n"
                         " center freq0:%-14u\n"
-                        " channel_width: %-12d\n"
+                        " width: %-12d\n"
                         " Type:%-15s\n"
                         " peer:%-10u\n"
                         " burst_period:%-16u\n"
@@ -1842,28 +2001,36 @@ static void testRTT()
                         " LCR_request: %-15u\n"
                         " burst_duration: %-10hhu\n"
                         " preamble:%-10hhu\n"
-                        " bw:%-10hhu\n"
-                        " ntb_min_measurement_time: %-14lu\n"
-                        " ntb_max_measurement_time: %-14lu\n",
-                        i+1, ssid, bssid,
-                        params[i].rtt_config.channel.center_freq,
-                        params[i].rtt_config.channel.center_freq0,
-                        params[i].rtt_config.channel.width,
-                        RttTypeToString(params[i].rtt_config.type),
-                        params[i].rtt_config.peer,
-                        params[i].rtt_config.burst_period,
-                        params[i].rtt_config.num_burst,
-                        params[i].rtt_config.num_frames_per_burst,
-                        params[i].rtt_config.num_retries_per_rtt_frame,
-                        params[i].rtt_config.num_retries_per_ftmr,
-                        params[i].rtt_config.LCI_request,
-                        params[i].rtt_config.LCR_request,
-                        params[i].rtt_config.burst_duration,
-                        params[i].rtt_config.preamble,
-                        params[i].rtt_config.bw,
-                        params[i].ntb_min_measurement_time,
-                        params[i].ntb_max_measurement_time);
-
+                        " bw:%-10hhu\n",
+		        i+1, ssid, bssid,
+                        rtt_config_v1->channel.center_freq,
+                        rtt_config_v1->channel.center_freq0,
+                        rtt_config_v1->channel.width,
+                        RttTypeToString(rtt_config_v1->type),
+                        rtt_config_v1->peer,
+                        rtt_config_v1->burst_period,
+                        rtt_config_v1->num_burst,
+                        rtt_config_v1->num_frames_per_burst,
+                        rtt_config_v1->num_retries_per_rtt_frame,
+                        rtt_config_v1->num_retries_per_ftmr,
+                        rtt_config_v1->LCI_request,
+                        rtt_config_v1->LCR_request,
+                        rtt_config_v1->burst_duration,
+                        rtt_config_v1->preamble,
+                        rtt_config_v1->bw);
+
+                if (rtt_config_v1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE) {
+                    printMsg("ap-list: base_akm: %-10u\n"
+                            " pairwise_cipher_suite: %-10u\n"
+                            " Passphrase:%-32s\n"
+                            " enable_secure_he_ltf: %-10u\n"
+                            " enable_ranging_frame_protection: %-10u\n",
+                            rtt_secure_config->pasn_config.base_akm,
+                            rtt_secure_config->pasn_config.pairwise_cipher_suite,
+                            rtt_secure_config->pasn_config.passphrase,
+                            rtt_secure_config->enable_secure_he_ltf,
+                            rtt_secure_config->enable_ranging_frame_protection);
+                }
                 i++;
             } else {
                 /* Ignore the rest of the line. */
@@ -1885,19 +2052,19 @@ static void testRTT()
         fp = NULL;
     }
 
-    wifi_rtt_event_handler_v3 handler;
+    wifi_rtt_event_handler_v4 handler;
     memset(&handler, 0, sizeof(handler));
-    handler.on_rtt_results_v3 = &onRTTResultsV3;
+    handler.on_rtt_results_v4 = &onRTTResultsV4;
 
-    if (!rtt_to_file || rtt_sta || rtt_nan)  {
+    if (!rtt_to_file || rtt_sta || rtt_nan) {
         if (num_ap || num_sta) {
             if (num_ap) {
                 printMsg("Configuring RTT for %d APs\n", num_ap);
-                result = hal_fn.wifi_rtt_range_request_v3(rttCmdId, wlan0Handle,
+                result = hal_fn.wifi_rtt_range_request_v4(rttCmdId, wlan0Handle,
                         num_ap, params, handler);
             } else if (num_sta) {
                 printMsg("Configuring RTT for %d sta \n", num_sta);
-                result = hal_fn.wifi_rtt_range_request_v3(rttCmdId, wlan0Handle,
+                result = hal_fn.wifi_rtt_range_request_v4(rttCmdId, wlan0Handle,
                         num_sta, params, handler);
             }
 
@@ -1936,48 +2103,89 @@ static int cancelRTT()
 static void getRTTCapability()
 {
     int ret;
-    wifi_rtt_capabilities_v3 rtt_capability;
-    ret = hal_fn.wifi_get_rtt_capabilities_v3(wlan0Handle, &rtt_capability);
+    wifi_rtt_capabilities_v4 rtt_capability_v4;
+    wifi_rtt_capabilities_v3 *rtt_capab_v3 = NULL;
+    wifi_rtt_capabilities *rtt_capab = NULL;
+
+    ret = hal_fn.wifi_get_rtt_capabilities_v4(wlan0Handle, &rtt_capability_v4);
     if (ret == WIFI_SUCCESS) {
+        rtt_capab_v3 = &rtt_capability_v4.rtt_capab_v3;
+        rtt_capab = &rtt_capab_v3->rtt_capab;
+
         printMsg("Supported Capabilites of RTT :\n");
-        if (rtt_capability.rtt_capab.rtt_one_sided_supported)
-            printMsg("One side RTT is supported\n");
-        if (rtt_capability.rtt_capab.rtt_ftm_supported)
-            printMsg("FTM(11mc) RTT is supported\n");
-        if (rtt_capability.rtt_capab.lci_support)
-            printMsg("LCI is supported\n");
-        if (rtt_capability.rtt_capab.lcr_support)
-            printMsg("LCR is supported\n");
-        if (rtt_capability.rtt_capab.bw_support) {
+        if (rtt_capab->rtt_one_sided_supported)
+            printMsg("One side RTT is supported.\n");
+        if (rtt_capab->rtt_ftm_supported)
+            printMsg("FTM(11mc) RTT is supported.\n");
+        if (rtt_capab->lci_support)
+            printMsg("LCI is supported.\n");
+        if (rtt_capab->lcr_support)
+            printMsg("LCR is supported.\n");
+        if (rtt_capab->bw_support) {
             printMsg("BW(%s %s %s %s) are supported\n",
-                    (rtt_capability.rtt_capab.bw_support & BW_20_SUPPORT) ? "20MHZ" : "",
-                    (rtt_capability.rtt_capab.bw_support & BW_40_SUPPORT) ? "40MHZ" : "",
-                    (rtt_capability.rtt_capab.bw_support & BW_80_SUPPORT) ? "80MHZ" : "",
-                    (rtt_capability.rtt_capab.bw_support & BW_160_SUPPORT) ? "160MHZ" : "");
+                    (rtt_capab->bw_support & BW_20_SUPPORT) ? "20MHZ" : "",
+                    (rtt_capab->bw_support & BW_40_SUPPORT) ? "40MHZ" : "",
+                    (rtt_capab->bw_support & BW_80_SUPPORT) ? "80MHZ" : "",
+                    (rtt_capab->bw_support & BW_160_SUPPORT) ? "160MHZ" : "");
         }
-        if (rtt_capability.rtt_capab.preamble_support) {
+        if (rtt_capab->preamble_support) {
             printMsg("Preamble(%s %s %s) are supported\n",
-                    (rtt_capability.rtt_capab.preamble_support & PREAMBLE_LEGACY) ? "Legacy" : "",
-                    (rtt_capability.rtt_capab.preamble_support & PREAMBLE_HT) ? "HT" : "",
-                    (rtt_capability.rtt_capab.preamble_support & PREAMBLE_VHT) ? "VHT" : "");
+                    (rtt_capab->preamble_support & PREAMBLE_LEGACY) ? "Legacy" : "",
+                    (rtt_capab->preamble_support & PREAMBLE_HT) ? "HT" : "",
+                    (rtt_capab->preamble_support & PREAMBLE_VHT) ? "VHT" : "");
 
         }
 
-        if (rtt_capability.az_preamble_support) {
-            printMsg("AZ preamble is supported\n");
+        if (rtt_capab_v3->az_preamble_support) {
+            printMsg("AZ preamble is supported!!\n");
         }
 
-        if (rtt_capability.az_bw_support) {
-            printMsg("AZ bw is supported\n");
+        if (rtt_capab_v3->az_bw_support) {
+            printMsg("AZ BW(%s %s %s %s) are supported:\n",
+                    (rtt_capab_v3->az_bw_support & BW_20_SUPPORT) ? "20MHZ" : "",
+                    (rtt_capab_v3->az_bw_support & BW_40_SUPPORT) ? "40MHZ" : "",
+                    (rtt_capab_v3->az_bw_support & BW_80_SUPPORT) ? "80MHZ" : "",
+                    (rtt_capab_v3->az_bw_support & BW_160_SUPPORT) ? "160MHZ" : "");
         }
 
-        if (rtt_capability.ntb_initiator_supported) {
+        if (rtt_capab_v3->ntb_initiator_supported) {
             printMsg("NTB initiator is supported\n");
         }
 
-        if (rtt_capability.ntb_responder_supported) {
+        if (rtt_capab_v3->ntb_responder_supported) {
             printMsg("NTB responder is supported\n");
         }
+
+        if (rtt_capability_v4.secure_he_ltf_supported) {
+            printMsg("secure_he_ltf_supported is supported\n");
+        }
+
+        if (rtt_capability_v4.ranging_fame_protection_supported) {
+            printMsg("protected range neg meas is supported\n");
+        }
+
+        if (rtt_capability_v4.supported_akms) {
+            printMsg("Supported AKM TYPES: (%s %s %s %s %s %s %s %s %s)\n",
+                    (!rtt_capability_v4.supported_akms) ? "WPA_KEY_MGMT_NONE," : "",
+                    (rtt_capability_v4.supported_akms & WPA_KEY_MGMT_PASN) ? "WPA_KEY_MGMT_PASN," : "",
+                    (rtt_capability_v4.supported_akms & WPA_KEY_MGMT_SAE) ? "WPA_KEY_MGMT_SAE," : "",
+                    (rtt_capability_v4.supported_akms & WPA_KEY_MGMT_EAP_FT_SHA256) ? "WPA_KEY_MGMT_EAP_FT_SHA256," : "",
+                    (rtt_capability_v4.supported_akms & WPA_KEY_MGMT_FT_PSK_SHA256) ? "WPA_KEY_MGMT_FT_PSK_SHA256," : "",
+                    (rtt_capability_v4.supported_akms & WPA_KEY_MGMT_EAP_FT_SHA384) ? "WPA_KEY_MGMT_EAP_FT_SHA384," : "",
+                    (rtt_capability_v4.supported_akms & WPA_KEY_MGMT_FT_PSK_SHA384) ? "WPA_KEY_MGMT_FT_PSK_SHA384," : "",
+                    (rtt_capability_v4.supported_akms & WPA_KEY_MGMT_EAP_FILS_SHA256) ? "WPA_KEY_MGMT_EAP_FILS_SHA256," : "",
+                    (rtt_capability_v4.supported_akms & WPA_KEY_MGMT_EAP_FILS_SHA384) ? "WPA_KEY_MGMT_EAP_FILS_SHA384," : "");
+        }
+
+        if (rtt_capability_v4.supported_cipher_suites) {
+            printMsg("Supported CIPHER TYPE SUITES: (%s %s %s %s %s)\n",
+                    (!rtt_capability_v4.supported_cipher_suites) ? "WPA_CIPHER_NONE," : "",
+                    (rtt_capability_v4.supported_cipher_suites & WPA_CIPHER_CCMP_128) ? "WPA_CIPHER_CCMP_128," : "",
+                    (rtt_capability_v4.supported_cipher_suites & WPA_CIPHER_CCMP_256) ? "WPA_CIPHER_CCMP_256," : "",
+                    (rtt_capability_v4.supported_cipher_suites & WPA_CIPHER_GCMP_128) ? "WPA_CIPHER_GCMP_128," : "",
+                    (rtt_capability_v4.supported_cipher_suites & WPA_CIPHER_GCMP_256) ? "WPA_CIPHER_GCMP_256" : "");
+        }
+
     } else {
         printMsg("Could not get the rtt capabilities : %d\n", ret);
     }
@@ -4069,6 +4277,70 @@ void readRTTOptions(int argc, char *argv[]) {
                     ntb_max_meas_time = atoi(argv[j]);
                 }
             }
+
+            /* Read akm */
+            if ((argv[j+1]) && (type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)) {
+                if (isdigit(argv[j+1][0])) {
+                    j++;
+                    base_akm = (wifi_rtt_akm)atoi(argv[j]);
+                    printf("base_akm : %d\n", base_akm);
+                    printMsg("AKM TYPES: (%s %s %s %s %s %s %s %s %s)\n",
+                            (!base_akm) ? "WPA_KEY_MGMT_NONE," : "",
+                            (base_akm & WPA_KEY_MGMT_PASN) ? "WPA_KEY_MGMT_PASN," : "",
+                            (base_akm & WPA_KEY_MGMT_SAE) ? "WPA_KEY_MGMT_SAE," : "",
+                            (base_akm & WPA_KEY_MGMT_EAP_FT_SHA256) ? "WPA_KEY_MGMT_EAP_FT_SHA256," : "",
+                            (base_akm & WPA_KEY_MGMT_FT_PSK_SHA256) ? "WPA_KEY_MGMT_FT_PSK_SHA256," : "",
+                            (base_akm & WPA_KEY_MGMT_EAP_FT_SHA384) ? "WPA_KEY_MGMT_EAP_FT_SHA384," : "",
+                            (base_akm & WPA_KEY_MGMT_FT_PSK_SHA384) ? "WPA_KEY_MGMT_FT_PSK_SHA384," : "",
+                            (base_akm & WPA_KEY_MGMT_EAP_FILS_SHA256) ? "WPA_KEY_MGMT_EAP_FILS_SHA256," : "",
+                            (base_akm & WPA_KEY_MGMT_EAP_FILS_SHA384) ? "WPA_KEY_MGMT_EAP_FILS_SHA384," : "");
+                }
+            }
+
+            if ((argv[j+1]) && (type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)) {
+                /* Read cipher type */
+                if (isdigit(argv[j+1][0])) {
+                    j++;
+                    pairwise_cipher_suite = (wifi_rtt_cipher_suite)atoi(argv[j]);
+                    printf("pairwise_cipher_suite : %d\n", pairwise_cipher_suite);
+                    printMsg("PAIRWISE CIPHER TYPE SUITES: (%s %s %s %s %s)\n",
+                            (!pairwise_cipher_suite) ? "WPA_CIPHER_NONE," : "",
+                            (pairwise_cipher_suite & WPA_CIPHER_CCMP_128) ? "WPA_CIPHER_CCMP_128," : "",
+                            (pairwise_cipher_suite & WPA_CIPHER_CCMP_256) ? "WPA_CIPHER_CCMP_256," : "",
+                            (pairwise_cipher_suite & WPA_CIPHER_GCMP_128) ? "WPA_CIPHER_GCMP_128," : "",
+                            (pairwise_cipher_suite & WPA_CIPHER_GCMP_256) ? "WPA_CIPHER_GCMP_256" : "");
+                }
+            }
+
+            if ((argv[j+1]) && (type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)) {
+                /* Read enable_secure_he_ltf */
+                if (isdigit(argv[j+1][0])) {
+                    j++;
+                    enable_secure_he_ltf = atoi(argv[j]);
+                    printf("enable_secure_he_ltf : %d\n", enable_secure_he_ltf);
+                }
+            }
+
+            if ((argv[j+1]) && (type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)) {
+                /* Read enable_ranging_frame_protection */
+                if (isdigit(argv[j+1][0])) {
+                    j++;
+                    enable_ranging_frame_protection = atoi(argv[j]);
+                    printf("enable_ranging_frame_protection : %d\n", enable_ranging_frame_protection);
+                }
+            }
+
+            if ((argv[j+1]) && (type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)) {
+                /* Read passphrase */
+                j++;
+                val_p = argv[j];
+                passphrase_len = strlen(val_p);
+                ret = set_interface_params(passphrase, val_p, passphrase_len);
+                if (ret != WIFI_SUCCESS) {
+                    printMsg("Failed to configure passphrase\n");
+                    return;
+                }
+            }
         }
     }
 }
@@ -4434,9 +4706,57 @@ const char *rates[] = {
     "HT N/A   | VHT/HE MCS11 NSS2",
 };
 
+const char *rates_vht[] = {
+    "OFDM/LEGACY 1Mbps",
+    "OFDM/LEGACY 2Mbps",
+    "OFDM/LEGACY 5.5Mbps",
+    "OFDM/LEGACY 6Mbps",
+    "OFDM/LEGACY 9Mbps",
+    "OFDM/LEGACY 11Mbps",
+    "OFDM/LEGACY 12Mbps",
+    "OFDM/LEGACY 18Mbps",
+    "OFDM/LEGACY 24Mbps",
+    "OFDM/LEGACY 36Mbps",
+    "OFDM/LEGACY 48Mbps",
+    "OFDM/LEGACY 54Mbps",
+    "HT MCS0  | VHT/HE MCS0  NSS1",
+    "HT MCS1  | VHT/HE MCS1  NSS1",
+    "HT MCS2  | VHT/HE MCS2  NSS1",
+    "HT MCS3  | VHT/HE MCS3  NSS1",
+    "HT MCS4  | VHT/HE MCS4  NSS1",
+    "HT MCS5  | VHT/HE MCS5  NSS1",
+    "HT MCS6  | VHT/HE MCS6  NSS1",
+    "HT MCS7  | VHT/HE MCS7  NSS1",
+    "HT MCS8  | VHT/HE MCS8  NSS1",
+    "HT MCS9  | VHT/HE MCS9  NSS1",
+    "HT MCS10 | VHT/HE MCS10 NSS1",
+    "HT MCS11 | VHT/HE MCS11 NSS1",
+    "HT MCS12 | VHT/HE MCS0  NSS2",
+    "HT MCS13 | VHT/HE MCS1  NSS2",
+    "HT MCS14 | VHT/HE MCS2  NSS2",
+    "HT MCS15 | VHT/HE MCS3  NSS2",
+};
+
+const char *rates_ht[] = {
+    "OFDM/LEGACY 1Mbps",
+    "OFDM/LEGACY 2Mbps",
+    "OFDM/LEGACY 5.5Mbps",
+    "OFDM/LEGACY 6Mbps",
+    "OFDM/LEGACY 9Mbps",
+    "OFDM/LEGACY 11Mbps",
+    "OFDM/LEGACY 12Mbps",
+    "OFDM/LEGACY 18Mbps",
+    "OFDM/LEGACY 24Mbps",
+    "OFDM/LEGACY 36Mbps",
+    "OFDM/LEGACY 48Mbps",
+    "OFDM/LEGACY 54Mbps",
+};
+
 /* Legacy rates */
-#define NUM_RATES (sizeof(rates)/sizeof(rates[0]))
+#define MAX_NUM_RATES (sizeof(rates)/sizeof(rates[0]))
 #define NUM_EHT_RATES (sizeof(eht_rates)/sizeof(eht_rates[0]))
+#define NUM_VHT_RATES (sizeof(rates_vht)/sizeof(rates_vht[0]))
+#define NUM_HT_RATES  (sizeof(rates_ht)/sizeof(rates_ht[0]))
 
 #define RATE_SPEC_STR_LEN       10
 #define RATE_SPEC_CHECK_INDEX   27
@@ -4459,6 +4779,7 @@ const short int rate_stat_bandwidth[] = {
 
 int radios = 0;
 int ml_links = 0;
+bool ml_data = false;
 
 wifi_radio_stat rx_stat[MAX_NUM_RADIOS];
 wifi_channel_stat cca_stat[MAX_CH_BUF_SIZE];
@@ -4481,10 +4802,18 @@ void updateRateStats(u8 **buf, int num_rates) {
             printMsg("%-28s  %10d   %10d     %10d      %10d\n",
                 eht_rates[k], local_ratestat_ptr->tx_mpdu, local_ratestat_ptr->rx_mpdu,
                     local_ratestat_ptr->mpdu_lost, local_ratestat_ptr->retries);
-        } else if (num_rates == NUM_RATES) {
+        } else if (num_rates == MAX_NUM_RATES) {
             printMsg("%-28s  %10d   %10d     %10d      %10d\n",
                 rates[k], local_ratestat_ptr->tx_mpdu, local_ratestat_ptr->rx_mpdu,
                     local_ratestat_ptr->mpdu_lost, local_ratestat_ptr->retries);
+        } else if (num_rates == NUM_RATE_VHT) {
+            printMsg("%-28s  %10d   %10d     %10d      %10d\n",
+                rates_vht[k], local_ratestat_ptr->tx_mpdu, local_ratestat_ptr->rx_mpdu,
+                    local_ratestat_ptr->mpdu_lost, local_ratestat_ptr->retries);
+        } else if (num_rates == NUM_RATE_HT) {
+            printMsg("%-28s  %10d   %10d     %10d      %10d\n",
+                rates_ht[k], local_ratestat_ptr->tx_mpdu, local_ratestat_ptr->rx_mpdu,
+                    local_ratestat_ptr->mpdu_lost, local_ratestat_ptr->retries);
         } else {
             printMsg("num_rates %d value is not supported\n", num_rates);
             continue;
@@ -4511,8 +4840,10 @@ void update_peer_info_per_link(u8 **buf) {
         return;
     }
 
-    if ((local_peer_ptr->num_rate == NUM_RATES) ||
-        (local_peer_ptr->num_rate == NUM_EHT_RATES)) {
+    if ((local_peer_ptr->num_rate == MAX_NUM_RATES) ||
+        (local_peer_ptr->num_rate == NUM_EHT_RATES) ||
+        (local_peer_ptr->num_rate == NUM_RATE_HT) ||
+        (local_peer_ptr->num_rate == NUM_RATE_VHT)) {
         printPeerinfoStats(local_peer_ptr);
         *buf += offsetof(wifi_peer_info, rate_stats);
         if (!*buf) {
@@ -4541,23 +4872,12 @@ void printPerLinkStats(wifi_link_stat *local_link_ptr, int link_id) {
     printMsg("RSSI mgmt = %d\n", local_link_ptr->rssi_mgmt);
     printMsg("RSSI data = %d\n", local_link_ptr->rssi_data);
     printMsg("RSSI ack = %d\n", local_link_ptr->rssi_ack);
-    printMsg("AC_BE:\n");
-    printMsg("txmpdu = %d\n", local_link_ptr->ac[WIFI_AC_BE].tx_mpdu);
-    printMsg("rxmpdu = %d\n", local_link_ptr->ac[WIFI_AC_BE].rx_mpdu);
-    printMsg("mpdu_lost = %d\n", local_link_ptr->ac[WIFI_AC_BE].mpdu_lost);
-    printMsg("retries = %d\n", local_link_ptr->ac[WIFI_AC_BE].retries);
-    printMsg("AC_BK:\n");
-    printMsg("txmpdu = %d\n", local_link_ptr->ac[WIFI_AC_BK].tx_mpdu);
-    printMsg("rxmpdu = %d\n", local_link_ptr->ac[WIFI_AC_BK].rx_mpdu);
-    printMsg("mpdu_lost = %d\n", local_link_ptr->ac[WIFI_AC_BK].mpdu_lost);
-    printMsg("AC_VI:\n");
-    printMsg("txmpdu = %d\n", local_link_ptr->ac[WIFI_AC_VI].tx_mpdu);
-    printMsg("rxmpdu = %d\n", local_link_ptr->ac[WIFI_AC_VI].rx_mpdu);
-    printMsg("mpdu_lost = %d\n", local_link_ptr->ac[WIFI_AC_VI].mpdu_lost);
-    printMsg("AC_VO:\n");
-    printMsg("txmpdu = %d\n", local_link_ptr->ac[WIFI_AC_VO].tx_mpdu);
-    printMsg("rxmpdu = %d\n", local_link_ptr->ac[WIFI_AC_VO].rx_mpdu);
-    printMsg("mpdu_lost = %d\n", local_link_ptr->ac[WIFI_AC_VO].mpdu_lost);
+    for (int i = WIFI_AC_VO; i < WIFI_AC_MAX; i++) {
+        printMsg("Traffic AC: %s\n", TrafficACToString(i));
+        printMsg("txmpdu = %d, rxmpdu = %d, mpdu_lost = %d, retries = %d\n",
+                local_link_ptr->ac[i].tx_mpdu, local_link_ptr->ac[i].rx_mpdu,
+                local_link_ptr->ac[i].mpdu_lost, local_link_ptr->ac[i].retries);
+    }
     printMsg("time slicing duty_cycle = %d\n", local_link_ptr->time_slicing_duty_cycle_percent);
     printMsg("Num peers = %d\n", local_link_ptr->num_peers);
 }
@@ -4627,6 +4947,8 @@ void onMultiLinkStatsResults(wifi_request_id id, wifi_iface_ml_stat *iface_ml_st
         local_rx_ptr += channel_size;
         local_cca_ptr += channel_size;
     }
+
+    ml_data = true;
     /* radio stat data and channel stats data is printed in printMultiLinkStats */
     if (!iface_ml_stat) {
         ALOGE("No valid ml stats data\n");
@@ -4655,7 +4977,7 @@ wifi_iface_stat link_stat;
 int num_rate;
 bssload_info_t bssload;
 wifi_peer_info peer_info[32];
-wifi_rate_stat rate_stat[NUM_RATES];
+wifi_rate_stat rate_stat[MAX_NUM_RATES];
 wifi_rate_stat eht_rate_stat[NUM_EHT_RATES];
 
 void onLinkStatsResults(wifi_request_id id, wifi_iface_stat *iface_stat,
@@ -4716,7 +5038,7 @@ void onLinkStatsResults(wifi_request_id id, wifi_iface_stat *iface_stat,
     if (num_rate == NUM_EHT_RATES) {
         memset(eht_rate_stat, 0, num_rate*sizeof(wifi_rate_stat));
         memcpy(&eht_rate_stat, iface_stat->peer_info->rate_stats, num_rate*sizeof(wifi_rate_stat));
-    } else if (num_rate == NUM_RATES) {
+    } else if (num_rate == MAX_NUM_RATES) {
         memset(rate_stat, 0, num_rate*sizeof(wifi_rate_stat));
         memcpy(&rate_stat, iface_stat->peer_info->rate_stats, num_rate*sizeof(wifi_rate_stat));
     }
@@ -4911,7 +5233,7 @@ void printLinkStats(wifi_iface_stat *link_stat, wifi_channel_stat cca_stat[],
         printMsg("(current BSS info: %s, %dMhz)\n",
             rate_stat_preamble[eht_rate_stat[RATE_SPEC_CHECK_INDEX].rate.preamble],
             rate_stat_bandwidth[eht_rate_stat[RATE_SPEC_CHECK_INDEX].rate.bw]);
-    } else if (num_rate == NUM_RATES) {
+    } else if (num_rate == MAX_NUM_RATES) {
         printMsg("(current BSS info: %s, %dMhz)\n",
             rate_stat_preamble[rate_stat[RATE_SPEC_CHECK_INDEX].rate.preamble],
             rate_stat_bandwidth[rate_stat[RATE_SPEC_CHECK_INDEX].rate.bw]);
@@ -4927,7 +5249,7 @@ void printLinkStats(wifi_iface_stat *link_stat, wifi_channel_stat cca_stat[],
             printMsg("%-28s  %10d   %10d     %10d      %10d\n",
                 eht_rates[i], eht_rate_stat[i].tx_mpdu, eht_rate_stat[i].rx_mpdu,
                 eht_rate_stat[i].mpdu_lost, eht_rate_stat[i].retries);
-        } else if (num_rate == NUM_RATES) {
+        } else if (num_rate == MAX_NUM_RATES) {
             printMsg("%-28s  %10d   %10d     %10d      %10d\n",
                 rates[i], rate_stat[i].tx_mpdu, rate_stat[i].rx_mpdu,
                 rate_stat[i].mpdu_lost, rate_stat[i].retries);
@@ -4935,20 +5257,49 @@ void printLinkStats(wifi_iface_stat *link_stat, wifi_channel_stat cca_stat[],
     }
 }
 
-void getLinkStats(void)
+void getLinkStats(char *argv[])
 {
+    wifi_error ret = WIFI_SUCCESS;
+    char *param, *val_p;
+    /* Interface name */
+    wifi_interface_handle ifHandle = NULL;
+    /* skip utility */
+    argv++;
+    /* skip command */
+    argv++;
+
+    /* Parse iface */
+    while ((param = *argv++) != NULL) {
+        val_p = *argv++;
+        if (!val_p || *val_p == '-') {
+            printMsg("%s:Need value following %s\n", __FUNCTION__, param);
+            return;
+        }
+        if (strcmp(param, "-iface") == 0) {
+            ifHandle = wifi_get_iface_handle_by_iface_name(val_p);
+        } else {
+            printMsg("%s:Unsupported Parameter for get stats request\n", __FUNCTION__);
+            return;
+        }
+    }
+
+    if (ifHandle == NULL) {
+        printMsg("-iface <> is mandatory\n");
+        return;
+    }
+
     wifi_stats_result_handler handler;
     memset(&handler, 0, sizeof(handler));
 
     handler.on_link_stats_results = &onLinkStatsResults;
     handler.on_multi_link_stats_results = &onMultiLinkStatsResults;
 
-    int result = hal_fn.wifi_get_link_stats(0, wlan0Handle, handler);
+    int result = hal_fn.wifi_get_link_stats(0, ifHandle, handler);
     if (result < 0) {
         printMsg("failed to get link stat - %d\n", result);
     } else if (!radios) {
         printMsg("Invalid link stat data\n");
-    } else if (ml_links) {
+    } else if (ml_data) {
         printMultiLinkStats(cca_stat, rx_stat, radios);
     } else {
         printLinkStats(&link_stat, cca_stat, rx_stat, &bssload, radios);
@@ -5987,7 +6338,9 @@ void printUsage() {
     printf(" -cancel_resp     cancel the responder\n");
     printf(" -get_responder_info    return the responder info\n");
     printf(" -rtt -sta/-nan <peer mac addr> <channel> <bandwidth>"
-            " <is_6g> <rtt_type> <ntb_min_meas_time> <ntb_max_meas_time>\n");
+            " <is_6g> <rtt_type> <ntb_min_meas_time> <ntb_max_meas_time>"
+            " <akm> <pairwise_cipher_suite> <enable_secure_he_ltf> <enable_ranging_frame_protection>"
+            " <passphrase>\n");
     printf(" -get_capa_rtt Get the capability of RTT such as 11mc");
     printf(" -scan_mac_oui XY:AB:CD\n");
     printf(" -nodfs <0|1>     Turn OFF/ON non-DFS locales\n");
@@ -10254,7 +10607,7 @@ int main(int argc, char *argv[]) {
         setPnoMacOui();
         testHotlistAPs();
     } else if (strcmp(argv[1], "-stats") == 0) {
-        getLinkStats();
+        getLinkStats(argv);
     } else if (strcmp(argv[1], "-rtt") == 0) {
         readRTTOptions(argc, ++argv);
         testRTT();
diff --git a/bcmdhd/wifi_hal/common.h b/bcmdhd/wifi_hal/common.h
index fe251b0..f568522 100644
--- a/bcmdhd/wifi_hal/common.h
+++ b/bcmdhd/wifi_hal/common.h
@@ -64,7 +64,7 @@ const uint32_t BRCM_OUI =  0x001018;
 #define SAR_CONFIG_SCENARIO_COUNT       100
 #define MAX_NUM_RADIOS                  3u
 #define MAX_CMD_RESP_BUF_LEN            8192u
-#define MAX_MLO_LINK                    3u
+#define MAX_MLO_LINK                    4u
 /* For STA, peer would be only one - AP.*/
 #define NUM_PEER_AP                     1u
 /* 11n/HT:   OFDM(12) + HT(16) rates = 28 (MCS0 ~ MCS15)
@@ -74,6 +74,8 @@ const uint32_t BRCM_OUI =  0x001018;
  */
 #define MAX_NUM_RATE                        44u
 #define NUM_RATE_NON_BE                 36u
+#define NUM_RATE_VHT                    28u
+#define NUM_RATE_HT                     12u
 
 #define NL_MSG_MAX_LEN                  5120u
 
@@ -615,8 +617,8 @@ typedef struct rtt_capabilities {
 } rtt_capabilities_t;
 
 typedef u16 rtt_cap_preamble_type_t;
-typedef u16 rtt_akm_type_t;
-typedef u16 rtt_cipher_type_t;
+typedef u16 base_akm_type_t;
+typedef u16 rtt_cipher_suite_t;
 /* RTT Capabilities v2 (11az support) */
 typedef struct rtt_capabilities_mc_az {
     struct rtt_capabilities rtt_capab;
@@ -630,13 +632,13 @@ typedef struct rtt_capabilities_mc_az {
     /* if 11az non-TB responder is supported */
     u8 ntb_responder_supported;
     /* if 11az secure ltf is supported */
-    u8 secure_ltf_supported;
+    u8 secure_he_ltf_supported;
     /* if 11az protected ranging frame is supported */
     u8 protected_rtt_frm_supported;
     /* Supported AKM for secure ranging */
-    rtt_akm_type_t akm_type_supported;
+    base_akm_type_t supported_akms;
     /* Supported cipher type for secure ranging */
-    rtt_cipher_type_t cipher_type_supported;
+    rtt_cipher_suite_t supported_cipher_suites;
 } rtt_capabilities_mc_az_t;
 #endif
 
diff --git a/bcmdhd/wifi_hal/cpp_bindings.h b/bcmdhd/wifi_hal/cpp_bindings.h
index f96f264..666eddd 100755
--- a/bcmdhd/wifi_hal/cpp_bindings.h
+++ b/bcmdhd/wifi_hal/cpp_bindings.h
@@ -332,7 +332,10 @@ protected:
     }
 
     int ifaceId() {
-        return mIfaceInfo->id;
+        if (mIfaceInfo) {
+            return mIfaceInfo->id;
+        }
+        return NL_SKIP;
     }
 
     /* Override this method to parse reply and dig out data; save it in the object */
diff --git a/bcmdhd/wifi_hal/link_layer_stats.cpp b/bcmdhd/wifi_hal/link_layer_stats.cpp
index 695a900..99b8afe 100644
--- a/bcmdhd/wifi_hal/link_layer_stats.cpp
+++ b/bcmdhd/wifi_hal/link_layer_stats.cpp
@@ -280,7 +280,10 @@ exit:
         /* report valid radiostat eventhough there is no linkstat info
          * (non assoc/error case)
          */
-        if ((ret != WIFI_SUCCESS) && num_radios && per_radio_size) {
+        if ((ret != WIFI_SUCCESS) && num_radios && per_radio_size && ml_data) {
+            (*mHandler.on_multi_link_stats_results)(id, NULL, num_radios,
+                    (wifi_radio_stat *)radioStatsBuf);
+        } else if ((ret != WIFI_SUCCESS) && num_radios && per_radio_size) {
             (*mHandler.on_link_stats_results)(id, NULL,
                     num_radios, (wifi_radio_stat *)radioStatsBuf);
         }
@@ -335,6 +338,8 @@ private:
             goto exit;
         }
 
+        ALOGV("Available data_rem_len %d, expected size %d for rate_stat\n",
+                *data_rem_len, all_rates_size);
         for (k = 0; k < num_rate; k++) {
             data_ptr = ((*data) + (*offset));
             if (!data_ptr) {
@@ -358,6 +363,8 @@ private:
                 goto exit;
             }
 
+            ALOGI("index: %d per_rate_size %d, data_rem_len %d\n",
+                   k, per_rate_size, *data_rem_len);
             memcpy(*outbuf, data_ptr, per_rate_size);
             *data_rem_len -= per_rate_size;
             *outbuf_rem_len -= per_rate_size;
@@ -491,7 +498,6 @@ private:
 
             if (!links_ptr->num_peers) {
                 ALOGI("no peers in unassoc case, skip processing peer stats\n");
-                ret = WIFI_SUCCESS;
                 continue;
             }
 
diff --git a/bcmdhd/wifi_hal/rtt.cpp b/bcmdhd/wifi_hal/rtt.cpp
index 039f27a..de7f440 100644
--- a/bcmdhd/wifi_hal/rtt.cpp
+++ b/bcmdhd/wifi_hal/rtt.cpp
@@ -46,10 +46,15 @@
 #include "cpp_bindings.h"
 
 using namespace android;
+#define RTT_RESULT_V4_SIZE (sizeof(wifi_rtt_result_v4))
 #define RTT_RESULT_V3_SIZE (sizeof(wifi_rtt_result_v3))
 #define RTT_RESULT_V2_SIZE (sizeof(wifi_rtt_result_v2))
 #define RTT_RESULT_V1_SIZE (sizeof(wifi_rtt_result))
 #define UNSPECIFIED -1 // wifi HAL common definition for unspecified value
+/* Loglevel */
+#define RTT_DEBUG(x)
+#define RTT_INFO(x) ALOGI x
+
 typedef enum {
 
     RTT_SUBCMD_SET_CONFIG = ANDROID_NL80211_SUBCMD_RTT_RANGE_START,
@@ -92,6 +97,22 @@ typedef enum {
     RTT_ATTRIBUTE_RESULT_R2I_TX_LTF_RPT_CNT = 38,
     RTT_ATTRIBUTE_RESULT_NTB_MIN_MEAS_TIME  = 39,
     RTT_ATTRIBUTE_RESULT_NTB_MAX_MEAS_TIME  = 40,
+
+    /* Security */
+    RTT_ATTRIBUTE_TARGET_PROTECTED_FRM_REQD = 41,
+    RTT_ATTRIBUTE_TARGET_KEY_LIFE_TIME      = 42,
+    RTT_ATTRIBUTE_TARGET_RTT_AKM            = 43,
+    RTT_ATTRIBUTE_TARGET_SEC_LTF_REQD       = 44,
+    RTT_ATTRIBUTE_TARGET_KEY_PASSPHRASE     = 45,
+    RTT_ATTRIBUTE_TARGET_KEY_PASSPHRASE_LEN = 46,
+    RTT_ATTRIBUTE_TARGET_CIPHER_TYPE        = 47,
+    RTT_ATTRIBUTE_RESULT_NTB_I2R_STS        = 48,
+    RTT_ATTRIBUTE_RESULT_NTB_R2I_STS        = 49,
+    RTT_ATTRIBUTE_RESULT_RNG_PROT_ENABLED   = 50,
+    RTT_ATTRIBUTE_RESULT_SLTF_ENABLED       = 51,
+    RTT_ATTRIBUTE_RESULT_RTT_AKM            = 52,
+    RTT_ATTRIBUTE_RESULT_CIPHER_TYPE        = 53,
+    RTT_ATTRIBUTE_RESULT_SLTF_PROTO_VER	    = 54,
     /* Add any new RTT_ATTRIBUTE prior to RTT_ATTRIBUTE_MAX */
     RTT_ATTRIBUTE_MAX
 } RTT_ATTRIBUTE;
@@ -149,10 +170,11 @@ get_err_info(int status)
 
 class GetRttCapabilitiesCommand : public WifiCommand
 {
-    wifi_rtt_capabilities_v3 *mCapabilities;
+    wifi_rtt_capabilities_v4 *mCapabilities;
+
 public:
-    GetRttCapabilitiesCommand(wifi_interface_handle iface, wifi_rtt_capabilities_v3 *capabitlites)
-        : WifiCommand("GetRttCapabilitiesCommand", iface, 0), mCapabilities(capabitlites)
+    GetRttCapabilitiesCommand(wifi_interface_handle iface, wifi_rtt_capabilities_v4 *capabilities)
+        : WifiCommand("GetRttCapabilitiesCommand", iface, 0), mCapabilities(capabilities)
     {
         memset(mCapabilities, 0, sizeof(*mCapabilities));
     }
@@ -171,56 +193,122 @@ public:
 protected:
     virtual int handleResponse(WifiEvent& reply) {
         rtt_capabilities_mc_az_t SrcCapabilities;
-        wifi_rtt_capabilities_v3 DestCapabilities;
+        rtt_capabilities_t mcSrcCapabilities;
+        wifi_rtt_capabilities_v4 DestCapabilities;
 
         ALOGD("In GetRttCapabilitiesCommand::handleResponse");
 
-        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
-            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
+        if ((reply.get_cmd() != NL80211_CMD_VENDOR) || (reply.get_vendor_data() == NULL) ||
+                (reply.get_vendor_data_len() < sizeof(rtt_capabilities_t))) {
+            ALOGD("Ignoring reply with cmd = %d "
+                    "min expected len %d, mc_az rtt capa size %d,"
+                    "  mc rtt capa size %d\n",
+                    reply.get_cmd(), reply.get_vendor_data_len(),
+                    sizeof(rtt_capabilities_mc_az_t), sizeof(rtt_capabilities_t));
             return NL_SKIP;
         }
 
         int id = reply.get_vendor_id();
         int subcmd = reply.get_vendor_subcmd();
-
         void *data = reply.get_vendor_data();
         int len = reply.get_vendor_data_len();
 
-        ALOGD("Id = %0x, subcmd = %d, len = %d, expected len = %d",
-                id, subcmd, len, sizeof(*mCapabilities));
+        ALOGD("Id = %0x, subcmd = %d, len = %d,"
+                " min expected len = %d, max exp len %d\n",
+                id, subcmd, len, sizeof(rtt_capabilities_t), sizeof(rtt_capabilities_mc_az_t));
 
         memset(&SrcCapabilities, 0, sizeof(SrcCapabilities));
+        memset(&mcSrcCapabilities, 0, sizeof(mcSrcCapabilities));
         memset(&DestCapabilities, 0, sizeof(DestCapabilities));
 
-        memcpy(&SrcCapabilities, data,
-                min(len, (int) sizeof(SrcCapabilities)));
+        if (len == sizeof(mcSrcCapabilities)) {
+            memcpy(&mcSrcCapabilities, data, min((int)sizeof(rtt_capabilities_t), len));
+            DestCapabilities.rtt_capab_v3.rtt_capab.rtt_one_sided_supported =
+                    mcSrcCapabilities.rtt_one_sided_supported;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.rtt_ftm_supported =
+                    mcSrcCapabilities.rtt_ftm_supported;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.lci_support =
+                    mcSrcCapabilities.lci_support;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.lcr_support =
+                    mcSrcCapabilities.lcr_support;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.preamble_support =
+                    mcSrcCapabilities.preamble_support;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.bw_support =
+                    mcSrcCapabilities.bw_support;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.responder_supported = 0;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.mc_version = 0;
+
+            DestCapabilities.rtt_capab_v3.az_preamble_support = 0;
+
+            DestCapabilities.rtt_capab_v3.az_bw_support = 0;
+
+            DestCapabilities.rtt_capab_v3.ntb_initiator_supported = 0;
+
+            DestCapabilities.rtt_capab_v3.ntb_responder_supported = 0;
+
+            DestCapabilities.secure_he_ltf_supported = 0;
+
+            DestCapabilities.ranging_fame_protection_supported = 0;
+
+            DestCapabilities.supported_akms = WPA_KEY_MGMT_NONE;
+
+            DestCapabilities.supported_cipher_suites = WPA_CIPHER_NONE;
+        } else {
+            memcpy(&SrcCapabilities, data, min((int)sizeof(rtt_capabilities_mc_az_t), len));
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.rtt_one_sided_supported =
+                    SrcCapabilities.rtt_capab.rtt_one_sided_supported;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.rtt_ftm_supported =
+                    SrcCapabilities.rtt_capab.rtt_ftm_supported;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.lci_support =
+                    SrcCapabilities.rtt_capab.lci_support;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.lcr_support =
+                    SrcCapabilities.rtt_capab.lcr_support;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.preamble_support =
+                    SrcCapabilities.rtt_capab.preamble_support;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.bw_support =
+                    SrcCapabilities.rtt_capab.bw_support;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.responder_supported = 0;
+
+            DestCapabilities.rtt_capab_v3.rtt_capab.mc_version = 0;
+
+            DestCapabilities.rtt_capab_v3.az_preamble_support =
+                     (rtt_cap_preamble_type_t)SrcCapabilities.az_preamble_support;
 
-        DestCapabilities.rtt_capab.rtt_one_sided_supported =
-                SrcCapabilities.rtt_capab.rtt_one_sided_supported;
-        DestCapabilities.rtt_capab.rtt_ftm_supported =
-                SrcCapabilities.rtt_capab.rtt_ftm_supported;
-        DestCapabilities.rtt_capab.lci_support =
-                SrcCapabilities.rtt_capab.lci_support;
-        DestCapabilities.rtt_capab.lcr_support =
-                SrcCapabilities.rtt_capab.lcr_support;
-        DestCapabilities.rtt_capab.preamble_support =
-                SrcCapabilities.rtt_capab.preamble_support;
-        DestCapabilities.rtt_capab.bw_support =
-                SrcCapabilities.rtt_capab.bw_support;
-        DestCapabilities.rtt_capab.responder_supported = 0;
-        DestCapabilities.rtt_capab.mc_version = 0;
+            DestCapabilities.rtt_capab_v3.az_bw_support =
+                    SrcCapabilities.az_bw_support;
 
-        DestCapabilities.az_preamble_support =
-                SrcCapabilities.az_preamble_support;
+            DestCapabilities.rtt_capab_v3.ntb_initiator_supported =
+                    SrcCapabilities.ntb_initiator_supported;
 
-        DestCapabilities.az_bw_support =
-                SrcCapabilities.az_bw_support;
+            DestCapabilities.rtt_capab_v3.ntb_responder_supported =
+                    SrcCapabilities.ntb_responder_supported;
 
-        DestCapabilities.ntb_initiator_supported =
-                SrcCapabilities.ntb_initiator_supported;
+            DestCapabilities.secure_he_ltf_supported =
+                    SrcCapabilities.secure_he_ltf_supported;
 
-        DestCapabilities.ntb_responder_supported =
-                SrcCapabilities.ntb_responder_supported;
+            DestCapabilities.ranging_fame_protection_supported =
+                    SrcCapabilities.protected_rtt_frm_supported;
+
+            DestCapabilities.supported_akms =
+                    (wifi_rtt_akm)SrcCapabilities.supported_akms;
+
+            DestCapabilities.supported_cipher_suites =
+                    (wifi_rtt_cipher_suite)SrcCapabilities.supported_cipher_suites;
+        }
 
         memcpy(mCapabilities, &DestCapabilities, sizeof(DestCapabilities));
         return NL_OK;
@@ -358,7 +446,6 @@ protected:
 
 };
 
-
 class RttCommand : public WifiCommand
 {
     unsigned numRttParams;
@@ -367,10 +454,11 @@ class RttCommand : public WifiCommand
     int totalCnt = 0;
     static const int MAX_RESULTS = 1024;
     wifi_rtt_result *rttResultsV1[MAX_RESULTS];
-    wifi_rtt_result_v2 *rttResultsV2[MAX_RESULTS];
-    wifi_rtt_result_v3 *rttResultsV3[MAX_RESULTS];
-    wifi_rtt_config_v3 *rttParams;
-    wifi_rtt_event_handler_v3 rttHandler;
+    wifi_rtt_result_v4 *rttResultsV4[MAX_RESULTS];
+    wifi_rtt_config *rttParamsV1;
+    wifi_rtt_config_v3 *rttParamsV3;
+    wifi_rtt_config_v4 *rttParamsV4;
+    wifi_rtt_event_handler_v4 rttHandlerV4;
     int nextidx = 0;
     wifi_channel channel = 0;
     wifi_rtt_bw bw;
@@ -380,16 +468,21 @@ class RttCommand : public WifiCommand
     u8 r2i_tx_ltf_repetition_count = 0;
     u32 ntb_min_measurement_time = 0;
     u32 ntb_max_measurement_time = 0;
+    wifi_rtt_akm base_akm = WPA_KEY_MGMT_NONE;
+    wifi_rtt_cipher_suite cipher_suite = WPA_CIPHER_NONE;
+    int secure_he_ltf_protocol_version = 0;
+    bool is_ranging_protection_enabled = 0;
+    bool is_secure_he_ltf_enabled = 0;
+    u8 num_tx_sts = 0, num_rx_sts = 0;
 
 public:
     RttCommand(wifi_interface_handle iface, int id, unsigned num_rtt_config,
-            wifi_rtt_config_v3 rtt_config[], wifi_rtt_event_handler_v3 handler)
-        : WifiCommand("RttCommand", iface, id), numRttParams(num_rtt_config), rttParams(rtt_config),
-        rttHandler(handler)
+            wifi_rtt_config_v4 rtt_config[], wifi_rtt_event_handler_v4 handler)
+        : WifiCommand("RttCommand", iface, id), numRttParams(num_rtt_config), rttParamsV4(rtt_config),
+        rttHandlerV4(handler)
     {
         memset(rttResultsV1, 0, sizeof(rttResultsV1));
-        memset(rttResultsV2, 0, sizeof(rttResultsV2));
-        memset(rttResultsV3, 0, sizeof(rttResultsV3));
+        memset(rttResultsV4, 0, sizeof(rttResultsV4));
         currentIdx = 0;
         mCompleted = 0;
         totalCnt = 0;
@@ -409,10 +502,11 @@ public:
         totalCnt = 0;
         numRttParams = 0;
         memset(rttResultsV1, 0, sizeof(rttResultsV1));
-        memset(rttResultsV2, 0, sizeof(rttResultsV2));
-        memset(rttResultsV3, 0, sizeof(rttResultsV3));
-        rttParams = NULL;
-        rttHandler.on_rtt_results_v3 = NULL;
+        memset(rttResultsV4, 0, sizeof(rttResultsV4));
+        rttParamsV1 = NULL;
+        rttParamsV3 = NULL;
+        rttParamsV4 = NULL;
+        rttHandlerV4.on_rtt_results_v4 = NULL;
         channel = 0;
         result_size = 0;
         opt_result_size = 0;
@@ -436,98 +530,149 @@ public:
                 return WIFI_ERROR_OUT_OF_MEMORY;
             }
 
-            result = request.put_addr(RTT_ATTRIBUTE_TARGET_MAC, rttParams[i].rtt_config.addr);
+            rttParamsV3 = &rttParamsV4[i].rtt_config;
+            rttParamsV1 = &rttParamsV3->rtt_config;
+            result = request.put_addr(RTT_ATTRIBUTE_TARGET_MAC, rttParamsV1->addr);
             if (result < 0) {
                 return result;
             }
 
-            result = request.put_u8(RTT_ATTRIBUTE_TARGET_TYPE, rttParams[i].rtt_config.type);
+            result = request.put_u8(RTT_ATTRIBUTE_TARGET_TYPE, rttParamsV1->type);
             if (result < 0) {
                 return result;
             }
 
-            result = request.put_u8(RTT_ATTRIBUTE_TARGET_PEER, rttParams[i].rtt_config.peer);
+            result = request.put_u8(RTT_ATTRIBUTE_TARGET_PEER, rttParamsV1->peer);
             if (result < 0) {
                 return result;
             }
 
-            result = request.put(RTT_ATTRIBUTE_TARGET_CHAN, &rttParams[i].rtt_config.channel,
+            result = request.put(RTT_ATTRIBUTE_TARGET_CHAN, &rttParamsV1->channel,
                     sizeof(wifi_channel_info));
             if (result < 0) {
                 return result;
             }
 
-            result = request.put_u32(RTT_ATTRIBUTE_TARGET_NUM_BURST,
-                    rttParams[i].rtt_config.num_burst);
+            result = request.put_u32(RTT_ATTRIBUTE_TARGET_NUM_BURST, rttParamsV1->num_burst);
             if (result < 0) {
                 return result;
             }
 
+            ALOGI("num_frames_per_burst %d\n", rttParamsV1->num_frames_per_burst);
             result = request.put_u32(RTT_ATTRIBUTE_TARGET_NUM_FTM_BURST,
-                    rttParams[i].rtt_config.num_frames_per_burst);
+                    rttParamsV1->num_frames_per_burst);
             if (result < 0) {
                 return result;
             }
 
             result = request.put_u32(RTT_ATTRIBUTE_TARGET_NUM_RETRY_FTM,
-                    rttParams[i].rtt_config.num_retries_per_rtt_frame);
+                    rttParamsV1->num_retries_per_rtt_frame);
             if (result < 0) {
                 return result;
             }
 
             result = request.put_u32(RTT_ATTRIBUTE_TARGET_NUM_RETRY_FTMR,
-                    rttParams[i].rtt_config.num_retries_per_ftmr);
+                    rttParamsV1->num_retries_per_ftmr);
             if (result < 0) {
                 return result;
             }
 
             result = request.put_u32(RTT_ATTRIBUTE_TARGET_PERIOD,
-                    rttParams[i].rtt_config.burst_period);
+                    rttParamsV1->burst_period);
             if (result < 0) {
                 return result;
             }
 
             result = request.put_u32(RTT_ATTRIBUTE_TARGET_BURST_DURATION,
-                    rttParams[i].rtt_config.burst_duration);
+                    rttParamsV1->burst_duration);
             if (result < 0) {
                 return result;
             }
 
-            result = request.put_u8(RTT_ATTRIBUTE_TARGET_LCI,
-                    rttParams[i].rtt_config.LCI_request);
+            result = request.put_u8(RTT_ATTRIBUTE_TARGET_LCI, rttParamsV1->LCI_request);
             if (result < 0) {
                 return result;
             }
 
-            result = request.put_u8(RTT_ATTRIBUTE_TARGET_LCR,
-                    rttParams[i].rtt_config.LCR_request);
+            result = request.put_u8(RTT_ATTRIBUTE_TARGET_LCR, rttParamsV1->LCR_request);
             if (result < 0) {
                 return result;
             }
 
-            result = request.put_u8(RTT_ATTRIBUTE_TARGET_BW,
-                    rttParams[i].rtt_config.bw);
+            result = request.put_u8(RTT_ATTRIBUTE_TARGET_BW, rttParamsV1->bw);
             if (result < 0) {
                 return result;
             }
 
-            result = request.put_u8(RTT_ATTRIBUTE_TARGET_PREAMBLE,
-                    rttParams[i].rtt_config.preamble);
+            result = request.put_u8(RTT_ATTRIBUTE_TARGET_PREAMBLE, rttParamsV1->preamble);
             if (result < 0) {
                 return result;
             }
 
             /* Below params are applicable for only 11az ranging */
-            if (rttParams[i].rtt_config.type == RTT_TYPE_2_SIDED_11AZ_NTB) {
+            if ((rttParamsV1->type == RTT_TYPE_2_SIDED_11AZ_NTB) ||
+                    (rttParamsV1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE)) {
                 result = request.put_u32(RTT_ATTRIBUTE_TARGET_NTB_MIN_MEAS_TIME,
-                        rttParams[i].ntb_min_measurement_time);
+                        rttParamsV3->ntb_min_measurement_time);
                 if (result < 0) {
                     return result;
                 }
 
                 result = request.put_u32(RTT_ATTRIBUTE_TARGET_NTB_MAX_MEAS_TIME,
-                        rttParams[i].ntb_max_measurement_time);
+                        rttParamsV3->ntb_max_measurement_time);
+                if (result < 0) {
+                    return result;
+                }
+            }
+
+            /* Below params are applicable for only 11az secure ranging */
+            if (rttParamsV1->type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE) {
+                result = request.put_u16(RTT_ATTRIBUTE_TARGET_RTT_AKM,
+                        rttParamsV4[i].rtt_secure_config.pasn_config.base_akm);
+                if (result < 0) {
+                    return result;
+                }
+
+                result = request.put_u16(RTT_ATTRIBUTE_TARGET_CIPHER_TYPE,
+                        rttParamsV4[i].rtt_secure_config.pasn_config.pairwise_cipher_suite);
+                if (result < 0) {
+                    return result;
+                }
+
+                if (rttParamsV4[i].rtt_secure_config.pasn_config.passphrase_len) {
+                    if (rttParamsV4[i].rtt_secure_config.pasn_config.passphrase_len >
+                            RTT_SECURITY_MAX_PASSPHRASE_LEN) {
+                        ALOGE("%s: Invalid passphrase len = %d\n", __func__,
+                                rttParamsV4[i].rtt_secure_config.pasn_config.passphrase_len);
+                        return WIFI_ERROR_INVALID_ARGS;
+                    }
+                    result = request.put_u32(RTT_ATTRIBUTE_TARGET_KEY_PASSPHRASE_LEN,
+                            rttParamsV4[i].rtt_secure_config.pasn_config.passphrase_len);
+                    if (result < 0) {
+                        ALOGE("%s: Failed to fill passphrase len, result = %d\n", __func__, result);
+                        return result;
+                    }
+
+                    result = request.put(RTT_ATTRIBUTE_TARGET_KEY_PASSPHRASE,
+                            (void *)rttParamsV4[i].rtt_secure_config.pasn_config.passphrase,
+                             rttParamsV4[i].rtt_secure_config.pasn_config.passphrase_len);
+                    if (result < 0) {
+                        ALOGE("%s: Failed to fill passphrase, result = %d\n", __func__, result);
+                        return result;
+                    }
+                }
+
+                result = request.put_u8(RTT_ATTRIBUTE_TARGET_SEC_LTF_REQD,
+                        rttParamsV4[i].rtt_secure_config.enable_secure_he_ltf);
                 if (result < 0) {
+                    ALOGE("%s: Failed to fill enab_sec_ltf val, result = %d\n", __func__, result);
+                    return result;
+                }
+
+                result = request.put_u8(RTT_ATTRIBUTE_TARGET_PROTECTED_FRM_REQD,
+                        rttParamsV4[i].rtt_secure_config.enable_ranging_frame_protection);
+                if (result < 0) {
+                    ALOGE("%s: Failed to fill enab_range_prot val, result= %d\n", __func__, result);
                     return result;
                 }
             }
@@ -630,6 +775,12 @@ public:
         ALOGI("Got an RTT event");
         nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
         int len = event.get_vendor_data_len();
+        int result_cnt = 0;
+        wifi_rtt_result *rtt_result_v1_ptr = NULL;
+        wifi_rtt_result_v3 *rtt_result_v3_ptr = NULL;
+        wifi_rtt_result_v2 *rtt_result_v2_ptr = NULL;
+        wifi_rtt_result_v4 *rtt_result_v4_ptr = NULL;
+
         if (vendor_data == NULL || len == 0) {
             ALOGI("No rtt results found");
             return NL_STOP;
@@ -638,111 +789,183 @@ public:
         for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
             if (it.get_type() == RTT_ATTRIBUTE_RESULTS_COMPLETE) {
                 mCompleted = it.get_u32();
-                ALOGI("Completed flag : %d\n", mCompleted);
+                RTT_DEBUG(("Completed flag : %d\n", mCompleted));
             } else if (it.get_type() == RTT_ATTRIBUTE_RESULTS_PER_TARGET) {
-                int result_cnt = 0;
+                result_cnt = 0;
                 mac_addr bssid;
                 for (nl_iterator it2(it.get()); it2.has_next(); it2.next()) {
                     if (it2.get_type() == RTT_ATTRIBUTE_TARGET_MAC) {
                         memcpy(bssid, it2.get_data(), sizeof(mac_addr));
-                        ALOGI("target mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
+                        RTT_DEBUG(("target mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
                                 bssid[0], bssid[1], bssid[2], bssid[3],
-                                bssid[4], bssid[5]);
+                                bssid[4], bssid[5]));
                     } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_FREQ) {
                         channel = it2.get_u32();
-                        if (rttResultsV3[currentIdx] == NULL) {
-                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
-                            break;
-                        }
-                        if (!channel) {
-                            rttResultsV3[currentIdx]->rtt_result.frequency =
-                                    UNSPECIFIED;
+                        if (rtt_result_v2_ptr) {
+                            if (!channel) {
+                                rtt_result_v2_ptr->frequency = UNSPECIFIED;
+                            } else {
+                                rtt_result_v2_ptr->frequency = channel;
+                            }
+                            RTT_DEBUG(("rtt_resultV2 : \n\tchannel :%d",
+                                    rtt_result_v2_ptr->frequency));
                         } else {
-                            rttResultsV3[currentIdx]->rtt_result.frequency =
-                                    channel;
+                            ALOGE("Not allocated to copy freq, currentIdx %d\n", currentIdx);
+                            break;
                         }
-
-                        ALOGI("rtt_resultV3 : \n\tchannel :%d",
-                                rttResultsV3[currentIdx]->rtt_result.frequency);
                     } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_BW) {
                         bw = (wifi_rtt_bw)it2.get_u32();
-                        if (rttResultsV3[currentIdx] == NULL) {
-                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
+                        if (rtt_result_v2_ptr) {
+                            rtt_result_v2_ptr->packet_bw = bw;
+                            RTT_DEBUG(("rtt_resultV2 : \n\tpacket_bw :%d",
+                                    rtt_result_v2_ptr->packet_bw));
+                        } else {
+                            ALOGE("Not allocated to copy bw, currentIdx %d\n", currentIdx);
                             break;
                         }
-                        rttResultsV3[currentIdx]->rtt_result.packet_bw =
-                                bw;
-
-                        ALOGI("rtt_resultV3 : \n\tpacket_bw :%d",
-                               rttResultsV3[currentIdx]->rtt_result.packet_bw);
                     } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_CNT) {
                         result_cnt = it2.get_u32();
-                        ALOGI("result_cnt : %d\n", result_cnt);
+                        RTT_DEBUG(("result_cnt : %d\n", result_cnt));
                     } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_I2R_TX_LTF_RPT_CNT) {
                         i2r_tx_ltf_repetition_count = it2.get_u8();
-                        if (rttResultsV3[currentIdx] == NULL) {
-                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
+                        RTT_DEBUG(("i2r_tx_ltf_repetition_count: %d\n",
+                                i2r_tx_ltf_repetition_count));
+                        if (rtt_result_v3_ptr) {
+                            rtt_result_v3_ptr->i2r_tx_ltf_repetition_count =
+                                    i2r_tx_ltf_repetition_count;
+                        } else {
+                            ALOGE("Not allocated to copy i2r, currentIdx %d\n", currentIdx);
                             break;
                         }
-                        rttResultsV3[currentIdx]->i2r_tx_ltf_repetition_count =
-                                i2r_tx_ltf_repetition_count;
-                        ALOGI("rtt_resultv3 : \n\ti2r_tx_ltf_repetition_count :%d",
-                                rttResultsV3[currentIdx]->i2r_tx_ltf_repetition_count);
                     } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_R2I_TX_LTF_RPT_CNT) {
                         r2i_tx_ltf_repetition_count = it2.get_u8();
-                        if (rttResultsV3[currentIdx] == NULL) {
-                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
+                        RTT_DEBUG(("r2i_tx_ltf_repetition_count: %d\n",
+                                r2i_tx_ltf_repetition_count));
+                        if (rtt_result_v3_ptr) {
+                            rtt_result_v3_ptr->r2i_tx_ltf_repetition_count =
+                                    r2i_tx_ltf_repetition_count;
+                        } else {
+                            ALOGE("Not allocated to copy r2i, currentIdx %d\n", currentIdx);
                             break;
                         }
-                        rttResultsV3[currentIdx]->r2i_tx_ltf_repetition_count =
-                                r2i_tx_ltf_repetition_count;
-                        ALOGI("rtt_resultv3 : \n\tr2i_tx_ltf_repetition_count :%d",
-                                rttResultsV3[currentIdx]->r2i_tx_ltf_repetition_count);
                     } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_NTB_MIN_MEAS_TIME) {
                         ntb_min_measurement_time = it2.get_u32();
-                        if (rttResultsV3[currentIdx] == NULL) {
-                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
+                        RTT_DEBUG(("ntb_min_measurement_time: %d\n", ntb_min_measurement_time));
+                        if (rtt_result_v3_ptr) {
+                            rtt_result_v3_ptr->ntb_min_measurement_time =
+                                    ntb_min_measurement_time;
+                        } else {
+                            ALOGE("Not allocated to copy min meas time, currentIdx %d\n", currentIdx);
                             break;
                         }
-                        rttResultsV3[currentIdx]->ntb_min_measurement_time =
-                                ntb_min_measurement_time;
-                        ALOGI("rtt_resultv3 : \n\t ntb_min_measurement_time :%lu units of 100 us",
-                                rttResultsV3[currentIdx]->ntb_min_measurement_time);
                     } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_NTB_MAX_MEAS_TIME) {
                         ntb_max_measurement_time = it2.get_u32();
-                        if (rttResultsV3[currentIdx] == NULL) {
-                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
+                        RTT_DEBUG(("ntb_max_measurement_time: %d\n", ntb_max_measurement_time));
+                        if (rtt_result_v3_ptr) {
+                            rtt_result_v3_ptr->ntb_max_measurement_time =
+                                    ntb_max_measurement_time;
+                        } else {
+                            ALOGE("Not allocated to copy max meas time, currentIdx %d\n", currentIdx);
+                            break;
+                        }
+                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_NTB_I2R_STS) {
+                        num_tx_sts = it2.get_u8();
+                        RTT_DEBUG(("num_tx_sts: %d\n", num_tx_sts));
+                        if (rtt_result_v3_ptr) {
+                            rtt_result_v3_ptr->num_tx_sts = num_tx_sts;
+                        } else {
+                            ALOGE("Not allocated to copy i2r sts, currentIdx %d\n", currentIdx);
+                            break;
+                        }
+                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_NTB_R2I_STS) {
+                        num_rx_sts = it2.get_u8();
+                        RTT_DEBUG(("num_rx_sts: %d\n", num_rx_sts));
+                        if (rtt_result_v3_ptr) {
+                            rtt_result_v3_ptr->num_rx_sts = num_rx_sts;
+                        } else {
+                            ALOGE("Not allocated to copy r2i sts, currentIdx %d\n", currentIdx);
+                            break;
+                        }
+                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_RNG_PROT_ENABLED) {
+                        is_ranging_protection_enabled = it2.get_u8();
+                        RTT_DEBUG(("ranging_enab %d, currentIdx %d\n",
+                                is_ranging_protection_enabled, currentIdx));
+                        if (rtt_result_v4_ptr) {
+                            rtt_result_v4_ptr->is_ranging_protection_enabled =
+                                    is_ranging_protection_enabled;
+                        } else {
+                            ALOGE("Not allocated to copy ranging_enab, currentIdx %d\n", currentIdx);
+                            break;
+                        }
+                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_SLTF_ENABLED) {
+                        is_secure_he_ltf_enabled = it2.get_u8();
+                        RTT_DEBUG(("ltf_enab %d, currentIdx %d\n",
+                              is_secure_he_ltf_enabled, currentIdx));
+                        if (rtt_result_v4_ptr) {
+                            rtt_result_v4_ptr->is_secure_he_ltf_enabled =
+                                    is_secure_he_ltf_enabled;
+                        } else {
+                            ALOGE("Not allocated to copy sltf enab, currentIdx %d\n", currentIdx);
+                            break;
+                        }
+                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_RTT_AKM) {
+                        base_akm = (wifi_rtt_akm)it2.get_u16();
+                        RTT_DEBUG(("rtt_resultv4 : \n\t base_akm: %d", base_akm));
+                        if (rtt_result_v4_ptr) {
+                            rtt_result_v4_ptr->base_akm = base_akm;
+                        } else {
+                            ALOGE("Not allocated to copy akm, currentIdx %d\n", currentIdx);
+                            break;
+                        }
+                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_CIPHER_TYPE) {
+                        cipher_suite = (wifi_rtt_cipher_suite)it2.get_u16();
+                        RTT_DEBUG(("rtt_resultv4 : \n\t cipher_suite: %d", cipher_suite));
+                        if (rtt_result_v4_ptr) {
+                            rtt_result_v4_ptr->cipher_suite = cipher_suite;
+                        } else {
+                            ALOGE("Not allocated to copy cipher, currentIdx %d\n", currentIdx);
+                            break;
+                        }
+                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_SLTF_PROTO_VER) {
+                        secure_he_ltf_protocol_version = it2.get_u32();
+                        RTT_DEBUG(("rtt_resultv4 : \n\t secure_he_ltf_protocol_version: %d",
+                                secure_he_ltf_protocol_version));
+                        if (rtt_result_v4_ptr) {
+                            rtt_result_v4_ptr->secure_he_ltf_protocol_version =
+                                    secure_he_ltf_protocol_version;
+                        } else {
+                            ALOGE("Not allocated to copy secure ltf, currentIdx %d\n", currentIdx);
                             break;
                         }
-                        rttResultsV3[currentIdx]->ntb_max_measurement_time =
-                                ntb_max_measurement_time;
-                        ALOGI("rtt_resultv3 : \n\t ntb_max_measurement_time:%lu units of 10ms",
-                                rttResultsV3[currentIdx]->ntb_max_measurement_time);
                     } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT) {
                         currentIdx = nextidx;
                         int result_len = it2.get_len();
+                        if (!result_len) {
+                            ALOGE("Invalid result_len %d\n", result_len);
+                            break;
+                        }
                         rttResultsV1[currentIdx] =
                                 (wifi_rtt_result *)malloc(it2.get_len());
-                        wifi_rtt_result *rtt_results_v1 = rttResultsV1[currentIdx];
-                        if (rtt_results_v1 == NULL) {
+                        rtt_result_v1_ptr = rttResultsV1[currentIdx];
+                        if (rtt_result_v1_ptr == NULL) {
                             mCompleted = 1;
                             ALOGE("failed to allocate the wifi_result_v1\n");
                             break;
                         }
 
-                        /* Populate to the rtt_results_v1 struct */
-                        memcpy(rtt_results_v1, it2.get_data(), it2.get_len());
+                        /* Populate first the fixed elements of rtt_results_v1 struct */
+                        memcpy(rtt_result_v1_ptr, it2.get_data(), it2.get_len());
 
                         /* handle the optional data */
                         result_len -= RTT_RESULT_V1_SIZE;
                         if (result_len > 0) {
-                            dot11_rm_ie_t *ele_1;
-                            dot11_rm_ie_t *ele_2;
+                            dot11_rm_ie_t *ele_1 = NULL;
+                            dot11_rm_ie_t *ele_2 = NULL;
                             /* The result has LCI or LCR element */
-                            ele_1 = (dot11_rm_ie_t *)(rtt_results_v1 + 1);
+                            ele_1 = (dot11_rm_ie_t *)(rtt_result_v1_ptr + 1);
                             if (ele_1->id == DOT11_MNG_MEASURE_REPORT_ID) {
                                 if (ele_1->type == DOT11_MEASURE_TYPE_LCI) {
-                                    rtt_results_v1->LCI = (wifi_information_element *)ele_1;
+                                    rtt_result_v1_ptr->LCI = (wifi_information_element *)ele_1;
                                     result_len -= (ele_1->len + DOT11_HDR_LEN);
                                     opt_result_size += (ele_1->len + DOT11_HDR_LEN);
                                     /* get a next rm ie */
@@ -751,11 +974,11 @@ public:
                                             (ele_1->len + DOT11_HDR_LEN));
                                         if ((ele_2->id == DOT11_MNG_MEASURE_REPORT_ID) &&
                                                 (ele_2->type == DOT11_MEASURE_TYPE_CIVICLOC)) {
-                                            rtt_results_v1->LCR = (wifi_information_element *)ele_2;
+                                            rtt_result_v1_ptr->LCR = (wifi_information_element *)ele_2;
                                         }
                                     }
                                 } else if (ele_1->type == DOT11_MEASURE_TYPE_CIVICLOC) {
-                                    rtt_results_v1->LCR = (wifi_information_element *)ele_1;
+                                    rtt_result_v1_ptr->LCR = (wifi_information_element *)ele_1;
                                     result_len -= (ele_1->len + DOT11_HDR_LEN);
                                     opt_result_size += (ele_1->len + DOT11_HDR_LEN);
                                     /* get a next rm ie */
@@ -764,69 +987,56 @@ public:
                                                 (ele_1->len + DOT11_HDR_LEN));
                                         if ((ele_2->id == DOT11_MNG_MEASURE_REPORT_ID) &&
                                                 (ele_2->type == DOT11_MEASURE_TYPE_LCI)) {
-                                            rtt_results_v1->LCI = (wifi_information_element *)ele_2;
+                                            rtt_result_v1_ptr->LCI = (wifi_information_element *)ele_2;
                                         }
                                     }
                                 }
                             }
                         }
 
-                        /* Alloc struct v2 including new elements of ver2 */
-                        rttResultsV2[currentIdx] =
-                                (wifi_rtt_result_v2 *)malloc(RTT_RESULT_V2_SIZE + opt_result_size);
-                        wifi_rtt_result_v2 *rtt_result_v2 = rttResultsV2[currentIdx];
-                        if (rtt_result_v2 == NULL) {
-                            ALOGE("failed to allocate the rtt_result\n");
+                        /* Alloc struct v4 including nested rtt result elements including opt data */
+                        rttResultsV4[currentIdx] =
+                                (wifi_rtt_result_v4 *)malloc(RTT_RESULT_V4_SIZE + opt_result_size);
+                        rtt_result_v4_ptr = rttResultsV4[currentIdx];
+                        if (rtt_result_v4_ptr == NULL) {
+                            ALOGE("failed to allocate the rtt_result v4\n");
                             break;
                         }
 
-                        /* Populate the v2 result struct as per the v1 result struct elements */
-                        memcpy(&rtt_result_v2->rtt_result,
-                                (wifi_rtt_result *)rtt_results_v1, RTT_RESULT_V1_SIZE);
-                        if (!channel) {
-                            rtt_result_v2->frequency = UNSPECIFIED;
-                        }
-
-                        /* Copy the optional v1 data to v2 struct */
-                        if (opt_result_size &&
-                            (opt_result_size == (it2.get_len() - RTT_RESULT_V1_SIZE))) {
-
-                            wifi_rtt_result_v2 *opt_rtt_result_v2 = NULL;
-                            /* Intersect the optional data from v1 rtt result struct */
-                            wifi_rtt_result *opt_rtt_result_v1 =
-                                    (wifi_rtt_result *)(rtt_results_v1 + 1);
-
-                            /* Move to v2 ptr to the start of the optional params */
-                            opt_rtt_result_v2 =
-                                    (wifi_rtt_result_v2 *)(rtt_result_v2 + 1);
-
-                            /* Append optional rtt_result_v1 data to optional rtt_result_v2 */
-                            memcpy(opt_rtt_result_v2, opt_rtt_result_v1,
-                                    (it2.get_len() - RTT_RESULT_V1_SIZE));
-                        } else {
-                           ALOGI("Optional rtt result elements missing, skip processing\n");
+                        rtt_result_v3_ptr = &rtt_result_v4_ptr->rtt_result_v3;
+                        if (rtt_result_v3_ptr == NULL) {
+                            ALOGE("failed to allocate the rtt_result v3\n");
+                            break;
                         }
 
-                        /* Alloc struct v3 including new elements, reserve for new elements */
-                        rttResultsV3[currentIdx] =
-                                (wifi_rtt_result_v3 *)malloc(RTT_RESULT_V3_SIZE + opt_result_size);
-                        wifi_rtt_result_v3 *rtt_result_v3 = rttResultsV3[currentIdx];
-                        if (rtt_result_v3 == NULL) {
-                            ALOGE("failed to allocate the rtt_result ver3\n");
+                        rtt_result_v2_ptr = &rtt_result_v3_ptr->rtt_result;
+                        if (rtt_result_v2_ptr == NULL) {
+                            ALOGE("failed to allocate the rtt_result v2\n");
                             break;
                         }
 
-                        /* Populate the v3 struct with v1 struct, v1 struct opt + v2 struct + v2 struct opt */
-                        memcpy(&rtt_result_v3->rtt_result,
-                                (wifi_rtt_result_v2 *)rtt_result_v2,
-                                RTT_RESULT_V2_SIZE + opt_result_size);
+                        /* Populate the v2 result struct as per the v1 result struct elements */
+                        memcpy(&rtt_result_v2_ptr->rtt_result, (wifi_rtt_result *)rtt_result_v1_ptr,
+                                RTT_RESULT_V1_SIZE + opt_result_size);
+
+                        if (!channel) {
+                            rtt_result_v2_ptr->frequency = UNSPECIFIED;
+                        }
 
                         totalCnt++;
                         nextidx = currentIdx;
                         nextidx++;
                     }
                 }
-                ALOGI("Current Id: %d: retrieved rtt_resultv3 :\n"
+            }
+        }
+
+        if (mCompleted) {
+            unregisterVendorHandler(GOOGLE_OUI, RTT_EVENT_COMPLETE);
+            {
+                if (*rttHandlerV4.on_rtt_results_v4) {
+#ifdef HAL_DEBUG
+                    ALOGI("Current Id: %d: retrieved rtt_resultv4 :\n"
                             " burst_num : %d, measurement_number : %d,\n"
                             " success_number : %d, number_per_burst_peer : %d, status : %s,\n"
                             " retry_after_duration : %d rssi : %d dbm,\n"
@@ -834,30 +1044,29 @@ public:
                             " distance : %d mm, burst_duration : %d ms, freq : %d,\n"
                             " packet_bw : %d, negotiated_burst_num : %d\n",
                             currentIdx,
-                            rttResultsV3[currentIdx]->rtt_result.rtt_result.burst_num,
-                            rttResultsV3[currentIdx]->rtt_result.rtt_result.measurement_number,
-                            rttResultsV3[currentIdx]->rtt_result.rtt_result.success_number,
-                            rttResultsV3[currentIdx]->rtt_result.rtt_result.number_per_burst_peer,
-                            get_err_info(rttResultsV3[currentIdx]->rtt_result.rtt_result.status),
-                            rttResultsV3[currentIdx]->rtt_result.rtt_result.retry_after_duration,
-                            rttResultsV3[currentIdx]->rtt_result.rtt_result.rssi,
-                            rttResultsV3[currentIdx]->rtt_result.rtt_result.rx_rate.bitrate * 100,
-                            (unsigned long)rttResultsV3[currentIdx]->rtt_result.rtt_result.rtt,
-                            (unsigned long)rttResultsV3[currentIdx]->rtt_result.rtt_result.rtt_sd,
-                            rttResultsV3[currentIdx]->rtt_result.rtt_result.distance_mm,
-                            rttResultsV3[currentIdx]->rtt_result.rtt_result.burst_duration,
-                            rttResultsV3[currentIdx]->rtt_result.frequency,
-                            rttResultsV3[currentIdx]->rtt_result.packet_bw,
-                            rttResultsV3[currentIdx]->rtt_result.rtt_result.negotiated_burst_num);
-
-            }
-        }
-
-        if (mCompleted) {
-            unregisterVendorHandler(GOOGLE_OUI, RTT_EVENT_COMPLETE);
-            {
-                if (*rttHandler.on_rtt_results_v3) {
-                    (*rttHandler.on_rtt_results_v3)(id(), totalCnt, rttResultsV3);
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.burst_num,
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.measurement_number,
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.success_number,
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.number_per_burst_peer,
+                            get_err_info(rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.status),
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.retry_after_duration,
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.rssi,
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.rx_rate.bitrate * 100,
+                            (unsigned long)rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.rtt,
+                            (unsigned long)rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.rtt_sd,
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.distance_mm,
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.burst_duration,
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.frequency,
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.packet_bw,
+                            rttResultsV4[currentIdx]->rtt_result_v3.rtt_result.rtt_result.negotiated_burst_num);
+                    ALOGE("is_ranging_protection_enabled == %d",
+                           rttResultsV4[currentIdx]->is_ranging_protection_enabled);
+                    ALOGE("is_secure_he_ltf_enabled == %d",
+                           rttResultsV4[currentIdx]->is_secure_he_ltf_enabled);
+                    ALOGE("base_akm == %d", rttResultsV4[currentIdx]->base_akm);
+                    ALOGE("cipher_suite == %d", rttResultsV4[currentIdx]->cipher_suite);
+#endif /* HAL_DEBUG */
+                    (*rttHandlerV4.on_rtt_results_v4)(id(), totalCnt, rttResultsV4);
                 }
             }
 
@@ -865,11 +1074,8 @@ public:
                 free(rttResultsV1[i]);
                 rttResultsV1[i] = NULL;
 
-                free(rttResultsV2[i]);
-                rttResultsV2[i] = NULL;
-
-                free(rttResultsV3[i]);
-                rttResultsV3[i] = NULL;
+                free(rttResultsV4[i]);
+                rttResultsV4[i] = NULL;
             }
             totalCnt = currentIdx = nextidx = 0;
             WifiCommand *cmd = wifi_unregister_cmd(wifiHandle(), id());
@@ -880,11 +1086,10 @@ public:
     }
 };
 
-
 /* API to request RTT measurement */
-wifi_error wifi_rtt_range_request_v3(wifi_request_id id, wifi_interface_handle iface,
-        unsigned num_rtt_config, wifi_rtt_config_v3 rtt_config[],
-        wifi_rtt_event_handler_v3 handler)
+wifi_error wifi_rtt_range_request_v4(wifi_request_id id, wifi_interface_handle iface,
+        unsigned num_rtt_config, wifi_rtt_config_v4 rtt_config[],
+        wifi_rtt_event_handler_v4 handler)
 {
     if (iface == NULL) {
         ALOGE("wifi_rtt_range_request_v3: NULL iface pointer provided."
@@ -943,17 +1148,17 @@ wifi_error wifi_rtt_range_cancel(wifi_request_id id,  wifi_interface_handle ifac
 }
 
 /* API to get RTT capability */
-wifi_error wifi_get_rtt_capabilities_v3(wifi_interface_handle iface,
-        wifi_rtt_capabilities_v3 *capabilities)
+wifi_error wifi_get_rtt_capabilities_v4(wifi_interface_handle iface,
+        wifi_rtt_capabilities_v4 *capabilities)
 {
     if (iface == NULL) {
-        ALOGE("wifi_get_rtt_capabilities_v3: NULL iface pointer provided."
+        ALOGE("wifi_get_rtt_capabilities_v4: NULL iface pointer provided."
                 " Exit.");
         return WIFI_ERROR_INVALID_ARGS;
     }
 
     if (capabilities == NULL) {
-        ALOGE("wifi_get_rtt_capabilities_v3: NULL capabilities pointer provided."
+        ALOGE("wifi_get_rtt_capabilities_v4: NULL capabilities pointer provided."
                 " Exit.");
         return WIFI_ERROR_INVALID_ARGS;
     }
diff --git a/bcmdhd/wifi_hal/wifi_hal.cpp b/bcmdhd/wifi_hal/wifi_hal.cpp
index 7867572..bf700d1 100644
--- a/bcmdhd/wifi_hal/wifi_hal.cpp
+++ b/bcmdhd/wifi_hal/wifi_hal.cpp
@@ -282,9 +282,9 @@ wifi_error init_wifi_vendor_hal_func_table(wifi_hal_fn *fn)
     fn->wifi_set_link_stats = wifi_set_link_stats;
     fn->wifi_clear_link_stats = wifi_clear_link_stats;
     fn->wifi_get_valid_channels = wifi_get_valid_channels;
-    fn->wifi_rtt_range_request_v3 = wifi_rtt_range_request_v3;
+    fn->wifi_rtt_range_request_v4 = wifi_rtt_range_request_v4;
     fn->wifi_rtt_range_cancel = wifi_rtt_range_cancel;
-    fn->wifi_get_rtt_capabilities_v3 = wifi_get_rtt_capabilities_v3;
+    fn->wifi_get_rtt_capabilities_v4 = wifi_get_rtt_capabilities_v4;
     fn->wifi_rtt_get_responder_info = wifi_rtt_get_responder_info;
     fn->wifi_enable_responder = wifi_enable_responder;
     fn->wifi_disable_responder = wifi_disable_responder;
@@ -802,12 +802,13 @@ void wifi_event_loop(wifi_handle handle)
             // ALOGE("Error polling socket");
         } else if (pfd[0].revents & POLLERR) {
             ALOGE("POLL Error; error no = %d (%s)", errno, strerror(errno));
-            ssize_t result2 = TEMP_FAILURE_RETRY(read(pfd[0].fd, buf, sizeof(buf)));
-            ALOGE("Read after POLL returned %zd, error no = %d (%s)", result2,
-                  errno, strerror(errno));
             if (errno == WIFI_HAL_EVENT_BUFFER_NOT_AVAILABLE) {
-                ALOGE("Exit, No buffer space");
-                break;
+                ALOGE("Poll again, No buffer space");
+                internal_pollin_handler(handle);
+            } else {
+                ssize_t result2 = TEMP_FAILURE_RETRY(read(pfd[0].fd, buf, sizeof(buf)));
+                ALOGE("Read after POLL returned %zd, error no = %d (%s)", result2,
+                        errno, strerror(errno));
             }
         } else if (pfd[0].revents & POLLHUP) {
             ALOGE("Remote side hung up");
@@ -1846,6 +1847,7 @@ wifi_error wifi_clear_iface_hal_info(wifi_handle handle, const char* ifname)
         if ((info->interfaces[i] != NULL) &&
             strncmp(info->interfaces[i]->name, ifname,
             sizeof(info->interfaces[i]->name)) == 0) {
+            memset(info->interfaces[i], 0, sizeof(info->interfaces[i]));
             free(info->interfaces[i]);
             info->interfaces[i] = NULL;
             info->num_interfaces--;
diff --git a/bcmdhd/wifi_hal/wifi_logger.cpp b/bcmdhd/wifi_hal/wifi_logger.cpp
index 92df920..17f190f 100755
--- a/bcmdhd/wifi_hal/wifi_logger.cpp
+++ b/bcmdhd/wifi_hal/wifi_logger.cpp
@@ -1780,7 +1780,6 @@ public:
         for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
             buf_attr = it.get_type();
             switch (buf_attr) {
-                case DUMP_BUF_ATTR_MEMDUMP:
                 case DUMP_BUF_ATTR_TIMESTAMP:
                 case DUMP_BUF_ATTR_ECNTRS:
                 case DUMP_BUF_ATTR_DHD_DUMP:
@@ -1793,7 +1792,8 @@ public:
                 case DUMP_BUF_ATTR_PKTID_MAP_LOG:
                 case DUMP_BUF_ATTR_PKTID_UNMAP_LOG: {
                     if (it.get_u32()) {
-                        ALOGE("Copying data to userspace failed, status = %d\n", it.get_u32());
+                        ALOGE("Copying data to userspace failed for buf attr = %s, status = %d\n",
+                            EWP_CmdAttrToString(buf_attr), it.get_u32());
                         return WIFI_ERROR_UNKNOWN;
                     }
                     index = logger_attr_buffer_lookup(buf_attr);
@@ -1807,6 +1807,7 @@ public:
                         return WIFI_ERROR_UNKNOWN;
                     }
                     if (!mBuff || attr_type_len[len_attr] <= 0) {
+                        ALOGE("buff is empty for attr = %s\n", EWP_CmdAttrToString(buf_attr));
                         return WIFI_ERROR_UNKNOWN;
                     }
 
@@ -1910,7 +1911,6 @@ public:
             for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
                 int attr = it.get_type();
                 switch (attr) {
-                    case DUMP_LEN_ATTR_MEMDUMP:
                     case DUMP_LEN_ATTR_TIMESTAMP:
                     case DUMP_LEN_ATTR_ECNTRS:
                     case DUMP_LEN_ATTR_DHD_DUMP:
```

