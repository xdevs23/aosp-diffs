```diff
diff --git a/OWNERS b/OWNERS
index dd590d3..ea7aaf7 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
 arabawy@google.com
-etancohen@google.com
 kumachang@google.com
 wangroger@google.com
diff --git a/bcmdhd/halutil/halutil.cpp b/bcmdhd/halutil/halutil.cpp
index 906ec64..f2f59a8 100644
--- a/bcmdhd/halutil/halutil.cpp
+++ b/bcmdhd/halutil/halutil.cpp
@@ -74,7 +74,7 @@ wifi_error  nan_event_check_request(transaction_id id,
         wifi_interface_handle handle);
 
 /* API to spawn a hal instance from halutil CLI to capture events */
-wifi_error twt_event_check_request(transaction_id id,
+wifi_error twt_event_check_request(int id,
         wifi_interface_handle handle);
 static int set_interface_params(char *p_info, char *val_p, int len);
 static wifi_interface_handle wifi_get_iface_handle_by_iface_name(char *val_p);
@@ -963,7 +963,6 @@ static int rttCmdId;
 static int epnoCmdId;
 static int loggerCmdId;
 static u16 nanCmdId;
-static u16 twtCmdId;
 static wifi_error twt_init_handlers(void);
 
 static bool startScan(int max_ap_per_scan, int base_period, int threshold_percent,
@@ -1576,7 +1575,7 @@ static void testRTT()
                 return;
             }
             fprintf(w_fp, "|SSID|BSSID|Primary Freq|Center Freq|Channel BW(0=20MHZ,1=40MZ,2=80MHZ)\n"
-                    "|rtt_type(1=1WAY,2=2WAY,3=auto)|Peer Type(STA=0, AP=1)|burst period|\n"
+                    "is_6g|rtt_type(1=1WAY,2=2WAY,3=auto)|Peer Type(STA=0, AP=1)|burst period|\n"
                     "Num of Burst|FTM retry count|FTMR retry count|LCI|LCR|\n"
                     "Burst Duration|Preamble|BW||NTB Min Meas Time in units of 100us|\n"
                     "NTB Max Meas Time in units of 10ms\n");
@@ -1592,6 +1591,11 @@ static void testRTT()
                         scan_param->ssid, addr[0], addr[1],
                         addr[2], addr[3], addr[4], addr[5],
                         scan_param->channel, RttTypeToString(type));
+
+                if (type > RTT_TYPE_2_SIDED_11AZ_NTB) {
+                    printf("Unsupported rtt_type %d, exit!!\n", type);
+                    return;
+                }
                 params[num_ap].rtt_config.type = type;
                 params[num_ap].rtt_config.channel = get_channel_of_ie(&scan_param->ie_data[0],
                         scan_param->ie_length);
@@ -1686,6 +1690,10 @@ static void testRTT()
                 MAC2STR(responder_addr),
                 params[num_sta].rtt_config.channel.center_freq,
                 RttTypeToString(type));
+        if (type > RTT_TYPE_2_SIDED_11AZ_NTB) {
+             printf("Unsupported rtt_type %d, exit!!\n", type);
+             return;
+        }
         /*As we are doing STA-STA RTT */
         params[num_sta].rtt_config.type = type;
         if (rtt_nan) {
@@ -1750,7 +1758,7 @@ static void testRTT()
             printMsg("\nRTT AP list file does not exist on %s.\n"
                     "Please specify correct full path or use default one, %s, \n"
                     "  by following order in file, such as:\n"
-                    "SSID | BSSID | chan_num |Channel BW(0=20MHZ,1=40MZ,2=80MHZ)|"
+                    "SSID | BSSID | chan_num | Channel BW(0=20MHZ,1=40MZ,2=80MHZ)| is_6g |"
                     " RTT_Type(1=1WAY,2=2WAY,3=auto) |Peer Type(STA=0, AP=1)| Burst Period|"
                     " No of Burst| No of FTM Burst| FTM Retry Count| FTMR Retry Count| LCI| LCR|"
                     " Burst Duration| Preamble|Channel_Bandwith|"
@@ -1768,16 +1776,22 @@ static void testRTT()
                     break;
                 }
 
-                result = fscanf(fp,"%s %s %u %u %u\n",
+                result = fscanf(fp,"%s %s %u %u %u %u\n",
                         ssid, bssid, (unsigned int*)&responder_channel,
                         (unsigned int*)&channel_width,
+                        (unsigned int*)&is_6g,
                         (unsigned int*)&params[i].rtt_config.type);
-                if (result != 5) {
-                    printMsg("fscanf failed to read ssid, bssid, channel, type: %d\n", result);
+                if (result != 6) {
+                    printMsg("fscanf failed to read ssid, bssid, channel, width, is_6g, type. err: %d\n", result);
                     break;
                 }
 
-                result = fscanf(fp, "%u %u %u %u %u %u %hhu %hhu %u %hhu %u\n",
+                if (params[i].rtt_config.type > RTT_TYPE_2_SIDED_11AZ_NTB) {
+                    printf("Unsupported rtt_type %d, exit!!\n", type);
+                    break;
+                }
+
+                result = fscanf(fp, "%u %u %u %u %u %u %hhu %hhu %u %hhu\n",
                         (unsigned int*)&params[i].rtt_config.peer,
                         &params[i].rtt_config.burst_period,
                         &params[i].rtt_config.num_burst,
@@ -1787,8 +1801,8 @@ static void testRTT()
                         (unsigned char*)&params[i].rtt_config.LCI_request,
                         (unsigned char*)&params[i].rtt_config.LCR_request,
                         (unsigned int*)&params[i].rtt_config.burst_duration,
-                        (unsigned char*)&params[i].rtt_config.preamble, &channel_width);
-                if (result != 11) {
+                        (unsigned char*)&params[i].rtt_config.preamble);
+                if (result != 10) {
                     printMsg("fscanf failed to read mc params %d\n", result);
                     break;
                 }
@@ -1971,8 +1985,9 @@ static void getRTTCapability()
 }
 
 /* TWT related apis */
-static void setupTwtRequest(char *argv[]) {
-    TwtSetupRequest msg;
+static void setupTwtSession(char *argv[]) {
+    wifi_twt_request msg;
+    wifi_request_id id = 0;
     wifi_error ret = WIFI_SUCCESS;
     char *endptr, *param, *val_p;
 
@@ -1996,30 +2011,16 @@ static void setupTwtRequest(char *argv[]) {
         }
         if (strcmp(param, "-iface") == 0) {
             ifHandle = wifi_get_iface_handle_by_iface_name(val_p);
-        } else if (strcmp(param, "-config_id") == 0) {
-            msg.config_id = atoi(val_p);
-        } else if (strcmp(param, "-neg_type") == 0) {
-            msg.negotiation_type = atoi(val_p);
-        } else if (strcmp(param, "-trigger_type") == 0) {
-            msg.trigger_type = atoi(val_p);
-        } else if (strcmp(param, "-wake_dur_us") == 0) {
-            msg.wake_dur_us = strtoul(val_p, &endptr, 0);
-        } else if (strcmp(param, "-wake_int_us") == 0) {
-            msg.wake_int_us = strtoul(val_p, &endptr, 0);
-        } else if (strcmp(param, "-wake_int_min_us") == 0) {
-            msg.wake_int_min_us = strtoul(val_p, &endptr, 0);
-        } else if (strcmp(param, "-wake_int_max_us") == 0) {
-            msg.wake_int_max_us = strtoul(val_p, &endptr, 0);
-        } else if (strcmp(param, "-wake_dur_min_us") == 0) {
-            msg.wake_dur_min_us = strtoul(val_p, &endptr, 0);
-        } else if (strcmp(param, "-wake_dur_max_us") == 0) {
-            msg.wake_dur_max_us = strtoul(val_p, &endptr, 0);
-        } else if (strcmp(param, "-avg_pkt_size") == 0) {
-            msg.avg_pkt_size = strtoul(val_p, &endptr, 0);
-        } else if (strcmp(param, "-avg_pkt_num") == 0) {
-            msg.avg_pkt_num = strtoul(val_p, &endptr, 0);
-        } else if (strcmp(param, "-wake_time_off_us") == 0) {
-            msg.wake_time_off_us = strtoul(val_p, &endptr, 0);
+        } else if (strcmp(param, "-mlo_link_id") == 0) {
+            msg.mlo_link_id = atoi(val_p);
+        } else if (strcmp(param, "-min_wake_dur_us") == 0) {
+            msg.min_wake_duration_micros = strtoul(val_p, &endptr, 0);
+        } else if (strcmp(param, "-max_wake_dur_us") == 0) {
+            msg.max_wake_duration_micros = strtoul(val_p, &endptr, 0);
+        } else if (strcmp(param, "-min_wake_inter_us") == 0) {
+            msg.min_wake_interval_micros = strtoul(val_p, &endptr, 0);
+        } else if (strcmp(param, "-max_wake_inter_us") == 0) {
+            msg.max_wake_interval_micros = strtoul(val_p, &endptr, 0);
         } else {
             printMsg("%s:Unsupported Parameter for twt setup request\n", __FUNCTION__);
             ret = WIFI_ERROR_INVALID_ARGS;
@@ -2034,23 +2035,27 @@ static void setupTwtRequest(char *argv[]) {
 
     ret = twt_init_handlers();
     if (ret != WIFI_SUCCESS) {
-        printMsg("Failed to initialize twt handlers %d\n", ret);
+        printMsg("Failed to initialize twt events %d\n", ret);
         goto exit;
     }
 
-    ret = twt_setup_request(ifHandle, &msg);
+    id = getNewCmdId();
+
+    ret = hal_fn.wifi_twt_session_setup(id, ifHandle, msg);
 
 exit:
     printMsg("%s:ret = %d\n", __FUNCTION__, ret);
     return;
 }
 
-static void TeardownTwt(char *argv[]) {
-    TwtTeardownRequest msg;
+static void UpdateTwtSession(char *argv[]) {
     wifi_error ret = WIFI_SUCCESS;
-    char *param, *val_p;
+    wifi_twt_request msg;
+    wifi_request_id id = 0;
+    int session_id = 0;
+    char *param, *val_p, *endptr;
 
-    /* Set Default twt teardown params */
+    /* Set Default twt update request params */
     memset(&msg, 0, sizeof(msg));
 
     /* Parse args for twt params */
@@ -2070,14 +2075,20 @@ static void TeardownTwt(char *argv[]) {
         }
         if (strcmp(param, "-iface") == 0) {
             ifHandle = wifi_get_iface_handle_by_iface_name(val_p);
-        } else if (strcmp(param, "-config_id") == 0) {
-            msg.config_id = atoi(val_p);
-        } else if (strcmp(param, "-all_twt") == 0) {
-            msg.all_twt = atoi(val_p);
-        } else if (strcmp(param, "-neg_type") == 0) {
-            msg.negotiation_type = atoi(val_p);
+        } else if (strcmp(param, "-session_id") == 0) {
+            session_id = atoi(val_p);
+        } else if (strcmp(param, "-mlo_link_id") == 0) {
+            msg.mlo_link_id = atoi(val_p);
+        } else if (strcmp(param, "-min_wake_dur_us") == 0) {
+            msg.min_wake_duration_micros = strtoul(val_p, &endptr, 0);
+        } else if (strcmp(param, "-max_wake_dur_us") == 0) {
+            msg.max_wake_duration_micros = strtoul(val_p, &endptr, 0);
+        } else if (strcmp(param, "-min_wake_inter_us") == 0) {
+            msg.min_wake_interval_micros = strtoul(val_p, &endptr, 0);
+        } else if (strcmp(param, "-max_wake_inter_us") == 0) {
+            msg.max_wake_interval_micros = strtoul(val_p, &endptr, 0);
         } else {
-            printMsg("%s:Unsupported Parameter for twt teardown request\n", __FUNCTION__);
+            printMsg("%s:Unsupported Parameter for update twt session request\n", __FUNCTION__);
             ret = WIFI_ERROR_INVALID_ARGS;
             goto exit;
         }
@@ -2090,25 +2101,25 @@ static void TeardownTwt(char *argv[]) {
 
     ret = twt_init_handlers();
     if (ret != WIFI_SUCCESS) {
-        printMsg("Failed to initialize twt handlers %d\n", ret);
+        printMsg("Failed to initialize twt events %d\n", ret);
         goto exit;
     }
 
-    ret = twt_teardown_request(ifHandle, &msg);
+    id = getNewCmdId();
+
+    ret = hal_fn.wifi_twt_session_update(id, ifHandle, session_id, msg);
 
 exit:
     printMsg("%s:ret = %d\n", __FUNCTION__, ret);
     return;
 }
 
-static void InfoFrameTwt(char *argv[]) {
-    TwtInfoFrameRequest msg;
+static void SuspendTwtSession(char *argv[]) {
     wifi_error ret = WIFI_SUCCESS;
+    wifi_request_id id = 0;
+    int session_id = 0;
     char *param, *val_p;
 
-    /* Set Default twt info frame params */
-    memset(&msg, 0, sizeof(msg));
-
     /* Parse args for twt params */
     /* skip utility */
     argv++;
@@ -2126,14 +2137,10 @@ static void InfoFrameTwt(char *argv[]) {
         }
         if (strcmp(param, "-iface") == 0) {
             ifHandle = wifi_get_iface_handle_by_iface_name(val_p);
-        } else if (strcmp(param, "-config_id") == 0) {
-            msg.config_id = atoi(val_p);
-        } else if (strcmp(param, "-all_twt") == 0) {
-            msg.all_twt = atoi(val_p);
-        } else if (strcmp(param, "-resume_time_us") == 0) {
-            msg.resume_time_us = atoi(val_p);
+        } else if (strcmp(param, "-session_id") == 0) {
+            session_id = atoi(val_p);
         } else {
-            printMsg("%s:Unsupported Parameter for twt info request\n", __FUNCTION__);
+            printMsg("%s:Unsupported Parameter for suspend twt session request\n", __FUNCTION__);
             ret = WIFI_ERROR_INVALID_ARGS;
             goto exit;
         }
@@ -2146,22 +2153,24 @@ static void InfoFrameTwt(char *argv[]) {
 
     ret = twt_init_handlers();
     if (ret != WIFI_SUCCESS) {
-        printMsg("Failed to initialize twt handlers %d\n", ret);
+        printMsg("Failed to initialize twt events %d\n", ret);
         goto exit;
     }
 
-    ret = twt_info_frame_request(ifHandle, &msg);
+    id = getNewCmdId();
+
+    ret = hal_fn.wifi_twt_session_suspend(id, ifHandle, session_id);
 
 exit:
     printMsg("%s:ret = %d\n", __FUNCTION__, ret);
     return;
 }
 
-static void GetTwtStats(char *argv[]) {
+static void ResumeTwtSession(char *argv[]) {
     wifi_error ret = WIFI_SUCCESS;
+    wifi_request_id id = 0;
+    int session_id = 0;
     char *param, *val_p;
-    u8 config_id = 1;
-    TwtStats twt_stats;
 
     /* Parse args for twt params */
     /* skip utility */
@@ -2174,16 +2183,16 @@ static void GetTwtStats(char *argv[]) {
     while ((param = *argv++) != NULL) {
         val_p = *argv++;
         if (!val_p || *val_p == '-') {
-            printMsg("%s:Need value following %s\n", __FUNCTION__, param);
+            printMsg("%s: Need value following %s\n", __FUNCTION__, param);
             ret = WIFI_ERROR_NOT_SUPPORTED;
             goto exit;
         }
         if (strcmp(param, "-iface") == 0) {
             ifHandle = wifi_get_iface_handle_by_iface_name(val_p);
-        } else if (strcmp(param, "-config_id") == 0) {
-            config_id = atoi(val_p);
+        } else if (strcmp(param, "-session_id") == 0) {
+            session_id = atoi(val_p);
         } else {
-            printMsg("%s:Unsupported Parameter for get stats request\n", __FUNCTION__);
+            printMsg("%s:Unsupported Parameter for resume twt session request\n", __FUNCTION__);
             ret = WIFI_ERROR_INVALID_ARGS;
             goto exit;
         }
@@ -2194,38 +2203,26 @@ static void GetTwtStats(char *argv[]) {
         goto exit;
     }
 
-    memset(&twt_stats, 0, sizeof(twt_stats));
+    ret = twt_init_handlers();
+    if (ret != WIFI_SUCCESS) {
+        printMsg("Failed to initialize twt events %d\n", ret);
+        goto exit;
+    }
 
-    ret = twt_get_stats(ifHandle, config_id, &twt_stats);
+    id = getNewCmdId();
 
-    if (ret == WIFI_SUCCESS) {
-        printMsg("TWT stats :\n");
-        if (twt_stats.config_id)
-            printMsg("config id = %d\n", twt_stats.config_id);
-        if (twt_stats.avg_pkt_num_tx)
-            printMsg("avg_pkt_num_tx = %d\n", twt_stats.avg_pkt_num_tx);
-        if (twt_stats.avg_pkt_num_rx)
-            printMsg("avg_pkt_num_rx = %d\n", twt_stats.avg_pkt_num_rx);
-        if (twt_stats.avg_tx_pkt_size)
-            printMsg("avg_tx_pkt_size = %d\n", twt_stats.avg_tx_pkt_size);
-        if (twt_stats.avg_rx_pkt_size)
-            printMsg("avg_rx_pkt_size = %d\n", twt_stats.avg_rx_pkt_size);
-        if (twt_stats.avg_eosp_dur_us)
-            printMsg("avg_eosp_dur_us = %d\n", twt_stats.avg_eosp_dur_us);
-        if (twt_stats.eosp_count)
-            printMsg("eosp_count = %d\n", twt_stats.eosp_count);
+    ret = hal_fn.wifi_twt_session_resume(id, ifHandle, session_id);
 
-        return;
-    }
 exit:
-    printMsg("Could not get the twt stats : err %d\n", ret);
+    printMsg("%s:ret = %d\n", __FUNCTION__, ret);
     return;
 }
 
-void ClearTwtStats(char *argv[]) {
+static void TeardownTwtSession(char *argv[]) {
     wifi_error ret = WIFI_SUCCESS;
+    wifi_request_id id = 0;
+    int session_id = 0;
     char *param, *val_p;
-    u8 config_id = 1;
 
     /* Parse args for twt params */
     /* skip utility */
@@ -2244,10 +2241,10 @@ void ClearTwtStats(char *argv[]) {
         }
         if (strcmp(param, "-iface") == 0) {
             ifHandle = wifi_get_iface_handle_by_iface_name(val_p);
-        } else if (strcmp(param, "-config_id") == 0) {
-            config_id = atoi(val_p);
+        } else if (strcmp(param, "-session_id") == 0) {
+            session_id = atoi(val_p);
         } else {
-            printMsg("%s:Unsupported Parameter for twt info request\n", __FUNCTION__);
+            printMsg("%s:Unsupported Parameter for twt teardown request\n", __FUNCTION__);
             ret = WIFI_ERROR_INVALID_ARGS;
             goto exit;
         }
@@ -2260,36 +2257,46 @@ void ClearTwtStats(char *argv[]) {
 
     ret = twt_init_handlers();
     if (ret != WIFI_SUCCESS) {
-        printMsg("Failed to initialize twt handlers %d\n", ret);
+        printMsg("Failed to initialize twt event %d\n", ret);
         goto exit;
     }
-    ret = twt_clear_stats(ifHandle, config_id);
+
+    id = getNewCmdId();
+
+    ret = hal_fn.wifi_twt_session_teardown(id, ifHandle, session_id);
 
 exit:
     printMsg("%s:ret = %d\n", __FUNCTION__, ret);
     return;
 }
 
-static void getTWTCapability(char *argv[]) {
+static void GetTwtStats(char *argv[]) {
     wifi_error ret = WIFI_SUCCESS;
     char *param, *val_p;
+    wifi_request_id id = 0;
+    u8 session_id = 0;
 
+    /* Parse args for twt params */
     /* skip utility */
     argv++;
     /* skip command */
     argv++;
+    /* skip command */
+    argv++;
 
     while ((param = *argv++) != NULL) {
         val_p = *argv++;
         if (!val_p || *val_p == '-') {
-            printMsg("%s: Need value following %s\n", __FUNCTION__, param);
+            printMsg("%s:Need value following %s\n", __FUNCTION__, param);
             ret = WIFI_ERROR_NOT_SUPPORTED;
             goto exit;
         }
         if (strcmp(param, "-iface") == 0) {
             ifHandle = wifi_get_iface_handle_by_iface_name(val_p);
+        } else if (strcmp(param, "-session_id") == 0) {
+            session_id = atoi(val_p);
         } else {
-            printMsg("%s:Unsupported Parameter for twt capability request\n", __FUNCTION__);
+            printMsg("%s:Unsupported Parameter for get stats request\n", __FUNCTION__);
             ret = WIFI_ERROR_INVALID_ARGS;
             goto exit;
         }
@@ -2300,31 +2307,108 @@ static void getTWTCapability(char *argv[]) {
         goto exit;
     }
 
-    TwtCapabilitySet twt_capability;
+    ret = twt_init_handlers();
+    if (ret != WIFI_SUCCESS) {
+        printMsg("Failed to initialize twt event %d\n", ret);
+        goto exit;
+    }
+
+    id = getNewCmdId();
+
+    ret = hal_fn.wifi_twt_session_get_stats(id, ifHandle, session_id);
+
+exit:
+    printMsg("%s: ret = %d\n", __FUNCTION__, ret);
+    return;
+}
+
+#ifdef NOT_YET
+static void ClearTwtStats(char *argv[]) {
+    wifi_error ret = WIFI_SUCCESS;
+    char *param, *val_p;
+    /* Interface name */
+    wifi_interface_handle ifHandle = NULL;
+    wifi_request_id id = 0;
+    u8 session_id = 0;
+
+    /* Parse args for twt params */
+    /* skip utility */
+    argv++;
+    /* skip command */
+    argv++;
+    /* skip command */
+    argv++;
 
-    ret = twt_get_capability(ifHandle, &twt_capability);
+    while ((param = *argv++) != NULL) {
+        val_p = *argv++;
+        if (!val_p || *val_p == '-') {
+            printMsg("%s:Need value following %s\n", __FUNCTION__, param);
+            ret = WIFI_ERROR_NOT_SUPPORTED;
+            goto exit;
+        }
+        if (strcmp(param, "-iface") == 0) {
+            ifHandle = wifi_get_iface_handle_by_iface_name(val_p);
+        } else if (strcmp(param, "-session_id") == 0) {
+            session_id = atoi(val_p);
+        } else {
+            printMsg("%s:Unsupported Parameter for get stats request\n", __FUNCTION__);
+            ret = WIFI_ERROR_INVALID_ARGS;
+            goto exit;
+        }
+    }
+
+    if (ifHandle == NULL) {
+        printMsg("-iface <> is mandatory\n");
+        goto exit;
+    }
+
+    ret = twt_init_handlers();
+    if (ret != WIFI_SUCCESS) {
+        printMsg("Failed to initialize twt event %d\n", ret);
+        goto exit;
+    }
+
+    id = getNewCmdId();
+
+    ret = hal_fn.wifi_twt_session_clear_stats(id, ifHandle, session_id);
+
+exit:
+    printMsg("%s:ret = %d\n", __FUNCTION__, ret);
+    return;
+}
+#endif /* NOT_YET */
+
+static void getTWTCapability() {
+    wifi_error ret = WIFI_SUCCESS;
+
+    wifi_twt_capabilities twt_capability;
+
+    ret = hal_fn.wifi_twt_get_capabilities(wlan0Handle, &twt_capability);
     if (ret == WIFI_SUCCESS) {
         printMsg("Supported Capabilites of TWT :\n");
-        if (twt_capability.device_capability.requester_supported)
-            printMsg("Device Requester supported\n");
-        if (twt_capability.device_capability.responder_supported)
-            printMsg("Device Responder supported\n");
-        if (twt_capability.device_capability.broadcast_twt_supported)
-            printMsg("Device Broadcast twt supported\n");
-        if (twt_capability.device_capability.flexibile_twt_supported)
-            printMsg("Device Flexibile twt supported\n");
-        if (twt_capability.peer_capability.requester_supported)
-            printMsg("Peer Requester supported\n");
-        if (twt_capability.peer_capability.responder_supported)
-            printMsg("Peer Responder supported\n");
-        if (twt_capability.peer_capability.broadcast_twt_supported)
-            printMsg("Peer Broadcast twt supported\n");
-        if (twt_capability.peer_capability.flexibile_twt_supported)
-            printMsg("Peer Flexibile twt supported\n");
+        if (twt_capability.is_twt_requester_supported)
+            printMsg("Twt Requester supported\n");
+        if (twt_capability.is_twt_responder_supported)
+            printMsg("Twt Responder supported\n");
+        if (twt_capability.is_broadcast_twt_supported)
+            printMsg("Broadcast twt supported\n");
+        if (twt_capability.is_flexible_twt_supported)
+            printMsg("Flexibile twt supported\n");
+        if (twt_capability.min_wake_duration_micros)
+            printMsg("Min wake duration %d microseconds\n",
+                    twt_capability.min_wake_duration_micros);
+        if (twt_capability.max_wake_duration_micros)
+            printMsg("Max wake duration %d microseconds\n",
+                    twt_capability.max_wake_duration_micros);
+        if (twt_capability.min_wake_interval_micros)
+            printMsg("Min wake interval %d microseconds\n",
+                    twt_capability.min_wake_interval_micros);
+        if (twt_capability.max_wake_interval_micros)
+            printMsg("Max wake interval %d microseconds\n",
+                    twt_capability.max_wake_interval_micros);
     } else {
         printMsg("Could not get the twt capabilities : %d\n", ret);
     }
-exit:
     return;
 }
 
@@ -3856,6 +3940,9 @@ void readTestOptions(int argc, char *argv[]) {
 }
 
 void readRTTOptions(int argc, char *argv[]) {
+    char *val_p = NULL;
+    int ret;
+
     for (int j = 1; j < argc-1; j++) {
         if ((strcmp(argv[j], "-get_ch_list") == 0)) {
             if(strcmp(argv[j + 1], "a") == 0) {
@@ -3925,7 +4012,7 @@ void readRTTOptions(int argc, char *argv[]) {
             if (isxdigit(argv[j+1][0])) {
                 j++;
                 parseMacAddress(argv[j], responder_addr);
-                printMsg("Target mac(" MACSTR ")", MAC2STR(responder_addr));
+                printMsg("Target mac(" MACSTR ")" , MAC2STR(responder_addr));
             }
             /* Read channel if present */
             if (argv[j+1]) {
@@ -3934,56 +4021,57 @@ void readRTTOptions(int argc, char *argv[]) {
                     responder_channel = atoi(argv[j]);
                     printf("Channel set as %d \n", responder_channel);
                 }
-                /* Read band width if present */
-                if (argv[j+1]) {
-                    if (isdigit(argv[j+1][0])) {
-                        j++;
-                        channel_width = atoi(argv[j]);
-                        printf("channel_width as %d \n", channel_width);
-                    }
+            }
+            /* Read band width if present */
+            if (argv[j+1]) {
+                if (isdigit(argv[j+1][0])) {
+                    j++;
+                    channel_width = atoi(argv[j]);
+                    printf("channel_width as %d \n", channel_width);
                 }
-                /* check its 6g channel */
-                if (argv[j+1]) {
-                    if (isdigit(argv[j+1][0])) {
-                        j++;
-                        if(atoi(argv[j]) == 1) {
-                            printf(" IS 6G CHANNEL \n");
-                            is_6g = true;
-                        }
+            }
+            /* check its 6g channel */
+            if (argv[j+1]) {
+                if (isdigit(argv[j+1][0])) {
+                    j++;
+                    if (atoi(argv[j]) == 1) {
+                        printf(" IS 6G CHANNEL \n");
+                        is_6g = true;
                     }
                 }
+            }
 
-                /* Read rtt_type if present */
-                if (argv[j+1]) {
-                    if (isdigit(argv[j+1][0])) {
-                        j++;
-                        type = (wifi_rtt_type)atoi(argv[j]);
-                        printf("rtt_type %d \n", type);
-                    }
+            /* Read rtt_type if present */
+            if (argv[j+1]) {
+                if (isdigit(argv[j+1][0])) {
+                    j++;
+                    type = (wifi_rtt_type)atoi(argv[j]);
+                    printf("rtt_type %d \n", type);
                 }
+            }
 
-                /* Read ntb_min_meas_time if present */
-                if (argv[j+1] && (type == RTT_TYPE_2_SIDED_11AZ_NTB)) {
-                    if (isdigit(argv[j+1][0])) {
-                        j++;
-                        ntb_min_meas_time = atoi(argv[j]);
-                        printf("ntb_min_meas_time as %lu \n", ntb_min_meas_time);
-                    }
+            /* Read ntb_min_meas_time if present */
+            if ((argv[j+1]) && ((type == RTT_TYPE_2_SIDED_11AZ_NTB) ||
+                    (type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE))) {
+                if (isdigit(argv[j+1][0])) {
+                    j++;
+                    printf("ntb_min_meas_time : %lu \n", atoi(argv[j]));
+                    ntb_min_meas_time = atoi(argv[j]);
                 }
+            }
 
-                /* Read ntb_max_meas_time if present */
-                if (argv[j+1] && (type == RTT_TYPE_2_SIDED_11AZ_NTB)) {
-                    if (isdigit(argv[j+1][0])) {
-                        j++;
-                        ntb_max_meas_time = atoi(argv[j]);
-                        printf("ntb_max_meas_time as %lu \n", ntb_max_meas_time);
-                    }
+            /* Read ntb_max_meas_time if present */
+            if ((argv[j+1]) && ((type == RTT_TYPE_2_SIDED_11AZ_NTB) ||
+                    (type == RTT_TYPE_2_SIDED_11AZ_NTB_SECURE))) {
+                if (isdigit(argv[j+1][0])) {
+                    j++;
+                    printf("ntb_max_meas_time : %lu \n", atoi(argv[j]));
+                    ntb_max_meas_time = atoi(argv[j]);
                 }
             }
         }
     }
 }
-
 void readLoggerOptions(int argc, char *argv[])
 {
     void printUsage();          // declaration for below printUsage()
@@ -5539,17 +5627,18 @@ static void printApfUsage() {
 
 static void printTwtUsage() {
     printf("Usage: halutil [OPTION]\n");
-    printf("halutil -twt -setup -iface <> -config_id <> -neg_type <0 for individual TWT, 1 for broadcast TWT> "
-            "-trigger_type <0 for non-triggered TWT, 1 for triggered TWT> "
-            "-wake_dur_us <> -wake_int_us <> -wake_int_min_us <> "
-            "-wake_int_max_us <> -wake_dur_min_us <> -wake_dur_max_us <> "
-            "-avg_pkt_size <> -avg_pkt_num <> -wake_time_off_us <>\n");
-    printf("halutil -twt -info_frame -iface <> -config_id <>"
-            " -all_twt <0 for individual setp request, 1 for all TWT> -resume_time_us <>\n");
-    printf("halutil -twt -teardown -iface <> -config_id <> -all_twt <> "
-            " -neg_type <0 for individual TWT, 1 for broadcast TWT>\n");
-    printf("halutil -twt -get_stats -iface <> -config_id <>\n");
-    printf("halutil -twt -clear_stats -iface <> -config_id <>\n");
+    printf("halutil -twt -setup -iface <> -mlo_link_id <> -min_wake_dur_us <>\n"
+            " -max_wake_dur_us <> -min_wake_inter_us <> -max_wake_inter_us <>\n");
+    printf("halutil -twt -update -iface <> -session_id <> -mlo_link_id <> \n"
+            "-min_wake_dur_us <> -max_wake_dur_us <> -min_wake_inter_us <>\n"
+            " -max_wake_inter_us <>\n");
+    printf("halutil -twt -teardown -iface <> -session_id <>\n");
+    printf("halutil -twt -suspend -iface <> -session_id <>\n");
+    printf("halutil -twt -resume -iface <> -session_id <>\n");
+    printf("halutil -twt -get_stats -iface <> -session_id <>\n");
+#ifdef NOT_YET
+    printf("halutil -twt -clear_stats -iface <> -session_id <>\n");
+#endif /* NOT_YET */
     printf("halutil -get_capa_twt -iface <>\n");
     printf("halutil -twt -event_chk\n");
     return;
@@ -5897,8 +5986,8 @@ void printUsage() {
     printf(" -enable_resp     enables the responder\n");
     printf(" -cancel_resp     cancel the responder\n");
     printf(" -get_responder_info    return the responder info\n");
-    printf(" -rtt -sta/-nan <peer mac addr> <channel> [ <bandwidth> [0 - 2]] <is_6g>"
-        "  bandwidth - 0 for 20, 1 for 40 , 2 for 80 . is_6g = 1 if channel is 6G\n");
+    printf(" -rtt -sta/-nan <peer mac addr> <channel> <bandwidth>"
+            " <is_6g> <rtt_type> <ntb_min_meas_time> <ntb_max_meas_time>\n");
     printf(" -get_capa_rtt Get the capability of RTT such as 11mc");
     printf(" -scan_mac_oui XY:AB:CD\n");
     printf(" -nodfs <0|1>     Turn OFF/ON non-DFS locales\n");
@@ -6516,61 +6605,127 @@ wifi_error nan_init_handlers(void) {
     return ret;
 }
 
-static void OnTwtNotify(TwtDeviceNotify* event) {
-    if (event) {
-        printMsg("OnTwtNotify, notification = %d\n", event->notification);
+static const char *TwtReasonCodeToString(wifi_twt_teardown_reason_code reason_code)
+{
+    switch (reason_code) {
+        C2S(WIFI_TWT_TEARDOWN_REASON_CODE_UNKNOWN)
+        C2S(WIFI_TWT_TEARDOWN_REASON_CODE_LOCALLY_REQUESTED)
+        C2S(WIFI_TWT_TEARDOWN_REASON_CODE_INTERNALLY_INITIATED)
+        C2S(WIFI_TWT_TEARDOWN_REASON_CODE_PEER_INITIATED)
+    default:
+        return "TWT_REASON_CODE_UNKNOWN";
     }
-    return;
 }
 
-static void OnTwtSetupResponse(TwtSetupResponse* event) {
-    printMsg("\n OnTwtSetupResponse\n");
-    if (event) {
-        printMsg("config id = %d\n", event->config_id);
-        printMsg("status = %d\n", event->status);
-        printMsg("reason_code = %d\n", event->reason_code);
-        printMsg("negotiation_type = %d\n", event->negotiation_type);
-        printMsg("trigger_type = %d\n", event->trigger_type);
-        printMsg("wake_dur_us = %d\n", event->wake_dur_us);
-        printMsg("wake_int_us = %d\n", event->wake_int_us);
-        printMsg("wake_time_off_us = %d\n", event->wake_time_off_us);
+static const char *TwtErrorCodeToString(wifi_twt_error_code error_code)
+{
+    switch (error_code) {
+        C2S(WIFI_TWT_ERROR_CODE_FAILURE_UNKNOWN)
+        C2S(WIFI_TWT_ERROR_CODE_ALREADY_RESUMED)
+        C2S(WIFI_TWT_ERROR_CODE_ALREADY_SUSPENDED)
+        C2S(WIFI_TWT_ERROR_CODE_INVALID_PARAMS)
+        C2S(WIFI_TWT_ERROR_CODE_MAX_SESSION_REACHED)
+        C2S(WIFI_TWT_ERROR_CODE_NOT_AVAILABLE)
+        C2S(WIFI_TWT_ERROR_CODE_NOT_SUPPORTED)
+        C2S(WIFI_TWT_ERROR_CODE_PEER_NOT_SUPPORTED)
+        C2S(WIFI_TWT_ERROR_CODE_PEER_REJECTED)
+        C2S(WIFI_TWT_ERROR_CODE_TIMEOUT)
+    default:
+        return "TWT_ERROR_CODE_UNKNOWN";
     }
+}
+
+static void OnTwtSessionFailure(wifi_request_id id, wifi_twt_error_code error_code) {
+    printMsg("OnTwtSessionFailure:\n");
+    printMsg("Error_code %s (%d)\n",
+            TwtErrorCodeToString(error_code), error_code);
     return;
 }
 
-static void OnTwtTearDownCompletion(TwtTeardownCompletion* event) {
-    printMsg("\n OnTwtTearDownCompletion\n");
-    if (event) {
-        printMsg("config id = %d\n", event->config_id);
-        printMsg("status = %d\n", event->status);
-        printMsg("all twt = %d\n", event->all_twt);
-        printMsg("reason = %d\n", event->reason);
-    }
+static void OnTwtSessionCreate(wifi_request_id id, wifi_twt_session session) {
+    printMsg("OnTwtSessionCreate:\n");
+    printMsg("Session data\n");
+    printMsg("session_id: %d\n", session.session_id);
+    printMsg("mlo_link_id: %d\n", session.mlo_link_id);
+    printMsg("wake_duration_micros: %d\n", session.wake_duration_micros);
+    printMsg("wake_interval_micros: %d\n", session.wake_interval_micros);
+    printMsg("negotiation_type: %d\n", session.negotiation_type);
+    printMsg("is_trigger_enabled: %d\n", session.is_trigger_enabled);
+    printMsg("is_announced: %d\n", session.is_announced);
+    printMsg("is_implicit: %d\n", session.is_implicit);
+    printMsg("is_protected: %d\n", session.is_protected);
+    printMsg("is_updatable: %d\n", session.is_updatable);
+    printMsg("is_suspendable: %d\n", session.is_suspendable);
+    printMsg("is_responder_pm_mode_enabled: %d\n", session.is_responder_pm_mode_enabled);
     return;
 }
 
-static void OnTwtInfoFrameReceived(TwtInfoFrameReceived* event) {
-    printMsg("\n OnTwtInfoFrameReceived\n");
-    if (event) {
-        printMsg("config id = %d\n", event->config_id);
-        printMsg("status = %d\n", event->status);
-        printMsg("all twt = %d\n", event->all_twt);
-        printMsg("reason = %d\n", event->reason);
-        printMsg("twt_resumed = %d\n", event->twt_resumed);
-    }
+static void OnTwtSessionUpdate(wifi_request_id id, wifi_twt_session session) {
+    printMsg("OnTwtSessionUpdate:\n");
+    printMsg("Session data\n");
+    printMsg("session_id: %d\n", session.session_id);
+    printMsg("mlo_link_id: %d\n", session.mlo_link_id);
+    printMsg("wake_duration_micros: %d\n", session.wake_duration_micros);
+    printMsg("wake_interval_micros: %d\n", session.wake_interval_micros);
+    printMsg("negotiation_type: %d\n", session.negotiation_type);
+    printMsg("is_trigger_enabled: %d\n", session.is_trigger_enabled);
+    printMsg("is_announced: %d\n", session.is_announced);
+    printMsg("is_implicit: %d\n", session.is_implicit);
+    printMsg("is_protected: %d\n", session.is_protected);
+    printMsg("is_updatable: %d\n", session.is_updatable);
+    printMsg("is_suspendable: %d\n", session.is_suspendable);
+    printMsg("is_responder_pm_mode_enabled: %d\n", session.is_responder_pm_mode_enabled);
+    return;
+}
+
+static void OnTwtSessionTearDown(wifi_request_id id, int session_id,
+        wifi_twt_teardown_reason_code reason) {
+    printMsg("OnTwtSessionTearDown:\n");
+    printMsg("Session id: %d\n", session_id);
+    printMsg("Reason:%s (%d)\n", TwtReasonCodeToString(reason), reason);
+    return;
+}
+
+static void OnTwtSessionStats(wifi_request_id id, int session_id,
+        wifi_twt_session_stats stats) {
+    printMsg("OnTwtSessionStats:\n");
+    printMsg("Session id: %d\n", session_id);
+    printMsg("avg_pkt_num_tx: %d\n", stats.avg_pkt_num_tx);
+    printMsg("avg_pkt_num_rx: %d\n", stats.avg_pkt_num_rx);
+    printMsg("avg_tx_pkt_size: %d\n", stats.avg_tx_pkt_size);
+    printMsg("avg_rx_pkt_size: %d\n", stats.avg_rx_pkt_size);
+    printMsg("avg_eosp_dur_us: %d\n", stats.avg_eosp_dur_us);
+    printMsg("eosp_count: %d\n", stats.eosp_count);
+    return;
+}
+
+static void OnTwtSessionSuspend(wifi_request_id id, int session_id) {
+    printMsg("OnTwtSessionSuspend:\n");
+    printMsg("Session id: %d\n", session_id);
     return;
 }
 
-wifi_error twt_init_handlers(void) {
+static void OnTwtSessionResume(wifi_request_id id, int session_id) {
+    printMsg("OnTwtSessionResume:\n");
+    printMsg("Session id: %d\n", session_id);
+    return;
+}
+
+wifi_error twt_init_handlers() {
     wifi_error ret = WIFI_SUCCESS;
-    TwtCallbackHandler handlers;
-    memset(&handlers, 0, sizeof(handlers));
-    handlers.EventTwtDeviceNotify = OnTwtNotify;
-    handlers.EventTwtSetupResponse = OnTwtSetupResponse;
-    handlers.EventTwtTeardownCompletion = OnTwtTearDownCompletion;
-    handlers.EventTwtInfoFrameReceived = OnTwtInfoFrameReceived;
-    ret = twt_register_handler(wlan0Handle , handlers);
-    printMsg("%s: ret = %d\n", __FUNCTION__, ret);
+    wifi_twt_events events;
+
+    memset(&events, 0, sizeof(events));
+    events.on_twt_failure = OnTwtSessionFailure;
+    events.on_twt_session_create = OnTwtSessionCreate;
+    events.on_twt_session_update = OnTwtSessionUpdate;
+    events.on_twt_session_teardown = OnTwtSessionTearDown;
+    events.on_twt_session_stats = OnTwtSessionStats;
+    events.on_twt_session_suspend = OnTwtSessionSuspend;
+    events.on_twt_session_resume = OnTwtSessionResume;
+
+    ret = wifi_twt_register_events(wlan0Handle, events);
+    ALOGD("%s: ret = %d\n", __FUNCTION__, ret);
     return ret;
 }
 
@@ -6587,8 +6742,7 @@ void twtEventCheck(void) {
         return;
     }
 
-    twtCmdId = getNewCmdId();
-    ret = twt_event_check_request(twtCmdId, wlan0Handle);
+    ret = twt_event_check_request(cmdId, wlan0Handle);
     if (ret != WIFI_SUCCESS) {
         printMsg("Failed to check the twt events: %d\n", ret);
         return;
@@ -10233,26 +10387,32 @@ int main(int argc, char *argv[]) {
         MultiStaSetUsecase(argv);
     } else if ((strcmp(argv[1], "-voip_mode") == 0) && (argc > 2)) {
         SetVoipMode(argv);
-    } else if (strcmp(argv[1], "-twt") == 0) {
+    } else if ((strcmp(argv[1], "-twt") == 0) && (argc > 2)) {
         if ((strcmp(argv[2], "-setup") == 0)) {
-            setupTwtRequest(argv);
+            setupTwtSession(argv);
         } else if ((strcmp(argv[2], "-teardown") == 0)) {
-            TeardownTwt(argv);
-        } else if ((strcmp(argv[2], "-info_frame") == 0)) {
-            InfoFrameTwt(argv);
+            TeardownTwtSession(argv);
+        } else if ((strcmp(argv[2], "-update") == 0)) {
+            UpdateTwtSession(argv);
+        } else if ((strcmp(argv[2], "-suspend") == 0)) {
+            SuspendTwtSession(argv);
+        } else if ((strcmp(argv[2], "-resume") == 0)) {
+            ResumeTwtSession(argv);
         } else if ((strcmp(argv[2], "-get_stats") == 0)) {
             GetTwtStats(argv);
+#ifdef NOT_YET
         } else if ((strcmp(argv[2], "-clear_stats") == 0)) {
             ClearTwtStats(argv);
+#endif /* NOT_YET */
         } else if ((strcmp(argv[2], "-event_chk") == 0)) {
             twtEventCheck();
         } else {
             printMsg("\n Unknown command\n");
             printTwtUsage();
-            return WIFI_SUCCESS;
+            goto cleanup;
         }
     } else if (strcmp(argv[1], "-get_capa_twt") == 0) {
-        getTWTCapability(argv);
+        getTWTCapability();
     } else if ((strcmp(argv[1], "-dtim_multiplier") == 0) && (argc > 2)) {
         int dtim_multiplier = (atoi)(argv[2]);
         hal_fn.wifi_set_dtim_config(wlan0Handle, dtim_multiplier);
diff --git a/bcmdhd/wifi_hal/common.h b/bcmdhd/wifi_hal/common.h
index 8223051..fe251b0 100644
--- a/bcmdhd/wifi_hal/common.h
+++ b/bcmdhd/wifi_hal/common.h
@@ -28,6 +28,7 @@
 #include "sync.h"
 #include <unistd.h>
 
+#define ARRAYSIZE(a)            (u8)(sizeof(a) / sizeof(a[0]))
 #define SOCKET_BUFFER_SIZE      (32768U)
 #define RECV_BUF_SIZE           (4096)
 #define DEFAULT_EVENT_CB_SIZE   (64)
@@ -87,6 +88,7 @@ const uint32_t BRCM_OUI =  0x001018;
 
 #define NAN_MAX_PAIRING_CNT             8u
 #define NAN_MAX_COOKIE_LEN              255u
+#define NAN_DEFAULT_RX_CHAINS_SUPPORTED 2u
 
 /*
  This enum defines ranges for various commands; commands themselves
@@ -260,11 +262,13 @@ typedef enum {
     CHAVOID_SUBCMD_SET_CONFIG = ANDROID_NL80211_SUBCMD_CHAVOID_RANGE_START,
 
     TWT_SUBCMD_GETCAPABILITY	= ANDROID_NL80211_SUBCMD_TWT_START,
-    TWT_SUBCMD_SETUP_REQUEST,
-    TWT_SUBCMD_TEAR_DOWN_REQUEST,
-    TWT_SUBCMD_INFO_FRAME_REQUEST,
-    TWT_SUBCMD_GETSTATS,
-    TWT_SUBCMD_CLR_STATS,
+    TWT_SUBCMD_SESSION_SETUP_REQUEST,
+    TWT_SUBCMD_SESSION_TEAR_DOWN_REQUEST,
+    TWT_SUBCMD_SESSION_UPDATE_REQUEST,
+    TWT_SUBCMD_SESSION_SUSPEND_REQUEST,
+    TWT_SUBCMD_SESSION_RESUME_REQUEST,
+    TWT_SUBCMD_SESSION_GETSTATS,
+    TWT_SUBCMD_SESSION_CLR_STATS,
 
     WIFI_SUBCMD_CONFIG_VOIP_MODE = ANDROID_NL80211_SUBCMD_VIOP_MODE_START,
 
@@ -429,56 +433,82 @@ typedef struct wifi_gscan_full_result {
     u8  ie_data[1];                  // IE data to follow
 } wifi_gscan_full_result_t;
 
+wifi_error wifi_twt_session_setup(wifi_request_id id, wifi_interface_handle iface,
+        wifi_twt_request request);
+wifi_error wifi_twt_session_update(wifi_request_id id, wifi_interface_handle iface,
+        int session_id, wifi_twt_request request);
+wifi_error wifi_twt_session_suspend(wifi_request_id id, wifi_interface_handle iface,
+        int session_id);
+wifi_error wifi_twt_session_resume(wifi_request_id id, wifi_interface_handle iface,
+        int session_id);
+wifi_error wifi_twt_session_teardown(wifi_request_id id, wifi_interface_handle iface,
+        int session_id);
+wifi_error wifi_twt_session_get_stats(wifi_request_id id, wifi_interface_handle iface,
+        int session_id);
+wifi_error wifi_twt_get_capabilities(wifi_interface_handle iface,
+        wifi_twt_capabilities* capabilities);
+wifi_error wifi_twt_register_events(wifi_interface_handle iface, wifi_twt_events events);
+
 void twt_deinit_handler();
 
 typedef enum {
-    TWT_EVENT_INVALID          = 0,
-    TWT_SETUP_RESPONSE         = 1,
-    TWT_TEARDOWN_COMPLETION    = 2,
-    TWT_INFORM_FRAME           = 3,
-    TWT_NOTIFY                 = 4,
+    TWT_EVENT_INVALID            = 0,
+    TWT_SESSION_FAILURE          = 1,
+    TWT_SESSION_SETUP_CREATE     = 2,
+    TWT_SESSION_SETUP_UPDATE     = 3,
+    TWT_SESSION_TEARDOWN         = 4,
+    TWT_SESSION_STATS            = 5,
+    TWT_SESSION_SUSPEND          = 6,
+    TWT_SESSION_RESUME           = 7,
     TWT_EVENT_LAST
 } TwtEventType;
 
 typedef enum {
-    TWT_INVALID			= 0,
-    TWT_SETUP_REQUEST		= 1,
-    TWT_INFO_FRAME_REQUEST	= 2,
-    TWT_TEAR_DOWN_REQUEST	= 3,
+    TWT_INVALID                     = 0,
+    TWT_GET_CAPABILITIES            = 1,
+    TWT_SESSION_SETUP_REQUEST       = 2,
+    TWT_SESSION_UPDATE_REQUEST	    = 3,
+    TWT_SESSION_SUSPEND_REQUEST	    = 4,
+    TWT_SESSION_RESUME_REQUEST	    = 5,
+    TWT_SESSION_TEAR_DOWN_REQUEST   = 6,
+    TWT_SESSION_GET_STATS           = 7,
+    TWT_SESSION_CLEAR_STATS         = 8,
     TWT_LAST
 } TwtRequestType;
 
 typedef enum {
-    TWT_ATTRIBUTE_INVALID		= 0,
-    TWT_ATTRIBUTE_CONFIG_ID		= 1,
-    TWT_ATTRIBUTE_NEG_TYPE		= 2,
-    TWT_ATTRIBUTE_TRIGGER_TYPE		= 3,
-    TWT_ATTRIBUTE_WAKE_DUR_US		= 4,
-    TWT_ATTRIBUTE_WAKE_INT_US		= 5,
-    TWT_ATTRIBUTE_WAKE_INT_MIN_US	= 6,
-    TWT_ATTRIBUTE_WAKE_INT_MAX_US	= 7,
-    TWT_ATTRIBUTE_WAKE_DUR_MIN_US	= 8,
-    TWT_ATTRIBUTE_WAKE_DUR_MAX_US	= 9,
-    TWT_ATTRIBUTE_AVG_PKT_SIZE		= 10,
-    TWT_ATTRIBUTE_AVG_PKT_NUM		= 11,
-    TWT_ATTRIBUTE_WAKE_TIME_OFF_US	= 12,
-    TWT_ATTRIBUTE_ALL_TWT		= 13,
-    TWT_ATTRIBUTE_RESUME_TIME_US	= 14,
-    TWT_ATTRIBUTE_AVG_EOSP_DUR		= 15,
-    TWT_ATTRIBUTE_EOSP_COUNT		= 16,
-    TWT_ATTRIBUTE_NUM_SP		= 17,
-    TWT_ATTRIBUTE_DEVICE_CAP		= 18,
-    TWT_ATTRIBUTE_PEER_CAP		= 19,
-    TWT_ATTRIBUTE_STATUS		= 20,
-    TWT_ATTRIBUTE_REASON_CODE		= 21,
-    TWT_ATTRIBUTE_RESUMED		= 22,
-    TWT_ATTRIBUTE_NOTIFICATION		= 23,
-    TWT_ATTRIBUTE_SUB_EVENT		= 24,
-    TWT_ATTRIBUTE_NUM_PEER_STATS	= 25,
-    TWT_ATTRIBUTE_AVG_PKT_NUM_TX	= 26,
-    TWT_ATTRIBUTE_AVG_PKT_SIZE_TX	= 27,
-    TWT_ATTRIBUTE_AVG_PKT_NUM_RX	= 28,
-    TWT_ATTRIBUTE_AVG_PKT_SIZE_RX	= 29,
+    TWT_ATTRIBUTE_INVALID                 = 0,
+    TWT_ATTRIBUTE_SESSION_ID              = 1,
+    TWT_ATTRIBUTE_MLO_LINK_ID             = 2,
+    TWT_ATTRIBUTE_WAKE_DUR_MICROS         = 3,
+    TWT_ATTRIBUTE_WAKE_INTERVAL_MICROS    = 4,
+    TWT_ATTRIBUTE_NEG_TYPE                = 5,
+    TWT_ATTRIBUTE_IS_TRIGGER_ENABLED      = 6,
+    TWT_ATTRIBUTE_IS_ANNOUNCED            = 7,
+    TWT_ATTRIBUTE_IS_IMPLICIT             = 8,
+    TWT_ATTRIBUTE_IS_PROTECTED            = 9,
+    TWT_ATTRIBUTE_IS_UPDATABLE            = 10,
+    TWT_ATTRIBUTE_IS_SUSPENDABLE          = 11,
+    TWT_ATTRIBUTE_IS_RESP_PM_MODE_ENABLED = 12,
+    TWT_ATTRIBUTE_REASON_CODE             = 13,
+    TWT_ATTRIBUTE_AVG_PKT_NUM_TX          = 14,
+    TWT_ATTRIBUTE_AVG_PKT_NUM_RX          = 15,
+    TWT_ATTRIBUTE_AVG_TX_PKT_SIZE         = 16,
+    TWT_ATTRIBUTE_AVG_RX_PKT_SIZE         = 17,
+    TWT_ATTRIBUTE_AVG_EOSP_DUR_US         = 18,
+    TWT_ATTRIBUTE_EOSP_COUNT              = 19,
+    TWT_ATTRIBUTE_MIN_WAKE_DURATION_US    = 20,
+    TWT_ATTRIBUTE_MAX_WAKE_DURATION_US    = 21,
+    TWT_ATTRIBUTE_MIN_WAKE_INTERVAL_US    = 22,
+    TWT_ATTRIBUTE_MAX_WAKE_INTERVAL_US    = 23,
+    TWT_ATTRIBUTE_ERROR_CODE              = 24,
+    TWT_ATTRIBUTE_SUB_EVENT               = 25,
+    TWT_ATTRIBUTE_CAP                     = 26,
+    TWT_ATTRIBUTE_IS_REQUESTOR_SUPPORTED  = 27,
+    TWT_ATTRIBUTE_IS_RESPONDER_SUPPORTED  = 28,
+    TWT_ATTRIBUTE_IS_BROADCAST_SUPPORTED  = 29,
+    TWT_ATTRIBUTE_IS_FLEXIBLE_SUPPORTED	  = 30,
+    TWT_ATTRIBUTE_WIFI_ERROR              = 31,
     TWT_ATTRIBUTE_MAX
 } TWT_ATTRIBUTE;
 
@@ -528,69 +558,6 @@ wifi_error wifi_set_dtim_config(wifi_interface_handle handle, u32 multiplier);
 void set_hautil_mode(bool halutil_mode);
 bool get_halutil_mode();
 
-/* API's to support TWT */
-
-/**@brief twt_get_capability
- *        Request TWT capability
- * @param wifi_interface_handle:
- * @return Synchronous wifi_error and TwtCapabilitySet
- */
-wifi_error twt_get_capability(wifi_interface_handle iface, TwtCapabilitySet* twt_cap_set);
-
-/**@brief twt_register_handler
- *        Request to register TWT callback
- * @param wifi_interface_handle:
- * @param TwtCallbackHandler:
- * @return Synchronous wifi_error
- */
-wifi_error twt_register_handler(wifi_interface_handle iface, TwtCallbackHandler handler);
-
-/**@brief twt_setup_request
- *        Request to send TWT setup frame
- * @param wifi_interface_handle:
- * @param TwtSetupRequest:
- * @return Synchronous wifi_error
- * @return Asynchronous EventTwtSetupResponse CB return TwtSetupResponse
- */
-wifi_error twt_setup_request(wifi_interface_handle iface, TwtSetupRequest* msg);
-
-/**@brief twt_teardown_request
- *        Request to send TWT teardown frame
- * @param wifi_interface_handle:
- * @param TwtTeardownRequest:
- * @return Synchronous wifi_error
- * @return Asynchronous EventTwtTeardownCompletion CB return TwtTeardownCompletion
- * TwtTeardownCompletion may also be received due to other events
- * like CSA, BTCX, TWT scheduler, MultiConnection, peer-initiated teardown, etc.
- */
-wifi_error twt_teardown_request(wifi_interface_handle iface, TwtTeardownRequest* msg);
-
-/**@brief twt_info_frame_request
- *        Request to send TWT info frame
- * @param wifi_interface_handle:
- * @param TwtInfoFrameRequest:
- * @return Synchronous wifi_error
- * @return Asynchronous EventTwtInfoFrameReceived CB return TwtInfoFrameReceived
- * Driver may also receive Peer-initiated TwtInfoFrame
- */
-wifi_error twt_info_frame_request(wifi_interface_handle iface, TwtInfoFrameRequest* msg);
-
-/**@brief twt_get_stats
- *        Request to get TWT stats
- * @param wifi_interface_handle:
- * @param config_id:
- * @return Synchronous wifi_error and TwtStats
- */
-wifi_error twt_get_stats(wifi_interface_handle iface, u8 config_id, TwtStats* stats);
-
-/**@brief twt_clear_stats
- *        Request to clear TWT stats
- * @param wifi_interface_handle:
- * @param config_id:
- * @return Synchronous wifi_error
- */
-wifi_error twt_clear_stats(wifi_interface_handle iface, u8 config_id);
-
 wifi_error wifi_trigger_subsystem_restart(wifi_handle handle);
 
 /**@brief nan_chre_enable_request
@@ -636,5 +603,40 @@ void prhex(const char *msg, u8 *buf, u32 nbytes);
         } \
     } while (0)
 
+/* RTT Capabilities */
+typedef struct rtt_capabilities {
+    u8 rtt_one_sided_supported;  /* if 1-sided rtt data collection is supported */
+    u8 rtt_ftm_supported;        /* if ftm rtt data collection is supported */
+    u8 lci_support;              /* location configuration information */
+    u8 lcr_support;              /* Civic Location */
+    u8 preamble_support;         /* bit mask indicate what preamble is supported */
+    u8 bw_support;               /* bit mask indicate what BW is supported */
+    u8 PAD[2];
+} rtt_capabilities_t;
+
+typedef u16 rtt_cap_preamble_type_t;
+typedef u16 rtt_akm_type_t;
+typedef u16 rtt_cipher_type_t;
+/* RTT Capabilities v2 (11az support) */
+typedef struct rtt_capabilities_mc_az {
+    struct rtt_capabilities rtt_capab;
+    /* 11AZ support */
+    /* Bitmask of preamble supported by the 11az initiator */
+    rtt_cap_preamble_type_t az_preamble_support;
+    /* bitmask of BW supported by 11az initiator */
+    u8 az_bw_support;
+    /* if 11az non-TB initiator is supported */
+    u8 ntb_initiator_supported;
+    /* if 11az non-TB responder is supported */
+    u8 ntb_responder_supported;
+    /* if 11az secure ltf is supported */
+    u8 secure_ltf_supported;
+    /* if 11az protected ranging frame is supported */
+    u8 protected_rtt_frm_supported;
+    /* Supported AKM for secure ranging */
+    rtt_akm_type_t akm_type_supported;
+    /* Supported cipher type for secure ranging */
+    rtt_cipher_type_t cipher_type_supported;
+} rtt_capabilities_mc_az_t;
 #endif
 
diff --git a/bcmdhd/wifi_hal/cpp_bindings.h b/bcmdhd/wifi_hal/cpp_bindings.h
index e006775..f96f264 100755
--- a/bcmdhd/wifi_hal/cpp_bindings.h
+++ b/bcmdhd/wifi_hal/cpp_bindings.h
@@ -77,6 +77,10 @@ public:
         return mAttributes[attribute];
     }
 
+    int get_s8(int attribute) {
+        return mAttributes[attribute] ? nla_get_s8(mAttributes[attribute]) : 0;
+    }
+
     uint8_t get_u8(int attribute) {
         return mAttributes[attribute] ? nla_get_u8(mAttributes[attribute]) : 0;
     }
@@ -131,6 +135,9 @@ public:
     uint8_t get_u8() {
         return nla_get_u8(pos);
     }
+    int get_s8() {
+        return nla_get_s8(pos);
+    }
     uint16_t get_u16() {
         return nla_get_u16(pos);
     }
diff --git a/bcmdhd/wifi_hal/nan.cpp b/bcmdhd/wifi_hal/nan.cpp
index c8ce0be..f4c4090 100644
--- a/bcmdhd/wifi_hal/nan.cpp
+++ b/bcmdhd/wifi_hal/nan.cpp
@@ -1524,9 +1524,10 @@ class NanPairingPrimitive : public WifiCommand
                     }
                 }
 
-                if (!pairing_confirm_event.npk_security_association.cipher_type ||
+                if (!pairing_confirm_event.rsp_code &&
+                        (!pairing_confirm_event.npk_security_association.cipher_type ||
                         !pairing_confirm_event.npk_security_association.npk.pmk_len ||
-                        !pairing_confirm_event.pairing_instance_id) {
+                        !pairing_confirm_event.pairing_instance_id)) {
                     ALOGE("Check invalid params received csid: 0x%x pmk_len: %u pairing_id: %u\n",
                             pairing_confirm_event.npk_security_association.cipher_type,
                             pairing_confirm_event.npk_security_association.npk.pmk_len,
@@ -2784,12 +2785,24 @@ class NanDiscEnginePrimitive : public WifiCommand
         nan_hal_resp_t *rsp_vndr_data = NULL;
         NanResponseMsg rsp_data;
         hal_info *h_info = getHalInfo(mIface);
-
-        if (reply.get_cmd() != NL80211_CMD_VENDOR || reply.get_vendor_data() == NULL) {
-            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
+        int vendor_data_len = 0;
+        int driver_nan_cap_len = 0;
+        int android15_nan_cap_size =
+                offsetof(NanCapabilities, is_suspension_supported) + sizeof(bool);
+        int min_nan_resp_size = offsetof(nan_hal_resp_t, capabilities);
+        int copy_data_len = 0;
+
+        if ((reply.get_cmd() != NL80211_CMD_VENDOR) || (reply.get_vendor_data() == NULL) ||
+                (reply.get_vendor_data_len() < min_nan_resp_size)) {
+            ALOGD("Ignoring reply with cmd = %d mType = %d len = %d,"
+                    "min expected len %d, supported nan capa size %d\n",
+                    reply.get_cmd(), mType, reply.get_vendor_data_len(),
+                    min_nan_resp_size, android15_nan_cap_size);
             return NL_SKIP;
         }
         rsp_vndr_data = (nan_hal_resp_t *)reply.get_vendor_data();
+        vendor_data_len = reply.get_vendor_data_len();
+
         ALOGI("NanDiscEnginePrmitive::handle response\n");
         memset(&rsp_data, 0, sizeof(NanResponseMsg));
         rsp_data.response_type = get_response_type((WIFI_SUB_COMMAND)rsp_vndr_data->subcmd);
@@ -2804,7 +2817,7 @@ class NanDiscEnginePrimitive : public WifiCommand
             rsp_data.nan_error[strlen(NanStatusToString(rsp_data.status))] = '\0';
         }
         rsp_data.nan_error[NAN_ERROR_STR_LEN - 1] = '\0';
-        ALOGI("\n Received nan_error string %s\n", (u8*)rsp_data.nan_error);
+        ALOGI("Received nan_error string %s\n", (u8*)rsp_data.nan_error);
 
         if (mInstId == 0 &&
                 (rsp_data.response_type == NAN_RESPONSE_PUBLISH ||
@@ -2818,37 +2831,24 @@ class NanDiscEnginePrimitive : public WifiCommand
         } else if (rsp_data.response_type == NAN_RESPONSE_SUBSCRIBE) {
             rsp_data.body.subscribe_response.subscribe_id = mInstId;
         } else if (rsp_data.response_type == NAN_GET_CAPABILITIES) {
-            /* avoid memcpy to keep backward compatibility */
-            NanCapabilities *desc = &rsp_data.body.nan_capabilities;
-            NanCapabilities *src = &rsp_vndr_data->capabilities;
-
-            desc->max_publishes = src->max_publishes;
-            desc->max_subscribes = src->max_subscribes;
-            desc->max_ndi_interfaces = src->max_ndi_interfaces;
-            desc->max_ndp_sessions = src->max_ndp_sessions;
-            desc->max_concurrent_nan_clusters = src->max_concurrent_nan_clusters;
-            desc->max_service_name_len = src->max_service_name_len;
-            desc->max_match_filter_len = src->max_match_filter_len;
-            desc->max_total_match_filter_len = src->max_total_match_filter_len;
-            desc->max_service_specific_info_len = src->max_service_specific_info_len;
-            desc->max_app_info_len = src->max_app_info_len;
-            desc->max_sdea_service_specific_info_len = src->max_sdea_service_specific_info_len;
-            desc->max_queued_transmit_followup_msgs = src->max_queued_transmit_followup_msgs;
-            desc->max_subscribe_address = src->max_subscribe_address;
-            desc->is_ndp_security_supported = src->is_ndp_security_supported;
-            desc->ndp_supported_bands = src->ndp_supported_bands;
-            desc->cipher_suites_supported = src->cipher_suites_supported;
-            desc->is_instant_mode_supported = src->is_instant_mode_supported;
-            desc->ndpe_attr_supported = src->ndpe_attr_supported;
-            desc->is_suspension_supported = src->is_suspension_supported;
-            /* Temporarily disable NAN pairing feature capability */
-            //desc->is_pairing_supported = src->is_pairing_supported;
-            ALOGI("Capabilities pairing %u, local pairing %u csid 0x%x", desc->is_pairing_supported,
-                    src->is_pairing_supported, desc->cipher_suites_supported);
-
+            NanCapabilities *dest = &rsp_data.body.nan_capabilities;
+            driver_nan_cap_len = (vendor_data_len - min_nan_resp_size);
+            copy_data_len = sizeof(NanCapabilities);
+            if (copy_data_len != driver_nan_cap_len) {
+                /* take min of driver data_nan_cap_len and android15 cap */
+                copy_data_len = min(android15_nan_cap_size, driver_nan_cap_len);
+                /* keeping framework defaults */
+                dest->is_periodic_ranging_supported = false;
+                dest->supported_bw = WIFI_RTT_BW_UNSPECIFIED;
+                dest->num_rx_chains_supported = NAN_DEFAULT_RX_CHAINS_SUPPORTED;
+            }
+            memcpy(dest, &rsp_vndr_data->capabilities, copy_data_len);
+
+            ALOGI("Capabilities pairing %u, csid 0x%x", dest->is_pairing_supported,
+                    dest->cipher_suites_supported);
             if (!get_halutil_mode()) {
-                SET_NAN_SUSPEND_CAP(h_info, desc->is_suspension_supported);
-                SET_NAN_PAIRING_CAP(h_info, desc->is_pairing_supported);
+                SET_NAN_SUSPEND_CAP(h_info, dest->is_suspension_supported);
+                SET_NAN_PAIRING_CAP(h_info, dest->is_pairing_supported);
                 ALOGI("Capabilities Cached pairing %d suspend %d\n", GET_NAN_PAIRING_CAP(h_info),
                         GET_NAN_SUSPEND_CAP(h_info));
 
@@ -3092,28 +3092,6 @@ class NanDiscEnginePrimitive : public WifiCommand
                 }
                 GET_NAN_HANDLE(info)->mHandlers.EventTransmitFollowup(&followup_ind);
                 break;
-#ifdef NOT_YET
-            case NAN_EVENT_PUBLISH_REPLIED_IND:
-                NanPublishRepliedInd pub_reply_event;
-                memset(&pub_reply_event, 0, sizeof(pub_reply_event));
-
-                for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
-                    attr_type = it.get_type();
-
-                    if (attr_type == NAN_ATTRIBUTE_SUBSCRIBE_ID) {
-                        ALOGI("sub id: %u", it.get_u16());
-                        pub_reply_event.requestor_instance_id = it.get_u8();
-                    } else if (attr_type == NAN_ATTRIBUTE_MAC_ADDR) {
-                        memcpy(pub_reply_event.addr, it.get_data(), NAN_MAC_ADDR_LEN);
-                        ALOGI("Subscriber mac: " MACSTR, MAC2STR(pub_reply_event.addr));
-                    } else if (attr_type == NAN_ATTRIBUTE_RSSI_PROXIMITY) {
-                        pub_reply_event.rssi_value = it.get_u8();
-                        ALOGI("Received rssi value : %u", it.get_u8());
-                    }
-                }
-                GET_NAN_HANDLE(info)->mHandlers.EventPublishReplied(&pub_reply_event);
-                break;
-#endif /* NOT_YET */
         } // end-of-switch-case
         return NL_SKIP;
     }
@@ -3758,6 +3736,7 @@ class NanDataPathPrimitive : public WifiCommand
         nan_hal_resp_t *rsp_vndr_data = NULL;
         NanResponseMsg rsp_data;
         int32_t result = BCME_OK;
+        int min_nan_resp_size = offsetof(nan_hal_resp_t, capabilities);
 
         ALOGI("NanDataPathPrmitive::handle Response\n");
         memset(&rsp_data, 0, sizeof(NanResponseMsg));
@@ -3771,9 +3750,11 @@ class NanDataPathPrimitive : public WifiCommand
              rsp_data.status = NAN_STATUS_SUCCESS;
         } else if (reply.get_cmd() != NL80211_CMD_VENDOR ||
             reply.get_vendor_data() == NULL ||
-                    reply.get_vendor_data_len() != sizeof(nan_hal_resp_t)) {
-            ALOGD("Ignoring reply with cmd = %d mType = %d len = %d\n",
-                    reply.get_cmd(), mType, reply.get_vendor_data_len());
+                    reply.get_vendor_data_len() < min_nan_resp_size) {
+            ALOGD("Ignoring reply with cmd = %d mType = %d len = %d,"
+                    " min expected len %d, capa size %d\n",
+                    reply.get_cmd(), mType, reply.get_vendor_data_len(),
+                    min_nan_resp_size, sizeof(NanCapabilities));
             return NL_SKIP;
         } else {
             rsp_vndr_data = (nan_hal_resp_t *)reply.get_vendor_data();
@@ -4923,6 +4904,7 @@ class NanMacControl : public WifiCommand
         int len = event.get_vendor_data_len();
         u16 attr_type;
         nan_hal_resp_t *rsp_vndr_data = NULL;
+        int min_nan_resp_size = offsetof(nan_hal_resp_t, capabilities);
 
         ALOGI("%s: Received NanMacControl event = %d (len=%d)\n",
                 __func__, event.get_cmd(), len);
@@ -4941,13 +4923,13 @@ class NanMacControl : public WifiCommand
                 ndp_instance_id = it.get_u32();
                 ALOGI("handleEvent: ndp_instance_id = [%d]\n", ndp_instance_id);
             } else if (attr_type == NAN_ATTRIBUTE_CMD_RESP_DATA) {
-                ALOGI("sizeof cmd response data: %ld, it.get_len() = %d\n",
-                        sizeof(nan_hal_resp_t), it.get_len());
-                if (it.get_len() == sizeof(nan_hal_resp_t)) {
-                    rsp_vndr_data = (nan_hal_resp_t*)it.get_data();
-                } else {
-                    ALOGE("Wrong cmd response data received\n");
+                if (it.get_len() < min_nan_resp_size) {
+                    ALOGI("Skip handling cmd resp data !!"
+                        " Min expected len : %ld, it.get_len() = %d\n",
+                        min_nan_resp_size, it.get_len());
                     return NL_SKIP;
+                } else {
+                    rsp_vndr_data = (nan_hal_resp_t *)it.get_data();
                 }
             }
         }
@@ -6121,6 +6103,7 @@ wifi_error nan_disable_request(transaction_id id,
 {
     wifi_error ret = WIFI_SUCCESS;
     hal_info *h_info = getHalInfo(iface);
+    NanMacControl *mac_prim = NULL;
 
     ALOGE("nan_disable_request: nan_state %d\n", h_info->nan_state);
 
@@ -6129,7 +6112,14 @@ wifi_error nan_disable_request(transaction_id id,
         return ret;
     }
 
-    NanMacControl *mac_prim = (NanMacControl*)(info.nan_mac_control);
+    if (NAN_HANDLE(info)) {
+        mac_prim = (NanMacControl*)(info.nan_mac_control);
+    } else {
+        ALOGE("\n info is not allocated, due to driver mismatch... Check DHD\n");
+        return WIFI_ERROR_NOT_SUPPORTED;
+    }
+
+    NULL_CHECK_RETURN(mac_prim, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
     NanMacControl *cmd = new NanMacControl(iface, id, NULL, NAN_REQUEST_LAST);
 
     NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
@@ -6942,30 +6932,6 @@ class NanEventCap : public WifiCommand
                     GET_NAN_HANDLE(info)->mHandlers.EventBeaconSdfPayload(&sdfInd);
                     break;
                 }
-#ifdef NOT_YET
-                case NAN_EVENT_PUBLISH_REPLIED_IND: {
-                    ALOGI("Received NAN_EVENT_PUBLISH_REPLIED_IND\n");
-                    NanPublishRepliedInd pub_reply_event;
-                    memset(&pub_reply_event, 0, sizeof(pub_reply_event));
-
-                    for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
-                        attr_type = it.get_type();
-
-                        if (attr_type == NAN_ATTRIBUTE_SUBSCRIBE_ID) {
-                            ALOGI("sub id: %u", it.get_u32());
-                            pub_reply_event.requestor_instance_id = it.get_u32();
-                        } else if (attr_type == NAN_ATTRIBUTE_MAC_ADDR) {
-                            memcpy(pub_reply_event.addr, it.get_data(), NAN_MAC_ADDR_LEN);
-                            ALOGI("Subscriber mac: " MACSTR, MAC2STR(pub_reply_event.addr));
-                        } else if (attr_type == NAN_ATTRIBUTE_RSSI_PROXIMITY) {
-                            pub_reply_event.rssi_value = it.get_u8();
-                            ALOGI("Received rssi value : %u", it.get_u8());
-                        }
-                    }
-                    GET_NAN_HANDLE(info)->mHandlers.EventPublishReplied(&pub_reply_event);
-                    break;
-                }
-#endif /* NOT_YET */
                 case NAN_EVENT_TCA: {
                     ALOGI("Received NAN_EVENT_TCA\n");
                     //GET_NAN_HANDLE(info)->mHandlers.EventTca(&sdfPayload);
@@ -7310,9 +7276,10 @@ class NanEventCap : public WifiCommand
                         }
                     }
 
-                    if (!pairing_confirm_event.npk_security_association.cipher_type ||
+                    if (!pairing_confirm_event.rsp_code &&
+                            (!pairing_confirm_event.npk_security_association.cipher_type ||
                             !pairing_confirm_event.npk_security_association.npk.pmk_len ||
-                            !pairing_confirm_event.pairing_instance_id) {
+                            !pairing_confirm_event.pairing_instance_id)) {
                         ALOGE("Check invalid params received csid:0x%x pmk_len:%u pairing_id: %u\n",
                                 pairing_confirm_event.npk_security_association.cipher_type,
                                 pairing_confirm_event.npk_security_association.npk.pmk_len,
@@ -7549,6 +7516,9 @@ wifi_error nan_data_request_initiator(transaction_id id,
         }
     } else if (msg->key_info.key_type == NAN_SECURITY_KEY_INPUT_PASSPHRASE) {
         NanDataPathSecInfoRequest msg_sec_info;
+
+        memset(&msg_sec_info, 0, sizeof(msg_sec_info));
+
         if (msg->requestor_instance_id == 0) {
             ALOGE("Invalid Pub ID = %d, Mandatory param is missing\n", msg->requestor_instance_id);
             ret = WIFI_ERROR_INVALID_ARGS;
@@ -7557,7 +7527,7 @@ wifi_error nan_data_request_initiator(transaction_id id,
             ALOGI("Pub ID = %d, Mandatory param is present\n", msg->requestor_instance_id);
         }
         if (ETHER_ISNULLADDR(msg->peer_disc_mac_addr)) {
-            ALOGE("Invalid Pub NMI, Mandatory param is missing\n");
+            ALOGE("NDP Init: Invalid Pub NMI, Mandatory param is missing\n");
             ret = WIFI_ERROR_INVALID_ARGS;
             goto done;
         }
@@ -7640,6 +7610,8 @@ wifi_error nan_data_indication_response(transaction_id id,
     if (msg->key_info.key_type == NAN_SECURITY_KEY_INPUT_PASSPHRASE) {
         NanDataPathSecInfoRequest msg_sec_info;
 
+        memset(&msg_sec_info, 0, sizeof(msg_sec_info));
+
         if (msg->ndp_instance_id == 0) {
             ALOGE("Invalid NDP ID, Mandatory info is not present\n");
             ret = WIFI_ERROR_INVALID_ARGS;
@@ -7660,7 +7632,7 @@ wifi_error nan_data_indication_response(transaction_id id,
         }
 
         if (ETHER_ISNULLADDR(cmd->mPubNmi)) {
-            ALOGE("Invalid Pub NMI\n");
+            ALOGE("NDP resp: Invalid Pub NMI\n");
             ret = WIFI_ERROR_INVALID_ARGS;
             goto done;
         }
diff --git a/bcmdhd/wifi_hal/rtt.cpp b/bcmdhd/wifi_hal/rtt.cpp
index c4adace..039f27a 100644
--- a/bcmdhd/wifi_hal/rtt.cpp
+++ b/bcmdhd/wifi_hal/rtt.cpp
@@ -158,7 +158,7 @@ public:
     }
 
     virtual int create() {
-        ALOGD("Creating message to get scan capablities; iface = %d", mIfaceInfo->id);
+        ALOGD("Creating message to get rtt capabilities; iface = %d", mIfaceInfo->id);
 
         int ret = mMsg.create(GOOGLE_OUI, RTT_SUBCMD_GETCAPABILITY);
         if (ret < 0) {
@@ -170,6 +170,8 @@ public:
 
 protected:
     virtual int handleResponse(WifiEvent& reply) {
+        rtt_capabilities_mc_az_t SrcCapabilities;
+        wifi_rtt_capabilities_v3 DestCapabilities;
 
         ALOGD("In GetRttCapabilitiesCommand::handleResponse");
 
@@ -184,11 +186,43 @@ protected:
         void *data = reply.get_vendor_data();
         int len = reply.get_vendor_data_len();
 
-        ALOGD("Id = %0x, subcmd = %d, len = %d, expected len = %d", id, subcmd, len,
-                sizeof(*mCapabilities));
+        ALOGD("Id = %0x, subcmd = %d, len = %d, expected len = %d",
+                id, subcmd, len, sizeof(*mCapabilities));
+
+        memset(&SrcCapabilities, 0, sizeof(SrcCapabilities));
+        memset(&DestCapabilities, 0, sizeof(DestCapabilities));
+
+        memcpy(&SrcCapabilities, data,
+                min(len, (int) sizeof(SrcCapabilities)));
+
+        DestCapabilities.rtt_capab.rtt_one_sided_supported =
+                SrcCapabilities.rtt_capab.rtt_one_sided_supported;
+        DestCapabilities.rtt_capab.rtt_ftm_supported =
+                SrcCapabilities.rtt_capab.rtt_ftm_supported;
+        DestCapabilities.rtt_capab.lci_support =
+                SrcCapabilities.rtt_capab.lci_support;
+        DestCapabilities.rtt_capab.lcr_support =
+                SrcCapabilities.rtt_capab.lcr_support;
+        DestCapabilities.rtt_capab.preamble_support =
+                SrcCapabilities.rtt_capab.preamble_support;
+        DestCapabilities.rtt_capab.bw_support =
+                SrcCapabilities.rtt_capab.bw_support;
+        DestCapabilities.rtt_capab.responder_supported = 0;
+        DestCapabilities.rtt_capab.mc_version = 0;
+
+        DestCapabilities.az_preamble_support =
+                SrcCapabilities.az_preamble_support;
+
+        DestCapabilities.az_bw_support =
+                SrcCapabilities.az_bw_support;
+
+        DestCapabilities.ntb_initiator_supported =
+                SrcCapabilities.ntb_initiator_supported;
 
-        memcpy(mCapabilities, data, min(len, (int) sizeof(*mCapabilities)));
+        DestCapabilities.ntb_responder_supported =
+                SrcCapabilities.ntb_responder_supported;
 
+        memcpy(mCapabilities, &DestCapabilities, sizeof(DestCapabilities));
         return NL_OK;
     }
 };
diff --git a/bcmdhd/wifi_hal/twt.cpp b/bcmdhd/wifi_hal/twt.cpp
index 8a55ec0..b9ad330 100755
--- a/bcmdhd/wifi_hal/twt.cpp
+++ b/bcmdhd/wifi_hal/twt.cpp
@@ -45,20 +45,51 @@
 
 static const char *TwtCmdToString(int cmd);
 static void EventGetAttributeData(u8 sub_event_type, nlattr *vendor_data);
-typedef void *TwtRequest;
+static const char *TwtEventToString(int cmd);
+int session_id;
 
 #define C2S(x)  case x: return #x;
+#define TWT_MAC_INVALID_TRANSID 0xFFFF
+#define TWT_CONFIG_ID_AUTO      0xFF
+
+/* Struct for table which has event and cmd type */
+typedef struct cmd_type_lookup {
+    int event_type;
+    int cmd_type;
+} cmd_type_lookup_t;
+
+cmd_type_lookup_t cmd_type_lookup_tbl[] = {
+    {TWT_SESSION_SETUP_CREATE, TWT_SESSION_SETUP_REQUEST},
+    {TWT_SESSION_SETUP_UPDATE, TWT_SESSION_UPDATE_REQUEST},
+    {TWT_SESSION_TEARDOWN, TWT_SESSION_TEAR_DOWN_REQUEST},
+    {TWT_SESSION_STATS, TWT_SESSION_GET_STATS},
+    {TWT_SESSION_SUSPEND, TWT_SESSION_SUSPEND_REQUEST},
+    {TWT_SESSION_RESUME, TWT_SESSION_RESUME_REQUEST}
+};
 
 typedef struct _twt_hal_info {
     void *twt_handle;
     void *twt_feature_request;
+    wifi_request_id request_id;
+    TwtRequestType cmd_type;
 } twt_hal_info_t;
 
 twt_hal_info_t twt_info;
 
-#define TWT_HANDLE(twt_info)                  ((twt_info).twt_handle)
-#define GET_TWT_HANDLE(twt_info)              ((TwtHandle *)twt_info.twt_handle)
+#define TWT_HANDLE(twt_info)           ((twt_info).twt_handle)
+#define GET_TWT_HANDLE(twt_info)       ((TwtHandle *)twt_info.twt_handle)
+#define SET_TWT_DATA(id, type)         ((twt_info.cmd_type = type) && (twt_info.request_id = id))
+
+#define WIFI_IS_TWT_REQ_SUPPORT        ((1u << 0u))
+#define WIFI_IS_TWT_RESP_SUPPORT       ((1u << 1u))
+#define WIFI_IS_TWT_BROADCAST_SUPPORT  ((1u << 2u))
+#define WIFI_IS_TWT_FLEX_SUPPORT       ((1u << 3u))
+#define WIFI_MIN_WAKE_DUR_MICROS       ((1u << 4u))
+#define WIFI_MAX_WAKE_DUR_MICROS       ((1u << 5u))
+#define WIFI_MIN_WAKE_INRVL_MICROS     ((1u << 6u))
+#define WIFI_MAX_WAKE_iNRVL_MICROS     ((1u << 7u))
 
+/* To be deprecated */
 #define WL_TWT_CAP_FLAGS_REQ_SUPPORT    (1u << 0u)
 #define WL_TWT_CAP_FLAGS_RESP_SUPPORT   (1u << 1u)
 #define WL_TWT_CAP_FLAGS_BTWT_SUPPORT   (1u << 2u)
@@ -67,8 +98,8 @@ twt_hal_info_t twt_info;
 class TwtHandle
 {
     public:
-        TwtCallbackHandler mHandlers;
-        TwtHandle(wifi_handle handle, TwtCallbackHandler handlers):mHandlers(handlers)
+        wifi_twt_events mEvents;
+        TwtHandle(wifi_handle handle, wifi_twt_events events):mEvents(events)
     {}
 
 };
@@ -76,11 +107,31 @@ class TwtHandle
 static const char *TwtCmdToString(int cmd)
 {
     switch (cmd) {
-        C2S(TWT_SETUP_REQUEST);
-        C2S(TWT_INFO_FRAME_REQUEST);
-        C2S(TWT_TEAR_DOWN_REQUEST);
+        C2S(TWT_GET_CAPABILITIES);
+        C2S(TWT_SESSION_SETUP_REQUEST);
+        C2S(TWT_SESSION_UPDATE_REQUEST);
+        C2S(TWT_SESSION_SUSPEND_REQUEST);
+        C2S(TWT_SESSION_RESUME_REQUEST);
+        C2S(TWT_SESSION_TEAR_DOWN_REQUEST);
+        C2S(TWT_SESSION_GET_STATS);
+        C2S(TWT_SESSION_CLEAR_STATS);
+        default:
+            return "UNKNOWN_TWT_CMD";
+    }
+}
+
+static const char *TwtEventToString(int sub_event_type)
+{
+    switch (sub_event_type) {
+        C2S(TWT_SESSION_FAILURE);
+        C2S(TWT_SESSION_SETUP_CREATE);
+        C2S(TWT_SESSION_SETUP_UPDATE);
+        C2S(TWT_SESSION_TEARDOWN);
+        C2S(TWT_SESSION_STATS);
+        C2S(TWT_SESSION_SUSPEND);
+        C2S(TWT_SESSION_RESUME);
         default:
-        return "UNKNOWN_NAN_CMD";
+            return "UNKNOWN_TWT_EVENT";
     }
 }
 
@@ -88,153 +139,308 @@ static bool is_twt_sub_event(int sub_event_type)
 {
     bool is_twt_event = false;
     switch (sub_event_type) {
-        case TWT_SETUP_RESPONSE:
-        case TWT_TEARDOWN_COMPLETION:
-        case TWT_INFORM_FRAME:
-        case TWT_NOTIFY:
+        case TWT_SESSION_FAILURE:
+        case TWT_SESSION_SETUP_CREATE:
+        case TWT_SESSION_SETUP_UPDATE:
+        case TWT_SESSION_TEARDOWN:
+        case TWT_SESSION_STATS:
+        case TWT_SESSION_SUSPEND:
+        case TWT_SESSION_RESUME:
             is_twt_event = true;
     }
     return is_twt_event;
 }
 
+/* Return cmd type matching the event type */
+static int cmd_type_lookup(int event_type) {
+    for (u8 i = 0; i < ARRAYSIZE(cmd_type_lookup_tbl); i++) {
+        if (event_type == cmd_type_lookup_tbl[i].event_type) {
+            return cmd_type_lookup_tbl[i].cmd_type;
+        }
+    }
+    ALOGE("Lookup for cmd type with event_type = %s failed\n",
+                TwtEventToString(event_type));
+    return -1;
+}
+
 void EventGetAttributeData(u8 sub_event_type, nlattr *vendor_data)
 {
     u8 attr_type = 0;
+    wifi_twt_error_code error_code;
+    TwtHandle *twt_handle = GET_TWT_HANDLE(twt_info);
+    wifi_request_id RequestId = 0;
+
+    if (!get_halutil_mode()) {
+        TwtRequestType cmd_type = (TwtRequestType)cmd_type_lookup(sub_event_type);
+
+        if (twt_handle == NULL) {
+            ALOGE("twt callback handle is null, skip processing the event data !!\n");
+            goto fail;
+        }
+
+        ALOGI("EventGetAttributeData: event: %s, cmd: %s!!\n",
+            TwtEventToString(sub_event_type), TwtCmdToString(cmd_type));
+
+        if ((sub_event_type == TWT_SESSION_FAILURE) || (cmd_type == twt_info.cmd_type)) {
+            RequestId = twt_info.request_id;
+            ALOGE("Retrieved RequestId %d\n", RequestId);
+        } else {
+            ALOGE("Unexpected event_type %d!!\n", cmd_type);
+            goto fail;
+        }
+    }
 
     switch (sub_event_type) {
-        case TWT_SETUP_RESPONSE:
-            TwtSetupResponse setup_response;
+        case TWT_SESSION_FAILURE: {
+            for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
+                attr_type = it.get_type();
+                switch (attr_type) {
+                    case TWT_ATTRIBUTE_SUB_EVENT:
+                        if (sub_event_type != it.get_u8()) {
+                            ALOGE("Non matching attributes: Skip\n");
+                            goto fail;
+                        }
+                        break;
+                    case TWT_ATTRIBUTE_ERROR_CODE:
+                        error_code = (wifi_twt_error_code)it.get_u8();
+                        ALOGD("error code = %u\n", error_code);
+                        break;
+                    default:
+                        ALOGE("Unknown attr_type: %d\n", attr_type);
+                        goto fail;
+                }
+            }
+
+            twt_handle->mEvents.on_twt_failure(RequestId, error_code);
+            ALOGI("Notified on_twt_failure: Id %d\n", RequestId);
+            break;
+        }
+        case TWT_SESSION_SETUP_CREATE:
+        case TWT_SESSION_SETUP_UPDATE: {
+            wifi_twt_session session;
+
+            memset(&session, 0, sizeof(wifi_twt_session));
+
             for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
                 attr_type = it.get_type();
                 switch (attr_type) {
-                    case TWT_ATTRIBUTE_CONFIG_ID:
-                        ALOGI("config_id = %u\n", it.get_u8());
-                        setup_response.config_id = it.get_u8();
+                    case TWT_ATTRIBUTE_SUB_EVENT:
+                        if (sub_event_type != it.get_u8()) {
+                            ALOGE("Non matching attributes: Skip\n");
+                            goto fail;
+                        }
+                        break;
+                    case TWT_ATTRIBUTE_SESSION_ID:
+                        session.session_id = it.get_u32();
+                        ALOGI("session_id = %d\n", session.session_id);
+                        break;
+                    case TWT_ATTRIBUTE_MLO_LINK_ID:
+                        session.mlo_link_id = it.get_u8();
+                        ALOGI("mlo_link_id = %d\n", session.mlo_link_id);
+                        break;
+                    case TWT_ATTRIBUTE_WAKE_DUR_MICROS:
+                        session.wake_duration_micros = it.get_u32();
+                        ALOGI("wake_duration_micros = %d\n",
+                                session.wake_duration_micros);
+                        break;
+                    case TWT_ATTRIBUTE_WAKE_INTERVAL_MICROS:
+                        session.wake_interval_micros = it.get_u32();
+                        ALOGI("wake_interval_micros = %d\n",
+                                session.wake_interval_micros);
                         break;
                     case TWT_ATTRIBUTE_NEG_TYPE:
-                        ALOGI("neg type = %u\n", it.get_u8());
-                        setup_response.negotiation_type = it.get_u8();
+                        session.negotiation_type = (wifi_twt_negotiation_type)it.get_u8();
+                        ALOGI("neg type = %u\n", session.negotiation_type);
                         break;
-                    case TWT_ATTRIBUTE_REASON_CODE:
-                        setup_response.reason_code = (TwtSetupReasonCode)it.get_u8();
-                        ALOGI("reason code = %u\n", setup_response.reason_code);
+                    case TWT_ATTRIBUTE_IS_TRIGGER_ENABLED:
+                        session.is_trigger_enabled = it.get_u8();
+                        ALOGI("is_trigger_enabled = %d\n", session.is_trigger_enabled);
+                        break;
+                    case TWT_ATTRIBUTE_IS_ANNOUNCED:
+                        session.is_announced = it.get_u8();
+                        ALOGI("is_announced = %d\n", session.is_announced);
                         break;
-                    case TWT_ATTRIBUTE_STATUS:
-                        setup_response.status = it.get_u8();
-                        ALOGI("status = %u\n", setup_response.status);
+                    case TWT_ATTRIBUTE_IS_IMPLICIT:
+                        session.is_implicit = it.get_u8();
+                        ALOGI("is_implicit = %d\n", session.is_implicit);
                         break;
-                    case TWT_ATTRIBUTE_TRIGGER_TYPE:
-                        setup_response.trigger_type = it.get_u8();
-                        ALOGI("trigger type = %u\n", setup_response.trigger_type);
+                    case TWT_ATTRIBUTE_IS_PROTECTED:
+                        session.is_protected = it.get_u8();
+                        ALOGI("is_protected = %d\n", session.is_protected);
                         break;
-                    case TWT_ATTRIBUTE_WAKE_DUR_US:
-                        setup_response.wake_dur_us = it.get_u32();
-                        ALOGI("wake_dur_us = %d\n", setup_response.wake_dur_us);
+                    case TWT_ATTRIBUTE_IS_UPDATABLE:
+                        session.is_updatable = it.get_u8();
+                        ALOGI("is_updatable = %d\n", session.is_updatable);
                         break;
-                    case TWT_ATTRIBUTE_WAKE_INT_US:
-                        setup_response.wake_int_us = it.get_u32();
-                        ALOGI("wake_int_us = %d\n", setup_response.wake_int_us);
+                    case TWT_ATTRIBUTE_IS_SUSPENDABLE:
+                        session.is_suspendable = it.get_u8();
+                        ALOGI("is_suspendable = %d\n", session.is_suspendable);
                         break;
-                     case TWT_ATTRIBUTE_WAKE_TIME_OFF_US:
-                         setup_response.wake_time_off_us = it.get_u32();
-                         ALOGI("wake_time_off_us = %d\n", setup_response.wake_time_off_us);
-                         break;
-                     default:
-                         if (attr_type != TWT_ATTRIBUTE_SUB_EVENT) {
-                             ALOGE("Unknown attr_type: %d\n", attr_type);
-                         }
-                         break;
+                    case TWT_ATTRIBUTE_IS_RESP_PM_MODE_ENABLED:
+                        session.is_responder_pm_mode_enabled = it.get_u8();
+                        ALOGI("is_responder_pm_mode_enabled = %d\n",
+                                session.is_responder_pm_mode_enabled);
+                        break;
+                    default:
+                        ALOGE("Unknown attr_type: %d\n", attr_type);
+                        goto fail;
                 }
             }
-            GET_TWT_HANDLE(twt_info)->mHandlers.EventTwtSetupResponse(&setup_response);
+
+            if (session.session_id != TWT_CONFIG_ID_AUTO) {
+                if (sub_event_type == TWT_SESSION_SETUP_CREATE) {
+                    twt_handle->mEvents.on_twt_session_create(RequestId, session);
+                    ALOGI("Notified on_twt_session_create: Id %d\n", RequestId);
+                } else if (sub_event_type == TWT_SESSION_SETUP_UPDATE) {
+                    twt_handle->mEvents.on_twt_session_update(RequestId, session);
+                    ALOGI("Notified on_twt_session_update: Id %d\n", RequestId);
+                } else {
+                    ALOGE("Unexpected event_type %d!!\n", sub_event_type);
+                }
+            } else {
+                ALOGE("Unexpected session_id!!\n");
+            }
+
             break;
-        case TWT_TEARDOWN_COMPLETION:
-            TwtTeardownCompletion teardown_event;
+        }
+
+        case TWT_SESSION_SUSPEND:
+        case TWT_SESSION_RESUME: {
             for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
                 attr_type = it.get_type();
                 switch (attr_type) {
-                    case TWT_ATTRIBUTE_CONFIG_ID:
-                        ALOGI("config_id = %u\n", it.get_u8());
-                        teardown_event.config_id = it.get_u8();
-                        break;
-                    case TWT_ATTRIBUTE_STATUS:
-                        teardown_event.status = it.get_u8();
-                        ALOGI("status = %u\n", teardown_event.status);
-                        break;
-                    case TWT_ATTRIBUTE_ALL_TWT:
-                        teardown_event.all_twt = it.get_u32();
-                        ALOGI("all_twt = %d\n", teardown_event.all_twt);
+                    case TWT_ATTRIBUTE_SUB_EVENT:
+                        if (sub_event_type != it.get_u8()) {
+                            ALOGE("Non matching attributes: Skip\n");
+                            goto fail;
+                        }
                         break;
-                    case TWT_ATTRIBUTE_REASON_CODE:
-                        teardown_event.reason = (TwtTeardownReason)it.get_u8();
-                        ALOGI("reason = %u\n", teardown_event.reason);
+                    case TWT_ATTRIBUTE_SESSION_ID:
+                        session_id = it.get_u32();
+                        ALOGI("session_id = %d\n", session_id);
                         break;
                     default:
-                        if (attr_type != TWT_ATTRIBUTE_SUB_EVENT) {
-                            ALOGE("Unknown attr_type: %d\n", attr_type);
-                        }
-                        break;
+                        ALOGE("Unknown attr_type: %d\n", attr_type);
+                        goto fail;
+                }
+            }
+
+            if (session_id != TWT_CONFIG_ID_AUTO) {
+                if (sub_event_type == TWT_SESSION_SUSPEND) {
+                    twt_handle->mEvents.on_twt_session_suspend(RequestId, session_id);
+                    ALOGI("Notified on_twt_session_suspend: Id %d\n", RequestId);
+                } else if (sub_event_type == TWT_SESSION_RESUME) {
+                    twt_handle->mEvents.on_twt_session_resume(RequestId, session_id);
+                    ALOGI("Notified on_twt_session_resume: Id %d\n", RequestId);
+                } else {
+                    ALOGE("Unexpected event_type %d!!\n", sub_event_type);
                 }
+            } else {
+                ALOGE("Unexpected session_id!!\n");
             }
-            GET_TWT_HANDLE(twt_info)->mHandlers.EventTwtTeardownCompletion(&teardown_event);
             break;
-        case TWT_INFORM_FRAME:
-            TwtInfoFrameReceived info_frame_event;
+        }
+        case TWT_SESSION_TEARDOWN: {
+            wifi_twt_teardown_reason_code reason_code;
+
             for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
                 attr_type = it.get_type();
                 switch (attr_type) {
-                    case TWT_ATTRIBUTE_CONFIG_ID:
-                        ALOGI("config_id = %u\n", it.get_u8());
-                        info_frame_event.config_id = it.get_u8();
-                        break;
-                    case TWT_ATTRIBUTE_REASON_CODE:
-                        info_frame_event.reason = (TwtInfoFrameReason)it.get_u8();
-                        ALOGI("reason = %u\n", info_frame_event.reason);
-                        break;
-                    case TWT_ATTRIBUTE_STATUS:
-                        info_frame_event.status = it.get_u8();
-                        ALOGI("status = %u\n", info_frame_event.status);
+                    case TWT_ATTRIBUTE_SUB_EVENT:
+                        if (sub_event_type != it.get_u8()) {
+                            ALOGE("Non matching attributes: Skip\n");
+                            goto fail;
+                        }
                         break;
-                    case TWT_ATTRIBUTE_ALL_TWT:
-                        info_frame_event.all_twt = it.get_u32();
-                        ALOGI("all_twt = %d\n", info_frame_event.all_twt);
+                    case TWT_ATTRIBUTE_SESSION_ID:
+                        session_id = it.get_u32();
+                        ALOGI("session_id = %d\n", session_id);
                         break;
-                    case TWT_ATTRIBUTE_RESUMED:
-                        info_frame_event.twt_resumed = it.get_u8();
-                        ALOGI("twt_resumed = %u\n", info_frame_event.twt_resumed);
+                    case TWT_ATTRIBUTE_REASON_CODE:
+                        reason_code = (wifi_twt_teardown_reason_code)it.get_u8();
+                        ALOGI("reason code = %u\n", reason_code);
                         break;
                     default:
-                        if (attr_type != TWT_ATTRIBUTE_SUB_EVENT) {
-                            ALOGE("Unknown attr_type: %d\n", attr_type);
-                        }
-                        break;
+                        ALOGE("Unknown attr_type: %d\n", attr_type);
+                        goto fail;
                 }
             }
-            GET_TWT_HANDLE(twt_info)->mHandlers.EventTwtInfoFrameReceived(&info_frame_event);
+
+            if (session_id != TWT_CONFIG_ID_AUTO) {
+                twt_handle->mEvents.on_twt_session_teardown(RequestId,
+                        session_id, reason_code);
+                ALOGI("Notified on_twt_session_teardown: Id %d\n", RequestId);
+            } else {
+                ALOGE("Unexpected session_id!!\n");
+            }
+
             break;
-        case TWT_NOTIFY:
-            TwtDeviceNotify notif_event;
+        }
+        case TWT_SESSION_STATS: {
+            wifi_twt_session_stats stats;
+
+            memset(&stats, 0, sizeof(wifi_twt_session_stats));
+
             for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
                 attr_type = it.get_type();
                 switch (attr_type) {
-                    case TWT_ATTRIBUTE_NOTIFICATION:
-                        notif_event.notification = (TwtNotification)it.get_u8();
-                        ALOGI("notification = %u\n", notif_event.notification);
-                        break;
-                    default:
-                        if (attr_type != TWT_ATTRIBUTE_SUB_EVENT) {
-                            ALOGE("Unknown attr_type: %d\n", attr_type);
+                    case TWT_ATTRIBUTE_SUB_EVENT:
+                        if (sub_event_type != it.get_u8()) {
+                            ALOGE("Non matching attributes: Skip\n");
+                            goto fail;
                         }
                         break;
+                    case TWT_ATTRIBUTE_SESSION_ID:
+                        session_id = it.get_u32();
+                        ALOGI("session_id = %d\n", session_id);
+                        break;
+                    case TWT_ATTRIBUTE_AVG_PKT_NUM_TX:
+                        stats.avg_pkt_num_tx = it.get_u32();
+                        ALOGI("avg_pkt_num_tx = %u\n", stats.avg_pkt_num_tx);
+                        break;
+                    case TWT_ATTRIBUTE_AVG_PKT_NUM_RX:
+                        stats.avg_pkt_num_rx = it.get_u32();
+                        ALOGI("avg_pkt_num_rx = %u\n", stats.avg_pkt_num_rx);
+                        break;
+                    case TWT_ATTRIBUTE_AVG_TX_PKT_SIZE:
+                        stats.avg_tx_pkt_size = it.get_u32();
+                        ALOGI("avg_tx_pkt_size = %u\n", stats.avg_tx_pkt_size);
+                        break;
+                    case TWT_ATTRIBUTE_AVG_RX_PKT_SIZE:
+                        stats.avg_rx_pkt_size = it.get_u32();
+                        ALOGI("avg_rx_pkt_size = %u\n", stats.avg_rx_pkt_size);
+                        break;
+                    case TWT_ATTRIBUTE_AVG_EOSP_DUR_US:
+                        stats.avg_eosp_dur_us = it.get_u32();
+                        ALOGI("avg_eosp_dur_us = %u\n", stats.avg_eosp_dur_us);
+                        break;
+                    case TWT_ATTRIBUTE_EOSP_COUNT:
+                        stats.eosp_count = it.get_u32();
+                        ALOGI("eosp_count = %u\n", stats.eosp_count);
+                        break;
+                    default:
+                        ALOGE("Unknown attr_type: %d\n", attr_type);
+                        goto fail;
                 }
             }
-            GET_TWT_HANDLE(twt_info)->mHandlers.EventTwtDeviceNotify(&notif_event);
+
+            if (session_id != TWT_CONFIG_ID_AUTO) {
+                twt_handle->mEvents.on_twt_session_stats(RequestId,
+                        session_id, stats);
+                ALOGI("Notified on_twt_session_stats: Id %d\n", RequestId);
+            } else {
+                ALOGE("Unexpected session_id!!\n");
+            }
+
             break;
+        }
         default:
             ALOGE("Unknown event_type: %d\n", sub_event_type);
             break;
     }
-    return;
+
+    fail:
+        return;
 }
 
 void HandleTwtEvent(nlattr *vendor_data) {
@@ -245,6 +451,8 @@ void HandleTwtEvent(nlattr *vendor_data) {
         event_type = it.get_type();
         if (event_type == TWT_ATTRIBUTE_SUB_EVENT) {
             sub_event_type = it.get_u8();
+            ALOGI("%s: Event %s: (%d)\n",
+                    __func__, TwtEventToString(sub_event_type), sub_event_type);
             if (is_twt_sub_event(sub_event_type)) {
                 EventGetAttributeData(sub_event_type, vendor_data);
             }
@@ -255,361 +463,196 @@ void HandleTwtEvent(nlattr *vendor_data) {
 
 class TwtEventCap : public WifiCommand
 {
-    public:
-        TwtEventCap(wifi_interface_handle iface, int id)
-            : WifiCommand("TwtCommand", iface, id)
-        {}
-
-        int start()
-        {
-            registerTwtVendorEvents();
-            return WIFI_SUCCESS;
-        }
-
-        int handleResponse(WifiEvent& reply) {
-            return NL_SKIP;
-        }
-
-        void registerTwtVendorEvents()
-        {
-            registerVendorHandler(BRCM_OUI, BRCM_VENDOR_EVENT_TWT);
-        }
-
-        void unregisterTwtVendorEvents()
-        {
-            unregisterVendorHandler(BRCM_OUI, BRCM_VENDOR_EVENT_TWT);
-        }
-
-        int handleEvent(WifiEvent& event) {
-            u16 attr_type;
-            TwtEventType twt_event;
-
-            nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
-            int len = event.get_vendor_data_len();
-            int event_id = event.get_vendor_subcmd();
-
-            ALOGI("EventCapture: Received TWT event: %d\n", event_id);
-            if (!vendor_data || len == 0) {
-                ALOGE("No event data found");
-                return NL_SKIP;
-            }
-
-            switch (event_id) {
-                case BRCM_VENDOR_EVENT_TWT: {
-                    ALOGE("Handle TWT event: %d\n", event_id);
-                    HandleTwtEvent(vendor_data);
-                    break;
-                }
-                default:
-                    break;
-            }
-            return NL_SKIP;
-        }
-};
-
-/* To see event prints in console */
-wifi_error twt_event_check_request(transaction_id id, wifi_interface_handle iface)
-{
-    TwtEventCap *cmd = new TwtEventCap(iface, id);
-    if (cmd == NULL) {
-        return WIFI_ERROR_NOT_SUPPORTED;
-    }
-    return (wifi_error)cmd->start();
-}
-
-//////////////////////////////////////////////////////////////////////////
-class GetTwtCapabilitiesCommand : public WifiCommand
-{
-    TwtCapabilitySet *mCapabilities;
+    transaction_id mId;
 public:
-    GetTwtCapabilitiesCommand(wifi_interface_handle iface, TwtCapabilitySet *capabilities)
-        : WifiCommand("GetTwtCapabilitiesCommand", iface, 0), mCapabilities(capabilities)
+    TwtEventCap(wifi_interface_handle iface, int id)
+        : WifiCommand("TwtCommand", iface, id)
     {
-        memset(mCapabilities, 0, sizeof(*mCapabilities));
+        mId = id;
     }
 
-    virtual int create() {
-        ALOGD("Creating message to get twt capabilities; iface\n");
-
-        int ret = mMsg.create(GOOGLE_OUI, TWT_SUBCMD_GETCAPABILITY);
-        if (ret < 0) {
-            ALOGE("Failed to send the twt cap cmd, err = %d\n", ret);
-        }
-        ALOGD("Success to send twt cap cmd, err = %d\n", ret);
-        return ret;
+    int start()
+    {
+        registerTwtVendorEvents();
+        return WIFI_SUCCESS;
     }
 
-private:
-    TwtCapability parseTwtCap(uint32_t twt_peer_cap) {
-        TwtCapability cap;
-        cap.requester_supported = (twt_peer_cap & WL_TWT_CAP_FLAGS_REQ_SUPPORT) ? 1 : 0;
-        cap.responder_supported = (twt_peer_cap & WL_TWT_CAP_FLAGS_RESP_SUPPORT) ? 1 : 0;
-        cap.broadcast_twt_supported = (twt_peer_cap & WL_TWT_CAP_FLAGS_BTWT_SUPPORT) ? 1 : 0;
-        cap.flexibile_twt_supported = (twt_peer_cap & WL_TWT_CAP_FLAGS_FLEX_SUPPORT) ? 1 : 0;
-        return cap;
+    int handleResponse(WifiEvent& reply) {
+        return NL_SKIP;
     }
 
-protected:
-    virtual int handleResponse(WifiEvent& reply) {
+    void registerTwtVendorEvents()
+    {
+        registerVendorHandler(BRCM_OUI, BRCM_VENDOR_EVENT_TWT);
+    }
 
-        ALOGI("In GetTwtCapabilitiesCommand::handleResponse");
+    void unregisterTwtVendorEvents()
+    {
+        unregisterVendorHandler(BRCM_OUI, BRCM_VENDOR_EVENT_TWT);
+    }
 
-        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
-            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
-            return NL_SKIP;
-        }
+    int handleEvent(WifiEvent& event) {
+        u16 attr_type;
+        wifi_twt_error_code error_code;
+        u8 sub_event_type = 0;
+        TwtEventType twt_event;
+        int session_id = 0;
 
-        int id = reply.get_vendor_id();
-        int subcmd = reply.get_vendor_subcmd();
-        uint32_t twt_device_cap = 0, twt_peer_cap = 0, twt_num_stats = 0;
+        ALOGI("In TwtEventCap::handleEvent\n");
 
-        nlattr *data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
-        int len = reply.get_vendor_data_len();
+        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
+        int len = event.get_vendor_data_len();
+        int event_id = event.get_vendor_subcmd();
 
-        ALOGD("Id = %0x, subcmd = %d, len = %d, expected len = %d", id, subcmd, len);
-        if (data == NULL || len == 0) {
-            ALOGE("no vendor data in GetTwtCapabilitiesCommand response; ignoring it\n");
+        if (!vendor_data || len == 0) {
+            ALOGE("No event data found");
             return NL_SKIP;
         }
 
-        for (nl_iterator it(data); it.has_next(); it.next()) {
-            switch (it.get_type()) {
-                case TWT_ATTRIBUTE_DEVICE_CAP:
-                    twt_device_cap = it.get_u32();
-                    ALOGI("TWT device cap %04x\n", twt_device_cap);
-                    mCapabilities->device_capability = parseTwtCap(twt_device_cap);
-                    break;
-                case TWT_ATTRIBUTE_PEER_CAP:
-                    twt_peer_cap = it.get_u32();
-                    ALOGI("TWT peer cap %04x\n", twt_peer_cap);
-                    mCapabilities->peer_capability = parseTwtCap(twt_peer_cap);
-                    break;
-                case TWT_ATTRIBUTE_NUM_PEER_STATS:
-                    twt_num_stats = it.get_u32();
-                    ALOGI("TWT num stats %04x\n", twt_num_stats);
-                    break;
-                default:
-                    ALOGE("Ignoring invalid attribute type = %d, size = %d\n",
-                            it.get_type(), it.get_len());
-                    break;
+        switch (event_id) {
+            case BRCM_VENDOR_EVENT_TWT: {
+                HandleTwtEvent(vendor_data);
+                break;
             }
+            default:
+                break;
         }
-
-        ALOGE("Out GetTwtCapabilitiesCommand::handleResponse\n");
-        return NL_OK;
+        return NL_SKIP;
     }
 };
 
-/* API to get TWT capability */
-wifi_error twt_get_capability(wifi_interface_handle iface,
-        TwtCapabilitySet *twt_cap_set)
+/* To see event prints in console */
+wifi_error twt_event_check_request(int id, wifi_interface_handle iface)
 {
-    if (iface == NULL) {
-        ALOGE("twt_get_capability: NULL iface pointer provided."
-            " Exit.");
-        return WIFI_ERROR_INVALID_ARGS;
-    }
-
-    if (twt_cap_set == NULL) {
-        ALOGE("twt_get_capability: NULL capabilities pointer provided."
-            " Exit.");
-        return WIFI_ERROR_INVALID_ARGS;
+    TwtEventCap *cmd = new TwtEventCap(iface, id);
+    if (cmd == NULL) {
+        return WIFI_ERROR_NOT_SUPPORTED;
     }
-
-    GetTwtCapabilitiesCommand command(iface, twt_cap_set);
-    return (wifi_error) command.requestResponse();
+    return (wifi_error)cmd->start();
 }
 
-//////////////////////////////////////////////////////////////////////////
-class GetTwtStatsCommand : public WifiCommand
+static void twt_parse_cap_report(nlattr *vendor_data, wifi_twt_capabilities *mCapabilities)
 {
-    TwtStats* mStats;
-    u8 mConfig_id;
-public:
-    GetTwtStatsCommand(wifi_interface_handle iface, u8 config_id, TwtStats *stats)
-        : WifiCommand("GetTwtStatsCommand", iface, 0), mConfig_id(config_id), mStats(stats)
-    {
-        memset(mStats, 0, sizeof(*mStats));
-        mConfig_id = 0;
-    }
-
-    virtual int create() {
-        ALOGD("Creating message to get twt stats; iface = %d", mIfaceInfo->id);
-
-        int ret = mMsg.create(GOOGLE_OUI, TWT_SUBCMD_GETSTATS);
-        if (ret < 0) {
-            return ret;
-        }
-
-        nlattr *data = mMsg.attr_start(NL80211_ATTR_VENDOR_DATA);
-        ret = mMsg.put_u8(TWT_ATTRIBUTE_CONFIG_ID, mConfig_id);
-        if (ret < 0) {
-             ALOGE("Failed to set mConfig_id %d\n", mConfig_id);
-             return ret;
+    for (nl_iterator it2(vendor_data); it2.has_next(); it2.next()) {
+        if (it2.get_type() == TWT_ATTRIBUTE_IS_REQUESTOR_SUPPORTED) {
+            mCapabilities->is_twt_requester_supported = it2.get_u8();
+        } else if (it2.get_type() == TWT_ATTRIBUTE_IS_RESPONDER_SUPPORTED) {
+            mCapabilities->is_twt_responder_supported = it2.get_u8();
+        } else if (it2.get_type() == TWT_ATTRIBUTE_IS_BROADCAST_SUPPORTED) {
+            mCapabilities->is_broadcast_twt_supported = it2.get_u8();
+        } else if (it2.get_type() == TWT_ATTRIBUTE_IS_FLEXIBLE_SUPPORTED) {
+            mCapabilities->is_flexible_twt_supported = it2.get_u8();
+        } else if (it2.get_type() == TWT_ATTRIBUTE_MIN_WAKE_DURATION_US) {
+            mCapabilities->min_wake_duration_micros = it2.get_u32();
+        } else if (it2.get_type() == TWT_ATTRIBUTE_MAX_WAKE_DURATION_US) {
+            mCapabilities->max_wake_duration_micros = it2.get_u32();
+        } else if (it2.get_type() == TWT_ATTRIBUTE_MIN_WAKE_INTERVAL_US) {
+            mCapabilities->min_wake_interval_micros = it2.get_u32();
+        } else if (it2.get_type() == TWT_ATTRIBUTE_MAX_WAKE_INTERVAL_US) {
+            mCapabilities->max_wake_interval_micros = it2.get_u32();
+        } else {
+             ALOGW("Ignoring invalid attribute type = %d, size = %d",
+                     it2.get_type(), it2.get_len());
         }
-
-        ALOGI("Successfully configured config id %d\n", mConfig_id);
-        mMsg.attr_end(data);
-        return WIFI_SUCCESS;
     }
+    return;
+}
+////////////////////////////////////////////////////////////////////////////////
+class TwtFeatureRequest : public WifiCommand
+{
+    wifi_twt_request *reqContext;
+    TwtRequestType mType;
+    wifi_request_id mId = 0;
+    int mSessionId;
+    wifi_twt_capabilities *mCapabilities;
 
-protected:
-    virtual int handleResponse(WifiEvent& reply) {
-
-        ALOGI("In GetTwtStatsCommand::handleResponse");
-
-        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
-            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
-            return NL_SKIP;
-        }
-
-        int id = reply.get_vendor_id();
-        int subcmd = reply.get_vendor_subcmd();
-
-        nlattr *data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
-        int len = reply.get_vendor_data_len();
-
-        ALOGD("Id = %0x, subcmd = %d, len = %d, expected len = %d", id, subcmd, len);
-        if (data == NULL || len == 0) {
-            ALOGE("no vendor data in GetTwtStatsCommand response; ignoring it\n");
-            return NL_SKIP;
-        }
-
-        for (nl_iterator it(data); it.has_next(); it.next()) {
-            switch (it.get_type()) {
-                case TWT_ATTRIBUTE_CONFIG_ID:
-                    mStats->config_id = it.get_u8();
-                    break;
-                case TWT_ATTRIBUTE_AVG_PKT_NUM_TX:
-                    mStats->avg_pkt_num_tx = it.get_u32();
-                    break;
-                case TWT_ATTRIBUTE_AVG_PKT_NUM_RX:
-                    mStats->avg_pkt_num_rx = it.get_u32();
-                    break;
-                case TWT_ATTRIBUTE_AVG_PKT_SIZE_TX:
-                    mStats->avg_tx_pkt_size = it.get_u32();
-                    break;
-                case TWT_ATTRIBUTE_AVG_PKT_SIZE_RX:
-                    mStats->avg_rx_pkt_size = it.get_u32();
-                    break;
-                case TWT_ATTRIBUTE_AVG_EOSP_DUR:
-                    mStats->avg_eosp_dur_us = it.get_u32();
-                    break;
-                case TWT_ATTRIBUTE_EOSP_COUNT:
-                    mStats->eosp_count = it.get_u32();
-                    break;
-                case TWT_ATTRIBUTE_NUM_SP:
-                    mStats->num_sp = it.get_u32();
-                    break;
-                default:
-                    ALOGE("Ignoring invalid attribute type = %d, size = %d\n",
-                            it.get_type(), it.get_len());
-                    break;
-            }
-        }
-
-        return NL_OK;
+public:
+    /* Constructor for register event callback */
+    TwtFeatureRequest(wifi_interface_handle iface, wifi_request_id id,
+        TwtRequestType cmdType)
+        : WifiCommand("TwtFeatureRequest", iface, id),
+        mType(cmdType)
+    {
     }
-};
 
-/* API to get TWT stats */
-wifi_error twt_get_stats(wifi_interface_handle iface, u8 config_id, TwtStats* stats)
-{
-    if (iface == NULL) {
-        ALOGE("twt_get_stats: NULL iface pointer provided."
-            " Exit.");
-        return WIFI_ERROR_INVALID_ARGS;
+    TwtFeatureRequest(wifi_interface_handle iface, wifi_twt_capabilities *capabilities,
+        TwtRequestType cmdType)
+        : WifiCommand("TwtFeatureRequest", iface, 0), mCapabilities(capabilities),
+        mType(cmdType)
+    {
+        memset(mCapabilities, 0, sizeof(*mCapabilities));
     }
 
-    if (stats == NULL) {
-        ALOGE("TwtCapabilitySet: NULL capabilities pointer provided."
-            " Exit.");
-        return WIFI_ERROR_INVALID_ARGS;
+    /* Constructor for session_setup */
+    TwtFeatureRequest(wifi_interface_handle iface, wifi_request_id id,
+        wifi_twt_request *params, TwtRequestType cmdType)
+        : WifiCommand("TwtFeatureRequest", iface, id),
+        reqContext(params), mType(cmdType)
+    {
+        setId(id);
     }
 
-    GetTwtStatsCommand command(iface, config_id, stats);
-    return (wifi_error) command.requestResponse();
-}
-
-//////////////////////////////////////////////////////////////////////////////////////
-class ClearTwtStatsCommand : public WifiCommand
-{
-    u8 mConfig_id;
-public:
-    ClearTwtStatsCommand(wifi_interface_handle iface, u8 config_id)
-        : WifiCommand("ClearTwtStatsCommand", iface, 0), mConfig_id(config_id)
+    /* Constructor for session_update */
+    TwtFeatureRequest(wifi_interface_handle iface, wifi_request_id id,
+        int session_id, wifi_twt_request *params, TwtRequestType cmdType)
+        : WifiCommand("TwtFeatureRequest", iface, id),
+        mSessionId(session_id), reqContext(params), mType(cmdType)
     {
-        mConfig_id = 0;
+        setId(id);
+        mSessionId = session_id;
     }
 
-    virtual int create() {
-        ALOGD("Creating message to clear twt stats; config_id = %d\n", mConfig_id);
-
-        int ret = mMsg.create(GOOGLE_OUI, TWT_SUBCMD_CLR_STATS);
-        if (ret < 0) {
-            return ret;
-        }
-
-        nlattr *data = mMsg.attr_start(NL80211_ATTR_VENDOR_DATA);
-        ret = mMsg.put_u8(TWT_ATTRIBUTE_CONFIG_ID, mConfig_id);
-        if (ret < 0) {
-             ALOGE("Failed to set mConfig_id %d\n", mConfig_id);
-             return ret;
-        }
-
-        ALOGI("Successfully configured config id %d\n", mConfig_id);
-        mMsg.attr_end(data);
-        return WIFI_SUCCESS;
+    /* Constructor for session suspend, resume, teardown, get_stats, clear_stats */
+    TwtFeatureRequest(wifi_interface_handle iface, wifi_request_id id,
+        int session_id, TwtRequestType cmdType)
+        : WifiCommand("TwtFeatureRequest", iface, id),
+        mSessionId(session_id), mType(cmdType)
+    {
+        setId(id);
+        mSessionId = session_id;
     }
 
-protected:
-    virtual int handleResponse(WifiEvent& reply) {
-        ALOGD("In ClearTwtStatsCommand::handleResponse");
-        /* Nothing to do on response! */
-        return NL_SKIP;
+    ~TwtFeatureRequest() {
+        ALOGE("TwtFeatureRequest destroyed\n");
     }
-};
 
-/* API to clear TWT stats */
-wifi_error twt_clear_stats(wifi_interface_handle iface, u8 config_id)
-{
-    if (iface == NULL || !config_id) {
-        ALOGE("twt_clear_stats: NULL iface pointer provided."
-            " Exit.");
-        return WIFI_ERROR_INVALID_ARGS;
+    void setId(transaction_id id) {
+        if (id != TWT_MAC_INVALID_TRANSID) {
+            mId = id;
+        }
     }
-    ALOGE("twt_clear_stats: config id: %d\n", config_id);
-
-    ClearTwtStatsCommand command(iface, config_id);
-    return (wifi_error) command.requestResponse();
-}
 
-////////////////////////////////////////////////////////////////////////////////
-class TwtFeatureRequest : public WifiCommand
-{
-    TwtRequest reqContext;
-    TwtRequestType mType;
-
-    public:
-    TwtFeatureRequest(wifi_interface_handle iface,
-            TwtRequest params, TwtRequestType cmdType)
-        : WifiCommand("TwtFeatureRequest", iface, 0), reqContext(params), mType(cmdType)
-    {
+    transaction_id getId() {
+        return mId;
     }
 
     void setType(TwtRequestType type ) {
         mType = type;
     }
 
+    int getSessionId() {
+        return mSessionId;
+    }
+
     int createRequest(WifiRequest& request)
     {
-        ALOGI("TWT CMD: %s\n", TwtCmdToString(mType));
-        if (mType == TWT_SETUP_REQUEST) {
-            return createTwtSetupRequest(request, (TwtSetupRequest *)reqContext);
-        } else if (mType == TWT_INFO_FRAME_REQUEST) {
-            return createInfoFrameRequest(request, (TwtInfoFrameRequest *)reqContext);
-        } else if (mType == TWT_TEAR_DOWN_REQUEST) {
-            return createTearDownRequest(request, (TwtTeardownRequest *)reqContext);
+        ALOGI("TWT CMD: %s, Id %d\n", TwtCmdToString(mType), mId);
+        if (mType == TWT_GET_CAPABILITIES) {
+            return TwtSessionGetCap(request);
+        } else if (mType == TWT_SESSION_SETUP_REQUEST) {
+            return TwtSessionSetup(request, (wifi_twt_request *)reqContext);
+        } else if (mType == TWT_SESSION_UPDATE_REQUEST) {
+            return TwtSessionUpdate(request, mSessionId, (wifi_twt_request *)reqContext);
+        } else if (mType == TWT_SESSION_SUSPEND_REQUEST) {
+            return TwtSessionSuspend(request, mSessionId);
+        } else if (mType == TWT_SESSION_RESUME_REQUEST) {
+            return TwtSessionResume(request, mSessionId);
+        } else if (mType == TWT_SESSION_TEAR_DOWN_REQUEST) {
+            return TwtSessionTearDown(request, mSessionId);
+        } else if (mType == TWT_SESSION_GET_STATS) {
+            return TwtSessionGetStats(request, mSessionId);
+        } else if (mType == TWT_SESSION_CLEAR_STATS) {
+            return TwtSessionClearStats(request, mSessionId);
         } else {
             ALOGE("%s: Unknown TWT request: %d\n", __func__, mType);
             return WIFI_ERROR_UNKNOWN;
@@ -618,9 +661,21 @@ class TwtFeatureRequest : public WifiCommand
         return WIFI_SUCCESS;
     }
 
-    int createTwtSetupRequest(WifiRequest& request, TwtSetupRequest *mParams)
+    int TwtSessionGetCap(WifiRequest& request) {
+        ALOGD("Creating message to get twt capabilities; iface\n");
+
+        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_GETCAPABILITY);
+        if (result < 0) {
+            ALOGE("Failed to send the twt cap cmd, err = %d\n", result);
+        } else {
+            ALOGD("Success to send twt cap cmd, err = %d\n", result);
+        }
+        return result;
+    }
+
+    int TwtSessionSetup(WifiRequest& request, wifi_twt_request *mParams)
     {
-        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_SETUP_REQUEST);
+        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_SESSION_SETUP_REQUEST);
         if (result < 0) {
             ALOGE("%s Failed to create request, result = %d\n", __func__, result);
             return result;
@@ -630,187 +685,240 @@ class TwtFeatureRequest : public WifiCommand
          * otherwise, update not needed
          */
         nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
-        if (mParams->config_id) {
-            result = request.put_u8(TWT_ATTRIBUTE_CONFIG_ID, mParams->config_id);
+        if (mParams->mlo_link_id) {
+            result = request.put_s8(TWT_ATTRIBUTE_MLO_LINK_ID, mParams->mlo_link_id);
             if (result < 0) {
-                ALOGE("%s: Failed to fill config_id = %d, result = %d\n",
-                    __func__, mParams->config_id, result);
+                ALOGE("%s: Failed to fill mlo link id = %d, result = %d\n",
+                        __func__, mParams->mlo_link_id, result);
                 return result;
             }
         }
 
-        if (mParams->negotiation_type) {
-            result = request.put_u8(TWT_ATTRIBUTE_NEG_TYPE, mParams->negotiation_type);
+        if (mParams->min_wake_duration_micros) {
+            result = request.put_u32(TWT_ATTRIBUTE_MIN_WAKE_DURATION_US,
+                    mParams->min_wake_duration_micros);
             if (result < 0) {
-                ALOGE("%s: Failed to fill negotiation_type = %d, result = %d\n",
-                    __func__, mParams->negotiation_type, result);
+                ALOGE("%s: Failed to fill min_wake_duration_micros = %d, result = %d\n",
+                        __func__, mParams->min_wake_duration_micros, result);
                 return result;
             }
         }
-        if (mParams->trigger_type) {
-            result = request.put_u8(TWT_ATTRIBUTE_TRIGGER_TYPE, mParams->trigger_type);
+
+        if (mParams->max_wake_duration_micros) {
+            result = request.put_u32(TWT_ATTRIBUTE_MAX_WAKE_DURATION_US,
+                    mParams->max_wake_duration_micros);
             if (result < 0) {
-                ALOGE("%s: Failed to fill trigger_type = %d, result = %d\n",
-                    __func__, mParams->trigger_type, result);
+                ALOGE("%s: Failed to fill max_wake_duration_micros = %d, result = %d\n",
+                        __func__, mParams->max_wake_duration_micros, result);
                 return result;
             }
-        }
-        if (mParams->wake_dur_us) {
-            result = request.put_u32(TWT_ATTRIBUTE_WAKE_DUR_US, mParams->wake_dur_us);
+         }
+
+         if (mParams->min_wake_interval_micros) {
+            result = request.put_u32(TWT_ATTRIBUTE_MIN_WAKE_INTERVAL_US,
+                    mParams->min_wake_interval_micros);
             if (result < 0) {
-                ALOGE("%s: Failed to fill wake_dur_us = %d, result = %d\n",
-                    __func__, mParams->wake_dur_us, result);
+                ALOGE("%s: Failed to fill min_wake_interval_micros = %d, result = %d\n",
+                        __func__, mParams->min_wake_interval_micros, result);
                 return result;
             }
         }
-        if (mParams->wake_int_us) {
-            result = request.put_u32(TWT_ATTRIBUTE_WAKE_INT_US, mParams->wake_int_us);
+
+        if (mParams->max_wake_interval_micros) {
+            result = request.put_u32(TWT_ATTRIBUTE_MAX_WAKE_INTERVAL_US,
+                    mParams->max_wake_interval_micros);
             if (result < 0) {
-                ALOGE("%s: Failed to fill wake_int_us = %d, result = %d\n",
-                    __func__, mParams->wake_int_us, result);
+                ALOGE("%s: Failed to fill max_wake_interval_micros = %d, result = %d\n",
+                        __func__, mParams->max_wake_interval_micros, result);
                 return result;
             }
         }
-        if (mParams->wake_int_min_us) {
-            result = request.put_u32(TWT_ATTRIBUTE_WAKE_INT_MIN_US, mParams->wake_int_min_us);
-            if (result < 0) {
-                ALOGE("%s: Failed to fill wake_int_min_us = %d, result = %d\n",
-                    __func__, mParams->wake_int_min_us, result);
-                return result;
-            }
+
+        request.attr_end(data);
+
+        ALOGI("Returning successfully\n");
+        return result;
+    }
+
+    int TwtSessionUpdate(WifiRequest& request, int mSessionId, wifi_twt_request *mParams)
+    {
+        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_SESSION_UPDATE_REQUEST);
+        if (result < 0) {
+            ALOGE("%s: Failed to create twt_update request, result = %d\n",
+                    __func__, result);
+            return result;
         }
-        if (mParams->wake_int_max_us) {
-            result = request.put_u32(TWT_ATTRIBUTE_WAKE_INT_MAX_US, mParams->wake_int_max_us);
-            if (result < 0) {
-                ALOGE("%s: Failed to fill wake_int_max_us = %d, result = %d\n",
-                    __func__, mParams->wake_int_max_us, result);
-                return result;
-            }
+
+        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
+        result = request.put_u32(TWT_ATTRIBUTE_SESSION_ID, mSessionId);
+        if (result < 0) {
+            ALOGE("%s: Failed to fill mSessionId = %d, result = %d\n",
+                    __func__, mSessionId, result);
+            return result;
         }
-        if (mParams->wake_dur_min_us) {
-            result = request.put_u32(TWT_ATTRIBUTE_WAKE_DUR_MIN_US, mParams->wake_dur_min_us);
+
+        if (mParams->mlo_link_id) {
+            result = request.put_s8(TWT_ATTRIBUTE_MLO_LINK_ID, mParams->mlo_link_id);
             if (result < 0) {
-                ALOGE("%s: Failed to fill wake_dur_min_us = %d, result = %d\n",
-                    __func__, mParams->wake_dur_min_us, result);
+                ALOGE("%s: Failed to fill mlo link id = %d, result = %d\n",
+                        __func__, mParams->mlo_link_id, result);
                 return result;
-            }
+           }
         }
-        if (mParams->wake_dur_max_us) {
-            result = request.put_u32(TWT_ATTRIBUTE_WAKE_DUR_MAX_US, mParams->wake_dur_max_us);
+
+        if (mParams->min_wake_duration_micros) {
+            result = request.put_u32(TWT_ATTRIBUTE_MIN_WAKE_DURATION_US,
+                    mParams->min_wake_duration_micros);
             if (result < 0) {
-                ALOGE("%s: Failed to fill wake_dur_max_us = %d, result = %d\n",
-                    __func__, mParams->wake_dur_max_us, result);
+                ALOGE("%s: Failed to fill min_wake_duration_micros = %d, result = %d\n",
+                        __func__, mParams->min_wake_duration_micros, result);
                 return result;
             }
         }
-        if (mParams->avg_pkt_size) {
-            result = request.put_u32(TWT_ATTRIBUTE_AVG_PKT_SIZE, mParams->avg_pkt_size);
+
+        if (mParams->max_wake_duration_micros) {
+            result = request.put_u32(TWT_ATTRIBUTE_MAX_WAKE_DURATION_US,
+                    mParams->max_wake_duration_micros);
             if (result < 0) {
-                ALOGE("%s: Failed to fill avg_pkt_size = %d, result = %d\n",
-                    __func__, mParams->avg_pkt_size, result);
+                ALOGE("%s: Failed to fill max_wake_duration_micros = %d, result = %d\n",
+                        __func__, mParams->max_wake_duration_micros, result);
                 return result;
             }
         }
-        if (mParams->avg_pkt_num) {
-            result = request.put_u32(TWT_ATTRIBUTE_AVG_PKT_NUM, mParams->avg_pkt_num);
+
+        if (mParams->min_wake_interval_micros) {
+            result = request.put_u32(TWT_ATTRIBUTE_MIN_WAKE_INTERVAL_US,
+                    mParams->min_wake_interval_micros);
             if (result < 0) {
-                ALOGE("%s: Failed to fill avg_pkt_num = %d, result = %d\n",
-                    __func__, mParams->avg_pkt_num, result);
+                ALOGE("%s: Failed to fill min_wake_interval_micros = %d, result = %d\n",
+                        __func__, mParams->min_wake_interval_micros, result);
                 return result;
             }
         }
-        if (mParams->wake_time_off_us) {
-            result = request.put_u32(TWT_ATTRIBUTE_WAKE_TIME_OFF_US, mParams->wake_time_off_us);
+
+        if (mParams->max_wake_interval_micros) {
+            result = request.put_u32(TWT_ATTRIBUTE_MAX_WAKE_INTERVAL_US,
+                    mParams->max_wake_interval_micros);
             if (result < 0) {
-                ALOGE("%s: Failed to fill wake_time_off_us = %d, result = %d\n",
-                    __func__, mParams->wake_time_off_us, result);
+                ALOGE("%s: Failed to fill max_wake_interval_micros = %d, result = %d\n",
+                        __func__, mParams->max_wake_interval_micros, result);
                 return result;
             }
         }
+
         request.attr_end(data);
 
-        ALOGI("Returning successfully\n");
-        return result;
+        ALOGI("TwtSessionUpdate: Returning successfully\n");
+
+        return WIFI_SUCCESS;
     }
 
-    int createInfoFrameRequest(WifiRequest& request, TwtInfoFrameRequest *mParams)
+    int TwtSessionTearDown(WifiRequest& request, int mSessionId)
     {
-        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_INFO_FRAME_REQUEST);
+        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_SESSION_TEAR_DOWN_REQUEST);
         if (result < 0) {
             ALOGE("%s: Failed to create request, result = %d\n", __func__, result);
             return result;
         }
 
         nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
-        if (mParams->config_id) {
-            result = request.put_u8(TWT_ATTRIBUTE_CONFIG_ID, mParams->config_id);
-            if (result < 0) {
-                ALOGE("%s: Failed to fill config_id = %d, result = %d\n",
-                    __func__, mParams->config_id, result);
-                return result;
-            }
+        result = request.put_u32(TWT_ATTRIBUTE_SESSION_ID, mSessionId);
+        if (result < 0) {
+            ALOGE("%s: Failed to fill mSessionId = %d, result = %d\n",
+                    __func__, mSessionId, result);
+            return result;
         }
-        if (mParams->resume_time_us) {
-            result = request.put_u32(TWT_ATTRIBUTE_RESUME_TIME_US, mParams->resume_time_us);
-            if (result < 0) {
-                ALOGE("%s: Failed to fill resume_time_us = %d, result = %d\n",
-                    __func__, mParams->resume_time_us, result);
-                return result;
-            }
+        request.attr_end(data);
+        return WIFI_SUCCESS;
+    }
+
+    int TwtSessionSuspend(WifiRequest& request, int mSessionId)
+    {
+        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_SESSION_SUSPEND_REQUEST);
+        if (result < 0) {
+            ALOGE("%s: Failed to create session suspend request, result = %d\n",
+                    __func__, result);
+            return result;
         }
-        if (mParams->all_twt) {
-            result = request.put_u8(TWT_ATTRIBUTE_ALL_TWT, mParams->all_twt);
-            if (result < 0) {
-                ALOGE("%s: Failed to fill all_twt = %d, result = %d\n",
-                    __func__, mParams->all_twt, result);
-                return result;
-            }
+
+        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
+        result = request.put_u32(TWT_ATTRIBUTE_SESSION_ID, mSessionId);
+        if (result < 0) {
+            ALOGE("%s: Failed to fill mSessionId = %d, result = %d\n",
+                    __func__, mSessionId, result);
+            return result;
         }
         request.attr_end(data);
         return WIFI_SUCCESS;
     }
 
-    int createTearDownRequest(WifiRequest& request, TwtTeardownRequest *mParams)
+    int TwtSessionResume(WifiRequest& request, int mSessionId)
     {
-        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_TEAR_DOWN_REQUEST);
+        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_SESSION_RESUME_REQUEST);
         if (result < 0) {
-            ALOGE("%s: Failed to create request, result = %d\n", __func__, result);
+            ALOGE("%s: Failed to create session resume request, result = %d\n",
+                    __func__, result);
             return result;
         }
 
         nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
-        if (mParams->config_id) {
-            result = request.put_u8(TWT_ATTRIBUTE_CONFIG_ID, mParams->config_id);
-            if (result < 0) {
-                ALOGE("%s: Failed to fill config_id = %d, result = %d\n",
-                    __func__, mParams->config_id, result);
-                return result;
-            }
+        result = request.put_u32(TWT_ATTRIBUTE_SESSION_ID, mSessionId);
+        if (result < 0) {
+            ALOGE("%s: Failed to fill mSessionId = %d, result = %d\n",
+                    __func__, mSessionId, result);
+            return result;
         }
-        if (mParams->negotiation_type) {
-            result = request.put_u8(TWT_ATTRIBUTE_NEG_TYPE, mParams->negotiation_type);
-            if (result < 0) {
-                ALOGE("%s: Failed to fill negotiation_type = %d, result = %d\n",
-                        __func__, mParams->negotiation_type, result);
-                return result;
-            }
+
+        request.attr_end(data);
+        return WIFI_SUCCESS;
+    }
+
+    int TwtSessionGetStats(WifiRequest& request, int mSessionId)
+    {
+        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_SESSION_GETSTATS);
+        if (result < 0) {
+            ALOGE("%s: Failed to create session get stats request, result = %d\n",
+                    __func__, result);
+            return result;
         }
-        if (mParams->all_twt) {
-            result = request.put_u8(TWT_ATTRIBUTE_ALL_TWT, mParams->all_twt);
-            if (result < 0) {
-                ALOGE("%s: Failed to fill all_twt = %d, result = %d\n",
-                        __func__, mParams->all_twt, result);
-                return result;
-            }
+
+        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
+        result = request.put_u32(TWT_ATTRIBUTE_SESSION_ID, mSessionId);
+        if (result < 0) {
+            ALOGE("%s: Failed to fill mSessionId = %d, result = %d\n",
+                    __func__, mSessionId, result);
+            return result;
         }
         request.attr_end(data);
         return WIFI_SUCCESS;
     }
 
+    int TwtSessionClearStats(WifiRequest& request, int mSessionId)
+    {
+        int result = request.create(GOOGLE_OUI, TWT_SUBCMD_SESSION_CLR_STATS);
+        if (result < 0) {
+            ALOGE("%s: Failed to create session clear stats request, result = %d\n",
+                    __func__, result);
+            return result;
+        }
+
+        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
+        result = request.put_u32(TWT_ATTRIBUTE_SESSION_ID, mSessionId);
+        if (result < 0) {
+            ALOGE("%s: Failed to fill mSessionId = %d, result = %d\n",
+                    __func__, mSessionId, result);
+            return result;
+        }
+
+        request.attr_end(data);
+        return WIFI_SUCCESS;
+    }
+
     int open()
     {
+        int result = 0;
         WifiRequest request(familyId(), ifaceId());
-        int result = createRequest(request);
+        result = createRequest(request);
         if (result != WIFI_SUCCESS) {
             ALOGE("%s: failed to create setup request; result = %d", __func__, result);
             return result;
@@ -836,20 +944,52 @@ class TwtFeatureRequest : public WifiCommand
         unregisterVendorHandler(BRCM_OUI, BRCM_VENDOR_EVENT_TWT);
     }
 
+protected:
     virtual int handleResponse(WifiEvent& reply) {
-         ALOGD("Request complete!");
-        /* Nothing to do on response! */
+
+        ALOGI("In TwtFeatureRequest::handleResponse\n");
+
+        wifi_error ret = WIFI_SUCCESS;
+
+        if (reply.get_cmd() != NL80211_CMD_VENDOR || reply.get_vendor_data() == NULL) {
+            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
+            return NL_SKIP;
+        }
+
+        nlattr *vendor_data = reply.get_attribute(NL80211_ATTR_VENDOR_DATA);
+        int len = reply.get_vendor_data_len();
+
+        if (vendor_data == NULL || len == 0) {
+            ALOGE("no vendor data in twt cmd response; ignoring it");
+            return NL_SKIP;
+        }
+
+        for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
+            if (it.get_type() == TWT_ATTRIBUTE_WIFI_ERROR) {
+                ret = (wifi_error)it.get_s8();
+            } else if ((mType == TWT_GET_CAPABILITIES) && (it.get_type() == TWT_ATTRIBUTE_CAP)) {
+                twt_parse_cap_report(it.get(), mCapabilities);
+            } else {
+                ALOGW("Ignoring invalid attribute type = %d, size = %d",
+                        it.get_type(), it.get_len());
+            }
+        }
+
         return NL_SKIP;
     }
 
     int handleEvent(WifiEvent& event) {
         u16 attr_type;
+        u8 sub_event_type = 0;
         TwtEventType twt_event;
+        wifi_twt_error_code error_code;
+        int session_id = 0;
+
+        ALOGI("In TwtFeatureRequest::handleEvent\n");
 
         nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
         int len = event.get_vendor_data_len();
         int event_id = event.get_vendor_subcmd();
-        ALOGI("Received TWT event: %d\n", event_id);
 
         if (!vendor_data || len == 0) {
             ALOGE("No event data found");
@@ -867,14 +1007,14 @@ class TwtFeatureRequest : public WifiCommand
         }
         return NL_SKIP;
     }
-
 };
 
 void twt_deinit_handler()
 {
     if (twt_info.twt_feature_request) {
         /* register for Twt vendor events with info mac class*/
-        TwtFeatureRequest *cmd_event = (TwtFeatureRequest*)(twt_info.twt_feature_request);
+        TwtFeatureRequest *cmd_event =
+                (TwtFeatureRequest*)(twt_info.twt_feature_request);
         cmd_event->unregisterTwtVendorEvents();
         delete (TwtFeatureRequest*)twt_info.twt_feature_request;
         twt_info.twt_feature_request = NULL;
@@ -887,8 +1027,8 @@ void twt_deinit_handler()
     return;
 }
 
-wifi_error twt_register_handler(wifi_interface_handle iface,
-        TwtCallbackHandler handlers)
+wifi_error wifi_twt_register_events(wifi_interface_handle iface,
+        wifi_twt_events handlers)
 {
     wifi_handle handle = getWifiHandle(iface);
     if (TWT_HANDLE(twt_info)) {
@@ -898,61 +1038,170 @@ wifi_error twt_register_handler(wifi_interface_handle iface,
     memset(&twt_info, 0, sizeof(twt_info));
     TWT_HANDLE(twt_info) = new TwtHandle(handle, handlers);
     twt_info.twt_feature_request =
-        (void*)new TwtFeatureRequest(iface, NULL, TWT_LAST);
+            (void*)new TwtFeatureRequest(iface, 0, TWT_LAST);
     NULL_CHECK_RETURN(twt_info.twt_feature_request,
-        "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
+            "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
     TwtFeatureRequest *cmd_event = (TwtFeatureRequest*)(twt_info.twt_feature_request);
     cmd_event->registerTwtVendorEvents();
     return WIFI_SUCCESS;
 }
 
-wifi_error twt_setup_request(wifi_interface_handle iface, TwtSetupRequest* msg)
+/* API to get TWT capability */
+wifi_error wifi_twt_get_capabilities(wifi_interface_handle iface,
+        wifi_twt_capabilities* capabilities)
 {
     wifi_error ret = WIFI_SUCCESS;
     TwtFeatureRequest *cmd;
-    TwtRequestType cmdType = TWT_SETUP_REQUEST;
+    TwtRequestType cmdType = TWT_GET_CAPABILITIES;
+    memset(capabilities, 0, sizeof(wifi_twt_capabilities));
 
-    cmd = new TwtFeatureRequest(iface, (void *)msg, cmdType);
+    if (iface == NULL) {
+        ALOGE("wifi_twt_get_capability: NULL iface pointer provided."
+                " Exit.");
+        return WIFI_ERROR_INVALID_ARGS;
+    }
+
+    if (capabilities == NULL) {
+        ALOGE("wifi_twt_get_capability: NULL capabilities pointer provided."
+                " Exit.");
+        return WIFI_ERROR_INVALID_ARGS;
+    }
+
+    cmd = new TwtFeatureRequest(iface, capabilities, cmdType);
     NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
 
     ret = (wifi_error)cmd->open();
     if (ret != WIFI_SUCCESS) {
-        ALOGE("%s : failed in open, error = %d\n", __func__, ret);
+        ALOGE("%s : failed in create twt_cap req, error = %d\n", __func__, ret);
+        ret = WIFI_ERROR_NOT_SUPPORTED;
     }
     cmd->releaseRef();
     return ret;
 }
 
-wifi_error twt_info_frame_request(wifi_interface_handle iface, TwtInfoFrameRequest* msg)
+wifi_error wifi_twt_session_setup(wifi_request_id id, wifi_interface_handle iface,
+        wifi_twt_request request)
 {
     wifi_error ret = WIFI_SUCCESS;
     TwtFeatureRequest *cmd;
-    TwtRequestType cmdType = TWT_INFO_FRAME_REQUEST;
+    TwtRequestType cmdType = TWT_SESSION_SETUP_REQUEST;
 
-    cmd = new TwtFeatureRequest(iface, (void *)msg, cmdType);
+    SET_TWT_DATA(id, cmdType);
+
+    cmd = new TwtFeatureRequest(iface, id, &request, cmdType);
     NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
 
+    cmd->setId(id);
     ret = (wifi_error)cmd->open();
     if (ret != WIFI_SUCCESS) {
-        ALOGE("%s : failed in open, error = %d\n", __func__, ret);
+        ALOGE("%s : failed in create twt_setup req, error = %d\n", __func__, ret);
     }
     cmd->releaseRef();
     return ret;
 }
 
-wifi_error twt_teardown_request(wifi_interface_handle iface, TwtTeardownRequest* msg)
+wifi_error wifi_twt_session_update(wifi_request_id id, wifi_interface_handle iface,
+        int session_id, wifi_twt_request request)
 {
     wifi_error ret = WIFI_SUCCESS;
     TwtFeatureRequest *cmd;
-    TwtRequestType cmdType = TWT_TEAR_DOWN_REQUEST;
+    TwtRequestType cmdType = TWT_SESSION_UPDATE_REQUEST;
+
+    SET_TWT_DATA(id, cmdType);
 
-    cmd = new TwtFeatureRequest(iface, (void *)msg, cmdType);
+    cmd = new TwtFeatureRequest(iface, id, session_id, &request, cmdType);
     NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
 
+    cmd->setId(id);
     ret = (wifi_error)cmd->open();
     if (ret != WIFI_SUCCESS) {
-        ALOGE("%s : failed in open, error = %d\n", __func__, ret);
+        ALOGE("%s : failed in create twt_update req, error = %d\n", __func__, ret);
     }
     cmd->releaseRef();
     return ret;
 }
+
+wifi_error wifi_twt_session_suspend(wifi_request_id id, wifi_interface_handle iface,
+        int session_id)
+{
+    wifi_error ret = WIFI_SUCCESS;
+    TwtFeatureRequest *cmd;
+    TwtRequestType cmdType = TWT_SESSION_SUSPEND_REQUEST;
+
+    SET_TWT_DATA(id, cmdType);
+
+    cmd = new TwtFeatureRequest(iface, id, session_id, cmdType);
+    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
+
+    cmd->setId(id);
+    ret = (wifi_error)cmd->open();
+    if (ret != WIFI_SUCCESS) {
+        ALOGE("%s : failed in create twt_suspend req, error = %d\n", __func__, ret);
+    }
+    cmd->releaseRef();
+    return ret;
+}
+
+wifi_error wifi_twt_session_resume(wifi_request_id id, wifi_interface_handle iface,
+        int session_id)
+{
+    wifi_error ret = WIFI_SUCCESS;
+    TwtFeatureRequest *cmd;
+    TwtRequestType cmdType = TWT_SESSION_RESUME_REQUEST;
+
+    SET_TWT_DATA(id, cmdType);
+
+    cmd = new TwtFeatureRequest(iface, id, session_id, cmdType);
+    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
+
+    cmd->setId(id);
+    ret = (wifi_error)cmd->open();
+    if (ret != WIFI_SUCCESS) {
+        ALOGE("%s : failed in create twt_resume req, error = %d\n", __func__, ret);
+    }
+    cmd->releaseRef();
+    return ret;
+}
+
+wifi_error wifi_twt_session_teardown(wifi_request_id id, wifi_interface_handle iface,
+        int session_id)
+{
+    wifi_error ret = WIFI_SUCCESS;
+    TwtFeatureRequest *cmd;
+    TwtRequestType cmdType = TWT_SESSION_TEAR_DOWN_REQUEST;
+
+    SET_TWT_DATA(id, cmdType);
+
+    cmd = new TwtFeatureRequest(iface, id, session_id, cmdType);
+    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
+
+    cmd->setId(id);
+    ret = (wifi_error)cmd->open();
+    if (ret != WIFI_SUCCESS) {
+        ALOGE("%s : failed in create twt_teardown req, error = %d\n", __func__, ret);
+    }
+    cmd->releaseRef();
+    return ret;
+}
+
+wifi_error wifi_twt_session_get_stats(wifi_request_id id, wifi_interface_handle iface,
+        int session_id)
+{
+    wifi_error ret = WIFI_SUCCESS;
+    TwtFeatureRequest *cmd;
+    TwtRequestType cmdType = TWT_SESSION_GET_STATS;
+
+    SET_TWT_DATA(id, cmdType);
+
+    cmd = new TwtFeatureRequest(iface, id, session_id, cmdType);
+    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
+
+    cmd->setId(id);
+    ret = (wifi_error)cmd->open();
+    if (ret != WIFI_SUCCESS) {
+        ALOGE("%s : failed to create twt_get_stats req, error = %d\n", __func__, ret);
+    }
+    cmd->releaseRef();
+    return ret;
+}
+
diff --git a/bcmdhd/wifi_hal/wifi_hal.cpp b/bcmdhd/wifi_hal/wifi_hal.cpp
index 99aad5f..7867572 100644
--- a/bcmdhd/wifi_hal/wifi_hal.cpp
+++ b/bcmdhd/wifi_hal/wifi_hal.cpp
@@ -347,13 +347,14 @@ wifi_error init_wifi_vendor_hal_func_table(wifi_hal_fn *fn)
     fn->wifi_virtual_interface_create = wifi_virtual_interface_create;
     fn->wifi_virtual_interface_delete = wifi_virtual_interface_delete;
     fn->wifi_set_coex_unsafe_channels = wifi_set_coex_unsafe_channels;
-    fn->wifi_twt_get_capability = twt_get_capability;
-    fn->wifi_twt_register_handler = twt_register_handler;
-    fn->wifi_twt_setup_request = twt_setup_request;
-    fn->wifi_twt_teardown_request = twt_teardown_request;
-    fn->wifi_twt_info_frame_request = twt_info_frame_request;
-    fn->wifi_twt_get_stats = twt_get_stats;
-    fn->wifi_twt_clear_stats = twt_clear_stats;
+    fn->wifi_twt_get_capabilities = wifi_twt_get_capabilities;
+    fn->wifi_twt_register_events = wifi_twt_register_events;
+    fn->wifi_twt_session_setup = wifi_twt_session_setup;
+    fn->wifi_twt_session_update = wifi_twt_session_update;
+    fn->wifi_twt_session_suspend = wifi_twt_session_suspend;
+    fn->wifi_twt_session_resume = wifi_twt_session_resume;
+    fn->wifi_twt_session_teardown = wifi_twt_session_teardown;
+    fn->wifi_twt_session_get_stats = wifi_twt_session_get_stats;
     fn->wifi_multi_sta_set_primary_connection = wifi_multi_sta_set_primary_connection;
     fn->wifi_multi_sta_set_use_case = wifi_multi_sta_set_use_case;
     fn->wifi_set_voip_mode = wifi_set_voip_mode;
diff --git a/bcmdhd/wifi_hal/wifi_logger.cpp b/bcmdhd/wifi_hal/wifi_logger.cpp
index 83431f6..92df920 100755
--- a/bcmdhd/wifi_hal/wifi_logger.cpp
+++ b/bcmdhd/wifi_hal/wifi_logger.cpp
@@ -50,7 +50,6 @@
 #include "brcm_version.h"
 #define WIFI_HAL_EVENT_SOCK_PORT     645
 
-#define ARRAYSIZE(a)	(u8)(sizeof(a) / sizeof(a[0]))
 typedef enum {
     LOGGER_START_LOGGING = ANDROID_NL80211_SUBCMD_DEBUG_RANGE_START,
     LOGGER_TRIGGER_MEM_DUMP,
```

