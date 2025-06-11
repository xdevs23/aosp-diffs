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
diff --git a/synadhd/wifi_hal/common.h b/synadhd/wifi_hal/common.h
index 1c7b7a8..e2a6796 100755
--- a/synadhd/wifi_hal/common.h
+++ b/synadhd/wifi_hal/common.h
@@ -61,6 +61,7 @@ const uint32_t BRCM_OUI =  0x001018;
 #define MAX_CMD_RESP_BUF_LEN 8192
 
 #define NL_MSG_MAX_LEN                  5120u
+#define NAN_DEFAULT_RX_CHAINS_SUPPORTED 2u
 
 /* nl_msg->nm_nlh->nlmsg_len is added by data len of the attributes
  * NL80211_ATTR_VENDOR_ID, NL80211_ATTR_VENDOR_SUBCMD,
diff --git a/synadhd/wifi_hal/nan.cpp b/synadhd/wifi_hal/nan.cpp
index ddbc598..fb1fe39 100755
--- a/synadhd/wifi_hal/nan.cpp
+++ b/synadhd/wifi_hal/nan.cpp
@@ -384,6 +384,7 @@ static int is_cmd_response(int cmd);
 static int get_svc_hash(unsigned char *svc_name, u16 svc_name_len,
         u8 *svc_hash, u16 svc_hash_len);
 NanResponseType get_response_type(WIFI_SUB_COMMAND nan_subcmd);
+NanResponseType get_response_type_frm_req_type(NanRequestType cmdType);
 static NanStatusType nan_map_response_status(int vendor_status);
 
 /* Function to separate the common events to NAN1.0 events */
@@ -1502,13 +1503,24 @@ class NanDiscEnginePrimitive : public WifiCommand
     {
         nan_hal_resp_t *rsp_vndr_data = NULL;
         NanResponseMsg rsp_data;
-        u32 len;
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
-        len = reply.get_vendor_data_len();
+        vendor_data_len = reply.get_vendor_data_len();
+
         ALOGI("NanDiscEnginePrmitive::handle response\n");
         memset(&rsp_data, 0, sizeof(NanResponseMsg));
         rsp_data.response_type = get_response_type((WIFI_SUB_COMMAND)rsp_vndr_data->subcmd);
@@ -1537,8 +1549,27 @@ class NanDiscEnginePrimitive : public WifiCommand
         } else if (rsp_data.response_type == NAN_RESPONSE_SUBSCRIBE) {
             rsp_data.body.subscribe_response.subscribe_id = mInstId;
         } else if (rsp_data.response_type == NAN_GET_CAPABILITIES) {
-            memcpy((void *)&rsp_data.body.nan_capabilities, (void *)&rsp_vndr_data->capabilities,
-                    min(len, sizeof(rsp_data.body.nan_capabilities)));
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
+            if (!get_halutil_mode()) {
+                if (!id()) {
+                    ALOGE("Skip to send the nan cap cmd response, id() %d\n", id());
+                    return NL_SKIP;
+                }
+            }
         }
 
         GET_NAN_HANDLE(info)->mHandlers.NotifyResponse(id(), &rsp_data);
@@ -2297,7 +2328,22 @@ class NanDataPathPrimitive : public WifiCommand
             ALOGE("%s: failed to configure setup; result = %d", __func__, result);
             return result;
         }
-
+        ALOGI("NanDataPathPrmitive::request Response\n");
+        if (mType == NAN_DATA_PATH_IFACE_DELETE) {
+            NanResponseMsg rsp_data;
+            memset(&rsp_data, 0, sizeof(NanResponseMsg));
+            /* Prepare the NanResponseMsg payload */
+            rsp_data.response_type = get_response_type_frm_req_type((NanRequestType)mType);
+            /* Return success even for no dev case also, nothing to do */
+            rsp_data.status = NAN_STATUS_SUCCESS;
+            memcpy(rsp_data.nan_error, NanStatusToString(rsp_data.status),
+                    strlen(NanStatusToString(rsp_data.status)));
+            rsp_data.nan_error[strlen(NanStatusToString(rsp_data.status))] = '\0';
+            rsp_data.nan_error[NAN_ERROR_STR_LEN - 1] = '\0';
+            ALOGI("hal status = %d, resp_string %s\n",
+                    rsp_data.status, (u8*)rsp_data.nan_error);
+            GET_NAN_HANDLE(info)->mHandlers.NotifyResponse(id(), &rsp_data);
+        }
         request.destroy();
         return WIFI_SUCCESS;
     }
@@ -2322,49 +2368,62 @@ class NanDataPathPrimitive : public WifiCommand
     int handleResponse(WifiEvent& reply)
     {
         nan_hal_resp_t *rsp_vndr_data = NULL;
-
-        if (reply.get_cmd() != NL80211_CMD_VENDOR || reply.get_vendor_data() == NULL) {
-            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
-            return NL_SKIP;
-        }
-
-        rsp_vndr_data = (nan_hal_resp_t *)reply.get_vendor_data();
-        ALOGI("NanDataPathPrmitive::handle response\n");
-        int32_t result = rsp_vndr_data->value;
         NanResponseMsg rsp_data;
+        int32_t result = BCME_OK;
+        int min_nan_resp_size = offsetof(nan_hal_resp_t, capabilities);
 
+        ALOGI("NanDataPathPrmitive::handle Response\n");
         memset(&rsp_data, 0, sizeof(NanResponseMsg));
-        rsp_data.response_type = get_response_type((WIFI_SUB_COMMAND)rsp_vndr_data->subcmd);
-
-        if ((WIFI_SUB_COMMAND)rsp_vndr_data->subcmd == NAN_SUBCMD_DATA_PATH_SEC_INFO) {
-            /* Follow through */
-        } else if (!valid_dp_response_type(rsp_data.response_type)) {
+        if (mType == NAN_DATA_PATH_IFACE_CREATE) {
+            /* NDI creation and deletion are done through vendor ops,
+             * driver does not send the cmd response payload,
+             * but for framework,
+             * mimicking the NanResponseMsg for iface create and delete nan cmds
+             */
+            rsp_data.response_type = get_response_type_frm_req_type((NanRequestType)mType);
+            rsp_data.status = NAN_STATUS_SUCCESS;
+        } else if (reply.get_cmd() != NL80211_CMD_VENDOR ||
+            reply.get_vendor_data() == NULL ||
+            reply.get_vendor_data_len() < min_nan_resp_size) {
+            ALOGD("Ignoring reply with cmd = %d mType = %d len = %d,"
+                    " min expected len %d, capa size %d\n",
+                    reply.get_cmd(), mType, reply.get_vendor_data_len(),
+                    min_nan_resp_size, sizeof(NanCapabilities));
             return NL_SKIP;
-        }
-        rsp_data.status = nan_map_response_status(rsp_vndr_data->status);
-        ALOGE("Mapped hal status = %d\n", rsp_data.status);
+        } else {
+            rsp_vndr_data = (nan_hal_resp_t *)reply.get_vendor_data();
+            result = rsp_vndr_data->value;
+            rsp_data.response_type = get_response_type((WIFI_SUB_COMMAND)rsp_vndr_data->subcmd);
 
-        if (rsp_vndr_data->nan_reason[0] == '\0') {
-            memcpy(rsp_data.nan_error, NanStatusToString(rsp_data.status),
-                    strlen(NanStatusToString(rsp_data.status)));
-            rsp_data.nan_error[strlen(NanStatusToString(rsp_data.status))] = '\0';
-        }
-        rsp_data.nan_error[NAN_ERROR_STR_LEN - 1] = '\0';
-        ALOGI("\n Received nan_error string %s\n", (u8*)rsp_data.nan_error);
+            if ((WIFI_SUB_COMMAND)rsp_vndr_data->subcmd == NAN_SUBCMD_DATA_PATH_SEC_INFO) {
+                /* Follow through */
+            } else if (!valid_dp_response_type(rsp_data.response_type)) {
+                return NL_SKIP;
+            }
+            rsp_data.status = nan_map_response_status(rsp_vndr_data->status);
 
-        if (rsp_data.response_type == NAN_DP_INITIATOR_RESPONSE) {
-            ALOGI("received ndp instance_id %d and ret = %d\n", rsp_vndr_data->ndp_instance_id, result);
-            rsp_data.body.data_request_response.ndp_instance_id = rsp_vndr_data->ndp_instance_id;
-            mNdpId = rsp_vndr_data->ndp_instance_id;
-        } else if ((WIFI_SUB_COMMAND)rsp_vndr_data->subcmd == NAN_SUBCMD_DATA_PATH_SEC_INFO) {
-            memcpy(mPubNmi, rsp_vndr_data->pub_nmi, NAN_MAC_ADDR_LEN);
-            memcpy(mSvcHash, rsp_vndr_data->svc_hash, NAN_SVC_HASH_SIZE);
-            return NL_SKIP;
+            if (rsp_data.response_type == NAN_DP_INITIATOR_RESPONSE) {
+                ALOGI("received ndp instance_id %d and ret = %d\n", rsp_vndr_data->ndp_instance_id, result);
+                rsp_data.body.data_request_response.ndp_instance_id = rsp_vndr_data->ndp_instance_id;
+                mNdpId = rsp_vndr_data->ndp_instance_id;
+            } else if ((WIFI_SUB_COMMAND)rsp_vndr_data->subcmd == NAN_SUBCMD_DATA_PATH_SEC_INFO) {
+                  memcpy(mPubNmi, rsp_vndr_data->pub_nmi, NAN_MAC_ADDR_LEN);
+                  memcpy(mSvcHash, rsp_vndr_data->svc_hash, NAN_SVC_HASH_SIZE);
+                  return NL_SKIP;
+            }
         }
 
+        memcpy(rsp_data.nan_error, NanStatusToString(rsp_data.status),
+                strlen(NanStatusToString(rsp_data.status)));
+        rsp_data.nan_error[strlen(NanStatusToString(rsp_data.status))] = '\0';
+        rsp_data.nan_error[NAN_ERROR_STR_LEN - 1] = '\0';
+
+        ALOGI("Mapped hal status = %d\n", rsp_data.status);
+        ALOGI("Received nan_error string %s\n", (u8*)rsp_data.nan_error);
         ALOGI("NanDataPathPrmitive:Received response for cmd [%s], ret %d\n",
                 NanRspToString(rsp_data.response_type), rsp_data.status);
         GET_NAN_HANDLE(info)->mHandlers.NotifyResponse(id(), &rsp_data);
+        ALOGE("Notified by cmd reply!!");
         return NL_SKIP;
     }
 
@@ -3395,6 +3454,7 @@ class NanMacControl : public WifiCommand
         int len = event.get_vendor_data_len();
         u16 attr_type;
         nan_hal_resp_t *rsp_vndr_data = NULL;
+        int min_nan_resp_size = offsetof(nan_hal_resp_t, capabilities);
 
         ALOGI("%s: Received NanMacControl event = %d (len=%d)\n",
                 __func__, event.get_cmd(), len);
@@ -3406,18 +3466,17 @@ class NanMacControl : public WifiCommand
         for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
             attr_type = it.get_type();
 
-            if (it.get_type() == NAN_ATTRIBUTE_HANDLE) {
-            } else if (it.get_type() == NAN_ATTRIBUTE_NDP_ID) {
+            if (it.get_type() == NAN_ATTRIBUTE_NDP_ID) {
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
@@ -3840,6 +3899,26 @@ NanResponseType get_response_type(WIFI_SUB_COMMAND nan_subcmd)
     return response_type;
 }
 
+NanResponseType get_response_type_frm_req_type(NanRequestType cmdType) {
+    NanResponseType response_type;
+
+    switch (cmdType) {
+        case NAN_DATA_PATH_IFACE_CREATE:
+            response_type = NAN_DP_INTERFACE_CREATE;
+            break;
+        case NAN_DATA_PATH_IFACE_DELETE:
+            response_type = NAN_DP_INTERFACE_DELETE;
+            break;
+        default:
+            /* unknown response for a request type */
+            response_type = NAN_RESPONSE_ERROR;
+            break;
+    }
+
+    return response_type;
+
+}
+
 static int get_svc_hash(unsigned char *svc_name,
         u16 svc_name_len, u8 *svc_hash, u16 svc_hash_len)
 {
@@ -5214,6 +5293,7 @@ wifi_error nan_data_interface_create(transaction_id id,
     if (ret != WIFI_SUCCESS) {
         ALOGE("%s : failed in open, error = %d\n", __func__, ret);
     }
+
     cmd->releaseRef();
 
     NAN_DBG_EXIT();
@@ -5278,6 +5358,9 @@ wifi_error nan_data_request_initiator(transaction_id id,
         }
     } else if (msg->key_info.key_type == NAN_SECURITY_KEY_INPUT_PASSPHRASE) {
         NanDataPathSecInfoRequest msg_sec_info;
+
+        memset(&msg_sec_info, 0, sizeof(msg_sec_info));
+
         if (msg->requestor_instance_id == 0) {
             ALOGE("Invalid Pub ID = %d, Mandatory param is missing\n", msg->requestor_instance_id);
             ret = WIFI_ERROR_INVALID_ARGS;
@@ -5364,6 +5447,8 @@ wifi_error nan_data_indication_response(transaction_id id,
     if (msg->key_info.key_type == NAN_SECURITY_KEY_INPUT_PASSPHRASE) {
         NanDataPathSecInfoRequest msg_sec_info;
 
+        memset(&msg_sec_info, 0, sizeof(msg_sec_info));
+
         if (msg->ndp_instance_id == 0) {
             ALOGE("Invalid NDP ID, Mandatory info is not present\n");
             ret = WIFI_ERROR_INVALID_ARGS;
diff --git a/synadhd/wifi_hal/wifi_hal.cpp b/synadhd/wifi_hal/wifi_hal.cpp
index d13ac05..9814019 100755
--- a/synadhd/wifi_hal/wifi_hal.cpp
+++ b/synadhd/wifi_hal/wifi_hal.cpp
@@ -596,7 +596,9 @@ static void internal_cleaned_up_handler(wifi_handle handle)
     if (info->cmd_sock != 0) {
         ALOGI("cmd_sock non null. clean up");
         close(info->cleanup_socks[0]);
+        info->cleanup_socks[0] = -1;
         close(info->cleanup_socks[1]);
+        info->cleanup_socks[1] = -1;
         nl_socket_free(info->cmd_sock);
         nl_socket_free(info->event_sock);
         info->cmd_sock = NULL;
@@ -606,6 +608,7 @@ static void internal_cleaned_up_handler(wifi_handle handle)
     DestroyResponseLock();
     pthread_mutex_destroy(&info->cb_lock);
     free(info);
+    info = NULL;
 
     ALOGI("Internal cleanup completed");
 }
@@ -699,8 +702,6 @@ void wifi_cleanup(wifi_handle handle, wifi_cleaned_up_handler cleaned_up_handler
     }
     pthread_mutex_unlock(&info->cb_lock);
 
-    info->clean_up = true;
-
     /* global func ptr be invalidated and will not call any command from legacy hal */
     if (cleaned_up_handler) {
         ALOGI("cleaned_up_handler to invalidates func ptr");
@@ -709,9 +710,12 @@ void wifi_cleanup(wifi_handle handle, wifi_cleaned_up_handler cleaned_up_handler
         ALOGI("cleaned up handler is null");
     }
 
-    if (TEMP_FAILURE_RETRY(write(info->cleanup_socks[0], "Exit", 4)) < 1) {
-        // As a fallback set the cleanup flag to TRUE
-        ALOGE("could not write to the cleanup socket");
+    info->clean_up = true;
+    if (info && info->cleanup_socks[0] != -1) {
+        if (TEMP_FAILURE_RETRY(write(info->cleanup_socks[0], "Exit", 4)) < 1) {
+           // As a fallback set the cleanup flag to TRUE
+           ALOGE("could not write to the cleanup socket");
+       }
     }
     ALOGE("wifi_clean_up done");
 }
```

