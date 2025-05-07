```diff
diff --git a/android/app/jni/com_android_bluetooth_avrcp_controller.cpp b/android/app/jni/com_android_bluetooth_avrcp_controller.cpp
index 5150a01c6e..64cb0083ff 100644
--- a/android/app/jni/com_android_bluetooth_avrcp_controller.cpp
+++ b/android/app/jni/com_android_bluetooth_avrcp_controller.cpp
@@ -861,8 +861,7 @@ static void setPlayerApplicationSettingValuesNative(JNIEnv* env, jobject /* obje
     return;
   }
 
-  int i;
-  for (i = 0; i < num_attrib; ++i) {
+  for (int i = 0; i < num_attrib; ++i) {
     pAttrs[i] = (uint8_t)attr[i];
     pAttrsVal[i] = (uint8_t)attr_val[i];
   }
@@ -1047,12 +1046,6 @@ static void changeFolderPathNative(JNIEnv* env, jobject /* object */, jbyteArray
     return;
   }
 
-  // jbyte* uid = env->GetByteArrayElements(uidarr, NULL);
-  // if (!uid) {
-  //  jniThrowIOException(env, EINVAL);
-  //  return;
-  //}
-
   log::info("sBluetoothAvrcpInterface: {}", std::format_ptr(sBluetoothAvrcpInterface));
   RawAddress rawAddress;
   rawAddress.FromOctets((uint8_t*)addr);
@@ -1062,7 +1055,7 @@ static void changeFolderPathNative(JNIEnv* env, jobject /* object */, jbyteArray
   if (status != BT_STATUS_SUCCESS) {
     log::error("Failed sending changeFolderPathNative command, status: {}", bt_status_text(status));
   }
-  // env->ReleaseByteArrayElements(address, addr, 0);
+  env->ReleaseByteArrayElements(address, addr, 0);
 }
 
 static void setBrowsedPlayerNative(JNIEnv* env, jobject /* object */, jbyteArray address, jint id) {
@@ -1118,11 +1111,6 @@ static void playItemNative(JNIEnv* env, jobject /* object */, jbyteArray address
     return;
   }
 
-  //  jbyte* uid = env->GetByteArrayElements(uidArr, NULL);
-  //  if (!uid) {
-  //    jniThrowIOException(env, EINVAL);
-  //    return;
-  //  }
   RawAddress rawAddress;
   rawAddress.FromOctets((uint8_t*)addr);
 
diff --git a/android/app/jni/com_android_bluetooth_btservice_AdapterService.cpp b/android/app/jni/com_android_bluetooth_btservice_AdapterService.cpp
index 805e22b0df..b035c7b8e8 100644
--- a/android/app/jni/com_android_bluetooth_btservice_AdapterService.cpp
+++ b/android/app/jni/com_android_bluetooth_btservice_AdapterService.cpp
@@ -1216,13 +1216,16 @@ static jboolean set_data(JNIEnv* env, jobject oobData, jint transport, bt_oob_da
   }
 
   // Convert the address from byte[]
-  jbyte* addressBytes = env->GetByteArrayElements(address, NULL);
-  if (addressBytes == NULL) {
-    log::error("addressBytes cannot be null!");
-    jniThrowIOException(env, EINVAL);
-    return JNI_FALSE;
+  {
+    jbyte* addressBytes = env->GetByteArrayElements(address, NULL);
+    if (addressBytes == NULL) {
+      log::error("addressBytes cannot be null!");
+      jniThrowIOException(env, EINVAL);
+      return JNI_FALSE;
+    }
+    memcpy(oob_data->address, addressBytes, len);
+    env->ReleaseByteArrayElements(address, addressBytes, 0);
   }
-  memcpy(oob_data->address, addressBytes, len);
 
   // Get the device name byte[] java object
   jbyteArray deviceName =
@@ -1291,7 +1294,6 @@ static jboolean set_data(JNIEnv* env, jobject oobData, jint transport, bt_oob_da
     if (oobDataLength == NULL || env->GetArrayLength(oobDataLength) != OOB_DATA_LEN_SIZE) {
       log::info("wrong length of oobDataLength, should be empty or {} bytes.", OOB_DATA_LEN_SIZE);
       jniThrowIOException(env, EINVAL);
-      env->ReleaseByteArrayElements(oobDataLength, NULL, 0);
       return JNI_FALSE;
     }
 
@@ -1410,6 +1412,10 @@ static jboolean createBondOutOfBandNative(JNIEnv* env, jobject /* obj */, jbyteA
     return JNI_FALSE;
   }
 
+  RawAddress addr_obj = {};
+  addr_obj.FromOctets(reinterpret_cast<uint8_t*>(addr));
+  env->ReleaseByteArrayElements(address, addr, 0);
+
   // Convert P192 data from Java POJO to C Struct
   bt_oob_data_t p192_data = {};
   if (p192Data != NULL) {
@@ -1428,9 +1434,8 @@ static jboolean createBondOutOfBandNative(JNIEnv* env, jobject /* obj */, jbyteA
     }
   }
 
-  return ((sBluetoothInterface->create_bond_out_of_band(reinterpret_cast<RawAddress*>(addr),
-                                                        transport, &p192_data, &p256_data)) ==
-          BT_STATUS_SUCCESS)
+  return ((sBluetoothInterface->create_bond_out_of_band(&addr_obj, transport, &p192_data,
+                                                        &p256_data)) == BT_STATUS_SUCCESS)
                  ? JNI_TRUE
                  : JNI_FALSE;
 }
@@ -1761,6 +1766,7 @@ static jbyteArray obfuscateAddressNative(JNIEnv* env, jobject /* obj */, jbyteAr
   }
   RawAddress addr_obj = {};
   addr_obj.FromOctets(reinterpret_cast<uint8_t*>(addr));
+  env->ReleaseByteArrayElements(address, addr, 0);
   std::string output = sBluetoothInterface->obfuscate_address(addr_obj);
   jsize output_size = output.size() * sizeof(char);
   jbyteArray output_bytes = env->NewByteArray(output_size);
@@ -1898,6 +1904,7 @@ static int getMetricIdNative(JNIEnv* env, jobject /* obj */, jbyteArray address)
   }
   RawAddress addr_obj = {};
   addr_obj.FromOctets(reinterpret_cast<uint8_t*>(addr));
+  env->ReleaseByteArrayElements(address, addr, 0);
   return sBluetoothInterface->get_metric_id(addr_obj);
 }
 
@@ -1915,6 +1922,7 @@ static jboolean allowLowLatencyAudioNative(JNIEnv* env, jobject /* obj */, jbool
 
   RawAddress addr_obj = {};
   addr_obj.FromOctets(reinterpret_cast<uint8_t*>(addr));
+  env->ReleaseByteArrayElements(address, addr, 0);
   sBluetoothInterface->allow_low_latency_audio(allowed, addr_obj);
   return true;
 }
@@ -1932,6 +1940,7 @@ static void metadataChangedNative(JNIEnv* env, jobject /* obj */, jbyteArray add
   }
   RawAddress addr_obj = {};
   addr_obj.FromOctets(reinterpret_cast<uint8_t*>(addr));
+  env->ReleaseByteArrayElements(address, addr, 0);
 
   if (value == NULL) {
     log::error("metadataChangedNative() ignoring NULL array");
diff --git a/android/app/jni/com_android_bluetooth_gatt.cpp b/android/app/jni/com_android_bluetooth_gatt.cpp
index 54e97282a1..20eb8a63ec 100644
--- a/android/app/jni/com_android_bluetooth_gatt.cpp
+++ b/android/app/jni/com_android_bluetooth_gatt.cpp
@@ -1790,6 +1790,7 @@ static void gattClientScanFilterAddNative(JNIEnv* env, jobject /* object */, jin
       for (int j = 0; j < len; j++) {
         curr.irk[j] = irkBytes[j];
       }
+      env->ReleaseByteArrayElements(irkByteArray.get(), irkBytes, JNI_ABORT);
     }
 
     ScopedLocalRef<jobject> uuid(env, env->GetObjectField(current.get(), uuidFid));
@@ -2000,6 +2001,7 @@ static void gattClientMsftAdvMonitorAddNative(JNIEnv* env, jobject /* object*/,
       for (int j = 0; j < env->GetArrayLength(patternByteArray.get()); j++) {
         native_msft_adv_monitor_pattern.pattern.push_back(patternBytes[j]);
       }
+      env->ReleaseByteArrayElements(patternByteArray.get(), patternBytes, 0);
     }
 
     patterns.push_back(native_msft_adv_monitor_pattern);
diff --git a/android/app/jni/com_android_bluetooth_hfp.cpp b/android/app/jni/com_android_bluetooth_hfp.cpp
index 0a53d42c6f..18a0bf1950 100644
--- a/android/app/jni/com_android_bluetooth_hfp.cpp
+++ b/android/app/jni/com_android_bluetooth_hfp.cpp
@@ -967,6 +967,7 @@ static jboolean enableSwbNative(JNIEnv* env, jobject /* object */, jint swbCodec
   }
   bt_status_t ret = sBluetoothHfpInterface->EnableSwb(
           (bluetooth::headset::bthf_swb_codec_t)swbCodec, (bool)enable, (RawAddress*)addr);
+  env->ReleaseByteArrayElements(address, addr, 0);
   if (ret != BT_STATUS_SUCCESS) {
     log::error("Failed to {}", (enable ? "enable" : "disable"));
     return JNI_FALSE;
diff --git a/android/app/jni/com_android_bluetooth_hid_device.cpp b/android/app/jni/com_android_bluetooth_hid_device.cpp
index 5f2b98a2ce..336be9299b 100644
--- a/android/app/jni/com_android_bluetooth_hid_device.cpp
+++ b/android/app/jni/com_android_bluetooth_hid_device.cpp
@@ -445,6 +445,8 @@ static jboolean connectNative(JNIEnv* env, jobject /* thiz */, jbyteArray addres
 
   bt_status_t ret = sHiddIf->connect((RawAddress*)addr);
 
+  env->ReleaseByteArrayElements(address, addr, 0);
+
   log::verbose("connect() returned {}", bt_status_text(ret));
 
   if (ret == BT_STATUS_SUCCESS) {
diff --git a/flags/security.aconfig b/flags/security.aconfig
index 40a6890649..4066058497 100644
--- a/flags/security.aconfig
+++ b/flags/security.aconfig
@@ -15,16 +15,6 @@ flag {
     bug: "333634398"
 }
 
-flag {
-  name: "bta_av_setconfig_rej_type_confusion"
-  namespace: "bluetooth"
-  description: "Use stream control block for bta_av_setconfig_rej instead of a possibly incorrect union type"
-  bug: "341754333"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
 flag {
   name: "btsec_check_valid_discovery_database"
   namespace: "bluetooth"
@@ -65,17 +55,6 @@ flag {
   }
 }
 
-flag {
-  name: "btsec_le_oob_pairing"
-  namespace: "bluetooth"
-  description: "Drop connection if a peer claims it has OOB data but no local OOB data is stored"
-  bug: "374376990"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
-
 flag {
   name: "opp_check_content_uri_permissions"
   namespace: "bluetooth"
diff --git a/system/bta/av/bta_av_aact.cc b/system/bta/av/bta_av_aact.cc
index 6113eebdc1..15da885015 100644
--- a/system/bta/av/bta_av_aact.cc
+++ b/system/bta/av/bta_av_aact.cc
@@ -1797,23 +1797,13 @@ void bta_av_setconfig_rej(tBTA_AV_SCB* p_scb, tBTA_AV_DATA* p_data) {
 
   tBTA_AV bta_av_data;
 
-  if (com::android::bluetooth::flags::bta_av_setconfig_rej_type_confusion()) {
-    bta_av_data = {
-        .reject =
-            {
-                .bd_addr = p_scb->PeerAddress(),
-                .hndl = p_scb->hndl,
-            },
-    };
-  } else {
-    bta_av_data = {
-        .reject =
-            {
-                .bd_addr = p_data->str_msg.bd_addr,
-                .hndl = p_scb->hndl,
-            },
-    };
-  }
+  bta_av_data = {
+    .reject =
+    {
+      .bd_addr = p_scb->PeerAddress(),
+      .hndl = p_scb->hndl,
+    },
+  };
 
   (*bta_av_cb.p_cback)(BTA_AV_REJECT_EVT, &bta_av_data);
 }
diff --git a/system/stack/btm/btm_sec.cc b/system/stack/btm/btm_sec.cc
index 08e2a3371e..18e4ef7fec 100644
--- a/system/stack/btm/btm_sec.cc
+++ b/system/stack/btm/btm_sec.cc
@@ -3485,7 +3485,7 @@ void btm_sec_encryption_change_evt(uint16_t handle, tHCI_STATUS status, uint8_t
   if (com::android::bluetooth::flags::disconnect_on_encryption_failure()) {
     if (status != HCI_SUCCESS && encr_enable == 0) {
       log::error("Encryption failure {}, disconnecting {}", status, handle);
-      btm_sec_disconnect(handle, HCI_ERR_AUTH_FAILURE,
+      btm_sec_disconnect(handle, status,
                          "stack::btu::btu_hcif::encryption_change_evt Encryption Failure");
     }
   }
diff --git a/system/stack/smp/smp_act.cc b/system/stack/smp/smp_act.cc
index 35e2643319..00d5572e5d 100644
--- a/system/stack/smp/smp_act.cc
+++ b/system/stack/smp/smp_act.cc
@@ -1954,16 +1954,14 @@ void smp_process_secure_connection_oob_data(tSMP_CB* p_cb, tSMP_INT_DATA* /* p_d
     p_cb->local_random = {0};
   }
 
-  if (com::android::bluetooth::flags::btsec_le_oob_pairing()) {
-    if (p_cb->peer_oob_flag == SMP_OOB_PRESENT && !p_sc_oob_data->loc_oob_data.present) {
-      log::warn(
-              "local OOB data is not present but peer claims to have received it; dropping "
-              "connection");
-      tSMP_INT_DATA smp_int_data{};
-      smp_int_data.status = SMP_OOB_FAIL;
-      smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &smp_int_data);
-      return;
-    }
+  if (p_cb->peer_oob_flag == SMP_OOB_PRESENT && !p_sc_oob_data->loc_oob_data.present) {
+    log::warn(
+            "local OOB data is not present but peer claims to have received it; dropping "
+            "connection");
+    tSMP_INT_DATA smp_int_data{};
+    smp_int_data.status = SMP_OOB_FAIL;
+    smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &smp_int_data);
+    return;
   }
 
   if (!p_sc_oob_data->peer_oob_data.present) {
```

