```diff
diff --git a/snxxx/halimpl/hal/phNxpNciHal.cc b/snxxx/halimpl/hal/phNxpNciHal.cc
index 018a1ef..c0a39b8 100644
--- a/snxxx/halimpl/hal/phNxpNciHal.cc
+++ b/snxxx/halimpl/hal/phNxpNciHal.cc
@@ -713,6 +713,9 @@ int phNxpNciHal_MinOpen() {
   int dnld_retry_cnt = 0;
   sIsHalOpenErrorRecovery = false;
   setObserveModeFlag(false);
+  NciDiscoveryCommandBuilderInstance.setObserveModePerTech(
+      NCI_ANDROID_PASSIVE_OBSERVE_PARAM_DISABLE);
+  NciDiscoveryCommandBuilderInstance.setRfDiscoveryReceived(false);
   NXPLOG_NCIHAL_D("phNxpNci_MinOpen(): enter");
 
   if (nxpncihal_ctrl.halStatus == HAL_STATUS_MIN_OPEN) {
@@ -2651,6 +2654,10 @@ void phNxpNciHal_clean_resources() {
       NXPLOG_TML_E("phTmlNfc_Shutdown Failed");
     }
 
+    if (0 != pthread_join(nxpncihal_ctrl.client_thread, (void**)NULL)) {
+      NXPLOG_TML_E("NxpNci Fail to kill client thread!");
+    }
+
     PhNxpEventLogger::GetInstance().Finalize();
     phNxpTempMgr::GetInstance().Reset();
     phTmlNfc_CleanUp();
diff --git a/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc b/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc
index 98d2e54..1636b20 100644
--- a/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc
+++ b/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.cc
@@ -181,6 +181,7 @@ void NciDiscoveryCommandBuilder::setDiscoveryCommand(uint16_t data_len,
   if (!p_data || data_len <= 0) {
     return;
   }
+  setRfDiscoveryReceived(true);
   currentDiscoveryCommand = vector<uint8_t>(p_data, p_data + data_len);
 }
 
@@ -196,3 +197,58 @@ void NciDiscoveryCommandBuilder::setDiscoveryCommand(uint16_t data_len,
 vector<uint8_t> NciDiscoveryCommandBuilder::getDiscoveryCommand() {
   return currentDiscoveryCommand;
 }
+
+/*****************************************************************************
+ *
+ * Function         setObserveModePerTech
+ *
+ * Description      Sets ObserveMode per tech
+ *
+ * Parameters       techMode - ObserveMode per tech
+ *
+ * Returns          return void
+ *
+ ****************************************************************************/
+void NciDiscoveryCommandBuilder::setObserveModePerTech(uint8_t techMode) {
+  currentObserveModeTech = techMode;
+}
+
+/*****************************************************************************
+ *
+ * Function         getCurrentObserveModeTechValue
+ *
+ * Description      gets ObserveMode tech mode
+ *
+ * Returns          return Observe mode tech mode
+ *
+ ****************************************************************************/
+uint8_t NciDiscoveryCommandBuilder::getCurrentObserveModeTechValue() {
+  return currentObserveModeTech;
+}
+
+/*****************************************************************************
+ *
+ * Function         setRfDiscoveryReceived
+ *
+ * Description      Set flags when it receives discovery command received,
+ *                  set to false during nfc init begin
+ *
+ * Returns          return void
+ *
+ ****************************************************************************/
+void NciDiscoveryCommandBuilder::setRfDiscoveryReceived(bool flag) {
+  mIsRfDiscoveriryReceived = flag;
+}
+
+/*****************************************************************************
+ *
+ * Function         isRfDiscoveryCommandReceived
+ *
+ * Description      returns true if discovery command set otherwise false
+ *
+ * Returns          return bool
+ *
+ ****************************************************************************/
+bool NciDiscoveryCommandBuilder::isRfDiscoveryCommandReceived() {
+  return mIsRfDiscoveriryReceived;
+}
diff --git a/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.h b/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.h
index 87eaada..162593d 100644
--- a/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.h
+++ b/snxxx/halimpl/observe_mode/NciDiscoveryCommandBuilder.h
@@ -43,8 +43,10 @@ class DiscoveryConfiguration {
  */
 class NciDiscoveryCommandBuilder {
  private:
+  uint8_t currentObserveModeTech = 0x00;
   vector<uint8_t> currentDiscoveryCommand;
   vector<DiscoveryConfiguration> mRfDiscoverConfiguration;
+  bool mIsRfDiscoveriryReceived;
 
   /*****************************************************************************
    *
@@ -152,5 +154,53 @@ class NciDiscoveryCommandBuilder {
    *
    ****************************************************************************/
   vector<uint8_t> reConfigRFDiscCmd();
+
+  /*****************************************************************************
+   *
+   * Function         setObserveModePerTech
+   *
+   * Description      Sets ObserveMode tech mode
+   *
+   * Parameters       techMode - ObserveMode tech mode
+   *
+   * Returns          return void
+   *
+   ****************************************************************************/
+  void setObserveModePerTech(uint8_t techMode);
+
+  /*****************************************************************************
+   *
+   * Function         getCurrentObserveModeTechValue
+   *
+   * Description      gets Current ObserveMode per tech
+   *
+   * Returns          return Current Observe mode tech
+   *
+   ****************************************************************************/
+  uint8_t getCurrentObserveModeTechValue();
+
+  /*****************************************************************************
+   *
+   * Function         setRfDiscoveryReceived
+   *
+   * Description      Set flags when it receives discovery command received,
+   *                  set to false during nfc init begin
+   *
+   * Returns          return void
+   *
+   ****************************************************************************/
+  void setRfDiscoveryReceived(bool flag);
+
+  /*****************************************************************************
+   *
+   * Function         isRfDiscoveryCommandReceived
+   *
+   * Description      returns true if discovery command set otherwise false
+   *
+   * Returns          return bool
+   *
+   ****************************************************************************/
+  bool isRfDiscoveryCommandReceived();
+
   static NciDiscoveryCommandBuilder& getInstance();
 };
diff --git a/snxxx/halimpl/observe_mode/ObserveMode.cc b/snxxx/halimpl/observe_mode/ObserveMode.cc
index 498ae34..f90e979 100644
--- a/snxxx/halimpl/observe_mode/ObserveMode.cc
+++ b/snxxx/halimpl/observe_mode/ObserveMode.cc
@@ -69,6 +69,10 @@ int handleObserveMode(uint16_t data_len, const uint8_t* p_data) {
   uint8_t status = NCI_RSP_FAIL;
   if (phNxpNciHal_isObserveModeSupported()) {
     setObserveModeFlag(p_data[NCI_MSG_INDEX_FEATURE_VALUE]);
+    // ObserveMode per tech will be set to 0x01/0x00 for observe mode old
+    // command
+    NciDiscoveryCommandBuilderInstance.setObserveModePerTech(
+        p_data[NCI_MSG_INDEX_FEATURE_VALUE]);
     status = NCI_RSP_OK;
   }
 
@@ -78,6 +82,51 @@ int handleObserveMode(uint16_t data_len, const uint8_t* p_data) {
   return p_data[NCI_MSG_LEN_INDEX];
 }
 
+/*******************************************************************************
+ *
+ * Function         deactivateRfDiscovery()
+ *
+ * Description      sends RF deactivate command
+ *
+ * Returns          It returns Rf deactivate status
+ *
+ ******************************************************************************/
+NFCSTATUS deactivateRfDiscovery() {
+  if (NciDiscoveryCommandBuilderInstance.isRfDiscoveryCommandReceived()) {
+    uint8_t rf_deactivate_cmd[] = {0x21, 0x06, 0x01, 0x00};
+    return phNxpNciHal_send_ext_cmd(sizeof(rf_deactivate_cmd),
+                                    rf_deactivate_cmd);
+  } else {
+    return NFCSTATUS_SUCCESS;
+  }
+}
+
+/*******************************************************************************
+ *
+ * Function         sendRfDiscoveryCommand()
+ *
+ * Description      sends RF discovery command
+ *
+ * Parameters       isObserveModeEnable
+ *                      - true to send discovery with field detect mode
+ *                      - false to send default discovery command
+ *
+ * Returns          It returns Rf deactivate status
+ *
+ ******************************************************************************/
+NFCSTATUS sendRfDiscoveryCommand(bool isObserveModeEnable) {
+  if (NciDiscoveryCommandBuilderInstance.isRfDiscoveryCommandReceived()) {
+    vector<uint8_t> discoveryCommand =
+        isObserveModeEnable
+            ? NciDiscoveryCommandBuilderInstance.reConfigRFDiscCmd()
+            : NciDiscoveryCommandBuilderInstance.getDiscoveryCommand();
+    return phNxpNciHal_send_ext_cmd(discoveryCommand.size(),
+                                    &discoveryCommand[0]);
+  } else {
+    return NFCSTATUS_SUCCESS;
+  }
+}
+
 /*******************************************************************************
  *
  * Function         handleObserveModeTechCommand()
@@ -89,49 +138,56 @@ int handleObserveMode(uint16_t data_len, const uint8_t* p_data) {
  *
  ******************************************************************************/
 int handleObserveModeTechCommand(uint16_t data_len, const uint8_t* p_data) {
+  NFCSTATUS nciStatus = NFCSTATUS_FAILED;
   uint8_t status = NCI_RSP_FAIL;
+  uint8_t techValue = p_data[NCI_MSG_INDEX_FEATURE_VALUE];
   if (phNxpNciHal_isObserveModeSupported() &&
-      (p_data[NCI_MSG_INDEX_FEATURE_VALUE] ==
-           OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG ||
-       p_data[NCI_MSG_INDEX_FEATURE_VALUE] ==
-           OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG_FOR_ALL_TECH ||
-       p_data[NCI_MSG_INDEX_FEATURE_VALUE] ==
-           NCI_ANDROID_PASSIVE_OBSERVE_PARAM_DISABLE)) {
-    bool flag = (p_data[NCI_MSG_INDEX_FEATURE_VALUE] ==
-                     OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG ||
-                 p_data[NCI_MSG_INDEX_FEATURE_VALUE] ==
-                     OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG_FOR_ALL_TECH)
-                    ? true
-                    : false;
-    uint8_t rf_deactivate_cmd[] = {0x21, 0x06, 0x01, 0x00};
-
+      (techValue == OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG ||
+       techValue == OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG_FOR_ALL_TECH ||
+       techValue == NCI_ANDROID_PASSIVE_OBSERVE_PARAM_DISABLE)) {
+    bool flag =
+        (techValue == OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG ||
+         techValue == OBSERVE_MODE_TECH_COMMAND_SUPPORT_FLAG_FOR_ALL_TECH)
+            ? true
+            : false;
     // send RF Deactivate command
-    NFCSTATUS rfDeactivateStatus =
-        phNxpNciHal_send_ext_cmd(sizeof(rf_deactivate_cmd), rf_deactivate_cmd);
-    if (rfDeactivateStatus == NFCSTATUS_SUCCESS) {
-      if (flag) {
+    nciStatus = deactivateRfDiscovery();
+    if (nciStatus == NFCSTATUS_SUCCESS) {
+      if (flag && techValue != NciDiscoveryCommandBuilderInstance
+                                   .getCurrentObserveModeTechValue()) {
         // send Observe Mode Tech command
-        NFCSTATUS nciStatus =
-            phNxpNciHal_send_ext_cmd(data_len, (uint8_t*)p_data);
+        NciDiscoveryCommandBuilderInstance.setObserveModePerTech(techValue);
+
+        nciStatus = phNxpNciHal_send_ext_cmd(data_len, (uint8_t*)p_data);
         if (nciStatus != NFCSTATUS_SUCCESS) {
           NXPLOG_NCIHAL_E("%s ObserveMode tech command failed", __func__);
         }
       }
 
-      // send Discovery command
-      vector<uint8_t> discoveryCommand =
-          flag ? NciDiscoveryCommandBuilderInstance.reConfigRFDiscCmd()
-               : NciDiscoveryCommandBuilderInstance.getDiscoveryCommand();
-      NFCSTATUS rfDiscoveryStatus = phNxpNciHal_send_ext_cmd(
-          discoveryCommand.size(), &discoveryCommand[0]);
+      // Send RF Discovery command
+      NFCSTATUS rfDiscoveryStatus =
+          sendRfDiscoveryCommand(nciStatus == NFCSTATUS_SUCCESS ? flag : false);
 
-      if (rfDiscoveryStatus == NFCSTATUS_SUCCESS) {
+      if (rfDiscoveryStatus == NFCSTATUS_SUCCESS &&
+          nciStatus == NFCSTATUS_SUCCESS) {
         setObserveModeFlag(flag);
         status = NCI_RSP_OK;
-      } else {
-        NXPLOG_NCIHAL_E("%s Rf Disovery command failed", __func__);
+      } else if (rfDiscoveryStatus != NFCSTATUS_SUCCESS) {
+        NXPLOG_NCIHAL_E(
+            "%s Rf Disovery command failed, reset back to default discovery",
+            __func__);
+        // Recovery to fallback to default discovery when there is a failure
+        nciStatus = deactivateRfDiscovery();
+        if (nciStatus != NFCSTATUS_SUCCESS) {
+          NXPLOG_NCIHAL_E("%s Rf Deactivate command failed on recovery",
+                          __func__);
+        }
+        rfDiscoveryStatus = sendRfDiscoveryCommand(false);
+        if (rfDiscoveryStatus != NFCSTATUS_SUCCESS) {
+          NXPLOG_NCIHAL_E("%s Rf Disovery command failed on recovery",
+                          __func__);
+        }
       }
-
     } else {
       NXPLOG_NCIHAL_E("%s Rf Deactivate command failed", __func__);
     }
@@ -163,8 +219,11 @@ int handleGetObserveModeStatus(uint16_t data_len, const uint8_t* p_data) {
     return 0;
   }
   vector<uint8_t> response;
-  response.push_back(NCI_RSP_OK);
-  response.push_back(isObserveModeEnabled() ? 0x01 : 0x00);
+  response.push_back(0x00);
+  response.push_back(
+      isObserveModeEnabled()
+          ? NciDiscoveryCommandBuilderInstance.getCurrentObserveModeTechValue()
+          : 0x00);
   phNxpNciHal_vendorSpecificCallback(p_data[NCI_OID_INDEX],
                                      p_data[NCI_MSG_INDEX_FOR_FEATURE],
                                      std::move(response));
diff --git a/snxxx/halimpl/utils/phNxpNciHal_utils.cc b/snxxx/halimpl/utils/phNxpNciHal_utils.cc
index f9d28d0..92f3db9 100644
--- a/snxxx/halimpl/utils/phNxpNciHal_utils.cc
+++ b/snxxx/halimpl/utils/phNxpNciHal_utils.cc
@@ -362,9 +362,14 @@ NFCSTATUS phNxpNciHal_init_cb_data(phNxpNciHal_Sem_t* pCallbackData,
 
   /* Add to active semaphore list */
   phNxpNciHal_Monitor_t* hal_monitor = phNxpNciHal_get_monitor();
-  if (hal_monitor == NULL ||
-      listAdd(&hal_monitor->sem_list, pCallbackData) != 1) {
+  if (hal_monitor == NULL) {
+    NXPLOG_NCIHAL_E("Failed to get the monitor");
+    return NFCSTATUS_FAILED;
+  }
+  struct listHead* head = &hal_monitor->sem_list;
+  if (head == NULL || listAdd(head, pCallbackData) != 1) {
     NXPLOG_NCIHAL_E("Failed to add the semaphore to the list");
+    return NFCSTATUS_FAILED;
   }
 
   return NFCSTATUS_SUCCESS;
@@ -390,8 +395,12 @@ void phNxpNciHal_cleanup_cb_data(phNxpNciHal_Sem_t* pCallbackData) {
 
   /* Remove from active semaphore list */
   phNxpNciHal_Monitor_t* hal_monitor = phNxpNciHal_get_monitor();
-  if (hal_monitor == NULL ||
-      listRemove(&hal_monitor->sem_list, pCallbackData) != 1) {
+  if (hal_monitor == NULL) {
+    NXPLOG_NCIHAL_E("Failed to get the monitor");
+    return;
+  }
+  listHead* head = &hal_monitor->sem_list;
+  if (head == NULL || listRemove(head, pCallbackData) != 1) {
     NXPLOG_NCIHAL_E(
         "phNxpNciHal_cleanup_cb_data: Failed to remove semaphore from the "
         "list");
@@ -412,10 +421,15 @@ void phNxpNciHal_cleanup_cb_data(phNxpNciHal_Sem_t* pCallbackData) {
 void phNxpNciHal_releaseall_cb_data(void) {
   phNxpNciHal_Sem_t* pCallbackData;
   phNxpNciHal_Monitor_t* hal_monitor = phNxpNciHal_get_monitor();
+  if (hal_monitor == NULL) {
+    NXPLOG_NCIHAL_E("Failed to get the monitor");
+    return;
+  }
+  listHead* head = &hal_monitor->sem_list;
 
-  if (hal_monitor == NULL) return;
+  if (head == NULL) return;
 
-  while (listGetAndRemoveNext(&hal_monitor->sem_list, (void**)&pCallbackData)) {
+  while (listGetAndRemoveNext(head, (void**)&pCallbackData)) {
     pCallbackData->status = NFCSTATUS_FAILED;
     sem_post(&pCallbackData->sem);
   }
```

