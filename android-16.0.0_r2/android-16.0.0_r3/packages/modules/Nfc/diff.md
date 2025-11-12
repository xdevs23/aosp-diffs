```diff
diff --git a/NfcNci/AndroidManifest.xml b/NfcNci/AndroidManifest.xml
index a0fca02f3..e43f97b6e 100755
--- a/NfcNci/AndroidManifest.xml
+++ b/NfcNci/AndroidManifest.xml
@@ -71,91 +71,9 @@
     <uses-permission android:name="android.permission.READ_PRIVILEGED_PHONE_STATE"/>
     <uses-permission android:name="android.permission.MODIFY_PHONE_STATE"/>
     <uses-permission android:name="android.permission.WRITE_SECURITY_LOG"/>
+    <uses-permission android:name="android.permission.UPDATE_DEVICE_STATS"/>
 
     <protected-broadcast android:name="android.nfc.intent.action.WATCHDOG" />
-
-    <application android:name=".NfcApplication"
-                 android:icon="@drawable/icon"
-                 android:label="@string/app_name"
-                 android:theme="@android:style/Theme.Material.Light"
-                 android:persistent="true"
-                 android:persistentWhenFeatureAvailable="android.hardware.nfc.any"
-                 android:restoreAnyVersion="true"
-                 android:backupAgent="com.android.nfc.NfcBackupAgent"
-                 android:killAfterRestore="false"
-                 android:usesCleartextTraffic="false"
-                 android:supportsRtl="true"
-                 android:hardwareAccelerated="false"
-                 android:memtagMode="async"
-                 android:featureFlag="!com.android.nfc.flags.enable_direct_boot_aware"
-    >
-        <meta-data android:name="com.google.android.backup.api_key"
-            android:value="AEdPqrEAAAAIbiKKs0wlimxeJ9y8iRIaBOH6aeb2IurmZyBHvg" />
-
-        <provider android:name="androidx.core.content.FileProvider"
-            android:authorities="com.google.android.nfc.fileprovider"
-            android:grantUriPermissions="true"
-            android:exported="false">
-            <meta-data
-                android:name="android.support.FILE_PROVIDER_PATHS"
-                android:resource="@xml/file_paths" />
-        </provider>
-
-        <activity android:name=".TechListChooserActivity"
-            android:theme="@*android:style/Theme.Dialog.Alert"
-            android:finishOnCloseSystemDialogs="true"
-            android:excludeFromRecents="true"
-            android:multiprocess="true"
-        />
-
-        <activity android:name=".cardemulation.AppChooserActivity"
-            android:finishOnCloseSystemDialogs="true"
-            android:excludeFromRecents="true"
-            android:clearTaskOnLaunch="true"
-            android:multiprocess="true"
-            android:theme="@style/BottomSheetDialogStyle"
-        />
-
-        <activity android:name=".cardemulation.TapAgainDialog"
-            android:finishOnCloseSystemDialogs="true"
-            android:excludeFromRecents="true"
-            android:clearTaskOnLaunch="true"
-            android:multiprocess="true"
-        />
-        <activity android:name=".NfcRootActivity"
-            android:theme="@*android:style/Theme.Translucent.NoTitleBar"
-            android:excludeFromRecents="true"
-            android:noHistory="true"
-        />
-        <activity android:name=".handover.ConfirmConnectActivity"
-            android:finishOnCloseSystemDialogs="true"
-            android:excludeFromRecents="true"
-            android:theme="@android:style/Theme.Translucent.NoTitleBar"
-            android:noHistory="true"
-            android:configChanges="orientation|keyboardHidden|screenSize"
-        />
-        <activity android:name=".ConfirmConnectToWifiNetworkActivity"
-            android:finishOnCloseSystemDialogs="true"
-            android:excludeFromRecents="true"
-            android:theme="@android:style/Theme.Translucent.NoTitleBar"
-            android:noHistory="true"
-        />
-        <activity android:name=".NfcEnableAllowlistActivity"
-            android:theme="@android:style/Theme.Translucent.NoTitleBar"
-            android:noHistory="true"
-        />
-
-        <receiver android:name=".NfcBootCompletedReceiver"
-            android:exported="true">
-            <intent-filter>
-                <action android:name="android.intent.action.BOOT_COMPLETED" />
-            </intent-filter>
-        </receiver>
-
-        <service android:name=".handover.PeripheralHandoverService"
-        />
-    </application>
-
     <application android:name=".NfcApplication"
                  android:icon="@drawable/icon"
                  android:label="@string/app_name"
@@ -170,9 +88,7 @@
                  android:hardwareAccelerated="false"
                  android:memtagMode="async"
                  android:directBootAware="true"
-                 android:defaultToDeviceProtectedStorage="true"
-                 android:featureFlag="com.android.nfc.flags.enable_direct_boot_aware"
-    >
+                 android:defaultToDeviceProtectedStorage="true">
         <meta-data android:name="com.google.android.backup.api_key"
             android:value="AEdPqrEAAAAIbiKKs0wlimxeJ9y8iRIaBOH6aeb2IurmZyBHvg" />
 
diff --git a/NfcNci/TEST_MAPPING b/NfcNci/TEST_MAPPING
index 76a49ed9d..f2eb8b219 100644
--- a/NfcNci/TEST_MAPPING
+++ b/NfcNci/TEST_MAPPING
@@ -19,5 +19,15 @@
       "name": "libnfc-nci-jni-tests",
       "keywords": ["primary-device"]
     }
+  ],
+  "wear-cts-presubmit": [
+    {
+      "name": "CtsNfcTestCases",
+      "options": [
+       {
+         "include-filter": "android.nfc.cts.CardEmulationTest"
+       }
+     ]
+    }
   ]
 }
diff --git a/NfcNci/com.android.nfc.xml b/NfcNci/com.android.nfc.xml
index 01669088a..6ef9d695f 100644
--- a/NfcNci/com.android.nfc.xml
+++ b/NfcNci/com.android.nfc.xml
@@ -38,5 +38,6 @@
         <permission name="android.permission.MODIFY_PHONE_STATE"/>
         <permission name="android.permission.WRITE_SECURITY_LOG"/>
         <permission name="android.permission.SUBSCRIBE_TO_KEYGUARD_LOCKED_STATE"/>
+        <permission name="android.permission.UPDATE_DEVICE_STATS"/>
     </privapp-permissions>
 </permissions>
diff --git a/NfcNci/flags/nfc_flags.aconfig b/NfcNci/flags/nfc_flags.aconfig
index fb6c8e8e1..0f67c65bb 100644
--- a/NfcNci/flags/nfc_flags.aconfig
+++ b/NfcNci/flags/nfc_flags.aconfig
@@ -40,13 +40,6 @@ flag {
     bug: "345570691"
 }
 
-flag {
-    name: "enable_direct_boot_aware"
-    namespace: "nfc"
-    description: "Enable direct boot aware for nfc service"
-    bug: "321310938"
-}
-
 flag {
     name: "observe_mode_without_rf"
     namespace: "nfc"
diff --git a/NfcNci/nci/jni/Android.bp b/NfcNci/nci/jni/Android.bp
index 2c6b1b6e8..6cd559746 100644
--- a/NfcNci/nci/jni/Android.bp
+++ b/NfcNci/nci/jni/Android.bp
@@ -179,4 +179,7 @@ cc_test {
         },
     },
     auto_gen_config: true,
+    visibility: [
+        "//platform_testing:__subpackages__",
+    ],
 }
diff --git a/NfcNci/nci/jni/NativeNfcManager.cpp b/NfcNci/nci/jni/NativeNfcManager.cpp
index f0f15d6db..e8c4d493c 100644
--- a/NfcNci/nci/jni/NativeNfcManager.cpp
+++ b/NfcNci/nci/jni/NativeNfcManager.cpp
@@ -200,7 +200,7 @@ tNFA_STATUS gVSCmdStatus = NFA_STATUS_OK;
 uint16_t gCurrentConfigLen;
 uint8_t gConfig[256];
 std::vector<uint8_t> gCaps(0);
-static int prevScreenState = NFA_SCREEN_STATE_OFF_LOCKED;
+static int prevScreenState = NFA_SCREEN_STATE_UNKNOWN;
 static int NFA_SCREEN_POLLING_TAG_MASK = 0x10;
 bool gIsDtaEnabled = false;
 static bool gObserveModeEnabled = false;
@@ -326,6 +326,11 @@ static void nfaConnectionCallback(uint8_t connEvent,
       sNfaEnableDisablePollingEvent.notifyOne();
     } break;
 
+    case NFA_LISTEN_DISABLED_EVT:
+      LOG(DEBUG) << StringPrintf("%s: NFA_LISTEN_DISABLED_EVT:status= %u",
+                                 __func__, eventData->status);
+      break;
+
     case NFA_POLL_ENABLED_EVT:  // whether polling successfully started
     {
       LOG(DEBUG) << StringPrintf("%s: NFA_POLL_ENABLED_EVT: status = %u",
@@ -420,6 +425,7 @@ static void nfaConnectionCallback(uint8_t connEvent,
       if (eventData->status != NFA_STATUS_OK) {
         if (gIsSelectingRfInterface) {
           nativeNfcTag_doConnectStatus(false);
+          NfcTag::getInstance().selectCompleteStatus(false);
         }
 
         LOG(ERROR) << StringPrintf(
@@ -448,6 +454,7 @@ static void nfaConnectionCallback(uint8_t connEvent,
       uint8_t activatedMode =
           eventData->activated.activate_ntf.rf_tech_param.mode;
       gTagJustActivated = true;
+      NfcTag::getInstance().selectCompleteStatus(true);
       if (NFC_PROTOCOL_T5T == activatedProtocol &&
           NfcTag::getInstance().getNumDiscNtf()) {
         /* T5T doesn't support multiproto detection logic */
@@ -1171,6 +1178,7 @@ static jboolean nfcManager_unrouteAid(JNIEnv* e, jobject, jbyteArray aid) {
 *******************************************************************************/
 static jint nfcManager_commitRouting(JNIEnv* e, jobject) {
   if (sIsShuttingDown) return -1;
+  if (sIsRecovering) return -1;
   if (sRfEnabled) {
     /*Update routing table only in Idle state.*/
     startRfDiscovery(false);
@@ -1512,11 +1520,7 @@ static jint nfcManager_doRegisterT3tIdentifier(JNIEnv* e, jobject,
   size_t bufLen = bytes.size();
   int handle = RoutingManager::getInstance().registerT3tIdentifier(buf, bufLen);
 
-  LOG(DEBUG) << StringPrintf("%s: handle=%d", __func__, handle);
-  if (handle != NFA_HANDLE_INVALID)
-    RoutingManager::getInstance().commitRouting();
-  LOG(DEBUG) << StringPrintf("%s: exit", __func__);
-
+  LOG(DEBUG) << StringPrintf("%s: exit, handle=%d", __func__, handle);
   return handle;
 }
 
@@ -1538,8 +1542,6 @@ static void nfcManager_doDeregisterT3tIdentifier(JNIEnv*, jobject,
   LOG(DEBUG) << StringPrintf("%s: enter; handle=%d", __func__, handle);
 
   RoutingManager::getInstance().deregisterT3tIdentifier(handle);
-  RoutingManager::getInstance().commitRouting();
-
   LOG(DEBUG) << StringPrintf("%s: exit", __func__);
 }
 
@@ -1595,7 +1597,15 @@ static jboolean doPartialInit() {
     }
     NFA_SetNfccMode(ENABLE_MODE_DEFAULT);
   }
-
+  if (stat == NFA_STATUS_OK) {
+    // sIsNfaEnabled indicates whether stack started successfully
+    if (sIsNfaEnabled) {
+      NativeT4tNfcee::getInstance().initialize();
+    }
+  } else {
+    LOG(ERROR) << StringPrintf("%s: fail enable; error=0x%X", __func__, stat);
+    return JNI_FALSE;
+  }
   // sIsNfaEnabled indicates whether stack started successfully
   if (!sIsNfaEnabled) {
     NFA_Disable(false /* ungraceful */);
@@ -1704,7 +1714,7 @@ static jboolean nfcManager_doInitialize(JNIEnv* e, jobject o) {
           }
         }
 
-        prevScreenState = NFA_SCREEN_STATE_OFF_LOCKED;
+        prevScreenState = NFA_SCREEN_STATE_UNKNOWN;
 
         // Do custom NFCA startup configuration.
         doStartupConfig();
@@ -1801,12 +1811,10 @@ static tNFA_STATUS setTechAPollingLoopAnnotation(JNIEnv* env, jobject o,
       command.push_back(0x00);
     } else {
       command.push_back(0x01);                 // Number of frame entries.
-      command.push_back(0x21);                 // Position and type.
-      command.push_back(annotation_size + 3);  // Length
+      command.push_back(0x20);                 // Position and type.
+      command.push_back(annotation_size + 1);  // Length
       command.push_back(0x0a);                 // Waiting time
       command.insert(command.end(), annotation_data, annotation_data + annotation_size);
-      command.push_back(0x00);
-      command.push_back(0x00);
     }
     SyncEventGuard guard(gNfaVsCommand);
     tNFA_STATUS status =
@@ -1846,7 +1854,8 @@ static void nfcManager_enableDiscovery(JNIEnv* e, jobject o,
                                        jboolean enable_host_routing,
                                        jbyteArray tech_a_polling_loop_annotation,
                                        jboolean restart) {
-  if (sIsShuttingDown) return;
+  if (sIsShuttingDown || sIsRecovering || sIsDisabling || !sIsNfaEnabled)
+    return;
   tNFA_TECHNOLOGY_MASK tech_mask = DEFAULT_TECH_MASK;
   struct nfc_jni_native_data* nat = getNative(e, o);
 
@@ -1934,7 +1943,8 @@ static void nfcManager_enableDiscovery(JNIEnv* e, jobject o,
   }
 
   // Checking if RT should be updated
-  RoutingManager::getInstance().commitRouting();
+  if (!RoutingManager::getInstance().isRTUpdateOptimized())
+    RoutingManager::getInstance().commitRouting();
 
   // Actually start discovery.
   startRfDiscovery(true);
@@ -1955,7 +1965,8 @@ static void nfcManager_enableDiscovery(JNIEnv* e, jobject o,
 **
 *******************************************************************************/
 void nfcManager_disableDiscovery(JNIEnv* e, jobject o) {
-  if (sIsShuttingDown) return;
+  if (sIsShuttingDown || sIsRecovering || sIsDisabling || !sIsNfaEnabled)
+    return;
   tNFA_STATUS status = NFA_STATUS_OK;
   LOG(DEBUG) << StringPrintf("%s: enter;", __func__);
 
@@ -1987,6 +1998,7 @@ static jboolean doPartialDeinit() {
   LOG(DEBUG) << StringPrintf("%s: enter", __func__);
   tNFA_STATUS stat = NFA_STATUS_OK;
   sIsDisabling = true;
+  NativeT4tNfcee::getInstance().onNfccShutdown();
   if (sIsNfaEnabled) {
     SyncEventGuard guard(sNfaDisableEvent);
     stat = NFA_Disable(TRUE /* graceful */);
@@ -2280,6 +2292,12 @@ static void nfcManager_doSetScreenState(JNIEnv* e, jobject o,
       "%s: state = %d prevScreenState= %d, discovry_param = %d", __FUNCTION__,
       state, prevScreenState, discovry_param);
 
+  if (gPartialInitMode != ENABLE_MODE_DEFAULT) {
+    LOG(ERROR) << StringPrintf(
+        "%s: PartialInit mode Screen state change not required", __FUNCTION__);
+    return;
+  }
+
   if (prevScreenState == state) {
     LOG(DEBUG) << StringPrintf(
         "%s: New screen state is same as previous state. No action taken",
@@ -2288,7 +2306,7 @@ static void nfcManager_doSetScreenState(JNIEnv* e, jobject o,
   }
 
   if (sIsDisabling || !sIsNfaEnabled ||
-      (NFC_GetNCIVersion() != NCI_VERSION_2_0)) {
+      (NFC_GetNCIVersion() < NCI_VERSION_2_0)) {
     prevScreenState = state;
     return;
   }
@@ -2301,7 +2319,8 @@ static void nfcManager_doSetScreenState(JNIEnv* e, jobject o,
 
   if (prevScreenState == NFA_SCREEN_STATE_OFF_LOCKED ||
       prevScreenState == NFA_SCREEN_STATE_OFF_UNLOCKED ||
-      prevScreenState == NFA_SCREEN_STATE_ON_LOCKED) {
+      prevScreenState == NFA_SCREEN_STATE_ON_LOCKED ||
+      prevScreenState == NFA_SCREEN_STATE_UNKNOWN) {
     SyncEventGuard guard(sNfaSetPowerSubState);
     status = NFA_SetPowerSubStateForScreenState(state);
     if (status != NFA_STATUS_OK) {
@@ -2457,6 +2476,7 @@ static bool nfcManager_isMultiTag() {
 static void nfcManager_doStartStopPolling(JNIEnv* e, jobject o,
                                           jboolean start) {
   if (sIsShuttingDown) return;
+  if (sIsRecovering) return;
   startStopPolling(start);
 }
 
diff --git a/NfcNci/nci/jni/NativeNfcTag.cpp b/NfcNci/nci/jni/NativeNfcTag.cpp
index 896889c50..fb9a033ed 100644
--- a/NfcNci/nci/jni/NativeNfcTag.cpp
+++ b/NfcNci/nci/jni/NativeNfcTag.cpp
@@ -132,6 +132,7 @@ static bool sReselectTagIdle = false;
 
 static int sPresCheckStatus = 0;
 static bool sIsDisconnecting = false;
+void nativeNfcTag_doPresenceCheckResult(tNFA_STATUS status);
 
 static int reSelect(tNFA_INTF_TYPE rfInterface, bool fSwitchIfNeeded);
 extern bool gIsDtaEnabled;
@@ -164,10 +165,8 @@ void nativeNfcTag_abortWaits() {
   }
 
   sem_post(&sCheckNdefSem);
-  {
-    SyncEventGuard guard(sPresenceCheckEvent);
-    sPresenceCheckEvent.notifyOne();
-  }
+  nativeNfcTag_doPresenceCheckResult(NFA_STATUS_FAILED);
+
   sem_post(&sMakeReadonlySem);
   sCurrentRfInterface = NFA_INTERFACE_ISO_DEP;
   sCurrentActivatedProtocl = NFA_INTERFACE_ISO_DEP;
@@ -588,15 +587,16 @@ static jint nativeNfcTag_doConnect(JNIEnv*, jobject, jint targetIdx,
   }
 
   if (sCurrentConnectedTargetType == TARGET_TYPE_ISO14443_3A ||
-      sCurrentConnectedTargetType == TARGET_TYPE_ISO14443_3B) {
-    if (sCurrentConnectedTargetProtocol != NFC_PROTOCOL_MIFARE) {
+      sCurrentConnectedTargetType == TARGET_TYPE_ISO14443_3B ||
+      sCurrentConnectedTargetType == TARGET_TYPE_MIFARE_CLASSIC) {
+    if (sCurrentConnectedTargetProtocol == NFC_PROTOCOL_MIFARE) {
+      intfType = NFA_INTERFACE_MIFARE;
+    } else {
       LOG(DEBUG) << StringPrintf(
           "%s: switching to tech=%x need to switch rf intf to frame", __func__,
           sCurrentConnectedTargetType);
       intfType = NFA_INTERFACE_FRAME;
     }
-  } else if (sCurrentConnectedTargetType == TARGET_TYPE_MIFARE_CLASSIC) {
-    intfType = NFA_INTERFACE_MIFARE;
   } else {
     intfType = NFA_INTERFACE_ISO_DEP;
   }
diff --git a/NfcNci/nci/jni/NfcTag.cpp b/NfcNci/nci/jni/NfcTag.cpp
index a20fda458..34c1e140f 100755
--- a/NfcNci/nci/jni/NfcTag.cpp
+++ b/NfcNci/nci/jni/NfcTag.cpp
@@ -24,6 +24,7 @@
 #include <log/log.h>
 #include <nativehelper/ScopedLocalRef.h>
 #include <nativehelper/ScopedPrimitiveArray.h>
+#include "IntervalTimer.h"
 #include <statslog_nfc.h>
 
 #include "JavaClassConstants.h"
@@ -38,6 +39,9 @@ static jobjectArray sTechPollBytes;
 static jobjectArray gtechActBytes;
 static int sLastSelectedTagId = 0;
 
+static void selectCompleteCallBack(union sigval);
+IntervalTimer gSelectCompleteTimer;
+
 /*******************************************************************************
 **
 ** Function:        NfcTag
@@ -51,6 +55,7 @@ NfcTag::NfcTag()
     : mNumTechList(0),
       mNumRfDiscId(0),
       mIsReselecting(false),
+      mWaitingForSelect(false),
       mTechnologyTimeoutsTable(MAX_NUM_TECHNOLOGY),
       mNativeData(NULL),
       mIsActivated(false),
@@ -1086,6 +1091,7 @@ void NfcTag::resetTechnologies() {
   memset(mTechParams, 0, sizeof(mTechParams));
   mIsDynamicTagId = false;
   mIsFelicaLite = false;
+  selectCompleteStatus(false);
   resetAllTransceiveTimeouts(true);
 }
 
@@ -1116,8 +1122,13 @@ void NfcTag::selectFirstTag() {
 
   if (foundIdx != -1) {
     tNFA_STATUS stat = selectTagAtIndex(foundIdx);
-    if (stat != NFA_STATUS_OK)
+    if (stat != NFA_STATUS_OK) {
       LOG(ERROR) << StringPrintf("%s: fail select; error=0x%X", fn, stat);
+    } else {
+      mWaitingForSelect = true;
+      gSelectCompleteTimer.set(1000, selectCompleteCallBack);
+      LOG(DEBUG) << StringPrintf("%s: starting timer", fn);
+    }
   } else
     LOG(ERROR) << StringPrintf("%s: only found NFC-DEP technology.", fn);
 }
@@ -1165,6 +1176,9 @@ void NfcTag::selectNextTagIfExists() {
                                  fn);
     } else {
       LOG(ERROR) << StringPrintf("%s: fail select; error=0x%X", fn, stat);
+      mWaitingForSelect = true;
+      LOG(DEBUG) << StringPrintf("%s: Starting timer", fn);
+      gSelectCompleteTimer.set(1000, selectCompleteCallBack);
     }
   } else {
     LOG(ERROR) << StringPrintf("%s: only found NFC-DEP technology.", fn);
@@ -1794,3 +1808,37 @@ bool NfcTag::isReselecting() { return mIsReselecting; }
 **
 *******************************************************************************/
 void NfcTag::setReselect(bool isReselecting) { mIsReselecting = isReselecting; }
+
+/*******************************************************************************
+**
+** Function:        selectCompleteStatus
+**
+** Description:     Notify whether tag select is success/failure
+**
+** Returns:         None
+**
+*******************************************************************************/
+void NfcTag::selectCompleteStatus(bool status) {
+  if (mWaitingForSelect == true) {
+    LOG(INFO) << StringPrintf("%s: status=%u", __func__, status);
+    gSelectCompleteTimer.kill();
+    mWaitingForSelect = false;
+  }
+}
+
+/*******************************************************************************
+**
+** Function:        selectCompleteCallBack
+**
+** Description:     CallBack called when tag select is timed out.
+**
+** Returns:         None
+**
+*******************************************************************************/
+void selectCompleteCallBack(union sigval) {
+  if (NfcTag::getInstance().mWaitingForSelect == true) {
+    LOG(DEBUG) << StringPrintf("%s", __func__);
+    NfcTag::getInstance().mWaitingForSelect = false;
+    NFA_Deactivate(false);
+  }
+}
diff --git a/NfcNci/nci/jni/NfcTag.h b/NfcNci/nci/jni/NfcTag.h
index 0598070c6..57fff714d 100644
--- a/NfcNci/nci/jni/NfcTag.h
+++ b/NfcNci/nci/jni/NfcTag.h
@@ -48,6 +48,7 @@ class NfcTag {
   int mNumTechList;  // current number of NFC technologies in the list
   int mNumRfDiscId;
   bool mIsReselecting;
+  bool mWaitingForSelect;
 
   /*******************************************************************************
   **
@@ -502,6 +503,17 @@ class NfcTag {
   *******************************************************************************/
   int getNumDiscNtf();
 
+  /*******************************************************************************
+  **
+  ** Function:        selectCompleteStatus
+  **
+  ** Description:     Notify whether tag select is success/failure
+  **
+  ** Returns:         None
+  **
+  *******************************************************************************/
+  void selectCompleteStatus(bool status);
+
  private:
   std::vector<int> mTechnologyTimeoutsTable;
   std::vector<int> mTechnologyDefaultTimeoutsTable;
diff --git a/NfcNci/nci/jni/RoutingManager.cpp b/NfcNci/nci/jni/RoutingManager.cpp
index 50d79f141..a509a416b 100755
--- a/NfcNci/nci/jni/RoutingManager.cpp
+++ b/NfcNci/nci/jni/RoutingManager.cpp
@@ -64,7 +64,6 @@ const JNINativeMethod RoutingManager::sMethods[] = {
     {"doGetEuiccMepMode", "()I",
      (void*)RoutingManager::com_android_nfc_cardemulation_doGetEuiccMepMode}};
 
-static const int MAX_NUM_EE = 5;
 // SCBR from host works only when App is in foreground
 static const uint8_t SYS_CODE_PWR_STATE_HOST = 0x01;
 static const uint16_t DEFAULT_SYS_CODE = 0xFEFE;
@@ -156,6 +155,21 @@ RoutingManager::RoutingManager()
         mIsRFDiscoveryOptimized);
   }
 
+  if (NfcConfig::hasKey(NAME_OPTIMIZE_ROUTING_TABLE_UPDATE)) {
+    mIsRTUpdateOptimized =
+        (NfcConfig::getUnsigned(NAME_OPTIMIZE_ROUTING_TABLE_UPDATE) == 0x01
+             ? true
+             : false);
+    LOG(VERBOSE) << StringPrintf(
+        "%s: NAME_OPTIMIZE_ROUTING_TABLE_UPDATE found=%d", fn,
+        mIsRTUpdateOptimized);
+  } else {
+    mIsRTUpdateOptimized = false;
+    LOG(VERBOSE) << StringPrintf(
+        "%s: NAME_OPTIMIZE_ROUTING_TABLE_UPDATE not found=%d", fn,
+        mIsRTUpdateOptimized);
+  }
+
   memset(&mEeInfo, 0, sizeof(mEeInfo));
   mReceivedEeInfo = false;
   mSeTechMask = 0x00;
@@ -259,7 +273,7 @@ RoutingManager& RoutingManager::getInstance() {
  *******************************************************************************/
 bool RoutingManager::isTypeATypeBTechSupportedInEe(tNFA_HANDLE eeHandle) {
   static const char fn[] = "RoutingManager::isTypeATypeBTechSupportedInEe";
-  uint8_t actualNbEe = MAX_NUM_EE;
+  uint8_t actualNbEe = NFA_EE_MAX_EE_SUPPORTED;
   tNFA_EE_INFO eeInfo[actualNbEe];
 
   memset(&eeInfo, 0, actualNbEe * sizeof(tNFA_EE_INFO));
@@ -276,7 +290,7 @@ bool RoutingManager::isTypeATypeBTechSupportedInEe(tNFA_HANDLE eeHandle) {
   }
 
   if (mEuiccMepMode) {
-    memset(&eeInfo, 0, MAX_NUM_EE * sizeof(tNFA_EE_INFO));
+    memset(&eeInfo, 0, actualNbEe * sizeof(tNFA_EE_INFO));
     nfaStat = NFA_EeGetMepInfo(&actualNbEe, eeInfo);
     if (nfaStat != NFA_STATUS_OK) {
       return false;
@@ -433,8 +447,8 @@ void RoutingManager::onNfccShutdown() {
   if (mDefaultOffHostRoute == 0x00 && mDefaultFelicaRoute == 0x00) return;
 
   tNFA_STATUS nfaStat = NFA_STATUS_FAILED;
-  uint8_t actualNumEe = MAX_NUM_EE;
-  tNFA_EE_INFO eeInfo[MAX_NUM_EE];
+  uint8_t actualNumEe = NFA_EE_MAX_EE_SUPPORTED;
+  tNFA_EE_INFO eeInfo[actualNumEe];
   mDeinitializing = true;
 
   memset(&eeInfo, 0, sizeof(eeInfo));
@@ -575,16 +589,16 @@ void RoutingManager::notifyEeAidSelected(tNFC_AID& nfcaid,
                         (jbyte*)&aid[0]);
   CHECK(!e->ExceptionCheck());
 
-  std::string evtSrc;
-  if (!getNameOfEe(ee_handle, evtSrc)) {
+  std::string eeName;
+  if (!getNameOfEe(ee_handle, eeName)) {
     return;
   }
 
-  ScopedLocalRef<jobject> srcJavaString(e, e->NewStringUTF(evtSrc.c_str()));
-  CHECK(srcJavaString.get());
+  ScopedLocalRef<jobject> eeNameJavaString(e, e->NewStringUTF(eeName.c_str()));
+  CHECK(eeNameJavaString.get());
   e->CallVoidMethod(mNativeData->manager,
                     android::gCachedNfcManagerNotifyEeAidSelected,
-                    aidJavaArray.get(), srcJavaString.get());
+                    aidJavaArray.get(), eeNameJavaString.get());
 }
 
 /*******************************************************************************
@@ -603,16 +617,16 @@ void RoutingManager::notifyEeProtocolSelected(uint8_t protocol,
   ScopedAttach attach(mNativeData->vm, &e);
   CHECK(e);
 
-  std::string evtSrc;
-  if (!getNameOfEe(ee_handle, evtSrc)) {
+  std::string eeName;
+  if (!getNameOfEe(ee_handle, eeName)) {
     return;
   }
 
-  ScopedLocalRef<jobject> srcJavaString(e, e->NewStringUTF(evtSrc.c_str()));
-  CHECK(srcJavaString.get());
+  ScopedLocalRef<jobject> eeNameJavaString(e, e->NewStringUTF(eeName.c_str()));
+  CHECK(eeNameJavaString.get());
   e->CallVoidMethod(mNativeData->manager,
                     android::gCachedNfcManagerNotifyEeProtocolSelected,
-                    protocol, srcJavaString.get());
+                    protocol, eeNameJavaString.get());
 }
 
 /*******************************************************************************
@@ -630,16 +644,16 @@ void RoutingManager::notifyEeTechSelected(uint8_t tech, tNFA_HANDLE ee_handle) {
   ScopedAttach attach(mNativeData->vm, &e);
   CHECK(e);
 
-  std::string evtSrc;
-  if (!getNameOfEe(ee_handle, evtSrc)) {
+  std::string eeName;
+  if (!getNameOfEe(ee_handle, eeName)) {
     return;
   }
 
-  ScopedLocalRef<jobject> srcJavaString(e, e->NewStringUTF(evtSrc.c_str()));
-  CHECK(srcJavaString.get());
+  ScopedLocalRef<jobject> eeNameJavaString(e, e->NewStringUTF(eeName.c_str()));
+  CHECK(eeNameJavaString.get());
   e->CallVoidMethod(mNativeData->manager,
                     android::gCachedNfcManagerNotifyEeTechSelected, tech,
-                    srcJavaString.get());
+                    eeNameJavaString.get());
 }
 
 /*******************************************************************************
@@ -940,7 +954,7 @@ void RoutingManager::updateDefaultRoute() {
   static const char fn[] = "RoutingManager::updateDefaultRoute";
   int defaultAidRoute = mDefaultEe;
 
-  if (NFC_GetNCIVersion() != NCI_VERSION_2_0) return;
+  if (NFC_GetNCIVersion() < NCI_VERSION_2_0) return;
 
   LOG(DEBUG) << StringPrintf("%s:  Default SC route=0x%x", fn,
                              mDefaultSysCodeRoute);
@@ -1004,7 +1018,7 @@ tNFA_TECHNOLOGY_MASK RoutingManager::updateTechnologyABFRoute(int route,
   static const char fn[] = "RoutingManager::updateTechnologyABFRoute";
   LOG(DEBUG) << StringPrintf("%s:  New default A/B route=0x%x", fn, route);
   LOG(DEBUG) << StringPrintf("%s:  New default F route=0x%x", fn, felicaRoute);
-  mEeInfoChanged = true;
+  setEeTechRouteUpdateRequired();
   mDefaultFelicaRoute = felicaRoute;
   mDefaultOffHostRoute = route;
   return mSeTechMask;
@@ -1371,6 +1385,7 @@ int RoutingManager::registerT3tIdentifier(uint8_t* t3tId, uint8_t t3tIdLen) {
     if (nfaStat == NFA_STATUS_OK) {
       mRoutingEvent.wait();
     }
+    setEeTechRouteUpdateRequired();
     if ((nfaStat != NFA_STATUS_OK) || (mCbEventData.status != NFA_STATUS_OK)) {
       LOG(ERROR) << StringPrintf("%s: Fail to register system code on DH", fn);
       return NFA_HANDLE_INVALID;
@@ -1429,6 +1444,7 @@ void RoutingManager::deregisterT3tIdentifier(int handle) {
           LOG(ERROR) << StringPrintf("%s: Fail to deregister system Code on DH",
                                      fn);
         }
+        setEeTechRouteUpdateRequired();
       }
     }
   }
@@ -1554,6 +1570,7 @@ void RoutingManager::clearRoutingEntry(int clearFlags) {
     RoutingManager::getInstance().removeAidRouting((uint8_t*)NFA_REMOVE_ALL_AID,
                                                    NFA_REMOVE_ALL_AID_LEN);
     mDefaultAidRouteAdded = false;
+    setEeTechRouteUpdateRequired();
   }
 
   if (clearFlags & CLEAR_PROTOCOL_ENTRIES) {
@@ -1624,6 +1641,19 @@ void RoutingManager::setEeInfoChangedFlag() {
   sEeInfoChangedMutex.unlock();
 }
 
+/*******************************************************************************
+**
+** Function:        isRTUpdateOptimized
+**
+** Description:     Checking if routing table update optimized or not.
+**
+** Returns:         True/False
+**
+*******************************************************************************/
+bool RoutingManager::isRTUpdateOptimized() {
+  return mIsRTUpdateOptimized;
+}
+
 /*******************************************************************************
 **
 ** Function:        registerJniFunctions
diff --git a/NfcNci/nci/jni/RoutingManager.h b/NfcNci/nci/jni/RoutingManager.h
index d72351ed7..5a6e0f408 100755
--- a/NfcNci/nci/jni/RoutingManager.h
+++ b/NfcNci/nci/jni/RoutingManager.h
@@ -55,6 +55,7 @@ class RoutingManager {
   void notifyEeTechSelected(uint8_t tech, tNFA_HANDLE ee_handle);
   bool getNameOfEe(tNFA_HANDLE ee_handle, std::string& eeName);
   void setEeInfoChangedFlag();
+  bool isRTUpdateOptimized();
 
   static const int CLEAR_AID_ENTRIES = 0x01;
   static const int CLEAR_PROTOCOL_ENTRIES = 0x02;
@@ -137,6 +138,7 @@ class RoutingManager {
   bool mReceivedEeInfo;
   bool mAidRoutingConfigured;
   bool mIsRFDiscoveryOptimized;
+  bool mIsRTUpdateOptimized;
   tNFA_EE_CBACK_DATA mCbEventData;
   tNFA_EE_DISCOVER_REQ mEeInfo;
   tNFA_TECHNOLOGY_MASK mSeTechMask;
diff --git a/NfcNci/nci/src/com/android/nfc/dhimpl/NativeNfcManager.java b/NfcNci/nci/src/com/android/nfc/dhimpl/NativeNfcManager.java
index ff2591043..8a4595bdc 100644
--- a/NfcNci/nci/src/com/android/nfc/dhimpl/NativeNfcManager.java
+++ b/NfcNci/nci/src/com/android/nfc/dhimpl/NativeNfcManager.java
@@ -163,6 +163,11 @@ public class NativeNfcManager implements DeviceHost {
         doFactoryReset();
     }
 
+    @Override
+    public boolean isPowerSavingModeSupported() {
+        return mProprietaryCaps.isPowerSavingModeSupported();
+    }
+
     private native boolean doSetPowerSavingMode(boolean flag);
 
     @Override
@@ -338,6 +343,11 @@ public class NativeNfcManager implements DeviceHost {
     @Override
     public void clearT3tIdentifiersCache() {
         synchronized (mLock) {
+            Iterator<Integer> it = mT3tIdentifiers.keySet().iterator();
+            while (it.hasNext()) {
+                int handle = it.next().intValue();
+                doDeregisterT3tIdentifier(handle);
+            }
             mT3tIdentifiers.clear();
         }
     }
@@ -439,6 +449,7 @@ public class NativeNfcManager implements DeviceHost {
 
     @Override
     public void dump(PrintWriter pw, FileDescriptor fd) {
+        pw.println("Firmware version=" + NfcProperties.fw_version().orElse("<Unknown>"));
         pw.println("Native Proprietary Caps=" + mProprietaryCaps);
         doDump(fd);
     }
@@ -528,25 +539,25 @@ public class NativeNfcManager implements DeviceHost {
         mListener.onHwErrorReported();
     }
 
-    private void notifyEeAidSelected(byte[] aid, String eventSrc) {
+    private void notifyEeAidSelected(byte[] aid, String eeName) {
         Log.i(TAG, "notifyEeAidSelected: AID= " + HexFormat.of().formatHex(aid) + " selected by "
-                + eventSrc);
+                + eeName);
         if (com.android.nfc.flags.Flags.eeAidSelect()) {
-            mListener.onSeSelected(NfcService.SE_SELECTED_AID);
+            mListener.onSeSelected(NfcService.SE_SELECTED_AID, aid, eeName);
         }
     }
 
-    private void notifyEeProtocolSelected(int protocol, String eventSrc) {
-        Log.i(TAG, "notifyEeProtocolSelected: Protocol: " + protocol + " selected by " + eventSrc);
+    private void notifyEeProtocolSelected(int protocol, String eeName) {
+        Log.i(TAG, "notifyEeProtocolSelected: Protocol: " + protocol + " selected by " + eeName);
         if (com.android.nfc.flags.Flags.eeAidSelect()) {
-            mListener.onSeSelected(NfcService.SE_SELECTED_PROTOCOL);
+            mListener.onSeSelected(NfcService.SE_SELECTED_PROTOCOL, null, eeName);
         }
     }
 
-    private void notifyEeTechSelected(int tech, String eventSrc) {
-        Log.i(TAG, "notifyEeTechSelected: Tech: " + tech + " selected by " + eventSrc);
+    private void notifyEeTechSelected(int tech, String eeName) {
+        Log.i(TAG, "notifyEeTechSelected: Tech: " + tech + " selected by " + eeName);
         if (com.android.nfc.flags.Flags.eeAidSelect()) {
-            mListener.onSeSelected(NfcService.SE_SELECTED_TECH);
+            mListener.onSeSelected(NfcService.SE_SELECTED_TECH, null, eeName);
         }
     }
 
diff --git a/NfcNci/nci/src/com/android/nfc/dhimpl/NativeNfcTag.java b/NfcNci/nci/src/com/android/nfc/dhimpl/NativeNfcTag.java
index 30d47d1e3..6dce6b78d 100755
--- a/NfcNci/nci/src/com/android/nfc/dhimpl/NativeNfcTag.java
+++ b/NfcNci/nci/src/com/android/nfc/dhimpl/NativeNfcTag.java
@@ -69,6 +69,7 @@ public class NativeNfcTag implements TagEndpoint {
 
     private boolean mIsPresent; // Whether the tag is known to be still present
 
+    private boolean mIsShutdown;
     private PresenceCheckWatchdog mWatchdog;
 
     private boolean mIsRemovalDetectionModeReq = false;
@@ -149,12 +150,17 @@ public class NativeNfcTag implements TagEndpoint {
             if (!isRemovalDetectionModeRequested()) {
                 // Restart the polling loop
                 Log.d(TAG, "Tag lost, restarting polling loop");
-                doDisconnect();
+                if (!mIsShutdown) {
+                    doDisconnect();
+                }
             }
-            if (tagDisconnectedCallback != null) {
-                tagDisconnectedCallback.onTagDisconnected();
+            if (!mIsShutdown) {
+                if (tagDisconnectedCallback != null) {
+                    tagDisconnectedCallback.onTagDisconnected();
+                }
             }
-            if (DBG) Log.d(TAG, "Stopping background presence check");
+            if (DBG)
+                Log.d(TAG, "Stopping background presence check");
         }
     }
 
@@ -254,7 +260,8 @@ public class NativeNfcTag implements TagEndpoint {
     }
 
     @Override
-    public synchronized void stopPresenceChecking() {
+    public synchronized void stopPresenceChecking(boolean isShutdown) {
+        mIsShutdown = isShutdown;
         mIsPresent = false;
         if (mWatchdog != null) {
             mWatchdog.end(true);
@@ -267,6 +274,7 @@ public class NativeNfcTag implements TagEndpoint {
         // Once we start presence checking, we allow the upper layers
         // to know the tag is in the field.
         mIsPresent = true;
+        mIsShutdown = false;
         if (mWatchdog == null) {
             mWatchdog = new PresenceCheckWatchdog(presenceCheckDelay, callback);
             mWatchdog.start();
diff --git a/NfcNci/res/values-fa/strings.xml b/NfcNci/res/values-fa/strings.xml
index 43ecb4356..a9d3d52cb 100644
--- a/NfcNci/res/values-fa/strings.xml
+++ b/NfcNci/res/values-fa/strings.xml
@@ -39,7 +39,7 @@
     <string name="ask_nfc_tap" msgid="7921925213499063051">"برای تکمیل، روی دستگاه دیگری تک‌ضرب بزنید"</string>
     <string name="wifi_connect" msgid="2726973850576310336">"اتصال"</string>
     <string name="status_unable_to_connect" msgid="3282224066213036023">"اتصال به شبکه ممکن نیست"</string>
-    <string name="status_wifi_connected" msgid="8878112079913521399">"وصل شد"</string>
+    <string name="status_wifi_connected" msgid="8878112079913521399">"متصل شد"</string>
     <string name="title_connect_to_network" msgid="5617055452888255705">"اتصال به شبکه"</string>
     <string name="prompt_connect_to_network" msgid="6954936151128422990">"به شبکه <xliff:g id="NETWORK_SSID">%1$s</xliff:g> متصل می‌شوید؟"</string>
     <string name="beam_requires_nfc_enabled" msgid="1943159298389147033">"‏Android Beam برای فعال شدن به NFC نیاز دارد. می‌خواهید آن را فعال کنید؟"</string>
diff --git a/NfcNci/res/values-ml/strings.xml b/NfcNci/res/values-ml/strings.xml
index 54c764166..8c8d3eb40 100644
--- a/NfcNci/res/values-ml/strings.xml
+++ b/NfcNci/res/values-ml/strings.xml
@@ -24,7 +24,7 @@
     <string name="pairing_peripheral" msgid="5319926791325775305">"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>, ജോടിയാക്കുന്നു"</string>
     <string name="pairing_peripheral_failed" msgid="5905500974914016272">"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>, ജോടിയാക്കാനായില്ല"</string>
     <string name="failed_to_enable_bt" msgid="5978409523818027926">"ബ്ലൂടൂത്ത് പ്രവർത്തനക്ഷമമാക്കാനായില്ല"</string>
-    <string name="confirm_pairing" msgid="6587809107551647782">"നിങ്ങൾക്ക് <xliff:g id="DEVICE_NAME">%1$s</xliff:g> എന്ന Bluetooth ഉപകരണം ജോടിയാക്കണമെന്ന് തീർച്ചയാണോ?"</string>
+    <string name="confirm_pairing" msgid="6587809107551647782">"നിങ്ങൾക്ക് <xliff:g id="DEVICE_NAME">%1$s</xliff:g> എന്ന ബ്ലൂടൂത്ത് ഉപകരണം ജോടിയാക്കണമെന്ന് തീർച്ചയാണോ?"</string>
     <string name="pair_yes" msgid="3624986519335168604">"വേണം"</string>
     <string name="pair_no" msgid="1333098406083837138">"വേണ്ട"</string>
     <string name="tap_again_to_pay" msgid="4338572813931564301">"<xliff:g id="APP">%1$s</xliff:g> എന്നതുപയോഗിച്ച് പണമടയ്‌ക്കുന്നതിന് വീണ്ടും ടാപ്പുചെയ്യുക"</string>
diff --git a/NfcNci/res/values-ne/strings.xml b/NfcNci/res/values-ne/strings.xml
index 7965e8ff5..0bf461f51 100644
--- a/NfcNci/res/values-ne/strings.xml
+++ b/NfcNci/res/values-ne/strings.xml
@@ -29,7 +29,7 @@
     <string name="pair_no" msgid="1333098406083837138">"होइन"</string>
     <string name="tap_again_to_pay" msgid="4338572813931564301">"<xliff:g id="APP">%1$s</xliff:g>सँग तिर्न फेरी छुनुहोस्"</string>
     <string name="tap_again_to_complete" msgid="6649361012821973200">"<xliff:g id="APP">%1$s</xliff:g> सँग समाप्त गर्न फेरी छुनुहोस्"</string>
-    <string name="tap_again_description" msgid="7062073825398109427">"रिडर नजिकै लग्नुहोस्"</string>
+    <string name="tap_again_description" msgid="7062073825398109427">"रिडर नजिकै लैजानुहोस्"</string>
     <string name="appchooser_description" msgid="4568068957993132082">"स्क्यान गर्नु पर्ने एप छनौट गर्नुहोस्"</string>
     <string name="transaction_failure" msgid="6933419514549792555">"यस transaction <xliff:g id="APP">%1$s</xliff:g> सगँ सम्पन्न गर्न सकिन्न।"</string>
     <string name="could_not_use_app" msgid="2945389413330489607">"<xliff:g id="APP">%1$s</xliff:g> प्रयोग गर्न सकेन।"</string>
diff --git a/NfcNci/res/values-sw360dp/styles.xml b/NfcNci/res/values-sw360dp/styles.xml
new file mode 100755
index 000000000..82305e054
--- /dev/null
+++ b/NfcNci/res/values-sw360dp/styles.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="utf-8"?>
+<resources>
+    <style name="DialogAlertDayNight" parent="@android:style/Theme.DeviceDefault.Light.Dialog">
+        <item name="android:windowMinWidthMajor">50%</item>
+        <item name="android:windowMinWidthMinor">50%</item>
+    </style>
+</resources>
\ No newline at end of file
diff --git a/NfcNci/res/values-te/strings.xml b/NfcNci/res/values-te/strings.xml
index b521b18c3..45d15fbcb 100644
--- a/NfcNci/res/values-te/strings.xml
+++ b/NfcNci/res/values-te/strings.xml
@@ -12,10 +12,10 @@
     <string name="beam_canceled" msgid="512339558899479458">"Beam రద్దు చేయబడింది"</string>
     <string name="cancel" msgid="2441041247172250936">"రద్దు చేయండి"</string>
     <string name="beam_tap_to_view" msgid="9147455481297418801">"చూడటానికి నొక్కండి"</string>
-    <string name="beam_handover_not_supported" msgid="3930703977696510905">"స్వీకర్త పరికరం Beam ద్వారా పెద్ద ఫైల్ బదిలీకి మద్దతు ఇవ్వదు."</string>
+    <string name="beam_handover_not_supported" msgid="3930703977696510905">"స్వీకర్త డివైజ్ Beam ద్వారా పెద్ద ఫైల్ బదిలీకి మద్దతు ఇవ్వదు."</string>
     <string name="beam_try_again" msgid="1962556612448345422">"పరికరాలను మళ్లీ సమీపంలోకి తీసుకురండి"</string>
     <string name="beam_busy" msgid="8179024484757185047">"Beam ప్రస్తుతం బిజీగా ఉంది. మునుపటి బదిలీ పూర్తయిన తర్వాత మళ్లీ ట్రై చేయండి."</string>
-    <string name="device" msgid="6859793408635712424">"పరికరం"</string>
+    <string name="device" msgid="6859793408635712424">"డివైజ్"</string>
     <string name="connecting_peripheral" msgid="5023158537894294802">"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>ని కనెక్ట్ చేస్తోంది"</string>
     <string name="connected_peripheral" msgid="2496731052957541047">"<xliff:g id="DEVICE_NAME">%1$s</xliff:g> కనెక్ట్ చేయబడింది"</string>
     <string name="connect_peripheral_failed" msgid="368937385551413385">"<xliff:g id="DEVICE_NAME">%1$s</xliff:g>ని కనెక్ట్ చేయడం సాధ్యపడలేదు"</string>
diff --git a/NfcNci/res/values/config.xml b/NfcNci/res/values/config.xml
index 00394b8fd..4d2a3decb 100644
--- a/NfcNci/res/values/config.xml
+++ b/NfcNci/res/values/config.xml
@@ -73,4 +73,6 @@
     <integer name="slow_tap_threshold_millis">2000</integer>
     <!-- Disable CE services for CATEGORY_OTHER from managed profiles by default -->
     <bool name="ce_disable_other_services_on_managed_profiles">false</bool>
+    <!-- Timeout for CE field on wake lock. Set to 0 to disable the CE wake lock. -->
+    <integer name="ce_wake_lock_timeout_millis">1000</integer>
 </resources>
diff --git a/NfcNci/res/values/overlayable.xml b/NfcNci/res/values/overlayable.xml
index 44f4cb2e0..cdeb5f675 100644
--- a/NfcNci/res/values/overlayable.xml
+++ b/NfcNci/res/values/overlayable.xml
@@ -71,12 +71,16 @@
             <item name="removal_detection_waiting_time" type="integer" />
             <item name="inactive_presence_check_allowed_time" type="integer" />
             <item name="ce_disable_other_services_on_managed_profiles" type="bool" />
+            <item name="ce_wake_lock_timeout_millis" type="integer" />
           <!-- Params from config.xml that can be overlaid -->
 
           <!-- Params from strings.xml that can be overlaid -->
           <!-- Params from strings.xml that can be overlaid -->
 
           <!-- Params from styles.xml that can be overlaid -->
+          <item type="style" name="DialogAlertDayNight"/>
+          <item type="style" name="TapAgainDayNight"/>
+          <item type="style" name="BottomSheetDialogStyle"/>
           <!-- Params from styles.xml that can be overlaid -->
 
           <!-- Params from drawable/ that can be overlaid -->
diff --git a/NfcNci/src/com/android/nfc/DeviceConfigFacade.java b/NfcNci/src/com/android/nfc/DeviceConfigFacade.java
index c58255109..afcd1b60b 100644
--- a/NfcNci/src/com/android/nfc/DeviceConfigFacade.java
+++ b/NfcNci/src/com/android/nfc/DeviceConfigFacade.java
@@ -68,6 +68,7 @@ public class DeviceConfigFacade {
     private int mUnknownTagPollingDelayMax;
     private int mUnknownTagPollingDelayLong;
     private boolean mCeDisableOtherServicesOnManagedProfiles;
+    private int mCeWakeLockTimeoutMillis;
 
     private static DeviceConfigFacade sInstance;
     public static DeviceConfigFacade getInstance(Context context, Handler handler) {
@@ -189,6 +190,9 @@ public class DeviceConfigFacade {
         mCeDisableOtherServicesOnManagedProfiles = DeviceConfig.getBoolean(DeviceConfig.NAMESPACE_NFC,
                 "ce_disable_other_services_on_managed_profiles",
                 mContext.getResources().getBoolean(R.bool.ce_disable_other_services_on_managed_profiles));
+        mCeWakeLockTimeoutMillis = DeviceConfig.getInt(DEVICE_CONFIG_NAMESPACE_NFC,
+                "ce_wake_lock_timeout_millis",
+                mContext.getResources().getInteger(R.integer.ce_wake_lock_timeout_millis));
     }
 
     private boolean isSecureNfcCapableDefault() {
@@ -259,4 +263,8 @@ public class DeviceConfigFacade {
     public boolean getCeDisableOtherServicesOnManagedProfiles() {
         return mCeDisableOtherServicesOnManagedProfiles;
     }
+
+    public int getCeWakeLockTimeoutMillis() {
+        return mCeWakeLockTimeoutMillis;
+    }
 }
diff --git a/NfcNci/src/com/android/nfc/DeviceHost.java b/NfcNci/src/com/android/nfc/DeviceHost.java
index 815bd9012..0b9816d65 100644
--- a/NfcNci/src/com/android/nfc/DeviceHost.java
+++ b/NfcNci/src/com/android/nfc/DeviceHost.java
@@ -16,6 +16,7 @@
 
 package com.android.nfc;
 
+import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.nfc.NdefMessage;
 import android.nfc.cardemulation.PollingFrame;
@@ -64,7 +65,7 @@ public interface DeviceHost {
 
         public void onEeListenActivated(boolean isActivated);
 
-        public void onSeSelected(int type);
+        public void onSeSelected(int type, @Nullable byte[] aid, @NonNull String eeName);
 
         public void onCommandTimeout();
 
@@ -85,7 +86,7 @@ public interface DeviceHost {
         boolean isPresent();
         void startPresenceChecking(int presenceCheckDelay,
                                    @Nullable TagDisconnectedCallback callback);
-        void stopPresenceChecking();
+        void stopPresenceChecking(boolean isShutdown);
         boolean isPresenceCheckStopped();
         void prepareForRemovalDetectionMode();
 
@@ -306,6 +307,8 @@ public interface DeviceHost {
     */
     void setNfceePowerAndLinkCtrl(boolean enable);
 
+    boolean isPowerSavingModeSupported();
+
     /**
      * Enable or Disable the Power Saving Mode based on flag
      */
diff --git a/NfcNci/src/com/android/nfc/ForegroundUtils.java b/NfcNci/src/com/android/nfc/ForegroundUtils.java
index ea650a7a8..5fb9ed29d 100644
--- a/NfcNci/src/com/android/nfc/ForegroundUtils.java
+++ b/NfcNci/src/com/android/nfc/ForegroundUtils.java
@@ -27,7 +27,7 @@ import java.util.ArrayList;
 import java.util.List;
 
 public class ForegroundUtils implements ActivityManager.OnUidImportanceListener {
-    static final boolean VDBG = false;
+    static final boolean VDBG = NfcProperties.verbose_debug_enabled().orElse(true);
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
     private final String TAG = "ForegroundUtils";
     private final ActivityManager mActivityManager;
diff --git a/NfcNci/src/com/android/nfc/NfcEnableAllowlistActivity.java b/NfcNci/src/com/android/nfc/NfcEnableAllowlistActivity.java
index c05da4765..67e37b3c7 100644
--- a/NfcNci/src/com/android/nfc/NfcEnableAllowlistActivity.java
+++ b/NfcNci/src/com/android/nfc/NfcEnableAllowlistActivity.java
@@ -53,6 +53,7 @@ public class NfcEnableAllowlistActivity extends Activity implements View.OnClick
                     Log.i(TAG, "Nfc is disallowed by user for app: " + appName);
                     finish();
                 });
+        mAlertDialog.setOnCancelListener(dialog -> finish());
     }
 
     @Override
diff --git a/NfcNci/src/com/android/nfc/NfcInjector.java b/NfcNci/src/com/android/nfc/NfcInjector.java
index ab8f2e185..e94613840 100644
--- a/NfcNci/src/com/android/nfc/NfcInjector.java
+++ b/NfcNci/src/com/android/nfc/NfcInjector.java
@@ -374,4 +374,11 @@ public class NfcInjector {
         return mContext.getPackageManager().checkSignatures(uid, Process.SYSTEM_UID)
                 == PackageManager.SIGNATURE_MATCH;
     }
+
+    /** Creates a looper to handle broadcasts within the {@link NfcService}. */
+    public Looper getNfcBroadcastLooper() {
+        HandlerThread handlerThread = new HandlerThread("NfcBroadcastThread");
+        handlerThread.start();
+        return handlerThread.getLooper();
+    }
 }
diff --git a/NfcNci/src/com/android/nfc/NfcService.java b/NfcNci/src/com/android/nfc/NfcService.java
index 880008b27..3777154df 100644
--- a/NfcNci/src/com/android/nfc/NfcService.java
+++ b/NfcNci/src/com/android/nfc/NfcService.java
@@ -17,6 +17,8 @@
 package com.android.nfc;
 
 import static android.Manifest.permission.BIND_NFC_SERVICE;
+import static android.content.Intent.ACTION_BOOT_COMPLETED;
+import static android.content.Intent.ACTION_LOCKED_BOOT_COMPLETED;
 import static android.nfc.OemLogItems.EVENT_DISABLE;
 import static android.nfc.OemLogItems.EVENT_ENABLE;
 
@@ -114,15 +116,17 @@ import android.se.omapi.ISecureElementService;
 import android.sysprop.NfcProperties;
 import android.util.EventLog;
 import android.util.Log;
+import android.util.Pair;
 import android.util.proto.ProtoOutputStream;
-import android.view.Display;
 import android.widget.Toast;
 
 import androidx.annotation.VisibleForTesting;
 
+import com.android.internal.annotations.GuardedBy;
 import com.android.nfc.DeviceHost.DeviceHostListener;
 import com.android.nfc.DeviceHost.TagEndpoint;
 import com.android.nfc.cardemulation.CardEmulationManager;
+import com.android.nfc.cardemulation.RoutingOptionManager;
 import com.android.nfc.cardemulation.util.StatsdUtils;
 import com.android.nfc.dhimpl.NativeNfcManager;
 import com.android.nfc.flags.FeatureFlags;
@@ -144,6 +148,7 @@ import java.io.PrintWriter;
 import java.io.StringWriter;
 import java.io.UnsupportedEncodingException;
 import java.nio.ByteBuffer;
+import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.security.SecureRandom;
 import java.time.Instant;
@@ -174,7 +179,7 @@ import java.util.stream.Collectors;
 
 public class NfcService implements DeviceHostListener, ForegroundUtils.Callback {
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
-    private static final boolean VDBG = false; // turn on for local testing.
+    static final boolean VDBG = NfcProperties.verbose_debug_enabled().orElse(true);
     static final String TAG = "NfcService";
     private static final int APP_INFO_FLAGS_SYSTEM_APP =
             ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP;
@@ -349,7 +354,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
     public static final int WAIT_FOR_OEM_CALLBACK_TIMEOUT_MS = 3000;
 
-    public static final int WAIT_FOR_COMMIT_ROUTING_TIMEOUT_MS = 10000;
+    public static final int WAIT_FOR_COMMIT_ROUTING_TIMEOUT_MS = 3_000;
 
     private static final long TIME_TO_MONITOR_AFTER_FIELD_ON_MS = 10000L;
 
@@ -435,7 +440,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     // and the default AsyncTask thread so it is read unprotected from that thread
     int mAlwaysOnState;  // one of NfcAdapter.STATE_ON, STATE_TURNING_ON, etc
     int mAlwaysOnMode; // one of NfcOemExtension.ENABLE_DEFAULT, ENABLE_TRANSPARENT, etc
-    private boolean mIsPowerSavingModeEnabled = false;
+    private final Object mPowerSavingModeLock = new Object();
+    @GuardedBy("mPowerSavingModeLock")
+    private @NfcAdapter.AdapterState int mPowerSavingState = NfcAdapter.STATE_OFF;
 
     // fields below are final after onCreate()
     boolean mIsReaderOptionEnabled = true;
@@ -468,13 +475,13 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     boolean mIsRequestUnlockShowed;
     boolean mIsRecovering;
     boolean mIsNfcUserRestricted;
-    boolean mIsNfcUserChangeRestricted;
     boolean mIsWatchType;
     boolean mPendingPowerStateUpdate;
     boolean mIsWlcCapable;
     boolean mIsWlcEnabled;
     boolean mIsRWCapable;
     boolean mIsRDCapable;
+    boolean mIsEuiccCapable;
     WlcListenerDeviceInfo mWlcListenerDeviceInfo;
     public NfcDiagnostics  mNfcDiagnostics;
 
@@ -489,6 +496,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     private int mReadErrorCount;
     private int mReadErrorCountMax;
     private boolean mPollDelayed;
+    private Handler mNfcBroadcastHandler;
 
     boolean mNotifyDispatchFailed;
     boolean mNotifyReadFailed;
@@ -541,8 +549,6 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     private  INfcVendorNciCallback mNfcVendorNciCallBack = null;
     private  INfcOemExtensionCallback mNfcOemExtensionCallback = null;
 
-    private CountDownLatch mCommitRoutingCountDownLatch = null;
-    private int mCommitRoutingStatus;
     private final DisplayListener mDisplayListener = new DisplayListener() {
         @Override
         public void onDisplayAdded(int displayId) {
@@ -554,9 +560,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
         @Override
         public void onDisplayChanged(int displayId) {
-            if (displayId == Display.DEFAULT_DISPLAY) {
-                handleScreenStateChanged();
-            }
+            handleScreenStateChanged();
         }
     };
 
@@ -907,8 +911,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     }
 
     @Override
-    public void onSeSelected(int type) {
-        sendMessage(MSG_SE_SELECTED_EVENT, type);
+    public void onSeSelected(int type, @Nullable byte[] aid, @NonNull String eeName) {
+        sendMessage(MSG_SE_SELECTED_EVENT, type, Pair.create(aid, eeName));
     }
 
     @Override
@@ -919,31 +923,48 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     /**
      * Enable or Disable PowerSaving Mode based on flag
      */
-    private boolean setPowerSavingMode(boolean flag) {
-        synchronized (NfcService.this) {
-            if ((flag && mState != NfcAdapter.STATE_ON)
-                    || (!flag && mState != NfcAdapter.STATE_OFF)) {
-                Log.d(TAG,
-                        "setPowerSavingMode: Enable Power Saving Mode is allowed in "
-                                + "Nfc On state or "
-                                + "Disable PowerSaving is allowed only if it is enabled");
-                return false;
+    private void setPowerSavingModeInternal(boolean enable) {
+        synchronized (mPowerSavingModeLock) {
+            if (!mDeviceHost.isPowerSavingModeSupported()) {
+                throw new UnsupportedOperationException(
+                        "Device does not support power saving mode");
             }
-        }
 
-        Log.d(TAG, "setPowerSavingMode: " + flag);
-        if (flag) {
-            if (mDeviceHost.setPowerSavingMode(flag)) {
-                mIsPowerSavingModeEnabled = true;
-                new EnableDisableTask().execute(TASK_DISABLE);
-                return true;
+            if (enable && isPowerSavingModeEnabled()) return;
+            if (!enable && !isPowerSavingModeEnabled()) return;
+
+            @NfcAdapter.AdapterState int oldState = mPowerSavingState;
+            mPowerSavingState = enable
+                    ? NfcAdapter.STATE_TURNING_ON
+                    : NfcAdapter.STATE_TURNING_OFF;
+            mDeviceHost.setPowerSavingMode(enable);
+
+            if (mState == NfcAdapter.STATE_OFF) {
+                EnableDisableTask chip = new EnableDisableTask();
+                if (!chip.enableInternal()) {
+                    mPowerSavingState = oldState;
+                    throw new IllegalStateException(
+                            "Failed to temporarily enable chip for power saving mode update");
+                }
+                chip.disableInternal();
             }
-        } else {
-            new EnableDisableTask().execute(TASK_ENABLE);
-            return true;
+
+            mPowerSavingState = enable ? NfcAdapter.STATE_ON : NfcAdapter.STATE_OFF;
+        }
+    }
+
+    boolean isPowerSavingModeEnabled() {
+        synchronized (mPowerSavingModeLock) {
+            return mPowerSavingState == NfcAdapter.STATE_ON
+                    || mPowerSavingState == NfcAdapter.STATE_TURNING_ON;
+        }
+    }
+
+    boolean isPowerSavingModeChanging() {
+        synchronized (mPowerSavingModeLock) {
+            return mPowerSavingState == NfcAdapter.STATE_TURNING_ON
+                    || mPowerSavingState == NfcAdapter.STATE_TURNING_OFF;
         }
-        Log.d(TAG, "PowerSavingMode: failed");
-        return false;
     }
 
     public void onWlcData(Map<String, Integer> WlcDeviceInfo) {
@@ -1030,7 +1051,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
     int getNfcPollTech() {
         synchronized (NfcService.this) {
-            return mPrefs.getInt(PREF_POLL_TECH, DEFAULT_POLL_TECH);
+            return isReaderOptionEnabled()
+                    ? mPrefs.getInt(PREF_POLL_TECH, DEFAULT_POLL_TECH) : 0x00;
         }
     }
 
@@ -1110,8 +1132,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         filter.addAction(Intent.ACTION_USER_PRESENT);
         filter.addAction(Intent.ACTION_USER_SWITCHED);
         filter.addAction(Intent.ACTION_USER_ADDED);
-        filter.addAction(Intent.ACTION_BOOT_COMPLETED);
-        if (mFeatureFlags.enableDirectBootAware()) filter.addAction(Intent.ACTION_USER_UNLOCKED);
+        filter.addAction(ACTION_BOOT_COMPLETED);
+        filter.addAction(ACTION_LOCKED_BOOT_COMPLETED);
+        filter.addAction(Intent.ACTION_USER_UNLOCKED);
         mContext.registerReceiverForAllUsers(mReceiver, filter, null, null);
     }
 
@@ -1237,6 +1260,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         if (mIsHceCapable) {
             mCardEmulationManager = mNfcInjector.getCardEmulationManager();
         }
+        mIsEuiccCapable = mContext.getResources().getBoolean(R.bool.enable_euicc_support)
+                && NfcInjector.NfcProperties.isEuiccSupported();
         mForegroundUtils = mNfcInjector.getForegroundUtils();
         mIsSecureNfcCapable = mDeviceConfigFacade.isSecureNfcCapable();
         mIsSecureNfcEnabled = mPrefs.getBoolean(PREF_SECURE_NFC_ON,
@@ -1250,6 +1275,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             sToast_debounce_time_ms = MAX_TOAST_DEBOUNCE_TIME;
         }
 
+        mNfcBroadcastHandler = new Handler(mNfcInjector.getNfcBroadcastLooper());
+
         // Notification message variables
         mDispatchFailedCount = 0;
         if (mDeviceConfigFacade.isAntennaBlockedAlertEnabled() &&
@@ -1324,12 +1351,10 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
 
         mIsNfcUserRestricted = isNfcUserRestricted();
-        mIsNfcUserChangeRestricted = isNfcUserChangeRestricted();
         mContext.registerReceiver(
                 new BroadcastReceiver() {
                     @Override
                     public void onReceive(Context context, Intent intent) {
-                        mIsNfcUserChangeRestricted = isNfcUserChangeRestricted();
                         if (mIsNfcUserRestricted == isNfcUserRestricted()) {
                             return;
                         }
@@ -1354,13 +1379,16 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
         mNfcPermissions = new NfcPermissions(mContext);
         mReaderOptionCapable = mDeviceConfigFacade.isReaderOptionCapable();
-
-        if (mReaderOptionCapable) {
-            mIsReaderOptionEnabled =
-                mPrefs.getBoolean(PREF_NFC_READER_OPTION_ON,
-                    mDeviceConfigFacade.getDefaultReaderOption() || mInProvisionMode);
+        if (mIsRWCapable) {
+            if (mReaderOptionCapable) {
+                mIsReaderOptionEnabled =
+                        mPrefs.getBoolean(PREF_NFC_READER_OPTION_ON,
+                                mDeviceConfigFacade.getDefaultReaderOption() || mInProvisionMode);
+            }
+        } else {
+            // Turn off reader option if the device does not support reader mode.
+            mIsReaderOptionEnabled = false;
         }
-
         executeTaskBoot();  // do blocking boot tasks
 
         if ((NFC_SNOOP_LOG_MODE.equals(NfcProperties.snoop_log_mode_values.FULL) ||
@@ -1818,6 +1846,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                         if (mIsRecovering) {
                             // Recovering needs the full init. Put default value
                             mAlwaysOnState = NfcAdapter.STATE_OFF;
+                            synchronized (mPowerSavingModeLock) {
+                                mPowerSavingState = NfcAdapter.STATE_OFF;
+                            }
                         }
                         if (!mDeviceHost.initialize()) {
                             Log.w(TAG, "enableInternal: Error enabling NFC");
@@ -1876,11 +1907,11 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                         && mAlwaysOnState != NfcAdapter.STATE_TURNING_OFF)) {
                 /* Start polling loop */
                 applyRouting(true);
-            }
 
-            if (mIsHceCapable) {
-                // Generate the initial card emulation routing table
-                mCardEmulationManager.onNfcEnabled();
+                if (mIsHceCapable) {
+                    // Generate the initial card emulation routing table
+                    mCardEmulationManager.onNfcEnabled();
+                }
             }
 
             if (mIsRecovering) {
@@ -1889,11 +1920,6 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 mIsRecovering = false;
             }
 
-            if (mIsPowerSavingModeEnabled) {
-                mDeviceHost.setPowerSavingMode(false);
-                mIsPowerSavingModeEnabled = false;
-            }
-
             if (DBG) Log.d(TAG, "EnableDisableTask.enableInternal: end");
             return true;
         }
@@ -2054,10 +2080,15 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     mCardEmulationManager.onNfcStateChanged(newState);
                 }
                 if (mState == NfcAdapter.STATE_ON && mCardEmulationManager != null) {
-                    mCardEmulationManager.updateForShouldDefaultToObserveMode(getUserId());
-                    mCardEmulationManager.updateFirmwareExitFramesForWalletRole(getUserId());
+                    // Update default observe mode and exit frames lazily to avoid blocking on
+                    // NfcService.this for a long duration.
+                    mHandler.post(() -> {
+                        Log.d(TAG, "Update default observe mode and exit frames after NFC enable");
+                        mCardEmulationManager.updateForShouldDefaultToObserveMode(getUserId());
+                        mCardEmulationManager.updateFirmwareExitFramesForWalletRole(getUserId());
+                    });
                 }
-                if (mAlwaysOnState != NfcAdapter.STATE_TURNING_ON) {
+                if (mAlwaysOnState != NfcAdapter.STATE_TURNING_ON && !isPowerSavingModeChanging()) {
                     Intent intent = new Intent(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED);
                     intent.setFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
                     intent.putExtra(NfcAdapter.EXTRA_ADAPTER_STATE, mState);
@@ -2113,7 +2144,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 listenTech = (NfcAdapter.FLAG_LISTEN_KEEP | NfcAdapter.FLAG_USE_ALL_TECH
                     | NfcAdapter.FLAG_SET_DEFAULT_TECH);
             }
-            mDeviceHost.setDiscoveryTech(NfcAdapter.FLAG_READER_KEEP, listenTech);
+            setDiscoveryTech(NfcAdapter.FLAG_READER_KEEP, listenTech);
         }
     }
 
@@ -2133,10 +2164,23 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         if (pollTech == -1 || pollTech == DEFAULT_POLL_TECH)
             pollTech = (NfcAdapter.FLAG_READER_KEEP|NfcAdapter.FLAG_USE_ALL_TECH);
 
-        mDeviceHost.setDiscoveryTech(pollTech|NfcAdapter.FLAG_SET_DEFAULT_TECH,
+        setDiscoveryTech(pollTech|NfcAdapter.FLAG_SET_DEFAULT_TECH,
                 listenTech|NfcAdapter.FLAG_SET_DEFAULT_TECH);
     }
 
+    private void setDiscoveryTech(int pollTech, int listenTech) {
+        if(mReaderModeParams != null) {
+            Log.d(TAG, "setDiscoveryTech mReaderModeParams.flags = 0x"
+                + Integer.toHexString(mReaderModeParams.flags));
+            mDeviceHost.setDiscoveryTech(
+                    mReaderModeParams.flags == DISABLE_POLLING_FLAGS
+                        ? NfcAdapter.FLAG_READER_DISABLE
+                        : mReaderModeParams.flags, listenTech);
+        } else {
+            mDeviceHost.setDiscoveryTech(pollTech, listenTech);
+        }
+    }
+
     public void playSound(int sound) {
         synchronized (this) {
             switch (sound) {
@@ -2168,7 +2212,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 Log.d(TAG, "resetReaderModeParams: Disabling reader mode because app died"
                         + " or moved to background");
                 mReaderModeParams = null;
-                StopPresenceChecking();
+                StopPresenceChecking(false);
                 // listenTech is different from the default value, the stored listenTech will be included.
                 // When using enableReaderMode, change listenTech to default & restore to the previous value.
                 if (isNfcEnabled()) {
@@ -2246,7 +2290,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 throw new SecurityException(
                         "caller is not a system app, device owner or profile owner!");
             }
-            if (!isDeviceOrProfileOwner && mIsNfcUserChangeRestricted) {
+            if (!isDeviceOrProfileOwner && isNfcUserChangeRestricted()) {
                 throw new SecurityException("Change nfc state by system app is not allowed!");
             }
 
@@ -2300,7 +2344,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 throw new SecurityException(
                         "caller is not a system app, device owner or profile owner!");
             }
-            if (!isDeviceOrProfileOwner && mIsNfcUserChangeRestricted) {
+            if (!isDeviceOrProfileOwner && isNfcUserChangeRestricted()) {
                 throw new SecurityException("Change nfc state by system app is not allowed!");
             }
 
@@ -2445,6 +2489,32 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             return roleHolders.isEmpty() ? null : roleHolders.get(0);
         }
 
+        @Override
+        public boolean isPowerSavingModeSupported() {
+            synchronized (NfcService.this) {
+                if (!isNfcEnabled()) {
+                    Log.e(TAG, "isPowerSavingModeSupported: NFC must be enabled but is: " + mState);
+                    return false;
+                }
+                NfcPermissions.enforceUserPermissions(mContext);
+                return mDeviceHost.isPowerSavingModeSupported();
+            }
+        }
+
+        @Override
+        public boolean isPowerSavingModeEnabled() {
+            synchronized (NfcService.this) {
+                return NfcService.this.isPowerSavingModeEnabled();
+            }
+        }
+
+        @Override
+        public void setPowerSavingMode(boolean enabled) {
+            synchronized (NfcService.this) {
+                NfcService.this.setPowerSavingModeInternal(enabled);
+            }
+        }
+
         @Override
         public int pausePolling(long timeoutInMs) {
             NfcPermissions.enforceAdminPermissions(mContext);
@@ -2743,7 +2813,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     listenTech = getNfcListenTech();
                 }
 
-                mDeviceHost.setDiscoveryTech(pollTech, listenTech);
+                setDiscoveryTech(pollTech, listenTech);
                 applyRouting(true);
                 return;
             }
@@ -2779,7 +2849,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                         listenTech = getNfcListenTech();
                     }
                     try {
-                        mDeviceHost.setDiscoveryTech(pollTech, listenTech);
+                        setDiscoveryTech(pollTech, listenTech);
                         mDiscoveryTechParams = new DiscoveryTechParams();
                         mDiscoveryTechParams.uid = callingUid;
                         mDiscoveryTechParams.binder = binder;
@@ -2825,7 +2895,10 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             // Allow non-foreground callers with system uid or systemui
             privilegedCaller |= packageName.equals(SYSTEM_UI);
             Log.d(TAG, "setReaderMode: uid=" + callingUid + ", packageName: "
-                    + packageName + ", flags: " + flags);
+                    + packageName + ", flags: " + flags + ", annotation: "
+                    + (extras != null
+                        ? extras.getString(NfcAdapter.EXTRA_READER_TECH_A_POLLING_LOOP_ANNOTATION)
+                        : "null"));
             if (!privilegedCaller
                     && !mForegroundUtils.registerUidToBackgroundCallback(
                             NfcService.this, callingUid)) {
@@ -2891,7 +2964,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
                         if (mPollingDisableDeathRecipients.size() == 0) {
                             mReaderModeParams = null;
-                            StopPresenceChecking();
+                            StopPresenceChecking(false);
                         }
 
                         if (pollingDisableDeathRecipient != null) {
@@ -3230,6 +3303,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 mPrefsEditor.apply();
                 mIsReaderOptionEnabled = enable;
                 mBackupManager.dataChanged();
+                if (isNfcEnabled()) {
+                    setDiscoveryTech(getNfcPollTech(), getNfcListenTech());
+                }
             }
             applyRouting(true);
             if (mNfcOemExtensionCallback != null) {
@@ -3379,7 +3455,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         public int sendVendorNciMessage(int mt, int gid, int oid, byte[] payload)
                 throws RemoteException {
             NfcPermissions.enforceAdminPermissions(mContext);
-            if ((!isNfcEnabled() && !mIsPowerSavingModeEnabled) && !isControllerAlwaysOn()) {
+            if (!isNfcEnabled() && !isControllerAlwaysOn()) {
                 Log.e(TAG, "sendVendorNciMessage: Nfc is not enabled");
                 return NCI_STATUS_FAILED;
             }
@@ -3387,15 +3463,21 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             FutureTask<Integer> sendVendorCmdTask = new FutureTask<>(
                 () -> { synchronized (NfcService.this) {
                         if (isPowerSavingModeCmd(gid, oid, payload)) {
-                            boolean status = setPowerSavingMode(payload[1] == 0x01);
-                            return status ? NCI_STATUS_OK : NCI_STATUS_FAILED;
+                            try {
+                                NfcService.this.setPowerSavingModeInternal(payload[1] == 0x01);
+                            } catch (Exception e) {
+                                Log.e(TAG, "Failed to set power saving mode " + e);
+                                return NCI_STATUS_FAILED;
+                            }
+                            return NCI_STATUS_OK;
                         } else if (isQueryPowerSavingStatusCmd(gid, oid, payload)) {
                             NfcVendorNciResponse response = new NfcVendorNciResponse(
                                     (byte) NCI_STATUS_OK, NCI_GID_PROP, NCI_MSG_PROP_ANDROID,
                                     new byte[] {
                                             (byte) NCI_PROP_ANDROID_QUERY_POWER_SAVING_STATUS_CMD,
                                             0x00,
-                                            mIsPowerSavingModeEnabled ? (byte) 0x01 : (byte) 0x00});
+                                            isPowerSavingModeEnabled() ? (byte) 0x01 : (byte) 0x00
+                                    });
                             if (response.status == NCI_STATUS_OK) {
                                 mHandler.post(() -> mNfcAdapter.sendVendorNciResponse(
                                         response.gid, response.oid, response.payload));
@@ -3452,7 +3534,10 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 throws RemoteException {
             if (DBG) Log.i(TAG, "registerOemExtensionCallback");
             NfcPermissions.enforceAdminPermissions(mContext);
-            mNfcOemExtensionCallback = callbacks;
+            synchronized (NfcService.this) {
+                mNfcOemExtensionCallback = callbacks;
+                mNfcOemExtensionCallback.asBinder().linkToDeath(mOemExtensionCbDeathRecipient, 0);
+            }
             updateNfCState();
             if (mCardEmulationManager != null) {
                 mCardEmulationManager.setOemExtension(mNfcOemExtensionCallback);
@@ -3467,7 +3552,11 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 throws RemoteException {
             if (DBG) Log.i(TAG, "unregisterOemExtensionCallback");
             NfcPermissions.enforceAdminPermissions(mContext);
-            mNfcOemExtensionCallback = null;
+            synchronized (NfcService.this) {
+                if (mNfcOemExtensionCallback == null) return;
+                mNfcOemExtensionCallback.asBinder().unlinkToDeath(mOemExtensionCbDeathRecipient, 0);
+                mNfcOemExtensionCallback = null;
+            }
             if (mCardEmulationManager != null) {
                 mCardEmulationManager.setOemExtension(mNfcOemExtensionCallback);
             }
@@ -3496,7 +3585,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                                 .build());
             }
             mPrefsEditor.clear();
-            if (mIsNfcUserChangeRestricted) {
+            if (isNfcUserChangeRestricted()) {
                 mPrefsEditor.putBoolean(PREF_NFC_ON, getNfcOnSetting());
             }
             mPrefsEditor.putBoolean(
@@ -3596,7 +3685,13 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             }
             if (DBG) Log.i(TAG, "commitRouting");
             NfcPermissions.enforceAdminPermissions(mContext);
-            return mDeviceHost.commitRouting();
+
+            @NfcOemExtension.StatusCode int status = mDeviceHost.commitRouting();
+            if (mCardEmulationManager.onRoutingChangeCompleted(status)) {
+                return status;
+            } else {
+                return NfcOemExtension.STATUS_UNKNOWN_ERROR;
+            }
         }
 
         @Override
@@ -3645,6 +3740,12 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
     }
 
+    private final IBinder.DeathRecipient mOemExtensionCbDeathRecipient = () -> {
+        synchronized (NfcService.this) {
+            Log.w(TAG, "binderDied: OEM extension died");
+            mNfcOemExtensionCallback = null;
+        }
+    };
 
     final class SeServiceDeathRecipient implements IBinder.DeathRecipient {
         @Override
@@ -4276,6 +4377,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             boolean status  = mDeviceHost.doClearNdefData();
             if (!isEnabled) {
                 mDeviceHost.deinitialize();
+                mDeviceHost.setPartialInitMode(NfcOemExtension.ENABLE_DEFAULT);
             }
             Log.i(TAG, "clearNdefData: " + status);
             return status
@@ -4314,7 +4416,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
     boolean isNfcEnabled() {
         synchronized (this) {
-            return mState == NfcAdapter.STATE_ON;
+            return mState == NfcAdapter.STATE_ON && !isPowerSavingModeEnabled();
         }
     }
 
@@ -4482,7 +4584,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             Log.d(TAG, "applyRouting");
         }
         synchronized (this) {
-            if (!isNfcEnabledOrShuttingDown()) {
+            if (isNfcDisabledOrDisabling()) {
                 return;
             }
             if (mNfcOemExtensionCallback != null
@@ -4491,7 +4593,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 return;
             }
             refreshTagDispatcherInProvisionMode();
-            if (mPollingPaused) {
+            if (mPollingPaused && !NfcInjector.isPrivileged(Binder.getCallingUid())) {
                 Log.d(TAG, "applyRouting: Not updating discovery parameters, polling paused");
                 return;
             }
@@ -4624,7 +4726,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
     }
 
-    private void StopPresenceChecking() {
+    private void StopPresenceChecking(boolean isShutdown) {
         Object[] objectValues = mObjectMap.values().toArray();
         if (!ArrayUtils.isEmpty(objectValues)) {
             // If there are some tags connected, we need to execute the callback to indicate
@@ -4633,8 +4735,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
         for (Object object : objectValues) {
             if (object instanceof TagEndpoint) {
-                TagEndpoint tag = (TagEndpoint)object;
-                ((TagEndpoint) object).stopPresenceChecking();
+                TagEndpoint tag = (TagEndpoint) object;
+                ((TagEndpoint) object).stopPresenceChecking(isShutdown);
             }
         }
     }
@@ -4774,23 +4876,12 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             mHandler.sendEmptyMessage(MSG_COMMIT_ROUTING);
             return STATUS_OK;
         }
-        mCommitRoutingCountDownLatch = new CountDownLatch(1);
-        mHandler.sendEmptyMessage(MSG_COMMIT_ROUTING);
-        try {
-            boolean success = mCommitRoutingCountDownLatch
-                    .await(WAIT_FOR_COMMIT_ROUTING_TIMEOUT_MS, TimeUnit.MILLISECONDS);
-            if (!success) {
-                Log.e(TAG, "commitRouting: timed out!");
-                return STATUS_UNKNOWN_ERROR;
-            } else {
-                Log.i(TAG, "commitRouting: status= " + mCommitRoutingStatus);
-                return mCommitRoutingStatus;
-            }
-        } catch (InterruptedException e) {
-            return STATUS_UNKNOWN_ERROR;
-        } finally {
-            mCommitRoutingCountDownLatch = null;
+        if (mCardEmulationManager.onRoutingChangeStarted()) {
+            mHandler.sendEmptyMessage(MSG_COMMIT_ROUTING);
+        } else {
+            Log.d(TAG, "Routing commit already in progress, ignoring...");
         }
+        return STATUS_OK;
     }
 
     public boolean sendScreenMessageAfterNfcCharging() {
@@ -4802,7 +4893,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 Log.d(TAG, "sendScreenMessageAfterNfcCharging: applying postponed screen state "
                         + screenState);
             }
-            NfcService.getInstance().sendMessage(MSG_APPLY_SCREEN_STATE, screenState);
+            sendMessage(NfcService.MSG_APPLY_SCREEN_STATE, screenState);
             mPendingPowerStateUpdate = false;
             return true;
         }
@@ -4838,6 +4929,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     }
 
     public void onPreferredPaymentChanged(int reason) {
+        mHandler.removeMessages(MSG_PREFERRED_PAYMENT_CHANGED);
         sendMessage(MSG_PREFERRED_PAYMENT_CHANGED, reason);
     }
 
@@ -4870,7 +4962,10 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     }
 
     public void setSystemCodeRoute(int route) {
-        sendMessage(MSG_UPDATE_SYSTEM_CODE_ROUTE, route);
+        // Don't call function "nfcManager_updateSystemCodeRoute()" after NFC Deinitialization
+        if(!isNfcDisabledOrDisabling()) {
+            sendMessage(MSG_UPDATE_SYSTEM_CODE_ROUTE, route);
+        }
     }
 
     void sendMessage(int what, Object obj) {
@@ -4880,6 +4975,14 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         mHandler.sendMessage(msg);
     }
 
+    void sendMessage(int what, int arg1, Object obj) {
+        Message msg = mHandler.obtainMessage();
+        msg.what = what;
+        msg.arg1 = arg1;
+        msg.obj = obj;
+        mHandler.sendMessage(msg);
+    }
+
     /**
      * Send require device unlock for NFC intent to system UI.
      */
@@ -4956,26 +5059,26 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                         if (isNfcDisabledOrDisabling()) {
                             Log.d(TAG, "handleMessage: Skip commit routing when NFCC is off "
                                     + "or turning off");
-                            if (mCommitRoutingCountDownLatch != null) {
-                                mCommitRoutingStatus = STATUS_UNKNOWN_ERROR;
-                                mCommitRoutingCountDownLatch.countDown();
-                            }
+                            mCardEmulationManager.onRoutingChangeCompleted(STATUS_UNKNOWN_ERROR);
                             return;
                         }
                         if (mCurrentDiscoveryParameters.shouldEnableDiscovery()) {
                             if (mNfcOemExtensionCallback != null) {
+                                // OemExtension will call the commit routing after some actions
                                 if (receiveOemCallbackResult(ACTION_ON_ROUTING_CHANGED)) {
                                     Log.e(TAG, "handleMessage: Oem skip commitRouting");
-                                    if (mCommitRoutingCountDownLatch != null) {
-                                        mCommitRoutingStatus = STATUS_UNKNOWN_ERROR;
-                                        mCommitRoutingCountDownLatch.countDown();
-                                    }
                                     return;
                                 }
                             }
-                            mCommitRoutingStatus = mDeviceHost.commitRouting();
-                            if (mCommitRoutingCountDownLatch != null) {
-                                mCommitRoutingCountDownLatch.countDown();
+                            mCardEmulationManager.onRoutingChangeCompleted(
+                                    mDeviceHost.commitRouting());
+
+                            if (mNfcOemExtensionCallback != null) {
+                                try {
+                                    mNfcOemExtensionCallback.onRoutingChangeCompleted();
+                                } catch (RemoteException e) {
+                                    Log.e(TAG, "onRoutingChangeCompleted failed e = " + e);
+                                }
                             }
                         } else {
                             Log.d(TAG,
@@ -5191,7 +5294,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     Log.d(TAG, "handleMessage: MSG_RF_FIELD_DEACTIVATED");
                     notifyOemLogEvent(new OemLogItems
                             .Builder(OemLogItems.LOG_ACTION_RF_FIELD_STATE_CHANGED)
-                            .setRfFieldOnTime(Instant.now()).build());
+                            .setRfFieldOnTime(Instant.EPOCH).build());
                     if (mCardEmulationManager != null) {
                         mCardEmulationManager.onFieldChangeDetected(false);
                     }
@@ -5223,7 +5326,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
                 case MSG_APPLY_SCREEN_STATE:
                     mScreenState = (Integer)msg.obj;
-                    Log.d(TAG, "handleMessage: MSG_APPLY_SCREEN_STATE"
+                    Log.d(TAG, "handleMessage: MSG_APPLY_SCREEN_STATE "
                             + ScreenStateHelper.screenStateToString(mScreenState));
 
                     synchronized (NfcService.this) {
@@ -5263,9 +5366,21 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 case MSG_TRANSACTION_EVENT:
                     Log.d(TAG, "handleMessage: MSG_TRANSACTION_EVENT");
                     if (mCardEmulationManager != null) {
-                        mCardEmulationManager.onOffHostAidSelected();
+                        mCardEmulationManager.onOffHostAidTransaction();
                     }
                     byte[][] data = (byte[][]) msg.obj;
+                    if (mIsEuiccCapable){
+                        byte [] reader = null;
+                        String sReader = new String(data[2], StandardCharsets.UTF_8);
+
+                        if (mCardEmulationManager != null
+                                && sReader.contains(RoutingOptionManager.SE_PREFIX_SIM)) {
+                            reader = mCardEmulationManager.getReaderByPreferredSim();
+                        }
+                        if (reader != null) {
+                            data[2] = reader;
+                        }
+                    }
                     synchronized (NfcService.this) {
                         sendOffHostTransactionEvent(data[0], data[1], data[2]);
                     }
@@ -5273,9 +5388,11 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
                 case MSG_SE_SELECTED_EVENT:
                     Log.d(TAG, "handleMessage: MSG_SE_SELECTED_EVENT");
-                    int type = (int) msg.obj;
+                    int type = (int) msg.arg1;
                     if (mCardEmulationManager != null && type == SE_SELECTED_AID) {
-                        mCardEmulationManager.onOffHostAidSelected();
+                        Pair<byte[], String> aidAndEeName = (Pair<byte[], String>) msg.obj;
+                        String aidString = Utils.aidBytesToString(aidAndEeName.first);
+                        mCardEmulationManager.onOffHostAidSelected(aidString, aidAndEeName.second);
                     }
                     break;
                 case MSG_PREFERRED_PAYMENT_CHANGED:
@@ -5324,7 +5441,6 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     }
                     break;
                 case MSG_WATCHDOG_PING:
-                    Log.d(TAG, "handleMessage: MSG_WATCHDOG_PING");
                     NfcWatchdog watchdog = (NfcWatchdog) msg.obj;
                     watchdog.notifyHasReturned();
                     if (mLastFieldOnTimestamp + TIME_TO_MONITOR_AFTER_FIELD_ON_MS >
@@ -5358,11 +5474,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             int uid = -1;
             int offhostCategory = NfcStatsLog.NFC_CARDEMULATION_OCCURRED__CATEGORY__OFFHOST;
             try {
-                StringBuilder aidString = new StringBuilder(aid.length);
-                for (byte b : aid) {
-                    aidString.append(String.format("%02X", b));
-                }
-
+                String aidString = Utils.aidBytesToString(aid);
                 String aidCategory = mCardEmulationManager
                         .getRegisteredAidCategory(aidString.toString());
                 if (DBG) {
@@ -5481,19 +5593,28 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 return;
             }
             intent.addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES);
-            for (int userId : mNfcEventInstalledPackages.keySet()) {
-                for (String packageName : mNfcEventInstalledPackages.get(userId)) {
-                    intent.setPackage(packageName);
-                    mContext.sendBroadcastAsUser(intent, UserHandle.of(userId));
+
+            Runnable task = () -> {
+                Map<Integer, List<String>> packagesCopy = new HashMap<>(mNfcEventInstalledPackages);
+                Intent broadcastIntent = new Intent(intent);
+                for (int userId : packagesCopy.keySet()) {
+                    List<String> pkgList = new ArrayList<>(packagesCopy.get(userId));
+                    for (String packageName : pkgList) {
+                        broadcastIntent.setPackage(packageName);
+                        mContext.sendBroadcastAsUser(broadcastIntent, UserHandle.of(userId));
+                    }
                 }
-            }
+                Log.d(TAG, "Background task sendBroadcast " + intent.getAction());
+            };
+
+            mNfcBroadcastHandler.post(task);
         }
 
         /* Returns the list of packages request for nfc preferred payment service changed and
          * have access to NFC Events on any SE */
         private ArrayList<String> getNfcPreferredPaymentChangedSEAccessAllowedPackages(int userId) {
             synchronized (NfcService.this) {
-                if (!isSEServiceAvailable()
+                if (!isSEServiceAvailable() || isPowerSavingModeEnabled()
                         || mNfcPreferredPaymentChangedInstalledPackages.get(userId).isEmpty()) {
                     return null;
                 }
@@ -5679,7 +5800,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     unregisterObject(tagEndpoint.getHandle());
                     if (mPollDelayTime > NO_POLL_DELAY) {
                         pollingDelay();
-                        tagEndpoint.stopPresenceChecking();
+                        tagEndpoint.stopPresenceChecking(false);
                     } else {
                         Log.d(TAG, "dispatchTagEndpoint: Keep presence checking");
                     }
@@ -5833,9 +5954,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     + "Detection Procedure");
             if (isTagPresent()) {
                 prepareForRemovalDetectionMode();
-                mHandler.post(() -> Toast.makeText(mContext,
-                        "No activity over reader mode, RF removal detection procedure started",
-                        Toast.LENGTH_LONG).show());
+                Log.d(TAG, "No activity over reader mode, RF removal detection procedure started");
                 /* Request JNI to start remove detection procedure */
                 startRemovalDetection(mTagRemovalDetectionWaitTime);
             } else {
@@ -5859,7 +5978,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     || action.equals(Intent.ACTION_SCREEN_OFF)
                     || action.equals(Intent.ACTION_USER_PRESENT)) {
                 handleScreenStateChanged();
-            } else if (action.equals(Intent.ACTION_BOOT_COMPLETED) && mIsHceCapable) {
+            } else if ((action.equals(ACTION_BOOT_COMPLETED)
+                    || action.equals(ACTION_LOCKED_BOOT_COMPLETED))
+                    && mIsHceCapable) {
                 if (DBG) Log.d(TAG, action + " received");
                 mCardEmulationManager.onBootCompleted();
             } else if (action.equals(Intent.ACTION_USER_SWITCHED)) {
@@ -5894,8 +6015,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                             UserHandle.of(ActivityManager.getCurrentUser()), /*flags=*/0))
                             .startNotification();
                 }
-            } else if (action.equals(Intent.ACTION_USER_UNLOCKED)
-                    && mFeatureFlags.enableDirectBootAware()) {
+            } else if (action.equals(Intent.ACTION_USER_UNLOCKED)) {
                 // If this is first unlock after upgrading to NFC stack that is direct boot aware,
                 // migrate over the data from CE directory to DE directory for access before user
                 // unlock in subsequent bootups.
@@ -6003,6 +6123,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     new EnableDisableTask().execute(TASK_DISABLE_ALWAYS_ON);
                 }
                 if (isNfcEnabled()) {
+                    StopPresenceChecking(true);
                     mDeviceHost.shutdown();
                 }
             }
@@ -6023,7 +6144,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     + ScreenStateHelper.screenStateToString(screenState));
         }
         if (mScreenState != screenState) {
-            if (nci_version != NCI_VERSION_2_0) {
+            if (nci_version < NCI_VERSION_2_0) {
                 new ApplyRoutingTask().execute(Integer.valueOf(screenState));
             }
             if (DBG) Log.d(TAG, "applyScreenState: screenState != mScreenState=" + mScreenState);
@@ -6192,7 +6313,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             }
             pw.println("SnoopLogMode=" + NFC_SNOOP_LOG_MODE);
             pw.println("VendorDebugEnabled=" + NFC_VENDOR_DEBUG_ENABLED);
-            pw.println("mIsPowerSavingModeEnabled=" + mIsPowerSavingModeEnabled);
+            pw.println("mPowerSavingState=" + mPowerSavingState);
             pw.println("mIsObserveModeSupported=" + mNfcAdapter.isObserveModeSupported());
             pw.println("mIsObserveModeEnabled=" + mNfcAdapter.isObserveModeEnabled());
             pw.println("listenTech=0x" + Integer.toHexString(getNfcListenTech()));
diff --git a/NfcNci/src/com/android/nfc/NfcShellCommand.java b/NfcNci/src/com/android/nfc/NfcShellCommand.java
index 0f77f9258..e14df5e81 100644
--- a/NfcNci/src/com/android/nfc/NfcShellCommand.java
+++ b/NfcNci/src/com/android/nfc/NfcShellCommand.java
@@ -43,6 +43,8 @@ import androidx.annotation.VisibleForTesting;
  * enforce the corresponding API permissions.
  */
 public class NfcShellCommand extends BasicShellCommandHandler {
+    @VisibleForTesting
+    public static String SHELL_PACKAGE_NAME = "com.android.shell";
     private static final int DISABLE_POLLING_FLAGS = 0x1000;
     private static final int ENABLE_POLLING_FLAGS = 0x0000;
 
@@ -111,21 +113,21 @@ public class NfcShellCommand extends BasicShellCommandHandler {
                     if (TextUtils.equals(stringSaveState, "[persist]")) {
                         saveState = true;
                     }
-                    mNfcService.mNfcAdapter.disable(saveState, mContext.getPackageName());
+                    mNfcService.mNfcAdapter.disable(saveState, SHELL_PACKAGE_NAME);
                     return 0;
                 case "enable-nfc":
-                    mNfcService.mNfcAdapter.enable(mContext.getPackageName());
+                    mNfcService.mNfcAdapter.enable(SHELL_PACKAGE_NAME);
                     return 0;
                 case "set-reader-mode":
                     boolean enable_polling =
                             getNextArgRequiredTrueOrFalse("enable-polling", "disable-polling");
                     int flags = enable_polling ? ENABLE_POLLING_FLAGS : DISABLE_POLLING_FLAGS;
                     mNfcService.mNfcAdapter.setReaderMode(
-                        new Binder(), null, flags, null, mContext.getPackageName());
+                        new Binder(), null, flags, null, SHELL_PACKAGE_NAME);
                     return 0;
                 case "set-observe-mode":
                     boolean enable = getNextArgRequiredTrueOrFalse("enable", "disable");
-                    mNfcService.mNfcAdapter.setObserveMode(enable, mContext.getPackageName());
+                    mNfcService.mNfcAdapter.setObserveMode(enable, SHELL_PACKAGE_NAME);
                     return 0;
                 case "set-controller-always-on":
                     int mode = Integer.parseInt(getNextArgRequired());
@@ -135,7 +137,7 @@ public class NfcShellCommand extends BasicShellCommandHandler {
                     int pollTech = Integer.parseInt(getNextArg());
                     int listenTech = Integer.parseInt(getNextArg());
                     mNfcService.mNfcAdapter.updateDiscoveryTechnology(
-                            new Binder(), pollTech, listenTech, mContext.getPackageName());
+                            new Binder(), pollTech, listenTech, SHELL_PACKAGE_NAME);
                     return 0;
                 case "configure-dta":
                     boolean enableDta = getNextArgRequiredTrueOrFalse("enable", "disable");
@@ -206,7 +208,7 @@ public class NfcShellCommand extends BasicShellCommandHandler {
         pw.println("  configure-dta");
         try {
             INfcDta dtaService =
-                    mNfcService.mNfcAdapter.getNfcDtaInterface(mContext.getPackageName());
+                    mNfcService.mNfcAdapter.getNfcDtaInterface(SHELL_PACKAGE_NAME);
             if (enable) {
                 pw.println("  enableDta()");
                 dtaService.enableDta();
diff --git a/NfcNci/src/com/android/nfc/RegisteredComponentCache.java b/NfcNci/src/com/android/nfc/RegisteredComponentCache.java
index 5674e288b..42c5b2020 100644
--- a/NfcNci/src/com/android/nfc/RegisteredComponentCache.java
+++ b/NfcNci/src/com/android/nfc/RegisteredComponentCache.java
@@ -50,9 +50,8 @@ import java.util.concurrent.atomic.AtomicReference;
  */
 public class RegisteredComponentCache {
     private static final String TAG = "RegisteredComponentCache";
-    private static final boolean DEBUG =
-            NfcProperties.debug_enabled().orElse(true);
-    private static final boolean VDBG = false; // turn on for local testing.
+    private static final boolean DEBUG = NfcProperties.debug_enabled().orElse(true);
+    private static final boolean VDBG = NfcProperties.verbose_debug_enabled().orElse(true);
 
     final Context mContext;
     final String mAction;
diff --git a/NfcNci/src/com/android/nfc/RoutingTableParser.java b/NfcNci/src/com/android/nfc/RoutingTableParser.java
index b52a524c0..fa97d27ee 100644
--- a/NfcNci/src/com/android/nfc/RoutingTableParser.java
+++ b/NfcNci/src/com/android/nfc/RoutingTableParser.java
@@ -112,6 +112,14 @@ public class RoutingTableParser {
         return "SYSTEMCODE_" + systemCodeStr;
     }
 
+    /**
+     * Check SystemCode string by inputting systemCode
+     */
+    @VisibleForTesting
+    public String accessGetSystemCodeStr(byte[] sc) {
+        return getSystemCodeStr(sc);
+    }
+
     private String getBlockCtrlStr(byte mask) {
         if ((mask & 0x40) != 0) {
             return "True";
@@ -119,6 +127,14 @@ public class RoutingTableParser {
         return "False";
     }
 
+    /**
+     * Check BlockCtrl String by inputting mask
+     */
+    @VisibleForTesting
+    public String accessGetBlockCtrlStr(byte mask) {
+        return getBlockCtrlStr(mask);
+    }
+
     private String getPrefixSubsetStr(byte mask, byte type) {
         if (type != TYPE_AID) {
             return "";
@@ -137,6 +153,14 @@ public class RoutingTableParser {
         return prefix_subset_str;
     }
 
+    /**
+     * Check Prefix String by inputting mask and type
+     */
+    @VisibleForTesting
+    public String accessGetPrefixSubsetStr(byte mask, byte type) {
+        return getPrefixSubsetStr(mask, type);
+    }
+
     private String formatRow(String entry, String eeId,
             String pwrState, String blkCtrl, String extra) {
         String fmt = "\t%-36s\t%8s\t%-11s\t%-10s\t%-10s";
@@ -339,7 +363,8 @@ public class RoutingTableParser {
                 default -> null;
             };
             entries.add(new Entry(entry, info.mType, info.mNfceeId,
-                    RoutingOptionManager.getInstance().getSecureElementForRoute(info.mNfceeId)));
+                    RoutingOptionManager.getInstance()
+                    .getSecureElementForRoute((int) (info.mNfceeId & 0xFF)), info.mPowerState));
         }
         return entries;
     }
diff --git a/NfcNci/src/com/android/nfc/Utils.java b/NfcNci/src/com/android/nfc/Utils.java
index 526eda811..7329b8817 100644
--- a/NfcNci/src/com/android/nfc/Utils.java
+++ b/NfcNci/src/com/android/nfc/Utils.java
@@ -201,4 +201,12 @@ public final class Utils {
         }
         return masked.toString();
     }
+
+    public static String aidBytesToString(byte[] aid) {
+        StringBuilder aidString = new StringBuilder();
+        for (byte b : aid) {
+            aidString.append(String.format("%02X", b));
+        }
+        return aidString.toString();
+    }
 }
diff --git a/NfcNci/src/com/android/nfc/cardemulation/AidRoutingManager.java b/NfcNci/src/com/android/nfc/cardemulation/AidRoutingManager.java
index fc8b6885e..e8fb961aa 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/AidRoutingManager.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/AidRoutingManager.java
@@ -43,9 +43,10 @@ import java.util.Set;
 
 public class AidRoutingManager {
 
-    static final String TAG = "AidRoutingManager";
+    static final String TAG = "NfcAidRoutingManager";
 
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
+    static final boolean VDBG = NfcProperties.verbose_debug_enabled().orElse(true);
 
     static final int ROUTE_HOST = 0x00;
 
@@ -102,19 +103,38 @@ public class AidRoutingManager {
 
     public AidRoutingManager() {
         mDefaultRoute = mRoutingOptionManager.getDefaultRoute();
-        if (DBG) Log.d(TAG, "mDefaultRoute=0x" + Integer.toHexString(mDefaultRoute));
+        if (DBG) {
+            Log.d(TAG, "mDefaultRoute=0x" + Integer.toHexString(mDefaultRoute));
+        }
         mDefaultOffHostRoute = mRoutingOptionManager.getDefaultOffHostRoute();
-        if (DBG) Log.d(TAG, "mDefaultOffHostRoute=0x" + Integer.toHexString(mDefaultOffHostRoute));
+        if (DBG) {
+            Log.d(TAG, "mDefaultOffHostRoute=0x"
+                    + Integer.toHexString(mDefaultOffHostRoute));
+        }
         mDefaultFelicaRoute = mRoutingOptionManager.getDefaultFelicaRoute();
-        if (DBG) Log.d(TAG, "mDefaultFelicaRoute=0x" + Integer.toHexString(mDefaultFelicaRoute));
+        if (DBG) {
+            Log.d(TAG, "mDefaultFelicaRoute=0x"
+                    + Integer.toHexString(mDefaultFelicaRoute));
+        }
         mOffHostRouteUicc = mRoutingOptionManager.getOffHostRouteUicc();
-        if (DBG) Log.d(TAG, "mOffHostRouteUicc=" + Arrays.toString(mOffHostRouteUicc));
+        if (DBG) {
+            Log.d(TAG,
+                    "mOffHostRouteUicc=" + Arrays.toString(mOffHostRouteUicc));
+        }
         mOffHostRouteEse = mRoutingOptionManager.getOffHostRouteEse();
-        if (DBG) Log.d(TAG, "mOffHostRouteEse=" + Arrays.toString(mOffHostRouteEse));
+        if (DBG) {
+            Log.d(TAG, "mOffHostRouteEse=" + Arrays.toString(mOffHostRouteEse));
+        }
         mAidMatchingSupport = mRoutingOptionManager.getAidMatchingSupport();
-        if (DBG) Log.d(TAG, "mAidMatchingSupport=0x" + Integer.toHexString(mAidMatchingSupport));
+        if (DBG) {
+            Log.d(TAG, "mAidMatchingSupport=0x"
+                    + Integer.toHexString(mAidMatchingSupport));
+        }
         mDefaultIsoDepRoute = mRoutingOptionManager.getDefaultIsoDepRoute();
-        if (DBG) Log.d(TAG, "mDefaultIsoDepRoute=0x" + Integer.toHexString(mDefaultIsoDepRoute));
+        if (DBG) {
+            Log.d(TAG, "mDefaultIsoDepRoute=0x"
+                    + Integer.toHexString(mDefaultIsoDepRoute));
+        }
     }
 
     public boolean supportsAidPrefixRouting() {
@@ -140,7 +160,10 @@ public class AidRoutingManager {
                 routeTableSize += (aid.length() / 0x02)+ AID_HDR_LENGTH;
             }
         }
-        if (DBG) Log.d(TAG, "calculateAidRouteSize: " + routeTableSize);
+        if (DBG) {
+            Log.d(TAG, "calculateAidRouteSize: size for route "
+                    + String.format("%02X", mDefaultRoute) + "=" + routeTableSize);
+        }
         return routeTableSize;
     }
 
@@ -243,6 +266,66 @@ public class AidRoutingManager {
     @Retention(RetentionPolicy.SOURCE)
     public @interface ConfigureRoutingResult {}
 
+    /**
+     * Adds AID to RoutingTableCache by handling prefix,suffix if any.
+     *
+     * @param aid AID which need to be handled and added to RoutingTableCache
+     * @param aidRoutingTableCache Final map of AIDs to their corresponding {@link AidEntry}.
+     * @param aidMap The map of AIDs to their corresponding {@link AidEntry}.
+     * @param route Route of the AID
+     */
+    void addAidToRoutingtable(String aid, HashMap<String, AidEntry> aidRoutingTableCache,
+            HashMap<String, AidEntry> aidMap, int route) {
+        if (aid.endsWith("*")) {
+            if (mAidMatchingSupport == AID_MATCHING_EXACT_ONLY) {
+                Log.e(TAG,
+                        "configureRouting: This device does not support "
+                        + "prefix AIDs.");
+            } else if (mAidMatchingSupport == AID_MATCHING_PREFIX_ONLY) {
+                if (VDBG) {
+                    Log.d(TAG,
+                            "configureRouting: Routing prefix AID " + aid + " to route "
+                            + Integer.toString(route));
+                }
+                // Cut off '*' since controller anyway treats all AIDs as a prefix
+                aidRoutingTableCache.put(aid.substring(0, aid.length() - 1), aidMap.get(aid));
+            } else if (mAidMatchingSupport == AID_MATCHING_EXACT_OR_PREFIX
+                    || mAidMatchingSupport == AID_MATCHING_EXACT_OR_SUBSET_OR_PREFIX) {
+                if (VDBG) {
+                    Log.d(TAG,
+                            "configureRouting: Routing prefix AID " + aid + " to route "
+                            + Integer.toString(route));
+                }
+                aidRoutingTableCache.put(aid.substring(0, aid.length() - 1), aidMap.get(aid));
+            }
+        } else if (aid.endsWith("#")) {
+            if (mAidMatchingSupport == AID_MATCHING_EXACT_ONLY) {
+                Log.e(TAG,
+                        "configureRouting: Device does not support subset "
+                        + "AIDs but AID [" + aid + "] is registered");
+            } else if (mAidMatchingSupport == AID_MATCHING_PREFIX_ONLY
+                    || mAidMatchingSupport == AID_MATCHING_EXACT_OR_PREFIX) {
+                Log.e(TAG,
+                        "configureRouting: Device does not support subset "
+                        + "AIDs but AID [" + aid + "] is registered");
+            } else if (mAidMatchingSupport == AID_MATCHING_EXACT_OR_SUBSET_OR_PREFIX) {
+                if (VDBG) {
+                    Log.d(TAG,
+                            "configureRouting: Routing subset AID " + aid + " to route "
+                            + Integer.toString(route));
+                }
+                aidRoutingTableCache.put(aid.substring(0, aid.length() - 1), aidMap.get(aid));
+            }
+        } else {
+            if (VDBG) {
+                Log.d(TAG,
+                        "configureRouting: Routing exact AID " + aid + " to route "
+                        + Integer.toString(route));
+            }
+            aidRoutingTableCache.put(aid, aidMap.get(aid));
+        }
+    }
+
     /**
      * Configures the routing table with the given {@code aidMap}.
      *
@@ -274,6 +357,10 @@ public class AidRoutingManager {
             mDefaultOffHostRoute = mRoutingOptionManager.getDefaultOffHostRoute();
             mDefaultFelicaRoute = mRoutingOptionManager.getDefaultFelicaRoute();
         }
+        if (DBG) {
+            Log.d(TAG, "configureRouting: Nb of AIDs in aidMap=" + aidMap.size()
+                    + ", mDefaultRoute=" + String.format("0x%02X", mDefaultRoute));
+        }
 
         boolean isPowerStateUpdated = false;
         seList.add(mDefaultRoute);
@@ -317,6 +404,10 @@ public class AidRoutingManager {
             infoForAid.put(aid, aidType);
         }
 
+        if (DBG) {
+            Log.d(TAG, "configureRouting: Nb of different routes in routing table="
+                    + aidRoutingTable.size());
+        }
         if (!mRoutingOptionManager.isAutoChangeEnabled() && seList.size() >= 2) {
             Log.d(TAG, "configureRouting: AutoRouting is not enabled, make only one item in list");
             int firstRoute = seList.get(0);
@@ -327,6 +418,10 @@ public class AidRoutingManager {
         synchronized (mLock) {
             if (routeForAid.equals(mRouteForAid) && powerForAid.equals(mPowerForAid) && !force) {
                 if (DBG) Log.d(TAG, "configureRouting: Routing table unchanged, not updating");
+                // restore state variables since we did not update the routing table.
+                mDefaultRoute = prevDefaultRoute;
+                mDefaultIsoDepRoute = prevDefaultIsoDepRoute;
+                mDefaultOffHostRoute = prevDefaultOffHostRoute;
                 return CONFIGURE_ROUTING_SUCCESS;
             }
 
@@ -338,7 +433,7 @@ public class AidRoutingManager {
             mAidRoutingTable = aidRoutingTable;
 
             mMaxAidRoutingTableSize = NfcService.getInstance().getAidRoutingTableSize();
-            if (DBG) {
+            if (VDBG) {
                 Log.d(TAG, "configureRouting: mMaxAidRoutingTableSize: " + mMaxAidRoutingTableSize);
             }
 
@@ -397,48 +492,7 @@ public class AidRoutingManager {
                     if (route != mDefaultRoute) {
                         Set<String> aidsForRoute = mAidRoutingTable.get(route);
                         for (String aid : aidsForRoute) {
-                            if (aid.endsWith("*")) {
-                                if (mAidMatchingSupport == AID_MATCHING_EXACT_ONLY) {
-                                    Log.e(TAG, "configureRouting: This device does not support "
-                                            + "prefix AIDs.");
-                                } else if (mAidMatchingSupport == AID_MATCHING_PREFIX_ONLY) {
-                                    if (DBG) {
-                                        Log.d(TAG, "configureRouting: Routing prefix AID " + aid
-                                                + " to route " + Integer.toString(route));
-                                    }
-                                    // Cut off '*' since controller anyway treats all AIDs as a prefix
-                                    aidRoutingTableCache.put(aid.substring(0,aid.length() - 1), aidMap.get(aid));
-                                } else if (mAidMatchingSupport == AID_MATCHING_EXACT_OR_PREFIX ||
-                                  mAidMatchingSupport == AID_MATCHING_EXACT_OR_SUBSET_OR_PREFIX) {
-                                    if (DBG) {
-                                        Log.d(TAG, "configureRouting: Routing prefix AID " + aid
-                                                + " to route " + Integer.toString(route));
-                                    }
-                                    aidRoutingTableCache.put(aid.substring(0,aid.length() - 1), aidMap.get(aid));
-                                }
-                            } else if (aid.endsWith("#")) {
-                                if (mAidMatchingSupport == AID_MATCHING_EXACT_ONLY) {
-                                    Log.e(TAG,
-                                            "configureRouting: Device does not support subset "
-                                                    + "AIDs but AID [" + aid + "] is registered");
-                                } else if (mAidMatchingSupport == AID_MATCHING_PREFIX_ONLY ||
-                                    mAidMatchingSupport == AID_MATCHING_EXACT_OR_PREFIX) {
-                                    Log.e(TAG, "configureRouting: Device does not support subset "
-                                            + "AIDs but AID [" + aid + "] is registered");
-                                } else if (mAidMatchingSupport == AID_MATCHING_EXACT_OR_SUBSET_OR_PREFIX) {
-                                    if (DBG) {
-                                        Log.d(TAG, "configureRouting: Routing subset AID " + aid
-                                                + " to route " + Integer.toString(route));
-                                    }
-                                    aidRoutingTableCache.put(aid.substring(0,aid.length() - 1), aidMap.get(aid));
-                                }
-                            } else {
-                                if (DBG) {
-                                    Log.d(TAG, "configureRouting: Routing exact AID " + aid
-                                            + " to route " + Integer.toString(route));
-                                }
-                                aidRoutingTableCache.put(aid, aidMap.get(aid));
-                            }
+                            addAidToRoutingtable(aid, aidRoutingTableCache, aidMap, route);
                         }
                     }
                 }
@@ -487,7 +541,8 @@ public class AidRoutingManager {
                     if (aidsForDefaultRoute != null) {
                         for (String aid : aidsForDefaultRoute) {
                             if (aidMap.get(aid).power != default_route_power_state) {
-                                aidRoutingTableCache.put(aid, aidMap.get(aid));
+                                addAidToRoutingtable(
+                                        aid, aidRoutingTableCache, aidMap, mDefaultRoute);
                                 isPowerStateUpdated = true;
                             }
                         }
@@ -496,7 +551,9 @@ public class AidRoutingManager {
 
                 // Unchecked Offhosts rout to host
                 if (mDefaultRoute != ROUTE_HOST) {
-                    Log.d(TAG, "configureRouting: check offHost route to host");
+                    if (VDBG) {
+                        Log.d(TAG, "configureRouting: check offHost route to host");
+                    }
                     checkOffHostRouteToHost(aidRoutingTableCache);
                 }
 
@@ -545,7 +602,7 @@ public class AidRoutingManager {
                 int aidType = aidEntry.getValue().aidInfo;
                 String aid = aidEntry.getKey();
                 int power = aidEntry.getValue().power;
-                if (DBG)  {
+                if (VDBG)  {
                     Log.d(TAG, "commit: aid:" + aid + ",route:" + route
                         + ",aidtype:" + aidType + ", power state:" + power);
                 }
diff --git a/NfcNci/src/com/android/nfc/cardemulation/AppChooserActivity.java b/NfcNci/src/com/android/nfc/cardemulation/AppChooserActivity.java
index 131ec4371..1e37ba4e2 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/AppChooserActivity.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/AppChooserActivity.java
@@ -31,6 +31,7 @@ import android.nfc.cardemulation.ApduServiceInfo;
 import android.nfc.cardemulation.CardEmulation;
 import android.os.Bundle;
 import android.os.UserHandle;
+import android.sysprop.NfcProperties;
 import android.util.Log;
 import android.view.LayoutInflater;
 import android.view.View;
@@ -54,7 +55,8 @@ import java.util.List;
 public class AppChooserActivity extends AppCompatActivity
         implements AdapterView.OnItemClickListener {
 
-    static final String TAG = "AppChooserActivity";
+    static final String TAG = "NfcAppChooserActivity";
+    static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
 
     public static final String EXTRA_APDU_SERVICES = "services";
     public static final String EXTRA_CATEGORY = "category";
@@ -88,7 +90,7 @@ public class AppChooserActivity extends AppCompatActivity
         registerReceiver(mReceiver, filter);
 
         if ((options == null || options.size() == 0) && failedComponent == null) {
-            Log.e(TAG, "onCreate: No components passed in.");
+            Log.e(TAG, "onCreate: No components passed in, finishing");
             finish();
             return;
         }
@@ -98,12 +100,19 @@ public class AppChooserActivity extends AppCompatActivity
 
         final NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
         if (adapter == null) {
-            Log.e(TAG, "onCreate: adapter is null");
+            Log.e(TAG, "onCreate: adapter is null, finishing");
             finish();
             return;
         }
         mCardEmuManager = CardEmulation.getInstance(adapter);
 
+        if (DBG) {
+            Log.d(TAG, "onCreate: " + options.size() + " services");
+            for (int i = 0; i < options.size(); i++) {
+                Log.d(TAG, "onCreate: service=" + options.get(i).getComponent());
+            }
+        }
+
         final ActivityManager am = getSystemService(ActivityManager.class);
         mIconSize = am.getLauncherLargeIconSize();
 
@@ -172,6 +181,7 @@ public class AppChooserActivity extends AppCompatActivity
 
     @Override
     protected void onCreate(Bundle savedInstanceState) {
+        if (DBG) Log.d(TAG, "onCreate");
         Intent intent = getIntent();
         ArrayList<ApduServiceInfo> services = intent.getParcelableArrayListExtra(EXTRA_APDU_SERVICES);
         String category = intent.getStringExtra(EXTRA_CATEGORY);
@@ -181,6 +191,7 @@ public class AppChooserActivity extends AppCompatActivity
 
     @Override
     public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
+        if (DBG) Log.d(TAG, "onItemClick");
         DisplayAppInfo info = (DisplayAppInfo) mListAdapter.getItem(position);
         mCardEmuManager.setDefaultForNextTap(
                 UserHandle.getUserHandleForUid(info.serviceInfo.getUid()).getIdentifier(),
diff --git a/NfcNci/src/com/android/nfc/cardemulation/CardEmulationManager.java b/NfcNci/src/com/android/nfc/cardemulation/CardEmulationManager.java
index 0c358a707..ec90092fc 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/CardEmulationManager.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/CardEmulationManager.java
@@ -43,6 +43,7 @@ import android.nfc.cardemulation.NfcFServiceInfo;
 import android.nfc.cardemulation.PollingFrame;
 import android.os.Binder;
 import android.os.Build;
+import android.os.Handler;
 import android.os.Looper;
 import android.os.PowerManager;
 import android.os.Process;
@@ -75,11 +76,17 @@ import com.android.nfc.proto.NfcEventProto;
 
 import java.io.FileDescriptor;
 import java.io.PrintWriter;
+import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 import java.util.Objects;
 import java.util.Optional;
+import java.util.concurrent.Callable;
+import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.Executors;
+import java.util.concurrent.TimeUnit;
 import java.util.function.Consumer;
 import java.util.function.Function;
 import java.util.function.Supplier;
@@ -108,8 +115,9 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         EnabledNfcFServices.Callback, WalletRoleObserver.Callback,
         PreferredSubscriptionService.Callback,
         HostEmulationManager.NfcAidRoutingListener {
-    static final String TAG = "CardEmulationManager";
+    static final String TAG = "NfcCardEmulationManager";
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
+    static final boolean VDBG = NfcProperties.verbose_debug_enabled().orElse(true);
 
     static final int NFC_HCE_APDU = 0x01;
     static final int NFC_HCE_NFCF = 0x04;
@@ -128,7 +136,9 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     /** Select APDU header */
     static final byte[] SELECT_AID_HDR = new byte[] {0x00, (byte) 0xa4, 0x04, 0x00};
     private static final int FIRMWARE_EXIT_FRAME_TIMEOUT_MS = 5000;
+    private static final int WAIT_FOR_ROUTING_CHANGE_TIMEOUT_MS = 1000;
 
+    final Handler mHandler;
     final RegisteredAidCache mAidCache;
     final RegisteredT3tIdentifiersCache mT3tIdentifiersCache;
     final RegisteredServicesCache mServiceCache;
@@ -161,6 +171,11 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     private final DeviceConfigFacade mDeviceConfigFacade;
     private final NfcInjector mNfcInjector;
 
+    private CompletableFuture<Integer> mRoutingChangeFuture = null;
+    private final ExecutorService mCommitRoutingExecutor = Executors.newSingleThreadExecutor();
+
+    private boolean mIsEuiccCapable;
+
     // TODO: Move this object instantiation and dependencies to NfcInjector.
     public CardEmulationManager(Context context, NfcInjector nfcInjector,
         DeviceConfigFacade deviceConfigFacade) {
@@ -173,6 +188,8 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         mWalletRoleObserver = new WalletRoleObserver(context,
                 context.getSystemService(RoleManager.class), this, nfcInjector);
 
+        mIsEuiccCapable = mContext.getResources().getBoolean(R.bool.enable_euicc_support)
+                && NfcInjector.NfcProperties.isEuiccSupported();
         mRoutingOptionManager = RoutingOptionManager.getInstance();
         mOffHostRouteEse = mRoutingOptionManager.getOffHostRouteEse();
         mOffHostRouteUicc = mRoutingOptionManager.getOffHostRouteUicc();
@@ -181,6 +198,7 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         mTelephonyUtils = TelephonyUtils.getInstance(mContext);
         mTelephonyUtils.setMepMode(mRoutingOptionManager.getMepMode());
 
+        mHandler = new Handler(Looper.getMainLooper());
         mAidCache = new RegisteredAidCache(context, mWalletRoleObserver);
         mT3tIdentifiersCache = new RegisteredT3tIdentifiersCache(context);
         mHostEmulationManager =
@@ -206,6 +224,7 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     CardEmulationManager(Context context,
             ForegroundUtils foregroundUtils,
             WalletRoleObserver walletRoleObserver,
+            Handler handler,
             RegisteredAidCache registeredAidCache,
             RegisteredT3tIdentifiersCache registeredT3tIdentifiersCache,
             HostEmulationManager hostEmulationManager,
@@ -227,6 +246,7 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         mNfcFCardEmulationInterface = new NfcFCardEmulationInterface();
         mForegroundUtils = foregroundUtils;
         mWalletRoleObserver = walletRoleObserver;
+        mHandler = handler;
         mAidCache = registeredAidCache;
         mT3tIdentifiersCache = registeredT3tIdentifiersCache;
         mHostEmulationManager = hostEmulationManager;
@@ -360,8 +380,15 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         }
     }
 
-    public void onOffHostAidSelected() {
-        mHostEmulationManager.onOffHostAidSelected();
+    public void onOffHostAidTransaction() {
+        mHostEmulationManager.onOffHostAidSelectedOrTransaction();
+    }
+
+    public void onOffHostAidSelected(@NonNull String aid, @NonNull String eeName) {
+        mHostEmulationManager.onOffHostAidSelectedOrTransaction();
+        if (com.android.nfc.module.flags.Flags.eventListenerOffhostAidSelected()) {
+            callNfcEventCallbacks(listener -> listener.onOffHostAidSelected(aid, eeName));
+        }
     }
 
     public void onBootCompleted() {
@@ -370,6 +397,7 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     }
 
     public void onUserSwitched(int userId) {
+        if (DBG) Log.d(TAG, "onUserSwitched");
         mWalletRoleObserver.onUserSwitched(userId);
         // for HCE
         mServiceCache.onUserSwitched();
@@ -393,6 +421,7 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     }
 
     public void onNfcEnabled() {
+        if (DBG) Log.d(TAG, "onNfcEnabled");
         // for HCE
         mAidCache.onNfcEnabled();
         // for HCE-F
@@ -400,6 +429,7 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     }
 
     public void onNfcDisabled() {
+        if (DBG) Log.d(TAG, "onNfcDisabled");
         // for HCE
         mAidCache.onNfcDisabled();
         // for HCE-F
@@ -415,6 +445,18 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         mT3tIdentifiersCache.onTriggerRoutingTableUpdate();
     }
 
+    public boolean onRoutingChangeStarted() {
+        if (mRoutingChangeFuture != null) return false;
+        mRoutingChangeFuture = new CompletableFuture<>();
+        return true;
+    }
+
+    public boolean onRoutingChangeCompleted(@NfcOemExtension.StatusCode int status) {
+        Log.d(TAG, "onRoutingChangeComplete: " + status);
+        if (mRoutingChangeFuture == null) return false;
+        return mRoutingChangeFuture.complete(status);
+    }
+
     public void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
         mServiceCache.dump(fd, pw, args);
         mNfcFServicesCache.dump(fd, pw ,args);
@@ -479,12 +521,17 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         // Update the AID cache
         mAidCache.onServicesUpdated(userId, services);
         // Update the preferred services list
-        mPreferredServices.onServicesUpdated();
+        boolean preferredServicesUpdated = mPreferredServices.onServicesUpdated();
         mHostEmulationManager.updatePollingLoopFilters(userId, services);
         if (Flags.exitFrames()) {
-            updateFirmwareExitFramesForWalletRole(userId);
+            mHandler.post(() -> {
+                updateFirmwareExitFramesForWalletRole(userId);
+            });
+        }
+        if (preferredServicesUpdated) {
+            NfcService.getInstance().onPreferredPaymentChanged(
+                    NfcAdapter.PREFERRED_PAYMENT_UPDATED);
         }
-        NfcService.getInstance().onPreferredPaymentChanged(NfcAdapter.PREFERRED_PAYMENT_UPDATED);
     }
 
     @Override
@@ -627,6 +674,10 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
 
     boolean setDefaultServiceForCategoryChecked(int userId, ComponentName service,
             String category) {
+        if (DBG) {
+            Log.d(TAG, "setDefaultServiceForCategoryChecked: service=" + service + ", category="
+                    + category);
+        }
         if (!CardEmulation.CATEGORY_PAYMENT.equals(category)) {
             Log.e(TAG, "setDefaultServiceForCategoryChecked: Not allowing defaults for category "
                     + category);
@@ -727,9 +778,8 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     @Override
     public void onPreferredSubscriptionChanged(int subscriptionId, boolean isActive) {
         int simType = isActive ?  getSimTypeById(subscriptionId) : TelephonyUtils.SIM_TYPE_UNKNOWN;
-        Log.i(TAG, "onPreferredSubscriptionChanged: subscription_" + subscriptionId + "is active("
-                + isActive + ")"
-                + ", type(" + simType + ")");
+        Log.i(TAG, "onPreferredSubscriptionChanged: subscription_" + subscriptionId
+                + "is active(" + isActive + "), type(" + simType + ")");
         mRoutingOptionManager.onPreferredSimChanged(simType);
         if (simType != TelephonyUtils.SIM_TYPE_UNKNOWN) {
             updateRouteBasedOnPreferredSim();
@@ -781,6 +831,10 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
             if (!isServiceRegistered(userId, service)) {
                 return false;
             }
+            if (DBG) {
+                Log.d(TAG, "isDefaultServiceForCategory: service=" + service + ", category="
+                        + category);
+            }
             if (mWalletRoleObserver.isWalletRoleFeatureEnabled()) {
                 PackageAndUser holder =
                         mWalletRoleObserver.getDefaultWalletRoleHolder(userId);
@@ -822,6 +876,9 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
                 throws RemoteException {
             NfcPermissions.validateProfileId(mContext, userId);
             NfcPermissions.enforceAdminPermissions(mContext);
+            if (DBG) {
+                Log.d(TAG, "setDefaultForNextTap: service=" + service);
+            }
             if (service != null && !isServiceRegistered(userId, service)) {
                 return false;
             }
@@ -851,6 +908,66 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
             return true;
         }
 
+        @Override
+        public void setRequireDeviceScreenOnForService(int userId, ComponentName service,
+                boolean enable) {
+            NfcPermissions.validateUserId(userId);
+            NfcPermissions.enforceUserPermissions(mContext);
+
+            if (!isServiceRegistered(userId, service)) {
+                throw new IllegalArgumentException(
+                        "Service with component name " + service + " is not registered");
+            }
+
+            Log.d(TAG, "setRequireDeviceScreenOnForService: (" + service + ") to " + enable);
+
+            mServiceCache.setRequireDeviceScreenOnForService(
+                    userId, Binder.getCallingUid(), service, enable);
+        }
+
+        @Override
+        public boolean isDeviceScreenOnRequiredForService(int userId, ComponentName service) {
+            NfcPermissions.validateUserId(userId);
+            NfcPermissions.enforceUserPermissions(mContext);
+
+            if (!isServiceRegistered(userId, service)) {
+                throw new IllegalArgumentException(
+                        "Service with component name " + service + " is not registered");
+            }
+
+            return mServiceCache.getService(userId, service).requiresScreenOn();
+        }
+
+        @Override
+        public void setRequireDeviceUnlockForService(int userId, ComponentName service,
+                boolean enable) {
+            NfcPermissions.validateUserId(userId);
+            NfcPermissions.enforceUserPermissions(mContext);
+
+            if (!isServiceRegistered(userId, service)) {
+                throw new IllegalArgumentException(
+                        "Service with component name " + service + " is not registered");
+            }
+
+            Log.d(TAG, "setRequireDeviceUnlockForService: (" + service + ") to " + enable);
+
+            mServiceCache.setRequireDeviceUnlockForService(
+                    userId, Binder.getCallingUid(), service, enable);
+        }
+
+        @Override
+        public boolean isDeviceUnlockRequiredForService(int userId, ComponentName service) {
+            NfcPermissions.validateUserId(userId);
+            NfcPermissions.enforceUserPermissions(mContext);
+
+            if (!isServiceRegistered(userId, service)) {
+                throw new IllegalArgumentException(
+                        "Service with component name " + service + " is not registered");
+            }
+
+            return mServiceCache.getService(userId, service).requiresUnlock();
+        }
+
         @Override
         public boolean registerAidGroupForService(int userId,
                 ComponentName service, AidGroup aidGroup) throws RemoteException {
@@ -957,6 +1074,18 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
             return true;
         }
 
+        @Override
+        public List<String> getPollingLoopFiltersForService(int userId, ComponentName service) {
+            NfcPermissions.validateUserId(userId);
+            NfcPermissions.enforceUserPermissions(mContext);
+            if (!isServiceRegistered(userId, service)) {
+                throw new IllegalArgumentException("getPollingLoopPatternFiltersForService: "
+                        + "service (" + service + ") isn't registered for user " + userId);
+            }
+            return List.copyOf(mServiceCache.getPollingLoopFiltersForService(
+                    userId,Binder.getCallingUid(), service));
+        }
+
         @Override
         public boolean registerPollingLoopPatternFilterForService(int userId, ComponentName service,
                 String pollingLoopPatternFilter, boolean autoTransact) throws RemoteException {
@@ -1027,6 +1156,19 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
             return true;
         }
 
+        @Override
+        public List<String> getPollingLoopPatternFiltersForService(
+            int userId, ComponentName service) {
+            NfcPermissions.validateUserId(userId);
+            NfcPermissions.enforceUserPermissions(mContext);
+            if (!isServiceRegistered(userId, service)) {
+                throw new IllegalArgumentException("getPollingLoopPatternFiltersForService: "
+                        + "service (" + service + ") isn't registered for user " + userId);
+            }
+            return List.copyOf(mServiceCache.getPollingLoopPatternFiltersForService(
+                    userId, Binder.getCallingUid(), service));
+        }
+
         @Override
         public boolean setOffHostForService(int userId, ComponentName service, String offHostSE) {
             NfcPermissions.validateUserId(userId);
@@ -1162,9 +1304,12 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
                 return mWalletRoleObserver.getDefaultWalletRoleHolder(
                         callingUserId).getPackage() != null;
             }
-            String defaultComponent = Settings.Secure.getString(mContext.getContentResolver(),
-                    Constants.SETTINGS_SECURE_NFC_PAYMENT_DEFAULT_COMPONENT);
-            return defaultComponent != null ? true : false;
+            boolean isRegistered = Settings.Secure.getString(mContext.getContentResolver(),
+                    Constants.SETTINGS_SECURE_NFC_PAYMENT_DEFAULT_COMPONENT) != null;
+            if (DBG) {
+                Log.d(TAG, "isDefaultPaymentRegistered: " + isRegistered);
+            }
+            return isRegistered;
         }
 
         @Override
@@ -1204,10 +1349,11 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
                         + ", technologyRoute " + technologyRoute);
             }
 
-//            mRoutingOptionManager.overrideDefaultRoute(protocolRoute);
+            mRoutingOptionManager.overrideDefaultRoute(protocolRoute);
             mRoutingOptionManager.overrideDefaultIsoDepRoute(protocolRoute);
             mRoutingOptionManager.overrideDefaultOffHostRoute(technologyRoute);
-            int result = mAidCache.onRoutingOverridedOrRecovered();
+            int result = callRoutingOverridedOrRecovered();
+
             switch (result) {
                 case AidRoutingManager.CONFIGURE_ROUTING_SUCCESS:
                     break;
@@ -1231,7 +1377,7 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
             mForegroundUid = Process.INVALID_UID;
 
             mRoutingOptionManager.recoverOverridedRoutingTable();
-            if (mAidCache.onRoutingOverridedOrRecovered()
+            if (callRoutingOverridedOrRecovered()
                         != AidRoutingManager.CONFIGURE_ROUTING_SUCCESS) {
                 throw new IllegalArgumentException(
                         "recoverRoutingTable: " + "onRoutingOverridedOrRecovered() failed");
@@ -1247,10 +1393,18 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
 
             NfcPermissions.enforceAdminPermissions(mContext);
 
-            int aidRoute = getRouteForSecureElement(aids);
-            int protocolRoute = getRouteForSecureElement(protocol);
-            int technologyRoute = getRouteForSecureElement(technology);
-            int scRoute = getRouteForSecureElement(sc);
+            int aidRoute = (aids != null && aids.equals("default"))
+                    ? mRoutingOptionManager.getDefaultRoute()
+                    : getRouteForSecureElement(aids);
+            int protocolRoute = (protocol != null && protocol.equals("default"))
+                    ? mRoutingOptionManager.getDefaultIsoDepRoute()
+                    : getRouteForSecureElement(protocol);
+            int technologyRoute = (technology != null && technology.equals("default"))
+                    ? mRoutingOptionManager.getDefaultOffHostRoute()
+                    : getRouteForSecureElement(technology);
+            int scRoute = (sc != null && sc.equals("default"))
+                    ? mRoutingOptionManager.getDefaultScRoute()
+                    : getRouteForSecureElement(sc);
 
             if (DBG)  {
                 Log.d(TAG, "overwriteRoutingTable(): aidRoute: " + Integer.toHexString(aidRoute)
@@ -1273,7 +1427,8 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
             if (aids != null || protocol != null || technology != null || sc != null) {
                 mRoutingOptionManager.overwriteRoutingTable();
             }
-            if (mAidCache.onRoutingOverridedOrRecovered()
+
+            if (callRoutingOverridedOrRecovered()
                         != AidRoutingManager.CONFIGURE_ROUTING_SUCCESS) {
                 throw new IllegalArgumentException("onRoutingOverridedOrRecovered() failed");
             }
@@ -1285,9 +1440,24 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
             List<Integer> routingList = new ArrayList<>();
 
             if (mRoutingOptionManager.isRoutingTableOverrided()) {
-                routingList.add(mRoutingOptionManager.getOverrideDefaultRoute());
-                routingList.add(mRoutingOptionManager.getOverrideDefaultIsoDepRoute());
-                routingList.add(mRoutingOptionManager.getOverrideDefaultOffHostRoute());
+                int overrideDefaultRoute = mRoutingOptionManager.getOverrideDefaultRoute();
+                if (overrideDefaultRoute == RoutingOptionManager.ROUTE_UNKNOWN) {
+                    overrideDefaultRoute = mRoutingOptionManager.getDefaultRoute();
+                }
+                int overrideDefaultIsoDepRoute =
+                        mRoutingOptionManager.getOverrideDefaultIsoDepRoute();
+                if (overrideDefaultIsoDepRoute == RoutingOptionManager.ROUTE_UNKNOWN) {
+                    overrideDefaultIsoDepRoute = mRoutingOptionManager.getDefaultIsoDepRoute();
+                }
+                int overrideDefaultOffHostRoute =
+                        mRoutingOptionManager.getOverrideDefaultOffHostRoute();
+                if (overrideDefaultOffHostRoute == RoutingOptionManager.ROUTE_UNKNOWN) {
+                    overrideDefaultOffHostRoute =
+                        mRoutingOptionManager.getDefaultOffHostRoute();
+                }
+                routingList.add(overrideDefaultRoute);
+                routingList.add(overrideDefaultIsoDepRoute);
+                routingList.add(overrideDefaultOffHostRoute);
             }
             else {
                 routingList.add(mRoutingOptionManager.getDefaultRoute());
@@ -1453,6 +1623,11 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
                     }
                     mForegroundUid = Process.INVALID_UID;
                     mRoutingOptionManager.recoverOverridedRoutingTable();
+                    if (callRoutingOverridedOrRecovered()
+                            != AidRoutingManager.CONFIGURE_ROUTING_SUCCESS) {
+                        throw new IllegalArgumentException(
+                                "recoverRoutingTable: " + "onRoutingOverridedOrRecovered() failed");
+                    }
                 }
             }
         }
@@ -1637,8 +1812,7 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     }
 
     private int getSimTypeById(int subscriptionId) {
-        Optional<SubscriptionInfo> optionalInfo =
-                mTelephonyUtils.getActiveSubscriptionInfoById(subscriptionId);
+        Optional<SubscriptionInfo> optionalInfo = getActiveSubscriptionInfoById(subscriptionId);
         if (optionalInfo.isPresent()) {
             SubscriptionInfo info = optionalInfo.get();
             if (info.isEmbedded()) {
@@ -1653,6 +1827,19 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         return TelephonyUtils.SIM_TYPE_UNKNOWN;
     }
 
+    public byte[] getReaderByPreferredSim() {
+        Optional<SubscriptionInfo> optionalInfo =
+                getActiveSubscriptionInfoById(
+                    mPreferredSubscriptionService.getPreferredSubscriptionId());
+        if (optionalInfo.isPresent() && optionalInfo.get().isEmbedded()) {
+            SubscriptionInfo info = optionalInfo.get();
+            return (RoutingOptionManager.SE_PREFIX_SIM + (1 + info.getSimSlotIndex()))
+                    .getBytes(StandardCharsets.UTF_8);
+        } else {
+            return null;
+        }
+    }
+
     public void updateForShouldDefaultToObserveMode(int userId) {
         long token = Binder.clearCallingIdentity();
         try {
@@ -1740,7 +1927,9 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         mPreferredServices.onWalletRoleHolderChanged(holder, userId);
         mAidCache.onWalletRoleHolderChanged(holder, userId);
         if (Flags.exitFrames()) {
-            updateFirmwareExitFramesForWalletRole(userId);
+            mHandler.post(() -> {
+                updateFirmwareExitFramesForWalletRole(userId);
+            });
         }
     }
 
@@ -1769,4 +1958,52 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     public boolean isHostCardEmulationActivated() {
         return mHostEmulationManager.isHostCardEmulationActivated();
     }
+
+    Optional<SubscriptionInfo> getActiveSubscriptionInfoById(int subscriptionId) {
+        Log.d(TAG, "getActiveSubscriptionInfoById: " + subscriptionId);
+        if (mTelephonyUtils.isUiccSubscription(subscriptionId)) {
+            Log.d(TAG, "Get activated uicc subscription with SWP supported physical slot");
+            return mTelephonyUtils.getActiveSubscriptions().stream()
+                    .filter(TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_UICC)
+                    .filter(subscriptionInfo ->
+                                mTelephonyUtils.findPhysicalSlotIndex(subscriptionInfo)
+                                == TelephonyUtils.SWP_SUPPORTED_PHYSICAL_SIM_SLOT)
+                    .findFirst();
+        } else {
+            return mTelephonyUtils.getActiveSubscriptions().stream()
+                    .filter(TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_EUICC)
+                    .filter(subscriptionInfo ->
+                                subscriptionInfo.getSubscriptionId() == subscriptionId)
+                    .findFirst();
+        }
+    }
+
+    private int callRoutingOverridedOrRecovered() {
+        Callable<Integer> task = () -> {
+            @AidRoutingManager.ConfigureRoutingResult int status =
+                    mAidCache.onRoutingOverridedOrRecovered();
+
+            if (status == AidRoutingManager.CONFIGURE_ROUTING_SUCCESS
+                    && mRoutingChangeFuture != null) {
+                if (mRoutingChangeFuture.get() == NfcOemExtension.STATUS_OK) {
+                    return AidRoutingManager.CONFIGURE_ROUTING_SUCCESS;
+                } else {
+                    return AidRoutingManager.CONFIGURE_ROUTING_FAILURE_UNKNOWN;
+                }
+            }
+
+            return status;
+        };
+
+        try {
+            return mCommitRoutingExecutor
+                    .submit(task)
+                    .get(WAIT_FOR_ROUTING_CHANGE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
+        } catch (Exception e) {
+            Log.e(TAG, "callRoutingOverridedOrRecovered failed: " , e);
+            return AidRoutingManager.CONFIGURE_ROUTING_FAILURE_UNKNOWN;
+        } finally {
+            mRoutingChangeFuture = null;
+        }
+    }
 }
diff --git a/NfcNci/src/com/android/nfc/cardemulation/HostEmulationManager.java b/NfcNci/src/com/android/nfc/cardemulation/HostEmulationManager.java
index 25c55fd00..b9a94c778 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/HostEmulationManager.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/HostEmulationManager.java
@@ -17,6 +17,7 @@
 package com.android.nfc.cardemulation;
 
 import static com.android.nfc.module.flags.Flags.nfcHceLatencyEvents;
+import static com.android.nfc.module.flags.Flags.ceWakeLock;
 
 import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
@@ -53,6 +54,7 @@ import android.os.RemoteException;
 import android.os.SystemClock;
 import android.os.Trace;
 import android.os.UserHandle;
+import android.os.WorkSource;
 import android.sysprop.NfcProperties;
 import android.util.ArraySet;
 import android.util.Log;
@@ -88,8 +90,9 @@ import java.util.Set;
 import java.util.regex.Pattern;
 
 public class HostEmulationManager {
-    static final String TAG = "HostEmulationManager";
+    static final String TAG = "NfcHostEmulationManager";
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
+    static final boolean VDBG = NfcProperties.verbose_debug_enabled().orElse(true);
 
     static final int STATE_IDLE = 0;
     static final int STATE_W4_SELECT = 1;
@@ -136,6 +139,7 @@ public class HostEmulationManager {
     final KeyguardManager mKeyguard;
     final Object mLock;
     final PowerManager mPowerManager;
+    final PowerManager.WakeLock mWakeLock;
     private final Looper mLooper;
     final DeviceConfigFacade mDeviceConfig;
 
@@ -241,7 +245,9 @@ public class HostEmulationManager {
         @Override
         public void run() {
             synchronized (mLock) {
-                Log.d(TAG, "Have been outside field, returning to idle state");
+                Log.d(TAG,
+                        "mReturnToIdleStateRunnable: Have been outside field, "
+                                + "returning to idle state");
                 returnToIdleStateLocked();
             }
         }
@@ -331,6 +337,9 @@ public class HostEmulationManager {
         mPollingLoopState = PollingLoopState.EVALUATING_POLLING_LOOP;
         mKeyguard = context.getSystemService(KeyguardManager.class);
         mPowerManager = context.getSystemService(PowerManager.class);
+        mWakeLock = mPowerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
+                "HostEmulationManager:mWakeLock");
+        mWakeLock.setReferenceCounted(false);
         mStatsdUtils = Flags.statsdCeEventsFlag() ? statsdUtils : null;
         mPollingLoopFilters = new HashMap<Integer, Map<String, List<ApduServiceInfo>>>();
         mPollingLoopPatternFilters = new HashMap<Integer, Map<Pattern, List<ApduServiceInfo>>>();
@@ -352,7 +361,7 @@ public class HostEmulationManager {
             // check for package name explicitly.
             ComponentName preferredPaymentServiceName = preferredPaymentService.getComponentName();
             if (preferredPaymentServiceName != null) {
-                Log.d(TAG, "onBootCompleted, payment service not bound, binding");
+                Log.d(TAG, "onBootCompleted: payment service not bound, binding");
                 onPreferredPaymentServiceChanged(preferredPaymentService);
             }
         }
@@ -362,6 +371,9 @@ public class HostEmulationManager {
      *  Preferred payment service changed
      */
     public void onPreferredPaymentServiceChanged(final ComponentNameAndUser service) {
+        if (DBG) {
+            Log.d(TAG, "onPreferredPaymentServiceChanged: service=" + service);
+        }
         mHandler.post(() -> {
             synchronized (mLock) {
                 if (!isHostCardEmulationActivated()) {
@@ -402,6 +414,10 @@ public class HostEmulationManager {
 
     @TargetApi(35)
     public void updateForShouldDefaultToObserveMode(boolean enabled) {
+        if (DBG) {
+            Log.d(TAG, "updateForShouldDefaultToObserveMode: enabled=" + enabled);
+        }
+
         synchronized (mLock) {
             if (isHostCardEmulationActivated()) {
                 mEnableObserveModeAfterTransaction = enabled;
@@ -429,7 +445,13 @@ public class HostEmulationManager {
         HashMap<Pattern, List<ApduServiceInfo>> pollingLoopPatternFilters =
                 new HashMap<Pattern, List<ApduServiceInfo>>();
         for (ApduServiceInfo serviceInfo : services) {
+            if (DBG) {
+                Log.d(TAG, "updatePollingLoopFilters: service=" + serviceInfo);
+            }
             for (String plf : serviceInfo.getPollingLoopFilters()) {
+                if (DBG) {
+                    Log.d(TAG, "updatePollingLoopFilters: filter=" + plf);
+                }
                 List<ApduServiceInfo> list =
                         pollingLoopFilters.getOrDefault(plf, new ArrayList<ApduServiceInfo>());
                 list.add(serviceInfo);
@@ -437,6 +459,9 @@ public class HostEmulationManager {
 
             }
             for (Pattern plpf : serviceInfo.getPollingLoopPatternFilters()) {
+                if (DBG) {
+                    Log.d(TAG, "updatePollingLoopFilters: patternFilter=" + plpf);
+                }
                 List<ApduServiceInfo> list =
                         pollingLoopPatternFilters.getOrDefault(plpf,
                         new ArrayList<ApduServiceInfo>());
@@ -601,6 +626,7 @@ public class HostEmulationManager {
                     }
                 } else if (pollingFrame.getType()
                         == PollingFrame.POLLING_LOOP_TYPE_UNKNOWN) {
+                    if (DBG) Log.d(TAG, "onPollingLoopDetected: POLLING_LOOP_TYPE_UNKNOWN");
                     byte[] data = pollingFrame.getData();
                     String dataStr = HexFormat.of().formatHex(data).toUpperCase(Locale.ROOT);
                     List<ApduServiceInfo> serviceInfos =
@@ -630,7 +656,13 @@ public class HostEmulationManager {
                                 serviceInfo = serviceInfos.get(0);
                             }
                         }
+                        if (DBG) {
+                            Log.d(TAG, "onPollingLoopDetected: service: "
+                                    + serviceInfo.toString());
+                        }
                         if (serviceInfo.getShouldAutoTransact(dataStr)) {
+                            if (DBG) Log.d(TAG, "onPollingLoopDetected: Autotransact");
+
                             if (mStatsdUtils != null) {
                                 mStatsdUtils.logAutoTransactReported(
                                     StatsdUtils.PROCESSOR_HOST, data);
@@ -753,6 +785,9 @@ public class HostEmulationManager {
      *  Preferred foreground service changed
      */
     public void onPreferredForegroundServiceChanged(ComponentNameAndUser serviceAndUser) {
+        if (DBG) {
+            Log.d(TAG, "onPreferredForegroundServiceChanged: serviceAndUser=" + serviceAndUser);
+        }
         synchronized (mLock) {
             int userId = serviceAndUser.getUserId();
             ComponentName service = serviceAndUser.getComponentName();
@@ -785,6 +820,13 @@ public class HostEmulationManager {
         if (fieldOn && nfcHceLatencyEvents()) {
             mFieldOnTime = SystemClock.elapsedRealtime();
         }
+        if (fieldOn) {
+            // Acquire the wakelock when FIELD_ON is detected.
+            acquireWakeLock();
+        } else {
+            // Release the wakelock when FIELD_OFF is detected.
+            releaseWakeLock();
+        }
     }
 
     public void onHostEmulationActivated() {
@@ -806,29 +848,6 @@ public class HostEmulationManager {
         }
     }
 
-    static private class UnroutableAidBugReportRunnable implements Runnable {
-        List<String> mUnroutedAids;
-
-        UnroutableAidBugReportRunnable(String aid) {
-            mUnroutedAids = new ArrayList<String>(1);
-            mUnroutedAids.add(aid);
-        }
-
-        void addAid(String aid) {
-            mUnroutedAids.add(aid);
-        }
-        @Override
-        public void run() {
-            NfcService.getInstance().mNfcDiagnostics.takeBugReport(
-                    "NFC tap failed."
-                        + " (If you weren't using NFC, "
-                        + "no need to submit this report.)",
-                    "Couldn't route " + String.join(", ", mUnroutedAids));
-        }
-    }
-
-    UnroutableAidBugReportRunnable mUnroutableAidBugReportRunnable = null;
-
     public void onHostEmulationData(byte[] data) {
         Log.d(TAG, "onHostEmulationData");
         mHandler.removeCallbacks(mEnableObserveModeAfterTransactionRunnable);
@@ -865,15 +884,6 @@ public class HostEmulationManager {
                         if (android.nfc.Flags.nfcEventListener()) {
                             notifyAidNotRoutedListener(selectAid);
                         }
-                        if (mUnroutableAidBugReportRunnable != null) {
-                            mUnroutableAidBugReportRunnable.addAid(selectAid);
-                        } else {
-                            mUnroutableAidBugReportRunnable =
-                                    new UnroutableAidBugReportRunnable(selectAid);
-                            /* Wait 1s to see if there is an alternate AID we can route before
-                             * taking a bug report */
-                            mHandler.postDelayed(mUnroutableAidBugReportRunnable, 1000);
-                        }
                     }
                     NfcInjector.getInstance().getNfcEventLog().logEvent(
                             NfcEventProto.EventType.newBuilder()
@@ -885,10 +895,6 @@ public class HostEmulationManager {
                     // Tell the remote we don't handle this AID
                     NfcService.getInstance().sendData(AID_NOT_FOUND);
                     return;
-                } else if (mUnroutableAidBugReportRunnable != null) {
-                    /* If there is a pending bug report runnable, cancel it. */
-                    mHandler.removeCallbacks(mUnroutableAidBugReportRunnable);
-                    mUnroutableAidBugReportRunnable = null;
                 }
                 mLastSelectedAid = selectAid;
                 if (resolveInfo.defaultService != null) {
@@ -954,6 +960,7 @@ public class HostEmulationManager {
                         mStatsdUtils.setCardEmulationEventCategory(CardEmulation.CATEGORY_OTHER);
                         mStatsdUtils.logCardEmulationWrongSettingEvent();
                     }
+                    if (DBG) Log.d(TAG, "onHostEmulationData: AID conflict, launch resolver");
                     launchResolver(selectAid, (ArrayList<ApduServiceInfo>)resolveInfo.services,
                         null, resolveInfo.category);
                     return;
@@ -1086,8 +1093,8 @@ public class HostEmulationManager {
         }
     }
 
-    public void onOffHostAidSelected() {
-        Log.d(TAG, "onOffHostAidSelected");
+    public void onOffHostAidSelectedOrTransaction() {
+        Log.d(TAG, "onOffHostAidSelectedOrTransaction");
         synchronized (mLock) {
             mHandler.removeCallbacks(mEnableObserveModeAfterTransactionRunnable);
             rescheduleInactivityChecks();
@@ -1112,10 +1119,45 @@ public class HostEmulationManager {
         }
     }
 
+    private void acquireWakeLock() {
+        if (!ceWakeLock() || mDeviceConfig.getCeWakeLockTimeoutMillis() == 0) return;
+        Log.d(TAG, "acquireWakeLock");
+        mWakeLock.setWorkSource(null); // reset work source from previous transaction
+        mWakeLock.acquire(mDeviceConfig.getCeWakeLockTimeoutMillis());
+    }
+
+    private void updateWakeLockWorkSource(ComponentNameAndUser componentNameAndUser) {
+        if (!ceWakeLock() || !mWakeLock.isHeld()) return;
+        Log.d(TAG, "updateWakeLockWorkSource: " + componentNameAndUser);
+        final String packageName = componentNameAndUser.getComponentName().getPackageName();
+        try {
+            int uid = mContext.getPackageManager().getPackageUidAsUser(
+                    packageName,
+                    PackageManager.PackageInfoFlags.of(0),
+                    componentNameAndUser.getUserId()
+            );
+            // Re-acquire the wake lock with the new work source.
+            mWakeLock.setWorkSource(new WorkSource(uid, packageName));
+            mWakeLock.acquire(mDeviceConfig.getCeWakeLockTimeoutMillis());
+        } catch (PackageManager.NameNotFoundException e) {
+            Log.w(TAG, "Failed to find uid for " + packageName + " and user "
+                    + componentNameAndUser.getUserId());
+        }
+    }
+
+    private void releaseWakeLock() {
+        if (!ceWakeLock() || !mWakeLock.isHeld()) return;
+        Log.d(TAG, "releaseWakeLock");
+        mWakeLock.release();
+        mWakeLock.setWorkSource(null);
+    }
+
     Messenger bindServiceIfNeededLocked(@UserIdInt int userId, ComponentName service) {
         if (service == null) {
             Log.e(TAG, "bindServiceIfNeededLocked: service ComponentName is null");
             return null;
+        } else {
+            if (VDBG) Log.d(TAG, "bindServiceIfNeededLocked: service: " + service);
         }
 
         ComponentNameAndUser preferredPaymentService = mAidCache.getPreferredPaymentService();
@@ -1123,14 +1165,20 @@ public class HostEmulationManager {
         ComponentName preferredPaymentServiceName = preferredPaymentService.getComponentName();
         ComponentNameAndUser newServiceAndUser = new ComponentNameAndUser(userId, service);
 
+        // When the service to handle this transaction is found, update the worksource
+        // to share the power blame.
+        updateWakeLockWorkSource(newServiceAndUser);
+
         if (mPaymentServiceName != null && mPaymentServiceName.equals(service)
                 && mPaymentServiceUserId == userId) {
-            Log.d(TAG, "bindServiceIfNeededLocked: Service already bound as payment service.");
+            if (VDBG) {
+                Log.d(TAG, "bindServiceIfNeededLocked: Service already bound as payment service");
+            }
             return mPaymentService;
         } else if (!mPaymentServiceBound && preferredPaymentServiceName != null
                 && preferredPaymentServiceName.equals(service)
                 && preferredPaymentUserId == userId) {
-            Log.d(TAG, "bindServiceIfNeededLocked: Service should be bound as "
+            Log.w(TAG, "bindServiceIfNeededLocked: Service should be bound as "
                     + "payment service but is not, binding now");
             bindPaymentServiceLocked(userId, preferredPaymentServiceName);
             return null;
@@ -1138,13 +1186,17 @@ public class HostEmulationManager {
                 && mServiceName != null
                 && mServiceName.equals(service)
                 && mServiceUserId == userId) {
-            Log.d(TAG, "bindServiceIfNeededLocked: Service already bound as regular service.");
+            if (VDBG) {
+                Log.d(TAG, "bindServiceIfNeededLocked: Service already bound as regular service");
+            }
             return mService;
         } else if (isMultipleBindingSupported()
                 && mComponentNameToConnectionsMap.containsKey(newServiceAndUser)
                 && mComponentNameToConnectionsMap.get(newServiceAndUser).mMessenger != null) {
-            Log.d(TAG, "bindServiceIfNeededLocked: Service" + service
-                    + " already bound as regular service.");
+            if (VDBG) {
+                Log.d(TAG, "bindServiceIfNeededLocked: Service" + service
+                        + " already bound as regular service");
+            }
             return mComponentNameToConnectionsMap.get(newServiceAndUser).mMessenger;
         } else {
             Log.d(TAG, "bindServiceIfNeededLocked: Binding to service " + service + " for userId:"
@@ -1180,7 +1232,7 @@ public class HostEmulationManager {
                     if (nfcHceLatencyEvents()) {
                         Trace.endAsyncSection(EVENT_HCE_BIND_SERVICE, 0);
                     }
-                    Log.e(TAG, "bindServiceIfNeededLocked: Could not bind service.");
+                    Log.e(TAG, "bindServiceIfNeededLocked: Could not bind service");
                 } else {
                     mServiceUserId = userId;
                 }
@@ -1189,7 +1241,7 @@ public class HostEmulationManager {
                     Trace.endAsyncSection(EVENT_HCE_BIND_SERVICE, 0);
                 }
                 Log.e(TAG, "bindServiceIfNeededLocked: Could not bind service "
-                        + "due to security exception.");
+                        + "due to security exception");
             }
             return null;
         }
@@ -1202,6 +1254,8 @@ public class HostEmulationManager {
     }
 
     void sendDataToServiceLocked(Messenger service, byte[] data) {
+        if (DBG) Log.d(TAG, "sendDataToServiceLocked");
+
         mState = STATE_XFER;
 
         int cookie = 0;
@@ -1302,6 +1356,8 @@ public class HostEmulationManager {
     }
 
     void sendDeactivateToActiveServiceLocked(int reason) {
+        if (DBG) Log.d(TAG, "sendDeactivateToActiveServiceLocked: reason: " + reason);
+
         if (mActiveService == null) return;
         Message msg = Message.obtain(null, HostApduService.MSG_DEACTIVATED);
         msg.arg1 = reason;
@@ -1313,8 +1369,8 @@ public class HostEmulationManager {
     }
 
     void unbindPaymentServiceLocked() {
-        Log.d(TAG, "unbindPaymentServiceLocked");
         if (mPaymentServiceBound) {
+            Log.d(TAG, "unbindPaymentServiceLocked: " + mPaymentServiceName);
             try {
                 mContext.unbindService(mPaymentConnection);
                 if (isMultipleBindingSupported()) {
@@ -1339,7 +1395,7 @@ public class HostEmulationManager {
         }
         unbindPaymentServiceLocked();
 
-        Log.d(TAG, "bindPaymentServiceLocked:" + serviceName + " for userId:" + userId);
+        Log.d(TAG, "bindPaymentServiceLocked: " + serviceName + " for userId=" + userId);
         Intent intent = new Intent(HostApduService.SERVICE_INTERFACE);
         intent.setComponent(serviceName);
         try {
@@ -1401,6 +1457,9 @@ public class HostEmulationManager {
     }
 
     void launchTapAgain(ApduServiceInfo service, String category) {
+        if (DBG) {
+            Log.d(TAG, "launchTapAgain: service=" + service.toString() + ", category=" + category);
+        }
         if (mNfcOemExtensionCallback != null) {
             try {
                 mNfcOemExtensionCallback.onLaunchHceTapAgainActivity(service, category);
@@ -1729,6 +1788,7 @@ public class HostEmulationManager {
                 }
             }
             if (msg.what == HostApduService.MSG_RESPONSE_APDU) {
+                if (DBG) Log.d(TAG, "handleMessage: MSG_RESPONSE_APDU");
                 Bundle dataBundle = msg.getData();
                 if (dataBundle == null) {
                     return;
@@ -1780,6 +1840,9 @@ public class HostEmulationManager {
                     }
                 }
             } else if (msg.what == HostApduService.MSG_COMMAND_APDU_ACK) {
+                if (DBG) {
+                    Log.d(TAG, "handleMessage: MSG_COMMAND_APDU_ACK");
+                }
                 if (nfcHceLatencyEvents()) {
                     Trace.endAsyncSection(EVENT_HCE_COMMAND_APDU, msg.arg1);
                 }
diff --git a/NfcNci/src/com/android/nfc/cardemulation/PreferredServices.java b/NfcNci/src/com/android/nfc/cardemulation/PreferredServices.java
index d38207c3c..daed09fb5 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/PreferredServices.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/PreferredServices.java
@@ -63,7 +63,7 @@ import java.util.Objects;
  * mappings and the routing table).
  */
 public class PreferredServices implements com.android.nfc.ForegroundUtils.Callback {
-    static final String TAG = "PreferredCardEmulationServices";
+    static final String TAG = "NFCPreferredServices";
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
     static final Uri paymentDefaultUri = Settings.Secure.getUriFor(
             Constants.SETTINGS_SECURE_NFC_PAYMENT_DEFAULT_COMPONENT);
@@ -163,12 +163,12 @@ public class PreferredServices implements com.android.nfc.ForegroundUtils.Callba
     };
 
     @TargetApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
-    public void onWalletRoleHolderChanged(String defaultWalletHolderPackageName, int userId) {
+    public boolean onWalletRoleHolderChanged(String defaultWalletHolderPackageName, int userId) {
         if (defaultWalletHolderPackageName == null) {
             mDefaultWalletHolderPaymentService = null;
             mUserIdDefaultWalletHolder = userId;
             mCallback.onPreferredPaymentServiceChanged(new ComponentNameAndUser(userId, null));
-            return;
+            return true;
         }
         List<ApduServiceInfo> serviceInfos = mServiceCache.getInstalledServices(userId);
         List<ComponentName> roleHolderPaymentServices = new ArrayList<>();
@@ -197,7 +197,9 @@ public class PreferredServices implements com.android.nfc.ForegroundUtils.Callba
             mDefaultWalletHolderPaymentService = candidate;
             mUserIdDefaultWalletHolder = userId;
             mCallback.onPreferredPaymentServiceChanged(new ComponentNameAndUser(userId, candidate));
+            return true;
         }
+        return false;
     }
 
     void loadDefaultsFromSettings(int userId, boolean force) {
@@ -326,7 +328,10 @@ public class PreferredServices implements com.android.nfc.ForegroundUtils.Callba
         return true;
     }
 
-    public void onServicesUpdated() {
+    /**
+     * @return true if the foreground service or wallet role holder has changed.
+     */
+    public boolean onServicesUpdated() {
         // If this service is the current foreground service, verify
         // there are no conflicts
         boolean foregroundChanged = false;
@@ -350,12 +355,15 @@ public class PreferredServices implements com.android.nfc.ForegroundUtils.Callba
             computePreferredForegroundService();
         }
 
+        boolean walletRoleHolderChanged = false;
         if (mWalletRoleObserver.isWalletRoleFeatureEnabled()
                 && mUserIdDefaultWalletHolder >= 0) {
             PackageAndUser roleHolder = mWalletRoleObserver
                     .getDefaultWalletRoleHolder(mUserIdDefaultWalletHolder);
-            onWalletRoleHolderChanged(roleHolder.getPackage(), roleHolder.getUserId());
+            walletRoleHolderChanged =
+                onWalletRoleHolderChanged(roleHolder.getPackage(), roleHolder.getUserId());
         }
+        return foregroundChanged || walletRoleHolderChanged;
     }
 
     // Verifies whether a service is allowed to register as preferred
diff --git a/NfcNci/src/com/android/nfc/cardemulation/PreferredSubscriptionService.java b/NfcNci/src/com/android/nfc/cardemulation/PreferredSubscriptionService.java
index de741abb9..405a412c4 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/PreferredSubscriptionService.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/PreferredSubscriptionService.java
@@ -28,7 +28,7 @@ import java.util.List;
 import java.util.stream.Collectors;
 
 public class PreferredSubscriptionService implements TelephonyUtils.Callback {
-    static final String TAG = "PreferredSubscriptionService";
+    static final String TAG = "NFCPreferredSubscriptionService";
     static final String PREF_SUBSCRIPTION = "SubscriptionPref";
     static final String PREF_PREFERRED_SUB_ID = "pref_sub_id";
     private SharedPreferences mSubscriptionPrefs = null;
@@ -63,8 +63,8 @@ public class PreferredSubscriptionService implements TelephonyUtils.Callback {
         if (mIsUiccCapable || mIsEuiccCapable) {
             mDefaultSubscriptionId = getPreferredSubscriptionId();
             if (mDefaultSubscriptionId == TelephonyUtils.SUBSCRIPTION_ID_UNKNOWN) {
-                Log.d(TAG, "PreferredSubscriptionService: Set preferred subscription "
-                        + "to UICC, only update");
+                Log.d(TAG, "Set preferred subscription to UICC forcely, because currently unknown"
+                    + " state");
                 setPreferredSubscriptionId(TelephonyUtils.SUBSCRIPTION_ID_UICC, false);
             }
         }
@@ -105,8 +105,7 @@ public class PreferredSubscriptionService implements TelephonyUtils.Callback {
 
     @Override
     public void onActiveSubscriptionsUpdated(List<SubscriptionInfo> activeSubscriptionList) {
-        boolean isActivationStateChanged = checkSubscriptionStateChanged(activeSubscriptionList);
-        if (isActivationStateChanged) {
+        if (checkSubscriptionStateChanged(activeSubscriptionList)) {
             mCallback.onPreferredSubscriptionChanged(mDefaultSubscriptionId,
                     mActiveSubscriptoinState == TelephonyUtils.SUBSCRIPTION_STATE_ACTIVATE);
         } else {
@@ -116,30 +115,40 @@ public class PreferredSubscriptionService implements TelephonyUtils.Callback {
 
     private boolean isSubscriptionActivated(int subscriptionId) {
         if (mActiveSubscriptions == null) {
-            Log.d(TAG, "isSubscriptionActivated: get active subscriptions is "
-                    + "list because it's null");
-            mActiveSubscriptions = mTelephonyUtils.getActiveSubscriptions().stream().filter(
-                            TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_UICC.or(
-                                    TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_EUICC))
+            Log.d(TAG, "Get active subscriptions because list is empty");
+            mActiveSubscriptions = mTelephonyUtils.getActiveSubscriptions().stream()
+                    .filter(TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_UICC
+                            .or(TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_EUICC))
                     .collect(Collectors.toList());
         }
-        boolean isEuiccSubscription = mTelephonyUtils.isEuiccSubscription(subscriptionId);
-        return mActiveSubscriptions.stream().anyMatch(subscriptionInfo ->
-                subscriptionInfo.isEmbedded() == isEuiccSubscription);
+
+        if (mTelephonyUtils.isUiccSubscription(subscriptionId)) {
+            Log.d(TAG, "Check uicc subscription activated status with SWP supported physical slot");
+            return mActiveSubscriptions.stream()
+                    .filter(TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_UICC)
+                    .anyMatch(subscriptionInfo ->
+                                  mTelephonyUtils.findPhysicalSlotIndex(subscriptionInfo)
+                                  == TelephonyUtils.SWP_SUPPORTED_PHYSICAL_SIM_SLOT);
+        } else {
+            return mActiveSubscriptions.stream()
+                    .filter(TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_EUICC)
+                    .anyMatch(subscriptionInfo ->
+                                  subscriptionInfo.getSubscriptionId() == subscriptionId);
+        }
     }
 
     private boolean checkSubscriptionStateChanged(List<SubscriptionInfo> activeSubscriptionList) {
         // filtered subscriptions
-        mActiveSubscriptions = activeSubscriptionList.stream().filter(
-                        TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_UICC.or(
-                                TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_EUICC))
+        mActiveSubscriptions = activeSubscriptionList.stream()
+                .filter(TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_UICC
+                        .or(TelephonyUtils.SUBSCRIPTION_ACTIVE_CONDITION_FOR_EUICC))
                 .collect(Collectors.toList());
         int previousActiveSubscriptionState = mActiveSubscriptoinState;
         int currentActiveSubscriptionState = isSubscriptionActivated(mDefaultSubscriptionId) ?
                 TelephonyUtils.SUBSCRIPTION_STATE_ACTIVATE :
                 TelephonyUtils.SUBSCRIPTION_STATE_INACTIVATE;
         if (previousActiveSubscriptionState != currentActiveSubscriptionState) {
-            Log.d(TAG, "checkSubscriptionStateChanged: state changed: "
+            Log.d(TAG, "active subscription state changed "
                     + previousActiveSubscriptionState + " to " + currentActiveSubscriptionState);
             mActiveSubscriptoinState = currentActiveSubscriptionState;
             return true;
diff --git a/NfcNci/src/com/android/nfc/cardemulation/RegisteredAidCache.java b/NfcNci/src/com/android/nfc/cardemulation/RegisteredAidCache.java
index 500b3a65a..c45efe855 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/RegisteredAidCache.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/RegisteredAidCache.java
@@ -56,11 +56,11 @@ import java.util.TreeMap;
 import java.util.stream.Collectors;
 
 public class RegisteredAidCache {
-    static final String TAG = "RegisteredAidCache";
+    static final String TAG = "NfcRegisteredAidCache";
     private INfcOemExtensionCallback mNfcOemExtensionCallback;
 
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
-    private static final boolean VDBG = false; // turn on for local testing.
+    static final boolean VDBG = NfcProperties.verbose_debug_enabled().orElse(true);
 
     static final int AID_ROUTE_QUAL_SUBSET = 0x20;
     static final int AID_ROUTE_QUAL_PREFIX = 0x10;
@@ -367,14 +367,14 @@ public class RegisteredAidCache {
     private static void nonDefaultRouting(AidResolveInfo resolveInfo,
             boolean makeSingleServiceDefault) {
         if (resolveInfo.services.size() == 1 && makeSingleServiceDefault) {
-            if (DBG)  {
+            if (VDBG) {
                 Log.d(TAG, "nonDefaultRouting: DECISION: making single handling service "
                         + resolveInfo.services.get(0).getComponent() + " default.");
             }
             resolveInfo.defaultService = resolveInfo.services.get(0);
         } else {
             // Nothing to do, all services already in list
-            if (DBG)  {
+            if (VDBG) {
                 Log.d(TAG, "nonDefaultRouting: DECISION: routing to all matching services");
             }
         }
@@ -516,7 +516,7 @@ public class RegisteredAidCache {
             } else {
                 if (componentName.equals(mPreferredPaymentService)
                         && userId == mUserIdPreferredPaymentService && serviceClaimsPaymentAid) {
-                    if (DBG) {
+                    if (VDBG) {
                         Log.d(TAG, "resolveAidConflictLocked: Prioritizing dpp services");
                     }
                     resolveInfo.services.add(serviceAidInfo.service);
@@ -530,7 +530,7 @@ public class RegisteredAidCache {
         if (matchedForeground != null) {
             // 1st priority: if the foreground app prefers a service,
             // and that service asks for the AID, that service gets it
-            if (DBG) {
+            if (VDBG) {
                 Log.d(TAG, "resolveAidConflictLocked: DECISION: routing to foreground preferred "
                         + matchedForeground);
             }
@@ -586,14 +586,23 @@ public class RegisteredAidCache {
             if (componentName.equals(mPreferredForegroundService) &&
                     userId == mUserIdPreferredForegroundService) {
                 defaultServiceInfo.foregroundDefault = serviceAidInfo;
+                if (DBG && (serviceAidInfo != null)) {
+                    Log.d(TAG, "findDefaultServices: foregroundDefault=" + serviceAidInfo);
+                }
             } else if (mWalletRoleObserver.isWalletRoleFeatureEnabled()) {
                 if (isDefaultOrAssociatedWalletService(serviceAidInfo.service, userId)) {
                     defaultServiceInfo.walletDefaults.add(serviceAidInfo);
+                    if (DBG && (serviceAidInfo != null)) {
+                        Log.d(TAG, "findDefaultServices: walletDefaults=" + serviceAidInfo);
+                    }
                 }
             }else if (componentName.equals(mPreferredPaymentService) &&
                     userId == mUserIdPreferredPaymentService &&
                     serviceClaimsPaymentAid) {
                 defaultServiceInfo.paymentDefault = serviceAidInfo;
+                if (DBG && (serviceAidInfo != null)) {
+                    Log.d(TAG, "findDefaultServices: paymentDefault=" + serviceAidInfo);
+                }
             }
         }
         return defaultServiceInfo;
@@ -603,7 +612,7 @@ public class RegisteredAidCache {
             ArrayList<ServiceAidInfo> conflictingServices) {
         // No children that are preferred; add all services of the root
         // make single service default if no children are present
-        if (DBG) Log.d(TAG, "noChildrenAidsPreferred: No service has preference, adding all");
+        if (VDBG) Log.d(TAG, "noChildrenAidsPreferred: No service has preference, adding all");
         AidResolveInfo resolveinfo =
                 resolveAidConflictLocked(aidServices, conflictingServices.isEmpty());
         //If the AID is subsetAID check for conflicting prefix in all
@@ -636,7 +645,7 @@ public class RegisteredAidCache {
         //    no child is the current foreground preferred
         // 4. There is only one service for the root AID, and there are no children
         if (aidDefaultInfo.foregroundDefault != null) {
-            if (DBG) {
+            if (VDBG) {
                 Log.d(TAG,
                         "resolveAidConflictLocked: Prefix AID service "
                                 + aidDefaultInfo.foregroundDefault.service.getComponent()
@@ -656,14 +665,14 @@ public class RegisteredAidCache {
                 // Check if any of the conflicting services is foreground default
                 if (conflictingDefaultInfo.foregroundDefault != null) {
                     // Conflicting AID registration is in foreground, trumps prefix tap&pay default
-                    if (DBG) {
+                    if (VDBG) {
                         Log.d(TAG, "resolveAidConflictLocked: One of the conflicting AID "
                                 + "registrations is foreground preferred, ignoring prefix");
                     }
                     return EMPTY_RESOLVE_INFO;
                 } else {
                     // Prefix service is default wallet, treat as normal AID conflict for just prefix
-                    if (DBG) {
+                    if (VDBG) {
                         Log.d(TAG, "resolveAidConflictLocked: Default wallet app exists. "
                                 + "ignoring conflicting AIDs");
                     }
@@ -679,7 +688,7 @@ public class RegisteredAidCache {
             } else {
                 if (conflictingDefaultInfo.foregroundDefault != null ||
                         !conflictingDefaultInfo.walletDefaults.isEmpty()) {
-                    if (DBG) {
+                    if (VDBG) {
                         Log.d(TAG, "resolveAidConflictLocked: One of the conflicting "
                                 + "AID registrations "
                                 + "is wallet holder or foreground preferred, ignoring prefix");
@@ -693,14 +702,14 @@ public class RegisteredAidCache {
             // Check if any of the conflicting services is foreground default
             if (conflictingDefaultInfo.foregroundDefault != null) {
                 // Conflicting AID registration is in foreground, trumps prefix tap&pay default
-                if (DBG) {
+                if (VDBG) {
                     Log.d(TAG, "resolveAidConflictLocked: One of the conflicting AID "
                             + "registrations is foreground preferred, ignoring prefix");
                 }
                 return EMPTY_RESOLVE_INFO;
             } else {
                 // Prefix service is tap&pay default, treat as normal AID conflict for just prefix
-                if (DBG) {
+                if (VDBG) {
                     Log.d(TAG,
                             "resolveAidConflictLocked: Prefix AID service "
                                     + aidDefaultInfo.paymentDefault.service.getComponent()
@@ -717,7 +726,7 @@ public class RegisteredAidCache {
         } else {
             if (conflictingDefaultInfo.foregroundDefault != null ||
                     conflictingDefaultInfo.paymentDefault != null) {
-                if (DBG) {
+                if (VDBG) {
                     Log.d(TAG,
                             "resolveAidConflictLocked: One of the conflicting AID "
                                     + "registrations is either payment "
@@ -748,6 +757,9 @@ public class RegisteredAidCache {
     }
 
     void generateServiceMapLocked(List<ApduServiceInfo> services) {
+        if (DBG) {
+            Log.d(TAG, "generateServiceMapLocked: nb services=" + services.size());
+        }
         // Easiest is to just build the entire tree again
         mAidServices.clear();
         int currentUser = ActivityManager.getCurrentUser();
@@ -761,8 +773,20 @@ public class RegisteredAidCache {
                 continue;
             }
             for (ApduServiceInfo service : entry.getValue()) {
-                if (VDBG) {
-                    Log.d(TAG, "generateServiceMapLocked: component: " + service.getComponent());
+                if (DBG) {
+                    String category = null;
+                    if (service.hasCategory(CardEmulation.CATEGORY_OTHER)) {
+                        category = CardEmulation.CATEGORY_OTHER;
+                    } else {
+                        category = CardEmulation.CATEGORY_PAYMENT;
+                    }
+
+                    String route = "DH";
+                    if (!service.isOnHost()) {
+                        route = service.getOffHostSecureElement();
+                    }
+                    Log.d(TAG, "generateServiceMapLocked: component=" + service.getComponent()
+                            + ", category=" + category + ", route=" + route);
                 }
                 List<String> prefixAids = service.getPrefixAids();
                 List<String> subSetAids = service.getSubsetAids();
@@ -905,7 +929,7 @@ public class RegisteredAidCache {
         AidConflicts prefixConflicts = new AidConflicts();
         String plainAid = prefixAid.substring(0, prefixAid.length() - 1); // Cut off "*"
         String lastAidWithPrefix = String.format("%-32s", plainAid).replace(' ', 'F');
-        if (DBG) {
+        if (VDBG) {
             Log.d(TAG, "findConflictsForPrefixLocked: Finding AIDs in range [" + plainAid + " - "
                     + lastAidWithPrefix + "]");
         }
@@ -914,11 +938,11 @@ public class RegisteredAidCache {
         for (Map.Entry<String, ArrayList<ServiceAidInfo>> entry :
                 prefixConflicts.conflictMap.entrySet()) {
             if (!entry.getKey().equalsIgnoreCase(prefixAid)) {
-                if (DBG)
-                    Log.d(TAG,
-                            "findConflictsForPrefixLocked: AID " + entry.getKey()
-                                    + " conflicts with prefix; "
-                                    + " adding handling services for conflict resolution.");
+                if (VDBG) {
+                    Log.d(TAG, "findConflictsForPrefixLocked: AID " + entry.getKey()
+                            + " conflicts with prefix; "
+                            + " adding handling services for conflict resolution.");
+                }
                 prefixConflicts.services.addAll(entry.getValue());
                 prefixConflicts.aids.add(entry.getKey());
             }
@@ -970,6 +994,10 @@ public class RegisteredAidCache {
         //aidCache is temproary cache for geenrating the first prefix based lookup table.
         PriorityQueue<String> aidsToResolve = new PriorityQueue<String>(mAidServices.keySet());
         aidCache.clear();
+        if (DBG) {
+            Log.d(TAG, "generateAidCacheLocked: Nb of AIDs to process=" + aidsToResolve.size());
+        }
+
         while (!aidsToResolve.isEmpty()) {
             final ArrayList<String> resolvedAids = new ArrayList<String>();
 
@@ -983,7 +1011,7 @@ public class RegisteredAidCache {
             if (aidsToResolve.contains(aidToResolve + "*")) {
                 aidToResolve = aidToResolve + "*";
             }
-            if (DBG) Log.d(TAG, "generateAidCacheLocked: starting with aid " + aidToResolve);
+            if (VDBG) Log.d(TAG, "generateAidCacheLocked: starting with aid " + aidToResolve);
 
             if (isPrefix(aidToResolve)) {
                 // This AID itself is a prefix; let's consider this prefix as the "root",
@@ -1017,8 +1045,10 @@ public class RegisteredAidCache {
                                      userId == mUserIdPreferredForegroundService)) {
                                 AidResolveInfo childResolveInfo = resolveAidConflictLocked(mAidServices.get(aid), false);
                                 aidCache.put(aid,childResolveInfo);
-                                Log.d(TAG, "generateAidCacheLocked: AID " + aid
-                                        + " shared with prefix; adding subset .");
+                                if (VDBG) {
+                                    Log.d(TAG, "generateAidCacheLocked: AID " + aid
+                                            + " shared with prefix; adding subset ");
+                                }
                              }
                         }
                    }
@@ -1030,11 +1060,11 @@ public class RegisteredAidCache {
                     for (Map.Entry<String, ArrayList<ServiceAidInfo>> entry :
                             prefixConflicts.conflictMap.entrySet()) {
                         if (!entry.getKey().equalsIgnoreCase(aidToResolve)) {
-                            if (DBG)
-                                Log.d(TAG,
-                                        "generateAidCacheLocked: AID " + entry.getKey()
-                                                + " shared with prefix; "
-                                                + " adding all handling services.");
+                            if (VDBG) {
+                                Log.d(TAG, "generateAidCacheLocked: AID " + entry.getKey()
+                                        + " shared with prefix; "
+                                        + " adding all handling services");
+                            }
                             AidResolveInfo childResolveInfo = resolveAidConflictLocked(
                                     entry.getValue(), false);
                             // Special case: in this case all children AIDs must be routed to the
@@ -1064,7 +1094,7 @@ public class RegisteredAidCache {
                 // Exact AID and no other conflicting AID registrations present
                 // This is true because aidsToResolve is lexicographically ordered, and
                 // so by necessity all other AIDs are different than this AID or longer.
-                if (DBG) Log.d(TAG, "generateAidCacheLocked: Exact AID, resolving.");
+                if (VDBG) Log.d(TAG, "generateAidCacheLocked: Exact AID, resolving.");
                 final ArrayList<ServiceAidInfo> conflictingServiceInfos =
                         new ArrayList<ServiceAidInfo>(mAidServices.get(aidToResolve));
                 aidCache.put(aidToResolve, resolveAidConflictLocked(conflictingServiceInfos, true));
@@ -1072,7 +1102,7 @@ public class RegisteredAidCache {
             }
 
             // Remove the AIDs we resolved from the list of AIDs to resolve
-            if (DBG) {
+            if (VDBG) {
                 Log.d(TAG, "generateAidCacheLocked: AIDs: " + resolvedAids + " were resolved.");
             }
             aidsToResolve.removeAll(resolvedAids);
@@ -1086,14 +1116,14 @@ public class RegisteredAidCache {
             String aidToResolve = reversedQueue.peek();
             if (isPrefix(aidToResolve)) {
                 String matchingSubset = aidToResolve.substring(0, aidToResolve.length() - 1) + "#";
-                if (DBG) {
+                if (VDBG) {
                     Log.d(TAG, "generateAidCacheLocked: matching subset" + matchingSubset);
                 }
                 if (reversedQueue.contains(matchingSubset))
                      aidToResolve = aidToResolve.substring(0,aidToResolve.length()-1) + "#";
             }
             if (isSubset(aidToResolve)) {
-                if (DBG) {
+                if (VDBG) {
                     Log.d(TAG, "generateAidCacheLocked: subset resolving aidToResolve  "
                             + aidToResolve);
                 }
@@ -1113,12 +1143,13 @@ public class RegisteredAidCache {
                     // will no longer be evaluated.Check for any prefix matching in the same service
                     if (resolveInfo.prefixInfo != null && resolveInfo.prefixInfo.prefixAid != null &&
                             !resolveInfo.prefixInfo.matchingSubset) {
-                        if (DBG)
+                        if (VDBG) {
                             Log.d(TAG,
                                     "generateAidCacheLocked: AID default "
                                             + resolveInfo.prefixInfo.prefixAid
                                             + " prefix AID shared with dsubset root; "
                                             + " adding prefix aid");
+                        }
                         AidResolveInfo childResolveInfo = resolveAidConflictLocked(
                         mAidServices.get(resolveInfo.prefixInfo.prefixAid), false);
                         mAidCache.put(resolveInfo.prefixInfo.prefixAid, childResolveInfo);
@@ -1133,11 +1164,12 @@ public class RegisteredAidCache {
                         aidConflicts.conflictMap.entrySet()) {
                         // We need to add shortest prefix among them.
                         if (!entry.getKey().equalsIgnoreCase(aidToResolve)) {
-                            if (DBG)
+                            if (VDBG) {
                                 Log.d(TAG,
                                         "generateAidCacheLocked: AID " + entry.getKey()
                                                 + " shared with subset root; "
-                                                + " adding all handling services.");
+                                                + " adding all handling services");
+                            }
                             AidResolveInfo childResolveInfo = resolveAidConflictLocked(
                                 entry.getValue(), false);
                             // Special case: in this case all children AIDs must be routed to the
@@ -1160,12 +1192,13 @@ public class RegisteredAidCache {
                         AidResolveInfo childResolveInfo = resolveAidConflictLocked(
                         mAidServices.get(resolveInfo.prefixInfo.prefixAid), false);
                         mAidCache.put(resolveInfo.prefixInfo.prefixAid, childResolveInfo);
-                        if (DBG)
+                        if (VDBG) {
                             Log.d(TAG,
                                     "generateAidCacheLocked: AID "
                                             + resolveInfo.prefixInfo.prefixAid
                                             + " prefix AID shared with subset root; "
                                             + " adding prefix aid");
+                        }
                     }
                     // Special case: if in the end we didn't add any children services,
                     // and the subset has only one service, make that default
@@ -1180,7 +1213,7 @@ public class RegisteredAidCache {
                 // Exact AID and no other conflicting AID registrations present. This is
                 // true because reversedQueue is lexicographically ordered in revrese, and
                 // so by necessity all other AIDs are different than this AID or shorter.
-                if (DBG) {
+                if (VDBG) {
                     Log.d(TAG, "generateAidCacheLocked: Exact or Prefix AID." + aidToResolve);
                 }
                 mAidCache.put(aidToResolve, aidCache.get(aidToResolve));
@@ -1188,15 +1221,15 @@ public class RegisteredAidCache {
             }
 
             // Remove the AIDs we resolved from the list of AIDs to resolve
-            if (DBG) {
+            if (VDBG) {
                 Log.d(TAG, "generateAidCacheLocked: AIDs: " + resolvedAids + " were resolved.");
             }
             reversedQueue.removeAll(resolvedAids);
             resolvedAids.clear();
         }
-        if (DBG)  {
+        if (VDBG)  {
             for (String key : mAidCache.keySet()) {
-                Log.d(TAG, "generateAidCacheLocked: aid cache entry" + key + " val:"
+                Log.d(TAG, "generateAidCacheLocked: aid=" + key + " val="
                         + mAidCache.get(key).toString());
             }
         }
@@ -1321,9 +1354,11 @@ public class RegisteredAidCache {
                             offHostSE = service.getOffHostSecureElement();
                             requiresUnlock = service.requiresUnlock();
                             requiresScreenOn = service.requiresScreenOn();
-                        } else if (!offHostSE.equals(
-                                service.getOffHostSecureElement())) {
-                            // There are registrations to different SEs, route this
+                        } else if (service.getOffHostSecureElement() != null
+                                       && !offHostSE.equals(
+                                           service.getOffHostSecureElement())) {
+                            // if getOffHostSecureElement() is null, assume it is same SE
+                            // else, there are registrations to different SEs, route this
                             // to host and have user choose a service for this AID
                             offHostSE = null;
                             onHost = true;
@@ -1347,12 +1382,23 @@ public class RegisteredAidCache {
                 aidType.isOnHost = onHost;
                 aidType.offHostSE = onHost ? null : offHostSE;
                 requiresUnlock = onHost ? false : requiresUnlock;
-                requiresScreenOn = onHost ? true : requiresScreenOn;
+                requiresScreenOn = onHost ? false : requiresScreenOn;
 
                 aidType.power = computeAidPowerState(onHost, requiresScreenOn, requiresUnlock);
 
                 routingEntries.put(aid, aidType);
             }
+            if ((DBG) && (resolveInfo.services.size() != 0)) {
+                String host = "DH";
+                if (!aidType.isOnHost) {
+                    host = aidType.offHostSE;
+                }
+                Log.d(TAG,
+                        "updateRoutingLocked: AID " + aid + ", route=" + host + ", power="
+                                + String.format("0x%02X", aidType.power) + ", nb services="
+                                + resolveInfo.services.size() + ", service="
+                                + resolveInfo.services.get(0).getComponent());
+            }
         }
         mRequiresScreenOnServiceExist = requiresScreenOnServiceExist;
         int result = mRoutingManager.configureRouting(routingEntries, force, isOverrideOrRecover);
@@ -1398,7 +1444,10 @@ public class RegisteredAidCache {
     }
 
     public void onWalletRoleHolderChanged(String defaultWalletHolderPackageName, int userId) {
-        if (DBG) Log.d(TAG, "onWalletRoleHolderChanged: user:" + userId);
+        if (DBG) {
+            Log.d(TAG, "onWalletRoleHolderChanged: Wallet name=" + defaultWalletHolderPackageName
+                    + ", User=" + userId);
+        }
         synchronized (mLock) {
             mDefaultWalletHolderPackageName = defaultWalletHolderPackageName;
             mUserIdDefaultWalletHolder = userId;
@@ -1503,6 +1552,8 @@ public class RegisteredAidCache {
 
 
     public void onNfcDisabled() {
+        if (DBG) Log.d(TAG, "onNfcDisabled");
+
         synchronized (mLock) {
             mNfcEnabled = false;
         }
@@ -1510,6 +1561,8 @@ public class RegisteredAidCache {
     }
 
     public void onNfcEnabled() {
+        if (DBG) Log.d(TAG, "onNfcEnabled");
+
         synchronized (mLock) {
             mNfcEnabled = true;
             updateRoutingLocked(true, false);
@@ -1613,6 +1666,7 @@ public class RegisteredAidCache {
     }
 
     public void onPreferredSimChanged(int simType) {
+        if (DBG) Log.d(TAG, "onPreferredSimChanged");
         synchronized (mLock) {
             mPreferredSimType = simType;
             mRoutingManager.onNfccRoutingTableCleared();
diff --git a/NfcNci/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCache.java b/NfcNci/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCache.java
index 9d9c376c4..0232e63c3 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCache.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCache.java
@@ -66,7 +66,7 @@ public class RegisteredNfcFServicesCache {
     static final String XML_INDENT_OUTPUT_FEATURE = "http://xmlpull.org/v1/doc/features.html#indent-output";
     static final String TAG = "RegisteredNfcFServicesCache";
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
-    private static final boolean VDBG = false; // turn on for local testing.
+    static final boolean VDBG = NfcProperties.verbose_debug_enabled().orElse(true);
 
     final Context mContext;
     final AtomicReference<BroadcastReceiver> mReceiver;
diff --git a/NfcNci/src/com/android/nfc/cardemulation/RegisteredServicesCache.java b/NfcNci/src/com/android/nfc/cardemulation/RegisteredServicesCache.java
index 8a116e0a2..4939da4f6 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/RegisteredServicesCache.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/RegisteredServicesCache.java
@@ -34,6 +34,7 @@ import android.content.pm.PackageManager.NameNotFoundException;
 import android.content.pm.PackageManager.ResolveInfoFlags;
 import android.content.pm.ResolveInfo;
 import android.content.pm.ServiceInfo;
+import android.net.Uri;
 import android.nfc.cardemulation.AidGroup;
 import android.nfc.cardemulation.ApduServiceInfo;
 import android.nfc.cardemulation.CardEmulation;
@@ -78,6 +79,7 @@ import java.util.HashMap;
 import java.util.Iterator;
 import java.util.List;
 import java.util.Map;
+import java.util.Set;
 import java.util.concurrent.atomic.AtomicReference;
 
 /**
@@ -89,12 +91,12 @@ import java.util.concurrent.atomic.AtomicReference;
  */
 public class RegisteredServicesCache {
     static final String XML_INDENT_OUTPUT_FEATURE = "http://xmlpull.org/v1/doc/features.html#indent-output";
-    static final String TAG = "RegisteredServicesCache";
+    static final String TAG = "NfcRegisteredServicesCache";
     static final String AID_XML_PATH = "dynamic_aids.xml";
     static final String OTHER_STATUS_PATH = "other_status.xml";
     static final String PACKAGE_DATA = "package";
     static final boolean DEBUG = NfcProperties.debug_enabled().orElse(true);
-    private static final boolean VDBG = false; // turn on for local testing.
+    static final boolean VDBG = NfcProperties.verbose_debug_enabled().orElse(true);
 
     final Context mContext;
     final AtomicReference<BroadcastReceiver> mReceiver;
@@ -134,6 +136,8 @@ public class RegisteredServicesCache {
         public final HashMap<String, AidGroup> aidGroups = new HashMap<>();
         public String offHostSE;
         public String shouldDefaultToObserveModeStr;
+        public String requireDeviceScreenOnStr;
+        public String requireDeviceUnlockStr;
 
         DynamicSettings(int uid) {
             this.uid = uid;
@@ -269,7 +273,7 @@ public class RegisteredServicesCache {
             public void onReceive(Context context, Intent intent) {
                 final int uid = intent.getIntExtra(Intent.EXTRA_UID, -1);
                 String action = intent.getAction();
-                if (VDBG) Log.d(TAG, "onReceive: Intent action: " + action);
+                if (VDBG) Log.d(TAG, "onReceive: Intent action=" + action);
 
                 if (mRoutingOptionManager.isRoutingTableOverrided()) {
                     if (DEBUG) {
@@ -278,6 +282,7 @@ public class RegisteredServicesCache {
                 }
                 if (uid == -1) return;
                 int userId = UserHandle.getUserHandleForUid(uid).getIdentifier();
+
                 int currentUser = ActivityManager.getCurrentUser();
                 if (currentUser != getProfileParentId(context, userId)) {
                     // Cache will automatically be updated on user switch
@@ -295,10 +300,16 @@ public class RegisteredServicesCache {
                     }
                     return;
                 }
+
                 boolean replaced = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
                         && (Intent.ACTION_PACKAGE_ADDED.equals(action)
                         || Intent.ACTION_PACKAGE_REMOVED.equals(action));
                 if (!replaced) {
+                    if (DEBUG) {
+                        Uri uri = intent.getData();
+                        String pkg = uri != null ? uri.getSchemeSpecificPart() : null;
+                        Log.d(TAG, "onReceive: action=" + action + ", pkg=" + pkg);
+                    }
                     if (Intent.ACTION_PACKAGE_REMOVED.equals(action)) {
                         invalidateCache(UserHandle.
                                 getUserHandleForUid(uid).getIdentifier(), true);
@@ -307,7 +318,7 @@ public class RegisteredServicesCache {
                                 getUserHandleForUid(uid).getIdentifier(), false);
                     }
                 } else {
-                    if (DEBUG) {
+                    if (VDBG) {
                         Log.d(TAG,
                                 "onReceive: Ignoring package intent due to package "
                                         + "being replaced");
@@ -414,13 +425,13 @@ public class RegisteredServicesCache {
 
     void dump(List<ApduServiceInfo> services) {
         for (ApduServiceInfo service : services) {
-            if (DEBUG) Log.d(TAG, service.toString());
+            if (DEBUG) Log.d(TAG, "invalidateCache: " + service.toString());
         }
     }
 
     void dump(ArrayList<ComponentName> services) {
         for (ComponentName service : services) {
-            if (DEBUG) Log.d(TAG, service.toString());
+            if (DEBUG) Log.d(TAG, "invalidateOther: " + service.toString());
         }
     }
 
@@ -446,6 +457,9 @@ public class RegisteredServicesCache {
         final ArrayList<ApduServiceInfo> services = new ArrayList<ApduServiceInfo>();
         synchronized (mLock) {
             UserServices userServices = findOrCreateUserLocked(userId);
+            if (DEBUG) {
+                Log.d(TAG, "getServices: Nb services found=" + userServices.services.size());
+            }
             services.addAll(userServices.services.values());
         }
         return services;
@@ -459,6 +473,10 @@ public class RegisteredServicesCache {
                 if (service.hasCategory(category)) services.add(service);
             }
         }
+        if (DEBUG) {
+            Log.d(TAG, "getServicesForCategory: found " + services.size()
+                    + " services for category " + category);
+        }
         return services;
     }
 
@@ -482,6 +500,7 @@ public class RegisteredServicesCache {
                 mOffHostApduServiceIntent,
                 ResolveInfoFlags.of(PackageManager.GET_META_DATA), UserHandle.of(userId));
         resolvedServices.addAll(resolvedOffHostServices);
+
         for (ResolveInfo resolvedService : resolvedServices) {
             try {
                 boolean onHost = !resolvedOffHostServices.contains(resolvedService);
@@ -562,6 +581,10 @@ public class RegisteredServicesCache {
      * invalidateCache for specific userId.
      */
     public void invalidateCache(int userId, boolean validateInstalled) {
+        if (DEBUG) {
+            Log.d(TAG, "invalidateCache");
+        }
+
         final ArrayList<ApduServiceInfo> validServices = getInstalledServices(userId);
         if (validServices == null) {
             return;
@@ -619,6 +642,16 @@ public class RegisteredServicesCache {
                                 convertValueToBoolean(dynamicSettings.shouldDefaultToObserveModeStr,
                                 false));
                     }
+                    if (dynamicSettings.requireDeviceScreenOnStr != null) {
+                        serviceInfo.setRequiresScreenOn(
+                                convertValueToBoolean(dynamicSettings.requireDeviceScreenOnStr,
+                                        serviceInfo.requiresScreenOn()));
+                    }
+                    if (dynamicSettings.requireDeviceUnlockStr != null) {
+                        serviceInfo.setRequiresUnlock(
+                                convertValueToBoolean(dynamicSettings.requireDeviceScreenOnStr,
+                                        serviceInfo.requiresUnlock()));
+                    }
                 }
             }
             if (toBeRemoved.size() > 0) {
@@ -642,15 +675,19 @@ public class RegisteredServicesCache {
             dump(validServices);
         } else {
             // dump only new services added or removed
-            Log.i(TAG, "invalidateCache: New Services => ");
-            dump(toBeAdded);
-            Log.i(TAG, "invalidateCache: Removed Services => ");
-            dump(toBeRemoved);
+            if (toBeAdded.size() > 0) {
+                Log.i(TAG, "invalidateCache: New Services => ");
+                dump(toBeAdded);
+            }
+            if (toBeRemoved.size()  > 0) {
+                Log.i(TAG, "invalidateCache: Removed Services => ");
+                dump(toBeRemoved);
+            }
         }
     }
 
     private void invalidateOther(int userId, List<ApduServiceInfo> validOtherServices) {
-        Log.d(TAG, "invalidateOther : " + userId);
+        Log.d(TAG, "invalidateOther : userId=" + userId);
         ArrayList<ComponentName> toBeAdded = new ArrayList<>();
         ArrayList<ComponentName> toBeRemoved = new ArrayList<>();
         // remove services
@@ -711,10 +748,14 @@ public class RegisteredServicesCache {
             dump(validOtherServices);
         } else {
             // dump only new services added or removed
-            Log.i(TAG, "invalidateOther: New Services => ");
-            dump(toBeAdded);
-            Log.i(TAG, "invalidateOther: Removed Services => ");
-            dump(toBeRemoved);
+            if (toBeAdded.size() > 0) {
+                Log.i(TAG, "invalidateOther: New Services => ");
+                dump(toBeAdded);
+            }
+            if (toBeRemoved.size() > 0) {
+                Log.i(TAG, "invalidateOther: Removed Services => ");
+                dump(toBeRemoved);
+            }
         }
     }
 
@@ -760,6 +801,8 @@ public class RegisteredServicesCache {
                 int currentUid = -1;
                 String currentOffHostSE = null;
                 String shouldDefaultToObserveModeStr = null;
+                String requireDeviceScreenOnStr = null;
+                String requireDeviceUnlockStr = null;
                 ArrayList<AidGroup> currentGroups = new ArrayList<AidGroup>();
                 Map<String, Boolean> plFilters = new HashMap<>();
                 Map<String, Boolean> plPatternFilters = new HashMap<>();
@@ -773,6 +816,10 @@ public class RegisteredServicesCache {
                                     = parser.getAttributeValue(null, "offHostSE");
                             shouldDefaultToObserveModeStr =
                                     parser.getAttributeValue(null, "shouldDefaultToObserveMode");
+                            requireDeviceScreenOnStr =
+                                    parser.getAttributeValue(null, "requireDeviceScreenOn");
+                            requireDeviceUnlockStr =
+                                    parser.getAttributeValue(null, "requireDeviceUnlock");
                             if (compString == null || uidString == null) {
                                 Log.e(TAG,
                                         "readDynamicSettingsFromFile: Invalid service attributes");
@@ -829,6 +876,8 @@ public class RegisteredServicesCache {
                                 dynSettings.offHostSE = currentOffHostSE;
                                 dynSettings.shouldDefaultToObserveModeStr
                                         = shouldDefaultToObserveModeStr;
+                                dynSettings.requireDeviceScreenOnStr = requireDeviceScreenOnStr;
+                                dynSettings.requireDeviceUnlockStr = requireDeviceUnlockStr;
                                 if (!readSettingsMap.containsKey(userId)) {
                                     readSettingsMap.put(userId, new ArrayList<>());
                                 }
@@ -929,12 +978,16 @@ public class RegisteredServicesCache {
                         if ("service".equals(tagName)) {
                             // See if we have a valid service
                             if (currentComponent != null && currentUid >= 0) {
-                                Log.d(TAG, "readOtherFromFile: end of service tag");
+                                if (VDBG) {
+                                    Log.d(TAG, "readOtherFromFile: end of service tag");
+                                }
                                 final int userId =
                                         UserHandle.getUserHandleForUid(currentUid).getIdentifier();
                                 OtherServiceStatus status =
                                         new OtherServiceStatus(currentUid, checked);
-                                Log.d(TAG, "readOtherFromFile: ## user id - " + userId);
+                                if (VDBG) {
+                                    Log.d(TAG, "readOtherFromFile: ## user id - " + userId);
+                                }
                                 if (!readSettingsMap.containsKey(userId)) {
                                     readSettingsMap.put(userId, new ArrayList<>());
                                 }
@@ -965,6 +1018,9 @@ public class RegisteredServicesCache {
     }
 
     private void readOthersLocked() {
+        if (DEBUG) {
+            Log.d(TAG, "readOthersLocked");
+        }
         Map<Integer, List<Pair<ComponentName, OtherServiceStatus>>> readSettingsMap
                 = readOtherFromFile(mOthersFile);
         for (Integer userId: readSettingsMap.keySet()) {
@@ -982,6 +1038,10 @@ public class RegisteredServicesCache {
     }
 
     private boolean writeDynamicSettingsLocked() {
+        if (DEBUG) {
+            Log.d(TAG, "writeDynamicSettingsLocked");
+        }
+
         FileOutputStream fos = null;
         try {
             fos = mDynamicSettingsFile.startWrite();
@@ -1004,6 +1064,14 @@ public class RegisteredServicesCache {
                         out.attribute(null, "shouldDefaultToObserveMode",
                                 service.getValue().shouldDefaultToObserveModeStr);
                     }
+                    if (service.getValue().requireDeviceScreenOnStr != null) {
+                        out.attribute(null, "requireDeviceScreenOnStr",
+                                service.getValue().requireDeviceScreenOnStr);
+                    }
+                    if (service.getValue().requireDeviceUnlockStr != null) {
+                        out.attribute(null, "requireDeviceUnlockStr",
+                                service.getValue().requireDeviceUnlockStr);
+                    }
                     for (AidGroup group : service.getValue().aidGroups.values()) {
                         group.writeAsXml(out);
                     }
@@ -1044,7 +1112,9 @@ public class RegisteredServicesCache {
     }
 
     private boolean writeOthersLocked() {
-        Log.d(TAG, "writeOthersLocked");
+        if (VDBG) {
+            Log.d(TAG, "writeOthersLocked");
+        }
 
         FileOutputStream fos = null;
         try {
@@ -1055,18 +1125,26 @@ public class RegisteredServicesCache {
             out.setFeature(XML_INDENT_OUTPUT_FEATURE, true);
             out.startTag(null, "services");
 
-            Log.d(TAG, "writeOthersLocked: userServices.size: " + mUserServices.size());
+            if (VDBG) {
+                Log.d(TAG, "writeOthersLocked: userServices.size: " + mUserServices.size());
+            }
             for (int i = 0; i < mUserServices.size(); i++) {
                 final UserServices user = mUserServices.valueAt(i);
                 int userId = mUserServices.keyAt(i);
                 // Checking for 1 times
-                Log.d(TAG, "writeOthersLocked: userId: " + userId);
-                Log.d(TAG, "writeOthersLocked: others size: " + user.others.size());
+                if (VDBG) {
+                    Log.d(TAG, "writeOthersLocked: userId: " + userId);
+                    Log.d(TAG, "writeOthersLocked: others size: " + user.others.size());
+                }
                 ArrayList<ComponentName> currentService = new ArrayList<ComponentName>();
                 for (Map.Entry<ComponentName, OtherServiceStatus> service : user.others
                         .entrySet()) {
-                    Log.d(TAG, "writeOthersLocked: component: " + service.getKey().flattenToString()
-                            + ", checked: " + service.getValue().checked);
+                    if (VDBG) {
+                        Log.d(TAG,
+                                "writeOthersLocked: component: "
+                                        + service.getKey().flattenToString() + ", checked: "
+                                        + service.getValue().checked);
+                    }
 
                     boolean hasDupe = false;
                     for (ComponentName cn : currentService) {
@@ -1078,7 +1156,9 @@ public class RegisteredServicesCache {
                     if (hasDupe) {
                         continue;
                     } else {
-                        Log.d(TAG, "writeOthersLocked: Already written");
+                        if (VDBG) {
+                            Log.d(TAG, "writeOthersLocked: Already written");
+                        }
                         currentService.add(service.getKey());
                     }
 
@@ -1104,6 +1184,10 @@ public class RegisteredServicesCache {
 
     public boolean setOffHostSecureElement(int userId, int uid, ComponentName componentName,
             String offHostSE) {
+        if (DEBUG) {
+            Log.d(TAG, "setOffHostSecureElement: componentName: " + componentName.flattenToString()
+                    + " offHostSE=" + offHostSE);
+        }
         ArrayList<ApduServiceInfo> newServices = null;
         synchronized (mLock) {
             UserServices services = findOrCreateUserLocked(userId);
@@ -1190,6 +1274,10 @@ public class RegisteredServicesCache {
 
     public boolean setShouldDefaultToObserveModeForService(int userId, int uid,
             ComponentName componentName, boolean enable) {
+        if (DEBUG) {
+            Log.d(TAG, "setShouldDefaultToObserveModeForService: componentName="
+                    + componentName.flattenToString() + " enable=" + enable);
+        }
         synchronized (mLock) {
             UserServices services = findOrCreateUserLocked(userId);
             // Check if we can find this service
@@ -1219,9 +1307,63 @@ public class RegisteredServicesCache {
         return true;
     }
 
+    public void setRequireDeviceScreenOnForService(int userId, int uid,
+            ComponentName componentName, boolean enable) {
+        synchronized (mLock) {
+            UserServices services = findOrCreateUserLocked(userId);
+            ApduServiceInfo serviceInfo = services.services.get(componentName);
+            if (serviceInfo == null) {
+                throw new IllegalArgumentException(
+                        "Service with component name " + componentName + " is not registered");
+            }
+            if (!NfcInjector.isPrivileged(uid) && serviceInfo.getUid() != uid) {
+                Log.e(TAG, "setRequireDeviceScreenOnForService UID mismatch");
+                throw new IllegalArgumentException("UID mismatch between caller and service "
+                        + componentName);
+            }
+            if (serviceInfo.requiresScreenOn() == enable) {
+                return;
+            }
+            serviceInfo.setRequiresScreenOn(enable);
+            DynamicSettings settings = getOrCreateSettings(services, componentName, uid);
+            settings.requireDeviceScreenOnStr = Boolean.toString(enable);
+            mCallback.onServicesUpdated(userId, List.of(serviceInfo), true);
+        }
+    }
+
+    public void setRequireDeviceUnlockForService(int userId, int uid,
+            ComponentName componentName, boolean enable) {
+        synchronized (mLock) {
+            UserServices services = findOrCreateUserLocked(userId);
+            ApduServiceInfo serviceInfo = services.services.get(componentName);
+            if (serviceInfo == null) {
+                throw new IllegalArgumentException(
+                        "Service with component name " + componentName + " is not registered");
+            }
+            if (!NfcInjector.isPrivileged(uid) && serviceInfo.getUid() != uid) {
+                Log.e(TAG, "setRequireDeviceUnlockForService UID mismatch");
+                throw new IllegalArgumentException("UID mismatch between caller and service "
+                        + componentName);
+            }
+            if (serviceInfo.requiresUnlock() == enable) {
+                return;
+            }
+            serviceInfo.setRequiresUnlock(enable);
+            DynamicSettings settings = getOrCreateSettings(services, componentName, uid);
+            settings.requireDeviceUnlockStr = Boolean.toString(enable);
+            mCallback.onServicesUpdated(userId, List.of(serviceInfo), true);
+        }
+    }
+
     public boolean registerPollingLoopFilterForService(int userId, int uid,
             ComponentName componentName, String pollingLoopFilter,
             boolean autoTransact) {
+        if (DEBUG) {
+            Log.d(TAG,
+                    "registerPollingLoopFilterForService: componentName="
+                            + componentName.flattenToString() + ", pollingLoopFilter="
+                            + pollingLoopFilter + ", autoTransact=" + autoTransact);
+        }
         ArrayList<ApduServiceInfo> newServices = null;
         synchronized (mLock) {
             UserServices services = findOrCreateUserLocked(userId);
@@ -1256,6 +1398,10 @@ public class RegisteredServicesCache {
 
     public boolean removePollingLoopFilterForService(int userId, int uid,
             ComponentName componentName, String pollingLoopFilter) {
+        if (DEBUG) {
+            Log.d(TAG, "removePollingLoopFilterForService: componentName="
+                    + componentName.flattenToString() + ", pollingLoopFilter=" + pollingLoopFilter);
+        }
         ArrayList<ApduServiceInfo> newServices = null;
         synchronized (mLock) {
             UserServices services = findOrCreateUserLocked(userId);
@@ -1284,9 +1430,38 @@ public class RegisteredServicesCache {
         return true;
     }
 
+    public Set<String> getPollingLoopFiltersForService(int userId, int uid,
+            ComponentName componentName) {
+        synchronized (mLock) {
+            UserServices services = findOrCreateUserLocked(userId);
+            // Check if we can find this service
+            ApduServiceInfo serviceInfo = getService(userId, componentName);
+            if (serviceInfo == null) {
+                throw new IllegalArgumentException("getPollingLoopFiltersForService: Service "
+                                                       + componentName + " does not exist");
+            }
+            if (!NfcInjector.isPrivileged(uid) && serviceInfo.getUid() != uid) {
+                // This is probably a good indication something is wrong here.
+                // Either newer service installed with different uid (but then
+                // we should have known about it), or somebody calling us from
+                // a different uid.
+                throw new SecurityException("getPollingLoopFiltersForService: UID mismatch");
+            }
+            DynamicSettings dynamicSettings =
+                    getOrCreateSettings(services, componentName, serviceInfo.getUid());
+            return dynamicSettings.pollingLoopFilters.keySet();
+        }
+    }
+
     public boolean registerPollingLoopPatternFilterForService(int userId, int uid,
             ComponentName componentName, String pollingLoopPatternFilter,
             boolean autoTransact) {
+        if (DEBUG) {
+            Log.d(TAG,
+                    "registerPollingLoopPatternFilterForService: componentName="
+                            + componentName.flattenToString() + ", pollingLoopPatternFilter="
+                            + pollingLoopPatternFilter + ", autoTransact=" + autoTransact);
+        }
         ArrayList<ApduServiceInfo> newServices = null;
         synchronized (mLock) {
             UserServices services = findOrCreateUserLocked(userId);
@@ -1321,6 +1496,12 @@ public class RegisteredServicesCache {
 
     public boolean removePollingLoopPatternFilterForService(int userId, int uid,
             ComponentName componentName, String pollingLoopPatternFilter) {
+        if (DEBUG) {
+            Log.d(TAG,
+                    "removePollingLoopPatternFilterForService: componentName="
+                            + componentName.flattenToString() + ", pollingLoopPatternFilter="
+                            + pollingLoopPatternFilter);
+        }
         ArrayList<ApduServiceInfo> newServices = null;
         synchronized (mLock) {
             UserServices services = findOrCreateUserLocked(userId);
@@ -1349,10 +1530,37 @@ public class RegisteredServicesCache {
         return true;
     }
 
+    public Set<String> getPollingLoopPatternFiltersForService(int userId, int uid,
+            ComponentName componentName) {
+        synchronized (mLock) {
+            UserServices services = findOrCreateUserLocked(userId);
+            // Check if we can find this service
+            ApduServiceInfo serviceInfo = getService(userId, componentName);
+            if (serviceInfo == null) {
+                throw new IllegalArgumentException("getPollingLoopFiltersForService: Service "
+                                                       + componentName + " does not exist");
+            }
+            if (!NfcInjector.isPrivileged(uid) && serviceInfo.getUid() != uid) {
+                // This is probably a good indication something is wrong here.
+                // Either newer service installed with different uid (but then
+                // we should have known about it), or somebody calling us from
+                // a different uid.
+                throw new SecurityException("getPollingLoopFiltersForService: UID mismatch");
+            }
+            DynamicSettings dynamicSettings =
+                    getOrCreateSettings(services, componentName, serviceInfo.getUid());
+            return dynamicSettings.pollingLoopPatternFilters.keySet();
+        }
+    }
 
 
     public boolean registerAidGroupForService(int userId, int uid,
             ComponentName componentName, AidGroup aidGroup) {
+        if (DEBUG) {
+            Log.d(TAG,
+                    "registerAidGroupForService: componentName=" + componentName.flattenToString());
+        }
+
         ArrayList<ApduServiceInfo> newServices = null;
         boolean success;
         synchronized (mLock) {
@@ -1453,6 +1661,10 @@ public class RegisteredServicesCache {
 
     public AidGroup getAidGroupForService(int userId, int uid, ComponentName componentName,
             String category) {
+        if (DEBUG) {
+            Log.d(TAG, "getAidGroupForService: componentName=" + componentName.flattenToString());
+        }
+
         ApduServiceInfo serviceInfo = getService(userId, componentName);
         if (serviceInfo != null) {
             if (!NfcInjector.isPrivileged(uid) && serviceInfo.getUid() != uid) {
@@ -1468,6 +1680,10 @@ public class RegisteredServicesCache {
 
     public boolean removeAidGroupForService(int userId, int uid, ComponentName componentName,
             String category) {
+        if (DEBUG) {
+            Log.d(TAG, "removeAidGroupForService");
+        }
+
         boolean success = false;
         ArrayList<ApduServiceInfo> newServices = null;
         synchronized (mLock) {
diff --git a/NfcNci/src/com/android/nfc/cardemulation/RegisteredT3tIdentifiersCache.java b/NfcNci/src/com/android/nfc/cardemulation/RegisteredT3tIdentifiersCache.java
index 41e886610..c313abc76 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/RegisteredT3tIdentifiersCache.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/RegisteredT3tIdentifiersCache.java
@@ -38,7 +38,7 @@ import java.util.List;
 import java.util.Map;
 
 public class RegisteredT3tIdentifiersCache {
-    static final String TAG = "RegisteredT3tIdentifiersCache";
+    static final String TAG = "NfcRegisteredT3tIdentifiersCache";
 
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
 
diff --git a/NfcNci/src/com/android/nfc/cardemulation/RoutingOptionManager.java b/NfcNci/src/com/android/nfc/cardemulation/RoutingOptionManager.java
index 95eee1e87..a0cb30c78 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/RoutingOptionManager.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/RoutingOptionManager.java
@@ -35,7 +35,7 @@ import java.util.Map;
 import java.util.Optional;
 
 public class RoutingOptionManager {
-    static final String TAG = "RoutingOptionManager";
+    static final String TAG = "NfcRoutingOptionManager";
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
 
     static final int ROUTE_UNKNOWN = -1;
@@ -155,23 +155,41 @@ public class RoutingOptionManager {
     @VisibleForTesting
     RoutingOptionManager() {
         mDefaultRoute = doGetDefaultRouteDestination();
-        if (DBG) Log.d(TAG, "mDefaultRoute=0x" + Integer.toHexString(mDefaultRoute));
+        if (DBG) {
+            Log.d(TAG, "mDefaultRoute=0x" + Integer.toHexString(mDefaultRoute));
+        }
         mDefaultIsoDepRoute = doGetDefaultIsoDepRouteDestination();
-        if (DBG) Log.d(TAG, "mDefaultIsoDepRoute=0x" + Integer.toHexString(mDefaultIsoDepRoute));
+        if (DBG) {
+            Log.d(TAG, "mDefaultIsoDepRoute=0x" + Integer.toHexString(mDefaultIsoDepRoute));
+        }
         mDefaultOffHostRoute = doGetDefaultOffHostRouteDestination();
-        if (DBG) Log.d(TAG, "mDefaultOffHostRoute=0x" + Integer.toHexString(mDefaultOffHostRoute));
+        if (DBG) {
+            Log.d(TAG, "mDefaultOffHostRoute=0x" + Integer.toHexString(mDefaultOffHostRoute));
+        }
         mDefaultFelicaRoute = doGetDefaultFelicaRouteDestination();
-        if (DBG) Log.d(TAG, "mDefaultFelicaRoute=0x" + Integer.toHexString(mDefaultFelicaRoute));
+        if (DBG) {
+            Log.d(TAG, "mDefaultFelicaRoute=0x" + Integer.toHexString(mDefaultFelicaRoute));
+        }
         mDefaultScRoute = doGetDefaultScRouteDestination();
-        if (DBG) Log.d(TAG, "mDefaultScRoute=0x" + Integer.toHexString(mDefaultScRoute));
+        if (DBG) {
+            Log.d(TAG, "mDefaultScRoute=0x" + Integer.toHexString(mDefaultScRoute));
+        }
         mOffHostRouteUicc = doGetOffHostUiccDestination();
-        if (DBG) Log.d(TAG, "mOffHostRouteUicc=" + Arrays.toString(mOffHostRouteUicc));
+        if (DBG) {
+            Log.d(TAG, "mOffHostRouteUicc=" + Arrays.toString(mOffHostRouteUicc));
+        }
         mOffHostRouteEse = doGetOffHostEseDestination();
-        if (DBG) Log.d(TAG, "mOffHostRouteEse=" + Arrays.toString(mOffHostRouteEse));
+        if (DBG) {
+            Log.d(TAG, "mOffHostRouteEse=" + Arrays.toString(mOffHostRouteEse));
+        }
         mAidMatchingSupport = doGetAidMatchingMode();
-        if (DBG) Log.d(TAG, "mAidMatchingSupport=0x" + Integer.toHexString(mAidMatchingSupport));
+        if (DBG) {
+            Log.d(TAG, "mAidMatchingSupport=0x" + Integer.toHexString(mAidMatchingSupport));
+        }
         mNdefNfceeRoute = NativeNfcManager.getInstance().getNdefNfceeRouteId();
-        if (DBG) Log.d(TAG, "mNdefNfceeRoute=0x" + Integer.toHexString(mNdefNfceeRoute));
+        if (DBG) {
+            Log.d(TAG, "mNdefNfceeRoute=0x" + Integer.toHexString(mNdefNfceeRoute));
+        }
 
         mPreferredSimSettings = new SimSettings((mOffHostRouteUicc != null) ?
                 mOffHostRouteUicc.length : 0, 1);
@@ -343,6 +361,15 @@ public class RoutingOptionManager {
 
         addOrUpdateTableItems(SE_PREFIX_SIM, mOffHostRouteUicc);
         addOrUpdateTableItems(SE_PREFIX_ESE, mOffHostRouteEse);
+
+        for (Map.Entry<String, Integer> entry : mRouteForSecureElement.entrySet()) {
+            Log.d(TAG, "createLookUpTable: route=" + entry.getKey() + ", nfceeId="
+                    + Integer.toHexString(entry.getValue()));
+        }
+        for (Map.Entry<Integer, String> entry : mSecureElementForRoute.entrySet()) {
+            Log.d(TAG, "createLookUpTable: nfceeId=" + Integer.toHexString(entry.getKey())
+                    + ", route=" + entry.getValue());
+        }
     }
 
     boolean isRoutingTableOverwrittenOrOverlaid(
@@ -414,6 +441,7 @@ public class RoutingOptionManager {
 
     public void setAutoChangeStatus(boolean status) {
         mIsAutoChangeCapable = status;
+        writeRoutingOption(KEY_AUTO_CHANGE_CAPABLE, mIsAutoChangeCapable);
     }
 
     public boolean isAutoChangeEnabled() {
@@ -467,14 +495,5 @@ public class RoutingOptionManager {
                 mSecureElementForRoute.putIfAbsent(route, name);
             }
         }
-
-        for (Map.Entry<String, Integer> entry : mRouteForSecureElement.entrySet()) {
-            Log.d(TAG, "addOrUpdateTableItems: route: " + entry.getKey() + ", nfceeId: "
-                    + Integer.toHexString(entry.getValue()));
-        }
-        for (Map.Entry<Integer, String> entry : mSecureElementForRoute.entrySet()) {
-            Log.d(TAG, "addOrUpdateTableItems: nfceeId: " + Integer.toHexString(entry.getKey())
-                    + ", route: " + entry.getValue());
-        }
     }
 }
diff --git a/NfcNci/src/com/android/nfc/cardemulation/SystemCodeRoutingManager.java b/NfcNci/src/com/android/nfc/cardemulation/SystemCodeRoutingManager.java
index 3620783f1..cac1c4784 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/SystemCodeRoutingManager.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/SystemCodeRoutingManager.java
@@ -29,7 +29,7 @@ import java.util.ArrayList;
 import java.util.List;
 
 public class SystemCodeRoutingManager {
-    static final String TAG = "SystemCodeRoutingManager";
+    static final String TAG = "NfcSystemCodeRoutingManager";
 
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
 
diff --git a/NfcNci/src/com/android/nfc/cardemulation/TapAgainDialog.java b/NfcNci/src/com/android/nfc/cardemulation/TapAgainDialog.java
index b462d644a..ff6db2d09 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/TapAgainDialog.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/TapAgainDialog.java
@@ -28,6 +28,7 @@ import android.nfc.cardemulation.ApduServiceInfo;
 import android.nfc.cardemulation.CardEmulation;
 import android.os.Bundle;
 import android.os.UserHandle;
+import android.sysprop.NfcProperties;
 import android.util.Log;
 import android.view.View;
 import android.view.Window;
@@ -41,7 +42,8 @@ import com.android.nfc.cardemulation.util.AlertActivity;
 import java.util.concurrent.atomic.AtomicReference;
 
 public class TapAgainDialog extends AlertActivity implements DialogInterface.OnClickListener {
-    private static final String TAG = "TapAgainDialog";
+    private static final String TAG = "NfcTapAgainDialog";
+    static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
     public static final String ACTION_CLOSE =
             "com.android.nfc.cardemulation.action.CLOSE_TAP_DIALOG";
     public static final String EXTRA_APDU_SERVICE = "apdu_service";
@@ -56,7 +58,9 @@ public class TapAgainDialog extends AlertActivity implements DialogInterface.OnC
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
-
+        if (DBG) {
+            Log.d(TAG, "onCreate");
+        }
         setTheme(com.android.nfc.R.style.TapAgainDayNight);
 
         final NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
@@ -124,7 +128,7 @@ public class TapAgainDialog extends AlertActivity implements DialogInterface.OnC
     @Override
     protected void onDestroy() {
         super.onDestroy();
-        if (mReceiver.get() != null) {
+        if (mReceiver != null && mReceiver.get() != null) {
             Log.e(TAG, "onDestroy: Failed to unregister receiver");
             close();
         }
diff --git a/NfcNci/src/com/android/nfc/cardemulation/WalletRoleObserver.java b/NfcNci/src/com/android/nfc/cardemulation/WalletRoleObserver.java
index 225ca9abc..d601a2a37 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/WalletRoleObserver.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/WalletRoleObserver.java
@@ -40,7 +40,7 @@ import java.util.Objects;
 
 public class WalletRoleObserver {
     static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
-    private static final String TAG = "WalletRoleObserver";
+    private static final String TAG = "NfcWalletRoleObserver";
 
     public interface Callback {
         void onWalletRoleHolderChanged(String holder, int userId);
diff --git a/NfcNci/src/com/android/nfc/cardemulation/util/TelephonyUtils.java b/NfcNci/src/com/android/nfc/cardemulation/util/TelephonyUtils.java
index 279461ebe..e927cb3a4 100644
--- a/NfcNci/src/com/android/nfc/cardemulation/util/TelephonyUtils.java
+++ b/NfcNci/src/com/android/nfc/cardemulation/util/TelephonyUtils.java
@@ -19,6 +19,7 @@ import android.content.Context;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
+import android.telephony.UiccCardInfo;
 import android.util.Log;
 
 import java.util.Collections;
@@ -48,11 +49,19 @@ public class TelephonyUtils extends SubscriptionManager.OnSubscriptionsChangedLi
     public static final int MEP_MODE_A2 = 2;
     public static final int MEP_MODE_B = 3;
 
+    public static final int SWP_SUPPORTED_PHYSICAL_SIM_SLOT = 0;
+
     private TelephonyManager mTelephonyManager;
     private SubscriptionManager mSubscriptionManager;
 
     private boolean mIsSubscriptionsChangedListenerRegistered = false;
 
+    // Condition for checking active subscription for UICC and eUICC
+    // When find for an active list, the UICC and eUICC status are different as
+    // the SIM manager enables or disables it.
+    // In the case of UICC, it is included in the active list when disabled in the SIM manager,
+    // while eUICC is not included. This is based on the SIM power maintenance policy.
+    // For UICC, also check the application state.
     public static Predicate<SubscriptionInfo> SUBSCRIPTION_ACTIVE_CONDITION_FOR_UICC =
             subscriptionInfo -> !subscriptionInfo.isEmbedded()
                     && subscriptionInfo.areUiccApplicationsEnabled();
@@ -87,20 +96,6 @@ public class TelephonyUtils extends SubscriptionManager.OnSubscriptionsChangedLi
                 Executors.newSingleThreadExecutor(), this);
     }
 
-    public Optional<SubscriptionInfo> getActiveSubscriptionInfoById(int subscriptionId) {
-        Log.d(TAG, "getActiveSubscriptionInfoById: " + subscriptionId);
-        if (isUiccSubscription(subscriptionId)) {
-            Log.d(TAG, "getActiveSubscriptionInfoById: Uicc Subscription");
-            return findFirstActiveSubscriptionInfo(subscriptionInfo ->
-                    !subscriptionInfo.isEmbedded()
-                            && subscriptionInfo.areUiccApplicationsEnabled());
-        }
-        else {
-            Log.d(TAG, "getActiveSubscriptionInfoById: Embedded Uicc Subscription");
-            return Optional.ofNullable(
-                    mSubscriptionManager.getActiveSubscriptionInfo(subscriptionId));
-        }
-    }
     public boolean isUiccSubscription(int subscriptionId) {
         return subscriptionId == SUBSCRIPTION_ID_UICC;
     }
@@ -115,6 +110,15 @@ public class TelephonyUtils extends SubscriptionManager.OnSubscriptionsChangedLi
         return (list != null) ? list : Collections.emptyList();
     }
 
+    public int findPhysicalSlotIndex(SubscriptionInfo subscriptionInfo) {
+        return mTelephonyManager.getUiccCardsInfo().stream()
+                .filter(info->!info.isEuicc())
+                .filter(card->card.getPorts().stream()
+                        .anyMatch(port->
+                                port.getLogicalSlotIndex() == subscriptionInfo.getSimSlotIndex()))
+                .map(UiccCardInfo::getPhysicalSlotIndex)
+                .findFirst().orElseGet(()->-1);
+    }
     @Override
     public void onSubscriptionsChanged() {
         Log.d(TAG, "onSubscriptionsChanged");
@@ -125,7 +129,7 @@ public class TelephonyUtils extends SubscriptionManager.OnSubscriptionsChangedLi
         }
 
         mCallback.onActiveSubscriptionsUpdated(
-                mSubscriptionManager.getActiveSubscriptionInfoList());
+            mSubscriptionManager.getActiveSubscriptionInfoList());
     }
 
     public String updateSwpStatusForEuicc(int simType) {
@@ -176,6 +180,4 @@ public class TelephonyUtils extends SubscriptionManager.OnSubscriptionsChangedLi
     public void setMepMode(int mepMode) {
         mMepMode = mepMode;
     }
-
-
 }
diff --git a/NfcNci/src/com/android/nfc/wlc/NfcCharging.java b/NfcNci/src/com/android/nfc/wlc/NfcCharging.java
index fe8280acf..96187b9f1 100644
--- a/NfcNci/src/com/android/nfc/wlc/NfcCharging.java
+++ b/NfcNci/src/com/android/nfc/wlc/NfcCharging.java
@@ -980,7 +980,8 @@ public class NfcCharging {
                     Log.d(TAG, "HandleWLCState: STATE_24 (" + convert_state_2_str(STATE_24) + ")");
                 }
 
-                TagHandler.stopPresenceChecking();
+                TagHandler.stopPresenceChecking(false);
+
                 WLCState = STATE_2;
                 NfcChargingOnGoing = false;
                 if (mWatchdogWlc != null) {
diff --git a/NfcNci/tests/testcases/hostsidetests/Android.bp b/NfcNci/tests/testcases/hostsidetests/Android.bp
new file mode 100644
index 000000000..9a9f0ab46
--- /dev/null
+++ b/NfcNci/tests/testcases/hostsidetests/Android.bp
@@ -0,0 +1,57 @@
+android_app {
+    name: "EmulatorApduAppNonTest",
+    sdk_version: "test_current",
+    min_sdk_version: "35",
+    srcs: [
+        "src/com/android/nfc/emulatorapduapp/**/*.kt",
+    ],
+    assets: ["src/com/android/nfc/emulatorapduapp/parsed_files/**/*.txt"],
+    resource_dirs: ["src/com/android/nfc/emulatorapduapp/res"],
+    manifest: "src/com/android/nfc/emulatorapduapp/AndroidManifest.xml",
+    static_libs: [
+        "guava",
+        "androidx.appcompat_appcompat",
+        "kotlinx-coroutines-android",
+        "androidx.annotation_annotation",
+        "androidx.compose.ui_ui",
+        "com.google.android.material_material",
+        "kotlinx_serialization_core",
+        "kotlinx_serialization_json",
+        "nfc-multidevice-utils",
+    ],
+    visibility: [
+        "//cts:__subpackages__",
+        "//packages/modules/Nfc/NfcNci:__subpackages__",
+        "//packages/modules/Nfc:__subpackages__",
+        "//vendor:__subpackages__",
+    ],
+}
+
+android_test {
+    name: "EmulatorApduApp",
+    sdk_version: "test_current",
+    min_sdk_version: "35",
+    srcs: [
+        "src/com/android/nfc/emulatorapduapp/**/*.kt",
+    ],
+    assets: ["src/com/android/nfc/emulatorapduapp/parsed_files/**/*.txt"],
+    resource_dirs: ["src/com/android/nfc/emulatorapduapp/res"],
+    manifest: "src/com/android/nfc/emulatorapduapp/AndroidManifest.xml",
+    static_libs: [
+        "guava",
+        "androidx.appcompat_appcompat",
+        "kotlinx-coroutines-android",
+        "androidx.annotation_annotation",
+        "androidx.compose.ui_ui",
+        "com.google.android.material_material",
+        "nfc-multidevice-utils",
+        "kotlinx_serialization_core",
+        "kotlinx_serialization_json",
+    ],
+    visibility: [
+        "//cts:__subpackages__",
+        "//packages/modules/Nfc/NfcNci:__subpackages__",
+        "//packages/modules/Nfc:__subpackages__",
+        "//vendor:__subpackages__",
+    ],
+}
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/AndroidManifest.xml b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/AndroidManifest.xml
similarity index 86%
rename from NfcNci/testutils/src/com/android/nfc/emulatorapp/AndroidManifest.xml
rename to NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/AndroidManifest.xml
index 4804d0733..f5d362f35 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/AndroidManifest.xml
+++ b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/AndroidManifest.xml
@@ -1,7 +1,7 @@
 <?xml version="1.0" encoding="utf-8"?>
 <manifest
     xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.android.nfc.emulatorapp">
+    package="com.android.nfc.emulatorapduapp">
 
   <uses-sdk android:minSdkVersion="33" android:targetSdkVersion="33"/>
   <uses-permission android:name="android.permission.NFC" />
@@ -13,10 +13,11 @@
       android:theme="@style/AppTheme">
     <meta-data
         android:name="mobly-snippets"
-        android:value="com.android.nfc.emulatorapp.NfcApduDeviceSnippet" />
+        android:value="com.android.nfc.emulatorapduapp.NfcApduDeviceSnippet" />
     <service
         android:name=".EmulatorHostApduService"
         android:exported="true"
+        android:enabled="false"
         android:permission="android.permission.BIND_NFC_SERVICE">
       <intent-filter>
         <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE"/>
@@ -36,6 +37,6 @@
     </activity>
   </application>
   <instrumentation android:name="com.google.android.mobly.snippet.SnippetRunner"
-      android:targetPackage="com.android.nfc.emulatorapp"
+      android:targetPackage="com.android.nfc.emulatorapduapp"
       android:label="Nfc Multi Device Emulator Apdu Snippet" />
 </manifest>
\ No newline at end of file
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/EmulatorHostApduService.kt b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/EmulatorHostApduService.kt
similarity index 98%
rename from NfcNci/testutils/src/com/android/nfc/emulatorapp/EmulatorHostApduService.kt
rename to NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/EmulatorHostApduService.kt
index 75b73a2b2..d52b8a74a 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/EmulatorHostApduService.kt
+++ b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/EmulatorHostApduService.kt
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.nfc.emulatorapp
+package com.android.nfc.emulatorapduapp
 
 import android.nfc.cardemulation.HostApduService
 import android.nfc.cardemulation.PollingFrame
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/EmulatorViewModel.kt b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/EmulatorViewModel.kt
similarity index 97%
rename from NfcNci/testutils/src/com/android/nfc/emulatorapp/EmulatorViewModel.kt
rename to NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/EmulatorViewModel.kt
index 5c2fb5b91..557d8c0a9 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/EmulatorViewModel.kt
+++ b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/EmulatorViewModel.kt
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.nfc.emulatorapp
+package com.android.nfc.emulatorapduapp
 
 import androidx.lifecycle.LiveData
 import androidx.lifecycle.MutableLiveData
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/MainActivity.kt b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/MainActivity.kt
similarity index 93%
rename from NfcNci/testutils/src/com/android/nfc/emulatorapp/MainActivity.kt
rename to NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/MainActivity.kt
index 107b3cd5e..2c6c05d07 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/MainActivity.kt
+++ b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/MainActivity.kt
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.nfc.emulatorapp
+package com.android.nfc.emulatorapduapp
 
 import android.content.ComponentName
 import android.content.pm.PackageManager
@@ -68,6 +68,11 @@ class MainActivity : AppCompatActivity() {
     startHostApduService()
   }
 
+  override fun onDestroy() {
+    super.onDestroy()
+    stopHostApduService()
+  }
+
   private fun startHostApduService() {
     packageManager.setComponentEnabledSetting(
       ComponentName(this, EmulatorHostApduService::class.java),
@@ -76,6 +81,14 @@ class MainActivity : AppCompatActivity() {
     )
   }
 
+  private fun stopHostApduService() {
+    packageManager.setComponentEnabledSetting(
+      ComponentName(this, EmulatorHostApduService::class.java),
+      PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
+      PackageManager.DONT_KILL_APP,
+    )
+  }
+
   /* Opens the snoop file and extracts all APDU commands and responses. */
   private fun openAndParseFile(file: String): List<ApduPair> {
     val apduPairs = mutableListOf<ApduPair>()
@@ -143,6 +156,6 @@ class MainActivity : AppCompatActivity() {
     private const val TAG = "EmulatorHostApduServiceLog"
     const val SNOOP_DATA_FLAG = "snoop_data"
     const val SNOOP_FILE_FLAG = "snoop_file"
-    private const val PARSED_FILES_DIR = "src/com/android/nfc/emulatorapp/parsed_files/"
+    private const val PARSED_FILES_DIR = "src/com/android/nfc/emulatorapduapp/parsed_files/"
   }
 }
\ No newline at end of file
diff --git a/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/NfcApduDeviceSnippet.kt b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/NfcApduDeviceSnippet.kt
new file mode 100644
index 000000000..84348793e
--- /dev/null
+++ b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/NfcApduDeviceSnippet.kt
@@ -0,0 +1,153 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.nfc.emulatorapduapp
+
+import android.app.Instrumentation
+import android.content.Intent
+import android.nfc.NfcAdapter
+import android.util.Log
+import androidx.test.platform.app.InstrumentationRegistry
+
+import com.android.nfc.utils.NfcSnippet
+import com.google.android.mobly.snippet.rpc.Rpc
+
+import java.util.concurrent.CountDownLatch
+import java.util.concurrent.Executors
+import java.util.concurrent.TimeUnit
+
+class NfcApduDeviceSnippet : NfcSnippet() {
+  private val TAG = "NfcApduDeviceSnippet"
+  private lateinit var mActivity: MainActivity
+  private val mContext = InstrumentationRegistry.getInstrumentation().getContext()
+
+  @Rpc(description = "Checks if observe mode is supported on device")
+  fun isObserveModeSupported(): Boolean {
+    val nfcAdapter = NfcAdapter.getDefaultAdapter(mContext)
+    return nfcAdapter.isObserveModeSupported()
+  }
+
+  @Rpc(description = "Checks if secure NFC is supported on device")
+  fun isSecureNfcSupported(): Boolean {
+    val nfcAdapter = NfcAdapter.getDefaultAdapter(mContext)
+    return nfcAdapter.isSecureNfcSupported()
+  }
+
+  @Rpc(description = "Checks if reader option is supported on device")
+  fun isReaderOptionSupported(): Boolean {
+    val nfcAdapter = NfcAdapter.getDefaultAdapter(mContext)
+    return nfcAdapter.isReaderOptionSupported()
+  }
+
+  @Rpc(description = "Checks if controller always on is supported on device")
+  fun isControllerAlwaysOnSupported(): Boolean {
+    val nfcAdapter = NfcAdapter.getDefaultAdapter(mContext)
+    return nfcAdapter.isControllerAlwaysOnSupported()
+  }
+
+  @Rpc(description = "Start Main Activity")
+  fun startMainActivity(json: String) {
+    val instrumentation: Instrumentation = InstrumentationRegistry.getInstrumentation()
+    val intent = Intent(Intent.ACTION_MAIN)
+    intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
+    intent.setClassName(
+      instrumentation.getTargetContext(), MainActivity::class.java.getName())
+    intent.putExtra(MainActivity.SNOOP_DATA_FLAG, json)
+
+    mActivity = instrumentation.startActivitySync(intent) as MainActivity
+  }
+
+  @Rpc(description = "Close activity")
+  fun closeActivity() {
+    mActivity.finish()
+  }
+
+  @Rpc(description = "Call to set reader option")
+  fun setReaderOption(enable: Boolean) {
+    val nfcAdapter = NfcAdapter.getDefaultAdapter(mContext)
+    try {
+      val result = nfcAdapter.enableReaderOption(enable)
+      if (!result) {
+        Log.e(TAG, "Failed to set reader option")
+      }
+    } catch (e: Exception) {
+      Log.e(TAG, "Exception", e)
+    }
+  }
+
+  @Rpc(description = "Call to set NFC controller always on feature")
+  fun setControllerAlwaysOn(value: Boolean) {
+    val nfcAdapter = NfcAdapter.getDefaultAdapter(mContext)
+    val countDownLatch = CountDownLatch(1)
+    val listener = NfcControllerAlwaysOnListener(countDownLatch)
+    try {
+      nfcAdapter.registerControllerAlwaysOnListener(Executors.newSingleThreadExecutor(), listener)
+      nfcAdapter.setControllerAlwaysOn(value)
+      countDownLatch.await(5, TimeUnit.SECONDS)
+      nfcAdapter.unregisterControllerAlwaysOnListener(listener)
+    } catch (e: Exception) {
+      Log.e(TAG, "Exception", e)
+    }
+  }
+
+  @Rpc(description = "Call to set observe mode")
+  fun setObserveMode(enabled: Boolean) {
+    val nfcAdapter = NfcAdapter.getDefaultAdapter(mContext)
+    try {
+      val result = nfcAdapter.setObserveModeEnabled(enabled)
+      if (!result) {
+        Log.e(TAG, "Failed to set observe mode")
+      }
+    } catch (e: Exception) {
+      Log.e(TAG, "Exception", e)
+    }
+  }
+
+  @Rpc(description = "Call to set secure NFC")
+  fun setSecureNfc(enabled: Boolean) {
+    val nfcAdapter = NfcAdapter.getDefaultAdapter(mContext)
+    try {
+      val result = nfcAdapter.enableSecureNfc(enabled)
+      if (!result) {
+        Log.e(TAG, "Failed to set secure NFC")
+      }
+    } catch (e: Exception) {
+      Log.e(TAG, "Exception", e)
+    }
+  }
+
+  @Rpc(description = "Adopt permissions necessary to use other functions in NfcApduDeviceSnippet")
+  fun adoptPermissions() {
+    InstrumentationRegistry.getInstrumentation()
+      .getUiAutomation()
+      .adoptShellPermissionIdentity(android.Manifest.permission.WRITE_SECURE_SETTINGS)
+    InstrumentationRegistry.getInstrumentation()
+      .getUiAutomation()
+      .adoptShellPermissionIdentity(android.Manifest.permission.NFC_SET_CONTROLLER_ALWAYS_ON)
+  }
+
+  @Rpc(description = "Drop permissions")
+  fun dropPermissions() {
+    InstrumentationRegistry.getInstrumentation().getUiAutomation().dropShellPermissionIdentity()
+  }
+
+  class NfcControllerAlwaysOnListener(private val countDownLatch: CountDownLatch)
+    : NfcAdapter.ControllerAlwaysOnListener {
+    override fun onControllerAlwaysOnChanged(isEnabled: Boolean) {
+      countDownLatch.countDown()
+    }
+  }
+}
\ No newline at end of file
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/layout/activity_main.xml b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/res/layout/activity_main.xml
similarity index 100%
rename from NfcNci/testutils/src/com/android/nfc/emulatorapp/res/layout/activity_main.xml
rename to NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/res/layout/activity_main.xml
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values/strings.xml b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/res/values/strings.xml
similarity index 100%
rename from NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values/strings.xml
rename to NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/res/values/strings.xml
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values/styles.xml b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/res/values/styles.xml
similarity index 100%
rename from NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values/styles.xml
rename to NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/res/values/styles.xml
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/xml/aids.xml b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/res/xml/aids.xml
similarity index 70%
rename from NfcNci/testutils/src/com/android/nfc/emulatorapp/res/xml/aids.xml
rename to NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/res/xml/aids.xml
index 713c4182b..2c25fb27f 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/xml/aids.xml
+++ b/NfcNci/tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/res/xml/aids.xml
@@ -3,7 +3,7 @@
     android:requireDeviceUnlock="false"
     android:description="@string/app_name">
   <aid-group android:category="other">
-    <aid-filter android:name="A000000151000000"/>
-    <aid-filter android:name="A000000003000000"/>
+    <aid-filter android:name="A000000004101017"/>
+    <aid-filter android:name="A000000004101020"/>
   </aid-group>
 </host-apdu-service>
\ No newline at end of file
diff --git a/NfcNci/tests/unit/src/com/android/nfc/NfcDispatcherTest.java b/NfcNci/tests/unit/src/com/android/nfc/NfcDispatcherTest.java
index 9b98ad84d..9b9ccdb3d 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/NfcDispatcherTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/NfcDispatcherTest.java
@@ -19,8 +19,9 @@ import static android.nfc.tech.Ndef.EXTRA_NDEF_MSG;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
@@ -33,6 +34,7 @@ import android.app.KeyguardManager;
 import android.app.PendingIntent;
 import android.bluetooth.BluetoothProtoEnums;
 import android.content.BroadcastReceiver;
+import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
@@ -47,7 +49,10 @@ import android.nfc.NdefMessage;
 import android.nfc.NdefRecord;
 import android.nfc.NfcAdapter;
 import android.nfc.Tag;
+import android.nfc.tech.IsoDep;
 import android.nfc.tech.Ndef;
+import android.nfc.tech.NfcA;
+import android.nfc.tech.NfcB;
 import android.nfc.tech.NfcBarcode;
 import android.nfc.tech.TagTechnology;
 import android.os.Bundle;
@@ -55,14 +60,17 @@ import android.os.Handler;
 import android.os.Message;
 import android.os.PowerManager;
 import android.os.RemoteException;
+import android.os.ResultReceiver;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.os.test.TestLooper;
+import android.util.proto.ProtoOutputStream;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.nfc.flags.FeatureFlags;
+import com.android.nfc.flags.Flags;
 import com.android.nfc.handover.HandoverDataParser;
 import com.android.nfc.handover.PeripheralHandoverService;
 
@@ -77,8 +85,12 @@ import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 
+import java.io.FileDescriptor;
+import java.io.PrintWriter;
+import java.lang.reflect.Field;
 import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
@@ -89,7 +101,8 @@ import java.util.concurrent.atomic.AtomicBoolean;
 public final class NfcDispatcherTest {
 
     private static final String TAG = NfcDispatcherTest.class.getSimpleName();
-    @Mock private NfcInjector mNfcInjector;
+    @Mock
+    private NfcInjector mNfcInjector;
     private MockitoSession mStaticMockSession;
     private NfcDispatcher mNfcDispatcher;
     TestLooper mLooper;
@@ -167,7 +180,7 @@ public final class NfcDispatcherTest {
     public void testLogOthers() {
         Tag tag = Tag.createMockTag(null, new int[0], new Bundle[0], 0L);
         mNfcDispatcher.dispatchTag(tag);
-        ExtendedMockito.verify(() ->  NfcStatsLog.write(
+        ExtendedMockito.verify(() -> NfcStatsLog.write(
                 NfcStatsLog.NFC_TAG_OCCURRED,
                 NfcStatsLog.NFC_TAG_OCCURRED__TYPE__PROVISION,
                 -1,
@@ -387,7 +400,7 @@ public final class NfcDispatcherTest {
     }
 
     @Test
-    public void testReceiveOemCallbackResult() throws  RemoteException {
+    public void testReceiveOemCallbackResult() throws RemoteException {
         Tag tag = mock(Tag.class);
         NdefMessage ndefMessage = mock(NdefMessage.class);
         NdefRecord ndefRecord = NdefRecord.createUri("https://www.example.com");
@@ -508,4 +521,271 @@ public final class NfcDispatcherTest {
         handler.handleMessage(msg);
         verify(mAtomicBoolean).set(true);
     }
+
+    @Test
+    public void testDump() {
+        PrintWriter pw = mock(PrintWriter.class);
+        PendingIntent pendingIntent = mock(PendingIntent.class);
+        IntentFilter[] intentFilters = {};
+        String[][] techLists = {{"Ndef"}};
+        mNfcDispatcher.setForegroundDispatch(pendingIntent, intentFilters, techLists);
+
+        mNfcDispatcher.dump(mock(FileDescriptor.class), pw, new String[]{});
+        verify(pw).println("mOverrideTechLists=" + Arrays.deepToString(techLists));
+    }
+
+    @Test
+    public void testDumpDebug() {
+        ProtoOutputStream proto = mock(ProtoOutputStream.class);
+        PendingIntent pendingIntent = mock(PendingIntent.class);
+        IntentFilter[] intentFilters = {};
+        String[][] techLists = {{"Ndef"}};
+        mNfcDispatcher.setForegroundDispatch(pendingIntent, intentFilters, techLists);
+        mNfcDispatcher.disableProvisioningMode();
+        when(mAtomicBoolean.get()).thenReturn(true);
+
+        mNfcDispatcher.dumpDebug(proto);
+        verify(proto).write(NfcDispatcherProto.PROVISIONING_ONLY, false);
+    }
+
+    @Test
+    public void testExtractOemPackages() throws RemoteException {
+        NdefMessage message = mock(NdefMessage.class);
+        INfcOemExtensionCallback nfcOemExtensionCallback = mock(INfcOemExtensionCallback.class);
+        mNfcDispatcher.setOemExtension(nfcOemExtensionCallback);
+
+        mNfcDispatcher.extractOemPackages(message);
+        verify(nfcOemExtensionCallback).onExtractOemPackages(any(NdefMessage.class), any(
+                ResultReceiver.class));
+    }
+
+    @Test
+    public void testTryActivityOrLaunchAppStore()
+            throws PackageManager.NameNotFoundException, NoSuchFieldException,
+            IllegalAccessException {
+        NfcDispatcher.DispatchInfo dispatch = mock(NfcDispatcher.DispatchInfo.class);
+        List<String> packages = new ArrayList<>();
+        packages.add("example.nfc");
+        UserHandle userHandle = mock(UserHandle.class);
+        Context context = mock(Context.class);
+        PackageManager pm = mock(PackageManager.class);
+        Intent appLaunchIntent = mock(Intent.class);
+        Intent intent = mock(Intent.class);
+        List<UserHandle> luh = new ArrayList<>();
+        luh.add(userHandle);
+        when(dispatch.tryStartActivity()).thenReturn(false);
+        when(dispatch.getCurrentActiveUserHandles()).thenReturn(luh);
+        when(mockContext.createPackageContextAsUser(anyString(), anyInt(),
+                any(UserHandle.class))).thenReturn(context);
+        when(context.getPackageManager()).thenReturn(pm);
+        when(pm.getLaunchIntentForPackage(packages.getFirst())).thenReturn(appLaunchIntent);
+        when(pm.resolveActivity(appLaunchIntent, 0)).thenReturn(null);
+        when(dispatch.tryStartActivity(any(Intent.class))).thenReturn(true);
+        Field field = NfcDispatcher.DispatchInfo.class.getDeclaredField("intent");
+        field.setAccessible(true);
+        field.set(dispatch, intent);
+
+        assertTrue(mNfcDispatcher.tryActivityOrLaunchAppStore(dispatch, packages, true));
+    }
+
+    @Test
+    public void testTryActivityOrLaunchAppStoreWhenAarToNdef()
+            throws NoSuchFieldException, IllegalAccessException {
+        NfcDispatcher.DispatchInfo dispatch = mock(NfcDispatcher.DispatchInfo.class);
+        List<String> packages = new ArrayList<>();
+        packages.add("example.nfc");
+        UserHandle userHandle = mock(UserHandle.class);
+        Intent intent = mock(Intent.class);
+        List<UserHandle> luh = new ArrayList<>();
+        luh.add(userHandle);
+        when(dispatch.tryStartActivity()).thenReturn(true);
+        Field field = NfcDispatcher.DispatchInfo.class.getDeclaredField("intent");
+        field.setAccessible(true);
+        field.set(dispatch, intent);
+
+        assertTrue(mNfcDispatcher.tryActivityOrLaunchAppStore(dispatch, packages, true));
+    }
+
+    @Test
+    public void testTryActivityOrLaunchAppStoreWhenOemToNdef()
+            throws NoSuchFieldException, IllegalAccessException {
+        NfcDispatcher.DispatchInfo dispatch = mock(NfcDispatcher.DispatchInfo.class);
+        List<String> packages = new ArrayList<>();
+        packages.add("example.nfc");
+        UserHandle userHandle = mock(UserHandle.class);
+        Intent intent = mock(Intent.class);
+        List<UserHandle> luh = new ArrayList<>();
+        luh.add(userHandle);
+        when(dispatch.tryStartActivity()).thenReturn(true);
+        Field field = NfcDispatcher.DispatchInfo.class.getDeclaredField("intent");
+        field.setAccessible(true);
+        field.set(dispatch, intent);
+
+        assertTrue(mNfcDispatcher.tryActivityOrLaunchAppStore(dispatch, packages, false));
+    }
+
+    @Test
+    public void testTryActivityOrLaunchAppStoreWhenMatchedAarApplicationLaunch()
+            throws PackageManager.NameNotFoundException, NoSuchFieldException,
+            IllegalAccessException {
+        NfcDispatcher.DispatchInfo dispatch = mock(NfcDispatcher.DispatchInfo.class);
+        List<String> packages = new ArrayList<>();
+        packages.add("example.nfc");
+        UserHandle userHandle = mock(UserHandle.class);
+        Context context = mock(Context.class);
+        PackageManager pm = mock(PackageManager.class);
+        Intent appLaunchIntent = mock(Intent.class);
+        Intent intent = mock(Intent.class);
+        List<UserHandle> luh = new ArrayList<>();
+        luh.add(userHandle);
+        ResolveInfo ri = mock(ResolveInfo.class);
+        ActivityInfo activityInfo = mock(ActivityInfo.class);
+        activityInfo.exported = true;
+        ri.activityInfo = activityInfo;
+        when(dispatch.tryStartActivity()).thenReturn(false);
+        when(dispatch.getCurrentActiveUserHandles()).thenReturn(luh);
+        when(mockContext.createPackageContextAsUser(anyString(), anyInt(),
+                any(UserHandle.class))).thenReturn(context);
+        when(context.getPackageManager()).thenReturn(pm);
+        when(pm.getLaunchIntentForPackage(packages.getFirst())).thenReturn(appLaunchIntent);
+        when(pm.resolveActivity(appLaunchIntent, 0)).thenReturn(ri);
+        when(dispatch.tryStartActivity(any(Intent.class))).thenReturn(true);
+        Field field = NfcDispatcher.DispatchInfo.class.getDeclaredField("intent");
+        field.setAccessible(true);
+        field.set(dispatch, intent);
+
+        assertTrue(mNfcDispatcher.tryActivityOrLaunchAppStore(dispatch, packages, true));
+    }
+
+    @Test
+    public void testTryActivityOrLaunchAppStoreWhenMatchedOemApplicationLaunch()
+            throws PackageManager.NameNotFoundException, NoSuchFieldException,
+            IllegalAccessException {
+        NfcDispatcher.DispatchInfo dispatch = mock(NfcDispatcher.DispatchInfo.class);
+        List<String> packages = new ArrayList<>();
+        packages.add("example.nfc");
+        UserHandle userHandle = mock(UserHandle.class);
+        Context context = mock(Context.class);
+        PackageManager pm = mock(PackageManager.class);
+        Intent appLaunchIntent = mock(Intent.class);
+        Intent intent = mock(Intent.class);
+        List<UserHandle> luh = new ArrayList<>();
+        luh.add(userHandle);
+        ResolveInfo ri = mock(ResolveInfo.class);
+        ActivityInfo activityInfo = mock(ActivityInfo.class);
+        activityInfo.exported = true;
+        ri.activityInfo = activityInfo;
+        when(dispatch.tryStartActivity()).thenReturn(false);
+        when(dispatch.getCurrentActiveUserHandles()).thenReturn(luh);
+        when(mockContext.createPackageContextAsUser(anyString(), anyInt(),
+                any(UserHandle.class))).thenReturn(context);
+        when(context.getPackageManager()).thenReturn(pm);
+        when(pm.getLaunchIntentForPackage(packages.getFirst())).thenReturn(appLaunchIntent);
+        when(pm.resolveActivity(appLaunchIntent, 0)).thenReturn(ri);
+        when(dispatch.tryStartActivity(any(Intent.class))).thenReturn(true);
+        Field field = NfcDispatcher.DispatchInfo.class.getDeclaredField("intent");
+        field.setAccessible(true);
+        field.set(dispatch, intent);
+
+        assertTrue(mNfcDispatcher.tryActivityOrLaunchAppStore(dispatch, packages, false));
+        verify(pm).getLaunchIntentForPackage(packages.getFirst());
+    }
+
+    @Test
+    public void testTryActivityOrLaunchAppStoreWithException()
+            throws PackageManager.NameNotFoundException, NoSuchFieldException,
+            IllegalAccessException {
+        NfcDispatcher.DispatchInfo dispatch = mock(NfcDispatcher.DispatchInfo.class);
+        List<String> packages = new ArrayList<>();
+        packages.add("example.nfc");
+        UserHandle userHandle = mock(UserHandle.class);
+        Context context = mock(Context.class);
+        PackageManager pm = mock(PackageManager.class);
+        Intent intent = mock(Intent.class);
+        List<UserHandle> luh = new ArrayList<>();
+        luh.add(userHandle);
+        ResolveInfo ri = mock(ResolveInfo.class);
+        ActivityInfo activityInfo = mock(ActivityInfo.class);
+        activityInfo.exported = true;
+        ri.activityInfo = activityInfo;
+        when(dispatch.tryStartActivity()).thenReturn(false);
+        when(dispatch.getCurrentActiveUserHandles()).thenReturn(luh);
+        when(mockContext.createPackageContextAsUser(anyString(), anyInt(),
+                any(UserHandle.class))).thenThrow(PackageManager.NameNotFoundException.class);
+        when(context.getPackageManager()).thenReturn(pm);
+        Field field = NfcDispatcher.DispatchInfo.class.getDeclaredField("intent");
+        field.setAccessible(true);
+        field.set(dispatch, intent);
+        INfcOemExtensionCallback nfcOemExtensionCallback = mock(INfcOemExtensionCallback.class);
+        mNfcDispatcher.setOemExtension(nfcOemExtensionCallback);
+
+        assertFalse(mNfcDispatcher.tryActivityOrLaunchAppStore(dispatch, packages, false));
+    }
+
+    @Test
+    public void testTryTechWithSingleMatch() throws IllegalAccessException, NoSuchFieldException,
+            PackageManager.NameNotFoundException {
+        NfcDispatcher.DispatchInfo dispatch = mock(NfcDispatcher.DispatchInfo.class);
+        RegisteredComponentCache mTechListFilters = mock(RegisteredComponentCache.class);
+        UserHandle userHandle = mock(UserHandle.class);
+        Context context = mock(Context.class);
+        ResolveInfo resolveInfo = mock(ResolveInfo.class);
+        ActivityInfo activityInfo = mock(ActivityInfo.class);
+        ApplicationInfo appInfo = mock(ApplicationInfo.class);
+        Intent intent = mock(Intent.class);
+        Tag tag = mock(Tag.class);
+        String packageName = "sample.package.name";
+        RegisteredComponentCache.ComponentInfo info = mock(
+                RegisteredComponentCache.ComponentInfo.class);
+        PackageManager pm = mock(PackageManager.class);
+        List<UserHandle> luh = new ArrayList<>();
+        luh.add(userHandle);
+        ArrayList<RegisteredComponentCache.ComponentInfo> registered = new ArrayList<>();
+        registered.add(info);
+        Map<String, Boolean> prefList = new HashMap<>();
+        prefList.put(packageName + "another", true);
+        String[] tagTechs =
+                new String[]{IsoDep.class.getName(), NfcA.class.getName(), NfcB.class.getName()};
+        Field field = NfcDispatcher.class.getDeclaredField("mTechListFilters");
+        field.setAccessible(true);
+        field.set(mNfcDispatcher, mTechListFilters);
+        Field fieldCompInfoResolveInfo =
+                RegisteredComponentCache.ComponentInfo.class.getDeclaredField("resolveInfo");
+        fieldCompInfoResolveInfo.setAccessible(true);
+        fieldCompInfoResolveInfo.set(info, resolveInfo);
+        activityInfo.exported = true;
+        activityInfo.applicationInfo = appInfo;
+        activityInfo.packageName = packageName;
+        activityInfo.name = "name";
+        resolveInfo.activityInfo = activityInfo;
+        Field fieldCompInfoResolveTech =
+                RegisteredComponentCache.ComponentInfo.class.getDeclaredField("techs");
+        fieldCompInfoResolveTech.setAccessible(true);
+        fieldCompInfoResolveTech.set(info, tagTechs);
+        Field fieldNfcAdapter = NfcDispatcher.class.getDeclaredField("mNfcAdapter");
+        fieldNfcAdapter.setAccessible(true);
+        fieldNfcAdapter.set(mNfcDispatcher, mNfcAdapter);
+        Field fieldTagAppSupported = NfcDispatcher.class.getDeclaredField("mIsTagAppPrefSupported");
+        fieldTagAppSupported.setAccessible(true);
+        fieldTagAppSupported.set(mNfcDispatcher, true);
+        Field fieldIntent = NfcDispatcher.DispatchInfo.class.getDeclaredField("intent");
+        fieldIntent.setAccessible(true);
+        fieldIntent.set(dispatch, intent);
+        when(tag.getTechList()).thenReturn(tagTechs);
+        when(mTechListFilters.getComponents()).thenReturn(registered);
+        when(dispatch.getCurrentActiveUserHandles()).thenReturn(luh);
+        when(mockContext.createPackageContextAsUser("android", 0, userHandle))
+                .thenReturn(context);
+        when(context.getPackageManager()).thenReturn(pm);
+        when(pm.getActivityInfo(any(ComponentName.class), anyInt())).thenReturn(activityInfo);
+        when(mockContext.getPackageManager()).thenReturn(pm);
+        when(pm.getApplicationLabel(appInfo)).thenReturn("appname");
+        when(userHandle.getIdentifier()).thenReturn(0);
+        when(mNfcAdapter.getTagIntentAppPreferenceForUser(0)).thenReturn(prefList);
+        when(Flags.nfcAlertTagAppLaunch()).thenReturn(false);
+        when(dispatch.tryStartActivity()).thenReturn(true);
+
+        assertTrue(mNfcDispatcher.tryTech(dispatch, tag));
+        verify(mNfcAdapter).setTagIntentAppPreferenceForUser(0, packageName, true);
+    }
 }
diff --git a/NfcNci/tests/unit/src/com/android/nfc/NfcRoutingTableParseTest.java b/NfcNci/tests/unit/src/com/android/nfc/NfcRoutingTableParseTest.java
index d435fde03..8433e8cdf 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/NfcRoutingTableParseTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/NfcRoutingTableParseTest.java
@@ -15,18 +15,34 @@
  */
 package com.android.nfc;
 
+import static com.android.nfc.RoutingTableParser.TYPE_AID;
+
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.junit.Assert.assertEquals;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.nfc.Entry;
+
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.nfc.cardemulation.RoutingOptionManager;
+
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.mockito.MockitoSession;
+import org.mockito.quality.Strictness;
+
+import java.io.PrintWriter;
+import java.util.List;
 
 @RunWith(AndroidJUnit4.class)
 public final class NfcRoutingTableParseTest {
-    private static final String TAG = NfcRoutingTableParseTest.class.getSimpleName();
     private RoutingTableParser mRoutingTableParser;
 
     // NFCEE-ID
@@ -40,16 +56,21 @@ public final class NfcRoutingTableParseTest {
     static final byte SWITCH_ON_SUB_2 = (byte) 0x10;
     static final byte SWITCH_ON_SUB_1 = (byte) 0x08;
     static final byte BATTERY_OFF = (byte) 0x04;
-    static final byte SWITCH_OFF = (byte) 0x02;
     static final byte SWITCH_ON = (byte) 0x01;
+    private MockitoSession mStaticMockSession;
 
     @Before
     public void setUp() {
+        mStaticMockSession = ExtendedMockito.mockitoSession()
+                .mockStatic(RoutingOptionManager.class)
+                .strictness(Strictness.LENIENT)
+                .startMocking();
         mRoutingTableParser = new RoutingTableParser();
     }
 
     @After
     public void tearDown() throws Exception {
+        mStaticMockSession.finishMocking();
     }
 
     @Test
@@ -135,7 +156,7 @@ public final class NfcRoutingTableParseTest {
          * where it is not supported
          */
         byte qualifier = (byte) 0x40;
-        byte type = RoutingTableParser.TYPE_AID;
+        byte type = TYPE_AID;
         byte eeId = EE_ID_UICC;
         byte pwrState = (byte) (APPLY_ALL ^ BATTERY_OFF);
         byte[] entry = hexStrToByteArray("6E6663746573743031");
@@ -154,7 +175,7 @@ public final class NfcRoutingTableParseTest {
          * where it is not supported
          */
         byte qualifier = (byte) 0x40;
-        byte type = RoutingTableParser.TYPE_AID;
+        byte type = TYPE_AID;
         byte eeId = EE_ID_UICC;
         byte pwrState = (byte) (APPLY_ALL ^ BATTERY_OFF);
         byte[] entry = hexStrToByteArray("6E66637465737430316E6663746573743031");
@@ -259,9 +280,148 @@ public final class NfcRoutingTableParseTest {
             if (value > 127) {
                 value -= 256;
             }
-            byteArr [i] = (byte) value;
+            byteArr[i] = (byte) value;
         }
 
         return byteArr;
     }
+
+    @Test
+    public void testDump() {
+        byte qualifier = (byte) 0x40;
+        byte type = RoutingTableParser.TYPE_SYSTEMCODE;
+        byte eeId = EE_ID_ESE;
+        byte pwrState = (byte) (APPLY_ALL ^ BATTERY_OFF);
+        byte[] entryAll = hexStrToByteArray("FEFEEEEE");
+        byte[] rt = generateRoutingEntry(qualifier, type, eeId, pwrState, entryAll);
+        DeviceHost dh = mock(DeviceHost.class);
+        PrintWriter pw = mock(PrintWriter.class);
+        when(dh.getMaxRoutingTableSize()).thenReturn(1);
+        when(dh.getRoutingTable()).thenReturn(rt);
+
+        mRoutingTableParser.dump(dh, pw);
+        verify(dh).getRoutingTable();
+        verify(pw).println("--- dumpRoutingTable:  end  ---");
+    }
+
+    @Test
+    public void testGetRoutingEntryInfo() {
+        byte qualifier = (byte) 0x40;
+        byte type = TYPE_AID;
+        byte eeId = EE_ID_ESE;
+        byte pwrState = (byte) (APPLY_ALL ^ BATTERY_OFF);
+        byte[] entryAll = hexStrToByteArray("FEFEEEEE");
+        byte[] rt = generateRoutingEntry(qualifier, type, eeId, pwrState, entryAll);
+        DeviceHost dh = mock(DeviceHost.class);
+        when(dh.getMaxRoutingTableSize()).thenReturn(1);
+        when(dh.getRoutingTable()).thenReturn(rt);
+        RoutingOptionManager routingOptionManager = mock(RoutingOptionManager.class);
+        when(RoutingOptionManager.getInstance()).thenReturn(routingOptionManager);
+
+        List<Entry> entries = mRoutingTableParser.getRoutingTableEntryList(dh);
+        Entry entry = new Entry(getAidStr(entryAll), type, eeId,
+                routingOptionManager.getSecureElementForRoute(eeId), pwrState);
+        assertEquals(entry.getEntry(), entries.getFirst().getEntry());
+    }
+
+    @Test
+    public void testGetRoutingEntryInfoWithEmptyAid() {
+        byte qualifier = (byte) 0x40;
+        byte type = TYPE_AID;
+        byte eeId = EE_ID_ESE;
+        byte pwrState = (byte) (APPLY_ALL ^ BATTERY_OFF);
+        byte[] entryAll = hexStrToByteArray("");
+        byte[] rt = generateRoutingEntry(qualifier, type, eeId, pwrState, entryAll);
+        DeviceHost dh = mock(DeviceHost.class);
+        when(dh.getMaxRoutingTableSize()).thenReturn(1);
+        when(dh.getRoutingTable()).thenReturn(rt);
+        RoutingOptionManager routingOptionManager = mock(RoutingOptionManager.class);
+        when(RoutingOptionManager.getInstance()).thenReturn(routingOptionManager);
+
+        List<Entry> entries = mRoutingTableParser.getRoutingTableEntryList(dh);
+        Entry entry = new Entry(getAidStr(entryAll), type, eeId,
+                routingOptionManager.getSecureElementForRoute(eeId), pwrState);
+        assertEquals(entry.getEntry(), entries.getFirst().getEntry());
+    }
+
+    String getAidStr(byte[] aid) {
+        String aidStr = "";
+
+        for (byte b : aid) {
+            aidStr += String.format("%02X", b);
+        }
+
+        if (aidStr.length() == 0) {
+            return "Empty_AID";
+        }
+        return "AID_" + aidStr;
+    }
+
+    @Test
+    public void testGetBlockCtrlStr() {
+        assertEquals("True", mRoutingTableParser.accessGetBlockCtrlStr((byte) 0x40));
+        assertEquals("False", mRoutingTableParser.accessGetBlockCtrlStr((byte) 0x10));
+    }
+
+    @Test
+    public void testGetPrefixSubsetStrTypeNotAid() {
+        assertEquals("", mRoutingTableParser.accessGetPrefixSubsetStr((byte) 0x30, (byte) 0x01));
+    }
+
+    @Test
+    public void testGetPrefixSubsetStrMaskHasPrefixOnly() {
+        assertEquals("Prefix ",
+                mRoutingTableParser.accessGetPrefixSubsetStr((byte) 0x10, TYPE_AID));
+    }
+
+    @Test
+    public void testGetPrefixSubsetStrMaskHasSubsetOnly() {
+        assertEquals("Subset", mRoutingTableParser.accessGetPrefixSubsetStr((byte) 0x20, TYPE_AID));
+    }
+
+    @Test
+    public void testGetPrefixSubsetStrMaskHasBothPrefixAndSubset() {
+        assertEquals("Prefix Subset",
+                mRoutingTableParser.accessGetPrefixSubsetStr((byte) 0x30, TYPE_AID));
+    }
+
+    @Test
+    public void testGetPrefixSubsetStrMaskHasNeitherPrefixNorSubset() {
+        assertEquals("Exact", mRoutingTableParser.accessGetPrefixSubsetStr((byte) 0x0F, TYPE_AID));
+    }
+
+    @Test
+    public void testGetPrefixSubsetStrMaskIsZero() {
+        assertEquals("Exact", mRoutingTableParser.accessGetPrefixSubsetStr((byte) 0x00, TYPE_AID));
+    }
+
+    @Test
+    public void testGetSystemCodeStrEmptyByteArray() {
+        byte[] systemCode = {};
+        assertEquals("SYSTEMCODE_", mRoutingTableParser.accessGetSystemCodeStr(systemCode));
+    }
+
+    @Test
+    public void testGetSystemCodeStrSingleByte() {
+        byte[] systemCode = {0x01};
+        assertEquals("SYSTEMCODE_01", mRoutingTableParser.accessGetSystemCodeStr(systemCode));
+    }
+
+    @Test
+    public void testGetSystemCodeStrMultipleBytes() {
+        byte[] systemCode = {0x1A, 0x2B, 0x3C};
+        assertEquals("SYSTEMCODE_1A2B3C", mRoutingTableParser.accessGetSystemCodeStr(systemCode));
+    }
+
+    @Test
+    public void testGetSystemCodeStrBytesWithLeadingZeros() {
+        byte[] systemCode = {0x0A, 0x0B, 0x0C};
+        assertEquals("SYSTEMCODE_0A0B0C", mRoutingTableParser.accessGetSystemCodeStr(systemCode));
+    }
+
+    @Test
+    public void testGetSystemCodeStrBytesWithMaxHexValue() {
+        byte[] systemCode = {(byte) 0xFF, (byte) 0xFE};
+        assertEquals("SYSTEMCODE_FFFE", mRoutingTableParser.accessGetSystemCodeStr(systemCode));
+    }
 }
diff --git a/NfcNci/tests/unit/src/com/android/nfc/NfcServiceTest.java b/NfcNci/tests/unit/src/com/android/nfc/NfcServiceTest.java
index 40c0eddcf..87f2bacf9 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/NfcServiceTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/NfcServiceTest.java
@@ -30,8 +30,10 @@ import static com.android.nfc.NfcService.SOUND_ERROR;
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertArrayEquals;
-import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyFloat;
@@ -124,7 +126,6 @@ import com.android.nfc.flags.FeatureFlags;
 import com.android.nfc.flags.Flags;
 import com.android.nfc.wlc.NfcCharging;
 
-
 import org.junit.After;
 import org.junit.Assert;
 import org.junit.Assume;
@@ -248,6 +249,7 @@ public final class NfcServiceTest {
         when(mNfcInjector.isSatelliteModeSensitive()).thenReturn(true);
         when(mNfcInjector.getCardEmulationManager()).thenReturn(mCardEmulationManager);
         when(mNfcInjector.getNfcCharging(mDeviceHost)).thenReturn(mNfcCharging);
+        when(mNfcInjector.getNfcBroadcastLooper()).thenReturn(mLooper.getLooper());
         when(mApplication.getSharedPreferences(anyString(), anyInt())).thenReturn(mPreferences);
         when(mApplication.getSystemService(PowerManager.class)).thenReturn(mPowerManager);
         when(mApplication.getSystemService(UserManager.class)).thenReturn(mUserManager);
@@ -414,7 +416,10 @@ public final class NfcServiceTest {
     public void testEnableNfc_changeStateRestricted() throws Exception {
         when(mUserRestrictions.getBoolean(
                 UserManager.DISALLOW_CHANGE_NEAR_FIELD_COMMUNICATION_RADIO)).thenReturn(true);
-        mNfcService.mNfcAdapter.enable(PKG_NAME);
+        Exception exception = assertThrows(SecurityException.class, () -> {
+            mNfcService.mNfcAdapter.enable(PKG_NAME);
+        });
+        assertEquals("Change nfc state by system app is not allowed!", exception.getMessage());
         assert(mNfcService.mState == NfcAdapter.STATE_OFF);
     }
 
@@ -423,7 +428,10 @@ public final class NfcServiceTest {
         enableAndVerify();
         when(mUserRestrictions.getBoolean(
                 UserManager.DISALLOW_CHANGE_NEAR_FIELD_COMMUNICATION_RADIO)).thenReturn(true);
-        mNfcService.mNfcAdapter.disable(true, PKG_NAME);
+        Exception exception = assertThrows(SecurityException.class, () -> {
+            mNfcService.mNfcAdapter.disable(true, PKG_NAME);
+        });
+        assertEquals("Change nfc state by system app is not allowed!", exception.getMessage());
         assert(mNfcService.mState == NfcAdapter.STATE_ON);
     }
 
@@ -607,6 +615,7 @@ public final class NfcServiceTest {
         mNfcService.mIsRequestUnlockShowed = false;
         when(mNfcInjector.isDeviceLocked()).thenReturn(true);
         handler.handleMessage(msg);
+        mLooper.dispatchAll();
         verify(mApplication).sendBroadcastAsUser(mIntentArgumentCaptor.capture(), any());
         Intent intent = mIntentArgumentCaptor.getValue();
         Assert.assertNotNull(intent);
@@ -625,6 +634,7 @@ public final class NfcServiceTest {
         userlist.add("com.android.nfc");
         mNfcService.mNfcEventInstalledPackages.put(1, userlist);
         handler.handleMessage(msg);
+        mLooper.dispatchAll();
         verify(mApplication).sendBroadcastAsUser(mIntentArgumentCaptor.capture(), any());
         Intent intent = mIntentArgumentCaptor.getValue();
         Assert.assertNotNull(intent);
@@ -824,7 +834,6 @@ public final class NfcServiceTest {
     @Test
     public void testDirectBootAware() throws Exception {
         when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
-        when(mFeatureFlags.enableDirectBootAware()).thenReturn(true);
         mNfcService = new NfcService(mApplication, mNfcInjector);
         mLooper.dispatchAll();
         verify(mNfcInjector).makeDeviceHost(mDeviceHostListener.capture());
@@ -859,6 +868,7 @@ public final class NfcServiceTest {
     public void testAllowOemOnTagDispatchCallback() throws Exception {
         when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
         INfcOemExtensionCallback callback = mock(INfcOemExtensionCallback.class);
+        when(callback.asBinder()).thenReturn(mock(IBinder.class));
         mNfcService.mNfcAdapter.registerOemExtensionCallback(callback);
         Handler handler = mNfcService.getHandler();
         Assert.assertNotNull(handler);
@@ -905,6 +915,7 @@ public final class NfcServiceTest {
     public void testAllowOemOnNdefReadCallback() throws Exception {
         when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
         INfcOemExtensionCallback callback = mock(INfcOemExtensionCallback.class);
+        when(callback.asBinder()).thenReturn(mock(IBinder.class));
         mNfcService.mNfcAdapter.registerOemExtensionCallback(callback);
         Handler handler = mNfcService.getHandler();
         Assert.assertNotNull(handler);
@@ -950,6 +961,7 @@ public final class NfcServiceTest {
     @Test
     public void testAllowOemOnApplyRoutingCallback() throws Exception {
         INfcOemExtensionCallback callback = mock(INfcOemExtensionCallback.class);
+        when(callback.asBinder()).thenReturn(mock(IBinder.class));
         mNfcService.mNfcAdapter.registerOemExtensionCallback(callback);
         mNfcService.mState = NfcAdapter.STATE_ON;
         INfcUnlockHandler binder = mock(INfcUnlockHandler.class);
@@ -1132,6 +1144,7 @@ public final class NfcServiceTest {
         assertThat(pollTech).isEqualTo(0);
         when(mPreferences.getInt(NfcService.PREF_POLL_TECH, NfcService.DEFAULT_POLL_TECH))
                 .thenReturn(NfcService.DEFAULT_LISTEN_TECH);
+        mNfcService.mIsReaderOptionEnabled = true;
         pollTech = mNfcService.getNfcPollTech();
         assertThat(pollTech).isEqualTo(0xf);
         verify(mPreferences, atLeastOnce()).getInt(anyString(), anyInt());
@@ -1226,6 +1239,7 @@ public final class NfcServiceTest {
     public void testOnHostCardEmulationActivated() throws RemoteException {
         when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
         INfcOemExtensionCallback callback = mock(INfcOemExtensionCallback.class);
+        when(callback.asBinder()).thenReturn(mock(IBinder.class));
         mNfcService.mNfcAdapter.registerOemExtensionCallback(callback);
         verify(callback).onCardEmulationActivated(anyBoolean());
         when(android.nfc.Flags.nfcPersistLog()).thenReturn(true);
@@ -1238,6 +1252,7 @@ public final class NfcServiceTest {
     public void testOnHostCardEmulationDeactivated()  throws RemoteException {
         when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
         INfcOemExtensionCallback callback = mock(INfcOemExtensionCallback.class);
+        when(callback.asBinder()).thenReturn(mock(IBinder.class));
         mNfcService.mNfcAdapter.registerOemExtensionCallback(callback);
         verify(callback).onCardEmulationActivated(false);
         when(android.nfc.Flags.nfcPersistLog()).thenReturn(true);
@@ -1287,7 +1302,7 @@ public final class NfcServiceTest {
         byte[] data = { 0x12, 0x34, 0x56, 0x78, 0x78 };
         mNfcService.onNfcTransactionEvent(aid, data, "SecureElement1");
         mLooper.dispatchAll();
-        verify(mCardEmulationManager).onOffHostAidSelected();
+        verify(mCardEmulationManager).onOffHostAidTransaction();
         verify(mPackageManager).queryBroadcastReceiversAsUser(any(), anyInt(), any());
         verify(mApplication).sendBroadcastAsUser(any(), any(), isNull(), any());
     }
@@ -1315,6 +1330,7 @@ public final class NfcServiceTest {
         when(mNfcInjector.isDeviceLocked()).thenReturn(true);
         mNfcService.mNfcEventInstalledPackages.put(1, userlist);
         INfcOemExtensionCallback callback = mock(INfcOemExtensionCallback.class);
+        when(callback.asBinder()).thenReturn(mock(IBinder.class));
         mNfcService.mNfcAdapter.registerOemExtensionCallback(callback);
         when(android.nfc.Flags.nfcPersistLog()).thenReturn(true);
         mNfcService.onRemoteFieldActivated();
@@ -1337,6 +1353,7 @@ public final class NfcServiceTest {
         when(mKeyguardManager.isKeyguardLocked()).thenReturn(true);
         mNfcService.mNfcEventInstalledPackages.put(1, userlist);
         INfcOemExtensionCallback callback = mock(INfcOemExtensionCallback.class);
+        when(callback.asBinder()).thenReturn(mock(IBinder.class));
         mNfcService.mNfcAdapter.registerOemExtensionCallback(callback);
         when(android.nfc.Flags.nfcPersistLog()).thenReturn(true);
         mNfcService.onRemoteFieldDeactivated();
@@ -1376,9 +1393,11 @@ public final class NfcServiceTest {
 
     @Test
     public void testOnSeSelected() {
-        mNfcService.onSeSelected(NfcService.SE_SELECTED_AID);
+        byte[] aid = new byte[]{ 0x0A, 0x00, 0x00, 0x00 };
+        mNfcService.onSeSelected(
+                NfcService.SE_SELECTED_AID, aid, "eSE1");
         mLooper.dispatchAll();
-        verify(mCardEmulationManager).onOffHostAidSelected();
+        verify(mCardEmulationManager).onOffHostAidSelected(Utils.aidBytesToString(aid), "eSE1");
     }
 
     @Test
@@ -1507,18 +1526,21 @@ public final class NfcServiceTest {
     }
 
     @Test
-    public void testSetPowerSavingMode() throws RemoteException {
+    public void testSetPowerSavingModeNciMessage() throws RemoteException {
         mNfcService.mState = NfcAdapter.STATE_ON;
         byte[] payload = { 0x01, 0x01, 0x00, 0x00 };
+        when(mDeviceHost.isPowerSavingModeSupported()).thenReturn(true);
         when(mDeviceHost.setPowerSavingMode(true)).thenReturn(true);
         int result = mNfcService.mNfcAdapter.sendVendorNciMessage(1,0x0f,0x0c, payload);
         mLooper.dispatchAll();
         assertThat(result).isEqualTo(0x00);
-        verify(mDeviceHost).setPowerSavingMode(anyBoolean());
+        verify(mDeviceHost).setPowerSavingMode(eq(true));
     }
 
     @Test
-    public void testSetSystemCodeRoute() {
+    public void testSetSystemCodeRoute() throws Exception {
+        enableAndVerify();
+
         mNfcService.setSystemCodeRoute(1);
         mLooper.dispatchAll();
         ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
@@ -1651,6 +1673,7 @@ public final class NfcServiceTest {
     public void testEnableReaderOption() throws RemoteException {
         when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
         INfcOemExtensionCallback callback = mock(INfcOemExtensionCallback.class);
+        when(callback.asBinder()).thenReturn(mock(IBinder.class));
         mNfcService.mNfcAdapter.registerOemExtensionCallback(callback);
         mNfcService.mReaderOptionCapable = true;
         when(android.nfc.Flags.nfcPersistLog()).thenReturn(true);
@@ -2120,13 +2143,17 @@ public final class NfcServiceTest {
     public void testUnregisterOemExtensionCallback() throws RemoteException {
         when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
         INfcOemExtensionCallback callback = mock(INfcOemExtensionCallback.class);
+        IBinder binder = mock(IBinder.class);
+        when(callback.asBinder()).thenReturn(binder);
         mNfcService.mNfcAdapter.registerOemExtensionCallback(callback);
+        verify(binder).linkToDeath(any(), anyInt());
         ArgumentCaptor<INfcOemExtensionCallback> captor = ArgumentCaptor
                 .forClass(INfcOemExtensionCallback.class);
         verify(mCardEmulationManager).setOemExtension(captor.capture());
         assertThat(captor.getValue()).isEqualTo(callback);
 
         mNfcService.mNfcAdapter.unregisterOemExtensionCallback(callback);
+        verify(binder).unlinkToDeath(any(), anyInt());
         mNfcService.onHostCardEmulationActivated(Ndef.NDEF);
         verify(callback, times(1)).onCardEmulationActivated(anyBoolean());
     }
@@ -2237,6 +2264,7 @@ public final class NfcServiceTest {
         Assert.assertNotNull(callback);
         when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
         INfcOemExtensionCallback oemExtensionCallback = mock(INfcOemExtensionCallback.class);
+        when(oemExtensionCallback.asBinder()).thenReturn(mock(IBinder.class));
         mNfcService.mNfcAdapter.registerOemExtensionCallback(oemExtensionCallback);
         callback.onTagDisconnected();
         assertThat(mNfcService.mCookieUpToDate).isLessThan(0);
diff --git a/NfcNci/tests/unit/src/com/android/nfc/NfcShellCommandTest.java b/NfcNci/tests/unit/src/com/android/nfc/NfcShellCommandTest.java
index cfc8a263e..a5a8ad5f2 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/NfcShellCommandTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/NfcShellCommandTest.java
@@ -16,22 +16,28 @@
 
 package com.android.nfc;
 
-
+import static com.android.nfc.NfcShellCommand.SHELL_PACKAGE_NAME;
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.ArgumentMatchers.isNull;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.content.Context;
 import android.content.pm.PackageManager;
+import android.nfc.INfcCardEmulation;
+import android.nfc.INfcDta;
 import android.os.Binder;
 import android.os.RemoteException;
 
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.nfc.cardemulation.CardEmulationManager;
 
@@ -43,11 +49,6 @@ import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
-import androidx.test.ext.junit.runners.AndroidJUnit4;
-import static org.mockito.ArgumentMatchers.isNull;
-import android.nfc.INfcDta;
-import android.nfc.INfcCardEmulation;
-
 
 import java.io.FileDescriptor;
 import java.io.PrintWriter;
@@ -114,9 +115,8 @@ public class NfcShellCommandTest {
     public void testOnCommandEnableNfc() throws RemoteException {
         NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
         mNfcService.mNfcAdapter = nfcAdapterService;
-        when(mContext.getPackageName()).thenReturn("com.android.test");
         int status = mNfcShellCommand.onCommand("enable-nfc");
-        verify(nfcAdapterService).enable("com.android.test");
+        verify(nfcAdapterService).enable(SHELL_PACKAGE_NAME);
         assertThat(status).isEqualTo(0);
     }
 
@@ -129,7 +129,8 @@ public class NfcShellCommandTest {
                 .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                         mFileDescriptorErr, new String[]{"enable-polling"}, 0);
         int status = mNfcShellCommand.onCommand("set-reader-mode");
-        verify(nfcAdapterService).setReaderMode(any(), isNull(), anyInt(), isNull(), isNull());
+        verify(nfcAdapterService).setReaderMode(
+                any(), isNull(), anyInt(), isNull(), eq(SHELL_PACKAGE_NAME));
         assertThat(status).isEqualTo(0);
     }
 
@@ -142,7 +143,7 @@ public class NfcShellCommandTest {
                 .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                         mFileDescriptorErr, new String[]{"enable"}, 0);
         int status = mNfcShellCommand.onCommand("set-observe-mode");
-        verify(nfcAdapterService).setObserveMode(anyBoolean(), isNull());
+        verify(nfcAdapterService).setObserveMode(anyBoolean(), eq(SHELL_PACKAGE_NAME));
         assertThat(status).isEqualTo(0);
     }
 
@@ -166,7 +167,6 @@ public class NfcShellCommandTest {
         mNfcShellCommand
                 .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                         mFileDescriptorErr, new String[]{"1", "2"}, 0);
-        when(mContext.getPackageName()).thenReturn("com.android.test");
         int status = mNfcShellCommand.onCommand("set-discovery-tech");
         verify(nfcAdapterService).updateDiscoveryTechnology(any(), anyInt(), anyInt(), anyString());
         assertThat(status).isEqualTo(0);
@@ -179,9 +179,8 @@ public class NfcShellCommandTest {
         mNfcShellCommand
                 .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                         mFileDescriptorErr, new String[]{"enable"}, 0);
-        when(mContext.getPackageName()).thenReturn("com.android.test");
         INfcDta dtaService = mock(INfcDta.class);
-        when(nfcAdapterService.getNfcDtaInterface("com.android.test")).thenReturn(dtaService);
+        when(nfcAdapterService.getNfcDtaInterface(SHELL_PACKAGE_NAME)).thenReturn(dtaService);
         int status = mNfcShellCommand.onCommand("configure-dta");
         verify(mPrintWriter).println("  configure-dta");
         verify(mPrintWriter).println("  enableDta()");
@@ -195,7 +194,7 @@ public class NfcShellCommandTest {
         mNfcService.mNfcAdapter = nfcAdapterService;
         mNfcShellCommand
                 .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
-                        mFileDescriptorErr, new String[]{"1", "com.android.test",
+                        mFileDescriptorErr, new String[]{"1", SHELL_PACKAGE_NAME,
                                 "NfcTest", "test"}, 0);
         CardEmulationManager cardEmulationManager = mock(CardEmulationManager.class);
         INfcCardEmulation iNfcCardEmulation = mock(INfcCardEmulation.class);
@@ -213,7 +212,7 @@ public class NfcShellCommandTest {
         mNfcService.mNfcAdapter = nfcAdapterService;
         mNfcShellCommand
                 .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
-                        mFileDescriptorErr, new String[]{"1", "com.android.test",
+                        mFileDescriptorErr, new String[]{"1", SHELL_PACKAGE_NAME,
                                 "NfcTest"}, 0);
         CardEmulationManager cardEmulationManager = mock(CardEmulationManager.class);
         INfcCardEmulation iNfcCardEmulation = mock(INfcCardEmulation.class);
@@ -231,7 +230,7 @@ public class NfcShellCommandTest {
         mNfcService.mNfcAdapter = nfcAdapterService;
         mNfcShellCommand
                 .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
-                        mFileDescriptorErr, new String[]{"1", "com.android.test",
+                        mFileDescriptorErr, new String[]{"1", SHELL_PACKAGE_NAME,
                                 "NfcTest", "325041592E5359532E4444463031", "payment"}, 0);
         CardEmulationManager cardEmulationManager = mock(CardEmulationManager.class);
         INfcCardEmulation iNfcCardEmulation = mock(INfcCardEmulation.class);
@@ -250,7 +249,7 @@ public class NfcShellCommandTest {
         mNfcService.mNfcAdapter = nfcAdapterService;
         mNfcShellCommand
                 .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
-                        mFileDescriptorErr, new String[]{"1", "com.android.test",
+                        mFileDescriptorErr, new String[]{"1", SHELL_PACKAGE_NAME,
                                 "NfcTest", "payment"}, 0);
         CardEmulationManager cardEmulationManager = mock(CardEmulationManager.class);
         INfcCardEmulation iNfcCardEmulation = mock(INfcCardEmulation.class);
@@ -261,4 +260,55 @@ public class NfcShellCommandTest {
         verify(iNfcCardEmulation).removeAidGroupForService(anyInt(), any(), any());
         assertThat(status).isEqualTo(0);
     }
+
+    @Test
+    public void testOnHelp() {
+        mNfcShellCommand.onHelp();
+        verify(mPrintWriter).println("    Toggle NFC off (optionally make it persistent)");
+    }
+
+    @Test
+    public void testOnCommandSetReaderModeWithDisable() throws RemoteException {
+        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
+        mNfcService.mNfcAdapter = nfcAdapterService;
+        when(ArrayUtils.indexOf(any(), anyString())).thenReturn(0);
+        mNfcShellCommand
+                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
+                        mFileDescriptorErr, new String[]{"disable-polling"}, 0);
+        int status = mNfcShellCommand.onCommand("set-reader-mode");
+        verify(nfcAdapterService).setReaderMode(
+                any(), isNull(), eq(0x1000), isNull(), eq(SHELL_PACKAGE_NAME));
+        assertThat(status).isEqualTo(0);
+    }
+
+    @Test
+    public void testOnCommandConfigureDtaWithDisable() throws RemoteException {
+        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
+        mNfcService.mNfcAdapter = nfcAdapterService;
+        mNfcShellCommand
+                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
+                        mFileDescriptorErr, new String[]{"disable"}, 0);
+        INfcDta dtaService = mock(INfcDta.class);
+        when(nfcAdapterService.getNfcDtaInterface(SHELL_PACKAGE_NAME)).thenReturn(dtaService);
+        int status = mNfcShellCommand.onCommand("configure-dta");
+        verify(mPrintWriter).println("  configure-dta");
+        verify(mPrintWriter).println("  disableDta()");
+        verify(dtaService).disableDta();
+        assertThat(status).isEqualTo(0);
+    }
+
+    @Test
+    public void testOnCommandConfigureDtaWithException() throws RemoteException {
+        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
+        mNfcService.mNfcAdapter = nfcAdapterService;
+        mNfcShellCommand
+                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
+                        mFileDescriptorErr, new String[]{"enable"}, 0);
+        when(nfcAdapterService.getNfcDtaInterface(SHELL_PACKAGE_NAME)).thenThrow(
+                RemoteException.class);
+        int status = mNfcShellCommand.onCommand("configure-dta");
+        verify(mPrintWriter).println("  configure-dta");
+        verify(mPrintWriter).println("Exception while executing nfc shell command configureDta():");
+        assertThat(status).isEqualTo(0);
+    }
 }
diff --git a/NfcNci/tests/unit/src/com/android/nfc/UtilsTest.java b/NfcNci/tests/unit/src/com/android/nfc/UtilsTest.java
index b354d84ad..652955deb 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/UtilsTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/UtilsTest.java
@@ -19,31 +19,37 @@ package com.android.nfc;
 import static android.Manifest.permission.BIND_NFC_SERVICE;
 import static android.Manifest.permission.NFC;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.app.PendingIntent;
 import android.content.Context;
 import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.IntentFilterProto;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.ServiceInfo;
 import android.net.Uri;
+import android.os.PatternMatcher;
 import android.os.UserHandle;
-import android.text.TextUtils;
-import android.util.Log;
+import android.util.proto.ProtoOutputStream;
 
 import org.junit.Before;
 import org.junit.Test;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
-import java.util.Arrays;
-
-import static org.junit.Assert.assertFalse;
-import static org.junit.Assert.assertTrue;
-import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.anyInt;
-import static org.mockito.ArgumentMatchers.anyString;
-import static org.mockito.Mockito.doReturn;
-import static org.mockito.Mockito.mock;
-
 public class UtilsTest {
     @Mock
     Context context;
@@ -74,7 +80,8 @@ public class UtilsTest {
     }
 
     @Test
-    public void testHasCeServicesWithValidPermissions() throws PackageManager.NameNotFoundException {
+    public void testHasCeServicesWithValidPermissions()
+            throws PackageManager.NameNotFoundException {
         // Prepare data for the test
         Intent intent = mock(Intent.class);
         Uri uri = mock(Uri.class);
@@ -100,5 +107,115 @@ public class UtilsTest {
         boolean result = Utils.hasCeServicesWithValidPermissions(context, intent, 123);
         assertTrue(result);
     }
-}
 
+    @Test
+    public void testArrayContainsWithNullArray() {
+        assertFalse(Utils.arrayContains(null, 1));
+    }
+
+    @Test
+    public void testArrayContains() {
+        Integer[] array = {1, 2, 3, 4, 5, 6};
+        int elem = 5;
+        assertTrue(Utils.arrayContains(array, elem));
+    }
+
+    @Test
+    public void testArrayContainsWithoutMatch() {
+        Integer[] array = {1, 2, 3, 4, 5, 6};
+        int elem = -1;
+        assertFalse(Utils.arrayContains(array, elem));
+    }
+
+    @Test
+    public void testNullInput() {
+        assertEquals("", Utils.maskSubstring(null, 2));
+    }
+
+    @Test
+    public void testStartGreaterThanLength() {
+        assertEquals("abc", Utils.maskSubstring("abc", 5));
+    }
+
+    @Test
+    public void testStartEqualToLength() {
+        assertEquals("abc", Utils.maskSubstring("abc", 3));
+    }
+
+    @Test
+    public void testStartIsZero() {
+        assertEquals("***", Utils.maskSubstring("abc", 0));
+    }
+
+    @Test
+    public void testMiddleStart() {
+        assertEquals("ab***", Utils.maskSubstring("abcde", 2));
+    }
+
+    @Test
+    public void testStartAtLastChar() {
+        assertEquals("abcd*", Utils.maskSubstring("abcde", 4));
+    }
+
+    @Test
+    public void testEmptyString() {
+        assertEquals("", Utils.maskSubstring("", 0));
+    }
+
+    @Test
+    public void testStartNegative() {
+        try {
+            Utils.maskSubstring("test", -1);
+            fail("Expected StringIndexOutOfBoundsException");
+        } catch (StringIndexOutOfBoundsException e) {
+            e.printStackTrace();
+        }
+    }
+
+    @Test
+    public void testDumpDebugPendingIntent() {
+        PendingIntent pendingIntent = mock(PendingIntent.class);
+        ProtoOutputStream proto = mock(ProtoOutputStream.class);
+        long fieldId = 123L;
+        when(proto.start(fieldId)).thenReturn(fieldId);
+        when(pendingIntent.toString()).thenReturn("pendingIntent");
+
+        Utils.dumpDebugPendingIntent(pendingIntent, proto, fieldId);
+        verify(proto).start(fieldId);
+    }
+
+    @Test
+    public void testDumpDebugIntentFilter() {
+        IntentFilter intentFilter = mock(IntentFilter.class);
+        ProtoOutputStream proto = mock(ProtoOutputStream.class);
+        long fieldId = 123L;
+        PatternMatcher patternMatcher = mock(PatternMatcher.class);
+        IntentFilter.AuthorityEntry authorityEntry = mock(IntentFilter.AuthorityEntry.class);
+        when(proto.start(anyInt())).thenReturn(fieldId);
+        when(intentFilter.countActions()).thenReturn(1);
+        when(intentFilter.getAction(0)).thenReturn("test.action");
+        when(intentFilter.countCategories()).thenReturn(1);
+        when(intentFilter.getCategory(0)).thenReturn("test.category");
+        when(intentFilter.countDataSchemes()).thenReturn(1);
+        when(intentFilter.getDataScheme(0)).thenReturn("test.data");
+        when(intentFilter.countDataSchemeSpecificParts()).thenReturn(1);
+        when(intentFilter.getDataSchemeSpecificPart(0)).thenReturn(patternMatcher);
+        when(patternMatcher.getPath()).thenReturn("test.path");
+        when(patternMatcher.getType()).thenReturn(1);
+        when(intentFilter.countDataAuthorities()).thenReturn(1);
+        when(intentFilter.getDataAuthority(0)).thenReturn(authorityEntry);
+        when(authorityEntry.getHost()).thenReturn("*.test.host");
+        when(authorityEntry.getPort()).thenReturn(1);
+        when(intentFilter.countDataPaths()).thenReturn(1);
+        when(intentFilter.getDataPath(0)).thenReturn(patternMatcher);
+        when(intentFilter.countDataTypes()).thenReturn(1);
+        when(intentFilter.getDataType(0)).thenReturn("test.datatype");
+        when(intentFilter.getPriority()).thenReturn(1);
+
+        Utils.dumpDebugIntentFilter(intentFilter, proto, fieldId);
+        verify(proto).write(IntentFilterProto.ACTIONS, "test.action");
+        verify(authorityEntry).getHost();
+        verify(proto).write(IntentFilterProto.PRIORITY, 1);
+        verify(intentFilter, times(2)).getPriority();
+    }
+}
diff --git a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/CardEmulationManagerTest.java b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/CardEmulationManagerTest.java
index 2ae584940..212d84b58 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/CardEmulationManagerTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/CardEmulationManagerTest.java
@@ -19,6 +19,8 @@ package com.android.nfc.cardemulation;
 import static android.nfc.cardemulation.CardEmulation.SET_SERVICE_ENABLED_STATUS_FAILURE_FEATURE_UNSUPPORTED;
 import static android.nfc.cardemulation.CardEmulation.SET_SERVICE_ENABLED_STATUS_OK;
 
+import static com.android.nfc.cardemulation.util.TelephonyUtils.SWP_SUPPORTED_PHYSICAL_SIM_SLOT;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertEquals;
@@ -60,10 +62,12 @@ import android.nfc.cardemulation.CardEmulation;
 import android.nfc.cardemulation.NfcFServiceInfo;
 import android.nfc.cardemulation.PollingFrame;
 import android.os.Binder;
+import android.os.Handler;
 import android.os.PowerManager;
 import android.os.RemoteException;
 import android.os.UserHandle;
 import android.os.UserManager;
+import android.os.test.TestLooper;
 import android.provider.Settings;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
@@ -147,6 +151,7 @@ public class CardEmulationManagerTest {
                     "com.android.test.walletroleholder.WalletRoleHolderApduService");
     private static final String PAYMENT_AID_1 = "A000000004101012";
 
+    private TestLooper mLooper;
     @Mock
     private Context mContext;
     @Mock
@@ -229,6 +234,7 @@ public class CardEmulationManagerTest {
         when(mDeviceConfigFacade.getIndicateUserActivityForHce()).thenReturn(true);
         when(android.nfc.Flags.nfcEventListener()).thenReturn(true);
         when(android.nfc.Flags.enableCardEmulationEuicc()).thenReturn(true);
+        mLooper = new TestLooper();
         mCardEmulationManager = createInstanceWithMockParams();
     }
 
@@ -382,12 +388,20 @@ public class CardEmulationManagerTest {
         verifyNoMoreInteractions(mPreferredServices);
     }
 
+    @Test
+    public void testOnOffHostTransaction() {
+        mCardEmulationManager.onOffHostAidTransaction();
+
+        assertConstructorMethodCalls();
+        verify(mHostEmulationManager).onOffHostAidSelectedOrTransaction();
+    }
+
     @Test
     public void testOnOffHostAidSelected() {
-        mCardEmulationManager.onOffHostAidSelected();
+        mCardEmulationManager.onOffHostAidSelected("056870", "eSE1");
 
         assertConstructorMethodCalls();
-        verify(mHostEmulationManager).onOffHostAidSelected();
+        verify(mHostEmulationManager).onOffHostAidSelectedOrTransaction();
     }
 
     @Test
@@ -448,8 +462,10 @@ public class CardEmulationManagerTest {
         when(Flags.exitFrames()).thenReturn(true);
         when(mNfcService.isFirmwareExitFramesSupported()).thenReturn(true);
         when(mNfcService.getNumberOfFirmwareExitFramesSupported()).thenReturn(5);
+        when(mPreferredServices.onServicesUpdated()).thenReturn(true);
 
         mCardEmulationManager.onServicesUpdated(USER_ID, UPDATED_SERVICES, false);
+        mLooper.dispatchAll();
 
         verify(mWalletRoleObserver, times(2)).isWalletRoleFeatureEnabled();
         verify(mRegisteredAidCache).onServicesUpdated(eq(USER_ID), mServiceListCaptor.capture());
@@ -1610,6 +1626,7 @@ public class CardEmulationManagerTest {
 
         verify(mRegisteredAidCache)
                 .onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME), eq(USER_ID));
+        verify(mRoutingOptionManager).overrideDefaultRoute(eq(-1));
         verify(mRoutingOptionManager).overrideDefaultIsoDepRoute(eq(-1));
         verify(mRoutingOptionManager).overrideDefaultOffHostRoute(eq(-1));
         verify(mRoutingOptionManager).getOffHostRouteEse();
@@ -1632,6 +1649,7 @@ public class CardEmulationManagerTest {
 
         verify(mRegisteredAidCache)
                 .onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME), eq(USER_ID));
+        verify(mRoutingOptionManager).overrideDefaultRoute(eq(0));
         verify(mRoutingOptionManager).overrideDefaultIsoDepRoute(eq(0));
         verify(mRoutingOptionManager).overrideDefaultOffHostRoute(eq(0));
         verify(mRoutingOptionManager).getOffHostRouteEse();
@@ -1654,6 +1672,7 @@ public class CardEmulationManagerTest {
 
         verify(mRegisteredAidCache)
                 .onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME), eq(USER_ID));
+        verify(mRoutingOptionManager).overrideDefaultRoute(eq(TEST_DATA_1[0] & 0xFF));
         verify(mRoutingOptionManager).overrideDefaultIsoDepRoute(eq(TEST_DATA_1[0] & 0xFF));
         verify(mRoutingOptionManager).overrideDefaultOffHostRoute(eq(TEST_DATA_1[0] & 0xFF));
         verify(mRoutingOptionManager).getOffHostRouteEse();
@@ -1677,6 +1696,7 @@ public class CardEmulationManagerTest {
 
         verify(mRegisteredAidCache)
                 .onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME), eq(USER_ID));
+        verify(mRoutingOptionManager).overrideDefaultRoute(eq(TEST_DATA_2[0] & 0xFF));
         verify(mRoutingOptionManager).overrideDefaultIsoDepRoute(eq(TEST_DATA_2[0] & 0xFF));
         verify(mRoutingOptionManager).overrideDefaultOffHostRoute(eq(TEST_DATA_2[0] & 0xFF));
         verify(mRoutingOptionManager).getOffHostRouteEse();
@@ -2264,6 +2284,7 @@ public class CardEmulationManagerTest {
                 mContext,
                 mForegroundUtils,
                 mWalletRoleObserver,
+                new Handler(mLooper.getLooper()),
                 mRegisteredAidCache,
                 mRegisteredT3tIdentifiersCache,
                 mHostEmulationManager,
@@ -2657,6 +2678,7 @@ public class CardEmulationManagerTest {
         when(mNfcService.getNumberOfFirmwareExitFramesSupported()).thenReturn(0);
 
         mCardEmulationManager.onWalletRoleHolderChanged("com.android.test", 0);
+        mLooper.dispatchAll();
 
         verify(mNfcService, never()).setFirmwareExitFrameTable(any(), anyInt());
     }
@@ -2689,6 +2711,7 @@ public class CardEmulationManagerTest {
         when(service2.getShouldAutoTransact(any())).thenReturn(true);
 
         mCardEmulationManager.onWalletRoleHolderChanged("com.android.test", 0);
+        mLooper.dispatchAll();
 
         ArgumentCaptor<List<ExitFrame>> frameCaptor = ArgumentCaptor.forClass(List.class);
         verify(mNfcService).setFirmwareExitFrameTable(frameCaptor.capture(), anyInt());
@@ -2717,6 +2740,7 @@ public class CardEmulationManagerTest {
         when(service1.getShouldAutoTransact(any())).thenReturn(true);
 
         mCardEmulationManager.onWalletRoleHolderChanged("com.android.test", 0);
+        mLooper.dispatchAll();
 
         ArgumentCaptor<List<ExitFrame>> frameCaptor = ArgumentCaptor.forClass(List.class);
         verify(mNfcService).setFirmwareExitFrameTable(frameCaptor.capture(), anyInt());
@@ -2750,13 +2774,13 @@ public class CardEmulationManagerTest {
         boolean isActive = true;
         TelephonyUtils telephonyUtils = mock(TelephonyUtils.class);
         SubscriptionInfo subscriptionInfo = mock(SubscriptionInfo.class);
-        Optional<SubscriptionInfo> optionalInfo = Optional.of(subscriptionInfo);
         Field field = CardEmulationManager.class.getDeclaredField("mTelephonyUtils");
         field.setAccessible(true);
         field.set(mCardEmulationManager, telephonyUtils);
         when(subscriptionInfo.isEmbedded()).thenReturn(true);
         when(subscriptionInfo.getPortIndex()).thenReturn(0);
-        when(telephonyUtils.getActiveSubscriptionInfoById(subscriptionId)).thenReturn(optionalInfo);
+        when(subscriptionInfo.getSubscriptionId()).thenReturn(subscriptionId);
+        when(telephonyUtils.getActiveSubscriptions()).thenReturn(List.of(subscriptionInfo));
         when(mRoutingOptionManager.getSecureElementForRoute(anyInt())).thenReturn("");
 
         mCardEmulationManager.onPreferredSubscriptionChanged(subscriptionId, isActive);
@@ -2777,7 +2801,8 @@ public class CardEmulationManagerTest {
         field.set(mCardEmulationManager, telephonyUtils);
         when(subscriptionInfo.isEmbedded()).thenReturn(true);
         when(subscriptionInfo.getPortIndex()).thenReturn(1);
-        when(telephonyUtils.getActiveSubscriptionInfoById(subscriptionId)).thenReturn(optionalInfo);
+        when(subscriptionInfo.getSubscriptionId()).thenReturn(subscriptionId);
+        when(telephonyUtils.getActiveSubscriptions()).thenReturn(List.of(subscriptionInfo));
         when(mRoutingOptionManager.getSecureElementForRoute(anyInt())).thenReturn("");
 
         mCardEmulationManager.onPreferredSubscriptionChanged(subscriptionId, isActive);
@@ -2792,12 +2817,16 @@ public class CardEmulationManagerTest {
         boolean isActive = true;
         TelephonyUtils telephonyUtils = mock(TelephonyUtils.class);
         SubscriptionInfo subscriptionInfo = mock(SubscriptionInfo.class);
-        Optional<SubscriptionInfo> optionalInfo = Optional.of(subscriptionInfo);
         Field field = CardEmulationManager.class.getDeclaredField("mTelephonyUtils");
         field.setAccessible(true);
         field.set(mCardEmulationManager, telephonyUtils);
+        when(telephonyUtils.isUiccSubscription(subscriptionId)).thenReturn(true);
         when(subscriptionInfo.isEmbedded()).thenReturn(false);
-        when(telephonyUtils.getActiveSubscriptionInfoById(subscriptionId)).thenReturn(optionalInfo);
+        when(subscriptionInfo.areUiccApplicationsEnabled()).thenReturn(true);
+        when(subscriptionInfo.getSubscriptionId()).thenReturn(subscriptionId);
+        when(telephonyUtils.getActiveSubscriptions()).thenReturn(List.of(subscriptionInfo));
+        when(telephonyUtils.findPhysicalSlotIndex(subscriptionInfo))
+                .thenReturn(SWP_SUPPORTED_PHYSICAL_SIM_SLOT);
         when(mRoutingOptionManager.getSecureElementForRoute(anyInt())).thenReturn("");
 
         mCardEmulationManager.onPreferredSubscriptionChanged(subscriptionId, isActive);
@@ -2811,11 +2840,10 @@ public class CardEmulationManagerTest {
         int subscriptionId = 1;
         boolean isActive = true;
         TelephonyUtils telephonyUtils = mock(TelephonyUtils.class);
-        Optional<SubscriptionInfo> optionalInfo = Optional.empty();
         Field field = CardEmulationManager.class.getDeclaredField("mTelephonyUtils");
         field.setAccessible(true);
         field.set(mCardEmulationManager, telephonyUtils);
-        when(telephonyUtils.getActiveSubscriptionInfoById(subscriptionId)).thenReturn(optionalInfo);
+        when(telephonyUtils.getActiveSubscriptions()).thenReturn(List.of());
 
         mCardEmulationManager.onPreferredSubscriptionChanged(subscriptionId, isActive);
         verify(mRoutingOptionManager).onPreferredSimChanged(TelephonyUtils.SIM_TYPE_UNKNOWN);
@@ -2924,13 +2952,13 @@ public class CardEmulationManagerTest {
         when(mPreferredSubscriptionService.getPreferredSubscriptionId()).thenReturn(subscriptionId);
         TelephonyUtils telephonyUtils = mock(TelephonyUtils.class);
         SubscriptionInfo subscriptionInfo = mock(SubscriptionInfo.class);
-        Optional<SubscriptionInfo> optionalInfo = Optional.of(subscriptionInfo);
         Field field = CardEmulationManager.class.getDeclaredField("mTelephonyUtils");
         field.setAccessible(true);
         field.set(mCardEmulationManager, telephonyUtils);
         when(subscriptionInfo.isEmbedded()).thenReturn(true);
         when(subscriptionInfo.getPortIndex()).thenReturn(0);
-        when(telephonyUtils.getActiveSubscriptionInfoById(subscriptionId)).thenReturn(optionalInfo);
+        when(subscriptionInfo.getSubscriptionId()).thenReturn(subscriptionId);
+        when(telephonyUtils.getActiveSubscriptions()).thenReturn(List.of(subscriptionInfo));
         when(telephonyUtils.updateSwpStatusForEuicc(TelephonyUtils.SIM_TYPE_EUICC_1)).thenReturn(
                 "6F02839000");
 
@@ -2952,13 +2980,13 @@ public class CardEmulationManagerTest {
         when(mPreferredSubscriptionService.getPreferredSubscriptionId()).thenReturn(subscriptionId);
         TelephonyUtils telephonyUtils = mock(TelephonyUtils.class);
         SubscriptionInfo subscriptionInfo = mock(SubscriptionInfo.class);
-        Optional<SubscriptionInfo> optionalInfo = Optional.of(subscriptionInfo);
         Field field = CardEmulationManager.class.getDeclaredField("mTelephonyUtils");
         field.setAccessible(true);
         field.set(mCardEmulationManager, telephonyUtils);
         when(subscriptionInfo.isEmbedded()).thenReturn(true);
         when(subscriptionInfo.getPortIndex()).thenReturn(0);
-        when(telephonyUtils.getActiveSubscriptionInfoById(subscriptionId)).thenReturn(optionalInfo);
+        when(subscriptionInfo.getSubscriptionId()).thenReturn(subscriptionId);
+        when(telephonyUtils.getActiveSubscriptions()).thenReturn(List.of(subscriptionInfo));
         when(telephonyUtils.updateSwpStatusForEuicc(TelephonyUtils.SIM_TYPE_EUICC_1)).thenReturn(
                 "6F0283FFFF");
 
@@ -2981,13 +3009,13 @@ public class CardEmulationManagerTest {
         when(mPreferredSubscriptionService.getPreferredSubscriptionId()).thenReturn(subscriptionId);
         TelephonyUtils telephonyUtils = mock(TelephonyUtils.class);
         SubscriptionInfo subscriptionInfo = mock(SubscriptionInfo.class);
-        Optional<SubscriptionInfo> optionalInfo = Optional.of(subscriptionInfo);
         Field field = CardEmulationManager.class.getDeclaredField("mTelephonyUtils");
         field.setAccessible(true);
         field.set(mCardEmulationManager, telephonyUtils);
         when(subscriptionInfo.isEmbedded()).thenReturn(true);
         when(subscriptionInfo.getPortIndex()).thenReturn(0);
-        when(telephonyUtils.getActiveSubscriptionInfoById(subscriptionId)).thenReturn(optionalInfo);
+        when(subscriptionInfo.getSubscriptionId()).thenReturn(subscriptionId);
+        when(telephonyUtils.getActiveSubscriptions()).thenReturn(List.of(subscriptionInfo));
         when(telephonyUtils.updateSwpStatusForEuicc(TelephonyUtils.SIM_TYPE_EUICC_1)).thenReturn(
                 "6FF");
 
diff --git a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/HostEmulationManagerTest.java b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/HostEmulationManagerTest.java
index c07858175..58ee56b7c 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/HostEmulationManagerTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/HostEmulationManagerTest.java
@@ -53,6 +53,7 @@ import android.os.PowerManager;
 import android.os.Process;
 import android.os.RemoteException;
 import android.os.UserHandle;
+import android.os.WorkSource;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 
@@ -88,6 +89,7 @@ import java.util.regex.Pattern;
 public class HostEmulationManagerTest {
 
     private static final String WALLET_HOLDER_PACKAGE_NAME = "com.android.test.walletroleholder";
+    private static final int WALLET_HOLDER_UID = 10234;
     private static final String NFC_PACKAGE = "com.android.nfc";
     private static final ComponentName WALLET_PAYMENT_SERVICE =
             new ComponentName(
@@ -108,6 +110,7 @@ public class HostEmulationManagerTest {
     @Mock private Context mContext;
     @Mock private RegisteredAidCache mRegisteredAidCache;
     @Mock private PowerManager mPowerManager;
+    @Mock private PowerManager.WakeLock mWakeLock;
     @Mock private KeyguardManager mKeyguardManager;
     @Mock private PackageManager mPackageManager;
     @Mock private NfcAdapter mNfcAdapter;
@@ -152,6 +155,7 @@ public class HostEmulationManagerTest {
         when(mNfcInjector.getDeviceConfigFacade()).thenReturn(mDeviceConfigFacade);
         when(com.android.nfc.flags.Flags.statsdCeEventsFlag()).thenReturn(true);
         when(mContext.getSystemService(eq(PowerManager.class))).thenReturn(mPowerManager);
+        when(mPowerManager.newWakeLock(anyInt(), anyString())).thenReturn(mWakeLock);
         when(mContext.getSystemService(eq(KeyguardManager.class))).thenReturn(mKeyguardManager);
         when(mRegisteredAidCache.getPreferredPaymentService())
                 .thenReturn(new ComponentNameAndUser(0, null));
@@ -304,6 +308,9 @@ public class HostEmulationManagerTest {
         mHostEmulationManager.mPaymentServiceName = WALLET_PAYMENT_SERVICE;
         when(mPackageManager.getApplicationInfo(eq(WALLET_HOLDER_PACKAGE_NAME), eq(0)))
                 .thenReturn(applicationInfo);
+        when(mPackageManager.getPackageUidAsUser(eq(WALLET_HOLDER_PACKAGE_NAME),
+                eq(PackageManager.PackageInfoFlags.of(0)), eq(USER_ID))).thenReturn(
+                        WALLET_HOLDER_UID);
         String data = "filter";
         PollingFrame frame1 =
                 new PollingFrame(
@@ -765,8 +772,21 @@ public class HostEmulationManagerTest {
     }
 
     @Test
-    public void testOnHostEmulationData_stateW4Select_noDefaultService_noBoundActiveService() {
+    public void testOnHostEmulationData_stateW4Select_noDefaultService_noBoundActiveService()
+            throws Exception {
+        when(com.android.nfc.module.flags.Flags.ceWakeLock()).thenReturn(true);
+        when(mDeviceConfigFacade.getCeWakeLockTimeoutMillis()).thenReturn(1000);
+        when(mContext.getPackageManager()).thenReturn(mPackageManager);
+        when(mPackageManager.getPackageUidAsUser(
+                eq(WALLET_HOLDER_PACKAGE_NAME), any(), eq(USER_ID)))
+                .thenReturn(WALLET_HOLDER_UID);
         when(mContext.bindServiceAsUser(any(), any(), anyInt(), any())).thenReturn(true);
+
+        mHostEmulationManager.onFieldChangeDetected(true);
+        verify(mWakeLock).acquire(1000);
+        verify(mWakeLock, times(1)).setWorkSource(null);
+        when(mWakeLock.isHeld()).thenReturn(true);
+
         byte[] mockAidData = createSelectAidData(MOCK_AID);
         mHostEmulationManager.mState = HostEmulationManager.STATE_W4_SELECT;
         ApduServiceInfo apduServiceInfo = mock(ApduServiceInfo.class);
@@ -798,6 +818,10 @@ public class HostEmulationManagerTest {
         verify(mRegisteredAidCache).resolveAid(eq(MOCK_AID));
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
+        verify(mContext).getPackageManager();
+        verify(mPackageManager).getPackageUidAsUser(anyString(), any(), anyInt());
+        verify(mWakeLock).setWorkSource(
+                eq(new WorkSource(WALLET_HOLDER_UID, WALLET_HOLDER_PACKAGE_NAME)));
         verify(mContext)
                 .bindServiceAsUser(
                         mIntentArgumentCaptor.capture(),
@@ -815,6 +839,10 @@ public class HostEmulationManagerTest {
         assertTrue(mHostEmulationManager.mServiceBound);
         assertEquals(USER_ID, mHostEmulationManager.mServiceUserId);
         verifyNoMoreInteractions(mContext);
+
+        mHostEmulationManager.onFieldChangeDetected(false);
+        verify(mWakeLock).release();
+        verify(mWakeLock, times(2)).setWorkSource(null);
     }
 
     @Test
@@ -1043,7 +1071,7 @@ public class HostEmulationManagerTest {
         mHostEmulationManager.mServiceBound = false;
         mHostEmulationManager.mState = HostEmulationManager.STATE_XFER;
 
-        mHostEmulationManager.onOffHostAidSelected();
+        mHostEmulationManager.onOffHostAidSelectedOrTransaction();
 
         assertNull(mHostEmulationManager.mActiveService);
         assertNull(mHostEmulationManager.mActiveServiceName);
@@ -1065,7 +1093,7 @@ public class HostEmulationManagerTest {
         mHostEmulationManager.mServiceBound = true;
         mHostEmulationManager.mState = HostEmulationManager.STATE_XFER;
 
-        mHostEmulationManager.onOffHostAidSelected();
+        mHostEmulationManager.onOffHostAidSelectedOrTransaction();
 
         assertNull(mHostEmulationManager.mActiveService);
         assertNull(mHostEmulationManager.mActiveServiceName);
@@ -1092,7 +1120,7 @@ public class HostEmulationManagerTest {
         mHostEmulationManager.mServiceBound = true;
         mHostEmulationManager.mState = HostEmulationManager.STATE_IDLE;
 
-        mHostEmulationManager.onOffHostAidSelected();
+        mHostEmulationManager.onOffHostAidSelectedOrTransaction();
 
         assertNull(mHostEmulationManager.mActiveService);
         assertNull(mHostEmulationManager.mActiveServiceName);
@@ -1411,6 +1439,7 @@ public class HostEmulationManagerTest {
     @Test
     public void testSlowTapTrace() {
         when(com.android.nfc.module.flags.Flags.nfcHceLatencyEvents()).thenReturn(true);
+
         mHostEmulationManager.onFieldChangeDetected(true);
         mHostEmulationManager.onHostEmulationActivated();
 
@@ -1426,6 +1455,21 @@ public class HostEmulationManagerTest {
                 () -> PerfettoTrigger.trigger(HostEmulationManager.TRIGGER_NAME_SLOW_TAP));
     }
 
+    @Test
+    public void testWakeLockAcquireOnFieldChangeDetected() {
+        when(com.android.nfc.module.flags.Flags.ceWakeLock()).thenReturn(true);
+        when(mDeviceConfigFacade.getCeWakeLockTimeoutMillis()).thenReturn(1000);
+
+        mHostEmulationManager.onFieldChangeDetected(true);
+        verify(mWakeLock).acquire(1000);
+        verify(mWakeLock, times(1)).setWorkSource(null);
+        when(mWakeLock.isHeld()).thenReturn(true);
+
+        mHostEmulationManager.onFieldChangeDetected(false);
+        verify(mWakeLock).release();
+        verify(mWakeLock, times(2)).setWorkSource(null);
+    }
+
     private void verifyTapAgainLaunched(ApduServiceInfo service, String category) {
         verify(mContext).getPackageName();
         verify(mContext).startActivityAsUser(mIntentArgumentCaptor.capture(), eq(USER_HANDLE));
diff --git a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/NfcCardEmulationOccurredTest.java b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/NfcCardEmulationOccurredTest.java
index d6e7013dc..e2101e2b2 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/NfcCardEmulationOccurredTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/NfcCardEmulationOccurredTest.java
@@ -279,7 +279,7 @@ public final class NfcCardEmulationOccurredTest {
 
     @Test
     public void testOnOffHostAidSelected() {
-        mHostEmulation.onOffHostAidSelected();
+        mHostEmulation.onOffHostAidSelectedOrTransaction();
         int state = mHostEmulation.getState();
         assertEquals(STATE_W4_SELECT, state);
     }
diff --git a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/PreferredSubscriptionServiceTest.java b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/PreferredSubscriptionServiceTest.java
index ff5bffcd0..042886884 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/PreferredSubscriptionServiceTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/PreferredSubscriptionServiceTest.java
@@ -127,13 +127,13 @@ public class PreferredSubscriptionServiceTest {
                 editor);
         when(editor.commit()).thenReturn(true);
         when(mTelephonyUtils.getActiveSubscriptions()).thenReturn(infos);
-        when(mTelephonyUtils.isEuiccSubscription(
+        when(mTelephonyUtils.isUiccSubscription(
                 TelephonyUtils.SUBSCRIPTION_ID_UICC)).thenReturn(
-                false);
+                true);
 
         mPreferredSubscriptionService.setPreferredSubscriptionId(
                 TelephonyUtils.SUBSCRIPTION_ID_UICC, true);
-        verify(mTelephonyUtils).isEuiccSubscription(TelephonyUtils.SUBSCRIPTION_ID_UICC);
+        verify(mTelephonyUtils).isUiccSubscription(TelephonyUtils.SUBSCRIPTION_ID_UICC);
         verify(editor).commit();
     }
 
@@ -150,11 +150,11 @@ public class PreferredSubscriptionServiceTest {
         when(mSubscriptionInfo.areUiccApplicationsEnabled()).thenReturn(true);
         infos.add(mSubscriptionInfo);
         when(mTelephonyUtils.getActiveSubscriptions()).thenReturn(infos);
-        when(mTelephonyUtils.isEuiccSubscription(TelephonyUtils.SUBSCRIPTION_ID_UICC)).thenReturn(
-                false);
+        when(mTelephonyUtils.isUiccSubscription(TelephonyUtils.SUBSCRIPTION_ID_UICC)).thenReturn(
+                true);
 
         mPreferredSubscriptionService.onActiveSubscriptionsUpdated(infos);
-        verify(mTelephonyUtils).isEuiccSubscription(TelephonyUtils.SUBSCRIPTION_ID_UICC);
+        verify(mTelephonyUtils).isUiccSubscription(TelephonyUtils.SUBSCRIPTION_ID_UICC);
         verify(mCallback).onPreferredSubscriptionChanged(TelephonyUtils.SUBSCRIPTION_ID_UICC,
                 false);
     }
@@ -171,10 +171,10 @@ public class PreferredSubscriptionServiceTest {
         when(mSubscriptionInfo.areUiccApplicationsEnabled()).thenReturn(true);
         infos.add(mSubscriptionInfo);
         when(mTelephonyUtils.getActiveSubscriptions()).thenReturn(infos);
-        when(mTelephonyUtils.isEuiccSubscription(anyInt())).thenReturn(false);
+        when(mTelephonyUtils.isUiccSubscription(anyInt())).thenReturn(false);
 
         mPreferredSubscriptionService.initialize();
-        verify(mTelephonyUtils).isEuiccSubscription(anyInt());
+        verify(mTelephonyUtils).isUiccSubscription(anyInt());
         verify(mTelephonyUtils).registerSubscriptionChangedCallback(
                 any(TelephonyUtils.Callback.class));
 
diff --git a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/RegisteredAidCacheTest.java b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/RegisteredAidCacheTest.java
index a4b3f3db1..f8869b341 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/RegisteredAidCacheTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/RegisteredAidCacheTest.java
@@ -22,8 +22,12 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.verifyNoMoreInteractions;
 import static org.mockito.Mockito.when;
@@ -34,10 +38,13 @@ import android.content.Context;
 import android.content.pm.PackageManager;
 import android.nfc.ComponentNameAndUser;
 import android.nfc.Flags;
+import android.nfc.INfcOemExtensionCallback;
 import android.nfc.cardemulation.ApduServiceInfo;
 import android.nfc.cardemulation.CardEmulation;
+import android.os.RemoteException;
 import android.os.UserHandle;
 import android.os.UserManager;
+import android.util.proto.ProtoOutputStream;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
@@ -56,10 +63,18 @@ import org.mockito.Mockito;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 
+import java.io.FileDescriptor;
+import java.io.PrintWriter;
+import java.lang.reflect.Field;
+import java.util.AbstractMap;
 import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.Collections;
 import java.util.HashMap;
 import java.util.HashSet;
 import java.util.List;
+import java.util.Map;
+import java.util.TreeMap;
 
 @RunWith(AndroidJUnit4.class)
 public class RegisteredAidCacheTest {
@@ -101,20 +116,70 @@ public class RegisteredAidCacheTest {
 
     private static final int USER_ID = 0;
     private static final UserHandle USER_HANDLE = UserHandle.of(USER_ID);
-
-    @Mock private Context mContext;
-    @Mock private WalletRoleObserver mWalletRoleObserver;
-    @Mock private AidRoutingManager mAidRoutingManager;
-    @Mock private UserManager mUserManager;
-    @Mock private PackageManager mPackageManager;
-    @Mock private NfcService mNfcService;
-
+    RegisteredAidCache mRegisteredAidCache;
+    @Mock
+    private Context mContext;
+    @Mock
+    private WalletRoleObserver mWalletRoleObserver;
+    @Mock
+    private AidRoutingManager mAidRoutingManager;
+    @Mock
+    private UserManager mUserManager;
+    @Mock
+    private PackageManager mPackageManager;
+    @Mock
+    private NfcService mNfcService;
     @Captor
     private ArgumentCaptor<HashMap<String, AidRoutingManager.AidEntry>> mRoutingEntryMapCaptor;
-
     private MockitoSession mStaticMockSession;
 
-    RegisteredAidCache mRegisteredAidCache;
+    private static ApduServiceInfo createServiceInfoForAidRouting(
+            ComponentName componentName,
+            boolean onHost,
+            List<String> aids,
+            List<String> categories,
+            boolean requiresUnlock,
+            boolean requiresScreenOn,
+            int uid,
+            boolean isCategoryOtherServiceEnabled) {
+        return createServiceInfoForAidRouting(componentName,
+                onHost,
+                aids,
+                categories,
+                requiresUnlock,
+                requiresScreenOn,
+                uid,
+                isCategoryOtherServiceEnabled,
+                false);
+    }
+
+    private static ApduServiceInfo createServiceInfoForAidRouting(
+            ComponentName componentName,
+            boolean onHost,
+            List<String> aids,
+            List<String> categories,
+            boolean requiresUnlock,
+            boolean requiresScreenOn,
+            int uid,
+            boolean isCategoryOtherServiceEnabled,
+            boolean wantsRoleHolderPriority) {
+        ApduServiceInfo apduServiceInfo = Mockito.mock(ApduServiceInfo.class);
+        when(apduServiceInfo.isOnHost()).thenReturn(onHost);
+        when(apduServiceInfo.getAids()).thenReturn(aids);
+        when(apduServiceInfo.getUid()).thenReturn(uid);
+        when(apduServiceInfo.requiresUnlock()).thenReturn(requiresUnlock);
+        when(apduServiceInfo.requiresScreenOn()).thenReturn(requiresScreenOn);
+        when(apduServiceInfo.isCategoryOtherServiceEnabled())
+                .thenReturn(isCategoryOtherServiceEnabled);
+        when(apduServiceInfo.getComponent()).thenReturn(componentName);
+        when(apduServiceInfo.wantsRoleHolderPriority()).thenReturn(wantsRoleHolderPriority);
+        for (int i = 0; i < aids.size(); i++) {
+            String aid = aids.get(i);
+            String category = categories.get(i);
+            when(apduServiceInfo.getCategoryForAid(eq(aid))).thenReturn(category);
+        }
+        return apduServiceInfo;
+    }
 
     @Before
     public void setUp() {
@@ -132,7 +197,7 @@ public class RegisteredAidCacheTest {
         when(mUserManager.getProfileParent(eq(USER_HANDLE))).thenReturn(USER_HANDLE);
         when(mContext.createContextAsUser(any(), anyInt())).thenReturn(mContext);
         when(mContext.getSystemService(eq(UserManager.class))).thenReturn(mUserManager);
-        when (mContext.getPackageManager()).thenReturn(mPackageManager);
+        when(mContext.getPackageManager()).thenReturn(mPackageManager);
     }
 
     @After
@@ -770,54 +835,6 @@ public class RegisteredAidCacheTest {
         when(mAidRoutingManager.supportsAidSubsetRouting()).thenReturn(support);
     }
 
-    private static ApduServiceInfo createServiceInfoForAidRouting(
-            ComponentName componentName,
-            boolean onHost,
-            List<String> aids,
-            List<String> categories,
-            boolean requiresUnlock,
-            boolean requiresScreenOn,
-            int uid,
-            boolean isCategoryOtherServiceEnabled) {
-        return createServiceInfoForAidRouting(componentName,
-                onHost,
-                aids,
-                categories,
-                requiresUnlock,
-                requiresScreenOn,
-                uid,
-                isCategoryOtherServiceEnabled,
-                false);
-    }
-
-    private static ApduServiceInfo createServiceInfoForAidRouting(
-            ComponentName componentName,
-            boolean onHost,
-            List<String> aids,
-            List<String> categories,
-            boolean requiresUnlock,
-            boolean requiresScreenOn,
-            int uid,
-            boolean isCategoryOtherServiceEnabled,
-            boolean wantsRoleHolderPriority) {
-        ApduServiceInfo apduServiceInfo = Mockito.mock(ApduServiceInfo.class);
-        when(apduServiceInfo.isOnHost()).thenReturn(onHost);
-        when(apduServiceInfo.getAids()).thenReturn(aids);
-        when(apduServiceInfo.getUid()).thenReturn(uid);
-        when(apduServiceInfo.requiresUnlock()).thenReturn(requiresUnlock);
-        when(apduServiceInfo.requiresScreenOn()).thenReturn(requiresScreenOn);
-        when(apduServiceInfo.isCategoryOtherServiceEnabled())
-                .thenReturn(isCategoryOtherServiceEnabled);
-        when(apduServiceInfo.getComponent()).thenReturn(componentName);
-        when(apduServiceInfo.wantsRoleHolderPriority()).thenReturn(wantsRoleHolderPriority);
-        for (int i = 0; i < aids.size(); i++) {
-            String aid = aids.get(i);
-            String category = categories.get(i);
-            when(apduServiceInfo.getCategoryForAid(eq(aid))).thenReturn(category);
-        }
-        return apduServiceInfo;
-    }
-
     @Test
     public void testGetPreferredService() {
 
@@ -831,4 +848,604 @@ public class RegisteredAidCacheTest {
         Assert.assertNotNull(servicePair.getComponentName());
         assertEquals(new ComponentNameAndUser(USER_ID, FOREGROUND_SERVICE), servicePair);
     }
+
+    @Test
+    public void testIsDefaultServiceForAidWithDefaultService()
+            throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        List<ApduServiceInfo> services = new ArrayList<>();
+        ApduServiceInfo apduServiceInfo = mock(ApduServiceInfo.class);
+        services.add(apduServiceInfo);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put(PAYMENT_AID_1, aidResolveInfo);
+        when(mAidRoutingManager.supportsAidPrefixRouting()).thenReturn(false);
+        when(mAidRoutingManager.supportsAidSubsetRouting()).thenReturn(false);
+        Field field = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        field.setAccessible(true);
+        field.set(mRegisteredAidCache, mAidCache);
+        aidResolveInfo.services = services;
+        aidResolveInfo.defaultService = apduServiceInfo;
+        when(apduServiceInfo.getComponent()).thenReturn(PAYMENT_SERVICE);
+
+        assertTrue(
+                mRegisteredAidCache.isDefaultServiceForAid(1, PAYMENT_SERVICE, PAYMENT_AID_1));
+        verify(apduServiceInfo).getComponent();
+    }
+
+    @Test
+    public void testIsDefaultServiceForAidWithSingleService()
+            throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        List<ApduServiceInfo> services = new ArrayList<>();
+        ApduServiceInfo apduServiceInfo = mock(ApduServiceInfo.class);
+        services.add(apduServiceInfo);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put(PAYMENT_AID_1, aidResolveInfo);
+        when(mAidRoutingManager.supportsAidPrefixRouting()).thenReturn(false);
+        when(mAidRoutingManager.supportsAidSubsetRouting()).thenReturn(false);
+        Field field = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        field.setAccessible(true);
+        field.set(mRegisteredAidCache, mAidCache);
+        aidResolveInfo.services = services;
+        aidResolveInfo.defaultService = null;
+        when(apduServiceInfo.getComponent()).thenReturn(PAYMENT_SERVICE);
+
+        assertTrue(
+                mRegisteredAidCache.isDefaultServiceForAid(1, PAYMENT_SERVICE, PAYMENT_AID_1));
+        verify(apduServiceInfo).getComponent();
+    }
+
+    @Test
+    public void testIsDefaultServiceForAidWithMultipleService()
+            throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        List<ApduServiceInfo> services = new ArrayList<>();
+        ApduServiceInfo apduServiceInfo = mock(ApduServiceInfo.class);
+        ApduServiceInfo secondApduServiceInfo = mock(ApduServiceInfo.class);
+        services.add(apduServiceInfo);
+        services.add(secondApduServiceInfo);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put(PAYMENT_AID_1, aidResolveInfo);
+        when(mAidRoutingManager.supportsAidPrefixRouting()).thenReturn(false);
+        when(mAidRoutingManager.supportsAidSubsetRouting()).thenReturn(false);
+        Field field = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        field.setAccessible(true);
+        field.set(mRegisteredAidCache, mAidCache);
+        aidResolveInfo.services = services;
+        aidResolveInfo.defaultService = null;
+        when(apduServiceInfo.getComponent()).thenReturn(PAYMENT_SERVICE);
+
+        assertFalse(
+                mRegisteredAidCache.isDefaultServiceForAid(1, PAYMENT_SERVICE, PAYMENT_AID_1));
+        verify(apduServiceInfo, never()).getComponent();
+    }
+
+    @Test
+    public void testIsDefaultServiceForAid() throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        when(mAidRoutingManager.supportsAidPrefixRouting()).thenReturn(false);
+        when(mAidRoutingManager.supportsAidSubsetRouting()).thenReturn(false);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put("aidResolveInfo", aidResolveInfo);
+        Field field = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        field.setAccessible(true);
+        field.set(mRegisteredAidCache, mAidCache);
+        aidResolveInfo.services = null;
+
+        assertFalse(mRegisteredAidCache.isDefaultServiceForAid(1, PAYMENT_SERVICE, "AID"));
+    }
+
+    @Test
+    public void testDumpEntry() {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        ApduServiceInfo defaultServiceInfo = mock(ApduServiceInfo.class);
+        Map.Entry<String, RegisteredAidCache.AidResolveInfo> map = new AbstractMap.SimpleEntry<>(
+                PAYMENT_AID_1, aidResolveInfo);
+        List<ApduServiceInfo> services = new ArrayList<>();
+        services.add(defaultServiceInfo);
+        aidResolveInfo.category = "PAYMENT";
+        aidResolveInfo.defaultService = defaultServiceInfo;
+        aidResolveInfo.services = services;
+        when(defaultServiceInfo.getComponent()).thenReturn(PAYMENT_SERVICE);
+        when(defaultServiceInfo.getDescription()).thenReturn("PAYMENT");
+        String sb = "    \"" + PAYMENT_AID_1 + "\" (category: " + "PAYMENT" + ")\n"
+                + "        "
+                + "*DEFAULT* "
+                + defaultServiceInfo + " (Description: " + "PAYMENT" + ")\n";
+        assertEquals(sb, mRegisteredAidCache.dumpEntry(map));
+    }
+
+    @Test
+    public void testDump() throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        FileDescriptor fd = mock(FileDescriptor.class);
+        PrintWriter pw = mock(PrintWriter.class);
+        String[] args = new String[]{};
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put("PAYMENT_AID_1", aidResolveInfo);
+        ApduServiceInfo defaultServiceInfo = mock(ApduServiceInfo.class);
+        Map.Entry<String, RegisteredAidCache.AidResolveInfo> map = new AbstractMap.SimpleEntry<>(
+                PAYMENT_AID_1, aidResolveInfo);
+        List<ApduServiceInfo> services = new ArrayList<>();
+        services.add(defaultServiceInfo);
+        aidResolveInfo.category = "PAYMENT";
+        aidResolveInfo.defaultService = defaultServiceInfo;
+        aidResolveInfo.services = services;
+        when(defaultServiceInfo.getComponent()).thenReturn(PAYMENT_SERVICE);
+        when(defaultServiceInfo.getDescription()).thenReturn("PAYMENT");
+        when(Flags.nfcAssociatedRoleServices()).thenReturn(true);
+        Field field = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        field.setAccessible(true);
+        field.set(mRegisteredAidCache, mAidCache);
+
+        mRegisteredAidCache.dump(fd, pw, args);
+        verify(mAidRoutingManager).dump(fd, pw, args);
+    }
+
+    @Test
+    public void testDumpDebug() throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        ProtoOutputStream proto = mock(ProtoOutputStream.class);
+        ApduServiceInfo defaultServiceInfo = mock(ApduServiceInfo.class);
+        ComponentName mPreferredPaymentService = mock(ComponentName.class);
+        ComponentName mPreferredForegroundService = mock(ComponentName.class);
+        aidResolveInfo.category = "PAYMENT";
+        aidResolveInfo.defaultService = defaultServiceInfo;
+        List<ApduServiceInfo> services = new ArrayList<>();
+        services.add(defaultServiceInfo);
+        aidResolveInfo.services = services;
+        when(defaultServiceInfo.getComponent()).thenReturn(PAYMENT_SERVICE);
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put(PAYMENT_AID_1, aidResolveInfo);
+        Field fieldAidCache = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        fieldAidCache.setAccessible(true);
+        fieldAidCache.set(mRegisteredAidCache, mAidCache);
+        Field fieldPayScheme = RegisteredAidCache.class.getDeclaredField(
+                "mPreferredPaymentService");
+        fieldPayScheme.setAccessible(true);
+        fieldPayScheme.set(mRegisteredAidCache, mPreferredPaymentService);
+        Field fieldService = RegisteredAidCache.class.getDeclaredField(
+                "mPreferredForegroundService");
+        fieldService.setAccessible(true);
+        fieldService.set(mRegisteredAidCache, mPreferredForegroundService);
+
+        mRegisteredAidCache.dumpDebug(proto);
+        verify(mAidRoutingManager).dumpDebug(proto);
+    }
+
+    @Test
+    public void testFindPrefixConflictForSubsetAidNoPrefixMatch() {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String subsetAid = "A000000001#";
+        List<ApduServiceInfo> prefixServices = Collections.emptyList();
+
+        RegisteredAidCache.ResolvedPrefixConflictAid result =
+                mRegisteredAidCache.findPrefixConflictForSubsetAid(
+                        subsetAid, prefixServices, false);
+        assertNull(result.prefixAid);
+        assertFalse(result.matchingSubset);
+    }
+
+    @Test
+    public void testFindPrefixConflictForSubsetAidWithMatchingPrefix() {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String subsetAid = "A000000001#";
+        ApduServiceInfo mockService = mock(ApduServiceInfo.class);
+        when(mockService.getPrefixAids()).thenReturn(List.of("A0000000#"));
+        List<ApduServiceInfo> prefixServices = Collections.singletonList(mockService);
+
+        RegisteredAidCache.ResolvedPrefixConflictAid result =
+                mRegisteredAidCache.findPrefixConflictForSubsetAid(
+                        subsetAid, prefixServices, false);
+        assertNotNull(result.prefixAid);
+        assertEquals("A0000000#", result.prefixAid);
+        assertFalse(result.matchingSubset);
+    }
+
+    @Test
+    public void testFindPrefixConflictForSubsetAidMultiplePrefixes() {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String subsetAid = "A000000001#";
+        ApduServiceInfo mockService = mock(ApduServiceInfo.class);
+        when(mockService.getPrefixAids()).thenReturn(Arrays.asList("A0000000#", "A000#"));
+        List<ApduServiceInfo> prefixServices = Collections.singletonList(mockService);
+
+        RegisteredAidCache.ResolvedPrefixConflictAid result =
+                mRegisteredAidCache.findPrefixConflictForSubsetAid(
+                        subsetAid, prefixServices, false);
+        assertNotNull(result.prefixAid);
+        assertEquals("A000#", result.prefixAid); // The smallest prefix should be chosen
+    }
+
+    @Test
+    public void testFindPrefixConflictForSubsetAidMatchingSubset() {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String subsetAid = "A000000001#";
+        ApduServiceInfo mockService = mock(ApduServiceInfo.class);
+        when(mockService.getPrefixAids()).thenReturn(List.of("A000000001#"));
+        List<ApduServiceInfo> prefixServices = Collections.singletonList(mockService);
+
+        RegisteredAidCache.ResolvedPrefixConflictAid result =
+                mRegisteredAidCache.findPrefixConflictForSubsetAid(
+                        subsetAid, prefixServices, false);
+        assertNotNull(result.prefixAid);
+        assertEquals("A000000001#", result.prefixAid);
+        assertTrue(result.matchingSubset);
+    }
+
+    @Test
+    public void testFindPrefixConflictForSubsetAidPriorityRootAid() {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String subsetAid = "A000000001#";
+        ApduServiceInfo mockService = mock(ApduServiceInfo.class);
+        when(mockService.getPrefixAids()).thenReturn(Arrays.asList("A0000000#", "A000#"));
+        when(mockService.getCategoryForAid(anyString())).thenReturn(CardEmulation.CATEGORY_PAYMENT);
+        when(mockService.getUid()).thenReturn(1000);
+        List<ApduServiceInfo> prefixServices = Collections.singletonList(mockService);
+
+        RegisteredAidCache.ResolvedPrefixConflictAid result =
+                mRegisteredAidCache.findPrefixConflictForSubsetAid(
+                        subsetAid, prefixServices, true);
+        assertNotNull(result.prefixAid);
+        assertEquals("A000#", result.prefixAid); // Smallest prefix should be chosen
+    }
+
+    @Test
+    public void testOnRoutingOverridedOrRecovered()
+            throws NoSuchFieldException, IllegalAccessException, RemoteException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        INfcOemExtensionCallback mNfcOemExtensionCallback = mock(INfcOemExtensionCallback.class);
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField("mNfcEnabled");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, true);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        aidResolveInfo.services = new ArrayList<>();
+        List<String> unCheckedOffHostSecureElement = new ArrayList<>();
+        unCheckedOffHostSecureElement.add("SampleElement");
+        aidResolveInfo.unCheckedOffHostSecureElement = unCheckedOffHostSecureElement;
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put(PAYMENT_AID_1, aidResolveInfo);
+        Field fieldAidCache = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        fieldAidCache.setAccessible(true);
+        fieldAidCache.set(mRegisteredAidCache, mAidCache);
+        when(mAidRoutingManager.configureRouting(any(HashMap.class), anyBoolean(),
+                anyBoolean())).thenReturn(AidRoutingManager.CONFIGURE_ROUTING_FAILURE_TABLE_FULL);
+        mRegisteredAidCache.setOemExtension(mNfcOemExtensionCallback);
+
+        assertEquals(AidRoutingManager.CONFIGURE_ROUTING_FAILURE_TABLE_FULL,
+                mRegisteredAidCache.onRoutingOverridedOrRecovered());
+        verify(mNfcOemExtensionCallback).onRoutingTableFull();
+    }
+
+    @Test
+    public void testUpdateRoutingLockedWithNfcDisabled() {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+
+        assertEquals(AidRoutingManager.CONFIGURE_ROUTING_FAILURE_UNKNOWN,
+                mRegisteredAidCache.updateRoutingLocked(true, true));
+    }
+
+    @Test
+    public void testUpdateRoutingLockedWithDefaultService()
+            throws NoSuchFieldException, IllegalAccessException, RemoteException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        INfcOemExtensionCallback mNfcOemExtensionCallback = mock(INfcOemExtensionCallback.class);
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField("mNfcEnabled");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, true);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        ApduServiceInfo defaultServiceInfo = mock(ApduServiceInfo.class);
+        when(defaultServiceInfo.isOnHost()).thenReturn(false);
+        when(defaultServiceInfo.requiresUnlock()).thenReturn(true);
+        when(defaultServiceInfo.requiresScreenOn()).thenReturn(true);
+        when(defaultServiceInfo.getOffHostSecureElement()).thenReturn("sampleElement");
+        List<ApduServiceInfo> services = new ArrayList<>();
+        services.add(defaultServiceInfo);
+        aidResolveInfo.services = services;
+        aidResolveInfo.defaultService = defaultServiceInfo;
+        List<String> unCheckedOffHostSecureElement = new ArrayList<>();
+        unCheckedOffHostSecureElement.add("SampleElement");
+        aidResolveInfo.unCheckedOffHostSecureElement = unCheckedOffHostSecureElement;
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put(SUBSET_AID, aidResolveInfo);
+        Field fieldAidCache = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        fieldAidCache.setAccessible(true);
+        fieldAidCache.set(mRegisteredAidCache, mAidCache);
+        NfcService nfcService = mock(NfcService.class);
+        when(NfcService.getInstance()).thenReturn(nfcService);
+        when(nfcService.getNciVersion()).thenReturn(NfcService.NCI_VERSION_1_0);
+        when(mAidRoutingManager.configureRouting(any(HashMap.class), anyBoolean(),
+                anyBoolean())).thenReturn(AidRoutingManager.CONFIGURE_ROUTING_SUCCESS);
+        mRegisteredAidCache.setOemExtension(mNfcOemExtensionCallback);
+
+        assertEquals(AidRoutingManager.CONFIGURE_ROUTING_SUCCESS,
+                mRegisteredAidCache.updateRoutingLocked(true, true));
+        verify(mNfcOemExtensionCallback, never()).onRoutingTableFull();
+        verify(nfcService).getNciVersion();
+    }
+
+    @Test
+    public void testUpdateRoutingLockedWithSingleServiceAsPayment()
+            throws NoSuchFieldException, IllegalAccessException, RemoteException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        INfcOemExtensionCallback mNfcOemExtensionCallback = mock(INfcOemExtensionCallback.class);
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField("mNfcEnabled");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, true);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        ApduServiceInfo defaultServiceInfo = mock(ApduServiceInfo.class);
+        when(defaultServiceInfo.requiresUnlock()).thenReturn(true);
+        when(defaultServiceInfo.requiresScreenOn()).thenReturn(true);
+        List<ApduServiceInfo> services = new ArrayList<>();
+        services.add(defaultServiceInfo);
+        aidResolveInfo.services = services;
+        aidResolveInfo.defaultService = null;
+        aidResolveInfo.category = CardEmulation.CATEGORY_PAYMENT;
+        List<String> unCheckedOffHostSecureElement = new ArrayList<>();
+        unCheckedOffHostSecureElement.add("SampleElement");
+        aidResolveInfo.unCheckedOffHostSecureElement = unCheckedOffHostSecureElement;
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put(PREFIX_AID, aidResolveInfo);
+        Field fieldAidCache = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        fieldAidCache.setAccessible(true);
+        fieldAidCache.set(mRegisteredAidCache, mAidCache);
+        NfcService nfcService = mock(NfcService.class);
+        when(NfcService.getInstance()).thenReturn(nfcService);
+        when(nfcService.getNciVersion()).thenReturn(NfcService.NCI_VERSION_1_0);
+        when(mAidRoutingManager.configureRouting(any(HashMap.class), anyBoolean(),
+                anyBoolean())).thenReturn(AidRoutingManager.CONFIGURE_ROUTING_SUCCESS);
+        mRegisteredAidCache.setOemExtension(mNfcOemExtensionCallback);
+
+        assertEquals(AidRoutingManager.CONFIGURE_ROUTING_SUCCESS,
+                mRegisteredAidCache.updateRoutingLocked(true, true));
+        verify(mNfcOemExtensionCallback, never()).onRoutingTableFull();
+        verify(nfcService).getNciVersion();
+    }
+
+    @Test
+    public void testUpdateRoutingLockedWithSingleService()
+            throws NoSuchFieldException, IllegalAccessException, RemoteException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        INfcOemExtensionCallback mNfcOemExtensionCallback = mock(INfcOemExtensionCallback.class);
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField("mNfcEnabled");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, true);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        ApduServiceInfo defaultServiceInfo = mock(ApduServiceInfo.class);
+        when(defaultServiceInfo.isOnHost()).thenReturn(false);
+        when(defaultServiceInfo.requiresUnlock()).thenReturn(true);
+        when(defaultServiceInfo.requiresScreenOn()).thenReturn(true);
+        when(defaultServiceInfo.getOffHostSecureElement()).thenReturn("sampleElement");
+        List<ApduServiceInfo> services = new ArrayList<>();
+        services.add(defaultServiceInfo);
+        aidResolveInfo.services = services;
+        aidResolveInfo.defaultService = null;
+        aidResolveInfo.category = CardEmulation.CATEGORY_PAYMENT;
+        List<String> unCheckedOffHostSecureElement = new ArrayList<>();
+        unCheckedOffHostSecureElement.add("SampleElement");
+        aidResolveInfo.unCheckedOffHostSecureElement = unCheckedOffHostSecureElement;
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put(PREFIX_AID, aidResolveInfo);
+        Field fieldAidCache = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        fieldAidCache.setAccessible(true);
+        fieldAidCache.set(mRegisteredAidCache, mAidCache);
+        NfcService nfcService = mock(NfcService.class);
+        when(NfcService.getInstance()).thenReturn(nfcService);
+        when(nfcService.getNciVersion()).thenReturn(NfcService.NCI_VERSION_1_0);
+        when(mAidRoutingManager.configureRouting(any(HashMap.class), anyBoolean(),
+                anyBoolean())).thenReturn(AidRoutingManager.CONFIGURE_ROUTING_SUCCESS);
+        mRegisteredAidCache.setOemExtension(mNfcOemExtensionCallback);
+
+        assertEquals(AidRoutingManager.CONFIGURE_ROUTING_SUCCESS,
+                mRegisteredAidCache.updateRoutingLocked(true, true));
+        verify(mNfcOemExtensionCallback, never()).onRoutingTableFull();
+        verify(nfcService).getNciVersion();
+    }
+
+    @Test
+    public void testUpdateRoutingLockedWithMultipleService()
+            throws NoSuchFieldException, IllegalAccessException, RemoteException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        INfcOemExtensionCallback mNfcOemExtensionCallback = mock(INfcOemExtensionCallback.class);
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField("mNfcEnabled");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, true);
+        RegisteredAidCache.AidResolveInfo aidResolveInfo = mock(
+                RegisteredAidCache.AidResolveInfo.class);
+        ApduServiceInfo defaultServiceInfo = mock(ApduServiceInfo.class);
+        ApduServiceInfo secondServiceInfo = mock(ApduServiceInfo.class);
+        when(defaultServiceInfo.isOnHost()).thenReturn(false);
+        when(defaultServiceInfo.requiresUnlock()).thenReturn(true);
+        when(defaultServiceInfo.requiresScreenOn()).thenReturn(true);
+        when(defaultServiceInfo.getOffHostSecureElement()).thenReturn("sampleElement");
+        when(secondServiceInfo.getOffHostSecureElement()).thenReturn("sampleElement");
+        List<ApduServiceInfo> services = new ArrayList<>();
+        services.add(defaultServiceInfo);
+        services.add(secondServiceInfo);
+        aidResolveInfo.services = services;
+        aidResolveInfo.defaultService = null;
+        aidResolveInfo.category = CardEmulation.CATEGORY_PAYMENT;
+        List<String> unCheckedOffHostSecureElement = new ArrayList<>();
+        unCheckedOffHostSecureElement.add("SampleElement");
+        aidResolveInfo.unCheckedOffHostSecureElement = unCheckedOffHostSecureElement;
+        TreeMap<String, RegisteredAidCache.AidResolveInfo> mAidCache = new TreeMap<>();
+        mAidCache.put(PREFIX_AID, aidResolveInfo);
+        Field fieldAidCache = RegisteredAidCache.class.getDeclaredField("mAidCache");
+        fieldAidCache.setAccessible(true);
+        fieldAidCache.set(mRegisteredAidCache, mAidCache);
+        NfcService nfcService = mock(NfcService.class);
+        when(NfcService.getInstance()).thenReturn(nfcService);
+        when(nfcService.getNciVersion()).thenReturn(NfcService.NCI_VERSION_1_0);
+        when(mAidRoutingManager.configureRouting(any(HashMap.class), anyBoolean(),
+                anyBoolean())).thenReturn(AidRoutingManager.CONFIGURE_ROUTING_SUCCESS);
+        mRegisteredAidCache.setOemExtension(mNfcOemExtensionCallback);
+
+        assertEquals(AidRoutingManager.CONFIGURE_ROUTING_SUCCESS,
+                mRegisteredAidCache.updateRoutingLocked(true, true));
+        verify(mNfcOemExtensionCallback, never()).onRoutingTableFull();
+        verify(nfcService).getNciVersion();
+    }
+
+    @Test
+    public void testisPreferredServicePackageNameForUser()
+            throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String packageName = FOREGROUND_SERVICE.getPackageName();
+        ComponentName mPreferredForegroundService = mock(ComponentName.class);
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField(
+                "mPreferredForegroundService");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, mPreferredForegroundService);
+        Field fieldService = RegisteredAidCache.class.getDeclaredField(
+                "mUserIdPreferredForegroundService");
+        fieldService.setAccessible(true);
+        fieldService.set(mRegisteredAidCache, USER_ID);
+        when(mPreferredForegroundService.getPackageName()).thenReturn(packageName);
+
+        assertTrue(mRegisteredAidCache.isPreferredServicePackageNameForUser(packageName, USER_ID));
+    }
+
+    @Test
+    public void testisPreferredServicePackageNameForUserWithDifferentService()
+            throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String packageName = WALLET_PAYMENT_SERVICE.getPackageName();
+        ComponentName mPreferredForegroundService = mock(ComponentName.class);
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField(
+                "mPreferredForegroundService");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, mPreferredForegroundService);
+        Field fieldService = RegisteredAidCache.class.getDeclaredField(
+                "mUserIdPreferredForegroundService");
+        fieldService.setAccessible(true);
+        fieldService.set(mRegisteredAidCache, USER_ID);
+        when(mPreferredForegroundService.getPackageName()).thenReturn(packageName);
+
+        assertFalse(mRegisteredAidCache.isPreferredServicePackageNameForUser(
+                FOREGROUND_SERVICE.getPackageName(), USER_ID));
+    }
+
+    @Test
+    public void testisPreferredServicePackageNameForUserWithWallet()
+            throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String packageName = WALLET_PAYMENT_SERVICE.getPackageName();
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField(
+                "mPreferredForegroundService");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, null);
+        Field fieldWalletHolder = RegisteredAidCache.class.getDeclaredField(
+                "mUserIdDefaultWalletHolder");
+        fieldWalletHolder.setAccessible(true);
+        fieldWalletHolder.set(mRegisteredAidCache, USER_ID);
+        Field fieldWalletHolderPackage = RegisteredAidCache.class.getDeclaredField(
+                "mDefaultWalletHolderPackageName");
+        fieldWalletHolderPackage.setAccessible(true);
+        fieldWalletHolderPackage.set(mRegisteredAidCache, packageName);
+        when(mWalletRoleObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
+
+
+        assertTrue(mRegisteredAidCache.isPreferredServicePackageNameForUser(packageName, USER_ID));
+    }
+
+    @Test
+    public void testisPreferredServicePackageNameForUserWithDifferentWalletService()
+            throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String packageName = WALLET_PAYMENT_SERVICE.getPackageName();
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField(
+                "mPreferredForegroundService");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, null);
+        Field fieldWalletHolder = RegisteredAidCache.class.getDeclaredField(
+                "mUserIdDefaultWalletHolder");
+        fieldWalletHolder.setAccessible(true);
+        fieldWalletHolder.set(mRegisteredAidCache, 1);
+        when(mWalletRoleObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
+
+
+        assertFalse(mRegisteredAidCache.isPreferredServicePackageNameForUser(packageName, USER_ID));
+    }
+
+    @Test
+    public void testisPreferredServicePackageNameForUserWithPreferredPaymentService()
+            throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String packageName = PAYMENT_SERVICE.getPackageName();
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField(
+                "mPreferredForegroundService");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, null);
+        Field fieldService = RegisteredAidCache.class.getDeclaredField(
+                "mPreferredPaymentService");
+        fieldService.setAccessible(true);
+        fieldService.set(mRegisteredAidCache, PAYMENT_SERVICE);
+        Field fieldWalletHolder = RegisteredAidCache.class.getDeclaredField(
+                "mUserIdPreferredPaymentService");
+        fieldWalletHolder.setAccessible(true);
+        fieldWalletHolder.set(mRegisteredAidCache, USER_ID);
+        when(mWalletRoleObserver.isWalletRoleFeatureEnabled()).thenReturn(false);
+
+        assertTrue(mRegisteredAidCache.isPreferredServicePackageNameForUser(packageName, USER_ID));
+    }
+
+    @Test
+    public void testisPreferredServicePackageNameForUserWithNonDefaultService()
+            throws NoSuchFieldException, IllegalAccessException {
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        String packageName = PAYMENT_SERVICE.getPackageName();
+        Field fieldNfcEnable = RegisteredAidCache.class.getDeclaredField(
+                "mPreferredForegroundService");
+        fieldNfcEnable.setAccessible(true);
+        fieldNfcEnable.set(mRegisteredAidCache, null);
+        Field fieldService = RegisteredAidCache.class.getDeclaredField(
+                "mPreferredPaymentService");
+        fieldService.setAccessible(true);
+        fieldService.set(mRegisteredAidCache, null);
+        when(mWalletRoleObserver.isWalletRoleFeatureEnabled()).thenReturn(false);
+
+        assertFalse(mRegisteredAidCache.isPreferredServicePackageNameForUser(packageName, USER_ID));
+    }
 }
diff --git a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/RoutingOptionManagerTest.java b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/RoutingOptionManagerTest.java
index 0e3b1c6c0..075922226 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/RoutingOptionManagerTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/RoutingOptionManagerTest.java
@@ -15,16 +15,34 @@
  */
 package com.android.nfc.cardemulation;
 
+import static com.android.nfc.cardemulation.RoutingOptionManager.KEY_AUTO_CHANGE_CAPABLE;
+import static com.android.nfc.cardemulation.RoutingOptionManager.KEY_DEFAULT_ISO_DEP_ROUTE;
+import static com.android.nfc.cardemulation.RoutingOptionManager.KEY_DEFAULT_OFFHOST_ROUTE;
+import static com.android.nfc.cardemulation.RoutingOptionManager.KEY_DEFAULT_ROUTE;
+import static com.android.nfc.cardemulation.RoutingOptionManager.KEY_DEFAULT_SC_ROUTE;
+import static com.android.nfc.cardemulation.RoutingOptionManager.ROUTE_DEFAULT;
+import static com.android.nfc.cardemulation.RoutingOptionManager.ROUTE_UNKNOWN;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
+import android.content.Context;
+import android.content.SharedPreferences;
+import android.content.pm.PackageManager;
+
 import androidx.test.runner.AndroidJUnit4;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.nfc.DeviceConfigFacade;
 import com.android.nfc.NfcService;
+import com.android.nfc.cardemulation.util.TelephonyUtils;
 import com.android.nfc.dhimpl.NativeNfcManager;
 
 import org.junit.After;
@@ -38,17 +56,16 @@ import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 
+import java.lang.reflect.Field;
+
 @RunWith(AndroidJUnit4.class)
 public class RoutingOptionManagerTest {
-
     @Mock
     private NfcService mNfcService;
     @Mock
     private NativeNfcManager mNativeNfcManager;
-
     @Captor
     private ArgumentCaptor<Integer> mRouteCaptor;
-
     private static final int DEFAULT_ROUTE = 0;
     private static final int DEFAULT_ISO_DEP_ROUTE = 1;
     private static final int NDEF_NFCEE_ROUTE = 4;
@@ -61,6 +78,7 @@ public class RoutingOptionManagerTest {
     private static final byte[] OFF_HOST_ESE = new byte[] {3, 4};
     private static final int AID_MATCHING_MODE = 3;
     private static final int DEFAULT_EUICC_MEP_MODE = 0;
+    private RoutingOptionManager mRoutingOptionManager;
 
     private static class TestRoutingOptionManager extends RoutingOptionManager {
         @Override
@@ -124,6 +142,53 @@ public class RoutingOptionManagerTest {
         when(mNativeNfcManager.getNdefNfceeRouteId()).thenReturn(NDEF_NFCEE_ROUTE);
         when(NfcService.getInstance()).thenReturn(mNfcService);
         when(NativeNfcManager.getInstance()).thenReturn(mNativeNfcManager);
+        mRoutingOptionManager = new RoutingOptionManager() {
+            @Override
+            int doGetDefaultRouteDestination() {
+                return DEFAULT_ROUTE;
+            }
+
+            @Override
+            int doGetDefaultIsoDepRouteDestination() {
+                return DEFAULT_ISO_DEP_ROUTE;
+            }
+
+            @Override
+            int doGetDefaultOffHostRouteDestination() {
+                return DEFAULT_OFF_HOST_ROUTE;
+            }
+
+            @Override
+            int doGetDefaultFelicaRouteDestination() {
+                return DEFAULT_FELICA_ROUTE;
+            }
+
+            @Override
+            int doGetDefaultScRouteDestination() {
+                return DEFAULT_SC_ROUTE;
+            }
+
+            @Override
+            byte[] doGetOffHostUiccDestination() {
+                return OFF_HOST_UICC;
+            }
+
+            @Override
+            byte[] doGetOffHostEseDestination() {
+                return OFF_HOST_ESE;
+            }
+
+            @Override
+            int doGetAidMatchingMode() {
+                return AID_MATCHING_MODE;
+            }
+
+            @Override
+            int doGetEuiccMepMode() {
+                return DEFAULT_EUICC_MEP_MODE;
+            }
+        };
+
     }
 
     @After
@@ -149,7 +214,6 @@ public class RoutingOptionManagerTest {
         mManager = new TestRoutingOptionManager();
 
         mManager.overrideDefaultIsoDepRoute(OVERRIDDEN_ISO_DEP_ROUTE);
-
         assertEquals(OVERRIDDEN_ISO_DEP_ROUTE, mManager.getOverrideDefaultIsoDepRoute());
         verify(mNfcService).setIsoDepProtocolRoute(mRouteCaptor.capture());
         assertEquals(Integer.valueOf(OVERRIDDEN_ISO_DEP_ROUTE), mRouteCaptor.getValue());
@@ -160,7 +224,6 @@ public class RoutingOptionManagerTest {
         mManager = new TestRoutingOptionManager();
 
         mManager.overrideDefaultOffHostRoute(OVERRIDDEN_OFF_HOST_ROUTE);
-
         assertEquals(OVERRIDDEN_OFF_HOST_ROUTE, mManager.getOverrideDefaultOffHostRoute());
         verify(mNfcService).setTechnologyABFRoute(mRouteCaptor.capture(), mRouteCaptor.capture());
         assertEquals(Integer.valueOf(OVERRIDDEN_OFF_HOST_ROUTE), mRouteCaptor.getValue());
@@ -171,7 +234,6 @@ public class RoutingOptionManagerTest {
         mManager = new TestRoutingOptionManager();
 
         mManager.overrideDefaultRoute(OVERRIDDEN_OFF_HOST_ROUTE);
-
         assertEquals(OVERRIDDEN_OFF_HOST_ROUTE, mManager.getOverrideDefaultRoute());
     }
 
@@ -183,9 +245,9 @@ public class RoutingOptionManagerTest {
 
         verify(mNfcService).setIsoDepProtocolRoute(anyInt());
         verify(mNfcService).setTechnologyABFRoute(anyInt(), anyInt());
-        assertEquals(RoutingOptionManager.ROUTE_UNKNOWN, mManager.mOverrideDefaultRoute);
-        assertEquals(RoutingOptionManager.ROUTE_UNKNOWN, mManager.mOverrideDefaultIsoDepRoute);
-        assertEquals(RoutingOptionManager.ROUTE_UNKNOWN, mManager.mOverrideDefaultOffHostRoute);
+        assertEquals(ROUTE_UNKNOWN, mManager.mOverrideDefaultRoute);
+        assertEquals(ROUTE_UNKNOWN, mManager.mOverrideDefaultIsoDepRoute);
+        assertEquals(ROUTE_UNKNOWN, mManager.mOverrideDefaultOffHostRoute);
     }
 
     @Test
@@ -209,6 +271,7 @@ public class RoutingOptionManagerTest {
         assertEquals(OFF_HOST_UICC, offHostRouteUicc);
         assertEquals(OFF_HOST_ESE, offHostRouteEse);
         assertEquals(AID_MATCHING_MODE, aidMatchingSupport);
+        assertEquals(DEFAULT_SC_ROUTE, mManager.getDefaultScRoute());
     }
 
     @Test
@@ -216,7 +279,137 @@ public class RoutingOptionManagerTest {
         mManager = new TestRoutingOptionManager();
 
         boolean result = mManager.isRoutingTableOverrided();
-
         assertFalse(result);
     }
+
+    @Test
+    public void testDefaultScRoute() {
+        mManager = new TestRoutingOptionManager();
+        assertEquals(ROUTE_UNKNOWN, mManager.getOverrideDefaultScRoute());
+
+        mManager.overrideDefaultScRoute(DEFAULT_SC_ROUTE);
+        assertEquals(DEFAULT_SC_ROUTE, mManager.getOverrideDefaultScRoute());
+    }
+
+    @Test
+    public void testPreferredSim() {
+        mManager = new TestRoutingOptionManager();
+        assertEquals("SIM1", mManager.getPreferredSim());
+    }
+
+    @Test
+    public void testAutoChangeStatus() throws NoSuchFieldException, IllegalAccessException {
+        SharedPreferences mPrefs = mock(SharedPreferences.class);
+        SharedPreferences.Editor editor = mock(SharedPreferences.Editor.class);
+        Field field = RoutingOptionManager.class.getDeclaredField("mPrefs");
+        field.setAccessible(true);
+        field.set(mRoutingOptionManager, mPrefs);
+        when(mPrefs.edit()).thenReturn(editor);
+        when(editor.putBoolean(anyString(), anyBoolean())).thenReturn(editor);
+
+        assertTrue(mRoutingOptionManager.isAutoChangeEnabled());
+
+        mRoutingOptionManager.setAutoChangeStatus(false);
+        assertFalse(mRoutingOptionManager.isAutoChangeEnabled());
+    }
+
+    @Test
+    public void testOverwriteRoutingTableWithDefaultRoute()
+            throws NoSuchFieldException, IllegalAccessException {
+
+        SharedPreferences mPrefs = mock(SharedPreferences.class);
+        SharedPreferences.Editor editor = mock(SharedPreferences.Editor.class);
+        mRoutingOptionManager.overrideDefaultRoute(ROUTE_DEFAULT);
+        mRoutingOptionManager.overrideDefaultIsoDepRoute(ROUTE_DEFAULT);
+        mRoutingOptionManager.overrideDefaultOffHostRoute(ROUTE_DEFAULT);
+        mRoutingOptionManager.overrideDefaultScRoute(ROUTE_DEFAULT);
+        Field field = RoutingOptionManager.class.getDeclaredField("mPrefs");
+        field.setAccessible(true);
+        field.set(mRoutingOptionManager, mPrefs);
+        when(mPrefs.edit()).thenReturn(editor);
+        when(editor.putString(anyString(), anyString())).thenReturn(editor);
+
+        mRoutingOptionManager.overwriteRoutingTable();
+        assertEquals(DEFAULT_ROUTE, mRoutingOptionManager.getDefaultRoute());
+        assertEquals(DEFAULT_ISO_DEP_ROUTE, mRoutingOptionManager.getDefaultIsoDepRoute());
+        assertEquals(DEFAULT_OFF_HOST_ROUTE, mRoutingOptionManager.getDefaultOffHostRoute());
+        assertEquals(DEFAULT_SC_ROUTE, mRoutingOptionManager.getDefaultScRoute());
+    }
+
+    @Test
+    public void testOverwriteRoutingTable()
+            throws NoSuchFieldException, IllegalAccessException {
+        SharedPreferences mPrefs = mock(SharedPreferences.class);
+        SharedPreferences.Editor editor = mock(SharedPreferences.Editor.class);
+        mRoutingOptionManager.overrideDefaultRoute(NDEF_NFCEE_ROUTE);
+        mRoutingOptionManager.overrideDefaultIsoDepRoute(OVERRIDDEN_ISO_DEP_ROUTE);
+        mRoutingOptionManager.overrideDefaultOffHostRoute(OVERRIDDEN_OFF_HOST_ROUTE);
+        mRoutingOptionManager.overrideDefaultScRoute(DEFAULT_SC_ROUTE);
+        Field field = RoutingOptionManager.class.getDeclaredField("mPrefs");
+        field.setAccessible(true);
+        field.set(mRoutingOptionManager, mPrefs);
+        when(mPrefs.edit()).thenReturn(editor);
+        when(editor.putString(anyString(), anyString())).thenReturn(editor);
+
+        mRoutingOptionManager.overwriteRoutingTable();
+        assertEquals(NDEF_NFCEE_ROUTE, mRoutingOptionManager.getDefaultRoute());
+        assertEquals(OVERRIDDEN_ISO_DEP_ROUTE, mRoutingOptionManager.getDefaultIsoDepRoute());
+        assertEquals(OVERRIDDEN_OFF_HOST_ROUTE, mRoutingOptionManager.getDefaultOffHostRoute());
+        assertEquals(DEFAULT_SC_ROUTE, mRoutingOptionManager.getDefaultScRoute());
+        assertEquals(ROUTE_UNKNOWN, mRoutingOptionManager.getOverrideDefaultFelicaRoute());
+    }
+
+    @Test
+    public void testReadRoutingOptionsFromPrefs()
+            throws NoSuchFieldException, IllegalAccessException {
+        String defaultRoute = "DefaultRoute";
+        Context context = mock(Context.class);
+        DeviceConfigFacade deviceConfigFacade = mock(DeviceConfigFacade.class);
+        PackageManager packageManager = mock(PackageManager.class);
+        SharedPreferences mPrefs = mock(SharedPreferences.class);
+        SharedPreferences.Editor editor = mock(SharedPreferences.Editor.class);
+        mRoutingOptionManager.overrideDefaultRoute(NDEF_NFCEE_ROUTE);
+        Field field = RoutingOptionManager.class.getDeclaredField("mPrefs");
+        field.setAccessible(true);
+        field.set(mRoutingOptionManager, null);
+        when(context.getSharedPreferences(anyString(), anyInt())).thenReturn(mPrefs);
+        when(context.getPackageManager()).thenReturn(packageManager);
+        when(packageManager.hasSystemFeature(anyString())).thenReturn(true);
+        when(mPrefs.edit()).thenReturn(editor);
+        when(editor.putString(anyString(), anyString())).thenReturn(editor);
+        when(editor.putBoolean(anyString(), anyBoolean())).thenReturn(editor);
+        when(deviceConfigFacade.getDefaultRoute()).thenReturn(defaultRoute);
+        when(deviceConfigFacade.getDefaultIsoDepRoute()).thenReturn(defaultRoute);
+        when(deviceConfigFacade.getDefaultOffHostRoute()).thenReturn(defaultRoute);
+        when(deviceConfigFacade.getDefaultScRoute()).thenReturn(defaultRoute);
+        when(mPrefs.contains(KEY_DEFAULT_ROUTE)).thenReturn(false);
+        when(mPrefs.contains(KEY_DEFAULT_ISO_DEP_ROUTE)).thenReturn(false);
+        when(mPrefs.contains(KEY_DEFAULT_OFFHOST_ROUTE)).thenReturn(false);
+        when(mPrefs.contains(KEY_DEFAULT_SC_ROUTE)).thenReturn(false);
+        when(mPrefs.contains(KEY_AUTO_CHANGE_CAPABLE)).thenReturn(false);
+        when(mPrefs.getString(KEY_DEFAULT_ROUTE, null)).thenReturn(defaultRoute);
+        when(mPrefs.getString(KEY_DEFAULT_ISO_DEP_ROUTE, null)).thenReturn(defaultRoute);
+        when(mPrefs.getString(KEY_DEFAULT_OFFHOST_ROUTE, null)).thenReturn(defaultRoute);
+        when(mPrefs.getString(KEY_DEFAULT_SC_ROUTE, null)).thenReturn(defaultRoute);
+        when(mPrefs.getBoolean(KEY_AUTO_CHANGE_CAPABLE, true)).thenReturn(true);
+
+        mRoutingOptionManager.readRoutingOptionsFromPrefs(context, deviceConfigFacade);
+        assertTrue(mRoutingOptionManager.isAutoChangeEnabled());
+        verify(mPrefs).contains(KEY_AUTO_CHANGE_CAPABLE);
+    }
+
+    @Test
+    public void testSimSettings() {
+        RoutingOptionManager.SimSettings simSettings = new RoutingOptionManager.SimSettings(2, 1);
+        assertEquals("SIM1", simSettings.getName());
+
+        simSettings.setType(TelephonyUtils.SIM_TYPE_UICC);
+        assertEquals("SIM1", simSettings.getName());
+
+        simSettings.setType(TelephonyUtils.SIM_TYPE_EUICC_1);
+        assertEquals("SIM2", simSettings.getName());
+
+        simSettings.setType(TelephonyUtils.SIM_TYPE_EUICC_2);
+        assertEquals("SIM2", simSettings.getName());
+    }
 }
diff --git a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/util/TelephonyUtilsTest.java b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/util/TelephonyUtilsTest.java
index cdd073385..ac1a3afa6 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/cardemulation/util/TelephonyUtilsTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/cardemulation/util/TelephonyUtilsTest.java
@@ -105,27 +105,6 @@ public class TelephonyUtilsTest {
         assertFalse(mTelephonyUtils.isEuiccSubscription(SUBSCRIPTION_ID_UICC));
     }
 
-    @Test
-    public void testGetActiveSubscriptionInfoByIdWhenIdUicc() {
-        SubscriptionInfo subscriptionInfo = mock(SubscriptionInfo.class);
-        List<SubscriptionInfo> list = new ArrayList<>();
-        list.add(subscriptionInfo);
-        when(mSubscriptionManager.getActiveSubscriptionInfoList()).thenReturn(list);
-
-        mTelephonyUtils.getActiveSubscriptionInfoById(SUBSCRIPTION_ID_UICC);
-        verify(mSubscriptionManager).getActiveSubscriptionInfoList();
-    }
-
-    @Test
-    public void testGetActiveSubscriptionInfoByIdWhenEmbeddedUicc() {
-        SubscriptionInfo subscriptionInfo = mock(SubscriptionInfo.class);
-        when(mSubscriptionManager.getActiveSubscriptionInfo(SUBSCRIPTION_ID_UNKNOWN)).thenReturn(
-                subscriptionInfo);
-
-        mTelephonyUtils.getActiveSubscriptionInfoById(SUBSCRIPTION_ID_UNKNOWN);
-        verify(mSubscriptionManager).getActiveSubscriptionInfo(SUBSCRIPTION_ID_UNKNOWN);
-    }
-
     @Test
     public void testOnSubscriptionsChanged() {
         TelephonyUtils.Callback callback = mock(TelephonyUtils.Callback.class);
diff --git a/NfcNci/tests/unit/src/com/android/nfc/wlc/NfcChargingTest.java b/NfcNci/tests/unit/src/com/android/nfc/wlc/NfcChargingTest.java
index 549ddc6f1..7d66fd9fb 100644
--- a/NfcNci/tests/unit/src/com/android/nfc/wlc/NfcChargingTest.java
+++ b/NfcNci/tests/unit/src/com/android/nfc/wlc/NfcChargingTest.java
@@ -327,7 +327,7 @@ public class NfcChargingTest {
     public void testHandleWlcCap_ModeReq_State24() {
         mNfcCharging.WLCState = 9;
         mNfcCharging.HandleWLCState();
-        verify(mNfcCharging.TagHandler).stopPresenceChecking();
+        verify(mNfcCharging.TagHandler).stopPresenceChecking(false);
         Assert.assertEquals(0, mNfcCharging.WLCState);
     }
 
diff --git a/NfcNci/testutils/Android.bp b/NfcNci/testutils/Android.bp
index 3865297a8..1561b763a 100644
--- a/NfcNci/testutils/Android.bp
+++ b/NfcNci/testutils/Android.bp
@@ -23,64 +23,6 @@ android_library {
     ],
 }
 
-android_app {
-    name: "NfcEmulatorApduAppNonTest",
-    sdk_version: "test_current",
-    min_sdk_version: "35",
-    srcs: [
-        "src/com/android/nfc/emulatorapp/**/*.kt",
-    ],
-    assets: ["src/com/android/nfc/emulatorapp/parsed_files/**/*.txt"],
-    resource_dirs: ["src/com/android/nfc/emulatorapp/res"],
-    manifest: "src/com/android/nfc/emulatorapp/AndroidManifest.xml",
-    static_libs: [
-        "guava",
-        "androidx.appcompat_appcompat",
-        "kotlinx-coroutines-android",
-        "androidx.annotation_annotation",
-        "androidx.compose.ui_ui",
-        "com.google.android.material_material",
-        "kotlinx_serialization_core",
-        "kotlinx_serialization_json",
-        "nfc-multidevice-utils",
-    ],
-    visibility: [
-        "//cts:__subpackages__",
-        "//packages/modules/Nfc/NfcNci:__subpackages__",
-        "//packages/modules/Nfc:__subpackages__",
-        "//vendor:__subpackages__",
-    ],
-}
-
-android_test {
-    name: "NfcEmulatorApduApp",
-    sdk_version: "test_current",
-    min_sdk_version: "35",
-    srcs: [
-        "src/com/android/nfc/emulatorapp/**/*.kt",
-    ],
-    assets: ["src/com/android/nfc/emulatorapp/parsed_files/**/*.txt"],
-    resource_dirs: ["src/com/android/nfc/emulatorapp/res"],
-    manifest: "src/com/android/nfc/emulatorapp/AndroidManifest.xml",
-    static_libs: [
-        "guava",
-        "androidx.appcompat_appcompat",
-        "kotlinx-coroutines-android",
-        "androidx.annotation_annotation",
-        "androidx.compose.ui_ui",
-        "com.google.android.material_material",
-        "nfc-multidevice-utils",
-        "kotlinx_serialization_core",
-        "kotlinx_serialization_json",
-    ],
-    visibility: [
-        "//cts:__subpackages__",
-        "//packages/modules/Nfc/NfcNci:__subpackages__",
-        "//packages/modules/Nfc:__subpackages__",
-        "//vendor:__subpackages__",
-    ],
-}
-
 android_test {
     name: "NfcEmulatorTestApp",
     sdk_version: "test_current",
diff --git a/NfcNci/testutils/AndroidTest.xml b/NfcNci/testutils/AndroidTest.xml
index 98b9ad1cd..64a67e6d7 100644
--- a/NfcNci/testutils/AndroidTest.xml
+++ b/NfcNci/testutils/AndroidTest.xml
@@ -35,6 +35,5 @@
     <option name="mobly-test-timeout" value="180000" />
   </test>
 
-  <option name="build_apk" key="file" value="NfcEmulatorApduApp.apk" />
   <option name="mobly_config" key="file" value="config.yaml" />
 </configuration>
\ No newline at end of file
diff --git a/NfcNci/testutils/README.md b/NfcNci/testutils/README.md
index a94d2277b..6ab0108e4 100644
--- a/NfcNci/testutils/README.md
+++ b/NfcNci/testutils/README.md
@@ -1,7 +1,7 @@
 ### NFC Replay Utility
 
 The NFC Replay tool allows a PN 532 module to reenact a NFC transaction from a
-snoop log. Currently, the tool is capable of replaying polling loop transactions
+raw bug report. Currently, the tool is capable of replaying polling loop transactions
 and APDU exchanges. Once the transaction has been replayed, a test can
 optionally be generated based on the interaction between the module and
 emulator.
@@ -12,31 +12,33 @@ The detailed design for this feature can be found at go/nfc-replay-utility-dd.
 
 #### Generating and replaying a test
 
-1\. Obtain a snoop log from the device (see instructions below for how to do this).
+1\. Obtain a bug report from the device. You will need to locate the raw bug
+report file (which will likely have the title "bugreport-...txt") and keep
+track of its path.
 
 2\. Connect the PN532 module via a serial port.
 
-3\. To replay the transaction, substitute the name of the snoop file and the
-serial port that the PN 532 module is using.
+3\. To replay the transaction, substitute the path of the bug report file and
+the serial port that the PN 532 module is using.
 
 ```
-python3 nfcreplay.py -f $SNOOP_FILE -p $READER_PATH
+python3 nfcreplay.py -f $BUG_REPORT_FILE -p $READER_PATH
 ```
 
-Alternatively, to replay a specific section of the snoop log, additional
+Alternatively, to replay a specific section of the bug report, additional
 arguments should be added to denote the desired start and end time frame of the
 transaction. For instance:
 
 ```
-python3 nfcreplay.py -f $SNOOP_FILE -p $READER_PATH --start "2024-07-17 12:00:00" --end "2024-07-17 15:00:00"
+python3 nfcreplay.py -f $BUG_REPORT_FILE -p $READER_PATH --start "2024-07-17 12:00:00" --end "2024-07-17 15:00:00"
 ```
 
 Information about the transaction will be printed out to console, including a
 list of all polling loop and APDU exchanges that took place.
 
-5\. To generate and run a test from the snoop log, use the command:
+5\. To generate and run a test from the bug report, use the command:
 ```
-python3 nfcreplay.py -f $SNOOP_FILE -p $READER_PATH --generate_and_replay_test
+python3 nfcreplay.py -f $BUG_REPORT_FILE -p $READER_PATH --generate_and_replay_test
 ```
 
 A Python file will be created, representing the test, along with a JSON file
@@ -58,31 +60,29 @@ the emulator app.
 
 To use the emulator app outside of a generated test, perform the following steps:
 
-1\. To prepare a snoop log to be replayed with the app:
+1\. To prepare a bug report to be replayed with the app:
 
 ```
-python3 nfcreplay.py -f $SNOOP_FILE --parse_only
+python3 nfcreplay.py -f $BUG_REPORT_FILE --parse_only
 ```
 
 The script will produce the name of the parsed log, which will be located within
 the folder emulatorapp/parsed_files. Save the name for Step 3.
 
-2\. Build and install the emulator app. The following commands are specific to
-the Pixel 6 Pro (Raven). Non-Raven devices should substitute "raven" for the
-appropriate value.
+2\. Build and install the emulator app.
 
 ```
-mma NfcEmulatorApduAppNonTest
-adb install -r -g ~/aosp-main-with-phones/out/target/product/raven/system/app/emulatorapp/NfcEmulatorApduAppNonTest.apk
+mma EmulatorApduAppNonTest
+adb install -r -g $PATH_TO_EMULATOR_APP_APK
 
 ```
 
-3\. Start the activity. Make sure that $PARSED_SNOOP_FILE is the name of the
-file, rather than its path. It is assumed that this file is located within
+3\. Start the activity. Make sure that $$PARSED_FILE is the name of
+the file, rather than its path. It is assumed that this file is located within
 emulatorapp/parsed_files, where it was originally created.
 
 ```
-adb shell am start -n com.android.nfc.emulatorapp/.MainActivity --es "snoop_file" "$PARSED_SNOOP_FILE"
+adb shell am start -n com.android.nfc.emulatorapduapp/.MainActivity --es "snoop_file" "$PARSED_FILE"
 ```
 
 When you are ready to start the transaction, press the "Start Host APDU Service"
@@ -95,17 +95,4 @@ generate and replay a test case, though you should make sure to append the flag
 When the transaction is replayed, you should be able to see a list of APDU
 commands and responses received and sent by the Host APDU service displayed on
 the emulator app. Additionally, the replay script will output similar
-information.
-
-### Creating a Snoop Log
-
-To create a snoop log from your Android device, you should first go to Developer
-Options in Settings to make sure that "NFC NCI unfiltered log" is enabled. This
-will ensure that the data packets sent during NFC transactions are not truncated
-in the snoop log.
-
-After the NFC transaction is complete, enter the command `adb shell dumpsys
-nfc`. This will output the snoop log, which will begin with the line `---
-BEGIN:NFCSNOOP_VS_LOG_SUMMARY` and end with the line `---
-END:NFCSNOOP_VS_LOG_SUMMARY ---`. Copy the snoop log into a text file, and make
-sure to include both the start and end lines.
\ No newline at end of file
+information.
\ No newline at end of file
diff --git a/NfcNci/testutils/generate_test.py b/NfcNci/testutils/generate_test.py
index dfdd9335b..a25c7e499 100644
--- a/NfcNci/testutils/generate_test.py
+++ b/NfcNci/testutils/generate_test.py
@@ -14,32 +14,34 @@
 
 # Lint as: python3
 
-"""Generates a Python test case from a snoop log."""
+"""Generates a Python test case from a bug report."""
 
 import json
 import math
 import os
 
-from parse_log import FullApduEntry, NfcType, PollingLoopEntry
+from parse_log import DumpNfcInfo, FullApduEntry, NfcType, PollingLoopEntry
 
 INDENT_SIZE = 4
 
 
 def generate_test(
-    log: list[FullApduEntry | PollingLoopEntry], name: str
+    log: list[FullApduEntry | PollingLoopEntry],
+    name: str,
+    nfc_dump: DumpNfcInfo,
 ) -> str:
-  """Generates a Python test case from a snoop log parsed by the replay tool.
+  """Generates a Python test case from a bug report parsed by the replay tool.
 
   The generated test will be placed in the current directory.
 
   Args:
-    log: The parsed snoop log.
-    name: The name of the file containing the snoop log.
+    log: The parsed snoop log from the bug report.
+    name: The name of the file containing the bug report.
 
   Returns:
     The name of the JSON file containing APDUs needed to run the test.
   """
-  # The name of the test file is based on the name of the snoop log
+  # The name of the test file is based on the name of the bug report
   python_local_file = name + "_test.py"
   file_path = (
       os.path.dirname(os.path.realpath(__file__)) + "/" + python_local_file
@@ -54,7 +56,7 @@ def generate_test(
   file.write(create_imports())
   file.write(create_polling_loop_methods())
   file.write(create_apdu_exchange_method())
-  file.write(create_setup())
+  file.write(create_setup(nfc_dump))
   file.write(create_test_opening(name))
 
   last_timestamp = log[0].ts
@@ -81,7 +83,9 @@ def generate_test(
   print()
   print(
       "Test generated at {}. To run the test, copy the test file to"
-      " packages/modules/Nfc/NfcNci/tests/testcases/multidevices/.".format(file_path)
+      " packages/modules/Nfc/NfcNci/tests/testcases/multidevices/.".format(
+          file_path
+      )
   )
   update_android_bp(python_local_file, name)
 
@@ -102,10 +106,10 @@ def update_android_bp(local_file_path, test_name):
   s += create_line('main: "{}",'.format(local_file_path), indent=1)
   s += create_line('srcs: ["{}"],'.format(local_file_path), indent=1)
   s += create_line('test_config: "AndroidTest.xml",', indent=1)
-  s += create_line('device_common_data: [', indent=1)
-  s += create_line('":NfcEmulatorApduApp",', indent=2)
+  s += create_line("device_common_data: [", indent=1)
+  s += create_line('":EmulatorApduApp",', indent=2)
   s += create_line('"config.yaml",', indent=2)
-  s += create_line('],', indent=1)
+  s += create_line("],", indent=1)
   s += create_line("test_options: {", indent=1)
   s += create_line("unit_test: false,", indent=2)
   s += create_line('runner: "mobly",', indent=2)
@@ -144,7 +148,9 @@ def create_test_opening(name: str):
   s += create_line("apdu_rsps = []", indent=2)
   s += create_line("if file_path_name:", indent=2)
   s += create_line('with open(file_path_name, "r") as json_str:', indent=3)
-  s += create_line('self.emulator.nfc_emulator.startMainActivity(json_str.read())', indent=4)
+  s += create_line(
+      "self.emulator.nfc_emulator.startMainActivity(json_str.read())", indent=4
+  )
   s += create_line()
   s += create_line('with open(file_path_name, "r") as json_data:', indent=3)
   s += create_line("d = json.load(json_data)", indent=4)
@@ -248,6 +254,7 @@ def create_imports():
   s += create_line()
   return s
 
+
 def create_polling_loop_methods():
   """Create methods that send polling loops to the reader.
 
@@ -311,28 +318,30 @@ def create_apdu_exchange_method():
   s += create_line(
       '"""Conducts an APDU exchange with the PN532 reader."""', indent=1
   )
-  s += create_line('for _ in range(_NUM_POLLING_LOOPS):', indent=1)
-  s += create_line('tag = reader.poll_a()', indent=2)
-  s += create_line('if tag is not None:', indent=2)
-  s += create_line('transacted = tag.transact(commands, responses)', indent=3)
-  s += create_line('reader.mute()', indent=3)
-  s += create_line('# edge case: expect no response', indent=3)
-  s += create_line('if not responses or responses[0] == bytearray.fromhex(""):', indent=3)
-  s += create_line('return tag, True', indent=4)
-  s += create_line('return tag, transacted', indent=3)
-  s += create_line('reader.mute()', indent=2)
-  s += create_line('return None, False', indent=1)
+  s += create_line("for _ in range(_NUM_POLLING_LOOPS):", indent=1)
+  s += create_line("tag = reader.poll_a()", indent=2)
+  s += create_line("if tag is not None:", indent=2)
+  s += create_line("transacted = tag.transact(commands, responses)", indent=3)
+  s += create_line("reader.mute()", indent=3)
+  s += create_line("# edge case: expect no response", indent=3)
+  s += create_line(
+      'if not responses or responses[0] == bytearray.fromhex(""):', indent=3
+  )
+  s += create_line("return tag, True", indent=4)
+  s += create_line("return tag, transacted", indent=3)
+  s += create_line("reader.mute()", indent=2)
+  s += create_line("return None, False", indent=1)
   return s
 
 
-def create_setup():
+def create_setup(nfc_dump: DumpNfcInfo):
   """Creates methods to prepare the PN532 reader and emulator before the test.
 
   This involves checking to ensure that the raeder and emulator are both
   present, and enabling NFC on the emulator.
 
   Args:
-    name: The name of the original snoop log file.
+    name: The name of the original bug report file.
   """
   s = create_line()
   s += create_line()
@@ -345,14 +354,25 @@ def create_setup():
       "self.emulator = self.register_controller(android_device)[0]", indent=2
   )
   s += create_line('self.emulator.debug_tag = "emulator"', indent=2)
-  s += create_line('if (hasattr(self.emulator, "dimensions") and "pn532_serial_path" in self.emulator.dimensions):', indent=2)
-  s += create_line('pn532_serial_path = self.emulator.dimensions["pn532_serial_path"]', indent=3)
-  s += create_line('else:', indent=2)
+  s += create_line(
+      'if (hasattr(self.emulator, "dimensions") and "pn532_serial_path" in'
+      " self.emulator.dimensions):",
+      indent=2,
+  )
+  s += create_line(
+      'pn532_serial_path = self.emulator.dimensions["pn532_serial_path"]',
+      indent=3,
+  )
+  s += create_line("else:", indent=2)
   s += create_line(
       'pn532_serial_path = self.user_params.get("pn532_serial_path", "")',
       indent=3,
   )
-  s += create_line('self.emulator.load_snippet("nfc_emulator", "com.android.nfc.emulatorapp")', indent=2)
+  s += create_line(
+      'self.emulator.load_snippet("nfc_emulator",'
+      ' "com.android.nfc.emulatorapduapp")',
+      indent=2,
+  )
   s += create_line(
       'self.emulator.adb.shell(["svc", "nfc", "disable"])', indent=2
   )
@@ -362,12 +382,67 @@ def create_setup():
   s += create_line("self.reader = pn532.PN532(pn532_serial_path)", indent=2)
   s += create_line("self.reader.mute()", indent=2)
   s += create_line()
+
+  s += create_line("self.emulator.nfc_emulator.adoptPermissions()", indent=2)
+
+  if nfc_dump.is_screen_on:
+    s += create_line("self.emulator.nfc_emulator.turnScreenOn()", indent=2)
+  else:
+    s += create_line("self.emulator.nfc_emulator.turnScreenOff()", indent=2)
+
+  s += create_line(
+      "if self.emulator.nfc_emulator.isSecureNfcSupported():", indent=2
+  )
+  if nfc_dump.is_secure_nfc_enabled:
+    s += create_line("self.emulator.nfc_emulator.setSecureNfc(True)", indent=3)
+  else:
+    s += create_line("self.emulator.nfc_emulator.setSecureNfc(False)", indent=3)
+
+  s += create_line(
+      "if self.emulator.nfc_emulator.isReaderOptionSupported():", indent=2
+  )
+  if nfc_dump.is_reader_option_enabled:
+    s += create_line(
+        "self.emulator.nfc_emulator.setReaderOption(True)", indent=3
+    )
+  else:
+    s += create_line(
+        "self.emulator.nfc_emulator.setReaderOption(False)", indent=3
+    )
+
+  s += create_line(
+      "if self.emulator.nfc_emulator.isControllerAlwaysOnSupported():", indent=2
+  )
+  if nfc_dump.is_always_on_supported:
+    s += create_line(
+        "self.emulator.nfc_emulator.setControllerAlwaysOn(True)", indent=3
+    )
+  else:
+    s += create_line(
+        "self.emulator.nfc_emulator.setControllerAlwaysOn(False)", indent=3
+    )
+
+  if nfc_dump.is_observe_mode_supported:
+    s += create_line(
+        "if self.emulator.nfc_emulator.isObserveModeSupported():", indent=2
+    )
+    if nfc_dump.is_observe_mode_enabled:
+      s += create_line(
+          "self.emulator.nfc_emulator.setObserveMode(True)", indent=3
+      )
+    else:
+      s += create_line(
+          "self.emulator.nfc_emulator.setObserveMode(False)", indent=3
+      )
+
+  s += create_line()
   return s
 
 
 def create_teardown_test():
   s = create_line("def teardown_test(self):", indent=1)
   s += create_line("self.reader.mute()", indent=2)
+  s += create_line("self.emulator.nfc_emulator.dropPermissions()", indent=2)
   return s
 
 
diff --git a/NfcNci/testutils/nfcreplay.py b/NfcNci/testutils/nfcreplay.py
index 3fb55fcad..879602aee 100644
--- a/NfcNci/testutils/nfcreplay.py
+++ b/NfcNci/testutils/nfcreplay.py
@@ -47,7 +47,7 @@ _ERROR_STR = "     ERROR: {}"
 _COLUMN_WIDTH = 80
 
 # Directory for generated test cases and files for the emulator app.
-_EMULATOR_APP_PARSED_DIR = "src/com/android/nfc/emulatorapp/parsed_files/"
+_EMULATOR_APP_PARSED_DIR = "tests/testcases/hostsidetests/src/com/android/nfc/emulatorapduapp/parsed_files/"
 
 
 def send_nfc_a_data(reader: PN532) -> str | None:
@@ -178,8 +178,8 @@ def replay_transaction(log, module_path: str):
   reader.mute()
 
 
-def parse_snoop_log(args: argparse.Namespace):
-  """Parses the given snoop log file.
+def parse_bug_report(args: argparse.Namespace):
+  """Parses the given bug report.
 
   If the file will be used for replaying a transaction with the emulator app,
   the AIDs will be replaced with the ones used by the app. Additionally, if the
@@ -187,18 +187,18 @@ def parse_snoop_log(args: argparse.Namespace):
   transactions that fall within that timeframe.
 
   Args:
-    snoop_file: The local path to the snoop log file.
+    bug_report_file: The local path to the bug report file.
 
   Returns:
-    The parsed snoop log.
+    Device properties, parsed snoop log
   """
-  parsed = open_and_parse_file(args.file)
+  dump, parsed = open_and_parse_file(args.file)
 
   # replace the AIDs with the ones used by the emulator app
   if args.replay_with_app or args.parse_only:
     parsed = replace_aids(parsed)
 
-  return parse_timeframe(parsed, args.start, args.end)
+  return dump, parse_timeframe(parsed, args.start, args.end)
 
 
 def output_line_for_snoop_log(
@@ -236,7 +236,7 @@ def print_opening_sequence(
     start: str | None = None,
     end: str | None = None,
 ):
-  """Prints the opening sequence for a test case or snoop log.
+  """Prints the opening sequence for a test case or bug report.
 
   The name of the file to be replayed is displayed, along with the timeframe
   that will be replayed, if specified by the user.
@@ -247,7 +247,7 @@ def print_opening_sequence(
     end: The end of the timeframe to be replayed.
   """
   print()
-  print("Replaying transaction from snoop log: {}".format(file_name))
+  print("Replaying transaction from bug report: {}".format(file_name))
   if start is not None and end is not None:
     print("Timeframe: {} - {}".format(start, end))
   elif start is not None:
@@ -270,10 +270,11 @@ def create_file_for_emulator_app(
     output: A list of polling loop entries and APDU exchanges parsed from the
       snoop log.
     filename: The name of the file to be created. This is near-identical to the
-      name of the snoop log file.
+      name of the bug report file.
   """
   local_path = _EMULATOR_APP_PARSED_DIR + filename.replace("/", "_")
-  full_path = os.path.dirname(os.path.realpath(__file__)) + "/" + local_path
+  full_path = os.path.dirname(os.path.realpath(__file__)).replace("testutils", "") + local_path
+
   try:
     file = open(full_path, "wt")
   except Exception as e:
@@ -310,7 +311,7 @@ def main():
       "--file",
       action="store",
       required=True,
-      help="Path to the file of the snoop log",
+      help="Path to the file of the bug report",
   )
   parser.add_argument(
       "--start",
@@ -339,7 +340,7 @@ def main():
   )
   args = parser.parse_args()
 
-  parsed_snoop_log = parse_snoop_log(args)
+  nfc_dump, parsed_snoop_log = parse_bug_report(args)
   if args.parse_only:  # scenario 1: parse snoop log for the emulator app
     create_file_for_emulator_app(parsed_snoop_log, args.file)
   else:  # scenario 2: replay transaction from a snoop log
@@ -350,7 +351,9 @@ def main():
     )
     if args.generate_and_replay_test:  # Replay the test that was just generated
       test_case_name = get_name_for_test_case(args.file)
-      apdu_local_file = generate_test(parsed_snoop_log, test_case_name)
+      apdu_local_file = generate_test(
+          parsed_snoop_log, test_case_name, nfc_dump
+      )
       test_command = [
           "atest",
           "-v",
@@ -361,8 +364,6 @@ def main():
           "--testparam",
           "file_path=" + apdu_local_file,
       ]
-      if args.replay_with_app:
-        test_command += ["--testparam", "with_emulator_app=True"]
       subprocess.run(test_command)
     else:  # Default: replay the transaction
       replay_transaction(parsed_snoop_log, args.path)
diff --git a/NfcNci/testutils/parse_log.py b/NfcNci/testutils/parse_log.py
index b299657fd..212ef6763 100644
--- a/NfcNci/testutils/parse_log.py
+++ b/NfcNci/testutils/parse_log.py
@@ -14,7 +14,7 @@
 
 # Lint as: python3
 
-"""Parses the snoop log to extract polling loop data and APDU exchanges."""
+"""Parses the bug report to extract polling loop data and APDU exchanges."""
 
 import base64
 import dataclasses
@@ -25,8 +25,8 @@ import zlib
 
 PREAMBLE_LENGTH = 9
 HEADER_LENGTH = 7
-SNOOP_LOG_START = "BEGIN:NFCSNOOP_"
-SNOOP_LOG_END = "END:NFCSNOOP_"
+SNOOP_LOG_START = "BEGIN:NFCSNOOP_VS_LOG_SUMMARY"
+SNOOP_LOG_END = "END:NFCSNOOP_VS_LOG_SUMMARY"
 
 # Bytes identifying the starts of polling loop and APDU transactions
 POLLING_LOOP_START_BYTES = bytes.fromhex("6f0c")
@@ -66,8 +66,18 @@ APDU_ORDER_SECOND_ALT = bytes([0x0B, 0x00])
 AID_START_BYTES = bytes.fromhex("00A40400")
 
 # AID groups that are used by the emulator app
-SELECT_AID_FIRST = bytes.fromhex("00A4040008A000000151000000")
-SELECT_AID_SECOND = bytes.fromhex("00A4040008A000000003000000")
+SELECT_AID_FIRST = bytes.fromhex("00A4040008A000000004101017")
+SELECT_AID_SECOND = bytes.fromhex("00A4040008A000000004101020")
+
+# parsing device information from NFC dump section
+DUMP_HEADER = "DUMP OF SERVICE nfc:"
+
+SCREEN_STATE_HEADING = "mScreenState="
+SECURE_NFC_HEADING = "mIsSecureNfcEnabled"
+READER_OPTION_HEADING = "mIsReaderOptionEnabled"
+ALWAYS_ON_HEADING = "mIsAlwaysOnSupported"
+OBSERVE_MODE_SUPPORTED_HEADING = "mIsObserveModeSupported"
+OBSERVE_MODE_ENABLED_HEADING = "mIsObserveModeEnabled"
 
 
 class NfcType(enum.Enum):
@@ -106,6 +116,16 @@ class FullApduEntry:
   error: str | None = None
 
 
+@dataclasses.dataclass
+class DumpNfcInfo:
+  is_screen_on: bool = False
+  is_secure_nfc_enabled: bool = False
+  is_reader_option_enabled: bool = False
+  is_always_on_supported: bool = False
+  is_observe_mode_supported: bool = False
+  is_observe_mode_enabled: bool = False
+
+
 def replace_aids(
     log: list[PollingLoopEntry | FullApduEntry],
 ) -> list[PollingLoopEntry | FullApduEntry]:
@@ -234,31 +254,84 @@ def parse_file(data: bytes) -> list[PollingLoopEntry | PartialApduEntry]:
 
 def open_and_parse_file(
     file_path: str,
-) -> list[PollingLoopEntry | FullApduEntry]:
-  """Opens the file that contains the unparsed snoop log and parses it.
+):
+  """Opens the file that contains the unparsed bug report and parses it.
 
   Args:
-    file_path: The path of the file containing the unparsed snoop log.
+    file_path: The path of the file containing the unparsed bug report.
 
   Returns:
-    A list of polling loop entries and APDU exchanges parsed from the file.
+    Device properties, as well as a list of polling loop entries and APDU
+    exchanges parsed from the file.
 
   Raises:
     RuntimeError: If the file cannot be found.
   """
-  snoop_file = open_read_file(file_path)
-  str_data = ""
-  found_log = False
-  while line := snoop_file.readline():
-    if not found_log and SNOOP_LOG_START in line:
-      found_log = True
-    elif found_log:
+  raw_bug_report = open_read_file(file_path)
+  found_snoop_log = False
+  found_dump = False
+  snoop_data = list()
+  cur_snoop_data = ""
+  dump_data = list()
+  while line := raw_bug_report.readline():
+    if not found_dump and DUMP_HEADER in line:
+      found_dump = True
+    elif found_dump:
+      if line == "\n":
+        found_dump = False
+      else:
+        dump_data.append(line)
+
+    if not found_snoop_log and SNOOP_LOG_START in line:
+      found_snoop_log = True
+    elif found_snoop_log:
       if SNOOP_LOG_END in line:
-        break
-      str_data += line
-  snoop_bytes = inflate(base64.b64decode(str_data))
-  parsed = parse_file(snoop_bytes)
-  return standardize_log(parsed)
+        found_snoop_log = False
+        snoop_data.append(cur_snoop_data.replace("\n", ""))
+        cur_snoop_data = ""
+      else:
+        cur_snoop_data += line
+
+  parsed_snoop_log = list()
+  # parse snoop log data
+  for cur_log in snoop_data:
+    snoop_bytes = inflate(base64.b64decode(cur_log))
+    parsed_snoop_log.extend(parse_file(snoop_bytes))
+
+  # parse dump data
+  dump_nfc_info = parse_dump_data(dump_data)
+
+  return dump_nfc_info, standardize_log(parsed_snoop_log)
+
+
+def parse_dump_data(data: list[str]) -> DumpNfcInfo:
+  dump_nfc_info = DumpNfcInfo()
+  for entry in data:
+    if entry.startswith(SCREEN_STATE_HEADING):
+      if "ON_" in entry:
+        dump_nfc_info.is_screen_on = True
+      continue
+    if entry.startswith(SECURE_NFC_HEADING):
+      if "true" in entry:
+        dump_nfc_info.is_secure_nfc_enabled = True
+      continue
+    if entry.startswith(READER_OPTION_HEADING):
+      if "true" in entry:
+        dump_nfc_info.is_reader_option_enabled = True
+      continue
+    if entry.startswith(ALWAYS_ON_HEADING):
+      if "true" in entry:
+        dump_nfc_info.is_always_on_supported = True
+      continue
+    if entry.startswith(OBSERVE_MODE_SUPPORTED_HEADING):
+      if "true" in entry:
+        dump_nfc_info.is_observe_mode_supported = True
+      continue
+    if entry.startswith(OBSERVE_MODE_ENABLED_HEADING):
+      if "true" in entry:
+        dump_nfc_info.is_observe_mode_enabled = True
+      continue
+  return dump_nfc_info
 
 
 def find_apdu_transactions(data: bytes, ts: int) -> list[PartialApduEntry]:
diff --git a/NfcNci/testutils/pn532/nfcutils/polling_frame_utils.py b/NfcNci/testutils/pn532/nfcutils/polling_frame_utils.py
index c90a21574..064483b18 100644
--- a/NfcNci/testutils/pn532/nfcutils/polling_frame_utils.py
+++ b/NfcNci/testutils/pn532/nfcutils/polling_frame_utils.py
@@ -162,10 +162,6 @@ _B_NOCRC = TransceiveConfiguration(
 _F = TransceiveConfiguration(
     type="F", crc=True, bits=8, bitrate=212, timeout=_F_TIMEOUT
 )
-_F_424 = TransceiveConfiguration(
-    type="F", crc=True, bits=8, bitrate=424, timeout=_F_TIMEOUT
-)
-
 
 # Possible polling frame configurations
 # 1) Frames with special meaning like wakeup/request:
@@ -306,11 +302,6 @@ POLLING_FRAMES_TYPE_F_SPECIAL = [
     PollingFrameTestCase(_F, "00ffff0001", ["F"]),
     #   SENSF_REQ, SC, 0x0003, RC 0x00, TS 0x02 (4)
     PollingFrameTestCase(_F, "0000030002", ["F"]),
-    # 2) 424 kbps
-    #   SENSF_REQ, SC, 0xffff
-    PollingFrameTestCase(_F_424, "00ffff0100", ["F"]),
-    #   SENSF_REQ, SC, 0x0003
-    PollingFrameTestCase(_F_424, "00ffff0100", ["F"]),
 ]
 
 POLLING_FRAME_ALL_TEST_CASES = [
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/AccessServiceTurnObserveModeOnProcessApduEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/AccessServiceTurnObserveModeOnProcessApduEmulatorActivity.java
index d57278714..2be0d33e7 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/AccessServiceTurnObserveModeOnProcessApduEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/AccessServiceTurnObserveModeOnProcessApduEmulatorActivity.java
@@ -25,6 +25,7 @@ public class AccessServiceTurnObserveModeOnProcessApduEmulatorActivity
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
+        setupServices(AccessServiceTurnObserveModeOnProcessApdu.COMPONENT);
     }
 
     @Override
@@ -37,11 +38,6 @@ public class AccessServiceTurnObserveModeOnProcessApduEmulatorActivity
     @Override
     protected void onResume() {
         super.onResume();
-        setupServices(AccessServiceTurnObserveModeOnProcessApdu.COMPONENT);
-    }
-
-    @Override
-    protected void onServicesSetup() {
         mCardEmulation.setPreferredService(
                 this, AccessServiceTurnObserveModeOnProcessApdu.COMPONENT);
     }
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/BaseEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/BaseEmulatorActivity.java
index da31afe97..e45d1f7e7 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/BaseEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/BaseEmulatorActivity.java
@@ -55,6 +55,13 @@ public abstract class BaseEmulatorActivity extends Activity {
 
     // Intent action that's sent after the test condition is met.
     protected static final String ACTION_TEST_PASSED = PACKAGE_NAME + ".ACTION_TEST_PASSED";
+    protected static final String ACTION_OFFHOST_AID_SELECTED =
+            PACKAGE_NAME + ".ACTION_OFFHOST_AID_SELECTED";
+    protected static final String EXTRA_OFFHOST_AID_SELECTED_AID =
+            PACKAGE_NAME + ".EXTRA_OFFHOST_AID_SELECTED_AID";
+    protected static final String EXTRA_OFFHOST_AID_SELECTED_SE =
+            PACKAGE_NAME + ".EXTRA_OFFHOST_AID_SELECTED_SE";
+
     protected static final String TAG = "BaseEmulatorActivity";
     protected NfcAdapter mAdapter;
     protected CardEmulation mCardEmulation;
@@ -82,7 +89,7 @@ public abstract class BaseEmulatorActivity extends Activity {
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
-        Log.d(TAG, "onCreate");
+
         mAdapter = NfcAdapter.getDefaultAdapter(this);
         mCardEmulation = CardEmulation.getInstance(mAdapter);
         mRoleManager = getSystemService(RoleManager.class);
@@ -98,11 +105,6 @@ public abstract class BaseEmulatorActivity extends Activity {
         }
     }
 
-    @Override
-    protected void onResume() {
-        super.onResume();
-    }
-
     @Override
     protected void onDestroy() {
         super.onDestroy();
@@ -243,6 +245,10 @@ public abstract class BaseEmulatorActivity extends Activity {
         onServicesSetup();
     }
 
+    public List<String> getAidsForService(ComponentName componentName) {
+        return mCardEmulation.getAidsForService(componentName, CardEmulation.CATEGORY_PAYMENT);
+    }
+
     /** Executed after services are set up */
     protected void onServicesSetup() {}
 
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/ConflictingNonPaymentPrefixEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/ConflictingNonPaymentPrefixEmulatorActivity.java
index 46214a684..1a88d9516 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/ConflictingNonPaymentPrefixEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/ConflictingNonPaymentPrefixEmulatorActivity.java
@@ -41,7 +41,6 @@ public class ConflictingNonPaymentPrefixEmulatorActivity extends BaseEmulatorAct
         super.onCreate(savedInstanceState);
         setupServices(
                 PrefixTransportService1.COMPONENT, PrefixTransportService2.COMPONENT);
-
         registerEventListener(mEventListener);
     }
 
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/DualNonPaymentPrefixEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/DualNonPaymentPrefixEmulatorActivity.java
index 5276fb6ff..0408fb53d 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/DualNonPaymentPrefixEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/DualNonPaymentPrefixEmulatorActivity.java
@@ -32,7 +32,6 @@ public class DualNonPaymentPrefixEmulatorActivity extends BaseEmulatorActivity {
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
-        Log.d(TAG, "onCreate");
         setupServices(PrefixTransportService1.COMPONENT, PrefixAccessService.COMPONENT);
     }
 
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/DynamicAidEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/DynamicAidEmulatorActivity.java
index 80fce0082..1b2b844cb 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/DynamicAidEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/DynamicAidEmulatorActivity.java
@@ -29,11 +29,6 @@ public class DynamicAidEmulatorActivity extends BaseEmulatorActivity {
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
-    }
-
-    @Override
-    protected void onResume() {
-        super.onResume();
         setupServices(PaymentServiceDynamicAids.COMPONENT);
     }
 
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/EventListenerEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/EventListenerEmulatorActivity.java
index 74621b6f9..870b164fd 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/EventListenerEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/EventListenerEmulatorActivity.java
@@ -52,7 +52,6 @@ public class EventListenerEmulatorActivity extends BaseEmulatorActivity {
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
-
         setupServices(TransportService1.COMPONENT);
     }
 
@@ -70,7 +69,6 @@ public class EventListenerEmulatorActivity extends BaseEmulatorActivity {
     @Override
     public void onPause() {
         super.onPause();
-
         mCardEmulation.unregisterNfcEventCallback(mEventListener);
         mCardEmulation.unsetPreferredService(this);
     }
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/LargeNumAidsEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/LargeNumAidsEmulatorActivity.java
index 612886087..2ac18cc28 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/LargeNumAidsEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/LargeNumAidsEmulatorActivity.java
@@ -28,8 +28,14 @@ public class LargeNumAidsEmulatorActivity extends BaseEmulatorActivity {
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
+        setupServices(LargeNumAidsService.COMPONENT);
     }
 
+    @Override
+    public void onResume() {
+        super.onResume();
+        mCardEmulation.setPreferredService(this, LargeNumAidsService.COMPONENT);
+    }
     @Override
     public void onApduSequenceComplete(ComponentName component, long duration) {
         if (component.equals(LargeNumAidsService.COMPONENT)) {
@@ -37,12 +43,6 @@ public class LargeNumAidsEmulatorActivity extends BaseEmulatorActivity {
         }
     }
 
-    @Override
-    protected void onResume() {
-        super.onResume();
-        setupServices(LargeNumAidsService.COMPONENT);
-    }
-
     @Override
     protected void onServicesSetup() {
         ArrayList<String> aids = new ArrayList<String>();
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/NfcEmulatorDeviceSnippet.java b/NfcNci/testutils/src/com/android/nfc/emulator/NfcEmulatorDeviceSnippet.java
index 18dfa8c51..a523bf06e 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/NfcEmulatorDeviceSnippet.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/NfcEmulatorDeviceSnippet.java
@@ -513,6 +513,12 @@ public class NfcEmulatorDeviceSnippet extends NfcSnippet {
                 AccessServiceTurnObserveModeOnProcessApdu.OBSERVE_MODE_FALSE);
     }
 
+    @AsyncRpc(description = "Waits for off host aid selected event")
+    public void asyncWaitForOffHostAidSelected(String callbackId, String eventName) {
+        registerSnippetBroadcastReceiver(
+                callbackId, eventName, BaseEmulatorActivity.ACTION_OFFHOST_AID_SELECTED);
+    }
+
     /** Sets the listen tech for the active emulator activity */
     @Rpc(description = "Set the listen tech for the emulator")
     public void setListenTech(Integer listenTech) {
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/OffHostEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/OffHostEmulatorActivity.java
index 64dff2355..a73ef20e7 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/OffHostEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/OffHostEmulatorActivity.java
@@ -16,7 +16,10 @@
 package com.android.nfc.emulator;
 
 import android.content.ComponentName;
+import android.content.Intent;
+import android.nfc.cardemulation.CardEmulation;
 import android.os.Bundle;
+import android.util.Log;
 
 import com.android.nfc.service.OffHostService;
 import com.android.nfc.service.PollingLoopService;
@@ -24,6 +27,21 @@ import com.android.nfc.service.PollingLoopService;
 public class OffHostEmulatorActivity extends BaseEmulatorActivity {
     public static final String EXTRA_ENABLE_OBSERVE_MODE = "EXTRA_ENABLE_OBSERVE_MODE";
 
+    private CardEmulation.NfcEventCallback mEventListener = new CardEmulation.NfcEventCallback() {
+        @Override
+        public void onOffHostAidSelected(String aid, String offHostSe) {
+            Log.d(TAG, "onOffHostAidSelected: " + aid + ", " + offHostSe);
+            if (getAidsForService(OffHostService.COMPONENT).contains(aid)) {
+                Intent intent = new Intent(BaseEmulatorActivity.ACTION_OFFHOST_AID_SELECTED);
+                intent.putExtra(EXTRA_OFFHOST_AID_SELECTED_AID, aid);
+                intent.putExtra(EXTRA_OFFHOST_AID_SELECTED_SE, offHostSe);
+                sendBroadcast(intent);
+            } else {
+                Log.e(TAG, "Unknown AID detected in offHostAidSelected callback");
+            }
+        }
+    };
+
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
@@ -33,7 +51,7 @@ public class OffHostEmulatorActivity extends BaseEmulatorActivity {
     @Override
     protected void onResume() {
         super.onResume();
-
+        registerEventListener(mEventListener);
         if (getIntent().getBooleanExtra(EXTRA_ENABLE_OBSERVE_MODE, false)) {
             // Still need to set a preferred service to be able to set observe mode.
             mCardEmulation.setPreferredService(
@@ -45,6 +63,7 @@ public class OffHostEmulatorActivity extends BaseEmulatorActivity {
     @Override
     public void onPause() {
         super.onPause();
+        mCardEmulation.unregisterNfcEventCallback(mEventListener);
         if (getIntent().getBooleanExtra(EXTRA_ENABLE_OBSERVE_MODE, false)) {
             mCardEmulation.unsetPreferredService(this);
             mAdapter.setObserveModeEnabled(false);
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/PollingLoopEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/PollingLoopEmulatorActivity.java
index d320a510f..9025e997f 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/PollingLoopEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/PollingLoopEmulatorActivity.java
@@ -66,6 +66,7 @@ public class PollingLoopEmulatorActivity extends BaseEmulatorActivity {
     @Override
     protected void onResume() {
         super.onResume();
+
         IntentFilter filter = new IntentFilter(PollingLoopService.POLLING_FRAME_ACTION);
         registerReceiver(mFieldStateReceiver, filter, RECEIVER_EXPORTED);
         mNfcTech = getIntent().getIntExtra(NFC_TECH_KEY, NfcAdapter.FLAG_READER_NFC_A);
@@ -102,7 +103,6 @@ public class PollingLoopEmulatorActivity extends BaseEmulatorActivity {
     @Override
     public void onPause() {
         super.onPause();
-        Log.e(TAG, "onPause");
         unregisterReceiver(mFieldStateReceiver);
         mCardEmulation.unsetPreferredService(this);
     }
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/PrefixPaymentEmulator2Activity.java b/NfcNci/testutils/src/com/android/nfc/emulator/PrefixPaymentEmulator2Activity.java
index 1da181978..528b6dc3d 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/PrefixPaymentEmulator2Activity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/PrefixPaymentEmulator2Activity.java
@@ -16,6 +16,7 @@
 package com.android.nfc.emulator;
 
 import android.content.ComponentName;
+import android.os.Bundle;
 
 import com.android.nfc.service.PrefixPaymentService1;
 import com.android.nfc.service.PrefixPaymentService2;
@@ -28,8 +29,8 @@ public class PrefixPaymentEmulator2Activity extends BaseEmulatorActivity {
     private int mState = STATE_IDLE;
 
     @Override
-    protected void onResume() {
-        super.onResume();
+    protected void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
         mState = STATE_SERVICE2_SETTING_UP;
         setupServices(PrefixPaymentService2.COMPONENT);
     }
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/PrefixPaymentEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/PrefixPaymentEmulatorActivity.java
index 00dc51cca..c8b036f23 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/PrefixPaymentEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/PrefixPaymentEmulatorActivity.java
@@ -31,11 +31,6 @@ public class PrefixPaymentEmulatorActivity extends BaseEmulatorActivity {
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
-    }
-
-    @Override
-    protected void onResume() {
-        super.onResume();
         mState = STATE_SERVICE1_SETTING_UP;
         setupServices(PrefixPaymentService1.COMPONENT);
     }
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/ScreenOffPaymentEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/ScreenOffPaymentEmulatorActivity.java
index 7b65bcdd6..1657481d0 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/ScreenOffPaymentEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/ScreenOffPaymentEmulatorActivity.java
@@ -55,11 +55,6 @@ public class ScreenOffPaymentEmulatorActivity extends BaseEmulatorActivity {
         registerReceiver(mScreenOnOffReceiver, filter, RECEIVER_EXPORTED);
     }
 
-    @Override
-    protected void onResume() {
-        super.onResume();
-    }
-
     @Override
     protected void onDestroy() {
         super.onDestroy();
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/SimpleEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/SimpleEmulatorActivity.java
index 5809a9d72..01eaacb9c 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/SimpleEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/SimpleEmulatorActivity.java
@@ -16,6 +16,7 @@
 package com.android.nfc.emulator;
 
 import android.content.ComponentName;
+import android.os.Bundle;
 
 import java.util.List;
 import java.util.Objects;
@@ -32,9 +33,8 @@ public class SimpleEmulatorActivity extends BaseEmulatorActivity {
     private ComponentName mPreferredService = null;
 
     @Override
-    protected void onResume() {
-        super.onResume();
-
+    protected void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
         List<ComponentName> components =
                 getIntent().getExtras().getParcelableArrayList(EXTRA_SERVICES, ComponentName.class);
         if (components != null) {
@@ -44,10 +44,13 @@ public class SimpleEmulatorActivity extends BaseEmulatorActivity {
         if (getIntent().getBooleanExtra(EXTRA_IS_PAYMENT_ACTIVITY, false)) {
             makeDefaultWalletRoleHolder();
         }
+    }
 
+    @Override
+    protected void onResume() {
+        super.onResume();
         mPreferredService =
                 getIntent().getExtras().getParcelable(EXTRA_PREFERRED_SERVICE, ComponentName.class);
-
         if (mPreferredService != null) {
             mCardEmulation.setPreferredService(this, mPreferredService);
         }
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/ThroughputEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/ThroughputEmulatorActivity.java
index ac1abcb37..aae7780f7 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/ThroughputEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/ThroughputEmulatorActivity.java
@@ -29,12 +29,6 @@ public class ThroughputEmulatorActivity extends BaseEmulatorActivity {
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
-    }
-
-    @Override
-    protected void onResume() {
-        super.onResume();
-        Log.d(TAG, "onResume");
         setupServices(ThroughputService.COMPONENT);
     }
 
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/TwoPollingFrameEmulatorActivity.java b/NfcNci/testutils/src/com/android/nfc/emulator/TwoPollingFrameEmulatorActivity.java
index 1c6fe69e7..2b6aa3627 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/TwoPollingFrameEmulatorActivity.java
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/TwoPollingFrameEmulatorActivity.java
@@ -72,7 +72,7 @@ public class TwoPollingFrameEmulatorActivity extends BaseEmulatorActivity {
     @Override
     public void onPause() {
         super.onPause();
-        Log.e(TAG, "onPause");
+        Log.d(TAG, "onPause");
         unregisterReceiver(mFieldStateReceiver);
         mCardEmulation.unsetPreferredService(this);
     }
diff --git a/NfcNci/testutils/src/com/android/nfc/emulator/res/xml/offhost_aid_list.xml b/NfcNci/testutils/src/com/android/nfc/emulator/res/xml/offhost_aid_list.xml
index ff0a1030a..6d44612b3 100644
--- a/NfcNci/testutils/src/com/android/nfc/emulator/res/xml/offhost_aid_list.xml
+++ b/NfcNci/testutils/src/com/android/nfc/emulator/res/xml/offhost_aid_list.xml
@@ -1,5 +1,6 @@
 <offhost-apdu-service xmlns:android="http://schemas.android.com/apk/res/android"
-    android:description="@string/offhostService">
+    android:description="@string/offhostService"
+    android:secureElementName="eSE">
     <aid-group>
         <!-- OBTH card manager AID -->
         <aid-filter android:name="A000000151000000"/>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/NfcApduDeviceSnippet.kt b/NfcNci/testutils/src/com/android/nfc/emulatorapp/NfcApduDeviceSnippet.kt
deleted file mode 100644
index c959a9caa..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/NfcApduDeviceSnippet.kt
+++ /dev/null
@@ -1,44 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.nfc.emulatorapp
-
-import android.app.Instrumentation
-import android.content.Intent
-import androidx.test.platform.app.InstrumentationRegistry
-import com.android.nfc.utils.NfcSnippet
-import com.google.android.mobly.snippet.rpc.Rpc;
-
-class NfcApduDeviceSnippet : NfcSnippet() {
-  private lateinit var mActivity: MainActivity
-
-  @Rpc(description = "Start Main Activity")
-  fun startMainActivity(json: String) {
-    val instrumentation: Instrumentation = InstrumentationRegistry.getInstrumentation()
-    val intent = Intent(Intent.ACTION_MAIN)
-    intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
-    intent.setClassName(
-            instrumentation.getTargetContext(), MainActivity::class.java.getName())
-    intent.putExtra(MainActivity.SNOOP_DATA_FLAG, json)
-
-    mActivity = instrumentation.startActivitySync(intent) as MainActivity
-  }
-
-  @Rpc(description = "Close activity")
-  fun closeActivity() {
-    mActivity.finish()
-  }
-}
\ No newline at end of file
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-af/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-af/strings.xml
deleted file mode 100644
index 2867c0d84..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-af/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay-app"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Begin Host APDU-diens"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Herspeel tans lêer:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transaksieloglêer:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-am/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-am/strings.xml
deleted file mode 100644
index 58267b525..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-am/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"የNFC Replay App"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"የአስተናጋጅ APDU አገልግሎት ጀምር"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ፋይልን እንደገና በማጫወት ላይ፦"</string>
-    <string name="log_text" msgid="5517852408962406645">"የግብይት ምዝግብ ማስታወሻ፦"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ar/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ar/strings.xml
deleted file mode 100644
index a41a6b3d4..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ar/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"‏تطبيق \"استخدام NFC تلقائيًا\""</string>
-    <string name="service_button_text" msgid="5013402864802312301">"‏بدء خدمة APDU للمضيف"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ملف البيانات المُعاد استخدامها:"</string>
-    <string name="log_text" msgid="5517852408962406645">"سجلّ المعاملات:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-as/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-as/strings.xml
deleted file mode 100644
index 1927c1bbd..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-as/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay এপ্"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"হ’ষ্ট APDU সেৱা আৰম্ভ কৰক"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"পুনৰ প্লে’ কৰা ফাইল:"</string>
-    <string name="log_text" msgid="5517852408962406645">"লেনদেনৰ লগ:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-az/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-az/strings.xml
deleted file mode 100644
index 314baa6e7..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-az/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay tətbiqi"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU xidmətini işə salın"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Fayl yenidən işə salınır:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Tranzaksiya jurnalı:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-b+sr+Latn/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-b+sr+Latn/strings.xml
deleted file mode 100644
index 93a95b1e1..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-b+sr+Latn/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplikacija NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Pokreni Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Ponovo se pušta fajl:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Evidencija transakcija:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-be/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-be/strings.xml
deleted file mode 100644
index fc098aa4d..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-be/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Праграма NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Запусціць сэрвіс Host APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Паўторнае прайграванне файла:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Журнал трансакцый:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-bg/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-bg/strings.xml
deleted file mode 100644
index 5eca63feb..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-bg/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Приложение NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Стартиране на услугата за хостване на APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Повторно пускане на файла:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Регистрационен файл за транзакциите:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-bn/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-bn/strings.xml
deleted file mode 100644
index cf0ec2a79..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-bn/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay অ্যাপ"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU সার্ভিস শুরু করুন"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ফাইল আবার চালু করা হচ্ছে:"</string>
-    <string name="log_text" msgid="5517852408962406645">"ট্রানজ্যাকশন লগ:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-bs/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-bs/strings.xml
deleted file mode 100644
index bc46df815..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-bs/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay App"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Pokreni HostApduService"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Ponovna reprodukcija fajla:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Zapisnik transakcije:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ca/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ca/strings.xml
deleted file mode 100644
index 63169280b..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ca/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplicació NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Inicia el servei APDU d\'amfitrió"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"S\'està tornant a reproduir el fitxer:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Registre de transaccions:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-cs/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-cs/strings.xml
deleted file mode 100644
index b38da4656..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-cs/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplikace NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Spustit službu Host APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Přehrávání souboru:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Protokol transakcí:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-da/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-da/strings.xml
deleted file mode 100644
index 2493beaaf..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-da/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Appen NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Start Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Filen, der afspilles igen:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transaktionslog:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-de/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-de/strings.xml
deleted file mode 100644
index 57b6768de..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-de/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay App"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"HostApduService starten"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Datei, die noch einmal abgespielt wird:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transaktionsprotokoll:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-el/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-el/strings.xml
deleted file mode 100644
index ab40db49c..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-el/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Εφαρμογή NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Έναρξη υπηρεσίας Host APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Επανάληψη αρχείου:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Αρχείο καταγραφής συναλλαγών:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rAU/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rAU/strings.xml
deleted file mode 100644
index 77951db7f..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rAU/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay app"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Start host APDU service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Replaying file:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transaction log:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rCA/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rCA/strings.xml
deleted file mode 100644
index bd26ed6ee..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rCA/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay App"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Start Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Replaying File:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transaction Log:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rGB/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rGB/strings.xml
deleted file mode 100644
index 77951db7f..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rGB/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay app"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Start host APDU service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Replaying file:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transaction log:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rIN/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rIN/strings.xml
deleted file mode 100644
index 77951db7f..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-en-rIN/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay app"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Start host APDU service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Replaying file:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transaction log:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-es-rUS/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-es-rUS/strings.xml
deleted file mode 100644
index 193405aac..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-es-rUS/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"App de repetición de NFC"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Iniciar el servicio de APDU del host"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Volviendo a reproducir el archivo:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Registro de transacciones:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-es/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-es/strings.xml
deleted file mode 100644
index a38f7eca9..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-es/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplicación NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Iniciar servicio APDU de host"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Volviendo a reproducir el archivo:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Registro de transacción:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-et/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-et/strings.xml
deleted file mode 100644
index c466760c2..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-et/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Rakendus NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Käivita Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Faili taasesitus:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Tehingu logi:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-eu/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-eu/strings.xml
deleted file mode 100644
index f8418983b..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-eu/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay aplikazioa"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Abiarazi APDU zerbitzu ostalaria"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Berriro erreproduzitzen ari den fitxategia:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transakzioen erregistroa:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fa/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fa/strings.xml
deleted file mode 100644
index 7995e329a..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fa/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"‏برنامه بازپخش NFC"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"‏راه‌انداختن سرویس APDU میزبان"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"درحال بازپخش فایل:"</string>
-    <string name="log_text" msgid="5517852408962406645">"گزارش تراکنش:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fi/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fi/strings.xml
deleted file mode 100644
index ca4365f60..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fi/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay -sovellus"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Käynnistä isännän APDU-palvelu"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Toistetaan tiedostoa:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Tapahtumaloki:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fr-rCA/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fr-rCA/strings.xml
deleted file mode 100644
index 2f060906a..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fr-rCA/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Appli NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Démarrer Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Relecture du fichier :"</string>
-    <string name="log_text" msgid="5517852408962406645">"Journal des transactions :"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fr/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fr/strings.xml
deleted file mode 100644
index 67b54bfa4..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-fr/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Appli NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Démarrer Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Nouvelle lecture du fichier :"</string>
-    <string name="log_text" msgid="5517852408962406645">"Journal des transactions :"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-gl/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-gl/strings.xml
deleted file mode 100644
index 04dc8a2e2..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-gl/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplicación NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Iniciar servizo APDU do host"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Reproducindo ficheiro de novo:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Rexistro das transaccións:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-gu/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-gu/strings.xml
deleted file mode 100644
index 345d8e830..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-gu/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay ઍપ"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"હોસ્ટ APDU સેવા ચાલુ કરો"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ફાઇલને ફરીથી ચલાવી રહ્યાં છીએ:"</string>
-    <string name="log_text" msgid="5517852408962406645">"વ્યવહારનો લૉગ:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hi/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hi/strings.xml
deleted file mode 100644
index 4fbc3f7f5..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hi/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay ऐप्लिकेशन"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"होस्ट एपीडीयू सर्विस को चालू करें"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"फ़ाइल को फिर से चलाया जा रहा है:"</string>
-    <string name="log_text" msgid="5517852408962406645">"लेन-देन की जानकारी:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hr/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hr/strings.xml
deleted file mode 100644
index 64a6a75b2..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hr/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplikacija NCF Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Pokreni Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Reproduciranje datoteke:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Zapisnik transakcija:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hu/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hu/strings.xml
deleted file mode 100644
index 051b62484..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hu/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay App"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU szolgáltatás indítása"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Fájl újrajátszása:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Tranzakciónapló:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hy/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hy/strings.xml
deleted file mode 100644
index 7f3b23feb..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-hy/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay հավելված"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Գործարկել Host APDU ծառայությունը"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Վերարտադրվող ֆայլ՝"</string>
-    <string name="log_text" msgid="5517852408962406645">"Գործարքների մատյան՝"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-in/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-in/strings.xml
deleted file mode 100644
index 11ee00d1d..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-in/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplikasi NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Mulai Layanan Host APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Memutar Ulang File:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Log Transaksi:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-is/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-is/strings.xml
deleted file mode 100644
index f0122097a..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-is/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Forritið NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Virkja APDU-hýsilþjónustu"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Skrá sem er spiluð aftur:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Færsluannáll:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-it/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-it/strings.xml
deleted file mode 100644
index d75742fb2..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-it/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"App NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Avvia servizio APDU host"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Ripetizione del file in corso:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Log di transazione:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-iw/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-iw/strings.xml
deleted file mode 100644
index 395355918..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-iw/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"‏אפליקציית NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"‏הפעלת שירות Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"הקובץ שיופעל מחדש:"</string>
-    <string name="log_text" msgid="5517852408962406645">"יומן הטרנזקציות:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ja/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ja/strings.xml
deleted file mode 100644
index 83b430034..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ja/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay アプリ"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU サービスを開始"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"再生しているファイル:"</string>
-    <string name="log_text" msgid="5517852408962406645">"トランザクション ログ:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ka/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ka/strings.xml
deleted file mode 100644
index 5b7219c6a..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ka/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay აპი"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU მომსახურების დაწყება"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ხელახლა დაკრული ფაილი:"</string>
-    <string name="log_text" msgid="5517852408962406645">"ტრანზაქციების ჟურნალი:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-kk/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-kk/strings.xml
deleted file mode 100644
index 7d8691414..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-kk/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay қолданбасы"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU Service қызметін іске қосу"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Қайта ойнатылатын файл:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Транзакция журналы:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-km/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-km/strings.xml
deleted file mode 100644
index 2396c40ae..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-km/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"កម្មវិធី NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"ចាប់ផ្ដើមសេវាកម្មម៉ាស៊ីន APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ឯកសារចាក់​​ឡើងវិញ៖"</string>
-    <string name="log_text" msgid="5517852408962406645">"កំណត់​ហេតុប្រតិបត្តិការ៖"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-kn/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-kn/strings.xml
deleted file mode 100644
index 2898478aa..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-kn/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay ಆ್ಯಪ್‌"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"ಹೋಸ್ಟ್‌ APDU ಸೇವೆಯನ್ನು ಪ್ರಾರಂಭಿಸಿ"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ಫೈಲ್‌ ಅನ್ನು ಮರುಪ್ಲೇ ಮಾಡಲಾಗುತ್ತಿದೆ:"</string>
-    <string name="log_text" msgid="5517852408962406645">"ವಹಿವಾಟಿನ ಲಾಗ್‌:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ko/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ko/strings.xml
deleted file mode 100644
index 02dad84d9..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ko/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay 앱"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"호스트 APDU 서비스 시작"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"재생 중인 파일:"</string>
-    <string name="log_text" msgid="5517852408962406645">"트랜잭션 로그:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ky/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ky/strings.xml
deleted file mode 100644
index 99503f2b7..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ky/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay колдонмосу"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU кызматын иштетүү"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Файл кайталанууда:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Транзакциянын таржымалы:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-lo/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-lo/strings.xml
deleted file mode 100644
index f8f261533..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-lo/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"ແອັບ NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"ເລີ່ມບໍລິການໂຮສ APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ການຫຼິ້ນໄຟລ໌ຄືນໃໝ່:"</string>
-    <string name="log_text" msgid="5517852408962406645">"ບັນທຶກທຸລະກຳ:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-lt/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-lt/strings.xml
deleted file mode 100644
index 253b41166..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-lt/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC pakartojimo programa"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Paleisti prieglobos APDU paslaugą"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Pakartojamas failas:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Operacijų žurnalas:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-lv/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-lv/strings.xml
deleted file mode 100644
index 988c4cfb8..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-lv/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Lietotne NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Sākt HostApduService"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Atkārtoti atskaņo failu:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Darījumu žurnāls:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-mk/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-mk/strings.xml
deleted file mode 100644
index 17588d32d..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-mk/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Апликација NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Стартувајте Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Датотеката што се пушта повторно:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Евиденција на трансакцијата:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ml/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ml/strings.xml
deleted file mode 100644
index a991963c4..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ml/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay ആപ്പ്"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU സേവനം ആരംഭിക്കുക"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"വീണ്ടും പ്ലേ ചെയ്യുന്ന ഫയൽ:"</string>
-    <string name="log_text" msgid="5517852408962406645">"ഇടപാട് ലോഗ്:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-mn/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-mn/strings.xml
deleted file mode 100644
index 71dc60131..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-mn/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay апп"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU Service-г эхлүүлэх"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Дахин тоглуулж буй файл:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Гүйлгээний лог:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-mr/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-mr/strings.xml
deleted file mode 100644
index 5a6e45056..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-mr/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay App"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"होस्ट APDU सेवा सुरू करा"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"फाइल रीप्ले करत आहे:"</string>
-    <string name="log_text" msgid="5517852408962406645">"व्यवहाराचा लॉग:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ms/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ms/strings.xml
deleted file mode 100644
index 647590ae8..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ms/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Apl NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Mulakan Perkhidmatan Host APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Memainkan Semula Fail:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Log Transaksi:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-my/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-my/strings.xml
deleted file mode 100644
index 1a8e9ab59..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-my/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay အက်ပ်"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"‘ဆာဗာပင်ရင်း APDU ဝန်ဆောင်မှု’ စတင်ရန်"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ဖိုင်ကို ပြန်ဖွင့်ထားသည်-"</string>
-    <string name="log_text" msgid="5517852408962406645">"ငွေလွှဲပြောင်းမှုမှတ်တမ်း-"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-nb/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-nb/strings.xml
deleted file mode 100644
index 0c6551d5e..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-nb/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay-app"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Start verts-APDU-tjenesten"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Spiller av filen på nytt:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transaksjonslogg:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ne/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ne/strings.xml
deleted file mode 100644
index adba248f4..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ne/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC रिप्ले एप"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"होस्ट APDU सेवा सुरु गर्नुहोस्"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"फाइल रिप्ले गरिँदै छ:"</string>
-    <string name="log_text" msgid="5517852408962406645">"कारोबारको लग:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-nl/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-nl/strings.xml
deleted file mode 100644
index f14cc6b58..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-nl/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay-app"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU-service starten"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Bestand opnieuw afspelen:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transactielogboek:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-or/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-or/strings.xml
deleted file mode 100644
index 6f04f70a7..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-or/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay ଆପ"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"ହୋଷ୍ଟ APDU ସେବା ଆରମ୍ଭ କରନ୍ତୁ"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ଏହି ଫାଇଲକୁ ରିପ୍ଲେ କରାଯାଉଛି:"</string>
-    <string name="log_text" msgid="5517852408962406645">"ଟ୍ରାଞ୍ଜେକ୍ସନ ଲଗ:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pa/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pa/strings.xml
deleted file mode 100644
index bb55bfd8c..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pa/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay ਐਪ"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU ਸੇਵਾ ਸ਼ੁਰੂ ਕਰੋ"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ਫ਼ਾਈਲ ਨੂੰ ਮੁੜ ਚਲਾਉਣਾ:"</string>
-    <string name="log_text" msgid="5517852408962406645">"ਲੈਣ-ਦੇਣ ਸੰਬੰਧੀ ਲੌਗ:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pl/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pl/strings.xml
deleted file mode 100644
index 70ea41e64..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pl/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplikacja NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Uruchom usługę APDU hosta"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Odtwarzam ponownie plik:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Dziennik transakcji:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pt-rPT/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pt-rPT/strings.xml
deleted file mode 100644
index 0c588a988..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pt-rPT/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"App de reprodução NFC"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Iniciar serviço APDU do anfitrião"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"A reproduzir o ficheiro:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Registo de transações:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pt/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pt/strings.xml
deleted file mode 100644
index ef01529e4..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-pt/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"App NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Iniciar serviço APDU do host"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Arquivo de reprodução:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Registro de transação:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ro/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ro/strings.xml
deleted file mode 100644
index 8cfc4a033..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ro/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplicația NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Inițiază Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Se redă din nou fișierul:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Jurnalul tranzacțiilor:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ru/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ru/strings.xml
deleted file mode 100644
index e6ecc9e5d..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ru/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Приложение NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Запустить Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Повторно воспроизводится:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Журнал транзакций:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-si/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-si/strings.xml
deleted file mode 100644
index 58ad0ee71..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-si/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC යළි වාදන යෙදුම"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"සත්කාරක APDU සේවාව ආරම්භ කරන්න"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ගොනුව යළි වාදනය කිරීම:"</string>
-    <string name="log_text" msgid="5517852408962406645">"ගනුදෙනු ලොගය:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sk/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sk/strings.xml
deleted file mode 100644
index 346c19a21..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sk/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplikácia NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Spustiť Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Prehráva sa súbor:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Denník transakcií:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sl/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sl/strings.xml
deleted file mode 100644
index 872f9bc83..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sl/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplikacija NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Zaženi storitev gostitelja APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Vnovično predvajanje datoteke:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Dnevnik transakcij:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sq/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sq/strings.xml
deleted file mode 100644
index d8e7e9132..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sq/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Aplikacioni NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Nis \"Shërbimin APDU të strehimit\""</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Skedari po riluhet:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Evidenca e transaksioneve:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sr/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sr/strings.xml
deleted file mode 100644
index 366f5ce59..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sr/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Апликација NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Покрени Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Поново се пушта фајл:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Евиденција трансакција:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sv/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sv/strings.xml
deleted file mode 100644
index 85e07ed10..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sv/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Appen NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Starta APDU-värdtjänsten"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Spelar upp filen igen:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Transaktionslogg:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sw/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sw/strings.xml
deleted file mode 100644
index fcf3a8f3f..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-sw/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Programu ya Kucheza Tena ya NFC"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Anzisha Huduma ya Host APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Faili ya Kucheza Tena:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Kumbukumbu ya Miamala:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ta/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ta/strings.xml
deleted file mode 100644
index 6f38a07f0..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ta/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay ஆப்ஸ்"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU சேவையைத் தொடங்கு"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"ஃபைலை மீண்டும் இயக்குகிறது:"</string>
-    <string name="log_text" msgid="5517852408962406645">"பரிவர்த்தனைப் பதிவு:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-te/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-te/strings.xml
deleted file mode 100644
index c5b056ed2..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-te/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC రీప్లే యాప్"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"హోస్ట్ APDU సర్వీస్‌ను ప్రారంభించండి"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"మళ్లీ ప్లే చేయబడే ఫైల్:"</string>
-    <string name="log_text" msgid="5517852408962406645">"లావాదేవీ లాగ్:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-th/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-th/strings.xml
deleted file mode 100644
index 397767b8a..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-th/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"แอป NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"เริ่มบริการ Host APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"การเล่นไฟล์ซ้ำ:"</string>
-    <string name="log_text" msgid="5517852408962406645">"บันทึกธุรกรรม:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-tl/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-tl/strings.xml
deleted file mode 100644
index d56edcba1..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-tl/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay App"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Simulan ang Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Nire-replay ang File:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Log ng Transaksyon:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-tr/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-tr/strings.xml
deleted file mode 100644
index 672fa054f..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-tr/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay Uygulaması"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Ana Makine APDU Hizmetini Başlat"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Tekrar Oynatılan Dosya:"</string>
-    <string name="log_text" msgid="5517852408962406645">"İşlem Günlüğü:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-uk/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-uk/strings.xml
deleted file mode 100644
index 3d257f206..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-uk/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Додаток NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Запустити Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Повторне відтворення файлу:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Журнал трансакцій:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ur/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ur/strings.xml
deleted file mode 100644
index ebbfe3582..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-ur/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"‏‫NFC دوبارہ چلائیں ایپ"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"‏‫Host APDU سروس شروع کریں"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"فائل کو دوبارہ چلایا جا رہا ہے:"</string>
-    <string name="log_text" msgid="5517852408962406645">"ٹرانزیکشن لاگ:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-uz/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-uz/strings.xml
deleted file mode 100644
index 9d9590dce..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-uz/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay ilovasi"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Host APDU Service boshlash"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Qayta ijrodagi fayl:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Tranzaksiya jurnali:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-vi/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-vi/strings.xml
deleted file mode 100644
index f9f3389d7..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-vi/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"Ứng dụng NFC Replay"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Khởi động Host APDU Service"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Đang phát lại tệp:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Nhật ký giao dịch:"</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zh-rCN/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zh-rCN/strings.xml
deleted file mode 100644
index edcb5c6b2..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zh-rCN/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC 重放应用"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"启动主机 APDU 服务"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"正在重放文件："</string>
-    <string name="log_text" msgid="5517852408962406645">"事务日志："</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zh-rHK/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zh-rHK/strings.xml
deleted file mode 100644
index 5e5f8d8d6..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zh-rHK/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC Replay 應用程式"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"啟動主機 APDU 服務"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"正在重播檔案："</string>
-    <string name="log_text" msgid="5517852408962406645">"交易記錄："</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zh-rTW/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zh-rTW/strings.xml
deleted file mode 100644
index 40d19ff83..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zh-rTW/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"NFC 重播應用程式"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"啟動主機 APDU 服務"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"正在重播檔案："</string>
-    <string name="log_text" msgid="5517852408962406645">"交易記錄："</string>
-</resources>
diff --git a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zu/strings.xml b/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zu/strings.xml
deleted file mode 100644
index 64467439b..000000000
--- a/NfcNci/testutils/src/com/android/nfc/emulatorapp/res/values-zu/strings.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="2676644544773839281">"I-app Yokudlala Futhi ye-NFC"</string>
-    <string name="service_button_text" msgid="5013402864802312301">"Qala Isevisi Yokusingatha ye-APDU"</string>
-    <string name="replayed_file_text" msgid="2512008003720490850">"Idlala Ifayela Futhi:"</string>
-    <string name="log_text" msgid="5517852408962406645">"Ilogu yethransekshini:"</string>
-</resources>
diff --git a/OWNERS b/OWNERS
index ca7af35bd..5b8022a60 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,4 @@
 # Bug component: 48448
-alisher@google.com
 georgekgchang@google.com
 jackcwyu@google.com
 rpius@google.com
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 000000000..066f314bd
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,18 @@
+{
+  "wear-cts-presubmit": [
+    {
+      "name": "CtsNfcTestCases",
+      "options": [
+       {
+         "include-filter": "android.nfc.cts.CardEmulationTest"
+       },
+       {
+         "include-filter": "android.nfc.cts.NfcFCardEmulationTest"
+       },
+       {
+         "include-filter": "android.nfc.cts.NfcAdapterTest"
+       }
+     ]
+    }
+  ]
+}
diff --git a/apex/Android.bp b/apex/Android.bp
index 8f68fa882..116f7bcaf 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -77,6 +77,10 @@ custom_apex {
         "//build/make/target:__subpackages__",
         "//vendor:__subpackages__",
     ],
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 sdk {
diff --git a/flags/Android.bp b/flags/Android.bp
index 66803ef49..e31721882 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -23,6 +23,7 @@ aconfig_declarations {
     name: "com.android.nfc.module.flags-aconfig",
     package: "com.android.nfc.module.flags",
     container: "com.android.nfcservices",
+    exportable: true,
     srcs: ["*.aconfig"],
 }
 
@@ -39,6 +40,20 @@ java_aconfig_library {
     ],
 }
 
+java_aconfig_library {
+    name: "com.android.nfc.module.flags-aconfig-exported-java",
+    aconfig_declarations: "com.android.nfc.module.flags-aconfig",
+    defaults: ["framework-minus-apex-aconfig-java-defaults"],
+    min_sdk_version: "36",
+    mode: "exported",
+    apex_available: [
+        "com.android.nfcservices",
+    ],
+    visibility: [
+        "//packages/modules/Nfc:__subpackages__",
+    ],
+}
+
 cc_aconfig_library {
     name: "com.android.nfc.module.flags-aconfig-cpp",
     aconfig_declarations: "com.android.nfc.module.flags-aconfig",
diff --git a/flags/flags.aconfig b/flags/flags.aconfig
index 8cc5e2ae7..08a7692dc 100644
--- a/flags/flags.aconfig
+++ b/flags/flags.aconfig
@@ -27,10 +27,50 @@ flag {
     }
 }
 
-
 flag {
     name: "oem_extension_25q4"
+    is_exported: true
     namespace: "nfc"
     description: "OEM extensions for Android 25Q4 release"
     bug: "402346002"
 }
+
+flag {
+    name: "event_listener_offhost_aid_selected"
+    is_exported: true
+    namespace: "nfc"
+    description: "Event listener callback for offhost AID select"
+    bug: "396186563"
+}
+
+flag {
+    name: "get_polling_loop_filters"
+    is_exported: true
+    namespace: "nfc"
+    description: "API to fetch polling loop filters registered for HCE service"
+    bug: "402776679"
+}
+
+flag {
+    name: "ce_wake_lock"
+    is_exported: false
+    namespace: "nfc"
+    description: "Holds a wake lock while CE is in field on state."
+    bug: "406827464"
+}
+
+flag {
+    name: "screen_state_attribute_toggle"
+    is_exported: true
+    namespace: "nfc"
+    description: "API to toggle requireDeviceUnlock and requireDeviceScreenOn attributes for HCE service."
+    bug: "417742419"
+}
+
+flag {
+    name: "nfc_power_saving_mode"
+    is_exported: true
+    namespace: "nfc"
+    description: "API to get and set power saving mode."
+    bug: "311419563"
+}
diff --git a/framework/api/current.txt b/framework/api/current.txt
index 835734b70..c04e3294a 100644
--- a/framework/api/current.txt
+++ b/framework/api/current.txt
@@ -77,6 +77,8 @@ package android.nfc {
     method public boolean isEnabled();
     method public boolean isObserveModeEnabled();
     method public boolean isObserveModeSupported();
+    method @FlaggedApi("com.android.nfc.module.flags.nfc_power_saving_mode") public boolean isPowerSavingModeEnabled();
+    method @FlaggedApi("com.android.nfc.module.flags.nfc_power_saving_mode") public boolean isPowerSavingModeSupported();
     method @FlaggedApi("com.android.nfc.module.flags.reader_mode_annotations") public boolean isReaderModeAnnotationSupported();
     method @FlaggedApi("android.nfc.enable_nfc_reader_option") public boolean isReaderOptionEnabled();
     method @FlaggedApi("android.nfc.enable_nfc_reader_option") public boolean isReaderOptionSupported();
@@ -88,6 +90,7 @@ package android.nfc {
     method @FlaggedApi("android.nfc.enable_nfc_set_discovery_tech") public void resetDiscoveryTechnology(@NonNull android.app.Activity);
     method @FlaggedApi("android.nfc.enable_nfc_set_discovery_tech") public void setDiscoveryTechnology(@NonNull android.app.Activity, int, int);
     method public boolean setObserveModeEnabled(boolean);
+    method @FlaggedApi("com.android.nfc.module.flags.nfc_power_saving_mode") @RequiresPermission(android.Manifest.permission.WRITE_SECURE_SETTINGS) public void setPowerSavingMode(boolean);
     field public static final String ACTION_ADAPTER_STATE_CHANGED = "android.nfc.action.ADAPTER_STATE_CHANGED";
     field @FlaggedApi("android.nfc.nfc_check_tag_intent_preference") public static final String ACTION_CHANGE_TAG_INTENT_PREFERENCE = "android.nfc.action.CHANGE_TAG_INTENT_PREFERENCE";
     field public static final String ACTION_NDEF_DISCOVERED = "android.nfc.action.NDEF_DISCOVERED";
@@ -207,10 +210,14 @@ package android.nfc.cardemulation {
     method @FlaggedApi("android.nfc.enable_card_emulation_euicc") public int getDefaultNfcSubscriptionId();
     method @Nullable @RequiresPermission(android.Manifest.permission.NFC_PREFERRED_PAYMENT_INFO) public CharSequence getDescriptionForPreferredPaymentService();
     method public static android.nfc.cardemulation.CardEmulation getInstance(android.nfc.NfcAdapter);
+    method @FlaggedApi("com.android.nfc.module.flags.get_polling_loop_filters") @NonNull public java.util.List<java.lang.String> getPollingLoopFiltersForService(@NonNull android.content.ComponentName);
+    method @FlaggedApi("com.android.nfc.module.flags.get_polling_loop_filters") @NonNull public java.util.List<java.lang.String> getPollingLoopPatternFiltersForService(@NonNull android.content.ComponentName);
     method @Nullable @RequiresPermission(android.Manifest.permission.NFC_PREFERRED_PAYMENT_INFO) public String getRouteDestinationForPreferredPaymentService();
     method public int getSelectionModeForCategory(String);
     method public boolean isDefaultServiceForAid(android.content.ComponentName, String);
     method public boolean isDefaultServiceForCategory(android.content.ComponentName, String);
+    method @FlaggedApi("com.android.nfc.module.flags.screen_state_attribute_toggle") public boolean isDeviceScreenOnRequiredForService(@NonNull android.content.ComponentName);
+    method @FlaggedApi("com.android.nfc.module.flags.screen_state_attribute_toggle") public boolean isDeviceUnlockRequiredForService(@NonNull android.content.ComponentName);
     method @FlaggedApi("android.nfc.enable_card_emulation_euicc") public boolean isEuiccSupported();
     method public boolean registerAidsForService(android.content.ComponentName, String, java.util.List<java.lang.String>);
     method @FlaggedApi("android.nfc.nfc_event_listener") public void registerNfcEventCallback(@NonNull java.util.concurrent.Executor, @NonNull android.nfc.cardemulation.CardEmulation.NfcEventCallback);
@@ -221,6 +228,8 @@ package android.nfc.cardemulation {
     method public boolean removePollingLoopPatternFilterForService(@NonNull android.content.ComponentName, @NonNull String);
     method @NonNull @RequiresPermission(android.Manifest.permission.NFC) public boolean setOffHostForService(@NonNull android.content.ComponentName, @NonNull String);
     method public boolean setPreferredService(android.app.Activity, android.content.ComponentName);
+    method @FlaggedApi("com.android.nfc.module.flags.screen_state_attribute_toggle") public void setRequireDeviceScreenOnForService(@NonNull android.content.ComponentName, boolean);
+    method @FlaggedApi("com.android.nfc.module.flags.screen_state_attribute_toggle") public void setRequireDeviceUnlockForService(@NonNull android.content.ComponentName, boolean);
     method public boolean setShouldDefaultToObserveModeForService(@NonNull android.content.ComponentName, boolean);
     method public boolean supportsAidPrefixRegistration();
     method @FlaggedApi("android.nfc.nfc_event_listener") public void unregisterNfcEventCallback(@NonNull android.nfc.cardemulation.CardEmulation.NfcEventCallback);
@@ -253,6 +262,7 @@ package android.nfc.cardemulation {
     method @FlaggedApi("android.nfc.nfc_event_listener") public default void onInternalErrorReported(int);
     method @FlaggedApi("android.nfc.nfc_event_listener") public default void onNfcStateChanged(int);
     method @FlaggedApi("android.nfc.nfc_event_listener") public default void onObserveModeStateChanged(boolean);
+    method @FlaggedApi("com.android.nfc.module.flags.event_listener_offhost_aid_selected") public default void onOffHostAidSelected(@NonNull String, @NonNull String);
     method @FlaggedApi("android.nfc.nfc_event_listener") public default void onPreferredServiceChanged(boolean);
     method @FlaggedApi("android.nfc.nfc_event_listener") public default void onRemoteFieldChanged(boolean);
   }
diff --git a/framework/api/system-current.txt b/framework/api/system-current.txt
index 6e69da1c6..b3f90bb1a 100644
--- a/framework/api/system-current.txt
+++ b/framework/api/system-current.txt
@@ -119,6 +119,7 @@ package android.nfc {
     method public void onReaderOptionChanged(boolean);
     method public void onRfDiscoveryStarted(boolean);
     method public void onRfFieldDetected(boolean);
+    method @FlaggedApi("com.android.nfc.module.flags.oem_extension_25q4") public default void onRoutingChangeCompleted();
     method public void onRoutingChanged(@NonNull java.util.function.Consumer<java.lang.Boolean>);
     method public void onRoutingTableFull();
     method public void onStateUpdated(int);
diff --git a/framework/java/android/nfc/Entry.java b/framework/java/android/nfc/Entry.java
index aa5ba58e7..7ea462356 100644
--- a/framework/java/android/nfc/Entry.java
+++ b/framework/java/android/nfc/Entry.java
@@ -26,12 +26,14 @@ public final class Entry implements Parcelable {
     private final byte mNfceeId;
     private final String mEntry;
     private final String mRoutingType;
+    private final byte mPowerState;
 
-    public Entry(String entry, byte type, byte nfceeId, String routingType) {
+    public Entry(String entry, byte type, byte nfceeId, String routingType, byte powerState) {
         mEntry = entry;
         mType = type;
         mNfceeId = nfceeId;
         mRoutingType = routingType;
+        mPowerState = powerState;
     }
 
     public byte getType() {
@@ -50,6 +52,10 @@ public final class Entry implements Parcelable {
         return mRoutingType;
     }
 
+    public byte getPowerState() {
+        return mPowerState;
+    }
+
     @Override
     public int describeContents() {
         return 0;
@@ -60,6 +66,7 @@ public final class Entry implements Parcelable {
         this.mNfceeId = in.readByte();
         this.mType = in.readByte();
         this.mRoutingType = in.readString();
+        this.mPowerState = in.readByte();
     }
 
     public static final @NonNull Parcelable.Creator<Entry> CREATOR =
@@ -81,5 +88,6 @@ public final class Entry implements Parcelable {
         dest.writeByte(mNfceeId);
         dest.writeByte(mType);
         dest.writeString(mRoutingType);
+        dest.writeByte(mPowerState);
     }
 }
diff --git a/framework/java/android/nfc/INfcAdapter.aidl b/framework/java/android/nfc/INfcAdapter.aidl
index 43d601f78..f563adbdd 100644
--- a/framework/java/android/nfc/INfcAdapter.aidl
+++ b/framework/java/android/nfc/INfcAdapter.aidl
@@ -95,6 +95,9 @@ interface INfcAdapter
     boolean isObserveModeSupported();
     boolean isObserveModeEnabled();
     boolean setObserveMode(boolean enabled, String pkg);
+    boolean isPowerSavingModeSupported();
+    boolean isPowerSavingModeEnabled();
+    void setPowerSavingMode(boolean enabled);
 
     @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.WRITE_SECURE_SETTINGS)")
     boolean setWlcEnabled(boolean enable);
diff --git a/framework/java/android/nfc/INfcCardEmulation.aidl b/framework/java/android/nfc/INfcCardEmulation.aidl
index 00ceaa980..c2e7b9914 100644
--- a/framework/java/android/nfc/INfcCardEmulation.aidl
+++ b/framework/java/android/nfc/INfcCardEmulation.aidl
@@ -33,6 +33,10 @@ interface INfcCardEmulation
     boolean setDefaultServiceForCategory(int userHandle, in ComponentName service, String category);
     boolean setDefaultForNextTap(int userHandle, in ComponentName service);
     boolean setShouldDefaultToObserveModeForService(int userId, in android.content.ComponentName service, boolean enable);
+    void setRequireDeviceScreenOnForService(int userId, in android.content.ComponentName service, boolean enable);
+    boolean isDeviceScreenOnRequiredForService(int userId, in android.content.ComponentName service);
+    void setRequireDeviceUnlockForService(int userId, in android.content.ComponentName service, boolean enable);
+    boolean isDeviceUnlockRequiredForService(int userId, in android.content.ComponentName service);
     boolean registerAidGroupForService(int userHandle, in ComponentName service, in AidGroup aidGroup);
     boolean registerPollingLoopFilterForService(int userHandle, in ComponentName service, in String pollingLoopFilter, boolean autoTransact);
     boolean registerPollingLoopPatternFilterForService(int userHandle, in ComponentName service, in String pollingLoopPatternFilter, boolean autoTransact);
@@ -42,6 +46,8 @@ interface INfcCardEmulation
     boolean removeAidGroupForService(int userHandle, in ComponentName service, String category);
     boolean removePollingLoopFilterForService(int userHandle, in ComponentName service, in String pollingLoopFilter);
     boolean removePollingLoopPatternFilterForService(int userHandle, in ComponentName service, in String pollingLoopPatternFilter);
+    List<String> getPollingLoopFiltersForService(int userHandle, in ComponentName service);
+    List<String> getPollingLoopPatternFiltersForService(int userHandle, in ComponentName service);
     List<ApduServiceInfo> getServices(int userHandle, in String category);
     boolean setPreferredService(in ComponentName service);
     boolean unsetPreferredService();
diff --git a/framework/java/android/nfc/INfcEventCallback.aidl b/framework/java/android/nfc/INfcEventCallback.aidl
index 17b0d58c9..6b49f41c2 100644
--- a/framework/java/android/nfc/INfcEventCallback.aidl
+++ b/framework/java/android/nfc/INfcEventCallback.aidl
@@ -15,4 +15,5 @@ oneway interface INfcEventCallback {
     void onNfcStateChanged(in int nfcState);
     void onRemoteFieldChanged(boolean isDetected);
     void onInternalErrorReported(in int errorType);
+    void onOffHostAidSelected(in String aid, in String eeName);
 }
\ No newline at end of file
diff --git a/framework/java/android/nfc/INfcOemExtensionCallback.aidl b/framework/java/android/nfc/INfcOemExtensionCallback.aidl
index 357d32293..8f9219071 100644
--- a/framework/java/android/nfc/INfcOemExtensionCallback.aidl
+++ b/framework/java/android/nfc/INfcOemExtensionCallback.aidl
@@ -42,6 +42,7 @@ interface INfcOemExtensionCallback {
    void onDisableFinished(int status);
    void onTagDispatch(in ResultReceiver isSkipped);
    void onRoutingChanged(in ResultReceiver isSkipped);
+   void onRoutingChangeCompleted();
    void onHceEventReceived(int action);
    void onReaderOptionChanged(boolean enabled);
    void onCardEmulationActivated(boolean isActivated);
diff --git a/framework/java/android/nfc/NfcAdapter.java b/framework/java/android/nfc/NfcAdapter.java
index c8e19cf34..dd4f09d95 100644
--- a/framework/java/android/nfc/NfcAdapter.java
+++ b/framework/java/android/nfc/NfcAdapter.java
@@ -1255,6 +1255,47 @@ public final class NfcAdapter {
                 false);
     }
 
+    /**
+     * Returns whether the device supports power-saving mode or not.
+     *
+     * @return True if the device supports power-saving mode, false otherwise
+     */
+    @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_NFC_POWER_SAVING_MODE)
+    public boolean isPowerSavingModeSupported() {
+        return callServiceReturn(sService::isPowerSavingModeSupported, false);
+    }
+
+    /**
+     * Returns whether power-saving mode is currently enabled or not.
+     *
+     * @return True if power saving mode is enabled, false otherwise
+     */
+    @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_NFC_POWER_SAVING_MODE)
+    public boolean isPowerSavingModeEnabled() {
+        return callServiceReturn(sService::isPowerSavingModeEnabled, false);
+    }
+
+
+    /**
+     * Sets whether or not the NFC chip should be in power-saving mode next time it is disabled
+     * with {@link NfcAdapter#disable()}. If the chip is already disabled, power-saving mode will
+     * take effect immediately.
+     *
+     * <p>This mode puts the NFC chip in a very low power mode, but not fully turned off. This mode
+     * limits communication between the NFC chip and the host processor to conserve power, although
+     * the exact implementation may depend on the device's underlying hardware. Other NFC APIs are
+     * disabled while this mode is active.
+     *
+     * @throws UnsupportedOperationException If the device does not support power-saving mode.
+     * @throws IllegalStateException If a transient failure related to current device state
+     * prevented power-saving mode from being set.
+     */
+    @RequiresPermission(Manifest.permission.WRITE_SECURE_SETTINGS)
+    @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_NFC_POWER_SAVING_MODE)
+    public void setPowerSavingMode(boolean enabled) {
+        callService(() -> sService.setPowerSavingMode(enabled));
+    }
+
     /**
      * Resumes default NFC tag reader mode polling for the current device state if polling is
      * paused. Calling this while already in polling is a no-op.
@@ -2922,7 +2963,7 @@ public final class NfcAdapter {
     @FlaggedApi(Flags.FLAG_NFC_OEM_EXTENSION)
     @NonNull public NfcOemExtension getNfcOemExtension() {
         synchronized (sLock) {
-            if (!sHasNfcFeature) {
+            if (!sHasNfcFeature && !sHasCeFeature) {
                 throw new UnsupportedOperationException();
             }
         }
diff --git a/framework/java/android/nfc/NfcOemExtension.java b/framework/java/android/nfc/NfcOemExtension.java
index 4e2e1d98c..2e68f72d8 100644
--- a/framework/java/android/nfc/NfcOemExtension.java
+++ b/framework/java/android/nfc/NfcOemExtension.java
@@ -38,6 +38,9 @@ import android.nfc.cardemulation.CardEmulation;
 import android.nfc.cardemulation.CardEmulation.ProtocolAndTechnologyRoute;
 import android.os.Binder;
 import android.os.Bundle;
+import android.os.Handler;
+import android.os.IBinder;
+import android.os.Looper;
 import android.os.RemoteException;
 import android.os.ResultReceiver;
 import android.se.omapi.Reader;
@@ -376,7 +379,8 @@ public final class NfcOemExtension {
         void onTagDispatch(@NonNull Consumer<Boolean> isSkipped);
 
         /**
-         * Notifies routing configuration is changed.
+         * Notifies routing configuration is changed. This indicates the start
+         * of a possible routing change procedure.
          * @param isCommitRoutingSkipped The {@link Consumer} to be
          * completed. If routing commit should be skipped,
          * the {@link Consumer#accept(Object)} should be called with
@@ -384,6 +388,14 @@ public final class NfcOemExtension {
          */
         void onRoutingChanged(@NonNull Consumer<Boolean> isCommitRoutingSkipped);
 
+        /**
+         * Notifies routing configuration change is completed. This indicates
+         * the end of a routing change procedure.
+         * @see #onRoutingChanged(Consumer<Boolean>)
+         */
+        @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_OEM_EXTENSION_25Q4)
+        default void onRoutingChangeCompleted() { }
+
         /**
          * API to activate start stop cpu boost on hce event.
          *
@@ -593,6 +605,7 @@ public final class NfcOemExtension {
                 NfcAdapter.callService(() -> {
                     NfcAdapter.sService.registerOemExtensionCallback(mOemNfcExtensionCallback);
                     mIsRegistered = true;
+                    linkToNfcDeath();
                 });
             } else {
                 updateNfCState(callback, executor);
@@ -635,6 +648,10 @@ public final class NfcOemExtension {
                     NfcAdapter.sService.unregisterOemExtensionCallback(mOemNfcExtensionCallback);
                     mIsRegistered = false;
                     mCallbackMap.remove(callback);
+                    if (mDeathRecipient != null) {
+                        NfcAdapter.sService.asBinder().unlinkToDeath(mDeathRecipient, 0);
+                        mDeathRecipient = null;
+                    }
                 });
             } else {
                 mCallbackMap.remove(callback);
@@ -896,21 +913,26 @@ public final class NfcOemExtension {
                 case TYPE_TECHNOLOGY -> result.add(
                         new RoutingTableTechnologyEntry(entry.getNfceeId(),
                                 RoutingTableTechnologyEntry.techStringToInt(entry.getEntry()),
-                                routeStringToInt(entry.getRoutingType()))
+                                routeStringToInt(entry.getRoutingType()),
+                                entry.getPowerState()
+                        )
                 );
                 case TYPE_PROTOCOL -> result.add(
                         new RoutingTableProtocolEntry(entry.getNfceeId(),
                                 RoutingTableProtocolEntry.protocolStringToInt(entry.getEntry()),
-                                routeStringToInt(entry.getRoutingType()))
+                                routeStringToInt(entry.getRoutingType()),
+                                entry.getPowerState())
                 );
                 case TYPE_AID -> result.add(
                         new RoutingTableAidEntry(entry.getNfceeId(), entry.getEntry(),
-                                routeStringToInt(entry.getRoutingType()))
+                                routeStringToInt(entry.getRoutingType()),
+                                entry.getPowerState())
                 );
                 case TYPE_SYSTEMCODE -> result.add(
                         new RoutingTableSystemCodeEntry(entry.getNfceeId(),
                                 entry.getEntry().getBytes(StandardCharsets.UTF_8),
-                                routeStringToInt(entry.getRoutingType()))
+                                routeStringToInt(entry.getRoutingType()),
+                                entry.getPowerState())
                 );
             }
         }
@@ -1045,6 +1067,11 @@ public final class NfcOemExtension {
                             new ReceiverWrapper<>(isSkipped), cb::onRoutingChanged, ex));
         }
         @Override
+        public void onRoutingChangeCompleted() throws RemoteException {
+            mCallbackMap.forEach((cb, ex) ->
+                    handleVoidCallback(null, (Object input) -> cb.onRoutingChangeCompleted(), ex));
+        }
+        @Override
         public void onHceEventReceived(int action) throws RemoteException {
             mCallbackMap.forEach((cb, ex) ->
                     handleVoidCallback(action, cb::onHceEventReceived, ex));
@@ -1213,6 +1240,39 @@ public final class NfcOemExtension {
         }
     }
 
+    private IBinder.DeathRecipient mDeathRecipient;
+    private void linkToNfcDeath() {
+        try {
+            mDeathRecipient = new IBinder.DeathRecipient() {
+                @Override
+                public void binderDied() {
+                    synchronized (mCallbackMap) {
+                        mDeathRecipient = null;
+                    }
+                    Handler handler = new Handler(Looper.getMainLooper());
+                    handler.postDelayed(new Runnable() {
+                        public void run() {
+                            try {
+                                synchronized (mCallbackMap) {
+                                    if (mCallbackMap.size() > 0) {
+                                        NfcAdapter.callService(() ->
+                                                NfcAdapter.sService.registerOemExtensionCallback(
+                                                        mOemNfcExtensionCallback));
+                                        linkToNfcDeath();
+                                    }
+                                }
+                            } catch (Throwable t) {
+                                handler.postDelayed(this, 50);
+                            }
+                        }
+                    }, 50);
+                }
+            };
+            NfcAdapter.sService.asBinder().linkToDeath(mDeathRecipient, 0);
+        } catch (RemoteException re) {
+            Log.e(TAG, "Couldn't link to death");
+        }
+    }
     private @CardEmulation.ProtocolAndTechnologyRoute int routeStringToInt(String route) {
         if (route.equals("DH")) {
             return PROTOCOL_AND_TECHNOLOGY_ROUTE_DH;
diff --git a/framework/java/android/nfc/NfcRoutingTableEntry.java b/framework/java/android/nfc/NfcRoutingTableEntry.java
index 4153779a8..20a6663b2 100644
--- a/framework/java/android/nfc/NfcRoutingTableEntry.java
+++ b/framework/java/android/nfc/NfcRoutingTableEntry.java
@@ -37,6 +37,7 @@ public abstract class NfcRoutingTableEntry {
     private final int mNfceeId;
     private final int mType;
     private final int mRouteType;
+    private final int mPowerState;
 
     /**
      * AID routing table type.
@@ -70,10 +71,11 @@ public abstract class NfcRoutingTableEntry {
 
     /** @hide */
     protected NfcRoutingTableEntry(int nfceeId, @RoutingTableType int type,
-            @CardEmulation.ProtocolAndTechnologyRoute int routeType) {
+            @CardEmulation.ProtocolAndTechnologyRoute int routeType, int powerState) {
         mNfceeId = nfceeId;
         mType = type;
         mRouteType = routeType;
+        mPowerState = powerState;
     }
 
     /**
@@ -102,4 +104,12 @@ public abstract class NfcRoutingTableEntry {
     public int getRouteType() {
         return mRouteType;
     }
+
+    /**
+     * Get the PowerState of this entry
+     * @hide
+     */
+    public int getPowerState() {
+        return mPowerState;
+    }
 }
diff --git a/framework/java/android/nfc/NfcVendorNciCallbackListener.java b/framework/java/android/nfc/NfcVendorNciCallbackListener.java
index acbc993fb..4333f2b82 100644
--- a/framework/java/android/nfc/NfcVendorNciCallbackListener.java
+++ b/framework/java/android/nfc/NfcVendorNciCallbackListener.java
@@ -55,6 +55,7 @@ public final class NfcVendorNciCallbackListener extends INfcVendorNciCallback.St
                                                 NfcAdapter.getService()
                                                         .registerVendorExtensionCallback(
                                                                 NfcVendorNciCallbackListener.this));
+                                        linkToNfcDeath();
                                     }
                                 }
                             } catch (Throwable t) {
diff --git a/framework/java/android/nfc/RoutingTableAidEntry.java b/framework/java/android/nfc/RoutingTableAidEntry.java
index be94f9fc1..e9e6744ff 100644
--- a/framework/java/android/nfc/RoutingTableAidEntry.java
+++ b/framework/java/android/nfc/RoutingTableAidEntry.java
@@ -31,8 +31,8 @@ public class RoutingTableAidEntry extends NfcRoutingTableEntry {
 
     /** @hide */
     public RoutingTableAidEntry(int nfceeId, String value,
-            @CardEmulation.ProtocolAndTechnologyRoute int routeType) {
-        super(nfceeId, TYPE_AID, routeType);
+            @CardEmulation.ProtocolAndTechnologyRoute int routeType, int powerState) {
+        super(nfceeId, TYPE_AID, routeType, powerState);
         this.mValue = value;
     }
 
diff --git a/framework/java/android/nfc/RoutingTableProtocolEntry.java b/framework/java/android/nfc/RoutingTableProtocolEntry.java
index a68d8c167..e8be3f25b 100644
--- a/framework/java/android/nfc/RoutingTableProtocolEntry.java
+++ b/framework/java/android/nfc/RoutingTableProtocolEntry.java
@@ -98,8 +98,8 @@ public class RoutingTableProtocolEntry extends NfcRoutingTableEntry {
 
     /** @hide */
     public RoutingTableProtocolEntry(int nfceeId, @ProtocolValue int value,
-            @CardEmulation.ProtocolAndTechnologyRoute int routeType) {
-        super(nfceeId, TYPE_PROTOCOL, routeType);
+            @CardEmulation.ProtocolAndTechnologyRoute int routeType, int powerState) {
+        super(nfceeId, TYPE_PROTOCOL, routeType, powerState);
         this.mValue = value;
     }
 
diff --git a/framework/java/android/nfc/RoutingTableSystemCodeEntry.java b/framework/java/android/nfc/RoutingTableSystemCodeEntry.java
index 06cc0a5f2..69f96ca04 100644
--- a/framework/java/android/nfc/RoutingTableSystemCodeEntry.java
+++ b/framework/java/android/nfc/RoutingTableSystemCodeEntry.java
@@ -33,8 +33,8 @@ public class RoutingTableSystemCodeEntry extends NfcRoutingTableEntry {
 
     /** @hide */
     public RoutingTableSystemCodeEntry(int nfceeId, byte[] value,
-            @CardEmulation.ProtocolAndTechnologyRoute int routeType) {
-        super(nfceeId, TYPE_SYSTEM_CODE, routeType);
+            @CardEmulation.ProtocolAndTechnologyRoute int routeType, int powerState) {
+        super(nfceeId, TYPE_SYSTEM_CODE, routeType, powerState);
         this.mValue = value;
     }
 
@@ -47,4 +47,5 @@ public class RoutingTableSystemCodeEntry extends NfcRoutingTableEntry {
     public byte[] getSystemCode() {
         return mValue;
     }
+
 }
diff --git a/framework/java/android/nfc/RoutingTableTechnologyEntry.java b/framework/java/android/nfc/RoutingTableTechnologyEntry.java
index 86239ce7a..45611c645 100644
--- a/framework/java/android/nfc/RoutingTableTechnologyEntry.java
+++ b/framework/java/android/nfc/RoutingTableTechnologyEntry.java
@@ -79,8 +79,8 @@ public class RoutingTableTechnologyEntry extends NfcRoutingTableEntry {
 
     /** @hide */
     public RoutingTableTechnologyEntry(int nfceeId, @TechnologyValue int value,
-            @CardEmulation.ProtocolAndTechnologyRoute int routeType) {
-        super(nfceeId, TYPE_TECHNOLOGY, routeType);
+            @CardEmulation.ProtocolAndTechnologyRoute int routeType, int powerState) {
+        super(nfceeId, TYPE_TECHNOLOGY, routeType, powerState);
         this.mValue = value;
     }
 
diff --git a/framework/java/android/nfc/cardemulation/CardEmulation.java b/framework/java/android/nfc/cardemulation/CardEmulation.java
index 90aae8394..12dc774a9 100644
--- a/framework/java/android/nfc/cardemulation/CardEmulation.java
+++ b/framework/java/android/nfc/cardemulation/CardEmulation.java
@@ -49,6 +49,7 @@ import android.os.RemoteException;
 import android.os.UserHandle;
 import android.provider.Settings;
 import android.provider.Settings.SettingNotFoundException;
+import android.se.omapi.Reader;
 import android.telephony.SubscriptionManager;
 import android.util.ArrayMap;
 import android.util.Log;
@@ -456,6 +457,68 @@ public final class CardEmulation {
                 mContext.getUser().getIdentifier(), service, enable), false);
     }
 
+    /**
+     * Sets whether the device must have its screen on for the service to be activated. This API
+     * overrides the {@code android:requireDeviceScreenOn} attribute declared in the service's
+     * manifest.
+     *
+     * @param service The component name of the service
+     * @param enable Whether the service should only be activated when the device's screen is on
+     * @throws IllegalArgumentException If the provided service has not been registered
+     */
+    @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_SCREEN_STATE_ATTRIBUTE_TOGGLE)
+    public void setRequireDeviceScreenOnForService(@NonNull ComponentName service,
+            boolean enable) {
+        callService(() ->
+                sService.setRequireDeviceScreenOnForService(
+                        mContext.getUser().getIdentifier(), service, enable));
+    }
+
+    /**
+     * Checks whether the device must have its screen on for the service to be activated.
+     *
+     * @param service The component name of the service
+     * @return True if the device must have its screen on for the service to be activated, false
+     * otherwise
+     * @throws IllegalArgumentException If the provided service has not been registered
+     */
+    @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_SCREEN_STATE_ATTRIBUTE_TOGGLE)
+    public boolean isDeviceScreenOnRequiredForService(@NonNull ComponentName service) {
+        return callServiceReturn(() ->
+                sService.isDeviceScreenOnRequiredForService(
+                        mContext.getUser().getIdentifier(), service), false);
+    }
+
+    /**
+     * Sets whether the device must be unlocked for the service to be activated. This API overrides
+     * the {@code android:requireDeviceUnlock} attribute declared in the service's manifest.
+     *
+     * @param service The component name of the service
+     * @param enable Whether the service should only be activated when the device is unlocked
+     * @throws IllegalArgumentException If the provided service has not been registered
+     */
+    @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_SCREEN_STATE_ATTRIBUTE_TOGGLE)
+    public void setRequireDeviceUnlockForService(@NonNull ComponentName service,
+            boolean enable) {
+        callService(() ->
+                sService.setRequireDeviceUnlockForService(
+                        mContext.getUser().getIdentifier(), service, enable));
+    }
+
+    /**
+     * Checks whether the device must be unlocked for the service to be activated.
+     *
+     * @param service The component name of the service
+     * @return True if the device must be unlocked for the service to be activated, false otherwise
+     * @throws IllegalArgumentException If the provided service has not been registered
+     */
+    @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_SCREEN_STATE_ATTRIBUTE_TOGGLE)
+    public boolean isDeviceUnlockRequiredForService(@NonNull ComponentName service) {
+        return callServiceReturn(() ->
+                sService.isDeviceUnlockRequiredForService(
+                        mContext.getUser().getIdentifier(), service), false);
+    }
+
     /**
      * Register a polling loop filter (PLF) for a HostApduService and indicate whether it should
      * auto-transact or not.  The PLF can be sequence of an
@@ -497,6 +560,22 @@ public final class CardEmulation {
                 mContext.getUser().getIdentifier(), service, pollingLoopFilterV), false);
     }
 
+    /**
+     * Retrieve all the polling loop filters registered for a {@link HostApduService}.
+     *
+     * @param service The HostApduService to retrieve the filter for
+     * @return List of polling loop filters, will be empty if there are none registered.
+     * @throws IllegalArgumentException if the service is not valid.
+     * @see #registerPollingLoopFilterForService(ComponentName, String, boolean)
+     */
+    @NonNull
+    @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_GET_POLLING_LOOP_FILTERS)
+    public List<String> getPollingLoopFiltersForService(@NonNull ComponentName service) {
+        return callServiceReturn(() ->
+                        sService.getPollingLoopFiltersForService(
+                                mContext.getUser().getIdentifier(), service),
+                List.of());
+    }
 
     /**
      * Register a polling loop pattern filter (PLPF) for a HostApduService and indicate whether it
@@ -553,6 +632,23 @@ public final class CardEmulation {
                 mContext.getUser().getIdentifier(), service, pollingLoopPatternFilterV), false);
     }
 
+    /**
+     * Retrieve all the polling loop pattern filters registered for a {@link HostApduService}.
+     *
+     * @param service The HostApduService to retrieve the filter for
+     * @return List of polling loop pattern filters, will be empty if there are none registered.
+     * @throws IllegalArgumentException if the service is not valid.
+     * @see #registerPollingLoopPatternFilterForService(ComponentName, String, boolean)
+     */
+    @NonNull
+    @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_GET_POLLING_LOOP_FILTERS)
+    public List<String> getPollingLoopPatternFiltersForService(@NonNull ComponentName service) {
+        return callServiceReturn(() ->
+                        sService.getPollingLoopPatternFiltersForService(
+                                mContext.getUser().getIdentifier(), service),
+                List.of());
+    }
+
     /**
      * Registers a list of AIDs for a specific category for the
      * specified service.
@@ -1418,6 +1514,27 @@ public final class CardEmulation {
          */
         @FlaggedApi(android.nfc.Flags.FLAG_NFC_EVENT_LISTENER)
         default void onInternalErrorReported(@NfcInternalErrorType int errorType) {}
+
+        /**
+         * This method is called when an off-host AID is selected.
+         *
+         * This indicates that an offhost (Secure Element or UICC) transaction
+         * has started.
+         *
+         * @param aid The AID that was selected
+         * @param offHostSecureElement Secure Element on which the AID was routed to. Will be string
+         *                             with prefix SIM or prefix eSE ({@link Reader#getName()}).
+         *                             Ref: GSMA TS.26 - NFC Handset Requirements
+         *                             TS26_NFC_REQ_069: For UICC, Secure Element Name SHALL be
+         *                                               SIM[smartcard slot]
+         *                                               (e.g. SIM/SIM1, SIM2… SIMn).
+         *                             TS26_NFC_REQ_070: For embedded SE, Secure Element Name SHALL
+         *                                               be eSE[number]
+         *                                               (e.g. eSE/eSE1, eSE2, etc.).
+         */
+        @FlaggedApi(com.android.nfc.module.flags.Flags.FLAG_EVENT_LISTENER_OFFHOST_AID_SELECTED)
+        default void onOffHostAidSelected(@NonNull String aid,
+                @NonNull String offHostSecureElement) {}
     }
 
     private final ArrayMap<NfcEventCallback, Executor> mNfcEventCallbacks = new ArrayMap<>();
@@ -1489,6 +1606,13 @@ public final class CardEmulation {
                     callListeners(listener -> listener.onInternalErrorReported(errorType));
                 }
 
+                public void onOffHostAidSelected(String aid, String eeName) {
+                    if (!com.android.nfc.module.flags.Flags.eventListenerOffhostAidSelected()) {
+                        return;
+                    }
+                    callListeners(listener -> listener.onOffHostAidSelected(aid, eeName));
+                }
+
                 interface ListenerCall {
                     void invoke(NfcEventCallback listener);
                 }
diff --git a/framework/tests/src/android/nfc/EntryTest.java b/framework/tests/src/android/nfc/EntryTest.java
index 5202c3693..a5ff64e78 100644
--- a/framework/tests/src/android/nfc/EntryTest.java
+++ b/framework/tests/src/android/nfc/EntryTest.java
@@ -29,11 +29,12 @@ public class EntryTest {
     private final byte mType = 1;
     private final byte mNfceeId = 2;
     private final String mSampleRoutingType = "SampleRoutingType";
+    private final byte mPowerState = 1;
     private Entry mEntry;
 
     @Before
     public void setUp() {
-        mEntry = new Entry(mSampleEntry, mType, mNfceeId, mSampleRoutingType);
+        mEntry = new Entry(mSampleEntry, mType, mNfceeId, mSampleRoutingType, mPowerState);
     }
 
     @Test
@@ -65,7 +66,8 @@ public class EntryTest {
         byte type = 0;
         byte nfceeId = 0;
         String routingType = "";
-        Entry original = new Entry(entry, type, nfceeId, routingType);
+        byte powerState = 1;
+        Entry original = new Entry(entry, type, nfceeId, routingType, powerState);
         Parcel parcel = Parcel.obtain();
         original.writeToParcel(parcel, 0);
         parcel.setDataPosition(0);
diff --git a/framework/tests/src/android/nfc/NfcRoutingTableEntryTest.java b/framework/tests/src/android/nfc/NfcRoutingTableEntryTest.java
index a90a716b6..f86b077a2 100644
--- a/framework/tests/src/android/nfc/NfcRoutingTableEntryTest.java
+++ b/framework/tests/src/android/nfc/NfcRoutingTableEntryTest.java
@@ -29,7 +29,7 @@ public final class NfcRoutingTableEntryTest {
     @Test
     public void testAidEntry_GetAid() {
         String expectedAid = "A00000061A02";
-        RoutingTableAidEntry entry = new RoutingTableAidEntry(1, expectedAid, 0);
+        RoutingTableAidEntry entry = new RoutingTableAidEntry(1, expectedAid, 0, 1);
 
         assertEquals(expectedAid, entry.getAid());
     }
@@ -37,7 +37,7 @@ public final class NfcRoutingTableEntryTest {
     @Test
     public void testProtocolEntry_GetProtocol() {
         RoutingTableProtocolEntry entry =
-                new RoutingTableProtocolEntry(1, RoutingTableProtocolEntry.PROTOCOL_T1T, 0);
+                new RoutingTableProtocolEntry(1, RoutingTableProtocolEntry.PROTOCOL_T1T, 0, 1);
 
         assertEquals(RoutingTableProtocolEntry.PROTOCOL_T1T, entry.getProtocol());
     }
@@ -46,7 +46,7 @@ public final class NfcRoutingTableEntryTest {
     public void testSystemCodeEntry_GetSystemCode() {
         byte[] expectedSystemCode = {0x01, 0x02, 0x03};
         RoutingTableSystemCodeEntry entry =
-                new RoutingTableSystemCodeEntry(1, expectedSystemCode, 0);
+                new RoutingTableSystemCodeEntry(1, expectedSystemCode, 0, 1);
 
         assertArrayEquals(expectedSystemCode, entry.getSystemCode());
     }
@@ -54,7 +54,7 @@ public final class NfcRoutingTableEntryTest {
     @Test
     public void testTechnologyEntry_GetTechnology_A() {
         RoutingTableTechnologyEntry entry =
-                new RoutingTableTechnologyEntry(1, RoutingTableTechnologyEntry.TECHNOLOGY_A, 0);
+                new RoutingTableTechnologyEntry(1, RoutingTableTechnologyEntry.TECHNOLOGY_A, 0, 1);
 
         assertEquals(RoutingTableTechnologyEntry.TECHNOLOGY_A, entry.getTechnology());
     }
diff --git a/framework/tests/src/android/nfc/RoutingTableProtocolEntryTest.java b/framework/tests/src/android/nfc/RoutingTableProtocolEntryTest.java
index 208d2079f..6f49612aa 100644
--- a/framework/tests/src/android/nfc/RoutingTableProtocolEntryTest.java
+++ b/framework/tests/src/android/nfc/RoutingTableProtocolEntryTest.java
@@ -28,9 +28,10 @@ public class RoutingTableProtocolEntryTest {
         int nfceeId = 1;
         int protocolValue = RoutingTableProtocolEntry.PROTOCOL_ISO_DEP;
         int routeType = PROTOCOL_AND_TECHNOLOGY_ROUTE_DH;
+        int powerState = 1;
 
         RoutingTableProtocolEntry entry = new RoutingTableProtocolEntry(nfceeId, protocolValue,
-                routeType);
+                routeType, powerState);
         assertEquals(protocolValue, entry.getProtocol());
         assertEquals(nfceeId, entry.getNfceeId());
         assertEquals(routeType, entry.getRouteType());
diff --git a/libnfc-nci/TEST_MAPPING b/libnfc-nci/TEST_MAPPING
index 89553f673..cae4e9a5b 100644
--- a/libnfc-nci/TEST_MAPPING
+++ b/libnfc-nci/TEST_MAPPING
@@ -8,5 +8,15 @@
     {
       "name": "libnfc-nci-tests"
     }
+  ],
+  "wear-cts-presubmit": [
+    {
+      "name": "CtsNfcTestCases",
+      "options": [
+       {
+         "include-filter": "android.nfc.cts.CardEmulationTest"
+       }
+     ]
+    }
   ]
 }
diff --git a/libnfc-nci/conf/libnfc-nci.conf b/libnfc-nci/conf/libnfc-nci.conf
index 7892ea2b1..ed62be6ec 100644
--- a/libnfc-nci/conf/libnfc-nci.conf
+++ b/libnfc-nci/conf/libnfc-nci.conf
@@ -90,6 +90,12 @@ EUICC_MEP_MODE=0x03
 # 0x01 : EE_ENABLED_BASED   (RF discovery called after all EE are enabled)
 NFCEE_EVENT_RF_DISCOVERY_OPTION=0x00
 
+#########################################################################
+# RT update based on below options.
+# 0x00 : RT command sent to controller with default entry and current entry
+# 0x01 : RT command sent to controller only with current entry
+OPTIMIZE_ROUTING_TABLE_UPDATE=0x00
+
 ###############################################################################
 # To enable or disable debounce timer for routing API calls.
 # 0x00 : disable the debounce timer for routing api call.
diff --git a/libnfc-nci/src/adaptation/NfcAdaptation.cc b/libnfc-nci/src/adaptation/NfcAdaptation.cc
index 2cb10dcc3..75c3afb97 100644
--- a/libnfc-nci/src/adaptation/NfcAdaptation.cc
+++ b/libnfc-nci/src/adaptation/NfcAdaptation.cc
@@ -29,6 +29,7 @@
 #include <android/hardware/nfc/1.1/INfc.h>
 #include <android/hardware/nfc/1.2/INfc.h>
 #include <cutils/properties.h>
+#include <future>
 #include <hwbinder/ProcessState.h>
 
 #include <thread>
@@ -103,6 +104,7 @@ uint8_t appl_dta_mode_flag = 0x00;
 bool isDownloadFirmwareCompleted = false;
 bool use_aidl = false;
 uint8_t mute_tech_route_option = 0x00;
+std::vector<uint8_t> t4tNfceeAidBuf;
 unsigned int t5t_mute_legacy = 0;
 bool nfa_ee_route_debounce_timer = true;
 
@@ -600,9 +602,11 @@ void NfcAdaptation::Initialize() {
 
   if (NfcConfig::hasKey(NAME_NFA_MAX_EE_SUPPORTED)) {
     nfa_ee_max_ee_cfg = NfcConfig::getUnsigned(NAME_NFA_MAX_EE_SUPPORTED);
-    LOG(VERBOSE) << StringPrintf(
-        "%s: Overriding NFA_EE_MAX_EE_SUPPORTED to use %d", func,
-        nfa_ee_max_ee_cfg);
+    if (NFA_EE_MAX_EE_SUPPORTED != nfa_ee_max_ee_cfg) {
+      LOG(WARNING) << StringPrintf(
+          "%s: Overriding NFA_EE_MAX_EE_SUPPORTED (%d) to use %d", func,
+          NFA_EE_MAX_EE_SUPPORTED, nfa_ee_max_ee_cfg);
+    }
   }
 
   if (NfcConfig::hasKey(NAME_NFA_POLL_BAIL_OUT_MODE)) {
@@ -650,6 +654,10 @@ void NfcAdaptation::Initialize() {
         NfcConfig::getUnsigned(NAME_ISO15693_SKIP_GET_SYS_INFO_CMD);
   }
 
+  if (NfcConfig::hasKey(NAME_T4T_NDEF_NFCEE_AID)) {
+    t4tNfceeAidBuf = NfcConfig::getBytes(NAME_T4T_NDEF_NFCEE_AID);
+  }
+
   if (NfcConfig::hasKey(NAME_NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT)) {
     unsigned int value =
         NfcConfig::getUnsigned(NAME_NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT);
@@ -733,6 +741,9 @@ void NfcAdaptation::FactoryReset() {
 }
 
 void NfcAdaptation::DeviceShutdown() {
+  if (sVndExtnsPresent) {
+    sNfcVendorExtn->processEvent(HANDLE_NFC_DEVICE_SHUTDOWN, HAL_NFC_STATUS_OK);
+  }
   if (mAidlHal != nullptr && AIBinder_isAlive(mAidlHal->asBinder().get())) {
     mAidlHal->close(NfcCloseType::HOST_SWITCHED_OFF);
     AIBinder_unlinkToDeath(mAidlHal->asBinder().get(), mDeathRecipient.get(),
@@ -837,6 +848,32 @@ uint32_t NfcAdaptation::Thread(__attribute__((unused)) uint32_t arg) {
 *******************************************************************************/
 tHAL_NFC_ENTRY* NfcAdaptation::GetHalEntryFuncs() { return &mHalEntryFuncs; }
 
+/*******************************************************************************
+**
+** Function:    NfcAdaptation::waitForNfcServiceAsync()
+**
+** Description: Binder to NFC HAL Service.
+**
+** Returns:     Binder object if success or nullptr if timeout(5s).
+**
+*******************************************************************************/
+std::shared_ptr<INfcAidl> waitForNfcServiceAsync() {
+  auto future = std::async(std::launch::async, []() -> std::shared_ptr<INfcAidl> {
+      ::ndk::SpAIBinder binder(
+          AServiceManager_waitForService(NFC_AIDL_HAL_SERVICE_NAME.c_str()));
+      return INfcAidl::fromBinder(binder);
+  });
+
+  constexpr auto timeout = std::chrono::seconds(5);
+  if (future.wait_for(timeout) == std::future_status::ready) {
+    ALOGD("Ready for NFC AIDL service (future).");
+    return future.get();
+  } else {
+    ALOGE("Timeout waiting for NFC AIDL service (future).");
+    return nullptr;
+  }
+}
+
 /*******************************************************************************
 **
 ** Function:    NfcAdaptation::InitializeHalDeviceContext
@@ -873,9 +910,7 @@ void NfcAdaptation::InitializeHalDeviceContext() {
   }
   if (mHal == nullptr) {
     // Try get AIDL
-    ::ndk::SpAIBinder binder(
-        AServiceManager_waitForService(NFC_AIDL_HAL_SERVICE_NAME.c_str()));
-    mAidlHal = INfcAidl::fromBinder(binder);
+    mAidlHal = waitForNfcServiceAsync();
     if (mAidlHal != nullptr) {
       use_aidl = true;
       AIBinder_linkToDeath(mAidlHal->asBinder().get(), mDeathRecipient.get(),
@@ -889,9 +924,11 @@ void NfcAdaptation::InitializeHalDeviceContext() {
       if (mAidlHalVer <= 1) {
         sVndExtnsPresent = sNfcVendorExtn->Initialize(nullptr, mAidlHal);
       }
+    } else {
+      LOG(INFO) << StringPrintf("%s: Failed to retrieve the NFC AIDL!", func);
+      ALOGE("Exit current process to recover.");
+      _exit(0);
     }
-    LOG_ALWAYS_FATAL_IF(mAidlHal == nullptr,
-                        "Failed to retrieve the NFC AIDL!");
   } else {
     LOG(INFO) << StringPrintf("%s: INfc::getService() returned %p (%s)", func,
                               mHal.get(),
diff --git a/libnfc-nci/src/fuzzers/fuzz_cmn.cc b/libnfc-nci/src/fuzzers/fuzz_cmn.cc
index 9afd7359a..2461edc89 100644
--- a/libnfc-nci/src/fuzzers/fuzz_cmn.cc
+++ b/libnfc-nci/src/fuzzers/fuzz_cmn.cc
@@ -10,6 +10,7 @@ uint8_t appl_dta_mode_flag = 0;
 unsigned int t5t_mute_legacy = 0;
 bool nfc_nci_reset_keep_cfg_enabled = false;
 uint8_t nfc_nci_reset_type = 0x00;
+std::vector<uint8_t> t4tNfceeAidBuf = {};
 
 namespace android {
 namespace util {
diff --git a/libnfc-nci/src/fuzzers/integration/fakes/nfc_adaptation_fakes.cc b/libnfc-nci/src/fuzzers/integration/fakes/nfc_adaptation_fakes.cc
index bc1ac851a..c8facf8df 100644
--- a/libnfc-nci/src/fuzzers/integration/fakes/nfc_adaptation_fakes.cc
+++ b/libnfc-nci/src/fuzzers/integration/fakes/nfc_adaptation_fakes.cc
@@ -5,6 +5,7 @@ unsigned int t5t_mute_legacy = 0;
 bool nfc_nci_reset_keep_cfg_enabled = false;
 uint8_t nfc_nci_reset_type = 0x00;
 bool nfa_ee_route_debounce_timer = true;
+std::vector<uint8_t> t4tNfceeAidBuf = {};
 
 NfcAdaptation* NfcAdaptation::mpInstance = nullptr;
 
diff --git a/libnfc-nci/src/gki/common/gki_buffer.cc b/libnfc-nci/src/gki/common/gki_buffer.cc
index b46138241..e57be1afb 100644
--- a/libnfc-nci/src/gki/common/gki_buffer.cc
+++ b/libnfc-nci/src/gki/common/gki_buffer.cc
@@ -307,9 +307,11 @@ void* GKI_getbuf(uint16_t size) {
   if (++Q->cur_cnt > Q->max_cnt) Q->max_cnt = Q->cur_cnt;
   GKI_enable();
 
+#if (GKI_ENABLE_BUF_CORRUPTION_CHECK == TRUE)
   LOG(VERBOSE) << StringPrintf("%s: %p %d:%d", __func__,
                                ((uint8_t*)p_hdr + BUFFER_HDR_SIZE), Q->cur_cnt,
                                Q->max_cnt);
+#endif
   UNUSED(gki_alloc_free_queue);
   return (void*)((uint8_t*)p_hdr + BUFFER_HDR_SIZE);
 #else
@@ -510,6 +512,11 @@ void GKI_freebuf(void* p_buf) {
   Q = &gki_cb.com.freeq[p_hdr->q_id];
   if (Q->cur_cnt > 0) Q->cur_cnt--;
   GKI_enable();
+#if (GKI_ENABLE_BUF_CORRUPTION_CHECK == TRUE)
+  LOG(VERBOSE) << StringPrintf("%s %p %d:%d", __func__,
+                               ((uint8_t*)p_hdr + BUFFER_HDR_SIZE), Q->cur_cnt,
+                               Q->max_cnt);
+#endif
 
   GKI_os_free(p_hdr);
 #else
diff --git a/libnfc-nci/src/gki/common/gki_time.cc b/libnfc-nci/src/gki/common/gki_time.cc
index 1cace08d7..cf78ab84f 100644
--- a/libnfc-nci/src/gki/common/gki_time.cc
+++ b/libnfc-nci/src/gki/common/gki_time.cc
@@ -226,11 +226,11 @@ void GKI_start_timer(uint8_t tnum, int32_t ticks, bool is_continuous) {
   ** Note that this works when no timers are active since
   ** both OSNumOrigTicks and OSTicksTilExp are 0.
   */
-  if (GKI_MAX_INT32 - (gki_cb.com.OSNumOrigTicks - gki_cb.com.OSTicksTilExp) >
-      ticks) {
-    ticks += gki_cb.com.OSNumOrigTicks - gki_cb.com.OSTicksTilExp;
-  } else
+  if (__builtin_add_overflow(
+          ticks, gki_cb.com.OSNumOrigTicks - gki_cb.com.OSTicksTilExp,
+          &ticks)) {
     ticks = GKI_MAX_INT32;
+  }
 
   switch (tnum) {
 #if (GKI_NUM_TIMERS > 0)
@@ -368,6 +368,8 @@ void GKI_timer_update(int32_t ticks_since_last_update) {
   long next_expiration; /* Holds the next soonest expiration time after this
                            update */
 
+  GKI_disable();
+
   /* Increment the number of ticks used for time stamps */
   gki_cb.com.OSTicks += ticks_since_last_update;
 
@@ -377,7 +379,10 @@ void GKI_timer_update(int32_t ticks_since_last_update) {
   gki_cb.com.OSTicksTilExp -= ticks_since_last_update;
 
   /* Don't allow timer interrupt nesting */
-  if (gki_cb.com.timer_nesting) return;
+  if (gki_cb.com.timer_nesting) {
+    GKI_enable();
+    return;
+  }
 
   gki_cb.com.timer_nesting = 1;
 
@@ -391,6 +396,7 @@ void GKI_timer_update(int32_t ticks_since_last_update) {
       }
       gki_cb.com.OSTicksTilStop = 0; /* clear inactivity delay timer */
       gki_cb.com.timer_nesting = 0;
+      GKI_enable();
       return;
     } else
       gki_cb.com.OSTicksTilStop -= ticks_since_last_update;
@@ -400,11 +406,10 @@ void GKI_timer_update(int32_t ticks_since_last_update) {
   /* No need to update the ticks if no timeout has occurred */
   if (gki_cb.com.OSTicksTilExp > 0) {
     gki_cb.com.timer_nesting = 0;
+    GKI_enable();
     return;
   }
 
-  GKI_disable();
-
   next_expiration = GKI_NO_NEW_TMRS_STARTED;
 
   /* If here then gki_cb.com.OSTicksTilExp <= 0. If negative, then increase
diff --git a/libnfc-nci/src/include/nfc_config.h b/libnfc-nci/src/include/nfc_config.h
index f478179af..c48a791a1 100644
--- a/libnfc-nci/src/include/nfc_config.h
+++ b/libnfc-nci/src/include/nfc_config.h
@@ -47,6 +47,7 @@
   "NFA_DM_LISTEN_ACTIVE_DEACT_NTF_TIMEOUT"
 #define NAME_EUICC_MEP_MODE "EUICC_MEP_MODE"
 #define NAME_NFCEE_EVENT_RF_DISCOVERY_OPTION "NFCEE_EVENT_RF_DISCOVERY_OPTION"
+#define NAME_OPTIMIZE_ROUTING_TABLE_UPDATE "OPTIMIZE_ROUTING_TABLE_UPDATE"
 #define NAME_NFA_EE_ROUTE_DEBOUNCE_TIMER "NFA_EE_ROUTE_DEBOUNCE_TIMER"
 /* Configs from vendor interface */
 #define NAME_NFA_POLL_BAIL_OUT_MODE "NFA_POLL_BAIL_OUT_MODE"
diff --git a/libnfc-nci/src/nfa/dm/nfa_dm_api.cc b/libnfc-nci/src/nfa/dm/nfa_dm_api.cc
index 816a143fa..3fab39893 100644
--- a/libnfc-nci/src/nfa/dm/nfa_dm_api.cc
+++ b/libnfc-nci/src/nfa/dm/nfa_dm_api.cc
@@ -86,6 +86,7 @@ extern void NFA_Partial_Init(tHAL_NFC_ENTRY* p_hal_entry_tbl, uint8_t mode) {
     nfa_sys_init();
     nfa_dm_init();
     nfa_ee_init();
+    nfa_t4tnfcee_init();
   } else {
     LOG(ERROR) << StringPrintf("%s: Unknown Mode!", __func__);
     return;
diff --git a/libnfc-nci/src/nfa/dm/nfa_dm_discover.cc b/libnfc-nci/src/nfa/dm/nfa_dm_discover.cc
index ccc9b6319..e056ec699 100644
--- a/libnfc-nci/src/nfa/dm/nfa_dm_discover.cc
+++ b/libnfc-nci/src/nfa/dm/nfa_dm_discover.cc
@@ -1788,16 +1788,6 @@ void nfa_dm_disc_new_state(tNFA_DM_RF_DISC_STATE new_state) {
       nfa_sys_check_disabled();
     }
   }
-
-  if (((nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_IDLE) ||
-       (nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_DISCOVERY)) &&
-      (!(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_W4_RSP)) &&
-      (nfc_cb.is_nfcee_discovery_required)) {
-    LOG(VERBOSE) << StringPrintf("%s: Triggering Pending EE discovery...",
-                                 __func__);
-    nfa_dm_nfc_response_cback_wrapper(NFC_NFCEE_STATUS_REVT,
-                                      &nfc_cb.nfcee_data);
-  }
 }
 
 /*******************************************************************************
@@ -2996,6 +2986,16 @@ void nfa_dm_disc_sm_execute(tNFA_DM_RF_DISC_SM_EVENT event,
       "%s: new state=%s (%d), disc_flags=0x%x", __func__,
       nfa_dm_disc_state_2_str(nfa_dm_cb.disc_cb.disc_state).c_str(),
       nfa_dm_cb.disc_cb.disc_state, nfa_dm_cb.disc_cb.disc_flags);
+
+  if (((nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_IDLE) ||
+        (nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_DISCOVERY)) &&
+      (!(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_W4_RSP)) &&
+      (nfc_cb.is_nfcee_discovery_required)) {
+    LOG(VERBOSE) << StringPrintf("%s: Triggering Pending EE discovery...",
+        __func__);
+    nfa_dm_nfc_response_cback_wrapper(NFC_NFCEE_STATUS_REVT,
+        &nfc_cb.nfcee_data);
+  }
 }
 
 /*******************************************************************************
@@ -3167,28 +3167,16 @@ bool nfa_dm_rf_removal_detection(uint8_t waiting_time) {
                                waiting_time);
 
   if (nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_POLL_ACTIVE) {
-    if ((nfa_dm_cb.disc_cb.activated_protocol == NFC_PROTOCOL_T2T) ||
-        (nfa_dm_cb.disc_cb.activated_protocol == NFC_PROTOCOL_T3T) ||
-        (nfa_dm_cb.disc_cb.activated_protocol == NFC_PROTOCOL_ISO_DEP) ||
-        (nfa_dm_cb.disc_cb.activated_protocol == NFA_PROTOCOL_T5T)) {
-      /* state is OK: notify the status when the response is received from NFCC
-       */
-      detect_params.waiting_time = waiting_time;
+    /* state is OK: notify the status when the response is received from NFCC
+     */
+    detect_params.waiting_time = waiting_time;
 
-      nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_NOTIFY;
-      nfa_dm_cb.flags |= NFA_DM_FLAGS_EP_REMOVAL_DETECT_PEND;
-      tNFA_DM_RF_DISC_DATA nfa_dm_rf_disc_data;
-      nfa_dm_rf_disc_data.detect_removal = detect_params;
-      nfa_dm_disc_sm_execute(NFA_DM_RF_REMOVAL_DETECT_START_CMD,
-                             &nfa_dm_rf_disc_data);
-    } else {
-      LOG(ERROR) << __func__
-                 << ": Activated RF interface not ISO-DEP "
-                    "or Frame RF Interface";
-      conn_evt.status = NFA_STATUS_FAILED;
-      nfa_dm_conn_cback_event_notify(NFA_DETECT_REMOVAL_STARTED_EVT, &conn_evt);
-      return false;
-    }
+    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_NOTIFY;
+    nfa_dm_cb.flags |= NFA_DM_FLAGS_EP_REMOVAL_DETECT_PEND;
+    tNFA_DM_RF_DISC_DATA nfa_dm_rf_disc_data;
+    nfa_dm_rf_disc_data.detect_removal = detect_params;
+    nfa_dm_disc_sm_execute(NFA_DM_RF_REMOVAL_DETECT_START_CMD,
+                           &nfa_dm_rf_disc_data);
   } else {
     /* Wrong state: notify failed status right away */
     LOG(ERROR) << __func__ << ": NFCC not in poll active state";
diff --git a/libnfc-nci/src/nfa/ee/nfa_ee_act.cc b/libnfc-nci/src/nfa/ee/nfa_ee_act.cc
index 0ba16889d..ec0853b13 100644
--- a/libnfc-nci/src/nfa/ee/nfa_ee_act.cc
+++ b/libnfc-nci/src/nfa/ee/nfa_ee_act.cc
@@ -641,8 +641,10 @@ static void nfa_ee_conn_cback(uint8_t conn_id, tNFC_CONN_EVT event,
 *******************************************************************************/
 int nfa_ee_find_max_aid_cfg_len(void) {
   int max_lmrt_size = NFC_GetLmrtSize();
-  if (max_lmrt_size > NFA_EE_MAX_PROTO_TECH_EXT_ROUTE_LEN) {
-    return max_lmrt_size - NFA_EE_MAX_PROTO_TECH_EXT_ROUTE_LEN;
+  int reserved =
+      (NFA_EE_MAX_PROTO_TECH_EXT_ROUTE_LEN + NFA_EE_MAX_SYSTEM_CODE_CFG_LEN);
+  if (max_lmrt_size > reserved) {
+    return (max_lmrt_size - reserved);
   } else {
     return 0;
   }
@@ -2656,6 +2658,7 @@ void nfa_ee_nci_disc_req_ntf(tNFA_EE_MSG* p_data) {
   uint8_t report_ntf = 0;
   uint8_t xx;
   std::vector<uint8_t> uicc_ids;
+  uint8_t listen_cnt = 0;
 
   LOG(VERBOSE) << StringPrintf("%s: num_info=%d cur_ee=%d", __func__,
                                p_cbk->num_info, nfa_ee_cb.cur_ee);
@@ -2703,10 +2706,13 @@ void nfa_ee_nci_disc_req_ntf(tNFA_EE_MSG* p_data) {
         p_cb->ee_status = NFA_EE_STATUS_ACTIVE | NFA_EE_STATUS_MEP_MASK;
       }
       if (p_cbk->info[xx].tech_n_mode == NFC_DISCOVERY_TYPE_LISTEN_A) {
+        listen_cnt++;
         p_cb->la_protocol = p_cbk->info[xx].protocol;
       } else if (p_cbk->info[xx].tech_n_mode == NFC_DISCOVERY_TYPE_LISTEN_B) {
+        listen_cnt++;
         p_cb->lb_protocol = p_cbk->info[xx].protocol;
       } else if (p_cbk->info[xx].tech_n_mode == NFC_DISCOVERY_TYPE_LISTEN_F) {
+        listen_cnt++;
         p_cb->lf_protocol = p_cbk->info[xx].protocol;
       } else if (p_cbk->info[xx].tech_n_mode ==
                  NFC_DISCOVERY_TYPE_LISTEN_B_PRIME) {
@@ -2717,17 +2723,22 @@ void nfa_ee_nci_disc_req_ntf(tNFA_EE_MSG* p_data) {
         nfa_ee_report_event(p_cb->p_ee_cback, NFA_EE_DISCOVER_REQ_EVT,
                             &nfa_ee_cback_data);
       }
-      LOG(VERBOSE) << StringPrintf(
-          "%s:  nfcee_id=0x%x ee_status=0x%x ecb_flags=0x%x la_protocol=0x%x "
-          "lb_protocol=0x%x lf_protocol=0x%x",
-          __func__, p_cb->nfcee_id, p_cb->ee_status, p_cb->ecb_flags,
-          p_cb->la_protocol, p_cb->lb_protocol, p_cb->lf_protocol);
+      if (listen_cnt) {
+        LOG(VERBOSE) << StringPrintf(
+            "%s:  nfcee_id=0x%x ee_status=0x%x ecb_flags=0x%x la_protocol=0x%x "
+            "lb_protocol=0x%x lf_protocol=0x%x",
+            __func__, p_cb->nfcee_id, p_cb->ee_status, p_cb->ecb_flags,
+            p_cb->la_protocol, p_cb->lb_protocol, p_cb->lf_protocol);
+      }
     } else {
       if (p_cbk->info[xx].tech_n_mode == NFC_DISCOVERY_TYPE_LISTEN_A) {
+        listen_cnt++;
         p_cb->la_protocol = 0;
       } else if (p_cbk->info[xx].tech_n_mode == NFC_DISCOVERY_TYPE_LISTEN_B) {
+        listen_cnt++;
         p_cb->lb_protocol = 0;
       } else if (p_cbk->info[xx].tech_n_mode == NFC_DISCOVERY_TYPE_LISTEN_F) {
+        listen_cnt++;
         p_cb->lf_protocol = 0;
       } else if (p_cbk->info[xx].tech_n_mode ==
                  NFC_DISCOVERY_TYPE_LISTEN_B_PRIME) {
@@ -2743,7 +2754,7 @@ void nfa_ee_nci_disc_req_ntf(tNFA_EE_MSG* p_data) {
   }
 
   /* Report NFA_EE_DISCOVER_REQ_EVT for all active NFCEE */
-  if (report_ntf) nfa_ee_report_discover_req_evt();
+  if (report_ntf && listen_cnt) nfa_ee_report_discover_req_evt();
 }
 
 /*******************************************************************************
diff --git a/libnfc-nci/src/nfa/hci/nfa_hci_main.cc b/libnfc-nci/src/nfa/hci/nfa_hci_main.cc
index c5c5e40da..51df35067 100644
--- a/libnfc-nci/src/nfa/hci/nfa_hci_main.cc
+++ b/libnfc-nci/src/nfa/hci/nfa_hci_main.cc
@@ -557,9 +557,8 @@ void nfa_hci_enable_one_nfcee(void) {
       if (nfa_ee_cb.isDiscoveryStopped == true) {
         nfa_dm_act_start_rf_discovery(nullptr);
         nfa_ee_cb.isDiscoveryStopped = false;
-        tNFA_EE_ECB* p_cb = nfa_ee_find_ecb(nfceeid);
         tNFA_EE_CBACK_DATA nfa_ee_cback_data;
-        p_cb->p_ee_cback(NFA_EE_ENABLED_EVT, &nfa_ee_cback_data);
+        nfa_ee_report_event(nullptr, NFA_EE_ENABLED_EVT, &nfa_ee_cback_data);
       }
     }
   }
diff --git a/libnfc-nci/src/nfa/include/nfa_ee_int.h b/libnfc-nci/src/nfa/include/nfa_ee_int.h
index 63a00ad73..5233bdcc0 100644
--- a/libnfc-nci/src/nfa/include/nfa_ee_int.h
+++ b/libnfc-nci/src/nfa/include/nfa_ee_int.h
@@ -110,9 +110,9 @@ typedef uint8_t tNFA_EE_CONN_ST;
 
 #define NFA_EE_MAX_AID_CFG_LEN (510)
 // Technology A/B/F reserved: 5*3 = 15
-// Protocol ISODEP/NFCDEP/T3T reserved: 5*3 = 15
-// Extends (APDU pattern/SC)reserved: 30
-#define NFA_EE_MAX_PROTO_TECH_EXT_ROUTE_LEN 60
+// Protocol ISODEP reserved: 5
+// Extends (default SC)reserved: 6
+#define NFA_EE_MAX_PROTO_TECH_EXT_ROUTE_LEN 26
 
 #define NFA_EE_SYSTEM_CODE_LEN 02
 #define NFA_EE_SYSTEM_CODE_TLV_SIZE 06
diff --git a/libnfc-nci/src/nfc/include/nfc_int.h b/libnfc-nci/src/nfc/include/nfc_int.h
index fced0ce3a..e5fd92109 100644
--- a/libnfc-nci/src/nfc/include/nfc_int.h
+++ b/libnfc-nci/src/nfc/include/nfc_int.h
@@ -44,7 +44,6 @@
 
 /* NFC Timer events */
 #define NFC_TTYPE_NCI_WAIT_RSP 0
-#define NFC_TTYPE_WAIT_2_DEACTIVATE 1
 #define NFC_WAIT_RSP_RAW_VS 0x02
 #define NFC_TTYPE_WAIT_MODE_SET_NTF 2
 
@@ -74,8 +73,6 @@ enum {
 typedef uint8_t tNFC_STATE;
 
 /* NFC control block flags */
-/* NFC_Deactivate () is called and the NCI cmd is not sent   */
-#define NFC_FL_DEACTIVATING 0x0001
 /* restarting NFCC after PowerOffSleep          */
 #define NFC_FL_RESTARTING 0x0002
 /* enterning power off sleep mode               */
@@ -183,7 +180,6 @@ typedef struct {
   TIMER_LIST_Q timer_queue; /* 1-sec timer event queue */
   TIMER_LIST_Q quick_timer_queue;
   TIMER_LIST_ENT mode_set_ntf_timer; /* Timer to wait for deactivation */
-  TIMER_LIST_ENT deactivate_timer;   /* Timer to wait for deactivation */
 
   tNFC_STATE nfc_state;
   bool reassembly; /* Reassemble fragmented data pkt */
@@ -253,7 +249,6 @@ extern void nfc_data_event(tNFC_CONN_CB* p_cb);
 
 extern uint8_t nfc_ncif_send_data(tNFC_CONN_CB* p_cb, NFC_HDR* p_data);
 extern void nfc_ncif_cmd_timeout(void);
-extern void nfc_wait_2_deactivate_timeout(void);
 extern void nfc_mode_set_ntf_timeout(void);
 
 extern bool nfc_ncif_process_event(NFC_HDR* p_msg);
diff --git a/libnfc-nci/src/nfc/nfc/nfc_main.cc b/libnfc-nci/src/nfc/nfc/nfc_main.cc
index 110ae887b..dfd00b746 100644
--- a/libnfc-nci/src/nfc/nfc/nfc_main.cc
+++ b/libnfc-nci/src/nfc/nfc/nfc_main.cc
@@ -375,7 +375,6 @@ void nfc_set_state(tNFC_STATE nfc_state) {
 **
 *******************************************************************************/
 void nfc_gen_cleanup(void) {
-  nfc_cb.flags &= ~NFC_FL_DEACTIVATING;
   if (!gki_utils) {
     gki_utils = new GkiUtils();
   }
@@ -391,8 +390,6 @@ void nfc_gen_cleanup(void) {
   nfc_cb.flags &= ~(NFC_FL_CONTROL_REQUESTED | NFC_FL_CONTROL_GRANTED |
                     NFC_FL_HAL_REQUESTED);
 
-  nfc_stop_timer(&nfc_cb.deactivate_timer);
-
   /* Reset the connection control blocks */
   nfc_reset_all_conn_cbs();
 
@@ -1318,15 +1315,6 @@ tNFC_STATUS NFC_Deactivate(tNFC_DEACT_TYPE deactivate_type) {
     LOG(VERBOSE) << StringPrintf("%s: act_protocol=%x credits=%d/%d", __func__,
                                  p_cb->act_protocol, p_cb->init_credits,
                                  p_cb->num_buff);
-    if ((p_cb->act_protocol == NCI_PROTOCOL_NFC_DEP) &&
-        (p_cb->init_credits != p_cb->num_buff)) {
-      nfc_cb.flags |= NFC_FL_DEACTIVATING;
-      nfc_cb.deactivate_timer.param = (uintptr_t)deactivate_type;
-      nfc_start_timer(&nfc_cb.deactivate_timer,
-                      (uint16_t)(NFC_TTYPE_WAIT_2_DEACTIVATE),
-                      NFC_DEACTIVATE_TIMEOUT);
-      return status;
-    }
   }
 
   status = nci_snd_deactivate_cmd(deactivate_type);
diff --git a/libnfc-nci/src/nfc/nfc/nfc_ncif.cc b/libnfc-nci/src/nfc/nfc/nfc_ncif.cc
index a1595caed..92a4af382 100644
--- a/libnfc-nci/src/nfc/nfc/nfc_ncif.cc
+++ b/libnfc-nci/src/nfc/nfc/nfc_ncif.cc
@@ -109,21 +109,6 @@ void nfc_ncif_cmd_timeout(void) {
   }
 }
 
-/*******************************************************************************
-**
-** Function         nfc_wait_2_deactivate_timeout
-**
-** Description      Handle a command timeout
-**
-** Returns          void
-**
-*******************************************************************************/
-void nfc_wait_2_deactivate_timeout(void) {
-  LOG(ERROR) << __func__;
-  nfc_cb.flags &= ~NFC_FL_DEACTIVATING;
-  nci_snd_deactivate_cmd((uint8_t)nfc_cb.deactivate_timer.param);
-}
-
 /*******************************************************************************
 **
 ** Function         nfc_ncif_send_data
@@ -154,20 +139,6 @@ uint8_t nfc_ncif_send_data(tNFC_CONN_CB* p_cb, NFC_HDR* p_data) {
                                p_cb->conn_id, p_cb->num_buff, p_cb->tx_q.count);
   if (p_cb->id == NFC_RF_CONN_ID) {
     if (nfc_cb.nfc_state != NFC_STATE_OPEN) {
-      if (nfc_cb.nfc_state == NFC_STATE_CLOSING) {
-        if ((p_data == nullptr) && /* called because credit from NFCC */
-            (nfc_cb.flags & NFC_FL_DEACTIVATING)) {
-          if (p_cb->init_credits == p_cb->num_buff) {
-            /* all the credits are back */
-            nfc_cb.flags &= ~NFC_FL_DEACTIVATING;
-            LOG(VERBOSE) << StringPrintf(
-                "%s: deactivating NFC-DEP init_credits=%d, num_buff=%d",
-                __func__, p_cb->init_credits, p_cb->num_buff);
-            nfc_stop_timer(&nfc_cb.deactivate_timer);
-            nci_snd_deactivate_cmd((uint8_t)nfc_cb.deactivate_timer.param);
-          }
-        }
-      }
       return NCI_STATUS_FAILED;
     }
   }
diff --git a/libnfc-nci/src/nfc/nfc/nfc_task.cc b/libnfc-nci/src/nfc/nfc/nfc_task.cc
index d2109d71b..79fdea32b 100644
--- a/libnfc-nci/src/nfc/nfc/nfc_task.cc
+++ b/libnfc-nci/src/nfc/nfc/nfc_task.cc
@@ -118,10 +118,6 @@ void nfc_process_timer_evt(void) {
       case NFC_TTYPE_NCI_WAIT_RSP:
         nfc_ncif_cmd_timeout();
         break;
-
-      case NFC_TTYPE_WAIT_2_DEACTIVATE:
-        nfc_wait_2_deactivate_timeout();
-        break;
       case NFC_TTYPE_WAIT_MODE_SET_NTF:
         nfc_mode_set_ntf_timeout();
         break;
diff --git a/libnfc-nci/src/nfc/tags/rw_t4t.cc b/libnfc-nci/src/nfc/tags/rw_t4t.cc
index 0c9c32fc4..93153089e 100644
--- a/libnfc-nci/src/nfc/tags/rw_t4t.cc
+++ b/libnfc-nci/src/nfc/tags/rw_t4t.cc
@@ -31,6 +31,7 @@
 #include "nfa_nfcee_int.h"
 #include "nfa_rw_int.h"
 #include "nfc_api.h"
+#include "nfc_config.h"
 #include "nfc_int.h"
 #include "nfc_target.h"
 #include "rw_api.h"
@@ -39,6 +40,7 @@
 using android::base::StringPrintf;
 
 extern unsigned char appl_dta_mode_flag;
+extern std::vector<uint8_t> t4tNfceeAidBuf;
 
 /* main state */
 /* T4T is not activated                 */
@@ -1260,14 +1262,26 @@ static bool rw_t4t_select_application(uint8_t version) {
   } else if ((version == T4T_VERSION_2_0) || /* this is for V2.0 */
              (version == T4T_VERSION_3_0))   /* this is for V3.0 */
   {
-    UINT8_TO_BE_STREAM(p, T4T_V20_NDEF_TAG_AID_LEN);
+    if (t4tNfceeAidBuf.size() == 0 || !(NFA_T4tNfcEeIsProcessing())) {
+      UINT8_TO_BE_STREAM(p, T4T_V20_NDEF_TAG_AID_LEN);
 
-    memcpy(p, t4t_v20_ndef_tag_aid, T4T_V20_NDEF_TAG_AID_LEN);
-    p += T4T_V20_NDEF_TAG_AID_LEN;
+      memcpy(p, t4t_v20_ndef_tag_aid, T4T_V20_NDEF_TAG_AID_LEN);
+      p += T4T_V20_NDEF_TAG_AID_LEN;
 
-    UINT8_TO_BE_STREAM(p, 0x00); /* Le set to 0x00 */
+      UINT8_TO_BE_STREAM(p, 0x00); /* Le set to 0x00 */
 
-    p_c_apdu->len = T4T_CMD_MAX_HDR_SIZE + T4T_V20_NDEF_TAG_AID_LEN + 1;
+      p_c_apdu->len = T4T_CMD_MAX_HDR_SIZE + T4T_V20_NDEF_TAG_AID_LEN + 1;
+    } else {
+      uint8_t* t4tAidBuf = t4tNfceeAidBuf.data();
+      UINT8_TO_BE_STREAM(p, t4tNfceeAidBuf.size());
+
+      memcpy(p, t4tAidBuf, t4tNfceeAidBuf.size());
+      p += t4tNfceeAidBuf.size();
+
+      UINT8_TO_BE_STREAM(p, 0x00); /* Le set to 0x00 */
+
+      p_c_apdu->len = T4T_CMD_MAX_HDR_SIZE + t4tNfceeAidBuf.size() + 1;
+    }
   } else {
     GKI_freebuf(p_c_apdu);
     return false;
diff --git a/libnfc-nci/src/nfc_vendor_extn/NfcVendorExtn.cc b/libnfc-nci/src/nfc_vendor_extn/NfcVendorExtn.cc
index dfbf6b22a..5277df828 100644
--- a/libnfc-nci/src/nfc_vendor_extn/NfcVendorExtn.cc
+++ b/libnfc-nci/src/nfc_vendor_extn/NfcVendorExtn.cc
@@ -257,7 +257,12 @@ void phNfcExtn_LibClose() {
   }
   if (p_oem_extn_handle != NULL) {
     LOG(DEBUG) << StringPrintf("%s: Closing %s!!", __func__, mLibPathName.c_str());
-    dlclose(p_oem_extn_handle);
+    int32_t status = dlclose(p_oem_extn_handle);
+    dlerror(); /* Clear any existing error */
+    if (status != 0) {
+      LOG(ERROR) << StringPrintf("%s: Closing %s failed !!", __func__,
+                                 mLibPathName.c_str());
+    }
     p_oem_extn_handle = NULL;
   }
 }
diff --git a/libnfc-nci/src/nfc_vendor_extn/include/NfcVendorExtn.h b/libnfc-nci/src/nfc_vendor_extn/include/NfcVendorExtn.h
index 7d35fa8cc..b78ea90d5 100644
--- a/libnfc-nci/src/nfc_vendor_extn/include/NfcVendorExtn.h
+++ b/libnfc-nci/src/nfc_vendor_extn/include/NfcVendorExtn.h
@@ -94,6 +94,7 @@ typedef enum {
   HANDLE_NFC_HAL_POWER_CYCLE,
   HANDLE_NFC_GET_MAX_NFCEE,
   HANDLE_NFC_HAL_CLOSE,
+  HANDLE_NFC_DEVICE_SHUTDOWN,
 } NfcExtEvent_t;
 
 typedef enum {
diff --git a/libnfc-nci/tests/Android.bp b/libnfc-nci/tests/Android.bp
index c217e972d..182a4ff3c 100644
--- a/libnfc-nci/tests/Android.bp
+++ b/libnfc-nci/tests/Android.bp
@@ -92,4 +92,7 @@ cc_test {
     },
     auto_gen_config: true,
     min_sdk_version: "36",
+    visibility: [
+        "//platform_testing:__subpackages__",
+    ],
 }
diff --git a/tests/cts/hostsidetests/multidevices/Android.bp b/tests/cts/hostsidetests/multidevices/Android.bp
index b0b2903fc..7169ffdbb 100644
--- a/tests/cts/hostsidetests/multidevices/Android.bp
+++ b/tests/cts/hostsidetests/multidevices/Android.bp
@@ -37,7 +37,7 @@ python_test_host {
     test_config: "AndroidTest.xml",
     device_common_data: [
         ":NfcEmulatorTestApp",
-        ":NfcEmulatorApduApp",
+        ":EmulatorApduApp",
     ],
     test_options: {
         unit_test: false,
diff --git a/tests/cts/hostsidetests/multidevices/AndroidTest.xml b/tests/cts/hostsidetests/multidevices/AndroidTest.xml
index ad5cd2096..b7727cfaa 100644
--- a/tests/cts/hostsidetests/multidevices/AndroidTest.xml
+++ b/tests/cts/hostsidetests/multidevices/AndroidTest.xml
@@ -35,5 +35,5 @@
 
     <option name="mobly_pkg" key="file" value="CtsNfcHceMultiDeviceTestCases" />
     <option name="build_apk" key="file" value="NfcEmulatorTestApp.apk" />
-    <option name="build_apk" key="file" value="NfcEmulatorApduApp.apk" />
+    <option name="build_apk" key="file" value="EmulatorApduApp.apk" />
 </configuration>
diff --git a/tests/cts/hostsidetests/multidevices/cts_nfc_hce_multi_device_test.py b/tests/cts/hostsidetests/multidevices/cts_nfc_hce_multi_device_test.py
index bfc4dae7a..2ad06e7b6 100644
--- a/tests/cts/hostsidetests/multidevices/cts_nfc_hce_multi_device_test.py
+++ b/tests/cts/hostsidetests/multidevices/cts_nfc_hce_multi_device_test.py
@@ -34,6 +34,7 @@ acts as an NFC reader. The devices should be placed back to back.
 from http.client import HTTPSConnection
 import json
 import logging
+import re
 import ssl
 import sys
 import time
@@ -121,10 +122,31 @@ Polling frame vendor specific gain value dropped on power increase
 _FAILED_FRAME_TYPE_INVALID = "Polling frame type is invalid"
 _FAILED_FRAME_DATA_INVALID = "Polling frame data is invalid"
 
+_MAINLINE_MODULE_VERSION_REGEX = re.compile(
+    r"package:(?P<package>[\S]+) versionCode:(?P<version>\d+)"
+)
 
 
 class CtsNfcHceMultiDeviceTestCases(base_test.BaseTestClass):
 
+    def record_mainline_version(self, ad: android_device.AndroidDevice) -> None:
+      """Records NFC mainline version in Android device info."""
+      apex = "com.google.android.nfcservices"
+      if apex in ad.device_info["user_added_info"]:
+        return
+
+      try:
+        mainline_info = ad.adb.shell(
+            f"pm list packages --apex-only --show-versioncode | grep {apex}"
+        ).decode().strip()
+      except adb.AdbError:
+        ad.log.debug("No mainline modules found")
+        return
+
+      match = _MAINLINE_MODULE_VERSION_REGEX.match(mainline_info)
+      if match is not None:
+        ad.add_device_info(apex, match.group("version"))
+
     def _set_up_emulator(self, *args, start_emulator_fun=None, service_list=[],
                  expected_service=None, is_payment=False, preferred_service=None,
                  payment_default_service=None, should_disable_services_on_destroy=True):
@@ -226,6 +248,7 @@ class CtsNfcHceMultiDeviceTestCases(base_test.BaseTestClass):
         try:
             devices = self.register_controller(android_device)[:1]
             self.emulator = devices[0]
+            self.record_mainline_version(self.emulator)
 
             self._setup_failure_reason = (
                 'Cannot load emulator snippet. Is NfcEmulatorTestApp.apk '
@@ -606,8 +629,32 @@ class CtsNfcHceMultiDeviceTestCases(base_test.BaseTestClass):
         """
         self._set_up_emulator(
             False, start_emulator_fun=self.emulator.nfc_emulator.startOffHostEmulatorActivity)
+        self._set_up_reader_and_assert_transaction(expected_service=_OFFHOST_SERVICE)
 
+    @CddTest(requirements = ["7.4.4/C-2-2", "7.4.4/C-1-2"])
+    def test_offhost_aid_selected_event_listener(self):
+        """Tests successful APDU exchange between offhost service and reader and verifies that
+        offhost aid selected listener is invoked.
+
+        Test Steps:
+        1. Start emulator activity.
+        2. Set callback handler for when reader TestPass event is received.
+        3. Start reader activity, which should trigger APDU exchange between
+        reader and emulator.
+        4. Verifies that off host aid selected event listener is received
+
+        Verifies:
+        1. Verifies offhost aid selected listener invocation.
+        """
+        asserts.skip_if(int(self.emulator.build_info[
+                            android_device.BuildInfoConstants.BUILD_VERSION_SDK.build_info_key]) <= 36,
+                        "Skipping aid selected tests on SDK < 36")
+        offhost_aid_selected_handler = self.emulator.nfc_emulator.asyncWaitForOffHostAidSelected(
+            'OffHostAidSelected')
+        self._set_up_emulator(
+            False, start_emulator_fun=self.emulator.nfc_emulator.startOffHostEmulatorActivity)
         self._set_up_reader_and_assert_transaction(expected_service=_OFFHOST_SERVICE)
+        offhost_aid_selected_handler.waitAndGet('OffHostAidSelected', _NFC_TIMEOUT_SEC)
 
     @CddTest(requirements = ["7.4.4/C-2-2", "7.4.4/C-1-2"])
     def test_on_and_offhost_service(self):
@@ -990,6 +1037,7 @@ class CtsNfcHceMultiDeviceTestCases(base_test.BaseTestClass):
         )
 
         self.emulator.nfc_emulator.setNfcState(False)
+        time.sleep(2) # Let NFC stack complete initialization.
         self.emulator.nfc_emulator.setNfcState(True)
 
         self._set_up_reader_and_assert_transaction(expected_service=_PAYMENT_SERVICE_1)
@@ -1025,6 +1073,8 @@ class CtsNfcHceMultiDeviceTestCases(base_test.BaseTestClass):
             start_emulator_fun=self.emulator.nfc_emulator.startPollingFrameEmulatorActivity
         )
 
+        time.sleep(3) # Let NFC stack complete onServicesUpdated.
+
         timed_pn532 = TimedWrapper(self.pn532)
         testcases = [
             POLLING_FRAME_ON,
@@ -1036,8 +1086,6 @@ class CtsNfcHceMultiDeviceTestCases(base_test.BaseTestClass):
             *POLLING_FRAMES_TYPE_B_SPECIAL,
             *POLLING_FRAMES_TYPE_B_LONG,
             *POLLING_FRAMES_TYPE_B_LONG,
-            *POLLING_FRAMES_TYPE_F_SPECIAL,
-            *POLLING_FRAMES_TYPE_F_SPECIAL,
             POLLING_FRAME_OFF,
         ]
         # 3. Transmit polling frames
@@ -1156,7 +1204,6 @@ class CtsNfcHceMultiDeviceTestCases(base_test.BaseTestClass):
             POLLING_FRAME_ON,
             *POLLING_FRAMES_TYPE_A_SPECIAL,
             *POLLING_FRAMES_TYPE_B_SPECIAL,
-            *POLLING_FRAMES_TYPE_F_SPECIAL,
             POLLING_FRAME_OFF
         ] * 2
 
diff --git a/tests/cts/tests/Android.bp b/tests/cts/tests/Android.bp
index 22843e619..9cc773520 100644
--- a/tests/cts/tests/Android.bp
+++ b/tests/cts/tests/Android.bp
@@ -25,7 +25,7 @@ android_test {
         "android.nfc.flags-aconfig-java",
         "android.permission.flags-aconfig-java",
         "com.android.nfc.flags-aconfig-java",
-        "com.android.nfc.module.flags-aconfig-java",
+        "com.android.nfc.module.flags-aconfig-exported-java",
         "ctstestrunner-axt",
         "compatibility-device-util-axt",
         "flag-junit",
@@ -33,7 +33,7 @@ android_test {
         "testables",
         "testng",
         "androidx.appcompat_appcompat",
-        "CtsAppTestStubsShared",
+        "cts_app_test_shared_lib",
     ],
     srcs: [
         "src/android/nfc/cts/*.java",
@@ -62,6 +62,7 @@ android_test {
         "mcts-nfc",
     ],
     min_sdk_version: "36",
+    jarjar_rules: ":nfc-cts-jarjar-rules",
 }
 
 android_test {
@@ -89,4 +90,12 @@ android_test {
     ],
     test_config: "InteractiveAndroidTest.xml",
     min_sdk_version: "36",
+    jarjar_rules: ":nfc-cts-jarjar-rules",
+}
+
+filegroup {
+    name: "nfc-cts-jarjar-rules",
+    srcs: [
+        "jarjar-rules.txt",
+    ],
 }
diff --git a/tests/cts/tests/jarjar-rules.txt b/tests/cts/tests/jarjar-rules.txt
new file mode 100644
index 000000000..a09b26526
--- /dev/null
+++ b/tests/cts/tests/jarjar-rules.txt
@@ -0,0 +1,5 @@
+# Rename the flag package included in the CTS tests to prevent runtime collisions with the same flag
+# package included in the framework jar.
+# See https://yaqs.corp.google.com/eng/q/1929945272444518400#a3 for more info.
+
+rule com.android.nfc.module.flags.** com.android.nfc.module.cts.flags.@1
diff --git a/tests/cts/tests/src/android/nfc/cts/CardEmulationTest.java b/tests/cts/tests/src/android/nfc/cts/CardEmulationTest.java
index f8f056c46..40dc2c85a 100644
--- a/tests/cts/tests/src/android/nfc/cts/CardEmulationTest.java
+++ b/tests/cts/tests/src/android/nfc/cts/CardEmulationTest.java
@@ -110,6 +110,11 @@ public class CardEmulationTest {
         return pm.hasSystemFeature(PackageManager.FEATURE_NFC_OFF_HOST_CARD_EMULATION_ESE);
     }
 
+    private boolean supportsTelephonySubscription() {
+        final PackageManager pm = InstrumentationRegistry.getContext().getPackageManager();
+        return pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION);
+    }
+
     @Before
     public void setUp() throws NoSuchFieldException, RemoteException, InterruptedException {
         assumeTrue("Device must support NFC HCE", supportsHardware());
@@ -117,6 +122,12 @@ public class CardEmulationTest {
         mAdapter = NfcAdapter.getDefaultAdapter(mContext);
         assertNotNull("NFC Adapter is null", mAdapter);
         assertTrue("NFC Adapter could not be enabled", NfcUtils.enableNfc(mAdapter, mContext));
+
+        CardEmulation cardEmulation = CardEmulation.getInstance(mAdapter);
+        cardEmulation.setShouldDefaultToObserveModeForService(new ComponentName(mContext,
+                CustomHostApduService.class), false);
+        cardEmulation.setShouldDefaultToObserveModeForService(new ComponentName(mContext,
+                CtsMyHostApduService.class), false);
     }
 
     @After
@@ -124,6 +135,11 @@ public class CardEmulationTest {
         if (mAdapter != null && mContext != null) {
             Assert.assertTrue("Failed to enable NFC in test cleanup",
                 NfcUtils.enableNfc(mAdapter, mContext));
+            CardEmulation cardEmulation = CardEmulation.getInstance(mAdapter);
+            cardEmulation.setShouldDefaultToObserveModeForService(new ComponentName(mContext,
+                    CustomHostApduService.class), false);
+            cardEmulation.setShouldDefaultToObserveModeForService(new ComponentName(mContext,
+                    CtsMyHostApduService.class), false);
         } else {
             Log.w("CardEmulationTest", "mAdapter or mContext is null");
         }
@@ -510,6 +526,9 @@ public class CardEmulationTest {
                 }
             }
         }
+        @Override
+        public void onOffHostAidSelected(String aid, String offHostSecureElement) { }
+
 
         public void onListenersRegistered() {
             if (mLatch != null) {
@@ -637,6 +656,9 @@ public class CardEmulationTest {
             assertTrue((boolean)event.mState);
 
             assertFalse(adapter.isObserveModeEnabled());
+
+            Thread.sleep(1_000); // Drain out all incoming events.
+
             eventPollLoopReceiver.setNumEventsToWaitFor(1);
 
             assertTrue(adapter.setObserveModeEnabled(true));
@@ -1117,6 +1139,61 @@ public class CardEmulationTest {
         }
     }
 
+    @RequiresFlagsEnabled({com.android.nfc.module.flags.Flags.FLAG_SCREEN_STATE_ATTRIBUTE_TOGGLE})
+    @ApiTest(apis = {
+            "android.nfc.cardemulation.CardEmulation.setRequireDeviceScreenOnForService",
+            "android.nfc.cardemulation.CardEmulation.isDeviceScreenOnRequiredForService",
+    })
+    @Test
+    public void testToggleRequireDeviceScreenOn() {
+        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
+        adapter.notifyHceDeactivated();
+        Activity activity = createAndResumeActivity();
+        CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
+        ComponentName service = new ComponentName(mContext, CtsMyHostApduService.class);
+        try {
+            assertTrue(cardEmulation.setPreferredService(activity, service));
+
+            cardEmulation.setRequireDeviceScreenOnForService(service, true);
+            assertTrue(cardEmulation.isDeviceScreenOnRequiredForService(service));
+
+            cardEmulation.setRequireDeviceScreenOnForService(service, false);
+            assertFalse(cardEmulation.isDeviceScreenOnRequiredForService(service));
+        } finally {
+            assertTrue(cardEmulation.unsetPreferredService(activity));
+            activity.finish();
+            adapter.notifyHceDeactivated();
+        }
+    }
+
+    @RequiresFlagsEnabled({com.android.nfc.module.flags.Flags.FLAG_SCREEN_STATE_ATTRIBUTE_TOGGLE})
+    @ApiTest(apis = {
+            "android.nfc.cardemulation.CardEmulation.setRequireDeviceUnlockForService",
+            "android.nfc.cardemulation.CardEmulation.isDeviceUnlockRequiredForService",
+    })
+    @Test
+    public void testToggleRequireDeviceUnlock() {
+        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
+        adapter.notifyHceDeactivated();
+        Activity activity = createAndResumeActivity();
+        CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
+        ComponentName service = new ComponentName(mContext, CtsMyHostApduService.class);
+        try {
+            assertTrue(cardEmulation.setPreferredService(activity, service));
+
+            cardEmulation.setRequireDeviceUnlockForService(service, true);
+            assertTrue(cardEmulation.isDeviceUnlockRequiredForService(service));
+
+            cardEmulation.setRequireDeviceUnlockForService(service, false);
+            assertFalse(cardEmulation.isDeviceUnlockRequiredForService(service));
+        } finally {
+            assertTrue(cardEmulation.unsetPreferredService(activity));
+            activity.finish();
+            adapter.notifyHceDeactivated();
+        }
+    }
+
+
     @Test
     public void testTypeAOneLoopPollingLoopToForeground() {
         assumeVsrApiGreaterThanUdc();
@@ -1277,14 +1354,23 @@ public class CardEmulationTest {
             frames.add(createFrameWithData(PollingFrame.POLLING_LOOP_TYPE_UNKNOWN,
                     HexFormat.of().parseHex(annotationStringHex2)));
 
-            notifyPollingLoopAndWait(frames, /* serviceName = */ null);
-            assertTrue(cardEmulation.removePollingLoopFilterForService(
-                backgroundServiceName, annotationStringHex1));
-            assertTrue(cardEmulation.removePollingLoopFilterForService(
-                customServiceName, annotationStringHex2));
+            sCurrentPollLoopReceiver = new PollLoopReceiver(frames, null);
+            for (PollingFrame frame : frames) {
+                adapter.notifyPollingLoop(frame);
+            }
+            synchronized (sCurrentPollLoopReceiver) {
+                try {
+                    sCurrentPollLoopReceiver.wait(5000);
+                } catch (InterruptedException ie) {
+                    Assert.assertNull(ie);
+                }
+            }
+            Assert.assertEquals(frames.size(), sCurrentPollLoopReceiver.mReceivedFrames.size());
+            Assert.assertEquals(2, sCurrentPollLoopReceiver.mReceivedServiceNames.size());
         } finally {
             cardEmulation.unsetPreferredService(activity);
             activity.finish();
+            sCurrentPollLoopReceiver = null;
             adapter.notifyHceDeactivated();
         }
     }
@@ -1978,6 +2064,40 @@ public class CardEmulationTest {
 
     }
 
+    @Test
+    @RequiresFlagsEnabled(com.android.nfc.module.flags.Flags.FLAG_GET_POLLING_LOOP_FILTERS)
+    public void testGetPollingLoopFilters() throws NoSuchFieldException {
+        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
+        CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
+        ComponentName customServiceName = new ComponentName(mContext, CustomHostApduService.class);
+        String testName = new Object() {
+        }.getClass().getEnclosingMethod().getName();
+        String annotationStringHex =
+            HexFormat.of().withUpperCase().toHexDigits(testName.hashCode());
+        assertTrue(cardEmulation.registerPollingLoopFilterForService(
+                customServiceName,
+                annotationStringHex, false));
+        assertTrue(cardEmulation.getPollingLoopFiltersForService(customServiceName)
+                       .contains(annotationStringHex));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(com.android.nfc.module.flags.Flags.FLAG_GET_POLLING_LOOP_FILTERS)
+    public void testGetPollingLoopPatternFilters() throws NoSuchFieldException {
+        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
+        CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
+        ComponentName customServiceName = new ComponentName(mContext, CustomHostApduService.class);
+        String testName = new Object() {
+        }.getClass().getEnclosingMethod().getName();
+        String annotationStringHexPrefix =
+            HexFormat.of().withUpperCase().toHexDigits(testName.hashCode());
+        String annotationStringHexPattern = annotationStringHexPrefix + ".*";
+        assertTrue(cardEmulation.registerPollingLoopPatternFilterForService(
+                customServiceName, annotationStringHexPattern, false));
+        assertTrue(cardEmulation.getPollingLoopPatternFiltersForService(customServiceName)
+                         .contains(annotationStringHexPattern));
+    }
+
     static void ensureUnlocked() {
         final Context context = InstrumentationRegistry.getInstrumentation().getContext();
         final UserManager userManager = context.getSystemService(UserManager.class);
@@ -2446,6 +2566,7 @@ public class CardEmulationTest {
     @RequiresFlagsEnabled(Flags.FLAG_ENABLE_CARD_EMULATION_EUICC)
     @Test
     public void testGetSetDefaultNfcSubscriptionId() {
+        assumeTrue(supportsTelephonySubscription());
         NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
         assertTrue(NfcUtils.enableNfc(adapter, mContext));
         CardEmulation instance = CardEmulation.getInstance(adapter);
@@ -2507,22 +2628,32 @@ public class CardEmulationTest {
                 ArrayList<PollingFrame> frames = new ArrayList<PollingFrame>(1);
                 frames.add(createFrameWithData(PollingFrame.POLLING_LOOP_TYPE_UNKNOWN,
                         HexFormat.of().parseHex("7f71156b")));
+                ExecutorService pool = Executors.newFixedThreadPool(1);
+                CountDownLatch latch = new CountDownLatch(1);
+                CardEmulation.NfcEventCallback nfcCallback =
+                        new CardEmulation.NfcEventCallback() {
+                            @Override
+                            public void onObserveModeStateChanged(boolean isEnabled) {
+                                synchronized (this) {
+                                    if (!isEnabled) {
+                                        latch.countDown();
+                                    }
+                                }
+                            }
+                        };
+                cardEmulation.registerNfcEventCallback(pool, nfcCallback);
                 notifyPollingLoopAndWait(frames, CustomHostApduService.class.getName());
+                Assert.assertTrue("NFC didn't autotransact within 200ms",
+                        latch.await(200, TimeUnit.MILLISECONDS));
                 assertFalse(adapter.isObserveModeEnabled());
                 adapter.notifyHceDeactivated();
                 activity.finish();
-                try {
-                    Thread.sleep(200);
-                } catch (InterruptedException e) {
-                    throw new RuntimeException(e);
-                }
+                Thread.sleep(200);
                 assertFalse(adapter.isObserveModeEnabled());
-                try {
-                    Thread.sleep(2000);
-                } catch (InterruptedException e) {
-                    throw new RuntimeException(e);
-                }
+                Thread.sleep(2000);
                 assertTrue(adapter.isObserveModeEnabled());
+            } catch (InterruptedException e) {
+                throw new RuntimeException(e);
             } finally {
                 cardEmulation.unsetPreferredService(activity);
                 activity.finish();
@@ -2566,22 +2697,32 @@ public class CardEmulationTest {
                 ArrayList<PollingFrame> frames = new ArrayList<PollingFrame>(1);
                 frames.add(createFrameWithData(PollingFrame.POLLING_LOOP_TYPE_UNKNOWN,
                         HexFormat.of().parseHex("7f71156b")));
+                ExecutorService pool = Executors.newFixedThreadPool(1);
+                CountDownLatch latch = new CountDownLatch(1);
+                CardEmulation.NfcEventCallback nfcCallback =
+                        new CardEmulation.NfcEventCallback() {
+                            @Override
+                            public void onObserveModeStateChanged(boolean isEnabled) {
+                                synchronized (this) {
+                                    if (!isEnabled) {
+                                        latch.countDown();
+                                    }
+                                }
+                            }
+                        };
+                cardEmulation.registerNfcEventCallback(pool, nfcCallback);
                 notifyPollingLoopAndWait(frames, CustomHostApduService.class.getName());
+                Assert.assertTrue("NFC didn't autotransact within 200ms",
+                        latch.await(200, TimeUnit.MILLISECONDS));
                 assertFalse(adapter.isObserveModeEnabled());
                 adapter.notifyHceDeactivated();
                 activity.finish();
-                try {
-                    Thread.sleep(200);
-                } catch (InterruptedException e) {
-                    throw new RuntimeException(e);
-                }
+                Thread.sleep(200);
                 assertFalse(adapter.isObserveModeEnabled());
-                try {
-                    Thread.sleep(2000);
-                } catch (InterruptedException e) {
-                    throw new RuntimeException(e);
-                }
+                Thread.sleep(2000);
                 assertFalse(adapter.isObserveModeEnabled());
+            } catch (InterruptedException e) {
+                throw new RuntimeException(e);
             } finally {
                 cardEmulation.unsetPreferredService(activity);
                 activity.finish();
diff --git a/tests/cts/tests/src/android/nfc/cts/NfcAdapterTest.java b/tests/cts/tests/src/android/nfc/cts/NfcAdapterTest.java
index 60695fa92..a2dd8214c 100644
--- a/tests/cts/tests/src/android/nfc/cts/NfcAdapterTest.java
+++ b/tests/cts/tests/src/android/nfc/cts/NfcAdapterTest.java
@@ -39,6 +39,7 @@ import android.content.Intent;
 import android.content.pm.PackageManager;
 import android.nfc.Flags;
 import android.nfc.NdefMessage;
+import android.nfc.NdefRecord;
 import android.nfc.NfcAdapter;
 import android.nfc.NfcAntennaInfo;
 import android.nfc.NfcOemExtension;
@@ -72,7 +73,6 @@ import androidx.test.core.app.ApplicationProvider;
 import androidx.test.filters.RequiresDevice;
 
 import org.junit.Assert;
-import org.junit.Assume;
 import org.junit.Before;
 import org.junit.Ignore;
 import org.junit.Rule;
@@ -103,7 +103,7 @@ public class NfcAdapterTest {
 
     private boolean supportsHardware() {
         final PackageManager pm = mContext.getPackageManager();
-        return pm.hasSystemFeature(PackageManager.FEATURE_NFC);
+        return pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY);
     }
 
     @Before
@@ -125,6 +125,7 @@ public class NfcAdapterTest {
 
     @Test
     public void testAddAndRemoveNfcUnlockHandler() {
+        assumeTrue(mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC));
         NfcAdapter adapter = getDefaultAdapter();
         CtsNfcUnlockHandler unlockHandler = new CtsNfcUnlockHandler();
 
@@ -162,6 +163,7 @@ public class NfcAdapterTest {
 
     @Test
     public void testEnableAndDisableForegroundDispatch() throws RemoteException {
+        assumeTrue(mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC));
         NfcAdapter adapter = getDefaultAdapter();
         Activity activity = createAndResumeActivity();
         Intent intent = new Intent(ApplicationProvider.getApplicationContext(),
@@ -178,6 +180,7 @@ public class NfcAdapterTest {
 
     @Test
     public void testEnableAndDisableReaderMode() {
+        assumeTrue(mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC));
         NfcAdapter adapter = getDefaultAdapter();
         Activity activity = createAndResumeActivity();
         Intent intent = new Intent(ApplicationProvider.getApplicationContext(),
@@ -198,6 +201,7 @@ public class NfcAdapterTest {
     @Test
     @RequiresFlagsEnabled(Flags.FLAG_ENABLE_NFC_READER_OPTION)
     public void testEnableAndDisableReaderOption() throws NoSuchFieldException, RemoteException {
+        assumeTrue(mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC));
         NfcAdapter adapter = getDefaultAdapter();
         assumeTrue("Device must support reader option", adapter.isReaderOptionSupported());
 
@@ -333,6 +337,7 @@ public class NfcAdapterTest {
     @Test
     @RequiresFlagsEnabled(Flags.FLAG_ENABLE_NFC_MAINLINE)
     public void testSetReaderMode() {
+        assumeTrue(mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC));
         NfcAdapter adapter = getDefaultAdapter();
         // Verify the API does not crash or throw any exceptions.
         adapter.setReaderModePollingEnabled(true);
@@ -441,23 +446,32 @@ public class NfcAdapterTest {
         CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
         cardEmulation.setShouldDefaultToObserveModeForService(new ComponentName(mContext,
                 CtsMyHostApduService.class), true);
+        cardEmulation.setShouldDefaultToObserveModeForService(new ComponentName(mContext,
+                CustomHostApduService.class), false);
         WalletRoleTestUtils.runWithRole(mContext, WalletRoleTestUtils.CTS_PACKAGE_NAME, () -> {
             CardEmulationTest.ensurePreferredService(CtsMyHostApduService.class, mContext);
-            assertTrue(adapter.isObserveModeEnabled());
-            assertTrue(adapter.setObserveModeEnabled(false));
-            assertFalse(adapter.isObserveModeEnabled());
+            assertTrue("observe mode isn't enabled after setting preferred service to one that"
+                    + " defaults it on", adapter.isObserveModeEnabled());
+            assertTrue("set observe mode to false failed", adapter.setObserveModeEnabled(false));
+            assertFalse("observe mode is still enabled after setting it to false",
+                    adapter.isObserveModeEnabled());
             try {
                 Activity activity = createAndResumeActivity();
                 assertTrue(cardEmulation.setPreferredService(activity,
                         new ComponentName(mContext, CtsMyHostApduService.class)));
                 CardEmulationTest.ensurePreferredService(CtsMyHostApduService.class, mContext);
-                assertFalse(adapter.isObserveModeEnabled());
-                assertTrue(adapter.setObserveModeEnabled(true));
-                assertTrue(adapter.isObserveModeEnabled());
-                assertTrue(cardEmulation.setPreferredService(activity,
+                assertFalse("observe mode enabled after setting preferred service to one that"
+                        + " defaults it enabled, even though preferred service didn't change",
+                        adapter.isObserveModeEnabled());
+                assertTrue("set observe mode enabled failed", adapter.setObserveModeEnabled(true));
+                assertTrue("observe mode disabled after enabling it",
+                        adapter.isObserveModeEnabled());
+                assertTrue("setting preferred service failed",
+                        cardEmulation.setPreferredService(activity,
                         new ComponentName(mContext, CustomHostApduService.class)));
                 CardEmulationTest.ensurePreferredService(CustomHostApduService.class, mContext);
-                assertFalse(adapter.isObserveModeEnabled());
+                assertFalse("observe mode enabled after setting preferred service that disables it",
+                        adapter.isObserveModeEnabled());
             } finally {
                 cardEmulation.setShouldDefaultToObserveModeForService(new ComponentName(mContext,
                         CustomHostApduService.class), false);
@@ -668,6 +682,19 @@ public class NfcAdapterTest {
         }
     }
 
+    @Test
+    @RequiresFlagsEnabled(com.android.nfc.module.flags.Flags.FLAG_NFC_POWER_SAVING_MODE)
+    public void testTogglePowerSavingMode() {
+        assumeTrue(getDefaultAdapter().isPowerSavingModeSupported());
+
+        NfcAdapter adapter = getDefaultAdapter();
+        adapter.setPowerSavingMode(true);
+        assertTrue(adapter.isPowerSavingModeEnabled());
+
+        adapter.setPowerSavingMode(false);
+        assertFalse(adapter.isPowerSavingModeEnabled());
+    }
+
     @Test
     @RequiresFlagsEnabled(Flags.FLAG_NFC_OEM_EXTENSION)
     public void testOemExtension() throws InterruptedException {
@@ -701,8 +728,10 @@ public class NfcAdapterTest {
             T4tNdefNfcee ndefNfcee = nfcOemExtension.getT4tNdefNfcee();
             assertThat(ndefNfcee).isNotNull();
             if (ndefNfcee.isSupported()) {
-                byte[] ndefData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
-
+                String data = "0123456789012345678901234567890123456789";
+                NdefRecord record = NdefRecord.createTextRecord("en", data);
+                NdefMessage message = new NdefMessage(new NdefRecord[]{record});
+                byte[] ndefData = message.toByteArray();
                 byte[] FILE_ID_NDEF_TEST = new byte[]{(byte)0xE1, 0x04};
                 assertThat(ndefNfcee.writeData(bytesToInt(FILE_ID_NDEF_TEST), ndefData))
                                .isEqualTo(T4tNdefNfcee.WRITE_DATA_SUCCESS);
@@ -1044,6 +1073,10 @@ public class NfcAdapterTest {
             isSkipped.accept(false);
         }
 
+        @Override
+        public void onRoutingChangeCompleted() {
+        }
+
         @Override
         public void onHceEventReceived(int action) {
         }
@@ -1263,6 +1296,7 @@ public class NfcAdapterTest {
     @Test
     @RequiresFlagsEnabled(Flags.FLAG_NFC_CHECK_TAG_INTENT_PREFERENCE)
     public void testSetTagIntentAppPreference() throws NoSuchFieldException, RemoteException {
+        assumeTrue(mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC));
         NfcAdapter adapter = getDefaultAdapter();
         assumeTrue("Device must support tag intent app preference",
             adapter.isTagIntentAppPreferenceSupported());
```

