```diff
diff --git a/Android.bp b/Android.bp
index 88b8c09..af11258 100644
--- a/Android.bp
+++ b/Android.bp
@@ -16,8 +16,8 @@ license {
 soong_config_string_variable {
     name: "chip",
     values: [
-        "SR1XX",
-        "SR200",
+        "hbci",
+        "hdll",
     ],
 }
 
@@ -27,9 +27,7 @@ soong_config_module_type {
     config_namespace: "nxp_uwb",
     variables: ["chip"],
     properties: [
-        "cflags",
-        "srcs",
-        "local_include_dirs",
+        "static_libs",
     ],
 }
 
@@ -37,22 +35,14 @@ uwb_cc_defaults {
     name: "uwb_defaults",
     soong_config_variables: {
         chip: {
-            SR200: {
-                cflags: ["-DSR200=TRUE"],
-                srcs: [
-                    "halimpl/hal/sr200/*.cc",
-                ],
-                local_include_dirs: [
-                    "halimpl/hal/sr200",
+            hdll: {
+                static_libs: [
+                    "nxp_uwb_hdll",
                 ],
             },
             conditions_default: {
-                cflags: ["-DSR1XX=TRUE"],
-                srcs: [
-                    "halimpl/hal/sr1xx/*.cc",
-                ],
-                local_include_dirs: [
-                    "halimpl/hal/sr1xx",
+                static_libs: [
+                    "nxp_uwb_hbci",
                 ],
             },
         },
diff --git a/aidl/OWNERS b/OWNERS
similarity index 66%
rename from aidl/OWNERS
rename to OWNERS
index c4ad416..fe8763d 100644
--- a/aidl/OWNERS
+++ b/OWNERS
@@ -1,2 +1,5 @@
 # Bug component: 1042770
 include platform/packages/modules/Uwb:/OWNERS
+
+ikjn@google.com
+purnank@google.com
diff --git a/aidl/uwb_chip.h b/aidl/uwb_chip.h
index 2ccc579..a963bc3 100644
--- a/aidl/uwb_chip.h
+++ b/aidl/uwb_chip.h
@@ -55,7 +55,7 @@ class UwbChip : public BnUwbChip {
       }
     }
   }
-  static void dataCallback(uint16_t data_len, uint8_t* p_data) {
+  static void dataCallback(uint16_t data_len, const uint8_t* p_data) {
       std::vector<uint8_t> data;
       data.assign(p_data, p_data + data_len);
       if (mClientCallback != nullptr) {
diff --git a/extns/inc/uci_defs.h b/extns/inc/uci_defs.h
index 4acfd77..b6e7394 100644
--- a/extns/inc/uci_defs.h
+++ b/extns/inc/uci_defs.h
@@ -68,46 +68,6 @@
 #define UCI_OID_MASK 0x3F
 #define UCI_OID_SHIFT 0
 
-/* builds byte0 of UCI Command and Notification packet */
-#define UCI_MSG_BLD_HDR0(p, mt, gid) \
-  *(p)++ = (uint8_t)(((mt) << UCI_MT_SHIFT) | (gid));
-
-#define UCI_MSG_PBLD_HDR0(p, mt, pbf, gid) \
-  *(p)++ = (uint8_t)(((mt) << UCI_MT_SHIFT) | ((pbf) << UCI_PBF_SHIFT) | (gid));
-
-/* builds byte1 of UCI Command and Notification packet */
-#define UCI_MSG_BLD_HDR1(p, oid) *(p)++ = (uint8_t)(((oid) << UCI_OID_SHIFT));
-
-/* parse byte0 of UCI packet */
-#define UCI_MSG_PRS_HDR0(p, mt, pbf, gid)     \
-  mt = (*(p)&UCI_MT_MASK) >> UCI_MT_SHIFT;    \
-  pbf = (*(p)&UCI_PBF_MASK) >> UCI_PBF_SHIFT; \
-  gid = *(p)++ & UCI_GID_MASK;
-
-/* parse MT and PBF bits of UCI packet */
-#define UCI_MSG_PRS_MT_PBF(p, mt, pbf)     \
-  mt = (*(p)&UCI_MT_MASK) >> UCI_MT_SHIFT; \
-  pbf = (*(p)&UCI_PBF_MASK) >> UCI_PBF_SHIFT;
-
-/* parse byte1 of UCI Cmd/Ntf */
-#define UCI_MSG_PRS_HDR1(p, oid) \
-  oid = (*(p)&UCI_OID_MASK);     \
-  (p)++;
-
-#define UINT8_TO_STREAM(p, u8) \
-  { *(p)++ = (uint8_t)(u8); }
-
-#define ARRAY_TO_STREAM(p, a, len)                                \
-  {                                                               \
-    int ijk;                                                      \
-    for (ijk = 0; ijk < (len); ijk++) *(p)++ = (uint8_t)(a)[ijk]; \
-  }
-
-/* Allocate smallest possible buffer (for platforms with limited RAM) */
-#define UCI_GET_CMD_BUF(paramlen)                                    \
-  ((UWB_HDR*)phUwb_GKI_getbuf((uint16_t)(UWB_HDR_SIZE + UCI_MSG_HDR_SIZE + \
-                                   UCI_MSG_OFFSET_SIZE + (paramlen))))
-
 /**********************************************
  * UCI Core Group-0: Opcodes and size of commands
  **********************************************/
@@ -219,6 +179,7 @@ constexpr uint8_t kSessionType_CCCRanging = 0xA0;
 /* Generic Status Codes */
 #define UCI_STATUS_OK 0x00
 #define UCI_STATUS_FAILED 0x02
+#define UCI_STATUS_SYNTAX_ERROR 0x03
 #define UCI_STATUS_INVALID_PARAM 0x04
 #define UCI_STATUS_COMMAND_RETRY 0x0A
 #define UCI_STATUS_UNKNOWN 0x0B
diff --git a/halimpl/config/SR1XX/libuwb-nxp-SR100S.conf b/halimpl/config/SR1XX/libuwb-nxp-SR100S.conf
index 6743e64..97742ce 100644
--- a/halimpl/config/SR1XX/libuwb-nxp-SR100S.conf
+++ b/halimpl/config/SR1XX/libuwb-nxp-SR100S.conf
@@ -14,13 +14,7 @@ UWB_BOARD_VARIANT_VERSION=0x01
 #DELAY_CALIBRATION_VALUE    E400
 #AOA_CALIBRATION_CTRL       E401
 #DPD_WAKEUP_SRC             E402
-#WTX_COUNT_CONFIG           E403
 #DPD_ENTRY_TIMEOUT          E404
-#WIFI_COEX_FEATURE          E405
-  ##Note: WIFI COEX CONFIG Disabled by default, if required add the
-  ##      config (E4, 05, 04, 00, 3C, 1E, 1E) and update the
-  ##      Lentgh and number of parameter accordingly in the header part.
-  ##      WIFI COEX feature supports only in user binary.
 #GPIO_USAGE_CONFIG          E408
   ##Note: Configure the GPIO for multiple purposes depending on usecase ID
   ##      config(E4, 08, 03, 00, 00, 00)
@@ -28,10 +22,6 @@ UWB_BOARD_VARIANT_VERSION=0x01
 #CLK_CONFIG_CTRL            E430
   ##Note: Config for clock source selection and refer UCI specification
   ##      for more information.
-#UWB_WLAN_5GHZ_CHANNEL_INTERFERENCE_LIST  E432
-  ##Note: List of problematic channels in 5GHz Range, if required add
-  ##      config (E4, 32, 03, 120, 124, 128) and update the
-  ##      Length and number of parameters accordingly in header part.
 # Refer the NXP UCI specification for below configs
 #ANTENNA_RX_IDX_DEFINE   E460
 #ANTENNA_TX_IDX_DEFINE   E461
@@ -45,25 +35,62 @@ UWB_CORE_EXT_DEVICE_DEFAULT_CONFIG={05,
     E4, 65, 06, 01, 03, 03, 00, 01, 01
 }
 
+# This config enable/disable the dpd entry prevention ntf config during init
+# 00 for disable
+# 01 for enable
+UWB_DPD_ENTRY_PREVENTION_NTF_CONFIG=0x01
+
+#This config call's suspend to kernel driver on idle
+#This is only activated when AUTO_SUSPEND_ENABLED=1
+#0=disable
+#1=enable
+AUTO_SUSPEND_ENABLE=0
+#This config defines duration to resume the device before sending any commands
+AUTO_SUSPEND_TIMEOUT_MS=100
+
 ##Note: Below configs are applicable in User_Mode FW only
-##Note: WIFI COEX CONFIG Disabled by default, if required add the
-  ##      config (E4, 05, 04, 00, 3C, 1E, 1E) and update the
-  ##      Lentgh and number of parameter accordingly in the header part.
-  ##      WIFI COEX feature supports only in user binary.
+#WIFI_COEX_FEATURE_ALL_CH  0xF0
+##Note: WIFI_COEX_FEATURE_ALL_CH is disabled by default.
+  ##  Octet[0]: Enable/Disable WiFi CoEx feature
+  ##  0x00: Disable (default)
+  ##  • b[3:0]: Enable/Disable functionality CoEx
+  ##  – 0x1 : Enable CoEx Interface without Debug and without Warning Verbose
+  ##  – 0x2 : Enable CoEx Interface with Debug Verbose only
+  ##  – 0x3 : Enable CoEx Interface with Warnings Verbose only
+  ##  – 0x4 : Enable CoEx Interface with both Debug and Warning Verbose
+  ##  • b[7:4]: CoEx Interface (GPIO) selection:
+  ##  – 0x0 : GPIO Interface
+  ##  – Rest of the values are Reserved
+  ##  Octect[1]: Number of channels N Shall be >= 1 (0 will be rejected by UWBS)
+  ##  N*4 octets to follow
+  ##  Octet[2]: Channel ID
+  ##  Octet[3]: MIN_GUARD_DURATION
+  ##  Octet[4]: MAX_GRANT_DURATION
+  ##  Octet[5]: ADVANCED GRANT DURATION
+  ##  Based on requirement add the below configs:
+  ##  Enable CH5 - (F0, 06, 01, 01, 05, 3C, 1E, 1E)
+  ##  Enable CH9 - (F0, 06, 01, 01, 09, 3C, 1E, 1E)
+  ##  Enable both CH5 and CH9 - (F0, 0A, 01, 02, 05, 3C, 1E, 1E, 09, 3C, 1E, 1E)
+  ##
+  ##  Update the length and number of parameter accordingly in
+  ##  the header part.
+  ##  WIFI COEX feature supports only in user binary.
 #GPIO_USAGE_CONFIG E4 08
-  ## Customer need to set the DPD_WAKEUP_SOURCE as 02 (GPIO1) before applying the GPIO_USAGE_CONFIG command to
-  ## enable time sync notification feature
-UWB_USER_FW_BOOT_MODE_CONFIG={20, 04, 00, 12, 03,
-    E4, 05, 04, 00, 3C, 1E, 1E,
+  ## Customer need to set the DPD_WAKEUP_SOURCE as 02 (GPIO1) before applying
+  ## the GPIO_USAGE_CONFIG command to enable time sync notification feature
+UWB_USER_FW_BOOT_MODE_CONFIG={20, 04, 00, 13, 02,
+    F0, 06, 00, 01, 05, 3C, 1E, 1E,
     E4, 02, 01, 00,
     E4, 08, 03, 00, 00, 00
 }
 
+# Set system time uncertainty value in microsec for CCC ranging
+UWB_INITIATION_TIME_DELTA=200000
+
 #LIST OF UWB CAPABILITY INFO NOT RECEIVED FROM UWBS
 # mapping device caps according to Fira 2.0
 # TODO: Remove once FW support available
-UWB_VENDOR_CAPABILITY={ A7, 04, 01, 00, 00, 00,
-  A8, 04, 05, 00, 00, 00,
+UWB_VENDOR_CAPABILITY={A8, 04, 05, 00, 00, 00,
   E3, 01, 01,
   E4, 04, 64, 00, 00, 00,
   E5, 04, 03, 00, 00, 00,
@@ -71,7 +98,9 @@ UWB_VENDOR_CAPABILITY={ A7, 04, 01, 00, 00, 00,
   E7, 01, 01,
   E8, 04, B0, 04, 00, 00,
   E9, 04, 05, 00, 00, 00,
-  EA, 02, 09, 00
+  EA, 02, 09, 00,
+  AB, 02, 64, 00,
+  EB, 04, 05, 00, 00, 00
 }
 
 ###############################################################################
diff --git a/halimpl/hal/hbci/Android.bp b/halimpl/hal/hbci/Android.bp
new file mode 100644
index 0000000..92c9aad
--- /dev/null
+++ b/halimpl/hal/hbci/Android.bp
@@ -0,0 +1,23 @@
+package {
+    default_applicable_licenses: ["hardware_nxp_uwb_license"],
+}
+
+cc_library_static {
+    name: "nxp_uwb_hbci",
+    srcs: [
+        "NxpUwbChipHbciModule.cc",
+        "phNxpUciHal_hbci_fwd.cc",
+    ],
+    shared_libs: [
+        "android.hardware.uwb-V1-ndk",
+    ],
+    include_dirs: [
+        "hardware/nxp/uwb/extns/inc",
+        "hardware/nxp/uwb/halimpl/hal",
+        "hardware/nxp/uwb/halimpl/inc",
+        "hardware/nxp/uwb/halimpl/inc/common",
+        "hardware/nxp/uwb/halimpl/log",
+        "hardware/nxp/uwb/halimpl/tml",
+        "hardware/nxp/uwb/halimpl/utils",
+    ],
+}
diff --git a/halimpl/hal/sr1xx/NxpUwbChipSr1xx.cc b/halimpl/hal/hbci/NxpUwbChipHbciModule.cc
similarity index 87%
rename from halimpl/hal/sr1xx/NxpUwbChipSr1xx.cc
rename to halimpl/hal/hbci/NxpUwbChipHbciModule.cc
index 2299036..4e80b85 100644
--- a/halimpl/hal/sr1xx/NxpUwbChipSr1xx.cc
+++ b/halimpl/hal/hbci/NxpUwbChipHbciModule.cc
@@ -26,7 +26,6 @@ static void report_binding_status(uint8_t binding_status)
   buffer[2] = 0x00;
   buffer[3] = 0x01;
   buffer[4] = binding_status;
-  nxpucihal_ctrl.rx_data_len = 5;
   if (nxpucihal_ctrl.p_uwb_stack_data_cback != NULL) {
     (*nxpucihal_ctrl.p_uwb_stack_data_cback)(data_len, buffer);
   }
@@ -48,7 +47,7 @@ static bool otp_read_data(const uint8_t channel, const uint8_t param_id, uint8_t
   // NXP_READ_CALIB_DATA_NTF
   bool received = false;
   auto read_calib_ntf_cb =
-  [&] (size_t packet_len, const uint8_t *packet) mutable
+  [&] (size_t packet_len, const uint8_t *packet) mutable -> bool
   {
     // READ_CALIB_DATA_NTF: status(1), length-of-payload(1), payload(N)
     const uint8_t plen = packet[3]; // payload-length
@@ -57,7 +56,7 @@ static bool otp_read_data(const uint8_t channel, const uint8_t param_id, uint8_t
     if (plen < 2) {
       NXPLOG_UCIHAL_E("Otp read: bad payload length %u", plen);
     } else if (p[0] != UCI_STATUS_OK) {
-      NXPLOG_UCIHAL_E("Otp read: bad status=0x%x", nxpucihal_ctrl.p_rx_data[4]);
+      NXPLOG_UCIHAL_E("Otp read: bad status=0x%x", packet[4]);
     } else if (p[1] != len) {
       NXPLOG_UCIHAL_E("Otp read: size mismatch %u (expected %zu for param 0x%x)",
         p[1], len, param_id);
@@ -66,10 +65,11 @@ static bool otp_read_data(const uint8_t channel, const uint8_t param_id, uint8_t
       received = true;
       SEM_POST(&calib_data_ntf_wait);
     }
+    return true;
   };
   auto handler = phNxpUciHal_rx_handler_add(
       UCI_MT_NTF, UCI_GID_PROPRIETARY_0X0A, UCI_MSG_READ_CALIB_DATA,
-      true, true, read_calib_ntf_cb);
+      true, read_calib_ntf_cb);
 
 
   // READ_CALIB_DATA_CMD
@@ -171,7 +171,7 @@ static tHAL_UWB_STATUS sr1xx_do_bind(uint8_t *binding_status, uint8_t *remain_co
   phNxpUciHal_init_cb_data(&binding_ntf_wait, NULL);
 
   auto binding_ntf_cb =
-    [&](size_t packet_len, const uint8_t *packet) mutable
+    [&](size_t packet_len, const uint8_t *packet) mutable -> bool
   {
       if (packet_len == UCI_MSG_UWB_ESE_BINDING_LEN) {
         uint8_t status = packet[UCI_RESPONSE_STATUS_OFFSET];
@@ -186,10 +186,11 @@ static tHAL_UWB_STATUS sr1xx_do_bind(uint8_t *binding_status, uint8_t *remain_co
       } else {
         NXPLOG_UCIHAL_E("UWB_ESE_BINDING_NTF: packet length mismatched %zu", packet_len);
       }
+      return true;
   };
   auto handler = phNxpUciHal_rx_handler_add(
       UCI_MT_NTF, UCI_GID_PROPRIETARY_0X0F, UCI_MSG_UWB_ESE_BINDING,
-      true, true, binding_ntf_cb);
+      true, binding_ntf_cb);
 
   // UWB_ESE_BINDING_CMD
   uint8_t buffer[] = {0x2F, 0x31, 0x00, 0x00};
@@ -230,16 +231,17 @@ static tHAL_UWB_STATUS sr1xx_check_binding_status(uint8_t *binding_status)
   uint8_t binding_status_got = UWB_DEVICE_UNKNOWN;
   phNxpUciHal_Sem_t binding_check_ntf_wait;
   phNxpUciHal_init_cb_data(&binding_check_ntf_wait, NULL);
-  auto binding_check_ntf_cb = [&](size_t packet_len, const uint8_t *packet) mutable {
+  auto binding_check_ntf_cb = [&](size_t packet_len, const uint8_t *packet) mutable -> bool {
     if (packet_len >= UCI_RESPONSE_STATUS_OFFSET) {
       binding_status_got = packet[UCI_RESPONSE_STATUS_OFFSET];
       NXPLOG_UCIHAL_D("Received UWB_ESE_BINDING_CHECK_NTF, binding_status=0x%x", binding_status_got);
       SEM_POST(&binding_check_ntf_wait);
     }
+    return true;
   };
   auto handler = phNxpUciHal_rx_handler_add(
       UCI_MT_NTF, UCI_GID_PROPRIETARY_0X0F, UCI_MSG_UWB_ESE_BINDING_CHECK,
-      true, true, binding_check_ntf_cb);
+      true, binding_check_ntf_cb);
 
   // UWB_ESE_BINDING_CHECK_CMD
   uint8_t lock_cmd[] = {0x2F, 0x32, 0x00, 0x00};
@@ -275,9 +277,9 @@ static int16_t sr1xx_extra_group_delay(const uint8_t ch)
   bool is_calibrated_with_d4x = false;
 
   int has_calibrated_with_fw_config = NxpConfig_GetStr(
-    "cal.fw_version", calibrated_with_fw, sizeof(calibrated_with_fw) - 1);
+      "cal.fw_version", calibrated_with_fw, sizeof(calibrated_with_fw) - 1);
 
-  if ( has_calibrated_with_fw_config ) {
+  if (has_calibrated_with_fw_config) {
     // Conf file has entry of `cal.fw_version`
     if ( ( 0 == memcmp("48.", calibrated_with_fw, 3)) ||
          ( 0 == memcmp("49.", calibrated_with_fw, 3))) {
@@ -321,10 +323,10 @@ static int16_t sr1xx_extra_group_delay(const uint8_t ch)
   return required_compensation;
 }
 
-class NxpUwbChipSr1xx final : public NxpUwbChip {
+class NxpUwbChipHbciModule final : public NxpUwbChip {
 public:
-  NxpUwbChipSr1xx();
-  virtual ~NxpUwbChipSr1xx();
+  NxpUwbChipHbciModule();
+  virtual ~NxpUwbChipHbciModule();
 
   tHAL_UWB_STATUS chip_init();
   tHAL_UWB_STATUS core_init();
@@ -335,9 +337,9 @@ public:
 
 private:
   tHAL_UWB_STATUS check_binding();
-  void onDeviceStatusNtf(size_t packet_len, const uint8_t* packet);
-  void onGenericErrorNtf(size_t packet_len, const uint8_t* packet);
-  void onBindingStatusNtf(size_t packet_len, const uint8_t* packet);
+  bool onDeviceStatusNtf(size_t packet_len, const uint8_t* packet);
+  bool onGenericErrorNtf(size_t packet_len, const uint8_t* packet);
+  bool onBindingStatusNtf(size_t packet_len, const uint8_t* packet);
 
 private:
   UciHalRxHandler deviceStatusNtfHandler_;
@@ -347,16 +349,16 @@ private:
   uint8_t bindingStatus_;
 };
 
-NxpUwbChipSr1xx::NxpUwbChipSr1xx() :
+NxpUwbChipHbciModule::NxpUwbChipHbciModule() :
   bindingStatus_(UWB_DEVICE_UNKNOWN)
 {
 }
 
-NxpUwbChipSr1xx::~NxpUwbChipSr1xx()
+NxpUwbChipHbciModule::~NxpUwbChipHbciModule()
 {
 }
 
-void NxpUwbChipSr1xx::onDeviceStatusNtf(size_t packet_len, const uint8_t* packet)
+bool NxpUwbChipHbciModule::onDeviceStatusNtf(size_t packet_len, const uint8_t* packet)
 {
   if(packet_len > UCI_RESPONSE_STATUS_OFFSET) {
     uint8_t status = packet[UCI_RESPONSE_STATUS_OFFSET];
@@ -364,29 +366,32 @@ void NxpUwbChipSr1xx::onDeviceStatusNtf(size_t packet_len, const uint8_t* packet
       sr1xx_clear_device_error();
     }
   }
+  return false;
 }
 
-void NxpUwbChipSr1xx::onGenericErrorNtf(size_t packet_len, const uint8_t* packet)
+bool NxpUwbChipHbciModule::onGenericErrorNtf(size_t packet_len, const uint8_t* packet)
 {
   if(packet_len > UCI_RESPONSE_STATUS_OFFSET) {
     uint8_t status = packet[UCI_RESPONSE_STATUS_OFFSET];
     if ( status == UCI_STATUS_THERMAL_RUNAWAY || status == UCI_STATUS_LOW_VBAT) {
-      nxpucihal_ctrl.isSkipPacket = 1;
       sr1xx_handle_device_error();
+      return true;
     }
   }
+  return false;
 }
 
-void NxpUwbChipSr1xx::onBindingStatusNtf(size_t packet_len, const uint8_t* packet)
+bool NxpUwbChipHbciModule::onBindingStatusNtf(size_t packet_len, const uint8_t* packet)
 {
   if (packet_len > UCI_RESPONSE_STATUS_OFFSET) {
     bindingStatus_ = packet[UCI_RESPONSE_STATUS_OFFSET];
     NXPLOG_UCIHAL_D("BINDING_STATUS_NTF: 0x%x", bindingStatus_);
     bindingStatusNtfWait_.post(UWBSTATUS_SUCCESS);
   }
+  return true;
 }
 
-tHAL_UWB_STATUS NxpUwbChipSr1xx::check_binding()
+tHAL_UWB_STATUS NxpUwbChipHbciModule::check_binding()
 {
   // Wait for Binding status notification
   if (bindingStatusNtfWait_.getStatus() != UWBSTATUS_SUCCESS) {
@@ -403,9 +408,9 @@ tHAL_UWB_STATUS NxpUwbChipSr1xx::check_binding()
       return UWBSTATUS_SUCCESS;
   }
 
-  uint32_t val = 0;
+  unsigned long val = 0;
   NxpConfig_GetNum(NAME_UWB_BINDING_LOCKING_ALLOWED, &val, sizeof(val));
-  bool isBindingLockingAllowed = !!val;
+  bool isBindingLockingAllowed = (val != 0);
   if (!isBindingLockingAllowed) {
     return UWBSTATUS_SUCCESS;
   }
@@ -465,7 +470,7 @@ tHAL_UWB_STATUS NxpUwbChipSr1xx::check_binding()
 
 extern int phNxpUciHal_fw_download();
 
-tHAL_UWB_STATUS NxpUwbChipSr1xx::chip_init()
+tHAL_UWB_STATUS NxpUwbChipHbciModule::chip_init()
 {
   tHAL_UWB_STATUS status;
 
@@ -493,31 +498,31 @@ tHAL_UWB_STATUS NxpUwbChipSr1xx::chip_init()
 
   // register device status ntf handler
   deviceStatusNtfHandler_ = UciHalRxHandler(
-      UCI_MT_NTF, UCI_GID_CORE, UCI_MSG_CORE_DEVICE_STATUS_NTF, false,
-      std::bind(&NxpUwbChipSr1xx::onDeviceStatusNtf, this, std::placeholders::_1, std::placeholders::_2)
+      UCI_MT_NTF, UCI_GID_CORE, UCI_MSG_CORE_DEVICE_STATUS_NTF,
+      std::bind(&NxpUwbChipHbciModule::onDeviceStatusNtf, this, std::placeholders::_1, std::placeholders::_2)
   );
 
   // register device error ntf handler
   genericErrorNtfHandler_ = UciHalRxHandler(
-    UCI_MT_NTF, UCI_GID_CORE, UCI_MSG_CORE_GENERIC_ERROR_NTF, false,
-    std::bind(&NxpUwbChipSr1xx::onGenericErrorNtf, this, std::placeholders::_1, std::placeholders::_2)
+    UCI_MT_NTF, UCI_GID_CORE, UCI_MSG_CORE_GENERIC_ERROR_NTF,
+    std::bind(&NxpUwbChipHbciModule::onGenericErrorNtf, this, std::placeholders::_1, std::placeholders::_2)
   );
 
   // register binding status ntf handler
   bindingStatusNtfHandler_ = UciHalRxHandler(
-      UCI_MT_NTF, UCI_GID_PROPRIETARY, UCI_MSG_BINDING_STATUS_NTF, true,
-      std::bind(&NxpUwbChipSr1xx::onBindingStatusNtf, this, std::placeholders::_1, std::placeholders::_2)
+      UCI_MT_NTF, UCI_GID_PROPRIETARY, UCI_MSG_BINDING_STATUS_NTF,
+      std::bind(&NxpUwbChipHbciModule::onBindingStatusNtf, this, std::placeholders::_1, std::placeholders::_2)
   );
 
   return status;
 }
 
-tHAL_UWB_STATUS NxpUwbChipSr1xx::core_init()
+tHAL_UWB_STATUS NxpUwbChipHbciModule::core_init()
 {
   return check_binding();
 }
 
-device_type_t NxpUwbChipSr1xx::get_device_type(const uint8_t *param, size_t param_len)
+device_type_t NxpUwbChipHbciModule::get_device_type(const uint8_t *param, size_t param_len)
 {
   // 'SR100S' or 'SR1..T'
   if (param_len >= 6) {
@@ -530,7 +535,7 @@ device_type_t NxpUwbChipSr1xx::get_device_type(const uint8_t *param, size_t para
   return DEVICE_TYPE_UNKNOWN;
 }
 
-tHAL_UWB_STATUS NxpUwbChipSr1xx::read_otp(extcal_param_id_t id, uint8_t *data, size_t data_len, size_t *retlen)
+tHAL_UWB_STATUS NxpUwbChipHbciModule::read_otp(extcal_param_id_t id, uint8_t *data, size_t data_len, size_t *retlen)
 {
   return sr1xx_read_otp(id, data, data_len, retlen);
 }
@@ -564,7 +569,7 @@ tHAL_UWB_STATUS sr1xx_apply_calibration_ant_delay(extcal_param_id_t id, const ui
   return sr1xx_apply_calibration(id, ch, patched_data.data(), data_len);
 }
 
-tHAL_UWB_STATUS NxpUwbChipSr1xx::apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len)
+tHAL_UWB_STATUS NxpUwbChipHbciModule::apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len)
 {
   if (id == EXTCAL_PARAM_RX_ANT_DELAY) {
     return sr1xx_apply_calibration_ant_delay(id, ch, data, data_len);
@@ -576,7 +581,7 @@ tHAL_UWB_STATUS NxpUwbChipSr1xx::apply_calibration(extcal_param_id_t id, const u
 }
 
 tHAL_UWB_STATUS
-NxpUwbChipSr1xx::get_supported_channels(const uint8_t **cal_channels, uint8_t *nr)
+NxpUwbChipHbciModule::get_supported_channels(const uint8_t **cal_channels, uint8_t *nr)
 {
   static const uint8_t sr100_cal_channels[] = {5, 6, 8, 9};
   *cal_channels = sr100_cal_channels;
@@ -586,5 +591,5 @@ NxpUwbChipSr1xx::get_supported_channels(const uint8_t **cal_channels, uint8_t *n
 
 std::unique_ptr<NxpUwbChip> GetUwbChip()
 {
-  return std::make_unique<NxpUwbChipSr1xx>();
+  return std::make_unique<NxpUwbChipHbciModule>();
 }
diff --git a/halimpl/hal/sr1xx/phNxpUciHal_fwd.cc b/halimpl/hal/hbci/phNxpUciHal_hbci_fwd.cc
similarity index 99%
rename from halimpl/hal/sr1xx/phNxpUciHal_fwd.cc
rename to halimpl/hal/hbci/phNxpUciHal_hbci_fwd.cc
index d315e87..ee56a7f 100644
--- a/halimpl/hal/sr1xx/phNxpUciHal_fwd.cc
+++ b/halimpl/hal/hbci/phNxpUciHal_hbci_fwd.cc
@@ -27,7 +27,7 @@
 
 #include "phNxpConfig.h"
 #include "phNxpLog.h"
-#include "phNxpUciHal_fwd.h"
+#include "phNxpUciHal_hbci_fwd.h"
 #include <phNxpUciHal_utils.h>
 #include <phTmlUwb_spi.h>
 
diff --git a/halimpl/hal/sr1xx/phNxpUciHal_fwd.h b/halimpl/hal/hbci/phNxpUciHal_hbci_fwd.h
similarity index 100%
rename from halimpl/hal/sr1xx/phNxpUciHal_fwd.h
rename to halimpl/hal/hbci/phNxpUciHal_hbci_fwd.h
diff --git a/halimpl/hal/phNxpUciHal.cc b/halimpl/hal/phNxpUciHal.cc
index 0990d25..5f648c0 100644
--- a/halimpl/hal/phNxpUciHal.cc
+++ b/halimpl/hal/phNxpUciHal.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2012-2019, 2022-2023 NXP
+ * Copyright 2012-2019, 2022-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -50,11 +50,9 @@ bool uwb_device_initialized = false;
 bool uwb_get_platform_id = false;
 uint32_t timeoutTimerId = 0;
 char persistant_log_path[120];
-static uint8_t Rx_data[UCI_MAX_DATA_LEN];
-
+constexpr long HAL_WRITE_TIMEOUT_MS = 1000;
 /**************** local methods used in this file only ************************/
-static void phNxpUciHal_write_complete(void* pContext,
-                                       phTmlUwb_TransactInfo_t* pInfo);
+static void phNxpUciHal_write_complete(void* pContext, phTmlUwb_WriteTransactInfo* pInfo);
 extern int phNxpUciHal_fw_download();
 static void phNxpUciHal_getVersionInfo();
 static tHAL_UWB_STATUS phNxpUciHal_sendCoreConfig(const uint8_t *p_cmd,
@@ -64,24 +62,18 @@ static tHAL_UWB_STATUS phNxpUciHal_sendCoreConfig(const uint8_t *p_cmd,
  * RX packet handler
  ******************************************************************************/
 struct phNxpUciHal_RxHandler {
+  phNxpUciHal_RxHandler(uint8_t mt, uint8_t gid, uint8_t oid,
+    bool run_once, RxHandlerCallback callback) :
+      mt(mt), gid(gid), oid(oid),
+      run_once(run_once),
+      callback(callback) { }
+
   // mt, gid, oid: packet type
   uint8_t mt;
   uint8_t gid;
   uint8_t oid;
-
-  // skip_reporting: not reports the packet to upper layer if it's true
-  bool skip_reporting;
   bool run_once;
-
-  std::function<void(size_t packet_len, const uint8_t *packet)> callback;
-
-  phNxpUciHal_RxHandler(uint8_t mt, uint8_t gid, uint8_t oid,
-    bool skip_reporting, bool run_once,
-    std::function<void(size_t packet_len, const uint8_t *packet)> callback) :
-      mt(mt), gid(gid), oid(oid),
-      skip_reporting(skip_reporting),
-      run_once(run_once),
-      callback(callback) { }
+  RxHandlerCallback callback;
 };
 
 static std::list<std::shared_ptr<phNxpUciHal_RxHandler>> rx_handlers;
@@ -89,11 +81,11 @@ static std::mutex rx_handlers_lock;
 
 std::shared_ptr<phNxpUciHal_RxHandler> phNxpUciHal_rx_handler_add(
   uint8_t mt, uint8_t gid, uint8_t oid,
-  bool skip_reporting, bool run_once,
-  std::function<void(size_t packet_len, const uint8_t *packet)> callback)
+  bool run_once,
+  RxHandlerCallback callback)
 {
-  auto handler = std::make_shared<phNxpUciHal_RxHandler>(mt, gid, oid,
-    skip_reporting, run_once, callback);
+  auto handler = std::make_shared<phNxpUciHal_RxHandler>(
+    mt, gid, oid, run_once, callback);
   std::lock_guard<std::mutex> guard(rx_handlers_lock);
   rx_handlers.push_back(handler);
   return handler;
@@ -105,25 +97,35 @@ void phNxpUciHal_rx_handler_del(std::shared_ptr<phNxpUciHal_RxHandler> handler)
   rx_handlers.remove(handler);
 }
 
-static void phNxpUciHal_rx_handler_check(size_t packet_len, const uint8_t *packet)
+// Returns true when this packet is handled by one of the handler.
+static bool phNxpUciHal_rx_handler_check(size_t packet_len, const uint8_t *packet)
 {
   const uint8_t mt = ((packet[0]) & UCI_MT_MASK) >> UCI_MT_SHIFT;
   const uint8_t gid = packet[0] & UCI_GID_MASK;
   const uint8_t oid = packet[1] & UCI_OID_MASK;
+  bool skip_packet = false;
 
-  std::lock_guard<std::mutex> guard(rx_handlers_lock);
+  // Copy the whole list to allow rx handlers to call rx_handler_add().
+  std::list<std::shared_ptr<phNxpUciHal_RxHandler>> handlers;
+  {
+    std::lock_guard<std::mutex> guard(rx_handlers_lock);
+    handlers = rx_handlers;
+  }
 
-  for (auto handler : rx_handlers) {
+  for (auto handler : handlers) {
     if (mt == handler->mt && gid == handler->gid && oid == handler->oid) {
-      handler->callback(packet_len, packet);
-      if (handler->skip_reporting) {
-        nxpucihal_ctrl.isSkipPacket = 1;
+      if (handler->callback(packet_len, packet)) {
+        skip_packet = true;
       }
     }
   }
+
+  std::lock_guard<std::mutex> guard(rx_handlers_lock);
   rx_handlers.remove_if([mt, gid, oid](auto& handler) {
     return mt == handler->mt && gid == handler->gid && oid == handler->oid && handler->run_once;
   });
+
+  return skip_packet;
 }
 
 static void phNxpUciHal_rx_handler_destroy(void)
@@ -224,42 +226,45 @@ static void phNxpUciHal_client_thread(phNxpUciHal_Control_t* p_nxpucihal_ctrl)
  * Returns          It returns true if the incoming command to be skipped.
  *
  ******************************************************************************/
-bool phNxpUciHal_parse(uint16_t data_len, const uint8_t *p_data)
+bool phNxpUciHal_parse(size_t* cmdlen, uint8_t* cmd)
 {
   bool ret = false;
 
-  if (data_len < UCI_MSG_HDR_SIZE)
+  if ((*cmdlen) < UCI_MSG_HDR_SIZE) {
     return false;
+  }
 
-  const uint8_t mt = (p_data[0] &UCI_MT_MASK) >> UCI_MT_SHIFT;
-  const uint8_t gid = p_data[0] & UCI_GID_MASK;
-  const uint8_t oid = p_data[1] & UCI_OID_MASK;
+  const uint8_t mt = (cmd[0] &UCI_MT_MASK) >> UCI_MT_SHIFT;
+  const uint8_t gid = cmd[0] & UCI_GID_MASK;
+  const uint8_t oid = cmd[1] & UCI_OID_MASK;
+  if (mt != UCI_MT_CMD) {
+    return false;
+  }
 
-  if (mt == UCI_MT_CMD) {
-    if ((gid == UCI_GID_ANDROID) && (oid == UCI_MSG_ANDROID_SET_COUNTRY_CODE)) {
-      char country_code[2];
-      if (data_len == 6) {
-        country_code[0] = (char)p_data[4];
-        country_code[1] = (char)p_data[5];
-      } else {
-        NXPLOG_UCIHAL_E("Unexpected payload length for ANDROID_SET_COUNTRY_CODE, handle this with 00 country code");
-        country_code[0] = '0';
-        country_code[1] = '0';
-      }
-      phNxpUciHal_handle_set_country_code(country_code);
-      return true;
-    } else if ((gid == UCI_GID_PROPRIETARY_0x0F) && (oid == SET_VENDOR_SET_CALIBRATION)) {
-        if (p_data[UCI_MSG_HDR_SIZE + 1] ==
-            VENDOR_CALIB_PARAM_TX_POWER_PER_ANTENNA) {
-          phNxpUciHal_handle_set_calibration(p_data, data_len);
-        }
-    } else if ((gid == UCI_GID_SESSION_MANAGE) && (oid == UCI_MSG_SESSION_SET_APP_CONFIG)) {
-      return phNxpUciHal_handle_set_app_config(&nxpucihal_ctrl.cmd_len, nxpucihal_ctrl.p_cmd_data);
-    } else if ((gid == UCI_GID_SESSION_MANAGE) && (oid == UCI_MSG_SESSION_STATE_INIT)) {
-      SessionTrack_onSessionInit(nxpucihal_ctrl.cmd_len, nxpucihal_ctrl.p_cmd_data);
+  if ((gid == UCI_GID_ANDROID) && (oid == UCI_MSG_ANDROID_SET_COUNTRY_CODE)) {
+    char country_code[2];
+    if ((*cmdlen) == 6) {
+      country_code[0] = (char)cmd[4];
+      country_code[1] = (char)cmd[5];
+    } else {
+      NXPLOG_UCIHAL_E("Unexpected payload length for ANDROID_SET_COUNTRY_CODE, handle this with 00 country code");
+      country_code[0] = '0';
+      country_code[1] = '0';
     }
-  } else {
-    ret = false;
+    phNxpUciHal_handle_set_country_code(country_code);
+    return true;
+  } else if ((gid == UCI_GID_PROPRIETARY_0x0F) && (oid == SET_VENDOR_SET_CALIBRATION)) {
+    if (cmd[UCI_MSG_HDR_SIZE + 1] == VENDOR_CALIB_PARAM_TX_POWER_PER_ANTENNA) {
+      // XXX: packet can be patched by here.
+      phNxpUciHal_handle_set_calibration(cmd, *cmdlen);
+    }
+  } else if ((gid == UCI_GID_SESSION_MANAGE) && (oid == UCI_MSG_SESSION_SET_APP_CONFIG)) {
+    // XXX: packet can be patched by here.
+    return phNxpUciHal_handle_set_app_config(cmdlen, cmd);
+  } else if ((gid == UCI_GID_SESSION_MANAGE) && (oid == UCI_MSG_SESSION_STATE_INIT)) {
+    SessionTrack_onSessionInit(*cmdlen, cmd);
+  } if (mt == UCI_MT_CMD && gid == UCI_GID_SESSION_CONTROL && oid == UCI_MSG_SESSION_START) {
+    SessionTrack_onSessionStart(*cmdlen, cmd);
   }
   return ret;
 }
@@ -296,7 +301,7 @@ tHAL_UWB_STATUS phNxpUciHal_open(uwb_stack_callback_t* p_cback, uwb_stack_data_c
   /*Create the timer for extns write response*/
   timeoutTimerId = phOsalUwb_Timer_Create();
 
-  if (phNxpUciHal_init_monitor() == NULL) {
+  if (!phNxpUciHal_init_monitor()) {
     NXPLOG_UCIHAL_E("Init monitor failed");
     return UWBSTATUS_FAILED;
   }
@@ -315,6 +320,10 @@ tHAL_UWB_STATUS phNxpUciHal_open(uwb_stack_callback_t* p_cback, uwb_stack_data_c
   nxpucihal_ctrl.gDrvCfg.pClientMq = std::make_shared<MessageQueue<phLibUwb_Message>>("Client");
   nxpucihal_ctrl.gDrvCfg.nLinkType = ENUM_LINK_TYPE_SPI;
 
+  // Default country code = '00'
+  nxpucihal_ctrl.country_code[0] = '0';
+  nxpucihal_ctrl.country_code[1] = '0';
+
   /* Initialize TML layer */
   wConfigStatus = phTmlUwb_Init(uwb_dev_node, nxpucihal_ctrl.gDrvCfg.pClientMq);
   if (wConfigStatus != UWBSTATUS_SUCCESS) {
@@ -333,6 +342,10 @@ tHAL_UWB_STATUS phNxpUciHal_open(uwb_stack_callback_t* p_cback, uwb_stack_data_c
   // Per-chip (SR1XX or SR200) implementation
   nxpucihal_ctrl.uwb_chip = GetUwbChip();
 
+  // Install rx packet handlers
+  phNxpUciHal_rx_handler_add(UCI_MT_RSP, UCI_GID_CORE, UCI_MSG_CORE_GET_CAPS_INFO,
+    false, phNxpUciHal_handle_get_caps_info);
+
   /* Call open complete */
   phTmlUwb_DeferredCall(std::make_shared<phLibUwb_Message>(UCI_HAL_OPEN_CPLT_MSG));
 
@@ -363,20 +376,18 @@ clean_and_return:
  * Returns          It returns number of bytes successfully written to UWBC.
  *
  ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_write(uint16_t data_len, const uint8_t* p_data) {
+int32_t phNxpUciHal_write(size_t data_len, const uint8_t* p_data) {
   if (nxpucihal_ctrl.halStatus != HAL_STATUS_OPEN) {
     return UWBSTATUS_FAILED;
   }
-  uint16_t len = 0;
-
   SessionTrack_keepAlive();
 
   CONCURRENCY_LOCK();
-  phNxpUciHal_process_ext_cmd_rsp(data_len, p_data, &len);
+  auto status = phNxpUciHal_process_ext_cmd_rsp(data_len, p_data);
   CONCURRENCY_UNLOCK();
 
   /* No data written */
-  return len;
+  return (status == UWBSTATUS_SUCCESS) ? data_len : 0;
 }
 
 /******************************************************************************
@@ -387,63 +398,33 @@ tHAL_UWB_STATUS phNxpUciHal_write(uint16_t data_len, const uint8_t* p_data) {
  *                  It waits till write callback provide the result of write
  *                  process.
  *
- * Returns          It returns number of bytes successfully written to UWBC.
+ * Returns          Status code.
  *
  ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_write_unlocked(uint16_t data_len, const uint8_t* p_data) {
+tHAL_UWB_STATUS phNxpUciHal_write_unlocked(size_t data_len, const uint8_t* p_data) {
   tHAL_UWB_STATUS status;
-  uint8_t mt, pbf, gid, oid;
-
-  phNxpUciHal_Sem_t cb_data;
-  /* Create the local semaphore */
-  if (phNxpUciHal_init_cb_data(&cb_data, NULL) != UWBSTATUS_SUCCESS) {
-    NXPLOG_UCIHAL_D("phNxpUciHal_write_unlocked Create cb data failed");
-    data_len = 0;
-    goto clean_and_return;
-  }
 
   if ((data_len > UCI_MAX_DATA_LEN) || (data_len < UCI_PKT_HDR_LEN)) {
     NXPLOG_UCIHAL_E("Invalid data_len");
-    data_len = 0;
-    goto clean_and_return;
+    return UWBSTATUS_INVALID_PARAMETER;
   }
 
-  /* Create local copy of cmd_data */
-  memcpy(nxpucihal_ctrl.p_cmd_data, p_data, data_len);
-  nxpucihal_ctrl.cmd_len = data_len;
-
-  data_len = nxpucihal_ctrl.cmd_len;
-  UCI_MSG_PRS_HDR0(p_data, mt, pbf, gid);
-  UCI_MSG_PRS_HDR1(p_data, oid);
-
-  /* Vendor Specific Parsing logic */
-  nxpucihal_ctrl.hal_parse_enabled =
-      phNxpUciHal_parse(nxpucihal_ctrl.cmd_len, nxpucihal_ctrl.p_cmd_data);
-  if (nxpucihal_ctrl.hal_parse_enabled) {
-    goto clean_and_return;
-  }
-  status = phTmlUwb_Write(
-      (uint8_t*)nxpucihal_ctrl.p_cmd_data, (uint16_t)nxpucihal_ctrl.cmd_len,
-      (pphTmlUwb_TransactCompletionCb_t)&phNxpUciHal_write_complete,
-      (void*)&cb_data);
+  /* Create the local semaphore */
+  UciHalSemaphore cb_data;
 
+  status = phTmlUwb_Write(p_data, data_len, phNxpUciHal_write_complete, &cb_data);
 
   if (status != UWBSTATUS_PENDING) {
-    NXPLOG_UCIHAL_E("write_unlocked status error");
-    data_len = 0;
-    goto clean_and_return;
+    return UWBSTATUS_FAILED;
   }
 
   /* Wait for callback response */
-  if (SEM_WAIT(&cb_data)) {
+  if (cb_data.wait_timeout_msec(HAL_WRITE_TIMEOUT_MS)) {
     NXPLOG_UCIHAL_E("write_unlocked semaphore error");
-    data_len = 0;
-    goto clean_and_return;
+    return UWBSTATUS_FAILED;
   }
 
-clean_and_return:
-  phNxpUciHal_cleanup_cb_data(&cb_data);
-  return data_len;
+  return UWBSTATUS_SUCCESS;
 }
 
 /******************************************************************************
@@ -455,19 +436,112 @@ clean_and_return:
  *
  ******************************************************************************/
 static void phNxpUciHal_write_complete(void* pContext,
-                                       phTmlUwb_TransactInfo_t* pInfo) {
-  phNxpUciHal_Sem_t* p_cb_data = (phNxpUciHal_Sem_t*)pContext;
+                                       phTmlUwb_WriteTransactInfo* pInfo) {
+  UciHalSemaphore* p_cb_data = (UciHalSemaphore*)pContext;
 
   if (pInfo->wStatus == UWBSTATUS_SUCCESS) {
     NXPLOG_UCIHAL_V("write successful status = 0x%x", pInfo->wStatus);
   } else {
     NXPLOG_UCIHAL_E("write error status = 0x%x", pInfo->wStatus);
   }
-  p_cb_data->status = pInfo->wStatus;
+  p_cb_data->post(pInfo->wStatus);
+}
+
+void report_uci_message(const uint8_t* buffer, size_t len)
+{
+  if ((nxpucihal_ctrl.p_uwb_stack_data_cback != NULL) && (len <= UCI_MAX_PAYLOAD_LEN)) {
+    (*nxpucihal_ctrl.p_uwb_stack_data_cback)(len, buffer);
+  }
+}
+
+static void handle_rx_packet(uint8_t *buffer, size_t length)
+{
+  phNxpUciHal_print_packet(NXP_TML_UCI_RSP_NTF_UWBS_2_AP, buffer, length);
+
+  uint8_t mt = ((buffer[0]) & UCI_MT_MASK) >> UCI_MT_SHIFT;
+  uint8_t gid = buffer[0] & UCI_GID_MASK;
+  uint8_t oid = buffer[1] & UCI_OID_MASK;
+  uint8_t pbf = (buffer[0] & UCI_PBF_MASK) >> UCI_PBF_SHIFT;
+
+  bool isSkipPacket = false;
+
+  if (phNxpUciHal_rx_handler_check(length, buffer)) {
+    isSkipPacket = true;
+  }
+
+  if (mt == UCI_MT_NTF) {
+    if (!pbf && gid == UCI_GID_CORE && oid == UCI_MSG_CORE_GENERIC_ERROR_NTF) {
+      uint8_t status_code = buffer[UCI_RESPONSE_STATUS_OFFSET];
+
+      if (status_code == UCI_STATUS_COMMAND_RETRY ||
+          status_code == UCI_STATUS_SYNTAX_ERROR) {
+        // Handle retransmissions
+        // TODO: Do not retransmit it when !nxpucihal_ctrl.hal_ext_enabled,
+        // Upper layer should take care of it.
+        isSkipPacket = true;
+        nxpucihal_ctrl.cmdrsp.WakeupError(UWBSTATUS_COMMAND_RETRANSMIT);
+      } else if (status_code == UCI_STATUS_BUFFER_UNDERFLOW) {
+        if (nxpucihal_ctrl.hal_ext_enabled) {
+          NXPLOG_UCIHAL_E("Got Underflow error for ext cmd, retransmit");
+          isSkipPacket = true;
+          nxpucihal_ctrl.cmdrsp.WakeupError(UWBSTATUS_COMMAND_RETRANSMIT);
+        } else {
+          // uci to handle retransmission
+          buffer[UCI_RESPONSE_STATUS_OFFSET] = UCI_STATUS_COMMAND_RETRY;
+          // TODO: Why this should be treated as fail? once we already patched
+          // the status code here. Write operation should be treated as success.
+          nxpucihal_ctrl.cmdrsp.WakeupError(UWBSTATUS_FAILED);
+        }
+      } else {
+        // TODO: Why should we wake up the user thread here?
+        nxpucihal_ctrl.cmdrsp.WakeupError(UWBSTATUS_FAILED);
+      }
+    }
+    // End of UCI_MT_NTF
+  } else if (mt == UCI_MT_RSP) {
+    if (nxpucihal_ctrl.hal_ext_enabled) {
+      isSkipPacket = true;
+
+      if (pbf) {
+        /* XXX: fix the whole logic if this really happens */
+        NXPLOG_UCIHAL_E("FIXME: Fragmented packets received while processing internal commands!");
+      }
+
+      uint8_t status_code = (length > UCI_RESPONSE_STATUS_OFFSET) ?
+        buffer[UCI_RESPONSE_STATUS_OFFSET] : UCI_STATUS_UNKNOWN;
+
+      if (status_code == UCI_STATUS_OK) {
+        nxpucihal_ctrl.cmdrsp.Wakeup(gid, oid);
+      } else if ((gid == UCI_GID_CORE) && (oid == UCI_MSG_CORE_SET_CONFIG)){
+        /* check if any configurations are not supported then ignore the
+          * UWBSTATUS_FEATURE_NOT_SUPPORTED status code*/
+        uint8_t status = phNxpUciHal_process_ext_rsp(length, buffer);
+        if (status == UWBSTATUS_SUCCESS) {
+          nxpucihal_ctrl.cmdrsp.Wakeup(gid, oid);
+        } else {
+          nxpucihal_ctrl.cmdrsp.WakeupError(status);
+        }
+      } else {
+        NXPLOG_UCIHAL_E("Got error status code(0x%x) from internal command.", status_code);
+        usleep(1);  // XXX: not sure if it's really needed
+        nxpucihal_ctrl.cmdrsp.WakeupError(UWBSTATUS_FAILED);
+      }
+    } else {
+      nxpucihal_ctrl.cmdrsp.Wakeup(gid, oid);
+    }
+  } // End of UCI_MT_RSP
 
-  SEM_POST(p_cb_data);
+  if (!isSkipPacket) {
+    /* Read successful, send the event to higher layer */
+    report_uci_message(buffer, length);
+  }
 
-  return;
+  /* Disable junk data check for each UCI packet*/
+  if(nxpucihal_ctrl.fw_dwnld_mode) {
+    if((gid == UCI_GID_CORE) && (oid == UCI_MSG_CORE_DEVICE_STATUS_NTF)){
+      nxpucihal_ctrl.fw_dwnld_mode = false;
+    }
+  }
 }
 
 /******************************************************************************
@@ -484,7 +558,7 @@ static void phNxpUciHal_write_complete(void* pContext,
  * Returns          void.
  *
  ******************************************************************************/
-void phNxpUciHal_read_complete(void* pContext, phTmlUwb_TransactInfo_t* pInfo)
+void phNxpUciHal_read_complete(void* pContext, phTmlUwb_ReadTransactInfo* pInfo)
 {
   UNUSED(pContext);
 
@@ -504,112 +578,14 @@ void phNxpUciHal_read_complete(void* pContext, phTmlUwb_TransactInfo_t* pInfo)
      length = (length << EXTENDED_MODE_LEN_SHIFT) | pInfo->pBuff[index + EXTENDED_MODE_LEN_OFFSET] ;
     }
     length += UCI_MSG_HDR_SIZE;
-    NXPLOG_UCIHAL_V("read successful length = %d", length);
-
-    nxpucihal_ctrl.p_rx_data = &pInfo->pBuff[index];
-    nxpucihal_ctrl.rx_data_len = length;
-    phNxpUciHal_print_packet(NXP_TML_UCI_RSP_NTF_UWBS_2_AP, nxpucihal_ctrl.p_rx_data, nxpucihal_ctrl.rx_data_len);
-
-    uint8_t mt = ((nxpucihal_ctrl.p_rx_data[0]) & UCI_MT_MASK) >> UCI_MT_SHIFT;
-    uint8_t gid = nxpucihal_ctrl.p_rx_data[0] & UCI_GID_MASK;
-    uint8_t oid = nxpucihal_ctrl.p_rx_data[1] & UCI_OID_MASK;
-    uint8_t pbf = (nxpucihal_ctrl.p_rx_data[0] & UCI_PBF_MASK) >> UCI_PBF_SHIFT;
-
-    nxpucihal_ctrl.isSkipPacket = 0;
-
-    phNxpUciHal_rx_handler_check(nxpucihal_ctrl.rx_data_len,
-                                 nxpucihal_ctrl.p_rx_data);
-
-    // mapping device caps according to Fira 2.0
-    if (mt == UCI_MT_RSP && gid == UCI_GID_CORE && oid == UCI_MSG_CORE_GET_CAPS_INFO) {
-      phNxpUciHal_handle_get_caps_info(nxpucihal_ctrl.rx_data_len, nxpucihal_ctrl.p_rx_data);
-    }
 
-    // phNxpUciHal_process_ext_cmd_rsp() is waiting for the response packet
-    // set this true to wake it up for other reasons
-    bool bWakeupExtCmd = (mt == UCI_MT_RSP);
-    if (bWakeupExtCmd && nxpucihal_ctrl.ext_cb_waiting) {
-      nxpucihal_ctrl.ext_cb_data.status = UWBSTATUS_SUCCESS;
-    }
-
-    /* DBG packets not yet supported, just ignore them silently */
-    if (!nxpucihal_ctrl.isSkipPacket) {
-      if ((mt == UCI_MT_NTF) && (gid == UCI_GID_INTERNAL) &&
-          (oid == UCI_EXT_PARAM_DBG_RFRAME_LOG_NTF)) {
-        nxpucihal_ctrl.isSkipPacket = 1;
-      }
-    }
-
-    if (!nxpucihal_ctrl.isSkipPacket) {
-      if (!pbf && mt == UCI_MT_NTF && gid == UCI_GID_CORE && oid == UCI_MSG_CORE_GENERIC_ERROR_NTF) {
-        uint8_t status_code = nxpucihal_ctrl.p_rx_data[UCI_RESPONSE_STATUS_OFFSET];
-
-        if (status_code == UCI_STATUS_COMMAND_RETRY) {
-          // Handle retransmissions
-          // TODO: Do not retransmit it when !nxpucihal_ctrl.hal_ext_enabled,
-          // Upper layer should take care of it.
-          nxpucihal_ctrl.ext_cb_data.status = UWBSTATUS_COMMAND_RETRANSMIT;
-          nxpucihal_ctrl.isSkipPacket = 1;
-        } else if (status_code == UCI_STATUS_BUFFER_UNDERFLOW) {
-          if (nxpucihal_ctrl.hal_ext_enabled) {
-            nxpucihal_ctrl.ext_cb_data.status = UWBSTATUS_COMMAND_RETRANSMIT;
-            nxpucihal_ctrl.isSkipPacket = 1;
-          } else {
-            // uci to handle retransmission
-            nxpucihal_ctrl.p_rx_data[UCI_RESPONSE_STATUS_OFFSET] =
-                UCI_STATUS_COMMAND_RETRY;
-          }
-        }
-        bWakeupExtCmd = true;
-      }
-    }
-
-    // Check status code only for extension commands
-    if (!nxpucihal_ctrl.isSkipPacket) {
-      if (mt == UCI_MT_RSP) {
-        if (nxpucihal_ctrl.hal_ext_enabled) {
-          nxpucihal_ctrl.isSkipPacket = 1;
-
-          if (pbf) {
-            /* XXX: fix the whole logic if this really happens */
-            NXPLOG_UCIHAL_E("FIXME: Fragmented packets received while processing internal commands!");
-          }
-
-          uint8_t status_code = (nxpucihal_ctrl.rx_data_len > UCI_RESPONSE_STATUS_OFFSET) ?
-            nxpucihal_ctrl.p_rx_data[UCI_RESPONSE_STATUS_OFFSET] : UCI_STATUS_UNKNOWN;
-
-          if (status_code == UCI_STATUS_OK) {
-            nxpucihal_ctrl.ext_cb_data.status = UWBSTATUS_SUCCESS;
-          } else if ((gid == UCI_GID_CORE) && (oid == UCI_MSG_CORE_SET_CONFIG)){
-            /* check if any configurations are not supported then ignore the
-              * UWBSTATUS_FEATURE_NOT_SUPPORTED status code*/
-            nxpucihal_ctrl.ext_cb_data.status = phNxpUciHal_process_ext_rsp(nxpucihal_ctrl.rx_data_len, nxpucihal_ctrl.p_rx_data);
-          } else {
-            nxpucihal_ctrl.ext_cb_data.status = UWBSTATUS_FAILED;
-            NXPLOG_UCIHAL_E("Got error status code(0x%x) from internal command.", status_code);
-            usleep(1);  // XXX: not sure if it's really needed
-          }
-        }
-      }
-    }
-
-    if (bWakeupExtCmd && nxpucihal_ctrl.ext_cb_waiting) {
-      SEM_POST(&(nxpucihal_ctrl.ext_cb_data));
-    }
-
-    if (!nxpucihal_ctrl.isSkipPacket) {
-      /* Read successful, send the event to higher layer */
-      if ((nxpucihal_ctrl.p_uwb_stack_data_cback != NULL) && (nxpucihal_ctrl.rx_data_len <= UCI_MAX_PAYLOAD_LEN)) {
-        (*nxpucihal_ctrl.p_uwb_stack_data_cback)(nxpucihal_ctrl.rx_data_len, nxpucihal_ctrl.p_rx_data);
-      }
+    if ((index + length) > pInfo->wLength) {
+      NXPLOG_UCIHAL_E("RX Packet misaligned! given length=%u, offset=%d, len=%d",
+        pInfo->wLength, index, length);
+      return;
     }
+    handle_rx_packet(&pInfo->pBuff[index], length);
 
-    /* Disable junk data check for each UCI packet*/
-    if(nxpucihal_ctrl.fw_dwnld_mode) {
-      if((gid == UCI_GID_CORE) && (oid == UCI_MSG_CORE_DEVICE_STATUS_NTF)){
-        nxpucihal_ctrl.fw_dwnld_mode = false;
-      }
-    }
     index += length;
   } //End of loop
 }
@@ -674,7 +650,7 @@ tHAL_UWB_STATUS phNxpUciHal_close() {
 static void parseAntennaConfig(const char *configName)
 {
   std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
-  long retlen = 0;
+  size_t retlen = 0;
   int gotConfig = NxpConfig_GetByteArray(configName, buffer.data(), buffer.size(), &retlen);
   if (gotConfig) {
     if (retlen <= UCI_MSG_HDR_SIZE) {
@@ -721,7 +697,7 @@ tHAL_UWB_STATUS phNxpUciHal_applyVendorConfig()
 {
   std::vector<const char *> vendorParamNames;
   std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
-  long retlen = 0;
+  size_t retlen = 0;
   tHAL_UWB_STATUS status = UWBSTATUS_FAILED;
 
   // Base parameter names
@@ -820,14 +796,14 @@ tHAL_UWB_STATUS phNxpUciHal_uwb_reset() {
 
 static bool cacheDevInfoRsp()
 {
-  auto dev_info_cb = [](size_t packet_len, const uint8_t *packet) mutable {
+  auto dev_info_cb = [](size_t packet_len, const uint8_t *packet) mutable -> bool {
     if (packet_len < 5 || packet[UCI_RESPONSE_STATUS_OFFSET] != UWBSTATUS_SUCCESS) {
       NXPLOG_UCIHAL_E("Failed to get valid CORE_DEVICE_INFO_RSP");
-      return;
+      return true;
     }
     if (packet_len > sizeof(nxpucihal_ctrl.dev_info_resp)) {
       NXPLOG_UCIHAL_E("FIXME: CORE_DEVICE_INFO_RSP buffer overflow!");
-      return;
+      return true;
     }
 
     // FIRA UCIv2.0 packet size = 14
@@ -837,7 +813,7 @@ static bool cacheDevInfoRsp()
 
     if (packet_len < firaDevInfoRspSize) {
       NXPLOG_UCIHAL_E("DEVICE_INFO_RSP packet size mismatched.");
-      return;
+      return true;
     }
 
     const uint8_t vendorSpecificLen = packet[firaDevInfoVendorLenOffset];
@@ -866,10 +842,11 @@ static bool cacheDevInfoRsp()
     memcpy(nxpucihal_ctrl.dev_info_resp, packet, packet_len);
     nxpucihal_ctrl.isDevInfoCached = true;
     NXPLOG_UCIHAL_D("Device Info cached.");
+    return true;
   };
 
   nxpucihal_ctrl.isDevInfoCached = false;
-  UciHalRxHandler devInfoRspHandler(UCI_MT_RSP, UCI_GID_CORE, UCI_MSG_CORE_DEVICE_INFO, true, dev_info_cb);
+  UciHalRxHandler devInfoRspHandler(UCI_MT_RSP, UCI_GID_CORE, UCI_MSG_CORE_DEVICE_INFO, dev_info_cb);
 
   const uint8_t CoreGetDevInfoCmd[] = {(UCI_MT_CMD << UCI_MT_SHIFT) | UCI_GID_CORE, UCI_MSG_CORE_DEVICE_INFO, 0, 0};
   tHAL_UWB_STATUS status = phNxpUciHal_send_ext_cmd(sizeof(CoreGetDevInfoCmd), CoreGetDevInfoCmd);
@@ -901,16 +878,16 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
   // Device Status Notification
   UciHalSemaphore devStatusNtfWait;
   uint8_t dev_status = UWB_DEVICE_ERROR;
-  auto dev_status_ntf_cb = [&dev_status,
-                            &devStatusNtfWait](size_t packet_len,
-                                               const uint8_t *packet) mutable {
+  auto dev_status_ntf_cb = [&dev_status, &devStatusNtfWait]
+      (size_t packet_len, const uint8_t *packet) mutable -> bool {
     if (packet_len >= 5) {
       dev_status = packet[UCI_RESPONSE_STATUS_OFFSET];
       devStatusNtfWait.post();
     }
+    return true;
   };
   UciHalRxHandler devStatusNtfHandler(UCI_MT_NTF, UCI_GID_CORE, UCI_MSG_CORE_DEVICE_STATUS_NTF,
-                                      true, dev_status_ntf_cb);
+                                      dev_status_ntf_cb);
 
   // FW download and enter UCI operating mode
   status = nxpucihal_ctrl.uwb_chip->chip_init();
@@ -919,8 +896,7 @@ tHAL_UWB_STATUS phNxpUciHal_init_hw()
   }
 
   // Initiate UCI packet read
-  status = phTmlUwb_StartRead( Rx_data, UCI_MAX_DATA_LEN,
-            (pphTmlUwb_TransactCompletionCb_t)&phNxpUciHal_read_complete, NULL);
+  status = phTmlUwb_StartRead(&phNxpUciHal_read_complete, NULL);
   if (status != UWBSTATUS_SUCCESS) {
     NXPLOG_UCIHAL_E("read status error status = %x", status);
     return status;
@@ -1000,10 +976,8 @@ tHAL_UWB_STATUS phNxpUciHal_coreInitialization()
   // report to upper-layer
   phTmlUwb_DeferredCall(std::make_shared<phLibUwb_Message>(UCI_HAL_INIT_CPLT_MSG));
 
-  if (nxpucihal_ctrl.p_uwb_stack_data_cback != NULL) {
-    uint8_t dev_ready_ntf[] = {0x60, 0x01, 0x00, 0x01, 0x01};
-    (*nxpucihal_ctrl.p_uwb_stack_data_cback)((sizeof(dev_ready_ntf)/sizeof(uint8_t)), dev_ready_ntf);
-  }
+  constexpr uint8_t dev_ready_ntf[] = {0x60, 0x01, 0x00, 0x01, 0x01};
+  report_uci_message(dev_ready_ntf, sizeof(dev_ready_ntf));
 
   return UWBSTATUS_SUCCESS;
 }
@@ -1127,8 +1101,7 @@ tHAL_UWB_STATUS phNxpUciHal_sendCoreConfig(const uint8_t *p_cmd,
  ******************************************* ***********************************/
 void phNxpUciHal_send_dev_error_status_ntf()
 {
- NXPLOG_UCIHAL_D("phNxpUciHal_send_dev_error_status_ntf ");
- nxpucihal_ctrl.rx_data_len = 5;
- static uint8_t rsp_data[5] = {0x60, 0x01, 0x00, 0x01, 0xFF};
- (*nxpucihal_ctrl.p_uwb_stack_data_cback)(nxpucihal_ctrl.rx_data_len, rsp_data);
+  NXPLOG_UCIHAL_D("phNxpUciHal_send_dev_error_status_ntf ");
+  constexpr uint8_t rsp_data[5] = {0x60, 0x01, 0x00, 0x01, 0xFF};
+  report_uci_message(rsp_data, sizeof(rsp_data));
 }
diff --git a/halimpl/hal/phNxpUciHal.h b/halimpl/hal/phNxpUciHal.h
index 1b12546..e7c0f7b 100644
--- a/halimpl/hal/phNxpUciHal.h
+++ b/halimpl/hal/phNxpUciHal.h
@@ -159,6 +159,80 @@ typedef struct {
   short tx_power_offset;    // From UWB_COUNTRY_CODE_CAPS
 } phNxpUciHal_Runtime_Settings_t;
 
+// From phNxpUciHal_process_ext_cmd_rsp(),
+// For checking CMD/RSP turn around matching.
+class CmdRspCheck {
+public:
+  CmdRspCheck() { }
+
+  void StartCmd(uint8_t gid, uint8_t oid) {
+    if (sem_ != nullptr) {
+      NXPLOG_UCIHAL_E("CMD/RSP turnaround is already ongoing!");
+    } else {
+      sem_ = std::make_shared<UciHalSemaphore>();
+      gid_ = gid;
+      oid_ = oid;
+    }
+  }
+
+  // CMD writer waits for the corresponding RSP
+  tHAL_UWB_STATUS Wait(long timeout_ms) {
+    auto sem = GetSemaphore();
+    if (sem == nullptr) {
+      NXPLOG_UCIHAL_E("Wait CMD/RSP for non-existed turnaround!");
+      return UCI_STATUS_FAILED;
+    }
+    sem->wait_timeout_msec(timeout_ms);
+    auto ret = sem->getStatus();
+    ReleaseSemaphore();
+    return ret;
+  }
+
+  // Reset the state, this shouldn't be called while
+  // Someone is waiting from WaitRsp().
+  void Cancel() {
+    ReleaseSemaphore();
+  }
+
+  // Wakes up the user thread when RSP packet is matched.
+  void Wakeup(uint8_t gid, uint8_t oid) {
+    auto sem = GetSemaphore();
+    if (sem == nullptr) {
+      NXPLOG_UCIHAL_E("Wakeup CMD/RSP while no one is waiting for CMD/RSP!");
+      return;
+    }
+    if (gid_ != gid || oid_ != oid) {
+      NXPLOG_UCIHAL_E(
+        "Received incorrect response of GID:%x OID:%x, expected GID:%x OID:%x",
+        gid, oid, gid_, oid_);
+      sem->post(UWBSTATUS_COMMAND_RETRANSMIT);
+    } else {
+      sem->post(UWBSTATUS_SUCCESS);
+    }
+  }
+
+  // Wakes up the user thread with error status code.
+  void WakeupError(tHAL_UWB_STATUS status) {
+    auto sem = GetSemaphore();
+    if (sem == nullptr) {
+      NXPLOG_UCIHAL_V("Got error while no one is waiting for CMD/RSP!");
+      return;
+    }
+    sem->post(status);
+  }
+
+private:
+  std::shared_ptr<UciHalSemaphore> GetSemaphore() {
+    return sem_;
+  }
+  void ReleaseSemaphore() {
+    sem_ = nullptr;
+  }
+  std::shared_ptr<UciHalSemaphore> sem_;
+  uint8_t gid_;
+  uint8_t oid_;
+};
+
 /* UCI Control structure */
 typedef struct phNxpUciHal_Control {
   phNxpUci_HalStatus halStatus; /* Indicate if hal is open or closed */
@@ -167,29 +241,15 @@ typedef struct phNxpUciHal_Control {
 
   std::unique_ptr<NxpUwbChip> uwb_chip;
 
-  /* Rx data */
-  uint8_t* p_rx_data;
-  uint16_t rx_data_len;
-
   /* libuwb-uci callbacks */
   uwb_stack_callback_t* p_uwb_stack_cback;
   uwb_stack_data_callback_t* p_uwb_stack_data_cback;
 
   /* HAL extensions */
   uint8_t hal_ext_enabled;
-  bool_t hal_parse_enabled;
 
   /* Waiting semaphore */
-  phNxpUciHal_Sem_t ext_cb_data;
-
-  // in case of fragmented response,
-  // ext_cb_data is flagged only from the 1st response packet
-  bool ext_cb_waiting;
-
-  uint16_t cmd_len;
-  uint8_t p_cmd_data[UCI_MAX_DATA_LEN];
-  uint16_t rsp_len;
-  uint8_t p_rsp_data[UCI_MAX_DATA_LEN];
+  CmdRspCheck cmdrsp;
 
   /* CORE_DEVICE_INFO_RSP cache */
   bool isDevInfoCached;
@@ -198,9 +258,6 @@ typedef struct phNxpUciHal_Control {
   phNxpUciHal_FW_Version_t fw_version;
   device_type_t device_type;
   uint8_t fw_boot_mode;
-
-  /* To skip sending packets to upper layer from HAL*/
-  uint8_t isSkipPacket;
   bool_t fw_dwnld_mode;
 
   // Per-country settings
@@ -213,6 +270,9 @@ typedef struct phNxpUciHal_Control {
   // Antenna Definitions for extra calibration, b0=Antenna1, b1=Antenna2, ...
   uint8_t cal_rx_antenna_mask;
   uint8_t cal_tx_antenna_mask;
+
+  // Current country code
+  uint8_t country_code[2];
 } phNxpUciHal_Control_t;
 
 // RX packet handler
@@ -237,29 +297,40 @@ struct phNxpUciHal_RxHandler;
 #define UWB_NXP_ANDROID_MW_DROP_VERSION (0x07) /* Android MW early drops */
 /******************** UCI HAL exposed functions *******************************/
 tHAL_UWB_STATUS phNxpUciHal_init_hw();
-tHAL_UWB_STATUS phNxpUciHal_write_unlocked(uint16_t data_len, const uint8_t *p_data);
-void phNxpUciHal_read_complete(void* pContext, phTmlUwb_TransactInfo_t* pInfo);
+tHAL_UWB_STATUS phNxpUciHal_write_unlocked(size_t cmd_len, const uint8_t* p_cmd);
+void phNxpUciHal_read_complete(void* pContext, phTmlUwb_ReadTransactInfo* pInfo);
+
+// Report UCI packet to upper layer
+void report_uci_message(const uint8_t* buffer, size_t len);
+
 tHAL_UWB_STATUS phNxpUciHal_uwb_reset();
 tHAL_UWB_STATUS phNxpUciHal_applyVendorConfig();
-tHAL_UWB_STATUS phNxpUciHal_process_ext_cmd_rsp(uint16_t cmd_len, const uint8_t *p_cmd, uint16_t *data_written);
+tHAL_UWB_STATUS phNxpUciHal_process_ext_cmd_rsp(size_t cmd_len, const uint8_t *p_cmd);
 void phNxpUciHal_send_dev_error_status_ntf();
+bool phNxpUciHal_parse(size_t* data_len, uint8_t *p_data);
+
+// RX packet handler
+// handler should returns true if the packet is handled and
+// shouldn't report it to the upper layer.
+
+using RxHandlerCallback = std::function<bool(size_t packet_len, const uint8_t *packet)>;
 
 std::shared_ptr<phNxpUciHal_RxHandler> phNxpUciHal_rx_handler_add(
   uint8_t mt, uint8_t gid, uint8_t oid,
-  bool skip_reporting, bool run_once,
-  std::function<void(size_t packet_len, const uint8_t *packet)> callback);
+  bool run_once,
+  RxHandlerCallback callback);
 void phNxpUciHal_rx_handler_del(std::shared_ptr<phNxpUciHal_RxHandler> handler);
 
-// Helper class for rx handler with once=false
+// Helper class for rx handler with run_once=false
 // auto-unregistered from destructor
+
 class UciHalRxHandler {
 public:
   UciHalRxHandler() {
   }
   UciHalRxHandler(uint8_t mt, uint8_t gid, uint8_t oid,
-                 bool skip_reporting,
-                 std::function<void(size_t packet_len, const uint8_t *packet)> callback) {
-    handler_ = phNxpUciHal_rx_handler_add(mt, gid, oid, skip_reporting, false, callback);
+                  RxHandlerCallback callback) {
+    handler_ = phNxpUciHal_rx_handler_add(mt, gid, oid, false, callback);
   }
   UciHalRxHandler& operator=(UciHalRxHandler &&handler) {
     handler_ = std::move(handler.handler_);
diff --git a/halimpl/hal/phNxpUciHal_ext.cc b/halimpl/hal/phNxpUciHal_ext.cc
index f5cc90d..6b8975f 100644
--- a/halimpl/hal/phNxpUciHal_ext.cc
+++ b/halimpl/hal/phNxpUciHal_ext.cc
@@ -58,95 +58,70 @@ static void phNxpUciHal_hw_reset_ntf_timeout_cb(uint32_t timerId,
  *                  returns failure.
  *
  ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_process_ext_cmd_rsp(uint16_t cmd_len,
-                                                const uint8_t *p_cmd,
-                                                uint16_t *data_written) {
+tHAL_UWB_STATUS phNxpUciHal_process_ext_cmd_rsp(size_t cmd_len,
+                                                const uint8_t *p_cmd) {
+  if (cmd_len > UCI_MAX_DATA_LEN) {
+    NXPLOG_UCIHAL_E("Packet size is too big to send: %u.", cmd_len);
+    return UWBSTATUS_FAILED;
+  }
+  if (cmd_len < 1) {
+    return UWBSTATUS_FAILED;
+  }
+
+
   // PBF=1 or DATA packet: don't check RSP
-  bool isRetryNotRequired = phNxpUciHal_is_retry_not_required(p_cmd[0]) || (cmd_len < 4);
+  // upper-layer should handle the case of UWBSTATUS_COMMAND_RETRANSMIT && isRetryNotRequired
+  if (phNxpUciHal_is_retry_not_required(p_cmd[0]) ||
+      cmd_len < UCI_MSG_HDR_SIZE) {
+    return phNxpUciHal_write_unlocked(cmd_len, p_cmd);
+  }
 
   const uint8_t mt = (p_cmd[0] & UCI_MT_MASK) >> UCI_MT_SHIFT;
   const uint8_t gid = p_cmd[0] & UCI_GID_MASK;
   const uint8_t oid = p_cmd[1] & UCI_OID_MASK;
 
-  if (mt == UCI_MT_CMD && gid == UCI_GID_SESSION_CONTROL && oid == UCI_MSG_SESSION_START) {
-    SessionTrack_onSessionStart(cmd_len, p_cmd);
-  }
-
-  // upper-layer should handle the case of UWBSTATUS_COMMAND_RETRANSMIT && isRetryNotRequired
-  if (isRetryNotRequired) {
-    *data_written = phNxpUciHal_write_unlocked(cmd_len, p_cmd);
-
-    if (*data_written != cmd_len) {
-      NXPLOG_UCIHAL_D("phNxpUciHal_write failed for hal ext");
-      return UWBSTATUS_FAILED;
-    } else {
-      return UWBSTATUS_SUCCESS;
-    }
-  }
+  // Create local copy of cmd_data
+  uint8_t cmd[UCI_MAX_DATA_LEN];
+  memcpy(cmd, p_cmd, cmd_len);
 
-  /* Create the local semaphore */
-  if (phNxpUciHal_init_cb_data(&nxpucihal_ctrl.ext_cb_data, NULL) != UWBSTATUS_SUCCESS) {
-    NXPLOG_UCIHAL_D("Create ext_cb_data failed");
-    return UWBSTATUS_FAILED;
+  /* Vendor Specific Parsing logic */
+  if (phNxpUciHal_parse(&cmd_len, cmd)) {
+    return UWBSTATUS_SUCCESS;
   }
 
   tHAL_UWB_STATUS status = UWBSTATUS_FAILED;
   int nr_retries = 0;
   int nr_timedout = 0;
-  bool exit_loop = false;
-
-  while(!exit_loop) {
-    nxpucihal_ctrl.ext_cb_data.status = UWBSTATUS_FAILED;
-    nxpucihal_ctrl.ext_cb_waiting = true;
 
-    *data_written = phNxpUciHal_write_unlocked(cmd_len, p_cmd);
+  while(nr_retries < MAX_COMMAND_RETRY_COUNT) {
+    nxpucihal_ctrl.cmdrsp.StartCmd(gid, oid);
+    status = phNxpUciHal_write_unlocked(cmd_len, cmd);
 
-    if (*data_written != cmd_len) {
-      status = UWBSTATUS_FAILED;
+    if (status != UWBSTATUS_SUCCESS) {
       NXPLOG_UCIHAL_D("phNxpUciHal_write failed for hal ext");
-      goto clean_and_return;
-    }
-
-    if (nxpucihal_ctrl.hal_parse_enabled) {
-      status = UWBSTATUS_SUCCESS;
-      goto clean_and_return;
+      nxpucihal_ctrl.cmdrsp.Cancel();
+      return status;
     }
 
     // Wait for rsp
-    phNxpUciHal_sem_timed_wait_msec(&nxpucihal_ctrl.ext_cb_data, HAL_EXTNS_WRITE_RSP_TIMEOUT_MS);
-
-    nxpucihal_ctrl.ext_cb_waiting = false;
+    status = nxpucihal_ctrl.cmdrsp.Wait(HAL_EXTNS_WRITE_RSP_TIMEOUT_MS);
 
-    switch (nxpucihal_ctrl.ext_cb_data.status) {
-    case UWBSTATUS_RESPONSE_TIMEOUT:
+    if (status == UWBSTATUS_RESPONSE_TIMEOUT) {
       nr_timedout++;
-      [[fallthrough]];
-    case UWBSTATUS_COMMAND_RETRANSMIT:
+      nr_retries++;
+    } else if (status == UWBSTATUS_COMMAND_RETRANSMIT) {
       // TODO: Do not retransmit CMD by here when !nxpucihal_ctrl.hal_ext_enabled,
       // Upper layer should take care of it.
       nr_retries++;
-      break;
-    default:
-      // Check CMD/RSP gid/oid matching
-      uint8_t rsp_gid = nxpucihal_ctrl.p_rx_data[0] & UCI_GID_MASK;
-      uint8_t rsp_oid = nxpucihal_ctrl.p_rx_data[1] & UCI_OID_MASK;
-      if (gid != rsp_gid || oid != rsp_oid) {
-        NXPLOG_UCIHAL_E("Received incorrect response of GID:%x OID:%x, expected GID:%x OID:%x",
-            rsp_gid, rsp_oid, gid, oid);
-        nr_retries++;
-      } else {
-        status = nxpucihal_ctrl.ext_cb_data.status;
-        exit_loop = true;
-      }
+    } else {
       break;
     }
+  }
 
-    if (nr_retries >= MAX_COMMAND_RETRY_COUNT) {
-      NXPLOG_UCIHAL_E("Failed to process cmd/rsp 0x%x", nxpucihal_ctrl.ext_cb_data.status);
-      status = UWBSTATUS_FAILED;
-      exit_loop = true;
-      phNxpUciHal_send_dev_error_status_ntf();
-    }
+  if (nr_retries >= MAX_COMMAND_RETRY_COUNT) {
+    NXPLOG_UCIHAL_E("Failed to process cmd/rsp 0x%x", status);
+    phNxpUciHal_send_dev_error_status_ntf();
+    return UWBSTATUS_FAILED;
   }
 
   if (nr_timedout > 0) {
@@ -154,9 +129,6 @@ tHAL_UWB_STATUS phNxpUciHal_process_ext_cmd_rsp(uint16_t cmd_len,
                     nr_retries, nr_timedout);
   }
 
-clean_and_return:
-  phNxpUciHal_cleanup_cb_data(&nxpucihal_ctrl.ext_cb_data);
-
   return status;
 }
 
@@ -171,19 +143,13 @@ clean_and_return:
  *                  response is received.
  *
  ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_send_ext_cmd(uint16_t cmd_len, const uint8_t* p_cmd) {
-  tHAL_UWB_STATUS status;
-
+tHAL_UWB_STATUS phNxpUciHal_send_ext_cmd(size_t cmd_len, const uint8_t* p_cmd) {
   if (cmd_len >= UCI_MAX_DATA_LEN) {
-    status = UWBSTATUS_FAILED;
-    return status;
+    return UWBSTATUS_FAILED;
   }
-  uint16_t data_written = 0;
+
   HAL_ENABLE_EXT();
-  nxpucihal_ctrl.cmd_len = cmd_len;
-  memcpy(nxpucihal_ctrl.p_cmd_data, p_cmd, cmd_len);
-  status = phNxpUciHal_process_ext_cmd_rsp(
-      nxpucihal_ctrl.cmd_len, nxpucihal_ctrl.p_cmd_data, &data_written);
+  tHAL_UWB_STATUS status = phNxpUciHal_process_ext_cmd_rsp(cmd_len, p_cmd);
   HAL_DISABLE_EXT();
 
   return status;
@@ -234,7 +200,7 @@ tHAL_UWB_STATUS phNxpUciHal_set_board_config(){
 ** Returns          UWBSTATUS_SUCCESS if success
 **
 *******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_process_ext_rsp(uint16_t rsp_len, uint8_t* p_buff){
+tHAL_UWB_STATUS phNxpUciHal_process_ext_rsp(size_t rsp_len, uint8_t* p_buff){
   tHAL_UWB_STATUS status;
   int NumOfTlv, index;
   uint8_t paramId, extParamId, IdStatus;
@@ -383,6 +349,7 @@ static bool phNxpUciHal_is_retry_not_required(uint8_t uci_octet0) {
   return isRetryRequired;
 }
 
+// TODO: remove this out
 /******************************************************************************
  * Function         CountryCodeCapsGenTxPowerPacket
  *
@@ -392,7 +359,7 @@ static bool phNxpUciHal_is_retry_not_required(uint8_t uci_octet0) {
  * Returns          true if packet has been updated
  *
  ******************************************************************************/
-static bool CountryCodeCapsGenTxPowerPacket(uint8_t *packet, size_t packet_len, uint16_t *out_len)
+static bool CountryCodeCapsGenTxPowerPacket(uint8_t *packet, size_t packet_len)
 {
   phNxpUciHal_Runtime_Settings_t *rt_set = &nxpucihal_ctrl.rt_settings;
 
@@ -402,10 +369,10 @@ static bool CountryCodeCapsGenTxPowerPacket(uint8_t *packet, size_t packet_len,
   if (gtx_power.empty())
     return false;
 
-  if (gtx_power.size() > packet_len)
+  if (gtx_power.size() != packet_len)
     return false;
 
-  uint16_t gtx_power_len = gtx_power.size();
+  size_t gtx_power_len = gtx_power.size();
   memcpy(packet, gtx_power.data(), gtx_power_len);
   uint8_t index = UCI_MSG_HDR_SIZE + 2;  // channel + Tag
 
@@ -444,12 +411,10 @@ static bool CountryCodeCapsGenTxPowerPacket(uint8_t *packet, size_t packet_len,
     packet[index++] = tx_power_u16 >> RMS_TX_POWER_SHIFT;
   }
 
-  if (out_len)
-    *out_len = gtx_power_len;
-
   return true;
 }
 
+// TODO: remove this out
 /*******************************************************************************
  * Function     phNxpUciHal_handle_set_calibration
  *
@@ -458,7 +423,7 @@ static bool CountryCodeCapsGenTxPowerPacket(uint8_t *packet, size_t packet_len,
  * Returns      void
  *
  *******************************************************************************/
-void phNxpUciHal_handle_set_calibration(const uint8_t *p_data, uint16_t data_len)
+void phNxpUciHal_handle_set_calibration(uint8_t *p_data, size_t data_len)
 {
   // Only saves the SET_CALIBRATION_CMD from upper-layer
   if (nxpucihal_ctrl.hal_ext_enabled) {
@@ -484,7 +449,7 @@ void phNxpUciHal_handle_set_calibration(const uint8_t *p_data, uint16_t data_len
   gtx_power = std::move(std::vector<uint8_t> {p_data, p_data + data_len});
 
   // Patch SET_CALIBRATION_CMD per gtx_power + tx_power_offset
-  CountryCodeCapsGenTxPowerPacket(nxpucihal_ctrl.p_cmd_data, sizeof(nxpucihal_ctrl.p_cmd_data), &nxpucihal_ctrl.cmd_len);
+  CountryCodeCapsGenTxPowerPacket(p_data, data_len);
 }
 
 /******************************************************************************
@@ -503,11 +468,11 @@ static bool CountryCodeCapsApplyTxPower(void)
 
   // use whole packet as-is from upper-layer command (gtx_power[])
   std::vector<uint8_t> packet(gtx_power.size());
-  uint16_t packet_size = 0;
-  if (!CountryCodeCapsGenTxPowerPacket(packet.data(), packet.size(), &packet_size))
+  size_t packet_size = 0;
+  if (!CountryCodeCapsGenTxPowerPacket(packet.data(), packet.size()))
     return false;
 
-  tHAL_UWB_STATUS status = phNxpUciHal_send_ext_cmd(packet_size, packet.data());
+  tHAL_UWB_STATUS status = phNxpUciHal_send_ext_cmd(packet.size(), packet.data());
   if (status != UWBSTATUS_SUCCESS) {
       NXPLOG_UCIHAL_D("%s: send failed", __func__);
   }
@@ -531,7 +496,7 @@ static void extcal_do_xtal(void)
     nxpucihal_ctrl.uwb_chip->read_otp(EXTCAL_PARAM_CLK_ACCURACY, xtal_data, sizeof(xtal_data), &xtal_data_len);
   }
   if (!xtal_data_len) {
-    long retlen = 0;
+    size_t retlen = 0;
     if (NxpConfig_GetByteArray("cal.xtal", xtal_data, sizeof(xtal_data), &retlen)) {
       xtal_data_len = retlen;
     }
@@ -646,12 +611,12 @@ static void extcal_do_tx_power(void)
         std::snprintf(key, sizeof(key), "cal.ant%u.ch%u.tx_power", ant_id, ch);
 
         uint8_t power_value[32];
-        long retlen = 0;
+        size_t retlen = 0;
         if (!NxpConfig_GetByteArray(key, power_value, sizeof(power_value), &retlen)) {
           continue;
         }
 
-        NXPLOG_UCIHAL_D("Apply TX_POWER: %s = { %lu bytes }", key, retlen);
+        NXPLOG_UCIHAL_D("Apply TX_POWER: %s = { %zu bytes }", key, retlen);
         entries.push_back(ant_id);
         entries.insert(entries.end(), power_value, power_value + retlen);
         n_entries++;
@@ -672,11 +637,11 @@ static void extcal_do_tx_power(void)
 static void extcal_do_tx_pulse_shape(void)
 {
   // parameters: cal.tx_pulse_shape={...}
-  long retlen = 0;
+  size_t retlen = 0;
   uint8_t data[64];
 
   if (NxpConfig_GetByteArray("cal.tx_pulse_shape", data, sizeof(data), &retlen) && retlen) {
-      NXPLOG_UCIHAL_D("Apply TX_PULSE_SHAPE: data = { %lu bytes }", retlen);
+      NXPLOG_UCIHAL_D("Apply TX_PULSE_SHAPE: data = { %zu bytes }", retlen);
 
       tHAL_UWB_STATUS ret = nxpucihal_ctrl.uwb_chip->apply_calibration(EXTCAL_PARAM_TX_PULSE_SHAPE, 0, data, (size_t)retlen);
       if (ret != UWBSTATUS_SUCCESS) {
@@ -691,7 +656,7 @@ static void extcal_do_tx_base_band(void)
   // parameters: cal.ddfs_enable=1|0, cal.dc_suppress=1|0, ddfs_tone_config={...}
   uint8_t ddfs_enable = 0, dc_suppress = 0;
   uint8_t ddfs_tone[256];
-  long retlen = 0;
+  size_t retlen = 0;
   tHAL_UWB_STATUS ret;
 
   if (NxpConfig_GetNum("cal.ddfs_enable", &ddfs_enable, 1)) {
@@ -707,7 +672,7 @@ static void extcal_do_tx_base_band(void)
       NXPLOG_UCIHAL_E("cal.ddfs_tone_config is not supplied while cal.ddfs_enable=1, ddfs was not enabled.");
       ddfs_enable = 0;
     } else {
-      NXPLOG_UCIHAL_D("Apply DDFS_TONE_CONFIG: ddfs_tone_config = { %lu bytes }", retlen);
+      NXPLOG_UCIHAL_D("Apply DDFS_TONE_CONFIG: ddfs_tone_config = { %zu bytes }", retlen);
 
       ret = nxpucihal_ctrl.uwb_chip->apply_calibration(EXTCAL_PARAM_DDFS_TONE_CONFIG, 0, ddfs_tone, (size_t)retlen);
       if (ret != UWBSTATUS_SUCCESS) {
@@ -786,13 +751,19 @@ void phNxpUciHal_handle_set_country_code(const char country_code[2])
   NXPLOG_UCIHAL_D("Apply country code %c%c", country_code[0], country_code[1]);
 
   phNxpUciHal_Runtime_Settings_t *rt_set = &nxpucihal_ctrl.rt_settings;
-  phNxpUciHal_resetRuntimeSettings();
 
   if (!is_valid_country_code(country_code)) {
     NXPLOG_UCIHAL_D("Country code %c%c is invalid, UWB should be disabled", country_code[0], country_code[1]);
-  }
+    phNxpUciHal_resetRuntimeSettings();
+    rt_set->uwb_enable = false;
+  } else if (!(nxpucihal_ctrl.country_code[0] == country_code[0] &&
+               nxpucihal_ctrl.country_code[1] == country_code[1])) {
+
+    nxpucihal_ctrl.country_code[0] = country_code[0];
+    nxpucihal_ctrl.country_code[1] = country_code[1];
+    NxpConfig_SetCountryCode(country_code);
+    phNxpUciHal_resetRuntimeSettings();
 
-  if (NxpConfig_SetCountryCode(country_code)) {
     // Load ExtraCal restrictions
     uint16_t mask= 0;
     if (NxpConfig_GetNum("cal.restricted_channels", &mask, sizeof(mask))) {
@@ -808,7 +779,7 @@ void phNxpUciHal_handle_set_country_code(const char country_code[2])
 
     // Apply COUNTRY_CODE_CAPS
     uint8_t cc_caps[UCI_MAX_DATA_LEN];
-    long retlen = 0;
+    size_t retlen = 0;
     if (NxpConfig_GetByteArray(NAME_NXP_UWB_COUNTRY_CODE_CAPS, cc_caps, sizeof(cc_caps), &retlen) && retlen) {
       NXPLOG_UCIHAL_D("COUNTRY_CODE_CAPS is provided.");
       phNxpUciHal_applyCountryCaps(country_code, cc_caps, retlen);
@@ -823,17 +794,21 @@ void phNxpUciHal_handle_set_country_code(const char country_code[2])
 
     // Apply per-country calibration, it's handled by SessionTrack
     SessionTrack_onCountryCodeChanged();
+  } else {
+    NXPLOG_UCIHAL_D("Country code %c%c: not changed, keep same configuration.",
+                    country_code[0], country_code[1]);
   }
 
   // send country code response to upper layer
-  nxpucihal_ctrl.rx_data_len = 5;
-  static uint8_t rsp_data[5] = { 0x4c, 0x01, 0x00, 0x01 };
   if (rt_set->uwb_enable) {
-    rsp_data[4] = UWBSTATUS_SUCCESS;
+    constexpr uint8_t rsp_data[5] = {
+      0x4c, 0x01, 0x00, 0x01, UWBSTATUS_SUCCESS };
+    report_uci_message(rsp_data, sizeof(rsp_data));
   } else {
-    rsp_data[4] = UCI_STATUS_CODE_ANDROID_REGULATION_UWB_OFF;
+    constexpr uint8_t rsp_data[5] = {
+      0x4c, 0x01, 0x00, 0x01, UCI_STATUS_CODE_ANDROID_REGULATION_UWB_OFF };
+    report_uci_message(rsp_data, sizeof(rsp_data));
   }
-  (*nxpucihal_ctrl.p_uwb_stack_data_cback)(nxpucihal_ctrl.rx_data_len, rsp_data);
 }
 
 // TODO: support fragmented packets
@@ -847,7 +822,7 @@ void phNxpUciHal_handle_set_country_code(const char country_code[2])
  *                  false : This packet should go to chip
  *
  *************************************************************************************/
-bool phNxpUciHal_handle_set_app_config(uint16_t *data_len, uint8_t *p_data)
+bool phNxpUciHal_handle_set_app_config(size_t *data_len, uint8_t *p_data)
 {
   const phNxpUciHal_Runtime_Settings_t *rt_set = &nxpucihal_ctrl.rt_settings;
   // Android vendor specific app configs not supported by FW
@@ -859,7 +834,7 @@ bool phNxpUciHal_handle_set_app_config(uint16_t *data_len, uint8_t *p_data)
   };
 
   // check basic validity
-  uint16_t payload_len = (p_data[UCI_CMD_LENGTH_PARAM_BYTE1] & 0xFF) |
+  size_t payload_len = (p_data[UCI_CMD_LENGTH_PARAM_BYTE1] & 0xFF) |
                          ((p_data[UCI_CMD_LENGTH_PARAM_BYTE2] & 0xFF) << 8);
   if (payload_len != (*data_len - UCI_MSG_HDR_SIZE)) {
     NXPLOG_UCIHAL_E("SESSION_SET_APP_CONFIG_CMD: payload length mismatch");
@@ -874,7 +849,7 @@ bool phNxpUciHal_handle_set_app_config(uint16_t *data_len, uint8_t *p_data)
 
   // Create local copy of cmd_data for data manipulation
   uint8_t uciCmd[UCI_MAX_DATA_LEN];
-  uint16_t packet_len = *data_len;
+  size_t packet_len = *data_len;
   if (sizeof(uciCmd) < packet_len) {
     NXPLOG_UCIHAL_E("SESSION_SET_APP_CONFIG_CMD packet size %u is too big to handle, skip patching.", packet_len);
     return false;
@@ -908,11 +883,10 @@ bool phNxpUciHal_handle_set_app_config(uint16_t *data_len, uint8_t *p_data)
         NXPLOG_UCIHAL_D("Country code blocked channel %u", ch);
 
         // send setAppConfig response with UCI_STATUS_CODE_ANDROID_REGULATION_UWB_OFF response
-        static uint8_t rsp_data[] = { 0x41, 0x03, 0x04, 0x04,
+        uint8_t rsp_data[] = { 0x41, 0x03, 0x04, 0x04,
           UCI_STATUS_FAILED, 0x01, tlv_tag, UCI_STATUS_CODE_ANDROID_REGULATION_UWB_OFF
         };
-        nxpucihal_ctrl.rx_data_len = sizeof(rsp_data);
-        (*nxpucihal_ctrl.p_uwb_stack_data_cback)(nxpucihal_ctrl.rx_data_len, rsp_data);
+        report_uci_message(rsp_data, sizeof(rsp_data));
         return true;
       }
     }
@@ -958,15 +932,15 @@ bool phNxpUciHal_handle_set_app_config(uint16_t *data_len, uint8_t *p_data)
   return false;
 }
 
-void phNxpUciHal_handle_get_caps_info(uint16_t data_len, uint8_t *p_data)
+bool phNxpUciHal_handle_get_caps_info(size_t data_len, const uint8_t *p_data)
 {
   if (data_len < UCI_MSG_CORE_GET_CAPS_INFO_NR_OFFSET)
-    return;
+    return false;
 
   uint8_t status = p_data[UCI_RESPONSE_STATUS_OFFSET];
   uint8_t nr = p_data[UCI_MSG_CORE_GET_CAPS_INFO_NR_OFFSET];
   if (status != UWBSTATUS_SUCCESS || nr < 1)
-    return;
+    return false;
 
   auto tlvs = decodeTlvBytes({0xe0, 0xe1, 0xe2, 0xe3}, &p_data[UCI_MSG_CORE_GET_CAPS_INFO_TLV_OFFSET], data_len - UCI_MSG_CORE_GET_CAPS_INFO_TLV_OFFSET);
   if (tlvs.size() != nr) {
@@ -1002,7 +976,7 @@ void phNxpUciHal_handle_get_caps_info(uint16_t data_len, uint8_t *p_data)
   // Append UWB_VENDOR_CAPABILITY from configuration files
   {
     std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
-    long retlen = 0;
+    size_t retlen = 0;
     if (NxpConfig_GetByteArray(NAME_UWB_VENDOR_CAPABILITY, buffer.data(),
                                buffer.size(), &retlen) && retlen) {
       auto vendorTlvs = decodeTlvBytes({}, buffer.data(), retlen);
@@ -1044,6 +1018,7 @@ void phNxpUciHal_handle_get_caps_info(uint16_t data_len, uint8_t *p_data)
   auto tlv_bytes = encodeTlvBytes(tlvs);
   if ((tlv_bytes.size() + UCI_MSG_CORE_GET_CAPS_INFO_TLV_OFFSET) > sizeof(packet)) {
     NXPLOG_UCIHAL_E("DevCaps overflow!");
+    return false;
   } else {
     uint8_t packet_len = UCI_MSG_CORE_GET_CAPS_INFO_TLV_OFFSET + tlv_bytes.size();
     packet[UCI_PAYLOAD_LENGTH_OFFSET] = packet_len - UCI_MSG_HDR_SIZE;
@@ -1051,10 +1026,9 @@ void phNxpUciHal_handle_get_caps_info(uint16_t data_len, uint8_t *p_data)
 
     phNxpUciHal_print_packet(NXP_TML_UCI_RSP_NTF_UWBS_2_AP, packet, packet_len);
 
-    // send GET CAPS INFO response to the Upper Layer
-    (*nxpucihal_ctrl.p_uwb_stack_data_cback)(packet_len, packet);
+    report_uci_message(packet, packet_len);
     // skip the incoming packet as we have send the modified response
     // already
-    nxpucihal_ctrl.isSkipPacket = 1;
+    return true;
   }
 }
diff --git a/halimpl/hal/phNxpUciHal_ext.h b/halimpl/hal/phNxpUciHal_ext.h
index 147847a..bff986e 100644
--- a/halimpl/hal/phNxpUciHal_ext.h
+++ b/halimpl/hal/phNxpUciHal_ext.h
@@ -1,5 +1,5 @@
 /*
- * Copyright 2012-2020, 2022-2023 NXP
+ * Copyright 2012-2020, 2022-2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -34,7 +34,6 @@
 #define UCI_EXT_PARAM_DDFS_TONE_CONFIG         0x27
 #define UCI_EXT_PARAM_TX_PULSE_SHAPE_CONFIG    0x28
 #define UCI_EXT_PARAM_CLK_CONFIG_CTRL          0x30
-#define UCI_EXT_PARAM_DBG_RFRAME_LOG_NTF       0x22
 
 #define UCI_PARAM_ID_LOW_POWER_MODE            0x01
 
@@ -57,14 +56,18 @@
 #define UCI_EXT_STATUS_SE_APDU_CMD_FAIL     0x74
 #define UCI_EXT_STATUS_SE_AUTH_FAIL         0x75
 
-tHAL_UWB_STATUS phNxpUciHal_send_ext_cmd(uint16_t cmd_len, const uint8_t* p_cmd);
-tHAL_UWB_STATUS phNxpUciHal_process_ext_rsp(uint16_t cmd_len, uint8_t* p_buff);
+tHAL_UWB_STATUS phNxpUciHal_send_ext_cmd(size_t cmd_len, const uint8_t* p_cmd);
+tHAL_UWB_STATUS phNxpUciHal_process_ext_rsp(size_t cmd_len, uint8_t* p_buff);
 tHAL_UWB_STATUS phNxpUciHal_set_board_config();
-void phNxpUciHal_handle_set_calibration(const uint8_t *p_data, uint16_t data_len);
+void phNxpUciHal_handle_set_calibration(uint8_t *p_data, size_t data_len);
 void phNxpUciHal_extcal_handle_coreinit(void);
 void phNxpUciHal_process_response();
 void phNxpUciHal_handle_set_country_code(const char country_code[2]);
-bool phNxpUciHal_handle_set_app_config(uint16_t *data_len, uint8_t *p_data);
-void phNxpUciHal_handle_get_caps_info(uint16_t data_len, uint8_t *p_data);
+bool phNxpUciHal_handle_set_app_config(size_t *data_len, uint8_t *p_data);
+
+// Handles CORE_GET_CAPS_INFO_RSP
+// Returns true if the packet is patched / reported to upper layer.
+bool phNxpUciHal_handle_get_caps_info(size_t data_len, const uint8_t *p_data);
+
 void apply_per_country_calibrations(void);
 #endif /* _PHNXPNICHAL_EXT_H_ */
diff --git a/halimpl/hal/sessionTrack.cc b/halimpl/hal/sessionTrack.cc
index be63067..af3ebdb 100644
--- a/halimpl/hal/sessionTrack.cc
+++ b/halimpl/hal/sessionTrack.cc
@@ -83,7 +83,7 @@ private:
     std::condition_variable cond_;
 
     SessionTrackMsg(SessionTrackWorkType type, bool sync)
-        : type_(type), sync_(sync), cond_flag(false) {}
+        : type_(type), session_info_(nullptr), sync_(sync), cond_flag(false) {}
 
     // Per-session work item
     SessionTrackMsg(SessionTrackWorkType type,
@@ -92,7 +92,7 @@ private:
           cond_flag(false) {}
   };
   static constexpr unsigned long kAutoSuspendTimeoutDefaultMs_ = (30 * 1000);
-  static constexpr long kQueueTimeoutMs = 500;
+  static constexpr long kQueueTimeoutMs = 2000;
   static constexpr long kUrskDeleteNtfTimeoutMs = 500;
 
 private:
@@ -153,7 +153,7 @@ public:
     // register SESSION_STATUS_NTF rx handler
     rx_handler_session_status_ntf_ = phNxpUciHal_rx_handler_add(
       UCI_MT_NTF, UCI_GID_SESSION_MANAGE, UCI_MSG_SESSION_STATUS_NTF,
-      false, false,
+      false,
       std::bind(&SessionTrack::OnSessionStatusNtf, this, std::placeholders::_1, std::placeholders::_2));
   }
 
@@ -163,8 +163,7 @@ public:
     if (auto_suspend_enabled_) {
       phOsalUwb_Timer_Delete(idle_timer_);
     }
-    auto msg = std::make_shared<SessionTrackMsg>(SessionTrackWorkType::STOP, true);
-    QueueSessionTrackWork(msg);
+    QueueSessionTrackWork(SessionTrackWorkType::STOP);
     worker_thread_.join();
   }
 
@@ -179,15 +178,15 @@ public:
 
     // Check SESSION_INIT_RSP for SessionID - Handle matching
     auto session_init_rsp_cb =
-      [this, session_id, session_type](size_t packet_len, const uint8_t *packet)
+      [this, session_id, session_type](size_t packet_len, const uint8_t *packet) -> bool
     {
       if (packet_len != UCI_MSG_SESSION_STATE_INIT_RSP_LEN )
-        return;
+        return false;
 
       uint8_t status = packet[UCI_MSG_SESSION_STATE_INIT_RSP_STATUS_OFFSET];
       uint32_t handle = le_bytes_to_cpu<uint32_t>(&packet[UCI_MSG_SESSION_STATE_INIT_RSP_HANDLE_OFFSET]);
       if (status != UWBSTATUS_SUCCESS)
-        return;
+        return false;
 
       bool was_idle;
       {
@@ -200,15 +199,16 @@ public:
       }
       if (was_idle) {
         NXPLOG_UCIHAL_D("Queue Active");
-        auto msg = std::make_shared<SessionTrackMsg>(SessionTrackWorkType::ACTIVATE, false);
-        QueueSessionTrackWork(msg);
+        QueueSessionTrackWork(SessionTrackWorkType::ACTIVATE);
       }
+
+      return false;
     };
 
     // XXX: This rx handler can be called multiple times on
     // UCI_STATUS_COMMAND_RETRY(0xA) from SESSION_INIT_CMD
     phNxpUciHal_rx_handler_add(UCI_MT_RSP, UCI_GID_SESSION_MANAGE,
-      UCI_MSG_SESSION_STATE_INIT, false, true, session_init_rsp_cb);
+      UCI_MSG_SESSION_STATE_INIT, true, session_init_rsp_cb);
   }
 
   // Called by upper-layer's SetAppConfig command handler
@@ -261,8 +261,7 @@ public:
   }
 
   void RefreshIdle() {
-    auto msg = std::make_shared<SessionTrackMsg>(SessionTrackWorkType::REFRESH_IDLE, true);
-    QueueSessionTrackWork(msg);
+    QueueSessionTrackWork(SessionTrackWorkType::REFRESH_IDLE);
   }
 
   void OnSessionStart(size_t packet_len, const uint8_t *packet) {
@@ -342,20 +341,21 @@ private:
     phNxpUciHal_init_cb_data(&urskDeleteNtfWait, NULL);
 
     phNxpUciHal_rx_handler_add(UCI_MT_RSP, UCI_GID_PROPRIETARY_0X0F,
-      UCI_MSG_URSK_DELETE, true, true,
-      [](size_t packet_len, const uint8_t *packet) {
+      UCI_MSG_URSK_DELETE, true,
+      [](size_t packet_len, const uint8_t *packet) -> bool {
         if (packet_len < 5)
-          return;
+          return true;
         if (packet[4] != UWBSTATUS_SUCCESS) {
           NXPLOG_UCIHAL_E("SessionTrack: URSR_DELETE failed, rsp status=0x%x", packet[4]);
         }
+        return true;
       }
     );
     phNxpUciHal_rx_handler_add(UCI_MT_NTF, UCI_GID_PROPRIETARY_0X0F,
-      UCI_MSG_URSK_DELETE, true, true,
-      [&urskDeleteNtfWait](size_t packet_len, const uint8_t *packet) {
+      UCI_MSG_URSK_DELETE, true,
+      [&urskDeleteNtfWait](size_t packet_len, const uint8_t *packet) -> bool {
         if (packet_len < 6)
-          return;
+          return true;
         uint8_t status = packet[4];
         uint8_t nr = packet[5];
 
@@ -384,6 +384,7 @@ private:
           }
         }
         SEM_POST(&urskDeleteNtfWait);
+        return true;
       }
     );
 
@@ -418,29 +419,30 @@ private:
     bool result = false;
 
     phNxpUciHal_rx_handler_add(UCI_MT_RSP, UCI_GID_SESSION_MANAGE,
-      UCI_MSG_SESSION_GET_APP_CONFIG, true, true,
-      [&val, &result, tag](size_t packet_len, const uint8_t *packet) {
+      UCI_MSG_SESSION_GET_APP_CONFIG, true,
+      [&val, &result, tag](size_t packet_len, const uint8_t *packet) -> bool {
         if (packet_len != 12)
-          return;
+          return true;
 
         if (packet[4] != UWBSTATUS_SUCCESS) {
           NXPLOG_UCIHAL_E("SessionTrack: GetAppConfig failed, status=0x%02x", packet[4]);
-          return;
+          return true;
         }
         if (packet[5] != 1) {
           NXPLOG_UCIHAL_E("SessionTrack: GetAppConfig failed, nr=%u", packet[5]);
-          return;
+          return true;
         }
         if (packet[6] != tag) {
           NXPLOG_UCIHAL_E("SessionTrack: GetAppConfig failed, tag=0x%02x, expected=0x%02x", packet[6], tag);
-          return;
+          return true;
         }
         if (packet[7] != 4) {
           NXPLOG_UCIHAL_E("SessionTrack: GetAppConfig failed, len=%u", packet[7]);
-          return;
+          return true;
         }
         val = le_bytes_to_cpu<uint32_t>(&packet[8]);
         result = true;
+        return true;
       }
     );
 
@@ -506,16 +508,16 @@ private:
     std::random_device rdev;
     std::mt19937 rng(rdev());
 
-    // valid range is [0, 2~30), but use half of it to prevent roll over
-    std::uniform_int_distribution<std::mt19937::result_type> sts_index(0, (1 << 16) - 1);
+    // valid range is [1, 2~30), but use half of it to prevent roll over
+    std::uniform_int_distribution<std::mt19937::result_type> sts_index(1, (1 << 16) - 1);
     return sts_index(rng);
   }
 
   // UCI_MSG_SESSION_STATUS_NTF rx handler
-  void OnSessionStatusNtf(size_t packet_len, const uint8_t* packet) {
+  bool OnSessionStatusNtf(size_t packet_len, const uint8_t* packet) {
     if (packet_len != UCI_MSG_SESSION_STATUS_NTF_LENGTH) {
       NXPLOG_UCIHAL_E("SessionTrack: SESSION_STATUS_NTF packet parse error");
-      return;
+      return false;
     }
 
     uint32_t session_handle = le_bytes_to_cpu<uint32_t>(&packet[UCI_MSG_SESSION_STATUS_NTF_HANDLE_OFFSET]);
@@ -536,9 +538,10 @@ private:
 
         if (delete_ursk_ccc_enabled_ && pSessionInfo &&
             pSessionInfo->session_type_ == kSessionType_CCCRanging) {
+
           // If this CCC ranging session, issue DELETE_URSK_CMD for this session.
-          auto msg = std::make_shared<SessionTrackMsg>(SessionTrackWorkType::DELETE_URSK, pSessionInfo, true);
-          QueueSessionTrackWork(msg);
+          // This is executed on client thread, we shouldn't block the execution of this thread.
+          QueueDeleteUrsk(pSessionInfo);
         }
         sessions_.erase(session_handle);
         is_idle = IsDeviceIdle();
@@ -550,15 +553,15 @@ private:
 
     if (is_idle) { // transition to IDLE
       NXPLOG_UCIHAL_D("Queue Idle");
-      auto msg = std::make_shared<SessionTrackMsg>(SessionTrackWorkType::IDLE, false);
-      QueueSessionTrackWork(msg);
+      QueueSessionTrackWork(SessionTrackWorkType::IDLE);
     }
+
+    return false;
   }
 
   static void IdleTimerCallback(uint32_t TimerId, void* pContext) {
     SessionTrack *mgr = static_cast<SessionTrack*>(pContext);
-    auto msg = std::make_shared<SessionTrackMsg>(SessionTrackWorkType::IDLE_TIMER_FIRED, false);
-    mgr->QueueSessionTrackWork(msg);
+    mgr->QueueSessionTrackWork(SessionTrackWorkType::IDLE_TIMER_FIRED);
   }
 
   void PowerIdleTimerStop() {
@@ -644,7 +647,9 @@ private:
         }
         break;
       case SessionTrackWorkType::DELETE_URSK:
+        CONCURRENCY_LOCK();
         DeleteUrsk(msg->session_info_);
+        CONCURRENCY_UNLOCK();
         break;
       case SessionTrackWorkType::STOP:
         stop_thread = true;
@@ -654,6 +659,7 @@ private:
         break;
       }
       if (msg->sync_) {
+        std::lock_guard<std::mutex> lock(sync_mutex_);
         msg->cond_flag = true;
         msg->cond_.notify_one();
       }
@@ -671,12 +677,28 @@ private:
     if (msg->sync_) {
       std::unique_lock<std::mutex> lock(sync_mutex_);
       if (!msg->cond_.wait_for(lock, std::chrono::milliseconds(kQueueTimeoutMs),
-                               [msg] { return msg->cond_flag; })) {
+                               [&msg] { return msg->cond_flag; })) {
         NXPLOG_UCIHAL_E("SessionTrack: timeout to process %d", static_cast<int>(msg->type_));
       }
     }
   }
 
+  void QueueSessionTrackWork(SessionTrackWorkType work) {
+    // When sync is true, the job shouldn't trigger another transaction.
+    // TODO: strict checking of each job is not executing UCI transactions.
+    bool sync = (work == SessionTrackWorkType::STOP ||
+                 work == SessionTrackWorkType::REFRESH_IDLE);
+    auto msg = std::make_shared<SessionTrackMsg>(work, sync);
+    QueueSessionTrackWork(msg);
+  }
+
+  void QueueDeleteUrsk(std::shared_ptr<SessionInfo> pSessionInfo) {
+    // This job will execute another UCI transaction.
+    auto msg = std::make_shared<SessionTrackMsg>(
+      SessionTrackWorkType::DELETE_URSK, pSessionInfo, false);
+    QueueSessionTrackWork(msg);
+  }
+
   std::shared_ptr<SessionInfo> GetSessionInfo(uint32_t session_handle) {
     auto it = sessions_.find(session_handle);
     if (it == sessions_.end()) {
diff --git a/halimpl/hal/sr200/NxpUwbChipSr200.cc b/halimpl/hal/sr200/NxpUwbChipSr200.cc
deleted file mode 100644
index 2b28127..0000000
--- a/halimpl/hal/sr200/NxpUwbChipSr200.cc
+++ /dev/null
@@ -1,182 +0,0 @@
-#include "NxpUwbChip.h"
-#include "phNxpConfig.h"
-#include "phNxpUciHal.h"
-#include "phNxpUciHal_ext.h"
-#include "phUwbStatus.h"
-#include "phUwbTypes.h"
-#include "phNxpUwbCalib.h"
-#include "uci_defs.h"
-
-#define UCI_MSG_UWB_ESE_BINDING_LEN                   11
-#define UCI_MSG_UWB_ESE_BINDING_OFFSET_COUNT          5
-#define UCI_MSG_UWB_ESE_BINDING_OFFSET_BINDING_STATE  6
-
-extern phNxpUciHal_Control_t nxpucihal_ctrl;
-extern int hdll_fw_download();
-
-class NxpUwbChipSr200 final : public NxpUwbChip {
-public:
-  NxpUwbChipSr200();
-  virtual ~NxpUwbChipSr200();
-
-  tHAL_UWB_STATUS chip_init();
-  tHAL_UWB_STATUS core_init();
-  device_type_t get_device_type(const uint8_t *param, size_t param_len);
-  tHAL_UWB_STATUS read_otp(extcal_param_id_t id, uint8_t *data, size_t data_len, size_t *retlen);
-  tHAL_UWB_STATUS apply_calibration(extcal_param_id_t id, const uint8_t ch, const uint8_t *data, size_t data_len);
-  tHAL_UWB_STATUS get_supported_channels(const uint8_t **cal_channels, uint8_t *nr);
-private:
-  void on_binding_status_ntf(size_t packet_len, const uint8_t* packet);
-
-  tHAL_UWB_STATUS check_binding_done();
-
-  UciHalRxHandler bindingStatusNtfHandler_;
-  UciHalSemaphore bindingStatusNtfWait_;
-  uint8_t bindingStatus_;
-};
-
-NxpUwbChipSr200::NxpUwbChipSr200() :
-  bindingStatus_(UWB_DEVICE_UNKNOWN)
-{
-}
-
-NxpUwbChipSr200::~NxpUwbChipSr200()
-{
-}
-
-void NxpUwbChipSr200::on_binding_status_ntf(size_t packet_len, const uint8_t* packet)
-{
-  if (packet_len >= UCI_RESPONSE_STATUS_OFFSET) {
-    bindingStatus_ = packet[UCI_RESPONSE_STATUS_OFFSET];
-    NXPLOG_UCIHAL_D("BINDING_STATUS_NTF: 0x%x", bindingStatus_);
-    bindingStatusNtfWait_.post(UWBSTATUS_SUCCESS);
-  }
-}
-
-tHAL_UWB_STATUS NxpUwbChipSr200::check_binding_done()
-{
-  // Wait for Binding status notification
-  if (bindingStatusNtfWait_.getStatus() != UWBSTATUS_SUCCESS) {
-    bindingStatusNtfWait_.wait();
-  }
-  if (bindingStatusNtfWait_.getStatus() != UWBSTATUS_SUCCESS) {
-    NXPLOG_UCIHAL_E("Binding status notification timeout");
-
-    // Stop HAL init when it didn't receive the binding notification
-    if (nxpucihal_ctrl.fw_boot_mode == USER_FW_BOOT_MODE)
-      return UWBSTATUS_FAILED;
-    else
-      return UWBSTATUS_SUCCESS;
-  }
-
-  switch (bindingStatus_) {
-  case UWB_DEVICE_NOT_BOUND:
-    NXPLOG_UCIHAL_E("Binding status: Unbound.");
-    break;
-  case UWB_DEVICE_BOUND_UNLOCKED:
-    NXPLOG_UCIHAL_E("Binding status: bound & unlocked.");
-    break;
-  case UWB_DEVICE_BOUND_LOCKED:
-    NXPLOG_UCIHAL_D("Binding status: bound & locked.");
-    break;
-  case UWB_DEVICE_UNKNOWN:
-    NXPLOG_UCIHAL_D("Binding status: Unknown.");
-    break;
-  default:
-    NXPLOG_UCIHAL_E("Unknown binding status: 0x%x", bindingStatus_);
-    return UWBSTATUS_FAILED;
-  }
-
-  return UWBSTATUS_SUCCESS;
-}
-
-tHAL_UWB_STATUS NxpUwbChipSr200::chip_init()
-{
-  tHAL_UWB_STATUS status;
-
-  // system in FW download mode
-  // This will be cleared on first Device Status NTF
-  nxpucihal_ctrl.fw_dwnld_mode = true;
-
-  NXPLOG_UCIHAL_D("Start SR200 FW download");
-
-  for (int i = 0; i < 5; i++) {
-    phTmlUwb_Chip_Reset();
-
-    status = hdll_fw_download();
-
-    if (status == UWBSTATUS_SUCCESS) {
-      NXPLOG_UCIHAL_D("Complete SR200 FW download");
-      break;
-    } else if(status == UWBSTATUS_FILE_NOT_FOUND) {
-      NXPLOG_UCIHAL_E("FW file Not found.");
-      break;
-    } else {
-      NXPLOG_UCIHAL_E("FW download failed, status= 0x%x, retry.", status);
-    }
-  }
-
-  // register binding status ntf handler
-  bindingStatusNtfHandler_ = UciHalRxHandler(
-      UCI_MT_NTF, UCI_GID_PROPRIETARY, UCI_MSG_BINDING_STATUS_NTF,
-      true,
-      std::bind(&NxpUwbChipSr200::on_binding_status_ntf, this, std::placeholders::_1, std::placeholders::_2));
-
-  return status;
-}
-
-tHAL_UWB_STATUS NxpUwbChipSr200::core_init()
-{
-  return check_binding_done();
-}
-
-device_type_t NxpUwbChipSr200::get_device_type(const uint8_t *param, size_t param_len)
-{
-  // should be 'SR200..'
-  const char marker[] = { 'S', 'R', '2', '0', '0' };
-  if (param_len >= sizeof(marker)) {
-    if (!memcmp(param, marker, sizeof(marker)))
-      return DEVICE_TYPE_SR200;
-  }
-  return DEVICE_TYPE_UNKNOWN;
-}
-
-tHAL_UWB_STATUS
-NxpUwbChipSr200::read_otp(extcal_param_id_t id,
-                          uint8_t *data, size_t data_len, size_t *retlen)
-{
-  return UWBSTATUS_NOT_ALLOWED;
-}
-
-tHAL_UWB_STATUS
-NxpUwbChipSr200::apply_calibration(extcal_param_id_t id, const uint8_t ch,
-                                   const uint8_t *data, size_t data_len)
-{
-  switch (id) {
-  case EXTCAL_PARAM_TX_POWER:
-  case EXTCAL_PARAM_TX_BASE_BAND_CONTROL:
-  case EXTCAL_PARAM_DDFS_TONE_CONFIG:
-  case EXTCAL_PARAM_TX_PULSE_SHAPE:
-    return sr1xx_apply_calibration(id, ch, data, data_len);
-  case EXTCAL_PARAM_CLK_ACCURACY:
-  case EXTCAL_PARAM_RX_ANT_DELAY:
-    /* break through */
-  default:
-    NXPLOG_UCIHAL_E("Unsupported parameter: 0x%x", id);
-    return UWBSTATUS_FAILED;
-  }
-}
-
-tHAL_UWB_STATUS
-NxpUwbChipSr200::get_supported_channels(const uint8_t **cal_channels, uint8_t *nr)
-{
-  static const uint8_t sr200_cal_channels[] = {5, 9, 10};
-  *cal_channels = sr200_cal_channels;
-  *nr = std::size(sr200_cal_channels);
-  return UWBSTATUS_SUCCESS;
-}
-
-std::unique_ptr<NxpUwbChip> GetUwbChip()
-{
-  return std::make_unique<NxpUwbChipSr200>();
-}
diff --git a/halimpl/hal/sr200/fwd_hdll.cc b/halimpl/hal/sr200/fwd_hdll.cc
deleted file mode 100644
index 45145ca..0000000
--- a/halimpl/hal/sr200/fwd_hdll.cc
+++ /dev/null
@@ -1,2168 +0,0 @@
-/*
- * Copyright 2021-2023 NXP
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
-#include <sys/ioctl.h>
-#include <dlfcn.h>
-
-#include "fwd_hdll.h"
-#include "phNxpConfig.h"
-#include "phNxpLog.h"
-#include "phNxpUciHal_fwd_utils.h"
-#include "phNxpUciHal_utils.h"
-#include "phTmlUwb_spi.h"
-
-#define MAX_FRAME_LEN 4200
-static uint8_t is_fw_download_log_enabled = 0x00;
-
-static phFWD_Status_t openFwBinFile(phUwbFWImageContext_t *pfwImageCtx);
-static phFWD_Status_t openFwSoFile(phUwbFWImageContext_t *pfwImageCtx);
-static phFWD_Status_t phNxpUciHal_fw_recovery(phUwbFWImageContext_t *pfwImageCtx);
-
-char default_fw_path[FILEPATH_MAXLEN] = "/vendor/firmware/uwb/";
-const char *default_dev_fw_bin = "libsr200t_fw.bin";
-const char *default_dev_fw_so = "libsr200t_fw.so";
-const char *default_so_file_extn = ".so";
-extern uint32_t timeoutTimerId;
-static bool isHdllReadTmeoutExpired = false;
-static bool bSkipEdlCheck = false;
-static bool glcRotation = false;
-
-phUwbFWImageContext_t fwImageCtx;
-
-/*******************************************************************************
-**
-** Function    :   phGenericSendAndRecv
-**
-** Description :   This function sends the HDLL commands to HeliosX chip over
-                   SPI using phHdll_PutApdu() and gets the response using
-                   phHdll_GetApdu().
-**
-** Parameters  :   payload     - HDLL command to be sent
-                   len         - HDLL command length
-                   readbuff    - HDLL command response buffer
-                   rsp_buf_len - HDLL command rsponse buffer length
-**
-** Returns     :   phFWD_Status_t : 0 - success
-                                     1 - failure
-**
-**
-*******************************************************************************/
-phFWD_Status_t phGenericSendAndRecv(uint8_t *payload, uint16_t len,
-                                    uint8_t *read_buff, uint16_t *rsp_buf_len) {
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-  if (FW_DNLD_SUCCESS != (ret = phHdll_PutApdu((uint8_t *)&payload[0], len))) {
-    return ret;
-  }
-  if (FW_DNLD_SUCCESS !=
-      (ret = phHdll_GetApdu((uint8_t *)&read_buff[0], HDLL_READ_BUFF_SIZE,
-                            rsp_buf_len))) {
-    return ret;
-  }
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   print_getInfoRsp
-**
-** Description :   This function prints the HDLL GetInfo command's response
-**
-** Parameters  :   getInfoRsp  - Struct which has the GetInfo response details.
-**
-** Returns     :   None
-**
-**
-*******************************************************************************/
-void print_getInfoRsp(phHDLLGetInfo_t *getInfoRsp) {
-  uint8_t i = 0, offset = 0;
-  char buff[HDLL_READ_BUFF_SIZE] = {0};
-  if (NULL == getInfoRsp) {
-    return;
-  }
-  NXPLOG_FWDNLD_D("=====================GET_INFO =======================\n");
-  NXPLOG_FWDNLD_D("Boot Status: 0x%02X\n", getInfoRsp->boot_status);
-  NXPLOG_FWDNLD_D("Session Control: 0x%02X\n", getInfoRsp->session_control);
-  NXPLOG_FWDNLD_D("Session Type: 0x%02X\n", getInfoRsp->session_type);
-  NXPLOG_FWDNLD_D("ROM Version: 0x%02X\n", getInfoRsp->rom_version);
-  NXPLOG_FWDNLD_D("AT Page Status: 0x%02X\n", getInfoRsp->AT_page_status);
-  NXPLOG_FWDNLD_D("Chip Version: Major.Minor: %02X.%02X\n",
-                  getInfoRsp->chip_major_ver, getInfoRsp->chip_minor_ver);
-  NXPLOG_FWDNLD_D("FW Version: Major.Minor: %02X.%02X\n",
-                  getInfoRsp->fw_major_ver, getInfoRsp->fw_minor_ver);
-
-  for (i = 0; i != 8; i += 2) { // 4bytes
-    sprintf(&buff[i], "%02X", getInfoRsp->chip_variant[offset++]);
-  }
-  buff[i] = '\0';
-  NXPLOG_FWDNLD_D("Chip Variant: 0x%s\n", buff);
-  NXPLOG_FWDNLD_D("Device Lifecycle: 0x%X\n", getInfoRsp->device_life_cycle);
-
-  for (i = 0, offset = 0; i != 32; i += 2) { // 16bytes
-    sprintf(&buff[i], "%02X", getInfoRsp->chip_id[offset++]);
-  }
-  buff[i] = '\0';
-  NXPLOG_FWDNLD_D("Chip ID: 0x%s\n", buff);
-
-  for (i = 0, offset = 0; i != 8; i += 2) { // 4bytes
-    sprintf(&buff[i], "%02X", getInfoRsp->chip_id_crc[offset++]);
-  }
-  buff[i] = '\0';
-  NXPLOG_FWDNLD_D("Chip ID CRC:0x%s\n", buff);
-  NXPLOG_FWDNLD_D("=====================================================\n");
-}
-
-/*******************************************************************************
-**
-** Function    :   process_getInfo_rsp
-**
-** Description :   This function processes the HDLL GetInfo command's response
-**
-** Parameters  :   payload  - Struct in which the processed info will be kept
-**
-** Returns     :   On failure - NULL
-                   On success - Pointer to the phHDLLGetInfo_t struct
-**
-**
-*******************************************************************************/
-phHDLLGetInfo_t *process_getInfo_rsp(uint8_t *payload) {
-  uint8_t offset = 0;
-  phHDLLGetInfo_t *getInfoRsp = NULL;
-  uint8_t device_lc_mode[4] = {0};
-
-  getInfoRsp = (phHDLLGetInfo_t *)malloc(sizeof(phHDLLGetInfo_t));
-  if (NULL == getInfoRsp) {
-    return NULL;
-  }
-  memset(getInfoRsp, 0, sizeof(phHDLLGetInfo_t));
-  getInfoRsp->boot_status = payload[offset++];
-  getInfoRsp->session_control = payload[offset++];
-  getInfoRsp->session_type = payload[offset++];
-  getInfoRsp->rom_version = (eUWBD_Rom_Version_t)payload[offset++];
-  getInfoRsp->AT_page_status = (eUWBD_AT_Page_status_t)payload[offset++];
-  offset += 2; // padding bytes
-  getInfoRsp->chip_major_ver = payload[offset++];
-  getInfoRsp->chip_minor_ver = payload[offset++];
-  getInfoRsp->fw_major_ver = payload[offset++];
-  getInfoRsp->fw_minor_ver = payload[offset++];
-  memcpy(getInfoRsp->chip_variant, payload + offset, sizeof(uint8_t) * 4);
-  offset += 4;
-  memcpy(device_lc_mode, payload + offset, sizeof(uint8_t) * 4);
-  getInfoRsp->device_life_cycle = (eUWBD_LC_mode_t)(device_lc_mode[0] | (device_lc_mode[1] << 8) | (device_lc_mode[2] << 16) | (device_lc_mode[3] << 24));
-  offset += 4;
-  memcpy(getInfoRsp->chip_id, payload + offset, sizeof(uint8_t) * 16);
-  offset += 16;
-  memcpy(getInfoRsp->chip_id_crc, payload + offset, sizeof(uint8_t) * 4);
-  return getInfoRsp;
-}
-
-/*******************************************************************************
-**
-** Function    :   getFwImageCtx
-**
-** Description :   This function use to get the FW image context
-**
-** Parameters  :   pfwImageCtx -> pointer to fw image context
-**
-** Returns     :   On failure - returns FW_DNLD_FAILURE
-                              - or FW_DNLD_FILE_NOT_FOUND if FW file not present
-                                in the MW.
-                   On success - returns FW_DNLD_SUCCESS.
-**
-**
-*******************************************************************************/
-phFWD_Status_t getFwImageCtx(phUwbFWImageContext_t *pfwImageCtx) {
-  phFWD_Status_t status = FW_DNLD_SUCCESS;
-  char *configured_fw_name = NULL;
-  const uint16_t fw_file_max_len = FILENAME_MAXLEN;
-  const char *pDefaultFwFileName = NULL;
-  char* ret = NULL;
-
-  configured_fw_name = (char *)malloc(fw_file_max_len * sizeof(char));
-  int maxSrcLen = (FILEPATH_MAXLEN - strlen(pfwImageCtx->default_fw_path)) - 1;
-  if (configured_fw_name == NULL) {
-    NXPLOG_FWDNLD_E("malloc of configured_fw_name failed ");
-    return FW_DNLD_FAILURE;
-  }
-
-  /* Default FW download configset to bin file */
-  pDefaultFwFileName = default_dev_fw_bin;
-
-  if (!NxpConfig_GetStr(NAME_NXP_UWB_FW_FILENAME, configured_fw_name,
-                            fw_file_max_len)) {
-    NXPLOG_FWDNLD_D("Invalid Dev Fw  name keeping the default name: %s",
-                    pDefaultFwFileName);
-    strncat(pfwImageCtx->default_fw_path, pDefaultFwFileName, maxSrcLen);
-  } else {
-    NXPLOG_FWDNLD_D("configured_fw_name : %s", configured_fw_name);
-    strncat(pfwImageCtx->default_fw_path, configured_fw_name, maxSrcLen);
-  }
-
-  NXPLOG_FWDNLD_D("fw file path : %s", pfwImageCtx->default_fw_path);
-  // Search for so extension in filename
-  ret = strstr(configured_fw_name, default_so_file_extn);
-  if(ret) {
-    pfwImageCtx->fw_dnld_config = SO_FILE_BASED_FW_DOWNLOAD;
-    /* Get Fw Context from so file */
-    status = openFwSoFile(pfwImageCtx);
-  } else {
-    /* Get Fw Context from bin file */
-    status = openFwBinFile(pfwImageCtx);
-  }
-
-  if (configured_fw_name != NULL) {
-      free(configured_fw_name);
-    }
-  memset(pfwImageCtx->default_fw_path, '\0', sizeof(char) * FILEPATH_MAXLEN);
-  strcpy(pfwImageCtx->default_fw_path, "/vendor/firmware/uwb/");
-  return status;
-}
-
-/*******************************************************************************
-**
-** Function    :   printManifestInfo
-**
-** Description :   This function is use to get UWB Manifest info
-**
-** Parameters  :   pfwImageCtx -> pointer to fw image context
-**
-** Returns     :   On failure - returns FW_DNLD_FAILURE
-                              - or FW_DNLD_FILE_NOT_FOUND if FW file not present
-                                in the MW.
-                   On success - returns FW_DNLD_SUCCESS.
-**
-**
-*******************************************************************************/
-void printManifest_info(UWBManifest_t *fwLibManifest) {
-
-  if(fwLibManifest == NULL) {
-    return;
-  }
-  NXPLOG_FWDNLD_D("================= FW Lib Manifest ====================\n");
-  NXPLOG_FWDNLD_D("UWB manifest version = %x\n",fwLibManifest->layout_version);
-  NXPLOG_FWDNLD_D("UWB manifest creation year = %d\n",fwLibManifest->creation_date_yy);
-  NXPLOG_FWDNLD_D("UWB manifest creation month = %d\n",fwLibManifest->creation_date_month);
-  NXPLOG_FWDNLD_D("UWB manifest creation day = %d\n",fwLibManifest->creation_date_day);
-  NXPLOG_FWDNLD_D("UWB manifest creation hour = %d\n",fwLibManifest->creation_date_hour);
-  NXPLOG_FWDNLD_D("UWB manifest creation minutes = %d\n",fwLibManifest->creation_date_minutes);
-  NXPLOG_FWDNLD_D("UWB manifest creation seconds = %d\n",fwLibManifest->creation_date_seconds);
-  NXPLOG_FWDNLD_D("UWB manifest count  = %d\n",fwLibManifest->countMWCESFW);
-
-  return;
-
-}
-
-/*******************************************************************************
-**
-** Function    :   openFwSoFile
-**
-** Description :   This function loads the FW shared library context
-                   if the FW file exists otherwise returns failure.
-**
-** Parameters  :   pfwImageCtx -> pointer to fw image context
-**
-** Returns     :   On failure - returns FW_DNLD_FAILURE
-                              - or FW_DNLD_FILE_NOT_FOUND if FW file not present
-                                in the MW.
-                   On success - returns FW_DNLD_SUCCESS.
-**
-**
-*******************************************************************************/
-static phFWD_Status_t openFwSoFile(phUwbFWImageContext_t *pfwImageCtx) {
-  void *flibptr = NULL;
-  UWBManifest_t *currentFwLib = NULL;
-  pfwImageCtx->gFwLib = NULL;
-  phFWD_Status_t status = FW_DNLD_SUCCESS;
-
-  NXPLOG_FWDNLD_D("%s:%d enter", __func__,__LINE__);
-
-  pfwImageCtx->gFwLib = dlopen(pfwImageCtx->default_fw_path, RTLD_LAZY);
-  if (pfwImageCtx->gFwLib == NULL) {
-    // Apparently, the library could not be opened
-    NXPLOG_FWDNLD_E("%s: Error! opening FW file %s\n", __func__,
-                    pfwImageCtx->default_fw_path);
-    status = FW_DNLD_FILE_NOT_FOUND;
-    goto cleanup;
-  }
-  flibptr = dlsym(pfwImageCtx->gFwLib, "gUWBManifest");
-  if (!flibptr) {
-    NXPLOG_FWDNLD_E("%s: Could not get function pointer\n", __func__);
-    status = FW_DNLD_FAILURE;
-    goto cleanup;
-  }
-
-  currentFwLib = (UWBManifest_t *)flibptr;
-  if (currentFwLib == NULL) {
-    NXPLOG_FWDNLD_E("%s:%d UwbManifest is null exiting.....", __func__, __LINE__);
-    status = FW_DNLD_FAILURE;
-    goto cleanup;
-  }
-
-  printManifest_info(currentFwLib);
-
-  // read the FW bytes into buffer
-  if (pfwImageCtx->deviceInfo->rom_version == VER_A1V1) {
-    if(currentFwLib->mwCESFW[MWCESFW_A1V1_RECOVERY_FW_OFFSET] == NULL || currentFwLib->mwCESFW[MWCESFW_A1V1_FW_OFFSET] == NULL) {
-        NXPLOG_FWDNLD_E("%s:%d UwbManifest mwCESFW is null exiting.....", __func__, __LINE__);
-        status = FW_DNLD_FAILURE;
-        goto cleanup;
-    }
-    if(pfwImageCtx->deviceInfo->AT_page_status == STATUS_PAGE_ERROR) {
-      pfwImageCtx->fwRecovery = true;
-      pfwImageCtx->fwImgSize = currentFwLib->mwCESFW[MWCESFW_A1V1_RECOVERY_FW_OFFSET]->lenCESFW;
-      pfwImageCtx->fwImage = currentFwLib->mwCESFW[MWCESFW_A1V1_RECOVERY_FW_OFFSET]->pCESFW;
-    } else if((pfwImageCtx->deviceInfo->device_life_cycle == CUSTOMER_MODE) && glcRotation == true) {
-      if(currentFwLib->mwCESFW[MWCESFW_A1V1_LC_FW_OFFSET] == NULL ) {
-        NXPLOG_FWDNLD_E("%s:%d LC FW does not exist.....", __func__, __LINE__);
-        status = FW_DNLD_FAILURE;
-        goto cleanup;
-      } else {
-        pfwImageCtx->fwImgSize = currentFwLib->mwCESFW[MWCESFW_A1V1_LC_FW_OFFSET]->lenCESFW;
-        pfwImageCtx->fwImage = currentFwLib->mwCESFW[MWCESFW_A1V1_LC_FW_OFFSET]->pCESFW;
-      }
-    }else {
-      pfwImageCtx->fwImgSize = currentFwLib->mwCESFW[MWCESFW_A1V1_FW_OFFSET]->lenCESFW;
-      pfwImageCtx->fwImage = currentFwLib->mwCESFW[MWCESFW_A1V1_FW_OFFSET]->pCESFW;
-    }
-  }
-  else if (pfwImageCtx->deviceInfo->rom_version == VER_A1V2) {
-    if(currentFwLib->mwCESFW[MWCESFW_A1V2_RECOVERY_FW_OFFSET] == NULL || currentFwLib->mwCESFW[MWCESFW_A1V2_FW_OFFSET] == NULL) {
-        NXPLOG_FWDNLD_E("%s:%d UwbManifest mwCESFW is null exiting.....", __func__, __LINE__);
-        status = FW_DNLD_FAILURE;
-        goto cleanup;
-    }
-    if(pfwImageCtx->deviceInfo->AT_page_status == STATUS_PAGE_ERROR) {
-      pfwImageCtx->fwRecovery = true;
-      pfwImageCtx->fwImgSize = currentFwLib->mwCESFW[MWCESFW_A1V2_RECOVERY_FW_OFFSET]->lenCESFW;
-      pfwImageCtx->fwImage = currentFwLib->mwCESFW[MWCESFW_A1V2_RECOVERY_FW_OFFSET]->pCESFW;
-    } else if((pfwImageCtx->deviceInfo->device_life_cycle == CUSTOMER_MODE) && glcRotation == true) {
-      if(currentFwLib->mwCESFW[MWCESFW_A1V2_LC_FW_OFFSET] == NULL ) {
-        NXPLOG_FWDNLD_E("%s:%d LC FW does not exist.....", __func__, __LINE__);
-        status = FW_DNLD_FAILURE;
-        goto cleanup;
-      } else {
-        pfwImageCtx->fwImgSize = currentFwLib->mwCESFW[MWCESFW_A1V2_LC_FW_OFFSET]->lenCESFW;
-        pfwImageCtx->fwImage = currentFwLib->mwCESFW[MWCESFW_A1V2_LC_FW_OFFSET]->pCESFW;
-      }
-    } else {
-      pfwImageCtx->fwImgSize = currentFwLib->mwCESFW[MWCESFW_A1V2_FW_OFFSET]->lenCESFW;
-      pfwImageCtx->fwImage = currentFwLib->mwCESFW[MWCESFW_A1V2_FW_OFFSET]->pCESFW;
-    }
-  }
-  if ((!(pfwImageCtx->fwImgSize)) || (NULL == pfwImageCtx->fwImage)) {
-    NXPLOG_FWDNLD_E("%s: Error! File %s is empty\n", __func__, pfwImageCtx->default_fw_path);
-    status = FW_DNLD_FAILURE;
-    goto cleanup;
-  }
-
-  NXPLOG_FWDNLD_E("exiting %s fwImgSize %d" , __func__, pfwImageCtx->fwImgSize);
-
-  return status;
-
-cleanup:
-  if (pfwImageCtx->gFwLib != NULL) {
-        dlclose(pfwImageCtx->gFwLib);
-        pfwImageCtx->gFwLib = NULL;
-  }
-  return status;
-
-}
-
-/*******************************************************************************
-**
-** Function    :   openFwBinFile
-**
-** Description :   This function copies the entire Bin FW file content into a buffer
-                   if the FW file exists otherwise returns failure.
-**
-** Parameters  :   pfwImageCtx -> pointer to fw image context
-**
-** Returns     :   On failure - returns FW_DNLD_FAILURE
-                              - or FW_DNLD_FILE_NOT_FOUND if FW file not present
-                                in the MW.
-                   On success - returns FW_DNLD_SUCCESS.
-**
-**
-*******************************************************************************/
-static phFWD_Status_t openFwBinFile(phUwbFWImageContext_t *pfwImageCtx) {
-  phFWD_Status_t status = FW_DNLD_SUCCESS;
-  long int file_size = 0;
-  size_t ret_size = 0;
-  FILE *fptr = NULL;
-
-  NXPLOG_FWDNLD_D("%s:%d enter", __func__,__LINE__);
-
-  // open FW binary file
-  if ((fptr = fopen(pfwImageCtx->default_fw_path, "rb")) == NULL) {
-    NXPLOG_FWDNLD_E("%s: Error! opening FW file %s\n", __func__,
-                    pfwImageCtx->default_fw_path);
-    status = FW_DNLD_FILE_NOT_FOUND;
-    goto exit;
-  }
-
-  // find the FW binary file size
-  fseek(fptr, 0L, SEEK_END);
-  file_size = ftell(fptr);
-  if (!file_size || (-1L == file_size)) {
-    NXPLOG_FWDNLD_E("%s: Error! File %s is empty\n", __func__, pfwImageCtx->default_fw_path);
-    status = FW_DNLD_FAILURE;
-    goto exit;
-  }
-  else {
-    pfwImageCtx->fwImgSize = file_size;
-  }
-
-  // read the FW bytes into buffer
-  pfwImageCtx->fwImage = (uint8_t *)malloc(sizeof(uint8_t) * pfwImageCtx->fwImgSize);
-  if (NULL == pfwImageCtx->fwImage)
-  {
-    status = FW_DNLD_FAILURE;
-    NXPLOG_FWDNLD_E("%s: Error in allocating memory\n", __func__);
-    goto exit;
-  }
-  rewind(fptr);
-  ret_size = fread(pfwImageCtx->fwImage, sizeof(uint8_t), pfwImageCtx->fwImgSize, fptr);
-  if (ret_size != pfwImageCtx->fwImgSize) {
-    if (feof(fptr))
-    {
-      NXPLOG_FWDNLD_E("%s: Error reading file %s, unexpected end of file\n",
-                      __func__, pfwImageCtx->default_fw_path);
-    }
-    else if (ferror(fptr))
-    {
-      NXPLOG_FWDNLD_E("%s: Error reading file %s\n", __func__, pfwImageCtx->default_fw_path);
-    }
-    status = FW_DNLD_FAILURE;
-    goto exit;
-  }
-
-exit:
-  if (NULL != fptr)
-  {
-    fclose(fptr);
-  }
-
-  return status;
-}
-
-/*******************************************************************************
-**
-** Function    :   check_fw_update_required
-**
-** Description :   This function checks whether FW update is required or not
-                   based on FW version from MW binary and FW version present in
-                   the HeliosX chip.
-**
-** Parameters  :   getInfoRsp  - Struct which has the GetInfo response details.
-**
-** Returns     :   FW_DNLD_FAILURE - If any un expected failure
-                   FW_DNLD_NOT_REQUIRED - FW update not required
-                   FW_DNLD_REQUIRED - FW update required
-                   FW_DNLD_FILE_NOT_FOUND - if the FW bin file is unable to
-                                                open or not present
-**
-**
-*******************************************************************************/
-phFWD_Status_t check_fw_update_required(phHDLLGetInfo_t *getInfoRsp) {
-  uint32_t next_frame_first_byte_index = 0;
-  uint32_t index = 0;
-  uint8_t mw_fw_major_ver = 0;
-  uint8_t mw_fw_minor_ver = 0;
-  uint32_t frame_payload_length = 0;
-  uint32_t frame_length = 0;
-  unsigned long num = 0;
-  phFWD_Status_t status = FW_DNLD_FAILURE;
-
-  fwImageCtx.deviceInfo = getInfoRsp;
-  fwImageCtx.fw_dnld_config = BIN_FILE_BASED_FW_DOWNLOAD;
-  fwImageCtx.fw_flash_config = FLASH_UPPER_VER_UPDATE;
-  fwImageCtx.fwRecovery = false;
-  strcpy(fwImageCtx.default_fw_path, default_fw_path);
-
-  status = getFwImageCtx(&fwImageCtx);
-  if (status != FW_DNLD_SUCCESS) {
-    return status;
-  }
-
-  if (NxpConfig_GetNum(NAME_NXP_UWB_FLASH_CONFIG, &num, sizeof(num))) {
-    fwImageCtx.fw_flash_config = (uint8_t)num;
-    NXPLOG_FWDNLD_D("NAME_NXP_UWB_FLASH_CONFIG: 0x%02x\n", fwImageCtx.fw_flash_config);
-    if (!(fwImageCtx.fw_flash_config == FLASH_UPPER_VER_UPDATE ||
-          fwImageCtx.fw_flash_config == FLASH_DIFFERENT_VER_UPDATE ||
-          fwImageCtx.fw_flash_config == FLASH_FORCE_UPDATE))
-    {
-      fwImageCtx.fw_flash_config = FLASH_UPPER_VER_UPDATE;
-    }
-  }
-  else {
-    NXPLOG_FWDNLD_D("NAME_NXP_UWB_FLASH_CONFIG: failed 0x%02x\n",
-                    fwImageCtx.fw_flash_config);
-  }
-
-  frame_payload_length = (fwImageCtx.fwImage[next_frame_first_byte_index] << 8) +
-                         (fwImageCtx.fwImage[next_frame_first_byte_index + 1]);
-  frame_length = frame_payload_length + HDLL_HEADER_LEN + HDLL_FOOTER_LEN;
-
-  // get the index of first_write_cmd_payload
-  next_frame_first_byte_index = next_frame_first_byte_index + frame_length;
-  index = next_frame_first_byte_index;
-  mw_fw_major_ver = fwImageCtx.fwImage[index + MW_MAJOR_FW_VER_OFFSET];
-  mw_fw_minor_ver = fwImageCtx.fwImage[index + MW_MINOR_FW_VER_OFFSET];
-  NXPLOG_FWDNLD_D("mw_fw_ver: %02X.%02X chip_fw_ver: %02X.%02X\n",
-                  mw_fw_major_ver, mw_fw_minor_ver, getInfoRsp->fw_major_ver,
-                  getInfoRsp->fw_minor_ver);
-
-  if(getInfoRsp->session_control == SESSION_CONTROL_OPEN){
-    NXPLOG_FWDNLD_D("FW Update required as session control is open \n");
-    status = FW_DNLD_REQUIRED;
-  } else {
-    switch (fwImageCtx.fw_flash_config) {
-    case FLASH_UPPER_VER_UPDATE: {
-      if (mw_fw_major_ver > getInfoRsp->fw_major_ver) {
-        NXPLOG_FWDNLD_D("FLASH_UPPER_VER_UPDATE:FW Update required\n");
-        status = FW_DNLD_REQUIRED;
-      } else if (mw_fw_major_ver == getInfoRsp->fw_major_ver) {
-        if (mw_fw_minor_ver > getInfoRsp->fw_minor_ver) {
-          NXPLOG_FWDNLD_D("FLASH_UPPER_VER_UPDATE:FW Update required\n");
-          status = FW_DNLD_REQUIRED;
-        } else {
-          NXPLOG_FWDNLD_E(
-              "FLASH_UPPER_VER_UPDATE:FW lower Minor version is not supported\n");
-          status = FW_DNLD_NOT_REQUIRED;
-        }
-      } else {
-        NXPLOG_FWDNLD_E(
-            "FLASH_UPPER_VER_UPDATE:FW lower Major version is not supported\n");
-        status = FW_DNLD_NOT_REQUIRED;
-      }
-    } break;
-    case FLASH_FORCE_UPDATE: {
-      if (mw_fw_major_ver < getInfoRsp->fw_major_ver) {
-        NXPLOG_FWDNLD_E(
-            "FLASH_FORCE_UPDATE:FW lower Major version is not supported\n");
-        status = FW_DNLD_NOT_REQUIRED;
-      } else {
-        NXPLOG_FWDNLD_D("FLASH_FORCE_UPDATE:FW Update required\n");
-        status = FW_DNLD_REQUIRED;
-      }
-    } break;
-    case FLASH_DIFFERENT_VER_UPDATE: {
-      if (mw_fw_major_ver > getInfoRsp->fw_major_ver) {
-        NXPLOG_FWDNLD_D("FLASH_DIFFERENT_VER_UPDATE:FW Update required\n");
-        status = FW_DNLD_REQUIRED;
-      } else if(mw_fw_major_ver == getInfoRsp->fw_major_ver) {
-        if(mw_fw_minor_ver == getInfoRsp->fw_minor_ver) {
-          NXPLOG_FWDNLD_E(
-            "FLASH_DIFFERENT_VER_UPDATE:Same Minor FW version update is not supported\n");
-            status = FW_DNLD_NOT_REQUIRED;
-        } else {
-          NXPLOG_FWDNLD_E(
-            "FLASH_DIFFERENT_VER_UPDATE:FW Update required\n");
-            status = FW_DNLD_REQUIRED;
-        }
-      } else {
-        NXPLOG_FWDNLD_D("FLASH_DIFFERENT_VER_UPDATE:lower Major FW version update is not supported\n");
-        status = FW_DNLD_NOT_REQUIRED;;
-      }
-    } break;
-    }
-  }
-  return status;
-}
-
-/*******************************************************************************
-**
-** Function    :   handleGetInfoRsp
-**
-** Description :   This function handles the GetInfo response that is received
-                   from the HeliosX chip.
-**
-** Parameters  :   hdll_payload  - HDLL response buffer
-**
-** Returns     :   FW_DNLD_FAILURE - If any un expected failure
-                   FW_DNLD_NOT_REQUIRED - FW update not required
-                   FW_DNLD_REQUIRED - FW update required
-                   FW_DNLD_FILE_NOT_FOUND - if the FW bin file is unable to
-                                                open or not present
-**
-**
-*******************************************************************************/
-phFWD_Status_t handleGetInfoRsp(uint8_t *hdll_payload) {
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-  phHDLLGetInfo_t *getInfoRsp = NULL;
-
-  getInfoRsp = process_getInfo_rsp(hdll_payload);
-  if (NULL == getInfoRsp) {
-    return ret;
-  }
-  print_getInfoRsp(getInfoRsp);
-  ret = check_fw_update_required(getInfoRsp);
-
-  if (NULL != getInfoRsp) {
-    free(getInfoRsp);
-  }
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   printHDLLRspStatus
-**
-** Description :   This function prints the HDLL response status string based on
-                   the given status code
-
-** Parameters  :   status  - status code
-**
-** Returns     :   None
-**
-**
-*******************************************************************************/
-
-void printHDLLRspStatus(uint8_t status) {
-  switch (status) {
-  case GENERIC_SUCCESS:
-    NXPLOG_FWDNLD_D("Received status: GENERIC_SUCCESS");
-    break;
-  case ACKNOWLEDGE:
-    NXPLOG_FWDNLD_D("Received status: ACKNOWLEDGE");
-    break;
-  case READY:
-    NXPLOG_FWDNLD_D("Received status: READY");
-    break;
-  case GENERIC_ERROR:
-    NXPLOG_FWDNLD_D("Received status: GENERIC_ERROR");
-    break;
-  case MEMORY_ERROR:
-    NXPLOG_FWDNLD_D("Received status: MEMORY_ERROR");
-    break;
-  case TIMEOUT_ERROR:
-    NXPLOG_FWDNLD_D("Received status: TIMEOUT_ERROR");
-    break;
-  case CRC_ERROR:
-    NXPLOG_FWDNLD_D("Received status: CRC_ERROR");
-    break;
-  case INVALID_ERROR:
-    NXPLOG_FWDNLD_D("Received status: INVALID_ERROR");
-    break;
-  case INVALID_LENGTH_ERROR:
-    NXPLOG_FWDNLD_D("Received status: INVALID_LENGTH_ERROR");
-    break;
-  case INVALID_ADDRESS_ERROR:
-    NXPLOG_FWDNLD_D("Received status: INVALID_ADDRESS_ERROR");
-    break;
-  case ECC_SIGNATURE_ERROR:
-    NXPLOG_FWDNLD_D("Received status: ECC_SIGNATURE_ERROR");
-    break;
-  case SHA384_HASH_ERROR:
-    NXPLOG_FWDNLD_D("Received status: SHA384_HASH_ERROR");
-    break;
-  case LIFECYCLE_VALIDITY_ERROR:
-    NXPLOG_FWDNLD_D("Received status: LIFECYCLE_VALIDITY_ERROR");
-    break;
-  case CHIP_ID_ERROR:
-    NXPLOG_FWDNLD_D("Received status: CHIP_ID_ERROR");
-    break;
-  case CHIP_VERSION_ERROR:
-    NXPLOG_FWDNLD_D("Received status: CHIP_VERSION_ERROR");
-    break;
-  case CERTIFICATE_VERSION_ERROR:
-    NXPLOG_FWDNLD_D("Received status: CERTIFICATE_VERSION_ERROR");
-    break;
-  case FIRMWARE_VERSION_ERROR:
-    NXPLOG_FWDNLD_D("Received status: FIRMWARE_VERSION_ERROR");
-    break;
-  case SRAM_DOWNLOAD_ALLOW_ERROR:
-    NXPLOG_FWDNLD_D("Received status: SRAM_DOWNLOAD_ALLOW_ERROR");
-    break;
-  case KEY_DERIVATION_ERROR:
-    NXPLOG_FWDNLD_D("Received status: KEY_DERIVATION_ERROR");
-    break;
-  case ENCRYPTED_PAYLOAD_DECRYPTION_ERROR:
-    NXPLOG_FWDNLD_D("Received status: ENCRYPTED_PAYLOAD_DECRYPTION_ERROR");
-    break;
-  case INVALID_ENCRYPTED_PAYLOAD_ERROR:
-    NXPLOG_FWDNLD_D("Received status: INVALID_ENCRYPTED_PAYLOAD_ERROR");
-    break;
-  case PROTECTED_CACHE_LOAD_ERROR:
-    NXPLOG_FWDNLD_D("Received status: PROTECTED_CACHE_LOAD_ERROR");
-    break;
-  case PROTECTED_CACHE_DEPLOY_ERROR:
-    NXPLOG_FWDNLD_D("Received status: PROTECTED_CACHE_DEPLOY_ERROR");
-    break;
-  case LIFECYCLE_UPDATE_ERROR:
-    NXPLOG_FWDNLD_D("Received status: LIFECYCLE_UPDATE_ERROR");
-    break;
-  case FLASH_BLANK_PAGE_ERROR:
-    NXPLOG_FWDNLD_D("Received status: FLASH_BLANK_PAGE_ERROR");
-    break;
-  case FLASH_CHECK_MARGIN_ERROR:
-    NXPLOG_FWDNLD_D("Received status: FLASH_CHECK_MARGIN_ERROR");
-    break;
-  default:
-    break;
-  };
-}
-
-/*******************************************************************************
-**
-** Function    :   process_hdll_response
-**
-** Description :   This function processes the HDLL response
-
-** Parameters  :   hdllCmdRsp  - HDLL command response structure which has the
-                                 received response info as well as the expected
-                                 response info.
-**
-** Returns     :   FW_DNLD_FAILURE - If any undesired response received
-                   FW_DNLD_SUCCESS - On proper response
-**
-**
-*******************************************************************************/
-
-/*
- * HDLL Response:
- * <-------HDLL Header--->|<------------------HDLL payload--------------------->
- * <-------HDLL (2bytes)->|<-----HCP (2bytes)------->|<-Application--> <--CRC-->
- * <31 30> <29>  <28 -16> |<15 -14><13 - 8> <7 - 0>  |<status><Payload><2 bytes>
- * <--R--><Chunk><length> |< Type ><Group><Operation>|<1 byte>
- *
- */
-phFWD_Status_t process_hdll_response(phHDLLCmdRsp_t *hdllCmdRsp) {
-  uint8_t hdll_msg_type = 0;
-  uint8_t hdll_rsp_status = 0;
-  uint16_t hdll_packet_len = 0;
-  uint8_t hdll_group = 0;
-  uint8_t hdll_operation = 0;
-  uint8_t *hdll_payload = NULL;
-  uint16_t hdll_payload_len = 0;
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-
-  if (hdllCmdRsp == NULL || hdllCmdRsp->rsp_buf == NULL) {
-    NXPLOG_FWDNLD_E("%s HDLL response buffer is NULL\n", __func__);
-    return ret;
-  }
-  if (hdllCmdRsp->rsp_buf_len < HDLL_MIN_RSP_LEN) {
-    NXPLOG_FWDNLD_E(
-        "%s Error! HDLL response buffer length is %d, expected min %d bytes\n",
-        __func__, hdllCmdRsp->rsp_buf_len, HDLL_MIN_RSP_LEN);
-    return ret;
-  }
-
-  // parse hdll frame
-  hdll_packet_len = (uint16_t)(hdllCmdRsp->rsp_buf[0] << 8) |
-                    (hdllCmdRsp->rsp_buf[HDLL_LEN_OFFSET]);
-  hdll_packet_len &= HDLL_PKT_LEN_BITMASK;
-  NXPLOG_FWDNLD_D("Received RSP packet len      :0x%04X\n", hdll_packet_len);
-  if (hdll_packet_len == 0) {
-    NXPLOG_FWDNLD_D("Error in hdll response.. hdll_packet_len = 0\n");
-    return ret;
-  }
-
-  hdll_msg_type = hdllCmdRsp->rsp_buf[HDLL_TYPE_OFFSET] >> HCP_GROUP_LEN;
-  hdll_group =
-      (hdllCmdRsp->rsp_buf[HDLL_GROUP_OFFSET] & HDLL_RSP_GROUP_BIT_MASK);
-  hdll_operation = hdllCmdRsp->rsp_buf[HDLL_OPERATION_OFFSET];
-  hdll_rsp_status = hdllCmdRsp->rsp_buf[HDLL_RSP_STATUS_OFFSET];
-
-  NXPLOG_FWDNLD_D("Received RSP msg type        :0x%02X\n", hdll_msg_type);
-  NXPLOG_FWDNLD_D("Received RSP group operation :0x%02X%02X\n", hdll_group,
-                  hdll_operation);
-  NXPLOG_FWDNLD_D("Received RSP status code     :0x%02X\n", hdll_rsp_status);
-  printHDLLRspStatus(hdll_rsp_status);
-
-  hdll_payload_len = hdllCmdRsp->rsp_buf_len - (HDLL_RSP_PAYLOAD_OFFSET + HDLL_CRC_LEN);
-  NXPLOG_FWDNLD_D("hdll payload len = 0x%02x" , hdll_payload_len);
-
-  if (hdll_payload_len > 0) {
-    hdll_payload = (uint8_t *)malloc(
-        sizeof(uint8_t) *
-        (hdll_payload_len));
-    if (NULL == hdll_payload) {
-      return ret;
-    }
-    memcpy(hdll_payload, &hdllCmdRsp->rsp_buf[HDLL_RSP_PAYLOAD_OFFSET],
-           hdll_payload_len);
-  }
-
-  // validate the response
-  if (hdllCmdRsp->status != hdll_rsp_status) {
-    NXPLOG_FWDNLD_D("Error! expected response status code is 0x%02X  but "
-                    "received 0x%02X\n",
-                    hdllCmdRsp->status, hdll_rsp_status);
-    ret = FW_DNLD_FAILURE;
-  } else if (hdllCmdRsp->type != hdll_msg_type) {
-    NXPLOG_FWDNLD_D(
-        "Error! expected HDLL type code is 0x%02X but received 0x%02X\n",
-        hdllCmdRsp->type, hdll_msg_type);
-    ret = FW_DNLD_FAILURE;
-  } else if ((hdllCmdRsp->group != hdll_group) ||
-           (hdllCmdRsp->operation != hdll_operation)) {
-    NXPLOG_FWDNLD_D("Error! expected response operation code is 0x%02X%02X but "
-                    "received 0x%02X%02X \n",
-                    hdllCmdRsp->group, hdllCmdRsp->operation, hdll_group,
-                    hdll_operation);
-    ret = FW_DNLD_FAILURE;
-  } else
-  {
-    ret = FW_DNLD_SUCCESS;
-  }
-
-  if (ret == FW_DNLD_FAILURE){
-    goto exit;
-  }
-
-  // Handle the response according to the operation
-  switch (hdll_group) {
-  case HCP_OPERATION_GROUP_PROTOCOL: {
-    switch (hdll_operation) {
-    case PROTOCOL_GROUP_OP_CODE_HDLL: {
-      NXPLOG_FWDNLD_D("Received PROTOCOL_GROUP_HDLL_OP_CODE\n");
-    } break;
-    case PROTOCOL_GROUP_OP_CODE_HCP: {
-      NXPLOG_FWDNLD_D("Received PROTOCOL_GROUP_HCP_OP_CODE\n");
-    } break;
-    case PROTOCOL_GROUP_OP_CODE_EDL: {
-      NXPLOG_FWDNLD_D("Received PROTOCOL_GROUP_EDL_OP_CODE\n");
-    } break;
-    }
-  } break;
-
-  case HCP_OPERATION_GROUP_GENERIC: {
-    switch (hdll_operation) {
-    case GENERIC_GROUP_OP_CODE_RESET: {
-      NXPLOG_FWDNLD_D("Received OP_GENERIC_RESET\n");
-      // Generic reset cmd will have the rsp only in case of error.
-      // How to handle the situation.
-    } break;
-    case GENERIC_GROUP_OP_CODE_GETINFO: {
-      NXPLOG_FWDNLD_D("Received OP_GENERIC_GET_INFO\n");
-      if (hdll_payload != NULL) {
-        ret = handleGetInfoRsp(hdll_payload);
-      }
-    } break;
-    }
-  } break;
-
-  case HCP_OPERATION_GROUP_EDL: {
-    switch (hdll_operation) {
-    case EDL_DOWNLOAD_CERTIFICATE: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_DOWNLOAD_CERTIFICATE\n");
-    } break;
-    case EDL_DOWNLOAD_FLASH_WRITE_FIRST: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_DOWNLOAD_FLASH_WRITE_FIRST\n");
-    }
-    break;
-    case EDL_DOWNLOAD_FLASH_WRITE: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_DOWNLOAD_FLASH_WRITE\n");
-    } break;
-    case EDL_DOWNLOAD_FLASH_WRITE_LAST: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_DOWNLOAD_FLASH_WRITE_LAST\n");
-    } break;
-    case EDL_DOWNLOAD_SRAM_WRITE_FIRST: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_DOWNLOAD_SRAM_WRITE_FIRST\n");
-    } break;
-    case EDL_DOWNLOAD_SRAM_WRITE: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_DOWNLOAD_SRAM_WRITE\n");
-    } break;
-    case EDL_DOWNLOAD_SRAM_WRITE_LAST: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_DOWNLOAD_SRAM_WRITE_LAST\n");
-    } break;
-    case EDL_LIFECYCLE_CERTIFICATE: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_LIFECYCLE_CERTIFICATE\n");
-    } break;
-    case EDL_LIFECYCLE_WRITE_FIRST: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_LIFECYCLE_WRITE_FIRST\n");
-    } break;
-    case EDL_LIFECYCLE_WRITE_LAST: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_LIFECYCLE_WRITE_LAST\n");
-    } break;
-    case EDL_PATCH_SRAM_WRITE: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_PATCH_SRAM_WRITE\n");
-    } break;
-    case EDL_PATCH_SRAM_WRITE_LAST: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_PATCH_SRAM_WRITE_LAST\n");
-    } break;
-    case EDL_PATCH_FLASH_WRITE: {
-      NXPLOG_FWDNLD_D("Received OP_EDL_PATCH_FLASH_WRITE\n");
-    } break;
-    }
-  } break;
-  default:
-    break;
-  }
-
-exit:
-  if (hdll_payload != NULL) {
-    free(hdll_payload);
-  }
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   sendEdlDownloadCertificateCmd
-**
-** Description :   This function frames the EdlDownloadCertificateCmd which
-                   needs to be sent as part of FW download sequence.
-**
-** Parameters  :   payload  - HDLL command buffer
-                   len - command buffer length
-                   rsp_buf - response buffer that will be received from the
-                   HeliosX chip.
-**
-** Returns     :   FW_DNLD_FAILURE - If any undesired response received
-                   FW_DNLD_SUCCESS - On proper response
-**
-**
-*******************************************************************************/
-phFWD_Status_t sendEdlDownloadCertificateCmd(uint8_t *payload, uint16_t len,
-                                             uint8_t *rsp_buf) {
-
-  uint16_t rsp_buf_len = 0x0;
-  phFWD_Status_t ret = FW_DNLD_SUCCESS;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  ret = phGenericSendAndRecv(payload, len, rsp_buf, &rsp_buf_len);
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in sending/receiving OP_EDL_DOWNLOAD_CERTIFICATE "
-                    "cmd/response\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    return ret;
-  }
-
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_EDL;
-  hdllCmdRsp->operation = EDL_DOWNLOAD_CERTIFICATE;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = GENERIC_SUCCESS;
-  hdllCmdRsp->type = HCP_TYPE_RESPONSE;
-  ret = process_hdll_response(hdllCmdRsp);
-
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   sendEdlFlashWriteFirstCmd
-**
-** Description :   This function frames the EdlFlashWriteFirstCmd which
-                   needs to be sent as part of FW download sequence.
-**
-** Parameters  :   payload  - HDLL command buffer
-                   len - command buffer length
-                   rsp_buf - response buffer that will be received from the
-                   HeliosX chip.
-**
-** Returns     :   FW_DNLD_FAILURE - If any undesired response received
-                   FW_DNLD_SUCCESS - On proper response
-**
-**
-*******************************************************************************/
-phFWD_Status_t sendEdlFlashWriteFirstCmd(uint8_t *payload, uint16_t len,
-                                         uint8_t *rsp_buf) {
-  uint16_t rsp_buf_len = 0x0;
-  phFWD_Status_t ret = FW_DNLD_SUCCESS;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  ret = phGenericSendAndRecv(payload, len, rsp_buf, &rsp_buf_len);
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in sending/receiving "
-                    "OP_EDL_DOWNLOAD_FLASH_WRITE_FIRST cmd/response\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    return ret;
-  }
-
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_EDL;
-  hdllCmdRsp->operation = EDL_DOWNLOAD_FLASH_WRITE_FIRST;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = GENERIC_SUCCESS;
-  hdllCmdRsp->type = HCP_TYPE_RESPONSE;
-  ret = process_hdll_response(hdllCmdRsp);
-
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   sendEdlFlashWriteCmd
-**
-** Description :   This function frames the sendEdlFlashWriteCmd which
-                   will have the actual FW chunk.
-**
-** Parameters  :   payload  - HDLL command buffer
-                   len - command buffer length
-                   rsp_buf - response buffer that will be received from the
-                   HeliosX chip.
-**
-** Returns     :   FW_DNLD_FAILURE - If any undesired response received
-                   FW_DNLD_SUCCESS - On proper response
-**
-**
-*******************************************************************************/
-phFWD_Status_t sendEdlFlashWriteCmd(uint8_t *payload, uint16_t len,
-                                    uint8_t *rsp_buf) {
-  uint16_t rsp_buf_len = 0x0;
-  phFWD_Status_t ret = FW_DNLD_SUCCESS;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  ret = phGenericSendAndRecv(payload, len, rsp_buf, &rsp_buf_len);
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in sending/receiving OP_EDL_DOWNLOAD_FLASH_WRITE "
-                    "cmd/response\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    return ret;
-  }
-
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_EDL;
-  hdllCmdRsp->operation = EDL_DOWNLOAD_FLASH_WRITE;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = GENERIC_SUCCESS;
-  hdllCmdRsp->type = HCP_TYPE_RESPONSE;
-  ret = process_hdll_response(hdllCmdRsp);
-
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   sendEdlFlashWriteLastCmd
-**
-** Description :   This function frames the EdlFlashWriteLastCmd which
-                   needs to be sent as part of FW download sequence.
-**
-** Parameters  :   payload  - HDLL command buffer
-                   len - command buffer length
-                   rsp_buf - response buffer that will be received from the
-                   HeliosX chip.
-**
-** Returns     :   FW_DNLD_FAILURE - If any undesired response received
-                   FW_DNLD_SUCCESS - On proper response
-**
-**
-*******************************************************************************/
-phFWD_Status_t sendEdlFlashWriteLastCmd(uint8_t *payload, uint16_t len,
-                                        uint8_t *rsp_buf) {
-  uint16_t rsp_buf_len = 0x0;
-  phFWD_Status_t ret = FW_DNLD_SUCCESS;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  ret = phGenericSendAndRecv(payload, len, rsp_buf, &rsp_buf_len);
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in sending/receiving "
-                    "OP_EDL_DOWNLOAD_FLASH_WRITE_LAST cmd/response\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    return ret;
-  }
-
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_EDL;
-  hdllCmdRsp->operation = EDL_DOWNLOAD_FLASH_WRITE_LAST;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = GENERIC_SUCCESS;
-  hdllCmdRsp->type = HCP_TYPE_RESPONSE;
-  ret = process_hdll_response(hdllCmdRsp);
-
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   sendEdlLifecycleCertificateCmd
-**
-** Description :   This function frames the EdlLifecycleCertificateCmd which
-                   needs to be sent as part of Lifecycle update.
-**
-** Parameters  :   payload  - HDLL command buffer
-                   len - command buffer length
-                   rsp_buf - response buffer that will be received from the
-                   HeliosX chip.
-**
-** Returns     :   FW_DNLD_FAILURE - If any undesired response received
-                   FW_DNLD_SUCCESS - On proper response
-**
-**
-*******************************************************************************/
-phFWD_Status_t sendEdlLifecycleCertificateCmd(uint8_t *payload, uint16_t len,
-                                              uint8_t *rsp_buf) {
-  uint16_t rsp_buf_len = 0x0;
-  phFWD_Status_t ret = FW_DNLD_SUCCESS;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  ret = phGenericSendAndRecv(payload, len, rsp_buf, &rsp_buf_len);
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in sending/receiving "
-                    "EDL_LIFECYCLE_CERTIFICATE cmd/response\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    return ret;
-  }
-
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_EDL;
-  hdllCmdRsp->operation = EDL_LIFECYCLE_CERTIFICATE;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = GENERIC_SUCCESS;
-  hdllCmdRsp->type = HCP_TYPE_RESPONSE;
-  ret = process_hdll_response(hdllCmdRsp);
-
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   sendEdlLifecycleWriteFirstCmd
-**
-** Description :   This function frames the EdlLifecycleWriteFirstCmd which
-                   needs to be sent as part of Lifecycle update.
-**
-** Parameters  :   payload  - HDLL command buffer
-                   len - command buffer length
-                   rsp_buf - response buffer that will be received from the
-                   HeliosX chip.
-**
-** Returns     :   FW_DNLD_FAILURE - If any undesired response received
-                   FW_DNLD_SUCCESS - On proper response
-**
-**
-*******************************************************************************/
-phFWD_Status_t sendEdlLifecycleWriteFirstCmd(uint8_t *payload, uint16_t len,
-                                             uint8_t *rsp_buf) {
-  uint16_t rsp_buf_len = 0x0;
-  phFWD_Status_t ret = FW_DNLD_SUCCESS;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  ret = phGenericSendAndRecv(payload, len, rsp_buf, &rsp_buf_len);
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in sending/receiving "
-                    "EDL_LIFECYCLE_WRITE_FIRST cmd/response\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    return ret;
-  }
-
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_EDL;
-  hdllCmdRsp->operation = EDL_LIFECYCLE_WRITE_FIRST;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = GENERIC_SUCCESS;
-  hdllCmdRsp->type = HCP_TYPE_RESPONSE;
-  ret = process_hdll_response(hdllCmdRsp);
-
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   sendEdlLifecycleWriteLastCmd
-**
-** Description :   This function frames the EdlLifecycleWriteLastCmd which
-                   needs to be sent as part of Lifecycle update.
-**
-** Parameters  :   payload  - HDLL command buffer
-                   len - command buffer length
-                   rsp_buf - response buffer that will be received from the
-                   HeliosX chip.
-**
-** Returns     :   FW_DNLD_FAILURE - If any undesired response received
-                   FW_DNLD_SUCCESS - On proper response
-**
-**
-*******************************************************************************/
-phFWD_Status_t sendEdlLifecycleWriteLastCmd(uint8_t *payload, uint16_t len,
-                                            uint8_t *rsp_buf) {
-  uint16_t rsp_buf_len = 0x0;
-  phFWD_Status_t ret = FW_DNLD_SUCCESS;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  ret = phGenericSendAndRecv(payload, len, rsp_buf, &rsp_buf_len);
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in sending/receiving "
-                    "EDL_LIFECYCLE_WRITE_LAST cmd/response\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    return ret;
-  }
-
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_EDL;
-  hdllCmdRsp->operation = EDL_LIFECYCLE_WRITE_LAST;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = GENERIC_SUCCESS;
-  hdllCmdRsp->type = HCP_TYPE_RESPONSE;
-  ret = process_hdll_response(hdllCmdRsp);
-
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   sendEdlPatchFlashWriteCmd
-**
-** Description :   This function frames the sendEdlPatchlFlashWriteCmd which
-                   will send the EDL Patch Flash Write cmd
-**
-** Parameters  :   payload  - HDLL command buffer
-                   len - command buffer length
-                   rsp_buf - response buffer that will be received from the
-                   HeliosX chip.
-**
-** Returns     :   FW_DNLD_FAILURE - If any undesired response received
-                   FW_DNLD_SUCCESS - On proper response
-**
-**
-*******************************************************************************/
-phFWD_Status_t sendEdlPatchFlashWriteCmd(uint8_t *payload, uint16_t len,
-                                    uint8_t *rsp_buf) {
-  uint16_t rsp_buf_len = 0x0;
-  phFWD_Status_t ret = FW_DNLD_SUCCESS;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  ret = phGenericSendAndRecv(payload, len, rsp_buf, &rsp_buf_len);
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in sending/receiving OP_EDL_PATCH_FLASH_WRITE "
-                    "cmd/response\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    return ret;
-  }
-
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_EDL;
-  hdllCmdRsp->operation = EDL_PATCH_FLASH_WRITE;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = GENERIC_SUCCESS;
-  hdllCmdRsp->type = HCP_TYPE_RESPONSE;
-  ret = process_hdll_response(hdllCmdRsp);
-
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   phHal_Host_CalcCrc16
-**
-** Description :   This function calculates the HDLL command's CRC
-**
-** Parameters  :   p  - HDLL command buffer
-                   dwLength - command buffer length
-**
-** Returns     :   the calculated CRC value
-**
-**
-*******************************************************************************/
-static uint16_t phHal_Host_CalcCrc16(uint8_t *p, uint32_t dwLength) {
-  uint32_t i;
-  uint16_t crc_new;
-  uint16_t crc = 0xffffU;
-
-  for (i = 0; i < dwLength; i++) {
-    crc_new = (uint8_t)(crc >> 8) | (crc << 8);
-    crc_new ^= p[i];
-    crc_new ^= (uint8_t)(crc_new & 0xff) >> 4;
-    crc_new ^= crc_new << 12;
-    crc_new ^= (crc_new & 0xff) << 5;
-    crc = crc_new;
-  }
-  return crc;
-}
-
-/*******************************************************************************
-**
-** Function    :   phBuildHdllCmd
-**
-** Description :   This function frames the final HDLL command (HDLL header +
-                   HDLL payload + CRC) by framing HDLL payload and HDLL frame
-                   using 2 different APIs.
-**
-** Parameters  :   hdllCmd - HDLL command structure which has the information
-                             to build the corresponding HDLL command.
-**
-** Returns     :   NULL - on failure
-                   HDLL command buffer - On success
-**
-**
-*******************************************************************************/
-
-/*
- * HDLL Command:
- * <--------HDLL Header---->|<------------------HDLL payload------------------->
- * <--------HDLL (2bytes)-->|<-----HCP (2bytes)------->|<-Application-><--CRC-->
- * <31 30> <29>    <28 -16> |<15 -14><13 - 8><7 - 0>   |<---Payload---><2 bytes>
- * <--R--> <Chunk> <length> |< Type ><Group><Operation>|
- *
- */
-
-uint8_t *phBuildHdllCmd(phHDLLCmd_t *hdllCmd) {
-  uint8_t type = 0;
-  uint8_t *hdll_frame = NULL;
-  uint16_t hdll_frame_size = 0;
-  uint16_t hdll_crc = 0x0;
-  uint16_t hdll_header = 0x0;
-  NXPLOG_FWDNLD_D("phBuildHdllCmd:\n");
-
-  if (NULL == hdllCmd) {
-    return NULL;
-  }
-  // header len =2 bytes + hdll_payload_len + crc =2 bytes
-  hdll_frame_size = HDLL_HEADER_LEN + HCP_MSG_HEADER_LEN +
-                    hdllCmd->payload_len + HDLL_CRC_LEN;
-  hdll_frame = (uint8_t *)malloc(sizeof(uint8_t) * hdll_frame_size);
-  if (NULL == hdll_frame) {
-    return hdll_frame;
-  }
-
-  // build hdll frame
-  hdll_header |= hdllCmd->payload_len + HCP_MSG_HEADER_LEN;
-  hdll_header &= HDLL_PKT_LEN_BITMASK;
-  hdll_header = hdllCmd->chunk_size ? (HDLL_PKT_CHUNK_BITMASK | hdll_header)
-                                    : hdll_header;
-
-  // hdll_header uint16 to uint8
-  hdll_frame[HDLL_CHUNK_OFFSET] = (hdll_header >> 8);
-  hdll_frame[HDLL_LEN_OFFSET] = (hdll_header & 0xFF);
-
-  type = HCP_TYPE_COMMAND;
-  type <<= HCP_GROUP_LEN;
-  hdll_frame[HDLL_TYPE_OFFSET] = type | hdllCmd->group;
-  hdll_frame[HDLL_OPERATION_OFFSET] = hdllCmd->operation;
-
-  if (hdllCmd->payload_len > 0 && hdllCmd->payload != NULL) {
-    // copy hdll payload into hdll frame
-    memcpy(&hdll_frame[HDLL_PAYLOAD_OFFSET], hdllCmd->payload,
-           hdllCmd->payload_len);
-  }
-
-  hdll_crc = phHal_Host_CalcCrc16(hdll_frame, hdll_frame_size - 2);
-  hdll_frame[hdll_frame_size - 2] = (hdll_crc >> 8);
-  hdll_frame[hdll_frame_size - 1] = (hdll_crc & 0xFF);
-
-  hdllCmd->frame_size = hdll_frame_size;
-  return hdll_frame;
-}
-
-/*******************************************************************************
-**
-** Function    :   sendEdlResetCmd
-**
-** Description :   This function frames the EdlResetCmd and sends to the HeliosX
-                   chip
-**
-** Parameters  :   None
-**
-** Returns     :   FW_DNLD_FAILURE - If any failure occurs while framing or
-                                    sending the command or while receiving the
-                                    response
-                   FW_DNLD_SUCCESS - On success
-**
-**
-*******************************************************************************/
-phFWD_Status_t sendEdlResetCmd() {
-  uint8_t rsp_buf[HDLL_READ_BUFF_SIZE] = {0};
-  uint8_t *hdll_frame = NULL;
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-  uint16_t rsp_buf_len = 0x0;
-  phHDLLCmd_t *hdllCmd = NULL;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  hdllCmd = (phHDLLCmd_t *)malloc(sizeof(phHDLLCmd_t));
-  if (NULL == hdllCmd) {
-    goto exit;
-  }
-
-  hdllCmd->group = HCP_OPERATION_GROUP_GENERIC;
-  hdllCmd->operation = GENERIC_GROUP_OP_CODE_RESET;
-  hdllCmd->chunk_size = 0;
-  hdllCmd->frame_size = 0;
-  hdllCmd->payload = NULL;
-  hdllCmd->payload_len = 0;
-
-  hdll_frame = phBuildHdllCmd(hdllCmd);
-  if (NULL == hdll_frame) {
-    goto exit;
-  }
-  NXPLOG_FWDNLD_D("Sending operation: OP_GENERIC_RESET\n");
-  ret = phGenericSendAndRecv(hdll_frame, hdllCmd->frame_size, rsp_buf,
-                             &rsp_buf_len);
-  if (ret == FW_DNLD_FAILURE) {
-    // treat is as success as generic reset will have response only if there
-    // is an error.
-    ret = FW_DNLD_SUCCESS;
-  }
-  if (rsp_buf_len > 0) {
-    hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-    if (NULL == hdllCmdRsp) {
-      ret = FW_DNLD_FAILURE;
-      goto exit;
-    }
-    hdllCmdRsp->group = HCP_OPERATION_GROUP_GENERIC;
-    hdllCmdRsp->operation = GENERIC_GROUP_OP_CODE_RESET;
-    hdllCmdRsp->rsp_buf = rsp_buf;
-    hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-    hdllCmdRsp->status = GENERIC_SUCCESS;
-    hdllCmdRsp->type = HCP_TYPE_RESPONSE;
-    ret = process_hdll_response(hdllCmdRsp);
-  }
-exit:
-  if (hdll_frame != NULL) {
-    free(hdll_frame);
-  }
-  if (NULL != hdllCmd) {
-    free(hdllCmd);
-  }
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   phGetEdlReadyNtf
-**
-** Description :   This function frames the GetEdlReadyNtf command and sends to
-                   the HeliosX chip
-**
-** Parameters  :   None
-**
-** Returns     :   FW_DNLD_FAILURE - If any failure occurs while framing or
-                                    sending the command or while receiving the
-                                    response
-                   FW_DNLD_SUCCESS - On success
-**
-**
-*******************************************************************************/
-phFWD_Status_t phGetEdlReadyNtf() {
-  uint8_t rsp_buf[HDLL_READ_BUFF_SIZE] = {0};
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-  uint16_t rsp_buf_len = 0x0;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  NXPLOG_FWDNLD_D("Wait for EDL_READY notification\n");
-  ret =
-      phHdll_GetApdu((uint8_t *)&rsp_buf[0], HDLL_READ_BUFF_SIZE, &rsp_buf_len);
-
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in sending/receiving GET_EDL_READY cmd/response\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    return ret;
-  }
-
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_PROTOCOL;
-  hdllCmdRsp->operation = PROTOCOL_GROUP_OP_CODE_EDL;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = READY;
-  hdllCmdRsp->type = HCP_TYPE_NOTIFICATION;
-  ret = process_hdll_response(hdllCmdRsp);
-
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   phGenericGetInfo
-**
-** Description :   This function frames the GenericGetInfo command and sends to
-                   the HeliosX chip
-**
-** Parameters  :   None
-**
-** Returns     :   FW_DNLD_FAILURE - If any failure occurs while framing or
-                                    sending the command or while receiving the
-                                    response
-                   FW_DNLD_SUCCESS - On success
-**
-**
-*******************************************************************************/
-phFWD_Status_t phGenericGetInfo() {
-  uint8_t rsp_buf[HDLL_READ_BUFF_SIZE] = {0};
-  uint8_t *hdll_frame = NULL;
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-  uint16_t rsp_buf_len = 0x0;
-  phHDLLCmd_t *hdllCmd = NULL;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  hdllCmd = (phHDLLCmd_t *)malloc(sizeof(phHDLLCmd_t));
-  if (NULL == hdllCmd) {
-    ret = FW_DNLD_FAILURE;
-    goto exit;
-  }
-  hdllCmd->group = HCP_OPERATION_GROUP_GENERIC;
-  hdllCmd->operation = GENERIC_GROUP_OP_CODE_GETINFO;
-  hdllCmd->chunk_size = 0;
-  hdllCmd->frame_size = 0;
-  hdllCmd->payload = NULL;
-  hdllCmd->payload_len = 0;
-
-  hdll_frame = phBuildHdllCmd(hdllCmd);
-  if (NULL == hdll_frame) {
-    goto exit;
-  }
-  NXPLOG_FWDNLD_D("Sending operation: OP_GENERIC_GET_INFO\n");
-  ret = phGenericSendAndRecv(hdll_frame, hdllCmd->frame_size, rsp_buf,
-                             &rsp_buf_len);
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in sending/receiving hdll cmd/response\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    ret = FW_DNLD_FAILURE;
-    goto exit;
-  }
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_GENERIC;
-  hdllCmdRsp->operation = GENERIC_GROUP_OP_CODE_GETINFO;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = GENERIC_SUCCESS;
-  hdllCmdRsp->type = HCP_TYPE_RESPONSE;
-  ret = process_hdll_response(hdllCmdRsp);
-exit:
-  if (NULL != hdll_frame) {
-    free(hdll_frame);
-  }
-  if (NULL != hdllCmd) {
-    free(hdllCmd);
-  }
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   phHdll_GetHdllReadyNtf
-**
-** Description :   This function frames the GetHdllReadyNtf command and sends to
-                   the HeliosX chip
-**
-** Parameters  :   None
-**
-** Returns     :   FW_DNLD_FAILURE - If any failure occurs while framing or
-                                    sending the command or while receiving the
-                                    response
-                   FW_DNLD_SUCCESS - On success
-**
-**
-*******************************************************************************/
-phFWD_Status_t phHdll_GetHdllReadyNtf() {
-  uint8_t rsp_buf[HDLL_READ_BUFF_SIZE] = {0};
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-  uint16_t rsp_buf_len = 0x0;
-  phHDLLCmdRsp_t *hdllCmdRsp = NULL;
-
-  NXPLOG_FWDNLD_D("Wait for HDL_READY notification\n");
-  ret =
-      phHdll_GetApdu((uint8_t *)&rsp_buf[0], HDLL_READ_BUFF_SIZE, &rsp_buf_len);
-
-  if (!rsp_buf_len || ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_D("Error in reading GET_HDL_READY notification\n");
-    return ret;
-  }
-
-  hdllCmdRsp = (phHDLLCmdRsp_t *)malloc(sizeof(phHDLLCmdRsp_t));
-  if (NULL == hdllCmdRsp) {
-    return ret;
-  }
-
-  hdllCmdRsp->group = HCP_OPERATION_GROUP_PROTOCOL;
-  hdllCmdRsp->operation = PROTOCOL_GROUP_OP_CODE_HDLL;
-  hdllCmdRsp->rsp_buf = rsp_buf;
-  hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-  hdllCmdRsp->status = READY;
-  hdllCmdRsp->type = HCP_TYPE_NOTIFICATION;
-  ret = process_hdll_response(hdllCmdRsp);
-
-  if (FW_DNLD_SUCCESS != ret) {
-    // check whether we received EDL ready notification or not
-    // if yes, perform FW download directly.
-    hdllCmdRsp->group = HCP_OPERATION_GROUP_PROTOCOL;
-    hdllCmdRsp->operation = PROTOCOL_GROUP_OP_CODE_EDL;
-    hdllCmdRsp->rsp_buf = rsp_buf;
-    hdllCmdRsp->rsp_buf_len = rsp_buf_len;
-    hdllCmdRsp->status = READY;
-    hdllCmdRsp->type = HCP_TYPE_NOTIFICATION;
-    ret = process_hdll_response(hdllCmdRsp);
-
-    if (FW_DNLD_SUCCESS == ret) {
-      bSkipEdlCheck = true;
-    }
-  }
-
-  if (NULL != hdllCmdRsp) {
-    free(hdllCmdRsp);
-  }
-
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   phEdl_send_and_recv
-**
-** Description :   This function sends and receives the EDL group commands and
-                   responses based on the given operation code.
-**
-** Parameters  :   hdll_data - HDLL command buffer
-                   hdll_data_len - HDLL command buffer len
-                   group - HCP group code
-                   operation - operation code.
-**
-** Returns     :   FW_DNLD_FAILURE - If any failure occurs while framing or
-                                    sending the command or while receiving the
-                                    response
-                   FW_DNLD_SUCCESS - On success
-**
-**
-*******************************************************************************/
-
-phFWD_Status_t phEdl_send_and_recv(uint8_t *hdll_data, uint32_t hdll_data_len,
-                                   uint8_t group, uint8_t operation) {
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-  uint8_t rsp_buff[HDLL_READ_BUFF_SIZE] = {0};
-
-  if (group != HCP_OPERATION_GROUP_EDL) {
-    NXPLOG_FWDNLD_D("Error! HCP operation group is not EDL\n");
-    return ret;
-  }
-  switch (operation) {
-  case EDL_DOWNLOAD_CERTIFICATE: {
-    ret = sendEdlDownloadCertificateCmd(hdll_data, hdll_data_len, rsp_buff);
-  } break;
-  case EDL_DOWNLOAD_FLASH_WRITE_FIRST: {
-    ret = sendEdlFlashWriteFirstCmd(hdll_data, hdll_data_len, rsp_buff);
-  } break;
-  case EDL_DOWNLOAD_FLASH_WRITE: {
-    ret = sendEdlFlashWriteCmd(hdll_data, hdll_data_len, rsp_buff);
-  } break;
-  case EDL_DOWNLOAD_FLASH_WRITE_LAST: {
-    ret = sendEdlFlashWriteLastCmd(hdll_data, hdll_data_len, rsp_buff);
-  } break;
-  case EDL_LIFECYCLE_CERTIFICATE: {
-    ret = sendEdlLifecycleCertificateCmd(hdll_data, hdll_data_len, rsp_buff);
-  } break;
-  case EDL_LIFECYCLE_WRITE_FIRST: {
-    ret = sendEdlLifecycleWriteFirstCmd(hdll_data, hdll_data_len, rsp_buff);
-  } break;
-  case EDL_LIFECYCLE_WRITE_LAST: {
-    ret = sendEdlLifecycleWriteLastCmd(hdll_data, hdll_data_len, rsp_buff);
-  } break;
-  case EDL_PATCH_FLASH_WRITE: {
-    ret = sendEdlPatchFlashWriteCmd(hdll_data, hdll_data_len, rsp_buff);
-  } break;
-
-  default:
-    break;
-  }
-  return ret;
-}
-
-/*******************************************************************************
-**
-** Function    :   phLoadFwBinary
-**
-** Description :   This function reads the MW FW binary file and writes to
-                   HeliosX chip.
-**
-** Parameters  :   pfwImageCtx -> pointer to fw image context
-**
-** Returns     :   FW_DNLD_FAILURE - on failure
-                   FW_DNLD_SUCCESS - On success
-**
-**
-*******************************************************************************/
-phFWD_Status_t phLoadFwBinary(phUwbFWImageContext_t *pfwImageCtx) {
-  uint32_t next_frame_first_byte_index = 0;
-  uint8_t current_op_group;
-  uint8_t current_op;
-  uint32_t frame_payload_length = 0;
-  uint32_t frame_length = 0;
-  phFWD_Status_t status = FW_DNLD_FAILURE;
-  uint8_t current_frame[MAX_FRAME_LEN] = {0};
-
-  if (NULL == pfwImageCtx->fwImage) {
-    return status;
-  }
-  NXPLOG_FWDNLD_D("phLoadFwBinary\n");
-  while (1) {
-    // compute next frame payload length
-    // TODO: warning this is not HDLL fragmentation compatible (valid header can
-    // have chunk flag (biy 10 (13)) set) Assuming header length is 2 bytes
-    frame_payload_length = (pfwImageCtx->fwImage[next_frame_first_byte_index] << 8) +
-                           (pfwImageCtx->fwImage[next_frame_first_byte_index + 1]);
-
-    // if max_payload_length is not None and (frame_payload_length >=
-    // max_payload_length): raise Exception('Invalid SFWU content (not an HDLL
-    // header).')
-
-    // copy the header, the payload and the footer (crc) from the file bytes
-    // into a byte array
-    frame_length = frame_payload_length + HDLL_HEADER_LEN + HDLL_FOOTER_LEN;
-    if (frame_length > MAX_FRAME_LEN) {
-      NXPLOG_FWDNLD_E("%s: Error while performing FW download frame_length > "
-                      "MAX_FRAME_LEN\n",
-                      __func__);
-      status = FW_DNLD_FAILURE;
-      break;
-    }
-    memcpy(current_frame, &pfwImageCtx->fwImage[next_frame_first_byte_index],
-           frame_length);
-    current_op_group = current_frame[2];
-    current_op = current_frame[3];
-
-    status = phEdl_send_and_recv(current_frame, frame_length, current_op_group,
-                                 current_op);
-    if (status != FW_DNLD_SUCCESS) {
-      NXPLOG_FWDNLD_E("%s: Error while performing FW download\n", __func__);
-      break;
-    }
-
-    // update byte index
-    next_frame_first_byte_index = next_frame_first_byte_index + frame_length;
-
-    // check end of file
-    if (next_frame_first_byte_index >= pfwImageCtx->fwImgSize) {
-      break;
-    }
-  }
-
-  // clean-up
-  if (pfwImageCtx->fwImage != NULL) {
-    if (pfwImageCtx->fw_dnld_config == BIN_FILE_BASED_FW_DOWNLOAD) {
-      free(pfwImageCtx->fwImage);
-    } else if (pfwImageCtx->fw_dnld_config == SO_FILE_BASED_FW_DOWNLOAD) {
-      if (pfwImageCtx->gFwLib != NULL) {
-        dlclose(pfwImageCtx->gFwLib);
-        pfwImageCtx->gFwLib = NULL;
-      }
-    }
-
-    pfwImageCtx->fwImage = NULL;
-  }
-  return status;
-}
-
-/******************************************************************************
- * Function         phHandle_hdll_read_timeout_cb
- *
- * Description      Timer call back function
- *
- * Returns          None
- *
- ******************************************************************************/
-static void phHandle_hdll_read_timeout_cb(uint32_t timerId, void *pContext) {
-  UNUSED(timerId);
-  UNUSED(pContext);
-  NXPLOG_FWDNLD_E("ERROR: phHandle_hdll_read_timeout_cb - HDLL read timeout\n");
-  ioctl((intptr_t)tPalConfig.pDevHandle, SRXXX_SET_PWR, ABORT_READ_PENDING);
-  isHdllReadTmeoutExpired = true;
-}
-
-/******************************************************************************/
-/*   GLOBAL FUNCTIONS                                                         */
-/******************************************************************************/
-
-/*******************************************************************************
-**
-** Function    :   phHdll_GetApdu
-**
-** Description :   This function reads the HDLL command's response from HeliosX
-                   chip over SPI.
-**
-** Parameters  :   pApdu     - HDLL response buffer
-                   sz        - Max buffer size to be read
-                   rsp_buf_len - HDLL response buffer length
-**
-** Returns     :   phFWD_Status_t : 0 - success
-                                     1 - failure
-**
-**
-*******************************************************************************/
-
-phFWD_Status_t phHdll_GetApdu(uint8_t *pApdu, uint16_t sz,
-                              uint16_t *rsp_buf_len) {
-  // NXPLOG_FWDNLD_D("phHdll_GetApdu Enter\n");
-  int ret_len = 0;
-  int status = 0;
-
-  if (sz == 0 || sz > PHHDLL_MAX_LEN_PAYLOAD_MISO) {
-    NXPLOG_FWDNLD_E("ERROR: phHdll_GetApdu data len is 0 or greater than max "
-                    "palyload length supported\n");
-    return FW_DNLD_FAILURE;
-  }
-
-  /* Start timer */
-  status = phOsalUwb_Timer_Start(timeoutTimerId, HDLL_READ_OP_TIMEOUT,
-                                 &phHandle_hdll_read_timeout_cb, NULL);
-  if (UWBSTATUS_SUCCESS != status) {
-    NXPLOG_FWDNLD_E("%s: Response timer not started!!!", __func__);
-    return FW_DNLD_FAILURE;
-  }
-  ret_len = read((intptr_t)tPalConfig.pDevHandle, (void *)pApdu, (sz));
-
-  if (true == isHdllReadTmeoutExpired) {
-    isHdllReadTmeoutExpired = false;
-    return FW_DNLD_FAILURE;
-  } else {
-    /* Stop Timer */
-    status = phOsalUwb_Timer_Stop(timeoutTimerId);
-    if (UWBSTATUS_SUCCESS != status) {
-      NXPLOG_FWDNLD_E("%s: Response timer stop ERROR!!!", __func__);
-      return FW_DNLD_FAILURE;
-    }
-  }
-
-  if (ret_len <= 0) {
-    NXPLOG_FWDNLD_E("ERROR: Get APDU %u bytes failed!\n", sz);
-    return FW_DNLD_FAILURE;
-  }
-  *rsp_buf_len = ret_len;
-  if (is_fw_download_log_enabled == 0x01) {
-    phNxpUciHal_print_packet(NXP_TML_FW_DNLD_RSP_UWBS_2_AP, pApdu, ret_len);
-  }
-
-  return FW_DNLD_SUCCESS;
-}
-
-/*******************************************************************************
-**
-** Function    :   phHdll_PutApdu
-**
-** Description :   This function sends the HDLL command to HeliosX chip over SPI
-**
-** Parameters  :   pApdu     - HDLL command to be sent
-                   sz        - HDLL command length
-**
-** Returns     :   phFWD_Status_t : 0 - success
-                                     1 - failure
-**
-**
-*******************************************************************************/
-
-phFWD_Status_t phHdll_PutApdu(uint8_t *pApdu, uint16_t sz) {
-  int ret;
-  int numWrote = 0;
-  if (is_fw_download_log_enabled == 0x01) {
-    phNxpUciHal_print_packet(NXP_TML_FW_DNLD_CMD_AP_2_UWBS, pApdu, sz);
-  }
-
-  ret = write((intptr_t)tPalConfig.pDevHandle, pApdu, sz);
-  if (ret > 0) {
-    numWrote += ret;
-  } else if (ret == 0) {
-    NXPLOG_FWDNLD_E("_spi_write() EOF");
-    return FW_DNLD_FAILURE;
-  } else {
-    NXPLOG_FWDNLD_E("_spi_write() errno : %x", ret);
-    return FW_DNLD_FAILURE;
-  }
-  return FW_DNLD_SUCCESS;
-}
-
-/*******************************************************************************
- * Function         hdll_fw_download
- *
- * Description      This function is called by jni when wired mode is
- *                  performed.First SRXXX driver will give the access
- *                  permission whether wired mode is allowed or not
- *                  arg (0):
- * Returns          FW_DNLD_SUCCESS - on success
-                    FW_DNLD_FAILURE - on failure
-                    FW_DNLD_FILE_NOT_FOUND - if the FW binary is not found or
-                                             unable to open
- *
- ******************************************************************************/
-int hdll_fw_download()
-{
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-  unsigned long num = 0;
-  NXPLOG_FWDNLD_D("hdll_fw_download enter.....\n");
-
-  isHdllReadTmeoutExpired = false;
-  bSkipEdlCheck = false;
-  if (NxpConfig_GetNum(NAME_UWB_FW_DOWNLOAD_LOG, &num, sizeof(num))) {
-    is_fw_download_log_enabled = (uint8_t)num;
-    ALOGD("NAME_UWB_FW_DOWNLOAD_LOG: 0x%02x\n", is_fw_download_log_enabled);
-  } else {
-    ALOGD("NAME_UWB_FW_DOWNLOAD_LOG: failed 0x%02x\n",
-          is_fw_download_log_enabled);
-  }
-  ioctl((intptr_t)tPalConfig.pDevHandle, SRXXX_SET_FWD, PWR_ENABLE);
-
-  ret = phHdll_GetHdllReadyNtf();
-  if (ret != FW_DNLD_SUCCESS) {
-    NXPLOG_FWDNLD_E("%s:%d error in getting the hdll ready notification...\n",
-                    __func__,__LINE__);
-    return ret;
-  }
-  /* Get the Device information */
-  ret = phGenericGetInfo();
-  if (ret == FW_DNLD_FILE_NOT_FOUND) {
-      goto exit;
-  }
-
-  if (ret == FW_DNLD_FAILURE) {
-    NXPLOG_FWDNLD_E("%s: error in getting the getInfo notification...\n",
-                      __func__);
-    return ret;
-  }
-
-  if (!bSkipEdlCheck) {
-    if (ret == FW_DNLD_NOT_REQUIRED)
-    {
-      goto exit;
-    }
-    ret = phGetEdlReadyNtf();
-    if (ret != FW_DNLD_SUCCESS) {
-      NXPLOG_FWDNLD_E("%s: error in getting the EDL ready notification...\n",
-                      __func__);
-      return ret;
-    }
-  }
-
-  if(fwImageCtx.fwRecovery)
-  {
-    /* perform FW recovery */
-    ret = phNxpUciHal_fw_recovery(&fwImageCtx);
-    if (ret == FW_DNLD_FAILURE) {
-      NXPLOG_FWDNLD_E("%s: error downloading recovery FW...\n",
-                      __func__);
-      return ret;
-    }
-    // TODO: Remove this after recovrry FW tested added to avoid endless loop of fw download.
-    fwImageCtx.fwRecovery = false;
-  }
-
-  /*  */
-  ret = phLoadFwBinary(&fwImageCtx);
-  if (ret != FW_DNLD_SUCCESS) {
-    NXPLOG_FWDNLD_E("%s: error in phLoadFwBinary...\n", __func__);
-    return ret;
-  }
-
-exit:
-  // do chip reset
-  phTmlUwb_Chip_Reset();
-  ret = phHdll_GetHdllReadyNtf();
-
-  ioctl((intptr_t)tPalConfig.pDevHandle, SRXXX_SET_FWD, PWR_DISABLE);
-  NXPLOG_FWDNLD_D("hdll_fw_download completed.....\n");
-  return ret;
-}
-
-/*******************************************************************************
- * Function         phNxpUciHal_fw_recovery
- *
- * Description      This function is use to download recovery FW
- * Returns          FW_DNLD_SUCCESS - on success
-                    FW_DNLD_FAILURE - on failure
-                    FW_DNLD_FILE_NOT_FOUND - if the FW binary is not found or
-                                             unable to open
- *
- ******************************************************************************/
-
-static phFWD_Status_t phNxpUciHal_fw_recovery(phUwbFWImageContext_t *pfwImageCtx) {
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-  NXPLOG_FWDNLD_D("phNxpUciHal_fw_recovery enter.....\n");
-
-  ret = phLoadFwBinary(pfwImageCtx);
-  if (ret != FW_DNLD_SUCCESS) {
-    NXPLOG_FWDNLD_E("%s: error in phLoadFwBinary...\n", __func__);
-    return ret;
-  }
-
-  // do chip reset
-  phTmlUwb_Chip_Reset();
-  ret = phHdll_GetHdllReadyNtf();
-  if (ret != FW_DNLD_SUCCESS) {
-    NXPLOG_FWDNLD_E("%s:%d error in getting the hdll ready notification...\n",
-                    __func__,__LINE__);
-    return ret;
-  }
-  /* Get the Device information */
-  ret = phGenericGetInfo();
-  if (ret == FW_DNLD_FAILURE || ret == FW_DNLD_FILE_NOT_FOUND) {
-      NXPLOG_FWDNLD_E("%s:%d error in getting the getInfo notification...\n",
-                      __func__,__LINE__);
-      return ret;
-  }
-
-  if (!bSkipEdlCheck) {
-    if (ret == FW_DNLD_NOT_REQUIRED) {
-      return ret;
-    }
-
-    ret = phGetEdlReadyNtf();
-    if (ret != FW_DNLD_SUCCESS) {
-      NXPLOG_FWDNLD_E("%s:%d error in getting the EDL ready notification...\n",
-                      __func__,__LINE__);
-      return ret;
-    }
-  }
-
-  return ret;
-}
-
-/*******************************************************************************
- * Function         phNxpUciHal_fw_lcrotation
- *
- * Description      This function is use to download recovery FW
- * Returns          FW_DNLD_SUCCESS - on success
-                    FW_DNLD_FAILURE - on failure
-                    FW_DNLD_FILE_NOT_FOUND - if the FW binary is not found or
-                                             unable to open
- *
- ******************************************************************************/
-
-phFWD_Status_t phNxpUciHal_fw_lcrotation() {
-  phFWD_Status_t ret = FW_DNLD_FAILURE;
-  glcRotation = true;
-  NXPLOG_FWDNLD_D("phNxpUciHal_fw_lcrotation enter.....\n");
-
-  ioctl((intptr_t)tPalConfig.pDevHandle, SRXXX_SET_FWD, PWR_ENABLE);
-
-  ret = phHdll_GetHdllReadyNtf();
-  if (ret != FW_DNLD_SUCCESS) {
-    NXPLOG_FWDNLD_E("%s:%d error in getting the hdll ready notification...\n",
-                    __func__,__LINE__);
-    return ret;
-  }
-    /* Get the Device information */
-  ret = phGenericGetInfo();
-  if (ret == FW_DNLD_FILE_NOT_FOUND) {
-    goto exit;
-  }
-
-  if (ret == FW_DNLD_FAILURE) {
-      NXPLOG_FWDNLD_E("%s:%d error in getting the getInfo notification...\n",
-                      __func__,__LINE__);
-      return ret;
-  }
-
-  if (!bSkipEdlCheck) {
-
-    ret = phGetEdlReadyNtf();
-    if (ret != FW_DNLD_SUCCESS) {
-      NXPLOG_FWDNLD_E("%s:%d error in getting the EDL ready notification...\n",
-                      __func__,__LINE__);
-      return ret;
-    }
-  }
-  ret = phLoadFwBinary(&fwImageCtx);
-  if (ret != FW_DNLD_SUCCESS) {
-    NXPLOG_FWDNLD_E("%s: error in phLoadFwBinary...\n", __func__);
-    glcRotation = false;
-    return ret;
-  }
-  glcRotation = false;
-
-exit:
-  // do chip reset
-  phTmlUwb_Chip_Reset();
-  ret = phHdll_GetHdllReadyNtf();
-
-  ioctl((intptr_t)tPalConfig.pDevHandle, SRXXX_SET_FWD, PWR_DISABLE);
-  NXPLOG_FWDNLD_D("hdll_fw_download completed.....\n");
-  return ret;
-}
-
-/*******************************************************************************
- * Function         setDeviceHandle
- *
- * Description      This function sets the SPI device handle that needs to be
-                    used in this file for SPI communication
- * Parameters       pDevHandle - SPI device handle
- * Returns          None
- *
- ******************************************************************************/
-void setDeviceHandle(void *pDevHandle) {
-  NXPLOG_FWDNLD_D("Set the device handle!\n");
-  if (pDevHandle == NULL) {
-    NXPLOG_FWDNLD_E("device handle is NULL!\n");
-  } else {
-    tPalConfig.pDevHandle = (void *)((intptr_t)pDevHandle);
-  }
-}
diff --git a/halimpl/hal/sr200/fwd_hdll.h b/halimpl/hal/sr200/fwd_hdll.h
deleted file mode 100644
index 7b54a49..0000000
--- a/halimpl/hal/sr200/fwd_hdll.h
+++ /dev/null
@@ -1,258 +0,0 @@
-/*
- * Copyright 2021-2023 NXP
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
-#ifndef _PHNXPUCIHAL_FW_H
-#define _PHNXPUCIHAL_FW_H
-#include <stdint.h>
-
-#define PHHDLL_LEN_LRC (1U)
-#define PHHDLL_MAX_MISO_DATA_LEN (256U)
-#define PHHDLL_MAX_LEN_PAYLOAD_MISO (PHHDLL_MAX_MISO_DATA_LEN + PHHDLL_LEN_LRC)
-
-#define FILEPATH_MAXLEN 500
-#define FILENAME_MAXLEN 260
-
-#define HCP_MSG_HEADER_LEN 2
-#define HDLL_HEADER_LEN 2
-#define HDLL_FOOTER_LEN 2
-#define HDLL_CRC_LEN 2
-#define HDLL_PKT_CHUNK_BITMASK 0x2000
-#define HDLL_PKT_LEN_BITMASK 0x1FFF
-#define HCP_GROUP_LEN 6 // bits
-
-#define HDLL_CHUNK_OFFSET 0
-#define HDLL_LEN_OFFSET 1
-#define HDLL_TYPE_OFFSET 2
-#define HDLL_GROUP_OFFSET 2
-#define HDLL_OPERATION_OFFSET 3
-#define HDLL_PAYLOAD_OFFSET 4
-
-#define HDLL_RSP_STATUS_OFFSET 4
-#define HDLL_RSP_PAYLOAD_OFFSET 5
-
-#define HDLL_RSP_GROUP_BIT_MASK 0x3F
-#define HDLL_MIN_RSP_LEN 8
-#define MW_MAJOR_FW_VER_OFFSET 4
-#define MW_MINOR_FW_VER_OFFSET 5
-
-#define HDLL_READ_BUFF_SIZE 64
-#define HDLL_READ_OP_TIMEOUT 2000 /* 2 seconds timeout */
-
-#define BIN_FILE_BASED_FW_DOWNLOAD 0x00
-#define SO_FILE_BASED_FW_DOWNLOAD  0x01
-#define SESSION_CONTROL_OPEN 0x55
-
-/* Struct to frame HDLL command */
-typedef struct phHDLLCmd {
-  uint8_t group;
-  uint8_t operation;
-  uint8_t chunk_size;
-  uint16_t payload_len;
-  uint16_t frame_size;
-  uint8_t *payload;
-} phHDLLCmd_t;
-
-/* Struct to process HDLL response */
-typedef struct phHDLLCmdRsp {
-  uint8_t *rsp_buf;
-  uint8_t rsp_buf_len;
-  uint8_t group;
-  uint8_t operation;
-  uint8_t status;
-  uint8_t type;
-} phHDLLCmdRsp_t;
-
-/* HCP Operation Group */
-typedef enum {
-  HCP_OPERATION_GROUP_PROTOCOL = 0x01,
-  HCP_OPERATION_GROUP_GENERIC,
-  HCP_OPERATION_GROUP_EDL
-} eHCP_OPERATION_GROUP_t;
-
-/* operation codes under protocol group */
-typedef enum {
-  PROTOCOL_GROUP_OP_CODE_HDLL = 0x01,
-  PROTOCOL_GROUP_OP_CODE_HCP,
-  PROTOCOL_GROUP_OP_CODE_EDL
-} ePROTOCOL_GROUP_OP_CODE_t;
-
-/* operation codes under generic group */
-typedef enum {
-  GENERIC_GROUP_OP_CODE_RESET = 0x01,
-  GENERIC_GROUP_OP_CODE_GETINFO
-} eGENERIC_GROUP_OP_CODE_t;
-
-/* operation code under EDL group */
-typedef enum {
-  EDL_DOWNLOAD_CERTIFICATE = 0x01,
-  EDL_DOWNLOAD_FLASH_WRITE_FIRST = 0x02,
-  EDL_DOWNLOAD_FLASH_WRITE = 0x03,
-  EDL_DOWNLOAD_FLASH_WRITE_LAST = 0x04,
-  EDL_DOWNLOAD_SRAM_WRITE_FIRST = 0x05,
-  EDL_DOWNLOAD_SRAM_WRITE = 0x06,
-  EDL_DOWNLOAD_SRAM_WRITE_LAST = 0x07,
-  EDL_LIFECYCLE_CERTIFICATE = 0x11,
-  EDL_LIFECYCLE_WRITE_FIRST = 0x12,
-  EDL_LIFECYCLE_WRITE_LAST = 0x13,
-  EDL_PATCH_SRAM_WRITE = 0x21,
-  EDL_PATCH_SRAM_WRITE_LAST = 0x22,
-  EDL_PATCH_FLASH_WRITE = 0x23
-} eEDL_GROUP_OP_CODE_t;
-
-/* UWB Device ROM Version */
-typedef enum {
-  VER_A1V1 = 0x02,
-  VER_A1V2 = 0x03,
-} eUWBD_Rom_Version_t;
-
-/* UWB AT page status */
-typedef enum {
-  STATUS_PAGE_OK = 0x55,
-  STATUS_RECOVERED_N_1 = 0x5A,
-  STATUS_RECOVERED_N_2 = 0xA5,
-  STATUS_PAGE_ERROR = 0xAA,
-} eUWBD_AT_Page_status_t;
-
-/* UWB Device lifecycle mode */
-typedef enum {
-  UNKNOWN = 0xCCCCCCCC,
-  DEGRADED_MODE = 0x5C5C5C5C,
-  FLASH_TEST_MODE = 0xAAAAAAAA,
-  DEVELOPMENT_MODE = 0xC5C5C5C5,
-  CUSTOMER_MODE = 0xA5A5A5A5,
-  PROTECTED_MODE = 0x55555555,
-  NXP_RMA_MODE = 0x5A5A5A5A,
-} eUWBD_LC_mode_t;
-
-/* Struct to store the getinfo response */
-typedef struct phHDLLGetInfo {
-  uint8_t boot_status;
-  uint8_t session_control;
-  uint8_t session_type;
-  eUWBD_Rom_Version_t rom_version;
-  eUWBD_AT_Page_status_t AT_page_status;
-  uint8_t chip_major_ver;
-  uint8_t chip_minor_ver;
-  uint8_t fw_minor_ver;
-  uint8_t fw_major_ver;
-  uint8_t chip_variant[4];
-  eUWBD_LC_mode_t device_life_cycle;
-  uint8_t chip_id[16];
-  uint8_t chip_id_crc[4];
-} phHDLLGetInfo_t;
-
-/* HCP type */
-typedef enum {
-  HCP_TYPE_COMMAND = 0x00,
-  HCP_TYPE_RESPONSE,
-  HCP_TYPE_NOTIFICATION
-} eHCP_TYPE_t;
-
-/* Application status codes */
-typedef enum {
-  /* Success */
-  GENERIC_SUCCESS = 0x00,
-  ACKNOWLEDGE = 0x01,
-  READY = 0x02,
-
-  /* Generic errors */
-  GENERIC_ERROR = 0x80,
-  MEMORY_ERROR = 0x81,
-  TIMEOUT_ERROR = 0x82,
-  CRC_ERROR = 0x83,
-  INVALID_ERROR = 0x84,
-
-  /* Verification errors */
-  INVALID_LENGTH_ERROR = 0x90,
-  INVALID_ADDRESS_ERROR = 0x91,
-  ECC_SIGNATURE_ERROR = 0x92,
-  SHA384_HASH_ERROR = 0x93,
-  LIFECYCLE_VALIDITY_ERROR = 0x94,
-  CHIP_ID_ERROR = 0x95,
-  CHIP_VERSION_ERROR = 0x96,
-  CERTIFICATE_VERSION_ERROR = 0x97,
-  FIRMWARE_VERSION_ERROR = 0x98,
-  SRAM_DOWNLOAD_ALLOW_ERROR = 0x99,
-
-  /* Encryption errors */
-  KEY_DERIVATION_ERROR = 0xA0,
-  ENCRYPTED_PAYLOAD_DECRYPTION_ERROR = 0xA1,
-  INVALID_ENCRYPTED_PAYLOAD_ERROR = 0xA2,
-
-  /* N-1 & N-2 errors */
-  PROTECTED_CACHE_LOAD_ERROR = 0xB0,
-  PROTECTED_CACHE_DEPLOY_ERROR = 0xB1,
-  LIFECYCLE_UPDATE_ERROR = 0xB2,
-
-  /* Flash errors */
-  FLASH_BLANK_PAGE_ERROR = 0xC0,
-  FLASH_CHECK_MARGIN_ERROR = 0xC1
-} eAPPLICATION_STATUS_CODES_t;
-
-/* FW download status */
-typedef enum phFWD_Status {
-  FW_DNLD_SUCCESS = 0x00,
-  FW_DNLD_FAILURE = 0x01,
-  FW_DNLD_REQUIRED = 0x02,
-  FW_DNLD_NOT_REQUIRED = 0x03,
-  FW_DNLD_FILE_NOT_FOUND = 0x14,
-} phFWD_Status_t;
-
-/* FW download flash config status */
-typedef enum phFWD_flash_Status {
-  FLASH_UPPER_VER_UPDATE = 0x01,
-  FLASH_FORCE_UPDATE = 0x02,
-  FLASH_DIFFERENT_VER_UPDATE = 0x03,
-} phFWD_flash_Status_t;
-
-typedef struct phUwbFWImageContext
-{
-    /* pointer to the FW image to be used */
-    uint8_t *fwImage;
-    /* size of fw image */
-    uint32_t fwImgSize;
-    /* FW FLASH update Options Configurations */
-    uint8_t fw_flash_config;
-    /* FW Download file Options Configurations */
-    uint8_t fw_dnld_config;
-    /* FW recovery */
-    bool fwRecovery;
-    void *gFwLib;
-    /* default fw file path */
-    char default_fw_path[FILEPATH_MAXLEN];
-    /* Device Info */
-    phHDLLGetInfo_t *deviceInfo;
-} phUwbFWImageContext_t;
-
-/* SR200 device config */
-typedef struct phPalSr200_Config {
-  void* pDevHandle;
-} phPalSr200_Config_t;
-
-/* PWR States */
-typedef enum phSetPwrState{
-  PWR_DISABLE = 0,
-  PWR_ENABLE,
-  ABORT_READ_PENDING
-} phSetPwrState_t;
-
-phPalSr200_Config_t tPalConfig;
-
-phFWD_Status_t phHdll_GetApdu(uint8_t *pApdu, uint16_t sz,
-                              uint16_t *rsp_buf_len);
-phFWD_Status_t phHdll_PutApdu(uint8_t *pApdu, uint16_t sz);
-
-#endif /* _PHNXPUCIHAL_FW_H */
diff --git a/halimpl/hal/sr200/phNxpUciHal_LC.cc b/halimpl/hal/sr200/phNxpUciHal_LC.cc
deleted file mode 100644
index 1a3d56f..0000000
--- a/halimpl/hal/sr200/phNxpUciHal_LC.cc
+++ /dev/null
@@ -1,498 +0,0 @@
-/*
- * Copyright 2012-2019, 2022-2023 NXP
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
-#if 0
-
-#include <log/log.h>
-#include <phNxpLog.h>
-#include <cutils/properties.h>
-#include <phNxpUciHal.h>
-#include <phNxpUciHal_Adaptation.h>
-#include <phNxpUciHal_ext.h>
-#include <phTmlUwb.h>
-#include <phTmlUwb_spi.h>
-#include <sys/stat.h>
-#include <string.h>
-#include <array>
-#include "hal_nxpuwb.h"
-#include "phNxpConfig.h"
-#include <android-base/stringprintf.h>
-
-#if (NXP_UWB_EXTNS == TRUE)
-#include "phNxpUciHalProp.h"
-#endif
-#include <phNxpUciHal_LC.h>
-
-using android::base::StringPrintf;
-
-phNxpUciHal_lcfwdl_Control_t nxpucihal_lcfwdl_ctrl;
-extern phNxpUciHal_Control_t nxpucihal_ctrl;
-extern bool uwb_get_platform_id;
-extern bool uwb_device_initialized;
-static uint8_t Rx_buffer[UCI_MAX_DATA_LEN];
-
-/**************** local methods used in this file only ************************/
-static tHAL_UWB_STATUS phNxpUciHal_performLcRotation();
-static void* phNxpUciHal_lcfwdl_thread(void* arg);
-
-/******************************************************************************
- * Function         phNxpUciHal_lcfwdl_thread
- *
- * Description      This function is a thread handler which handles all TML and
- *                  UCI messages.
- *
- * Returns          void
- *
- ******************************************************************************/
-static void* phNxpUciHal_lcfwdl_thread(void* arg) {
-  phNxpUciHal_lcfwdl_Control_t* p_nxpucihal_lcfwdl_ctrl = (phNxpUciHal_lcfwdl_Control_t*)arg;
-  tHAL_UWB_STATUS status = UWBSTATUS_FAILED;
-
-  NXPLOG_UCIHAL_D("lcfwdl thread started");
-  p_nxpucihal_lcfwdl_ctrl->lcfwdl_thread_running = 1;
-
-  while (p_nxpucihal_lcfwdl_ctrl->lcfwdl_thread_running == 1) {
-
-    if (p_nxpucihal_lcfwdl_ctrl->lcfwdl_thread_running == 0) {
-      break;
-    }
-
-    if(p_nxpucihal_lcfwdl_ctrl->isPlatformIdSet) {
-      status = phNxpUciHal_performLcRotation();
-      if (nxpucihal_ctrl.p_uwb_stack_cback != NULL) {
-        /* Send binding status cached ntf event */
-        if ((nxpucihal_ctrl.p_uwb_stack_data_cback != NULL) && (nxpucihal_lcfwdl_ctrl.rcv_data_len <= UCI_MAX_PAYLOAD_LEN)) {
-          if(status != UWBSTATUS_SUCCESS) {
-            /* lc rotation FW fwdl failed cased */
-            NXPLOG_UCIHAL_E("phNxpUciHal_performLcRotation failed...");
-            nxpucihal_lcfwdl_ctrl.rcv_data[4] = 0x04;
-          }
-          (*nxpucihal_ctrl.p_uwb_stack_data_cback)(nxpucihal_lcfwdl_ctrl.rcv_data_len, nxpucihal_lcfwdl_ctrl.rcv_data);
-        }
-      }
-    } else {
-      if (nxpucihal_ctrl.p_uwb_stack_cback != NULL) {
-        /* Send binding status cached ntf event */
-        if ((nxpucihal_ctrl.p_uwb_stack_data_cback != NULL) && (nxpucihal_lcfwdl_ctrl.rcv_data_len <= UCI_MAX_PAYLOAD_LEN)) {
-            /* lc rotation FW fwdl failed cased */
-            NXPLOG_UCIHAL_E("%s Platform Id is not set...", __func__);
-            nxpucihal_lcfwdl_ctrl.rcv_data[4] = 0x04;
-          (*nxpucihal_ctrl.p_uwb_stack_data_cback)(nxpucihal_lcfwdl_ctrl.rcv_data_len, nxpucihal_lcfwdl_ctrl.rcv_data);
-        }
-      }
-    }
-    p_nxpucihal_lcfwdl_ctrl->isLcRotationOngoing = 0;
-    p_nxpucihal_lcfwdl_ctrl->lcfwdl_thread_running = 0;
-
-    break;
-  }
-
-  NXPLOG_UCIHAL_D("lcfwdl thread stopped");
-  pthread_attr_destroy(&nxpucihal_lcfwdl_ctrl.attr_thread);
-  pthread_exit(NULL);
-  return NULL;
-}
-
-/******************************************************************************
- * Function         phNxpUciHal_parsePlatformId
- *
- * Description      This function parse GetPlatformId response.
- *
- * Returns          void
- *
- ******************************************************************************/
-void phNxpUciHal_parsePlatformId(uint8_t * p_rx_data , uint16_t rx_data_len) {
-  uint8_t index = UCI_MSG_HDR_SIZE; // Excluding the header and Versions
-  uint8_t * pUwbsRsp = NULL;
-  uint16_t uwbsRspLen = 0;
-  uint8_t getCalibStatus = UWBSTATUS_FAILED;
-  uint8_t getCalibState;
-  uint8_t count = 0;
-  NXPLOG_UCIHAL_D("phNxpUciHal_parsePlatformId enter ....");
-
-  pUwbsRsp = (uint8_t*)malloc(sizeof(uint8_t) * rx_data_len);
-  if(pUwbsRsp == NULL) {
-    NXPLOG_UCIHAL_E("pUwbsRsp memory allocation failed");
-    return;
-  }
-  memcpy(&pUwbsRsp[0], &p_rx_data[0], rx_data_len);
-  if (rx_data_len < UCI_MSG_HDR_SIZE){
-    NXPLOG_UCIHAL_E("%s : Invalid rsp length", __func__);
-    free(pUwbsRsp);
-    return;
-  }
-  uwbsRspLen = rx_data_len ;
-  getCalibStatus = pUwbsRsp[index++];
-  NXPLOG_UCIHAL_D("getCalibStatus %d" , getCalibStatus);
-  if(getCalibStatus == UWBSTATUS_SUCCESS) {
-    getCalibState = pUwbsRsp[index++];
-    if (getCalibState == 0x08) {
-      NXPLOG_UCIHAL_D("Platform ID not Set");
-      uwb_get_platform_id = false;
-      free(pUwbsRsp);
-      return;
-    } else {
-      do {
-          nxpucihal_lcfwdl_ctrl.uwbsPlatformId[count++] = pUwbsRsp[index++];
-      } while(index < uwbsRspLen);
-    }
-    nxpucihal_lcfwdl_ctrl.isPlatformIdSet = true;
-    uwb_get_platform_id = false;
-    NXPLOG_UCIHAL_D("Platform ID: %s", nxpucihal_lcfwdl_ctrl.uwbsPlatformId);
-  }
-  free(pUwbsRsp);
-  return;
-}
-
-/******************************************************************************
- * Function         phNxpUciHal_parseUWBSLifecycle
- *
- * Description      This function parse UWBS Lifecycle response.
- *
- * Returns          UWBS Lifecycle.
- *
- ******************************************************************************/
-uint32_t phNxpUciHal_parseUWBSLifecycle(uint8_t * p_rx_data , uint16_t rx_data_len) {
-  uint8_t index = UCI_MSG_HDR_SIZE; // Excluding the header and Versions
-  uint8_t paramId = 0;
-  uint8_t length = 0;
-  uint32_t uwbsLc = 0;
-  uint8_t * pUwbsDeviceInfo = NULL;
-  uint16_t pUwbsDeviceInfoLen = 0;
-  uint8_t getDeviceInfostatus = UWBSTATUS_FAILED;
-  NXPLOG_UCIHAL_D("phNxpUciHal_parseUWBSLifecycle enter ....");
-
-  pUwbsDeviceInfo = (uint8_t*)malloc(sizeof(uint8_t) * rx_data_len);
-  if(pUwbsDeviceInfo == NULL) {
-    NXPLOG_UCIHAL_E("pUwbsDeviceInfo memory allocation failed");
-    return uwbsLc;
-  }
-  memcpy(&pUwbsDeviceInfo[0], &p_rx_data[0], rx_data_len);
-  pUwbsDeviceInfoLen = rx_data_len ;
-  getDeviceInfostatus = pUwbsDeviceInfo[index++];
-  NXPLOG_UCIHAL_D("getDeviceInfostatus %d" , getDeviceInfostatus);
-  if(getDeviceInfostatus == UWBSTATUS_SUCCESS)
-  {
-    index = index + UWB_INDEX_TO_RETRIEVE_PARAMS;
-    uint8_t parameterLength = pUwbsDeviceInfo[index++];
-    if (parameterLength > 0) {
-      do {
-          paramId = pUwbsDeviceInfo[index++];
-          length = pUwbsDeviceInfo[index++];
-          if ((paramId == UWBS_LIFECYCLE) && (length == UWBS_LIFECYCLE_LENGTH)) {
-            uwbsLc = (pUwbsDeviceInfo[index] | (pUwbsDeviceInfo[index+1] << 8) | (pUwbsDeviceInfo[index+2] <<16) | (pUwbsDeviceInfo[index+3] <<24));
-            break;
-          } else {
-            index = index + length;
-          }
-      } while(index < pUwbsDeviceInfoLen);
-    }
-  }
-  NXPLOG_UCIHAL_D("UWBS Lifecycle: 0x%x", uwbsLc);
-  free(pUwbsDeviceInfo);
-  return uwbsLc;
-}
-
-/******************************************************************************
- * Function         phNxpUciHal_sendSetCoreConfigurations
- *
- * Description      This function send Core device Config command.
- *
- * Returns          status.
- *
- ******************************************************************************/
-static uint8_t phNxpUciHal_sendSetCoreConfigurations(){
-  /* Disable Low power mode */
-  const uint8_t setCoreConfigurations[] = {0x20, 0x04, 0x00, 0x04, 0x01, 0x01, 0x01, 0x00};
-  tHAL_UWB_STATUS status = phNxpUciHal_send_ext_cmd(sizeof(setCoreConfigurations), setCoreConfigurations);
-  if(status != UWBSTATUS_SUCCESS) {
-    return status;
-  }
-  return status;
-}
-
-/******************************************************************************
- * Function         phNxpUciHal_sendGetDeviceCapInfo
- *
- * Description      This function send Device Caps Info command.
- *
- * Returns          status.
- *
- ******************************************************************************/
-static uint8_t phNxpUciHal_sendGetDeviceCapInfo(){
-  const uint8_t buffer[] = {0x20, 0x03, 0x00, 0x00};
-  tHAL_UWB_STATUS status = phNxpUciHal_send_ext_cmd(sizeof(buffer), buffer);
-  if(status != UWBSTATUS_SUCCESS) {
-    return status;
-  }
-  return status;
-}
-
-/******************************************************************************
- * Function         phNxpUciHal_setSecureConfig
- *
- * Description      This function set secure calibration parameters from config file.
- *
- * Returns          tHAL_UWB_STATUS.
- *
- ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_setSecureConfig() {
-  NXPLOG_UCIHAL_D(" phNxpUciHal_setSecureConfig Enter..");
-  std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
-  uint8_t* vendorConfig = NULL;
-  tHAL_UWB_STATUS status;
-  buffer.fill(0);
-  long retlen = 0;
-  // Apply secure calibration
-  for(int i = 1;i <= 10;i++) {
-    std::string str = NAME_NXP_SECURE_CONFIG_BLK;
-    std::string value = std::to_string(i);
-    std::string name = str + value;
-    NXPLOG_UCIHAL_D(" phNxpUciHal_setSecureConfig :: Name of the config block is %s", name.c_str());
-    if (GetNxpConfigByteArrayValue(name.c_str(), (char*)buffer.data(), buffer.size(), &retlen)) {
-      if ((retlen > 0) && (retlen <= UCI_MAX_DATA_LEN)) {
-        vendorConfig = buffer.data();
-        status = phNxpUciHal_send_ext_cmd(retlen,vendorConfig);
-        NXPLOG_UCIHAL_D(" phNxpUciHal_send_ext_cmd :: status value for %s is %d ", name.c_str(),status);
-        if(status != UWBSTATUS_SUCCESS) {
-          NXPLOG_UCIHAL_D(" phNxpUciHal_send_ext_cmd :: setting %s is failed ", name.c_str());
-          //skip returning error and go ahead with remaining blocks
-          continue;
-        }
-      }
-    } else {
-      NXPLOG_UCIHAL_D(" phNxpUciHal_setSecureConfig::%s not available in the config file", name.c_str());
-    }
-  }
-  return UWBSTATUS_SUCCESS;
-}
-
-/******************************************************************************
- * Function         phNxpUciHal_getPlatformId
- *
- * Description      This function use to get platform ID.
- *
- * Returns          tHAL_UWB_STATUS.
- *
- ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_getPlatformId() {
-  NXPLOG_UCIHAL_D(" phNxpUciHal_getPlatformId Enter..");
-  const uint8_t buffer[] = {0x2F, EXT_UCI_MSG_GET_CALIBRATION, 0x00, 0x02, 0x00, UCI_CALIB_PARAM_PLATFORM_ID};
-  uwb_get_platform_id = true;
-  tHAL_UWB_STATUS status = phNxpUciHal_send_ext_cmd(sizeof(buffer), buffer);
-  if(status != UWBSTATUS_SUCCESS) {
-    return status;
-  }
-  return UWBSTATUS_SUCCESS;
-}
-
-/******************************************************************************
- * Function         phNxpUciHal_setPlatformId
- *
- * Description      This function set platform ID given in config file.
- *
- * Returns          tHAL_UWB_STATUS.
- *
- ******************************************************************************/
-tHAL_UWB_STATUS phNxpUciHal_setPlatformId() {
-  NXPLOG_UCIHAL_D(" phNxpUciHal_setPlatformId Enter..");
-  uint8_t *platformId = NULL;
-  uint8_t buffer[UCI_MAX_DATA_LEN] = {0x00};
-  tHAL_UWB_STATUS status;
-
-  platformId = (uint8_t *)malloc(NXP_MAX_CONFIG_STRING_LEN * sizeof(uint8_t));
-  if (platformId == NULL) {
-    NXPLOG_FWDNLD_E("malloc of platformId failed ");
-    return UWBSTATUS_FAILED;
-  }
-
-  if (GetNxpConfigStrValue(NAME_PLATFORM_ID, (char *)platformId, NXP_MAX_CONFIG_STRING_LEN)) {
-    int platformIdLen = strlen((char*)platformId);
-    NXPLOG_UCIHAL_D(" %s Platform ID: %s",__func__, platformId);
-    buffer[0] = 0x2F;
-    buffer[1] = EXT_UCI_MSG_SET_CALIBRATION;
-    buffer[2] = 0x00;
-    buffer[3] = platformIdLen + 3; //payload (channelid+calibparam+length+calibValue)
-    buffer[4] = 0x00; //channel id
-    buffer[5] = UCI_CALIB_PARAM_PLATFORM_ID;
-    buffer[6] = platformIdLen;
-    for(int i = 0 ; i < platformIdLen ; i++)
-    {
-      buffer[7 + i] = platformId[i];
-    }
-    int cmdLen = buffer[3] + UCI_MSG_HDR_SIZE;
-
-    status = phNxpUciHal_send_ext_cmd(cmdLen,buffer);
-    NXPLOG_UCIHAL_D(" phNxpUciHal_send_ext_cmd :: status value for PLATFORM_ID is %d ", status);
-  } else {
-    NXPLOG_UCIHAL_D(" %s :: PLATFORM_ID not available in the config file", __func__);
-    status = UWBSTATUS_FAILED;
-  }
-
-  if (platformId != NULL) {
-      free(platformId);
-  }
-  return status;
-}
-
-tHAL_UWB_STATUS phNxpUciHal_start_lcfwdl_thread() {
-  NXPLOG_UCIHAL_D("phNxpUciHal_start_lcfwdl_thread enter....");
-
-  nxpucihal_lcfwdl_ctrl.rcv_data_len = nxpucihal_ctrl.rx_data_len;
-  memcpy(&nxpucihal_lcfwdl_ctrl.rcv_data[0], nxpucihal_ctrl.p_rx_data, nxpucihal_lcfwdl_ctrl.rcv_data_len);
-
-  CONCURRENCY_LOCK();
-  pthread_attr_init(&nxpucihal_lcfwdl_ctrl.attr_thread);
-  pthread_attr_setdetachstate(&nxpucihal_lcfwdl_ctrl.attr_thread, PTHREAD_CREATE_DETACHED);
-  if (pthread_create(&nxpucihal_lcfwdl_ctrl.lcfwdl_tread, &nxpucihal_lcfwdl_ctrl.attr_thread,
-               phNxpUciHal_lcfwdl_thread, &nxpucihal_lcfwdl_ctrl) != 0) {
-    NXPLOG_UCIHAL_E("pthread_create failed");
-    CONCURRENCY_UNLOCK();
-    return UWBSTATUS_FAILED;
-  }
-  CONCURRENCY_UNLOCK();
-  return UWBSTATUS_SUCCESS;
-}
-
-static tHAL_UWB_STATUS phNxpUciHal_performLcRotation() {
-  tHAL_UWB_STATUS status = UWBSTATUS_FAILED;
-  uint8_t fwd_retry_count = 0;
-
-  phTmlUwb_Spi_Reset();
-  NXPLOG_UCIHAL_D(" Start LC rotation FW download");
-  /* Create the local semaphore */
-  if (phNxpUciHal_init_cb_data(&nxpucihal_ctrl.dev_status_ntf_wait, NULL) !=
-      UWBSTATUS_SUCCESS) {
-    NXPLOG_UCIHAL_E("Create dev_status_ntf_wait failed");
-    return status;
-  }
-
-  uwb_device_initialized = false;
-fwd_retry:
-      nxpucihal_ctrl.fw_dwnld_mode = true; /* system in FW download mode*/
-      nxpucihal_ctrl.uwbc_device_state = UWB_DEVICE_STATE_UNKNOWN;
-      status = phNxpUciHal_fw_lcrotation();
-      if(status == UWBSTATUS_SUCCESS) {
-          nxpucihal_ctrl.isSkipPacket = 1;
-          status = phTmlUwb_Read( Rx_buffer, UCI_MAX_DATA_LEN,
-                    (pphTmlUwb_TransactCompletionCb_t)&phNxpUciHal_read_complete, NULL);
-          if (status != UWBSTATUS_PENDING) {
-            NXPLOG_UCIHAL_E("read status error status = %x", status);
-            goto failure;
-          }
-          phNxpUciHal_sem_timed_wait(&nxpucihal_ctrl.dev_status_ntf_wait);
-          if (nxpucihal_ctrl.dev_status_ntf_wait.status != UWBSTATUS_SUCCESS) {
-            NXPLOG_UCIHAL_E("UWB_DEVICE_READY dev_status_ntf_wait semaphore timed out");
-            goto failure;
-          }
-          NXPLOG_UCIHAL_D("uwbc_device_state: %d",nxpucihal_ctrl.uwbc_device_state);
-          if(nxpucihal_ctrl.uwbc_device_state != UWB_DEVICE_READY) {
-            NXPLOG_UCIHAL_E("UWB_DEVICE_READY not received uwbc_device_state = %x",nxpucihal_ctrl.uwbc_device_state);
-            goto failure;
-          }
-          nxpucihal_ctrl.isSkipPacket = 0;
-          status = phNxpUciHal_set_board_config();
-          if (status != UWBSTATUS_SUCCESS) {
-            NXPLOG_UCIHAL_E("%s: Set Board Config Failed", __func__);
-            goto failure;
-          }
-          phNxpUciHal_sem_timed_wait(&nxpucihal_ctrl.dev_status_ntf_wait);
-          if (nxpucihal_ctrl.dev_status_ntf_wait.status != UWBSTATUS_SUCCESS) {
-            NXPLOG_UCIHAL_E("UWB_DEVICE_READY dev_status_ntf_wait semaphore timed out");
-            goto failure;
-          }
-          if(nxpucihal_ctrl.uwbc_device_state != UWB_DEVICE_READY) {
-            NXPLOG_UCIHAL_E("UWB_DEVICE_READY not received uwbc_device_state = %x",nxpucihal_ctrl.uwbc_device_state);
-            goto failure;
-          }
-          NXPLOG_UCIHAL_D("%s: Send device reset", __func__);
-          status = phNxpUciHal_uwb_reset();
-          if (status != UWBSTATUS_SUCCESS) {
-            NXPLOG_UCIHAL_E("%s: device reset Failed", __func__);
-            goto failure;
-          }
-          phNxpUciHal_sem_timed_wait(&nxpucihal_ctrl.dev_status_ntf_wait);
-          if (nxpucihal_ctrl.dev_status_ntf_wait.status != UWBSTATUS_SUCCESS) {
-            NXPLOG_UCIHAL_E("UWB_DEVICE_READY dev_status_ntf_wait semaphore timed out");
-            goto failure;
-          }
-          if(nxpucihal_ctrl.uwbc_device_state != UWB_DEVICE_READY) {
-            NXPLOG_UCIHAL_E("UWB_DEVICE_READY not received uwbc_device_state = %x",nxpucihal_ctrl.uwbc_device_state);
-            goto failure;
-          }
-
-          status = phNxpUciHal_applyVendorConfig();
-          if (status != UWBSTATUS_SUCCESS) {
-            // If vendor config is failed after LC rotation , as of now skip reporting error
-            NXPLOG_UCIHAL_E("%s: Apply vendor Config Failed", __func__);
-          }
-
-          status = phNxpUciHal_setSecureConfig();
-          if (status != UWBSTATUS_SUCCESS) {
-            // If set secure calib param failed , as of now skip reporting error
-            NXPLOG_UCIHAL_E("%s: Apply secure Config Failed", __func__);
-          }
-
-          status = phNxpUciHal_sendGetCoreDeviceInfo();
-          if (status != UWBSTATUS_SUCCESS) {
-            NXPLOG_UCIHAL_E("%s: phNxpUciHal_sendGetCoreDeviceInfo Failed", __func__);
-            goto failure;
-          }
-
-          status = phNxpUciHal_sendSetCoreConfigurations();
-          if (status != UWBSTATUS_SUCCESS) {
-            NXPLOG_UCIHAL_E("%s: phNxpUciHal_setCoreConfigurations Failed", __func__);
-            goto failure;
-          }
-          status = phNxpUciHal_sendGetDeviceCapInfo();
-          if (status != UWBSTATUS_SUCCESS) {
-            NXPLOG_UCIHAL_E("%s: phNxpUciHal_sendGetDeviceCapInfo Failed", __func__);
-            goto failure;
-          }
-          uwb_device_initialized = true;
-      } else if(status == UWBSTATUS_FILE_NOT_FOUND) {
-        NXPLOG_UCIHAL_E("FW download File Not found: status= %x", status);
-        goto failure;
-      } else {
-        NXPLOG_UCIHAL_E("FW download is failed FW download recovery starts: status= %x", status);
-        fwd_retry_count++;
-          if(fwd_retry_count <= FWD_MAX_RETRY_COUNT) {
-            phTmlUwb_Chip_Reset();
-            usleep(5000);
-            goto fwd_retry;
-          } else {
-            goto failure;
-          }
-      }
-      phNxpUciHal_cleanup_cb_data(&nxpucihal_ctrl.dev_status_ntf_wait);
-      return status;
-    failure:
-        if(nxpucihal_ctrl.uwbc_device_state == UWB_DEVICE_ERROR) {
-          phNxpUciHalProp_dump_fw_crash_log();
-          if (UWBSTATUS_SUCCESS != phNxpUciHal_uwb_reset()) {
-            NXPLOG_UCIHAL_E("%s: device reset Failed", __func__);
-          } else {
-            NXPLOG_UCIHAL_E("%s: device reset success", __func__);
-          }
-          phTmlUwb_Spi_Reset();
-          goto fwd_retry;
-        }
-        phNxpUciHal_cleanup_cb_data(&nxpucihal_ctrl.dev_status_ntf_wait);
-
-        return UWBSTATUS_FAILED;
-}
-
-#endif
\ No newline at end of file
diff --git a/halimpl/hal/sr200/phNxpUciHal_LC.h b/halimpl/hal/sr200/phNxpUciHal_LC.h
deleted file mode 100644
index 077b8a1..0000000
--- a/halimpl/hal/sr200/phNxpUciHal_LC.h
+++ /dev/null
@@ -1,59 +0,0 @@
-/*
- * Copyright 2012-2020, 2023 NXP
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
-#ifndef _PHNXPUCIHAL_LC_H_
-#define _PHNXPUCIHAL_LC_H_
-
-#include <phNxpUciHal.h>
-
-/* Macros for parsing GetDeviceInfo response */
-#define UWB_INDEX_TO_RETRIEVE_PARAMS 0x08
-#define UWBS_LIFECYCLE 0x06
-#define UWBS_LIFECYCLE_LENGTH 0x04
-
-/* LC Rotation data structure */
-typedef struct {
-  pthread_attr_t attr_thread;
-  pthread_t lcfwdl_tread;      /* lcfwdl thread handle */
-  uint8_t lcfwdl_thread_running;
-  /* Rx data */
-  uint8_t rcv_data[100];
-  uint16_t rcv_data_len;
-  /* To check LC rotation process*/
-  uint8_t isLcRotationOngoing;
-  /* UWBs device lifecycle */
-  uint32_t uwbsDeviceLc;
-  /* To check platformId */
-  bool isPlatformIdSet;
-  /* Platform ID */
-  uint8_t uwbsPlatformId[NXP_MAX_CONFIG_STRING_LEN];
-}phNxpUciHal_lcfwdl_Control_t;
-
-#define UWBS_LC_DEVELOPMENT_MODE  0xC5C5C5C5
-#define UWBS_LC_CUSTOMER_MODE     0xA5A5A5A5
-#define UWBS_LC_PROTECTED_MODE    0x55555555
-
-extern phNxpUciHal_lcfwdl_Control_t nxpucihal_lcfwdl_ctrl;
-
-extern int phNxpUciHal_fw_lcrotation();
-tHAL_UWB_STATUS phNxpUciHal_start_lcfwdl_thread();
-uint32_t phNxpUciHal_parseUWBSLifecycle(uint8_t * p_rx_data , uint16_t rx_data_len);
-void phNxpUciHal_parsePlatformId(uint8_t * p_rx_data , uint16_t rx_data_len);
-tHAL_UWB_STATUS phNxpUciHal_getPlatformId();
-tHAL_UWB_STATUS phNxpUciHal_setPlatformId();
-tHAL_UWB_STATUS phNxpUciHal_setSecureConfig();
-
-#endif
diff --git a/halimpl/hal/sr200/phNxpUciHal_fwd_utils.h b/halimpl/hal/sr200/phNxpUciHal_fwd_utils.h
deleted file mode 100644
index 4b07a4e..0000000
--- a/halimpl/hal/sr200/phNxpUciHal_fwd_utils.h
+++ /dev/null
@@ -1,56 +0,0 @@
-/*
- * Copyright 2022-2023 NXP
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
-#include <stdint.h>
-#include <stdio.h>
-
-#define __PACKED__ __attribute__((packed))
-
-#define MWCESFW_COUNT 0x08
-
-#define MWCESFW_A1V1_FW_OFFSET              0x00
-#define MWCESFW_A1V1_RECOVERY_FW_OFFSET     0x01
-#define MWCESFW_A1V2_FW_OFFSET              0x02
-#define MWCESFW_A1V2_RECOVERY_FW_OFFSET     0x03
-#define MWCESFW_A1V1_LC_FW_OFFSET           0x04
-#define MWCESFW_A1V2_LC_FW_OFFSET           0x05
-
-typedef struct __PACKED__ MWCESFW
-{
-  uint32_t layout_version;
-  uint8_t fw_ver_major;
-  uint8_t fw_ver_minor;
-  uint8_t fw_ver_dev;
-  uint8_t fw_ver_is_to;
-  uint8_t fw_ver_git_sha1[32];
-  uint32_t fw_artifact_number;
-  uint32_t lenCESFW;
-  uint8_t *pCESFW;
-} MWCESFW_t;
-
-typedef struct __PACKED__ UWBManifest
-{
-  uint32_t layout_version;
-  uint8_t creation_date_yy;
-  uint8_t creation_date_month;
-  uint8_t creation_date_day;
-  uint8_t creation_date_hour;
-  uint8_t creation_date_minutes;
-  uint8_t creation_date_seconds;
-  uint8_t padding;
-  uint8_t countMWCESFW;
-  MWCESFW_t *mwCESFW[MWCESFW_COUNT];
-} UWBManifest_t;
diff --git a/halimpl/inc/phNxpUciHal_Adaptation.h b/halimpl/inc/phNxpUciHal_Adaptation.h
index 3cc77d9..94eff2c 100644
--- a/halimpl/inc/phNxpUciHal_Adaptation.h
+++ b/halimpl/inc/phNxpUciHal_Adaptation.h
@@ -34,12 +34,12 @@ typedef void(uwb_stack_callback_t)(uwb_event_t event,
  * The callback passed in from the UWB stack that the HAL
  * can use to pass incomming data to the stack.
  */
-typedef void(uwb_stack_data_callback_t)(uint16_t data_len, uint8_t* p_data);
+typedef void(uwb_stack_data_callback_t)(uint16_t data_len, const uint8_t* p_data);
 
 /* NXP HAL functions */
 uint16_t phNxpUciHal_open(uwb_stack_callback_t* p_cback,
                      uwb_stack_data_callback_t* p_data_cback);
-uint16_t phNxpUciHal_write(uint16_t data_len, const uint8_t* p_data);
+int32_t phNxpUciHal_write(size_t data_len, const uint8_t* p_data);
 uint16_t phNxpUciHal_close();
 uint16_t phNxpUciHal_coreInitialization();
 uint16_t phNxpUciHal_sessionInitialization(uint32_t sessionId);
diff --git a/halimpl/tml/phTmlUwb.cc b/halimpl/tml/phTmlUwb.cc
index 7025e2a..5f27afb 100644
--- a/halimpl/tml/phTmlUwb.cc
+++ b/halimpl/tml/phTmlUwb.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright 2012-2020 NXP
+ * Copyright 2012-2020, 2024 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -35,8 +35,57 @@ extern phNxpUciHal_Control_t nxpucihal_ctrl;
 /* Indicates a Initial or offset value */
 #define PH_TMLUWB_VALUE_ONE (0x01)
 
-/* Initialize Context structure pointer used to access context structure */
-static phTmlUwb_Context_t* gpphTmlUwb_Context;
+namespace {
+
+// Structure containing details related to read and write operations
+struct phTmlUwb_ReadInfo {
+  volatile bool bThreadShouldStop;
+  volatile bool bThreadRunning;
+  uint8_t
+      bThreadBusy; /*Flag to indicate thread is busy on respective operation */
+  /* Transaction completion Callback function */
+  ReadCallback* pThread_Callback;
+  void* pContext;        /*Context passed while invocation of operation */
+  uint8_t* pBuffer;      /*Buffer passed while invocation of operation */
+  size_t wLength;      /*Length of data read/written */
+  tHAL_UWB_STATUS wWorkStatus; /*Status of the transaction performed */
+};
+
+struct phTmlUwb_WriteInfo {
+  volatile bool bThreadShouldStop;
+  volatile bool bThreadRunning;
+  uint8_t
+      bThreadBusy; /*Flag to indicate thread is busy on respective operation */
+  /* Transaction completion Callback function */
+  WriteCallback* pThread_Callback;
+  void* pContext;        /*Context passed while invocation of operation */
+  const uint8_t* pBuffer;      /*Buffer passed while invocation of operation */
+  size_t wLength;      /*Length of data read/written */
+  tHAL_UWB_STATUS wWorkStatus; /*Status of the transaction performed */
+};
+
+// Base Context Structure containing members required for entire session
+struct phTmlUwb_Context {
+  pthread_t readerThread;
+  pthread_t writerThread;
+
+  phTmlUwb_ReadInfo tReadInfo;  /*Pointer to Reader Thread Structure */
+  phTmlUwb_WriteInfo tWriteInfo; /*Pointer to Writer Thread Structure */
+  void* pDevHandle;                    /* Pointer to Device Handle */
+  std::shared_ptr<MessageQueue<phLibUwb_Message>> pClientMq; /* Pointer to Client thread message queue */
+  sem_t rxSemaphore;
+  sem_t txSemaphore;      /* Lock/Acquire txRx Semaphore */
+
+  pthread_cond_t wait_busy_condition; /*Condition to wait reader thread*/
+  pthread_mutex_t wait_busy_lock;     /*Condition lock to wait reader thread*/
+  volatile uint8_t wait_busy_flag;    /*Condition flag to wait reader thread*/
+  volatile uint8_t gWriterCbflag;    /* flag to indicate write callback message is pushed to
+                           queue*/
+};
+
+std::unique_ptr<phTmlUwb_Context> gpphTmlUwb_Context;
+
+}   // namespace
 
 /* Local Function prototypes */
 static tHAL_UWB_STATUS phTmlUwb_StartWriterThread(void);
@@ -77,68 +126,52 @@ static int phTmlUwb_WaitReadInit(void);
 **                                             been disconnected
 **
 *******************************************************************************/
-tHAL_UWB_STATUS phTmlUwb_Init(const char* pDevName, std::shared_ptr<MessageQueue<phLibUwb_Message>> pClientMq)
+tHAL_UWB_STATUS phTmlUwb_Init(const char* pDevName,
+    std::shared_ptr<MessageQueue<phLibUwb_Message>> pClientMq)
 {
-  tHAL_UWB_STATUS wInitStatus = UWBSTATUS_SUCCESS;
+  if (gpphTmlUwb_Context != nullptr) {
+    return PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_ALREADY_INITIALISED);
+  }
 
-  /* Check if TML layer is already Initialized */
-  if (NULL != gpphTmlUwb_Context) {
-    /* TML initialization is already completed */
-    wInitStatus = PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_ALREADY_INITIALISED);
+  if (!pDevName || !pClientMq) {
+    return PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_INVALID_PARAMETER);
   }
-  /* Validate Input parameters */
-  else if (!pDevName || !pClientMq) {
-    /*Parameters passed to TML init are wrong */
-    wInitStatus = PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_INVALID_PARAMETER);
-  } else {
-    /* Allocate memory for TML context */
-    gpphTmlUwb_Context =
-        (phTmlUwb_Context_t*)malloc(sizeof(phTmlUwb_Context_t));
 
-    if (NULL == gpphTmlUwb_Context) {
-      wInitStatus = PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_FAILED);
-    } else {
-      /* Initialise all the internal TML variables */
-      memset(gpphTmlUwb_Context, PH_TMLUWB_RESET_VALUE,
-             sizeof(phTmlUwb_Context_t));
+  // Allocate memory for TML context
+  gpphTmlUwb_Context = std::make_unique<phTmlUwb_Context>();
+  if (gpphTmlUwb_Context == nullptr) {
+    return PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_FAILED);
+  }
 
-      /* Open the device file to which data is read/written */
-      wInitStatus = phTmlUwb_spi_open_and_configure(pDevName, &(gpphTmlUwb_Context->pDevHandle));
+  // Open the device file to which data is read/written
+  tHAL_UWB_STATUS wInitStatus =
+    phTmlUwb_spi_open_and_configure(pDevName, &(gpphTmlUwb_Context->pDevHandle));
+  if (UWBSTATUS_SUCCESS != wInitStatus) {
+    gpphTmlUwb_Context->pDevHandle = NULL;
+    return PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_INVALID_DEVICE);
+  }
 
-      if (UWBSTATUS_SUCCESS != wInitStatus) {
-        wInitStatus = PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_INVALID_DEVICE);
-        gpphTmlUwb_Context->pDevHandle = NULL;
-      } else {
-        gpphTmlUwb_Context->tWriteInfo.bThreadBusy = false;
-        gpphTmlUwb_Context->pClientMq = pClientMq;
-
-        setDeviceHandle(gpphTmlUwb_Context->pDevHandle);  // To set device handle for FW download usecase
-
-        if (0 != sem_init(&gpphTmlUwb_Context->rxSemaphore, 0, 0)) {
-          wInitStatus = UWBSTATUS_FAILED;
-        } else if (0 != sem_init(&gpphTmlUwb_Context->txSemaphore, 0, 0)) {
-          wInitStatus = UWBSTATUS_FAILED;
-        } else if(0 != phTmlUwb_WaitReadInit()) {
-           wInitStatus = UWBSTATUS_FAILED;
-        } else {
-          /* Start TML thread (to handle write and read operations) */
-          if (UWBSTATUS_SUCCESS != phTmlUwb_StartWriterThread()) {
-            wInitStatus = PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_FAILED);
-          } else {
-            /* Store the Thread Identifier to which Message is to be posted */
-            wInitStatus = UWBSTATUS_SUCCESS;
-          }
-        }
-      }
-    }
+  gpphTmlUwb_Context->tWriteInfo.bThreadBusy = false;
+  gpphTmlUwb_Context->pClientMq = pClientMq;
+
+  setDeviceHandle(gpphTmlUwb_Context->pDevHandle);  // To set device handle for FW download usecase
+
+  if (sem_init(&gpphTmlUwb_Context->rxSemaphore, 0, 0)) {
+    return UWBSTATUS_FAILED;
   }
-  /* Clean up all the TML resources if any error */
-  if (UWBSTATUS_SUCCESS != wInitStatus) {
-    /* Clear all handles and memory locations initialized during init */
-    phTmlUwb_CleanUp();
+  if (sem_init(&gpphTmlUwb_Context->txSemaphore, 0, 0)) {
+    return UWBSTATUS_FAILED;
+  }
+  if(phTmlUwb_WaitReadInit()) {
+    return UWBSTATUS_FAILED;
+  }
+
+  // Start TML thread (to handle write and read operations)
+  if (UWBSTATUS_SUCCESS != phTmlUwb_StartWriterThread()) {
+    return PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_FAILED);
   }
 
-  return wInitStatus;
+  return UWBSTATUS_SUCCESS;
 }
 
 /*******************************************************************************
@@ -157,7 +190,7 @@ static void* phTmlUwb_TmlReaderThread(void* pParam)
   UNUSED(pParam);
 
   /* Transaction info buffer to be passed to Callback Thread */
-  static phTmlUwb_TransactInfo_t tTransactionInfo;
+  static phTmlUwb_ReadTransactInfo tTransactionInfo;
   /* Structure containing Tml callback function and parameters to be invoked
      by the callback thread */
   static phLibUwb_DeferredCall_t tDeferredInfo;
@@ -184,7 +217,7 @@ static void* phTmlUwb_TmlReaderThread(void* pParam)
     NXPLOG_TML_V("TmlReader:  Invoking SPI Read");
 
     uint8_t temp[UCI_MAX_DATA_LEN];
-    int32_t dwNoBytesWrRd =
+    int dwNoBytesWrRd =
         phTmlUwb_spi_read(gpphTmlUwb_Context->pDevHandle, temp, UCI_MAX_DATA_LEN);
 
     if(gpphTmlUwb_Context->tReadInfo.bThreadShouldStop) {
@@ -206,7 +239,7 @@ static void* phTmlUwb_TmlReaderThread(void* pParam)
       NXPLOG_TML_V("TmlReader: SPI Read successful");
 
       /* Update the actual number of bytes read including header */
-      gpphTmlUwb_Context->tReadInfo.wLength = (uint16_t)(dwNoBytesWrRd);
+      gpphTmlUwb_Context->tReadInfo.wLength = dwNoBytesWrRd;
 
       dwNoBytesWrRd = PH_TMLUWB_RESET_VALUE;
 
@@ -225,13 +258,18 @@ static void* phTmlUwb_TmlReaderThread(void* pParam)
       tDeferredInfo.pParameter = &tTransactionInfo;
 
       /* TML reader writer callback synchronization mutex lock --- START */
-      pthread_mutex_lock(&gpphTmlUwb_Context->wait_busy_lock);
+      if (pthread_mutex_lock(&gpphTmlUwb_Context->wait_busy_lock)) {
+        NXPLOG_TML_E("[%s] Mutex lock failed for wait_busy_lock at line: %d", __func__, __LINE__);
+      }
+
       if ((gpphTmlUwb_Context->gWriterCbflag == false) &&
         ((gpphTmlUwb_Context->tReadInfo.pBuffer[0] & 0x60) != 0x60)) {
         phTmlUwb_WaitWriteComplete();
       }
       /* TML reader writer callback synchronization mutex lock --- END */
-      pthread_mutex_unlock(&gpphTmlUwb_Context->wait_busy_lock);
+      if (pthread_mutex_unlock(&gpphTmlUwb_Context->wait_busy_lock)) {
+        NXPLOG_TML_E("[%s] Mutex unlock failed for wait_busy_lock at line: %d", __func__, __LINE__);
+      }
 
       auto msg = std::make_shared<phLibUwb_Message>(PH_LIBUWB_DEFERREDCALL_MSG, &tDeferredInfo);
       phTmlUwb_DeferredCall(msg);
@@ -260,7 +298,7 @@ static void* phTmlUwb_TmlWriterThread(void* pParam)
   UNUSED(pParam);
 
   /* Transaction info buffer to be passed to Callback Thread */
-  static phTmlUwb_TransactInfo_t tTransactionInfo;
+  static phTmlUwb_WriteTransactInfo tTransactionInfo;
   /* Structure containing Tml callback function and parameters to be invoked
      by the callback thread */
   static phLibUwb_DeferredCall_t tDeferredInfo;
@@ -291,14 +329,18 @@ static void* phTmlUwb_TmlWriterThread(void* pParam)
 
     /* TML reader writer callback synchronization mutex lock --- START
       */
-    pthread_mutex_lock(&gpphTmlUwb_Context->wait_busy_lock);
+    if (pthread_mutex_lock(&gpphTmlUwb_Context->wait_busy_lock)) {
+      NXPLOG_TML_E("[%s] Mutex lock failed for wait_busy_lock at line: %d", __func__, __LINE__);
+    }
     gpphTmlUwb_Context->gWriterCbflag = false;
     int32_t dwNoBytesWrRd =
         phTmlUwb_spi_write(gpphTmlUwb_Context->pDevHandle,
                             gpphTmlUwb_Context->tWriteInfo.pBuffer,
                             gpphTmlUwb_Context->tWriteInfo.wLength);
     /* TML reader writer callback synchronization mutex lock --- END */
-    pthread_mutex_unlock(&gpphTmlUwb_Context->wait_busy_lock);
+    if (pthread_mutex_unlock(&gpphTmlUwb_Context->wait_busy_lock)) {
+      NXPLOG_TML_E("[%s] Mutex unlock failed for wait_busy_lock at line: %d", __func__, __LINE__);
+    }
 
     /* Try SPI Write Five Times, if it fails :*/
     if (-1 == dwNoBytesWrRd) {
@@ -320,7 +362,7 @@ static void* phTmlUwb_TmlWriterThread(void* pParam)
      */
     tTransactionInfo.wStatus = wStatus;
     tTransactionInfo.pBuff = gpphTmlUwb_Context->tWriteInfo.pBuffer;
-    tTransactionInfo.wLength = (uint16_t)dwNoBytesWrRd;
+    tTransactionInfo.wLength = dwNoBytesWrRd;
 
     /* Prepare the message to be posted on the User thread */
     tDeferredInfo.pCallback = &phTmlUwb_WriteDeferredCb;
@@ -332,11 +374,15 @@ static void* phTmlUwb_TmlWriterThread(void* pParam)
     if (UWBSTATUS_SUCCESS == wStatus) {
       /* TML reader writer callback synchronization mutex lock --- START
           */
-      pthread_mutex_lock(&gpphTmlUwb_Context->wait_busy_lock);
+      if (pthread_mutex_lock(&gpphTmlUwb_Context->wait_busy_lock)) {
+        NXPLOG_TML_E("[%s] Mutex lock failed for wait_busy_lock at line: %d", __func__, __LINE__);
+      }
       gpphTmlUwb_Context->gWriterCbflag = true;
       phTmlUwb_SignalWriteComplete();
         /* TML reader writer callback synchronization mutex lock --- END */
-      pthread_mutex_unlock(&gpphTmlUwb_Context->wait_busy_lock);
+      if (pthread_mutex_unlock(&gpphTmlUwb_Context->wait_busy_lock)) {
+        NXPLOG_TML_E("[%s] Mutex unlock failed for wait_busy_lock at line: %d", __func__, __LINE__);
+      }
     }
   } /* End of While loop */
 
@@ -358,26 +404,27 @@ static void* phTmlUwb_TmlWriterThread(void* pParam)
 **
 *******************************************************************************/
 static void phTmlUwb_CleanUp(void) {
-  if (NULL == gpphTmlUwb_Context) {
+  if (gpphTmlUwb_Context == nullptr) {
     return;
   }
+
   if (NULL != gpphTmlUwb_Context->pDevHandle) {
     (void)phTmlUwb_Spi_Ioctl(gpphTmlUwb_Context->pDevHandle, phTmlUwb_ControlCode_t::SetPower, 0);
   }
 
   sem_destroy(&gpphTmlUwb_Context->rxSemaphore);
   sem_destroy(&gpphTmlUwb_Context->txSemaphore);
-  pthread_mutex_destroy(&gpphTmlUwb_Context->wait_busy_lock);
-  pthread_cond_destroy(&gpphTmlUwb_Context->wait_busy_condition);
+  if (pthread_mutex_destroy(&gpphTmlUwb_Context->wait_busy_lock)) {
+    NXPLOG_TML_E("[%s] Failed to destroy mutex 'wait_busy_lock' at line: %d", __func__, __LINE__);
+  }
+  if (pthread_cond_destroy(&gpphTmlUwb_Context->wait_busy_condition)) {
+    NXPLOG_TML_E("[%s] Failed to destroy conditional variable 'wait_busy_condition' at line: %d",
+        __func__, __LINE__);
+  }
   phTmlUwb_spi_close(gpphTmlUwb_Context->pDevHandle);
   gpphTmlUwb_Context->pDevHandle = NULL;
 
-  /* Clear memory allocated for storing Context variables */
-  free((void*)gpphTmlUwb_Context);
-  /* Set the pointer to NULL to indicate De-Initialization */
-  gpphTmlUwb_Context = NULL;
-
-  return;
+  gpphTmlUwb_Context.reset();
 }
 
 /*******************************************************************************
@@ -443,8 +490,8 @@ tHAL_UWB_STATUS phTmlUwb_Shutdown(void)
 **                  UWBSTATUS_BUSY - write request is already in progress
 **
 *******************************************************************************/
-tHAL_UWB_STATUS phTmlUwb_Write(uint8_t* pBuffer, uint16_t wLength,
-                         pphTmlUwb_TransactCompletionCb_t pTmlWriteComplete,
+tHAL_UWB_STATUS phTmlUwb_Write(const uint8_t* pBuffer, size_t wLength,
+                         WriteCallback pTmlWriteComplete,
                          void* pContext) {
   tHAL_UWB_STATUS wWriteStatus;
 
@@ -505,16 +552,17 @@ tHAL_UWB_STATUS phTmlUwb_Write(uint8_t* pBuffer, uint16_t wLength,
 **                  UWBSTATUS_BUSY - read request is already in progress
 **
 *******************************************************************************/
-tHAL_UWB_STATUS phTmlUwb_StartRead(uint8_t* pBuffer, uint16_t wLength,
-                        pphTmlUwb_TransactCompletionCb_t pTmlReadComplete,
-                        void* pContext)
+tHAL_UWB_STATUS phTmlUwb_StartRead(ReadCallback pTmlReadComplete, void* pContext)
 {
+  // TODO: move this to gpphTmlUwb_Context
+  static uint8_t shared_rx_buffer[UCI_MAX_DATA_LEN];
+
   /* Check whether TML is Initialized */
   if (!gpphTmlUwb_Context || !gpphTmlUwb_Context->pDevHandle) {
     return PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_NOT_INITIALISED);
   }
 
-  if (!pBuffer || wLength < 1 || !pTmlReadComplete) {
+  if (!pTmlReadComplete) {
     return PHUWBSTVAL(CID_UWB_TML, UWBSTATUS_INVALID_PARAMETER);
   }
 
@@ -523,8 +571,8 @@ tHAL_UWB_STATUS phTmlUwb_StartRead(uint8_t* pBuffer, uint16_t wLength,
   }
 
   /* Setting the flag marks beginning of a Read Operation */
-  gpphTmlUwb_Context->tReadInfo.pBuffer = pBuffer;
-  gpphTmlUwb_Context->tReadInfo.wLength = wLength;
+  gpphTmlUwb_Context->tReadInfo.pBuffer = shared_rx_buffer;
+  gpphTmlUwb_Context->tReadInfo.wLength = sizeof(shared_rx_buffer);
   gpphTmlUwb_Context->tReadInfo.pThread_Callback = pTmlReadComplete;
   gpphTmlUwb_Context->tReadInfo.pContext = pContext;
 
@@ -551,7 +599,9 @@ void phTmlUwb_StopRead()
     phTmlUwb_Spi_Ioctl(gpphTmlUwb_Context->pDevHandle, phTmlUwb_ControlCode_t::SetPower, ABORT_READ_PENDING);
     sem_post(&gpphTmlUwb_Context->rxSemaphore);
 
-    pthread_join(gpphTmlUwb_Context->readerThread, NULL);
+    if (pthread_join(gpphTmlUwb_Context->readerThread, NULL)) {
+      NXPLOG_TML_E("[%s] pthread_join failed for reader thread at line: %d ", __func__, __LINE__);
+    }
   }
 }
 
@@ -604,7 +654,9 @@ static void phTmlUwb_StopWriterThread(void)
   if (gpphTmlUwb_Context->tWriteInfo.bThreadRunning) {
     sem_post(&gpphTmlUwb_Context->txSemaphore);
 
-    pthread_join(gpphTmlUwb_Context->writerThread, NULL);
+    if (pthread_join(gpphTmlUwb_Context->writerThread, NULL)) {
+      NXPLOG_TML_E("[%s] pthread_join failed for writer thread at line: %d ", __func__, __LINE__);
+    }
   }
 }
 
@@ -639,7 +691,7 @@ void phTmlUwb_DeferredCall(std::shared_ptr<phLibUwb_Message> msg)
 static void phTmlUwb_ReadDeferredCb(void* pParams)
 {
   /* Transaction info buffer to be passed to Callback Function */
-  phTmlUwb_TransactInfo_t* pTransactionInfo = (phTmlUwb_TransactInfo_t*)pParams;
+  phTmlUwb_ReadTransactInfo* pTransactionInfo = (phTmlUwb_ReadTransactInfo*)pParams;
 
   /* Reset the flag to accept another Read Request */
   gpphTmlUwb_Context->tReadInfo.pThread_Callback(
@@ -661,7 +713,7 @@ static void phTmlUwb_ReadDeferredCb(void* pParams)
 *******************************************************************************/
 static void phTmlUwb_WriteDeferredCb(void* pParams) {
   /* Transaction info buffer to be passed to Callback Function */
-  phTmlUwb_TransactInfo_t* pTransactionInfo = (phTmlUwb_TransactInfo_t*)pParams;
+  phTmlUwb_WriteTransactInfo* pTransactionInfo = (phTmlUwb_WriteTransactInfo*)pParams;
 
   /* Reset the flag to accept another Write Request */
   gpphTmlUwb_Context->tWriteInfo.bThreadBusy = false;
@@ -739,14 +791,21 @@ static void phTmlUwb_SignalWriteComplete(void) {
 static int phTmlUwb_WaitReadInit(void) {
   int ret;
   pthread_condattr_t attr;
-  pthread_condattr_init(&attr);
-  pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
+  if (pthread_condattr_init(&attr)) {
+    NXPLOG_TML_E(" [%s] conditional attr init failed at line: %d", __func__, __LINE__);
+  }
+  if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC)) {
+    NXPLOG_TML_E(" [%s] conditional attr setClock failed at line: %d", __func__, __LINE__);
+  }
   memset(&gpphTmlUwb_Context->wait_busy_condition, 0,
          sizeof(gpphTmlUwb_Context->wait_busy_condition));
-  pthread_mutex_init(&gpphTmlUwb_Context->wait_busy_lock, NULL);
+  if (pthread_mutex_init(&gpphTmlUwb_Context->wait_busy_lock, NULL)) {
+    NXPLOG_TML_E(" [%s] mutex init failed for wait busy lock at line: %d", __func__,  __LINE__);
+  }
   ret = pthread_cond_init(&gpphTmlUwb_Context->wait_busy_condition, &attr);
   if (ret) {
-    NXPLOG_TML_E(" phTmlUwb_WaitReadInit failed, error = 0x%X", ret);
+    NXPLOG_TML_E("[%s] pthread_cond_init failed for wait_busy_condition at line: %d", __func__,
+        __LINE__);
   }
   return ret;
 }
diff --git a/halimpl/tml/phTmlUwb.h b/halimpl/tml/phTmlUwb.h
index 8e5c53b..fcbf13e 100644
--- a/halimpl/tml/phTmlUwb.h
+++ b/halimpl/tml/phTmlUwb.h
@@ -62,59 +62,23 @@
  * file or timeout.
  */
 
-typedef struct phTmlUwb_TransactInfo {
-  tHAL_UWB_STATUS wStatus;       /* Status of the Transaction Completion*/
-  uint8_t* pBuff;          /* Response Data of the Transaction*/
-  uint16_t wLength;        /* Data size of the Transaction*/
-} phTmlUwb_TransactInfo_t; /* Instance of Transaction structure */
-
-/*
- * TML transreceive completion callback to Upper Layer
- *
- * pContext - Context provided by upper layer
- * pInfo    - Transaction info. See phTmlUwb_TransactInfo
- */
-typedef void (*pphTmlUwb_TransactCompletionCb_t)(
-    void* pContext, phTmlUwb_TransactInfo_t* pInfo);
+struct phTmlUwb_WriteTransactInfo {
+  tHAL_UWB_STATUS wStatus;
+  const uint8_t* pBuff;
+  size_t wLength;
+};
 
-/*
- * Structure containing details related to read and write operations
- *
- */
-typedef struct phTmlUwb_ReadWriteInfo {
-  volatile bool bThreadShouldStop;
-  volatile bool bThreadRunning;
-  uint8_t
-      bThreadBusy; /*Flag to indicate thread is busy on respective operation */
-  /* Transaction completion Callback function */
-  pphTmlUwb_TransactCompletionCb_t pThread_Callback;
-  void* pContext;        /*Context passed while invocation of operation */
-  uint8_t* pBuffer;      /*Buffer passed while invocation of operation */
-  uint16_t wLength;      /*Length of data read/written */
-  tHAL_UWB_STATUS wWorkStatus; /*Status of the transaction performed */
-} phTmlUwb_ReadWriteInfo_t;
+struct phTmlUwb_ReadTransactInfo {
+  tHAL_UWB_STATUS wStatus;
+  uint8_t* pBuff;
+  size_t wLength;
+};
 
-/*
- *Base Context Structure containing members required for entire session
- */
-typedef struct phTmlUwb_Context {
-  pthread_t readerThread; /*Handle to the thread which handles write and read
-                             operations */
-  pthread_t writerThread;
-
-  phTmlUwb_ReadWriteInfo_t tReadInfo;  /*Pointer to Reader Thread Structure */
-  phTmlUwb_ReadWriteInfo_t tWriteInfo; /*Pointer to Writer Thread Structure */
-  void* pDevHandle;                    /* Pointer to Device Handle */
-  std::shared_ptr<MessageQueue<phLibUwb_Message>> pClientMq; /* Pointer to Client thread message queue */
-  sem_t rxSemaphore;
-  sem_t txSemaphore;      /* Lock/Acquire txRx Semaphore */
-
-  pthread_cond_t wait_busy_condition; /*Condition to wait reader thread*/
-  pthread_mutex_t wait_busy_lock;     /*Condition lock to wait reader thread*/
-  volatile uint8_t wait_busy_flag;    /*Condition flag to wait reader thread*/
-  volatile uint8_t gWriterCbflag;    /* flag to indicate write callback message is pushed to
-                           queue*/
-} phTmlUwb_Context_t;
+// IO completion callback to Upper Layer
+// pContext - Context provided by upper layer
+// pInfo    - Transaction info. See phTmlUwb_[Read|Write]TransactInfo
+using ReadCallback = void (void *pContext, phTmlUwb_ReadTransactInfo* pInfo);
+using WriteCallback = void (void *pContext, phTmlUwb_WriteTransactInfo* pInfo);
 
 /*
  * Enum definition contains  supported ioctl control codes.
@@ -136,15 +100,13 @@ void phTmlUwb_Suspend(void);
 void phTmlUwb_Resume(void);
 
 // Writer: caller should call this for every write io
-tHAL_UWB_STATUS phTmlUwb_Write(uint8_t* pBuffer, uint16_t wLength,
-                         pphTmlUwb_TransactCompletionCb_t pTmlWriteComplete,
+tHAL_UWB_STATUS phTmlUwb_Write(const uint8_t* pBuffer, size_t wLength,
+                         WriteCallback pTmlWriteComplete,
                          void* pContext);
 
 // Reader: caller calls this once, callback will be called for every received packet.
 //         and call StopRead() to unscribe RX packet.
-tHAL_UWB_STATUS phTmlUwb_StartRead(uint8_t* pBuffer, uint16_t wLength,
-                        pphTmlUwb_TransactCompletionCb_t pTmlReadComplete,
-                        void* pContext);
+tHAL_UWB_STATUS phTmlUwb_StartRead(ReadCallback pTmlReadComplete, void* pContext);
 void phTmlUwb_StopRead();
 
 void phTmlUwb_Chip_Reset(void);
diff --git a/halimpl/tml/phTmlUwb_spi.cc b/halimpl/tml/phTmlUwb_spi.cc
index 132a990..3a33d81 100644
--- a/halimpl/tml/phTmlUwb_spi.cc
+++ b/halimpl/tml/phTmlUwb_spi.cc
@@ -78,7 +78,7 @@ tHAL_UWB_STATUS phTmlUwb_spi_open_and_configure(const char* pDevName, void** pLi
 **                  -1         - write operation failure
 **
 *******************************************************************************/
-int phTmlUwb_spi_write(void* pDevHandle, uint8_t* pBuffer, size_t nNbBytesToWrite)
+int phTmlUwb_spi_write(void* pDevHandle, const uint8_t* pBuffer, size_t nNbBytesToWrite)
 {
   int ret;
   ssize_t numWrote;
diff --git a/halimpl/tml/phTmlUwb_spi.h b/halimpl/tml/phTmlUwb_spi.h
index acf42e1..442c002 100644
--- a/halimpl/tml/phTmlUwb_spi.h
+++ b/halimpl/tml/phTmlUwb_spi.h
@@ -49,5 +49,5 @@
 void phTmlUwb_spi_close(void* pDevHandle);
 tHAL_UWB_STATUS phTmlUwb_spi_open_and_configure(const char* pDevName, void** pLinkHandle);
 int phTmlUwb_spi_read(void* pDevHandle, uint8_t* pBuffer, size_t nNbBytesToRead);
-int phTmlUwb_spi_write(void* pDevHandle, uint8_t* pBuffer, size_t nNbBytesToWrite);
+int phTmlUwb_spi_write(void* pDevHandle, const uint8_t* pBuffer, size_t nNbBytesToWrite);
 int phTmlUwb_Spi_Ioctl(void* pDevHandle, phTmlUwb_ControlCode_t cmd, long arg);
diff --git a/halimpl/utils/phNxpConfig.cc b/halimpl/utils/phNxpConfig.cc
index b929a03..5bd2125 100644
--- a/halimpl/utils/phNxpConfig.cc
+++ b/halimpl/utils/phNxpConfig.cc
@@ -1,7 +1,7 @@
 /******************************************************************************
  *
  *  Copyright (C) 2011-2012 Broadcom Corporation
- *  Copyright 2018-2019, 2023 NXP
+ *  Copyright 2018-2019, 2023-2024 NXP
  *
  *  Licensed under the Apache License, Version 2.0 (the "License");
  *  you may not use this file except in compliance with the License.
@@ -22,6 +22,8 @@
 #include <limits.h>
 #include <sys/stat.h>
 
+#include <cstddef>
+#include <cstdint>
 #include <iomanip>
 #include <list>
 #include <memory>
@@ -42,6 +44,8 @@
 #include "phNxpUciHal_utils.h"
 #include "phNxpLog.h"
 
+namespace {
+
 static const char default_nxp_config_path[] = "/vendor/etc/libuwb-nxp.conf";
 static const char country_code_config_name[] = "libuwb-countrycode.conf";
 static const char nxp_uci_config_file[] = "libuwb-uci.conf";
@@ -91,6 +95,7 @@ public:
 
     void dump(const string &tag) const;
 private:
+    // TODO: use uint64_t or uint32_t instead of unsigned long.
     unsigned long   m_numValue;
     string          m_str_value;
     vector<uint8_t>  m_arrValue;
@@ -377,7 +382,9 @@ bool CUwbNxpConfig::readConfig()
             state = END_LINE;
     }
 
-    fclose(fd);
+    if (fclose(fd) != 0) {
+      ALOGE("[%s] fclose failed", __func__);
+    }
 
     if (m_map.size() > 0) {
         mValidFile = true;
@@ -643,7 +650,7 @@ public:
     const uwbParam* find(const char *name)  const;
     bool    getValue(const char* name, char* pValue, size_t len) const;
     bool    getValue(const char* name, unsigned long& rValue) const;
-    bool    getValue(const char* name, uint8_t* pValue, long len, long* readlen) const;
+    bool    getValue(const char* name, uint8_t* pValue, size_t len, size_t* readlen) const;
 private:
     // default_nxp_config_path
     CUwbNxpConfig mMainConfig;
@@ -793,9 +800,9 @@ void CascadeConfig::init(const char *main_config)
 
     // Pick one libuwb-countrycode.conf with the highest VERSION number
     // from multiple directories specified by COUNTRY_CODE_CAP_FILE_LOCATION
-    unsigned long arrLen = 0;
+    size_t arrLen = 0;
     if (NxpConfig_GetStrArrayLen(NAME_COUNTRY_CODE_CAP_FILE_LOCATION, &arrLen) && arrLen > 0) {
-        const long loc_max_len = 260;
+        constexpr size_t loc_max_len = 260;
         auto loc = make_unique<char[]>(loc_max_len);
         int version, max_version = -1;
         string strPickedPath;
@@ -907,7 +914,7 @@ bool CascadeConfig::getValue(const char* name, char* pValue, size_t len) const
     return true;
 }
 
-bool CascadeConfig::getValue(const char* name, uint8_t* pValue, long len, long* readlen) const
+bool CascadeConfig::getValue(const char* name, uint8_t* pValue, size_t len, size_t* readlen) const
 {
     const uwbParam *param = find(name);
     if (!param)
@@ -934,7 +941,7 @@ bool CascadeConfig::getValue(const char* name, unsigned long& rValue) const
     return true;
 }
 
-/*******************************************************************************/
+}   // namespace
 
 static CascadeConfig gConfig;
 
@@ -964,7 +971,7 @@ bool NxpConfig_SetCountryCode(const char country_code[2])
 ** Returns:     True if found, otherwise False.
 **
 *******************************************************************************/
-int NxpConfig_GetStr(const char* name, char* pValue, unsigned long len)
+bool NxpConfig_GetStr(const char* name, char* pValue, size_t len)
 {
     return gConfig.getValue(name, pValue, len);
 }
@@ -985,9 +992,9 @@ int NxpConfig_GetStr(const char* name, char* pValue, unsigned long len)
 ** Returns:     TRUE[1] if config param name is found in the config file, else FALSE[0]
 **
 *******************************************************************************/
-int NxpConfig_GetByteArray(const char* name, uint8_t* pValue, long bufflen, long *len)
+bool NxpConfig_GetByteArray(const char* name, uint8_t* pValue, size_t bufflen, size_t* len)
 {
-    return gConfig.getValue(name, pValue, bufflen,len);
+    return gConfig.getValue(name, pValue, bufflen, len);
 }
 
 /*******************************************************************************
@@ -999,17 +1006,18 @@ int NxpConfig_GetByteArray(const char* name, uint8_t* pValue, long bufflen, long
 ** Returns:     true, if successful
 **
 *******************************************************************************/
-int NxpConfig_GetNum(const char* name, void* pValue, unsigned long len)
+bool NxpConfig_GetNum(const char* name, void* pValue, size_t len)
 {
-    if (pValue == NULL){
+    if ((name == nullptr) || (pValue == nullptr)){
+        ALOGE("[%s] Invalid arguments", __func__);
         return false;
     }
     const uwbParam* pParam = gConfig.find(name);
 
-    if (pParam == NULL)
-        return false;
-    if (pParam->getType() != uwbParam::type::NUMBER)
+    if ((pParam == nullptr) || (pParam->getType() != uwbParam::type::NUMBER)) {
+        ALOGE("Config:%s not found in the config file", name);
         return false;
+    }
 
     unsigned long v = pParam->numValue();
     switch (len)
@@ -1024,13 +1032,14 @@ int NxpConfig_GetNum(const char* name, void* pValue, unsigned long len)
         *(static_cast<unsigned char*> (pValue)) = (unsigned char)v;
         break;
     default:
+        ALOGE("[%s] unsupported length:%zu", __func__, len);
         return false;
     }
     return true;
 }
 
 // Get the length of a 'string-array' type parameter
-int NxpConfig_GetStrArrayLen(const char* name, unsigned long* pLen)
+bool NxpConfig_GetStrArrayLen(const char* name, size_t* pLen)
 {
     const uwbParam* param = gConfig.find(name);
     if (!param || param->getType() != uwbParam::type::STRINGARRAY)
@@ -1041,7 +1050,7 @@ int NxpConfig_GetStrArrayLen(const char* name, unsigned long* pLen)
 }
 
 // Get a string value from 'string-array' type parameters, index zero-based
-int NxpConfig_GetStrArrayVal(const char* name, int index, char* pValue, unsigned long len)
+bool NxpConfig_GetStrArrayVal(const char* name, int index, char* pValue, size_t len)
 {
     const uwbParam* param = gConfig.find(name);
     if (!param || param->getType() != uwbParam::type::STRINGARRAY)
diff --git a/halimpl/utils/phNxpConfig.h b/halimpl/utils/phNxpConfig.h
index 16552e0..030fc03 100644
--- a/halimpl/utils/phNxpConfig.h
+++ b/halimpl/utils/phNxpConfig.h
@@ -20,18 +20,23 @@
 #ifndef __CONFIG_H
 #define __CONFIG_H
 
-#include <stdint.h>
+#include <cstddef>
+#include <cstdint>
 
 void NxpConfig_Init(void);
 void NxpConfig_Deinit(void);
 bool NxpConfig_SetCountryCode(const char country_code[2]);
 
-int NxpConfig_GetStr(const char* name, char* p_value, unsigned long len);
-int NxpConfig_GetNum(const char* name, void* p_value, unsigned long len);
-int NxpConfig_GetByteArray(const char* name, uint8_t* pValue, long bufflen, long *len);
+// TODO: use std::optional as return type.
+// TODO: use std::string_view instead of const char*.
+// TODO: add GetBool().
+// TODO: use template for GetNum() (uint8_t, uint16_t, uint32_t).
+bool NxpConfig_GetStr(const char* name, char* p_value, size_t len);
+bool NxpConfig_GetNum(const char* name, void* p_value, size_t len);
+bool NxpConfig_GetByteArray(const char* name, uint8_t* pValue, size_t bufflen, size_t *len);
 
-int NxpConfig_GetStrArrayLen(const char* name, unsigned long *pLen);
-int NxpConfig_GetStrArrayVal(const char* name, int index, char* pValue, unsigned long len);
+bool NxpConfig_GetStrArrayLen(const char* name, size_t* pLen);
+bool NxpConfig_GetStrArrayVal(const char* name, int index, char* pValue, size_t len);
 
 /* libuwb-nxp.conf parameters */
 #define NAME_UWB_BOARD_VARIANT_CONFIG "UWB_BOARD_VARIANT_CONFIG"
diff --git a/halimpl/utils/phNxpUciHal_utils.cc b/halimpl/utils/phNxpUciHal_utils.cc
index 42af937..2db40b2 100644
--- a/halimpl/utils/phNxpUciHal_utils.cc
+++ b/halimpl/utils/phNxpUciHal_utils.cc
@@ -25,228 +25,83 @@ using namespace std;
 map<uint16_t, vector<uint16_t>> input_map;
 map<uint16_t, vector<uint16_t>> conf_map;
 
-/*********************** Link list functions **********************************/
-
-/*******************************************************************************
-**
-** Function         listInit
-**
-** Description      List initialization
-**
-** Returns          1, if list initialized, 0 otherwise
-**
-*******************************************************************************/
-int listInit(struct listHead* pList) {
-  pList->pFirst = NULL;
-  if (pthread_mutex_init(&pList->mutex, NULL) == -1) {
-    NXPLOG_UCIHAL_E("Mutex creation failed (errno=0x%08x)", errno);
-    return 0;
-  }
-
-  return 1;
-}
-
-/*******************************************************************************
-**
-** Function         listDestroy
-**
-** Description      List destruction
-**
-** Returns          1, if list destroyed, 0 if failed
-**
-*******************************************************************************/
-int listDestroy(struct listHead* pList) {
-  int bListNotEmpty = 1;
-  while (bListNotEmpty) {
-    bListNotEmpty = listGetAndRemoveNext(pList, NULL);
-  }
-
-  if (pthread_mutex_destroy(&pList->mutex) == -1) {
-    NXPLOG_UCIHAL_E("Mutex destruction failed (errno=0x%08x)", errno);
-    return 0;
-  }
-
-  return 1;
-}
-
-/*******************************************************************************
-**
-** Function         listAdd
-**
-** Description      Add a node to the list
-**
-** Returns          1, if added, 0 if otherwise
-**
-*******************************************************************************/
-int listAdd(struct listHead* pList, void* pData) {
-  struct listNode* pNode;
-  struct listNode* pLastNode;
-  int result;
-
-  /* Create node */
-  pNode = (struct listNode*)malloc(sizeof(struct listNode));
-  if (pNode == NULL) {
-    result = 0;
-    NXPLOG_UCIHAL_E("Failed to malloc");
-    goto clean_and_return;
-  }
-  pNode->pData = pData;
-  pNode->pNext = NULL;
-  pthread_mutex_lock(&pList->mutex);
-
-  /* Add the node to the list */
-  if (pList->pFirst == NULL) {
-    /* Set the node as the head */
-    pList->pFirst = pNode;
-  } else {
-    /* Seek to the end of the list */
-    pLastNode = pList->pFirst;
-    while (pLastNode->pNext != NULL) {
-      pLastNode = pLastNode->pNext;
+/****************** Semaphore and mutex helper functions **********************/
+/* Semaphore and mutex monitor */
+struct phNxpUciHal_Monitor {
+public:
+  static std::unique_ptr<phNxpUciHal_Monitor> Create() {
+    //auto monitor = std::unique_ptr<phNxpUciHal_Monitor>(new phNxpUciHal_Monitor());
+    auto monitor = std::make_unique<phNxpUciHal_Monitor>();
+    if (pthread_mutex_init(&monitor->reentrance_mutex_, NULL) == -1) {
+      return nullptr;
     }
-
-    /* Add the node to the current list */
-    pLastNode->pNext = pNode;
+    if (pthread_mutex_init(&monitor->concurrency_mutex_, NULL) == -1) {
+      pthread_mutex_destroy(&monitor->reentrance_mutex_);
+      return nullptr;
+    }
+    return monitor;
   }
 
-  result = 1;
-
-clean_and_return:
-  pthread_mutex_unlock(&pList->mutex);
-  return result;
-}
-
-/*******************************************************************************
-**
-** Function         listRemove
-**
-** Description      Remove node from the list
-**
-** Returns          1, if removed, 0 if otherwise
-**
-*******************************************************************************/
-int listRemove(struct listHead* pList, void* pData) {
-  struct listNode* pNode;
-  struct listNode* pRemovedNode;
-  int result;
-
-  pthread_mutex_lock(&pList->mutex);
-
-  if (pList->pFirst == NULL) {
-    /* Empty list */
-    NXPLOG_UCIHAL_E("Failed to deallocate (list empty)");
-    result = 0;
-    goto clean_and_return;
+  virtual ~phNxpUciHal_Monitor() {
+    pthread_mutex_destroy(&concurrency_mutex_);
+    ReentranceUnlock();
+    pthread_mutex_destroy(&reentrance_mutex_);
+    for (auto p : sems_) {
+      NXPLOG_UCIHAL_E("Unreleased semaphore %p", p);
+      p->status = UWBSTATUS_FAILED;
+      sem_post(&p->sem);
+    }
+    sems_.clear();
   }
 
-  pNode = pList->pFirst;
-  if (pList->pFirst->pData == pData) {
-    /* Get the removed node */
-    pRemovedNode = pNode;
-
-    /* Remove the first node */
-    pList->pFirst = pList->pFirst->pNext;
-  } else {
-    while (pNode->pNext != NULL) {
-      if (pNode->pNext->pData == pData) {
-        /* Node found ! */
-        break;
-      }
-      pNode = pNode->pNext;
+  void AddSem(phNxpUciHal_Sem_t* pCallbackData) {
+    std::lock_guard<std::mutex> lock(lock_);
+    auto it = sems_.find(pCallbackData);
+    if (it == sems_.end()) {
+      sems_.insert(pCallbackData);
+    } else {
+      NXPLOG_UCIHAL_E("phNxpUciHal_init_cb_data: duplicated semaphore %p",
+        pCallbackData);
     }
+  }
 
-    if (pNode->pNext == NULL) {
-      /* Node not found */
-      result = 0;
-      NXPLOG_UCIHAL_E("Failed to deallocate (not found %8p)", pData);
-      goto clean_and_return;
+  void RemoveSem(phNxpUciHal_Sem_t* pCallbackData) {
+    std::lock_guard<std::mutex> lock(lock_);
+    auto it = sems_.find(pCallbackData);
+    if (it == sems_.end()) {
+      NXPLOG_UCIHAL_E("phNxpUciHal_cleanup_cb_data: orphan semaphore %p",
+        pCallbackData);
+    } else {
+      sems_.erase(it);
     }
-
-    /* Get the removed node */
-    pRemovedNode = pNode->pNext;
-
-    /* Remove the node from the list */
-    pNode->pNext = pNode->pNext->pNext;
   }
 
-  /* Deallocate the node */
-  free(pRemovedNode);
-
-  result = 1;
-
-clean_and_return:
-  pthread_mutex_unlock(&pList->mutex);
-  return result;
-}
-
-/*******************************************************************************
-**
-** Function         listGetAndRemoveNext
-**
-** Description      Get next node on the list and remove it
-**
-** Returns          1, if successful, 0 if otherwise
-**
-*******************************************************************************/
-int listGetAndRemoveNext(struct listHead* pList, void** ppData) {
-  struct listNode* pNode;
-  int result;
-
-  pthread_mutex_lock(&pList->mutex);
-
-  if (pList->pFirst == NULL) {
-    /* Empty list */
-    NXPLOG_UCIHAL_D("Failed to deallocate (list empty)");
-    result = 0;
-    goto clean_and_return;
+  void Reentrancelock() {
+    pthread_mutex_lock(&reentrance_mutex_);
   }
 
-  /* Work on the first node */
-  pNode = pList->pFirst;
-
-  /* Return the data */
-  if (ppData != NULL) {
-    *ppData = pNode->pData;
+  void ReentranceUnlock() {
+    pthread_mutex_unlock(&reentrance_mutex_);
   }
 
-  /* Remove and deallocate the node */
-  pList->pFirst = pNode->pNext;
-  free(pNode);
-
-  result = 1;
-
-clean_and_return:
-  listDump(pList);
-  pthread_mutex_unlock(&pList->mutex);
-  return result;
-}
-
-/*******************************************************************************
-**
-** Function         listDump
-**
-** Description      Dump list information
-**
-** Returns          None
-**
-*******************************************************************************/
-void listDump(struct listHead* pList) {
-  struct listNode* pNode = pList->pFirst;
-
-  NXPLOG_UCIHAL_D("Node dump:");
-  while (pNode != NULL) {
-    NXPLOG_UCIHAL_D("- %8p (%8p)", pNode, pNode->pData);
-    pNode = pNode->pNext;
+  void Concurrencylock() {
+    pthread_mutex_lock(&concurrency_mutex_);
   }
 
-  return;
-}
-
-/* END Linked list source code */
+  void ConcurrencyUnlock() {
+    pthread_mutex_unlock(&concurrency_mutex_);
+  }
 
-/****************** Semaphore and mutex helper functions **********************/
+private:
+  std::unordered_set<phNxpUciHal_Sem_t*> sems_;
+  std::mutex lock_;
+  // Mutex protecting native library against reentrance
+  pthread_mutex_t reentrance_mutex_;
+  // Mutex protecting native library against concurrency
+  pthread_mutex_t concurrency_mutex_;
+};
 
-static phNxpUciHal_Monitor_t* nxpucihal_monitor = NULL;
+static std::unique_ptr<phNxpUciHal_Monitor> nxpucihal_monitor;
 
 /*******************************************************************************
 **
@@ -257,52 +112,16 @@ static phNxpUciHal_Monitor_t* nxpucihal_monitor = NULL;
 ** Returns          Pointer to monitor, otherwise NULL if failed
 **
 *******************************************************************************/
-phNxpUciHal_Monitor_t* phNxpUciHal_init_monitor(void) {
+bool phNxpUciHal_init_monitor(void) {
   NXPLOG_UCIHAL_D("Entering phNxpUciHal_init_monitor");
 
-  if (nxpucihal_monitor == NULL) {
-    nxpucihal_monitor =
-        (phNxpUciHal_Monitor_t*)malloc(sizeof(phNxpUciHal_Monitor_t));
-  }
-
-  if (nxpucihal_monitor != NULL) {
-    memset(nxpucihal_monitor, 0x00, sizeof(phNxpUciHal_Monitor_t));
-
-    if (pthread_mutex_init(&nxpucihal_monitor->reentrance_mutex, NULL) == -1) {
-      NXPLOG_UCIHAL_E("reentrance_mutex creation returned 0x%08x", errno);
-      goto clean_and_return;
-    }
-
-    if (pthread_mutex_init(&nxpucihal_monitor->concurrency_mutex, NULL) == -1) {
-      NXPLOG_UCIHAL_E("concurrency_mutex creation returned 0x%08x", errno);
-      pthread_mutex_destroy(&nxpucihal_monitor->reentrance_mutex);
-      goto clean_and_return;
-    }
+  nxpucihal_monitor = phNxpUciHal_Monitor::Create();
 
-    if (listInit(&nxpucihal_monitor->sem_list) != 1) {
-      NXPLOG_UCIHAL_E("Semaphore List creation failed");
-      pthread_mutex_destroy(&nxpucihal_monitor->concurrency_mutex);
-      pthread_mutex_destroy(&nxpucihal_monitor->reentrance_mutex);
-      goto clean_and_return;
-    }
-  } else {
+  if (nxpucihal_monitor == nullptr) {
     NXPLOG_UCIHAL_E("nxphal_monitor creation failed");
-    goto clean_and_return;
-  }
-
-  NXPLOG_UCIHAL_D("Returning with SUCCESS");
-
-  return nxpucihal_monitor;
-
-clean_and_return:
-  NXPLOG_UCIHAL_D("Returning with FAILURE");
-
-  if (nxpucihal_monitor != NULL) {
-    free(nxpucihal_monitor);
-    nxpucihal_monitor = NULL;
+    return false;
   }
-
-  return NULL;
+  return true;
 }
 
 /*******************************************************************************
@@ -315,33 +134,7 @@ clean_and_return:
 **
 *******************************************************************************/
 void phNxpUciHal_cleanup_monitor(void) {
-  if (nxpucihal_monitor != NULL) {
-    pthread_mutex_destroy(&nxpucihal_monitor->concurrency_mutex);
-    REENTRANCE_UNLOCK();
-    pthread_mutex_destroy(&nxpucihal_monitor->reentrance_mutex);
-    phNxpUciHal_releaseall_cb_data();
-    listDestroy(&nxpucihal_monitor->sem_list);
-    free(nxpucihal_monitor);
-    nxpucihal_monitor = NULL;
-  }
-
-  return;
-}
-
-/*******************************************************************************
-**
-** Function         phNxpUciHal_get_monitor
-**
-** Description      Get monitor
-**
-** Returns          Pointer to monitor
-**
-*******************************************************************************/
-phNxpUciHal_Monitor_t* phNxpUciHal_get_monitor(void) {
-  if (nxpucihal_monitor == NULL) {
-    NXPLOG_UCIHAL_E("nxpucihal_monitor is null");
-  }
-  return nxpucihal_monitor;
+  nxpucihal_monitor = nullptr;
 }
 
 /* Initialize the callback data */
@@ -360,8 +153,8 @@ tHAL_UWB_STATUS phNxpUciHal_init_cb_data(phNxpUciHal_Sem_t* pCallbackData,
   pCallbackData->pContext = pContext;
 
   /* Add to active semaphore list */
-  if (listAdd(&phNxpUciHal_get_monitor()->sem_list, pCallbackData) != 1) {
-    NXPLOG_UCIHAL_E("Failed to add the semaphore to the list");
+  if (nxpucihal_monitor != nullptr) {
+    nxpucihal_monitor->AddSem(pCallbackData);
   }
 
   return UWBSTATUS_SUCCESS;
@@ -382,15 +175,30 @@ void phNxpUciHal_cleanup_cb_data(phNxpUciHal_Sem_t* pCallbackData) {
     NXPLOG_UCIHAL_E(
         "phNxpUciHal_cleanup_cb_data: Failed to destroy semaphore");
   }
-
-  /* Remove from active semaphore list */
-  if (listRemove(&phNxpUciHal_get_monitor()->sem_list, pCallbackData) != 1) {
-    NXPLOG_UCIHAL_E(
-        "phNxpUciHal_cleanup_cb_data: Failed to remove semaphore from the "
-        "list");
+  if (nxpucihal_monitor != nullptr) {
+    nxpucihal_monitor->RemoveSem(pCallbackData);
   }
+}
 
-  return;
+void REENTRANCE_LOCK() {
+  if (nxpucihal_monitor != nullptr) {
+    nxpucihal_monitor->Reentrancelock();
+  }
+}
+void REENTRANCE_UNLOCK() {
+  if (nxpucihal_monitor != nullptr) {
+    nxpucihal_monitor->ReentranceUnlock();
+  }
+}
+void CONCURRENCY_LOCK() {
+  if (nxpucihal_monitor != nullptr) {
+    nxpucihal_monitor->Concurrencylock();
+  }
+}
+void CONCURRENCY_UNLOCK() {
+  if (nxpucihal_monitor != nullptr) {
+    nxpucihal_monitor->ConcurrencyUnlock();
+  }
 }
 
 int phNxpUciHal_sem_timed_wait_msec(phNxpUciHal_Sem_t* pCallbackData, long msec)
@@ -423,27 +231,6 @@ int phNxpUciHal_sem_timed_wait_msec(phNxpUciHal_Sem_t* pCallbackData, long msec)
   return 0;
 }
 
-/*******************************************************************************
-**
-** Function         phNxpUciHal_releaseall_cb_data
-**
-** Description      Release all callback data
-**
-** Returns          None
-**
-*******************************************************************************/
-void phNxpUciHal_releaseall_cb_data(void) {
-  phNxpUciHal_Sem_t* pCallbackData;
-
-  while (listGetAndRemoveNext(&phNxpUciHal_get_monitor()->sem_list,
-                              (void**)&pCallbackData)) {
-    pCallbackData->status = UWBSTATUS_FAILED;
-    sem_post(&pCallbackData->sem);
-  }
-
-  return;
-}
-
 /* END Semaphore and mutex helper functions */
 
 /**************************** Other functions *********************************/
diff --git a/halimpl/utils/phNxpUciHal_utils.h b/halimpl/utils/phNxpUciHal_utils.h
index 6639fb1..501052a 100644
--- a/halimpl/utils/phNxpUciHal_utils.h
+++ b/halimpl/utils/phNxpUciHal_utils.h
@@ -17,33 +17,25 @@
 #ifndef _PHNXPUCIHAL_UTILS_H_
 #define _PHNXPUCIHAL_UTILS_H_
 
-#include <assert.h>
 #include <pthread.h>
 #include <semaphore.h>
 #include <time.h>
+#include <unordered_set>
 
-#include <cstring>
+#include <assert.h>
 #include <bit>
+#include <cstring>
 #include <map>
+#include <memory>
+#include <thread>
 #include <type_traits>
 #include <vector>
 
+
 #include "phNxpLog.h"
 #include "phUwbStatus.h"
 
 /********************* Definitions and structures *****************************/
-
-/* List structures */
-struct listNode {
-  void* pData;
-  struct listNode* pNext;
-};
-
-struct listHead {
-  struct listNode* pFirst;
-  pthread_mutex_t mutex;
-};
-
 /* Which is the direction of UWB Packet.
  *
  * Used by the @ref phNxpUciHal_print_packet API.
@@ -80,34 +72,13 @@ static inline int SEM_POST(phNxpUciHal_Sem_t* pCallbackData)
   return sem_post(&pCallbackData->sem);
 }
 
-/* Semaphore and mutex monitor */
-typedef struct phNxpUciHal_Monitor {
-  /* Mutex protecting native library against reentrance */
-  pthread_mutex_t reentrance_mutex;
-
-  /* Mutex protecting native library against concurrency */
-  pthread_mutex_t concurrency_mutex;
-
-  /* List used to track pending semaphores waiting for callback */
-  struct listHead sem_list;
-
-} phNxpUciHal_Monitor_t;
-
 /************************ Exposed functions ***********************************/
-/* List functions */
-int listInit(struct listHead* pList);
-int listDestroy(struct listHead* pList);
-int listAdd(struct listHead* pList, void* pData);
-int listRemove(struct listHead* pList, void* pData);
-int listGetAndRemoveNext(struct listHead* pList, void** ppData);
-void listDump(struct listHead* pList);
-
 /* NXP UCI HAL utility functions */
-phNxpUciHal_Monitor_t* phNxpUciHal_init_monitor(void);
+bool phNxpUciHal_init_monitor(void);
 void phNxpUciHal_cleanup_monitor(void);
-phNxpUciHal_Monitor_t* phNxpUciHal_get_monitor(void);
+
 tHAL_UWB_STATUS phNxpUciHal_init_cb_data(phNxpUciHal_Sem_t* pCallbackData,
-                                   void* pContext);
+                                         void* pContext);
 
 int phNxpUciHal_sem_timed_wait_msec(phNxpUciHal_Sem_t* pCallbackData, long msec);
 
@@ -123,7 +94,6 @@ static inline int phNxpUciHal_sem_timed_wait(phNxpUciHal_Sem_t* pCallbackData)
 }
 
 void phNxpUciHal_cleanup_cb_data(phNxpUciHal_Sem_t* pCallbackData);
-void phNxpUciHal_releaseall_cb_data(void);
 
 // helper class for Semaphore
 // phNxpUciHal_init_cb_data(), phNxpUciHal_cleanup_cb_data(),
@@ -207,18 +177,10 @@ static inline void cpu_to_le_bytes(uint8_t *p, const T num)
 }
 
 /* Lock unlock helper macros */
-#define REENTRANCE_LOCK()        \
-  if (phNxpUciHal_get_monitor()) \
-  pthread_mutex_lock(&phNxpUciHal_get_monitor()->reentrance_mutex)
-#define REENTRANCE_UNLOCK()      \
-  if (phNxpUciHal_get_monitor()) \
-  pthread_mutex_unlock(&phNxpUciHal_get_monitor()->reentrance_mutex)
-#define CONCURRENCY_LOCK()       \
-  if (phNxpUciHal_get_monitor()) \
-  pthread_mutex_lock(&phNxpUciHal_get_monitor()->concurrency_mutex)
-#define CONCURRENCY_UNLOCK()     \
-  if (phNxpUciHal_get_monitor()) \
-  pthread_mutex_unlock(&phNxpUciHal_get_monitor()->concurrency_mutex)
+void REENTRANCE_LOCK();
+void REENTRANCE_UNLOCK();
+void CONCURRENCY_LOCK();
+void CONCURRENCY_UNLOCK();
 
 // Decode bytes into map<key=T, val=LV>
 std::map<uint16_t, std::vector<uint8_t>>
```

