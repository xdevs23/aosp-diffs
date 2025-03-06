```diff
diff --git a/src/rust/uwb_core/protos/uwb_service.proto b/src/rust/uwb_core/protos/uwb_service.proto
index aaf6d18..ff4b335 100644
--- a/src/rust/uwb_core/protos/uwb_service.proto
+++ b/src/rust/uwb_core/protos/uwb_service.proto
@@ -137,7 +137,7 @@ enum ReasonCode {
   SESSION_STOPPED_DUE_TO_INBAND_SIGNAL = 5;
   ERROR_INVALID_UL_TDOA_RANDOM_WINDOW = 29;
   ERROR_MIN_RFRAMES_PER_RR_NOT_SUPPORTED = 30;
-  ERROR_TX_DELAY_NOT_SUPPORTED = 31;
+  ERROR_INTER_FRAME_INTERVAL_NOT_SUPPORTED = 31;
   ERROR_SLOT_LENGTH_NOT_SUPPORTED = 32;
   ERROR_INSUFFICIENT_SLOTS_PER_RR = 33;
   ERROR_MAC_ADDRESS_MODE_NOT_SUPPORTED = 34;
@@ -174,6 +174,7 @@ enum ReasonCode {
   ERROR_STOPPED_DUE_TO_OTHER_SESSION_CONFLICT = 129;
   ERROR_DT_ANCHOR_RANGING_ROUNDS_NOT_CONFIGURED = 130;
   ERROR_DT_TAG_RANGING_ROUNDS_NOT_CONFIGURED = 131;
+  SESSION_STOPPED_DUE_TO_MAX_STS_INDEX_VALUE = 162;
   // All vendor reason code will be mapped to ERROR_VENDOR_SPECIFIC.
   ERROR_RFU_OR_VENDOR_SPECIFIC = 255;
 }
diff --git a/src/rust/uwb_core/src/params/uci_packets.rs b/src/rust/uwb_core/src/params/uci_packets.rs
index c7062d4..e034cf8 100644
--- a/src/rust/uwb_core/src/params/uci_packets.rs
+++ b/src/rust/uwb_core/src/params/uci_packets.rs
@@ -30,7 +30,8 @@ pub use uwb_uci_packets::{
     ExtendedAddressTwoWayRangingMeasurement, GroupId, MacAddressIndicator, MessageType,
     MulticastUpdateStatusCode, PhaseList, PowerStats, RadarConfigStatus, RadarConfigTlv,
     RadarConfigTlvType, RadarDataType, RangingMeasurementType, ReasonCode, ResetConfig,
-    SessionState, SessionType, SessionUpdateControllerMulticastListNtfV1Payload,
+    RfTestConfigStatus, RfTestConfigTlv, RfTestConfigTlvType, SessionState, SessionType,
+    SessionUpdateControllerMulticastListNtfV1Payload,
     SessionUpdateControllerMulticastListNtfV2Payload,
     SessionUpdateControllerMulticastListRspV1Payload,
     SessionUpdateControllerMulticastListRspV2Payload, ShortAddressDlTdoaRangingMeasurement,
@@ -163,6 +164,19 @@ fn radar_config_tlvs_to_map(
     HashMap::from_iter(tlvs.iter().map(|config| (config.cfg_id, &config.v)))
 }
 
+/// Compare if two RfTestConfigTlv array are equal. Convert the array to HashMap before comparing
+/// because the order of TLV elements doesn't matter.
+#[allow(dead_code)]
+pub fn rf_test_config_tlvs_eq(a: &[RfTestConfigTlv], b: &[RfTestConfigTlv]) -> bool {
+    rf_test_config_tlvs_to_map(a) == rf_test_config_tlvs_to_map(b)
+}
+
+fn rf_test_config_tlvs_to_map(
+    tlvs: &[RfTestConfigTlv],
+) -> HashMap<RfTestConfigTlvType, &Vec<u8>, RandomState> {
+    HashMap::from_iter(tlvs.iter().map(|config| (config.cfg_id, &config.v)))
+}
+
 /// The response of the UciManager::core_set_config() method.
 #[derive(Debug, Clone, PartialEq)]
 pub struct CoreSetConfigResponse {
@@ -208,6 +222,15 @@ pub struct SessionUpdateDtTagRangingRoundsResponse {
     pub ranging_round_indexes: Vec<u8>,
 }
 
+/// The response of the UciManager::android_set_rf_test_config() method.
+#[derive(Debug, Clone, PartialEq)]
+pub struct RfTestConfigResponse {
+    /// The status code of the response.
+    pub status: StatusCode,
+    /// The status of each config TLV.
+    pub config_status: Vec<RfTestConfigStatus>,
+}
+
 /// The country code struct that contains 2 uppercase ASCII characters.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct CountryCode([u8; 2]);
@@ -326,4 +349,26 @@ mod tests {
         let country_code_invalid_2: Result<CountryCode, Error> = String::from("ÀÈ").try_into();
         country_code_invalid_2.unwrap_err();
     }
+
+    #[test]
+    fn test_rf_test_config_tlvs_eq() {
+        let tlv1 = RfTestConfigTlv { cfg_id: RfTestConfigTlvType::NumPackets, v: vec![10, 20] };
+        let tlv2 = RfTestConfigTlv { cfg_id: RfTestConfigTlvType::TStart, v: vec![30, 40] };
+
+        let array1 = vec![tlv1.clone(), tlv2.clone()];
+        let array2 = vec![tlv2.clone(), tlv1.clone()]; // Different order
+
+        // Test that arrays with the same elements in different orders are equal.
+        assert!(rf_test_config_tlvs_eq(&array1, &array2));
+
+        let tlv3 = RfTestConfigTlv {
+            cfg_id: RfTestConfigTlvType::TWin,
+            v: vec![70, 80], // Different value
+        };
+
+        let array3 = vec![tlv1.clone(), tlv3.clone()];
+
+        // Test that arrays with different elements are not equal.
+        assert!(!rf_test_config_tlvs_eq(&array1, &array3));
+    }
 }
diff --git a/src/rust/uwb_core/src/proto/mappings.rs b/src/rust/uwb_core/src/proto/mappings.rs
index 089af2f..ccf0a4c 100644
--- a/src/rust/uwb_core/src/proto/mappings.rs
+++ b/src/rust/uwb_core/src/proto/mappings.rs
@@ -324,7 +324,9 @@ impl From<ProtoReasonCode> for ReasonCode {
             ProtoReasonCode::ERROR_MIN_RFRAMES_PER_RR_NOT_SUPPORTED => {
                 ReasonCode::ErrorMinRframesPerRrNotSupported
             }
-            ProtoReasonCode::ERROR_TX_DELAY_NOT_SUPPORTED => ReasonCode::ErrorTxDelayNotSupported,
+            ProtoReasonCode::ERROR_INTER_FRAME_INTERVAL_NOT_SUPPORTED => {
+                ReasonCode::ErrorInterFrameIntervalNotSupported
+            }
             ProtoReasonCode::ERROR_SLOT_LENGTH_NOT_SUPPORTED => {
                 ReasonCode::ErrorSlotLengthNotSupported
             }
@@ -398,6 +400,9 @@ impl From<ProtoReasonCode> for ReasonCode {
             ProtoReasonCode::ERROR_STOPPED_DUE_TO_OTHER_SESSION_CONFLICT => {
                 ReasonCode::ErrorStoppedDueToOtherSessionConflict
             }
+            ProtoReasonCode::SESSION_STOPPED_DUE_TO_MAX_STS_INDEX_VALUE => {
+                ReasonCode::SessionStoppedDueToMaxStsIndexValue
+            }
             _ => ReasonCode::VendorSpecificReasonCode2,
         }
     }
@@ -430,7 +435,9 @@ impl From<ReasonCode> for ProtoReasonCode {
             ReasonCode::ErrorMinRframesPerRrNotSupported => {
                 ProtoReasonCode::ERROR_MIN_RFRAMES_PER_RR_NOT_SUPPORTED
             }
-            ReasonCode::ErrorTxDelayNotSupported => ProtoReasonCode::ERROR_TX_DELAY_NOT_SUPPORTED,
+            ReasonCode::ErrorInterFrameIntervalNotSupported => {
+                ProtoReasonCode::ERROR_INTER_FRAME_INTERVAL_NOT_SUPPORTED
+            }
             ReasonCode::ErrorSlotLengthNotSupported => {
                 ProtoReasonCode::ERROR_SLOT_LENGTH_NOT_SUPPORTED
             }
diff --git a/src/rust/uwb_core/src/uci.rs b/src/rust/uwb_core/src/uci.rs
index 4364966..a102d60 100644
--- a/src/rust/uwb_core/src/uci.rs
+++ b/src/rust/uwb_core/src/uci.rs
@@ -42,7 +42,8 @@ pub mod mock_uci_manager;
 pub use command::UciCommand;
 pub use notification::{
     CoreNotification, DataRcvNotification, RadarDataRcvNotification, RadarSweepData,
-    RangingMeasurements, SessionNotification, SessionRangeData, UciNotification,
+    RangingMeasurements, RfTestNotification, SessionNotification, SessionRangeData,
+    UciNotification,
 };
 pub use uci_hal::{NopUciHal, UciHal, UciHalPacket};
 pub use uci_logger_factory::{NopUciLoggerFactory, UciLoggerFactory};
diff --git a/src/rust/uwb_core/src/uci/command.rs b/src/rust/uwb_core/src/uci/command.rs
index 6c3a339..f603238 100644
--- a/src/rust/uwb_core/src/uci/command.rs
+++ b/src/rust/uwb_core/src/uci/command.rs
@@ -20,8 +20,8 @@ use log::error;
 use crate::error::{Error, Result};
 use crate::params::uci_packets::{
     AppConfigTlv, AppConfigTlvType, Controlees, CountryCode, DeviceConfigId, DeviceConfigTlv,
-    RadarConfigTlv, RadarConfigTlvType, ResetConfig, SessionId, SessionToken, SessionType,
-    UpdateMulticastListAction, UpdateTime,
+    RadarConfigTlv, RadarConfigTlvType, ResetConfig, RfTestConfigTlv, SessionId, SessionToken,
+    SessionType, UpdateMulticastListAction, UpdateTime,
 };
 use uwb_uci_packets::{
     build_data_transfer_phase_config_cmd, build_session_set_hybrid_controller_config_cmd,
@@ -124,6 +124,14 @@ pub enum UciCommand {
         oid: u32,
         payload: Vec<u8>,
     },
+    SessionSetRfTestConfig {
+        session_token: SessionToken,
+        config_tlvs: Vec<RfTestConfigTlv>,
+    },
+    TestPeriodicTx {
+        psdu_data: Vec<u8>,
+    },
+    StopRfTest,
 }
 
 impl TryFrom<UciCommand> for uwb_uci_packets::UciControlPacket {
@@ -280,6 +288,18 @@ impl TryFrom<UciCommand> for uwb_uci_packets::UciControlPacket {
             )
             .map_err(|_| Error::BadParameters)?
             .into(),
+            UciCommand::SessionSetRfTestConfig { session_token, config_tlvs } => {
+                uwb_uci_packets::SessionSetRfTestConfigCmdBuilder {
+                    session_token,
+                    tlvs: config_tlvs,
+                }
+                .build()
+                .into()
+            }
+            UciCommand::TestPeriodicTx { psdu_data } => {
+                uwb_uci_packets::TestPeriodicTxCmdBuilder { psdu_data }.build().into()
+            }
+            UciCommand::StopRfTest {} => uwb_uci_packets::StopRfTestCmdBuilder {}.build().into(),
         };
         Ok(packet)
     }
@@ -585,5 +605,21 @@ mod tests {
             .build()
             .into()
         );
+
+        cmd = UciCommand::SessionSetRfTestConfig { session_token: 1, config_tlvs: vec![] };
+        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
+        assert_eq!(
+            packet,
+            uwb_uci_packets::SessionSetRfTestConfigCmdBuilder { session_token: 1, tlvs: vec![] }
+                .build()
+                .into()
+        );
+
+        cmd = UciCommand::TestPeriodicTx { psdu_data: vec![0] };
+        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
+        assert_eq!(
+            packet,
+            uwb_uci_packets::TestPeriodicTxCmdBuilder { psdu_data: vec![0] }.build().into()
+        );
     }
 }
diff --git a/src/rust/uwb_core/src/uci/mock_uci_manager.rs b/src/rust/uwb_core/src/uci/mock_uci_manager.rs
index 608205d..cbd8538 100644
--- a/src/rust/uwb_core/src/uci/mock_uci_manager.rs
+++ b/src/rust/uwb_core/src/uci/mock_uci_manager.rs
@@ -27,17 +27,18 @@ use tokio::time::timeout;
 
 use crate::error::{Error, Result};
 use crate::params::uci_packets::{
-    app_config_tlvs_eq, device_config_tlvs_eq, radar_config_tlvs_eq, AndroidRadarConfigResponse,
-    AppConfigTlv, AppConfigTlvType, CapTlv, ControleePhaseList, Controlees, CoreSetConfigResponse,
-    CountryCode, DeviceConfigId, DeviceConfigTlv, GetDeviceInfoResponse, PhaseList, PowerStats,
-    RadarConfigTlv, RadarConfigTlvType, RawUciMessage, ResetConfig, SessionId, SessionState,
+    app_config_tlvs_eq, device_config_tlvs_eq, radar_config_tlvs_eq, rf_test_config_tlvs_eq,
+    AndroidRadarConfigResponse, AppConfigTlv, AppConfigTlvType, CapTlv, ControleePhaseList,
+    Controlees, CoreSetConfigResponse, CountryCode, DeviceConfigId, DeviceConfigTlv,
+    GetDeviceInfoResponse, PhaseList, PowerStats, RadarConfigTlv, RadarConfigTlvType,
+    RawUciMessage, ResetConfig, RfTestConfigResponse, RfTestConfigTlv, SessionId, SessionState,
     SessionToken, SessionType, SessionUpdateControllerMulticastResponse,
     SessionUpdateDtTagRangingRoundsResponse, SetAppConfigResponse, UpdateMulticastListAction,
     UpdateTime,
 };
 use crate::uci::notification::{
-    CoreNotification, DataRcvNotification, RadarDataRcvNotification, SessionNotification,
-    UciNotification,
+    CoreNotification, DataRcvNotification, RadarDataRcvNotification, RfTestNotification,
+    SessionNotification, UciNotification,
 };
 use crate::uci::uci_logger::UciLoggerMode;
 use crate::uci::uci_manager::UciManager;
@@ -52,6 +53,7 @@ pub struct MockUciManager {
     vendor_notf_sender: mpsc::UnboundedSender<RawUciMessage>,
     data_rcv_notf_sender: mpsc::UnboundedSender<DataRcvNotification>,
     radar_data_rcv_notf_sender: mpsc::UnboundedSender<RadarDataRcvNotification>,
+    rf_test_notf_sender: mpsc::UnboundedSender<RfTestNotification>,
 }
 
 #[allow(dead_code)]
@@ -66,6 +68,7 @@ impl MockUciManager {
             vendor_notf_sender: mpsc::unbounded_channel().0,
             data_rcv_notf_sender: mpsc::unbounded_channel().0,
             radar_data_rcv_notf_sender: mpsc::unbounded_channel().0,
+            rf_test_notf_sender: mpsc::unbounded_channel().0,
         }
     }
 
@@ -521,6 +524,49 @@ impl MockUciManager {
         );
     }
 
+    /// Prepare Mock to expect session_set_rf_test_config.
+    ///
+    /// MockUciManager expects call with parameters, returns out as response, followed by notfs
+    /// sent.
+    pub fn expect_session_set_rf_test_config(
+        &mut self,
+        expected_session_id: SessionId,
+        expected_config_tlvs: Vec<RfTestConfigTlv>,
+        notfs: Vec<UciNotification>,
+        out: Result<RfTestConfigResponse>,
+    ) {
+        self.expected_calls.lock().unwrap().push_back(ExpectedCall::SessionSetRfTestConfig {
+            expected_session_id,
+            expected_config_tlvs,
+            notfs,
+            out,
+        });
+    }
+
+    /// Prepare Mock to expect rf_test_periodic_tx.
+    ///
+    /// MockUciManager expects call with parameters, returns out as response, followed by notfs
+    /// sent.
+    pub fn expect_test_periodic_tx(
+        &mut self,
+        expected_psdu_data: Vec<u8>,
+        notfs: Vec<UciNotification>,
+        out: Result<()>,
+    ) {
+        self.expected_calls.lock().unwrap().push_back(ExpectedCall::TestPeriodicTx {
+            expected_psdu_data,
+            notfs,
+            out,
+        });
+    }
+
+    /// Prepare Mock to expect StopRfTest.
+    ///
+    /// MockUciManager expects call with parameters, returns out as response
+    pub fn expect_stop_rf_test(&mut self, out: Result<()>) {
+        self.expected_calls.lock().unwrap().push_back(ExpectedCall::StopRfTest { out });
+    }
+
     /// Call Mock to send notifications.
     fn send_notifications(&self, notfs: Vec<UciNotification>) {
         for notf in notfs.into_iter() {
@@ -534,6 +580,9 @@ impl MockUciManager {
                 UciNotification::Vendor(notf) => {
                     let _ = self.vendor_notf_sender.send(notf);
                 }
+                UciNotification::RfTest(notf) => {
+                    let _ = self.rf_test_notf_sender.send(notf);
+                }
             }
         }
     }
@@ -581,6 +630,13 @@ impl UciManager for MockUciManager {
         self.radar_data_rcv_notf_sender = radar_data_rcv_notf_sender;
     }
 
+    async fn set_rf_test_notification_sender(
+        &mut self,
+        rf_test_notf_sender: mpsc::UnboundedSender<RfTestNotification>,
+    ) {
+        self.rf_test_notf_sender = rf_test_notf_sender;
+    }
+
     async fn open_hal(&self) -> Result<GetDeviceInfoResponse> {
         let mut expected_calls = self.expected_calls.lock().unwrap();
         match expected_calls.pop_front() {
@@ -1209,6 +1265,66 @@ impl UciManager for MockUciManager {
             None => Err(Error::MockUndefined),
         }
     }
+
+    async fn session_set_rf_test_config(
+        &self,
+        session_id: SessionId,
+        config_tlvs: Vec<RfTestConfigTlv>,
+    ) -> Result<RfTestConfigResponse> {
+        let mut expected_calls = self.expected_calls.lock().unwrap();
+        match expected_calls.pop_front() {
+            Some(ExpectedCall::SessionSetRfTestConfig {
+                expected_session_id,
+                expected_config_tlvs,
+                notfs,
+                out,
+            }) if expected_session_id == session_id
+                && rf_test_config_tlvs_eq(&expected_config_tlvs, &config_tlvs) =>
+            {
+                self.expect_call_consumed.notify_one();
+                self.send_notifications(notfs);
+                out
+            }
+            Some(call) => {
+                expected_calls.push_front(call);
+                Err(Error::MockUndefined)
+            }
+            None => Err(Error::MockUndefined),
+        }
+    }
+
+    async fn rf_test_periodic_tx(&self, psdu_data: Vec<u8>) -> Result<()> {
+        let mut expected_calls = self.expected_calls.lock().unwrap();
+        match expected_calls.pop_front() {
+            Some(ExpectedCall::TestPeriodicTx { expected_psdu_data, notfs, out })
+                if expected_psdu_data == psdu_data =>
+            {
+                self.expect_call_consumed.notify_one();
+                self.send_notifications(notfs);
+                out
+            }
+            Some(call) => {
+                expected_calls.push_front(call);
+                Err(Error::MockUndefined)
+            }
+            None => Err(Error::MockUndefined),
+        }
+    }
+
+    async fn stop_rf_test(&self) -> Result<()> {
+        let mut expected_calls = self.expected_calls.lock().unwrap();
+        match expected_calls.pop_front() {
+            Some(ExpectedCall::StopRfTest { out }) => {
+                self.expect_call_consumed.notify_one();
+                out
+            }
+            Some(call) => {
+                expected_calls.push_front(call);
+                Err(Error::MockUndefined)
+            }
+            None => Err(Error::MockUndefined),
+        }
+    }
 }
 
 #[derive(Clone)]
@@ -1355,4 +1471,18 @@ enum ExpectedCall {
         expected_slot_bitmap: Vec<u8>,
         out: Result<()>,
     },
+    SessionSetRfTestConfig {
+        expected_session_id: SessionId,
+        expected_config_tlvs: Vec<RfTestConfigTlv>,
+        notfs: Vec<UciNotification>,
+        out: Result<RfTestConfigResponse>,
+    },
+    TestPeriodicTx {
+        expected_psdu_data: Vec<u8>,
+        notfs: Vec<UciNotification>,
+        out: Result<()>,
+    },
+    StopRfTest {
+        out: Result<()>,
+    },
 }
diff --git a/src/rust/uwb_core/src/uci/notification.rs b/src/rust/uwb_core/src/uci/notification.rs
index 688199e..a0ee9a3 100644
--- a/src/rust/uwb_core/src/uci/notification.rs
+++ b/src/rust/uwb_core/src/uci/notification.rs
@@ -44,6 +44,8 @@ pub enum UciNotification {
     Session(SessionNotification),
     /// UciVendor_X_Notification equivalent.
     Vendor(RawUciMessage),
+    /// RfTestNotification equivalent
+    RfTest(RfTestNotification),
 }
 
 /// UCI CoreNotification.
@@ -114,6 +116,19 @@ pub enum SessionNotification {
     },
 }
 
+/// UCI RfTest Notification.
+#[derive(Debug, Clone, PartialEq)]
+pub enum RfTestNotification {
+    ///TestPeriodicTxNtf equivalent
+    TestPeriodicTxNtf {
+        /// Status
+        status: StatusCode,
+        /// The raw data of the notification message.
+        /// It's not at FiRa specification, only used by vendor's extension.
+        raw_notification_data: Vec<u8>,
+    },
+}
+
 /// The session range data.
 #[derive(Debug, Clone, PartialEq)]
 pub struct SessionRangeData {
@@ -366,7 +381,7 @@ impl TryFrom<(uwb_uci_packets::UciNotification, UCIMajorVersion, bool)> for UciN
             UciNotificationChild::UciVendor_B_Notification(evt) => vendor_notification(evt.into()),
             UciNotificationChild::UciVendor_E_Notification(evt) => vendor_notification(evt.into()),
             UciNotificationChild::UciVendor_F_Notification(evt) => vendor_notification(evt.into()),
-            UciNotificationChild::TestNotification(evt) => vendor_notification(evt.into()),
+            UciNotificationChild::TestNotification(evt) => Ok(Self::RfTest(evt.try_into()?)),
             _ => {
                 error!("Unknown UciNotification: {:?}", evt);
                 Err(Error::Unknown)
@@ -623,6 +638,24 @@ fn vendor_notification(evt: uwb_uci_packets::UciNotification) -> Result<UciNotif
     }))
 }
 
+impl TryFrom<uwb_uci_packets::TestNotification> for RfTestNotification {
+    type Error = Error;
+    fn try_from(evt: uwb_uci_packets::TestNotification) -> std::result::Result<Self, Self::Error> {
+        use uwb_uci_packets::TestNotificationChild;
+        let raw_ntf_data = evt.clone().encode_to_bytes().unwrap()[UCI_PACKET_HEADER_LEN..].to_vec();
+        match evt.specialize() {
+            TestNotificationChild::TestPeriodicTxNtf(evt) => Ok(Self::TestPeriodicTxNtf {
+                status: evt.get_status(),
+                raw_notification_data: raw_ntf_data,
+            }),
+            _ => {
+                error!("Unknown RfTestNotification: {:?}", evt);
+                Err(Error::Unknown)
+            }
+        }
+    }
+}
+
 fn get_vendor_uci_payload(evt: uwb_uci_packets::UciNotification) -> Result<Vec<u8>> {
     match evt.specialize() {
         uwb_uci_packets::UciNotificationChild::UciVendor_9_Notification(evt) => {
@@ -665,10 +698,6 @@ fn get_vendor_uci_payload(evt: uwb_uci_packets::UciNotification) -> Result<Vec<u
                 uwb_uci_packets::UciVendor_F_NotificationChild::None => Ok(Vec::new()),
             }
         }
-        uwb_uci_packets::UciNotificationChild::TestNotification(evt) => match evt.specialize() {
-            uwb_uci_packets::TestNotificationChild::Payload(payload) => Ok(payload.to_vec()),
-            uwb_uci_packets::TestNotificationChild::None => Ok(Vec::new()),
-        },
         _ => {
             error!("Unknown UciVendor packet: {:?}", evt);
             Err(Error::Unknown)
@@ -1419,18 +1448,25 @@ mod tests {
     }
 
     #[test]
-    fn test_test_to_vendor_notification_casting() {
-        let test_notification: uwb_uci_packets::UciNotification =
-            uwb_uci_packets::TestNotificationBuilder { opcode: 0x22, payload: None }.build().into();
-        let uci_fira_major_version = UCIMajorVersion::V1;
-        let test_uci_notification =
-            UciNotification::try_from((test_notification, uci_fira_major_version, false)).unwrap();
+    fn test_rf_test_notification_casting_from_rf_periodic_tx_ntf() {
+        let test_periodic_tx_ntf_packet = uwb_uci_packets::TestPeriodicTxNtfBuilder {
+            status: uwb_uci_packets::StatusCode::UciStatusOk,
+            vendor_data: vec![],
+        }
+        .build();
+        let raw_notification_data = test_periodic_tx_ntf_packet.clone().encode_to_bytes().unwrap()
+            [UCI_PACKET_HEADER_LEN..]
+            .to_vec();
+        let rf_test_notification =
+            uwb_uci_packets::TestNotification::try_from(test_periodic_tx_ntf_packet).unwrap();
+        let uci_notification = RfTestNotification::try_from(rf_test_notification).unwrap();
+        let uci_notification_from_periodic_tx_ntf = UciNotification::RfTest(uci_notification);
+        let status = uwb_uci_packets::StatusCode::UciStatusOk;
         assert_eq!(
-            test_uci_notification,
-            UciNotification::Vendor(RawUciMessage {
-                gid: 0x0d, // per enum Test GroupId in uci_packets.pdl
-                oid: 0x22,
-                payload: vec![],
+            uci_notification_from_periodic_tx_ntf,
+            UciNotification::RfTest(RfTestNotification::TestPeriodicTxNtf {
+                status,
+                raw_notification_data
             })
         );
     }
diff --git a/src/rust/uwb_core/src/uci/response.rs b/src/rust/uwb_core/src/uci/response.rs
index 74e8328..3dbfc59 100644
--- a/src/rust/uwb_core/src/uci/response.rs
+++ b/src/rust/uwb_core/src/uci/response.rs
@@ -19,8 +19,8 @@ use log::error;
 use crate::error::{Error, Result};
 use crate::params::uci_packets::{
     AndroidRadarConfigResponse, AppConfigTlv, CapTlv, CoreSetConfigResponse, DeviceConfigTlv,
-    GetDeviceInfoResponse, PowerStats, RadarConfigTlv, RawUciMessage, SessionHandle, SessionState,
-    SessionUpdateControllerMulticastListRspV1Payload,
+    GetDeviceInfoResponse, PowerStats, RadarConfigTlv, RawUciMessage, RfTestConfigResponse,
+    SessionHandle, SessionState, SessionUpdateControllerMulticastListRspV1Payload,
     SessionUpdateControllerMulticastListRspV2Payload, SessionUpdateControllerMulticastResponse,
     SessionUpdateDtTagRangingRoundsResponse, SetAppConfigResponse, StatusCode, UCIMajorVersion,
     UciControlPacket,
@@ -60,6 +60,8 @@ pub(super) enum UciResponse {
     SessionSetHybridControllerConfig(Result<()>),
     SessionSetHybridControleeConfig(Result<()>),
     SessionDataTransferPhaseConfig(Result<()>),
+    SessionSetRfTestConfig(RfTestConfigResponse),
+    RfTest(Result<()>),
 }
 
 impl UciResponse {
@@ -95,6 +97,8 @@ impl UciResponse {
             Self::SessionSetAppConfig(resp) => Self::matches_status_retry(&resp.status),
 
             Self::SessionQueryMaxDataSize(result) => Self::matches_result_retry(result),
+            Self::SessionSetRfTestConfig(resp) => Self::matches_status_retry(&resp.status),
+            Self::RfTest(result) => Self::matches_result_retry(result),
             // TODO(b/273376343): Implement retry logic for Data packet send.
             Self::SendUciData(_result) => false,
         }
@@ -124,6 +128,7 @@ impl TryFrom<(uwb_uci_packets::UciResponse, UCIMajorVersion, bool)> for UciRespo
             }
             UciResponseChild::SessionControlResponse(evt) => evt.try_into(),
             UciResponseChild::AndroidResponse(evt) => evt.try_into(),
+            UciResponseChild::TestResponse(evt) => evt.try_into(),
             UciResponseChild::UciVendor_9_Response(evt) => raw_response(evt.into()),
             UciResponseChild::UciVendor_A_Response(evt) => raw_response(evt.into()),
             UciResponseChild::UciVendor_B_Response(evt) => raw_response(evt.into()),
@@ -350,6 +355,28 @@ impl TryFrom<uwb_uci_packets::AndroidResponse> for UciResponse {
     }
 }
 
+impl TryFrom<uwb_uci_packets::TestResponse> for UciResponse {
+    type Error = Error;
+    fn try_from(evt: uwb_uci_packets::TestResponse) -> std::result::Result<Self, Self::Error> {
+        use uwb_uci_packets::TestResponseChild;
+        match evt.specialize() {
+            TestResponseChild::SessionSetRfTestConfigRsp(evt) => {
+                Ok(UciResponse::SessionSetRfTestConfig(RfTestConfigResponse {
+                    status: evt.get_status(),
+                    config_status: evt.get_cfg_status().clone(),
+                }))
+            }
+            TestResponseChild::TestPeriodicTxRsp(evt) => {
+                Ok(UciResponse::RfTest(status_code_to_result(evt.get_status())))
+            }
+            TestResponseChild::StopRfTestRsp(evt) => {
+                Ok(UciResponse::RfTest(status_code_to_result(evt.get_status())))
+            }
+            _ => Err(Error::Unknown),
+        }
+    }
+}
+
 fn raw_response(evt: uwb_uci_packets::UciResponse) -> Result<UciResponse> {
     let gid: u32 = evt.get_group_id().into();
     let oid: u32 = evt.get_opcode().into();
diff --git a/src/rust/uwb_core/src/uci/uci_manager.rs b/src/rust/uwb_core/src/uci/uci_manager.rs
index ce2e103..237e9a7 100644
--- a/src/rust/uwb_core/src/uci/uci_manager.rs
+++ b/src/rust/uwb_core/src/uci/uci_manager.rs
@@ -26,17 +26,18 @@ use crate::params::uci_packets::{
     AndroidRadarConfigResponse, AppConfigTlv, AppConfigTlvType, CapTlv, CapTlvType, Controlees,
     CoreSetConfigResponse, CountryCode, CreditAvailability, DeviceConfigId, DeviceConfigTlv,
     DeviceState, GetDeviceInfoResponse, GroupId, MessageType, PowerStats, RadarConfigTlv,
-    RadarConfigTlvType, RawUciMessage, ResetConfig, SessionId, SessionState, SessionToken,
-    SessionType, SessionUpdateControllerMulticastResponse, SessionUpdateDtTagRangingRoundsResponse,
-    SetAppConfigResponse, UciDataPacket, UciDataPacketHal, UpdateMulticastListAction, UpdateTime,
+    RadarConfigTlvType, RawUciMessage, ResetConfig, RfTestConfigResponse, RfTestConfigTlv,
+    SessionId, SessionState, SessionToken, SessionType, SessionUpdateControllerMulticastResponse,
+    SessionUpdateDtTagRangingRoundsResponse, SetAppConfigResponse, UciDataPacket, UciDataPacketHal,
+    UpdateMulticastListAction, UpdateTime,
 };
 use crate::params::utils::{bytes_to_u16, bytes_to_u64};
 use crate::params::UCIMajorVersion;
 use crate::uci::command::UciCommand;
 use crate::uci::message::UciMessage;
 use crate::uci::notification::{
-    CoreNotification, DataRcvNotification, RadarDataRcvNotification, SessionNotification,
-    SessionRangeData, UciNotification,
+    CoreNotification, DataRcvNotification, RadarDataRcvNotification, RfTestNotification,
+    SessionNotification, SessionRangeData, UciNotification,
 };
 use crate::uci::response::UciResponse;
 use crate::uci::timeout_uci_hal::TimeoutUciHal;
@@ -81,6 +82,10 @@ pub trait UciManager: 'static + Send + Sync + Clone {
         &mut self,
         radar_data_rcv_notf_sender: mpsc::UnboundedSender<RadarDataRcvNotification>,
     );
+    async fn set_rf_test_notification_sender(
+        &mut self,
+        rf_test_notf_sender: mpsc::UnboundedSender<RfTestNotification>,
+    );
 
     // Open the UCI HAL.
     // All the UCI commands should be called after the open_hal() completes successfully.
@@ -203,6 +208,13 @@ pub trait UciManager: 'static + Send + Sync + Clone {
         session_id: SessionId,
         controlee_phase_list: Vec<ControleePhaseList>,
     ) -> Result<()>;
+    async fn session_set_rf_test_config(
+        &self,
+        session_id: SessionId,
+        config_tlvs: Vec<RfTestConfigTlv>,
+    ) -> Result<RfTestConfigResponse>;
+    async fn rf_test_periodic_tx(&self, psdu_data: Vec<u8>) -> Result<()>;
+    async fn stop_rf_test(&self) -> Result<()>;
 }
 
 /// UciManagerImpl is the main implementation of UciManager. Using the actor model, UciManagerImpl
@@ -310,6 +322,14 @@ impl UciManager for UciManagerImpl {
             .await;
     }
 
+    async fn set_rf_test_notification_sender(
+        &mut self,
+        rf_test_notf_sender: mpsc::UnboundedSender<RfTestNotification>,
+    ) {
+        let _ =
+            self.send_cmd(UciManagerCmd::SetRfTestNotificationSender { rf_test_notf_sender }).await;
+    }
+
     async fn open_hal(&self) -> Result<GetDeviceInfoResponse> {
         match self.send_cmd(UciManagerCmd::OpenHal).await {
             Ok(UciResponse::OpenHal) => {
@@ -722,6 +742,40 @@ impl UciManager for UciManagerImpl {
             Err(e) => Err(e),
         }
     }
+
+    async fn session_set_rf_test_config(
+        &self,
+        session_id: SessionId,
+        config_tlvs: Vec<RfTestConfigTlv>,
+    ) -> Result<RfTestConfigResponse> {
+        let cmd = UciCommand::SessionSetRfTestConfig {
+            session_token: self.get_session_token(&session_id).await?,
+            config_tlvs,
+        };
+        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
+            Ok(UciResponse::SessionSetRfTestConfig(resp)) => Ok(resp),
+            Ok(_) => Err(Error::Unknown),
+            Err(e) => Err(e),
+        }
+    }
+
+    async fn rf_test_periodic_tx(&self, psdu_data: Vec<u8>) -> Result<()> {
+        let cmd = UciCommand::TestPeriodicTx { psdu_data };
+        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
+            Ok(UciResponse::RfTest(resp)) => resp,
+            Ok(_) => Err(Error::Unknown),
+            Err(e) => Err(e),
+        }
+    }
+
+    async fn stop_rf_test(&self) -> Result<()> {
+        let cmd = UciCommand::StopRfTest;
+        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
+            Ok(UciResponse::RfTest(resp)) => resp,
+            Ok(_) => Err(Error::Unknown),
+            Err(e) => Err(e),
+        }
+    }
 }
 
 struct UciManagerActor<T: UciHal, U: UciLogger> {
@@ -776,6 +830,7 @@ struct UciManagerActor<T: UciHal, U: UciLogger> {
     vendor_notf_sender: mpsc::UnboundedSender<RawUciMessage>,
     data_rcv_notf_sender: mpsc::UnboundedSender<DataRcvNotification>,
     radar_data_rcv_notf_sender: mpsc::UnboundedSender<RadarDataRcvNotification>,
+    rf_test_notf_sender: mpsc::UnboundedSender<RfTestNotification>,
 
     // Used to store the last init session id to help map the session handle sent
     // in session int response can be correctly mapped.
@@ -832,6 +887,7 @@ impl<T: UciHal, U: UciLogger> UciManagerActor<T, U> {
             vendor_notf_sender: mpsc::unbounded_channel().0,
             data_rcv_notf_sender: mpsc::unbounded_channel().0,
             radar_data_rcv_notf_sender: mpsc::unbounded_channel().0,
+            rf_test_notf_sender: mpsc::unbounded_channel().0,
             last_init_session_id: None,
             session_id_to_token_map,
             get_device_info_rsp: None,
@@ -1016,6 +1072,10 @@ impl<T: UciHal, U: UciLogger> UciManagerActor<T, U> {
                 self.radar_data_rcv_notf_sender = radar_data_rcv_notf_sender;
                 let _ = result_sender.send(Ok(UciResponse::SetNotification));
             }
+            UciManagerCmd::SetRfTestNotificationSender { rf_test_notf_sender } => {
+                self.rf_test_notf_sender = rf_test_notf_sender;
+                let _ = result_sender.send(Ok(UciResponse::SetNotification));
+            }
             UciManagerCmd::OpenHal => {
                 if self.is_hal_opened {
                     warn!("The UCI HAL is already opened, skip.");
@@ -1455,6 +1515,9 @@ impl<T: UciHal, U: UciLogger> UciManagerActor<T, U> {
                 }
                 let _ = self.session_notf_sender.send(mod_session_notf);
             }
+            UciNotification::RfTest(rftest_notf) => {
+                let _ = self.rf_test_notf_sender.send(rftest_notf);
+            }
             UciNotification::Vendor(vendor_notf) => {
                 let _ = self.vendor_notf_sender.send(vendor_notf);
             }
@@ -1686,6 +1749,9 @@ enum UciManagerCmd {
     SetRadarDataRcvNotificationSender {
         radar_data_rcv_notf_sender: mpsc::UnboundedSender<RadarDataRcvNotification>,
     },
+    SetRfTestNotificationSender {
+        rf_test_notf_sender: mpsc::UnboundedSender<RfTestNotification>,
+    },
     OpenHal,
     CloseHal {
         force: bool,
@@ -1712,7 +1778,7 @@ mod tests {
 
     use crate::params::uci_packets::{
         AppConfigStatus, AppConfigTlvType, BitsPerSample, CapTlvType, Controlee, DataRcvStatusCode,
-        DataTransferNtfStatusCode, RadarDataType, StatusCode,
+        DataTransferNtfStatusCode, RadarDataType, RfTestConfigTlvType, StatusCode,
     };
     use crate::params::UwbAddress;
     use crate::uci::mock_uci_hal::MockUciHal;
@@ -4358,4 +4424,41 @@ mod tests {
 
         assert!(mock_hal.wait_expected_calls_done().await);
     }
+
+    #[tokio::test]
+    async fn test_session_set_rf_config_ok() {
+        let session_id = 0x123;
+        let session_token = 0x123;
+        let config_tlv =
+            RfTestConfigTlv { cfg_id: RfTestConfigTlvType::NumPackets, v: vec![0x12, 0x34, 0x56] };
+        let config_tlv_clone = config_tlv.clone();
+
+        let (uci_manager, mut mock_hal) = setup_uci_manager_with_session_initialized(
+            |mut hal| async move {
+                let cmd = UciCommand::SessionSetRfTestConfig {
+                    session_token,
+                    config_tlvs: vec![config_tlv_clone],
+                };
+                let resp =
+                    into_uci_hal_packets(uwb_uci_packets::SessionSetRfTestConfigRspBuilder {
+                        status: uwb_uci_packets::StatusCode::UciStatusOk,
+                        cfg_status: vec![],
+                    });
+
+                hal.expected_send_command(cmd, resp, Ok(()));
+            },
+            UciLoggerMode::Disabled,
+            mpsc::unbounded_channel::<UciLogEvent>().0,
+            session_id,
+            session_token,
+        )
+        .await;
+
+        let expected_result =
+            RfTestConfigResponse { status: StatusCode::UciStatusOk, config_status: vec![] };
+        let result =
+            uci_manager.session_set_rf_test_config(session_id, vec![config_tlv]).await.unwrap();
+        assert_eq!(result, expected_result);
+        assert!(mock_hal.wait_expected_calls_done().await);
+    }
 }
diff --git a/src/rust/uwb_core/src/uci/uci_manager_sync.rs b/src/rust/uwb_core/src/uci/uci_manager_sync.rs
index acb6af7..b348cc3 100644
--- a/src/rust/uwb_core/src/uci/uci_manager_sync.rs
+++ b/src/rust/uwb_core/src/uci/uci_manager_sync.rs
@@ -28,14 +28,16 @@ use crate::error::{Error, Result};
 use crate::params::{
     AndroidRadarConfigResponse, AppConfigTlv, AppConfigTlvType, CapTlv, CoreSetConfigResponse,
     CountryCode, DeviceConfigId, DeviceConfigTlv, GetDeviceInfoResponse, PowerStats,
-    RadarConfigTlv, RadarConfigTlvType, RawUciMessage, ResetConfig, SessionId, SessionState,
-    SessionType, SessionUpdateControllerMulticastResponse, SessionUpdateDtTagRangingRoundsResponse,
+    RadarConfigTlv, RadarConfigTlvType, RawUciMessage, ResetConfig, RfTestConfigResponse,
+    RfTestConfigTlv, SessionId, SessionState, SessionType,
+    SessionUpdateControllerMulticastResponse, SessionUpdateDtTagRangingRoundsResponse,
     SetAppConfigResponse, UpdateMulticastListAction, UpdateTime,
 };
 #[cfg(any(test, feature = "mock-utils"))]
 use crate::uci::mock_uci_manager::MockUciManager;
 use crate::uci::notification::{
-    CoreNotification, DataRcvNotification, RadarDataRcvNotification, SessionNotification,
+    CoreNotification, DataRcvNotification, RadarDataRcvNotification, RfTestNotification,
+    SessionNotification,
 };
 use crate::uci::uci_hal::UciHal;
 use crate::uci::uci_logger::{UciLogger, UciLoggerMode};
@@ -68,6 +70,9 @@ pub trait NotificationManager: 'static {
         &mut self,
         radar_data_rcv_notification: RadarDataRcvNotification,
     ) -> Result<()>;
+
+    /// Callback for RF Test notification.
+    fn on_rf_test_notification(&mut self, rftest_notification: RfTestNotification) -> Result<()>;
 }
 
 /// Builder for NotificationManager. Builder is sent between threads.
@@ -84,6 +89,7 @@ struct NotificationDriver<U: NotificationManager> {
     vendor_notification_receiver: mpsc::UnboundedReceiver<RawUciMessage>,
     data_rcv_notification_receiver: mpsc::UnboundedReceiver<DataRcvNotification>,
     radar_data_rcv_notification_receiver: mpsc::UnboundedReceiver<RadarDataRcvNotification>,
+    rf_test_notification_receiver: mpsc::UnboundedReceiver<RfTestNotification>,
     notification_manager: U,
 }
 impl<U: NotificationManager> NotificationDriver<U> {
@@ -93,6 +99,7 @@ impl<U: NotificationManager> NotificationDriver<U> {
         vendor_notification_receiver: mpsc::UnboundedReceiver<RawUciMessage>,
         data_rcv_notification_receiver: mpsc::UnboundedReceiver<DataRcvNotification>,
         radar_data_rcv_notification_receiver: mpsc::UnboundedReceiver<RadarDataRcvNotification>,
+        rf_test_notification_receiver: mpsc::UnboundedReceiver<RfTestNotification>,
         notification_manager: U,
     ) -> Self {
         Self {
@@ -101,6 +108,7 @@ impl<U: NotificationManager> NotificationDriver<U> {
             vendor_notification_receiver,
             data_rcv_notification_receiver,
             radar_data_rcv_notification_receiver,
+            rf_test_notification_receiver,
             notification_manager,
         }
     }
@@ -132,6 +140,11 @@ impl<U: NotificationManager> NotificationDriver<U> {
                         error!("NotificationDriver: OnRadarDataRcv callback error: {:?}",e);
                 });
                 }
+                Some(ntf) = self.rf_test_notification_receiver.recv() =>{
+                    self.notification_manager.on_rf_test_notification(ntf).unwrap_or_else(|e|{
+                        error!("NotificationDriver: RF notification callback error: {:?}",e);
+                });
+                }
                 else =>{
                     debug!("NotificationDriver dropping.");
                     break;
@@ -168,6 +181,8 @@ impl<U: UciManager> UciManagerSync<U> {
             mpsc::unbounded_channel::<DataRcvNotification>();
         let (radar_data_rcv_notification_sender, radar_data_rcv_notification_receiver) =
             mpsc::unbounded_channel::<RadarDataRcvNotification>();
+        let (rftest_notification_sender, rf_test_notification_receiver) =
+            mpsc::unbounded_channel::<RfTestNotification>();
         self.runtime_handle.to_owned().block_on(async {
             self.uci_manager.set_core_notification_sender(core_notification_sender).await;
             self.uci_manager.set_session_notification_sender(session_notification_sender).await;
@@ -176,6 +191,7 @@ impl<U: UciManager> UciManagerSync<U> {
             self.uci_manager
                 .set_radar_data_rcv_notification_sender(radar_data_rcv_notification_sender)
                 .await;
+            self.uci_manager.set_rf_test_notification_sender(rftest_notification_sender).await;
         });
         // The potentially !Send NotificationManager is created in a separate thread.
         let (driver_status_sender, mut driver_status_receiver) = mpsc::unbounded_channel::<bool>();
@@ -209,6 +225,7 @@ impl<U: UciManager> UciManagerSync<U> {
                 vendor_notification_receiver,
                 data_rcv_notification_receiver,
                 radar_data_rcv_notification_receiver,
+                rf_test_notification_receiver,
                 notification_manager,
             );
             local.spawn_local(async move {
@@ -470,6 +487,26 @@ impl<U: UciManager> UciManagerSync<U> {
             slot_bitmap,
         ))
     }
+
+    /// Set rf test config.
+    pub fn session_set_rf_test_app_config(
+        &self,
+        session_id: SessionId,
+        config_tlvs: Vec<RfTestConfigTlv>,
+    ) -> Result<RfTestConfigResponse> {
+        self.runtime_handle
+            .block_on(self.uci_manager.session_set_rf_test_config(session_id, config_tlvs))
+    }
+
+    /// Test Periodic tx command
+    pub fn rf_test_periodic_tx(&self, psdu_data: Vec<u8>) -> Result<()> {
+        self.runtime_handle.block_on(self.uci_manager.rf_test_periodic_tx(psdu_data))
+    }
+
+    /// Test stop rf test command
+    pub fn stop_rf_test(&self) -> Result<()> {
+        self.runtime_handle.block_on(self.uci_manager.stop_rf_test())
+    }
 }
 
 impl UciManagerSync<UciManagerImpl> {
@@ -573,6 +610,15 @@ mod tests {
             self.nonsend_counter.replace_with(|&mut prev| prev + 1);
             Ok(())
         }
+        fn on_rf_test_notification(
+            &mut self,
+            rftest_notification: RfTestNotification,
+        ) -> Result<()> {
+            self.nonsend_counter.replace_with(|&mut prev| prev + 1);
+            self.notf_sender
+                .send(UciNotification::RfTest(rftest_notification))
+                .map_err(|_| Error::Unknown)
+        }
     }
 
     /// Builder for MockNotificationManager.
diff --git a/src/rust/uwb_uci_packets/uci_packets.pdl b/src/rust/uwb_uci_packets/uci_packets.pdl
index 765e2a8..04b13dc 100644
--- a/src/rust/uwb_uci_packets/uci_packets.pdl
+++ b/src/rust/uwb_uci_packets/uci_packets.pdl
@@ -94,6 +94,12 @@ enum AndroidOpCode : 6 {
     ANDROID_RADAR_GET_APP_CONFIG = 0x12,
 }
 
+enum TestOpCode : 6 {
+    RF_TEST_CONFIG_SET_COMMAND  = 0x0,
+    RF_TEST_CONFIG_GET_COMMAND  = 0x1,
+    RF_TEST_PERIODIC_TX_CMD = 0x2,
+}
+
 enum StatusCode : 8 {
     // Generic Status Codes
     UCI_STATUS_OK = 0x00,
@@ -287,6 +293,7 @@ enum AppConfigTlvType : 8 {
         CCC_PULSESHAPE_COMBO = 0xA5,
         CCC_URSK_TTL = 0xA6,
         CCC_LAST_INDEX_USED  = 0xA8,
+        ALIRO_MAC_MODE = 0xA9,
     },
 
     // Reserved for extension IDs.
@@ -356,6 +363,7 @@ enum CapTlvType : 8 {
         CCC_SUPPORTED_MIN_UWB_INITIATION_TIME_MS = 0xA9,
         CCC_PRIORITIZED_CHANNEL_LIST = 0xAA,
         CCC_SUPPORTED_UWBS_MAX_PPM = 0xAB,
+        ALIRO_SUPPORTED_MAC_MODES = 0xAC,
 
         // RADAR specific
         RADAR_SUPPORT = 0xB0
@@ -410,7 +418,7 @@ enum ReasonCode : 8 {
     RFU_REASON_CODE_RANGE_1 = 0x06..0x1C,
     ERROR_INVALID_UL_TDOA_RANDOM_WINDOW = 0x1D,
     ERROR_MIN_RFRAMES_PER_RR_NOT_SUPPORTED = 0x1E,
-    ERROR_TX_DELAY_NOT_SUPPORTED = 0x1F,
+    ERROR_INTER_FRAME_INTERVAL_NOT_SUPPORTED = 0x1F,
     ERROR_SLOT_LENGTH_NOT_SUPPORTED = 0x20,
     ERROR_INSUFFICIENT_SLOTS_PER_RR = 0x21,
     ERROR_MAC_ADDRESS_MODE_NOT_SUPPORTED = 0x22,
@@ -447,10 +455,12 @@ enum ReasonCode : 8 {
         ERROR_DT_ANCHOR_RANGING_ROUNDS_NOT_CONFIGURED = 0x40,
         ERROR_DT_TAG_RANGING_ROUNDS_NOT_CONFIGURED = 0x41,
     },
-    VENDOR_SPECIFIC_REASON_CODE_RANGE_1 = 0x80..0xFE {
+    VENDOR_SPECIFIC_REASON_CODE_RANGE_1 = 0x80..0xA1 {
         ERROR_INVALID_CHANNEL_WITH_AOA = 0x80,
         ERROR_STOPPED_DUE_TO_OTHER_SESSION_CONFLICT = 0x81,
     },
+    SESSION_STOPPED_DUE_TO_MAX_STS_INDEX_VALUE = 0xA2,
+    VENDOR_SPECIFIC_REASON_CODE_RANGE_2 = 0xA3..0xFE,
     // For internal usage, we will use 0xFF as default.
     VENDOR_SPECIFIC_REASON_CODE_2 = 0xFF,
 }
@@ -495,6 +505,20 @@ enum MessageType: 3 {
     RESERVED_FOR_TESTING_2 = 0x05,
 }
 
+enum RfTestConfigTlvType : 8 {
+    NUM_PACKETS = 0x00,
+    T_GAP = 0x01,
+    T_START = 0x02,
+    T_WIN = 0x03,
+    RANDOMIZE_PSDU = 0x04,
+    PHR_RANGING_BIT = 0x05,
+    RMARKER_TX_START = 0x06,
+    RMARKER_RX_START = 0x07,
+    STS_INDEX_AUTO_INCR = 0x08,
+    STS_DETECT_BITMAP = 0x09,
+    RFU_TEST_APP_CFG_TLV_TYPE_RANGE = 0x0A..0xFF,
+}
+
 // UCI packet description in compliance with the FIRA UCI spec.
 // Only this packet should be sent/expected across the HAL interface.
 packet UciPacketHal {
@@ -639,6 +663,18 @@ packet AndroidNotification : UciNotification (group_id = VENDOR_ANDROID) {
     _body_,
 }
 
+packet TestCommand : UciCommand (group_id = TEST) {
+    _body_,
+}
+
+packet TestResponse : UciResponse (group_id = TEST) {
+    _body_,
+}
+
+packet TestNotification : UciNotification (group_id = TEST) {
+    _body_,
+}
+
 // TODO: b/202760099: Use the correspnding opcode enum instead of the raw value in the |opcode| field.
 packet DeviceResetCmd : CoreCommand (opcode = 0x0) { //CORE_DEVICE_RESET
     reset_config: ResetConfig,
@@ -1540,10 +1576,6 @@ packet UciVendor_F_Notification : UciNotification (group_id = VENDOR_RESERVED_F)
     _payload_,
 }
 
-packet TestNotification : UciNotification (group_id = TEST) {
-    _payload_,
-}
-
 enum RadarDataType : 8 {
     RADAR_SWEEP_SAMPLES = 0x00,
 }
@@ -1628,3 +1660,68 @@ packet RadarDataRcv : UciDataPacket (data_packet_format = RADAR_DATA_MESSAGE, me
     sweep_data: 8[],
 }
 
+struct RfTestConfigTlv {
+    cfg_id: RfTestConfigTlvType,
+    _count_(v): 8,
+    v: 8[],
+}
+
+packet SessionSetRfTestConfigCmd : TestCommand (opcode = 0x00) {
+    session_token: 32, // Session ID or Session Handle (based on UWBS version)
+    _count_(tlvs): 8,
+    tlvs: RfTestConfigTlv[]
+}
+
+test SessionSetRfTestConfigCmd {
+    "\x2D\x00\x00\x08\x01\x00\x00\x0D\x01\x08\x01\x00",
+}
+
+struct RfTestConfigStatus {
+    cfg_id: RfTestConfigTlvType,
+    status: StatusCode,
+}
+
+packet SessionSetRfTestConfigRsp : TestResponse (opcode = 0x00) {
+    status: StatusCode,
+    _count_(cfg_status): 8,
+    cfg_status: RfTestConfigStatus[],
+}
+
+test SessionSetRfTestConfigRsp {
+    "\x4D\x00\x00\x02\x00\x00",
+}
+
+packet TestPeriodicTxCmd : TestCommand (opcode = 0x02) {
+    psdu_data : 8[],
+}
+
+test TestPeriodicTxCmd {
+    "\x2D\x02\x00\x0a\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
+}
+
+packet TestPeriodicTxRsp : TestResponse (opcode = 0x02) {
+    status: StatusCode,
+}
+
+test TestPeriodicTxRsp {
+    "\x4D\x02\x00\x01\x00",
+}
+
+packet TestPeriodicTxNtf : TestNotification (opcode = 0x02) {
+    status: StatusCode,
+    vendor_data: 8[],
+}
+
+test TestPeriodicTxNtf {
+    "\x6D\x02\x00\x01\x00",
+}
+
+packet StopRfTestCmd : TestCommand (opcode = 0x07) { }
+
+test StopRfTestCmd { "\x2D\x07\x00\x00", }
+
+packet StopRfTestRsp : TestResponse (opcode = 0x07) {
+    status: StatusCode,
+}
+
+test StopRfTestRsp { "\x4D\x07\x00\x01\x00", }
```

