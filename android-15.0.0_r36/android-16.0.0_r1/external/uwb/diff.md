```diff
diff --git a/OWNERS b/OWNERS
index 3c40e93..b6f8933 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@ include platform/packages/modules/Uwb:/OWNERS
 
 # This repo is shared with ChromeOS, so add the ChromeOS UWB team as the owners.
 # include /OWNERS_chromeos
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/src/Android.bp b/src/Android.bp
index 875197a..e7d8c9d 100755
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -278,6 +278,7 @@ rust_defaults {
     ],
     apex_available: [
         "com.android.uwb",
+        "//apex_available:platform",
     ],
     min_sdk_version: "Tiramisu",
     srcs: [
diff --git a/src/rust/uwb_core/protos/uwb_service.proto b/src/rust/uwb_core/protos/uwb_service.proto
index ff4b335..71b2f05 100644
--- a/src/rust/uwb_core/protos/uwb_service.proto
+++ b/src/rust/uwb_core/protos/uwb_service.proto
@@ -195,6 +195,7 @@ enum SessionType {
   FIRA_RANGING_ONLY_PHASE = 0x03;
   FIRA_IN_BAND_DATA_PHASE = 0x04;
   FIRA_RANGING_WITH_DATA_PHASE = 0x05;
+  FIRA_HUS_PRIMARY_SESSION = 0x9F;
   CCC = 0xA0;
   RADAR_SESSION = 0xA1;
   ALIRO = 0xA2;
diff --git a/src/rust/uwb_core/src/params/uci_packets.rs b/src/rust/uwb_core/src/params/uci_packets.rs
index e034cf8..54e7ae2 100644
--- a/src/rust/uwb_core/src/params/uci_packets.rs
+++ b/src/rust/uwb_core/src/params/uci_packets.rs
@@ -24,13 +24,13 @@ use num_derive::{FromPrimitive, ToPrimitive};
 pub use uwb_uci_packets::{
     AppConfigStatus, AppConfigTlv as RawAppConfigTlv, AppConfigTlvType, BitsPerSample, CapTlv,
     CapTlvType, Controlee, ControleePhaseList, ControleeStatusV1, ControleeStatusV2, Controlees,
-    CreditAvailability, DataRcvStatusCode, DataTransferNtfStatusCode,
+    ControllerPhaseList, CreditAvailability, DataRcvStatusCode, DataTransferNtfStatusCode,
     DataTransferPhaseConfigUpdateStatusCode, DeviceConfigId, DeviceConfigStatus, DeviceConfigTlv,
     DeviceState, ExtendedAddressDlTdoaRangingMeasurement, ExtendedAddressOwrAoaRangingMeasurement,
     ExtendedAddressTwoWayRangingMeasurement, GroupId, MacAddressIndicator, MessageType,
-    MulticastUpdateStatusCode, PhaseList, PowerStats, RadarConfigStatus, RadarConfigTlv,
-    RadarConfigTlvType, RadarDataType, RangingMeasurementType, ReasonCode, ResetConfig,
-    RfTestConfigStatus, RfTestConfigTlv, RfTestConfigTlvType, SessionState, SessionType,
+    MulticastUpdateStatusCode, PowerStats, RadarConfigStatus, RadarConfigTlv, RadarConfigTlvType,
+    RadarDataType, RangingMeasurementType, ReasonCode, ResetConfig, RfTestConfigStatus,
+    RfTestConfigTlv, RfTestConfigTlvType, SessionState, SessionType,
     SessionUpdateControllerMulticastListNtfV1Payload,
     SessionUpdateControllerMulticastListNtfV2Payload,
     SessionUpdateControllerMulticastListRspV1Payload,
@@ -66,13 +66,15 @@ pub enum ControleeStatusList {
 }
 
 /// UCI major version
-#[derive(FromPrimitive, ToPrimitive, PartialEq, Clone)]
+#[derive(FromPrimitive, ToPrimitive, PartialEq, Clone, PartialOrd, Ord, Eq)]
 #[repr(u8)]
 pub enum UCIMajorVersion {
     /// Version 1.x
     V1 = 1,
     /// Version 2.0
     V2 = 2,
+    /// Version 3.0
+    V3 = 3,
 }
 
 impl std::fmt::Debug for AppConfigTlv {
@@ -264,23 +266,6 @@ impl TryFrom<String> for CountryCode {
     }
 }
 
-/// absolute time in UWBS Time domain(ms) when this configuration applies
-#[derive(Debug, Clone, PartialEq, Copy)]
-pub struct UpdateTime([u8; 8]);
-
-impl UpdateTime {
-    /// Create a UpdateTime instance.
-    pub fn new(update_time: &[u8; 8]) -> Option<Self> {
-        Some(Self(*update_time))
-    }
-}
-
-impl From<UpdateTime> for [u8; 8] {
-    fn from(item: UpdateTime) -> [u8; 8] {
-        item.0
-    }
-}
-
 /// The response of the UciManager::core_get_device_info() method.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct GetDeviceInfoResponse {
diff --git a/src/rust/uwb_core/src/proto/mappings.rs b/src/rust/uwb_core/src/proto/mappings.rs
index ccf0a4c..095d2d9 100644
--- a/src/rust/uwb_core/src/proto/mappings.rs
+++ b/src/rust/uwb_core/src/proto/mappings.rs
@@ -545,6 +545,7 @@ enum_mapping! {
     FIRA_RANGING_ONLY_PHASE => FiraRangingOnlyPhase,
     FIRA_IN_BAND_DATA_PHASE => FiraInBandDataPhase,
     FIRA_RANGING_WITH_DATA_PHASE => FiraRangingWithDataPhase,
+    FIRA_HUS_PRIMARY_SESSION => FiraHusPrimarySession,
     CCC => Ccc,
     RADAR_SESSION => RadarSession,
     ALIRO => Aliro,
diff --git a/src/rust/uwb_core/src/session/session_manager.rs b/src/rust/uwb_core/src/session/session_manager.rs
index feb32b7..b03964c 100644
--- a/src/rust/uwb_core/src/session/session_manager.rs
+++ b/src/rust/uwb_core/src/session/session_manager.rs
@@ -534,6 +534,7 @@ pub(crate) mod test_utils {
             session_token: session_id,
             current_ranging_interval_ms: 3,
             ranging_measurement_type: RangingMeasurementType::TwoWay,
+            hus_primary_session_id: 0,
             ranging_measurements: RangingMeasurements::ShortAddressTwoWay(vec![
                 ShortAddressTwoWayRangingMeasurement {
                     mac_address: 0x123,
diff --git a/src/rust/uwb_core/src/uci.rs b/src/rust/uwb_core/src/uci.rs
index a102d60..82577d8 100644
--- a/src/rust/uwb_core/src/uci.rs
+++ b/src/rust/uwb_core/src/uci.rs
@@ -42,7 +42,7 @@ pub mod mock_uci_manager;
 pub use command::UciCommand;
 pub use notification::{
     CoreNotification, DataRcvNotification, RadarDataRcvNotification, RadarSweepData,
-    RangingMeasurements, RfTestNotification, SessionNotification, SessionRangeData,
+    RangingMeasurements, RfTestNotification, RfTestPerRxData, SessionNotification, SessionRangeData,
     UciNotification,
 };
 pub use uci_hal::{NopUciHal, UciHal, UciHalPacket};
diff --git a/src/rust/uwb_core/src/uci/command.rs b/src/rust/uwb_core/src/uci/command.rs
index f603238..9bc0aef 100644
--- a/src/rust/uwb_core/src/uci/command.rs
+++ b/src/rust/uwb_core/src/uci/command.rs
@@ -21,12 +21,11 @@ use crate::error::{Error, Result};
 use crate::params::uci_packets::{
     AppConfigTlv, AppConfigTlvType, Controlees, CountryCode, DeviceConfigId, DeviceConfigTlv,
     RadarConfigTlv, RadarConfigTlvType, ResetConfig, RfTestConfigTlv, SessionId, SessionToken,
-    SessionType, UpdateMulticastListAction, UpdateTime,
+    SessionType, UpdateMulticastListAction,
 };
 use uwb_uci_packets::{
-    build_data_transfer_phase_config_cmd, build_session_set_hybrid_controller_config_cmd,
-    build_session_update_controller_multicast_list_cmd, ControleePhaseList, GroupId, MessageType,
-    PhaseList,
+    build_data_transfer_phase_config_cmd, build_session_update_controller_multicast_list_cmd,
+    ControleePhaseList, ControllerPhaseList, GroupId, MessageType,
 };
 
 /// The enum to represent the UCI commands. The definition of each field should follow UCI spec.
@@ -89,10 +88,8 @@ pub enum UciCommand {
     },
     SessionSetHybridControllerConfig {
         session_token: SessionToken,
-        message_control: u8,
         number_of_phases: u8,
-        update_time: UpdateTime,
-        phase_list: PhaseList,
+        phase_list: Vec<ControllerPhaseList>,
     },
     SessionSetHybridControleeConfig {
         session_token: SessionToken,
@@ -105,6 +102,7 @@ pub enum UciCommand {
         dtpml_size: u8,
         mac_address: Vec<u8>,
         slot_bitmap: Vec<u8>,
+        stop_data_transfer: Vec<u8>,
     },
     AndroidSetCountryCode {
         country_code: CountryCode,
@@ -131,6 +129,9 @@ pub enum UciCommand {
     TestPeriodicTx {
         psdu_data: Vec<u8>,
     },
+    TestPerRx {
+        psdu_data: Vec<u8>,
+    },
     StopRfTest,
 }
 
@@ -250,18 +251,14 @@ impl TryFrom<UciCommand> for uwb_uci_packets::UciControlPacket {
             }
             UciCommand::SessionSetHybridControllerConfig {
                 session_token,
-                message_control,
                 number_of_phases,
-                update_time,
                 phase_list,
-            } => build_session_set_hybrid_controller_config_cmd(
+            } => uwb_uci_packets::SessionSetHybridControllerConfigCmdBuilder {
                 session_token,
-                message_control,
                 number_of_phases,
-                update_time.into(),
                 phase_list,
-            )
-            .map_err(|_| Error::BadParameters)?
+            }
+            .build()
             .into(),
             UciCommand::SessionSetHybridControleeConfig { session_token, controlee_phase_list } => {
                 uwb_uci_packets::SessionSetHybridControleeConfigCmdBuilder {
@@ -278,6 +275,7 @@ impl TryFrom<UciCommand> for uwb_uci_packets::UciControlPacket {
                 dtpml_size,
                 mac_address,
                 slot_bitmap,
+                stop_data_transfer,
             } => build_data_transfer_phase_config_cmd(
                 session_token,
                 dtpcm_repetition,
@@ -285,6 +283,7 @@ impl TryFrom<UciCommand> for uwb_uci_packets::UciControlPacket {
                 dtpml_size,
                 mac_address,
                 slot_bitmap,
+                stop_data_transfer,
             )
             .map_err(|_| Error::BadParameters)?
             .into(),
@@ -299,6 +298,9 @@ impl TryFrom<UciCommand> for uwb_uci_packets::UciControlPacket {
             UciCommand::TestPeriodicTx { psdu_data } => {
                 uwb_uci_packets::TestPeriodicTxCmdBuilder { psdu_data }.build().into()
             }
+            UciCommand::TestPerRx { psdu_data } => {
+                uwb_uci_packets::TestPerRxCmdBuilder { psdu_data }.build().into()
+            }
             UciCommand::StopRfTest {} => uwb_uci_packets::StopRfTestCmdBuilder {}.build().into(),
         };
         Ok(packet)
@@ -334,7 +336,6 @@ fn build_raw_uci_cmd_packet(
 #[cfg(test)]
 mod tests {
     use super::*;
-    use uwb_uci_packets::PhaseListShortMacAddress;
 
     #[test]
     fn test_build_raw_uci_cmd() {
@@ -532,38 +533,32 @@ mod tests {
                 .expect("Failed to build raw cmd packet.")
         );
 
-        let phase_list_short_mac_address = PhaseListShortMacAddress {
+        let phase_list_short_mac_address = vec![uwb_uci_packets::ControllerPhaseList {
             session_token: 0x1324_3546,
             start_slot_index: 0x1111,
             end_slot_index: 0x1121,
-            phase_participation: 0x0,
-            mac_address: [0x1, 0x2],
-        };
+            control: 0x01,
+            mac_address: [0x1, 0x2].to_vec(),
+        }];
         cmd = UciCommand::SessionSetHybridControllerConfig {
             session_token: 1,
-            message_control: 0,
             number_of_phases: 0,
-            update_time: UpdateTime::new(&[1; 8]).unwrap(),
-            phase_list: PhaseList::ShortMacAddress(vec![phase_list_short_mac_address]),
+            phase_list: vec![uwb_uci_packets::ControllerPhaseList {
+                session_token: 0x1324_3546,
+                start_slot_index: 0x1111,
+                end_slot_index: 0x1121,
+                control: 0x01,
+                mac_address: [0x1, 0x2].to_vec(),
+            }],
         };
         packet = uwb_uci_packets::UciControlPacket::try_from(cmd).unwrap();
+        let phase_list_clone = phase_list_short_mac_address.clone();
         assert_eq!(
             packet,
             uwb_uci_packets::SessionSetHybridControllerConfigCmdBuilder {
-                message_control: 0,
-                number_of_phases: 0,
                 session_token: 1,
-                update_time: [1; 8],
-                payload: Some(
-                    vec![
-                        0x46, 0x35, 0x24, 0x13, // session id (LE)
-                        0x11, 0x11, // start slot index (LE)
-                        0x21, 0x11, // end slot index (LE)
-                        0x00, // phase_participation
-                        0x01, 0x02
-                    ]
-                    .into()
-                )
+                number_of_phases: 0,
+                phase_list: phase_list_clone,
             }
             .build()
             .into()
@@ -591,6 +586,7 @@ mod tests {
             dtpml_size: 1,
             mac_address: vec![0, 1],
             slot_bitmap: vec![2, 3],
+            stop_data_transfer: vec![0],
         };
         packet = uwb_uci_packets::UciControlPacket::try_from(cmd).unwrap();
         assert_eq!(
@@ -600,7 +596,7 @@ mod tests {
                 dtpcm_repetition: 0,
                 data_transfer_control: 2,
                 dtpml_size: 1,
-                payload: Some(vec![0x00, 0x01, 0x02, 0x03].into()),
+                payload: Some(vec![0x00, 0x01, 0x02, 0x03, 0x00].into()),
             }
             .build()
             .into()
@@ -621,5 +617,12 @@ mod tests {
             packet,
             uwb_uci_packets::TestPeriodicTxCmdBuilder { psdu_data: vec![0] }.build().into()
         );
+
+        cmd = UciCommand::TestPerRx { psdu_data: vec![0] };
+        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
+        assert_eq!(
+            packet,
+            uwb_uci_packets::TestPerRxCmdBuilder { psdu_data: vec![0] }.build().into()
+        );
     }
 }
diff --git a/src/rust/uwb_core/src/uci/mock_uci_manager.rs b/src/rust/uwb_core/src/uci/mock_uci_manager.rs
index cbd8538..55fcabb 100644
--- a/src/rust/uwb_core/src/uci/mock_uci_manager.rs
+++ b/src/rust/uwb_core/src/uci/mock_uci_manager.rs
@@ -29,12 +29,11 @@ use crate::error::{Error, Result};
 use crate::params::uci_packets::{
     app_config_tlvs_eq, device_config_tlvs_eq, radar_config_tlvs_eq, rf_test_config_tlvs_eq,
     AndroidRadarConfigResponse, AppConfigTlv, AppConfigTlvType, CapTlv, ControleePhaseList,
-    Controlees, CoreSetConfigResponse, CountryCode, DeviceConfigId, DeviceConfigTlv,
-    GetDeviceInfoResponse, PhaseList, PowerStats, RadarConfigTlv, RadarConfigTlvType,
+    Controlees, ControllerPhaseList, CoreSetConfigResponse, CountryCode, DeviceConfigId,
+    DeviceConfigTlv, GetDeviceInfoResponse, PowerStats, RadarConfigTlv, RadarConfigTlvType,
     RawUciMessage, ResetConfig, RfTestConfigResponse, RfTestConfigTlv, SessionId, SessionState,
     SessionToken, SessionType, SessionUpdateControllerMulticastResponse,
     SessionUpdateDtTagRangingRoundsResponse, SetAppConfigResponse, UpdateMulticastListAction,
-    UpdateTime,
 };
 use crate::uci::notification::{
     CoreNotification, DataRcvNotification, RadarDataRcvNotification, RfTestNotification,
@@ -462,18 +461,14 @@ impl MockUciManager {
     pub fn expect_session_set_hybrid_controller_config(
         &mut self,
         expected_session_id: SessionId,
-        expected_message_control: u8,
         expected_number_of_phases: u8,
-        expected_update_time: UpdateTime,
-        expected_phase_list: PhaseList,
+        expected_phase_list: Vec<ControllerPhaseList>,
         out: Result<()>,
     ) {
         self.expected_calls.lock().unwrap().push_back(
             ExpectedCall::SessionSetHybridControllerConfig {
                 expected_session_id,
-                expected_message_control,
                 expected_number_of_phases,
-                expected_update_time,
                 expected_phase_list,
                 out,
             },
@@ -509,6 +504,7 @@ impl MockUciManager {
         expected_dtpml_size: u8,
         expected_mac_address: Vec<u8>,
         expected_slot_bitmap: Vec<u8>,
+        expected_stop_data_transfer: Vec<u8>,
         out: Result<()>,
     ) {
         self.expected_calls.lock().unwrap().push_back(
@@ -519,6 +515,7 @@ impl MockUciManager {
                 expected_dtpml_size,
                 expected_mac_address,
                 expected_slot_bitmap,
+                expected_stop_data_transfer,
                 out,
             },
         );
@@ -560,6 +557,23 @@ impl MockUciManager {
         });
     }
 
+    /// Prepare Mock to expect rf_test_per_rx.
+    ///
+    /// MockUciManager expects call with parameters, returns out as response, followed by notfs
+    /// sent.
+    pub fn expect_test_per_rx(
+        &mut self,
+        expected_psdu_data: Vec<u8>,
+        notfs: Vec<UciNotification>,
+        out: Result<()>,
+    ) {
+        self.expected_calls.lock().unwrap().push_back(ExpectedCall::TestPerRx {
+            expected_psdu_data,
+            notfs,
+            out,
+        });
+    }
+
     /// Prepare Mock to expect StopRfTest.
     ///
     /// MockUciManager expects call with parameters, returns out as response
@@ -931,6 +945,7 @@ impl UciManager for MockUciManager {
         dtpml_size: u8,
         mac_address: Vec<u8>,
         slot_bitmap: Vec<u8>,
+        stop_data_transfer: Vec<u8>,
     ) -> Result<()> {
         let mut expected_calls = self.expected_calls.lock().unwrap();
         match expected_calls.pop_front() {
@@ -941,13 +956,15 @@ impl UciManager for MockUciManager {
                 expected_dtpml_size,
                 expected_mac_address,
                 expected_slot_bitmap,
+                expected_stop_data_transfer,
                 out,
             }) if expected_session_id == session_id
                 && expected_dtpcm_repetition == dtpcm_repetition
                 && expected_data_transfer_control == data_transfer_control
                 && expected_dtpml_size == dtpml_size
                 && expected_mac_address == mac_address
-                && expected_slot_bitmap == slot_bitmap =>
+                && expected_slot_bitmap == slot_bitmap
+                && expected_stop_data_transfer == stop_data_transfer =>
             {
                 self.expect_call_consumed.notify_one();
                 out
@@ -1209,24 +1226,18 @@ impl UciManager for MockUciManager {
     async fn session_set_hybrid_controller_config(
         &self,
         session_id: SessionId,
-        message_control: u8,
         number_of_phases: u8,
-        update_time: UpdateTime,
-        phase_lists: PhaseList,
+        phase_lists: Vec<ControllerPhaseList>,
     ) -> Result<()> {
         let mut expected_calls = self.expected_calls.lock().unwrap();
         match expected_calls.pop_front() {
             Some(ExpectedCall::SessionSetHybridControllerConfig {
                 expected_session_id,
-                expected_message_control,
                 expected_number_of_phases,
-                expected_update_time,
                 expected_phase_list,
                 out,
             }) if expected_session_id == session_id
-                && expected_message_control == message_control
                 && expected_number_of_phases == number_of_phases
-                && expected_update_time == update_time
                 && expected_phase_list == phase_lists =>
             {
                 self.expect_call_consumed.notify_one();
@@ -1311,6 +1322,24 @@ impl UciManager for MockUciManager {
         }
     }
 
+    async fn rf_test_per_rx(&self, psdu_data: Vec<u8>) -> Result<()> {
+        let mut expected_calls = self.expected_calls.lock().unwrap();
+        match expected_calls.pop_front() {
+            Some(ExpectedCall::TestPerRx { expected_psdu_data, notfs, out })
+            if expected_psdu_data == psdu_data =>
+                {
+                    self.expect_call_consumed.notify_one();
+                    self.send_notifications(notfs);
+                    out
+                }
+            Some(call) => {
+                expected_calls.push_front(call);
+                Err(Error::MockUndefined)
+            }
+            None => Err(Error::MockUndefined),
+        }
+    }
+
     async fn stop_rf_test(&self) -> Result<()> {
         let mut expected_calls = self.expected_calls.lock().unwrap();
         match expected_calls.pop_front() {
@@ -1451,10 +1480,8 @@ enum ExpectedCall {
     },
     SessionSetHybridControllerConfig {
         expected_session_id: SessionId,
-        expected_message_control: u8,
         expected_number_of_phases: u8,
-        expected_update_time: UpdateTime,
-        expected_phase_list: PhaseList,
+        expected_phase_list: Vec<ControllerPhaseList>,
         out: Result<()>,
     },
     SessionSetHybridControleeConfig {
@@ -1469,6 +1496,7 @@ enum ExpectedCall {
         expected_dtpml_size: u8,
         expected_mac_address: Vec<u8>,
         expected_slot_bitmap: Vec<u8>,
+        expected_stop_data_transfer: Vec<u8>,
         out: Result<()>,
     },
     SessionSetRfTestConfig {
@@ -1482,6 +1510,11 @@ enum ExpectedCall {
         notfs: Vec<UciNotification>,
         out: Result<()>,
     },
+    TestPerRx {
+        expected_psdu_data: Vec<u8>,
+        notfs: Vec<UciNotification>,
+        out: Result<()>,
+    },
     StopRfTest {
         out: Result<()>,
     },
diff --git a/src/rust/uwb_core/src/uci/notification.rs b/src/rust/uwb_core/src/uci/notification.rs
index a0ee9a3..0c71d18 100644
--- a/src/rust/uwb_core/src/uci/notification.rs
+++ b/src/rust/uwb_core/src/uci/notification.rs
@@ -127,6 +127,8 @@ pub enum RfTestNotification {
         /// It's not at FiRa specification, only used by vendor's extension.
         raw_notification_data: Vec<u8>,
     },
+    /// TestPerRxNtf equivalent
+    TestPerRxNtf(RfTestPerRxData),
 }
 
 /// The session range data.
@@ -144,6 +146,9 @@ pub struct SessionRangeData {
     /// The ranging measurement type.
     pub ranging_measurement_type: RangingMeasurementType,
 
+    /// Hus primary session Session Id
+    pub hus_primary_session_id: SessionToken,
+
     /// The ranging measurement data.
     pub ranging_measurements: RangingMeasurements,
 
@@ -155,6 +160,56 @@ pub struct SessionRangeData {
     pub raw_ranging_data: Vec<u8>,
 }
 
+/// PER RX NTF Data
+#[derive(Debug, Clone, PartialEq)]
+pub struct RfTestPerRxData {
+    /// Status
+    pub status: StatusCode,
+
+    /// Number of RX attempts.
+    pub attempts: u32,
+
+    /// Number of times signal was detected.
+    pub acq_detect: u32,
+
+    /// Number of times signal was rejected.
+    pub acq_reject: u32,
+
+    /// Number of times RX did not go beyound ACQ stage.
+    pub rx_fail: u32,
+
+    /// Number of times sync CIR ready event was received.
+    pub sync_cir_ready: u32,
+
+    /// Number of times RX was stuck at either ACQ detect or sync CIR ready.
+    pub sfd_fail: u32,
+
+    /// Number of times SFD was found.
+    pub sfd_found: u32,
+
+    /// Number of times PHR decode failed.
+    pub phr_dec_error: u32,
+
+    /// Number of times PHR bits in error.
+    pub phr_bit_error: u32,
+
+    /// Number of times payload decode failed.
+    pub psdu_dec_error: u32,
+
+    /// Number of times payload bits in error.
+    pub psdu_bit_error: u32,
+
+    /// Number of times STS detection was successful.
+    pub sts_found: u32,
+
+    /// Number of times end of frame event was triggered.
+    pub eof: u32,
+
+    /// The raw data of the notification message.
+    /// It's not at FiRa specification, only used by vendor's extension.
+    pub raw_notification_data: Vec<u8>,
+}
+
 /// The ranging measurements.
 #[derive(Debug, Clone, PartialEq)]
 pub enum RangingMeasurements {
@@ -450,7 +505,7 @@ impl TryFrom<(uwb_uci_packets::SessionConfigNotification, UCIMajorVersion, bool)
                 })
             }
             SessionConfigNotificationChild::SessionUpdateControllerMulticastListNtf(evt)
-                if uci_fira_major_ver == UCIMajorVersion::V2 =>
+                if uci_fira_major_ver >= UCIMajorVersion::V2 =>
             {
                 let payload = evt.get_payload();
                 let multicast_update_list_payload_v2 =
@@ -606,6 +661,7 @@ impl TryFrom<uwb_uci_packets::SessionInfoNtf> for SessionNotification {
             session_token: evt.get_session_token(),
             current_ranging_interval_ms: evt.get_current_ranging_interval(),
             ranging_measurement_type: evt.get_ranging_measurement_type(),
+            hus_primary_session_id: evt.get_hus_primary_session_id(),
             ranging_measurements,
             rcr_indicator: evt.get_rcr_indicator(),
             raw_ranging_data,
@@ -648,6 +704,23 @@ impl TryFrom<uwb_uci_packets::TestNotification> for RfTestNotification {
                 status: evt.get_status(),
                 raw_notification_data: raw_ntf_data,
             }),
+            TestNotificationChild::TestPerRxNtf(evt) => Ok(Self::TestPerRxNtf (RfTestPerRxData {
+                status: evt.get_status(),
+                attempts: evt.get_attempts(),
+                acq_detect: evt.get_acq_detect(),
+                acq_reject: evt.get_acq_reject(),
+                rx_fail: evt.get_rx_fail(),
+                sync_cir_ready: evt.get_sync_cir_ready(),
+                sfd_fail: evt.get_sfd_fail(),
+                sfd_found: evt.get_sfd_found(),
+                phr_dec_error: evt.get_phr_dec_error(),
+                phr_bit_error: evt.get_phr_bit_error(),
+                psdu_dec_error: evt.get_psdu_dec_error(),
+                psdu_bit_error: evt.get_psdu_bit_error(),
+                sts_found: evt.get_sts_found(),
+                eof: evt.get_eof(),
+                raw_notification_data: raw_ntf_data,
+            })),
             _ => {
                 error!("Unknown RfTestNotification: {:?}", evt);
                 Err(Error::Unknown)
@@ -797,6 +870,7 @@ mod tests {
                 session_token: 0x11,
                 rcr_indicator: 0x12,
                 current_ranging_interval: 0x13,
+                hus_primary_session_id: 0x00,
                 two_way_ranging_measurements: vec![extended_measurement.clone()],
                 vendor_data: vec![],
             }
@@ -815,6 +889,7 @@ mod tests {
                 sequence_number: 0x10,
                 session_token: 0x11,
                 ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::TwoWay,
+                hus_primary_session_id: 0x00,
                 current_ranging_interval_ms: 0x13,
                 ranging_measurements: RangingMeasurements::ExtendedAddressTwoWay(vec![
                     extended_measurement
@@ -848,6 +923,7 @@ mod tests {
             session_token: 0x11,
             rcr_indicator: 0x12,
             current_ranging_interval: 0x13,
+            hus_primary_session_id: 0x00,
             two_way_ranging_measurements: vec![short_measurement.clone()],
             vendor_data: vec![0x02, 0x01],
         }
@@ -866,6 +942,7 @@ mod tests {
                 sequence_number: 0x10,
                 session_token: 0x11,
                 ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::TwoWay,
+                hus_primary_session_id: 0x00,
                 current_ranging_interval_ms: 0x13,
                 ranging_measurements: RangingMeasurements::ShortAddressTwoWay(vec![
                     short_measurement
@@ -895,6 +972,7 @@ mod tests {
                 session_token: 0x11,
                 rcr_indicator: 0x12,
                 current_ranging_interval: 0x13,
+                hus_primary_session_id: 0x00,
                 owr_aoa_ranging_measurements: vec![extended_measurement.clone()],
                 vendor_data: vec![],
             }
@@ -913,6 +991,7 @@ mod tests {
                 sequence_number: 0x10,
                 session_token: 0x11,
                 ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::OwrAoa,
+                hus_primary_session_id: 0x00,
                 current_ranging_interval_ms: 0x13,
                 ranging_measurements: RangingMeasurements::ExtendedAddressOwrAoa(
                     extended_measurement
@@ -941,6 +1020,7 @@ mod tests {
             session_token: 0x11,
             rcr_indicator: 0x12,
             current_ranging_interval: 0x13,
+            hus_primary_session_id: 0x00,
             owr_aoa_ranging_measurements: vec![short_measurement.clone()],
             vendor_data: vec![],
         }
@@ -959,6 +1039,7 @@ mod tests {
                 sequence_number: 0x10,
                 session_token: 0x11,
                 ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::OwrAoa,
+                hus_primary_session_id: 0x00,
                 current_ranging_interval_ms: 0x13,
                 ranging_measurements: RangingMeasurements::ShortAddressOwrAoa(short_measurement),
                 rcr_indicator: 0x12,
@@ -1252,6 +1333,7 @@ mod tests {
         let short_mac_dl_tdoa_session_info_ntf =
             uwb_uci_packets::ShortMacDlTDoASessionInfoNtfBuilder {
                 current_ranging_interval: 0x13,
+                hus_primary_session_id: 0x00,
                 dl_tdoa_measurements: dl_tdoa_measurements.clone(),
                 no_of_ranging_measurements: 1,
                 rcr_indicator: 0x12,
@@ -1277,6 +1359,7 @@ mod tests {
                 session_token: 0x11,
                 ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::DlTdoa,
                 current_ranging_interval_ms: 0x13,
+                hus_primary_session_id: 0x00,
                 ranging_measurements: RangingMeasurements::ShortAddressDltdoa(short_measurement),
                 rcr_indicator: 0x12,
                 raw_ranging_data,
@@ -1306,6 +1389,7 @@ mod tests {
         let extended_mac_dl_tdoa_session_info_ntf =
             uwb_uci_packets::ExtendedMacDlTDoASessionInfoNtfBuilder {
                 current_ranging_interval: 0x13,
+                hus_primary_session_id: 0x00,
                 dl_tdoa_measurements: dl_tdoa_measurements.clone(),
                 no_of_ranging_measurements: 1,
                 rcr_indicator: 0x12,
@@ -1332,6 +1416,7 @@ mod tests {
                 session_token: 0x11,
                 ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::DlTdoa,
                 current_ranging_interval_ms: 0x13,
+                hus_primary_session_id: 0x00,
                 ranging_measurements: RangingMeasurements::ExtendedAddressDltdoa(short_measurement),
                 rcr_indicator: 0x12,
                 raw_ranging_data,
@@ -1470,4 +1555,67 @@ mod tests {
             })
         );
     }
+
+    #[test]
+    fn test_rf_test_notification_casting_from_rf_per_rx_ntf() {
+        let test_per_rx_ntf_packet = uwb_uci_packets::TestPerRxNtfBuilder {
+            status: uwb_uci_packets::StatusCode::UciStatusOk,
+            attempts: 1,
+            acq_detect: 2,
+            acq_reject: 3,
+            rx_fail: 4,
+            sync_cir_ready: 5,
+            sfd_fail: 6,
+            sfd_found: 7,
+            phr_dec_error: 8,
+            phr_bit_error: 9,
+            psdu_dec_error: 10,
+            psdu_bit_error: 11,
+            sts_found: 12,
+            eof: 13,
+            vendor_data: vec![],
+        }
+            .build();
+        let raw_notification_data = test_per_rx_ntf_packet.clone().encode_to_bytes().unwrap()
+            [UCI_PACKET_HEADER_LEN..]
+            .to_vec();
+        let rf_test_notification =
+            uwb_uci_packets::TestNotification::try_from(test_per_rx_ntf_packet).unwrap();
+        let uci_notification = RfTestNotification::try_from(rf_test_notification).unwrap();
+        let uci_notification_from_per_rx_ntf = UciNotification::RfTest(uci_notification);
+        let status = uwb_uci_packets::StatusCode::UciStatusOk;
+        let attempts = 1;
+        let acq_detect = 2;
+        let acq_reject = 3;
+        let rx_fail = 4;
+        let sync_cir_ready = 5;
+        let sfd_fail = 6;
+        let sfd_found = 7;
+        let phr_dec_error = 8;
+        let phr_bit_error = 9;
+        let psdu_dec_error = 10;
+        let psdu_bit_error = 11;
+        let sts_found = 12;
+        let eof = 13;
+        assert_eq!(
+            uci_notification_from_per_rx_ntf,
+            UciNotification::RfTest(RfTestNotification::TestPerRxNtf(RfTestPerRxData {
+                status,
+                attempts,
+                acq_detect,
+                acq_reject,
+                rx_fail,
+                sync_cir_ready,
+                sfd_fail,
+                sfd_found,
+                phr_dec_error,
+                phr_bit_error,
+                psdu_dec_error,
+                psdu_bit_error,
+                sts_found,
+                eof,
+                raw_notification_data
+            }))
+        );
+    }
 }
diff --git a/src/rust/uwb_core/src/uci/response.rs b/src/rust/uwb_core/src/uci/response.rs
index 3dbfc59..df50c40 100644
--- a/src/rust/uwb_core/src/uci/response.rs
+++ b/src/rust/uwb_core/src/uci/response.rs
@@ -219,7 +219,7 @@ impl TryFrom<(uwb_uci_packets::SessionConfigResponse, UCIMajorVersion, bool)> fo
                     SessionUpdateControllerMulticastListRspV1Payload::parse(payload).map_err(
                         |e| {
                             error!(
-                                "Failed to parse Multicast list ntf v1 {:?}, payload: {:?}",
+                                "Failed to parse Multicast list rsp v1 {:?}, payload: {:?}",
                                 e, &payload
                             );
                             Error::BadParameters
@@ -234,7 +234,7 @@ impl TryFrom<(uwb_uci_packets::SessionConfigResponse, UCIMajorVersion, bool)> fo
                 )))
             }
             SessionConfigResponseChild::SessionUpdateControllerMulticastListRsp(evt)
-                if uci_fira_major_ver == UCIMajorVersion::V2 =>
+                if uci_fira_major_ver >= UCIMajorVersion::V2 =>
             {
                 error!(
                     "Tryfrom: SessionConfigResponse:: SessionUpdateControllerMulticastListRspV2 "
@@ -244,7 +244,7 @@ impl TryFrom<(uwb_uci_packets::SessionConfigResponse, UCIMajorVersion, bool)> fo
                     SessionUpdateControllerMulticastListRspV2Payload::parse(payload).map_err(
                         |e| {
                             error!(
-                                "Failed to parse Multicast list ntf v1 {:?}, payload: {:?}",
+                                "Failed to parse Multicast list rsp v2 {:?}, payload: {:?}",
                                 e, &payload
                             );
                             Error::BadParameters
@@ -369,6 +369,9 @@ impl TryFrom<uwb_uci_packets::TestResponse> for UciResponse {
             TestResponseChild::TestPeriodicTxRsp(evt) => {
                 Ok(UciResponse::RfTest(status_code_to_result(evt.get_status())))
             }
+            TestResponseChild::TestPerRxRsp(evt) => {
+                Ok(UciResponse::RfTest(status_code_to_result(evt.get_status())))
+            }
             TestResponseChild::StopRfTestRsp(evt) => {
                 Ok(UciResponse::RfTest(status_code_to_result(evt.get_status())))
             }
diff --git a/src/rust/uwb_core/src/uci/uci_manager.rs b/src/rust/uwb_core/src/uci/uci_manager.rs
index 237e9a7..87b6638 100644
--- a/src/rust/uwb_core/src/uci/uci_manager.rs
+++ b/src/rust/uwb_core/src/uci/uci_manager.rs
@@ -29,7 +29,7 @@ use crate::params::uci_packets::{
     RadarConfigTlvType, RawUciMessage, ResetConfig, RfTestConfigResponse, RfTestConfigTlv,
     SessionId, SessionState, SessionToken, SessionType, SessionUpdateControllerMulticastResponse,
     SessionUpdateDtTagRangingRoundsResponse, SetAppConfigResponse, UciDataPacket, UciDataPacketHal,
-    UpdateMulticastListAction, UpdateTime,
+    UpdateMulticastListAction,
 };
 use crate::params::utils::{bytes_to_u16, bytes_to_u64};
 use crate::params::UCIMajorVersion;
@@ -47,8 +47,8 @@ use crate::utils::{clean_mpsc_receiver, PinSleep};
 use pdl_runtime::Packet;
 use std::collections::{HashMap, VecDeque};
 use uwb_uci_packets::{
-    fragment_data_msg_send, ControleePhaseList, PhaseList, RawUciControlPacket, UciDataSnd,
-    UciDefragPacket,
+    fragment_data_msg_send, ControleePhaseList, ControllerPhaseList, RawUciControlPacket,
+    UciDataSnd, UciDefragPacket,
 };
 
 const UCI_TIMEOUT_MS: u64 = 2000;
@@ -176,6 +176,7 @@ pub trait UciManager: 'static + Send + Sync + Clone {
     ) -> Result<()>;
 
     // set Data transfer phase config
+    #[allow(clippy::too_many_arguments)]
     async fn session_data_transfer_phase_config(
         &self,
         session_id: SessionId,
@@ -184,6 +185,7 @@ pub trait UciManager: 'static + Send + Sync + Clone {
         dtpml_size: u8,
         mac_address: Vec<u8>,
         slot_bitmap: Vec<u8>,
+        stop_data_transfer: Vec<u8>,
     ) -> Result<()>;
 
     // Get Session token from session id
@@ -196,10 +198,8 @@ pub trait UciManager: 'static + Send + Sync + Clone {
     async fn session_set_hybrid_controller_config(
         &self,
         session_id: SessionId,
-        message_control: u8,
         number_of_phases: u8,
-        update_time: UpdateTime,
-        phase_list: PhaseList,
+        phase_list: Vec<ControllerPhaseList>,
     ) -> Result<()>;
 
     /// Send UCI command for setting hybrid controlee config
@@ -214,6 +214,7 @@ pub trait UciManager: 'static + Send + Sync + Clone {
         config_tlvs: Vec<RfTestConfigTlv>,
     ) -> Result<RfTestConfigResponse>;
     async fn rf_test_periodic_tx(&self, psdu_data: Vec<u8>) -> Result<()>;
+    async fn rf_test_per_rx(&self, psdu_data: Vec<u8>) -> Result<()>;
     async fn stop_rf_test(&self) -> Result<()>;
 }
 
@@ -678,6 +679,7 @@ impl UciManager for UciManagerImpl {
         dtpml_size: u8,
         mac_address: Vec<u8>,
         slot_bitmap: Vec<u8>,
+        stop_data_transfer: Vec<u8>,
     ) -> Result<()> {
         let cmd = UciCommand::SessionDataTransferPhaseConfig {
             session_token: self.get_session_token(&session_id).await?,
@@ -686,6 +688,7 @@ impl UciManager for UciManagerImpl {
             dtpml_size,
             mac_address,
             slot_bitmap,
+            stop_data_transfer,
         };
 
         match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
@@ -707,16 +710,12 @@ impl UciManager for UciManagerImpl {
     async fn session_set_hybrid_controller_config(
         &self,
         session_id: SessionId,
-        message_control: u8,
         number_of_phases: u8,
-        update_time: UpdateTime,
-        phase_list: PhaseList,
+        phase_list: Vec<ControllerPhaseList>,
     ) -> Result<()> {
         let cmd = UciCommand::SessionSetHybridControllerConfig {
             session_token: self.get_session_token(&session_id).await?,
-            message_control,
             number_of_phases,
-            update_time,
             phase_list,
         };
         match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
@@ -768,6 +767,15 @@ impl UciManager for UciManagerImpl {
         }
     }
 
+    async fn rf_test_per_rx(&self, psdu_data: Vec<u8>) -> Result<()> {
+        let cmd = UciCommand::TestPerRx { psdu_data };
+        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
+            Ok(UciResponse::RfTest(resp)) => resp,
+            Ok(_) => Err(Error::Unknown),
+            Err(e) => Err(e),
+        }
+    }
+
     async fn stop_rf_test(&self) -> Result<()> {
         let cmd = UciCommand::StopRfTest;
         match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
@@ -1565,6 +1573,7 @@ impl<T: UciHal, U: UciLogger> UciManagerActor<T, U> {
                     session_token: self.get_session_id(&session_range_data.session_token).await?,
                     current_ranging_interval_ms: session_range_data.current_ranging_interval_ms,
                     ranging_measurement_type: session_range_data.ranging_measurement_type,
+                    hus_primary_session_id: session_range_data.hus_primary_session_id,
                     ranging_measurements: session_range_data.ranging_measurements,
                     rcr_indicator: session_range_data.rcr_indicator,
                     raw_ranging_data: session_range_data.raw_ranging_data,
@@ -2440,54 +2449,49 @@ mod tests {
     #[tokio::test]
     async fn test_session_set_hybrid_controller_config_ok() {
         let session_id = 0x123;
-        let message_control = 0x00;
-        let message_control_extended = 0x01;
         let session_token = 0x123;
         let number_of_phases = 0x02;
-        let update_time = UpdateTime::new(&[0x0; 8]).unwrap();
-        let phase_list_short_mac_address = PhaseList::ShortMacAddress(vec![
-            uwb_uci_packets::PhaseListShortMacAddress {
+        let phase_list_short_mac_address = vec![
+            uwb_uci_packets::ControllerPhaseList {
                 session_token: 0x11,
                 start_slot_index: 0x12,
                 end_slot_index: 0x13,
-                phase_participation: 0x01,
-                mac_address: [0x11, 0x22],
+                control: 0x01,
+                mac_address: [0x11, 0x22].to_vec(),
             },
-            uwb_uci_packets::PhaseListShortMacAddress {
+            uwb_uci_packets::ControllerPhaseList {
                 session_token: 0x21,
                 start_slot_index: 0x22,
                 end_slot_index: 0x23,
-                phase_participation: 0x01,
-                mac_address: [0x11, 0x33],
+                control: 0x01,
+                mac_address: [0x11, 0x33].to_vec(),
             },
-        ]);
-        let phase_list_extended_mac_address = PhaseList::ExtendedMacAddress(vec![
-            uwb_uci_packets::PhaseListExtendedMacAddress {
+        ];
+        let phase_list_extended_mac_address = vec![
+            uwb_uci_packets::ControllerPhaseList {
                 session_token: 0x11,
                 start_slot_index: 0x12,
                 end_slot_index: 0x13,
-                phase_participation: 0x01,
-                mac_address: [0x11, 0x22, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38],
+                control: 0x01,
+                mac_address: [0x11, 0x22, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38].to_vec(),
             },
-            uwb_uci_packets::PhaseListExtendedMacAddress {
+            uwb_uci_packets::ControllerPhaseList {
                 session_token: 0x21,
                 start_slot_index: 0x22,
                 end_slot_index: 0x23,
-                phase_participation: 0x01,
-                mac_address: [0x11, 0x22, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39],
+                control: 0x01,
+                mac_address: [0x11, 0x22, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39].to_vec(),
             },
-        ]);
-        let mut phase_list_clone = phase_list_short_mac_address.clone();
+        ];
+        let phase_list_clone_short = phase_list_short_mac_address.clone();
 
         // short mac address
         let (uci_manager, mut mock_hal) = setup_uci_manager_with_session_active(
             |mut hal| async move {
                 let cmd = UciCommand::SessionSetHybridControllerConfig {
                     session_token,
-                    message_control,
                     number_of_phases,
-                    update_time,
-                    phase_list: phase_list_clone,
+                    phase_list: phase_list_clone_short,
                 };
                 let resp = into_uci_hal_packets(
                     uwb_uci_packets::SessionSetHybridControllerConfigRspBuilder {
@@ -2507,9 +2511,7 @@ mod tests {
         let result = uci_manager
             .session_set_hybrid_controller_config(
                 session_token,
-                message_control,
                 number_of_phases,
-                update_time,
                 phase_list_short_mac_address,
             )
             .await;
@@ -2517,15 +2519,14 @@ mod tests {
         assert!(mock_hal.wait_expected_calls_done().await);
 
         // extended mac address
-        phase_list_clone = phase_list_extended_mac_address.clone();
+        let phase_list_clone_extended = phase_list_extended_mac_address.clone();
+        //phase_list_clone.clone_from(&phase_list_extended_mac_address);
         let (uci_manager, mut mock_hal) = setup_uci_manager_with_session_active(
             |mut hal| async move {
                 let cmd = UciCommand::SessionSetHybridControllerConfig {
                     session_token,
-                    message_control: message_control_extended,
                     number_of_phases,
-                    update_time,
-                    phase_list: phase_list_clone,
+                    phase_list: phase_list_clone_extended,
                 };
                 let resp = into_uci_hal_packets(
                     uwb_uci_packets::SessionSetHybridControllerConfigRspBuilder {
@@ -2545,9 +2546,7 @@ mod tests {
         let result = uci_manager
             .session_set_hybrid_controller_config(
                 session_token,
-                message_control_extended,
                 number_of_phases,
-                update_time,
                 phase_list_extended_mac_address,
             )
             .await;
@@ -2560,8 +2559,8 @@ mod tests {
         let session_id = 0x123;
         let session_token = 0x123;
         let phase_list = vec![
-            ControleePhaseList { session_token: 0x12, phase_participation: 0x01 },
-            ControleePhaseList { session_token: 0x14, phase_participation: 0x01 },
+            ControleePhaseList { session_token: 0x12 },
+            ControleePhaseList { session_token: 0x14 },
         ];
         let phase_list_clone = phase_list.clone();
 
@@ -2601,8 +2600,10 @@ mod tests {
         let dtpml_size = 0x02;
         let mac_address = vec![0x22, 0x11, 0x44, 0x33];
         let slot_bitmap = vec![0xF0, 0x0F];
+        let stop_data_transfer = vec![0x00, 0x01];
         let mac_address_clone = mac_address.clone();
         let slot_bitmap_clone = slot_bitmap.clone();
+        let stop_data_transfer_clone = stop_data_transfer.clone();
 
         let (uci_manager, mut mock_hal) = setup_uci_manager_with_session_active(
             |mut hal| async move {
@@ -2613,6 +2614,7 @@ mod tests {
                     dtpml_size,
                     mac_address,
                     slot_bitmap,
+                    stop_data_transfer,
                 };
                 let resp = into_uci_hal_packets(
                     uwb_uci_packets::SessionDataTransferPhaseConfigRspBuilder {
@@ -2637,6 +2639,7 @@ mod tests {
                 dtpml_size,
                 mac_address_clone,
                 slot_bitmap_clone,
+                stop_data_transfer_clone,
             )
             .await;
         assert!(result.is_ok());
diff --git a/src/rust/uwb_core/src/uci/uci_manager_sync.rs b/src/rust/uwb_core/src/uci/uci_manager_sync.rs
index b348cc3..5158905 100644
--- a/src/rust/uwb_core/src/uci/uci_manager_sync.rs
+++ b/src/rust/uwb_core/src/uci/uci_manager_sync.rs
@@ -31,7 +31,7 @@ use crate::params::{
     RadarConfigTlv, RadarConfigTlvType, RawUciMessage, ResetConfig, RfTestConfigResponse,
     RfTestConfigTlv, SessionId, SessionState, SessionType,
     SessionUpdateControllerMulticastResponse, SessionUpdateDtTagRangingRoundsResponse,
-    SetAppConfigResponse, UpdateMulticastListAction, UpdateTime,
+    SetAppConfigResponse, UpdateMulticastListAction,
 };
 #[cfg(any(test, feature = "mock-utils"))]
 use crate::uci::mock_uci_manager::MockUciManager;
@@ -42,7 +42,7 @@ use crate::uci::notification::{
 use crate::uci::uci_hal::UciHal;
 use crate::uci::uci_logger::{UciLogger, UciLoggerMode};
 use crate::uci::uci_manager::{UciManager, UciManagerImpl};
-use uwb_uci_packets::{ControleePhaseList, Controlees, PhaseList};
+use uwb_uci_packets::{ControleePhaseList, Controlees, ControllerPhaseList};
 
 /// The NotificationManager processes UciNotification relayed from UciManagerSync in a sync fashion.
 /// The UciManagerSync assumes the NotificationManager takes the responsibility to properly handle
@@ -443,16 +443,12 @@ impl<U: UciManager> UciManagerSync<U> {
     pub fn session_set_hybrid_controller_config(
         &self,
         session_id: SessionId,
-        message_control: u8,
         number_of_phases: u8,
-        update_time: UpdateTime,
-        phase_list: PhaseList,
+        phase_list: Vec<ControllerPhaseList>,
     ) -> Result<()> {
         self.runtime_handle.block_on(self.uci_manager.session_set_hybrid_controller_config(
             session_id,
-            message_control,
             number_of_phases,
-            update_time,
             phase_list,
         ))
     }
@@ -469,6 +465,7 @@ impl<U: UciManager> UciManagerSync<U> {
     }
 
     /// Send UCI command for session data transfer phase config
+    #[allow(clippy::too_many_arguments)]
     pub fn session_data_transfer_phase_config(
         &self,
         session_id: SessionId,
@@ -477,6 +474,7 @@ impl<U: UciManager> UciManagerSync<U> {
         dtpml_size: u8,
         mac_address: Vec<u8>,
         slot_bitmap: Vec<u8>,
+        stop_data_transfer: Vec<u8>,
     ) -> Result<()> {
         self.runtime_handle.block_on(self.uci_manager.session_data_transfer_phase_config(
             session_id,
@@ -485,6 +483,7 @@ impl<U: UciManager> UciManagerSync<U> {
             dtpml_size,
             mac_address,
             slot_bitmap,
+            stop_data_transfer,
         ))
     }
 
@@ -503,6 +502,11 @@ impl<U: UciManager> UciManagerSync<U> {
         self.runtime_handle.block_on(self.uci_manager.rf_test_periodic_tx(psdu_data))
     }
 
+    /// Test Per rx command
+    pub fn rf_test_per_rx(&self, psdu_data: Vec<u8>) -> Result<()> {
+        self.runtime_handle.block_on(self.uci_manager.rf_test_per_rx(psdu_data))
+    }
+
     /// Test stop rf test command
     pub fn stop_rf_test(&self) -> Result<()> {
         self.runtime_handle.block_on(self.uci_manager.stop_rf_test())
diff --git a/src/rust/uwb_uci_packets/src/lib.rs b/src/rust/uwb_uci_packets/src/lib.rs
index 278a2df..929f5c1 100644
--- a/src/rust/uwb_uci_packets/src/lib.rs
+++ b/src/rust/uwb_uci_packets/src/lib.rs
@@ -920,6 +920,7 @@ pub fn build_data_transfer_phase_config_cmd(
     dtpml_size: u8,
     mac_address: Vec<u8>,
     slot_bitmap: Vec<u8>,
+    stop_data_transfer: Vec<u8>,
 ) -> Result<SessionDataTransferPhaseConfigCmd, DecodeError> {
     let mut dtpml_buffer = BytesMut::new();
 
@@ -949,10 +950,19 @@ pub fn build_data_transfer_phase_config_cmd(
         return Err(DecodeError::InvalidPacketError);
     }
 
+    // Prepare segmented vectors for stop_data_transfer
+    let stop_data_transfer_vector: Vec<_> =
+        stop_data_transfer.chunks(1).map(|chunk| chunk.to_owned()).collect();
+
     // Combine segmented vectors into dtpml_buffer
-    for (elem1, elem2) in mac_address_vec.into_iter().zip(slot_bitmap_vec.into_iter()) {
+    for ((elem1, elem2), elem3) in mac_address_vec
+        .into_iter()
+        .zip(slot_bitmap_vec.into_iter())
+        .zip(stop_data_transfer.into_iter())
+    {
         dtpml_buffer.extend_from_slice(&elem1);
         dtpml_buffer.extend_from_slice(&elem2);
+        dtpml_buffer.extend_from_slice(&[elem3]);
     }
 
     Ok(SessionDataTransferPhaseConfigCmdBuilder {
@@ -974,68 +984,6 @@ impl Drop for AppConfigTlv {
     }
 }
 
-#[derive(Debug, Clone, PartialEq)]
-pub enum PhaseList {
-    ShortMacAddress(Vec<PhaseListShortMacAddress>),
-    ExtendedMacAddress(Vec<PhaseListExtendedMacAddress>),
-}
-
-/// Generate the SessionSetHybridControllerConfig packet.
-pub fn build_session_set_hybrid_controller_config_cmd(
-    session_token: u32,
-    message_control: u8,
-    number_of_phases: u8,
-    update_time: [u8; 8],
-    phase_list: PhaseList,
-) -> Result<SessionSetHybridControllerConfigCmd, DecodeError> {
-    let mut phase_list_buffer = BytesMut::new();
-    match phase_list {
-        PhaseList::ShortMacAddress(phaseListShortMacAddressVec) => {
-            for phaseListShortMacAddress in phaseListShortMacAddressVec {
-                phase_list_buffer.extend_from_slice(
-                    &(phaseListShortMacAddress.session_token.to_le_bytes()[0..4]),
-                );
-                phase_list_buffer.extend_from_slice(
-                    &(phaseListShortMacAddress.start_slot_index.to_le_bytes()[0..2]),
-                );
-                phase_list_buffer.extend_from_slice(
-                    &(phaseListShortMacAddress.end_slot_index.to_le_bytes()[0..2]),
-                );
-                phase_list_buffer.extend_from_slice(std::slice::from_ref(
-                    &phaseListShortMacAddress.phase_participation,
-                ));
-                phase_list_buffer.extend_from_slice(&phaseListShortMacAddress.mac_address);
-            }
-        }
-        PhaseList::ExtendedMacAddress(phaseListExtendedMacAddressVec) => {
-            for phaseListExtendedMacAddress in phaseListExtendedMacAddressVec {
-                phase_list_buffer.extend_from_slice(
-                    &(phaseListExtendedMacAddress.session_token.to_le_bytes()[0..4]),
-                );
-                phase_list_buffer.extend_from_slice(
-                    &(phaseListExtendedMacAddress.start_slot_index.to_le_bytes()[0..2]),
-                );
-                phase_list_buffer.extend_from_slice(
-                    &(phaseListExtendedMacAddress.end_slot_index.to_le_bytes()[0..2]),
-                );
-                phase_list_buffer.extend_from_slice(std::slice::from_ref(
-                    &phaseListExtendedMacAddress.phase_participation,
-                ));
-                phase_list_buffer.extend_from_slice(&phaseListExtendedMacAddress.mac_address);
-            }
-        }
-        _ => return Err(DecodeError::InvalidPacketError),
-    }
-    Ok(SessionSetHybridControllerConfigCmdBuilder {
-        session_token,
-        message_control,
-        number_of_phases,
-        update_time,
-        payload: Some(phase_list_buffer.freeze()),
-    }
-    .build())
-}
-
 // Radar data 'bits per sample' field isn't a raw value, instead it's an enum
 // that maps to the raw value. We need this mapping to get the max sample size
 // length.
@@ -1419,74 +1367,14 @@ mod tests {
 
     #[test]
     fn test_build_data_transfer_phase_config_cmd() {
-        let packet: UciControlPacket =
-            build_data_transfer_phase_config_cmd(0x1234_5678, 0x0, 0x2, 1, vec![0, 1], vec![2, 3])
-                .unwrap()
-                .into();
-        let packet_fragments: Vec<UciControlPacketHal> = packet.into();
-        let uci_packet = packet_fragments[0].encode_to_vec();
-        assert_eq!(
-            uci_packet,
-            Ok(vec![
-                0x21, 0x0e, 0x00, 0x0b, // 2(packet info), RFU, payload length(11)
-                0x78, 0x56, 0x34, 0x12, // 4(session id (LE))
-                0x00, 0x02, 0x01, // dtpcm_repetition, data_transfer_control, dtpml_size
-                0x00, 0x01, 0x02, 0x03, // payload
-            ])
-        );
-    }
-
-    #[test]
-    fn test_build_session_set_hybrid_controller_config_cmd_short_address() {
-        let phase_list_short_mac_address = PhaseListShortMacAddress {
-            session_token: 0x1324_3546,
-            start_slot_index: 0x1111,
-            end_slot_index: 0x1121,
-            phase_participation: 0x0,
-            mac_address: [0x1, 0x2],
-        };
-        let packet: UciControlPacket = build_session_set_hybrid_controller_config_cmd(
-            0x1234_5678,
-            0x0,
-            0x0,
-            [1; 8],
-            PhaseList::ShortMacAddress(vec![phase_list_short_mac_address]),
-        )
-        .unwrap()
-        .into();
-        let packet_fragments: Vec<UciControlPacketHal> = packet.into();
-        let uci_packet = packet_fragments[0].encode_to_vec();
-        assert_eq!(
-            uci_packet,
-            Ok(vec![
-                0x21, 0x0c, 0x00, 0x19, // 2(packet info), RFU, payload length(25)
-                0x78, 0x56, 0x34, 0x12, // 4(session id (LE))
-                0x00, 0x00, // message_control, number_of_phases
-                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // update_time
-                0x46, 0x35, 0x24, 0x13, // session id (LE)
-                0x11, 0x11, // start slot index (LE)
-                0x21, 0x11, // end slot index (LE)
-                0x00, // phase_participation
-                0x01, 0x02, // mac address
-            ])
-        );
-    }
-
-    #[test]
-    fn test_build_session_set_hybrid_controller_config_cmd_extended_address() {
-        let phase_list_extended_mac_address = PhaseListExtendedMacAddress {
-            session_token: 0x1324_3546,
-            start_slot_index: 0x1111,
-            end_slot_index: 0x1121,
-            phase_participation: 0x0,
-            mac_address: [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8],
-        };
-        let packet: UciControlPacket = build_session_set_hybrid_controller_config_cmd(
+        let packet: UciControlPacket = build_data_transfer_phase_config_cmd(
             0x1234_5678,
             0x0,
-            0x0,
-            [1; 8],
-            PhaseList::ExtendedMacAddress(vec![phase_list_extended_mac_address]),
+            0x2,
+            1,
+            vec![0, 1],
+            vec![2, 3],
+            vec![0x00],
         )
         .unwrap()
         .into();
@@ -1495,15 +1383,11 @@ mod tests {
         assert_eq!(
             uci_packet,
             Ok(vec![
-                0x21, 0x0c, 0x00, 0x1f, // 2(packet info), RFU, payload length(31)
+                0x21, 0x0e, 0x00, 0x0c, // 2(packet info), RFU, payload length(12)
                 0x78, 0x56, 0x34, 0x12, // 4(session id (LE))
-                0x00, 0x00, // message_control, number_of_phases
-                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // update_time
-                0x46, 0x35, 0x24, 0x13, // session id (LE)
-                0x11, 0x11, // start slot index (LE)
-                0x21, 0x11, // end slot index (LE)
-                0x00, // phase_participation
-                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 // mac address
+                0x00, 0x02, 0x01, // dtpcm_repetition, data_transfer_control, dtpml_size
+                0x00, 0x01, 0x02, 0x03, // payload
+                0x00, //stop_data_transfer
             ])
         );
     }
diff --git a/src/rust/uwb_uci_packets/uci_packets.pdl b/src/rust/uwb_uci_packets/uci_packets.pdl
index 04b13dc..b23cb3e 100644
--- a/src/rust/uwb_uci_packets/uci_packets.pdl
+++ b/src/rust/uwb_uci_packets/uci_packets.pdl
@@ -95,9 +95,13 @@ enum AndroidOpCode : 6 {
 }
 
 enum TestOpCode : 6 {
-    RF_TEST_CONFIG_SET_COMMAND  = 0x0,
-    RF_TEST_CONFIG_GET_COMMAND  = 0x1,
-    RF_TEST_PERIODIC_TX_CMD = 0x2,
+    RF_TEST_CONFIG_SET  = 0x0,
+    RF_TEST_CONFIG_GET  = 0x1,
+    RF_TEST_PERIODIC_TX = 0x2,
+    RF_TEST_PER_RX = 0x3,
+    RF_TEST_RX = 0x5,
+    RF_TEST_LOOPBACK = 0x6,
+    RF_TEST_STOP_SESSION = 0x07,
 }
 
 enum StatusCode : 8 {
@@ -490,6 +494,7 @@ enum SessionType: 8 {
     FIRA_RANGING_ONLY_PHASE = 0x03,
     FIRA_IN_BAND_DATA_PHASE = 0x04,
     FIRA_RANGING_WITH_DATA_PHASE = 0x05,
+    FIRA_HUS_PRIMARY_SESSION = 0x9F,
     CCC = 0xA0,
     RADAR_SESSION = 0xA1,
     ALIRO = 0xA2,
@@ -1135,28 +1140,18 @@ test SessionDataTransferPhaseConfigNtf {
     "\x61\x0E\x00\x05\x00\x00\x00\x00\x00"
 }
 
-struct PhaseListShortMacAddress {
+struct ControllerPhaseList {
     session_token: 32,
     start_slot_index: 16,
     end_slot_index: 16,
-    phase_participation: 8,
-    mac_address: 8[2],
-}
-
-struct PhaseListExtendedMacAddress {
-    session_token: 32,
-    start_slot_index: 16,
-    end_slot_index: 16,
-    phase_participation: 8,
-    mac_address: 8[8],
+    control: 8,
+    mac_address: 8[],
 }
 
 packet SessionSetHybridControllerConfigCmd : SessionConfigCommand (opcode = 0x0C) { //SESSION_SET_HUS_CONTROLLER_CONFIG
     session_token: 32,
-    message_control: 8,
     number_of_phases: 8,
-    update_time: 8[8],
-    _payload_,
+    phase_list: ControllerPhaseList[],
 }
 
 test SessionSetHybridControllerConfigCmd {
@@ -1173,7 +1168,6 @@ test SessionSetHybridControllerConfigRsp {
 
 struct ControleePhaseList {
     session_token: 32,
-    phase_participation: 8,
 }
 
 packet SessionSetHybridControleeConfigCmd : SessionConfigCommand (opcode = 0x0D) { //SESSION_SET_HUS_CONTROLEE_CONFIG
@@ -1289,7 +1283,8 @@ packet SessionInfoNtf : SessionControlNotification (opcode = 0x0) { // SESSION_I
     ranging_measurement_type: RangingMeasurementType,
     _reserved_: 8,
     mac_address_indicator: MacAddressIndicator,
-    _reserved_: 64,
+    hus_primary_session_id: 32,
+    _reserved_: 32,
     _body_,
 }
 
@@ -1666,7 +1661,7 @@ struct RfTestConfigTlv {
     v: 8[],
 }
 
-packet SessionSetRfTestConfigCmd : TestCommand (opcode = 0x00) {
+packet SessionSetRfTestConfigCmd : TestCommand (opcode = 0x00) {  // RF_TEST_CONFIG_SET
     session_token: 32, // Session ID or Session Handle (based on UWBS version)
     _count_(tlvs): 8,
     tlvs: RfTestConfigTlv[]
@@ -1681,7 +1676,7 @@ struct RfTestConfigStatus {
     status: StatusCode,
 }
 
-packet SessionSetRfTestConfigRsp : TestResponse (opcode = 0x00) {
+packet SessionSetRfTestConfigRsp : TestResponse (opcode = 0x00) { // RF_TEST_CONFIG_SET
     status: StatusCode,
     _count_(cfg_status): 8,
     cfg_status: RfTestConfigStatus[],
@@ -1691,7 +1686,7 @@ test SessionSetRfTestConfigRsp {
     "\x4D\x00\x00\x02\x00\x00",
 }
 
-packet TestPeriodicTxCmd : TestCommand (opcode = 0x02) {
+packet TestPeriodicTxCmd : TestCommand (opcode = 0x02) { // RF_TEST_PERIODIC_TX
     psdu_data : 8[],
 }
 
@@ -1699,7 +1694,7 @@ test TestPeriodicTxCmd {
     "\x2D\x02\x00\x0a\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
 }
 
-packet TestPeriodicTxRsp : TestResponse (opcode = 0x02) {
+packet TestPeriodicTxRsp : TestResponse (opcode = 0x02) { // RF_TEST_PERIODIC_TX
     status: StatusCode,
 }
 
@@ -1707,7 +1702,7 @@ test TestPeriodicTxRsp {
     "\x4D\x02\x00\x01\x00",
 }
 
-packet TestPeriodicTxNtf : TestNotification (opcode = 0x02) {
+packet TestPeriodicTxNtf : TestNotification (opcode = 0x02) { // RF_TEST_PERIODIC_TX
     status: StatusCode,
     vendor_data: 8[],
 }
@@ -1716,12 +1711,122 @@ test TestPeriodicTxNtf {
     "\x6D\x02\x00\x01\x00",
 }
 
-packet StopRfTestCmd : TestCommand (opcode = 0x07) { }
+packet TestPerRxCmd : TestCommand (opcode = 0x03) { // RF_TEST_PER_RX
+    psdu_data : 8[],
+}
+
+test TestPerRxCmd {
+    "\x2D\x03\x00\x0a\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
+}
+
+packet TestPerRxRsp : TestResponse (opcode = 0x03) { // RF_TEST_PER_RX
+    status: StatusCode,
+}
+
+test TestPerRxRsp {
+    "\x4D\x03\x00\x01\x00",
+}
+
+packet TestPerRxNtf : TestNotification (opcode = 0x03) { // RF_TEST_PER_RX
+    status: StatusCode,
+    attempts: 32,
+    acq_detect: 32,
+    acq_reject: 32,
+    rx_fail: 32,
+    sync_cir_ready: 32,
+    sfd_fail: 32,
+    sfd_found: 32,
+    phr_dec_error: 32,
+    phr_bit_error: 32,
+    psdu_dec_error: 32,
+    psdu_bit_error: 32,
+    sts_found: 32,
+    eof: 32,
+    vendor_data: 8[],
+}
+
+test TestPerRxNtf {
+    "\x6D\x03\x00\x35\x00\xE8\x03\x00\x00\x0C\x04\x00\x00\x24\x00\x00\x00\x00\x00\x00\x00\xE8\x03\x00\x00\x00\x00\xE8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE8\x03\x00\x00"
+}
+
+packet TestRxCmd : TestCommand (opcode = 0x05) { // RF_TEST_RX
+    psdu_data : 8[],
+}
 
-test StopRfTestCmd { "\x2D\x07\x00\x00", }
+test TestRxCmd {
+    "\x2D\x05\x00\x0a\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
+}
 
-packet StopRfTestRsp : TestResponse (opcode = 0x07) {
+packet TestRxRsp : TestResponse (opcode = 0x05) { // RF_TEST_RX
     status: StatusCode,
 }
 
-test StopRfTestRsp { "\x4D\x07\x00\x01\x00", }
+test TestRxRsp {
+    "\x4D\x05\x00\x01\x00",
+}
+
+packet TestRxNtf : TestNotification (opcode = 0x05) { // RF_TEST_RX
+    status: StatusCode,
+    rx_done_ts_int: 32,
+    rx_done_ts_frac: 16,
+    aoa_azimuth: 16,
+    aoa_elevation: 16,
+    toa_gap: 8,
+    phr: 16,
+    _count_(psdu_data): 16,
+    psdu_data: 8[],
+    vendor_data: 8[],
+}
+
+test TestRxNtf {
+    "\x6D\x05\x00\x14\x00\x52\x21\x00\x00\x00\x00\x00\x00\x00\x00\x0F\x12\x0A\x04\x00\xAB\xCD\xAB\xCD"
+}
+
+packet TestLoopbackCmd : TestCommand (opcode = 0x06) { // RF_TEST_LOOPBACK
+    psdu_data : 8[],
+}
+
+test TestLoopbackCmd {
+    "\x2D\x06\x00\x0a\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
+}
+
+packet TestLoopbackRsp : TestResponse (opcode = 0x06) { // RF_TEST_LOOPBACK
+    status: StatusCode,
+}
+
+test TestLoopbackRsp {
+    "\x4D\x06\x00\x01\x00",
+}
+
+packet TestLoopbackNtf : TestNotification (opcode = 0x06) { // RF_TEST_LOOPBACK
+    status: StatusCode,
+    tx_ts_int: 32,
+    tx_ts_frac: 16,
+    rx_ts_int: 32,
+    rx_ts_frac: 16,
+    aoa_azimuth: 16,
+    aoa_elevation: 16,
+    phr: 16,
+    _count_(psdu_data): 16,
+    psdu_data: 8[],
+    vendor_data: 8[],
+}
+
+test TestLoopbackNtf {
+    "\x6D\x06\x00\x19\x00\x00\x00\x00\x00\x00\x00\x52\x21\x05\x00\x25\x00\x00\x00\x00\x00\x12\x0A\x04\x00\xAB\xCD\xAB\xCD"
+}
+
+packet StopRfTestCmd : TestCommand (opcode = 0x07) { // RF_TEST_STOP_SESSION
+}
+
+test StopRfTestCmd {
+    "\x2D\x07\x00\x00",
+}
+
+packet StopRfTestRsp : TestResponse (opcode = 0x07) {  // RF_TEST_STOP_SESSION
+    status: StatusCode,
+}
+
+test StopRfTestRsp {
+    "\x4D\x07\x00\x01\x00",
+}
```

