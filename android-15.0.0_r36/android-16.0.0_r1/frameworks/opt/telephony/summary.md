```
0a93c66b9d: Use all satellite plmn list in isSatellitePlmn() (Aishwarya Mallampati <amallampati@google.com>)
59ab1b53b3: Fix wrong report for satelite eSOS event count (Hakjun Choi <hakjunc@google.com>)
6cc79f7334: Fix UiccController crash due to inconsistent phone count (Tomasz Wasilczyk <twasilczyk@google.com>)
3557c8b10d: Do check for throttled before allowing sms is throttled (Sooraj Sasindran <sasindran@google.com>)
577e9a0d27: Ignore geofence carrier tag IDs requirements for old devices (Thomas Nguyen <tnd@google.com>)
0f40261c9b: Check if ar.result is boolean before calling cast (Aishwarya Mallampati <amallampati@google.com>)
58a68fe141: Don't send selected satellite subscription ID changed when there is no c... (Thomas Nguyen <tnd@google.com>)
08aafb133d: add is_opportunistic into related atoms (joonhunshin <joonhunshin@google.com>)
01e0245fab: Return highest preferred data policy if input plmn is empty. (Aishwarya Mallampati <amallampati@google.com>)
f45e22b4da: Fix wrong time logging for satellite connection time (Hakjun Choi <hakjunc@google.com>)
4054aae04f: Add is_nb_iot_ntn field into related atoms (Hakjun Choi <hakjunc@google.com>)
e0e76f3999: Fixed the phone number issue (Jack Yu <jackyu@google.com>)
81e1ea8c68: Revert "Fix video Call goes on hold instead of terminating when acceptin... (Joonhun Shin <joonhunshin@google.com>)
cac60f0088: Only do performance-based switch for HOME (Ling Ma <linggm@google.com>)
ec3e01f435: DSDA: Handle call resume failure (Pranav Madapurmath <pmadapurmath@google.com>)
67411ed9fc: Check data registration state in isCellularAvailable (Aishwarya Mallampati <amallampati@google.com>)
6777240d79: Extend canoical linger time (Ling Ma <linggm@google.com>)
3f3c3062cd: Don't send disable request to modem when enable is in progress if device... (Thomas Nguyen <tnd@google.com>)
2714660d3f: Fix incorrect satellite config udater metrics logging (Karthick M J <karthickmj@google.com>)
42e37234ce: Removing the overwrite logic of sim slot length to mCi's length (sandeepjs <sandeepjs@google.com>)
6248aec83e: Temporarily ignore tests using reflection on NetworkAgent (Chalard Jean <jchalard@google.com>)
b096be5195: Telephony: remove usages of deprecated Mockito matchers (Adrian Roos <roosa@google.com>)
ebac75111e: logic for api getSatelliteDataMode (Akash Garg <gargakash@google.com>)
9bb8195a39: Use ConnectivityManager.MockHelpers (Chalard Jean <jchalard@google.com>)
e2174101b1: Add cross stack redialing during emergency call (Hwangoo Park <hwangoo@google.com>)
cf6acd5f46: Support overrding data version and backup/restore config data for CTS (youngtaecha <youngtaecha@google.com>)
b4c9afd853: Use ConnectivityManager.MockHelpers (Chalard Jean <jchalard@google.com>)
041542a66c: Add Carrrier ID whenever CarrierRoamingSatelliteController atom event is... (Hakjun Choi <hakjunc@google.com>)
8eb1b3a8f3: Support to notify when the satellite config data is updated by OTA (youngtaecha <youngtaecha@google.com>)
a859dce948: Send all satellite PLMNs (Aishwarya Mallampati <amallampati@google.com>)
5ac640563c: Add new fields for counting sms sms message for Satellite (Hakjun Choi <hakjunc@google.com>)
73f88f7b6e: Avoid PDN Tear down at Out of service scenario (Nagendra Prasad Nagarle Basavaraju <nagendranb@g...)
e2f9483e73: Check Pco when network disconnects (Ling Ma <linggm@google.com>)
85de84299a: Cleaned up the flag subscription_user_association_query (Jack Yu <jackyu@google.com>)
e63a50fef2: Block premium SMS in satellite mode. (Aishwarya Mallampati <amallampati@google.com>)
0af95a25bb: Removed CDMA unit tests (Jack Yu <jackyu@google.com>)
8e734d7b14: frameworks/opt/telephony: remove deprecated Mockito usages (Adrian Roos <roosa@google.com>)
faa0419d89: Update  notifySmsSent() feature flag dependency (Madhav <madhavadas@google.com>)
e0e16e47ed: Update satellite mode condition for emergency call (Hwangoo Park <hwangoo@google.com>)
f60813118f: Skip testSendMultipartSmsByCarrierAppNoResponse on automotive (Tomasz Wasilczyk <twasilczyk@google.com>)
7157f27694: Check emergency messaging support before showing SOS button (Thomas Nguyen <tnd@google.com>)
b89457ff83: Skip call for deprecated HAL (Ling Ma <linggm@google.com>)
fefdf9fed5: Cache nrBand during idle (Ling Ma <linggm@google.com>)
e6384a5bae: frameworks/opt/telephony: remove usages of Mockito.verifyZeroInteraction... (Adrian Roos <roosa@google.com>)
98abaa6ddf: Remove MessageQueue reflection from ImsTestBase (Shai Barack <shayba@google.com>)
1e2293be1e: Remove MessageQueue reflection from TelephonyTest (Shai Barack <shayba@google.com>)
407d3bd86e: Add sorting by ascending order for repeated atom fields (Hakjun Choi <hakjunc@google.com>)
783c6c8664: Cleaned up the flag reset_primary_sim_default_values (Jack Yu <jackyu@google.com>)
49ac318f60: Cleaned up the flag network_validation (Jack Yu <jackyu@google.com>)
d7ceb8a6de: Removed the flag minimal_telephony_managers_conditional_on_features (Jack Yu <jackyu@google.com>)
562d78c4ea: CDMA code cleanup (Jack Yu <jackyu@google.com>)
eaf4851fe6: Silence MockitoHint(s) in telephony tests base (Tomasz Wasilczyk <twasilczyk@google.com>)
e7ad27bde5: Fix a race condition that causes DatagramDispatcher to get stuck (Thomas Nguyen <tnd@google.com>)
3ba4955779: Add a new field count_of_satellite_sessions into CarrierRoamingSatellite... (Hakjun Choi <hakjunc@google.com>)
bc424ccbb1: [log] user enable per sub (Ling Ma <linggm@google.com>)
0626e66429: Add new flag for "robust number verification". (Tyler Gunn <tgunn@google.com>)
ee223e33c4: More CDMA cleanup (Jack Yu <jackyu@google.com>)
b58bf9cd81: Allow creation of EmergencyNumberTracker when CALLING or MESSAGING is en... (Madhav <madhavadas@google.com>)
c6f7a96870: Allow use of EmergencyNumberTracker when CALLING or MESSAGING is enabled (Madhav <madhavadas@google.com>)
c6bf1564d1: Removed CDMA related test cases (Jack Yu <jackyu@google.com>)
13c136c804: Add a new field is_multi into Satellite atoms (Hakjun Choi <hakjunc@google.com>)
fa47e8cc36: Do not switch phone type to CDMA (Jack Yu <jackyu@google.com>)
c154f896bc: Force ActivityManager unmocking (Tomasz Wasilczyk <twasilczyk@google.com>)
0309e4b282: [DSRM] skip the recovery action when network scan started (Willy Hu <willycwhu@google.com>)
cb91adaaf4: Handle radio unavailable state properly (Mengjun Leng <quic_mengju@quicinc.com>)
94d91b0b3b: Remove roaming flag (Ling Ma <linggm@google.com>)
3357b2f12e: Add debugging messages for NTN mode update (Thomas Nguyen <tnd@google.com>)
dc00e1c923: [Satellite] Satellite entitlement results are saved to persistent memory... (arunvoddu <arunvoddu@google.com>)
680b18ac05: Add flag for hanging up active call based on emergency call domain (Hwangoo Park <hwangoo@google.com>)
d714cf4bc1: Add resource config gating ApduSender performance optimization. (Qingqi Lei <qingqi@google.com>)
0557c21422: Log session gap min, avg and max (Aishwarya Mallampati <amallampati@google.com>)
d7db3050e1: Support satellite states overriding for CTS test (Thomas Nguyen <tnd@google.com>)
a1e4468954: Update eligibility metrics whenever notifyCarrierRoamingNtnEligibleState... (Aishwarya Mallampati <amallampati@google.com>)
e954c80df7: Exit P2P satellite session outside geofence (Aishwarya Mallampati <amallampati@google.com>)
cb84dbd3eb: (APDS) Don't enter ECBM when ECC ends in GSM/UMTS networks (jaesikkong <jaesikkong@google.com>)
07baa852ad: EmergencyNumberTrackerTest: use base class mocks (Tomasz Wasilczyk <twasilczyk@google.com>)
66fba601a0: Fix remembering last known cell identity for data-only devices (Tomasz Wasilczyk <twasilczyk@google.com>)
76580f91a7: Fix testNetworkCachingOverflow failure in CellularNetworkValidatorTest (Qiong Liu <qiong.b.liu@sony.com>)
d7cfa61c65: Cleaned up the flag minimal_telephony_cdm_check (Jack Yu <jackyu@google.com>)
b3b55e96d9: CarrierService: Disable marching dots on carrier app crash/lost (Jesse Melhuish <melhuishj@google.com>)
06a41dc7b6: Allow satellite to bypass roaming settings (Ling Ma <linggm@google.com>)
8158def01a: Handling application removal case. (Akash Garg <gargakash@google.com>)
5be4bc2302: Add checking Location service status before notification CarrierRoamingN... (joonhunshin <joonhunshin@google.com>)
d2c4d5885d: Add Satellite Data Metrics Support (Nagendra Prasad Nagarle Basavaraju <nagendranb@g...)
83d06828b4: Add flag not to enter ECBM in GSM and UMTS networks (jaesikkong <jaesikkong@google.com>)
f190ad93ee: Fix SIM load race condition (Ling Ma <linggm@google.com>)
cae29ec6fe: CarrierPrivilegesTracker: additional logging to diagnose lost SIM state (Tomasz Wasilczyk <twasilczyk@google.com>)
679dcf9787: Repackage ConfigUpdateInstallReceiver in telephony-common (Jared Duke <jdduke@google.com>)
67dbee48ea: Fix race condition set mobile data policy (Ling Ma <linggm@google.com>)
f40fc09d1f: Cleaned up the flag enforce_telephony_feature_mapping_for_public_apis (Jack Yu <jackyu@google.com>)
ac52fd9bdd: update to block sending check message when p2p is disabled. (joonhunshin <joonhunshin@google.com>)
78f43fd014: CTS test for satellite config OTA (Karthick M J <karthickmj@google.com>)
b9c782f064: Adjust NR timer on PCI change (Ling Ma <linggm@google.com>)
97f7110723: Remove satellite supported check before calling setSatelliteEnabledForCa... (Aishwarya Mallampati <amallampati@google.com>)
ae84b56a34: [owners] Remove forestchoi@google.com from OWNERS (Owner Cleanup Bot <swarming-tasks@owners-cleanup...)
11505c8c04: Clean up aconfig flag satellite_persist_logging (Hakjun Choi <hakjunc@google.com>)
74b0a78aff: Cleaned up the flag enforce_telephony_feature_mapping (Jack Yu <jackyu@google.com>)
11698a3934: Enable auto switch to satellite (Ling Ma <linggm@google.com>)
5b47704832: Add exception handling for radio power off during emergency call (Hwangoo Park <hwangoo@google.com>)
89a6b21fce: Cleaned up the flag roaming_notification_for_single_data_network (Jack Yu <jackyu@google.com>)
0def5801b1: Cleaned up the flag enable_telephony_analytics (Jack Yu <jackyu@google.com>)
264cb2e037: Cleaned up the flag log_mms_sms_database_access_info (Jack Yu <jackyu@google.com>)
aaf3d539f2: remove aflag declaration OEM_ENABLED_SATELLITE_FLAG (Hakjun Choi <hakjunc@google.com>)
cc656f67c7: Cleaned up the flag dismiss_network_selection_notification_on_sim_disabl... (Jack Yu <jackyu@google.com>)
f4c981c574: fixing java.lang.NullPointerException issues when cache is not build (Akash Garg <gargakash@google.com>)
1e64a98500: Cleaned up the flag reorganize_roaming_notification (Jack Yu <jackyu@google.com>)
f3f298620e: Cleaned up the flag data_rat_metric_enabled (Jack Yu <jackyu@google.com>)
7ab46564de: Cleaned up the flag dsrs_diagnostics_enabled (Jack Yu <jackyu@google.com>)
412c8b211d: Add lock and exception handling for startPointingUI (Hakjun Choi <hakjunc@google.com>)
3de51440d9: Cleaned up the flag reconnect_qualified_network (Jack Yu <jackyu@google.com>)
11a51c6beb: Cleaned up the flag data_call_session_stats_captures_cross_sim_calling (Jack Yu <jackyu@google.com>)
838611ee07: Cleaned up the flag vonr_enabled_metric (Jack Yu <jackyu@google.com>)
32b663bb7b: Cleaned up the flag backup_and_restore_for_enable_2g (Jack Yu <jackyu@google.com>)
399dc4d5d2: Revert^2 "Expose telephony flags to WiFi mainline module" (Sewook Seo <sewookseo@google.com>)
b5db88d989: Clean up aconfig flag carrier_enabled_satellite_flag (Hakjun Choi <hakjunc@google.com>)
06a63b8c3b: Fixed race condition that carrier config change event not notified (Jack Yu <jackyu@google.com>)
441bbdf656: Fix IWLAN data block due to dataServiceCheck. (Sewook Seo <sewookseo@google.com>)
e84f0048ef: [Satellite] Introduced satellite connected notification throttle time to... (arunvoddu <arunvoddu@google.com>)
defe486215: Report the updated proto version correctly for the first time of updatin... (youngtaecha <youngtaecha@google.com>)
bf9b287747: Support satellite config version for metrics (youngtaecha <youngtaecha@google.com>)
0ab0f86056: Ensure the same OnSubscriptionChangedListener is reused in PhoneConfigur... (Grant Menke <grantmenke@google.com>)
e5971468bd: Use most recent Radio HAL libraries (Andrew Lassalle <andrewlassalle@google.com>)
f6e36cd9ff: Support getVersion() of satellite access config (youngtaecha <youngtaecha@google.com>)
2d10ad8727: Logic to retrieve the satellite data supported applications. (arunvoddu <arunvoddu@google.com>)
49849546ee: DSDA: Resolve missed call not received for 2nd MT. (Pranav Madapurmath <pmadapurmath@google.com>)
a73c7371e2: Removed the flag enable_modem_cipher_transparency_unsol_events (Jack Yu <jackyu@google.com>)
b3843f62a2: Fixed incorrect permission check (Jack Yu <jackyu@google.com>)
30df24c4b2: Cleaned up the flag satellite_internet (Jack Yu <jackyu@google.com>)
b0504af9a5: Cleaned up the flag apn_setting_field_support_flag (Jack Yu <jackyu@google.com>)
bbe27c56f1: Cleaned up the flag uicc_phone_number_fix (Jack Yu <jackyu@google.com>)
cfc78eeae5: Return starlink error code for outgoing call if eligibility is true. (Aishwarya Mallampati <amallampati@google.com>)
117659dc8d: Satellite Data Support changes (Nagendra Prasad Nagarle Basavaraju <nagendranb@g...)
39d1efbb6a: Allowed Services info changes to support Data Service check (Nagendra Prasad Nagarle Basavaraju <nagendranb@g...)
fca759d088: Remove try catch for TANSPORT_SATELLITE (Nagendra Prasad Nagarle Basavaraju <nagendranb@g...)
12fb46cb03: Satellite Data Support changes (Nagendra Prasad Nagarle Basavaraju <nagendranb@g...)
753f37f920: Allowed Services info changes to support Data Service check (Nagendra Prasad Nagarle Basavaraju <nagendranb@g...)
e1f42da8d8: Added test to check that telephonyFinder returns the same countries as M... (Geoffrey Boullanger <boullanger@google.com>)
08bcaf4bd1: Fix crash when mcc is null in MccTable.getCountryCodeForMcc. (Geoffrey Boullanger <boullanger@google.com>)
5f91f203bd: Fixed ConcurrentModificationException in UiccSlot component. (arunvoddu <arunvoddu@google.com>)
3291cb3f66: Trivial fix (Ling Ma <linggm@google.com>)
c9843e2bbb: Update carrier roaming available services after selecting satellite subs... (Aishwarya Mallampati <amallampati@google.com>)
f8b20f9c77: Clean up aconfig flag oem_enabled_satellite_flag (Hakjun Choi <hakjunc@google.com>)
7e4c153a8b: Cleaned up the flag enable_modem_cipher_transparency (Jack Yu <jackyu@google.com>)
f6ae98895d: Added unsupported network capabilities (Jack Yu <jackyu@google.com>)
e93617524b: clean up flag (Ling Ma <linggm@google.com>)
9fc9719a3d: Revert^2 "Use the newly introduced MCC to country table, f..." (Geoffrey Boullanger <boullanger@google.com>)
695fb20109: Cleaned up the flag enable_identifier_disclosure_transparency_unsol_even... (Jack Yu <jackyu@google.com>)
74e1e27f1f: Revert "Use the newly introduced MCC to country table, from the ..." (Liana Kazanova (xWF) <lkazanova@google.com>)
5f732156eb: Call stopP2pSmsInactivityTimer in PowerOff and Transferring state (Aishwarya Mallampati <amallampati@google.com>)
e6731b32a9: Use the newly introduced MCC to country table, from the time zone mainli... (Geoffrey Boullanger <boullanger@google.com>)
342f138797: Added unit test for getting SatelliteAccessConfigJsonFile (Karthick M J <karthickmj@google.com>)
6ed9a419f3: Block SMS in satellite mode if P2P SMS is not supported (Aishwarya Mallampati <amallampati@google.com>)
b7ee8efcce: Update mLastNotifiedNtnEligibility before calling notify. (Aishwarya Mallampati <amallampati@google.com>)
41a6413c61: Cleaned up the flag enable_identifier_disclosure_transparency (Jack Yu <jackyu@google.com>)
06f1c0e692: Re-enable CDMA SMS dispatcher (Tomasz Wasilczyk <twasilczyk@google.com>)
d46ce473ea: [telephony] Remove the PII for user build (Sungcheol Ahn <donaldahn@google.com>)
deeaae81bf: Remove carrier configuration value check when registering screen on/off ... (joonhunshin <joonhunshin@google.com>)
51f53cac43: Handle device doesn't point to satellite in CONNECTED state (joonhunshin <joonhunshin@google.com>)
78e44bd3c8: Support satelltie access config file by configupdater (youngtaecha <youngtaecha@google.com>)
9cf9c16c14: Add flag to define redial codes for normal routed emergency call. (Avinash Malipatil <avinashmp@google.com>)
a8d039bea2: Cleaned up the flag hide_roaming_icon (Jack Yu <jackyu@google.com>)
70793e9f6a: Migrate to WorkerThread and BackgroundThread (Nathan Harold <nharold@google.com>)
d7c657c134: Cleaned up the flag enable_carrier_config_n1_control_attempt2 (Jack Yu <jackyu@google.com>)
3bac7177e2: Update ImsNrSaModeHandler to Improve Unit Testing (Nathan Harold <nharold@google.com>)
e2b3e0416f: Clean up flag (Ling Ma <linggm@google.com>)
9772f73a91: Re-enable CDMA SMS dispatcher (Tomasz Wasilczyk <twasilczyk@google.com>)
38e0836cac: If the 2-digit number is an emergency number, it should not be treated a... (joonhunshin <joonhunshin@google.com>)
2ea2c37651: Support satellite_access_config_json field (youngtaecha <youngtaecha@google.com>)
4356d5208b: Update feature flag (Ling Ma <linggm@google.com>)
f4025bcd6b: Add transport type get function in SimultaenousCallingTracker.java (Grant Menke <grantmenke@google.com>)
33f43ffb6f: Reset on radio unavailable (Ling Ma <linggm@google.com>)
c63e08ec60: Fix stringIndexOutOfBoundException in getPhoneNumberBasedCarrier (Aishwarya Mallampati <amallampati@google.com>)
4e2f49565d: Cleanup flag (Ling Ma <linggm@google.com>)
d94cb9c86c: Replace when with doReturn (Aishwarya Mallampati <amallampati@google.com>)
9acd7e4040: [Satellite] Satellite Notification changes to show data service informat... (arunvoddu <arunvoddu@google.com>)
30a60d0783: Update available services info for satellite (Nagendra Prasad Nagarle Basavaraju <nagendranb@g...)
5766555648: Remove sim slot input param from satellite HAL APIs. (Aishwarya Mallampati <amallampati@google.com>)
30eb77b2fe: Add phoneId to APDUSender log tag to distinguish multiple instances. (Qingqi Lei <qingqi@google.com>)
8b784bfe98: Call starlink HAL APIs added in RIL.java (Aishwarya Mallampati <amallampati@google.com>)
dbb25f141b: Explicitly keep default constructor in rules without members (Christoffer Adamsen <christofferqa@google.com>)
a51bda88b7: Add unit test for sms relay metrics (Hidayat Khan <hidayatkhan@google.com>)
e5ce0d20a9: Determine carrier roaming ntn eligibility only based on selectedSatellit... (Aishwarya Mallampati <amallampati@google.com>)
449d45b18d: Revert "Expose telephony flags to WiFi mainline module" (Priyanka Advani (xWF) <padvani@google.com>)
5aae2dcc89: Add unit test for isSatelliteProvisionedForNonIpDatagram (Aishwarya Mallampati <amallampati@google.com>)
4f6188d257: Add null check for subInfo (Aishwarya Mallampati <amallampati@google.com>)
162453c8a3: Add sms log to session metrics (Aishwarya Mallampati <amallampati@google.com>)
1b84454eed: Fixed that remote SIM can't be inserted correctly (Jack Yu <jackyu@google.com>)
d35ef42930: Add imei info in log for RIL#getImei (Honggang Luo <honggang.luo@sony.com>)
f0e75385f4: Aligning the API call sequence for IMS call status (yongnamcha <yongnamcha@google.com>)
4e8e3df744: Override satellite display name if we are in satellite mode and has vali... (Aishwarya Mallampati <amallampati@google.com>)
e59d2c11a4: Address API review comments. (Aishwarya Mallampati <amallampati@google.com>)
e20bf94b3c: Expose telephony flags to WiFi mainline module (Sewook Seo <sewookseo@google.com>)
00c56723e1: Add support for vendor indication that disclosures are benign (Shawn Willden <swillden@google.com>)
3b4eab147b: Add isMtSmsPolling value to OutgoingSms Atom (Adrian Mejia <adrianmg@google.com>)
34a416810a: MtSmsPolling messages to be sent the first time the satellite modem is c... (Daniel Banta <danielbanta@google.com>)
1bcb3d701e: [VZW P2P] Add metric for Carrier Roaming NB-IoT NTN module, maxInactivit... (Daniel Banta <danielbanta@google.com>)
8015be9077: Exit from satellite mode on p2p sms inactivity time out. (Aishwarya Mallampati <amallampati@google.com>)
0bfaacbaac: Make No Emergency Wifi Calling "Do Not Ask Again" text translatable (Thomas Stuart <tjstuart@google.com>)
9bd323131e: Add "isNtnOnlyCarrier" field into metrics atoms for satellite sessions. (Adrian Mejia <adrianmg@google.com>)
696c3b7d2b: Added field for outgoingSms atoms (Adrian Mejia <adrianmg@google.com>)
99126fdf5f: Allow GsmSMSDispatcher to send MtSmsPollingMessage while not in service. (Daniel Banta <danielbanta@google.com>)
30a4cfec15: Support handover rule based on incall (gwenlin <gwenlin@google.com>)
d8ca37ecb3: Fixed to not show any notification if the carrier do not support the sat... (Sungcheol Ahn <donaldahn@google.com>)
3ec9b3b64e: Add unit tests to check APDU channel is always released. (Qingqi Lei <qingqi@google.com>)
e3515e45b5: Fixed the data switch issue (Jack Yu <jackyu@google.com>)
d56d4233c2: Enhance satellite metrics (Hakjun Choi <hakjunc@google.com>)
d953275c5e: Update carrier roaming ntn eligibility whenever satellite access allowed... (Aishwarya Mallampati <amallampati@google.com>)
d80717a8c5: Ignore MCC/MNC from RIL operator indication for locale (Jack Yu <jackyu@google.com>)
478c307d23: Address API review comments (Aishwarya Mallampati <amallampati@google.com>)
cb0ebe5e43: Pass ntn signal strength to listeners in IDLE state. (Aishwarya Mallampati <amallampati@google.com>)
d09450c79c: Keep ping request (Ling Ma <linggm@google.com>)
3c9b3d9b56: Fix NPE at DisplayInfoController (Nagendra Prasad Nagarle Basavaraju <nagendranb@g...)
9685ac17f9: [Satellite] Satellite metrics to capture pending message count per datag... (arunvoddu <arunvoddu@google.com>)
6a489a8e35: Changes to support geofence for carrier satellite (Hidayat Khan <hidayatkhan@google.com>)
843c3b07d6: Removed TelephonyNetworkFactory (Jack Yu <jackyu@google.com>)
8dcd39dfd0: Select proper handover type and monitoring timeout duration (Thomas Nguyen <tnd@google.com>)
dd4d094b4b: Update CellBroadcastConfigTraker state for cleanupCdma case (Hyein Yu <hyeinyu@google.com>)
3458f70ce6: If the 2-digit number is an emergency number, it should not be treated a... (joonhunshin <joonhunshin@google.com>)
4a2fb375a4: Change the max limit count from 100 to 500 (youngtaecha <youngtaecha@google.com>)
e742a0517c: Update network request evaluation for satellite when data roaming off (Karthick M J <karthickmj@google.com>)
1df5397b96: Override satellite display name in ServiceStateTracker (Sangyun Yun <sangyun@google.com>)
f76796138b: Revert "Add NB_IOT_NTN" (Aishwarya Mallampati <amallampati@google.com>)
72b20dd5b8: [NTN][VZW P2P] Account for all cases in DatagramDispatcher to allow Chec... (Daniel Banta <danielbanta@google.com>)
a24632b991: Cleanup CDMA unit tests (Tomasz Wasilczyk <twasilczyk@google.com>)
335cf79549: Fix nvResetConfig after CDMA cleanup (Tomasz Wasilczyk <twasilczyk@google.com>)
fb280d3a86: Disable more deprecated calls (Tomasz Wasilczyk <twasilczyk@google.com>)
67a53cfa45: Update IMS call status on network type changes (yongnamcha <yongnamcha@google.com>)
```

