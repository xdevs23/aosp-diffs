```
615790d212: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
4128c8eed3: Update Aware pairing API documentation (maheshkkv <maheshkkv@google.com>)
8a6b0e8611: Don't send BLOCK_DISCOVERY when P2P is in Disabled state (sunilravi <sunilravi@google.com>)
8729cd99dd: Log WifiMulticastLockManager active sessions in WifiMetrics when filteri... (Gabriel Biren <gbiren@google.com>)
f0dba4d92d: Fix parsing of CIPHER and AKM for secure ranging (maheshkkv <maheshkkv@google.com>)
23bfefa795: Split addWifiLockActiveSession into separate methods for WifiLockManager... (Gabriel Biren <gbiren@google.com>)
cfdd5f1d6a: Log WifiMulticastLockManager acquired sessions in WifiMetrics when locks... (Gabriel Biren <gbiren@google.com>)
d5c5b2bf3c: Fix mobly issue (Nate Jiang <qiangjiang@google.com>)
70b1a5f693: Implement the remaining USD methods in the framework mainline supplicant... (Gabriel Biren <gbiren@google.com>)
6f9b934db4: Add framework implementations for startUsdPublish and startUsdSubscribe. (Gabriel Biren <gbiren@google.com>)
739e49277d: Retrieve the attribution tag and package name when a multicast lock is a... (Gabriel Biren <gbiren@google.com>)
ad4675fe32: Split addWifiLockAcqSession into separate methods for WifiLockManager an... (Gabriel Biren <gbiren@google.com>)
b4dbe39009: Only release the Aware when it's disabled from vendor (Nate Jiang <qiangjiang@google.com>)
9d204dbd2f: Implement the USD callbacks in the framework mainline supplicant class. (Gabriel Biren <gbiren@google.com>)
7c2351f0fe: Update SarInfo even before boot completed (Nate Jiang <qiangjiang@google.com>)
d65e6affdb: Allow fulfill approved request even screen off (Nate Jiang <qiangjiang@google.com>)
6080c0a6f5: Use ParceledListSlice fix the binder transcation issue (Nate Jiang <qiangjiang@google.com>)
32c880ec8e: Wifi: remove usages of deprecated Mockito matchers (Adrian Roos <roosa@google.com>)
d9155dc8da: Fix secure ranging result flag (maheshkkv <maheshkkv@google.com>)
533a191ac7: Fix Secure ranging result processing (maheshkkv <maheshkkv@google.com>)
f51443e4bc: Update pre-shared key for secure ranging (maheshkkv <maheshkkv@google.com>)
5d83e0c385: Mask the password string for PASN config (maheshkkv <maheshkkv@google.com>)
452e0ea4c4: Fix the cipher usage for PASN (maheshkkv <maheshkkv@google.com>)
ba584eb50c: Remove the timeout in network factory. (Nate Jiang <qiangjiang@google.com>)
c54183a057: Fix RangingResult#toString() format (maheshkkv <maheshkkv@google.com>)
51395dd8df: Use Background thread in LastMileLogger (Oscar Shu <xshu@google.com>)
47666f6dd8: Decrease framework connection timeout (Oscar Shu <xshu@google.com>)
1f4ce7c4b2: Support AT&T IMSI protect requirement 1.2 (xiaoyingliu <xiaoyingliu@google.com>)
02000ff19f: Put the SSR event to the front of the queue (Nate Jiang <qiangjiang@google.com>)
fe7f10859f: Wifi P2p Manager Test Cases (ChenYu <wangchenyu@google.com>)
188b3a0d85: Parcel should not change any value (Nate Jiang <qiangjiang@google.com>)
014ef4cd77: [CTS-V-Host][WiFi] Remove CTS-V-Host tag from Wifi Direct tests and remo... (Minghao Li <minghaoli@google.com>)
3b2ec0c97e: [CTS-V-Host][WiFi] Fix the bug that test skip singal was transformed to ... (Minghao Li <minghaoli@google.com>)
d96fd31fa3: [CTS-V-Host][WiFi] Remove mainline module check configuration in CTS-V-H... (Minghao Li <minghaoli@google.com>)
9d3aab90d3: Register a callback with each STA interface when it is brought up in mai... (Gabriel Biren <gbiren@google.com>)
2a1c84b0e5: [AAPM] Add WEP FeatureId for getFeatures (Hani Kazmi <hanikazmi@google.com>)
79f6de360d: Add a skeleton implementation for MainlineSupplicantStaIfaceCallback. (Gabriel Biren <gbiren@google.com>)
64831ff299: Support shell cmd to clear all suggestions added into this device (xiaoyingliu <xiaoyingliu@google.com>)
7e22846566: WiFi: Force 11be to false when 11ax is false. (Les Lee <lesl@google.com>)
c7d3f17c17: Cleanup the mainline supplicant AIDL interface. (Gabriel Biren <gbiren@google.com>)
fa6b15b93d: Wifi: remove usages of deprecated Mockito matchers (Adrian Roos <roosa@google.com>)
cfbda2df84: Include mockito extended explicitly (Remi NGUYEN VAN <reminv@google.com>)
3419639e13: packages/modules/Wifi: remove usages of Mockito.verifyZeroInteractions (Adrian Roos <roosa@google.com>)
109b96c6b4: Wifi P2p Manager Test Cases (ChenYu <wangchenyu@google.com>)
87ee3ae234: Stop mocking the WifiStatsLog (Nate Jiang <qiangjiang@google.com>)
7331612313: Cleanup python version properties (Cole Faust <colefaust@google.com>)
aab313c77c: Add STA interfaces to mainline supplicant when they are added in the ven... (Gabriel Biren <gbiren@google.com>)
8b6c3799f5: Add methods to add and remove a STA interface to the MainlineSupplicant ... (Gabriel Biren <gbiren@google.com>)
cf7e370efc: Revert "Revert "Rename IUsdInterface to IStaInterface, and add a..." (Gabriel Biren <gbiren@google.com>)
b67a3dc096: Revert "Revert "Change the return type in the addUsdInterface AI..." (Gabriel Biren <gbiren@google.com>)
50c759bfd7: Revert "Change the return type in the addUsdInterface AIDL defin..." (Liana Kazanova (xWF) <lkazanova@google.com>)
9dec2c8502: Revert "Rename IUsdInterface to IStaInterface, and add a registe..." (Liana Kazanova (xWF) <lkazanova@google.com>)
708c476af6: Retry calling WifiP2pManager#discoverPeers 3 times if GC failed to disco... (Minghao Li <minghaoli@google.com>)
02f2d5166a: packages/modules/Wifi: remove deprecated Mockito usages (Adrian Roos <roosa@google.com>)
bb693815f2: Fix the Aware geofence threshold (maheshkkv <maheshkkv@google.com>)
f3249fd911: Temporarily block local-only network if user switch away (Oscar Shu <xshu@google.com>)
82c728c672: Cleanup python version properties (Cole Faust <colefaust@google.com>)
b84c69f406: Remove group in Wi-Fi Direct test (sunilravi <sunilravi@google.com>)
c9f43d9984: Add an overlay to override publisher support (maheshkkv <maheshkkv@google.com>)
4ad3b19e25: Add USD status listener support (maheshkkv <maheshkkv@google.com>)
0281a24a9c: Rename IUsdInterface to IStaInterface, and add a registerCallback method... (Gabriel Biren <gbiren@google.com>)
814e5d2776: Change the return type in the addUsdInterface AIDL definition to return ... (Gabriel Biren <gbiren@google.com>)
c3e6fba897: Support for re-invoking the persistent WFD R2 group (sunilravi <sunilravi@google.com>)
f7be34e513: Limit disable firmware roaming only when screen is off (Oscar Shu <xshu@google.com>)
420f7402ea: Unit test for Wi-Fi Direct R2 USD (Sunil Ravi <sunilravi@google.com>)
40bceaf0e1: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
b4d172f287: Fix scan mode switch issue (Ye Jiao <ye.jiao@mediatek.com>)
d5b843d0fb: Revert "Add NIDL rro" (Gabriel Biren <gbiren@google.com>)
12c01a5447: Start and stop the mainline supplicant alongside the vendor supplicant. (Gabriel Biren <gbiren@google.com>)
8ac4d00660: WiFi Aware RTT Disable Test Cases (ChenYu <wangchenyu@google.com>)
8f9802485e: Adding API in AwareDataPath test (lutina <lutina@google.com>)
702e6d2de2: [CTS-V-HOST] Enable WiFi verbose logging in new CTS-V-HOST tests. (Minghao Li <minghaoli@google.com>)
f2b6a4ca03: Add a framework death handler for the mainline supplicant in WifiNative. (Gabriel Biren <gbiren@google.com>)
291318a3f3: WiFi Aware RTT Disable Test Cases (ChenYu <wangchenyu@google.com>)
a68c72bd04: Shut down wifi if WifiIfaceInfo is out of sync with cache (Quang Anh Luong <qal@google.com>)
795e57980f: Fix secure ranging request conversion (maheshkkv <maheshkkv@google.com>)
54f8683202: WiFi P2P GroupTest Cases (ChenYu <wangchenyu@google.com>)
5e2de3b3c7: [owners] Remove murj@google.com from tests/OWNERS (Owner Cleanup Bot <swarming-tasks@owners-cleanup...)
b8030e65b2: Fix WFDR2 unit tests (sunilravi <sunilravi@google.com>)
a46e43b428: Fix GroupOwnerTest#test_connect_with_pin_code failure by sleeping 10 sec... (Minghao Li <minghaoli@google.com>)
63af1db730: Fix watchdog preventing blocklist (Oscar Shu <xshu@google.com>)
03005d3359: Notify WifiStateChangedListener upon registration (Quang Anh Luong <qal@google.com>)
f00d2eff06: Don't add SAE AKM when preshared key is raw PSK (sunilravi <sunilravi@google.com>)
246b4d8e29: Add missing data dependency in integration test (Kolin Lu <kolinlu@google.com>)
259cc5ad45: Add a method to check whether mainline supplicant is available. (Gabriel Biren <gbiren@google.com>)
a248a5c055: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
8ae53188b3: wifi: generated LOHS config should be SAE when customized band is 6GHz (Les Lee <lesl@google.com>)
3fb8c35923: Add coverage for secure ranging in NetworkDetail (maheshkkv <maheshkkv@google.com>)
5367efaf3d: Add coverage for secure ranging in ScanResult (maheshkkv <maheshkkv@google.com>)
a6b3a9be34: Add coverage for Rsnxe class (maheshkkv <maheshkkv@google.com>)
286d6525f0: Fix RangingResult parcelling (maheshkkv <maheshkkv@google.com>)
6a4bacc625: Add unit test for SecureRangingConfig (maheshkkv <maheshkkv@google.com>)
6aefad8617: Create an instance of MainlineSupplicant and pass it to WifiNative. (Gabriel Biren <gbiren@google.com>)
150737dfb8: Update boot image and system server profiles [M46C37P58S0PP] (art-benchmark-service <art-benchmark-service-bot...)
c2e6d7004d: Add WiFi Aware ApiTest description for the following cases. (ChenYu <wangchenyu@google.com>)
d4ec149514: Fix PasnConfig parcelling (maheshkkv <maheshkkv@google.com>)
c3ea19625f: Move to GroupCreatedState after user accepting the connect request (ellen.yang <ellen.yang@unisoc.com>)
9e8107b993: wifi: Checks telephony flag & overlay when enabling wifi voip detection (Les Lee <lesl@google.com>)
309e4b640b: WFD-R2: Support for provision discovery (Sunil Ravi <sunilravi@google.com>)
8850de0981: Add @UnsupportedAppUsage to @hide API (Oscar Shu <xshu@google.com>)
b044e598d4: Create a Mobly test suite to run all Wi-Fi Aware Integration tests (Kolin Lu <kolinlu@google.com>)
4254ce0166: Keep public long getSupportedFeatures() in ConcreteClientModeManager (Nate Jiang <qiangjiang@google.com>)
3c80bb9f03: Make verbose logging on for eng build (Nate Jiang <qiangjiang@google.com>)
6d776dd6ae: Dismiss EAP failure notification when connected (Oscar Shu <xshu@google.com>)
f48ad3901b: Add Wifi connection duration to WifiMetrics. (yachilin <yachilin@google.com>)
2b08fafc83: Remove powerstat from Wifi dump (Nate Jiang <qiangjiang@google.com>)
d7b19b3bd9: Adding API test in awaretest#1 (lutina <lutina@google.com>)
a60b5b8669: Wifi: use mMldAddress to display MLD MAC if exist (Xin Deng <quic_deng@quicinc.com>)
03c3d1e3cf: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
66460c4c4f: Add xshu to wifi owners (Oscar Shu <xshu@google.com>)
5867bf3d05: Handle deferred CMD_AIRPLANE_TOGGLED (Oscar Shu <xshu@google.com>)
e9b7f76ec6: wifi: fix incorrect calling feature support check (Les Lee <lesl@google.com>)
ea553ee622: wifi: Using registerReceiverForAllUsers (Les Lee <lesl@google.com>)
0befec7e14: Allow WifiNetworkSpecifier to hint preference to secondary (Oscar Shu <xshu@google.com>)
275f0acf0a: WiFi Aware Datapath Test#7 (lutina <lutina@google.com>)
28f7312aae: Add size check for IP config (Nate Jiang <qiangjiang@google.com>)
a7b08b4051: Add size check for IP config (Nate Jiang <qiangjiang@google.com>)
caa9a4c7b4: Add size check for IP config (Nate Jiang <qiangjiang@google.com>)
360eb9fd69: Change the max length of username from 63 octets to 253 octets. (xiaoyingliu <xiaoyingliu@google.com>)
73467ad812: WiFi Aware Datapath Test#6 (lutina <lutina@google.com>)
b336c66cf9: WiFi Aware DiscoveryWithRanging Test (ChenYu <wangchenyu@google.com>)
57e446cfdc: Add size check for IP config (Nate Jiang <qiangjiang@google.com>)
ea9d8f7dd3: Update coverage files (Nate Jiang <qiangjiang@google.com>)
7b42f5c3e0: Check both OEM and chip support in the P2P, Aware, and Passpoint-support... (Gabriel Biren <gbiren@google.com>)
8628d8bda2: Bind/Unbind WiFi scorer service when the scorer is set/cleared. (xiaoyingliu <xiaoyingliu@google.com>)
92712183f7: Revert "Bind WiFi scorer service to prevent the external scorer from fre... (Xiaoying Liu <xiaoyingliu@google.com>)
9fe597d92c: Put unregister listener in handler (Oscar Shu <xshu@google.com>)
63df4a18b8: WiFi Aware Protocols Test Test #2 (ChenYu <wangchenyu@google.com>)
e45f3d8983: Unify burstDuration calculation in AIDL and HIDL (maheshkkv <maheshkkv@google.com>)
8b6c18926a: Fix an import error (Nate Jiang <qiangjiang@google.com>)
eac7eda0b1: Replace .toList() with .collect() (Cole Faust <colefaust@google.com>)
138ed3d5fc: Bind WiFi scorer service to prevent the external scorer from freezing. (xiaoyingliu <xiaoyingliu@google.com>)
35a563bbe1: Add max_client to SoftApStoppedEvent. (yachilin <yachilin@google.com>)
dd27f7a679: Check permission before calling LOHS callback (Quang Anh Luong <qal@google.com>)
e707a9a172: Normalizes ring buffer timebase (peroulas <peroulas@google.com>)
2472073f13: Reschedule DPP timer for connection status result frame (Sunil Ravi <sunilravi@google.com>)
443d434f9c: Ensures ring buffer R/W is synchronized. (peroulas <peroulas@google.com>)
cb0fa6a2a8: Ring buffer is no longer cleared. (peroulas <peroulas@google.com>)
74d88deafd: Removes unused code. (peroulas <peroulas@google.com>)
90717ef12d: WFD-R2: Set IP provisioning mode to IPV6 link local (Sunil Ravi <sunilravi@google.com>)
00f8df8582: Unit test for Wi-Fi Direct R2 (Sunil Ravi <sunilravi@google.com>)
73f5370e7f: Correctly specify the config for CtsWifiSoftApTestCases (Xianyuan Jia <xianyuanjia@google.com>)
6cb0a409b2: wifi: Only update SAP allowed channel for non world mode country code (Les Lee <lesl@google.com>)
915381054c: Check the flag in the code when using new API (Nate Jiang <qiangjiang@google.com>)
acbff7b01c: Fix NPE in getPerSsidRoamingModes Log (Quang Anh Luong <qal@google.com>)
48a21d45c2: wifi: Mock security flag value to avoid mismatch problem (Les Lee <lesl@google.com>)
af7fe0c305: Add to CTS-v-host test (Nate Jiang <qiangjiang@google.com>)
e664b7e6c0: [CTS-V] Add the ATS config and cts-v-host tag to new Wifi Aware and Dire... (Minghao Li <minghaoli@google.com>)
5b2d8bba81: [CTS-V Migration][Wi-Fi Direct] Add test #11-19. (An Liu <aaanliu@google.com>)
dd11903a4b: WiFi Aware Datapath Test#5 (lutina <lutina@google.com>)
57b3213285: Clear blocklist after a full band scan (maheshkkv <maheshkkv@google.com>)
9d525f1e27: Delay the release lock to avoid stress the HAL (Nate Jiang <qiangjiang@google.com>)
f3d3d714bd: Trigger full band scan immediately if channel set (Nate Jiang <qiangjiang@google.com>)
bd771a93a3: Add logging for SoftApCallback#onClientsDisconnected (Chris Desir <cdesir@google.com>)
28c5c3664c: [CTS-V Migration][Wi-Fi Direct] Add test #8-10. (An Liu <aaanliu@google.com>)
41ec15893b: WiFi Aware Datapath Test#4 (lutina <lutina@google.com>)
2b0f4c690b: WiFi Aware Datapath Test#3 (lutina <lutina@google.com>)
59303aa426: ProtocolsMultiCountry Test (ChenYu <wangchenyu@google.com>)
5a3bbe16f8: WiFi Aware DiscoveryWithRanging Test #2 (ChenYu <wangchenyu@google.com>)
37a0df5305: WiFi Aware Datapath Test#2 (lutina <lutina@google.com>)
f701ada004: [CTS-V Migration][Wi-Fi Direct] Add test #5-7. (An Liu <aaanliu@google.com>)
6029597038: [CTS-V Migration][Wi-Fi Direct] Add test case #4. (An Liu <aaanliu@google.com>)
6174d6a75c: Fix channel validation logic in USD subscriber (maheshkkv <maheshkkv@google.com>)
47173579ec: Adds human readable logging text (peroulas <peroulas@google.com>)
609a4ab1cf: [CTS-V Modernization][Wi-Fi Aware] Avoid querying distance when got a ra... (An Liu <aaanliu@google.com>)
e2994751b6: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
8332e84391: Revert "P2P Ownership" (Stephanie Bak <dasol@google.com>)
383be217ca: wifi: Check 11AX when 11BE is configured. (Les Lee <lesl@google.com>)
8de0f9b201: Revert "Check if dual p2p is supported" (Stephanie Bak <dasol@google.com>)
fd2f2d344a: Revert "Update P2P Connection Changed Broadcast" (Stephanie Bak <dasol@google.com>)
6cc29c65d4: Revert "Add L3ConnectingState" (Stephanie Bak <dasol@google.com>)
09db8602e6: wifi: Check driver capability when determining the number of supported M... (Les Lee <lesl@google.com>)
38ed018127: WiFi Aware DiscoveryWithRanging Test #1 (ChenYu <wangchenyu@google.com>)
18a072788c: WiFi Aware Protocols Test Test #1 (ChenYu <wangchenyu@google.com>)
85583169dc: Add channel bandwidth into Wifi health stat report. (yachilin <yachilin@google.com>)
5eec0acd38: Fix RTT preamble based on band and RTT type (maheshkkv <maheshkkv@google.com>)
1b16453c1f: Bug fix on accessing AP BSSID (Peng Wang <wanpeng@google.com>)
5858def136: Fix format in constants.py. (Minghao Li <minghaoli@google.com>)
2024a17c43: [CTS-V Modernization][Wifi Aware] Re-organize the WiFi Aware test code. (Minghao Li <minghaoli@google.com>)
9e2c6d828d: Do not get looper during initialize (Nate Jiang <qiangjiang@google.com>)
2ce0e59037: Pass the USD config error code from the HAL to the framework callbacks. (Gabriel Biren <gbiren@google.com>)
4a0f243d81: [CTS-V Migration][Wi-Fi Direct] Implement test case #3. (Minghao Li <minghaoli@google.com>)
a0b5c10352: Add txLinkSpeed and rxLinkSpeed into Wifi health stat report. (yachilin <yachilin@google.com>)
e5533d0a90: Bug fix while copying wifiUsabilityStatsTraining (Peng Wang <wanpeng@google.com>)
aac147fa40: wifi: supports to query mlo support by shell (Les Lee <lesl@google.com>)
fa313762c9: wifi: Copy channels configuration only for non exclusive config (Les Lee <lesl@google.com>)
17cc52980e: Add frequency into wifi connection result report metric. (yachilin <yachilin@google.com>)
ac9d6dc8c8: Revert^2 "[AAPM] Update WEP feature identifier" (Hani Kazmi <hanikazmi@google.com>)
a97278f01a: Reduce WifiConnectivityManager test flaky (Oscar Shu <xshu@google.com>)
3432c0d00b: Minimize ScanResult garbage churn (Jared Duke <jdduke@google.com>)
41dce2ef16: Address API review comments for NAN periodic ranging (maheshkkv <maheshkkv@google.com>)
c835338f1b: Need to log wifi on after reboot (Oscar Shu <xshu@google.com>)
57b15e518b: ClientMode L3 disconnect  should not call reportConnectionAttemptEnd (Oscar Shu <xshu@google.com>)
94e12ed9eb: Update disabling state earlier (Oscar Shu <xshu@google.com>)
5b749d16f3: Support for Connection using P2P pairing protocol (Sunil Ravi <sunilravi@google.com>)
83274c7424: Revert "[AAPM] Update WEP feature identifier" (Priyanka Advani (xWF) <padvani@google.com>)
8a92493c93: Update feature logging in WifiServiceImpl and add shell command to print... (Gabriel Biren <gbiren@google.com>)
18a29f3725: Add utility class to format the WifiManager features as a String. (Gabriel Biren <gbiren@google.com>)
89f3b5bc1f: Add error code to the framework onUsdPublishConfigFailed and onUsdSubscr... (Gabriel Biren <gbiren@google.com>)
9af253d462: Implementation of DIR APIs for BLE assisted connection (Sunil Ravi <sunilravi@google.com>)
3085ff7838: wifi: Update P2P device found with WFD R2 information (Sunil Ravi <sunilravi@google.com>)
af73f07a57: wifi: WFD USD based service advertisement (Sunil Ravi <sunilravi@google.com>)
fc7c2c2387: wifi: WFD USD based service discovery (Sunil Ravi <sunilravi@google.com>)
7677042d68: Add 11az secure ranging implementation (maheshkkv <maheshkkv@google.com>)
8a28f3da9c: Add USD implementation (maheshkkv <maheshkkv@google.com>)
3992aeca66: Keep the old method for backward compatible (Nate Jiang <qiangjiang@google.com>)
bc0abe1a81: Update USD subscriber/publisher availability APIs (maheshkkv <maheshkkv@google.com>)
72599e969e: WiFi Aware MacRandom Test (ChenYu <wangchenyu@google.com>)
2aa2011223: WiFi Aware Capabilities Test #1 (ChenYu <wangchenyu@google.com>)
0339866aba: Configure WiFi multidevice CTS tests to be added to cts-interactive suit... (Xianyuan Jia <xianyuanjia@google.com>)
f7a67049b0: wifi:  DFS support for Wi-Fi 5GHz frequency channels (Les Lee <lesl@google.com>)
ca6a55709a: wifi: comparing caller priority for LOHS (Les Lee <lesl@google.com>)
5be7338f05: Use TetheringRequest to start SoftApManager (Quang Anh Luong <qal@google.com>)
b3edcc5ec0: API feedback changes in USD and Pairing (Sunil Ravi <sunilravi@google.com>)
7758b5fd39: Add shell command to set wifi throttling (Oscar Shu <xshu@google.com>)
56ab854acc: wifi: refactoring java doc since it is public API (Les Lee <lesl@google.com>)
5a4f198bfc: API feedback changes in WifiP2pConfig (Sunil Ravi <sunilravi@google.com>)
04903dc00c: WiFi Aware Datapath Test#1 (lutina <lutina@google.com>)
1d4e6ba665: wifi: Calls hostapd link removal API when current AP is using MLO (Les Lee <lesl@google.com>)
38e416011e: Format proto field with underscore (Peng Wang <wanpeng@google.com>)
3720db9378: Fix ClientModeImpl disconnect behavior (Oscar Shu <xshu@google.com>)
13728ebbbd: Add a check to build time overlay for USD support (maheshkkv <maheshkkv@google.com>)
09a6496c09: Add missing fields into proto copy func (Peng Wang <wanpeng@google.com>)
92b678f5ca: Add WifiManager and TetheringManager snippet to Wi-Fi snippet APK (Chris Desir <cdesir@google.com>)
98444b56c2: Add multidevice testing for SoftApCallback#onClientsDisconnected (Chris Desir <cdesir@google.com>)
0566dac7f7: [CTS-V Migration] Add ApiTest annotation to new Wi-Fi CTS-V tests. (Minghao Li <minghaoli@google.com>)
09bf6db23c: Handle locale change in Resource Cache (qiangjiang <qiangjiang@google.com>)
7584b9646b: Add WiFi Scorer data capture function in framework (Peng Wang <wanpeng@google.com>)
4d5ecdbabe: [AAPM] Update WEP feature identifier (Azhara Assanova <azharaa@google.com>)
238b128bb1: Reset resource cache when SIM changes to adopt carrier specific overlay (qiangjiang <qiangjiang@google.com>)
73fd50bec3: Import translations. DO NOT MERGE ANYWHERE (Bill Yi <byi@google.com>)
3b1b5900b0: wifi: fill mld MAC address to SoftApInfo (Les Lee <lesl@google.com>)
055e9f894f: Bug fix throughput predictor. (Kai Shi <kaishi@google.com>)
6baa094752: Remove unused resources from overlayable.xml (Abhijit Adsule <adsule@google.com>)
44b3d9e880: [CTS-V Migration][Wi-Fi Direct] Extract Wi-Fi Direct utility functions i... (Minghao Li <minghaoli@google.com>)
78e4b9643d: [CTS-V Migration][Wi-Fi Direct] Adjust wifi p2p test utils to make tests... (Minghao Li <minghaoli@google.com>)
d3767073d4: [CTS-V Migration][Wi-Fi Direct] Add the skeleton of 2nd test class and c... (Minghao Li <minghaoli@google.com>)
db24d146dc: Add USD methods to the Mainline Supplicant Unstable AIDL interface. (Gabriel Biren <gbiren@google.com>)
ac914b9c35: Add all USD parcelables and enums to the mainline supplicant AIDL interf... (Gabriel Biren <gbiren@google.com>)
c2d503d3cd: [CTS-V Migration][Wi-Fi Direct] Implement test case #2 (An Liu <aaanliu@google.com>)
c118007bf8: Remove flag of WiFi Scorer new stats (Peng Wang <wanpeng@google.com>)
19e35e8a08: DEV: Fill in testUpdateWifiUsabilityStatsEntries() (Peng Wang <wanpeng@google.com>)
```

