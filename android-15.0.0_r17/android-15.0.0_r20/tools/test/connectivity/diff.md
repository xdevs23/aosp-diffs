```diff
diff --git a/acts/framework/acts/controllers/openwrt_lib/wireless_settings_applier.py b/acts/framework/acts/controllers/openwrt_lib/wireless_settings_applier.py
index 57329a0dd..ccd7fcc4f 100644
--- a/acts/framework/acts/controllers/openwrt_lib/wireless_settings_applier.py
+++ b/acts/framework/acts/controllers/openwrt_lib/wireless_settings_applier.py
@@ -63,6 +63,13 @@ class WirelessSettingsApplier(object):
     self.ssh.run("uci set wireless.%s.channel='%s'" % (self.radio_5g, self.channel_5g))
     if self.channel_5g == 165:
       self.ssh.run("uci set wireless.%s.htmode='VHT20'" % self.radio_5g)
+    elif self.channel_5g in [64]:
+      self.ssh.run("iw reg set IN")
+      self.ssh.run("uci set wireless.%s.htmode='VHT40'" % self.radio_5g)
+    elif self.channel_5g in [144]:
+      self.ssh.run("iw reg set RU")
+      self.ssh.run("uci set wireless.%s.htmode='VHT40'" % self.radio_5g)
+      self.ssh.run("uci set wireless.%s.country3=0x49" % self.radio_5g)
     elif self.channel_5g in [149,153,157,161,165]:
       self.ssh.run("iw reg set US")
     elif self.channel_5g == 132 or self.channel_5g == 136:
diff --git a/acts_tests/acts_contrib/test_utils/wifi/wifi_test_utils.py b/acts_tests/acts_contrib/test_utils/wifi/wifi_test_utils.py
index 79ded25b3..14d54259f 100755
--- a/acts_tests/acts_contrib/test_utils/wifi/wifi_test_utils.py
+++ b/acts_tests/acts_contrib/test_utils/wifi/wifi_test_utils.py
@@ -370,6 +370,7 @@ class WifiEnums():
         5660: 132,
         5680: 136,
         5700: 140,
+        5720: 144,
         5745: 149,
         5765: 153,
         5785: 157,
diff --git a/acts_tests/tests/google/wifi/WifiEdgeChannelsTest.py b/acts_tests/tests/google/wifi/WifiEdgeChannelsTest.py
new file mode 100644
index 000000000..fc52ee4c6
--- /dev/null
+++ b/acts_tests/tests/google/wifi/WifiEdgeChannelsTest.py
@@ -0,0 +1,104 @@
+#!/usr/bin/env python3.4
+#
+#   Copyright 2024 - The Android Open Source Project
+#
+#   Licensed under the Apache License, Version 2.0 (the "License");
+#   you may not use this file except in compliance with the License.
+#   You may obtain a copy of the License at
+#
+#       http://www.apache.org/licenses/LICENSE-2.0
+#
+#   Unless required by applicable law or agreed to in writing, software
+#   distributed under the License is distributed on an "AS IS" BASIS,
+#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+#   See the License for the specific language governing permissions and
+#   limitations under the License.
+
+from acts.controllers.ap_lib import hostapd_constants
+import acts.signals as signals
+import acts_contrib.test_utils.wifi.wifi_test_utils as wutils
+from acts_contrib.test_utils.wifi.WifiBaseTest import WifiBaseTest
+
+
+class WifiEdgeChannelsTest(WifiBaseTest):
+  """Tests for Wifi Edge Channel Connection.
+
+  Test Bed Requirement:
+  * One Android devices and an AP.
+  * 2GHz and 5GHz Wi-Fi network visible to the device.
+  """
+
+  def setup_class(self):
+    super().setup_class()
+
+    self.dut = self.android_devices[0]
+    wutils.wifi_test_device_init(self.dut)
+    wutils.wifi_toggle_state(self.dut, True)
+    req_params = ["wifi6_models",]
+    opt_param = ["reference_networks", "pixel_models"]
+    self.unpack_userparams(req_param_names=req_params,
+                           opt_param_names=opt_param)
+
+  def setup_test(self):
+    self.dut.droid.wakeLockAcquireBright()
+    self.dut.droid.wakeUpNow()
+
+  def teardown_test(self):
+    super().teardown_test()
+    self.dut.droid.wakeLockRelease()
+    self.dut.droid.goToSleepNow()
+
+  def configure_ap(self, channel_2g=None, channel_5g=None):
+    """Configure and bring up AP on required channel.
+
+    Args:
+        channel_2g: The channel number to use for 2GHz network.
+        channel_5g: The channel number to use for 5GHz network.
+
+    """
+    if not channel_2g:
+      channel_2g = hostapd_constants.AP_DEFAULT_CHANNEL_2G
+    if not channel_5g:
+      channel_5g = hostapd_constants.AP_DEFAULT_CHANNEL_5G
+    if "OpenWrtAP" in self.user_params:
+      self.openwrt = self.access_points[0]
+      self.configure_openwrt_ap_and_start(
+          wpa_network=True,
+          channel_2g=channel_2g,
+          channel_5g=channel_5g)
+
+  def verify_wifi_connection(self, channel_2g=None, channel_5g=None):
+    """Verify wifi connection on given channel.
+    Args:
+        channel_2g: The channel number to use for 2GHz network.
+        channel_5g: The channel number to use for 5GHz network.
+    """
+    self.configure_ap(channel_2g=channel_2g, channel_5g=channel_5g)
+    if channel_2g:
+      network = self.reference_networks[0]["2g"]
+    elif channel_5g:
+      network = self.reference_networks[0]["5g"]
+    else :
+      raise signals.TestError("No channel specified")
+
+    wutils.connect_to_wifi_network(self.dut, network)
+    wutils.verify_11ax_wifi_connection(self.dut, self.wifi6_models,
+                                       "wifi6_ap" in self.user_params)
+    self.dut.log.info("Current network = %s" %
+                       self.dut.droid.wifiGetConnectionInfo())
+    try:
+      self.dut.ed.clear_all_events()
+      wutils.wait_for_disconnect(self.dut, timeout=180)
+    except:
+      self.dut.log.info("Disconnection not happened (as expected)")
+    else:
+      self.dut.log.info("Unexpected disconnection happened")
+      raise signals.TestFailure("Unexpected disconnection happened")
+
+  def test_wifi_connect_edge_channel_64(self):
+    """Test to connect 5G edge channel 64."""
+    self.verify_wifi_connection(channel_5g=64)
+
+  def test_wifi_connect_edge_channel_144(self):
+    """Test to connect 5G edge channel 144."""
+    self.verify_wifi_connection(channel_5g=144)
diff --git a/acts_tests/tests/google/wifi/WifiManagerTest.py b/acts_tests/tests/google/wifi/WifiManagerTest.py
index 26cc60752..33f7436a2 100644
--- a/acts_tests/tests/google/wifi/WifiManagerTest.py
+++ b/acts_tests/tests/google/wifi/WifiManagerTest.py
@@ -116,6 +116,8 @@ class WifiManagerTest(WifiBaseTest):
             ad.droid.wakeLockRelease()
             ad.droid.goToSleepNow()
         self.turn_location_off_and_scan_toggle_off()
+        self.dut.adb.shell("cmd bluetooth_manager enable")
+        self.dut.adb.shell("cmd bluetooth_manager wait-for-state:STATE_ON")
         if self.dut.droid.wifiIsApEnabled():
             wutils.stop_wifi_tethering(self.dut)
         for ad in self.android_devices:
@@ -1320,3 +1322,30 @@ class WifiManagerTest(WifiBaseTest):
                                 " setCoexUnsafeChannels")
 
         self.dut.droid.wifiUnregisterCoexCallback()
+
+    def test_reboot_bluetooth_off_location_off(self):
+        """
+        Toggle bluetooth and location OFF then reboot and test wifi connection.
+
+        Steps:
+        1. Toggle bluetooth and location OFF
+        2. Reboot device
+        3. Connect to a 2GHz network and verify internet connection
+        4. Connect to a 5GHz network and verify internet connection
+        """
+        self.log.info("Toggling location and bluetooth OFF")
+        acts.utils.set_location_service(self.dut, False)
+        self.dut.adb.shell("cmd bluetooth_manager disable")
+        self.dut.adb.shell("cmd bluetooth_manager wait-for-state:STATE_OFF")
+
+        self.dut.reboot()
+        time.sleep(DEFAULT_TIMEOUT)
+        self.dut.adb.shell("cmd bluetooth_manager wait-for-state:STATE_OFF")
+
+        wutils.connect_to_wifi_network(self.dut, self.wpa_networks[0]["2g"])
+        wutils.verify_11ax_wifi_connection(
+            self.dut, self.wifi6_models, "wifi6_ap" in self.user_params)
+
+        wutils.connect_to_wifi_network(self.dut, self.wpa_networks[0]["5g"])
+        wutils.verify_11ax_wifi_connection(
+            self.dut, self.wifi6_models, "wifi6_ap" in self.user_params)
diff --git a/acts_tests/tests/google/wifi/WifiPreTest.py b/acts_tests/tests/google/wifi/WifiPreTest.py
index cc470786e..829241eb2 100644
--- a/acts_tests/tests/google/wifi/WifiPreTest.py
+++ b/acts_tests/tests/google/wifi/WifiPreTest.py
@@ -100,10 +100,13 @@ class WifiPreTest(WifiBaseTest):
         openwrt.ssh = connection.SshConnection(openwrt.ssh_settings)
         openwrt.ssh.setup_master_ssh()
         return True
-      except (paramiko.ssh_exception.NoValidConnectionsError,
-              paramiko.ssh_exception.AuthenticationException,
-              paramiko.ssh_exception.SSHException,
-              TimeoutError) as e:
+      except (
+          paramiko.ssh_exception.NoValidConnectionsError,
+          paramiko.ssh_exception.AuthenticationException,
+          paramiko.ssh_exception.SSHException,
+          connection.Error,
+          TimeoutError,
+      ) as e:
         logging.info(f"Connection error: {e}, reconnecting {ip} "
                       f"in {retry_duration} seconds.")
         time.sleep(_POLL_AP_RETRY_INTERVAL_SEC)
@@ -131,7 +134,7 @@ class WifiPreTest(WifiBaseTest):
         for radio in radios:
           ssid_radio_map = openwrt.get_ifnames_for_ssids(radio)
           for ssid, radio_ifname in ssid_radio_map.items():
-              openwrt.log.info(f"{radio_ifname}:  {ssid}")
+            openwrt.log.info(f"{radio_ifname}:  {ssid}")
 
         band_bssid_map = openwrt.get_bssids_for_wifi_networks()
         openwrt.log.info(band_bssid_map)
diff --git a/acts_tests/tests/google/wifi/WifiSoftApTest.py b/acts_tests/tests/google/wifi/WifiSoftApTest.py
index 12cf328da..211562dcf 100644
--- a/acts_tests/tests/google/wifi/WifiSoftApTest.py
+++ b/acts_tests/tests/google/wifi/WifiSoftApTest.py
@@ -123,6 +123,7 @@ class WifiSoftApTest(WifiBaseTest):
         self.dut.log.debug("Toggling Airplane mode OFF.")
         asserts.assert_true(utils.force_airplane_mode(self.dut, False),
                             "Can not turn off airplane mode: %s" % self.dut.serial)
+        self.dut.adb.shell("cmd wifi reset-coex-cell-channels")
         if self.dut.droid.wifiIsApEnabled():
             wutils.stop_wifi_tethering(self.dut)
         if "chan_13" in self.test_name and "OpenWrtAP" in self.user_params:
@@ -1343,6 +1344,28 @@ class WifiSoftApTest(WifiBaseTest):
         asserts.assert_true(softap_channel == 13,
                             "Dut client did not connect to softAp on channel 13")
 
+    def test_softap_2G_two_clients_ping_each_other_with_lte_coex(self):
+        """Test for 2G hotspot with 2 clients when lte coex applied
+
+        1. Set country code as TW and set lte coex channels
+        2. Turn on 2G hotspot
+        3. Two clients connect to the hotspot
+        4. Two clients ping each other
+        """
+
+        asserts.skip_if(self.dut.model not in self.sim_supported_models,
+                        "Device does not support SIM card, softAp not applicable.")
+        asserts.skip_if(len(self.android_devices) < 3,
+                        "No extra android devices. Skip test")
+
+        wutils.set_wifi_country_code(self.dut, "TW")
+        self.dut.adb.shell("cmd wifi set-coex-cell-channels "
+                           "lte 7 2650000 20000 2530000 20000 "
+                           "lte 3 1860000 10000 -1 0 "
+                           "lte 8 955000 10000 -1 0 "
+                           "lte 7 2685000 10000 -1 0")
+        self.validate_full_tether_startup(WIFI_CONFIG_APBAND_2G, test_clients=True)
+
     """ Tests End """
 
 
```

