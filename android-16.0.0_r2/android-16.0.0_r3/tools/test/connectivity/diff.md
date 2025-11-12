```diff
diff --git a/acts_tests/tests/google/wifi/WifiManagerTest.py b/acts_tests/tests/google/wifi/WifiManagerTest.py
index 33f7436a2..e243385b5 100644
--- a/acts_tests/tests/google/wifi/WifiManagerTest.py
+++ b/acts_tests/tests/google/wifi/WifiManagerTest.py
@@ -85,7 +85,7 @@ class WifiManagerTest(WifiBaseTest):
             self.openwrt = self.access_points[0]
             self.configure_openwrt_ap_and_start(open_network=True,
                                                 wpa_network=True,
-                                                wep_network=self.openwrt.is_version_under_20())
+                                                wep_network=True)
 
         asserts.assert_true(
             len(self.reference_networks) > 0,
@@ -1024,10 +1024,6 @@ class WifiManagerTest(WifiBaseTest):
         1. Ensure the 2GHz WEP network is visible in scan result.
         2. Connect to the network and validate internet connection.
         """
-        asserts.skip_if(
-            hasattr(self, "openwrt") and not self.access_points[0].is_version_under_20(),
-            "OpenWrt no longer support wep network."
-        )
         wutils.connect_to_wifi_network(self.dut, self.wep_networks[0]["2g"])
 
     @test_tracker_info(uuid="1f2d17a2-e92d-43af-966b-3421c0db8620")
@@ -1038,10 +1034,6 @@ class WifiManagerTest(WifiBaseTest):
         1. Ensure the 5GHz WEP network is visible in scan result.
         2. Connect to the network and validate internet connection.
         """
-        asserts.skip_if(
-            hasattr(self, "openwrt") and not self.access_points[0].is_version_under_20(),
-            "OpenWrt no longer support wep network."
-        )
         wutils.connect_to_wifi_network(self.dut, self.wep_networks[0]["5g"])
 
     @test_tracker_info(uuid="4a957952-289d-4657-9882-e1475274a7ff")
diff --git a/acts_tests/tests/google/wifi/WifiNetworkRequestTest.py b/acts_tests/tests/google/wifi/WifiNetworkRequestTest.py
index 6bbeb5e62..a9d1d066d 100644
--- a/acts_tests/tests/google/wifi/WifiNetworkRequestTest.py
+++ b/acts_tests/tests/google/wifi/WifiNetworkRequestTest.py
@@ -64,7 +64,7 @@ class WifiNetworkRequestTest(WifiBaseTest):
             self.openwrt = self.access_points[0]
             self.configure_openwrt_ap_and_start(open_network=True,
                                                 wpa_network=True,
-                                                wep_network=self.openwrt.is_version_under_20())
+                                                wep_network=True)
 
         asserts.assert_true(
             len(self.reference_networks) > 0,
diff --git a/acts_tests/tests/google/wifi/WifiSoftApAcsTest.py b/acts_tests/tests/google/wifi/WifiSoftApAcsTest.py
index fb8add899..a91717c77 100644
--- a/acts_tests/tests/google/wifi/WifiSoftApAcsTest.py
+++ b/acts_tests/tests/google/wifi/WifiSoftApAcsTest.py
@@ -205,7 +205,7 @@ class WifiSoftApAcsTest(WifiBaseTest):
         elif "OpenWrtAP" in self.user_params:
             self.openwrt = self.access_points[0]
             self.configure_openwrt_ap_and_start(wpa_network=True,
-                                                wep_network=self.openwrt.is_version_under_20(),
+                                                wep_network=True,
                                                 channel_2g=channel_2g,
                                                 channel_5g=channel_5g)
 
```

