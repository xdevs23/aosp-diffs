```diff
diff --git a/assets/carrier_config_carrierid_1385_TIM.xml b/assets/carrier_config_carrierid_1385_TIM.xml
index cd359b8..0303aca 100644
--- a/assets/carrier_config_carrierid_1385_TIM.xml
+++ b/assets/carrier_config_carrierid_1385_TIM.xml
@@ -6,4 +6,6 @@
         <item value="815641A2394999AA9AD4D499BFBD23CD073024D13A8A8639F834B5166C80B8DB:br.com.timbrasil.meutim"/>
         <item value="5D4369640AD4D8972B75C831DC5C135B700BB1E793CEB7EC89FA6AA0469143CC:br.com.timbrasil.meutim"/>
     </string-array>
+    <boolean name="ims.sip_over_ipsec_enabled_bool" value="false"/>
+    <boolean name="carrier_supports_ss_over_ut_bool" value="true"/>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_1492_O2.xml b/assets/carrier_config_carrierid_1492_O2.xml
index 48b1b3a..9f7ef6a 100644
--- a/assets/carrier_config_carrierid_1492_O2.xml
+++ b/assets/carrier_config_carrierid_1492_O2.xml
@@ -18,4 +18,7 @@
     <int-array name="radio_restart_failure_causes_int_array" num="1">
         <item value="55"/>
     </int-array>
+    <string-array name="carrier_certificate_string_array" num="1">
+      <item value="A5E39BBC6CAC87DAC88DCEA70AA47C61E3D49A09662E97971C787CBE2DFE21C2:uk.co.o2.android.myo2"/>
+    </string-array>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_1839_Verizon-Wireless.xml b/assets/carrier_config_carrierid_1839_Verizon-Wireless.xml
index f426c4b..83ec3c5 100644
--- a/assets/carrier_config_carrierid_1839_Verizon-Wireless.xml
+++ b/assets/carrier_config_carrierid_1839_Verizon-Wireless.xml
@@ -175,6 +175,7 @@
         <item value="77"/>
     </int-array>
     <int name="nr_advanced_bands_secondary_timer_seconds_int" value="300"/>
+    <int name="nr_advanced_pci_change_secondary_timer_seconds_int" value="60"/>
     <string-array name="unmetered_network_types_string_array" num="2">
         <item value="NR_NSA_MMWAVE"/>
         <item value="NR_SA_MMWAVE"/>
diff --git a/assets/carrier_config_carrierid_1890_KT.xml b/assets/carrier_config_carrierid_1890_KT.xml
index 0c48b4a..2134109 100644
--- a/assets/carrier_config_carrierid_1890_KT.xml
+++ b/assets/carrier_config_carrierid_1890_KT.xml
@@ -35,14 +35,13 @@
         <item value="NR_NSA_MMWAVE:563200,614400"/>
         <item value="NR_SA:563200,61440"/>
     </string-array>
-    <string-array name="carrier_certificate_string_array" num="8">
-        <item value="7117EE13C842F1009553C8B70FFF7CF30EC8F04118AE87B6722E2F05193EA09A:com.kt.olleh.servicemenu"/>
+    <string-array name="carrier_certificate_string_array" num="7">
+        <item value="7117EE13C842F1009553C8B70FFF7CF30EC8F04118AE87B6722E2F05193EA09A:com.kt.olleh.servicemenu,com.kt.watchcfmanager,com.kt.gtv"/>
         <item value="30BCC971FC0B69D54E7795B73EA2B11BF526E783850AFD2E73E1EE66DF120630:com.ktshow.cs"/>
         <item value="EE0E64652EC30DE70A3753F4B139B782092608739A9FD213A0A9075F13F97DC5:com.olleh.android.oc2"/>
         <item value="C14BC5BC392DA316E7477D3BB4FB1AC045CDB7FA07874967143633F69373493F:com.kt.ollehfamilybox"/>
         <item value="01B6241AB640C986B4C1AD572231442C5C313404A8955B28BBEBC92F4FF6901A:com.kt.ollehusimmanager"/>
         <item value="5129ABC4317E79EC871024D9CA6912B61FB657EC70D3618493CA424678BB7BFE:com.ktcs.whowho"/>
-        <item value="100deca7ee3f5b66e0cf8acb06d8a3935e99b189fcb393431c4f0c2ff619cad5:com.kt.watchcfmanager"/>
         <item value="4060781A91ED2C66BBEC69744AD87C05749AC5ABF2A5E06B87006AC46A6DD849:com.kt.serviceagent"/>
     </string-array>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_1_T-Mobile-US.xml b/assets/carrier_config_carrierid_1_T-Mobile-US.xml
index 1d28bb7..0f369fb 100644
--- a/assets/carrier_config_carrierid_1_T-Mobile-US.xml
+++ b/assets/carrier_config_carrierid_1_T-Mobile-US.xml
@@ -72,9 +72,16 @@
         <item value="311250"/>
     </string-array>
     <pbundle_as_map name="carrier_supported_satellite_services_per_provider_bundle">
-        <int-array name = "310830" num = "2">
+        <int-array name = "310830" num = "3">
+            <item value = "2"/>
             <item value = "3"/>
             <item value = "6"/>
         </int-array>
     </pbundle_as_map>
+    <boolean name="satellite_ignore_data_roaming_setting_bool" value="true"/>
+    <int-array name="carrier_roaming_satellite_default_services_int_array" num="3">
+        <item value="2"/>
+        <item value="3"/>
+        <item value="6"/>
+    </int-array>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_2006_Madar.xml b/assets/carrier_config_carrierid_2006_Madar.xml
new file mode 100644
index 0000000..ddf2b64
--- /dev/null
+++ b/assets/carrier_config_carrierid_2006_Madar.xml
@@ -0,0 +1,9 @@
+<?xml version="1.0" encoding="utf-8" standalone="yes"?>
+<carrier_config>
+    <boolean name="carrier_volte_available_bool" value="true"/>
+    <boolean name="enhanced_4g_lte_on_by_default_bool" value="true"/>
+    <boolean name="hide_enhanced_4g_lte_bool" value="false"/>
+    <boolean name="carrier_supports_ss_over_ut_bool" value="true"/>
+    <boolean name="carrier_wfc_ims_available_bool" value="true"/>
+    <boolean name="carrier_default_wfc_ims_enabled_bool" value="true"/>
+</carrier_config>
diff --git a/assets/carrier_config_carrierid_2025_TelritePure-Talk.xml b/assets/carrier_config_carrierid_2025_TelritePure-Talk.xml
index 26179db..41505ea 100644
--- a/assets/carrier_config_carrierid_2025_TelritePure-Talk.xml
+++ b/assets/carrier_config_carrierid_2025_TelritePure-Talk.xml
@@ -1,4 +1,28 @@
 <?xml version="1.0" encoding="utf-8" standalone="yes"?>
 <carrier_config>
     <boolean name="inflate_signal_strength_bool" value="true" />
+    <string-array name="mmi_two_digit_number_pattern_string_array" num="22">
+        <item value="0"/>
+        <item value="00"/>
+        <item value="*0"/>
+        <item value="*1"/>
+        <item value="*2"/>
+        <item value="*3"/>
+        <item value="*4"/>
+        <item value="*5"/>
+        <item value="*6"/>
+        <item value="*7"/>
+        <item value="*8"/>
+        <item value="*9"/>
+        <item value="#0"/>
+        <item value="#1"/>
+        <item value="#2"/>
+        <item value="#3"/>
+        <item value="#4"/>
+        <item value="#5"/>
+        <item value="#6"/>
+        <item value="#7"/>
+        <item value="#8"/>
+        <item value="#9"/>
+    </string-array>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_2025_TelritePureTalk.xml b/assets/carrier_config_carrierid_2025_TelritePureTalk.xml
deleted file mode 100644
index 479ec33..0000000
--- a/assets/carrier_config_carrierid_2025_TelritePureTalk.xml
+++ /dev/null
@@ -1,27 +0,0 @@
-<?xml version="1.0" encoding="utf-8" standalone="yes"?>
-<carrier_config>
-    <string-array name="mmi_two_digit_number_pattern_string_array" num="22">
-        <item value="0"/>
-        <item value="00"/>
-        <item value="*0"/>
-        <item value="*1"/>
-        <item value="*2"/>
-        <item value="*3"/>
-        <item value="*4"/>
-        <item value="*5"/>
-        <item value="*6"/>
-        <item value="*7"/>
-        <item value="*8"/>
-        <item value="*9"/>
-        <item value="#0"/>
-        <item value="#1"/>
-        <item value="#2"/>
-        <item value="#3"/>
-        <item value="#4"/>
-        <item value="#5"/>
-        <item value="#6"/>
-        <item value="#7"/>
-        <item value="#8"/>
-        <item value="#9"/>
-    </string-array>
-</carrier_config>
diff --git a/assets/carrier_config_carrierid_2032_Xfinity-Mobile.xml b/assets/carrier_config_carrierid_2032_Xfinity-Mobile.xml
index 2a60976..0600613 100644
--- a/assets/carrier_config_carrierid_2032_Xfinity-Mobile.xml
+++ b/assets/carrier_config_carrierid_2032_Xfinity-Mobile.xml
@@ -157,12 +157,15 @@
         <item value="82"/>
         <item value="83"/>
     </int-array>
-    <string-array name="carrier_certificate_string_array" num="5">
-        <item value="31b4c17315c2269040d535f7b6a79cf4d11517c664d9de8f1ddf4f8a785aad47:com.xfinity.digitalhome"/>
-        <item value="c9133e8168f97573c8c567f46777dff74ade0c015ecf2c5e91be3e4e76ddcae2:com.xfinity.digitalhome.debug"/>
+    <string-array name="carrier_certificate_string_array" num="8">
+        <item value="953f5a4c22e7fd16adc3f12eb038682aad377fef9a18b9d12c1abea78911c749:com.xfinity.digitalhome"/>
+        <item value="06aada946110e64414aebe3af34ae06baf239ef75c947149fb67263d8a2547c3:com.xfinity.digitalhome.debug"/>
         <item value="141E264EB08B576F6C32E49FD47A34300553A132EC5EB1DD58B354A0B15A5E40:com.xfinitymobile.cometcarrierservice"/>
-        <item value="c9133e8168f97573c8c567f46777dff74ade0c015ecf2c5e91be3e4e76ddcae2:com.xfinity.dh.xm"/>
+        <item value="06aada946110e64414aebe3af34ae06baf239ef75c947149fb67263d8a2547c3:com.xfinity.dh.xm.app"/>
         <item value="914C26403B57D2D482359FC235CC825AD00D52B0121C18EF2B2B9D4DDA4B8996:com.comcast.mobile.mxs"/>
+        <item value="953f5a4c22e7fd16adc3f12eb038682aad377fef9a18b9d12c1abea78911c749:com.xfinity.mobile.spamfilter"/>
+        <item value="3557afac6c4a4951b6d669408dc35bf6dfb1b1536eeb465493f9d29ad166c91d:com.xfinity.mobile.spamfilter"/>
+        <item value="3557afac6c4a4951b6d669408dc35bf6dfb1b1536eeb465493f9d29ad166c91d:com.xfinity.digitalhome"/>
     </string-array>
     <int-array name="additional_nr_advanced_bands_int_array" num="2">
         <item value="48"/>
diff --git a/assets/carrier_config_carrierid_2130_ALIV_BS.xml b/assets/carrier_config_carrierid_2130_ALIV_BS.xml
index c839508..8fd276f 100644
--- a/assets/carrier_config_carrierid_2130_ALIV_BS.xml
+++ b/assets/carrier_config_carrierid_2130_ALIV_BS.xml
@@ -1,4 +1,11 @@
 <?xml version="1.0" encoding="utf-8" standalone="yes"?>
 <carrier_config>
     <string name="sim_country_iso_override_string">bs</string>
+    <boolean name="carrier_volte_available_bool" value="true"/>
+    <boolean name="carrier_supports_ss_over_ut_bool" value="true"/>
+    <boolean name="hide_ims_apn_bool" value="true"/>
+    <int name="carrier_ussd_method_int" value="1"/>
+    <int name="imsvoice.conference_subscribe_type_int" value="1"/>
+    <string name="imsvoice.conference_factory_uri_string">conf_uri@ims.mnc049.mcc364.3gppnetwork.org</string>
+    <string name="carrier_name_string">aliv</string>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_2447_IDC.xml b/assets/carrier_config_carrierid_2447_IDC.xml
new file mode 100644
index 0000000..3151b27
--- /dev/null
+++ b/assets/carrier_config_carrierid_2447_IDC.xml
@@ -0,0 +1,8 @@
+<?xml version="1.0" encoding="utf-8" standalone="yes"?>
+<carrier_config>
+    <boolean name="show_4g_for_lte_data_icon_bool" value="true"/>
+    <boolean name="carrier_volte_available_bool" value="true"/>
+    <string-array name="carrier_certificate_string_array" num="1">
+        <item value="D0635100654A8CE8680CF8D5FD098483CC2EFAB3C58A983839C49262F8EAF221:md.idc.my"/>
+    </string-array>
+</carrier_config>
diff --git a/assets/carrier_config_carrierid_2464_mobi.xml b/assets/carrier_config_carrierid_2464_mobi.xml
new file mode 100644
index 0000000..432aba3
--- /dev/null
+++ b/assets/carrier_config_carrierid_2464_mobi.xml
@@ -0,0 +1,10 @@
+<?xml version="1.0" encoding="utf-8" standalone="yes"?>
+<carrier_config>
+    <boolean name="carrier_name_override_bool" value="true"/>
+    <boolean name="carrier_volte_available_bool" value="true"/>
+    <string name="carrier_name_string">mobi</string>
+    <string-array name="carrier_certificate_string_array" num="2">
+        <item value="CA357AC6A590067CB064D081960AFAF88F3157DE8E7D3B77EDE78FFAA1A519B7:com.mobi.stitch,com.mobi.stitch.test"/>
+        <item value="70907933D77B20329475188F12D3AAA2BE20CDA25A1D86DD9DE9CA2FC0A989D3:com.mobi.stitch,com.mobi.stitch.test"/>
+    </string-array>
+</carrier_config>
\ No newline at end of file
diff --git a/assets/carrier_config_carrierid_2532_Xfinity-Mobile.xml b/assets/carrier_config_carrierid_2532_Xfinity-Mobile.xml
index 83d0b06..252ceaf 100644
--- a/assets/carrier_config_carrierid_2532_Xfinity-Mobile.xml
+++ b/assets/carrier_config_carrierid_2532_Xfinity-Mobile.xml
@@ -1,10 +1,13 @@
 <?xml version="1.0" encoding="utf-8" standalone="yes"?>
 <carrier_config>
-    <string-array name="carrier_certificate_string_array" num="5">
-        <item value="31b4c17315c2269040d535f7b6a79cf4d11517c664d9de8f1ddf4f8a785aad47:com.xfinity.digitalhome"/>
-        <item value="c9133e8168f97573c8c567f46777dff74ade0c015ecf2c5e91be3e4e76ddcae2:com.xfinity.digitalhome.debug"/>
+    <string-array name="carrier_certificate_string_array" num="8">
+        <item value="953f5a4c22e7fd16adc3f12eb038682aad377fef9a18b9d12c1abea78911c749:com.xfinity.digitalhome"/>
+        <item value="06aada946110e64414aebe3af34ae06baf239ef75c947149fb67263d8a2547c3:com.xfinity.digitalhome.debug"/>
         <item value="141E264EB08B576F6C32E49FD47A34300553A132EC5EB1DD58B354A0B15A5E40:com.xfinitymobile.cometcarrierservice"/>
-        <item value="c9133e8168f97573c8c567f46777dff74ade0c015ecf2c5e91be3e4e76ddcae2:com.xfinity.dh.xm"/>
+        <item value="06aada946110e64414aebe3af34ae06baf239ef75c947149fb67263d8a2547c3:com.xfinity.dh.xm.app"/>
         <item value="914C26403B57D2D482359FC235CC825AD00D52B0121C18EF2B2B9D4DDA4B8996:com.comcast.mobile.mxs"/>
+        <item value="953f5a4c22e7fd16adc3f12eb038682aad377fef9a18b9d12c1abea78911c749:com.xfinity.mobile.spamfilter"/>
+        <item value="3557afac6c4a4951b6d669408dc35bf6dfb1b1536eeb465493f9d29ad166c91d:com.xfinity.mobile.spamfilter"/>
+        <item value="3557afac6c4a4951b6d669408dc35bf6dfb1b1536eeb465493f9d29ad166c91d:com.xfinity.digitalhome"/>
     </string-array>
 </carrier_config>
\ No newline at end of file
diff --git a/assets/carrier_config_carrierid_2556_Xfinity_Mobile.xml b/assets/carrier_config_carrierid_2556_Xfinity_Mobile.xml
index b689251..8346c59 100644
--- a/assets/carrier_config_carrierid_2556_Xfinity_Mobile.xml
+++ b/assets/carrier_config_carrierid_2556_Xfinity_Mobile.xml
@@ -156,13 +156,16 @@
         <item value="82"/>
         <item value="83"/>
     </int-array>
-    <string-array name="carrier_certificate_string_array" num="5">
-        <item value="31b4c17315c2269040d535f7b6a79cf4d11517c664d9de8f1ddf4f8a785aad47:com.xfinity.digitalhome"/>
-        <item value="c9133e8168f97573c8c567f46777dff74ade0c015ecf2c5e91be3e4e76ddcae2:com.xfinity.digitalhome.debug"/>
+    <string-array name="carrier_certificate_string_array" num="8">
+        <item value="953f5a4c22e7fd16adc3f12eb038682aad377fef9a18b9d12c1abea78911c749:com.xfinity.digitalhome"/>
+        <item value="06aada946110e64414aebe3af34ae06baf239ef75c947149fb67263d8a2547c3:com.xfinity.digitalhome.debug"/>
         <item value="141E264EB08B576F6C32E49FD47A34300553A132EC5EB1DD58B354A0B15A5E40:com.xfinitymobile.cometcarrierservice"/>
-        <item value="c9133e8168f97573c8c567f46777dff74ade0c015ecf2c5e91be3e4e76ddcae2:com.xfinity.dh.xm"/>
+        <item value="06aada946110e64414aebe3af34ae06baf239ef75c947149fb67263d8a2547c3:com.xfinity.dh.xm.app"/>
         <item value="914C26403B57D2D482359FC235CC825AD00D52B0121C18EF2B2B9D4DDA4B8996:com.comcast.mobile.mxs"/>
-    </string-array>
+        <item value="953f5a4c22e7fd16adc3f12eb038682aad377fef9a18b9d12c1abea78911c749:com.xfinity.mobile.spamfilter"/>
+        <item value="3557afac6c4a4951b6d669408dc35bf6dfb1b1536eeb465493f9d29ad166c91d:com.xfinity.mobile.spamfilter"/>
+        <item value="3557afac6c4a4951b6d669408dc35bf6dfb1b1536eeb465493f9d29ad166c91d:com.xfinity.digitalhome"/>
+   </string-array>
     <int-array name="additional_nr_advanced_bands_int_array" num="2">
         <item value="48"/>
         <item value="77"/>
diff --git a/assets/carrier_config_carrierid_2599_NetGenuity.xml b/assets/carrier_config_carrierid_2599_NetGenuity.xml
new file mode 100644
index 0000000..9b95259
--- /dev/null
+++ b/assets/carrier_config_carrierid_2599_NetGenuity.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8" standalone="yes"?>
+<carrier_config>
+    <boolean name="carrier_name_override_bool" value="true"/>
+    <boolean name="carrier_volte_available_bool" value="true"/>
+    <string name="carrier_name_string">NetGenuity</string>
+</carrier_config>
\ No newline at end of file
diff --git a/assets/carrier_config_carrierid_2652_OXIO.xml b/assets/carrier_config_carrierid_2652_OXIO.xml
new file mode 100644
index 0000000..e22b70f
--- /dev/null
+++ b/assets/carrier_config_carrierid_2652_OXIO.xml
@@ -0,0 +1,13 @@
+<?xml version="1.0" encoding="utf-8" standalone="yes"?>
+<carrier_config>
+    <boolean name="allow_hold_call_during_emergency_bool" value="false"/>
+    <boolean name="carrier_supports_ss_over_ut_bool" value="true"/>
+    <boolean name="carrier_volte_available_bool" value="true"/>
+    <boolean name="carrier_name_override_bool" value="false"/>
+    <boolean name="csp_enabled_bool" value="false"/>
+    <boolean name="hide_ims_apn_bool" value="true"/>
+    <boolean name="show_4g_for_lte_data_icon_bool" value="true"/>
+    <boolean name="display_hd_audio_property_bool" value="false"/>
+    <boolean name="allow_hold_in_ims_call" value="true"/>
+    <int name="volte_replacement_rat_int" value="3"/>
+</carrier_config>
\ No newline at end of file
diff --git a/assets/carrier_config_carrierid_34_Movistar.xml b/assets/carrier_config_carrierid_34_Movistar.xml
index ca9cdfb..29211a7 100644
--- a/assets/carrier_config_carrierid_34_Movistar.xml
+++ b/assets/carrier_config_carrierid_34_Movistar.xml
@@ -46,4 +46,7 @@
     <item value="017"/>
   </string-array>
   <boolean name="carrier_allow_transfer_ims_call_bool" value="true"/>
+  <string-array name="carrier_certificate_string_array" num="1">
+    <item value="25373D2A75B1689F4FAD3400C5814C13B4218CDC34D35B8509FB06671E3D36A3:com.movistar.android.mimovistar.es"/>
+  </string-array>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_492_Pivotel.xml b/assets/carrier_config_carrierid_492_Pivotel.xml
new file mode 100644
index 0000000..69c46c0
--- /dev/null
+++ b/assets/carrier_config_carrierid_492_Pivotel.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="utf-8" standalone="yes"?>
+<carrier_config>
+    <boolean name="show_4g_for_lte_data_icon_bool" value="true"/>
+    <boolean name="carrier_volte_available_bool" value="true"/>
+    <boolean name="carrier_supports_ss_over_ut_bool" value="true"/>
+    <boolean name="hide_lte_plus_data_icon_bool" value="false"/>
+</carrier_config>
diff --git a/assets/carrier_config_carrierid_718_EE.xml b/assets/carrier_config_carrierid_718_EE.xml
index ed7105d..35276b9 100644
--- a/assets/carrier_config_carrierid_718_EE.xml
+++ b/assets/carrier_config_carrierid_718_EE.xml
@@ -1,11 +1,9 @@
 <?xml version="1.0" encoding="utf-8" standalone="yes"?>
 <carrier_config>
-    <boolean name="carrier_name_override_bool" value="true"/>
     <boolean name="display_voicemail_number_as_default_call_forwarding_number" value="true"/>
     <boolean name="prefer_2g_bool" value="false"/>
     <boolean name="show_4g_for_lte_data_icon_bool" value="true"/>
     <int name="wfc_spn_format_idx_int" value="1"/>
-    <string name="carrier_name_string">EE</string>
     <string-array name="non_roaming_operator_string_array" num="6">
         <item value="23430"/>
         <item value="23431"/>
diff --git a/tests/src/com/android/carrierconfig/CarrierConfigTest.java b/tests/src/com/android/carrierconfig/CarrierConfigTest.java
index 4d753a1..3ee0273 100644
--- a/tests/src/com/android/carrierconfig/CarrierConfigTest.java
+++ b/tests/src/com/android/carrierconfig/CarrierConfigTest.java
@@ -34,9 +34,11 @@ import java.io.IOException;
 import java.io.InputStream;
 import java.lang.reflect.Field;
 import java.lang.reflect.Modifier;
+import java.util.ArrayDeque;
 import java.util.ArrayList;
 import java.util.HashSet;
 import java.util.List;
+import java.util.Optional;
 import java.util.Set;
 
 import junit.framework.AssertionFailedError;
@@ -173,44 +175,63 @@ public class CarrierConfigTest extends InstrumentationTestCase {
      */
     public void testVariableNames() {
         final Set<String> varXmlNames = getCarrierConfigXmlNames();
+        ArrayDeque<String> pathStack = new ArrayDeque<String>();
         // organize them into sets by type or unknown
         forEachConfigXml(new ParserChecker() {
             public void check(XmlPullParser parser, String mccmnc) throws XmlPullParserException,
                     IOException {
                 int event;
                 while (((event = parser.next()) != XmlPullParser.END_DOCUMENT)) {
-                    if (event == XmlPullParser.START_TAG) {
-                        switch (parser.getName()) {
-                            case "int-array":
-                            case "string-array":
-                                // string-array and int-array require the 'num' attribute
-                                final String varNum = parser.getAttributeValue(null, "num");
-                                assertNotNull("No 'num' attribute in array: "
-                                        + parser.getPositionDescription(), varNum);
-                            case "int":
-                            case "long":
-                            case "boolean":
-                            case "string":
-                                // NOTE: This doesn't check for other valid Bundle values, but it
-                                // is limited to the key types in CarrierConfigManager.
-                                final String varName = parser.getAttributeValue(null, "name");
-                                assertNotNull("No 'name' attribute: "
-                                        + parser.getPositionDescription(), varName);
-                                assertTrue("Unknown variable: '" + varName
-                                        + "' at " + parser.getPositionDescription(),
-                                        varXmlNames.contains(varName));
-                                // TODO: Check that the type is correct.
-                                break;
-                            case "carrier_config_list":
-                            case "item":
-                            case "carrier_config":
-                                // do nothing
-                                break;
-                            default:
-                                fail("unexpected tag: '" + parser.getName()
-                                        + "' at " + parser.getPositionDescription());
-                                break;
-                        }
+                    switch (event) {
+                        case XmlPullParser.START_TAG:
+                            String elementName = parser.getName();
+                            String pathString = String.join(
+                                "/",
+                                Optional.ofNullable(pathStack.peek()).orElse(""),
+                                elementName);
+                            pathStack.push(pathString);
+
+                            switch (elementName) {
+                                case "int-array":
+                                case "string-array":
+                                    // string-array and int-array require the 'num' attribute
+                                    final String varNum = parser.getAttributeValue(null, "num");
+                                    assertNotNull("No 'num' attribute in array: "
+                                            + parser.getPositionDescription(), varNum);
+                                case "int":
+                                case "long":
+                                case "boolean":
+                                case "pbundle_as_map":
+                                case "string":
+                                    // NOTE: This doesn't check for other valid Bundle values, but
+                                    // it is limited to the key types in CarrierConfigManager.
+                                    final String varName = parser.getAttributeValue(null, "name");
+                                    assertNotNull("No 'name' attribute: "
+                                            + parser.getPositionDescription(), varName);
+                                    if (!pathString.equals(
+                                          "/carrier_config/pbundle_as_map/int-array")) {
+                                        assertTrue("Unknown variable: '" + varName
+                                            + "' at " + parser.getPositionDescription(),
+                                            varXmlNames.contains(varName));
+                                    }
+                                    // TODO: Check that the type is correct.
+                                    break;
+                                case "carrier_config_list":
+                                case "item":
+                                case "carrier_config":
+                                    // do nothing
+                                    break;
+                                default:
+                                    fail("unexpected tag: '" + parser.getName()
+                                            + "' at " + parser.getPositionDescription());
+                                    break;
+                            }
+                        break;
+                    case XmlPullParser.END_TAG:
+                        pathStack.pop();
+                        break;
+                    default:
+                        break;
                     }
                 }
             }
```

