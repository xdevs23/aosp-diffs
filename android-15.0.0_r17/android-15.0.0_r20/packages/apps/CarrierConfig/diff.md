```diff
diff --git a/assets/carrier_config_carrierid_1520_Claro-GT.xml b/assets/carrier_config_carrierid_1520_Claro-GT.xml
index ebbcbe9..21a90ad 100644
--- a/assets/carrier_config_carrierid_1520_Claro-GT.xml
+++ b/assets/carrier_config_carrierid_1520_Claro-GT.xml
@@ -5,10 +5,9 @@
         <item value="*5"/>
         <item value="*9"/>
     </string-array>
-    <string-array name="carrier_certificate_string_array" num="4">
-      <item value="7D7226772D4F6D778FEF53A36BE15AD78D8D9D4BC4CE00C5F2E3216C19480FA0"/>
+    <string-array name="carrier_certificate_string_array" num="3">
       <item value="2333f4065b9f054363ca63d1866cc168f45d641645b31131b14e173b9c922d15:co.sitic.pp"/>
       <item value="14d54c64599a3e9a3b766239b160de3935093e0a:co.sitic.pp"/>
       <item value="f54cac11d5af77a5f10c21d536ad5d1c40b00d63a92cab917aa84dc714d622d8:co.sitic.pp"/>
     </string-array>
-</carrier_config>
+</carrier_config>
\ No newline at end of file
diff --git a/assets/carrier_config_carrierid_1839_Verizon-Wireless.xml b/assets/carrier_config_carrierid_1839_Verizon-Wireless.xml
index f64431f..f426c4b 100644
--- a/assets/carrier_config_carrierid_1839_Verizon-Wireless.xml
+++ b/assets/carrier_config_carrierid_1839_Verizon-Wireless.xml
@@ -189,4 +189,31 @@
     <string-array name="boosted_nrarfcns_string_array" num="1">
         <item value="200000-866666"/>
     </string-array>
+    <boolean name="nr_timers_reset_on_voice_qos_bool" value="true" />
+    <pbundle_as_map name="regional_satellite_earfcn_bundle">
+        <int-array name="0" num="2">
+            <item value="229011"/>
+            <item value="229015"/>
+        </int-array>
+    </pbundle_as_map>
+    <boolean name="satellite_attach_supported_bool" value="false" />
+    <boolean name="satellite_esos_supported_bool" value="true" />
+    <string name="satellite_nidd_apn_name_string">VZWNTN.LBO</string>
+    <boolean name="satellite_roaming_p2p_sms_supported_bool" value="true" />
+    <string name="satellite_display_name_string">Satellite</string>
+    <boolean name="satellite_entitlement_supported_bool" value="true" />
+    <boolean name="override_wfc_roaming_mode_while_using_ntn_bool" value="true" />
+    <boolean name="emergency_messaging_supported_bool" value="true" />
+    <boolean name="remove_satellite_plmn_in_manual_network_scan_bool" value="true" />
+    <int name="carrier_roaming_ntn_connect_type_int" value="1"/>
+    <int name="satellite_connection_hysteresis_sec_int" value="0"/>
+    <int name="satellite_entitlement_status_refresh_days_int" value="7"/>
+    <int name="carrier_roaming_ntn_emergency_call_to_satellite_handover_type_int" value="1"/>
+    <pbundle_as_map name="carrier_supported_satellite_services_per_provider_bundle">
+        <int-array name="90198" num="1">
+            <item value="3"/>
+        </int-array>
+    </pbundle_as_map>
+    <string name="satellite_information_redirect_url_string">https://www.verizon.com/wireless-devices/smartphones/messages-via-satellite/</string>
+
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_1958_Free.xml b/assets/carrier_config_carrierid_1958_Free.xml
index c1d3ab9..2520c30 100644
--- a/assets/carrier_config_carrierid_1958_Free.xml
+++ b/assets/carrier_config_carrierid_1958_Free.xml
@@ -8,8 +8,8 @@
         <item value="20801"/>
     </string-array>
     <string-array name="carrier_certificate_string_array" num="3">
-      <item value="d543e9f245aa584a84c608069cffe1f507be61eb496d7585ac02a2fce05dcb28:fr.freemobile.android.mobileconf,fr.freemobile.android.freenetworkmonitor,fr.free.moncomptefree"/>
-      <item value="a1fe35ab00f6301fdafda1309b8faac2895bf5d46ef5d9ae6895c5a5ad84eeb7:fr.freemobile.android.mobileconf,fr.freemobile.android.freenetworkmonitor,fr.free.moncomptefree"/>
-      <item value="176461745f20b294b43960e9357bd6daffc87def7ddd75b9596e74076e5b19b0:fr.freemobile.android.mobileconf,fr.freemobile.android.freenetworkmonitor,fr.free.moncomptefree"/>
+      <item value="d543e9f245aa584a84c608069cffe1f507be61eb496d7585ac02a2fce05dcb28:fr.freemobile.android.mobileconf,fr.freemobile.android.freenetworkmonitor,fr.free.moncomptefree,fr.freemobile.android.mobilestest"/>
+      <item value="a1fe35ab00f6301fdafda1309b8faac2895bf5d46ef5d9ae6895c5a5ad84eeb7:fr.freemobile.android.mobileconf,fr.freemobile.android.freenetworkmonitor,fr.free.moncomptefree,fr.freemobile.android.mobilestest"/>
+      <item value="176461745f20b294b43960e9357bd6daffc87def7ddd75b9596e74076e5b19b0:fr.freemobile.android.mobileconf,fr.freemobile.android.freenetworkmonitor,fr.free.moncomptefree,fr.freemobile.android.mobilestest"/>
     </string-array>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_1989_Google-Fi.xml b/assets/carrier_config_carrierid_1989_Google-Fi.xml
index 86b0d4c..7bcae26 100644
--- a/assets/carrier_config_carrierid_1989_Google-Fi.xml
+++ b/assets/carrier_config_carrierid_1989_Google-Fi.xml
@@ -5,4 +5,7 @@
     <boolean name="force_home_network_bool" value="true"/>
     <string name="carrier_name_string">Google Fi</string>
     <string name="sim_country_iso_override_string">us</string>
-</carrier_config>
\ No newline at end of file
+    <string-array name="carrier_certificate_string_array" num="1">
+        <item value="4C36AF4A5BDAD97C1F3D8B283416D244496C2AC5EAFE8226079EF6F676FD1859:com.google.android.apps.tycho"/>
+    </string-array>
+</carrier_config>
diff --git a/assets/carrier_config_carrierid_1_T-Mobile-US.xml b/assets/carrier_config_carrierid_1_T-Mobile-US.xml
index f871ffa..1d28bb7 100644
--- a/assets/carrier_config_carrierid_1_T-Mobile-US.xml
+++ b/assets/carrier_config_carrierid_1_T-Mobile-US.xml
@@ -71,4 +71,10 @@
         <item value="311170"/>
         <item value="311250"/>
     </string-array>
+    <pbundle_as_map name="carrier_supported_satellite_services_per_provider_bundle">
+        <int-array name = "310830" num = "2">
+            <item value = "3"/>
+            <item value = "6"/>
+        </int-array>
+    </pbundle_as_map>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_2124_Iliad.xml b/assets/carrier_config_carrierid_2124_Iliad.xml
index 7afd863..3c3fec3 100644
--- a/assets/carrier_config_carrierid_2124_Iliad.xml
+++ b/assets/carrier_config_carrierid_2124_Iliad.xml
@@ -2,6 +2,6 @@
 <carrier_config>
     <string name="sim_country_iso_override_string">it</string>
     <string-array name="carrier_certificate_string_array" num="1">
-        <item value="8227db5476f1d42a17bead90b73c8624b262152edad34ebd8f7e6472a47c6e03:fr.freemobile.android.mobileconf,fr.freemobile.android.freenetworkmonitor,it.iliad.android.mobileconf,it.iliad.android.iccid"/>
+        <item value="8227db5476f1d42a17bead90b73c8624b262152edad34ebd8f7e6472a47c6e03:fr.freemobile.android.mobileconf,fr.freemobile.android.freenetworkmonitor,it.iliad.android.mobileconf,it.iliad.android.iccid,fr.freemobile.android.mobilestest,it.iliad,it.iliad.business,it.iliad.test"/>
     </string-array>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_2127_free_re.xml b/assets/carrier_config_carrierid_2127_free_re.xml
index 8021a44..6f1b3d2 100644
--- a/assets/carrier_config_carrierid_2127_free_re.xml
+++ b/assets/carrier_config_carrierid_2127_free_re.xml
@@ -2,6 +2,6 @@
 <carrier_config>
     <string name="sim_country_iso_override_string">re</string>
     <string-array name="carrier_certificate_string_array" num="1">
-        <item value="d543e9f245aa584a84c608069cffe1f507be61eb496d7585ac02a2fce05dcb28:fr.freemobile.android.mobileconf,fr.freemobile.android.freenetworkmonitor,it.iliad.android.mobileconf,it.iliad.android.iccid"/>
+        <item value="d543e9f245aa584a84c608069cffe1f507be61eb496d7585ac02a2fce05dcb28:fr.freemobile.android.mobileconf,fr.freemobile.android.freenetworkmonitor,fr.freemobile.android.mobilestest,re.free.moncomptefree"/>
     </string-array>
 </carrier_config>
diff --git a/assets/carrier_config_carrierid_2646_Rcell.xml b/assets/carrier_config_carrierid_2646_Rcell.xml
new file mode 100644
index 0000000..ee6f2fe
--- /dev/null
+++ b/assets/carrier_config_carrierid_2646_Rcell.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="utf-8" standalone="yes"?>
+<carrier_config>
+    <boolean name="show_ims_registration_status_bool" value="true" />
+    <boolean name="carrier_volte_available_bool" value="true"/>
+    <boolean name="carrier_supports_ss_over_ut_bool" value="true"/>
+    <boolean name="carrier_volte_provisioned_bool" value="true"/>
+</carrier_config>
\ No newline at end of file
diff --git a/assets/satellite/skylo_us_sats2.dat b/assets/satellite/skylo_us_sats2.dat
new file mode 100644
index 0000000..71bc1c6
Binary files /dev/null and b/assets/satellite/skylo_us_sats2.dat differ
```

