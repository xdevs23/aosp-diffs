```diff
diff --git a/Android.bp b/Android.bp
index f0da5bb..e733839 100644
--- a/Android.bp
+++ b/Android.bp
@@ -14,16 +14,5 @@
 // limitations under the License.
 
 package {
-    default_applicable_licenses: ["device_sample_license"],
-}
-
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
-license {
-    name: "device_sample_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-Apache-2.0",
-    ],
-    // large-scale-change unable to identify any license_text files
+    default_applicable_licenses: ["Android-Apache-2.0"],
 }
diff --git a/METADATA b/METADATA
deleted file mode 100644
index d97975c..0000000
--- a/METADATA
+++ /dev/null
@@ -1,3 +0,0 @@
-third_party {
-  license_type: NOTICE
-}
diff --git a/apps/tv/OWNERS b/apps/tv/OWNERS
index 26063a3..482adcd 100644
--- a/apps/tv/OWNERS
+++ b/apps/tv/OWNERS
@@ -1,7 +1,6 @@
 dake@google.com
-leifhendrik@google.com
 rausanka@google.com
 rgl@google.com
 shaopengjia@google.com
 tolstykh@google.com
-virgild@google.com
\ No newline at end of file
+virgild@google.com
diff --git a/etc/Android.bp b/etc/Android.bp
index 62c04ed..85126d7 100644
--- a/etc/Android.bp
+++ b/etc/Android.bp
@@ -1,3 +1,23 @@
+//
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
 prebuilt_etc {
     name: "apns-full-conf.xml",
     src: "apns-full-conf.xml",
diff --git a/etc/apns-full-conf.xml b/etc/apns-full-conf.xml
index fa05a6e..59607f2 100644
--- a/etc/apns-full-conf.xml
+++ b/etc/apns-full-conf.xml
@@ -2471,7 +2471,7 @@
       type="dun"
       mvno_type="spn"
       mvno_match_data="Orange"
-      user_visible="false"
+      user_editable="false"
   />
 
   <apn carrier="Orange IMS"
@@ -3083,6 +3083,28 @@
       mvno_match_data="Lebara"
   />
 
+  <apn carrier="PTV Telecom V"
+      mcc="214"
+      mnc="06"
+      apn="datos"
+      type="default,supl,dun"
+      protocol="IPV4V6"
+      mvno_type="spn"
+      mvno_match_data="PTV"
+  />
+
+  <apn carrier="PTV IMS V"
+      mcc="214"
+      mnc="06"
+      apn="ims"
+      type="ims"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+      user_visible="false"
+      mvno_type="spn"
+      mvno_match_data="PTV"
+  />
+
   <apn carrier="Movistar"
       carrier_id = "34"
       mcc="214"
@@ -3129,6 +3151,24 @@
       type="default,ia,supl"
   />
 
+  <apn carrier="PTV Telecom"
+      mcc="214"
+      mnc="15"
+      apn="datos"
+      protocol="IPV4V6"
+      type="default,supl,dun"
+  />
+
+  <apn carrier="PTV IMS"
+      mcc="214"
+      mnc="15"
+      apn="ims"
+      type="ims"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+      user_visible="false"
+  />
+
   <apn carrier="TeleCable Internet"
       mcc="214"
       mnc="16"
@@ -4376,6 +4416,14 @@
       type="mms"
   />
 
+  <apn carrier="Orange LTE"
+      carrier_id = "1011"
+      mcc="226"
+      mnc="10"
+      apn=""
+      type="ia"
+  />
+
   <apn carrier="Orange MMS"
       carrier_id = "1011"
       mcc="226"
@@ -4396,7 +4444,7 @@
       mcc="226"
       mnc="10"
       apn="net"
-      type="default,ia"
+      type="default"
   />
 
   <apn carrier="Orange IMS"
@@ -4430,17 +4478,6 @@
       type="default,ia,supl"
   />
 
-  <apn carrier="Sunrise MMS"
-      carrier_id = "1413"
-      mcc="228"
-      mnc="02"
-      apn="mms.sunrise.ch"
-      mmsc="http://mmsc.sunrise.ch"
-      mmsproxy="212.35.34.75"
-      mmsport="8080"
-      type="mms"
-  />
-
   <apn carrier="Sunrise IMS"
       carrier_id = "1413"
       mcc="228"
@@ -4470,18 +4507,8 @@
       apn="internet"
       authtype="1"
       type="default,ia,supl"
-  />
-
-  <apn carrier="Salt MMS"
-      carrier_id = "1414"
-      mcc="228"
-      mnc="03"
-      apn="mms"
-      mmsc="http://192.168.151.3:8002"
-      mmsproxy="192.168.151.2"
-      mmsport="8080"
-      authtype="1"
-      type="mms"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
   />
 
   <apn carrier="Salt IMS"
@@ -4501,6 +4528,8 @@
       mnc="03"
       apn="hos"
       type="xcap"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       user_visible="false"
   />
 
@@ -4537,18 +4566,6 @@
       mvno_match_data="75636831"
   />
 
-  <apn carrier="upcmms"
-      mcc="228"
-      mnc="53"
-      apn="mms.ch.upcmobile.com"
-      mmsc="http://mms.ch.upcmobile.com:8080/servlets/mms"
-      mmsproxy="62.179.127.18"
-      mmsport="8080"
-      type="mms"
-      mvno_type="gid"
-      mvno_match_data="75636831"
-  />
-
   <apn carrier="Lycamobile"
       mcc="228"
       mnc="54"
@@ -4670,7 +4687,8 @@
       mnc="03"
       apn="internet"
       type="default,ia,supl,xcap"
-      user_editable="false"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
   />
 
   <apn carrier="MMS"
@@ -4685,6 +4703,8 @@
       mmsport="80"
       authtype="1"
       type="mms"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       user_editable="false"
   />
 
@@ -5468,12 +5488,10 @@
       user_visible="false"
   />
 
-  <apn carrier="Talkmob PAYG WAP"
+  <apn carrier="Talkmobile Data"
       mcc="234"
       mnc="15"
-      apn="payg.talkmobile.co.uk"
-      proxy="212.183.137.12"
-      port="8799"
+      apn="talkmobile.co.uk"
       user="wap"
       password="wap"
       mmsc="http://mms.talkmobile.co.uk/servlets/mms"
@@ -5481,41 +5499,45 @@
       mmsport="8799"
       authtype="1"
       type="default,ia,supl,mms"
-      mvno_match_data="C1"
+      protocol="IPV4V6"
       mvno_type="gid"
+      mvno_match_data="C1"
+      user_editable="false"
   />
 
-  <apn carrier="Talkmob WAP"
+  <apn carrier="ASDA Mobile Data"
       mcc="234"
       mnc="15"
-      apn="talkmobile.co.uk"
-      proxy="212.183.137.12"
-      port="8799"
+      apn="MY.INTERNET"
       user="wap"
       password="wap"
-      mmsc="http://mms.talkmobile.co.uk/servlets/mms"
+      mmsc="http://mms.ad.vodafone.co.uk/servlets/mms"
       mmsproxy="212.183.137.12"
       mmsport="8799"
       authtype="1"
       type="default,ia,supl,mms"
-      mvno_match_data="C1"
+      protocol="IPV4V6"
       mvno_type="gid"
+      mvno_match_data="A1"
+      user_editable="false"
   />
 
-  <apn carrier="Lebara Internet"
+  <apn carrier="Lebara Data"
       carrier_id = "2309"
       mcc="234"
       mnc="15"
-      apn="uk.lebara.mobi"
+      apn="UK.LEBARA.MOBI"
       authtype="1"
       user="wap"
       password="wap"
       mmsc="http://mms.lebara.co.uk/servlets/mms"
       mmsproxy="212.183.137.12"
       mmsport="8799"
-      mvno_type="spn"
-      mvno_match_data="Lebara"
       type="default,ia,supl,mms"
+      protocol="IPV4V6"
+      mvno_type="gid"
+      mvno_match_data="90"
+      user_editable="false"
   />
 
   <apn carrier="3"
@@ -6253,6 +6275,8 @@
       apn="mobile.sky"
       authtype="0"
       type="default,ia,supl"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
   />
 
   <apn carrier="MMS"
@@ -6263,6 +6287,8 @@
       mmsproxy="185.110.178.97"
       mmsport="9028"
       type="mms"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       network_type_bitmask="1|2|3|4|5|6|7|8|9|10|12|13|14|15|17|20"
   />
 
@@ -6271,6 +6297,8 @@
       mnc="57"
       apn="IMS"
       type="ims"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       user_visible="false"
   />
 
@@ -6279,6 +6307,8 @@
       mnc="57"
       apn="ut.mobile.sky"
       type="xcap"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       user_visible="false"
   />
 
@@ -6291,6 +6321,8 @@
       mmsproxy="185.110.178.97"
       mmsport="9028"
       network_type_bitmask="18"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       user_visible="false"
   />
 
@@ -6979,6 +7011,8 @@
       type="ims"
       mvno_type="gid"
       mvno_match_data="0C"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       user_visible="false"
   />
 
@@ -6993,6 +7027,8 @@
       network_type_bitmask="1|2|3|4|5|6|7|8|9|10|12|13|14|15|17|20"
       mvno_match_data="0C"
       mvno_type="gid"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
   />
 
   <apn carrier="Sky MMS VoWiFi"
@@ -7006,6 +7042,8 @@
       network_type_bitmask="18"
       mvno_type="gid"
       mvno_match_data="0C"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       user_visible="false"
   />
 
@@ -7016,6 +7054,8 @@
       type="default,ia,supl"
       mvno_match_data="0C"
       mvno_type="gid"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
   />
 
   <apn carrier="Sky Ut"
@@ -7025,6 +7065,8 @@
       type="xcap"
       mvno_type="gid"
       mvno_match_data="0C"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       user_visible="false"
   />
 
@@ -7316,6 +7358,23 @@
       type="default,ia,supl"
   />
 
+  <apn carrier="IXT"
+      mcc="242"
+      mnc="13"
+      apn="ixt"
+      type="default,ia"
+      protocol="IPV4V6"
+  />
+
+  <apn carrier="IXT IMS"
+      mcc="242"
+      mnc="13"
+      apn="ixtims"
+      type="ims"
+      protocol="IPV4V6"
+      user_visible="false"
+  />
+
   <apn carrier="ice.net"
       mcc="242"
       mnc="14"
@@ -8562,6 +8621,27 @@
       type="mms"
   />
 
+  <apn carrier="IDC Internet"
+      carrier_id = "2447"
+      mcc="259"
+      mnc="15"
+      apn="internet"
+      type="default"
+      protocol="IPV4V6"
+      roaming_protocol="IP"
+/>
+
+  <apn carrier="IDC IMS"
+      carrier_id = "2447"
+      mcc="259"
+      mnc="15"
+      apn="ims"
+      type="ims"
+      protocol="IPV4V6"
+      roaming_protocol="IP"
+      user_visible="false"
+  />
+
   <apn carrier="Plus Internet"
       carrier_id = "1658"
       mcc="260"
@@ -9880,6 +9960,8 @@
       mnc="03"
       apn="data.myeirmobile.ie"
       type="default,ia,supl"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
   />
 
   <apn carrier="eir MMS"
@@ -10835,6 +10917,8 @@
       mnc="220"
       apn="ims"
       type="ims"
+      mvno_type="gid"
+      mvno_match_data="4D4F"
       protocol="IPV6"
       roaming_protocol="IPV4V6"
   />
@@ -11240,6 +11324,18 @@
       protocol="IPV4V6"
   />
 
+  <apn carrier="Lüm Mobile"
+      carrier_id = "2638"
+      mcc="302"
+      mnc="780"
+      apn="lum"
+      type="default,ia,mms,supl"
+      mmsc="http://mms.lum.ca/"
+      protocol="IPV4V6"
+      mvno_type="imsi"
+      mvno_match_data="3027805"
+  />
+
   <apn carrier="Verizon CDMA HRPD"
       mcc="310"
       mnc="000"
@@ -18193,62 +18289,32 @@
       protocol="IPV4V6"
   />
 
-  <apn carrier="GigSky"
-      carrier_id="2459"
+  <apn carrier="NetGenuity IMS"
+      carrier_id="2599"
       mcc="312"
-      mnc="870"
-      apn="gigsky"
-      type="default,ia"
-  />
-
-  <apn carrier="mobi LTE"
-      carrier_id = "2464"
-      mcc="313"
-      mnc="460"
-      apn="4g.mobi.net"
-      type="default,supl,ia,dun"
-      protocol="IPV4V6"
-      roaming_protocol="IPV4V6"
-  />
-
-  <apn carrier="mobi MMS"
-      carrier_id = "2464"
-      mcc="313"
-      mnc="460"
-      apn="mms.mobi.net"
-      mmsc="http://mms.mobi.net"
-      type="mms"
-  />
-
-  <apn carrier="mobi IMS"
-      carrier_id = "2464"
-      mcc="313"
-      mnc="460"
+      mnc="630"
       apn="ims"
       type="ims"
       protocol="IPV4V6"
       roaming_protocol="IPV4V6"
-      network_type_bitmask="13|18|20"
   />
 
-  <apn carrier="mobi XCAP"
-      carrier_id = "2464"
-      mcc="313"
-      mnc="460"
-      apn="hos"
-      type="xcap"
+  <apn carrier="NetGenuity Internet"
+      carrier_id = "2599"
+      mcc="312"
+      mnc="630"
+      apn="data"
+      type="default,ia,supl"
       protocol="IPV4V6"
-      network_type_bitmask="13|18|20"
+      roaming_protocol="IPV4V6"
   />
 
-  <apn carrier="mobi OTA"
-      carrier_id = "2464"
-      mcc="313"
-      mnc="460"
-      apn="ota.mobi.net"
-      type="fota"
-      protocol="IPV4V6"
-      roaming_protocol="IPV4V6"
+  <apn carrier="GigSky"
+      carrier_id="2459"
+      mcc="312"
+      mnc="870"
+      apn="gigsky"
+      type="default,ia"
   />
 
   <apn carrier="MobileUC IMS"
@@ -18283,6 +18349,27 @@
       user_editable="false"
   />
 
+  <apn carrier="Internet USA"
+      carrier_id = "2652"
+      mcc="314"
+      mnc="720"
+      apn="internet"
+      type="default,ia,supl,hipri,fota,dun,xcap"
+      mtu="1430"
+      protocol="IPV4V6"
+  />
+
+  <apn carrier="IMS USA"
+      carrier_id = "2652"
+      mcc="314"
+      mnc="720"
+      apn="ims"
+      type="ims"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+      user_visible="false"
+  />
+
   <apn carrier="openmobile"
       mcc="330"
       mnc="000"
@@ -19254,6 +19341,53 @@
       mvno_match_data="IENTC"
   />
 
+  <apn carrier="Izzi"
+      carrier_id="2488"
+      mcc="334"
+      mnc="160"
+      apn="mvne.izzi.mx"
+      type="default,ia,supl,xcap,dun"
+      user=""
+      password=""
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+      mvno_type="spn"
+      mvno_match_data="izzi"
+  />
+
+  <apn carrier="Izzi"
+      carrier_id="2488"
+      mcc="334"
+      mnc="160"
+      apn="ims"
+      type="ims"
+      user=""
+      password=""
+      mvno_type="spn"
+      mvno_match_data="izzi"
+  />
+
+  <apn carrier="Internet Mexico"
+      carrier_id = "2652"
+      mcc="334"
+      mnc="170"
+      apn="internet"
+      type="default,ia,supl,hipri,fota,dun,xcap"
+      mtu="1430"
+      protocol="IPV4V6"
+  />
+
+  <apn carrier="IMS Mexico"
+      carrier_id = "2652"
+      mcc="334"
+      mnc="170"
+      apn="ims"
+      type="ims"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+      user_visible="false"
+  />
+
   <apn carrier="INTERNET Digicel"
       carrier_id = "1577"
       mcc="338"
@@ -35714,6 +35848,26 @@
       type="default,ia,supl"
   />
 
+  <apn carrier="almadar IMS"
+      carrier_id = "2006"
+      mcc="606"
+      mnc="01"
+      apn="ims"
+      type="ims"
+      authtype="1"
+      protocol="IPV4V6"
+  />
+
+  <apn carrier="almadar XCAP"
+      carrier_id = "2006"
+      mcc="606"
+      mnc="01"
+      apn="hos"
+      type="xcap"
+      authtype="1"
+      protocol="IPV4V6"
+  />
+
   <apn carrier="Al-Jeel Phone"
       carrier_id = "2189"
       mcc="606"
@@ -37182,9 +37336,21 @@
       user="orange"
       password="orange"
       type="default,ia,supl"
+      protocol="IPV6"
+      user_editable="false"
+  />
+
+  <apn carrier="Orange RE IMS"
+      carrier_id = "1676"
+      mcc="647"
+      mnc="00"
+      apn="ims"
+      type="ims"
+      protocol="IPV4V6"
+      user_visible="false"
   />
 
-  <apn carrier="Orange MMS Réunion"
+  <apn carrier="Orange RE MMS"
       carrier_id = "1676"
       mcc="647"
       mnc="00"
@@ -40211,6 +40377,47 @@
       user_visible="false"
   />
 
+  <apn carrier="mobi LTE"
+      carrier_id = "2464"
+      apn="4g.mobi.net"
+      type="default,supl,ia,dun"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+  />
+
+  <apn carrier="mobi MMS"
+      carrier_id = "2464"
+      apn="mms.mobi.net"
+      mmsc="http://mms.mobi.net"
+      type="mms"
+  />
+
+  <apn carrier="mobi IMS"
+      carrier_id = "2464"
+      apn="ims"
+      type="ims"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+      network_type_bitmask="13|18|20"
+  />
+
+  <apn carrier="mobi XCAP"
+      carrier_id = "2464"
+      apn="hos"
+      type="xcap"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+      network_type_bitmask="13|18|20"
+  />
+
+  <apn carrier="mobi OTA"
+      carrier_id = "2464"
+      apn="ota.mobi.net"
+      type="fota"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+  />
+
   <apn carrier="travelfy"
       carrier_id="2472"
       apn="travelfy"
diff --git a/frameworks/PlatformLibrary/Android.bp b/frameworks/PlatformLibrary/Android.bp
index e3e929b..29d3bae 100644
--- a/frameworks/PlatformLibrary/Android.bp
+++ b/frameworks/PlatformLibrary/Android.bp
@@ -13,12 +13,7 @@
 // limitations under the License.
 
 package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_sample_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    default_applicable_licenses: ["device_sample_license"],
+    default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
 javadoc {
```

