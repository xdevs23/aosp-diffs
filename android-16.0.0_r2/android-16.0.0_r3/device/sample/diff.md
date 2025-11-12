```diff
diff --git a/etc/apns-full-conf.xml b/etc/apns-full-conf.xml
index 59607f2..0620ab8 100644
--- a/etc/apns-full-conf.xml
+++ b/etc/apns-full-conf.xml
@@ -1551,8 +1551,6 @@
       mcc="208"
       mnc="01"
       apn="ofnew.fr"
-      proxy="192.168.10.100"
-      port="8080"
       user="orange"
       password="orange"
       authtype="1"
@@ -1569,8 +1567,6 @@
       user="orange"
       password="orange"
       mmsc="http://mms.orange.fr"
-      mmsproxy="192.168.10.200"
-      mmsport="8080"
       authtype="1"
       type="mms"
       mvno_match_data="33"
@@ -1596,8 +1592,6 @@
       user="orange"
       password="orange"
       mmsc="http://mms.orange.fr"
-      mmsproxy="192.168.10.200"
-      mmsport="8080"
       authtype="0"
       type="mms"
       mvno_match_data="4E"
@@ -5540,6 +5534,14 @@
       user_editable="false"
   />
 
+    <apn carrier="Wireless Logic"
+      mcc="234"
+      mnc="18"
+      apn="globaldata"
+      type="default,ia,supl"
+      protocol="IPV4V6"
+  />
+
   <apn carrier="3"
       carrier_id = "1505"
       mcc="234"
@@ -6269,7 +6271,7 @@
       type="mms"
   />
 
-  <apn carrier="Internet"
+  <apn carrier="Sky Internet"
       mcc="234"
       mnc="57"
       apn="mobile.sky"
@@ -6279,7 +6281,7 @@
       roaming_protocol="IPV4V6"
   />
 
-  <apn carrier="MMS"
+  <apn carrier="Sky MMS"
       mcc="234"
       mnc="57"
       apn="mms.mobile.sky"
@@ -6295,7 +6297,7 @@
   <apn carrier="Sky IMS"
       mcc="234"
       mnc="57"
-      apn="IMS"
+      apn="ims"
       type="ims"
       protocol="IPV4V6"
       roaming_protocol="IPV4V6"
@@ -6312,7 +6314,7 @@
       user_visible="false"
   />
 
-  <apn carrier="Sky MMS VoWiFi"
+  <apn carrier="Sky MMS WiFi"
       mcc="234"
       mnc="57"
       apn="wifi.mms.mobile.sky"
@@ -7007,7 +7009,7 @@
  <apn carrier="Sky IMS"
       mcc="240"
       mnc="07"
-      apn="IMS"
+      apn="ims"
       type="ims"
       mvno_type="gid"
       mvno_match_data="0C"
@@ -7031,7 +7033,7 @@
       roaming_protocol="IPV4V6"
   />
 
-  <apn carrier="Sky MMS VoWiFi"
+  <apn carrier="Sky MMS WiFi"
       mcc="240"
       mnc="07"
       apn="wifi.mms.mobile.sky"
@@ -7070,6 +7072,35 @@
       user_visible="false"
   />
 
+  <apn carrier="Sky IE IMS"
+     mcc="240"
+     mnc="07"
+     apn="ims"
+     type="ims"
+     mvno_type="gid"
+     mvno_match_data="0D"
+     user_visible="false"
+  />
+
+  <apn carrier="Sky IE Internet"
+     mcc="240"
+     mnc="07"
+     apn="mobile.sky"
+     type="default,ia,supl"
+     mvno_match_data="0D"
+     mvno_type="gid"
+  />
+
+  <apn carrier="Sky IE Ut"
+     mcc="240"
+     mnc="07"
+     apn="ut.mobile.sky"
+     type="xcap"
+     mvno_type="gid"
+     mvno_match_data="0D"
+     user_visible="false"
+  />
+
   <apn carrier="Sberbank-Telecom Internet"
       mcc="240"
       mnc="07"
@@ -10032,6 +10063,30 @@
       mvno_match_data="75696531"
   />
 
+  <apn carrier="Sky IE Internet"
+     mcc="272"
+     mnc="25"
+     apn="mobile.sky"
+     authtype="0"
+     type="default,ia,supl"
+  />
+
+  <apn carrier="Sky IE IMS"
+     mcc="272"
+     mnc="25"
+     apn="ims"
+     type="ims"
+     user_visible="false"
+  />
+
+  <apn carrier="Sky IE Ut"
+     mcc="272"
+     mnc="25"
+     apn="ut.mobile.sky"
+     type="xcap"
+     user_visible="false"
+  />
+
   <apn carrier="Siminn Internet"
       carrier_id = "1565"
       mcc="274"
@@ -10697,9 +10752,9 @@
       mcc="295"
       mnc="01"
       apn="gprs.swisscom.ch"
-      proxy="192.168.210.1"
-      port="8080"
-      type="default,ia"
+      type="default,ia,supl"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
   />
 
   <apn carrier="Internet"
@@ -29720,6 +29775,14 @@
       type="default,ia,supl"
   />
 
+  <apn carrier="Omnnea"
+      carrier_id = "2167"
+      mcc="418"
+      mnc="92"
+      apn="ims"
+      type="ims"
+  />
+
   <apn carrier="MI"
       carrier_id = "1585"
       mcc="419"
@@ -40833,6 +40896,13 @@
       protocol="IPV4V6"
    />
 
+  <apn carrier="Webbing"
+      carrier_id = "2631"
+      apn="mms.wbdata"
+      type="mms"
+      mmsc="http://mms.webbingsolutions.com"
+      protocol="IPV4V6"
+   />
 
   <apn carrier="Tracfone AT&amp;T"
       carrier_id = "10000"
```

