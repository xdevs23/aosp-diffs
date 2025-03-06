```diff
diff --git a/etc/Android.bp b/etc/Android.bp
new file mode 100644
index 0000000..62c04ed
--- /dev/null
+++ b/etc/Android.bp
@@ -0,0 +1,7 @@
+prebuilt_etc {
+    name: "apns-full-conf.xml",
+    src: "apns-full-conf.xml",
+    filename: "apns-conf.xml",
+    product_specific: true,
+    no_full_install: true,
+}
diff --git a/etc/apns-full-conf.xml b/etc/apns-full-conf.xml
index e4a1de2..fa05a6e 100644
--- a/etc/apns-full-conf.xml
+++ b/etc/apns-full-conf.xml
@@ -823,6 +823,23 @@
       roaming_protocol="IPV4V6"
   />
 
+ <apn carrier="Tata Move"
+      mcc="204"
+      mnc="07"
+      apn="move.dataxs.mobi"
+      type="default,supl,dun"
+  />
+
+ <apn carrier="IMS"
+      mcc="204"
+      mnc="07"
+      apn="ims"
+      type="ims"
+      protocol="IPV6"
+      roaming_protocol="IPV6"
+      user_visible="false"
+  />
+
   <apn carrier="KPN Mobiel Internet"
       carrier_id = "1644"
       mcc="204"
@@ -913,7 +930,7 @@
       type="default,ia,supl"
   />
 
-  <apn carrier="KPN Mobiel Internet"
+  <apn carrier="Telfort Mobiel Internet"
       carrier_id = "1644"
       mcc="204"
       mnc="12"
@@ -1509,15 +1526,6 @@
       user_visible="false"
   />
 
-  <apn carrier="Orange Entreprises"
-      carrier_id = "32"
-      mcc="208"
-      mnc="01"
-      apn="orange-mib"
-      type="default,ia,supl"
-      user_editable="false"
-  />
-
   <apn carrier="Orange MCX"
       carrier_id="32"
       mcc="208"
@@ -1652,46 +1660,6 @@
       mvno_match_data="8981090"
   />
 
-  <apn carrier="Webbing"
-      mcc="208"
-      mnc="01"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="208"
-      mnc="01"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="208"
-      mnc="01"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="208"
-      mnc="01"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="SFR LTE"
       carrier_id = "27"
       mcc="208"
@@ -2471,7 +2439,7 @@
       authtype="1"
       mvno_type="spn"
       mvno_match_data="Orange"
-      type="default"
+      type="default,supl,ia"
       user_editable="false"
   />
 
@@ -2657,17 +2625,18 @@
       mvno_match_data="JAZZTEL"
   />
 
-  <apn carrier="jazzinternet"
+  <apn carrier="JAZZTEL internet"
       carrier_id = "1974"
       mcc="214"
       mnc="03"
       apn="jazzinternet"
       mvno_type="spn"
       mvno_match_data="JAZZTEL"
-      type="default,supl,dun"
+      type="default,supl,dun,ia"
+      user_editable="false"
   />
 
-  <apn carrier="MMS"
+  <apn carrier="JAZZTEL MMS"
       carrier_id = "1974"
       mcc="214"
       mnc="03"
@@ -2681,6 +2650,7 @@
       mvno_type="spn"
       mvno_match_data="JAZZTEL"
       type="mms"
+      user_editable="false"
   />
 
   <apn carrier="JAZZTEL IMS"
@@ -2717,7 +2687,8 @@
       password = "orange"
       mvno_type="spn"
       mvno_match_data="simyo"
-      type="default,supl,dun"
+      type="default,supl,dun,ia"
+      user_editable="false"
   />
 
   <apn carrier="simyo MMS"
@@ -2734,6 +2705,7 @@
       mvno_type="spn"
       mvno_match_data="simyo"
       type="mms"
+      user_editable="false"
   />
 
   <apn carrier="simyo IMS"
@@ -3208,6 +3180,7 @@
       type="default,ia,supl,dun"
       mvno_type="spn"
       mvno_match_data="simyo"
+      user_editable="false"
     />
 
   <apn carrier="simyo MMS"
@@ -3216,12 +3189,15 @@
       mnc="19"
       apn="orangemms"
       authtype="1"
+      user="orange"
+      password="orange"
       mmsc="http://mms.orange.es"
       mmsproxy="172.22.188.25"
       mmsport="8080"
       type="mms"
       mvno_type="spn"
       mvno_match_data="simyo"
+      user_editable="false"
   />
 
   <apn carrier="jazzinternet"
@@ -3962,46 +3938,6 @@
       mvno_match_data="Kena Mobile R"
   />
 
-  <apn carrier="Webbing"
-      mcc="222"
-      mnc="01"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="222"
-      mnc="01"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="222"
-      mnc="01"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="222"
-      mnc="01"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="Kena Mobile Web"
       mcc="222"
       mnc="07"
@@ -5459,46 +5395,6 @@
       mvno_match_data="Jump"
   />
 
-  <apn carrier="Webbing"
-      mcc="234"
-      mnc="10"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="234"
-      mnc="10"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="234"
-      mnc="10"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="234"
-      mnc="10"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="o2 Mobile Web"
       carrier_id = "1492"
       mcc="234"
@@ -5807,6 +5703,23 @@
       type="default,ia,supl"
   />
 
+  <apn carrier="Tata Move UK"
+      mcc="234"
+      mnc="27"
+      apn="move.dataxs.mobi"
+      type="default,supl,dun"
+  />
+
+  <apn carrier="IMS"
+      mcc="234"
+      mnc="27"
+      apn="ims"
+      type="ims"
+      protocol="IPV6"
+      roaming_protocol="IPV6"
+      user_visible="false"
+  />
+
   <apn carrier="EE Internet"
       carrier_id = "718"
       mcc="234"
@@ -6606,16 +6519,6 @@
   />
 
   <apn carrier="3"
-      carrier_id = "1466"
-      mcc="238"
-      mnc="06"
-      apn="data.tre.dk"
-      type="default,ia,supl"
-      protocol="IPV4V6"
-      roaming_protocol="IPV4V6"
-  />
-
-  <apn carrier="3 MMS"
       carrier_id = "1466"
       mcc="238"
       mnc="06"
@@ -6623,8 +6526,9 @@
       mmsc="http://mms.3.dk/"
       mmsproxy="mmsproxy.3.dk"
       mmsport="8799"
-      type="mms"
+      type="default,ia,supl,mms"
       protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       network_type_bitmask="1|2|3|4|5|6|7|8|9|10|12|13|14|15|17|20"
   />
 
@@ -6837,16 +6741,6 @@
   />
 
   <apn carrier="3"
-      carrier_id = "1691"
-      mcc="240"
-      mnc="02"
-      apn="data.tre.se"
-      type="default,ia,supl"
-      protocol="IPV4V6"
-      roaming_protocol="IPV4V6"
-  />
-
-  <apn carrier="3 MMS"
       carrier_id = "1691"
       mcc="240"
       mnc="02"
@@ -6854,8 +6748,9 @@
       mmsc="http://mms.tre.se"
       mmsproxy="mmsproxy.tre.se"
       mmsport="8799"
-      type="mms"
+      type="default,ia,supl,mms"
       protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
       network_type_bitmask="1|2|3|4|5|6|7|8|9|10|12|13|14|15|17|20"
   />
 
@@ -10829,41 +10724,59 @@
       mmsport="8799"
       mvno_match_data="5455"
       mvno_type="gid"
+      protocol="IPV4V6"
+      roaming_protocol="IP"
   />
 
-  <apn carrier="TELUS Tether"
+  <apn carrier="TELUS ISP"
       carrier_id = "1404"
       mcc="302"
       mnc="220"
       apn="isp.telus.com"
-      server="*"
       type="dun"
       mvno_match_data="5455"
       mvno_type="gid"
+      protocol="IP"
+      roaming_protocol="IP"
   />
 
-  <apn carrier="Koodo"
+  <apn carrier="IMS"
+        carrier_id = "1404"
+        mcc="302"
+        mnc="220"
+        apn="ims"
+        type="ims"
+        mvno_match_data="5455"
+        mvno_type="gid"
+        protocol="IPV6"
+        roaming_protocol="IPV4V6"
+  />
+
+  <apn carrier="KOODO SP"
       carrier_id = "2020"
       mcc="302"
       mnc="220"
       apn="sp.koodo.com"
-      type="default,ia,mms,supl"
+      type="default,ia,mms,supl,dun"
       mmsc="http://aliasredirect.net/proxy/koodo/mmsc"
       mmsproxy="mmscproxy.mobility.ca"
       mmsport="8799"
       mvno_match_data="4B4F"
       mvno_type="gid"
+      protocol="IPV4V6"
+      roaming_protocol="IP"
   />
 
-  <apn carrier="Koodo Tether"
+  <apn carrier="IMS"
       carrier_id = "2020"
       mcc="302"
       mnc="220"
-      apn="sp.koodo.com"
-      server="*"
-      type="dun"
+      apn="ims"
+      type="ims"
       mvno_match_data="4B4F"
       mvno_type="gid"
+      protocol="IPV6"
+      roaming_protocol="IPV4V6"
   />
 
   <apn carrier="Mobile Internet"
@@ -10900,6 +10813,8 @@
       mmsport="8799"
       mvno_type="gid"
       mvno_match_data="4D4F"
+      protocol="IPV4V6"
+      roaming_protocol="IP"
   />
 
   <apn carrier="Tethered Mobile Internet"
@@ -10910,6 +10825,18 @@
       type="dun"
       mvno_type="gid"
       mvno_match_data="4D4F"
+      protocol="IP"
+      roaming_protocol="IP"
+  />
+
+  <apn carrier="IMS"
+      carrier_id = "2089"
+      mcc="302"
+      mnc="220"
+      apn="ims"
+      type="ims"
+      protocol="IPV6"
+      roaming_protocol="IPV4V6"
   />
 
   <apn carrier="TELUS ISP"
@@ -17410,46 +17337,6 @@
       mtu="1422"
   />
 
-  <apn carrier="Webbing"
-      mcc="311"
-      mnc="588"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="311"
-      mnc="588"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="311"
-      mnc="588"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="311"
-      mnc="588"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="U.S. Cellular"
       mcc="311"
       mnc="589"
@@ -18314,6 +18201,56 @@
       type="default,ia"
   />
 
+  <apn carrier="mobi LTE"
+      carrier_id = "2464"
+      mcc="313"
+      mnc="460"
+      apn="4g.mobi.net"
+      type="default,supl,ia,dun"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+  />
+
+  <apn carrier="mobi MMS"
+      carrier_id = "2464"
+      mcc="313"
+      mnc="460"
+      apn="mms.mobi.net"
+      mmsc="http://mms.mobi.net"
+      type="mms"
+  />
+
+  <apn carrier="mobi IMS"
+      carrier_id = "2464"
+      mcc="313"
+      mnc="460"
+      apn="ims"
+      type="ims"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+      network_type_bitmask="13|18|20"
+  />
+
+  <apn carrier="mobi XCAP"
+      carrier_id = "2464"
+      mcc="313"
+      mnc="460"
+      apn="hos"
+      type="xcap"
+      protocol="IPV4V6"
+      network_type_bitmask="13|18|20"
+  />
+
+  <apn carrier="mobi OTA"
+      carrier_id = "2464"
+      mcc="313"
+      mnc="460"
+      apn="ota.mobi.net"
+      type="fota"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+  />
+
   <apn carrier="MobileUC IMS"
       carrier_id = "10030"
       mcc="313"
@@ -29493,6 +29430,21 @@
       type="mms"
   />
 
+  <apn carrier="Rcell IMS"
+      carrier_id = "2646"
+      mcc="417"
+      mnc="50"
+      apn="ims"
+      type="ims"
+  />
+   <apn carrier="Rcell Internet"
+      carrier_id = "2646"
+      mcc="417"
+      mnc="50"
+      apn="internet"
+      type="default"
+  />
+
   <apn carrier="Asiacell Internet"
       carrier_id = "1969"
       mcc="418"
@@ -29954,46 +29906,6 @@
       user_visible="false"
   />
 
-  <apn carrier="Webbing"
-      mcc="424"
-      mnc="02"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="424"
-      mnc="02"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="424"
-      mnc="02"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="424"
-      mnc="02"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="du LTE"
       carrier_id = "1970"
       mcc="424"
@@ -30085,12 +29997,10 @@
       type="default,ia,supl"
   />
 
-  <apn carrier="Jawwal WAP"
+  <apn carrier="Jawwal internet"
       mcc="425"
       mnc="05"
-      apn="wap"
-      proxy="213.244.118.129"
-      port="8080"
+      apn="internet"
       type="default,ia,supl"
   />
 
@@ -30459,7 +30369,7 @@
       type="default,ia,supl"
   />
 
-  <apn carrier="shatelmonile"
+  <apn carrier="shatelmobile"
      mcc="432"
      mnc="08"
      apn="shatelmobile"
@@ -30468,7 +30378,7 @@
      roaming_protocol="IPV4V6"
   />
 
-  <apn carrier="shatelmonile"
+  <apn carrier="shatelmobile"
      mcc="432"
      mnc="08"
      apn="SHM-IMS"
@@ -31477,46 +31387,6 @@
       mvno_match_data="547275554B3030656E"
   />
 
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="00"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="00"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="00"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="00"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="csl"
       carrier_id = "759"
       mcc="454"
@@ -32132,46 +32002,6 @@
       roaming_protocol="IPV4V6"
   />
 
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="12"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="12"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="12"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="12"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="CMHK MMS"
       carrier_id = "767"
       mcc="454"
@@ -32626,38 +32456,6 @@
       roaming_protocol="IPV4V6"
   />
 
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="35"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-  />
-
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="35"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-  />
-
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="35"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-   />
-
-  <apn carrier="Webbing"
-      mcc="454"
-      mnc="35"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-   />
-
   <apn carrier="SmarTone Macau"
       carrier_id = "1613"
       mcc="455"
@@ -34360,23 +34158,35 @@
       roaming_protocol="IP"
   />
 
-  <apn carrier="VF AU PXT"
+  <apn carrier="Pivotel MMS"
       carrier_id = "492"
       mcc="505"
       mnc="88"
-      apn="live.vodafone.com"
-      mmsc="http://pxt.vodafone.net.au/pxtsend"
-      mmsproxy="10.202.2.60"
-      mmsport="8080"
+      apn="mms"
+      mmsc="http://mmsc.pivotel.com.au:8002"
+      mmsproxy="203.105.216.88"
+      mmsport="8088"
       type="mms"
   />
 
-  <apn carrier="VF Internet"
+  <apn carrier="Pivotel Internet"
       carrier_id = "492"
       mcc="505"
       mnc="88"
-      apn="vfinternet.au"
+      apn="internet"
       type="default,ia,supl"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
+  />
+
+  <apn carrier="Pivotel IMS"
+      carrier_id = "492"
+      mcc="505"
+      mnc="88"
+      apn="ims"
+      type="ims"
+      protocol="IPV4V6"
+      roaming_protocol="IPV4V6"
   />
 
   <apn carrier="Optus Internet"
@@ -39033,46 +38843,6 @@
       password="1212"
   />
 
-  <apn carrier="Webbing"
-      mcc="724"
-      mnc="32"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="724"
-      mnc="32"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="724"
-      mnc="32"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="724"
-      mnc="32"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="Algar Telecom Internet"
       carrier_id = "1390"
       mcc="724"
@@ -39152,46 +38922,6 @@
       type="ims"
   />
 
-  <apn carrier="Webbing"
-      mcc="724"
-      mnc="54"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="724"
-      mnc="54"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="724"
-      mnc="54"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="724"
-      mnc="54"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="Internet Movil"
       carrier_id = "1427"
       mcc="730"
@@ -39395,46 +39125,6 @@
       roaming_protocol="IPV4V6"
   />
 
-  <apn carrier="Webbing"
-      mcc="732"
-      mnc="101"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="732"
-      mnc="101"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="732"
-      mnc="101"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="732"
-      mnc="101"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="Tigo Web"
       carrier_id = "624"
       mcc="732"
@@ -40110,38 +39800,6 @@
       type="default,ia,supl,mms"
   />
 
-  <apn carrier="Webbing"
-      mcc="901"
-      mnc="01"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-  />
-
-  <apn carrier="Webbing"
-      mcc="901"
-      mnc="01"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-   />
-
-  <apn carrier="Webbing"
-      mcc="901"
-      mnc="01"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-   />
-
-  <apn carrier="Webbing"
-      mcc="901"
-      mnc="01"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-   />
-
   <apn carrier="CIOT Vodafone"
       mcc="901"
       mnc="28"
@@ -40151,46 +39809,6 @@
       type="default,ia"
   />
 
-  <apn carrier="Webbing"
-      mcc="901"
-      mnc="31"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-  />
-
-  <apn carrier="Webbing"
-      mcc="901"
-      mnc="31"
-      apn="ims"
-      type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="901"
-      mnc="31"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
-  <apn carrier="Webbing"
-      mcc="901"
-      mnc="31"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
-
   <apn carrier="mobiledata"
       mcc="901"
       mnc="37"
@@ -40212,53 +39830,37 @@
       type="default,ia,supl"
   />
 
-  <apn carrier="BICS Internet"
-      carrier_id = "2132"
+  <apn carrier="Tata Move IOT"
       mcc="901"
-      mnc="58"
-      apn="bicsapn"
-      type="default,ia,supl"
-  />
-
-  <apn carrier="Webbing"
-      mcc="901"
-      mnc="61"
-      apn="wbdata"
-      type="default,ia,dun"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
+      mnc="54"
+      apn="move.dataxs.mobi"
+      type="default,supl,dun"
   />
 
-  <apn carrier="Webbing"
+  <apn carrier="IMS"
       mcc="901"
-      mnc="61"
+      mnc="54"
       apn="ims"
       type="ims"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
+      protocol="IPV6"
+      roaming_protocol="IPV6"
+      user_visible="false"
+  />
 
-  <apn carrier="Webbing"
+  <apn carrier="BICS Internet"
+      carrier_id = "2132"
       mcc="901"
-      mnc="61"
-      apn="xcap"
-      type="xcap"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
+      mnc="58"
+      apn="bicsapn"
+      type="default,ia,supl"
+  />
 
-  <apn carrier="Webbing"
+<apn carrier="Sparkle"
       mcc="901"
-      mnc="61"
-      apn="sos"
-      type="emergency"
-      protocol="IPV4V6"
-      mvno_type="gid"
-      mvno_match_data="536E617065"
-   />
+      mnc="78"
+      apn="ep05.tis.com"
+      type="default,ia,supl"
+  />
 
   <apn carrier="Verizon IA"
       mcc="999"
@@ -40996,6 +40598,35 @@
       user_visible="false"
   />
 
+  <apn carrier="Webbing"
+      carrier_id = "2631"
+      apn="wbdata"
+      type="default,ia,dun"
+      protocol="IPV4V6"
+  />
+
+  <apn carrier="Webbing"
+      carrier_id = "2631"
+      apn="ims"
+      type="ims"
+      protocol="IPV4V6"
+   />
+
+  <apn carrier="Webbing"
+      carrier_id = "2631"
+      apn="xcap"
+      type="xcap"
+      protocol="IPV4V6"
+   />
+
+  <apn carrier="Webbing"
+      carrier_id = "2631"
+      apn="sos"
+      type="emergency"
+      protocol="IPV4V6"
+   />
+
+
   <apn carrier="Tracfone AT&amp;T"
       carrier_id = "10000"
       apn="ereseller"
```

