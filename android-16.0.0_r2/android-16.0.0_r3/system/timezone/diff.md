```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index a782005..8e445ec 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -77,4 +77,8 @@ apex {
         "apex_tzdata_ver9",
         "apex_icu_res_files_ver9",
     ],
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
diff --git a/apex/tests/src/java/android/tzdata/mts/TimeZoneVersionTest.java b/apex/tests/src/java/android/tzdata/mts/TimeZoneVersionTest.java
index baf7d0a..f07adca 100644
--- a/apex/tests/src/java/android/tzdata/mts/TimeZoneVersionTest.java
+++ b/apex/tests/src/java/android/tzdata/mts/TimeZoneVersionTest.java
@@ -159,7 +159,7 @@ public class TimeZoneVersionTest {
                 .collect(toMap(File::toString, TimeZoneVersionTest::readTzDbVersionFrom));
 
         String msg = "Versions are not consistent: " + ianaVersionInVersionFile;
-        assertEquals(msg, 1, Set.of(ianaVersionInVersionFile.values()).size());
+        assertEquals(msg, 1, Set.copyOf(ianaVersionInVersionFile.values()).size());
     }
 
     private static int getCurrentFormatMajorVersion() {
diff --git a/input_data/android/countryzones.txt b/input_data/android/countryzones.txt
index d1a64ff..60ee865 100644
--- a/input_data/android/countryzones.txt
+++ b/input_data/android/countryzones.txt
@@ -25,7 +25,7 @@
 # a time zone for an Android device.
 
 # ianaVersion: The version of the IANA rules this file matches.
-ianaVersion:"2025a"
+ianaVersion:"2025b"
 
 # countries:
 #
@@ -1078,6 +1078,7 @@ countries:<
   timeZoneMappings:<
     utcOffset:"-3:00"
     id:"America/Punta_Arenas"
+    alternativeIds: "America/Coyhaique"
   >
 
   timeZoneMappings:<
@@ -1868,6 +1869,11 @@ countries:<
 countries:<
   isoCode:"ki"
   defaultTimeZoneId:"Pacific/Tarawa"
+
+  # Boost the strength of the country default:
+  # >91% of the population use "Pacific/Tarawa"
+  defaultTimeZoneBoost: true
+
   timeZoneMappings:<
     utcOffset:"14:00"
     id:"Pacific/Kiritimati"
@@ -2579,6 +2585,11 @@ countries:<
 countries:<
   isoCode:"pf"
   defaultTimeZoneId:"Pacific/Tahiti"
+
+  # Boost the strength of the country default:
+  # >96% of the population use "Pacific/Tahiti"
+  defaultTimeZoneBoost: true
+
   timeZoneMappings:<
     utcOffset:"-9:00"
     id:"Pacific/Gambier"
diff --git a/input_data/android/telephonylookup.txt b/input_data/android/telephonylookup.txt
index 6802417..ff7c757 100644
--- a/input_data/android/telephonylookup.txt
+++ b/input_data/android/telephonylookup.txt
@@ -65,6 +65,41 @@ networks:<
   countryIsoCode: "as"
 >
 
+networks:<
+  # Sure  http://b/411132517
+  mcc: "234"
+  mnc: "55"
+  countryIsoCode: "je"
+>
+
+networks:<
+  # JT  http://b/411132517
+  mcc: "234"
+  mnc: "50"
+  countryIsoCode: "je"
+>
+
+networks:<
+  # Airtel-Vodafone  http://b/411132517
+  mcc: "234"
+  mnc: "03"
+  countryIsoCode: "je"
+>
+
+networks:<
+  # Manx Telecom  http://b/411132517
+  mcc: "234"
+  mnc: "58"
+  countryIsoCode: "im"
+>
+
+networks:<
+  # Sure  http://b/411132517
+  mcc: "234"
+  mnc: "36"
+  countryIsoCode: "im"
+>
+
 # Countries / regions by Mobile Country Code (MCC).
 #
 # The table below is built from three main resources:
diff --git a/input_data/iana/tzdata2025a.tar.gz b/input_data/iana/tzdata2025a.tar.gz
deleted file mode 100644
index fee077f..0000000
Binary files a/input_data/iana/tzdata2025a.tar.gz and /dev/null differ
diff --git a/input_data/iana/tzdata2025a.tar.gz.asc b/input_data/iana/tzdata2025a.tar.gz.asc
deleted file mode 100644
index a4ce3e2..0000000
--- a/input_data/iana/tzdata2025a.tar.gz.asc
+++ /dev/null
@@ -1,16 +0,0 @@
------BEGIN PGP SIGNATURE-----
-
-iQIzBAABCgAdFiEEfjeSqdis99YzvBWI7ZfpDmKqfjQFAmeIA2oACgkQ7ZfpDmKq
-fjREhxAAjB1QDroFoq07V+56IIrJR3pK/x4Z2jBbg53N49Cam1oMZK5Wxm291d0G
-lPutNQvjiNubnBG4pgMMQ2xEF6jgYY0eFfLlORGK9IoW8e3lnlAqSR9BsOQvWjeA
-lKfmBkhFXetSJ8gu2ModVybpVIqDaJJ73sNQSsA01MHwz0RLV5CLOHXitJ8lBO68
-vdSArRhalLUEIVytAKyy1a0msFdzrrDj/7q6tMV9NDY1xQg4V9TLxnPNds29H0x8
-xO2zrDug6zrbg9z994JYkhq9h9DLe5h4F3StnaDwRK8eLLRq5D7ryK77Z8dtyXZf
-tDPgiNc1MquSg48481dDiUfsRdN5S2OLVFqjyWUuwVKBSkSRv/nBQqisGEybY86T
-H84D5WA0zlj8mFJyuKFmvGHzzKZ6X7mUNrTObaY3G+QHgHjIKWqO7oog447YOYOG
-DSA5rSmYrzZp2RXP/doeFZD+2kbNVPlN8zBh6lANABwvFH6IhDI+/OJzGJqeYotz
-ZWVoU3um6aToMS4Uv2PdBNbH1W1P1pzzMM5TJ/bQO/ujCwaBSTwoDPJT6tW9BLrO
-gJUWd1AumocieAWc0Vyzbrpzbo7Vc//1LF+s1eI+zWt8925unFrBArvQ4h/PyXsc
-O5LhOQVm1986y9xy2YyF+Cy5s+xsKvKENQ0NbLIDa+l5MdEdEXc=
-=NQgW
------END PGP SIGNATURE-----
diff --git a/input_data/iana/tzdata2025b.tar.gz b/input_data/iana/tzdata2025b.tar.gz
new file mode 100644
index 0000000..698897b
Binary files /dev/null and b/input_data/iana/tzdata2025b.tar.gz differ
diff --git a/input_data/iana/tzdata2025b.tar.gz.asc b/input_data/iana/tzdata2025b.tar.gz.asc
new file mode 100644
index 0000000..70182e1
--- /dev/null
+++ b/input_data/iana/tzdata2025b.tar.gz.asc
@@ -0,0 +1,16 @@
+-----BEGIN PGP SIGNATURE-----
+
+iQIzBAABCgAdFiEEfjeSqdis99YzvBWI7ZfpDmKqfjQFAmffIRcACgkQ7ZfpDmKq
+fjS6yw//Wdqj0sipbfTMHAJh3y5065wUkwJhi4cbMbpG1MfJ7HQOeF/ISXBnQo2L
+RIzpRPswIUweKziBQx5+f+VgViWJTJRTbb2Vk0i1SfnQ6BfeEmqIXwxa87rSeCEk
+vBeur6mnv3Nc/f9HVvKBqx9ux6FIPWMoQbuDZyNh/GfAvrCp69YkC4miZlo8D1M5
+QKoNqLB2B/JTeFVdchVYu9Jxyc2LGsSM9SDTuDDHKQyMyZN/93vJiSzfUMkzW6AF
+dJif5zWaj2YfrcMFP87IMKH9rAA6XrKNbf+0Xu7AWKpMW6vu30NyMoLQvuo1Gf0g
+uFxqFTu7fVt6ZzO2cVFuzS/MPj8pufPng88gOHpU34ASID5DB5hf98r7fxmn3jwc
+aBiecrqpq4F4GEqrBQHGVugFM95iBElvl5kEupO0C/8wqvV7gWoo8Qiaix7b/DE4
+zpc4z8wNHntqjeP3Qrv+zX9wfZThYoX/j8UuIVZEhm1o/vHeNn5zBZz55jCQ4KOc
+Sffl68lWjdLkcS4edsaM1GyPsFnqaFP6FZ95zrhyl/mpsDNJggIaL3RuajMIMCBt
+othXosBAuBKlv3gqXBIEDaifp2aqBo0YgUUJhcVtyv+advzcUgeppnMUPh0US66R
+inVSt7pMQ8ubYcDQzDchoVPEay/69SPaRRd3W9unQGCBepjaXGo=
+=W7AG
+-----END PGP SIGNATURE-----
diff --git a/output_data/android/telephonylookup.xml b/output_data/android/telephonylookup.xml
index 6582955..341b861 100644
--- a/output_data/android/telephonylookup.xml
+++ b/output_data/android/telephonylookup.xml
@@ -7,6 +7,11 @@
   <network mcc="310" mnc="370" country="gu"/>
   <network mcc="310" mnc="470" country="gu"/>
   <network mcc="311" mnc="780" country="as"/>
+  <network mcc="234" mnc="55" country="je"/>
+  <network mcc="234" mnc="50" country="je"/>
+  <network mcc="234" mnc="03" country="je"/>
+  <network mcc="234" mnc="58" country="im"/>
+  <network mcc="234" mnc="36" country="im"/>
  </networks>
  <mobile_countries>
   <mobile_country mcc="202">
diff --git a/output_data/android/tzids.prototxt b/output_data/android/tzids.prototxt
index ba603e0..81fab57 100644
--- a/output_data/android/tzids.prototxt
+++ b/output_data/android/tzids.prototxt
@@ -1,5 +1,5 @@
 # Autogenerated file - DO NOT EDIT.
-ianaVersion: "2025a"
+ianaVersion: "2025b"
 countryMappings {
   isoCode: "ad"
   timeZoneIds: "Europe/Andorra"
@@ -582,6 +582,10 @@ countryMappings {
   timeZoneIds: "America/Punta_Arenas"
   timeZoneIds: "America/Santiago"
   timeZoneIds: "Pacific/Easter"
+  timeZoneLinks {
+    alternativeId: "America/Coyhaique"
+    preferredId: "America/Punta_Arenas"
+  }
   timeZoneLinks {
     alternativeId: "Chile/Continental"
     preferredId: "America/Santiago"
diff --git a/output_data/android/tzlookup.xml b/output_data/android/tzlookup.xml
index da38859..5cbc9d0 100644
--- a/output_data/android/tzlookup.xml
+++ b/output_data/android/tzlookup.xml
@@ -2,7 +2,7 @@
 
  **** Autogenerated file - DO NOT EDIT ****
 
---><timezones ianaversion="2025a">
+--><timezones ianaversion="2025b">
  <countryzones>
   <country code="ad" default="Europe/Andorra" everutc="n">
    <id>Europe/Andorra</id>
@@ -206,7 +206,7 @@
    <id>Pacific/Rarotonga</id>
   </country>
   <country code="cl" default="America/Santiago" everutc="n">
-   <id>America/Punta_Arenas</id>
+   <id alts="America/Coyhaique">America/Punta_Arenas</id>
    <id alts="Chile/Continental">America/Santiago</id>
    <id alts="Chile/EasterIsland">Pacific/Easter</id>
   </country>
@@ -434,7 +434,7 @@
   <country code="kh" default="Asia/Phnom_Penh" everutc="n">
    <id>Asia/Phnom_Penh</id>
   </country>
-  <country code="ki" default="Pacific/Tarawa" everutc="n">
+  <country code="ki" default="Pacific/Tarawa" defaultBoost="y" everutc="n">
    <id>Pacific/Kiritimati</id>
    <id alts="Pacific/Enderbury">Pacific/Kanton</id>
    <id>Pacific/Tarawa</id>
@@ -628,7 +628,7 @@
   <country code="pe" default="America/Lima" everutc="n">
    <id>America/Lima</id>
   </country>
-  <country code="pf" default="Pacific/Tahiti" everutc="n">
+  <country code="pf" default="Pacific/Tahiti" defaultBoost="y" everutc="n">
    <id>Pacific/Gambier</id>
    <id>Pacific/Marquesas</id>
    <id>Pacific/Tahiti</id>
diff --git a/output_data/iana/tzdata b/output_data/iana/tzdata
index 2dd2c26..a32b76e 100644
Binary files a/output_data/iana/tzdata and b/output_data/iana/tzdata differ
diff --git a/output_data/icu_overlay/metaZones.res b/output_data/icu_overlay/metaZones.res
index b225f75..5bc0e42 100644
Binary files a/output_data/icu_overlay/metaZones.res and b/output_data/icu_overlay/metaZones.res differ
diff --git a/output_data/icu_overlay/timezoneTypes.res b/output_data/icu_overlay/timezoneTypes.res
index 5023ea2..b71388a 100644
Binary files a/output_data/icu_overlay/timezoneTypes.res and b/output_data/icu_overlay/timezoneTypes.res differ
diff --git a/output_data/icu_overlay/windowsZones.res b/output_data/icu_overlay/windowsZones.res
index 02197f7..0b9f4b6 100644
Binary files a/output_data/icu_overlay/windowsZones.res and b/output_data/icu_overlay/windowsZones.res differ
diff --git a/output_data/icu_overlay/zoneinfo64.res b/output_data/icu_overlay/zoneinfo64.res
index 3d809cf..d72c3d6 100644
Binary files a/output_data/icu_overlay/zoneinfo64.res and b/output_data/icu_overlay/zoneinfo64.res differ
diff --git a/output_data/version/tz_version b/output_data/version/tz_version
index 183987b..050bda8 100644
--- a/output_data/version/tz_version
+++ b/output_data/version/tz_version
@@ -1 +1 @@
-009.001|2025a|001
\ No newline at end of file
+009.001|2025b|001
\ No newline at end of file
diff --git a/output_data/versioned/8/version/tz_version b/output_data/versioned/8/version/tz_version
index aa9aca1..ec83ff5 100644
--- a/output_data/versioned/8/version/tz_version
+++ b/output_data/versioned/8/version/tz_version
@@ -1 +1 @@
-008.001|2025a|001
+008.001|2025b|001
diff --git a/testing/data/test1/output_data/android/telephonylookup.xml b/testing/data/test1/output_data/android/telephonylookup.xml
index 6582955..341b861 100644
--- a/testing/data/test1/output_data/android/telephonylookup.xml
+++ b/testing/data/test1/output_data/android/telephonylookup.xml
@@ -7,6 +7,11 @@
   <network mcc="310" mnc="370" country="gu"/>
   <network mcc="310" mnc="470" country="gu"/>
   <network mcc="311" mnc="780" country="as"/>
+  <network mcc="234" mnc="55" country="je"/>
+  <network mcc="234" mnc="50" country="je"/>
+  <network mcc="234" mnc="03" country="je"/>
+  <network mcc="234" mnc="58" country="im"/>
+  <network mcc="234" mnc="36" country="im"/>
  </networks>
  <mobile_countries>
   <mobile_country mcc="202">
diff --git a/testing/data/test1/output_data/android/tzlookup.xml b/testing/data/test1/output_data/android/tzlookup.xml
index 8610778..30a661c 100644
--- a/testing/data/test1/output_data/android/tzlookup.xml
+++ b/testing/data/test1/output_data/android/tzlookup.xml
@@ -206,7 +206,7 @@
    <id>Pacific/Rarotonga</id>
   </country>
   <country code="cl" default="America/Santiago" everutc="n">
-   <id>America/Punta_Arenas</id>
+   <id alts="America/Coyhaique">America/Punta_Arenas</id>
    <id alts="Chile/Continental">America/Santiago</id>
    <id alts="Chile/EasterIsland">Pacific/Easter</id>
   </country>
@@ -434,7 +434,7 @@
   <country code="kh" default="Asia/Phnom_Penh" everutc="n">
    <id>Asia/Phnom_Penh</id>
   </country>
-  <country code="ki" default="Pacific/Tarawa" everutc="n">
+  <country code="ki" default="Pacific/Tarawa" defaultBoost="y" everutc="n">
    <id>Pacific/Kiritimati</id>
    <id alts="Pacific/Enderbury">Pacific/Kanton</id>
    <id>Pacific/Tarawa</id>
@@ -628,7 +628,7 @@
   <country code="pe" default="America/Lima" everutc="n">
    <id>America/Lima</id>
   </country>
-  <country code="pf" default="Pacific/Tahiti" everutc="n">
+  <country code="pf" default="Pacific/Tahiti" defaultBoost="y" everutc="n">
    <id>Pacific/Gambier</id>
    <id>Pacific/Marquesas</id>
    <id>Pacific/Tahiti</id>
diff --git a/testing/data/test1/output_data/iana/tzdata b/testing/data/test1/output_data/iana/tzdata
index 6909eb9..dc986ec 100644
Binary files a/testing/data/test1/output_data/iana/tzdata and b/testing/data/test1/output_data/iana/tzdata differ
diff --git a/testing/data/test1/output_data/icu_overlay/metaZones.res b/testing/data/test1/output_data/icu_overlay/metaZones.res
index b225f75..5bc0e42 100644
Binary files a/testing/data/test1/output_data/icu_overlay/metaZones.res and b/testing/data/test1/output_data/icu_overlay/metaZones.res differ
diff --git a/testing/data/test1/output_data/icu_overlay/timezoneTypes.res b/testing/data/test1/output_data/icu_overlay/timezoneTypes.res
index 5023ea2..b71388a 100644
Binary files a/testing/data/test1/output_data/icu_overlay/timezoneTypes.res and b/testing/data/test1/output_data/icu_overlay/timezoneTypes.res differ
diff --git a/testing/data/test1/output_data/icu_overlay/windowsZones.res b/testing/data/test1/output_data/icu_overlay/windowsZones.res
index 02197f7..0b9f4b6 100644
Binary files a/testing/data/test1/output_data/icu_overlay/windowsZones.res and b/testing/data/test1/output_data/icu_overlay/windowsZones.res differ
diff --git a/testing/data/test1/output_data/icu_overlay/zoneinfo64.res b/testing/data/test1/output_data/icu_overlay/zoneinfo64.res
index fdffb07..69e0ed1 100644
Binary files a/testing/data/test1/output_data/icu_overlay/zoneinfo64.res and b/testing/data/test1/output_data/icu_overlay/zoneinfo64.res differ
diff --git a/testing/data/test3/output_data/android/telephonylookup.xml b/testing/data/test3/output_data/android/telephonylookup.xml
index 6582955..341b861 100644
--- a/testing/data/test3/output_data/android/telephonylookup.xml
+++ b/testing/data/test3/output_data/android/telephonylookup.xml
@@ -7,6 +7,11 @@
   <network mcc="310" mnc="370" country="gu"/>
   <network mcc="310" mnc="470" country="gu"/>
   <network mcc="311" mnc="780" country="as"/>
+  <network mcc="234" mnc="55" country="je"/>
+  <network mcc="234" mnc="50" country="je"/>
+  <network mcc="234" mnc="03" country="je"/>
+  <network mcc="234" mnc="58" country="im"/>
+  <network mcc="234" mnc="36" country="im"/>
  </networks>
  <mobile_countries>
   <mobile_country mcc="202">
diff --git a/testing/data/test3/output_data/android/tzlookup.xml b/testing/data/test3/output_data/android/tzlookup.xml
index 8610778..30a661c 100644
--- a/testing/data/test3/output_data/android/tzlookup.xml
+++ b/testing/data/test3/output_data/android/tzlookup.xml
@@ -206,7 +206,7 @@
    <id>Pacific/Rarotonga</id>
   </country>
   <country code="cl" default="America/Santiago" everutc="n">
-   <id>America/Punta_Arenas</id>
+   <id alts="America/Coyhaique">America/Punta_Arenas</id>
    <id alts="Chile/Continental">America/Santiago</id>
    <id alts="Chile/EasterIsland">Pacific/Easter</id>
   </country>
@@ -434,7 +434,7 @@
   <country code="kh" default="Asia/Phnom_Penh" everutc="n">
    <id>Asia/Phnom_Penh</id>
   </country>
-  <country code="ki" default="Pacific/Tarawa" everutc="n">
+  <country code="ki" default="Pacific/Tarawa" defaultBoost="y" everutc="n">
    <id>Pacific/Kiritimati</id>
    <id alts="Pacific/Enderbury">Pacific/Kanton</id>
    <id>Pacific/Tarawa</id>
@@ -628,7 +628,7 @@
   <country code="pe" default="America/Lima" everutc="n">
    <id>America/Lima</id>
   </country>
-  <country code="pf" default="Pacific/Tahiti" everutc="n">
+  <country code="pf" default="Pacific/Tahiti" defaultBoost="y" everutc="n">
    <id>Pacific/Gambier</id>
    <id>Pacific/Marquesas</id>
    <id>Pacific/Tahiti</id>
diff --git a/testing/data/test3/output_data/iana/tzdata b/testing/data/test3/output_data/iana/tzdata
index 6909eb9..dc986ec 100644
Binary files a/testing/data/test3/output_data/iana/tzdata and b/testing/data/test3/output_data/iana/tzdata differ
diff --git a/testing/data/test3/output_data/icu_overlay/metaZones.res b/testing/data/test3/output_data/icu_overlay/metaZones.res
index c4e9a78..59ca1f7 100644
Binary files a/testing/data/test3/output_data/icu_overlay/metaZones.res and b/testing/data/test3/output_data/icu_overlay/metaZones.res differ
diff --git a/testing/data/test3/output_data/icu_overlay/timezoneTypes.res b/testing/data/test3/output_data/icu_overlay/timezoneTypes.res
index c6ba2cf..9a7f781 100644
Binary files a/testing/data/test3/output_data/icu_overlay/timezoneTypes.res and b/testing/data/test3/output_data/icu_overlay/timezoneTypes.res differ
diff --git a/testing/data/test3/output_data/icu_overlay/windowsZones.res b/testing/data/test3/output_data/icu_overlay/windowsZones.res
index fb242db..9369587 100644
Binary files a/testing/data/test3/output_data/icu_overlay/windowsZones.res and b/testing/data/test3/output_data/icu_overlay/windowsZones.res differ
diff --git a/testing/data/test3/output_data/icu_overlay/zoneinfo64.res b/testing/data/test3/output_data/icu_overlay/zoneinfo64.res
index f504759..7ff6020 100644
Binary files a/testing/data/test3/output_data/icu_overlay/zoneinfo64.res and b/testing/data/test3/output_data/icu_overlay/zoneinfo64.res differ
```

