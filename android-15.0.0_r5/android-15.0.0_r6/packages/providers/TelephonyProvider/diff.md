```diff
diff --git a/Android.bp b/Android.bp
index 95b25796..7a1fca2e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -13,6 +13,23 @@ android_app {
     libs: ["telephony-common"],
     static_libs: ["android-common", "telephonyprovider-protos"],
     generate_product_characteristics_rro: true,
+    manifest: "AndroidManifest.xml",
+}
+
+android_app {
+    name: "TelephonyProviderHsum",
+    privileged: true,
+    srcs: ["src/**/*.java", "proto/**/*.proto"],
+    asset_dirs: ["assets/latest_carrier_id"],
+    platform_apis: true,
+    certificate: "platform",
+    libs: ["telephony-common"],
+    static_libs: ["android-common", "telephonyprovider-protos"],
+    generate_product_characteristics_rro: true,
+    overrides: ["TelephonyProvider"],
+
+    manifest: "AndroidManifestHsum.xml",
+    additional_manifests: [ "AndroidManifest.xml" ],
 }
 
 filegroup {
diff --git a/AndroidManifestHsum.xml b/AndroidManifestHsum.xml
new file mode 100644
index 00000000..18bd19c6
--- /dev/null
+++ b/AndroidManifestHsum.xml
@@ -0,0 +1,44 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+        package="com.android.providers.telephony"
+        coreApp="true"
+        android:sharedUserId="android.uid.phone"
+        xmlns:tools="http://schemas.android.com/tools">
+
+    <application>
+
+        <!-- Special for Headless System User Mode (HSUM): This is a non-singleton provider;
+             each user has their own instance and their own db. -->
+        <provider android:name="SmsProvider"
+                  android:singleUser="false"
+                  tools:replace="android:singleUser" />
+
+        <!-- Special for Headless System User Mode (HSUM): This is a non-singleton provider;
+             each user has their own instance and their own db. -->
+        <provider android:name="MmsProvider"
+                  android:singleUser="false"
+                  tools:replace="android:singleUser" />
+
+        <!-- Special for Headless System User Mode (HSUM): This is a non-singleton provider;
+             each user has their own instance and their own db. -->
+        <provider android:name="MmsSmsProvider"
+                  android:singleUser="false"
+                  tools:replace="android:singleUser" />
+
+    </application>
+</manifest>
diff --git a/assets/latest_carrier_id/carrier_list.pb b/assets/latest_carrier_id/carrier_list.pb
index d4e32c66..9b2500a5 100644
Binary files a/assets/latest_carrier_id/carrier_list.pb and b/assets/latest_carrier_id/carrier_list.pb differ
diff --git a/assets/latest_carrier_id/carrier_list.textpb b/assets/latest_carrier_id/carrier_list.textpb
index 747d2acc..b14127b1 100644
--- a/assets/latest_carrier_id/carrier_list.textpb
+++ b/assets/latest_carrier_id/carrier_list.textpb
@@ -425,6 +425,7 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "21405"
     mccmnc_tuple: "21407"
+    mccmnc_tuple: "21438"
   }
 }
 carrier_id {
@@ -499,7 +500,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 493
-  carrier_name: "Setar GSM"
+  carrier_name: "SETAR"
   carrier_attribute {
     mccmnc_tuple: "36301"
   }
@@ -4378,10 +4379,9 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1619
-  carrier_name: "Vodafone"
+  carrier_name: "Epic"
   carrier_attribute {
     mccmnc_tuple: "27801"
-    spn: "vodafone MT"
   }
 }
 carrier_id {
@@ -5034,7 +5034,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1712
-  carrier_name: "Tusmobil d.o.o."
+  carrier_name: "Telemach"
   carrier_attribute {
     mccmnc_tuple: "29370"
   }
@@ -7319,9 +7319,10 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2007
-  carrier_name: "Telenor Myanmar"
+  carrier_name: "ATOM"
   carrier_attribute {
     mccmnc_tuple: "41406"
+    spn: "ATOM"
   }
 }
 carrier_id {
@@ -9765,14 +9766,6 @@ carrier_id {
     spn: "EMnify"
   }
 }
-carrier_id {
-  canonical_id: 2327
-  carrier_name: "Telemach"
-  carrier_attribute {
-    mccmnc_tuple: "29370"
-    imsi_prefix_xpattern: "29370029"
-  }
-}
 carrier_id {
   canonical_id: 2328
   carrier_name: "Fonic Prepaid"
@@ -10033,13 +10026,6 @@ carrier_id {
     mccmnc_tuple: "26002"
   }
 }
-carrier_id {
-  canonical_id: 2368
-  carrier_name: "Vodafone"
-  carrier_attribute {
-    mccmnc_tuple: "27801"
-  }
-}
 carrier_id {
   canonical_id: 2369
   carrier_name: "Orange"
@@ -10296,7 +10282,6 @@ carrier_id {
   carrier_name: "TalkMobile"
   carrier_attribute {
     mccmnc_tuple: "23415"
-    spn: ""
     spn: "Talkmobile"
     gid1: "C1"
   }
@@ -11153,6 +11138,14 @@ carrier_id {
     mccmnc_tuple: "24006"
     spn: "Telavox"
   }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    gid1: "0E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    spn: "Telavox"
+  }
 }
 carrier_id {
   canonical_id: 2525
@@ -11565,7 +11558,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2570
-  carrier_name: "Netcom Group"
+  carrier_name: "Netcom O"
   carrier_attribute {
     mccmnc_tuple: "20801"
     spn: "Netcom Mobile"
@@ -12059,10 +12052,13 @@ carrier_id {
   carrier_name: "Webbing"
   carrier_attribute {
     mccmnc_tuple: "20801"
+    mccmnc_tuple: "22201"
     mccmnc_tuple: "23410"
     mccmnc_tuple: "42402"
     mccmnc_tuple: "45400"
+    mccmnc_tuple: "45412"
     mccmnc_tuple: "45435"
+    mccmnc_tuple: "72432"
     mccmnc_tuple: "72454"
     mccmnc_tuple: "90101"
     mccmnc_tuple: "90131"
@@ -12165,6 +12161,58 @@ carrier_id {
     gid1: "BA01500000000000"
   }
 }
+carrier_id {
+  canonical_id: 2642
+  carrier_name: "Netcom Group"
+  carrier_attribute {
+    mccmnc_tuple: "20804"
+  }
+}
+carrier_id {
+  canonical_id: 2643
+  carrier_name: "Cablenet"
+  carrier_attribute {
+    mccmnc_tuple: "28022"
+  }
+}
+carrier_id {
+  canonical_id: 2644
+  carrier_name: "IMOWI"
+  carrier_attribute {
+    mccmnc_tuple: "722210"
+    spn: "imowi"
+    gid1: "722210"
+  }
+}
+carrier_id {
+  canonical_id: 2645
+  carrier_name: "ASDA GB"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A0"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A1"
+  }
+}
+carrier_id {
+  canonical_id: 2646
+  carrier_name: "Rcell"
+  carrier_attribute {
+    mccmnc_tuple: "41750"
+  }
+}
+carrier_id {
+  canonical_id: 2647
+  carrier_name: "Field Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "50549"
+    spn: "Field Mobile"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -12572,4 +12620,4 @@ carrier_id {
   }
   parent_canonical_id: 1779
 }
-version: 134217766
+version: 134217768
diff --git a/assets/sdk28_carrier_id/carrier_list.pb b/assets/sdk28_carrier_id/carrier_list.pb
index 416eb625..4b526f19 100644
Binary files a/assets/sdk28_carrier_id/carrier_list.pb and b/assets/sdk28_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk28_carrier_id/carrier_list.textpb b/assets/sdk28_carrier_id/carrier_list.textpb
index 192f26e5..326a3efa 100644
--- a/assets/sdk28_carrier_id/carrier_list.textpb
+++ b/assets/sdk28_carrier_id/carrier_list.textpb
@@ -743,6 +743,9 @@ carrier_id {
     mccmnc_tuple: "21405"
     mccmnc_tuple: "21407"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21438"
+  }
 }
 carrier_id {
   canonical_id: 450
@@ -816,7 +819,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 493
-  carrier_name: "Setar GSM"
+  carrier_name: "SETAR"
   carrier_attribute {
     mccmnc_tuple: "36301"
   }
@@ -4871,7 +4874,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1619
-  carrier_name: "Vodafone"
+  carrier_name: "Epic"
   carrier_attribute {
     mccmnc_tuple: "27801"
   }
@@ -5571,7 +5574,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1712
-  carrier_name: "Tusmobil d.o.o."
+  carrier_name: "Telemach"
   carrier_attribute {
     mccmnc_tuple: "29370"
   }
@@ -8016,7 +8019,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2007
-  carrier_name: "Telenor Myanmar"
+  carrier_name: "ATOM"
   carrier_attribute {
     mccmnc_tuple: "41406"
   }
@@ -12105,6 +12108,14 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "24050"
   }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    gid1: "0E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    spn: "Telavox"
+  }
 }
 carrier_id {
   canonical_id: 2525
@@ -13220,6 +13231,14 @@ carrier_id {
     mccmnc_tuple: "90161"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "45412"
+    gid1: "536E617065"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "72432"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -13308,6 +13327,58 @@ carrier_id {
     gid1: "BA01500000000000"
   }
 }
+carrier_id {
+  canonical_id: 2642
+  carrier_name: "Netcom Group"
+  carrier_attribute {
+    mccmnc_tuple: "20804"
+  }
+}
+carrier_id {
+  canonical_id: 2643
+  carrier_name: "Cablenet"
+  carrier_attribute {
+    mccmnc_tuple: "28022"
+  }
+}
+carrier_id {
+  canonical_id: 2644
+  carrier_name: "IMOWI"
+  carrier_attribute {
+    mccmnc_tuple: "722210"
+    spn: "imowi"
+    gid1: "722210"
+  }
+}
+carrier_id {
+  canonical_id: 2645
+  carrier_name: "ASDA GB"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A0"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A1"
+  }
+}
+carrier_id {
+  canonical_id: 2646
+  carrier_name: "Rcell"
+  carrier_attribute {
+    mccmnc_tuple: "41750"
+  }
+}
+carrier_id {
+  canonical_id: 2647
+  carrier_name: "Field Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "50549"
+    spn: "Field Mobile"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -13550,4 +13621,4 @@ carrier_id {
   }
   parent_canonical_id: 2023
 }
-version: 46
+version: 48
diff --git a/assets/sdk29_carrier_id/carrier_list.pb b/assets/sdk29_carrier_id/carrier_list.pb
index 19d7e331..521b0eef 100644
Binary files a/assets/sdk29_carrier_id/carrier_list.pb and b/assets/sdk29_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk29_carrier_id/carrier_list.textpb b/assets/sdk29_carrier_id/carrier_list.textpb
index 94a2b489..9173b00b 100644
--- a/assets/sdk29_carrier_id/carrier_list.textpb
+++ b/assets/sdk29_carrier_id/carrier_list.textpb
@@ -731,6 +731,9 @@ carrier_id {
     mccmnc_tuple: "21405"
     mccmnc_tuple: "21407"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21438"
+  }
 }
 carrier_id {
   canonical_id: 450
@@ -804,7 +807,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 493
-  carrier_name: "Setar GSM"
+  carrier_name: "SETAR"
   carrier_attribute {
     mccmnc_tuple: "36301"
   }
@@ -4719,7 +4722,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1619
-  carrier_name: "Vodafone"
+  carrier_name: "Epic"
   carrier_attribute {
     mccmnc_tuple: "27801"
     spn: "vodafone MT"
@@ -5410,7 +5413,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1712
-  carrier_name: "Tusmobil d.o.o."
+  carrier_name: "Telemach"
   carrier_attribute {
     mccmnc_tuple: "29370"
   }
@@ -7749,7 +7752,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2007
-  carrier_name: "Telenor Myanmar"
+  carrier_name: "ATOM"
   carrier_attribute {
     mccmnc_tuple: "41406"
   }
@@ -11937,6 +11940,14 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "24050"
   }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    gid1: "0E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    spn: "Telavox"
+  }
 }
 carrier_id {
   canonical_id: 2525
@@ -13130,6 +13141,14 @@ carrier_id {
     mccmnc_tuple: "90161"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "45412"
+    gid1: "536E617065"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "72432"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -13214,6 +13233,58 @@ carrier_id {
     gid1: "BA01500000000000"
   }
 }
+carrier_id {
+  canonical_id: 2642
+  carrier_name: "Netcom Group"
+  carrier_attribute {
+    mccmnc_tuple: "20804"
+  }
+}
+carrier_id {
+  canonical_id: 2643
+  carrier_name: "Cablenet"
+  carrier_attribute {
+    mccmnc_tuple: "28022"
+  }
+}
+carrier_id {
+  canonical_id: 2644
+  carrier_name: "IMOWI"
+  carrier_attribute {
+    mccmnc_tuple: "722210"
+    spn: "imowi"
+    gid1: "722210"
+  }
+}
+carrier_id {
+  canonical_id: 2645
+  carrier_name: "ASDA GB"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A0"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A1"
+  }
+}
+carrier_id {
+  canonical_id: 2646
+  carrier_name: "Rcell"
+  carrier_attribute {
+    mccmnc_tuple: "41750"
+  }
+}
+carrier_id {
+  canonical_id: 2647
+  carrier_name: "Field Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "50549"
+    spn: "Field Mobile"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -13455,4 +13526,4 @@ carrier_id {
   }
   parent_canonical_id: 2023
 }
-version: 16777270
+version: 16777272
diff --git a/assets/sdk30_carrier_id/carrier_list.pb b/assets/sdk30_carrier_id/carrier_list.pb
index 4af370d0..512dff2f 100644
Binary files a/assets/sdk30_carrier_id/carrier_list.pb and b/assets/sdk30_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk30_carrier_id/carrier_list.textpb b/assets/sdk30_carrier_id/carrier_list.textpb
index 8bde8aba..2a84e88c 100644
--- a/assets/sdk30_carrier_id/carrier_list.textpb
+++ b/assets/sdk30_carrier_id/carrier_list.textpb
@@ -731,6 +731,9 @@ carrier_id {
     mccmnc_tuple: "21405"
     mccmnc_tuple: "21407"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21438"
+  }
 }
 carrier_id {
   canonical_id: 450
@@ -804,7 +807,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 493
-  carrier_name: "Setar GSM"
+  carrier_name: "SETAR"
   carrier_attribute {
     mccmnc_tuple: "36301"
   }
@@ -4716,7 +4719,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1619
-  carrier_name: "Vodafone"
+  carrier_name: "Epic"
   carrier_attribute {
     mccmnc_tuple: "27801"
     spn: "vodafone MT"
@@ -5408,7 +5411,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1712
-  carrier_name: "Tusmobil d.o.o."
+  carrier_name: "Telemach"
   carrier_attribute {
     mccmnc_tuple: "29370"
   }
@@ -7744,7 +7747,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2007
-  carrier_name: "Telenor Myanmar"
+  carrier_name: "ATOM"
   carrier_attribute {
     mccmnc_tuple: "41406"
   }
@@ -11915,6 +11918,14 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "24050"
   }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    gid1: "0E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    spn: "Telavox"
+  }
 }
 carrier_id {
   canonical_id: 2525
@@ -13112,6 +13123,14 @@ carrier_id {
     mccmnc_tuple: "90161"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "45412"
+    gid1: "536E617065"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "72432"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -13196,6 +13215,58 @@ carrier_id {
     gid1: "BA01500000000000"
   }
 }
+carrier_id {
+  canonical_id: 2642
+  carrier_name: "Netcom Group"
+  carrier_attribute {
+    mccmnc_tuple: "20804"
+  }
+}
+carrier_id {
+  canonical_id: 2643
+  carrier_name: "Cablenet"
+  carrier_attribute {
+    mccmnc_tuple: "28022"
+  }
+}
+carrier_id {
+  canonical_id: 2644
+  carrier_name: "IMOWI"
+  carrier_attribute {
+    mccmnc_tuple: "722210"
+    spn: "imowi"
+    gid1: "722210"
+  }
+}
+carrier_id {
+  canonical_id: 2645
+  carrier_name: "ASDA GB"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A0"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A1"
+  }
+}
+carrier_id {
+  canonical_id: 2646
+  carrier_name: "Rcell"
+  carrier_attribute {
+    mccmnc_tuple: "41750"
+  }
+}
+carrier_id {
+  canonical_id: 2647
+  carrier_name: "Field Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "50549"
+    spn: "Field Mobile"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -13457,4 +13528,4 @@ carrier_id {
   }
   parent_canonical_id: 2023
 }
-version: 33554504
+version: 33554506
diff --git a/assets/sdk31_carrier_id/carrier_list.pb b/assets/sdk31_carrier_id/carrier_list.pb
index bf5314a0..f4220a59 100644
Binary files a/assets/sdk31_carrier_id/carrier_list.pb and b/assets/sdk31_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk31_carrier_id/carrier_list.textpb b/assets/sdk31_carrier_id/carrier_list.textpb
index e8e037d2..71fdab6d 100644
--- a/assets/sdk31_carrier_id/carrier_list.textpb
+++ b/assets/sdk31_carrier_id/carrier_list.textpb
@@ -501,6 +501,9 @@ carrier_id {
     mccmnc_tuple: "21405"
     mccmnc_tuple: "21407"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21438"
+  }
 }
 carrier_id {
   canonical_id: 450
@@ -574,7 +577,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 493
-  carrier_name: "Setar GSM"
+  carrier_name: "SETAR"
   carrier_attribute {
     mccmnc_tuple: "36301"
   }
@@ -4453,7 +4456,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1619
-  carrier_name: "Vodafone"
+  carrier_name: "Epic"
   carrier_attribute {
     mccmnc_tuple: "27801"
     spn: "vodafone MT"
@@ -5145,7 +5148,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1712
-  carrier_name: "Tusmobil d.o.o."
+  carrier_name: "Telemach"
   carrier_attribute {
     mccmnc_tuple: "29370"
   }
@@ -7465,7 +7468,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2007
-  carrier_name: "Telenor Myanmar"
+  carrier_name: "ATOM"
   carrier_attribute {
     mccmnc_tuple: "41406"
   }
@@ -11603,6 +11606,14 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "24050"
   }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    gid1: "0E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    spn: "Telavox"
+  }
 }
 carrier_id {
   canonical_id: 2525
@@ -12815,6 +12826,14 @@ carrier_id {
     mccmnc_tuple: "90161"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "45412"
+    gid1: "536E617065"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "72432"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -12923,6 +12942,58 @@ carrier_id {
     gid1: "BA01500000000000"
   }
 }
+carrier_id {
+  canonical_id: 2642
+  carrier_name: "Netcom Group"
+  carrier_attribute {
+    mccmnc_tuple: "20804"
+  }
+}
+carrier_id {
+  canonical_id: 2643
+  carrier_name: "Cablenet"
+  carrier_attribute {
+    mccmnc_tuple: "28022"
+  }
+}
+carrier_id {
+  canonical_id: 2644
+  carrier_name: "IMOWI"
+  carrier_attribute {
+    mccmnc_tuple: "722210"
+    spn: "imowi"
+    gid1: "722210"
+  }
+}
+carrier_id {
+  canonical_id: 2645
+  carrier_name: "ASDA GB"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A0"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A1"
+  }
+}
+carrier_id {
+  canonical_id: 2646
+  carrier_name: "Rcell"
+  carrier_attribute {
+    mccmnc_tuple: "41750"
+  }
+}
+carrier_id {
+  canonical_id: 2647
+  carrier_name: "Field Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "50549"
+    spn: "Field Mobile"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -13224,4 +13295,4 @@ carrier_id {
   }
   parent_canonical_id: 1894
 }
-version: 50331696
+version: 50331698
diff --git a/assets/sdk33_carrier_id/carrier_list.pb b/assets/sdk33_carrier_id/carrier_list.pb
index fad92d58..a223e2f4 100644
Binary files a/assets/sdk33_carrier_id/carrier_list.pb and b/assets/sdk33_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk33_carrier_id/carrier_list.textpb b/assets/sdk33_carrier_id/carrier_list.textpb
index 2424bcc2..1ea05b9c 100644
--- a/assets/sdk33_carrier_id/carrier_list.textpb
+++ b/assets/sdk33_carrier_id/carrier_list.textpb
@@ -445,6 +445,9 @@ carrier_id {
     mccmnc_tuple: "21405"
     mccmnc_tuple: "21407"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21438"
+  }
 }
 carrier_id {
   canonical_id: 450
@@ -518,7 +521,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 493
-  carrier_name: "Setar GSM"
+  carrier_name: "SETAR"
   carrier_attribute {
     mccmnc_tuple: "36301"
   }
@@ -4408,7 +4411,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1619
-  carrier_name: "Vodafone"
+  carrier_name: "Epic"
   carrier_attribute {
     mccmnc_tuple: "27801"
     spn: "vodafone MT"
@@ -5087,7 +5090,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1712
-  carrier_name: "Tusmobil d.o.o."
+  carrier_name: "Telemach"
   carrier_attribute {
     mccmnc_tuple: "29370"
   }
@@ -7372,7 +7375,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2007
-  carrier_name: "Telenor Myanmar"
+  carrier_name: "ATOM"
   carrier_attribute {
     mccmnc_tuple: "41406"
   }
@@ -11332,6 +11335,14 @@ carrier_id {
     mccmnc_tuple: "24006"
     spn: "Telavox"
   }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    gid1: "0E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    spn: "Telavox"
+  }
 }
 carrier_id {
   canonical_id: 2525
@@ -12563,6 +12574,14 @@ carrier_id {
     mccmnc_tuple: "90161"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "45412"
+    gid1: "536E617065"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "72432"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -12671,6 +12690,58 @@ carrier_id {
     gid1: "BA01500000000000"
   }
 }
+carrier_id {
+  canonical_id: 2642
+  carrier_name: "Netcom Group"
+  carrier_attribute {
+    mccmnc_tuple: "20804"
+  }
+}
+carrier_id {
+  canonical_id: 2643
+  carrier_name: "Cablenet"
+  carrier_attribute {
+    mccmnc_tuple: "28022"
+  }
+}
+carrier_id {
+  canonical_id: 2644
+  carrier_name: "IMOWI"
+  carrier_attribute {
+    mccmnc_tuple: "722210"
+    spn: "imowi"
+    gid1: "722210"
+  }
+}
+carrier_id {
+  canonical_id: 2645
+  carrier_name: "ASDA GB"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A0"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A1"
+  }
+}
+carrier_id {
+  canonical_id: 2646
+  carrier_name: "Rcell"
+  carrier_attribute {
+    mccmnc_tuple: "41750"
+  }
+}
+carrier_id {
+  canonical_id: 2647
+  carrier_name: "Field Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "50549"
+    spn: "Field Mobile"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -13047,4 +13118,4 @@ carrier_id {
   }
   parent_canonical_id: 2560
 }
-version: 100663334
+version: 100663336
diff --git a/assets/sdk34_carrier_id/carrier_list.pb b/assets/sdk34_carrier_id/carrier_list.pb
index 6fde599c..8fd4240a 100644
Binary files a/assets/sdk34_carrier_id/carrier_list.pb and b/assets/sdk34_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk34_carrier_id/carrier_list.textpb b/assets/sdk34_carrier_id/carrier_list.textpb
index b33bbd04..292aeedb 100644
--- a/assets/sdk34_carrier_id/carrier_list.textpb
+++ b/assets/sdk34_carrier_id/carrier_list.textpb
@@ -423,6 +423,9 @@ carrier_id {
     mccmnc_tuple: "21405"
     mccmnc_tuple: "21407"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21438"
+  }
 }
 carrier_id {
   canonical_id: 450
@@ -496,7 +499,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 493
-  carrier_name: "Setar GSM"
+  carrier_name: "SETAR"
   carrier_attribute {
     mccmnc_tuple: "36301"
   }
@@ -4379,7 +4382,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1619
-  carrier_name: "Vodafone"
+  carrier_name: "Epic"
   carrier_attribute {
     mccmnc_tuple: "27801"
     spn: "vodafone MT"
@@ -5035,7 +5038,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1712
-  carrier_name: "Tusmobil d.o.o."
+  carrier_name: "Telemach"
   carrier_attribute {
     mccmnc_tuple: "29370"
   }
@@ -7320,7 +7323,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2007
-  carrier_name: "Telenor Myanmar"
+  carrier_name: "ATOM"
   carrier_attribute {
     mccmnc_tuple: "41406"
   }
@@ -11174,6 +11177,14 @@ carrier_id {
     mccmnc_tuple: "24006"
     spn: "Telavox"
   }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    gid1: "0E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "20614"
+    spn: "Telavox"
+  }
 }
 carrier_id {
   canonical_id: 2525
@@ -11586,7 +11597,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2570
-  carrier_name: "Netcom Group"
+  carrier_name: "Netcom O"
   carrier_attribute {
     mccmnc_tuple: "20801"
     spn: "Netcom Mobile"
@@ -12095,6 +12106,14 @@ carrier_id {
     mccmnc_tuple: "90161"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "45412"
+    gid1: "536E617065"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "72432"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -12195,6 +12214,58 @@ carrier_id {
     mccmnc_tuple: "27225"
   }
 }
+carrier_id {
+  canonical_id: 2642
+  carrier_name: "Netcom Group"
+  carrier_attribute {
+    mccmnc_tuple: "20804"
+  }
+}
+carrier_id {
+  canonical_id: 2643
+  carrier_name: "Cablenet"
+  carrier_attribute {
+    mccmnc_tuple: "28022"
+  }
+}
+carrier_id {
+  canonical_id: 2644
+  carrier_name: "IMOWI"
+  carrier_attribute {
+    mccmnc_tuple: "722210"
+    spn: "imowi"
+    gid1: "722210"
+  }
+}
+carrier_id {
+  canonical_id: 2645
+  carrier_name: "ASDA GB"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A0"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "ASDA Mobile"
+    gid1: "A1"
+  }
+}
+carrier_id {
+  canonical_id: 2646
+  carrier_name: "Rcell"
+  carrier_attribute {
+    mccmnc_tuple: "41750"
+  }
+}
+carrier_id {
+  canonical_id: 2647
+  carrier_name: "Field Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "50549"
+    spn: "Field Mobile"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -12602,4 +12673,4 @@ carrier_id {
   }
   parent_canonical_id: 1779
 }
-version: 117440550
+version: 117440552
diff --git a/src/com/android/providers/telephony/ProviderUtil.java b/src/com/android/providers/telephony/ProviderUtil.java
index 247d2402..4efe3fbb 100644
--- a/src/com/android/providers/telephony/ProviderUtil.java
+++ b/src/com/android/providers/telephony/ProviderUtil.java
@@ -51,7 +51,6 @@ import java.util.stream.Collectors;
 public class ProviderUtil {
     private final static String TAG = "SmsProvider";
     private static final String TELEPHONY_PROVIDER_PACKAGE = "com.android.providers.telephony";
-    private static final int PHONE_UID = 1001;
 
     /**
      * Check if a caller of the provider has restricted access,
@@ -63,8 +62,7 @@ public class ProviderUtil {
      * @return true if the caller is not system, or phone or default sms app, false otherwise
      */
     public static boolean isAccessRestricted(Context context, String packageName, int uid) {
-        return (uid != Process.SYSTEM_UID
-                && uid != Process.PHONE_UID
+        return (!TelephonyPermissions.isSystemOrPhone(uid)
                 && !SmsApplication.isDefaultSmsApplication(context, packageName));
     }
 
@@ -76,9 +74,9 @@ public class ProviderUtil {
      * @return true if we should set CREATOR, false otherwise
      */
     public static boolean shouldSetCreator(ContentValues values, int uid) {
-        return (uid != Process.SYSTEM_UID && uid != Process.PHONE_UID) ||
-                (!values.containsKey(Telephony.Sms.CREATOR) &&
-                        !values.containsKey(Telephony.Mms.CREATOR));
+        return (!TelephonyPermissions.isSystemOrPhone(uid))
+                || (!values.containsKey(Telephony.Sms.CREATOR)
+                        && !values.containsKey(Telephony.Mms.CREATOR));
     }
 
     /**
@@ -89,9 +87,9 @@ public class ProviderUtil {
      * @return true if we should remove CREATOR, false otherwise
      */
     public static boolean shouldRemoveCreator(ContentValues values, int uid) {
-        return (uid != Process.SYSTEM_UID && uid != Process.PHONE_UID) &&
-                (values.containsKey(Telephony.Sms.CREATOR) ||
-                        values.containsKey(Telephony.Mms.CREATOR));
+        return (!TelephonyPermissions.isSystemOrPhone(uid))
+                && (values.containsKey(Telephony.Sms.CREATOR)
+                        || values.containsKey(Telephony.Mms.CREATOR));
     }
 
     /**
@@ -294,7 +292,7 @@ public class ProviderUtil {
         StringBuilder sb = new StringBuilder();
         for (ActivityManager.RunningAppProcessInfo processInfo : processInfos) {
             if (Arrays.asList(processInfo.pkgList).contains(TELEPHONY_PROVIDER_PACKAGE)
-                    || processInfo.uid == PHONE_UID) {
+                    || UserHandle.isSameApp(processInfo.uid, Process.PHONE_UID)) {
                 sb.append("{ProcessName=");
                 sb.append(processInfo.processName);
                 sb.append(";PID=");
diff --git a/src/com/android/providers/telephony/SmsProvider.java b/src/com/android/providers/telephony/SmsProvider.java
index 14a74be2..eabff64d 100644
--- a/src/com/android/providers/telephony/SmsProvider.java
+++ b/src/com/android/providers/telephony/SmsProvider.java
@@ -987,8 +987,10 @@ public class SmsProvider extends ContentProvider {
             // Filter SMS based on subId and emergency numbers.
             selectionBySubIds = ProviderUtil.getSelectionBySubIds(getContext(),
                     callerUserHandle);
-            selectionByEmergencyNumbers = ProviderUtil
-                    .getSelectionByEmergencyNumbers(getContext());
+            if (hasCalling()) {
+                selectionByEmergencyNumbers = ProviderUtil
+                        .getSelectionByEmergencyNumbers(getContext());
+            }
         } finally {
             Binder.restoreCallingIdentity(token);
         }
diff --git a/src/com/android/providers/telephony/TelephonyBackupAgent.java b/src/com/android/providers/telephony/TelephonyBackupAgent.java
index 2f142382..385f3634 100644
--- a/src/com/android/providers/telephony/TelephonyBackupAgent.java
+++ b/src/com/android/providers/telephony/TelephonyBackupAgent.java
@@ -392,6 +392,7 @@ public class TelephonyBackupAgent extends BackupAgent {
         if (subscriptionManager != null) {
             final List<SubscriptionInfo> subInfo =
                     subscriptionManager.getCompleteActiveSubscriptionInfoList();
+            Log.d(TAG, "onCreate: completeActiveSubInfo count=" + subInfo.size());
             if (subInfo != null) {
                 for (SubscriptionInfo sub : subInfo) {
                     final String phoneNumber = getNormalizedNumber(sub);
@@ -441,6 +442,7 @@ public class TelephonyBackupAgent extends BackupAgent {
 
     @Override
     public void onFullBackup(FullBackupDataOutput data) throws IOException {
+        Log.d(TAG, "onFullBackup()");
         SharedPreferences sharedPreferences = getSharedPreferences(BACKUP_PREFS, MODE_PRIVATE);
         if (sharedPreferences.getLong(QUOTA_RESET_TIME, Long.MAX_VALUE) <
                 System.currentTimeMillis()) {
@@ -539,7 +541,9 @@ public class TelephonyBackupAgent extends BackupAgent {
 
     private void backupAll(FullBackupDataOutput data, Cursor cursor, String fileName)
             throws IOException {
+        Log.d(TAG, "backupAll()");
         if (cursor == null || cursor.isAfterLast()) {
+            Log.d(TAG, "backupAll(): cursor is null return");
             return;
         }
 
@@ -550,10 +554,13 @@ public class TelephonyBackupAgent extends BackupAgent {
             if (fileName.endsWith(SMS_BACKUP_FILE_SUFFIX)) {
                 chunk = putSmsMessagesToJson(cursor, jsonWriter);
                 mSmsCount = chunk.count;
+                Log.d(TAG, "backupAll: Wrote SMS messages to Json. mSmsCount=" + mSmsCount);
             } else {
                 chunk = putMmsMessagesToJson(cursor, jsonWriter);
                 mMmsCount = chunk.count;
+                Log.d(TAG, "backupAll: Wrote MMS messages to Json. mMmsCount=" + mMmsCount);
             }
+
         }
         backupFile(chunk, fileName, data);
     }
@@ -774,6 +781,7 @@ public class TelephonyBackupAgent extends BackupAgent {
         int msgCount = 0;
         int numExceptions = 0;
         final int bulkInsertSize = mMaxMsgPerFile;
+        Log.d(TAG, "putSmsMessagesToProvider: bulkInsertSize=" + bulkInsertSize);
         ContentValues[] values = new ContentValues[bulkInsertSize];
         while (jsonReader.hasNext()) {
             ContentValues cv = readSmsValuesFromReader(jsonReader);
@@ -784,6 +792,7 @@ public class TelephonyBackupAgent extends BackupAgent {
                 values[(msgCount++) % bulkInsertSize] = cv;
                 if (msgCount % bulkInsertSize == 0) {
                     mContentResolver.bulkInsert(Telephony.Sms.CONTENT_URI, values);
+                    Log.d(TAG, "putSmsMessagesToProvider: msgCount:" + msgCount);
                 }
             } catch (RuntimeException e) {
                 Log.e(TAG, "putSmsMessagesToProvider", e);
@@ -794,6 +803,7 @@ public class TelephonyBackupAgent extends BackupAgent {
         if (msgCount % bulkInsertSize > 0) {
             mContentResolver.bulkInsert(Telephony.Sms.CONTENT_URI,
                     Arrays.copyOf(values, msgCount % bulkInsertSize));
+            Log.d(TAG, "putSmsMessagesToProvider: msgCount:" + msgCount);
         }
         jsonReader.endArray();
         incremenentSharedPref(true, msgCount, numExceptions);
diff --git a/src/com/android/providers/telephony/TelephonyProvider.java b/src/com/android/providers/telephony/TelephonyProvider.java
index c3150f58..b350ba10 100644
--- a/src/com/android/providers/telephony/TelephonyProvider.java
+++ b/src/com/android/providers/telephony/TelephonyProvider.java
@@ -128,6 +128,7 @@ import android.util.Xml;
 
 import com.android.internal.annotations.GuardedBy;
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.internal.telephony.TelephonyPermissions;
 import com.android.internal.telephony.TelephonyStatsLog;
 import com.android.internal.telephony.flags.Flags;
 import com.android.internal.util.XmlUtils;
@@ -165,7 +166,7 @@ public class TelephonyProvider extends ContentProvider
     private static final boolean DBG = true;
     private static final boolean VDBG = false; // STOPSHIP if true
 
-    private static final int DATABASE_VERSION = 71 << 16;
+    private static final int DATABASE_VERSION = 73 << 16;
     private static final int URL_UNKNOWN = 0;
     private static final int URL_TELEPHONY = 1;
     private static final int URL_CURRENT = 2;
@@ -473,7 +474,7 @@ public class TelephonyProvider extends ContentProvider
                 Telephony.SimInfo.COLUMN_SATELLITE_ATTACH_ENABLED_FOR_CARRIER,
                 Cursor.FIELD_TYPE_INTEGER);
         SIM_INFO_COLUMNS_TO_BACKUP.put(
-                Telephony.SimInfo.COLUMN_IS_NTN, Cursor.FIELD_TYPE_INTEGER);
+                Telephony.SimInfo.COLUMN_IS_ONLY_NTN, Cursor.FIELD_TYPE_INTEGER);
         SIM_INFO_COLUMNS_TO_BACKUP.put(
                 Telephony.SimInfo.COLUMN_TRANSFER_STATUS, Cursor.FIELD_TYPE_INTEGER);
         SIM_INFO_COLUMNS_TO_BACKUP.put(
@@ -484,6 +485,11 @@ public class TelephonyProvider extends ContentProvider
         SIM_INFO_COLUMNS_TO_BACKUP.put(
                 Telephony.SimInfo.COLUMN_ALLOWED_NETWORK_TYPES_FOR_REASONS,
                 Cursor.FIELD_TYPE_STRING);
+        SIM_INFO_COLUMNS_TO_BACKUP.put(
+                Telephony.SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED, Cursor.FIELD_TYPE_INTEGER);
+        SIM_INFO_COLUMNS_TO_BACKUP.put(
+                Telephony.SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM,
+                Cursor.FIELD_TYPE_INTEGER);
     }
 
     @VisibleForTesting
@@ -629,12 +635,15 @@ public class TelephonyProvider extends ContentProvider
                 + Telephony.SimInfo.COLUMN_SATELLITE_ENABLED + " INTEGER DEFAULT 0,"
                 + Telephony.SimInfo.COLUMN_SATELLITE_ATTACH_ENABLED_FOR_CARRIER
                 + " INTEGER DEFAULT 1, "
-                + Telephony.SimInfo.COLUMN_IS_NTN + " INTEGER DEFAULT 0, "
+                + Telephony.SimInfo.COLUMN_IS_ONLY_NTN + " INTEGER DEFAULT 0, "
                 + Telephony.SimInfo.COLUMN_SERVICE_CAPABILITIES + " INTEGER DEFAULT "
                 + SubscriptionManager.getAllServiceCapabilityBitmasks() + ","
                 + Telephony.SimInfo.COLUMN_TRANSFER_STATUS + " INTEGER DEFAULT 0,"
                 + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_STATUS + " INTEGER DEFAULT 0,"
-                + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS + " TEXT"
+                + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS + " TEXT,"
+                + Telephony.SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED + " INTEGER DEFAULT 0,"
+                + Telephony.SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM
+                + " INTEGER DEFAULT 0"
                 + ");";
     }
 
@@ -1987,7 +1996,7 @@ public class TelephonyProvider extends ContentProvider
 
                     // Try to update the siminfo table with new columns.
                     db.execSQL("ALTER TABLE " + SIMINFO_TABLE + " ADD COLUMN "
-                            + Telephony.SimInfo.COLUMN_IS_NTN
+                            + Telephony.SimInfo.COLUMN_IS_ONLY_NTN
                             + "  INTEGER DEFAULT 0;");
                 } catch (SQLiteException e) {
                     if (DBG) {
@@ -2106,6 +2115,48 @@ public class TelephonyProvider extends ContentProvider
                 oldVersion = 71 << 16 | 6;
             }
 
+            if (oldVersion < (72 << 16 | 6)) {
+                try {
+                    // Try to update the siminfo table with new columns.
+                    db.execSQL("ALTER TABLE " + SIMINFO_TABLE + " ADD COLUMN "
+                            + Telephony.SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED
+                            + " INTEGER DEFAULT 0;");
+                    db.execSQL("ALTER TABLE " + SIMINFO_TABLE + " ADD COLUMN "
+                            + Telephony.SimInfo.COLUMN_IS_ONLY_NTN + " INTEGER DEFAULT 0;");
+
+                    // Copy the value of the previous column (COLUMN_IS_NTN) to the new column
+                    // (COLUMN_IS_ONLY_NTN) for all rows in the sim_info table.
+                    final String columnIsNtn = "is_ntn";
+                    db.execSQL("UPDATE " + SIMINFO_TABLE + " SET "
+                            + Telephony.SimInfo.COLUMN_IS_ONLY_NTN + " = " + columnIsNtn + ";");
+
+                    // ALTER TABLE siminfo DROP is_ntn;
+                    db.execSQL(
+                            "ALTER TABLE " + SIMINFO_TABLE + " DROP COLUMN " + columnIsNtn + ";");
+                } catch (SQLiteException e) {
+                    if (DBG) {
+                        log("onUpgrade failed to update " + SIMINFO_TABLE
+                                + " to add is satellite esos supported");
+                    }
+                }
+                oldVersion = 72 << 16 | 6;
+            }
+
+            if (oldVersion < (73 << 16 | 6)) {
+                try {
+                    // Try to update the siminfo table with new columns.
+                    db.execSQL("ALTER TABLE " + SIMINFO_TABLE + " ADD COLUMN "
+                            + Telephony.SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM
+                            + "  INTEGER DEFAULT 0;");
+                } catch (SQLiteException e) {
+                    if (DBG) {
+                        log("onUpgrade failed to update " + SIMINFO_TABLE
+                                + " to add satellite is provisioned");
+                    }
+                }
+                oldVersion = 73 << 16 | 6;
+            }
+
             if (DBG) {
                 log("dbh.onUpgrade:- db=" + db + " oldV=" + oldVersion + " newV=" + newVersion);
             }
@@ -3572,9 +3623,9 @@ public class TelephonyProvider extends ContentProvider
 
     boolean isCallingFromSystemOrPhoneUid() {
         int callingUid = mInjector.binderGetCallingUid();
-        return callingUid == Process.SYSTEM_UID || callingUid == Process.PHONE_UID
+        return TelephonyPermissions.isSystemOrPhone(callingUid)
                 // Allow ROOT for testing. ROOT can access underlying DB files anyways.
-                || callingUid == Process.ROOT_UID;
+                || UserHandle.isSameApp(callingUid, Process.ROOT_UID);
     }
 
     void ensureCallingFromSystemOrPhoneUid(String message) {
@@ -3988,7 +4039,7 @@ public class TelephonyProvider extends ContentProvider
                 PersistableBundle backedUpSimInfoEntry, int backupDataFormatVersion,
                 String isoCountryCodeFromDb, String allowedNetworkTypesForReasonsFromDb,
                 List<String> wfcRestoreBlockedCountries) {
-            if (DATABASE_VERSION != 71 << 16) {
+            if (DATABASE_VERSION != 73 << 16) {
                 throw new AssertionError("The database schema has been updated which might make "
                     + "the format of #BACKED_UP_SIM_SPECIFIC_SETTINGS_FILE outdated. Make sure to "
                     + "1) review whether any of the columns in #SIM_INFO_COLUMNS_TO_BACKUP have "
@@ -4030,6 +4081,20 @@ public class TelephonyProvider extends ContentProvider
              * Also make sure to add necessary removal of sensitive settings in
              * polishContentValues(ContentValues contentValues).
              */
+            if (backupDataFormatVersion >= 73 << 16) {
+                contentValues.put(
+                        Telephony.SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM,
+                        backedUpSimInfoEntry.getInt(
+                                Telephony.SimInfo
+                                        .COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM,
+                                DEFAULT_INT_COLUMN_VALUE));
+            }
+            if (backupDataFormatVersion >= 72 << 16) {
+                contentValues.put(Telephony.SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED,
+                        backedUpSimInfoEntry.getInt(
+                                Telephony.SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED,
+                                DEFAULT_INT_COLUMN_VALUE));
+            }
             if (backupDataFormatVersion >= 71 << 16) {
                 contentValues.put(Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_STATUS,
                         backedUpSimInfoEntry.getInt(
@@ -4054,8 +4119,8 @@ public class TelephonyProvider extends ContentProvider
                                 DEFAULT_INT_COLUMN_VALUE));
             }
             if (backupDataFormatVersion >= 64 << 16) {
-                contentValues.put(Telephony.SimInfo.COLUMN_IS_NTN,
-                        backedUpSimInfoEntry.getInt(Telephony.SimInfo.COLUMN_IS_NTN,
+                contentValues.put(Telephony.SimInfo.COLUMN_IS_ONLY_NTN,
+                        backedUpSimInfoEntry.getInt(Telephony.SimInfo.COLUMN_IS_ONLY_NTN,
                                 DEFAULT_INT_COLUMN_VALUE));
             }
             if (backupDataFormatVersion >= 63 << 16) {
@@ -5458,6 +5523,10 @@ public class TelephonyProvider extends ContentProvider
         }
 
         PackageManager packageManager = getContext().getPackageManager();
+        if (Flags.hsumPackageManager()) {
+            packageManager = getContext().createContextAsUser(Binder.getCallingUserHandle(), 0)
+                    .getPackageManager();
+        }
         String[] packages = packageManager.getPackagesForUid(Binder.getCallingUid());
 
         TelephonyManager telephonyManager =
diff --git a/tests/Android.bp b/tests/Android.bp
index ff48ed84..6ce55718 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -15,10 +15,10 @@ android_test {
         "androidx.test.ext.junit",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "telephony-common",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
     srcs: [
         "src/**/*.java",
diff --git a/tests/src/com/android/providers/telephony/TelephonyDatabaseHelperTest.java b/tests/src/com/android/providers/telephony/TelephonyDatabaseHelperTest.java
index 1d0e3e89..6c7f2833 100644
--- a/tests/src/com/android/providers/telephony/TelephonyDatabaseHelperTest.java
+++ b/tests/src/com/android/providers/telephony/TelephonyDatabaseHelperTest.java
@@ -20,6 +20,7 @@ import static android.provider.Telephony.Carriers;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertTrue;
 
@@ -495,20 +496,83 @@ public final class TelephonyDatabaseHelperTest {
     }
 
     @Test
-    public void databaseHelperOnUpgrade_hasSatelliteIsNtnField() {
-        Log.d(TAG, "databaseHelperOnUpgrade_hasSatelliteIsNtnField");
-        // (5 << 16 | 6) is the first upgrade trigger in onUpgrade
+    public void databaseHelperOnUpgrade_hasIsNtn_updateToIsOnlyNtnField() {
+        Log.d(TAG, "databaseHelperOnUpgrade_hasIsNtn_updateToIsOnlyNtnField");
+
+        final String columnIsNtn = "is_ntn";
         SQLiteDatabase db = mInMemoryDbHelper.getWritableDatabase();
-        mHelper.onUpgrade(db, (4 << 16), TelephonyProvider.getVersion(mContext));
 
-        // the upgraded db must have
-        // Telephony.SimInfo.IS_NTN
-        Cursor cursor = db.query("siminfo", null, null, null, null, null, null);
-        String[] upgradedColumns = cursor.getColumnNames();
-        Log.d(TAG, "siminfo columns: " + Arrays.toString(upgradedColumns));
+        mHelper.onUpgrade(db, (4 << 16), 65);
+        // Add is_ntn column and drop the latest columns.
+        db.execSQL("ALTER TABLE siminfo ADD COLUMN " + columnIsNtn + " INTEGER DEFAULT 0;");
+        db.execSQL("ALTER TABLE siminfo DROP COLUMN "
+                + Telephony.SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED + ";");
+        db.execSQL("ALTER TABLE siminfo DROP COLUMN " + Telephony.SimInfo.COLUMN_IS_ONLY_NTN + ";");
+
+        // Insert is_ntn column values
+        ContentValues cv1 = new ContentValues();
+        cv1.put(Telephony.SimInfo.COLUMN_UNIQUE_KEY_SUBSCRIPTION_ID, 1);
+        cv1.put(Telephony.SimInfo.COLUMN_ICC_ID, "123");
+        cv1.put(Telephony.SimInfo.COLUMN_DISPLAY_NUMBER_FORMAT, 0);
+        cv1.put(Telephony.SimInfo.COLUMN_CARD_ID, "123");
+        cv1.put(columnIsNtn, "1");
+        db.insert("siminfo", null, cv1);
+        ContentValues cv2 = new ContentValues();
+        cv2.put(Telephony.SimInfo.COLUMN_UNIQUE_KEY_SUBSCRIPTION_ID, 2);
+        cv2.put(Telephony.SimInfo.COLUMN_ICC_ID, "456");
+        cv2.put(Telephony.SimInfo.COLUMN_DISPLAY_NUMBER_FORMAT, 0);
+        cv2.put(Telephony.SimInfo.COLUMN_CARD_ID, "456");
+        cv2.put(columnIsNtn, "0");
+        db.insert("simInfo", null, cv2);
+
+        // Verify is_ntn column is exists
+        Cursor cursor = db.query("siminfo", null, null, null,
+                null, null, null);
+        String[] columnNames = cursor.getColumnNames();
+        Log.d(TAG, "siminfo columns: " + Arrays.toString(columnNames));
+        assertTrue(Arrays.asList(columnNames).contains(columnIsNtn));
 
-        assertTrue(Arrays.asList(upgradedColumns).contains(
-                Telephony.SimInfo.COLUMN_IS_NTN));
+        final String[] testProjection = {columnIsNtn};
+        final int[] expectedValues = {1, 0};
+        cursor = db.query("simInfo", testProjection, null, null,
+                null, null, null);
+
+        // Verify is_ntn column's value
+        cursor.moveToFirst();
+        assertNotNull(cursor);
+        assertEquals(expectedValues.length, cursor.getCount());
+        for (int i = 0; i < expectedValues.length; i++) {
+            assertEquals(expectedValues[i], cursor.getInt(0));
+            if (!cursor.moveToNext()) {
+                break;
+            }
+        }
+
+        // Upgrade db from version 65 to version 72.
+        mHelper.onUpgrade(db, (65 << 16), 72);
+
+        // Verify after upgraded db must have Telephony.SimInfo.COLUMN_IS_ONLY_NTN column and not
+        // have is_ntn column.
+        cursor = db.query("simInfo", null, null, null,
+                null, null, null);
+        columnNames = cursor.getColumnNames();
+        Log.d(TAG, "siminfo columns: " + Arrays.toString(columnNames));
+        assertTrue(Arrays.asList(columnNames).contains(Telephony.SimInfo.COLUMN_IS_ONLY_NTN));
+        assertFalse(Arrays.asList(columnNames).contains(columnIsNtn));
+
+        // Verify values copy from is_ntn columns to Telephony.SimInfo.COLUMN_IS_ONLY_NTN columns.
+        final String[] testProjection2 = {Telephony.SimInfo.COLUMN_IS_ONLY_NTN};
+        cursor = db.query("simInfo", testProjection2, null, null,
+                null, null, null);
+        cursor.moveToFirst();
+        assertNotNull(cursor);
+        assertEquals(expectedValues.length, cursor.getCount());
+        for (int i = 0; i < expectedValues.length; i++) {
+            assertEquals(expectedValues[i], cursor.getInt(0));
+            if (!cursor.moveToNext()) {
+                break;
+            }
+        }
     }
 
     @Test
@@ -715,6 +779,39 @@ public final class TelephonyDatabaseHelperTest {
                 Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS));
     }
 
+    @Test
+    public void databaseHelperOnUpgrade_hasSatelliteESOSSupportedFields() {
+        Log.d(TAG, "databaseHelperOnUpgrade_hasSatelliteESOSSupportedFields");
+        // (5 << 16 | 6) is the first upgrade trigger in onUpgrade
+        SQLiteDatabase db = mInMemoryDbHelper.getWritableDatabase();
+        mHelper.onUpgrade(db, (4 << 16), TelephonyProvider.getVersion(mContext));
+
+        // the upgraded db must have Telephony.SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED
+        Cursor cursor = db.query("siminfo", null, null, null, null, null, null);
+        String[] upgradedColumns = cursor.getColumnNames();
+        Log.d(TAG, "siminfo columns: " + Arrays.toString(upgradedColumns));
+
+        assertTrue(Arrays.asList(upgradedColumns).contains(
+                Telephony.SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED));
+    }
+
+    @Test
+    public void databaseHelperOnUpgrade_hasIsSatelliteProvisionedField() {
+        Log.d(TAG, "databaseHelperOnUpgrade_hasIsSatelliteProvisionedField");
+        // (5 << 16 | 6) is the first upgrade trigger in onUpgrade
+        SQLiteDatabase db = mInMemoryDbHelper.getWritableDatabase();
+        mHelper.onUpgrade(db, (4 << 16), TelephonyProvider.getVersion(mContext));
+
+        // the upgraded db must have
+        // Telephony.SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM
+        Cursor cursor = db.query("siminfo", null, null, null, null, null, null);
+        String[] upgradedColumns = cursor.getColumnNames();
+        Log.d(TAG, "siminfo columns: " + Arrays.toString(upgradedColumns));
+
+        assertTrue(Arrays.asList(upgradedColumns).contains(
+                Telephony.SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM));
+    }
+
     /**
      * Helper for an in memory DB used to test the TelephonyProvider#DatabaseHelper.
      *
diff --git a/tests/src/com/android/providers/telephony/TelephonyProviderTest.java b/tests/src/com/android/providers/telephony/TelephonyProviderTest.java
index bfd85a98..4d1912af 100644
--- a/tests/src/com/android/providers/telephony/TelephonyProviderTest.java
+++ b/tests/src/com/android/providers/telephony/TelephonyProviderTest.java
@@ -256,7 +256,7 @@ public class TelephonyProviderTest {
         contentValues.put(Telephony.SimInfo.COLUMN_SATELLITE_ENABLED, arbitraryIntVal);
         contentValues.put(Telephony.SimInfo.COLUMN_SATELLITE_ATTACH_ENABLED_FOR_CARRIER,
                 arbitraryIntVal);
-        contentValues.put(SimInfo.COLUMN_IS_NTN, arbitraryIntVal);
+        contentValues.put(SimInfo.COLUMN_IS_ONLY_NTN, arbitraryIntVal);
         contentValues.put(SimInfo.COLUMN_SERVICE_CAPABILITIES, arbitraryIntVal);
         contentValues.put(SimInfo.COLUMN_TRANSFER_STATUS, arbitraryIntVal);
         contentValues.put(SimInfo.COLUMN_SATELLITE_ENTITLEMENT_STATUS, arbitraryIntVal);
@@ -264,7 +264,10 @@ public class TelephonyProviderTest {
         if (isoCountryCode != null) {
             contentValues.put(Telephony.SimInfo.COLUMN_ISO_COUNTRY_CODE, isoCountryCode);
         }
+        contentValues.put(SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED, arbitraryIntVal);
 
+        contentValues.put(SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM,
+                arbitraryIntVal);
         return contentValues;
     }
 
@@ -764,6 +767,8 @@ public class TelephonyProviderTest {
         final int insertTransferStatus = 1;
         final int insertSatelliteEntitlementStatus = 1;
         final String insertSatelliteEntitlementPlmns = "examplePlmns";
+        final int insertCarrierRoamingNtn = 1;
+        final int insertIsSatelliteProvisioned = 1;
         contentValues.put(SubscriptionManager.UNIQUE_KEY_SUBSCRIPTION_ID, insertSubId);
         contentValues.put(SubscriptionManager.DISPLAY_NAME, insertDisplayName);
         contentValues.put(SubscriptionManager.CARRIER_NAME, insertCarrierName);
@@ -775,13 +780,16 @@ public class TelephonyProviderTest {
         contentValues.put(SubscriptionManager.SATELLITE_ENABLED, insertSatelliteEnabled);
         contentValues.put(SubscriptionManager.SATELLITE_ATTACH_ENABLED_FOR_CARRIER,
                 insertSatelliteAttachEnabledForCarrier);
-        contentValues.put(SubscriptionManager.IS_NTN, insertSatelliteIsNtn);
+        contentValues.put(SubscriptionManager.IS_ONLY_NTN, insertSatelliteIsNtn);
         contentValues.put(SubscriptionManager.SERVICE_CAPABILITIES, insertCellularService);
         contentValues.put(SubscriptionManager.TRANSFER_STATUS, insertTransferStatus);
         contentValues.put(SubscriptionManager.SATELLITE_ENTITLEMENT_STATUS,
                 insertSatelliteEntitlementStatus);
         contentValues.put(SubscriptionManager.SATELLITE_ENTITLEMENT_PLMNS,
                 insertSatelliteEntitlementPlmns);
+        contentValues.put(SubscriptionManager.SATELLITE_ESOS_SUPPORTED, insertCarrierRoamingNtn);
+        contentValues.put(SubscriptionManager.IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM,
+                insertIsSatelliteProvisioned);
 
         Log.d(TAG, "testSimTable Inserting contentValues: " + contentValues);
         mContentResolver.insert(SimInfo.CONTENT_URI, contentValues);
@@ -797,11 +805,13 @@ public class TelephonyProviderTest {
             SubscriptionManager.USER_HANDLE,
             SubscriptionManager.SATELLITE_ENABLED,
             SubscriptionManager.SATELLITE_ATTACH_ENABLED_FOR_CARRIER,
-            SubscriptionManager.IS_NTN,
+            SubscriptionManager.IS_ONLY_NTN,
             SubscriptionManager.SERVICE_CAPABILITIES,
             SubscriptionManager.TRANSFER_STATUS,
             SubscriptionManager.SATELLITE_ENTITLEMENT_STATUS,
             SubscriptionManager.SATELLITE_ENTITLEMENT_PLMNS,
+            SubscriptionManager.SATELLITE_ESOS_SUPPORTED,
+            SubscriptionManager.IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM
         };
         final String selection = SubscriptionManager.DISPLAY_NAME + "=?";
         String[] selectionArgs = { insertDisplayName };
@@ -827,6 +837,8 @@ public class TelephonyProviderTest {
         final int resultTransferStatus = cursor.getInt(10);
         final int resultSatelliteEntitlementStatus = cursor.getInt(11);
         final String resultSatelliteEntitlementPlmns = cursor.getString(12);
+        final int resultCarrierRoamingNtn = cursor.getInt(13);
+        final int resultIsSatelliteProvisioned = cursor.getInt(14);
         assertEquals(insertSubId, resultSubId);
         assertEquals(insertCarrierName, resultCarrierName);
         assertEquals(insertCardId, resultCardId);
@@ -840,6 +852,8 @@ public class TelephonyProviderTest {
         assertEquals(insertTransferStatus, resultTransferStatus);
         assertEquals(insertSatelliteEntitlementStatus, resultSatelliteEntitlementStatus);
         assertEquals(insertSatelliteEntitlementPlmns, resultSatelliteEntitlementPlmns);
+        assertEquals(insertCarrierRoamingNtn, resultCarrierRoamingNtn);
+        assertEquals(insertIsSatelliteProvisioned, resultIsSatelliteProvisioned);
 
         // delete test content
         final String selectionToDelete = SubscriptionManager.DISPLAY_NAME + "=?";
@@ -907,7 +921,7 @@ public class TelephonyProviderTest {
                 getIntValueFromCursor(cursor,
                         Telephony.SimInfo.COLUMN_SATELLITE_ATTACH_ENABLED_FOR_CARRIER));
         assertEquals(ARBITRARY_SIMINFO_DB_TEST_INT_VALUE_1,
-                getIntValueFromCursor(cursor, SimInfo.COLUMN_IS_NTN));
+                getIntValueFromCursor(cursor, SimInfo.COLUMN_IS_ONLY_NTN));
         assertEquals(ARBITRARY_SIMINFO_DB_TEST_INT_VALUE_1,
                 getIntValueFromCursor(cursor, SimInfo.COLUMN_TRANSFER_STATUS));
         assertEquals(ARBITRARY_SIMINFO_DB_TEST_INT_VALUE_1,
@@ -916,6 +930,10 @@ public class TelephonyProviderTest {
         assertEquals(ARBITRARY_SIMINFO_DB_TEST_STRING_VALUE_1,
                 getStringValueFromCursor(cursor,
                         SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS));
+        assertEquals(ARBITRARY_SIMINFO_DB_TEST_INT_VALUE_1,
+                getIntValueFromCursor(cursor, SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED));
+        assertEquals(ARBITRARY_SIMINFO_DB_TEST_INT_VALUE_1, getIntValueFromCursor(cursor,
+                SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM));
         assertRestoredSubIdIsRemembered();
     }
 
```

