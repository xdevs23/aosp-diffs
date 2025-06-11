```diff
diff --git a/assets/latest_carrier_id/carrier_list.pb b/assets/latest_carrier_id/carrier_list.pb
index 344cfcd7..577108aa 100644
Binary files a/assets/latest_carrier_id/carrier_list.pb and b/assets/latest_carrier_id/carrier_list.pb differ
diff --git a/assets/latest_carrier_id/carrier_list.textpb b/assets/latest_carrier_id/carrier_list.textpb
index 7d8ed008..c34a40fc 100644
--- a/assets/latest_carrier_id/carrier_list.textpb
+++ b/assets/latest_carrier_id/carrier_list.textpb
@@ -21,7 +21,6 @@ carrier_id {
     mccmnc_tuple: "310660"
     mccmnc_tuple: "310800"
     mccmnc_tuple: "311490"
-    mccmnc_tuple: "311660"
     mccmnc_tuple: "311882"
     mccmnc_tuple: "312250"
   }
@@ -481,7 +480,7 @@ carrier_id {
   canonical_id: 457
   carrier_name: "APUA PCS"
   carrier_attribute {
-    mccmnc_tuple: "344030"
+    mccmnc_tuple: "34403"
   }
 }
 carrier_id {
@@ -928,18 +927,19 @@ carrier_id {
     spn: "LLAMAYA"
     spn: "Guuk"
     spn: "Cablemovil"
+    spn: "Tu Operador"
     spn: "Sweno"
     spn: "Lebara"
     spn: "Lycamobile"
-  }
-  carrier_attribute {
-    mccmnc_tuple: "21404"
-    imsi_prefix_xpattern: "2140423"
+    spn: "Euskaltel"
     spn: "EUSKALTEL"
+    spn: "RACCtel+"
     spn: "RACC"
+    spn: "R"
     spn: "mobilR"
     spn: "Virgin telco"
     spn: "telecable"
+    spn: "Populoos"
   }
 }
 carrier_id {
@@ -1508,7 +1508,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 905
-  carrier_name: "Moldcell GSM"
+  carrier_name: "Moldcell"
   carrier_attribute {
     mccmnc_tuple: "25902"
   }
@@ -1693,7 +1693,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1014
-  carrier_name: "Vip mobile d.o.o."
+  carrier_name: "A1 SRB"
   carrier_attribute {
     mccmnc_tuple: "22005"
   }
@@ -3279,19 +3279,17 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1453
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
-    mccmnc_tuple: "26205"
-    mccmnc_tuple: "26277"
   }
 }
 carrier_id {
   canonical_id: 1454
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
-    mccmnc_tuple: "26208"
+    mccmnc_tuple: "26211"
   }
 }
 carrier_id {
@@ -3301,13 +3299,6 @@ carrier_id {
     mccmnc_tuple: "26210"
   }
 }
-carrier_id {
-  canonical_id: 1456
-  carrier_name: "O2 (Germany) GmbH & Co. OHG"
-  carrier_attribute {
-    mccmnc_tuple: "26211"
-  }
-}
 carrier_id {
   canonical_id: 1457
   carrier_name: "Dolphin Telecom (Deutschland) GmbH"
@@ -3924,6 +3915,7 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "40434"
     mccmnc_tuple: "40438"
+    mccmnc_tuple: "40439"
     mccmnc_tuple: "40451"
     mccmnc_tuple: "40453"
     mccmnc_tuple: "40454"
@@ -3933,6 +3925,7 @@ carrier_id {
     mccmnc_tuple: "40459"
     mccmnc_tuple: "40462"
     mccmnc_tuple: "40464"
+    mccmnc_tuple: "40465"
     mccmnc_tuple: "40466"
     mccmnc_tuple: "40471"
     mccmnc_tuple: "40472"
@@ -5140,7 +5133,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1727
-  carrier_name: "Josa Babilon-T"
+  carrier_name: "Babilon-Mobile"
   carrier_attribute {
     mccmnc_tuple: "43604"
   }
@@ -6743,7 +6736,6 @@ carrier_id {
     mccmnc_tuple: "310200"
     mccmnc_tuple: "310160"
     mccmnc_tuple: "311490"
-    mccmnc_tuple: "311660"
     mccmnc_tuple: "311882"
     mccmnc_tuple: "312250"
     gid1: "6D38"
@@ -6995,13 +6987,9 @@ carrier_id {
 carrier_id {
   canonical_id: 1974
   carrier_name: "Jazztel"
-  carrier_attribute {
-    mccmnc_tuple: "21421"
-  }
   carrier_attribute {
     mccmnc_tuple: "21403"
     spn: "JAZZTEL"
-    spn: "Jazztel"
   }
 }
 carrier_id {
@@ -8377,10 +8365,6 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "23439"
   }
-  carrier_attribute {
-    mccmnc_tuple: "24007"
-    imsi_prefix_xpattern: "240075610"
-  }
 }
 carrier_id {
   canonical_id: 2138
@@ -8388,7 +8372,6 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "23410"
     mccmnc_tuple: "23439"
-    mccmnc_tuple: "24007"
     spn: "jump"
   }
   carrier_attribute {
@@ -8534,6 +8517,10 @@ carrier_id {
     mccmnc_tuple: "23426"
     spn: "Lycamobile"
   }
+  carrier_attribute {
+    mccmnc_tuple: "23430"
+    spn: "LycaMobile"
+  }
 }
 carrier_id {
   canonical_id: 2153
@@ -9967,7 +9954,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2360
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -9976,7 +9963,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2361
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -10404,7 +10391,6 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "310240"
     mccmnc_tuple: "311490"
-    mccmnc_tuple: "311660"
     mccmnc_tuple: "311882"
     mccmnc_tuple: "312250"
     gid1: "1A53"
@@ -10658,6 +10644,12 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "313460"
   }
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    mccmnc_tuple: "311588"
+    mccmnc_tuple: "302220"
+    gid1: "6624"
+  }
 }
 carrier_id {
   canonical_id: 2467
@@ -11261,6 +11253,10 @@ carrier_id {
     imsi_prefix_xpattern: "26203293x"
     imsi_prefix_xpattern: "26203330x"
   }
+  carrier_attribute {
+    mccmnc_tuple: "20801"
+    spn: "1&1"
+  }
 }
 carrier_id {
   canonical_id: 2537
@@ -11557,12 +11553,15 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2570
-  carrier_name: "Netcom O"
+  carrier_name: "Orange MVNOs"
   carrier_attribute {
     mccmnc_tuple: "20801"
     spn: "Netcom Mobile"
     spn: "Mobile O"
     spn: "YouPrice O"
+    spn: "SEWAN"
+    spn: "NORDNET"
+    spn: "NETWORTH"
   }
 }
 carrier_id {
@@ -12050,6 +12049,7 @@ carrier_id {
   canonical_id: 2631
   carrier_name: "Webbing"
   carrier_attribute {
+    mccmnc_tuple: "20404"
     mccmnc_tuple: "20801"
     mccmnc_tuple: "22201"
     mccmnc_tuple: "23410"
@@ -12057,7 +12057,7 @@ carrier_id {
     mccmnc_tuple: "45400"
     mccmnc_tuple: "45412"
     mccmnc_tuple: "45435"
-    mccmnc_tuple: "72432"
+    mccmnc_tuple: "72418"
     mccmnc_tuple: "72454"
     mccmnc_tuple: "90101"
     mccmnc_tuple: "90131"
@@ -12179,8 +12179,6 @@ carrier_id {
   carrier_name: "IMOWI"
   carrier_attribute {
     mccmnc_tuple: "722210"
-    spn: "imowi"
-    gid1: "722210"
   }
 }
 carrier_id {
@@ -12219,6 +12217,145 @@ carrier_id {
     mccmnc_tuple: "25097"
   }
 }
+carrier_id {
+  canonical_id: 2649
+  carrier_name: "Private FR"
+  carrier_attribute {
+    mccmnc_tuple: "208180"
+  }
+}
+carrier_id {
+  canonical_id: 2650
+  carrier_name: "T-Mobile - Private 5G"
+  carrier_attribute {
+    mccmnc_tuple: "311660"
+  }
+}
+carrier_id {
+  canonical_id: 2651
+  carrier_name: "KPN Lab"
+  carrier_attribute {
+    mccmnc_tuple: "20469"
+  }
+}
+carrier_id {
+  canonical_id: 2652
+  carrier_name: "OXIO"
+  carrier_attribute {
+    mccmnc_tuple: "314720"
+    mccmnc_tuple: "334170"
+  }
+}
+carrier_id {
+  canonical_id: 2653
+  carrier_name: "Cox MSO"
+  carrier_attribute {
+    mccmnc_tuple: "314420"
+  }
+}
+carrier_id {
+  canonical_id: 2654
+  carrier_name: "Mediacom Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "311480"
+    gid1: "BA01700000000000"
+    gid2: "C400000000000000"
+  }
+}
+carrier_id {
+  canonical_id: 2655
+  carrier_name: "Optimum"
+  carrier_attribute {
+    mccmnc_tuple: "310240"
+    spn: "Optimum"
+    gid1: "6784"
+  }
+}
+carrier_id {
+  canonical_id: 2656
+  carrier_name: "Mettel"
+  carrier_attribute {
+    mccmnc_tuple: "314610"
+    mccmnc_tuple: "20801"
+    mccmnc_tuple: "90101"
+    mccmnc_tuple: "206018"
+    mccmnc_tuple: "21407"
+    gid1: "8915518F"
+  }
+}
+carrier_id {
+  canonical_id: 2657
+  carrier_name: "CiFi"
+  carrier_attribute {
+    mccmnc_tuple: "50557"
+  }
+}
+carrier_id {
+  canonical_id: 2658
+  carrier_name: "Lycamobile"
+  carrier_attribute {
+    mccmnc_tuple: "23812"
+  }
+}
+carrier_id {
+  canonical_id: 2659
+  carrier_name: "Brisanet"
+  carrier_attribute {
+    mccmnc_tuple: "72477"
+  }
+}
+carrier_id {
+  canonical_id: 2660
+  carrier_name: "eSIM Go"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "eSIM Go"
+    gid1: "0033"
+  }
+}
+carrier_id {
+  canonical_id: 2661
+  carrier_name: "Finetwork"
+  carrier_attribute {
+    mccmnc_tuple: "21406"
+    spn: "Finetwork"
+  }
+}
+carrier_id {
+  canonical_id: 2662
+  carrier_name: "Oceus"
+  carrier_attribute {
+    mccmnc_tuple: "314360"
+    spn: "OceusNet"
+    gid1: "FFFF"
+  }
+}
+carrier_id {
+  canonical_id: 2663
+  carrier_name: "TextNow Wireless"
+  carrier_attribute {
+    mccmnc_tuple: "314730"
+  }
+}
+carrier_id {
+  canonical_id: 2664
+  carrier_name: "Popcorn"
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    mccmnc_tuple: "311588"
+    mccmnc_tuple: "302220"
+    gid1: "7911"
+  }
+}
+carrier_id {
+  canonical_id: 2665
+  carrier_name: "iWay"
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "ispmobile"
+    spn: "iWay"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -12626,4 +12763,4 @@ carrier_id {
   }
   parent_canonical_id: 1779
 }
-version: 134217769
+version: 134217771
diff --git a/assets/sdk28_carrier_id/carrier_list.pb b/assets/sdk28_carrier_id/carrier_list.pb
index c5ee573f..9a48e0db 100644
Binary files a/assets/sdk28_carrier_id/carrier_list.pb and b/assets/sdk28_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk28_carrier_id/carrier_list.textpb b/assets/sdk28_carrier_id/carrier_list.textpb
index 7e18290d..45d6a589 100644
--- a/assets/sdk28_carrier_id/carrier_list.textpb
+++ b/assets/sdk28_carrier_id/carrier_list.textpb
@@ -802,6 +802,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "344030"
   }
+  carrier_attribute {
+    mccmnc_tuple: "34403"
+  }
 }
 carrier_id {
   canonical_id: 491
@@ -1839,7 +1842,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 905
-  carrier_name: "Moldcell GSM"
+  carrier_name: "Moldcell"
   carrier_attribute {
     mccmnc_tuple: "25902"
   }
@@ -2033,7 +2036,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1014
-  carrier_name: "Vip mobile d.o.o."
+  carrier_name: "A1 SRB"
   carrier_attribute {
     mccmnc_tuple: "22005"
   }
@@ -3661,7 +3664,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1453
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     mccmnc_tuple: "26205"
@@ -3670,7 +3673,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1454
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     mccmnc_tuple: "26208"
@@ -4395,6 +4398,12 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "40479"
   }
+  carrier_attribute {
+    mccmnc_tuple: "40439"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "40465"
+  }
 }
 carrier_id {
   canonical_id: 1550
@@ -5679,7 +5688,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1727
-  carrier_name: "Josa Babilon-T"
+  carrier_name: "Babilon-Mobile"
   carrier_attribute {
     mccmnc_tuple: "43604"
   }
@@ -11006,7 +11015,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2360
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -11038,7 +11047,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2361
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -11640,6 +11649,14 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "313460"
   }
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "6624"
+  }
 }
 carrier_id {
   canonical_id: 2465
@@ -13238,6 +13255,10 @@ carrier_id {
     mccmnc_tuple: "72432"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "72418"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -13345,8 +13366,6 @@ carrier_id {
   carrier_name: "IMOWI"
   carrier_attribute {
     mccmnc_tuple: "722210"
-    spn: "imowi"
-    gid1: "722210"
   }
 }
 carrier_id {
@@ -13385,6 +13404,145 @@ carrier_id {
     mccmnc_tuple: "25097"
   }
 }
+carrier_id {
+  canonical_id: 2649
+  carrier_name: "Private FR"
+  carrier_attribute {
+    mccmnc_tuple: "208180"
+  }
+}
+carrier_id {
+  canonical_id: 2651
+  carrier_name: "KPN Lab"
+  carrier_attribute {
+    mccmnc_tuple: "20469"
+  }
+}
+carrier_id {
+  canonical_id: 2652
+  carrier_name: "OXIO"
+  carrier_attribute {
+    mccmnc_tuple: "314720"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "334170"
+  }
+}
+carrier_id {
+  canonical_id: 2653
+  carrier_name: "Cox MSO"
+  carrier_attribute {
+    mccmnc_tuple: "314420"
+  }
+}
+carrier_id {
+  canonical_id: 2654
+  carrier_name: "Mediacom Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "311480"
+    gid1: "BA01700000000000"
+    gid2: "C400000000000000"
+  }
+}
+carrier_id {
+  canonical_id: 2655
+  carrier_name: "Optimum"
+  carrier_attribute {
+    mccmnc_tuple: "310240"
+    spn: "Optimum"
+    gid1: "6784"
+  }
+}
+carrier_id {
+  canonical_id: 2656
+  carrier_name: "Mettel"
+  carrier_attribute {
+    mccmnc_tuple: "314610"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90101"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "20601"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "206018"
+    gid1: "8915518F"
+  }
+}
+carrier_id {
+  canonical_id: 2657
+  carrier_name: "CiFi"
+  carrier_attribute {
+    mccmnc_tuple: "50557"
+  }
+}
+carrier_id {
+  canonical_id: 2658
+  carrier_name: "Lycamobile"
+  carrier_attribute {
+    mccmnc_tuple: "23812"
+  }
+}
+carrier_id {
+  canonical_id: 2659
+  carrier_name: "Brisanet"
+  carrier_attribute {
+    mccmnc_tuple: "72477"
+  }
+}
+carrier_id {
+  canonical_id: 2660
+  carrier_name: "eSIM Go"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "eSIM Go"
+    gid1: "0033"
+  }
+}
+carrier_id {
+  canonical_id: 2662
+  carrier_name: "Oceus"
+  carrier_attribute {
+    mccmnc_tuple: "314360"
+    spn: "OceusNet"
+    gid1: "FFFF"
+  }
+}
+carrier_id {
+  canonical_id: 2663
+  carrier_name: "TextNow Wireless"
+  carrier_attribute {
+    mccmnc_tuple: "314730"
+  }
+}
+carrier_id {
+  canonical_id: 2664
+  carrier_name: "Popcorn"
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "7911"
+  }
+}
+carrier_id {
+  canonical_id: 2665
+  carrier_name: "iWay"
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "ispmobile"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "iWay"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -13627,4 +13785,4 @@ carrier_id {
   }
   parent_canonical_id: 2023
 }
-version: 49
+version: 51
diff --git a/assets/sdk29_carrier_id/carrier_list.pb b/assets/sdk29_carrier_id/carrier_list.pb
index 0df750ff..5332c9ca 100644
Binary files a/assets/sdk29_carrier_id/carrier_list.pb and b/assets/sdk29_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk29_carrier_id/carrier_list.textpb b/assets/sdk29_carrier_id/carrier_list.textpb
index 9dad2821..161c7422 100644
--- a/assets/sdk29_carrier_id/carrier_list.textpb
+++ b/assets/sdk29_carrier_id/carrier_list.textpb
@@ -790,6 +790,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "344030"
   }
+  carrier_attribute {
+    mccmnc_tuple: "34403"
+  }
 }
 carrier_id {
   canonical_id: 491
@@ -1801,7 +1804,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 905
-  carrier_name: "Moldcell GSM"
+  carrier_name: "Moldcell"
   carrier_attribute {
     mccmnc_tuple: "25902"
   }
@@ -1995,7 +1998,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1014
-  carrier_name: "Vip mobile d.o.o."
+  carrier_name: "A1 SRB"
   carrier_attribute {
     mccmnc_tuple: "22005"
   }
@@ -3611,7 +3614,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1453
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     mccmnc_tuple: "26205"
@@ -3620,7 +3623,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1454
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     mccmnc_tuple: "26208"
@@ -4281,6 +4284,12 @@ carrier_id {
     mccmnc_tuple: "40480"
     mccmnc_tuple: "40481"
   }
+  carrier_attribute {
+    mccmnc_tuple: "40439"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "40465"
+  }
 }
 carrier_id {
   canonical_id: 1550
@@ -5518,7 +5527,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1727
-  carrier_name: "Josa Babilon-T"
+  carrier_name: "Babilon-Mobile"
   carrier_attribute {
     mccmnc_tuple: "43604"
   }
@@ -10720,7 +10729,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2360
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -10749,7 +10758,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2361
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -11456,6 +11465,18 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "313460"
   }
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "6624"
+  }
 }
 carrier_id {
   canonical_id: 2465
@@ -13148,6 +13169,10 @@ carrier_id {
     mccmnc_tuple: "72432"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "72418"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -13251,8 +13276,6 @@ carrier_id {
   carrier_name: "IMOWI"
   carrier_attribute {
     mccmnc_tuple: "722210"
-    spn: "imowi"
-    gid1: "722210"
   }
 }
 carrier_id {
@@ -13291,6 +13314,145 @@ carrier_id {
     mccmnc_tuple: "25097"
   }
 }
+carrier_id {
+  canonical_id: 2649
+  carrier_name: "Private FR"
+  carrier_attribute {
+    mccmnc_tuple: "208180"
+  }
+}
+carrier_id {
+  canonical_id: 2651
+  carrier_name: "KPN Lab"
+  carrier_attribute {
+    mccmnc_tuple: "20469"
+  }
+}
+carrier_id {
+  canonical_id: 2652
+  carrier_name: "OXIO"
+  carrier_attribute {
+    mccmnc_tuple: "314720"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "334170"
+  }
+}
+carrier_id {
+  canonical_id: 2653
+  carrier_name: "Cox MSO"
+  carrier_attribute {
+    mccmnc_tuple: "314420"
+  }
+}
+carrier_id {
+  canonical_id: 2654
+  carrier_name: "Mediacom Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "311480"
+    gid1: "BA01700000000000"
+    gid2: "C400000000000000"
+  }
+}
+carrier_id {
+  canonical_id: 2655
+  carrier_name: "Optimum"
+  carrier_attribute {
+    mccmnc_tuple: "310240"
+    spn: "Optimum"
+    gid1: "6784"
+  }
+}
+carrier_id {
+  canonical_id: 2656
+  carrier_name: "Mettel"
+  carrier_attribute {
+    mccmnc_tuple: "314610"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90101"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "206018"
+    gid1: "8915518F"
+  }
+}
+carrier_id {
+  canonical_id: 2657
+  carrier_name: "CiFi"
+  carrier_attribute {
+    mccmnc_tuple: "50557"
+  }
+}
+carrier_id {
+  canonical_id: 2658
+  carrier_name: "Lycamobile"
+  carrier_attribute {
+    mccmnc_tuple: "23812"
+  }
+}
+carrier_id {
+  canonical_id: 2659
+  carrier_name: "Brisanet"
+  carrier_attribute {
+    mccmnc_tuple: "72477"
+  }
+}
+carrier_id {
+  canonical_id: 2660
+  carrier_name: "eSIM Go"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "eSIM Go"
+    gid1: "0033"
+  }
+}
+carrier_id {
+  canonical_id: 2662
+  carrier_name: "Oceus"
+  carrier_attribute {
+    mccmnc_tuple: "314360"
+    spn: "OceusNet"
+    gid1: "FFFF"
+  }
+}
+carrier_id {
+  canonical_id: 2663
+  carrier_name: "TextNow Wireless"
+  carrier_attribute {
+    mccmnc_tuple: "314730"
+  }
+}
+carrier_id {
+  canonical_id: 2664
+  carrier_name: "Popcorn"
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "7911"
+  }
+}
+carrier_id {
+  canonical_id: 2665
+  carrier_name: "iWay"
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "ispmobile"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "iWay"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -13532,4 +13694,4 @@ carrier_id {
   }
   parent_canonical_id: 2023
 }
-version: 16777273
+version: 16777275
diff --git a/assets/sdk30_carrier_id/carrier_list.pb b/assets/sdk30_carrier_id/carrier_list.pb
index 0207cd93..6c5a8107 100644
Binary files a/assets/sdk30_carrier_id/carrier_list.pb and b/assets/sdk30_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk30_carrier_id/carrier_list.textpb b/assets/sdk30_carrier_id/carrier_list.textpb
index e8ab920a..dca11e9e 100644
--- a/assets/sdk30_carrier_id/carrier_list.textpb
+++ b/assets/sdk30_carrier_id/carrier_list.textpb
@@ -790,6 +790,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "344030"
   }
+  carrier_attribute {
+    mccmnc_tuple: "34403"
+  }
 }
 carrier_id {
   canonical_id: 491
@@ -1812,7 +1815,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 905
-  carrier_name: "Moldcell GSM"
+  carrier_name: "Moldcell"
   carrier_attribute {
     mccmnc_tuple: "25902"
   }
@@ -2006,7 +2009,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1014
-  carrier_name: "Vip mobile d.o.o."
+  carrier_name: "A1 SRB"
   carrier_attribute {
     mccmnc_tuple: "22005"
   }
@@ -3612,7 +3615,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1453
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     mccmnc_tuple: "26205"
@@ -3621,7 +3624,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1454
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     mccmnc_tuple: "26208"
@@ -4282,6 +4285,12 @@ carrier_id {
     mccmnc_tuple: "40480"
     mccmnc_tuple: "40481"
   }
+  carrier_attribute {
+    mccmnc_tuple: "40439"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "40465"
+  }
 }
 carrier_id {
   canonical_id: 1550
@@ -5516,7 +5525,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1727
-  carrier_name: "Josa Babilon-T"
+  carrier_name: "Babilon-Mobile"
   carrier_attribute {
     mccmnc_tuple: "43604"
   }
@@ -10686,7 +10695,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2360
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -10695,7 +10704,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2361
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -11405,6 +11414,18 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "313460"
   }
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "6624"
+  }
 }
 carrier_id {
   canonical_id: 2465
@@ -13130,6 +13151,10 @@ carrier_id {
     mccmnc_tuple: "72432"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "72418"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -13233,8 +13258,6 @@ carrier_id {
   carrier_name: "IMOWI"
   carrier_attribute {
     mccmnc_tuple: "722210"
-    spn: "imowi"
-    gid1: "722210"
   }
 }
 carrier_id {
@@ -13273,6 +13296,145 @@ carrier_id {
     mccmnc_tuple: "25097"
   }
 }
+carrier_id {
+  canonical_id: 2649
+  carrier_name: "Private FR"
+  carrier_attribute {
+    mccmnc_tuple: "208180"
+  }
+}
+carrier_id {
+  canonical_id: 2651
+  carrier_name: "KPN Lab"
+  carrier_attribute {
+    mccmnc_tuple: "20469"
+  }
+}
+carrier_id {
+  canonical_id: 2652
+  carrier_name: "OXIO"
+  carrier_attribute {
+    mccmnc_tuple: "314720"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "334170"
+  }
+}
+carrier_id {
+  canonical_id: 2653
+  carrier_name: "Cox MSO"
+  carrier_attribute {
+    mccmnc_tuple: "314420"
+  }
+}
+carrier_id {
+  canonical_id: 2654
+  carrier_name: "Mediacom Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "311480"
+    gid1: "BA01700000000000"
+    gid2: "C400000000000000"
+  }
+}
+carrier_id {
+  canonical_id: 2655
+  carrier_name: "Optimum"
+  carrier_attribute {
+    mccmnc_tuple: "310240"
+    spn: "Optimum"
+    gid1: "6784"
+  }
+}
+carrier_id {
+  canonical_id: 2656
+  carrier_name: "Mettel"
+  carrier_attribute {
+    mccmnc_tuple: "314610"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90101"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "206018"
+    gid1: "8915518F"
+  }
+}
+carrier_id {
+  canonical_id: 2657
+  carrier_name: "CiFi"
+  carrier_attribute {
+    mccmnc_tuple: "50557"
+  }
+}
+carrier_id {
+  canonical_id: 2658
+  carrier_name: "Lycamobile"
+  carrier_attribute {
+    mccmnc_tuple: "23812"
+  }
+}
+carrier_id {
+  canonical_id: 2659
+  carrier_name: "Brisanet"
+  carrier_attribute {
+    mccmnc_tuple: "72477"
+  }
+}
+carrier_id {
+  canonical_id: 2660
+  carrier_name: "eSIM Go"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "eSIM Go"
+    gid1: "0033"
+  }
+}
+carrier_id {
+  canonical_id: 2662
+  carrier_name: "Oceus"
+  carrier_attribute {
+    mccmnc_tuple: "314360"
+    spn: "OceusNet"
+    gid1: "FFFF"
+  }
+}
+carrier_id {
+  canonical_id: 2663
+  carrier_name: "TextNow Wireless"
+  carrier_attribute {
+    mccmnc_tuple: "314730"
+  }
+}
+carrier_id {
+  canonical_id: 2664
+  carrier_name: "Popcorn"
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "7911"
+  }
+}
+carrier_id {
+  canonical_id: 2665
+  carrier_name: "iWay"
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "ispmobile"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "iWay"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -13534,4 +13696,4 @@ carrier_id {
   }
   parent_canonical_id: 2023
 }
-version: 33554507
+version: 33554509
diff --git a/assets/sdk31_carrier_id/carrier_list.pb b/assets/sdk31_carrier_id/carrier_list.pb
index e8587e4f..cd69e801 100644
Binary files a/assets/sdk31_carrier_id/carrier_list.pb and b/assets/sdk31_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk31_carrier_id/carrier_list.textpb b/assets/sdk31_carrier_id/carrier_list.textpb
index 5d69a904..f171d240 100644
--- a/assets/sdk31_carrier_id/carrier_list.textpb
+++ b/assets/sdk31_carrier_id/carrier_list.textpb
@@ -560,6 +560,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "344030"
   }
+  carrier_attribute {
+    mccmnc_tuple: "34403"
+  }
 }
 carrier_id {
   canonical_id: 491
@@ -1574,7 +1577,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 905
-  carrier_name: "Moldcell GSM"
+  carrier_name: "Moldcell"
   carrier_attribute {
     mccmnc_tuple: "25902"
   }
@@ -1759,7 +1762,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1014
-  carrier_name: "Vip mobile d.o.o."
+  carrier_name: "A1 SRB"
   carrier_attribute {
     mccmnc_tuple: "22005"
   }
@@ -3349,7 +3352,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1453
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     mccmnc_tuple: "26205"
@@ -3358,7 +3361,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1454
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     mccmnc_tuple: "26208"
@@ -4019,6 +4022,12 @@ carrier_id {
     mccmnc_tuple: "40480"
     mccmnc_tuple: "40481"
   }
+  carrier_attribute {
+    mccmnc_tuple: "40439"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "40465"
+  }
 }
 carrier_id {
   canonical_id: 1550
@@ -5253,7 +5262,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1727
-  carrier_name: "Josa Babilon-T"
+  carrier_name: "Babilon-Mobile"
   carrier_attribute {
     mccmnc_tuple: "43604"
   }
@@ -10386,7 +10395,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2360
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -10395,7 +10404,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2361
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -11092,6 +11101,18 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "313460"
   }
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "6624"
+  }
 }
 carrier_id {
   canonical_id: 2465
@@ -12833,6 +12854,10 @@ carrier_id {
     mccmnc_tuple: "72432"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "72418"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -12960,8 +12985,6 @@ carrier_id {
   carrier_name: "IMOWI"
   carrier_attribute {
     mccmnc_tuple: "722210"
-    spn: "imowi"
-    gid1: "722210"
   }
 }
 carrier_id {
@@ -13000,6 +13023,145 @@ carrier_id {
     mccmnc_tuple: "25097"
   }
 }
+carrier_id {
+  canonical_id: 2649
+  carrier_name: "Private FR"
+  carrier_attribute {
+    mccmnc_tuple: "208180"
+  }
+}
+carrier_id {
+  canonical_id: 2651
+  carrier_name: "KPN Lab"
+  carrier_attribute {
+    mccmnc_tuple: "20469"
+  }
+}
+carrier_id {
+  canonical_id: 2652
+  carrier_name: "OXIO"
+  carrier_attribute {
+    mccmnc_tuple: "314720"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "334170"
+  }
+}
+carrier_id {
+  canonical_id: 2653
+  carrier_name: "Cox MSO"
+  carrier_attribute {
+    mccmnc_tuple: "314420"
+  }
+}
+carrier_id {
+  canonical_id: 2654
+  carrier_name: "Mediacom Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "311480"
+    gid1: "BA01700000000000"
+    gid2: "C400000000000000"
+  }
+}
+carrier_id {
+  canonical_id: 2655
+  carrier_name: "Optimum"
+  carrier_attribute {
+    mccmnc_tuple: "310240"
+    spn: "Optimum"
+    gid1: "6784"
+  }
+}
+carrier_id {
+  canonical_id: 2656
+  carrier_name: "Mettel"
+  carrier_attribute {
+    mccmnc_tuple: "314610"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90101"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "206018"
+    gid1: "8915518F"
+  }
+}
+carrier_id {
+  canonical_id: 2657
+  carrier_name: "CiFi"
+  carrier_attribute {
+    mccmnc_tuple: "50557"
+  }
+}
+carrier_id {
+  canonical_id: 2658
+  carrier_name: "Lycamobile"
+  carrier_attribute {
+    mccmnc_tuple: "23812"
+  }
+}
+carrier_id {
+  canonical_id: 2659
+  carrier_name: "Brisanet"
+  carrier_attribute {
+    mccmnc_tuple: "72477"
+  }
+}
+carrier_id {
+  canonical_id: 2660
+  carrier_name: "eSIM Go"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "eSIM Go"
+    gid1: "0033"
+  }
+}
+carrier_id {
+  canonical_id: 2662
+  carrier_name: "Oceus"
+  carrier_attribute {
+    mccmnc_tuple: "314360"
+    spn: "OceusNet"
+    gid1: "FFFF"
+  }
+}
+carrier_id {
+  canonical_id: 2663
+  carrier_name: "TextNow Wireless"
+  carrier_attribute {
+    mccmnc_tuple: "314730"
+  }
+}
+carrier_id {
+  canonical_id: 2664
+  carrier_name: "Popcorn"
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "7911"
+  }
+}
+carrier_id {
+  canonical_id: 2665
+  carrier_name: "iWay"
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "ispmobile"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "iWay"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -13301,4 +13463,4 @@ carrier_id {
   }
   parent_canonical_id: 1894
 }
-version: 50331699
+version: 50331701
diff --git a/assets/sdk33_carrier_id/carrier_list.pb b/assets/sdk33_carrier_id/carrier_list.pb
index c0ef6c8a..b6f5bed4 100644
Binary files a/assets/sdk33_carrier_id/carrier_list.pb and b/assets/sdk33_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk33_carrier_id/carrier_list.textpb b/assets/sdk33_carrier_id/carrier_list.textpb
index 349055a2..d821ad1a 100644
--- a/assets/sdk33_carrier_id/carrier_list.textpb
+++ b/assets/sdk33_carrier_id/carrier_list.textpb
@@ -504,6 +504,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "344030"
   }
+  carrier_attribute {
+    mccmnc_tuple: "34403"
+  }
 }
 carrier_id {
   canonical_id: 491
@@ -1536,7 +1539,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 905
-  carrier_name: "Moldcell GSM"
+  carrier_name: "Moldcell"
   carrier_attribute {
     mccmnc_tuple: "25902"
   }
@@ -1721,7 +1724,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1014
-  carrier_name: "Vip mobile d.o.o."
+  carrier_name: "A1 SRB"
   carrier_attribute {
     mccmnc_tuple: "22005"
   }
@@ -3309,7 +3312,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1453
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     mccmnc_tuple: "26205"
@@ -3318,7 +3321,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1454
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     mccmnc_tuple: "26208"
@@ -3977,6 +3980,12 @@ carrier_id {
     mccmnc_tuple: "40480"
     mccmnc_tuple: "40481"
   }
+  carrier_attribute {
+    mccmnc_tuple: "40439"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "40465"
+  }
 }
 carrier_id {
   canonical_id: 1550
@@ -5196,7 +5205,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1727
-  carrier_name: "Josa Babilon-T"
+  carrier_name: "Babilon-Mobile"
   carrier_attribute {
     mccmnc_tuple: "43604"
   }
@@ -10114,7 +10123,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2360
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -10123,7 +10132,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2361
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -10820,6 +10829,18 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "313460"
   }
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "6624"
+  }
 }
 carrier_id {
   canonical_id: 2467
@@ -12581,6 +12602,10 @@ carrier_id {
     mccmnc_tuple: "72432"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "72418"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -12708,8 +12733,6 @@ carrier_id {
   carrier_name: "IMOWI"
   carrier_attribute {
     mccmnc_tuple: "722210"
-    spn: "imowi"
-    gid1: "722210"
   }
 }
 carrier_id {
@@ -12748,6 +12771,149 @@ carrier_id {
     mccmnc_tuple: "25097"
   }
 }
+carrier_id {
+  canonical_id: 2649
+  carrier_name: "Private FR"
+  carrier_attribute {
+    mccmnc_tuple: "208180"
+  }
+}
+carrier_id {
+  canonical_id: 2651
+  carrier_name: "KPN Lab"
+  carrier_attribute {
+    mccmnc_tuple: "20469"
+  }
+}
+carrier_id {
+  canonical_id: 2652
+  carrier_name: "OXIO"
+  carrier_attribute {
+    mccmnc_tuple: "314720"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "334170"
+  }
+}
+carrier_id {
+  canonical_id: 2653
+  carrier_name: "Cox MSO"
+  carrier_attribute {
+    mccmnc_tuple: "314420"
+  }
+}
+carrier_id {
+  canonical_id: 2654
+  carrier_name: "Mediacom Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "311480"
+    gid1: "BA01700000000000"
+    gid2: "C400000000000000"
+  }
+}
+carrier_id {
+  canonical_id: 2655
+  carrier_name: "Optimum"
+  carrier_attribute {
+    mccmnc_tuple: "310240"
+    spn: "Optimum"
+    gid1: "6784"
+  }
+}
+carrier_id {
+  canonical_id: 2656
+  carrier_name: "Mettel"
+  carrier_attribute {
+    mccmnc_tuple: "314610"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90101"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "21407"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "206018"
+    gid1: "8915518F"
+  }
+}
+carrier_id {
+  canonical_id: 2657
+  carrier_name: "CiFi"
+  carrier_attribute {
+    mccmnc_tuple: "50557"
+  }
+}
+carrier_id {
+  canonical_id: 2658
+  carrier_name: "Lycamobile"
+  carrier_attribute {
+    mccmnc_tuple: "23812"
+  }
+}
+carrier_id {
+  canonical_id: 2659
+  carrier_name: "Brisanet"
+  carrier_attribute {
+    mccmnc_tuple: "72477"
+  }
+}
+carrier_id {
+  canonical_id: 2660
+  carrier_name: "eSIM Go"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "eSIM Go"
+    gid1: "0033"
+  }
+}
+carrier_id {
+  canonical_id: 2662
+  carrier_name: "Oceus"
+  carrier_attribute {
+    mccmnc_tuple: "314360"
+    spn: "OceusNet"
+    gid1: "FFFF"
+  }
+}
+carrier_id {
+  canonical_id: 2663
+  carrier_name: "TextNow Wireless"
+  carrier_attribute {
+    mccmnc_tuple: "314730"
+  }
+}
+carrier_id {
+  canonical_id: 2664
+  carrier_name: "Popcorn"
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "7911"
+  }
+}
+carrier_id {
+  canonical_id: 2665
+  carrier_name: "iWay"
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "ispmobile"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "iWay"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -13124,4 +13290,4 @@ carrier_id {
   }
   parent_canonical_id: 2560
 }
-version: 100663337
+version: 100663339
diff --git a/assets/sdk34_carrier_id/carrier_list.pb b/assets/sdk34_carrier_id/carrier_list.pb
index 31eeb48f..42631b82 100644
Binary files a/assets/sdk34_carrier_id/carrier_list.pb and b/assets/sdk34_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk34_carrier_id/carrier_list.textpb b/assets/sdk34_carrier_id/carrier_list.textpb
index b1c9637b..3895fc75 100644
--- a/assets/sdk34_carrier_id/carrier_list.textpb
+++ b/assets/sdk34_carrier_id/carrier_list.textpb
@@ -482,6 +482,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "344030"
   }
+  carrier_attribute {
+    mccmnc_tuple: "34403"
+  }
 }
 carrier_id {
   canonical_id: 491
@@ -1511,7 +1514,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 905
-  carrier_name: "Moldcell GSM"
+  carrier_name: "Moldcell"
   carrier_attribute {
     mccmnc_tuple: "25902"
   }
@@ -1696,7 +1699,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1014
-  carrier_name: "Vip mobile d.o.o."
+  carrier_name: "A1 SRB"
   carrier_attribute {
     mccmnc_tuple: "22005"
   }
@@ -3282,7 +3285,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1453
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     mccmnc_tuple: "26205"
@@ -3291,7 +3294,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1454
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     mccmnc_tuple: "26208"
@@ -3948,6 +3951,12 @@ carrier_id {
     mccmnc_tuple: "40480"
     mccmnc_tuple: "40481"
   }
+  carrier_attribute {
+    mccmnc_tuple: "40439"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "40465"
+  }
 }
 carrier_id {
   canonical_id: 1550
@@ -5144,7 +5153,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 1727
-  carrier_name: "Josa Babilon-T"
+  carrier_name: "Babilon-Mobile"
   carrier_attribute {
     mccmnc_tuple: "43604"
   }
@@ -9978,7 +9987,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2360
-  carrier_name: "Telefonica"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26203"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -9987,7 +9996,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2361
-  carrier_name: "o2"
+  carrier_name: "O2"
   carrier_attribute {
     mccmnc_tuple: "26207"
     gid1: "010301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
@@ -10684,6 +10693,18 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "313460"
   }
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "6624"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "6624"
+  }
 }
 carrier_id {
   canonical_id: 2467
@@ -11596,7 +11617,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2570
-  carrier_name: "Netcom O"
+  carrier_name: "Orange MVNOs"
   carrier_attribute {
     mccmnc_tuple: "20801"
     spn: "Netcom Mobile"
@@ -12113,6 +12134,10 @@ carrier_id {
     mccmnc_tuple: "72432"
     gid1: "536E617065"
   }
+  carrier_attribute {
+    mccmnc_tuple: "72418"
+    gid1: "536E617065"
+  }
 }
 carrier_id {
   canonical_id: 2632
@@ -12232,8 +12257,6 @@ carrier_id {
   carrier_name: "IMOWI"
   carrier_attribute {
     mccmnc_tuple: "722210"
-    spn: "imowi"
-    gid1: "722210"
   }
 }
 carrier_id {
@@ -12272,6 +12295,149 @@ carrier_id {
     mccmnc_tuple: "25097"
   }
 }
+carrier_id {
+  canonical_id: 2649
+  carrier_name: "Private FR"
+  carrier_attribute {
+    mccmnc_tuple: "208180"
+  }
+}
+carrier_id {
+  canonical_id: 2651
+  carrier_name: "KPN Lab"
+  carrier_attribute {
+    mccmnc_tuple: "20469"
+  }
+}
+carrier_id {
+  canonical_id: 2652
+  carrier_name: "OXIO"
+  carrier_attribute {
+    mccmnc_tuple: "314720"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "334170"
+  }
+}
+carrier_id {
+  canonical_id: 2653
+  carrier_name: "Cox MSO"
+  carrier_attribute {
+    mccmnc_tuple: "314420"
+  }
+}
+carrier_id {
+  canonical_id: 2654
+  carrier_name: "Mediacom Mobile"
+  carrier_attribute {
+    mccmnc_tuple: "311480"
+    gid1: "BA01700000000000"
+    gid2: "C400000000000000"
+  }
+}
+carrier_id {
+  canonical_id: 2655
+  carrier_name: "Optimum"
+  carrier_attribute {
+    mccmnc_tuple: "310240"
+    spn: "Optimum"
+    gid1: "6784"
+  }
+}
+carrier_id {
+  canonical_id: 2656
+  carrier_name: "Mettel"
+  carrier_attribute {
+    mccmnc_tuple: "314610"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90101"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "21407"
+    gid1: "880A3E"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "206018"
+    gid1: "8915518F"
+  }
+}
+carrier_id {
+  canonical_id: 2657
+  carrier_name: "CiFi"
+  carrier_attribute {
+    mccmnc_tuple: "50557"
+  }
+}
+carrier_id {
+  canonical_id: 2658
+  carrier_name: "Lycamobile"
+  carrier_attribute {
+    mccmnc_tuple: "23812"
+  }
+}
+carrier_id {
+  canonical_id: 2659
+  carrier_name: "Brisanet"
+  carrier_attribute {
+    mccmnc_tuple: "72477"
+  }
+}
+carrier_id {
+  canonical_id: 2660
+  carrier_name: "eSIM Go"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "eSIM Go"
+    gid1: "0033"
+  }
+}
+carrier_id {
+  canonical_id: 2662
+  carrier_name: "Oceus"
+  carrier_attribute {
+    mccmnc_tuple: "314360"
+    spn: "OceusNet"
+    gid1: "FFFF"
+  }
+}
+carrier_id {
+  canonical_id: 2663
+  carrier_name: "TextNow Wireless"
+  carrier_attribute {
+    mccmnc_tuple: "314730"
+  }
+}
+carrier_id {
+  canonical_id: 2664
+  carrier_name: "Popcorn"
+  carrier_attribute {
+    mccmnc_tuple: "313460"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "7911"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "7911"
+  }
+}
+carrier_id {
+  canonical_id: 2665
+  carrier_name: "iWay"
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "ispmobile"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "22873"
+    spn: "iWay"
+  }
+}
 carrier_id {
   canonical_id: 10000
   carrier_name: "Tracfone-ATT"
@@ -12679,4 +12845,4 @@ carrier_id {
   }
   parent_canonical_id: 1779
 }
-version: 117440553
+version: 117440555
diff --git a/src/com/android/providers/telephony/MmsProvider.java b/src/com/android/providers/telephony/MmsProvider.java
index ec487d21..050826d9 100644
--- a/src/com/android/providers/telephony/MmsProvider.java
+++ b/src/com/android/providers/telephony/MmsProvider.java
@@ -64,6 +64,8 @@ import com.google.android.mms.util.DownloadDrmHelper;
 import java.io.File;
 import java.io.FileNotFoundException;
 import java.io.IOException;
+import java.util.ArrayList;
+import java.util.List;
 
 /**
  * The class to provide base facility to access MMS related content,
@@ -83,6 +85,8 @@ public class MmsProvider extends ContentProvider {
 
     private ProviderUtilWrapper providerUtilWrapper = new ProviderUtilWrapper();
 
+    private final List<UserHandle> mUsersRemovedBeforeUnlockList = new ArrayList<>();
+
     @VisibleForTesting
     public void setProviderUtilWrapper(ProviderUtilWrapper providerUtilWrapper) {
         this.providerUtilWrapper = providerUtilWrapper;
@@ -96,7 +100,9 @@ public class MmsProvider extends ContentProvider {
 
         // Creating intent broadcast receiver for user actions like Intent.ACTION_USER_REMOVED,
         // where we would need to remove MMS related to removed user.
-        IntentFilter userIntentFilter = new IntentFilter(Intent.ACTION_USER_REMOVED);
+        IntentFilter userIntentFilter = new IntentFilter();
+        userIntentFilter.addAction(Intent.ACTION_USER_REMOVED);
+        userIntentFilter.addAction(Intent.ACTION_USER_UNLOCKED);
         getContext().registerReceiver(mUserIntentReceiver, userIntentFilter,
                 Context.RECEIVER_NOT_EXPORTED);
 
@@ -1244,35 +1250,57 @@ public class MmsProvider extends ContentProvider {
                         // Do not delete MMS if removed profile is not managed profile.
                         return;
                     }
-                    Log.d(TAG, "Received ACTION_USER_REMOVED for managed profile - Deleting MMS.");
-
-                    // Deleting MMS related to managed profile.
-                    Uri uri = Telephony.Mms.CONTENT_URI;
-                    SQLiteDatabase db = mOpenHelper.getWritableDatabase();
 
-                    final long token = Binder.clearCallingIdentity();
-                    String selectionBySubIds;
-                    try {
-                        // Filter MMS based on subId.
-                        selectionBySubIds = ProviderUtil.getSelectionBySubIds(getContext(),
-                                userToBeRemoved);
-                    } finally {
-                        Binder.restoreCallingIdentity(token);
-                    }
-                    if (selectionBySubIds == null) {
-                        // No subscriptions associated with user, return.
+                    if (!userManager.isUserUnlocked()) {
+                        Log.d(TAG, "Received ACTION_USER_REMOVED for managed profile: "
+                                + "Cannot delete MMS now as user is locked.");
+                        mUsersRemovedBeforeUnlockList.add(userToBeRemoved);
                         return;
                     }
 
-                    int deletedRows = deleteMessages(getContext(), db, selectionBySubIds,
-                            null, uri);
-                    if (deletedRows > 0) {
-                        // Don't update threads unless something changed.
-                        MmsSmsDatabaseHelper.updateThreads(db, selectionBySubIds, null);
-                        notifyChange(uri, null);
+                    Log.d(TAG, "Received ACTION_USER_REMOVED for managed profile: Deleting MMS.");
+                    deleteManagedProfileMessages(userToBeRemoved);
+                    break;
+                case Intent.ACTION_USER_UNLOCKED: {
+                    for (UserHandle user : mUsersRemovedBeforeUnlockList) {
+                        deleteManagedProfileMessages(user);
                     }
+                    mUsersRemovedBeforeUnlockList.clear();
                     break;
+                }
             }
         }
     };
+
+    private void deleteManagedProfileMessages(UserHandle userToBeRemoved) {
+        Log.d(TAG, "deleteManagedProfileMessages: userToBeRemoved="
+                + userToBeRemoved.getIdentifier());
+        // Deleting MMS related to managed profile.
+        Uri uri = Telephony.Mms.CONTENT_URI;
+        SQLiteDatabase db = mOpenHelper.getWritableDatabase();
+
+        final long token = Binder.clearCallingIdentity();
+        String selectionBySubIds;
+        try {
+            // Filter MMS based on subId.
+            selectionBySubIds = ProviderUtil.getSelectionBySubIds(getContext(),
+                    userToBeRemoved);
+        } finally {
+            Binder.restoreCallingIdentity(token);
+        }
+        if (selectionBySubIds == null) {
+            // No subscriptions associated with user, return.
+            Log.d(TAG, "deleteManagedProfileMessages: "
+                    + "no subscriptions associated with user.");
+            return;
+        }
+
+        int deletedRows = deleteMessages(getContext(), db, selectionBySubIds,
+                null, uri);
+        if (deletedRows > 0) {
+            // Don't update threads unless something changed.
+            MmsSmsDatabaseHelper.updateThreads(db, selectionBySubIds, null);
+            notifyChange(uri, null);
+        }
+    }
 }
diff --git a/src/com/android/providers/telephony/MmsSmsDatabaseHelper.java b/src/com/android/providers/telephony/MmsSmsDatabaseHelper.java
index 606e582a..eff5113a 100644
--- a/src/com/android/providers/telephony/MmsSmsDatabaseHelper.java
+++ b/src/com/android/providers/telephony/MmsSmsDatabaseHelper.java
@@ -54,7 +54,6 @@ import android.util.Log;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.PhoneFactory;
 import com.android.internal.telephony.TelephonyStatsLog;
-import com.android.internal.telephony.flags.Flags;
 
 import com.google.android.mms.pdu.EncodedStringValue;
 import com.google.android.mms.pdu.PduHeaders;
@@ -2566,9 +2565,6 @@ public class MmsSmsDatabaseHelper extends SQLiteOpenHelper {
      * Add the MMS/SMS database opening info to the debug log.
      */
     public void addDatabaseOpeningDebugLog(@NonNull String databaseOpeningLog, boolean isQuery) {
-        if (!Flags.logMmsSmsDatabaseAccessInfo()) {
-            return;
-        }
         addDatabaseOpeningDebugLog(isQuery ? mDatabaseReadOpeningInfos : mDatabaseWriteOpeningInfos,
                 databaseOpeningLog);
     }
@@ -2577,9 +2573,6 @@ public class MmsSmsDatabaseHelper extends SQLiteOpenHelper {
      * Print the MMS/SMS database opening debug log to file.
      */
     public void printDatabaseOpeningDebugLog() {
-        if (!Flags.logMmsSmsDatabaseAccessInfo()) {
-            return;
-        }
         Log.e(TAG, "MMS/SMS database read opening info: "
                 + getDatabaseOpeningInfo(mDatabaseReadOpeningInfos));
         Log.e(TAG, "MMS/SMS database write opening info: "
@@ -2619,9 +2612,6 @@ public class MmsSmsDatabaseHelper extends SQLiteOpenHelper {
     }
 
     private void reportAnomalyForDatabaseOpeningException(@NonNull Exception ex) {
-        if (!Flags.logMmsSmsDatabaseAccessInfo()) {
-            return;
-        }
         Log.e(TAG, "DatabaseOpeningException=" + ex);
         printDatabaseOpeningDebugLog();
         AnomalyReporter.reportAnomaly(DATABASE_OPENING_EXCEPTION_UUID,
diff --git a/src/com/android/providers/telephony/ProviderUtil.java b/src/com/android/providers/telephony/ProviderUtil.java
index 4efe3fbb..d544b32c 100644
--- a/src/com/android/providers/telephony/ProviderUtil.java
+++ b/src/com/android/providers/telephony/ProviderUtil.java
@@ -272,10 +272,6 @@ public class ProviderUtil {
      * Log all running processes of the telephony provider package.
      */
     public static void logRunningTelephonyProviderProcesses(@NonNull Context context) {
-        if (!Flags.logMmsSmsDatabaseAccessInfo()) {
-            return;
-        }
-
         ActivityManager am = context.getSystemService(ActivityManager.class);
         if (am == null) {
             Log.d(TAG, "logRunningTelephonyProviderProcesses: ActivityManager service is not"
diff --git a/src/com/android/providers/telephony/SmsProvider.java b/src/com/android/providers/telephony/SmsProvider.java
index eabff64d..d1ec5c6f 100644
--- a/src/com/android/providers/telephony/SmsProvider.java
+++ b/src/com/android/providers/telephony/SmsProvider.java
@@ -52,6 +52,7 @@ import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.TelephonyPermissions;
 import com.android.internal.telephony.util.TelephonyUtils;
 
+import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.List;
 public class SmsProvider extends ContentProvider {
@@ -101,6 +102,8 @@ public class SmsProvider extends ContentProvider {
         "_id"
     };
 
+    private final List<UserHandle> mUsersRemovedBeforeUnlockList = new ArrayList<>();
+
     @Override
     public boolean onCreate() {
         setAppOps(AppOpsManager.OP_READ_SMS, AppOpsManager.OP_WRITE_SMS);
@@ -112,7 +115,9 @@ public class SmsProvider extends ContentProvider {
 
         // Creating intent broadcast receiver for user actions like Intent.ACTION_USER_REMOVED,
         // where we would need to remove SMS related to removed user.
-        IntentFilter userIntentFilter = new IntentFilter(Intent.ACTION_USER_REMOVED);
+        IntentFilter userIntentFilter = new IntentFilter();
+        userIntentFilter.addAction(Intent.ACTION_USER_REMOVED);
+        userIntentFilter.addAction(Intent.ACTION_USER_UNLOCKED);
         getContext().registerReceiver(mUserIntentReceiver, userIntentFilter,
                 Context.RECEIVER_NOT_EXPORTED);
 
@@ -1471,35 +1476,57 @@ public class SmsProvider extends ContentProvider {
                         // Do not delete SMS if removed profile is not managed profile.
                         return;
                     }
-                    Log.d(TAG, "Received ACTION_USER_REMOVED for managed profile - Deleting SMS.");
-
-                    // Deleting SMS related to managed profile.
-                    Uri uri = Sms.CONTENT_URI;
-                    int match = sURLMatcher.match(uri);
-                    SQLiteDatabase db = getWritableDatabase(match);
 
-                    final long token = Binder.clearCallingIdentity();
-                    String selectionBySubIds;
-                    try {
-                        // Filter SMS based on subId.
-                        selectionBySubIds = ProviderUtil.getSelectionBySubIds(getContext(),
-                                userToBeRemoved);
-                    } finally {
-                        Binder.restoreCallingIdentity(token);
-                    }
-                    if (selectionBySubIds == null) {
-                        // No subscriptions associated with user, return.
+                    if (!userManager.isUserUnlocked()) {
+                        Log.d(TAG, "Received ACTION_USER_REMOVED for managed profile: "
+                                + "Cannot delete SMS now as user is locked.");
+                        mUsersRemovedBeforeUnlockList.add(userToBeRemoved);
                         return;
                     }
 
-                    int count = db.delete(TABLE_SMS, selectionBySubIds, null);
-                    if (count != 0) {
-                        // Don't update threads unless something changed.
-                        MmsSmsDatabaseHelper.updateThreads(db, selectionBySubIds, null);
-                        notifyChange(true, uri, getCallingPackage());
+                    Log.d(TAG, "Received ACTION_USER_REMOVED for managed profile: Deleting SMS.");
+                    deleteManagedProfileMessages(userToBeRemoved);
+                    break;
+                case Intent.ACTION_USER_UNLOCKED: {
+                    for (UserHandle user : mUsersRemovedBeforeUnlockList) {
+                        deleteManagedProfileMessages(user);
                     }
+                    mUsersRemovedBeforeUnlockList.clear();
                     break;
+                }
             }
         }
     };
+
+    private void deleteManagedProfileMessages(UserHandle userToBeRemoved) {
+        Log.d(TAG, "deleteManagedProfileMessages: userToBeRemoved="
+                + userToBeRemoved.getIdentifier());
+        // Deleting SMS related to managed profile.
+        Uri uri = Sms.CONTENT_URI;
+        int match = sURLMatcher.match(uri);
+        SQLiteDatabase db = getWritableDatabase(match);
+
+        final long token = Binder.clearCallingIdentity();
+        String selectionBySubIds;
+        try {
+            // Filter SMS based on subId.
+            selectionBySubIds = ProviderUtil.getSelectionBySubIds(getContext(),
+                    userToBeRemoved);
+        } finally {
+            Binder.restoreCallingIdentity(token);
+        }
+        if (selectionBySubIds == null) {
+            // No subscriptions associated with user, return.
+            Log.d(TAG, "deleteManagedProfileMessages: "
+                    + "no subscriptions associated with user.");
+            return;
+        }
+
+        int count = db.delete(TABLE_SMS, selectionBySubIds, null);
+        if (count != 0) {
+            // Don't update threads unless something changed.
+            MmsSmsDatabaseHelper.updateThreads(db, selectionBySubIds, null);
+            notifyChange(true, uri, getCallingPackage());
+        }
+    }
 }
diff --git a/src/com/android/providers/telephony/TelephonyBackupAgent.java b/src/com/android/providers/telephony/TelephonyBackupAgent.java
index 385f3634..29890fc1 100644
--- a/src/com/android/providers/telephony/TelephonyBackupAgent.java
+++ b/src/com/android/providers/telephony/TelephonyBackupAgent.java
@@ -25,6 +25,7 @@ import android.app.backup.BackupDataInput;
 import android.app.backup.BackupDataOutput;
 import android.app.backup.BackupManager;
 import android.app.backup.BackupRestoreEventLogger;
+import android.app.backup.BackupRestoreEventLogger.BackupRestoreDataType;
 import android.app.backup.FullBackupDataOutput;
 import android.content.ContentResolver;
 import android.content.ContentUris;
@@ -324,8 +325,12 @@ public class TelephonyBackupAgent extends BackupAgent {
     private long mBytesOverQuota;
     private BackupRestoreEventLogger mLogger;
     private BackupManager mBackupManager;
-    private int mSmsCount = 0;
-    private int mMmsCount = 0;
+
+    @BackupRestoreDataType
+    private static final String SMS_LOGGING_DATA_TYPE = "SMS";
+    @BackupRestoreDataType
+    private static final String MMS_LOGGING_DATA_TYPE = "MMS";
+
 
     // Cache list of recipients by threadId. It reduces db requests heavily. Used during backup.
     @VisibleForTesting
@@ -473,8 +478,6 @@ public class TelephonyBackupAgent extends BackupAgent {
             // messages, otherwise 1000 MMS messages. Repeat until out of SMS's or MMS's.
             // It ensures backups are incremental.
             int fileNum = 0;
-            mSmsCount = 0;
-            mMmsCount = 0;
             while (smsCursor != null && !smsCursor.isAfterLast() &&
                     mmsCursor != null && !mmsCursor.isAfterLast()) {
                 final long smsDate = TimeUnit.MILLISECONDS.toSeconds(getMessageDate(smsCursor));
@@ -497,14 +500,6 @@ public class TelephonyBackupAgent extends BackupAgent {
                 backupAll(data, mmsCursor,
                         String.format(Locale.US, MMS_BACKUP_FILE_FORMAT, fileNum++));
             }
-
-            if (mSmsCount > 0) {
-                mBackupRestoreEventLoggerProxy.logItemsBackedUp("SMS", mSmsCount);
-            }
-
-            if (mMmsCount > 0) {
-                mBackupRestoreEventLoggerProxy.logItemsBackedUp("MMS", mMmsCount);
-            }
         }
 
         mThreadArchived = new HashMap<>();
@@ -553,12 +548,12 @@ public class TelephonyBackupAgent extends BackupAgent {
         try (JsonWriter jsonWriter = getJsonWriter(fileName)) {
             if (fileName.endsWith(SMS_BACKUP_FILE_SUFFIX)) {
                 chunk = putSmsMessagesToJson(cursor, jsonWriter);
-                mSmsCount = chunk.count;
-                Log.d(TAG, "backupAll: Wrote SMS messages to Json. mSmsCount=" + mSmsCount);
+                mBackupRestoreEventLoggerProxy.logItemsBackedUp(SMS_LOGGING_DATA_TYPE, chunk.count);
+                Log.d(TAG, "backupAll: Wrote SMS messages to Json. count=" + chunk.count);
             } else {
                 chunk = putMmsMessagesToJson(cursor, jsonWriter);
-                mMmsCount = chunk.count;
-                Log.d(TAG, "backupAll: Wrote MMS messages to Json. mMmsCount=" + mMmsCount);
+                mBackupRestoreEventLoggerProxy.logItemsBackedUp(MMS_LOGGING_DATA_TYPE, chunk.count);
+                Log.d(TAG, "backupAll: Wrote MMS messages to Json. count=" + chunk.count);
             }
 
         }
diff --git a/src/com/android/providers/telephony/TelephonyProvider.java b/src/com/android/providers/telephony/TelephonyProvider.java
index 9e1c189d..9bb8eb27 100644
--- a/src/com/android/providers/telephony/TelephonyProvider.java
+++ b/src/com/android/providers/telephony/TelephonyProvider.java
@@ -166,7 +166,7 @@ public class TelephonyProvider extends ContentProvider
     private static final boolean DBG = true;
     private static final boolean VDBG = false; // STOPSHIP if true
 
-    private static final int DATABASE_VERSION = 73 << 16;
+    private static final int DATABASE_VERSION = 74 << 16;
     private static final int URL_UNKNOWN = 0;
     private static final int URL_TELEPHONY = 1;
     private static final int URL_CURRENT = 2;
@@ -377,15 +377,10 @@ public class TelephonyProvider extends ContentProvider
      */
     private static final int  RIL_RADIO_TECHNOLOGY_NR = 20;
 
-    /**
-     * 3GPP NB-IOT (Narrowband Internet of Things) over Non-Terrestrial-Networks technology.
-     */
-    private static final int RIL_RADIO_TECHNOLOGY_NB_IOT_NTN = 21;
-
     /**
      * The number of the radio technologies.
      */
-    private static final int NEXT_RIL_RADIO_TECHNOLOGY = 22;
+    private static final int NEXT_RIL_RADIO_TECHNOLOGY = 21;
 
     private static final Map<String, Integer> MVNO_TYPE_STRING_MAP;
 
@@ -495,6 +490,21 @@ public class TelephonyProvider extends ContentProvider
         SIM_INFO_COLUMNS_TO_BACKUP.put(
                 Telephony.SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM,
                 Cursor.FIELD_TYPE_INTEGER);
+        SIM_INFO_COLUMNS_TO_BACKUP.put(
+                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_BARRED_PLMNS,
+                Cursor.FIELD_TYPE_STRING);
+        SIM_INFO_COLUMNS_TO_BACKUP.put(
+                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_PLAN_PLMNS,
+                Cursor.FIELD_TYPE_STRING);
+        SIM_INFO_COLUMNS_TO_BACKUP.put(
+                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_SERVICE_TYPE_MAP,
+                Cursor.FIELD_TYPE_STRING);
+        SIM_INFO_COLUMNS_TO_BACKUP.put(
+                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_SERVICE_POLICY,
+                Cursor.FIELD_TYPE_STRING);
+        SIM_INFO_COLUMNS_TO_BACKUP.put(
+                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_VOICE_SERVICE_POLICY,
+                Cursor.FIELD_TYPE_STRING);
     }
 
     @VisibleForTesting
@@ -648,7 +658,12 @@ public class TelephonyProvider extends ContentProvider
                 + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS + " TEXT,"
                 + Telephony.SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED + " INTEGER DEFAULT 0,"
                 + Telephony.SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM
-                + " INTEGER DEFAULT 0"
+                + " INTEGER DEFAULT 0,"
+                + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_BARRED_PLMNS + " TEXT,"
+                + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_PLAN_PLMNS + " TEXT,"
+                + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_SERVICE_TYPE_MAP + " TEXT,"
+                + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_SERVICE_POLICY + " TEXT,"
+                + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_VOICE_SERVICE_POLICY + " TEXT"
                 + ");";
     }
 
@@ -2186,6 +2201,32 @@ public class TelephonyProvider extends ContentProvider
                 oldVersion = 73 << 16 | 6;
             }
 
+            if (oldVersion < (74 << 16 | 6)) {
+                try {
+                    // Try to update the siminfo table with new columns.
+                    db.execSQL("ALTER TABLE " + SIMINFO_TABLE + " ADD COLUMN "
+                            + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_BARRED_PLMNS
+                            + " TEXT DEFAULT '';");
+                    db.execSQL("ALTER TABLE " + SIMINFO_TABLE + " ADD COLUMN "
+                            + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_PLAN_PLMNS
+                            + " TEXT DEFAULT '';");
+                    db.execSQL("ALTER TABLE " + SIMINFO_TABLE + " ADD COLUMN "
+                            + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_SERVICE_TYPE_MAP
+                            + " TEXT DEFAULT '';");
+                    db.execSQL("ALTER TABLE " + SIMINFO_TABLE + " ADD COLUMN "
+                            + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_SERVICE_POLICY
+                            + " TEXT DEFAULT '';");
+                    db.execSQL("ALTER TABLE " + SIMINFO_TABLE + " ADD COLUMN "
+                            + Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_VOICE_SERVICE_POLICY
+                            + " TEXT DEFAULT '';");
+                } catch (SQLiteException e) {
+                    if (DBG) {
+                        log("onUpgrade failed to update " + SIMINFO_TABLE
+                                + " to add satellite entitlement data");
+                    }
+                }
+                oldVersion = 74 << 16 | 6;
+            }
             if (DBG) {
                 log("dbh.onUpgrade:- db=" + db + " oldV=" + oldVersion + " newV=" + newVersion);
             }
@@ -4068,7 +4109,7 @@ public class TelephonyProvider extends ContentProvider
                 PersistableBundle backedUpSimInfoEntry, int backupDataFormatVersion,
                 String isoCountryCodeFromDb, String allowedNetworkTypesForReasonsFromDb,
                 List<String> wfcRestoreBlockedCountries) {
-            if (DATABASE_VERSION != 73 << 16) {
+            if (DATABASE_VERSION != 74 << 16) {
                 throw new AssertionError("The database schema has been updated which might make "
                     + "the format of #BACKED_UP_SIM_SPECIFIC_SETTINGS_FILE outdated. Make sure to "
                     + "1) review whether any of the columns in #SIM_INFO_COLUMNS_TO_BACKUP have "
@@ -4110,6 +4151,31 @@ public class TelephonyProvider extends ContentProvider
              * Also make sure to add necessary removal of sensitive settings in
              * polishContentValues(ContentValues contentValues).
              */
+            if (backupDataFormatVersion >= 74 << 16) {
+                contentValues.put(Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_BARRED_PLMNS,
+                        backedUpSimInfoEntry.getString(
+                                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_BARRED_PLMNS,
+                                DEFAULT_STRING_COLUMN_VALUE));
+                contentValues.put(Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_PLAN_PLMNS,
+                        backedUpSimInfoEntry.getString(
+                                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_PLAN_PLMNS,
+                                DEFAULT_STRING_COLUMN_VALUE));
+                contentValues.put(Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_SERVICE_TYPE_MAP,
+                        backedUpSimInfoEntry.getString(
+                                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_SERVICE_TYPE_MAP,
+                                DEFAULT_STRING_COLUMN_VALUE));
+                contentValues.put(
+                        Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_SERVICE_POLICY,
+                        backedUpSimInfoEntry.getString(
+                                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_SERVICE_POLICY,
+                                DEFAULT_STRING_COLUMN_VALUE));
+                contentValues.put(
+                        Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_VOICE_SERVICE_POLICY,
+                        backedUpSimInfoEntry.getString(
+                                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_VOICE_SERVICE_POLICY,
+                                DEFAULT_STRING_COLUMN_VALUE));
+
+            }
             if (backupDataFormatVersion >= 73 << 16) {
                 contentValues.put(
                         Telephony.SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM,
@@ -4133,14 +4199,12 @@ public class TelephonyProvider extends ContentProvider
                         backedUpSimInfoEntry.getString(
                                 Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS,
                                 DEFAULT_STRING_COLUMN_VALUE));
-                if (Flags.backupAndRestoreForEnable2g()) {
-                    contentValues.put(Telephony.SimInfo.COLUMN_ALLOWED_NETWORK_TYPES_FOR_REASONS,
-                            replaceEnable2g(
-                                    allowedNetworkTypesForReasonsFromDb,
-                                    backedUpSimInfoEntry.getString(Telephony.SimInfo
-                                                    .COLUMN_ALLOWED_NETWORK_TYPES_FOR_REASONS),
-                                    DEFAULT_STRING_COLUMN_VALUE));
-                }
+                contentValues.put(Telephony.SimInfo.COLUMN_ALLOWED_NETWORK_TYPES_FOR_REASONS,
+                        replaceEnable2g(
+                                allowedNetworkTypesForReasonsFromDb,
+                                backedUpSimInfoEntry.getString(Telephony.SimInfo
+                                                .COLUMN_ALLOWED_NETWORK_TYPES_FOR_REASONS),
+                                DEFAULT_STRING_COLUMN_VALUE));
             }
             if (backupDataFormatVersion >= 70 << 16) {
                 contentValues.put(Telephony.SimInfo.COLUMN_TRANSFER_STATUS,
@@ -4267,7 +4331,7 @@ public class TelephonyProvider extends ContentProvider
         private ContentValues polishContentValues(ContentValues contentValues) {
             /* Remove any values that weren't found in the backup file. These were set to defaults
             in #convertBackedUpDataToContentValues(). */
-            for (Map.Entry<String, Integer> column : getSimInfoColumnsToBackup().entrySet()) {
+            for (Map.Entry<String, Integer> column : SIM_INFO_COLUMNS_TO_BACKUP.entrySet()) {
                 String columnName = column.getKey();
 
                 if (!contentValues.containsKey(columnName)) {
@@ -4306,7 +4370,7 @@ public class TelephonyProvider extends ContentProvider
      * @return data of interest from SimInfoDB as a byte array.
      */
     private byte[] getSimSpecificDataToBackUp() {
-        Map<String, Integer> simInfoColumnsToBackup = getSimInfoColumnsToBackup();
+        Map<String, Integer> simInfoColumnsToBackup = SIM_INFO_COLUMNS_TO_BACKUP;
         String[] projection = simInfoColumnsToBackup.keySet()
                 .toArray(new String[simInfoColumnsToBackup.size()]);
 
@@ -4326,25 +4390,13 @@ public class TelephonyProvider extends ContentProvider
         }
     }
 
-    private static @NonNull Map<String, Integer> getSimInfoColumnsToBackup() {
-        if (Flags.backupAndRestoreForEnable2g()) {
-            return SIM_INFO_COLUMNS_TO_BACKUP;
-        }
-        Map<String, Integer> simInfoColumnsToBackup =
-                new HashMap<String, Integer>(SIM_INFO_COLUMNS_TO_BACKUP);
-        simInfoColumnsToBackup.remove(
-                Telephony.SimInfo.COLUMN_ALLOWED_NETWORK_TYPES_FOR_REASONS);
-        return simInfoColumnsToBackup;
-    }
-
     private static PersistableBundle convertSimInfoDbEntryToPersistableBundle(Cursor cursor) {
         PersistableBundle bundle = new PersistableBundle();
-        for (Map.Entry<String, Integer> column : getSimInfoColumnsToBackup().entrySet()) {
+        for (Map.Entry<String, Integer> column : SIM_INFO_COLUMNS_TO_BACKUP.entrySet()) {
             String columnName = column.getKey();
             int columnType = column.getValue();
             int columnIndex = cursor.getColumnIndex(columnName);
-            if (Flags.backupAndRestoreForEnable2g()
-                    && Telephony.SimInfo.COLUMN_ALLOWED_NETWORK_TYPES_FOR_REASONS
+            if (Telephony.SimInfo.COLUMN_ALLOWED_NETWORK_TYPES_FOR_REASONS
                             .equals(columnName)) {
                 bundle.putString(columnName,
                         filteredAllowedNetworkTypesForBackup(cursor.getString(columnIndex)));
@@ -5946,8 +5998,6 @@ public class TelephonyProvider extends ContentProvider
                 return (int) TelephonyManager.NETWORK_TYPE_BITMASK_LTE_CA;
             case RIL_RADIO_TECHNOLOGY_NR:
                 return (int) TelephonyManager.NETWORK_TYPE_BITMASK_NR;
-            case RIL_RADIO_TECHNOLOGY_NB_IOT_NTN:
-                return (int) TelephonyManager.NETWORK_TYPE_BITMASK_NB_IOT_NTN;
             default:
                 return (int) TelephonyManager.NETWORK_TYPE_BITMASK_UNKNOWN;
         }
diff --git a/tests/src/com/android/providers/telephony/TelephonyBackupAgentTest.java b/tests/src/com/android/providers/telephony/TelephonyBackupAgentTest.java
index f75480a6..1d821cff 100644
--- a/tests/src/com/android/providers/telephony/TelephonyBackupAgentTest.java
+++ b/tests/src/com/android/providers/telephony/TelephonyBackupAgentTest.java
@@ -117,12 +117,14 @@ public class TelephonyBackupAgentTest extends AndroidTestCase {
     private boolean mItemBackedUpFailed = false;
     private boolean mItemRestored = false;
     private boolean mItemsRestoreFailed = false;
+    private int mSuccessItemBackupTotalCount = 0;
 
     private TelephonyBackupAgent.BackupRestoreEventLoggerProxy mBackupRestoreEventLoggerProxy =
             new TelephonyBackupAgent.BackupRestoreEventLoggerProxy() {
         @Override
         public void logItemsBackedUp(String dataType, int count) {
             mItemBackedUp = true;
+            mSuccessItemBackupTotalCount += count;
         }
 
         @Override
@@ -352,6 +354,7 @@ public class TelephonyBackupAgentTest extends AndroidTestCase {
         mItemBackedUpFailed = false;
         mItemRestored = false;
         mItemsRestoreFailed = false;
+        mSuccessItemBackupTotalCount = 0;
         BackupManager mockBackupManager = Mockito.mock(BackupManager.class);
         mTelephonyBackupAgent.setBackupRestoreEventLoggerProxy(mBackupRestoreEventLoggerProxy);
         mTelephonyBackupAgent.setBackupManager(mockBackupManager);
@@ -837,6 +840,17 @@ public class TelephonyBackupAgentTest extends AndroidTestCase {
         assertArrayEquals(firstBackup, secondBackup);
     }
 
+    /**
+     * Back up all 4 messages, but limit to 1 per file to verify all messages are correctly logged.
+     */
+    public void testBackupSms_multipleFiles_logsCorrectly() throws Exception {
+        mTelephonyBackupAgent.mMaxMsgPerFile = 1;
+        mSmsTable.addAll(Arrays.asList(mSmsRows));
+        mTelephonyBackupAgent.onFullBackup(new FullBackupDataOutput(Integer.MAX_VALUE));
+
+        assertEquals(mSmsRows.length , mSuccessItemBackupTotalCount);
+    }
+
     private byte[] getBackup(String runId) throws IOException {
         File cacheDir = getContext().getCacheDir();
         File backupOutput = File.createTempFile("backup", runId, cacheDir);
diff --git a/tests/src/com/android/providers/telephony/TelephonyDatabaseHelperTest.java b/tests/src/com/android/providers/telephony/TelephonyDatabaseHelperTest.java
index cfc89707..1b0e23c9 100644
--- a/tests/src/com/android/providers/telephony/TelephonyDatabaseHelperTest.java
+++ b/tests/src/com/android/providers/telephony/TelephonyDatabaseHelperTest.java
@@ -836,6 +836,86 @@ public final class TelephonyDatabaseHelperTest extends TelephonyTestBase {
         assertEquals(0, cursor.getCount());
     }
 
+    @Test
+    public void databaseHelperOnUpgrade_hasSatelliteEntitlementBarredPlmnsFields() {
+        Log.d(TAG, "databaseHelperOnUpgrade_hasSatelliteEntitlementBarredPlmnsFields");
+        // (5 << 16 | 6) is the first upgrade trigger in onUpgrade
+        SQLiteDatabase db = mInMemoryDbHelper.getWritableDatabase();
+        mHelper.onUpgrade(db, (4 << 16), TelephonyProvider.getVersion(mContext));
+
+        // the upgraded db must have Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS
+        Cursor cursor = db.query("siminfo", null, null, null, null, null, null);
+        String[] upgradedColumns = cursor.getColumnNames();
+        Log.d(TAG, "siminfo columns: " + Arrays.toString(upgradedColumns));
+
+        assertTrue(Arrays.asList(upgradedColumns).contains(
+                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_BARRED_PLMNS));
+    }
+
+    @Test
+    public void databaseHelperOnUpgrade_hasSatelliteEntitlementDataPlanPlmns() {
+        Log.d(TAG, "databaseHelperOnUpgrade_hasSatelliteEntitlementDataPlanPlmns");
+        // (5 << 16 | 6) is the first upgrade trigger in onUpgrade
+        SQLiteDatabase db = mInMemoryDbHelper.getWritableDatabase();
+        mHelper.onUpgrade(db, (4 << 16), TelephonyProvider.getVersion(mContext));
+
+        // the upgraded db must have Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS
+        Cursor cursor = db.query("siminfo", null, null, null, null, null, null);
+        String[] upgradedColumns = cursor.getColumnNames();
+        Log.d(TAG, "siminfo columns: " + Arrays.toString(upgradedColumns));
+
+        assertTrue(Arrays.asList(upgradedColumns).contains(
+                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_PLAN_PLMNS));
+    }
+
+    @Test
+    public void databaseHelperOnUpgrade_hasSatelliteEntitlementServiceTypeMap() {
+        Log.d(TAG, "databaseHelperOnUpgrade_hasSatelliteEntitlementServiceTypeMap");
+        // (5 << 16 | 6) is the first upgrade trigger in onUpgrade
+        SQLiteDatabase db = mInMemoryDbHelper.getWritableDatabase();
+        mHelper.onUpgrade(db, (4 << 16), TelephonyProvider.getVersion(mContext));
+
+        // the upgraded db must have Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS
+        Cursor cursor = db.query("siminfo", null, null, null, null, null, null);
+        String[] upgradedColumns = cursor.getColumnNames();
+        Log.d(TAG, "siminfo columns: " + Arrays.toString(upgradedColumns));
+
+        assertTrue(Arrays.asList(upgradedColumns).contains(
+                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_SERVICE_TYPE_MAP));
+    }
+
+    @Test
+    public void databaseHelperOnUpgrade_hasSatelliteEntitlementDataServicePolicy() {
+        Log.d(TAG, "databaseHelperOnUpgrade_hasSatelliteEntitlementDataServicePolicy");
+        // (5 << 16 | 6) is the first upgrade trigger in onUpgrade
+        SQLiteDatabase db = mInMemoryDbHelper.getWritableDatabase();
+        mHelper.onUpgrade(db, (4 << 16), TelephonyProvider.getVersion(mContext));
+
+        // the upgraded db must have Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS
+        Cursor cursor = db.query("siminfo", null, null, null, null, null, null);
+        String[] upgradedColumns = cursor.getColumnNames();
+        Log.d(TAG, "siminfo columns: " + Arrays.toString(upgradedColumns));
+
+        assertTrue(Arrays.asList(upgradedColumns).contains(
+                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_SERVICE_POLICY));
+    }
+
+    @Test
+    public void databaseHelperOnUpgrade_hasSatelliteEntitlementVoiceServicePolicy() {
+        Log.d(TAG, "databaseHelperOnUpgrade_hasSatelliteEntitlementVoiceServicePolicy");
+        // (5 << 16 | 6) is the first upgrade trigger in onUpgrade
+        SQLiteDatabase db = mInMemoryDbHelper.getWritableDatabase();
+        mHelper.onUpgrade(db, (4 << 16), TelephonyProvider.getVersion(mContext));
+
+        // the upgraded db must have Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_PLMNS
+        Cursor cursor = db.query("siminfo", null, null, null, null, null, null);
+        String[] upgradedColumns = cursor.getColumnNames();
+        Log.d(TAG, "siminfo columns: " + Arrays.toString(upgradedColumns));
+
+        assertTrue(Arrays.asList(upgradedColumns).contains(
+                Telephony.SimInfo.COLUMN_SATELLITE_ENTITLEMENT_VOICE_SERVICE_POLICY));
+    }
+
     /**
      * Helper for an in memory DB used to test the TelephonyProvider#DatabaseHelper.
      *
diff --git a/tests/src/com/android/providers/telephony/TelephonyProviderTest.java b/tests/src/com/android/providers/telephony/TelephonyProviderTest.java
index 4d1912af..182e61de 100644
--- a/tests/src/com/android/providers/telephony/TelephonyProviderTest.java
+++ b/tests/src/com/android/providers/telephony/TelephonyProviderTest.java
@@ -62,7 +62,6 @@ import androidx.test.filters.SmallTest;
 
 import com.android.internal.telephony.LocalLog;
 import com.android.internal.telephony.PhoneFactory;
-import com.android.internal.telephony.flags.Flags;
 
 import org.junit.After;
 import org.junit.Before;
@@ -268,6 +267,14 @@ public class TelephonyProviderTest {
 
         contentValues.put(SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM,
                 arbitraryIntVal);
+        contentValues.put(SimInfo.COLUMN_SATELLITE_ENTITLEMENT_BARRED_PLMNS, arbitraryStringVal);
+        contentValues.put(SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_PLAN_PLMNS, arbitraryStringVal);
+        contentValues.put(SimInfo.COLUMN_SATELLITE_ENTITLEMENT_SERVICE_TYPE_MAP,
+                arbitraryStringVal);
+        contentValues.put(SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_SERVICE_POLICY,
+                arbitraryStringVal);
+        contentValues.put(SimInfo.COLUMN_SATELLITE_ENTITLEMENT_VOICE_SERVICE_POLICY,
+                arbitraryStringVal);
         return contentValues;
     }
 
@@ -769,6 +776,11 @@ public class TelephonyProviderTest {
         final String insertSatelliteEntitlementPlmns = "examplePlmns";
         final int insertCarrierRoamingNtn = 1;
         final int insertIsSatelliteProvisioned = 1;
+        final String insertSatelliteEntitlementBarredPlmns = "exampleBarredPlmns";
+        final String insertSatelliteEntitlementDataPlanPlmns = "exampleDataPlanPlmns";
+        final String insertSatelliteEntitlementServiceTypeMap = "exampleServiceTypeMap";
+        final String insertSatelliteEntitlementDataServicePolicy = "exampleDataServicePolicy";
+        final String insertSatelliteEntitlementVoiceServicePolicy = "exampleVoiceServicePolicy";
         contentValues.put(SubscriptionManager.UNIQUE_KEY_SUBSCRIPTION_ID, insertSubId);
         contentValues.put(SubscriptionManager.DISPLAY_NAME, insertDisplayName);
         contentValues.put(SubscriptionManager.CARRIER_NAME, insertCarrierName);
@@ -790,6 +802,16 @@ public class TelephonyProviderTest {
         contentValues.put(SubscriptionManager.SATELLITE_ESOS_SUPPORTED, insertCarrierRoamingNtn);
         contentValues.put(SubscriptionManager.IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM,
                 insertIsSatelliteProvisioned);
+        contentValues.put(SubscriptionManager.SATELLITE_ENTITLEMENT_BARRED_PLMNS,
+                insertSatelliteEntitlementBarredPlmns);
+        contentValues.put(SubscriptionManager.SATELLITE_ENTITLEMENT_DATA_PLAN_PLMNS,
+                insertSatelliteEntitlementDataPlanPlmns);
+        contentValues.put(SubscriptionManager.SATELLITE_ENTITLEMENT_SERVICE_TYPE_MAP,
+                insertSatelliteEntitlementServiceTypeMap);
+        contentValues.put(SubscriptionManager.SATELLITE_ENTITLEMENT_DATA_SERVICE_POLICY,
+                insertSatelliteEntitlementDataServicePolicy);
+        contentValues.put(SubscriptionManager.SATELLITE_ENTITLEMENT_VOICE_SERVICE_POLICY,
+                insertSatelliteEntitlementVoiceServicePolicy);
 
         Log.d(TAG, "testSimTable Inserting contentValues: " + contentValues);
         mContentResolver.insert(SimInfo.CONTENT_URI, contentValues);
@@ -811,7 +833,12 @@ public class TelephonyProviderTest {
             SubscriptionManager.SATELLITE_ENTITLEMENT_STATUS,
             SubscriptionManager.SATELLITE_ENTITLEMENT_PLMNS,
             SubscriptionManager.SATELLITE_ESOS_SUPPORTED,
-            SubscriptionManager.IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM
+            SubscriptionManager.IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM,
+            SubscriptionManager.SATELLITE_ENTITLEMENT_BARRED_PLMNS,
+            SubscriptionManager.SATELLITE_ENTITLEMENT_DATA_PLAN_PLMNS,
+            SubscriptionManager.SATELLITE_ENTITLEMENT_SERVICE_TYPE_MAP,
+            SubscriptionManager.SATELLITE_ENTITLEMENT_DATA_SERVICE_POLICY,
+            SubscriptionManager.SATELLITE_ENTITLEMENT_VOICE_SERVICE_POLICY
         };
         final String selection = SubscriptionManager.DISPLAY_NAME + "=?";
         String[] selectionArgs = { insertDisplayName };
@@ -839,6 +866,11 @@ public class TelephonyProviderTest {
         final String resultSatelliteEntitlementPlmns = cursor.getString(12);
         final int resultCarrierRoamingNtn = cursor.getInt(13);
         final int resultIsSatelliteProvisioned = cursor.getInt(14);
+        final String resultSatelliteEntitlementBarredPlmns = cursor.getString(15);
+        final String resultSatelliteEntitlementDataPlanPlmns = cursor.getString(16);
+        final String resultSatelliteEntitlementServiceTypeMap = cursor.getString(17);
+        final String resultSatelliteEntitlementDataServicePolicy = cursor.getString(18);
+        final String resultSatelliteEntitlementVoiceServicePolicy = cursor.getString(19);
         assertEquals(insertSubId, resultSubId);
         assertEquals(insertCarrierName, resultCarrierName);
         assertEquals(insertCardId, resultCardId);
@@ -854,6 +886,16 @@ public class TelephonyProviderTest {
         assertEquals(insertSatelliteEntitlementPlmns, resultSatelliteEntitlementPlmns);
         assertEquals(insertCarrierRoamingNtn, resultCarrierRoamingNtn);
         assertEquals(insertIsSatelliteProvisioned, resultIsSatelliteProvisioned);
+        assertEquals(insertSatelliteEntitlementBarredPlmns, resultSatelliteEntitlementBarredPlmns);
+        assertEquals(insertSatelliteEntitlementDataPlanPlmns,
+                resultSatelliteEntitlementDataPlanPlmns);
+        assertEquals(insertSatelliteEntitlementServiceTypeMap,
+                resultSatelliteEntitlementServiceTypeMap);
+        assertEquals(insertSatelliteEntitlementDataServicePolicy,
+                resultSatelliteEntitlementDataServicePolicy);
+        assertEquals(insertSatelliteEntitlementVoiceServicePolicy,
+                resultSatelliteEntitlementVoiceServicePolicy);
+
 
         // delete test content
         final String selectionToDelete = SubscriptionManager.DISPLAY_NAME + "=?";
@@ -934,6 +976,21 @@ public class TelephonyProviderTest {
                 getIntValueFromCursor(cursor, SimInfo.COLUMN_SATELLITE_ESOS_SUPPORTED));
         assertEquals(ARBITRARY_SIMINFO_DB_TEST_INT_VALUE_1, getIntValueFromCursor(cursor,
                 SimInfo.COLUMN_IS_SATELLITE_PROVISIONED_FOR_NON_IP_DATAGRAM));
+        assertEquals(ARBITRARY_SIMINFO_DB_TEST_STRING_VALUE_1,
+                getStringValueFromCursor(cursor,
+                        SimInfo.COLUMN_SATELLITE_ENTITLEMENT_BARRED_PLMNS));
+        assertEquals(ARBITRARY_SIMINFO_DB_TEST_STRING_VALUE_1,
+                getStringValueFromCursor(cursor,
+                        SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_PLAN_PLMNS));
+        assertEquals(ARBITRARY_SIMINFO_DB_TEST_STRING_VALUE_1,
+                getStringValueFromCursor(cursor,
+                        SimInfo.COLUMN_SATELLITE_ENTITLEMENT_SERVICE_TYPE_MAP));
+        assertEquals(ARBITRARY_SIMINFO_DB_TEST_STRING_VALUE_1,
+                getStringValueFromCursor(cursor,
+                        SimInfo.COLUMN_SATELLITE_ENTITLEMENT_DATA_SERVICE_POLICY));
+        assertEquals(ARBITRARY_SIMINFO_DB_TEST_STRING_VALUE_1,
+                getStringValueFromCursor(cursor,
+                        SimInfo.COLUMN_SATELLITE_ENTITLEMENT_VOICE_SERVICE_POLICY));
         assertRestoredSubIdIsRemembered();
     }
 
@@ -1074,7 +1131,6 @@ public class TelephonyProviderTest {
     public void testBackupForAllowedNetworkTypesForReasons() {
         // If the Backup&Restore for 2g setting feature flag is enabled, backup data must contain
         // allowed network type reasons data.
-        mSetFlagsRule.enableFlags(Flags.FLAG_BACKUP_AND_RESTORE_FOR_ENABLE_2G);
         String backupDataFeatureTrue = new String(getBackupData(new ContentValues[] {
                 BACKED_UP_SIM_INFO_VALUES_WITH_ALLOWED_NETWORK_REASONS}));
         Log.d(TAG, "backupData with feature flag as true:" + new String(backupDataFeatureTrue));
@@ -1083,19 +1139,6 @@ public class TelephonyProviderTest {
                 ARBITRARY_ALLOWED_NETWORK_TYPES_BACKUP_STRING_VALUE));
     }
 
-    @Test
-    public void testBackupForAllowedNetworkTypesForReasonsWithFeatureDisabled() {
-        // If the Backup&Restore for 2g setting feature flag is disabled, backup data must not
-        // contain any of allowed network type reasons data.
-        mSetFlagsRule.disableFlags(Flags.FLAG_BACKUP_AND_RESTORE_FOR_ENABLE_2G);
-        String backupDataFeatureFalse = new String(getBackupData(new ContentValues[]{
-                BACKED_UP_SIM_INFO_VALUES_WITH_ALLOWED_NETWORK_REASONS}));
-        Log.d(TAG, "backupData with feature flag as false:" + new String(backupDataFeatureFalse));
-        // Verify that backupdata does not have allowed network types.
-        assertFalse(backupDataFeatureFalse.contains(
-                ARBITRARY_ALLOWED_NETWORK_TYPES_BACKUP_STRING_VALUE));
-    }
-
     private void backupForAllowedNetworkTypesForReasons() {
         // Content value includes allowed_network_types for all reasons.
         ContentValues contentValues = BACKED_UP_SIM_INFO_VALUES_WITH_ALLOWED_NETWORK_REASONS;
@@ -1125,8 +1168,6 @@ public class TelephonyProviderTest {
 
     @Test
     public void testBackupAndRestoreForAllowedNetworkTypesForReasons() {
-        mSetFlagsRule.enableFlags(Flags.FLAG_BACKUP_AND_RESTORE_FOR_ENABLE_2G);
-
         backupForAllowedNetworkTypesForReasons();
         Cursor cursor = restoreForAllowedNetworkTypesForReasons();
         cursor.moveToFirst();
@@ -1138,20 +1179,6 @@ public class TelephonyProviderTest {
         assertRestoredSubIdIsRemembered();
     }
 
-    @Test
-    public void testBackupAndRestoreForAllowedNetworkTypesForReasonsWithFeatureDisabled() {
-        mSetFlagsRule.disableFlags(Flags.FLAG_BACKUP_AND_RESTORE_FOR_ENABLE_2G);
-
-        backupForAllowedNetworkTypesForReasons();
-        Cursor cursor = restoreForAllowedNetworkTypesForReasons();
-        cursor.moveToFirst();
-
-        // Ensure network types reason values got updated. Only enable_2g needs to be updated.
-        assertNull(getStringValueFromCursor(cursor,
-                SimInfo.COLUMN_ALLOWED_NETWORK_TYPES_FOR_REASONS));
-        assertRestoredSubIdIsRemembered();
-    }
-
     private void assertRestoredSubIdIsRemembered() {
         PersistableBundle bundle = getPersistableBundleFromInternalStorageFile();
         int[] previouslyRestoredSubIds =
```

