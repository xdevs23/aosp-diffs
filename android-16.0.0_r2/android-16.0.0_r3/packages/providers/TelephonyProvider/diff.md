```diff
diff --git a/assets/latest_carrier_id/carrier_list.pb b/assets/latest_carrier_id/carrier_list.pb
index 577108aa..d45a0464 100644
Binary files a/assets/latest_carrier_id/carrier_list.pb and b/assets/latest_carrier_id/carrier_list.pb differ
diff --git a/assets/latest_carrier_id/carrier_list.textpb b/assets/latest_carrier_id/carrier_list.textpb
index c34a40fc..fa3edb73 100644
--- a/assets/latest_carrier_id/carrier_list.textpb
+++ b/assets/latest_carrier_id/carrier_list.textpb
@@ -253,9 +253,10 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 21
-  carrier_name: "Vodafone"
+  carrier_name: "One NZ"
   carrier_attribute {
     mccmnc_tuple: "53001"
+    spn: "One NZ"
     spn: "vodafone NZ"
   }
 }
@@ -701,7 +702,7 @@ carrier_id {
   canonical_id: 574
   carrier_name: "Ice Wireless"
   carrier_attribute {
-    mccmnc_tuple: "30262"
+    mccmnc_tuple: "302620"
   }
 }
 carrier_id {
@@ -5694,6 +5695,7 @@ carrier_id {
   carrier_name: "East Kentucky Network LLC dba Appalachian Wireless"
   carrier_attribute {
     mccmnc_tuple: "310750"
+    mccmnc_tuple: "312130"
   }
 }
 carrier_id {
@@ -8071,6 +8073,7 @@ carrier_id {
     mccmnc_tuple: "21403"
     mccmnc_tuple: "21408"
     spn: "EUSKALTEL"
+    spn: "Euskaltel"
   }
 }
 carrier_id {
@@ -8415,7 +8418,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2143
-  carrier_name: "Truphone"
+  carrier_name: "1GLOBAL"
   carrier_attribute {
     mccmnc_tuple: "20404"
     mccmnc_tuple: "20408"
@@ -8423,11 +8426,11 @@ carrier_id {
     mccmnc_tuple: "20809"
     mccmnc_tuple: "20812"
     mccmnc_tuple: "21427"
+    mccmnc_tuple: "23410"
     mccmnc_tuple: "23425"
     mccmnc_tuple: "26033"
     mccmnc_tuple: "26242"
     mccmnc_tuple: "310300"
-    mccmnc_tuple: "310690"
     mccmnc_tuple: "45400"
     mccmnc_tuple: "45408"
     mccmnc_tuple: "50538"
@@ -11755,7 +11758,7 @@ carrier_id {
   }
   carrier_attribute {
     mccmnc_tuple: "24007"
-    gid1: "41"
+    gid1: "0041"
   }
 }
 carrier_id {
@@ -11790,7 +11793,7 @@ carrier_id {
   }
   carrier_attribute {
     mccmnc_tuple: "24007"
-    gid1: "40"
+    gid1: "0040"
   }
 }
 carrier_id {
@@ -11801,7 +11804,7 @@ carrier_id {
   }
   carrier_attribute {
     mccmnc_tuple: "24007"
-    gid1: "48"
+    gid1: "0048"
   }
 }
 carrier_id {
@@ -11812,7 +11815,7 @@ carrier_id {
   }
   carrier_attribute {
     mccmnc_tuple: "24007"
-    gid1: "52"
+    gid1: "0052"
   }
 }
 carrier_id {
@@ -12352,8 +12355,120 @@ carrier_id {
   carrier_name: "iWay"
   carrier_attribute {
     mccmnc_tuple: "22873"
-    spn: "ispmobile"
-    spn: "iWay"
+  }
+}
+carrier_id {
+  canonical_id: 2666
+  carrier_name: "Telecom26"
+  carrier_attribute {
+    mccmnc_tuple: "20404"
+    mccmnc_tuple: "22201"
+    mccmnc_tuple: "22862"
+    mccmnc_tuple: "23455"
+    mccmnc_tuple: "42402"
+    mccmnc_tuple: "51503"
+    mccmnc_tuple: "73001"
+    mccmnc_tuple: "90146"
+    gid1: "54656c65636f6d3236"
+  }
+}
+carrier_id {
+  canonical_id: 2667
+  carrier_name: "Gigs"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "Gigs"
+    gid1: "22"
+  }
+}
+carrier_id {
+  canonical_id: 2668
+  carrier_name: "TELUS Cloud Core"
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    mccmnc_tuple: "302221"
+    gid1: "4C4F"
+  }
+}
+carrier_id {
+  canonical_id: 2669
+  carrier_name: "Execulink Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "302340"
+  }
+}
+carrier_id {
+  canonical_id: 2670
+  carrier_name: "Cape"
+  carrier_attribute {
+    mccmnc_tuple: "314560"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    mccmnc_tuple: "311588"
+    gid1: "2273"
+  }
+}
+carrier_id {
+  canonical_id: 2671
+  carrier_name: "Yobi Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "334110"
+    spn: "YOBI"
+  }
+}
+carrier_id {
+  canonical_id: 2672
+  carrier_name: "R"
+  carrier_attribute {
+    mccmnc_tuple: "21403"
+    spn: "R"
+  }
+}
+carrier_id {
+  canonical_id: 2673
+  carrier_name: "Ericsson Test"
+  carrier_attribute {
+    mccmnc_tuple: "262800"
+  }
+}
+carrier_id {
+  canonical_id: 2674
+  carrier_name: "Telecable"
+  carrier_attribute {
+    mccmnc_tuple: "21403"
+    spn: "Telecable"
+  }
+}
+carrier_id {
+  canonical_id: 2675
+  carrier_name: "VOCUS-CN"
+  carrier_attribute {
+    mccmnc_tuple: "505023"
+    spn: "VOCUS"
+  }
+}
+carrier_id {
+  canonical_id: 2676
+  carrier_name: "PMCI"
+  carrier_attribute {
+    mccmnc_tuple: "55299"
+    spn: "PMCI"
+  }
+}
+carrier_id {
+  canonical_id: 2677
+  carrier_name: "netplus.ch"
+  carrier_attribute {
+    mccmnc_tuple: "22874"
+  }
+}
+carrier_id {
+  canonical_id: 2678
+  carrier_name: "One5G"
+  carrier_attribute {
+    mccmnc_tuple: "61908"
   }
 }
 carrier_id {
@@ -12763,4 +12878,4 @@ carrier_id {
   }
   parent_canonical_id: 1779
 }
-version: 134217771
+version: 134217773
diff --git a/assets/sdk28_carrier_id/carrier_list.pb b/assets/sdk28_carrier_id/carrier_list.pb
index 9a48e0db..7b865d61 100644
Binary files a/assets/sdk28_carrier_id/carrier_list.pb and b/assets/sdk28_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk28_carrier_id/carrier_list.textpb b/assets/sdk28_carrier_id/carrier_list.textpb
index 45d6a589..30166fae 100644
--- a/assets/sdk28_carrier_id/carrier_list.textpb
+++ b/assets/sdk28_carrier_id/carrier_list.textpb
@@ -313,7 +313,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 21
-  carrier_name: "Vodafone"
+  carrier_name: "One NZ"
   carrier_attribute {
     mccmnc_tuple: "53001"
   }
@@ -1026,6 +1026,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "30262"
   }
+  carrier_attribute {
+    mccmnc_tuple: "302620"
+  }
 }
 carrier_id {
   canonical_id: 575
@@ -6274,6 +6277,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "310750"
   }
+  carrier_attribute {
+    mccmnc_tuple: "312130"
+  }
 }
 carrier_id {
   canonical_id: 1814
@@ -9028,6 +9034,10 @@ carrier_id {
     mccmnc_tuple: "21408"
     spn: "EUSKALTEL"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21408"
+    spn: "Euskaltel"
+  }
 }
 carrier_id {
   canonical_id: 2112
@@ -9326,7 +9336,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2143
-  carrier_name: "Truphone"
+  carrier_name: "1GLOBAL"
   carrier_attribute {
     mccmnc_tuple: "20433"
   }
@@ -9372,6 +9382,10 @@ carrier_id {
     mccmnc_tuple: "45408"
     gid1: "547275554b3030656e"
   }
+  carrier_attribute {
+    mccmnc_tuple: "23410"
+    gid1: "547275554b3030656e"
+  }
 }
 carrier_id {
   canonical_id: 2144
@@ -13536,11 +13550,103 @@ carrier_id {
   carrier_name: "iWay"
   carrier_attribute {
     mccmnc_tuple: "22873"
-    spn: "ispmobile"
+  }
+}
+carrier_id {
+  canonical_id: 2666
+  carrier_name: "Telecom26"
+  carrier_attribute {
+    mccmnc_tuple: "22862"
+    gid1: "54656c65636f6d3236"
   }
   carrier_attribute {
-    mccmnc_tuple: "22873"
-    spn: "iWay"
+    mccmnc_tuple: "23455"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "42402"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "73001"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90146"
+    gid1: "54656c65636f6d3236"
+  }
+}
+carrier_id {
+  canonical_id: 2667
+  carrier_name: "Gigs"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "Gigs"
+    gid1: "22"
+  }
+}
+carrier_id {
+  canonical_id: 2669
+  carrier_name: "Execulink Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "302340"
+  }
+}
+carrier_id {
+  canonical_id: 2670
+  carrier_name: "Cape"
+  carrier_attribute {
+    mccmnc_tuple: "314560"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "2273"
+  }
+}
+carrier_id {
+  canonical_id: 2671
+  carrier_name: "Yobi Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "334110"
+    spn: "YOBI"
+  }
+}
+carrier_id {
+  canonical_id: 2673
+  carrier_name: "Ericsson Test"
+  carrier_attribute {
+    mccmnc_tuple: "262800"
+  }
+}
+carrier_id {
+  canonical_id: 2675
+  carrier_name: "VOCUS-CN"
+  carrier_attribute {
+    mccmnc_tuple: "505023"
+    spn: "VOCUS"
+  }
+}
+carrier_id {
+  canonical_id: 2676
+  carrier_name: "PMCI"
+  carrier_attribute {
+    mccmnc_tuple: "55299"
+    spn: "PMCI"
+  }
+}
+carrier_id {
+  canonical_id: 2677
+  carrier_name: "netplus.ch"
+  carrier_attribute {
+    mccmnc_tuple: "22874"
+  }
+}
+carrier_id {
+  canonical_id: 2678
+  carrier_name: "One5G"
+  carrier_attribute {
+    mccmnc_tuple: "61908"
   }
 }
 carrier_id {
@@ -13785,4 +13891,4 @@ carrier_id {
   }
   parent_canonical_id: 2023
 }
-version: 51
+version: 53
diff --git a/assets/sdk29_carrier_id/carrier_list.pb b/assets/sdk29_carrier_id/carrier_list.pb
index 5332c9ca..1abcd4f0 100644
Binary files a/assets/sdk29_carrier_id/carrier_list.pb and b/assets/sdk29_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk29_carrier_id/carrier_list.textpb b/assets/sdk29_carrier_id/carrier_list.textpb
index 161c7422..ac3572e8 100644
--- a/assets/sdk29_carrier_id/carrier_list.textpb
+++ b/assets/sdk29_carrier_id/carrier_list.textpb
@@ -314,11 +314,15 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 21
-  carrier_name: "Vodafone"
+  carrier_name: "One NZ"
   carrier_attribute {
     mccmnc_tuple: "53001"
     spn: "vodafone NZ"
   }
+  carrier_attribute {
+    mccmnc_tuple: "53001"
+    spn: "One NZ"
+  }
 }
 carrier_id {
   canonical_id: 22
@@ -1014,6 +1018,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "30262"
   }
+  carrier_attribute {
+    mccmnc_tuple: "302620"
+  }
 }
 carrier_id {
   canonical_id: 575
@@ -6089,6 +6096,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "310750"
   }
+  carrier_attribute {
+    mccmnc_tuple: "312130"
+  }
 }
 carrier_id {
   canonical_id: 1814
@@ -8778,6 +8788,10 @@ carrier_id {
     mccmnc_tuple: "21408"
     spn: "EUSKALTEL"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21408"
+    spn: "Euskaltel"
+  }
 }
 carrier_id {
   canonical_id: 2112
@@ -9110,7 +9124,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2143
-  carrier_name: "Truphone"
+  carrier_name: "1GLOBAL"
   carrier_attribute {
     mccmnc_tuple: "20433"
     mccmnc_tuple: "21427"
@@ -13446,11 +13460,119 @@ carrier_id {
   carrier_name: "iWay"
   carrier_attribute {
     mccmnc_tuple: "22873"
-    spn: "ispmobile"
   }
+}
+carrier_id {
+  canonical_id: 2666
+  carrier_name: "Telecom26"
   carrier_attribute {
-    mccmnc_tuple: "22873"
-    spn: "iWay"
+    mccmnc_tuple: "22862"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23455"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "42402"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "73001"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90146"
+    gid1: "54656c65636f6d3236"
+  }
+}
+carrier_id {
+  canonical_id: 2667
+  carrier_name: "Gigs"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "Gigs"
+    gid1: "22"
+  }
+}
+carrier_id {
+  canonical_id: 2668
+  carrier_name: "TELUS Cloud Core"
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "4C4F"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302221"
+    gid1: "4C4F"
+  }
+}
+carrier_id {
+  canonical_id: 2669
+  carrier_name: "Execulink Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "302340"
+  }
+}
+carrier_id {
+  canonical_id: 2670
+  carrier_name: "Cape"
+  carrier_attribute {
+    mccmnc_tuple: "314560"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "2273"
+  }
+}
+carrier_id {
+  canonical_id: 2671
+  carrier_name: "Yobi Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "334110"
+    spn: "YOBI"
+  }
+}
+carrier_id {
+  canonical_id: 2673
+  carrier_name: "Ericsson Test"
+  carrier_attribute {
+    mccmnc_tuple: "262800"
+  }
+}
+carrier_id {
+  canonical_id: 2675
+  carrier_name: "VOCUS-CN"
+  carrier_attribute {
+    mccmnc_tuple: "505023"
+    spn: "VOCUS"
+  }
+}
+carrier_id {
+  canonical_id: 2676
+  carrier_name: "PMCI"
+  carrier_attribute {
+    mccmnc_tuple: "55299"
+    spn: "PMCI"
+  }
+}
+carrier_id {
+  canonical_id: 2677
+  carrier_name: "netplus.ch"
+  carrier_attribute {
+    mccmnc_tuple: "22874"
+  }
+}
+carrier_id {
+  canonical_id: 2678
+  carrier_name: "One5G"
+  carrier_attribute {
+    mccmnc_tuple: "61908"
   }
 }
 carrier_id {
@@ -13694,4 +13816,4 @@ carrier_id {
   }
   parent_canonical_id: 2023
 }
-version: 16777275
+version: 16777277
diff --git a/assets/sdk30_carrier_id/carrier_list.pb b/assets/sdk30_carrier_id/carrier_list.pb
index 6c5a8107..b7970df0 100644
Binary files a/assets/sdk30_carrier_id/carrier_list.pb and b/assets/sdk30_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk30_carrier_id/carrier_list.textpb b/assets/sdk30_carrier_id/carrier_list.textpb
index dca11e9e..ef6e2d71 100644
--- a/assets/sdk30_carrier_id/carrier_list.textpb
+++ b/assets/sdk30_carrier_id/carrier_list.textpb
@@ -314,11 +314,15 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 21
-  carrier_name: "Vodafone"
+  carrier_name: "One NZ"
   carrier_attribute {
     mccmnc_tuple: "53001"
     spn: "vodafone NZ"
   }
+  carrier_attribute {
+    mccmnc_tuple: "53001"
+    spn: "One NZ"
+  }
 }
 carrier_id {
   canonical_id: 22
@@ -1014,6 +1018,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "30262"
   }
+  carrier_attribute {
+    mccmnc_tuple: "302620"
+  }
 }
 carrier_id {
   canonical_id: 575
@@ -6086,6 +6093,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "310750"
   }
+  carrier_attribute {
+    mccmnc_tuple: "312130"
+  }
 }
 carrier_id {
   canonical_id: 1814
@@ -8737,6 +8747,10 @@ carrier_id {
     mccmnc_tuple: "21408"
     spn: "EUSKALTEL"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21408"
+    spn: "Euskaltel"
+  }
 }
 carrier_id {
   canonical_id: 2112
@@ -9081,7 +9095,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2143
-  carrier_name: "Truphone"
+  carrier_name: "1GLOBAL"
   carrier_attribute {
     mccmnc_tuple: "20433"
     mccmnc_tuple: "21427"
@@ -13428,11 +13442,119 @@ carrier_id {
   carrier_name: "iWay"
   carrier_attribute {
     mccmnc_tuple: "22873"
-    spn: "ispmobile"
   }
+}
+carrier_id {
+  canonical_id: 2666
+  carrier_name: "Telecom26"
   carrier_attribute {
-    mccmnc_tuple: "22873"
-    spn: "iWay"
+    mccmnc_tuple: "22862"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23455"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "42402"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "73001"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90146"
+    gid1: "54656c65636f6d3236"
+  }
+}
+carrier_id {
+  canonical_id: 2667
+  carrier_name: "Gigs"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "Gigs"
+    gid1: "22"
+  }
+}
+carrier_id {
+  canonical_id: 2668
+  carrier_name: "TELUS Cloud Core"
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "4C4F"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302221"
+    gid1: "4C4F"
+  }
+}
+carrier_id {
+  canonical_id: 2669
+  carrier_name: "Execulink Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "302340"
+  }
+}
+carrier_id {
+  canonical_id: 2670
+  carrier_name: "Cape"
+  carrier_attribute {
+    mccmnc_tuple: "314560"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "2273"
+  }
+}
+carrier_id {
+  canonical_id: 2671
+  carrier_name: "Yobi Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "334110"
+    spn: "YOBI"
+  }
+}
+carrier_id {
+  canonical_id: 2673
+  carrier_name: "Ericsson Test"
+  carrier_attribute {
+    mccmnc_tuple: "262800"
+  }
+}
+carrier_id {
+  canonical_id: 2675
+  carrier_name: "VOCUS-CN"
+  carrier_attribute {
+    mccmnc_tuple: "505023"
+    spn: "VOCUS"
+  }
+}
+carrier_id {
+  canonical_id: 2676
+  carrier_name: "PMCI"
+  carrier_attribute {
+    mccmnc_tuple: "55299"
+    spn: "PMCI"
+  }
+}
+carrier_id {
+  canonical_id: 2677
+  carrier_name: "netplus.ch"
+  carrier_attribute {
+    mccmnc_tuple: "22874"
+  }
+}
+carrier_id {
+  canonical_id: 2678
+  carrier_name: "One5G"
+  carrier_attribute {
+    mccmnc_tuple: "61908"
   }
 }
 carrier_id {
@@ -13696,4 +13818,4 @@ carrier_id {
   }
   parent_canonical_id: 2023
 }
-version: 33554509
+version: 33554511
diff --git a/assets/sdk31_carrier_id/carrier_list.pb b/assets/sdk31_carrier_id/carrier_list.pb
index cd69e801..a60616c8 100644
Binary files a/assets/sdk31_carrier_id/carrier_list.pb and b/assets/sdk31_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk31_carrier_id/carrier_list.textpb b/assets/sdk31_carrier_id/carrier_list.textpb
index f171d240..dbe56a59 100644
--- a/assets/sdk31_carrier_id/carrier_list.textpb
+++ b/assets/sdk31_carrier_id/carrier_list.textpb
@@ -307,11 +307,15 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 21
-  carrier_name: "Vodafone"
+  carrier_name: "One NZ"
   carrier_attribute {
     mccmnc_tuple: "53001"
     spn: "vodafone NZ"
   }
+  carrier_attribute {
+    mccmnc_tuple: "53001"
+    spn: "One NZ"
+  }
 }
 carrier_id {
   canonical_id: 22
@@ -784,6 +788,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "30262"
   }
+  carrier_attribute {
+    mccmnc_tuple: "302620"
+  }
 }
 carrier_id {
   canonical_id: 575
@@ -5824,6 +5831,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "310750"
   }
+  carrier_attribute {
+    mccmnc_tuple: "312130"
+  }
 }
 carrier_id {
   canonical_id: 1814
@@ -8465,6 +8475,10 @@ carrier_id {
     mccmnc_tuple: "21408"
     spn: "EUSKALTEL"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21408"
+    spn: "Euskaltel"
+  }
 }
 carrier_id {
   canonical_id: 2112
@@ -8809,7 +8823,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2143
-  carrier_name: "Truphone"
+  carrier_name: "1GLOBAL"
   carrier_attribute {
     mccmnc_tuple: "20404"
     mccmnc_tuple: "20408"
@@ -13155,11 +13169,119 @@ carrier_id {
   carrier_name: "iWay"
   carrier_attribute {
     mccmnc_tuple: "22873"
-    spn: "ispmobile"
   }
+}
+carrier_id {
+  canonical_id: 2666
+  carrier_name: "Telecom26"
   carrier_attribute {
-    mccmnc_tuple: "22873"
-    spn: "iWay"
+    mccmnc_tuple: "22862"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23455"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "42402"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "73001"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90146"
+    gid1: "54656c65636f6d3236"
+  }
+}
+carrier_id {
+  canonical_id: 2667
+  carrier_name: "Gigs"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "Gigs"
+    gid1: "22"
+  }
+}
+carrier_id {
+  canonical_id: 2668
+  carrier_name: "TELUS Cloud Core"
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "4C4F"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302221"
+    gid1: "4C4F"
+  }
+}
+carrier_id {
+  canonical_id: 2669
+  carrier_name: "Execulink Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "302340"
+  }
+}
+carrier_id {
+  canonical_id: 2670
+  carrier_name: "Cape"
+  carrier_attribute {
+    mccmnc_tuple: "314560"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "2273"
+  }
+}
+carrier_id {
+  canonical_id: 2671
+  carrier_name: "Yobi Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "334110"
+    spn: "YOBI"
+  }
+}
+carrier_id {
+  canonical_id: 2673
+  carrier_name: "Ericsson Test"
+  carrier_attribute {
+    mccmnc_tuple: "262800"
+  }
+}
+carrier_id {
+  canonical_id: 2675
+  carrier_name: "VOCUS-CN"
+  carrier_attribute {
+    mccmnc_tuple: "505023"
+    spn: "VOCUS"
+  }
+}
+carrier_id {
+  canonical_id: 2676
+  carrier_name: "PMCI"
+  carrier_attribute {
+    mccmnc_tuple: "55299"
+    spn: "PMCI"
+  }
+}
+carrier_id {
+  canonical_id: 2677
+  carrier_name: "netplus.ch"
+  carrier_attribute {
+    mccmnc_tuple: "22874"
+  }
+}
+carrier_id {
+  canonical_id: 2678
+  carrier_name: "One5G"
+  carrier_attribute {
+    mccmnc_tuple: "61908"
   }
 }
 carrier_id {
@@ -13463,4 +13585,4 @@ carrier_id {
   }
   parent_canonical_id: 1894
 }
-version: 50331701
+version: 50331703
diff --git a/assets/sdk33_carrier_id/carrier_list.pb b/assets/sdk33_carrier_id/carrier_list.pb
index b6f5bed4..d0460d5f 100644
Binary files a/assets/sdk33_carrier_id/carrier_list.pb and b/assets/sdk33_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk33_carrier_id/carrier_list.textpb b/assets/sdk33_carrier_id/carrier_list.textpb
index d821ad1a..06050a69 100644
--- a/assets/sdk33_carrier_id/carrier_list.textpb
+++ b/assets/sdk33_carrier_id/carrier_list.textpb
@@ -251,11 +251,15 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 21
-  carrier_name: "Vodafone"
+  carrier_name: "One NZ"
   carrier_attribute {
     mccmnc_tuple: "53001"
     spn: "vodafone NZ"
   }
+  carrier_attribute {
+    mccmnc_tuple: "53001"
+    spn: "One NZ"
+  }
 }
 carrier_id {
   canonical_id: 22
@@ -728,6 +732,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "30262"
   }
+  carrier_attribute {
+    mccmnc_tuple: "302620"
+  }
 }
 carrier_id {
   canonical_id: 575
@@ -5767,6 +5774,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "310750"
   }
+  carrier_attribute {
+    mccmnc_tuple: "312130"
+  }
 }
 carrier_id {
   canonical_id: 1814
@@ -8224,6 +8234,10 @@ carrier_id {
     mccmnc_tuple: "21408"
     spn: "EUSKALTEL"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21408"
+    spn: "Euskaltel"
+  }
 }
 carrier_id {
   canonical_id: 2112
@@ -8572,7 +8586,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2143
-  carrier_name: "Truphone"
+  carrier_name: "1GLOBAL"
   carrier_attribute {
     mccmnc_tuple: "20404"
     mccmnc_tuple: "20408"
@@ -12907,11 +12921,119 @@ carrier_id {
   carrier_name: "iWay"
   carrier_attribute {
     mccmnc_tuple: "22873"
-    spn: "ispmobile"
   }
+}
+carrier_id {
+  canonical_id: 2666
+  carrier_name: "Telecom26"
   carrier_attribute {
-    mccmnc_tuple: "22873"
-    spn: "iWay"
+    mccmnc_tuple: "22862"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23455"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "42402"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "73001"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90146"
+    gid1: "54656c65636f6d3236"
+  }
+}
+carrier_id {
+  canonical_id: 2667
+  carrier_name: "Gigs"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "Gigs"
+    gid1: "22"
+  }
+}
+carrier_id {
+  canonical_id: 2668
+  carrier_name: "TELUS Cloud Core"
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "4C4F"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302221"
+    gid1: "4C4F"
+  }
+}
+carrier_id {
+  canonical_id: 2669
+  carrier_name: "Execulink Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "302340"
+  }
+}
+carrier_id {
+  canonical_id: 2670
+  carrier_name: "Cape"
+  carrier_attribute {
+    mccmnc_tuple: "314560"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "2273"
+  }
+}
+carrier_id {
+  canonical_id: 2671
+  carrier_name: "Yobi Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "334110"
+    spn: "YOBI"
+  }
+}
+carrier_id {
+  canonical_id: 2673
+  carrier_name: "Ericsson Test"
+  carrier_attribute {
+    mccmnc_tuple: "262800"
+  }
+}
+carrier_id {
+  canonical_id: 2675
+  carrier_name: "VOCUS-CN"
+  carrier_attribute {
+    mccmnc_tuple: "505023"
+    spn: "VOCUS"
+  }
+}
+carrier_id {
+  canonical_id: 2676
+  carrier_name: "PMCI"
+  carrier_attribute {
+    mccmnc_tuple: "55299"
+    spn: "PMCI"
+  }
+}
+carrier_id {
+  canonical_id: 2677
+  carrier_name: "netplus.ch"
+  carrier_attribute {
+    mccmnc_tuple: "22874"
+  }
+}
+carrier_id {
+  canonical_id: 2678
+  carrier_name: "One5G"
+  carrier_attribute {
+    mccmnc_tuple: "61908"
   }
 }
 carrier_id {
@@ -13290,4 +13412,4 @@ carrier_id {
   }
   parent_canonical_id: 2560
 }
-version: 100663339
+version: 100663341
diff --git a/assets/sdk34_carrier_id/carrier_list.pb b/assets/sdk34_carrier_id/carrier_list.pb
index 42631b82..d10cffb1 100644
Binary files a/assets/sdk34_carrier_id/carrier_list.pb and b/assets/sdk34_carrier_id/carrier_list.pb differ
diff --git a/assets/sdk34_carrier_id/carrier_list.textpb b/assets/sdk34_carrier_id/carrier_list.textpb
index 3895fc75..497ccd1f 100644
--- a/assets/sdk34_carrier_id/carrier_list.textpb
+++ b/assets/sdk34_carrier_id/carrier_list.textpb
@@ -251,11 +251,15 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 21
-  carrier_name: "Vodafone"
+  carrier_name: "One NZ"
   carrier_attribute {
     mccmnc_tuple: "53001"
     spn: "vodafone NZ"
   }
+  carrier_attribute {
+    mccmnc_tuple: "53001"
+    spn: "One NZ"
+  }
 }
 carrier_id {
   canonical_id: 22
@@ -706,6 +710,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "30262"
   }
+  carrier_attribute {
+    mccmnc_tuple: "302620"
+  }
 }
 carrier_id {
   canonical_id: 575
@@ -5715,6 +5722,9 @@ carrier_id {
   carrier_attribute {
     mccmnc_tuple: "310750"
   }
+  carrier_attribute {
+    mccmnc_tuple: "312130"
+  }
 }
 carrier_id {
   canonical_id: 1814
@@ -8096,6 +8106,10 @@ carrier_id {
     mccmnc_tuple: "21408"
     spn: "EUSKALTEL"
   }
+  carrier_attribute {
+    mccmnc_tuple: "21408"
+    spn: "Euskaltel"
+  }
 }
 carrier_id {
   canonical_id: 2112
@@ -8444,7 +8458,7 @@ carrier_id {
 }
 carrier_id {
   canonical_id: 2143
-  carrier_name: "Truphone"
+  carrier_name: "1GLOBAL"
   carrier_attribute {
     mccmnc_tuple: "20404"
     mccmnc_tuple: "20408"
@@ -12431,11 +12445,119 @@ carrier_id {
   carrier_name: "iWay"
   carrier_attribute {
     mccmnc_tuple: "22873"
-    spn: "ispmobile"
   }
+}
+carrier_id {
+  canonical_id: 2666
+  carrier_name: "Telecom26"
   carrier_attribute {
-    mccmnc_tuple: "22873"
-    spn: "iWay"
+    mccmnc_tuple: "22862"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "23455"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "42402"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "73001"
+    gid1: "54656c65636f6d3236"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "90146"
+    gid1: "54656c65636f6d3236"
+  }
+}
+carrier_id {
+  canonical_id: 2667
+  carrier_name: "Gigs"
+  carrier_attribute {
+    mccmnc_tuple: "23415"
+    spn: "Gigs"
+    gid1: "22"
+  }
+}
+carrier_id {
+  canonical_id: 2668
+  carrier_name: "TELUS Cloud Core"
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "4C4F"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302221"
+    gid1: "4C4F"
+  }
+}
+carrier_id {
+  canonical_id: 2669
+  carrier_name: "Execulink Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "302340"
+  }
+}
+carrier_id {
+  canonical_id: 2670
+  carrier_name: "Cape"
+  carrier_attribute {
+    mccmnc_tuple: "314560"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "302220"
+    gid1: "2273"
+  }
+  carrier_attribute {
+    mccmnc_tuple: "311588"
+    gid1: "2273"
+  }
+}
+carrier_id {
+  canonical_id: 2671
+  carrier_name: "Yobi Telecom"
+  carrier_attribute {
+    mccmnc_tuple: "334110"
+    spn: "YOBI"
+  }
+}
+carrier_id {
+  canonical_id: 2673
+  carrier_name: "Ericsson Test"
+  carrier_attribute {
+    mccmnc_tuple: "262800"
+  }
+}
+carrier_id {
+  canonical_id: 2675
+  carrier_name: "VOCUS-CN"
+  carrier_attribute {
+    mccmnc_tuple: "505023"
+    spn: "VOCUS"
+  }
+}
+carrier_id {
+  canonical_id: 2676
+  carrier_name: "PMCI"
+  carrier_attribute {
+    mccmnc_tuple: "55299"
+    spn: "PMCI"
+  }
+}
+carrier_id {
+  canonical_id: 2677
+  carrier_name: "netplus.ch"
+  carrier_attribute {
+    mccmnc_tuple: "22874"
+  }
+}
+carrier_id {
+  canonical_id: 2678
+  carrier_name: "One5G"
+  carrier_attribute {
+    mccmnc_tuple: "61908"
   }
 }
 carrier_id {
@@ -12845,4 +12967,4 @@ carrier_id {
   }
   parent_canonical_id: 1779
 }
-version: 117440555
+version: 117440557
diff --git a/src/com/android/providers/telephony/TelephonyProvider.java b/src/com/android/providers/telephony/TelephonyProvider.java
index 9bb8eb27..fd533614 100644
--- a/src/com/android/providers/telephony/TelephonyProvider.java
+++ b/src/com/android/providers/telephony/TelephonyProvider.java
@@ -32,8 +32,8 @@ import static android.provider.Telephony.Carriers.CONTENT_URI;
 import static android.provider.Telephony.Carriers.CURRENT;
 import static android.provider.Telephony.Carriers.DEFAULT_SORT_ORDER;
 import static android.provider.Telephony.Carriers.EDITED_STATUS;
-import static android.provider.Telephony.Carriers.INFRASTRUCTURE_BITMASK;
 import static android.provider.Telephony.Carriers.ESIM_BOOTSTRAP_PROVISIONING;
+import static android.provider.Telephony.Carriers.INFRASTRUCTURE_BITMASK;
 import static android.provider.Telephony.Carriers.LINGERING_NETWORK_TYPE_BITMASK;
 import static android.provider.Telephony.Carriers.MAX_CONNECTIONS;
 import static android.provider.Telephony.Carriers.MCC;
@@ -130,7 +130,6 @@ import com.android.internal.annotations.GuardedBy;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.TelephonyPermissions;
 import com.android.internal.telephony.TelephonyStatsLog;
-import com.android.internal.telephony.flags.Flags;
 import com.android.internal.util.XmlUtils;
 
 import org.xmlpull.v1.XmlPullParser;
@@ -5604,10 +5603,8 @@ public class TelephonyProvider extends ContentProvider
         }
 
         PackageManager packageManager = getContext().getPackageManager();
-        if (Flags.hsumPackageManager()) {
-            packageManager = getContext().createContextAsUser(Binder.getCallingUserHandle(), 0)
-                    .getPackageManager();
-        }
+        packageManager = getContext().createContextAsUser(Binder.getCallingUserHandle(), 0)
+                .getPackageManager();
         String[] packages = packageManager.getPackagesForUid(Binder.getCallingUid());
 
         TelephonyManager telephonyManager =
```

