```diff
diff --git a/METADATA b/METADATA
index c3d3941..5011f3f 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/libhevc
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libhevc"
 description: "Android fork of the libhevc library."
@@ -8,12 +8,12 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 6
-    day: 7
+    month: 8
+    day: 19
   }
   identifier {
     type: "Git"
     value: "https://github.com/ittiam-systems/libhevc.git"
-    version: "v1.5.1"
+    version: "v1.6.0"
   }
 }
diff --git a/encoder/ihevce_error_check.c b/encoder/ihevce_error_check.c
index 60be50a..fbdfd9e 100644
--- a/encoder/ihevce_error_check.c
+++ b/encoder/ihevce_error_check.c
@@ -712,8 +712,6 @@ WORD32 ihevce_hle_validate_static_params(ihevce_static_cfg_params_t *ps_static_c
     }
 
     {
-        WORD32 sub_gop_size = (1 << ps_static_cfg_prms->s_coding_tools_prms.i4_max_temporal_layers)
-                              << ps_static_cfg_prms->s_src_prms.i4_field_pic;
         WORD32 i4_max_idr_period, i4_min_idr_period, i4_max_cra_period, i4_max_i_period;
         WORD32 i4_max_i_distance;
         WORD32 i4_min_i_distance = 0, i4_non_zero_idr_period = 0x7FFFFFFF,
@@ -723,6 +721,12 @@ WORD32 ihevce_hle_validate_static_params(ihevce_static_cfg_params_t *ps_static_c
         i4_max_cra_period = ps_static_cfg_prms->s_coding_tools_prms.i4_max_cra_open_gop_period;
         i4_max_i_period = ps_static_cfg_prms->s_coding_tools_prms.i4_max_i_open_gop_period;
         i4_max_i_distance = MAX(MAX(i4_max_idr_period, i4_max_cra_period), i4_max_i_period);
+        WORD32 num_b_frms =
+                (1 << ps_static_cfg_prms->s_coding_tools_prms.i4_max_temporal_layers) - 1;
+        if (i4_max_i_distance <= num_b_frms)
+            ps_static_cfg_prms->s_coding_tools_prms.i4_max_temporal_layers = 0;
+        WORD32 sub_gop_size = (1 << ps_static_cfg_prms->s_coding_tools_prms.i4_max_temporal_layers)
+                << ps_static_cfg_prms->s_src_prms.i4_field_pic;
 
         if(sub_gop_size > 1)
         {
```

