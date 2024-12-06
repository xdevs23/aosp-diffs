```diff
diff --git a/METADATA b/METADATA
index 798232c..cd2d855 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/libavc
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libavc"
 description: "Android fork of the libavc library."
@@ -8,12 +8,12 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 4
-    day: 24
+    month: 8
+    day: 19
   }
   identifier {
     type: "Git"
     value: "https://github.com/ittiam-systems/libavc.git"
-    version: "v1.4.0"
+    version: "v1.5.0"
   }
 }
diff --git a/decoder/ih264d_utils.c b/decoder/ih264d_utils.c
index ffb575a..a6eea60 100644
--- a/decoder/ih264d_utils.c
+++ b/decoder/ih264d_utils.c
@@ -172,8 +172,8 @@ WORD32 ih264d_decode_pic_order_cnt(UWORD8 u1_is_idr_slice,
             /* POC TYPE 0 */
             if(u1_is_idr_slice)
             {
-                ps_prev_poc->i4_pic_order_cnt_msb = 0;
-                ps_prev_poc->i4_pic_order_cnt_lsb = 0;
+                ps_cur_poc->i4_pic_order_cnt_msb = 0;
+                ps_cur_poc->i4_pic_order_cnt_lsb = 0;
             }
             if(ps_prev_poc->u1_mmco_equalto5)
             {
diff --git a/decoder/mvc/imvcd_api.c b/decoder/mvc/imvcd_api.c
index 1026fc8..4b1876b 100644
--- a/decoder/mvc/imvcd_api.c
+++ b/decoder/mvc/imvcd_api.c
@@ -733,7 +733,13 @@ static IV_API_CALL_STATUS_T imvcd_view_decode(iv_obj_t *ps_dec_hdl, imvcd_video_
 
         if(i4_nalu_length)
         {
-            UWORD32 u4_nalu_buf_size = ((UWORD32) i4_nalu_length) + 8;
+            /* In some erroneous fuzzer bistreams, the slice data requires more
+              parsing than what was implied by the distance between successive
+              start codes.The primary culprit is the NEXTBITS macro which requires
+              reading 4 additional bytes of the bitstream buffer.To alleviate
+              this, 4 bytes per 4x4 TU have been additionally allocated to the
+              bitstream buffer. */
+            UWORD32 u4_nalu_buf_size = ((UWORD32) i4_nalu_length) + 8 + 4 * 16;
 
             if(u4_nalu_buf_size > u4_bitstream_buf_size)
             {
diff --git a/decoder/svc/isvcd_api.c b/decoder/svc/isvcd_api.c
index c789785..1d58ab5 100644
--- a/decoder/svc/isvcd_api.c
+++ b/decoder/svc/isvcd_api.c
@@ -4474,16 +4474,17 @@ WORD32 isvcd_dec_non_vcl(void *pv_out_non_vcl, void *pv_seq_params, void *pv_pic
             case PIC_PARAM_NAL:
 
                 i_status = isvcd_parse_pps(ps_svc_lyr_dec, ps_bitstrm);
-                if(i_status == ERROR_INV_SPS_PPS_T) return i_status;
                 if(!i_status)
                 {
                     ps_dec->i4_header_decoded |= 0x2;
                     ps_svcd_ctxt->u4_num_pps_ctr++;
                 }
+                if(i_status) return i_status;
                 break;
             case SEI_NAL:
             {
                 i_status = ih264d_parse_sei_message(ps_dec, ps_bitstrm);
+                if(i_status) return i_status;
                 ih264d_parse_sei(ps_dec, ps_bitstrm);
             }
             break;
@@ -4545,7 +4546,7 @@ WORD32 isvcd_seq_hdr_dec(svc_dec_ctxt_t *ps_svcd_ctxt, ivd_video_decode_ip_t *ps
     /*          2. Picture parameter set                      */
     /*          3. SEI message                                */
     /* ------------------------------------------------------ */
-    isvcd_dec_non_vcl(&ps_svcd_ctxt->s_non_vcl_nal, ps_svcd_ctxt->ps_sps, ps_svcd_ctxt->ps_pps,
+    i4_status = isvcd_dec_non_vcl(&ps_svcd_ctxt->s_non_vcl_nal, ps_svcd_ctxt->ps_sps, ps_svcd_ctxt->ps_pps,
                       ps_svcd_ctxt);
 
     return (i4_status);
@@ -4579,7 +4580,7 @@ WORD32 isvcd_seq_hdr_dec(svc_dec_ctxt_t *ps_svcd_ctxt, ivd_video_decode_ip_t *ps
 WORD32 isvcd_pre_parse_refine_au(svc_dec_ctxt_t *ps_svcd_ctxt, ivd_video_decode_ip_t *ps_in_bufs,
                                  UWORD32 *pu4_bytes_consumed)
 {
-    WORD32 i4_status, i4_non_vcl_status;
+    WORD32 i4_status = 0, i4_non_vcl_status;
     UWORD32 u4_bytes_consumed = 0;
     dec_struct_t *ps_dec;
     svc_dec_lyr_struct_t *ps_svc_lyr_dec;
@@ -4602,6 +4603,10 @@ WORD32 isvcd_pre_parse_refine_au(svc_dec_ctxt_t *ps_svcd_ctxt, ivd_video_decode_
         }
     }
     *pu4_bytes_consumed = u4_bytes_consumed;
+    if (i4_status)
+    {
+        return NOT_OK;
+    }
     if(1 == ps_dec->i4_decode_header)
     {
         return OK;
diff --git a/decoder/svc/isvcd_parse_slice.c b/decoder/svc/isvcd_parse_slice.c
index 226a6e4..60bed2a 100644
--- a/decoder/svc/isvcd_parse_slice.c
+++ b/decoder/svc/isvcd_parse_slice.c
@@ -766,6 +766,12 @@ WORD32 isvcd_parse_decode_slice_ext_nal(UWORD8 u1_is_idr_slice, UWORD8 u1_nal_re
         if(ps_dec->u2_frm_ht_in_mbs != ps_seq->u2_frm_ht_in_mbs) return ERROR_INV_SLICE_HDR_T;
     }
 
+    if(ps_dec->u1_init_dec_flag == 1)
+    {
+        if(ps_dec->u2_disp_height != ps_subset_seq->u2_disp_height) return ERROR_INV_SLICE_HDR_T;
+        if(ps_dec->u2_disp_width != ps_subset_seq->u2_disp_width) return ERROR_INV_SLICE_HDR_T;
+    }
+
     ps_dec->i4_reorder_depth = ps_subset_seq->i4_reorder_depth;
 
     ps_dec->u2_disp_height = ps_subset_seq->u2_disp_height;
@@ -2004,6 +2010,12 @@ WORD32 isvcd_parse_decode_slice(UWORD8 u1_is_idr_slice, UWORD8 u1_nal_ref_idc,
         if(ps_dec->u2_frm_ht_in_mbs != ps_seq->u2_frm_ht_in_mbs) return ERROR_INV_SLICE_HDR_T;
     }
 
+    if(ps_dec->u1_init_dec_flag == 1)
+    {
+        if(ps_dec->u2_disp_height != ps_subset_seq->u2_disp_height) return ERROR_INV_SLICE_HDR_T;
+        if(ps_dec->u2_disp_width != ps_subset_seq->u2_disp_width) return ERROR_INV_SLICE_HDR_T;
+    }
+
     if(ps_seq->u1_profile_idc == BASE_PROFILE_IDC)
     {
         if(ps_pps->u1_entropy_coding_mode != 0)
diff --git a/fuzzer/svc_dec_fuzzer.cpp b/fuzzer/svc_dec_fuzzer.cpp
index 6ae8747..378373d 100644
--- a/fuzzer/svc_dec_fuzzer.cpp
+++ b/fuzzer/svc_dec_fuzzer.cpp
@@ -312,7 +312,8 @@ void Codec::allocFrame()
 void Codec::decodeHeader(const uint8_t *data, size_t size)
 {
     setParams(IVD_DECODE_HEADER);
-    while(size > 0)
+    size_t numDecodeCalls = 0;
+    while(size > 0 && numDecodeCalls < kMaxNumDecodeCalls)
     {
         IV_API_CALL_STATUS_T ret;
         isvcd_video_decode_ip_t s_video_decode_ip;
@@ -339,6 +340,7 @@ void Codec::decodeHeader(const uint8_t *data, size_t size)
 
         data += bytes_consumed;
         size -= bytes_consumed;
+        numDecodeCalls++;
 
         mWidth = std::min(s_video_decode_op.s_ivd_video_decode_op_t.u4_pic_wd, (UWORD32) 10240);
         mHeight = std::min(s_video_decode_op.s_ivd_video_decode_op_t.u4_pic_ht, (UWORD32) 10240);
```

