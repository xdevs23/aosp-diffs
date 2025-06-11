```diff
diff --git a/METADATA b/METADATA
index 19a1ca4..e015327 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,19 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/libxaac
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libxaac"
 description: "Android fork of the xaac library."
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 5
-    day: 28
+    year: 2025
+    month: 1
+    day: 29
   }
   identifier {
     type: "Git"
     value: "https://github.com/ittiam-systems/libxaac.git"
-    version: "v0.1.11"
+    version: "v0.1.12"
   }
 }
diff --git a/decoder/ixheaacd_block.h b/decoder/ixheaacd_block.h
index cc7119e..4cb3ed2 100644
--- a/decoder/ixheaacd_block.h
+++ b/decoder/ixheaacd_block.h
@@ -109,9 +109,8 @@ VOID ixheaacd_set_corr_info(
 VOID ixheaacd_gen_rand_vec(WORD32 scale, WORD shift, WORD32 *spec,
                            WORD32 sfb_width, WORD32 *random_vec);
 
-VOID ixheaacd_pns_process(
-    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[], WORD32 channel,
-    ia_aac_dec_tables_struct *ptr_aac_tables);
+VOID ixheaacd_pns_process(ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[CHANNELS],
+                          WORD32 channel, ia_aac_dec_tables_struct *ptr_aac_tables);
 
 VOID ixheaacd_spec_to_overlapbuf_dec(WORD32 *ptr_overlap_buf,
                                      WORD32 *ptr_spec_coeff, WORD32 q_shift,
diff --git a/decoder/ixheaacd_channel.c b/decoder/ixheaacd_channel.c
index c53d487..f1371ec 100644
--- a/decoder/ixheaacd_channel.c
+++ b/decoder/ixheaacd_channel.c
@@ -600,11 +600,10 @@ VOID ixheaacd_read_ms_data(
 }
 
 IA_ERRORCODE ixheaacd_channel_pair_process(
-    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[], WORD32 num_ch,
-    ia_aac_dec_tables_struct *ptr_aac_tables, WORD32 total_channels,
-    WORD32 object_type, WORD32 aac_spect_data_resil_flag,
-    WORD32 aac_sf_data_resil_flag, WORD32 *in_data, WORD32 *out_data,
-    void *self_ptr) {
+    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[CHANNELS], WORD32 num_ch,
+    ia_aac_dec_tables_struct *ptr_aac_tables, WORD32 total_channels, WORD32 object_type,
+    WORD32 aac_spect_data_resil_flag, WORD32 aac_sf_data_resil_flag, WORD32 *in_data,
+    WORD32 *out_data, void *self_ptr) {
   WORD32 channel;
   IA_ERRORCODE err = IA_NO_ERROR;
   ia_aac_decoder_struct *self = self_ptr;
diff --git a/decoder/ixheaacd_channel.h b/decoder/ixheaacd_channel.h
index d223e09..ae2dc3d 100644
--- a/decoder/ixheaacd_channel.h
+++ b/decoder/ixheaacd_channel.h
@@ -41,11 +41,10 @@ enum {
 #define RIGHT 1
 
 IA_ERRORCODE ixheaacd_channel_pair_process(
-    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[], WORD32 num_ch,
-    ia_aac_dec_tables_struct *ptr_aac_tables, WORD32 total_channels,
-    WORD32 object_type, WORD32 aac_spect_data_resil_flag,
-    WORD32 aac_sf_data_resil_flag, WORD32 *in_data, WORD32 *out_data,
-    void *self_ptr);
+    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[CHANNELS], WORD32 num_ch,
+    ia_aac_dec_tables_struct *ptr_aac_tables, WORD32 total_channels, WORD32 object_type,
+    WORD32 aac_spect_data_resil_flag, WORD32 aac_sf_data_resil_flag, WORD32 *in_data,
+    WORD32 *out_data, void *self_ptr);
 
 VOID ixheaacd_map_ms_mask_pns(
     ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[CHANNELS]);
diff --git a/decoder/ixheaacd_freq_sca.c b/decoder/ixheaacd_freq_sca.c
index c59663c..f6f0c1c 100644
--- a/decoder/ixheaacd_freq_sca.c
+++ b/decoder/ixheaacd_freq_sca.c
@@ -696,7 +696,8 @@ WORD32 ixheaacd_calc_frq_bnd_tbls(ia_sbr_header_data_struct *ptr_header_data,
 
   ptr_header_data->status = 1;
 
-  if ((lsb > NO_ANALYSIS_CHANNELS) || (lsb >= usb)) {
+  if ((lsb > ((ptr_header_data->sbr_ratio_idx == SBR_UPSAMPLE_IDX_4_1) ? 16 : 32)) ||
+      (lsb >= usb)) {
     return -1;
   }
 
diff --git a/decoder/ixheaacd_mps_parse.c b/decoder/ixheaacd_mps_parse.c
index 19b7212..84c9fdc 100644
--- a/decoder/ixheaacd_mps_parse.c
+++ b/decoder/ixheaacd_mps_parse.c
@@ -688,8 +688,7 @@ static VOID ixheaacd_ld_mps_ecdata_decoding(
     ia_mps_dec_state_struct *self, ia_bit_buf_struct *it_bit_buff,
     WORD32 data[MAX_PARAMETER_SETS_MPS][MAX_PARAMETER_BANDS], WORD32 datatype,
     WORD32 start_band) {
-  WORD32 i, j, pb, data_set, set_index, bs_data_pair, data_bands,
-      old_quant_coarse_xxx;
+  WORD32 i, j, pb, set_index, bs_data_pair, data_bands, old_quant_coarse_xxx;
   WORD32 strides[MAX_PARAMETER_BANDS + 1] = {0};
   WORD32 band_stop = 0;
 
@@ -716,13 +715,9 @@ static VOID ixheaacd_ld_mps_ecdata_decoding(
     lastdata = frame->cmp_cld_idx_prev;
     band_stop = self->bs_param_bands;
   }
-  data_set = 0;
   for (i = 0; i < self->num_parameter_sets; i++) {
     frame_xxx_data->bs_xxx_data_mode[i] =
         ixheaacd_read_bits_buf(it_bit_buff, 2);
-    if (frame_xxx_data->bs_xxx_data_mode[i] == 3) {
-      data_set++;
-    }
   }
 
   set_index = 0;
diff --git a/decoder/ixheaacd_mps_polyphase.c b/decoder/ixheaacd_mps_polyphase.c
index ad309bb..8398e2c 100644
--- a/decoder/ixheaacd_mps_polyphase.c
+++ b/decoder/ixheaacd_mps_polyphase.c
@@ -826,7 +826,7 @@ VOID ixheaacd_calculate_syn_filt_bank_res64(ia_mps_dec_qmf_syn_filter_bank *syn,
   p_si = si;
   for (k = 0; k < nr_samples; k++) {
     WORD32 *new_samp = p_si;
-    WORD32 *new_samp1, *new_samp2;
+    WORD32 *new_samp2;
 
     ixheaacd_inverse_modulation(p_sr, p_si, qmf_table_ptr);
 
@@ -872,7 +872,6 @@ VOID ixheaacd_calculate_syn_filt_bank_res64(ia_mps_dec_qmf_syn_filter_bank *syn,
 
     syn_buf_p2 = synth_buf;
     syn_buf_p3 = syn_buf_p2;
-    new_samp1 = p_sr + 1;
     new_samp2 = p_sr + 63;
     for (j = 0; j < resolution - 1; j++) {
       *time_sig-- = ixheaac_add32_sat(syn_buf_p3[512],
@@ -898,7 +897,6 @@ VOID ixheaacd_calculate_syn_filt_bank_res64(ia_mps_dec_qmf_syn_filter_bank *syn,
       new_samp++;
       syn_buf_p2++;
 
-      new_samp1++;
       new_samp2--;
       syn_buf_p3++;
     }
diff --git a/decoder/ixheaacd_pns_js_thumb.c b/decoder/ixheaacd_pns_js_thumb.c
index c39b3f2..9186e41 100644
--- a/decoder/ixheaacd_pns_js_thumb.c
+++ b/decoder/ixheaacd_pns_js_thumb.c
@@ -111,9 +111,8 @@ VOID ixheaacd_gen_rand_vec(WORD32 scale, WORD shift, WORD32 *ptr_spec_coef,
   }
 }
 
-VOID ixheaacd_pns_process(
-    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[], WORD32 channel,
-    ia_aac_dec_tables_struct *ptr_aac_tables) {
+VOID ixheaacd_pns_process(ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[CHANNELS],
+                          WORD32 channel, ia_aac_dec_tables_struct *ptr_aac_tables) {
   ia_pns_info_struct *ptr_pns_info =
       &ptr_aac_dec_channel_info[channel]->str_pns_info;
   ia_ics_info_struct *ptr_ics_info =
diff --git a/decoder/ixheaacd_sbr_dec.h b/decoder/ixheaacd_sbr_dec.h
index ca605df..7ba4b5c 100644
--- a/decoder/ixheaacd_sbr_dec.h
+++ b/decoder/ixheaacd_sbr_dec.h
@@ -294,10 +294,9 @@ VOID ixheaacd_rescale_x_overlap(
     WORD32 **pp_overlap_buffer_real, WORD32 **pp_overlap_buffer_imag,
     FLAG low_pow_flag);
 
-WORD32 ixheaacd_qmf_hbe_data_reinit(
-    ia_esbr_hbe_txposer_struct *ptr_hbe_transposer_str,
-    WORD16 *ptr_freq_band_tbl[MAX_FREQ_COEFFS + 1], WORD16 *ptr_num_sf_bands,
-    WORD32 upsamp_4_flag);
+WORD32 ixheaacd_qmf_hbe_data_reinit(ia_esbr_hbe_txposer_struct *ptr_hbe_transposer_str,
+                                    WORD16 *ptr_freq_band_tbl[2], WORD16 *ptr_num_sf_bands,
+                                    WORD32 upsamp_4_flag);
 
 WORD32 ixheaacd_dft_hbe_data_reinit(ia_esbr_hbe_txposer_struct *ptr_hbe_txposer,
                                     WORD16 *p_freq_band_tab[2], WORD16 *p_num_sfb);
diff --git a/decoder/ixheaacd_sbrqmftrans.h b/decoder/ixheaacd_sbrqmftrans.h
index 3522b84..d9093c7 100644
--- a/decoder/ixheaacd_sbrqmftrans.h
+++ b/decoder/ixheaacd_sbrqmftrans.h
@@ -36,10 +36,9 @@ WORD32 ixheaacd_dft_hbe_apply(ia_esbr_hbe_txposer_struct *ptr_hbe_txposer,
                               WORD32 pitch_in_bins,
                               FLOAT32 *dft_hbe_scratch_buf);
 
-WORD32 ixheaacd_qmf_hbe_data_reinit(
-    ia_esbr_hbe_txposer_struct *ptr_hbe_transposer_str,
-    WORD16 *ptr_freq_band_tbl[MAX_FREQ_COEFFS + 1], WORD16 *ptr_num_sf_bands,
-    WORD32 upsamp_4_flag);
+WORD32 ixheaacd_qmf_hbe_data_reinit(ia_esbr_hbe_txposer_struct *ptr_hbe_transposer_str,
+                                    WORD16 *ptr_freq_band_tbl[2], WORD16 *ptr_num_sf_bands,
+                                    WORD32 upsamp_4_flag);
 
 IA_ERRORCODE ixheaacd_hbe_post_anal_process(ia_esbr_hbe_txposer_struct *ptr_hbe_txposer,
                                             WORD32 pitch_in_bins, WORD32 sbr_upsamp_4_flg);
diff --git a/decoder/ixheaacd_stereo.c b/decoder/ixheaacd_stereo.c
index 586f4c2..af92f66 100644
--- a/decoder/ixheaacd_stereo.c
+++ b/decoder/ixheaacd_stereo.c
@@ -52,7 +52,7 @@
 #include "ixheaacd_stereo.h"
 
 VOID ixheaacd_ms_stereo_process(
-    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[2],
+    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[CHANNELS],
     ia_aac_dec_tables_struct *ptr_aac_tables)
 
 {
@@ -127,9 +127,9 @@ static PLATFORM_INLINE WORD32 ixheaacd_mult32x16in32l(WORD32 a, WORD32 b) {
 }
 
 VOID ixheaacd_intensity_stereo_process(
-    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[2],
-    ia_aac_dec_tables_struct *ptr_aac_tables, WORD32 object_type,
-    WORD32 aac_sf_data_resil_flag, WORD16 framelength) {
+    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[CHANNELS],
+    ia_aac_dec_tables_struct *ptr_aac_tables, WORD32 object_type, WORD32 aac_sf_data_resil_flag,
+    WORD16 framelength) {
   UWORD8 *ptr_ms_used =
       &ptr_aac_dec_channel_info[LEFT]->pstr_stereo_info->ms_used[0][0];
   WORD8 *ptr_code_book = &ptr_aac_dec_channel_info[RIGHT]->ptr_code_book[0];
diff --git a/decoder/ixheaacd_stereo.h b/decoder/ixheaacd_stereo.h
index 8a68c60..35655b7 100644
--- a/decoder/ixheaacd_stereo.h
+++ b/decoder/ixheaacd_stereo.h
@@ -24,12 +24,12 @@ VOID ixheaacd_read_ms_data(ia_bit_buf_struct *it_bit_buff,
                            ia_aac_dec_channel_info_struct *ptr_aac_dec_ch_info);
 
 VOID ixheaacd_ms_stereo_process(
-    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[],
+    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[CHANNELS],
     ia_aac_dec_tables_struct *ptr_aac_tables);
 
 VOID ixheaacd_intensity_stereo_process(
-    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[2],
-    ia_aac_dec_tables_struct *ptr_aac_tables, WORD32 object_type,
-    WORD32 aac_sf_data_resil_flag, WORD16 framelength);
+    ia_aac_dec_channel_info_struct *ptr_aac_dec_channel_info[CHANNELS],
+    ia_aac_dec_tables_struct *ptr_aac_tables, WORD32 object_type, WORD32 aac_sf_data_resil_flag,
+    WORD16 framelength);
 
 #endif /* #ifndef IXHEAACD_STEREO_H */
diff --git a/encoder/iusace_cnst.h b/encoder/iusace_cnst.h
index fb9234e..ee44f9a 100644
--- a/encoder/iusace_cnst.h
+++ b/encoder/iusace_cnst.h
@@ -210,3 +210,4 @@
 #define MAX_PREROLL_CONFIG_SIZE (1024)
 #define CC_NUM_PREROLL_FRAMES (1)
 #define USAC_FIRST_FRAME_FLAG_DEFAULT_VALUE (1)
+#define USAC_DEFAULT_DELAY_ADJUSTMENT_VALUE (1)
diff --git a/encoder/iusace_config.h b/encoder/iusace_config.h
index bf04c69..1a46001 100644
--- a/encoder/iusace_config.h
+++ b/encoder/iusace_config.h
@@ -286,6 +286,7 @@ typedef struct {
   ia_drc_internal_config str_internal_drc_cfg;
   WORD32 use_measured_loudness;
   UWORD16 stream_id;
+  FLAG use_delay_adjustment;
 } ia_usac_encoder_config_struct;
 
 typedef struct {
diff --git a/encoder/ixheaace_api.c b/encoder/ixheaace_api.c
index 2fadb8e..6d5c47e 100644
--- a/encoder/ixheaace_api.c
+++ b/encoder/ixheaace_api.c
@@ -158,8 +158,20 @@ static WORD32 iusace_calc_pers_buf_sizes(ixheaace_api_struct *pstr_api_struct) {
       (IXHEAAC_GET_SIZE_ALIGNED((2 * pstr_config->ccfl * sizeof(FLOAT32)), BYTE_ALIGN_8) *
        pstr_config->channels);
   pers_size += (IXHEAAC_GET_SIZE_ALIGNED((2 * pstr_config->drc_frame_size * sizeof(FLOAT32)),
-                                          BYTE_ALIGN_8) *
+                                         BYTE_ALIGN_8) *
                 pstr_config->channels);
+  if (pstr_config->use_delay_adjustment == 1) {
+    pers_size +=
+        (IXHEAAC_GET_SIZE_ALIGNED(
+             ((CC_DELAY_ADJUSTMENT * pstr_config->ccfl) / FRAME_LEN_1024) * sizeof(FLOAT32),
+             BYTE_ALIGN_8) *
+         pstr_config->channels);
+    pers_size += (IXHEAAC_GET_SIZE_ALIGNED(
+                      ((CC_DELAY_ADJUSTMENT * pstr_config->drc_frame_size) / FRAME_LEN_1024) *
+                          sizeof(FLOAT32),
+                      BYTE_ALIGN_8) *
+                  pstr_config->channels);
+  }
 
   pers_size +=
       (IXHEAAC_GET_SIZE_ALIGNED((2 * pstr_config->ccfl * sizeof(FLOAT64)), BYTE_ALIGN_8) *
@@ -531,6 +543,7 @@ static VOID ixheaace_set_default_config(ixheaace_api_struct *pstr_api_struct,
     pstr_usac_config->is_first_frame = USAC_FIRST_FRAME_FLAG_DEFAULT_VALUE;
     pstr_usac_config->num_preroll_frames = CC_NUM_PREROLL_FRAMES;
     pstr_usac_config->stream_id = USAC_DEFAULT_STREAM_ID_VALUE;
+    pstr_usac_config->use_delay_adjustment = USAC_DEFAULT_DELAY_ADJUSTMENT_VALUE;
   }
   /* Initialize table pointers */
   ia_enhaacplus_enc_init_aac_tabs(&(pstr_api_struct->pstr_aac_tabs));
@@ -731,6 +744,10 @@ static IA_ERRORCODE ixheaace_validate_config_params(ixheaace_input_config *pstr_
         pstr_input_config->sample_peak_level < MIN_SAMPLE_PEAK_LEVEL) {
       pstr_input_config->sample_peak_level = DEFAULT_SAMPLE_PEAK_VALUE;
     }
+    if (pstr_input_config->use_delay_adjustment != 0 &&
+        pstr_input_config->use_delay_adjustment != 1) {
+      pstr_input_config->use_delay_adjustment = USAC_DEFAULT_DELAY_ADJUSTMENT_VALUE;
+    }
     if (pstr_input_config->use_drc_element) {
       ia_drc_input_config *pstr_drc_cfg = (ia_drc_input_config *)pstr_input_config->pv_drc_cfg;
       err_code = impd_drc_validate_config_params(pstr_drc_cfg);
@@ -749,6 +766,7 @@ static IA_ERRORCODE ixheaace_validate_config_params(ixheaace_input_config *pstr_
     pstr_input_config->inter_tes_active = 0;
     pstr_input_config->use_drc_element = 0;
     pstr_input_config->hq_esbr = 0;
+    pstr_input_config->use_delay_adjustment = 0;
     if (pstr_input_config->i_channels != 2 && pstr_input_config->aot == AOT_PS) {
       pstr_input_config->aot = AOT_SBR;
     }
@@ -972,7 +990,7 @@ static IA_ERRORCODE ixheaace_set_config_params(ixheaace_api_struct *pstr_api_str
                     (pstr_usac_config->ccfl * 1000 - 1)) /
                    (pstr_usac_config->ccfl * 1000));
     }
-
+    pstr_usac_config->use_delay_adjustment = pstr_input_config->use_delay_adjustment;
     if (pstr_usac_config->random_access_interval) {
       pstr_usac_config->preroll_flag = 1;
     }
@@ -981,6 +999,10 @@ static IA_ERRORCODE ixheaace_set_config_params(ixheaace_api_struct *pstr_api_str
       if (pstr_usac_config->sbr_harmonic == 1) {
         pstr_usac_config->num_preroll_frames++;
       }
+    } else {
+      if (pstr_usac_config->use_delay_adjustment == 1) {
+        pstr_usac_config->num_preroll_frames++;
+      }
     }
     pstr_usac_config->stream_id = pstr_input_config->stream_id;
     if (pstr_input_config->ccfl_idx < NO_SBR_CCFL_768 || pstr_input_config->ccfl_idx > SBR_4_1) {
@@ -1645,6 +1667,12 @@ static IA_ERRORCODE ixheaace_alloc_and_assign_mem(ixheaace_api_struct *pstr_api_
             p_offset += IXHEAAC_GET_SIZE_ALIGNED(
                 (pstr_usac_config->drc_frame_size * sizeof(pstr_state->pp_drc_in_buf[0][0]) * 2),
                 BYTE_ALIGN_8);
+            if (pstr_usac_config->use_delay_adjustment == 1) {
+              p_offset += IXHEAAC_GET_SIZE_ALIGNED(
+                  ((CC_DELAY_ADJUSTMENT * pstr_usac_config->drc_frame_size) / FRAME_LEN_1024) *
+                      sizeof(pstr_state->pp_drc_in_buf[0][0]),
+                  BYTE_ALIGN_8);
+            }
           }
           memset(p_temp, 0, (p_offset - p_temp));
         }
@@ -1653,7 +1681,13 @@ static IA_ERRORCODE ixheaace_alloc_and_assign_mem(ixheaace_api_struct *pstr_api_
         for (i = 0; i < pstr_usac_config->channels; i++) {
           pstr_state->ptr_in_buf[i] = (FLOAT32 *)(p_offset);
           p_offset += IXHEAAC_GET_SIZE_ALIGNED((pstr_usac_config->ccfl * sizeof(FLOAT32) * 2),
-                                                BYTE_ALIGN_8);
+                                               BYTE_ALIGN_8);
+          if (pstr_usac_config->use_delay_adjustment) {
+            p_offset += IXHEAAC_GET_SIZE_ALIGNED(
+                ((CC_DELAY_ADJUSTMENT * pstr_usac_config->ccfl) / FRAME_LEN_1024) *
+                    sizeof(FLOAT32),
+                BYTE_ALIGN_8);
+          }
         }
         memset(p_temp, 0, (p_offset - p_temp));
 
@@ -2024,7 +2058,7 @@ static IA_ERRORCODE ia_usac_enc_init(ixheaace_api_struct *pstr_api_struct, WORD3
         (pstr_api_struct->pstr_state->mps_enable != 1) ? pstr_config->i_channels : 1,
         pstr_usac_config->core_sample_rate, AACENC_TRANS_FAC, 24000,
         pstr_api_struct->spectral_band_replication_tabs.ptr_qmf_tab,
-        pstr_api_struct->pstr_state->aot);
+        pstr_api_struct->pstr_state->aot, (pstr_api_struct->config[0].ccfl_idx == SBR_4_1));
 
     error = ixheaace_env_open(
         &pstr_api_struct->pstr_state->spectral_band_replication_enc_pers_mem[0],
@@ -2528,11 +2562,11 @@ static IA_ERRORCODE ia_enhaacplus_enc_init(ixheaace_api_struct *pstr_api_struct,
       }
     }
 
-    ixheaace_adjust_sbr_settings(&spectral_band_replication_config, pstr_aac_config->bit_rate,
-                                 pstr_aac_config->num_out_channels, core_sample_rate,
-                                 AACENC_TRANS_FAC, 24000,
-                                 pstr_api_struct->spectral_band_replication_tabs.ptr_qmf_tab,
-                                 pstr_api_struct->pstr_state->aot);
+    ixheaace_adjust_sbr_settings(
+        &spectral_band_replication_config, pstr_aac_config->bit_rate,
+        pstr_aac_config->num_out_channels, core_sample_rate, AACENC_TRANS_FAC, 24000,
+        pstr_api_struct->spectral_band_replication_tabs.ptr_qmf_tab,
+        pstr_api_struct->pstr_state->aot, (pstr_api_struct->config[0].ccfl_idx == SBR_4_1));
 
     if (pstr_api_struct->config[ele_idx].element_type != ID_LFE) {
       /* open SBR PART, set core bandwidth */
@@ -3003,16 +3037,14 @@ static IA_ERRORCODE iusace_process(ixheaace_api_struct *pstr_api_struct) {
   UWORD32 padding_bits = 0;
   WORD32 core_sample;
   WORD32 drc_sample;
-  WORD32 i4_inp_data;
   WORD32 ptr_inp_buf_offset = 0;
   WORD32 num_ch;
   WORD16 *ps_inp_buf = NULL;
-  WORD8 *pi1_inp_buf = NULL;
   WORD8 *ps_out_buf = NULL;
-  WORD32 *pi4_inp_buf = NULL;
   FLOAT32 *ptr_input_buffer = NULL;
   FLOAT32 *ptr_inp_buf[MAX_TIME_CHANNELS];
   FLOAT32 *ptr_drc_inp_buf[MAX_TIME_CHANNELS];
+  WORD32 delay = 0;
   ixheaace_state_struct *pstr_state = pstr_api_struct->pstr_state;
   ia_bit_buf_struct *pstr_it_bit_buff = &pstr_state->str_bit_buf;
   ia_usac_encoder_config_struct *pstr_config = &pstr_api_struct->config[0].usac_config;
@@ -3026,11 +3058,13 @@ static IA_ERRORCODE iusace_process(ixheaace_api_struct *pstr_api_struct) {
   num_ch = pstr_config->channels;
   usac_independency_flg = pstr_usac_data->usac_independency_flag;
   ps_inp_buf = (WORD16 *)pstr_api_struct->pp_mem[IA_MEMTYPE_INPUT];
-  pi1_inp_buf = (WORD8 *)pstr_api_struct->pp_mem[IA_MEMTYPE_INPUT];
   ps_out_buf = (WORD8 *)pstr_api_struct->pp_mem[IA_MEMTYPE_OUTPUT];
 
   if (pstr_config->use_drc_element) {
-    for (idx = 0; idx < core_sample; idx++) {
+    if (pstr_config->use_delay_adjustment == 1) {
+      delay = (CC_DELAY_ADJUSTMENT * pstr_config->drc_frame_size / FRAME_LEN_1024) * num_ch;
+    }
+    for (idx = 0; idx < core_sample + delay; idx++) {
       pstr_api_struct->pstr_state->pp_drc_in_buf[idx % num_ch][idx / num_ch] =
           pstr_api_struct->pstr_state
               ->pp_drc_in_buf[idx % num_ch][idx / num_ch + pstr_config->drc_frame_size];
@@ -3074,6 +3108,21 @@ static IA_ERRORCODE iusace_process(ixheaace_api_struct *pstr_api_struct) {
     }
 
     write_off_set = INPUT_DELAY_LC * IXHEAACE_MAX_CH_IN_BS_ELE;
+
+    if (pstr_config->use_delay_adjustment == 1) {
+      if (pstr_api_struct->config[0].ccfl_idx == SBR_4_1) {
+        write_off_set += SBR_4_1_DELAY_ADJUSTMENT * IXHEAACE_MAX_CH_IN_BS_ELE;
+      } else if (pstr_api_struct->config[0].ccfl_idx == SBR_2_1) {
+        write_off_set += SBR_2_1_DELAY_ADJUSTMENT * IXHEAACE_MAX_CH_IN_BS_ELE;
+      } else {
+        write_off_set += SBR_8_3_DELAY_ADJUSTMENT * IXHEAACE_MAX_CH_IN_BS_ELE;
+      }
+    }
+
+    if (pstr_api_struct->config[0].ccfl_idx == SBR_4_1) {
+      write_off_set = write_off_set * 2;
+    }
+
     if (pstr_api_struct->pstr_state->downsample[0]) {
       if (pstr_api_struct->config[0].ccfl_idx == SBR_8_3) {
         write_off_set +=
@@ -3144,30 +3193,8 @@ static IA_ERRORCODE iusace_process(ixheaace_api_struct *pstr_api_struct) {
 
     if (num_ch == 2) {
       if (1 == pstr_config->use_drc_element) {
-        if (16 == pstr_config->ui_pcm_wd_sz) {
-          for (idx = 0; idx < drc_sample; idx++) {
-            ptr_drc_inp_buf[idx % num_ch][idx / num_ch + ptr_inp_buf_offset] =
-                ptr_input_buffer[idx];
-          }
-        } else if (24 == pstr_config->ui_pcm_wd_sz) {
-          for (idx = 0; idx < drc_sample; idx++) {
-            i4_inp_data = ((WORD32)(*pi1_inp_buf)) & 0xFF;
-            pi1_inp_buf++;
-            i4_inp_data += ((WORD32)(*pi1_inp_buf) << 8) & 0xFFFF;
-            pi1_inp_buf++;
-            i4_inp_data += ((WORD32)(*pi1_inp_buf) << 16) & 0xFFFFFF;
-            pi1_inp_buf++;
-            i4_inp_data = i4_inp_data - (i4_inp_data >> 23 << 24);
-            ptr_drc_inp_buf[idx % num_ch][idx / num_ch + ptr_inp_buf_offset] =
-                (FLOAT32)i4_inp_data / DIV_FAC_24_BIT_PCM;
-          }
-        } else if (32 == pstr_config->ui_pcm_wd_sz) {
-          pi4_inp_buf = (WORD32 *)pi1_inp_buf;
-          for (idx = 0; idx < drc_sample; idx++) {
-            i4_inp_data = *pi4_inp_buf++;
-            ptr_drc_inp_buf[idx % num_ch][idx / num_ch + ptr_inp_buf_offset] =
-                (FLOAT32)i4_inp_data / DIV_FAC_32_BIT_PCM;
-          }
+        for (idx = 0; idx < drc_sample; idx++) {
+          ptr_drc_inp_buf[idx % num_ch][(idx >> 1) + ptr_inp_buf_offset] = ptr_input_buffer[idx];
         }
       }
 
@@ -3296,33 +3323,12 @@ static IA_ERRORCODE iusace_process(ixheaace_api_struct *pstr_api_struct) {
 
       FLOAT32 *time_signal = pstr_api_struct->pstr_state->time_signal;
       for (idx = 0; idx < num_samples_read; idx++) {
-        time_signal[idx] = (FLOAT32)ptr_input_buffer[2 * idx];
+        time_signal[idx] = (FLOAT32)ptr_input_buffer[idx << 1];
       }
 
       if (1 == pstr_config->use_drc_element) {
-        if (16 == pstr_config->ui_pcm_wd_sz) {
-          for (idx = 0; idx < drc_sample; idx++) {
-            ptr_drc_inp_buf[idx % num_ch][idx / num_ch + ptr_inp_buf_offset] = time_signal[idx];
-          }
-        } else if (24 == pstr_config->ui_pcm_wd_sz) {
-          for (idx = 0; idx < drc_sample; idx++) {
-            i4_inp_data = ((WORD32)(*pi1_inp_buf)) & 0xFF;
-            pi1_inp_buf++;
-            i4_inp_data += ((WORD32)(*pi1_inp_buf) << 8) & 0xFFFF;
-            pi1_inp_buf++;
-            i4_inp_data += ((WORD32)(*pi1_inp_buf) << 16) & 0xFFFFFF;
-            pi1_inp_buf++;
-            i4_inp_data = i4_inp_data - (i4_inp_data >> 23 << 24);
-            ptr_drc_inp_buf[idx % num_ch][idx / num_ch + ptr_inp_buf_offset] =
-                (FLOAT32)i4_inp_data / DIV_FAC_24_BIT_PCM;
-          }
-        } else if (32 == pstr_config->ui_pcm_wd_sz) {
-          pi4_inp_buf = (WORD32 *)pi1_inp_buf;
-          for (idx = 0; idx < drc_sample; idx++) {
-            i4_inp_data = *pi4_inp_buf++;
-            ptr_drc_inp_buf[idx % num_ch][idx / num_ch + ptr_inp_buf_offset] =
-                (FLOAT32)i4_inp_data / DIV_FAC_32_BIT_PCM;
-          }
+        for (idx = 0; idx < drc_sample; idx++) {
+          ptr_drc_inp_buf[0][idx + ptr_inp_buf_offset] = time_signal[idx];
         }
       }
 
@@ -3345,9 +3351,12 @@ static IA_ERRORCODE iusace_process(ixheaace_api_struct *pstr_api_struct) {
       ixheaace_get_input_scratch_buf(pstr_api_struct->pstr_state->ptr_temp_buff_resamp,
                                      &in_buffer_temp);
       if (pstr_api_struct->config[0].ccfl_idx == SBR_8_3) {
+        if (pstr_config->use_delay_adjustment == 1) {
+          delay = SBR_8_3_DELAY_ADJUSTMENT * IXHEAACE_MAX_CH_IN_BS_ELE;
+        }
         WORD32 input_tot = num_samples_read / pstr_api_struct->config[0].i_channels;
         ixheaace_upsampling_inp_buf_generation(ptr_input_buffer, in_buffer_temp, input_tot,
-                                               UPSAMPLE_FAC, write_off_set);
+                                               UPSAMPLE_FAC, write_off_set - delay);
       }
 
       for (ch = 0; ch < num_ch; ch++) {
@@ -3373,10 +3382,16 @@ static IA_ERRORCODE iusace_process(ixheaace_api_struct *pstr_api_struct) {
               shared_buf1_ring, shared_buf2_ring, pstr_scratch_resampler);
         } else {
           WORD32 out_stride = IXHEAACE_MAX_CH_IN_BS_ELE * resamp_ratio;
-
+          if (pstr_config->use_delay_adjustment == 1) {
+            if (pstr_api_struct->config[0].ccfl_idx == SBR_2_1) {
+              delay = out_stride * SBR_2_1_DELAY_ADJUSTMENT;
+            } else {
+              delay = out_stride * SBR_4_1_DELAY_ADJUSTMENT;
+            }
+          }
           ia_enhaacplus_enc_iir_downsampler(
               &(pstr_api_struct->pstr_state->down_sampler[0][ch]),
-              ptr_input_buffer + write_off_set + ch,
+              ptr_input_buffer + write_off_set - delay + ch,
               num_samples_read / pstr_api_struct->config[0].i_channels, IXHEAACE_MAX_CH_IN_BS_ELE,
               ptr_input_buffer + ch, &out_samples, out_stride, shared_buf1_ring, shared_buf2_ring,
               pstr_scratch_resampler);
@@ -3389,87 +3404,33 @@ static IA_ERRORCODE iusace_process(ixheaace_api_struct *pstr_api_struct) {
         ptr_inp_buf[idx] = pstr_api_struct->pstr_state->ptr_in_buf[idx];
       }
 
-      if (16 == pstr_config->ui_pcm_wd_sz) {
-        if (num_ch == 1) {
-          for (idx = 0; idx < core_sample; idx++) {
-            ptr_inp_buf[idx % num_ch][idx / num_ch] = ptr_input_buffer[2 * idx];
-          }
-        } else {
-          for (idx = 0; idx < core_sample; idx++) {
-            ptr_inp_buf[idx % num_ch][idx / num_ch] = ptr_input_buffer[idx];
-          }
-        }
-      } else if (24 == pstr_config->ui_pcm_wd_sz) {
+      if (num_ch == 1) {
         for (idx = 0; idx < core_sample; idx++) {
-          i4_inp_data = ((WORD32)(*pi1_inp_buf)) & 0xFF;
-          pi1_inp_buf++;
-          i4_inp_data += ((WORD32)(*pi1_inp_buf) << 8) & 0xFFFF;
-          pi1_inp_buf++;
-          i4_inp_data += ((WORD32)(*pi1_inp_buf) << 16) & 0xFFFFFF;
-          pi1_inp_buf++;
-          i4_inp_data = i4_inp_data - (i4_inp_data >> 23 << 24);
-          ptr_inp_buf[idx % num_ch][idx / num_ch] = (FLOAT32)i4_inp_data / DIV_FAC_24_BIT_PCM;
-        }
-      } else if (32 == pstr_config->ui_pcm_wd_sz) {
-        pi4_inp_buf = (WORD32 *)pi1_inp_buf;
+          ptr_inp_buf[0][idx] = ptr_input_buffer[idx << 1];
+        }
+      } else {
         for (idx = 0; idx < core_sample; idx++) {
-          i4_inp_data = *pi4_inp_buf++;
-          ptr_inp_buf[idx % num_ch][idx / num_ch] = (FLOAT32)i4_inp_data / DIV_FAC_32_BIT_PCM;
+          ptr_inp_buf[idx % num_ch][idx / num_ch] = ptr_input_buffer[idx];
         }
       }
     }
   } else {
+    if (pstr_config->use_delay_adjustment == 1) {
+      delay = ((CC_DELAY_ADJUSTMENT * core_coder_frame_length) / FRAME_LEN_1024) * num_ch;
+    }
     if (num_ch != 0) {
       for (idx = 0; idx < num_ch; idx++) {
         ptr_inp_buf[idx] = pstr_api_struct->pstr_state->ptr_in_buf[idx];
       }
 
-      if (16 == pstr_config->ui_pcm_wd_sz) {
-        for (idx = 0; idx < core_sample; idx++) {
-          ptr_inp_buf[idx % num_ch][idx / num_ch] = ps_inp_buf[idx];
-        }
-      } else if (24 == pstr_config->ui_pcm_wd_sz) {
-        for (idx = 0; idx < core_sample; idx++) {
-          i4_inp_data = ((WORD32)(*pi1_inp_buf)) & 0xFF;
-          pi1_inp_buf++;
-          i4_inp_data += ((WORD32)(*pi1_inp_buf) << 8) & 0xFFFF;
-          pi1_inp_buf++;
-          i4_inp_data += ((WORD32)(*pi1_inp_buf) << 16) & 0xFFFFFF;
-          pi1_inp_buf++;
-          i4_inp_data = i4_inp_data - (i4_inp_data >> 23 << 24);
-          ptr_inp_buf[idx % num_ch][idx / num_ch] = (FLOAT32)i4_inp_data / DIV_FAC_24_BIT_PCM;
-        }
-      } else if (32 == pstr_config->ui_pcm_wd_sz) {
-        pi4_inp_buf = (WORD32 *)pi1_inp_buf;
-        for (idx = 0; idx < core_sample; idx++) {
-          i4_inp_data = *pi4_inp_buf++;
-          ptr_inp_buf[idx % num_ch][idx / num_ch] = (FLOAT32)i4_inp_data / DIV_FAC_32_BIT_PCM;
-        }
+      for (idx = 0; idx < core_sample; idx++) {
+        ptr_inp_buf[idx % num_ch][(idx + delay) / num_ch] = ps_inp_buf[idx];
       }
+
       if (1 == pstr_config->use_drc_element) {
-        if (16 == pstr_config->ui_pcm_wd_sz) {
-          for (idx = 0; idx < drc_sample; idx++) {
-            ptr_drc_inp_buf[idx % num_ch][idx / num_ch + ptr_inp_buf_offset] = ps_inp_buf[idx];
-          }
-        } else if (24 == pstr_config->ui_pcm_wd_sz) {
-          for (idx = 0; idx < drc_sample; idx++) {
-            i4_inp_data = ((WORD32)(*pi1_inp_buf)) & 0xFF;
-            pi1_inp_buf++;
-            i4_inp_data += ((WORD32)(*pi1_inp_buf) << 8) & 0xFFFF;
-            pi1_inp_buf++;
-            i4_inp_data += ((WORD32)(*pi1_inp_buf) << 16) & 0xFFFFFF;
-            pi1_inp_buf++;
-            i4_inp_data = i4_inp_data - (i4_inp_data >> 23 << 24);
-            ptr_drc_inp_buf[idx % num_ch][idx / num_ch + ptr_inp_buf_offset] =
-                (FLOAT32)i4_inp_data / DIV_FAC_24_BIT_PCM;
-          }
-        } else if (32 == pstr_config->ui_pcm_wd_sz) {
-          pi4_inp_buf = (WORD32 *)pi1_inp_buf;
-          for (idx = 0; idx < drc_sample; idx++) {
-            i4_inp_data = *pi4_inp_buf++;
-            ptr_drc_inp_buf[idx % num_ch][idx / num_ch + ptr_inp_buf_offset] =
-                (FLOAT32)i4_inp_data / DIV_FAC_32_BIT_PCM;
-          }
+        for (idx = 0; idx < drc_sample; idx++) {
+          ptr_drc_inp_buf[idx % num_ch][(idx + delay) / num_ch + ptr_inp_buf_offset] =
+              ps_inp_buf[idx];
         }
       }
     }
@@ -3535,6 +3496,11 @@ static IA_ERRORCODE iusace_process(ixheaace_api_struct *pstr_api_struct) {
       memmove(ptr_input_buffer, ptr_input_buffer + num_samples,
               write_off_set * sizeof(ptr_input_buffer[0]));
     }
+  } else if (!pstr_config->sbr_enable && pstr_config->use_delay_adjustment) {
+    for (idx = 0; idx < num_ch; idx++) {
+      memmove(&ptr_inp_buf[idx][0], &ptr_inp_buf[idx][core_sample / num_ch],
+              sizeof(ptr_inp_buf[idx][0]) * delay / num_ch);
+    }
   }
 
   return IA_NO_ERROR;
@@ -3914,6 +3880,15 @@ IA_ERRORCODE ixheaace_init(pVOID pstr_obj_ixheaace, pVOID pv_input, pVOID pv_out
 
   pstr_api_struct->pstr_state->ui_init_done = 1;
   pstr_output_config->i_out_bytes = pstr_api_struct->pstr_state->i_out_bytes;
+  if (pstr_output_config->input_size) {
+    pstr_output_config->expected_frame_count =
+        (pstr_input_config->aac_config.length + (pstr_output_config->input_size - 1)) /
+        pstr_output_config->input_size;
+    if (pstr_api_struct->config[0].usac_config.use_delay_adjustment == 1) {
+      pstr_output_config->expected_frame_count -=
+          pstr_api_struct->config[0].usac_config.num_preroll_frames;
+    }
+  }
 
   return error;
 }
diff --git a/encoder/ixheaace_api.h b/encoder/ixheaace_api.h
index 3c99db2..64e8ea0 100644
--- a/encoder/ixheaace_api.h
+++ b/encoder/ixheaace_api.h
@@ -115,6 +115,7 @@ typedef struct {
   UWORD32 measurement_system;
   FLOAT32 sample_peak_level;
   UWORD16 stream_id;
+  FLAG use_delay_adjustment;
 } ixheaace_input_config;
 
 typedef struct {
@@ -140,7 +141,7 @@ typedef struct {
   WORD32 header_samp_freq;
   WORD32 audio_profile;
   FLOAT32 down_sampling_ratio;
-  pWORD32 pb_inp_buf_32;
+  WORD32 expected_frame_count;
 } ixheaace_output_config;
 
 typedef struct {
diff --git a/encoder/ixheaace_loudness_measurement.c b/encoder/ixheaace_loudness_measurement.c
index dfb01b3..6491a7c 100644
--- a/encoder/ixheaace_loudness_measurement.c
+++ b/encoder/ixheaace_loudness_measurement.c
@@ -354,8 +354,12 @@ FLOAT64 ixheaace_measure_integrated_loudness(pVOID loudness_handle) {
   pstr_loudness_hdl->no_of_mf_passing_rel_gate = 0;
   pstr_loudness_hdl->tot_int_val_mf_passing_rel_gate = 0;
 
-  avg = (pstr_loudness_hdl->tot_int_val_mf_passing_abs_gate /
-         pstr_loudness_hdl->no_of_mf_passing_abs_gate);
+  if (pstr_loudness_hdl->no_of_mf_passing_abs_gate) {
+    avg = (pstr_loudness_hdl->tot_int_val_mf_passing_abs_gate /
+           pstr_loudness_hdl->no_of_mf_passing_abs_gate);
+  } else {
+    avg = IXHEAACE_SUM_SQUARE_EPS / pstr_loudness_hdl->num_samples_per_ch;
+  }
   pstr_loudness_hdl->rel_gate = -0.691 + 10 * log10(avg) - 10;
 
   while (count < pstr_loudness_hdl->ml_count_fn_call) {
@@ -368,8 +372,13 @@ FLOAT64 ixheaace_measure_integrated_loudness(pVOID loudness_handle) {
     count++;
   }
 
-  loudness = -0.691 + 10 * log10((pstr_loudness_hdl->tot_int_val_mf_passing_rel_gate /
-                                  (FLOAT64)pstr_loudness_hdl->no_of_mf_passing_rel_gate));
+  if (pstr_loudness_hdl->no_of_mf_passing_rel_gate) {
+    loudness = -0.691 + 10 * log10((pstr_loudness_hdl->tot_int_val_mf_passing_rel_gate /
+                                    (FLOAT64)pstr_loudness_hdl->no_of_mf_passing_rel_gate));
+  } else {
+    loudness =
+        -0.691 + 10 * log10(IXHEAACE_SUM_SQUARE_EPS / pstr_loudness_hdl->num_samples_per_ch);
+  }
 
   return loudness;
 }
diff --git a/encoder/ixheaace_loudness_measurement.h b/encoder/ixheaace_loudness_measurement.h
index 3856d99..bbb66d3 100644
--- a/encoder/ixheaace_loudness_measurement.h
+++ b/encoder/ixheaace_loudness_measurement.h
@@ -32,6 +32,7 @@
 #define IXHEAACE_DEFAULT_SHORT_TERM_LOUDENSS (-1000)
 #define IXHEAACE_DEFAULT_MOMENTARY_LOUDENSS (-1000)
 #define IXHEAACE_SEC_TO_100MS_FACTOR (60 * 10)
+#define IXHEAACE_SUM_SQUARE_EPS (1/32768.0f * 1/32768.0f)
 
 typedef struct {
   BOOL passes_abs_gate;
diff --git a/encoder/ixheaace_rom.h b/encoder/ixheaace_rom.h
index f70f799..eb9e882 100644
--- a/encoder/ixheaace_rom.h
+++ b/encoder/ixheaace_rom.h
@@ -163,6 +163,11 @@ input buffer (1ch)
 /* For 1:3 resampler -> max phase delay * resamp_fac */
 #define MAXIMUM_DS_1_3_FILTER_DELAY (36)
 
+#define CC_DELAY_ADJUSTMENT (448)
+#define SBR_2_1_DELAY_ADJUSTMENT (-70)
+#define SBR_4_1_DELAY_ADJUSTMENT (218)
+#define SBR_8_3_DELAY_ADJUSTMENT (-74)
+
 extern const FLOAT32 ixheaace_fd_quant_table[257];
 extern const FLOAT32 ixheaace_fd_inv_quant_table[257];
 extern const FLOAT32 ixheaace_pow_4_3_table[64];
diff --git a/encoder/ixheaace_sbr_env_est.c b/encoder/ixheaace_sbr_env_est.c
index 4011802..a02e0bd 100644
--- a/encoder/ixheaace_sbr_env_est.c
+++ b/encoder/ixheaace_sbr_env_est.c
@@ -201,8 +201,8 @@ static IA_ERRORCODE ixheaace_calculate_sbr_envelope(
 
   i = 0;
   while (i < n_envelopes) {
-    start_pos = time_step * pstr_const_frame_info->borders[i];
-    stop_pos = time_step * pstr_const_frame_info->borders[i + 1];
+    start_pos = pstr_const_frame_info->borders[i];
+    stop_pos = pstr_const_frame_info->borders[i + 1];
     freq_res = pstr_const_frame_info->freq_res[i];
     num_bands = pstr_sbr_cfg->num_scf[freq_res];
 
@@ -216,7 +216,7 @@ static IA_ERRORCODE ixheaace_calculate_sbr_envelope(
           stop_pos = stop_pos - temp;
         }
       } else {
-        stop_pos = stop_pos - time_step;
+        stop_pos = stop_pos - 1;
       }
     }
     for (j = 0; j < num_bands; j++) {
@@ -265,14 +265,22 @@ static IA_ERRORCODE ixheaace_calculate_sbr_envelope(
       if (missing_harmonic) {
         count = stop_pos - start_pos;
         for (l = start_pos; l < stop_pos; l++) {
-          energy_left += ptr_y_buf_left[l / 2][li];
+          if (pstr_sbr_cfg->is_ld_sbr) {
+            energy_left += ptr_y_buf_left[l >> 1][li];
+          } else {
+            energy_left += ptr_y_buf_left[l][li];
+          }
         }
 
         k = li + 1;
         while (k < ui) {
           tmp_ene_l = 0.0f;
           for (l = start_pos; l < stop_pos; l++) {
-            tmp_ene_l += ptr_y_buf_left[l / 2][k];
+            if (pstr_sbr_cfg->is_ld_sbr) {
+              tmp_ene_l += ptr_y_buf_left[l >> 1][k];
+            } else {
+              tmp_ene_l += ptr_y_buf_left[l][k];
+            }
           }
 
           if (tmp_ene_l > energy_left) {
@@ -291,14 +299,22 @@ static IA_ERRORCODE ixheaace_calculate_sbr_envelope(
 
         if (stereo_mode == SBR_COUPLING) {
           for (l = start_pos; l < stop_pos; l++) {
-            energy_right += ptr_y_buf_right[l / 2][li];
+            if (pstr_sbr_cfg->is_ld_sbr) {
+              energy_right += ptr_y_buf_right[l >> 1][li];
+            } else {
+              energy_right += ptr_y_buf_right[l][li];
+            }
           }
 
           k = li + 1;
           while (k < ui) {
             tmp_ene_r = 0.0f;
             for (l = start_pos; l < stop_pos; l++) {
-              tmp_ene_r += ptr_y_buf_right[l / 2][k];
+              if (pstr_sbr_cfg->is_ld_sbr) {
+                tmp_ene_r += ptr_y_buf_right[l >> 1][k];
+              } else {
+                tmp_ene_r += ptr_y_buf_right[l][k];
+              }
             }
 
             if (tmp_ene_r > energy_right) {
@@ -314,10 +330,9 @@ static IA_ERRORCODE ixheaace_calculate_sbr_envelope(
               energy_right = energy_right * 0.5f;
             }
           }
-
           tmp_ene_l = energy_left;
           energy_left = (energy_left + energy_right) * 0.5f;
-          energy_right = (tmp_ene_l + 1) / (energy_right + 1);
+          energy_right = ((tmp_ene_l * time_step) + 1) / ((energy_right * time_step) + 1);
         }
       } else {
         count = (stop_pos - start_pos) * (ui - li);
@@ -325,11 +340,7 @@ static IA_ERRORCODE ixheaace_calculate_sbr_envelope(
         k = li;
         while (k < ui) {
           for (l = start_pos; l < stop_pos; l++) {
-            if (pstr_sbr_cfg->is_ld_sbr) {
-              energy_left += ptr_y_buf_left[l][k];
-            } else {
-              energy_left += ptr_y_buf_left[l / 2][k];
-            }
+            energy_left += ptr_y_buf_left[l][k];
           }
           k++;
         }
@@ -338,17 +349,21 @@ static IA_ERRORCODE ixheaace_calculate_sbr_envelope(
           k = li;
           while (k < ui) {
             for (l = start_pos; l < stop_pos; l++) {
-              energy_right += ptr_y_buf_right[l / 2][k];
+              if (pstr_sbr_cfg->is_ld_sbr) {
+                energy_right += ptr_y_buf_right[l >> 1][k];
+              } else {
+                energy_right += ptr_y_buf_right[l][k];
+              }
             }
             k++;
           }
           tmp_ene_l = energy_left;
           energy_left = (energy_left + energy_right) * 0.5f;
-          energy_right = (tmp_ene_l + 1) / (energy_right + 1);
+          energy_right = ((tmp_ene_l * time_step) + 1) / ((energy_right * time_step) + 1);
         }
       }
 
-      energy_left = (FLOAT32)(log(energy_left / (count * 64) + EPS) * SBR_INV_LOG_2);
+      energy_left = (FLOAT32)(log((energy_left / (count * 64)) + EPS) * SBR_INV_LOG_2);
 
       if (energy_left < 0.0f) {
         energy_left = 0.0f;
@@ -374,8 +389,9 @@ static IA_ERRORCODE ixheaace_calculate_sbr_envelope(
 
       for (j = 0; j < num_bands; j++) {
         if (freq_res == FREQ_RES_HIGH && pstr_sbr->str_sbr_extract_env.envelope_compensation[j]) {
-          ptr_sfb_ene_l[m] -= (WORD32)(
-              ca * ixheaac_abs32(pstr_sbr->str_sbr_extract_env.envelope_compensation[j]));
+          ptr_sfb_ene_l[m] -=
+              (WORD32)(ca *
+                       ixheaac_abs32(pstr_sbr->str_sbr_extract_env.envelope_compensation[j]));
         }
 
         if (ptr_sfb_ene_l[m] < 0) {
@@ -2124,17 +2140,22 @@ IA_ERRORCODE ixheaace_extract_sbr_envelope(FLOAT32 *ptr_in_time, FLOAT32 *ptr_co
         pstr_sbr_extract_env->ptr_y_buffer + pstr_sbr_extract_env->y_buffer_write_offset,
         pstr_sbr_extract_env->ptr_r_buffer, pstr_sbr_extract_env->ptr_i_buffer,
         pstr_sbr_cfg->is_ld_sbr, pstr_env_ch[ch]->str_sbr_qmf.num_time_slots, samp_ratio_fac,
-        pstr_hbe_enc, (IXHEAACE_OP_DELAY_OFFSET + IXHEAACE_ESBR_HBE_DELAY_OFFSET +
-        IXHEAACE_SBR_HF_ADJ_OFFSET), pstr_sbr_hdr->sbr_harmonic);
+        pstr_hbe_enc,
+        (IXHEAACE_OP_DELAY_OFFSET + IXHEAACE_ESBR_HBE_DELAY_OFFSET + IXHEAACE_SBR_HF_ADJ_OFFSET),
+        pstr_sbr_hdr->sbr_harmonic);
 
     ixheaace_calculate_tonality_quotas(
         &pstr_env_ch[ch]->str_ton_corr, pstr_sbr_extract_env->ptr_r_buffer,
         pstr_sbr_extract_env->ptr_i_buffer,
         pstr_sbr_cfg->ptr_freq_band_tab[HI][pstr_sbr_cfg->num_scf[HI]],
-        pstr_env_ch[ch]->str_sbr_qmf.num_time_slots, pstr_sbr_cfg->is_ld_sbr);
+        pstr_env_ch[ch]->str_sbr_qmf.num_time_slots, pstr_sbr_extract_env->time_step);
     if (pstr_sbr_cfg->is_ld_sbr) {
       ixheaace_detect_transient_eld(pstr_sbr_extract_env->ptr_y_buffer,
                                     &pstr_env_ch[ch]->str_sbr_trans_detector, transient_info[ch]);
+    } else if (pstr_sbr_extract_env->time_step == 4) {
+      ixheaace_detect_transient_4_1(pstr_sbr_extract_env->ptr_y_buffer,
+                                    &pstr_env_ch[ch]->str_sbr_trans_detector, transient_info[ch],
+                                    pstr_sbr_extract_env->time_step, pstr_sbr_cfg->sbr_codec);
     } else {
       ixheaace_detect_transient(pstr_sbr_extract_env->ptr_y_buffer,
                                 &pstr_env_ch[ch]->str_sbr_trans_detector, transient_info[ch],
@@ -2913,8 +2934,8 @@ IA_ERRORCODE ixheaace_extract_sbr_envelope(FLOAT32 *ptr_in_time, FLOAT32 *ptr_co
       FLOAT32 *ptr_tmp;
       ptr_tmp = pstr_sbr_extract_env->ptr_y_buffer[i];
       pstr_sbr_extract_env->ptr_y_buffer[i] =
-          pstr_sbr_extract_env->ptr_y_buffer[i + (pstr_sbr_extract_env->no_cols >> 1)];
-      pstr_sbr_extract_env->ptr_y_buffer[i + (pstr_sbr_extract_env->no_cols >> 1)] = ptr_tmp;
+          pstr_sbr_extract_env->ptr_y_buffer[i + pstr_sbr_extract_env->time_slots];
+      pstr_sbr_extract_env->ptr_y_buffer[i + pstr_sbr_extract_env->time_slots] = ptr_tmp;
     }
 
     pstr_sbr_extract_env->buffer_flag ^= 1;
diff --git a/encoder/ixheaace_sbr_env_est_init.c b/encoder/ixheaace_sbr_env_est_init.c
index 19e0713..2f2d8d1 100644
--- a/encoder/ixheaace_sbr_env_est_init.c
+++ b/encoder/ixheaace_sbr_env_est_init.c
@@ -99,12 +99,9 @@ ixheaace_create_extract_sbr_envelope(WORD32 ch,
     if ((sbr_codec == USAC_SBR) && (USAC_SBR_RATIO_INDEX_4_1 == sbr_ratio_idx)) {
       qmf_time_slots = QMF_TIME_SLOTS_USAC_4_1;
       y_buffer_write_offset = QMF_TIME_SLOTS_USAC_4_1;
+      no_cols = qmf_time_slots;
     }
-    if (is_ld_sbr && frame_flag_480) {
-      y_buffer_write_offset = 30;
-      no_cols = 30;
-      time_slots = 15;
-    }
+
     pstr_sbr_ext_env->y_buffer_write_offset = y_buffer_write_offset;
 
     y_buffer_length = pstr_sbr_ext_env->y_buffer_write_offset + y_buffer_write_offset;
diff --git a/encoder/ixheaace_sbr_main.c b/encoder/ixheaace_sbr_main.c
index 7836985..64b6a2f 100644
--- a/encoder/ixheaace_sbr_main.c
+++ b/encoder/ixheaace_sbr_main.c
@@ -431,7 +431,7 @@ UWORD32 ixheaace_sbr_limit_bitrate(UWORD32 bit_rate, UWORD32 num_ch, UWORD32 cor
 VOID ixheaace_adjust_sbr_settings(const ixheaace_pstr_sbr_cfg pstr_config, UWORD32 bit_rate,
                                   UWORD32 num_ch, UWORD32 fs_core, UWORD32 trans_fac,
                                   UWORD32 std_br, ixheaace_str_qmf_tabs *pstr_qmf_tab,
-                                  WORD32 aot) {
+                                  WORD32 aot, WORD32 is_esbr_4_1) {
   FLAG table_found = IXHEAACE_TABLE_IDX_NOT_FOUND;
   WORD32 idx_sr = 0;
   WORD32 idx_ch = 0;
@@ -538,6 +538,11 @@ VOID ixheaace_adjust_sbr_settings(const ixheaace_pstr_sbr_cfg pstr_config, UWORD
       pstr_config->ps_mode = ixheaace_get_ps_mode(bit_rate);
     }
   }
+
+  if (is_esbr_4_1) {
+    pstr_config->start_freq = 10;
+    pstr_config->stop_freq = 11;
+  }
 }
 
 VOID ixheaace_initialize_sbr_defaults(ixheaace_pstr_sbr_cfg pstr_config) {
diff --git a/encoder/ixheaace_sbr_main.h b/encoder/ixheaace_sbr_main.h
index 3603fdf..f84dccd 100644
--- a/encoder/ixheaace_sbr_main.h
+++ b/encoder/ixheaace_sbr_main.h
@@ -101,7 +101,7 @@ UWORD32 ixheaace_sbr_limit_bitrate(UWORD32 bit_rate, UWORD32 num_channels,
 VOID ixheaace_adjust_sbr_settings(const ixheaace_pstr_sbr_cfg pstr_config, UWORD32 bit_rate,
                                   UWORD32 num_channels, UWORD32 fs_core, UWORD32 trans_fac,
                                   UWORD32 standard_bitrate, ixheaace_str_qmf_tabs *ptr_qmf_tab,
-                                  WORD32 aot);
+                                  WORD32 aot, WORD32 is_esbr_4_1);
 
 VOID ixheaace_initialize_sbr_defaults(ixheaace_pstr_sbr_cfg pstr_config);
 
diff --git a/encoder/ixheaace_sbr_qmf_enc.c b/encoder/ixheaace_sbr_qmf_enc.c
index cfe485f..9ac3210 100644
--- a/encoder/ixheaace_sbr_qmf_enc.c
+++ b/encoder/ixheaace_sbr_qmf_enc.c
@@ -961,17 +961,14 @@ VOID ixheaace_get_energy_from_cplx_qmf(
   }
   if (0 == is_ld_sbr) {
     FLOAT32 *ptr_energy_val = &ptr_energy_vals[0][0];
-    FLOAT32 *ptr_real = &ptr_real_values[0][0];
-    FLOAT32 *ptr_imag = &ptr_imag_values[0][0];
     FLOAT32 *ptr_hbe_real = NULL;
     FLOAT32 *ptr_hbe_imag = NULL;
     if (harmonic_sbr == 1) {
       ptr_hbe_real = &pstr_hbe_enc->qmf_buf_real[op_delay][0];
       ptr_hbe_imag = &pstr_hbe_enc->qmf_buf_imag[op_delay][0];
     }
-    k = (num_time_slots - 1);
-    while (k >= 0) {
-      for (j = 63; j >= 0; j--) {
+    for (k = 0; k < num_time_slots; k++) {
+      for (j = 0; j < IXHEAACE_QMF_CHANNELS; j++) {
         FLOAT32 tmp = 0.0f;
         if (harmonic_sbr == 1) {
           FLOAT32 real_hbe, imag_hbe;
@@ -981,28 +978,23 @@ VOID ixheaace_get_energy_from_cplx_qmf(
           *ptr_energy_val = tmp;
           ptr_hbe_real++;
           ptr_hbe_imag++;
+          ptr_energy_val++;
         } else {
           FLOAT32 real, imag;
-          WORD32 i;
+          WORD32 i, subband;
+          subband = samp_ratio_fac * k;
           for (i = 0; i < samp_ratio_fac; i++) {
-            real = *(ptr_real + i * IXHEAACE_QMF_CHANNELS);
-            imag = *(ptr_imag + i * IXHEAACE_QMF_CHANNELS);
+            real = ptr_real_values[subband + i][j];
+            imag = ptr_imag_values[subband + i][j];
             tmp += (real * real) + (imag * imag);
           }
-          *ptr_energy_val = tmp * avg_fac;
-          ptr_real++;
-          ptr_imag++;
+          ptr_energy_vals[k][j] = tmp * avg_fac;
         }
-        ptr_energy_val++;
       }
       if (harmonic_sbr == 1) {
         ptr_hbe_real += 64;
         ptr_hbe_imag += 64;
-      } else {
-        ptr_real += 64;
-        ptr_imag += 64;
       }
-      k--;
     }
   } else {
     FLOAT32 *ptr_real = &ptr_real_values[0][0];
diff --git a/encoder/ixheaace_sbr_ton_corr_hp.c b/encoder/ixheaace_sbr_ton_corr_hp.c
index 1bcd3c8..dc48d6d 100644
--- a/encoder/ixheaace_sbr_ton_corr_hp.c
+++ b/encoder/ixheaace_sbr_ton_corr_hp.c
@@ -117,7 +117,7 @@ static VOID ixheaace_calc_auto_corr_second_order(ixheaace_acorr_coeffs *pstr_ac,
 
 VOID ixheaace_calculate_tonality_quotas(ixheaace_pstr_sbr_ton_corr_est pstr_ton_corr,
                                         FLOAT32 **ptr_real, FLOAT32 **ptr_imag, WORD32 usb,
-                                        WORD32 num_time_slots, WORD32 is_ld_sbr) {
+                                        WORD32 num_time_slots, WORD32 time_step) {
   WORD32 i, k, r, time_index;
   FLOAT32 alphar[2], alphai[2], r01r, r02r, r11r, r12r, r01i, r02i, r12i, det, r00r;
   ixheaace_acorr_coeffs ac;
@@ -129,7 +129,7 @@ VOID ixheaace_calculate_tonality_quotas(ixheaace_pstr_sbr_ton_corr_est pstr_ton_
   WORD32 no_est_per_frame = pstr_ton_corr->est_cnt_per_frame;
   WORD32 move = pstr_ton_corr->move;
   WORD32 num_qmf_ch = pstr_ton_corr->num_qmf_ch;
-  WORD32 len = num_time_slots;
+  WORD32 len;
   WORD32 qm_len;
   for (i = 0; i < move; i++) {
     memcpy(ptr_quota_mtx[i], ptr_quota_mtx[i + no_est_per_frame],
@@ -139,12 +139,9 @@ VOID ixheaace_calculate_tonality_quotas(ixheaace_pstr_sbr_ton_corr_est pstr_ton_
   memmove(ptr_energy_vec, ptr_energy_vec + no_est_per_frame, move * sizeof(ptr_energy_vec[0]));
   memset(ptr_energy_vec + start_index_matrix, 0,
          (tot_no_est - start_index_matrix) * sizeof(ptr_energy_vec[0]));
-  if (is_ld_sbr) {
-    len = num_time_slots / 2;
-    qm_len = 2 + len;
-  } else {
-    qm_len = 18;
-  }
+
+  len = (num_time_slots * time_step) / 2;
+  qm_len = 2 + len;
 
   for (r = 0; r < usb; r++) {
     k = 2;
@@ -185,7 +182,7 @@ VOID ixheaace_calculate_tonality_quotas(ixheaace_pstr_sbr_ton_corr_est pstr_ton_
       }
       ptr_energy_vec[time_index] += r00r;
 
-      k += is_ld_sbr ? len : 16;
+      k += len;
 
       time_index++;
     }
diff --git a/encoder/ixheaace_sbr_tran_det.c b/encoder/ixheaace_sbr_tran_det.c
index a18ba9e..3f9363f 100644
--- a/encoder/ixheaace_sbr_tran_det.c
+++ b/encoder/ixheaace_sbr_tran_det.c
@@ -87,26 +87,25 @@ static IA_ERRORCODE ixheaace_spectral_change(FLOAT32 *ptr_energies[16], FLOAT32
 }
 
 FLOAT32 ixheaace_add_lowband_energies(FLOAT32 **ptr_energies, UWORD8 *ptr_freq_band_tab,
-                                      WORD32 time_slots, WORD32 is_ld_sbr) {
+                                      WORD32 time_slots, WORD32 is_ld_sbr, WORD32 time_step) {
   WORD32 band, ts;
   FLOAT32 energy = 1.0f;
   WORD32 tran_offset = 0;
   if (is_ld_sbr) {
     tran_offset = 7;
     energy = 0.0f;
-
-    for (ts = tran_offset; ts < time_slots + tran_offset; ts++) {
-      for (band = 0; band < ptr_freq_band_tab[0]; band++) {
-        energy += ptr_energies[ts][band];
-      }
-    }
   } else {
-    for (ts = tran_offset; ts < time_slots + tran_offset; ts++) {
-      for (band = 0; band < ptr_freq_band_tab[0]; band++) {
-        energy += ptr_energies[(ts + time_slots / 2) / 2][band];
-      }
+    tran_offset = time_slots / 2;
+  }
+
+  for (ts = tran_offset; ts < time_slots + tran_offset; ts++) {
+    for (band = 0; band < ptr_freq_band_tab[0]; band++) {
+      energy += ptr_energies[ts][band];
     }
   }
+
+  energy *= time_step;
+
   return energy;
 }
 
@@ -114,41 +113,25 @@ static FLOAT32 ixheaace_add_highband_energies(FLOAT32 **ptr_energies, FLOAT32 *p
                                               UWORD8 *ptr_freq_band_tab, WORD32 num_sfb,
                                               WORD32 time_slots, WORD32 time_step,
                                               WORD32 is_ld_sbr) {
-  WORD32 band, ts, sfb, low_band, high_band, st;
+  WORD32 band, ts, sfb, low_band, high_band;
   FLOAT32 energy = 1.0f, tmp;
   if (is_ld_sbr) {
     energy = 0.0f;
-    for (ts = 0; ts < time_slots; ts++) {
-      for (sfb = 0; sfb < num_sfb; sfb++) {
-        tmp = 0;
-        low_band = ptr_freq_band_tab[sfb];
-        high_band = ptr_freq_band_tab[sfb + 1];
-        band = low_band;
-        while (band < high_band) {
-          tmp += ptr_energies[ts][band];
-          band++;
-        }
-        ptr_energies_m[ts][sfb] = tmp;
-        energy += tmp;
+  }
+  for (ts = 0; ts < time_slots; ts++) {
+    for (sfb = 0; sfb < num_sfb; sfb++) {
+      tmp = 0;
+      low_band = ptr_freq_band_tab[sfb];
+      high_band = ptr_freq_band_tab[sfb + 1];
+      band = low_band;
+      while (band < high_band) {
+        tmp += (ptr_energies[ts][band] * time_step);
+        band++;
       }
-    }
-  } else {
-    for (ts = 0; ts < time_slots; ts++) {
-      for (sfb = 0; sfb < num_sfb; sfb++) {
-        tmp = 0;
-        low_band = ptr_freq_band_tab[sfb];
-        high_band = ptr_freq_band_tab[sfb + 1];
-        band = low_band;
-        while (band < high_band) {
-          st = 0;
-          while (st < time_step) {
-            tmp += ptr_energies[ts + (st / 2)][band];
-            st++;
-          }
-          band++;
-        }
-        ptr_energies_m[ts][sfb] = tmp;
-
+      ptr_energies_m[ts][sfb] = tmp;
+      if (is_ld_sbr || time_step == 4) {
+        energy += tmp;
+      } else {
         energy += ptr_energies[ts][sfb];
       }
     }
@@ -181,8 +164,8 @@ ixheaace_frame_splitter(FLOAT32 **ptr_energies,
     ptr_frame_splitter_scratch += MAXIMUM_FREQ_COEFFS;
   }
 
-  low_band_energy =
-      ixheaace_add_lowband_energies(ptr_energies, ptr_freq_band_tab, no_cols, is_ld_sbr);
+  low_band_energy = ixheaace_add_lowband_energies(ptr_energies, ptr_freq_band_tab, num_sbr_slots,
+                                                  is_ld_sbr, time_step);
 
   high_band_energy =
       ixheaace_add_highband_energies(ptr_energies, ptr_energies_m, ptr_freq_band_tab, num_scf,
@@ -222,6 +205,7 @@ VOID ixheaace_create_sbr_transient_detector(
   if ((sbr_codec == USAC_SBR) && (sbr_ratio_idx == USAC_SBR_RATIO_INDEX_4_1)) {
     frm_dur = frm_dur * 2;
     split_thr_fac = frm_dur - 0.01f;
+    no_cols = 64;
   }
   if ((1 == is_ld_sbr) && (1 == frame_flag_480)) {
     no_cols = 30;
diff --git a/encoder/ixheaace_sbr_tran_det.h b/encoder/ixheaace_sbr_tran_det.h
index 94dd3a5..20ec440 100644
--- a/encoder/ixheaace_sbr_tran_det.h
+++ b/encoder/ixheaace_sbr_tran_det.h
@@ -59,6 +59,11 @@ VOID ixheaace_detect_transient(FLOAT32 **ptr_energies,
                                WORD32 *ptr_tran_vector, WORD32 time_step,
                                ixheaace_sbr_codec_type sbr_codec);
 
+VOID ixheaace_detect_transient_4_1(FLOAT32 **ptr_energies,
+                                   ixheaace_pstr_sbr_trans_detector pstr_sbr_trans_det,
+                                   WORD32 *ptr_tran_vector, WORD32 time_step,
+                                   ixheaace_sbr_codec_type sbr_codec);
+
 VOID ixheaace_detect_transient_eld(FLOAT32 **ptr_energies,
                                    ixheaace_pstr_sbr_trans_detector pstr_sbr_trans_det,
                                    WORD32 *ptr_tran_vector);
diff --git a/encoder/ixheaace_sbr_tran_det_hp.c b/encoder/ixheaace_sbr_tran_det_hp.c
index b4a5765..2fb8846 100644
--- a/encoder/ixheaace_sbr_tran_det_hp.c
+++ b/encoder/ixheaace_sbr_tran_det_hp.c
@@ -161,6 +161,107 @@ VOID ixheaace_detect_transient(FLOAT32 **ptr_energies,
   }
 }
 
+static VOID ixheaace_calc_thresholds_4_1(FLOAT32 **ptr_energies, WORD32 num_cols, WORD32 num_rows,
+                                         FLOAT32 *ptr_thresholds,
+                                         ixheaace_sbr_codec_type sbr_codec, WORD32 time_step) {
+  FLOAT32 mean_val, std_val, thr;
+  FLOAT32 *ptr_energy;
+  FLOAT32 inv_num_cols = 1.0f / (FLOAT32)((num_cols + num_cols / 2) / time_step);
+  FLOAT32 inv_num_cols_1 = 1.0f / (FLOAT32)((num_cols + num_cols / 2 - 1) / time_step);
+
+  WORD32 i = 0;
+  WORD32 j;
+  WORD32 start_band = 8;
+  WORD32 end_band = 32;
+
+  while (i < num_rows) {
+    mean_val = std_val = 0;
+
+    j = start_band;
+    while (j < end_band) {
+      ptr_energy = &ptr_energies[j][i];
+      mean_val += (*ptr_energy);
+      j++;
+    }
+
+    mean_val *= inv_num_cols;
+
+    j = start_band;
+    while (j < end_band) {
+      FLOAT32 tmp_var;
+      tmp_var = mean_val - ptr_energies[j][i];
+      std_val += tmp_var * tmp_var;
+      j++;
+    }
+
+    std_val = (FLOAT32)sqrt(std_val * inv_num_cols_1);
+
+    thr = 0.66f * ptr_thresholds[i] + 0.34f * IXHEAACE_SBR_TRAN_STD_FAC * std_val;
+    ptr_thresholds[i] = MAX(thr, IXHEAACE_SBR_TRAN_ABS_THR);
+
+    i++;
+  }
+}
+
+static VOID ixheaace_extract_transient_candidates_4_1(FLOAT32 **ptr_energies,
+                                                      FLOAT32 *ptr_thresholds,
+                                                      FLOAT32 *ptr_transients, WORD32 num_cols,
+                                                      WORD32 start_band, WORD32 stop_band,
+                                                      WORD32 buf_len, WORD32 time_step)
+
+{
+  WORD32 idx;
+  WORD32 buf_move = num_cols / 2;
+  WORD32 band = start_band;
+
+  memmove(ptr_transients, ptr_transients + num_cols, buf_move * sizeof(ptr_transients[0]));
+  memset(ptr_transients + buf_move, 0, num_cols * sizeof(ptr_transients[0]));
+
+  while (band < stop_band) {
+    for (idx = buf_move; idx < num_cols + buf_move; idx++) {
+      float l = 0, r = 0;
+      for (int d = 1; d < 4; d++) {
+        l = ptr_energies[(idx - d) / time_step][band];
+        r = ptr_energies[(idx + d) / time_step][band];
+        if (r - l > ptr_thresholds[band])
+          ptr_transients[idx] += (r - l - ptr_thresholds[band]) / ptr_thresholds[band];
+      }
+    }
+    band++;
+  }
+}
+
+VOID ixheaace_detect_transient_4_1(FLOAT32 **ptr_energies,
+                                   ixheaace_pstr_sbr_trans_detector pstr_sbr_trans_det,
+                                   WORD32 *ptr_tran_vector, WORD32 time_step,
+                                   ixheaace_sbr_codec_type sbr_codec) {
+  WORD32 i;
+  WORD32 no_cols = pstr_sbr_trans_det->no_cols;
+  WORD32 qmf_start_sample = time_step * 4;
+  FLOAT32 int_thr = (FLOAT32)pstr_sbr_trans_det->tran_thr / (FLOAT32)pstr_sbr_trans_det->no_rows;
+  FLOAT32 *ptr_trans = &(pstr_sbr_trans_det->ptr_transients[qmf_start_sample]);
+
+  ptr_tran_vector[0] = 0;
+  ptr_tran_vector[1] = 0;
+
+  ixheaace_calc_thresholds_4_1(ptr_energies, pstr_sbr_trans_det->no_cols,
+                               pstr_sbr_trans_det->no_rows, pstr_sbr_trans_det->ptr_thresholds,
+                               sbr_codec, time_step);
+
+  ixheaace_extract_transient_candidates_4_1(
+      ptr_energies, pstr_sbr_trans_det->ptr_thresholds, pstr_sbr_trans_det->ptr_transients,
+      pstr_sbr_trans_det->no_cols, 0, pstr_sbr_trans_det->no_rows,
+      pstr_sbr_trans_det->buffer_length, time_step);
+
+  for (i = 0; i < no_cols; i++) {
+    if ((ptr_trans[i] < 0.9f * ptr_trans[i - 1]) && (ptr_trans[i - 1] > int_thr)) {
+      ptr_tran_vector[0] = (WORD32)floor(i / time_step);
+      ptr_tran_vector[1] = 1;
+      break;
+    }
+  }
+}
+
 VOID ixheaace_detect_transient_eld(FLOAT32 **ptr_energies,
                                    ixheaace_pstr_sbr_trans_detector pstr_sbr_trans_det,
                                    WORD32 *ptr_tran_vector) {
diff --git a/fuzzer/Android.bp b/fuzzer/Android.bp
index 56ea46b..80912e5 100644
--- a/fuzzer/Android.bp
+++ b/fuzzer/Android.bp
@@ -22,6 +22,15 @@ cc_fuzz {
             "android-media-fuzzing-reports@google.com",
         ],
         componentid: 155276,
+        hotlists: [
+            "2100854",
+            "4593311",
+        ],
+        description: "The fuzzer targets the APIs of libxaacdec",
+        vector: "remote",
+        service_privilege: "constrained",
+        users: "multi_user",
+        fuzzed_code_usage: "experimental",
     },
 }
 
@@ -40,5 +49,14 @@ cc_fuzz {
             "android-media-fuzzing-reports@google.com",
         ],
         componentid: 155276,
+        hotlists: [
+            "2100854",
+            "4593311",
+        ],
+        description: "The fuzzer targets the APIs of libxaacenc",
+        vector: "local_no_privileges_required",
+        service_privilege: "constrained",
+        users: "multi_user",
+        fuzzed_code_usage: "experimental",
     },
 }
diff --git a/fuzzer/xaac_enc_fuzzer.cpp b/fuzzer/xaac_enc_fuzzer.cpp
index fe96c8a..530d6a1 100644
--- a/fuzzer/xaac_enc_fuzzer.cpp
+++ b/fuzzer/xaac_enc_fuzzer.cpp
@@ -544,6 +544,7 @@ static VOID ixheaace_fuzzer_flag(ixheaace_input_config *pstr_in_cfg,
   pstr_in_cfg->measurement_system = fuzzed_data->ConsumeIntegral<WORD32>();
   pstr_in_cfg->measured_loudness = fuzzed_data->ConsumeIntegral<WORD32>();
   pstr_in_cfg->stream_id = fuzzed_data->ConsumeIntegral<UWORD16>();
+  pstr_in_cfg->use_delay_adjustment = fuzzed_data->ConsumeIntegral<WORD32>();
   /* DRC */
   if (pstr_in_cfg->use_drc_element == 1) {
     ixheaace_read_drc_config_params(&pstr_drc_cfg->str_enc_params,
@@ -675,7 +676,7 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   ixheaace_fuzzer_flag(pstr_in_cfg, pstr_drc_cfg, &fuzzed_data, pstr_in_cfg->i_channels);
 
   /*1st pass -> Loudness Measurement */
-  if (pstr_in_cfg->aot == AOT_USAC) {
+  if (pstr_in_cfg->aot == AOT_USAC || pstr_in_cfg->usac_en) {
     err_code =
         ixheaace_calculate_loudness_measure(pstr_in_cfg, pstr_out_cfg, &fuzzed_data_loudness);
     if (err_code) {
diff --git a/test/encoder/ixheaace_testbench.c b/test/encoder/ixheaace_testbench.c
index 706373e..6260b90 100644
--- a/test/encoder/ixheaace_testbench.c
+++ b/test/encoder/ixheaace_testbench.c
@@ -229,6 +229,7 @@ void ia_enhaacplus_enc_print_usage() {
   printf("\n[-inter_tes_enc:<inter_tes_enc_flag>]");
   printf("\n[-rap:<random access interval in ms>]");
   printf("\n[-stream_id:<stream identifier>]");
+  printf("\n[-delay_adjust:<delay adjustment>]");
   printf("\n\nwhere, \n  <paramfile> is the parameter file with multiple commands");
   printf("\n  <inputfile> is the input 16-bit WAV or PCM file name");
   printf("\n  <outputfile> is the output ADTS/ES file name");
@@ -317,6 +318,10 @@ void ia_enhaacplus_enc_print_usage() {
       "\n <stream identifier> is the stream id used to uniquely identify configuration of a "
       "stream within a set of associated streams."
       "\n        It is applicable only for AOT 42. Valid values are 0 to 65535. Default is 0.");
+  printf(
+    "\n <delay adjustment> is used to discard delay on the decoded file using pre-roll frames"
+    "on encoder."
+    "\n        It is applicable only for AOT 42. Valid values are 0 and 1. Default is 0.");
   exit(1);
 }
 
@@ -425,6 +430,10 @@ static VOID ixheaace_parse_config_param(WORD32 argc, pWORD8 argv[], pVOID ptr_en
       pCHAR8 pb_arg_val = (pCHAR8)(argv[i] + 11);
       pstr_enc_api->input_config.stream_id = atoi(pb_arg_val);
     }
+    if (!strncmp((const char *)argv[i], "-delay_adjust:", 14)) {
+      pWORD8 pb_arg_val = argv[i] + 14;
+      pstr_enc_api->input_config.use_delay_adjustment = atoi((const char *)pb_arg_val);
+    }
   }
 
   return;
@@ -972,6 +981,12 @@ static VOID ixheaace_print_config_params(ixheaace_input_config *pstr_input_confi
       printf("\nRandom access interval (Invalid config value, setting to default) : %d",
              pstr_input_config->random_access_interval);
     }
+
+    if (pstr_input_config->use_delay_adjustment !=
+      pstr_input_config_user->use_delay_adjustment) {
+      printf("\nDelay compensation (Invalid config value, setting to default) : %d",
+        pstr_input_config->use_delay_adjustment);
+    }
   }
 
   printf(
@@ -1146,6 +1161,7 @@ IA_ERRORCODE ia_enhaacplus_enc_main_process(ixheaace_app_context *pstr_context,
   pstr_in_cfg->random_access_interval = DEFAULT_RAP_INTERVAL_IN_MS;
   pstr_in_cfg->method_def = METHOD_DEFINITION_PROGRAM_LOUDNESS;
   pstr_in_cfg->measurement_system = MEASUREMENT_SYSTEM_BS_1770_3;
+  pstr_in_cfg->use_delay_adjustment = USAC_DEFAULT_DELAY_ADJUSTMENT_VALUE;
 
   /* ******************************************************************/
   /* Parse input configuration parameters                             */
@@ -1219,7 +1235,7 @@ IA_ERRORCODE ia_enhaacplus_enc_main_process(ixheaace_app_context *pstr_context,
   }
 
   /*1st pass -> Loudness Measurement */
-  if (pstr_in_cfg->aot == AOT_USAC) {
+  if (pstr_in_cfg->aot == AOT_USAC || pstr_in_cfg->usac_en) {
     err_code =
         ixheaace_calculate_loudness_measure(pstr_in_cfg, pstr_out_cfg, pstr_context->pf_inp);
     if (err_code) {
@@ -1322,10 +1338,7 @@ IA_ERRORCODE ia_enhaacplus_enc_main_process(ixheaace_app_context *pstr_context,
 
   start_offset_samples = 0;
   input_size = pstr_out_cfg->input_size;
-
-  if (input_size) {
-    expected_frame_count = (pstr_in_cfg->aac_config.length + (input_size - 1)) / input_size;
-  }
+  expected_frame_count = pstr_out_cfg->expected_frame_count;
 
   if (NULL == ia_stsz_size) {
     ia_stsz_size = (UWORD32 *)malloc_global((expected_frame_count + 2) * sizeof(*ia_stsz_size),
@@ -1382,10 +1395,16 @@ IA_ERRORCODE ia_enhaacplus_enc_main_process(ixheaace_app_context *pstr_context,
 
       ia_enhaacplus_enc_fwrite(pb_out_buf, pstr_context->pf_out, i_out_bytes);
       fflush(pstr_context->pf_out);
-
+      if (!pstr_in_cfg->use_delay_adjustment) {
+         i_bytes_read = ia_enhaacplus_enc_fread((pVOID)pb_inp_buf, sizeof(WORD8), input_size,
+           pstr_context->pf_inp);
+      }
+    }
+    if (pstr_in_cfg->use_delay_adjustment) {
       i_bytes_read = ia_enhaacplus_enc_fread((pVOID)pb_inp_buf, sizeof(WORD8), input_size,
-                                             pstr_context->pf_inp);
+        pstr_context->pf_inp);
     }
+
     if (frame_count == expected_frame_count) break;
   }
 
```

