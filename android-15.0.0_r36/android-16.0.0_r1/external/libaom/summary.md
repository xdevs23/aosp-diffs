```
8d160a21c: Android.bp: add 'cfi_assembly_support: true' (James Zern <jzern@google.com>)
3b624af45: Update CHANGELOG for libaom v3.12.0 (Wan-Teh Chang <wtc@google.com>)
ef88d9c02: Fix a comment typo (Wan-Teh Chang <wtc@google.com>)
3d0000651: rtc: Remove num_col/row_blscroll_last_tl0 (Marco Paniconi <marpan@google.com>)
5850fbf90: Update CHANGELOG for libaom v3.12.0 (Wan-Teh Chang <wtc@google.com>)
68a1f6a5a: Document new value 3 for AV1E_SET_ENABLE_CDEF (Wan-Teh Chang <wtc@google.com>)
7e257ce03: Update AUTHORS,CHANGELOG,CMakeLists.txt for 3.12.0 (Wan-Teh Chang <wtc@google.com>)
3b6812b91: Rename tune=ssimulacra2 to tune=iq (Wan-Teh Chang <wtc@google.com>)
3990233fc: warped_motion.c,cosmetics: fix long line (James Zern <jzern@google.com>)
26b58c14b: enable runtime cpu detection for x86 & x86-64 (James Zern <jzern@google.com>)
feba11b38: Remove interleaving load/stores in cfl_predict_neon (Salome Thirot <salome.thirot@arm.com>)
d8ec0d2e5: aomenc.c: add missing cast (James Zern <jzern@google.com>)
5d06690b9: riscv64/cdef: Add the CDEF optimization (jerry <jerytsai@andestech.com>)
8498455b2: Optimize Neon implementation of aom_highbd_lpf_14_neon (Salome Thirot <salome.thirot@arm.com>)
cebba96df: Optimize Neon implementation of aom_highbd_lpf_8_neon (Salome Thirot <salome.thirot@arm.com>)
99258a8f9: Optimize Neon implementation of aom_highbd_lpf_6_neon (Salome Thirot <salome.thirot@arm.com>)
0af5397be: Cleanup and optimize aom_highbd_lpf_4_neon (Salome Thirot <salome.thirot@arm.com>)
92f9a3b93: Cleanup Neon implementation of aom_lpf4 (Salome Thirot <salome.thirot@arm.com>)
0b436b0d6: Optimize Neon implementation of aom_lpf_14 (Salome Thirot <salome.thirot@arm.com>)
0e1c1a328: Optimize Neon implementation of aom_lpf_8 (Salome Thirot <salome.thirot@arm.com>)
16d45e093: Optimize Neon implementation of aom_lpf_6 (Salome Thirot <salome.thirot@arm.com>)
a8f1280da: test_aom_rc: work around multiple def link error w/cygwin/mingw (James Zern <jzern@google.com>)
8a1be021f: cmake: don't use -Wl,-z,def w/cygwin (James Zern <jzern@google.com>)
c10770a6b: set_encoder_config: rm VBR rc buf size override (James Zern <jzern@google.com>)
3f94cfa28: rtc-screen: Make sb horiz scroll search window same as vert (Marco Paniconi <marpan@google.com>)
db1d742e2: Match types between refs and coeffs in generic path (Mahesh Madhav <mahesh@amperecomputing.com>)
e0e69ad3a: Remove the int16_t * casts for av1_warped_filter (Wan-Teh Chang <wtc@google.com>)
eac382e19: Remove the int16_t * casts for av1_warped_filter (Wan-Teh Chang <wtc@google.com>)
22881fc86: README.md: add a note for MSYS2 yasm/nasm binaries (James Zern <jzern@google.com>)
628255e24: riscv64: Introduce RVV and cpu-detection (jerry <jerytsai@andestech.com>)
a4d200cfa: rerun external_updater (James Zern <jzern@google.com>)
d0a581133: use external_updater (James Zern <jzern@google.com>)
e3c9f144d: README.android: remove redundant version info (James Zern <jzern@google.com>)
d737ca3eb: exports_com: rm aom_{malloc,free} (James Zern <jzern@google.com>)
25a5fc4a1: rtc: Add higher resolution screen test for 2TL (Marco Paniconi <marpan@google.com>)
0c13a5d54: rtc-screen: Fix for estimate_scroll (Marco Paniconi <marpan@google.com>)
0935f0805: Revert "rtc-screen: Increase horiz search in estimate_scroll_motion" (Marco Paniconi <marpan@google.com>)
76df9967c: rtc: Fix to skip_encoding_non_reference_slide_change (Marco Paniconi <marpan@google.com>)
433be28b4: Define opaque struct of RC class for C (Jerome Jiang <jianj@google.com>)
4afbf1b46: cmake: add float-cast-overflow w/ubsan (James Zern <jzern@google.com>)
79fc63a10: Don't check size limit in aom_realloc_frame_buffer (Wan-Teh Chang <wtc@google.com>)
f74eae54f: rtc-screen: Increase horiz search in estimate_scroll_motion (Marco Paniconi <marpan@google.com>)
4364ee455: Fix spelling in comment (Marco Paniconi <marpan@google.com>)
019574ff3: Use typedef for C structs (Jerome Jiang <jianj@google.com>)
455decf1c: multilayer_metadata_test: temp out files as text (Wan-Teh Chang <wtc@google.com>)
96f455fc5: Remove C++ declaration for constants (Jerome Jiang <jianj@google.com>)
64e800702: Unify enums in RC interface & restore namespace (Jerome Jiang <jianj@google.com>)
ebf1efc22: Fix the test case for C interface in RTC RC (Jerome Jiang <jianj@google.com>)
6cfc05e39: Don't update seg map if cyclic refresh disabled (Zhaoliang Ma <zhaoliang.ma@intel.com>)
d032a4f33: Use alias to restore namespace for structs in RC (Jerome Jiang <jianj@google.com>)
b04d32f13: cpu.cmake: Fix typo: OLD_CMAKE_{REQURED => REQUIRED}_FLAGS (George Steed <george.steed@arm.com>)
bfd2c2435: add missing includes for the build with use_libcxx_modules (Takuto Ikuta <tikuta@google.com>)
2d84c873b: Use std::ifstream instead of std::fstream (Wan-Teh Chang <wtc@google.com>)
c1bcb109d: Use local variable to facilitate vectorization (Mahesh Madhav <mahesh@amperecomputing.com>)
cae8337e8: Use alias to restore aom namespace for RC frame params (Jerome Jiang <jianj@google.com>)
a532b43a3: Use seekg (instead of seekp) to match tellg (Wan-Teh Chang <wtc@google.com>)
7fb093c7e: Use alias to restore aom namespace for rc config (Jerome Jiang <jianj@google.com>)
29333d1b9: Make AV1RateControlRtcConfigInitDefault internal (Wan-Teh Chang <wtc@google.com>)
9a9b6b25b: ratectrl_rtc_test,cosmetics: fix typo (James Zern <jzern@google.com>)
abb4bd836: Add #include statements (Wan-Teh Chang <wtc@google.com>)
bd244ba64: Correct misspelling: discernable -> discernible (Wan-Teh Chang <wtc@google.com>)
92dcf3177: rtc-screen: Fix to horiz scroll motion detection (Marco Paniconi <marpan@google.com>)
4903fe778: Add 'is_layer_specific_obu' param to av1_write_obu_header (Maryla <maryla@google.com>)
21a881b90: Adaptive CDEF: feedback follow-up (Julio Barba <juliobbv@gmail.com>)
975e26681: Fix typos in the copyright notice (Wan-Teh Chang <wtc@google.com>)
61a05dd4e: Include headers and change to aom_svc_params_t (Wan-Teh Chang <wtc@google.com>)
d5d33643d: Remove the redundant #include <cstdio> (Wan-Teh Chang <wtc@google.com>)
c1f1605f9: Add extern 'C' methods for AV1 ratecontrol (Pradeep Kumar <pradeep.kumar@intel.corp-partner....)
5f119718b: svc_encoder_rtc.cc: fix conversion warning (James Zern <jzern@google.com>)
dcee16fdc: Decrease AC chroma on 4:2:2 content with `tune=ssimulacra2` (Julio Barba <juliobbv@gmail.com>)
96dce73a2: multilayer_metadata.cc: rm unused <optional> (James Zern <jzern@google.com>)
ebd28d180: Update comments for frame in Next()/frame() (Marco Paniconi <marpan@google.com>)
006338030: Adaptive CDEF: introduce reduced strength CDEF (Julio Barba <juliobbv@gmail.com>)
eb89ea28b: Change "sanity check" to "quick validation" (Wan-Teh Chang <wtc@google.com>)
001afd380: Include header for AOMMIN/AOMMAX/PICK_MODE_CONTEXT (Wan-Teh Chang <wtc@google.com>)
278c08911: Use the `img` variable in Encoder::InitEncoder() (Wan-Teh Chang <wtc@google.com>)
18ec8e155: Remove an extra comma after a list item (Wan-Teh Chang <wtc@google.com>)
e10457237: rtc: Reduce intrad sad threshold on pruning palette (Marco Paniconi <marpan@google.com>)
dedba6a71: rtc: Fix to artifact for grayscale input (Marco Paniconi <marpan@google.com>)
697c3da33: rtc-screen: Increase search window for scroll detection (Marco Paniconi <marpan@google.com>)
5665f1cd6: svc_encoder_rtc: improve multilayer metadata handling (Maryla <maryla@google.com>)
1c78c3a09: Fix bug where metadata was lost when resizing a frame. (Maryla <maryla@google.com>)
e8f5f00fa: METADATA: update version to v3.11.0 (James Zern <jzern@google.com>)
ff9badefd: Tweak luma QM levels with `tune=ssimulacra2` (Julio Barba <juliobbv@gmail.com>)
f28171c29: Variance Boost: update comment on variance calculation (Julio Barba <juliobbv@gmail.com>)
6a1c55623: Variance Boost: 3-octile subblock variance sampling (Julio Barba <juliobbv@gmail.com>)
89a0651d2: rtc-screen: Prune palette testing for speed 11 (Marco Paniconi <marpan@google.com>)
d486d0de8: av1_return_max/min_sub_pixel_mv: set sse1 output (Wan-Teh Chang <wtc@google.com>)
4e96b7c70: Spell "filesize" and "tilesize" as two words (Wan-Teh Chang <wtc@google.com>)
37c5c4e6a: Use ROUND_POWER_OF_TWO() in av1_optimize_txb() (Wan-Teh Chang <wtc@google.com>)
3f8a73cdf: Tweak rdmult with `tune=ssimulacra2` (Julio Barba <juliobbv@gmail.com>)
36813a385: Build: compile source files in parallel under MSVC (Aras Pranckevicius <aras@nesnausk.org>)
c2f59745e: Tweak 4:4:4 chroma QM levels with `tune=ssimulacra2` (Julio Barba <juliobbv@gmail.com>)
80070c4b3: Ensure Variance Boost only runs in all intra mode (Julio Barba <juliobbv@gmail.com>)
822b18eaa: Decrease AC chroma on 4:4:4 content with `tune=ssimulacra2` (Julio Barba <juliobbv@gmail.com>)
bc45e0395: Variance Boost: feedback follow-up (Julio Barba <juliobbv@gmail.com>)
80a21c19c: Don't assert signed integer overflow didn't happen (Wan-Teh Chang <wtc@google.com>)
5406c5739: Declare some cpi parameters as const AV1_COMP * (Wan-Teh Chang <wtc@google.com>)
893c832a3: Cosmetic: change "allintra" to "all intra" (Wan-Teh Chang <wtc@google.com>)
b19982bf0: Use more commonly-used expression of rounding term (Wan-Teh Chang <wtc@google.com>)
2894f5627: Change the default_extra_cfg array back to a struct (Wan-Teh Chang <wtc@google.com>)
58bbf5ec5: Enable QM-PSNR metric with `tune=ssimulacra2` (Julio Barba <juliobbv@gmail.com>)
5b8a8e135: av1_inv_txfm2d_test: make arrays const (Tristan Matthews <tmatth@videolan.org>)
03b9a9ac9: svc_encoder_rtc: make arrays const (Tristan Matthews <tmatth@videolan.org>)
57a768dfc: speed_features: make arrays const (Tristan Matthews <tmatth@videolan.org>)
a38b795ad: compound_type: make arrays const (Tristan Matthews <tmatth@videolan.org>)
ecad80769: timing: make arrays const (Tristan Matthews <tmatth@videolan.org>)
7883c101d: av1_inv_txfm_ssse3: make arrays const (Tristan Matthews <tmatth@videolan.org>)
d3c03f26e: av1_inv_txfm_avx2: make arrays const (Tristan Matthews <tmatth@videolan.org>)
ed4a674b1: mvref_common: make arrays const (Tristan Matthews <tmatth@videolan.org>)
c1e3378c3: av1_inv_txfm_neon: make arrays const (Tristan Matthews <tmatth@videolan.org>)
4d61b2fb8: highbd_intrapred_neon: make arrays const (Tristan Matthews <tmatth@videolan.org>)
c1842f7dd: Introduce Variance Boost (Julio Barba <juliobbv@gmail.com>)
37a438c61: Boost chroma on 4:2:0 content with `tune=ssimulacra2` (Julio Barba <juliobbv@gmail.com>)
0c10cd532: Save layer context when dropping frame in temporal svc encoding (Zhaoliang Ma <zhaoliang.ma@intel.com>)
4dc2f7c75: Add CONFIG_CWG_E050 cmake flag. (Maryla <maryla@google.com>)
f6f2deb51: Adjust temporal filter strength for better visual quality (Yunqing Wang <yunqingwang@google.com>)
1a6540010: {highbd_,}sad_sse2.asm: fix function names in comments (James Zern <jzern@google.com>)
706b6b421: sad.c: simplify SADMXN defines (James Zern <jzern@google.com>)
d906231ce: rm dist_wtd_sad*_avg & dist_wtd_sub_pixel_avg_variance fns (James Zern <jzern@google.com>)
d6e0beabc: rm highbd_sad4xN_avg & highbd_sadNx4_avg (James Zern <jzern@google.com>)
b94d47b65: rm sad4xN_avg & sadNx4_avg (James Zern <jzern@google.com>)
0380900cd: av1/encoder: move variance fn ptr constant out of loops (James Zern <jzern@google.com>)
a6c705bf2: Add const to the "MACROBLOCK *x" parameter (Wan-Teh Chang <wtc@google.com>)
8a692cb59: Fix spelling error "sensitiivty" to "sensitivity" (Wan-Teh Chang <wtc@google.com>)
be60f06ab: Use std::pair<T,bool> instead of std::optional. (Maryla <maryla@google.com>)
a433a392e: Remove experimental feature AOM_CODEC_USE_PRESET (Wan-Teh Chang <wtc@google.com>)
bfe96c2b1: svc_encoder_rtc: add multilayer metadata (Maryla <maryla@google.com>)
77846f5e9: Ignore .DS_Store (Julio Barba <juliobbv@gmail.com>)
ac811e68e: Enable new --tune=ssimulacra2 defaults (Julio Barba <juliobbv@gmail.com>)
0fc5b011f: rtc: Remove old/unneeded comment. (Marco Paniconi <marpan@google.com>)
986c536bd: rtc: Allow for color_sensitivity for speed 11 (Marco Paniconi <marpan@google.com>)
2d2f644e4: Add --tune=ssimulacra2 / AOM_TUNE_SSIMULACRA2 (Wan-Teh Chang <wtc@google.com>)
8a2253176: Introduce Adaptive CDEF (Julio Barba <juliobbv@gmail.com>)
6418c21b8: rtc: Change subpel motion speed feature for speed 11 (Marco Paniconi <marpan@google.com>)
f391745e7: Write unit tests for get QM formulas (Julio Barba <juliobbv@gmail.com>)
28e9fef3c: Revert^2 "Re-enable MonochromeRealtimeTest" (Marco Paniconi <marpan@google.com>)
b5556134a: Revert "Re-enable MonochromeRealtimeTest" (Marco Paniconi <marpan@google.com>)
96484b5a1: rtc: Extend speed 11 to resolutions above 720p for camera input (Marco Paniconi <marpan@google.com>)
3b8a9b236: Re-enable MonochromeRealtimeTest (Marco Paniconi <marpan@google.com>)
93f20a145: test.cmake: enable monochrome_test.cc w/CONFIG_REALTIME_ONLY (James Zern <jzern@google.com>)
cb7d3eb73: Remove experimental status of AOM_CODEC_USE_PRESET (Wan-Teh Chang <wtc@google.com>)
f21be213b: av1_cx_iface.c: clarify allintra overrides (Julio Barba <juliobbv@gmail.com>)
3395f9a10: Introduce qindex -> QM level formula tuned for allintra mode (Julio Barba <juliobbv@gmail.com>)
540542caa: sad_sse2.asm,cosmetics: fix function names in comments (James Zern <jzern@google.com>)
0a56af371: rm unused aom_sad_skip functions (James Zern <jzern@google.com>)
3e71b2681: rm unused aom_highbd_sad_skip functions (James Zern <jzern@google.com>)
ff1bba121: Update `sharpness` comments to mention loop filter adjustment (Julio Barba <juliobbv@gmail.com>)
5b48af3fe: Lower PSNR thresholds after commit b4f03d7 (Wan-Teh Chang <wtc@google.com>)
5dd7a2e5e: log_sub_block_var: move fn ptr constant out of loop (James Zern <jzern@google.com>)
6fcaf2cb2: tpl_model.c: add missing CONFIG_* checks (James Zern <jzern@google.com>)
1abb3a86c: pass2_strategy.c: make av1_gop_bit_allocation static (James Zern <jzern@google.com>)
b4f03d760: Wire `sharpness` value to loop filter sharpness in allintra mode (Julio Barba <juliobbv@gmail.com>)
f036dcbff: cdef_test,cosmetics: fix class member names (James Zern <jzern@google.com>)
95a2b8973: av1_fwd_txfm1d_sse4.c: rm unused av1_fadst4_sse4_1 (James Zern <jzern@google.com>)
87aa5a96e: ratectrl.c: rm av1_q_mode_get_q_index (James Zern <jzern@google.com>)
58017cc71: args_helper.c: make arg_init() static (James Zern <jzern@google.com>)
99bac040e: quant_common.c: remove av1_qmatrix() (James Zern <jzern@google.com>)
c1b5f78aa: rtc: Fix to color_sensitivity for fading scene transitions (Marco Paniconi <marpan@google.com>)
6972a6494: txb_rdopt.c: make av1_cost_coeffs_txb_estimate static (James Zern <jzern@google.com>)
e88161627: av1_encoder.dox: fix doxygen 1.9.8 warnings (James Zern <jzern@google.com>)
d37af01e8: bitstream.c: make av1_write_uleb_obu_size_unsafe static (James Zern <jzern@google.com>)
00e3da195: fast_9.c: make aom_fast9_corner_score static (James Zern <jzern@google.com>)
270b7d59b: entenc.c: rm od_ec_enc_patch_initial_bits() (James Zern <jzern@google.com>)
88e0bd404: partition_strategy.c: add missing CONFIG_ check (James Zern <jzern@google.com>)
6b3cfa194: restoration.c: make av1_loop_restoration_copy_planes static (James Zern <jzern@google.com>)
5975de7ec: resize.c: make av1_highbd_resize_plane static (James Zern <jzern@google.com>)
999567b9b: mv av1_calculate_unscaled_superres_size() to test (James Zern <jzern@google.com>)
61046cf6d: misc_model_weights.h: make tables static (James Zern <jzern@google.com>)
7b366cb5f: pass2_strategy.c: make some fns static (James Zern <jzern@google.com>)
bb6e9f7f3: grain_synthesis.c: make av1_add_film_grain_run static (James Zern <jzern@google.com>)
076306fec: binary_codes_writer.c: make some fns static (James Zern <jzern@google.com>)
f3955b2a9: binary_codes_writer.c: remove unused functions (James Zern <jzern@google.com>)
e6925ce65: rtc-screen: Reduce thresholds to set high_source_sad (Marco Paniconi <marpan@google.com>)
4a244f0f9: Enable skip_encoding_non_reference when frame_dropper enabled (Marco Paniconi <marpan@google.com>)
241da4674: rm aom_highbd_dist_wtd_comp_avg_upsampled_pred (James Zern <jzern@google.com>)
cbe1ed4db: partition_search.c: add missing CONFIG_ check (James Zern <jzern@google.com>)
d25f4c90d: tpl_model.c: make av1_tpl_get_frame_importance static (James Zern <jzern@google.com>)
e9271ea81: Fix exit condition in rate correction update (Marco Paniconi <marpan@google.com>)
13e711d6d: aom/exports_com: rm aom_wb_* (James Zern <jzern@google.com>)
840f87978: Avoid the use of aom_write_bit_buffer (Wan-Teh Chang <wtc@google.com>)
ed5a2445b: Do not use aom_write_bit_buffer in write_av1config (Wan-Teh Chang <wtc@google.com>)
fbe5f6101: fft.c: make some functions static (James Zern <jzern@google.com>)
a48dd53fc: rm inv_wht_sse2.asm (James Zern <jzern@google.com>)
06b8416ab: Do not export aom_dsp_rtcd,aom_scale_rtcd,av1_rtcd (Wan-Teh Chang <wtc@google.com>)
c505953b4: rtc: Reduce partition thresh_base for high motion (Marco Paniconi <marpan@google.com>)
5df8f3bc4: Fix type of previous_layer_frame_avail to avoid MSVC warning. (Maryla <maryla@google.com>)
09e894ae0: svc_encoder_rt: allow one input file per spatial layer (Maryla <maryla@google.com>)
27b123ff6: decodetxb.c: make av1_read_coeffs_txb() static (James Zern <jzern@google.com>)
1140dd36c: metadata_test: fix test w/CONFIG_REALTIME_ONLY=1 (James Zern <jzern@google.com>)
8d389aa4f: metadata_test.cc: remove unneeded bitstream.h include (James Zern <jzern@google.com>)
b8f382156: aom/exports_com: rm aom_img_metadata_array_{alloc,free} (James Zern <jzern@google.com>)
bebbb6d87: global_motion.c: make av1_warp_error() static (James Zern <jzern@google.com>)
b2fd5787b: decodeframe.c: make av1_read_frame_size() static (James Zern <jzern@google.com>)
95ad0bce4: av1/exports_com: rm aom_wb_write_unsigned_literal (James Zern <jzern@google.com>)
591fcbabf: av1/exports_dec: rm av1_add_film_grain (James Zern <jzern@google.com>)
278c94236: aom/exports_test: rm aom_*_metadata_to_frame_buffer (James Zern <jzern@google.com>)
a42ea198d: av1/exports_test: rm av1_fwd_txfm2d_test (James Zern <jzern@google.com>)
```

