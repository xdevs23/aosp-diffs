```diff
diff --git a/Android.bp b/Android.bp
index 5f830d5..6a76d8e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -36,6 +36,7 @@ cc_library_static {
         "src/oapv.c",
         "src/oapv_bs.c",
         "src/oapv_metadata.c",
+        "src/oapv_param.c",
         "src/oapv_port.c",
         "src/oapv_rc.c",
         "src/oapv_sad.c",
diff --git a/METADATA b/METADATA
index a0d5c2e..a4401b0 100644
--- a/METADATA
+++ b/METADATA
@@ -8,14 +8,14 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2025
-    month: 3
-    day: 5
+    month: 4
+    day: 22
   }
   homepage: "https://github.com/openapv/openapv"
   identifier {
     type: "Git"
     value: "https://github.com/openapv/openapv.git"
-    version: "v0.1.11.3"
+    version: "v0.1.13.1"
     primary_source: true
   }
 }
diff --git a/README.md b/README.md
index eb753b3..79f650c 100644
--- a/README.md
+++ b/README.md
@@ -1,7 +1,7 @@
 ![OAPV](/readme/img/oapv_logo_bar_256.png)
 # OpenAPV (Open Advanced Professional Video Codec)
 
-[![Build and test](https://github.com/openapv/openapv/actions/workflows/build.yml/badge.svg)](https://github.com/openapv/openapv/actions/workflows/build.yml)
+[![Build and test](https://github.com/AcademySoftwareFoundation/openapv/actions/workflows/build.yml/badge.svg)](https://github.com/AcademySoftwareFoundation/openapv/actions/workflows/build.yml)
 
 OpenAPV provides the reference implementation of the [APV codec](#apv-codec) which can be used to record professional-grade video and associated metadata without quality degradation. OpenAPV is free and open source software provided by [LICENSE](#license).
 
@@ -44,7 +44,7 @@ The APV codec standard has the following features:
   For ARM
   - gcc-aarch64-linux-gnu
   - binutils-aarch64-linux-gnu
- 
+
   For Windows (crosscompile)
   - mingw-w64
   - mingw-w64-tools
@@ -57,13 +57,13 @@ The APV codec standard has the following features:
 
 - Build Instructions ARM (Crosscompile)
   ```
-  cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=aarch64_toolchain.cmake -DCMAKE_BUILD_TYPE=Release 
+  cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=aarch64_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
   cmake --build build-arm
   ```
 
 - Build Instructions Windows (Crosscompile)
   ```
-  cmake -S . -B build-windows -DCMAKE_TOOLCHAIN_FILE=windows_x86_64_toolchain.cmake -DCMAKE_BUILD_TYPE=Release 
+  cmake -S . -B build-windows -DCMAKE_TOOLCHAIN_FILE=windows_x86_64_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
   cmake --build build-windows
   ```
 
@@ -71,7 +71,7 @@ The APV codec standard has the following features:
   - Executable applications can be found under build*/bin/
   - Library files can be found under build*/lib/
 
-## How to use
+## How to use applications
 ### Encoder
 
 Encoder as input require raw YCbCr file (422, 444), 10-bit or more.
diff --git a/app/oapv_app_args.h b/app/oapv_app_args.h
index 55711ed..f6e85c3 100644
--- a/app/oapv_app_args.h
+++ b/app/oapv_app_args.h
@@ -69,6 +69,7 @@ struct args_parser {
     int (*get_int)(args_parser_t *args, char *keyl, int *val, int *flag);
     int (*set_str)(args_parser_t *args, char *keyl, char *str);
     int (*set_int)(args_parser_t *args, char *keyl, int val);
+    int (*set_int2str)(args_parser_t* args, char* keyl, int val);
     int (*set_flag)(args_parser_t *args, char *keyl, int flag);
     int (*check_mandatory)(args_parser_t *args, char **err_arg);
 
@@ -406,6 +407,21 @@ static int args_set_int(args_parser_t *args, char *keyl, int val)
     }
 }
 
+static int args_set_int2str(args_parser_t* args, char* keyl, int val)
+{
+    int idx;
+
+    idx = args_search_long_key(args->opts, keyl);
+    if (idx >= 0) {
+        sprintf((char*)(args->opts[idx].val), "%d", val);
+        args->opts[idx].flag = 1;
+        return 0;
+    }
+    else {
+        return -1;
+    }
+}
+
 static int args_set_flag(args_parser_t *args, char *keyl, int flag)
 {
     int idx;
@@ -572,6 +588,7 @@ static args_parser_t *args_create(const args_opt_t *opt_table, int num_opt)
     args->get_int = args_get_int;
     args->set_str = args_set_str;
     args->set_int = args_set_int;
+    args->set_int2str = args_set_int2str;
     args->set_flag = args_set_flag;
     args->check_mandatory = args_check_mandatory;
 
diff --git a/app/oapv_app_dec.c b/app/oapv_app_dec.c
index 15dcbbc..b553282 100644
--- a/app/oapv_app_dec.c
+++ b/app/oapv_app_dec.c
@@ -69,8 +69,9 @@ static const args_opt_t dec_args_opts[] = {
         "maximum number of access units to be decoded"
     },
     {
-        'm',  "threads", ARGS_VAL_TYPE_INTEGER, 0, NULL,
+        'm',  "threads", ARGS_VAL_TYPE_STRING, 0, NULL,
         "force to use a specific number of threads"
+        "      - 'auto' means that the value is internally determined"
     },
     {
         'd',  "output-depth", ARGS_VAL_TYPE_INTEGER, 0, NULL,
@@ -98,7 +99,7 @@ typedef struct args_var {
     char fname_out[256];
     int  max_au;
     int  hash;
-    int  threads;
+    char threads[16];
     int  output_depth;
     int  output_csp;
 } args_var_t;
@@ -119,8 +120,8 @@ static args_var_t *args_init_vars(args_parser_t *args)
     args_set_variable_by_key_long(opts, "hash", &vars->hash);
     args_set_variable_by_key_long(opts, "verbose", &op_verbose);
     op_verbose = VERBOSE_SIMPLE; /* default */
-    args_set_variable_by_key_long(opts, "threads", &vars->threads);
-    vars->threads = 1; /* default */
+    args_set_variable_by_key_long(opts, "threads", vars->threads);
+    strcpy(vars->threads, "auto");
     args_set_variable_by_key_long(opts, "output-depth", &vars->output_depth);
     args_set_variable_by_key_long(opts, "output-csp", &vars->output_csp);
     vars->output_csp = 0; /* default: coded CSP */
@@ -374,6 +375,14 @@ int main(int argc, const char **argv)
     memset(&aui, 0, sizeof(oapv_au_info_t));
     memset(&ofrms, 0, sizeof(oapv_frms_t));
 
+    // print logo
+    logv2("  ____                ___   ___ _   __\n");
+    logv2(" / __ \\___  ___ ___  / _ | / _ \\ | / / Decoder (v%s)\n", oapv_version());
+    logv2("/ /_/ / _ \\/ -_) _ \\/ __ |/ ___/ |/ / \n");
+    logv2("\\____/ .__/\\__/_//_/_/ |_/_/   |___/  \n");
+    logv2("    /_/                               \n");
+    logv2("\n");
+
     /* help message */
     if(argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
         print_usage(argv);
@@ -397,14 +406,6 @@ int main(int argc, const char **argv)
         ret = -1;
         goto ERR;
     }
-    // print logo
-    logv2("  ____                ___   ___ _   __\n");
-    logv2(" / __ \\___  ___ ___  / _ | / _ \\ | / / Decoder\n");
-    logv2("/ /_/ / _ \\/ -_) _ \\/ __ |/ ___/ |/ / \n");
-    logv2("\\____/ .__/\\__/_//_/_/ |_/_/   |___/  \n");
-    logv2("    /_/                               \n");
-    logv2("\n");
-
     // print command line string for information
     print_commandline(argc, argv);
 
@@ -445,7 +446,12 @@ int main(int argc, const char **argv)
         goto ERR;
     }
     // create decoder
-    cdesc.threads = args_var->threads;
+    if(!strcmp(args_var->threads, "auto")){
+        cdesc.threads = OAPV_CDESC_THREADS_AUTO;
+    }
+    else {
+        cdesc.threads = atoi(args_var->threads);
+    }
     did = oapvd_create(&cdesc, &ret);
     if(did == NULL) {
         logerr("ERROR: cannot create OAPV decoder (err=%d)\n", ret);
diff --git a/app/oapv_app_enc.c b/app/oapv_app_enc.c
index 58fa94c..1132208 100644
--- a/app/oapv_app_enc.c
+++ b/app/oapv_app_enc.c
@@ -70,26 +70,28 @@ static const args_opt_t enc_args_opts[] = {
         "file name of reconstructed video"
     },
     {
-        'w',  "width", ARGS_VAL_TYPE_INTEGER | ARGS_VAL_TYPE_MANDATORY, 0, NULL,
+        'w',  "width", ARGS_VAL_TYPE_STRING, 0, NULL,
         "pixel width of input video"
     },
     {
-        'h',  "height", ARGS_VAL_TYPE_INTEGER | ARGS_VAL_TYPE_MANDATORY, 0, NULL,
+        'h',  "height", ARGS_VAL_TYPE_STRING, 0, NULL,
         "pixel height of input video"
     },
     {
-        'q',  "qp", ARGS_VAL_TYPE_INTEGER, 0, NULL,
+        'q',  "qp", ARGS_VAL_TYPE_STRING, 0, NULL,
         "QP value: 0 ~ (63 + (bitdepth - 10)*6) \n"
         "      - 10bit input: 0 ~ 63\n"
-        "      - 12bit input: 0 ~ 75\n"
+        "      - 12bit input: 0 ~ 75"
+        "      - 'auto' means that the value is internally determined"
     },
     {
-        'z',  "fps", ARGS_VAL_TYPE_STRING | ARGS_VAL_TYPE_MANDATORY, 0, NULL,
+        'z',  "fps", ARGS_VAL_TYPE_STRING, 0, NULL,
         "frame rate (frame per second))"
     },
     {
-        'm',  "threads", ARGS_VAL_TYPE_INTEGER, 0, NULL,
-        "force to use a specific number of threads"
+        'm',  "threads", ARGS_VAL_TYPE_STRING, 0, NULL,
+        "force to use a specific number of threads\n"
+        "      - 'auto' means that the value is internally determined"
     },
     {
         ARGS_NO_KEY,  "preset", ARGS_VAL_TYPE_STRING, 0, NULL,
@@ -115,10 +117,11 @@ static const args_opt_t enc_args_opts[] = {
     },
     {
         ARGS_NO_KEY,  "level", ARGS_VAL_TYPE_STRING, 0, NULL,
-        "level setting (1, 1.1, 2, 2.1, 3, 3.1, 4, 4.1, 5, 5.1, 6, 6.1, 7, 7.1)"
+        "level setting (1, 1.1, 2, 2.1, 3, 3.1, 4, 4.1, 5, 5.1, 6, 6.1, 7, 7.1)\n"
+        "      - 'auto' means that the value is internally determined"
     },
     {
-        ARGS_NO_KEY,  "band", ARGS_VAL_TYPE_INTEGER, 0, NULL,
+        ARGS_NO_KEY,  "band", ARGS_VAL_TYPE_STRING, 0, NULL,
         "band setting (0, 1, 2, 3)"
     },
     {
@@ -130,24 +133,24 @@ static const args_opt_t enc_args_opts[] = {
         "number of skipped access units before encoding"
     },
     {
-        ARGS_NO_KEY,  "qp-offset-c1", ARGS_VAL_TYPE_INTEGER, 0, NULL,
+        ARGS_NO_KEY,  "qp-offset-c1", ARGS_VAL_TYPE_STRING, 0, NULL,
         "QP offset value for Component 1 (Cb)"
     },
     {
-        ARGS_NO_KEY,  "qp-offset-c2", ARGS_VAL_TYPE_INTEGER, 0, NULL,
+        ARGS_NO_KEY,  "qp-offset-c2", ARGS_VAL_TYPE_STRING, 0, NULL,
         "QP offset value for Component 2 (Cr)"
     },
     {
-        ARGS_NO_KEY,  "qp-offset-c3", ARGS_VAL_TYPE_INTEGER, 0, NULL,
+        ARGS_NO_KEY,  "qp-offset-c3", ARGS_VAL_TYPE_STRING, 0, NULL,
         "QP offset value for Component 3"
     },
     {
-        ARGS_NO_KEY,  "tile-w-mb", ARGS_VAL_TYPE_INTEGER, 0, NULL,
-        "width of tile in units of MBs"
+        ARGS_NO_KEY,  "tile-w", ARGS_VAL_TYPE_STRING, 0, NULL,
+        "width of tile in units of pixels"
     },
     {
-        ARGS_NO_KEY,  "tile-h-mb", ARGS_VAL_TYPE_INTEGER, 0, NULL,
-        "height of tile in units of MBs"
+        ARGS_NO_KEY,  "tile-h", ARGS_VAL_TYPE_STRING, 0, NULL,
+        "height of tile in units of pixels"
     },
     {
         ARGS_NO_KEY,  "bitrate", ARGS_VAL_TYPE_STRING, 0, NULL,
@@ -155,10 +158,6 @@ static const args_opt_t enc_args_opts[] = {
         "      bitrate in terms of kilo-bits per second: Kbps(none,K,k), Mbps(M,m)\n"
         "      ex) 100 = 100K = 0.1M"
     },
-    {
-        ARGS_NO_KEY,  "use-filler", ARGS_VAL_TYPE_INTEGER, 0, NULL,
-        "user filler flag"
-    },
     {
         ARGS_NO_KEY,  "q-matrix-c0", ARGS_VAL_TYPE_STRING, 0, NULL,
         "custom quantization matrix for component 0 (Y) \"q1 q2 ... q63 q64\""
@@ -196,14 +195,36 @@ typedef struct args_var {
     int            input_depth;
     int            input_csp;
     int            seek;
-    int            threads;
-    char           profile[32];
-    char           level[32];
-    int            band;
-    char           bitrate[64];
-    char           fps[256];
-    char           q_matrix[OAPV_MAX_CC][512]; // raster-scan order
-    char           preset[32];
+    char           threads[16];
+
+    char           profile[16];
+    char           level[16];
+    char           band[16];
+
+    char           width[16];
+    char           height[16];
+    char           fps[16];
+
+    char           qp[16];
+    char           qp_offset_c1[16];
+    char           qp_offset_c2[16];
+    char           qp_offset_c3[16];
+    char           bitrate[32];
+
+    char           preset[16];
+
+    char           q_matrix_c0[512]; // raster-scan order
+    char           q_matrix_c1[512]; // raster-scan order
+    char           q_matrix_c2[512]; // raster-scan order
+    char           q_matrix_c3[512]; // raster-scan order
+    char           tile_w[16];
+    char           tile_h[16];
+
+    char           color_primaries[16];
+    char           color_transfer[16];
+    char           color_matrix[16];
+    char           color_range[16];
+
     oapve_param_t *param;
 } args_var_t;
 
@@ -235,34 +256,34 @@ static args_var_t *args_init_vars(args_parser_t *args, oapve_param_t *param)
     args_set_variable_by_key_long(opts, "profile", vars->profile);
     strcpy(vars->profile, "422-10");
     args_set_variable_by_key_long(opts, "level", vars->level);
-    strcpy(vars->level, "4.1");
-    args_set_variable_by_key_long(opts, "band", &vars->band);
-    vars->band = 2; /* default */
-    args_set_variable_by_key_long(opts, "bitrate", vars->bitrate);
+    strcpy(vars->level, "auto"); /* default */
+    args_set_variable_by_key_long(opts, "band", vars->band);
+    strcpy(vars->band, "2"); /* default */
+
+    args_set_variable_by_key_long(opts, "width", vars->width);
+    args_set_variable_by_key_long(opts, "height", vars->height);
     args_set_variable_by_key_long(opts, "fps", vars->fps);
-    strcpy(vars->fps, "60");
-    args_set_variable_by_key_long(opts, "q-matrix-c0", vars->q_matrix[0]);
-    strcpy(vars->q_matrix[0], "");
-    args_set_variable_by_key_long(opts, "q-matrix-c1", vars->q_matrix[1]);
-    strcpy(vars->q_matrix[1], "");
-    args_set_variable_by_key_long(opts, "q-matrix-c2", vars->q_matrix[2]);
-    strcpy(vars->q_matrix[2], "");
-    args_set_variable_by_key_long(opts, "q-matrix-c3", vars->q_matrix[3]);
-    strcpy(vars->q_matrix[3], "");
-    args_set_variable_by_key_long(opts, "threads", &vars->threads);
-    vars->threads = 1; /* default */
+
+    args_set_variable_by_key_long(opts, "qp", vars->qp);
+    strcpy(vars->qp, "auto"); /* default */
+    args_set_variable_by_key_long(opts, "qp_offset_c1", vars->qp_offset_c1);
+    args_set_variable_by_key_long(opts, "qp_offset_c2", vars->qp_offset_c2);
+    args_set_variable_by_key_long(opts, "qp_offset_c3", vars->qp_offset_c3);
+
+
+    args_set_variable_by_key_long(opts, "bitrate", vars->bitrate);
+    args_set_variable_by_key_long(opts, "q-matrix-c0", vars->q_matrix_c0);
+    args_set_variable_by_key_long(opts, "q-matrix-c1", vars->q_matrix_c1);
+    args_set_variable_by_key_long(opts, "q-matrix-c2", vars->q_matrix_c2);
+    args_set_variable_by_key_long(opts, "q-matrix-c3", vars->q_matrix_c3);
+
+    args_set_variable_by_key_long(opts, "threads", vars->threads);
+    strcpy(vars->threads, "auto");
+
+    args_set_variable_by_key_long(opts, "tile-w", vars->tile_w);
+    args_set_variable_by_key_long(opts, "tile-h", vars->tile_h);
+
     args_set_variable_by_key_long(opts, "preset", vars->preset);
-    strcpy(vars->preset, "");
-
-    ARGS_SET_PARAM_VAR_KEY(opts, param, w);
-    ARGS_SET_PARAM_VAR_KEY(opts, param, h);
-    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, qp);
-    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, use_filler);
-    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, tile_w_mb);
-    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, tile_h_mb);
-    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, qp_offset_c1);
-    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, qp_offset_c2);
-    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, qp_offset_c3);
 
     return vars;
 }
@@ -353,6 +374,29 @@ static void print_commandline(int argc, const char **argv)
     logv3("\n\n");
 }
 
+static void add_thousands_comma_to_number(char *in, char *out)
+{
+    int len, left = 0;
+    len = strlen(in);
+    left = len % 3;
+
+    while(len > 0) {
+        *out = *in;
+
+        out++; in++;
+
+        left--;
+        len--;
+
+        if(left == 0 && len >= 3) {
+            *out = ',';
+            out++;
+            left = 3;
+        }
+    }
+    *out='\0';
+}
+
 static void print_config(args_var_t *vars, oapve_param_t *param)
 {
     if(op_verbose < VERBOSE_FRAME)
@@ -367,16 +411,21 @@ static void print_config(args_var_t *vars, oapve_param_t *param)
         logv3("Reconstructed sequence : %s \n", vars->fname_rec);
     }
     logv3("    profile             = %s\n", vars->profile);
+    logv3("    level               = %s\n", vars->level);
+    logv3("    band                = %s\n", vars->band);
     logv3("    width               = %d\n", param->w);
     logv3("    height              = %d\n", param->h);
-    logv3("    FPS                 = %.2f\n", (float)param->fps_num / param->fps_den);
-    logv3("    QP                  = %d\n", param->qp);
-    logv3("    max number of AUs   = %d\n", vars->max_au);
-    logv3("    rate control type   = %s\n", (param->rc_type == OAPV_RC_ABR) ? "average Bitrate" : "constant QP");
-    if(param->rc_type == OAPV_RC_ABR) {
-        logv3("    target bitrate      = %dkbps\n", param->bitrate);
+    logv3("    fps                 = %.2f\n", (float)param->fps_num / param->fps_den);
+    logv3("    rate control type   = %s\n", (param->rc_type == OAPV_RC_ABR) ? "average bitrate" : "constant qp");
+    if(param->rc_type == OAPV_RC_CQP){
+        logv3("    qp                  = %d\n", param->qp);
+    }
+    else if(param->rc_type == OAPV_RC_ABR) {
+        //add_thousands_comma_to_number(vars->bitrate, tstr);
+        logv3("    target bitrate      = %s\n", vars->bitrate);
     }
-    logv3("    tile size           = %d x %d\n", param->tile_w_mb * OAPV_MB_W, param->tile_h_mb * OAPV_MB_H);
+    logv3("    max number of AUs   = %d\n", vars->max_au);
+    logv3("    tile size           = %d x %d\n", param->tile_w, param->tile_h);
 }
 
 static void print_stat_au(oapve_stat_t *stat, int au_cnt, oapve_param_t *param, int max_au, double bitrate_tot, oapv_clk_t clk_au, oapv_clk_t clk_tot)
@@ -462,108 +511,47 @@ static int kbps_str_to_int(char *str)
     return kbps;
 }
 
+#define UPDATE_A_PARAM_W_KEY_VAL(param, key, val) \
+    if(strlen(val) > 0) { \
+        if(OAPV_FAILED(oapve_param_parse(param, key, val))) { \
+            logerr("input value (%s) of %s is invalid\n", val, key); \
+            return -1; \
+        } \
+    }
+
 static int update_param(args_var_t *vars, oapve_param_t *param)
 {
-    int q_len[OAPV_MAX_CC];
-    /* update reate controller  parameters */
-    if(strlen(vars->bitrate) > 0) {
-        param->bitrate = kbps_str_to_int(vars->bitrate);
-        param->rc_type = OAPV_RC_ABR;
-    }
-
-    /* update q_matrix */
-    for(int c = 0; c < OAPV_MAX_CC; c++) {
-        q_len[c] = (int)strlen(vars->q_matrix[c]);
-        if(q_len[c] > 0) {
-            param->use_q_matrix = 1;
-            char *qstr = vars->q_matrix[c];
-            int   qcnt = 0;
-            while(strlen(qstr) > 0 && qcnt < OAPV_BLK_D) {
-                int t0, read;
-                sscanf(qstr, "%d%n", &t0, &read);
-                if(t0 < 1 || t0 > 255) {
-                    logerr("input value (%d) for q_matrix[%d][%d] is invalid\n", t0, c, qcnt);
-                    return -1;
-                }
-                param->q_matrix[c][qcnt] = t0;
-                qstr += read;
-                qcnt++;
-            }
-            if(qcnt < OAPV_BLK_D) {
-                logerr("input number of q_matrix[%d] is not enough\n", c);
-                return -1;
-            }
-        }
-    }
+    UPDATE_A_PARAM_W_KEY_VAL(param, "profile", vars->profile);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "level", vars->level);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "band", vars->band);
 
-    param->csp = vars->input_csp;
+    UPDATE_A_PARAM_W_KEY_VAL(param, "width", vars->width);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "height", vars->height);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "fps", vars->fps);
 
-    /* update level idc */
-    float tmp_level = 0;
-    sscanf(vars->level, "%f", &tmp_level);
-    param->level_idc = (int)((tmp_level * 30.0) + 0.5);
-    /* update band idc */
-    param->band_idc = vars->band;
+    UPDATE_A_PARAM_W_KEY_VAL(param, "qp", vars->qp);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "qp-offset-c1", vars->qp_offset_c1);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "qp-offset-c2", vars->qp_offset_c2);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "qp-offset-c3", vars->qp_offset_c3);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "bitrate", vars->bitrate);
 
-    /* update fps */
-    if(strpbrk(vars->fps, "/") != NULL) {
-        sscanf(vars->fps, "%d/%d", &param->fps_num, &param->fps_den);
-    }
-    else if(strpbrk(vars->fps, ".") != NULL) {
-        float tmp_fps = 0;
-        sscanf(vars->fps, "%f", &tmp_fps);
-        param->fps_num = tmp_fps * 10000;
-        param->fps_den = 10000;
-    }
-    else {
-        sscanf(vars->fps, "%d", &param->fps_num);
-        param->fps_den = 1;
-    }
+    UPDATE_A_PARAM_W_KEY_VAL(param, "preset", vars->preset);
 
-    if(strlen(vars->preset) > 0) {
-        if(strcmp(vars->preset, "fastest") == 0) {
-            param->preset = OAPV_PRESET_FASTEST;
-        }
-        else if(strcmp(vars->preset, "fast") == 0) {
-            param->preset = OAPV_PRESET_FAST;
-        }
-        else if(strcmp(vars->preset, "medium") == 0) {
-            param->preset = OAPV_PRESET_MEDIUM;
-        }
-        else if(strcmp(vars->preset, "slow") == 0) {
-            param->preset = OAPV_PRESET_SLOW;
-        }
-        else if(strcmp(vars->preset, "placebo") == 0) {
-            param->preset = OAPV_PRESET_PLACEBO;
-        }
-        else {
-            logerr("input value of preset is invalid\n");
-            return -1;
-        }
-    }
-    else {
-        param->preset = OAPV_PRESET_DEFAULT;
-    }
+    UPDATE_A_PARAM_W_KEY_VAL(param, "q-matrix-c0", vars->q_matrix_c0);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "q-matrix-c1", vars->q_matrix_c1);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "q-matrix-c2", vars->q_matrix_c2);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "q-matrix-c3", vars->q_matrix_c3);
 
-    /* update tile */
-    if (param->tile_w_mb < OAPV_MIN_TILE_W_MB) {
-        param->tile_w_mb = OAPV_MIN_TILE_W_MB;
-    }
-    if (param->tile_h_mb < OAPV_MIN_TILE_H_MB) {
-        param->tile_h_mb = OAPV_MIN_TILE_H_MB;
-    }
+    UPDATE_A_PARAM_W_KEY_VAL(param, "color-primaries", vars->color_primaries);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "color-transfer", vars->color_transfer);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "color-matrix", vars->color_matrix);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "color-range", vars->color_range);
 
-    int tile_w = param->tile_w_mb << OAPV_LOG2_MB_W;
-    int tile_h = param->tile_h_mb << OAPV_LOG2_MB_H;
-    int tile_cols = (param->w + tile_w - 1) / tile_w;
-    int tile_rows = (param->h + tile_h - 1) / tile_h;
-    if (tile_cols > OAPV_MAX_TILE_COLS) {
-        param->tile_w_mb = (((param->w + OAPV_MB_W - 1) >> OAPV_LOG2_MB_W) + OAPV_MAX_TILE_COLS - 1) / OAPV_MAX_TILE_COLS;
-    }
-    if (tile_rows > OAPV_MAX_TILE_ROWS) {
-        param->tile_h_mb = (((param->h + OAPV_MB_H - 1) >> OAPV_LOG2_MB_H) + OAPV_MAX_TILE_ROWS - 1) / OAPV_MAX_TILE_ROWS;
-    }
 
+    UPDATE_A_PARAM_W_KEY_VAL(param, "tile-w", vars->tile_w);
+    UPDATE_A_PARAM_W_KEY_VAL(param, "tile-h", vars->tile_h);
+
+    param->csp = vars->input_csp;
     return 0;
 }
 
@@ -599,6 +587,14 @@ int main(int argc, const char **argv)
     int            cfmt;                      // color format
     const int      num_frames = MAX_NUM_FRMS; // number of frames in an access unit
 
+    // print logo
+    logv2("  ____                ___   ___ _   __\n");
+    logv2(" / __ \\___  ___ ___  / _ | / _ \\ | / / Encoder (v%s)\n", oapv_version());
+    logv2("/ /_/ / _ \\/ -_) _ \\/ __ |/ ___/ |/ / \n");
+    logv2("\\____/ .__/\\__/_//_/_/ |_/_/   |___/  \n");
+    logv2("    /_/                               \n");
+    logv2("\n");
+
     /* help message */
     if(argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
         print_usage(argv);
@@ -632,14 +628,6 @@ int main(int argc, const char **argv)
         ret = -1;
         goto ERR;
     }
-    // print logo
-    logv2("  ____                ___   ___ _   __\n");
-    logv2(" / __ \\___  ___ ___  / _ | / _ \\ | / / Encoder\n");
-    logv2("/ /_/ / _ \\/ -_) _ \\/ __ |/ ___/ |/ / \n");
-    logv2("\\____/ .__/\\__/_//_/_/ |_/_/   |___/  \n");
-    logv2("    /_/                               \n");
-    logv2("\n");
-
     // print command line string for information
     print_commandline(argc, argv);
 
@@ -691,6 +679,17 @@ int main(int argc, const char **argv)
             (args_var->input_csp == 4 ? OAPV_CF_YCBCR4444 : \
             (args_var->input_csp == 5 ? OAPV_CF_PLANAR2   : OAPV_CF_UNKNOWN))))));
         // clang-format on
+
+        // check mandatory parameters for YUV raw file.
+        if(strlen(args_var->width) == 0) {
+            logerr("'--width' argument is required\n"); ret = -1; goto ERR;
+        }
+        if(strlen(args_var->height) == 0) {
+            logerr("'--height' argument is required\n"); ret = -1; goto ERR;
+        }
+        if(strlen(args_var->fps) == 0) {
+            logerr("'--fps' argument is required\n"); ret = -1; goto ERR;
+        }
     }
     if(args_var->input_csp == -1) {
         logerr("Unknown input color space. set '--input-csp' argument\n");
@@ -707,7 +706,12 @@ int main(int argc, const char **argv)
 
     cdesc.max_bs_buf_size = MAX_BS_BUF; /* maximum bitstream buffer size */
     cdesc.max_num_frms = MAX_NUM_FRMS;
-    cdesc.threads = args_var->threads;
+    if(!strcmp(args_var->threads, "auto")){
+        cdesc.threads = OAPV_CDESC_THREADS_AUTO;
+    }
+    else {
+        cdesc.threads = atoi(args_var->threads);
+    }
 
     if(check_conf(&cdesc, args_var)) {
         logerr("invalid configuration\n");
@@ -745,10 +749,9 @@ int main(int argc, const char **argv)
     }
 
     /* create encoder */
-    id = oapve_create(&cdesc, NULL);
+    id = oapve_create(&cdesc, &ret);
     if(id == NULL) {
         logerr("cannot create OAPV encoder\n");
-        ret = -1;
         goto ERR;
     }
 
diff --git a/app/oapv_app_y4m.h b/app/oapv_app_y4m.h
index e385028..8f6fe79 100644
--- a/app/oapv_app_y4m.h
+++ b/app/oapv_app_y4m.h
@@ -207,8 +207,8 @@ int y4m_header_parser(FILE *ip_y4m, y4m_params_t *y4m)
 
 static void y4m_update_param(args_parser_t *args, y4m_params_t *y4m)
 {
-    args->set_int(args, "width", y4m->w);
-    args->set_int(args, "height", y4m->h);
+    args->set_int2str(args, "width", y4m->w);
+    args->set_int2str(args, "height", y4m->h);
     char tmp_fps[256];
     sprintf(tmp_fps, "%d/%d", y4m->fps_num, y4m->fps_den);
     args->set_str(args, "fps", tmp_fps);
diff --git a/inc/oapv.h b/inc/oapv.h
index db4a091..84dc1c2 100644
--- a/inc/oapv.h
+++ b/inc/oapv.h
@@ -60,11 +60,13 @@ extern "C" {
 #define OAPV_BLK_D                      (OAPV_BLK_W * OAPV_BLK_H)
 
 /* size of tile */
-#define OAPV_MAX_TILE_ROWS              (20)
-#define OAPV_MAX_TILE_COLS              (20)
+#define OAPV_MAX_TILE_ROWS              (20) // max number of tiles in row
+#define OAPV_MAX_TILE_COLS              (20) // max number of tiles in column
 #define OAPV_MAX_TILES                  (OAPV_MAX_TILE_ROWS * OAPV_MAX_TILE_COLS)
 #define OAPV_MIN_TILE_W_MB              (16)
 #define OAPV_MIN_TILE_H_MB              (8)
+#define OAPV_MIN_TILE_W                 (OAPV_MIN_TILE_W_MB << OAPV_LOG2_MB_W)
+#define OAPV_MIN_TILE_H                 (OAPV_MIN_TILE_H_MB << OAPV_LOG2_MB_H)
 
 /* maximum number of thread */
 #define OAPV_MAX_THREADS                (32)
@@ -84,6 +86,7 @@ extern "C" {
 #define OAPV_ERR_OUT_OF_BS_BUF          (-203) /* too small bitstream buffer */
 #define OAPV_ERR_NOT_FOUND              (-204)
 #define OAPV_ERR_FAILED_SYSCALL         (-301)   /* failed system call */
+#define OAPV_ERR_INVALID_LEVEL          (-401)
 #define OAPV_ERR_UNKNOWN                (-32767) /* unknown error */
 
 /* return value checking */
@@ -360,15 +363,18 @@ struct oapv_frm_info {
     int           chroma_format_idc;
     int           bit_depth;
     int           capture_time_distance;
-    /* custom quantization matrix */
+    // flag for custom quantization matrix
     int           use_q_matrix;
-    unsigned char q_matrix[OAPV_MAX_CC][OAPV_BLK_D]; // only meaningful if use_q_matrix is true
-    /* color description values */
+    // q_matrix is meaningful if use_q_matrix is true
+    unsigned char q_matrix[OAPV_MAX_CC][OAPV_BLK_D];
+    // flag for color_description_present_flag */
     int           color_description_present_flag;
-    unsigned char color_primaries;          // only meaningful if color_description_present_flag is true
-    unsigned char transfer_characteristics; // only meaningful if color_description_present_flag is true
-    unsigned char matrix_coefficients;      // only meaningful if color_description_present_flag is true
-    int           full_range_flag;          // only meaningful if color_description_present_flag is true
+    // color_primaries, transfer_characteristics, matrix_coefficients, and
+    // full_range_flag are meaningful if color_description_present_flag is true
+    unsigned char color_primaries;
+    unsigned char transfer_characteristics;
+    unsigned char matrix_coefficients;
+    int           full_range_flag;
 };
 
 typedef struct oapv_au_info oapv_au_info_t;
@@ -377,16 +383,109 @@ struct oapv_au_info {
     oapv_frm_info_t frm_info[OAPV_MAX_NUM_FRAMES];
 };
 
+/*****************************************************************************
+ * constant string values for oapve_param_parse() and command-line options
+ *****************************************************************************/
+typedef struct oapv_dict_str_int oapv_dict_str_int_t; // dictionary type
+struct oapv_dict_str_int {
+    const char * key;
+    const int    val;
+};
+
+static const oapv_dict_str_int_t oapv_param_opts_profile[] = {
+    {"422-10",  OAPV_PROFILE_422_10},
+    {"", 0} // termination
+};
+
+static const oapv_dict_str_int_t oapv_param_opts_preset[] = {
+    {"fastest", OAPV_PRESET_FASTEST},
+    {"fast",    OAPV_PRESET_FAST},
+    {"medium",  OAPV_PRESET_MEDIUM},
+    {"slow",    OAPV_PRESET_SLOW},
+    {"placebo", OAPV_PRESET_PLACEBO},
+    {"", 0} // termination
+};
+
+static const oapv_dict_str_int_t oapv_param_opts_color_range[] = {
+    {"limited", 0},
+    {"tv",      0}, // alternative value of "limited"
+    {"full",    1},
+    {"pc",      1}, // alternative value of "full"
+    {"", 0} // termination
+};
+
+static const oapv_dict_str_int_t oapv_param_opts_color_primaries[] = {
+    {"reserved",     0},
+    {"bt709",        1},
+    {"unspecified",  2},
+    {"reserved",     3},
+    {"bt470m",       4},
+    {"bt470bg",      5},
+    {"smpte170m",    6},
+    {"smpte240m",    7},
+    {"film",         8},
+    {"bt2020",       9},
+    {"smpte428",    10},
+    {"smpte431",    11},
+    {"smpte432",    12},
+    {"", 0} // termination
+};
+
+static const oapv_dict_str_int_t oapv_param_opts_color_transfer[] = {
+    {"reserved",        0},
+    {"bt709",           1},
+    {"unspecified",     2},
+    {"reserved",        3},
+    {"bt470m",          4},
+    {"bt470bg",         5},
+    {"smpte170m",       6},
+    {"smpte240m",       7},
+    {"linear",          8},
+    {"log100",          9},
+    {"log316",         10},
+    {"iec61966-2-4",   11},
+    {"bt1361e",        12},
+    {"iec61966-2-1",   13},
+    {"bt2020-10",      14},
+    {"bt2020-12",      15},
+    {"smpte2084",      16},
+    {"smpte428",       17},
+    {"arib-std-b67",   18},
+    {"", 0} // termination
+};
+static const oapv_dict_str_int_t oapv_param_opts_color_matrix[] = {
+    {"gbr",                 0},
+    {"bt709",               1},
+    {"unspecified",         2},
+    {"reserved",            3},
+    {"fcc",                 4},
+    {"bt470bg",             5},
+    {"smpte170m",           6},
+    {"smpte240m",           7},
+    {"ycgco",               8},
+    {"bt2020nc",            9},
+    {"bt2020c",            10},
+    {"smpte2085",          11},
+    {"chroma-derived-nc",  12},
+    {"chroma-derived-c",   13},
+    {"ictcp",              14},
+    {"", 0} // termination
+};
+
 /*****************************************************************************
  * coding parameters
  *****************************************************************************/
+#define OAPV_LEVEL_TO_LEVEL_IDC(level)   (int)(((level) * 30.0) + 0.5)
+#define OAPVE_PARAM_LEVEL_IDC_AUTO       (0)
+#define OAPVE_PARAM_QP_AUTO              (255)
+
 typedef struct oapve_param oapve_param_t;
 struct oapve_param {
-    /* profile_idc */
+    /* profile_idc defined in spec. */
     int           profile_idc;
-    /* level */
+    /* level_idc defined in spec. */
     int           level_idc;
-    /* band */
+    /* band_idc defined in spec. */
     int           band_idc;
     /* width of input frame */
     int           w;
@@ -417,10 +516,13 @@ struct oapve_param {
     unsigned char q_matrix[OAPV_MAX_CC][OAPV_BLK_D]; // raster-scan order
     /* color space */
     int           csp;
-    int           tile_cols;
-    int           tile_rows;
-    int           tile_w_mb;
-    int           tile_h_mb;
+    /* NOTE: tile_w and tile_h value can be changed internally,
+             if the values are not set properly.
+             the min and max values are defeind in APV specification */
+    int           tile_w; // width of tile MUST be N * MB width
+    int           tile_h; // height of tile MUST be N * MB height
+
+    /* preset for setting trade-off between complexity and coding gain */
     int           preset;
     /* color description values */
     int           color_description_present_flag;
@@ -430,15 +532,25 @@ struct oapve_param {
     int           full_range_flag;
 };
 
+#define OAPV_CDESC_THREADS_AUTO          0
+/*****************************************************************************
+ * automatic assignment of number of threads in creation of encoder & decoder
+ *****************************************************************************/
+#define OAPV_CDESC_THREADS_AUTO          0
+
 /*****************************************************************************
  * description for encoder creation
  *****************************************************************************/
 typedef struct oapve_cdesc oapve_cdesc_t;
 struct oapve_cdesc {
-    int           max_bs_buf_size;            // max bitstream buffer size
-    int           max_num_frms;               // max number of frames to be encoded
-    int           threads;                    // number of threads
-    oapve_param_t param[OAPV_MAX_NUM_FRAMES]; // encoding parameters
+    // max bitstream buffer size
+    int           max_bs_buf_size;
+    // max number of frames to be encoded
+    int           max_num_frms;
+    // max number of threads (or OAPV_CDESC_THREADS_AUTO for auto-assignment)
+    int           threads;
+    // encoding parameters
+    oapve_param_t param[OAPV_MAX_NUM_FRAMES];
 };
 
 /*****************************************************************************
@@ -446,9 +558,12 @@ struct oapve_cdesc {
  *****************************************************************************/
 typedef struct oapve_stat oapve_stat_t;
 struct oapve_stat {
-    int            write;                         // byte size of encoded bitstream
-    oapv_au_info_t aui;                           // information of encoded frames
-    int            frm_size[OAPV_MAX_NUM_FRAMES]; // bitstream byte size of each frame
+    // byte size of encoded bitstream
+    int            write;
+    // information of encoded frames
+    oapv_au_info_t aui;
+    // bitstream byte size of each frame
+    int            frm_size[OAPV_MAX_NUM_FRAMES];
 };
 
 /*****************************************************************************
@@ -456,7 +571,8 @@ struct oapve_stat {
  *****************************************************************************/
 typedef struct oapvd_cdesc oapvd_cdesc_t;
 struct oapvd_cdesc {
-    int threads; // number of threads
+    // max number of threads (or OAPV_CDESC_THREADS_AUTO for auto-assignment)
+    int threads;
 };
 
 /*****************************************************************************
@@ -464,9 +580,12 @@ struct oapvd_cdesc {
  *****************************************************************************/
 typedef struct oapvd_stat oapvd_stat_t;
 struct oapvd_stat {
-    int            read;                          // byte size of decoded bitstream (read size)
-    oapv_au_info_t aui;                           // information of decoded frames
-    int            frm_size[OAPV_MAX_NUM_FRAMES]; // bitstream byte size of each frame
+    // byte size of decoded bitstream (read size)
+    int            read;
+    // information of decoded frames
+    oapv_au_info_t aui;
+    // bitstream byte size of each frame
+    int            frm_size[OAPV_MAX_NUM_FRAMES];
 };
 
 /*****************************************************************************
@@ -484,7 +603,7 @@ struct oapvm_payload {
 /*****************************************************************************
  * interface for metadata container
  *****************************************************************************/
-typedef void       *oapvm_t; /* instance identifier for OAPV metadata container */
+typedef void       *oapvm_t; // instance identifier for OAPV metadata container
 
 oapvm_t OAPV_EXPORT oapvm_create(int *err);
 void OAPV_EXPORT oapvm_delete(oapvm_t mid);
@@ -504,6 +623,7 @@ oapve_t OAPV_EXPORT oapve_create(oapve_cdesc_t *cdesc, int *err);
 void OAPV_EXPORT oapve_delete(oapve_t eid);
 int OAPV_EXPORT oapve_config(oapve_t eid, int cfg, void *buf, int *size);
 int OAPV_EXPORT oapve_param_default(oapve_param_t *param);
+int OAPV_EXPORT oapve_param_parse(oapve_param_t* param, const char* name,  const char* value);
 int OAPV_EXPORT oapve_encode(oapve_t eid, oapv_frms_t *ifrms, oapvm_t mid, oapv_bitb_t *bitb, oapve_stat_t *stat, oapv_frms_t *rfrms);
 
 /*****************************************************************************
@@ -521,6 +641,11 @@ int OAPV_EXPORT oapvd_decode(oapvd_t did, oapv_bitb_t *bitb, oapv_frms_t *ofrms,
  *****************************************************************************/
 int OAPV_EXPORT oapvd_info(void *au, int au_size, oapv_au_info_t *aui);
 
+/*****************************************************************************
+ * openapv version
+ *****************************************************************************/
+char * OAPV_EXPORT oapv_version();
+
 #ifdef __cplusplus
 } /* extern "C" */
 #endif
diff --git a/readme/img/apv_parser_on_imhex.png b/readme/img/apv_parser_on_imhex.png
index 3ad7a2e..46dbd0d 100644
Binary files a/readme/img/apv_parser_on_imhex.png and b/readme/img/apv_parser_on_imhex.png differ
diff --git a/src/CMakeLists.txt b/src/CMakeLists.txt
index 9bee1bc..ee8fec7 100644
--- a/src/CMakeLists.txt
+++ b/src/CMakeLists.txt
@@ -105,7 +105,11 @@ elseif( UNIX OR MINGW )
 
   set_target_properties(${LIB_NAME_BASE}_dynamic PROPERTIES FOLDER lib
                                                             LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
-  target_compile_definitions( ${LIB_NAME_BASE} PUBLIC ANY LINUX )
+  if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
+    target_compile_definitions( ${LIB_NAME_BASE} PUBLIC ANY MACOS )
+  else()
+    target_compile_definitions( ${LIB_NAME_BASE} PUBLIC ANY LINUX )
+  endif()
   target_link_libraries(${LIB_NAME_BASE} m)
 endif()
 
diff --git a/src/neon/oapv_sad_neon.c b/src/neon/oapv_sad_neon.c
index f494ae7..0c37318 100644
--- a/src/neon/oapv_sad_neon.c
+++ b/src/neon/oapv_sad_neon.c
@@ -182,7 +182,6 @@ static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, in
     s64 ssd = 0;
     s16* s1 = (s16*) src1;
     s16* s2 = (s16*) src2;
-    s16 i;
     int16x8_t s1_vector, s2_vector;
     int32x4_t diff1, diff2;
     int32x2_t diff1_low, diff2_low;
@@ -480,7 +479,6 @@ int oapv_dc_removed_had8x8_neon(pel* org, int s_org)
     int16x8_t pred4_8x16b, pred5_8x16b, pred6_8x16b, pred7_8x16b;
     int16x8_t out0_8x16b, out1_8x16b, out2_8x16b, out3_8x16b;
     int16x8_t out4_8x16b, out5_8x16b, out6_8x16b, out7_8x16b;
-    int16x8x2_t out0_8x16bx2, out1_8x16bx2, out2_8x16bx2, out3_8x16bx2;
 
     src0_8x16b = (vld1q_s16(&org[0]));
     org = org + s_org;
diff --git a/src/oapv.c b/src/oapv.c
index a797c6d..ae70de4 100644
--- a/src/oapv.c
+++ b/src/oapv.c
@@ -296,8 +296,8 @@ static void enc_minus_mid_val(s16 *coef, int w_blk, int h_blk, int bit_depth)
 static int enc_set_tile_info(oapve_tile_t *ti, int w_pel, int h_pel, int tile_w,
                              int tile_h, int *num_tile_cols, int *num_tile_rows, int *num_tiles)
 {
-    (*num_tile_cols) = (w_pel + (tile_w - 1)) / tile_w;
-    (*num_tile_rows) = (h_pel + (tile_h - 1)) / tile_h;
+    (*num_tile_cols) = oapv_div_round_up(w_pel, tile_w);
+    (*num_tile_rows) = oapv_div_round_up(h_pel, tile_h);
     (*num_tiles) = (*num_tile_cols) * (*num_tile_rows);
 
     for(int i = 0; i < (*num_tiles); i++) {
@@ -642,7 +642,7 @@ static int enc_read_param(oapve_ctx_t *ctx, oapve_param_t *param)
 {
     /* check input parameters */
     oapv_assert_rv(param->w > 0 && param->h > 0, OAPV_ERR_INVALID_ARGUMENT);
-    oapv_assert_rv(param->qp >= MIN_QUANT && param->qp <= MAX_QUANT(10), OAPV_ERR_INVALID_ARGUMENT);
+    oapv_assert_rv((param->qp >= MIN_QUANT && param->qp <= MAX_QUANT(10)) || param->qp == OAPVE_PARAM_QP_AUTO, OAPV_ERR_INVALID_ARGUMENT);
 
     ctx->qp_offset[Y_C] = 0;
     ctx->qp_offset[U_C] = param->qp_offset_c1;
@@ -671,12 +671,10 @@ static int enc_read_param(oapve_ctx_t *ctx, oapve_param_t *param)
     ctx->log2_block = OAPV_LOG2_BLK;
 
     /* set various value */
-    ctx->w = ((param->w + (OAPV_MB_W - 1)) >> OAPV_LOG2_MB_W) << OAPV_LOG2_MB_W;
-    ctx->h = ((param->h + (OAPV_MB_H - 1)) >> OAPV_LOG2_MB_H) << OAPV_LOG2_MB_H;
+    ctx->w = oapv_div_round_up(param->w, OAPV_MB_W) * OAPV_MB_W;
+    ctx->h = oapv_div_round_up(param->h, OAPV_MB_H) * OAPV_MB_H;
 
-    int tile_w = param->tile_w_mb * OAPV_MB_W;
-    int tile_h = param->tile_h_mb * OAPV_MB_H;
-    enc_set_tile_info(ctx->tile, ctx->w, ctx->h, tile_w, tile_h, &ctx->num_tile_cols, &ctx->num_tile_rows, &ctx->num_tiles);
+    enc_set_tile_info(ctx->tile, ctx->w, ctx->h, ctx->param->tile_w, ctx->param->tile_h, &ctx->num_tile_cols, &ctx->num_tile_rows, &ctx->num_tiles);
 
     return OAPV_OK;
 }
@@ -684,11 +682,11 @@ static int enc_read_param(oapve_ctx_t *ctx, oapve_param_t *param)
 static void enc_flush(oapve_ctx_t *ctx)
 {
     // Release thread pool controller and created threads
-    if(ctx->cdesc.threads >= 1) {
+    if(ctx->threads >= 1) {
         if(ctx->tpool) {
             // thread controller instance is present
             // terminate the created thread
-            for(int i = 0; i < ctx->cdesc.threads; i++) {
+            for(int i = 0; i < ctx->threads; i++) {
                 if(ctx->thread_id[i]) {
                     // valid thread instance
                     ctx->tpool->release(&ctx->thread_id[i]);
@@ -701,8 +699,10 @@ static void enc_flush(oapve_ctx_t *ctx)
         }
     }
 
-    oapv_tpool_sync_obj_delete(&ctx->sync_obj);
-    for(int i = 0; i < ctx->cdesc.threads; i++) {
+    if (ctx->sync_obj != NULL) {
+        oapv_tpool_sync_obj_delete(&ctx->sync_obj);
+    }
+    for(int i = 0; i < ctx->threads; i++) {
         enc_core_free(ctx->core[i]);
         ctx->core[i] = NULL;
     }
@@ -716,7 +716,10 @@ static int enc_ready(oapve_ctx_t *ctx)
     int           ret = OAPV_OK;
     oapv_assert(ctx->core[0] == NULL);
 
-    for(int i = 0; i < ctx->cdesc.threads; i++) {
+    ret = oapve_param_update(ctx);
+    oapv_assert_g(ret == OAPV_OK, ERR);
+
+    for(int i = 0; i < ctx->threads; i++) {
         core = enc_core_alloc();
         oapv_assert_gv(core != NULL, ret, OAPV_ERR_OUT_OF_MEMORY, ERR);
         ctx->core[i] = core;
@@ -731,10 +734,10 @@ static int enc_ready(oapve_ctx_t *ctx)
     ctx->sync_obj = oapv_tpool_sync_obj_create();
     oapv_assert_gv(ctx->sync_obj != NULL, ret, OAPV_ERR_UNKNOWN, ERR);
 
-    if(ctx->cdesc.threads >= 1) {
+    if(ctx->threads >= 1) {
         ctx->tpool = oapv_malloc(sizeof(oapv_tpool_t));
-        oapv_tpool_init(ctx->tpool, ctx->cdesc.threads);
-        for(int i = 0; i < ctx->cdesc.threads; i++) {
+        oapv_tpool_init(ctx->tpool, ctx->threads);
+        for(int i = 0; i < ctx->threads; i++) {
             ctx->thread_id[i] = ctx->tpool->create(ctx->tpool, i);
             oapv_assert_gv(ctx->thread_id[i] != NULL, ret, OAPV_ERR_UNKNOWN, ERR);
         }
@@ -751,7 +754,6 @@ static int enc_ready(oapve_ctx_t *ctx)
 
     return OAPV_OK;
 ERR:
-
     enc_flush(ctx);
 
     return ret;
@@ -1092,7 +1094,7 @@ static int enc_frm_prepare(oapve_ctx_t *ctx, oapv_imgb_t *imgb_i, oapv_imgb_t *i
         ctx->tile[i].bs_buf_max = buf_size;
     }
 
-    for(int i = 0; i < ctx->cdesc.threads; i++) {
+    for(int i = 0; i < ctx->threads; i++) {
         ctx->core[i]->ctx = ctx;
         ctx->core[i]->thread_idx = i;
     }
@@ -1137,7 +1139,12 @@ static int enc_frame(oapve_ctx_t *ctx)
         }
 
         ctx->rc_param.lambda = oapve_rc_estimate_pic_lambda(ctx, cost_sum);
-        ctx->rc_param.qp = oapve_rc_estimate_pic_qp(ctx->rc_param.lambda);
+        if (ctx->param->qp == OAPVE_PARAM_QP_AUTO || ctx->rc_param.is_updated != 0) {
+            ctx->rc_param.qp = oapve_rc_estimate_pic_qp(ctx->rc_param.lambda);
+        }
+        else {
+            ctx->rc_param.qp = ctx->param->qp;
+        }
 
         for(int c = 0; c < ctx->num_comp; c++) {
             ctx->qp[c] = oapv_clip3(MIN_QUANT, MAX_QUANT(10), ctx->rc_param.qp + ctx->qp_offset[c]);
@@ -1146,7 +1153,7 @@ static int enc_frame(oapve_ctx_t *ctx)
 
     oapv_tpool_t *tpool = ctx->tpool;
     int           res, tidx = 0, thread_num1 = 0;
-    int           parallel_task = (ctx->cdesc.threads > ctx->num_tiles) ? ctx->num_tiles : ctx->cdesc.threads;
+    int           parallel_task = (ctx->threads > ctx->num_tiles) ? ctx->num_tiles : ctx->threads;
 
     /* encode tiles ************************************/
     for(tidx = 0; tidx < (parallel_task - 1); tidx++) {
@@ -1299,7 +1306,7 @@ int oapve_encode(oapve_t eid, oapv_frms_t *ifrms, oapvm_t mid, oapv_bitb_t *bitb
     u8       *bs_pos_au_beg = oapv_bsw_sink(bs); // address syntax of au size
     u8       *bs_pos_pbu_beg;
     oapv_bs_t bs_pbu_beg;
-    oapv_bsw_write(bs, 0, 32);
+    oapv_bsw_write(bs, 0, 32); // raw bitstream byte size (skip)
 
     oapv_bsw_write(bs, 0x61507631, 32); // signature ('aPv1')
 
@@ -1309,7 +1316,7 @@ int oapve_encode(oapve_t eid, oapv_frms_t *ifrms, oapvm_t mid, oapv_bitb_t *bitb
         /* set default value for encoding parameter */
         ctx->param = &ctx->cdesc.param[i];
         ret = enc_read_param(ctx, ctx->param);
-        oapv_assert_rv(ret == OAPV_OK, OAPV_ERR);
+        oapv_assert_rv(ret == OAPV_OK, ret);
 
         oapv_assert_rv(ctx->param->profile_idc == OAPV_PROFILE_422_10, OAPV_ERR_UNSUPPORTED);
 
@@ -1375,7 +1382,7 @@ int oapve_encode(oapve_t eid, oapv_frms_t *ifrms, oapvm_t mid, oapv_bitb_t *bitb
         }
     }
 
-    u32 au_size = (u32)((u8 *)oapv_bsw_sink(bs) - bs_pos_au_beg) - 4;
+    u32 au_size = (u32)((u8 *)oapv_bsw_sink(bs) - bs_pos_au_beg) - 4 /* au_size */;
     oapv_bsw_write_direct(bs_pos_au_beg, au_size, 32); /* u(32) */
 
     oapv_bsw_deinit(&ctx->bs); /* de-init BSW */
@@ -1456,39 +1463,6 @@ int oapve_config(oapve_t eid, int cfg, void *buf, int *size)
     return OAPV_OK;
 }
 
-int oapve_param_default(oapve_param_t *param)
-{
-    oapv_mset(param, 0, sizeof(oapve_param_t));
-    param->preset = OAPV_PRESET_DEFAULT;
-
-    param->qp_offset_c1 = 0;
-    param->qp_offset_c2 = 0;
-    param->qp_offset_c3 = 0;
-
-    param->tile_w_mb = 16;
-    param->tile_h_mb = 16;
-
-    param->profile_idc = OAPV_PROFILE_422_10;
-    param->level_idc = (int)((4.1 * 30.0) + 0.5);
-    param->band_idc = 2;
-
-    param->use_q_matrix = 0;
-
-    param->color_description_present_flag = 0;
-    param->color_primaries = 2; // unspecified color primaries
-    param->transfer_characteristics = 2; // unspecified transfer characteristics
-    param->matrix_coefficients = 2; // unspecified matrix coefficients
-    param->full_range_flag = 0; // limited range
-
-    for(int c = 0; c < OAPV_MAX_CC; c++) {
-        for(int i = 0; i < OAPV_BLK_D; i++) {
-            param->q_matrix[c][i] = 16;
-        }
-    }
-
-    return OAPV_OK;
-}
-
 ///////////////////////////////////////////////////////////////////////////////
 // enc of encoder code
 #endif // ENABLE_ENCODER
@@ -1672,6 +1646,9 @@ static int dec_tile_comp(oapvd_tile_t *tile, oapvd_ctx_t *ctx, oapvd_core_t *cor
 
     /* byte align */
     oapv_bsr_align8(bs);
+    /* check actual read size of 'tile()' is equal or smaller than 'tile_data_size' in tile header */
+    oapv_assert_rv(BSR_GET_READ_BYTE(bs) <= tile->th.tile_data_size[c], OAPV_ERR_MALFORMED_BITSTREAM);
+
     return OAPV_OK;
 }
 
@@ -1679,11 +1656,12 @@ static int dec_tile(oapvd_core_t *core, oapvd_tile_t *tile)
 {
     int          ret, midx, x, y, c;
     oapvd_ctx_t *ctx = core->ctx;
-    oapv_bs_t    bs;
+    oapv_bs_t    bs; // bs for 'tile()' syntax
 
     oapv_bsr_init(&bs, tile->bs_beg + OAPV_TILE_SIZE_LEN, tile->data_size, NULL);
     ret = oapvd_vlc_tile_header(&bs, ctx, &tile->th);
     oapv_assert_rv(OAPV_SUCCEEDED(ret), ret);
+
     for(c = 0; c < ctx->num_comp; c++) {
         core->qp[c] = tile->th.tile_qp[c];
         int dq_scale = oapv_tbl_dq_scale[core->qp[c] % 6];
@@ -1704,6 +1682,9 @@ static int dec_tile(oapvd_core_t *core, oapvd_tile_t *tile)
     for(c = 0; c < ctx->num_comp; c++) {
         int  tc, s_dst;
         s16 *dst;
+        oapv_bs_t bsc; // bs for 'tile_data()' syntax
+
+        oapv_bsr_init(&bsc, BSR_GET_CUR(&bs), tile->th.tile_data_size[c], NULL);
 
         if(OAPV_CS_GET_FORMAT(ctx->imgb->cs) == OAPV_CF_PLANAR2) {
             tc = c > 0 ? 1 : 0;
@@ -1716,8 +1697,11 @@ static int dec_tile(oapvd_core_t *core, oapvd_tile_t *tile)
             s_dst = ctx->imgb->s[c];
         }
 
-        ret = dec_tile_comp(tile, ctx, core, &bs, c, s_dst, dst);
+        ret = dec_tile_comp(tile, ctx, core, &bsc, c, s_dst, dst);
         oapv_assert_rv(OAPV_SUCCEEDED(ret), ret);
+
+        // move bs buffer to next 'tile_data()' component
+        BSR_MOVE_BYTE_ALIGN(&bs, tile->th.tile_data_size[c]);
     }
 
     oapvd_vlc_tile_dummy_data(&bs);
@@ -1800,11 +1784,11 @@ ERR:
 
 static void dec_flush(oapvd_ctx_t *ctx)
 {
-    if(ctx->cdesc.threads >= 2) {
+    if(ctx->threads >= 2) {
         if(ctx->tpool) {
             // thread controller instance is present
             // terminate the created thread
-            for(int i = 0; i < ctx->cdesc.threads - 1; i++) {
+            for(int i = 0; i < ctx->threads - 1; i++) {
                 if(ctx->thread_id[i]) {
                     // valid thread instance
                     ctx->tpool->release(&ctx->thread_id[i]);
@@ -1819,7 +1803,7 @@ static void dec_flush(oapvd_ctx_t *ctx)
 
     oapv_tpool_sync_obj_delete(&(ctx->sync_obj));
 
-    for(int i = 0; i < ctx->cdesc.threads; i++) {
+    for(int i = 0; i < ctx->threads; i++) {
         dec_core_free(ctx->core[i]);
     }
 }
@@ -1828,9 +1812,18 @@ static int dec_ready(oapvd_ctx_t *ctx)
 {
     int i, ret = OAPV_OK;
 
+    if (ctx->cdesc.threads == OAPV_CDESC_THREADS_AUTO) {
+        int num_cores = oapv_get_num_cpu_cores();
+        ctx->threads = oapv_min(OAPV_MAX_THREADS, num_cores);
+    }
+    else {
+        ctx->threads = ctx->cdesc.threads;
+    }
+    oapv_assert_gv(ctx->threads > 0 && ctx->threads <= OAPV_MAX_THREADS, ret, OAPV_ERR_INVALID_ARGUMENT, ERR);
+
     if(ctx->core[0] == NULL) {
         // create cores
-        for(i = 0; i < ctx->cdesc.threads; i++) {
+        for(i = 0; i < ctx->threads; i++) {
             ctx->core[i] = dec_core_alloc();
             oapv_assert_gv(ctx->core[i], ret, OAPV_ERR_OUT_OF_MEMORY, ERR);
             ctx->core[i]->ctx = ctx;
@@ -1838,7 +1831,7 @@ static int dec_ready(oapvd_ctx_t *ctx)
     }
 
     // initialize the threads to NULL
-    for(i = 0; i < OAPV_MAX_THREADS; i++) {
+    for(i = 0; i < ctx->threads; i++) {
         ctx->thread_id[i] = 0;
     }
 
@@ -1846,10 +1839,10 @@ static int dec_ready(oapvd_ctx_t *ctx)
     ctx->sync_obj = oapv_tpool_sync_obj_create();
     oapv_assert_gv(ctx->sync_obj != NULL, ret, OAPV_ERR_UNKNOWN, ERR);
 
-    if(ctx->cdesc.threads >= 2) {
+    if(ctx->threads >= 2) {
         ctx->tpool = oapv_malloc(sizeof(oapv_tpool_t));
-        oapv_tpool_init(ctx->tpool, ctx->cdesc.threads - 1);
-        for(i = 0; i < ctx->cdesc.threads - 1; i++) {
+        oapv_tpool_init(ctx->tpool, ctx->threads - 1);
+        for(i = 0; i < ctx->threads - 1; i++) {
             ctx->thread_id[i] = ctx->tpool->create(ctx->tpool, i);
             oapv_assert_gv(ctx->thread_id[i] != NULL, ret, OAPV_ERR_UNKNOWN, ERR);
         }
@@ -1899,7 +1892,7 @@ oapvd_t oapvd_create(oapvd_cdesc_t *cdesc, int *err)
     ctx = NULL;
 
     /* check if any decoder argument is correctly set */
-    oapv_assert_gv(cdesc->threads > 0 && cdesc->threads <= OAPV_MAX_THREADS, ret, OAPV_ERR_INVALID_ARGUMENT, ERR);
+    oapv_assert_gv((cdesc->threads > 0 && cdesc->threads <= OAPV_MAX_THREADS) || cdesc->threads == OAPV_CDESC_THREADS_AUTO , ret, OAPV_ERR_INVALID_ARGUMENT, ERR);
 
     /* memory allocation for ctx and core structure */
     ctx = (oapvd_ctx_t *)dec_ctx_alloc();
@@ -1945,7 +1938,6 @@ void oapvd_delete(oapvd_t did)
 int oapvd_decode(oapvd_t did, oapv_bitb_t *bitb, oapv_frms_t *ofrms, oapvm_t mid, oapvd_stat_t *stat)
 {
     oapvd_ctx_t *ctx;
-    oapv_bs_t   *bs;
     oapv_pbuh_t  pbuh;
     int          ret = OAPV_OK;
     u32          pbu_size;
@@ -1962,7 +1954,9 @@ int oapvd_decode(oapvd_t did, oapv_bitb_t *bitb, oapv_frms_t *ofrms, oapvm_t mid
     cur_read_size += 4;
     stat->read += 4;
 
+    // decode PBUs
     do {
+        oapv_bs_t   *bs;
         u32 remain = bitb->ssize - cur_read_size;
         oapv_assert_gv((remain >= 8), ret, OAPV_ERR_MALFORMED_BITSTREAM, ERR);
         oapv_bsr_init(&ctx->bs, (u8 *)bitb->addr + cur_read_size, remain, NULL);
@@ -1995,7 +1989,7 @@ int oapvd_decode(oapvd_t did, oapv_bitb_t *bitb, oapv_frms_t *ofrms, oapvm_t mid
             int           parallel_task = 1;
             int           tidx = 0;
 
-            parallel_task = (ctx->cdesc.threads > ctx->num_tiles) ? ctx->num_tiles : ctx->cdesc.threads;
+            parallel_task = (ctx->threads > ctx->num_tiles) ? ctx->num_tiles : ctx->threads;
 
             /* decode tiles ************************************/
             for(tidx = 0; tidx < (parallel_task - 1); tidx++) {
@@ -2025,7 +2019,7 @@ int oapvd_decode(oapvd_t did, oapv_bitb_t *bitb, oapv_frms_t *ofrms, oapvm_t mid
 
             ofrms->frm[frame_cnt].pbu_type = pbuh.pbu_type;
             ofrms->frm[frame_cnt].group_id = pbuh.group_id;
-            stat->frm_size[frame_cnt] = pbu_size + 4 /* PUB size length*/;
+            stat->frm_size[frame_cnt] = pbu_size + 4 /* byte size of 'pbu_size' syntax */;
             frame_cnt++;
         }
         else if(pbuh.pbu_type == OAPV_PBU_TYPE_METADATA) {
@@ -2038,7 +2032,7 @@ int oapvd_decode(oapvd_t did, oapv_bitb_t *bitb, oapv_frms_t *ofrms, oapvm_t mid
             ret = oapvd_vlc_filler(bs, (pbu_size - 4));
             oapv_assert_g(OAPV_SUCCEEDED(ret), ERR);
         }
-        cur_read_size += pbu_size + 4;
+        cur_read_size += pbu_size + 4 /* byte size of 'pbu_size' syntax */;
     } while(cur_read_size < bitb->ssize);
     stat->aui.num_frms = frame_cnt;
     oapv_assert_gv(ofrms->num_frms == frame_cnt, ret, OAPV_ERR_MALFORMED_BITSTREAM, ERR);
@@ -2071,6 +2065,8 @@ int oapvd_info(void *au, int au_size, oapv_au_info_t *aui)
 {
     int ret, frm_count = 0;
     u32 cur_read_size = 0;
+    int pbu_count = 0;
+    oapv_bs_t bs;
 
     DUMP_SET(0);
 
@@ -2080,12 +2076,11 @@ int oapvd_info(void *au, int au_size, oapv_au_info_t *aui)
     oapv_assert_rv(signature == 0x61507631, OAPV_ERR_MALFORMED_BITSTREAM);
     cur_read_size += 4;
 
-    /* 'au' address contains series of PBU */
+    // parse PBUs
     do {
-        oapv_bs_t bs;
         u32 pbu_size = 0;
         u32 remain = au_size - cur_read_size;
-        oapv_assert_rv((remain >= 8), OAPV_ERR_MALFORMED_BITSTREAM);
+        oapv_assert_rv(remain >= 8, OAPV_ERR_MALFORMED_BITSTREAM);
         oapv_bsr_init(&bs, (u8 *)au + cur_read_size, remain, NULL);
 
         ret = oapvd_vlc_pbu_size(&bs, &pbu_size); // read pbu_size (4 byte)
@@ -2127,6 +2122,7 @@ int oapvd_info(void *au, int au_size, oapv_au_info_t *aui)
         }
         aui->num_frms = frm_count;
         cur_read_size += pbu_size + 4; /* 4byte is for pbu_size syntax itself */
+        pbu_count++;
     } while(cur_read_size < au_size);
     DUMP_SET(1);
     return OAPV_OK;
@@ -2135,4 +2131,7 @@ int oapvd_info(void *au, int au_size, oapv_au_info_t *aui)
 ///////////////////////////////////////////////////////////////////////////////
 // end of decoder code
 #endif // ENABLE_DECODER
-///////////////////////////////////////////////////////////////////////////////
\ No newline at end of file
+///////////////////////////////////////////////////////////////////////////////
+
+static char *oapv_ver = "0.1.13.1";
+char * oapv_version() { return oapv_ver; }
diff --git a/src/oapv_bs.c b/src/oapv_bs.c
index 968a798..c20b195 100644
--- a/src/oapv_bs.c
+++ b/src/oapv_bs.c
@@ -80,10 +80,10 @@ void *oapv_bsw_sink(oapv_bs_t *bs)
     return (void *)bs->cur;
 }
 
-int oapv_bsw_write_direct(void *bits, u32 val, int len)
+int oapv_bsw_write_direct(void *addr, u32 val, int len)
 {
     int            i;
-    unsigned char *p = (unsigned char *)bits;
+    unsigned char *p = (unsigned char *)addr;
 
     oapv_assert_rv((len & 0x7) == 0, -1); // len should be byte-aligned
 
diff --git a/src/oapv_bs.h b/src/oapv_bs.h
index 81ee317..a6845fa 100644
--- a/src/oapv_bs.h
+++ b/src/oapv_bs.h
@@ -69,7 +69,7 @@ static inline int bsw_get_write_byte(oapv_bs_t *bs)
 void oapv_bsw_init(oapv_bs_t *bs, u8 *buf, int size, oapv_bs_fn_flush_t fn_flush);
 void oapv_bsw_deinit(oapv_bs_t *bs);
 void *oapv_bsw_sink(oapv_bs_t *bs);
-int oapv_bsw_write_direct(void *bits, u32 val, int len);
+int oapv_bsw_write_direct(void *addr, u32 val, int len);
 int oapv_bsw_write1(oapv_bs_t *bs, int val);
 int oapv_bsw_write(oapv_bs_t *bs, u32 val, int len);
 ///////////////////////////////////////////////////////////////////////////////
diff --git a/src/oapv_def.h b/src/oapv_def.h
index acb4f6f..b8479e0 100644
--- a/src/oapv_def.h
+++ b/src/oapv_def.h
@@ -199,6 +199,7 @@ typedef struct oapve_rc_param {
     int    qp;
     double lambda;
     double cost;
+    unsigned char is_updated;
 } oapve_rc_param_t;
 
 typedef struct oapve_rc_tile {
@@ -271,6 +272,7 @@ struct oapve_ctx {
     oapve_param_t            *param;
     oapv_fh_t                 fh;
     oapve_tile_t              tile[OAPV_MAX_TILES];
+    int                       num_tiles_frms[OAPV_MAX_NUM_FRAMES];
     int                       num_tiles;
     int                       num_tile_cols;
     int                       num_tile_rows;
@@ -308,6 +310,7 @@ struct oapve_ctx {
     int                       use_frm_hash;
     oapve_rc_param_t          rc_param;
 
+    int                       threads; // num of thread for encoding
     /* platform specific data, if needed */
     void                     *pf;
 };
@@ -345,7 +348,7 @@ typedef struct oapvd_ctx  oapvd_ctx_t;
 
 struct oapvd_core {
     ALIGNED_16(s16 coef[OAPV_MB_D]);
-    oapvd_ctx_t *ctx;
+    s16          q_mat[N_C][OAPV_BLK_D];
 
     int          prev_dc_ctx[N_C];
     int          prev_1st_ac_ctx[N_C];
@@ -354,10 +357,9 @@ struct oapvd_core {
                           /* and coded as abs_dc_coeff_diff and sign_dc_coeff_diff */
     int          qp[N_C];
     int          dq_shift[N_C];
-    s16          q_mat[N_C][OAPV_BLK_D];
-
     int          tile_idx;
 
+    oapvd_ctx_t *ctx;
     /* platform specific data, if needed */
     void        *pf;
 };
@@ -383,6 +385,7 @@ struct oapvd_ctx {
     int                     num_tile_rows;
     int                     w;
     int                     h;
+    int                     threads;
     oapv_tpool_t           *tpool;
     oapv_thread_t           thread_id[OAPV_MAX_THREADS];
     oapv_sync_obj_t         sync_obj;
@@ -410,6 +413,7 @@ struct oapvd_ctx {
 #include "oapv_tbl.h"
 #include "oapv_rc.h"
 #include "oapv_sad.h"
+#include "oapv_param.h"
 
 #if X86_SSE
 #include "sse/oapv_sad_sse.h"
diff --git a/src/oapv_param.c b/src/oapv_param.c
new file mode 100644
index 0000000..cc62d1a
--- /dev/null
+++ b/src/oapv_param.c
@@ -0,0 +1,500 @@
+/*
+ * Copyright (c) 2022 Samsung Electronics Co., Ltd.
+ * All Rights Reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions are met:
+ *
+ * - Redistributions of source code must retain the above copyright notice,
+ *   this list of conditions and the following disclaimer.
+ *
+ * - Redistributions in binary form must reproduce the above copyright notice,
+ *   this list of conditions and the following disclaimer in the documentation
+ *   and/or other materials provided with the distribution.
+ *
+ * - Neither the name of the copyright owner, nor the names of its contributors
+ *   may be used to endorse or promote products derived from this software
+ *   without specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ * ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
+ * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ * CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ * POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include "oapv_def.h"
+#include <string.h>
+
+int oapve_param_default(oapve_param_t *param)
+{
+    oapv_mset(param, 0, sizeof(oapve_param_t));
+    param->preset = OAPV_PRESET_DEFAULT;
+
+    param->qp = OAPVE_PARAM_QP_AUTO; // default
+    param->qp_offset_c1 = 0;
+    param->qp_offset_c2 = 0;
+    param->qp_offset_c3 = 0;
+
+    param->tile_w = 16 * OAPV_MB_W; // default: 256
+    param->tile_h = 16 * OAPV_MB_H; // default: 256
+
+    param->profile_idc = OAPV_PROFILE_422_10;
+    param->level_idc = OAPVE_PARAM_LEVEL_IDC_AUTO;
+    param->band_idc = 2;
+
+    param->use_q_matrix = 0;
+
+    for(int c = 0; c < OAPV_MAX_CC; c++) {
+        for(int i = 0; i < OAPV_BLK_D; i++) {
+            param->q_matrix[c][i] = 16;
+        }
+    }
+
+    param->color_description_present_flag = 0;
+    param->color_primaries = 2; // unspecified color primaries
+    param->transfer_characteristics = 2; // unspecified transfer characteristics
+    param->matrix_coefficients = 2; // unspecified matrix coefficients
+    param->full_range_flag = 0; // limited range
+
+    return OAPV_OK;
+}
+
+///////////////////////////////////////////////////////////////////////////////
+// parameter parsing helper function for encoder
+static int is_digit(const char* str)
+{
+    while(*str) {
+        if(*str < '0' || *str > '9')
+            return 0;
+        ++str;
+    }
+    return 1;
+}
+
+static int get_ival_from_skey(const oapv_dict_str_int_t * dict, const char * skey, int * ival)
+{
+    while(strlen(dict->key) > 0) {
+        if(strcmp(dict->key, skey) == 0){
+            *ival = dict->val;
+            return 0;
+        }
+        dict++;
+    }
+    return -1;
+}
+
+static int kbps_str_to_int(const char *str)
+{
+    int kbps;
+    char *s = (char *)str;
+    if(strchr(s, 'K') || strchr(s, 'k')) {
+        char *tmp = strtok(s, "Kk ");
+        kbps = (int)(atof(tmp));
+    }
+    else if(strchr(s, 'M') || strchr(s, 'm')) {
+        char *tmp = strtok(s, "Mm ");
+        kbps = (int)(atof(tmp) * 1000);
+    }
+    else if(strchr(s, 'G') || strchr(s, 'g')) {
+        char *tmp = strtok(s, "Gg ");
+        kbps = (int)(atof(tmp) * 1000000);
+    }
+    else {
+        kbps = atoi(s);
+    }
+    return kbps;
+}
+
+static int get_q_matrix(const char *str, u8 q_matrix[OAPV_BLK_D])
+{
+    int   t0, qcnt = 0;
+    char *left;
+    char *qstr = (char *)str;
+
+    while(strlen(qstr) > 0 && qcnt < OAPV_BLK_D) {
+        t0 = strtol(qstr, &left, 10);
+        oapv_assert_rv(t0 >= 1 && t0 <= 255, -1);
+
+        q_matrix[qcnt] = (u8)t0;
+        qstr = left;
+        qcnt++;
+    }
+    oapv_assert_rv(qcnt == OAPV_BLK_D, -1);
+    return 0;
+}
+
+#define NAME_CMP(VAL)      else if(strcmp(name, VAL)== 0)
+#define GET_INTEGER_OR_ERR(STR, F) { \
+    char * left; (F) = strtol(STR, &left, 10); \
+    if(strlen(left)>0) return OAPV_ERR_INVALID_ARGUMENT; \
+}
+#define GET_INTEGER_MIN_OR_ERR(STR, F, MIN) { \
+        GET_INTEGER_OR_ERR(STR, F); \
+        if((F) < (MIN)) return OAPV_ERR_INVALID_ARGUMENT; \
+}
+#define GET_INTEGER_MIN_MAX_OR_ERR(STR, F, MIN, MAX) { \
+    GET_INTEGER_OR_ERR(STR, F); \
+    if((F) < (MIN) || (F) > (MAX)) return OAPV_ERR_INVALID_ARGUMENT; \
+}
+#define GET_FLOAT_OR_ERR(STR, F) { \
+    char * left; (F) = strtof(STR, &left); \
+    if(strlen(left)>0) return OAPV_ERR_INVALID_ARGUMENT; \
+}
+
+int oapve_param_parse(oapve_param_t *param, const char *name,  const char *value)
+{
+    u8    q_matrix[OAPV_BLK_D];
+    char  str_buf[64];
+    int   ti0;
+    float tf0;
+
+    /* normalization of name and value ***************************************/
+    // pass '-- prefix' if exists
+    if(name[0] == '-' && name[1] == '-') { name += 2; }
+
+    // replace '_' with '-'
+    if(strlen(name) + 1 < sizeof(str_buf) && strchr(name, '_')) {
+        char *c;
+        strcpy(str_buf, name);
+        while((c = strchr(str_buf, '_')) != 0) { *c = '-'; } // replace
+        name = str_buf; // change address
+    }
+
+    /* parsing ***************************************************************/
+    if(0){;}
+    NAME_CMP("profile") {
+        if(get_ival_from_skey(oapv_param_opts_profile, value, &ti0)) {
+            return OAPV_ERR_INVALID_ARGUMENT;
+        }
+        param->profile_idc = ti0;
+    }
+    NAME_CMP("level") {
+        if(!strcmp(value, "auto")) {
+            param->level_idc = OAPVE_PARAM_LEVEL_IDC_AUTO;
+        }
+        else {
+            GET_FLOAT_OR_ERR(value, tf0);
+            // validation check
+            // level == [1, 1.1, 2, 2.1, 3, 3.1, 4, 4.1, 5, 5.1, 6, 6.1, 7, 7.1]
+            if(tf0 == 1.0f || tf0 == 1.1f || tf0 == 2.0f || tf0 == 2.1f || \
+                tf0 == 3.0f || tf0 == 3.1f || tf0 == 4.0f || tf0 == 4.1f ||\
+                tf0 == 5.0f || tf0 == 5.1f || tf0 == 6.0f || tf0 == 6.1f ||\
+                tf0 == 7.0f || tf0 == 7.1f) {
+                param->level_idc = OAPV_LEVEL_TO_LEVEL_IDC(tf0);
+            }
+            else {
+                return OAPV_ERR_INVALID_ARGUMENT;
+            }
+        }
+    }
+    NAME_CMP("band") {
+        GET_INTEGER_MIN_MAX_OR_ERR(value, ti0, 0, 3);
+        param->band_idc = ti0;
+    }
+    NAME_CMP("preset") {
+        if(get_ival_from_skey(oapv_param_opts_preset, value, &ti0)) {
+            return OAPV_ERR_INVALID_ARGUMENT;
+        }
+        param->preset = ti0;
+    }
+    NAME_CMP("width") {
+        GET_INTEGER_OR_ERR(value, ti0);
+        oapv_assert_rv(ti0 > 0, OAPV_ERR_INVALID_ARGUMENT);
+        param->w = ti0;
+    }
+    NAME_CMP("height") {
+        GET_INTEGER_OR_ERR(value, ti0);
+        oapv_assert_rv(ti0 > 0, OAPV_ERR_INVALID_ARGUMENT);
+        param->h = ti0;
+    }
+    NAME_CMP("fps") {
+        if(strpbrk(value, "/") != NULL) {
+            sscanf(value, "%d/%d", &param->fps_num, &param->fps_den);
+        }
+        else if(strpbrk(value, ".") != NULL) {
+            GET_FLOAT_OR_ERR(value, tf0);
+            param->fps_num = tf0 * 10000;
+            param->fps_den = 10000;
+        }
+        else {
+            GET_INTEGER_OR_ERR(value, ti0);
+            param->fps_num = ti0;
+            param->fps_den = 1;
+        }
+    }
+    NAME_CMP("qp") {
+        if(!strcmp(value, "auto")) {
+            param->qp = OAPVE_PARAM_QP_AUTO;
+            param->rc_type = OAPV_RC_ABR;
+        }
+        else {
+            //  QP value: 0 ~ (63 + (bitdepth - 10)*6)
+            //     - 10bit input: 0 ~ 63"
+            //     - 12bit input: 0 ~ 75"
+            // max value cannot be decided without bitdepth value
+            GET_INTEGER_MIN_MAX_OR_ERR(value, ti0, MIN_QUANT, MAX_QUANT(12));
+            param->qp = ti0;
+            param->rc_type = OAPV_RC_CQP;
+        }
+    }
+    NAME_CMP("qp-offset-c1") {
+        GET_INTEGER_OR_ERR(value, ti0);
+        param->qp_offset_c1 = ti0;
+    }
+    NAME_CMP("qp-offset-c2") {
+        GET_INTEGER_OR_ERR(value, ti0);
+        param->qp_offset_c2 = ti0;
+    }
+    NAME_CMP("qp-offset-c3") {
+        GET_INTEGER_OR_ERR(value, ti0);
+        param->qp_offset_c3 = ti0;
+    }
+    NAME_CMP("bitrate") {
+        if(strlen(value) > 0) {
+            strcpy(str_buf, value); // to maintain original value
+            param->bitrate = kbps_str_to_int(str_buf); // unit: kbps
+            if(param->bitrate <= 0) return OAPV_ERR_INVALID_ARGUMENT;
+            param->rc_type = OAPV_RC_ABR;
+        }
+        else return OAPV_ERR_INVALID_ARGUMENT;
+    }
+    NAME_CMP("q-matrix-c0") {
+
+        if(get_q_matrix(value, q_matrix)) {
+            return OAPV_ERR_INVALID_ARGUMENT;
+        }
+        oapv_mcpy(param->q_matrix[Y_C], q_matrix, sizeof(u8)*OAPV_BLK_D);
+        param->use_q_matrix = 1;
+    }
+    NAME_CMP("q-matrix-c1") {
+
+        if(get_q_matrix(value, q_matrix)) {
+            return OAPV_ERR_INVALID_ARGUMENT;
+        }
+        oapv_mcpy(param->q_matrix[U_C], q_matrix, sizeof(u8)*OAPV_BLK_D);
+        param->use_q_matrix = 1;
+    }
+    NAME_CMP("q-matrix-c2") {
+
+        if(get_q_matrix(value, q_matrix)) {
+            return OAPV_ERR_INVALID_ARGUMENT;
+        }
+        oapv_mcpy(param->q_matrix[V_C], q_matrix, sizeof(u8)*OAPV_BLK_D);
+        param->use_q_matrix = 1;
+    }
+    NAME_CMP("q-matrix-c3") {
+
+        if(get_q_matrix(value, q_matrix)) {
+            return OAPV_ERR_INVALID_ARGUMENT;
+        }
+        oapv_mcpy(param->q_matrix[X_C], q_matrix, sizeof(u8)*OAPV_BLK_D);
+        param->use_q_matrix = 1;
+    }
+    NAME_CMP("tile-w") {
+        GET_INTEGER_MIN_OR_ERR(value, ti0, OAPV_MIN_TILE_W);
+        oapv_assert_rv((ti0 & (OAPV_MB_W - 1)) == 0, OAPV_ERR_INVALID_ARGUMENT);
+        param->tile_w = ti0;
+    }
+    NAME_CMP("tile-h") {
+        GET_INTEGER_MIN_OR_ERR(value, ti0, OAPV_MIN_TILE_H);
+        oapv_assert_rv((ti0 & (OAPV_MB_W - 1)) == 0, OAPV_ERR_INVALID_ARGUMENT);
+        param->tile_h = ti0;
+    }
+    NAME_CMP("color-primaries") {
+        if(get_ival_from_skey(oapv_param_opts_color_primaries, value, &ti0)) {
+            return OAPV_ERR_INVALID_ARGUMENT;
+        }
+        param->color_primaries = ti0;
+        param->color_description_present_flag = 1;
+    }
+    NAME_CMP("color-transfer") {
+        if(get_ival_from_skey(oapv_param_opts_color_transfer, value, &ti0)) {
+            return OAPV_ERR_INVALID_ARGUMENT;
+        }
+        param->transfer_characteristics = ti0;
+        param->color_description_present_flag = 1;
+    }
+    NAME_CMP("color-matrix") {
+        if(get_ival_from_skey(oapv_param_opts_color_matrix, value, &ti0)) {
+            return OAPV_ERR_INVALID_ARGUMENT;
+        }
+        param->matrix_coefficients = ti0;
+        param->color_description_present_flag = 1;
+    }
+    NAME_CMP("color-range") {
+        if(get_ival_from_skey(oapv_param_opts_color_range, value, &ti0)) {
+            return OAPV_ERR_INVALID_ARGUMENT;
+        }
+        param->full_range_flag = ti0;
+        param->color_description_present_flag = 1;
+    }
+    else {
+        return OAPV_ERR_INVALID_ARGUMENT;
+    }
+
+    return OAPV_OK;
+}
+
+#define MAX_LEVEL_NUM 14
+#define MAX_BAND_NUM  4
+
+static float level_avail[MAX_LEVEL_NUM] = {
+    1, 1.1, 2, 2.1, 3, 3.1, 4, 4.1, 5, 5.1, 6, 6.1, 7, 7.1
+};
+
+static int level_idc_to_level_idx(int level_idc)
+{
+    for (int i = 0; i < MAX_LEVEL_NUM; i++) {
+        if (level_idc == OAPV_LEVEL_TO_LEVEL_IDC(level_avail[i])) {
+            return i;
+        }
+    }
+
+    return OAPV_ERR;
+}
+
+static int max_coded_data_rate[MAX_LEVEL_NUM][MAX_BAND_NUM] = {
+    {     7000,    11000,     14000,     21000 },
+    {    14000,    21000,     28000,     42000 },
+    {    36000,    53000,     71000,    106000 },
+    {    71000,   106000,    141000,    212000 },
+    {   101000,   151000,    201000,    301000 },
+    {   201000,   301000,    401000,    602000 },
+    {   401000,   602000,    780000,   1170000 },
+    {   780000,  1170000,   1560000,   2340000 },
+    {  1560000,  2340000,   3324000,   4986000 },
+    {  3324000,  4986000,   6648000,   9972000 },
+    {  6648000,  9972000,  13296000,  19944000 },
+    { 13296000, 19944000,  26592000,  39888000 },
+    { 26592000, 39888000,  53184000,  79776000 },
+    { 53184000, 79776000, 106368000, 159552000 }
+};
+
+static u64 max_luma_sample_rate[MAX_LEVEL_NUM] = {
+    3041280,     6082560,    15667200,   31334400,
+    66846720,    133693440,  265420800,  530841600,
+    1061683200,  2123366400, 4777574400, 8493465600,
+    16986931200, 33973862400
+};
+
+static int enc_update_param_level(oapve_param_t* param)
+{
+    int w = oapv_div_round_up(param->w, OAPV_MB_W) * OAPV_MB_W;
+    int h = oapv_div_round_up(param->h, OAPV_MB_H) * OAPV_MB_H;
+    double fps = (double)param->fps_num / param->fps_den;
+    u64 luma_sample_rate = (int)((double)w * h * fps);
+    int min_level_idx = 0;
+    for (int i = 0 ; i < MAX_LEVEL_NUM ; i++) {
+        if (luma_sample_rate <= max_luma_sample_rate[i]) {
+            min_level_idx = i;
+            break;
+        }
+    }
+
+    if (param->bitrate > 0) {
+        for (int i = min_level_idx; i < MAX_LEVEL_NUM; i++) {
+            if (param->bitrate <= max_coded_data_rate[i][param->band_idc]) {
+                min_level_idx = i;
+                break;
+            }
+
+        }
+    }
+
+    int min_level_idc = OAPV_LEVEL_TO_LEVEL_IDC(level_avail[min_level_idx]);
+
+    if (param->level_idc == OAPVE_PARAM_LEVEL_IDC_AUTO) {
+        param->level_idc = min_level_idc;
+    }
+    else {
+        if (param->level_idc < min_level_idc) {
+            return OAPV_ERR_INVALID_LEVEL;
+        }
+    }
+
+    return OAPV_OK;
+}
+
+static int enc_update_param_bitrate(oapve_param_t* param)
+{
+    int level_idx = level_idc_to_level_idx(param->level_idc);
+
+    if (param->bitrate == 0 && param->qp == OAPVE_PARAM_QP_AUTO) {
+        param->bitrate = max_coded_data_rate[level_idx][param->band_idc];
+    }
+    else if (param->bitrate > 0) {
+        if (param->bitrate > max_coded_data_rate[level_idx][param->band_idc]) {
+            return OAPV_ERR_INVALID_LEVEL;
+        }
+    }
+
+    return OAPV_OK;
+}
+
+static int enc_update_param_tile(oapve_ctx_t* ctx, oapve_param_t* param)
+{
+    /* set various value */
+    ctx->w = oapv_div_round_up(param->w, OAPV_MB_W) * OAPV_MB_W;
+    ctx->h = oapv_div_round_up(param->h, OAPV_MB_H) * OAPV_MB_H;
+
+    /* find correct tile width and height */
+    int tile_w, tile_h;
+
+    oapv_assert_rv(param->tile_w >= OAPV_MIN_TILE_W && param->tile_h >= OAPV_MIN_TILE_H, OAPV_ERR_INVALID_ARGUMENT);
+    oapv_assert_rv((param->tile_w & (OAPV_MB_W - 1)) == 0 && (param->tile_h & (OAPV_MB_H - 1)) == 0, OAPV_ERR_INVALID_ARGUMENT);
+
+    if (oapv_div_round_up(ctx->w, param->tile_w) > OAPV_MAX_TILE_COLS) {
+        tile_w = oapv_div_round_up(ctx->w, OAPV_MAX_TILE_COLS);
+        tile_w = oapv_div_round_up(tile_w, OAPV_MB_W) * OAPV_MB_W; // align to MB width
+    }
+    else {
+        tile_w = param->tile_w;
+    }
+    param->tile_w = tile_w;
+
+    if (oapv_div_round_up(ctx->h, param->tile_h) > OAPV_MAX_TILE_ROWS) {
+        tile_h = oapv_div_round_up(ctx->h, OAPV_MAX_TILE_ROWS);
+        tile_h = oapv_div_round_up(tile_h, OAPV_MB_H) * OAPV_MB_H; // align to MB height
+    }
+    else {
+        tile_h = param->tile_h;
+    }
+    param->tile_h = tile_h;
+
+    return OAPV_OK;
+}
+
+int oapve_param_update(oapve_ctx_t* ctx)
+{
+    int ret = OAPV_OK;
+    int min_num_tiles = OAPV_MAX_TILES;
+    for (int i = 0; i < ctx->cdesc.max_num_frms; i++) {
+        ret = enc_update_param_tile(ctx, &ctx->cdesc.param[i]);
+        oapv_assert_rv(ret == OAPV_OK, ret);
+        int num_tiles = oapv_div_round_up(ctx->w, ctx->cdesc.param[i].tile_w) * oapv_div_round_up(ctx->h, ctx->cdesc.param[i].tile_h);
+        min_num_tiles = oapv_min(min_num_tiles, num_tiles);
+
+        ret = enc_update_param_level(&ctx->cdesc.param[i]);
+        oapv_assert_rv(ret == OAPV_OK, ret);
+
+        ret = enc_update_param_bitrate(&ctx->cdesc.param[i]);
+        oapv_assert_rv(ret == OAPV_OK, ret);
+    }
+
+    if (ctx->cdesc.threads == OAPV_CDESC_THREADS_AUTO) {
+        int num_cores = oapv_get_num_cpu_cores();
+        ctx->threads = oapv_min(OAPV_MAX_THREADS, oapv_min(num_cores, min_num_tiles));
+    }
+    else {
+        ctx->threads = ctx->cdesc.threads;
+    }
+
+    return ret;
+}
diff --git a/src/oapv_param.h b/src/oapv_param.h
new file mode 100644
index 0000000..9e33402
--- /dev/null
+++ b/src/oapv_param.h
@@ -0,0 +1,42 @@
+/*
+ * Copyright (c) 2022 Samsung Electronics Co., Ltd.
+ * All Rights Reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions are met:
+ *
+ * - Redistributions of source code must retain the above copyright notice,
+ *   this list of conditions and the following disclaimer.
+ *
+ * - Redistributions in binary form must reproduce the above copyright notice,
+ *   this list of conditions and the following disclaimer in the documentation
+ *   and/or other materials provided with the distribution.
+ *
+ * - Neither the name of the copyright owner, nor the names of its contributors
+ *   may be used to endorse or promote products derived from this software
+ *   without specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ * ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
+ * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ * CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ * POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#ifndef __OAPV_PARAM_H__32943289478329438247238643278463728473829__
+#define __OAPV_PARAM_H__32943289478329438247238643278463728473829__
+
+#include "oapv.h"
+
+int oapve_param_default(oapve_param_t *param);
+int oapve_param_parse(oapve_param_t *param, const char *name,  const char *value);
+int oapve_param_update(oapve_ctx_t* ctx);
+
+#endif /* __OAPV_PARAM_H__32943289478329438247238643278463728473829__ */
+
diff --git a/src/oapv_port.c b/src/oapv_port.c
index b42d144..6075132 100644
--- a/src/oapv_port.c
+++ b/src/oapv_port.c
@@ -87,4 +87,37 @@ void oapv_trace_line(char *pre)
     }
     str[chars] = '\0';
     printf("%s\n", str);
-}
\ No newline at end of file
+}
+
+#if defined(WIN32) || defined(WIN64) || defined(_WIN32)
+#include <windows.h>
+#include <sysinfoapi.h>
+#else /* LINUX, MACOS, Android */
+#include <unistd.h>
+#endif
+
+int oapv_get_num_cpu_cores(void)
+{
+    int num_cores = 1; // default
+#if defined(WIN32) || defined(WIN64) || defined(_WIN32)
+    {
+        SYSTEM_INFO si;
+        GetNativeSystemInfo(&si);
+        num_cores = si.dwNumberOfProcessors;
+    }
+#elif defined(_SC_NPROCESSORS_ONLN)
+    {
+        num_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
+    }
+#elif defined(CPU_COUNT)
+    {
+        cpu_set_t cset;
+        memset(&cset, 0, sizeof(cset));
+        if(!sched_getaffinity(0, sizeof(cset), &cset)) {
+            num_cores = CPU_COUNT(&cset);
+        }
+    }
+#endif
+    return num_cores;
+}
+
diff --git a/src/oapv_port.h b/src/oapv_port.h
index 0ff627e..83769c2 100644
--- a/src/oapv_port.h
+++ b/src/oapv_port.h
@@ -199,4 +199,9 @@ void oapv_trace_line(char *pre);
 #define ALIGNED_32(var)  DECLARE_ALIGNED(var, 32)
 #define ALIGNED_128(var) DECLARE_ALIGNED(var, 128)
 
+
+/* CPU information */
+int oapv_get_num_cpu_cores(void);
+
 #endif /* _OAPV_PORT_H_ */
+
diff --git a/src/oapv_rc.c b/src/oapv_rc.c
index 91e2ae5..077297c 100644
--- a/src/oapv_rc.c
+++ b/src/oapv_rc.c
@@ -101,7 +101,7 @@ int oapve_rc_get_tile_cost_thread(oapve_ctx_t* ctx, u64* sum)
     }
 
     oapv_tpool_t* tpool = ctx->tpool;
-    int parallel_task = (ctx->cdesc.threads > ctx->num_tiles) ? ctx->num_tiles : ctx->cdesc.threads;
+    int parallel_task = (ctx->threads > ctx->num_tiles) ? ctx->num_tiles : ctx->threads;
 
     // run new threads
     int tidx = 0;
@@ -207,4 +207,5 @@ void oapve_rc_update_after_pic(oapve_ctx_t* ctx, double cost)
     diff_lambda = oapv_clip3(-0.125, 0.125, 0.25 * diff_lambda);
     ctx->rc_param.alpha = (ctx->rc_param.alpha) * exp(diff_lambda);
     ctx->rc_param.beta = (ctx->rc_param.beta) + diff_lambda / ln_bpp;
+    ctx->rc_param.is_updated = 1;
 }
diff --git a/src/oapv_util.h b/src/oapv_util.h
index 302452e..4c7a4cb 100644
--- a/src/oapv_util.h
+++ b/src/oapv_util.h
@@ -38,6 +38,10 @@
 #define oapv_min(a, b)               (((a) < (b)) ? (a) : (b))
 #define oapv_median(x, y, z)         ((((y) < (z)) ^ ((z) < (x))) ? (((x) < (y)) ^ ((z) < (x))) ? (y) : (x) : (z))
 
+#define oapv_div_round_up(n, d)      ((int)(((n) + (d) - 1) / (d)))
+#define oapv_div_round_closest(n, d) ((int)(((n) + (d)/2)/(d)))
+
+
 #define oapv_abs(a)                  (((a) > (0)) ? (a) : (-(a)))
 #define oapv_abs64(a)                (((a) ^ ((a) >> 63)) - ((a) >> 63)) // only for 64bit variable
 #define oapv_abs32(a)                (((a) ^ ((a) >> 31)) - ((a) >> 31)) // only for 32bit variable
diff --git a/src/oapv_vlc.c b/src/oapv_vlc.c
index bc80e6c..c9aab77 100644
--- a/src/oapv_vlc.c
+++ b/src/oapv_vlc.c
@@ -279,8 +279,8 @@ void oapve_set_frame_header(oapve_ctx_t *ctx, oapv_fh_t *fh)
     fh->fi.frame_height = param->h;
     fh->fi.chroma_format_idc = ctx->cfi;
     fh->fi.bit_depth = ctx->bit_depth;
-    fh->tile_width_in_mbs = param->tile_w_mb;
-    fh->tile_height_in_mbs = param->tile_h_mb;
+    fh->tile_width_in_mbs = param->tile_w / OAPV_MB_W;
+    fh->tile_height_in_mbs = param->tile_h / OAPV_MB_H;
 
     fh->color_description_present_flag = param->color_description_present_flag;
     fh->color_primaries = param->color_primaries;
diff --git a/test/README.md b/test/README.md
index a404bfc..2488915 100644
--- a/test/README.md
+++ b/test/README.md
@@ -5,18 +5,18 @@
 
 | No. | Bitstream Name | Description                                                  | Profile&nbsp;&nbsp; | Level | Band | Frame Rate | Resolution | # of Frame | MD5 sum of bitstream             |
 |-----|----------------|--------------------------------------------------------------|---------------------|-------|------|------------|------------|------------|----------------------------------|
-| 1   | tile_A         | one-tile per   one-picture                                   | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 74c5c0ca1bd2cfb28c6e2e0673e965f9 |
-| 2   | tile_B         | Tile size = min size   tile (256x128)                        | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 666ec80235a1e8f59db044d77a89a495 |
-| 3   | tile_C         | # of Tiles: max num   tile (20x20)                           | 422-10              | 5     | 0    | 30 fps     | 7680x4320  | 3          | 75363d036965a9dccc90a9ce8d0ae652 |
-| 4   | tile_D         | tile dummy data test                                         | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | dd492519c90409a9ca5710746f45c125 |
-| 5   | tile_E         | tile_size_present_in_fh_flag=on                              | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 134c4aa46cec9ab0299824682a89eecd |
-| 6   | qp_A           | QP matrix enabled                                            | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 5ca6d4ea0f65add261b44ed3532a0a73 |
-| 7   | qp_B           | Tile QP   variation in a frame                               | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 85bfa477911447d994c17dea9703a9c7 |
-| 8   | qp_C           | Set all the QPs in a   frame equal to min. QP (=0)           | 422-10              | 6     | 2    | 60 fps     | 3840x2160  | 3          | 8c2928ec05eb06d42d6a8bda0ceb7e8d |
-| 9   | qp_D           | Set all the QPs in a   frame equal to max. QP (=51)          | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 9c98e376fb59100f5a5585482fb33746 |
-| 10  | qp_E           | Set different QP   betwee luma and chroma                    | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 6d1a1bc982d412758f353c8d041979d1 |
-| 11  | syn_A          | Exercise a synthetic   image with QP = 0 and QP = 51         | 422-10              | 4.1   | 2    | 60 fps     | 1920x1080  | 2          | db9f8f7ce57871481e5b257b79149b1e |
-| 12  | syn_B          | Exercise a synthetic   image with Tile QP variation in Frame | 422-10              | 4.1   | 2    | 60 fps     | 1920x1080  | 2          | 5f6c57f0bfe7ceb2f97a56a3bec7fb7a |
+| 1   | tile_A         | one-tile per   one-picture                                   | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | c5b2f4c4ec9804f0292b2f12bd558dc5 |
+| 2   | tile_B         | Tile size = min size   tile (256x128)                        | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 7d626cea95f8d7a4b3f1f6e3d10e923c |
+| 3   | tile_C         | # of Tiles: max num   tile (20x20)                           | 422-10              | 5     | 0    | 30 fps     | 7680x4320  | 3          | 758377994717d15999f53341eb5d6038 |
+| 4   | tile_D         | tile dummy data test                                         | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | e124625d4ad310e2e60e366a63f669c9 |
+| 5   | tile_E         | tile_size_present_in_fh_flag=on                              | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 77cd01a8821cd17c2188fca033edc726 |
+| 6   | qp_A           | QP matrix enabled                                            | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 1ade0aed96ddf0aab286a082c17701d7 |
+| 7   | qp_B           | Tile QP   variation in a frame                               | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | c7cac366f29dc6571bc814923cadeb4b |
+| 8   | qp_C           | Set all the QPs in a   frame equal to min. QP (=0)           | 422-10              | 6     | 2    | 60 fps     | 3840x2160  | 3          | 6e2928f315e1670b6842955b0e7b4ad8 |
+| 9   | qp_D           | Set all the QPs in a   frame equal to max. QP (=51)          | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | c7a3e5d7f1c987a064a7bdb08944901f |
+| 10  | qp_E           | Set different QP   betwee luma and chroma                    | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 7d626cea95f8d7a4b3f1f6e3d10e923c |
+| 11  | syn_A          | Exercise a synthetic   image with QP = 0 and QP = 51         | 422-10              | 4.1   | 2    | 60 fps     | 1920x1080  | 2          | 7b0cc8fdffdfca860dcee9b69b051053 |
+| 12  | syn_B          | Exercise a synthetic   image with Tile QP variation in Frame | 422-10              | 4.1   | 2    | 60 fps     | 1920x1080  | 2          | b87a59443b009e9241393e6e1a927d61 |
 
 ## Test sequence
 "sequence" folder has the uncompressed video sequence for encoder testing.
diff --git a/test/bitstream/qp_A.apv b/test/bitstream/qp_A.apv
index 39b97a6..226a2ab 100644
Binary files a/test/bitstream/qp_A.apv and b/test/bitstream/qp_A.apv differ
diff --git a/test/bitstream/qp_B.apv b/test/bitstream/qp_B.apv
index f685630..927395b 100644
Binary files a/test/bitstream/qp_B.apv and b/test/bitstream/qp_B.apv differ
diff --git a/test/bitstream/qp_C.apv b/test/bitstream/qp_C.apv
index 33b599e..e088ee7 100644
Binary files a/test/bitstream/qp_C.apv and b/test/bitstream/qp_C.apv differ
diff --git a/test/bitstream/qp_D.apv b/test/bitstream/qp_D.apv
index d094042..b461159 100644
Binary files a/test/bitstream/qp_D.apv and b/test/bitstream/qp_D.apv differ
diff --git a/test/bitstream/qp_E.apv b/test/bitstream/qp_E.apv
index 62bde8c..9d552d3 100644
Binary files a/test/bitstream/qp_E.apv and b/test/bitstream/qp_E.apv differ
diff --git a/test/bitstream/syn_A.apv b/test/bitstream/syn_A.apv
index 1d325d1..ae845c9 100644
Binary files a/test/bitstream/syn_A.apv and b/test/bitstream/syn_A.apv differ
diff --git a/test/bitstream/syn_B.apv b/test/bitstream/syn_B.apv
index 641a108..2c61834 100644
Binary files a/test/bitstream/syn_B.apv and b/test/bitstream/syn_B.apv differ
diff --git a/test/bitstream/tile_A.apv b/test/bitstream/tile_A.apv
index 1f8d213..9967b4c 100644
Binary files a/test/bitstream/tile_A.apv and b/test/bitstream/tile_A.apv differ
diff --git a/test/bitstream/tile_B.apv b/test/bitstream/tile_B.apv
index f796778..9d552d3 100644
Binary files a/test/bitstream/tile_B.apv and b/test/bitstream/tile_B.apv differ
diff --git a/test/bitstream/tile_C.apv b/test/bitstream/tile_C.apv
index 4bf2f9b..1b837c4 100644
Binary files a/test/bitstream/tile_C.apv and b/test/bitstream/tile_C.apv differ
diff --git a/test/bitstream/tile_D.apv b/test/bitstream/tile_D.apv
index 7d61d5c..fea21fd 100644
Binary files a/test/bitstream/tile_D.apv and b/test/bitstream/tile_D.apv differ
diff --git a/test/bitstream/tile_E.apv b/test/bitstream/tile_E.apv
index 66b1c3d..f9938cf 100644
Binary files a/test/bitstream/tile_E.apv and b/test/bitstream/tile_E.apv differ
diff --git a/util/apv.hexpat b/util/apv.hexpat
index 86431cd..0dd1b14 100644
--- a/util/apv.hexpat
+++ b/util/apv.hexpat
@@ -20,20 +20,20 @@ fn get_0xff_ext_var(auto addr) {
     u32 read = 1;
     u32 var = 0;
     u8 ext = std::mem::read_unsigned(addr, 1);
-    
+
     while (ext == 0xFF) {
         var += 0xFF;
         ext = std::mem::read_unsigned(addr + read, 1);
         read += 1;
     }
-    var += ext; 
+    var += ext;
     return var;
 };
 
 fn get_0xff_ext_var_bytes(auto addr) {
     u32 read = 1;
     u8 ext = std::mem::read_unsigned(addr, 1);
-    
+
     while (ext == 0xFF) {
         ext = std::mem::read_unsigned(addr + read, 1);
         read += 1;
@@ -41,12 +41,22 @@ fn get_0xff_ext_var_bytes(auto addr) {
     return read;
 };
 
+fn get_num_comp(auto chroma_format_idc) {
+    u32 nc = 0;
+
+    if(chroma_format_idc == 0) nc = 1;
+    else if(chroma_format_idc == 4) nc = 4;
+    else nc = 3;
+
+    return nc;
+};
+
 struct PbuBase {
 
     u32 read = 0;
     str ptype_str = "";
-    
-    /*    
+
+    /*
     syntax code                                                   | type
     --------------------------------------------------------------|-----
     pbu_header(){                                                 |
@@ -55,7 +65,7 @@ struct PbuBase {
         reserved_zero_8bits                                       | u(8)
     }
     */
-        
+
     u32 pbu_size; // originally, this syntax is part of AuccessUnit
     u8 pbu_type;
     u16 group_id;
@@ -63,7 +73,7 @@ struct PbuBase {
     read += 4;
 };
 
-/*    
+/*
 syntax code                                                   | type
 --------------------------------------------------------------|-----
 frame_info(){                                                 |
@@ -93,18 +103,58 @@ bitfield FrmInfo {
     reserved_zero_8bits: 8;
 };
 
+bitfield ColorInfo {
+    u32 readbits = 25;
+
+    color_primaries : 8;
+    transfer_characteristics : 8;
+    matrix_coefficients : 8;
+    bool full_range_flag : 1;
+};
+
+bitfield FrmHeader {
+    u32 readbits = 0;
+    u32 ncomps = 0;
+
+    FrmInfo finfo [[name("frame_info()")]];
+    readbits += (12 * 8);
+
+    ncomps = get_num_comp(finfo.chroma_format_idc);
+    std::print("    NumComps = {:d}", ncomps);
+
+    reserved_zero_8bits : 8;
+    readbits += 8;
+
+    bool color_description_present_flag : 1;
+    readbits += 1;
+    if(color_description_present_flag) {
+        ColorInfo color_description;
+        readbits += color_description.readbits;
+    }
+    bool use_q_matrix : 1;
+    readbits += 1;
+    if(use_q_matrix) {
+        // need to implement
+        std::print("    ERR: not implemented yet!!!\n");
+    }
+};
+
 struct PbuFrm:PbuBase {
-    
+    u32 frmh_bits = 0;
+    u32 NumComps = 0;
+    u32 NumTiles = 0;
+
     if(pbu_type == PbuType::FRM_PRI) ptype_str = "Frm(Pri)";
     else if(pbu_type == PbuType::FRM_NONPRI) ptype_str = "Frm(Nonpri)";
     else if(pbu_type == PbuType::FRM_PREVIEW) ptype_str = "Frm(Preview)";
     else if(pbu_type == PbuType::FRM_DEPTH) ptype_str = "Frm(Depth)";
     else if(pbu_type == PbuType::FRM_ALPHA) ptype_str = "Frm(Alpha)";
     else ptype_str = "Frm(Unknown)";
-    
-    FrmInfo finfo [[name("frame_info()")]];
-    read += 12; // byte size of frame_info()
-    
+
+    FrmHeader fh [[name("frame_header()")]];
+
+    read += (fh.readbits + 7) >> 3;
+
     u8 frameData[pbu_size - read] [[sealed]];
 };
 
@@ -113,7 +163,7 @@ u32 metadata_payload_count = 0;
 struct MetadataPayload {
     str ptype_str = "";
     u32 read = 0;
-    
+
     u32 payloadType = get_0xff_ext_var($) [[export]];
     read += get_0xff_ext_var_bytes($);
     $ += get_0xff_ext_var_bytes($); // update current reading point
@@ -121,9 +171,8 @@ struct MetadataPayload {
     u32 payloadSize = get_0xff_ext_var($) [[export]];
     read += get_0xff_ext_var_bytes($);
     $ += get_0xff_ext_var_bytes($); // update current reading point
-    
-    u64 endOffset = $ + payloadSize;
 
+    u64 endOffset = $ + payloadSize;
 
     if (payloadType == 4) ptype_str = "itu_t_t35";
     else if (payloadType == 5) ptype_str = "mdcv";
@@ -131,29 +180,27 @@ struct MetadataPayload {
     else if (payloadType == 10) ptype_str = "filler";
     else if (payloadType == 170) ptype_str = "user_defined";
     else ptype_str = "undefined";
-    
-    std::print("    metadata payload[{:d}] type = {:d}({}), size = {:d}", metadata_payload_count, payloadType, ptype_str, payloadSize);                 
+
+    std::print("    metadata payload[{:d}] type = {:d}({}), size = {:d}", metadata_payload_count, payloadType, ptype_str, payloadSize);
 
     u8 payloadData[while($ < endOffset)] [[sealed]];
-    
+
     metadata_payload_count += 1;
-    
-    
+
 } [[name(std::format("MetadataPayload[{}]:{}", (metadata_payload_count - 1), ptype_str))]];
 
 struct PbuMetadata:PbuBase {
     u64 endOffset = 0;
     ptype_str = "Metadata";
     metadata_payload_count = 0; // reset number of metadata payload
-     
+
     u32 metadata_size; // syntax
-    
+
     endOffset = $ + metadata_size;
 
     MetadataPayload pay[while($ < endOffset)] [[inline]];
 };
 
-
 struct PbuAui:PbuBase {
     ptype_str = "aui";
     u8 data[pbu_size - read] [[sealed]];
@@ -169,13 +216,13 @@ struct PbuUnknown:PbuBase {
     ptype_str = "unknown";
     u8 data[pbu_size - read] [[sealed]];
 };
-    
+
 u32 pbu_count = 0;
 
-struct PBU {  
+struct PBU {
     u32 pbu_size = std::mem::read_unsigned($, 4, std::mem::Endian::Big);
     u8 pbu_type = std::mem::read_unsigned($ + 4, 1, std::mem::Endian::Big);
-    
+
     match (pbu_type) {
         (PbuType::FRM_PRI) : PbuFrm Pbu [[inline]];
         (PbuType::FRM_NONPRI) :  PbuFrm Pbu [[inline]];
@@ -187,8 +234,8 @@ struct PBU {
         (PbuType::FILLER): PbuFiller Pbu [[inline]];
         (_) : PbuUnknown Pbu [[inline]];
     }
-    
-    std::print("  PBU[{:d}] size = {:d}, {}", pbu_count, pbu_size, Pbu.ptype_str);    
+
+    std::print("  PBU[{:d}] size = {:d}, {}", pbu_count, pbu_size, Pbu.ptype_str);
 
     pbu_count += 1;
 
@@ -199,13 +246,13 @@ u32 au_count = 0;
 
 struct AccessUnit {
     u64 au_end = 0;
-        
+
     u32 au_size; // originally this syntax is part of RawBitstream
-        
+
     std::print("AU[{:d}] size = {:d}", au_count, au_size);
-                
+
     au_end = $ + au_size;
-    
+
     pbu_count = 0; // reset number of PBU
 
     char signature[4]; // 'aPv1'
@@ -214,7 +261,7 @@ struct AccessUnit {
 
 u32 raw_count = 0;
 
-struct RawBitstream {       
+struct RawBitstream {
     AccessUnit AU [[name(std::format("AU[{}]", raw_count))]];
     raw_count += 1;
 } [[name(std::format("Raw[{}]", (raw_count - 1)))]];
@@ -223,4 +270,4 @@ struct ApvBitstream {
     RawBitstream Raw [[inline]];
 }[[inline]];
 
-ApvBitstream APV[while(!std::mem::eof())] @ 0x0 [[inline]];
\ No newline at end of file
+ApvBitstream APV[while(!std::mem::eof())] @ 0x0 [[inline]];
diff --git a/version.txt b/version.txt
index 5edad9a..faceed6 100644
--- a/version.txt
+++ b/version.txt
@@ -1 +1 @@
-v0.1.11.3.1
+v0.1.13
```

