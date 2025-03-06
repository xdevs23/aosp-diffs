```diff
diff --git a/emoji-compat/Android.bp b/emoji-compat/Android.bp
index 4ea10ca..92ac0cf 100644
--- a/emoji-compat/Android.bp
+++ b/emoji-compat/Android.bp
@@ -60,7 +60,7 @@ prebuilt_emoji_font {
         targets: ["droidcore"],
     },
     // Need a default value because SDK build doesn't include fonts.mk.
-    src: "font/2.042/Noto-COLRv1-noflags.ttf",
+    src: "font/2.047/Noto-COLRv1-noflags.ttf",
     soong_config_variables: {
         emoji_font_version: {
             src: "font/%s/Noto-COLRv1-noflags.ttf",
@@ -82,7 +82,7 @@ prebuilt_flag_emoji_font {
         targets: ["droidcore"],
     },
     // Need a default value because SDK build doesn't include fonts.mk.
-    src: "font/2.042/NotoColorEmoji-flagsonly.ttf",
+    src: "font/2.047/NotoColorEmoji-flagsonly.ttf",
     soong_config_variables: {
         flag_emoji_font_version: {
             src: "font/%s/NotoColorEmoji-flagsonly.ttf",
@@ -92,7 +92,7 @@ prebuilt_flag_emoji_font {
 
 prebuilt_font {
     name: "NotoColorEmojiLegacy.ttf",
-    src: "font/2.042/NotoColorEmoji-noflags.ttf",
+    src: "font/2.047/NotoColorEmoji-noflags.ttf",
     dist: {
         targets: ["droidcore"],
     },
diff --git a/emoji-compat/font/2.047/Noto-COLRv1-noflags.ttf b/emoji-compat/font/2.047/Noto-COLRv1-noflags.ttf
new file mode 100644
index 0000000..f7ccf83
Binary files /dev/null and b/emoji-compat/font/2.047/Noto-COLRv1-noflags.ttf differ
diff --git a/emoji-compat/font/2.047/NotoColorEmoji-flagsonly.ttf b/emoji-compat/font/2.047/NotoColorEmoji-flagsonly.ttf
new file mode 100644
index 0000000..6e1642e
Binary files /dev/null and b/emoji-compat/font/2.047/NotoColorEmoji-flagsonly.ttf differ
diff --git a/emoji-compat/font/2.047/NotoColorEmoji-noflags.ttf b/emoji-compat/font/2.047/NotoColorEmoji-noflags.ttf
new file mode 100644
index 0000000..93b1759
Binary files /dev/null and b/emoji-compat/font/2.047/NotoColorEmoji-noflags.ttf differ
diff --git a/fonts.mk b/fonts.mk
index cc00b9b..a9839fa 100644
--- a/fonts.mk
+++ b/fonts.mk
@@ -16,25 +16,11 @@
 # PRODUCT_COPY_FILES to install the font files, so that the NOTICE file can
 # get installed too.
 
-ifneq ($(RELEASE_REMOVE_LEGACY_EMOJI_FONT),true)
-# The legacy emoji font is always excluded from the wear OS.
-ifneq ($(CLOCKWORK_PRODUCT),true)
-	PRODUCT_PACKAGES := NotoColorEmojiLegacy.ttf
-endif
-endif
-
-
-# Set RELEASE_PACKAGE_VARIABLE_NOTO_SANS_CJK to noto_sans_cjk_config.use_var_font in Android.bp
-$(call soong_config_set,noto_sans_cjk_config,use_var_font,$(RELEASE_PACKAGE_VARIABLE_NOTO_SANS_CJK))
-
 # Set emoji version in Android.bp
 $(call soong_config_set,emoji_font,emoji_font_version,$(RELEASE_PACKAGE_EMOJI_FONT_VERSION))
 $(call soong_config_set,flag_emoji_font,flag_emoji_font_version,$(RELEASE_PACKAGE_FLAG_EMOJI_FONT_VERSION))
 
-ifeq ($(RELEASE_PACKAGE_HENTAIGANA_FONT), true)
-	PRODUCT_PACKAGES := NotoSerifHentaigana.ttf
-endif
-
+$(call soong_config_set,noto_fonts,notosanskhmer_ver,$(RELEASE_PACKAGE_NOTO_SANS_KHMER_VERSION))
 
 PRODUCT_PACKAGES := \
     $(PRODUCT_PACKAGES) \
@@ -212,6 +198,7 @@ PRODUCT_PACKAGES := \
     NotoSerifGurmukhi-VF.ttf \
     NotoSerifHebrew-Bold.ttf \
     NotoSerifHebrew-Regular.ttf \
+    NotoSerifHentaigana.ttf \
     NotoSerifKannada-VF.ttf \
     NotoSerifKhmer-Bold.otf \
     NotoSerifKhmer-Regular.otf \
diff --git a/notosanscjk/Android.bp b/notosanscjk/Android.bp
index 4f76787..35c6ccc 100644
--- a/notosanscjk/Android.bp
+++ b/notosanscjk/Android.bp
@@ -45,47 +45,15 @@ license {
     ],
 }
 
-soong_config_bool_variable {
-    name: "use_var_font",
-}
-
-soong_config_module_type {
-    name: "prebuilt_noto_sans_cjk",
-    module_type: "prebuilt_font",
-    config_namespace: "noto_sans_cjk_config",
-    bool_variables: ["use_var_font"],
-    properties: ["src"],
-}
-
-prebuilt_noto_sans_cjk {
+prebuilt_font {
     name: "NotoSansCJK-Regular.ttc",
-    src: "NotoSansCJK-Regular.ttc",
-    soong_config_variables: {
-        use_var_font: {
-            src: "NotoSansCJK-wght-400-900.otf.ttc",
-        },
-    },
-}
-
-soong_config_module_type {
-    name: "filegroup_for_vf",
-    module_type: "filegroup",
-    config_namespace: "noto_sans_cjk_config",
-    bool_variables: ["use_var_font"],
-    properties: ["srcs"],
+    src: "NotoSansCJK-wght-400-900.otf.ttc",
 }
 
-filegroup_for_vf {
+filegroup {
     name: "NotoSansCJK",
     required: [
         "NotoSansCJK-Regular.ttc",
     ],
-    soong_config_variables: {
-        use_var_font: {
-            srcs: ["font_config_vf.json"],
-            conditions_default: {
-                srcs: ["font_config.json"],
-            },
-        },
-    },
+    srcs: ["font_config.json"],
 }
diff --git a/notosanscjk/font_config.json b/notosanscjk/font_config.json
index 8a56897..b6eccc0 100644
--- a/notosanscjk/font_config.json
+++ b/notosanscjk/font_config.json
@@ -7,6 +7,7 @@
                 "postScriptName": "NotoSansCJKJP-Regular",
                 "weight": "400",
                 "style": "normal",
+                "supportedAxes": "wght",
                 "index": "2"
             }
         ],
@@ -20,6 +21,7 @@
                 "postScriptName": "NotoSansCJKJP-Regular",
                 "weight": "400",
                 "style": "normal",
+                "supportedAxes": "wght",
                 "index": "3"
             }
         ],
@@ -33,6 +35,7 @@
                 "postScriptName": "NotoSansCJKJP-Regular",
                 "weight": "400",
                 "style": "normal",
+                "supportedAxes": "wght",
                 "index": "0"
             }
         ],
@@ -46,6 +49,7 @@
                 "postScriptName": "NotoSansCJKJP-Regular",
                 "weight": "400",
                 "style": "normal",
+                "supportedAxes": "wght",
                 "index": "1"
             }
         ],
diff --git a/notosanscjk/font_config_vf.json b/notosanscjk/font_config_vf.json
deleted file mode 100644
index c09d6ea..0000000
--- a/notosanscjk/font_config_vf.json
+++ /dev/null
@@ -1,70 +0,0 @@
-[
-    {
-        "lang": "zh-Hans",
-        "fonts": [
-            {
-                "file": "NotoSansCJK-Regular.ttc",
-                "postScriptName": "NotoSansCJKJP-Regular",
-                "weight": "400",
-                "style": "normal",
-                "supportedAxes": "wght",
-                "axes": {
-                    "wght": "400"
-                },
-                "index": "2"
-            }
-        ],
-        "id": "NotoSansCJK_zh-Hans"
-    },
-    {
-        "lang": "zh-Hant,zh-Bopo",
-        "fonts": [
-            {
-                "file": "NotoSansCJK-Regular.ttc",
-                "postScriptName": "NotoSansCJKJP-Regular",
-                "weight": "400",
-                "style": "normal",
-                "supportedAxes": "wght",
-                "axes": {
-                    "wght": "400"
-                },
-                "index": "3"
-            }
-        ],
-        "id": "NotoSansCJK_zh-Hant,zh-Bopo"
-    },
-    {
-        "lang": "ja",
-        "fonts": [
-            {
-                "file": "NotoSansCJK-Regular.ttc",
-                "postScriptName": "NotoSansCJKJP-Regular",
-                "weight": "400",
-                "style": "normal",
-                "supportedAxes": "wght",
-                "axes": {
-                    "wght": "400"
-                },
-                "index": "0"
-            }
-        ],
-        "id": "NotoSansCJK_ja"
-    },
-    {
-        "lang": "ko",
-        "fonts": [
-            {
-                "file": "NotoSansCJK-Regular.ttc",
-                "postScriptName": "NotoSansCJKJP-Regular",
-                "weight": "400",
-                "style": "normal",
-                "supportedAxes": "wght",
-                "axes": {
-                    "wght": "400"
-                },
-                "index": "1"
-            }
-        ],
-        "id": "NotoSansCJK_ko"
-    }
-]
\ No newline at end of file
diff --git a/notosanskhmer/NotoSansKhmer-VF.ttf b/notosanskhmer/1.901/NotoSansKhmer-VF.ttf
similarity index 100%
rename from notosanskhmer/NotoSansKhmer-VF.ttf
rename to notosanskhmer/1.901/NotoSansKhmer-VF.ttf
diff --git a/notosanskhmer/font_config.json b/notosanskhmer/1.901/font_config.json
similarity index 100%
rename from notosanskhmer/font_config.json
rename to notosanskhmer/1.901/font_config.json
diff --git a/notosanskhmer/2.004/NotoSansKhmer-VF.ttf b/notosanskhmer/2.004/NotoSansKhmer-VF.ttf
new file mode 100644
index 0000000..4ede67c
Binary files /dev/null and b/notosanskhmer/2.004/NotoSansKhmer-VF.ttf differ
diff --git a/notosanskhmer/2.004/font_config.json b/notosanskhmer/2.004/font_config.json
new file mode 100644
index 0000000..0d843b9
--- /dev/null
+++ b/notosanskhmer/2.004/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Khmr",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansKhmer-VF.ttf",
+                "postScriptName": "NotoSansKhmer-Regular",
+                "weight": "400",
+                "style": "normal",
+                "supportedAxes": "wght",
+                "axes": {
+                    "wdth": "100.0"
+                }
+            }
+        ],
+        "id": "NotoSansKhmer-VF_und-Khmr"
+    }
+]
diff --git a/notosanskhmer/Android.bp b/notosanskhmer/Android.bp
index 835fc75..52ffd3b 100644
--- a/notosanskhmer/Android.bp
+++ b/notosanskhmer/Android.bp
@@ -45,15 +45,45 @@ license {
     ],
 }
 
-prebuilt_font {
+soong_config_module_type {
+    name: "prebuilt_notosanskhmer",
+    module_type: "prebuilt_font",
+    config_namespace: "noto_fonts",
+    value_variables: ["notosanskhmer_ver"],
+    properties: ["src"],
+}
+
+prebuilt_notosanskhmer {
     name: "NotoSansKhmer-VF.ttf",
-    src: "NotoSansKhmer-VF.ttf",
+    soong_config_variables: {
+        notosanskhmer_ver: {
+            src: "%s/NotoSansKhmer-VF.ttf",
+            conditions_default: {
+                src: "1.901/NotoSansKhmer-VF.ttf"
+            }
+        },
+    },
+}
+
+soong_config_module_type {
+    name: "filegroup_notosanskhmer",
+    module_type: "filegroup",
+    config_namespace: "noto_fonts",
+    value_variables: ["notosanskhmer_ver"],
+    properties: ["srcs"],
 }
 
-filegroup {
+filegroup_notosanskhmer {
     name: "NotoSansKhmer-VF",
-    srcs: ["font_config.json"],
     required: [
-        "NotoSansKhmer-VF.ttf",
+        "NotoSansKhmer-VF.ttf"
     ],
+    soong_config_variables: {
+        notosanskhmer_ver: {
+          srcs: ["%s/font_config.json"],
+          conditions_default: {
+              srcs: ["1.901/font_config.json"],
+          },
+        }
+    }
 }
diff --git a/notosanskhmer/METADATA b/notosanskhmer/METADATA
index 117e8a2..c556136 100644
--- a/notosanskhmer/METADATA
+++ b/notosanskhmer/METADATA
@@ -7,7 +7,7 @@ third_party {
     type: ARCHIVE
     value: "https://github.com/google/fonts/tree/main/ofl/notosanskhmer"
   }
-  version: "1.901"
+  version: "2.004"
   license_type: NOTICE
-  last_upgrade_date { year: 2017 month: 3 day: 17 }
+  last_upgrade_date { year: 2024 month: 11 day: 27 }
 }
```

