```diff
diff --git a/Android.bp b/Android.bp
index 39811ec16..01e830c29 100644
--- a/Android.bp
+++ b/Android.bp
@@ -101,7 +101,7 @@ java_aconfig_library {
     libs: [
         "fake_device_config",
         "aconfig-annotations-lib-sdk-none",
-        "aconfig_storage_reader_java_none",
+        "aconfig_storage_stub_none",
         "unsupportedappusage-sdk-none",
     ],
     apex_available: [
diff --git a/android_icu4j/Android.bp b/android_icu4j/Android.bp
index 51c80f84b..99d7eebb9 100644
--- a/android_icu4j/Android.bp
+++ b/android_icu4j/Android.bp
@@ -30,10 +30,6 @@ package {
     default_applicable_licenses: ["external_icu_license"],
 }
 
-build = [
-    "Ravenwood.bp",
-]
-
 //==========================================================
 // build repackaged ICU for target
 //
@@ -378,6 +374,15 @@ filegroup {
     ],
 }
 
+// Used by ravenwood for processing
+filegroup {
+    name: "icu-ravenwood-policies",
+    visibility: ["//frameworks/base/ravenwood"],
+    srcs: [
+        "icu-ravenwood-policies.txt",
+    ],
+}
+
 // Generates stub source files for the core platform API of the I18N module.
 // i.e. every class/member that is either in the public API or annotated with
 // @CorePlatformApi.
diff --git a/android_icu4j/Ravenwood.bp b/android_icu4j/Ravenwood.bp
deleted file mode 100644
index 283939203..000000000
--- a/android_icu4j/Ravenwood.bp
+++ /dev/null
@@ -1,69 +0,0 @@
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-// For ravenwood.
-// TODO(b/340889954) Enable --supported-api-list-file, once AOSP gets this feature.
-java_genrule {
-    name: "core-icu4j-for-host.ravenwood-base",
-    tools: ["hoststubgen"],
-    cmd: "$(location hoststubgen) " +
-        "@$(location :ravenwood-standard-options) " +
-
-        "--debug-log $(location hoststubgen_core-icu4j-for-host.log) " +
-        "--stats-file $(location hoststubgen_core-icu4j-for-host_stats.csv) " +
-        // "--supported-api-list-file $(location hoststubgen_core-icu4j-for-host_apis.csv) " +
-
-        "--out-impl-jar $(location ravenwood.jar) " +
-
-        "--gen-keep-all-file $(location hoststubgen_core-icu4j-for-host_keep_all.txt) " +
-        "--gen-input-dump-file $(location hoststubgen_core-icu4j-for-host_dump.txt) " +
-
-        "--in-jar $(location :core-icu4j-for-host) " +
-        "--policy-override-file $(location icu-ravenwood-policies.txt) " +
-        "--annotation-allowed-classes-file $(location :ravenwood-annotation-allowed-classes) ",
-    srcs: [
-        ":core-icu4j-for-host",
-
-        "icu-ravenwood-policies.txt",
-        ":ravenwood-standard-options",
-        ":ravenwood-annotation-allowed-classes",
-    ],
-    out: [
-        "ravenwood.jar",
-
-        // Following files are created just as FYI.
-        "hoststubgen_core-icu4j-for-host_keep_all.txt",
-        "hoststubgen_core-icu4j-for-host_dump.txt",
-
-        "hoststubgen_core-icu4j-for-host.log",
-        "hoststubgen_core-icu4j-for-host_stats.csv",
-        // "hoststubgen_core-icu4j-for-host_apis.csv",
-    ],
-    defaults: ["ravenwood-internal-only-visibility-genrule"],
-}
-
-// Extract the impl jar from "core-icu4j-for-host.ravenwood-base" for subsequent build rules.
-// Note this emits a "device side" output, so that ravenwood tests can (implicitly)
-// depend on it.
-java_genrule {
-    name: "core-icu4j-for-host.ravenwood",
-    defaults: ["ravenwood-internal-only-visibility-genrule"],
-    cmd: "cp $(in) $(out)",
-    srcs: [
-        ":core-icu4j-for-host.ravenwood-base{ravenwood.jar}",
-    ],
-    out: [
-        "core-icu4j-for-host.ravenwood.jar",
-    ],
-}
diff --git a/android_icu4j/api/public/current.txt b/android_icu4j/api/public/current.txt
index 6125d3847..16b480778 100644
--- a/android_icu4j/api/public/current.txt
+++ b/android_icu4j/api/public/current.txt
@@ -242,6 +242,7 @@ package android.icu.lang {
     field public static final int OTHER = 0; // 0x0
     field public static final int PURE_KILLER = 26; // 0x1a
     field public static final int REGISTER_SHIFTER = 27; // 0x1b
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int REORDERING_KILLER = 36; // 0x24
     field public static final int SYLLABLE_MODIFIER = 28; // 0x1c
     field public static final int TONE_LETTER = 29; // 0x1d
     field public static final int TONE_MARK = 30; // 0x1e
@@ -281,6 +282,7 @@ package android.icu.lang {
     field public static final int HETH = 18; // 0x12
     field public static final int KAF = 19; // 0x13
     field public static final int KAPH = 20; // 0x14
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int KASHMIRI_YEH = 104; // 0x68
     field public static final int KHAPH = 52; // 0x34
     field public static final int KNOTTED_HEH = 21; // 0x15
     field public static final int LAM = 22; // 0x16
@@ -370,9 +372,9 @@ package android.icu.lang {
   }
 
   public static interface UCharacter.LineBreak {
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final int AKSARA = 43; // 0x2b
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final int AKSARA_PREBASE = 44; // 0x2c
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final int AKSARA_START = 45; // 0x2d
+    field public static final int AKSARA = 43; // 0x2b
+    field public static final int AKSARA_PREBASE = 44; // 0x2c
+    field public static final int AKSARA_START = 45; // 0x2d
     field public static final int ALPHABETIC = 2; // 0x2
     field public static final int AMBIGUOUS = 1; // 0x1
     field public static final int BREAK_AFTER = 4; // 0x4
@@ -414,8 +416,8 @@ package android.icu.lang {
     field public static final int SPACE = 26; // 0x1a
     field public static final int SURROGATE = 25; // 0x19
     field public static final int UNKNOWN = 0; // 0x0
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final int VIRAMA = 47; // 0x2f
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final int VIRAMA_FINAL = 46; // 0x2e
+    field public static final int VIRAMA = 47; // 0x2f
+    field public static final int VIRAMA_FINAL = 46; // 0x2e
     field public static final int WORD_JOINER = 30; // 0x1e
     field public static final int ZWJ = 42; // 0x2a
     field public static final int ZWSPACE = 28; // 0x1c
@@ -572,8 +574,8 @@ package android.icu.lang {
     field public static final int CJK_UNIFIED_IDEOGRAPHS_EXTENSION_G_ID = 302; // 0x12e
     field public static final android.icu.lang.UCharacter.UnicodeBlock CJK_UNIFIED_IDEOGRAPHS_EXTENSION_H;
     field public static final int CJK_UNIFIED_IDEOGRAPHS_EXTENSION_H_ID = 322; // 0x142
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.lang.UCharacter.UnicodeBlock CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final int CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I_ID = 328; // 0x148
+    field public static final android.icu.lang.UCharacter.UnicodeBlock CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I;
+    field public static final int CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I_ID = 328; // 0x148
     field public static final int CJK_UNIFIED_IDEOGRAPHS_ID = 71; // 0x47
     field public static final android.icu.lang.UCharacter.UnicodeBlock COMBINING_DIACRITICAL_MARKS;
     field public static final android.icu.lang.UCharacter.UnicodeBlock COMBINING_DIACRITICAL_MARKS_EXTENDED;
@@ -640,6 +642,8 @@ package android.icu.lang {
     field public static final android.icu.lang.UCharacter.UnicodeBlock EARLY_DYNASTIC_CUNEIFORM;
     field public static final int EARLY_DYNASTIC_CUNEIFORM_ID = 257; // 0x101
     field public static final android.icu.lang.UCharacter.UnicodeBlock EGYPTIAN_HIEROGLYPHS;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.lang.UCharacter.UnicodeBlock EGYPTIAN_HIEROGLYPHS_EXTENDED_A;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int EGYPTIAN_HIEROGLYPHS_EXTENDED_A_ID = 329; // 0x149
     field public static final int EGYPTIAN_HIEROGLYPHS_ID = 194; // 0xc2
     field public static final android.icu.lang.UCharacter.UnicodeBlock EGYPTIAN_HIEROGLYPH_FORMAT_CONTROLS;
     field public static final int EGYPTIAN_HIEROGLYPH_FORMAT_CONTROLS_ID = 292; // 0x124
@@ -667,6 +671,8 @@ package android.icu.lang {
     field public static final int ETHIOPIC_ID = 31; // 0x1f
     field public static final android.icu.lang.UCharacter.UnicodeBlock ETHIOPIC_SUPPLEMENT;
     field public static final int ETHIOPIC_SUPPLEMENT_ID = 134; // 0x86
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.lang.UCharacter.UnicodeBlock GARAY;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int GARAY_ID = 330; // 0x14a
     field public static final android.icu.lang.UCharacter.UnicodeBlock GENERAL_PUNCTUATION;
     field public static final int GENERAL_PUNCTUATION_ID = 40; // 0x28
     field public static final android.icu.lang.UCharacter.UnicodeBlock GEOMETRIC_SHAPES;
@@ -697,6 +703,8 @@ package android.icu.lang {
     field public static final int GUNJALA_GONDI_ID = 284; // 0x11c
     field public static final android.icu.lang.UCharacter.UnicodeBlock GURMUKHI;
     field public static final int GURMUKHI_ID = 17; // 0x11
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.lang.UCharacter.UnicodeBlock GURUNG_KHEMA;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int GURUNG_KHEMA_ID = 331; // 0x14b
     field public static final android.icu.lang.UCharacter.UnicodeBlock HALFWIDTH_AND_FULLWIDTH_FORMS;
     field public static final int HALFWIDTH_AND_FULLWIDTH_FORMS_ID = 87; // 0x57
     field public static final android.icu.lang.UCharacter.UnicodeBlock HANGUL_COMPATIBILITY_JAMO;
@@ -777,6 +785,8 @@ package android.icu.lang {
     field public static final int KHOJKI_ID = 229; // 0xe5
     field public static final android.icu.lang.UCharacter.UnicodeBlock KHUDAWADI;
     field public static final int KHUDAWADI_ID = 230; // 0xe6
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.lang.UCharacter.UnicodeBlock KIRAT_RAI;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int KIRAT_RAI_ID = 332; // 0x14c
     field public static final android.icu.lang.UCharacter.UnicodeBlock LAO;
     field public static final int LAO_ID = 26; // 0x1a
     field public static final android.icu.lang.UCharacter.UnicodeBlock LATIN_1_SUPPLEMENT;
@@ -886,6 +896,8 @@ package android.icu.lang {
     field public static final int MYANMAR_EXTENDED_A_ID = 182; // 0xb6
     field public static final android.icu.lang.UCharacter.UnicodeBlock MYANMAR_EXTENDED_B;
     field public static final int MYANMAR_EXTENDED_B_ID = 238; // 0xee
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.lang.UCharacter.UnicodeBlock MYANMAR_EXTENDED_C;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int MYANMAR_EXTENDED_C_ID = 333; // 0x14d
     field public static final int MYANMAR_ID = 28; // 0x1c
     field public static final android.icu.lang.UCharacter.UnicodeBlock NABATAEAN;
     field public static final int NABATAEAN_ID = 239; // 0xef
@@ -928,6 +940,8 @@ package android.icu.lang {
     field public static final int OLD_UYGHUR_ID = 315; // 0x13b
     field public static final android.icu.lang.UCharacter.UnicodeBlock OL_CHIKI;
     field public static final int OL_CHIKI_ID = 157; // 0x9d
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.lang.UCharacter.UnicodeBlock OL_ONAL;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int OL_ONAL_ID = 334; // 0x14e
     field public static final android.icu.lang.UCharacter.UnicodeBlock OPTICAL_CHARACTER_RECOGNITION;
     field public static final int OPTICAL_CHARACTER_RECOGNITION_ID = 50; // 0x32
     field public static final android.icu.lang.UCharacter.UnicodeBlock ORIYA;
@@ -1004,6 +1018,8 @@ package android.icu.lang {
     field public static final int SUNDANESE_ID = 155; // 0x9b
     field public static final android.icu.lang.UCharacter.UnicodeBlock SUNDANESE_SUPPLEMENT;
     field public static final int SUNDANESE_SUPPLEMENT_ID = 219; // 0xdb
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.lang.UCharacter.UnicodeBlock SUNUWAR;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int SUNUWAR_ID = 335; // 0x14f
     field public static final android.icu.lang.UCharacter.UnicodeBlock SUPERSCRIPTS_AND_SUBSCRIPTS;
     field public static final int SUPERSCRIPTS_AND_SUBSCRIPTS_ID = 41; // 0x29
     field public static final android.icu.lang.UCharacter.UnicodeBlock SUPPLEMENTAL_ARROWS_A;
@@ -1030,6 +1046,8 @@ package android.icu.lang {
     field public static final int SYMBOLS_AND_PICTOGRAPHS_EXTENDED_A_ID = 298; // 0x12a
     field public static final android.icu.lang.UCharacter.UnicodeBlock SYMBOLS_FOR_LEGACY_COMPUTING;
     field public static final int SYMBOLS_FOR_LEGACY_COMPUTING_ID = 306; // 0x132
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.lang.UCharacter.UnicodeBlock SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT_ID = 336; // 0x150
     field public static final android.icu.lang.UCharacter.UnicodeBlock SYRIAC;
     field public static final int SYRIAC_ID = 13; // 0xd
     field public static final android.icu.lang.UCharacter.UnicodeBlock SYRIAC_SUPPLEMENT;
@@ -1074,10 +1092,14 @@ package android.icu.lang {
     field public static final int TIFINAGH_ID = 144; // 0x90
     field public static final android.icu.lang.UCharacter.UnicodeBlock TIRHUTA;
     field public static final int TIRHUTA_ID = 251; // 0xfb
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.lang.UCharacter.UnicodeBlock TODHRI;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int TODHRI_ID = 337; // 0x151
     field public static final android.icu.lang.UCharacter.UnicodeBlock TOTO;
     field public static final int TOTO_ID = 317; // 0x13d
     field public static final android.icu.lang.UCharacter.UnicodeBlock TRANSPORT_AND_MAP_SYMBOLS;
     field public static final int TRANSPORT_AND_MAP_SYMBOLS_ID = 207; // 0xcf
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.lang.UCharacter.UnicodeBlock TULU_TIGALARI;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int TULU_TIGALARI_ID = 338; // 0x152
     field public static final android.icu.lang.UCharacter.UnicodeBlock UGARITIC;
     field public static final int UGARITIC_ID = 120; // 0x78
     field public static final android.icu.lang.UCharacter.UnicodeBlock UNIFIED_CANADIAN_ABORIGINAL_SYLLABICS;
@@ -1294,6 +1316,9 @@ package android.icu.lang {
     field public static final int IDEOGRAPHIC = 17; // 0x11
     field public static final int IDS_BINARY_OPERATOR = 18; // 0x12
     field public static final int IDS_TRINARY_OPERATOR = 19; // 0x13
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int IDS_UNARY_OPERATOR = 72; // 0x48
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int ID_COMPAT_MATH_CONTINUE = 74; // 0x4a
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int ID_COMPAT_MATH_START = 73; // 0x49
     field public static final int ID_CONTINUE = 15; // 0xf
     field public static final int ID_START = 16; // 0x10
     field public static final int INDIC_POSITIONAL_CATEGORY = 4118; // 0x1016
@@ -1388,6 +1413,7 @@ package android.icu.lang {
     field public static final int AHOM = 161; // 0xa1
     field public static final int ANATOLIAN_HIEROGLYPHS = 156; // 0x9c
     field public static final int ARABIC = 2; // 0x2
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int ARABIC_NASTALIQ = 200; // 0xc8
     field public static final int ARMENIAN = 3; // 0x3
     field public static final int AVESTAN = 117; // 0x75
     field public static final int BALINESE = 62; // 0x3e
@@ -1429,6 +1455,7 @@ package android.icu.lang {
     field public static final int ELYMAIC = 185; // 0xb9
     field public static final int ESTRANGELO_SYRIAC = 95; // 0x5f
     field public static final int ETHIOPIC = 11; // 0xb
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int GARAY = 201; // 0xc9
     field public static final int GEORGIAN = 12; // 0xc
     field public static final int GLAGOLITIC = 56; // 0x38
     field public static final int GOTHIC = 13; // 0xd
@@ -1437,6 +1464,7 @@ package android.icu.lang {
     field public static final int GUJARATI = 15; // 0xf
     field public static final int GUNJALA_GONDI = 179; // 0xb3
     field public static final int GURMUKHI = 16; // 0x10
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int GURUNG_KHEMA = 202; // 0xca
     field public static final int HAN = 17; // 0x11
     field public static final int HANGUL = 18; // 0x12
     field public static final int HANIFI_ROHINGYA = 182; // 0xb6
@@ -1468,6 +1496,7 @@ package android.icu.lang {
     field public static final int KHOJKI = 157; // 0x9d
     field public static final int KHUDAWADI = 145; // 0x91
     field public static final int KHUTSURI = 72; // 0x48
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int KIRAT_RAI = 203; // 0xcb
     field public static final int KOREAN = 119; // 0x77
     field public static final int KPELLE = 138; // 0x8a
     field public static final int LANNA = 106; // 0x6a
@@ -1526,6 +1555,7 @@ package android.icu.lang {
     field public static final int OLD_SOUTH_ARABIAN = 133; // 0x85
     field public static final int OLD_UYGHUR = 194; // 0xc2
     field public static final int OL_CHIKI = 109; // 0x6d
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int OL_ONAL = 204; // 0xcc
     field public static final int ORIYA = 31; // 0x1f
     field public static final int ORKHON = 88; // 0x58
     field public static final int OSAGE = 171; // 0xab
@@ -1554,6 +1584,7 @@ package android.icu.lang {
     field public static final int SORA_SOMPENG = 152; // 0x98
     field public static final int SOYOMBO = 176; // 0xb0
     field public static final int SUNDANESE = 113; // 0x71
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int SUNUWAR = 205; // 0xcd
     field public static final int SYLOTI_NAGRI = 58; // 0x3a
     field public static final int SYMBOLS = 129; // 0x81
     field public static final int SYMBOLS_EMOJI = 174; // 0xae
@@ -1573,8 +1604,10 @@ package android.icu.lang {
     field public static final int TIBETAN = 39; // 0x27
     field public static final int TIFINAGH = 60; // 0x3c
     field public static final int TIRHUTA = 158; // 0x9e
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int TODHRI = 206; // 0xce
     field public static final int TOTO = 196; // 0xc4
     field public static final int TRADITIONAL_HAN = 74; // 0x4a
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int TULU_TIGALARI = 207; // 0xcf
     field public static final int UCAS = 40; // 0x28
     field public static final int UGARITIC = 53; // 0x35
     field public static final int UNKNOWN = 103; // 0x67
@@ -1716,7 +1749,7 @@ package android.icu.number {
   public class FormattedNumber implements android.icu.text.FormattedValue {
     method public <A extends java.lang.Appendable> A appendTo(A);
     method public char charAt(int);
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.NounClass getNounClass();
+    method public android.icu.text.DisplayOptions.NounClass getNounClass();
     method public android.icu.util.MeasureUnit getOutputUnit();
     method public int length();
     method public boolean nextPosition(android.icu.text.ConstrainedFieldPosition);
@@ -1756,12 +1789,14 @@ package android.icu.number {
     method public android.icu.number.FormattedNumber format(Number);
     method public android.icu.number.FormattedNumber format(android.icu.util.Measure);
     method public java.text.Format toFormat();
+    method @FlaggedApi("com.android.icu.icu_25q2_api") public android.icu.number.UnlocalizedNumberFormatter withoutLocale();
   }
 
   public class LocalizedNumberRangeFormatter extends android.icu.number.NumberRangeFormatterSettings<android.icu.number.LocalizedNumberRangeFormatter> {
     method public android.icu.number.FormattedNumberRange formatRange(int, int);
     method public android.icu.number.FormattedNumberRange formatRange(double, double);
     method public android.icu.number.FormattedNumberRange formatRange(Number, Number);
+    method @FlaggedApi("com.android.icu.icu_25q2_api") public android.icu.number.UnlocalizedNumberRangeFormatter withoutLocale();
   }
 
   public class Notation {
@@ -1825,7 +1860,7 @@ package android.icu.number {
 
   public abstract class NumberFormatterSettings<T extends android.icu.number.NumberFormatterSettings<?>> {
     method public T decimal(android.icu.number.NumberFormatter.DecimalSeparatorDisplay);
-    method @FlaggedApi("com.android.icu.icu_v_api") public T displayOptions(android.icu.text.DisplayOptions);
+    method public T displayOptions(android.icu.text.DisplayOptions);
     method public T grouping(android.icu.number.NumberFormatter.GroupingStrategy);
     method public T integerWidth(android.icu.number.IntegerWidth);
     method public T notation(android.icu.number.Notation);
@@ -2625,7 +2660,7 @@ package android.icu.text {
     method public String getBestPattern(String);
     method public String getBestPattern(String, int);
     method public String getDateTimeFormat();
-    method @FlaggedApi("com.android.icu.icu_v_api") public String getDateTimeFormat(int);
+    method public String getDateTimeFormat(int);
     method public String getDecimal();
     method public android.icu.text.DateFormat.HourCycle getDefaultHourCycle();
     method public static android.icu.text.DateTimePatternGenerator getEmptyInstance();
@@ -2641,7 +2676,7 @@ package android.icu.text {
     method public void setAppendItemFormat(int, String);
     method public void setAppendItemName(int, String);
     method public void setDateTimeFormat(String);
-    method @FlaggedApi("com.android.icu.icu_v_api") public void setDateTimeFormat(int, String);
+    method public void setDateTimeFormat(int, String);
     method public void setDecimal(String);
     field public static final int DAY = 7; // 0x7
     field public static final int DAYPERIOD = 10; // 0xa
@@ -2867,106 +2902,106 @@ package android.icu.text {
     enum_constant public static final android.icu.text.DisplayContext.Type SUBSTITUTE_HANDLING;
   }
 
-  @FlaggedApi("com.android.icu.icu_v_api") public final class DisplayOptions {
-    method @FlaggedApi("com.android.icu.icu_v_api") public static android.icu.text.DisplayOptions.Builder builder();
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.Builder copyToBuilder();
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.Capitalization getCapitalization();
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.DisplayLength getDisplayLength();
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.GrammaticalCase getGrammaticalCase();
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.NameStyle getNameStyle();
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.NounClass getNounClass();
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.PluralCategory getPluralCategory();
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.SubstituteHandling getSubstituteHandling();
-  }
-
-  @FlaggedApi("com.android.icu.icu_v_api") public static class DisplayOptions.Builder {
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions build();
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.Builder setCapitalization(android.icu.text.DisplayOptions.Capitalization);
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.Builder setDisplayLength(android.icu.text.DisplayOptions.DisplayLength);
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.Builder setGrammaticalCase(android.icu.text.DisplayOptions.GrammaticalCase);
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.Builder setNameStyle(android.icu.text.DisplayOptions.NameStyle);
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.Builder setNounClass(android.icu.text.DisplayOptions.NounClass);
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.Builder setPluralCategory(android.icu.text.DisplayOptions.PluralCategory);
-    method @FlaggedApi("com.android.icu.icu_v_api") public android.icu.text.DisplayOptions.Builder setSubstituteHandling(android.icu.text.DisplayOptions.SubstituteHandling);
-  }
-
-  @FlaggedApi("com.android.icu.icu_v_api") public enum DisplayOptions.Capitalization {
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.Capitalization BEGINNING_OF_SENTENCE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.Capitalization MIDDLE_OF_SENTENCE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.Capitalization STANDALONE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.Capitalization UI_LIST_OR_MENU;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.Capitalization UNDEFINED;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final java.util.List<android.icu.text.DisplayOptions.Capitalization> VALUES;
-  }
-
-  @FlaggedApi("com.android.icu.icu_v_api") public enum DisplayOptions.DisplayLength {
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.DisplayLength LENGTH_FULL;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.DisplayLength LENGTH_SHORT;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.DisplayLength UNDEFINED;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final java.util.List<android.icu.text.DisplayOptions.DisplayLength> VALUES;
-  }
-
-  @FlaggedApi("com.android.icu.icu_v_api") public enum DisplayOptions.GrammaticalCase {
-    method @FlaggedApi("com.android.icu.icu_v_api") public static android.icu.text.DisplayOptions.GrammaticalCase fromIdentifier(String);
-    method @FlaggedApi("com.android.icu.icu_v_api") public String getIdentifier();
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase ABLATIVE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase ACCUSATIVE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase COMITATIVE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase DATIVE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase ERGATIVE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase GENITIVE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase INSTRUMENTAL;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase LOCATIVE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase LOCATIVE_COPULATIVE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase NOMINATIVE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase OBLIQUE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase PREPOSITIONAL;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase SOCIATIVE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase UNDEFINED;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.GrammaticalCase VOCATIVE;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final java.util.List<android.icu.text.DisplayOptions.GrammaticalCase> VALUES;
-  }
-
-  @FlaggedApi("com.android.icu.icu_v_api") public enum DisplayOptions.NameStyle {
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NameStyle DIALECT_NAMES;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NameStyle STANDARD_NAMES;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NameStyle UNDEFINED;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final java.util.List<android.icu.text.DisplayOptions.NameStyle> VALUES;
-  }
-
-  @FlaggedApi("com.android.icu.icu_v_api") public enum DisplayOptions.NounClass {
-    method @FlaggedApi("com.android.icu.icu_v_api") public static android.icu.text.DisplayOptions.NounClass fromIdentifier(String);
-    method @FlaggedApi("com.android.icu.icu_v_api") public String getIdentifier();
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NounClass ANIMATE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NounClass COMMON;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NounClass FEMININE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NounClass INANIMATE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NounClass MASCULINE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NounClass NEUTER;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NounClass OTHER;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NounClass PERSONAL;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.NounClass UNDEFINED;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final java.util.List<android.icu.text.DisplayOptions.NounClass> VALUES;
-  }
-
-  @FlaggedApi("com.android.icu.icu_v_api") public enum DisplayOptions.PluralCategory {
-    method @FlaggedApi("com.android.icu.icu_v_api") public static android.icu.text.DisplayOptions.PluralCategory fromIdentifier(String);
-    method @FlaggedApi("com.android.icu.icu_v_api") public String getIdentifier();
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.PluralCategory FEW;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.PluralCategory MANY;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.PluralCategory ONE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.PluralCategory OTHER;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.PluralCategory TWO;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.PluralCategory UNDEFINED;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.PluralCategory ZERO;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final java.util.List<android.icu.text.DisplayOptions.PluralCategory> VALUES;
-  }
-
-  @FlaggedApi("com.android.icu.icu_v_api") public enum DisplayOptions.SubstituteHandling {
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.SubstituteHandling NO_SUBSTITUTE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.SubstituteHandling SUBSTITUTE;
-    enum_constant @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.DisplayOptions.SubstituteHandling UNDEFINED;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final java.util.List<android.icu.text.DisplayOptions.SubstituteHandling> VALUES;
+  public final class DisplayOptions {
+    method public static android.icu.text.DisplayOptions.Builder builder();
+    method public android.icu.text.DisplayOptions.Builder copyToBuilder();
+    method public android.icu.text.DisplayOptions.Capitalization getCapitalization();
+    method public android.icu.text.DisplayOptions.DisplayLength getDisplayLength();
+    method public android.icu.text.DisplayOptions.GrammaticalCase getGrammaticalCase();
+    method public android.icu.text.DisplayOptions.NameStyle getNameStyle();
+    method public android.icu.text.DisplayOptions.NounClass getNounClass();
+    method public android.icu.text.DisplayOptions.PluralCategory getPluralCategory();
+    method public android.icu.text.DisplayOptions.SubstituteHandling getSubstituteHandling();
+  }
+
+  public static class DisplayOptions.Builder {
+    method public android.icu.text.DisplayOptions build();
+    method public android.icu.text.DisplayOptions.Builder setCapitalization(android.icu.text.DisplayOptions.Capitalization);
+    method public android.icu.text.DisplayOptions.Builder setDisplayLength(android.icu.text.DisplayOptions.DisplayLength);
+    method public android.icu.text.DisplayOptions.Builder setGrammaticalCase(android.icu.text.DisplayOptions.GrammaticalCase);
+    method public android.icu.text.DisplayOptions.Builder setNameStyle(android.icu.text.DisplayOptions.NameStyle);
+    method public android.icu.text.DisplayOptions.Builder setNounClass(android.icu.text.DisplayOptions.NounClass);
+    method public android.icu.text.DisplayOptions.Builder setPluralCategory(android.icu.text.DisplayOptions.PluralCategory);
+    method public android.icu.text.DisplayOptions.Builder setSubstituteHandling(android.icu.text.DisplayOptions.SubstituteHandling);
+  }
+
+  public enum DisplayOptions.Capitalization {
+    enum_constant public static final android.icu.text.DisplayOptions.Capitalization BEGINNING_OF_SENTENCE;
+    enum_constant public static final android.icu.text.DisplayOptions.Capitalization MIDDLE_OF_SENTENCE;
+    enum_constant public static final android.icu.text.DisplayOptions.Capitalization STANDALONE;
+    enum_constant public static final android.icu.text.DisplayOptions.Capitalization UI_LIST_OR_MENU;
+    enum_constant public static final android.icu.text.DisplayOptions.Capitalization UNDEFINED;
+    field public static final java.util.List<android.icu.text.DisplayOptions.Capitalization> VALUES;
+  }
+
+  public enum DisplayOptions.DisplayLength {
+    enum_constant public static final android.icu.text.DisplayOptions.DisplayLength LENGTH_FULL;
+    enum_constant public static final android.icu.text.DisplayOptions.DisplayLength LENGTH_SHORT;
+    enum_constant public static final android.icu.text.DisplayOptions.DisplayLength UNDEFINED;
+    field public static final java.util.List<android.icu.text.DisplayOptions.DisplayLength> VALUES;
+  }
+
+  public enum DisplayOptions.GrammaticalCase {
+    method public static android.icu.text.DisplayOptions.GrammaticalCase fromIdentifier(String);
+    method public String getIdentifier();
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase ABLATIVE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase ACCUSATIVE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase COMITATIVE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase DATIVE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase ERGATIVE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase GENITIVE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase INSTRUMENTAL;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase LOCATIVE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase LOCATIVE_COPULATIVE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase NOMINATIVE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase OBLIQUE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase PREPOSITIONAL;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase SOCIATIVE;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase UNDEFINED;
+    enum_constant public static final android.icu.text.DisplayOptions.GrammaticalCase VOCATIVE;
+    field public static final java.util.List<android.icu.text.DisplayOptions.GrammaticalCase> VALUES;
+  }
+
+  public enum DisplayOptions.NameStyle {
+    enum_constant public static final android.icu.text.DisplayOptions.NameStyle DIALECT_NAMES;
+    enum_constant public static final android.icu.text.DisplayOptions.NameStyle STANDARD_NAMES;
+    enum_constant public static final android.icu.text.DisplayOptions.NameStyle UNDEFINED;
+    field public static final java.util.List<android.icu.text.DisplayOptions.NameStyle> VALUES;
+  }
+
+  public enum DisplayOptions.NounClass {
+    method public static android.icu.text.DisplayOptions.NounClass fromIdentifier(String);
+    method public String getIdentifier();
+    enum_constant public static final android.icu.text.DisplayOptions.NounClass ANIMATE;
+    enum_constant public static final android.icu.text.DisplayOptions.NounClass COMMON;
+    enum_constant public static final android.icu.text.DisplayOptions.NounClass FEMININE;
+    enum_constant public static final android.icu.text.DisplayOptions.NounClass INANIMATE;
+    enum_constant public static final android.icu.text.DisplayOptions.NounClass MASCULINE;
+    enum_constant public static final android.icu.text.DisplayOptions.NounClass NEUTER;
+    enum_constant public static final android.icu.text.DisplayOptions.NounClass OTHER;
+    enum_constant public static final android.icu.text.DisplayOptions.NounClass PERSONAL;
+    enum_constant public static final android.icu.text.DisplayOptions.NounClass UNDEFINED;
+    field public static final java.util.List<android.icu.text.DisplayOptions.NounClass> VALUES;
+  }
+
+  public enum DisplayOptions.PluralCategory {
+    method public static android.icu.text.DisplayOptions.PluralCategory fromIdentifier(String);
+    method public String getIdentifier();
+    enum_constant public static final android.icu.text.DisplayOptions.PluralCategory FEW;
+    enum_constant public static final android.icu.text.DisplayOptions.PluralCategory MANY;
+    enum_constant public static final android.icu.text.DisplayOptions.PluralCategory ONE;
+    enum_constant public static final android.icu.text.DisplayOptions.PluralCategory OTHER;
+    enum_constant public static final android.icu.text.DisplayOptions.PluralCategory TWO;
+    enum_constant public static final android.icu.text.DisplayOptions.PluralCategory UNDEFINED;
+    enum_constant public static final android.icu.text.DisplayOptions.PluralCategory ZERO;
+    field public static final java.util.List<android.icu.text.DisplayOptions.PluralCategory> VALUES;
+  }
+
+  public enum DisplayOptions.SubstituteHandling {
+    enum_constant public static final android.icu.text.DisplayOptions.SubstituteHandling NO_SUBSTITUTE;
+    enum_constant public static final android.icu.text.DisplayOptions.SubstituteHandling SUBSTITUTE;
+    enum_constant public static final android.icu.text.DisplayOptions.SubstituteHandling UNDEFINED;
+    field public static final java.util.List<android.icu.text.DisplayOptions.SubstituteHandling> VALUES;
   }
 
   public final class Edits {
@@ -3291,6 +3326,7 @@ package android.icu.text {
     method public static android.icu.text.Normalizer2 getNFDInstance();
     method public static android.icu.text.Normalizer2 getNFKCCasefoldInstance();
     method public static android.icu.text.Normalizer2 getNFKCInstance();
+    method @FlaggedApi("com.android.icu.icu_25q2_api") public static android.icu.text.Normalizer2 getNFKCSimpleCasefoldInstance();
     method public static android.icu.text.Normalizer2 getNFKDInstance();
     method public String getRawDecomposition(int);
     method public abstract boolean hasBoundaryAfter(int);
@@ -3390,7 +3426,7 @@ package android.icu.text {
 
   public static class NumberFormat.Field extends java.text.Format.Field {
     ctor protected NumberFormat.Field(String);
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.text.NumberFormat.Field APPROXIMATELY_SIGN;
+    field public static final android.icu.text.NumberFormat.Field APPROXIMATELY_SIGN;
     field public static final android.icu.text.NumberFormat.Field COMPACT;
     field public static final android.icu.text.NumberFormat.Field CURRENCY;
     field public static final android.icu.text.NumberFormat.Field DECIMAL_SEPARATOR;
@@ -4040,6 +4076,7 @@ package android.icu.text {
     field public static final int IGNORE_SPACE = 1; // 0x1
     field public static final int MAX_VALUE = 1114111; // 0x10ffff
     field public static final int MIN_VALUE = 0; // 0x0
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int SIMPLE_CASE_INSENSITIVE = 6; // 0x6
   }
 
   public enum UnicodeSet.ComparisonStyle {
@@ -4175,6 +4212,7 @@ package android.icu.util {
     method public int getRepeatedWallTimeOption();
     method public int getSkippedWallTimeOption();
     method protected final int getStamp(int);
+    method @FlaggedApi("com.android.icu.icu_25q2_api") public String getTemporalMonthCode();
     method public final java.util.Date getTime();
     method public long getTimeInMillis();
     method public android.icu.util.TimeZone getTimeZone();
@@ -4194,6 +4232,7 @@ package android.icu.util {
     method protected abstract int handleGetLimit(int, int);
     method protected int handleGetMonthLength(int, int);
     method protected int handleGetYearLength(int);
+    method @FlaggedApi("com.android.icu.icu_25q2_api") public boolean inTemporalLeapYear();
     method protected final int internalGet(int);
     method protected final int internalGet(int, int);
     method protected final long internalGetTimeInMillis();
@@ -4223,6 +4262,7 @@ package android.icu.util {
     method public void setMinimalDaysInFirstWeek(int);
     method public void setRepeatedWallTimeOption(int);
     method public void setSkippedWallTimeOption(int);
+    method @FlaggedApi("com.android.icu.icu_25q2_api") public void setTemporalMonthCode(String);
     method public final void setTime(java.util.Date);
     method public void setTimeInMillis(long);
     method public void setTimeZone(android.icu.util.TimeZone);
@@ -4284,6 +4324,7 @@ package android.icu.util {
     field protected static final int ONE_MINUTE = 60000; // 0xea60
     field protected static final int ONE_SECOND = 1000; // 0x3e8
     field protected static final long ONE_WEEK = 604800000L; // 0x240c8400L
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final int ORDINAL_MONTH = 23; // 0x17
     field public static final int PM = 1; // 0x1
     field protected static final int RESOLVE_REMAP = 32; // 0x20
     field public static final int SATURDAY = 7; // 0x7
@@ -4657,6 +4698,7 @@ package android.icu.util {
     field public static final android.icu.util.MeasureUnit ARC_SECOND;
     field public static final android.icu.util.MeasureUnit ASTRONOMICAL_UNIT;
     field public static final android.icu.util.MeasureUnit ATMOSPHERE;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.util.MeasureUnit BEAUFORT;
     field public static final android.icu.util.MeasureUnit BIT;
     field public static final android.icu.util.MeasureUnit BUSHEL;
     field public static final android.icu.util.MeasureUnit BYTE;
@@ -4693,6 +4735,7 @@ package android.icu.util {
     field public static final android.icu.util.MeasureUnit FURLONG;
     field public static final android.icu.util.MeasureUnit GALLON;
     field public static final android.icu.util.MeasureUnit GALLON_IMPERIAL;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.util.MeasureUnit GASOLINE_ENERGY_DENSITY;
     field public static final android.icu.util.MeasureUnit GENERIC_TEMPERATURE;
     field public static final android.icu.util.MeasureUnit GIGABIT;
     field public static final android.icu.util.MeasureUnit GIGABYTE;
@@ -4782,7 +4825,7 @@ package android.icu.util {
     field public static final android.icu.util.MeasureUnit POUND;
     field public static final android.icu.util.MeasureUnit POUND_PER_SQUARE_INCH;
     field public static final android.icu.util.MeasureUnit QUART;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.util.MeasureUnit QUARTER;
+    field public static final android.icu.util.MeasureUnit QUARTER;
     field public static final android.icu.util.MeasureUnit RADIAN;
     field public static final android.icu.util.MeasureUnit REVOLUTION_ANGLE;
     field public static final android.icu.util.TimeUnit SECOND;
@@ -4799,7 +4842,7 @@ package android.icu.util {
     field public static final android.icu.util.MeasureUnit TERABIT;
     field public static final android.icu.util.MeasureUnit TERABYTE;
     field public static final android.icu.util.MeasureUnit TON;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.util.MeasureUnit TONNE;
+    field public static final android.icu.util.MeasureUnit TONNE;
     field public static final android.icu.util.MeasureUnit VOLT;
     field public static final android.icu.util.MeasureUnit WATT;
     field public static final android.icu.util.TimeUnit WEEK;
@@ -4907,6 +4950,7 @@ package android.icu.util {
     method public static android.icu.util.TimeZone getFrozenTimeZone(String);
     method public String getID();
     method public static String getIDForWindowsID(String, String);
+    method @FlaggedApi("com.android.icu.icu_25q2_api") public static String getIanaID(String);
     method public abstract int getOffset(int, int, int, int, int, int);
     method public int getOffset(long);
     method public void getOffset(long, boolean, int[]);
@@ -5156,7 +5200,8 @@ package android.icu.util {
     field public static final android.icu.util.VersionInfo UNICODE_13_0;
     field public static final android.icu.util.VersionInfo UNICODE_14_0;
     field public static final android.icu.util.VersionInfo UNICODE_15_0;
-    field @FlaggedApi("com.android.icu.icu_v_api") public static final android.icu.util.VersionInfo UNICODE_15_1;
+    field public static final android.icu.util.VersionInfo UNICODE_15_1;
+    field @FlaggedApi("com.android.icu.icu_25q2_api") public static final android.icu.util.VersionInfo UNICODE_16_0;
     field public static final android.icu.util.VersionInfo UNICODE_1_0;
     field public static final android.icu.util.VersionInfo UNICODE_1_0_1;
     field public static final android.icu.util.VersionInfo UNICODE_1_1_0;
diff --git a/android_icu4j/icu-ravenwood-policies.txt b/android_icu4j/icu-ravenwood-policies.txt
index 208b8567c..5a5ecae24 100644
--- a/android_icu4j/icu-ravenwood-policies.txt
+++ b/android_icu4j/icu-ravenwood-policies.txt
@@ -1,614 +1,4 @@
 # Ravenwood policy file to expose APIs under android.icu, (which is under src/main/java)
 # We do not expose APIs under com.android, which is under libcore_bridge.
 
-# This file is generated with the following:
-# $ jar tvf $ANDROID_BUILD_TOP/out/host/linux-x86/testcases/ravenwood-runtime/core-icu4j-for-host.ravenwood.jar | sed -ne 's!^.* !! ; \!\$!d ; y!/!.!; s!\.class$!!p' | grep '^android\.icu' | sed -e 's!^!class ! ; s!$! keepclass!'
-
-# On goog/master, or once AOSP gets ravenwood-stats-collector.sh, we can use the following command
-# instead.
-# $ $ANDROID_BUILD_TOP/frameworks/base/ravenwood/scripts/ravenwood-stats-collector.sh
-# $ sed -ne '\!\$!d ; s/ keep$/ keepclass/ ; /^class android\.icu/p' /tmp/ravenwood/ravenwood-keep-all/hoststubgen_core-icu4j-for-host_keep_all.txt
-
-# TODO(b/353573764): Switch to `package` once it's supported on aosp/main.
-
-class android.icu.impl.Assert keepclass
-class android.icu.impl.BMPSet keepclass
-class android.icu.impl.CSCharacterIterator keepclass
-class android.icu.impl.CacheBase keepclass
-class android.icu.impl.CacheValue keepclass
-class android.icu.impl.CalType keepclass
-class android.icu.impl.CalendarAstronomer keepclass
-class android.icu.impl.CalendarCache keepclass
-class android.icu.impl.CalendarUtil keepclass
-class android.icu.impl.CaseMapImpl keepclass
-class android.icu.impl.CharTrie keepclass
-class android.icu.impl.CharacterIteration keepclass
-class android.icu.impl.CharacterIteratorWrapper keepclass
-class android.icu.impl.CharacterPropertiesImpl keepclass
-class android.icu.impl.ClassLoaderUtil keepclass
-class android.icu.impl.CollectionSet keepclass
-class android.icu.impl.CurrencyData keepclass
-class android.icu.impl.DateNumberFormat keepclass
-class android.icu.impl.DayPeriodRules keepclass
-class android.icu.impl.DontCareFieldPosition keepclass
-class android.icu.impl.EmojiProps keepclass
-class android.icu.impl.EraRules keepclass
-class android.icu.impl.FormattedStringBuilder keepclass
-class android.icu.impl.FormattedValueFieldPositionIteratorImpl keepclass
-class android.icu.impl.FormattedValueStringBuilderImpl keepclass
-class android.icu.impl.Grego keepclass
-class android.icu.impl.ICUBinary keepclass
-class android.icu.impl.ICUCache keepclass
-class android.icu.impl.ICUConfig keepclass
-class android.icu.impl.ICUCurrencyDisplayInfoProvider keepclass
-class android.icu.impl.ICUCurrencyMetaInfo keepclass
-class android.icu.impl.ICUData keepclass
-class android.icu.impl.ICUDataVersion keepclass
-class android.icu.impl.ICUDebug keepclass
-class android.icu.impl.ICULangDataTables keepclass
-class android.icu.impl.ICULocaleService keepclass
-class android.icu.impl.ICUNotifier keepclass
-class android.icu.impl.ICURWLock keepclass
-class android.icu.impl.ICURegionDataTables keepclass
-class android.icu.impl.ICUResourceBundle keepclass
-class android.icu.impl.ICUResourceBundleImpl keepclass
-class android.icu.impl.ICUResourceBundleReader keepclass
-class android.icu.impl.ICUResourceTableAccess keepclass
-class android.icu.impl.ICUService keepclass
-class android.icu.impl.IDNA2003 keepclass
-class android.icu.impl.IllegalIcuArgumentException keepclass
-class android.icu.impl.IntTrie keepclass
-class android.icu.impl.IntTrieBuilder keepclass
-class android.icu.impl.InvalidFormatException keepclass
-class android.icu.impl.IterableComparator keepclass
-class android.icu.impl.JavaTimeZone keepclass
-class android.icu.impl.LocaleDisplayNamesImpl keepclass
-class android.icu.impl.LocaleFallbackData keepclass
-class android.icu.impl.LocaleIDParser keepclass
-class android.icu.impl.LocaleIDs keepclass
-class android.icu.impl.LocaleUtility keepclass
-class android.icu.impl.Norm2AllModes keepclass
-class android.icu.impl.Normalizer2Impl keepclass
-class android.icu.impl.OlsonTimeZone keepclass
-class android.icu.impl.PVecToTrieCompactHandler keepclass
-class android.icu.impl.Pair keepclass
-class android.icu.impl.PatternProps keepclass
-class android.icu.impl.PatternTokenizer keepclass
-class android.icu.impl.PluralRulesLoader keepclass
-class android.icu.impl.PropsVectors keepclass
-class android.icu.impl.Punycode keepclass
-class android.icu.impl.RBBIDataWrapper keepclass
-class android.icu.impl.Relation keepclass
-class android.icu.impl.RelativeDateFormat keepclass
-class android.icu.impl.ReplaceableUCharacterIterator keepclass
-class android.icu.impl.ResourceBundleWrapper keepclass
-class android.icu.impl.Row keepclass
-class android.icu.impl.RuleCharacterIterator keepclass
-class android.icu.impl.SimpleCache keepclass
-class android.icu.impl.SimpleFilteredSentenceBreakIterator keepclass
-class android.icu.impl.SimpleFormatterImpl keepclass
-class android.icu.impl.SoftCache keepclass
-class android.icu.impl.SortedSetRelation keepclass
-class android.icu.impl.StandardPlural keepclass
-class android.icu.impl.StaticUnicodeSets keepclass
-class android.icu.impl.StringPrepDataReader keepclass
-class android.icu.impl.StringRange keepclass
-class android.icu.impl.StringSegment keepclass
-class android.icu.impl.TZDBTimeZoneNames keepclass
-class android.icu.impl.TextTrieMap keepclass
-class android.icu.impl.TimeZoneAdapter keepclass
-class android.icu.impl.TimeZoneGenericNames keepclass
-class android.icu.impl.TimeZoneNamesFactoryImpl keepclass
-class android.icu.impl.TimeZoneNamesImpl keepclass
-class android.icu.impl.Trie keepclass
-class android.icu.impl.Trie2 keepclass
-class android.icu.impl.Trie2Writable keepclass
-class android.icu.impl.Trie2_16 keepclass
-class android.icu.impl.Trie2_32 keepclass
-class android.icu.impl.TrieBuilder keepclass
-class android.icu.impl.TrieIterator keepclass
-class android.icu.impl.UBiDiProps keepclass
-class android.icu.impl.UCaseProps keepclass
-class android.icu.impl.UCharArrayIterator keepclass
-class android.icu.impl.UCharacterIteratorWrapper keepclass
-class android.icu.impl.UCharacterName keepclass
-class android.icu.impl.UCharacterNameChoice keepclass
-class android.icu.impl.UCharacterNameReader keepclass
-class android.icu.impl.UCharacterProperty keepclass
-class android.icu.impl.UCharacterUtility keepclass
-class android.icu.impl.UPropertyAliases keepclass
-class android.icu.impl.URLHandler keepclass
-class android.icu.impl.UResource keepclass
-class android.icu.impl.USerializedSet keepclass
-class android.icu.impl.UTS46 keepclass
-class android.icu.impl.UnicodeRegex keepclass
-class android.icu.impl.UnicodeSetStringSpan keepclass
-class android.icu.impl.Utility keepclass
-class android.icu.impl.UtilityExtensions keepclass
-class android.icu.impl.ValidIdentifiers keepclass
-class android.icu.impl.ZoneMeta keepclass
-class android.icu.impl.breakiter.BurmeseBreakEngine keepclass
-class android.icu.impl.breakiter.BytesDictionaryMatcher keepclass
-class android.icu.impl.breakiter.CharsDictionaryMatcher keepclass
-class android.icu.impl.breakiter.CjkBreakEngine keepclass
-class android.icu.impl.breakiter.DictionaryBreakEngine keepclass
-class android.icu.impl.breakiter.DictionaryData keepclass
-class android.icu.impl.breakiter.DictionaryMatcher keepclass
-class android.icu.impl.breakiter.KhmerBreakEngine keepclass
-class android.icu.impl.breakiter.LSTMBreakEngine keepclass
-class android.icu.impl.breakiter.LanguageBreakEngine keepclass
-class android.icu.impl.breakiter.LaoBreakEngine keepclass
-class android.icu.impl.breakiter.MlBreakEngine keepclass
-class android.icu.impl.breakiter.ModelIndex keepclass
-class android.icu.impl.breakiter.ThaiBreakEngine keepclass
-class android.icu.impl.breakiter.UnhandledBreakEngine keepclass
-class android.icu.impl.coll.BOCSU keepclass
-class android.icu.impl.coll.Collation keepclass
-class android.icu.impl.coll.CollationBuilder keepclass
-class android.icu.impl.coll.CollationCompare keepclass
-class android.icu.impl.coll.CollationData keepclass
-class android.icu.impl.coll.CollationDataBuilder keepclass
-class android.icu.impl.coll.CollationDataReader keepclass
-class android.icu.impl.coll.CollationFCD keepclass
-class android.icu.impl.coll.CollationFastLatin keepclass
-class android.icu.impl.coll.CollationFastLatinBuilder keepclass
-class android.icu.impl.coll.CollationIterator keepclass
-class android.icu.impl.coll.CollationKeys keepclass
-class android.icu.impl.coll.CollationLoader keepclass
-class android.icu.impl.coll.CollationRoot keepclass
-class android.icu.impl.coll.CollationRootElements keepclass
-class android.icu.impl.coll.CollationRuleParser keepclass
-class android.icu.impl.coll.CollationSettings keepclass
-class android.icu.impl.coll.CollationTailoring keepclass
-class android.icu.impl.coll.CollationWeights keepclass
-class android.icu.impl.coll.ContractionsAndExpansions keepclass
-class android.icu.impl.coll.FCDIterCollationIterator keepclass
-class android.icu.impl.coll.FCDUTF16CollationIterator keepclass
-class android.icu.impl.coll.IterCollationIterator keepclass
-class android.icu.impl.coll.SharedObject keepclass
-class android.icu.impl.coll.TailoredSet keepclass
-class android.icu.impl.coll.UTF16CollationIterator keepclass
-class android.icu.impl.coll.UVector32 keepclass
-class android.icu.impl.coll.UVector64 keepclass
-class android.icu.impl.data.HolidayBundle keepclass
-class android.icu.impl.data.HolidayBundle_da keepclass
-class android.icu.impl.data.HolidayBundle_da_DK keepclass
-class android.icu.impl.data.HolidayBundle_de keepclass
-class android.icu.impl.data.HolidayBundle_de_AT keepclass
-class android.icu.impl.data.HolidayBundle_de_DE keepclass
-class android.icu.impl.data.HolidayBundle_el keepclass
-class android.icu.impl.data.HolidayBundle_el_GR keepclass
-class android.icu.impl.data.HolidayBundle_en keepclass
-class android.icu.impl.data.HolidayBundle_en_CA keepclass
-class android.icu.impl.data.HolidayBundle_en_GB keepclass
-class android.icu.impl.data.HolidayBundle_en_US keepclass
-class android.icu.impl.data.HolidayBundle_es keepclass
-class android.icu.impl.data.HolidayBundle_es_MX keepclass
-class android.icu.impl.data.HolidayBundle_fr keepclass
-class android.icu.impl.data.HolidayBundle_fr_CA keepclass
-class android.icu.impl.data.HolidayBundle_fr_FR keepclass
-class android.icu.impl.data.HolidayBundle_it keepclass
-class android.icu.impl.data.HolidayBundle_it_IT keepclass
-class android.icu.impl.data.HolidayBundle_iw keepclass
-class android.icu.impl.data.HolidayBundle_iw_IL keepclass
-class android.icu.impl.data.HolidayBundle_ja_JP keepclass
-class android.icu.impl.data.ResourceReader keepclass
-class android.icu.impl.data.TokenIterator keepclass
-class android.icu.impl.duration.BasicDurationFormat keepclass
-class android.icu.impl.duration.BasicDurationFormatter keepclass
-class android.icu.impl.duration.BasicDurationFormatterFactory keepclass
-class android.icu.impl.duration.BasicPeriodBuilderFactory keepclass
-class android.icu.impl.duration.BasicPeriodFormatter keepclass
-class android.icu.impl.duration.BasicPeriodFormatterFactory keepclass
-class android.icu.impl.duration.BasicPeriodFormatterService keepclass
-class android.icu.impl.duration.DateFormatter keepclass
-class android.icu.impl.duration.DurationFormatter keepclass
-class android.icu.impl.duration.DurationFormatterFactory keepclass
-class android.icu.impl.duration.FixedUnitBuilder keepclass
-class android.icu.impl.duration.MultiUnitBuilder keepclass
-class android.icu.impl.duration.OneOrTwoUnitBuilder keepclass
-class android.icu.impl.duration.Period keepclass
-class android.icu.impl.duration.PeriodBuilder keepclass
-class android.icu.impl.duration.PeriodBuilderFactory keepclass
-class android.icu.impl.duration.PeriodBuilderImpl keepclass
-class android.icu.impl.duration.PeriodFormatter keepclass
-class android.icu.impl.duration.PeriodFormatterFactory keepclass
-class android.icu.impl.duration.PeriodFormatterService keepclass
-class android.icu.impl.duration.SingleUnitBuilder keepclass
-class android.icu.impl.duration.TimeUnit keepclass
-class android.icu.impl.duration.TimeUnitConstants keepclass
-class android.icu.impl.duration.impl.DataRecord keepclass
-class android.icu.impl.duration.impl.PeriodFormatterData keepclass
-class android.icu.impl.duration.impl.PeriodFormatterDataService keepclass
-class android.icu.impl.duration.impl.RecordReader keepclass
-class android.icu.impl.duration.impl.RecordWriter keepclass
-class android.icu.impl.duration.impl.ResourceBasedPeriodFormatterDataService keepclass
-class android.icu.impl.duration.impl.Utils keepclass
-class android.icu.impl.duration.impl.XMLRecordReader keepclass
-class android.icu.impl.duration.impl.XMLRecordWriter keepclass
-class android.icu.impl.locale.AsciiUtil keepclass
-class android.icu.impl.locale.BaseLocale keepclass
-class android.icu.impl.locale.Extension keepclass
-class android.icu.impl.locale.InternalLocaleBuilder keepclass
-class android.icu.impl.locale.KeyTypeData keepclass
-class android.icu.impl.locale.LSR keepclass
-class android.icu.impl.locale.LanguageTag keepclass
-class android.icu.impl.locale.LikelySubtags keepclass
-class android.icu.impl.locale.LocaleDistance keepclass
-class android.icu.impl.locale.LocaleExtensions keepclass
-class android.icu.impl.locale.LocaleObjectCache keepclass
-class android.icu.impl.locale.LocaleSyntaxException keepclass
-class android.icu.impl.locale.LocaleValidityChecker keepclass
-class android.icu.impl.locale.ParseStatus keepclass
-class android.icu.impl.locale.StringTokenIterator keepclass
-class android.icu.impl.locale.UnicodeLocaleExtension keepclass
-class android.icu.impl.locale.XCldrStub keepclass
-class android.icu.impl.number.AdoptingModifierStore keepclass
-class android.icu.impl.number.AffixPatternProvider keepclass
-class android.icu.impl.number.AffixUtils keepclass
-class android.icu.impl.number.CompactData keepclass
-class android.icu.impl.number.ConstantAffixModifier keepclass
-class android.icu.impl.number.ConstantMultiFieldModifier keepclass
-class android.icu.impl.number.CurrencyPluralInfoAffixProvider keepclass
-class android.icu.impl.number.CurrencySpacingEnabledModifier keepclass
-class android.icu.impl.number.CustomSymbolCurrency keepclass
-class android.icu.impl.number.DecimalFormatProperties keepclass
-class android.icu.impl.number.DecimalQuantity keepclass
-class android.icu.impl.number.DecimalQuantity_AbstractBCD keepclass
-class android.icu.impl.number.DecimalQuantity_DualStorageBCD keepclass
-class android.icu.impl.number.Grouper keepclass
-class android.icu.impl.number.LocalizedNumberFormatterAsFormat keepclass
-class android.icu.impl.number.LongNameHandler keepclass
-class android.icu.impl.number.LongNameMultiplexer keepclass
-class android.icu.impl.number.MacroProps keepclass
-class android.icu.impl.number.MicroProps keepclass
-class android.icu.impl.number.MicroPropsGenerator keepclass
-class android.icu.impl.number.MicroPropsMutator keepclass
-class android.icu.impl.number.MixedUnitLongNameHandler keepclass
-class android.icu.impl.number.Modifier keepclass
-class android.icu.impl.number.ModifierStore keepclass
-class android.icu.impl.number.MultiplierFormatHandler keepclass
-class android.icu.impl.number.MultiplierProducer keepclass
-class android.icu.impl.number.MutablePatternModifier keepclass
-class android.icu.impl.number.Padder keepclass
-class android.icu.impl.number.PatternStringParser keepclass
-class android.icu.impl.number.PatternStringUtils keepclass
-class android.icu.impl.number.Properties keepclass
-class android.icu.impl.number.PropertiesAffixPatternProvider keepclass
-class android.icu.impl.number.RoundingUtils keepclass
-class android.icu.impl.number.SimpleModifier keepclass
-class android.icu.impl.number.UnitConversionHandler keepclass
-class android.icu.impl.number.UsagePrefsHandler keepclass
-class android.icu.impl.number.parse.AffixMatcher keepclass
-class android.icu.impl.number.parse.AffixPatternMatcher keepclass
-class android.icu.impl.number.parse.AffixTokenMatcherFactory keepclass
-class android.icu.impl.number.parse.CodePointMatcher keepclass
-class android.icu.impl.number.parse.CombinedCurrencyMatcher keepclass
-class android.icu.impl.number.parse.DecimalMatcher keepclass
-class android.icu.impl.number.parse.IgnorablesMatcher keepclass
-class android.icu.impl.number.parse.InfinityMatcher keepclass
-class android.icu.impl.number.parse.MinusSignMatcher keepclass
-class android.icu.impl.number.parse.MultiplierParseHandler keepclass
-class android.icu.impl.number.parse.NanMatcher keepclass
-class android.icu.impl.number.parse.NumberParseMatcher keepclass
-class android.icu.impl.number.parse.NumberParserImpl keepclass
-class android.icu.impl.number.parse.PaddingMatcher keepclass
-class android.icu.impl.number.parse.ParsedNumber keepclass
-class android.icu.impl.number.parse.ParsingUtils keepclass
-class android.icu.impl.number.parse.PercentMatcher keepclass
-class android.icu.impl.number.parse.PermilleMatcher keepclass
-class android.icu.impl.number.parse.PlusSignMatcher keepclass
-class android.icu.impl.number.parse.RequireAffixValidator keepclass
-class android.icu.impl.number.parse.RequireCurrencyValidator keepclass
-class android.icu.impl.number.parse.RequireDecimalSeparatorValidator keepclass
-class android.icu.impl.number.parse.RequireNumberValidator keepclass
-class android.icu.impl.number.parse.ScientificMatcher keepclass
-class android.icu.impl.number.parse.SeriesMatcher keepclass
-class android.icu.impl.number.parse.SymbolMatcher keepclass
-class android.icu.impl.number.parse.ValidationMatcher keepclass
-class android.icu.impl.number.range.PrefixInfixSuffixLengthHelper keepclass
-class android.icu.impl.number.range.RangeMacroProps keepclass
-class android.icu.impl.number.range.StandardPluralRanges keepclass
-class android.icu.impl.personname.FieldModifierImpl keepclass
-class android.icu.impl.personname.PersonNameFormatterImpl keepclass
-class android.icu.impl.personname.PersonNamePattern keepclass
-class android.icu.impl.text.RbnfScannerProviderImpl keepclass
-class android.icu.impl.units.ComplexUnitsConverter keepclass
-class android.icu.impl.units.ConversionRates keepclass
-class android.icu.impl.units.MeasureUnitImpl keepclass
-class android.icu.impl.units.SingleUnitImpl keepclass
-class android.icu.impl.units.UnitPreferences keepclass
-class android.icu.impl.units.UnitsConverter keepclass
-class android.icu.impl.units.UnitsData keepclass
-class android.icu.impl.units.UnitsRouter keepclass
-class android.icu.lang.CharSequences keepclass
-class android.icu.lang.CharacterProperties keepclass
-class android.icu.lang.UCharacter keepclass
-class android.icu.lang.UCharacterCategory keepclass
-class android.icu.lang.UCharacterDirection keepclass
-class android.icu.lang.UCharacterEnums keepclass
-class android.icu.lang.UCharacterNameIterator keepclass
-class android.icu.lang.UProperty keepclass
-class android.icu.lang.UScript keepclass
-class android.icu.lang.UScriptRun keepclass
-class android.icu.math.BigDecimal keepclass
-class android.icu.math.MathContext keepclass
-class android.icu.message2.DateTimeFormatterFactory keepclass
-class android.icu.message2.FormattedMessage keepclass
-class android.icu.message2.FormattedPlaceholder keepclass
-class android.icu.message2.Formatter keepclass
-class android.icu.message2.FormatterFactory keepclass
-class android.icu.message2.IdentityFormatterFactory keepclass
-class android.icu.message2.InputSource keepclass
-class android.icu.message2.MFDataModel keepclass
-class android.icu.message2.MFDataModelFormatter keepclass
-class android.icu.message2.MFDataModelValidator keepclass
-class android.icu.message2.MFFunctionRegistry keepclass
-class android.icu.message2.MFParseException keepclass
-class android.icu.message2.MFParser keepclass
-class android.icu.message2.MFSerializer keepclass
-class android.icu.message2.MessageFormatter keepclass
-class android.icu.message2.NumberFormatterFactory keepclass
-class android.icu.message2.OptUtils keepclass
-class android.icu.message2.PlainStringFormattedValue keepclass
-class android.icu.message2.Selector keepclass
-class android.icu.message2.SelectorFactory keepclass
-class android.icu.message2.StringUtils keepclass
-class android.icu.message2.StringView keepclass
-class android.icu.message2.TextSelectorFactory keepclass
-class android.icu.number.CompactNotation keepclass
-class android.icu.number.CurrencyPrecision keepclass
-class android.icu.number.FormattedNumber keepclass
-class android.icu.number.FormattedNumberRange keepclass
-class android.icu.number.FractionPrecision keepclass
-class android.icu.number.IntegerWidth keepclass
-class android.icu.number.LocalizedNumberFormatter keepclass
-class android.icu.number.LocalizedNumberRangeFormatter keepclass
-class android.icu.number.Notation keepclass
-class android.icu.number.NumberFormatter keepclass
-class android.icu.number.NumberFormatterImpl keepclass
-class android.icu.number.NumberFormatterSettings keepclass
-class android.icu.number.NumberPropertyMapper keepclass
-class android.icu.number.NumberRangeFormatter keepclass
-class android.icu.number.NumberRangeFormatterImpl keepclass
-class android.icu.number.NumberRangeFormatterSettings keepclass
-class android.icu.number.NumberSkeletonImpl keepclass
-class android.icu.number.Precision keepclass
-class android.icu.number.Scale keepclass
-class android.icu.number.ScientificNotation keepclass
-class android.icu.number.SimpleNotation keepclass
-class android.icu.number.SkeletonSyntaxException keepclass
-class android.icu.number.UnlocalizedNumberFormatter keepclass
-class android.icu.number.UnlocalizedNumberRangeFormatter keepclass
-class android.icu.platform.AndroidDataFiles keepclass
-class android.icu.text.AbsoluteValueSubstitution keepclass
-class android.icu.text.AlphabeticIndex keepclass
-class android.icu.text.AnyTransliterator keepclass
-class android.icu.text.ArabicShaping keepclass
-class android.icu.text.ArabicShapingException keepclass
-class android.icu.text.Bidi keepclass
-class android.icu.text.BidiClassifier keepclass
-class android.icu.text.BidiLine keepclass
-class android.icu.text.BidiRun keepclass
-class android.icu.text.BidiTransform keepclass
-class android.icu.text.BidiWriter keepclass
-class android.icu.text.BreakIterator keepclass
-class android.icu.text.BreakIteratorFactory keepclass
-class android.icu.text.BreakTransliterator keepclass
-class android.icu.text.CanonicalIterator keepclass
-class android.icu.text.CaseFoldTransliterator keepclass
-class android.icu.text.CaseMap keepclass
-class android.icu.text.CharsetDetector keepclass
-class android.icu.text.CharsetMatch keepclass
-class android.icu.text.CharsetRecog_2022 keepclass
-class android.icu.text.CharsetRecog_UTF8 keepclass
-class android.icu.text.CharsetRecog_Unicode keepclass
-class android.icu.text.CharsetRecog_mbcs keepclass
-class android.icu.text.CharsetRecog_sbcs keepclass
-class android.icu.text.CharsetRecognizer keepclass
-class android.icu.text.ChineseDateFormat keepclass
-class android.icu.text.ChineseDateFormatSymbols keepclass
-class android.icu.text.CollationElementIterator keepclass
-class android.icu.text.CollationKey keepclass
-class android.icu.text.Collator keepclass
-class android.icu.text.CollatorServiceShim keepclass
-class android.icu.text.CompactDecimalFormat keepclass
-class android.icu.text.ComposedCharIter keepclass
-class android.icu.text.CompoundTransliterator keepclass
-class android.icu.text.ConstrainedFieldPosition keepclass
-class android.icu.text.CurrencyDisplayNames keepclass
-class android.icu.text.CurrencyFormat keepclass
-class android.icu.text.CurrencyMetaInfo keepclass
-class android.icu.text.CurrencyPluralInfo keepclass
-class android.icu.text.DateFormat keepclass
-class android.icu.text.DateFormatSymbols keepclass
-class android.icu.text.DateIntervalFormat keepclass
-class android.icu.text.DateIntervalInfo keepclass
-class android.icu.text.DateTimePatternGenerator keepclass
-class android.icu.text.DecimalFormat keepclass
-class android.icu.text.DecimalFormatSymbols keepclass
-class android.icu.text.DisplayContext keepclass
-class android.icu.text.DisplayOptions keepclass
-class android.icu.text.DurationFormat keepclass
-class android.icu.text.Edits keepclass
-class android.icu.text.EscapeTransliterator keepclass
-class android.icu.text.FilteredBreakIteratorBuilder keepclass
-class android.icu.text.FilteredNormalizer2 keepclass
-class android.icu.text.FormattedValue keepclass
-class android.icu.text.FractionalPartSubstitution keepclass
-class android.icu.text.FunctionReplacer keepclass
-class android.icu.text.IDNA keepclass
-class android.icu.text.IntegralPartSubstitution keepclass
-class android.icu.text.ListFormatter keepclass
-class android.icu.text.LocaleDisplayNames keepclass
-class android.icu.text.LowercaseTransliterator keepclass
-class android.icu.text.MeasureFormat keepclass
-class android.icu.text.MessageFormat keepclass
-class android.icu.text.MessagePattern keepclass
-class android.icu.text.MessagePatternUtil keepclass
-class android.icu.text.ModulusSubstitution keepclass
-class android.icu.text.MultiplierSubstitution keepclass
-class android.icu.text.NFRule keepclass
-class android.icu.text.NFRuleSet keepclass
-class android.icu.text.NFSubstitution keepclass
-class android.icu.text.NameUnicodeTransliterator keepclass
-class android.icu.text.NormalizationTransliterator keepclass
-class android.icu.text.Normalizer keepclass
-class android.icu.text.Normalizer2 keepclass
-class android.icu.text.NullTransliterator keepclass
-class android.icu.text.NumberFormat keepclass
-class android.icu.text.NumberFormatServiceShim keepclass
-class android.icu.text.NumberingSystem keepclass
-class android.icu.text.NumeratorSubstitution keepclass
-class android.icu.text.PersonName keepclass
-class android.icu.text.PersonNameFormatter keepclass
-class android.icu.text.PluralFormat keepclass
-class android.icu.text.PluralRules keepclass
-class android.icu.text.PluralRulesSerialProxy keepclass
-class android.icu.text.Quantifier keepclass
-class android.icu.text.QuantityFormatter keepclass
-class android.icu.text.RBBINode keepclass
-class android.icu.text.RBBIRuleBuilder keepclass
-class android.icu.text.RBBIRuleParseTable keepclass
-class android.icu.text.RBBIRuleScanner keepclass
-class android.icu.text.RBBISetBuilder keepclass
-class android.icu.text.RBBISymbolTable keepclass
-class android.icu.text.RBBITableBuilder keepclass
-class android.icu.text.RBNFChinesePostProcessor keepclass
-class android.icu.text.RBNFPostProcessor keepclass
-class android.icu.text.RawCollationKey keepclass
-class android.icu.text.RbnfLenientScanner keepclass
-class android.icu.text.RbnfLenientScannerProvider keepclass
-class android.icu.text.RelativeDateTimeFormatter keepclass
-class android.icu.text.RemoveTransliterator keepclass
-class android.icu.text.Replaceable keepclass
-class android.icu.text.ReplaceableContextIterator keepclass
-class android.icu.text.ReplaceableString keepclass
-class android.icu.text.RuleBasedBreakIterator keepclass
-class android.icu.text.RuleBasedCollator keepclass
-class android.icu.text.RuleBasedNumberFormat keepclass
-class android.icu.text.RuleBasedTransliterator keepclass
-class android.icu.text.SCSU keepclass
-class android.icu.text.SameValueSubstitution keepclass
-class android.icu.text.ScientificNumberFormatter keepclass
-class android.icu.text.SearchIterator keepclass
-class android.icu.text.SelectFormat keepclass
-class android.icu.text.SimpleDateFormat keepclass
-class android.icu.text.SimpleFormatter keepclass
-class android.icu.text.SimplePersonName keepclass
-class android.icu.text.SourceTargetUtility keepclass
-class android.icu.text.SpoofChecker keepclass
-class android.icu.text.StringCharacterIterator keepclass
-class android.icu.text.StringMatcher keepclass
-class android.icu.text.StringPrep keepclass
-class android.icu.text.StringPrepParseException keepclass
-class android.icu.text.StringReplacer keepclass
-class android.icu.text.StringSearch keepclass
-class android.icu.text.StringTransform keepclass
-class android.icu.text.SymbolTable keepclass
-class android.icu.text.TimeUnitFormat keepclass
-class android.icu.text.TimeZoneFormat keepclass
-class android.icu.text.TimeZoneNames keepclass
-class android.icu.text.TitlecaseTransliterator keepclass
-class android.icu.text.Transform keepclass
-class android.icu.text.TransliterationRule keepclass
-class android.icu.text.TransliterationRuleSet keepclass
-class android.icu.text.Transliterator keepclass
-class android.icu.text.TransliteratorIDParser keepclass
-class android.icu.text.TransliteratorParser keepclass
-class android.icu.text.TransliteratorRegistry keepclass
-class android.icu.text.UCharacterIterator keepclass
-class android.icu.text.UFieldPosition keepclass
-class android.icu.text.UFormat keepclass
-class android.icu.text.UForwardCharacterIterator keepclass
-class android.icu.text.UTF16 keepclass
-class android.icu.text.UnescapeTransliterator keepclass
-class android.icu.text.UnicodeCompressor keepclass
-class android.icu.text.UnicodeDecompressor keepclass
-class android.icu.text.UnicodeFilter keepclass
-class android.icu.text.UnicodeMatcher keepclass
-class android.icu.text.UnicodeNameTransliterator keepclass
-class android.icu.text.UnicodeReplacer keepclass
-class android.icu.text.UnicodeSet keepclass
-class android.icu.text.UnicodeSetIterator keepclass
-class android.icu.text.UnicodeSetSpanner keepclass
-class android.icu.text.UppercaseTransliterator keepclass
-class android.icu.util.AnnualTimeZoneRule keepclass
-class android.icu.util.BasicTimeZone keepclass
-class android.icu.util.BuddhistCalendar keepclass
-class android.icu.util.ByteArrayWrapper keepclass
-class android.icu.util.BytesTrie keepclass
-class android.icu.util.BytesTrieBuilder keepclass
-class android.icu.util.CECalendar keepclass
-class android.icu.util.Calendar keepclass
-class android.icu.util.CaseInsensitiveString keepclass
-class android.icu.util.CharsTrie keepclass
-class android.icu.util.CharsTrieBuilder keepclass
-class android.icu.util.ChineseCalendar keepclass
-class android.icu.util.CodePointMap keepclass
-class android.icu.util.CodePointTrie keepclass
-class android.icu.util.CompactByteArray keepclass
-class android.icu.util.CompactCharArray keepclass
-class android.icu.util.CopticCalendar keepclass
-class android.icu.util.Currency keepclass
-class android.icu.util.CurrencyAmount keepclass
-class android.icu.util.CurrencyServiceShim keepclass
-class android.icu.util.DangiCalendar keepclass
-class android.icu.util.DateInterval keepclass
-class android.icu.util.DateRule keepclass
-class android.icu.util.DateTimeRule keepclass
-class android.icu.util.EasterHoliday keepclass
-class android.icu.util.EasterRule keepclass
-class android.icu.util.EthiopicCalendar keepclass
-class android.icu.util.Freezable keepclass
-class android.icu.util.GenderInfo keepclass
-class android.icu.util.GlobalizationPreferences keepclass
-class android.icu.util.GregorianCalendar keepclass
-class android.icu.util.HebrewCalendar keepclass
-class android.icu.util.HebrewHoliday keepclass
-class android.icu.util.Holiday keepclass
-class android.icu.util.ICUCloneNotSupportedException keepclass
-class android.icu.util.ICUException keepclass
-class android.icu.util.ICUInputTooLongException keepclass
-class android.icu.util.ICUUncheckedIOException keepclass
-class android.icu.util.IllformedLocaleException keepclass
-class android.icu.util.IndianCalendar keepclass
-class android.icu.util.InitialTimeZoneRule keepclass
-class android.icu.util.IslamicCalendar keepclass
-class android.icu.util.JapaneseCalendar keepclass
-class android.icu.util.LocaleData keepclass
-class android.icu.util.LocaleMatcher keepclass
-class android.icu.util.LocalePriorityList keepclass
-class android.icu.util.Measure keepclass
-class android.icu.util.MeasureUnit keepclass
-class android.icu.util.MutableCodePointTrie keepclass
-class android.icu.util.NoUnit keepclass
-class android.icu.util.Output keepclass
-class android.icu.util.OutputInt keepclass
-class android.icu.util.PersianCalendar keepclass
-class android.icu.util.Range keepclass
-class android.icu.util.RangeDateRule keepclass
-class android.icu.util.RangeValueIterator keepclass
-class android.icu.util.Region keepclass
-class android.icu.util.RuleBasedTimeZone keepclass
-class android.icu.util.STZInfo keepclass
-class android.icu.util.SimpleDateRule keepclass
-class android.icu.util.SimpleHoliday keepclass
-class android.icu.util.SimpleTimeZone keepclass
-class android.icu.util.StringTokenizer keepclass
-class android.icu.util.StringTrieBuilder keepclass
-class android.icu.util.TaiwanCalendar keepclass
-class android.icu.util.TimeArrayTimeZoneRule keepclass
-class android.icu.util.TimeUnit keepclass
-class android.icu.util.TimeUnitAmount keepclass
-class android.icu.util.TimeZone keepclass
-class android.icu.util.TimeZoneRule keepclass
-class android.icu.util.TimeZoneTransition keepclass
-class android.icu.util.ULocale keepclass
-class android.icu.util.UResourceBundle keepclass
-class android.icu.util.UResourceBundleIterator keepclass
-class android.icu.util.UResourceTypeMismatchException keepclass
-class android.icu.util.UniversalTimeScale keepclass
-class android.icu.util.VTimeZone keepclass
-class android.icu.util.ValueIterator keepclass
-class android.icu.util.VersionInfo keepclass
+package android.icu keepclass
diff --git a/android_icu4j/libcore_bridge/src/java/com/android/i18n/system/ZygoteHooks.java b/android_icu4j/libcore_bridge/src/java/com/android/i18n/system/ZygoteHooks.java
index 9be61a98a..d9c0c4f04 100644
--- a/android_icu4j/libcore_bridge/src/java/com/android/i18n/system/ZygoteHooks.java
+++ b/android_icu4j/libcore_bridge/src/java/com/android/i18n/system/ZygoteHooks.java
@@ -27,6 +27,7 @@ import android.icu.text.DecimalFormatSymbols;
 import android.icu.util.TimeZone;
 import android.icu.util.ULocale;
 
+import com.android.i18n.util.ATrace;
 import com.android.icu.util.UResourceBundleNative;
 
 import dalvik.annotation.compat.VersionCodes;
@@ -51,6 +52,7 @@ public final class ZygoteHooks {
      */
     @libcore.api.IntraCoreApi
     public static void onBeginPreload() {
+        ATrace.traceBegin("IcuZygoteHooksOnBeginPreload");
         // Pin ICU data in memory from this point that would normally be held by soft references.
         // Without this, any references created immediately below or during class preloading
         // would be collected when the Zygote GC runs in gcAndFinalize().
@@ -69,6 +71,7 @@ public final class ZygoteHooks {
 
         // Preload the String[] ZoneMeta#ZONEIDS. See http://b/73282298
         ZoneMeta.getAvailableIDs(TimeZone.SystemTimeZoneType.ANY, null, null);
+        ATrace.traceEnd();
     }
 
     /**
@@ -76,6 +79,7 @@ public final class ZygoteHooks {
      */
     @libcore.api.IntraCoreApi
     public static void onEndPreload() {
+        ATrace.traceBegin("IcuZygoteHooksOnEndPreload");
         // All cache references created by ICU from this point will be soft.
         CacheValue.setStrength(CacheValue.Strength.SOFT);
 
@@ -91,6 +95,7 @@ public final class ZygoteHooks {
         // Cache the timezone bundles, e.g. metaZones.res, in Zygote due to app compat.
         // http://b/339899412
         UResourceBundleNative.cacheTimeZoneBundles();
+        ATrace.traceEnd();
     }
 
     /**
diff --git a/android_icu4j/libcore_bridge/src/java/com/android/i18n/util/ATrace.java b/android_icu4j/libcore_bridge/src/java/com/android/i18n/util/ATrace.java
new file mode 100644
index 000000000..fccaa736f
--- /dev/null
+++ b/android_icu4j/libcore_bridge/src/java/com/android/i18n/util/ATrace.java
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.i18n.util;
+
+import java.util.Objects;
+
+/**
+ * Writes event into the system trace buffer, and exactly like {@link android.os.Trace}.
+ * However, ICU4J can't be compiled with the framework class due to the circular dependency.
+ * ICU has its our own java class to write the trace event via libcutils.
+ *
+ * @hide
+ */
+public class ATrace {
+
+    public static void traceBegin(String event) {
+        Objects.requireNonNull(event);
+        nativeTraceBegin(event);
+    }
+
+    public static void traceEnd() {
+        nativeTraceEnd();
+    }
+
+    private static native void nativeTraceBegin(String methodName);
+
+    private static native void nativeTraceEnd();
+
+}
diff --git a/android_icu4j/libcore_bridge/src/native/Android.bp b/android_icu4j/libcore_bridge/src/native/Android.bp
index 9dc0212e6..dfc41b9ff 100644
--- a/android_icu4j/libcore_bridge/src/native/Android.bp
+++ b/android_icu4j/libcore_bridge/src/native/Android.bp
@@ -41,6 +41,7 @@ cc_library_shared {
         "liblog",
         "libnativehelper",
     ],
+    static_libs: ["libcutils"],
     srcs: [
         "*.cpp",
     ],
diff --git a/android_icu4j/libcore_bridge/src/native/Register.cpp b/android_icu4j/libcore_bridge/src/native/Register.cpp
index 25d53f3e5..0a4bc4c2a 100644
--- a/android_icu4j/libcore_bridge/src/native/Register.cpp
+++ b/android_icu4j/libcore_bridge/src/native/Register.cpp
@@ -49,6 +49,7 @@ jint JNI_OnLoad(JavaVM* vm, void*) {
 #define REGISTER(FN) extern void FN(JNIEnv*); FN(env)
     REGISTER(register_com_android_icu_text_TimeZoneNamesNative);
     REGISTER(register_com_android_i18n_timezone_internal_Memory);
+    REGISTER(register_com_android_i18n_util_ATrace);
     REGISTER(register_com_android_i18n_util_Log);
     REGISTER(register_com_android_icu_util_CaseMapperNative);
     REGISTER(register_com_android_icu_util_Icu4cMetadata);
diff --git a/android_icu4j/libcore_bridge/src/native/com_android_i18n_util_ATrace.cpp b/android_icu4j/libcore_bridge/src/native/com_android_i18n_util_ATrace.cpp
new file mode 100644
index 000000000..ab9208f49
--- /dev/null
+++ b/android_icu4j/libcore_bridge/src/native/com_android_i18n_util_ATrace.cpp
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#define ATRACE_TAG ATRACE_TAG_DALVIK
+
+#include <cutils/trace.h>
+#include "jni.h"
+#include <nativehelper/JNIHelp.h>
+#include <nativehelper/jni_macros.h>
+#include <nativehelper/scoped_utf_chars.h>
+
+static void ATrace_nativeTraceBegin(JNIEnv* env, jclass, jstring event) {
+  ScopedUtfChars event_name(env, event);
+
+  ATRACE_BEGIN(event_name.c_str());
+}
+
+static void ATrace_nativeTraceEnd(JNIEnv* env, jclass) {
+  ATRACE_END();
+}
+
+static JNINativeMethod gMethods[] = {
+  NATIVE_METHOD(ATrace, nativeTraceBegin, "(Ljava/lang/String;)V"),
+  NATIVE_METHOD(ATrace, nativeTraceEnd, "()V"),
+};
+
+void register_com_android_i18n_util_ATrace(JNIEnv* env) {
+  jniRegisterNativeMethods(env, "com/android/i18n/util/ATrace", gMethods, NELEM(gMethods));
+}
diff --git a/android_icu4j/src/main/java/android/icu/lang/UCharacter.java b/android_icu4j/src/main/java/android/icu/lang/UCharacter.java
index b25205f12..891905c02 100644
--- a/android_icu4j/src/main/java/android/icu/lang/UCharacter.java
+++ b/android_icu4j/src/main/java/android/icu/lang/UCharacter.java
@@ -1122,9 +1122,41 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
         // New block in Unicode 15.1
 
         /***/
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final int CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I_ID = 328; /*[2EBF0]*/
 
+        // New blocks in Unicode 16.0
+
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int EGYPTIAN_HIEROGLYPHS_EXTENDED_A_ID = 329; /*[13460]*/
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int GARAY_ID = 330; /*[10D40]*/
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int GURUNG_KHEMA_ID = 331; /*[16100]*/
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int KIRAT_RAI_ID = 332; /*[16D40]*/
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int MYANMAR_EXTENDED_C_ID = 333; /*[116D0]*/
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int OL_ONAL_ID = 334; /*[1E5D0]*/
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int SUNUWAR_ID = 335; /*[11BC0]*/
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT_ID = 336; /*[1CC00]*/
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int TODHRI_ID = 337; /*[105C0]*/
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int TULU_TIGALARI_ID = 338; /*[11380]*/
+
         /**
          * One more than the highest normal UnicodeBlock value.
          * The highest value is available via UCharacter.getIntPropertyMaxValue(UProperty.BLOCK).
@@ -2393,11 +2425,50 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
         // New block in Unicode 15.1
 
         /***/
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final UnicodeBlock CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I =
                 new UnicodeBlock("CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I",
                         CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I_ID); /*[2EBF0]*/
 
+        // New blocks in Unicode 16.0
+
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final UnicodeBlock EGYPTIAN_HIEROGLYPHS_EXTENDED_A =
+                new UnicodeBlock("EGYPTIAN_HIEROGLYPHS_EXTENDED_A",
+                        EGYPTIAN_HIEROGLYPHS_EXTENDED_A_ID);
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final UnicodeBlock GARAY = new UnicodeBlock("GARAY", GARAY_ID);
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final UnicodeBlock GURUNG_KHEMA =
+                new UnicodeBlock("GURUNG_KHEMA", GURUNG_KHEMA_ID);
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final UnicodeBlock KIRAT_RAI = new UnicodeBlock("KIRAT_RAI", KIRAT_RAI_ID);
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final UnicodeBlock MYANMAR_EXTENDED_C =
+                new UnicodeBlock("MYANMAR_EXTENDED_C", MYANMAR_EXTENDED_C_ID);
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final UnicodeBlock OL_ONAL = new UnicodeBlock("OL_ONAL", OL_ONAL_ID);
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final UnicodeBlock SUNUWAR = new UnicodeBlock("SUNUWAR", SUNUWAR_ID);
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final UnicodeBlock SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT =
+                new UnicodeBlock("SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT",
+                        SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT_ID);
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final UnicodeBlock TODHRI = new UnicodeBlock("TODHRI", TODHRI_ID);
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final UnicodeBlock TULU_TIGALARI =
+                new UnicodeBlock("TULU_TIGALARI", TULU_TIGALARI_ID);
+
         /**
          */
         public static final UnicodeBlock INVALID_CODE
@@ -2520,7 +2591,11 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
         {
             super(name);
             m_id_ = id;
-            if (id >= 0) {
+            // Android-changed: Avoid leaking flagged UnicodeBlock until ICU 76 data is integrated.
+            // Without the Unicode 16.0 database, UCharacter.UnicodeBlock.forName(name) is broken if
+            // the new faked UnicodeBlock is stored in this global BLOCKS_ array, See b/320357773.
+            // if (id >= 0) {
+            if (id >= 0 && id < BLOCKS_.length) {
                 BLOCKS_[id] = this;
             }
         }
@@ -2944,6 +3019,9 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
         public static final int THIN_YEH = 102;
         /***/
         public static final int VERTICAL_TAIL = 103;
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int KASHMIRI_YEH = 104;
 
         /**
          * One more than the highest normal JoiningGroup value.
@@ -3291,19 +3369,14 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
         /***/
         public static final int ZWJ = 42;  /*[ZWJ]*/
         /***/
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final int AKSARA = 43;  /*[AK]*/ /* from here on: new in Unicode 15.1/ICU 74 */
         /***/
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final int AKSARA_PREBASE = 44;  /*[AP]*/
         /***/
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final int AKSARA_START = 45;  /*[AS]*/
         /***/
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final int VIRAMA_FINAL = 46;  /*[VF]*/
         /***/
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final int VIRAMA = 47;  /*[VI]*/
         /**
          * One more than the highest normal LineBreak value.
@@ -3528,6 +3601,9 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
         public static final int VOWEL_DEPENDENT = 34;
         /***/
         public static final int VOWEL_INDEPENDENT = 35;
+        /***/
+        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+        public static final int REORDERING_KILLER = 36;
     }
 
     /**
diff --git a/android_icu4j/src/main/java/android/icu/lang/UProperty.java b/android_icu4j/src/main/java/android/icu/lang/UProperty.java
index 001188162..1bddf7a53 100644
--- a/android_icu4j/src/main/java/android/icu/lang/UProperty.java
+++ b/android_icu4j/src/main/java/android/icu/lang/UProperty.java
@@ -531,25 +531,22 @@ public interface UProperty
     /**
      * Binary property IDS_Unary_Operator.
      * For programmatic determination of Ideographic Description Sequences.
-     *
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public static final int IDS_UNARY_OPERATOR = 72;
 
     /**
      * Binary property ID_Compat_Math_Start.
      * <p>Used in mathematical identifier profile in UAX #31.
-     *
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public static final int ID_COMPAT_MATH_START = 73;
 
     /**
      * Binary property ID_Compat_Math_Continue.
      * <p>Used in mathematical identifier profile in UAX #31.
-     *
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public static final int ID_COMPAT_MATH_CONTINUE = 74;
 
     /**
diff --git a/android_icu4j/src/main/java/android/icu/lang/UScript.java b/android_icu4j/src/main/java/android/icu/lang/UScript.java
index f4972e5f1..4510fbd7b 100644
--- a/android_icu4j/src/main/java/android/icu/lang/UScript.java
+++ b/android_icu4j/src/main/java/android/icu/lang/UScript.java
@@ -880,9 +880,33 @@ public final class UScript {
     /***/
     public static final int NAG_MUNDARI = 199; /* Nagm */
 
-    /** @hide unsupported on Android*/
+    /***/
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public static final int ARABIC_NASTALIQ = 200; /* Aran */
 
+    /***/
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+    public static final int GARAY = 201; /* Gara */
+    /***/
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+    public static final int GURUNG_KHEMA = 202; /* Gukh */
+    /***/
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+    public static final int KIRAT_RAI = 203; /* Krai */
+    /***/
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+    public static final int OL_ONAL = 204; /* Onao */
+    /***/
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+    public static final int SUNUWAR = 205; /* Sunu */
+    /***/
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+    public static final int TODHRI = 206; /* Todr */
+    /***/
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+    public static final int TULU_TIGALARI = 207; /* Tutg */
+
+
     /**
      * One more than the highest normal UScript code.
      * The highest value is available via UCharacter.getIntPropertyMaxValue(UProperty.SCRIPT).
diff --git a/android_icu4j/src/main/java/android/icu/number/FormattedNumber.java b/android_icu4j/src/main/java/android/icu/number/FormattedNumber.java
index 435c7c908..dcda34179 100644
--- a/android_icu4j/src/main/java/android/icu/number/FormattedNumber.java
+++ b/android_icu4j/src/main/java/android/icu/number/FormattedNumber.java
@@ -127,7 +127,6 @@ public class FormattedNumber implements FormattedValue {
      *
      * @return NounClass
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public DisplayOptions.NounClass getNounClass() {
         return DisplayOptions.NounClass.fromIdentifier(this.gender);
     }
diff --git a/android_icu4j/src/main/java/android/icu/number/LocalizedNumberFormatter.java b/android_icu4j/src/main/java/android/icu/number/LocalizedNumberFormatter.java
index 9ef5a5c29..37623d026 100644
--- a/android_icu4j/src/main/java/android/icu/number/LocalizedNumberFormatter.java
+++ b/android_icu4j/src/main/java/android/icu/number/LocalizedNumberFormatter.java
@@ -120,8 +120,8 @@ public class LocalizedNumberFormatter extends NumberFormatterSettings<LocalizedN
      * Disassociate the locale from this formatter.
      *
      * @return The fluent chain.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public UnlocalizedNumberFormatter withoutLocale() {
         return new UnlocalizedNumberFormatter(this, KEY_LOCALE, null);
     }
diff --git a/android_icu4j/src/main/java/android/icu/number/LocalizedNumberRangeFormatter.java b/android_icu4j/src/main/java/android/icu/number/LocalizedNumberRangeFormatter.java
index c711d34c2..7dc94ed64 100644
--- a/android_icu4j/src/main/java/android/icu/number/LocalizedNumberRangeFormatter.java
+++ b/android_icu4j/src/main/java/android/icu/number/LocalizedNumberRangeFormatter.java
@@ -83,8 +83,8 @@ public class LocalizedNumberRangeFormatter extends NumberRangeFormatterSettings<
      * Disassociate the locale from this formatter.
      *
      * @return The fluent chain.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public UnlocalizedNumberRangeFormatter withoutLocale() {
         return new UnlocalizedNumberRangeFormatter(this, KEY_LOCALE, null);
     }
diff --git a/android_icu4j/src/main/java/android/icu/number/NumberFormatterSettings.java b/android_icu4j/src/main/java/android/icu/number/NumberFormatterSettings.java
index 74ec0163e..377bc99eb 100644
--- a/android_icu4j/src/main/java/android/icu/number/NumberFormatterSettings.java
+++ b/android_icu4j/src/main/java/android/icu/number/NumberFormatterSettings.java
@@ -536,7 +536,6 @@ public abstract class NumberFormatterSettings<T extends NumberFormatterSettings<
      *
      * @return The fluent chain.
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public T displayOptions(DisplayOptions displayOptions) {
         // `displayCase` does not recognise the `undefined`
         if (displayOptions.getGrammaticalCase() == GrammaticalCase.UNDEFINED) {
diff --git a/android_icu4j/src/main/java/android/icu/text/DateTimePatternGenerator.java b/android_icu4j/src/main/java/android/icu/text/DateTimePatternGenerator.java
index 7fda6a158..a6728a2e2 100644
--- a/android_icu4j/src/main/java/android/icu/text/DateTimePatternGenerator.java
+++ b/android_icu4j/src/main/java/android/icu/text/DateTimePatternGenerator.java
@@ -1081,7 +1081,6 @@ public class DateTimePatternGenerator implements Freezable<DateTimePatternGenera
      * @param dateTimeFormat
      *              the new dateTimeFormat to set for the specified style
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public void setDateTimeFormat(int style, String dateTimeFormat) {
         if (style < DateFormat.FULL || style > DateFormat.SHORT) {
             throw new IllegalArgumentException("Illegal style here: " + style);
@@ -1099,7 +1098,6 @@ public class DateTimePatternGenerator implements Freezable<DateTimePatternGenera
      * @return
      *              the current dateTimeFormat for the specified style.
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public String getDateTimeFormat(int style) {
         if (style < DateFormat.FULL || style > DateFormat.SHORT) {
             throw new IllegalArgumentException("Illegal style here: " + style);
diff --git a/android_icu4j/src/main/java/android/icu/text/DisplayOptions.java b/android_icu4j/src/main/java/android/icu/text/DisplayOptions.java
index 9089a64e6..7538dbe21 100644
--- a/android_icu4j/src/main/java/android/icu/text/DisplayOptions.java
+++ b/android_icu4j/src/main/java/android/icu/text/DisplayOptions.java
@@ -22,7 +22,6 @@ import java.util.List;
  *                             .build();
  *                             }
  */
-@android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
 public final class DisplayOptions {
     private final GrammaticalCase grammaticalCase;
     private final NounClass nounClass;
@@ -47,7 +46,6 @@ public final class DisplayOptions {
      *
      * @return Builder
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public static Builder builder() {
         return new Builder();
     }
@@ -57,7 +55,6 @@ public final class DisplayOptions {
      *
      * @return Builder
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public Builder copyToBuilder() {
         return new Builder(this);
     }
@@ -67,7 +64,6 @@ public final class DisplayOptions {
      *
      * @return GrammaticalCase
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public GrammaticalCase getGrammaticalCase() {
         return this.grammaticalCase;
     }
@@ -77,7 +73,6 @@ public final class DisplayOptions {
      *
      * @return NounClass
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public NounClass getNounClass() {
         return this.nounClass;
     }
@@ -87,7 +82,6 @@ public final class DisplayOptions {
      *
      * @return PluralCategory
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public PluralCategory getPluralCategory() {
         return this.pluralCategory;
     }
@@ -97,7 +91,6 @@ public final class DisplayOptions {
      *
      * @return Capitalization
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public Capitalization getCapitalization() {
         return this.capitalization;
     }
@@ -107,7 +100,6 @@ public final class DisplayOptions {
      *
      * @return NameStyle
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public NameStyle getNameStyle() {
         return this.nameStyle;
     }
@@ -117,7 +109,6 @@ public final class DisplayOptions {
      *
      * @return DisplayLength
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public DisplayLength getDisplayLength() {
         return this.displayLength;
     }
@@ -127,7 +118,6 @@ public final class DisplayOptions {
      *
      * @return SubstituteHandling
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public SubstituteHandling getSubstituteHandling() {
         return this.substituteHandling;
     }
@@ -135,7 +125,6 @@ public final class DisplayOptions {
     /**
      * Responsible for building {@code DisplayOptions}.
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public static class Builder {
         private GrammaticalCase grammaticalCase;
         private NounClass nounClass;
@@ -179,7 +168,6 @@ public final class DisplayOptions {
          * @param grammaticalCase The grammatical case.
          * @return Builder
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public Builder setGrammaticalCase(GrammaticalCase grammaticalCase) {
             this.grammaticalCase = grammaticalCase;
             return this;
@@ -191,7 +179,6 @@ public final class DisplayOptions {
          * @param nounClass The noun class.
          * @return Builder
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public Builder setNounClass(NounClass nounClass) {
             this.nounClass = nounClass;
             return this;
@@ -203,7 +190,6 @@ public final class DisplayOptions {
          * @param pluralCategory The plural category.
          * @return Builder
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public Builder setPluralCategory(PluralCategory pluralCategory) {
             this.pluralCategory = pluralCategory;
             return this;
@@ -215,7 +201,6 @@ public final class DisplayOptions {
          * @param capitalization The capitalization.
          * @return Builder
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public Builder setCapitalization(Capitalization capitalization) {
             this.capitalization = capitalization;
             return this;
@@ -227,7 +212,6 @@ public final class DisplayOptions {
          * @param nameStyle The name style.
          * @return Builder
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public Builder setNameStyle(NameStyle nameStyle) {
             this.nameStyle = nameStyle;
             return this;
@@ -239,7 +223,6 @@ public final class DisplayOptions {
          * @param displayLength The display length.
          * @return Builder
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public Builder setDisplayLength(DisplayLength displayLength) {
             this.displayLength = displayLength;
             return this;
@@ -251,7 +234,6 @@ public final class DisplayOptions {
          * @param substituteHandling The substitute handling.
          * @return Builder
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public Builder setSubstituteHandling(SubstituteHandling substituteHandling) {
             this.substituteHandling = substituteHandling;
             return this;
@@ -262,7 +244,6 @@ public final class DisplayOptions {
          *
          * @return DisplayOptions
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public DisplayOptions build() {
             DisplayOptions displayOptions = new DisplayOptions(this);
             return displayOptions;
@@ -272,45 +253,35 @@ public final class DisplayOptions {
     /**
      * Represents all the grammatical noun classes that are supported by CLDR.
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public enum NounClass {
         /**
          * A possible setting for NounClass. The noun class context to be used is unknown (this is the
          * default value).
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         UNDEFINED("undefined"),
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         OTHER("other"),
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         NEUTER("neuter"),
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         FEMININE("feminine"),
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         MASCULINE("masculine"),
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         ANIMATE("animate"),
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         INANIMATE("inanimate"),
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         PERSONAL("personal"),
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         COMMON("common");
 
         private final String identifier;
@@ -322,14 +293,12 @@ public final class DisplayOptions {
         /**
          * Unmodifiable List of all noun classes constants. List version of {@link #values()}.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final List<NounClass> VALUES =
                 Collections.unmodifiableList(Arrays.asList(NounClass.values()));
 
         /**
          * @return the lowercase CLDR keyword string for the noun class.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public final String getIdentifier() {
             return this.identifier;
         }
@@ -338,7 +307,6 @@ public final class DisplayOptions {
          * @param identifier in lower case such as "feminine" or "masculine"
          * @return the plural category corresponding to the identifier, or {@code UNDEFINED}
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final NounClass fromIdentifier(String identifier) {
             if (identifier == null) {
                 return NounClass.UNDEFINED;
@@ -357,31 +325,26 @@ public final class DisplayOptions {
     /**
      * Represents all the name styles.
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public enum NameStyle {
         /**
          * A possible setting for NameStyle. The NameStyle context to be used is unknown (this is the
          * default value).
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         UNDEFINED,
         /**
          * Use standard names when generating a locale name, e.g. en_GB displays as 'English (United
          * Kingdom)'.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         STANDARD_NAMES,
 
         /**
          * Use dialect names, when generating a locale name, e.g. en_GB displays as 'British English'.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         DIALECT_NAMES;
 
         /**
          * Unmodifiable List of all name styles constants. List version of {@link #values()}.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final List<NameStyle> VALUES =
                 Collections.unmodifiableList(Arrays.asList(NameStyle.values()));
     }
@@ -389,31 +352,26 @@ public final class DisplayOptions {
     /**
      * Represents all the substitute handlings.
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public enum SubstituteHandling {
         /**
          * A possible setting for SubstituteHandling. The SubstituteHandling context to be used is
          * unknown (this is the default value).
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         UNDEFINED,
         /**
          * Returns a fallback value (e.g., the input code) when no data is available. This is the
          * default behaviour.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         SUBSTITUTE,
 
         /**
          * Returns a null value when no data is available.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         NO_SUBSTITUTE;
 
         /**
          * Unmodifiable List of all substitute handlings constants. List version of {@link #values()}.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final List<SubstituteHandling> VALUES =
                 Collections.unmodifiableList(Arrays.asList(SubstituteHandling.values()));
     }
@@ -421,30 +379,25 @@ public final class DisplayOptions {
     /**
      * Represents all the display lengths.
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public enum DisplayLength {
         /**
          * A possible setting for DisplayLength. The DisplayLength context to be used is unknown (this
          * is the default value).
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         UNDEFINED,
         /**
          * Uses full names when generating a locale name, e.g. "United States" for US.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         LENGTH_FULL,
 
         /**
          * Use short names when generating a locale name, e.g. "U.S." for US.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         LENGTH_SHORT;
 
         /**
          * Unmodifiable List of all display lengths constants. List version of {@link #values()}.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final List<DisplayLength> VALUES =
                 Collections.unmodifiableList(Arrays.asList(DisplayLength.values()));
     }
@@ -452,27 +405,23 @@ public final class DisplayOptions {
     /**
      * Represents all the capitalization options.
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public enum Capitalization {
         /**
          * A possible setting for Capitalization. The capitalization context to be used is unknown (this
          * is the default value).
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         UNDEFINED,
 
         /**
          * The capitalization context if a date, date symbol or display name is to be formatted with
          * capitalization appropriate for the beginning of a sentence.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         BEGINNING_OF_SENTENCE,
 
         /**
          * The capitalization context if a date, date symbol or display name is to be formatted with
          * capitalization appropriate for the middle of a sentence.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         MIDDLE_OF_SENTENCE,
 
         /**
@@ -480,20 +429,17 @@ public final class DisplayOptions {
          * capitalization appropriate for stand-alone usage such as an isolated name on a calendar
          * page.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         STANDALONE,
 
         /**
          * The capitalization context if a date, date symbol or display name is to be formatted with
          * capitalization appropriate for a user-interface list or menu item.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         UI_LIST_OR_MENU;
 
         /**
          * Unmodifiable List of all the capitalizations constants. List version of {@link #values()}.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final List<Capitalization> VALUES =
                 Collections.unmodifiableList(Arrays.asList(Capitalization.values()));
     }
@@ -501,43 +447,35 @@ public final class DisplayOptions {
     /**
      * Standard CLDR plural category constants. See http://www.unicode.org/reports/tr35/tr35-numbers.html#Language_Plural_Rules
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public enum PluralCategory {
         /**
          * A possible setting for PluralCategory. The plural category context to be used is unknown
          * (this is the default value).
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         UNDEFINED("undefined"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         ZERO("zero"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         ONE("one"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         TWO("two"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         FEW("few"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         MANY("many"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         OTHER("other");
 
         private final String identifier;
@@ -549,14 +487,12 @@ public final class DisplayOptions {
         /**
          * Unmodifiable List of all plural categories constants. List version of {@link #values()}.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final List<PluralCategory> VALUES =
                 Collections.unmodifiableList(Arrays.asList(PluralCategory.values()));
 
         /**
          * @return the lowercase CLDR keyword string for the plural category
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public final String getIdentifier() {
             return this.identifier;
         }
@@ -565,7 +501,6 @@ public final class DisplayOptions {
          * @param identifier in lower case such as "few" or "other"
          * @return the plural category corresponding to the identifier, or {@code UNDEFINED}
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final PluralCategory fromIdentifier(String identifier) {
             if (identifier == null) {
                 return PluralCategory.UNDEFINED;
@@ -584,83 +519,67 @@ public final class DisplayOptions {
     /**
      * Represents all the grammatical cases that are supported by CLDR.
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public enum GrammaticalCase {
         /**
          * A possible setting for GrammaticalCase. The grammatical case context to be used is unknown
          * (this is the default value).
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         UNDEFINED("undefined"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         ABLATIVE("ablative"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         ACCUSATIVE("accusative"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         COMITATIVE("comitative"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         DATIVE("dative"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         ERGATIVE("ergative"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         GENITIVE("genitive"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         INSTRUMENTAL("instrumental"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         LOCATIVE("locative"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         LOCATIVE_COPULATIVE("locative_copulative"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         NOMINATIVE("nominative"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         OBLIQUE("oblique"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         PREPOSITIONAL("prepositional"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         SOCIATIVE("sociative"),
 
         /**
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         VOCATIVE("vocative");
 
         private final String identifier;
@@ -672,14 +591,12 @@ public final class DisplayOptions {
         /**
          * Unmodifiable List of all grammatical cases constants. List version of {@link #values()}.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final List<GrammaticalCase> VALUES =
                 Collections.unmodifiableList(Arrays.asList(GrammaticalCase.values()));
 
         /**
          * @return the lowercase CLDR keyword string for the grammatical case.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public final String getIdentifier() {
             return this.identifier;
         }
@@ -688,7 +605,6 @@ public final class DisplayOptions {
          * @param identifier in lower case such as "dative" or "nominative"
          * @return the plural category corresponding to the identifier, or {@code UNDEFINED}
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final GrammaticalCase fromIdentifier(String identifier) {
             if (identifier == null) {
                 return GrammaticalCase.UNDEFINED;
diff --git a/android_icu4j/src/main/java/android/icu/text/Normalizer2.java b/android_icu4j/src/main/java/android/icu/text/Normalizer2.java
index 4cbbe1547..a3bc71100 100644
--- a/android_icu4j/src/main/java/android/icu/text/Normalizer2.java
+++ b/android_icu4j/src/main/java/android/icu/text/Normalizer2.java
@@ -168,8 +168,8 @@ public abstract class Normalizer2 {
      * <p>Same as getInstance(null, "nfkc_scf", Mode.COMPOSE).
      * Returns an unmodifiable singleton instance.
      * @return the requested Normalizer2, if successful
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public static Normalizer2 getNFKCSimpleCasefoldInstance() {
         return Norm2AllModes.getNFKC_SCFInstance().comp;
     }
diff --git a/android_icu4j/src/main/java/android/icu/text/NumberFormat.java b/android_icu4j/src/main/java/android/icu/text/NumberFormat.java
index 0034e0336..d342875c9 100644
--- a/android_icu4j/src/main/java/android/icu/text/NumberFormat.java
+++ b/android_icu4j/src/main/java/android/icu/text/NumberFormat.java
@@ -1868,7 +1868,6 @@ public abstract class NumberFormat extends UFormat {
         /**
          * Approximately sign. In ICU 70, this was categorized under the generic SIGN field.
          */
-        @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
         public static final Field APPROXIMATELY_SIGN = new Field("approximately sign");
 
         /**
diff --git a/android_icu4j/src/main/java/android/icu/text/UnicodeSet.java b/android_icu4j/src/main/java/android/icu/text/UnicodeSet.java
index a6d8570d7..78beb8b16 100644
--- a/android_icu4j/src/main/java/android/icu/text/UnicodeSet.java
+++ b/android_icu4j/src/main/java/android/icu/text/UnicodeSet.java
@@ -3870,9 +3870,8 @@ public class UnicodeSet extends UnicodeFilter implements Iterable<String>, Compa
      * <p>This value is an options bit set value for some
      * constructors, applyPattern(), and closeOver().
      * It can be ORed together with other, unrelated options.
-     *
-     * @hide unsupported on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public static final int SIMPLE_CASE_INSENSITIVE = 6;
 
     private static final int CASE_MASK = CASE_INSENSITIVE | ADD_CASE_MAPPINGS;
diff --git a/android_icu4j/src/main/java/android/icu/util/Calendar.java b/android_icu4j/src/main/java/android/icu/util/Calendar.java
index 6b0dd1f3c..f0ae1aac4 100644
--- a/android_icu4j/src/main/java/android/icu/util/Calendar.java
+++ b/android_icu4j/src/main/java/android/icu/util/Calendar.java
@@ -951,8 +951,8 @@ public abstract class Calendar implements Serializable, Cloneable, Comparable<Ca
      * is associated with ORDINAL_MONTH value 6 because 4665 is a leap year
      * and there is an extra "Leap Month 5" which associated with ORDINAL_MONTH
      * value 5 before "Month 6" of year 4664.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public static final int ORDINAL_MONTH = 23;
 
     // Android patch: Soft removal the BASE_FIELD_COUNT API on Android.
@@ -2001,8 +2001,8 @@ public abstract class Calendar implements Serializable, Cloneable, Comparable<Ca
      * proposal.
      * @return true if the date in the fields is in a Temporal proposal
      *               defined leap year. False otherwise.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public boolean inTemporalLeapYear() {
         // Default to Gregorian based leap year rule.
         return getActualMaximum(DAY_OF_YEAR) == 366;
@@ -2027,8 +2027,8 @@ public abstract class Calendar implements Serializable, Cloneable, Comparable<Ca
      * years are "M01" to "M13".
      *
      * @return       One of 25 possible strings in {"M01".."M13", "M01L".."M12L"}.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public String getTemporalMonthCode() {
         int month = get(MONTH);
         assert(month < 12);
@@ -2051,8 +2051,8 @@ public abstract class Calendar implements Serializable, Cloneable, Comparable<Ca
      * years are "M01" to "M13".
      * @param temporalMonth One of 25 possible strings in {"M01".. "M12", "M13", "M01L",
      *  "M12L"}.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public void setTemporalMonthCode( String temporalMonth ) {
         if (temporalMonth.length() == 3 && temporalMonth.charAt(0) == 'M') {
             for (int m = 0; m < gTemporalMonthCodes.length; m++) {
diff --git a/android_icu4j/src/main/java/android/icu/util/ChineseCalendar.java b/android_icu4j/src/main/java/android/icu/util/ChineseCalendar.java
index 0aa63956d..fea456e3d 100644
--- a/android_icu4j/src/main/java/android/icu/util/ChineseCalendar.java
+++ b/android_icu4j/src/main/java/android/icu/util/ChineseCalendar.java
@@ -1040,8 +1040,8 @@ public class ChineseCalendar extends Calendar {
      * proposal.
      * @return true if the date in the fields is in a Temporal proposal
      *               defined leap year. False otherwise.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public boolean inTemporalLeapYear() {
         return getActualMaximum(DAY_OF_YEAR) > 360;
     }
@@ -1060,8 +1060,8 @@ public class ChineseCalendar extends Calendar {
      * non-leap year and * in leap year with another monthCode in "M01L" .. "M12L".
      *
      * @return       One of 24 possible strings in {"M01".."M12", "M01L".."M12L"}.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public String getTemporalMonthCode() {
         // We need to call get, not internalGet, to force the calculation
         // from ORDINAL_MONTH.
@@ -1082,8 +1082,8 @@ public class ChineseCalendar extends Calendar {
      * in leap year with another monthCode in "M01L" .. "M12L".
      * @param temporalMonth One of 25 possible strings in {"M01".. "M12", "M13", "M01L",
      *  "M12L"}.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public void setTemporalMonthCode( String temporalMonth ) {
         if (temporalMonth.length() != 4 || temporalMonth.charAt(0) != 'M' || temporalMonth.charAt(3) != 'L') {
             set(IS_LEAP_MONTH, 0);
diff --git a/android_icu4j/src/main/java/android/icu/util/HebrewCalendar.java b/android_icu4j/src/main/java/android/icu/util/HebrewCalendar.java
index 82779d534..c22727f05 100644
--- a/android_icu4j/src/main/java/android/icu/util/HebrewCalendar.java
+++ b/android_icu4j/src/main/java/android/icu/util/HebrewCalendar.java
@@ -890,8 +890,8 @@ public class HebrewCalendar extends Calendar {
     //-------------------------------------------------------------------------
     /**
      * {@inheritDoc}
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public boolean inTemporalLeapYear() {
         return isLeapYear(get(EXTENDED_YEAR));
     }
@@ -911,8 +911,8 @@ public class HebrewCalendar extends Calendar {
      * non-leap year, and "M01" .. "M05", "M05L", "M06" .. "M12" for leap year.
      *
      * @return       One of 13 possible strings in {"M01".. "M05", "M05L", "M06" .. "M12"}.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public String getTemporalMonthCode() {
         return gTemporalMonthCodesForHebrew[get(MONTH)];
     }
@@ -926,8 +926,8 @@ public class HebrewCalendar extends Calendar {
      * are "M01" .. "M12" for non-leap years, and "M01" .. "M05", "M05L", "M06"
      * .. "M12" for leap year.
      * @param temporalMonth The value to be set for temporal monthCode.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public void setTemporalMonthCode( String temporalMonth ) {
         if (temporalMonth.length() == 3 || temporalMonth.length() == 4) {
             for (int m = 0; m < gTemporalMonthCodesForHebrew.length; m++) {
diff --git a/android_icu4j/src/main/java/android/icu/util/IslamicCalendar.java b/android_icu4j/src/main/java/android/icu/util/IslamicCalendar.java
index 8b0fbf432..eeb73f346 100644
--- a/android_icu4j/src/main/java/android/icu/util/IslamicCalendar.java
+++ b/android_icu4j/src/main/java/android/icu/util/IslamicCalendar.java
@@ -1145,8 +1145,8 @@ public class IslamicCalendar extends Calendar {
      * proposal.
      * @return true if the date in the fields is in a Temporal proposal
      *               defined leap year. False otherwise.
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public boolean inTemporalLeapYear() {
         return getActualMaximum(DAY_OF_YEAR) == 355;
     }
diff --git a/android_icu4j/src/main/java/android/icu/util/MeasureUnit.java b/android_icu4j/src/main/java/android/icu/util/MeasureUnit.java
index 4c7e7ca9c..295385f95 100644
--- a/android_icu4j/src/main/java/android/icu/util/MeasureUnit.java
+++ b/android_icu4j/src/main/java/android/icu/util/MeasureUnit.java
@@ -1102,7 +1102,6 @@ public class MeasureUnit implements Serializable {
     /**
      * Constant for unit of duration: quarter
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public static final MeasureUnit QUARTER = MeasureUnit.internalGetInstance("duration", "quarter");
 
     /**
@@ -1494,7 +1493,6 @@ public class MeasureUnit implements Serializable {
     /**
      * Constant for unit of mass: tonne
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public static final MeasureUnit TONNE = MeasureUnit.internalGetInstance("mass", "tonne");
 
     /**
@@ -1540,8 +1538,8 @@ public class MeasureUnit implements Serializable {
 
     /**
      * Constant for unit of pressure: gasoline-energy-density
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public static final MeasureUnit GASOLINE_ENERGY_DENSITY = MeasureUnit.internalGetInstance("pressure", "gasoline-energy-density");
 
     /**
@@ -1589,8 +1587,8 @@ public class MeasureUnit implements Serializable {
 
     /**
      * Constant for unit of speed: beaufort
-     * @hide unsupported on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public static final MeasureUnit BEAUFORT = MeasureUnit.internalGetInstance("speed", "beaufort");
 
     /**
diff --git a/android_icu4j/src/main/java/android/icu/util/TimeZone.java b/android_icu4j/src/main/java/android/icu/util/TimeZone.java
index 8aafaedc5..e27ba8bba 100644
--- a/android_icu4j/src/main/java/android/icu/util/TimeZone.java
+++ b/android_icu4j/src/main/java/android/icu/util/TimeZone.java
@@ -1097,8 +1097,8 @@ abstract public class TimeZone implements Serializable, Cloneable, Freezable<Tim
      * @return  The preferred time zone ID in the IANA time zone database, or {@link TimeZone#UNKNOWN_ZONE_ID}
      * if the input ID is not a system ID.
      * @see #getCanonicalID(String)
-     * @hide draft / provisional / internal are hidden on Android
      */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
     public static String getIanaID(String id) {
         String ianaId = TimeZone.UNKNOWN_ZONE_ID;
         if (id == null || id.length() == 0 || id.equals(TimeZone.UNKNOWN_ZONE)) {
diff --git a/android_icu4j/src/main/java/android/icu/util/VersionInfo.java b/android_icu4j/src/main/java/android/icu/util/VersionInfo.java
index ede34d910..ced753c6e 100644
--- a/android_icu4j/src/main/java/android/icu/util/VersionInfo.java
+++ b/android_icu4j/src/main/java/android/icu/util/VersionInfo.java
@@ -180,8 +180,12 @@ public final class VersionInfo implements Comparable<VersionInfo>
     /**
      * Unicode 15.1 version
      */
-    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_V_API)
     public static final VersionInfo UNICODE_15_1;
+    /**
+     * Unicode 16.0 version
+     */
+    @android.annotation.FlaggedApi(com.android.icu.Flags.FLAG_ICU_25Q2_API)
+    public static final VersionInfo UNICODE_16_0;
 
     /**
      * ICU4J current release version
@@ -526,6 +530,7 @@ public final class VersionInfo implements Comparable<VersionInfo>
         UNICODE_14_0   = getInstance(14, 0, 0, 0);
         UNICODE_15_0   = getInstance(15, 0, 0, 0);
         UNICODE_15_1   = getInstance(15, 1, 0, 0);
+        UNICODE_16_0   = getInstance(16, 0, 0, 0);
 
         ICU_VERSION   = getInstance(75, 1, 0, 0);
         ICU_DATA_VERSION = ICU_VERSION;
diff --git a/icu.aconfig b/icu.aconfig
index 275fd859d..9f975787c 100644
--- a/icu.aconfig
+++ b/icu.aconfig
@@ -17,18 +17,20 @@ container: "system"
 
 flag {
     namespace: "core_libraries"
-    name: "icu74"
-    description: "This flag is deprecated. Use icu_v_api flag instead."
+    name: "icu_v_api"
+    is_exported: true
+    description: "This flag controls whether exposing ICU 74 APIs and implementation"
     bug: "312171264"
+    # ICU is used before SettingsProvider starts
+    is_fixed_read_only: true
 }
 
-
 flag {
     namespace: "core_libraries"
-    name: "icu_v_api"
+    name: "icu_25q2_api"
     is_exported: true
-    description: "This flag controls whether exposing ICU 74 APIs and implementation"
-    bug: "312171264"
+    description: "This flag controls whether exposing new APIs in 25Q2"
+    bug: "374966838"
     # ICU is used before SettingsProvider starts
     is_fixed_read_only: true
 }
diff --git a/icu4c/source/Android.bp b/icu4c/source/Android.bp
index 3c6c961b6..68514c086 100644
--- a/icu4c/source/Android.bp
+++ b/icu4c/source/Android.bp
@@ -54,13 +54,6 @@ cc_library {
         windows: {
             enabled: true,
         },
-        windows_x86_64: {
-            dist: {
-                targets: ["layoutlib"],
-                dir: "layoutlib_native/windows",
-                tag: "stripped_all",
-            },
-        },
         android: {
             cflags: [
                 "-DANDROID_LINK_SHARED_ICU4C",
diff --git a/icu4c/source/common/Android.bp b/icu4c/source/common/Android.bp
index 88e05b265..b254026cb 100644
--- a/icu4c/source/common/Android.bp
+++ b/icu4c/source/common/Android.bp
@@ -116,13 +116,6 @@ cc_library {
                 enabled: false,
             },
         },
-        windows_x86_64: {
-            dist: {
-                targets: ["layoutlib"],
-                dir: "layoutlib_native/windows",
-                tag: "stripped_all",
-            },
-        },
     },
     header_libs: ["libicuuc_headers"],
     export_header_lib_headers: ["libicuuc_headers"],
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/lang/UCharacter.java b/icu4j/main/core/src/main/java/com/ibm/icu/lang/UCharacter.java
index 03e19013c..9fdf6bc7b 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/lang/UCharacter.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/lang/UCharacter.java
@@ -1315,6 +1315,29 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
         /** @stable ICU 74 */
         public static final int CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I_ID = 328; /*[2EBF0]*/
 
+        // New blocks in Unicode 16.0
+
+        /** @stable ICU 76 */
+        public static final int EGYPTIAN_HIEROGLYPHS_EXTENDED_A_ID = 329; /*[13460]*/
+        /** @stable ICU 76 */
+        public static final int GARAY_ID = 330; /*[10D40]*/
+        /** @stable ICU 76 */
+        public static final int GURUNG_KHEMA_ID = 331; /*[16100]*/
+        /** @stable ICU 76 */
+        public static final int KIRAT_RAI_ID = 332; /*[16D40]*/
+        /** @stable ICU 76 */
+        public static final int MYANMAR_EXTENDED_C_ID = 333; /*[116D0]*/
+        /** @stable ICU 76 */
+        public static final int OL_ONAL_ID = 334; /*[1E5D0]*/
+        /** @stable ICU 76 */
+        public static final int SUNUWAR_ID = 335; /*[11BC0]*/
+        /** @stable ICU 76 */
+        public static final int SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT_ID = 336; /*[1CC00]*/
+        /** @stable ICU 76 */
+        public static final int TODHRI_ID = 337; /*[105C0]*/
+        /** @stable ICU 76 */
+        public static final int TULU_TIGALARI_ID = 338; /*[11380]*/
+
         /**
          * One more than the highest normal UnicodeBlock value.
          * The highest value is available via UCharacter.getIntPropertyMaxValue(UProperty.BLOCK).
@@ -2760,6 +2783,36 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
                 new UnicodeBlock("CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I",
                         CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I_ID); /*[2EBF0]*/
 
+        // New blocks in Unicode 16.0
+
+        /** @stable ICU 76 */
+        public static final UnicodeBlock EGYPTIAN_HIEROGLYPHS_EXTENDED_A =
+                new UnicodeBlock("EGYPTIAN_HIEROGLYPHS_EXTENDED_A",
+                        EGYPTIAN_HIEROGLYPHS_EXTENDED_A_ID);
+        /** @stable ICU 76 */
+        public static final UnicodeBlock GARAY = new UnicodeBlock("GARAY", GARAY_ID);
+        /** @stable ICU 76 */
+        public static final UnicodeBlock GURUNG_KHEMA =
+                new UnicodeBlock("GURUNG_KHEMA", GURUNG_KHEMA_ID);
+        /** @stable ICU 76 */
+        public static final UnicodeBlock KIRAT_RAI = new UnicodeBlock("KIRAT_RAI", KIRAT_RAI_ID);
+        /** @stable ICU 76 */
+        public static final UnicodeBlock MYANMAR_EXTENDED_C =
+                new UnicodeBlock("MYANMAR_EXTENDED_C", MYANMAR_EXTENDED_C_ID);
+        /** @stable ICU 76 */
+        public static final UnicodeBlock OL_ONAL = new UnicodeBlock("OL_ONAL", OL_ONAL_ID);
+        /** @stable ICU 76 */
+        public static final UnicodeBlock SUNUWAR = new UnicodeBlock("SUNUWAR", SUNUWAR_ID);
+        /** @stable ICU 76 */
+        public static final UnicodeBlock SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT =
+                new UnicodeBlock("SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT",
+                        SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT_ID);
+        /** @stable ICU 76 */
+        public static final UnicodeBlock TODHRI = new UnicodeBlock("TODHRI", TODHRI_ID);
+        /** @stable ICU 76 */
+        public static final UnicodeBlock TULU_TIGALARI =
+                new UnicodeBlock("TULU_TIGALARI", TULU_TIGALARI_ID);
+
         /**
          * @stable ICU 2.4
          */
@@ -2887,7 +2940,11 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
         {
             super(name);
             m_id_ = id;
-            if (id >= 0) {
+            // Android-changed: Avoid leaking flagged UnicodeBlock until ICU 76 data is integrated.
+            // Without the Unicode 16.0 database, UCharacter.UnicodeBlock.forName(name) is broken if
+            // the new faked UnicodeBlock is stored in this global BLOCKS_ array, See b/320357773.
+            // if (id >= 0) {
+            if (id >= 0 && id < BLOCKS_.length) {
                 BLOCKS_[id] = this;
             }
         }
@@ -3397,6 +3454,8 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
         public static final int THIN_YEH = 102;
         /** @stable ICU 70 */
         public static final int VERTICAL_TAIL = 103;
+        /** @stable ICU 76 */
+        public static final int KASHMIRI_YEH = 104;
 
         /**
          * One more than the highest normal JoiningGroup value.
@@ -4067,6 +4126,8 @@ public final class UCharacter implements ECharacterCategory, ECharacterDirection
         public static final int VOWEL_DEPENDENT = 34;
         /** @stable ICU 63 */
         public static final int VOWEL_INDEPENDENT = 35;
+        /** @stable ICU 76 */
+        public static final int REORDERING_KILLER = 36;
     }
 
     /**
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/lang/UProperty.java b/icu4j/main/core/src/main/java/com/ibm/icu/lang/UProperty.java
index cdec41b9b..f4dc61440 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/lang/UProperty.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/lang/UProperty.java
@@ -621,7 +621,7 @@ public interface UProperty
      * Binary property IDS_Unary_Operator.
      * For programmatic determination of Ideographic Description Sequences.
      *
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public static final int IDS_UNARY_OPERATOR = 72;
 
@@ -629,7 +629,7 @@ public interface UProperty
      * Binary property ID_Compat_Math_Start.
      * <p>Used in mathematical identifier profile in UAX #31.
      *
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public static final int ID_COMPAT_MATH_START = 73;
 
@@ -637,7 +637,7 @@ public interface UProperty
      * Binary property ID_Compat_Math_Continue.
      * <p>Used in mathematical identifier profile in UAX #31.
      *
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public static final int ID_COMPAT_MATH_CONTINUE = 74;
 
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/lang/UScript.java b/icu4j/main/core/src/main/java/com/ibm/icu/lang/UScript.java
index 4f602990e..6ce3a7324 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/lang/UScript.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/lang/UScript.java
@@ -1068,6 +1068,22 @@ public final class UScript {
     /** @stable ICU 75 */
     public static final int ARABIC_NASTALIQ = 200; /* Aran */
 
+    /** @stable ICU 76 */
+    public static final int GARAY = 201; /* Gara */
+    /** @stable ICU 76 */
+    public static final int GURUNG_KHEMA = 202; /* Gukh */
+    /** @stable ICU 76 */
+    public static final int KIRAT_RAI = 203; /* Krai */
+    /** @stable ICU 76 */
+    public static final int OL_ONAL = 204; /* Onao */
+    /** @stable ICU 76 */
+    public static final int SUNUWAR = 205; /* Sunu */
+    /** @stable ICU 76 */
+    public static final int TODHRI = 206; /* Todr */
+    /** @stable ICU 76 */
+    public static final int TULU_TIGALARI = 207; /* Tutg */
+
+
     /**
      * One more than the highest normal UScript code.
      * The highest value is available via UCharacter.getIntPropertyMaxValue(UProperty.SCRIPT).
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/number/LocalizedNumberFormatter.java b/icu4j/main/core/src/main/java/com/ibm/icu/number/LocalizedNumberFormatter.java
index 9154647c2..784c0b40e 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/number/LocalizedNumberFormatter.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/number/LocalizedNumberFormatter.java
@@ -125,7 +125,7 @@ public class LocalizedNumberFormatter extends NumberFormatterSettings<LocalizedN
      * Disassociate the locale from this formatter.
      *
      * @return The fluent chain.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public UnlocalizedNumberFormatter withoutLocale() {
         return new UnlocalizedNumberFormatter(this, KEY_LOCALE, null);
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/number/LocalizedNumberRangeFormatter.java b/icu4j/main/core/src/main/java/com/ibm/icu/number/LocalizedNumberRangeFormatter.java
index 1c07d028c..057f131f9 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/number/LocalizedNumberRangeFormatter.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/number/LocalizedNumberRangeFormatter.java
@@ -86,7 +86,7 @@ public class LocalizedNumberRangeFormatter extends NumberRangeFormatterSettings<
      * Disassociate the locale from this formatter.
      *
      * @return The fluent chain.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public UnlocalizedNumberRangeFormatter withoutLocale() {
         return new UnlocalizedNumberRangeFormatter(this, KEY_LOCALE, null);
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/text/Normalizer2.java b/icu4j/main/core/src/main/java/com/ibm/icu/text/Normalizer2.java
index 869a2cdec..474c06371 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/text/Normalizer2.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/text/Normalizer2.java
@@ -178,7 +178,7 @@ public abstract class Normalizer2 {
      * <p>Same as getInstance(null, "nfkc_scf", Mode.COMPOSE).
      * Returns an unmodifiable singleton instance.
      * @return the requested Normalizer2, if successful
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public static Normalizer2 getNFKCSimpleCasefoldInstance() {
         return Norm2AllModes.getNFKC_SCFInstance().comp;
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/util/Calendar.java b/icu4j/main/core/src/main/java/com/ibm/icu/util/Calendar.java
index a79d4a351..6225a77f6 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/util/Calendar.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/util/Calendar.java
@@ -975,7 +975,7 @@ public abstract class Calendar implements Serializable, Cloneable, Comparable<Ca
      * is associated with ORDINAL_MONTH value 6 because 4665 is a leap year
      * and there is an extra "Leap Month 5" which associated with ORDINAL_MONTH
      * value 5 before "Month 6" of year 4664.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public static final int ORDINAL_MONTH = 23;
 
@@ -2078,7 +2078,7 @@ public abstract class Calendar implements Serializable, Cloneable, Comparable<Ca
      * proposal.
      * @return true if the date in the fields is in a Temporal proposal
      *               defined leap year. False otherwise.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public boolean inTemporalLeapYear() {
         // Default to Gregorian based leap year rule.
@@ -2104,7 +2104,7 @@ public abstract class Calendar implements Serializable, Cloneable, Comparable<Ca
      * years are "M01" to "M13".
      *
      * @return       One of 25 possible strings in {"M01".."M13", "M01L".."M12L"}.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public String getTemporalMonthCode() {
         int month = get(MONTH);
@@ -2128,7 +2128,7 @@ public abstract class Calendar implements Serializable, Cloneable, Comparable<Ca
      * years are "M01" to "M13".
      * @param temporalMonth One of 25 possible strings in {"M01".. "M12", "M13", "M01L",
      *  "M12L"}.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public void setTemporalMonthCode( String temporalMonth ) {
         if (temporalMonth.length() == 3 && temporalMonth.charAt(0) == 'M') {
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/util/ChineseCalendar.java b/icu4j/main/core/src/main/java/com/ibm/icu/util/ChineseCalendar.java
index d136b9d7f..7cfa4232a 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/util/ChineseCalendar.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/util/ChineseCalendar.java
@@ -1060,7 +1060,7 @@ public class ChineseCalendar extends Calendar {
      * proposal.
      * @return true if the date in the fields is in a Temporal proposal
      *               defined leap year. False otherwise.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public boolean inTemporalLeapYear() {
         return getActualMaximum(DAY_OF_YEAR) > 360;
@@ -1080,7 +1080,7 @@ public class ChineseCalendar extends Calendar {
      * non-leap year and * in leap year with another monthCode in "M01L" .. "M12L".
      *
      * @return       One of 24 possible strings in {"M01".."M12", "M01L".."M12L"}.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public String getTemporalMonthCode() {
         // We need to call get, not internalGet, to force the calculation
@@ -1102,7 +1102,7 @@ public class ChineseCalendar extends Calendar {
      * in leap year with another monthCode in "M01L" .. "M12L".
      * @param temporalMonth One of 25 possible strings in {"M01".. "M12", "M13", "M01L",
      *  "M12L"}.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public void setTemporalMonthCode( String temporalMonth ) {
         if (temporalMonth.length() != 4 || temporalMonth.charAt(0) != 'M' || temporalMonth.charAt(3) != 'L') {
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/util/HebrewCalendar.java b/icu4j/main/core/src/main/java/com/ibm/icu/util/HebrewCalendar.java
index c3bf4a5a8..e9be6e783 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/util/HebrewCalendar.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/util/HebrewCalendar.java
@@ -919,7 +919,7 @@ public class HebrewCalendar extends Calendar {
     //-------------------------------------------------------------------------
     /**
      * {@inheritDoc}
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public boolean inTemporalLeapYear() {
         return isLeapYear(get(EXTENDED_YEAR));
@@ -940,7 +940,7 @@ public class HebrewCalendar extends Calendar {
      * non-leap year, and "M01" .. "M05", "M05L", "M06" .. "M12" for leap year.
      *
      * @return       One of 13 possible strings in {"M01".. "M05", "M05L", "M06" .. "M12"}.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public String getTemporalMonthCode() {
         return gTemporalMonthCodesForHebrew[get(MONTH)];
@@ -955,7 +955,7 @@ public class HebrewCalendar extends Calendar {
      * are "M01" .. "M12" for non-leap years, and "M01" .. "M05", "M05L", "M06"
      * .. "M12" for leap year.
      * @param temporalMonth The value to be set for temporal monthCode.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public void setTemporalMonthCode( String temporalMonth ) {
         if (temporalMonth.length() == 3 || temporalMonth.length() == 4) {
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/util/IslamicCalendar.java b/icu4j/main/core/src/main/java/com/ibm/icu/util/IslamicCalendar.java
index 32dc33285..09d9d7e6e 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/util/IslamicCalendar.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/util/IslamicCalendar.java
@@ -1189,7 +1189,7 @@ public class IslamicCalendar extends Calendar {
      * proposal.
      * @return true if the date in the fields is in a Temporal proposal
      *               defined leap year. False otherwise.
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public boolean inTemporalLeapYear() {
         return getActualMaximum(DAY_OF_YEAR) == 355;
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/util/MeasureUnit.java b/icu4j/main/core/src/main/java/com/ibm/icu/util/MeasureUnit.java
index 8f33dd4b0..17dc33e05 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/util/MeasureUnit.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/util/MeasureUnit.java
@@ -1745,7 +1745,7 @@ public class MeasureUnit implements Serializable {
 
     /**
      * Constant for unit of pressure: gasoline-energy-density
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public static final MeasureUnit GASOLINE_ENERGY_DENSITY = MeasureUnit.internalGetInstance("pressure", "gasoline-energy-density");
 
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/util/TimeZone.java b/icu4j/main/core/src/main/java/com/ibm/icu/util/TimeZone.java
index 0846f51ef..aec4610f4 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/util/TimeZone.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/util/TimeZone.java
@@ -1187,7 +1187,7 @@ abstract public class TimeZone implements Serializable, Cloneable, Freezable<Tim
      * @return  The preferred time zone ID in the IANA time zone database, or {@link TimeZone#UNKNOWN_ZONE_ID}
      * if the input ID is not a system ID.
      * @see #getCanonicalID(String)
-     * @draft ICU 74
+     * @stable ICU 74
      */
     public static String getIanaID(String id) {
         String ianaId = TimeZone.UNKNOWN_ZONE_ID;
diff --git a/icu4j/main/core/src/main/java/com/ibm/icu/util/VersionInfo.java b/icu4j/main/core/src/main/java/com/ibm/icu/util/VersionInfo.java
index dbb596010..48c0ccb7b 100644
--- a/icu4j/main/core/src/main/java/com/ibm/icu/util/VersionInfo.java
+++ b/icu4j/main/core/src/main/java/com/ibm/icu/util/VersionInfo.java
@@ -216,6 +216,11 @@ public final class VersionInfo implements Comparable<VersionInfo>
      * @stable ICU 74
      */
     public static final VersionInfo UNICODE_15_1;
+    /**
+     * Unicode 16.0 version
+     * @stable ICU 76
+     */
+    public static final VersionInfo UNICODE_16_0;
 
     /**
      * ICU4J current release version
@@ -573,6 +578,7 @@ public final class VersionInfo implements Comparable<VersionInfo>
         UNICODE_14_0   = getInstance(14, 0, 0, 0);
         UNICODE_15_0   = getInstance(15, 0, 0, 0);
         UNICODE_15_1   = getInstance(15, 1, 0, 0);
+        UNICODE_16_0   = getInstance(16, 0, 0, 0);
 
         ICU_VERSION   = getInstance(75, 1, 0, 0);
         ICU_DATA_VERSION = ICU_VERSION;
diff --git a/tools/srcgen/currysrc/src/main/java/com/google/currysrc/aosp/Annotations.java b/tools/srcgen/currysrc/src/main/java/com/google/currysrc/aosp/Annotations.java
index 524da0e2c..ff028e154 100644
--- a/tools/srcgen/currysrc/src/main/java/com/google/currysrc/aosp/Annotations.java
+++ b/tools/srcgen/currysrc/src/main/java/com/google/currysrc/aosp/Annotations.java
@@ -19,6 +19,7 @@ import com.google.currysrc.api.process.Processor;
 import com.google.currysrc.api.process.ast.BodyDeclarationLocators;
 import com.google.currysrc.processors.AddAnnotation;
 import com.google.currysrc.processors.AnnotationInfo.AnnotationClass;
+import com.google.currysrc.processors.AnnotationInfo.Placeholder;
 import java.io.IOException;
 import java.nio.file.Path;
 
@@ -78,4 +79,15 @@ public final class Annotations {
       throw new IllegalStateException("Could not read JSON from " + unsupportedAppUsagePath, e);
     }
   }
+
+  public static AddAnnotation addFlaggedApi(Path flaggedApiPath) {
+    AnnotationClass annotationClass = new AnnotationClass(
+        "android.annotation.FlaggedApi")
+        .addProperty("value", Placeholder.class);
+    try {
+      return AddAnnotation.fromJsonFile(annotationClass, flaggedApiPath);
+    } catch (IOException e) {
+      throw new IllegalStateException("Could not read JSON from " + flaggedApiPath, e);
+    }
+  }
 }
diff --git a/tools/srcgen/currysrc/src/main/java/com/google/currysrc/aosp/RepackagingTransform.java b/tools/srcgen/currysrc/src/main/java/com/google/currysrc/aosp/RepackagingTransform.java
index 0b0ccfe69..c20ee629d 100644
--- a/tools/srcgen/currysrc/src/main/java/com/google/currysrc/aosp/RepackagingTransform.java
+++ b/tools/srcgen/currysrc/src/main/java/com/google/currysrc/aosp/RepackagingTransform.java
@@ -126,6 +126,13 @@ public class RepackagingTransform {
             .withRequiredArg()
             .withValuesConvertedBy(PATH_CONVERTER);
 
+    OptionSpec<Path> flaggedApiFileOption =
+        optionParser.accepts("flagged-api-file",
+            "json file containing body declaration identifiers and flag value for those members"
+                + " that should receive the @FlaggedApi annotation during transformation.")
+            .withRequiredArg()
+            .withValuesConvertedBy(PATH_CONVERTER);
+
     OptionSpec<Integer> tabSizeOption = optionParser.accepts("tab-size",
         "the number of spaces that represent a single tabulation; set to the default indent used in"
             + " the transformed code otherwise the transformed code may be incorrectly formatted")
@@ -242,6 +249,14 @@ public class RepackagingTransform {
         ruleBuilder.add(createOptionalRule(processor));
       }
 
+      Path flaggedApiFile = optionSet.valueOf(flaggedApiFileOption);
+      if (flaggedApiFile != null) {
+        // AST Change: Add FlaggedApi to specified class members.
+        AddAnnotation processor = Annotations.addFlaggedApi(flaggedApiFile);
+        processor.setListener(changeLog.asAddAnnotationListener());
+        ruleBuilder.add(createOptionalRule(processor));
+      }
+
       Map<String, String> options = JavaCore.getOptions();
       options.put(JavaCore.COMPILER_COMPLIANCE, JavaCore.VERSION_1_8);
       options.put(JavaCore.COMPILER_SOURCE, JavaCore.VERSION_1_8);
diff --git a/tools/srcgen/flagged-api-list.txt b/tools/srcgen/flagged-api-list.txt
deleted file mode 100644
index abb3a0969..000000000
--- a/tools/srcgen/flagged-api-list.txt
+++ /dev/null
@@ -1,99 +0,0 @@
-method:android.icu.number.FormattedNumber#getNounClass()
-method:android.icu.number.NumberFormatterSettings#displayOptions(DisplayOptions)
-method:android.icu.text.DateTimePatternGenerator#setDateTimeFormat(int,String)
-method:android.icu.text.DateTimePatternGenerator#getDateTimeFormat(int)
-type:android.icu.text.DisplayOptions
-method:android.icu.text.DisplayOptions#builder()
-method:android.icu.text.DisplayOptions#copyToBuilder()
-method:android.icu.text.DisplayOptions#getGrammaticalCase()
-method:android.icu.text.DisplayOptions#getNounClass()
-method:android.icu.text.DisplayOptions#getPluralCategory()
-method:android.icu.text.DisplayOptions#getCapitalization()
-method:android.icu.text.DisplayOptions#getNameStyle()
-method:android.icu.text.DisplayOptions#getDisplayLength()
-method:android.icu.text.DisplayOptions#getSubstituteHandling()
-type:android.icu.text.DisplayOptions$Builder
-method:android.icu.text.DisplayOptions$Builder#setGrammaticalCase(GrammaticalCase)
-method:android.icu.text.DisplayOptions$Builder#setNounClass(NounClass)
-method:android.icu.text.DisplayOptions$Builder#setPluralCategory(PluralCategory)
-method:android.icu.text.DisplayOptions$Builder#setCapitalization(Capitalization)
-method:android.icu.text.DisplayOptions$Builder#setNameStyle(NameStyle)
-method:android.icu.text.DisplayOptions$Builder#setDisplayLength(DisplayLength)
-method:android.icu.text.DisplayOptions$Builder#setSubstituteHandling(SubstituteHandling)
-method:android.icu.text.DisplayOptions$Builder#build()
-type:android.icu.text.DisplayOptions$NounClass
-enumConstant:android.icu.text.DisplayOptions$NounClass#UNDEFINED
-enumConstant:android.icu.text.DisplayOptions$NounClass#OTHER
-enumConstant:android.icu.text.DisplayOptions$NounClass#NEUTER
-enumConstant:android.icu.text.DisplayOptions$NounClass#FEMININE
-enumConstant:android.icu.text.DisplayOptions$NounClass#MASCULINE
-enumConstant:android.icu.text.DisplayOptions$NounClass#ANIMATE
-enumConstant:android.icu.text.DisplayOptions$NounClass#INANIMATE
-enumConstant:android.icu.text.DisplayOptions$NounClass#PERSONAL
-enumConstant:android.icu.text.DisplayOptions$NounClass#COMMON
-field:android.icu.text.DisplayOptions$NounClass#VALUES
-method:android.icu.text.DisplayOptions$NounClass#getIdentifier()
-method:android.icu.text.DisplayOptions$NounClass#fromIdentifier(String)
-type:android.icu.text.DisplayOptions$NameStyle
-enumConstant:android.icu.text.DisplayOptions$NameStyle#UNDEFINED
-enumConstant:android.icu.text.DisplayOptions$NameStyle#STANDARD_NAMES
-enumConstant:android.icu.text.DisplayOptions$NameStyle#DIALECT_NAMES
-field:android.icu.text.DisplayOptions$NameStyle#VALUES
-type:android.icu.text.DisplayOptions$SubstituteHandling
-enumConstant:android.icu.text.DisplayOptions$SubstituteHandling#UNDEFINED
-enumConstant:android.icu.text.DisplayOptions$SubstituteHandling#SUBSTITUTE
-enumConstant:android.icu.text.DisplayOptions$SubstituteHandling#NO_SUBSTITUTE
-field:android.icu.text.DisplayOptions$SubstituteHandling#VALUES
-type:android.icu.text.DisplayOptions$DisplayLength
-enumConstant:android.icu.text.DisplayOptions$DisplayLength#UNDEFINED
-enumConstant:android.icu.text.DisplayOptions$DisplayLength#LENGTH_FULL
-enumConstant:android.icu.text.DisplayOptions$DisplayLength#LENGTH_SHORT
-field:android.icu.text.DisplayOptions$DisplayLength#VALUES
-type:android.icu.text.DisplayOptions$Capitalization
-enumConstant:android.icu.text.DisplayOptions$Capitalization#UNDEFINED
-enumConstant:android.icu.text.DisplayOptions$Capitalization#BEGINNING_OF_SENTENCE
-enumConstant:android.icu.text.DisplayOptions$Capitalization#MIDDLE_OF_SENTENCE
-enumConstant:android.icu.text.DisplayOptions$Capitalization#STANDALONE
-enumConstant:android.icu.text.DisplayOptions$Capitalization#UI_LIST_OR_MENU
-field:android.icu.text.DisplayOptions$Capitalization#VALUES
-type:android.icu.text.DisplayOptions$PluralCategory
-enumConstant:android.icu.text.DisplayOptions$PluralCategory#UNDEFINED
-enumConstant:android.icu.text.DisplayOptions$PluralCategory#ZERO
-enumConstant:android.icu.text.DisplayOptions$PluralCategory#ONE
-enumConstant:android.icu.text.DisplayOptions$PluralCategory#TWO
-enumConstant:android.icu.text.DisplayOptions$PluralCategory#FEW
-enumConstant:android.icu.text.DisplayOptions$PluralCategory#MANY
-enumConstant:android.icu.text.DisplayOptions$PluralCategory#OTHER
-field:android.icu.text.DisplayOptions$PluralCategory#VALUES
-method:android.icu.text.DisplayOptions$PluralCategory#getIdentifier()
-method:android.icu.text.DisplayOptions$PluralCategory#fromIdentifier(String)
-type:android.icu.text.DisplayOptions$GrammaticalCase
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#UNDEFINED
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#ABLATIVE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#ACCUSATIVE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#COMITATIVE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#DATIVE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#ERGATIVE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#GENITIVE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#INSTRUMENTAL
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#LOCATIVE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#LOCATIVE_COPULATIVE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#NOMINATIVE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#OBLIQUE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#PREPOSITIONAL
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#SOCIATIVE
-enumConstant:android.icu.text.DisplayOptions$GrammaticalCase#VOCATIVE
-field:android.icu.text.DisplayOptions$GrammaticalCase#VALUES
-method:android.icu.text.DisplayOptions$GrammaticalCase#getIdentifier()
-method:android.icu.text.DisplayOptions$GrammaticalCase#fromIdentifier(String)
-field:android.icu.text.NumberFormat$Field#APPROXIMATELY_SIGN
-field:android.icu.util.MeasureUnit#QUARTER
-field:android.icu.util.MeasureUnit#TONNE
-field:android.icu.lang.UCharacter$LineBreak#AKSARA
-field:android.icu.lang.UCharacter$LineBreak#AKSARA_PREBASE
-field:android.icu.lang.UCharacter$LineBreak#AKSARA_START
-field:android.icu.lang.UCharacter$LineBreak#VIRAMA
-field:android.icu.lang.UCharacter$LineBreak#VIRAMA_FINAL
-field:android.icu.lang.UCharacter$UnicodeBlock#CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I
-field:android.icu.lang.UCharacter$UnicodeBlock#CJK_UNIFIED_IDEOGRAPHS_EXTENSION_I_ID
-field:android.icu.util.VersionInfo#UNICODE_15_1
diff --git a/tools/srcgen/flagged-api.json b/tools/srcgen/flagged-api.json
new file mode 100644
index 000000000..328bb0ae1
--- /dev/null
+++ b/tools/srcgen/flagged-api.json
@@ -0,0 +1,210 @@
+[
+  {
+    "@location": "field:android.icu.lang.UScript#ARABIC_NASTALIQ",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.text.UnicodeSet#SIMPLE_CASE_INSENSITIVE",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.util.MeasureUnit#BEAUFORT",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UProperty#IDS_UNARY_OPERATOR",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UProperty#ID_COMPAT_MATH_CONTINUE",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UProperty#ID_COMPAT_MATH_START",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.number.LocalizedNumberFormatter#withoutLocale()",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.number.LocalizedNumberRangeFormatter#withoutLocale()",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.text.Normalizer2#getNFKCSimpleCasefoldInstance()",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.util.Calendar#ORDINAL_MONTH",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.Calendar#getTemporalMonthCode()",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.Calendar#inTemporalLeapYear()",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.Calendar#setTemporalMonthCode(String)",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.ChineseCalendar#getTemporalMonthCode()",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.ChineseCalendar#inTemporalLeapYear()",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.ChineseCalendar#setTemporalMonthCode(String)",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.HebrewCalendar#getTemporalMonthCode()",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.HebrewCalendar#inTemporalLeapYear()",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.HebrewCalendar#setTemporalMonthCode(String)",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.IslamicCalendar#inTemporalLeapYear()",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.util.MeasureUnit#GASOLINE_ENERGY_DENSITY",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "method:android.icu.util.TimeZone#getIanaID(String)",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$IndicSyllabicCategory#REORDERING_KILLER",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$JoiningGroup#KASHMIRI_YEH",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#EGYPTIAN_HIEROGLYPHS_EXTENDED_A",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#EGYPTIAN_HIEROGLYPHS_EXTENDED_A_ID",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#GARAY",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#GARAY_ID",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#GURUNG_KHEMA",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#GURUNG_KHEMA_ID",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#KIRAT_RAI",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#KIRAT_RAI_ID",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#MYANMAR_EXTENDED_C",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#MYANMAR_EXTENDED_C_ID",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#OL_ONAL",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#OL_ONAL_ID",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#SUNUWAR",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#SUNUWAR_ID",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#SYMBOLS_FOR_LEGACY_COMPUTING_SUPPLEMENT_ID",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#TODHRI",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#TODHRI_ID",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#TULU_TIGALARI",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UCharacter$UnicodeBlock#TULU_TIGALARI_ID",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UScript#GARAY",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UScript#GURUNG_KHEMA",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UScript#KIRAT_RAI",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UScript#OL_ONAL",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UScript#SUNUWAR",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UScript#TODHRI",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.lang.UScript#TULU_TIGALARI",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  },
+  {
+    "@location": "field:android.icu.util.VersionInfo#UNICODE_16_0",
+    "value": "com.android.icu.Flags.FLAG_ICU_25Q2_API"
+  }
+]
diff --git a/tools/srcgen/generate_android_icu4j.sh b/tools/srcgen/generate_android_icu4j.sh
index 3a2d223be..9c09c302d 100755
--- a/tools/srcgen/generate_android_icu4j.sh
+++ b/tools/srcgen/generate_android_icu4j.sh
@@ -45,7 +45,7 @@ fi
 
 ALLOWLIST_API_FILE=${ICU_SRCGEN_DIR}/allowlisted-public-api.txt
 CORE_PLATFORM_API_FILE=${ICU_SRCGEN_DIR}/core-platform-api.txt
-FLAGGED_API_FILE=${ICU_SRCGEN_DIR}/flagged-api-list.txt
+FLAGGED_API_FILE=${ICU_SRCGEN_DIR}/flagged-api.json
 INTRA_CORE_API_FILE=${ICU_SRCGEN_DIR}/intra-core-api.txt
 UNSUPPORTED_APP_USAGE_FILE=${ICU_SRCGEN_DIR}/unsupported-app-usage.json
 
@@ -67,7 +67,7 @@ if [ -e "${ALLOWLIST_API_FILE}" ]; then
   ICU4J_BASE_COMMAND+=" --hide-non-allowlisted-api ${ALLOWLIST_API_FILE}"
 fi
 if [ -e "${FLAGGED_API_FILE}" ]; then
-  ICU4J_BASE_COMMAND+=" --flagged-api-list ${FLAGGED_API_FILE}"
+  ICU4J_BASE_COMMAND+=" --flagged-api ${FLAGGED_API_FILE}"
 fi
 
 ${ICU4J_BASE_COMMAND} ${INPUT_JAVA_DIRS} ${DEST_SRC_DIR} ${CORE_PLATFORM_API_FILE} ${INTRA_CORE_API_FILE} ${UNSUPPORTED_APP_USAGE_FILE}
diff --git a/tools/srcgen/src/main/java/com/android/icu4j/srcgen/Icu4jTransform.java b/tools/srcgen/src/main/java/com/android/icu4j/srcgen/Icu4jTransform.java
index 13b3a9fff..b76043b0c 100644
--- a/tools/srcgen/src/main/java/com/android/icu4j/srcgen/Icu4jTransform.java
+++ b/tools/srcgen/src/main/java/com/android/icu4j/srcgen/Icu4jTransform.java
@@ -793,11 +793,6 @@ public class Icu4jTransform {
       "type:android.icu.text.Collator$CollatorFactory",
       "type:android.icu.text.NumberFormat$NumberFormatFactory",
       "type:android.icu.text.NumberFormat$SimpleNumberFormatFactory",
-
-      // TODO: Remove the below list when the next window for new Android API opens
-      "field:android.icu.lang.UScript#ARABIC_NASTALIQ",
-      "field:android.icu.text.UnicodeSet#SIMPLE_CASE_INSENSITIVE",
-      "field:android.icu.util.MeasureUnit#BEAUFORT",
   };
 
   /**
@@ -908,7 +903,7 @@ public class Icu4jTransform {
     private static final String SOURCE_CODE_HEADER = "/* GENERATED SOURCE. DO NOT MODIFY. */\n";
     private static final String COMMAND_USAGE = "Usage: " + Icu4jTransform.class.getCanonicalName()
             + " [--hide-non-allowlisted-api <allowlisted-api-file>]"
-            + " [--flagged-api-list <flagged-api-file>]"
+            + " [--flagged-api <flagged-api-file>]"
             + " <source-dir>+ <target-dir> <core-platform-api-file> <intra-core-api-file>"
             + " <unsupported-app-usage-file>";
 
@@ -926,7 +921,7 @@ public class Icu4jTransform {
       }
 
       Path flaggedApiListPath = null;
-      if ("--flagged-api-list".equals(args[0])) {
+      if ("--flagged-api".equals(args[0])) {
         flaggedApiListPath = Paths.get(args[1]);
         String[] newArgs = new String[args.length - 2];
         System.arraycopy(args, 2, newArgs, 0, args.length - 2);
@@ -1072,7 +1067,7 @@ public class Icu4jTransform {
       rulesList.addAll(Arrays.asList(apiDocsRules));
       if (flaggedApiListPath != null) {
           // AST change: Add FlaggedApi to specified classes and members
-          rulesList.add(createFlaggedApiRule(flaggedApiListPath));
+          rulesList.add(createOptionalRule(Annotations.addFlaggedApi(flaggedApiListPath)));
       }
       return rulesList;
     }
@@ -1147,14 +1142,4 @@ public class Icu4jTransform {
     return createOptionalRule(new HideNonAllowlistedDeclarations(bodyDeclarationLocators,
             "@hide Hide new API in Android temporarily"));
   }
-
-  private static Rule createFlaggedApiRule(Path flaggedApiListPath) {
-      return createOptionalRule(AddAnnotation.markerAnnotationWithPropertyFromFlatFile(
-              "android.annotation.FlaggedApi",
-              "value",
-              String.class,
-              new AnnotationInfo.Placeholder("com.android.icu.Flags.FLAG_ICU_V_API"),
-              flaggedApiListPath));
-  }
-
 }
```

