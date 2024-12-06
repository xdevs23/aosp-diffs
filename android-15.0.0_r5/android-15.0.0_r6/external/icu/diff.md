```diff
diff --git a/Android.bp b/Android.bp
index d188be7d9..39811ec16 100644
--- a/Android.bp
+++ b/Android.bp
@@ -101,6 +101,7 @@ java_aconfig_library {
     libs: [
         "fake_device_config",
         "aconfig-annotations-lib-sdk-none",
+        "aconfig_storage_reader_java_none",
         "unsupportedappusage-sdk-none",
     ],
     apex_available: [
diff --git a/OWNERS b/OWNERS
index 2a49be3e2..ec19bb4b2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -10,3 +10,5 @@ libcore-bugs-triage@google.com
 # g2.corp.android-icu-maintainers@google.com
 # android-libcore-team+review@google.com
 
+per-file *ravenwood* = file:platform/frameworks/base:/ravenwood/OWNERS
+per-file *Ravenwood* = file:platform/frameworks/base:/ravenwood/OWNERS
diff --git a/README-ravenwood.md b/README-ravenwood.md
new file mode 100644
index 000000000..bfc6b6246
--- /dev/null
+++ b/README-ravenwood.md
@@ -0,0 +1,31 @@
+# ICU on Ravenwood
+
+# What APIs are enabled
+As of 2024-06-19, Ravenwood uses the host side JVM, not ART, so it doesn't use `libcore` either.
+
+To support ICU on Ravenwood, we include the following jar files in the
+Ravenwood classpath.
+- `core-icu4j-for-host.ravenwood`
+- `icu4j-icudata-jarjar`
+- `icu4j-icutzdata-jarjar`
+
+`core-icu4j-for-host.ravenwood` is made from `core-icu4j-for-host.ravenwood`
+with `hoststubgen` to make the following modifications.
+- Enable `android.icu` APIs on Ravenwood.
+- But all other APIs -- i.e. all `libcore_bridge` APIS -- will throw at runtime.
+
+This "policy" is defined in android_icu4j/icu-ravenwood-policies.txt.
+
+As a result, on Ravenwood, all `android.icu` APIs will work, but none of the `libcore_bridge` APIs.
+
+# CTS
+
+ICU's CTS is `CtsIcuTestCases`, which contains the tests under
+android_icu4j/src/main/tests/, which are the tests from the upstream ICU, and
+android_icu4j/testing/, which are android specific tests, which depends
+on `libcore_bridge`.
+
+On Ravenwood, android_icu4j/src/main/tests/ will pass, but not android_icu4j/testing/.
+
+So we have `CtsIcuTestCasesRavenwood-core-only`, which only contains the
+tests from the upstream. You can run this with `atest CtsIcuTestCasesRavenwood-core-only`.
diff --git a/TEST_MAPPING b/TEST_MAPPING
index de82f9ff1..442009214 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -6,5 +6,11 @@
     {
       "name": "minikin_tests"
     }
+  ],
+  "ravenwood-postsubmit": [
+    {
+      "name": "CtsIcuTestCasesRavenwood",
+      "host": true
+    }
   ]
 }
diff --git a/android_icu4j/Android.bp b/android_icu4j/Android.bp
index 0a4cff121..51c80f84b 100644
--- a/android_icu4j/Android.bp
+++ b/android_icu4j/Android.bp
@@ -30,6 +30,10 @@ package {
     default_applicable_licenses: ["external_icu_license"],
 }
 
+build = [
+    "Ravenwood.bp",
+]
+
 //==========================================================
 // build repackaged ICU for target
 //
@@ -128,6 +132,7 @@ java_library_static {
     },
     lint: {
         warning_checks: ["SuspiciousIndentation"],
+        baseline_filename: "lint-baseline.xml",
     },
 }
 
@@ -137,6 +142,7 @@ java_library {
     name: "core-icu4j",
     defaults: ["libcore_icu_bridge_defaults"],
     visibility: [
+        "//art/tools/fuzzer",
         "//packages/modules/RuntimeI18n/apex",
     ],
     apex_available: [
@@ -292,6 +298,12 @@ java_sdk_library {
     lint: {
         warning_checks: ["SuspiciousIndentation"],
     },
+
+    // This module's output stubs contain apis defined in "i18n.module.public.api.stubs",
+    // but adding "i18n.module.public.api" as a dependency of this module leads to circular
+    // dependency and requires further bootstrapping. Thus, disable stubs generation from the
+    // api signature files and generate stubs from the source Java files instead.
+    build_from_text_stub: false,
 }
 
 // Referenced implicitly from i18n.module.intra.core.api.
@@ -451,16 +463,11 @@ java_sdk_library {
 // repackaged android.icu classes and methods and not just the ones available
 // through the Android API.
 //==========================================================
-java_test {
-    name: "android-icu4j-tests",
+java_defaults {
+    name: "android-icu4j-tests-default",
     visibility: [
         "//cts/tests/tests/icu",
     ],
-
-    srcs: [
-        "src/main/tests/**/*.java",
-        "testing/src/**/*.java",
-    ],
     java_resource_dirs: [
         "src/main/tests",
         "testing/src",
@@ -492,3 +499,39 @@ java_test {
         ],
     },
 }
+
+java_test {
+    name: "android-icu4j-tests",
+    defaults: ["android-icu4j-tests-default"],
+    visibility: [
+        "//cts/tests/tests/icu",
+    ],
+    srcs: [
+        "src/main/tests/**/*.java",
+        "testing/src/**/*.java",
+    ],
+}
+
+// Equivalent to android-icu4j-tests, excluding the tests under testing/.
+// We run this as ICU CTS on Ravenwood, where the testing/ tests won't pass due to lack of
+// libcore.
+java_test {
+    name: "android-icu4j-tests-core-only",
+    defaults: ["android-icu4j-tests-default"],
+    visibility: [
+        "//cts/tests/tests/icu",
+    ],
+    srcs: [
+        "src/main/tests/**/*.java",
+        "testing/src/android/icu/testsharding/**/*.java",
+    ],
+    // TODO(b/340889954) Un-excluide the excluded tests.
+    exclude_srcs: [
+        // This class has a "known-failure", which we can't exclude on Ravenwood without
+        // modifying this file, so let's just exclude the whole class for now.
+        "src/main/tests/android/icu/dev/test/format/NumberFormatRegressionTest.java",
+
+        // This test takes too much time and hits the timeout.
+        "src/main/tests/android/icu/dev/test/rbbi/RBBIMonkeyTest.java",
+    ],
+}
diff --git a/android_icu4j/OWNERS b/android_icu4j/OWNERS
new file mode 100644
index 000000000..cb5dcc2e2
--- /dev/null
+++ b/android_icu4j/OWNERS
@@ -0,0 +1,2 @@
+per-file *ravenwood* = file:platform/frameworks/base:/ravenwood/OWNERS
+per-file *Ravenwood* = file:platform/frameworks/base:/ravenwood/OWNERS
diff --git a/android_icu4j/Ravenwood.bp b/android_icu4j/Ravenwood.bp
new file mode 100644
index 000000000..283939203
--- /dev/null
+++ b/android_icu4j/Ravenwood.bp
@@ -0,0 +1,69 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+// For ravenwood.
+// TODO(b/340889954) Enable --supported-api-list-file, once AOSP gets this feature.
+java_genrule {
+    name: "core-icu4j-for-host.ravenwood-base",
+    tools: ["hoststubgen"],
+    cmd: "$(location hoststubgen) " +
+        "@$(location :ravenwood-standard-options) " +
+
+        "--debug-log $(location hoststubgen_core-icu4j-for-host.log) " +
+        "--stats-file $(location hoststubgen_core-icu4j-for-host_stats.csv) " +
+        // "--supported-api-list-file $(location hoststubgen_core-icu4j-for-host_apis.csv) " +
+
+        "--out-impl-jar $(location ravenwood.jar) " +
+
+        "--gen-keep-all-file $(location hoststubgen_core-icu4j-for-host_keep_all.txt) " +
+        "--gen-input-dump-file $(location hoststubgen_core-icu4j-for-host_dump.txt) " +
+
+        "--in-jar $(location :core-icu4j-for-host) " +
+        "--policy-override-file $(location icu-ravenwood-policies.txt) " +
+        "--annotation-allowed-classes-file $(location :ravenwood-annotation-allowed-classes) ",
+    srcs: [
+        ":core-icu4j-for-host",
+
+        "icu-ravenwood-policies.txt",
+        ":ravenwood-standard-options",
+        ":ravenwood-annotation-allowed-classes",
+    ],
+    out: [
+        "ravenwood.jar",
+
+        // Following files are created just as FYI.
+        "hoststubgen_core-icu4j-for-host_keep_all.txt",
+        "hoststubgen_core-icu4j-for-host_dump.txt",
+
+        "hoststubgen_core-icu4j-for-host.log",
+        "hoststubgen_core-icu4j-for-host_stats.csv",
+        // "hoststubgen_core-icu4j-for-host_apis.csv",
+    ],
+    defaults: ["ravenwood-internal-only-visibility-genrule"],
+}
+
+// Extract the impl jar from "core-icu4j-for-host.ravenwood-base" for subsequent build rules.
+// Note this emits a "device side" output, so that ravenwood tests can (implicitly)
+// depend on it.
+java_genrule {
+    name: "core-icu4j-for-host.ravenwood",
+    defaults: ["ravenwood-internal-only-visibility-genrule"],
+    cmd: "cp $(in) $(out)",
+    srcs: [
+        ":core-icu4j-for-host.ravenwood-base{ravenwood.jar}",
+    ],
+    out: [
+        "core-icu4j-for-host.ravenwood.jar",
+    ],
+}
diff --git a/android_icu4j/icu-ravenwood-policies.txt b/android_icu4j/icu-ravenwood-policies.txt
new file mode 100644
index 000000000..208b8567c
--- /dev/null
+++ b/android_icu4j/icu-ravenwood-policies.txt
@@ -0,0 +1,614 @@
+# Ravenwood policy file to expose APIs under android.icu, (which is under src/main/java)
+# We do not expose APIs under com.android, which is under libcore_bridge.
+
+# This file is generated with the following:
+# $ jar tvf $ANDROID_BUILD_TOP/out/host/linux-x86/testcases/ravenwood-runtime/core-icu4j-for-host.ravenwood.jar | sed -ne 's!^.* !! ; \!\$!d ; y!/!.!; s!\.class$!!p' | grep '^android\.icu' | sed -e 's!^!class ! ; s!$! keepclass!'
+
+# On goog/master, or once AOSP gets ravenwood-stats-collector.sh, we can use the following command
+# instead.
+# $ $ANDROID_BUILD_TOP/frameworks/base/ravenwood/scripts/ravenwood-stats-collector.sh
+# $ sed -ne '\!\$!d ; s/ keep$/ keepclass/ ; /^class android\.icu/p' /tmp/ravenwood/ravenwood-keep-all/hoststubgen_core-icu4j-for-host_keep_all.txt
+
+# TODO(b/353573764): Switch to `package` once it's supported on aosp/main.
+
+class android.icu.impl.Assert keepclass
+class android.icu.impl.BMPSet keepclass
+class android.icu.impl.CSCharacterIterator keepclass
+class android.icu.impl.CacheBase keepclass
+class android.icu.impl.CacheValue keepclass
+class android.icu.impl.CalType keepclass
+class android.icu.impl.CalendarAstronomer keepclass
+class android.icu.impl.CalendarCache keepclass
+class android.icu.impl.CalendarUtil keepclass
+class android.icu.impl.CaseMapImpl keepclass
+class android.icu.impl.CharTrie keepclass
+class android.icu.impl.CharacterIteration keepclass
+class android.icu.impl.CharacterIteratorWrapper keepclass
+class android.icu.impl.CharacterPropertiesImpl keepclass
+class android.icu.impl.ClassLoaderUtil keepclass
+class android.icu.impl.CollectionSet keepclass
+class android.icu.impl.CurrencyData keepclass
+class android.icu.impl.DateNumberFormat keepclass
+class android.icu.impl.DayPeriodRules keepclass
+class android.icu.impl.DontCareFieldPosition keepclass
+class android.icu.impl.EmojiProps keepclass
+class android.icu.impl.EraRules keepclass
+class android.icu.impl.FormattedStringBuilder keepclass
+class android.icu.impl.FormattedValueFieldPositionIteratorImpl keepclass
+class android.icu.impl.FormattedValueStringBuilderImpl keepclass
+class android.icu.impl.Grego keepclass
+class android.icu.impl.ICUBinary keepclass
+class android.icu.impl.ICUCache keepclass
+class android.icu.impl.ICUConfig keepclass
+class android.icu.impl.ICUCurrencyDisplayInfoProvider keepclass
+class android.icu.impl.ICUCurrencyMetaInfo keepclass
+class android.icu.impl.ICUData keepclass
+class android.icu.impl.ICUDataVersion keepclass
+class android.icu.impl.ICUDebug keepclass
+class android.icu.impl.ICULangDataTables keepclass
+class android.icu.impl.ICULocaleService keepclass
+class android.icu.impl.ICUNotifier keepclass
+class android.icu.impl.ICURWLock keepclass
+class android.icu.impl.ICURegionDataTables keepclass
+class android.icu.impl.ICUResourceBundle keepclass
+class android.icu.impl.ICUResourceBundleImpl keepclass
+class android.icu.impl.ICUResourceBundleReader keepclass
+class android.icu.impl.ICUResourceTableAccess keepclass
+class android.icu.impl.ICUService keepclass
+class android.icu.impl.IDNA2003 keepclass
+class android.icu.impl.IllegalIcuArgumentException keepclass
+class android.icu.impl.IntTrie keepclass
+class android.icu.impl.IntTrieBuilder keepclass
+class android.icu.impl.InvalidFormatException keepclass
+class android.icu.impl.IterableComparator keepclass
+class android.icu.impl.JavaTimeZone keepclass
+class android.icu.impl.LocaleDisplayNamesImpl keepclass
+class android.icu.impl.LocaleFallbackData keepclass
+class android.icu.impl.LocaleIDParser keepclass
+class android.icu.impl.LocaleIDs keepclass
+class android.icu.impl.LocaleUtility keepclass
+class android.icu.impl.Norm2AllModes keepclass
+class android.icu.impl.Normalizer2Impl keepclass
+class android.icu.impl.OlsonTimeZone keepclass
+class android.icu.impl.PVecToTrieCompactHandler keepclass
+class android.icu.impl.Pair keepclass
+class android.icu.impl.PatternProps keepclass
+class android.icu.impl.PatternTokenizer keepclass
+class android.icu.impl.PluralRulesLoader keepclass
+class android.icu.impl.PropsVectors keepclass
+class android.icu.impl.Punycode keepclass
+class android.icu.impl.RBBIDataWrapper keepclass
+class android.icu.impl.Relation keepclass
+class android.icu.impl.RelativeDateFormat keepclass
+class android.icu.impl.ReplaceableUCharacterIterator keepclass
+class android.icu.impl.ResourceBundleWrapper keepclass
+class android.icu.impl.Row keepclass
+class android.icu.impl.RuleCharacterIterator keepclass
+class android.icu.impl.SimpleCache keepclass
+class android.icu.impl.SimpleFilteredSentenceBreakIterator keepclass
+class android.icu.impl.SimpleFormatterImpl keepclass
+class android.icu.impl.SoftCache keepclass
+class android.icu.impl.SortedSetRelation keepclass
+class android.icu.impl.StandardPlural keepclass
+class android.icu.impl.StaticUnicodeSets keepclass
+class android.icu.impl.StringPrepDataReader keepclass
+class android.icu.impl.StringRange keepclass
+class android.icu.impl.StringSegment keepclass
+class android.icu.impl.TZDBTimeZoneNames keepclass
+class android.icu.impl.TextTrieMap keepclass
+class android.icu.impl.TimeZoneAdapter keepclass
+class android.icu.impl.TimeZoneGenericNames keepclass
+class android.icu.impl.TimeZoneNamesFactoryImpl keepclass
+class android.icu.impl.TimeZoneNamesImpl keepclass
+class android.icu.impl.Trie keepclass
+class android.icu.impl.Trie2 keepclass
+class android.icu.impl.Trie2Writable keepclass
+class android.icu.impl.Trie2_16 keepclass
+class android.icu.impl.Trie2_32 keepclass
+class android.icu.impl.TrieBuilder keepclass
+class android.icu.impl.TrieIterator keepclass
+class android.icu.impl.UBiDiProps keepclass
+class android.icu.impl.UCaseProps keepclass
+class android.icu.impl.UCharArrayIterator keepclass
+class android.icu.impl.UCharacterIteratorWrapper keepclass
+class android.icu.impl.UCharacterName keepclass
+class android.icu.impl.UCharacterNameChoice keepclass
+class android.icu.impl.UCharacterNameReader keepclass
+class android.icu.impl.UCharacterProperty keepclass
+class android.icu.impl.UCharacterUtility keepclass
+class android.icu.impl.UPropertyAliases keepclass
+class android.icu.impl.URLHandler keepclass
+class android.icu.impl.UResource keepclass
+class android.icu.impl.USerializedSet keepclass
+class android.icu.impl.UTS46 keepclass
+class android.icu.impl.UnicodeRegex keepclass
+class android.icu.impl.UnicodeSetStringSpan keepclass
+class android.icu.impl.Utility keepclass
+class android.icu.impl.UtilityExtensions keepclass
+class android.icu.impl.ValidIdentifiers keepclass
+class android.icu.impl.ZoneMeta keepclass
+class android.icu.impl.breakiter.BurmeseBreakEngine keepclass
+class android.icu.impl.breakiter.BytesDictionaryMatcher keepclass
+class android.icu.impl.breakiter.CharsDictionaryMatcher keepclass
+class android.icu.impl.breakiter.CjkBreakEngine keepclass
+class android.icu.impl.breakiter.DictionaryBreakEngine keepclass
+class android.icu.impl.breakiter.DictionaryData keepclass
+class android.icu.impl.breakiter.DictionaryMatcher keepclass
+class android.icu.impl.breakiter.KhmerBreakEngine keepclass
+class android.icu.impl.breakiter.LSTMBreakEngine keepclass
+class android.icu.impl.breakiter.LanguageBreakEngine keepclass
+class android.icu.impl.breakiter.LaoBreakEngine keepclass
+class android.icu.impl.breakiter.MlBreakEngine keepclass
+class android.icu.impl.breakiter.ModelIndex keepclass
+class android.icu.impl.breakiter.ThaiBreakEngine keepclass
+class android.icu.impl.breakiter.UnhandledBreakEngine keepclass
+class android.icu.impl.coll.BOCSU keepclass
+class android.icu.impl.coll.Collation keepclass
+class android.icu.impl.coll.CollationBuilder keepclass
+class android.icu.impl.coll.CollationCompare keepclass
+class android.icu.impl.coll.CollationData keepclass
+class android.icu.impl.coll.CollationDataBuilder keepclass
+class android.icu.impl.coll.CollationDataReader keepclass
+class android.icu.impl.coll.CollationFCD keepclass
+class android.icu.impl.coll.CollationFastLatin keepclass
+class android.icu.impl.coll.CollationFastLatinBuilder keepclass
+class android.icu.impl.coll.CollationIterator keepclass
+class android.icu.impl.coll.CollationKeys keepclass
+class android.icu.impl.coll.CollationLoader keepclass
+class android.icu.impl.coll.CollationRoot keepclass
+class android.icu.impl.coll.CollationRootElements keepclass
+class android.icu.impl.coll.CollationRuleParser keepclass
+class android.icu.impl.coll.CollationSettings keepclass
+class android.icu.impl.coll.CollationTailoring keepclass
+class android.icu.impl.coll.CollationWeights keepclass
+class android.icu.impl.coll.ContractionsAndExpansions keepclass
+class android.icu.impl.coll.FCDIterCollationIterator keepclass
+class android.icu.impl.coll.FCDUTF16CollationIterator keepclass
+class android.icu.impl.coll.IterCollationIterator keepclass
+class android.icu.impl.coll.SharedObject keepclass
+class android.icu.impl.coll.TailoredSet keepclass
+class android.icu.impl.coll.UTF16CollationIterator keepclass
+class android.icu.impl.coll.UVector32 keepclass
+class android.icu.impl.coll.UVector64 keepclass
+class android.icu.impl.data.HolidayBundle keepclass
+class android.icu.impl.data.HolidayBundle_da keepclass
+class android.icu.impl.data.HolidayBundle_da_DK keepclass
+class android.icu.impl.data.HolidayBundle_de keepclass
+class android.icu.impl.data.HolidayBundle_de_AT keepclass
+class android.icu.impl.data.HolidayBundle_de_DE keepclass
+class android.icu.impl.data.HolidayBundle_el keepclass
+class android.icu.impl.data.HolidayBundle_el_GR keepclass
+class android.icu.impl.data.HolidayBundle_en keepclass
+class android.icu.impl.data.HolidayBundle_en_CA keepclass
+class android.icu.impl.data.HolidayBundle_en_GB keepclass
+class android.icu.impl.data.HolidayBundle_en_US keepclass
+class android.icu.impl.data.HolidayBundle_es keepclass
+class android.icu.impl.data.HolidayBundle_es_MX keepclass
+class android.icu.impl.data.HolidayBundle_fr keepclass
+class android.icu.impl.data.HolidayBundle_fr_CA keepclass
+class android.icu.impl.data.HolidayBundle_fr_FR keepclass
+class android.icu.impl.data.HolidayBundle_it keepclass
+class android.icu.impl.data.HolidayBundle_it_IT keepclass
+class android.icu.impl.data.HolidayBundle_iw keepclass
+class android.icu.impl.data.HolidayBundle_iw_IL keepclass
+class android.icu.impl.data.HolidayBundle_ja_JP keepclass
+class android.icu.impl.data.ResourceReader keepclass
+class android.icu.impl.data.TokenIterator keepclass
+class android.icu.impl.duration.BasicDurationFormat keepclass
+class android.icu.impl.duration.BasicDurationFormatter keepclass
+class android.icu.impl.duration.BasicDurationFormatterFactory keepclass
+class android.icu.impl.duration.BasicPeriodBuilderFactory keepclass
+class android.icu.impl.duration.BasicPeriodFormatter keepclass
+class android.icu.impl.duration.BasicPeriodFormatterFactory keepclass
+class android.icu.impl.duration.BasicPeriodFormatterService keepclass
+class android.icu.impl.duration.DateFormatter keepclass
+class android.icu.impl.duration.DurationFormatter keepclass
+class android.icu.impl.duration.DurationFormatterFactory keepclass
+class android.icu.impl.duration.FixedUnitBuilder keepclass
+class android.icu.impl.duration.MultiUnitBuilder keepclass
+class android.icu.impl.duration.OneOrTwoUnitBuilder keepclass
+class android.icu.impl.duration.Period keepclass
+class android.icu.impl.duration.PeriodBuilder keepclass
+class android.icu.impl.duration.PeriodBuilderFactory keepclass
+class android.icu.impl.duration.PeriodBuilderImpl keepclass
+class android.icu.impl.duration.PeriodFormatter keepclass
+class android.icu.impl.duration.PeriodFormatterFactory keepclass
+class android.icu.impl.duration.PeriodFormatterService keepclass
+class android.icu.impl.duration.SingleUnitBuilder keepclass
+class android.icu.impl.duration.TimeUnit keepclass
+class android.icu.impl.duration.TimeUnitConstants keepclass
+class android.icu.impl.duration.impl.DataRecord keepclass
+class android.icu.impl.duration.impl.PeriodFormatterData keepclass
+class android.icu.impl.duration.impl.PeriodFormatterDataService keepclass
+class android.icu.impl.duration.impl.RecordReader keepclass
+class android.icu.impl.duration.impl.RecordWriter keepclass
+class android.icu.impl.duration.impl.ResourceBasedPeriodFormatterDataService keepclass
+class android.icu.impl.duration.impl.Utils keepclass
+class android.icu.impl.duration.impl.XMLRecordReader keepclass
+class android.icu.impl.duration.impl.XMLRecordWriter keepclass
+class android.icu.impl.locale.AsciiUtil keepclass
+class android.icu.impl.locale.BaseLocale keepclass
+class android.icu.impl.locale.Extension keepclass
+class android.icu.impl.locale.InternalLocaleBuilder keepclass
+class android.icu.impl.locale.KeyTypeData keepclass
+class android.icu.impl.locale.LSR keepclass
+class android.icu.impl.locale.LanguageTag keepclass
+class android.icu.impl.locale.LikelySubtags keepclass
+class android.icu.impl.locale.LocaleDistance keepclass
+class android.icu.impl.locale.LocaleExtensions keepclass
+class android.icu.impl.locale.LocaleObjectCache keepclass
+class android.icu.impl.locale.LocaleSyntaxException keepclass
+class android.icu.impl.locale.LocaleValidityChecker keepclass
+class android.icu.impl.locale.ParseStatus keepclass
+class android.icu.impl.locale.StringTokenIterator keepclass
+class android.icu.impl.locale.UnicodeLocaleExtension keepclass
+class android.icu.impl.locale.XCldrStub keepclass
+class android.icu.impl.number.AdoptingModifierStore keepclass
+class android.icu.impl.number.AffixPatternProvider keepclass
+class android.icu.impl.number.AffixUtils keepclass
+class android.icu.impl.number.CompactData keepclass
+class android.icu.impl.number.ConstantAffixModifier keepclass
+class android.icu.impl.number.ConstantMultiFieldModifier keepclass
+class android.icu.impl.number.CurrencyPluralInfoAffixProvider keepclass
+class android.icu.impl.number.CurrencySpacingEnabledModifier keepclass
+class android.icu.impl.number.CustomSymbolCurrency keepclass
+class android.icu.impl.number.DecimalFormatProperties keepclass
+class android.icu.impl.number.DecimalQuantity keepclass
+class android.icu.impl.number.DecimalQuantity_AbstractBCD keepclass
+class android.icu.impl.number.DecimalQuantity_DualStorageBCD keepclass
+class android.icu.impl.number.Grouper keepclass
+class android.icu.impl.number.LocalizedNumberFormatterAsFormat keepclass
+class android.icu.impl.number.LongNameHandler keepclass
+class android.icu.impl.number.LongNameMultiplexer keepclass
+class android.icu.impl.number.MacroProps keepclass
+class android.icu.impl.number.MicroProps keepclass
+class android.icu.impl.number.MicroPropsGenerator keepclass
+class android.icu.impl.number.MicroPropsMutator keepclass
+class android.icu.impl.number.MixedUnitLongNameHandler keepclass
+class android.icu.impl.number.Modifier keepclass
+class android.icu.impl.number.ModifierStore keepclass
+class android.icu.impl.number.MultiplierFormatHandler keepclass
+class android.icu.impl.number.MultiplierProducer keepclass
+class android.icu.impl.number.MutablePatternModifier keepclass
+class android.icu.impl.number.Padder keepclass
+class android.icu.impl.number.PatternStringParser keepclass
+class android.icu.impl.number.PatternStringUtils keepclass
+class android.icu.impl.number.Properties keepclass
+class android.icu.impl.number.PropertiesAffixPatternProvider keepclass
+class android.icu.impl.number.RoundingUtils keepclass
+class android.icu.impl.number.SimpleModifier keepclass
+class android.icu.impl.number.UnitConversionHandler keepclass
+class android.icu.impl.number.UsagePrefsHandler keepclass
+class android.icu.impl.number.parse.AffixMatcher keepclass
+class android.icu.impl.number.parse.AffixPatternMatcher keepclass
+class android.icu.impl.number.parse.AffixTokenMatcherFactory keepclass
+class android.icu.impl.number.parse.CodePointMatcher keepclass
+class android.icu.impl.number.parse.CombinedCurrencyMatcher keepclass
+class android.icu.impl.number.parse.DecimalMatcher keepclass
+class android.icu.impl.number.parse.IgnorablesMatcher keepclass
+class android.icu.impl.number.parse.InfinityMatcher keepclass
+class android.icu.impl.number.parse.MinusSignMatcher keepclass
+class android.icu.impl.number.parse.MultiplierParseHandler keepclass
+class android.icu.impl.number.parse.NanMatcher keepclass
+class android.icu.impl.number.parse.NumberParseMatcher keepclass
+class android.icu.impl.number.parse.NumberParserImpl keepclass
+class android.icu.impl.number.parse.PaddingMatcher keepclass
+class android.icu.impl.number.parse.ParsedNumber keepclass
+class android.icu.impl.number.parse.ParsingUtils keepclass
+class android.icu.impl.number.parse.PercentMatcher keepclass
+class android.icu.impl.number.parse.PermilleMatcher keepclass
+class android.icu.impl.number.parse.PlusSignMatcher keepclass
+class android.icu.impl.number.parse.RequireAffixValidator keepclass
+class android.icu.impl.number.parse.RequireCurrencyValidator keepclass
+class android.icu.impl.number.parse.RequireDecimalSeparatorValidator keepclass
+class android.icu.impl.number.parse.RequireNumberValidator keepclass
+class android.icu.impl.number.parse.ScientificMatcher keepclass
+class android.icu.impl.number.parse.SeriesMatcher keepclass
+class android.icu.impl.number.parse.SymbolMatcher keepclass
+class android.icu.impl.number.parse.ValidationMatcher keepclass
+class android.icu.impl.number.range.PrefixInfixSuffixLengthHelper keepclass
+class android.icu.impl.number.range.RangeMacroProps keepclass
+class android.icu.impl.number.range.StandardPluralRanges keepclass
+class android.icu.impl.personname.FieldModifierImpl keepclass
+class android.icu.impl.personname.PersonNameFormatterImpl keepclass
+class android.icu.impl.personname.PersonNamePattern keepclass
+class android.icu.impl.text.RbnfScannerProviderImpl keepclass
+class android.icu.impl.units.ComplexUnitsConverter keepclass
+class android.icu.impl.units.ConversionRates keepclass
+class android.icu.impl.units.MeasureUnitImpl keepclass
+class android.icu.impl.units.SingleUnitImpl keepclass
+class android.icu.impl.units.UnitPreferences keepclass
+class android.icu.impl.units.UnitsConverter keepclass
+class android.icu.impl.units.UnitsData keepclass
+class android.icu.impl.units.UnitsRouter keepclass
+class android.icu.lang.CharSequences keepclass
+class android.icu.lang.CharacterProperties keepclass
+class android.icu.lang.UCharacter keepclass
+class android.icu.lang.UCharacterCategory keepclass
+class android.icu.lang.UCharacterDirection keepclass
+class android.icu.lang.UCharacterEnums keepclass
+class android.icu.lang.UCharacterNameIterator keepclass
+class android.icu.lang.UProperty keepclass
+class android.icu.lang.UScript keepclass
+class android.icu.lang.UScriptRun keepclass
+class android.icu.math.BigDecimal keepclass
+class android.icu.math.MathContext keepclass
+class android.icu.message2.DateTimeFormatterFactory keepclass
+class android.icu.message2.FormattedMessage keepclass
+class android.icu.message2.FormattedPlaceholder keepclass
+class android.icu.message2.Formatter keepclass
+class android.icu.message2.FormatterFactory keepclass
+class android.icu.message2.IdentityFormatterFactory keepclass
+class android.icu.message2.InputSource keepclass
+class android.icu.message2.MFDataModel keepclass
+class android.icu.message2.MFDataModelFormatter keepclass
+class android.icu.message2.MFDataModelValidator keepclass
+class android.icu.message2.MFFunctionRegistry keepclass
+class android.icu.message2.MFParseException keepclass
+class android.icu.message2.MFParser keepclass
+class android.icu.message2.MFSerializer keepclass
+class android.icu.message2.MessageFormatter keepclass
+class android.icu.message2.NumberFormatterFactory keepclass
+class android.icu.message2.OptUtils keepclass
+class android.icu.message2.PlainStringFormattedValue keepclass
+class android.icu.message2.Selector keepclass
+class android.icu.message2.SelectorFactory keepclass
+class android.icu.message2.StringUtils keepclass
+class android.icu.message2.StringView keepclass
+class android.icu.message2.TextSelectorFactory keepclass
+class android.icu.number.CompactNotation keepclass
+class android.icu.number.CurrencyPrecision keepclass
+class android.icu.number.FormattedNumber keepclass
+class android.icu.number.FormattedNumberRange keepclass
+class android.icu.number.FractionPrecision keepclass
+class android.icu.number.IntegerWidth keepclass
+class android.icu.number.LocalizedNumberFormatter keepclass
+class android.icu.number.LocalizedNumberRangeFormatter keepclass
+class android.icu.number.Notation keepclass
+class android.icu.number.NumberFormatter keepclass
+class android.icu.number.NumberFormatterImpl keepclass
+class android.icu.number.NumberFormatterSettings keepclass
+class android.icu.number.NumberPropertyMapper keepclass
+class android.icu.number.NumberRangeFormatter keepclass
+class android.icu.number.NumberRangeFormatterImpl keepclass
+class android.icu.number.NumberRangeFormatterSettings keepclass
+class android.icu.number.NumberSkeletonImpl keepclass
+class android.icu.number.Precision keepclass
+class android.icu.number.Scale keepclass
+class android.icu.number.ScientificNotation keepclass
+class android.icu.number.SimpleNotation keepclass
+class android.icu.number.SkeletonSyntaxException keepclass
+class android.icu.number.UnlocalizedNumberFormatter keepclass
+class android.icu.number.UnlocalizedNumberRangeFormatter keepclass
+class android.icu.platform.AndroidDataFiles keepclass
+class android.icu.text.AbsoluteValueSubstitution keepclass
+class android.icu.text.AlphabeticIndex keepclass
+class android.icu.text.AnyTransliterator keepclass
+class android.icu.text.ArabicShaping keepclass
+class android.icu.text.ArabicShapingException keepclass
+class android.icu.text.Bidi keepclass
+class android.icu.text.BidiClassifier keepclass
+class android.icu.text.BidiLine keepclass
+class android.icu.text.BidiRun keepclass
+class android.icu.text.BidiTransform keepclass
+class android.icu.text.BidiWriter keepclass
+class android.icu.text.BreakIterator keepclass
+class android.icu.text.BreakIteratorFactory keepclass
+class android.icu.text.BreakTransliterator keepclass
+class android.icu.text.CanonicalIterator keepclass
+class android.icu.text.CaseFoldTransliterator keepclass
+class android.icu.text.CaseMap keepclass
+class android.icu.text.CharsetDetector keepclass
+class android.icu.text.CharsetMatch keepclass
+class android.icu.text.CharsetRecog_2022 keepclass
+class android.icu.text.CharsetRecog_UTF8 keepclass
+class android.icu.text.CharsetRecog_Unicode keepclass
+class android.icu.text.CharsetRecog_mbcs keepclass
+class android.icu.text.CharsetRecog_sbcs keepclass
+class android.icu.text.CharsetRecognizer keepclass
+class android.icu.text.ChineseDateFormat keepclass
+class android.icu.text.ChineseDateFormatSymbols keepclass
+class android.icu.text.CollationElementIterator keepclass
+class android.icu.text.CollationKey keepclass
+class android.icu.text.Collator keepclass
+class android.icu.text.CollatorServiceShim keepclass
+class android.icu.text.CompactDecimalFormat keepclass
+class android.icu.text.ComposedCharIter keepclass
+class android.icu.text.CompoundTransliterator keepclass
+class android.icu.text.ConstrainedFieldPosition keepclass
+class android.icu.text.CurrencyDisplayNames keepclass
+class android.icu.text.CurrencyFormat keepclass
+class android.icu.text.CurrencyMetaInfo keepclass
+class android.icu.text.CurrencyPluralInfo keepclass
+class android.icu.text.DateFormat keepclass
+class android.icu.text.DateFormatSymbols keepclass
+class android.icu.text.DateIntervalFormat keepclass
+class android.icu.text.DateIntervalInfo keepclass
+class android.icu.text.DateTimePatternGenerator keepclass
+class android.icu.text.DecimalFormat keepclass
+class android.icu.text.DecimalFormatSymbols keepclass
+class android.icu.text.DisplayContext keepclass
+class android.icu.text.DisplayOptions keepclass
+class android.icu.text.DurationFormat keepclass
+class android.icu.text.Edits keepclass
+class android.icu.text.EscapeTransliterator keepclass
+class android.icu.text.FilteredBreakIteratorBuilder keepclass
+class android.icu.text.FilteredNormalizer2 keepclass
+class android.icu.text.FormattedValue keepclass
+class android.icu.text.FractionalPartSubstitution keepclass
+class android.icu.text.FunctionReplacer keepclass
+class android.icu.text.IDNA keepclass
+class android.icu.text.IntegralPartSubstitution keepclass
+class android.icu.text.ListFormatter keepclass
+class android.icu.text.LocaleDisplayNames keepclass
+class android.icu.text.LowercaseTransliterator keepclass
+class android.icu.text.MeasureFormat keepclass
+class android.icu.text.MessageFormat keepclass
+class android.icu.text.MessagePattern keepclass
+class android.icu.text.MessagePatternUtil keepclass
+class android.icu.text.ModulusSubstitution keepclass
+class android.icu.text.MultiplierSubstitution keepclass
+class android.icu.text.NFRule keepclass
+class android.icu.text.NFRuleSet keepclass
+class android.icu.text.NFSubstitution keepclass
+class android.icu.text.NameUnicodeTransliterator keepclass
+class android.icu.text.NormalizationTransliterator keepclass
+class android.icu.text.Normalizer keepclass
+class android.icu.text.Normalizer2 keepclass
+class android.icu.text.NullTransliterator keepclass
+class android.icu.text.NumberFormat keepclass
+class android.icu.text.NumberFormatServiceShim keepclass
+class android.icu.text.NumberingSystem keepclass
+class android.icu.text.NumeratorSubstitution keepclass
+class android.icu.text.PersonName keepclass
+class android.icu.text.PersonNameFormatter keepclass
+class android.icu.text.PluralFormat keepclass
+class android.icu.text.PluralRules keepclass
+class android.icu.text.PluralRulesSerialProxy keepclass
+class android.icu.text.Quantifier keepclass
+class android.icu.text.QuantityFormatter keepclass
+class android.icu.text.RBBINode keepclass
+class android.icu.text.RBBIRuleBuilder keepclass
+class android.icu.text.RBBIRuleParseTable keepclass
+class android.icu.text.RBBIRuleScanner keepclass
+class android.icu.text.RBBISetBuilder keepclass
+class android.icu.text.RBBISymbolTable keepclass
+class android.icu.text.RBBITableBuilder keepclass
+class android.icu.text.RBNFChinesePostProcessor keepclass
+class android.icu.text.RBNFPostProcessor keepclass
+class android.icu.text.RawCollationKey keepclass
+class android.icu.text.RbnfLenientScanner keepclass
+class android.icu.text.RbnfLenientScannerProvider keepclass
+class android.icu.text.RelativeDateTimeFormatter keepclass
+class android.icu.text.RemoveTransliterator keepclass
+class android.icu.text.Replaceable keepclass
+class android.icu.text.ReplaceableContextIterator keepclass
+class android.icu.text.ReplaceableString keepclass
+class android.icu.text.RuleBasedBreakIterator keepclass
+class android.icu.text.RuleBasedCollator keepclass
+class android.icu.text.RuleBasedNumberFormat keepclass
+class android.icu.text.RuleBasedTransliterator keepclass
+class android.icu.text.SCSU keepclass
+class android.icu.text.SameValueSubstitution keepclass
+class android.icu.text.ScientificNumberFormatter keepclass
+class android.icu.text.SearchIterator keepclass
+class android.icu.text.SelectFormat keepclass
+class android.icu.text.SimpleDateFormat keepclass
+class android.icu.text.SimpleFormatter keepclass
+class android.icu.text.SimplePersonName keepclass
+class android.icu.text.SourceTargetUtility keepclass
+class android.icu.text.SpoofChecker keepclass
+class android.icu.text.StringCharacterIterator keepclass
+class android.icu.text.StringMatcher keepclass
+class android.icu.text.StringPrep keepclass
+class android.icu.text.StringPrepParseException keepclass
+class android.icu.text.StringReplacer keepclass
+class android.icu.text.StringSearch keepclass
+class android.icu.text.StringTransform keepclass
+class android.icu.text.SymbolTable keepclass
+class android.icu.text.TimeUnitFormat keepclass
+class android.icu.text.TimeZoneFormat keepclass
+class android.icu.text.TimeZoneNames keepclass
+class android.icu.text.TitlecaseTransliterator keepclass
+class android.icu.text.Transform keepclass
+class android.icu.text.TransliterationRule keepclass
+class android.icu.text.TransliterationRuleSet keepclass
+class android.icu.text.Transliterator keepclass
+class android.icu.text.TransliteratorIDParser keepclass
+class android.icu.text.TransliteratorParser keepclass
+class android.icu.text.TransliteratorRegistry keepclass
+class android.icu.text.UCharacterIterator keepclass
+class android.icu.text.UFieldPosition keepclass
+class android.icu.text.UFormat keepclass
+class android.icu.text.UForwardCharacterIterator keepclass
+class android.icu.text.UTF16 keepclass
+class android.icu.text.UnescapeTransliterator keepclass
+class android.icu.text.UnicodeCompressor keepclass
+class android.icu.text.UnicodeDecompressor keepclass
+class android.icu.text.UnicodeFilter keepclass
+class android.icu.text.UnicodeMatcher keepclass
+class android.icu.text.UnicodeNameTransliterator keepclass
+class android.icu.text.UnicodeReplacer keepclass
+class android.icu.text.UnicodeSet keepclass
+class android.icu.text.UnicodeSetIterator keepclass
+class android.icu.text.UnicodeSetSpanner keepclass
+class android.icu.text.UppercaseTransliterator keepclass
+class android.icu.util.AnnualTimeZoneRule keepclass
+class android.icu.util.BasicTimeZone keepclass
+class android.icu.util.BuddhistCalendar keepclass
+class android.icu.util.ByteArrayWrapper keepclass
+class android.icu.util.BytesTrie keepclass
+class android.icu.util.BytesTrieBuilder keepclass
+class android.icu.util.CECalendar keepclass
+class android.icu.util.Calendar keepclass
+class android.icu.util.CaseInsensitiveString keepclass
+class android.icu.util.CharsTrie keepclass
+class android.icu.util.CharsTrieBuilder keepclass
+class android.icu.util.ChineseCalendar keepclass
+class android.icu.util.CodePointMap keepclass
+class android.icu.util.CodePointTrie keepclass
+class android.icu.util.CompactByteArray keepclass
+class android.icu.util.CompactCharArray keepclass
+class android.icu.util.CopticCalendar keepclass
+class android.icu.util.Currency keepclass
+class android.icu.util.CurrencyAmount keepclass
+class android.icu.util.CurrencyServiceShim keepclass
+class android.icu.util.DangiCalendar keepclass
+class android.icu.util.DateInterval keepclass
+class android.icu.util.DateRule keepclass
+class android.icu.util.DateTimeRule keepclass
+class android.icu.util.EasterHoliday keepclass
+class android.icu.util.EasterRule keepclass
+class android.icu.util.EthiopicCalendar keepclass
+class android.icu.util.Freezable keepclass
+class android.icu.util.GenderInfo keepclass
+class android.icu.util.GlobalizationPreferences keepclass
+class android.icu.util.GregorianCalendar keepclass
+class android.icu.util.HebrewCalendar keepclass
+class android.icu.util.HebrewHoliday keepclass
+class android.icu.util.Holiday keepclass
+class android.icu.util.ICUCloneNotSupportedException keepclass
+class android.icu.util.ICUException keepclass
+class android.icu.util.ICUInputTooLongException keepclass
+class android.icu.util.ICUUncheckedIOException keepclass
+class android.icu.util.IllformedLocaleException keepclass
+class android.icu.util.IndianCalendar keepclass
+class android.icu.util.InitialTimeZoneRule keepclass
+class android.icu.util.IslamicCalendar keepclass
+class android.icu.util.JapaneseCalendar keepclass
+class android.icu.util.LocaleData keepclass
+class android.icu.util.LocaleMatcher keepclass
+class android.icu.util.LocalePriorityList keepclass
+class android.icu.util.Measure keepclass
+class android.icu.util.MeasureUnit keepclass
+class android.icu.util.MutableCodePointTrie keepclass
+class android.icu.util.NoUnit keepclass
+class android.icu.util.Output keepclass
+class android.icu.util.OutputInt keepclass
+class android.icu.util.PersianCalendar keepclass
+class android.icu.util.Range keepclass
+class android.icu.util.RangeDateRule keepclass
+class android.icu.util.RangeValueIterator keepclass
+class android.icu.util.Region keepclass
+class android.icu.util.RuleBasedTimeZone keepclass
+class android.icu.util.STZInfo keepclass
+class android.icu.util.SimpleDateRule keepclass
+class android.icu.util.SimpleHoliday keepclass
+class android.icu.util.SimpleTimeZone keepclass
+class android.icu.util.StringTokenizer keepclass
+class android.icu.util.StringTrieBuilder keepclass
+class android.icu.util.TaiwanCalendar keepclass
+class android.icu.util.TimeArrayTimeZoneRule keepclass
+class android.icu.util.TimeUnit keepclass
+class android.icu.util.TimeUnitAmount keepclass
+class android.icu.util.TimeZone keepclass
+class android.icu.util.TimeZoneRule keepclass
+class android.icu.util.TimeZoneTransition keepclass
+class android.icu.util.ULocale keepclass
+class android.icu.util.UResourceBundle keepclass
+class android.icu.util.UResourceBundleIterator keepclass
+class android.icu.util.UResourceTypeMismatchException keepclass
+class android.icu.util.UniversalTimeScale keepclass
+class android.icu.util.VTimeZone keepclass
+class android.icu.util.ValueIterator keepclass
+class android.icu.util.VersionInfo keepclass
diff --git a/android_icu4j/libcore_bridge/src/native/Android.bp b/android_icu4j/libcore_bridge/src/native/Android.bp
index cd4833f98..9dc0212e6 100644
--- a/android_icu4j/libcore_bridge/src/native/Android.bp
+++ b/android_icu4j/libcore_bridge/src/native/Android.bp
@@ -29,6 +29,10 @@ package {
 cc_library_shared {
     name: "libicu_jni",
     host_supported: true,
+    visibility: [
+        "//art/tools/ahat",
+        "//packages/modules/RuntimeI18n/apex",
+    ],
     header_libs: ["jni_headers"],
     shared_libs: [
         "libbase",
diff --git a/android_icu4j/lint-baseline.xml b/android_icu4j/lint-baseline.xml
new file mode 100644
index 000000000..159b768d7
--- /dev/null
+++ b/android_icu4j/lint-baseline.xml
@@ -0,0 +1,81 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<issues format="6" by="lint 8.4.0-alpha08" type="baseline" client="" dependencies="true" name="" variant="all" version="8.4.0-alpha08">
+
+    <issue
+        id="FlaggedApi"
+        message="Field `APPROXIMATELY_SIGN` is a flagged API and should be inside an `if (Flags.icuVApi())` check (or annotate the surrounding method `getFieldForType` with `@FlaggedApi(Flags.FLAG_ICU_V_API) to transfer requirement to caller`)"
+        errorLine1="            return NumberFormat.Field.APPROXIMATELY_SIGN;"
+        errorLine2="                                      ~~~~~~~~~~~~~~~~~~">
+        <location
+            file="external/icu/android_icu4j/src/main/java/android/icu/impl/number/AffixUtils.java"
+            line="282"
+            column="39"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setDateTimeFormat()` is a flagged API and should be inside an `if (Flags.icuVApi())` check (or annotate the surrounding method `setDateTimeFromCalendar` with `@FlaggedApi(Flags.FLAG_ICU_V_API) to transfer requirement to caller`)"
+        errorLine1="            setDateTimeFormat(style, dateTimeFormat);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="external/icu/android_icu4j/src/main/java/android/icu/text/DateTimePatternGenerator.java"
+            line="315"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getDateTimeFormat()` is a flagged API and should be inside an `if (Flags.icuVApi())` check (or annotate the surrounding method `getBestPattern` with `@FlaggedApi(Flags.FLAG_ICU_V_API) to transfer requirement to caller`)"
+        errorLine1="                getDateTimeFormat(style), 2, 2, timePattern, datePattern);"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="external/icu/android_icu4j/src/main/java/android/icu/text/DateTimePatternGenerator.java"
+            line="702"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setDateTimeFormat()` is a flagged API and should be inside an `if (Flags.icuVApi())` check (or annotate the surrounding method `setDateTimeFormat` with `@FlaggedApi(Flags.FLAG_ICU_V_API) to transfer requirement to caller`)"
+        errorLine1="            setDateTimeFormat(style, dateTimeFormat);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="external/icu/android_icu4j/src/main/java/android/icu/text/DateTimePatternGenerator.java"
+            line="1048"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getDateTimeFormat()` is a flagged API and should be inside an `if (Flags.icuVApi())` check (or annotate the surrounding method `getDateTimeFormat` with `@FlaggedApi(Flags.FLAG_ICU_V_API) to transfer requirement to caller`)"
+        errorLine1="        return getDateTimeFormat(DateFormat.MEDIUM);"
+        errorLine2="               ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="external/icu/android_icu4j/src/main/java/android/icu/text/DateTimePatternGenerator.java"
+            line="1063"
+            column="16"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Field `UNICODE_15_1` is a flagged API and should be inside an `if (Flags.icuVApi())` check (or annotate the surrounding method `?` with `@FlaggedApi(Flags.FLAG_ICU_V_API) to transfer requirement to caller`)"
+        errorLine1="        UNICODE_15_1   = getInstance(15, 1, 0, 0);"
+        errorLine2="        ~~~~~~~~~~~~">
+        <location
+            file="external/icu/android_icu4j/src/main/java/android/icu/util/VersionInfo.java"
+            line="528"
+            column="9"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Field `UNICODE_15_1` is a flagged API and should be inside an `if (Flags.icuVApi())` check (or annotate the surrounding method `?` with `@FlaggedApi(Flags.FLAG_ICU_V_API) to transfer requirement to caller`)"
+        errorLine1="        UNICODE_VERSION = UNICODE_15_1;"
+        errorLine2="                          ~~~~~~~~~~~~">
+        <location
+            file="external/icu/android_icu4j/src/main/java/android/icu/util/VersionInfo.java"
+            line="532"
+            column="27"/>
+    </issue>
+
+</issues>
diff --git a/android_icu4j/src/main/tests/android/icu/dev/data/cldr/localeIdentifiers/likelySubtags.txt b/android_icu4j/src/main/tests/android/icu/dev/data/cldr/localeIdentifiers/likelySubtags.txt
index 76c7f4c29..b78342d30 100644
--- a/android_icu4j/src/main/tests/android/icu/dev/data/cldr/localeIdentifiers/likelySubtags.txt
+++ b/android_icu4j/src/main/tests/android/icu/dev/data/cldr/localeIdentifiers/likelySubtags.txt
@@ -1,5 +1,5 @@
 # Test data for Likely Subtags
-#  Copyright © 1991-2023 Unicode, Inc.
+#  Copyright © 1991-2024 Unicode, Inc.
 #  For terms of use, see http://www.unicode.org/copyright.html
 #  SPDX-License-Identifier: Unicode-3.0
 #  CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
diff --git a/android_icu4j/src/main/tests/android/icu/dev/test/calendar/IBMCalendarTest.java b/android_icu4j/src/main/tests/android/icu/dev/test/calendar/IBMCalendarTest.java
index 529850a4c..bcce28e5f 100644
--- a/android_icu4j/src/main/tests/android/icu/dev/test/calendar/IBMCalendarTest.java
+++ b/android_icu4j/src/main/tests/android/icu/dev/test/calendar/IBMCalendarTest.java
@@ -238,7 +238,10 @@ public class IBMCalendarTest extends CalendarTestFmwk {
 
         // Test -u-rg- value
         verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-mvzzzz-sd-usca", Calendar.FRIDAY);
-        verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-aezzzz-sd-usca", Calendar.SATURDAY);
+        // Android-changed: the first week day in UAE is Monday.
+        // verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-aezzzz-sd-usca", Calendar.SATURDAY);
+        verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-aezzzz-sd-usca", Calendar.MONDAY);
+
         verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-uszzzz-sd-usca", Calendar.SUNDAY);
         verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-gbzzzz-sd-usca", Calendar.MONDAY);
 
@@ -249,7 +252,9 @@ public class IBMCalendarTest extends CalendarTestFmwk {
 
         // Test Region Tags only
         verifyFirstDayOfWeek("en-MV", Calendar.FRIDAY);
-        verifyFirstDayOfWeek("en-AE", Calendar.SATURDAY);
+        // Android-changed: the first week day in UAE is Monday.
+        // verifyFirstDayOfWeek("en-AE", Calendar.SATURDAY);
+        verifyFirstDayOfWeek("en-AE", Calendar.MONDAY);
         verifyFirstDayOfWeek("en-US", Calendar.SUNDAY);
         verifyFirstDayOfWeek("dv-GB", Calendar.MONDAY);
 
@@ -265,8 +270,11 @@ public class IBMCalendarTest extends CalendarTestFmwk {
         // und_Thaa => dv_Thaa_MV => Friday
         verifyFirstDayOfWeek("und-Thaa", Calendar.FRIDAY);
 
+        // Android-changed: the first week day in UAE is Monday.
         // ssh => ssh_Arab_AE => Saturday
-        verifyFirstDayOfWeek("ssh", Calendar.SATURDAY);
+        // verifyFirstDayOfWeek("ssh", Calendar.SATURDAY);
+        // ssh => ssh_Arab_AE => Monday
+        verifyFirstDayOfWeek("ssh", Calendar.MONDAY);
         // wbl_Arab => wbl_Arab_AF => Saturday
         verifyFirstDayOfWeek("wbl-Arab", Calendar.SATURDAY);
 
diff --git a/icu4c/source/data/misc/supplementalData.txt b/icu4c/source/data/misc/supplementalData.txt
index 51736e63c..4ed65276f 100644
--- a/icu4c/source/data/misc/supplementalData.txt
+++ b/icu4c/source/data/misc/supplementalData.txt
@@ -36062,7 +36062,7 @@ supplementalData:table(nofallback){
             86400000,
         }
         AE:intvector{
-            7,
+            2,
             1,
             7,
             0,
diff --git a/icu4c/source/data/misc/units.txt b/icu4c/source/data/misc/units.txt
index c01febe10..e9e429cb0 100644
--- a/icu4c/source/data/misc/units.txt
+++ b/icu4c/source/data/misc/units.txt
@@ -2004,6 +2004,16 @@ units:table(nofallback){
                         unit{"kilometer-per-hour"}
                     }
                 }
+                CN{
+                    {
+                        unit{"meter-per-second"}
+                    }
+                }
+                DK{
+                    {
+                        unit{"meter-per-second"}
+                    }
+                }
                 FI{
                     {
                         unit{"meter-per-second"}
@@ -2014,6 +2024,11 @@ units:table(nofallback){
                         unit{"mile-per-hour"}
                     }
                 }
+                JP{
+                    {
+                        unit{"meter-per-second"}
+                    }
+                }
                 KR{
                     {
                         unit{"meter-per-second"}
diff --git a/icu4c/source/stubdata/Android.bp b/icu4c/source/stubdata/Android.bp
index d9457eeb5..6e78c00a8 100644
--- a/icu4c/source/stubdata/Android.bp
+++ b/icu4c/source/stubdata/Android.bp
@@ -48,19 +48,3 @@ prebuilt_root_host {
         dir: "layoutlib_native/icu",
     },
 }
-
-// Module definition producing ICU .dat prebuilt files in
-// /system/etc/icu for standalone ART testing purposes. This is a
-// temporary change needed until the ART Buildbot and Golem both fully
-// support the ART APEX (see b/121117762). This module should never
-// be shipped by default (i.e. should never be part of
-// `PRODUCT_PACKAGE`.)
-//
-// TODO(b/121117762): Remove this module definition when the ART
-// Buildbot and Golem have full support for the ART APEX.
-prebuilt_etc {
-    name: "icu-data-art-test-i18n",
-    src: dat_file,
-    filename_from_src: true,
-    relative_install_path: "i18n_module/etc/icu",
-}
diff --git a/icu4c/source/stubdata/icudt75l.dat b/icu4c/source/stubdata/icudt75l.dat
index 4e9751ba2..abaff46a2 100644
Binary files a/icu4c/source/stubdata/icudt75l.dat and b/icu4c/source/stubdata/icudt75l.dat differ
diff --git a/icu4c/source/test/intltest/caltest.cpp b/icu4c/source/test/intltest/caltest.cpp
index bace8d762..e8fa7f7cc 100644
--- a/icu4c/source/test/intltest/caltest.cpp
+++ b/icu4c/source/test/intltest/caltest.cpp
@@ -5602,7 +5602,9 @@ void CalendarTest::TestFirstDayOfWeek() {
 
     // Test -u-rg- value
     verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-mvzzzz-sd-usca", UCAL_FRIDAY);
-    verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-aezzzz-sd-usca", UCAL_SATURDAY);
+    // Android-changed: the first week day in UAE is Monday.
+    // verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-aezzzz-sd-usca", UCAL_SATURDAY);
+    verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-aezzzz-sd-usca", UCAL_MONDAY);
     verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-uszzzz-sd-usca", UCAL_SUNDAY);
     verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-gbzzzz-sd-usca", UCAL_MONDAY);
 
@@ -5613,13 +5615,17 @@ void CalendarTest::TestFirstDayOfWeek() {
 
     // Test Region Tags only
     verifyFirstDayOfWeek("en-MV", UCAL_FRIDAY);
-    verifyFirstDayOfWeek("en-AE", UCAL_SATURDAY);
+    // Android-changed: the first week day in UAE is Monday.
+    // verifyFirstDayOfWeek("en-AE", UCAL_SATURDAY);
+    verifyFirstDayOfWeek("en-AE", UCAL_MONDAY);
     verifyFirstDayOfWeek("en-US", UCAL_SUNDAY);
     verifyFirstDayOfWeek("dv-GB", UCAL_MONDAY);
 
     // Test -u-sd-
     verifyFirstDayOfWeek("en-u-sd-mv00", UCAL_FRIDAY);
-    verifyFirstDayOfWeek("en-u-sd-aeaj", UCAL_SATURDAY);
+    // Android-changed: the first week day in UAE is Monday.
+    // verifyFirstDayOfWeek("en-u-sd-aeaj", UCAL_SATURDAY);
+    verifyFirstDayOfWeek("en-u-sd-aeaj", UCAL_MONDAY);
     verifyFirstDayOfWeek("en-u-sd-usca", UCAL_SUNDAY);
     verifyFirstDayOfWeek("dv-u-sd-gbsct", UCAL_MONDAY);
 
@@ -5629,8 +5635,11 @@ void CalendarTest::TestFirstDayOfWeek() {
     // und_Thaa => dv_Thaa_MV => Friday
     verifyFirstDayOfWeek("und-Thaa", UCAL_FRIDAY);
 
+    // Android-changed: the first week day in UAE is Monday.
     // ssh => ssh_Arab_AE => Saturday
-    verifyFirstDayOfWeek("ssh", UCAL_SATURDAY);
+    // verifyFirstDayOfWeek("ssh", UCAL_SATURDAY);
+    // ssh => ssh_Arab_AE => Monday
+    verifyFirstDayOfWeek("ssh", UCAL_MONDAY);
     // wbl_Arab => wbl_Arab_AF => Saturday
     verifyFirstDayOfWeek("wbl-Arab", UCAL_SATURDAY);
 
diff --git a/icu4j/Android.bp b/icu4j/Android.bp
index cdca9e263..cea953820 100644
--- a/icu4j/Android.bp
+++ b/icu4j/Android.bp
@@ -181,11 +181,10 @@ java_library {
     jarjar_rules: "liblayout-jarjar-rules.txt",
 }
 
-// Compatibility alias until references to icu4j-host are removed
-//
-// When converting .mk files to .bp files do not change the visibility of this
-// module, instead replace usages of this with icu4j
 java_library_host {
     name: "icu4j-host",
     static_libs: ["icu4j"],
+    visibility: [
+        "//vendor:__subpackages__",
+    ],
 }
diff --git a/icu4j/main/core/src/main/resources/com/ibm/icu/impl/data/icudt75b/supplementalData.res b/icu4j/main/core/src/main/resources/com/ibm/icu/impl/data/icudt75b/supplementalData.res
index 816b1ff8a..4b73cccd4 100644
Binary files a/icu4j/main/core/src/main/resources/com/ibm/icu/impl/data/icudt75b/supplementalData.res and b/icu4j/main/core/src/main/resources/com/ibm/icu/impl/data/icudt75b/supplementalData.res differ
diff --git a/icu4j/main/core/src/main/resources/com/ibm/icu/impl/data/icudt75b/units.res b/icu4j/main/core/src/main/resources/com/ibm/icu/impl/data/icudt75b/units.res
index 89be0576d..00568b98e 100644
Binary files a/icu4j/main/core/src/main/resources/com/ibm/icu/impl/data/icudt75b/units.res and b/icu4j/main/core/src/main/resources/com/ibm/icu/impl/data/icudt75b/units.res differ
diff --git a/icu4j/main/core/src/test/java/com/ibm/icu/dev/test/calendar/IBMCalendarTest.java b/icu4j/main/core/src/test/java/com/ibm/icu/dev/test/calendar/IBMCalendarTest.java
index 66e3d6165..f80c12f5a 100644
--- a/icu4j/main/core/src/test/java/com/ibm/icu/dev/test/calendar/IBMCalendarTest.java
+++ b/icu4j/main/core/src/test/java/com/ibm/icu/dev/test/calendar/IBMCalendarTest.java
@@ -235,7 +235,10 @@ public class IBMCalendarTest extends CalendarTestFmwk {
 
         // Test -u-rg- value
         verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-mvzzzz-sd-usca", Calendar.FRIDAY);
-        verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-aezzzz-sd-usca", Calendar.SATURDAY);
+        // Android-changed: the first week day in UAE is Monday.
+        // verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-aezzzz-sd-usca", Calendar.SATURDAY);
+        verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-aezzzz-sd-usca", Calendar.MONDAY);
+
         verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-uszzzz-sd-usca", Calendar.SUNDAY);
         verifyFirstDayOfWeek("en-MV-u-ca-iso8601-rg-gbzzzz-sd-usca", Calendar.MONDAY);
 
@@ -246,7 +249,9 @@ public class IBMCalendarTest extends CalendarTestFmwk {
 
         // Test Region Tags only
         verifyFirstDayOfWeek("en-MV", Calendar.FRIDAY);
-        verifyFirstDayOfWeek("en-AE", Calendar.SATURDAY);
+        // Android-changed: the first week day in UAE is Monday.
+        // verifyFirstDayOfWeek("en-AE", Calendar.SATURDAY);
+        verifyFirstDayOfWeek("en-AE", Calendar.MONDAY);
         verifyFirstDayOfWeek("en-US", Calendar.SUNDAY);
         verifyFirstDayOfWeek("dv-GB", Calendar.MONDAY);
 
@@ -262,8 +267,11 @@ public class IBMCalendarTest extends CalendarTestFmwk {
         // und_Thaa => dv_Thaa_MV => Friday
         verifyFirstDayOfWeek("und-Thaa", Calendar.FRIDAY);
 
+        // Android-changed: the first week day in UAE is Monday.
         // ssh => ssh_Arab_AE => Saturday
-        verifyFirstDayOfWeek("ssh", Calendar.SATURDAY);
+        // verifyFirstDayOfWeek("ssh", Calendar.SATURDAY);
+        // ssh => ssh_Arab_AE => Monday
+        verifyFirstDayOfWeek("ssh", Calendar.MONDAY);
         // wbl_Arab => wbl_Arab_AF => Saturday
         verifyFirstDayOfWeek("wbl-Arab", Calendar.SATURDAY);
 
diff --git a/icu4j/main/shared/data/icudata.jar b/icu4j/main/shared/data/icudata.jar
index daf3975be..02f67cd54 100644
Binary files a/icu4j/main/shared/data/icudata.jar and b/icu4j/main/shared/data/icudata.jar differ
diff --git a/libicu/Android.bp b/libicu/Android.bp
index fb291fe56..55ca7d5b5 100644
--- a/libicu/Android.bp
+++ b/libicu/Android.bp
@@ -29,9 +29,6 @@ ndk_library {
     symbol_file: "libicu.map.txt",
     first_version: "31",
     unversioned_until: "current",
-    export_header_libs: [
-        "libicu_ndk_headers",
-    ],
 }
 
 ndk_headers {
diff --git a/libicu/test/src/uchar_test.cpp b/libicu/test/src/uchar_test.cpp
index 09c54fb64..77fc3d085 100644
--- a/libicu/test/src/uchar_test.cpp
+++ b/libicu/test/src/uchar_test.cpp
@@ -31,3 +31,13 @@ TEST(Icu4cUCharTest, test_u_toupper) {
   ASSERT_EQ(U'1', u_toupper(U'1'));
   ASSERT_EQ(U'Ë', u_toupper(U'ë'));
 }
+
+TEST(Icu4cUCharTest, test_u_charFromName) {
+  UErrorCode err;
+  ASSERT_EQ(0x0020, u_charFromName(U_UNICODE_CHAR_NAME, "SPACE", &err));
+  ASSERT_EQ(0x0061, u_charFromName(U_UNICODE_CHAR_NAME, "LATIN SMALL LETTER A", &err));
+  ASSERT_EQ(0x0042, u_charFromName(U_UNICODE_CHAR_NAME, "LATIN CAPITAL LETTER B", &err));
+  ASSERT_EQ(0x00a2, u_charFromName(U_UNICODE_CHAR_NAME, "CENT SIGN", &err));
+  ASSERT_EQ(0xffe5, u_charFromName(U_UNICODE_CHAR_NAME, "FULLWIDTH YEN SIGN", &err));
+  ASSERT_EQ(0x3401, u_charFromName(U_UNICODE_CHAR_NAME, "CJK UNIFIED IDEOGRAPH-3401", &err));
+}
diff --git a/libicu/test/src/utypes_test.cpp b/libicu/test/src/utypes_test.cpp
new file mode 100644
index 000000000..083fe56bd
--- /dev/null
+++ b/libicu/test/src/utypes_test.cpp
@@ -0,0 +1,31 @@
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
+#include <gtest/gtest.h>
+
+#include <unicode/utypes.h>
+
+TEST(Icu4cUTypesTest, test_u_errorName) {
+  EXPECT_STREQ("U_ZERO_ERROR", u_errorName(U_ZERO_ERROR));
+  EXPECT_STREQ("U_ILLEGAL_ARGUMENT_ERROR", u_errorName(U_ILLEGAL_ARGUMENT_ERROR));
+  EXPECT_STREQ("U_USING_FALLBACK_WARNING", u_errorName(U_USING_FALLBACK_WARNING));
+  EXPECT_STREQ("U_BAD_VARIABLE_DEFINITION", u_errorName(U_BAD_VARIABLE_DEFINITION));
+  EXPECT_STREQ("U_UNEXPECTED_TOKEN", u_errorName(U_UNEXPECTED_TOKEN));
+  EXPECT_STREQ("U_BRK_INTERNAL_ERROR", u_errorName(U_BRK_INTERNAL_ERROR));
+  EXPECT_STREQ("U_REGEX_INTERNAL_ERROR", u_errorName(U_REGEX_INTERNAL_ERROR));
+  EXPECT_STREQ("U_STRINGPREP_PROHIBITED_ERROR", u_errorName(U_STRINGPREP_PROHIBITED_ERROR));
+  EXPECT_STREQ("U_REGEX_INTERNAL_ERROR", u_errorName(U_REGEX_INTERNAL_ERROR));
+}
```

