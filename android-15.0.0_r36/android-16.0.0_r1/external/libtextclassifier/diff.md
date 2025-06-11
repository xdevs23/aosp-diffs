```diff
diff --git a/OWNERS b/OWNERS
index fbcf965..b838b2e 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
 wangqi@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/java/Android.bp b/java/Android.bp
index 46ada4a..4f08828 100644
--- a/java/Android.bp
+++ b/java/Android.bp
@@ -75,6 +75,7 @@ android_library {
         "androidx.concurrent_concurrent-futures",
         "auto_value_annotations",
         "androidx.room_room-runtime",
+        "android.permission.flags-aconfig-java-export",
     ],
     sdk_version: "system_current",
     min_sdk_version: "30",
@@ -85,6 +86,7 @@ android_library {
         "//apex_available:platform",
         "com.android.extservices",
     ],
+    jarjar_rules: "jarjar-rules.txt",
 
 }
 
@@ -105,7 +107,7 @@ genrule {
     name: "statslog-textclassifier-java-gen",
     tools: ["stats-log-api-gen"],
     cmd: "$(location stats-log-api-gen) --java $(out) --module textclassifier" +
-         " --javaPackage com.android.textclassifier.common.statsd" +
-         " --javaClass TextClassifierStatsLog --minApiLevel 30",
+        " --javaPackage com.android.textclassifier.common.statsd" +
+        " --javaClass TextClassifierStatsLog --minApiLevel 30",
     out: ["com/android/textclassifier/common/statsd/TextClassifierStatsLog.java"],
 }
diff --git a/java/jarjar-rules.txt b/java/jarjar-rules.txt
new file mode 100644
index 0000000..59d55ee
--- /dev/null
+++ b/java/jarjar-rules.txt
@@ -0,0 +1 @@
+rule android.permission.flags.** com.android.extservices.jarjar.@0
\ No newline at end of file
diff --git a/java/src/com/android/textclassifier/TextClassifierImpl.java b/java/src/com/android/textclassifier/TextClassifierImpl.java
index abe8994..8822ec7 100644
--- a/java/src/com/android/textclassifier/TextClassifierImpl.java
+++ b/java/src/com/android/textclassifier/TextClassifierImpl.java
@@ -60,6 +60,8 @@ import com.android.textclassifier.common.statsd.TextClassificationSessionIdConve
 import com.android.textclassifier.common.statsd.TextClassifierEventConverter;
 import com.android.textclassifier.common.statsd.TextClassifierEventLogger;
 import com.android.textclassifier.utils.IndentingPrintWriter;
+import com.android.textclassifier.utils.TextClassifierUtils;
+
 import com.google.android.textclassifier.ActionsSuggestionsModel;
 import com.google.android.textclassifier.ActionsSuggestionsModel.ActionSuggestions;
 import com.google.android.textclassifier.AnnotatorModel;
@@ -293,6 +295,12 @@ final class TextClassifierImpl {
                 .resolveEntityListModifications(
                     getEntitiesForHints(request.getEntityConfig().getHints()))
             : settings.getEntityListDefault();
+
+    if (TextClassifierUtils.isOtpClassificationEnabled() && entitiesToIdentify.contains(
+            TextClassifierUtils.TYPE_OTP)) {
+      TextClassifierOtpHelper.addOtpLink(request.getText().toString(), this, builder);
+    }
+
     final String localesString = concatenateLocales(request.getDefaultLocales());
     LangIdModel langId = getLangIdImpl();
     ImmutableList<String> detectLanguageTags = detectLanguageTags(langId, request.getText());
diff --git a/java/src/com/android/textclassifier/TextClassifierOtpHelper.java b/java/src/com/android/textclassifier/TextClassifierOtpHelper.java
new file mode 100644
index 0000000..9e924c5
--- /dev/null
+++ b/java/src/com/android/textclassifier/TextClassifierOtpHelper.java
@@ -0,0 +1,366 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.textclassifier;
+
+import static java.lang.String.format;
+
+import android.icu.util.ULocale;
+import android.os.Bundle;
+import android.util.ArrayMap;
+import android.view.textclassifier.TextLanguage;
+import android.view.textclassifier.TextLinks;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.textclassifier.common.base.TcLog;
+import com.android.textclassifier.utils.TextClassifierUtils;
+
+import com.google.common.annotations.VisibleForTesting;
+
+import java.io.IOException;
+import java.util.Collections;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
+
+/**
+ * Class with helper methods related to detecting OTP codes in a text.
+ */
+public class TextClassifierOtpHelper {
+  private static final String TAG = TextClassifierOtpHelper.class.getSimpleName();
+
+  private static final int PATTERN_FLAGS =
+      Pattern.DOTALL | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;
+
+  private static ThreadLocal<Matcher> compileToRegex(String pattern) {
+    return ThreadLocal.withInitial(() -> Pattern.compile(pattern, PATTERN_FLAGS).matcher(""));
+  }
+
+  private static final float TC_THRESHOLD = 0.6f;
+
+  private static final ArrayMap<String, ThreadLocal<Matcher>> EXTRA_LANG_OTP_REGEX =
+      new ArrayMap<>();
+
+  private static final ThreadLocal<Matcher> OTP_REGEX = compileToRegex(RegExStrings.ALL_OTP);
+
+  /**
+   * A combination of common false positives. These matches are expected to be longer than (or equal
+   * in length to) otp matches
+   */
+  private static final ThreadLocal<Matcher> FALSE_POSITIVE_REGEX =
+      compileToRegex(RegExStrings.FALSE_POSITIVE);
+
+  /**
+   * Creates a regular expression to match any of a series of individual words, case insensitive. It
+   * also verifies the position of the word, relative to the OTP match
+   */
+  private static ThreadLocal<Matcher> createDictionaryRegex(String[] words) {
+    StringBuilder regex = new StringBuilder("(");
+    for (int i = 0; i < words.length; i++) {
+      regex.append(findContextWordWithCode(words[i]));
+      if (i != words.length - 1) {
+        regex.append("|");
+      }
+    }
+    regex.append(")");
+    return compileToRegex(regex.toString());
+  }
+
+  /**
+   * Creates a regular expression that will find a context word, if that word occurs in the sentence
+   * preceding an OTP, or in the same sentence as an OTP (before or after). In both cases, the
+   * context word must occur within 50 characters of the suspected OTP
+   *
+   * @param contextWord The context word we expect to find around the OTP match
+   * @return A string representing a regular expression that will determine if we found a context
+   *     word occurring before an otp match, or after it, but in the same sentence.
+   */
+  private static String findContextWordWithCode(String contextWord) {
+    String boundedContext = "\\b" + contextWord + "\\b";
+    // Asserts that we find the OTP code within 50 characters after the context word, with at
+    // most one sentence punctuation between the OTP code and the context word (i.e. they are
+    // in the same sentence, or the context word is in the previous sentence)
+    String contextWordBeforeOtpInSameOrPreviousSentence =
+        String.format("(%s(?=.{1,50}%s)[^.?!]*[.?!]?[^.?!]*%s)", boundedContext, RegExStrings.ALL_OTP, RegExStrings.ALL_OTP);
+    // Asserts that we find the context word within 50 characters after the OTP code, with no
+    // sentence punctuation between the OTP code and the context word (i.e. they are in the same
+    // sentence)
+    String contextWordAfterOtpSameSentence =
+        String.format("(%s)[^.!?]{1,50}%s", RegExStrings.ALL_OTP, boundedContext);
+    return String.format(
+        "(%s|%s)", contextWordBeforeOtpInSameOrPreviousSentence, contextWordAfterOtpSameSentence);
+  }
+
+  static {
+    EXTRA_LANG_OTP_REGEX.put(
+        ULocale.ENGLISH.toLanguageTag(), createDictionaryRegex(RegExStrings.ENGLISH_CONTEXT_WORDS));
+  }
+
+  /**
+   * Checks if the text might contain an OTP, if so, adds a link to the builder with type as OTP
+   *
+   * @param text    The text whose content should be checked for OTP
+   * @param tcImpl  Instance of the TextClassifierImpl
+   * @param builder TextLinks builder object to whom the OTP link to be added
+   */
+  public static void addOtpLink(@NonNull String text, @NonNull TextClassifierImpl tcImpl,
+          @NonNull TextLinks.Builder builder) {
+    if (!containsOtp(text, tcImpl)) {
+      return;
+    }
+    final Map<String, Float> entityScores = Collections.singletonMap(TextClassifierUtils.TYPE_OTP,
+            1f);
+    builder.addLink(0, 0, entityScores, new Bundle());
+  }
+
+  /**
+   * Checks if a string of text might contain an OTP, based on several regular expressions, and
+   * potentially using a textClassifier to eliminate false positives
+   *
+   * @param text   The text whose content should be checked
+   * @param tcImpl If non null, the provided TextClassifierImpl will be used to find the language
+   *               of the text, and look for a language-specific regex for it.
+   * @return True if we believe an OTP is in the message, false otherwise.
+   */
+  protected static boolean containsOtp(
+          @NonNull String text,
+          @NonNull TextClassifierImpl tcImpl) {
+    if (!containsOtpLikePattern(text)) {
+      return false;
+    }
+
+    ULocale language = getLanguageWithRegex(text, tcImpl);
+    if (language == null) {
+      return false;
+    }
+    return hasLanguageSpecificOtpWord(text, language.toLanguageTag());
+  }
+
+  /**
+   * Checks if the given text contains a pattern resembling an OTP.
+   *
+   * <p>This method attempts to identify such patterns by matching against a regular expression.
+   * Avoids false positives by checking for common patterns that might be mistaken for OTPs, such
+   * as phone numbers or dates.</p>
+   *
+   * @param text The text to be checked.
+   * @return {@code true} if the text contains an OTP-like pattern, {@code false} otherwise.
+   */
+  @VisibleForTesting
+  protected static boolean containsOtpLikePattern(String text) {
+    Set<String> otpMatches = getAllMatches(text, OTP_REGEX.get());
+    if (otpMatches.isEmpty()) {
+      return false;
+    }
+    Set<String> falsePositives = getAllMatches(text, FALSE_POSITIVE_REGEX.get());
+
+    // This optional, but having this would help with performance
+    // Example: "Your OTP code is 1234 and this is sent on 01-01-2001"
+    // At this point -> otpMatches: [1234, 01-01-2001] falsePositives=[01-01-2001]
+    // It filters "01-01-2001" in advance and continues to next checks with otpMatches: [1234]
+    otpMatches.removeAll(falsePositives);
+
+    // Following is to handle text like: "Your OTP can't be shared at this point, please call
+    // (888) 888-8888"
+    // otpMatches: [888-8888] falsePositives=[(888) 888-8888] final=[]
+    for (String otpMatch : otpMatches) {
+      boolean currentOtpIsFalsePositive = false;
+      for (String falsePositive : falsePositives) {
+        if (falsePositive.contains(otpMatch)) {
+          currentOtpIsFalsePositive = true;
+          break;
+        }
+      }
+      if (!currentOtpIsFalsePositive) {
+        return true;
+      }
+    }
+    return false;
+  }
+
+  /**
+   * Checks if the given text contains a language-specific word or phrase associated with OTPs.
+   * This method uses regular expressions defined for specific languages to identify these words.
+   *
+   * @param text The text to check.
+   * @param languageTag The language tag (e.g., "en", "es", "fr") for which to check.
+   * @return {@code true} if the text contains a language-specific OTP word, {@code false} otherwise.
+   *         Returns {@code false} if no language-specific regex is defined for the given tag.
+   */
+  @VisibleForTesting
+  protected static boolean hasLanguageSpecificOtpWord(@NonNull String text, @NonNull String languageTag) {
+    if (!EXTRA_LANG_OTP_REGEX.containsKey(languageTag)){
+      return false;
+    }
+    Matcher languageSpecificMatcher = EXTRA_LANG_OTP_REGEX.get(languageTag).get();
+    if (languageSpecificMatcher == null) {
+      return false;
+    }
+    languageSpecificMatcher.reset(text);
+    return languageSpecificMatcher.find();
+  }
+
+  private static Set<String> getAllMatches(String text, Matcher regex) {
+    Set<String> matches = new HashSet<>();
+    regex.reset(text);
+    while (regex.find()) {
+      matches.add(regex.group());
+    }
+    return matches;
+  }
+
+  // Tries to determine the language of the given text. Will return the language with the highest
+  // confidence score that meets the minimum threshold, and has a language-specific regex, null
+  // otherwise
+  @Nullable
+  private static ULocale getLanguageWithRegex(String text, @NonNull TextClassifierImpl tcImpl) {
+    float highestConfidence = 0;
+    ULocale highestConfidenceLocale = null;
+    TextLanguage.Request langRequest = new TextLanguage.Request.Builder(text).build();
+    TextLanguage lang;
+    try {
+      lang = tcImpl.detectLanguage(null, null, langRequest);
+    } catch (IOException e) {
+      TcLog.e(TAG, "Except detecting language", e);
+      return null;
+    }
+    for (int i = 0; i < lang.getLocaleHypothesisCount(); i++) {
+      ULocale locale = lang.getLocale(i);
+      float confidence = lang.getConfidenceScore(locale);
+      if (confidence >= TC_THRESHOLD
+          && confidence >= highestConfidence
+          && EXTRA_LANG_OTP_REGEX.containsKey(locale.toLanguageTag())) {
+        highestConfidence = confidence;
+        highestConfidenceLocale = locale;
+      }
+    }
+    return highestConfidenceLocale;
+  }
+
+  private TextClassifierOtpHelper() {}
+
+  private static class RegExStrings {
+    /*
+     * A regex matching a line start, open paren, arrow, colon (not proceeded by a digit), open square
+     * bracket, equals sign, double or single quote, ideographic char, or a space that is not preceded
+     * by a number. It will not consume the start char (meaning START won't be included in the matched
+     * string)
+     */
+    private static final String START =
+            "(^|(?<=((^|[^0-9])\\s)|[>(\"'=\\[\\p{IsIdeographic}]|[^0-9]:))";
+
+    /*
+     * A regex matching a line end, a space that is not followed by a number, an ideographic char, or
+     * a period, close paren, close square bracket, single or double quote, exclamation point,
+     * question mark, or comma. It will not consume the end char
+     */
+    private static final String END = "(?=\\s[^0-9]|$|\\p{IsIdeographic}|[.?!,)'\\]\"])";
+
+    private static final String ALL_OTP;
+
+    static {
+      /* One single OTP char. A number or alphabetical char (that isn't also ideographic) */
+      final String OTP_CHAR = "([0-9\\p{IsAlphabetic}&&[^\\p{IsIdeographic}]])";
+
+      /* One OTP char, followed by an optional dash */
+      final String OTP_CHAR_WITH_DASH = format("(%s-?)", OTP_CHAR);
+
+      /*
+       * Performs a lookahead to find a digit after 0 to 7 OTP_CHARs. This ensures that our potential
+       * OTP code contains at least one number
+       */
+      final String FIND_DIGIT = format("(?=%s{0,7}\\d)", OTP_CHAR_WITH_DASH);
+
+      /*
+       * Matches between 5 and 8 otp chars, with dashes in between. Here, we are assuming an OTP code is
+       * 5-8 characters long. The last char must not be followed by a dash
+       */
+      final String OTP_CHARS = format("(%s{4,7}%s)", OTP_CHAR_WITH_DASH, OTP_CHAR);
+
+      /* A regex matching four digit numerical codes */
+      final String FOUR_DIGITS = "(\\d{4})";
+
+      final String FIVE_TO_EIGHT_ALPHANUM_AT_LEAST_ONE_NUM =
+              format("(%s%s)", FIND_DIGIT, OTP_CHARS);
+
+      /* A regex matching two pairs of 3 digits (ex "123 456") */
+      final String SIX_DIGITS_WITH_SPACE = "(\\d{3}\\s\\d{3})";
+
+      /*
+       * Combining the regular expressions above, we get an OTP regex: 1. search for START, THEN 2.
+       * match ONE of a. alphanumeric sequence, at least one number, length 5-8, with optional dashes b.
+       * 4 numbers in a row c. pair of 3 digit codes separated by a space THEN 3. search for END Ex:
+       * "6454", " 345 678.", "[YDT-456]"
+       */
+      ALL_OTP =
+              format(
+                      "%s(%s|%s|%s)%s",
+                      START, FIVE_TO_EIGHT_ALPHANUM_AT_LEAST_ONE_NUM, FOUR_DIGITS,
+                      SIX_DIGITS_WITH_SPACE, END);
+    }
+
+    private static final String FALSE_POSITIVE;
+
+    static {
+      /*
+       * A Date regular expression. Looks for dates with the month, day, and year separated by dashes.
+       * Handles one and two digit months and days, and four or two-digit years. It makes the following
+       * assumptions: Dates and months will never be higher than 39 If a four digit year is used, the
+       * leading digit will be 1 or 2
+       */
+      final String DATE_WITH_DASHES = "([0-3]?\\d-[0-3]?\\d-([12]\\d)?\\d\\d)";
+
+      /*
+       * matches a ten digit phone number, when the area code is separated by a space or dash. Supports
+       * optional parentheses around the area code, and an optional dash or space in between the rest of
+       * the numbers. This format registers as an otp match due to the space between the area code and
+       * the rest, but shouldn't.
+       */
+      final String PHONE_WITH_SPACE = "(\\(?\\d{3}\\)?(-|\\s)?\\d{3}(-|\\s)?\\d{4})";
+
+      /*
+       * A combination of common false positives. These matches are expected to be longer than (or equal
+       * in length to) otp matches.
+       */
+      FALSE_POSITIVE = format("%s(%s|%s)%s", START, DATE_WITH_DASHES, PHONE_WITH_SPACE, END);
+    }
+
+    /**
+     * A list of regular expressions representing words found in an OTP context (non case sensitive)
+     * Note: TAN is short for Transaction Authentication Number
+     */
+    private static final String[] ENGLISH_CONTEXT_WORDS =
+            new String[] {
+                    "pin",
+                    "pass[-\\s]?(code|word)",
+                    "TAN",
+                    "otp",
+                    "2fa",
+                    "(two|2)[-\\s]?factor",
+                    "log[-\\s]?in",
+                    "auth(enticat(e|ion))?",
+                    "code",
+                    "secret",
+                    "verif(y|ication)",
+                    "one(\\s|-)?time",
+                    "access",
+                    "validat(e|ion)"
+            };
+  }
+}
diff --git a/java/src/com/android/textclassifier/utils/TextClassifierUtils.java b/java/src/com/android/textclassifier/utils/TextClassifierUtils.java
new file mode 100644
index 0000000..9ab5e3f
--- /dev/null
+++ b/java/src/com/android/textclassifier/utils/TextClassifierUtils.java
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.textclassifier.utils;
+
+import android.os.Build;
+import android.permission.flags.Flags;
+import android.view.textclassifier.TextClassifier;
+
+public class TextClassifierUtils {
+    public static final String TYPE_OTP = getOtpType();
+
+    private static String getOtpType() {
+        if (!isAtLeastB() || !Flags.textClassifierChoiceApiEnabled()) {
+            return "otp";
+        }
+        return TextClassifier.TYPE_OTP;
+    }
+
+    private static boolean isAtLeastB() {
+        return Build.VERSION.CODENAME.equals("Baklava")
+                || Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA;
+    }
+
+    public static boolean isOtpClassificationEnabled() {
+        return isAtLeastB() && Flags.textClassifierChoiceApiEnabled()
+                && Flags.enableOtpInTextClassifiers();
+    }
+}
diff --git a/java/tests/instrumentation/Android.bp b/java/tests/instrumentation/Android.bp
index 9f034e1..50e8945 100644
--- a/java/tests/instrumentation/Android.bp
+++ b/java/tests/instrumentation/Android.bp
@@ -49,6 +49,7 @@ android_test {
 
     srcs: [
         "src/**/*.java",
+        "src/**/*.kt",
     ],
 
     exclude_srcs: [
@@ -56,7 +57,6 @@ android_test {
         "src/com/android/textclassifier/testing/*.java",
     ],
 
-
     static_libs: [
         "androidx.test.ext.junit",
         "androidx.test.espresso.core",
@@ -75,14 +75,15 @@ android_test {
 
     jni_libs: [
         "libtextclassifier",
-        "libdexmakerjvmtiagent"
+        "libdexmakerjvmtiagent",
     ],
 
     test_suites: [
-        "general-tests", "mts-extservices"
+        "general-tests",
+        "mts-extservices",
     ],
 
-    plugins: ["androidx.room_room-compiler-plugin",],
+    plugins: ["androidx.room_room-compiler-plugin"],
     min_sdk_version: "30",
     sdk_version: "system_current",
     use_embedded_native_libs: true,
@@ -116,7 +117,7 @@ android_test {
     ],
 
     test_suites: [
-        "general-tests"
+        "general-tests",
     ],
 
     min_sdk_version: "30",
diff --git a/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierImplTest.java b/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierImplTest.java
index 8a4487d..4f64c18 100644
--- a/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierImplTest.java
+++ b/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierImplTest.java
@@ -34,6 +34,8 @@ import android.content.Intent;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.LocaleList;
+import android.permission.flags.Flags;
+import android.platform.test.annotations.RequiresFlagsEnabled;
 import android.text.Spannable;
 import android.text.SpannableString;
 import android.view.textclassifier.ConversationAction;
@@ -52,6 +54,8 @@ import com.android.textclassifier.common.ModelType;
 import com.android.textclassifier.common.TextClassifierSettings;
 import com.android.textclassifier.testing.FakeContextBuilder;
 import com.android.textclassifier.testing.TestingDeviceConfig;
+import com.android.textclassifier.utils.TextClassifierUtils;
+
 import com.google.android.textclassifier.AnnotatorModel;
 import com.google.common.collect.ImmutableList;
 import java.io.IOException;
@@ -62,6 +66,7 @@ import java.util.List;
 import org.hamcrest.BaseMatcher;
 import org.hamcrest.Description;
 import org.hamcrest.Matcher;
+import org.junit.Assume;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -323,6 +328,33 @@ public class TextClassifierImplTest {
         isTextLinksContaining(text, "+12122537077", TextClassifier.TYPE_PHONE));
   }
 
+  @Test
+  @RequiresFlagsEnabled(Flags.FLAG_ENABLE_OTP_IN_TEXT_CLASSIFIERS)
+  public void testGenerateLinks_otp() throws IOException {
+    Assume.assumeTrue(TextClassifierUtils.isOtpClassificationEnabled());
+    String text = "Your OTP code is 123456";
+    List<String> included = new ArrayList<>(List.of(TextClassifier.TYPE_OTP));
+    TextClassifier.EntityConfig config =
+            new TextClassifier.EntityConfig.Builder()
+                    .setIncludedTypes(included)
+                    .includeTypesFromTextClassifier(false)
+                    .build();
+    TextLinks.Request request = new TextLinks.Request.Builder(text).setEntityConfig(config).build();
+    assertThat(
+            classifier.generateLinks(null, null, request),
+            isTextLinksContaining(text, "", TextClassifier.TYPE_OTP));
+  }
+
+  @Test
+  @RequiresFlagsEnabled(Flags.FLAG_ENABLE_OTP_IN_TEXT_CLASSIFIERS)
+  public void testGenerateLinks_otpTypeNotInRequest() throws IOException {
+    Assume.assumeTrue(TextClassifierUtils.isOtpClassificationEnabled());
+    String text = "Your OTP code is 123456";
+    TextLinks.Request request = new TextLinks.Request.Builder(text).build();
+    assertThat(
+            classifier.generateLinks(null, null, request).getLinks()).isEmpty();
+  }
+
   @Test
   public void testGenerateLinks_exclude() throws IOException {
     String text = "The number is +12122537077. See you tonight!";
diff --git a/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierOtpHelperTest.kt b/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierOtpHelperTest.kt
new file mode 100644
index 0000000..467e453
--- /dev/null
+++ b/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierOtpHelperTest.kt
@@ -0,0 +1,355 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.textclassifier
+
+import android.content.Context
+import androidx.collection.LruCache
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.textclassifier.common.ModelFile
+import com.android.textclassifier.common.ModelType
+import com.android.textclassifier.common.TextClassifierSettings
+import com.android.textclassifier.testing.FakeContextBuilder
+import com.android.textclassifier.testing.TestingDeviceConfig
+import com.android.textclassifier.utils.TextClassifierUtils
+import com.google.android.textclassifier.AnnotatorModel
+import org.junit.Assert
+import org.junit.Assume
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.ArgumentMatchers
+import org.mockito.ArgumentMatchers.any
+import org.mockito.Mock
+import org.mockito.Mockito
+import org.mockito.MockitoAnnotations
+
+@RunWith(AndroidJUnit4::class)
+class TextClassifierOtpHelperTest {
+    @Mock
+    private lateinit var modelFileManager: ModelFileManager
+
+    private lateinit var context: Context
+    private lateinit var deviceConfig: TestingDeviceConfig
+    private lateinit var settings: TextClassifierSettings
+    private lateinit var annotatorModelCache: LruCache<ModelFile, AnnotatorModel>
+    private lateinit var tcImpl: TextClassifierImpl
+
+    @Before
+    fun setup() {
+        Assume.assumeTrue(TextClassifierUtils.isOtpClassificationEnabled())
+
+        MockitoAnnotations.initMocks(this)
+        this.context =
+            FakeContextBuilder()
+                .setAllIntentComponent(FakeContextBuilder.DEFAULT_COMPONENT)
+                .setAppLabel(FakeContextBuilder.DEFAULT_COMPONENT.packageName, "Test app")
+                .build()
+        this.deviceConfig = TestingDeviceConfig()
+        this.settings = TextClassifierSettings(deviceConfig, /* isWear= */ false)
+        this.annotatorModelCache = LruCache(2)
+        this.tcImpl =
+            TextClassifierImpl(context, settings, modelFileManager, annotatorModelCache)
+
+        Mockito.`when`(
+            modelFileManager.findBestModelFile(
+                ArgumentMatchers.eq(ModelType.ANNOTATOR),
+                any(),
+                any()
+            )
+        )
+            .thenReturn(TestDataUtils.getTestAnnotatorModelFileWrapped())
+        Mockito.`when`(
+            modelFileManager.findBestModelFile(
+                ArgumentMatchers.eq(ModelType.LANG_ID),
+                any(),
+                any()
+            )
+        )
+            .thenReturn(TestDataUtils.getLangIdModelFileWrapped())
+        Mockito.`when`(
+            modelFileManager.findBestModelFile(
+                ArgumentMatchers.eq(ModelType.ACTIONS_SUGGESTIONS),
+                any(),
+                any()
+            )
+        )
+            .thenReturn(TestDataUtils.getTestActionsModelFileWrapped())
+    }
+
+    private fun containsOtp(text: String): Boolean {
+        return TextClassifierOtpHelper.containsOtp(
+            text,
+            this.tcImpl,
+        )
+    }
+
+    @Test
+    fun testOtpDetection() {
+        Assert.assertFalse(containsOtp("hello"))
+        Assert.assertTrue(containsOtp("Your OTP code is 123456"))
+    }
+
+    @Test
+    fun testContainsOtpLikePattern_length() {
+        val tooShortAlphaNum = "123G"
+        val tooShortNumOnly = "123"
+        val minLenAlphaNum = "123G5"
+        val minLenNumOnly = "1235"
+        val twoTriplets = "123 456"
+        val tooShortTriplets = "12 345"
+        val maxLen = "123456F8"
+        val tooLong = "123T56789"
+
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(minLenAlphaNum))
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(minLenNumOnly))
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(maxLen))
+        Assert.assertFalse(
+            "$tooShortAlphaNum is too short",
+            TextClassifierOtpHelper.containsOtpLikePattern(tooShortAlphaNum)
+        )
+        Assert.assertFalse(
+            "$tooShortNumOnly is too short",
+            TextClassifierOtpHelper.containsOtpLikePattern(tooShortNumOnly)
+        )
+        Assert.assertFalse(
+            "$tooLong is too long",
+            TextClassifierOtpHelper.containsOtpLikePattern(tooLong)
+        )
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(twoTriplets))
+        Assert.assertFalse(
+            "$tooShortTriplets is too short",
+            TextClassifierOtpHelper.containsOtpLikePattern(tooShortTriplets)
+        )
+    }
+
+    @Test
+    fun testContainsOtpLikePattern_acceptsNonRomanAlphabeticalChars() {
+        val lowercase = "123ķ4"
+        val uppercase = "123Ŀ4"
+        val ideographicInMiddle = "123码456"
+
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(lowercase))
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(uppercase))
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(ideographicInMiddle))
+    }
+
+    @Test
+    fun testContainsOtpLikePattern_dashes() {
+        val oneDash = "G-3d523"
+        val manyDashes = "G-FD-745"
+        val tooManyDashes = "6--7893"
+        val oopsAllDashes = "------"
+
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(oneDash))
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(oneDash))
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(manyDashes))
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(tooManyDashes))
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(oopsAllDashes))
+    }
+
+    @Test
+    fun testContainsOtpLikePattern_lookaheadMustBeOtpChar() {
+        val validLookahead = "g4zy75"
+        val spaceLookahead = "GVRXY 2"
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(validLookahead))
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(spaceLookahead))
+    }
+
+    @Test
+    fun testContainsOtpLikePattern_dateExclusion() {
+        val date = "01-01-2001"
+        val singleDigitDate = "1-1-2001"
+        val twoDigitYear = "1-1-01"
+        val dateWithOtpAfter = "1-1-01 is the date of your code T3425"
+        val dateWithOtpBefore = "your code 54-234-3 was sent on 1-1-01"
+        val otpWithDashesButInvalidDate = "34-58-30"
+        val otpWithDashesButInvalidYear = "12-1-3089"
+
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(date))
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(singleDigitDate))
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(twoDigitYear))
+
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(dateWithOtpAfter))
+        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(dateWithOtpBefore))
+        Assert.assertTrue(
+            TextClassifierOtpHelper.containsOtpLikePattern(otpWithDashesButInvalidDate)
+        )
+        Assert.assertTrue(
+            TextClassifierOtpHelper.containsOtpLikePattern(otpWithDashesButInvalidYear)
+        )
+    }
+
+    @Test
+    fun testContainsOtpLikePattern_phoneExclusion() {
+        val parens = "(888) 8888888"
+        val allSpaces = "888 888 8888"
+        val withDash = "(888) 888-8888"
+        val allDashes = "888-888-8888"
+        val allDashesWithParen = "(888)-888-8888"
+
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(parens))
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(allSpaces))
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(withDash))
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(allDashes))
+        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(allDashesWithParen))
+    }
+
+    @Test
+    fun testContainsOtp_falsePositiveExclusion() {
+        // OTP: [888-8888] falsePositives=[] finalOtpCandidate=[1234]
+        Assert.assertTrue(containsOtp("Your OTP is 888-8888"))
+
+        // OTP: [1234, 888-8888] falsePositives=[(888) 888-8888] finalOtpCandidate=[1234]
+        Assert.assertTrue(containsOtp("1234 is your OTP, call (888) 888-8888 for more info"))
+
+        // OTP: [888-8888] falsePositives=[(888) 888-8888] finalOtpCandidate=[]
+        Assert.assertFalse(containsOtp("Your OTP can't be shared at this point, please call (888) 888-8888"))
+
+        // OTP: [1234, 01-01-2001] falsePositives=[01-01-2001] finalOtpCandidate=[1234]
+        Assert.assertTrue(containsOtp("Your OTP code is 1234 and this is sent on 01-01-2001"))
+
+        // OTP: [01-01-2001] falsePositives=[01-01-2001] finalOtpCandidate=[]
+        Assert.assertFalse(containsOtp("Your OTP code is null and this is sent on 01-01-2001"))
+    }
+
+    @Test
+    fun testContainsOtp_mustHaveNumber() {
+        val noNums = "TEFHXES"
+        Assert.assertFalse(containsOtp(noNums))
+    }
+
+    @Test
+    fun testContainsOtp_startAndEnd() {
+        val noSpaceStart = "your code isG-345821"
+        val noSpaceEnd = "your code is G-345821for real"
+        val numberSpaceStart = "your code is 4 G-345821"
+        val numberSpaceEnd = "your code is G-345821 3"
+        val colonStart = "your code is:G-345821"
+        val newLineStart = "your code is \nG-345821"
+        val quote = "your code is 'G-345821'"
+        val doubleQuote = "your code is \"G-345821\""
+        val bracketStart = "your code is [G-345821"
+        val ideographicStart = "your code is码G-345821"
+        val colonStartNumberPreceding = "your code is4:G-345821"
+        val periodEnd = "you code is G-345821."
+        val parens = "you code is (G-345821)"
+        val squareBrkt = "you code is [G-345821]"
+        val dashEnd = "you code is 'G-345821-'"
+        val randomSymbolEnd = "your code is G-345821$"
+        val underscoreEnd = "you code is 'G-345821_'"
+        val ideographicEnd = "your code is码G-345821码"
+        Assert.assertFalse(containsOtp(noSpaceStart))
+        Assert.assertFalse(containsOtp(noSpaceEnd))
+        Assert.assertFalse(containsOtp(numberSpaceStart))
+        Assert.assertFalse(containsOtp(numberSpaceEnd))
+        Assert.assertFalse(containsOtp(colonStartNumberPreceding))
+        Assert.assertFalse(containsOtp(dashEnd))
+        Assert.assertFalse(containsOtp(underscoreEnd))
+        Assert.assertFalse(containsOtp(randomSymbolEnd))
+        Assert.assertTrue(containsOtp(colonStart))
+        Assert.assertTrue(containsOtp(newLineStart))
+        Assert.assertTrue(containsOtp(quote))
+        Assert.assertTrue(containsOtp(doubleQuote))
+        Assert.assertTrue(containsOtp(bracketStart))
+        Assert.assertTrue(containsOtp(ideographicStart))
+        Assert.assertTrue(containsOtp(periodEnd))
+        Assert.assertTrue(containsOtp(parens))
+        Assert.assertTrue(containsOtp(squareBrkt))
+        Assert.assertTrue(containsOtp(ideographicEnd))
+    }
+
+    @Test
+    fun testContainsOtp_multipleFalsePositives() {
+        val otp = "code 1543 code"
+        val longFp = "888-777-6666"
+        val shortFp = "34ess"
+        val multipleLongFp = "$longFp something something $longFp"
+        val multipleLongFpWithOtpBefore = "$otp $multipleLongFp"
+        val multipleLongFpWithOtpAfter = "$multipleLongFp $otp"
+        val multipleLongFpWithOtpBetween = "$longFp $otp $longFp"
+        val multipleShortFp = "$shortFp something something $shortFp"
+        val multipleShortFpWithOtpBefore = "$otp $multipleShortFp"
+        val multipleShortFpWithOtpAfter = "$otp $multipleShortFp"
+        val multipleShortFpWithOtpBetween = "$shortFp $otp $shortFp"
+        Assert.assertFalse(containsOtp(multipleLongFp))
+        Assert.assertFalse(containsOtp(multipleShortFp))
+        Assert.assertTrue(containsOtp(multipleLongFpWithOtpBefore))
+        Assert.assertTrue(containsOtp(multipleLongFpWithOtpAfter))
+        Assert.assertTrue(containsOtp(multipleLongFpWithOtpBetween))
+        Assert.assertTrue(containsOtp(multipleShortFpWithOtpBefore))
+        Assert.assertTrue(containsOtp(multipleShortFpWithOtpAfter))
+        Assert.assertTrue(containsOtp(multipleShortFpWithOtpBetween))
+    }
+
+    @Test
+    fun testContainsOtpCode_nonEnglish() {
+        val textWithOtp = "1234 是您的一次性代碼" // 1234 is your one time code
+        Assert.assertFalse(containsOtp(textWithOtp))
+    }
+
+    @Test
+    fun testContainsOtp_englishSpecificRegex() {
+        val englishFalsePositive = "This is a false positive 4543"
+        val englishContextWords =
+            listOf(
+                "login",
+                "log in",
+                "2fa",
+                "authenticate",
+                "auth",
+                "authentication",
+                "tan",
+                "password",
+                "passcode",
+                "two factor",
+                "two-factor",
+                "2factor",
+                "2 factor",
+                "pin",
+                "one time",
+            )
+        val englishContextWordsCase = listOf("LOGIN", "logIn", "LoGiN")
+        // Strings with a context word somewhere in the substring
+        val englishContextSubstrings = listOf("pins", "gaping", "backspin")
+        val codeInNextSentence = "context word: code. This sentence has the actual value of 434343"
+        val codeInNextSentenceTooFar =
+            "context word: code. ${"f".repeat(60)} This sentence has the actual value of 434343"
+        val codeTwoSentencesAfterContext = "context word: code. One sentence. actual value 34343"
+        val codeInSentenceBeforeContext = "34343 is a number. This number is a code"
+        val codeInSentenceAfterNewline = "your code is \n 34343"
+        val codeTooFarBeforeContext = "34343 ${"f".repeat(60)} code"
+
+        Assert.assertFalse(containsOtp(englishFalsePositive))
+        for (context in englishContextWords) {
+            val englishTruePositive = "$context $englishFalsePositive"
+            Assert.assertTrue(containsOtp(englishTruePositive))
+        }
+        for (context in englishContextWordsCase) {
+            val englishTruePositive = "$context $englishFalsePositive"
+            Assert.assertTrue(containsOtp(englishTruePositive))
+        }
+        for (falseContext in englishContextSubstrings) {
+            val anotherFalsePositive = "$falseContext $englishFalsePositive"
+            Assert.assertFalse(containsOtp(anotherFalsePositive))
+        }
+        Assert.assertTrue(containsOtp(codeInNextSentence))
+        Assert.assertTrue(containsOtp(codeInSentenceAfterNewline))
+        Assert.assertFalse(containsOtp(codeTwoSentencesAfterContext))
+        Assert.assertFalse(containsOtp(codeInSentenceBeforeContext))
+        Assert.assertFalse(containsOtp(codeInNextSentenceTooFar))
+        Assert.assertFalse(containsOtp(codeTooFarBeforeContext))
+    }
+}
diff --git a/native/Android.bp b/native/Android.bp
index 3052e33..bb4a246 100644
--- a/native/Android.bp
+++ b/native/Android.bp
@@ -28,9 +28,8 @@ cc_library_headers {
     export_include_dirs: ["."],
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
         "com.android.ondevicepersonalization",
     ],
     min_sdk_version: "apex_inherit",
@@ -67,9 +66,8 @@ cc_library_static {
     min_sdk_version: "apex_inherit",
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
         "com.android.extservices",
         "com.android.adservices",
         "com.android.ondevicepersonalization",
@@ -79,7 +77,6 @@ cc_library_static {
 cc_defaults {
     name: "libtextclassifier_defaults",
     stl: "libc++_static",
-    cpp_std: "gnu++17",
     sdk_version: "current",
     // For debug / treemap purposes.
     //strip: {
@@ -111,7 +108,13 @@ cc_defaults {
         "-DTC3_AOSP",
         "-DTC3_VOCAB_ANNOTATOR_IMPL",
         "-DTC3_POD_NER_ANNOTATOR_IMPL",
-    ],
+    ] + select((
+        release_flag("RELEASE_BUILD_USE_VARIANT_FLAGS"),
+        release_flag("RELEASE_EXTERNAL_TC3_DEBUG"),
+    ), {
+        (true, true): ["-DTC3_DEBUG_LOGGING=1"],
+        (default, default): unset,
+    }),
 
     product_variables: {
         debuggable: {
diff --git a/native/actions/actions-suggestions.cc b/native/actions/actions-suggestions.cc
index eeeb508..562ca23 100644
--- a/native/actions/actions-suggestions.cc
+++ b/native/actions/actions-suggestions.cc
@@ -987,12 +987,12 @@ bool ActionsSuggestions::ReadModelOutput(
               }
             }
             if (task_spec->concept_mappings()) {
-              for (const auto& concept : *task_spec->concept_mappings()) {
+              for (const auto& concept_mapping : *task_spec->concept_mappings()) {
                 std::vector<std::string> candidates;
-                for (const auto& candidate : *concept->candidates()) {
+                for (const auto& candidate : *concept_mapping->candidates()) {
                   candidates.push_back(candidate->str());
                 }
-                concept_mappings[concept->concept_name()->str()] = candidates;
+                concept_mappings[concept_mapping->concept_name()->str()] = candidates;
               }
             }
           }
```

