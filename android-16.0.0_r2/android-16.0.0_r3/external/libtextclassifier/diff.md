```diff
diff --git a/java/src/com/android/textclassifier/TextClassifierOtpHelper.java b/java/src/com/android/textclassifier/OtpDetector.java
similarity index 71%
rename from java/src/com/android/textclassifier/TextClassifierOtpHelper.java
rename to java/src/com/android/textclassifier/OtpDetector.java
index 9e924c5..946f6a0 100644
--- a/java/src/com/android/textclassifier/TextClassifierOtpHelper.java
+++ b/java/src/com/android/textclassifier/OtpDetector.java
@@ -18,33 +18,25 @@ package com.android.textclassifier;
 import static java.lang.String.format;
 
 import android.icu.util.ULocale;
-import android.os.Bundle;
 import android.util.ArrayMap;
+import android.view.textclassifier.TextClassifier;
 import android.view.textclassifier.TextLanguage;
-import android.view.textclassifier.TextLinks;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.textclassifier.common.base.TcLog;
-import com.android.textclassifier.utils.TextClassifierUtils;
-
-import com.google.common.annotations.VisibleForTesting;
-
-import java.io.IOException;
-import java.util.Collections;
 import java.util.HashSet;
-import java.util.Map;
 import java.util.Set;
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
 
 /**
- * Class with helper methods related to detecting OTP codes in a text.
+ * Class with helper methods to detecting One-Time Password (OTP) codes in a text.
+ *
+ * <p>This class is designed to be lightweight with minimal dependencies, allowing it
+ * to be easily exported and built as a standalone library.
  */
-public class TextClassifierOtpHelper {
-  private static final String TAG = TextClassifierOtpHelper.class.getSimpleName();
-
+public class OtpDetector {
   private static final int PATTERN_FLAGS =
       Pattern.DOTALL | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;
 
@@ -73,7 +65,8 @@ public class TextClassifierOtpHelper {
   private static ThreadLocal<Matcher> createDictionaryRegex(String[] words) {
     StringBuilder regex = new StringBuilder("(");
     for (int i = 0; i < words.length; i++) {
-      regex.append(findContextWordWithCode(words[i]));
+      String boundedWord = "\\b" + words[i] + "\\b";
+      regex.append(boundedWord);
       if (i != words.length - 1) {
         regex.append("|");
       }
@@ -82,74 +75,59 @@ public class TextClassifierOtpHelper {
     return compileToRegex(regex.toString());
   }
 
-  /**
-   * Creates a regular expression that will find a context word, if that word occurs in the sentence
-   * preceding an OTP, or in the same sentence as an OTP (before or after). In both cases, the
-   * context word must occur within 50 characters of the suspected OTP
-   *
-   * @param contextWord The context word we expect to find around the OTP match
-   * @return A string representing a regular expression that will determine if we found a context
-   *     word occurring before an otp match, or after it, but in the same sentence.
-   */
-  private static String findContextWordWithCode(String contextWord) {
-    String boundedContext = "\\b" + contextWord + "\\b";
-    // Asserts that we find the OTP code within 50 characters after the context word, with at
-    // most one sentence punctuation between the OTP code and the context word (i.e. they are
-    // in the same sentence, or the context word is in the previous sentence)
-    String contextWordBeforeOtpInSameOrPreviousSentence =
-        String.format("(%s(?=.{1,50}%s)[^.?!]*[.?!]?[^.?!]*%s)", boundedContext, RegExStrings.ALL_OTP, RegExStrings.ALL_OTP);
-    // Asserts that we find the context word within 50 characters after the OTP code, with no
-    // sentence punctuation between the OTP code and the context word (i.e. they are in the same
-    // sentence)
-    String contextWordAfterOtpSameSentence =
-        String.format("(%s)[^.!?]{1,50}%s", RegExStrings.ALL_OTP, boundedContext);
-    return String.format(
-        "(%s|%s)", contextWordBeforeOtpInSameOrPreviousSentence, contextWordAfterOtpSameSentence);
-  }
-
   static {
     EXTRA_LANG_OTP_REGEX.put(
-        ULocale.ENGLISH.toLanguageTag(), createDictionaryRegex(RegExStrings.ENGLISH_CONTEXT_WORDS));
-  }
-
-  /**
-   * Checks if the text might contain an OTP, if so, adds a link to the builder with type as OTP
-   *
-   * @param text    The text whose content should be checked for OTP
-   * @param tcImpl  Instance of the TextClassifierImpl
-   * @param builder TextLinks builder object to whom the OTP link to be added
-   */
-  public static void addOtpLink(@NonNull String text, @NonNull TextClassifierImpl tcImpl,
-          @NonNull TextLinks.Builder builder) {
-    if (!containsOtp(text, tcImpl)) {
-      return;
-    }
-    final Map<String, Float> entityScores = Collections.singletonMap(TextClassifierUtils.TYPE_OTP,
-            1f);
-    builder.addLink(0, 0, entityScores, new Bundle());
+        ULocale.ENGLISH.toLanguageTag(), createDictionaryRegex(RegExStrings.englishContextWords));
   }
 
   /**
    * Checks if a string of text might contain an OTP, based on several regular expressions, and
-   * potentially using a textClassifier to eliminate false positives
+   * potentially using a textClassifier to eliminate false positives.
+   *
+   * <p><b>Note:</b> This method is meant to be called in Android V only. Android B+ should make
+   * TextClassifier request to determine if the text contains OTP.</p>
    *
-   * @param text   The text whose content should be checked
-   * @param tcImpl If non null, the provided TextClassifierImpl will be used to find the language
-   *               of the text, and look for a language-specific regex for it.
-   * @return True if we believe an OTP is in the message, false otherwise.
+   * <p><b>Important:</b> Signature of this method to be kept intact since it is intended for
+   * use by external modules via an exported library.
+   *
+   * @param text The input text to scan for OTP keywords. Must not be null.
+   * @param tc TextClassifier instance to be used to find the language of the text.
+   * @return {@code true} if an OTP is determined to be in the text, {@code false} otherwise.
    */
-  protected static boolean containsOtp(
+  public static boolean containsOtp(
           @NonNull String text,
-          @NonNull TextClassifierImpl tcImpl) {
+          @NonNull TextClassifier tc) {
     if (!containsOtpLikePattern(text)) {
       return false;
     }
 
-    ULocale language = getLanguageWithRegex(text, tcImpl);
-    if (language == null) {
+    TextLanguage language = getTextLanguage(text, tc);
+    return containsOtpWithLanguage(text, language);
+  }
+
+  /**
+   * Checks if the input text likely contains a language-specific keyword commonly associated with
+   * OTP, based on the provided language hint.
+   *
+   * <p>This method first attempts to determine a high-confidence {@link ULocale} corresponding to
+   * the given {@link TextLanguage}. If a reliable locale cannot be determined, it assumes no
+   * relevant OTP keyword is present for that language. Otherwise, it delegates to
+   * {@link #hasLanguageSpecificOtpWord} to perform the actual check using the language tag derived
+   * from the determined locale.
+   *
+   * @param text The input text to scan for OTP keywords. Must not be null.
+   * @param language The language hint for the input text, used to determine the appropriate locale
+   * for keyword matching. Must not be null.
+   * @return {@code true} if the text is determined to contain a language-specific OTP keyword
+   * matching the language hint, {@code false} otherwise (including cases where the language
+   * could not be confidently identified or no specific OTP keyword is found).
+   */
+  protected static boolean containsOtpWithLanguage(@NonNull String text, @NonNull TextLanguage language) {
+    ULocale uLocale = getLanguageWithRegex(language);
+    if (uLocale == null) {
       return false;
     }
-    return hasLanguageSpecificOtpWord(text, language.toLanguageTag());
+    return hasLanguageSpecificOtpWord(text, uLocale.toLanguageTag());
   }
 
   /**
@@ -162,7 +140,6 @@ public class TextClassifierOtpHelper {
    * @param text The text to be checked.
    * @return {@code true} if the text contains an OTP-like pattern, {@code false} otherwise.
    */
-  @VisibleForTesting
   protected static boolean containsOtpLikePattern(String text) {
     Set<String> otpMatches = getAllMatches(text, OTP_REGEX.get());
     if (otpMatches.isEmpty()) {
@@ -203,8 +180,7 @@ public class TextClassifierOtpHelper {
    * @return {@code true} if the text contains a language-specific OTP word, {@code false} otherwise.
    *         Returns {@code false} if no language-specific regex is defined for the given tag.
    */
-  @VisibleForTesting
-  protected static boolean hasLanguageSpecificOtpWord(@NonNull String text, @NonNull String languageTag) {
+  private static boolean hasLanguageSpecificOtpWord(@NonNull String text, @NonNull String languageTag) {
     if (!EXTRA_LANG_OTP_REGEX.containsKey(languageTag)){
       return false;
     }
@@ -225,27 +201,24 @@ public class TextClassifierOtpHelper {
     return matches;
   }
 
-  // Tries to determine the language of the given text. Will return the language with the highest
-  // confidence score that meets the minimum threshold, and has a language-specific regex, null
-  // otherwise
+  // Tries to determine the language of the given text.
+  private static TextLanguage getTextLanguage(@NonNull String text, @NonNull TextClassifier tc) {
+    TextLanguage.Request langRequest = new TextLanguage.Request.Builder(text).build();
+    return tc.detectLanguage(langRequest);
+  }
+
+  // Will return the language with the highest confidence score that meets the minimum threshold,
+  // and has a language-specific regex, null otherwise
   @Nullable
-  private static ULocale getLanguageWithRegex(String text, @NonNull TextClassifierImpl tcImpl) {
+  private static ULocale getLanguageWithRegex(@NonNull TextLanguage lang) {
     float highestConfidence = 0;
     ULocale highestConfidenceLocale = null;
-    TextLanguage.Request langRequest = new TextLanguage.Request.Builder(text).build();
-    TextLanguage lang;
-    try {
-      lang = tcImpl.detectLanguage(null, null, langRequest);
-    } catch (IOException e) {
-      TcLog.e(TAG, "Except detecting language", e);
-      return null;
-    }
     for (int i = 0; i < lang.getLocaleHypothesisCount(); i++) {
       ULocale locale = lang.getLocale(i);
       float confidence = lang.getConfidenceScore(locale);
       if (confidence >= TC_THRESHOLD
-          && confidence >= highestConfidence
-          && EXTRA_LANG_OTP_REGEX.containsKey(locale.toLanguageTag())) {
+              && confidence >= highestConfidence
+              && EXTRA_LANG_OTP_REGEX.containsKey(locale.toLanguageTag())) {
         highestConfidence = confidence;
         highestConfidenceLocale = locale;
       }
@@ -253,7 +226,7 @@ public class TextClassifierOtpHelper {
     return highestConfidenceLocale;
   }
 
-  private TextClassifierOtpHelper() {}
+  private OtpDetector() {}
 
   private static class RegExStrings {
     /*
@@ -345,7 +318,7 @@ public class TextClassifierOtpHelper {
      * A list of regular expressions representing words found in an OTP context (non case sensitive)
      * Note: TAN is short for Transaction Authentication Number
      */
-    private static final String[] ENGLISH_CONTEXT_WORDS =
+    private static final String[] englishContextWords =
             new String[] {
                     "pin",
                     "pass[-\\s]?(code|word)",
diff --git a/java/src/com/android/textclassifier/TextClassifierImpl.java b/java/src/com/android/textclassifier/TextClassifierImpl.java
index 8822ec7..7fdb885 100644
--- a/java/src/com/android/textclassifier/TextClassifierImpl.java
+++ b/java/src/com/android/textclassifier/TextClassifierImpl.java
@@ -298,7 +298,7 @@ final class TextClassifierImpl {
 
     if (TextClassifierUtils.isOtpClassificationEnabled() && entitiesToIdentify.contains(
             TextClassifierUtils.TYPE_OTP)) {
-      TextClassifierOtpHelper.addOtpLink(request.getText().toString(), this, builder);
+      TextClassifierOtpHandler.addOtpLink(request.getText().toString(), this, builder);
     }
 
     final String localesString = concatenateLocales(request.getDefaultLocales());
diff --git a/java/src/com/android/textclassifier/TextClassifierOtpHandler.java b/java/src/com/android/textclassifier/TextClassifierOtpHandler.java
new file mode 100644
index 0000000..b1d0ff8
--- /dev/null
+++ b/java/src/com/android/textclassifier/TextClassifierOtpHandler.java
@@ -0,0 +1,93 @@
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
+import android.os.Bundle;
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
+import java.util.Map;
+
+/**
+ * Handler class for TextClassifier for One-Time Password (OTP) requests. Adds to
+ * to {@link android.view.textclassifier.TextLinks} if the input text contains an OTP
+ */
+class TextClassifierOtpHandler {
+  private static final String TAG = TextClassifierOtpHandler.class.getSimpleName();
+
+  /**
+   * Checks if the text might contain an OTP, if so, adds a link to the builder with type as OTP
+   *
+   * @param text    The text whose content should be checked for OTP
+   * @param tcImpl  Instance of the TextClassifierImpl to detect the language of input text
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
+   * @param text   The text whose content should be checked.
+   * @param tcImpl TextClassifierImpl to be used to find the language of the text.
+   * @return {@code true} if an OTP is determined to be in the text, {@code false} otherwise.
+   */
+  @VisibleForTesting
+  protected static boolean containsOtp(
+          @NonNull String text,
+          @NonNull TextClassifierImpl tcImpl) {
+    if (!OtpDetector.containsOtpLikePattern(text)) {
+      return false;
+    }
+
+    TextLanguage language = getTextLanguage(text, tcImpl);
+    if (language == null) {
+      return false;
+    }
+    return OtpDetector.containsOtpWithLanguage(text, language);
+  }
+
+  @Nullable
+  private static TextLanguage getTextLanguage(String text, @NonNull TextClassifierImpl tcImpl) {
+    TextLanguage.Request langRequest = new TextLanguage.Request.Builder(text).build();
+    try {
+      return tcImpl.detectLanguage(null, null, langRequest);
+    } catch (IOException e) {
+      TcLog.e(TAG, "Except detecting language", e);
+      return null;
+    }
+  }
+
+  private TextClassifierOtpHandler() {}
+}
diff --git a/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierOtpHelperTest.kt b/java/tests/instrumentation/src/com/android/textclassifier/OtpDetectorTest.kt
similarity index 70%
rename from java/tests/instrumentation/src/com/android/textclassifier/TextClassifierOtpHelperTest.kt
rename to java/tests/instrumentation/src/com/android/textclassifier/OtpDetectorTest.kt
index 467e453..9fe48df 100644
--- a/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierOtpHelperTest.kt
+++ b/java/tests/instrumentation/src/com/android/textclassifier/OtpDetectorTest.kt
@@ -16,10 +16,12 @@
 package com.android.textclassifier
 
 import android.content.Context
+import android.icu.util.ULocale
+import android.view.textclassifier.TextClassifier
+import android.view.textclassifier.TextLanguage
 import androidx.collection.LruCache
 import androidx.test.ext.junit.runners.AndroidJUnit4
 import com.android.textclassifier.common.ModelFile
-import com.android.textclassifier.common.ModelType
 import com.android.textclassifier.common.TextClassifierSettings
 import com.android.textclassifier.testing.FakeContextBuilder
 import com.android.textclassifier.testing.TestingDeviceConfig
@@ -30,22 +32,17 @@ import org.junit.Assume
 import org.junit.Before
 import org.junit.Test
 import org.junit.runner.RunWith
-import org.mockito.ArgumentMatchers
 import org.mockito.ArgumentMatchers.any
-import org.mockito.Mock
 import org.mockito.Mockito
 import org.mockito.MockitoAnnotations
 
 @RunWith(AndroidJUnit4::class)
-class TextClassifierOtpHelperTest {
-    @Mock
-    private lateinit var modelFileManager: ModelFileManager
-
+class OtpDetectorTest {
     private lateinit var context: Context
     private lateinit var deviceConfig: TestingDeviceConfig
     private lateinit var settings: TextClassifierSettings
     private lateinit var annotatorModelCache: LruCache<ModelFile, AnnotatorModel>
-    private lateinit var tcImpl: TextClassifierImpl
+    private lateinit var tc: TextClassifier
 
     @Before
     fun setup() {
@@ -60,39 +57,16 @@ class TextClassifierOtpHelperTest {
         this.deviceConfig = TestingDeviceConfig()
         this.settings = TextClassifierSettings(deviceConfig, /* isWear= */ false)
         this.annotatorModelCache = LruCache(2)
-        this.tcImpl =
-            TextClassifierImpl(context, settings, modelFileManager, annotatorModelCache)
-
-        Mockito.`when`(
-            modelFileManager.findBestModelFile(
-                ArgumentMatchers.eq(ModelType.ANNOTATOR),
-                any(),
-                any()
-            )
-        )
-            .thenReturn(TestDataUtils.getTestAnnotatorModelFileWrapped())
-        Mockito.`when`(
-            modelFileManager.findBestModelFile(
-                ArgumentMatchers.eq(ModelType.LANG_ID),
-                any(),
-                any()
-            )
-        )
-            .thenReturn(TestDataUtils.getLangIdModelFileWrapped())
-        Mockito.`when`(
-            modelFileManager.findBestModelFile(
-                ArgumentMatchers.eq(ModelType.ACTIONS_SUGGESTIONS),
-                any(),
-                any()
-            )
-        )
-            .thenReturn(TestDataUtils.getTestActionsModelFileWrapped())
+        this.tc = Mockito.mock(TextClassifier::class.java)
+        Mockito.doReturn(TextLanguage.Builder().putLocale(ULocale.ENGLISH, 0.9f).build())
+            .`when`(tc)
+            .detectLanguage(any())
     }
 
     private fun containsOtp(text: String): Boolean {
-        return TextClassifierOtpHelper.containsOtp(
+        return OtpDetector.containsOtp(
             text,
-            this.tcImpl,
+            this.tc,
         )
     }
 
@@ -113,25 +87,25 @@ class TextClassifierOtpHelperTest {
         val maxLen = "123456F8"
         val tooLong = "123T56789"
 
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(minLenAlphaNum))
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(minLenNumOnly))
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(maxLen))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(minLenAlphaNum))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(minLenNumOnly))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(maxLen))
         Assert.assertFalse(
             "$tooShortAlphaNum is too short",
-            TextClassifierOtpHelper.containsOtpLikePattern(tooShortAlphaNum)
+            OtpDetector.containsOtpLikePattern(tooShortAlphaNum)
         )
         Assert.assertFalse(
             "$tooShortNumOnly is too short",
-            TextClassifierOtpHelper.containsOtpLikePattern(tooShortNumOnly)
+            OtpDetector.containsOtpLikePattern(tooShortNumOnly)
         )
         Assert.assertFalse(
             "$tooLong is too long",
-            TextClassifierOtpHelper.containsOtpLikePattern(tooLong)
+            OtpDetector.containsOtpLikePattern(tooLong)
         )
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(twoTriplets))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(twoTriplets))
         Assert.assertFalse(
             "$tooShortTriplets is too short",
-            TextClassifierOtpHelper.containsOtpLikePattern(tooShortTriplets)
+            OtpDetector.containsOtpLikePattern(tooShortTriplets)
         )
     }
 
@@ -141,9 +115,9 @@ class TextClassifierOtpHelperTest {
         val uppercase = "123Ŀ4"
         val ideographicInMiddle = "123码456"
 
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(lowercase))
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(uppercase))
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(ideographicInMiddle))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(lowercase))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(uppercase))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(ideographicInMiddle))
     }
 
     @Test
@@ -153,19 +127,19 @@ class TextClassifierOtpHelperTest {
         val tooManyDashes = "6--7893"
         val oopsAllDashes = "------"
 
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(oneDash))
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(oneDash))
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(manyDashes))
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(tooManyDashes))
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(oopsAllDashes))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(oneDash))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(oneDash))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(manyDashes))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(tooManyDashes))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(oopsAllDashes))
     }
 
     @Test
     fun testContainsOtpLikePattern_lookaheadMustBeOtpChar() {
         val validLookahead = "g4zy75"
         val spaceLookahead = "GVRXY 2"
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(validLookahead))
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(spaceLookahead))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(validLookahead))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(spaceLookahead))
     }
 
     @Test
@@ -178,17 +152,17 @@ class TextClassifierOtpHelperTest {
         val otpWithDashesButInvalidDate = "34-58-30"
         val otpWithDashesButInvalidYear = "12-1-3089"
 
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(date))
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(singleDigitDate))
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(twoDigitYear))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(date))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(singleDigitDate))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(twoDigitYear))
 
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(dateWithOtpAfter))
-        Assert.assertTrue(TextClassifierOtpHelper.containsOtpLikePattern(dateWithOtpBefore))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(dateWithOtpAfter))
+        Assert.assertTrue(OtpDetector.containsOtpLikePattern(dateWithOtpBefore))
         Assert.assertTrue(
-            TextClassifierOtpHelper.containsOtpLikePattern(otpWithDashesButInvalidDate)
+            OtpDetector.containsOtpLikePattern(otpWithDashesButInvalidDate)
         )
         Assert.assertTrue(
-            TextClassifierOtpHelper.containsOtpLikePattern(otpWithDashesButInvalidYear)
+            OtpDetector.containsOtpLikePattern(otpWithDashesButInvalidYear)
         )
     }
 
@@ -200,11 +174,11 @@ class TextClassifierOtpHelperTest {
         val allDashes = "888-888-8888"
         val allDashesWithParen = "(888)-888-8888"
 
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(parens))
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(allSpaces))
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(withDash))
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(allDashes))
-        Assert.assertFalse(TextClassifierOtpHelper.containsOtpLikePattern(allDashesWithParen))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(parens))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(allSpaces))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(withDash))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(allDashes))
+        Assert.assertFalse(OtpDetector.containsOtpLikePattern(allDashesWithParen))
     }
 
     @Test
@@ -325,12 +299,7 @@ class TextClassifierOtpHelperTest {
         // Strings with a context word somewhere in the substring
         val englishContextSubstrings = listOf("pins", "gaping", "backspin")
         val codeInNextSentence = "context word: code. This sentence has the actual value of 434343"
-        val codeInNextSentenceTooFar =
-            "context word: code. ${"f".repeat(60)} This sentence has the actual value of 434343"
-        val codeTwoSentencesAfterContext = "context word: code. One sentence. actual value 34343"
-        val codeInSentenceBeforeContext = "34343 is a number. This number is a code"
         val codeInSentenceAfterNewline = "your code is \n 34343"
-        val codeTooFarBeforeContext = "34343 ${"f".repeat(60)} code"
 
         Assert.assertFalse(containsOtp(englishFalsePositive))
         for (context in englishContextWords) {
@@ -347,9 +316,5 @@ class TextClassifierOtpHelperTest {
         }
         Assert.assertTrue(containsOtp(codeInNextSentence))
         Assert.assertTrue(containsOtp(codeInSentenceAfterNewline))
-        Assert.assertFalse(containsOtp(codeTwoSentencesAfterContext))
-        Assert.assertFalse(containsOtp(codeInSentenceBeforeContext))
-        Assert.assertFalse(containsOtp(codeInNextSentenceTooFar))
-        Assert.assertFalse(containsOtp(codeTooFarBeforeContext))
     }
 }
diff --git a/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierOtpHandlerTest.kt b/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierOtpHandlerTest.kt
new file mode 100644
index 0000000..12486b8
--- /dev/null
+++ b/java/tests/instrumentation/src/com/android/textclassifier/TextClassifierOtpHandlerTest.kt
@@ -0,0 +1,241 @@
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
+class TextClassifierOtpHandlerTest {
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
+        return TextClassifierOtpHandler.containsOtp(
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
+        val codeInSentenceAfterNewline = "your code is \n 34343"
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
+    }
+}
diff --git a/native/Android.bp b/native/Android.bp
index bb4a246..082fe66 100644
--- a/native/Android.bp
+++ b/native/Android.bp
@@ -136,7 +136,12 @@ cc_defaults {
     ],
 
     static_libs: [
-        "libabsl",
+        "absl_strings",
+        "absl_container_flat_hash_map",
+        "absl_container_flat_hash_set",
+        "absl_container_node_hash_map",
+        "absl_numeric_int128",
+        "absl_random",
         "liblua",
         "libtflite_static",
         "libutf",
@@ -192,7 +197,12 @@ cc_library_static {
         "libtextclassifier_flatbuffer_headers",
     ],
     static_libs: [
-        "libabsl",
+        "absl_strings",
+        "absl_container_flat_hash_map",
+        "absl_container_flat_hash_set",
+        "absl_container_node_hash_map",
+        "absl_numeric_int128",
+        "absl_random",
         "tflite_support",
     ],
     sdk_version: "current",
```

