```diff
diff --git a/java/src/com/android/inputmethod/dictionarypack/DictionaryService.java b/java/src/com/android/inputmethod/dictionarypack/DictionaryService.java
index fe988ac70..5ab55bc44 100644
--- a/java/src/com/android/inputmethod/dictionarypack/DictionaryService.java
+++ b/java/src/com/android/inputmethod/dictionarypack/DictionaryService.java
@@ -229,8 +229,14 @@ public final class DictionaryService extends Service {
         final long now = System.currentTimeMillis();
         final long alarmTime = now + new Random().nextInt(MAX_ALARM_DELAY_MILLIS);
         final Intent updateIntent = new Intent(DictionaryPackConstants.UPDATE_NOW_INTENT_ACTION);
+        // Set the package name to ensure the PendingIntent is only delivered to trusted components
+        updateIntent.setPackage(context.getPackageName());
+        int pendingIntentFlags = PendingIntent.FLAG_CANCEL_CURRENT;
+        if (android.os.Build.VERSION.SDK_INT >= 23) {
+            pendingIntentFlags |= PendingIntent.FLAG_IMMUTABLE;
+        }
         final PendingIntent pendingIntent = PendingIntent.getBroadcast(context, 0,
-                updateIntent, PendingIntent.FLAG_CANCEL_CURRENT);
+                updateIntent, pendingIntentFlags);
 
         // We set the alarm in the type that doesn't forcefully wake the device
         // from sleep, but fires the next time the device actually wakes for any
diff --git a/native/dicttoolkit/Android.bp b/native/dicttoolkit/Android.bp
index 6560d654a..4ae250fa2 100644
--- a/native/dicttoolkit/Android.bp
+++ b/native/dicttoolkit/Android.bp
@@ -24,7 +24,6 @@ package {
 cc_defaults {
     name: "dicttoolkit_defaults",
 
-    cpp_std: "gnu++17",
     cflags: [
         "-Werror",
         "-Wall",
diff --git a/native/dicttoolkit/tests/utils/utf8_utils_test.cpp b/native/dicttoolkit/tests/utils/utf8_utils_test.cpp
index 9c59a8b05..18fa2f4bf 100644
--- a/native/dicttoolkit/tests/utils/utf8_utils_test.cpp
+++ b/native/dicttoolkit/tests/utils/utf8_utils_test.cpp
@@ -40,7 +40,7 @@ TEST(Utf8UtilsTests, TestGetCodePoints) {
         EXPECT_EQ('t', codePoints[3]);
     }
     {
-        const std::vector<int> codePoints = Utf8Utils::getCodePoints(u8"\u3042a\u03C2\u0410");
+        const std::vector<int> codePoints = Utf8Utils::getCodePoints("\u3042a\u03C2\u0410");
         EXPECT_EQ(4u, codePoints.size());
         EXPECT_EQ(0x3042, codePoints[0]); // HIRAGANA LETTER A
         EXPECT_EQ('a', codePoints[1]);
@@ -48,7 +48,7 @@ TEST(Utf8UtilsTests, TestGetCodePoints) {
         EXPECT_EQ(0x0410, codePoints[3]); // GREEK SMALL LETTER FINAL SIGMA
     }
     {
-        const std::vector<int> codePoints = Utf8Utils::getCodePoints(u8"\U0001F36A?\U0001F752");
+        const std::vector<int> codePoints = Utf8Utils::getCodePoints("\U0001F36A?\U0001F752");
         EXPECT_EQ(3u, codePoints.size());
         EXPECT_EQ(0x1F36A, codePoints[0]); // COOKIE
         EXPECT_EQ('?', codePoints[1]);
@@ -75,7 +75,7 @@ TEST(Utf8UtilsTests, TestGetUtf8String) {
                 0x1F36A /* COOKIE */,
                 0x1F752 /* ALCHEMICAL SYMBOL FOR STARRED TRIDENT */
         };
-        EXPECT_EQ(u8"\u00E0\u03C2\u0430\u3042\U0001F36A\U0001F752",
+        EXPECT_EQ("\u00E0\u03C2\u0430\u3042\U0001F36A\U0001F752",
                 Utf8Utils::getUtf8String(CodePointArrayView(codePoints)));
     }
 }
```

