```diff
diff --git a/java/proguard.flags b/java/proguard.flags
index c832a88e3..0ebca04de 100644
--- a/java/proguard.flags
+++ b/java/proguard.flags
@@ -1,11 +1,17 @@
 # Keep classes and methods that have the @UsedForTesting annotation
--keep @com.android.inputmethod.annotations.UsedForTesting class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.android.inputmethod.annotations.UsedForTesting class * {
+    void <init>();
+}
 -keepclassmembers class * {
     @com.android.inputmethod.annotations.UsedForTesting *;
 }
 
 # Keep classes and methods that have the @ExternallyReferenced annotation
--keep @com.android.inputmethod.annotations.ExternallyReferenced class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.android.inputmethod.annotations.ExternallyReferenced class * {
+    void <init>();
+}
 -keepclassmembers class * {
     @com.android.inputmethod.annotations.ExternallyReferenced *;
 }
@@ -17,11 +23,26 @@
 
 # Keep classes that are used as a parameter type of methods that are also marked as keep
 # to preserve changing those methods' signature.
--keep class com.android.inputmethod.latin.AssetFileAddress
--keep class com.android.inputmethod.latin.Dictionary
--keep class com.android.inputmethod.latin.NgramContext
--keep class com.android.inputmethod.latin.makedict.ProbabilityInfo
--keep class com.android.inputmethod.latin.utils.LanguageModelParam
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.inputmethod.latin.AssetFileAddress {
+    void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.inputmethod.latin.Dictionary {
+    void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.inputmethod.latin.NgramContext {
+    void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.inputmethod.latin.makedict.ProbabilityInfo {
+    void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.inputmethod.latin.utils.LanguageModelParam {
+    void <init>();
+}
 
 # TODO: remove once used in code.
 -keep class com.android.inputmethod.keyboard.KeyboardLayout { *; }
diff --git a/java/src/com/android/inputmethod/latin/suggestions/SuggestionStripView.java b/java/src/com/android/inputmethod/latin/suggestions/SuggestionStripView.java
index 840a4aa3d..5dba4928b 100644
--- a/java/src/com/android/inputmethod/latin/suggestions/SuggestionStripView.java
+++ b/java/src/com/android/inputmethod/latin/suggestions/SuggestionStripView.java
@@ -343,6 +343,9 @@ public final class SuggestionStripView extends RelativeLayout implements OnClick
             new GestureDetector.SimpleOnGestureListener() {
         @Override
         public boolean onScroll(MotionEvent down, MotionEvent me, float deltaX, float deltaY) {
+            if (down == null) {
+                return false;
+            }
             final float dy = me.getY() - down.getY();
             if (deltaY > 0 && dy < 0) {
                 return showMoreSuggestions();
diff --git a/tests/src/com/android/inputmethod/latin/ContactsContentObserverTest.java b/tests/src/com/android/inputmethod/latin/ContactsContentObserverTest.java
index 029e1b506..23caa41cb 100644
--- a/tests/src/com/android/inputmethod/latin/ContactsContentObserverTest.java
+++ b/tests/src/com/android/inputmethod/latin/ContactsContentObserverTest.java
@@ -18,7 +18,7 @@ package com.android.inputmethod.latin;
 
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.validateMockitoUsage;
 import static org.mockito.Mockito.when;
 
diff --git a/tests/src/com/android/inputmethod/latin/network/BlockingHttpClientTests.java b/tests/src/com/android/inputmethod/latin/network/BlockingHttpClientTests.java
index f6f54eb77..d6aaf080c 100644
--- a/tests/src/com/android/inputmethod/latin/network/BlockingHttpClientTests.java
+++ b/tests/src/com/android/inputmethod/latin/network/BlockingHttpClientTests.java
@@ -19,8 +19,8 @@ package com.android.inputmethod.latin.network;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
diff --git a/tests/src/com/android/inputmethod/latin/settings/AccountsSettingsFragmentTests.java b/tests/src/com/android/inputmethod/latin/settings/AccountsSettingsFragmentTests.java
index 667ffd1ae..3b55143a1 100644
--- a/tests/src/com/android/inputmethod/latin/settings/AccountsSettingsFragmentTests.java
+++ b/tests/src/com/android/inputmethod/latin/settings/AccountsSettingsFragmentTests.java
@@ -19,7 +19,7 @@ package com.android.inputmethod.latin.settings;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.fail;
-import static org.mockito.Matchers.any;
+import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.when;
 
 import android.app.AlertDialog;
```

