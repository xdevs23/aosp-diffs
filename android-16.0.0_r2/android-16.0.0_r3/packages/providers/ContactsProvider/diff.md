```diff
diff --git a/OWNERS b/OWNERS
index ddf8f853..1a127740 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,8 @@
+jigarthakkar@google.com
+himanshuz@google.com
+kkasia@google.com
+onshimiye@google.com
+corinac@google.com
 aibra@google.com
 oeissa@google.com
 
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 30d8014a..d1937085 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="sharedUserLabel" msgid="8024311725474286801">"Matične aplikacije za Android"</string>
-    <string name="app_label" msgid="3389954322874982620">"Prostor za pohranu kontakata"</string>
+    <string name="app_label" msgid="3389954322874982620">"Pohrana kontakata"</string>
     <string name="provider_label" msgid="6012150850819899907">"Kontakti"</string>
     <string name="upgrade_out_of_memory_notification_ticker" msgid="7638747231223520477">"Za nadogradnju kontakata potrebno je više memorije."</string>
     <string name="upgrade_out_of_memory_notification_title" msgid="8888171924684998531">"Nadogradnja pohrane za kontakte"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index fabbc1a2..c4206a17 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -30,7 +30,7 @@
     <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{ಅದನ್ನು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಲು # ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕ}one{# ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕಗಳು ಇವೆ ಎಂದು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಲು}other{# ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕಗಳು ಇವೆ ಎಂದು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಲು}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ಸಿಂಕ್ ಮಾಡಿ"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ಸಿಂಕ್ ಮಾಡಬೇಡಿ"</string>
-    <string name="debug_dump_title" msgid="4916885724165570279">"ಸಂಪರ್ಕಗಳ ಡೇಟಾಬೇಸ್‌‌ ನಕಲಿಸಿ"</string>
+    <string name="debug_dump_title" msgid="4916885724165570279">"ಸಂಪರ್ಕಗಳ ಡೇಟಾಬೇಸ್‌‌ ಕಾಪಿ ಮಾಡಿ"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"ನೀವು 1) ಎಲ್ಲಾ ಸಂಪರ್ಕಗಳ ಸಂಬಂಧಿಸಿದ ಮಾಹಿತಿಯನ್ನು ಒಳಗೊಂಡಿರುವ ನಿಮ್ಮ ಡೇಟಾಬೇಸ್ ನಕಲು ಮಾಡಲು ಮತ್ತು ಆಂತರಿಕ ಸಂಗ್ರಹಣೆಗೆ ಎಲ್ಲ ಕರೆಯ ಲಾಗ್‌ ಮಾಡಲು ಮತ್ತು 2) ಇಮೇಲ್‌‌ ಮಾಡಲಿರುವಿರಿ. ನೀವು ಸಾಧನವನ್ನು ಯಶಸ್ವಿಯಾಗಿ ನಕಲು ಮಾಡಿದ ಬಳಿಕ ಅಥವಾ ಇಮೇಲ್‌ ಸ್ವೀಕರಿಸಿದ ಕೂಡಲೇ ನಕಲು ಅಳಿಸುವುದನ್ನು ನೆನಪಿನಲ್ಲಿರಿಸಿಕೊಳ್ಳಿ."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"ಈಗ ಅಳಿಸಿ"</string>
     <string name="debug_dump_start_button" msgid="2837506913757600001">"ಪ್ರಾರಂಭಿಸು"</string>
diff --git a/tests/src/com/android/providers/contacts/BaseContactsProvider2Test.java b/tests/src/com/android/providers/contacts/BaseContactsProvider2Test.java
index dc8c917b..52b8d034 100644
--- a/tests/src/com/android/providers/contacts/BaseContactsProvider2Test.java
+++ b/tests/src/com/android/providers/contacts/BaseContactsProvider2Test.java
@@ -765,6 +765,7 @@ public abstract class BaseContactsProvider2Test extends PhotoLoadingTestCase {
         }
     }
 
+    @SuppressWarnings("BoxedPrimitiveEquality")
     private void assertNullOrEquals(Cursor c, Long value, String columnName) {
         if (value != NO_LONG) {
             if (value == null) assertTrue(c.isNull(c.getColumnIndexOrThrow(columnName)));
```

