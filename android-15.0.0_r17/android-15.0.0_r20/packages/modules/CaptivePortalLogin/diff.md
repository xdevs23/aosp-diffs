```diff
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 5ca06c3..ef9afba 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -19,8 +19,8 @@
     <string name="ssl_error_unknown" msgid="3751419329218834886">"Onbekende sertifikaatfout."</string>
     <string name="ssl_security_warning_title" msgid="7912335118289529802">"Sekuriteitswaarskuwing"</string>
     <string name="ssl_error_view_certificate" msgid="3447891108083278449">"Bekyk sertifikaat"</string>
-    <string name="custom_scheme_warning" msgid="1809266150423969087">"Die netwerk waarby jy probeer aansluit, vra dat jy \'n ander program oopmaak."</string>
-    <string name="custom_scheme_example" msgid="7126568152528588592">"Byvoorbeeld, die aanmeldbladsy kan dalk \'n spesifieke program vir stawing vereis"</string>
+    <string name="custom_scheme_warning" msgid="1809266150423969087">"Die netwerk waarby jy probeer aansluit, vra dat jy \'n ander app oopmaak."</string>
+    <string name="custom_scheme_example" msgid="7126568152528588592">"Byvoorbeeld, die aanmeldbladsy kan dalk \'n spesifieke app vir stawing vereis"</string>
     <string name="ok" msgid="6584612582120777209">"OK"</string>
     <string name="page_info_address" msgid="1290683284404217554">"Adres:"</string>
     <string name="page_info" msgid="46593086046896385">"Bladsy-inligting"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 2dedc6a..329872a 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -21,7 +21,7 @@
     <string name="ssl_error_view_certificate" msgid="3447891108083278449">"Visualizza certificato"</string>
     <string name="custom_scheme_warning" msgid="1809266150423969087">"La rete a cui stai tentando di accedere richiede di aprire un\'altra applicazione."</string>
     <string name="custom_scheme_example" msgid="7126568152528588592">"Ad esempio, la pagina di accesso potrebbe richiedere un\'applicazione specifica per l\'autenticazione"</string>
-    <string name="ok" msgid="6584612582120777209">"OK"</string>
+    <string name="ok" msgid="6584612582120777209">"Ok"</string>
     <string name="page_info_address" msgid="1290683284404217554">"Indirizzo:"</string>
     <string name="page_info" msgid="46593086046896385">"Informazioni sulla pagina"</string>
     <string name="downloading_paramfile" msgid="685182551665849043">"Download di %1$s"</string>
diff --git a/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java b/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
index b3cd4b6..70dd4ee 100644
--- a/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
+++ b/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
@@ -1079,8 +1079,13 @@ public class CaptivePortalLoginActivityTest {
         final Uri mockFile = Uri.parse("content://mockdata");
         final Uri otherFile = Uri.parse("content://otherdata");
         final int downloadId = 123;
+        final int otherDownloadId = 456;
         final HttpServer server = prepareTestDirectlyOpen(linkIdDownload, "dl",
                 filename, mimeType);
+        doReturn(downloadId).when(sDownloadServiceBinder)
+                .requestDownload(any(), any(), any(), any(), any(), any(), eq(mimeType));
+        // Mock intents trying to actually install the profile
+        Intents.intending(not(isInternal())).respondWith(new ActivityResult(RESULT_OK, null));
 
         final UiObject spinner = getUiSpinner();
         // Verify no spinner first.
@@ -1094,7 +1099,8 @@ public class CaptivePortalLoginActivityTest {
         assertEquals(0, Intents.getIntents().size());
         // Trigger callback with negative result with other undesired other download file.
         mActivityScenario.onActivity(a ->
-                a.mProgressCallback.onDownloadComplete(otherFile, mimeType, downloadId, false));
+                a.mProgressCallback.onDownloadComplete(otherFile, mimeType, otherDownloadId,
+                        false));
         // Verify spinner is still visible and no intent to open the target file.
         assertTrue(spinner.exists());
         assertEquals(0, Intents.getIntents().size());
```

