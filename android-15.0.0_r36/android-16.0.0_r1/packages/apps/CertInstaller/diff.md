```diff
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 82257bb..ab4622e 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -32,7 +32,7 @@
     <string name="one_cacrt" msgid="2667950425420663146">"un certificado AC"</string>
     <string name="n_cacrts" msgid="2141498640685639208">"%d certificados AC"</string>
     <string name="password_error" msgid="2042471639556516356">"Escribe la contraseña correcta."</string>
-    <string name="password_empty_error" msgid="591713406761723025">"Escribe la contraseña."</string>
+    <string name="password_empty_error" msgid="591713406761723025">"Introduce la contraseña."</string>
     <string name="name_empty_error" msgid="3808800768660110354">"Escribe un nombre."</string>
     <string name="name_char_error" msgid="3176618568784938968">"Escribe un nombre que contenga solo letras y números."</string>
     <string name="unable_to_save_cert" msgid="9178604087335389686">"No se ha podido guardar el certificado. El almacenamiento de credenciales no está habilitado o no se ha iniciado correctamente."</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index acf751c..8cd57b5 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -69,7 +69,7 @@
     <string name="wifi_title" msgid="8475811746333426489">"Wi-Fi प्रोफाइल"</string>
     <string name="wifi_detail_title" msgid="3627332137252994395">"%s को लागि विवरणहरू"</string>
     <string name="wifi_detail_label" msgid="3032151019356747583">"विवरणहरू"</string>
-    <string name="wifi_install_label" msgid="1449629407724323233">"स्थापना गर्नुहो"</string>
+    <string name="wifi_install_label" msgid="1449629407724323233">"इन्स्टल गर्नुहोस्"</string>
     <string name="wifi_installing_label" msgid="8387393993627129025">"स्थापना गर्दै"</string>
     <string name="wifi_cancel_label" msgid="1328748037608392134">"रद्द गर्नुहोस्"</string>
     <string name="wifi_dismiss_label" msgid="1916684434873972698">"खारेज गर्नुहोस्"</string>
diff --git a/robotests/Android.bp b/robotests/Android.bp
index 41ad026..2066fc8 100644
--- a/robotests/Android.bp
+++ b/robotests/Android.bp
@@ -17,7 +17,5 @@ android_robolectric_test {
 
     instrumentation_for: "CertInstaller",
 
-    upstream: true,
-
     strict_mode: false,
 }
```

