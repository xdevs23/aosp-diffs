```diff
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 930cc9e..0b5855f 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -19,7 +19,7 @@
     <string name="app_name" msgid="170210454004696382">"Porte-clés"</string>
     <string name="title_select_cert" msgid="3588447616418041699">"Choisir un certificat"</string>
     <string name="requesting_application" msgid="1589142627467598421">"L\'appli %s a demandé un certificat. Choisissez un certificat pour permettre à l\'appli d\'utiliser cette identité auprès des serveurs à compter d\'aujourd\'hui."</string>
-    <string name="requesting_server" msgid="5832565605998634370">"L\'appli a identifié le serveur demandeur comme %s, mais vous ne devez permettre à l\'appli d\'accéder au certificat que si vous faites confiance à celle-ci."</string>
+    <string name="requesting_server" msgid="5832565605998634370">"L\'appli a identifié le serveur demandeur en tant que %s, mais vous devriez permettre à l\'appli d\'accéder au certificat uniquement si vous faites confiance à celle-ci."</string>
     <string name="install_new_cert_message" msgid="4451971501142085495">"Vous pouvez installer des certificats à partir d\'un fichier PKCS#12 doté d\'une extension %1$s ou %2$s conservée dans la mémoire de stockage externe."</string>
     <string name="allow_button" msgid="3030990695030371561">"Sélectionner"</string>
     <string name="deny_button" msgid="3766539809121892584">"Refuser"</string>
diff --git a/tests/Android.bp b/tests/Android.bp
index 5ab61c2..2b28c15 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -35,7 +35,7 @@ android_test {
         "truth",
     ],
     libs: [
-        "android.test.base",
+        "android.test.base.stubs.system",
     ],
     test_suites: ["device-tests"],
     data: [
```

