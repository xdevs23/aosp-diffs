```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index d32bc3b..dd0900e 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -27,6 +27,7 @@
     <application
             android:label="@string/title"
             android:theme="@style/SystemUpdaterTheme"
+            android:enableOnBackInvokedCallback="false"
             android:supportsRtl="true">
         <activity
             android:name="com.android.car.systemupdater.SystemUpdaterActivity"
diff --git a/OWNERS b/OWNERS
index c6a8f5a..b36dee8 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
 nicksauer@google.com
-ajchen@google.com
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index ccc7f47..561b242 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -17,11 +17,11 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="title" msgid="9099755437807065998">"स्थानिक सिस्टम अपडेट"</string>
+    <string name="title" msgid="9099755437807065998">"स्थानिक सिस्टीम अपडेट"</string>
     <string name="invalid_file_type" msgid="5363346679377832590">"अपडेट करण्यासाठी ही फाइल योग्य नाही"</string>
     <string name="unknown_file" msgid="4460330045071455406">"अज्ञात फाइल"</string>
     <string name="cannot_access_storage" msgid="692801523959625901">"स्टोरेज डिव्हाइस अ‍ॅक्सेस करू शकत नाही"</string>
-    <string name="update_in_progress" msgid="7657197919645064655">"सिस्टम अपडेट लागू करत आहे"</string>
+    <string name="update_in_progress" msgid="7657197919645064655">"सिस्टीम अपडेट लागू करत आहे"</string>
     <string name="update_file_name" msgid="3034222525060204549">"फाइल: %s"</string>
     <string name="update_file_size" msgid="4816394194716640579">"आकार: "</string>
     <string name="install_now" msgid="1526380165774958831">"आता इंस्टॉल करा"</string>
@@ -31,7 +31,7 @@
     <string name="install_ready" msgid="5831701403889581045">"अपडेट इंस्टॉल होण्यासाठी तयार आहे."</string>
     <string name="install_in_progress" msgid="1447531401625704953">"इंस्टॉल करणे सुरू आहे…"</string>
     <string name="install_success" msgid="7607370228817982339">"अपडेट यशस्वीरीत्या पूर्ण झाले."</string>
-    <string name="install_failed" msgid="6019321590904856934">"सिस्टम अपडेट इंस्टॉल करता आले नाही."</string>
+    <string name="install_failed" msgid="6019321590904856934">"सिस्टीम अपडेट इंस्टॉल करता आले नाही."</string>
     <string name="rebooting" msgid="2147644401685874548">"अपडेट यशस्वीरीत्या पूर्ण झाले. रीबुटिंग…"</string>
     <string name="volumes" msgid="9062088000979584509">"व्हॉल्यूम (%d) आहे"</string>
     <string name="path" msgid="7133964085947968274">"पथ: %s"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 3199707..86905c5 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -31,7 +31,7 @@
     <string name="install_ready" msgid="5831701403889581045">"Atualização pronta a ser instalada."</string>
     <string name="install_in_progress" msgid="1447531401625704953">"Instalação em curso…"</string>
     <string name="install_success" msgid="7607370228817982339">"Atualização efetuada com êxito."</string>
-    <string name="install_failed" msgid="6019321590904856934">"Falha ao instalar a atualiz. do sistema."</string>
+    <string name="install_failed" msgid="6019321590904856934">"Falha ao instalar a atualização do sistema."</string>
     <string name="rebooting" msgid="2147644401685874548">"Atualização com êxito. A reiniciar…"</string>
     <string name="volumes" msgid="9062088000979584509">"Volumes (%d)"</string>
     <string name="path" msgid="7133964085947968274">"Caminho: %s"</string>
```

