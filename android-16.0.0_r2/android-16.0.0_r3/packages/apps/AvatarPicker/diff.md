```diff
diff --git a/src/main/java/com/android/avatarpicker/domain/FlagUtils.kt b/src/main/java/com/android/avatarpicker/domain/FlagUtils.kt
index 2ea2743..adefcb2 100644
--- a/src/main/java/com/android/avatarpicker/domain/FlagUtils.kt
+++ b/src/main/java/com/android/avatarpicker/domain/FlagUtils.kt
@@ -26,10 +26,9 @@ import androidx.compose.ui.semantics.semantics
 import androidx.compose.foundation.clickable
 
 fun Modifier.applyReadBackOrder() =
-    if (Flags.fixAvatarPickerReadBackOrder()) this.semantics { isTraversalGroup = true } else this
+    this.semantics { isTraversalGroup = true }
 
 fun Modifier.applySelectable(isSelected: Boolean, select:() ->Unit): Modifier {
-    if (Flags.fixAvatarPickerSelectedReadBack()) {
         if (isSelected)
             return this.semantics {
                 selected = isSelected
@@ -37,6 +36,4 @@ fun Modifier.applySelectable(isSelected: Boolean, select:() ->Unit): Modifier {
             }
         else
             return this.semantics{}.clickable{select()}
-    }
-    return this.clickable{select()}
 }
\ No newline at end of file
diff --git a/src/main/java/com/android/avatarpicker/ui/details/items/media/PhotoPickerIcon.kt b/src/main/java/com/android/avatarpicker/ui/details/items/media/PhotoPickerIcon.kt
index cf5f49b..2b10e60 100644
--- a/src/main/java/com/android/avatarpicker/ui/details/items/media/PhotoPickerIcon.kt
+++ b/src/main/java/com/android/avatarpicker/ui/details/items/media/PhotoPickerIcon.kt
@@ -53,29 +53,16 @@ fun PhotoPickerIcon(
     val photoPickerLauncher =
         rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { result ->
             result?.let { selectedUri ->
-                if(Flags.fixAvatarPickerNotRespondingForNewUser()){
-                    try {
-                            contentResolver.openInputStream(selectedUri)?.use { inputStream ->
-                                contentResolver.openOutputStream(contentUri)?.use { outputStream ->
-                                    inputStream.copyTo(outputStream)
-                                    val cropIntent = getCropIntent(contentUri, avatarSizeInPixels)
-                                    cropResult.launch(cropIntent)
-                                } ?: resultHandler.unselect()
+                try {
+                        contentResolver.openInputStream(selectedUri)?.use { inputStream ->
+                            contentResolver.openOutputStream(contentUri)?.use { outputStream ->
+                                inputStream.copyTo(outputStream)
+                                val cropIntent = getCropIntent(contentUri, avatarSizeInPixels)
+                                cropResult.launch(cropIntent)
                             } ?: resultHandler.unselect()
-                        } catch (e: Exception) {
-                            resultHandler.onError(e)
-                        }
-                } else {
-                    val source = ImageDecoder.createSource(contentResolver, selectedUri)
-                    ImageDecoder.decodeBitmap(source).let { bitmap ->
-                        try {
-                            tempFile.saveBitmap(bitmap)
-                            val cropIntent = getCropIntent(contentUri, avatarSizeInPixels)
-                            cropResult.launch(cropIntent)
-                        } catch (exc: IOException) {
-                            resultHandler.onError(exc)
-                        }
-                    }
+                        } ?: resultHandler.unselect()
+                    } catch (e: Exception) {
+                        resultHandler.onError(e)
                 }
             } ?: resultHandler.unselect()
         }
diff --git a/src/main/res-export/values-cs/strings.xml b/src/main/res-export/values-cs/strings.xml
index 673fed8..c990c68 100644
--- a/src/main/res-export/values-cs/strings.xml
+++ b/src/main/res-export/values-cs/strings.xml
@@ -20,7 +20,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="8177270961671323697">"Nástroj pro výběr avataru"</string>
-    <string name="avatar_picker_title" msgid="557920681111084237">"Vyberte obrázek"</string>
+    <string name="avatar_picker_title" msgid="557920681111084237">"Vyberte si obrázek"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"Vyfotit"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"Zvolit obrázek"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"Vybrat fotku"</string>
diff --git a/src/main/res-export/values-et/strings.xml b/src/main/res-export/values-et/strings.xml
index 2045ae2..f855ac9 100644
--- a/src/main/res-export/values-et/strings.xml
+++ b/src/main/res-export/values-et/strings.xml
@@ -20,7 +20,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="8177270961671323697">"Avatari valija"</string>
-    <string name="avatar_picker_title" msgid="557920681111084237">"Pildi valimine"</string>
+    <string name="avatar_picker_title" msgid="557920681111084237">"Valige pilt"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"Pildista"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"Vali pilt"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"Vali foto"</string>
diff --git a/src/main/res-export/values-fa/strings.xml b/src/main/res-export/values-fa/strings.xml
index 55619dd..9b77f1a 100644
--- a/src/main/res-export/values-fa/strings.xml
+++ b/src/main/res-export/values-fa/strings.xml
@@ -19,7 +19,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="8177270961671323697">"انتخابگر چهرک"</string>
+    <string name="app_name" msgid="8177270961671323697">"انتخاب‌گر چهرک"</string>
     <string name="avatar_picker_title" msgid="557920681111084237">"انتخاب عکس"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"عکس گرفتن"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"انتخاب تصویر"</string>
diff --git a/src/main/res-export/values-fr/strings.xml b/src/main/res-export/values-fr/strings.xml
index 79e5e3c..9211479 100644
--- a/src/main/res-export/values-fr/strings.xml
+++ b/src/main/res-export/values-fr/strings.xml
@@ -19,8 +19,8 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="8177270961671323697">"Outil de sélection d\'avatars"</string>
-    <string name="avatar_picker_title" msgid="557920681111084237">"Choisissez une photo"</string>
+    <string name="app_name" msgid="8177270961671323697">"Sélecteur d\'avatars"</string>
+    <string name="avatar_picker_title" msgid="557920681111084237">"Choisissez une image"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"Prendre une photo"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"Choisir une image"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"Sélectionner la photo"</string>
diff --git a/src/main/res-export/values-hy/strings.xml b/src/main/res-export/values-hy/strings.xml
index b622112..8c8404c 100644
--- a/src/main/res-export/values-hy/strings.xml
+++ b/src/main/res-export/values-hy/strings.xml
@@ -20,7 +20,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="8177270961671323697">"Ավատարի ընտրիչ"</string>
-    <string name="avatar_picker_title" msgid="557920681111084237">"Ընտրեք լուսանկար"</string>
+    <string name="avatar_picker_title" msgid="557920681111084237">"Ընտրեք նկար"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"Լուսանկարել"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"Ընտրել պատկեր"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"Ընտրել լուսանկար"</string>
diff --git a/src/main/res-export/values-lv/strings.xml b/src/main/res-export/values-lv/strings.xml
index cd1fd8c..20a4202 100644
--- a/src/main/res-export/values-lv/strings.xml
+++ b/src/main/res-export/values-lv/strings.xml
@@ -20,7 +20,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="8177270961671323697">"avatāra atlasītājs"</string>
-    <string name="avatar_picker_title" msgid="557920681111084237">"Attēla izvēle"</string>
+    <string name="avatar_picker_title" msgid="557920681111084237">"Izvēlieties attēlu"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"Uzņemt fotoattēlu"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"Izvēlēties attēlu"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"Atlasīt fotoattēlu"</string>
```

