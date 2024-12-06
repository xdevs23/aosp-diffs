```diff
diff --git a/src/main/java/com/android/avatarpicker/ui/details/items/media/PhotoPickerIcon.kt b/src/main/java/com/android/avatarpicker/ui/details/items/media/PhotoPickerIcon.kt
index 251e1ff..cf5f49b 100644
--- a/src/main/java/com/android/avatarpicker/ui/details/items/media/PhotoPickerIcon.kt
+++ b/src/main/java/com/android/avatarpicker/ui/details/items/media/PhotoPickerIcon.kt
@@ -17,6 +17,7 @@
 package com.android.avatarpicker.ui.details.items.media
 
 import android.graphics.ImageDecoder
+import android.multiuser.Flags
 import android.net.Uri
 import android.util.TypedValue
 import androidx.activity.compose.rememberLauncherForActivityResult
@@ -52,17 +53,30 @@ fun PhotoPickerIcon(
     val photoPickerLauncher =
         rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { result ->
             result?.let { selectedUri ->
-                val source = ImageDecoder.createSource(contentResolver, selectedUri)
-                ImageDecoder.decodeBitmap(source).let { bitmap ->
+                if(Flags.fixAvatarPickerNotRespondingForNewUser()){
                     try {
-                        tempFile.saveBitmap(bitmap)
-                        val cropIntent = getCropIntent(contentUri, avatarSizeInPixels)
-                        cropResult.launch(cropIntent)
-                    } catch (exc: IOException) {
-                        resultHandler.onError(exc)
+                            contentResolver.openInputStream(selectedUri)?.use { inputStream ->
+                                contentResolver.openOutputStream(contentUri)?.use { outputStream ->
+                                    inputStream.copyTo(outputStream)
+                                    val cropIntent = getCropIntent(contentUri, avatarSizeInPixels)
+                                    cropResult.launch(cropIntent)
+                                } ?: resultHandler.unselect()
+                            } ?: resultHandler.unselect()
+                        } catch (e: Exception) {
+                            resultHandler.onError(e)
+                        }
+                } else {
+                    val source = ImageDecoder.createSource(contentResolver, selectedUri)
+                    ImageDecoder.decodeBitmap(source).let { bitmap ->
+                        try {
+                            tempFile.saveBitmap(bitmap)
+                            val cropIntent = getCropIntent(contentUri, avatarSizeInPixels)
+                            cropResult.launch(cropIntent)
+                        } catch (exc: IOException) {
+                            resultHandler.onError(exc)
+                        }
                     }
                 }
-
             } ?: resultHandler.unselect()
         }
     MediaIcon(viewModel) {
```

