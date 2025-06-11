```diff
diff --git a/Android.bp b/Android.bp
index c6444e5..35edff6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -69,6 +69,7 @@ android_app {
     certificate: "platform",
     platform_apis: true,
     privileged: true,
+    system_ext_specific: true,
 
     optimize: {
         enabled: true,
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index f06ecb8..e107972 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -23,7 +23,7 @@
       android:allowBackup="true"
       android:dataExtractionRules="@xml/data_extraction_rules"
       android:fullBackupContent="@xml/backup_rules"
-      android:label="@string/app_name"
+      android:label="@string/avatar_picker_title"
       android:supportsRtl="true"
       android:theme="@style/Theme.AvatarPicker"
       tools:targetApi="31">
@@ -32,7 +32,7 @@
       android:name=".ui.AvatarPickerActivity"
       android:exported="true"
       android:configChanges="orientation|screenSize|smallestScreenSize|screenLayout|keyboardHidden"
-      android:label="@string/app_name"
+      android:label="@string/avatar_picker_title"
       android:theme="@style/Theme.AvatarPicker">
     <intent-filter>
       <action android:name="com.android.avatarpicker.FULL_SCREEN_ACTIVITY" />
diff --git a/src/main/java/com/android/avatarpicker/ui/AdaptivePane.kt b/src/main/java/com/android/avatarpicker/ui/AdaptivePane.kt
index dd7ac4c..ac0ca8a 100644
--- a/src/main/java/com/android/avatarpicker/ui/AdaptivePane.kt
+++ b/src/main/java/com/android/avatarpicker/ui/AdaptivePane.kt
@@ -41,6 +41,7 @@ import androidx.compose.ui.unit.dp
 @Composable
 fun AdaptivePane(
     showOnePane: Boolean,
+    columns: Int,
     startPane: @Composable () -> Unit,
     endPane: (scope: LazyGridScope) -> Unit,
     bottom: @Composable () -> Unit
@@ -66,7 +67,7 @@ fun AdaptivePane(
             if (showOnePane) {
                 LazyVerticalGrid(
                     modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 8.dp),
-                    columns = GridCells.Fixed(4),
+                    columns = GridCells.Fixed(columns),
                     horizontalArrangement = Arrangement.spacedBy(24.dp),
                     verticalArrangement = Arrangement.spacedBy(24.dp),
                     contentPadding = PaddingValues(bottom = 24.dp)
@@ -92,7 +93,7 @@ fun AdaptivePane(
                         modifier = Modifier.weight(1f)
                             .padding(top = 104.dp, start = 24.dp, end = 24.dp)
                             .fillMaxHeight(),
-                        columns = GridCells.Fixed(4),
+                        columns = GridCells.Fixed(columns),
                         horizontalArrangement = Arrangement.spacedBy(24.dp),
                         verticalArrangement = Arrangement.spacedBy(24.dp),
                         contentPadding = PaddingValues(bottom = 24.dp),
diff --git a/src/main/java/com/android/avatarpicker/ui/AvatarPickerActivity.kt b/src/main/java/com/android/avatarpicker/ui/AvatarPickerActivity.kt
index 4f5a804..beb8d6c 100644
--- a/src/main/java/com/android/avatarpicker/ui/AvatarPickerActivity.kt
+++ b/src/main/java/com/android/avatarpicker/ui/AvatarPickerActivity.kt
@@ -35,6 +35,7 @@ import androidx.compose.runtime.collectAsState
 import androidx.compose.runtime.getValue
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
+import androidx.compose.ui.platform.LocalContext
 import androidx.compose.ui.unit.dp
 import com.android.avatarpicker.AvatarProviderApp
 import com.android.avatarpicker.domain.CAMERA
@@ -44,6 +45,7 @@ import com.android.avatarpicker.ui.details.DetailsList
 import com.android.avatarpicker.ui.details.items.UiState
 import com.android.avatarpicker.ui.info.InfoCard
 import com.android.avatarpicker.ui.theme.AvatarPickerTheme
+import android.util.DisplayMetrics
 
 class AvatarPickerActivity : ComponentActivity() {
 
@@ -73,10 +75,14 @@ class AvatarPickerActivity : ComponentActivity() {
                     Box(
                         Modifier.fillMaxSize(), contentAlignment = Alignment.Center
                     ) {
+                        val display = LocalContext.current.resources.displayMetrics
+                        val defaultDensity = DisplayMetrics.DENSITY_DEVICE_STABLE.toFloat()  / DisplayMetrics.DENSITY_DEFAULT.toFloat()
+                        val columns  = (4 * defaultDensity / display.density).toInt()
                         AdaptivePane(showOnePane = showOnePane,
+                            columns,
                             startPane = { InfoCard(activityViewModel.infoViewModel) },
                             endPane = {
-                                it.DetailsList(activityViewModel.detailsViewModel, itemViewComposer)
+                                it.DetailsList(activityViewModel.detailsViewModel, itemViewComposer, columns)
                             },
                             bottom = {
                                 BottomActionBar(currentResult is UiState.Success<*>, {
diff --git a/src/main/java/com/android/avatarpicker/ui/ResultHandlerImpl.kt b/src/main/java/com/android/avatarpicker/ui/ResultHandlerImpl.kt
index 81b056f..fbdcfbe 100644
--- a/src/main/java/com/android/avatarpicker/ui/ResultHandlerImpl.kt
+++ b/src/main/java/com/android/avatarpicker/ui/ResultHandlerImpl.kt
@@ -30,6 +30,7 @@ import com.android.avatarpicker.ui.details.items.UriTypedItem
 import java.io.File
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.asStateFlow
+import androidx.compose.runtime.getValue
 
 class ResultHandlerImpl(context: Context) : ResultHandler {
     private val resultFile: File
@@ -38,8 +39,8 @@ class ResultHandlerImpl(context: Context) : ResultHandler {
     override val uiState = _uiState.asStateFlow()
 
     override fun <T : SelectableType> onSelect(result: T) {
-        getSelected()?.isSelected = false
-        result.isSelected = true
+        getSelected()?.unselect()
+        result.select()
         _uiState.value = UiState.Success(result)
     }
 
diff --git a/src/main/java/com/android/avatarpicker/ui/details/DetailsList.kt b/src/main/java/com/android/avatarpicker/ui/details/DetailsList.kt
index 41ef0ee..03de920 100644
--- a/src/main/java/com/android/avatarpicker/ui/details/DetailsList.kt
+++ b/src/main/java/com/android/avatarpicker/ui/details/DetailsList.kt
@@ -22,11 +22,11 @@ import com.android.avatarpicker.ui.details.items.ItemViewComposer
 import com.android.avatarpicker.ui.details.items.SelectorWrapper
 
 fun LazyGridScope.DetailsList(detailsViewModel: DetailsViewModel,
-    itemViewComposer: ItemViewComposer) {
+    itemViewComposer: ItemViewComposer, columns: Int) {
     val items = detailsViewModel.groups.value
     var index = 0
     items.forEach { group ->
-        val remaining = group.size % 4
+        val remaining = group.size % columns
         group.forEach { viewModel ->
             index += 1
             item(key = index, contentType = viewModel.typeId) {
@@ -38,7 +38,7 @@ fun LazyGridScope.DetailsList(detailsViewModel: DetailsViewModel,
             }
         }
         if (remaining > 0) {
-            item(span = { GridItemSpan(4 - remaining) }) {
+            item(span = { GridItemSpan(columns - remaining) }) {
                 // invisible break between group
             }
         }
diff --git a/src/main/java/com/android/avatarpicker/ui/details/items/ColoredIconWithDescription.kt b/src/main/java/com/android/avatarpicker/ui/details/items/ColoredIconWithDescription.kt
index da92e4b..6f2d958 100644
--- a/src/main/java/com/android/avatarpicker/ui/details/items/ColoredIconWithDescription.kt
+++ b/src/main/java/com/android/avatarpicker/ui/details/items/ColoredIconWithDescription.kt
@@ -18,6 +18,8 @@ package com.android.avatarpicker.ui.details.items
 
 import androidx.compose.foundation.Image
 import androidx.compose.runtime.Composable
+import androidx.compose.runtime.collectAsState
+import androidx.compose.runtime.getValue
 import androidx.compose.ui.graphics.Color
 import androidx.compose.ui.graphics.ColorFilter
 import androidx.compose.ui.res.painterResource
@@ -28,9 +30,10 @@ import com.android.avatarpicker.domain.applySelectable
 fun ColoredIconWithDescription(
     viewModel: ResourceViewModel, select: () -> Unit
 ) {
+    val isSelected: Boolean by viewModel.isSelected.collectAsState()
     Image(painter = painterResource(id = viewModel.drawableId),
         contentDescription = stringResource(id = viewModel.descriptionId),
         colorFilter = viewModel.color?.let { ColorFilter.tint(color = Color(it)) },
         modifier = GetDefaultIconModifier()
-            .applySelectable(viewModel.isSelected, select))
+            .applySelectable(isSelected, select))
 }
\ No newline at end of file
diff --git a/src/main/java/com/android/avatarpicker/ui/details/items/DrawableWithDescription.kt b/src/main/java/com/android/avatarpicker/ui/details/items/DrawableWithDescription.kt
index fa30f87..4b3be6f 100644
--- a/src/main/java/com/android/avatarpicker/ui/details/items/DrawableWithDescription.kt
+++ b/src/main/java/com/android/avatarpicker/ui/details/items/DrawableWithDescription.kt
@@ -18,6 +18,8 @@ package com.android.avatarpicker.ui.details.items
 
 import androidx.compose.foundation.Image
 import androidx.compose.runtime.Composable
+import androidx.compose.runtime.collectAsState
+import androidx.compose.runtime.getValue
 import androidx.compose.ui.res.painterResource
 import androidx.compose.ui.res.stringResource
 import com.android.avatarpicker.domain.applySelectable
@@ -27,8 +29,9 @@ fun DrawableWithDescription(
     viewModel: ResourceViewModel, select: () -> Unit
 ) {
     val painter = painterResource(id = viewModel.drawableId)
+    val isSelected: Boolean by viewModel.isSelected.collectAsState()
     Image(painter = painter,
         contentDescription = stringResource(id = viewModel.descriptionId),
         modifier = GetDefaultImageModifier()
-            .applySelectable(viewModel.isSelected, select))
+            .applySelectable(isSelected, select))
 }
\ No newline at end of file
diff --git a/src/main/java/com/android/avatarpicker/ui/details/items/SelectableType.kt b/src/main/java/com/android/avatarpicker/ui/details/items/SelectableType.kt
index 0a2dfe7..356a324 100644
--- a/src/main/java/com/android/avatarpicker/ui/details/items/SelectableType.kt
+++ b/src/main/java/com/android/avatarpicker/ui/details/items/SelectableType.kt
@@ -15,6 +15,19 @@
  */
 package com.android.avatarpicker.ui.details.items
 
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+
 open class SelectableType(
-    val typeId: Int, var isSelected: Boolean = false
-)
\ No newline at end of file
+    val typeId: Int, selected: Boolean = false
+) {
+    private val _isSelected = MutableStateFlow<Boolean>(selected)
+    val isSelected = _isSelected.asStateFlow()
+    fun select() {
+        _isSelected.value = true
+    }
+    fun unselect() {
+        _isSelected.value = false
+    }
+}
\ No newline at end of file
diff --git a/src/main/java/com/android/avatarpicker/ui/details/items/SelectorWrapper.kt b/src/main/java/com/android/avatarpicker/ui/details/items/SelectorWrapper.kt
index 6cb4eed..c5e2f5c 100644
--- a/src/main/java/com/android/avatarpicker/ui/details/items/SelectorWrapper.kt
+++ b/src/main/java/com/android/avatarpicker/ui/details/items/SelectorWrapper.kt
@@ -15,7 +15,7 @@
  */
 package com.android.avatarpicker.ui.details.items
 
-import androidx.compose.animation.AnimatedVisibility
+import androidx.compose.animation.core.animateFloatAsState
 import androidx.compose.animation.fadeIn
 import androidx.compose.animation.fadeOut
 import androidx.compose.foundation.background
@@ -28,35 +28,36 @@ import androidx.compose.material.icons.Icons
 import androidx.compose.material.icons.filled.Done
 import androidx.compose.material3.Icon
 import androidx.compose.material3.MaterialTheme
-import androidx.compose.runtime.Composable
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
+import androidx.compose.ui.graphics.graphicsLayer
 import androidx.compose.ui.unit.dp
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.collectAsState
+import androidx.compose.runtime.getValue
+import kotlinx.coroutines.flow.StateFlow
 
 @Composable
-fun SelectorWrapper(isSelected: Boolean, content: @Composable () -> Unit) {
+fun SelectorWrapper(selected: StateFlow<Boolean>, content: @Composable () -> Unit) {
+    val isSelected by selected.collectAsState()
+    val alpha by animateFloatAsState(if (isSelected) 1f else 0f, label = "alpha")
     Box(Modifier.fillMaxSize()) {
         content()
-        AnimatedVisibility(
-            isSelected,
-            Modifier.matchParentSize(),
-            enter = fadeIn(initialAlpha = .3f),
-            exit = fadeOut(targetAlpha = .3f)
+        Box(
+            modifier = Modifier.matchParentSize()
+                .graphicsLayer(alpha = alpha)
+                .background(MaterialTheme.colorScheme.scrim.copy(.32f), CircleShape),
+            contentAlignment = Alignment.Center
         ) {
-            Box(
-                modifier = Modifier.matchParentSize()
-                    .background(MaterialTheme.colorScheme.scrim.copy(.32f), CircleShape),
-                contentAlignment = Alignment.Center
-            ) {
-                Icon(
-                    imageVector = Icons.Default.Done,
-                    contentDescription = null,
-                    modifier = Modifier.background(
-                        MaterialTheme.colorScheme.primaryContainer, CircleShape
-                    ).padding(8.dp).size(16.dp),
-                    tint = MaterialTheme.colorScheme.primary
-                )
-            }
+            Icon(
+                imageVector = Icons.Default.Done,
+                contentDescription = null,
+                modifier = Modifier
+                    .graphicsLayer(alpha = alpha)
+                    .background(MaterialTheme.colorScheme.primaryContainer, CircleShape)
+                    .size(32.dp).padding(8.dp),
+                tint = MaterialTheme.colorScheme.primary
+            )
         }
     }
 }
\ No newline at end of file
diff --git a/src/main/java/com/android/avatarpicker/ui/details/items/media/MediaIcon.kt b/src/main/java/com/android/avatarpicker/ui/details/items/media/MediaIcon.kt
index 041aa9b..573bf56 100644
--- a/src/main/java/com/android/avatarpicker/ui/details/items/media/MediaIcon.kt
+++ b/src/main/java/com/android/avatarpicker/ui/details/items/media/MediaIcon.kt
@@ -20,6 +20,7 @@ import androidx.compose.foundation.Image
 import androidx.compose.foundation.clickable
 import androidx.compose.material3.MaterialTheme
 import androidx.compose.runtime.Composable
+import androidx.compose.ui.Modifier
 import androidx.compose.ui.graphics.ColorFilter
 import androidx.compose.ui.res.painterResource
 import androidx.compose.ui.res.stringResource
@@ -31,5 +32,5 @@ fun MediaIcon(model: ResourceViewModel, select: () -> Unit) {
     Image(painter = painterResource(id = model.drawableId),
         contentDescription = stringResource(id = model.descriptionId),
         colorFilter = ColorFilter.tint(color = MaterialTheme.colorScheme.primary),
-        modifier = GetCircleModifier().clickable { select() })
+        modifier = Modifier.clickable{ select() }.then(GetCircleModifier()))
 }
\ No newline at end of file
diff --git a/src/main/res-export/values-ar/strings.xml b/src/main/res-export/values-ar/strings.xml
index f57b5b5..9d32cb7 100644
--- a/src/main/res-export/values-ar/strings.xml
+++ b/src/main/res-export/values-ar/strings.xml
@@ -20,7 +20,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="8177270961671323697">"أداة اختيار الأفاتار"</string>
-    <string name="avatar_picker_title" msgid="557920681111084237">"اختيار صورة"</string>
+    <string name="avatar_picker_title" msgid="557920681111084237">"اختَر صورة"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"التقاط صورة"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"اختيار صورة"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"اختيار صورة"</string>
diff --git a/src/main/res-export/values-fi/strings.xml b/src/main/res-export/values-fi/strings.xml
index a9932ef..11cf731 100644
--- a/src/main/res-export/values-fi/strings.xml
+++ b/src/main/res-export/values-fi/strings.xml
@@ -25,7 +25,7 @@
     <string name="user_image_choose_photo" msgid="1705074212740055639">"Valitse kuva"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"Valitse kuva"</string>
     <string name="default_user_icon_description" msgid="102085856940412685">"Oletuskäyttäjäkuvake"</string>
-    <string name="cancel" msgid="939074129054561480">"Peruuta"</string>
+    <string name="cancel" msgid="939074129054561480">"Peru"</string>
     <string name="back" msgid="9180928429284474094">"Takaisin"</string>
     <string name="done" msgid="3529937494606458545">"Valmis"</string>
 </resources>
diff --git a/src/main/res-export/values-fr-rCA/strings.xml b/src/main/res-export/values-fr-rCA/strings.xml
index c745b50..ddf8bb4 100644
--- a/src/main/res-export/values-fr-rCA/strings.xml
+++ b/src/main/res-export/values-fr-rCA/strings.xml
@@ -20,7 +20,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="8177270961671323697">"Sélecteur d\'avatar"</string>
-    <string name="avatar_picker_title" msgid="557920681111084237">"Choisir une photo"</string>
+    <string name="avatar_picker_title" msgid="557920681111084237">"Choisissez une photo"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"Prendre une photo"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"Sélectionner une image"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"Sélectionner une photo"</string>
diff --git a/src/main/res-export/values-fr/strings.xml b/src/main/res-export/values-fr/strings.xml
index 7ddaee7..79e5e3c 100644
--- a/src/main/res-export/values-fr/strings.xml
+++ b/src/main/res-export/values-fr/strings.xml
@@ -20,7 +20,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="8177270961671323697">"Outil de sélection d\'avatars"</string>
-    <string name="avatar_picker_title" msgid="557920681111084237">"Choisir une photo"</string>
+    <string name="avatar_picker_title" msgid="557920681111084237">"Choisissez une photo"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"Prendre une photo"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"Choisir une image"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"Sélectionner la photo"</string>
diff --git a/src/main/res-export/values-hr/strings.xml b/src/main/res-export/values-hr/strings.xml
index 1fb0bf5..d845073 100644
--- a/src/main/res-export/values-hr/strings.xml
+++ b/src/main/res-export/values-hr/strings.xml
@@ -20,7 +20,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="8177270961671323697">"Alat za odabir avatara"</string>
-    <string name="avatar_picker_title" msgid="557920681111084237">"Odabir slike"</string>
+    <string name="avatar_picker_title" msgid="557920681111084237">"Odaberite sliku"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"Snimi fotografiju"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"Odaberite sliku"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"Odaberite fotografiju"</string>
diff --git a/src/main/res-export/values-iw/strings.xml b/src/main/res-export/values-iw/strings.xml
index 8d1d5e7..e3c6aff 100644
--- a/src/main/res-export/values-iw/strings.xml
+++ b/src/main/res-export/values-iw/strings.xml
@@ -20,7 +20,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="8177270961671323697">"הכלי לבחירת דמות"</string>
-    <string name="avatar_picker_title" msgid="557920681111084237">"בחירת תמונה"</string>
+    <string name="avatar_picker_title" msgid="557920681111084237">"איזו תמונה להגדיר לך?"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"צילום תמונה"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"לבחירת תמונה"</string>
     <string name="user_image_photo_selector" msgid="6810039483906384177">"בחירת תמונה"</string>
diff --git a/src/main/res-export/values-lv/strings.xml b/src/main/res-export/values-lv/strings.xml
index c7dba19..cd1fd8c 100644
--- a/src/main/res-export/values-lv/strings.xml
+++ b/src/main/res-export/values-lv/strings.xml
@@ -19,7 +19,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_name" msgid="8177270961671323697">"Iemiesojuma atlasītājs"</string>
+    <string name="app_name" msgid="8177270961671323697">"avatāra atlasītājs"</string>
     <string name="avatar_picker_title" msgid="557920681111084237">"Attēla izvēle"</string>
     <string name="user_image_take_photo" msgid="95128854106654908">"Uzņemt fotoattēlu"</string>
     <string name="user_image_choose_photo" msgid="1705074212740055639">"Izvēlēties attēlu"</string>
diff --git a/src/tests/common/java/com/android/avatatpicker/tests/FakeResultHandler.kt b/src/tests/common/java/com/android/avatatpicker/tests/FakeResultHandler.kt
index 1c87bbc..84689b6 100644
--- a/src/tests/common/java/com/android/avatatpicker/tests/FakeResultHandler.kt
+++ b/src/tests/common/java/com/android/avatatpicker/tests/FakeResultHandler.kt
@@ -31,8 +31,8 @@ class FakeResultHandler : ResultHandler {
     override val uiState = _uiState.asStateFlow()
 
     override fun <T : SelectableType> onSelect(result: T) {
-        getSelected()?.isSelected = false
-        result.isSelected = true
+        getSelected()?.unselect()
+        result.select()
         _uiState.value = UiState.Success(result)
     }
 
diff --git a/src/tests/ui/java/com/android/avatarpicker/tests/ui/DetailsCardTest.kt b/src/tests/ui/java/com/android/avatarpicker/tests/ui/DetailsCardTest.kt
index c0134dd..aedd025 100644
--- a/src/tests/ui/java/com/android/avatarpicker/tests/ui/DetailsCardTest.kt
+++ b/src/tests/ui/java/com/android/avatarpicker/tests/ui/DetailsCardTest.kt
@@ -55,7 +55,7 @@ class DetailsCardTest {
                     verticalArrangement = Arrangement.spacedBy(24.dp),
                     contentPadding = PaddingValues(bottom = 24.dp)
                 ) {
-                    DetailsList(model, ItemViewComposerImpl())
+                    DetailsList(model, ItemViewComposerImpl(), 4)
                 }
             }
         }
@@ -81,7 +81,7 @@ class DetailsCardTest {
                     verticalArrangement = Arrangement.spacedBy(24.dp),
                     contentPadding = PaddingValues(bottom = 24.dp)
                 ) {
-                    DetailsList(model, ItemViewComposerImpl())
+                    DetailsList(model, ItemViewComposerImpl(), 4)
                 }
             }
         }
```

