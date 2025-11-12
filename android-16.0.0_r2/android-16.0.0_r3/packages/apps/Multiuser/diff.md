```diff
diff --git a/Android.bp b/Android.bp
index c108e5e..d98fe87 100644
--- a/Android.bp
+++ b/Android.bp
@@ -22,6 +22,7 @@ android_app {
     platform_apis: true,
     privileged: true,
     system_ext_specific: true,
+    resource_dirs: ["Widget/src/main/res"],
 
     optimize: {
         enabled: true,
diff --git a/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidget.kt b/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidget.kt
index b57ade5..06f0808 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidget.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidget.kt
@@ -17,7 +17,7 @@
 package com.android.multiuser.widget
 
 import android.content.Context
-import android.os.UserManager
+import android.multiuser.Flags
 import androidx.compose.runtime.collectAsState
 import androidx.compose.runtime.Composable
 import androidx.compose.runtime.getValue
@@ -33,6 +33,7 @@ import com.android.multiuser.widget.data.ActionsRepository
 import com.android.multiuser.widget.data.ImageRepository
 import com.android.multiuser.widget.data.IntentRepository
 import com.android.multiuser.widget.data.UsersRepository
+import com.android.multiuser.widget.ui.view.LayoutView
 import com.android.multiuser.widget.ui.view.layout.ErrorLayout
 import com.android.multiuser.widget.ui.view.layout.LoadingLayout
 import com.android.multiuser.widget.ui.view.layout.MultiuserWidgetLayout
@@ -42,7 +43,8 @@ import com.android.multiuser.widget.viewmodel.UsersViewModel
 import kotlinx.coroutines.launch
 
 class MultiuserWidget : GlanceAppWidget() {
-  override val sizeMode: SizeMode = SizeMode.Exact
+
+  override val sizeMode = SizeMode.Exact
 
   override suspend fun provideGlance(context: Context, id: GlanceId) {
     val userManager = MultiuserWidgetUtil.getUserManager(context)
@@ -68,7 +70,13 @@ class MultiuserWidget : GlanceAppWidget() {
         scope.launch { viewModel.reload() }
 
       is UiState.Loading -> LoadingLayout()
-      is UiState.Success -> MultiuserWidgetLayout(viewModel)
+      is UiState.Success -> {
+        if (Flags.widgetCurrentUserView()) {
+          LayoutView(viewModel)
+        } else {
+          MultiuserWidgetLayout(viewModel)
+        }
+      }
       else -> ErrorLayout()
     }
   }
diff --git a/Widget/src/main/java/com/android/multiuser/widget/data/UsersRepository.kt b/Widget/src/main/java/com/android/multiuser/widget/data/UsersRepository.kt
index d172cee..65c420e 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/data/UsersRepository.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/data/UsersRepository.kt
@@ -17,15 +17,10 @@
 package com.android.multiuser.widget.data
 
 import android.app.ActivityManager
-import android.content.Context
-import android.content.ContextWrapper
 import android.content.pm.UserInfo
-import android.graphics.Bitmap
+import android.multiuser.Flags
 import android.os.UserHandle
 import android.os.UserManager
-import java.io.File
-import java.io.FileOutputStream
-import java.io.IOException
 import kotlin.collections.List
 import com.android.multiuser.widget.data.model.User
 import com.android.multiuser.widget.data.model.UserSwitchRestrictions
@@ -39,8 +34,14 @@ class UsersRepository(private val userManager: UserManager?,
             // This ensures the error layout is shown in the UI.
             return listOf()
         }
-        var userInfoList = userManager.getAliveUsers()
-            .filter { it.isFull() && it.supportsSwitchTo() }
+        var userInfoList = userManager.getAliveUsers().filter { user ->
+            if (Flags.widgetCurrentUserView()) {
+                user.id == currentUserId
+            } else {
+                (user.isFull() && user.supportsSwitchTo())
+            }
+        }
+
         return userInfoList
             .map { userInfo: UserInfo ->
                 User(
diff --git a/Widget/src/main/java/com/android/multiuser/widget/ui/view/AdaptiveUserView.kt b/Widget/src/main/java/com/android/multiuser/widget/ui/view/AdaptiveUserView.kt
new file mode 100644
index 0000000..1292315
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/ui/view/AdaptiveUserView.kt
@@ -0,0 +1,71 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.multiuser.widget.ui.view
+
+import androidx.compose.runtime.collectAsState
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.rememberCoroutineScope
+import androidx.compose.ui.unit.sp
+import androidx.glance.GlanceModifier
+import androidx.glance.Image
+import androidx.glance.ImageProvider
+import androidx.glance.layout.size
+import androidx.glance.text.Text
+import androidx.glance.text.TextStyle
+import com.android.multiuser.widget.R
+import com.android.multiuser.widget.ui.view.layout.AdaptivePane
+import com.android.multiuser.widget.viewmodel.UiState
+import com.android.multiuser.widget.viewmodel.UserStack
+import com.android.multiuser.widget.viewmodel.UserViewModel
+import kotlinx.coroutines.launch
+
+/**
+ * Displays user data in the widget.
+ */
+@Composable
+fun AdaptiveUserView (
+    viewModel: UserViewModel,
+    userStack: UserStack,
+    modifier: GlanceModifier,
+) {
+    val bitmap by viewModel.bitmap.collectAsState()
+    val scope = rememberCoroutineScope()
+    val uiState by viewModel.uiState.collectAsState()
+    scope.launch {
+        if (uiState != UiState.Loading) {
+            viewModel.loadAvatar()
+        }
+    }
+    AdaptivePane(modifier = modifier,
+        arrangement = userStack.arrangement,
+        startPane = {
+            Image(
+            provider = bitmap?.let { ImageProvider(it) }
+                ?: ImageProvider(R.drawable.account_circle),
+            contentDescription = viewModel.contentDescription,
+            modifier = GlanceModifier.size(userStack.imageSize)
+        )},
+        endPane = { if (userStack.textMetric.size > 0.sp) {
+            Text(
+                text = viewModel.name,
+                maxLines = 1,
+                style = TextStyle(fontSize = userStack.textMetric.size),
+            )
+        } else { null }
+        })
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/ui/view/AdptiveActionsView.kt b/Widget/src/main/java/com/android/multiuser/widget/ui/view/AdptiveActionsView.kt
new file mode 100644
index 0000000..32f7370
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/ui/view/AdptiveActionsView.kt
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.multiuser.widget.ui.actions
+
+import androidx.compose.runtime.Composable
+import androidx.glance.GlanceModifier
+import androidx.glance.layout.Alignment
+import androidx.glance.layout.Box
+import androidx.glance.layout.fillMaxWidth
+import androidx.glance.text.Text
+import androidx.glance.text.TextAlign
+import androidx.glance.text.TextStyle
+import com.android.multiuser.widget.viewmodel.Arrangement
+import com.android.multiuser.widget.viewmodel.LayoutViewModel
+
+//TODO: Implement b/409212274
+@Composable
+fun AdaptiveActionsView (
+    modifier: GlanceModifier = GlanceModifier,
+    layout: LayoutViewModel
+) {
+    Box(
+        modifier = modifier.fillMaxWidth(),
+        contentAlignment = if(layout.arrangement is Arrangement.Vertical) { Alignment.Center } else { Alignment.CenterEnd } // Center content within the Box
+    ) {
+        Text(
+            text = "PLACEHOLDER",
+            style = TextStyle(textAlign = TextAlign.Center)
+        )
+    }
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/ui/view/LayoutView.kt b/Widget/src/main/java/com/android/multiuser/widget/ui/view/LayoutView.kt
new file mode 100644
index 0000000..7786f76
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/ui/view/LayoutView.kt
@@ -0,0 +1,82 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.multiuser.widget.ui.view
+
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.collectAsState
+import androidx.compose.runtime.getValue
+import androidx.glance.GlanceModifier
+import androidx.glance.GlanceTheme
+import androidx.glance.LocalContext
+import androidx.glance.LocalSize
+import androidx.glance.appwidget.components.Scaffold
+import androidx.glance.layout.Alignment
+import androidx.glance.layout.Row
+import androidx.glance.layout.fillMaxSize
+import com.android.multiuser.widget.ui.actions.AdaptiveActionsView
+import com.android.multiuser.widget.ui.view.layout.AdaptivePane
+import com.android.multiuser.widget.ui.view.layout.WidgetTitleBar
+import com.android.multiuser.widget.viewmodel.Arrangement
+import com.android.multiuser.widget.viewmodel.LayoutViewModel
+import com.android.multiuser.widget.viewmodel.UserViewModel
+import com.android.multiuser.widget.viewmodel.UsersViewModel
+
+
+
+@Composable
+fun LayoutView(model: UsersViewModel) {
+    val items by model.data.collectAsState()
+    items.filterIsInstance<UserViewModel>().firstOrNull()?.let { userViewModel ->
+        val layout = LayoutViewModel(LocalSize.current, LocalContext.current.resources, userViewModel)
+        val titleBarVisible by layout.titleBarVisible.collectAsState()
+
+        Scaffold(
+            titleBar = if (titleBarVisible) {
+                { WidgetTitleBar() }
+            } else {
+                null
+            },
+            backgroundColor = GlanceTheme.colors.widgetBackground
+        ) {
+            Row(
+                modifier = GlanceModifier.fillMaxSize(),
+                verticalAlignment = Alignment.CenterVertically,
+                horizontalAlignment = if (layout.arrangement is Arrangement.Vertical) {
+                    Alignment.CenterHorizontally
+                    // |      🙃      |
+                    // |     Name     |
+                } else {
+                    Alignment.Start
+                    // | 🙃 Name      |
+                }
+            ) {
+                AdaptivePane(
+                    arrangement = layout.arrangement,
+                    startPane = {
+                        layout.userStack?.let { userStack ->
+                            AdaptiveUserView(
+                                viewModel = userViewModel,
+                                userStack,
+                                modifier = GlanceModifier
+                            )
+                        }
+                    },
+                    endPane = { AdaptiveActionsView(GlanceModifier, layout) })
+            }
+        }
+    }
+}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/ui/view/layout/AdaptivePane.kt b/Widget/src/main/java/com/android/multiuser/widget/ui/view/layout/AdaptivePane.kt
new file mode 100644
index 0000000..5f9d9fd
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/ui/view/layout/AdaptivePane.kt
@@ -0,0 +1,62 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.multiuser.widget.ui.view.layout
+
+import androidx.compose.runtime.Composable
+import androidx.glance.appwidget.components.Scaffold
+import androidx.glance.layout.size
+import androidx.glance.layout.Alignment
+import androidx.glance.layout.Column
+import androidx.glance.layout.Row
+import androidx.glance.layout.Spacer
+import androidx.glance.GlanceModifier
+import com.android.multiuser.widget.viewmodel.Arrangement
+
+
+/**
+ * A layout focused on presenting a grid of images with titles. The list is
+displayed in a [Scaffold] below a title bar.
+ * @param model view model with users and actions data.
+ */
+
+@Composable
+fun AdaptivePane(
+    modifier: GlanceModifier = GlanceModifier,
+    startPane: @Composable () -> Unit,
+    endPane: @Composable () -> Unit,
+    arrangement: Arrangement = Arrangement.Horizontal()
+) {
+    if (arrangement is Arrangement.Horizontal) {
+        // |                                |
+        // | Start Pane | Spacer | End Pane |
+        // |                                |
+        Row(modifier=modifier, verticalAlignment = Alignment.CenterVertically) {
+            startPane()
+            Spacer(GlanceModifier.size(arrangement.gutter))
+            endPane()
+        }
+    } else {
+        // |    Start Pane     |
+        // |      Spacer       |
+        // |     End Pane      |
+        Column(modifier=modifier, horizontalAlignment = Alignment.CenterHorizontally) {
+            startPane()
+            Spacer(GlanceModifier.size(arrangement.gutter))
+            endPane()
+        }
+    }
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/util/SizeUtils.kt b/Widget/src/main/java/com/android/multiuser/widget/util/SizeUtils.kt
new file mode 100644
index 0000000..0f527c9
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/util/SizeUtils.kt
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.multiuser.widget.util
+
+import android.content.res.Resources
+import android.util.DisplayMetrics
+import android.util.TypedValue
+import androidx.annotation.DimenRes
+import androidx.compose.ui.unit.TextUnit
+import androidx.compose.ui.unit.dp
+import androidx.compose.ui.unit.sp
+
+
+fun Resources.spToDp(@DimenRes dimenId: Int) = getDimension(dimenId).inSp(displayMetrics).value.dp
+fun Resources.dp(@DimenRes dimenId: Int) = getDimension(dimenId).inDp(displayMetrics)
+fun Resources.sp(@DimenRes dimenId: Int) = getDimension(dimenId).inSp(displayMetrics)
+
+fun Float.inSp(metrics: DisplayMetrics) = TypedValue.deriveDimension(
+    TypedValue.COMPLEX_UNIT_SP, this, metrics).sp
+
+fun Float.inDp(metrics: DisplayMetrics) = TypedValue.deriveDimension(
+    TypedValue.COMPLEX_UNIT_DIP, this, metrics).dp
+
+fun TextUnit.toDp(metrics: DisplayMetrics) =
+    TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value, metrics).dp
+
+
diff --git a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/Arrangement.kt b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/Arrangement.kt
new file mode 100644
index 0000000..6b0877e
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/Arrangement.kt
@@ -0,0 +1,25 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.multiuser.widget.viewmodel
+
+import androidx.compose.ui.unit.Dp
+import androidx.compose.ui.unit.dp
+
+sealed class Arrangement(val gutter: Dp = 0.dp, val padding: Dp = 0.dp) {
+    class Horizontal(gutter: Dp = 8.dp, padding: Dp = 0.dp) : Arrangement(gutter, padding)
+    class Vertical(gutter: Dp = 8.dp, padding: Dp = 0.dp)  : Arrangement(gutter, padding)
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/LayoutViewModel.kt b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/LayoutViewModel.kt
new file mode 100644
index 0000000..b67b767
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/LayoutViewModel.kt
@@ -0,0 +1,119 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.multiuser.widget.viewmodel
+
+import android.content.res.Resources
+import androidx.compose.ui.unit.dp
+import androidx.compose.ui.unit.DpSize
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import com.android.multiuser.widget.R
+import com.android.multiuser.widget.util.dp
+
+class LayoutViewModel(
+    var size: DpSize, val res: Resources, val userViewModel: UserViewModel
+) {
+    val titleBarVisible: StateFlow<Boolean> = MutableStateFlow<Boolean>(false)
+    val arrangement = if (size.width <= size.height) {
+        Arrangement.Vertical()
+    } else {
+        Arrangement.Horizontal()
+    }
+    var userStack: UserStack? = null
+    val actionStackHeight = 56.dp //TODO: Implement b/409212274
+    val actionStackWidth = 56.dp //TODO: Implement b/409212274
+    val widgetPadding = res.dp(R.dimen.content_padding) * 2// top+bottom or left+right
+
+    // with title bar visible we do not set top padding
+    val titleBarHeight = res.dp(R.dimen.title_bar_height) - res.dp(R.dimen.content_padding)
+    val userStacks = UserStacks(res, userViewModel.name)
+
+    init {
+        if (arrangement is Arrangement.Vertical) {
+            // | Users ⚙️|
+            // |=========|
+            // |   🙃    |
+            // |  Name   |
+            // |  🔄 ➕  |
+            var verticalHeight = actionStackHeight + widgetPadding
+            userStack =
+                listOf(
+                    userStacks.SMALL_VERTICAL,
+                    userStacks.LARGE_VERTICAL
+                ).filter { it.height + verticalHeight + titleBarHeight <= (size.height) }
+                    .maxByOrNull { it.height }
+            if (userStack == null) { // title bar does not fit, check without title bar
+                (titleBarVisible as MutableStateFlow<Boolean>).value = false
+                // |   🙃    |
+                // |  Name   |       |   🙃    |
+                // |  🔄 ➕  |       |  🔄 ➕  |
+                userStack = listOf(
+                    userStacks.SMALL_IMAGE_ONLY,
+                    userStacks.SMALL_VERTICAL,
+                    userStacks.LARGE_VERTICAL
+                ).filter { it.height + verticalHeight <= (size.height) }
+                    .maxByOrNull { it.height }
+                if (userStack == null) { // user name does not fit, use small image only
+                    // |  🔄 ➕  |
+                }
+            } else { // show title bar
+                (titleBarVisible as MutableStateFlow<Boolean>).value = true
+            }
+        } else { // Large vertical user stack has priority in horizontal layout
+            // | Users    ⚙️ |
+            // |=============|
+            // |   🙃   | 🔄 |
+            // |  Name  | ➕ |
+            var horizontalWidth = actionStackWidth + widgetPadding
+            if (userStacks.LARGE_VERTICAL.height + titleBarHeight + widgetPadding <= (size.height)
+                && (userStacks.LARGE_VERTICAL.width + horizontalWidth <= size.width)) {
+                (titleBarVisible as MutableStateFlow<Boolean>).value = true
+                userStack = userStacks.LARGE_VERTICAL
+            } else { // Vertical layout does not fit, try all others
+                // | Users         ⚙️ |    | Users    ⚙️ |    | Users    ⚙️ |    | Users  ⚙️ |
+                // |==================|    |=============|    |   🙃   | 🔄 |    |===========|
+                // | 🙃 Name | 🔄  ➕ |    | 🙃 | 🔄  ➕ |    |  Name  | ➕ |    |  🙃  | ➕ |
+                userStack = listOf(
+                    userStacks.SMALL_HORIZONTAL,
+                    userStacks.LARGE_HORIZONTAL,
+                    userStacks.SMALL_VERTICAL,
+                    userStacks.SMALL_IMAGE_ONLY
+                ).filter {
+                        (it.height + titleBarHeight + widgetPadding <= (size.height))
+                                && (it.width + horizontalWidth <= size.width)
+                    }.maxByOrNull { it.width }
+                (titleBarVisible as MutableStateFlow<Boolean>).value = true
+                if (userStack == null) {// Title bar does not fit, try without
+                    // | 🙃 Name | 🔄  ➕ |        | 🙃 | 🔄  ➕ |
+                    userStack = listOf(
+                        userStacks.SMALL_HORIZONTAL,
+                        userStacks.LARGE_HORIZONTAL,
+                        userStacks.SMALL_IMAGE_ONLY
+                    ).filter {
+                            (it.height + widgetPadding <= (size.height))
+                                    && (it.width + horizontalWidth <= size.width)
+                        }.maxByOrNull { it.width }
+                    (titleBarVisible as MutableStateFlow<Boolean>).value = false
+                }
+                if (userStack == null) {
+                    // user name does not fit, show buttons only
+                    // |  🔄 ➕  |
+                }
+            }
+        }
+    }
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/TextMetric.kt b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/TextMetric.kt
new file mode 100644
index 0000000..0aa5319
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/TextMetric.kt
@@ -0,0 +1,35 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.multiuser.widget.viewmodel
+
+import android.content.res.Resources
+import androidx.annotation.DimenRes
+import androidx.compose.ui.unit.Dp
+import androidx.compose.ui.unit.TextUnit
+import androidx.compose.ui.unit.dp
+import androidx.compose.ui.unit.sp
+import com.android.multiuser.widget.util.sp
+import com.android.multiuser.widget.util.spToDp
+
+class TextMetric(res: Resources, @DimenRes textSizeId: Int? = null, text: String = "") {
+    val size: TextUnit = textSizeId?.let { res.sp(it) } ?: 0.sp
+    val height: Dp = textSizeId?.let { res.spToDp(it) } ?: 0.dp
+    // TODO: Verify how text min width should be calculated
+    val width = 100.dp
+
+    override fun toString() = "TextMetric size: $size, height: $height, width: $width"
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UserStack.kt b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UserStack.kt
new file mode 100644
index 0000000..6458eef
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UserStack.kt
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.multiuser.widget.viewmodel
+
+import androidx.compose.ui.unit.Dp
+
+/**
+ * Single User Stack = person image + person name
+ */
+class UserStack(val arrangement: Arrangement, val imageSize: Dp, val textMetric: TextMetric) {
+    val width = if(arrangement is Arrangement.Horizontal) {
+        imageSize + textMetric.width + arrangement.gutter + arrangement.padding
+    } else {
+        imageSize + arrangement.padding
+    }
+
+    val height = if(arrangement is Arrangement.Vertical) {
+        imageSize + textMetric.height + arrangement.gutter + arrangement.padding
+    } else {
+        imageSize + arrangement.padding
+    }
+
+    override fun toString(): String {
+        return if(arrangement is Arrangement.Vertical) {"V"} else {"H"} + " ${width} x ${height} imageSize: $imageSize gutter: ${arrangement.gutter}\ntext: ${textMetric.width}x${textMetric.height}"
+    }
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UserStacks.kt b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UserStacks.kt
new file mode 100644
index 0000000..8ab3ea9
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UserStacks.kt
@@ -0,0 +1,46 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.multiuser.widget.viewmodel
+
+import android.content.res.Resources
+import androidx.compose.ui.unit.Dp
+import com.android.multiuser.widget.R
+import com.android.multiuser.widget.util.dp
+
+class UserStacks(val res: Resources,val text:String) {
+    private val NONE_TEXT = TextMetric(res)
+    private val MEDIUM_TEXT = TextMetric(res, R.dimen.user_text_min_size)
+    private val LARGE_TEXT = TextMetric(res, R.dimen.user_text_max_size)
+
+    val mediumImageSize: Dp = res.dp(R.dimen.user_image_min_size)
+    val largeImageSize = res.dp(R.dimen.user_image_max_size)
+    val verticalGutter = res.dp(R.dimen.user_vertical_gutter)
+    val verticalArrangement = Arrangement.Vertical(verticalGutter)
+    val horizontalGutter = res.dp(R.dimen.user_horizontal_gutter)
+    val horizontalArrangement = Arrangement.Horizontal(horizontalGutter)
+
+    val SMALL_IMAGE_ONLY =
+        UserStack(Arrangement.Vertical(verticalGutter), mediumImageSize, NONE_TEXT)
+    val SMALL_VERTICAL =
+        UserStack(Arrangement.Vertical(verticalGutter), mediumImageSize, MEDIUM_TEXT)
+    val LARGE_VERTICAL = UserStack(Arrangement.Vertical(verticalGutter), largeImageSize, LARGE_TEXT)
+    val SMALL_HORIZONTAL =
+        UserStack(Arrangement.Horizontal(horizontalGutter), mediumImageSize, MEDIUM_TEXT)
+    val LARGE_HORIZONTAL =
+        UserStack(Arrangement.Horizontal(horizontalGutter), largeImageSize, LARGE_TEXT)
+}
+
diff --git a/Widget/src/main/res/values/dimens.xml b/Widget/src/main/res/values/dimens.xml
index ab4c751..03e02d2 100644
--- a/Widget/src/main/res/values/dimens.xml
+++ b/Widget/src/main/res/values/dimens.xml
@@ -22,15 +22,24 @@
     <dimen name="widget_grid_bottom_spacing">4dp</dimen>
     <dimen name="widget_cell_spacing">2dp</dimen>
     <dimen name="widget_item_corner_radius">20dp</dimen>
-    <dimen name="widget_min_resize_height">40dp</dimen>
-    <dimen name="widget_min_resize_width">40dp</dimen>
+    <dimen name="widget_min_resize_height">104dp</dimen>
+    <dimen name="widget_min_resize_width">168dp</dimen>
     <dimen name="widget_grid_content_padding">4dp</dimen>
     <dimen name="widget_text_start_margin">4dp</dimen>
     <dimen name="widget_text_breakpoint">100dp</dimen>
     <dimen name="small_widget_size_breakpoint">300dp</dimen>
     <dimen name="medium_widget_size_breakpoint">400dp</dimen>
     <dimen name="large_widget_size_breakpoint">500dp</dimen>
-    <dimen name="widget_min_height">40dp</dimen>
-    <dimen name="widget_min_width">40dp</dimen>
+    <dimen name="widget_min_height">104dp</dimen>
+    <dimen name="widget_min_width">168dp</dimen>
     <dimen name="loading_layout_circular_progress_indicator_size">48dp</dimen>
+    <!-- Redesign dimensions -->
+    <dimen name="user_image_min_size">80dp</dimen>
+    <dimen name="user_image_max_size">100dp</dimen>
+    <dimen name="user_text_min_size">16sp</dimen>
+    <dimen name="user_text_max_size">22sp</dimen>
+    <dimen name="user_vertical_gutter">8dp</dimen>
+    <dimen name="user_horizontal_gutter">12dp</dimen>
+    <dimen name="content_padding">12dp</dimen>
+    <dimen name="title_bar_height">56dp</dimen>
 </resources>
diff --git a/Widget/src/main/res/values/strings.xml b/Widget/src/main/res/values/strings.xml
index 6277b2a..d0a8122 100644
--- a/Widget/src/main/res/values/strings.xml
+++ b/Widget/src/main/res/values/strings.xml
@@ -27,13 +27,13 @@
       name="add_user_button_content_description">Add user</string>
 
   <string translation_description="The widget name displayed in the widget picker. [CHAR_LIMIT=NONE]"
-      name="multiuser_widget_name">Switch users</string>
+      name="multiuser_widget_name">Users</string>
 
   <string translation_description="The widget description displayed in the widget picker. [CHAR_LIMIT=NONE]"
-      name="multiuser_widget_description">Quickly switch users</string>
+      name="multiuser_widget_description">Quickly add or switch users</string>
 
   <string translation_description="The text displayed in the title bar. [CHAR_LIMIT=NONE]"
-      name="multiuser_widget_title">Switch user</string>
+      name="multiuser_widget_title">Users</string>
 
   <string translation_description="The text displayed when user data doesn't load. [CHAR_LIMIT=NONE]"
       name="multiuser_widget_error_message">Failed to load widget.</string>
```

