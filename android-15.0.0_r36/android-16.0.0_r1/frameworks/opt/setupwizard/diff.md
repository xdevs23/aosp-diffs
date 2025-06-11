```diff
diff --git a/library/gingerbread/test/instrumentation/src/com/android/setupwizardlib/util/LinkAccessibilityHelperTest.java b/library/gingerbread/test/instrumentation/src/com/android/setupwizardlib/util/LinkAccessibilityHelperTest.java
index da5e16c..9be8135 100644
--- a/library/gingerbread/test/instrumentation/src/com/android/setupwizardlib/util/LinkAccessibilityHelperTest.java
+++ b/library/gingerbread/test/instrumentation/src/com/android/setupwizardlib/util/LinkAccessibilityHelperTest.java
@@ -18,8 +18,8 @@ package com.android.setupwizardlib.util;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
-import static org.mockito.Matchers.eq;
-import static org.mockito.Matchers.same;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.ArgumentMatchers.same;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.verify;
 
diff --git a/library/recyclerview/test/instrumentation/src/com/android/setupwizardlib/items/RecyclerItemAdapterTest.java b/library/recyclerview/test/instrumentation/src/com/android/setupwizardlib/items/RecyclerItemAdapterTest.java
index bed736e..051dc8f 100644
--- a/library/recyclerview/test/instrumentation/src/com/android/setupwizardlib/items/RecyclerItemAdapterTest.java
+++ b/library/recyclerview/test/instrumentation/src/com/android/setupwizardlib/items/RecyclerItemAdapterTest.java
@@ -22,8 +22,8 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertSame;
 import static org.junit.Assert.assertTrue;
-import static org.mockito.Matchers.anyObject;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.verify;
 
@@ -111,7 +111,7 @@ public class RecyclerItemAdapterTest {
     adapter.registerAdapterDataObserver(observer);
 
     mItems[0].setTitle("Child 1");
-    verify(observer).onItemRangeChanged(eq(0), eq(1), anyObject());
+    verify(observer).onItemRangeChanged(eq(0), eq(1), any());
 
     mItemGroup.removeChild(mItems[1]);
     verify(observer).onItemRangeRemoved(eq(1), eq(1));
diff --git a/library/recyclerview/test/instrumentation/src/com/android/setupwizardlib/test/HeaderRecyclerViewTest.java b/library/recyclerview/test/instrumentation/src/com/android/setupwizardlib/test/HeaderRecyclerViewTest.java
index 3d0f9da..803ea5b 100644
--- a/library/recyclerview/test/instrumentation/src/com/android/setupwizardlib/test/HeaderRecyclerViewTest.java
+++ b/library/recyclerview/test/instrumentation/src/com/android/setupwizardlib/test/HeaderRecyclerViewTest.java
@@ -16,7 +16,7 @@
 
 package com.android.setupwizardlib.test;
 
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.verify;
 
 import androidx.recyclerview.widget.RecyclerView;
diff --git a/library/recyclerview/test/robotest/src/com/android/setupwizardlib/template/RecyclerViewScrollHandlingDelegateTest.java b/library/recyclerview/test/robotest/src/com/android/setupwizardlib/template/RecyclerViewScrollHandlingDelegateTest.java
index bcb51a8..d689cc1 100644
--- a/library/recyclerview/test/robotest/src/com/android/setupwizardlib/template/RecyclerViewScrollHandlingDelegateTest.java
+++ b/library/recyclerview/test/robotest/src/com/android/setupwizardlib/template/RecyclerViewScrollHandlingDelegateTest.java
@@ -16,8 +16,8 @@
 
 package com.android.setupwizardlib.template;
 
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
diff --git a/library/test/instrumentation/src/com/android/setupwizardlib/template/ButtonFooterMixinTest.java b/library/test/instrumentation/src/com/android/setupwizardlib/template/ButtonFooterMixinTest.java
index 971211b..4026e03 100644
--- a/library/test/instrumentation/src/com/android/setupwizardlib/template/ButtonFooterMixinTest.java
+++ b/library/test/instrumentation/src/com/android/setupwizardlib/template/ButtonFooterMixinTest.java
@@ -19,7 +19,7 @@ package com.android.setupwizardlib.template;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
 
diff --git a/library/test/instrumentation/src/com/android/setupwizardlib/template/ColoredHeaderMixinTest.java b/library/test/instrumentation/src/com/android/setupwizardlib/template/ColoredHeaderMixinTest.java
index 3ea8f6e..19397ef 100644
--- a/library/test/instrumentation/src/com/android/setupwizardlib/template/ColoredHeaderMixinTest.java
+++ b/library/test/instrumentation/src/com/android/setupwizardlib/template/ColoredHeaderMixinTest.java
@@ -17,7 +17,7 @@
 package com.android.setupwizardlib.template;
 
 import static org.junit.Assert.assertEquals;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
 
diff --git a/library/test/instrumentation/src/com/android/setupwizardlib/template/HeaderMixinTest.java b/library/test/instrumentation/src/com/android/setupwizardlib/template/HeaderMixinTest.java
index 211f95f..8a11b6d 100644
--- a/library/test/instrumentation/src/com/android/setupwizardlib/template/HeaderMixinTest.java
+++ b/library/test/instrumentation/src/com/android/setupwizardlib/template/HeaderMixinTest.java
@@ -18,7 +18,7 @@ package com.android.setupwizardlib.template;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertSame;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
 
diff --git a/library/test/instrumentation/src/com/android/setupwizardlib/template/IconMixinTest.java b/library/test/instrumentation/src/com/android/setupwizardlib/template/IconMixinTest.java
index 001fe33..2e78de3 100644
--- a/library/test/instrumentation/src/com/android/setupwizardlib/template/IconMixinTest.java
+++ b/library/test/instrumentation/src/com/android/setupwizardlib/template/IconMixinTest.java
@@ -19,7 +19,7 @@ package com.android.setupwizardlib.template;
 import static com.google.common.truth.Truth.assertThat;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertSame;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
 
diff --git a/library/test/instrumentation/src/com/android/setupwizardlib/template/ListMixinTest.java b/library/test/instrumentation/src/com/android/setupwizardlib/template/ListMixinTest.java
index e73e2bc..9c2dd01 100644
--- a/library/test/instrumentation/src/com/android/setupwizardlib/template/ListMixinTest.java
+++ b/library/test/instrumentation/src/com/android/setupwizardlib/template/ListMixinTest.java
@@ -20,7 +20,7 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertSame;
 import static org.mockito.AdditionalAnswers.delegatesTo;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
diff --git a/library/test/instrumentation/src/com/android/setupwizardlib/template/NavigationBarMixinTest.java b/library/test/instrumentation/src/com/android/setupwizardlib/template/NavigationBarMixinTest.java
index 1e2aff3..28336c6 100644
--- a/library/test/instrumentation/src/com/android/setupwizardlib/template/NavigationBarMixinTest.java
+++ b/library/test/instrumentation/src/com/android/setupwizardlib/template/NavigationBarMixinTest.java
@@ -18,7 +18,7 @@ package com.android.setupwizardlib.template;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertSame;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
diff --git a/library/test/instrumentation/src/com/android/setupwizardlib/test/ItemTest.java b/library/test/instrumentation/src/com/android/setupwizardlib/test/ItemTest.java
index 84990dd..615bd9b 100644
--- a/library/test/instrumentation/src/com/android/setupwizardlib/test/ItemTest.java
+++ b/library/test/instrumentation/src/com/android/setupwizardlib/test/ItemTest.java
@@ -21,7 +21,7 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertSame;
 import static org.junit.Assert.assertTrue;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.inOrder;
 import static org.mockito.Mockito.verify;
 
diff --git a/library/test/robotest/src/com/android/setupwizardlib/gesture/ConsecutiveTapsGestureDetectorTest.java b/library/test/robotest/src/com/android/setupwizardlib/gesture/ConsecutiveTapsGestureDetectorTest.java
index ba3e2c5..0a98a2c 100644
--- a/library/test/robotest/src/com/android/setupwizardlib/gesture/ConsecutiveTapsGestureDetectorTest.java
+++ b/library/test/robotest/src/com/android/setupwizardlib/gesture/ConsecutiveTapsGestureDetectorTest.java
@@ -16,7 +16,7 @@
 
 package com.android.setupwizardlib.gesture;
 
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.inOrder;
 import static org.robolectric.RuntimeEnvironment.application;
 
diff --git a/library/test/robotest/src/com/android/setupwizardlib/items/ButtonItemTest.java b/library/test/robotest/src/com/android/setupwizardlib/items/ButtonItemTest.java
index b51e875..7b6b1cf 100644
--- a/library/test/robotest/src/com/android/setupwizardlib/items/ButtonItemTest.java
+++ b/library/test/robotest/src/com/android/setupwizardlib/items/ButtonItemTest.java
@@ -19,8 +19,8 @@ package com.android.setupwizardlib.items;
 import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
 import static org.junit.Assert.fail;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.same;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.same;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.verify;
diff --git a/library/test/robotest/src/com/android/setupwizardlib/items/ItemGroupTest.java b/library/test/robotest/src/com/android/setupwizardlib/items/ItemGroupTest.java
index 3cbc576..d9e54e2 100644
--- a/library/test/robotest/src/com/android/setupwizardlib/items/ItemGroupTest.java
+++ b/library/test/robotest/src/com/android/setupwizardlib/items/ItemGroupTest.java
@@ -17,7 +17,7 @@
 package com.android.setupwizardlib.items;
 
 import static com.google.common.truth.Truth.assertWithMessage;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.inOrder;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.verifyNoMoreInteractions;
diff --git a/library/test/robotest/src/com/android/setupwizardlib/template/RequireScrollMixinTest.java b/library/test/robotest/src/com/android/setupwizardlib/template/RequireScrollMixinTest.java
index fe45d5f..dc46a10 100644
--- a/library/test/robotest/src/com/android/setupwizardlib/template/RequireScrollMixinTest.java
+++ b/library/test/robotest/src/com/android/setupwizardlib/template/RequireScrollMixinTest.java
@@ -18,8 +18,8 @@ package com.android.setupwizardlib.template;
 
 import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.verify;
diff --git a/library/test/robotest/src/com/android/setupwizardlib/view/RichTextViewTest.java b/library/test/robotest/src/com/android/setupwizardlib/view/RichTextViewTest.java
index 477c42a..921f682 100644
--- a/library/test/robotest/src/com/android/setupwizardlib/view/RichTextViewTest.java
+++ b/library/test/robotest/src/com/android/setupwizardlib/view/RichTextViewTest.java
@@ -18,7 +18,7 @@ package com.android.setupwizardlib.view;
 
 import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.verify;
```

