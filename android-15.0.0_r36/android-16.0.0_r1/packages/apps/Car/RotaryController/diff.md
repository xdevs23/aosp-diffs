```diff
diff --git a/OWNERS b/OWNERS
index 833e19d..cae268d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,4 +2,3 @@
 yabinh@google.com
 
 # Secondary
-nehah@google.com
diff --git a/src/com/android/car/rotary/Utils.java b/src/com/android/car/rotary/Utils.java
index 3668839..c0af618 100644
--- a/src/com/android/car/rotary/Utils.java
+++ b/src/com/android/car/rotary/Utils.java
@@ -463,7 +463,9 @@ final class Utils {
             focusedNode = root.findFocus(FOCUS_INPUT);
             L.v("findFocus():" + focusedNode);
             focusedNode = Utils.refreshNode(focusedNode);
-            if (focusedNode != null && focusedNode.isFocused()) {
+            // The WebView might be focused but the node representing the WebView may not update
+            // the focused state correctly. See b/391683257.
+            if (focusedNode != null && (focusedNode.isFocused() || isWebView(focusedNode))) {
                 return focusedNode;
             }
             Utils.recycleNode(focusedNode);
diff --git a/tests/unit/src/com/android/car/rotary/UtilsTest.java b/tests/unit/src/com/android/car/rotary/UtilsTest.java
index 91bdef3..7fd1edb 100644
--- a/tests/unit/src/com/android/car/rotary/UtilsTest.java
+++ b/tests/unit/src/com/android/car/rotary/UtilsTest.java
@@ -16,6 +16,10 @@
 
 package com.android.car.rotary;
 
+import static android.view.accessibility.AccessibilityNodeInfo.FOCUS_INPUT;
+
+import static com.android.car.rotary.Utils.WEB_VIEW_CLASS_NAME;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.Mockito.mock;
@@ -94,4 +98,17 @@ public final class UtilsTest {
 
         assertThat(Utils.isInstalledIme("blah/someIme", mMockedInputMethodManager)).isTrue();
     }
+
+    @Test
+    public void findFocusWithRetry_WebViewIsFocused() {
+        AccessibilityNodeInfo root = mock(AccessibilityNodeInfo.class);
+        AccessibilityNodeInfo webView = mock(AccessibilityNodeInfo.class);
+        when(webView.refresh()).thenReturn(true);
+        when(webView.getClassName()).thenReturn(WEB_VIEW_CLASS_NAME);
+        // In b/391683257, the WebView is focused but the associated node is not.
+        when(webView.isFocused()).thenReturn(false);
+        when(root.findFocus(FOCUS_INPUT)).thenReturn(webView);
+
+        assertThat(Utils.findFocusWithRetry(root)).isEqualTo(webView);
+    }
 }
```

