```diff
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index aeb3b33..40cb271 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -19,7 +19,7 @@
     <string name="app_name" msgid="963247385700831716">"Менеджар сховішча"</string>
     <string name="cancel" msgid="7021218262867558825">"Скасаваць"</string>
     <string name="storage_menu_free" msgid="1878247401436882778">"Вызваліць месца"</string>
-    <string name="deletion_helper_title" msgid="3526170325226275927">"Выдаліць аб\'екты"</string>
+    <string name="deletion_helper_title" msgid="3526170325226275927">"Выдаліць аб’екты"</string>
     <string name="deletion_helper_app_summary" msgid="4904590040180275237">"Дзён таму: <xliff:g id="DAYS">%1$d</xliff:g>"</string>
     <!-- no translation found for deletion_helper_app_summary_item_size (3770886184921427886) -->
     <skip />
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 3a6e878..6eb841d 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="963247385700831716">"Հիշողության կառավարիչ"</string>
     <string name="cancel" msgid="7021218262867558825">"Չեղարկել"</string>
-    <string name="storage_menu_free" msgid="1878247401436882778">"Ազատել տարածք"</string>
+    <string name="storage_menu_free" msgid="1878247401436882778">"Տարածք ազատել"</string>
     <string name="deletion_helper_title" msgid="3526170325226275927">"Ջնջել տարրերը"</string>
     <string name="deletion_helper_app_summary" msgid="4904590040180275237">"<xliff:g id="DAYS">%1$d</xliff:g> օր առաջ"</string>
     <!-- no translation found for deletion_helper_app_summary_item_size (3770886184921427886) -->
@@ -35,9 +35,9 @@
     <skip />
     <!-- no translation found for deletion_helper_downloads_summary_empty (3988054032360371887) -->
     <skip />
-    <string name="deletion_helper_clear_dialog_title" msgid="9169670752655850967">"Ազատել տարածք"</string>
+    <string name="deletion_helper_clear_dialog_title" msgid="9169670752655850967">"Տարածք ազատել"</string>
     <string name="deletion_helper_clear_dialog_message" msgid="5196490478187120700">"Ձեր սարքից կհեռացվի <xliff:g id="CLEARABLE_BYTES">%1$s</xliff:g> ծավալով բովանդակություն"</string>
-    <string name="deletion_helper_clear_dialog_remove" msgid="863575755467985516">"Ազատել տարածք"</string>
+    <string name="deletion_helper_clear_dialog_remove" msgid="863575755467985516">"Տարածք ազատել"</string>
     <string name="deletion_helper_upsell_title" msgid="8512037674466762017">"Կառավարե՞լ հիշողությունն ավտոմատ կերպով:"</string>
     <string name="deletion_helper_upsell_summary" msgid="2301597713694474407">"<xliff:g id="USED">%1$s</xliff:g> այժմ ազատ է: Թույլատրե՞լ Հիշողության կառավարիչին տարածք ազատել՝ հեռացնելով սարքից պահուստավորված բովանդակությունը:"</string>
     <string name="deletion_helper_upsell_cancel" msgid="7084167642850053889">"Ոչ"</string>
diff --git a/robotests/src/com/android/storagemanager/deletionhelper/ConfirmDeletionDialogTest.java b/robotests/src/com/android/storagemanager/deletionhelper/ConfirmDeletionDialogTest.java
index 15a6124..ce48449 100644
--- a/robotests/src/com/android/storagemanager/deletionhelper/ConfirmDeletionDialogTest.java
+++ b/robotests/src/com/android/storagemanager/deletionhelper/ConfirmDeletionDialogTest.java
@@ -19,21 +19,22 @@ package com.android.storagemanager.deletionhelper;
 import static com.google.common.truth.Truth.assertThat;
 
 import android.R;
+import android.app.Activity;
+import android.app.Fragment;
 import android.widget.Button;
 import android.widget.TextView;
 
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.robolectric.Robolectric;
 import org.robolectric.RobolectricTestRunner;
 
-import static org.robolectric.util.FragmentTestUtil.startFragment;
-
 @RunWith(RobolectricTestRunner.class)
 public class ConfirmDeletionDialogTest {
     @Test
     public void testOnCreateDialog_saysCorrectStrings() {
         final ConfirmDeletionDialog alertDialog = ConfirmDeletionDialog.newInstance(100L);
-        startFragment(alertDialog);
+        startVisibleFragment(alertDialog);
 
         TextView message = alertDialog.getDialog().findViewById(R.id.message);
         Button button1 = alertDialog.getDialog().findViewById(android.R.id.button1);
@@ -43,4 +44,13 @@ public class ConfirmDeletionDialogTest {
         assertThat(button1.getText().toString()).isEqualTo("Free up space");
         assertThat(button2.getText().toString()).isEqualTo("Cancel");
     }
+
+    private static void startVisibleFragment(Fragment fragment) {
+        Activity activity = Robolectric.setupActivity(Activity.class);
+        activity
+            .getFragmentManager()
+            .beginTransaction()
+            .add(android.R.id.content, fragment, null)
+            .commitNow();
+    }
 }
diff --git a/robotests/src/com/android/storagemanager/deletionhelper/StorageManagerUpsellDialogTest.java b/robotests/src/com/android/storagemanager/deletionhelper/StorageManagerUpsellDialogTest.java
index f4d4db2..bd8f4de 100644
--- a/robotests/src/com/android/storagemanager/deletionhelper/StorageManagerUpsellDialogTest.java
+++ b/robotests/src/com/android/storagemanager/deletionhelper/StorageManagerUpsellDialogTest.java
@@ -16,11 +16,14 @@
 
 package com.android.storagemanager.deletionhelper;
 
+import android.app.Activity;
+import android.app.Fragment;
 import android.content.Context;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
+import org.robolectric.Robolectric;
 import org.robolectric.RobolectricTestRunner;
 import org.robolectric.RuntimeEnvironment;
 
@@ -29,7 +32,6 @@ import java.util.concurrent.TimeUnit;
 import static android.content.DialogInterface.BUTTON_NEGATIVE;
 import static com.google.common.truth.Truth.assertThat;
 import static org.mockito.Mockito.when;
-import static org.robolectric.util.FragmentTestUtil.startFragment;
 
 @RunWith(RobolectricTestRunner.class)
 public class StorageManagerUpsellDialogTest {
@@ -45,28 +47,38 @@ public class StorageManagerUpsellDialogTest {
         assertThat(StorageManagerUpsellDialog.shouldShow(context, TimeUnit.DAYS.toMillis(90)))
                 .isTrue();
 
-        startFragment(fragment);
+        startVisibleFragment(fragment);
         fragment.onClick(null, BUTTON_NEGATIVE);
         when(mClock.currentTimeMillis()).thenReturn(TimeUnit.DAYS.toMillis(90 * 2));
         assertThat(StorageManagerUpsellDialog.shouldShow(context, TimeUnit.DAYS.toMillis(90 * 2)))
                 .isTrue();
 
-        startFragment(fragment);
+        startVisibleFragment(fragment);
         fragment.onClick(null, BUTTON_NEGATIVE);
         when(mClock.currentTimeMillis()).thenReturn(TimeUnit.DAYS.toMillis(90 * 3));
         assertThat(StorageManagerUpsellDialog.shouldShow(context, TimeUnit.DAYS.toMillis(90 * 3)))
                 .isTrue();
 
-        startFragment(fragment);
+        startVisibleFragment(fragment);
         fragment.onClick(null, BUTTON_NEGATIVE);
         when(mClock.currentTimeMillis()).thenReturn(TimeUnit.DAYS.toMillis(90 * 4));
         assertThat(StorageManagerUpsellDialog.shouldShow(context, TimeUnit.DAYS.toMillis(90 * 4)))
                 .isTrue();
 
-        startFragment(fragment);
+        startVisibleFragment(fragment);
         fragment.onClick(null, BUTTON_NEGATIVE);
         when(mClock.currentTimeMillis()).thenReturn(TimeUnit.DAYS.toMillis(90 * 5));
         assertThat(StorageManagerUpsellDialog.shouldShow(context, TimeUnit.DAYS.toMillis(90 * 5)))
                 .isFalse();
     }
+    
+    private static void startVisibleFragment(Fragment fragment) {
+        Activity activity = Robolectric.setupActivity(Activity.class);
+        activity
+            .getFragmentManager()
+            .beginTransaction()
+            .add(android.R.id.content, fragment, null)
+            .commitNow();
+    }
 }
+
diff --git a/tests/app/Android.bp b/tests/app/Android.bp
index ddfa6df..dc54e19 100644
--- a/tests/app/Android.bp
+++ b/tests/app/Android.bp
@@ -6,7 +6,7 @@ package {
 android_test {
     name: "StorageManagerAppTests",
 
-    libs: ["android.test.runner"],
+    libs: ["android.test.runner.stubs.system"],
 
     static_libs: [
         "androidx.test.rules",
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index cada798..cd33396 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -7,9 +7,9 @@ android_test {
     name: "StorageManagerUnitTests",
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
 
     static_libs: [
```

