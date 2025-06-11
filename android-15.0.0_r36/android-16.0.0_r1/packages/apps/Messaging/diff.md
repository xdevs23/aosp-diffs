```diff
diff --git a/Android.bp b/Android.bp
index fd0ed55..05fd866 100644
--- a/Android.bp
+++ b/Android.bp
@@ -32,6 +32,7 @@ messaging_java_defaults {
     soong_config_variables: {
         build_variant_eng: {
             optimize: {
+                keep_runtime_invisible_annotations: true,
                 proguard_flags_files: [
                     "proguard.flags",
                     "proguard-test.flags",
@@ -39,6 +40,7 @@ messaging_java_defaults {
             },
             conditions_default: {
                 optimize: {
+                    keep_runtime_invisible_annotations: true,
                     proguard_flags_files: [
                         "proguard.flags",
                         "proguard-release.flags",
diff --git a/OWNERS b/OWNERS
index f4ccae0..f881f49 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
 tomtaylor@google.com
-rtenneti@google.com
diff --git a/proguard.flags b/proguard.flags
index c5bbb42..9c4c022 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -14,10 +14,18 @@
 #
 # Keep enough data for stack traces
 -renamesourcefileattribute SourceFile
--keepattributes SourceFile,LineNumberTable,*Annotation*
+-keepattributes SourceFile,
+                LineNumberTable,
+                RuntimeVisibleAnnotations,
+                RuntimeVisibleParameterAnnotations,
+                RuntimeVisibleTypeAnnotations,
+                AnnotationDefault
 
 # Keep classes and methods that have the guava @VisibleForTesting annotation
--keep @com.google.common.annotations.VisibleForTesting class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.google.common.annotations.VisibleForTesting class * {
+  void <init>();
+}
 -keepclassmembers class * {
   @com.google.common.annotations.VisibleForTesting *;
 }
@@ -26,19 +34,46 @@
 -keep class com.android.messaging.*.*.* { *; }
 
 # Keep methods that have the @VisibleForAnimation annotation
--keep @interface com.android.messaging.annotation.VisibleForAnimation
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @interface com.android.messaging.annotation.VisibleForAnimation {
+  void <init>();
+}
 -keepclassmembers class * {
   @com.android.messaging.annotation.VisibleForAnimation *;
 }
 
--keep public class * extends android.app.Activity
--keep public class * extends android.app.Application
--keep public class * extends android.app.Service
--keep public class * extends android.content.BroadcastReceiver
--keep public class * extends android.content.ContentProvider
--keep public class * extends android.app.backup.BackupAgentHelper
--keep public class * extends android.preference.Preference
--keep public class * extends androidx.fragment.app.Fragment
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * extends android.app.Activity {
+  void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * extends android.app.Application {
+  void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * extends android.app.Service {
+  void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * extends android.content.BroadcastReceiver {
+  void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * extends android.content.ContentProvider {
+  void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * extends android.app.backup.BackupAgentHelper {
+  void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * extends android.preference.Preference {
+  void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * extends androidx.fragment.app.Fragment {
+  void <init>();
+}
 -keep public class com.android.vcard.* { *; }
 
 -keep class androidx.collection.* { *; }
diff --git a/tests/src/com/android/messaging/FakeFactory.java b/tests/src/com/android/messaging/FakeFactory.java
index 4c7c9de..87be33d 100644
--- a/tests/src/com/android/messaging/FakeFactory.java
+++ b/tests/src/com/android/messaging/FakeFactory.java
@@ -40,7 +40,7 @@ import com.android.messaging.util.MediaUtil;
 import com.android.messaging.util.OsUtil;
 import com.android.messaging.util.PhoneUtils;
 
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 import org.mockito.invocation.InvocationOnMock;
@@ -86,7 +86,7 @@ public class FakeFactory extends Factory {
 
         ApnDatabase.initializeAppContext(context);
 
-        Mockito.when(factory.mPhoneUtils.getCanonicalBySystemLocale(Matchers.anyString()))
+        Mockito.when(factory.mPhoneUtils.getCanonicalBySystemLocale(ArgumentMatchers.anyString()))
                 .thenAnswer(new Answer<String>() {
                         @Override
                         public String answer(final InvocationOnMock invocation) throws Throwable {
@@ -95,7 +95,7 @@ public class FakeFactory extends Factory {
                         }
                     }
                 );
-        Mockito.when(factory.mPhoneUtils.getCanonicalBySimLocale(Matchers.anyString())).thenAnswer(
+        Mockito.when(factory.mPhoneUtils.getCanonicalBySimLocale(ArgumentMatchers.anyString())).thenAnswer(
                 new Answer<String>() {
                     @Override
                     public String answer(final InvocationOnMock invocation) throws Throwable {
@@ -104,7 +104,7 @@ public class FakeFactory extends Factory {
                     }
                 }
         );
-        Mockito.when(factory.mPhoneUtils.formatForDisplay(Matchers.anyString())).thenAnswer(
+        Mockito.when(factory.mPhoneUtils.formatForDisplay(ArgumentMatchers.anyString())).thenAnswer(
                 new Answer<String>() {
                     @Override
                     public String answer(final InvocationOnMock invocation) throws Throwable {
diff --git a/tests/src/com/android/messaging/datamodel/media/ImageRequestTest.java b/tests/src/com/android/messaging/datamodel/media/ImageRequestTest.java
index 3e0f4e0..1d9983f 100644
--- a/tests/src/com/android/messaging/datamodel/media/ImageRequestTest.java
+++ b/tests/src/com/android/messaging/datamodel/media/ImageRequestTest.java
@@ -28,7 +28,7 @@ import com.android.messaging.datamodel.MemoryCacheManager;
 import com.android.messaging.util.ImageUtils;
 
 import org.mockito.ArgumentCaptor;
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 import org.mockito.Mockito;
 import org.mockito.Spy;
 
@@ -62,8 +62,8 @@ public class ImageRequestTest extends BugleTestCase {
                     ArgumentCaptor.forClass(BitmapFactory.Options.class);
             Mockito.verify(spyImageUtils).calculateInSampleSize(
                     options.capture(),
-                    Matchers.eq(ImageRequest.UNSPECIFIED_SIZE),
-                    Matchers.eq(ImageRequest.UNSPECIFIED_SIZE));
+                    ArgumentMatchers.eq(ImageRequest.UNSPECIFIED_SIZE),
+                    ArgumentMatchers.eq(ImageRequest.UNSPECIFIED_SIZE));
             assertEquals(1, options.getValue().inSampleSize);
             assertNotNull(imageResource);
             assertNotNull(imageResource.getBitmap());
@@ -93,7 +93,7 @@ public class ImageRequestTest extends BugleTestCase {
                     ArgumentCaptor.forClass(BitmapFactory.Options.class);
             Mockito.verify(spyImageUtils).calculateInSampleSize(
                     options.capture(),
-                    Matchers.eq(DOWNSAMPLE_IMAGE_SIZE), Matchers.eq(DOWNSAMPLE_IMAGE_SIZE));
+                    ArgumentMatchers.eq(DOWNSAMPLE_IMAGE_SIZE), ArgumentMatchers.eq(DOWNSAMPLE_IMAGE_SIZE));
             assertNotSame(1, options.getValue().inSampleSize);
             assertNotNull(imageResource);
             assertNotNull(imageResource.getBitmap());
diff --git a/tests/src/com/android/messaging/ui/attachmentchooser/AttachmentChooserFragmentTest.java b/tests/src/com/android/messaging/ui/attachmentchooser/AttachmentChooserFragmentTest.java
index d723a40..96d6113 100644
--- a/tests/src/com/android/messaging/ui/attachmentchooser/AttachmentChooserFragmentTest.java
+++ b/tests/src/com/android/messaging/ui/attachmentchooser/AttachmentChooserFragmentTest.java
@@ -34,7 +34,7 @@ import com.android.messaging.ui.attachmentchooser.AttachmentChooserFragment.Atta
 import com.android.messaging.ui.conversationlist.ConversationListFragment;
 
 import org.mockito.ArgumentMatcher;
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 
@@ -85,7 +85,7 @@ public class AttachmentChooserFragmentTest extends FragmentTestCase<AttachmentCh
     }
 
     private void loadWith(final List<MessagePartData> attachments) {
-        Mockito.when(mockDraftMessageData.isBound(Matchers.anyString()))
+        Mockito.when(mockDraftMessageData.isBound(ArgumentMatchers.anyString()))
             .thenReturn(true);
         Mockito.doReturn(mockDraftMessageData)
             .when(mockDataModel)
@@ -94,7 +94,7 @@ public class AttachmentChooserFragmentTest extends FragmentTestCase<AttachmentCh
             .when(mockDraftMessageData)
             .getReadOnlyAttachments();
         Mockito.when(mockDataModel.createDraftMessageData(
-                Matchers.anyString()))
+                ArgumentMatchers.anyString()))
             .thenReturn(mockDraftMessageData);
 
         // Create fragment synchronously to avoid need for volatile, synchronization etc.
@@ -118,8 +118,8 @@ public class AttachmentChooserFragmentTest extends FragmentTestCase<AttachmentCh
                 Mockito.verify(mockDataModel).createDraftMessageData(
                         Mockito.matches(CONVERSATION_ID));
                 Mockito.verify(mockDraftMessageData).loadFromStorage(
-                        Matchers.eq(fragment.mBinding), Matchers.eq((MessageData) null),
-                        Matchers.eq(false));
+                        ArgumentMatchers.eq(fragment.mBinding), ArgumentMatchers.eq((MessageData) null),
+                        ArgumentMatchers.eq(false));
             }
         });
         // Now load the cursor
@@ -158,9 +158,9 @@ public class AttachmentChooserFragmentTest extends FragmentTestCase<AttachmentCh
         getFragment().confirmSelection();
         final MessagePartData[] attachmentsToRemove = new MessagePartData[] {
                 itemView.mAttachmentData, itemView2.mAttachmentData };
-        Mockito.verify(mockDraftMessageData).removeExistingAttachments(Matchers.argThat(
+        Mockito.verify(mockDraftMessageData).removeExistingAttachments(ArgumentMatchers.argThat(
                 new IsSetOfGivenAttachments(new HashSet<>(Arrays.asList(attachmentsToRemove)))));
-        Mockito.verify(mockDraftMessageData).saveToStorage(Matchers.eq(getFragment().mBinding));
+        Mockito.verify(mockDraftMessageData).saveToStorage(ArgumentMatchers.eq(getFragment().mBinding));
         Mockito.verify(mockHost).onConfirmSelection();
     }
 }
diff --git a/tests/src/com/android/messaging/ui/contact/ContactPickerFragmentTest.java b/tests/src/com/android/messaging/ui/contact/ContactPickerFragmentTest.java
index 4983cd3..ac4e818 100644
--- a/tests/src/com/android/messaging/ui/contact/ContactPickerFragmentTest.java
+++ b/tests/src/com/android/messaging/ui/contact/ContactPickerFragmentTest.java
@@ -38,7 +38,7 @@ import com.android.messaging.ui.FragmentTestCase;
 import com.android.messaging.ui.UIIntents;
 import com.android.messaging.ui.contact.ContactPickerFragment.ContactPickerFragmentHost;
 
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 
@@ -79,7 +79,7 @@ public class ContactPickerFragmentTest
      * Helper method to initialize the ContactPickerFragment and its data.
      */
     private ContactPickerFragmentTest initFragment(final int initialMode) {
-        Mockito.when(mMockContactPickerData.isBound(Matchers.anyString()))
+        Mockito.when(mMockContactPickerData.isBound(ArgumentMatchers.anyString()))
             .thenReturn(true);
 
         getActivity().runOnUiThread(new Runnable() {
@@ -103,7 +103,7 @@ public class ContactPickerFragmentTest
      * fragment.
      */
     private ContactPickerFragmentTest loadWithAllContactsCursor(final Cursor cursor) {
-        Mockito.when(mMockContactPickerData.isBound(Matchers.anyString()))
+        Mockito.when(mMockContactPickerData.isBound(ArgumentMatchers.anyString()))
             .thenReturn(true);
 
         getActivity().runOnUiThread(new Runnable() {
@@ -121,7 +121,7 @@ public class ContactPickerFragmentTest
      * fragment.
      */
     private ContactPickerFragmentTest loadWithFrequentContactsCursor(final Cursor cursor) {
-        Mockito.when(mMockContactPickerData.isBound(Matchers.anyString()))
+        Mockito.when(mMockContactPickerData.isBound(ArgumentMatchers.anyString()))
             .thenReturn(true);
         getActivity().runOnUiThread(new Runnable() {
             @Override
diff --git a/tests/src/com/android/messaging/ui/conversation/ComposeMessageViewTest.java b/tests/src/com/android/messaging/ui/conversation/ComposeMessageViewTest.java
index 9d55b6e..2876db5 100644
--- a/tests/src/com/android/messaging/ui/conversation/ComposeMessageViewTest.java
+++ b/tests/src/com/android/messaging/ui/conversation/ComposeMessageViewTest.java
@@ -43,7 +43,7 @@ import com.android.messaging.util.BugleGservices;
 import com.android.messaging.util.FakeMediaUtil;
 import com.android.messaging.util.ImeUtil;
 
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 import org.mockito.invocation.InvocationOnMock;
@@ -104,11 +104,11 @@ public class ComposeMessageViewTest extends ViewTest<ComposeMessageView> {
         final MessageData message = MessageData.createDraftSmsMessage("fake_id", "just_a_self_id",
                 "Sample Message");
 
-        Mockito.when(mockDraftMessageData.isBound(Matchers.anyString()))
+        Mockito.when(mockDraftMessageData.isBound(ArgumentMatchers.anyString()))
                 .thenReturn(true);
         Mockito.when(mockDraftMessageData.getMessageText()).thenReturn(message.getMessageText());
         Mockito.when(mockDraftMessageData.prepareMessageForSending(
-                Matchers.<BindingBase<DraftMessageData>>any()))
+                ArgumentMatchers.<BindingBase<DraftMessageData>>any()))
                 .thenReturn(message);
         Mockito.when(mockDraftMessageData.hasPendingAttachments()).thenReturn(false);
         Mockito.doAnswer(new Answer() {
@@ -155,11 +155,11 @@ public class ComposeMessageViewTest extends ViewTest<ComposeMessageView> {
         final MessageData message = MessageData.createDraftSmsMessage("fake_id", "just_a_self_id",
                 "Sample Message");
 
-        Mockito.when(mockDraftMessageData.isBound(Matchers.anyString()))
+        Mockito.when(mockDraftMessageData.isBound(ArgumentMatchers.anyString()))
                 .thenReturn(true);
         Mockito.when(mockDraftMessageData.getMessageText()).thenReturn(message.getMessageText());
         Mockito.when(mockDraftMessageData.prepareMessageForSending(
-                Matchers.<BindingBase<DraftMessageData>>any()))
+                ArgumentMatchers.<BindingBase<DraftMessageData>>any()))
                 .thenReturn(message);
         Mockito.when(mockDraftMessageData.hasPendingAttachments()).thenReturn(false);
 
diff --git a/tests/src/com/android/messaging/ui/conversation/ConversationFragmentTest.java b/tests/src/com/android/messaging/ui/conversation/ConversationFragmentTest.java
index 030306a..b9faaaf 100644
--- a/tests/src/com/android/messaging/ui/conversation/ConversationFragmentTest.java
+++ b/tests/src/com/android/messaging/ui/conversation/ConversationFragmentTest.java
@@ -40,7 +40,7 @@ import com.android.messaging.ui.conversationlist.ConversationListFragment;
 import com.android.messaging.util.BugleGservices;
 import com.android.messaging.util.ImeUtil;
 
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 
@@ -84,9 +84,9 @@ public class ConversationFragmentTest extends FragmentTestCase<ConversationFragm
      * @param cursor
      */
     private void loadWith(final Cursor cursor) {
-        Mockito.when(mockDraftMessageData.isBound(Matchers.anyString()))
+        Mockito.when(mockDraftMessageData.isBound(ArgumentMatchers.anyString()))
             .thenReturn(true);
-        Mockito.when(mockConversationData.isBound(Matchers.anyString()))
+        Mockito.when(mockConversationData.isBound(ArgumentMatchers.anyString()))
             .thenReturn(true);
         Mockito.doReturn(mockDraftMessageData)
             .when(mockDataModel)
@@ -95,9 +95,9 @@ public class ConversationFragmentTest extends FragmentTestCase<ConversationFragm
             .when(mockDataModel)
             .createDraftMessageData(null);
         Mockito.when(mockDataModel.createConversationData(
-                Matchers.any(Activity.class),
-                Matchers.any(ConversationDataListener.class),
-                Matchers.anyString()))
+                ArgumentMatchers.any(Activity.class),
+                ArgumentMatchers.any(ConversationDataListener.class),
+                ArgumentMatchers.anyString()))
             .thenReturn(mockConversationData);
 
         // Create fragment synchronously to avoid need for volatile, synchronization etc.
diff --git a/tests/src/com/android/messaging/ui/conversationlist/ConversationListFragmentTest.java b/tests/src/com/android/messaging/ui/conversationlist/ConversationListFragmentTest.java
index c3da81c..9f37c3f 100644
--- a/tests/src/com/android/messaging/ui/conversationlist/ConversationListFragmentTest.java
+++ b/tests/src/com/android/messaging/ui/conversationlist/ConversationListFragmentTest.java
@@ -33,7 +33,7 @@ import com.android.messaging.ui.FragmentTestCase;
 import com.android.messaging.ui.UIIntents;
 import com.android.messaging.ui.conversationlist.ConversationListFragment.ConversationListFragmentHost;
 
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 
@@ -71,7 +71,7 @@ public class ConversationListFragmentTest
      * @param cursor
      */
     private void loadWith(final Cursor cursor) {
-        Mockito.when(mMockConversationListData.isBound(Matchers.anyString()))
+        Mockito.when(mMockConversationListData.isBound(ArgumentMatchers.anyString()))
             .thenReturn(true);
 
         final ConversationListFragment fragment = getFragment();
diff --git a/tests/src/com/android/messaging/ui/mediapicker/AudioRecordViewTest.java b/tests/src/com/android/messaging/ui/mediapicker/AudioRecordViewTest.java
index a38dac2..f41bf5d 100644
--- a/tests/src/com/android/messaging/ui/mediapicker/AudioRecordViewTest.java
+++ b/tests/src/com/android/messaging/ui/mediapicker/AudioRecordViewTest.java
@@ -26,7 +26,7 @@ import com.android.messaging.datamodel.data.MessagePartData;
 import com.android.messaging.ui.ViewTest;
 import com.android.messaging.util.FakeMediaUtil;
 
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 
@@ -44,7 +44,7 @@ public class AudioRecordViewTest extends ViewTest<AudioRecordView> {
     }
 
     private void verifyAudioSubmitted() {
-        Mockito.verify(mockHost).onAudioRecorded(Matchers.any(MessagePartData.class));
+        Mockito.verify(mockHost).onAudioRecorded(ArgumentMatchers.any(MessagePartData.class));
     }
 
     private AudioRecordView initView() {
@@ -56,13 +56,13 @@ public class AudioRecordViewTest extends ViewTest<AudioRecordView> {
 
     public void testRecording() {
         Mockito.when(mockRecorder.isRecording()).thenReturn(false);
-        Mockito.when(mockRecorder.startRecording(Matchers.<OnErrorListener>any(),
-                Matchers.<OnInfoListener>any(), Matchers.anyInt())).thenReturn(true);
+        Mockito.when(mockRecorder.startRecording(ArgumentMatchers.<OnErrorListener>any(),
+                ArgumentMatchers.<OnInfoListener>any(), ArgumentMatchers.anyInt())).thenReturn(true);
         Mockito.when(mockRecorder.stopRecording()).thenReturn(Uri.parse("content://someaudio/2"));
         final AudioRecordView view = initView();
         view.onRecordButtonTouchDown();
-        Mockito.verify(mockRecorder).startRecording(Matchers.<OnErrorListener>any(),
-                Matchers.<OnInfoListener>any(), Matchers.anyInt());
+        Mockito.verify(mockRecorder).startRecording(ArgumentMatchers.<OnErrorListener>any(),
+                ArgumentMatchers.<OnInfoListener>any(), ArgumentMatchers.anyInt());
         Mockito.when(mockRecorder.isRecording()).thenReturn(true);
         // Record for 1 second to make it meaningful.
         sleepNoThrow(1000);
diff --git a/tests/src/com/android/messaging/ui/mediapicker/GalleryGridItemViewTest.java b/tests/src/com/android/messaging/ui/mediapicker/GalleryGridItemViewTest.java
index 304cc74..f3e6325 100644
--- a/tests/src/com/android/messaging/ui/mediapicker/GalleryGridItemViewTest.java
+++ b/tests/src/com/android/messaging/ui/mediapicker/GalleryGridItemViewTest.java
@@ -30,7 +30,7 @@ import com.android.messaging.ui.AsyncImageView;
 import com.android.messaging.ui.ViewTest;
 import com.android.messaging.util.UriUtil;
 
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 
@@ -72,7 +72,7 @@ public class GalleryGridItemViewTest extends ViewTest<GalleryGridItemView> {
 
     public void testBind() {
         Mockito.when(mockHost.isMultiSelectEnabled()).thenReturn(false);
-        Mockito.when(mockHost.isItemSelected(Matchers.<GalleryGridItemData>any()))
+        Mockito.when(mockHost.isItemSelected(ArgumentMatchers.<GalleryGridItemData>any()))
                 .thenReturn(false);
         final GalleryGridItemView view = getView();
         final FakeCursor cursor = TestDataFactory.getGalleryGridCursor();
@@ -85,7 +85,7 @@ public class GalleryGridItemViewTest extends ViewTest<GalleryGridItemView> {
 
     public void testBindMultiSelectUnSelected() {
         Mockito.when(mockHost.isMultiSelectEnabled()).thenReturn(true);
-        Mockito.when(mockHost.isItemSelected(Matchers.<GalleryGridItemData>any()))
+        Mockito.when(mockHost.isItemSelected(ArgumentMatchers.<GalleryGridItemData>any()))
                 .thenReturn(false);
         final GalleryGridItemView view = getView();
         final FakeCursor cursor = TestDataFactory.getGalleryGridCursor();
@@ -98,7 +98,7 @@ public class GalleryGridItemViewTest extends ViewTest<GalleryGridItemView> {
 
     public void testBindMultiSelectSelected() {
         Mockito.when(mockHost.isMultiSelectEnabled()).thenReturn(true);
-        Mockito.when(mockHost.isItemSelected(Matchers.<GalleryGridItemData>any()))
+        Mockito.when(mockHost.isItemSelected(ArgumentMatchers.<GalleryGridItemData>any()))
                 .thenReturn(true);
         final GalleryGridItemView view = getView();
         final FakeCursor cursor = TestDataFactory.getGalleryGridCursor();
@@ -111,7 +111,7 @@ public class GalleryGridItemViewTest extends ViewTest<GalleryGridItemView> {
 
     public void testClick() {
         Mockito.when(mockHost.isMultiSelectEnabled()).thenReturn(false);
-        Mockito.when(mockHost.isItemSelected(Matchers.<GalleryGridItemData>any()))
+        Mockito.when(mockHost.isItemSelected(ArgumentMatchers.<GalleryGridItemData>any()))
                 .thenReturn(false);
         final GalleryGridItemView view = getView();
         final FakeCursor cursor = TestDataFactory.getGalleryGridCursor();
@@ -123,7 +123,7 @@ public class GalleryGridItemViewTest extends ViewTest<GalleryGridItemView> {
 
     public void testBindTwice() {
         Mockito.when(mockHost.isMultiSelectEnabled()).thenReturn(true);
-        Mockito.when(mockHost.isItemSelected(Matchers.<GalleryGridItemData>any()))
+        Mockito.when(mockHost.isItemSelected(ArgumentMatchers.<GalleryGridItemData>any()))
                 .thenReturn(false);
         final GalleryGridItemView view = getView();
         final FakeCursor cursor = TestDataFactory.getGalleryGridCursor();
diff --git a/tests/src/com/android/messaging/ui/mediapicker/MediaPickerTest.java b/tests/src/com/android/messaging/ui/mediapicker/MediaPickerTest.java
index 4e7c2d2..10dc354 100644
--- a/tests/src/com/android/messaging/ui/mediapicker/MediaPickerTest.java
+++ b/tests/src/com/android/messaging/ui/mediapicker/MediaPickerTest.java
@@ -30,7 +30,7 @@ import com.android.messaging.datamodel.data.DraftMessageData;
 import com.android.messaging.datamodel.data.MediaPickerData;
 import com.android.messaging.ui.FragmentTestCase;
 
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 
@@ -66,9 +66,9 @@ public class MediaPickerTest extends FragmentTestCase<MediaPicker> {
      */
     private void initFragment(final int supportedMediaTypes, final Integer[] expectedLoaderIds,
             final boolean filterTabBeforeAttach) {
-        Mockito.when(mMockMediaPickerData.isBound(Matchers.anyString()))
+        Mockito.when(mMockMediaPickerData.isBound(ArgumentMatchers.anyString()))
             .thenReturn(true);
-        Mockito.when(mMockDraftMessageData.isBound(Matchers.anyString()))
+        Mockito.when(mMockDraftMessageData.isBound(ArgumentMatchers.anyString()))
             .thenReturn(true);
         final Binding<DraftMessageData> draftBinding = BindingBase.createBinding(this);
         draftBinding.bind(mMockDraftMessageData);
@@ -87,7 +87,7 @@ public class MediaPickerTest extends FragmentTestCase<MediaPicker> {
                 fragment.setDraftMessageDataModel(draftBinding);
                 Mockito.verify(mMockMediaPickerData,
                         Mockito.atLeastOnce()).init(
-                        Matchers.eq(fragment.getLoaderManager()));
+                        ArgumentMatchers.eq(fragment.getLoaderManager()));
                 fragment.open(MediaPicker.MEDIA_TYPE_ALL, false);
             }
         });
```

